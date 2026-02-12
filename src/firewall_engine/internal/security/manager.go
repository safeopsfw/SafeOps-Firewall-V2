package security

import (
	"sync"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
	"firewall_engine/internal/rate_limiting"
)

// Manager is the central security orchestrator. It initializes and coordinates
// all detection sub-systems: rate limiting, DDoS protection, brute force,
// port scanning, anomaly detection, traffic baseline, and ban management.
//
// The packet pipeline calls Manager.Check() which runs all enabled detectors
// and returns a SecurityVerdict.
type Manager struct {
	cfg       *config.DetectionConfig
	whitelist *config.ParsedWhitelist
	alertMgr  *alerting.Manager

	// Sub-systems
	RateLimiter    *rate_limiting.RateLimiter
	DDoS           *rate_limiting.DDoSProtection
	BruteForce     *BruteForceDetector
	PortScan       *PortScanDetector
	Anomaly        *AnomalyDetector
	Baseline       *TrafficBaseline
	BanMgr         *BanManager

	// Baseline deviation check interval
	lastBaselineCheck int64
	baselineMu        sync.Mutex
}

// SecurityVerdict is the result of all security checks for a single packet.
type SecurityVerdict struct {
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason,omitempty"`
	DetectorName string `json:"detector,omitempty"`

	// Specific results (nil if detector not triggered)
	IsBanned       bool              `json:"is_banned,omitempty"`
	BanEntry       *BanEntry         `json:"ban_entry,omitempty"`
	IsRateLimited  bool              `json:"is_rate_limited,omitempty"`
	IsDDoS         bool              `json:"is_ddos,omitempty"`
	IsBruteForce   bool              `json:"is_brute_force,omitempty"`
	IsPortScan     bool              `json:"is_port_scan,omitempty"`
	IsAnomaly      bool              `json:"is_anomaly,omitempty"`
}

// SecurityStats aggregates all sub-system stats
type SecurityStats struct {
	RateLimiter rate_limiting.RateLimiterStats `json:"rate_limiter"`
	DDoS        rate_limiting.DDoSStats        `json:"ddos"`
	BruteForce  BruteForceStats                `json:"brute_force"`
	PortScan    PortScanStats                  `json:"port_scan"`
	Anomaly     AnomalyStats                   `json:"anomaly"`
	Baseline    BaselineStats                  `json:"baseline"`
	Bans        BanManagerStats                `json:"bans"`
}

// NewManager creates and initializes all security sub-systems from config.
func NewManager(cfg *config.DetectionConfig, alertMgr *alerting.Manager) *Manager {
	// Parse whitelist
	whitelist, err := cfg.Whitelist.Parse()
	if err != nil {
		// Non-fatal: log and continue without whitelist
		whitelist = &config.ParsedWhitelist{IPs: make(map[string]bool)}
	}

	m := &Manager{
		cfg:       cfg,
		whitelist: whitelist,
		alertMgr:  alertMgr,
	}

	// Initialize sub-systems
	m.RateLimiter = rate_limiting.NewRateLimiter(cfg.RateLimit, whitelist)
	m.DDoS = rate_limiting.NewDDoSProtection(cfg.DDoS, alertMgr)
	m.BruteForce = NewBruteForceDetector(cfg.BruteForce, alertMgr)
	m.PortScan = NewPortScanDetector(cfg.PortScan, alertMgr)
	m.Anomaly = NewAnomalyDetector(cfg.Anomaly, alertMgr)
	m.Baseline = NewTrafficBaseline(cfg.Baseline, alertMgr)
	m.BanMgr = NewBanManager(
		cfg.DDoS.BanDurationMinutes,
		cfg.DDoS.EscalationMultiplier,
		cfg.DDoS.MaxBanDurationHours,
		alertMgr,
	)

	return m
}

// Check runs all security checks for a packet.
// This is the main entry point called from the packet pipeline.
// Order: banned? → whitelisted? → rate limit → DDoS → anomaly → baseline
// Brute force and port scan are checked via separate methods since they need
// specific context (failed connections for brute force, new connections for port scan).
func (m *Manager) Check(srcIP string, protocol string, tcpFlags uint8, packetSize int) SecurityVerdict {
	// 1. Check if already banned (O(1) — fastest check)
	if entry, banned := m.BanMgr.IsBanned(srcIP); banned {
		return SecurityVerdict{
			Allowed:      false,
			Reason:       "IP is banned: " + entry.Reason,
			DetectorName: "ban_manager",
			IsBanned:     true,
			BanEntry:     entry,
		}
	}

	// 2. Whitelist bypass
	if m.whitelist.Contains(srcIP) {
		// Still record for baseline
		m.Baseline.RecordPacket(protocol)
		return SecurityVerdict{Allowed: true}
	}

	// 3. DDoS detection (protocol-specific) — run BEFORE rate limiting
	// so that flood counters always increment even if rate limited
	if ddosResult := m.checkDDoS(srcIP, protocol); ddosResult.IsDDoS {
		// Auto-ban on DDoS detection
		m.BanMgr.Ban(srcIP, ddosResult.Reason)
		return ddosResult
	}

	// 4. Rate limiting
	if !m.RateLimiter.Allow(srcIP) {
		return SecurityVerdict{
			Allowed:       false,
			Reason:        "Rate limit exceeded",
			DetectorName:  "rate_limiter",
			IsRateLimited: true,
		}
	}

	// 5. Protocol anomaly detection (TCP flags)
	if protocol == "TCP" && tcpFlags != 0 {
		if result := m.Anomaly.CheckTCPFlags(srcIP, tcpFlags); result.Detected {
			return SecurityVerdict{
				Allowed:      false,
				Reason:       result.Details,
				DetectorName: "anomaly_detector",
				IsAnomaly:    true,
			}
		}
	}

	// 6. Packet size anomaly
	if result := m.Anomaly.CheckPacketSize(srcIP, packetSize); result.Detected {
		// Size anomalies are logged, not blocked
		// (oversized could be legitimate jumbo frames)
	}

	// 7. Record for traffic baseline (non-blocking)
	m.Baseline.RecordPacket(protocol)

	// 8. Periodic baseline deviation check (every 10 seconds)
	m.checkBaselinePeriodically()

	return SecurityVerdict{Allowed: true}
}

// CheckBruteForce should be called when a connection to a monitored port fails.
// Returns a verdict. If brute force is detected, the IP is auto-banned.
func (m *Manager) CheckBruteForce(srcIP string, dstPort int) SecurityVerdict {
	result := m.BruteForce.RecordFailure(srcIP, dstPort)
	if result.Detected {
		m.BanMgr.Ban(srcIP, result.ServiceName+" brute force")
		return SecurityVerdict{
			Allowed:      false,
			Reason:       result.ServiceName + " brute force detected",
			DetectorName: "brute_force",
			IsBruteForce: true,
		}
	}
	return SecurityVerdict{Allowed: true}
}

// CheckPortScan should be called for each new connection (SYN packet).
// Returns a verdict. If port scanning is detected, the IP is auto-banned.
func (m *Manager) CheckPortScan(srcIP string, dstPort uint16) SecurityVerdict {
	result := m.PortScan.RecordPort(srcIP, dstPort)
	if result.Detected {
		banDuration := time.Duration(m.cfg.PortScan.BanDurationMinutes) * time.Minute
		m.BanMgr.BanWithDuration(srcIP, "port scan ("+result.ScanType+")", banDuration)
		return SecurityVerdict{
			Allowed:      false,
			Reason:       "Port scan detected (" + result.ScanType + ")",
			DetectorName: "port_scan",
			IsPortScan:   true,
		}
	}
	return SecurityVerdict{Allowed: true}
}

// CheckBeaconing should be called for each outbound connection to track C2 patterns.
func (m *Manager) CheckBeaconing(srcIP, dstIP string) SecurityVerdict {
	result := m.Anomaly.RecordConnection(srcIP, dstIP)
	if result.Detected {
		m.BanMgr.Ban(dstIP, "beaconing/C2 destination")
		return SecurityVerdict{
			Allowed:      false,
			Reason:       result.Details,
			DetectorName: "anomaly_detector",
			IsAnomaly:    true,
		}
	}
	return SecurityVerdict{Allowed: true}
}

// UpdateConfig hot-reloads the detection configuration.
// Recreates sub-systems with new config while preserving the ban manager
// (bans are runtime state, not config-driven). Old sub-systems are stopped.
func (m *Manager) UpdateConfig(newCfg *config.DetectionConfig) {
	// Parse new whitelist
	whitelist, err := newCfg.Whitelist.Parse()
	if err != nil {
		whitelist = &config.ParsedWhitelist{IPs: make(map[string]bool)}
	}

	// Stop old sub-systems (except ban manager — bans persist)
	m.RateLimiter.Stop()
	m.DDoS.Stop()
	m.BruteForce.Stop()
	m.PortScan.Stop()
	m.Anomaly.Stop()
	m.Baseline.Stop()

	// Recreate with new config
	m.cfg = newCfg
	m.whitelist = whitelist
	m.RateLimiter = rate_limiting.NewRateLimiter(newCfg.RateLimit, whitelist)
	m.DDoS = rate_limiting.NewDDoSProtection(newCfg.DDoS, m.alertMgr)
	m.BruteForce = NewBruteForceDetector(newCfg.BruteForce, m.alertMgr)
	m.PortScan = NewPortScanDetector(newCfg.PortScan, m.alertMgr)
	m.Anomaly = NewAnomalyDetector(newCfg.Anomaly, m.alertMgr)
	m.Baseline = NewTrafficBaseline(newCfg.Baseline, m.alertMgr)

	// Update ban manager escalation params (don't recreate — preserve active bans)
	m.BanMgr.UpdateEscalation(
		newCfg.DDoS.BanDurationMinutes,
		newCfg.DDoS.EscalationMultiplier,
		newCfg.DDoS.MaxBanDurationHours,
	)
}

// Stats returns aggregated statistics from all sub-systems
func (m *Manager) Stats() SecurityStats {
	return SecurityStats{
		RateLimiter: m.RateLimiter.Stats(),
		DDoS:        m.DDoS.Stats(),
		BruteForce:  m.BruteForce.Stats(),
		PortScan:    m.PortScan.Stats(),
		Anomaly:     m.Anomaly.Stats(),
		Baseline:    m.Baseline.Stats(),
		Bans:        m.BanMgr.Stats(),
	}
}

// Stop shuts down all sub-systems
func (m *Manager) Stop() {
	m.RateLimiter.Stop()
	m.DDoS.Stop()
	m.BruteForce.Stop()
	m.PortScan.Stop()
	m.Anomaly.Stop()
	m.Baseline.Stop()
	m.BanMgr.Stop()
}

// checkDDoS runs protocol-specific flood detection
func (m *Manager) checkDDoS(srcIP, protocol string) SecurityVerdict {
	switch protocol {
	case "TCP":
		if isFlood, _ := m.DDoS.CheckSYN(srcIP); isFlood {
			return SecurityVerdict{
				Allowed:      false,
				Reason:       "SYN flood detected",
				DetectorName: "ddos_protection",
				IsDDoS:       true,
			}
		}
	case "UDP":
		if isFlood, _ := m.DDoS.CheckUDP(srcIP); isFlood {
			return SecurityVerdict{
				Allowed:      false,
				Reason:       "UDP flood detected",
				DetectorName: "ddos_protection",
				IsDDoS:       true,
			}
		}
	case "ICMP":
		if isFlood, _ := m.DDoS.CheckICMP(srcIP); isFlood {
			return SecurityVerdict{
				Allowed:      false,
				Reason:       "ICMP flood detected",
				DetectorName: "ddos_protection",
				IsDDoS:       true,
			}
		}
	}

	return SecurityVerdict{Allowed: true}
}

// checkBaselinePeriodically runs baseline deviation checks at intervals
func (m *Manager) checkBaselinePeriodically() {
	now := time.Now().Unix()

	m.baselineMu.Lock()
	if now-m.lastBaselineCheck < int64(m.cfg.Baseline.UpdateIntervalSeconds) {
		m.baselineMu.Unlock()
		return
	}
	m.lastBaselineCheck = now
	m.baselineMu.Unlock()

	// Non-blocking: just log deviations (don't block packets)
	m.Baseline.CheckDeviation()
}
