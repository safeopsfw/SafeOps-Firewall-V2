package security

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
)

// AnomalyDetector detects:
// 1. Protocol violations (SYN+FIN, Xmas, Null scans)
// 2. Packet size anomalies (zero-byte, oversized)
// 3. Beaconing/C2 activity (regular interval callbacks)
type AnomalyDetector struct {
	cfg      config.AnomalyConfig
	alertMgr *alerting.Manager

	// beaconTrackers: "srcIP:dstIP" -> *beaconTracker
	beaconTrackers sync.Map

	protocolViolations atomic.Int64
	sizeAnomalies      atomic.Int64
	beaconingAlerts    atomic.Int64

	cancel chan struct{}
	wg     sync.WaitGroup
}

// beaconTracker tracks connection intervals for C2/beaconing detection
type beaconTracker struct {
	mu        sync.Mutex
	intervals []float64 // seconds between connections
	lastTime  int64     // unix nanoseconds
	lastSeen  atomic.Int64
}

// AnomalyType classifies the anomaly
type AnomalyType string

const (
	AnomalySYNFIN   AnomalyType = "SYN_FIN"
	AnomalyXmas     AnomalyType = "XMAS_SCAN"
	AnomalyNull     AnomalyType = "NULL_SCAN"
	AnomalyZeroByte AnomalyType = "ZERO_BYTE"
	AnomalyOversized AnomalyType = "OVERSIZED"
	AnomalyBeaconing AnomalyType = "BEACONING"
)

// AnomalyResult is returned when an anomaly is detected
type AnomalyResult struct {
	Detected    bool
	AnomalyType AnomalyType
	Details     string
	Severity    alerting.Severity
}

// AnomalyStats holds detection statistics
type AnomalyStats struct {
	ProtocolViolations int64 `json:"protocol_violations"`
	SizeAnomalies      int64 `json:"size_anomalies"`
	BeaconingAlerts    int64 `json:"beaconing_alerts"`
}

// TCP flag constants
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(cfg config.AnomalyConfig, alertMgr *alerting.Manager) *AnomalyDetector {
	d := &AnomalyDetector{
		cfg:      cfg,
		alertMgr: alertMgr,
		cancel:   make(chan struct{}),
	}

	// Cleanup goroutine every 60s
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.cleanupLoop()
	}()

	return d
}

// CheckTCPFlags checks for protocol violations in TCP flags.
// flags is the raw TCP flags byte.
func (d *AnomalyDetector) CheckTCPFlags(srcIP string, flags uint8) AnomalyResult {
	if !d.cfg.Enabled || !d.cfg.EnableProtocolViolations {
		return AnomalyResult{}
	}

	// SYN+FIN: should never appear together
	if flags&TCPFlagSYN != 0 && flags&TCPFlagFIN != 0 {
		d.protocolViolations.Add(1)
		result := AnomalyResult{
			Detected:    true,
			AnomalyType: AnomalySYNFIN,
			Details:     "SYN+FIN flags set simultaneously — likely OS fingerprinting or evasion",
			Severity:    alerting.SeverityHigh,
		}
		d.fireProtocolAlert(srcIP, result)
		return result
	}

	// Xmas scan: FIN+PSH+URG
	if flags&TCPFlagFIN != 0 && flags&TCPFlagPSH != 0 && flags&TCPFlagURG != 0 {
		d.protocolViolations.Add(1)
		result := AnomalyResult{
			Detected:    true,
			AnomalyType: AnomalyXmas,
			Details:     "Xmas scan detected — FIN+PSH+URG flags set",
			Severity:    alerting.SeverityHigh,
		}
		d.fireProtocolAlert(srcIP, result)
		return result
	}

	// Null scan: no flags set at all
	if flags == 0 {
		d.protocolViolations.Add(1)
		result := AnomalyResult{
			Detected:    true,
			AnomalyType: AnomalyNull,
			Details:     "Null scan detected — no TCP flags set",
			Severity:    alerting.SeverityMedium,
		}
		d.fireProtocolAlert(srcIP, result)
		return result
	}

	return AnomalyResult{}
}

// CheckPacketSize checks for packet size anomalies.
// size is the total packet size in bytes.
func (d *AnomalyDetector) CheckPacketSize(srcIP string, size int) AnomalyResult {
	if !d.cfg.Enabled || !d.cfg.EnablePacketSize {
		return AnomalyResult{}
	}

	// Zero-byte payload (excluding headers)
	if size == 0 {
		// Zero-byte isn't always malicious (keepalives, ACKs), don't alert
		return AnomalyResult{}
	}

	// Oversized packet
	if d.cfg.OversizedPacketBytes > 0 && size > d.cfg.OversizedPacketBytes {
		d.sizeAnomalies.Add(1)
		result := AnomalyResult{
			Detected:    true,
			AnomalyType: AnomalyOversized,
			Details:     fmt.Sprintf("Oversized packet: %d bytes (threshold: %d)", size, d.cfg.OversizedPacketBytes),
			Severity:    alerting.SeverityLow,
		}
		d.fireSizeAlert(srcIP, result)
		return result
	}

	return AnomalyResult{}
}

// RecordConnection records a connection for beaconing detection.
// Call this for each new connection from srcIP to dstIP.
// Returns a result if beaconing is detected.
func (d *AnomalyDetector) RecordConnection(srcIP, dstIP string) AnomalyResult {
	if !d.cfg.Enabled || !d.cfg.EnableBeaconing {
		return AnomalyResult{}
	}

	key := srcIP + ":" + dstIP
	now := time.Now().UnixNano()

	val, loaded := d.beaconTrackers.LoadOrStore(key, &beaconTracker{
		intervals: make([]float64, 0, d.cfg.BeaconingMinSamples+1),
		lastTime:  now,
	})
	tracker := val.(*beaconTracker)
	tracker.lastSeen.Store(time.Now().Unix())

	if !loaded {
		// First connection, nothing to compare
		return AnomalyResult{}
	}

	tracker.mu.Lock()

	// Calculate interval since last connection
	intervalSec := float64(now-tracker.lastTime) / float64(time.Second)
	tracker.lastTime = now

	// Only track intervals > 1 second (ignore bursts)
	if intervalSec >= 1.0 {
		tracker.intervals = append(tracker.intervals, intervalSec)

		// Keep last N*2 intervals to avoid unbounded growth
		maxKeep := d.cfg.BeaconingMinSamples * 2
		if len(tracker.intervals) > maxKeep {
			tracker.intervals = tracker.intervals[len(tracker.intervals)-maxKeep:]
		}
	}

	intervals := tracker.intervals
	tracker.mu.Unlock()

	// Need minimum samples before checking
	if len(intervals) < d.cfg.BeaconingMinSamples {
		return AnomalyResult{}
	}

	// Calculate coefficient of variation (CoV = stddev / mean)
	// Low CoV means very regular intervals — characteristic of C2 beaconing
	cov := coefficientOfVariation(intervals)

	if cov < d.cfg.BeaconingCOVThreshold && cov >= 0 {
		d.beaconingAlerts.Add(1)
		meanInterval := mean(intervals)

		result := AnomalyResult{
			Detected:    true,
			AnomalyType: AnomalyBeaconing,
			Details: fmt.Sprintf("Beaconing detected %s→%s: CoV=%.4f (threshold: %.2f), mean interval=%.1fs, %d samples",
				srcIP, dstIP, cov, d.cfg.BeaconingCOVThreshold, meanInterval, len(intervals)),
			Severity: alerting.SeverityCritical,
		}
		d.fireBeaconingAlert(srcIP, dstIP, result, cov, meanInterval)

		// Clear intervals after detection
		tracker.mu.Lock()
		tracker.intervals = tracker.intervals[:0]
		tracker.mu.Unlock()

		return result
	}

	return AnomalyResult{}
}

// Stats returns detection statistics
func (d *AnomalyDetector) Stats() AnomalyStats {
	return AnomalyStats{
		ProtocolViolations: d.protocolViolations.Load(),
		SizeAnomalies:      d.sizeAnomalies.Load(),
		BeaconingAlerts:    d.beaconingAlerts.Load(),
	}
}

// Stop halts the cleanup goroutine
func (d *AnomalyDetector) Stop() {
	close(d.cancel)
	d.wg.Wait()
}

func (d *AnomalyDetector) fireProtocolAlert(srcIP string, result AnomalyResult) {
	if d.alertMgr == nil {
		return
	}

	alert := alerting.NewAlert(alerting.AlertProtocol, result.Severity).
		WithSource(srcIP, 0).
		WithDetails(result.Details).
		WithAction(alerting.ActionDropped).
		WithMeta("anomaly_type", string(result.AnomalyType)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *AnomalyDetector) fireSizeAlert(srcIP string, result AnomalyResult) {
	if d.alertMgr == nil {
		return
	}

	alert := alerting.NewAlert(alerting.AlertAnomaly, result.Severity).
		WithSource(srcIP, 0).
		WithDetails(result.Details).
		WithAction(alerting.ActionLogged).
		WithMeta("anomaly_type", string(result.AnomalyType)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *AnomalyDetector) fireBeaconingAlert(srcIP, dstIP string, result AnomalyResult, cov, meanInterval float64) {
	if d.alertMgr == nil {
		return
	}

	alert := alerting.NewAlert(alerting.AlertBeaconing, result.Severity).
		WithSource(srcIP, 0).
		WithDestination(dstIP, 0).
		WithDetails(result.Details).
		WithAction(alerting.ActionBanned).
		WithMeta("cov", fmt.Sprintf("%.4f", cov)).
		WithMeta("mean_interval", fmt.Sprintf("%.1f", meanInterval)).
		Build()

	d.alertMgr.Alert(alert)
}

func (d *AnomalyDetector) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.cancel:
			return
		case <-ticker.C:
			// Remove beacon trackers inactive for 10 minutes
			cutoff := time.Now().Unix() - 600

			d.beaconTrackers.Range(func(key, value interface{}) bool {
				tracker := value.(*beaconTracker)
				if tracker.lastSeen.Load() < cutoff {
					d.beaconTrackers.Delete(key)
				}
				return true
			})
		}
	}
}

// coefficientOfVariation calculates CoV = stddev / mean
func coefficientOfVariation(values []float64) float64 {
	if len(values) == 0 {
		return -1
	}

	m := mean(values)
	if m == 0 {
		return -1
	}

	variance := 0.0
	for _, v := range values {
		diff := v - m
		variance += diff * diff
	}
	variance /= float64(len(values))

	return math.Sqrt(variance) / m
}

// mean calculates the arithmetic mean
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
