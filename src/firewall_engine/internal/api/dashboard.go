package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ============================================================================
// Dashboard Stats
// ============================================================================

// DashboardStats is the aggregated response for GET /api/v1/dashboard/stats.
// It pulls from all engine component Stats() methods into a single JSON payload
// suitable for the frontend dashboard KPI cards and summary grids.
type DashboardStats struct {
	// Top-level KPIs
	Uptime        string `json:"uptime"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	EngineVersion string `json:"engine_version"`

	// Alert stats
	Alerts AlertSummary `json:"alerts"`

	// Security detection stats
	Security SecuritySummary `json:"security"`

	// Domain filter stats
	Domains DomainSummary `json:"domains"`

	// GeoIP stats
	GeoIP GeoIPSummary `json:"geoip"`

	// Hot-reload stats
	Reloader ReloaderSummary `json:"reloader"`

	// Timestamp
	Timestamp string `json:"timestamp"`
}

// AlertSummary is a condensed view of alert manager stats.
type AlertSummary struct {
	Total      int64            `json:"total"`
	Written    int64            `json:"written"`
	Throttled  int64            `json:"throttled"`
	Errors     int64            `json:"errors"`
	BySeverity map[string]int64 `json:"by_severity"`
	ByType     map[string]int64 `json:"by_type"`
}

// SecuritySummary is a condensed view of security manager stats.
type SecuritySummary struct {
	ActiveBans   int64 `json:"active_bans"`
	TotalBans    int64 `json:"total_bans"`
	RateLimited  int64 `json:"rate_limited"`
	DDoSDetected int64 `json:"ddos_detected"`
	BruteForce   int64 `json:"brute_force_detected"`
	PortScans    int64 `json:"port_scans_detected"`
	BaselineDevs int64 `json:"baseline_deviations"`
}

// DomainSummary is a condensed view of domain filter stats.
type DomainSummary struct {
	BlockedDomains   int   `json:"blocked_domains"`
	Categories       int   `json:"categories_active"`
	CDNProviders     int   `json:"cdn_providers"`
	TotalChecks      int64 `json:"total_checks"`
	TotalBlocks      int64 `json:"total_blocks"`
	ThreatIntelHits  int64 `json:"threat_intel_hits"`
	ThreatIntelAvail bool  `json:"threat_intel_available"`
}

// GeoIPSummary is a condensed view of GeoIP checker stats.
type GeoIPSummary struct {
	Enabled      bool   `json:"enabled"`
	Mode         string `json:"mode"`
	Countries    int    `json:"countries_count"`
	ASNsBlocked  int    `json:"asns_blocked"`
	TotalChecks  int64  `json:"total_checks"`
	TotalBlocks  int64  `json:"total_blocks"`
	CacheHitRate string `json:"cache_hit_rate"`
}

// ReloaderSummary is a condensed view of hot-reloader stats.
type ReloaderSummary struct {
	Successes  int64  `json:"successes"`
	Failures   int64  `json:"failures"`
	LastReload string `json:"last_reload"`
	LastError  string `json:"last_error,omitempty"`
}

// handleDashboardStats handles GET /api/v1/dashboard/stats.
// Returns aggregated statistics from all engine components.
func (s *Server) handleDashboardStats(c *fiber.Ctx) error {
	stats := DashboardStats{
		Uptime:        time.Since(s.deps.StartTime).Truncate(time.Second).String(),
		UptimeSeconds: int64(time.Since(s.deps.StartTime).Seconds()),
		EngineVersion: s.getEngineVersion(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	// Alert stats
	if s.deps.AlertMgr != nil {
		as := s.deps.AlertMgr.GetStats()
		stats.Alerts = AlertSummary{
			Total:      as.TotalAlerts,
			Written:    as.Written,
			Throttled:  as.Throttled,
			Errors:     as.Errors,
			BySeverity: as.BySeverity,
			ByType:     as.ByType,
		}
	}

	// Security stats
	if s.deps.SecurityMgr != nil {
		ss := s.deps.SecurityMgr.Stats()
		stats.Security = SecuritySummary{
			ActiveBans:   ss.Bans.ActiveBans,
			TotalBans:    ss.Bans.TotalBans,
			RateLimited:  ss.RateLimiter.Denied,
			DDoSDetected: ss.DDoS.SYNDetections + ss.DDoS.UDPDetections + ss.DDoS.ICMPDetections,
			BruteForce:   ss.BruteForce.Detections,
			PortScans:    ss.PortScan.Detections,
			BaselineDevs: ss.Baseline.Deviations,
		}
	}

	// Domain filter stats
	if s.deps.DomainFilter != nil {
		ds := s.deps.DomainFilter.Stats()
		stats.Domains = DomainSummary{
			BlockedDomains:   ds.ConfigDomains,
			Categories:       ds.CategoriesActive,
			CDNProviders:     ds.CDNProviders,
			TotalChecks:      ds.TotalChecks,
			TotalBlocks:      ds.TotalBlocks,
			ThreatIntelHits:  ds.ThreatIntelHits,
			ThreatIntelAvail: ds.ThreatIntelAvail,
		}
	}

	// GeoIP stats
	if s.deps.GeoChecker != nil {
		gs := s.deps.GeoChecker.Stats()
		cacheHitRate := "0%"
		total := gs.CacheHits + gs.CacheMisses
		if total > 0 {
			pct := float64(gs.CacheHits) / float64(total) * 100
			cacheHitRate = fmt.Sprintf("%.1f%%", pct)
		}
		stats.GeoIP = GeoIPSummary{
			Enabled:      gs.Enabled,
			Mode:         gs.Mode,
			Countries:    gs.CountriesCount,
			ASNsBlocked:  gs.ASNsBlocked,
			TotalChecks:  gs.TotalChecks,
			TotalBlocks:  gs.TotalBlocks,
			CacheHitRate: cacheHitRate,
		}
	}

	// Reloader stats
	if s.deps.Reloader != nil {
		rs := s.deps.Reloader.Stats()
		lastReload := "never"
		if !rs.LastReload.IsZero() {
			lastReload = rs.LastReload.Format(time.RFC3339)
		}
		stats.Reloader = ReloaderSummary{
			Successes:  rs.Successes,
			Failures:   rs.Failures,
			LastReload: lastReload,
			LastError:  rs.LastError,
		}
	}

	return c.JSON(stats)
}

// ============================================================================
// Dashboard Threats
// ============================================================================

// ThreatEntry represents an active threat for the dashboard threat feed.
type ThreatEntry struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Duration  string `json:"duration"`
	Level     int    `json:"level"`
	Permanent bool   `json:"permanent"`
}

// RecentAlert is a simplified alert for the dashboard feed.
type RecentAlert struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Details   string `json:"details"`
	SourceIP  string `json:"source_ip,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Timestamp string `json:"timestamp"`
}

// DashboardThreats is the response for GET /api/v1/dashboard/threats.
type DashboardThreats struct {
	ActiveBans   []ThreatEntry `json:"active_bans"`
	RecentAlerts []RecentAlert `json:"recent_alerts"`
	TotalBans    int           `json:"total_bans"`
	TotalAlerts  int           `json:"total_alerts"`
}

// handleDashboardThreats handles GET /api/v1/dashboard/threats.
// Returns active bans and recent alerts for the threat feed.
func (s *Server) handleDashboardThreats(c *fiber.Ctx) error {
	response := DashboardThreats{
		ActiveBans:   make([]ThreatEntry, 0),
		RecentAlerts: make([]RecentAlert, 0),
	}

	// Get active bans
	if s.deps.SecurityMgr != nil && s.deps.SecurityMgr.BanMgr != nil {
		bans := s.deps.SecurityMgr.BanMgr.GetActiveBans()
		for _, ban := range bans {
			entry := ThreatEntry{
				IP:        ban.IP,
				Reason:    ban.Reason,
				BannedAt:  ban.BannedAt.Format(time.RFC3339),
				Duration:  ban.Duration.String(),
				Level:     ban.Level,
				Permanent: ban.Permanent,
			}
			if !ban.ExpiresAt.IsZero() {
				entry.ExpiresAt = ban.ExpiresAt.Format(time.RFC3339)
			}
			response.ActiveBans = append(response.ActiveBans, entry)
		}
		response.TotalBans = len(response.ActiveBans)
	}

	// Get recent alerts from log files
	recentAlerts, err := s.readRecentAlerts(50)
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to read recent alerts for dashboard")
		// Non-fatal — still return bans data
	} else {
		response.RecentAlerts = recentAlerts
		response.TotalAlerts = len(recentAlerts)
	}

	return c.JSON(response)
}

// ============================================================================
// Alert file reading
// ============================================================================

// readRecentAlerts reads the most recent N alerts from the alert log directory.
// Alert logs are JSON-lines files in data/logs/firewall-alerts/.
// Returns alerts sorted by timestamp (newest first).
func (s *Server) readRecentAlerts(limit int) ([]RecentAlert, error) {
	alertDir := s.getAlertLogDir()
	if alertDir == "" {
		return nil, fmt.Errorf("alert log directory not configured")
	}

	// Find all alert log files
	entries, err := os.ReadDir(alertDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No alerts yet — not an error
		}
		return nil, fmt.Errorf("failed to read alert directory %s: %w", alertDir, err)
	}

	// Sort files by modification time (newest first)
	type fileInfo struct {
		name    string
		modTime time.Time
	}
	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{name: entry.Name(), modTime: info.ModTime()})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	// Read alerts from files until we have enough
	var alerts []RecentAlert
	for _, f := range files {
		if len(alerts) >= limit {
			break
		}

		filePath := filepath.Join(alertDir, f.name)
		fileAlerts, err := s.readAlertFile(filePath, limit-len(alerts))
		if err != nil {
			s.logger.Warn().Err(err).Str("file", f.name).Msg("Failed to read alert file")
			continue
		}
		alerts = append(alerts, fileAlerts...)
	}

	// Sort all collected alerts by timestamp (newest first)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp > alerts[j].Timestamp
	})

	// Trim to limit
	if len(alerts) > limit {
		alerts = alerts[:limit]
	}

	return alerts, nil
}

// readAlertFile reads up to N alerts from a single JSON-lines alert file.
// It reads the file from the end to get the newest entries first.
func (s *Server) readAlertFile(path string, limit int) ([]RecentAlert, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open alert file: %w", err)
	}
	defer file.Close()

	// Read all lines (alert files are typically small — <100MB)
	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan alert file: %w", err)
	}

	// Process from the end (newest alerts last in file)
	var alerts []RecentAlert
	for i := len(lines) - 1; i >= 0 && len(alerts) < limit; i-- {
		alert, err := parseAlertLine(lines[i])
		if err != nil {
			continue // Skip malformed lines
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// parseAlertLine parses a single JSON line from an alert log file.
func parseAlertLine(line string) (RecentAlert, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return RecentAlert{}, fmt.Errorf("invalid JSON: %w", err)
	}

	alert := RecentAlert{
		ID:        getString(raw, "id"),
		Type:      getString(raw, "type"),
		Severity:  getString(raw, "severity"),
		Details:   getString(raw, "details"),
		SourceIP:  getString(raw, "source_ip"),
		Domain:    getString(raw, "domain"),
		Timestamp: getString(raw, "timestamp"),
	}

	// Fallback: try nested source object
	if alert.SourceIP == "" {
		if src, ok := raw["source"].(map[string]interface{}); ok {
			alert.SourceIP = getString(src, "ip")
		}
	}

	return alert, nil
}

// ============================================================================
// Helpers
// ============================================================================

// getEngineVersion returns the configured engine version string.
func (s *Server) getEngineVersion() string {
	if s.deps.Config != nil && s.deps.Config.Firewall != nil {
		return s.deps.Config.Firewall.Engine.Version
	}
	return "unknown"
}

// getAlertLogDir returns the resolved alert log directory path.
func (s *Server) getAlertLogDir() string {
	if s.deps.Config == nil {
		return ""
	}
	dir, err := s.deps.Config.AlertLogDir()
	if err != nil {
		return ""
	}
	return dir
}

// getString safely extracts a string from a map.
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}
