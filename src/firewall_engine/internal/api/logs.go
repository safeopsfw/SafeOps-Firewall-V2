package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ============================================================================
// Verdict Log Viewer — GET /api/v1/logs/verdicts
// ============================================================================

// VerdictEntry mirrors the SOC JSONL firewall log fields (short names from verdict_logger.go).
type VerdictEntry struct {
	Timestamp   string `json:"ts"`
	EventType   string `json:"event_type,omitempty"`
	SrcIP       string `json:"src"`
	SrcPort     uint32 `json:"sp"`
	DstIP       string `json:"dst"`
	DstPort     uint32 `json:"dp"`
	Proto       string `json:"proto"`
	Action      string `json:"action"`
	Detector    string `json:"detector"`
	Domain      string `json:"domain,omitempty"`
	Reason      string `json:"reason"`
	Size        uint32 `json:"size,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Direction   string `json:"dir,omitempty"`
	TrafficType string `json:"ttype,omitempty"`
	CommunityID string `json:"cid,omitempty"`
	FlowID      uint64 `json:"flow_id,omitempty"`
	SrcGeo      string `json:"src_geo,omitempty"`
	DstGeo      string `json:"dst_geo,omitempty"`
	SrcASN      string `json:"src_asn,omitempty"`
	DstASN      string `json:"dst_asn,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// VerdictLogResponse is the response for GET /api/v1/logs/verdicts.
type VerdictLogResponse struct {
	Verdicts []VerdictEntry `json:"verdicts"`
	Total    int            `json:"total"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
}

// handleGetVerdictLogs handles GET /api/v1/logs/verdicts.
// Query params: limit (default 100), offset (default 0), action (DROP|BLOCK|REDIRECT filter).
func (s *Server) handleGetVerdictLogs(c *fiber.Ctx) error {
	limit := 100
	offset := 0
	actionFilter := ""

	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 10000 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	if a := c.Query("action"); a != "" {
		actionFilter = strings.ToUpper(a)
	}

	logDir := s.getVerdictLogDir()
	if logDir == "" {
		return respondError(c, fiber.StatusServiceUnavailable, "unavailable",
			"Verdict log directory not configured")
	}

	entries, err := readVerdictLogs(logDir, limit+offset, actionFilter)
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to read verdict logs")
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read verdict logs: "+err.Error())
	}

	total := len(entries)

	// Apply offset
	if offset >= len(entries) {
		entries = []VerdictEntry{}
	} else {
		entries = entries[offset:]
	}

	// Apply limit
	if len(entries) > limit {
		entries = entries[:limit]
	}

	return c.JSON(VerdictLogResponse{
		Verdicts: entries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	})
}

// getVerdictLogDir returns the path to the verdict log directory.
// Verdict logs live one level up from the config dir, under logs/.
func (s *Server) getVerdictLogDir() string {
	if s.deps.Config == nil {
		return ""
	}
	// ConfigDir is bin/firewall-engine/configs → go up one level to bin/firewall-engine/, then logs/
	// but verdicts are in bin/logs/firewall-verdicts.jsonl per memory notes
	// Use DataDir if available, else try relative
	configDir := s.deps.Config.ConfigDir
	if configDir == "" {
		return ""
	}
	// bin/firewall-engine/configs → bin/logs/
	return filepath.Join(filepath.Dir(configDir), "..", "logs")
}

// readVerdictLogs reads firewall log entries from plain JSONL files.
// Returns entries sorted newest-first, up to maxEntries, optionally filtered by action.
func readVerdictLogs(logDir string, maxEntries int, actionFilter string) ([]VerdictEntry, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []VerdictEntry{}, nil
		}
		return nil, fmt.Errorf("read log dir: %w", err)
	}

	// Collect firewall log files (active + rotated plain JSONL)
	type fileEntry struct {
		name    string
		modTime time.Time
	}
	var files []fileEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "firewall") {
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileEntry{name: name, modTime: info.ModTime()})
	}

	// Sort newest first
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	var verdicts []VerdictEntry
	for _, f := range files {
		if len(verdicts) >= maxEntries {
			break
		}
		path := filepath.Join(logDir, f.name)
		fileVerdicts, err := readVerdictFile(path, maxEntries-len(verdicts), actionFilter)
		if err != nil {
			continue // skip unreadable files
		}
		verdicts = append(verdicts, fileVerdicts...)
	}

	return verdicts, nil
}

// readVerdictFile reads firewall log entries from a single plain JSONL file.
func readVerdictFile(path string, limit int, actionFilter string) ([]VerdictEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Read from end (newest last in file)
	var entries []VerdictEntry
	for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
		var v VerdictEntry
		if err := json.Unmarshal([]byte(lines[i]), &v); err != nil {
			continue
		}
		if actionFilter != "" && !strings.EqualFold(v.Action, actionFilter) {
			continue
		}
		entries = append(entries, v)
	}

	return entries, nil
}

// ============================================================================
// Real-time Stats — GET /api/v1/stats/realtime
// ============================================================================

// handleRealtimeStats handles GET /api/v1/stats/realtime.
// Returns a lightweight snapshot of current engine metrics.
func (s *Server) handleRealtimeStats(c *fiber.Ctx) error {
	resp := fiber.Map{
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(s.deps.StartTime).Seconds()),
		"ws_clients":     s.hub.ClientCount(),
	}

	if s.deps.SecurityMgr != nil {
		ss := s.deps.SecurityMgr.Stats()
		resp["security"] = fiber.Map{
			"active_bans":   ss.Bans.ActiveBans,
			"rate_limited":  ss.RateLimiter.Denied,
			"ddos_detected": ss.DDoS.SYNDetections + ss.DDoS.UDPDetections + ss.DDoS.ICMPDetections,
		}
	}

	if s.deps.DomainFilter != nil {
		ds := s.deps.DomainFilter.Stats()
		resp["domains"] = fiber.Map{
			"total_checks": ds.TotalChecks,
			"total_blocks": ds.TotalBlocks,
		}
	}

	if s.deps.AlertMgr != nil {
		as := s.deps.AlertMgr.GetStats()
		resp["alerts"] = fiber.Map{
			"total":     as.TotalAlerts,
			"throttled": as.Throttled,
		}
	}

	return c.JSON(resp)
}
