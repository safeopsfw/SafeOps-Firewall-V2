package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ============================================================================
// Alert Listing
// ============================================================================

// AlertListResponse is the response for GET /api/v1/alerts.
type AlertListResponse struct {
	Alerts     []AlertEntry `json:"alerts"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
	Filters    AlertFilters `json:"filters"`
}

// AlertEntry is a full alert with triage status and threat intel links.
type AlertEntry struct {
	// Core alert fields (from JSON-lines log)
	ID        string `json:"id"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Details   string `json:"details"`
	Timestamp string `json:"timestamp"`

	// Source info
	SourceIP   string `json:"source_ip,omitempty"`
	SourcePort int    `json:"source_port,omitempty"`
	DestIP     string `json:"dest_ip,omitempty"`
	DestPort   int    `json:"dest_port,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

	// GeoIP enrichment
	GeoInfo *AlertGeoInfo `json:"geo_info,omitempty"`

	// Action taken
	Action      string  `json:"action,omitempty"`
	ThreatScore float64 `json:"threat_score,omitempty"`

	// Metadata
	Meta map[string]string `json:"meta,omitempty"`

	// Triage (from in-memory store)
	Triage *TriageStatus `json:"triage,omitempty"`

	// Threat Intel integration — external lookup links
	ThreatIntelLinks *ThreatIntelLinks `json:"threat_intel_links,omitempty"`
}

// AlertGeoInfo holds geo enrichment data embedded in alerts.
type AlertGeoInfo struct {
	CountryCode string `json:"country_code,omitempty"`
	ASN         uint32 `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
}

// ThreatIntelLinks provides clickable external lookup links for an IOC.
type ThreatIntelLinks struct {
	VirusTotal string `json:"virustotal,omitempty"`
	AbuseIPDB  string `json:"abuseipdb,omitempty"`
	Shodan     string `json:"shodan,omitempty"`
	URLScan    string `json:"urlscan,omitempty"`
	OTX        string `json:"otx,omitempty"`
	GreyNoise  string `json:"greynoise,omitempty"`
}

// AlertFilters is the set of available filter values for the UI.
type AlertFilters struct {
	Severities []string `json:"severities"`
	Types      []string `json:"types"`
}

// handleGetAlerts handles GET /api/v1/alerts.
// Supports query parameters: page, page_size, severity, type, ip, domain, from, to.
func (s *Server) handleGetAlerts(c *fiber.Ctx) error {
	// Parse pagination
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}

	// Parse filters
	severityFilter := strings.ToLower(c.Query("severity", ""))
	typeFilter := strings.ToLower(c.Query("type", ""))
	ipFilter := c.Query("ip", "")
	domainFilter := strings.ToLower(c.Query("domain", ""))
	fromFilter := c.Query("from", "")
	toFilter := c.Query("to", "")

	// Parse time filters
	var fromTime, toTime time.Time
	if fromFilter != "" {
		if t, err := time.Parse(time.RFC3339, fromFilter); err == nil {
			fromTime = t
		}
	}
	if toFilter != "" {
		if t, err := time.Parse(time.RFC3339, toFilter); err == nil {
			toTime = t
		}
	}

	// Read all alerts from log files
	allAlerts, err := s.readAllAlerts(1000) // Read up to 1000 recent alerts
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to read alerts")
		allAlerts = []AlertEntry{}
	}

	// Apply filters
	filtered := make([]AlertEntry, 0, len(allAlerts))
	for _, alert := range allAlerts {
		if !matchesAlertFilters(alert, severityFilter, typeFilter, ipFilter, domainFilter, fromTime, toTime) {
			continue
		}

		// Enrich with triage status
		if triage := s.triage.Get(alert.ID); triage != nil {
			alert.Triage = triage
		}

		// Add threat intel links for IPs and domains
		alert.ThreatIntelLinks = buildThreatIntelLinks(alert.SourceIP, alert.Domain)

		filtered = append(filtered, alert)
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp > filtered[j].Timestamp
	})

	// Paginate
	total := len(filtered)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	// Collect available filter values
	filterValues := collectFilterValues(allAlerts)

	return c.JSON(AlertListResponse{
		Alerts:     filtered[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		Filters:    filterValues,
	})
}

// ============================================================================
// Alert Detail
// ============================================================================

// handleGetAlert handles GET /api/v1/alerts/:id.
func (s *Server) handleGetAlert(c *fiber.Ctx) error {
	alertID := c.Params("id")
	if alertID == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Alert ID is required")
	}

	// Search all alerts for the matching ID
	allAlerts, err := s.readAllAlerts(2000)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to read alert logs")
	}

	for _, alert := range allAlerts {
		if alert.ID == alertID {
			// Enrich
			if triage := s.triage.Get(alert.ID); triage != nil {
				alert.Triage = triage
			}
			alert.ThreatIntelLinks = buildThreatIntelLinks(alert.SourceIP, alert.Domain)
			return c.JSON(alert)
		}
	}

	return respondError(c, fiber.StatusNotFound, "not_found",
		fmt.Sprintf("Alert %s not found", alertID))
}

// ============================================================================
// Alert Triage
// ============================================================================

// TriageRequest is the request body for POST /api/v1/alerts/:id/triage.
type TriageRequest struct {
	Status       string `json:"status"`        // new, acknowledged, escalated, dismissed, resolved
	Analyst      string `json:"analyst"`       // who is triaging
	Notes        string `json:"notes"`         // triage notes
	LinkedTicket string `json:"linked_ticket"` // link to a ticket ID
}

// handleTriageAlert handles POST /api/v1/alerts/:id/triage.
func (s *Server) handleTriageAlert(c *fiber.Ctx) error {
	alertID := c.Params("id")
	if alertID == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Alert ID is required")
	}

	var req TriageRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	// Validate status
	validStatuses := map[string]bool{
		"new": true, "acknowledged": true, "escalated": true,
		"dismissed": true, "resolved": true,
	}
	if !validStatuses[req.Status] {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			fmt.Sprintf("Invalid triage status %q. Valid: new, acknowledged, escalated, dismissed, resolved", req.Status))
	}

	// Store triage status
	status := &TriageStatus{
		AlertID:      alertID,
		Status:       req.Status,
		Analyst:      req.Analyst,
		Notes:        req.Notes,
		LinkedTicket: req.LinkedTicket,
		UpdatedAt:    time.Now(),
	}
	s.triage.Set(status)

	// Broadcast triage event via WebSocket
	s.hub.BroadcastEvent("alert_triage", map[string]interface{}{
		"alert_id": alertID,
		"status":   req.Status,
		"analyst":  req.Analyst,
	})

	s.logger.Info().
		Str("alert_id", alertID).
		Str("status", req.Status).
		Str("analyst", req.Analyst).
		Msg("Alert triaged")

	return c.JSON(fiber.Map{
		"message":  "Alert triaged successfully",
		"alert_id": alertID,
		"triage":   status,
	})
}

// ============================================================================
// Internal helpers
// ============================================================================

// readAllAlerts reads all alerts and converts them to AlertEntry format.
func (s *Server) readAllAlerts(limit int) ([]AlertEntry, error) {
	recent, err := s.readRecentAlerts(limit)
	if err != nil {
		return nil, err
	}

	entries := make([]AlertEntry, 0, len(recent))
	for _, r := range recent {
		entries = append(entries, AlertEntry{
			ID:        r.ID,
			Type:      r.Type,
			Severity:  r.Severity,
			Details:   r.Details,
			SourceIP:  r.SourceIP,
			Domain:    r.Domain,
			Timestamp: r.Timestamp,
		})
	}
	return entries, nil
}

// matchesAlertFilters checks if an alert matches all active filters.
func matchesAlertFilters(alert AlertEntry, severity, alertType, ip, domain string, from, to time.Time) bool {
	if severity != "" && strings.ToLower(alert.Severity) != severity {
		return false
	}
	if alertType != "" && strings.ToLower(alert.Type) != alertType {
		return false
	}
	if ip != "" && !strings.Contains(alert.SourceIP, ip) {
		return false
	}
	if domain != "" && !strings.Contains(strings.ToLower(alert.Domain), domain) {
		return false
	}

	// Time range filter
	if !from.IsZero() || !to.IsZero() {
		alertTime, err := time.Parse(time.RFC3339, alert.Timestamp)
		if err == nil {
			if !from.IsZero() && alertTime.Before(from) {
				return false
			}
			if !to.IsZero() && alertTime.After(to) {
				return false
			}
		}
	}

	return true
}

// collectFilterValues extracts unique filter values from a list of alerts.
func collectFilterValues(alerts []AlertEntry) AlertFilters {
	sevSet := make(map[string]bool)
	typeSet := make(map[string]bool)

	for _, a := range alerts {
		if a.Severity != "" {
			sevSet[a.Severity] = true
		}
		if a.Type != "" {
			typeSet[a.Type] = true
		}
	}

	var sevs, types []string
	for s := range sevSet {
		sevs = append(sevs, s)
	}
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(sevs)
	sort.Strings(types)

	return AlertFilters{
		Severities: sevs,
		Types:      types,
	}
}

// buildThreatIntelLinks generates external threat intel lookup links for an IOC.
// Supports IP addresses and domains.
func buildThreatIntelLinks(ip, domain string) *ThreatIntelLinks {
	if ip == "" && domain == "" {
		return nil
	}

	links := &ThreatIntelLinks{}

	if ip != "" {
		encodedIP := url.PathEscape(ip)
		links.VirusTotal = "https://www.virustotal.com/gui/ip-address/" + encodedIP
		links.AbuseIPDB = "https://www.abuseipdb.com/check/" + encodedIP
		links.Shodan = "https://www.shodan.io/host/" + encodedIP
		links.GreyNoise = "https://viz.greynoise.io/ip/" + encodedIP
		links.OTX = "https://otx.alienvault.com/indicator/ip/" + encodedIP
	}

	if domain != "" {
		encodedDomain := url.PathEscape(domain)
		if links.VirusTotal == "" {
			links.VirusTotal = "https://www.virustotal.com/gui/domain/" + encodedDomain
		}
		links.URLScan = "https://urlscan.io/search/#domain:" + encodedDomain
		if links.OTX == "" {
			links.OTX = "https://otx.alienvault.com/indicator/domain/" + encodedDomain
		}
	}

	return links
}

// parseAlertLineToEntry parses a JSON-lines alert into a full AlertEntry.
func parseAlertLineToEntry(line string) (AlertEntry, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return AlertEntry{}, err
	}

	entry := AlertEntry{
		ID:        getString(raw, "id"),
		Type:      getString(raw, "type"),
		Severity:  getString(raw, "severity"),
		Details:   getString(raw, "details"),
		Timestamp: getString(raw, "timestamp"),
		Domain:    getString(raw, "domain"),
		Action:    getString(raw, "action"),
		Protocol:  getString(raw, "protocol"),
	}

	// Source (can be nested)
	if src, ok := raw["source"].(map[string]interface{}); ok {
		entry.SourceIP = getString(src, "ip")
		if port, ok := src["port"].(float64); ok {
			entry.SourcePort = int(port)
		}
	} else {
		entry.SourceIP = getString(raw, "source_ip")
	}

	// Destination (can be nested)
	if dst, ok := raw["destination"].(map[string]interface{}); ok {
		entry.DestIP = getString(dst, "ip")
		if port, ok := dst["port"].(float64); ok {
			entry.DestPort = int(port)
		}
	}

	// Threat score
	if score, ok := raw["threat_score"].(float64); ok {
		entry.ThreatScore = score
	}

	// GeoIP enrichment
	if geo, ok := raw["geo_info"].(map[string]interface{}); ok {
		entry.GeoInfo = &AlertGeoInfo{
			CountryCode: getString(geo, "country_code"),
			ASNOrg:      getString(geo, "asn_org"),
		}
		if asn, ok := geo["asn"].(float64); ok {
			entry.GeoInfo.ASN = uint32(asn)
		}
	}

	// Metadata
	if meta, ok := raw["meta"].(map[string]interface{}); ok {
		entry.Meta = make(map[string]string)
		for k, v := range meta {
			entry.Meta[k] = fmt.Sprintf("%v", v)
		}
	}

	return entry, nil
}
