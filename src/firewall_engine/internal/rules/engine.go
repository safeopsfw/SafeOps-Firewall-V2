// Package rules provides a custom detection rule engine for the SafeOps Firewall Engine.
// It allows users to define detection rules in TOML config files that match packet metadata
// and trigger alerts, logging, drops, or IP bans.
package rules

import (
	"firewall_engine/internal/alerting"
	"firewall_engine/internal/security"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
)

// Rule represents a single detection rule with match conditions and actions.
type Rule struct {
	Name        string   `toml:"name"`
	Description string   `toml:"description"`
	Enabled     bool     `toml:"enabled"`
	Severity    string   `toml:"severity"` // LOW, MEDIUM, HIGH, CRITICAL

	// Match conditions (all specified conditions must match = AND logic)
	DstPort    []int    `toml:"dst_port"`     // match any of these dst ports
	SrcPort    []int    `toml:"src_port"`     // match any of these src ports
	Protocol   string   `toml:"protocol"`     // "TCP", "UDP", "ICMP", "" = any
	Direction  string   `toml:"direction"`    // "INBOUND", "OUTBOUND", "" = any
	DstIP      []string `toml:"dst_ip"`       // match any of these dst IPs
	SrcIP      []string `toml:"src_ip"`       // match any of these src IPs
	SrcNotCIDR []string `toml:"src_not_cidr"` // src must NOT be in these CIDRs
	DstNotCIDR []string `toml:"dst_not_cidr"` // dst must NOT be in these CIDRs
	Domain     []string `toml:"domain"`       // match these domains (substring)
	TCPFlags   string   `toml:"tcp_flags"`    // "SYN", "SYN+ACK", "FIN", etc.

	// Threshold (optional — if set, must reach count within window to trigger)
	ThresholdCount   int    `toml:"threshold_count"`
	ThresholdWindow  int    `toml:"threshold_window_seconds"`
	ThresholdGroupBy string `toml:"threshold_group_by"` // "src_ip", "dst_ip", "src_ip+dst_port"

	// Action
	Action      string `toml:"action"`        // "ALERT", "LOG", "DROP", "BAN"
	BanDuration string `toml:"ban_duration"`  // e.g. "30m", "2h" (only for BAN action)
	AlertType   string `toml:"alert_type"`    // Override alert type, default "CUSTOM_RULE"
}

// RulesConfig is the top-level TOML configuration structure.
type RulesConfig struct {
	Rule []Rule `toml:"rule"`
}

// PacketInfo contains packet metadata for rule evaluation.
type PacketInfo struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint32
	DstPort   uint32
	Protocol  string // "TCP", "UDP", "ICMP"
	Direction string // "INBOUND", "OUTBOUND"
	Domain    string
	TCPFlags  uint8
	Size      int
}

// RuleMatch represents the result of evaluating a packet against a rule.
type RuleMatch struct {
	Matched     bool
	Rule        *Rule
	Description string
}

// Engine is the main detection rule engine.
type Engine struct {
	rules      []Rule
	parsedNets map[int][]*net.IPNet // rule index -> parsed CIDRs for src_not_cidr/dst_not_cidr
	alertMgr   *alerting.Manager
	banMgr     *security.BanManager

	// Threshold tracking: key = "ruleIndex:groupValue" -> *thresholdTracker
	thresholds sync.Map

	// Stats
	totalChecks  atomic.Int64
	totalMatches atomic.Int64
	ruleHits     sync.Map // ruleName -> *atomic.Int64

	mu sync.RWMutex
}

// thresholdTracker tracks event counts within time windows for threshold-based rules.
type thresholdTracker struct {
	mu        sync.Mutex
	count     int64
	windowEnd int64 // unix timestamp when window expires
}

// NewEngine creates a new rule engine from the specified TOML configuration file.
// If the file doesn't exist, returns an engine with empty rules (not an error).
func NewEngine(configPath string, alertMgr *alerting.Manager, banMgr *security.BanManager) (*Engine, error) {
	e := &Engine{
		rules:      []Rule{},
		parsedNets: make(map[int][]*net.IPNet),
		alertMgr:   alertMgr,
		banMgr:     banMgr,
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// File doesn't exist - return empty engine (not an error)
		return e, nil
	}

	// Parse TOML config
	var config RulesConfig
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules config: %w", err)
	}

	// Filter to enabled rules and pre-parse CIDRs
	for i, rule := range config.Rule {
		if !rule.Enabled {
			continue
		}

		ruleIdx := len(e.rules)
		e.rules = append(e.rules, rule)

		// Pre-parse CIDR networks for NOT conditions
		var srcNets, dstNets []*net.IPNet

		for _, cidr := range rule.SrcNotCIDR {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): invalid src_not_cidr '%s': %w", i, rule.Name, cidr, err)
			}
			srcNets = append(srcNets, ipNet)
		}

		for _, cidr := range rule.DstNotCIDR {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): invalid dst_not_cidr '%s': %w", i, rule.Name, cidr, err)
			}
			dstNets = append(dstNets, ipNet)
		}

		// Store all parsed nets for this rule
		if len(srcNets) > 0 || len(dstNets) > 0 {
			allNets := append(srcNets, dstNets...)
			e.parsedNets[ruleIdx] = allNets
			// Also store separately for easier lookup
			e.parsedNets[ruleIdx*1000] = srcNets     // srcNotCIDR at index*1000
			e.parsedNets[ruleIdx*1000+1] = dstNets   // dstNotCIDR at index*1000+1
		}

		// Initialize rule hit counter
		e.ruleHits.Store(rule.Name, &atomic.Int64{})
	}

	return e, nil
}

// Evaluate evaluates a packet against all enabled rules.
// Returns all matching rules (a packet can match multiple rules).
func (e *Engine) Evaluate(pkt PacketInfo) []RuleMatch {
	e.totalChecks.Add(1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []RuleMatch

	for ruleIdx, rule := range e.rules {
		if e.matchRule(ruleIdx, &rule, pkt) {
			e.totalMatches.Add(1)

			// Increment rule hit counter
			if counter, ok := e.ruleHits.Load(rule.Name); ok {
				counter.(*atomic.Int64).Add(1)
			}

			matches = append(matches, RuleMatch{
				Matched:     true,
				Rule:        &rule,
				Description: fmt.Sprintf("Rule '%s' matched: %s", rule.Name, rule.Description),
			})

			// Fire alert and execute actions
			e.fireAlert(&rule, pkt)
			e.executeAction(&rule, pkt)
		}
	}

	return matches
}

// matchRule checks if a packet matches all conditions of a rule.
func (e *Engine) matchRule(ruleIdx int, rule *Rule, pkt PacketInfo) bool {
	// Check destination port (OR logic - match any)
	if len(rule.DstPort) > 0 && !containsPort(rule.DstPort, pkt.DstPort) {
		return false
	}

	// Check source port (OR logic - match any)
	if len(rule.SrcPort) > 0 && !containsPort(rule.SrcPort, pkt.SrcPort) {
		return false
	}

	// Check protocol
	if rule.Protocol != "" && !strings.EqualFold(rule.Protocol, pkt.Protocol) {
		return false
	}

	// Check direction
	if rule.Direction != "" && !strings.EqualFold(rule.Direction, pkt.Direction) {
		return false
	}

	// Check destination IP (OR logic - match any)
	if len(rule.DstIP) > 0 && !containsString(rule.DstIP, pkt.DstIP) {
		return false
	}

	// Check source IP (OR logic - match any)
	if len(rule.SrcIP) > 0 && !containsString(rule.SrcIP, pkt.SrcIP) {
		return false
	}

	// Check source IP NOT in CIDRs
	if srcNets, ok := e.parsedNets[ruleIdx*1000]; ok && len(srcNets) > 0 {
		if ipInCIDRs(pkt.SrcIP, srcNets) {
			return false // Source IP is in excluded CIDR - no match
		}
	}

	// Check destination IP NOT in CIDRs
	if dstNets, ok := e.parsedNets[ruleIdx*1000+1]; ok && len(dstNets) > 0 {
		if ipInCIDRs(pkt.DstIP, dstNets) {
			return false // Dest IP is in excluded CIDR - no match
		}
	}

	// Check domain (OR logic - match any substring)
	if len(rule.Domain) > 0 {
		matched := false
		for _, domain := range rule.Domain {
			if strings.Contains(strings.ToLower(pkt.Domain), strings.ToLower(domain)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check TCP flags
	if rule.TCPFlags != "" {
		expectedFlags := parseTCPFlags(rule.TCPFlags)
		if pkt.TCPFlags&expectedFlags != expectedFlags {
			return false // Expected flags not set
		}
	}

	// Check threshold
	if rule.ThresholdCount > 0 {
		if !e.checkThreshold(ruleIdx, rule, pkt) {
			return false
		}
	}

	return true
}

// checkThreshold checks if the packet meets the threshold criteria.
func (e *Engine) checkThreshold(ruleIdx int, rule *Rule, pkt PacketInfo) bool {
	// Build group key
	var groupKey string
	switch rule.ThresholdGroupBy {
	case "src_ip":
		groupKey = pkt.SrcIP
	case "dst_ip":
		groupKey = pkt.DstIP
	case "src_ip+dst_port":
		groupKey = fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.DstPort)
	default:
		groupKey = "global"
	}

	thresholdKey := fmt.Sprintf("%d:%s", ruleIdx, groupKey)

	now := time.Now().Unix()
	windowEnd := now + int64(rule.ThresholdWindow)

	// Get or create tracker
	val, _ := e.thresholds.LoadOrStore(thresholdKey, &thresholdTracker{
		windowEnd: windowEnd,
	})
	tracker := val.(*thresholdTracker)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	// Check if window expired - reset if so
	if now > tracker.windowEnd {
		tracker.count = 1
		tracker.windowEnd = windowEnd
		return false // First event in new window
	}

	// Increment count
	tracker.count++

	// Check if threshold reached
	return tracker.count >= int64(rule.ThresholdCount)
}

// fireAlert creates and sends an alert for a matched rule.
func (e *Engine) fireAlert(rule *Rule, pkt PacketInfo) {
	if e.alertMgr == nil {
		return
	}

	// Determine alert type
	alertType := rule.AlertType
	if alertType == "" {
		alertType = "CUSTOM_RULE"
	}

	// Parse severity
	var severity alerting.Severity
	switch strings.ToUpper(rule.Severity) {
	case "CRITICAL":
		severity = alerting.CRITICAL
	case "HIGH":
		severity = alerting.HIGH
	case "MEDIUM":
		severity = alerting.MEDIUM
	case "LOW":
		severity = alerting.LOW
	default:
		severity = alerting.MEDIUM
	}

	// Build alert details
	details := fmt.Sprintf("%s | Packet: %s:%d -> %s:%d (%s %s) | Size: %d bytes",
		rule.Description,
		pkt.SrcIP, pkt.SrcPort,
		pkt.DstIP, pkt.DstPort,
		pkt.Protocol, pkt.Direction,
		pkt.Size,
	)

	if pkt.Domain != "" {
		details += fmt.Sprintf(" | Domain: %s", pkt.Domain)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"rule_name":   rule.Name,
		"src_ip":      pkt.SrcIP,
		"src_port":    pkt.SrcPort,
		"dst_ip":      pkt.DstIP,
		"dst_port":    pkt.DstPort,
		"protocol":    pkt.Protocol,
		"direction":   pkt.Direction,
		"domain":      pkt.Domain,
		"tcp_flags":   pkt.TCPFlags,
		"packet_size": pkt.Size,
		"action":      rule.Action,
	}

	// Send alert
	alert := alerting.Alert{
		Type:      alertType,
		Severity:  severity,
		Details:   details,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	e.alertMgr.Send(alert)
}

// executeAction performs the configured action for a matched rule.
func (e *Engine) executeAction(rule *Rule, pkt PacketInfo) {
	switch strings.ToUpper(rule.Action) {
	case "BAN":
		if e.banMgr == nil {
			return
		}

		// Parse ban duration
		duration := 30 * time.Minute // Default
		if rule.BanDuration != "" {
			if d, err := time.ParseDuration(rule.BanDuration); err == nil {
				duration = d
			}
		}

		// Ban the source IP
		reason := fmt.Sprintf("Rule '%s': %s", rule.Name, rule.Description)
		e.banMgr.BanIP(pkt.SrcIP, duration, reason)

	case "DROP":
		// DROP action is handled by the caller (firewall engine)
		// We just log it here
		// In production, you'd return action hints to the caller

	case "LOG", "ALERT":
		// Already handled by fireAlert
	}
}

// Reload reloads rules from the configuration file (hot-reload support).
func (e *Engine) Reload(configPath string) error {
	// Parse new config
	var config RulesConfig
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return fmt.Errorf("failed to parse rules config: %w", err)
	}

	// Build new rules and parsed nets
	var newRules []Rule
	newParsedNets := make(map[int][]*net.IPNet)

	for i, rule := range config.Rule {
		if !rule.Enabled {
			continue
		}

		ruleIdx := len(newRules)
		newRules = append(newRules, rule)

		// Pre-parse CIDRs
		var srcNets, dstNets []*net.IPNet

		for _, cidr := range rule.SrcNotCIDR {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("rule %d (%s): invalid src_not_cidr '%s': %w", i, rule.Name, cidr, err)
			}
			srcNets = append(srcNets, ipNet)
		}

		for _, cidr := range rule.DstNotCIDR {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("rule %d (%s): invalid dst_not_cidr '%s': %w", i, rule.Name, cidr, err)
			}
			dstNets = append(dstNets, ipNet)
		}

		if len(srcNets) > 0 || len(dstNets) > 0 {
			newParsedNets[ruleIdx*1000] = srcNets
			newParsedNets[ruleIdx*1000+1] = dstNets
		}

		// Initialize rule hit counter if new
		if _, exists := e.ruleHits.Load(rule.Name); !exists {
			e.ruleHits.Store(rule.Name, &atomic.Int64{})
		}
	}

	// Atomically swap rules
	e.mu.Lock()
	e.rules = newRules
	e.parsedNets = newParsedNets
	e.mu.Unlock()

	return nil
}

// RuleCount returns the number of enabled rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_checks":  e.totalChecks.Load(),
		"total_matches": e.totalMatches.Load(),
		"rule_count":    e.RuleCount(),
		"rule_hits":     make(map[string]int64),
	}

	// Collect per-rule hit counts
	ruleHits := stats["rule_hits"].(map[string]int64)
	e.ruleHits.Range(func(key, value interface{}) bool {
		ruleName := key.(string)
		counter := value.(*atomic.Int64)
		ruleHits[ruleName] = counter.Load()
		return true
	})

	return stats
}

// Helper functions

// parseTCPFlags parses a TCP flags string into a bitmask.
// Supports: SYN, ACK, FIN, RST, PSH, URG, and combinations like "SYN+ACK".
func parseTCPFlags(s string) uint8 {
	var flags uint8

	parts := strings.Split(strings.ToUpper(s), "+")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "SYN":
			flags |= 0x02
		case "ACK":
			flags |= 0x10
		case "FIN":
			flags |= 0x01
		case "RST":
			flags |= 0x04
		case "PSH":
			flags |= 0x08
		case "URG":
			flags |= 0x20
		}
	}

	return flags
}

// containsPort checks if a port list contains the given port.
func containsPort(ports []int, port uint32) bool {
	for _, p := range ports {
		if uint32(p) == port {
			return true
		}
	}
	return false
}

// containsString checks if a string list contains the given string (exact match).
func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// ipInCIDRs checks if an IP address is in any of the given CIDR networks.
func ipInCIDRs(ipStr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
