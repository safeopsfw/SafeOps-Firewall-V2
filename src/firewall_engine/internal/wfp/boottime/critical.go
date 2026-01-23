// Package boottime provides critical rule selection logic for persistent filters.
// The CriticalSelector evaluates firewall rules to determine which ones should
// be installed as persistent boot-time filters based on security importance.
package boottime

import (
	"net"
	"strings"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Scoring Constants
// ============================================================================

// Scoring weights for determining rule criticality.
const (
	// Positive criteria - increase score
	ScoreBlocksMalwareIP = 30 // Blocks known malware IPs
	ScoreDefaultDeny     = 40 // Part of default deny policy
	ScoreDangerousPort   = 20 // Blocks dangerous ports (3389, 445, 22)
	ScoreBlockAction     = 10 // Block action (vs allow)
	ScoreHighPriority    = 10 // High priority rule (< 100)
	ScoreBlocksPrivateIP = 15 // Blocks private IP ranges from outside

	// Negative criteria - decrease score
	ScoreAllowAction = -10 // Allow action (less critical)

	// Thresholds
	DefaultMinScore = 40  // Minimum score to be considered critical
	DefaultMaxScore = 100 // Maximum possible score (for normalization)
)

// DangerousPorts are ports that should be protected at boot time.
var DangerousPorts = []uint16{
	3389,  // RDP
	445,   // SMB
	139,   // NetBIOS
	22,    // SSH
	23,    // Telnet
	135,   // RPC
	137,   // NetBIOS
	138,   // NetBIOS
	4444,  // Common backdoor port
	5900,  // VNC
	1433,  // MSSQL
	3306,  // MySQL
	5432,  // PostgreSQL
	27017, // MongoDB
}

// MalwareIPRanges are known malicious IP ranges (examples).
// In production, this would be loaded from threat intelligence feeds.
var MalwareIPRanges = []string{
	"185.220.0.0/16", // Known Tor exit node range
	"23.129.64.0/24", // Known proxy/anonymizer
}

// ============================================================================
// Critical Criteria
// ============================================================================

// CriticalCriteria defines what makes a rule critical for boot-time protection.
type CriticalCriteria struct {
	// BlocksMalwareIPs is true if rule blocks known malware IPs.
	BlocksMalwareIPs bool

	// BlocksDangerousPorts is true if rule blocks dangerous ports.
	BlocksDangerousPorts bool

	// IsDefaultDeny is true if rule is part of default deny policy.
	IsDefaultDeny bool

	// IsBlockAction is true if the rule blocks traffic.
	IsBlockAction bool

	// IsHighPriority is true if rule has high priority (< 100).
	IsHighPriority bool

	// Score is the calculated criticality score (0-100 normalized).
	Score int

	// RawScore is the raw calculated score before normalization.
	RawScore int

	// Reasons contains human-readable reasons for the score.
	Reasons []string
}

// IsCritical returns true if the criteria indicate the rule is critical.
func (c *CriticalCriteria) IsCritical(minScore int) bool {
	return c.Score >= minScore
}

// String returns a summary of the criteria.
func (c *CriticalCriteria) String() string {
	if len(c.Reasons) == 0 {
		return "no criteria matched"
	}
	return strings.Join(c.Reasons, ", ")
}

// ============================================================================
// Critical Selector
// ============================================================================

// CriticalSelector evaluates firewall rules to determine their criticality.
type CriticalSelector struct {
	// Configuration
	minScore      int
	maxPersistent int

	// Custom scoring
	dangerousPorts  []uint16
	malwareIPRanges []*net.IPNet
}

// NewCriticalSelector creates a new critical selector with default settings.
func NewCriticalSelector() *CriticalSelector {
	cs := &CriticalSelector{
		minScore:       DefaultMinScore,
		maxPersistent:  DefaultMaxPersistent,
		dangerousPorts: DangerousPorts,
	}

	// Parse malware IP ranges
	cs.malwareIPRanges = make([]*net.IPNet, 0, len(MalwareIPRanges))
	for _, cidr := range MalwareIPRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cs.malwareIPRanges = append(cs.malwareIPRanges, ipNet)
		}
	}

	return cs
}

// WithMinScore sets the minimum score threshold.
func (cs *CriticalSelector) WithMinScore(score int) *CriticalSelector {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	cs.minScore = score
	return cs
}

// WithMaxPersistent sets the maximum number of persistent filters.
func (cs *CriticalSelector) WithMaxPersistent(n int) *CriticalSelector {
	if n < MinMaxPersistent {
		n = MinMaxPersistent
	}
	if n > MaxMaxPersistent {
		n = MaxMaxPersistent
	}
	cs.maxPersistent = n
	return cs
}

// WithDangerousPorts sets custom dangerous ports.
func (cs *CriticalSelector) WithDangerousPorts(ports []uint16) *CriticalSelector {
	cs.dangerousPorts = ports
	return cs
}

// AddMalwareIPRange adds a malware IP range.
func (cs *CriticalSelector) AddMalwareIPRange(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	cs.malwareIPRanges = append(cs.malwareIPRanges, ipNet)
	return nil
}

// ============================================================================
// Core Evaluation Methods
// ============================================================================

// IsCritical returns true if the rule should be a persistent filter.
func (cs *CriticalSelector) IsCritical(rule *models.FirewallRule) bool {
	criteria := cs.EvaluateCriteria(rule)
	return criteria.IsCritical(cs.minScore)
}

// ScoreCriticality returns the criticality score for a rule (0-100).
func (cs *CriticalSelector) ScoreCriticality(rule *models.FirewallRule) int {
	criteria := cs.EvaluateCriteria(rule)
	return criteria.Score
}

// EvaluateCriteria evaluates all criteria for a rule.
func (cs *CriticalSelector) EvaluateCriteria(rule *models.FirewallRule) *CriticalCriteria {
	criteria := &CriticalCriteria{
		Reasons: make([]string, 0),
	}

	if rule == nil || !rule.Enabled {
		return criteria
	}

	rawScore := 0

	// Check action - use IsBlocking() method on Verdict
	if rule.Action.IsBlocking() {
		criteria.IsBlockAction = true
		rawScore += ScoreBlockAction
		criteria.Reasons = append(criteria.Reasons, "block action")
	} else if rule.Action.IsAllowing() {
		rawScore += ScoreAllowAction
	}

	// Check priority
	if rule.Priority < 100 {
		criteria.IsHighPriority = true
		rawScore += ScoreHighPriority
		criteria.Reasons = append(criteria.Reasons, "high priority")
	}

	// Check for dangerous ports
	if cs.hasDangerousPort(rule) {
		criteria.BlocksDangerousPorts = true
		rawScore += ScoreDangerousPort
		criteria.Reasons = append(criteria.Reasons, "blocks dangerous port")
	}

	// Check for malware IPs
	if cs.blocksMalwareIP(rule) {
		criteria.BlocksMalwareIPs = true
		rawScore += ScoreBlocksMalwareIP
		criteria.Reasons = append(criteria.Reasons, "blocks malware IP")
	}

	// Check for default deny characteristics
	if cs.isDefaultDeny(rule) {
		criteria.IsDefaultDeny = true
		rawScore += ScoreDefaultDeny
		criteria.Reasons = append(criteria.Reasons, "default deny policy")
	}

	// Calculate normalized score (0-100)
	criteria.RawScore = rawScore
	if rawScore <= 0 {
		criteria.Score = 0
	} else if rawScore >= DefaultMaxScore {
		criteria.Score = 100
	} else {
		criteria.Score = (rawScore * 100) / DefaultMaxScore
	}

	return criteria
}

// GetCriticalRules returns rules that should be persistent, sorted by score.
func (cs *CriticalSelector) GetCriticalRules(rules []*models.FirewallRule) []*models.FirewallRule {
	type scoredRule struct {
		rule  *models.FirewallRule
		score int
	}

	// Score all rules
	scored := make([]scoredRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		score := cs.ScoreCriticality(rule)
		if score >= cs.minScore {
			scored = append(scored, scoredRule{rule: rule, score: score})
		}
	}

	// Sort by score (descending)
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score > scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// Limit to max persistent
	if len(scored) > cs.maxPersistent {
		scored = scored[:cs.maxPersistent]
	}

	// Extract rules
	result := make([]*models.FirewallRule, len(scored))
	for i, sr := range scored {
		result[i] = sr.rule
	}

	return result
}

// ============================================================================
// Helper Methods
// ============================================================================

// hasDangerousPort checks if the rule involves a dangerous port.
func (cs *CriticalSelector) hasDangerousPort(rule *models.FirewallRule) bool {
	// Check destination ports
	for _, port := range rule.DestinationPort {
		uport := uint16(port)
		for _, dp := range cs.dangerousPorts {
			if uport == dp {
				return true
			}
		}
	}

	// Check source ports
	for _, port := range rule.SourcePort {
		uport := uint16(port)
		for _, dp := range cs.dangerousPorts {
			if uport == dp {
				return true
			}
		}
	}

	return false
}

// blocksMalwareIP checks if the rule blocks a known malware IP.
func (cs *CriticalSelector) blocksMalwareIP(rule *models.FirewallRule) bool {
	if !rule.Action.IsBlocking() {
		return false
	}

	// Check destination address
	if rule.DestinationAddress != "" {
		ip := net.ParseIP(rule.DestinationAddress)
		if ip != nil {
			for _, ipNet := range cs.malwareIPRanges {
				if ipNet.Contains(ip) {
					return true
				}
			}
		}

		// Check for CIDR
		_, ruleNet, err := net.ParseCIDR(rule.DestinationAddress)
		if err == nil {
			for _, ipNet := range cs.malwareIPRanges {
				if ipNet.Contains(ruleNet.IP) || ruleNet.Contains(ipNet.IP) {
					return true
				}
			}
		}
	}

	return false
}

// isDefaultDeny checks if this looks like a default deny rule.
func (cs *CriticalSelector) isDefaultDeny(rule *models.FirewallRule) bool {
	// Default deny typically:
	// - Has low priority (evaluated last)
	// - Has block/deny action
	// - Has no specific source/destination (matches all)
	// - Has no specific port

	if !rule.Action.IsBlocking() {
		return false
	}

	// Check for "catch-all" characteristics
	isWild := rule.SourceAddress == "" || rule.SourceAddress == "0.0.0.0/0" || rule.SourceAddress == "::/0"
	isDstWild := rule.DestinationAddress == "" || rule.DestinationAddress == "0.0.0.0/0" || rule.DestinationAddress == "::/0"
	noPort := len(rule.DestinationPort) == 0 && len(rule.SourcePort) == 0

	// Name hints
	nameLower := strings.ToLower(rule.Name)
	hasDefaultName := strings.Contains(nameLower, "default") ||
		strings.Contains(nameLower, "deny all") ||
		strings.Contains(nameLower, "block all")

	return (isWild && isDstWild && noPort) || hasDefaultName
}

// ============================================================================
// Batch Evaluation
// ============================================================================

// EvaluateAll evaluates all rules and returns their criteria.
func (cs *CriticalSelector) EvaluateAll(rules []*models.FirewallRule) map[string]*CriticalCriteria {
	result := make(map[string]*CriticalCriteria, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		result[rule.ID.String()] = cs.EvaluateCriteria(rule)
	}
	return result
}

// PartitionRules partitions rules into critical and non-critical.
func (cs *CriticalSelector) PartitionRules(rules []*models.FirewallRule) (critical, nonCritical []*models.FirewallRule) {
	critical = make([]*models.FirewallRule, 0)
	nonCritical = make([]*models.FirewallRule, 0)

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		if cs.IsCritical(rule) {
			critical = append(critical, rule)
		} else {
			nonCritical = append(nonCritical, rule)
		}
	}

	return critical, nonCritical
}

// CountCritical counts how many rules are critical.
func (cs *CriticalSelector) CountCritical(rules []*models.FirewallRule) int {
	count := 0
	for _, rule := range rules {
		if rule != nil && rule.Enabled && cs.IsCritical(rule) {
			count++
		}
	}
	return count
}

// GetMinScore returns the current minimum score threshold.
func (cs *CriticalSelector) GetMinScore() int {
	return cs.minScore
}

// GetMaxPersistent returns the maximum persistent filters allowed.
func (cs *CriticalSelector) GetMaxPersistent() int {
	return cs.maxPersistent
}
