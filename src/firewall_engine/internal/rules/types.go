// Package rules provides rule matching and management for the firewall engine.
// It evaluates packets against configured rules to produce allow/deny verdicts.
package rules

import (
	"firewall_engine/pkg/models"
)

// ============================================================================
// Rule Matcher Interface
// ============================================================================

// RuleMatcher is the interface for rule matching implementations.
type RuleMatcher interface {
	// Match evaluates a packet against all rules and returns a verdict.
	Match(pkt *models.PacketMetadata) *MatchResult

	// MatchWithConnection evaluates considering connection state.
	MatchWithConnection(pkt *models.PacketMetadata, conn *models.ConnectionInfo) *MatchResult

	// GetMatchingRules returns all rules that match the packet.
	GetMatchingRules(pkt *models.PacketMetadata) []*models.FirewallRule

	// GetDefaultVerdict returns the default verdict for unmatched packets.
	GetDefaultVerdict(direction models.Direction) models.Verdict
}

// MatchResult contains the result of rule matching.
type MatchResult struct {
	// Verdict is the final decision (ALLOW, DROP, DENY, etc.).
	Verdict models.Verdict `json:"verdict"`

	// MatchedRule is the rule that matched (nil if default policy).
	MatchedRule *models.FirewallRule `json:"matched_rule,omitempty"`

	// RuleID is the ID of the matched rule (0 if default).
	RuleID int `json:"rule_id"`

	// RuleName is the name of the matched rule.
	RuleName string `json:"rule_name,omitempty"`

	// GroupName is the group of the matched rule.
	GroupName string `json:"group_name,omitempty"`

	// IsDefaultPolicy indicates if the default policy was applied.
	IsDefaultPolicy bool `json:"is_default_policy"`

	// MatchReason explains why the rule matched.
	MatchReason string `json:"match_reason,omitempty"`

	// ShouldLog indicates if this verdict should be logged.
	ShouldLog bool `json:"should_log"`

	// RedirectInfo contains redirect details if verdict is REDIRECT.
	RedirectInfo *RedirectInfo `json:"redirect_info,omitempty"`

	// EvaluationTime is how long rule evaluation took (nanoseconds).
	EvaluationTimeNs int64 `json:"evaluation_time_ns"`

	// RulesEvaluated is how many rules were checked before match.
	RulesEvaluated int `json:"rules_evaluated"`
}

// RedirectInfo contains details for REDIRECT verdicts.
type RedirectInfo struct {
	// TargetIP is the IP to redirect to.
	TargetIP string `json:"target_ip"`

	// TargetPort is the port to redirect to (0 = same port).
	TargetPort uint16 `json:"target_port,omitempty"`

	// PreserveSource indicates if source should be preserved (NAT).
	PreserveSource bool `json:"preserve_source"`
}

// NewMatchResult creates a new match result with the given verdict.
func NewMatchResult(verdict models.Verdict) *MatchResult {
	return &MatchResult{
		Verdict: verdict,
	}
}

// NewDefaultMatch creates a match result indicating default policy was applied.
func NewDefaultMatch(verdict models.Verdict, direction models.Direction) *MatchResult {
	return &MatchResult{
		Verdict:         verdict,
		IsDefaultPolicy: true,
		MatchReason:     "no matching rule, applied default " + direction.String() + " policy",
	}
}

// NewRuleMatch creates a match result for a specific rule.
func NewRuleMatch(rule *models.FirewallRule) *MatchResult {
	result := &MatchResult{
		Verdict:     rule.Action,
		MatchedRule: rule,
		RuleID:      rule.RuleID,
		RuleName:    rule.Name,
		GroupName:   rule.GroupName,
		ShouldLog:   rule.LogEnabled,
		MatchReason: "matched rule conditions",
	}

	// Handle redirect
	if rule.Action == models.VerdictRedirect {
		result.RedirectInfo = &RedirectInfo{
			TargetIP:   rule.RedirectIP,
			TargetPort: uint16(rule.RedirectPort),
		}
	}

	return result
}

// ============================================================================
// Rule Store Interface
// ============================================================================

// RuleStore defines the interface for rule storage.
type RuleStore interface {
	// Add adds a rule to the store.
	Add(rule *models.FirewallRule) error

	// Remove removes a rule by ID.
	Remove(ruleID int) bool

	// Get retrieves a rule by ID.
	Get(ruleID int) (*models.FirewallRule, bool)

	// GetByName retrieves a rule by name.
	GetByName(name string) (*models.FirewallRule, bool)

	// All returns all rules.
	All() []*models.FirewallRule

	// Count returns the number of rules.
	Count() int

	// Clear removes all rules.
	Clear()

	// GetByGroup returns all rules in a group.
	GetByGroup(groupName string) []*models.FirewallRule

	// GetSortedByPriority returns rules sorted by priority.
	GetSortedByPriority() []*models.FirewallRule
}

// ============================================================================
// Rule Manager Interface
// ============================================================================

// RuleManager provides CRUD operations for rules and groups.
type RuleManager interface {
	RuleStore
	RuleMatcher

	// LoadFromConfig loads rules from configuration.
	LoadFromConfig(rules []*models.FirewallRule) error

	// AddGroup adds a rule group.
	AddGroup(group *models.RuleGroup) error

	// RemoveGroup removes a rule group by name.
	RemoveGroup(name string) bool

	// GetGroup retrieves a rule group by name.
	GetGroup(name string) (*models.RuleGroup, bool)

	// AllGroups returns all rule groups.
	AllGroups() []*models.RuleGroup

	// SetDefaultInboundPolicy sets the default inbound policy.
	SetDefaultInboundPolicy(verdict models.Verdict)

	// SetDefaultOutboundPolicy sets the default outbound policy.
	SetDefaultOutboundPolicy(verdict models.Verdict)

	// Enable/Disable rules
	EnableRule(ruleID int) bool
	DisableRule(ruleID int) bool

	// Stats
	GetStats() *ManagerStats
}

// ManagerStats contains statistics about rule management.
type ManagerStats struct {
	TotalRules       int            `json:"total_rules"`
	EnabledRules     int            `json:"enabled_rules"`
	DisabledRules    int            `json:"disabled_rules"`
	TotalGroups      int            `json:"total_groups"`
	RulesPerGroup    map[string]int `json:"rules_per_group"`
	RulesByAction    map[string]int `json:"rules_by_action"`
	RulesByDirection map[string]int `json:"rules_by_direction"`
	RulesByProtocol  map[string]int `json:"rules_by_protocol"`
	MatchCount       uint64         `json:"match_count"`
	HitCounts        map[int]uint64 `json:"hit_counts"` // ruleID -> hit count
}

// NewManagerStats creates empty manager statistics.
func NewManagerStats() *ManagerStats {
	return &ManagerStats{
		RulesPerGroup:    make(map[string]int),
		RulesByAction:    make(map[string]int),
		RulesByDirection: make(map[string]int),
		RulesByProtocol:  make(map[string]int),
		HitCounts:        make(map[int]uint64),
	}
}

// ============================================================================
// Matching Criteria
// ============================================================================

// MatchCriteria encapsulates conditions for matching.
type MatchCriteria struct {
	Direction models.Direction
	Protocol  models.Protocol
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Domain    string
	State     string
	Interface string
}

// MatchCriteriaFromPacket creates MatchCriteria from a packet.
func MatchCriteriaFromPacket(pkt *models.PacketMetadata) *MatchCriteria {
	return &MatchCriteria{
		Direction: pkt.Direction,
		Protocol:  pkt.Protocol,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Domain:    pkt.Domain,
		State:     pkt.ConnectionState.String(),
		Interface: pkt.AdapterName,
	}
}
