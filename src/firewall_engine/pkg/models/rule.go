// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Firewall Rule - Core filtering rule structure
// ============================================================================

// FirewallRule represents a single firewall rule for packet filtering.
// Rules are evaluated in priority order (lowest number = highest priority).
type FirewallRule struct {
	// === Identification ===

	// ID is the unique identifier for this rule (UUID).
	ID uuid.UUID `json:"id" toml:"id"`

	// RuleID is the numeric ID for TOML compatibility.
	RuleID int `json:"rule_id" toml:"rule_id"`

	// Name is the human-readable name for the rule.
	Name string `json:"name" toml:"rule_name"`

	// Description explains the purpose of this rule.
	Description string `json:"description,omitempty" toml:"description"`

	// === Rule Configuration ===

	// Enabled indicates if this rule is active.
	Enabled bool `json:"enabled" toml:"enabled"`

	// Action is the verdict to apply when this rule matches.
	Action Verdict `json:"action" toml:"action"`

	// Priority determines evaluation order (lower = higher priority).
	// Rules are sorted by group priority first, then rule priority.
	Priority int `json:"priority" toml:"priority"`

	// GroupName is the name of the rule group this belongs to.
	GroupName string `json:"group,omitempty" toml:"group"`

	// === Traffic Matching Criteria ===

	// Direction specifies the traffic direction to match.
	Direction Direction `json:"direction" toml:"direction"`

	// Protocol specifies the IP protocol to match (TCP, UDP, ICMP, ANY).
	Protocol Protocol `json:"protocol" toml:"protocol"`

	// === Source Matching ===

	// SourceAddress is the source IP/CIDR or object reference to match.
	// Supports: "192.168.1.0/24", "RFC1918_PRIVATE", "ANY", "!RFC1918_PRIVATE" (negation)
	SourceAddress string `json:"source_address,omitempty" toml:"source_address"`

	// SourcePort is the source port(s) to match.
	// Supports: single port [80], multiple ports [80, 443], ranges [8000-9000]
	SourcePort []int `json:"source_port,omitempty" toml:"source_port"`

	// SourcePortObject is a reference to a port object (e.g., "WEB_PORTS").
	SourcePortObject string `json:"source_port_object,omitempty" toml:"source_port_object"`

	// === Destination Matching ===

	// DestinationAddress is the destination IP/CIDR or object reference.
	DestinationAddress string `json:"destination_address,omitempty" toml:"destination_address"`

	// DestinationPort is the destination port(s) to match.
	DestinationPort []int `json:"destination_port,omitempty" toml:"destination_port"`

	// DestinationPortObject is a reference to a port object.
	DestinationPortObject string `json:"destination_port_object,omitempty" toml:"destination_port_object"`

	// === Domain Matching ===

	// Domain is the domain pattern to match (for DNS/SNI/HTTP traffic).
	// Supports wildcards: "*.facebook.com", exact: "facebook.com"
	Domain string `json:"domain,omitempty" toml:"domain"`

	// DomainObject is a reference to a domain object.
	DomainObject string `json:"domain_object,omitempty" toml:"domain_object"`

	// === Interface & Zone Matching ===

	// Interface is the network interface name to match (WAN, LAN, WIFI).
	Interface string `json:"interface,omitempty" toml:"interface"`

	// SourceZone is the security zone for source interface.
	SourceZone string `json:"source_zone,omitempty" toml:"source_zone"`

	// DestinationZone is the security zone for destination interface.
	DestinationZone string `json:"destination_zone,omitempty" toml:"destination_zone"`

	// === Stateful Matching ===

	// State is the connection state(s) to match.
	// Comma-separated: "NEW,ESTABLISHED"
	State string `json:"state,omitempty" toml:"state"`

	// ParsedStates is the parsed connection states (computed from State).
	ParsedStates []ConnectionState `json:"-" toml:"-"`

	// === Logging & Tracking ===

	// LogEnabled indicates whether matches should be logged.
	LogEnabled bool `json:"log_enabled" toml:"log_enabled"`

	// === Redirect Configuration (for REDIRECT action) ===

	// RedirectIP is the destination IP for redirect rules.
	RedirectIP string `json:"redirect_ip,omitempty" toml:"redirect_ip"`

	// RedirectPort is the destination port for redirect rules.
	RedirectPort uint16 `json:"redirect_port,omitempty" toml:"redirect_port"`

	// === Caching Configuration ===

	// CacheTTL is how long (seconds) the verdict can be cached (0 = no caching).
	CacheTTL uint32 `json:"cache_ttl,omitempty" toml:"cache_ttl"`

	// === Timestamps ===

	// CreatedAt is when the rule was created.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// ModifiedAt is when the rule was last modified.
	ModifiedAt time.Time `json:"modified_at,omitempty"`

	// === Computed Fields ===

	// EffectivePriority combines group and rule priority for sorting.
	// Calculated as: (groupPriority * 10000) + rulePriority
	EffectivePriority int `json:"-" toml:"-"`

	// IsNegatedSource indicates if source address uses negation (!).
	IsNegatedSource bool `json:"-" toml:"-"`

	// IsNegatedDestination indicates if destination address uses negation.
	IsNegatedDestination bool `json:"-" toml:"-"`

	// NormalizedSourceAddress is the source address without negation prefix.
	NormalizedSourceAddress string `json:"-" toml:"-"`

	// NormalizedDestAddress is the destination address without negation prefix.
	NormalizedDestAddress string `json:"-" toml:"-"`

	// === Statistics ===

	// HitCount is the number of times this rule has matched.
	HitCount uint64 `json:"-" toml:"-"`

	// LastMatchTime is when this rule last matched a packet.
	LastMatchTime time.Time `json:"-" toml:"-"`

	// BytesMatched is total bytes matched by this rule.
	BytesMatched uint64 `json:"-" toml:"-"`
}

// NewFirewallRule creates a new rule with a generated UUID.
func NewFirewallRule(name string) *FirewallRule {
	now := time.Now()
	return &FirewallRule{
		ID:         uuid.New(),
		Name:       name,
		Enabled:    true,
		Action:     VerdictBlock,
		Direction:  DirectionAny,
		Protocol:   ProtocolAny,
		Priority:   100,
		CreatedAt:  now,
		ModifiedAt: now,
	}
}

// Initialize prepares the rule for matching by parsing computed fields.
func (r *FirewallRule) Initialize() error {
	// Parse negated addresses
	if strings.HasPrefix(r.SourceAddress, "!") {
		r.IsNegatedSource = true
		r.NormalizedSourceAddress = strings.TrimPrefix(r.SourceAddress, "!")
	} else {
		r.NormalizedSourceAddress = r.SourceAddress
	}

	if strings.HasPrefix(r.DestinationAddress, "!") {
		r.IsNegatedDestination = true
		r.NormalizedDestAddress = strings.TrimPrefix(r.DestinationAddress, "!")
	} else {
		r.NormalizedDestAddress = r.DestinationAddress
	}

	// Parse connection states
	if r.State != "" {
		states, err := ParseConnectionStates(r.State)
		if err != nil {
			return fmt.Errorf("invalid state %q: %w", r.State, err)
		}
		r.ParsedStates = states
	}

	// Generate UUID if not set
	if r.ID == uuid.Nil && r.RuleID > 0 {
		r.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("rule-%d", r.RuleID)))
	}

	return nil
}

// SetEffectivePriority sets the effective priority based on group priority.
func (r *FirewallRule) SetEffectivePriority(groupPriority int) {
	r.EffectivePriority = (groupPriority * 10000) + r.Priority
}

// IncrementHit increments the hit counter and updates last match time.
func (r *FirewallRule) IncrementHit(bytes uint32) {
	r.HitCount++
	r.BytesMatched += uint64(bytes)
	r.LastMatchTime = time.Now()
}

// IsSourceAny returns true if source matches any address.
func (r *FirewallRule) IsSourceAny() bool {
	return r.SourceAddress == "" || strings.ToUpper(r.SourceAddress) == "ANY"
}

// IsDestinationAny returns true if destination matches any address.
func (r *FirewallRule) IsDestinationAny() bool {
	return r.DestinationAddress == "" || strings.ToUpper(r.DestinationAddress) == "ANY"
}

// HasSourcePorts returns true if source port matching is configured.
func (r *FirewallRule) HasSourcePorts() bool {
	return len(r.SourcePort) > 0 || r.SourcePortObject != ""
}

// HasDestinationPorts returns true if destination port matching is configured.
func (r *FirewallRule) HasDestinationPorts() bool {
	return len(r.DestinationPort) > 0 || r.DestinationPortObject != ""
}

// HasDomainMatch returns true if domain matching is configured.
func (r *FirewallRule) HasDomainMatch() bool {
	return r.Domain != "" || r.DomainObject != ""
}

// HasStateMatch returns true if connection state matching is configured.
func (r *FirewallRule) HasStateMatch() bool {
	return len(r.ParsedStates) > 0
}

// MatchesState checks if the rule matches the given connection state.
func (r *FirewallRule) MatchesState(state ConnectionState) bool {
	if !r.HasStateMatch() {
		return true // No state filter, matches all
	}
	return state.Matches(r.ParsedStates)
}

// ToVerdictResult creates a VerdictResult from a rule match.
func (r *FirewallRule) ToVerdictResult(reason string) *VerdictResult {
	return &VerdictResult{
		Verdict:      r.Action,
		RuleID:       r.ID.String(),
		RuleName:     r.Name,
		GroupName:    r.GroupName,
		Reason:       reason,
		LogEnabled:   r.LogEnabled,
		CacheTTL:     r.CacheTTL,
		Priority:     r.EffectivePriority,
		RedirectIP:   r.RedirectIP,
		RedirectPort: r.RedirectPort,
	}
}

// Clone creates a deep copy of the rule.
func (r *FirewallRule) Clone() *FirewallRule {
	if r == nil {
		return nil
	}
	clone := *r
	// Deep copy slices
	if r.SourcePort != nil {
		clone.SourcePort = make([]int, len(r.SourcePort))
		copy(clone.SourcePort, r.SourcePort)
	}
	if r.DestinationPort != nil {
		clone.DestinationPort = make([]int, len(r.DestinationPort))
		copy(clone.DestinationPort, r.DestinationPort)
	}
	if r.ParsedStates != nil {
		clone.ParsedStates = make([]ConnectionState, len(r.ParsedStates))
		copy(clone.ParsedStates, r.ParsedStates)
	}
	return &clone
}

// String returns a human-readable summary of the rule.
func (r *FirewallRule) String() string {
	status := "enabled"
	if !r.Enabled {
		status = "disabled"
	}
	return fmt.Sprintf("[%s] %s (%s, priority=%d, group=%s)",
		r.Action, r.Name, status, r.Priority, r.GroupName)
}

// MarshalJSON implements custom JSON marshaling.
func (r *FirewallRule) MarshalJSON() ([]byte, error) {
	type Alias FirewallRule
	return json.Marshal(&struct {
		*Alias
		ID string `json:"id"`
	}{
		Alias: (*Alias)(r),
		ID:    r.ID.String(),
	})
}

// ============================================================================
// Rule Group - Logical grouping of rules
// ============================================================================

// RuleGroup organizes rules into logical groups with shared priority.
type RuleGroup struct {
	// Name is the unique identifier for this group.
	Name string `json:"group_name" toml:"group_name"`

	// Description explains the purpose of this group.
	Description string `json:"description,omitempty" toml:"description"`

	// Enabled indicates if rules in this group are active.
	Enabled bool `json:"enabled" toml:"enabled"`

	// Priority determines group evaluation order (lower = higher priority).
	Priority int `json:"priority" toml:"priority"`

	// Rules contains all rules in this group.
	Rules []*FirewallRule `json:"rules,omitempty" toml:"-"`

	// RuleCount is the number of rules in this group.
	RuleCount int `json:"rule_count,omitempty" toml:"-"`
}

// NewRuleGroup creates a new rule group.
func NewRuleGroup(name string, priority int) *RuleGroup {
	return &RuleGroup{
		Name:     name,
		Enabled:  true,
		Priority: priority,
		Rules:    make([]*FirewallRule, 0),
	}
}

// AddRule adds a rule to this group and updates effective priority.
func (g *RuleGroup) AddRule(rule *FirewallRule) {
	rule.GroupName = g.Name
	rule.SetEffectivePriority(g.Priority)
	g.Rules = append(g.Rules, rule)
	g.RuleCount = len(g.Rules)
}

// RemoveRule removes a rule from this group by ID.
func (g *RuleGroup) RemoveRule(ruleID uuid.UUID) bool {
	for i, rule := range g.Rules {
		if rule.ID == ruleID {
			g.Rules = append(g.Rules[:i], g.Rules[i+1:]...)
			g.RuleCount = len(g.Rules)
			return true
		}
	}
	return false
}

// GetEnabledRules returns only enabled rules in this group.
func (g *RuleGroup) GetEnabledRules() []*FirewallRule {
	if !g.Enabled {
		return nil
	}

	enabled := make([]*FirewallRule, 0, len(g.Rules))
	for _, rule := range g.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

// String returns a human-readable summary of the group.
func (g *RuleGroup) String() string {
	status := "enabled"
	if !g.Enabled {
		status = "disabled"
	}
	return fmt.Sprintf("[Group: %s] priority=%d, rules=%d, %s",
		g.Name, g.Priority, g.RuleCount, status)
}

// ============================================================================
// Default Policies - Fallback behavior
// ============================================================================

// DefaultPolicies defines fallback actions when no rule matches.
type DefaultPolicies struct {
	// InboundPolicy is the default action for inbound traffic.
	InboundPolicy Verdict `json:"default_inbound_policy" toml:"default_inbound_policy"`

	// OutboundPolicy is the default action for outbound traffic.
	OutboundPolicy Verdict `json:"default_outbound_policy" toml:"default_outbound_policy"`

	// ForwardPolicy is the default action for forwarded traffic.
	ForwardPolicy Verdict `json:"default_forward_policy" toml:"default_forward_policy"`

	// PolicyLogEnabled indicates whether default policy hits should be logged.
	PolicyLogEnabled bool `json:"policy_log_enabled" toml:"policy_log_enabled"`

	// RejectWithICMP sends ICMP unreachable for REJECT actions.
	RejectWithICMP bool `json:"reject_with_icmp" toml:"reject_with_icmp"`
}

// NewDefaultPolicies creates default policies with secure defaults.
func NewDefaultPolicies() *DefaultPolicies {
	return &DefaultPolicies{
		InboundPolicy:    VerdictBlock, // Block inbound by default
		OutboundPolicy:   VerdictAllow, // Allow outbound by default
		ForwardPolicy:    VerdictBlock, // Block forwarding by default
		PolicyLogEnabled: true,
		RejectWithICMP:   true,
	}
}

// GetPolicyForDirection returns the default policy for a direction.
func (p *DefaultPolicies) GetPolicyForDirection(dir Direction) Verdict {
	switch dir {
	case DirectionInbound:
		return p.InboundPolicy
	case DirectionOutbound:
		return p.OutboundPolicy
	case DirectionForward:
		return p.ForwardPolicy
	default:
		return p.InboundPolicy // Default to most restrictive
	}
}

// ToVerdictResult creates a VerdictResult for a default policy match.
func (p *DefaultPolicies) ToVerdictResult(dir Direction) *VerdictResult {
	verdict := p.GetPolicyForDirection(dir)
	return &VerdictResult{
		Verdict:    verdict,
		RuleName:   "Default Policy",
		Reason:     fmt.Sprintf("No rule matched, applying default %s policy: %s", dir, verdict),
		LogEnabled: p.PolicyLogEnabled,
	}
}

// ============================================================================
// Rule Sorting Interface
// ============================================================================

// RulesByPriority implements sort.Interface for sorting rules by effective priority.
type RulesByPriority []*FirewallRule

func (r RulesByPriority) Len() int           { return len(r) }
func (r RulesByPriority) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r RulesByPriority) Less(i, j int) bool { return r[i].EffectivePriority < r[j].EffectivePriority }

// GroupsByPriority implements sort.Interface for sorting groups by priority.
type GroupsByPriority []*RuleGroup

func (g GroupsByPriority) Len() int           { return len(g) }
func (g GroupsByPriority) Swap(i, j int)      { g[i], g[j] = g[j], g[i] }
func (g GroupsByPriority) Less(i, j int) bool { return g[i].Priority < g[j].Priority }
