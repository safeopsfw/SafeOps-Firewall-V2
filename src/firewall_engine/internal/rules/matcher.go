// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"net"
	"strings"
	"sync/atomic"
	"time"

	"firewall_engine/internal/objects"
	"firewall_engine/pkg/models"
)

// ============================================================================
// 5-Tuple Matcher - Core Rule Matching Logic
// ============================================================================

// Matcher evaluates packets against firewall rules using 5-tuple matching.
// The 5-tuple consists of: Source IP, Destination IP, Source Port, Destination Port, Protocol
type Matcher struct {
	// Object resolver for address/port/domain lookups
	resolver *objects.Resolver

	// Default policies
	defaultInbound  models.Verdict
	defaultOutbound models.Verdict
	defaultForward  models.Verdict

	// Statistics
	matchCount    uint64
	hitCounts     map[int]*uint64 // ruleID -> hit count (atomic)
	totalEvalTime int64           // nanoseconds
}

// NewMatcher creates a new 5-tuple matcher.
func NewMatcher(resolver *objects.Resolver) *Matcher {
	return &Matcher{
		resolver:        resolver,
		defaultInbound:  models.VerdictDrop, // Secure default
		defaultOutbound: models.VerdictAllow,
		defaultForward:  models.VerdictDrop,
		hitCounts:       make(map[int]*uint64),
	}
}

// SetResolver sets the object resolver.
func (m *Matcher) SetResolver(resolver *objects.Resolver) {
	m.resolver = resolver
}

// SetDefaultPolicies sets the default policies for each direction.
func (m *Matcher) SetDefaultPolicies(inbound, outbound, forward models.Verdict) {
	m.defaultInbound = inbound
	m.defaultOutbound = outbound
	m.defaultForward = forward
}

// SetDefaultInboundPolicy sets the default inbound policy.
func (m *Matcher) SetDefaultInboundPolicy(v models.Verdict) {
	m.defaultInbound = v
}

// SetDefaultOutboundPolicy sets the default outbound policy.
func (m *Matcher) SetDefaultOutboundPolicy(v models.Verdict) {
	m.defaultOutbound = v
}

// GetDefaultVerdict returns the default verdict for a direction.
func (m *Matcher) GetDefaultVerdict(direction models.Direction) models.Verdict {
	switch direction {
	case models.DirectionInbound:
		return m.defaultInbound
	case models.DirectionOutbound:
		return m.defaultOutbound
	default:
		return m.defaultInbound // Conservative default
	}
}

// ============================================================================
// Main Matching Methods
// ============================================================================

// Match evaluates a packet against rules and returns a verdict.
func (m *Matcher) Match(pkt *models.PacketMetadata, rules []*models.FirewallRule) *MatchResult {
	startTime := time.Now()
	atomic.AddUint64(&m.matchCount, 1)

	result := m.evaluateRules(pkt, rules)
	result.EvaluationTimeNs = time.Since(startTime).Nanoseconds()

	atomic.AddInt64(&m.totalEvalTime, result.EvaluationTimeNs)

	return result
}

// MatchWithConnection evaluates considering connection state.
func (m *Matcher) MatchWithConnection(pkt *models.PacketMetadata, conn *models.ConnectionInfo, rules []*models.FirewallRule) *MatchResult {
	// Update packet with connection info
	if conn != nil {
		pkt.ConnectionState = conn.State
	}
	return m.Match(pkt, rules)
}

// evaluateRules iterates through rules and finds the first match.
func (m *Matcher) evaluateRules(pkt *models.PacketMetadata, rules []*models.FirewallRule) *MatchResult {
	rulesEvaluated := 0

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		rulesEvaluated++

		if m.matchRule(pkt, rule) {
			// Record hit
			m.recordHit(rule.RuleID)

			result := NewRuleMatch(rule)
			result.RulesEvaluated = rulesEvaluated
			return result
		}
	}

	// No rule matched, apply default policy
	defaultVerdict := m.GetDefaultVerdict(pkt.Direction)
	result := NewDefaultMatch(defaultVerdict, pkt.Direction)
	result.RulesEvaluated = rulesEvaluated
	return result
}

// recordHit increments the hit counter for a rule.
func (m *Matcher) recordHit(ruleID int) {
	if counter, ok := m.hitCounts[ruleID]; ok {
		atomic.AddUint64(counter, 1)
	} else {
		var count uint64 = 1
		m.hitCounts[ruleID] = &count
	}
}

// ============================================================================
// Rule Matching Logic
// ============================================================================

// matchRule checks if a packet matches a single rule.
func (m *Matcher) matchRule(pkt *models.PacketMetadata, rule *models.FirewallRule) bool {
	// 1. Direction check
	if !m.matchDirection(pkt.Direction, rule.Direction) {
		return false
	}

	// 2. Protocol check
	if !m.matchProtocol(pkt.Protocol, rule.Protocol) {
		return false
	}

	// 3. Source address check
	if !m.matchAddress(pkt.SrcIP, pkt.SrcIPParsed, rule.SourceAddress) {
		return false
	}

	// 4. Destination address check
	if !m.matchAddress(pkt.DstIP, pkt.DstIPParsed, rule.DestinationAddress) {
		return false
	}

	// 5. Source port check
	if !m.matchPort(pkt.SrcPort, rule.SourcePort, rule.SourcePortObject) {
		return false
	}

	// 6. Destination port check
	if !m.matchPort(pkt.DstPort, rule.DestinationPort, rule.DestinationPortObject) {
		return false
	}

	// 7. Domain check (if applicable)
	if rule.HasDomainMatch() {
		if !m.matchDomain(pkt.Domain, rule.Domain, rule.DomainObject) {
			return false
		}
	}

	// 8. Connection state check (if applicable)
	if rule.HasStateMatch() {
		if !m.matchState(pkt.ConnectionState.String(), rule.State) {
			return false
		}
	}

	// 9. Interface check (if applicable)
	if rule.Interface != "" {
		if !strings.EqualFold(rule.Interface, pkt.AdapterName) {
			return false
		}
	}

	// All conditions matched
	return true
}

// ============================================================================
// Individual Match Functions
// ============================================================================

// matchDirection checks if packet direction matches rule direction.
func (m *Matcher) matchDirection(pktDir, ruleDir models.Direction) bool {
	if ruleDir == models.DirectionAny || ruleDir == 0 {
		return true // Rule applies to any direction
	}
	return pktDir == ruleDir
}

// matchProtocol checks if packet protocol matches rule protocol.
func (m *Matcher) matchProtocol(pktProto, ruleProto models.Protocol) bool {
	if ruleProto == models.ProtocolAny || ruleProto == 0 {
		return true // Rule applies to any protocol
	}
	return pktProto == ruleProto
}

// matchAddress checks if an IP matches an address specification.
func (m *Matcher) matchAddress(ipStr string, ipParsed net.IP, spec string) bool {
	// Empty spec means match any
	if spec == "" {
		return true
	}

	// Handle ANY
	upper := strings.ToUpper(spec)
	if upper == "ANY" || spec == "0.0.0.0/0" || spec == "::/0" {
		return true
	}

	// Handle negation
	negated := false
	if strings.HasPrefix(spec, "!") {
		negated = true
		spec = strings.TrimPrefix(spec, "!")
	}

	var matches bool

	// Use resolver if available
	if m.resolver != nil {
		ip := ipParsed
		if ip == nil {
			ip = net.ParseIP(ipStr)
		}
		if ip != nil {
			var err error
			matches, err = m.resolver.ResolveAddress(spec, ip)
			if err != nil {
				matches = false
			}
		}
	} else {
		// Direct matching without resolver
		matches = m.directAddressMatch(ipStr, ipParsed, spec)
	}

	if negated {
		return !matches
	}
	return matches
}

// directAddressMatch performs address matching without resolver.
func (m *Matcher) directAddressMatch(ipStr string, ipParsed net.IP, spec string) bool {
	ip := ipParsed
	if ip == nil {
		ip = net.ParseIP(ipStr)
	}
	if ip == nil {
		return false
	}

	// Try as CIDR
	if strings.Contains(spec, "/") {
		_, network, err := net.ParseCIDR(spec)
		if err == nil {
			return network.Contains(ip)
		}
	}

	// Try as single IP
	specIP := net.ParseIP(spec)
	if specIP != nil {
		return specIP.Equal(ip)
	}

	return false
}

// matchPort checks if a port matches the rule's port specification.
func (m *Matcher) matchPort(pktPort uint16, ports []int, portObject string) bool {
	// No port filter means match any
	if len(ports) == 0 && portObject == "" {
		return true
	}

	// Check port object via resolver
	if portObject != "" && m.resolver != nil {
		return m.resolver.ResolvePort(portObject, nil, pktPort, models.ProtocolAny)
	}

	// Check direct port list
	for _, p := range ports {
		if uint16(p) == pktPort {
			return true
		}
	}

	return false
}

// matchDomain checks if a domain matches the rule's domain specification.
func (m *Matcher) matchDomain(pktDomain, ruleDomain, domainObject string) bool {
	// No domain filter means match any
	if ruleDomain == "" && domainObject == "" {
		return true
	}

	// Packet must have a domain to match domain rules
	if pktDomain == "" {
		return false
	}

	// Use resolver if available
	if m.resolver != nil {
		return m.resolver.ResolveDomain(domainObject, ruleDomain, pktDomain)
	}

	// Direct domain matching
	return MatchDomain(ruleDomain, pktDomain)
}

// matchState checks if connection state matches.
func (m *Matcher) matchState(pktState, ruleState string) bool {
	if ruleState == "" {
		return true
	}

	pktState = strings.ToUpper(pktState)
	ruleState = strings.ToUpper(ruleState)

	// Handle comma-separated states
	allowedStates := strings.Split(ruleState, ",")
	for _, state := range allowedStates {
		state = strings.TrimSpace(state)
		if state == pktState {
			return true
		}
	}

	return false
}

// ============================================================================
// Statistics
// ============================================================================

// MatcherStats contains matcher statistics.
type MatcherStats struct {
	TotalMatches    uint64         `json:"total_matches"`
	TotalEvalTimeNs int64          `json:"total_eval_time_ns"`
	AvgEvalTimeNs   float64        `json:"avg_eval_time_ns"`
	HitCounts       map[int]uint64 `json:"hit_counts"`
}

// GetStats returns current matcher statistics.
func (m *Matcher) GetStats() MatcherStats {
	stats := MatcherStats{
		TotalMatches:    atomic.LoadUint64(&m.matchCount),
		TotalEvalTimeNs: atomic.LoadInt64(&m.totalEvalTime),
		HitCounts:       make(map[int]uint64),
	}

	if stats.TotalMatches > 0 {
		stats.AvgEvalTimeNs = float64(stats.TotalEvalTimeNs) / float64(stats.TotalMatches)
	}

	for ruleID, count := range m.hitCounts {
		stats.HitCounts[ruleID] = atomic.LoadUint64(count)
	}

	return stats
}

// ResetStats resets all statistics.
func (m *Matcher) ResetStats() {
	atomic.StoreUint64(&m.matchCount, 0)
	atomic.StoreInt64(&m.totalEvalTime, 0)
	m.hitCounts = make(map[int]*uint64)
}
