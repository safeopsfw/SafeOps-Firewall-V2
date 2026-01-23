// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"fmt"
	"sync"
	"time"

	"firewall_engine/internal/config"
	"firewall_engine/internal/objects"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Rule Manager - Unified Rule Management and Matching
// ============================================================================

// Manager is the main entry point for rule management and matching.
// It combines storage, matching, and group management into a single interface.
type Manager struct {
	mu sync.RWMutex

	// Rule storage
	store *Store

	// Group management
	groups *GroupManager

	// Rule matcher
	matcher *Matcher

	// Priority sorter
	sorter *PrioritySorter

	// Object resolver
	resolver *objects.Resolver

	// Cached sorted rules (for fast matching)
	sortedRules      []*models.FirewallRule
	sortedRulesValid bool

	// Default policies
	defaultInbound  models.Verdict
	defaultOutbound models.Verdict

	// Metadata
	loadedAt time.Time
	version  string
}

// NewManager creates a new rule manager.
func NewManager() *Manager {
	store := NewStore()
	sorter := NewPrioritySorter()
	ApplyStandardPriorities(sorter)

	m := &Manager{
		store:           store,
		groups:          NewGroupManager(),
		sorter:          sorter,
		defaultInbound:  models.VerdictDrop, // Secure default
		defaultOutbound: models.VerdictAllow,
		loadedAt:        time.Now(),
	}

	m.matcher = NewMatcher(nil)
	m.matcher.SetDefaultPolicies(m.defaultInbound, m.defaultOutbound, models.VerdictDrop)

	return m
}

// NewManagerWithResolver creates a manager with an object resolver.
func NewManagerWithResolver(resolver *objects.Resolver) *Manager {
	m := NewManager()
	m.SetResolver(resolver)
	return m
}

// SetResolver sets the object resolver for address/port/domain lookups.
func (m *Manager) SetResolver(resolver *objects.Resolver) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.resolver = resolver
	m.matcher.SetResolver(resolver)
}

// ============================================================================
// Loading from Configuration
// ============================================================================

// LoadFromConfig loads rules and groups from configuration.
func (m *Manager) LoadFromConfig(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing
	m.store.Clear()
	m.groups.Clear()
	m.sortedRulesValid = false

	// Load groups first
	for _, grpCfg := range cfg.RuleGroups {
		group := &models.RuleGroup{
			Name:        grpCfg.GroupName,
			Description: grpCfg.Description,
			Priority:    grpCfg.Priority,
			Enabled:     grpCfg.Enabled,
		}
		if err := m.groups.Add(group); err != nil {
			return fmt.Errorf("failed to add group %q: %w", grpCfg.GroupName, err)
		}
		m.sorter.SetGroupPriority(grpCfg.GroupName, grpCfg.Priority)
	}

	// Load default policies
	if cfg.DefaultPolicies != nil {
		if v, err := models.VerdictFromString(cfg.DefaultPolicies.DefaultInboundPolicy); err == nil {
			m.defaultInbound = v
		}
		if v, err := models.VerdictFromString(cfg.DefaultPolicies.DefaultOutboundPolicy); err == nil {
			m.defaultOutbound = v
		}
		m.matcher.SetDefaultPolicies(m.defaultInbound, m.defaultOutbound, models.VerdictDrop)
	}

	// Load rules
	for _, ruleCfg := range cfg.Rules {
		rule, err := ruleCfg.ToModel()
		if err != nil {
			return fmt.Errorf("failed to parse rule %d: %w", ruleCfg.RuleID, err)
		}
		if err := m.store.Add(rule); err != nil {
			return fmt.Errorf("failed to add rule %d: %w", rule.RuleID, err)
		}
	}

	m.loadedAt = time.Now()
	m.version = cfg.Version

	return nil
}

// LoadFromRules loads rules from a slice.
func (m *Manager) LoadFromRules(rules []*models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.store.Clear()
	m.sortedRulesValid = false

	for _, rule := range rules {
		if err := m.store.Add(rule); err != nil {
			return err
		}
	}

	m.loadedAt = time.Now()
	return nil
}

// ============================================================================
// Rule CRUD Operations (RuleStore interface)
// ============================================================================

// Add adds a rule to the manager.
func (m *Manager) Add(rule *models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sortedRulesValid = false
	return m.store.Add(rule)
}

// Remove removes a rule by ID.
func (m *Manager) Remove(ruleID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sortedRulesValid = false
	return m.store.Remove(ruleID)
}

// Get retrieves a rule by ID.
func (m *Manager) Get(ruleID int) (*models.FirewallRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.Get(ruleID)
}

// GetByName retrieves a rule by name.
func (m *Manager) GetByName(name string) (*models.FirewallRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.GetByName(name)
}

// All returns all rules.
func (m *Manager) All() []*models.FirewallRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.All()
}

// Count returns the number of rules.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.Count()
}

// Clear removes all rules.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.store.Clear()
	m.sortedRules = nil
	m.sortedRulesValid = false
}

// GetByGroup returns all rules in a group.
func (m *Manager) GetByGroup(groupName string) []*models.FirewallRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.GetByGroup(groupName)
}

// GetSortedByPriority returns rules sorted by priority.
func (m *Manager) GetSortedByPriority() []*models.FirewallRule {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sortedRulesValid && m.sortedRules != nil {
		result := make([]*models.FirewallRule, len(m.sortedRules))
		copy(result, m.sortedRules)
		return result
	}

	// Get enabled rules and sort them
	allRules := m.store.All()
	enabled := FilterEnabled(allRules)
	m.sortedRules = m.sorter.Sort(enabled)
	m.sortedRulesValid = true

	result := make([]*models.FirewallRule, len(m.sortedRules))
	copy(result, m.sortedRules)
	return result
}

// EnableRule enables a rule.
func (m *Manager) EnableRule(ruleID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sortedRulesValid = false
	return m.store.EnableRule(ruleID)
}

// DisableRule disables a rule.
func (m *Manager) DisableRule(ruleID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sortedRulesValid = false
	return m.store.DisableRule(ruleID)
}

// ============================================================================
// Group Operations
// ============================================================================

// AddGroup adds a rule group.
func (m *Manager) AddGroup(group *models.RuleGroup) error {
	if err := m.groups.Add(group); err != nil {
		return err
	}
	m.sorter.SetGroupPriority(group.Name, group.Priority)
	return nil
}

// RemoveGroup removes a group by name.
func (m *Manager) RemoveGroup(name string) bool {
	return m.groups.Remove(name)
}

// GetGroup retrieves a group by name.
func (m *Manager) GetGroup(name string) (*models.RuleGroup, bool) {
	return m.groups.Get(name)
}

// AllGroups returns all groups.
func (m *Manager) AllGroups() []*models.RuleGroup {
	return m.groups.All()
}

// ============================================================================
// Matching (RuleMatcher interface)
// ============================================================================

// Match evaluates a packet against all rules.
func (m *Manager) Match(pkt *models.PacketMetadata) *MatchResult {
	rules := m.GetSortedByPriority()
	return m.matcher.Match(pkt, rules)
}

// MatchWithConnection evaluates considering connection state.
func (m *Manager) MatchWithConnection(pkt *models.PacketMetadata, conn *models.ConnectionInfo) *MatchResult {
	rules := m.GetSortedByPriority()
	return m.matcher.MatchWithConnection(pkt, conn, rules)
}

// GetMatchingRules returns all rules that match a packet.
func (m *Manager) GetMatchingRules(pkt *models.PacketMetadata) []*models.FirewallRule {
	rules := m.GetSortedByPriority()
	var matching []*models.FirewallRule

	for _, rule := range rules {
		if m.matcher.matchRule(pkt, rule) {
			matching = append(matching, rule)
		}
	}

	return matching
}

// GetDefaultVerdict returns the default verdict for a direction.
func (m *Manager) GetDefaultVerdict(direction models.Direction) models.Verdict {
	return m.matcher.GetDefaultVerdict(direction)
}

// SetDefaultInboundPolicy sets the default inbound policy.
func (m *Manager) SetDefaultInboundPolicy(verdict models.Verdict) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.defaultInbound = verdict
	m.matcher.SetDefaultInboundPolicy(verdict)
}

// SetDefaultOutboundPolicy sets the default outbound policy.
func (m *Manager) SetDefaultOutboundPolicy(verdict models.Verdict) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.defaultOutbound = verdict
	m.matcher.SetDefaultOutboundPolicy(verdict)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns comprehensive statistics.
func (m *Manager) GetStats() *ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storeStats := m.store.GetStoreStats()
	matcherStats := m.matcher.GetStats()

	stats := NewManagerStats()
	stats.TotalRules = storeStats.TotalRules
	stats.EnabledRules = storeStats.EnabledRules
	stats.DisabledRules = storeStats.DisabledRules
	stats.TotalGroups = m.groups.Count()
	stats.RulesPerGroup = storeStats.RulesPerGroup
	stats.MatchCount = matcherStats.TotalMatches
	stats.HitCounts = matcherStats.HitCounts

	// Count by action/direction/protocol
	for _, rule := range m.store.All() {
		stats.RulesByAction[rule.Action.String()]++
		stats.RulesByDirection[rule.Direction.String()]++
		stats.RulesByProtocol[rule.Protocol.String()]++
	}

	return stats
}

// GetMatcherStats returns matcher-specific statistics.
func (m *Manager) GetMatcherStats() MatcherStats {
	return m.matcher.GetStats()
}

// ResetStats resets all statistics.
func (m *Manager) ResetStats() {
	m.matcher.ResetStats()
}

// ============================================================================
// Metadata
// ============================================================================

// GetLoadedAt returns when the configuration was loaded.
func (m *Manager) GetLoadedAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadedAt
}

// GetVersion returns the configuration version.
func (m *Manager) GetVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}
