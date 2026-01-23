// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"fmt"
	"sort"
	"sync"

	"firewall_engine/pkg/models"
)

// ============================================================================
// In-Memory Rule Store
// ============================================================================

// Store provides thread-safe in-memory storage for firewall rules.
type Store struct {
	mu sync.RWMutex

	// Primary storage: ruleID -> rule
	rules map[int]*models.FirewallRule

	// Indexes for fast lookup
	rulesByName  map[string]*models.FirewallRule
	rulesByGroup map[string][]*models.FirewallRule

	// Cached sorted rule list (invalidated on changes)
	sortedRules      []*models.FirewallRule
	sortedRulesValid bool

	// Group priorities for sorting
	groupPriorities map[string]int
}

// NewStore creates a new in-memory rule store.
func NewStore() *Store {
	return &Store{
		rules:           make(map[int]*models.FirewallRule),
		rulesByName:     make(map[string]*models.FirewallRule),
		rulesByGroup:    make(map[string][]*models.FirewallRule),
		groupPriorities: make(map[string]int),
	}
}

// Add adds a rule to the store.
func (s *Store) Add(rule *models.FirewallRule) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate ID
	if _, exists := s.rules[rule.RuleID]; exists {
		return fmt.Errorf("rule with ID %d already exists", rule.RuleID)
	}

	// Check for duplicate name
	if rule.Name != "" {
		if _, exists := s.rulesByName[rule.Name]; exists {
			return fmt.Errorf("rule with name %q already exists", rule.Name)
		}
		s.rulesByName[rule.Name] = rule
	}

	// Add to primary storage
	s.rules[rule.RuleID] = rule

	// Add to group index
	groupName := rule.GroupName
	if groupName == "" {
		groupName = "_default"
	}
	s.rulesByGroup[groupName] = append(s.rulesByGroup[groupName], rule)

	// Invalidate cached sorted list
	s.sortedRulesValid = false

	return nil
}

// Remove removes a rule by ID.
func (s *Store) Remove(ruleID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule, exists := s.rules[ruleID]
	if !exists {
		return false
	}

	// Remove from primary storage
	delete(s.rules, ruleID)

	// Remove from name index
	if rule.Name != "" {
		delete(s.rulesByName, rule.Name)
	}

	// Remove from group index
	groupName := rule.GroupName
	if groupName == "" {
		groupName = "_default"
	}
	s.removeFromGroup(groupName, ruleID)

	// Invalidate cached sorted list
	s.sortedRulesValid = false

	return true
}

// removeFromGroup removes a rule from a group's list.
func (s *Store) removeFromGroup(groupName string, ruleID int) {
	rules := s.rulesByGroup[groupName]
	for i, r := range rules {
		if r.RuleID == ruleID {
			s.rulesByGroup[groupName] = append(rules[:i], rules[i+1:]...)
			break
		}
	}
}

// Get retrieves a rule by ID.
func (s *Store) Get(ruleID int) (*models.FirewallRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rule, ok := s.rules[ruleID]
	return rule, ok
}

// GetByName retrieves a rule by name.
func (s *Store) GetByName(name string) (*models.FirewallRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rule, ok := s.rulesByName[name]
	return rule, ok
}

// All returns all rules (unsorted).
func (s *Store) All() []*models.FirewallRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.FirewallRule, 0, len(s.rules))
	for _, rule := range s.rules {
		result = append(result, rule)
	}
	return result
}

// Count returns the number of rules.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// Clear removes all rules.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = make(map[int]*models.FirewallRule)
	s.rulesByName = make(map[string]*models.FirewallRule)
	s.rulesByGroup = make(map[string][]*models.FirewallRule)
	s.sortedRules = nil
	s.sortedRulesValid = false
}

// GetByGroup returns all rules in a group.
func (s *Store) GetByGroup(groupName string) []*models.FirewallRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if groupName == "" {
		groupName = "_default"
	}

	// Return a copy to prevent mutation
	rules := s.rulesByGroup[groupName]
	result := make([]*models.FirewallRule, len(rules))
	copy(result, rules)
	return result
}

// GetSortedByPriority returns rules sorted by group priority then rule priority.
func (s *Store) GetSortedByPriority() []*models.FirewallRule {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sortedRulesValid && s.sortedRules != nil {
		// Return cached sorted list
		result := make([]*models.FirewallRule, len(s.sortedRules))
		copy(result, s.sortedRules)
		return result
	}

	// Build and sort
	rules := make([]*models.FirewallRule, 0, len(s.rules))
	for _, rule := range s.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}

	s.sortRules(rules)

	// Cache the result
	s.sortedRules = rules
	s.sortedRulesValid = true

	// Return a copy
	result := make([]*models.FirewallRule, len(rules))
	copy(result, rules)
	return result
}

// sortRules sorts rules by group priority, then rule priority, then rule ID.
func (s *Store) sortRules(rules []*models.FirewallRule) {
	sort.Slice(rules, func(i, j int) bool {
		ri, rj := rules[i], rules[j]

		// First, compare group priorities
		gi := s.getGroupPriority(ri.GroupName)
		gj := s.getGroupPriority(rj.GroupName)
		if gi != gj {
			return gi < gj // Lower priority number = higher priority
		}

		// Then, compare rule priorities within the same group
		if ri.Priority != rj.Priority {
			return ri.Priority < rj.Priority
		}

		// Finally, compare by rule ID for stable ordering
		return ri.RuleID < rj.RuleID
	})
}

// getGroupPriority returns the priority for a group (lower = higher priority).
func (s *Store) getGroupPriority(groupName string) int {
	if groupName == "" {
		return 9999 // Default group has lowest priority
	}
	if priority, ok := s.groupPriorities[groupName]; ok {
		return priority
	}
	return 1000 // Unknown groups get medium priority
}

// SetGroupPriority sets the priority for a rule group.
func (s *Store) SetGroupPriority(groupName string, priority int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.groupPriorities[groupName] = priority
	s.sortedRulesValid = false // Invalidate cache
}

// SetGroupPriorities sets priorities for multiple groups.
func (s *Store) SetGroupPriorities(priorities map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, priority := range priorities {
		s.groupPriorities[name] = priority
	}
	s.sortedRulesValid = false
}

// ============================================================================
// Rule Enable/Disable
// ============================================================================

// EnableRule enables a rule by ID.
func (s *Store) EnableRule(ruleID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule, ok := s.rules[ruleID]
	if !ok {
		return false
	}

	if !rule.Enabled {
		rule.Enabled = true
		s.sortedRulesValid = false
	}
	return true
}

// DisableRule disables a rule by ID.
func (s *Store) DisableRule(ruleID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule, ok := s.rules[ruleID]
	if !ok {
		return false
	}

	if rule.Enabled {
		rule.Enabled = false
		s.sortedRulesValid = false
	}
	return true
}

// ============================================================================
// Statistics
// ============================================================================

// GetStoreStats returns statistics about the store.
func (s *Store) GetStoreStats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := StoreStats{
		TotalRules:    len(s.rules),
		TotalGroups:   len(s.rulesByGroup),
		RulesPerGroup: make(map[string]int),
	}

	for groupName, rules := range s.rulesByGroup {
		stats.RulesPerGroup[groupName] = len(rules)
	}

	for _, rule := range s.rules {
		if rule.Enabled {
			stats.EnabledRules++
		} else {
			stats.DisabledRules++
		}
	}

	return stats
}

// StoreStats contains statistics about rule storage.
type StoreStats struct {
	TotalRules    int            `json:"total_rules"`
	EnabledRules  int            `json:"enabled_rules"`
	DisabledRules int            `json:"disabled_rules"`
	TotalGroups   int            `json:"total_groups"`
	RulesPerGroup map[string]int `json:"rules_per_group"`
}

// ============================================================================
// Bulk Operations
// ============================================================================

// AddAll adds multiple rules at once.
func (s *Store) AddAll(rules []*models.FirewallRule) error {
	for _, rule := range rules {
		if err := s.Add(rule); err != nil {
			return err
		}
	}
	return nil
}

// LoadFromSlice replaces all rules with the given slice.
func (s *Store) LoadFromSlice(rules []*models.FirewallRule) error {
	s.Clear()
	return s.AddAll(rules)
}
