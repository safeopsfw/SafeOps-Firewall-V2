// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"sort"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Priority Sorting
// ============================================================================

// PrioritySorter sorts rules by priority for evaluation.
type PrioritySorter struct {
	// GroupPriorities maps group names to their priorities.
	GroupPriorities map[string]int
}

// NewPrioritySorter creates a new priority sorter.
func NewPrioritySorter() *PrioritySorter {
	return &PrioritySorter{
		GroupPriorities: make(map[string]int),
	}
}

// SetGroupPriority sets the priority for a rule group.
func (p *PrioritySorter) SetGroupPriority(groupName string, priority int) {
	p.GroupPriorities[groupName] = priority
}

// SetGroupPriorities sets priorities for multiple groups.
func (p *PrioritySorter) SetGroupPriorities(priorities map[string]int) {
	for name, priority := range priorities {
		p.GroupPriorities[name] = priority
	}
}

// Sort sorts rules by priority.
// Priority order:
// 1. Group priority (lower number = higher priority)
// 2. Rule priority within group (lower number = higher priority)
// 3. Rule ID (for stable ordering)
func (p *PrioritySorter) Sort(rules []*models.FirewallRule) []*models.FirewallRule {
	sorted := make([]*models.FirewallRule, len(rules))
	copy(sorted, rules)

	sort.Slice(sorted, func(i, j int) bool {
		return p.Less(sorted[i], sorted[j])
	})

	return sorted
}

// Less returns true if rule a has higher priority than rule b.
func (p *PrioritySorter) Less(a, b *models.FirewallRule) bool {
	ga := p.getGroupPriority(a.GroupName)
	gb := p.getGroupPriority(b.GroupName)
	if ga != gb {
		return ga < gb
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.RuleID < b.RuleID
}

// getGroupPriority returns the priority for a group.
func (p *PrioritySorter) getGroupPriority(groupName string) int {
	if groupName == "" {
		return 9999
	}
	if priority, ok := p.GroupPriorities[groupName]; ok {
		return priority
	}
	return 1000
}

// SortInPlace sorts the rules slice in place.
func (p *PrioritySorter) SortInPlace(rules []*models.FirewallRule) {
	sort.Slice(rules, func(i, j int) bool {
		return p.Less(rules[i], rules[j])
	})
}

// StandardGroupPriorities returns recommended group priorities.
func StandardGroupPriorities() map[string]int {
	return map[string]int{
		"security":       10,
		"block":          10,
		"emergency":      0,
		"system":         20,
		"infrastructure": 20,
		"whitelist":      30,
		"trusted":        30,
		"applications":   50,
		"services":       50,
		"custom":         100,
		"monitor":        200,
		"_default":       9999,
	}
}

// ApplyStandardPriorities applies standard group priorities to a sorter.
func ApplyStandardPriorities(sorter *PrioritySorter) {
	sorter.SetGroupPriorities(StandardGroupPriorities())
}

// SortByPriority sorts rules by priority using default settings.
func SortByPriority(rules []*models.FirewallRule) []*models.FirewallRule {
	sorter := NewPrioritySorter()
	ApplyStandardPriorities(sorter)
	return sorter.Sort(rules)
}

// FilterEnabled returns only enabled rules.
func FilterEnabled(rules []*models.FirewallRule) []*models.FirewallRule {
	result := make([]*models.FirewallRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			result = append(result, rule)
		}
	}
	return result
}

// FilterByDirection returns rules matching a direction.
func FilterByDirection(rules []*models.FirewallRule, dir models.Direction) []*models.FirewallRule {
	result := make([]*models.FirewallRule, 0)
	for _, rule := range rules {
		if rule.Direction == dir || rule.Direction == models.DirectionAny {
			result = append(result, rule)
		}
	}
	return result
}
