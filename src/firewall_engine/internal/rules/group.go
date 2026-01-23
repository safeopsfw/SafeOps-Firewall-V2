// Package rules provides rule matching and management for the firewall engine.
package rules

import (
	"fmt"
	"sync"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Rule Group Management
// ============================================================================

// GroupManager manages rule groups.
type GroupManager struct {
	mu     sync.RWMutex
	groups map[string]*models.RuleGroup
}

// NewGroupManager creates a new group manager.
func NewGroupManager() *GroupManager {
	return &GroupManager{
		groups: make(map[string]*models.RuleGroup),
	}
}

// Add adds a new rule group.
func (gm *GroupManager) Add(group *models.RuleGroup) error {
	if group == nil {
		return fmt.Errorf("group is nil")
	}
	if group.Name == "" {
		return fmt.Errorf("group name is required")
	}

	gm.mu.Lock()
	defer gm.mu.Unlock()

	if _, exists := gm.groups[group.Name]; exists {
		return fmt.Errorf("group %q already exists", group.Name)
	}

	gm.groups[group.Name] = group
	return nil
}

// Remove removes a group by name.
func (gm *GroupManager) Remove(name string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if _, exists := gm.groups[name]; !exists {
		return false
	}

	delete(gm.groups, name)
	return true
}

// Get retrieves a group by name.
func (gm *GroupManager) Get(name string) (*models.RuleGroup, bool) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	group, ok := gm.groups[name]
	return group, ok
}

// Exists checks if a group exists.
func (gm *GroupManager) Exists(name string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	_, ok := gm.groups[name]
	return ok
}

// All returns all groups.
func (gm *GroupManager) All() []*models.RuleGroup {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	result := make([]*models.RuleGroup, 0, len(gm.groups))
	for _, group := range gm.groups {
		result = append(result, group)
	}
	return result
}

// Names returns all group names.
func (gm *GroupManager) Names() []string {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	names := make([]string, 0, len(gm.groups))
	for name := range gm.groups {
		names = append(names, name)
	}
	return names
}

// Count returns the number of groups.
func (gm *GroupManager) Count() int {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return len(gm.groups)
}

// Clear removes all groups.
func (gm *GroupManager) Clear() {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.groups = make(map[string]*models.RuleGroup)
}

// GetPriorities returns a map of group name to priority.
func (gm *GroupManager) GetPriorities() map[string]int {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	priorities := make(map[string]int)
	for name, group := range gm.groups {
		priorities[name] = group.Priority
	}
	return priorities
}

// SetPriority sets the priority for a group.
func (gm *GroupManager) SetPriority(name string, priority int) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	group, ok := gm.groups[name]
	if !ok {
		return false
	}

	group.Priority = priority
	return true
}

// Enable enables a group.
func (gm *GroupManager) Enable(name string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	group, ok := gm.groups[name]
	if !ok {
		return false
	}

	group.Enabled = true
	return true
}

// Disable disables a group.
func (gm *GroupManager) Disable(name string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	group, ok := gm.groups[name]
	if !ok {
		return false
	}

	group.Enabled = false
	return true
}

// IsEnabled checks if a group is enabled.
func (gm *GroupManager) IsEnabled(name string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	group, ok := gm.groups[name]
	if !ok {
		return false
	}

	return group.Enabled
}

// ============================================================================
// Standard Groups
// ============================================================================

// CreateStandardGroups creates a set of standard rule groups.
func CreateStandardGroups() []*models.RuleGroup {
	return []*models.RuleGroup{
		{
			Name:        "emergency",
			Description: "Emergency blocking rules - highest priority",
			Priority:    0,
			Enabled:     true,
		},
		{
			Name:        "security",
			Description: "Security rules - block malicious traffic",
			Priority:    10,
			Enabled:     true,
		},
		{
			Name:        "system",
			Description: "System rules - allow core system services",
			Priority:    20,
			Enabled:     true,
		},
		{
			Name:        "trusted",
			Description: "Trusted networks and hosts",
			Priority:    30,
			Enabled:     true,
		},
		{
			Name:        "applications",
			Description: "Application-specific rules",
			Priority:    50,
			Enabled:     true,
		},
		{
			Name:        "services",
			Description: "Service rules - server applications",
			Priority:    50,
			Enabled:     true,
		},
		{
			Name:        "custom",
			Description: "User-defined custom rules",
			Priority:    100,
			Enabled:     true,
		},
		{
			Name:        "monitor",
			Description: "Monitoring rules - log only, no action",
			Priority:    200,
			Enabled:     true,
		},
	}
}

// LoadStandardGroups adds standard groups to the manager.
func (gm *GroupManager) LoadStandardGroups() {
	for _, group := range CreateStandardGroups() {
		_ = gm.Add(group) // Ignore errors for existing groups
	}
}

// ============================================================================
// Group Builder
// ============================================================================

// GroupBuilder provides a fluent interface for creating groups.
type GroupBuilder struct {
	group *models.RuleGroup
}

// NewGroupBuilder creates a new group builder.
func NewGroupBuilder(name string) *GroupBuilder {
	return &GroupBuilder{
		group: &models.RuleGroup{
			Name:     name,
			Priority: 100,
			Enabled:  true,
		},
	}
}

// Description sets the description.
func (gb *GroupBuilder) Description(desc string) *GroupBuilder {
	gb.group.Description = desc
	return gb
}

// Priority sets the priority.
func (gb *GroupBuilder) Priority(priority int) *GroupBuilder {
	gb.group.Priority = priority
	return gb
}

// Enabled sets whether the group is enabled.
func (gb *GroupBuilder) Enabled(enabled bool) *GroupBuilder {
	gb.group.Enabled = enabled
	return gb
}

// Build finalizes and returns the group.
func (gb *GroupBuilder) Build() *models.RuleGroup {
	return gb.group
}
