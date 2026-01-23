// Package wfp provides filter management for WFP integration.
// Handles adding, removing, and tracking filters.
package wfp

import (
	"fmt"
	"sync"

	"firewall_engine/internal/wfp/bindings"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Filter Manager
// ============================================================================

// FilterManager handles WFP filter CRUD operations.
type FilterManager struct {
	engine     *Engine
	translator *Translator

	// Filter tracking
	mu        sync.RWMutex
	filters   map[string]*FilterRecord // ruleID -> FilterRecord
	filterIDs map[uint64]string        // filterID -> ruleID (reverse lookup)
}

// FilterRecord tracks a filter installation.
type FilterRecord struct {
	RuleID    string
	RuleName  string
	FilterID  uint64
	FilterKey bindings.GUID
	LayerName string
	Action    bindings.FWP_ACTION0
	Installed bool
}

// NewFilterManager creates a new filter manager.
func NewFilterManager(engine *Engine) *FilterManager {
	return &FilterManager{
		engine:     engine,
		translator: NewTranslator(),
		filters:    make(map[string]*FilterRecord),
		filterIDs:  make(map[uint64]string),
	}
}

// ============================================================================
// Filter CRUD Operations
// ============================================================================

// AddFilter translates and installs a firewall rule as a WFP filter.
// Returns the filter ID assigned by WFP.
func (fm *FilterManager) AddFilter(rule *models.FirewallRule) (uint64, error) {
	if err := fm.engine.RequireOpen(); err != nil {
		return 0, fmt.Errorf("cannot add filter: %w", err)
	}

	// Check if already installed
	fm.mu.RLock()
	if existing, found := fm.filters[rule.ID.String()]; found && existing.Installed {
		fm.mu.RUnlock()
		return existing.FilterID, nil
	}
	fm.mu.RUnlock()

	// Translate rule to filter(s)
	result, err := fm.translator.TranslateRule(rule)
	if err != nil {
		return 0, fmt.Errorf("translation failed: %w", err)
	}

	if len(result.Filters) == 0 {
		return 0, fmt.Errorf("no filters generated for rule: %s", rule.Name)
	}

	// Install first filter (primary)
	// TODO: Handle multiple filters per rule
	filter := result.Filters[0]
	filterID, err := fm.engine.GetBindings().AddFilter(filter)
	if err != nil {
		return 0, fmt.Errorf("failed to install filter: %w", err)
	}

	// Track filter
	fm.mu.Lock()
	record := &FilterRecord{
		RuleID:    rule.ID.String(),
		RuleName:  rule.Name,
		FilterID:  filterID,
		FilterKey: filter.FilterKey,
		Action:    filter.Action,
		Installed: true,
	}
	fm.filters[rule.ID.String()] = record
	fm.filterIDs[filterID] = rule.ID.String()
	fm.mu.Unlock()

	// Track in engine stats
	fm.engine.TrackFilter(rule.ID.String(), filterID)

	return filterID, nil
}

// DeleteFilter removes a filter by rule ID.
func (fm *FilterManager) DeleteFilter(ruleID string) error {
	if err := fm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot delete filter: %w", err)
	}

	fm.mu.Lock()
	record, found := fm.filters[ruleID]
	if !found || !record.Installed {
		fm.mu.Unlock()
		return nil // Not installed
	}
	fm.mu.Unlock()

	// Delete from WFP
	if err := fm.engine.GetBindings().DeleteFilterByKey(record.FilterKey); err != nil {
		if !bindings.IsNotFound(err) {
			return fmt.Errorf("failed to delete filter: %w", err)
		}
	}

	// Update tracking
	fm.mu.Lock()
	delete(fm.filterIDs, record.FilterID)
	delete(fm.filters, ruleID)
	fm.mu.Unlock()

	fm.engine.UntrackFilter(ruleID)

	return nil
}

// DeleteFilterByID removes a filter by its WFP filter ID.
func (fm *FilterManager) DeleteFilterByID(filterID uint64) error {
	if err := fm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot delete filter: %w", err)
	}

	fm.mu.RLock()
	ruleID, found := fm.filterIDs[filterID]
	fm.mu.RUnlock()

	if !found {
		// Try direct deletion
		return fm.engine.GetBindings().DeleteFilterByID(filterID)
	}

	return fm.DeleteFilter(ruleID)
}

// UpdateFilter updates a filter by removing and re-adding it.
func (fm *FilterManager) UpdateFilter(rule *models.FirewallRule) error {
	// Delete existing
	if err := fm.DeleteFilter(rule.ID.String()); err != nil {
		return fmt.Errorf("failed to delete old filter: %w", err)
	}

	// Add new
	_, err := fm.AddFilter(rule)
	if err != nil {
		return fmt.Errorf("failed to add updated filter: %w", err)
	}

	return nil
}

// ============================================================================
// Enumeration
// ============================================================================

// GetFilter returns the filter record for a rule ID.
func (fm *FilterManager) GetFilter(ruleID string) (*FilterRecord, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	record, found := fm.filters[ruleID]
	return record, found
}

// GetFilterByID returns the filter record for a filter ID.
func (fm *FilterManager) GetFilterByID(filterID uint64) (*FilterRecord, bool) {
	fm.mu.RLock()
	ruleID, found := fm.filterIDs[filterID]
	if !found {
		fm.mu.RUnlock()
		return nil, false
	}
	record := fm.filters[ruleID]
	fm.mu.RUnlock()
	return record, record != nil
}

// GetAllFilters returns all tracked filter records.
func (fm *FilterManager) GetAllFilters() []*FilterRecord {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	records := make([]*FilterRecord, 0, len(fm.filters))
	for _, record := range fm.filters {
		records = append(records, record)
	}
	return records
}

// GetFilterCount returns the number of installed filters.
func (fm *FilterManager) GetFilterCount() int {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return len(fm.filters)
}

// IsInstalled checks if a rule has an installed filter.
func (fm *FilterManager) IsInstalled(ruleID string) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	record, found := fm.filters[ruleID]
	return found && record.Installed
}

// ============================================================================
// Bulk Operations
// ============================================================================

// AddFilters installs multiple rules as filters.
func (fm *FilterManager) AddFilters(rules []*models.FirewallRule) ([]uint64, error) {
	if err := fm.engine.RequireOpen(); err != nil {
		return nil, fmt.Errorf("cannot add filters: %w", err)
	}

	filterIDs := make([]uint64, 0, len(rules))
	var errs []error

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		id, err := fm.AddFilter(rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", rule.Name, err))
			continue
		}
		filterIDs = append(filterIDs, id)
	}

	if len(errs) > 0 {
		return filterIDs, fmt.Errorf("some filters failed: %v", errs)
	}

	return filterIDs, nil
}

// DeleteAllFilters removes all tracked filters.
func (fm *FilterManager) DeleteAllFilters() error {
	if err := fm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot delete filters: %w", err)
	}

	fm.mu.RLock()
	ruleIDs := make([]string, 0, len(fm.filters))
	for ruleID := range fm.filters {
		ruleIDs = append(ruleIDs, ruleID)
	}
	fm.mu.RUnlock()

	var errs []error
	for _, ruleID := range ruleIDs {
		if err := fm.DeleteFilter(ruleID); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("some deletions failed: %v", errs)
	}

	return nil
}

// ============================================================================
// Synchronization
// ============================================================================

// Sync synchronizes installed filters with the provided rules.
// Adds missing filters and removes stale ones.
func (fm *FilterManager) Sync(rules []*models.FirewallRule) error {
	if err := fm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("cannot sync: %w", err)
	}

	// Build set of rule IDs that should be installed
	wantedRules := make(map[string]*models.FirewallRule)
	for _, rule := range rules {
		if rule != nil && rule.Enabled {
			wantedRules[rule.ID.String()] = rule
		}
	}

	// Remove stale filters
	fm.mu.RLock()
	staleRuleIDs := make([]string, 0)
	for ruleID := range fm.filters {
		if _, wanted := wantedRules[ruleID]; !wanted {
			staleRuleIDs = append(staleRuleIDs, ruleID)
		}
	}
	fm.mu.RUnlock()

	for _, ruleID := range staleRuleIDs {
		_ = fm.DeleteFilter(ruleID)
	}

	// Add missing filters
	for ruleID, rule := range wantedRules {
		if !fm.IsInstalled(ruleID) {
			_, _ = fm.AddFilter(rule)
		}
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// FilterStats contains filter manager statistics.
type FilterStats struct {
	TotalFilters  int
	BlockFilters  int
	PermitFilters int
}

// GetStats returns filter statistics.
func (fm *FilterManager) GetStats() FilterStats {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	stats := FilterStats{
		TotalFilters: len(fm.filters),
	}

	for _, record := range fm.filters {
		switch record.Action.Type {
		case bindings.FWP_ACTION_BLOCK:
			stats.BlockFilters++
		case bindings.FWP_ACTION_PERMIT:
			stats.PermitFilters++
		}
	}

	return stats
}
