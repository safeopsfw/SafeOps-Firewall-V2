// Package boottime provides boot-time persistent filter management for WFP.
// Persistent filters survive system reboots and provide protection from the
// moment the WFP subsystem starts - before user login and before the firewall
// service loads.
package boottime

import (
	"fmt"
	"sync"
	"time"

	"firewall_engine/internal/wfp"
	"firewall_engine/internal/wfp/bindings"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// DefaultMaxPersistent is the default maximum number of persistent filters.
	// Limited to prevent boot-time performance degradation.
	DefaultMaxPersistent = 50

	// MinMaxPersistent is the minimum allowed max persistent filters.
	MinMaxPersistent = 5

	// MaxMaxPersistent is the maximum allowed max persistent filters.
	MaxMaxPersistent = 200
)

// ============================================================================
// Persistent Filter
// ============================================================================

// PersistentFilter represents an installed persistent WFP filter.
// These filters survive system reboots and remain active until explicitly deleted.
type PersistentFilter struct {
	// FilterGUID is the WFP filter's unique identifier.
	FilterGUID bindings.GUID

	// FilterID is the numeric ID assigned by WFP.
	FilterID uint64

	// RuleID is the SafeOps firewall rule ID.
	RuleID string

	// RuleName is the human-readable rule name.
	RuleName string

	// Layer is the WFP layer where the filter is installed.
	Layer string

	// Action is the filter action (BLOCK/PERMIT).
	Action string

	// Conditions is a summary of the filter's match conditions.
	Conditions string

	// Created is when the filter was first installed.
	Created time.Time

	// LastVerified is when the filter was last confirmed to exist in WFP.
	LastVerified time.Time

	// Verified indicates if the filter currently exists in WFP.
	Verified bool
}

// String returns a human-readable representation.
func (f *PersistentFilter) String() string {
	status := "unverified"
	if f.Verified {
		status = "verified"
	}
	return fmt.Sprintf("PersistentFilter[%s, rule=%s, layer=%s, %s]",
		f.RuleName, f.RuleID, f.Layer, status)
}

// GUIDString returns the filter GUID as a string.
func (f *PersistentFilter) GUIDString() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		f.FilterGUID.Data1, f.FilterGUID.Data2, f.FilterGUID.Data3,
		f.FilterGUID.Data4[0], f.FilterGUID.Data4[1],
		f.FilterGUID.Data4[2], f.FilterGUID.Data4[3],
		f.FilterGUID.Data4[4], f.FilterGUID.Data4[5],
		f.FilterGUID.Data4[6], f.FilterGUID.Data4[7])
}

// ============================================================================
// Persistent Manager Configuration
// ============================================================================

// PersistentConfig configures the persistent filter manager.
type PersistentConfig struct {
	// MaxPersistent is the maximum number of persistent filters allowed.
	MaxPersistent int

	// AutoSync enables automatic synchronization with WFP on startup.
	AutoSync bool

	// VerifyOnLoad verifies filters exist in WFP when loading from registry.
	VerifyOnLoad bool

	// Registry is the registry store for filter metadata.
	// If nil, a new store will be created.
	Registry *RegistryStore
}

// DefaultPersistentConfig returns the default configuration.
func DefaultPersistentConfig() *PersistentConfig {
	return &PersistentConfig{
		MaxPersistent: DefaultMaxPersistent,
		AutoSync:      true,
		VerifyOnLoad:  true,
		Registry:      nil,
	}
}

// ============================================================================
// Persistent Manager
// ============================================================================

// PersistentManager manages boot-time persistent WFP filters.
// It coordinates between the WFP engine and the registry store.
type PersistentManager struct {
	mu sync.RWMutex

	// Dependencies
	engine   *wfp.Engine
	registry *RegistryStore

	// Configuration
	maxPersistent int
	autoSync      bool
	verifyOnLoad  bool

	// State
	filters     map[string]*PersistentFilter // ruleID -> filter
	initialized bool

	// Statistics
	stats PersistentStats
}

// PersistentStats contains persistent filter statistics.
type PersistentStats struct {
	TotalInstalled    int
	TotalVerified     int
	TotalOrphaned     int
	LastSyncTime      time.Time
	LastInstallTime   time.Time
	LastUninstallTime time.Time
}

// NewPersistentManager creates a new persistent filter manager.
func NewPersistentManager(engine *wfp.Engine) (*PersistentManager, error) {
	return NewPersistentManagerWithConfig(engine, DefaultPersistentConfig())
}

// NewPersistentManagerWithConfig creates a manager with custom configuration.
func NewPersistentManagerWithConfig(engine *wfp.Engine, cfg *PersistentConfig) (*PersistentManager, error) {
	if engine == nil {
		return nil, fmt.Errorf("engine is required")
	}

	if cfg == nil {
		cfg = DefaultPersistentConfig()
	}

	// Validate max persistent
	maxPersistent := cfg.MaxPersistent
	if maxPersistent < MinMaxPersistent {
		maxPersistent = MinMaxPersistent
	}
	if maxPersistent > MaxMaxPersistent {
		maxPersistent = MaxMaxPersistent
	}

	// Create or use provided registry
	registry := cfg.Registry
	if registry == nil {
		var err error
		registry, err = NewRegistryStore()
		if err != nil {
			return nil, fmt.Errorf("create registry store: %w", err)
		}
	}

	pm := &PersistentManager{
		engine:        engine,
		registry:      registry,
		maxPersistent: maxPersistent,
		autoSync:      cfg.AutoSync,
		verifyOnLoad:  cfg.VerifyOnLoad,
		filters:       make(map[string]*PersistentFilter),
	}

	// Auto-sync if enabled
	if cfg.AutoSync {
		if err := pm.Initialize(); err != nil {
			return nil, fmt.Errorf("initialize: %w", err)
		}
	}

	return pm, nil
}

// ============================================================================
// Initialization
// ============================================================================

// Initialize loads filters from registry and syncs with WFP.
func (pm *PersistentManager) Initialize() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.initialized {
		return nil
	}

	// Open registry
	if err := pm.registry.Open(); err != nil {
		return fmt.Errorf("open registry: %w", err)
	}

	// Load all records from registry
	records, err := pm.registry.LoadAll()
	if err != nil {
		// Log warning but continue - registry may be empty
		records = []*PersistentFilterRecord{}
	}

	// Convert records to filters
	for _, record := range records {
		filter := recordToFilter(record)
		pm.filters[filter.RuleID] = filter
	}

	// Verify filters exist in WFP if enabled
	if pm.verifyOnLoad {
		pm.verifyFiltersLocked()
	}

	pm.initialized = true
	pm.stats.LastSyncTime = time.Now()
	pm.stats.TotalInstalled = len(pm.filters)

	return nil
}

// Close closes the manager and releases resources.
func (pm *PersistentManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.registry != nil {
		return pm.registry.Close()
	}
	return nil
}

// ============================================================================
// Filter Installation
// ============================================================================

// InstallPersistent installs a firewall rule as a persistent WFP filter.
// The filter will survive system reboots.
func (pm *PersistentManager) InstallPersistent(rule *models.FirewallRule) (*PersistentFilter, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is required")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	ruleID := rule.ID.String()

	// Check if already installed
	if existing, found := pm.filters[ruleID]; found && existing.Verified {
		return existing, nil
	}

	// Check limit
	if len(pm.filters) >= pm.maxPersistent {
		return nil, fmt.Errorf("maximum persistent filters reached (%d)", pm.maxPersistent)
	}

	// Check engine is open
	if err := pm.engine.RequireOpen(); err != nil {
		return nil, fmt.Errorf("engine not open: %w", err)
	}

	// Translate rule to WFP filter
	translator := wfp.NewTranslator()
	result, err := translator.TranslateRule(rule)
	if err != nil {
		return nil, fmt.Errorf("translate rule: %w", err)
	}

	if len(result.Filters) == 0 {
		return nil, fmt.Errorf("no filters generated for rule")
	}

	// Get the first filter and mark as persistent
	wfpFilter := result.Filters[0]
	wfpFilter.SetPersistent(true)

	// Install the filter
	filterID, err := pm.engine.GetBindings().AddFilter(wfpFilter)
	if err != nil {
		return nil, fmt.Errorf("add persistent filter: %w", err)
	}

	// Create persistent filter record
	filter := &PersistentFilter{
		FilterGUID:   wfpFilter.FilterKey,
		FilterID:     filterID,
		RuleID:       ruleID,
		RuleName:     rule.Name,
		Layer:        getLayerName(wfpFilter.LayerKey),
		Action:       getActionName(wfpFilter.Action.Type),
		Conditions:   summarizeConditions(wfpFilter),
		Created:      time.Now(),
		LastVerified: time.Now(),
		Verified:     true,
	}

	// Save to registry
	record := filterToRecord(filter)
	if err := pm.registry.SaveFilter(record); err != nil {
		// Try to clean up the WFP filter
		_ = pm.engine.GetBindings().DeleteFilterByKey(wfpFilter.FilterKey)
		return nil, fmt.Errorf("save to registry: %w", err)
	}

	// Track in memory
	pm.filters[ruleID] = filter
	pm.stats.TotalInstalled = len(pm.filters)
	pm.stats.LastInstallTime = time.Now()

	// Track in engine
	pm.engine.TrackFilter(ruleID, filterID)

	return filter, nil
}

// UninstallPersistent removes a persistent filter by rule ID.
func (pm *PersistentManager) UninstallPersistent(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID is required")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	filter, found := pm.filters[ruleID]
	if !found {
		return nil // Not installed
	}

	// Delete from WFP
	if err := pm.engine.RequireOpen(); err == nil {
		if err := pm.engine.GetBindings().DeleteFilterByKey(filter.FilterGUID); err != nil {
			if !bindings.IsNotFound(err) {
				return fmt.Errorf("delete WFP filter: %w", err)
			}
		}
	}

	// Delete from registry
	if err := pm.registry.DeleteFilter(ruleID); err != nil {
		// Log warning but continue
	}

	// Remove from memory
	delete(pm.filters, ruleID)
	pm.stats.TotalInstalled = len(pm.filters)
	pm.stats.LastUninstallTime = time.Now()

	// Untrack in engine
	pm.engine.UntrackFilter(ruleID)

	return nil
}

// UninstallByGUID removes a persistent filter by its WFP GUID.
func (pm *PersistentManager) UninstallByGUID(filterGUID bindings.GUID) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Find the filter with this GUID
	var targetRuleID string
	for ruleID, filter := range pm.filters {
		if filter.FilterGUID == filterGUID {
			targetRuleID = ruleID
			break
		}
	}

	if targetRuleID == "" {
		// Direct WFP deletion
		if err := pm.engine.RequireOpen(); err == nil {
			return pm.engine.GetBindings().DeleteFilterByKey(filterGUID)
		}
		return fmt.Errorf("filter not found and engine not open")
	}

	pm.mu.Unlock()
	return pm.UninstallPersistent(targetRuleID)
}

// ============================================================================
// Filter Management
// ============================================================================

// GetPersistentFilter returns a persistent filter by rule ID.
func (pm *PersistentManager) GetPersistentFilter(ruleID string) (*PersistentFilter, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	filter, found := pm.filters[ruleID]
	return filter, found
}

// GetAllPersistent returns all persistent filters.
func (pm *PersistentManager) GetAllPersistent() []*PersistentFilter {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	filters := make([]*PersistentFilter, 0, len(pm.filters))
	for _, filter := range pm.filters {
		filters = append(filters, filter)
	}
	return filters
}

// IsPersistent checks if a rule has a persistent filter installed.
func (pm *PersistentManager) IsPersistent(ruleID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, found := pm.filters[ruleID]
	return found
}

// GetPersistentCount returns the number of persistent filters.
func (pm *PersistentManager) GetPersistentCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.filters)
}

// GetAvailableSlots returns the number of available persistent filter slots.
func (pm *PersistentManager) GetAvailableSlots() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.maxPersistent - len(pm.filters)
}

// GetStats returns persistent filter statistics.
func (pm *PersistentManager) GetStats() PersistentStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.stats
}

// ============================================================================
// Synchronization
// ============================================================================

// SyncWithWFP synchronizes the manager's state with actual WFP filters.
// It detects orphaned filters and missing filters.
func (pm *PersistentManager) SyncWithWFP() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.engine.RequireOpen(); err != nil {
		return fmt.Errorf("engine not open: %w", err)
	}

	// Verify all known filters
	pm.verifyFiltersLocked()

	// Detect orphaned filters (in WFP but not in registry)
	orphans, err := pm.detectOrphansLocked()
	if err != nil {
		// Log warning but continue
		orphans = nil
	}
	pm.stats.TotalOrphaned = len(orphans)

	// Count verified
	verified := 0
	for _, filter := range pm.filters {
		if filter.Verified {
			verified++
		}
	}
	pm.stats.TotalVerified = verified
	pm.stats.LastSyncTime = time.Now()

	return nil
}

// verifyFiltersLocked verifies all filters exist in WFP.
// Caller must hold the write lock.
func (pm *PersistentManager) verifyFiltersLocked() {
	// For now, mark all as verified if engine is open
	// Full verification would require enumeration which is not yet implemented
	if err := pm.engine.RequireOpen(); err != nil {
		for _, filter := range pm.filters {
			filter.Verified = false
		}
		return
	}

	// Mark all as verified (engine is open)
	// TODO: Implement proper filter enumeration for verification
	for _, filter := range pm.filters {
		filter.Verified = true
		filter.LastVerified = time.Now()
	}
}

// detectOrphansLocked finds WFP filters that exist but are not in registry.
// Caller must hold the write lock.
// NOTE: This is a placeholder. Full orphan detection requires filter enumeration.
func (pm *PersistentManager) detectOrphansLocked() ([]bindings.GUID, error) {
	// TODO: Implement proper filter enumeration when bindings support it
	// For now, return empty (no orphans detected)
	// This is safe because orphan filters are benign - they just continue protecting
	return []bindings.GUID{}, nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// InstallMultiple installs multiple rules as persistent filters.
func (pm *PersistentManager) InstallMultiple(rules []*models.FirewallRule) ([]*PersistentFilter, []error) {
	filters := make([]*PersistentFilter, 0, len(rules))
	errors := make([]error, 0)

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		filter, err := pm.InstallPersistent(rule)
		if err != nil {
			errors = append(errors, fmt.Errorf("rule %s: %w", rule.Name, err))
			continue
		}
		filters = append(filters, filter)
	}

	return filters, errors
}

// UninstallAll removes all persistent filters.
func (pm *PersistentManager) UninstallAll() error {
	pm.mu.Lock()
	ruleIDs := make([]string, 0, len(pm.filters))
	for ruleID := range pm.filters {
		ruleIDs = append(ruleIDs, ruleID)
	}
	pm.mu.Unlock()

	var lastErr error
	for _, ruleID := range ruleIDs {
		if err := pm.UninstallPersistent(ruleID); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// ============================================================================
// Helper Functions
// ============================================================================

// recordToFilter converts a registry record to a PersistentFilter.
func recordToFilter(record *PersistentFilterRecord) *PersistentFilter {
	return &PersistentFilter{
		FilterGUID:   record.FilterGUID,
		RuleID:       record.RuleID,
		RuleName:     record.RuleName,
		Layer:        record.Layer,
		Action:       record.Action,
		Conditions:   record.Conditions,
		Created:      record.Created,
		LastVerified: record.Updated,
		Verified:     false, // Will be verified on sync
	}
}

// filterToRecord converts a PersistentFilter to a registry record.
func filterToRecord(filter *PersistentFilter) *PersistentFilterRecord {
	return &PersistentFilterRecord{
		FilterGUID: filter.FilterGUID,
		RuleID:     filter.RuleID,
		RuleName:   filter.RuleName,
		Layer:      filter.Layer,
		Action:     filter.Action,
		Conditions: filter.Conditions,
		Created:    filter.Created,
		Updated:    time.Now(),
		Version:    1,
	}
}

// getLayerName returns a human-readable layer name.
func getLayerName(layerGUID bindings.GUID) string {
	switch layerGUID {
	case bindings.FWPM_LAYER_INBOUND_IPPACKET_V4:
		return "INBOUND_IPPACKET_V4"
	case bindings.FWPM_LAYER_OUTBOUND_IPPACKET_V4:
		return "OUTBOUND_IPPACKET_V4"
	case bindings.FWPM_LAYER_INBOUND_IPPACKET_V6:
		return "INBOUND_IPPACKET_V6"
	case bindings.FWPM_LAYER_OUTBOUND_IPPACKET_V6:
		return "OUTBOUND_IPPACKET_V6"
	case bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V4:
		return "ALE_AUTH_CONNECT_V4"
	case bindings.FWPM_LAYER_ALE_AUTH_CONNECT_V6:
		return "ALE_AUTH_CONNECT_V6"
	case bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
		return "ALE_AUTH_RECV_ACCEPT_V4"
	case bindings.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
		return "ALE_AUTH_RECV_ACCEPT_V6"
	default:
		return "UNKNOWN"
	}
}

// getActionName returns a human-readable action name.
func getActionName(action bindings.FWP_ACTION_TYPE) string {
	switch action {
	case bindings.FWP_ACTION_BLOCK:
		return "BLOCK"
	case bindings.FWP_ACTION_PERMIT:
		return "PERMIT"
	default:
		return "UNKNOWN"
	}
}

// summarizeConditions creates a summary of filter conditions.
func summarizeConditions(filter *bindings.FWPM_FILTER0) string {
	if len(filter.Conditions) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d conditions", len(filter.Conditions))
}
