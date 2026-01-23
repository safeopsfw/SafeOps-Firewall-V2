// Package enforcement provides dual-engine coordination for WFP and SafeOps engines.
// The DualEngineCoordinator manages both engines together, providing failover,
// synchronization, and unified packet processing.
package enforcement

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/wfp"
	"firewall_engine/internal/wfp/boottime"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Dual Engine Mode
// ============================================================================

// DualEngineMode specifies which engines are active.
type DualEngineMode int

const (
	// DualModeBoth uses both SafeOps and WFP engines.
	// This provides maximum protection with redundancy.
	DualModeBoth DualEngineMode = iota

	// DualModeSafeOpsOnly uses only SafeOps engine.
	// WFP is disabled (e.g., not admin or compatibility issues).
	DualModeSafeOpsOnly

	// DualModeWFPOnly uses only WFP engine.
	// SafeOps is disabled (e.g., driver not loaded).
	DualModeWFPOnly

	// DualModeDisabled disables both engines.
	// Used for testing or when firewall should be inactive.
	DualModeDisabled
)

// String returns the string representation of the mode.
func (m DualEngineMode) String() string {
	switch m {
	case DualModeBoth:
		return "BOTH"
	case DualModeSafeOpsOnly:
		return "SAFEOPS_ONLY"
	case DualModeWFPOnly:
		return "WFP_ONLY"
	case DualModeDisabled:
		return "DISABLED"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Dual Engine Configuration
// ============================================================================

// DualEngineConfig configures the dual-engine coordinator.
type DualEngineConfig struct {
	// Mode is the initial operating mode.
	Mode DualEngineMode

	// FailoverEnabled enables automatic failover when one engine fails.
	FailoverEnabled bool

	// SyncInterval is how often to synchronize engine states.
	SyncInterval time.Duration

	// HealthCheckInterval is how often to check engine health.
	HealthCheckInterval time.Duration

	// MaxSyncRetries is the maximum number of sync retries before giving up.
	MaxSyncRetries int

	// WFPBatchSize is the number of filters to install in one batch.
	WFPBatchSize int

	// EnablePersistentFilters enables boot-time persistent filter support.
	EnablePersistentFilters bool

	// MaxPersistentFilters is the maximum number of persistent filters.
	MaxPersistentFilters int
}

// DefaultDualEngineConfig returns the default configuration.
func DefaultDualEngineConfig() *DualEngineConfig {
	return &DualEngineConfig{
		Mode:                    DualModeBoth,
		FailoverEnabled:         true,
		SyncInterval:            30 * time.Second,
		HealthCheckInterval:     10 * time.Second,
		MaxSyncRetries:          3,
		WFPBatchSize:            100,
		EnablePersistentFilters: true,
		MaxPersistentFilters:    50,
	}
}

// ============================================================================
// Dual Engine Health Status
// ============================================================================

// DualEngineHealth contains health status for both engines.
type DualEngineHealth struct {
	// Overall status
	Healthy     bool
	Mode        DualEngineMode
	Message     string
	LastChecked time.Time

	// SafeOps status
	SafeOpsHealthy   bool
	SafeOpsConnected bool
	SafeOpsMessage   string

	// WFP status
	WFPHealthy         bool
	WFPConnected       bool
	WFPFilterCount     int
	WFPPersistentCount int
	WFPMessage         string
}

// String returns a summary of the health status.
func (h *DualEngineHealth) String() string {
	status := "HEALTHY"
	if !h.Healthy {
		status = "UNHEALTHY"
	}
	return fmt.Sprintf("[%s] Mode=%s, SafeOps=%v, WFP=%v (%d filters)",
		status, h.Mode, h.SafeOpsHealthy, h.WFPHealthy, h.WFPFilterCount)
}

// ============================================================================
// Dual Engine Statistics
// ============================================================================

// DualEngineStats contains operational statistics.
type DualEngineStats struct {
	// Counters
	PacketsProcessed uint64
	SafeOpsBlocked   uint64
	WFPBlocked       uint64
	BothBlocked      uint64
	Failovers        uint64

	// Timings
	StartTime        time.Time
	LastSyncTime     time.Time
	LastFailoverTime time.Time

	// Rule counts
	TotalRules      int
	SyncedRules     int
	PersistentRules int
}

// ============================================================================
// Dual Engine Coordinator
// ============================================================================

// DualEngineCoordinator manages SafeOps and WFP engines together.
type DualEngineCoordinator struct {
	mu sync.RWMutex

	// Configuration
	config *DualEngineConfig
	mode   DualEngineMode

	// Engines
	wfpEngine      *wfp.Engine
	persistentMgr  *boottime.PersistentManager
	criticalSelect *boottime.CriticalSelector

	// Note: SafeOps engine is handled via gRPC client
	// We don't directly hold a reference - it's managed by safeops_client.go

	// State
	running      bool
	stopping     bool
	currentRules []*models.FirewallRule
	initialized  bool

	// Synchronization
	stopChan chan struct{}
	doneChan chan struct{}

	// Statistics
	stats DualEngineStats
}

// NewDualEngineCoordinator creates a new dual-engine coordinator.
func NewDualEngineCoordinator(wfpEngine *wfp.Engine) (*DualEngineCoordinator, error) {
	return NewDualEngineCoordinatorWithConfig(wfpEngine, DefaultDualEngineConfig())
}

// NewDualEngineCoordinatorWithConfig creates a coordinator with custom configuration.
func NewDualEngineCoordinatorWithConfig(wfpEngine *wfp.Engine, config *DualEngineConfig) (*DualEngineCoordinator, error) {
	if config == nil {
		config = DefaultDualEngineConfig()
	}

	// Determine initial mode based on available engines
	mode := config.Mode
	if wfpEngine == nil && (mode == DualModeBoth || mode == DualModeWFPOnly) {
		mode = DualModeSafeOpsOnly
	}

	dec := &DualEngineCoordinator{
		config:         config,
		mode:           mode,
		wfpEngine:      wfpEngine,
		criticalSelect: boottime.NewCriticalSelector().WithMaxPersistent(config.MaxPersistentFilters),
		currentRules:   make([]*models.FirewallRule, 0),
		stats: DualEngineStats{
			StartTime: time.Now(),
		},
	}

	return dec, nil
}

// ============================================================================
// Lifecycle Methods
// ============================================================================

// Start starts the dual-engine coordinator.
func (dec *DualEngineCoordinator) Start(ctx context.Context) error {
	dec.mu.Lock()
	defer dec.mu.Unlock()

	if dec.running {
		return fmt.Errorf("coordinator is already running")
	}

	// Initialize WFP engine if available
	if dec.wfpEngine != nil && (dec.mode == DualModeBoth || dec.mode == DualModeWFPOnly) {
		if err := dec.initWFPLocked(); err != nil {
			// WFP failed, fall back to SafeOps only if in dual mode
			if dec.mode == DualModeBoth && dec.config.FailoverEnabled {
				dec.mode = DualModeSafeOpsOnly
				dec.stats.Failovers++
			} else if dec.mode == DualModeWFPOnly {
				return fmt.Errorf("WFP initialization failed: %w", err)
			}
		}
	}

	// Initialize persistent manager if enabled
	if dec.config.EnablePersistentFilters && dec.wfpEngine != nil {
		pm, err := boottime.NewPersistentManager(dec.wfpEngine)
		if err != nil {
			// Log but don't fail - persistent filters are optional
		} else {
			dec.persistentMgr = pm
		}
	}

	// Start background goroutines
	dec.stopChan = make(chan struct{})
	dec.doneChan = make(chan struct{})
	dec.running = true
	dec.initialized = true
	dec.stats.StartTime = time.Now()

	go dec.healthCheckLoop(ctx)

	return nil
}

// Stop stops the dual-engine coordinator.
func (dec *DualEngineCoordinator) Stop() error {
	dec.mu.Lock()
	if !dec.running {
		dec.mu.Unlock()
		return nil
	}
	dec.stopping = true
	dec.mu.Unlock()

	// Signal stop
	close(dec.stopChan)

	// Wait for goroutines with timeout
	select {
	case <-dec.doneChan:
	case <-time.After(5 * time.Second):
	}

	dec.mu.Lock()
	defer dec.mu.Unlock()

	// Close persistent manager
	if dec.persistentMgr != nil {
		dec.persistentMgr.Close()
	}

	// Close WFP engine
	if dec.wfpEngine != nil {
		dec.wfpEngine.Close()
	}

	dec.running = false
	dec.stopping = false

	return nil
}

// IsRunning returns true if the coordinator is running.
func (dec *DualEngineCoordinator) IsRunning() bool {
	dec.mu.RLock()
	defer dec.mu.RUnlock()
	return dec.running
}

// ============================================================================
// WFP Initialization
// ============================================================================

// initWFPLocked initializes the WFP engine.
// Caller must hold the write lock.
func (dec *DualEngineCoordinator) initWFPLocked() error {
	if dec.wfpEngine == nil {
		return fmt.Errorf("WFP engine is nil")
	}

	// Check if already open
	if dec.wfpEngine.IsOpen() {
		return nil
	}

	// Open WFP session
	if err := dec.wfpEngine.Open(); err != nil {
		return fmt.Errorf("open WFP engine: %w", err)
	}

	return nil
}

// ============================================================================
// Mode Management
// ============================================================================

// GetMode returns the current operating mode.
func (dec *DualEngineCoordinator) GetMode() DualEngineMode {
	dec.mu.RLock()
	defer dec.mu.RUnlock()
	return dec.mode
}

// SetMode changes the operating mode.
func (dec *DualEngineCoordinator) SetMode(mode DualEngineMode) error {
	dec.mu.Lock()
	defer dec.mu.Unlock()

	// Validate mode change
	if mode == DualModeBoth || mode == DualModeWFPOnly {
		if dec.wfpEngine == nil {
			return fmt.Errorf("cannot use WFP mode without WFP engine")
		}
	}

	oldMode := dec.mode
	dec.mode = mode

	// If switching to include WFP and it's not open, initialize
	if (mode == DualModeBoth || mode == DualModeWFPOnly) &&
		(oldMode == DualModeSafeOpsOnly || oldMode == DualModeDisabled) {
		if err := dec.initWFPLocked(); err != nil {
			dec.mode = oldMode // Revert
			return fmt.Errorf("initialize WFP: %w", err)
		}

		// Re-sync rules to WFP
		if len(dec.currentRules) > 0 {
			if err := dec.syncRulesToWFPLocked(dec.currentRules); err != nil {
				// Log but don't revert - WFP may have partial sync
			}
		}
	}

	return nil
}

// ============================================================================
// Rule Synchronization
// ============================================================================

// SyncRules synchronizes firewall rules to both engines.
func (dec *DualEngineCoordinator) SyncRules(rules []*models.FirewallRule) error {
	dec.mu.Lock()
	defer dec.mu.Unlock()

	if !dec.running {
		return fmt.Errorf("coordinator is not running")
	}

	// Store rules for re-sync
	dec.currentRules = rules
	dec.stats.TotalRules = len(rules)

	// Sync to WFP if enabled
	if dec.mode == DualModeBoth || dec.mode == DualModeWFPOnly {
		if err := dec.syncRulesToWFPLocked(rules); err != nil {
			if dec.mode == DualModeBoth && dec.config.FailoverEnabled {
				// WFP sync failed, continue with SafeOps only
				dec.mode = DualModeSafeOpsOnly
				dec.stats.Failovers++
				dec.stats.LastFailoverTime = time.Now()
			} else {
				return fmt.Errorf("sync to WFP: %w", err)
			}
		}
	}

	// Install persistent filters for critical rules
	if dec.config.EnablePersistentFilters && dec.persistentMgr != nil {
		if err := dec.syncPersistentFiltersLocked(rules); err != nil {
			// Log but don't fail - persistent filters are optional
		}
	}

	dec.stats.LastSyncTime = time.Now()
	return nil
}

// syncRulesToWFPLocked syncs rules to WFP engine.
// Caller must hold the write lock.
func (dec *DualEngineCoordinator) syncRulesToWFPLocked(rules []*models.FirewallRule) error {
	if dec.wfpEngine == nil || !dec.wfpEngine.IsOpen() {
		return fmt.Errorf("WFP engine is not available")
	}

	bindingsEngine := dec.wfpEngine.GetBindings()
	if bindingsEngine == nil {
		return fmt.Errorf("bindings engine is nil")
	}

	// Use the engine's batch sync
	start := time.Now()

	// Delete existing filters first
	if err := bindingsEngine.DeleteAllFilters(); err != nil {
		return fmt.Errorf("delete existing filters: %w", err)
	}

	// Translate and install in batches
	translator := wfp.NewTranslator()
	synced := 0

	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		// Translate rule to WFP filters
		result, err := translator.TranslateRule(rule)
		if err != nil {
			// Log but continue with other rules
			continue
		}

		// Install each filter
		for _, filter := range result.Filters {
			filterID, err := bindingsEngine.AddFilter(filter)
			if err != nil {
				// Log but continue
				continue
			}
			dec.wfpEngine.TrackFilter(rule.ID.String(), filterID)
			synced++
		}
	}

	dec.stats.SyncedRules = synced

	// Log sync duration for performance tracking
	_ = time.Since(start)

	return nil
}

// syncPersistentFiltersLocked syncs critical rules as persistent filters.
// Caller must hold the write lock.
func (dec *DualEngineCoordinator) syncPersistentFiltersLocked(rules []*models.FirewallRule) error {
	if dec.persistentMgr == nil {
		return nil
	}

	// Select critical rules
	criticalRules := dec.criticalSelect.GetCriticalRules(rules)

	// Install persistent filters
	filters, errors := dec.persistentMgr.InstallMultiple(criticalRules)
	dec.stats.PersistentRules = len(filters)

	if len(errors) > 0 {
		return errors[0] // Return first error
	}

	return nil
}

// ============================================================================
// Rule Management
// ============================================================================

// AddRule adds a single rule to both engines.
func (dec *DualEngineCoordinator) AddRule(rule *models.FirewallRule) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}

	dec.mu.Lock()
	defer dec.mu.Unlock()

	if !dec.running {
		return fmt.Errorf("coordinator is not running")
	}

	// Add to tracked rules
	dec.currentRules = append(dec.currentRules, rule)
	dec.stats.TotalRules = len(dec.currentRules)

	// Add to WFP if enabled
	if dec.mode == DualModeBoth || dec.mode == DualModeWFPOnly {
		if dec.wfpEngine != nil && dec.wfpEngine.IsOpen() {
			bindingsEngine := dec.wfpEngine.GetBindings()
			if bindingsEngine != nil {
				translator := wfp.NewTranslator()
				result, err := translator.TranslateRule(rule)
				if err == nil {
					for _, filter := range result.Filters {
						filterID, err := bindingsEngine.AddFilter(filter)
						if err == nil {
							dec.wfpEngine.TrackFilter(rule.ID.String(), filterID)
						}
					}
				} else if dec.mode == DualModeWFPOnly {
					return fmt.Errorf("translate rule: %w", err)
				}
			}
		}
	}

	// Check if should be persistent
	if dec.config.EnablePersistentFilters && dec.persistentMgr != nil {
		if dec.criticalSelect.IsCritical(rule) {
			_, _ = dec.persistentMgr.InstallPersistent(rule)
		}
	}

	return nil
}

// RemoveRule removes a rule from both engines.
func (dec *DualEngineCoordinator) RemoveRule(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID is empty")
	}

	dec.mu.Lock()
	defer dec.mu.Unlock()

	if !dec.running {
		return fmt.Errorf("coordinator is not running")
	}

	// Remove from tracked rules
	for i, rule := range dec.currentRules {
		if rule.ID.String() == ruleID {
			dec.currentRules = append(dec.currentRules[:i], dec.currentRules[i+1:]...)
			break
		}
	}
	dec.stats.TotalRules = len(dec.currentRules)

	// Remove from WFP if enabled
	if dec.mode == DualModeBoth || dec.mode == DualModeWFPOnly {
		if dec.wfpEngine != nil && dec.wfpEngine.IsOpen() {
			bindingsEngine := dec.wfpEngine.GetBindings()
			if bindingsEngine != nil {
				_ = bindingsEngine.DeleteFilterByRuleID(ruleID)
			}
			dec.wfpEngine.UntrackFilter(ruleID)
		}
	}

	// Remove from persistent if applicable
	if dec.persistentMgr != nil {
		_ = dec.persistentMgr.UninstallPersistent(ruleID)
	}

	return nil
}

// ============================================================================
// Health Monitoring
// ============================================================================

// HealthCheck returns the current health status.
func (dec *DualEngineCoordinator) HealthCheck() *DualEngineHealth {
	dec.mu.RLock()
	defer dec.mu.RUnlock()

	health := &DualEngineHealth{
		Mode:        dec.mode,
		LastChecked: time.Now(),
	}

	// Check SafeOps (assume healthy if not WFP-only)
	if dec.mode != DualModeWFPOnly {
		health.SafeOpsHealthy = true // Actual check via gRPC client
		health.SafeOpsConnected = true
		health.SafeOpsMessage = "OK"
	}

	// Check WFP
	if dec.mode == DualModeBoth || dec.mode == DualModeWFPOnly {
		if dec.wfpEngine != nil && dec.wfpEngine.IsOpen() {
			health.WFPHealthy = true
			health.WFPConnected = true
			health.WFPFilterCount = dec.wfpEngine.GetFilterCount()
			if dec.persistentMgr != nil {
				health.WFPPersistentCount = dec.persistentMgr.GetPersistentCount()
			}
			health.WFPMessage = "OK"
		} else {
			health.WFPHealthy = false
			health.WFPMessage = "Engine not connected"
		}
	}

	// Overall health
	switch dec.mode {
	case DualModeBoth:
		health.Healthy = health.SafeOpsHealthy && health.WFPHealthy
	case DualModeSafeOpsOnly:
		health.Healthy = health.SafeOpsHealthy
	case DualModeWFPOnly:
		health.Healthy = health.WFPHealthy
	default:
		health.Healthy = true // Disabled is healthy
	}

	if health.Healthy {
		health.Message = "All engines healthy"
	} else {
		health.Message = "One or more engines unhealthy"
	}

	return health
}

// healthCheckLoop runs periodic health checks.
func (dec *DualEngineCoordinator) healthCheckLoop(ctx context.Context) {
	defer close(dec.doneChan)

	ticker := time.NewTicker(dec.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-dec.stopChan:
			return
		case <-ticker.C:
			health := dec.HealthCheck()

			// Handle failover
			if dec.config.FailoverEnabled {
				dec.handleFailover(health)
			}
		}
	}
}

// handleFailover handles automatic failover between engines.
func (dec *DualEngineCoordinator) handleFailover(health *DualEngineHealth) {
	dec.mu.Lock()
	defer dec.mu.Unlock()

	// In dual mode, fail over to working engine
	if dec.mode == DualModeBoth {
		if !health.WFPHealthy && health.SafeOpsHealthy {
			dec.mode = DualModeSafeOpsOnly
			dec.stats.Failovers++
			dec.stats.LastFailoverTime = time.Now()
		} else if !health.SafeOpsHealthy && health.WFPHealthy {
			dec.mode = DualModeWFPOnly
			dec.stats.Failovers++
			dec.stats.LastFailoverTime = time.Now()
		}
	}

	// Try to recover back to dual mode
	if dec.config.FailoverEnabled && dec.mode != DualModeBoth {
		if health.SafeOpsHealthy && health.WFPHealthy {
			dec.mode = DualModeBoth
		}
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns the current statistics.
func (dec *DualEngineCoordinator) GetStats() DualEngineStats {
	dec.mu.RLock()
	defer dec.mu.RUnlock()
	return dec.stats
}

// IncrementPacketsProcessed increments the packet counter.
func (dec *DualEngineCoordinator) IncrementPacketsProcessed() {
	atomic.AddUint64(&dec.stats.PacketsProcessed, 1)
}

// IncrementSafeOpsBlocked increments the SafeOps block counter.
func (dec *DualEngineCoordinator) IncrementSafeOpsBlocked() {
	atomic.AddUint64(&dec.stats.SafeOpsBlocked, 1)
}

// IncrementWFPBlocked increments the WFP block counter.
func (dec *DualEngineCoordinator) IncrementWFPBlocked() {
	atomic.AddUint64(&dec.stats.WFPBlocked, 1)
}

// IncrementBothBlocked increments the both-blocked counter.
func (dec *DualEngineCoordinator) IncrementBothBlocked() {
	atomic.AddUint64(&dec.stats.BothBlocked, 1)
}

// ============================================================================
// Accessor Methods
// ============================================================================

// GetWFPEngine returns the WFP engine (use with caution).
func (dec *DualEngineCoordinator) GetWFPEngine() *wfp.Engine {
	dec.mu.RLock()
	defer dec.mu.RUnlock()
	return dec.wfpEngine
}

// GetPersistentManager returns the persistent filter manager.
func (dec *DualEngineCoordinator) GetPersistentManager() *boottime.PersistentManager {
	dec.mu.RLock()
	defer dec.mu.RUnlock()
	return dec.persistentMgr
}

// GetCurrentRules returns a copy of the current rules.
func (dec *DualEngineCoordinator) GetCurrentRules() []*models.FirewallRule {
	dec.mu.RLock()
	defer dec.mu.RUnlock()

	rules := make([]*models.FirewallRule, len(dec.currentRules))
	copy(rules, dec.currentRules)
	return rules
}

// RequireRunning returns an error if the coordinator is not running.
func (dec *DualEngineCoordinator) RequireRunning() error {
	dec.mu.RLock()
	defer dec.mu.RUnlock()

	if !dec.running {
		return fmt.Errorf("dual-engine coordinator is not running")
	}
	return nil
}
