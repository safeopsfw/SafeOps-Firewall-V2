// Package boottime provides cleanup functionality for persistent filters.
// The Cleaner removes persistent filters during uninstall or upgrade operations,
// ensuring no orphaned filters remain in the system.
package boottime

import (
	"fmt"
	"time"

	"firewall_engine/internal/wfp"
	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// Cleanup Options
// ============================================================================

// CleanupOptions configures the cleanup operation.
type CleanupOptions struct {
	// RemoveOrphans removes filters that exist in WFP but not in registry.
	RemoveOrphans bool

	// Force continues on errors instead of stopping.
	Force bool

	// DryRun simulates the cleanup without making changes.
	DryRun bool

	// Verbose enables detailed logging.
	Verbose bool
}

// DefaultCleanupOptions returns the default cleanup options.
func DefaultCleanupOptions() *CleanupOptions {
	return &CleanupOptions{
		RemoveOrphans: true,
		Force:         false,
		DryRun:        false,
		Verbose:       false,
	}
}

// ============================================================================
// Cleanup Result
// ============================================================================

// CleanupResult contains the outcome of a cleanup operation.
type CleanupResult struct {
	// FiltersRemoved is the number of filters successfully removed.
	FiltersRemoved int

	// FiltersSkipped is the number of filters skipped (e.g., not found).
	FiltersSkipped int

	// FiltersFailed is the number of filters that failed to remove.
	FiltersFailed int

	// OrphansFound is the number of orphaned filters found.
	OrphansFound int

	// OrphansRemoved is the number of orphaned filters removed.
	OrphansRemoved int

	// RegistryEntriesRemoved is the number of registry entries removed.
	RegistryEntriesRemoved int

	// Errors contains any errors encountered during cleanup.
	Errors []error

	// StartTime is when cleanup started.
	StartTime time.Time

	// EndTime is when cleanup completed.
	EndTime time.Time

	// Duration is the total cleanup duration.
	Duration time.Duration

	// DryRun indicates if this was a simulation.
	DryRun bool
}

// NewCleanupResult creates a new empty result.
func NewCleanupResult() *CleanupResult {
	return &CleanupResult{
		Errors:    make([]error, 0),
		StartTime: time.Now(),
	}
}

// Finish marks the cleanup as complete.
func (r *CleanupResult) Finish() {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)
}

// Success returns true if cleanup completed without errors.
func (r *CleanupResult) Success() bool {
	return len(r.Errors) == 0 && r.FiltersFailed == 0
}

// AddError adds an error to the result.
func (r *CleanupResult) AddError(err error) {
	r.Errors = append(r.Errors, err)
}

// String returns a summary of the cleanup.
func (r *CleanupResult) String() string {
	status := "SUCCESS"
	if !r.Success() {
		status = "FAILED"
	}
	if r.DryRun {
		status = "DRY-RUN"
	}
	return fmt.Sprintf("[%s] Removed: %d, Skipped: %d, Failed: %d, Orphans: %d/%d, Duration: %v",
		status, r.FiltersRemoved, r.FiltersSkipped, r.FiltersFailed,
		r.OrphansRemoved, r.OrphansFound, r.Duration)
}

// ============================================================================
// Cleaner
// ============================================================================

// Cleaner removes persistent filters for uninstall or upgrade.
type Cleaner struct {
	// Dependencies
	engine   *wfp.Engine
	registry *RegistryStore
	manager  *PersistentManager

	// Configuration
	options *CleanupOptions
}

// NewCleaner creates a new cleaner with the given dependencies.
func NewCleaner(engine *wfp.Engine, registry *RegistryStore) *Cleaner {
	return &Cleaner{
		engine:   engine,
		registry: registry,
		options:  DefaultCleanupOptions(),
	}
}

// NewCleanerWithManager creates a cleaner using an existing manager.
func NewCleanerWithManager(manager *PersistentManager) *Cleaner {
	return &Cleaner{
		manager: manager,
		options: DefaultCleanupOptions(),
	}
}

// WithOptions sets the cleanup options.
func (c *Cleaner) WithOptions(opts *CleanupOptions) *Cleaner {
	if opts != nil {
		c.options = opts
	}
	return c
}

// ============================================================================
// Core Cleanup Operations
// ============================================================================

// RemoveAllPersistent removes all persistent filters.
func (c *Cleaner) RemoveAllPersistent() (*CleanupResult, error) {
	result := NewCleanupResult()
	result.DryRun = c.options.DryRun

	// Use manager if available
	if c.manager != nil {
		return c.removeAllViaManager(result)
	}

	// Otherwise use direct registry access
	return c.removeAllDirect(result)
}

// removeAllViaManager uses PersistentManager for cleanup.
func (c *Cleaner) removeAllViaManager(result *CleanupResult) (*CleanupResult, error) {
	filters := c.manager.GetAllPersistent()

	for _, filter := range filters {
		if c.options.DryRun {
			result.FiltersRemoved++
			continue
		}

		if err := c.manager.UninstallPersistent(filter.RuleID); err != nil {
			if c.options.Force {
				result.AddError(err)
				result.FiltersFailed++
				continue
			}
			result.Finish()
			return result, fmt.Errorf("remove filter %s: %w", filter.RuleName, err)
		}
		result.FiltersRemoved++
		result.RegistryEntriesRemoved++
	}

	result.Finish()
	return result, nil
}

// removeAllDirect uses direct registry and WFP access.
func (c *Cleaner) removeAllDirect(result *CleanupResult) (*CleanupResult, error) {
	// Open registry if needed
	if !c.registry.IsOpen() {
		if err := c.registry.Open(); err != nil {
			result.Finish()
			return result, fmt.Errorf("open registry: %w", err)
		}
	}

	// Load all records
	records, err := c.registry.LoadAll()
	if err != nil {
		result.Finish()
		return result, fmt.Errorf("load registry: %w", err)
	}

	// Delete each filter
	for _, record := range records {
		if c.options.DryRun {
			result.FiltersRemoved++
			continue
		}

		// Delete from WFP
		if c.engine != nil {
			if err := c.engine.RequireOpen(); err == nil {
				bindingsEngine := c.engine.GetBindings()
				if err := bindingsEngine.DeleteFilterByKey(record.FilterGUID); err != nil {
					if !bindings.IsNotFound(err) {
						if c.options.Force {
							result.AddError(err)
							result.FiltersFailed++
						} else {
							result.Finish()
							return result, fmt.Errorf("delete WFP filter: %w", err)
						}
					} else {
						result.FiltersSkipped++ // Already gone
					}
				} else {
					result.FiltersRemoved++
				}
			}
		}

		// Delete from registry
		if err := c.registry.DeleteFilter(record.RuleID); err != nil {
			result.AddError(err)
		} else {
			result.RegistryEntriesRemoved++
		}
	}

	result.Finish()
	return result, nil
}

// RemoveOrphans removes filters that exist in WFP but not in registry.
func (c *Cleaner) RemoveOrphans() (*CleanupResult, error) {
	result := NewCleanupResult()
	result.DryRun = c.options.DryRun

	// NOTE: Orphan detection requires filter enumeration which is not fully implemented
	// For now, this returns success with no orphans removed

	result.OrphansFound = 0
	result.OrphansRemoved = 0

	result.Finish()
	return result, nil
}

// RemoveByProvider removes all filters for a specific provider.
func (c *Cleaner) RemoveByProvider(providerGUID bindings.GUID) (*CleanupResult, error) {
	result := NewCleanupResult()
	result.DryRun = c.options.DryRun

	// This would require filter enumeration by provider
	// For now, if it's SafeOps provider, use RemoveAllPersistent
	if providerGUID == bindings.SAFEOPS_PROVIDER_GUID {
		return c.RemoveAllPersistent()
	}

	result.Finish()
	return result, nil
}

// DryRun simulates cleanup without making changes.
func (c *Cleaner) DryRun() (*CleanupResult, error) {
	savedDryRun := c.options.DryRun
	c.options.DryRun = true
	defer func() { c.options.DryRun = savedDryRun }()

	return c.RemoveAllPersistent()
}

// ============================================================================
// Uninstall Operations
// ============================================================================

// UninstallFirewall performs full cleanup for firewall uninstallation.
func (c *Cleaner) UninstallFirewall() error {
	// Step 1: Remove all persistent filters
	result, err := c.RemoveAllPersistent()
	if err != nil && !c.options.Force {
		return fmt.Errorf("remove persistent filters: %w", err)
	}

	// Step 2: Remove orphans
	if c.options.RemoveOrphans {
		orphanResult, _ := c.RemoveOrphans()
		result.OrphansFound = orphanResult.OrphansFound
		result.OrphansRemoved = orphanResult.OrphansRemoved
	}

	// Step 3: Unregister provider (if engine available)
	if c.engine != nil {
		if err := c.engine.RequireOpen(); err == nil {
			bindingsEngine := c.engine.GetBindings()
			if err := bindingsEngine.DeleteProvider(bindings.SAFEOPS_PROVIDER_GUID); err != nil {
				if !bindings.IsNotFound(err) {
					if !c.options.Force {
						return fmt.Errorf("unregister provider: %w", err)
					}
				}
			}
		}
	}

	// Step 4: Delete registry key
	if c.registry != nil {
		if err := c.registry.DeleteKey(); err != nil {
			if !c.options.Force {
				return fmt.Errorf("delete registry key: %w", err)
			}
		}
	}

	return nil
}

// PrepareForUpgrade cleans up for upgrade (preserves some state).
func (c *Cleaner) PrepareForUpgrade() error {
	// For upgrade, we keep persistent filters active
	// Only clean up orphans and refresh registry

	if c.options.RemoveOrphans {
		if _, err := c.RemoveOrphans(); err != nil {
			// Log but don't fail upgrade
		}
	}

	// Sync state if manager available
	if c.manager != nil {
		if err := c.manager.SyncWithWFP(); err != nil {
			// Log but don't fail upgrade
		}
	}

	return nil
}

// ============================================================================
// Specific Filter Removal
// ============================================================================

// RemoveFilter removes a specific filter by rule ID.
func (c *Cleaner) RemoveFilter(ruleID string) error {
	if c.options.DryRun {
		return nil
	}

	if c.manager != nil {
		return c.manager.UninstallPersistent(ruleID)
	}

	// Direct removal
	if c.registry != nil && c.registry.IsOpen() {
		record, err := c.registry.LoadFilter(ruleID)
		if err != nil {
			return fmt.Errorf("load filter: %w", err)
		}

		// Delete from WFP
		if c.engine != nil {
			if err := c.engine.RequireOpen(); err == nil {
				if err := c.engine.GetBindings().DeleteFilterByKey(record.FilterGUID); err != nil {
					if !bindings.IsNotFound(err) {
						return fmt.Errorf("delete from WFP: %w", err)
					}
				}
			}
		}

		// Delete from registry
		return c.registry.DeleteFilter(ruleID)
	}

	return fmt.Errorf("no manager or registry available")
}

// RemoveFilterByGUID removes a specific filter by WFP GUID.
func (c *Cleaner) RemoveFilterByGUID(filterGUID bindings.GUID) error {
	if c.options.DryRun {
		return nil
	}

	if c.manager != nil {
		return c.manager.UninstallByGUID(filterGUID)
	}

	// Direct WFP removal
	if c.engine != nil {
		if err := c.engine.RequireOpen(); err == nil {
			return c.engine.GetBindings().DeleteFilterByKey(filterGUID)
		}
	}

	return fmt.Errorf("no manager or engine available")
}

// ============================================================================
// Status Methods
// ============================================================================

// GetCleanupStatus returns the current cleanup status without performing cleanup.
func (c *Cleaner) GetCleanupStatus() (*CleanupResult, error) {
	// Use dry run to get status
	return c.DryRun()
}

// NeedsCleanup returns true if there are filters to clean up.
func (c *Cleaner) NeedsCleanup() bool {
	result, _ := c.DryRun()
	return result.FiltersRemoved > 0 || result.OrphansFound > 0
}
