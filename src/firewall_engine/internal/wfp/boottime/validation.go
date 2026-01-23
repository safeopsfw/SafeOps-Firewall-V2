// Package boottime provides boot-time protection validation for persistent filters.
// The BootValidator verifies that persistent filters are properly installed and
// active in WFP, detecting orphaned or missing filters.
package boottime

import (
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Validation Result
// ============================================================================

// ValidationResult contains the outcome of a validation check.
type ValidationResult struct {
	// CheckName is the name of the validation check.
	CheckName string

	// Passed indicates if the check succeeded.
	Passed bool

	// Message is a summary of the result.
	Message string

	// Details contains additional information about the check.
	Details []string

	// Timestamp is when the validation was performed.
	Timestamp time.Time

	// Duration is how long the check took.
	Duration time.Duration
}

// String returns a human-readable representation.
func (r *ValidationResult) String() string {
	status := "PASSED"
	if !r.Passed {
		status = "FAILED"
	}
	return fmt.Sprintf("[%s] %s: %s", status, r.CheckName, r.Message)
}

// AddDetail adds a detail line to the result.
func (r *ValidationResult) AddDetail(detail string) {
	r.Details = append(r.Details, detail)
}

// ============================================================================
// Validation Report
// ============================================================================

// ValidationReport contains the complete validation results.
type ValidationReport struct {
	// Results contains all individual check results.
	Results []*ValidationResult

	// TotalChecks is the number of checks performed.
	TotalChecks int

	// PassedChecks is the number of checks that passed.
	PassedChecks int

	// FailedChecks is the number of checks that failed.
	FailedChecks int

	// StartTime is when validation started.
	StartTime time.Time

	// EndTime is when validation completed.
	EndTime time.Time

	// Duration is the total validation duration.
	Duration time.Duration
}

// NewValidationReport creates a new empty report.
func NewValidationReport() *ValidationReport {
	return &ValidationReport{
		Results:   make([]*ValidationResult, 0),
		StartTime: time.Now(),
	}
}

// AddResult adds a validation result to the report.
func (r *ValidationReport) AddResult(result *ValidationResult) {
	r.Results = append(r.Results, result)
	r.TotalChecks++
	if result.Passed {
		r.PassedChecks++
	} else {
		r.FailedChecks++
	}
}

// Finish marks the report as complete.
func (r *ValidationReport) Finish() {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)
}

// AllPassed returns true if all checks passed.
func (r *ValidationReport) AllPassed() bool {
	return r.FailedChecks == 0 && r.TotalChecks > 0
}

// String returns a summary of the report.
func (r *ValidationReport) String() string {
	var sb strings.Builder
	sb.WriteString("=== Boot-Time Validation Report ===\n")
	sb.WriteString(fmt.Sprintf("Total Checks: %d\n", r.TotalChecks))
	sb.WriteString(fmt.Sprintf("Passed: %d\n", r.PassedChecks))
	sb.WriteString(fmt.Sprintf("Failed: %d\n", r.FailedChecks))
	sb.WriteString(fmt.Sprintf("Duration: %v\n\n", r.Duration))

	for _, result := range r.Results {
		sb.WriteString(result.String())
		sb.WriteString("\n")
		for _, detail := range result.Details {
			sb.WriteString(fmt.Sprintf("  - %s\n", detail))
		}
	}

	return sb.String()
}

// ============================================================================
// Boot Validator
// ============================================================================

// BootValidator validates boot-time persistent filter protection.
type BootValidator struct {
	// Dependencies
	manager *PersistentManager

	// Configuration
	testBlocking bool // Whether to test actual blocking (requires network)
}

// NewBootValidator creates a new boot validator.
func NewBootValidator(manager *PersistentManager) *BootValidator {
	return &BootValidator{
		manager:      manager,
		testBlocking: false, // Disabled by default (requires network access)
	}
}

// WithBlockingTest enables blocking tests (requires network).
func (v *BootValidator) WithBlockingTest(enabled bool) *BootValidator {
	v.testBlocking = enabled
	return v
}

// ============================================================================
// Validation Checks
// ============================================================================

// ValidateFiltersExist checks that expected filters exist in WFP.
func (v *BootValidator) ValidateFiltersExist() *ValidationResult {
	start := time.Now()
	result := &ValidationResult{
		CheckName: "Filters Exist",
		Passed:    true,
		Timestamp: time.Now(),
		Details:   make([]string, 0),
	}

	// Get all persistent filters
	filters := v.manager.GetAllPersistent()

	if len(filters) == 0 {
		result.Passed = true // Empty is valid
		result.Message = "No persistent filters configured"
		result.Duration = time.Since(start)
		return result
	}

	// Count verified filters
	verified := 0
	unverified := 0
	for _, filter := range filters {
		if filter.Verified {
			verified++
			result.AddDetail(fmt.Sprintf("✓ %s (layer: %s)", filter.RuleName, filter.Layer))
		} else {
			unverified++
			result.AddDetail(fmt.Sprintf("✗ %s - NOT VERIFIED", filter.RuleName))
		}
	}

	if unverified > 0 {
		result.Passed = false
		result.Message = fmt.Sprintf("%d of %d filters not verified", unverified, len(filters))
	} else {
		result.Message = fmt.Sprintf("All %d filters verified", verified)
	}

	result.Duration = time.Since(start)
	return result
}

// ValidateFiltersMatch checks that registry and WFP are in sync.
func (v *BootValidator) ValidateFiltersMatch() *ValidationResult {
	start := time.Now()
	result := &ValidationResult{
		CheckName: "Registry-WFP Sync",
		Passed:    true,
		Timestamp: time.Now(),
		Details:   make([]string, 0),
	}

	// Sync to get current state
	if err := v.manager.SyncWithWFP(); err != nil {
		result.Passed = false
		result.Message = fmt.Sprintf("Sync failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	stats := v.manager.GetStats()
	result.AddDetail(fmt.Sprintf("Total installed: %d", stats.TotalInstalled))
	result.AddDetail(fmt.Sprintf("Verified: %d", stats.TotalVerified))
	result.AddDetail(fmt.Sprintf("Orphaned: %d", stats.TotalOrphaned))

	if stats.TotalInstalled != stats.TotalVerified {
		result.Passed = false
		result.Message = fmt.Sprintf("%d filters installed, only %d verified",
			stats.TotalInstalled, stats.TotalVerified)
	} else if stats.TotalOrphaned > 0 {
		result.Passed = false
		result.Message = fmt.Sprintf("%d orphaned filters detected", stats.TotalOrphaned)
	} else {
		result.Message = fmt.Sprintf("All %d filters in sync", stats.TotalInstalled)
	}

	result.Duration = time.Since(start)
	return result
}

// ValidateFilterActive checks if a specific filter is active.
func (v *BootValidator) ValidateFilterActive(ruleID string) *ValidationResult {
	start := time.Now()
	result := &ValidationResult{
		CheckName: fmt.Sprintf("Filter Active: %s", ruleID),
		Passed:    false,
		Timestamp: time.Now(),
		Details:   make([]string, 0),
	}

	filter, found := v.manager.GetPersistentFilter(ruleID)
	if !found {
		result.Message = "Filter not found in registry"
		result.Duration = time.Since(start)
		return result
	}

	result.AddDetail(fmt.Sprintf("Rule: %s", filter.RuleName))
	result.AddDetail(fmt.Sprintf("Layer: %s", filter.Layer))
	result.AddDetail(fmt.Sprintf("Action: %s", filter.Action))
	result.AddDetail(fmt.Sprintf("GUID: %s", filter.GUIDString()))

	if filter.Verified {
		result.Passed = true
		result.Message = "Filter is active and verified"
	} else {
		result.Message = "Filter exists in registry but not verified in WFP"
	}

	result.Duration = time.Since(start)
	return result
}

// ValidateCount checks if the expected number of filters exist.
func (v *BootValidator) ValidateCount(expectedCount int) *ValidationResult {
	start := time.Now()
	result := &ValidationResult{
		CheckName: "Filter Count",
		Passed:    false,
		Timestamp: time.Now(),
		Details:   make([]string, 0),
	}

	actualCount := v.manager.GetPersistentCount()
	result.AddDetail(fmt.Sprintf("Expected: %d", expectedCount))
	result.AddDetail(fmt.Sprintf("Actual: %d", actualCount))

	if actualCount == expectedCount {
		result.Passed = true
		result.Message = fmt.Sprintf("Filter count matches: %d", actualCount)
	} else if actualCount < expectedCount {
		result.Message = fmt.Sprintf("Missing %d filters", expectedCount-actualCount)
	} else {
		result.Message = fmt.Sprintf("Extra %d filters", actualCount-expectedCount)
	}

	result.Duration = time.Since(start)
	return result
}

// ============================================================================
// Full Validation
// ============================================================================

// RunFullValidation runs all validation checks.
func (v *BootValidator) RunFullValidation() *ValidationReport {
	report := NewValidationReport()

	// Check 1: Filters exist
	report.AddResult(v.ValidateFiltersExist())

	// Check 2: Registry-WFP sync
	report.AddResult(v.ValidateFiltersMatch())

	// Check 3: Verify each individual filter
	for _, filter := range v.manager.GetAllPersistent() {
		report.AddResult(v.ValidateFilterActive(filter.RuleID))
	}

	report.Finish()
	return report
}

// QuickValidation runs essential checks only.
func (v *BootValidator) QuickValidation() *ValidationReport {
	report := NewValidationReport()

	// Only sync check
	report.AddResult(v.ValidateFiltersMatch())

	report.Finish()
	return report
}

// ============================================================================
// Orphan Detection
// ============================================================================

// DetectOrphans finds WFP filters that exist but are not in registry.
// NOTE: Currently returns empty as filter enumeration is not fully implemented.
func (v *BootValidator) DetectOrphans() ([]string, error) {
	// Sync first to get current state
	if err := v.manager.SyncWithWFP(); err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	// Get orphan count from stats
	stats := v.manager.GetStats()
	if stats.TotalOrphaned == 0 {
		return []string{}, nil
	}

	// TODO: Return actual orphan GUIDs when enumeration is implemented
	orphans := make([]string, stats.TotalOrphaned)
	for i := 0; i < stats.TotalOrphaned; i++ {
		orphans[i] = fmt.Sprintf("orphan-%d", i)
	}

	return orphans, nil
}

// DetectMissing finds registry entries that don't have corresponding WFP filters.
func (v *BootValidator) DetectMissing() ([]string, error) {
	// Sync first
	if err := v.manager.SyncWithWFP(); err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	missing := make([]string, 0)
	for _, filter := range v.manager.GetAllPersistent() {
		if !filter.Verified {
			missing = append(missing, filter.RuleID)
		}
	}

	return missing, nil
}

// ============================================================================
// Health Check
// ============================================================================

// HealthStatus represents the overall health of boot-time protection.
type HealthStatus struct {
	Healthy       bool
	Message       string
	FilterCount   int
	VerifiedCount int
	OrphanCount   int
	MissingCount  int
	LastCheck     time.Time
}

// CheckHealth performs a quick health check.
func (v *BootValidator) CheckHealth() *HealthStatus {
	status := &HealthStatus{
		LastCheck: time.Now(),
	}

	// Sync
	if err := v.manager.SyncWithWFP(); err != nil {
		status.Healthy = false
		status.Message = fmt.Sprintf("Sync failed: %v", err)
		return status
	}

	// Get counts
	stats := v.manager.GetStats()
	status.FilterCount = stats.TotalInstalled
	status.VerifiedCount = stats.TotalVerified
	status.OrphanCount = stats.TotalOrphaned

	// Count missing
	missing := 0
	for _, filter := range v.manager.GetAllPersistent() {
		if !filter.Verified {
			missing++
		}
	}
	status.MissingCount = missing

	// Determine health
	if status.FilterCount == 0 {
		status.Healthy = true
		status.Message = "No persistent filters configured"
	} else if status.MissingCount > 0 {
		status.Healthy = false
		status.Message = fmt.Sprintf("%d filters missing from WFP", status.MissingCount)
	} else if status.OrphanCount > 0 {
		status.Healthy = false
		status.Message = fmt.Sprintf("%d orphaned filters detected", status.OrphanCount)
	} else {
		status.Healthy = true
		status.Message = fmt.Sprintf("All %d filters healthy", status.FilterCount)
	}

	return status
}

// String returns a summary of the health status.
func (s *HealthStatus) String() string {
	status := "HEALTHY"
	if !s.Healthy {
		status = "UNHEALTHY"
	}
	return fmt.Sprintf("[%s] %s (filters=%d, verified=%d, orphans=%d, missing=%d)",
		status, s.Message, s.FilterCount, s.VerifiedCount, s.OrphanCount, s.MissingCount)
}
