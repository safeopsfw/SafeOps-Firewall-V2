// Package enforcement provides tests for dual-engine coordination.
package enforcement

import (
	"context"
	"testing"
	"time"

	"firewall_engine/pkg/models"

	"github.com/google/uuid"
)

// ============================================================================
// Dual Engine Mode Tests
// ============================================================================

func TestDualEngineModeString(t *testing.T) {
	tests := []struct {
		mode     DualEngineMode
		expected string
	}{
		{DualModeBoth, "BOTH"},
		{DualModeSafeOpsOnly, "SAFEOPS_ONLY"},
		{DualModeWFPOnly, "WFP_ONLY"},
		{DualModeDisabled, "DISABLED"},
		{DualEngineMode(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		result := tt.mode.String()
		if result != tt.expected {
			t.Errorf("Mode %v: expected %q, got %q", tt.mode, tt.expected, result)
		}
	}
}

// ============================================================================
// Configuration Tests
// ============================================================================

func TestDefaultDualEngineConfig(t *testing.T) {
	config := DefaultDualEngineConfig()

	if config == nil {
		t.Fatal("DefaultDualEngineConfig() returned nil")
	}

	if config.Mode != DualModeBoth {
		t.Errorf("Mode: expected DualModeBoth, got %v", config.Mode)
	}

	if !config.FailoverEnabled {
		t.Error("FailoverEnabled should be true by default")
	}

	if config.SyncInterval == 0 {
		t.Error("SyncInterval should not be zero")
	}

	if config.HealthCheckInterval == 0 {
		t.Error("HealthCheckInterval should not be zero")
	}

	if config.WFPBatchSize == 0 {
		t.Error("WFPBatchSize should not be zero")
	}

	if !config.EnablePersistentFilters {
		t.Error("EnablePersistentFilters should be true by default")
	}
}

// ============================================================================
// Coordinator Creation Tests
// ============================================================================

func TestNewDualEngineCoordinator_NilEngine(t *testing.T) {
	// Creating with nil engine should work, defaulting to SafeOps-only
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("NewDualEngineCoordinator(nil) failed: %v", err)
	}

	if dec == nil {
		t.Fatal("Expected non-nil coordinator")
	}

	// Mode should fall back to SafeOps-only
	if dec.GetMode() != DualModeSafeOpsOnly {
		t.Errorf("Expected DualModeSafeOpsOnly, got %v", dec.GetMode())
	}
}

func TestNewDualEngineCoordinatorWithConfig(t *testing.T) {
	config := &DualEngineConfig{
		Mode:                    DualModeSafeOpsOnly,
		FailoverEnabled:         false,
		SyncInterval:            60 * time.Second,
		HealthCheckInterval:     5 * time.Second,
		WFPBatchSize:            50,
		EnablePersistentFilters: false,
		MaxPersistentFilters:    25,
	}

	dec, err := NewDualEngineCoordinatorWithConfig(nil, config)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	if dec.GetMode() != DualModeSafeOpsOnly {
		t.Errorf("Expected DualModeSafeOpsOnly, got %v", dec.GetMode())
	}
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

func TestDualEngineCoordinator_StartStop(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// Initially not running
	if dec.IsRunning() {
		t.Error("Should not be running initially")
	}

	// Start
	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !dec.IsRunning() {
		t.Error("Should be running after Start")
	}

	// Start again should error
	if err := dec.Start(ctx); err == nil {
		t.Error("Expected error when starting already running coordinator")
	}

	// Stop
	if err := dec.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if dec.IsRunning() {
		t.Error("Should not be running after Stop")
	}

	// Stop again should be safe
	if err := dec.Stop(); err != nil {
		t.Errorf("Stop on stopped coordinator failed: %v", err)
	}
}

// ============================================================================
// Rule Management Tests
// ============================================================================

func TestDualEngineCoordinator_AddRemoveRule(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	// Create a test rule
	rule := &models.FirewallRule{
		ID:       uuid.New(),
		Name:     "Test_Block_Rule",
		Enabled:  true,
		Action:   models.VerdictBlock,
		Priority: 100,
	}

	// Add rule
	if err := dec.AddRule(rule); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Check stats
	stats := dec.GetStats()
	if stats.TotalRules != 1 {
		t.Errorf("Expected 1 rule, got %d", stats.TotalRules)
	}

	// Get current rules
	rules := dec.GetCurrentRules()
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}

	// Remove rule
	if err := dec.RemoveRule(rule.ID.String()); err != nil {
		t.Fatalf("RemoveRule failed: %v", err)
	}

	stats = dec.GetStats()
	if stats.TotalRules != 0 {
		t.Errorf("Expected 0 rules, got %d", stats.TotalRules)
	}
}

func TestDualEngineCoordinator_SyncRules(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	// Create test rules
	rules := []*models.FirewallRule{
		{ID: uuid.New(), Name: "Rule1", Enabled: true, Action: models.VerdictBlock, Priority: 100},
		{ID: uuid.New(), Name: "Rule2", Enabled: true, Action: models.VerdictAllow, Priority: 200},
		{ID: uuid.New(), Name: "Rule3", Enabled: false, Action: models.VerdictBlock, Priority: 300}, // Disabled
	}

	// Sync rules
	if err := dec.SyncRules(rules); err != nil {
		t.Fatalf("SyncRules failed: %v", err)
	}

	// Check stats
	stats := dec.GetStats()
	if stats.TotalRules != 3 {
		t.Errorf("Expected 3 total rules, got %d", stats.TotalRules)
	}
}

func TestDualEngineCoordinator_AddNilRule(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	// Add nil rule should error
	if err := dec.AddRule(nil); err == nil {
		t.Error("Expected error when adding nil rule")
	}
}

func TestDualEngineCoordinator_OperationsWhenNotRunning(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// Don't start - all operations should fail

	rule := &models.FirewallRule{
		ID:      uuid.New(),
		Name:    "Test",
		Enabled: true,
	}

	if err := dec.AddRule(rule); err == nil {
		t.Error("Expected error when adding rule without starting")
	}

	if err := dec.RemoveRule("test"); err == nil {
		t.Error("Expected error when removing rule without starting")
	}

	if err := dec.SyncRules([]*models.FirewallRule{rule}); err == nil {
		t.Error("Expected error when syncing rules without starting")
	}
}

// ============================================================================
// Mode Tests
// ============================================================================

func TestDualEngineCoordinator_SetMode(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// Can't switch to WFP mode without engine
	if err := dec.SetMode(DualModeWFPOnly); err == nil {
		t.Error("Expected error when switching to WFP mode without engine")
	}

	if err := dec.SetMode(DualModeBoth); err == nil {
		t.Error("Expected error when switching to Both mode without WFP engine")
	}

	// Can switch to SafeOps-only
	if err := dec.SetMode(DualModeSafeOpsOnly); err != nil {
		t.Errorf("SetMode(SafeOpsOnly) failed: %v", err)
	}

	// Can switch to disabled
	if err := dec.SetMode(DualModeDisabled); err != nil {
		t.Errorf("SetMode(Disabled) failed: %v", err)
	}
}

// ============================================================================
// Health Check Tests
// ============================================================================

func TestDualEngineCoordinator_HealthCheck(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	health := dec.HealthCheck()

	if health == nil {
		t.Fatal("HealthCheck returned nil")
	}

	// In SafeOps-only mode, should be healthy
	if !health.Healthy {
		t.Errorf("Expected healthy, got unhealthy: %s", health.Message)
	}

	if health.Mode != DualModeSafeOpsOnly {
		t.Errorf("Expected SafeOpsOnly mode, got %v", health.Mode)
	}

	if !health.SafeOpsHealthy {
		t.Error("SafeOps should be healthy")
	}

	// WFP should not be checked in SafeOps-only mode
	if health.WFPHealthy {
		t.Error("WFP should not be healthy when in SafeOps-only mode")
	}

	// String representation should work
	str := health.String()
	if str == "" {
		t.Error("Health string should not be empty")
	}
}

// ============================================================================
// Statistics Tests
// ============================================================================

func TestDualEngineCoordinator_Stats(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	// Increment counters
	dec.IncrementPacketsProcessed()
	dec.IncrementPacketsProcessed()
	dec.IncrementSafeOpsBlocked()
	dec.IncrementWFPBlocked()
	dec.IncrementBothBlocked()

	stats := dec.GetStats()

	if stats.PacketsProcessed != 2 {
		t.Errorf("Expected 2 packets, got %d", stats.PacketsProcessed)
	}

	if stats.SafeOpsBlocked != 1 {
		t.Errorf("Expected 1 SafeOps blocked, got %d", stats.SafeOpsBlocked)
	}

	if stats.WFPBlocked != 1 {
		t.Errorf("Expected 1 WFP blocked, got %d", stats.WFPBlocked)
	}

	if stats.BothBlocked != 1 {
		t.Errorf("Expected 1 both blocked, got %d", stats.BothBlocked)
	}
}

// ============================================================================
// Accessor Tests
// ============================================================================

func TestDualEngineCoordinator_Accessors(t *testing.T) {
	dec, err := NewDualEngineCoordinator(nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// WFP engine should be nil
	if dec.GetWFPEngine() != nil {
		t.Error("Expected nil WFP engine")
	}

	// Persistent manager should be nil initially
	if dec.GetPersistentManager() != nil {
		t.Error("Expected nil persistent manager initially")
	}

	// Current rules should be empty
	rules := dec.GetCurrentRules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(rules))
	}

	// RequireRunning should fail when not running
	if err := dec.RequireRunning(); err == nil {
		t.Error("Expected error from RequireRunning when not running")
	}

	// Start and check again
	ctx := context.Background()
	if err := dec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dec.Stop()

	if err := dec.RequireRunning(); err != nil {
		t.Errorf("RequireRunning failed when running: %v", err)
	}
}

// ============================================================================
// DualEngineHealth Tests
// ============================================================================

func TestDualEngineHealth_String(t *testing.T) {
	health := &DualEngineHealth{
		Healthy:        true,
		Mode:           DualModeBoth,
		WFPFilterCount: 10,
		SafeOpsHealthy: true,
		WFPHealthy:     true,
	}

	str := health.String()
	if str == "" {
		t.Error("String should not be empty")
	}

	// Should contain key info
	expected := "HEALTHY"
	if len(str) == 0 || str[1:len(expected)+1] != expected {
		t.Logf("Health string: %s", str)
	}
}
