package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestBasicHealthChecker tests basic checker functionality
func TestBasicHealthChecker(t *testing.T) {
	checker := NewChecker()

	// Add a simple passing check
	checker.AddCheckFunc("test", func(ctx context.Context) *Result {
		return Healthy()
	})

	report := checker.Check(context.Background())

	if report.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", report.Status)
	}

	if len(report.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(report.Checks))
	}
}

// TestRequiredVsOptional tests required vs optional check behavior
func TestRequiredVsOptional(t *testing.T) {
	tests := []struct {
		name           string
		requiredStatus Status
		optionalStatus Status
		expectedStatus Status
	}{
		{
			name:           "both healthy",
			requiredStatus: StatusHealthy,
			optionalStatus: StatusHealthy,
			expectedStatus: StatusHealthy,
		},
		{
			name:           "required unhealthy",
			requiredStatus: StatusUnhealthy,
			optionalStatus: StatusHealthy,
			expectedStatus: StatusUnhealthy,
		},
		{
			name:           "optional unhealthy",
			requiredStatus: StatusHealthy,
			optionalStatus: StatusUnhealthy,
			expectedStatus: StatusDegraded, // Optional failure = degraded
		},
		{
			name:           "both unhealthy",
			requiredStatus: StatusUnhealthy,
			optionalStatus: StatusUnhealthy,
			expectedStatus: StatusUnhealthy,
		},
		{
			name:           "required degraded",
			requiredStatus: StatusDegraded,
			optionalStatus: StatusHealthy,
			expectedStatus: StatusDegraded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker()

			// Add required check
			checker.AddCheck(NewRequiredCheck("required", func(ctx context.Context) *Result {
				return &Result{Status: tt.requiredStatus}
			}))

			// Add optional check
			checker.AddCheck(NewOptionalCheck("optional", func(ctx context.Context) *Result {
				return &Result{Status: tt.optionalStatus}
			}))

			report := checker.Check(context.Background())

			if report.Status != tt.expectedStatus {
				t.Errorf("expected %s, got %s", tt.expectedStatus, report.Status)
			}
		})
	}
}

// TestCheckTimeout tests that checks respect timeout
func TestCheckTimeout(t *testing.T) {
	checker := NewChecker()
	checker.SetTimeout(100 * time.Millisecond)

	// Add a slow check
	checker.AddCheckFunc("slow", func(ctx context.Context) *Result {
		select {
		case <-time.After(1 * time.Second):
			return Healthy()
		case <-ctx.Done():
			return Unhealthy("timeout")
		}
	})

	start := time.Now()
	report := checker.Check(context.Background())
	duration := time.Since(start)

	// Should complete within timeout + overhead
	if duration > 200*time.Millisecond {
		t.Errorf("check took too long: %v", duration)
	}

	// Check should have completed (may or may not be healthy depending on timing)
	if len(report.Checks) != 1 {
		t.Errorf("expected 1 check result, got %d", len(report.Checks))
	}
}

// TestStatusHelpers tests helper functions
func TestStatusHelpers(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() *Result
		expected Status
	}{
		{"Healthy", func() *Result { return Healthy() }, StatusHealthy},
		{"HealthyWithMessage", func() *Result { return HealthyWithMessage("all good") }, StatusHealthy},
		{"Unhealthy", func() *Result { return Unhealthy("error") }, StatusUnhealthy},
		{"UnhealthyWithError", func() *Result { return UnhealthyWithError(errors.New("test error")) }, StatusUnhealthy},
		{"Degraded", func() *Result { return Degraded("slow") }, StatusDegraded},
		{"Starting", func() *Result { return Starting("initializing") }, StatusStarting},
		{"Stopping", func() *Result { return Stopping("shutting down") }, StatusStopping},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result.Status != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result.Status)
			}
		})
	}
}

// TestResultWithDetails tests adding details to results
func TestResultWithDetails(t *testing.T) {
	result := Healthy().WithDetails(map[string]interface{}{
		"version": "1.0.0",
		"uptime":  3600,
	})

	if result.Details == nil {
		t.Error("expected details to be set")
	}

	if result.Details["version"] != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %v", result.Details["version"])
	}
}

// TestIsHealthy tests the IsHealthy convenience method
func TestIsHealthy(t *testing.T) {
	checker := NewChecker()

	// Add healthy check
	checker.AddCheckFunc("test", func(ctx context.Context) *Result {
		return Healthy()
	})

	if !checker.IsHealthy(context.Background()) {
		t.Error("expected IsHealthy to return true")
	}

	// Add unhealthy check
	checker.AddCheckFunc("bad", func(ctx context.Context) *Result {
		return Unhealthy("error")
	})

	if checker.IsHealthy(context.Background()) {
		t.Error("expected IsHealthy to return false")
	}
}

// TestConcurrentChecks tests that multiple checks run concurrently
func TestConcurrentChecks(t *testing.T) {
	checker := NewChecker()
	checker.SetTimeout(5 * time.Second)

	// Add 3 checks that each take 100ms
	for i := 0; i < 3; i++ {
		name := string(rune('a' + i))
		checker.AddCheckFunc(name, func(ctx context.Context) *Result {
			time.Sleep(100 * time.Millisecond)
			return Healthy()
		})
	}

	start := time.Now()
	report := checker.Check(context.Background())
	duration := time.Since(start)

	// Should complete in ~100ms (concurrent) not 300ms (sequential)
	if duration > 200*time.Millisecond {
		t.Errorf("checks appear to run sequentially, took %v", duration)
	}

	if len(report.Checks) != 3 {
		t.Errorf("expected 3 checks, got %d", len(report.Checks))
	}
}

// TestCompositeCheck tests composite check aggregation
func TestCompositeCheck(t *testing.T) {
	subCheck1 := NewCheck("sub1", func(ctx context.Context) *Result {
		return Healthy()
	})

	subCheck2 := NewCheck("sub2", func(ctx context.Context) *Result {
		return Unhealthy("error")
	})

	composite := NewCompositeCheck("composite", subCheck1, subCheck2)

	result := composite.Check(context.Background())

	if result.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy, got %s", result.Status)
	}

	// Composite should be required if any sub-check is required
	if !composite.IsRequired() {
		t.Error("expected composite to be required")
	}
}

// TestThrottledCheck tests check throttling
func TestThrottledCheck(t *testing.T) {
	callCount := 0
	baseCheck := NewCheck("test", func(ctx context.Context) *Result {
		callCount++
		return Healthy()
	})

	throttled := NewThrottledCheck(baseCheck, 100*time.Millisecond)

	// First call
	throttled.Check(context.Background())
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call immediately (should be cached)
	throttled.Check(context.Background())
	if callCount != 1 {
		t.Errorf("expected 1 call (cached), got %d", callCount)
	}

	// Wait for throttle interval
	time.Sleep(150 * time.Millisecond)

	// Third call (should execute)
	throttled.Check(context.Background())
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

// TestDefaultChecker tests the global default checker
func TestDefaultChecker(t *testing.T) {
	// Reset default for this test
	defaultChecker = NewChecker()

	AddCheckFunc("test", func(ctx context.Context) *Result {
		return Healthy()
	})

	report := CheckAll(context.Background())

	if report.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", report.Status)
	}

	if len(report.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(report.Checks))
	}
}

// BenchmarkHealthCheck benchmarks health check performance
func BenchmarkHealthCheck(b *testing.B) {
	checker := NewChecker()

	for i := 0; i < 10; i++ {
		name := string(rune('a' + i))
		checker.AddCheckFunc(name, func(ctx context.Context) *Result {
			return Healthy()
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check(context.Background())
	}
}
