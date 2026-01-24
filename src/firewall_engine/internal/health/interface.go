// Package health provides health monitoring for the firewall engine.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// Health Status Types
// ============================================================================

// Status represents the health status of a component.
type Status int

const (
	// StatusHealthy indicates the component is fully operational.
	StatusHealthy Status = iota

	// StatusDegraded indicates the component is working but with issues.
	StatusDegraded

	// StatusUnhealthy indicates the component is not working.
	StatusUnhealthy

	// StatusUnknown indicates the health status is not known.
	StatusUnknown
)

// String returns the string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusDegraded:
		return "degraded"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	switch str {
	case "healthy":
		*s = StatusHealthy
	case "degraded":
		*s = StatusDegraded
	case "unhealthy":
		*s = StatusUnhealthy
	default:
		*s = StatusUnknown
	}
	return nil
}

// IsOK returns true if status is healthy or degraded (still serving).
func (s Status) IsOK() bool {
	return s == StatusHealthy || s == StatusDegraded
}

// ============================================================================
// Check Result
// ============================================================================

// CheckResult contains the result of a health check.
type CheckResult struct {
	// Status is the health status.
	Status Status `json:"status"`

	// Message is a human-readable status description.
	Message string `json:"message"`

	// Latency is how long the check took.
	Latency time.Duration `json:"latency_ns"`

	// LatencyMs is latency in milliseconds (for JSON).
	LatencyMs float64 `json:"latency_ms"`

	// Timestamp is when the check was performed.
	Timestamp time.Time `json:"timestamp"`

	// Details contains additional check-specific details.
	Details map[string]any `json:"details,omitempty"`
}

// NewCheckResult creates a new check result with the given status and message.
func NewCheckResult(status Status, message string) CheckResult {
	return CheckResult{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Details:   make(map[string]any),
	}
}

// Healthy creates a healthy check result.
func Healthy(message string) CheckResult {
	return NewCheckResult(StatusHealthy, message)
}

// Degraded creates a degraded check result.
func Degraded(message string) CheckResult {
	return NewCheckResult(StatusDegraded, message)
}

// Unhealthy creates an unhealthy check result.
func Unhealthy(message string) CheckResult {
	return NewCheckResult(StatusUnhealthy, message)
}

// Unknown creates an unknown status check result.
func Unknown(message string) CheckResult {
	return NewCheckResult(StatusUnknown, message)
}

// WithLatency sets the latency on the result.
func (r CheckResult) WithLatency(d time.Duration) CheckResult {
	r.Latency = d
	r.LatencyMs = float64(d.Microseconds()) / 1000.0
	return r
}

// WithDetails adds details to the result.
func (r CheckResult) WithDetails(key string, value any) CheckResult {
	if r.Details == nil {
		r.Details = make(map[string]any)
	}
	r.Details[key] = value
	return r
}

// ============================================================================
// Health Checker Interface
// ============================================================================

// Checker is the interface for health checkers.
type Checker interface {
	// Name returns the component name.
	Name() string

	// Check performs the health check and returns the result.
	Check(ctx context.Context) CheckResult

	// IsCritical returns true if this is a critical component.
	// Unhealthy critical components cause overall unhealthy status.
	IsCritical() bool
}

// ============================================================================
// Base Checker Implementation
// ============================================================================

// BaseChecker provides common functionality for health checkers.
type BaseChecker struct {
	name       string
	critical   bool
	enabled    bool
	mu         sync.RWMutex
	lastResult CheckResult
	checkFunc  func(ctx context.Context) CheckResult
}

// NewBaseChecker creates a new base checker.
func NewBaseChecker(name string, critical bool, checkFunc func(ctx context.Context) CheckResult) *BaseChecker {
	return &BaseChecker{
		name:      name,
		critical:  critical,
		enabled:   true,
		checkFunc: checkFunc,
	}
}

// Name returns the component name.
func (c *BaseChecker) Name() string {
	return c.name
}

// IsCritical returns true if this is a critical component.
func (c *BaseChecker) IsCritical() bool {
	return c.critical
}

// Check performs the health check.
func (c *BaseChecker) Check(ctx context.Context) CheckResult {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		return Healthy(fmt.Sprintf("%s check disabled", c.name))
	}

	start := time.Now()
	result := c.checkFunc(ctx)
	result.Latency = time.Since(start)
	result.LatencyMs = float64(result.Latency.Microseconds()) / 1000.0
	result.Timestamp = time.Now()

	c.mu.Lock()
	c.lastResult = result
	c.mu.Unlock()

	return result
}

// SetEnabled enables or disables the checker.
func (c *BaseChecker) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// IsEnabled returns true if the checker is enabled.
func (c *BaseChecker) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// GetLastResult returns the last check result.
func (c *BaseChecker) GetLastResult() CheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastResult
}

// ============================================================================
// Component Result
// ============================================================================

// ComponentResult is the health result for a single component.
type ComponentResult struct {
	Name      string  `json:"name"`
	Status    Status  `json:"status"`
	Message   string  `json:"message"`
	LatencyMs float64 `json:"latency_ms"`
	Critical  bool    `json:"critical,omitempty"`
}

// FromCheckResult converts a CheckResult to ComponentResult.
func FromCheckResult(name string, result CheckResult, critical bool) ComponentResult {
	return ComponentResult{
		Name:      name,
		Status:    result.Status,
		Message:   result.Message,
		LatencyMs: result.LatencyMs,
		Critical:  critical,
	}
}

// ============================================================================
// Aggregated Result
// ============================================================================

// AggregatedResult contains the overall health status with component breakdown.
type AggregatedResult struct {
	// Status is the overall health status.
	Status Status `json:"status"`

	// Message is a summary message.
	Message string `json:"message,omitempty"`

	// Components contains individual component results.
	Components []ComponentResult `json:"components"`

	// Timestamp is when the check was performed.
	Timestamp time.Time `json:"timestamp"`

	// TotalLatencyMs is the total check time.
	TotalLatencyMs float64 `json:"total_latency_ms"`
}

// IsHealthy returns true if overall status is healthy.
func (r AggregatedResult) IsHealthy() bool {
	return r.Status == StatusHealthy
}

// IsOK returns true if status allows serving (healthy or degraded).
func (r AggregatedResult) IsOK() bool {
	return r.Status.IsOK()
}

// HTTPStatusCode returns the appropriate HTTP status code.
func (r AggregatedResult) HTTPStatusCode() int {
	if r.IsOK() {
		return 200
	}
	return 503
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrCheckTimeout is returned when a health check times out.
	ErrCheckTimeout = errors.New("health check timed out")

	// ErrCheckerNotFound is returned when a checker is not found.
	ErrCheckerNotFound = errors.New("health checker not found")

	// ErrNoCheckers is returned when no checkers are registered.
	ErrNoCheckers = errors.New("no health checkers registered")
)

// ============================================================================
// Check Options
// ============================================================================

// CheckOptions configures health check behavior.
type CheckOptions struct {
	// Timeout is the maximum time for all checks.
	Timeout time.Duration

	// Parallel enables parallel check execution.
	Parallel bool

	// IncludeDetails includes detailed information in results.
	IncludeDetails bool
}

// DefaultCheckOptions returns default check options.
func DefaultCheckOptions() CheckOptions {
	return CheckOptions{
		Timeout:        5 * time.Second,
		Parallel:       true,
		IncludeDetails: false,
	}
}
