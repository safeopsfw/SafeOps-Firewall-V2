// Package health provides health check framework.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// Check represents a health check
type Check interface {
	Name() string
	Check(ctx context.Context) *Result
}

// Result represents a health check result
type Result struct {
	Status    Status                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// CheckFunc is a function that performs a health check
type CheckFunc func(ctx context.Context) *Result

// SimpleCheck wraps a function as a Check
type SimpleCheck struct {
	name    string
	checkFn CheckFunc
}

// Name returns the check name
func (c *SimpleCheck) Name() string {
	return c.name
}

// Check performs the health check
func (c *SimpleCheck) Check(ctx context.Context) *Result {
	return c.checkFn(ctx)
}

// NewCheck creates a simple check
func NewCheck(name string, fn CheckFunc) Check {
	return &SimpleCheck{
		name:    name,
		checkFn: fn,
	}
}

// Checker manages health checks
type Checker struct {
	checks  []Check
	timeout time.Duration
	mu      sync.RWMutex
}

// NewChecker creates a new health checker
func NewChecker() *Checker {
	return &Checker{
		checks:  make([]Check, 0),
		timeout: 10 * time.Second,
	}
}

// AddCheck adds a health check
func (c *Checker) AddCheck(check Check) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, check)
}

// AddCheckFunc adds a check function
func (c *Checker) AddCheckFunc(name string, fn CheckFunc) {
	c.AddCheck(NewCheck(name, fn))
}

// SetTimeout sets the check timeout
func (c *Checker) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// Report represents overall health report
type Report struct {
	Status    Status             `json:"status"`
	Timestamp time.Time          `json:"timestamp"`
	Duration  time.Duration      `json:"duration"`
	Checks    map[string]*Result `json:"checks"`
}

// Check performs all health checks
func (c *Checker) Check(ctx context.Context) *Report {
	c.mu.RLock()
	defer c.mu.RUnlock()

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	report := &Report{
		Status:    StatusHealthy,
		Timestamp: start,
		Checks:    make(map[string]*Result),
	}

	// Run checks concurrently
	var wg sync.WaitGroup
	results := make(chan struct {
		name   string
		result *Result
	}, len(c.checks))

	for _, check := range c.checks {
		wg.Add(1)
		go func(check Check) {
			defer wg.Done()

			checkStart := time.Now()
			result := check.Check(ctx)
			result.Duration = time.Since(checkStart)
			result.Timestamp = checkStart

			results <- struct {
				name   string
				result *Result
			}{check.Name(), result}
		}(check)
	}

	// Wait for all checks
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for r := range results {
		report.Checks[r.name] = r.result

		// Update overall status
		switch r.result.Status {
		case StatusUnhealthy:
			report.Status = StatusUnhealthy
		case StatusDegraded:
			if report.Status != StatusUnhealthy {
				report.Status = StatusDegraded
			}
		}
	}

	report.Duration = time.Since(start)
	return report
}

// IsHealthy returns true if all checks pass
func (c *Checker) IsHealthy(ctx context.Context) bool {
	report := c.Check(ctx)
	return report.Status == StatusHealthy
}

// Handler creates an HTTP handler for health checks
func (c *Checker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := c.Check(r.Context())

		w.Header().Set("Content-Type", "application/json")

		status := http.StatusOK
		if report.Status == StatusUnhealthy {
			status = http.StatusServiceUnavailable
		}

		w.WriteHeader(status)
		json.NewEncoder(w).Encode(report)
	})
}

// LivenessHandler returns a simple liveness handler
func LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// ReadinessHandler creates a readiness handler
func (c *Checker) ReadinessHandler() http.Handler {
	return c.Handler()
}

// Healthy creates a healthy result
func Healthy() *Result {
	return &Result{
		Status: StatusHealthy,
	}
}

// HealthyWithMessage creates a healthy result with message
func HealthyWithMessage(msg string) *Result {
	return &Result{
		Status:  StatusHealthy,
		Message: msg,
	}
}

// Unhealthy creates an unhealthy result
func Unhealthy(msg string) *Result {
	return &Result{
		Status:  StatusUnhealthy,
		Message: msg,
	}
}

// UnhealthyWithError creates an unhealthy result from error
func UnhealthyWithError(err error) *Result {
	return &Result{
		Status:  StatusUnhealthy,
		Message: err.Error(),
	}
}

// Degraded creates a degraded result
func Degraded(msg string) *Result {
	return &Result{
		Status:  StatusDegraded,
		Message: msg,
	}
}

// WithDetails adds details to a result
func (r *Result) WithDetails(details map[string]interface{}) *Result {
	r.Details = details
	return r
}

// Global checker instance
var defaultChecker = NewChecker()

// Default returns the default checker
func Default() *Checker {
	return defaultChecker
}

// AddCheck adds a check to the default checker
func AddCheck(check Check) {
	defaultChecker.AddCheck(check)
}

// AddCheckFunc adds a check function to the default checker
func AddCheckFunc(name string, fn CheckFunc) {
	defaultChecker.AddCheckFunc(name, fn)
}

// Check performs all checks using the default checker
func CheckAll(ctx context.Context) *Report {
	return defaultChecker.Check(ctx)
}
