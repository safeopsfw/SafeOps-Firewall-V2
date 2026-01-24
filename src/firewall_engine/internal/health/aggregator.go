// Package health provides health monitoring for the firewall engine.
package health

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// Health Aggregator
// ============================================================================

// checkResultWithName holds a check result with component metadata.
type checkResultWithName struct {
	name     string
	result   CheckResult
	critical bool
}

// Aggregator aggregates health checks from multiple components.
type Aggregator struct {
	checkers    []Checker
	mu          sync.RWMutex
	lastResult  *AggregatedResult
	cacheTime   time.Duration
	lastCheckAt time.Time
}

// NewAggregator creates a new health aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		checkers:  make([]Checker, 0),
		cacheTime: 1 * time.Second, // Cache results for 1 second
	}
}

// Register adds a health checker to the aggregator.
func (a *Aggregator) Register(checker Checker) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checkers = append(a.checkers, checker)
}

// RegisterAll adds multiple health checkers.
func (a *Aggregator) RegisterAll(checkers ...Checker) {
	for _, c := range checkers {
		a.Register(c)
	}
}

// Unregister removes a health checker by name.
func (a *Aggregator) Unregister(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, c := range a.checkers {
		if c.Name() == name {
			a.checkers = append(a.checkers[:i], a.checkers[i+1:]...)
			return true
		}
	}
	return false
}

// SetCacheTime sets how long to cache health check results.
func (a *Aggregator) SetCacheTime(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cacheTime = d
}

// GetCheckerCount returns the number of registered checkers.
func (a *Aggregator) GetCheckerCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.checkers)
}

// ============================================================================
// Health Check Execution
// ============================================================================

// Check performs all health checks and returns aggregated result.
func (a *Aggregator) Check(ctx context.Context) AggregatedResult {
	return a.CheckWithOptions(ctx, DefaultCheckOptions())
}

// CheckWithTimeout performs health checks with a specific timeout.
func (a *Aggregator) CheckWithTimeout(timeout time.Duration) AggregatedResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return a.Check(ctx)
}

// CheckWithOptions performs health checks with custom options.
func (a *Aggregator) CheckWithOptions(ctx context.Context, opts CheckOptions) AggregatedResult {
	a.mu.RLock()

	// Return cached result if valid
	if a.lastResult != nil && time.Since(a.lastCheckAt) < a.cacheTime {
		result := *a.lastResult
		a.mu.RUnlock()
		return result
	}

	checkers := make([]Checker, len(a.checkers))
	copy(checkers, a.checkers)
	a.mu.RUnlock()

	if len(checkers) == 0 {
		return AggregatedResult{
			Status:    StatusHealthy,
			Message:   "No health checks registered",
			Timestamp: time.Now(),
		}
	}

	// Apply timeout if set
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	start := time.Now()
	var result AggregatedResult

	if opts.Parallel {
		result = a.checkParallel(ctx, checkers)
	} else {
		result = a.checkSequential(ctx, checkers)
	}

	result.TotalLatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	result.Timestamp = time.Now()

	// Cache result
	a.mu.Lock()
	a.lastResult = &result
	a.lastCheckAt = time.Now()
	a.mu.Unlock()

	return result
}

// checkParallel runs all checks in parallel.
func (a *Aggregator) checkParallel(ctx context.Context, checkers []Checker) AggregatedResult {
	results := make(chan checkResultWithName, len(checkers))

	var wg sync.WaitGroup
	for _, checker := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()

			// Check with context
			result := c.Check(ctx)

			select {
			case results <- checkResultWithName{
				name:     c.Name(),
				result:   result,
				critical: c.IsCritical(),
			}:
			case <-ctx.Done():
				// Context cancelled, send timeout result
				results <- checkResultWithName{
					name:     c.Name(),
					result:   Unhealthy("Check timed out"),
					critical: c.IsCritical(),
				}
			}
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	return a.aggregateResults(results, len(checkers))
}

// checkSequential runs all checks sequentially.
func (a *Aggregator) checkSequential(ctx context.Context, checkers []Checker) AggregatedResult {
	results := make(chan checkResultWithName, len(checkers))

	for _, checker := range checkers {
		select {
		case <-ctx.Done():
			results <- checkResultWithName{
				name:     checker.Name(),
				result:   Unhealthy("Check timed out"),
				critical: checker.IsCritical(),
			}
		default:
			result := checker.Check(ctx)
			results <- checkResultWithName{
				name:     checker.Name(),
				result:   result,
				critical: checker.IsCritical(),
			}
		}
	}

	close(results)
	return a.aggregateResults(results, len(checkers))
}

// aggregateResults combines individual results into overall status.
func (a *Aggregator) aggregateResults(results <-chan checkResultWithName, count int) AggregatedResult {
	components := make([]ComponentResult, 0, count)
	overallStatus := StatusHealthy

	for r := range results {
		comp := FromCheckResult(r.name, r.result, r.critical)
		components = append(components, comp)

		// Determine overall status
		switch r.result.Status {
		case StatusUnhealthy:
			if r.critical {
				overallStatus = StatusUnhealthy
			} else if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		case StatusDegraded:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		}
	}

	// Build message based on status
	var message string
	switch overallStatus {
	case StatusHealthy:
		message = fmt.Sprintf("All %d components healthy", len(components))
	case StatusDegraded:
		message = "Some components degraded"
	case StatusUnhealthy:
		message = "Critical component unhealthy"
	}

	return AggregatedResult{
		Status:     overallStatus,
		Message:    message,
		Components: components,
	}
}

// ============================================================================
// Quick Access Methods
// ============================================================================

// IsHealthy returns true if overall health is healthy.
func (a *Aggregator) IsHealthy() bool {
	result := a.CheckWithTimeout(2 * time.Second)
	return result.Status == StatusHealthy
}

// IsReady returns true if the system is ready to serve (healthy or degraded).
func (a *Aggregator) IsReady() bool {
	result := a.CheckWithTimeout(2 * time.Second)
	return result.IsOK()
}

// GetComponentStatus returns the status of a specific component.
func (a *Aggregator) GetComponentStatus(name string) (Status, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, c := range a.checkers {
		if c.Name() == name {
			result := c.Check(context.Background())
			return result.Status, nil
		}
	}

	return StatusUnknown, ErrCheckerNotFound
}

// ============================================================================
// Global Aggregator
// ============================================================================

var (
	globalAggregator     *Aggregator
	globalAggregatorOnce sync.Once
)

// DefaultAggregator returns the global default aggregator.
func DefaultAggregator() *Aggregator {
	globalAggregatorOnce.Do(func() {
		globalAggregator = NewAggregator()
	})
	return globalAggregator
}

// SetGlobalAggregator sets the global aggregator.
func SetGlobalAggregator(a *Aggregator) {
	globalAggregator = a
}

// RegisterGlobal registers a checker with the global aggregator.
func RegisterGlobal(checker Checker) {
	DefaultAggregator().Register(checker)
}

// CheckGlobal performs a health check using the global aggregator.
func CheckGlobal() AggregatedResult {
	return DefaultAggregator().CheckWithTimeout(5 * time.Second)
}
