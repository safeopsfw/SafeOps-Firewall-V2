// Package grpc_client provides comprehensive circuit breaker functionality to prevent cascading failures.
package grpc_client

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safeops/shared/go/errors"
	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// ============================================================================
// Circuit States
// ============================================================================

// CircuitState represents the circuit breaker state
type CircuitState int

const (
	// StateClosed - Normal operation, requests pass through
	StateClosed CircuitState = iota
	// StateOpen - Service unhealthy, fail fast without calling
	StateOpen
	// StateHalfOpen - Testing if service recovered
	StateHalfOpen
)

// String returns the state name
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "Closed"
	case StateOpen:
		return "Open"
	case StateHalfOpen:
		return "HalfOpen"
	default:
		return "Unknown"
	}
}

// ============================================================================
// Circuit Breaker Configuration
// ============================================================================

// CircuitBreakerConfig configures circuit breaker behavior
type CircuitBreakerConfig struct {
	MaxRequests      uint32                      // Max requests allowed in half-open state (default: 1)
	Interval         time.Duration               // Time window for counting failures (default: 60s)
	Timeout          time.Duration               // How long circuit stays open (default: 60s)
	FailureThreshold uint32                      // Consecutive failures to open circuit (default: 5)
	SuccessThreshold uint32                      // Successes in half-open to close circuit (default: 2)
	OnStateChange    func(from, to CircuitState) // Callback when state changes
	IsFailure        func(error) bool            // Custom failure classification
}

// DefaultCircuitBreakerConfig returns production-ready default configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxRequests:      1,
		Interval:         60 * time.Second,
		Timeout:          60 * time.Second,
		FailureThreshold: 5,
		SuccessThreshold: 2,
		IsFailure:        defaultIsFailure,
	}
}

// NewConfigFromEnv creates circuit breaker configuration from environment variables
func NewCircuitBreakerConfigFromEnv() CircuitBreakerConfig {
	cfg := DefaultCircuitBreakerConfig()

	if threshold := os.Getenv("GRPC_CB_FAILURE_THRESHOLD"); threshold != "" {
		if val, err := strconv.ParseUint(threshold, 10, 32); err == nil {
			cfg.FailureThreshold = uint32(val)
		}
	}

	if threshold := os.Getenv("GRPC_CB_SUCCESS_THRESHOLD"); threshold != "" {
		if val, err := strconv.ParseUint(threshold, 10, 32); err == nil {
			cfg.SuccessThreshold = uint32(val)
		}
	}

	if timeout := os.Getenv("GRPC_CB_TIMEOUT"); timeout != "" {
		if val, err := strconv.Atoi(timeout); err == nil {
			cfg.Timeout = time.Duration(val) * time.Second
		}
	}

	if interval := os.Getenv("GRPC_CB_INTERVAL"); interval != "" {
		if val, err := strconv.Atoi(interval); err == nil {
			cfg.Interval = time.Duration(val) * time.Second
		}
	}

	return cfg
}

// ============================================================================
// Circuit Breaker Implementation
// ============================================================================

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config CircuitBreakerConfig
	logger *logging.Logger
	mu     sync.Mutex

	state            CircuitState
	counts           Counts
	expiry           time.Time // When to transition from Open to Half-Open
	stateChangeCount uint64    // Total state changes
}

// Counts tracks request statistics
type Counts struct {
	Requests             uint64
	TotalSuccesses       uint64
	TotalFailures        uint64
	ConsecutiveSuccesses uint64
	ConsecutiveFailures  uint64
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig, logger *logging.Logger) *CircuitBreaker {
	// Apply defaults
	if config.MaxRequests == 0 {
		config.MaxRequests = 1
	}
	if config.Interval == 0 {
		config.Interval = 60 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.IsFailure == nil {
		config.IsFailure = defaultIsFailure
	}

	return &CircuitBreaker{
		config: config,
		logger: logger,
		state:  StateClosed,
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	// Check current state and get permission to proceed
	generation, err := cb.beforeCall()
	if err != nil {
		return err
	}

	// Execute the function
	err = fn()

	// Record result
	cb.afterCall(generation, err)

	return err
}

// beforeCall checks if request should proceed
func (cb *CircuitBreaker) beforeCall() (uint64, error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	state := cb.currentState(now)

	if state == StateOpen {
		return 0, errors.New("CIRCUIT_BREAKER_OPEN", "circuit breaker is open")
	}

	if state == StateHalfOpen && cb.counts.Requests >= uint64(cb.config.MaxRequests) {
		return 0, errors.New("CIRCUIT_BREAKER_HALF_OPEN_MAX", "circuit breaker half-open max requests reached")
	}

	cb.counts.Requests++
	return cb.stateChangeCount, nil
}

// afterCall records the call result
func (cb *CircuitBreaker) afterCall(generation uint64, err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Ignore if state changed between beforeCall and afterCall
	if generation != cb.stateChangeCount {
		return
	}

	isFailure := cb.config.IsFailure(err)

	if !isFailure {
		cb.onSuccess()
	} else {
		cb.onFailure()
	}
}

// onSuccess handles successful call
func (cb *CircuitBreaker) onSuccess() {
	cb.counts.TotalSuccesses++
	cb.counts.ConsecutiveSuccesses++
	cb.counts.ConsecutiveFailures = 0

	if cb.state == StateHalfOpen && cb.counts.ConsecutiveSuccesses >= uint64(cb.config.SuccessThreshold) {
		cb.setState(StateClosed)
	}
}

// onFailure handles failed call
func (cb *CircuitBreaker) onFailure() {
	cb.counts.TotalFailures++
	cb.counts.ConsecutiveFailures++
	cb.counts.ConsecutiveSuccesses = 0

	if cb.state == StateClosed && cb.counts.ConsecutiveFailures >= uint64(cb.config.FailureThreshold) {
		cb.setState(StateOpen)
	} else if cb.state == StateHalfOpen {
		cb.setState(StateOpen)
	}
}

// currentState returns the current state, transitioning to Half-Open if timeout expired
func (cb *CircuitBreaker) currentState(now time.Time) CircuitState {
	if cb.state == StateOpen && cb.expiry.Before(now) {
		cb.setState(StateHalfOpen)
	}
	return cb.state
}

// setState transitions to a new state
func (cb *CircuitBreaker) setState(newState CircuitState) {
	if cb.state == newState {
		return
	}

	prevState := cb.state
	cb.state = newState
	cb.stateChangeCount++
	cb.counts = Counts{} // Reset counts

	if newState == StateOpen {
		cb.expiry = time.Now().Add(cb.config.Timeout)
	}

	// Log state change
	if cb.logger != nil {
		cb.logger.Warn("Circuit breaker state changed",
			"from", prevState.String(),
			"to", newState.String(),
			"change_count", cb.stateChangeCount,
		)
	}

	// Trigger callback
	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(prevState, newState)
	}
}

// State returns current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentState(time.Now())
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return CircuitBreakerStats{
		State:                cb.state,
		Requests:             cb.counts.Requests,
		TotalSuccesses:       cb.counts.TotalSuccesses,
		TotalFailures:        cb.counts.TotalFailures,
		ConsecutiveSuccesses: cb.counts.ConsecutiveSuccesses,
		ConsecutiveFailures:  cb.counts.ConsecutiveFailures,
		StateChangeCount:     cb.stateChangeCount,
	}
}

// CircuitBreakerStats holds statistics
type CircuitBreakerStats struct {
	State                CircuitState
	Requests             uint64
	TotalSuccesses       uint64
	TotalFailures        uint64
	ConsecutiveSuccesses uint64
	ConsecutiveFailures  uint64
	StateChangeCount     uint64
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(StateClosed)
	cb.counts = Counts{}
}

// ============================================================================
// Failure Classification
// ============================================================================

// defaultIsFailure determines what counts as a failure
func defaultIsFailure(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		return true // Non-gRPC errors count as failures
	}

	code := st.Code()

	// Treat as failures (server errors)
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Aborted, codes.Internal, codes.Unknown, codes.DataLoss:
		return true
	}

	// Don't treat as failures (client errors)
	switch code {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
		codes.OutOfRange, codes.Unimplemented, codes.Canceled:
		return false
	}

	return true
}

// ============================================================================
// gRPC Interceptor
// ============================================================================

// CircuitBreakerInterceptor creates a circuit breaker interceptor
func CircuitBreakerInterceptor(cb *CircuitBreaker) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		return cb.Call(func() error {
			return invoker(ctx, method, req, reply, cc, opts...)
		})
	}
}

// ============================================================================
// Per-Method Circuit Breakers
// ============================================================================

// MethodCircuitBreakers manages circuit breakers per RPC method
type MethodCircuitBreakers struct {
	config   CircuitBreakerConfig
	logger   *logging.Logger
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// NewMethodCircuitBreakers creates per-method circuit breakers
func NewMethodCircuitBreakers(config CircuitBreakerConfig, logger *logging.Logger) *MethodCircuitBreakers {
	return &MethodCircuitBreakers{
		config:   config,
		logger:   logger,
		breakers: make(map[string]*CircuitBreaker),
	}
}

// Get returns circuit breaker for a method (creates if not exists)
func (m *MethodCircuitBreakers) Get(method string) *CircuitBreaker {
	m.mu.RLock()
	cb, exists := m.breakers[method]
	m.mu.RUnlock()

	if exists {
		return cb
	}

	// Create new circuit breaker for this method
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	cb, exists = m.breakers[method]
	if exists {
		return cb
	}

	cb = NewCircuitBreaker(m.config, m.logger)
	m.breakers[method] = cb
	return cb
}

// MethodCircuitBreakerInterceptor creates interceptor with per-method breakers
func MethodCircuitBreakerInterceptor(mcb *MethodCircuitBreakers) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		cb := mcb.Get(method)
		return cb.Call(func() error {
			return invoker(ctx, method, req, reply, cc, opts...)
		})
	}
}

// AllStats returns stats for all method circuit breakers
func (m *MethodCircuitBreakers) AllStats() map[string]CircuitBreakerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats, len(m.breakers))
	for method, cb := range m.breakers {
		stats[method] = cb.Stats()
	}
	return stats
}

// ============================================================================
// Metrics Integration
// ============================================================================

// RecordMetrics records circuit breaker metrics
func (cb *CircuitBreaker) RecordMetrics(metricsReg *metrics.MetricsRegistry, serviceName string) {
	stats := cb.Stats()

	if metricsReg != nil {
		// Record state as gauge (0=closed, 1=half-open, 2=open)
		metricsReg.RecordRequest(serviceName, "circuit_state", 0, fmt.Sprintf("%d", stats.State))

		// Record counts
		metricsReg.RecordRequest(serviceName, "circuit_failures", 0, fmt.Sprintf("%d", stats.ConsecutiveFailures))
		metricsReg.RecordRequest(serviceName, "circuit_successes", 0, fmt.Sprintf("%d", stats.ConsecutiveSuccesses))
		metricsReg.RecordRequest(serviceName, "circuit_state_changes", 0, fmt.Sprintf("%d", stats.StateChangeCount))
	}
}
