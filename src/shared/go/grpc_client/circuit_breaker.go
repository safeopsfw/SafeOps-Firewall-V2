// Package grpc_client provides circuit breaker functionality.
package grpc_client

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CircuitState represents the circuit breaker state
type CircuitState int

const (
	// StateClosed allows requests through
	StateClosed CircuitState = iota
	// StateOpen blocks requests
	StateOpen
	// StateHalfOpen allows limited requests for testing
	StateHalfOpen
)

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	maxFailures  uint32
	resetTimeout time.Duration
	halfOpenMax  uint32

	mu            sync.RWMutex
	state         CircuitState
	failures      uint32
	successes     uint32
	lastFailTime  time.Time
	nextRetryTime time.Time
}

// CircuitBreakerConfig configures the circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures before opening circuit
	MaxFailures uint32
	// ResetTimeout before trying half-open
	ResetTimeout time.Duration
	// HalfOpenMaxRequests allowed in half-open state
	HalfOpenMaxRequests uint32
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:         5,
		ResetTimeout:        60 * time.Second,
		HalfOpenMaxRequests: 3,
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.ResetTimeout == 0 {
		cfg.ResetTimeout = 60 * time.Second
	}
	if cfg.HalfOpenMaxRequests == 0 {
		cfg.HalfOpenMaxRequests = 3
	}

	return &CircuitBreaker{
		maxFailures:  cfg.MaxFailures,
		resetTimeout: cfg.ResetTimeout,
		halfOpenMax:  cfg.HalfOpenMaxRequests,
		state:        StateClosed,
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	// Check if we can proceed
	if err := cb.beforeCall(); err != nil {
		return err
	}

	// Execute the function
	err := fn()

	// Record result
	cb.afterCall(err)

	return err
}

// beforeCall checks if request should proceed
func (cb *CircuitBreaker) beforeCall() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		// Check if we should try half-open
		if now.After(cb.nextRetryTime) {
			cb.state = StateHalfOpen
			cb.successes = 0
			return nil
		}
		return errors.New("circuit breaker is open")

	case StateHalfOpen:
		// Allow limited requests
		if cb.successes < cb.halfOpenMax {
			return nil
		}
		return errors.New("circuit breaker is half-open (max requests reached)")

	default:
		return nil
	}
}

// afterCall records the call result
func (cb *CircuitBreaker) afterCall(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		cb.onSuccess()
	} else {
		cb.onFailure()
	}
}

// onSuccess handles successful call
func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case StateClosed:
		cb.failures = 0

	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.halfOpenMax {
			// Recovered, close the circuit
			cb.state = StateClosed
			cb.failures = 0
			cb.successes = 0
		}
	}
}

// onFailure handles failed call
func (cb *CircuitBreaker) onFailure() {
	cb.lastFailTime = time.Now()

	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.maxFailures {
			cb.state = StateOpen
			cb.nextRetryTime = time.Now().Add(cb.resetTimeout)
		}

	case StateHalfOpen:
		// Failed in half-open, go back to open
		cb.state = StateOpen
		cb.nextRetryTime = time.Now().Add(cb.resetTimeout)
		cb.successes = 0
	}
}

// State returns current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		State:        cb.state,
		Failures:     cb.failures,
		Successes:    cb.successes,
		LastFailTime: cb.lastFailTime,
	}
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	State        CircuitState
	Failures     uint32
	Successes    uint32
	LastFailTime time.Time
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
}

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

// IsRetryableError checks if error should count towards circuit breaker
func IsRetryableError(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}
