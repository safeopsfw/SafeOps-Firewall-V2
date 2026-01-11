// Package grpc_client provides retry budget management.
package grpc_client

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RetryBudget manages retry budget to prevent retry storms
type RetryBudget struct {
	// Configuration
	minRetryRatio float64
	budgetPercent float64

	// State
	mu             sync.RWMutex
	requests       int64
	retries        int64
	windowStart    time.Time
	windowDuration time.Duration
}

// RetryBudgetConfig configures the retry budget
type RetryBudgetConfig struct {
	// MinRetryRatio is minimum requests/retries ratio (e.g., 0.1 = 10% retries allowed)
	MinRetryRatio float64

	// BudgetPercent is percentage of budget to use for retries (0.0-1.0)
	BudgetPercent float64

	// WindowDuration is the time window for budget calculation
	WindowDuration time.Duration
}

// DefaultRetryBudgetConfig returns default retry budget configuration
func DefaultRetryBudgetConfig() RetryBudgetConfig {
	return RetryBudgetConfig{
		MinRetryRatio:  0.1, // Allow 10% retry rate
		BudgetPercent:  0.8, // Use 80% of calculated budget
		WindowDuration: 10 * time.Second,
	}
}

// NewRetryBudget creates a new retry budget manager
func NewRetryBudget(cfg RetryBudgetConfig) *RetryBudget {
	if cfg.MinRetryRatio <= 0 {
		cfg.MinRetryRatio = 0.1
	}
	if cfg.BudgetPercent <= 0 || cfg.BudgetPercent > 1.0 {
		cfg.BudgetPercent = 0.8
	}
	if cfg.WindowDuration == 0 {
		cfg.WindowDuration = 10 * time.Second
	}

	rb := &RetryBudget{
		minRetryRatio:  cfg.MinRetryRatio,
		budgetPercent:  cfg.BudgetPercent,
		windowDuration: cfg.WindowDuration,
		windowStart:    time.Now(),
	}

	// Start window rotation
	go rb.rotateWindow()

	return rb
}

// CanRetry checks if retry is allowed within budget
func (rb *RetryBudget) CanRetry() bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	requests := atomic.LoadInt64(&rb.requests)
	retries := atomic.LoadInt64(&rb.retries)

	if requests == 0 {
		return true // Always allow first request
	}

	// Calculate available retry budget
	budget := float64(requests) * rb.minRetryRatio * rb.budgetPercent

	return float64(retries) < budget
}

// RecordRequest records a request attempt
func (rb *RetryBudget) RecordRequest() {
	atomic.AddInt64(&rb.requests, 1)
}

// RecordRetry records a retry attempt
func (rb *RetryBudget) RecordRetry() {
	atomic.AddInt64(&rb.retries, 1)
}

// rotateWindow resets counters periodically
func (rb *RetryBudget) rotateWindow() {
	ticker := time.NewTicker(rb.windowDuration)
	defer ticker.Stop()

	for range ticker.C {
		rb.mu.Lock()
		atomic.StoreInt64(&rb.requests, 0)
		atomic.StoreInt64(&rb.retries, 0)
		rb.windowStart = time.Now()
		rb.mu.Unlock()
	}
}

// Stats returns retry budget statistics
func (rb *RetryBudget) Stats() RetryBudgetStats {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	requests := atomic.LoadInt64(&rb.requests)
	retries := atomic.LoadInt64(&rb.retries)

	retryRate := 0.0
	if requests > 0 {
		retryRate = float64(retries) / float64(requests)
	}

	budget := float64(requests) * rb.minRetryRatio * rb.budgetPercent
	budgetUsed := 0.0
	if budget > 0 {
		budgetUsed = float64(retries) / budget
	}

	return RetryBudgetStats{
		Requests:    requests,
		Retries:     retries,
		RetryRate:   retryRate,
		BudgetUsed:  budgetUsed,
		WindowStart: rb.windowStart,
	}
}

// RetryBudgetStats holds retry budget statistics
type RetryBudgetStats struct {
	Requests    int64
	Retries     int64
	RetryRate   float64
	BudgetUsed  float64
	WindowStart time.Time
}

// RetryBudgetInterceptor creates an interceptor with retry budget
func RetryBudgetInterceptor(budget *RetryBudget, retryFn func(error) bool) func(RetryConfig) grpc.UnaryClientInterceptor {
	return func(cfg RetryConfig) grpc.UnaryClientInterceptor {
		retryableCodes := make(map[codes.Code]bool)
		for _, code := range cfg.RetryableCodes {
			retryableCodes[code] = true
		}

		return func(
			ctx context.Context,
			method string,
			req, reply interface{},
			cc *grpc.ClientConn,
			invoker grpc.UnaryInvoker,
			opts ...grpc.CallOption,
		) error {
			budget.RecordRequest()

			var lastErr error
			backoff := cfg.InitialBackoff

			for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
				err := invoker(ctx, method, req, reply, cc, opts...)
				if err == nil {
					return nil
				}

				lastErr = err

				// Check if error is retryable
				st, ok := status.FromError(err)
				if !ok || !retryableCodes[st.Code()] {
					return err
				}

				// Don't retry on last attempt
				if attempt == cfg.MaxAttempts-1 {
					break
				}

				// Check retry budget
				if !budget.CanRetry() {
					return lastErr // Budget exhausted
				}

				budget.RecordRetry()

				// Check context
				if ctx.Err() != nil {
					return ctx.Err()
				}

				// Calculate backoff with jitter
				jitter := float64(backoff) * cfg.Jitter * (rand.Float64()*2 - 1)
				sleepTime := time.Duration(float64(backoff) + jitter)

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(sleepTime):
				}

				// Increase backoff
				backoff = time.Duration(float64(backoff) * cfg.BackoffMultiplier)
				if backoff > cfg.MaxBackoff {
					backoff = cfg.MaxBackoff
				}
			}

			return lastErr
		}
	}
}
