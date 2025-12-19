// Package utils provides retry logic with exponential backoff for handling transient failures.
// This file implements configurable retry strategies with jitter to prevent thundering herd,
// context-aware cancellation, and intelligent error classification.
package utils

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

// ============================================================================
// Retry Configuration
// ============================================================================

// RetryConfig defines the configuration for retry behavior
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts (including initial attempt)
	MaxAttempts int

	// InitialDelay is the starting delay before first retry
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries (caps exponential growth)
	MaxDelay time.Duration

	// Multiplier is the exponential backoff multiplier (e.g., 2.0 for doubling)
	Multiplier float64

	// Jitter adds randomness to delay (0.0 to 1.0, e.g., 0.1 = ±10%)
	Jitter float64

	// RetryableErrors is a list of error instances to match against (deprecated, use RetryIf instead)
	RetryableErrors []error

	// RetryIf is a custom function to determine if an error is retryable
	// If nil, uses default retryable error classification
	RetryIf func(error) bool
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
		RetryIf:      nil, // Use default classification
	}
}

// ============================================================================
// Core Retry Functions
// ============================================================================

// Retry executes an operation with retry logic using exponential backoff
// Returns nil on success, or the last error after all retry attempts are exhausted
func Retry(ctx context.Context, fn func() error, cfg RetryConfig) error {
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		// Check context before attempting
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("retry cancelled before attempt %d: %w", attempt, err)
		}

		// Execute the operation
		err := fn()
		if err == nil {
			// Success!
			return nil
		}

		lastErr = err

		// Check if we should retry this error
		if !shouldRetry(err, cfg) {
			return fmt.Errorf("non-retryable error on attempt %d/%d: %w", attempt, cfg.MaxAttempts, err)
		}

		// If this was the last attempt, don't wait
		if attempt >= cfg.MaxAttempts {
			break
		}

		// Calculate backoff delay
		delay := calculateBackoff(attempt, cfg)

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled after %d attempts: %w", attempt, ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("retry exhausted after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// RetryWithResult executes an operation that returns a value with retry logic
// Returns the result and nil on success, or zero value and error after all attempts
func RetryWithResult[T any](ctx context.Context, fn func() (T, error), cfg RetryConfig) (T, error) {
	var result T
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		// Check context before attempting
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("retry cancelled before attempt %d: %w", attempt, err)
		}

		// Execute the operation
		res, err := fn()
		if err == nil {
			// Success!
			return res, nil
		}

		lastErr = err

		// Check if we should retry this error
		if !shouldRetry(err, cfg) {
			return result, fmt.Errorf("non-retryable error on attempt %d/%d: %w", attempt, cfg.MaxAttempts, err)
		}

		// If this was the last attempt, don't wait
		if attempt >= cfg.MaxAttempts {
			break
		}

		// Calculate backoff delay
		delay := calculateBackoff(attempt, cfg)

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return result, fmt.Errorf("retry cancelled after %d attempts: %w", attempt, ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return result, fmt.Errorf("retry exhausted after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// ============================================================================
// Exponential Backoff Calculator
// ============================================================================

// calculateBackoff calculates the delay duration with exponential backoff and jitter
// Formula: min(InitialDelay * (Multiplier ^ (attempt-1)), MaxDelay) * (1 + random(-Jitter, +Jitter))
func calculateBackoff(attempt int, config RetryConfig) time.Duration {
	// Calculate base delay with exponential backoff (attempt-1 because first retry is attempt 2)
	exponentialDelay := float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt-1))

	// Cap at max delay
	delay := math.Min(exponentialDelay, float64(config.MaxDelay))

	// Apply jitter if configured
	if config.Jitter > 0 {
		// Generate random jitter between -Jitter and +Jitter
		jitterRange := delay * config.Jitter
		jitterValue := (rand.Float64()*2 - 1) * jitterRange // Random value in [-jitterRange, +jitterRange]
		delay = delay + jitterValue

		// Ensure delay is not negative
		if delay < 0 {
			delay = 0
		}
	}

	return time.Duration(delay)
}

// CalculateBackoff is the exported version for testing/external use
func CalculateBackoff(attempt int, cfg RetryConfig) time.Duration {
	return calculateBackoff(attempt, cfg)
}

// Backoff calculates exponential backoff delay (legacy function)
func Backoff(attempt int, baseDelay, maxDelay time.Duration, multiplier float64) time.Duration {
	delay := float64(baseDelay) * math.Pow(multiplier, float64(attempt))
	if delay > float64(maxDelay) {
		delay = float64(maxDelay)
	}
	return time.Duration(delay)
}

// BackoffWithJitter adds jitter to backoff (legacy function)
func BackoffWithJitter(attempt int, baseDelay, maxDelay time.Duration, multiplier, jitter float64) time.Duration {
	delay := Backoff(attempt, baseDelay, maxDelay, multiplier)
	jitterAmount := float64(delay) * jitter * (rand.Float64()*2 - 1)
	return time.Duration(float64(delay) + jitterAmount)
}

// ============================================================================
// Retryable Error Classification
// ============================================================================

// shouldRetry determines if an error should trigger a retry attempt
func shouldRetry(err error, cfg RetryConfig) bool {
	if err == nil {
		return false
	}

	// Use custom classifier if provided
	if cfg.RetryIf != nil {
		return cfg.RetryIf(err)
	}

	// Check RetryableErrors list (deprecated but supported)
	for _, retryableErr := range cfg.RetryableErrors {
		if errors.Is(err, retryableErr) {
			return true
		}
	}

	// Default retryable error classification
	return isDefaultRetryable(err)
}

// isDefaultRetryable implements default retryable error detection
func isDefaultRetryable(err error) bool {
	// Context deadline exceeded is retryable
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Temporary errors (network errors that implement Temporary() bool)
	type temporary interface {
		Temporary() bool
	}
	if te, ok := err.(temporary); ok && te.Temporary() {
		return true
	}

	// Check error message for common retryable patterns
	errMsg := strings.ToLower(err.Error())

	// Network-related errors
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"timeout",
		"temporary failure",
		"too many requests",
		"rate limit",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"deadline exceeded",
		"unavailable",
		"resource exhausted",
		"i/o timeout",
		"network unreachable",
		"no route to host",
		"broken pipe",
		"eof",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// IsRetryableHTTPStatus checks if an HTTP status code is retryable
func IsRetryableHTTPStatus(statusCode int) bool {
	switch statusCode {
	case 408: // Request Timeout
		return true
	case 429: // Too Many Requests
		return true
	case 500: // Internal Server Error
		return true
	case 502: // Bad Gateway
		return true
	case 503: // Service Unavailable
		return true
	case 504: // Gateway Timeout
		return true
	default:
		return false
	}
}

// IsNonRetryableHTTPStatus checks if an HTTP status code should NOT be retried
func IsNonRetryableHTTPStatus(statusCode int) bool {
	switch statusCode {
	case 400: // Bad Request
		return true
	case 401: // Unauthorized
		return true
	case 403: // Forbidden
		return true
	case 404: // Not Found
		return true
	case 405: // Method Not Allowed
		return true
	case 409: // Conflict
		return true
	case 410: // Gone
		return true
	case 422: // Unprocessable Entity
		return true
	default:
		return false
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// SimpleRetry retries with default config
func SimpleRetry(ctx context.Context, fn func() error) error {
	return Retry(ctx, fn, DefaultRetryConfig())
}

// RetryN retries up to n times
func RetryN(ctx context.Context, n int, fn func() error) error {
	cfg := DefaultRetryConfig()
	cfg.MaxAttempts = n
	return Retry(ctx, fn, cfg)
}

// WithMaxAttempts creates a new config with modified MaxAttempts
func (c RetryConfig) WithMaxAttempts(attempts int) RetryConfig {
	c.MaxAttempts = attempts
	return c
}

// WithInitialDelay creates a new config with modified InitialDelay
func (c RetryConfig) WithInitialDelay(delay time.Duration) RetryConfig {
	c.InitialDelay = delay
	return c
}

// WithMaxDelay creates a new config with modified MaxDelay
func (c RetryConfig) WithMaxDelay(delay time.Duration) RetryConfig {
	c.MaxDelay = delay
	return c
}

// WithMultiplier creates a new config with modified Multiplier
func (c RetryConfig) WithMultiplier(multiplier float64) RetryConfig {
	c.Multiplier = multiplier
	return c
}

// WithJitter creates a new config with modified Jitter
func (c RetryConfig) WithJitter(jitter float64) RetryConfig {
	c.Jitter = jitter
	return c
}

// WithCustomRetryable creates a new config with custom retryable function
func (c RetryConfig) WithCustomRetryable(fn func(error) bool) RetryConfig {
	c.RetryIf = fn
	return c
}
