// Package utils provides retry utilities.
package utils

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts     int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	Multiplier      float64
	Jitter          float64
	RetryableErrors []error
	RetryIf         func(error) bool
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
	}
}

// Retry retries a function with exponential backoff
func Retry(ctx context.Context, fn func() error, cfg RetryConfig) error {
	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err

			// Check if error is retryable
			if cfg.RetryIf != nil && !cfg.RetryIf(err) {
				return err
			}
		}

		// Don't sleep after last attempt
		if attempt == cfg.MaxAttempts-1 {
			break
		}

		// Calculate delay with jitter
		jitter := delay.Seconds() * cfg.Jitter * (rand.Float64()*2 - 1)
		sleepTime := time.Duration((delay.Seconds() + jitter) * float64(time.Second))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepTime):
		}

		// Increase delay for next attempt
		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}

	return lastErr
}

// RetryWithResult retries a function that returns a value
func RetryWithResult[T any](ctx context.Context, fn func() (T, error), cfg RetryConfig) (T, error) {
	var result T
	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		if res, err := fn(); err == nil {
			return res, nil
		} else {
			lastErr = err

			if cfg.RetryIf != nil && !cfg.RetryIf(err) {
				return result, err
			}
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		jitter := delay.Seconds() * cfg.Jitter * (rand.Float64()*2 - 1)
		sleepTime := time.Duration((delay.Seconds() + jitter) * float64(time.Second))

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(sleepTime):
		}

		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}

	return result, lastErr
}

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

// Backoff calculates exponential backoff delay
func Backoff(attempt int, baseDelay, maxDelay time.Duration, multiplier float64) time.Duration {
	delay := float64(baseDelay) * math.Pow(multiplier, float64(attempt))
	if delay > float64(maxDelay) {
		delay = float64(maxDelay)
	}
	return time.Duration(delay)
}

// BackoffWithJitter adds jitter to backoff
func BackoffWithJitter(attempt int, baseDelay, maxDelay time.Duration, multiplier, jitter float64) time.Duration {
	delay := Backoff(attempt, baseDelay, maxDelay, multiplier)
	jitterAmount := float64(delay) * jitter * (rand.Float64()*2 - 1)
	return time.Duration(float64(delay) + jitterAmount)
}
