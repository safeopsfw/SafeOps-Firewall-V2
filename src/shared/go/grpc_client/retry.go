// Package grpc_client provides retry utilities.
package grpc_client

import (
	"context"
	"math"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts       int
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64
	Jitter            float64
	RetryableCodes    []codes.Code
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
		RetryableCodes: []codes.Code{
			codes.Unavailable,
			codes.ResourceExhausted,
			codes.Aborted,
			codes.DeadlineExceeded,
		},
	}
}

// RetryInterceptor creates a retry interceptor
func RetryInterceptor(cfg RetryConfig) grpc.UnaryClientInterceptor {
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

// RetryStreamInterceptor creates a retry interceptor for streams
func RetryStreamInterceptor(cfg RetryConfig) grpc.StreamClientInterceptor {
	retryableCodes := make(map[codes.Code]bool)
	for _, code := range cfg.RetryableCodes {
		retryableCodes[code] = true
	}

	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		var lastErr error
		backoff := cfg.InitialBackoff

		for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
			stream, err := streamer(ctx, desc, cc, method, opts...)
			if err == nil {
				return stream, nil
			}

			lastErr = err

			st, ok := status.FromError(err)
			if !ok || !retryableCodes[st.Code()] {
				return nil, err
			}

			if attempt == cfg.MaxAttempts-1 {
				break
			}

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			jitter := float64(backoff) * cfg.Jitter * (rand.Float64()*2 - 1)
			sleepTime := time.Duration(float64(backoff) + jitter)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sleepTime):
			}

			backoff = time.Duration(float64(backoff) * cfg.BackoffMultiplier)
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}

		return nil, lastErr
	}
}

// ExponentialBackoff calculates exponential backoff
func ExponentialBackoff(attempt int, base, max time.Duration, multiplier float64) time.Duration {
	backoff := float64(base) * math.Pow(multiplier, float64(attempt))
	if backoff > float64(max) {
		return max
	}
	return time.Duration(backoff)
}

// WithJitter adds jitter to a duration
func WithJitter(d time.Duration, jitterFraction float64) time.Duration {
	jitter := float64(d) * jitterFraction * (rand.Float64()*2 - 1)
	return time.Duration(float64(d) + jitter)
}

// IsRetryable checks if an error code is retryable
func IsRetryable(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.ResourceExhausted, codes.Aborted, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

// WaitForReady returns call option to wait for connection
func WaitForReady() grpc.CallOption {
	return grpc.WaitForReady(true)
}

// WithRetry creates dial options with retry interceptor
func WithRetry(cfg RetryConfig) grpc.DialOption {
	return grpc.WithUnaryInterceptor(RetryInterceptor(cfg))
}

// WithStreamRetry creates dial options with stream retry interceptor
func WithStreamRetry(cfg RetryConfig) grpc.DialOption {
	return grpc.WithStreamInterceptor(RetryStreamInterceptor(cfg))
}
