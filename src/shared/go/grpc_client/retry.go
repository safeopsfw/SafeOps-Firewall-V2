// Package grpc_client provides comprehensive retry logic with exponential backoff and retry budgets.
package grpc_client

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// ============================================================================
// Retry Configuration
// ============================================================================

// RetryConfig configures retry behavior with exponential backoff
type RetryConfig struct {
	MaxAttempts       int           // Maximum retry attempts (default: 3)
	InitialBackoff    time.Duration // Starting backoff delay (default: 100ms)
	MaxBackoff        time.Duration // Maximum backoff delay (default: 10s)
	BackoffMultiplier float64       // Exponential multiplier (default: 2.0)
	Jitter            float64       // Random jitter percentage (default: 0.1)
	RetryableCodes    []codes.Code  // gRPC status codes to retry
	PerTryTimeout     time.Duration // Timeout for each attempt (optional)
	RetryBudget       *RetryBudget  // Retry budget (optional, prevents retry storms)
}

// DefaultRetryConfig returns production-ready default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.1,
		RetryableCodes: []codes.Code{
			codes.Unavailable,       // Service temporarily unavailable
			codes.ResourceExhausted, // Rate limited
			codes.Aborted,           // Transaction conflict
			codes.DeadlineExceeded,  // Timeout (retry with longer deadline)
		},
		PerTryTimeout: 0, // No per-try timeout by default
		RetryBudget:   nil,
	}
}

// NewRetryConfigFromEnv creates retry configuration from environment variables
func NewRetryConfigFromEnv() RetryConfig {
	cfg := DefaultRetryConfig()

	if maxAttempts := os.Getenv("GRPC_MAX_RETRY_ATTEMPTS"); maxAttempts != "" {
		if val, err := strconv.Atoi(maxAttempts); err == nil {
			cfg.MaxAttempts = val
		}
	}

	if initialBackoff := os.Getenv("GRPC_INITIAL_BACKOFF_MS"); initialBackoff != "" {
		if val, err := strconv.Atoi(initialBackoff); err == nil {
			cfg.InitialBackoff = time.Duration(val) * time.Millisecond
		}
	}

	if maxBackoff := os.Getenv("GRPC_MAX_BACKOFF_MS"); maxBackoff != "" {
		if val, err := strconv.Atoi(maxBackoff); err == nil {
			cfg.MaxBackoff = time.Duration(val) * time.Millisecond
		}
	}

	if multiplier := os.Getenv("GRPC_BACKOFF_MULTIPLIER"); multiplier != "" {
		if val, err := strconv.ParseFloat(multiplier, 64); err == nil {
			cfg.BackoffMultiplier = val
		}
	}

	if budgetRatio := os.Getenv("GRPC_RETRY_BUDGET_RATIO"); budgetRatio != "" {
		if val, err := strconv.ParseFloat(budgetRatio, 64); err == nil {
			budgetCfg := DefaultRetryBudgetConfig()
			budgetCfg.MinRetryRatio = val
			cfg.RetryBudget = NewRetryBudget(budgetCfg)
		}
	}

	return cfg
}

// ============================================================================
// Retry Interceptor
// ============================================================================

// RetryInterceptor creates a retry interceptor with exponential backoff
func RetryInterceptor(cfg RetryConfig, logger *logging.Logger, metricsReg *metrics.MetricsRegistry) grpc.UnaryClientInterceptor {
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
			// Record request in retry budget
			if cfg.RetryBudget != nil {
				cfg.RetryBudget.RecordRequest()
			}

			// Set per-try timeout if configured
			tryCtx := ctx
			if cfg.PerTryTimeout > 0 {
				var cancel context.CancelFunc
				tryCtx, cancel = context.WithTimeout(ctx, cfg.PerTryTimeout)
				defer cancel()
			}

			// Attempt RPC
			err := invoker(tryCtx, method, req, reply, cc, opts...)
			if err == nil {
				// Success!
				if attempt > 0 && logger != nil {
					logger.Info("gRPC call succeeded after retry",
						"method", method,
						"attempts", attempt+1,
					)
				}
				return nil
			}

			lastErr = err

			// Check if error is retryable
			st, ok := status.FromError(err)
			if !ok || !retryableCodes[st.Code()] {
				// Non-retryable error
				return err
			}

			// Don't retry on last attempt
			if attempt == cfg.MaxAttempts-1 {
				break
			}

			// Check retry budget
			if cfg.RetryBudget != nil {
				if !cfg.RetryBudget.CanRetry() {
					if logger != nil {
						logger.Warn("Retry budget exceeded, not retrying",
							"method", method,
							"attempt", attempt+1,
						)
					}
					return fmt.Errorf("retry budget exceeded: %w", err)
				}
				cfg.RetryBudget.RecordRetry()
			}

			// Check context cancellation
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Calculate backoff with jitter
			jitter := float64(backoff) * cfg.Jitter * (2*rand.Float64() - 1)
			sleepTime := time.Duration(float64(backoff) + jitter)

			if logger != nil {
				logger.Warn("gRPC call failed, retrying",
					"method", method,
					"attempt", attempt+1,
					"max_attempts", cfg.MaxAttempts,
					"code", st.Code().String(),
					"backoff_ms", sleepTime.Milliseconds(),
					"error", st.Message(),
				)
			}

			if metricsReg != nil {
				metricsReg.RecordError(method, fmt.Sprintf("retry_attempt_%d", attempt+1))
			}

			// Wait with context cancellation support
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepTime):
			}

			// Increase backoff exponentially
			backoff = time.Duration(float64(backoff) * cfg.BackoffMultiplier)
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}

		if logger != nil {
			logger.Error("gRPC call failed after all retries",
				"method", method,
				"max_attempts", cfg.MaxAttempts,
				"error", lastErr.Error(),
			)
		}

		return fmt.Errorf("RPC %s failed after %d attempts: %w", method, cfg.MaxAttempts, lastErr)
	}
}

// RetryStreamInterceptor creates a retry interceptor for streaming RPCs
func RetryStreamInterceptor(cfg RetryConfig, logger *logging.Logger) grpc.StreamClientInterceptor {
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

			jitter := float64(backoff) * cfg.Jitter * (2*rand.Float64() - 1)
			sleepTime := time.Duration(float64(backoff) + jitter)

			if logger != nil {
				logger.Warn("gRPC stream failed, retrying",
					"method", method,
					"attempt", attempt+1,
					"backoff_ms", sleepTime.Milliseconds(),
				)
			}

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

		return nil, fmt.Errorf("stream %s failed after %d attempts: %w", method, cfg.MaxAttempts, lastErr)
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// ExponentialBackoff calculates exponential backoff duration
func ExponentialBackoff(attempt int, base, max time.Duration, multiplier float64) time.Duration {
	backoff := float64(base) * math.Pow(multiplier, float64(attempt))
	if backoff > float64(max) {
		return max
	}
	return time.Duration(backoff)
}

// WithJitter adds jitter to a duration
func WithJitter(d time.Duration, jitterFraction float64) time.Duration {
	jitter := float64(d) * jitterFraction * (2*rand.Float64() - 1)
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

// ============================================================================
// Hedged Requests (Optional - for read-heavy workloads)
// ============================================================================

// HedgedRequestConfig configures hedged request behavior
type HedgedRequestConfig struct {
	NumRequests     int           // Number of requests to send
	HedgingDelay    time.Duration // Delay between hedged requests
	CancelOnSuccess bool          // Cancel other requests on first success
}

// HedgedRequest sends multiple requests and returns the first successful result
// Useful for tail latency reduction in read-heavy workloads
func HedgedRequest(ctx context.Context, cfg HedgedRequestConfig, invoker func(context.Context) error) error {
	if cfg.NumRequests <= 1 {
		return invoker(ctx)
	}

	results := make(chan error, cfg.NumRequests)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // Always cancel to clean up resources

	// Launch hedged requests with staggered delays
	for i := 0; i < cfg.NumRequests; i++ {
		go func(delay time.Duration) {
			time.Sleep(delay)
			results <- invoker(ctx)
		}(time.Duration(i) * cfg.HedgingDelay)
	}

	// Return first successful result or last error
	var lastErr error
	for i := 0; i < cfg.NumRequests; i++ {
		err := <-results
		if err == nil {
			return nil // Success!
		}
		lastErr = err
	}

	return lastErr
}

// ============================================================================
// Helper: Build Retry Dial Options
// ============================================================================

// WithRetry creates dial option with retry interceptor
func WithRetry(cfg RetryConfig, logger *logging.Logger, metricsReg *metrics.MetricsRegistry) grpc.DialOption {
	return grpc.WithUnaryInterceptor(RetryInterceptor(cfg, logger, metricsReg))
}

// WithStreamRetry creates dial option with stream retry interceptor
func WithStreamRetry(cfg RetryConfig, logger *logging.Logger) grpc.DialOption {
	return grpc.WithStreamInterceptor(RetryStreamInterceptor(cfg, logger))
}
