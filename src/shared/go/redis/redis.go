// Package redis provides Redis connection pool and utilities.
package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// Config holds Redis configuration
type Config struct {
	Addresses    []string
	Password     string
	Database     int
	PoolSize     int
	MinIdleConn  int
	MaxRetries   int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxIdleTime  time.Duration
	MaxConnAge   time.Duration

	// TLS Configuration
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	TLSInsecureSkipVerify bool
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Addresses:    []string{"localhost:6379"},
		Database:     0,
		PoolSize:     10,
		MinIdleConn:  2,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
}

// Client wraps redis.Client with additional functionality
type Client struct {
	*redis.Client
	cfg     Config
	metrics *metrics.MetricsRegistry
	logger  *logging.Logger
}

// NewClient creates a Redis client
func NewClient(cfg Config) (*Client, error) {
	tlsConfig, err := LoadTLSConfig(TLSConfig{
		Enabled:            cfg.TLSEnabled,
		CertFile:           cfg.TLSCertFile,
		KeyFile:            cfg.TLSKeyFile,
		CAFile:             cfg.TLSCAFile,
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	opts := &redis.Options{
		Addr:         cfg.Addresses[0],
		Password:     cfg.Password,
		DB:           cfg.Database,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConn,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		MaxConnAge:   cfg.MaxConnAge,
		IdleTimeout:  cfg.MaxIdleTime,
		TLSConfig:    tlsConfig,
	}

	client := redis.NewClient(opts)

	return &Client{
		Client: client,
		cfg:    cfg,
	}, nil
}

// NewClusterClient creates a Redis cluster client
func NewClusterClient(cfg Config) *redis.ClusterClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:        cfg.Addresses,
		Password:     cfg.Password,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConn,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})
}

// Ping checks connection
func (c *Client) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}

// IsConnected returns true if connected
func (c *Client) IsConnected(ctx context.Context) bool {
	return c.Ping(ctx) == nil
}

// SetWithTTL sets a key with TTL
func (c *Client) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return c.Client.Set(ctx, key, value, ttl).Err()
}

// GetString gets a string value
func (c *Client) GetString(ctx context.Context, key string) (string, error) {
	return c.Client.Get(ctx, key).Result()
}

// GetBytes gets a byte slice value
func (c *Client) GetBytes(ctx context.Context, key string) ([]byte, error) {
	return c.Client.Get(ctx, key).Bytes()
}

// Exists checks if keys exist
func (c *Client) Exists(ctx context.Context, keys ...string) (bool, error) {
	n, err := c.Client.Exists(ctx, keys...).Result()
	return n > 0, err
}

// Delete deletes keys
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	return c.Client.Del(ctx, keys...).Err()
}

// Incr increments a key
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.Client.Incr(ctx, key).Result()
}

// IncrBy increments a key by value
func (c *Client) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.Client.IncrBy(ctx, key, value).Result()
}

// Decr decrements a key
func (c *Client) Decr(ctx context.Context, key string) (int64, error) {
	return c.Client.Decr(ctx, key).Result()
}

// SetNX sets a key only if it doesn't exist
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	return c.Client.SetNX(ctx, key, value, ttl).Result()
}

// Expire sets TTL on a key
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.Client.Expire(ctx, key, ttl).Err()
}

// TTL gets remaining TTL
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.Client.TTL(ctx, key).Result()
}

// Hash operations

// HSet sets hash fields
func (c *Client) HSet(ctx context.Context, key string, values ...interface{}) error {
	return c.Client.HSet(ctx, key, values...).Err()
}

// HGet gets a hash field
func (c *Client) HGet(ctx context.Context, key, field string) (string, error) {
	return c.Client.HGet(ctx, key, field).Result()
}

// HGetAll gets all hash fields
func (c *Client) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.Client.HGetAll(ctx, key).Result()
}

// HDel deletes hash fields
func (c *Client) HDel(ctx context.Context, key string, fields ...string) error {
	return c.Client.HDel(ctx, key, fields...).Err()
}

// List operations

// LPush pushes to list left
func (c *Client) LPush(ctx context.Context, key string, values ...interface{}) error {
	return c.Client.LPush(ctx, key, values...).Err()
}

// RPush pushes to list right
func (c *Client) RPush(ctx context.Context, key string, values ...interface{}) error {
	return c.Client.RPush(ctx, key, values...).Err()
}

// LPop pops from list left
func (c *Client) LPop(ctx context.Context, key string) (string, error) {
	return c.Client.LPop(ctx, key).Result()
}

// RPop pops from list right
func (c *Client) RPop(ctx context.Context, key string) (string, error) {
	return c.Client.RPop(ctx, key).Result()
}

// LRange gets list range
func (c *Client) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return c.Client.LRange(ctx, key, start, stop).Result()
}

// LLen gets list length
func (c *Client) LLen(ctx context.Context, key string) (int64, error) {
	return c.Client.LLen(ctx, key).Result()
}

// Set operations

// SAdd adds to set
func (c *Client) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return c.Client.SAdd(ctx, key, members...).Err()
}

// SMembers gets set members
func (c *Client) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.Client.SMembers(ctx, key).Result()
}

// SIsMember checks set membership
func (c *Client) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	return c.Client.SIsMember(ctx, key, member).Result()
}

// SRem removes from set
func (c *Client) SRem(ctx context.Context, key string, members ...interface{}) error {
	return c.Client.SRem(ctx, key, members...).Err()
}

// Sorted set operations

// ZAdd adds to sorted set
func (c *Client) ZAdd(ctx context.Context, key string, members ...*redis.Z) error {
	return c.Client.ZAdd(ctx, key, members...).Err()
}

// ZRange gets sorted set range
func (c *Client) ZRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return c.Client.ZRange(ctx, key, start, stop).Result()
}

// ZScore gets member score
func (c *Client) ZScore(ctx context.Context, key, member string) (float64, error) {
	return c.Client.ZScore(ctx, key, member).Result()
}

// Stats returns pool stats
func (c *Client) Stats() *redis.PoolStats {
	return c.Client.PoolStats()
}

// Health check
func (c *Client) HealthCheck(ctx context.Context) error {
	return c.Ping(ctx)
}

// Close closes the client
func (c *Client) Close() error {
	return c.Client.Close()
}

// ============================================================================
// Environment Variable Configuration
// ============================================================================

// TLSConfig holds TLS configuration for Redis
type TLSConfig struct {
	Enabled            bool
	CertFile           string
	KeyFile            string
	CAFile             string
	InsecureSkipVerify bool
}

// NewConfigFromEnv creates config from environment variables
func NewConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()

	// Address
	if addr := os.Getenv("REDIS_ADDRESS"); addr != "" {
		cfg.Addresses = []string{addr}
	}

	// Password
	cfg.Password = os.Getenv("REDIS_PASSWORD")

	// Database
	if db := os.Getenv("REDIS_DATABASE"); db != "" {
		if val, err := strconv.Atoi(db); err == nil {
			cfg.Database = val
		}
	}

	// Pool size
	if ps := os.Getenv("REDIS_POOL_SIZE"); ps != "" {
		if val, err := strconv.Atoi(ps); err == nil {
			cfg.PoolSize = val
		}
	}

	// Max retries
	if mr := os.Getenv("REDIS_MAX_RETRIES"); mr != "" {
		if val, err := strconv.Atoi(mr); err == nil {
			cfg.MaxRetries = val
		}
	}

	// Dial timeout
	if dt := os.Getenv("REDIS_DIAL_TIMEOUT"); dt != "" {
		if val, err := strconv.Atoi(dt); err == nil {
			cfg.DialTimeout = time.Duration(val) * time.Second
		}
	}

	// Read timeout
	if rt := os.Getenv("REDIS_READ_TIMEOUT"); rt != "" {
		if val, err := strconv.Atoi(rt); err == nil {
			cfg.ReadTimeout = time.Duration(val) * time.Second
		}
	}

	// Write timeout
	if wt := os.Getenv("REDIS_WRITE_TIMEOUT"); wt != "" {
		if val, err := strconv.Atoi(wt); err == nil {
			cfg.WriteTimeout = time.Duration(val) * time.Second
		}
	}

	// TLS Configuration
	if tlsEnabled := os.Getenv("REDIS_TLS_ENABLED"); tlsEnabled == "true" {
		cfg.TLSEnabled = true
		cfg.TLSCertFile = os.Getenv("REDIS_TLS_CERT")
		cfg.TLSKeyFile = os.Getenv("REDIS_TLS_KEY")
		cfg.TLSCAFile = os.Getenv("REDIS_TLS_CA")

		if skip := os.Getenv("REDIS_TLS_INSECURE"); skip == "true" {
			cfg.TLSInsecureSkipVerify = true
		}
	}

	return cfg, nil
}

// ============================================================================
// Missing Redis Operations
// ============================================================================

// DecrBy decrements a key by value
func (c *Client) DecrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.Client.DecrBy(ctx, key, value).Result()
}

// GetSet atomically gets and sets a value
func (c *Client) GetSet(ctx context.Context, key string, value interface{}) (string, error) {
	return c.Client.GetSet(ctx, key, value).Result()
}

// HMSet sets multiple hash fields
func (c *Client) HMSet(ctx context.Context, key string, fields map[string]interface{}) error {
	return c.Client.HMSet(ctx, key, fields).Err()
}

// HExists checks if hash field exists
func (c *Client) HExists(ctx context.Context, key, field string) (bool, error) {
	return c.Client.HExists(ctx, key, field).Result()
}

// HLen gets number of fields in hash
func (c *Client) HLen(ctx context.Context, key string) (int64, error) {
	return c.Client.HLen(ctx, key).Result()
}

// LTrim trims list to range
func (c *Client) LTrim(ctx context.Context, key string, start, stop int64) error {
	return c.Client.LTrim(ctx, key, start, stop).Err()
}

// SCard gets set size
func (c *Client) SCard(ctx context.Context, key string) (int64, error) {
	return c.Client.SCard(ctx, key).Result()
}

// SInter gets intersection of sets
func (c *Client) SInter(ctx context.Context, keys ...string) ([]string, error) {
	return c.Client.SInter(ctx, keys...).Result()
}

// SUnion gets union of sets
func (c *Client) SUnion(ctx context.Context, keys ...string) ([]string, error) {
	return c.Client.SUnion(ctx, keys...).Result()
}

// ZRem removes members from sorted set
func (c *Client) ZRem(ctx context.Context, key string, members ...interface{}) error {
	return c.Client.ZRem(ctx, key, members...).Err()
}

// ZRangeByScore gets sorted set range by score
func (c *Client) ZRangeByScore(ctx context.Context, key string, min, max float64) ([]string, error) {
	return c.Client.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%f", min),
		Max: fmt.Sprintf("%f", max),
	}).Result()
}

// ZCard gets sorted set size
func (c *Client) ZCard(ctx context.Context, key string) (int64, error) {
	return c.Client.ZCard(ctx, key).Result()
}

// ============================================================================
// Pool Management Helpers
// ============================================================================

// IdleConns returns number of idle connections
func (c *Client) IdleConns() int {
	return int(c.Stats().IdleConns)
}

// TotalConns returns total connections
func (c *Client) TotalConns() int {
	return int(c.Stats().TotalConns)
}

// Hits returns pool hits
func (c *Client) Hits() uint32 {
	return c.Stats().Hits
}

// Misses returns pool misses
func (c *Client) Misses() uint32 {
	return c.Stats().Misses
}

// Timeouts returns pool timeouts
func (c *Client) Timeouts() uint32 {
	return c.Stats().Timeouts
}

// ============================================================================
// Circuit Breaker
// ============================================================================

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	mu                sync.RWMutex
	state             circuitState
	failures          int
	maxFailures       int
	resetTimeout      time.Duration
	lastFailureTime   time.Time
	halfOpenSuccesses int
	halfOpenMax       int
}

// NewCircuitBreaker creates a circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:        circuitClosed,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		halfOpenMax:  3,
	}
}

// Allow checks if operation is allowed
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.state == circuitOpen {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = circuitHalfOpen
			cb.halfOpenSuccesses = 0
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	}
	return true
}

// RecordSuccess records successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitHalfOpen {
		cb.halfOpenSuccesses++
		if cb.halfOpenSuccesses >= cb.halfOpenMax {
			cb.state = circuitClosed
			cb.failures = 0
		}
	} else {
		cb.failures = 0
	}
}

// RecordFailure records failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.maxFailures {
		cb.state = circuitOpen
	}
}

// ============================================================================
// Retry Logic with Exponential Backoff
// ============================================================================

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

// DefaultRetryConfig returns default retry config
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 100 * time.Millisecond,
		MaxWait:     5 * time.Second,
		Multiplier:  2.0,
	}
}

// WithRetry executes function with retry logic
func WithRetry(ctx context.Context, cfg RetryConfig, fn func() error) error {
	var lastErr error
	wait := cfg.InitialWait

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err

			// Don't retry on context cancellation
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Don't retry on non-retryable errors
			if !isRetryable(err) {
				return err
			}

			if attempt < cfg.MaxAttempts-1 {
				select {
				case <-time.After(wait):
					wait = time.Duration(float64(wait) * cfg.Multiplier)
					if wait > cfg.MaxWait {
						wait = cfg.MaxWait
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
	return lastErr
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// Retryable errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "EOF") {
		return true
	}

	// Non-retryable errors
	if strings.Contains(errStr, "OOM") ||
		strings.Contains(errStr, "WRONGTYPE") ||
		strings.Contains(errStr, "NOAUTH") {
		return false
	}

	return true
}

// ============================================================================
// TLS Support
// ============================================================================

// LoadTLSConfig loads TLS configuration
func LoadTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Load client certificate if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}
// ============================================================================
// Instrumentation
// ============================================================================

// WithMetrics attaches a metrics registry to the client
func (c *Client) WithMetrics(m *metrics.MetricsRegistry) *Client {
c.metrics = m
return c
}

// WithLogger attaches a logger to the client
func (c *Client) WithLogger(l *logging.Logger) *Client {
c.logger = l
return c
}
