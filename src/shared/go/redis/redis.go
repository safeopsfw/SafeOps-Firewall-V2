// Package redis provides Redis connection pool and utilities.
package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
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
	cfg Config
}

// NewClient creates a Redis client
func NewClient(cfg Config) *Client {
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
	}

	return &Client{
		Client: redis.NewClient(opts),
		cfg:    cfg,
	}
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
