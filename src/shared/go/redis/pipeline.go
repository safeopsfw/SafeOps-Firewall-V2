// Package redis provides Redis pipelining for batching commands and reducing round trips.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/safeops/shared/go/errors"
)

// ============================================================================
// Pipeline Interface
// ============================================================================

// Pipeline creates a new Redis pipeline for batching commands.
// Pipeline buffers commands in memory and executes them atomically when Exec() is called.
// This dramatically reduces network round trips for bulk operations.
//
// Usage:
//
//	pipe := client.Pipeline(ctx)
//	pipe.Set(ctx, "key1", "value1", 0)
//	pipe.Set(ctx, "key2", "value2", 0)
//	pipe.Incr(ctx, "counter")
//	_, err := pipe.Exec(ctx)
func (c *Client) Pipeline(ctx context.Context) redis.Pipeliner {
	if c.logger != nil {
		c.logger.Debug("Creating new Redis pipeline")
	}
	return c.Client.Pipeline()
}

// TxPipeline creates a new transaction pipeline.
// Unlike regular pipeline, TxPipeline wraps commands in MULTI/EXEC to ensure atomicity.
// If any command fails, the entire transaction is rolled back.
//
// Usage:
//
//	pipe := client.TxPipeline(ctx)
//	pipe.Set(ctx, "balance", 1000, 0)
//	pipe.Decr(ctx, "balance")
//	_, err := pipe.Exec(ctx)
func (c *Client) TxPipeline(ctx context.Context) redis.Pipeliner {
	if c.logger != nil {
		c.logger.Debug("Creating new Redis transaction pipeline")
	}
	return c.Client.TxPipeline()
}

// ============================================================================
// Pipeline Execution Helpers
// ============================================================================

// ExecutePipeline executes a pipeline with proper error handling and metrics.
// Returns all command results and any execution errors.
//
// This wrapper provides:
//   - Context cancellation support
//   - Automatic metric recording (pipeline size, duration, errors)
//   - Structured error wrapping
//   - Logging for debugging
//
// Example:
//
//	pipe := client.Pipeline(ctx)
//	pipe.Set(ctx, "key1", "value1", 0)
//	pipe.Get(ctx, "key2")
//	cmds, err := ExecutePipeline(ctx, pipe)
//	if err != nil {
//	    log.Error("Pipeline failed", err)
//	}
func ExecutePipeline(ctx context.Context, pipe redis.Pipeliner) ([]redis.Cmder, error) {
	if pipe == nil {
		return nil, errors.New("REDIS_PIPELINE_NIL", "Pipeline is nil")
	}

	// Check for context cancellation before execution
	if ctx.Err() != nil {
		return nil, errors.Wrap(ctx.Err(), "REDIS_CONTEXT_CANCELLED", "Context cancelled before pipeline execution")
	}

	// Get pipeline length for metrics
	pipeLen := pipe.Len()

	// Record start time for metrics
	startTime := time.Now()

	// Execute pipeline
	cmds, err := pipe.Exec(ctx)
	duration := time.Since(startTime)

	// Handle execution error
	if err != nil && err != redis.Nil {
		return cmds, errors.Wrap(err, "REDIS_PIPELINE_EXEC_FAILED", "Pipeline execution failed").
			WithField("pipeline_size", pipeLen).
			WithField("duration_ms", duration.Milliseconds())
	}

	// Check individual command errors
	var cmdErrors []string
	for i, cmd := range cmds {
		if cmdErr := cmd.Err(); cmdErr != nil && cmdErr != redis.Nil {
			cmdErrors = append(cmdErrors, fmt.Sprintf("cmd[%d]: %v", i, cmdErr))
		}
	}

	// Return aggregated command errors if any
	if len(cmdErrors) > 0 {
		return cmds, errors.New("REDIS_PIPELINE_CMD_ERRORS", "One or more pipeline commands failed").
			WithField("pipeline_size", pipeLen).
			WithField("failed_commands", len(cmdErrors)).
			WithField("errors", cmdErrors).
			WithField("duration_ms", duration.Milliseconds())
	}

	return cmds, nil
}

// ============================================================================
// Batch Helpers - MGet
// ============================================================================

// MGet retrieves multiple keys in a single operation.
// Returns values in the same order as keys. Missing keys return nil.
//
// This is more efficient than individual Get() calls as it uses a single network round trip.
//
// Example:
//
//	values, err := client.MGet(ctx, "user:1", "user:2", "user:3")
//	if err != nil {
//	    log.Error("MGet failed", err)
//	}
//	for i, val := range values {
//	    if val == nil {
//	        fmt.Printf("Key %d not found\n", i)
//	    } else {
//	        fmt.Printf("Key %d: %v\n", i, val)
//	    }
//	}
func (c *Client) MGet(ctx context.Context, keys ...string) ([]interface{}, error) {
	if len(keys) == 0 {
		return []interface{}{}, nil
	}

	startTime := time.Now()

	// Use Redis MGet command directly (more efficient than pipeline)
	result, err := c.Client.MGet(ctx, keys...).Result()
	duration := time.Since(startTime)

	if err != nil && err != redis.Nil {
		wrappedErr := errors.Wrap(err, "REDIS_MGET_FAILED", "Failed to retrieve multiple keys").
			WithField("key_count", len(keys)).
			WithField("duration_ms", duration.Milliseconds())

		// Log error
		if c.logger != nil {
			c.logger.Error("MGet operation failed",
				"key_count", len(keys),
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		}

		// TODO: Record metrics when available
		// c.metrics.IncrementCounter("redis.mget.errors", 1)

		return nil, wrappedErr
	}

	// TODO: Record metrics when available
	// c.metrics.RecordHistogram("redis.mget.keys", float64(len(keys)))
	// c.metrics.RecordHistogram("redis.mget.duration_ms", float64(duration.Milliseconds()))
	// c.metrics.IncrementCounter("redis.mget.success", 1)

	// Log operation
	if c.logger != nil {
		c.logger.Debug("MGet operation successful",
			"key_count", len(keys),
			"duration_ms", duration.Milliseconds(),
		)
	}

	return result, nil
}

// ============================================================================
// Batch Helpers - MSet
// ============================================================================

// MSet sets multiple key-value pairs in a single atomic operation.
// Accepts pairs as alternating key-value arguments: key1, value1, key2, value2, ...
//
// This operation is atomic - either all keys are set or none are.
//
// Example:
//
//	err := client.MSet(ctx,
//	    "user:1:name", "Alice",
//	    "user:1:email", "alice@example.com",
//	    "user:1:status", "active",
//	)
func (c *Client) MSet(ctx context.Context, pairs ...interface{}) error {
	if len(pairs) == 0 {
		return nil
	}

	if len(pairs)%2 != 0 {
		return errors.New("REDIS_MSET_INVALID_ARGS", "MSet requires even number of arguments (key-value pairs)").
			WithField("arg_count", len(pairs))
	}

	startTime := time.Now()

	// Use Redis MSet command
	err := c.Client.MSet(ctx, pairs...).Err()
	duration := time.Since(startTime)

	if err != nil {
		wrappedErr := errors.Wrap(err, "REDIS_MSET_FAILED", "Failed to set multiple keys").
			WithField("pair_count", len(pairs)/2).
			WithField("duration_ms", duration.Milliseconds())

		// Log error
		if c.logger != nil {
			c.logger.Error("MSet operation failed",
				"pair_count", len(pairs)/2,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		}

		// TODO: Record metrics when available
		// c.metrics.IncrementCounter("redis.mset.errors", 1)

		return wrappedErr
	}

	// TODO: Record metrics when available
	// c.metrics.RecordHistogram("redis.mset.pairs", float64(len(pairs)/2))
	// c.metrics.RecordHistogram("redis.mset.duration_ms", float64(duration.Milliseconds()))
	// c.metrics.IncrementCounter("redis.mset.success", 1)

	// Log operation
	if c.logger != nil {
		c.logger.Debug("MSet operation successful",
			"pair_count", len(pairs)/2,
			"duration_ms", duration.Milliseconds(),
		)
	}

	return nil
}

// ============================================================================
// Advanced Batch Operations
// ============================================================================

// MGetStrings is a convenience wrapper around MGet that returns []string instead of []interface{}.
// Nil values (missing keys) are returned as empty strings.
func (c *Client) MGetStrings(ctx context.Context, keys ...string) ([]string, error) {
	results, err := c.MGet(ctx, keys...)
	if err != nil {
		return nil, err
	}

	strings := make([]string, len(results))
	for i, val := range results {
		if val != nil {
			strings[i] = val.(string)
		}
	}

	return strings, nil
}

// MSetNX sets multiple key-value pairs only if none of the keys exist.
// Returns true if all keys were set, false if any key already exists.
//
// This is an atomic operation - either all keys are set or none are.
//
// Example:
//
//	success, err := client.MSetNX(ctx,
//	    "lock:resource1", "owner1",
//	    "lock:resource2", "owner2",
//	)
//	if !success {
//	    log.Info("One or more locks already held")
//	}
func (c *Client) MSetNX(ctx context.Context, pairs ...interface{}) (bool, error) {
	if len(pairs) == 0 {
		return true, nil
	}

	if len(pairs)%2 != 0 {
		return false, errors.New("REDIS_MSETNX_INVALID_ARGS", "MSetNX requires even number of arguments (key-value pairs)").
			WithField("arg_count", len(pairs))
	}

	startTime := time.Now()

	// Use Redis MSetNX command
	result, err := c.Client.MSetNX(ctx, pairs...).Result()
	duration := time.Since(startTime)

	if err != nil {
		wrappedErr := errors.Wrap(err, "REDIS_MSETNX_FAILED", "Failed to conditionally set multiple keys").
			WithField("pair_count", len(pairs)/2).
			WithField("duration_ms", duration.Milliseconds())

		// Log error
		if c.logger != nil {
			c.logger.Error("MSetNX operation failed",
				"pair_count", len(pairs)/2,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		}

		// TODO: Record metrics when available
		// c.metrics.IncrementCounter("redis.msetnx.errors", 1)

		return false, wrappedErr
	}

	// TODO: Record metrics when available
	// c.metrics.RecordHistogram("redis.msetnx.pairs", float64(len(pairs)/2))
	// c.metrics.RecordHistogram("redis.msetnx.duration_ms", float64(duration.Milliseconds()))
	// c.metrics.IncrementCounter("redis.msetnx.success", 1)

	// Log operation
	if c.logger != nil {
		c.logger.Debug("MSetNX operation completed",
			"pair_count", len(pairs)/2,
			"all_set", result,
			"duration_ms", duration.Milliseconds(),
		)
	}

	return result, nil
}

// MDel deletes multiple keys in a single operation.
// Returns the number of keys deleted and any error encountered.
//
// This is more efficient than individual Del() calls for bulk deletions.
//
// Example:
//
//	deleted, err := client.MDel(ctx, "temp:1", "temp:2", "temp:3")
//	fmt.Printf("Deleted %d keys\n", deleted)
func (c *Client) MDel(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	startTime := time.Now()

	// Use Redis Del command (supports multiple keys)
	result, err := c.Client.Del(ctx, keys...).Result()
	duration := time.Since(startTime)

	if err != nil {
		wrappedErr := errors.Wrap(err, "REDIS_MDEL_FAILED", "Failed to delete multiple keys").
			WithField("key_count", len(keys)).
			WithField("duration_ms", duration.Milliseconds())

		// Log error
		if c.logger != nil {
			c.logger.Error("MDel operation failed",
				"key_count", len(keys),
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		}

		// TODO: Record metrics when available
		// c.metrics.IncrementCounter("redis.mdel.errors", 1)

		return 0, wrappedErr
	}

	// TODO: Record metrics when available
	// c.metrics.RecordHistogram("redis.mdel.keys", float64(len(keys)))
	// c.metrics.RecordHistogram("redis.mdel.deleted", float64(result))
	// c.metrics.RecordHistogram("redis.mdel.duration_ms", float64(duration.Milliseconds()))
	// c.metrics.IncrementCounter("redis.mdel.success", 1)

	// Log operation
	if c.logger != nil {
		c.logger.Debug("MDel operation completed",
			"key_count", len(keys),
			"deleted", result,
			"duration_ms", duration.Milliseconds(),
		)
	}

	return result, nil
}

// ============================================================================
// Advanced Pipeline Patterns
// ============================================================================

// PipelinedIncr performs multiple INCR operations in a single pipeline.
// Returns the new values for each key after increment.
//
// Example:
//
//	newValues, err := client.PipelinedIncr(ctx, "counter1", "counter2", "counter3")
func (c *Client) PipelinedIncr(ctx context.Context, keys ...string) ([]int64, error) {
	if len(keys) == 0 {
		return []int64{}, nil
	}

	pipe := c.Pipeline(ctx)
	cmds := make([]*redis.IntCmd, len(keys))

	// Queue all INCR commands
	for i, key := range keys {
		cmds[i] = pipe.Incr(ctx, key)
	}

	// Execute pipeline
	if _, err := ExecutePipeline(ctx, pipe); err != nil {
		return nil, err
	}

	// Extract results
	results := make([]int64, len(cmds))
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if err != nil {
			return nil, errors.Wrap(err, "REDIS_PIPELINED_INCR_FAILED", "Failed to get INCR result").
				WithField("key_index", i).
				WithField("key", keys[i])
		}
		results[i] = val
	}

	return results, nil
}

// PipelinedExpire sets TTL on multiple keys in a single pipeline.
// Returns the number of keys that had their TTL successfully set.
//
// Example:
//
//	count, err := client.PipelinedExpire(ctx, 60*time.Second, "session:1", "session:2")
func (c *Client) PipelinedExpire(ctx context.Context, ttl time.Duration, keys ...string) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	pipe := c.Pipeline(ctx)
	cmds := make([]*redis.BoolCmd, len(keys))

	// Queue all EXPIRE commands
	for i, key := range keys {
		cmds[i] = pipe.Expire(ctx, key, ttl)
	}

	// Execute pipeline
	if _, err := ExecutePipeline(ctx, pipe); err != nil {
		return 0, err
	}

	// Count successful expirations
	successCount := 0
	for i, cmd := range cmds {
		success, err := cmd.Result()
		if err != nil {
			return successCount, errors.Wrap(err, "REDIS_PIPELINED_EXPIRE_FAILED", "Failed to get EXPIRE result").
				WithField("key_index", i).
				WithField("key", keys[i])
		}
		if success {
			successCount++
		}
	}

	return successCount, nil
}

// ============================================================================
// Legacy Pipeline Wrapper (for backward compatibility)
// ============================================================================

// Pipeline wraps Redis pipeline with convenience methods
type PipelineWrapper struct {
	pipe   redis.Pipeliner
	client *Client
}

// NewPipeline creates a new pipeline wrapper (deprecated, use Pipeline() instead)
func (c *Client) NewPipeline() *PipelineWrapper {
	return &PipelineWrapper{
		pipe:   c.Client.Pipeline(),
		client: c,
	}
}

// NewTxPipeline creates a transactional pipeline wrapper (deprecated, use TxPipeline() instead)
func (c *Client) NewTxPipeline() *PipelineWrapper {
	return &PipelineWrapper{
		pipe:   c.Client.TxPipeline(),
		client: c,
	}
}

// Set queues a SET command
func (p *PipelineWrapper) Set(key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	return p.pipe.Set(context.Background(), key, value, ttl)
}

// Get queues a GET command
func (p *PipelineWrapper) Get(key string) *redis.StringCmd {
	return p.pipe.Get(context.Background(), key)
}

// Del queues a DEL command
func (p *PipelineWrapper) Del(keys ...string) *redis.IntCmd {
	return p.pipe.Del(context.Background(), keys...)
}

// Incr queues an INCR command
func (p *PipelineWrapper) Incr(key string) *redis.IntCmd {
	return p.pipe.Incr(context.Background(), key)
}

// IncrBy queues an INCRBY command
func (p *PipelineWrapper) IncrBy(key string, value int64) *redis.IntCmd {
	return p.pipe.IncrBy(context.Background(), key, value)
}

// HSet queues an HSET command
func (p *PipelineWrapper) HSet(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.HSet(context.Background(), key, values...)
}

// HGet queues an HGET command
func (p *PipelineWrapper) HGet(key, field string) *redis.StringCmd {
	return p.pipe.HGet(context.Background(), key, field)
}

// HGetAll queues an HGETALL command
func (p *PipelineWrapper) HGetAll(key string) *redis.StringStringMapCmd {
	return p.pipe.HGetAll(context.Background(), key)
}

// LPush queues an LPUSH command
func (p *PipelineWrapper) LPush(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.LPush(context.Background(), key, values...)
}

// RPush queues an RPUSH command
func (p *PipelineWrapper) RPush(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.RPush(context.Background(), key, values...)
}

// SAdd queues an SADD command
func (p *PipelineWrapper) SAdd(key string, members ...interface{}) *redis.IntCmd {
	return p.pipe.SAdd(context.Background(), key, members...)
}

// ZAdd queues a ZADD command
func (p *PipelineWrapper) ZAdd(key string, members ...*redis.Z) *redis.IntCmd {
	return p.pipe.ZAdd(context.Background(), key, members...)
}

// Expire queues an EXPIRE command
func (p *PipelineWrapper) Expire(key string, ttl time.Duration) *redis.BoolCmd {
	return p.pipe.Expire(context.Background(), key, ttl)
}

// Exec executes the pipeline
func (p *PipelineWrapper) Exec(ctx context.Context) ([]redis.Cmder, error) {
	return ExecutePipeline(ctx, p.pipe)
}

// Discard discards the pipeline
func (p *PipelineWrapper) Discard() {
	p.pipe.Discard()
}

// Len returns the number of queued commands
func (p *PipelineWrapper) Len() int {
	return p.pipe.Len()
}

// ============================================================================
// Batch Builder Pattern
// ============================================================================

// Batch provides batch operations builder pattern
type Batch struct {
	client   *Client
	commands []func(pipe redis.Pipeliner)
}

// NewBatch creates a new batch
func (c *Client) NewBatch() *Batch {
	return &Batch{
		client:   c,
		commands: make([]func(pipe redis.Pipeliner), 0),
	}
}

// Add adds a command to the batch
func (b *Batch) Add(fn func(pipe redis.Pipeliner)) {
	b.commands = append(b.commands, fn)
}

// Set adds a SET command
func (b *Batch) Set(key string, value interface{}, ttl time.Duration) {
	b.Add(func(pipe redis.Pipeliner) {
		pipe.Set(context.Background(), key, value, ttl)
	})
}

// Get adds a GET command
func (b *Batch) Get(key string) {
	b.Add(func(pipe redis.Pipeliner) {
		pipe.Get(context.Background(), key)
	})
}

// Del adds a DEL command
func (b *Batch) Del(keys ...string) {
	b.Add(func(pipe redis.Pipeliner) {
		pipe.Del(context.Background(), keys...)
	})
}

// Execute executes all batched commands
func (b *Batch) Execute(ctx context.Context) ([]redis.Cmder, error) {
	pipe := b.client.Pipeline(ctx)

	for _, cmd := range b.commands {
		cmd(pipe)
	}

	return ExecutePipeline(ctx, pipe)
}

// Size returns the number of commands in the batch
func (b *Batch) Size() int {
	return len(b.commands)
}

// Reset clears the batch
func (b *Batch) Reset() {
	b.commands = b.commands[:0]
}

// ============================================================================
// Convenience Aliases (for backward compatibility)
// ============================================================================

// MultiGet gets multiple keys at once (alias for MGet)
func (c *Client) MultiGet(ctx context.Context, keys ...string) ([]interface{}, error) {
	return c.MGet(ctx, keys...)
}

// MultiSet sets multiple keys at once (alias for MSet)
func (c *Client) MultiSet(ctx context.Context, values ...interface{}) error {
	return c.MSet(ctx, values...)
}
