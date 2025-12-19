package redis

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPipelineCreation tests basic pipeline creation
func TestPipelineCreation(t *testing.T) {
	// Create mock client
	client := &Client{
		Client: redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		}),
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("Create regular pipeline", func(t *testing.T) {
		pipe := client.Pipeline(ctx)
		assert.NotNil(t, pipe, "Pipeline should not be nil")
		assert.Equal(t, 0, pipe.Len(), "New pipeline should be empty")
	})

	t.Run("Create transaction pipeline", func(t *testing.T) {
		pipe := client.TxPipeline(ctx)
		assert.NotNil(t, pipe, "TxPipeline should not be nil")
		assert.Equal(t, 0, pipe.Len(), "New transaction pipeline should be empty")
	})
}

// TestExecutePipeline tests pipeline execution
func TestExecutePipeline(t *testing.T) {
	ctx := context.Background()

	t.Run("Execute nil pipeline", func(t *testing.T) {
		_, err := ExecutePipeline(ctx, nil)
		assert.Error(t, err, "Should return error for nil pipeline")
		assert.Contains(t, err.Error(), "REDIS_PIPELINE_NIL")
	})

	t.Run("Execute with cancelled context", func(t *testing.T) {
		client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		defer client.Close()

		pipe := client.Pipeline()
		pipe.Set(ctx, "key1", "value1", 0)

		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		_, err := ExecutePipeline(cancelledCtx, pipe)
		assert.Error(t, err, "Should return error for cancelled context")
		assert.Contains(t, err.Error(), "REDIS_CONTEXT_CANCELLED")
	})
}

// TestMGetMSet tests batch get/set operations
func TestMGetMSet(t *testing.T) {
	// Note: These tests require a running Redis instance
	// In production, use redis-mock or testcontainers
	t.Skip("Skipping integration test - requires Redis instance")

	client, err := NewClient(Config{
		Addresses: []string{"localhost:6379"},
		Database:  0,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	t.Run("MSet and MGet", func(t *testing.T) {
		// Set multiple keys
		err := client.MSet(ctx,
			"test:key1", "value1",
			"test:key2", "value2",
			"test:key3", "value3",
		)
		require.NoError(t, err)

		// Get multiple keys
		values, err := client.MGet(ctx, "test:key1", "test:key2", "test:key3")
		require.NoError(t, err)
		assert.Len(t, values, 3)
		assert.Equal(t, "value1", values[0])
		assert.Equal(t, "value2", values[1])
		assert.Equal(t, "value3", values[2])

		// Cleanup
		client.Delete(ctx, "test:key1", "test:key2", "test:key3")
	})

	t.Run("MGet with missing keys", func(t *testing.T) {
		values, err := client.MGet(ctx, "nonexistent1", "nonexistent2")
		require.NoError(t, err)
		assert.Len(t, values, 2)
		assert.Nil(t, values[0])
		assert.Nil(t, values[1])
	})

	t.Run("MGetStrings", func(t *testing.T) {
		err := client.MSet(ctx, "str:key1", "hello", "str:key2", "world")
		require.NoError(t, err)

		values, err := client.MGetStrings(ctx, "str:key1", "str:key2", "str:missing")
		require.NoError(t, err)
		assert.Len(t, values, 3)
		assert.Equal(t, "hello", values[0])
		assert.Equal(t, "world", values[1])
		assert.Equal(t, "", values[2]) // Missing key returns empty string

		// Cleanup
		client.Delete(ctx, "str:key1", "str:key2")
	})
}

// TestMSetInvalidArgs tests MSet with invalid arguments
func TestMSetInvalidArgs(t *testing.T) {
	client := &Client{
		Client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("MSet with odd number of args", func(t *testing.T) {
		err := client.MSet(ctx, "key1", "value1", "key2")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "REDIS_MSET_INVALID_ARGS")
	})

	t.Run("MSet with empty args", func(t *testing.T) {
		err := client.MSet(ctx)
		assert.NoError(t, err, "Empty MSet should succeed without error")
	})
}

// TestMSetNX tests conditional multi-set
func TestMSetNX(t *testing.T) {
	t.Skip("Skipping integration test - requires Redis instance")

	client, err := NewClient(Config{
		Addresses: []string{"localhost:6379"},
		Database:  0,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	t.Run("MSetNX on non-existent keys", func(t *testing.T) {
		// Ensure keys don't exist
		client.Delete(ctx, "nx:key1", "nx:key2")

		// Should succeed
		success, err := client.MSetNX(ctx, "nx:key1", "value1", "nx:key2", "value2")
		require.NoError(t, err)
		assert.True(t, success, "MSetNX should succeed for non-existent keys")

		// Cleanup
		client.Delete(ctx, "nx:key1", "nx:key2")
	})

	t.Run("MSetNX on existing keys", func(t *testing.T) {
		// Set one key
		client.SetWithTTL(ctx, "nx:existing", "value", 0)

		// Should fail because one key exists
		success, err := client.MSetNX(ctx, "nx:existing", "newvalue", "nx:new", "value")
		require.NoError(t, err)
		assert.False(t, success, "MSetNX should fail if any key exists")

		// Cleanup
		client.Delete(ctx, "nx:existing")
	})

	t.Run("MSetNX with invalid args", func(t *testing.T) {
		success, err := client.MSetNX(ctx, "key1")
		assert.Error(t, err)
		assert.False(t, success)
		assert.Contains(t, err.Error(), "REDIS_MSETNX_INVALID_ARGS")
	})
}

// TestMDel tests bulk deletion
func TestMDel(t *testing.T) {
	t.Skip("Skipping integration test - requires Redis instance")

	client, err := NewClient(Config{
		Addresses: []string{"localhost:6379"},
		Database:  0,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	t.Run("MDel existing keys", func(t *testing.T) {
		// Create test keys
		client.MSet(ctx, "del:key1", "v1", "del:key2", "v2", "del:key3", "v3")

		// Delete keys
		deleted, err := client.MDel(ctx, "del:key1", "del:key2", "del:key3")
		require.NoError(t, err)
		assert.Equal(t, int64(3), deleted)
	})

	t.Run("MDel non-existent keys", func(t *testing.T) {
		deleted, err := client.MDel(ctx, "nonexistent1", "nonexistent2")
		require.NoError(t, err)
		assert.Equal(t, int64(0), deleted)
	})

	t.Run("MDel empty args", func(t *testing.T) {
		deleted, err := client.MDel(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), deleted)
	})
}

// TestPipelinedIncr tests batch increment operations
func TestPipelinedIncr(t *testing.T) {
	t.Skip("Skipping integration test - requires Redis instance")

	client, err := NewClient(Config{
		Addresses: []string{"localhost:6379"},
		Database:  0,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	t.Run("PipelinedIncr multiple counters", func(t *testing.T) {
		// Initialize counters
		client.Delete(ctx, "counter:1", "counter:2", "counter:3")

		// Increment all at once
		values, err := client.PipelinedIncr(ctx, "counter:1", "counter:2", "counter:3")
		require.NoError(t, err)
		assert.Len(t, values, 3)
		assert.Equal(t, int64(1), values[0])
		assert.Equal(t, int64(1), values[1])
		assert.Equal(t, int64(1), values[2])

		// Increment again
		values, err = client.PipelinedIncr(ctx, "counter:1", "counter:2", "counter:3")
		require.NoError(t, err)
		assert.Equal(t, int64(2), values[0])
		assert.Equal(t, int64(2), values[1])
		assert.Equal(t, int64(2), values[2])

		// Cleanup
		client.Delete(ctx, "counter:1", "counter:2", "counter:3")
	})

	t.Run("PipelinedIncr empty keys", func(t *testing.T) {
		values, err := client.PipelinedIncr(ctx)
		require.NoError(t, err)
		assert.Empty(t, values)
	})
}

// TestPipelinedExpire tests batch TTL setting
func TestPipelinedExpire(t *testing.T) {
	t.Skip("Skipping integration test - requires Redis instance")

	client, err := NewClient(Config{
		Addresses: []string{"localhost:6379"},
		Database:  0,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	t.Run("PipelinedExpire existing keys", func(t *testing.T) {
		// Create test keys
		client.MSet(ctx, "exp:key1", "v1", "exp:key2", "v2", "exp:key3", "v3")

		// Set expiration
		count, err := client.PipelinedExpire(ctx, 60*time.Second, "exp:key1", "exp:key2", "exp:key3")
		require.NoError(t, err)
		assert.Equal(t, 3, count, "All 3 keys should have expiration set")

		// Verify TTL is set
		ttl, err := client.TTL(ctx, "exp:key1")
		require.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0), "TTL should be positive")

		// Cleanup
		client.Delete(ctx, "exp:key1", "exp:key2", "exp:key3")
	})

	t.Run("PipelinedExpire non-existent keys", func(t *testing.T) {
		count, err := client.PipelinedExpire(ctx, 60*time.Second, "nonexistent1", "nonexistent2")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "No keys should have expiration set")
	})

	t.Run("PipelinedExpire empty keys", func(t *testing.T) {
		count, err := client.PipelinedExpire(ctx, 60*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

// TestPipelineWrapper tests backward compatibility wrapper
func TestPipelineWrapper(t *testing.T) {
	client := &Client{
		Client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
	}
	defer client.Close()

	t.Run("NewPipeline wrapper", func(t *testing.T) {
		pipe := client.NewPipeline()
		assert.NotNil(t, pipe)
		assert.Equal(t, 0, pipe.Len())
	})

	t.Run("NewTxPipeline wrapper", func(t *testing.T) {
		pipe := client.NewTxPipeline()
		assert.NotNil(t, pipe)
		assert.Equal(t, 0, pipe.Len())
	})

	t.Run("Queue commands", func(t *testing.T) {
		pipe := client.NewPipeline()
		pipe.Set("key1", "value1", 0)
		pipe.Incr("counter")
		assert.Equal(t, 2, pipe.Len(), "Pipeline should have 2 queued commands")
		pipe.Discard()
		assert.Equal(t, 0, pipe.Len(), "Pipeline should be empty after discard")
	})
}

// TestBatch tests batch builder pattern
func TestBatch(t *testing.T) {
	client := &Client{
		Client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
	}
	defer client.Close()

	t.Run("Build and execute batch", func(t *testing.T) {
		batch := client.NewBatch()
		assert.NotNil(t, batch)
		assert.Equal(t, 0, batch.Size())

		batch.Set("key1", "value1", 0)
		batch.Set("key2", "value2", 0)
		batch.Get("key1")
		batch.Del("key3")

		assert.Equal(t, 4, batch.Size())
	})

	t.Run("Reset batch", func(t *testing.T) {
		batch := client.NewBatch()
		batch.Set("key1", "value1", 0)
		batch.Set("key2", "value2", 0)
		assert.Equal(t, 2, batch.Size())

		batch.Reset()
		assert.Equal(t, 0, batch.Size())
	})
}

// TestContextCancellation tests context timeout handling
func TestContextCancellation(t *testing.T) {
	client := &Client{
		Client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
	}
	defer client.Close()

	t.Run("Pipeline with timeout context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		time.Sleep(5 * time.Millisecond) // Ensure context is cancelled

		pipe := client.Pipeline(ctx)
		pipe.Set(ctx, "key1", "value1", 0)

		_, err := ExecutePipeline(ctx, pipe)
		assert.Error(t, err, "Should return error for expired context")
	})
}

// Benchmark tests
func BenchmarkPipelineVsIndividual(b *testing.B) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer client.Close()
	ctx := context.Background()

	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		keys[i] = "benchmark:key:" + string(rune(i))
	}

	b.Run("Individual SET", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, key := range keys {
				client.Set(ctx, key, "value", 0)
			}
		}
	})

	b.Run("Pipelined SET", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pipe := client.Pipeline()
			for _, key := range keys {
				pipe.Set(ctx, key, "value", 0)
			}
			pipe.Exec(ctx)
		}
	})

	// Cleanup
	client.Del(ctx, keys...)
}
