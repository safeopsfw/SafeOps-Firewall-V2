// Package redis provides pipeline utilities.
package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

// Pipeline wraps Redis pipeline
type Pipeline struct {
	pipe   redis.Pipeliner
	client *Client
}

// NewPipeline creates a new pipeline
func (c *Client) NewPipeline() *Pipeline {
	return &Pipeline{
		pipe:   c.Client.Pipeline(),
		client: c,
	}
}

// TxPipeline creates a transactional pipeline
func (c *Client) TxPipeline() *Pipeline {
	return &Pipeline{
		pipe:   c.Client.TxPipeline(),
		client: c,
	}
}

// Set queues a SET command
func (p *Pipeline) Set(key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	return p.pipe.Set(context.Background(), key, value, ttl)
}

// Get queues a GET command
func (p *Pipeline) Get(key string) *redis.StringCmd {
	return p.pipe.Get(context.Background(), key)
}

// Del queues a DEL command
func (p *Pipeline) Del(keys ...string) *redis.IntCmd {
	return p.pipe.Del(context.Background(), keys...)
}

// Incr queues an INCR command
func (p *Pipeline) Incr(key string) *redis.IntCmd {
	return p.pipe.Incr(context.Background(), key)
}

// IncrBy queues an INCRBY command
func (p *Pipeline) IncrBy(key string, value int64) *redis.IntCmd {
	return p.pipe.IncrBy(context.Background(), key, value)
}

// HSet queues an HSET command
func (p *Pipeline) HSet(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.HSet(context.Background(), key, values...)
}

// HGet queues an HGET command
func (p *Pipeline) HGet(key, field string) *redis.StringCmd {
	return p.pipe.HGet(context.Background(), key, field)
}

// HGetAll queues an HGETALL command
func (p *Pipeline) HGetAll(key string) *redis.StringStringMapCmd {
	return p.pipe.HGetAll(context.Background(), key)
}

// LPush queues an LPUSH command
func (p *Pipeline) LPush(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.LPush(context.Background(), key, values...)
}

// RPush queues an RPUSH command
func (p *Pipeline) RPush(key string, values ...interface{}) *redis.IntCmd {
	return p.pipe.RPush(context.Background(), key, values...)
}

// SAdd queues an SADD command
func (p *Pipeline) SAdd(key string, members ...interface{}) *redis.IntCmd {
	return p.pipe.SAdd(context.Background(), key, members...)
}

// ZAdd queues a ZADD command
func (p *Pipeline) ZAdd(key string, members ...*redis.Z) *redis.IntCmd {
	return p.pipe.ZAdd(context.Background(), key, members...)
}

// Expire queues an EXPIRE command
func (p *Pipeline) Expire(key string, ttl time.Duration) *redis.BoolCmd {
	return p.pipe.Expire(context.Background(), key, ttl)
}

// Exec executes the pipeline
func (p *Pipeline) Exec(ctx context.Context) ([]redis.Cmder, error) {
	return p.pipe.Exec(ctx)
}

// Discard discards the pipeline
func (p *Pipeline) Discard() {
	p.pipe.Discard()
}

// Len returns the number of queued commands
func (p *Pipeline) Len() int {
	return p.pipe.Len()
}

// Batch provides batch operations
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
	pipe := b.client.Client.Pipeline()

	for _, cmd := range b.commands {
		cmd(pipe)
	}

	return pipe.Exec(ctx)
}

// Size returns the number of commands in the batch
func (b *Batch) Size() int {
	return len(b.commands)
}

// Reset clears the batch
func (b *Batch) Reset() {
	b.commands = b.commands[:0]
}

// MultiGet gets multiple keys at once
func (c *Client) MultiGet(ctx context.Context, keys ...string) ([]interface{}, error) {
	return c.Client.MGet(ctx, keys...).Result()
}

// MultiSet sets multiple keys at once
func (c *Client) MultiSet(ctx context.Context, values ...interface{}) error {
	return c.Client.MSet(ctx, values...).Err()
}
