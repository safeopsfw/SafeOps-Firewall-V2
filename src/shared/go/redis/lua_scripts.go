// Package redis provides Lua script utilities.
package redis

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sync"

	"github.com/go-redis/redis/v8"
)

// Script represents a Lua script
type Script struct {
	src  string
	hash string
}

// NewScript creates a new Lua script
func NewScript(src string) *Script {
	h := sha1.New()
	h.Write([]byte(src))
	hash := hex.EncodeToString(h.Sum(nil))

	return &Script{
		src:  src,
		hash: hash,
	}
}

// Run executes the script using EVALSHA, falls back to EVAL if needed
func (s *Script) Run(ctx context.Context, c *Client, keys []string, args ...interface{}) *redis.Cmd {
	// Try EVALSHA first (faster, uses cached script)
	cmd := c.Client.EvalSha(ctx, s.hash, keys, args...)

	// If script not cached, fallback to EVAL
	if err := cmd.Err(); err != nil && err.Error() == "NOSCRIPT No matching script. Please use EVAL." {
		return c.Client.Eval(ctx, s.src, keys, args...)
	}

	return cmd
}

// Load loads the script into Redis
func (s *Script) Load(ctx context.Context, c *Client) error {
	_, err := c.Client.ScriptLoad(ctx, s.src).Result()
	return err
}

// ScriptManager manages Lua scripts
type ScriptManager struct {
	client  *Client
	scripts map[string]*Script
	mu      sync.RWMutex
}

// NewScriptManager creates a new script manager
func NewScriptManager(client *Client) *ScriptManager {
	return &ScriptManager{
		client:  client,
		scripts: make(map[string]*Script),
	}
}

// Register registers a script
func (sm *ScriptManager) Register(name, src string) *Script {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	script := NewScript(src)
	sm.scripts[name] = script
	return script
}

// Get gets a registered script
func (sm *ScriptManager) Get(name string) *Script {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.scripts[name]
}

// LoadAll loads all registered scripts
func (sm *ScriptManager) LoadAll(ctx context.Context) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, script := range sm.scripts {
		if err := script.Load(ctx, sm.client); err != nil {
			return err
		}
	}
	return nil
}

// Run runs a registered script
func (sm *ScriptManager) Run(ctx context.Context, name string, keys []string, args ...interface{}) *redis.Cmd {
	script := sm.Get(name)
	if script == nil {
		return redis.NewCmd(ctx)
	}
	return script.Run(ctx, sm.client, keys, args...)
}

// Common Lua scripts

// RateLimitScript implements sliding window rate limiting
var RateLimitScript = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window)
    return 1
end
return 0
`

// IncrWithLimitScript increments a counter with limit
var IncrWithLimitScript = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current and tonumber(current) >= limit then
    return -1
end

local new = redis.call('INCR', key)
if new == 1 then
    redis.call('EXPIRE', key, ttl)
end
return new
`

// GetOrSetScript gets a value or sets it if not exists
var GetOrSetScript = `
local key = KEYS[1]
local value = ARGV[1]
local ttl = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current then
    return current
end

redis.call('SET', key, value, 'EX', ttl)
return value
`

// CompareAndSwapScript atomically compares and swaps
var CompareAndSwapScript = `
local key = KEYS[1]
local expected = ARGV[1]
local new = ARGV[2]

local current = redis.call('GET', key)
if current == expected then
    redis.call('SET', key, new)
    return 1
end
return 0
`

// DecrIfPositiveScript decrements only if result is non-negative
var DecrIfPositiveScript = `
local key = KEYS[1]
local amount = tonumber(ARGV[1])

local current = tonumber(redis.call('GET', key) or 0)
if current >= amount then
    return redis.call('DECRBY', key, amount)
end
return -1
`

// RegisterCommonScripts registers common scripts
func (sm *ScriptManager) RegisterCommonScripts() {
	sm.Register("rate_limit", RateLimitScript)
	sm.Register("incr_with_limit", IncrWithLimitScript)
	sm.Register("get_or_set", GetOrSetScript)
	sm.Register("compare_and_swap", CompareAndSwapScript)
	sm.Register("decr_if_positive", DecrIfPositiveScript)
}

// DistLockAcquireScript acquires a distributed lock with TTL
var DistLockAcquireScript = `
local key = KEYS[1]
local value = ARGV[1]
local ttl = tonumber(ARGV[2])

if redis.call('EXISTS', key) == 0 then
    redis.call('SET', key, value, 'PX', ttl)
    return 1
else
    return 0
end
`

// DistLockReleaseScript releases a lock only if owned
var DistLockReleaseScript = `
local key = KEYS[1]
local value = ARGV[1]

if redis.call('GET', key) == value then
    return redis.call('DEL', key)
else
    return 0
end
`

// DistLockExtendScript extends lock TTL if owned
var DistLockExtendScript = `
local key = KEYS[1]
local value = ARGV[1]
local ttl = tonumber(ARGV[2])

if redis.call('GET', key) == value then
    return redis.call('PEXPIRE', key, ttl)
else
    return 0
end
`

// TokenBucketScript implements token bucket rate limiting
var TokenBucketScript = `
local key = KEYS[1]
local max_tokens = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if not tokens then
    tokens = max_tokens
    last_refill = now
end

-- Calculate tokens to add based on time elapsed
local elapsed = (now - last_refill) / 1000.0
local tokens_to_add = elapsed * refill_rate
tokens = math.min(max_tokens, tokens + tokens_to_add)

-- Try to consume requested tokens
if tokens >= requested then
    tokens = tokens - requested
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, 3600)
    return {1, tokens}
else
    return {0, tokens}
end
`

// RegisterDistributedLockScripts registers distributed lock scripts
func (sm *ScriptManager) RegisterDistributedLockScripts() {
	sm.Register("dist_lock_acquire", DistLockAcquireScript)
	sm.Register("dist_lock_release", DistLockReleaseScript)
	sm.Register("dist_lock_extend", DistLockExtendScript)
	sm.Register("token_bucket", TokenBucketScript)
}

// RegisterAllScripts registers all common and distributed lock scripts
func (sm *ScriptManager) RegisterAllScripts() {
	sm.RegisterCommonScripts()
	sm.RegisterDistributedLockScripts()
}
