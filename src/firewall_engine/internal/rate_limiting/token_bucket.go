package rate_limiting

import (
	"sync/atomic"
	"time"
)

// TokenBucket implements a lock-free token bucket rate limiter.
// Tokens refill continuously at a fixed rate. Each Allow() consumes one token.
// If no tokens remain, the request is denied.
type TokenBucket struct {
	rate      float64 // tokens per second
	burst     int64   // max tokens (bucket capacity)
	tokens    atomic.Int64 // current tokens * 1000 (fixed-point for atomics)
	lastTime  atomic.Int64 // unix nanoseconds of last refill
}

const tokenScale = 1000 // fixed-point scale for sub-token precision

// NewTokenBucket creates a new token bucket.
// rate: tokens per second, burst: maximum burst capacity
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	tb := &TokenBucket{
		rate:  rate,
		burst: int64(burst),
	}
	tb.tokens.Store(int64(burst) * tokenScale)
	tb.lastTime.Store(time.Now().UnixNano())
	return tb
}

// Allow consumes one token. Returns true if allowed, false if rate-limited.
// Lock-free via compare-and-swap.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN consumes n tokens. Returns true if allowed.
func (tb *TokenBucket) AllowN(n int) bool {
	now := time.Now().UnixNano()
	cost := int64(n) * tokenScale

	for {
		oldTime := tb.lastTime.Load()
		elapsed := float64(now-oldTime) / float64(time.Second)
		if elapsed < 0 {
			elapsed = 0
		}

		// Calculate refill
		refill := int64(elapsed * tb.rate * float64(tokenScale))
		maxTokens := tb.burst * tokenScale

		oldTokens := tb.tokens.Load()
		newTokens := oldTokens + refill
		if newTokens > maxTokens {
			newTokens = maxTokens
		}

		// Try to consume
		if newTokens < cost {
			return false
		}

		if tb.tokens.CompareAndSwap(oldTokens, newTokens-cost) {
			tb.lastTime.Store(now)
			return true
		}
		// CAS failed, retry
	}
}

// Tokens returns the approximate current token count
func (tb *TokenBucket) Tokens() float64 {
	now := time.Now().UnixNano()
	oldTime := tb.lastTime.Load()
	elapsed := float64(now-oldTime) / float64(time.Second)

	current := float64(tb.tokens.Load())/float64(tokenScale) + elapsed*tb.rate
	max := float64(tb.burst)
	if current > max {
		return max
	}
	return current
}

// Rate returns the configured rate (tokens/sec)
func (tb *TokenBucket) Rate() float64 {
	return tb.rate
}

// Burst returns the configured burst size
func (tb *TokenBucket) Burst() int64 {
	return tb.burst
}
