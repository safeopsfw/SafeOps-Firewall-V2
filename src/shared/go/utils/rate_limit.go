// Package utils provides rate limiting utilities.
package utils

import (
	"context"
	"sync"
	"time"
)

// RateLimiter interface
type RateLimiter interface {
	Allow() bool
	Wait(ctx context.Context) error
}

// TokenBucket implements a token bucket rate limiter
type TokenBucket struct {
	rate       float64
	capacity   float64
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rate float64, capacity int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		capacity:   float64(capacity),
		tokens:     float64(capacity),
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if n tokens are available
func (tb *TokenBucket) AllowN(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// Wait waits until a token is available
func (tb *TokenBucket) Wait(ctx context.Context) error {
	return tb.WaitN(ctx, 1)
}

// WaitN waits for n tokens
func (tb *TokenBucket) WaitN(ctx context.Context, n int) error {
	for {
		if tb.AllowN(n) {
			return nil
		}

		// Calculate wait time
		tb.mu.Lock()
		needed := float64(n) - tb.tokens
		waitTime := time.Duration(needed / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.tokens += elapsed * tb.rate

	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastUpdate = now
}

// Available returns available tokens
func (tb *TokenBucket) Available() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return int(tb.tokens)
}

// SlidingWindow implements a sliding window rate limiter
type SlidingWindow struct {
	limit    int
	window   time.Duration
	requests []time.Time
	mu       sync.Mutex
}

// NewSlidingWindow creates a new sliding window limiter
func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		limit:    limit,
		window:   window,
		requests: make([]time.Time, 0, limit),
	}
}

// Allow checks if a request is allowed
func (sw *SlidingWindow) Allow() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-sw.window)

	// Remove expired requests
	valid := make([]time.Time, 0, len(sw.requests))
	for _, t := range sw.requests {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	sw.requests = valid

	// Check limit
	if len(sw.requests) >= sw.limit {
		return false
	}

	sw.requests = append(sw.requests, now)
	return true
}

// Wait waits until a request is allowed
func (sw *SlidingWindow) Wait(ctx context.Context) error {
	for {
		if sw.Allow() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sw.window / time.Duration(sw.limit)):
		}
	}
}

// FixedWindow implements a fixed window rate limiter
type FixedWindow struct {
	limit       int
	window      time.Duration
	count       int
	windowStart time.Time
	mu          sync.Mutex
}

// NewFixedWindow creates a new fixed window limiter
func NewFixedWindow(limit int, window time.Duration) *FixedWindow {
	return &FixedWindow{
		limit:       limit,
		window:      window,
		windowStart: time.Now(),
	}
}

// Allow checks if a request is allowed
func (fw *FixedWindow) Allow() bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	now := time.Now()

	// Reset window if expired
	if now.Sub(fw.windowStart) >= fw.window {
		fw.windowStart = now
		fw.count = 0
	}

	if fw.count >= fw.limit {
		return false
	}

	fw.count++
	return true
}

// Wait waits until a request is allowed
func (fw *FixedWindow) Wait(ctx context.Context) error {
	for {
		if fw.Allow() {
			return nil
		}

		fw.mu.Lock()
		waitTime := fw.window - time.Since(fw.windowStart)
		fw.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
}

// Remaining returns remaining requests in current window
func (fw *FixedWindow) Remaining() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	now := time.Now()
	if now.Sub(fw.windowStart) >= fw.window {
		return fw.limit
	}

	return fw.limit - fw.count
}

// LeakyBucket implements a leaky bucket rate limiter
type LeakyBucket struct {
	rate     float64 // requests per second
	capacity int
	queue    chan struct{}
}

// NewLeakyBucket creates a new leaky bucket
func NewLeakyBucket(rate float64, capacity int) *LeakyBucket {
	lb := &LeakyBucket{
		rate:     rate,
		capacity: capacity,
		queue:    make(chan struct{}, capacity),
	}

	go lb.leak()

	return lb
}

// leak drains the bucket at a fixed rate
func (lb *LeakyBucket) leak() {
	interval := time.Duration(float64(time.Second) / lb.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-lb.queue:
		default:
		}
	}
}

// Allow checks if a request is allowed
func (lb *LeakyBucket) Allow() bool {
	select {
	case lb.queue <- struct{}{}:
		return true
	default:
		return false
	}
}

// Wait waits until a request is allowed
func (lb *LeakyBucket) Wait(ctx context.Context) error {
	select {
	case lb.queue <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
