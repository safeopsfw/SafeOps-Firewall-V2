package rate_limiting

import (
	"sync/atomic"

	"firewall_engine/internal/config"
)

// RateLimiter combines per-IP and global rate limiting with whitelist bypass.
type RateLimiter struct {
	perIP      *PerIPLimiter
	global     *TokenBucket
	whitelist  *config.ParsedWhitelist
	enabled    bool

	allowed  atomic.Int64
	denied   atomic.Int64
}

// RateLimiterStats holds rate limiter statistics
type RateLimiterStats struct {
	Allowed   int64 `json:"allowed"`
	Denied    int64 `json:"denied"`
	ActiveIPs int64 `json:"active_ips"`
}

// NewRateLimiter creates a combined rate limiter from detection config
func NewRateLimiter(cfg config.RateLimitConfig, whitelist *config.ParsedWhitelist) *RateLimiter {
	rl := &RateLimiter{
		enabled:   cfg.Enabled,
		whitelist: whitelist,
	}

	if !cfg.Enabled {
		return rl
	}

	rl.perIP = NewPerIPLimiter(
		float64(cfg.DefaultRate),
		cfg.BurstSize,
		cfg.CleanupIntervalSeconds,
	)

	rl.global = NewTokenBucket(float64(cfg.GlobalRate), cfg.GlobalRate*2)

	return rl
}

// Allow checks if a packet from the given IP should be allowed.
// Trusted/whitelisted IPs bypass rate limiting entirely.
func (rl *RateLimiter) Allow(ip string) bool {
	if !rl.enabled {
		return true
	}

	// Whitelist bypass
	if rl.whitelist != nil && rl.whitelist.Contains(ip) {
		rl.allowed.Add(1)
		return true
	}

	// Global rate check first (cheaper)
	if !rl.global.Allow() {
		rl.denied.Add(1)
		return false
	}

	// Per-IP rate check
	if !rl.perIP.Allow(ip) {
		rl.denied.Add(1)
		return false
	}

	rl.allowed.Add(1)
	return true
}

// Stats returns rate limiter statistics
func (rl *RateLimiter) Stats() RateLimiterStats {
	var activeIPs int64
	if rl.perIP != nil {
		activeIPs = rl.perIP.ActiveCount()
	}
	return RateLimiterStats{
		Allowed:   rl.allowed.Load(),
		Denied:    rl.denied.Load(),
		ActiveIPs: activeIPs,
	}
}

// Stop cleans up the rate limiter
func (rl *RateLimiter) Stop() {
	if rl.perIP != nil {
		rl.perIP.Stop()
	}
}
