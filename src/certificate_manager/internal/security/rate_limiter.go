package security

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Configuration
// ============================================================================

// RateLimitConfig configures the rate limiter.
type RateLimitConfig struct {
	Enabled          bool
	PerDomainPerHour int           // Max certs per domain per hour
	PerDomainPerDay  int           // Max certs per domain per day
	PerClientPerHour int           // Max requests per client per hour
	GlobalPerMinute  int           // Max certs per minute globally
	GlobalPerHour    int           // Max certs per hour globally
	BurstSize        int           // Burst capacity
	ExemptIPs        []string      // IPs exempt from rate limiting
	ExemptDomains    []string      // Domains exempt from rate limiting
	CleanupInterval  time.Duration // Cleanup interval for expired buckets
}

// DefaultRateLimitConfig returns default configuration.
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled:          true,
		PerDomainPerHour: 10,
		PerDomainPerDay:  50,
		PerClientPerHour: 100,
		GlobalPerMinute:  50,
		GlobalPerHour:    1000,
		BurstSize:        5,
		CleanupInterval:  10 * time.Minute,
	}
}

// ============================================================================
// Token Bucket
// ============================================================================

// TokenBucket implements the token bucket algorithm.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket.
func NewTokenBucket(capacity float64, refillRate float64) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow attempts to consume a token.
func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefill = now

	// Check if token available
	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// Tokens returns current token count.
func (b *TokenBucket) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}

// TimeUntilAvailable returns duration until a token is available.
func (b *TokenBucket) TimeUntilAvailable() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tokens >= 1 {
		return 0
	}

	// Calculate time to refill 1 token
	needed := 1 - b.tokens
	seconds := needed / b.refillRate
	return time.Duration(seconds * float64(time.Second))
}

// ============================================================================
// Rate Limiter
// ============================================================================

// RateLimiter provides multi-level rate limiting.
type RateLimiter struct {
	config *RateLimitConfig

	// Domain-level limiters
	domainMu      sync.RWMutex
	domainBuckets map[string]*TokenBucket

	// Client-level limiters
	clientMu      sync.RWMutex
	clientBuckets map[string]*TokenBucket

	// Global limiter
	globalBucket *TokenBucket

	// Exemptions
	exemptIPs     map[string]bool
	exemptDomains map[string]bool

	// Statistics
	totalRequests       int64
	allowedRequests     int64
	rateLimitedRequests int64

	// Background cleanup
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	rl := &RateLimiter{
		config:        config,
		domainBuckets: make(map[string]*TokenBucket),
		clientBuckets: make(map[string]*TokenBucket),
		exemptIPs:     make(map[string]bool),
		exemptDomains: make(map[string]bool),
		stopCh:        make(chan struct{}),
	}

	// Initialize global bucket
	// Global: X per hour = X/3600 per second
	globalRate := float64(config.GlobalPerHour) / 3600.0
	rl.globalBucket = NewTokenBucket(float64(config.GlobalPerMinute), globalRate)

	// Build exemption maps
	for _, ip := range config.ExemptIPs {
		rl.exemptIPs[ip] = true
	}
	for _, domain := range config.ExemptDomains {
		rl.exemptDomains[strings.ToLower(domain)] = true
	}

	return rl
}

// Start starts the background cleanup goroutine.
func (r *RateLimiter) Start() {
	r.wg.Add(1)
	go r.cleanupLoop()
}

// Stop stops the rate limiter.
func (r *RateLimiter) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// ============================================================================
// Rate Limit Checking
// ============================================================================

// Allow checks all rate limits and returns whether the request is allowed.
func (r *RateLimiter) Allow(domain, clientID string) bool {
	if !r.config.Enabled {
		return true
	}

	atomic.AddInt64(&r.totalRequests, 1)

	// Check exemptions
	if r.IsExempt(clientID, domain) {
		atomic.AddInt64(&r.allowedRequests, 1)
		return true
	}

	// Check global limit
	if !r.checkGlobalLimit() {
		atomic.AddInt64(&r.rateLimitedRequests, 1)
		return false
	}

	// Check domain limit
	if !r.checkDomainLimit(domain) {
		atomic.AddInt64(&r.rateLimitedRequests, 1)
		return false
	}

	// Check client limit
	if !r.checkClientLimit(clientID) {
		atomic.AddInt64(&r.rateLimitedRequests, 1)
		return false
	}

	atomic.AddInt64(&r.allowedRequests, 1)
	return true
}

// checkGlobalLimit checks the global rate limit.
func (r *RateLimiter) checkGlobalLimit() bool {
	return r.globalBucket.Allow()
}

// checkDomainLimit checks the per-domain rate limit.
func (r *RateLimiter) checkDomainLimit(domain string) bool {
	domain = strings.ToLower(domain)

	r.domainMu.Lock()
	bucket, exists := r.domainBuckets[domain]
	if !exists {
		// Create new bucket: X per hour = X/3600 per second
		rate := float64(r.config.PerDomainPerHour) / 3600.0
		capacity := float64(r.config.BurstSize)
		bucket = NewTokenBucket(capacity, rate)
		r.domainBuckets[domain] = bucket
	}
	r.domainMu.Unlock()

	return bucket.Allow()
}

// checkClientLimit checks the per-client rate limit.
func (r *RateLimiter) checkClientLimit(clientID string) bool {
	if clientID == "" {
		return true // No client ID, skip client limit
	}

	r.clientMu.Lock()
	bucket, exists := r.clientBuckets[clientID]
	if !exists {
		// Create new bucket
		rate := float64(r.config.PerClientPerHour) / 3600.0
		capacity := float64(r.config.BurstSize * 2)
		bucket = NewTokenBucket(capacity, rate)
		r.clientBuckets[clientID] = bucket
	}
	r.clientMu.Unlock()

	return bucket.Allow()
}

// ============================================================================
// Exemptions
// ============================================================================

// IsExempt checks if a client or domain is exempt from rate limiting.
func (r *RateLimiter) IsExempt(clientID, domain string) bool {
	// Check IP exemption
	if r.exemptIPs[clientID] {
		return true
	}

	// Extract IP from clientID if it contains port
	ip := clientID
	if idx := strings.LastIndex(clientID, ":"); idx != -1 {
		ip = clientID[:idx]
	}
	if r.exemptIPs[ip] {
		return true
	}

	// Check domain exemption
	if r.exemptDomains[strings.ToLower(domain)] {
		return true
	}

	return false
}

// AddExemptIP adds an IP to the exemption list.
func (r *RateLimiter) AddExemptIP(ip string) {
	r.exemptIPs[ip] = true
}

// AddExemptDomain adds a domain to the exemption list.
func (r *RateLimiter) AddExemptDomain(domain string) {
	r.exemptDomains[strings.ToLower(domain)] = true
}

// ============================================================================
// HTTP Response
// ============================================================================

// RateLimitResult contains rate limit check results.
type RateLimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
	Limit      int
	Remaining  int
	ResetTime  time.Time
}

// HandleRateLimitExceeded sends an HTTP 429 response.
func HandleRateLimitExceeded(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.WriteHeader(http.StatusTooManyRequests)

	body := fmt.Sprintf(`{"error":"rate_limit_exceeded","message":"Too many certificate requests. Try again later.","retry_after":%d}`,
		int(retryAfter.Seconds()))
	w.Write([]byte(body))
}

// SetRateLimitHeaders sets rate limit headers on a response.
func SetRateLimitHeaders(w http.ResponseWriter, limit, remaining int, resetTime time.Time) {
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
}

// ============================================================================
// Statistics
// ============================================================================

// RateLimitStats contains rate limiter statistics.
type RateLimitStats struct {
	TotalRequests       int64   `json:"total_requests"`
	AllowedRequests     int64   `json:"allowed_requests"`
	RateLimitedRequests int64   `json:"rate_limited_requests"`
	HitRate             float64 `json:"hit_rate_percent"`
	DomainBucketCount   int     `json:"domain_bucket_count"`
	ClientBucketCount   int     `json:"client_bucket_count"`
	GlobalTokens        float64 `json:"global_tokens_remaining"`
}

// GetStats returns rate limiter statistics.
func (r *RateLimiter) GetStats() *RateLimitStats {
	total := atomic.LoadInt64(&r.totalRequests)
	limited := atomic.LoadInt64(&r.rateLimitedRequests)

	var hitRate float64
	if total > 0 {
		hitRate = float64(limited) / float64(total) * 100
	}

	r.domainMu.RLock()
	domainCount := len(r.domainBuckets)
	r.domainMu.RUnlock()

	r.clientMu.RLock()
	clientCount := len(r.clientBuckets)
	r.clientMu.RUnlock()

	return &RateLimitStats{
		TotalRequests:       total,
		AllowedRequests:     atomic.LoadInt64(&r.allowedRequests),
		RateLimitedRequests: limited,
		HitRate:             hitRate,
		DomainBucketCount:   domainCount,
		ClientBucketCount:   clientCount,
		GlobalTokens:        r.globalBucket.Tokens(),
	}
}

// ResetStats resets the statistics counters.
func (r *RateLimiter) ResetStats() {
	atomic.StoreInt64(&r.totalRequests, 0)
	atomic.StoreInt64(&r.allowedRequests, 0)
	atomic.StoreInt64(&r.rateLimitedRequests, 0)
}

// ============================================================================
// Cleanup
// ============================================================================

// cleanupLoop periodically removes stale rate limit buckets.
func (r *RateLimiter) cleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

// cleanup removes buckets that have been full for a while.
func (r *RateLimiter) cleanup() {
	threshold := r.config.CleanupInterval

	// Cleanup domain buckets
	r.domainMu.Lock()
	for domain, bucket := range r.domainBuckets {
		bucket.mu.Lock()
		// Remove if bucket is full and hasn't been used recently
		if bucket.tokens >= bucket.capacity && time.Since(bucket.lastRefill) > threshold {
			delete(r.domainBuckets, domain)
		}
		bucket.mu.Unlock()
	}
	r.domainMu.Unlock()

	// Cleanup client buckets
	r.clientMu.Lock()
	for client, bucket := range r.clientBuckets {
		bucket.mu.Lock()
		if bucket.tokens >= bucket.capacity && time.Since(bucket.lastRefill) > threshold {
			delete(r.clientBuckets, client)
		}
		bucket.mu.Unlock()
	}
	r.clientMu.Unlock()
}

// ============================================================================
// Utility Functions
// ============================================================================

// GetClientIDFromRequest extracts client identifier from HTTP request.
func GetClientIDFromRequest(r *http.Request) string {
	// Try X-Forwarded-For first (behind proxy)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take first IP if multiple
		if idx := strings.Index(forwarded, ","); idx != -1 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// GetRetryAfter calculates a suggested retry time.
func (r *RateLimiter) GetRetryAfter(domain string) time.Duration {
	r.domainMu.RLock()
	bucket, exists := r.domainBuckets[strings.ToLower(domain)]
	r.domainMu.RUnlock()

	if !exists {
		return time.Minute
	}

	return bucket.TimeUntilAvailable()
}
