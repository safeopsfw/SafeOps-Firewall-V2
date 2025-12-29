package tls_integration

import (
	"crypto"
	"crypto/x509"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Configuration
// ============================================================================

// CacheConfig configures the certificate cache.
type CacheConfig struct {
	MaxSize         int           // Maximum number of certificates to cache
	DefaultTTL      time.Duration // Default time-to-live for cached certificates
	CleanupInterval time.Duration // Interval for cleanup worker
	Enabled         bool          // Enable/disable caching
}

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		MaxSize:         10000,
		DefaultTTL:      24 * time.Hour,
		CleanupInterval: 15 * time.Minute,
		Enabled:         true,
	}
}

// ============================================================================
// Cached Certificate
// ============================================================================

// CachedCertificate represents a cached signed certificate.
type CachedCertificate struct {
	Certificate  *x509.Certificate
	PrivateKey   crypto.PrivateKey
	CertPEM      []byte
	KeyPEM       []byte
	Domain       string
	SANs         []string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	AccessCount  int64
	LastAccessed time.Time
}

// IsExpired checks if the cached certificate has expired.
func (c *CachedCertificate) IsExpired() bool {
	now := time.Now()
	// Check cache TTL expiration
	if now.After(c.ExpiresAt) {
		return true
	}
	// Check certificate validity
	if c.Certificate != nil && now.After(c.Certificate.NotAfter) {
		return true
	}
	return false
}

// IncrementAccess updates access statistics.
func (c *CachedCertificate) IncrementAccess() {
	atomic.AddInt64(&c.AccessCount, 1)
	c.LastAccessed = time.Now()
}

// ============================================================================
// Certificate Cache
// ============================================================================

// CertificateCache provides in-memory certificate caching.
type CertificateCache struct {
	mu           sync.RWMutex
	certificates map[string]*CachedCertificate
	config       *CacheConfig

	// Statistics
	hits        int64
	misses      int64
	evictions   int64
	expirations int64

	// Background cleanup
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewCertificateCache creates a new certificate cache.
func NewCertificateCache(config *CacheConfig) *CertificateCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	cache := &CertificateCache{
		certificates: make(map[string]*CachedCertificate),
		config:       config,
		stopCh:       make(chan struct{}),
	}

	return cache
}

// Start starts the background cleanup worker.
func (c *CertificateCache) Start() {
	if !c.config.Enabled {
		return
	}

	c.wg.Add(1)
	go c.cleanupWorker()
}

// Stop stops the cleanup worker and clears the cache.
func (c *CertificateCache) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

// ============================================================================
// Get/Set Operations
// ============================================================================

// Get retrieves a certificate from cache by domain.
func (c *CertificateCache) Get(domain string) (*CachedCertificate, bool) {
	if !c.config.Enabled {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	normalizedDomain := normalizeDomain(domain)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Try exact match
	if cert, ok := c.certificates[normalizedDomain]; ok {
		if !cert.IsExpired() {
			cert.IncrementAccess()
			atomic.AddInt64(&c.hits, 1)
			return cert, true
		}
	}

	// Try wildcard match
	wildcardKey := getWildcardKey(normalizedDomain)
	if wildcardKey != "" {
		if cert, ok := c.certificates[wildcardKey]; ok {
			if !cert.IsExpired() {
				cert.IncrementAccess()
				atomic.AddInt64(&c.hits, 1)
				return cert, true
			}
		}
	}

	atomic.AddInt64(&c.misses, 1)
	return nil, false
}

// Set stores a certificate in the cache.
func (c *CertificateCache) Set(domain string, cert *CachedCertificate) {
	if !c.config.Enabled || cert == nil {
		return
	}

	normalizedDomain := normalizeDomain(domain)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict
	if len(c.certificates) >= c.config.MaxSize {
		c.evictLRU()
	}

	// Set expiration time
	if cert.ExpiresAt.IsZero() {
		cert.ExpiresAt = time.Now().Add(c.config.DefaultTTL)
	}

	cert.Domain = normalizedDomain
	cert.CreatedAt = time.Now()
	cert.LastAccessed = time.Now()

	c.certificates[normalizedDomain] = cert
}

// SetWithTTL stores a certificate with a custom TTL.
func (c *CertificateCache) SetWithTTL(domain string, cert *CachedCertificate, ttl time.Duration) {
	if cert != nil {
		cert.ExpiresAt = time.Now().Add(ttl)
	}
	c.Set(domain, cert)
}

// Delete removes a certificate from the cache.
func (c *CertificateCache) Delete(domain string) bool {
	normalizedDomain := normalizeDomain(domain)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.certificates[normalizedDomain]; ok {
		delete(c.certificates, normalizedDomain)
		return true
	}
	return false
}

// Clear removes all certificates from the cache.
func (c *CertificateCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certificates = make(map[string]*CachedCertificate)
}

// ============================================================================
// Cache Statistics
// ============================================================================

// CacheStats contains cache statistics.
type CacheStats struct {
	Size        int     `json:"size"`
	MaxSize     int     `json:"max_size"`
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	HitRate     float64 `json:"hit_rate"`
	Evictions   int64   `json:"evictions"`
	Expirations int64   `json:"expirations"`
	Enabled     bool    `json:"enabled"`
}

// GetStats returns current cache statistics.
func (c *CertificateCache) GetStats() *CacheStats {
	c.mu.RLock()
	size := len(c.certificates)
	c.mu.RUnlock()

	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return &CacheStats{
		Size:        size,
		MaxSize:     c.config.MaxSize,
		Hits:        hits,
		Misses:      misses,
		HitRate:     hitRate,
		Evictions:   atomic.LoadInt64(&c.evictions),
		Expirations: atomic.LoadInt64(&c.expirations),
		Enabled:     c.config.Enabled,
	}
}

// Size returns the current number of cached certificates.
func (c *CertificateCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.certificates)
}

// ============================================================================
// Cleanup and Eviction
// ============================================================================

// cleanupWorker runs periodic cleanup of expired certificates.
func (c *CertificateCache) cleanupWorker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.CleanupExpired()
		}
	}
}

// CleanupExpired removes all expired certificates from the cache.
func (c *CertificateCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	expired := 0
	for domain, cert := range c.certificates {
		if cert.IsExpired() {
			delete(c.certificates, domain)
			expired++
		}
	}

	if expired > 0 {
		atomic.AddInt64(&c.expirations, int64(expired))
		log.Printf("[cache] Cleaned up %d expired certificates, cache size: %d", expired, len(c.certificates))
	}

	return expired
}

// evictLRU removes the least recently used certificate.
// Must be called with write lock held.
func (c *CertificateCache) evictLRU() {
	if len(c.certificates) == 0 {
		return
	}

	// Find LRU entry
	var oldestDomain string
	var oldestTime time.Time

	for domain, cert := range c.certificates {
		if oldestDomain == "" || cert.LastAccessed.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = cert.LastAccessed
		}
	}

	if oldestDomain != "" {
		delete(c.certificates, oldestDomain)
		atomic.AddInt64(&c.evictions, 1)
	}
}

// EvictOldest removes N oldest entries from the cache.
func (c *CertificateCache) EvictOldest(count int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if count <= 0 || len(c.certificates) == 0 {
		return 0
	}

	// Collect entries and sort by last accessed
	type entry struct {
		domain       string
		lastAccessed time.Time
	}
	entries := make([]entry, 0, len(c.certificates))
	for domain, cert := range c.certificates {
		entries = append(entries, entry{domain: domain, lastAccessed: cert.LastAccessed})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastAccessed.Before(entries[j].lastAccessed)
	})

	evicted := 0
	for i := 0; i < count && i < len(entries); i++ {
		delete(c.certificates, entries[i].domain)
		evicted++
	}

	atomic.AddInt64(&c.evictions, int64(evicted))
	return evicted
}

// ============================================================================
// Wildcard Support
// ============================================================================

// getWildcardKey returns the wildcard cache key for a domain.
// For "sub.example.com", returns "*.example.com".
func getWildcardKey(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	// Replace first part with wildcard
	parts[0] = "*"
	return strings.Join(parts, ".")
}

// normalizeDomain normalizes a domain name for cache key.
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// MatchesDomain checks if a cached certificate matches the requested domain.
func (c *CachedCertificate) MatchesDomain(domain string) bool {
	normalizedDomain := normalizeDomain(domain)

	// Exact match
	if normalizeDomain(c.Domain) == normalizedDomain {
		return true
	}

	// Check SANs
	for _, san := range c.SANs {
		normalizedSAN := normalizeDomain(san)
		if normalizedSAN == normalizedDomain {
			return true
		}
		// Wildcard SAN match
		if strings.HasPrefix(normalizedSAN, "*.") {
			suffix := normalizedSAN[2:] // Remove "*."
			if strings.HasSuffix(normalizedDomain, suffix) {
				parts := strings.Split(normalizedDomain, ".")
				if len(parts) >= 2 && strings.Join(parts[1:], ".") == suffix {
					return true
				}
			}
		}
	}

	return false
}

// ============================================================================
// Cache Warming
// ============================================================================

// WarmupConfig configures cache warming.
type WarmupConfig struct {
	Enabled bool
	Domains []string
}

// Warmup pre-populates the cache with certificates for specified domains.
// The signFunc should be a function that signs certificates for domains.
func (c *CertificateCache) Warmup(domains []string, signFunc func(domain string) (*CachedCertificate, error)) int {
	if !c.config.Enabled || signFunc == nil {
		return 0
	}

	warmed := 0
	for _, domain := range domains {
		cert, err := signFunc(domain)
		if err != nil {
			log.Printf("[cache] Warmup failed for %s: %v", domain, err)
			continue
		}
		c.Set(domain, cert)
		warmed++
	}

	if warmed > 0 {
		log.Printf("[cache] Warmed up %d certificates", warmed)
	}

	return warmed
}

// ============================================================================
// Utility Functions
// ============================================================================

// GetDomains returns a list of all cached domain names.
func (c *CertificateCache) GetDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	domains := make([]string, 0, len(c.certificates))
	for domain := range c.certificates {
		domains = append(domains, domain)
	}
	return domains
}

// Contains checks if a domain is in the cache (regardless of expiration).
func (c *CertificateCache) Contains(domain string) bool {
	normalizedDomain := normalizeDomain(domain)

	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.certificates[normalizedDomain]
	return ok
}

// GetExpiringSoon returns certificates expiring within the specified duration.
func (c *CertificateCache) GetExpiringSoon(within time.Duration) []*CachedCertificate {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cutoff := time.Now().Add(within)
	expiring := make([]*CachedCertificate, 0)

	for _, cert := range c.certificates {
		if cert.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, cert)
		}
	}

	return expiring
}
