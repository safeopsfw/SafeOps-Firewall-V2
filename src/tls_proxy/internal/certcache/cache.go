package certcache

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"tls_proxy/internal/integration"
)

// CertificateEntry represents a cached certificate
type CertificateEntry struct {
	Domain      string
	Certificate *tls.Certificate
	PEMCert     string
	PEMKey      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	HitCount    int64
}

// CertificateCache manages TLS certificates for domains
type CertificateCache struct {
	cache      map[string]*CertificateEntry
	mu         sync.RWMutex
	stepCA     *integration.StepCAClient
	defaultTTL time.Duration
	maxSize    int
}

// NewCertificateCache creates a new certificate cache
func NewCertificateCache(stepCA *integration.StepCAClient, ttl time.Duration, maxSize int) *CertificateCache {
	if maxSize == 0 {
		maxSize = 1000 // Default max 1000 cached certificates
	}
	if ttl == 0 {
		ttl = 24 * time.Hour // Default 24 hour TTL
	}

	cache := &CertificateCache{
		cache:      make(map[string]*CertificateEntry),
		stepCA:     stepCA,
		defaultTTL: ttl,
		maxSize:    maxSize,
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	log.Printf("[Cert Cache] Initialized (max size: %d, TTL: %v)", maxSize, ttl)
	return cache
}

// GetOrGenerate gets a certificate from cache or generates a new one
func (c *CertificateCache) GetOrGenerate(domain string) (*CertificateEntry, error) {
	// Check cache first
	c.mu.RLock()
	entry, found := c.cache[domain]
	c.mu.RUnlock()

	if found && !c.isExpired(entry) {
		// Update hit count
		c.mu.Lock()
		entry.HitCount++
		c.mu.Unlock()

		log.Printf("[Cert Cache] HIT for %s (hits: %d)", domain, entry.HitCount)
		return entry, nil
	}

	// Cache miss or expired - generate new certificate
	log.Printf("[Cert Cache] MISS for %s - generating certificate", domain)

	return c.generateAndCache(domain)
}

// generateAndCache generates a new certificate and caches it
func (c *CertificateCache) generateAndCache(domain string) (*CertificateEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check if another goroutine already generated it
	if entry, found := c.cache[domain]; found && !c.isExpired(entry) {
		return entry, nil
	}

	// Check cache size limit
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	// Request certificate from Step-CA
	certResp, err := c.stepCA.GenerateCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Parse TLS certificate from PEM
	tlsCert, err := tls.X509KeyPair([]byte(certResp.Certificate), []byte(certResp.PrivateKey))
	if err != nil {
		log.Printf("[Cert Cache] Failed to parse certificate PEM: %v", err)
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create cache entry
	entry := &CertificateEntry{
		Domain:      domain,
		Certificate: &tlsCert,
		PEMCert:     certResp.Certificate,
		PEMKey:      certResp.PrivateKey,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(c.defaultTTL),
		HitCount:    1,
	}

	// Store in cache
	c.cache[domain] = entry

	log.Printf("[Cert Cache] ✓ Cached certificate for %s (cache size: %d)", domain, len(c.cache))
	return entry, nil
}

// isExpired checks if a cache entry is expired
func (c *CertificateCache) isExpired(entry *CertificateEntry) bool {
	return time.Now().After(entry.ExpiresAt)
}

// evictOldest removes the oldest cache entry
func (c *CertificateCache) evictOldest() {
	var oldestDomain string
	var oldestTime time.Time

	for domain, entry := range c.cache {
		if oldestDomain == "" || entry.CreatedAt.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = entry.CreatedAt
		}
	}

	if oldestDomain != "" {
		delete(c.cache, oldestDomain)
		log.Printf("[Cert Cache] Evicted oldest entry: %s", oldestDomain)
	}
}

// cleanupLoop periodically removes expired certificates
func (c *CertificateCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup removes expired certificates
func (c *CertificateCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for domain, entry := range c.cache {
		if c.isExpired(entry) {
			delete(c.cache, domain)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[Cert Cache] Cleanup: removed %d expired certificates (cache size: %d)", removed, len(c.cache))
	}
}

// GetStats returns cache statistics
func (c *CertificateCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalHits := int64(0)
	for _, entry := range c.cache {
		totalHits += entry.HitCount
	}

	return map[string]interface{}{
		"size":       len(c.cache),
		"max_size":   c.maxSize,
		"total_hits": totalHits,
		"ttl":        c.defaultTTL.String(),
	}
}

// Clear removes all cached certificates
func (c *CertificateCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CertificateEntry)
	log.Println("[Cert Cache] Cleared all cached certificates")
}

// Remove removes a specific domain from cache
func (c *CertificateCache) Remove(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, found := c.cache[domain]; found {
		delete(c.cache, domain)
		log.Printf("[Cert Cache] Removed certificate for %s", domain)
	}
}
