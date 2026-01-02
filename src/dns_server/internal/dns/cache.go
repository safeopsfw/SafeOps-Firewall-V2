// Package dns implements DNS protocol handling including cache, response building, and UDP server.
package dns

import (
	"strings"
	"sync"
	"time"

	"dns_server/internal/models"
)

// =============================================================================
// DNS CACHE - 50,000 entry in-memory cache with LRU eviction
// =============================================================================

// DNSCache provides thread-safe in-memory DNS response caching.
// Supports 50,000 entries with O(1) lookup and LRU eviction policy.
type DNSCache struct {
	// entries stores domain names mapped to CacheEntry pointers
	entries map[string]*models.CacheEntry

	// mutex provides reader-writer lock for thread-safe concurrent access
	mutex sync.RWMutex

	// maxSize is the maximum number of entries allowed (50,000 for Phase 1)
	maxSize int

	// lruList tracks domain access order for LRU eviction
	// Most recently accessed domains are at the end
	lruList []string

	// stats tracks cache performance metrics
	stats CacheStats
}

// CacheStats contains cache performance metrics.
type CacheStats struct {
	// Hits is the total number of successful cache lookups
	Hits uint64

	// Misses is the total number of cache lookups where entry not found or expired
	Misses uint64

	// Evictions is the total number of entries removed due to capacity limits
	Evictions uint64

	// CurrentSize is the current number of entries in cache
	CurrentSize int
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewDNSCache creates a new DNS cache with the specified maximum size.
// For Phase 1, use 50,000 for production or smaller values for testing.
func NewDNSCache(maxSize int) *DNSCache {
	return &DNSCache{
		entries: make(map[string]*models.CacheEntry, maxSize),
		maxSize: maxSize,
		lruList: make([]string, 0, maxSize),
		stats:   CacheStats{},
	}
}

// =============================================================================
// CACHE OPERATIONS
// =============================================================================

// Get retrieves a cache entry for the given domain name.
// Returns the CacheEntry and CacheResult indicating hit/miss/expired.
// Domain lookup is case-insensitive.
func (c *DNSCache) Get(domain string) (*models.CacheEntry, models.CacheResult) {
	// Normalize domain to lowercase for case-insensitive lookup
	key := strings.ToLower(domain)

	// Acquire read lock for concurrent access
	c.mutex.RLock()
	entry, exists := c.entries[key]
	c.mutex.RUnlock()

	// Cache miss - entry not found
	if !exists {
		c.mutex.Lock()
		c.stats.Misses++
		c.mutex.Unlock()
		return nil, models.CacheMiss
	}

	// Check if entry has expired
	if entry.IsExpired() {
		// Upgrade to write lock to delete expired entry
		c.mutex.Lock()
		delete(c.entries, key)
		c.removeLRU(key)
		c.stats.Misses++
		c.stats.CurrentSize = len(c.entries)
		c.mutex.Unlock()
		return nil, models.CacheExpired
	}

	// Cache hit - update LRU position and stats
	c.mutex.Lock()
	c.updateLRU(key)
	c.stats.Hits++
	c.mutex.Unlock()

	return entry, models.CacheHit
}

// Set inserts or updates a cache entry for the given domain.
// If cache is at capacity, evicts the least recently used entry.
func (c *DNSCache) Set(domain string, ip string, ttl int) {
	// Normalize domain to lowercase
	key := strings.ToLower(domain)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if domain already exists (update case)
	if existing, exists := c.entries[key]; exists {
		existing.IP = ip
		existing.TTL = ttl
		existing.Timestamp = time.Now()
		c.updateLRU(key)
		return
	}

	// Evict LRU entry if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	// Create new cache entry
	c.entries[key] = &models.CacheEntry{
		IP:          ip,
		TTL:         ttl,
		Timestamp:   time.Now(),
		OriginalTTL: ttl,
		QueryType:   models.QueryTypeA,
	}

	// Add to LRU list
	c.lruList = append(c.lruList, key)
	c.stats.CurrentSize = len(c.entries)
}

// SetWithType inserts or updates a cache entry with explicit query type.
func (c *DNSCache) SetWithType(domain string, ip string, ttl int, queryType string) {
	key := strings.ToLower(domain)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if existing, exists := c.entries[key]; exists {
		existing.IP = ip
		existing.TTL = ttl
		existing.Timestamp = time.Now()
		existing.QueryType = queryType
		c.updateLRU(key)
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[key] = &models.CacheEntry{
		IP:          ip,
		TTL:         ttl,
		Timestamp:   time.Now(),
		OriginalTTL: ttl,
		QueryType:   queryType,
	}

	c.lruList = append(c.lruList, key)
	c.stats.CurrentSize = len(c.entries)
}

// Delete removes a specific entry from the cache.
// Returns true if entry existed and was deleted.
func (c *DNSCache) Delete(domain string) bool {
	key := strings.ToLower(domain)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.entries[key]; !exists {
		return false
	}

	delete(c.entries, key)
	c.removeLRU(key)
	c.stats.Evictions++
	c.stats.CurrentSize = len(c.entries)
	return true
}

// Clear removes all entries from the cache.
func (c *DNSCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.entries = make(map[string]*models.CacheEntry, c.maxSize)
	c.lruList = make([]string, 0, c.maxSize)
	c.stats = CacheStats{}
}

// =============================================================================
// STATISTICS
// =============================================================================

// GetStats returns a copy of current cache statistics.
func (c *DNSCache) GetStats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return CacheStats{
		Hits:        c.stats.Hits,
		Misses:      c.stats.Misses,
		Evictions:   c.stats.Evictions,
		CurrentSize: c.stats.CurrentSize,
	}
}

// Size returns the current number of entries in the cache.
func (c *DNSCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.entries)
}

// HitRate returns the cache hit rate as a percentage (0-100).
func (c *DNSCache) HitRate() float64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	total := c.stats.Hits + c.stats.Misses
	if total == 0 {
		return 0.0
	}
	return float64(c.stats.Hits) / float64(total) * 100.0
}

// =============================================================================
// LRU MANAGEMENT (internal methods - caller must hold lock)
// =============================================================================

// evictLRU removes the least recently used entry from the cache.
// Caller must hold write lock.
func (c *DNSCache) evictLRU() {
	if len(c.lruList) == 0 {
		return
	}

	// Remove first entry (oldest/least recently used)
	oldestKey := c.lruList[0]
	c.lruList = c.lruList[1:]

	delete(c.entries, oldestKey)
	c.stats.Evictions++
}

// updateLRU moves a domain to the end of the LRU list (most recently used).
// Caller must hold write lock.
func (c *DNSCache) updateLRU(key string) {
	// Find and remove from current position
	for i, k := range c.lruList {
		if k == key {
			c.lruList = append(c.lruList[:i], c.lruList[i+1:]...)
			break
		}
	}
	// Append to end (most recently used)
	c.lruList = append(c.lruList, key)
}

// removeLRU removes a domain from the LRU list.
// Caller must hold write lock.
func (c *DNSCache) removeLRU(key string) {
	for i, k := range c.lruList {
		if k == key {
			c.lruList = append(c.lruList[:i], c.lruList[i+1:]...)
			return
		}
	}
}
