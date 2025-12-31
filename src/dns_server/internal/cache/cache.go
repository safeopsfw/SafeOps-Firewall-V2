// Package cache implements DNS response caching.
package cache

import (
	"sync"
	"time"

	"safeops/dns_server/internal/protocol"
)

// ============================================================================
// DNS Cache
// ============================================================================

// Cache stores DNS responses for fast lookup
type Cache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	maxSize int
	stopCh  chan struct{}
}

// CacheEntry holds a cached DNS response
type CacheEntry struct {
	Records   []protocol.ResourceRecord
	ExpiresAt time.Time
	HitCount  int64
	CreatedAt time.Time
}

// Config holds cache configuration
type Config struct {
	MaxSize     int           // Maximum entries
	DefaultTTL  time.Duration // Default TTL if not specified
	CleanupFreq time.Duration // How often to clean expired entries
}

// DefaultConfig returns default cache configuration
func DefaultConfig() *Config {
	return &Config{
		MaxSize:     10000,
		DefaultTTL:  5 * time.Minute,
		CleanupFreq: 1 * time.Minute,
	}
}

// New creates a new DNS cache
func New(cfg *Config) *Cache {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	c := &Cache{
		entries: make(map[string]*CacheEntry),
		maxSize: cfg.MaxSize,
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go c.cleanupLoop(cfg.CleanupFreq)

	return c
}

// ============================================================================
// Cache Operations
// ============================================================================

// Get retrieves records from cache
func (c *Cache) Get(key string) ([]protocol.ResourceRecord, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		c.Delete(key)
		return nil, false
	}

	// Update hit count
	c.mu.Lock()
	entry.HitCount++
	c.mu.Unlock()

	return entry.Records, true
}

// Set stores records in cache
func (c *Cache) Set(key string, records []protocol.ResourceRecord, ttl time.Duration) {
	if len(records) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictOne()
	}

	c.entries[key] = &CacheEntry{
		Records:   records,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
		HitCount:  0,
	}
}

// Delete removes an entry from cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Flush clears all cache entries
func (c *Cache) Flush() {
	c.mu.Lock()
	c.entries = make(map[string]*CacheEntry)
	c.mu.Unlock()
}

// ============================================================================
// Cache Maintenance
// ============================================================================

func (c *Cache) cleanupLoop(freq time.Duration) {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

func (c *Cache) evictOne() {
	// Simple LRU: evict entry with lowest hit count
	var evictKey string
	var minHits int64 = -1

	for key, entry := range c.entries {
		if minHits == -1 || entry.HitCount < minHits {
			minHits = entry.HitCount
			evictKey = key
		}
	}

	if evictKey != "" {
		delete(c.entries, evictKey)
	}
}

// Stop stops the cleanup goroutine
func (c *Cache) Stop() {
	close(c.stopCh)
}

// ============================================================================
// Statistics
// ============================================================================

// Stats contains cache statistics
type Stats struct {
	Entries   int
	HitCount  int64
	MissCount int64
}

// GetStats returns cache statistics
func (c *Cache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalHits int64
	for _, entry := range c.entries {
		totalHits += entry.HitCount
	}

	return Stats{
		Entries:  len(c.entries),
		HitCount: totalHits,
	}
}

// Size returns current number of entries
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
