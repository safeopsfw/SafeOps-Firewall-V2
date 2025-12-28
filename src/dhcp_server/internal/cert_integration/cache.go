// Package cert_integration provides CA certificate integration for DHCP server.
// This file implements in-memory caching for Certificate Manager responses.
package cert_integration

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Cache Configuration
// ============================================================================

// CacheConfig holds cache settings.
type CacheConfig struct {
	TTL             time.Duration
	MaxEntries      int
	CleanupInterval time.Duration
	MemoryLimitMB   int // 0 = unlimited
	Enabled         bool
}

// DefaultCacheConfig returns sensible defaults.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		TTL:             time.Hour, // 1 hour
		MaxEntries:      1000,
		CleanupInterval: 5 * time.Minute,
		MemoryLimitMB:   0, // unlimited
		Enabled:         true,
	}
}

// ============================================================================
// Cache Entry
// ============================================================================

// CacheEntry represents a cached Certificate Manager response.
type CacheEntry struct {
	Info         *CertificateInfo
	CreatedAt    time.Time
	LastAccessed time.Time
	AccessCount  int64
	SizeBytes    int
	PoolID       string
}

// IsExpired checks if the entry has exceeded TTL.
func (e *CacheEntry) IsExpired(ttl time.Duration) bool {
	return time.Since(e.CreatedAt) > ttl
}

// Age returns the entry age.
func (e *CacheEntry) Age() time.Duration {
	return time.Since(e.CreatedAt)
}

// ============================================================================
// Certificate Cache
// ============================================================================

// CertCache provides thread-safe caching for Certificate Manager responses.
type CertCache struct {
	mu      sync.RWMutex
	config  *CacheConfig
	entries map[string]*CacheEntry

	// Background cleanup
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Statistics (atomic for lock-free access)
	hits          int64
	misses        int64
	evictions     int64
	sets          int64
	invalidations int64
}

// NewCertCache creates a new certificate cache.
func NewCertCache(config *CacheConfig) *CertCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	c := &CertCache{
		config:   config,
		entries:  make(map[string]*CacheEntry, config.MaxEntries),
		stopChan: make(chan struct{}),
	}

	return c
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the background cleanup goroutine.
func (c *CertCache) Start() {
	c.wg.Add(1)
	go c.cleanupLoop()
}

// Stop stops the cache and cleanup goroutine.
func (c *CertCache) Stop() {
	close(c.stopChan)
	c.wg.Wait()
}

func (c *CertCache) cleanupLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopChan:
			return
		}
	}
}

func (c *CertCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	evicted := 0

	for key, entry := range c.entries {
		if now.Sub(entry.CreatedAt) > c.config.TTL {
			delete(c.entries, key)
			evicted++
		}
	}

	if evicted > 0 {
		atomic.AddInt64(&c.evictions, int64(evicted))
	}
}

// ============================================================================
// Get Operation
// ============================================================================

// Get retrieves a cached entry by gateway IP.
func (c *CertCache) Get(gatewayIP net.IP) *CertificateInfo {
	if !c.config.Enabled {
		return nil
	}

	key := c.makeKey(gatewayIP)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil
	}

	// Check TTL
	if entry.IsExpired(c.config.TTL) {
		atomic.AddInt64(&c.misses, 1)
		// Trigger async cleanup
		go c.evictEntry(key)
		return nil
	}

	// Update access time (upgrade to write lock)
	c.mu.Lock()
	entry.LastAccessed = time.Now()
	entry.AccessCount++
	c.mu.Unlock()

	atomic.AddInt64(&c.hits, 1)
	return entry.Info
}

// GetWithMetadata retrieves entry with metadata.
func (c *CertCache) GetWithMetadata(gatewayIP net.IP) (*CacheEntry, bool) {
	if !c.config.Enabled {
		return nil, false
	}

	key := c.makeKey(gatewayIP)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists || entry.IsExpired(c.config.TTL) {
		return nil, false
	}

	return entry, true
}

// ============================================================================
// Set Operation
// ============================================================================

// Set stores a Certificate Manager response in cache.
func (c *CertCache) Set(gatewayIP net.IP, info *CertificateInfo) {
	if !c.config.Enabled || info == nil {
		return
	}

	key := c.makeKey(gatewayIP)
	now := time.Now()

	entry := &CacheEntry{
		Info:         info,
		CreatedAt:    now,
		LastAccessed: now,
		AccessCount:  0,
		SizeBytes:    c.estimateSize(info),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check capacity before adding
	if len(c.entries) >= c.config.MaxEntries {
		c.evictLRU()
	}

	c.entries[key] = entry
	atomic.AddInt64(&c.sets, 1)
}

// SetWithPool stores entry with pool ID.
func (c *CertCache) SetWithPool(gatewayIP net.IP, info *CertificateInfo, poolID string) {
	if !c.config.Enabled || info == nil {
		return
	}

	key := c.makeKeyWithPool(gatewayIP, poolID)
	now := time.Now()

	entry := &CacheEntry{
		Info:         info,
		CreatedAt:    now,
		LastAccessed: now,
		AccessCount:  0,
		SizeBytes:    c.estimateSize(info),
		PoolID:       poolID,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.config.MaxEntries {
		c.evictLRU()
	}

	c.entries[key] = entry
	atomic.AddInt64(&c.sets, 1)
}

// ============================================================================
// Eviction
// ============================================================================

func (c *CertCache) evictEntry(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; exists {
		delete(c.entries, key)
		atomic.AddInt64(&c.evictions, 1)
	}
}

func (c *CertCache) evictLRU() {
	// Find least recently accessed entry
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.LastAccessed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccessed
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		atomic.AddInt64(&c.evictions, 1)
	}
}

// ============================================================================
// Invalidation
// ============================================================================

// Invalidate removes a specific entry from cache.
func (c *CertCache) Invalidate(gatewayIP net.IP) bool {
	key := c.makeKey(gatewayIP)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; exists {
		delete(c.entries, key)
		atomic.AddInt64(&c.invalidations, 1)
		return true
	}
	return false
}

// InvalidateAll clears the entire cache.
func (c *CertCache) InvalidateAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.entries)
	c.entries = make(map[string]*CacheEntry, c.config.MaxEntries)
	atomic.AddInt64(&c.invalidations, int64(count))

	return count
}

// InvalidateByPool removes all entries for a specific pool.
func (c *CertCache) InvalidateByPool(poolID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for key, entry := range c.entries {
		if entry.PoolID == poolID {
			delete(c.entries, key)
			count++
		}
	}

	if count > 0 {
		atomic.AddInt64(&c.invalidations, int64(count))
	}
	return count
}

// ============================================================================
// Cache Key Generation
// ============================================================================

func (c *CertCache) makeKey(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}

	// Normalize to canonical form
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (c *CertCache) makeKeyWithPool(ip net.IP, poolID string) string {
	return c.makeKey(ip) + ":" + poolID
}

// ============================================================================
// Size Estimation
// ============================================================================

func (c *CertCache) estimateSize(info *CertificateInfo) int {
	if info == nil {
		return 0
	}

	size := len(info.CAURL) + len(info.WPADURL) + len(info.CRLURL) + len(info.OCSPURL)
	for _, script := range info.InstallScriptURLs {
		size += len(script)
	}

	// Add overhead for struct and metadata
	size += 100

	return size
}

// ============================================================================
// Statistics
// ============================================================================

// CacheStats holds cache statistics.
type CacheStats struct {
	Hits          int64
	Misses        int64
	Sets          int64
	Evictions     int64
	Invalidations int64
	EntryCount    int
	HitRate       float64
	MemoryBytes   int64
	OldestEntry   time.Duration
	NewestEntry   time.Duration
}

// GetStats returns cache statistics.
func (c *CertCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)

	stats := CacheStats{
		Hits:          hits,
		Misses:        misses,
		Sets:          atomic.LoadInt64(&c.sets),
		Evictions:     atomic.LoadInt64(&c.evictions),
		Invalidations: atomic.LoadInt64(&c.invalidations),
		EntryCount:    len(c.entries),
	}

	// Calculate hit rate
	total := hits + misses
	if total > 0 {
		stats.HitRate = float64(hits) / float64(total) * 100
	}

	// Calculate memory usage and age range
	var oldest, newest time.Time
	for _, entry := range c.entries {
		stats.MemoryBytes += int64(entry.SizeBytes)

		if oldest.IsZero() || entry.CreatedAt.Before(oldest) {
			oldest = entry.CreatedAt
		}
		if newest.IsZero() || entry.CreatedAt.After(newest) {
			newest = entry.CreatedAt
		}
	}

	if !oldest.IsZero() {
		stats.OldestEntry = time.Since(oldest)
	}
	if !newest.IsZero() {
		stats.NewestEntry = time.Since(newest)
	}

	return stats
}

// GetHitRate returns the cache hit rate percentage.
func (c *CertCache) GetHitRate() float64 {
	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// GetEntryCount returns current number of entries.
func (c *CertCache) GetEntryCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GetMemoryUsage returns estimated memory usage in bytes.
func (c *CertCache) GetMemoryUsage() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var total int64
	for _, entry := range c.entries {
		total += int64(entry.SizeBytes)
	}
	return total
}

// ============================================================================
// Configuration Updates
// ============================================================================

// UpdateTTL updates the cache TTL.
func (c *CertCache) UpdateTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.TTL = ttl
}

// UpdateMaxEntries updates the maximum entries limit.
func (c *CertCache) UpdateMaxEntries(max int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.MaxEntries = max

	// Evict if over new limit
	for len(c.entries) > max {
		c.evictLRU()
	}
}

// SetEnabled enables or disables the cache.
func (c *CertCache) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Enabled = enabled

	if !enabled {
		c.entries = make(map[string]*CacheEntry, c.config.MaxEntries)
	}
}

// IsEnabled returns whether the cache is enabled.
func (c *CertCache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Enabled
}

// ============================================================================
// Utility Methods
// ============================================================================

// Contains checks if an entry exists (regardless of TTL).
func (c *CertCache) Contains(gatewayIP net.IP) bool {
	key := c.makeKey(gatewayIP)

	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.entries[key]
	return exists
}

// GetEntryAge returns the age of an entry.
func (c *CertCache) GetEntryAge(gatewayIP net.IP) (time.Duration, bool) {
	key := c.makeKey(gatewayIP)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return 0, false
	}
	return entry.Age(), true
}

// GetAllKeys returns all cache keys.
func (c *CertCache) GetAllKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	return keys
}
