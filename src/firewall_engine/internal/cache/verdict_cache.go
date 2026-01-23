// Package cache provides high-performance verdict caching for the firewall engine.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Verdict Cache - Main Implementation
// ============================================================================

// VerdictCache combines LRU eviction with TTL expiration for caching
// firewall verdict decisions. It provides O(1) operations and thread safety.
//
// Key Features:
//   - O(1) Get/Set/Delete operations
//   - LRU eviction when capacity reached
//   - TTL expiration with background cleanup
//   - Thread-safe for concurrent access
//   - Per-verdict TTL configuration
//   - Multiple invalidation strategies
//   - Comprehensive statistics
//
// Usage:
//
//	cache, _ := NewVerdictCache(DefaultCacheConfig())
//	cache.Start(ctx)
//	defer cache.Stop()
//
//	// Store verdict
//	cache.Set("key", verdictResult, 60*time.Second)
//
//	// Retrieve verdict
//	if entry, found := cache.Get("key"); found && !entry.IsExpired() {
//	    // Use cached verdict
//	}
type VerdictCache struct {
	// Configuration
	config *CacheConfig

	// LRU cache (handles eviction)
	lru *LRU

	// TTL manager (handles expiration)
	ttlManager *TTLManager

	// Statistics
	stats *CacheStats

	// Logging
	logger *log.Logger

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   atomic.Bool
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once
}

// ============================================================================
// Constructor
// ============================================================================

// NewVerdictCache creates a new verdict cache with the given configuration.
func NewVerdictCache(config *CacheConfig) (*VerdictCache, error) {
	if config == nil {
		config = DefaultCacheConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cache config: %w", err)
	}

	// Create LRU
	lru := NewLRU(config.Capacity)

	// Create TTL config
	ttlConfig := &TTLConfig{
		DefaultTTL:      config.DefaultTTL,
		MinTTL:          1 * time.Second,
		MaxTTL:          24 * time.Hour,
		CleanupInterval: config.CleanupInterval,
		BatchSize:       1000,
		VerdictTTLs: map[models.Verdict]time.Duration{
			models.VerdictAllow:    config.TTLAllow,
			models.VerdictBlock:    config.TTLBlock,
			models.VerdictDrop:     config.TTLDrop,
			models.VerdictRedirect: config.TTLRedirect,
			models.VerdictReject:   config.TTLReject,
		},
	}

	// Create TTL manager
	ttlManager, err := NewTTLManager(ttlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TTL manager: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	vc := &VerdictCache{
		config:     config,
		lru:        lru,
		ttlManager: ttlManager,
		stats:      NewCacheStats(),
		logger:     log.New(log.Writer(), "[CACHE] ", log.LstdFlags|log.Lmicroseconds),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Set cleanup function for TTL manager
	ttlManager.SetCleanupFunc(vc.cleanupExpired)

	return vc, nil
}

// ============================================================================
// Core Cache Operations
// ============================================================================

// Get retrieves a cached verdict by key.
// Returns the entry and true if found and not expired, nil and false otherwise.
func (c *VerdictCache) Get(key string) (*CacheEntry, bool) {
	if c.closed.Load() {
		return nil, false
	}

	if key == "" {
		return nil, false
	}

	startTime := time.Now()

	// Lookup in LRU (also moves to front)
	entry := c.lru.Get(key)

	lookupTime := uint64(time.Since(startTime).Nanoseconds())

	if entry == nil {
		if c.config.EnableStats {
			c.stats.RecordMiss(lookupTime)
		}
		return nil, false
	}

	// Check if expired
	if c.config.EnableExpireOnGet && entry.IsExpired() {
		// Remove expired entry
		c.lru.Remove(key)
		if c.config.EnableStats {
			c.stats.RecordExpiration()
			c.stats.RecordMiss(lookupTime)
		}
		return nil, false
	}

	// Record hit
	if c.config.EnableStats {
		c.stats.RecordHit(lookupTime)
	}

	return entry, true
}

// Set stores a verdict in the cache with the specified TTL.
// If TTL is 0, the default TTL for the verdict type is used.
// If the cache is full, the least recently used entry is evicted.
func (c *VerdictCache) Set(key string, verdict *models.VerdictResult, ttl time.Duration) error {
	if c.closed.Load() {
		return ErrCacheClosed
	}

	if key == "" {
		return ErrKeyEmpty
	}

	if verdict == nil {
		return errors.New("verdict cannot be nil")
	}

	startTime := time.Now()

	// Determine TTL
	if ttl <= 0 {
		ttl = c.config.GetTTLForVerdict(verdict.Verdict)
	}

	// Create entry
	entry := NewCacheEntry(key, verdict, ttl)

	// Insert into LRU
	evicted := c.lru.Put(key, entry)

	insertTime := uint64(time.Since(startTime).Nanoseconds())

	// Update stats
	if c.config.EnableStats {
		c.stats.RecordInsert(insertTime)
		if evicted != nil {
			c.stats.RecordEviction()
		}
	}

	return nil
}

// Delete removes an entry from the cache.
// Returns true if the entry was found and removed.
func (c *VerdictCache) Delete(key string) bool {
	if c.closed.Load() {
		return false
	}

	if key == "" {
		return false
	}

	removed := c.lru.Remove(key)

	if removed && c.config.EnableStats {
		c.stats.RecordDelete()
	}

	return removed
}

// Clear removes all entries from the cache.
func (c *VerdictCache) Clear() {
	if c.closed.Load() {
		return
	}

	c.lru.Clear()

	if c.config.EnableStats {
		c.stats.FullInvalidations.Add(1)
		c.stats.CurrentSize.Store(0)
	}

	c.logger.Println("Cache cleared (full invalidation)")
}

// ============================================================================
// Query Operations
// ============================================================================

// Size returns the current number of entries in the cache.
func (c *VerdictCache) Size() int {
	return c.lru.Size()
}

// Capacity returns the maximum capacity of the cache.
func (c *VerdictCache) Capacity() int {
	return c.lru.Capacity()
}

// Contains returns true if the key exists in the cache.
func (c *VerdictCache) Contains(key string) bool {
	return c.lru.Contains(key)
}

// Keys returns all keys in the cache (most recent first).
func (c *VerdictCache) Keys() []string {
	return c.lru.Keys()
}

// Utilization returns the cache utilization as a percentage.
func (c *VerdictCache) Utilization() float64 {
	return c.lru.Utilization()
}

// ============================================================================
// TTL Cleanup
// ============================================================================

// cleanupExpired removes expired entries from the cache.
// This is called by the TTL manager's background goroutine.
func (c *VerdictCache) cleanupExpired() (int, error) {
	if c.closed.Load() {
		return 0, ErrCacheClosed
	}

	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.IsExpired()
	})

	if removed > 0 && c.config.EnableStats {
		// Note: RecordExpiration is called per-entry, not in bulk
		// The stats are updated via CurrentSize changes in RemoveIf
		for i := 0; i < removed; i++ {
			c.stats.Expirations.Add(1)
			c.stats.CurrentSize.Add(-1)
		}
	}

	return removed, nil
}

// ============================================================================
// Invalidation
// ============================================================================

// Invalidate clears cache entries based on the strategy.
// Returns the number of entries invalidated.
func (c *VerdictCache) Invalidate(strategy InvalidationStrategy, params interface{}) int {
	if c.closed.Load() {
		return 0
	}

	switch strategy {
	case InvalidateAll:
		size := c.lru.Size()
		c.Clear()
		return size

	case InvalidateExpired:
		removed, _ := c.cleanupExpired()
		return removed

	case InvalidateByIP:
		if p, ok := params.(*InvalidationParams); ok && p.IP != "" {
			return c.invalidateByIP(p.IP)
		}
		if ip, ok := params.(string); ok && ip != "" {
			return c.invalidateByIP(ip)
		}

	case InvalidateBySrcIP:
		if p, ok := params.(*InvalidationParams); ok && p.IP != "" {
			return c.invalidateBySrcIP(p.IP)
		}

	case InvalidateByDstIP:
		if p, ok := params.(*InvalidationParams); ok && p.IP != "" {
			return c.invalidateByDstIP(p.IP)
		}

	case InvalidateByRuleID:
		if p, ok := params.(*InvalidationParams); ok && p.RuleID != "" {
			return c.invalidateByRuleID(p.RuleID)
		}
		if ruleID, ok := params.(string); ok && ruleID != "" {
			return c.invalidateByRuleID(ruleID)
		}

	case InvalidateByRuleName:
		if p, ok := params.(*InvalidationParams); ok && p.RuleName != "" {
			return c.invalidateByRuleName(p.RuleName)
		}

	case InvalidateByVerdict:
		if p, ok := params.(*InvalidationParams); ok {
			return c.invalidateByVerdict(p.Verdict)
		}
	}

	return 0
}

// invalidateByIP removes entries matching the IP (source or destination).
func (c *VerdictCache) invalidateByIP(ip string) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return strings.Contains(key, ip)
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	c.logger.Printf("Invalidated %d entries for IP %s", removed, ip)
	return removed
}

// invalidateBySrcIP removes entries with matching source IP.
func (c *VerdictCache) invalidateBySrcIP(ip string) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.SrcIP == ip
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	return removed
}

// invalidateByDstIP removes entries with matching destination IP.
func (c *VerdictCache) invalidateByDstIP(ip string) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.DstIP == ip
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	return removed
}

// invalidateByRuleID removes entries matched by the rule ID.
func (c *VerdictCache) invalidateByRuleID(ruleID string) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.RuleID == ruleID
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	c.logger.Printf("Invalidated %d entries for rule ID %s", removed, ruleID)
	return removed
}

// invalidateByRuleName removes entries matched by rule name.
func (c *VerdictCache) invalidateByRuleName(ruleName string) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.RuleName == ruleName
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	return removed
}

// invalidateByVerdict removes entries with the specified verdict.
func (c *VerdictCache) invalidateByVerdict(verdict models.Verdict) int {
	removed := c.lru.RemoveIf(func(key string, entry *CacheEntry) bool {
		return entry.Verdict != nil && entry.Verdict.Verdict == verdict
	})

	if removed > 0 && c.config.EnableStats {
		c.stats.SelectiveInvalidations.Add(uint64(removed))
	}

	return removed
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start begins the cache background operations (TTL cleanup).
func (c *VerdictCache) Start(ctx context.Context) error {
	if c.closed.Load() {
		return ErrCacheClosed
	}

	if c.running.Load() {
		return errors.New("cache already running")
	}

	c.running.Store(true)

	// Start TTL manager
	if err := c.ttlManager.Start(ctx); err != nil {
		c.running.Store(false)
		return fmt.Errorf("failed to start TTL manager: %w", err)
	}

	c.logger.Printf("Cache started (capacity=%d, ttl=%v)", c.config.Capacity, c.config.DefaultTTL)
	return nil
}

// Stop gracefully shuts down the cache.
func (c *VerdictCache) Stop() error {
	var err error

	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		defer c.closeMu.Unlock()

		c.logger.Println("Stopping cache...")
		c.closed.Store(true)

		// Stop TTL manager
		if c.ttlManager != nil {
			if ttlErr := c.ttlManager.Stop(); ttlErr != nil {
				err = ttlErr
			}
		}

		// Cancel context
		c.cancel()

		// Wait for goroutines
		c.wg.Wait()

		c.running.Store(false)

		// Log final stats
		stats := c.GetStats()
		c.logger.Printf("Cache stopped. Final stats: hits=%d, misses=%d, hit_rate=%.2f%%, size=%d",
			stats.Hits.Load(),
			stats.Misses.Load(),
			stats.GetHitRate(),
			c.lru.Size(),
		)
	})

	return err
}

// IsRunning returns true if the cache is running.
func (c *VerdictCache) IsRunning() bool {
	return c.running.Load() && !c.closed.Load()
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns cache statistics.
func (c *VerdictCache) GetStats() *CacheStats {
	return c.stats
}

// GetStatsSnapshot returns a point-in-time snapshot of statistics.
func (c *VerdictCache) GetStatsSnapshot() map[string]interface{} {
	snapshot := c.stats.GetSnapshot()
	snapshot["capacity"] = c.config.Capacity
	snapshot["utilization_percent"] = c.lru.Utilization()
	return snapshot
}

// ============================================================================
// Configuration
// ============================================================================

// SetLogger sets a custom logger.
func (c *VerdictCache) SetLogger(logger *log.Logger) {
	if logger != nil {
		c.logger = logger
	}
	if c.ttlManager != nil {
		c.ttlManager.SetLogger(logger)
	}
}

// GetConfig returns the current configuration.
func (c *VerdictCache) GetConfig() *CacheConfig {
	return c.config
}

// ============================================================================
// Convenience Methods
// ============================================================================

// GetOrSet gets an entry from cache, or if not found, calls the loader func,
// caches the result, and returns it.
func (c *VerdictCache) GetOrSet(key string, loader func() (*models.VerdictResult, error), ttl time.Duration) (*models.VerdictResult, error) {
	// Try cache first
	if entry, found := c.Get(key); found {
		return entry.Verdict, nil
	}

	// Call loader
	verdict, err := loader()
	if err != nil {
		return nil, err
	}

	// Cache result
	if err := c.Set(key, verdict, ttl); err != nil {
		// Log but don't fail
		c.logger.Printf("Failed to cache verdict: %v", err)
	}

	return verdict, nil
}

// Warm pre-populates the cache with entries.
func (c *VerdictCache) Warm(entries map[string]*models.VerdictResult, ttl time.Duration) int {
	loaded := 0
	for key, verdict := range entries {
		if err := c.Set(key, verdict, ttl); err == nil {
			loaded++
		}
	}
	c.logger.Printf("Warmed cache with %d entries", loaded)
	return loaded
}
