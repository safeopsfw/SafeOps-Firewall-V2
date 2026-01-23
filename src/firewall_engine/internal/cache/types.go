// Package cache provides high-performance verdict caching for the firewall engine.
// It implements an LRU (Least Recently Used) cache with TTL (Time-To-Live) expiration
// to avoid re-evaluating identical flows, achieving 80%+ cache hit rate.
//
// Architecture:
//
//	Packet inspection request
//	        ↓
//	  Generate cache key (5-tuple: src/dst IP, src/dst port, protocol)
//	        ↓
//	  ┌─────┴─────┐
//	  ↓           ↓
//	Cache HIT   Cache MISS
//	  ↓           ↓
//	Return      Run full
//	cached      rule engine
//	verdict         ↓
//	  ↓        Cache result
//	  └─────┬─────┘
//	        ↓
//	   Enforce verdict
//
// Performance Impact:
//   - Without cache: 50μs/packet = 20K pps
//   - With cache (80% hit): 19μs average = 52K pps (2.6x improvement)
//   - Memory: 100K entries × 100 bytes = ~10MB
package cache

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrCacheClosed is returned when operations are attempted on a closed cache.
	ErrCacheClosed = errors.New("cache is closed")

	// ErrKeyEmpty is returned when an empty key is provided.
	ErrKeyEmpty = errors.New("cache key is empty")

	// ErrKeyNotFound is returned when a key doesn't exist in the cache.
	ErrKeyNotFound = errors.New("key not found in cache")

	// ErrEntryExpired is returned when an entry has expired.
	ErrEntryExpired = errors.New("cache entry has expired")

	// ErrCacheFull is returned when the cache is at capacity.
	ErrCacheFull = errors.New("cache is at capacity")

	// ErrInvalidConfig is returned when configuration is invalid.
	ErrInvalidConfig = errors.New("invalid cache configuration")

	// ErrInvalidTTL is returned when TTL is invalid.
	ErrInvalidTTL = errors.New("invalid TTL value")
)

// ============================================================================
// Cache Entry
// ============================================================================

// CacheEntry represents a cached verdict decision.
type CacheEntry struct {
	// Key is the unique identifier (5-tuple string).
	Key string `json:"key"`

	// Verdict is the cached firewall decision.
	Verdict *models.VerdictResult `json:"verdict"`

	// RuleID is the ID of the rule that matched (for selective invalidation).
	RuleID string `json:"rule_id,omitempty"`

	// RuleName is the name of the matched rule.
	RuleName string `json:"rule_name,omitempty"`

	// CreatedAt is when the entry was created.
	CreatedAt time.Time `json:"created_at"`

	// AccessedAt is when the entry was last accessed.
	AccessedAt time.Time `json:"accessed_at"`

	// ExpiresAt is when the entry expires (CreatedAt + TTL).
	ExpiresAt time.Time `json:"expires_at"`

	// TTL is the time-to-live for this entry.
	TTL time.Duration `json:"ttl"`

	// AccessCount is how many times this entry has been accessed.
	AccessCount uint64 `json:"access_count"`

	// Metadata for tracking
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	Protocol uint8  `json:"protocol,omitempty"`
}

// NewCacheEntry creates a new cache entry.
func NewCacheEntry(key string, verdict *models.VerdictResult, ttl time.Duration) *CacheEntry {
	now := time.Now()
	return &CacheEntry{
		Key:        key,
		Verdict:    verdict,
		RuleID:     verdict.RuleID,
		RuleName:   verdict.RuleName,
		CreatedAt:  now,
		AccessedAt: now,
		ExpiresAt:  now.Add(ttl),
		TTL:        ttl,
	}
}

// IsExpired returns true if the entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// TimeToExpiry returns the time until expiry.
func (e *CacheEntry) TimeToExpiry() time.Duration {
	remaining := time.Until(e.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Touch updates the access time and increments access count.
func (e *CacheEntry) Touch() {
	e.AccessedAt = time.Now()
	e.AccessCount++
}

// Age returns how long since the entry was created.
func (e *CacheEntry) Age() time.Duration {
	return time.Since(e.CreatedAt)
}

// ExtendTTL extends the expiry by the specified duration.
func (e *CacheEntry) ExtendTTL(extension time.Duration) {
	e.ExpiresAt = e.ExpiresAt.Add(extension)
	e.TTL += extension
}

// ============================================================================
// Cache Interface
// ============================================================================

// Cache defines the interface for verdict caching.
type Cache interface {
	// Get retrieves a cached verdict by key.
	// Returns the entry and true if found and not expired, nil and false otherwise.
	Get(key string) (*CacheEntry, bool)

	// Set stores a verdict in the cache with the specified TTL.
	// If the cache is full, the least recently used entry is evicted.
	Set(key string, verdict *models.VerdictResult, ttl time.Duration) error

	// Delete removes an entry from the cache.
	Delete(key string) bool

	// Clear removes all entries from the cache.
	Clear()

	// Size returns the current number of entries in the cache.
	Size() int

	// Capacity returns the maximum capacity of the cache.
	Capacity() int

	// Contains returns true if the key exists in the cache (even if expired).
	Contains(key string) bool

	// Keys returns all keys in the cache.
	Keys() []string

	// Start begins background cleanup (TTL expiration).
	Start(ctx context.Context) error

	// Stop gracefully shuts down the cache.
	Stop() error

	// GetStats returns cache statistics.
	GetStats() *CacheStats

	// Invalidate implements invalidation strategies.
	Invalidate(strategy InvalidationStrategy, params interface{}) int
}

// ============================================================================
// Cache Configuration
// ============================================================================

// CacheConfig contains configuration for the verdict cache.
type CacheConfig struct {
	// Capacity is the maximum number of entries.
	// Default: 100,000
	Capacity int `json:"capacity" toml:"capacity"`

	// DefaultTTL is the default time-to-live for entries.
	// Default: 60 seconds
	DefaultTTL time.Duration `json:"default_ttl" toml:"default_ttl"`

	// CleanupInterval is how often to run TTL cleanup.
	// Default: 10 seconds
	CleanupInterval time.Duration `json:"cleanup_interval" toml:"cleanup_interval"`

	// Per-verdict TTL overrides
	TTLAllow    time.Duration `json:"ttl_allow" toml:"ttl_allow"`
	TTLBlock    time.Duration `json:"ttl_block" toml:"ttl_block"`
	TTLDrop     time.Duration `json:"ttl_drop" toml:"ttl_drop"`
	TTLRedirect time.Duration `json:"ttl_redirect" toml:"ttl_redirect"`
	TTLReject   time.Duration `json:"ttl_reject" toml:"ttl_reject"`

	// EnableStats enables statistics collection.
	EnableStats bool `json:"enable_stats" toml:"enable_stats"`

	// EnableExpireOnGet checks expiry on every Get operation.
	EnableExpireOnGet bool `json:"enable_expire_on_get" toml:"enable_expire_on_get"`

	// ShardCount for sharded cache implementation (0 = no sharding).
	ShardCount int `json:"shard_count" toml:"shard_count"`
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Capacity:          100000,
		DefaultTTL:        60 * time.Second,
		CleanupInterval:   10 * time.Second,
		TTLAllow:          60 * time.Second,  // Allow decisions stable
		TTLBlock:          60 * time.Second,  // Block may change (user appeals)
		TTLDrop:           300 * time.Second, // Drop persistent (malware)
		TTLRedirect:       30 * time.Second,  // Captive portal shorter
		TTLReject:         60 * time.Second,
		EnableStats:       true,
		EnableExpireOnGet: true,
		ShardCount:        0, // No sharding by default
	}
}

// Validate checks the configuration for errors.
func (c *CacheConfig) Validate() error {
	if c.Capacity < 100 {
		return fmt.Errorf("%w: capacity must be >= 100, got %d", ErrInvalidConfig, c.Capacity)
	}
	if c.Capacity > 10000000 {
		return fmt.Errorf("%w: capacity must be <= 10,000,000, got %d", ErrInvalidConfig, c.Capacity)
	}
	if c.DefaultTTL < time.Second {
		return fmt.Errorf("%w: default_ttl must be >= 1s", ErrInvalidConfig)
	}
	if c.CleanupInterval < time.Second {
		return fmt.Errorf("%w: cleanup_interval must be >= 1s", ErrInvalidConfig)
	}
	return nil
}

// GetTTLForVerdict returns the appropriate TTL for a verdict type.
func (c *CacheConfig) GetTTLForVerdict(verdict models.Verdict) time.Duration {
	switch verdict {
	case models.VerdictAllow:
		if c.TTLAllow > 0 {
			return c.TTLAllow
		}
	case models.VerdictBlock:
		if c.TTLBlock > 0 {
			return c.TTLBlock
		}
	case models.VerdictDrop:
		if c.TTLDrop > 0 {
			return c.TTLDrop
		}
	case models.VerdictRedirect:
		if c.TTLRedirect > 0 {
			return c.TTLRedirect
		}
	case models.VerdictReject:
		if c.TTLReject > 0 {
			return c.TTLReject
		}
	}
	return c.DefaultTTL
}

// ============================================================================
// Cache Statistics
// ============================================================================

// CacheStats contains cache performance statistics.
type CacheStats struct {
	// Lookup counters
	Hits   atomic.Uint64 `json:"hits"`
	Misses atomic.Uint64 `json:"misses"`

	// Entry counters
	Inserts     atomic.Uint64 `json:"inserts"`
	Updates     atomic.Uint64 `json:"updates"`
	Deletes     atomic.Uint64 `json:"deletes"`
	Evictions   atomic.Uint64 `json:"evictions"`   // LRU evictions
	Expirations atomic.Uint64 `json:"expirations"` // TTL expirations

	// Invalidation counters
	FullInvalidations      atomic.Uint64 `json:"full_invalidations"`
	SelectiveInvalidations atomic.Uint64 `json:"selective_invalidations"`

	// Size tracking
	CurrentSize atomic.Int64 `json:"current_size"`
	MaxSize     atomic.Int64 `json:"max_size"`

	// Timing (nanoseconds)
	TotalLookupTimeNs atomic.Uint64 `json:"total_lookup_time_ns"`
	TotalInsertTimeNs atomic.Uint64 `json:"total_insert_time_ns"`

	// Cleanup stats
	CleanupRuns   atomic.Uint64 `json:"cleanup_runs"`
	LastCleanupNs atomic.Int64  `json:"last_cleanup_ns"`
}

// NewCacheStats creates a new statistics container.
func NewCacheStats() *CacheStats {
	return &CacheStats{}
}

// GetHitRate returns the cache hit rate as a percentage (0-100).
func (s *CacheStats) GetHitRate() float64 {
	hits := s.Hits.Load()
	misses := s.Misses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// GetTotalLookups returns total lookups (hits + misses).
func (s *CacheStats) GetTotalLookups() uint64 {
	return s.Hits.Load() + s.Misses.Load()
}

// GetAverageLookupTime returns average lookup time in nanoseconds.
func (s *CacheStats) GetAverageLookupTime() uint64 {
	total := s.GetTotalLookups()
	if total == 0 {
		return 0
	}
	return s.TotalLookupTimeNs.Load() / total
}

// GetSnapshot returns a point-in-time copy of statistics.
func (s *CacheStats) GetSnapshot() map[string]interface{} {
	return map[string]interface{}{
		"hits":                    s.Hits.Load(),
		"misses":                  s.Misses.Load(),
		"hit_rate_percent":        s.GetHitRate(),
		"inserts":                 s.Inserts.Load(),
		"updates":                 s.Updates.Load(),
		"deletes":                 s.Deletes.Load(),
		"evictions":               s.Evictions.Load(),
		"expirations":             s.Expirations.Load(),
		"full_invalidations":      s.FullInvalidations.Load(),
		"selective_invalidations": s.SelectiveInvalidations.Load(),
		"current_size":            s.CurrentSize.Load(),
		"max_size":                s.MaxSize.Load(),
		"avg_lookup_time_ns":      s.GetAverageLookupTime(),
		"cleanup_runs":            s.CleanupRuns.Load(),
	}
}

// Reset clears all statistics.
func (s *CacheStats) Reset() {
	s.Hits.Store(0)
	s.Misses.Store(0)
	s.Inserts.Store(0)
	s.Updates.Store(0)
	s.Deletes.Store(0)
	s.Evictions.Store(0)
	s.Expirations.Store(0)
	s.FullInvalidations.Store(0)
	s.SelectiveInvalidations.Store(0)
	s.CurrentSize.Store(0)
	s.TotalLookupTimeNs.Store(0)
	s.TotalInsertTimeNs.Store(0)
	s.CleanupRuns.Store(0)
}

// RecordHit records a cache hit.
func (s *CacheStats) RecordHit(lookupTimeNs uint64) {
	s.Hits.Add(1)
	s.TotalLookupTimeNs.Add(lookupTimeNs)
}

// RecordMiss records a cache miss.
func (s *CacheStats) RecordMiss(lookupTimeNs uint64) {
	s.Misses.Add(1)
	s.TotalLookupTimeNs.Add(lookupTimeNs)
}

// RecordInsert records an insert.
func (s *CacheStats) RecordInsert(insertTimeNs uint64) {
	s.Inserts.Add(1)
	s.TotalInsertTimeNs.Add(insertTimeNs)
	newSize := s.CurrentSize.Add(1)
	// Update max size if needed
	for {
		currentMax := s.MaxSize.Load()
		if newSize <= currentMax {
			break
		}
		if s.MaxSize.CompareAndSwap(currentMax, newSize) {
			break
		}
	}
}

// RecordEviction records an LRU eviction.
func (s *CacheStats) RecordEviction() {
	s.Evictions.Add(1)
	s.CurrentSize.Add(-1)
}

// RecordExpiration records a TTL expiration.
func (s *CacheStats) RecordExpiration() {
	s.Expirations.Add(1)
	s.CurrentSize.Add(-1)
}

// RecordDelete records a manual delete.
func (s *CacheStats) RecordDelete() {
	s.Deletes.Add(1)
	s.CurrentSize.Add(-1)
}

// ============================================================================
// Invalidation Strategy
// ============================================================================

// InvalidationStrategy defines how to invalidate cache entries.
type InvalidationStrategy int

const (
	// InvalidateAll clears the entire cache.
	InvalidateAll InvalidationStrategy = iota

	// InvalidateByIP clears entries matching a specific IP.
	InvalidateByIP

	// InvalidateBySrcIP clears entries matching source IP.
	InvalidateBySrcIP

	// InvalidateByDstIP clears entries matching destination IP.
	InvalidateByDstIP

	// InvalidateByRuleID clears entries matched by a specific rule.
	InvalidateByRuleID

	// InvalidateByRuleName clears entries matched by rule name.
	InvalidateByRuleName

	// InvalidateByVerdict clears entries with a specific verdict.
	InvalidateByVerdict

	// InvalidateExpired clears only expired entries.
	InvalidateExpired
)

// String returns the strategy name.
func (s InvalidationStrategy) String() string {
	switch s {
	case InvalidateAll:
		return "ALL"
	case InvalidateByIP:
		return "BY_IP"
	case InvalidateBySrcIP:
		return "BY_SRC_IP"
	case InvalidateByDstIP:
		return "BY_DST_IP"
	case InvalidateByRuleID:
		return "BY_RULE_ID"
	case InvalidateByRuleName:
		return "BY_RULE_NAME"
	case InvalidateByVerdict:
		return "BY_VERDICT"
	case InvalidateExpired:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

// InvalidationParams contains parameters for selective invalidation.
type InvalidationParams struct {
	IP       string         `json:"ip,omitempty"`
	RuleID   string         `json:"rule_id,omitempty"`
	RuleName string         `json:"rule_name,omitempty"`
	Verdict  models.Verdict `json:"verdict,omitempty"`
}

// ============================================================================
// Cache Key Generation
// ============================================================================

// GenerateCacheKey creates a cache key from packet metadata.
// Format: protocol:srcIP:srcPort-dstIP:dstPort
func GenerateCacheKey(packet *models.PacketMetadata) string {
	if packet == nil {
		return ""
	}
	return fmt.Sprintf("%d:%s:%d-%s:%d",
		packet.Protocol,
		packet.SrcIP, packet.SrcPort,
		packet.DstIP, packet.DstPort,
	)
}

// GenerateBidirectionalKey creates a normalized key for bidirectional flows.
// The lower IP:port combination comes first for consistency.
func GenerateBidirectionalKey(packet *models.PacketMetadata) string {
	if packet == nil {
		return ""
	}

	// Normalize: lower IP:port first
	src := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
	dst := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)

	if src < dst {
		return fmt.Sprintf("%d:%s-%s", packet.Protocol, src, dst)
	}
	return fmt.Sprintf("%d:%s-%s", packet.Protocol, dst, src)
}
