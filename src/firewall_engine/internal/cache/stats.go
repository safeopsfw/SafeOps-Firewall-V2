// Package cache provides high-performance verdict caching for the firewall engine.
package cache

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Extended Cache Statistics
// ============================================================================

// ExtendedStats provides detailed cache statistics with history and analysis.
type ExtendedStats struct {
	// Base stats (embedded)
	*CacheStats

	// Configuration
	config *StatsConfig

	// Time-based metrics
	startTime     time.Time
	lastResetTime time.Time

	// Rolling window for rate calculations
	recentHits   *RollingCounter
	recentMisses *RollingCounter

	// Per-verdict statistics
	verdictStats map[string]*VerdictStats

	// Latency histograms
	lookupLatencies *LatencyHistogram
	insertLatencies *LatencyHistogram

	// Thread safety
	mu sync.RWMutex
}

// StatsConfig contains configuration for statistics tracking.
type StatsConfig struct {
	// EnableVerdictStats tracks per-verdict statistics.
	EnableVerdictStats bool `json:"enable_verdict_stats" toml:"enable_verdict_stats"`

	// EnableLatencyHistogram tracks latency distribution.
	EnableLatencyHistogram bool `json:"enable_latency_histogram" toml:"enable_latency_histogram"`

	// EnableRollingRates tracks rates over rolling window.
	EnableRollingRates bool `json:"enable_rolling_rates" toml:"enable_rolling_rates"`

	// RollingWindowSize is the size of the rolling window.
	RollingWindowSize time.Duration `json:"rolling_window_size" toml:"rolling_window_size"`

	// HistogramBuckets are the latency histogram buckets (in nanoseconds).
	HistogramBuckets []int64 `json:"histogram_buckets" toml:"histogram_buckets"`
}

// DefaultStatsConfig returns the default statistics configuration.
func DefaultStatsConfig() *StatsConfig {
	return &StatsConfig{
		EnableVerdictStats:     true,
		EnableLatencyHistogram: true,
		EnableRollingRates:     true,
		RollingWindowSize:      60 * time.Second,
		HistogramBuckets:       []int64{100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000},
	}
}

// VerdictStats contains statistics for a specific verdict type.
type VerdictStats struct {
	VerdictType string        `json:"verdict_type"`
	Hits        atomic.Uint64 `json:"hits"`
	Misses      atomic.Uint64 `json:"misses"`
	Inserts     atomic.Uint64 `json:"inserts"`
	Evictions   atomic.Uint64 `json:"evictions"`
	AvgTTL      atomic.Int64  `json:"avg_ttl_ns"` // Nanoseconds
}

// ============================================================================
// Constructor
// ============================================================================

// NewExtendedStats creates extended statistics tracking.
func NewExtendedStats(config *StatsConfig) *ExtendedStats {
	if config == nil {
		config = DefaultStatsConfig()
	}

	now := time.Now()
	stats := &ExtendedStats{
		CacheStats:    NewCacheStats(),
		config:        config,
		startTime:     now,
		lastResetTime: now,
		verdictStats:  make(map[string]*VerdictStats),
	}

	if config.EnableRollingRates {
		stats.recentHits = NewRollingCounter(config.RollingWindowSize, 60)
		stats.recentMisses = NewRollingCounter(config.RollingWindowSize, 60)
	}

	if config.EnableLatencyHistogram {
		stats.lookupLatencies = NewLatencyHistogram(config.HistogramBuckets)
		stats.insertLatencies = NewLatencyHistogram(config.HistogramBuckets)
	}

	return stats
}

// ============================================================================
// Recording Methods
// ============================================================================

// RecordHitWithVerdict records a cache hit with verdict type.
func (s *ExtendedStats) RecordHitWithVerdict(lookupTimeNs uint64, verdict string) {
	s.RecordHit(lookupTimeNs)

	if s.config.EnableRollingRates && s.recentHits != nil {
		s.recentHits.Increment()
	}

	if s.config.EnableLatencyHistogram && s.lookupLatencies != nil {
		s.lookupLatencies.Record(int64(lookupTimeNs))
	}

	if s.config.EnableVerdictStats && verdict != "" {
		s.getVerdictStats(verdict).Hits.Add(1)
	}
}

// RecordMissWithDetails records a cache miss with additional details.
func (s *ExtendedStats) RecordMissWithDetails(lookupTimeNs uint64) {
	s.RecordMiss(lookupTimeNs)

	if s.config.EnableRollingRates && s.recentMisses != nil {
		s.recentMisses.Increment()
	}

	if s.config.EnableLatencyHistogram && s.lookupLatencies != nil {
		s.lookupLatencies.Record(int64(lookupTimeNs))
	}
}

// RecordInsertWithVerdict records an insert with verdict type and TTL.
func (s *ExtendedStats) RecordInsertWithVerdict(insertTimeNs uint64, verdict string, ttlNs int64) {
	s.RecordInsert(insertTimeNs)

	if s.config.EnableLatencyHistogram && s.insertLatencies != nil {
		s.insertLatencies.Record(int64(insertTimeNs))
	}

	if s.config.EnableVerdictStats && verdict != "" {
		vs := s.getVerdictStats(verdict)
		vs.Inserts.Add(1)
		// Update rolling average TTL
		oldAvg := vs.AvgTTL.Load()
		inserts := vs.Inserts.Load()
		if inserts > 0 {
			newAvg := ((oldAvg * int64(inserts-1)) + ttlNs) / int64(inserts)
			vs.AvgTTL.Store(newAvg)
		}
	}
}

// getVerdictStats gets or creates stats for a verdict type.
func (s *ExtendedStats) getVerdictStats(verdict string) *VerdictStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	if vs, ok := s.verdictStats[verdict]; ok {
		return vs
	}

	vs := &VerdictStats{VerdictType: verdict}
	s.verdictStats[verdict] = vs
	return vs
}

// ============================================================================
// Rate Calculations
// ============================================================================

// GetRecentHitRate returns the hit rate over the rolling window.
func (s *ExtendedStats) GetRecentHitRate() float64 {
	if !s.config.EnableRollingRates || s.recentHits == nil || s.recentMisses == nil {
		return s.GetHitRate()
	}

	hits := s.recentHits.Sum()
	misses := s.recentMisses.Sum()
	total := hits + misses

	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// GetHitsPerSecond returns the recent hit rate per second.
func (s *ExtendedStats) GetHitsPerSecond() float64 {
	if !s.config.EnableRollingRates || s.recentHits == nil {
		return 0
	}
	return s.recentHits.Rate()
}

// GetMissesPerSecond returns the recent miss rate per second.
func (s *ExtendedStats) GetMissesPerSecond() float64 {
	if !s.config.EnableRollingRates || s.recentMisses == nil {
		return 0
	}
	return s.recentMisses.Rate()
}

// GetLookupsPerSecond returns the total lookup rate per second.
func (s *ExtendedStats) GetLookupsPerSecond() float64 {
	return s.GetHitsPerSecond() + s.GetMissesPerSecond()
}

// ============================================================================
// Latency Statistics
// ============================================================================

// GetLookupLatencyPercentile returns the lookup latency at a percentile.
func (s *ExtendedStats) GetLookupLatencyPercentile(percentile float64) int64 {
	if s.lookupLatencies == nil {
		return 0
	}
	return s.lookupLatencies.Percentile(percentile)
}

// GetInsertLatencyPercentile returns the insert latency at a percentile.
func (s *ExtendedStats) GetInsertLatencyPercentile(percentile float64) int64 {
	if s.insertLatencies == nil {
		return 0
	}
	return s.insertLatencies.Percentile(percentile)
}

// ============================================================================
// Per-Verdict Statistics
// ============================================================================

// GetVerdictStats returns statistics for a specific verdict type.
func (s *ExtendedStats) GetVerdictStats(verdict string) map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vs, ok := s.verdictStats[verdict]
	if !ok {
		return nil
	}

	return map[string]uint64{
		"hits":       vs.Hits.Load(),
		"misses":     vs.Misses.Load(),
		"inserts":    vs.Inserts.Load(),
		"evictions":  vs.Evictions.Load(),
		"avg_ttl_ns": uint64(vs.AvgTTL.Load()),
	}
}

// GetAllVerdictStats returns statistics for all verdict types.
func (s *ExtendedStats) GetAllVerdictStats() map[string]map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]map[string]uint64)
	for verdict := range s.verdictStats {
		result[verdict] = s.GetVerdictStats(verdict)
	}
	return result
}

// ============================================================================
// Extended Snapshot
// ============================================================================

// GetExtendedSnapshot returns a comprehensive statistics snapshot.
func (s *ExtendedStats) GetExtendedSnapshot() map[string]interface{} {
	snapshot := s.CacheStats.GetSnapshot()

	// Add uptime
	snapshot["uptime_seconds"] = int64(time.Since(s.startTime).Seconds())

	// Add rolling rates if enabled
	if s.config.EnableRollingRates {
		snapshot["recent_hit_rate_percent"] = s.GetRecentHitRate()
		snapshot["hits_per_second"] = s.GetHitsPerSecond()
		snapshot["misses_per_second"] = s.GetMissesPerSecond()
		snapshot["lookups_per_second"] = s.GetLookupsPerSecond()
	}

	// Add latency percentiles if enabled
	if s.config.EnableLatencyHistogram {
		snapshot["lookup_latency_p50_ns"] = s.GetLookupLatencyPercentile(50)
		snapshot["lookup_latency_p95_ns"] = s.GetLookupLatencyPercentile(95)
		snapshot["lookup_latency_p99_ns"] = s.GetLookupLatencyPercentile(99)
		snapshot["insert_latency_p50_ns"] = s.GetInsertLatencyPercentile(50)
		snapshot["insert_latency_p95_ns"] = s.GetInsertLatencyPercentile(95)
	}

	// Add per-verdict stats if enabled
	if s.config.EnableVerdictStats {
		snapshot["verdict_stats"] = s.GetAllVerdictStats()
	}

	return snapshot
}

// ============================================================================
// Prometheus Export
// ============================================================================

// ToPrometheus returns statistics in Prometheus format.
func (s *ExtendedStats) ToPrometheus(prefix string) string {
	var sb strings.Builder

	// Hit rate gauge
	sb.WriteString(fmt.Sprintf("# HELP %s_cache_hit_rate Cache hit rate percentage\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_hit_rate gauge\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_hit_rate %.4f\n", prefix, s.GetHitRate()/100))

	// Counters
	sb.WriteString(fmt.Sprintf("# HELP %s_cache_hits_total Total cache hits\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_hits_total counter\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_hits_total %d\n", prefix, s.Hits.Load()))

	sb.WriteString(fmt.Sprintf("# HELP %s_cache_misses_total Total cache misses\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_misses_total counter\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_misses_total %d\n", prefix, s.Misses.Load()))

	sb.WriteString(fmt.Sprintf("# HELP %s_cache_evictions_total Total cache evictions\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_evictions_total counter\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_evictions_total %d\n", prefix, s.Evictions.Load()))

	sb.WriteString(fmt.Sprintf("# HELP %s_cache_expirations_total Total cache expirations\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_expirations_total counter\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_expirations_total %d\n", prefix, s.Expirations.Load()))

	// Size gauge
	sb.WriteString(fmt.Sprintf("# HELP %s_cache_size Current cache size\n", prefix))
	sb.WriteString(fmt.Sprintf("# TYPE %s_cache_size gauge\n", prefix))
	sb.WriteString(fmt.Sprintf("%s_cache_size %d\n", prefix, s.CurrentSize.Load()))

	return sb.String()
}

// ToJSON returns statistics as JSON.
func (s *ExtendedStats) ToJSON() ([]byte, error) {
	return json.Marshal(s.GetExtendedSnapshot())
}

// ============================================================================
// Rolling Counter
// ============================================================================

// RollingCounter tracks counts over a rolling time window.
type RollingCounter struct {
	buckets      []atomic.Uint64
	bucketWidth  time.Duration
	windowSize   time.Duration
	numBuckets   int
	currentIndex atomic.Int32
	lastRotation atomic.Int64
	mu           sync.RWMutex
}

// NewRollingCounter creates a new rolling counter.
func NewRollingCounter(windowSize time.Duration, numBuckets int) *RollingCounter {
	if numBuckets < 1 {
		numBuckets = 60
	}

	return &RollingCounter{
		buckets:      make([]atomic.Uint64, numBuckets),
		bucketWidth:  windowSize / time.Duration(numBuckets),
		windowSize:   windowSize,
		numBuckets:   numBuckets,
		lastRotation: atomic.Int64{},
	}
}

// Increment increments the current bucket.
func (r *RollingCounter) Increment() {
	r.rotate()
	idx := int(r.currentIndex.Load()) % r.numBuckets
	r.buckets[idx].Add(1)
}

// Sum returns the sum of all buckets.
func (r *RollingCounter) Sum() uint64 {
	r.rotate()
	var sum uint64
	for i := 0; i < r.numBuckets; i++ {
		sum += r.buckets[i].Load()
	}
	return sum
}

// Rate returns the rate per second over the window.
func (r *RollingCounter) Rate() float64 {
	sum := r.Sum()
	return float64(sum) / r.windowSize.Seconds()
}

// rotate rotates buckets based on elapsed time.
func (r *RollingCounter) rotate() {
	now := time.Now().UnixNano()
	last := r.lastRotation.Load()
	elapsed := time.Duration(now - last)

	if elapsed < r.bucketWidth {
		return
	}

	if !r.lastRotation.CompareAndSwap(last, now) {
		return
	}

	bucketsToRotate := int(elapsed / r.bucketWidth)
	if bucketsToRotate > r.numBuckets {
		bucketsToRotate = r.numBuckets
	}

	for i := 0; i < bucketsToRotate; i++ {
		newIdx := (int(r.currentIndex.Load()) + 1) % r.numBuckets
		r.currentIndex.Store(int32(newIdx))
		r.buckets[newIdx].Store(0)
	}
}

// ============================================================================
// Latency Histogram
// ============================================================================

// LatencyHistogram tracks latency distribution.
type LatencyHistogram struct {
	buckets []int64         // Bucket boundaries (ns)
	counts  []atomic.Uint64 // Count per bucket
	sum     atomic.Uint64   // Sum of all values
	count   atomic.Uint64   // Total count
	min     atomic.Int64    // Minimum value
	max     atomic.Int64    // Maximum value
}

// NewLatencyHistogram creates a new latency histogram.
func NewLatencyHistogram(buckets []int64) *LatencyHistogram {
	if len(buckets) == 0 {
		buckets = []int64{100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000}
	}

	return &LatencyHistogram{
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1), // +1 for overflow
	}
}

// Record records a latency value.
func (h *LatencyHistogram) Record(valueNs int64) {
	h.count.Add(1)
	h.sum.Add(uint64(valueNs))

	// Update min
	for {
		current := h.min.Load()
		if current != 0 && valueNs >= current {
			break
		}
		if h.min.CompareAndSwap(current, valueNs) {
			break
		}
	}

	// Update max
	for {
		current := h.max.Load()
		if valueNs <= current {
			break
		}
		if h.max.CompareAndSwap(current, valueNs) {
			break
		}
	}

	// Find bucket
	for i, boundary := range h.buckets {
		if valueNs <= boundary {
			h.counts[i].Add(1)
			return
		}
	}
	// Overflow bucket
	h.counts[len(h.buckets)].Add(1)
}

// Percentile returns the approximate value at a percentile.
func (h *LatencyHistogram) Percentile(p float64) int64 {
	total := h.count.Load()
	if total == 0 {
		return 0
	}

	target := uint64(float64(total) * p / 100)
	var cumulative uint64

	for i, bucket := range h.buckets {
		cumulative += h.counts[i].Load()
		if cumulative >= target {
			return bucket
		}
	}

	return h.max.Load()
}

// Average returns the average latency.
func (h *LatencyHistogram) Average() int64 {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	return int64(h.sum.Load() / count)
}

// Min returns the minimum latency.
func (h *LatencyHistogram) Min() int64 {
	return h.min.Load()
}

// Max returns the maximum latency.
func (h *LatencyHistogram) Max() int64 {
	return h.max.Load()
}
