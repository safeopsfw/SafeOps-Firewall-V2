// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Statistics Configuration
// ============================================================================

// StatisticsConfig configures the rolling window statistics.
type StatisticsConfig struct {
	// WindowSize is the total window duration.
	WindowSize time.Duration `json:"window_size" toml:"window_size"`

	// BucketDuration is the duration per bucket.
	BucketDuration time.Duration `json:"bucket_duration" toml:"bucket_duration"`
}

// DefaultStatisticsConfig returns config for 60-second window with 1-second buckets.
func DefaultStatisticsConfig() StatisticsConfig {
	return StatisticsConfig{
		WindowSize:     60 * time.Second,
		BucketDuration: 1 * time.Second,
	}
}

// ============================================================================
// Statistics Bucket
// ============================================================================

// StatsBucket holds statistics for a single time bucket.
type StatsBucket struct {
	// Timestamp is the bucket start time.
	Timestamp time.Time

	// Packet counts
	PacketsAllow uint64
	PacketsDeny  uint64
	PacketsTotal uint64

	// Byte counts
	BytesIn  uint64
	BytesOut uint64

	// Cache statistics
	CacheHits   uint64
	CacheMisses uint64

	// Latency statistics (in nanoseconds for precision)
	LatencySum   uint64
	LatencyCount uint64
	LatencyMin   uint64
	LatencyMax   uint64

	// Connection counts
	Connections uint64

	// Error counts
	Errors uint64
}

// Reset clears the bucket for reuse.
func (b *StatsBucket) Reset(timestamp time.Time) {
	b.Timestamp = timestamp
	b.PacketsAllow = 0
	b.PacketsDeny = 0
	b.PacketsTotal = 0
	b.BytesIn = 0
	b.BytesOut = 0
	b.CacheHits = 0
	b.CacheMisses = 0
	b.LatencySum = 0
	b.LatencyCount = 0
	b.LatencyMin = ^uint64(0) // Max value for min tracking
	b.LatencyMax = 0
	b.Connections = 0
	b.Errors = 0
}

// GetAverageLatency returns the average latency for this bucket.
func (b *StatsBucket) GetAverageLatency() time.Duration {
	if b.LatencyCount == 0 {
		return 0
	}
	return time.Duration(b.LatencySum / b.LatencyCount)
}

// GetCacheHitRate returns the cache hit rate for this bucket.
func (b *StatsBucket) GetCacheHitRate() float64 {
	total := b.CacheHits + b.CacheMisses
	if total == 0 {
		return 0
	}
	return float64(b.CacheHits) / float64(total)
}

// ============================================================================
// Aggregated Statistics
// ============================================================================

// Stats holds aggregated statistics over a time window.
type Stats struct {
	// Time range
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  float64   `json:"duration_seconds"`

	// Packet statistics
	PacketsTotal  uint64  `json:"packets_total"`
	PacketsAllow  uint64  `json:"packets_allow"`
	PacketsDeny   uint64  `json:"packets_deny"`
	PacketsPerSec float64 `json:"packets_per_second"`

	// Byte statistics
	BytesTotal  uint64  `json:"bytes_total"`
	BytesIn     uint64  `json:"bytes_in"`
	BytesOut    uint64  `json:"bytes_out"`
	BytesPerSec float64 `json:"bytes_per_second"`

	// Cache statistics
	CacheHits    uint64  `json:"cache_hits"`
	CacheMisses  uint64  `json:"cache_misses"`
	CacheHitRate float64 `json:"cache_hit_rate"`

	// Latency statistics
	LatencyAvg time.Duration `json:"latency_avg_ns"`
	LatencyMin time.Duration `json:"latency_min_ns"`
	LatencyMax time.Duration `json:"latency_max_ns"`

	// Connection statistics
	Connections       uint64  `json:"connections"`
	ConnectionsPerSec float64 `json:"connections_per_second"`

	// Error statistics
	Errors       uint64  `json:"errors"`
	ErrorsPerSec float64 `json:"errors_per_second"`
}

// ============================================================================
// Rolling Window Statistics
// ============================================================================

// RollingStats maintains rolling window statistics using a ring buffer.
type RollingStats struct {
	config StatisticsConfig

	// Ring buffer of buckets
	buckets    []StatsBucket
	numBuckets int
	currentIdx int

	// Current bucket for atomic updates
	current *StatsBucket

	// Ticker for bucket rotation
	ticker *time.Ticker
	stopCh chan struct{}

	mu        sync.RWMutex
	isRunning bool
}

// NewRollingStats creates a new rolling statistics tracker.
func NewRollingStats(config StatisticsConfig) *RollingStats {
	numBuckets := int(config.WindowSize / config.BucketDuration)
	if numBuckets < 1 {
		numBuckets = 60 // Default to 60 buckets
	}

	buckets := make([]StatsBucket, numBuckets)
	now := time.Now()
	for i := range buckets {
		buckets[i].Reset(now)
	}

	return &RollingStats{
		config:     config,
		buckets:    buckets,
		numBuckets: numBuckets,
		currentIdx: 0,
		current:    &buckets[0],
		stopCh:     make(chan struct{}),
	}
}

// NewDefaultRollingStats creates stats with default config (60s window, 1s buckets).
func NewDefaultRollingStats() *RollingStats {
	return NewRollingStats(DefaultStatisticsConfig())
}

// ============================================================================
// Recording Methods
// ============================================================================

// RecordPacket records a packet event.
func (r *RollingStats) RecordPacket(action string, bytes int, inbound bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	atomic.AddUint64(&r.current.PacketsTotal, 1)

	switch action {
	case ActionAllow:
		atomic.AddUint64(&r.current.PacketsAllow, 1)
	case ActionDeny, ActionDrop:
		atomic.AddUint64(&r.current.PacketsDeny, 1)
	}

	if bytes > 0 {
		if inbound {
			atomic.AddUint64(&r.current.BytesIn, uint64(bytes))
		} else {
			atomic.AddUint64(&r.current.BytesOut, uint64(bytes))
		}
	}
}

// RecordCacheHit records a cache hit.
func (r *RollingStats) RecordCacheHit() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	atomic.AddUint64(&r.current.CacheHits, 1)
}

// RecordCacheMiss records a cache miss.
func (r *RollingStats) RecordCacheMiss() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	atomic.AddUint64(&r.current.CacheMisses, 1)
}

// RecordLatency records a latency measurement.
func (r *RollingStats) RecordLatency(d time.Duration) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ns := uint64(d.Nanoseconds())
	atomic.AddUint64(&r.current.LatencySum, ns)
	atomic.AddUint64(&r.current.LatencyCount, 1)

	// Update min/max (not perfectly atomic but good enough for stats)
	if ns < atomic.LoadUint64(&r.current.LatencyMin) {
		atomic.StoreUint64(&r.current.LatencyMin, ns)
	}
	if ns > atomic.LoadUint64(&r.current.LatencyMax) {
		atomic.StoreUint64(&r.current.LatencyMax, ns)
	}
}

// RecordConnection records a connection event.
func (r *RollingStats) RecordConnection() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	atomic.AddUint64(&r.current.Connections, 1)
}

// RecordError records an error.
func (r *RollingStats) RecordError() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	atomic.AddUint64(&r.current.Errors, 1)
}

// ============================================================================
// Query Methods
// ============================================================================

// GetStats returns aggregated statistics for the specified duration.
func (r *RollingStats) GetStats(duration time.Duration) Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-duration)

	stats := Stats{
		EndTime:    now,
		LatencyMin: time.Hour * 24 * 365, // Large value for min tracking
	}

	// Aggregate buckets within the time range
	bucketsUsed := 0
	for i := 0; i < r.numBuckets; i++ {
		bucket := &r.buckets[i]
		if bucket.Timestamp.After(cutoff) || bucket.Timestamp.Equal(cutoff) {
			if stats.StartTime.IsZero() || bucket.Timestamp.Before(stats.StartTime) {
				stats.StartTime = bucket.Timestamp
			}

			stats.PacketsTotal += bucket.PacketsTotal
			stats.PacketsAllow += bucket.PacketsAllow
			stats.PacketsDeny += bucket.PacketsDeny
			stats.BytesIn += bucket.BytesIn
			stats.BytesOut += bucket.BytesOut
			stats.CacheHits += bucket.CacheHits
			stats.CacheMisses += bucket.CacheMisses
			stats.Connections += bucket.Connections
			stats.Errors += bucket.Errors

			if bucket.LatencyCount > 0 {
				stats.LatencyAvg += bucket.GetAverageLatency()
				if time.Duration(bucket.LatencyMin) < stats.LatencyMin {
					stats.LatencyMin = time.Duration(bucket.LatencyMin)
				}
				if time.Duration(bucket.LatencyMax) > stats.LatencyMax {
					stats.LatencyMax = time.Duration(bucket.LatencyMax)
				}
			}

			bucketsUsed++
		}
	}

	// Calculate averages and rates
	stats.BytesTotal = stats.BytesIn + stats.BytesOut
	stats.Duration = now.Sub(stats.StartTime).Seconds()

	if stats.Duration > 0 {
		stats.PacketsPerSec = float64(stats.PacketsTotal) / stats.Duration
		stats.BytesPerSec = float64(stats.BytesTotal) / stats.Duration
		stats.ConnectionsPerSec = float64(stats.Connections) / stats.Duration
		stats.ErrorsPerSec = float64(stats.Errors) / stats.Duration
	}

	cacheTotal := stats.CacheHits + stats.CacheMisses
	if cacheTotal > 0 {
		stats.CacheHitRate = float64(stats.CacheHits) / float64(cacheTotal)
	}

	if bucketsUsed > 0 {
		stats.LatencyAvg = stats.LatencyAvg / time.Duration(bucketsUsed)
	}

	// Reset min if no latency data
	if stats.LatencyMin == time.Hour*24*365 {
		stats.LatencyMin = 0
	}

	return stats
}

// GetCurrentPPS returns the current packets per second (last bucket).
func (r *RollingStats) GetCurrentPPS() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := atomic.LoadUint64(&r.current.PacketsTotal)
	return float64(count) / r.config.BucketDuration.Seconds()
}

// GetLast60sStats returns stats for the last 60 seconds.
func (r *RollingStats) GetLast60sStats() Stats {
	return r.GetStats(60 * time.Second)
}

// GetLast5sStats returns stats for the last 5 seconds.
func (r *RollingStats) GetLast5sStats() Stats {
	return r.GetStats(5 * time.Second)
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the bucket rotation ticker.
func (r *RollingStats) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isRunning {
		return
	}

	r.isRunning = true
	r.ticker = time.NewTicker(r.config.BucketDuration)

	go r.rotationLoop()
}

// Stop stops the bucket rotation.
func (r *RollingStats) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isRunning {
		return
	}

	r.isRunning = false
	close(r.stopCh)

	if r.ticker != nil {
		r.ticker.Stop()
	}
}

// rotationLoop rotates buckets on each tick.
func (r *RollingStats) rotationLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		case <-r.ticker.C:
			r.rotateBucket()
		}
	}
}

// rotateBucket advances to the next bucket.
func (r *RollingStats) rotateBucket() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Move to next bucket
	r.currentIdx = (r.currentIdx + 1) % r.numBuckets

	// Reset the new current bucket
	r.buckets[r.currentIdx].Reset(time.Now())
	r.current = &r.buckets[r.currentIdx]
}

// ============================================================================
// Global Statistics Instance
// ============================================================================

var (
	globalStats     *RollingStats
	globalStatsOnce sync.Once
)

// GlobalStats returns the global statistics instance.
func GlobalStats() *RollingStats {
	globalStatsOnce.Do(func() {
		globalStats = NewDefaultRollingStats()
	})
	return globalStats
}

// SetGlobalStats sets the global statistics instance.
func SetGlobalStats(stats *RollingStats) {
	globalStats = stats
}
