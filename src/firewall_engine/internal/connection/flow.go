// Package connection provides stateful connection tracking for the firewall engine.
package connection

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Flow Statistics
// ============================================================================

// FlowStats contains traffic statistics for a single flow/connection.
type FlowStats struct {
	// Key identifies the connection
	Key ConnectionKey `json:"key"`

	// Packets
	PacketsForward uint64 `json:"packets_forward"`
	PacketsReverse uint64 `json:"packets_reverse"`
	PacketsTotal   uint64 `json:"packets_total"`

	// Bytes
	BytesForward uint64 `json:"bytes_forward"`
	BytesReverse uint64 `json:"bytes_reverse"`
	BytesTotal   uint64 `json:"bytes_total"`

	// Rates (per second)
	PacketRate float64 `json:"packet_rate"`
	ByteRate   float64 `json:"byte_rate"`

	// Timing
	Duration   time.Duration `json:"duration"`
	IdleTime   time.Duration `json:"idle_time"`
	StartTime  time.Time     `json:"start_time"`
	LastActive time.Time     `json:"last_active"`

	// State
	State    string `json:"state"`
	TCPState string `json:"tcp_state,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// ============================================================================
// Flow Statistics Calculator
// ============================================================================

// FlowCalculator calculates flow statistics from the connection table.
type FlowCalculator struct {
	table *ConnectionTable
}

// NewFlowCalculator creates a new flow statistics calculator.
func NewFlowCalculator(table *ConnectionTable) *FlowCalculator {
	return &FlowCalculator{
		table: table,
	}
}

// GetFlowStats calculates statistics for a specific connection.
func (fc *FlowCalculator) GetFlowStats(key ConnectionKey) (*FlowStats, bool) {
	entry, exists := fc.table.Get(key)
	if !exists {
		return nil, false
	}

	return fc.calculateStats(entry), true
}

// calculateStats computes flow statistics from a connection entry.
func (fc *FlowCalculator) calculateStats(entry *ConnectionEntry) *FlowStats {
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	now := time.Now()
	duration := now.Sub(entry.CreatedAt)
	idleTime := now.Sub(entry.LastSeen)

	// Get packet/byte counts
	packetsForward := entry.PacketsForward.Load()
	packetsReverse := entry.PacketsReverse.Load()
	bytesForward := entry.BytesForward.Load()
	bytesReverse := entry.BytesReverse.Load()

	// Calculate rates
	var packetRate, byteRate float64
	if duration.Seconds() > 0 {
		totalPackets := packetsForward + packetsReverse
		totalBytes := bytesForward + bytesReverse
		packetRate = float64(totalPackets) / duration.Seconds()
		byteRate = float64(totalBytes) / duration.Seconds()
	}

	return &FlowStats{
		Key:            entry.Key,
		PacketsForward: packetsForward,
		PacketsReverse: packetsReverse,
		PacketsTotal:   packetsForward + packetsReverse,
		BytesForward:   bytesForward,
		BytesReverse:   bytesReverse,
		BytesTotal:     bytesForward + bytesReverse,
		PacketRate:     packetRate,
		ByteRate:       byteRate,
		Duration:       duration,
		IdleTime:       idleTime,
		StartTime:      entry.CreatedAt,
		LastActive:     entry.LastSeen,
		State:          entry.State.String(),
		TCPState:       entry.TCPState.String(),
		Domain:         entry.Domain,
	}
}

// GetAllFlowStats returns statistics for all connections.
func (fc *FlowCalculator) GetAllFlowStats() []*FlowStats {
	var stats []*FlowStats

	fc.table.Range(func(key ConnectionKey, entry *ConnectionEntry) bool {
		if !entry.IsMarkedForDeletion() {
			stats = append(stats, fc.calculateStats(entry))
		}
		return true
	})

	return stats
}

// ============================================================================
// Top-N Flows
// ============================================================================

// FlowSortBy defines the field to sort flows by.
type FlowSortBy int

const (
	SortByPackets FlowSortBy = iota
	SortByBytes
	SortByPacketRate
	SortByByteRate
	SortByDuration
)

// GetTopFlows returns the top N flows sorted by the specified criteria.
func (fc *FlowCalculator) GetTopFlows(n int, sortBy FlowSortBy) []*FlowStats {
	stats := fc.GetAllFlowStats()

	// Sort by criteria
	switch sortBy {
	case SortByPackets:
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].PacketsTotal > stats[j].PacketsTotal
		})
	case SortByBytes:
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].BytesTotal > stats[j].BytesTotal
		})
	case SortByPacketRate:
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].PacketRate > stats[j].PacketRate
		})
	case SortByByteRate:
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].ByteRate > stats[j].ByteRate
		})
	case SortByDuration:
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].Duration > stats[j].Duration
		})
	}

	// Limit to N
	if len(stats) > n {
		stats = stats[:n]
	}

	return stats
}

// ============================================================================
// Aggregate Statistics
// ============================================================================

// AggregateStats contains aggregate flow statistics.
type AggregateStats struct {
	TotalConnections  int     `json:"total_connections"`
	TotalPackets      uint64  `json:"total_packets"`
	TotalBytes        uint64  `json:"total_bytes"`
	PacketRate        float64 `json:"packet_rate"`
	ByteRate          float64 `json:"byte_rate"`
	AvgDuration       float64 `json:"avg_duration_seconds"`
	AvgPacketsPerFlow float64 `json:"avg_packets_per_flow"`
	AvgBytesPerFlow   float64 `json:"avg_bytes_per_flow"`
}

// GetAggregateStats calculates aggregate statistics across all flows.
func (fc *FlowCalculator) GetAggregateStats() AggregateStats {
	var (
		totalPackets    uint64
		totalBytes      uint64
		totalDuration   float64
		connectionCount int
	)

	fc.table.Range(func(key ConnectionKey, entry *ConnectionEntry) bool {
		if entry.IsMarkedForDeletion() {
			return true
		}

		entry.mu.RLock()
		totalPackets += entry.PacketsForward.Load() + entry.PacketsReverse.Load()
		totalBytes += entry.BytesForward.Load() + entry.BytesReverse.Load()
		totalDuration += time.Since(entry.CreatedAt).Seconds()
		entry.mu.RUnlock()

		connectionCount++
		return true
	})

	stats := AggregateStats{
		TotalConnections: connectionCount,
		TotalPackets:     totalPackets,
		TotalBytes:       totalBytes,
	}

	if connectionCount > 0 {
		stats.AvgDuration = totalDuration / float64(connectionCount)
		stats.AvgPacketsPerFlow = float64(totalPackets) / float64(connectionCount)
		stats.AvgBytesPerFlow = float64(totalBytes) / float64(connectionCount)
	}

	return stats
}

// ============================================================================
// Real-time Rate Tracking
// ============================================================================

// RateTracker tracks real-time packet and byte rates.
type RateTracker struct {
	// Sliding window for rate calculation
	windowSize    time.Duration
	bucketSize    time.Duration
	bucketCount   int
	buckets       []rateBucket
	currentBucket int
	mu            sync.Mutex

	// Totals
	totalPackets atomic.Uint64
	totalBytes   atomic.Uint64
}

// rateBucket holds counts for a single time bucket.
type rateBucket struct {
	timestamp time.Time
	packets   uint64
	bytes     uint64
}

// NewRateTracker creates a new rate tracker.
// windowSize: total time window for rate calculation (e.g., 60 seconds)
// bucketCount: number of buckets in the window (e.g., 60 for 1-second resolution)
func NewRateTracker(windowSize time.Duration, bucketCount int) *RateTracker {
	if bucketCount < 1 {
		bucketCount = 60
	}
	bucketSize := windowSize / time.Duration(bucketCount)

	return &RateTracker{
		windowSize:  windowSize,
		bucketSize:  bucketSize,
		bucketCount: bucketCount,
		buckets:     make([]rateBucket, bucketCount),
	}
}

// Record records a packet with the given size.
func (rt *RateTracker) Record(packetSize uint64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	rt.maybeRotateBuckets(now)

	rt.buckets[rt.currentBucket].packets++
	rt.buckets[rt.currentBucket].bytes += packetSize
	rt.buckets[rt.currentBucket].timestamp = now

	rt.totalPackets.Add(1)
	rt.totalBytes.Add(packetSize)
}

// maybeRotateBuckets rotates buckets if enough time has passed.
func (rt *RateTracker) maybeRotateBuckets(now time.Time) {
	if rt.buckets[rt.currentBucket].timestamp.IsZero() {
		rt.buckets[rt.currentBucket].timestamp = now
		return
	}

	elapsed := now.Sub(rt.buckets[rt.currentBucket].timestamp)
	bucketsToRotate := int(elapsed / rt.bucketSize)

	if bucketsToRotate <= 0 {
		return
	}

	// Rotate buckets
	for i := 0; i < bucketsToRotate && i < rt.bucketCount; i++ {
		rt.currentBucket = (rt.currentBucket + 1) % rt.bucketCount
		rt.buckets[rt.currentBucket] = rateBucket{timestamp: now}
	}
}

// GetRates returns the current packet and byte rates per second.
func (rt *RateTracker) GetRates() (packetRate, byteRate float64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	rt.maybeRotateBuckets(now)

	// Sum all buckets within the window
	var totalPackets, totalBytes uint64
	var validDuration time.Duration

	for i := 0; i < rt.bucketCount; i++ {
		bucket := rt.buckets[i]
		if bucket.timestamp.IsZero() {
			continue
		}

		age := now.Sub(bucket.timestamp)
		if age > rt.windowSize {
			continue
		}

		totalPackets += bucket.packets
		totalBytes += bucket.bytes
		validDuration += rt.bucketSize
	}

	if validDuration > 0 {
		seconds := validDuration.Seconds()
		packetRate = float64(totalPackets) / seconds
		byteRate = float64(totalBytes) / seconds
	}

	return
}

// GetTotals returns the total packets and bytes tracked.
func (rt *RateTracker) GetTotals() (packets, bytes uint64) {
	return rt.totalPackets.Load(), rt.totalBytes.Load()
}
