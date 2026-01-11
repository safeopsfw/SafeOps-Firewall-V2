// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types (Metrics Collector Specific)
// =============================================================================

var (
	// ErrInsufficientHistory indicates not enough samples for trend analysis.
	ErrInsufficientHistory = errors.New("insufficient history for analysis")
	// ErrCollectionTimeout indicates metrics collection exceeded timeout.
	ErrCollectionTimeout = errors.New("metrics collection timeout")
	// ErrInvalidWeights indicates performance weights don't sum to 1.0.
	ErrInvalidWeights = errors.New("invalid weights")
)

// =============================================================================
// Latency Trend
// =============================================================================

// LatencyTrend represents latency trend direction.
type LatencyTrend int

const (
	// TrendStable indicates consistent latency.
	TrendStable LatencyTrend = iota
	// TrendImproving indicates decreasing latency.
	TrendImproving
	// TrendDegrading indicates increasing latency.
	TrendDegrading
)

// String returns the string representation of the latency trend.
func (t LatencyTrend) String() string {
	switch t {
	case TrendStable:
		return "STABLE"
	case TrendImproving:
		return "IMPROVING"
	case TrendDegrading:
		return "DEGRADING"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Performance Weights
// =============================================================================

// PerformanceWeights defines weights for composite score calculation.
type PerformanceWeights struct {
	// HealthWeight is the health score impact.
	HealthWeight float64 `json:"health_weight"`
	// ThroughputWeight is the throughput impact.
	ThroughputWeight float64 `json:"throughput_weight"`
	// LatencyWeight is the latency impact.
	LatencyWeight float64 `json:"latency_weight"`
	// ErrorRateWeight is the error rate impact.
	ErrorRateWeight float64 `json:"error_rate_weight"`
	// UtilizationWeight is the bandwidth utilization impact.
	UtilizationWeight float64 `json:"utilization_weight"`
}

// DefaultPerformanceWeights returns the default weights.
func DefaultPerformanceWeights() PerformanceWeights {
	return PerformanceWeights{
		HealthWeight:      0.4,
		ThroughputWeight:  0.2,
		LatencyWeight:     0.2,
		ErrorRateWeight:   0.1,
		UtilizationWeight: 0.1,
	}
}

// Validate checks that weights sum to 1.0.
func (w PerformanceWeights) Validate() error {
	sum := w.HealthWeight + w.ThroughputWeight + w.LatencyWeight + w.ErrorRateWeight + w.UtilizationWeight
	if math.Abs(sum-1.0) > 0.001 {
		return ErrInvalidWeights
	}
	return nil
}

// =============================================================================
// Throughput Metrics
// =============================================================================

// ThroughputMetrics contains throughput measurements.
type ThroughputMetrics struct {
	// RxBytesPerSec is the receive bytes per second.
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	// TxBytesPerSec is the transmit bytes per second.
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	// RxPacketsPerSec is the receive packets per second.
	RxPacketsPerSec uint64 `json:"rx_packets_per_sec"`
	// TxPacketsPerSec is the transmit packets per second.
	TxPacketsPerSec uint64 `json:"tx_packets_per_sec"`
	// TotalRxBytes is the cumulative received bytes.
	TotalRxBytes uint64 `json:"total_rx_bytes"`
	// TotalTxBytes is the cumulative transmitted bytes.
	TotalTxBytes uint64 `json:"total_tx_bytes"`
	// PeakRxBytesPerSec is the peak receive rate.
	PeakRxBytesPerSec uint64 `json:"peak_rx_bytes_per_sec"`
	// PeakTxBytesPerSec is the peak transmit rate.
	PeakTxBytesPerSec uint64 `json:"peak_tx_bytes_per_sec"`
	// AverageRxBytesPerSec is the average receive rate.
	AverageRxBytesPerSec uint64 `json:"average_rx_bytes_per_sec"`
	// AverageTxBytesPerSec is the average transmit rate.
	AverageTxBytesPerSec uint64 `json:"average_tx_bytes_per_sec"`
}

// =============================================================================
// Bandwidth Metrics
// =============================================================================

// BandwidthMetrics contains bandwidth capacity and utilization.
type BandwidthMetrics struct {
	// MaxCapacity is the interface speed in bits/second.
	MaxCapacity uint64 `json:"max_capacity"`
	// RxUtilization is the receive utilization percentage.
	RxUtilization float64 `json:"rx_utilization"`
	// TxUtilization is the transmit utilization percentage.
	TxUtilization float64 `json:"tx_utilization"`
	// AvailableBandwidth is the unused capacity.
	AvailableBandwidth uint64 `json:"available_bandwidth"`
	// IsSaturated indicates utilization >= 90%.
	IsSaturated bool `json:"is_saturated"`
}

// =============================================================================
// Latency Metrics
// =============================================================================

// LatencyMetrics contains latency statistics.
type LatencyMetrics struct {
	// Current is the most recent RTT.
	Current time.Duration `json:"current"`
	// Average is the average over aggregation window.
	Average time.Duration `json:"average"`
	// Min is the minimum RTT observed.
	Min time.Duration `json:"min"`
	// Max is the maximum RTT observed.
	Max time.Duration `json:"max"`
	// P50 is the 50th percentile.
	P50 time.Duration `json:"p50"`
	// P95 is the 95th percentile.
	P95 time.Duration `json:"p95"`
	// P99 is the 99th percentile.
	P99 time.Duration `json:"p99"`
	// Jitter is the latency variance.
	Jitter time.Duration `json:"jitter"`
	// Trend is the trend direction.
	Trend LatencyTrend `json:"trend"`
}

// =============================================================================
// Error Metrics
// =============================================================================

// ErrorMetrics contains error and drop counters.
type ErrorMetrics struct {
	// RxErrors is the receive errors.
	RxErrors uint64 `json:"rx_errors"`
	// TxErrors is the transmit errors.
	TxErrors uint64 `json:"tx_errors"`
	// RxDrops is the receive drops.
	RxDrops uint64 `json:"rx_drops"`
	// TxDrops is the transmit drops.
	TxDrops uint64 `json:"tx_drops"`
	// Collisions is the collision count.
	Collisions uint64 `json:"collisions"`
	// ErrorRate is the errors per second.
	ErrorRate float64 `json:"error_rate"`
	// DropRate is the drops per second.
	DropRate float64 `json:"drop_rate"`
	// ErrorPercentage is the error percentage.
	ErrorPercentage float64 `json:"error_percentage"`
}

// =============================================================================
// Connection Metrics
// =============================================================================

// ConnectionMetrics contains connection tracking statistics.
type ConnectionMetrics struct {
	// ActiveConnections is the current active connections.
	ActiveConnections int `json:"active_connections"`
	// TotalConnectionsHandled is the cumulative connections.
	TotalConnectionsHandled uint64 `json:"total_connections_handled"`
	// NewConnectionsPerSec is the connection rate.
	NewConnectionsPerSec float64 `json:"new_connections_per_sec"`
	// AverageConnectionDuration is the mean connection lifetime.
	AverageConnectionDuration time.Duration `json:"average_connection_duration"`
	// ConnectionCapacity is the max connections.
	ConnectionCapacity int `json:"connection_capacity"`
	// UtilizationPercent is the connection utilization.
	UtilizationPercent float64 `json:"utilization_percent"`
}

// =============================================================================
// Metrics Snapshot
// =============================================================================

// MetricsSnapshot represents a point-in-time metrics sample.
type MetricsSnapshot struct {
	// Timestamp is when snapshot was taken.
	Timestamp time.Time `json:"timestamp"`
	// HealthScore is the health at that time.
	HealthScore float64 `json:"health_score"`
	// PerformanceScore is the performance at that time.
	PerformanceScore float64 `json:"performance_score"`
	// RxBytesPerSec is the throughput at that time.
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	// TxBytesPerSec is the throughput at that time.
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	// Latency is the RTT at that time.
	Latency time.Duration `json:"latency"`
	// ErrorRate is the error rate at that time.
	ErrorRate float64 `json:"error_rate"`
}

// =============================================================================
// Comprehensive WAN Metrics
// =============================================================================

// ComprehensiveWANMetrics contains complete performance metrics for a WAN.
type ComprehensiveWANMetrics struct {
	// WANID is the WAN identifier.
	WANID string `json:"wan_id"`
	// InterfaceName is the OS interface name.
	InterfaceName string `json:"interface_name"`
	// HealthScore is from the health checker.
	HealthScore float64 `json:"health_score"`
	// PerformanceScore is the composite score.
	PerformanceScore float64 `json:"performance_score"`
	// Throughput contains throughput measurements.
	Throughput ThroughputMetrics `json:"throughput"`
	// Bandwidth contains bandwidth metrics.
	Bandwidth BandwidthMetrics `json:"bandwidth"`
	// Latency contains latency statistics.
	Latency LatencyMetrics `json:"latency"`
	// Errors contains error counters.
	Errors ErrorMetrics `json:"errors"`
	// Connections contains connection metrics.
	Connections ConnectionMetrics `json:"connections"`
	// Timestamp is when metrics were last updated.
	Timestamp time.Time `json:"timestamp"`
	// History contains historical snapshots.
	History []*MetricsSnapshot `json:"history"`
}

// =============================================================================
// Peak Metrics
// =============================================================================

// PeakMetrics contains peak performance values.
type PeakMetrics struct {
	// PeakThroughput is the peak throughput.
	PeakThroughput uint64 `json:"peak_throughput"`
	// PeakLatency is the peak latency.
	PeakLatency time.Duration `json:"peak_latency"`
	// LowestErrorRate is the lowest error rate.
	LowestErrorRate float64 `json:"lowest_error_rate"`
	// HighestUtilization is the highest utilization.
	HighestUtilization float64 `json:"highest_utilization"`
}

// =============================================================================
// Metrics Configuration
// =============================================================================

// ComprehensiveMetricsConfig contains configuration for the metrics collector.
type ComprehensiveMetricsConfig struct {
	// CollectionInterval is how often to collect metrics.
	CollectionInterval time.Duration `json:"collection_interval"`
	// AggregationWindow is the time window for averaging.
	AggregationWindow time.Duration `json:"aggregation_window"`
	// EnableBandwidthMeasurement measures throughput.
	EnableBandwidthMeasurement bool `json:"enable_bandwidth_measurement"`
	// EnableLatencyTracking tracks latency trends.
	EnableLatencyTracking bool `json:"enable_latency_tracking"`
	// EnableErrorCounting counts errors and drops.
	EnableErrorCounting bool `json:"enable_error_counting"`
	// PerformanceScoreWeights are the metric weights.
	PerformanceScoreWeights PerformanceWeights `json:"performance_score_weights"`
	// HistoryRetention is how many samples to keep.
	HistoryRetention int `json:"history_retention"`
	// EnablePersistence saves metrics to database.
	EnablePersistence bool `json:"enable_persistence"`
	// PersistenceInterval is the DB write frequency.
	PersistenceInterval time.Duration `json:"persistence_interval"`
	// CompositeScoreFormula is the score calculation method.
	CompositeScoreFormula string `json:"composite_score_formula"`
}

// DefaultComprehensiveMetricsConfig returns the default configuration.
func DefaultComprehensiveMetricsConfig() *ComprehensiveMetricsConfig {
	return &ComprehensiveMetricsConfig{
		CollectionInterval:         5 * time.Second,
		AggregationWindow:          60 * time.Second,
		EnableBandwidthMeasurement: true,
		EnableLatencyTracking:      true,
		EnableErrorCounting:        true,
		PerformanceScoreWeights:    DefaultPerformanceWeights(),
		HistoryRetention:           720, // 1 hour at 5s intervals
		EnablePersistence:          true,
		PersistenceInterval:        300 * time.Second, // 5 minutes
		CompositeScoreFormula:      "weighted",
	}
}

// =============================================================================
// Performance Metrics Subscriber
// =============================================================================

// PerformanceMetricsSubscriber receives metric update notifications.
type PerformanceMetricsSubscriber interface {
	// OnComprehensiveMetricsUpdate is called when metrics are updated.
	OnComprehensiveMetricsUpdate(wanID string, metrics *ComprehensiveWANMetrics) error
	// OnPerformanceScoreChange is called when score changes significantly.
	OnPerformanceScoreChange(wanID string, oldScore, newScore float64) error
}

// =============================================================================
// Database Interface
// =============================================================================

// ComprehensiveMetricsDB defines the database interface.
type ComprehensiveMetricsDB interface {
	// LoadMetricsHistory loads recent snapshots.
	LoadMetricsHistory(ctx context.Context, wanID string, since time.Time) ([]*MetricsSnapshot, error)
	// SaveMetricsSnapshots saves snapshots.
	SaveMetricsSnapshots(ctx context.Context, wanID string, snapshots []*MetricsSnapshot) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpComprehensiveMetricsDB struct{}

func (n *noOpComprehensiveMetricsDB) LoadMetricsHistory(ctx context.Context, wanID string, since time.Time) ([]*MetricsSnapshot, error) {
	return nil, nil
}

func (n *noOpComprehensiveMetricsDB) SaveMetricsSnapshots(ctx context.Context, wanID string, snapshots []*MetricsSnapshot) error {
	return nil
}

// =============================================================================
// Comprehensive Metrics Collector
// =============================================================================

// ComprehensiveMetricsCollector aggregates WAN performance metrics.
type ComprehensiveMetricsCollector struct {
	// WAN pool manager.
	wanSelector *WANSelector
	// Health monitoring service.
	healthChecker *HealthChecker
	// Database for persistence.
	db ComprehensiveMetricsDB
	// Configuration.
	config *ComprehensiveMetricsConfig
	// Current metrics per WAN.
	metrics map[string]*ComprehensiveWANMetrics
	// Previous metrics for delta calculation.
	prevMetrics map[string]*ComprehensiveWANMetrics
	// Protects metrics.
	mu sync.RWMutex
	// Subscribers.
	subscribers   []PerformanceMetricsSubscriber
	subscribersMu sync.RWMutex
	// Statistics.
	totalCollections uint64
	collectionErrors uint64
	snapshotsCreated uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewComprehensiveMetricsCollector creates a new comprehensive metrics collector.
func NewComprehensiveMetricsCollector(wanSelector *WANSelector, healthChecker *HealthChecker, db ComprehensiveMetricsDB, config *ComprehensiveMetricsConfig) *ComprehensiveMetricsCollector {
	if config == nil {
		config = DefaultComprehensiveMetricsConfig()
	}

	if db == nil {
		db = &noOpComprehensiveMetricsDB{}
	}

	return &ComprehensiveMetricsCollector{
		wanSelector:   wanSelector,
		healthChecker: healthChecker,
		db:            db,
		config:        config,
		metrics:       make(map[string]*ComprehensiveWANMetrics),
		prevMetrics:   make(map[string]*ComprehensiveWANMetrics),
		subscribers:   make([]PerformanceMetricsSubscriber, 0),
		stopChan:      make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the comprehensive metrics collector.
func (cmc *ComprehensiveMetricsCollector) Start(ctx context.Context) error {
	cmc.runningMu.Lock()
	defer cmc.runningMu.Unlock()

	if cmc.running {
		return nil
	}

	// Initialize metrics for all WANs.
	if cmc.wanSelector != nil {
		wans := cmc.wanSelector.GetAllWANs()
		for _, wan := range wans {
			cmc.metrics[wan.ID] = &ComprehensiveWANMetrics{
				WANID:            wan.ID,
				InterfaceName:    wan.InterfaceName,
				HealthScore:      100.0,
				PerformanceScore: 100.0,
				Bandwidth: BandwidthMetrics{
					MaxCapacity: 1000000000, // 1 Gbps default
				},
				History: make([]*MetricsSnapshot, 0, cmc.config.HistoryRetention),
			}
		}
	}

	// Perform initial collection.
	_ = cmc.collectAllMetrics()

	// Start collection loop.
	cmc.wg.Add(1)
	go cmc.collectionLoop()

	// Start persistence loop.
	if cmc.config.EnablePersistence {
		cmc.wg.Add(1)
		go cmc.persistenceLoop()
	}

	// Subscribe to health updates.
	if cmc.healthChecker != nil {
		cmc.healthChecker.Subscribe(cmc)
	}

	cmc.running = true
	return nil
}

// Stop stops the comprehensive metrics collector.
func (cmc *ComprehensiveMetricsCollector) Stop() error {
	cmc.runningMu.Lock()
	if !cmc.running {
		cmc.runningMu.Unlock()
		return nil
	}
	cmc.running = false
	cmc.runningMu.Unlock()

	close(cmc.stopChan)
	cmc.wg.Wait()

	// Final persistence.
	if cmc.config.EnablePersistence {
		cmc.persistAllSnapshots()
	}

	return nil
}

// =============================================================================
// Background Loops
// =============================================================================

// collectionLoop runs periodic metrics collection.
func (cmc *ComprehensiveMetricsCollector) collectionLoop() {
	defer cmc.wg.Done()

	ticker := time.NewTicker(cmc.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cmc.stopChan:
			return
		case <-ticker.C:
			_ = cmc.collectAllMetrics()
		}
	}
}

// persistenceLoop periodically saves snapshots.
func (cmc *ComprehensiveMetricsCollector) persistenceLoop() {
	defer cmc.wg.Done()

	ticker := time.NewTicker(cmc.config.PersistenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cmc.stopChan:
			return
		case <-ticker.C:
			cmc.persistAllSnapshots()
		}
	}
}

// persistAllSnapshots saves all snapshots.
func (cmc *ComprehensiveMetricsCollector) persistAllSnapshots() {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for wanID, m := range cmc.metrics {
		if len(m.History) > 0 {
			_ = cmc.db.SaveMetricsSnapshots(ctx, wanID, m.History)
		}
	}
}

// =============================================================================
// Metrics Collection
// =============================================================================

// collectAllMetrics collects metrics for all WANs.
func (cmc *ComprehensiveMetricsCollector) collectAllMetrics() error {
	atomic.AddUint64(&cmc.totalCollections, 1)

	cmc.mu.RLock()
	wanIDs := make([]string, 0, len(cmc.metrics))
	for wanID := range cmc.metrics {
		wanIDs = append(wanIDs, wanID)
	}
	cmc.mu.RUnlock()

	var wg sync.WaitGroup
	for _, wanID := range wanIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := cmc.collectWANMetrics(id); err != nil {
				atomic.AddUint64(&cmc.collectionErrors, 1)
			}
		}(wanID)
	}

	wg.Wait()
	return nil
}

// collectWANMetrics collects metrics for a single WAN.
func (cmc *ComprehensiveMetricsCollector) collectWANMetrics(wanID string) error {
	cmc.mu.Lock()
	metrics, exists := cmc.metrics[wanID]
	if !exists {
		cmc.mu.Unlock()
		return ErrWANNotFound
	}

	prevMetrics := cmc.prevMetrics[wanID]
	cmc.mu.Unlock()

	now := time.Now()
	oldScore := metrics.PerformanceScore

	// Get health score.
	if cmc.healthChecker != nil {
		health, err := cmc.healthChecker.GetWANHealth(wanID)
		if err == nil {
			metrics.HealthScore = health.HealthScore
			metrics.Latency.Current = health.Latency
			metrics.Latency.Jitter = health.Jitter
		}
	}

	// Simulate interface statistics (would come from gopsutil in real impl).
	cmc.simulateInterfaceStats(metrics, prevMetrics, now)

	// Calculate bandwidth utilization.
	cmc.calculateBandwidth(metrics)

	// Update latency statistics.
	cmc.updateLatencyStats(metrics)

	// Calculate composite performance score.
	metrics.PerformanceScore = cmc.calculatePerformanceScore(metrics)

	// Create snapshot.
	snapshot := &MetricsSnapshot{
		Timestamp:        now,
		HealthScore:      metrics.HealthScore,
		PerformanceScore: metrics.PerformanceScore,
		RxBytesPerSec:    metrics.Throughput.RxBytesPerSec,
		TxBytesPerSec:    metrics.Throughput.TxBytesPerSec,
		Latency:          metrics.Latency.Current,
		ErrorRate:        metrics.Errors.ErrorRate,
	}

	// Update history.
	cmc.mu.Lock()
	metrics.History = append(metrics.History, snapshot)
	if len(metrics.History) > cmc.config.HistoryRetention {
		metrics.History = metrics.History[len(metrics.History)-cmc.config.HistoryRetention:]
	}
	metrics.Timestamp = now

	// Store for next delta calculation.
	metricsCopy := *metrics
	cmc.prevMetrics[wanID] = &metricsCopy
	cmc.mu.Unlock()

	atomic.AddUint64(&cmc.snapshotsCreated, 1)

	// Notify subscribers if score changed significantly.
	scoreChanged := math.Abs(oldScore-metrics.PerformanceScore) > 5.0
	cmc.notifySubscribers(wanID, metrics, scoreChanged, oldScore)

	return nil
}

// simulateInterfaceStats simulates interface statistics.
func (cmc *ComprehensiveMetricsCollector) simulateInterfaceStats(metrics *ComprehensiveWANMetrics, prevMetrics *ComprehensiveWANMetrics, now time.Time) {
	// In real implementation, this would call gopsutil.
	// For now, use placeholder values.
	if prevMetrics == nil {
		metrics.Throughput.TotalRxBytes = 0
		metrics.Throughput.TotalTxBytes = 0
		return
	}

	// Calculate delta.
	delta := now.Sub(prevMetrics.Timestamp)
	if delta.Seconds() <= 0 {
		return
	}

	// Simulate some throughput (in real impl, get from interface counters).
	metrics.Throughput.RxBytesPerSec = 1000000 // 1 MB/s placeholder
	metrics.Throughput.TxBytesPerSec = 500000  // 500 KB/s placeholder
	metrics.Throughput.RxPacketsPerSec = 1000
	metrics.Throughput.TxPacketsPerSec = 500

	// Update peaks.
	if metrics.Throughput.RxBytesPerSec > metrics.Throughput.PeakRxBytesPerSec {
		metrics.Throughput.PeakRxBytesPerSec = metrics.Throughput.RxBytesPerSec
	}
	if metrics.Throughput.TxBytesPerSec > metrics.Throughput.PeakTxBytesPerSec {
		metrics.Throughput.PeakTxBytesPerSec = metrics.Throughput.TxBytesPerSec
	}
}

// calculateBandwidth calculates bandwidth utilization.
func (cmc *ComprehensiveMetricsCollector) calculateBandwidth(metrics *ComprehensiveWANMetrics) {
	if metrics.Bandwidth.MaxCapacity == 0 {
		metrics.Bandwidth.MaxCapacity = 1000000000 // 1 Gbps default
	}

	// Convert bytes/sec to bits/sec.
	rxBitsPerSec := uint64(metrics.Throughput.RxBytesPerSec * 8)
	txBitsPerSec := uint64(metrics.Throughput.TxBytesPerSec * 8)

	// Calculate utilization.
	metrics.Bandwidth.RxUtilization = float64(rxBitsPerSec) / float64(metrics.Bandwidth.MaxCapacity) * 100.0
	metrics.Bandwidth.TxUtilization = float64(txBitsPerSec) / float64(metrics.Bandwidth.MaxCapacity) * 100.0

	// Calculate available bandwidth.
	usedBits := rxBitsPerSec + txBitsPerSec
	if usedBits < metrics.Bandwidth.MaxCapacity {
		metrics.Bandwidth.AvailableBandwidth = metrics.Bandwidth.MaxCapacity - usedBits
	} else {
		metrics.Bandwidth.AvailableBandwidth = 0
	}

	// Check saturation.
	maxUtilization := max(metrics.Bandwidth.RxUtilization, metrics.Bandwidth.TxUtilization)
	metrics.Bandwidth.IsSaturated = maxUtilization >= 90.0
}

// updateLatencyStats updates latency statistics from history.
func (cmc *ComprehensiveMetricsCollector) updateLatencyStats(metrics *ComprehensiveWANMetrics) {
	if len(metrics.History) == 0 {
		return
	}

	// Collect latencies.
	latencies := make([]time.Duration, 0, len(metrics.History))
	for _, s := range metrics.History {
		if s.Latency > 0 {
			latencies = append(latencies, s.Latency)
		}
	}

	if len(latencies) == 0 {
		return
	}

	// Calculate min/max/avg.
	var sum time.Duration
	minLatency := latencies[0]
	maxLatency := latencies[0]

	for _, l := range latencies {
		sum += l
		if l < minLatency {
			minLatency = l
		}
		if l > maxLatency {
			maxLatency = l
		}
	}

	metrics.Latency.Min = minLatency
	metrics.Latency.Max = maxLatency
	metrics.Latency.Average = sum / time.Duration(len(latencies))

	// Calculate percentiles.
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	metrics.Latency.P50 = sorted[len(sorted)*50/100]
	metrics.Latency.P95 = sorted[len(sorted)*95/100]
	if len(sorted) > 0 {
		metrics.Latency.P99 = sorted[len(sorted)*99/100]
	}

	// Calculate trend.
	metrics.Latency.Trend = cmc.calculateLatencyTrend(metrics.History)
}

// calculateLatencyTrend determines latency trend from history.
func (cmc *ComprehensiveMetricsCollector) calculateLatencyTrend(history []*MetricsSnapshot) LatencyTrend {
	if len(history) < 10 {
		return TrendStable
	}

	// Calculate linear regression slope.
	recentHistory := history[len(history)-10:]
	var sumX, sumY, sumXY, sumX2 float64

	for i, s := range recentHistory {
		x := float64(i)
		y := float64(s.Latency.Milliseconds())
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	n := float64(len(recentHistory))
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	// Determine trend based on slope.
	if slope < -0.1 {
		return TrendImproving
	} else if slope > 0.1 {
		return TrendDegrading
	}
	return TrendStable
}

// =============================================================================
// Performance Score Calculation
// =============================================================================

// calculatePerformanceScore computes composite performance score.
func (cmc *ComprehensiveMetricsCollector) calculatePerformanceScore(metrics *ComprehensiveWANMetrics) float64 {
	weights := cmc.config.PerformanceScoreWeights

	// Health component (0-100).
	healthComponent := metrics.HealthScore

	// Throughput component (0-100).
	// Higher throughput relative to capacity = better.
	throughputBits := float64(metrics.Throughput.RxBytesPerSec+metrics.Throughput.TxBytesPerSec) * 8
	maxBits := float64(metrics.Bandwidth.MaxCapacity)
	var throughputComponent float64
	if maxBits > 0 {
		throughputComponent = math.Min(100, throughputBits/maxBits*100)
	}

	// Latency component (0-100).
	// Lower latency = higher score.
	latencyMs := float64(metrics.Latency.Current.Milliseconds())
	latencyComponent := math.Max(0, 100-(latencyMs/5)) // 500ms = 0 score

	// Error component (0-100).
	// Lower errors = higher score.
	errorComponent := math.Max(0, 100-metrics.Errors.ErrorPercentage*10)

	// Utilization component (0-100).
	// Ideal utilization around 70%.
	avgUtilization := (metrics.Bandwidth.RxUtilization + metrics.Bandwidth.TxUtilization) / 2
	var utilizationComponent float64
	if avgUtilization <= 70 {
		utilizationComponent = avgUtilization / 70 * 100
	} else {
		utilizationComponent = 100 - (avgUtilization-70)/30*100
	}
	utilizationComponent = math.Max(0, math.Min(100, utilizationComponent))

	// Apply weights based on formula.
	var score float64
	switch cmc.config.CompositeScoreFormula {
	case "harmonic":
		// Harmonic mean.
		components := []float64{healthComponent, throughputComponent, latencyComponent, errorComponent, utilizationComponent}
		var sum float64
		count := 0
		for _, c := range components {
			if c > 0 {
				sum += 1 / c
				count++
			}
		}
		if count > 0 && sum > 0 {
			score = float64(count) / sum
		}
	case "geometric":
		// Geometric mean.
		product := healthComponent * throughputComponent * latencyComponent * errorComponent * utilizationComponent
		if product > 0 {
			score = math.Pow(product, 0.2)
		}
	default:
		// Weighted average (default).
		score = (healthComponent * weights.HealthWeight) +
			(throughputComponent * weights.ThroughputWeight) +
			(latencyComponent * weights.LatencyWeight) +
			(errorComponent * weights.ErrorRateWeight) +
			(utilizationComponent * weights.UtilizationWeight)
	}

	return math.Max(0, math.Min(100, score))
}

// =============================================================================
// Health Subscriber Implementation
// =============================================================================

// OnHealthUpdate receives health updates from health checker.
func (cmc *ComprehensiveMetricsCollector) OnHealthUpdate(wanID string, health *WANHealth) error {
	cmc.mu.Lock()
	metrics, exists := cmc.metrics[wanID]
	if exists {
		metrics.HealthScore = health.HealthScore
		metrics.Latency.Current = health.Latency
		metrics.Latency.Jitter = health.Jitter
		// Recalculate performance score.
		metrics.PerformanceScore = cmc.calculatePerformanceScore(metrics)
	}
	cmc.mu.Unlock()
	return nil
}

// OnStateChange receives state change notifications.
func (cmc *ComprehensiveMetricsCollector) OnStateChange(wanID string, oldState, newState HealthState) error {
	// State changes are handled via health score updates.
	return nil
}

// =============================================================================
// Subscription Management
// =============================================================================

// SubscribePerformance adds a subscriber for metric updates.
func (cmc *ComprehensiveMetricsCollector) SubscribePerformance(subscriber PerformanceMetricsSubscriber) {
	cmc.subscribersMu.Lock()
	defer cmc.subscribersMu.Unlock()
	cmc.subscribers = append(cmc.subscribers, subscriber)
}

// UnsubscribePerformance removes a subscriber.
func (cmc *ComprehensiveMetricsCollector) UnsubscribePerformance(subscriber PerformanceMetricsSubscriber) {
	cmc.subscribersMu.Lock()
	defer cmc.subscribersMu.Unlock()

	for i, s := range cmc.subscribers {
		if s == subscriber {
			cmc.subscribers = append(cmc.subscribers[:i], cmc.subscribers[i+1:]...)
			return
		}
	}
}

// notifySubscribers sends metric updates to subscribers.
func (cmc *ComprehensiveMetricsCollector) notifySubscribers(wanID string, metrics *ComprehensiveWANMetrics, scoreChanged bool, oldScore float64) {
	cmc.subscribersMu.RLock()
	subscribers := make([]PerformanceMetricsSubscriber, len(cmc.subscribers))
	copy(subscribers, cmc.subscribers)
	cmc.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s PerformanceMetricsSubscriber) {
			_ = s.OnComprehensiveMetricsUpdate(wanID, metrics)
			if scoreChanged {
				_ = s.OnPerformanceScoreChange(wanID, oldScore, metrics.PerformanceScore)
			}
		}(sub)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetComprehensiveWANMetrics retrieves current metrics for a WAN.
func (cmc *ComprehensiveMetricsCollector) GetComprehensiveWANMetrics(wanID string) (*ComprehensiveWANMetrics, error) {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	metrics, exists := cmc.metrics[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	// Return copy.
	copy := *metrics
	copy.History = make([]*MetricsSnapshot, len(metrics.History))
	for i, s := range metrics.History {
		snapshotCopy := *s
		copy.History[i] = &snapshotCopy
	}

	return &copy, nil
}

// GetAllComprehensiveMetrics retrieves metrics for all WANs.
func (cmc *ComprehensiveMetricsCollector) GetAllComprehensiveMetrics() map[string]*ComprehensiveWANMetrics {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	result := make(map[string]*ComprehensiveWANMetrics, len(cmc.metrics))
	for wanID, metrics := range cmc.metrics {
		copy := *metrics
		result[wanID] = &copy
	}
	return result
}

// GetPerformanceScoreFromCollector retrieves the composite performance score.
func (cmc *ComprehensiveMetricsCollector) GetPerformanceScoreFromCollector(wanID string) (float64, error) {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	metrics, exists := cmc.metrics[wanID]
	if !exists {
		return 0, ErrWANNotFound
	}

	return metrics.PerformanceScore, nil
}

// GetMetricsHistoryFromCollector retrieves historical snapshots.
func (cmc *ComprehensiveMetricsCollector) GetMetricsHistoryFromCollector(wanID string, duration time.Duration) ([]*MetricsSnapshot, error) {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	metrics, exists := cmc.metrics[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	cutoff := time.Now().Add(-duration)
	result := make([]*MetricsSnapshot, 0)
	for _, s := range metrics.History {
		if s.Timestamp.After(cutoff) {
			copy := *s
			result = append(result, &copy)
		}
	}

	return result, nil
}

// GetPeakMetrics retrieves peak performance values.
func (cmc *ComprehensiveMetricsCollector) GetPeakMetrics(wanID string) (*PeakMetrics, error) {
	cmc.mu.RLock()
	defer cmc.mu.RUnlock()

	metrics, exists := cmc.metrics[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	peak := &PeakMetrics{
		PeakThroughput:     metrics.Throughput.PeakRxBytesPerSec + metrics.Throughput.PeakTxBytesPerSec,
		PeakLatency:        metrics.Latency.Max,
		LowestErrorRate:    100.0,
		HighestUtilization: 0.0,
	}

	for _, s := range metrics.History {
		if s.ErrorRate < peak.LowestErrorRate {
			peak.LowestErrorRate = s.ErrorRate
		}
		utilization := float64(s.RxBytesPerSec+s.TxBytesPerSec) * 8 / float64(metrics.Bandwidth.MaxCapacity) * 100
		if utilization > peak.HighestUtilization {
			peak.HighestUtilization = utilization
		}
	}

	return peak, nil
}

// GetThroughputTrend analyzes throughput trend.
func (cmc *ComprehensiveMetricsCollector) GetThroughputTrend(wanID string, duration time.Duration) (string, error) {
	history, err := cmc.GetMetricsHistoryFromCollector(wanID, duration)
	if err != nil {
		return "", err
	}

	if len(history) < 10 {
		return "INSUFFICIENT_DATA", ErrInsufficientHistory
	}

	// Calculate trend from throughput.
	var sumX, sumY, sumXY, sumX2 float64
	for i, s := range history {
		x := float64(i)
		y := float64(s.RxBytesPerSec + s.TxBytesPerSec)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	n := float64(len(history))
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	if slope > 1000 {
		return "INCREASING", nil
	} else if slope < -1000 {
		return "DECREASING", nil
	}
	return "STABLE", nil
}

// ResetMetrics clears metrics history for a WAN.
func (cmc *ComprehensiveMetricsCollector) ResetMetrics(wanID string) error {
	cmc.mu.Lock()
	defer cmc.mu.Unlock()

	metrics, exists := cmc.metrics[wanID]
	if !exists {
		return ErrWANNotFound
	}

	metrics.History = make([]*MetricsSnapshot, 0, cmc.config.HistoryRetention)
	metrics.Throughput.PeakRxBytesPerSec = 0
	metrics.Throughput.PeakTxBytesPerSec = 0

	return nil
}

// =============================================================================
// WAN Management
// =============================================================================

// AddWANToCollector adds a WAN for metrics collection.
func (cmc *ComprehensiveMetricsCollector) AddWANToCollector(wanID, interfaceName string) error {
	cmc.mu.Lock()
	defer cmc.mu.Unlock()

	if _, exists := cmc.metrics[wanID]; exists {
		return nil
	}

	cmc.metrics[wanID] = &ComprehensiveWANMetrics{
		WANID:            wanID,
		InterfaceName:    interfaceName,
		HealthScore:      100.0,
		PerformanceScore: 100.0,
		Bandwidth: BandwidthMetrics{
			MaxCapacity: 1000000000,
		},
		History: make([]*MetricsSnapshot, 0, cmc.config.HistoryRetention),
	}

	return nil
}

// RemoveWANFromCollector removes a WAN from metrics collection.
func (cmc *ComprehensiveMetricsCollector) RemoveWANFromCollector(wanID string) error {
	cmc.mu.Lock()
	defer cmc.mu.Unlock()

	delete(cmc.metrics, wanID)
	delete(cmc.prevMetrics, wanID)
	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheckCollector verifies the collector is operational.
func (cmc *ComprehensiveMetricsCollector) HealthCheckCollector() error {
	cmc.runningMu.Lock()
	running := cmc.running
	cmc.runningMu.Unlock()

	if !running {
		return errors.New("comprehensive metrics collector not running")
	}

	cmc.mu.RLock()
	count := len(cmc.metrics)
	cmc.mu.RUnlock()

	if count == 0 {
		return errors.New("no WANs being monitored")
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetCollectorStatistics returns collector statistics.
func (cmc *ComprehensiveMetricsCollector) GetCollectorStatistics() map[string]interface{} {
	return map[string]interface{}{
		"total_collections":   atomic.LoadUint64(&cmc.totalCollections),
		"collection_errors":   atomic.LoadUint64(&cmc.collectionErrors),
		"snapshots_created":   atomic.LoadUint64(&cmc.snapshotsCreated),
		"monitored_wans":      len(cmc.metrics),
		"history_retention":   cmc.config.HistoryRetention,
		"collection_interval": cmc.config.CollectionInterval.String(),
	}
}

// GetConfig returns the current configuration.
func (cmc *ComprehensiveMetricsCollector) GetComprehensiveConfig() *ComprehensiveMetricsConfig {
	return cmc.config
}

// IsRunning returns whether the collector is running.
func (cmc *ComprehensiveMetricsCollector) IsCollectorRunning() bool {
	cmc.runningMu.Lock()
	defer cmc.runningMu.Unlock()
	return cmc.running
}

// =============================================================================
// Utility
// =============================================================================

// max returns the maximum of two float64 values.
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
