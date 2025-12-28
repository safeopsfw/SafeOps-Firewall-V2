// Package performance provides network interface performance monitoring
// for the NIC Management service.
package performance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Metrics Aggregator Error Types
// =============================================================================

var (
	// ErrAggregatorInterfaceNotFound indicates interface not found.
	ErrAggregatorInterfaceNotFound = errors.New("interface not found for aggregation")
	// ErrNoAggregatedData indicates no aggregated data available.
	ErrNoAggregatedData = errors.New("no aggregated data available")
	// ErrInsufficientDataForTrend indicates not enough data for trend analysis.
	ErrInsufficientDataForTrend = errors.New("insufficient data for trend analysis")
)

// =============================================================================
// Metric Dimension Constants
// =============================================================================

const (
	DimensionThroughput  = "throughput"
	DimensionLatency     = "latency"
	DimensionErrorRate   = "error_rate"
	DimensionPacketRate  = "packet_rate"
	DimensionUtilization = "utilization"
	DimensionJitter      = "jitter"
)

// Trend constants.
const (
	TrendImproving = "improving"
	TrendDegrading = "degrading"
	TrendStable    = "stable"
)

// =============================================================================
// Metric Weights Structure
// =============================================================================

// MetricWeights contains configurable weights for composite score calculation.
type MetricWeights struct {
	Throughput  float64 `json:"throughput"`
	Latency     float64 `json:"latency"`
	ErrorRate   float64 `json:"error_rate"`
	PacketRate  float64 `json:"packet_rate"`
	Utilization float64 `json:"utilization"`
	Jitter      float64 `json:"jitter"`
}

// DefaultMetricWeights returns the default metric weights.
func DefaultMetricWeights() *MetricWeights {
	return &MetricWeights{
		Throughput:  0.25, // 25%
		Latency:     0.25, // 25%
		ErrorRate:   0.20, // 20%
		PacketRate:  0.15, // 15%
		Utilization: 0.10, // 10%
		Jitter:      0.05, // 5%
	}
}

// Sum returns the sum of all weights.
func (w *MetricWeights) Sum() float64 {
	return w.Throughput + w.Latency + w.ErrorRate + w.PacketRate + w.Utilization + w.Jitter
}

// Normalize adjusts weights to sum to 1.0.
func (w *MetricWeights) Normalize() {
	sum := w.Sum()
	if sum <= 0 {
		*w = *DefaultMetricWeights()
		return
	}
	w.Throughput /= sum
	w.Latency /= sum
	w.ErrorRate /= sum
	w.PacketRate /= sum
	w.Utilization /= sum
	w.Jitter /= sum
}

// =============================================================================
// Performance Snapshot Structure
// =============================================================================

// PerformanceSnapshot is a single point-in-time snapshot.
type PerformanceSnapshot struct {
	Timestamp          time.Time `json:"timestamp"`
	CompositeScore     float64   `json:"composite_score"`
	ThroughputMbps     float64   `json:"throughput_mbps"`
	LatencyMs          float64   `json:"latency_ms"`
	ErrorsPerSec       float64   `json:"errors_per_sec"`
	PacketsPerSec      float64   `json:"packets_per_sec"`
	UtilizationPercent float64   `json:"utilization_percent"`
}

// =============================================================================
// Score Breakdown Structure
// =============================================================================

// ScoreBreakdown contains individual component scores.
type ScoreBreakdown struct {
	ThroughputScore  float64        `json:"throughput_score"`
	LatencyScore     float64        `json:"latency_score"`
	ErrorRateScore   float64        `json:"error_rate_score"`
	PacketRateScore  float64        `json:"packet_rate_score"`
	UtilizationScore float64        `json:"utilization_score"`
	JitterScore      float64        `json:"jitter_score"`
	Weights          *MetricWeights `json:"weights"`
}

// =============================================================================
// Performance Score Structure
// =============================================================================

// PerformanceScore contains composite score with breakdown.
type PerformanceScore struct {
	Overall          float64        `json:"overall"`
	ThroughputScore  float64        `json:"throughput_score"`
	LatencyScore     float64        `json:"latency_score"`
	ErrorRateScore   float64        `json:"error_rate_score"`
	PacketRateScore  float64        `json:"packet_rate_score"`
	UtilizationScore float64        `json:"utilization_score"`
	JitterScore      float64        `json:"jitter_score"`
	Weights          *MetricWeights `json:"weights"`
}

// =============================================================================
// Metric Statistics Structure
// =============================================================================

// MetricStatistics contains statistical summary.
type MetricStatistics struct {
	Min          float64 `json:"min"`
	Max          float64 `json:"max"`
	Average      float64 `json:"average"`
	StdDev       float64 `json:"std_dev"`
	Percentile50 float64 `json:"percentile_50"`
	Percentile95 float64 `json:"percentile_95"`
	Percentile99 float64 `json:"percentile_99"`
	SampleCount  int     `json:"sample_count"`
}

// =============================================================================
// Throughput Metrics Structure
// =============================================================================

// ThroughputMetricsData contains throughput data.
type ThroughputMetricsData struct {
	RxBytesPerSec uint64  `json:"rx_bytes_per_sec"`
	TxBytesPerSec uint64  `json:"tx_bytes_per_sec"`
	RxMbps        float64 `json:"rx_mbps"`
	TxMbps        float64 `json:"tx_mbps"`
	TotalMbps     float64 `json:"total_mbps"`
	Trend         string  `json:"trend"`
}

// =============================================================================
// Packet Rate Metrics Structure
// =============================================================================

// PacketRateMetricsData contains packet rate data.
type PacketRateMetricsData struct {
	RxPacketsPerSec    uint64  `json:"rx_packets_per_sec"`
	TxPacketsPerSec    uint64  `json:"tx_packets_per_sec"`
	TotalPacketsPerSec uint64  `json:"total_packets_per_sec"`
	AveragePacketSize  float64 `json:"average_packet_size"`
	MicroburstDetected bool    `json:"microburst_detected"`
}

// =============================================================================
// Error Rate Metrics Structure
// =============================================================================

// ErrorRateMetricsData contains error rate data.
type ErrorRateMetricsData struct {
	TotalErrorsPerSec float64 `json:"total_errors_per_sec"`
	RxErrorsPerSec    float64 `json:"rx_errors_per_sec"`
	TxErrorsPerSec    float64 `json:"tx_errors_per_sec"`
	DroppedPerSec     float64 `json:"dropped_per_sec"`
}

// =============================================================================
// Utilization Metrics Structure
// =============================================================================

// UtilizationMetricsData contains utilization data.
type UtilizationMetricsData struct {
	RxUtilization    float64 `json:"rx_utilization"`
	TxUtilization    float64 `json:"tx_utilization"`
	TotalUtilization float64 `json:"total_utilization"`
	MaxBandwidth     uint64  `json:"max_bandwidth"`
}

// =============================================================================
// Latency Metrics Structure
// =============================================================================

// LatencyMetricsData contains latency data.
type LatencyMetricsData struct {
	CurrentMs float64 `json:"current_ms"`
	AverageMs float64 `json:"average_ms"`
	MinMs     float64 `json:"min_ms"`
	MaxMs     float64 `json:"max_ms"`
}

// =============================================================================
// Jitter Metrics Structure
// =============================================================================

// JitterMetricsData contains jitter data.
type JitterMetricsData struct {
	CurrentMs float64 `json:"current_ms"`
	AverageMs float64 `json:"average_ms"`
}

// =============================================================================
// Aggregated Metrics Structure
// =============================================================================

// AggregatedMetrics contains unified performance snapshot.
type AggregatedMetrics struct {
	InterfaceName   string                 `json:"interface_name"`
	Timestamp       time.Time              `json:"timestamp"`
	Throughput      ThroughputMetricsData  `json:"throughput"`
	PacketRate      PacketRateMetricsData  `json:"packet_rate"`
	ErrorRates      ErrorRateMetricsData   `json:"error_rates"`
	Utilization     UtilizationMetricsData `json:"utilization"`
	Latency         LatencyMetricsData     `json:"latency"`
	Jitter          JitterMetricsData      `json:"jitter"`
	CompositeScore  float64                `json:"composite_score"`
	ScoreComponents *ScoreBreakdown        `json:"score_components"`
	History         []*PerformanceSnapshot `json:"history,omitempty"`
	Trend           string                 `json:"trend"`
	Statistics      *MetricStatistics      `json:"statistics,omitempty"`
	LinkSpeed       uint64                 `json:"link_speed"`
}

// =============================================================================
// Interface Ranking Structure
// =============================================================================

// InterfaceRanking contains ranking information.
type InterfaceRanking struct {
	Rank           int     `json:"rank"`
	InterfaceName  string  `json:"interface_name"`
	CompositeScore float64 `json:"composite_score"`
	Trend          string  `json:"trend"`
}

// =============================================================================
// Comparison Result Structure
// =============================================================================

// ComparisonResult contains interface comparison.
type ComparisonResult struct {
	Interface1     string             `json:"interface_1"`
	Interface2     string             `json:"interface_2"`
	Winner         string             `json:"winner"`
	ScoreDiff      float64            `json:"score_diff"`
	DimensionDiffs map[string]float64 `json:"dimension_diffs"`
}

// =============================================================================
// Aggregator Configuration
// =============================================================================

// AggregatorConfig contains configuration for metrics aggregator.
type AggregatorConfig struct {
	// AggregationWindow is time window for metric averaging (default: 60s).
	AggregationWindow time.Duration `json:"aggregation_window"`
	// HistoryRetention is how long to keep historical data (default: 24h).
	HistoryRetention time.Duration `json:"history_retention"`
	// CollectionInterval is how often to aggregate (default: 10s).
	CollectionInterval time.Duration `json:"collection_interval"`
	// Weights are the metric weights for scoring.
	Weights *MetricWeights `json:"weights"`
	// TrendSampleCount is samples for trend regression (default: 10).
	TrendSampleCount int `json:"trend_sample_count"`
	// TrendSlopeThreshold is min slope for improving/degrading (default: 0.5).
	TrendSlopeThreshold float64 `json:"trend_slope_threshold"`
	// DefaultLinkSpeed is assumed link speed when unknown (default: 1Gbps).
	DefaultLinkSpeed uint64 `json:"default_link_speed"`
}

// DefaultAggregatorConfig returns the default aggregator configuration.
func DefaultAggregatorConfig() *AggregatorConfig {
	return &AggregatorConfig{
		AggregationWindow:   60 * time.Second,
		HistoryRetention:    24 * time.Hour,
		CollectionInterval:  10 * time.Second,
		Weights:             DefaultMetricWeights(),
		TrendSampleCount:    10,
		TrendSlopeThreshold: 0.5,
		DefaultLinkSpeed:    1_000_000_000, // 1 Gbps.
	}
}

// =============================================================================
// Metrics Aggregator
// =============================================================================

// MetricsAggregator aggregates all performance metrics.
type MetricsAggregator struct {
	// Dependencies.
	statsCollector    *StatisticsCollector
	throughputCalc    *ThroughputCalculator
	packetRateMonitor *PacketRateCalculator
	errorCounter      *ErrorCounter

	// Configuration.
	config *AggregatorConfig

	// State.
	interfaces map[string]*AggregatedMetrics
	mu         sync.RWMutex

	// Collection control.
	ticker         *time.Ticker
	lastCollection time.Time

	// Statistics.
	aggregationsTotal uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewMetricsAggregator creates a new metrics aggregator.
func NewMetricsAggregator(
	statsCollector *StatisticsCollector,
	throughputCalc *ThroughputCalculator,
	packetRateMonitor *PacketRateCalculator,
	errorCounter *ErrorCounter,
	config *AggregatorConfig,
) *MetricsAggregator {
	if config == nil {
		config = DefaultAggregatorConfig()
	}

	if config.Weights == nil {
		config.Weights = DefaultMetricWeights()
	}
	config.Weights.Normalize()

	return &MetricsAggregator{
		statsCollector:    statsCollector,
		throughputCalc:    throughputCalc,
		packetRateMonitor: packetRateMonitor,
		errorCounter:      errorCounter,
		config:            config,
		interfaces:        make(map[string]*AggregatedMetrics),
		stopChan:          make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins the aggregation loop.
func (ma *MetricsAggregator) Start(ctx context.Context) error {
	ma.runningMu.Lock()
	defer ma.runningMu.Unlock()

	if ma.running {
		return nil
	}

	// Perform initial aggregation.
	ma.aggregateAllMetrics()

	// Start aggregation ticker.
	ma.ticker = time.NewTicker(ma.config.CollectionInterval)
	go ma.aggregationLoop()

	ma.running = true
	return nil
}

// Stop gracefully shuts down the aggregator.
func (ma *MetricsAggregator) Stop() error {
	ma.runningMu.Lock()
	if !ma.running {
		ma.runningMu.Unlock()
		return nil
	}
	ma.running = false
	ma.runningMu.Unlock()

	if ma.ticker != nil {
		ma.ticker.Stop()
	}
	close(ma.stopChan)

	return nil
}

// aggregationLoop is the background aggregation goroutine.
func (ma *MetricsAggregator) aggregationLoop() {
	for {
		select {
		case <-ma.stopChan:
			return
		case <-ma.ticker.C:
			ma.aggregateAllMetrics()
		}
	}
}

// =============================================================================
// Metric Aggregation
// =============================================================================

// aggregateAllMetrics aggregates metrics for all interfaces.
func (ma *MetricsAggregator) aggregateAllMetrics() {
	// Collect interface names from all sources.
	interfaceNames := make(map[string]bool)

	if ma.statsCollector != nil {
		for name := range ma.statsCollector.GetAllStatistics() {
			interfaceNames[name] = true
		}
	}

	if ma.throughputCalc != nil {
		for name := range ma.throughputCalc.GetAllThroughput() {
			interfaceNames[name] = true
		}
	}

	// Aggregate each interface.
	for name := range interfaceNames {
		ma.CollectAllMetrics(name)
	}

	atomic.AddUint64(&ma.aggregationsTotal, 1)
	ma.lastCollection = time.Now()

	// Prune old history.
	ma.pruneHistory()
}

// CollectAllMetrics collects and aggregates metrics for an interface.
func (ma *MetricsAggregator) CollectAllMetrics(interfaceName string) (*AggregatedMetrics, error) {
	now := time.Now()

	aggregated := &AggregatedMetrics{
		InterfaceName: interfaceName,
		Timestamp:     now,
		LinkSpeed:     ma.config.DefaultLinkSpeed,
	}

	// Collect from statistics collector.
	if ma.statsCollector != nil {
		if stats, err := ma.statsCollector.GetInterfaceStatistics(interfaceName); err == nil {
			aggregated.Throughput.RxBytesPerSec = stats.RxBytesPerSec
			aggregated.Throughput.TxBytesPerSec = stats.TxBytesPerSec
			aggregated.PacketRate.RxPacketsPerSec = stats.RxPacketsPerSec
			aggregated.PacketRate.TxPacketsPerSec = stats.TxPacketsPerSec
			aggregated.ErrorRates.RxErrorsPerSec = stats.RxErrorsPerSec
			aggregated.ErrorRates.TxErrorsPerSec = stats.TxErrorsPerSec
		}
	}

	// Collect from throughput calculator.
	if ma.throughputCalc != nil {
		if throughput, err := ma.throughputCalc.GetInterfaceThroughput(interfaceName); err == nil {
			aggregated.Throughput.RxMbps = throughput.RxMbps
			aggregated.Throughput.TxMbps = throughput.TxMbps
			aggregated.Throughput.TotalMbps = throughput.TotalMbps
			aggregated.Throughput.Trend = throughput.Trend.String()
			aggregated.Utilization.RxUtilization = throughput.RxUtilization
			aggregated.Utilization.TxUtilization = throughput.TxUtilization
			aggregated.Utilization.TotalUtilization = throughput.TotalUtilization
			aggregated.Utilization.MaxBandwidth = throughput.MaxBandwidth
			if throughput.MaxBandwidth > 0 {
				aggregated.LinkSpeed = throughput.MaxBandwidth
			}
		}
	}

	// Collect from packet rate calculator.
	if ma.packetRateMonitor != nil {
		if pktRate, err := ma.packetRateMonitor.GetInterfacePacketRate(interfaceName); err == nil {
			aggregated.PacketRate.TotalPacketsPerSec = pktRate.TotalPacketsPerSec
			aggregated.PacketRate.AveragePacketSize = pktRate.AveragePacketSize
			aggregated.PacketRate.MicroburstDetected = pktRate.MicroburstDetected
		}
	}

	// Collect from error counter.
	if ma.errorCounter != nil {
		if errRates, err := ma.errorCounter.GetCurrentRates(interfaceName); err == nil {
			aggregated.ErrorRates.TotalErrorsPerSec = errRates.TotalErrorsPerSec
			aggregated.ErrorRates.DroppedPerSec = errRates.RxDroppedPerSec + errRates.TxDroppedPerSec
		}
	}

	// Calculate composite score.
	score := ma.CalculateCompositeScore(aggregated)
	aggregated.CompositeScore = score.Overall
	aggregated.ScoreComponents = &ScoreBreakdown{
		ThroughputScore:  score.ThroughputScore,
		LatencyScore:     score.LatencyScore,
		ErrorRateScore:   score.ErrorRateScore,
		PacketRateScore:  score.PacketRateScore,
		UtilizationScore: score.UtilizationScore,
		JitterScore:      score.JitterScore,
		Weights:          ma.config.Weights,
	}

	// Store and update.
	ma.mu.Lock()
	existing := ma.interfaces[interfaceName]
	if existing != nil {
		aggregated.History = existing.History
	} else {
		aggregated.History = make([]*PerformanceSnapshot, 0, 720) // 24h at 10s intervals max.
	}

	// Add snapshot to history.
	aggregated.History = append(aggregated.History, &PerformanceSnapshot{
		Timestamp:          now,
		CompositeScore:     aggregated.CompositeScore,
		ThroughputMbps:     aggregated.Throughput.TotalMbps,
		LatencyMs:          aggregated.Latency.CurrentMs,
		ErrorsPerSec:       aggregated.ErrorRates.TotalErrorsPerSec,
		PacketsPerSec:      float64(aggregated.PacketRate.TotalPacketsPerSec),
		UtilizationPercent: aggregated.Utilization.TotalUtilization,
	})

	// Calculate trend.
	aggregated.Trend = ma.calculateTrend(aggregated)

	// Calculate statistics.
	aggregated.Statistics = ma.calculateStatistics(aggregated)

	ma.interfaces[interfaceName] = aggregated
	ma.mu.Unlock()

	return aggregated, nil
}

// =============================================================================
// Score Calculation
// =============================================================================

// CalculateCompositeScore computes weighted performance score.
func (ma *MetricsAggregator) CalculateCompositeScore(metrics *AggregatedMetrics) *PerformanceScore {
	weights := ma.config.Weights

	// Normalize and score each dimension.
	throughputScore := ma.scoreThroughput(metrics)
	latencyScore := ma.scoreLatency(metrics)
	errorRateScore := ma.scoreErrorRate(metrics)
	packetRateScore := ma.scorePacketRate(metrics)
	utilizationScore := ma.scoreUtilization(metrics)
	jitterScore := ma.scoreJitter(metrics)

	// Calculate weighted overall score.
	overall := throughputScore*weights.Throughput +
		latencyScore*weights.Latency +
		errorRateScore*weights.ErrorRate +
		packetRateScore*weights.PacketRate +
		utilizationScore*weights.Utilization +
		jitterScore*weights.Jitter

	return &PerformanceScore{
		Overall:          overall,
		ThroughputScore:  throughputScore,
		LatencyScore:     latencyScore,
		ErrorRateScore:   errorRateScore,
		PacketRateScore:  packetRateScore,
		UtilizationScore: utilizationScore,
		JitterScore:      jitterScore,
		Weights:          weights,
	}
}

// scoreThroughput scores throughput (higher is better).
func (ma *MetricsAggregator) scoreThroughput(metrics *AggregatedMetrics) float64 {
	// Normalize by link speed.
	linkSpeedMbps := float64(metrics.LinkSpeed) / 1_000_000
	if linkSpeedMbps <= 0 {
		linkSpeedMbps = 1000 // Default 1 Gbps.
	}

	// Score based on actual throughput vs capacity.
	// Higher throughput = higher score (up to capacity).
	ratio := metrics.Throughput.TotalMbps / linkSpeedMbps
	score := NormalizeMetric(ratio, 0, 1) // 0-100 based on 0-100% of capacity.

	return math.Min(score, 100)
}

// scoreLatency scores latency (lower is better).
func (ma *MetricsAggregator) scoreLatency(metrics *AggregatedMetrics) float64 {
	// Latency bounds: 0ms = 100, 500ms+ = 0.
	latency := metrics.Latency.CurrentMs
	score := NormalizeMetric(latency, 0, 500)
	return InvertScore(score) // Invert: lower latency = higher score.
}

// scoreErrorRate scores error rate (lower is better).
func (ma *MetricsAggregator) scoreErrorRate(metrics *AggregatedMetrics) float64 {
	// Error rate bounds: 0 errors/sec = 100, 100 errors/sec+ = 0.
	errorRate := metrics.ErrorRates.TotalErrorsPerSec
	score := NormalizeMetric(errorRate, 0, 100)
	return InvertScore(score) // Invert: lower errors = higher score.
}

// scorePacketRate scores packet rate (higher is better).
func (ma *MetricsAggregator) scorePacketRate(metrics *AggregatedMetrics) float64 {
	// Calculate theoretical max PPS based on link speed.
	// Minimum frame: 84 bytes (64 + 20 overhead).
	linkSpeedBits := float64(metrics.LinkSpeed)
	if linkSpeedBits <= 0 {
		linkSpeedBits = 1_000_000_000 // Default 1 Gbps.
	}
	maxPPS := linkSpeedBits / (84 * 8)

	// Score based on actual vs theoretical max.
	pps := float64(metrics.PacketRate.TotalPacketsPerSec)
	ratio := pps / maxPPS
	score := NormalizeMetric(ratio, 0, 1)

	return math.Min(score, 100)
}

// scoreUtilization scores utilization (moderate is best).
func (ma *MetricsAggregator) scoreUtilization(metrics *AggregatedMetrics) float64 {
	return ScoreUtilization(metrics.Utilization.TotalUtilization)
}

// scoreJitter scores jitter (lower is better).
func (ma *MetricsAggregator) scoreJitter(metrics *AggregatedMetrics) float64 {
	// Jitter bounds: 0ms = 100, 50ms+ = 0.
	jitter := metrics.Jitter.CurrentMs
	score := NormalizeMetric(jitter, 0, 50)
	return InvertScore(score) // Invert: lower jitter = higher score.
}

// =============================================================================
// Score Helper Functions
// =============================================================================

// NormalizeMetric scales value to 0-100 range.
func NormalizeMetric(value, min, max float64) float64 {
	if max <= min {
		return 0
	}
	if value <= min {
		return 0
	}
	if value >= max {
		return 100
	}
	return ((value - min) / (max - min)) * 100
}

// InvertScore inverts a score (for "lower is better" metrics).
func InvertScore(score float64) float64 {
	return 100 - score
}

// ScoreUtilization applies U-shaped scoring (moderate is best).
func ScoreUtilization(utilization float64) float64 {
	// Optimal utilization around 50%.
	// 0% = 60, 50% = 100, 100% = 40.
	if utilization <= 0 {
		return 60
	}
	if utilization >= 100 {
		return 40
	}

	// Parabolic scoring centered at 50%.
	optimal := 50.0
	distance := math.Abs(utilization - optimal)
	score := 100 - (distance * 0.8) // Max penalty of 40 points at extremes.

	return math.Max(score, 0)
}

// =============================================================================
// Trend Analysis
// =============================================================================

// calculateTrend determines if performance is improving/degrading/stable.
func (ma *MetricsAggregator) calculateTrend(metrics *AggregatedMetrics) string {
	if len(metrics.History) < ma.config.TrendSampleCount {
		return TrendStable
	}

	// Get last N samples.
	samples := metrics.History[len(metrics.History)-ma.config.TrendSampleCount:]

	// Linear regression on composite scores.
	n := float64(len(samples))
	var sumX, sumY, sumXY, sumX2 float64

	baseTime := samples[0].Timestamp.Unix()
	for _, sample := range samples {
		x := float64(sample.Timestamp.Unix()-baseTime) / 60 // Minutes.
		y := sample.CompositeScore

		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	denominator := n*sumX2 - sumX*sumX
	if denominator == 0 {
		return TrendStable
	}

	slope := (n*sumXY - sumX*sumY) / denominator

	// Classify trend based on slope (points per minute).
	if slope > ma.config.TrendSlopeThreshold {
		return TrendImproving
	} else if slope < -ma.config.TrendSlopeThreshold {
		return TrendDegrading
	}
	return TrendStable
}

// =============================================================================
// Statistics Calculation
// =============================================================================

// calculateStatistics computes statistical summary.
func (ma *MetricsAggregator) calculateStatistics(metrics *AggregatedMetrics) *MetricStatistics {
	// Filter to aggregation window.
	cutoff := time.Now().Add(-ma.config.AggregationWindow)
	var scores []float64

	for _, snapshot := range metrics.History {
		if snapshot.Timestamp.After(cutoff) {
			scores = append(scores, snapshot.CompositeScore)
		}
	}

	if len(scores) == 0 {
		return &MetricStatistics{}
	}

	// Calculate statistics.
	stats := &MetricStatistics{
		SampleCount: len(scores),
	}

	// Min, Max, Sum.
	stats.Min = scores[0]
	stats.Max = scores[0]
	sum := 0.0

	for _, s := range scores {
		if s < stats.Min {
			stats.Min = s
		}
		if s > stats.Max {
			stats.Max = s
		}
		sum += s
	}

	stats.Average = sum / float64(len(scores))

	// Standard deviation.
	var variance float64
	for _, s := range scores {
		diff := s - stats.Average
		variance += diff * diff
	}
	stats.StdDev = math.Sqrt(variance / float64(len(scores)))

	// Percentiles (sort for percentile calculation).
	sorted := make([]float64, len(scores))
	copy(sorted, scores)
	sort.Float64s(sorted)

	stats.Percentile50 = percentile(sorted, 0.50)
	stats.Percentile95 = percentile(sorted, 0.95)
	stats.Percentile99 = percentile(sorted, 0.99)

	return stats
}

// percentile calculates percentile from sorted slice.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}

	index := p * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	// Linear interpolation.
	frac := index - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// =============================================================================
// Query Methods
// =============================================================================

// GetAggregatedSnapshot returns metrics for an interface.
func (ma *MetricsAggregator) GetAggregatedSnapshot(interfaceName string) (*AggregatedMetrics, error) {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	metrics, exists := ma.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrAggregatorInterfaceNotFound, interfaceName)
	}

	// Return copy (shallow - history is shared).
	copy := *metrics
	return &copy, nil
}

// GetAllSnapshots returns all aggregated metrics.
func (ma *MetricsAggregator) GetAllSnapshots() map[string]*AggregatedMetrics {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	result := make(map[string]*AggregatedMetrics, len(ma.interfaces))
	for name, metrics := range ma.interfaces {
		copy := *metrics
		result[name] = &copy
	}
	return result
}

// =============================================================================
// Ranking Methods
// =============================================================================

// GetInterfaceRankings returns interfaces sorted by score.
func (ma *MetricsAggregator) GetInterfaceRankings() []*InterfaceRanking {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	rankings := make([]*InterfaceRanking, 0, len(ma.interfaces))
	for name, metrics := range ma.interfaces {
		rankings = append(rankings, &InterfaceRanking{
			InterfaceName:  name,
			CompositeScore: metrics.CompositeScore,
			Trend:          metrics.Trend,
		})
	}

	// Sort by score descending (best first).
	sort.Slice(rankings, func(i, j int) bool {
		return rankings[i].CompositeScore > rankings[j].CompositeScore
	})

	// Assign ranks.
	for i := range rankings {
		rankings[i].Rank = i + 1
	}

	return rankings
}

// GetBestPerformer returns the best performing interface.
func (ma *MetricsAggregator) GetBestPerformer() (string, float64) {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	var bestName string
	bestScore := -1.0

	for name, metrics := range ma.interfaces {
		if metrics.CompositeScore > bestScore {
			bestScore = metrics.CompositeScore
			bestName = name
		}
	}

	return bestName, bestScore
}

// GetWorstPerformer returns the worst performing interface.
func (ma *MetricsAggregator) GetWorstPerformer() (string, float64) {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	var worstName string
	worstScore := 101.0

	for name, metrics := range ma.interfaces {
		if metrics.CompositeScore < worstScore {
			worstScore = metrics.CompositeScore
			worstName = name
		}
	}

	return worstName, worstScore
}

// CompareInterfaces compares two interfaces.
func (ma *MetricsAggregator) CompareInterfaces(if1, if2 string) (*ComparisonResult, error) {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	m1, exists1 := ma.interfaces[if1]
	m2, exists2 := ma.interfaces[if2]

	if !exists1 {
		return nil, fmt.Errorf("%w: %s", ErrAggregatorInterfaceNotFound, if1)
	}
	if !exists2 {
		return nil, fmt.Errorf("%w: %s", ErrAggregatorInterfaceNotFound, if2)
	}

	result := &ComparisonResult{
		Interface1:     if1,
		Interface2:     if2,
		ScoreDiff:      m1.CompositeScore - m2.CompositeScore,
		DimensionDiffs: make(map[string]float64),
	}

	if m1.CompositeScore >= m2.CompositeScore {
		result.Winner = if1
	} else {
		result.Winner = if2
	}

	// Dimension differences.
	if m1.ScoreComponents != nil && m2.ScoreComponents != nil {
		result.DimensionDiffs[DimensionThroughput] = m1.ScoreComponents.ThroughputScore - m2.ScoreComponents.ThroughputScore
		result.DimensionDiffs[DimensionLatency] = m1.ScoreComponents.LatencyScore - m2.ScoreComponents.LatencyScore
		result.DimensionDiffs[DimensionErrorRate] = m1.ScoreComponents.ErrorRateScore - m2.ScoreComponents.ErrorRateScore
		result.DimensionDiffs[DimensionPacketRate] = m1.ScoreComponents.PacketRateScore - m2.ScoreComponents.PacketRateScore
		result.DimensionDiffs[DimensionUtilization] = m1.ScoreComponents.UtilizationScore - m2.ScoreComponents.UtilizationScore
		result.DimensionDiffs[DimensionJitter] = m1.ScoreComponents.JitterScore - m2.ScoreComponents.JitterScore
	}

	return result, nil
}

// =============================================================================
// Historical Methods
// =============================================================================

// GetHistoricalTrend returns historical data for an interface.
func (ma *MetricsAggregator) GetHistoricalTrend(interfaceName string, duration time.Duration) ([]*PerformanceSnapshot, error) {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	metrics, exists := ma.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrAggregatorInterfaceNotFound, interfaceName)
	}

	cutoff := time.Now().Add(-duration)
	var result []*PerformanceSnapshot

	for _, snapshot := range metrics.History {
		if snapshot.Timestamp.After(cutoff) {
			result = append(result, snapshot)
		}
	}

	return result, nil
}

// =============================================================================
// Maintenance Methods
// =============================================================================

// pruneHistory removes old history entries.
func (ma *MetricsAggregator) pruneHistory() {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	cutoff := time.Now().Add(-ma.config.HistoryRetention)

	for _, metrics := range ma.interfaces {
		var pruned []*PerformanceSnapshot
		for _, snapshot := range metrics.History {
			if snapshot.Timestamp.After(cutoff) {
				pruned = append(pruned, snapshot)
			}
		}
		metrics.History = pruned
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the aggregator is operational.
func (ma *MetricsAggregator) HealthCheck() error {
	ma.runningMu.Lock()
	running := ma.running
	ma.runningMu.Unlock()

	if !running {
		return errors.New("metrics aggregator not running")
	}

	// Check last aggregation was recent.
	if time.Since(ma.lastCollection) > ma.config.CollectionInterval*2 {
		return errors.New("metrics aggregation stalled")
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetAggregatorStatistics returns aggregator operation statistics.
func (ma *MetricsAggregator) GetAggregatorStatistics() map[string]uint64 {
	return map[string]uint64{
		"aggregations_total": atomic.LoadUint64(&ma.aggregationsTotal),
	}
}

// GetConfig returns the current configuration.
func (ma *MetricsAggregator) GetConfig() *AggregatorConfig {
	return ma.config
}

// GetLastAggregationTime returns timestamp of last aggregation.
func (ma *MetricsAggregator) GetLastAggregationTime() time.Time {
	return ma.lastCollection
}

// GetInterfaceCount returns the number of tracked interfaces.
func (ma *MetricsAggregator) GetInterfaceCount() int {
	ma.mu.RLock()
	defer ma.mu.RUnlock()
	return len(ma.interfaces)
}

// GetWeights returns the current metric weights.
func (ma *MetricsAggregator) GetWeights() *MetricWeights {
	return ma.config.Weights
}
