// Package performance provides network interface performance monitoring
// for the NIC Management service.
package performance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Throughput Error Types
// =============================================================================

var (
	// ErrThroughputInterfaceNotFound indicates interface not found.
	ErrThroughputInterfaceNotFound = errors.New("interface not found for throughput")
	// ErrNoThroughputData indicates no throughput data calculated yet.
	ErrNoThroughputData = errors.New("no throughput data available")
	// ErrInsufficientHistory indicates not enough samples for analysis.
	ErrInsufficientHistory = errors.New("insufficient history for analysis")
	// ErrInvalidDuration indicates invalid time window.
	ErrInvalidDuration = errors.New("invalid duration")
)

// =============================================================================
// Throughput Trend Enumeration
// =============================================================================

// ThroughputTrend represents throughput trend direction.
type ThroughputTrend int

const (
	// ThroughputTrendUnknown indicates insufficient data for trend.
	ThroughputTrendUnknown ThroughputTrend = iota
	// ThroughputTrendIncreasing indicates throughput trending upward.
	ThroughputTrendIncreasing
	// ThroughputTrendStable indicates throughput relatively constant.
	ThroughputTrendStable
	// ThroughputTrendDecreasing indicates throughput trending downward.
	ThroughputTrendDecreasing
)

// String returns the string representation of the trend.
func (t ThroughputTrend) String() string {
	switch t {
	case ThroughputTrendIncreasing:
		return "INCREASING"
	case ThroughputTrendStable:
		return "STABLE"
	case ThroughputTrendDecreasing:
		return "DECREASING"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Interface Throughput Structure
// =============================================================================

// InterfaceThroughput contains current throughput metrics for an interface.
type InterfaceThroughput struct {
	// InterfaceName is the interface name.
	InterfaceName string `json:"interface_name"`
	// Timestamp is when throughput was calculated.
	Timestamp time.Time `json:"timestamp"`

	// Instantaneous throughput.
	RxBytesPerSec uint64  `json:"rx_bytes_per_sec"`
	TxBytesPerSec uint64  `json:"tx_bytes_per_sec"`
	RxBitsPerSec  uint64  `json:"rx_bits_per_sec"`
	TxBitsPerSec  uint64  `json:"tx_bits_per_sec"`
	RxMbps        float64 `json:"rx_mbps"`
	TxMbps        float64 `json:"tx_mbps"`
	TotalMbps     float64 `json:"total_mbps"`

	// Averaged throughput.
	AverageRxBytesPerSec uint64 `json:"average_rx_bytes_per_sec"`
	AverageTxBytesPerSec uint64 `json:"average_tx_bytes_per_sec"`

	// Peak throughput.
	PeakRxBytesPerSec uint64    `json:"peak_rx_bytes_per_sec"`
	PeakTxBytesPerSec uint64    `json:"peak_tx_bytes_per_sec"`
	PeakTimestamp     time.Time `json:"peak_timestamp,omitempty"`

	// Bandwidth utilization.
	MaxBandwidth     uint64  `json:"max_bandwidth"`
	RxUtilization    float64 `json:"rx_utilization"`
	TxUtilization    float64 `json:"tx_utilization"`
	TotalUtilization float64 `json:"total_utilization"`

	// Trend and burst detection.
	Trend         ThroughputTrend `json:"trend"`
	BurstDetected bool            `json:"burst_detected"`
}

// =============================================================================
// Throughput Sample Structure
// =============================================================================

// ThroughputSample is a single throughput measurement.
type ThroughputSample struct {
	// Timestamp is when sample was taken.
	Timestamp time.Time `json:"timestamp"`
	// RxBytesPerSec is receive throughput.
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	// TxBytesPerSec is transmit throughput.
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	// RxUtilization is receive utilization.
	RxUtilization float64 `json:"rx_utilization"`
	// TxUtilization is transmit utilization.
	TxUtilization float64 `json:"tx_utilization"`
}

// =============================================================================
// Throughput History Structure
// =============================================================================

// ThroughputHistory maintains historical throughput samples.
type ThroughputHistory struct {
	// InterfaceName is the interface with this history.
	InterfaceName string
	// Samples is the circular buffer of samples.
	Samples []*ThroughputSample
	// MaxSamples is the maximum samples to retain.
	MaxSamples int
	// CurrentIndex is the next write position.
	CurrentIndex int
	// Count is the number of samples stored.
	Count int
}

// NewThroughputHistory creates a new throughput history buffer.
func NewThroughputHistory(interfaceName string, maxSamples int) *ThroughputHistory {
	return &ThroughputHistory{
		InterfaceName: interfaceName,
		Samples:       make([]*ThroughputSample, maxSamples),
		MaxSamples:    maxSamples,
		CurrentIndex:  0,
		Count:         0,
	}
}

// Add adds a sample to the history.
func (h *ThroughputHistory) Add(sample *ThroughputSample) {
	h.Samples[h.CurrentIndex] = sample
	h.CurrentIndex = (h.CurrentIndex + 1) % h.MaxSamples
	if h.Count < h.MaxSamples {
		h.Count++
	}
}

// GetRecent returns the most recent N samples.
func (h *ThroughputHistory) GetRecent(count int) []*ThroughputSample {
	if count > h.Count {
		count = h.Count
	}
	if count == 0 {
		return nil
	}

	result := make([]*ThroughputSample, count)
	idx := (h.CurrentIndex - count + h.MaxSamples) % h.MaxSamples

	for i := 0; i < count; i++ {
		result[i] = h.Samples[idx]
		idx = (idx + 1) % h.MaxSamples
	}

	return result
}

// GetSamplesInDuration returns samples within the specified duration.
func (h *ThroughputHistory) GetSamplesInDuration(duration time.Duration) []*ThroughputSample {
	if h.Count == 0 {
		return nil
	}

	cutoff := time.Now().Add(-duration)
	var result []*ThroughputSample

	samples := h.GetRecent(h.Count)
	for _, sample := range samples {
		if sample != nil && sample.Timestamp.After(cutoff) {
			result = append(result, sample)
		}
	}

	return result
}

// =============================================================================
// Throughput Configuration
// =============================================================================

// ThroughputConfig contains configuration for throughput calculation.
type ThroughputConfig struct {
	// CalculationInterval is how often to calculate throughput (default: 5s).
	CalculationInterval time.Duration `json:"calculation_interval"`
	// MeasurementWindow is time window for averaging (default: 60s).
	MeasurementWindow time.Duration `json:"measurement_window"`
	// EnableTrendAnalysis calculates trends (default: true).
	EnableTrendAnalysis bool `json:"enable_trend_analysis"`
	// TrendWindow is time window for trend calculation (default: 300s).
	TrendWindow time.Duration `json:"trend_window"`
	// EnablePeakTracking tracks peak values (default: true).
	EnablePeakTracking bool `json:"enable_peak_tracking"`
	// PeakResetInterval resets peaks after duration (default: 24h).
	PeakResetInterval time.Duration `json:"peak_reset_interval"`
	// EnableUtilizationCalculation calculates bandwidth utilization (default: true).
	EnableUtilizationCalculation bool `json:"enable_utilization_calculation"`
	// UtilizationThreshold is saturation threshold percentage (default: 80.0).
	UtilizationThreshold float64 `json:"utilization_threshold"`
	// MaxHistorySamples is samples to retain (default: 720).
	MaxHistorySamples int `json:"max_history_samples"`
	// EnableBurstDetection detects traffic bursts (default: true).
	EnableBurstDetection bool `json:"enable_burst_detection"`
	// BurstThreshold is multiplier for burst detection (default: 2.0).
	BurstThreshold float64 `json:"burst_threshold"`
}

// DefaultThroughputConfig returns the default throughput calculator configuration.
func DefaultThroughputConfig() *ThroughputConfig {
	return &ThroughputConfig{
		CalculationInterval:          5 * time.Second,
		MeasurementWindow:            60 * time.Second,
		EnableTrendAnalysis:          true,
		TrendWindow:                  300 * time.Second,
		EnablePeakTracking:           true,
		PeakResetInterval:            24 * time.Hour,
		EnableUtilizationCalculation: true,
		UtilizationThreshold:         80.0,
		MaxHistorySamples:            720,
		EnableBurstDetection:         true,
		BurstThreshold:               2.0,
	}
}

// =============================================================================
// Enumerator Interface for Throughput
// =============================================================================

// ThroughputEnumeratorInterface defines interface discovery operations.
type ThroughputEnumeratorInterface interface {
	// GetAllInterfaceNames returns all interface names.
	GetAllInterfaceNames() []string
	// GetInterfaceBandwidth returns interface maximum bandwidth in bits/sec.
	GetInterfaceBandwidth(interfaceName string) uint64
}

// No-op enumerator implementation.
type noOpThroughputEnumerator struct{}

func (n *noOpThroughputEnumerator) GetAllInterfaceNames() []string {
	return []string{}
}

func (n *noOpThroughputEnumerator) GetInterfaceBandwidth(interfaceName string) uint64 {
	// Default to 1 Gbps if unknown.
	return 1_000_000_000
}

// =============================================================================
// Throughput Calculator
// =============================================================================

// ThroughputCalculator calculates throughput metrics.
type ThroughputCalculator struct {
	// Dependencies.
	statsCollector *StatisticsCollector
	enumerator     ThroughputEnumeratorInterface

	// Configuration.
	config *ThroughputConfig

	// State.
	interfaceThroughput map[string]*InterfaceThroughput
	throughputHistory   map[string]*ThroughputHistory
	peakResetTime       map[string]time.Time
	mu                  sync.RWMutex

	// Calculation control.
	calculationTicker *time.Ticker
	lastCalculation   time.Time

	// Statistics.
	calculationsTotal uint64
	burstsDetected    uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewThroughputCalculator creates a new throughput calculator.
func NewThroughputCalculator(
	statsCollector *StatisticsCollector,
	enumerator ThroughputEnumeratorInterface,
	config *ThroughputConfig,
) *ThroughputCalculator {
	if config == nil {
		config = DefaultThroughputConfig()
	}

	if enumerator == nil {
		enumerator = &noOpThroughputEnumerator{}
	}

	return &ThroughputCalculator{
		statsCollector:      statsCollector,
		enumerator:          enumerator,
		config:              config,
		interfaceThroughput: make(map[string]*InterfaceThroughput),
		throughputHistory:   make(map[string]*ThroughputHistory),
		peakResetTime:       make(map[string]time.Time),
		stopChan:            make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the throughput calculator.
func (tc *ThroughputCalculator) Start(ctx context.Context) error {
	tc.runningMu.Lock()
	defer tc.runningMu.Unlock()

	if tc.running {
		return nil
	}

	// Perform initial calculation.
	_ = tc.calculateAllThroughput()

	// Start calculation ticker.
	tc.calculationTicker = time.NewTicker(tc.config.CalculationInterval)
	go tc.calculationLoop()

	tc.running = true
	return nil
}

// Stop shuts down the throughput calculator.
func (tc *ThroughputCalculator) Stop() error {
	tc.runningMu.Lock()
	if !tc.running {
		tc.runningMu.Unlock()
		return nil
	}
	tc.running = false
	tc.runningMu.Unlock()

	if tc.calculationTicker != nil {
		tc.calculationTicker.Stop()
	}
	close(tc.stopChan)

	return nil
}

// calculationLoop is the background calculation goroutine.
func (tc *ThroughputCalculator) calculationLoop() {
	for {
		select {
		case <-tc.stopChan:
			return
		case <-tc.calculationTicker.C:
			_ = tc.calculateAllThroughput()
		}
	}
}

// =============================================================================
// Throughput Calculation
// =============================================================================

// calculateAllThroughput calculates throughput for all interfaces.
func (tc *ThroughputCalculator) calculateAllThroughput() error {
	interfaces := tc.enumerator.GetAllInterfaceNames()

	// Also get interfaces from stats collector.
	if tc.statsCollector != nil {
		allStats := tc.statsCollector.GetAllStatistics()
		for name := range allStats {
			found := false
			for _, ifaceName := range interfaces {
				if ifaceName == name {
					found = true
					break
				}
			}
			if !found {
				interfaces = append(interfaces, name)
			}
		}
	}

	var lastErr error
	for _, ifaceName := range interfaces {
		throughput, err := tc.calculateInterfaceThroughput(ifaceName)
		if err != nil {
			lastErr = err
			continue
		}

		tc.mu.Lock()
		tc.interfaceThroughput[ifaceName] = throughput

		// Add to history.
		if tc.throughputHistory[ifaceName] == nil {
			tc.throughputHistory[ifaceName] = NewThroughputHistory(ifaceName, tc.config.MaxHistorySamples)
		}
		tc.throughputHistory[ifaceName].Add(&ThroughputSample{
			Timestamp:     throughput.Timestamp,
			RxBytesPerSec: throughput.RxBytesPerSec,
			TxBytesPerSec: throughput.TxBytesPerSec,
			RxUtilization: throughput.RxUtilization,
			TxUtilization: throughput.TxUtilization,
		})
		tc.mu.Unlock()
	}

	atomic.AddUint64(&tc.calculationsTotal, 1)
	tc.lastCalculation = time.Now()

	return lastErr
}

// calculateInterfaceThroughput calculates throughput for a single interface.
func (tc *ThroughputCalculator) calculateInterfaceThroughput(interfaceName string) (*InterfaceThroughput, error) {
	// Get current statistics.
	var stats *InterfaceStatistics
	if tc.statsCollector != nil {
		var err error
		stats, err = tc.statsCollector.GetInterfaceStatistics(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
		}
	} else {
		// No stats collector - create empty stats.
		stats = &InterfaceStatistics{
			InterfaceName: interfaceName,
			Timestamp:     time.Now(),
		}
	}

	throughput := &InterfaceThroughput{
		InterfaceName: interfaceName,
		Timestamp:     time.Now(),
	}

	// Step 1: Get instantaneous throughput from stats.
	throughput.RxBytesPerSec = stats.RxBytesPerSec
	throughput.TxBytesPerSec = stats.TxBytesPerSec

	// Step 2: Convert to bits per second.
	throughput.RxBitsPerSec = throughput.RxBytesPerSec * 8
	throughput.TxBitsPerSec = throughput.TxBytesPerSec * 8

	// Step 3: Convert to Mbps.
	throughput.RxMbps = float64(throughput.RxBitsPerSec) / 1_000_000
	throughput.TxMbps = float64(throughput.TxBitsPerSec) / 1_000_000
	throughput.TotalMbps = throughput.RxMbps + throughput.TxMbps

	// Step 4: Calculate average throughput.
	tc.calculateAverageThroughput(throughput)

	// Step 5: Update peak throughput.
	if tc.config.EnablePeakTracking {
		tc.updatePeakThroughput(throughput)
	}

	// Step 6: Calculate bandwidth utilization.
	if tc.config.EnableUtilizationCalculation {
		tc.calculateUtilization(throughput)
	}

	// Step 7: Detect throughput trend.
	if tc.config.EnableTrendAnalysis {
		throughput.Trend = tc.calculateTrend(interfaceName)
	}

	// Step 8: Detect traffic bursts.
	if tc.config.EnableBurstDetection {
		throughput.BurstDetected = tc.detectBurst(interfaceName, throughput)
	}

	return throughput, nil
}

// calculateAverageThroughput calculates average throughput over measurement window.
func (tc *ThroughputCalculator) calculateAverageThroughput(throughput *InterfaceThroughput) {
	tc.mu.RLock()
	history := tc.throughputHistory[throughput.InterfaceName]
	tc.mu.RUnlock()

	if history == nil || history.Count == 0 {
		throughput.AverageRxBytesPerSec = throughput.RxBytesPerSec
		throughput.AverageTxBytesPerSec = throughput.TxBytesPerSec
		return
	}

	samples := history.GetSamplesInDuration(tc.config.MeasurementWindow)
	if len(samples) == 0 {
		throughput.AverageRxBytesPerSec = throughput.RxBytesPerSec
		throughput.AverageTxBytesPerSec = throughput.TxBytesPerSec
		return
	}

	var totalRx, totalTx uint64
	for _, sample := range samples {
		totalRx += sample.RxBytesPerSec
		totalTx += sample.TxBytesPerSec
	}

	throughput.AverageRxBytesPerSec = totalRx / uint64(len(samples))
	throughput.AverageTxBytesPerSec = totalTx / uint64(len(samples))
}

// updatePeakThroughput updates peak throughput tracking.
func (tc *ThroughputCalculator) updatePeakThroughput(throughput *InterfaceThroughput) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Check if peak reset is needed.
	resetTime, exists := tc.peakResetTime[throughput.InterfaceName]
	if !exists || time.Since(resetTime) > tc.config.PeakResetInterval {
		tc.peakResetTime[throughput.InterfaceName] = time.Now()
		// Reset peaks - will be set below.
	}

	// Get existing throughput for peak comparison.
	existing := tc.interfaceThroughput[throughput.InterfaceName]
	if existing != nil {
		throughput.PeakRxBytesPerSec = existing.PeakRxBytesPerSec
		throughput.PeakTxBytesPerSec = existing.PeakTxBytesPerSec
		throughput.PeakTimestamp = existing.PeakTimestamp
	}

	// Update if current exceeds peak.
	if throughput.RxBytesPerSec > throughput.PeakRxBytesPerSec {
		throughput.PeakRxBytesPerSec = throughput.RxBytesPerSec
		throughput.PeakTimestamp = time.Now()
	}
	if throughput.TxBytesPerSec > throughput.PeakTxBytesPerSec {
		throughput.PeakTxBytesPerSec = throughput.TxBytesPerSec
		throughput.PeakTimestamp = time.Now()
	}
}

// calculateUtilization calculates bandwidth utilization percentages.
func (tc *ThroughputCalculator) calculateUtilization(throughput *InterfaceThroughput) {
	// Get interface maximum bandwidth.
	throughput.MaxBandwidth = tc.enumerator.GetInterfaceBandwidth(throughput.InterfaceName)

	if throughput.MaxBandwidth == 0 {
		return
	}

	// Calculate utilization percentages.
	throughput.RxUtilization = (float64(throughput.RxBitsPerSec) / float64(throughput.MaxBandwidth)) * 100
	throughput.TxUtilization = (float64(throughput.TxBitsPerSec) / float64(throughput.MaxBandwidth)) * 100

	// Total utilization is max of Rx and Tx.
	throughput.TotalUtilization = math.Max(throughput.RxUtilization, throughput.TxUtilization)
}

// =============================================================================
// Trend Analysis
// =============================================================================

// calculateTrend analyzes throughput trend using linear regression.
func (tc *ThroughputCalculator) calculateTrend(interfaceName string) ThroughputTrend {
	tc.mu.RLock()
	history := tc.throughputHistory[interfaceName]
	tc.mu.RUnlock()

	if history == nil {
		return ThroughputTrendUnknown
	}

	samples := history.GetSamplesInDuration(tc.config.TrendWindow)
	if len(samples) < 10 {
		return ThroughputTrendUnknown
	}

	// Linear regression calculation.
	n := float64(len(samples))
	var sumX, sumY, sumXY, sumX2 float64

	baseTime := samples[0].Timestamp.Unix()
	for i, sample := range samples {
		x := float64(sample.Timestamp.Unix() - baseTime)
		y := float64(sample.RxBytesPerSec + sample.TxBytesPerSec)

		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x

		_ = i // Suppress unused variable warning.
	}

	// Calculate slope.
	denominator := n*sumX2 - sumX*sumX
	if denominator == 0 {
		return ThroughputTrendStable
	}

	slope := (n*sumXY - sumX*sumY) / denominator

	// Determine trend based on slope (bytes/sec per second).
	const slopeThreshold = 1000.0 // 1 KB/s per second change

	if slope > slopeThreshold {
		return ThroughputTrendIncreasing
	} else if slope < -slopeThreshold {
		return ThroughputTrendDecreasing
	}
	return ThroughputTrendStable
}

// =============================================================================
// Burst Detection
// =============================================================================

// detectBurst identifies sudden throughput spikes.
func (tc *ThroughputCalculator) detectBurst(interfaceName string, current *InterfaceThroughput) bool {
	averageTotal := current.AverageRxBytesPerSec + current.AverageTxBytesPerSec
	if averageTotal == 0 {
		return false
	}

	currentTotal := current.RxBytesPerSec + current.TxBytesPerSec
	ratio := float64(currentTotal) / float64(averageTotal)

	if ratio >= tc.config.BurstThreshold {
		atomic.AddUint64(&tc.burstsDetected, 1)
		return true
	}

	return false
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfaceThroughput retrieves current throughput for specific interface.
func (tc *ThroughputCalculator) GetInterfaceThroughput(interfaceName string) (*InterfaceThroughput, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	throughput, exists := tc.interfaceThroughput[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	// Return copy.
	copy := *throughput
	return &copy, nil
}

// GetAllThroughput retrieves throughput for all interfaces.
func (tc *ThroughputCalculator) GetAllThroughput() map[string]*InterfaceThroughput {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	result := make(map[string]*InterfaceThroughput, len(tc.interfaceThroughput))
	for name, throughput := range tc.interfaceThroughput {
		copy := *throughput
		result[name] = &copy
	}
	return result
}

// GetThroughputHistory retrieves historical samples for interface.
func (tc *ThroughputCalculator) GetThroughputHistory(interfaceName string, duration time.Duration) ([]*ThroughputSample, error) {
	if duration <= 0 {
		return nil, ErrInvalidDuration
	}

	tc.mu.RLock()
	defer tc.mu.RUnlock()

	history, exists := tc.throughputHistory[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	return history.GetSamplesInDuration(duration), nil
}

// GetPeakThroughput retrieves peak throughput values.
func (tc *ThroughputCalculator) GetPeakThroughput(interfaceName string) (rxPeak, txPeak uint64, timestamp time.Time, err error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	throughput, exists := tc.interfaceThroughput[interfaceName]
	if !exists {
		return 0, 0, time.Time{}, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	return throughput.PeakRxBytesPerSec, throughput.PeakTxBytesPerSec, throughput.PeakTimestamp, nil
}

// ResetPeakThroughput resets peak throughput tracking.
func (tc *ThroughputCalculator) ResetPeakThroughput(interfaceName string) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	throughput, exists := tc.interfaceThroughput[interfaceName]
	if !exists {
		return fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	throughput.PeakRxBytesPerSec = 0
	throughput.PeakTxBytesPerSec = 0
	throughput.PeakTimestamp = time.Time{}
	tc.peakResetTime[interfaceName] = time.Now()

	return nil
}

// =============================================================================
// Utilization Methods
// =============================================================================

// GetBandwidthUtilization retrieves current bandwidth utilization.
func (tc *ThroughputCalculator) GetBandwidthUtilization(interfaceName string) (rxUtil, txUtil, totalUtil float64, err error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	throughput, exists := tc.interfaceThroughput[interfaceName]
	if !exists {
		return 0, 0, 0, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	return throughput.RxUtilization, throughput.TxUtilization, throughput.TotalUtilization, nil
}

// IsSaturated checks if interface bandwidth is saturated.
func (tc *ThroughputCalculator) IsSaturated(interfaceName string) (bool, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	throughput, exists := tc.interfaceThroughput[interfaceName]
	if !exists {
		return false, fmt.Errorf("%w: %s", ErrThroughputInterfaceNotFound, interfaceName)
	}

	return throughput.TotalUtilization >= tc.config.UtilizationThreshold, nil
}

// =============================================================================
// Aggregate Calculations
// =============================================================================

// CalculateAggregateThroughput calculates total throughput across interfaces.
func (tc *ThroughputCalculator) CalculateAggregateThroughput(interfaceNames []string) (totalRxMbps, totalTxMbps float64, err error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	for _, name := range interfaceNames {
		throughput, exists := tc.interfaceThroughput[name]
		if !exists {
			continue
		}
		totalRxMbps += throughput.RxMbps
		totalTxMbps += throughput.TxMbps
	}

	return totalRxMbps, totalTxMbps, nil
}

// GetTotalThroughput returns total throughput across all interfaces.
func (tc *ThroughputCalculator) GetTotalThroughput() (totalRxMbps, totalTxMbps float64) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	for _, throughput := range tc.interfaceThroughput {
		totalRxMbps += throughput.RxMbps
		totalTxMbps += throughput.TxMbps
	}

	return totalRxMbps, totalTxMbps
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the calculator is operational.
func (tc *ThroughputCalculator) HealthCheck() error {
	tc.runningMu.Lock()
	running := tc.running
	tc.runningMu.Unlock()

	if !running {
		return errors.New("throughput calculator not running")
	}

	// Check last calculation was recent.
	if time.Since(tc.lastCalculation) > tc.config.CalculationInterval*2 {
		return errors.New("throughput calculation stalled")
	}

	// Check we have throughput data.
	tc.mu.RLock()
	hasData := len(tc.interfaceThroughput) > 0
	tc.mu.RUnlock()

	if !hasData {
		return ErrNoThroughputData
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetCalculatorStatistics returns calculator operation statistics.
func (tc *ThroughputCalculator) GetCalculatorStatistics() map[string]uint64 {
	return map[string]uint64{
		"calculations_total": atomic.LoadUint64(&tc.calculationsTotal),
		"bursts_detected":    atomic.LoadUint64(&tc.burstsDetected),
	}
}

// GetConfig returns the current configuration.
func (tc *ThroughputCalculator) GetConfig() *ThroughputConfig {
	return tc.config
}

// GetLastCalculationTime returns the timestamp of the last calculation.
func (tc *ThroughputCalculator) GetLastCalculationTime() time.Time {
	return tc.lastCalculation
}

// GetInterfaceCount returns the number of monitored interfaces.
func (tc *ThroughputCalculator) GetInterfaceCount() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.interfaceThroughput)
}
