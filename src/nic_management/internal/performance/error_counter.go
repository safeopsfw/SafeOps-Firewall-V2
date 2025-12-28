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
// Error Counter Error Types
// =============================================================================

var (
	// ErrErrorCounterInterfaceNotFound indicates interface not found.
	ErrErrorCounterInterfaceNotFound = errors.New("interface not found for error tracking")
	// ErrNoErrorData indicates no error data collected yet.
	ErrNoErrorData = errors.New("no error data available")
	// ErrBaselineNotEstablished indicates baseline not yet established.
	ErrBaselineNotEstablished = errors.New("baseline not yet established")
)

// =============================================================================
// Error Type Constants
// =============================================================================

const (
	ErrorTypeRxErrors     = "rx_errors"
	ErrorTypeTxErrors     = "tx_errors"
	ErrorTypeRxDropped    = "rx_dropped"
	ErrorTypeTxDropped    = "tx_dropped"
	ErrorTypeRxCrc        = "rx_crc_errors"
	ErrorTypeRxFrame      = "rx_frame_errors"
	ErrorTypeRxFifo       = "rx_fifo_errors"
	ErrorTypeTxCarrier    = "tx_carrier_errors"
	ErrorTypeTxCollisions = "tx_collisions"
)

// =============================================================================
// Error Counts Structure
// =============================================================================

// ErrorCounts contains snapshot of absolute error counter values.
type ErrorCounts struct {
	RxErrors        uint64 `json:"rx_errors"`
	TxErrors        uint64 `json:"tx_errors"`
	RxDropped       uint64 `json:"rx_dropped"`
	TxDropped       uint64 `json:"tx_dropped"`
	RxCrcErrors     uint64 `json:"rx_crc_errors"`
	RxFrameErrors   uint64 `json:"rx_frame_errors"`
	RxFifoErrors    uint64 `json:"rx_fifo_errors"`
	TxCarrierErrors uint64 `json:"tx_carrier_errors"`
	TxCollisions    uint64 `json:"tx_collisions"`
}

// Total returns the sum of all error counts.
func (c *ErrorCounts) Total() uint64 {
	return c.RxErrors + c.TxErrors + c.RxDropped + c.TxDropped +
		c.RxCrcErrors + c.RxFrameErrors + c.RxFifoErrors +
		c.TxCarrierErrors + c.TxCollisions
}

// =============================================================================
// Error Rates Structure
// =============================================================================

// ErrorRates contains calculated error rates in errors-per-second.
type ErrorRates struct {
	RxErrorsPerSec     float64 `json:"rx_errors_per_sec"`
	TxErrorsPerSec     float64 `json:"tx_errors_per_sec"`
	RxDroppedPerSec    float64 `json:"rx_dropped_per_sec"`
	TxDroppedPerSec    float64 `json:"tx_dropped_per_sec"`
	RxCrcPerSec        float64 `json:"rx_crc_per_sec"`
	RxFramePerSec      float64 `json:"rx_frame_per_sec"`
	RxFifoPerSec       float64 `json:"rx_fifo_per_sec"`
	TxCarrierPerSec    float64 `json:"tx_carrier_per_sec"`
	TxCollisionsPerSec float64 `json:"tx_collisions_per_sec"`
	TotalErrorsPerSec  float64 `json:"total_errors_per_sec"`
}

// =============================================================================
// Error Thresholds Structure
// =============================================================================

// ErrorThresholds contains configurable threshold limits for alerts.
type ErrorThresholds struct {
	TotalErrorsPerSec   float64 `json:"total_errors_per_sec"`
	CrcErrorsPerSec     float64 `json:"crc_errors_per_sec"`
	DroppedPerSec       float64 `json:"dropped_per_sec"`
	FifoErrorsPerSec    float64 `json:"fifo_errors_per_sec"`
	CarrierErrorsPerSec float64 `json:"carrier_errors_per_sec"`
	CollisionsPerSec    float64 `json:"collisions_per_sec"`
}

// DefaultErrorThresholds returns the default error thresholds.
func DefaultErrorThresholds() *ErrorThresholds {
	return &ErrorThresholds{
		TotalErrorsPerSec:   100,
		CrcErrorsPerSec:     10,
		DroppedPerSec:       50,
		FifoErrorsPerSec:    20,
		CarrierErrorsPerSec: 15,
		CollisionsPerSec:    30,
	}
}

// =============================================================================
// Error History Point Structure
// =============================================================================

// ErrorHistoryPoint is a single historical data point.
type ErrorHistoryPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Counts    ErrorCounts `json:"counts"`
	Rates     ErrorRates  `json:"rates"`
}

// =============================================================================
// Threshold Violation Structure
// =============================================================================

// ThresholdViolation describes a threshold that was exceeded.
type ThresholdViolation struct {
	ErrorType   string  `json:"error_type"`
	CurrentRate float64 `json:"current_rate"`
	Threshold   float64 `json:"threshold"`
	Severity    float64 `json:"severity"` // How much threshold was exceeded (ratio).
}

// =============================================================================
// Interface Error State Structure
// =============================================================================

// InterfaceErrorState contains per-interface error tracking state.
type InterfaceErrorState struct {
	Current             ErrorCounts          `json:"current"`
	Previous            ErrorCounts          `json:"previous"`
	Rates               ErrorRates           `json:"rates"`
	History             []*ErrorHistoryPoint `json:"history,omitempty"`
	LastCollection      time.Time            `json:"last_collection"`
	Baseline            ErrorRates           `json:"baseline"`
	BaselineEstablished bool                 `json:"baseline_established"`
	BaselineStartTime   time.Time            `json:"baseline_start_time"`
	TotalSamples        int                  `json:"total_samples"`
	BaselineSumRates    ErrorRates           `json:"-"` // Accumulator for baseline calculation.
}

// =============================================================================
// Interface Error Summary Structure
// =============================================================================

// InterfaceErrorSummary is a summary of errors for an interface.
type InterfaceErrorSummary struct {
	InterfaceName string      `json:"interface_name"`
	Counts        ErrorCounts `json:"counts"`
	Rates         ErrorRates  `json:"rates"`
	TotalErrors   uint64      `json:"total_errors"`
	LastUpdated   time.Time   `json:"last_updated"`
}

// =============================================================================
// Error Counter Configuration
// =============================================================================

// ErrorCounterConfig contains configuration for error counter.
type ErrorCounterConfig struct {
	// CollectionInterval is how often to sample error counters (default: 5s).
	CollectionInterval time.Duration `json:"collection_interval"`
	// HistoryRetention is how long to keep historical data (default: 1h).
	HistoryRetention time.Duration `json:"history_retention"`
	// BaselinePeriod is duration for baseline establishment (default: 5m).
	BaselinePeriod time.Duration `json:"baseline_period"`
	// SpikeMultiplier is threshold for spike detection (default: 5.0).
	SpikeMultiplier float64 `json:"spike_multiplier"`
	// AlertCooldown is minimum time between repeated alerts (default: 5m).
	AlertCooldown time.Duration `json:"alert_cooldown"`
	// Thresholds are the error rate thresholds.
	Thresholds *ErrorThresholds `json:"thresholds"`
	// EnableSmoothing enables exponential moving average.
	EnableSmoothing bool `json:"enable_smoothing"`
	// SmoothingAlpha is the EMA alpha value (default: 0.3).
	SmoothingAlpha float64 `json:"smoothing_alpha"`
}

// DefaultErrorCounterConfig returns the default error counter configuration.
func DefaultErrorCounterConfig() *ErrorCounterConfig {
	return &ErrorCounterConfig{
		CollectionInterval: 5 * time.Second,
		HistoryRetention:   time.Hour,
		BaselinePeriod:     5 * time.Minute,
		SpikeMultiplier:    5.0,
		AlertCooldown:      5 * time.Minute,
		Thresholds:         DefaultErrorThresholds(),
		EnableSmoothing:    false,
		SmoothingAlpha:     0.3,
	}
}

// =============================================================================
// Error Counter
// =============================================================================

// ErrorCounter tracks network errors across all interfaces.
type ErrorCounter struct {
	// Dependencies.
	statsCollector *StatisticsCollector

	// Configuration.
	config *ErrorCounterConfig

	// State.
	interfaces     map[string]*InterfaceErrorState
	mu             sync.RWMutex
	alertCooldowns map[string]time.Time

	// Collection control.
	ticker         *time.Ticker
	lastCollection time.Time

	// Statistics.
	collectionsTotal    uint64
	thresholdViolations uint64
	spikeDetections     uint64
	anomaliesDetected   uint64

	// Callbacks.
	failoverCallback func(interfaceName string, degradationLevel float64)

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewErrorCounter creates a new error counter.
func NewErrorCounter(
	statsCollector *StatisticsCollector,
	config *ErrorCounterConfig,
) *ErrorCounter {
	if config == nil {
		config = DefaultErrorCounterConfig()
	}

	if config.Thresholds == nil {
		config.Thresholds = DefaultErrorThresholds()
	}

	return &ErrorCounter{
		statsCollector: statsCollector,
		config:         config,
		interfaces:     make(map[string]*InterfaceErrorState),
		alertCooldowns: make(map[string]time.Time),
		stopChan:       make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins the error collection loop.
func (ec *ErrorCounter) Start(ctx context.Context) error {
	ec.runningMu.Lock()
	defer ec.runningMu.Unlock()

	if ec.running {
		return nil
	}

	// Start collection ticker.
	ec.ticker = time.NewTicker(ec.config.CollectionInterval)
	go ec.collectionLoop()

	ec.running = true
	return nil
}

// Stop gracefully shuts down the error counter.
func (ec *ErrorCounter) Stop() error {
	ec.runningMu.Lock()
	if !ec.running {
		ec.runningMu.Unlock()
		return nil
	}
	ec.running = false
	ec.runningMu.Unlock()

	if ec.ticker != nil {
		ec.ticker.Stop()
	}
	close(ec.stopChan)

	return nil
}

// collectionLoop is the background collection goroutine.
func (ec *ErrorCounter) collectionLoop() {
	for {
		select {
		case <-ec.stopChan:
			return
		case <-ec.ticker.C:
			ec.collectAllErrors()
		}
	}
}

// SetFailoverCallback sets the callback for failover notifications.
func (ec *ErrorCounter) SetFailoverCallback(callback func(interfaceName string, degradationLevel float64)) {
	ec.failoverCallback = callback
}

// =============================================================================
// Error Collection
// =============================================================================

// collectAllErrors collects errors for all interfaces.
func (ec *ErrorCounter) collectAllErrors() {
	if ec.statsCollector == nil {
		return
	}

	allStats := ec.statsCollector.GetAllStatistics()

	for interfaceName, stats := range allStats {
		ec.collectInterfaceErrors(interfaceName, stats)
	}

	atomic.AddUint64(&ec.collectionsTotal, 1)
	ec.lastCollection = time.Now()

	// Prune historical data.
	ec.pruneHistory()
}

// collectInterfaceErrors collects errors for a single interface.
func (ec *ErrorCounter) collectInterfaceErrors(interfaceName string, stats *InterfaceStatistics) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	now := time.Now()

	// Get or create interface state.
	state, exists := ec.interfaces[interfaceName]
	if !exists {
		state = &InterfaceErrorState{
			History:           make([]*ErrorHistoryPoint, 0, 720), // 1 hour at 5s intervals.
			BaselineStartTime: now,
		}
		ec.interfaces[interfaceName] = state
	}

	// Store previous counts.
	state.Previous = state.Current

	// Collect current error counts from statistics.
	state.Current = ErrorCounts{
		RxErrors:  stats.RxErrors,
		TxErrors:  stats.TxErrors,
		RxDropped: stats.RxDrops,
		TxDropped: stats.TxDrops,
		// Additional error types would be populated from detailed stats.
		// For now, use aggregate RxErrors/TxErrors.
	}

	// Calculate rates if we have previous data.
	if !state.LastCollection.IsZero() {
		ec.calculateErrorRates(state, now)
	}

	state.LastCollection = now

	// Add to history.
	state.History = append(state.History, &ErrorHistoryPoint{
		Timestamp: now,
		Counts:    state.Current,
		Rates:     state.Rates,
	})

	// Establish baseline.
	ec.establishBaseline(state)

	// Check thresholds (without lock - use local copy).
	violations := ec.checkThresholdsInternal(state)

	// Detect anomalies.
	if state.BaselineEstablished {
		ec.detectAnomalies(interfaceName, state)
	}

	// Handle violations (outside lock would be better but keeping simple).
	for _, v := range violations {
		ec.handleViolation(interfaceName, v)
	}
}

// CollectErrors collects error counts for a specific interface.
func (ec *ErrorCounter) CollectErrors(interfaceName string) (*ErrorCounts, error) {
	if ec.statsCollector == nil {
		return nil, ErrNoErrorData
	}

	stats, err := ec.statsCollector.GetInterfaceStatistics(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	counts := &ErrorCounts{
		RxErrors:  stats.RxErrors,
		TxErrors:  stats.TxErrors,
		RxDropped: stats.RxDrops,
		TxDropped: stats.TxDrops,
	}

	return counts, nil
}

// =============================================================================
// Error Rate Calculation
// =============================================================================

// calculateErrorRates computes rates from counter deltas.
func (ec *ErrorCounter) calculateErrorRates(state *InterfaceErrorState, now time.Time) {
	interval := now.Sub(state.LastCollection).Seconds()
	if interval <= 0 {
		return
	}

	// Calculate deltas with wrap-around handling.
	rxErrorsDelta := ec.calculateDelta(state.Current.RxErrors, state.Previous.RxErrors)
	txErrorsDelta := ec.calculateDelta(state.Current.TxErrors, state.Previous.TxErrors)
	rxDroppedDelta := ec.calculateDelta(state.Current.RxDropped, state.Previous.RxDropped)
	txDroppedDelta := ec.calculateDelta(state.Current.TxDropped, state.Previous.TxDropped)
	rxCrcDelta := ec.calculateDelta(state.Current.RxCrcErrors, state.Previous.RxCrcErrors)
	rxFrameDelta := ec.calculateDelta(state.Current.RxFrameErrors, state.Previous.RxFrameErrors)
	rxFifoDelta := ec.calculateDelta(state.Current.RxFifoErrors, state.Previous.RxFifoErrors)
	txCarrierDelta := ec.calculateDelta(state.Current.TxCarrierErrors, state.Previous.TxCarrierErrors)
	txCollisionsDelta := ec.calculateDelta(state.Current.TxCollisions, state.Previous.TxCollisions)

	// Calculate rates.
	newRates := ErrorRates{
		RxErrorsPerSec:     float64(rxErrorsDelta) / interval,
		TxErrorsPerSec:     float64(txErrorsDelta) / interval,
		RxDroppedPerSec:    float64(rxDroppedDelta) / interval,
		TxDroppedPerSec:    float64(txDroppedDelta) / interval,
		RxCrcPerSec:        float64(rxCrcDelta) / interval,
		RxFramePerSec:      float64(rxFrameDelta) / interval,
		RxFifoPerSec:       float64(rxFifoDelta) / interval,
		TxCarrierPerSec:    float64(txCarrierDelta) / interval,
		TxCollisionsPerSec: float64(txCollisionsDelta) / interval,
	}

	// Calculate total.
	newRates.TotalErrorsPerSec = newRates.RxErrorsPerSec + newRates.TxErrorsPerSec +
		newRates.RxDroppedPerSec + newRates.TxDroppedPerSec +
		newRates.RxCrcPerSec + newRates.RxFramePerSec + newRates.RxFifoPerSec +
		newRates.TxCarrierPerSec + newRates.TxCollisionsPerSec

	// Apply EMA smoothing if enabled.
	if ec.config.EnableSmoothing && state.TotalSamples > 0 {
		alpha := ec.config.SmoothingAlpha
		newRates.RxErrorsPerSec = alpha*newRates.RxErrorsPerSec + (1-alpha)*state.Rates.RxErrorsPerSec
		newRates.TxErrorsPerSec = alpha*newRates.TxErrorsPerSec + (1-alpha)*state.Rates.TxErrorsPerSec
		newRates.RxDroppedPerSec = alpha*newRates.RxDroppedPerSec + (1-alpha)*state.Rates.RxDroppedPerSec
		newRates.TxDroppedPerSec = alpha*newRates.TxDroppedPerSec + (1-alpha)*state.Rates.TxDroppedPerSec
		newRates.TotalErrorsPerSec = alpha*newRates.TotalErrorsPerSec + (1-alpha)*state.Rates.TotalErrorsPerSec
	}

	state.Rates = newRates
}

// calculateDelta computes delta with wrap-around handling.
func (ec *ErrorCounter) calculateDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	// Counter wrapped around.
	// Check for 32-bit wrap (common in some drivers).
	if previous > math.MaxUint32 {
		// 64-bit wrap.
		return (math.MaxUint64 - previous) + current + 1
	}
	// Assume 32-bit wrap.
	return (math.MaxUint32 - previous) + current + 1
}

// =============================================================================
// Baseline Establishment
// =============================================================================

// establishBaseline computes normal error rate baseline.
func (ec *ErrorCounter) establishBaseline(state *InterfaceErrorState) {
	if state.BaselineEstablished {
		return
	}

	// Check if baseline period has elapsed.
	if time.Since(state.BaselineStartTime) < ec.config.BaselinePeriod {
		// Accumulate rates for averaging.
		state.BaselineSumRates.RxErrorsPerSec += state.Rates.RxErrorsPerSec
		state.BaselineSumRates.TxErrorsPerSec += state.Rates.TxErrorsPerSec
		state.BaselineSumRates.RxDroppedPerSec += state.Rates.RxDroppedPerSec
		state.BaselineSumRates.TxDroppedPerSec += state.Rates.TxDroppedPerSec
		state.BaselineSumRates.TotalErrorsPerSec += state.Rates.TotalErrorsPerSec
		state.TotalSamples++
		return
	}

	// Calculate average baseline.
	if state.TotalSamples > 0 {
		n := float64(state.TotalSamples)
		state.Baseline = ErrorRates{
			RxErrorsPerSec:    state.BaselineSumRates.RxErrorsPerSec / n,
			TxErrorsPerSec:    state.BaselineSumRates.TxErrorsPerSec / n,
			RxDroppedPerSec:   state.BaselineSumRates.RxDroppedPerSec / n,
			TxDroppedPerSec:   state.BaselineSumRates.TxDroppedPerSec / n,
			TotalErrorsPerSec: state.BaselineSumRates.TotalErrorsPerSec / n,
		}
		state.BaselineEstablished = true
	}
}

// =============================================================================
// Threshold Checking
// =============================================================================

// checkThresholdsInternal checks thresholds without locking.
func (ec *ErrorCounter) checkThresholdsInternal(state *InterfaceErrorState) []ThresholdViolation {
	var violations []ThresholdViolation
	thresholds := ec.config.Thresholds

	// Check total errors.
	if state.Rates.TotalErrorsPerSec > thresholds.TotalErrorsPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   "total",
			CurrentRate: state.Rates.TotalErrorsPerSec,
			Threshold:   thresholds.TotalErrorsPerSec,
			Severity:    state.Rates.TotalErrorsPerSec / thresholds.TotalErrorsPerSec,
		})
	}

	// Check CRC errors.
	if state.Rates.RxCrcPerSec > thresholds.CrcErrorsPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   ErrorTypeRxCrc,
			CurrentRate: state.Rates.RxCrcPerSec,
			Threshold:   thresholds.CrcErrorsPerSec,
			Severity:    state.Rates.RxCrcPerSec / thresholds.CrcErrorsPerSec,
		})
	}

	// Check dropped packets.
	droppedPerSec := state.Rates.RxDroppedPerSec + state.Rates.TxDroppedPerSec
	if droppedPerSec > thresholds.DroppedPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   "dropped",
			CurrentRate: droppedPerSec,
			Threshold:   thresholds.DroppedPerSec,
			Severity:    droppedPerSec / thresholds.DroppedPerSec,
		})
	}

	// Check FIFO errors.
	if state.Rates.RxFifoPerSec > thresholds.FifoErrorsPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   ErrorTypeRxFifo,
			CurrentRate: state.Rates.RxFifoPerSec,
			Threshold:   thresholds.FifoErrorsPerSec,
			Severity:    state.Rates.RxFifoPerSec / thresholds.FifoErrorsPerSec,
		})
	}

	// Check carrier errors.
	if state.Rates.TxCarrierPerSec > thresholds.CarrierErrorsPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   ErrorTypeTxCarrier,
			CurrentRate: state.Rates.TxCarrierPerSec,
			Threshold:   thresholds.CarrierErrorsPerSec,
			Severity:    state.Rates.TxCarrierPerSec / thresholds.CarrierErrorsPerSec,
		})
	}

	// Check collisions.
	if state.Rates.TxCollisionsPerSec > thresholds.CollisionsPerSec {
		violations = append(violations, ThresholdViolation{
			ErrorType:   ErrorTypeTxCollisions,
			CurrentRate: state.Rates.TxCollisionsPerSec,
			Threshold:   thresholds.CollisionsPerSec,
			Severity:    state.Rates.TxCollisionsPerSec / thresholds.CollisionsPerSec,
		})
	}

	return violations
}

// CheckThresholds checks thresholds for an interface.
func (ec *ErrorCounter) CheckThresholds(interfaceName string) ([]ThresholdViolation, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	return ec.checkThresholdsInternal(state), nil
}

// handleViolation processes a threshold violation.
func (ec *ErrorCounter) handleViolation(interfaceName string, violation ThresholdViolation) {
	atomic.AddUint64(&ec.thresholdViolations, 1)

	// Check cooldown.
	cooldownKey := fmt.Sprintf("%s:%s", interfaceName, violation.ErrorType)
	if ec.checkAlertCooldown(cooldownKey) {
		return
	}

	// Set cooldown.
	ec.alertCooldowns[cooldownKey] = time.Now()

	// Notify failover if callback set.
	if ec.failoverCallback != nil {
		degradation := math.Min(violation.Severity/10.0, 1.0) // Normalize to 0-1.
		ec.failoverCallback(interfaceName, degradation)
	}
}

// checkAlertCooldown checks if alert is in cooldown.
func (ec *ErrorCounter) checkAlertCooldown(key string) bool {
	lastAlert, exists := ec.alertCooldowns[key]
	if !exists {
		return false
	}
	return time.Since(lastAlert) < ec.config.AlertCooldown
}

// =============================================================================
// Anomaly Detection
// =============================================================================

// detectAnomalies detects rates exceeding baseline.
func (ec *ErrorCounter) detectAnomalies(interfaceName string, state *InterfaceErrorState) {
	multiplier := ec.config.SpikeMultiplier

	// Check if current rates exceed baseline by spike multiplier.
	if state.Baseline.TotalErrorsPerSec > 0 {
		ratio := state.Rates.TotalErrorsPerSec / state.Baseline.TotalErrorsPerSec
		if ratio >= multiplier {
			atomic.AddUint64(&ec.anomaliesDetected, 1)
		}
	}

	// Detect sudden spikes compared to previous.
	if state.TotalSamples > 1 {
		ec.detectSpike(interfaceName, state)
	}
}

// detectSpike detects sudden increases in error rates.
func (ec *ErrorCounter) detectSpike(_ string, state *InterfaceErrorState) {
	if len(state.History) < 2 {
		return
	}

	// Compare with previous rate.
	prevPoint := state.History[len(state.History)-2]
	if prevPoint.Rates.TotalErrorsPerSec > 0 {
		ratio := state.Rates.TotalErrorsPerSec / prevPoint.Rates.TotalErrorsPerSec
		if ratio >= 3.0 { // 3× spike.
			atomic.AddUint64(&ec.spikeDetections, 1)
		}
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetCurrentErrors returns current error counts for interface.
func (ec *ErrorCounter) GetCurrentErrors(interfaceName string) (*ErrorCounts, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	counts := state.Current
	return &counts, nil
}

// GetCurrentRates returns current error rates for interface.
func (ec *ErrorCounter) GetCurrentRates(interfaceName string) (*ErrorRates, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	rates := state.Rates
	return &rates, nil
}

// GetErrorHistory returns historical error data within duration.
func (ec *ErrorCounter) GetErrorHistory(interfaceName string, duration time.Duration) ([]*ErrorHistoryPoint, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	cutoff := time.Now().Add(-duration)
	var result []*ErrorHistoryPoint

	for _, point := range state.History {
		if point.Timestamp.After(cutoff) {
			result = append(result, point)
		}
	}

	return result, nil
}

// GetTotalErrors returns total error count for interface.
func (ec *ErrorCounter) GetTotalErrors(interfaceName string) (uint64, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return 0, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	return state.Current.Total(), nil
}

// GetErrorBreakdown returns percentage distribution of errors.
func (ec *ErrorCounter) GetErrorBreakdown(interfaceName string) (map[string]float64, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	total := float64(state.Current.Total())
	if total == 0 {
		return map[string]float64{}, nil
	}

	return map[string]float64{
		ErrorTypeRxErrors:     float64(state.Current.RxErrors) / total * 100,
		ErrorTypeTxErrors:     float64(state.Current.TxErrors) / total * 100,
		ErrorTypeRxDropped:    float64(state.Current.RxDropped) / total * 100,
		ErrorTypeTxDropped:    float64(state.Current.TxDropped) / total * 100,
		ErrorTypeRxCrc:        float64(state.Current.RxCrcErrors) / total * 100,
		ErrorTypeRxFrame:      float64(state.Current.RxFrameErrors) / total * 100,
		ErrorTypeRxFifo:       float64(state.Current.RxFifoErrors) / total * 100,
		ErrorTypeTxCarrier:    float64(state.Current.TxCarrierErrors) / total * 100,
		ErrorTypeTxCollisions: float64(state.Current.TxCollisions) / total * 100,
	}, nil
}

// GetAllInterfaceErrors returns error summary for all interfaces.
func (ec *ErrorCounter) GetAllInterfaceErrors() map[string]*InterfaceErrorSummary {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	result := make(map[string]*InterfaceErrorSummary, len(ec.interfaces))

	for name, state := range ec.interfaces {
		result[name] = &InterfaceErrorSummary{
			InterfaceName: name,
			Counts:        state.Current,
			Rates:         state.Rates,
			TotalErrors:   state.Current.Total(),
			LastUpdated:   state.LastCollection,
		}
	}

	return result
}

// GetBaseline returns the established baseline for interface.
func (ec *ErrorCounter) GetBaseline(interfaceName string) (*ErrorRates, bool, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	state, exists := ec.interfaces[interfaceName]
	if !exists {
		return nil, false, fmt.Errorf("%w: %s", ErrErrorCounterInterfaceNotFound, interfaceName)
	}

	rates := state.Baseline
	return &rates, state.BaselineEstablished, nil
}

// =============================================================================
// Maintenance Methods
// =============================================================================

// ResetCounters clears error tracking for interface.
func (ec *ErrorCounter) ResetCounters(interfaceName string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	delete(ec.interfaces, interfaceName)

	// Clear cooldowns for this interface.
	for key := range ec.alertCooldowns {
		if len(key) > len(interfaceName) && key[:len(interfaceName)] == interfaceName {
			delete(ec.alertCooldowns, key)
		}
	}

	return nil
}

// pruneHistory removes old history entries.
func (ec *ErrorCounter) pruneHistory() {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	cutoff := time.Now().Add(-ec.config.HistoryRetention)

	for _, state := range ec.interfaces {
		var pruned []*ErrorHistoryPoint
		for _, point := range state.History {
			if point.Timestamp.After(cutoff) {
				pruned = append(pruned, point)
			}
		}
		state.History = pruned
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the error counter is operational.
func (ec *ErrorCounter) HealthCheck() error {
	ec.runningMu.Lock()
	running := ec.running
	ec.runningMu.Unlock()

	if !running {
		return errors.New("error counter not running")
	}

	// Check last collection was recent.
	if time.Since(ec.lastCollection) > ec.config.CollectionInterval*2 {
		return errors.New("error collection stalled")
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetCounterStatistics returns error counter operation statistics.
func (ec *ErrorCounter) GetCounterStatistics() map[string]uint64 {
	return map[string]uint64{
		"collections_total":    atomic.LoadUint64(&ec.collectionsTotal),
		"threshold_violations": atomic.LoadUint64(&ec.thresholdViolations),
		"spike_detections":     atomic.LoadUint64(&ec.spikeDetections),
		"anomalies_detected":   atomic.LoadUint64(&ec.anomaliesDetected),
	}
}

// GetConfig returns the current configuration.
func (ec *ErrorCounter) GetConfig() *ErrorCounterConfig {
	return ec.config
}

// GetLastCollectionTime returns the timestamp of the last collection.
func (ec *ErrorCounter) GetLastCollectionTime() time.Time {
	return ec.lastCollection
}

// GetInterfaceCount returns the number of tracked interfaces.
func (ec *ErrorCounter) GetInterfaceCount() int {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return len(ec.interfaces)
}
