// Package performance provides network interface performance monitoring
// for the NIC Management service.
package performance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Packet Rate Error Types
// =============================================================================

var (
	// ErrPacketRateInterfaceNotFound indicates interface not found.
	ErrPacketRateInterfaceNotFound = errors.New("interface not found for packet rate")
	// ErrNoPacketRateData indicates no packet rate data calculated yet.
	ErrNoPacketRateData = errors.New("no packet rate data available")
	// ErrPacketRateInsufficientHistory indicates not enough samples.
	ErrPacketRateInsufficientHistory = errors.New("insufficient history for analysis")
	// ErrPacketRateInvalidDuration indicates invalid time window.
	ErrPacketRateInvalidDuration = errors.New("invalid duration")
)

// =============================================================================
// Interface Packet Rate Structure
// =============================================================================

// InterfacePacketRate contains current packet rate metrics for an interface.
type InterfacePacketRate struct {
	// InterfaceName is the interface name.
	InterfaceName string `json:"interface_name"`
	// Timestamp is when packet rate was calculated.
	Timestamp time.Time `json:"timestamp"`

	// Instantaneous packet rates.
	RxPacketsPerSec    uint64 `json:"rx_packets_per_sec"`
	TxPacketsPerSec    uint64 `json:"tx_packets_per_sec"`
	TotalPacketsPerSec uint64 `json:"total_packets_per_sec"`

	// Averaged packet rates.
	AverageRxPacketsPerSec uint64 `json:"average_rx_packets_per_sec"`
	AverageTxPacketsPerSec uint64 `json:"average_tx_packets_per_sec"`

	// Peak packet rates.
	PeakRxPacketsPerSec uint64    `json:"peak_rx_packets_per_sec"`
	PeakTxPacketsPerSec uint64    `json:"peak_tx_packets_per_sec"`
	PeakTimestamp       time.Time `json:"peak_timestamp,omitempty"`

	// Packet size analysis.
	AveragePacketSize   float64 `json:"average_packet_size"`
	RxAveragePacketSize float64 `json:"rx_average_packet_size"`
	TxAveragePacketSize float64 `json:"tx_average_packet_size"`

	// Small packet tracking.
	SmallPacketPercentage float64 `json:"small_packet_percentage"`

	// Microburst detection.
	MicroburstDetected bool `json:"microburst_detected"`

	// Capacity.
	PacketRateCapacity uint64 `json:"packet_rate_capacity"`
}

// =============================================================================
// Packet Rate Sample Structure
// =============================================================================

// PacketRateSample is a single packet rate measurement.
type PacketRateSample struct {
	// Timestamp is when sample was taken.
	Timestamp time.Time `json:"timestamp"`
	// RxPacketsPerSec is receive PPS.
	RxPacketsPerSec uint64 `json:"rx_packets_per_sec"`
	// TxPacketsPerSec is transmit PPS.
	TxPacketsPerSec uint64 `json:"tx_packets_per_sec"`
	// AveragePacketSize is average packet size at this time.
	AveragePacketSize float64 `json:"average_packet_size"`
}

// =============================================================================
// Packet Rate History Structure
// =============================================================================

// PacketRateHistory maintains historical packet rate samples.
type PacketRateHistory struct {
	// InterfaceName is the interface with this history.
	InterfaceName string
	// Samples is the circular buffer of samples.
	Samples []*PacketRateSample
	// MaxSamples is the maximum samples to retain.
	MaxSamples int
	// CurrentIndex is the next write position.
	CurrentIndex int
	// Count is the number of samples stored.
	Count int
}

// NewPacketRateHistory creates a new packet rate history buffer.
func NewPacketRateHistory(interfaceName string, maxSamples int) *PacketRateHistory {
	return &PacketRateHistory{
		InterfaceName: interfaceName,
		Samples:       make([]*PacketRateSample, maxSamples),
		MaxSamples:    maxSamples,
		CurrentIndex:  0,
		Count:         0,
	}
}

// Add adds a sample to the history.
func (h *PacketRateHistory) Add(sample *PacketRateSample) {
	h.Samples[h.CurrentIndex] = sample
	h.CurrentIndex = (h.CurrentIndex + 1) % h.MaxSamples
	if h.Count < h.MaxSamples {
		h.Count++
	}
}

// GetRecent returns the most recent N samples.
func (h *PacketRateHistory) GetRecent(count int) []*PacketRateSample {
	if count > h.Count {
		count = h.Count
	}
	if count == 0 {
		return nil
	}

	result := make([]*PacketRateSample, count)
	idx := (h.CurrentIndex - count + h.MaxSamples) % h.MaxSamples

	for i := 0; i < count; i++ {
		result[i] = h.Samples[idx]
		idx = (idx + 1) % h.MaxSamples
	}

	return result
}

// GetSamplesInDuration returns samples within the specified duration.
func (h *PacketRateHistory) GetSamplesInDuration(duration time.Duration) []*PacketRateSample {
	if h.Count == 0 {
		return nil
	}

	cutoff := time.Now().Add(-duration)
	var result []*PacketRateSample

	samples := h.GetRecent(h.Count)
	for _, sample := range samples {
		if sample != nil && sample.Timestamp.After(cutoff) {
			result = append(result, sample)
		}
	}

	return result
}

// =============================================================================
// Packet Rate Configuration
// =============================================================================

// PacketRateConfig contains configuration for packet rate calculation.
type PacketRateConfig struct {
	// CalculationInterval is how often to calculate packet rate (default: 5s).
	CalculationInterval time.Duration `json:"calculation_interval"`
	// MeasurementWindow is time window for averaging (default: 60s).
	MeasurementWindow time.Duration `json:"measurement_window"`
	// EnablePeakTracking tracks peak values (default: true).
	EnablePeakTracking bool `json:"enable_peak_tracking"`
	// PeakResetInterval resets peaks after duration (default: 24h).
	PeakResetInterval time.Duration `json:"peak_reset_interval"`
	// EnablePacketSizeAnalysis calculates average packet size (default: true).
	EnablePacketSizeAnalysis bool `json:"enable_packet_size_analysis"`
	// EnableMicroburstDetection detects microbursts (default: true).
	EnableMicroburstDetection bool `json:"enable_microburst_detection"`
	// MicroburstThreshold is PPS spike threshold (default: 3.0).
	MicroburstThreshold float64 `json:"microburst_threshold"`
	// SmallPacketThreshold is packet size considered "small" (default: 64).
	SmallPacketThreshold int `json:"small_packet_threshold"`
	// EnableSmallPacketTracking tracks small packet percentage (default: true).
	EnableSmallPacketTracking bool `json:"enable_small_packet_tracking"`
	// MaxHistorySamples is samples to retain (default: 720).
	MaxHistorySamples int `json:"max_history_samples"`
}

// DefaultPacketRateConfig returns the default packet rate calculator configuration.
func DefaultPacketRateConfig() *PacketRateConfig {
	return &PacketRateConfig{
		CalculationInterval:       5 * time.Second,
		MeasurementWindow:         60 * time.Second,
		EnablePeakTracking:        true,
		PeakResetInterval:         24 * time.Hour,
		EnablePacketSizeAnalysis:  true,
		EnableMicroburstDetection: true,
		MicroburstThreshold:       3.0,
		SmallPacketThreshold:      64,
		EnableSmallPacketTracking: true,
		MaxHistorySamples:         720,
	}
}

// =============================================================================
// Interface Bandwidth Provider
// =============================================================================

// PacketRateBandwidthProvider provides interface bandwidth information.
type PacketRateBandwidthProvider interface {
	// GetInterfaceBandwidth returns interface bandwidth in bits/sec.
	GetInterfaceBandwidth(interfaceName string) uint64
}

// No-op bandwidth provider.
type noOpPacketRateBandwidthProvider struct{}

func (n *noOpPacketRateBandwidthProvider) GetInterfaceBandwidth(interfaceName string) uint64 {
	return 1_000_000_000 // Default 1 Gbps.
}

// =============================================================================
// Packet Rate Calculator
// =============================================================================

// PacketRateCalculator calculates packet rate metrics.
type PacketRateCalculator struct {
	// Dependencies.
	statsCollector    *StatisticsCollector
	bandwidthProvider PacketRateBandwidthProvider

	// Configuration.
	config *PacketRateConfig

	// State.
	interfacePacketRate map[string]*InterfacePacketRate
	packetRateHistory   map[string]*PacketRateHistory
	peakResetTime       map[string]time.Time
	mu                  sync.RWMutex

	// Calculation control.
	calculationTicker *time.Ticker
	lastCalculation   time.Time

	// Statistics.
	calculationsTotal   uint64
	microburstsDetected uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewPacketRateCalculator creates a new packet rate calculator.
func NewPacketRateCalculator(
	statsCollector *StatisticsCollector,
	bandwidthProvider PacketRateBandwidthProvider,
	config *PacketRateConfig,
) *PacketRateCalculator {
	if config == nil {
		config = DefaultPacketRateConfig()
	}

	if bandwidthProvider == nil {
		bandwidthProvider = &noOpPacketRateBandwidthProvider{}
	}

	return &PacketRateCalculator{
		statsCollector:      statsCollector,
		bandwidthProvider:   bandwidthProvider,
		config:              config,
		interfacePacketRate: make(map[string]*InterfacePacketRate),
		packetRateHistory:   make(map[string]*PacketRateHistory),
		peakResetTime:       make(map[string]time.Time),
		stopChan:            make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the packet rate calculator.
func (prc *PacketRateCalculator) Start(ctx context.Context) error {
	prc.runningMu.Lock()
	defer prc.runningMu.Unlock()

	if prc.running {
		return nil
	}

	// Perform initial calculation.
	_ = prc.calculateAllPacketRates()

	// Start calculation ticker.
	prc.calculationTicker = time.NewTicker(prc.config.CalculationInterval)
	go prc.calculationLoop()

	prc.running = true
	return nil
}

// Stop shuts down the packet rate calculator.
func (prc *PacketRateCalculator) Stop() error {
	prc.runningMu.Lock()
	if !prc.running {
		prc.runningMu.Unlock()
		return nil
	}
	prc.running = false
	prc.runningMu.Unlock()

	if prc.calculationTicker != nil {
		prc.calculationTicker.Stop()
	}
	close(prc.stopChan)

	return nil
}

// calculationLoop is the background calculation goroutine.
func (prc *PacketRateCalculator) calculationLoop() {
	for {
		select {
		case <-prc.stopChan:
			return
		case <-prc.calculationTicker.C:
			_ = prc.calculateAllPacketRates()
		}
	}
}

// =============================================================================
// Packet Rate Calculation
// =============================================================================

// calculateAllPacketRates calculates packet rates for all interfaces.
func (prc *PacketRateCalculator) calculateAllPacketRates() error {
	if prc.statsCollector == nil {
		return nil
	}

	allStats := prc.statsCollector.GetAllStatistics()

	var lastErr error
	for interfaceName := range allStats {
		packetRate, err := prc.calculateInterfacePacketRate(interfaceName)
		if err != nil {
			lastErr = err
			continue
		}

		prc.mu.Lock()
		prc.interfacePacketRate[interfaceName] = packetRate

		// Add to history.
		if prc.packetRateHistory[interfaceName] == nil {
			prc.packetRateHistory[interfaceName] = NewPacketRateHistory(interfaceName, prc.config.MaxHistorySamples)
		}
		prc.packetRateHistory[interfaceName].Add(&PacketRateSample{
			Timestamp:         packetRate.Timestamp,
			RxPacketsPerSec:   packetRate.RxPacketsPerSec,
			TxPacketsPerSec:   packetRate.TxPacketsPerSec,
			AveragePacketSize: packetRate.AveragePacketSize,
		})
		prc.mu.Unlock()
	}

	atomic.AddUint64(&prc.calculationsTotal, 1)
	prc.lastCalculation = time.Now()

	return lastErr
}

// calculateInterfacePacketRate calculates packet rate for a single interface.
func (prc *PacketRateCalculator) calculateInterfacePacketRate(interfaceName string) (*InterfacePacketRate, error) {
	// Get current statistics.
	stats, err := prc.statsCollector.GetInterfaceStatistics(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	packetRate := &InterfacePacketRate{
		InterfaceName: interfaceName,
		Timestamp:     time.Now(),
	}

	// Step 1: Get instantaneous packet rates from stats.
	packetRate.RxPacketsPerSec = stats.RxPacketsPerSec
	packetRate.TxPacketsPerSec = stats.TxPacketsPerSec

	// Step 2: Calculate total packet rate.
	packetRate.TotalPacketsPerSec = packetRate.RxPacketsPerSec + packetRate.TxPacketsPerSec

	// Step 3: Calculate average packet rates.
	prc.calculateAveragePacketRates(packetRate)

	// Step 4: Update peak packet rates.
	if prc.config.EnablePeakTracking {
		prc.updatePeakPacketRates(packetRate)
	}

	// Step 5: Calculate average packet size.
	if prc.config.EnablePacketSizeAnalysis {
		prc.calculateAveragePacketSize(packetRate, stats)
	}

	// Step 6: Calculate small packet percentage.
	if prc.config.EnableSmallPacketTracking {
		prc.calculateSmallPacketPercentage(packetRate)
	}

	// Step 7: Detect microbursts.
	if prc.config.EnableMicroburstDetection {
		packetRate.MicroburstDetected = prc.detectMicroburst(interfaceName, packetRate)
	}

	// Step 8: Calculate packet rate capacity.
	prc.calculatePacketRateCapacity(packetRate)

	return packetRate, nil
}

// calculateAveragePacketRates calculates average packet rates over measurement window.
func (prc *PacketRateCalculator) calculateAveragePacketRates(packetRate *InterfacePacketRate) {
	prc.mu.RLock()
	history := prc.packetRateHistory[packetRate.InterfaceName]
	prc.mu.RUnlock()

	if history == nil || history.Count == 0 {
		packetRate.AverageRxPacketsPerSec = packetRate.RxPacketsPerSec
		packetRate.AverageTxPacketsPerSec = packetRate.TxPacketsPerSec
		return
	}

	samples := history.GetSamplesInDuration(prc.config.MeasurementWindow)
	if len(samples) == 0 {
		packetRate.AverageRxPacketsPerSec = packetRate.RxPacketsPerSec
		packetRate.AverageTxPacketsPerSec = packetRate.TxPacketsPerSec
		return
	}

	var totalRx, totalTx uint64
	for _, sample := range samples {
		totalRx += sample.RxPacketsPerSec
		totalTx += sample.TxPacketsPerSec
	}

	packetRate.AverageRxPacketsPerSec = totalRx / uint64(len(samples))
	packetRate.AverageTxPacketsPerSec = totalTx / uint64(len(samples))
}

// updatePeakPacketRates updates peak packet rate tracking.
func (prc *PacketRateCalculator) updatePeakPacketRates(packetRate *InterfacePacketRate) {
	prc.mu.Lock()
	defer prc.mu.Unlock()

	// Check if peak reset is needed.
	resetTime, exists := prc.peakResetTime[packetRate.InterfaceName]
	if !exists || time.Since(resetTime) > prc.config.PeakResetInterval {
		prc.peakResetTime[packetRate.InterfaceName] = time.Now()
		// Reset peaks - will be set below.
	}

	// Get existing packet rate for peak comparison.
	existing := prc.interfacePacketRate[packetRate.InterfaceName]
	if existing != nil {
		packetRate.PeakRxPacketsPerSec = existing.PeakRxPacketsPerSec
		packetRate.PeakTxPacketsPerSec = existing.PeakTxPacketsPerSec
		packetRate.PeakTimestamp = existing.PeakTimestamp
	}

	// Update if current exceeds peak.
	if packetRate.RxPacketsPerSec > packetRate.PeakRxPacketsPerSec {
		packetRate.PeakRxPacketsPerSec = packetRate.RxPacketsPerSec
		packetRate.PeakTimestamp = time.Now()
	}
	if packetRate.TxPacketsPerSec > packetRate.PeakTxPacketsPerSec {
		packetRate.PeakTxPacketsPerSec = packetRate.TxPacketsPerSec
		packetRate.PeakTimestamp = time.Now()
	}
}

// calculateAveragePacketSize calculates average packet size from byte/packet ratio.
func (prc *PacketRateCalculator) calculateAveragePacketSize(packetRate *InterfacePacketRate, stats *InterfaceStatistics) {
	totalPackets := packetRate.RxPacketsPerSec + packetRate.TxPacketsPerSec
	totalBytes := stats.RxBytesPerSec + stats.TxBytesPerSec

	if totalPackets > 0 {
		packetRate.AveragePacketSize = float64(totalBytes) / float64(totalPackets)
	}

	if packetRate.RxPacketsPerSec > 0 {
		packetRate.RxAveragePacketSize = float64(stats.RxBytesPerSec) / float64(packetRate.RxPacketsPerSec)
	}

	if packetRate.TxPacketsPerSec > 0 {
		packetRate.TxAveragePacketSize = float64(stats.TxBytesPerSec) / float64(packetRate.TxPacketsPerSec)
	}
}

// calculateSmallPacketPercentage estimates percentage of small packets.
func (prc *PacketRateCalculator) calculateSmallPacketPercentage(packetRate *InterfacePacketRate) {
	// Estimation based on average packet size.
	// Without deep packet inspection, we can only estimate.
	threshold := float64(prc.config.SmallPacketThreshold)

	if packetRate.AveragePacketSize <= 0 {
		packetRate.SmallPacketPercentage = 0
		return
	}

	if packetRate.AveragePacketSize < threshold {
		// If average is below threshold, most packets are likely small.
		// Estimate based on how far below threshold.
		ratio := packetRate.AveragePacketSize / threshold
		packetRate.SmallPacketPercentage = (1 - ratio) * 100
		if packetRate.SmallPacketPercentage > 100 {
			packetRate.SmallPacketPercentage = 100
		}
	} else {
		// Average is above threshold, estimate small packet percentage.
		// Using inverse relationship.
		ratio := threshold / packetRate.AveragePacketSize
		packetRate.SmallPacketPercentage = ratio * 50 // Max 50% if avg is above threshold.
	}
}

// calculatePacketRateCapacity calculates theoretical maximum PPS.
func (prc *PacketRateCalculator) calculatePacketRateCapacity(packetRate *InterfacePacketRate) {
	// Get interface bandwidth.
	bandwidth := prc.bandwidthProvider.GetInterfaceBandwidth(packetRate.InterfaceName)

	// Calculate theoretical maximum PPS.
	// Minimum Ethernet frame: 64 bytes + 20 bytes (interpacket gap + preamble) = 84 bytes.
	const minFrameSize = 84 * 8 // In bits.

	if bandwidth > 0 {
		packetRate.PacketRateCapacity = bandwidth / minFrameSize
	}
}

// =============================================================================
// Microburst Detection
// =============================================================================

// detectMicroburst identifies sudden packet rate spikes.
func (prc *PacketRateCalculator) detectMicroburst(interfaceName string, current *InterfacePacketRate) bool {
	averageTotal := current.AverageRxPacketsPerSec + current.AverageTxPacketsPerSec
	if averageTotal == 0 {
		return false
	}

	currentTotal := current.RxPacketsPerSec + current.TxPacketsPerSec
	ratio := float64(currentTotal) / float64(averageTotal)

	if ratio >= prc.config.MicroburstThreshold {
		atomic.AddUint64(&prc.microburstsDetected, 1)
		return true
	}

	return false
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfacePacketRate retrieves current packet rate for specific interface.
func (prc *PacketRateCalculator) GetInterfacePacketRate(interfaceName string) (*InterfacePacketRate, error) {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	// Return copy.
	copy := *packetRate
	return &copy, nil
}

// GetAllPacketRates retrieves packet rates for all interfaces.
func (prc *PacketRateCalculator) GetAllPacketRates() map[string]*InterfacePacketRate {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	result := make(map[string]*InterfacePacketRate, len(prc.interfacePacketRate))
	for name, packetRate := range prc.interfacePacketRate {
		copy := *packetRate
		result[name] = &copy
	}
	return result
}

// GetPacketRateHistory retrieves historical samples for interface.
func (prc *PacketRateCalculator) GetPacketRateHistory(interfaceName string, duration time.Duration) ([]*PacketRateSample, error) {
	if duration <= 0 {
		return nil, ErrPacketRateInvalidDuration
	}

	prc.mu.RLock()
	defer prc.mu.RUnlock()

	history, exists := prc.packetRateHistory[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	return history.GetSamplesInDuration(duration), nil
}

// GetPeakPacketRate retrieves peak packet rate values.
func (prc *PacketRateCalculator) GetPeakPacketRate(interfaceName string) (rxPeak, txPeak uint64, timestamp time.Time, err error) {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return 0, 0, time.Time{}, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	return packetRate.PeakRxPacketsPerSec, packetRate.PeakTxPacketsPerSec, packetRate.PeakTimestamp, nil
}

// ResetPeakPacketRate resets peak packet rate tracking.
func (prc *PacketRateCalculator) ResetPeakPacketRate(interfaceName string) error {
	prc.mu.Lock()
	defer prc.mu.Unlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	packetRate.PeakRxPacketsPerSec = 0
	packetRate.PeakTxPacketsPerSec = 0
	packetRate.PeakTimestamp = time.Time{}
	prc.peakResetTime[interfaceName] = time.Now()

	return nil
}

// =============================================================================
// Packet Size Analysis
// =============================================================================

// GetAveragePacketSize retrieves average packet size for interface.
func (prc *PacketRateCalculator) GetAveragePacketSize(interfaceName string) (avgSize float64, err error) {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return 0, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	return packetRate.AveragePacketSize, nil
}

// IsSmallPacketDominant checks if traffic is dominated by small packets.
func (prc *PacketRateCalculator) IsSmallPacketDominant(interfaceName string) (bool, error) {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return false, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	return packetRate.SmallPacketPercentage > 50, nil
}

// CalculatePacketRateEfficiency calculates bandwidth efficiency based on packet size.
func (prc *PacketRateCalculator) CalculatePacketRateEfficiency(interfaceName string) (efficiency float64, err error) {
	prc.mu.RLock()
	defer prc.mu.RUnlock()

	packetRate, exists := prc.interfacePacketRate[interfaceName]
	if !exists {
		return 0, fmt.Errorf("%w: %s", ErrPacketRateInterfaceNotFound, interfaceName)
	}

	if packetRate.AveragePacketSize <= 0 {
		return 0, nil
	}

	// Calculate efficiency: (packet size - overhead) / MTU.
	const overhead = 20.0 // Interpacket gap + preamble.
	const mtu = 1500.0

	efficiency = (packetRate.AveragePacketSize - overhead) / mtu * 100
	if efficiency < 0 {
		efficiency = 0
	}
	if efficiency > 100 {
		efficiency = 100
	}

	return efficiency, nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the calculator is operational.
func (prc *PacketRateCalculator) HealthCheck() error {
	prc.runningMu.Lock()
	running := prc.running
	prc.runningMu.Unlock()

	if !running {
		return errors.New("packet rate calculator not running")
	}

	// Check last calculation was recent.
	if time.Since(prc.lastCalculation) > prc.config.CalculationInterval*2 {
		return errors.New("packet rate calculation stalled")
	}

	// Check we have packet rate data.
	prc.mu.RLock()
	hasData := len(prc.interfacePacketRate) > 0
	prc.mu.RUnlock()

	if !hasData {
		return ErrNoPacketRateData
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetCalculatorStatistics returns calculator operation statistics.
func (prc *PacketRateCalculator) GetCalculatorStatistics() map[string]uint64 {
	return map[string]uint64{
		"calculations_total":   atomic.LoadUint64(&prc.calculationsTotal),
		"microbursts_detected": atomic.LoadUint64(&prc.microburstsDetected),
	}
}

// GetConfig returns the current configuration.
func (prc *PacketRateCalculator) GetConfig() *PacketRateConfig {
	return prc.config
}

// GetLastCalculationTime returns the timestamp of the last calculation.
func (prc *PacketRateCalculator) GetLastCalculationTime() time.Time {
	return prc.lastCalculation
}

// GetInterfaceCount returns the number of monitored interfaces.
func (prc *PacketRateCalculator) GetInterfaceCount() int {
	prc.mu.RLock()
	defer prc.mu.RUnlock()
	return len(prc.interfacePacketRate)
}
