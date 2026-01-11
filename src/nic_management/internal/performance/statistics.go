// Package performance provides network interface performance monitoring
// for the NIC Management service.
package performance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Statistics Error Types
// =============================================================================

var (
	// ErrStatsInterfaceNotFound indicates interface does not exist.
	ErrStatsInterfaceNotFound = errors.New("interface not found")
	// ErrNoStatisticsAvailable indicates no statistics collected yet.
	ErrNoStatisticsAvailable = errors.New("no statistics available")
	// ErrCollectionFailed indicates statistics collection failed.
	ErrCollectionFailed = errors.New("collection failed")
	// ErrInvalidTimeRange indicates invalid duration for historical query.
	ErrInvalidTimeRange = errors.New("invalid time range")
	// ErrStatsPlatformUnsupported indicates operating system not supported.
	ErrStatsPlatformUnsupported = errors.New("platform unsupported")
)

// =============================================================================
// Platform Detection
// =============================================================================

// StatsPlatform represents the operating system platform.
type StatsPlatform int

const (
	// StatsPlatformUnknown indicates unknown or unsupported platform.
	StatsPlatformUnknown StatsPlatform = iota
	// StatsPlatformLinux indicates Linux operating system.
	StatsPlatformLinux
	// StatsPlatformWindows indicates Windows operating system.
	StatsPlatformWindows
)

// DetectStatsPlatform detects the current operating system.
func DetectStatsPlatform() StatsPlatform {
	switch runtime.GOOS {
	case "linux":
		return StatsPlatformLinux
	case "windows":
		return StatsPlatformWindows
	default:
		return StatsPlatformUnknown
	}
}

// String returns the string representation of the platform.
func (p StatsPlatform) String() string {
	switch p {
	case StatsPlatformLinux:
		return "LINUX"
	case StatsPlatformWindows:
		return "WINDOWS"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Link State Enumeration
// =============================================================================

// LinkState represents physical link connection state.
type LinkState int

const (
	// LinkStateUnknown indicates link state indeterminate.
	LinkStateUnknown LinkState = iota
	// LinkStateUp indicates physical link connected.
	LinkStateUp
	// LinkStateDown indicates physical link disconnected.
	LinkStateDown
)

// String returns the string representation of the link state.
func (s LinkState) String() string {
	switch s {
	case LinkStateUp:
		return "UP"
	case LinkStateDown:
		return "DOWN"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Interface Statistics Structure
// =============================================================================

// InterfaceStatistics contains complete statistics snapshot for an interface.
type InterfaceStatistics struct {
	// InterfaceName is the interface name.
	InterfaceName string `json:"interface_name"`
	// Timestamp is when statistics were collected.
	Timestamp time.Time `json:"timestamp"`

	// Cumulative counters.
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxPackets  uint64 `json:"rx_packets"`
	TxPackets  uint64 `json:"tx_packets"`
	RxErrors   uint64 `json:"rx_errors"`
	TxErrors   uint64 `json:"tx_errors"`
	RxDrops    uint64 `json:"rx_drops"`
	TxDrops    uint64 `json:"tx_drops"`
	Collisions uint64 `json:"collisions"`
	Multicast  uint64 `json:"multicast"`

	// Calculated rates.
	RxBytesPerSec   uint64  `json:"rx_bytes_per_sec"`
	TxBytesPerSec   uint64  `json:"tx_bytes_per_sec"`
	RxPacketsPerSec uint64  `json:"rx_packets_per_sec"`
	TxPacketsPerSec uint64  `json:"tx_packets_per_sec"`
	RxErrorsPerSec  float64 `json:"rx_errors_per_sec"`
	TxErrorsPerSec  float64 `json:"tx_errors_per_sec"`

	// Link state.
	LinkState LinkState `json:"link_state"`
}

// =============================================================================
// Statistics History Structure
// =============================================================================

// StatisticsHistory maintains historical statistics samples.
type StatisticsHistory struct {
	// InterfaceName is the interface with this history.
	InterfaceName string
	// Samples is the circular buffer of samples.
	Samples []*InterfaceStatistics
	// MaxSamples is the maximum samples to retain.
	MaxSamples int
	// CurrentIndex is the next write position.
	CurrentIndex int
	// Count is the number of samples stored.
	Count int
}

// NewStatisticsHistory creates a new statistics history buffer.
func NewStatisticsHistory(interfaceName string, maxSamples int) *StatisticsHistory {
	return &StatisticsHistory{
		InterfaceName: interfaceName,
		Samples:       make([]*InterfaceStatistics, maxSamples),
		MaxSamples:    maxSamples,
		CurrentIndex:  0,
		Count:         0,
	}
}

// Add adds a sample to the history.
func (h *StatisticsHistory) Add(stats *InterfaceStatistics) {
	h.Samples[h.CurrentIndex] = stats
	h.CurrentIndex = (h.CurrentIndex + 1) % h.MaxSamples
	if h.Count < h.MaxSamples {
		h.Count++
	}
}

// GetRecent returns the most recent N samples.
func (h *StatisticsHistory) GetRecent(count int) []*InterfaceStatistics {
	if count > h.Count {
		count = h.Count
	}
	if count == 0 {
		return nil
	}

	result := make([]*InterfaceStatistics, count)
	idx := (h.CurrentIndex - count + h.MaxSamples) % h.MaxSamples

	for i := 0; i < count; i++ {
		result[i] = h.Samples[idx]
		idx = (idx + 1) % h.MaxSamples
	}

	return result
}

// =============================================================================
// Collector Configuration
// =============================================================================

// CollectorConfig contains configuration for statistics collection.
type CollectorConfig struct {
	// CollectionInterval is how often to collect statistics (default: 1s).
	CollectionInterval time.Duration `json:"collection_interval"`
	// EnableRateCalculation calculates per-second rates (default: true).
	EnableRateCalculation bool `json:"enable_rate_calculation"`
	// RateCalculationWindow is the time window for rate averaging (default: 1s).
	RateCalculationWindow time.Duration `json:"rate_calculation_window"`
	// MaxHistorySamples is number of historical samples to retain (default: 60).
	MaxHistorySamples int `json:"max_history_samples"`
	// EnableErrorTracking tracks error and drop counters (default: true).
	EnableErrorTracking bool `json:"enable_error_tracking"`
	// EnableCollisionTracking tracks collision counters (default: true).
	EnableCollisionTracking bool `json:"enable_collision_tracking"`
	// EnableCarrierTracking tracks link state events (default: true).
	EnableCarrierTracking bool `json:"enable_carrier_tracking"`
	// UseGopsutilLibrary uses gopsutil for cross-platform stats (default: true).
	UseGopsutilLibrary bool `json:"use_gopsutil_library"`
	// UseProcNetDev uses /proc/net/dev on Linux (default: false).
	UseProcNetDev bool `json:"use_proc_net_dev"`
	// UseWMI uses WMI on Windows (default: false).
	UseWMI bool `json:"use_wmi"`
}

// DefaultCollectorConfig returns the default statistics collector configuration.
func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		CollectionInterval:      time.Second,
		EnableRateCalculation:   true,
		RateCalculationWindow:   time.Second,
		MaxHistorySamples:       60,
		EnableErrorTracking:     true,
		EnableCollisionTracking: true,
		EnableCarrierTracking:   true,
		UseGopsutilLibrary:      true,
		UseProcNetDev:           false,
		UseWMI:                  false,
	}
}

// =============================================================================
// Enumerator Interface
// =============================================================================

// StatsEnumeratorInterface defines interface discovery operations needed by collector.
type StatsEnumeratorInterface interface {
	// GetAllInterfaceNames returns all interface names.
	GetAllInterfaceNames() []string
	// InterfaceExists checks if an interface exists.
	InterfaceExists(interfaceName string) bool
}

// No-op enumerator implementation.
type noOpStatsEnumerator struct{}

func (n *noOpStatsEnumerator) GetAllInterfaceNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, len(ifaces))
	for i, iface := range ifaces {
		names[i] = iface.Name
	}
	return names
}

func (n *noOpStatsEnumerator) InterfaceExists(interfaceName string) bool {
	_, err := net.InterfaceByName(interfaceName)
	return err == nil
}

// =============================================================================
// Statistics Collector
// =============================================================================

// StatisticsCollector collects network interface statistics.
type StatisticsCollector struct {
	// Dependencies.
	enumerator StatsEnumeratorInterface

	// Configuration.
	config *CollectorConfig

	// State.
	interfaceStats map[string]*InterfaceStatistics
	previousStats  map[string]*InterfaceStatistics
	statsHistory   map[string]*StatisticsHistory
	mu             sync.RWMutex

	// Collection control.
	collectionTicker *time.Ticker
	lastCollection   time.Time

	// Platform.
	platform StatsPlatform

	// Statistics.
	collectionsTotal uint64
	collectionErrors uint64
	linkStateChanges uint64

	// Control.
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewStatisticsCollector creates a new statistics collector.
func NewStatisticsCollector(
	enumerator StatsEnumeratorInterface,
	config *CollectorConfig,
) *StatisticsCollector {
	if config == nil {
		config = DefaultCollectorConfig()
	}

	if enumerator == nil {
		enumerator = &noOpStatsEnumerator{}
	}

	return &StatisticsCollector{
		enumerator:     enumerator,
		config:         config,
		interfaceStats: make(map[string]*InterfaceStatistics),
		previousStats:  make(map[string]*InterfaceStatistics),
		statsHistory:   make(map[string]*StatisticsHistory),
		platform:       DetectStatsPlatform(),
		stopChan:       make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the statistics collector.
func (sc *StatisticsCollector) Start(ctx context.Context) error {
	sc.runningMu.Lock()
	defer sc.runningMu.Unlock()

	if sc.running {
		return nil
	}

	// Validate platform support.
	if sc.platform == StatsPlatformUnknown {
		return ErrStatsPlatformUnsupported
	}

	// Perform initial collection.
	if err := sc.collectAllStatistics(); err != nil {
		// Log but continue - initial collection may fail for some interfaces.
		_ = err
	}

	// Start collection ticker.
	sc.collectionTicker = time.NewTicker(sc.config.CollectionInterval)
	go sc.collectionLoop()

	sc.running = true
	return nil
}

// Stop shuts down the statistics collector.
func (sc *StatisticsCollector) Stop() error {
	sc.runningMu.Lock()
	if !sc.running {
		sc.runningMu.Unlock()
		return nil
	}
	sc.running = false
	sc.runningMu.Unlock()

	if sc.collectionTicker != nil {
		sc.collectionTicker.Stop()
	}
	close(sc.stopChan)

	return nil
}

// collectionLoop is the background collection goroutine.
func (sc *StatisticsCollector) collectionLoop() {
	for {
		select {
		case <-sc.stopChan:
			return
		case <-sc.collectionTicker.C:
			_ = sc.collectAllStatistics()
		}
	}
}

// =============================================================================
// Statistics Collection
// =============================================================================

// collectAllStatistics collects statistics for all interfaces.
func (sc *StatisticsCollector) collectAllStatistics() error {
	interfaces := sc.enumerator.GetAllInterfaceNames()

	var lastErr error
	for _, ifaceName := range interfaces {
		stats, err := sc.collectInterfaceStatistics(ifaceName)
		if err != nil {
			atomic.AddUint64(&sc.collectionErrors, 1)
			lastErr = err
			continue
		}

		sc.mu.Lock()
		// Move current to previous.
		if current, exists := sc.interfaceStats[ifaceName]; exists {
			sc.previousStats[ifaceName] = current
		}
		sc.interfaceStats[ifaceName] = stats

		// Add to history.
		if sc.statsHistory[ifaceName] == nil {
			sc.statsHistory[ifaceName] = NewStatisticsHistory(ifaceName, sc.config.MaxHistorySamples)
		}
		sc.statsHistory[ifaceName].Add(stats)
		sc.mu.Unlock()
	}

	atomic.AddUint64(&sc.collectionsTotal, 1)
	sc.lastCollection = time.Now()

	return lastErr
}

// collectInterfaceStatistics collects statistics for a single interface.
func (sc *StatisticsCollector) collectInterfaceStatistics(interfaceName string) (*InterfaceStatistics, error) {
	var stats *InterfaceStatistics
	var err error

	// Get raw statistics from OS.
	if sc.config.UseGopsutilLibrary {
		stats, err = sc.collectViaGopsutil(interfaceName)
	} else if sc.platform == StatsPlatformLinux && sc.config.UseProcNetDev {
		stats, err = sc.collectViaProcNetDev(interfaceName)
	} else if sc.platform == StatsPlatformWindows && sc.config.UseWMI {
		stats, err = sc.collectViaWMI(interfaceName)
	} else {
		// Default to gopsutil-style collection using net package.
		stats, err = sc.collectViaNetInterface(interfaceName)
	}

	if err != nil {
		return nil, err
	}

	// Calculate rates if enabled.
	if sc.config.EnableRateCalculation {
		sc.mu.RLock()
		previous := sc.previousStats[interfaceName]
		sc.mu.RUnlock()

		if previous != nil {
			sc.calculateRates(stats, previous)
		}
	}

	// Detect link state changes.
	if sc.config.EnableCarrierTracking {
		sc.detectLinkStateChange(interfaceName, stats.LinkState)
	}

	return stats, nil
}

// collectViaGopsutil collects statistics using gopsutil-compatible methods.
func (sc *StatisticsCollector) collectViaGopsutil(interfaceName string) (*InterfaceStatistics, error) {
	// In production, this would use github.com/shirou/gopsutil/v3/net:
	//
	// counters, err := net.IOCounters(true)
	// if err != nil {
	//     return nil, err
	// }
	//
	// for _, counter := range counters {
	//     if counter.Name == interfaceName {
	//         return &InterfaceStatistics{
	//             InterfaceName: interfaceName,
	//             Timestamp:     time.Now(),
	//             RxBytes:       counter.BytesRecv,
	//             TxBytes:       counter.BytesSent,
	//             RxPackets:     counter.PacketsRecv,
	//             TxPackets:     counter.PacketsSent,
	//             RxErrors:      counter.Errin,
	//             TxErrors:      counter.Errout,
	//             RxDrops:       counter.Dropin,
	//             TxDrops:       counter.Dropout,
	//             LinkState:     getLinkState(interfaceName),
	//         }, nil
	//     }
	// }

	// Stub: Use net interface for basic stats.
	return sc.collectViaNetInterface(interfaceName)
}

// collectViaProcNetDev collects statistics from /proc/net/dev (Linux).
func (sc *StatisticsCollector) collectViaProcNetDev(interfaceName string) (*InterfaceStatistics, error) {
	// In production, this would parse /proc/net/dev:
	//
	// content, err := os.ReadFile("/proc/net/dev")
	// if err != nil {
	//     return nil, err
	// }
	//
	// lines := strings.Split(string(content), "\n")
	// for _, line := range lines[2:] { // Skip header lines
	//     line = strings.TrimSpace(line)
	//     if !strings.HasPrefix(line, interfaceName+":") {
	//         continue
	//     }
	//
	//     // Parse: iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets ...
	//     parts := strings.Fields(line)
	//     // parts[0] = "iface:"
	//     // parts[1] = rx_bytes, parts[2] = rx_packets, etc.
	//
	//     return &InterfaceStatistics{
	//         InterfaceName: interfaceName,
	//         Timestamp:     time.Now(),
	//         RxBytes:       parseUint64(parts[1]),
	//         RxPackets:     parseUint64(parts[2]),
	//         RxErrors:      parseUint64(parts[3]),
	//         RxDrops:       parseUint64(parts[4]),
	//         // ... more fields
	//     }, nil
	// }

	// Stub: Use net interface.
	return sc.collectViaNetInterface(interfaceName)
}

// collectViaWMI collects statistics via WMI (Windows).
func (sc *StatisticsCollector) collectViaWMI(interfaceName string) (*InterfaceStatistics, error) {
	// In production, this would use github.com/StackExchange/wmi:
	//
	// type Win32_PerfFormattedData_Tcpip_NetworkInterface struct {
	//     Name                  string
	//     BytesReceivedPerSec   uint64
	//     BytesSentPerSec       uint64
	//     PacketsReceivedPerSec uint64
	//     PacketsSentPerSec     uint64
	//     CurrentBandwidth      uint64
	// }
	//
	// var results []Win32_PerfFormattedData_Tcpip_NetworkInterface
	// query := fmt.Sprintf("SELECT * FROM Win32_PerfFormattedData_Tcpip_NetworkInterface WHERE Name = '%s'", interfaceName)
	// err := wmi.Query(query, &results)
	// if err != nil {
	//     return nil, err
	// }
	//
	// if len(results) > 0 {
	//     return &InterfaceStatistics{
	//         InterfaceName:   interfaceName,
	//         Timestamp:       time.Now(),
	//         RxBytesPerSec:   results[0].BytesReceivedPerSec,
	//         TxBytesPerSec:   results[0].BytesSentPerSec,
	//         // Note: WMI provides rates, not cumulative counters
	//     }, nil
	// }

	// Stub: Use net interface.
	return sc.collectViaNetInterface(interfaceName)
}

// collectViaNetInterface collects basic statistics using Go's net package.
func (sc *StatisticsCollector) collectViaNetInterface(interfaceName string) (*InterfaceStatistics, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStatsInterfaceNotFound, interfaceName)
	}

	// Basic stats from interface.
	stats := &InterfaceStatistics{
		InterfaceName: interfaceName,
		Timestamp:     time.Now(),
		LinkState:     LinkStateUnknown,
	}

	// Determine link state from flags.
	if iface.Flags&net.FlagUp != 0 {
		stats.LinkState = LinkStateUp
	} else {
		stats.LinkState = LinkStateDown
	}

	// Note: Go's net package doesn't provide byte/packet counters directly.
	// In production, we'd use gopsutil or read from /proc/net/dev.
	// For the stub, we simulate with zeros (would be populated by real implementation).

	return stats, nil
}

// =============================================================================
// Rate Calculation
// =============================================================================

// calculateRates calculates per-second rates from cumulative counters.
func (sc *StatisticsCollector) calculateRates(current, previous *InterfaceStatistics) {
	if previous == nil || current.Timestamp.Before(previous.Timestamp) {
		return
	}

	deltaTime := current.Timestamp.Sub(previous.Timestamp).Seconds()
	if deltaTime <= 0 {
		return
	}

	// Calculate byte rates with wrap-around handling.
	current.RxBytesPerSec = sc.calculateDeltaRate(current.RxBytes, previous.RxBytes, deltaTime)
	current.TxBytesPerSec = sc.calculateDeltaRate(current.TxBytes, previous.TxBytes, deltaTime)

	// Calculate packet rates.
	current.RxPacketsPerSec = sc.calculateDeltaRate(current.RxPackets, previous.RxPackets, deltaTime)
	current.TxPacketsPerSec = sc.calculateDeltaRate(current.TxPackets, previous.TxPackets, deltaTime)

	// Calculate error rates.
	rxErrorDelta := sc.calculateDelta(current.RxErrors, previous.RxErrors)
	txErrorDelta := sc.calculateDelta(current.TxErrors, previous.TxErrors)
	current.RxErrorsPerSec = float64(rxErrorDelta) / deltaTime
	current.TxErrorsPerSec = float64(txErrorDelta) / deltaTime
}

// calculateDeltaRate calculates rate from counter delta.
func (sc *StatisticsCollector) calculateDeltaRate(current, previous uint64, seconds float64) uint64 {
	delta := sc.calculateDelta(current, previous)
	return uint64(float64(delta) / seconds)
}

// calculateDelta calculates counter delta with wrap-around handling.
func (sc *StatisticsCollector) calculateDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	// Counter wrapped around.
	return (^uint64(0) - previous) + current + 1
}

// =============================================================================
// Link State Detection
// =============================================================================

// detectLinkStateChange monitors link state transitions.
func (sc *StatisticsCollector) detectLinkStateChange(interfaceName string, currentState LinkState) (bool, LinkState) {
	sc.mu.RLock()
	previous := sc.previousStats[interfaceName]
	sc.mu.RUnlock()

	if previous == nil {
		return false, LinkStateUnknown
	}

	if previous.LinkState != currentState {
		atomic.AddUint64(&sc.linkStateChanges, 1)
		return true, previous.LinkState
	}

	return false, LinkStateUnknown
}

// =============================================================================
// Query Methods
// =============================================================================

// GetInterfaceStatistics retrieves current statistics for specific interface.
func (sc *StatisticsCollector) GetInterfaceStatistics(interfaceName string) (*InterfaceStatistics, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats, exists := sc.interfaceStats[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrStatsInterfaceNotFound, interfaceName)
	}

	// Return copy.
	copy := *stats
	return &copy, nil
}

// GetAllStatistics retrieves statistics for all interfaces.
func (sc *StatisticsCollector) GetAllStatistics() map[string]*InterfaceStatistics {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make(map[string]*InterfaceStatistics, len(sc.interfaceStats))
	for name, stats := range sc.interfaceStats {
		copy := *stats
		result[name] = &copy
	}
	return result
}

// GetStatisticsHistory retrieves historical statistics samples.
func (sc *StatisticsCollector) GetStatisticsHistory(interfaceName string, samples int) ([]*InterfaceStatistics, error) {
	if samples <= 0 || samples > sc.config.MaxHistorySamples {
		return nil, fmt.Errorf("%w: samples must be 1-%d", ErrInvalidTimeRange, sc.config.MaxHistorySamples)
	}

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	history, exists := sc.statsHistory[interfaceName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrStatsInterfaceNotFound, interfaceName)
	}

	return history.GetRecent(samples), nil
}

// =============================================================================
// Throughput Calculation
// =============================================================================

// CalculateThroughput calculates average throughput over time window.
func (sc *StatisticsCollector) CalculateThroughput(interfaceName string, duration time.Duration) (rxThroughput, txThroughput uint64, err error) {
	if duration <= 0 {
		return 0, 0, ErrInvalidTimeRange
	}

	samplesNeeded := int(duration / sc.config.CollectionInterval)
	if samplesNeeded < 1 {
		samplesNeeded = 1
	}
	if samplesNeeded > sc.config.MaxHistorySamples {
		samplesNeeded = sc.config.MaxHistorySamples
	}

	samples, err := sc.GetStatisticsHistory(interfaceName, samplesNeeded)
	if err != nil {
		return 0, 0, err
	}

	if len(samples) < 2 {
		return 0, 0, ErrNoStatisticsAvailable
	}

	// Calculate total bytes over window.
	first := samples[0]
	last := samples[len(samples)-1]

	rxDelta := sc.calculateDelta(last.RxBytes, first.RxBytes)
	txDelta := sc.calculateDelta(last.TxBytes, first.TxBytes)

	timeDelta := last.Timestamp.Sub(first.Timestamp).Seconds()
	if timeDelta <= 0 {
		return 0, 0, ErrInvalidTimeRange
	}

	rxThroughput = uint64(float64(rxDelta) / timeDelta)
	txThroughput = uint64(float64(txDelta) / timeDelta)

	return rxThroughput, txThroughput, nil
}

// CalculatePacketRate calculates average packet rate over time window.
func (sc *StatisticsCollector) CalculatePacketRate(interfaceName string, duration time.Duration) (rxRate, txRate uint64, err error) {
	if duration <= 0 {
		return 0, 0, ErrInvalidTimeRange
	}

	samplesNeeded := int(duration / sc.config.CollectionInterval)
	if samplesNeeded < 1 {
		samplesNeeded = 1
	}
	if samplesNeeded > sc.config.MaxHistorySamples {
		samplesNeeded = sc.config.MaxHistorySamples
	}

	samples, err := sc.GetStatisticsHistory(interfaceName, samplesNeeded)
	if err != nil {
		return 0, 0, err
	}

	if len(samples) < 2 {
		return 0, 0, ErrNoStatisticsAvailable
	}

	first := samples[0]
	last := samples[len(samples)-1]

	rxDelta := sc.calculateDelta(last.RxPackets, first.RxPackets)
	txDelta := sc.calculateDelta(last.TxPackets, first.TxPackets)

	timeDelta := last.Timestamp.Sub(first.Timestamp).Seconds()
	if timeDelta <= 0 {
		return 0, 0, ErrInvalidTimeRange
	}

	rxRate = uint64(float64(rxDelta) / timeDelta)
	txRate = uint64(float64(txDelta) / timeDelta)

	return rxRate, txRate, nil
}

// CalculateErrorRate calculates average error rate over time window.
func (sc *StatisticsCollector) CalculateErrorRate(interfaceName string, duration time.Duration) (rxErrorRate, txErrorRate float64, err error) {
	if duration <= 0 {
		return 0, 0, ErrInvalidTimeRange
	}

	samplesNeeded := int(duration / sc.config.CollectionInterval)
	if samplesNeeded < 1 {
		samplesNeeded = 1
	}
	if samplesNeeded > sc.config.MaxHistorySamples {
		samplesNeeded = sc.config.MaxHistorySamples
	}

	samples, err := sc.GetStatisticsHistory(interfaceName, samplesNeeded)
	if err != nil {
		return 0, 0, err
	}

	if len(samples) < 2 {
		return 0, 0, ErrNoStatisticsAvailable
	}

	first := samples[0]
	last := samples[len(samples)-1]

	rxErrorDelta := sc.calculateDelta(last.RxErrors, first.RxErrors)
	txErrorDelta := sc.calculateDelta(last.TxErrors, first.TxErrors)
	rxPacketDelta := sc.calculateDelta(last.RxPackets, first.RxPackets)
	txPacketDelta := sc.calculateDelta(last.TxPackets, first.TxPackets)

	if rxPacketDelta > 0 {
		rxErrorRate = (float64(rxErrorDelta) / float64(rxPacketDelta)) * 100
	}
	if txPacketDelta > 0 {
		txErrorRate = (float64(txErrorDelta) / float64(txPacketDelta)) * 100
	}

	return rxErrorRate, txErrorRate, nil
}

// =============================================================================
// Statistics Management
// =============================================================================

// ResetStatistics clears statistics for interface.
func (sc *StatisticsCollector) ResetStatistics(interfaceName string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	delete(sc.interfaceStats, interfaceName)
	delete(sc.previousStats, interfaceName)
	delete(sc.statsHistory, interfaceName)

	return nil
}

// ResetAllStatistics clears all statistics.
func (sc *StatisticsCollector) ResetAllStatistics() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.interfaceStats = make(map[string]*InterfaceStatistics)
	sc.previousStats = make(map[string]*InterfaceStatistics)
	sc.statsHistory = make(map[string]*StatisticsHistory)
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the collector is operational.
func (sc *StatisticsCollector) HealthCheck() error {
	if sc.platform == StatsPlatformUnknown {
		return ErrStatsPlatformUnsupported
	}

	sc.runningMu.Lock()
	running := sc.running
	sc.runningMu.Unlock()

	if !running {
		return errors.New("statistics collector not running")
	}

	// Check last collection was recent.
	if time.Since(sc.lastCollection) > sc.config.CollectionInterval*2 {
		return errors.New("statistics collection stalled")
	}

	// Check we have stats for at least one interface.
	sc.mu.RLock()
	hasStats := len(sc.interfaceStats) > 0
	sc.mu.RUnlock()

	if !hasStats {
		return ErrNoStatisticsAvailable
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetCollectorStatistics returns collector operation statistics.
func (sc *StatisticsCollector) GetCollectorStatistics() map[string]uint64 {
	return map[string]uint64{
		"collections_total":  atomic.LoadUint64(&sc.collectionsTotal),
		"collection_errors":  atomic.LoadUint64(&sc.collectionErrors),
		"link_state_changes": atomic.LoadUint64(&sc.linkStateChanges),
	}
}

// GetConfig returns the current configuration.
func (sc *StatisticsCollector) GetConfig() *CollectorConfig {
	return sc.config
}

// GetPlatform returns the detected platform.
func (sc *StatisticsCollector) GetPlatform() StatsPlatform {
	return sc.platform
}

// GetLastCollectionTime returns the timestamp of the last collection.
func (sc *StatisticsCollector) GetLastCollectionTime() time.Time {
	return sc.lastCollection
}

// GetInterfaceCount returns the number of monitored interfaces.
func (sc *StatisticsCollector) GetInterfaceCount() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.interfaceStats)
}
