// Package monitoring provides monitoring and alerting for DHCP server.
// This file implements pool utilization tracking and metrics.
package monitoring

import (
	"context"
	"sync"
	"time"
)

// ============================================================================
// Pool Utilization Configuration
// ============================================================================

// PoolUtilizationConfig holds utilization tracking settings.
type PoolUtilizationConfig struct {
	UpdateInterval    time.Duration
	HistorySize       int
	WarningThreshold  float64
	CriticalThreshold float64
	HysteresisPercent float64
}

// DefaultPoolUtilizationConfig returns sensible defaults.
func DefaultPoolUtilizationConfig() *PoolUtilizationConfig {
	return &PoolUtilizationConfig{
		UpdateInterval:    60 * time.Second,
		HistorySize:       1440, // 24 hours at 1-minute intervals
		WarningThreshold:  80.0,
		CriticalThreshold: 90.0,
		HysteresisPercent: 5.0,
	}
}

// ============================================================================
// Pool Statistics
// ============================================================================

// PoolStats contains utilization statistics for a single pool.
type PoolStats struct {
	PoolName       string
	TotalIPs       int
	UsableIPs      int
	AllocatedIPs   int
	AvailableIPs   int
	ReservedIPs    int
	ExcludedIPs    int
	UtilizationPct float64
	LastUpdated    time.Time
}

// PoolHistoryEntry contains a historical utilization sample.
type PoolHistoryEntry struct {
	Timestamp      time.Time
	UtilizationPct float64
	AllocatedIPs   int
}

// ============================================================================
// Aggregate Statistics
// ============================================================================

// AggregateStats contains aggregate utilization across all pools.
type AggregateStats struct {
	TotalPools        int
	TotalCapacity     int
	TotalAllocated    int
	GlobalUtilization float64
	PoolsAtWarning    int
	PoolsAtCritical   int
	PoolsExhausted    int
	Pools             []PoolStats
}

// ============================================================================
// Pool Data Provider Interface
// ============================================================================

// PoolDataProvider provides pool data for utilization calculation.
type PoolDataProvider interface {
	GetPoolConfig(poolName string) (*PoolConfig, error)
	GetAllPoolNames() []string
	GetActiveLeaseCount(poolName string) (int, error)
	GetReservationCount(poolName string) (int, error)
}

// PoolConfig contains pool configuration for utilization calculation.
type PoolConfig struct {
	Name        string
	RangeStart  uint32
	RangeEnd    uint32
	ExcludedIPs []uint32
}

// ============================================================================
// Pool Utilization Monitor
// ============================================================================

// PoolUtilizationMonitor monitors pool utilization.
type PoolUtilizationMonitor struct {
	mu     sync.RWMutex
	config *PoolUtilizationConfig

	// Data providers
	poolProvider PoolDataProvider
	alertManager *AlertManager

	// Current statistics
	poolStats map[string]*PoolStats

	// Historical data
	history map[string][]PoolHistoryEntry

	// Alert state for hysteresis
	alertActive map[string]bool

	// Lifecycle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewPoolUtilizationMonitor creates a new pool utilization monitor.
func NewPoolUtilizationMonitor(config *PoolUtilizationConfig) *PoolUtilizationMonitor {
	if config == nil {
		config = DefaultPoolUtilizationConfig()
	}

	return &PoolUtilizationMonitor{
		config:      config,
		poolStats:   make(map[string]*PoolStats),
		history:     make(map[string][]PoolHistoryEntry),
		alertActive: make(map[string]bool),
		stopChan:    make(chan struct{}),
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetPoolProvider sets the pool data provider.
func (m *PoolUtilizationMonitor) SetPoolProvider(provider PoolDataProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.poolProvider = provider
}

// SetAlertManager sets the alert manager.
func (m *PoolUtilizationMonitor) SetAlertManager(alertManager *AlertManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertManager = alertManager
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the utilization monitor.
func (m *PoolUtilizationMonitor) Start(ctx context.Context) error {
	m.stopChan = make(chan struct{})

	// Initial calculation
	m.UpdateAllPools(ctx)

	// Start background monitoring
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	return nil
}

// Stop stops the utilization monitor.
func (m *PoolUtilizationMonitor) Stop() error {
	close(m.stopChan)
	m.wg.Wait()
	return nil
}

func (m *PoolUtilizationMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.UpdateAllPools(ctx)
		}
	}
}

// ============================================================================
// Utilization Calculation
// ============================================================================

// UpdateAllPools updates utilization for all pools.
func (m *PoolUtilizationMonitor) UpdateAllPools(ctx context.Context) {
	m.mu.RLock()
	provider := m.poolProvider
	m.mu.RUnlock()

	if provider == nil {
		return
	}

	poolNames := provider.GetAllPoolNames()
	for _, poolName := range poolNames {
		m.updatePoolUtilization(ctx, poolName)
	}
}

// UpdatePool updates utilization for a specific pool.
func (m *PoolUtilizationMonitor) UpdatePool(ctx context.Context, poolName string) {
	m.updatePoolUtilization(ctx, poolName)
}

func (m *PoolUtilizationMonitor) updatePoolUtilization(ctx context.Context, poolName string) {
	m.mu.RLock()
	provider := m.poolProvider
	alertMgr := m.alertManager
	m.mu.RUnlock()

	if provider == nil {
		return
	}

	// Get pool configuration
	poolConfig, err := provider.GetPoolConfig(poolName)
	if err != nil {
		return
	}

	// Calculate total IPs in range
	totalIPs := int(poolConfig.RangeEnd - poolConfig.RangeStart + 1)

	// Get excluded IPs count
	excludedIPs := len(poolConfig.ExcludedIPs)

	// Get reservation count
	reservedIPs, err := provider.GetReservationCount(poolName)
	if err != nil {
		reservedIPs = 0
	}

	// Calculate usable IPs
	usableIPs := totalIPs - excludedIPs - reservedIPs
	if usableIPs < 0 {
		usableIPs = 0
	}

	// Get allocated lease count
	allocatedIPs, err := provider.GetActiveLeaseCount(poolName)
	if err != nil {
		allocatedIPs = 0
	}

	// Calculate available IPs
	availableIPs := usableIPs - allocatedIPs
	if availableIPs < 0 {
		availableIPs = 0
	}

	// Calculate utilization percentage
	var utilizationPct float64
	if usableIPs > 0 {
		utilizationPct = float64(allocatedIPs) / float64(usableIPs) * 100
	} else {
		utilizationPct = 100.0 // No usable IPs = fully utilized
	}

	// Create stats
	stats := &PoolStats{
		PoolName:       poolName,
		TotalIPs:       totalIPs,
		UsableIPs:      usableIPs,
		AllocatedIPs:   allocatedIPs,
		AvailableIPs:   availableIPs,
		ReservedIPs:    reservedIPs,
		ExcludedIPs:    excludedIPs,
		UtilizationPct: utilizationPct,
		LastUpdated:    time.Now(),
	}

	// Store stats
	m.mu.Lock()
	m.poolStats[poolName] = stats

	// Add to history
	m.addHistoryEntry(poolName, stats)

	// Check thresholds
	wasActive := m.alertActive[poolName]
	m.mu.Unlock()

	// Trigger alerts
	m.checkThresholds(ctx, poolName, stats, wasActive, alertMgr)
}

func (m *PoolUtilizationMonitor) addHistoryEntry(poolName string, stats *PoolStats) {
	entry := PoolHistoryEntry{
		Timestamp:      time.Now(),
		UtilizationPct: stats.UtilizationPct,
		AllocatedIPs:   stats.AllocatedIPs,
	}

	history := m.history[poolName]
	history = append(history, entry)

	// Trim to max size
	if len(history) > m.config.HistorySize {
		history = history[1:]
	}

	m.history[poolName] = history
}

// ============================================================================
// Threshold Checking
// ============================================================================

func (m *PoolUtilizationMonitor) checkThresholds(ctx context.Context, poolName string, stats *PoolStats, wasActive bool, alertMgr *AlertManager) {
	if alertMgr == nil {
		return
	}

	// Check thresholds with hysteresis
	hysteresis := m.config.HysteresisPercent

	if stats.UtilizationPct >= 100 {
		// Pool exhausted - CRITICAL
		alertMgr.CheckPoolUtilization(ctx, poolName, stats.AllocatedIPs, stats.UsableIPs)
		m.setAlertActive(poolName, true)
	} else if stats.UtilizationPct >= m.config.CriticalThreshold {
		// Above critical threshold
		alertMgr.CheckPoolUtilization(ctx, poolName, stats.AllocatedIPs, stats.UsableIPs)
		m.setAlertActive(poolName, true)
	} else if stats.UtilizationPct >= m.config.WarningThreshold {
		// Above warning threshold
		alertMgr.CheckPoolUtilization(ctx, poolName, stats.AllocatedIPs, stats.UsableIPs)
		m.setAlertActive(poolName, true)
	} else if wasActive && stats.UtilizationPct < (m.config.WarningThreshold-hysteresis) {
		// Below threshold with hysteresis - resolve alert
		alertMgr.CheckPoolUtilization(ctx, poolName, stats.AllocatedIPs, stats.UsableIPs)
		m.setAlertActive(poolName, false)
	}
}

func (m *PoolUtilizationMonitor) setAlertActive(poolName string, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertActive[poolName] = active
}

// ============================================================================
// Statistics Retrieval
// ============================================================================

// GetPoolStats returns current stats for a specific pool.
func (m *PoolUtilizationMonitor) GetPoolStats(poolName string) *PoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if stats, ok := m.poolStats[poolName]; ok {
		return stats
	}
	return nil
}

// GetAllPoolStats returns current stats for all pools.
func (m *PoolUtilizationMonitor) GetAllPoolStats() []*PoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]*PoolStats, 0, len(m.poolStats))
	for _, s := range m.poolStats {
		stats = append(stats, s)
	}
	return stats
}

// GetAggregateStats returns aggregate statistics across all pools.
func (m *PoolUtilizationMonitor) GetAggregateStats() *AggregateStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agg := &AggregateStats{
		TotalPools: len(m.poolStats),
		Pools:      make([]PoolStats, 0, len(m.poolStats)),
	}

	for _, stats := range m.poolStats {
		agg.TotalCapacity += stats.UsableIPs
		agg.TotalAllocated += stats.AllocatedIPs
		agg.Pools = append(agg.Pools, *stats)

		if stats.UtilizationPct >= 100 {
			agg.PoolsExhausted++
		} else if stats.UtilizationPct >= m.config.CriticalThreshold {
			agg.PoolsAtCritical++
		} else if stats.UtilizationPct >= m.config.WarningThreshold {
			agg.PoolsAtWarning++
		}
	}

	if agg.TotalCapacity > 0 {
		agg.GlobalUtilization = float64(agg.TotalAllocated) / float64(agg.TotalCapacity) * 100
	}

	return agg
}

// ============================================================================
// Historical Data Access
// ============================================================================

// GetPoolHistory returns utilization history for a pool.
func (m *PoolUtilizationMonitor) GetPoolHistory(poolName string, duration time.Duration) []PoolHistoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	history, ok := m.history[poolName]
	if !ok {
		return nil
	}

	cutoff := time.Now().Add(-duration)
	result := make([]PoolHistoryEntry, 0)

	for _, entry := range history {
		if entry.Timestamp.After(cutoff) {
			result = append(result, entry)
		}
	}

	return result
}

// GetAverageUtilization calculates average utilization over a duration.
func (m *PoolUtilizationMonitor) GetAverageUtilization(poolName string, duration time.Duration) float64 {
	history := m.GetPoolHistory(poolName, duration)
	if len(history) == 0 {
		return 0
	}

	var sum float64
	for _, entry := range history {
		sum += entry.UtilizationPct
	}

	return sum / float64(len(history))
}

// GetPeakUtilization returns peak utilization over a duration.
func (m *PoolUtilizationMonitor) GetPeakUtilization(poolName string, duration time.Duration) float64 {
	history := m.GetPoolHistory(poolName, duration)
	if len(history) == 0 {
		return 0
	}

	var peak float64
	for _, entry := range history {
		if entry.UtilizationPct > peak {
			peak = entry.UtilizationPct
		}
	}

	return peak
}

// ============================================================================
// Capacity Forecasting
// ============================================================================

// CapacityForecast contains capacity projection data.
type CapacityForecast struct {
	PoolName           string
	CurrentUtilization float64
	GrowthRatePerDay   float64
	DaysToExhaustion   float64
	ProjectedDate      time.Time
}

// GetCapacityForecast projects when a pool will reach exhaustion.
func (m *PoolUtilizationMonitor) GetCapacityForecast(poolName string) *CapacityForecast {
	m.mu.RLock()
	stats := m.poolStats[poolName]
	history := m.history[poolName]
	m.mu.RUnlock()

	if stats == nil || len(history) < 2 {
		return nil
	}

	forecast := &CapacityForecast{
		PoolName:           poolName,
		CurrentUtilization: stats.UtilizationPct,
	}

	// Calculate growth rate from history
	if len(history) >= 2 {
		oldest := history[0]
		newest := history[len(history)-1]

		timeDiff := newest.Timestamp.Sub(oldest.Timestamp).Hours() / 24 // days
		utilizationDiff := newest.UtilizationPct - oldest.UtilizationPct

		if timeDiff > 0 {
			forecast.GrowthRatePerDay = utilizationDiff / timeDiff
		}
	}

	// Project days to exhaustion
	if forecast.GrowthRatePerDay > 0 {
		remainingPct := 100.0 - stats.UtilizationPct
		forecast.DaysToExhaustion = remainingPct / forecast.GrowthRatePerDay
		forecast.ProjectedDate = time.Now().AddDate(0, 0, int(forecast.DaysToExhaustion))
	} else {
		forecast.DaysToExhaustion = -1 // Not growing
	}

	return forecast
}

// ============================================================================
// Pool Utilization Map Interface (for PoolManagerComponent)
// ============================================================================

// GetPoolUtilization returns utilization map for all pools.
func (m *PoolUtilizationMonitor) GetPoolUtilization() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]float64)
	for name, stats := range m.poolStats {
		result[name] = stats.UtilizationPct
	}
	return result
}
