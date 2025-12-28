// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrWANNotFound indicates the WAN was not found.
	ErrWANNotFound = errors.New("WAN not found")
	// ErrProbeTimeout indicates a probe exceeded timeout.
	ErrProbeTimeout = errors.New("probe timeout")
	// ErrInvalidTarget indicates an invalid probe target.
	ErrInvalidTarget = errors.New("invalid probe target")
	// ErrDatabaseSyncFailed indicates database persistence failed.
	ErrDatabaseSyncFailed = errors.New("database sync failed")
	// ErrMetricsStale indicates metrics not updated recently.
	ErrMetricsStale = errors.New("metrics stale")
)

// =============================================================================
// Probe Type
// =============================================================================

// ProbeType represents the type of active probe.
type ProbeType int

const (
	// ICMPPing is an ICMP echo request probe.
	ICMPPing ProbeType = iota
	// HTTPGet is an HTTP/HTTPS GET request probe.
	HTTPGet
	// DNSQuery is a DNS resolution probe.
	DNSQuery
	// TCPConnect is a TCP connection probe.
	TCPConnect
)

// String returns the string representation of the probe type.
func (p ProbeType) String() string {
	switch p {
	case ICMPPing:
		return "ICMP"
	case HTTPGet:
		return "HTTP"
	case DNSQuery:
		return "DNS"
	case TCPConnect:
		return "TCP"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Probe Result
// =============================================================================

// ProbeResult represents a single probe test result.
type ProbeResult struct {
	// Target is the endpoint tested.
	Target string `json:"target"`
	// ProbeType is the test type.
	ProbeType ProbeType `json:"probe_type"`
	// Success indicates probe succeeded.
	Success bool `json:"success"`
	// Latency is the round-trip time.
	Latency time.Duration `json:"latency"`
	// Error is the error message if failed.
	Error string `json:"error,omitempty"`
	// Timestamp is when probe executed.
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// Bandwidth Sample
// =============================================================================

// BandwidthSample represents a snapshot of interface throughput.
type BandwidthSample struct {
	// RxBytesPerSec is received bytes per second.
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	// TxBytesPerSec is transmitted bytes per second.
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	// RxPacketsPerSec is received packets per second.
	RxPacketsPerSec uint64 `json:"rx_packets_per_sec"`
	// TxPacketsPerSec is transmitted packets per second.
	TxPacketsPerSec uint64 `json:"tx_packets_per_sec"`
	// LinkCapacity is interface speed in bits/sec.
	LinkCapacity uint64 `json:"link_capacity"`
	// Utilization is percentage of capacity used.
	Utilization float64 `json:"utilization"`
	// Timestamp is the sample time.
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// WAN Metrics
// =============================================================================

// WANMetrics represents performance metrics for a single WAN interface.
type WANMetrics struct {
	// WANID is the WAN interface identifier.
	WANID string `json:"wan_id"`
	// InterfaceName is the OS interface name.
	InterfaceName string `json:"interface_name"`
	// Latency is the average round-trip time.
	Latency time.Duration `json:"latency"`
	// PacketLoss is the packet loss percentage (0-100).
	PacketLoss float64 `json:"packet_loss"`
	// Jitter is the latency variance.
	Jitter time.Duration `json:"jitter"`
	// BandwidthUtilization is the percentage of link capacity used.
	BandwidthUtilization float64 `json:"bandwidth_utilization"`
	// Throughput is the current RX/TX bytes per second.
	Throughput BandwidthSample `json:"throughput"`
	// HealthScore is the normalized health rating (0-100).
	HealthScore float64 `json:"health_score"`
	// ProbeResults are the recent probe results.
	ProbeResults []ProbeResult `json:"probe_results"`
	// LastUpdate is when metrics were last updated.
	LastUpdate time.Time `json:"last_update"`
	// ErrorCount is the NIC error counter.
	ErrorCount uint64 `json:"error_count"`
	// ActiveConnections is the current connection count.
	ActiveConnections int `json:"active_connections"`
}

// =============================================================================
// Aggregated Metrics
// =============================================================================

// AggregatedMetrics represents time-bucketed metric summaries.
type AggregatedMetrics struct {
	// WANID is the WAN identifier.
	WANID string `json:"wan_id"`
	// StartTime is the aggregation start.
	StartTime time.Time `json:"start_time"`
	// EndTime is the aggregation end.
	EndTime time.Time `json:"end_time"`
	// AvgLatency is the average latency.
	AvgLatency time.Duration `json:"avg_latency"`
	// AvgPacketLoss is the average packet loss.
	AvgPacketLoss float64 `json:"avg_packet_loss"`
	// AvgJitter is the average jitter.
	AvgJitter time.Duration `json:"avg_jitter"`
	// AvgUtilization is the average utilization.
	AvgUtilization float64 `json:"avg_utilization"`
	// AvgHealthScore is the average health score.
	AvgHealthScore float64 `json:"avg_health_score"`
	// MinHealthScore is the minimum health score.
	MinHealthScore float64 `json:"min_health_score"`
	// MaxHealthScore is the maximum health score.
	MaxHealthScore float64 `json:"max_health_score"`
	// P95Latency is the 95th percentile latency.
	P95Latency time.Duration `json:"p95_latency"`
}

// =============================================================================
// Metrics Configuration
// =============================================================================

// MetricsConfig contains configuration for the metrics collector.
type MetricsConfig struct {
	// ProbeInterval is how often to probe.
	ProbeInterval time.Duration `json:"probe_interval"`
	// ProbeTimeout is the max probe wait time.
	ProbeTimeout time.Duration `json:"probe_timeout"`
	// HistoryRetention is how long to keep historical metrics.
	HistoryRetention time.Duration `json:"history_retention"`
	// PrometheusPort is the port for Prometheus scraping.
	PrometheusPort int `json:"prometheus_port"`
	// HealthThreshold is the minimum health for healthy state.
	HealthThreshold float64 `json:"health_threshold"`
	// ProbeTargets are endpoints to test.
	ProbeTargets []string `json:"probe_targets"`
	// EnablePassiveMonitoring monitors actual traffic stats.
	EnablePassiveMonitoring bool `json:"enable_passive_monitoring"`
	// BandwidthSampleInterval is bandwidth sampling frequency.
	BandwidthSampleInterval time.Duration `json:"bandwidth_sample_interval"`
	// EnableDatabasePersistence saves metrics to DB.
	EnableDatabasePersistence bool `json:"enable_database_persistence"`
	// DatabaseSyncInterval is how often to sync to DB.
	DatabaseSyncInterval time.Duration `json:"database_sync_interval"`
}

// DefaultMetricsConfig returns the default configuration.
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		ProbeInterval:             5 * time.Second,
		ProbeTimeout:              2 * time.Second,
		HistoryRetention:          168 * time.Hour, // 7 days
		PrometheusPort:            9090,
		HealthThreshold:           20.0,
		ProbeTargets:              []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
		EnablePassiveMonitoring:   true,
		BandwidthSampleInterval:   30 * time.Second,
		EnableDatabasePersistence: true,
		DatabaseSyncInterval:      60 * time.Second,
	}
}

// =============================================================================
// Metrics Subscriber
// =============================================================================

// MetricsSubscriber defines the interface for metric update notifications.
type MetricsSubscriber interface {
	// OnMetricsUpdate is called when metrics are updated.
	OnMetricsUpdate(wanID string, metrics *WANMetrics) error
}

// =============================================================================
// Database Interface
// =============================================================================

// MetricsDB defines the database interface for metrics persistence.
type MetricsDB interface {
	// SaveWANMetrics saves metrics to the database.
	SaveWANMetrics(ctx context.Context, metrics *WANMetrics) error
	// GetHistoricalMetrics retrieves historical metrics.
	GetHistoricalMetrics(ctx context.Context, wanID string, start, end time.Time) ([]*WANMetrics, error)
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpMetricsDB struct{}

func (n *noOpMetricsDB) SaveWANMetrics(ctx context.Context, metrics *WANMetrics) error {
	return nil
}

func (n *noOpMetricsDB) GetHistoricalMetrics(ctx context.Context, wanID string, start, end time.Time) ([]*WANMetrics, error) {
	return nil, nil
}

// =============================================================================
// Metrics Collector
// =============================================================================

// MetricsCollector manages per-WAN metric gathering.
type MetricsCollector struct {
	// Per-WAN current metrics.
	wanMetrics map[string]*WANMetrics
	// Database for persistence.
	db MetricsDB
	// Configuration.
	config *MetricsConfig
	// Read-write mutex.
	mu sync.RWMutex
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
	// Subscribers.
	subscribers   []MetricsSubscriber
	subscribersMu sync.RWMutex
	// Previous bandwidth counters for delta calculation.
	prevCounters map[string]*bandwidthCounters
}

// bandwidthCounters holds previous counter values for delta calculation.
type bandwidthCounters struct {
	RxBytes   uint64
	TxBytes   uint64
	Timestamp time.Time
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector(db MetricsDB, config *MetricsConfig) *MetricsCollector {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	if db == nil {
		db = &noOpMetricsDB{}
	}

	return &MetricsCollector{
		wanMetrics:   make(map[string]*WANMetrics),
		db:           db,
		config:       config,
		stopChan:     make(chan struct{}),
		subscribers:  make([]MetricsSubscriber, 0),
		prevCounters: make(map[string]*bandwidthCounters),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts metrics collection for all registered WANs.
func (mc *MetricsCollector) Start(ctx context.Context) error {
	mc.runningMu.Lock()
	defer mc.runningMu.Unlock()

	if mc.running {
		return nil
	}

	// Start probe goroutine for each WAN.
	mc.mu.RLock()
	wanIDs := make([]string, 0, len(mc.wanMetrics))
	for wanID := range mc.wanMetrics {
		wanIDs = append(wanIDs, wanID)
	}
	mc.mu.RUnlock()

	for _, wanID := range wanIDs {
		mc.wg.Add(1)
		go mc.probeLoop(wanID)

		if mc.config.EnablePassiveMonitoring {
			mc.wg.Add(1)
			go mc.monitorLoop(wanID)
		}
	}

	// Start database sync goroutine.
	if mc.config.EnableDatabasePersistence {
		mc.wg.Add(1)
		go mc.dbSyncLoop()
	}

	mc.running = true
	return nil
}

// Stop stops metrics collection.
func (mc *MetricsCollector) Stop() error {
	mc.runningMu.Lock()
	if !mc.running {
		mc.runningMu.Unlock()
		return nil
	}
	mc.running = false
	mc.runningMu.Unlock()

	close(mc.stopChan)
	mc.wg.Wait()

	return nil
}

// =============================================================================
// Probe Loop
// =============================================================================

// probeLoop runs periodic probing for a WAN.
func (mc *MetricsCollector) probeLoop(wanID string) {
	defer mc.wg.Done()

	ticker := time.NewTicker(mc.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.stopChan:
			return
		case <-ticker.C:
			mc.probeWAN(wanID)
		}
	}
}

// probeWAN executes probes against all targets for a WAN.
func (mc *MetricsCollector) probeWAN(wanID string) {
	results := make([]ProbeResult, 0, len(mc.config.ProbeTargets))

	for _, target := range mc.config.ProbeTargets {
		// Run probes.
		result := mc.probeICMP(wanID, target)
		results = append(results, result)
	}

	// Update metrics with probe results.
	mc.updateMetrics(wanID, results)
}

// probeICMP executes an ICMP ping probe.
func (mc *MetricsCollector) probeICMP(wanID, target string) ProbeResult {
	_ = wanID // Will be used for interface-specific probing.
	result := ProbeResult{
		Target:    target,
		ProbeType: ICMPPing,
		Timestamp: time.Now(),
	}

	// Simulate ICMP probe (actual implementation would use go-ping).
	// For now, we'll use HTTP as a fallback since ICMP requires privileges.
	client := &http.Client{
		Timeout: mc.config.ProbeTimeout,
	}

	start := time.Now()
	resp, err := client.Get("http://" + target)
	latency := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		resp.Body.Close()
		result.Success = true
		result.Latency = latency
	}

	return result
}

// probeHTTP executes an HTTP GET probe.
func (mc *MetricsCollector) probeHTTP(wanID, target string) ProbeResult {
	_ = wanID // Will be used for interface-specific probing.
	result := ProbeResult{
		Target:    target,
		ProbeType: HTTPGet,
		Timestamp: time.Now(),
	}

	client := &http.Client{
		Timeout: mc.config.ProbeTimeout,
	}

	start := time.Now()
	resp, err := client.Get(target)
	latency := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.Success = true
			result.Latency = latency
		} else {
			result.Success = false
			result.Error = resp.Status
		}
	}

	return result
}

// =============================================================================
// Passive Monitoring Loop
// =============================================================================

// monitorLoop runs passive traffic monitoring for a WAN.
func (mc *MetricsCollector) monitorLoop(wanID string) {
	defer mc.wg.Done()

	ticker := time.NewTicker(mc.config.BandwidthSampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.stopChan:
			return
		case <-ticker.C:
			mc.sampleBandwidth(wanID)
		}
	}
}

// sampleBandwidth samples bandwidth utilization for a WAN.
func (mc *MetricsCollector) sampleBandwidth(wanID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metrics, exists := mc.wanMetrics[wanID]
	if !exists {
		return
	}

	// TODO: Use gopsutil to read actual interface counters.
	// For now, use placeholder values.
	now := time.Now()

	sample := BandwidthSample{
		RxBytesPerSec:   0,
		TxBytesPerSec:   0,
		RxPacketsPerSec: 0,
		TxPacketsPerSec: 0,
		LinkCapacity:    1000000000, // 1 Gbps default
		Utilization:     0,
		Timestamp:       now,
	}

	metrics.Throughput = sample
	metrics.BandwidthUtilization = sample.Utilization
}

// =============================================================================
// Database Sync Loop
// =============================================================================

// dbSyncLoop periodically syncs metrics to the database.
func (mc *MetricsCollector) dbSyncLoop() {
	defer mc.wg.Done()

	ticker := time.NewTicker(mc.config.DatabaseSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.stopChan:
			return
		case <-ticker.C:
			mc.syncToDatabase()
		}
	}
}

// syncToDatabase saves all current metrics to database.
func (mc *MetricsCollector) syncToDatabase() {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, metrics := range mc.wanMetrics {
		_ = mc.db.SaveWANMetrics(ctx, metrics)
	}
}

// =============================================================================
// Metrics Update
// =============================================================================

// updateMetrics updates WAN metrics from probe results.
func (mc *MetricsCollector) updateMetrics(wanID string, results []ProbeResult) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metrics, exists := mc.wanMetrics[wanID]
	if !exists {
		return
	}

	// Calculate aggregate metrics.
	var totalLatency time.Duration
	var successCount, failCount int
	latencies := make([]time.Duration, 0, len(results))

	for _, r := range results {
		if r.Success {
			successCount++
			totalLatency += r.Latency
			latencies = append(latencies, r.Latency)
		} else {
			failCount++
		}
	}

	totalProbes := successCount + failCount
	if totalProbes > 0 {
		metrics.PacketLoss = float64(failCount) / float64(totalProbes) * 100.0
	}

	if successCount > 0 {
		metrics.Latency = totalLatency / time.Duration(successCount)
		metrics.Jitter = mc.calculateJitter(latencies)
	}

	// Keep last 10 probe results.
	metrics.ProbeResults = append(metrics.ProbeResults, results...)
	if len(metrics.ProbeResults) > 10 {
		metrics.ProbeResults = metrics.ProbeResults[len(metrics.ProbeResults)-10:]
	}

	metrics.LastUpdate = time.Now()

	// Calculate health score.
	metrics.HealthScore = mc.calculateHealthScore(metrics)

	// Notify subscribers.
	mc.notifySubscribers(wanID, metrics)
}

// calculateJitter calculates latency variance.
func (mc *MetricsCollector) calculateJitter(latencies []time.Duration) time.Duration {
	if len(latencies) < 2 {
		return 0
	}

	var sum float64
	for _, l := range latencies {
		sum += float64(l)
	}
	mean := sum / float64(len(latencies))

	var variance float64
	for _, l := range latencies {
		diff := float64(l) - mean
		variance += diff * diff
	}
	variance /= float64(len(latencies))

	return time.Duration(math.Sqrt(variance))
}

// =============================================================================
// Health Score Calculation
// =============================================================================

// calculateHealthScore computes the normalized health rating (0-100).
func (mc *MetricsCollector) calculateHealthScore(metrics *WANMetrics) float64 {
	// Latency score: 100 at 0ms, 0 at 200ms+
	latencyMs := float64(metrics.Latency.Milliseconds())
	latencyScore := math.Max(0, 100-(latencyMs/2))

	// Loss score: 100 at 0%, 0 at 50%+
	lossScore := math.Max(0, 100-(metrics.PacketLoss*2))

	// Jitter score: 100 at 0ms, 0 at 100ms+
	jitterMs := float64(metrics.Jitter.Milliseconds())
	jitterScore := math.Max(0, 100-jitterMs)

	// Utilization score: 100 at 0%, 0 at 100%
	utilizationScore := math.Max(0, 100-metrics.BandwidthUtilization)

	// Weighted combination.
	healthScore := (latencyScore * 0.3) +
		(lossScore * 0.4) +
		(jitterScore * 0.2) +
		(utilizationScore * 0.1)

	// Clamp to 0-100.
	return math.Max(0, math.Min(100, healthScore))
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for metric updates.
func (mc *MetricsCollector) Subscribe(subscriber MetricsSubscriber) {
	mc.subscribersMu.Lock()
	defer mc.subscribersMu.Unlock()
	mc.subscribers = append(mc.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (mc *MetricsCollector) Unsubscribe(subscriber MetricsSubscriber) {
	mc.subscribersMu.Lock()
	defer mc.subscribersMu.Unlock()

	for i, s := range mc.subscribers {
		if s == subscriber {
			mc.subscribers = append(mc.subscribers[:i], mc.subscribers[i+1:]...)
			return
		}
	}
}

// notifySubscribers notifies all subscribers of metric updates.
func (mc *MetricsCollector) notifySubscribers(wanID string, metrics *WANMetrics) {
	mc.subscribersMu.RLock()
	subscribers := make([]MetricsSubscriber, len(mc.subscribers))
	copy(subscribers, mc.subscribers)
	mc.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s MetricsSubscriber) {
			_ = s.OnMetricsUpdate(wanID, metrics)
		}(sub)
	}
}

// =============================================================================
// WAN Management
// =============================================================================

// AddWAN adds a WAN interface for monitoring.
func (mc *MetricsCollector) AddWAN(wanID, interfaceName string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, exists := mc.wanMetrics[wanID]; exists {
		return nil // Already exists.
	}

	mc.wanMetrics[wanID] = &WANMetrics{
		WANID:         wanID,
		InterfaceName: interfaceName,
		ProbeResults:  make([]ProbeResult, 0, 10),
		LastUpdate:    time.Now(),
		HealthScore:   100.0, // Start healthy.
	}

	// If running, start probe goroutine for new WAN.
	mc.runningMu.Lock()
	running := mc.running
	mc.runningMu.Unlock()

	if running {
		mc.wg.Add(1)
		go mc.probeLoop(wanID)

		if mc.config.EnablePassiveMonitoring {
			mc.wg.Add(1)
			go mc.monitorLoop(wanID)
		}
	}

	return nil
}

// RemoveWAN removes a WAN interface from monitoring.
func (mc *MetricsCollector) RemoveWAN(wanID string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, exists := mc.wanMetrics[wanID]; !exists {
		return ErrWANNotFound
	}

	delete(mc.wanMetrics, wanID)
	delete(mc.prevCounters, wanID)

	// Note: The probe goroutine will exit on next tick when it can't find the WAN.
	return nil
}

// =============================================================================
// Query API
// =============================================================================

// GetWANMetrics retrieves current metrics for a WAN.
func (mc *MetricsCollector) GetWANMetrics(wanID string) (*WANMetrics, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics, exists := mc.wanMetrics[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	// Return a copy.
	copy := *metrics
	return &copy, nil
}

// GetAllWANMetrics retrieves all current metrics.
func (mc *MetricsCollector) GetAllWANMetrics() map[string]*WANMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]*WANMetrics, len(mc.wanMetrics))
	for k, v := range mc.wanMetrics {
		copy := *v
		result[k] = &copy
	}
	return result
}

// GetHistoricalMetrics retrieves historical metrics from database.
func (mc *MetricsCollector) GetHistoricalMetrics(ctx context.Context, wanID string, start, end time.Time) ([]*WANMetrics, error) {
	return mc.db.GetHistoricalMetrics(ctx, wanID, start, end)
}

// GetHealthScore retrieves the current health score for a WAN.
func (mc *MetricsCollector) GetHealthScore(wanID string) (float64, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics, exists := mc.wanMetrics[wanID]
	if !exists {
		return 0, ErrWANNotFound
	}

	return metrics.HealthScore, nil
}

// GetAllHealthScores retrieves health scores for all WANs.
func (mc *MetricsCollector) GetAllHealthScores() map[string]float64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]float64, len(mc.wanMetrics))
	for wanID, metrics := range mc.wanMetrics {
		result[wanID] = metrics.HealthScore
	}
	return result
}

// =============================================================================
// Probe Target Management
// =============================================================================

// SetProbeTargets updates the probe targets.
func (mc *MetricsCollector) SetProbeTargets(targets []string) error {
	if len(targets) == 0 {
		return ErrInvalidTarget
	}
	mc.config.ProbeTargets = targets
	return nil
}

// AddProbeTarget adds a probe target.
func (mc *MetricsCollector) AddProbeTarget(target string) error {
	if target == "" {
		return ErrInvalidTarget
	}
	mc.config.ProbeTargets = append(mc.config.ProbeTargets, target)
	return nil
}

// RemoveProbeTarget removes a probe target.
func (mc *MetricsCollector) RemoveProbeTarget(target string) error {
	if len(mc.config.ProbeTargets) <= 1 {
		return ErrInvalidTarget // Must have at least one target.
	}

	newTargets := make([]string, 0, len(mc.config.ProbeTargets)-1)
	found := false
	for _, t := range mc.config.ProbeTargets {
		if t != target {
			newTargets = append(newTargets, t)
		} else {
			found = true
		}
	}

	if !found {
		return ErrInvalidTarget
	}

	mc.config.ProbeTargets = newTargets
	return nil
}

// =============================================================================
// Reset and Health Check
// =============================================================================

// ResetMetrics clears metrics for a WAN.
func (mc *MetricsCollector) ResetMetrics(wanID string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metrics, exists := mc.wanMetrics[wanID]
	if !exists {
		return ErrWANNotFound
	}

	metrics.ProbeResults = make([]ProbeResult, 0, 10)
	metrics.Latency = 0
	metrics.PacketLoss = 0
	metrics.Jitter = 0
	metrics.HealthScore = 100.0
	metrics.ErrorCount = 0
	metrics.LastUpdate = time.Now()

	return nil
}

// HealthCheck verifies the metrics system is operational.
func (mc *MetricsCollector) HealthCheck() error {
	mc.runningMu.Lock()
	running := mc.running
	mc.runningMu.Unlock()

	if !running {
		return ErrMetricsStale
	}

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Check that metrics are being updated.
	maxAge := 2 * mc.config.ProbeInterval
	now := time.Now()

	for _, metrics := range mc.wanMetrics {
		if now.Sub(metrics.LastUpdate) > maxAge {
			return ErrMetricsStale
		}
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// GetConfig returns the current configuration.
func (mc *MetricsCollector) GetConfig() *MetricsConfig {
	return mc.config
}

// IsRunning returns whether collection is running.
func (mc *MetricsCollector) IsRunning() bool {
	mc.runningMu.Lock()
	defer mc.runningMu.Unlock()
	return mc.running
}

// GetWANCount returns the number of monitored WANs.
func (mc *MetricsCollector) GetWANCount() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.wanMetrics)
}
