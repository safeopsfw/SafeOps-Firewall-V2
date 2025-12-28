// Package failover provides WAN failover management for the NIC Management service.
package failover

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types (WAN Monitor Specific)
// =============================================================================

var (
	// ErrMonitorWANNotFound indicates WAN ID not in monitor state.
	ErrMonitorWANNotFound = errors.New("WAN not found in monitor")
	// ErrMonitorCheckTimeout indicates availability check exceeded timeout.
	ErrMonitorCheckTimeout = errors.New("monitor check timeout")
	// ErrNoCheckTargets indicates no ping/TCP/DNS targets configured.
	ErrNoCheckTargets = errors.New("no check targets configured")
	// ErrAllMonitorChecksFailed indicates all targets failed for WAN.
	ErrAllMonitorChecksFailed = errors.New("all monitor checks failed")
)

// =============================================================================
// TCP Target
// =============================================================================

// TCPTarget defines a TCP connectivity check endpoint.
type TCPTarget struct {
	// Address is the target IP or hostname.
	Address string `json:"address"`
	// Port is the target port.
	Port int `json:"port"`
	// Timeout is max connection time.
	Timeout time.Duration `json:"timeout"`
}

// =============================================================================
// Availability Snapshot
// =============================================================================

// AvailabilitySnapshot represents a point-in-time availability sample.
type AvailabilitySnapshot struct {
	// Timestamp is when snapshot was taken.
	Timestamp time.Time `json:"timestamp"`
	// IsUp is availability status at that time.
	IsUp bool `json:"is_up"`
	// HealthScore is health score at that time.
	HealthScore float64 `json:"health_score"`
	// LatencyMs is latency in milliseconds.
	LatencyMs float64 `json:"latency_ms"`
	// FailureReason is reason if down.
	FailureReason string `json:"failure_reason,omitempty"`
}

// =============================================================================
// WAN Monitor State
// =============================================================================

// WANMonitorState contains per-WAN monitoring state and statistics.
type WANMonitorState struct {
	// WANID is the WAN identifier.
	WANID string `json:"wan_id"`
	// InterfaceName is the OS interface name.
	InterfaceName string `json:"interface_name"`
	// IsUp is current availability status.
	IsUp bool `json:"is_up"`
	// HealthScore is current health score.
	HealthScore float64 `json:"health_score"`
	// ConsecutiveFailures is consecutive failed checks.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// ConsecutiveSuccesses is consecutive successful checks.
	ConsecutiveSuccesses int `json:"consecutive_successes"`
	// LastCheckTime is when last checked.
	LastCheckTime time.Time `json:"last_check_time"`
	// LastUpTime is when last marked UP.
	LastUpTime time.Time `json:"last_up_time"`
	// LastDownTime is when last marked DOWN.
	LastDownTime time.Time `json:"last_down_time"`
	// TotalChecks is total checks since startup.
	TotalChecks uint64 `json:"total_checks"`
	// SuccessfulChecks is total successful checks.
	SuccessfulChecks uint64 `json:"successful_checks"`
	// FailedChecks is total failed checks.
	FailedChecks uint64 `json:"failed_checks"`
	// UptimePercentage is uptime over rolling window.
	UptimePercentage float64 `json:"uptime_percentage"`
	// CurrentStreak is how long in current state.
	CurrentStreak time.Duration `json:"current_streak"`
	// AvailabilityHistory is recent availability samples.
	AvailabilityHistory []*AvailabilitySnapshot `json:"availability_history"`
	// LastFailureReason is reason for last failure.
	LastFailureReason string `json:"last_failure_reason"`
}

// =============================================================================
// Monitor Configuration
// =============================================================================

// MonitorConfig contains configuration for WAN monitoring.
type MonitorConfig struct {
	// MonitorInterval is how often to check each WAN.
	MonitorInterval time.Duration `json:"monitor_interval"`
	// HealthCheckTimeout is max time per health check.
	HealthCheckTimeout time.Duration `json:"health_check_timeout"`
	// FailureThreshold is consecutive failures before DOWN.
	FailureThreshold int `json:"failure_threshold"`
	// RecoveryThreshold is consecutive successes before UP.
	RecoveryThreshold int `json:"recovery_threshold"`
	// PingTargets are ICMP ping targets.
	PingTargets []string `json:"ping_targets"`
	// TCPTargets are TCP connectivity targets.
	TCPTargets []TCPTarget `json:"tcp_targets"`
	// DNSTargets are DNS resolution targets.
	DNSTargets []string `json:"dns_targets"`
	// FailoverTriggerHealth is health score triggering failover.
	FailoverTriggerHealth float64 `json:"failover_trigger_health"`
	// RecoveryTriggerHealth is health score triggering recovery.
	RecoveryTriggerHealth float64 `json:"recovery_trigger_health"`
	// UptimeWindowDuration is rolling window for uptime.
	UptimeWindowDuration time.Duration `json:"uptime_window_duration"`
	// EnableEventPublishing publishes health change events.
	EnableEventPublishing bool `json:"enable_event_publishing"`
	// EnableAvailabilityTracking tracks uptime percentages.
	EnableAvailabilityTracking bool `json:"enable_availability_tracking"`
	// HistoryRetention is how long to keep history.
	HistoryRetention time.Duration `json:"history_retention"`
	// MaxHistorySize is max snapshots per WAN.
	MaxHistorySize int `json:"max_history_size"`
}

// DefaultMonitorConfig returns the default configuration.
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		MonitorInterval:    5 * time.Second,
		HealthCheckTimeout: 3 * time.Second,
		FailureThreshold:   3,
		RecoveryThreshold:  5,
		PingTargets:        []string{"8.8.8.8", "1.1.1.1"},
		TCPTargets: []TCPTarget{
			{Address: "8.8.8.8", Port: 53, Timeout: 2 * time.Second},
			{Address: "1.1.1.1", Port: 53, Timeout: 2 * time.Second},
		},
		DNSTargets:                 []string{"google.com", "cloudflare.com"},
		FailoverTriggerHealth:      40.0,
		RecoveryTriggerHealth:      70.0,
		UptimeWindowDuration:       24 * time.Hour,
		EnableEventPublishing:      true,
		EnableAvailabilityTracking: true,
		HistoryRetention:           30 * 24 * time.Hour, // 30 days
		MaxHistorySize:             1440,                // 24 hours at 1 per minute
	}
}

// =============================================================================
// Monitor Subscriber
// =============================================================================

// MonitorSubscriber receives WAN health change notifications.
type MonitorSubscriber interface {
	// OnWANHealthChange is called when health score changes.
	OnWANHealthChange(wanID string, oldHealth, newHealth float64)
	// OnWANStateChange is called when WAN goes UP/DOWN.
	OnWANStateChange(wanID string, isUp bool, reason string)
	// OnFailoverTriggered is called when failover conditions met.
	OnFailoverTriggered(primaryWAN, backupWAN, reason string)
}

// =============================================================================
// Database Interface
// =============================================================================

// MonitorDB defines the database interface for availability history.
type MonitorDB interface {
	// LoadAvailabilityHistory loads recent snapshots.
	LoadAvailabilityHistory(ctx context.Context, wanID string, since time.Time) ([]*AvailabilitySnapshot, error)
	// SaveAvailabilitySnapshots saves snapshots.
	SaveAvailabilitySnapshots(ctx context.Context, wanID string, snapshots []*AvailabilitySnapshot) error
	// PruneAvailabilityHistory removes old snapshots.
	PruneAvailabilityHistory(ctx context.Context, olderThan time.Time) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpMonitorDB struct{}

func (n *noOpMonitorDB) LoadAvailabilityHistory(ctx context.Context, wanID string, since time.Time) ([]*AvailabilitySnapshot, error) {
	return nil, nil
}

func (n *noOpMonitorDB) SaveAvailabilitySnapshots(ctx context.Context, wanID string, snapshots []*AvailabilitySnapshot) error {
	return nil
}

func (n *noOpMonitorDB) PruneAvailabilityHistory(ctx context.Context, olderThan time.Time) error {
	return nil
}

// =============================================================================
// WAN Monitor
// =============================================================================

// WANMonitor monitors WAN connectivity.
type WANMonitor struct {
	// Database for availability history.
	db MonitorDB
	// Configuration.
	config *MonitorConfig
	// Monitor state per WAN.
	monitorState map[string]*WANMonitorState
	// Primary WAN ID (for failover detection).
	primaryWAN string
	// Backup WAN ID.
	backupWAN string
	// Protects monitorState.
	mu sync.RWMutex
	// Subscribers.
	subscribers   []MonitorSubscriber
	subscribersMu sync.RWMutex
	// Statistics.
	totalChecks      uint64
	failedChecks     uint64
	stateChanges     uint64
	failoverTriggers uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewWANMonitor creates a new WAN monitor.
func NewWANMonitor(db MonitorDB, config *MonitorConfig) *WANMonitor {
	if config == nil {
		config = DefaultMonitorConfig()
	}

	if db == nil {
		db = &noOpMonitorDB{}
	}

	return &WANMonitor{
		db:           db,
		config:       config,
		monitorState: make(map[string]*WANMonitorState),
		subscribers:  make([]MonitorSubscriber, 0),
		stopChan:     make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the WAN monitor.
func (wm *WANMonitor) Start(ctx context.Context) error {
	wm.runningMu.Lock()
	defer wm.runningMu.Unlock()

	if wm.running {
		return nil
	}

	// Perform initial check.
	_ = wm.checkAllWANs()

	// Start monitor loop.
	wm.wg.Add(1)
	go wm.monitorLoop()

	// Start uptime calculation worker.
	if wm.config.EnableAvailabilityTracking {
		wm.wg.Add(1)
		go wm.uptimeCalculationWorker()
	}

	// Start availability persistence worker.
	if wm.config.EnableAvailabilityTracking {
		wm.wg.Add(1)
		go wm.availabilityPersistenceWorker()
	}

	wm.running = true
	return nil
}

// Stop stops the WAN monitor.
func (wm *WANMonitor) Stop() error {
	wm.runningMu.Lock()
	if !wm.running {
		wm.runningMu.Unlock()
		return nil
	}
	wm.running = false
	wm.runningMu.Unlock()

	close(wm.stopChan)
	wm.wg.Wait()

	// Final persistence.
	if wm.config.EnableAvailabilityTracking {
		wm.persistAllSnapshots()
	}

	return nil
}

// =============================================================================
// Background Loops
// =============================================================================

// monitorLoop runs periodic WAN checks.
func (wm *WANMonitor) monitorLoop() {
	defer wm.wg.Done()

	ticker := time.NewTicker(wm.config.MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-wm.stopChan:
			return
		case <-ticker.C:
			_ = wm.checkAllWANs()
		}
	}
}

// uptimeCalculationWorker recalculates uptime percentages.
func (wm *WANMonitor) uptimeCalculationWorker() {
	defer wm.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wm.stopChan:
			return
		case <-ticker.C:
			wm.recalculateAllUptimes()
		}
	}
}

// availabilityPersistenceWorker saves snapshots periodically.
func (wm *WANMonitor) availabilityPersistenceWorker() {
	defer wm.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wm.stopChan:
			return
		case <-ticker.C:
			wm.persistAllSnapshots()
			wm.pruneOldHistory()
		}
	}
}

// recalculateAllUptimes recalculates uptime for all WANs.
func (wm *WANMonitor) recalculateAllUptimes() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for wanID, state := range wm.monitorState {
		state.UptimePercentage = wm.calculateUptimePercentage(wanID)
		state.CurrentStreak = wm.calculateCurrentStreak(state)
	}
}

// persistAllSnapshots saves all snapshots to database.
func (wm *WANMonitor) persistAllSnapshots() {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for wanID, state := range wm.monitorState {
		if len(state.AvailabilityHistory) > 0 {
			_ = wm.db.SaveAvailabilitySnapshots(ctx, wanID, state.AvailabilityHistory)
		}
	}
}

// pruneOldHistory removes old history from database.
func (wm *WANMonitor) pruneOldHistory() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-wm.config.HistoryRetention)
	_ = wm.db.PruneAvailabilityHistory(ctx, cutoff)
}

// =============================================================================
// WAN Checking
// =============================================================================

// checkAllWANs performs availability checks for all WANs.
func (wm *WANMonitor) checkAllWANs() error {
	wm.mu.RLock()
	wanIDs := make([]string, 0, len(wm.monitorState))
	for wanID := range wm.monitorState {
		wanIDs = append(wanIDs, wanID)
	}
	wm.mu.RUnlock()

	var wg sync.WaitGroup
	for _, wanID := range wanIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = wm.checkWAN(id)
		}(wanID)
	}

	wg.Wait()
	return nil
}

// checkWAN performs availability check for single WAN.
func (wm *WANMonitor) checkWAN(wanID string) error {
	wm.mu.RLock()
	state, exists := wm.monitorState[wanID]
	if !exists {
		wm.mu.RUnlock()
		return ErrMonitorWANNotFound
	}
	oldHealth := state.HealthScore
	oldIsUp := state.IsUp
	wm.mu.RUnlock()

	atomic.AddUint64(&wm.totalChecks, 1)

	// Perform connectivity checks.
	checkSuccess, failureReason, latencyMs := wm.performConnectivityChecks()

	// Update state.
	wm.mu.Lock()
	state = wm.monitorState[wanID]
	if state == nil {
		wm.mu.Unlock()
		return ErrMonitorWANNotFound
	}

	state.LastCheckTime = time.Now()
	state.TotalChecks++

	if checkSuccess {
		state.ConsecutiveSuccesses++
		state.ConsecutiveFailures = 0
		state.SuccessfulChecks++
		state.HealthScore = 100.0 // Would come from actual health checker.
	} else {
		state.ConsecutiveFailures++
		state.ConsecutiveSuccesses = 0
		state.FailedChecks++
		state.LastFailureReason = failureReason
		state.HealthScore = 0.0 // Would come from actual health checker.
		atomic.AddUint64(&wm.failedChecks, 1)
	}

	// Evaluate state change.
	stateChanged := wm.evaluateStateChange(state)

	// Add snapshot to history.
	snapshot := &AvailabilitySnapshot{
		Timestamp:     time.Now(),
		IsUp:          state.IsUp,
		HealthScore:   state.HealthScore,
		LatencyMs:     latencyMs,
		FailureReason: failureReason,
	}
	state.AvailabilityHistory = append(state.AvailabilityHistory, snapshot)
	if len(state.AvailabilityHistory) > wm.config.MaxHistorySize {
		state.AvailabilityHistory = state.AvailabilityHistory[len(state.AvailabilityHistory)-wm.config.MaxHistorySize:]
	}

	newHealth := state.HealthScore
	newIsUp := state.IsUp
	wm.mu.Unlock()

	// Notify subscribers.
	if wm.config.EnableEventPublishing {
		// Notify health change if significant.
		if abs(newHealth-oldHealth) > 5.0 {
			wm.notifyHealthChange(wanID, oldHealth, newHealth)
		}

		// Notify state change.
		if stateChanged {
			wm.notifyStateChange(wanID, newIsUp, failureReason)
		}

		// Check failover trigger.
		if wanID == wm.primaryWAN && oldIsUp && !newIsUp {
			wm.notifyFailoverTrigger(wm.primaryWAN, wm.backupWAN, failureReason)
		}
	}

	return nil
}

// performConnectivityChecks performs TCP connectivity checks.
func (wm *WANMonitor) performConnectivityChecks() (bool, string, float64) {
	successCount := 0
	var lastError string
	var totalLatencyMs float64

	// TCP checks.
	for _, target := range wm.config.TCPTargets {
		start := time.Now()
		success, err := wm.checkTCPTarget(target)
		latency := time.Since(start)

		if success {
			successCount++
			totalLatencyMs += float64(latency.Milliseconds())
		} else if err != "" {
			lastError = err
		}
	}

	// DNS checks.
	for _, target := range wm.config.DNSTargets {
		start := time.Now()
		success, err := wm.checkDNSTarget(target)
		latency := time.Since(start)

		if success {
			successCount++
			totalLatencyMs += float64(latency.Milliseconds())
		} else if err != "" {
			lastError = err
		}
	}

	totalChecks := len(wm.config.TCPTargets) + len(wm.config.DNSTargets)
	if totalChecks == 0 {
		return true, "", 0 // No targets configured, assume up.
	}

	// Consider successful if at least one check passes.
	success := successCount > 0
	avgLatency := float64(0)
	if successCount > 0 {
		avgLatency = totalLatencyMs / float64(successCount)
	}

	if !success {
		return false, lastError, avgLatency
	}

	return true, "", avgLatency
}

// checkTCPTarget performs TCP connectivity check.
func (wm *WANMonitor) checkTCPTarget(target TCPTarget) (bool, string) {
	address := net.JoinHostPort(target.Address, formatPort(target.Port))

	dialer := &net.Dialer{
		Timeout: target.Timeout,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()

	return true, ""
}

// checkDNSTarget performs DNS resolution check.
func (wm *WANMonitor) checkDNSTarget(target string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), wm.config.HealthCheckTimeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
	}

	_, err := resolver.LookupHost(ctx, target)
	if err != nil {
		return false, err.Error()
	}

	return true, ""
}

// evaluateStateChange determines if WAN state should transition.
func (wm *WANMonitor) evaluateStateChange(state *WANMonitorState) bool {
	// Transition to DOWN.
	if state.ConsecutiveFailures >= wm.config.FailureThreshold && state.IsUp {
		state.IsUp = false
		state.LastDownTime = time.Now()
		atomic.AddUint64(&wm.stateChanges, 1)
		return true
	}

	// Transition to UP.
	if state.ConsecutiveSuccesses >= wm.config.RecoveryThreshold && !state.IsUp {
		state.IsUp = true
		state.LastUpTime = time.Now()
		atomic.AddUint64(&wm.stateChanges, 1)
		return true
	}

	return false
}

// =============================================================================
// Uptime Calculation
// =============================================================================

// calculateUptimePercentage computes uptime over rolling window.
func (wm *WANMonitor) calculateUptimePercentage(wanID string) float64 {
	state, exists := wm.monitorState[wanID]
	if !exists || len(state.AvailabilityHistory) == 0 {
		return 100.0
	}

	cutoff := time.Now().Add(-wm.config.UptimeWindowDuration)
	upCount := 0
	totalCount := 0

	for _, snapshot := range state.AvailabilityHistory {
		if snapshot.Timestamp.After(cutoff) {
			totalCount++
			if snapshot.IsUp {
				upCount++
			}
		}
	}

	if totalCount == 0 {
		return 100.0
	}

	return float64(upCount) / float64(totalCount) * 100.0
}

// calculateCurrentStreak calculates how long in current state.
func (wm *WANMonitor) calculateCurrentStreak(state *WANMonitorState) time.Duration {
	if state.IsUp {
		if state.LastUpTime.IsZero() {
			return 0
		}
		return time.Since(state.LastUpTime)
	}
	if state.LastDownTime.IsZero() {
		return 0
	}
	return time.Since(state.LastDownTime)
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for monitor notifications.
func (wm *WANMonitor) Subscribe(subscriber MonitorSubscriber) {
	wm.subscribersMu.Lock()
	defer wm.subscribersMu.Unlock()
	wm.subscribers = append(wm.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (wm *WANMonitor) Unsubscribe(subscriber MonitorSubscriber) {
	wm.subscribersMu.Lock()
	defer wm.subscribersMu.Unlock()

	for i, s := range wm.subscribers {
		if s == subscriber {
			wm.subscribers = append(wm.subscribers[:i], wm.subscribers[i+1:]...)
			return
		}
	}
}

// notifyHealthChange publishes health change events.
func (wm *WANMonitor) notifyHealthChange(wanID string, oldHealth, newHealth float64) {
	wm.subscribersMu.RLock()
	subscribers := make([]MonitorSubscriber, len(wm.subscribers))
	copy(subscribers, wm.subscribers)
	wm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s MonitorSubscriber) {
			s.OnWANHealthChange(wanID, oldHealth, newHealth)
		}(sub)
	}
}

// notifyStateChange publishes state change events.
func (wm *WANMonitor) notifyStateChange(wanID string, isUp bool, reason string) {
	wm.subscribersMu.RLock()
	subscribers := make([]MonitorSubscriber, len(wm.subscribers))
	copy(subscribers, wm.subscribers)
	wm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s MonitorSubscriber) {
			s.OnWANStateChange(wanID, isUp, reason)
		}(sub)
	}
}

// notifyFailoverTrigger publishes failover condition detection.
func (wm *WANMonitor) notifyFailoverTrigger(primaryWAN, backupWAN, reason string) {
	atomic.AddUint64(&wm.failoverTriggers, 1)

	wm.subscribersMu.RLock()
	subscribers := make([]MonitorSubscriber, len(wm.subscribers))
	copy(subscribers, wm.subscribers)
	wm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s MonitorSubscriber) {
			s.OnFailoverTriggered(primaryWAN, backupWAN, reason)
		}(sub)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetWANMonitorState retrieves current monitor state for a WAN.
func (wm *WANMonitor) GetWANMonitorState(wanID string) (*WANMonitorState, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return nil, ErrMonitorWANNotFound
	}

	// Return copy.
	copy := *state
	copy.AvailabilityHistory = make([]*AvailabilitySnapshot, len(state.AvailabilityHistory))
	for i, s := range state.AvailabilityHistory {
		snapshotCopy := *s
		copy.AvailabilityHistory[i] = &snapshotCopy
	}

	return &copy, nil
}

// GetAllMonitorStates retrieves monitor state for all WANs.
func (wm *WANMonitor) GetAllMonitorStates() map[string]*WANMonitorState {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	result := make(map[string]*WANMonitorState, len(wm.monitorState))
	for wanID, state := range wm.monitorState {
		copy := *state
		result[wanID] = &copy
	}
	return result
}

// GetUptimePercentage retrieves uptime percentage for a WAN.
func (wm *WANMonitor) GetUptimePercentage(wanID string) (float64, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return 0, ErrMonitorWANNotFound
	}

	return state.UptimePercentage, nil
}

// GetAvailabilityHistory retrieves historical snapshots.
func (wm *WANMonitor) GetAvailabilityHistory(wanID string, duration time.Duration) ([]*AvailabilitySnapshot, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return nil, ErrMonitorWANNotFound
	}

	cutoff := time.Now().Add(-duration)
	result := make([]*AvailabilitySnapshot, 0)
	for _, s := range state.AvailabilityHistory {
		if s.Timestamp.After(cutoff) {
			copy := *s
			result = append(result, &copy)
		}
	}

	return result, nil
}

// IsWANAvailable returns quick availability status.
func (wm *WANMonitor) IsWANAvailable(wanID string) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return false
	}

	return state.IsUp
}

// GetCurrentStreak returns how long WAN has been in current state.
func (wm *WANMonitor) GetCurrentStreak(wanID string) (time.Duration, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return 0, ErrMonitorWANNotFound
	}

	return state.CurrentStreak, nil
}

// GetOutageCount returns number of outages in time period.
func (wm *WANMonitor) GetOutageCount(wanID string, duration time.Duration) (int, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return 0, ErrMonitorWANNotFound
	}

	cutoff := time.Now().Add(-duration)
	outageCount := 0
	wasUp := true

	for _, s := range state.AvailabilityHistory {
		if s.Timestamp.After(cutoff) {
			if wasUp && !s.IsUp {
				outageCount++
			}
			wasUp = s.IsUp
		}
	}

	return outageCount, nil
}

// =============================================================================
// WAN Management
// =============================================================================

// AddWAN adds a WAN for monitoring.
func (wm *WANMonitor) AddWAN(wanID, interfaceName string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if _, exists := wm.monitorState[wanID]; exists {
		return nil
	}

	now := time.Now()
	wm.monitorState[wanID] = &WANMonitorState{
		WANID:               wanID,
		InterfaceName:       interfaceName,
		IsUp:                true, // Assume up until proven down.
		HealthScore:         100.0,
		LastUpTime:          now,
		AvailabilityHistory: make([]*AvailabilitySnapshot, 0, wm.config.MaxHistorySize),
	}

	return nil
}

// RemoveWAN removes a WAN from monitoring.
func (wm *WANMonitor) RemoveWAN(wanID string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	delete(wm.monitorState, wanID)
	return nil
}

// SetPrimaryWAN sets the primary WAN for failover detection.
func (wm *WANMonitor) SetPrimaryWAN(wanID string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.primaryWAN = wanID
}

// SetBackupWAN sets the backup WAN for failover detection.
func (wm *WANMonitor) SetBackupWAN(wanID string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.backupWAN = wanID
}

// ForceCheck triggers immediate availability check for WAN.
func (wm *WANMonitor) ForceCheck(wanID string) error {
	wm.mu.RLock()
	_, exists := wm.monitorState[wanID]
	wm.mu.RUnlock()

	if !exists {
		return ErrMonitorWANNotFound
	}

	return wm.checkWAN(wanID)
}

// ResetCounters resets consecutive failure/success counters.
func (wm *WANMonitor) ResetCounters(wanID string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	state, exists := wm.monitorState[wanID]
	if !exists {
		return ErrMonitorWANNotFound
	}

	state.ConsecutiveFailures = 0
	state.ConsecutiveSuccesses = 0
	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the monitor is operational.
func (wm *WANMonitor) HealthCheck() error {
	wm.runningMu.Lock()
	running := wm.running
	wm.runningMu.Unlock()

	if !running {
		return errors.New("WAN monitor not running")
	}

	wm.mu.RLock()
	count := len(wm.monitorState)
	wm.mu.RUnlock()

	if count == 0 {
		return ErrNoCheckTargets
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns monitor statistics.
func (wm *WANMonitor) GetStatistics() map[string]interface{} {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	return map[string]interface{}{
		"monitored_wans":     len(wm.monitorState),
		"total_checks":       atomic.LoadUint64(&wm.totalChecks),
		"failed_checks":      atomic.LoadUint64(&wm.failedChecks),
		"state_changes":      atomic.LoadUint64(&wm.stateChanges),
		"failover_triggers":  atomic.LoadUint64(&wm.failoverTriggers),
		"primary_wan":        wm.primaryWAN,
		"backup_wan":         wm.backupWAN,
		"monitor_interval":   wm.config.MonitorInterval.String(),
		"failure_threshold":  wm.config.FailureThreshold,
		"recovery_threshold": wm.config.RecoveryThreshold,
	}
}

// GetConfig returns the current configuration.
func (wm *WANMonitor) GetConfig() *MonitorConfig {
	return wm.config
}

// IsRunning returns whether the monitor is running.
func (wm *WANMonitor) IsRunning() bool {
	wm.runningMu.Lock()
	defer wm.runningMu.Unlock()
	return wm.running
}

// =============================================================================
// Utility
// =============================================================================

// formatPort converts int to port string.
func formatPort(port int) string {
	if port == 0 {
		return "0"
	}
	return formatPortInner(port)
}

func formatPortInner(n int) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	return formatPortInner(n/10) + string('0'+byte(n%10))
}

// abs returns absolute value of float64.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
