// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrCheckTimeout indicates health check exceeded timeout.
	ErrCheckTimeout = errors.New("health check timeout")
	// ErrNoHealthTargets indicates no targets configured for WAN.
	ErrNoHealthTargets = errors.New("no health targets configured")
	// ErrAllChecksFailed indicates all targets failed for WAN.
	ErrAllChecksFailed = errors.New("all health checks failed")
	// ErrHealthOverrideActive indicates cannot check WAN with active override.
	ErrHealthOverrideActive = errors.New("health override active")
)

// =============================================================================
// Target Type
// =============================================================================

// TargetType represents the type of health check target.
type TargetType int

const (
	// TargetGateway is the WAN gateway.
	TargetGateway TargetType = iota
	// TargetDNSPrimary is the primary DNS server.
	TargetDNSPrimary
	// TargetDNSSecondary is the secondary DNS server.
	TargetDNSSecondary
	// TargetHTTPPublic is a public HTTP endpoint.
	TargetHTTPPublic
	// TargetCustom is a user-defined target.
	TargetCustom
)

// String returns the string representation of the target type.
func (t TargetType) String() string {
	switch t {
	case TargetGateway:
		return "GATEWAY"
	case TargetDNSPrimary:
		return "DNS_PRIMARY"
	case TargetDNSSecondary:
		return "DNS_SECONDARY"
	case TargetHTTPPublic:
		return "HTTP_PUBLIC"
	case TargetCustom:
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Health State
// =============================================================================

// HealthState represents WAN health state.
type HealthState int

const (
	// HealthStateUnknown indicates not yet checked.
	HealthStateUnknown HealthState = iota
	// HealthStateUp indicates healthy.
	HealthStateUp
	// HealthStateDegraded indicates degraded but usable.
	HealthStateDegraded
	// HealthStateDown indicates failed.
	HealthStateDown
)

// String returns the string representation of the health state.
func (s HealthState) String() string {
	switch s {
	case HealthStateUnknown:
		return "UNKNOWN"
	case HealthStateUp:
		return "UP"
	case HealthStateDegraded:
		return "DEGRADED"
	case HealthStateDown:
		return "DOWN"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Health Target
// =============================================================================

// HealthTarget defines a health check endpoint.
type HealthTarget struct {
	// Type is the target type.
	Type TargetType `json:"type"`
	// Address is the target address.
	Address string `json:"address"`
	// Port is the target port.
	Port int `json:"port"`
	// Protocol is the check protocol.
	Protocol string `json:"protocol"`
	// ExpectedResponse is the expected response.
	ExpectedResponse string `json:"expected_response"`
	// Weight is the target importance.
	Weight float64 `json:"weight"`
	// Enabled indicates whether target is active.
	Enabled bool `json:"enabled"`
}

// =============================================================================
// Check Result
// =============================================================================

// CheckResult represents a single health check result.
type CheckResult struct {
	// Timestamp is when check was performed.
	Timestamp time.Time `json:"timestamp"`
	// Target is what was checked.
	Target HealthTarget `json:"target"`
	// Success indicates whether check passed.
	Success bool `json:"success"`
	// Latency is the response time.
	Latency time.Duration `json:"latency"`
	// Error is the error message.
	Error string `json:"error,omitempty"`
	// ResponseCode is the HTTP status code.
	ResponseCode int `json:"response_code,omitempty"`
}

// =============================================================================
// WAN Health
// =============================================================================

// WANHealth represents complete health state for a WAN.
type WANHealth struct {
	// WANID is the WAN identifier.
	WANID string `json:"wan_id"`
	// HealthScore is the normalized health score.
	HealthScore float64 `json:"health_score"`
	// State is the current health state.
	State HealthState `json:"state"`
	// Latency is the average RTT.
	Latency time.Duration `json:"latency"`
	// PacketLoss is the packet loss percentage.
	PacketLoss float64 `json:"packet_loss"`
	// Jitter is the latency variance.
	Jitter time.Duration `json:"jitter"`
	// LastCheckTime is when last checked.
	LastCheckTime time.Time `json:"last_check_time"`
	// ConsecutiveFailures is the consecutive failed checks.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// ConsecutiveSuccesses is the consecutive successful checks.
	ConsecutiveSuccesses int `json:"consecutive_successes"`
	// UptimePercentage is the uptime over last 24h.
	UptimePercentage float64 `json:"uptime_percentage"`
	// CheckResults are the recent check history.
	CheckResults []*CheckResult `json:"check_results"`
	// LastStateChange is when state last changed.
	LastStateChange time.Time `json:"last_state_change"`
	// StateChangeCount is the total state transitions.
	StateChangeCount uint64 `json:"state_change_count"`
	// OverrideActive indicates manual override is active.
	OverrideActive bool `json:"override_active"`
	// OverrideExpires is when override expires.
	OverrideExpires time.Time `json:"override_expires,omitempty"`
}

// =============================================================================
// Health Configuration
// =============================================================================

// HealthConfig contains configuration for health checking.
type HealthConfig struct {
	// CheckInterval is how often to check each WAN.
	CheckInterval time.Duration `json:"check_interval"`
	// CheckTimeout is the max time per health check.
	CheckTimeout time.Duration `json:"check_timeout"`
	// PingCount is the ICMP pings per check.
	PingCount int `json:"ping_count"`
	// PingTimeout is the max time per ping.
	PingTimeout time.Duration `json:"ping_timeout"`
	// FailureThreshold is the consecutive failures triggering DOWN.
	FailureThreshold int `json:"failure_threshold"`
	// RecoveryThreshold is the consecutive successes triggering UP.
	RecoveryThreshold int `json:"recovery_threshold"`
	// HealthTargets are the check targets.
	HealthTargets []HealthTarget `json:"health_targets"`
	// EnableTCPCheck performs TCP connection test.
	EnableTCPCheck bool `json:"enable_tcp_check"`
	// EnableDNSCheck performs DNS resolution test.
	EnableDNSCheck bool `json:"enable_dns_check"`
	// EnableHTTPCheck performs HTTP GET test.
	EnableHTTPCheck bool `json:"enable_http_check"`
	// LatencyWeight is the latency impact on score.
	LatencyWeight float64 `json:"latency_weight"`
	// PacketLossWeight is the packet loss impact on score.
	PacketLossWeight float64 `json:"packet_loss_weight"`
	// JitterWeight is the jitter impact on score.
	JitterWeight float64 `json:"jitter_weight"`
	// EnableHistoryPersistence saves health history to DB.
	EnableHistoryPersistence bool `json:"enable_history_persistence"`
	// HistoryRetention is how long to keep history.
	HistoryRetention time.Duration `json:"history_retention"`
}

// DefaultHealthConfig returns the default configuration.
func DefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		CheckInterval:     5 * time.Second,
		CheckTimeout:      3 * time.Second,
		PingCount:         3,
		PingTimeout:       1 * time.Second,
		FailureThreshold:  3,
		RecoveryThreshold: 5,
		HealthTargets: []HealthTarget{
			{Type: TargetDNSPrimary, Address: "8.8.8.8", Port: 53, Protocol: "tcp", Weight: 0.3, Enabled: true},
			{Type: TargetDNSSecondary, Address: "1.1.1.1", Port: 53, Protocol: "tcp", Weight: 0.3, Enabled: true},
			{Type: TargetHTTPPublic, Address: "http://www.google.com", Port: 80, Protocol: "http", Weight: 0.4, Enabled: true},
		},
		EnableTCPCheck:           true,
		EnableDNSCheck:           true,
		EnableHTTPCheck:          false,
		LatencyWeight:            0.3,
		PacketLossWeight:         0.5,
		JitterWeight:             0.2,
		EnableHistoryPersistence: true,
		HistoryRetention:         168 * time.Hour, // 7 days
	}
}

// =============================================================================
// Health Subscriber
// =============================================================================

// HealthSubscriber receives health event notifications.
type HealthSubscriber interface {
	// OnHealthUpdate is called on health score change.
	OnHealthUpdate(wanID string, health *WANHealth) error
	// OnStateChange is called on state transition.
	OnStateChange(wanID string, oldState, newState HealthState) error
}

// =============================================================================
// Database Interface
// =============================================================================

// HealthDB defines the database interface for health persistence.
type HealthDB interface {
	// LoadHealthHistory loads recent check results.
	LoadHealthHistory(ctx context.Context, wanID string, since time.Time) ([]*CheckResult, error)
	// SaveCheckResults saves check results.
	SaveCheckResults(ctx context.Context, wanID string, results []*CheckResult) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpHealthDB struct{}

func (n *noOpHealthDB) LoadHealthHistory(ctx context.Context, wanID string, since time.Time) ([]*CheckResult, error) {
	return nil, nil
}

func (n *noOpHealthDB) SaveCheckResults(ctx context.Context, wanID string, results []*CheckResult) error {
	return nil
}

// =============================================================================
// Health Checker
// =============================================================================

// HealthChecker monitors WAN health.
type HealthChecker struct {
	// WAN pool manager.
	wanSelector *WANSelector
	// Database for persistence.
	db HealthDB
	// Configuration.
	config *HealthConfig
	// Current health per WAN.
	healthState map[string]*WANHealth
	// Protects healthState.
	mu sync.RWMutex
	// Subscribers.
	subscribers   []HealthSubscriber
	subscribersMu sync.RWMutex
	// Statistics.
	totalChecks  uint64
	failedChecks uint64
	stateChanges uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(wanSelector *WANSelector, db HealthDB, config *HealthConfig) *HealthChecker {
	if config == nil {
		config = DefaultHealthConfig()
	}

	if db == nil {
		db = &noOpHealthDB{}
	}

	return &HealthChecker{
		wanSelector: wanSelector,
		db:          db,
		config:      config,
		healthState: make(map[string]*WANHealth),
		subscribers: make([]HealthSubscriber, 0),
		stopChan:    make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the health checker.
func (hc *HealthChecker) Start(ctx context.Context) error {
	hc.runningMu.Lock()
	defer hc.runningMu.Unlock()

	if hc.running {
		return nil
	}

	// Initialize health state for all WANs.
	if hc.wanSelector != nil {
		wans := hc.wanSelector.GetAllWANs()
		for _, wan := range wans {
			hc.healthState[wan.ID] = &WANHealth{
				WANID:        wan.ID,
				HealthScore:  100.0,
				State:        HealthStateUnknown,
				CheckResults: make([]*CheckResult, 0, 60),
			}
		}
	}

	// Perform initial health check.
	_ = hc.checkAllWANs()

	// Start check scheduler.
	hc.wg.Add(1)
	go hc.checkSchedulerLoop()

	// Start persistence loop.
	if hc.config.EnableHistoryPersistence {
		hc.wg.Add(1)
		go hc.persistenceLoop()
	}

	// Start override expiration checker.
	hc.wg.Add(1)
	go hc.overrideExpirationLoop()

	hc.running = true
	return nil
}

// Stop stops the health checker.
func (hc *HealthChecker) Stop() error {
	hc.runningMu.Lock()
	if !hc.running {
		hc.runningMu.Unlock()
		return nil
	}
	hc.running = false
	hc.runningMu.Unlock()

	close(hc.stopChan)
	hc.wg.Wait()

	// Final persistence.
	if hc.config.EnableHistoryPersistence {
		hc.persistAllResults()
	}

	return nil
}

// =============================================================================
// Background Loops
// =============================================================================

// checkSchedulerLoop runs periodic health checks.
func (hc *HealthChecker) checkSchedulerLoop() {
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopChan:
			return
		case <-ticker.C:
			_ = hc.checkAllWANs()
		}
	}
}

// persistenceLoop periodically saves check results.
func (hc *HealthChecker) persistenceLoop() {
	defer hc.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopChan:
			return
		case <-ticker.C:
			hc.persistAllResults()
		}
	}
}

// overrideExpirationLoop checks for expired overrides.
func (hc *HealthChecker) overrideExpirationLoop() {
	defer hc.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopChan:
			return
		case <-ticker.C:
			hc.checkOverrideExpirations()
		}
	}
}

// checkOverrideExpirations clears expired overrides.
func (hc *HealthChecker) checkOverrideExpirations() {
	now := time.Now()

	hc.mu.Lock()
	for _, health := range hc.healthState {
		if health.OverrideActive && !health.OverrideExpires.IsZero() && health.OverrideExpires.Before(now) {
			health.OverrideActive = false
			health.OverrideExpires = time.Time{}
		}
	}
	hc.mu.Unlock()
}

// persistAllResults saves all check results.
func (hc *HealthChecker) persistAllResults() {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for wanID, health := range hc.healthState {
		if len(health.CheckResults) > 0 {
			_ = hc.db.SaveCheckResults(ctx, wanID, health.CheckResults)
		}
	}
}

// =============================================================================
// Health Checking
// =============================================================================

// checkAllWANs performs health checks for all WANs.
func (hc *HealthChecker) checkAllWANs() error {
	hc.mu.RLock()
	wanIDs := make([]string, 0, len(hc.healthState))
	for wanID := range hc.healthState {
		wanIDs = append(wanIDs, wanID)
	}
	hc.mu.RUnlock()

	var wg sync.WaitGroup
	for _, wanID := range wanIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = hc.checkWANHealth(id)
		}(wanID)
	}

	wg.Wait()
	return nil
}

// checkWANHealth performs health check for single WAN.
func (hc *HealthChecker) checkWANHealth(wanID string) error {
	hc.mu.RLock()
	health, exists := hc.healthState[wanID]
	if !exists {
		hc.mu.RUnlock()
		return ErrWANNotFound
	}

	if health.OverrideActive {
		hc.mu.RUnlock()
		return nil // Skip check when override active.
	}
	hc.mu.RUnlock()

	// Build check targets.
	targets := hc.buildTargets(wanID)
	if len(targets) == 0 {
		return ErrNoHealthTargets
	}

	// Perform checks in parallel.
	results := make([]*CheckResult, 0, len(targets))
	resultsChan := make(chan *CheckResult, len(targets))

	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(t HealthTarget) {
			defer wg.Done()
			result := hc.performCheck(t, wanID)
			resultsChan <- result
		}(target)
	}

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		results = append(results, result)
	}

	atomic.AddUint64(&hc.totalChecks, 1)

	// Calculate metrics.
	score, latency, packetLoss, jitter := hc.calculateMetrics(results)

	// Count failures.
	failedCount := 0
	for _, r := range results {
		if !r.Success {
			failedCount++
		}
	}

	if failedCount == len(results) {
		atomic.AddUint64(&hc.failedChecks, 1)
	}

	// Update health state.
	hc.mu.Lock()
	health = hc.healthState[wanID]
	if health == nil {
		hc.mu.Unlock()
		return ErrWANNotFound
	}

	oldState := health.State
	health.HealthScore = score
	health.Latency = latency
	health.PacketLoss = packetLoss
	health.Jitter = jitter
	health.LastCheckTime = time.Now()

	// Add results to history (keep last 60).
	health.CheckResults = append(health.CheckResults, results...)
	if len(health.CheckResults) > 60 {
		health.CheckResults = health.CheckResults[len(health.CheckResults)-60:]
	}

	// Evaluate state transition.
	hc.evaluateStateTransition(health, failedCount == len(results))

	newState := health.State
	hc.mu.Unlock()

	// Notify subscribers if state changed.
	if oldState != newState {
		atomic.AddUint64(&hc.stateChanges, 1)
		hc.notifyStateChange(wanID, oldState, newState)
	}

	// Notify health update.
	hc.notifyHealthUpdate(wanID, health)

	return nil
}

// buildTargets builds health check targets.
func (hc *HealthChecker) buildTargets(wanID string) []HealthTarget {
	targets := make([]HealthTarget, 0, len(hc.config.HealthTargets))

	// Add configured targets.
	for _, t := range hc.config.HealthTargets {
		if t.Enabled {
			targets = append(targets, t)
		}
	}

	// Add gateway target if available.
	if hc.wanSelector != nil {
		wan, err := hc.wanSelector.GetWANByID(wanID)
		if err == nil && wan.InterfaceName != "" {
			targets = append(targets, HealthTarget{
				Type:     TargetGateway,
				Address:  "8.8.8.8", // Default to public DNS for gateway check.
				Port:     53,
				Protocol: "tcp",
				Weight:   0.5,
				Enabled:  true,
			})
		}
	}

	return targets
}

// performCheck executes a single health check.
func (hc *HealthChecker) performCheck(target HealthTarget, wanID string) *CheckResult {
	_ = wanID // Will be used for interface binding.

	ctx, cancel := context.WithTimeout(context.Background(), hc.config.CheckTimeout)
	defer cancel()

	var result *CheckResult
	switch target.Protocol {
	case "tcp":
		result = hc.performTCPCheck(ctx, target)
	case "http", "https":
		result = hc.performHTTPCheck(ctx, target)
	case "dns":
		result = hc.performDNSCheck(ctx, target)
	default:
		result = hc.performTCPCheck(ctx, target)
	}

	return result
}

// performTCPCheck performs TCP connection test.
func (hc *HealthChecker) performTCPCheck(ctx context.Context, target HealthTarget) *CheckResult {
	result := &CheckResult{
		Timestamp: time.Now(),
		Target:    target,
	}

	address := target.Address
	if target.Port > 0 {
		address = net.JoinHostPort(target.Address, formatInt(target.Port))
	}

	dialer := &net.Dialer{
		Timeout: hc.config.CheckTimeout,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	latency := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Latency = latency
	} else {
		conn.Close()
		result.Success = true
		result.Latency = latency
	}

	return result
}

// performHTTPCheck performs HTTP GET request.
func (hc *HealthChecker) performHTTPCheck(ctx context.Context, target HealthTarget) *CheckResult {
	result := &CheckResult{
		Timestamp: time.Now(),
		Target:    target,
	}

	client := &http.Client{
		Timeout: hc.config.CheckTimeout,
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.Address, nil)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Latency = latency
	} else {
		defer resp.Body.Close()
		result.Latency = latency
		result.ResponseCode = resp.StatusCode
		result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
		if !result.Success {
			result.Error = resp.Status
		}
	}

	return result
}

// performDNSCheck performs DNS resolution test.
func (hc *HealthChecker) performDNSCheck(ctx context.Context, target HealthTarget) *CheckResult {
	result := &CheckResult{
		Timestamp: time.Now(),
		Target:    target,
	}

	resolver := &net.Resolver{
		PreferGo: true,
	}

	start := time.Now()
	_, err := resolver.LookupHost(ctx, target.Address)
	latency := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Latency = latency
	} else {
		result.Success = true
		result.Latency = latency
	}

	return result
}

// =============================================================================
// Metrics Calculation
// =============================================================================

// calculateMetrics calculates health metrics from check results.
func (hc *HealthChecker) calculateMetrics(results []*CheckResult) (score float64, avgLatency time.Duration, packetLoss float64, jitter time.Duration) {
	if len(results) == 0 {
		return 0, 0, 100, 0
	}

	var totalLatency time.Duration
	var successCount int
	latencies := make([]time.Duration, 0, len(results))

	for _, r := range results {
		if r.Success {
			successCount++
			totalLatency += r.Latency
			latencies = append(latencies, r.Latency)
		}
	}

	// Calculate packet loss.
	packetLoss = float64(len(results)-successCount) / float64(len(results)) * 100.0

	// Calculate average latency.
	if successCount > 0 {
		avgLatency = totalLatency / time.Duration(successCount)
	}

	// Calculate jitter.
	if len(latencies) >= 2 {
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
		jitter = time.Duration(math.Sqrt(variance))
	}

	// Calculate score.
	score = hc.calculateHealthScore(avgLatency, packetLoss, jitter)

	return score, avgLatency, packetLoss, jitter
}

// calculateHealthScore computes normalized health score.
func (hc *HealthChecker) calculateHealthScore(latency time.Duration, packetLoss float64, jitter time.Duration) float64 {
	// Latency score: 100 at 0ms, 0 at 200ms+
	latencyMs := float64(latency.Milliseconds())
	latencyScore := math.Max(0, 100-(latencyMs/2))

	// Packet loss score: 100 at 0%, 0 at 100%
	lossScore := 100 - packetLoss

	// Jitter score: 100 at 0ms, 0 at 50ms+
	jitterMs := float64(jitter.Milliseconds())
	jitterScore := math.Max(0, 100-(jitterMs*2))

	// Weighted combination.
	score := (latencyScore * hc.config.LatencyWeight) +
		(lossScore * hc.config.PacketLossWeight) +
		(jitterScore * hc.config.JitterWeight)

	return math.Max(0, math.Min(100, score))
}

// =============================================================================
// State Transition
// =============================================================================

// evaluateStateTransition determines if health state should change.
func (hc *HealthChecker) evaluateStateTransition(health *WANHealth, allFailed bool) {
	// Determine target state based on score.
	var targetState HealthState
	if health.HealthScore >= 70 {
		targetState = HealthStateUp
	} else if health.HealthScore >= 40 {
		targetState = HealthStateDegraded
	} else {
		targetState = HealthStateDown
	}

	// Handle consecutive failures/successes.
	if allFailed {
		health.ConsecutiveFailures++
		health.ConsecutiveSuccesses = 0
	} else {
		health.ConsecutiveSuccesses++
		health.ConsecutiveFailures = 0
	}

	// Apply hysteresis.
	oldState := health.State

	if health.ConsecutiveFailures >= hc.config.FailureThreshold {
		targetState = HealthStateDown
	}

	if oldState == HealthStateDown && health.ConsecutiveSuccesses < hc.config.RecoveryThreshold {
		// Stay down until recovery threshold met.
		targetState = HealthStateDown
	}

	// Transition if state changed.
	if targetState != oldState {
		health.State = targetState
		health.LastStateChange = time.Now()
		health.StateChangeCount++
	}
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for health events.
func (hc *HealthChecker) Subscribe(subscriber HealthSubscriber) {
	hc.subscribersMu.Lock()
	defer hc.subscribersMu.Unlock()
	hc.subscribers = append(hc.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (hc *HealthChecker) Unsubscribe(subscriber HealthSubscriber) {
	hc.subscribersMu.Lock()
	defer hc.subscribersMu.Unlock()

	for i, s := range hc.subscribers {
		if s == subscriber {
			hc.subscribers = append(hc.subscribers[:i], hc.subscribers[i+1:]...)
			return
		}
	}
}

// notifyHealthUpdate notifies subscribers of health update.
func (hc *HealthChecker) notifyHealthUpdate(wanID string, health *WANHealth) {
	hc.subscribersMu.RLock()
	subscribers := make([]HealthSubscriber, len(hc.subscribers))
	copy(subscribers, hc.subscribers)
	hc.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s HealthSubscriber) {
			_ = s.OnHealthUpdate(wanID, health)
		}(sub)
	}
}

// notifyStateChange notifies subscribers of state change.
func (hc *HealthChecker) notifyStateChange(wanID string, oldState, newState HealthState) {
	hc.subscribersMu.RLock()
	subscribers := make([]HealthSubscriber, len(hc.subscribers))
	copy(subscribers, hc.subscribers)
	hc.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s HealthSubscriber) {
			_ = s.OnStateChange(wanID, oldState, newState)
		}(sub)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetWANHealth retrieves health state for specific WAN.
func (hc *HealthChecker) GetWANHealth(wanID string) (*WANHealth, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	health, exists := hc.healthState[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	// Return copy.
	copy := *health
	copy.CheckResults = make([]*CheckResult, len(health.CheckResults))
	for i, r := range health.CheckResults {
		resultCopy := *r
		copy.CheckResults[i] = &resultCopy
	}

	return &copy, nil
}

// GetAllHealthStates retrieves health for all WANs.
func (hc *HealthChecker) GetAllHealthStates() map[string]*WANHealth {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	result := make(map[string]*WANHealth, len(hc.healthState))
	for wanID, health := range hc.healthState {
		copy := *health
		result[wanID] = &copy
	}
	return result
}

// ForceHealthCheck triggers immediate health check for WAN.
func (hc *HealthChecker) ForceHealthCheck(wanID string) error {
	hc.mu.RLock()
	_, exists := hc.healthState[wanID]
	hc.mu.RUnlock()

	if !exists {
		return ErrWANNotFound
	}

	return hc.checkWANHealth(wanID)
}

// =============================================================================
// Override Management
// =============================================================================

// SetHealthOverride manually sets WAN health state.
func (hc *HealthChecker) SetHealthOverride(wanID string, score float64, duration time.Duration) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	health, exists := hc.healthState[wanID]
	if !exists {
		return ErrWANNotFound
	}

	health.HealthScore = score
	health.OverrideActive = true
	if duration > 0 {
		health.OverrideExpires = time.Now().Add(duration)
	} else {
		health.OverrideExpires = time.Time{} // Permanent until cleared.
	}

	// Update state based on score.
	if score >= 70 {
		health.State = HealthStateUp
	} else if score >= 40 {
		health.State = HealthStateDegraded
	} else {
		health.State = HealthStateDown
	}

	return nil
}

// ClearHealthOverride removes manual health override.
func (hc *HealthChecker) ClearHealthOverride(wanID string) error {
	hc.mu.Lock()
	health, exists := hc.healthState[wanID]
	if !exists {
		hc.mu.Unlock()
		return ErrWANNotFound
	}

	health.OverrideActive = false
	health.OverrideExpires = time.Time{}
	hc.mu.Unlock()

	// Perform immediate check.
	return hc.checkWANHealth(wanID)
}

// GetHealthHistory retrieves historical check results.
func (hc *HealthChecker) GetHealthHistory(wanID string, since time.Time) ([]*CheckResult, error) {
	return hc.db.LoadHealthHistory(context.Background(), wanID, since)
}

// =============================================================================
// WAN Management
// =============================================================================

// AddWAN adds a WAN for health monitoring.
func (hc *HealthChecker) AddWAN(wanID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if _, exists := hc.healthState[wanID]; exists {
		return nil
	}

	hc.healthState[wanID] = &WANHealth{
		WANID:        wanID,
		HealthScore:  100.0,
		State:        HealthStateUnknown,
		CheckResults: make([]*CheckResult, 0, 60),
	}

	return nil
}

// RemoveWAN removes a WAN from health monitoring.
func (hc *HealthChecker) RemoveWAN(wanID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	delete(hc.healthState, wanID)
	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the checker is operational.
func (hc *HealthChecker) HealthCheck() error {
	hc.runningMu.Lock()
	running := hc.running
	hc.runningMu.Unlock()

	if !running {
		return errors.New("health checker not running")
	}

	// Check at least one WAN being monitored.
	hc.mu.RLock()
	count := len(hc.healthState)
	hc.mu.RUnlock()

	if count == 0 {
		return ErrNoHealthTargets
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns health checker statistics.
func (hc *HealthChecker) GetStatistics() map[string]interface{} {
	return map[string]interface{}{
		"total_checks":   atomic.LoadUint64(&hc.totalChecks),
		"failed_checks":  atomic.LoadUint64(&hc.failedChecks),
		"state_changes":  atomic.LoadUint64(&hc.stateChanges),
		"monitored_wans": len(hc.healthState),
	}
}

// =============================================================================
// Utility
// =============================================================================

// formatInt converts int to string.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	return formatIntInner(n)
}

func formatIntInner(n int) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	return formatIntInner(n/10) + string('0'+byte(n%10))
}

// GetConfig returns the current configuration.
func (hc *HealthChecker) GetConfig() *HealthConfig {
	return hc.config
}

// IsRunning returns whether the checker is running.
func (hc *HealthChecker) IsRunning() bool {
	hc.runningMu.Lock()
	defer hc.runningMu.Unlock()
	return hc.running
}
