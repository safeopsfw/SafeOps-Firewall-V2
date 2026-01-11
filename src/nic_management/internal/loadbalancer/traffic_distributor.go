// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrFlowNotFound indicates flow ID not in registry.
	ErrFlowNotFound = errors.New("flow not found")
	// ErrNATTimeout indicates NAT translation exceeded timeout.
	ErrNATTimeout = errors.New("NAT translation timeout")
	// ErrNoAvailableWAN indicates no WANs meet selection criteria.
	ErrNoAvailableWAN = errors.New("no available WAN")
	// ErrPreemptionFailed indicates flow reassignment failed.
	ErrPreemptionFailed = errors.New("flow preemption failed")
	// ErrRegistryFull indicates flow registry at capacity.
	ErrRegistryFull = errors.New("flow registry full")
)

// =============================================================================
// Flow State
// =============================================================================

// FlowState represents the lifecycle state of a flow.
type FlowState int

const (
	// FlowStateNew indicates flow just discovered.
	FlowStateNew FlowState = iota
	// FlowStateEstablished indicates flow active.
	FlowStateEstablished
	// FlowStateClosing indicates flow termination detected.
	FlowStateClosing
	// FlowStateClosed indicates flow terminated.
	FlowStateClosed
)

// String returns the string representation of the flow state.
func (s FlowState) String() string {
	switch s {
	case FlowStateNew:
		return "NEW"
	case FlowStateEstablished:
		return "ESTABLISHED"
	case FlowStateClosing:
		return "CLOSING"
	case FlowStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Flow Assignment
// =============================================================================

// FlowAssignment represents a network flow assigned to a WAN.
type FlowAssignment struct {
	// FlowID is the unique flow identifier.
	FlowID string `json:"flow_id"`
	// FiveTuple is the flow identifier.
	FiveTuple FiveTuple `json:"five_tuple"`
	// AssignedWAN is the WAN ID handling this flow.
	AssignedWAN string `json:"assigned_wan"`
	// NATMappingID is the NAT mapping identifier.
	NATMappingID string `json:"nat_mapping_id"`
	// AssignedAt is when the flow was assigned.
	AssignedAt time.Time `json:"assigned_at"`
	// LastActivity is the last packet timestamp.
	LastActivity time.Time `json:"last_activity"`
	// PacketCount is the total packets in flow.
	PacketCount uint64 `json:"packet_count"`
	// ByteCount is the total bytes in flow.
	ByteCount uint64 `json:"byte_count"`
	// State is the current flow state.
	State FlowState `json:"state"`
	// Reason is the assignment reason.
	Reason string `json:"reason"`
}

// =============================================================================
// Distribution Statistics
// =============================================================================

// DistributionStatistics contains real-time distribution metrics.
type DistributionStatistics struct {
	// TotalFlowsDistributed is total flows assigned since startup.
	TotalFlowsDistributed uint64 `json:"total_flows_distributed"`
	// ActiveFlows is the currently active flows.
	ActiveFlows int `json:"active_flows"`
	// FlowsPerWAN is active flows per WAN.
	FlowsPerWAN map[string]int `json:"flows_per_wan"`
	// BytesPerWAN is total bytes routed per WAN.
	BytesPerWAN map[string]uint64 `json:"bytes_per_wan"`
	// PacketsPerWAN is total packets routed per WAN.
	PacketsPerWAN map[string]uint64 `json:"packets_per_wan"`
	// AverageSelectionLatency is the mean WAN selection time.
	AverageSelectionLatency time.Duration `json:"average_selection_latency"`
	// AverageNATLatency is the mean NAT translation time.
	AverageNATLatency time.Duration `json:"average_nat_latency"`
	// SelectionFailures is the failed WAN selections.
	SelectionFailures uint64 `json:"selection_failures"`
	// NATFailures is the failed NAT translations.
	NATFailures uint64 `json:"nat_failures"`
	// PreemptedFlows is the flows reassigned due to degradation.
	PreemptedFlows uint64 `json:"preempted_flows"`
	// LastUpdate is when stats were last recalculated.
	LastUpdate time.Time `json:"last_update"`
}

// =============================================================================
// WAN Distribution
// =============================================================================

// WANDistribution contains per-WAN distribution breakdown.
type WANDistribution struct {
	// WANID is the WAN identifier.
	WANID string `json:"wan_id"`
	// ActiveFlows is the current flow count.
	ActiveFlows int `json:"active_flows"`
	// TotalBytes is the bytes routed.
	TotalBytes uint64 `json:"total_bytes"`
	// TotalPackets is the packets routed.
	TotalPackets uint64 `json:"total_packets"`
	// PercentageOfTraffic is the traffic percentage.
	PercentageOfTraffic float64 `json:"percentage_of_traffic"`
}

// =============================================================================
// Distributor Configuration
// =============================================================================

// DistributorConfig contains configuration for the traffic distributor.
type DistributorConfig struct {
	// SelectionTimeout is the max time for WAN selection.
	SelectionTimeout time.Duration `json:"selection_timeout"`
	// NATTimeout is the max time for NAT translation.
	NATTimeout time.Duration `json:"nat_timeout"`
	// FlowRegistryCapacity is the max tracked flows.
	FlowRegistryCapacity int `json:"flow_registry_capacity"`
	// EnableFlowPersistence saves flows to database.
	EnableFlowPersistence bool `json:"enable_flow_persistence"`
	// PersistenceInterval is the flow sync frequency.
	PersistenceInterval time.Duration `json:"persistence_interval"`
	// EnablePreemption allows WAN reassignment on degradation.
	EnablePreemption bool `json:"enable_preemption"`
	// PreemptionHealthThreshold is the health triggering preemption.
	PreemptionHealthThreshold float64 `json:"preemption_health_threshold"`
	// StaleFlowTimeout removes inactive flows after this duration.
	StaleFlowTimeout time.Duration `json:"stale_flow_timeout"`
	// EnableRealTimeStats updates stats continuously.
	EnableRealTimeStats bool `json:"enable_real_time_stats"`
	// StatsUpdateInterval is the stats recalculation frequency.
	StatsUpdateInterval time.Duration `json:"stats_update_interval"`
}

// DefaultDistributorConfig returns the default configuration.
func DefaultDistributorConfig() *DistributorConfig {
	return &DistributorConfig{
		SelectionTimeout:          100 * time.Millisecond,
		NATTimeout:                50 * time.Millisecond,
		FlowRegistryCapacity:      1000000,
		EnableFlowPersistence:     true,
		PersistenceInterval:       60 * time.Second,
		EnablePreemption:          false,
		PreemptionHealthThreshold: 30.0,
		StaleFlowTimeout:          600 * time.Second,
		EnableRealTimeStats:       true,
		StatsUpdateInterval:       5 * time.Second,
	}
}

// =============================================================================
// Database Interface
// =============================================================================

// DistributorDB defines the database interface for flow persistence.
type DistributorDB interface {
	// LoadFlows loads active flows from database.
	LoadFlows(ctx context.Context) ([]*FlowAssignment, error)
	// SaveFlows saves flows to database.
	SaveFlows(ctx context.Context, flows []*FlowAssignment) error
	// DeleteFlow removes a flow from database.
	DeleteFlow(ctx context.Context, flowID string) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpDistributorDB struct{}

func (n *noOpDistributorDB) LoadFlows(ctx context.Context) ([]*FlowAssignment, error) {
	return nil, nil
}

func (n *noOpDistributorDB) SaveFlows(ctx context.Context, flows []*FlowAssignment) error {
	return nil
}

func (n *noOpDistributorDB) DeleteFlow(ctx context.Context, flowID string) error {
	return nil
}

// =============================================================================
// Traffic Distributor
// =============================================================================

// TrafficDistributor manages flow distribution across WANs.
type TrafficDistributor struct {
	// Routing algorithm for WAN selection.
	algorithm *RoutingAlgorithm
	// WAN pool manager.
	wanSelector *WANSelector
	// Database for flow persistence.
	db DistributorDB
	// Configuration.
	config *DistributorConfig
	// Active flow assignments.
	flowRegistry map[string]*FlowAssignment
	// Protects flowRegistry.
	mu sync.RWMutex
	// Real-time statistics.
	stats *DistributionStatistics
	// Statistics counters.
	totalFlowsDistributed uint64
	selectionFailures     uint64
	natFailures           uint64
	preemptedFlows        uint64
	// Latency tracking.
	selectionLatencySum   int64
	selectionLatencyCount int64
	natLatencySum         int64
	natLatencyCount       int64
	// Flow ID counter.
	flowCounter uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewTrafficDistributor creates a new traffic distributor.
func NewTrafficDistributor(algorithm *RoutingAlgorithm, wanSelector *WANSelector, db DistributorDB, config *DistributorConfig) *TrafficDistributor {
	if config == nil {
		config = DefaultDistributorConfig()
	}

	if db == nil {
		db = &noOpDistributorDB{}
	}

	return &TrafficDistributor{
		algorithm:    algorithm,
		wanSelector:  wanSelector,
		db:           db,
		config:       config,
		flowRegistry: make(map[string]*FlowAssignment, config.FlowRegistryCapacity),
		stats: &DistributionStatistics{
			FlowsPerWAN:   make(map[string]int),
			BytesPerWAN:   make(map[string]uint64),
			PacketsPerWAN: make(map[string]uint64),
		},
		stopChan: make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the traffic distributor.
func (td *TrafficDistributor) Start(ctx context.Context) error {
	td.runningMu.Lock()
	defer td.runningMu.Unlock()

	if td.running {
		return nil
	}

	// Load persisted flows.
	if td.config.EnableFlowPersistence {
		flows, _ := td.db.LoadFlows(ctx)
		for _, flow := range flows {
			td.flowRegistry[flow.FlowID] = flow
		}
	}

	// Start statistics update goroutine.
	if td.config.EnableRealTimeStats {
		td.wg.Add(1)
		go td.statsLoop()
	}

	// Start flow persistence goroutine.
	if td.config.EnableFlowPersistence {
		td.wg.Add(1)
		go td.persistenceLoop()
	}

	// Start stale flow cleanup goroutine.
	td.wg.Add(1)
	go td.cleanupLoop()

	// Start preemption monitor goroutine.
	if td.config.EnablePreemption {
		td.wg.Add(1)
		go td.preemptionLoop()
	}

	td.running = true
	return nil
}

// Stop stops the traffic distributor.
func (td *TrafficDistributor) Stop() error {
	td.runningMu.Lock()
	if !td.running {
		td.runningMu.Unlock()
		return nil
	}
	td.running = false
	td.runningMu.Unlock()

	close(td.stopChan)
	td.wg.Wait()

	// Final persistence.
	if td.config.EnableFlowPersistence {
		td.persistFlows()
	}

	return nil
}

// =============================================================================
// Background Loops
// =============================================================================

// statsLoop periodically updates statistics.
func (td *TrafficDistributor) statsLoop() {
	defer td.wg.Done()

	ticker := time.NewTicker(td.config.StatsUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.updateStatistics()
		}
	}
}

// persistenceLoop periodically persists flows.
func (td *TrafficDistributor) persistenceLoop() {
	defer td.wg.Done()

	ticker := time.NewTicker(td.config.PersistenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.persistFlows()
		}
	}
}

// cleanupLoop periodically cleans stale flows.
func (td *TrafficDistributor) cleanupLoop() {
	defer td.wg.Done()

	interval := td.config.StaleFlowTimeout / 2
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.cleanupStaleFlows()
		}
	}
}

// preemptionLoop monitors WAN health for preemption.
func (td *TrafficDistributor) preemptionLoop() {
	defer td.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.checkPreemption()
		}
	}
}

// =============================================================================
// Flow Distribution
// =============================================================================

// DistributeFlow assigns a new flow to a WAN.
func (td *TrafficDistributor) DistributeFlow(ctx context.Context, flow FiveTuple) (*FlowAssignment, error) {
	// Check registry capacity.
	td.mu.RLock()
	if len(td.flowRegistry) >= td.config.FlowRegistryCapacity {
		td.mu.RUnlock()
		return nil, ErrRegistryFull
	}
	td.mu.RUnlock()

	// Timeout context for selection.
	selCtx, selCancel := context.WithTimeout(ctx, td.config.SelectionTimeout)
	defer selCancel()

	// Select WAN using algorithm.
	selStart := time.Now()
	decision, err := td.algorithm.SelectWAN(selCtx, flow)
	selLatency := time.Since(selStart)

	// Track selection latency.
	atomic.AddInt64(&td.selectionLatencySum, int64(selLatency))
	atomic.AddInt64(&td.selectionLatencyCount, 1)

	if err != nil {
		atomic.AddUint64(&td.selectionFailures, 1)
		return nil, err
	}

	// Validate WAN availability.
	wan, err := td.wanSelector.GetWANByID(decision.SelectedWAN)
	if err != nil {
		atomic.AddUint64(&td.selectionFailures, 1)
		return nil, ErrNoAvailableWAN
	}

	if wan.State != StateEnabled && wan.State != StateDegraded {
		atomic.AddUint64(&td.selectionFailures, 1)
		return nil, ErrNoAvailableWAN
	}

	// Create NAT mapping (simulated - would call actual NAT translator).
	natStart := time.Now()
	natMappingID := td.generateNATMappingID(flow, decision.SelectedWAN)
	natLatency := time.Since(natStart)

	// Track NAT latency.
	atomic.AddInt64(&td.natLatencySum, int64(natLatency))
	atomic.AddInt64(&td.natLatencyCount, 1)

	// Generate flow ID.
	flowID := td.generateFlowID()

	// Create flow assignment.
	now := time.Now()
	assignment := &FlowAssignment{
		FlowID:       flowID,
		FiveTuple:    flow,
		AssignedWAN:  decision.SelectedWAN,
		NATMappingID: natMappingID,
		AssignedAt:   now,
		LastActivity: now,
		PacketCount:  0,
		ByteCount:    0,
		State:        FlowStateEstablished,
		Reason:       decision.Reason,
	}

	// Register flow.
	td.mu.Lock()
	td.flowRegistry[flowID] = assignment
	td.mu.Unlock()

	// Update counters.
	atomic.AddUint64(&td.totalFlowsDistributed, 1)

	return assignment, nil
}

// ReleaseFlow removes a flow assignment.
func (td *TrafficDistributor) ReleaseFlow(flowID string) error {
	td.mu.Lock()
	flow, exists := td.flowRegistry[flowID]
	if !exists {
		td.mu.Unlock()
		return ErrFlowNotFound
	}

	flow.State = FlowStateClosed
	delete(td.flowRegistry, flowID)
	td.mu.Unlock()

	// Decrement WAN connection counter.
	if td.algorithm != nil {
		td.algorithm.DecrementConnections(flow.AssignedWAN)
	}

	// Remove from database.
	if td.config.EnableFlowPersistence {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = td.db.DeleteFlow(ctx, flowID)
	}

	return nil
}

// UpdateFlowActivity records packet activity for a flow.
func (td *TrafficDistributor) UpdateFlowActivity(flowID string, packetSize uint64) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	flow, exists := td.flowRegistry[flowID]
	if !exists {
		return ErrFlowNotFound
	}

	flow.LastActivity = time.Now()
	flow.PacketCount++
	flow.ByteCount += packetSize

	return nil
}

// GetFlowAssignment retrieves a flow assignment.
func (td *TrafficDistributor) GetFlowAssignment(flowID string) (*FlowAssignment, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	flow, exists := td.flowRegistry[flowID]
	if !exists {
		return nil, ErrFlowNotFound
	}

	// Return copy.
	copy := *flow
	return &copy, nil
}

// GetFlowsByWAN retrieves all flows for a WAN.
func (td *TrafficDistributor) GetFlowsByWAN(wanID string) []*FlowAssignment {
	td.mu.RLock()
	defer td.mu.RUnlock()

	result := make([]*FlowAssignment, 0)
	for _, flow := range td.flowRegistry {
		if flow.AssignedWAN == wanID {
			copy := *flow
			result = append(result, &copy)
		}
	}
	return result
}

// =============================================================================
// Flow Preemption
// =============================================================================

// PreemptFlow reassigns a flow to a different WAN.
func (td *TrafficDistributor) PreemptFlow(flowID, newWANID, reason string) error {
	td.mu.Lock()
	flow, exists := td.flowRegistry[flowID]
	if !exists {
		td.mu.Unlock()
		return ErrFlowNotFound
	}

	oldWANID := flow.AssignedWAN

	// Validate new WAN.
	newWAN, err := td.wanSelector.GetWANByID(newWANID)
	if err != nil {
		td.mu.Unlock()
		return ErrPreemptionFailed
	}

	if newWAN.State != StateEnabled && newWAN.State != StateDegraded {
		td.mu.Unlock()
		return ErrPreemptionFailed
	}

	// Update assignment.
	flow.AssignedWAN = newWANID
	flow.NATMappingID = td.generateNATMappingID(flow.FiveTuple, newWANID)
	flow.Reason = reason
	td.mu.Unlock()

	// Update algorithm counters.
	if td.algorithm != nil {
		td.algorithm.DecrementConnections(oldWANID)
		td.algorithm.IncrementConnections(newWANID)
	}

	// Invalidate session affinity.
	if td.algorithm != nil {
		td.algorithm.RemoveSessionAffinity(flow.FiveTuple)
	}

	atomic.AddUint64(&td.preemptedFlows, 1)

	return nil
}

// checkPreemption monitors WAN health and reassigns flows.
func (td *TrafficDistributor) checkPreemption() {
	if td.wanSelector == nil || td.algorithm == nil {
		return
	}

	td.mu.RLock()
	flowIDs := make([]string, 0, len(td.flowRegistry))
	wanIDs := make(map[string]bool)
	for flowID, flow := range td.flowRegistry {
		flowIDs = append(flowIDs, flowID)
		wanIDs[flow.AssignedWAN] = true
	}
	td.mu.RUnlock()

	// Check health of WANs with active flows.
	degradedWANs := make(map[string]bool)
	for wanID := range wanIDs {
		wan, err := td.wanSelector.GetWANByID(wanID)
		if err != nil || wan.HealthScore < td.config.PreemptionHealthThreshold {
			degradedWANs[wanID] = true
		}
	}

	// Preempt flows from degraded WANs.
	for _, flowID := range flowIDs {
		td.mu.RLock()
		flow, exists := td.flowRegistry[flowID]
		if !exists {
			td.mu.RUnlock()
			continue
		}
		wanID := flow.AssignedWAN
		fiveTuple := flow.FiveTuple
		td.mu.RUnlock()

		if degradedWANs[wanID] {
			// Find better WAN.
			ctx := context.Background()
			decision, err := td.algorithm.SelectWAN(ctx, fiveTuple)
			if err == nil && decision.SelectedWAN != wanID {
				_ = td.PreemptFlow(flowID, decision.SelectedWAN, "HEALTH_DEGRADATION")
			}
		}
	}
}

// =============================================================================
// WAN Draining
// =============================================================================

// DrainWAN migrates all flows from a WAN.
func (td *TrafficDistributor) DrainWAN(wanID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		flows := td.GetFlowsByWAN(wanID)
		if len(flows) == 0 {
			return nil
		}

		for _, flow := range flows {
			// Find alternative WAN.
			ctx := context.Background()
			decision, err := td.algorithm.SelectWAN(ctx, flow.FiveTuple)
			if err != nil || decision.SelectedWAN == wanID {
				continue
			}

			_ = td.PreemptFlow(flow.FlowID, decision.SelectedWAN, "WAN_DRAIN")
		}

		time.Sleep(1 * time.Second)
	}

	// Check if flows remain.
	flows := td.GetFlowsByWAN(wanID)
	if len(flows) > 0 {
		return ErrDrainTimeout
	}

	return nil
}

// ForceReassignAll reassigns all flows.
func (td *TrafficDistributor) ForceReassignAll() error {
	td.mu.RLock()
	flowIDs := make([]string, 0, len(td.flowRegistry))
	for flowID := range td.flowRegistry {
		flowIDs = append(flowIDs, flowID)
	}
	td.mu.RUnlock()

	for _, flowID := range flowIDs {
		td.mu.RLock()
		flow, exists := td.flowRegistry[flowID]
		if !exists {
			td.mu.RUnlock()
			continue
		}
		fiveTuple := flow.FiveTuple
		td.mu.RUnlock()

		ctx := context.Background()
		decision, err := td.algorithm.SelectWAN(ctx, fiveTuple)
		if err == nil {
			_ = td.PreemptFlow(flowID, decision.SelectedWAN, "FORCE_REASSIGN")
		}
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// updateStatistics recalculates distribution statistics.
func (td *TrafficDistributor) updateStatistics() {
	td.mu.RLock()
	defer td.mu.RUnlock()

	flowsPerWAN := make(map[string]int)
	bytesPerWAN := make(map[string]uint64)
	packetsPerWAN := make(map[string]uint64)

	for _, flow := range td.flowRegistry {
		flowsPerWAN[flow.AssignedWAN]++
		bytesPerWAN[flow.AssignedWAN] += flow.ByteCount
		packetsPerWAN[flow.AssignedWAN] += flow.PacketCount
	}

	// Calculate average latencies.
	var avgSelectionLatency, avgNATLatency time.Duration
	selCount := atomic.LoadInt64(&td.selectionLatencyCount)
	if selCount > 0 {
		avgSelectionLatency = time.Duration(atomic.LoadInt64(&td.selectionLatencySum) / selCount)
	}
	natCount := atomic.LoadInt64(&td.natLatencyCount)
	if natCount > 0 {
		avgNATLatency = time.Duration(atomic.LoadInt64(&td.natLatencySum) / natCount)
	}

	td.stats = &DistributionStatistics{
		TotalFlowsDistributed:   atomic.LoadUint64(&td.totalFlowsDistributed),
		ActiveFlows:             len(td.flowRegistry),
		FlowsPerWAN:             flowsPerWAN,
		BytesPerWAN:             bytesPerWAN,
		PacketsPerWAN:           packetsPerWAN,
		AverageSelectionLatency: avgSelectionLatency,
		AverageNATLatency:       avgNATLatency,
		SelectionFailures:       atomic.LoadUint64(&td.selectionFailures),
		NATFailures:             atomic.LoadUint64(&td.natFailures),
		PreemptedFlows:          atomic.LoadUint64(&td.preemptedFlows),
		LastUpdate:              time.Now(),
	}
}

// GetStatistics returns current distribution statistics.
func (td *TrafficDistributor) GetStatistics() DistributionStatistics {
	td.mu.RLock()
	defer td.mu.RUnlock()

	if td.stats == nil {
		return DistributionStatistics{}
	}

	// Return copy.
	stats := *td.stats
	stats.FlowsPerWAN = make(map[string]int)
	stats.BytesPerWAN = make(map[string]uint64)
	stats.PacketsPerWAN = make(map[string]uint64)

	for k, v := range td.stats.FlowsPerWAN {
		stats.FlowsPerWAN[k] = v
	}
	for k, v := range td.stats.BytesPerWAN {
		stats.BytesPerWAN[k] = v
	}
	for k, v := range td.stats.PacketsPerWAN {
		stats.PacketsPerWAN[k] = v
	}

	return stats
}

// GetPerWANDistribution returns per-WAN breakdown.
func (td *TrafficDistributor) GetPerWANDistribution() map[string]*WANDistribution {
	td.mu.RLock()
	defer td.mu.RUnlock()

	result := make(map[string]*WANDistribution)
	var totalBytes uint64

	for _, flow := range td.flowRegistry {
		if _, ok := result[flow.AssignedWAN]; !ok {
			result[flow.AssignedWAN] = &WANDistribution{
				WANID: flow.AssignedWAN,
			}
		}
		result[flow.AssignedWAN].ActiveFlows++
		result[flow.AssignedWAN].TotalBytes += flow.ByteCount
		result[flow.AssignedWAN].TotalPackets += flow.PacketCount
		totalBytes += flow.ByteCount
	}

	// Calculate percentages.
	for _, dist := range result {
		if totalBytes > 0 {
			dist.PercentageOfTraffic = float64(dist.TotalBytes) / float64(totalBytes) * 100.0
		}
	}

	return result
}

// =============================================================================
// Persistence
// =============================================================================

// persistFlows saves active flows to database.
func (td *TrafficDistributor) persistFlows() {
	td.mu.RLock()
	flows := make([]*FlowAssignment, 0, len(td.flowRegistry))
	for _, flow := range td.flowRegistry {
		copy := *flow
		flows = append(flows, &copy)
	}
	td.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = td.db.SaveFlows(ctx, flows)
}

// cleanupStaleFlows removes inactive flows.
func (td *TrafficDistributor) cleanupStaleFlows() {
	now := time.Now()
	staleIDs := make([]string, 0)

	td.mu.RLock()
	for flowID, flow := range td.flowRegistry {
		if now.Sub(flow.LastActivity) > td.config.StaleFlowTimeout {
			staleIDs = append(staleIDs, flowID)
		}
	}
	td.mu.RUnlock()

	for _, flowID := range staleIDs {
		_ = td.ReleaseFlow(flowID)
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the distributor is operational.
func (td *TrafficDistributor) HealthCheck() error {
	td.runningMu.Lock()
	running := td.running
	td.runningMu.Unlock()

	if !running {
		return errors.New("traffic distributor not running")
	}

	// Check algorithm.
	if td.algorithm != nil {
		if err := td.algorithm.HealthCheck(); err != nil {
			return err
		}
	}

	// Check WAN selector.
	if td.wanSelector != nil {
		if err := td.wanSelector.HealthCheck(); err != nil {
			return err
		}
	}

	// Check registry not full.
	td.mu.RLock()
	registrySize := len(td.flowRegistry)
	td.mu.RUnlock()

	if registrySize >= td.config.FlowRegistryCapacity {
		return ErrRegistryFull
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// generateFlowID generates a unique flow ID.
func (td *TrafficDistributor) generateFlowID() string {
	counter := atomic.AddUint64(&td.flowCounter, 1)
	return time.Now().Format("20060102150405") + "-" + formatUint64(counter)
}

// generateNATMappingID generates a NAT mapping ID.
func (td *TrafficDistributor) generateNATMappingID(flow FiveTuple, wanID string) string {
	return wanID + "-" + formatUint64(flow.Hash())
}

// formatUint64 converts uint64 to string.
func formatUint64(n uint64) string {
	return string('0' + byte(n%10))[:0] + formatUint64Inner(n)
}

func formatUint64Inner(n uint64) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	return formatUint64Inner(n/10) + string('0'+byte(n%10))
}

// GetConfig returns the current configuration.
func (td *TrafficDistributor) GetConfig() *DistributorConfig {
	return td.config
}

// IsRunning returns whether the distributor is running.
func (td *TrafficDistributor) IsRunning() bool {
	td.runningMu.Lock()
	defer td.runningMu.Unlock()
	return td.running
}

// GetActiveFlowCount returns the number of active flows.
func (td *TrafficDistributor) GetActiveFlowCount() int {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return len(td.flowRegistry)
}
