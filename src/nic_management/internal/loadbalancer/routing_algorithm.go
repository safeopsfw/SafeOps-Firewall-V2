// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

import (
	"context"
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrNoHealthyWANs indicates no WANs meet minimum health threshold.
	ErrNoHealthyWANs = errors.New("no healthy WANs available")
	// ErrAllWANsAtCapacity indicates all WANs at connection limit.
	ErrAllWANsAtCapacity = errors.New("all WANs at capacity")
	// ErrInvalidStrategy indicates unknown balancing strategy.
	ErrInvalidStrategy = errors.New("invalid balancing strategy")
	// ErrWANBlacklisted indicates selected WAN is blacklisted.
	ErrWANBlacklisted = errors.New("WAN is blacklisted")
	// ErrSelectionTimeout indicates WAN selection exceeded timeout.
	ErrSelectionTimeout = errors.New("WAN selection timeout")
)

// =============================================================================
// Balancing Strategy
// =============================================================================

// BalancingStrategy represents the load balancing algorithm type.
type BalancingStrategy int

const (
	// WeightedRoundRobin distributes proportionally to health scores.
	WeightedRoundRobin BalancingStrategy = iota
	// LeastConnections selects WAN with fewest active connections.
	LeastConnections
	// LatencyBased routes to lowest-latency WAN.
	LatencyBased
	// HashBased uses deterministic selection via flow hash.
	HashBased
	// Adaptive switches strategies based on network conditions.
	Adaptive
	// FailoverOnly uses simple primary/backup with no load distribution.
	FailoverOnly
)

// String returns the string representation of the strategy.
func (s BalancingStrategy) String() string {
	switch s {
	case WeightedRoundRobin:
		return "WEIGHTED_ROUND_ROBIN"
	case LeastConnections:
		return "LEAST_CONNECTIONS"
	case LatencyBased:
		return "LATENCY_BASED"
	case HashBased:
		return "HASH_BASED"
	case Adaptive:
		return "ADAPTIVE"
	case FailoverOnly:
		return "FAILOVER_ONLY"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Fallback Mode
// =============================================================================

// FallbackMode defines behavior when all WANs are unhealthy.
type FallbackMode int

const (
	// UseBestAvailable uses least-unhealthy WAN even if below threshold.
	UseBestAvailable FallbackMode = iota
	// RejectNewConnections refuses new connections.
	RejectNewConnections
	// RoundRobinAll distributes across all WANs ignoring health.
	RoundRobinAll
	// UsePrimaryOnly forces all traffic to primary WAN.
	UsePrimaryOnly
)

// String returns the string representation of the fallback mode.
func (m FallbackMode) String() string {
	switch m {
	case UseBestAvailable:
		return "USE_BEST_AVAILABLE"
	case RejectNewConnections:
		return "REJECT_NEW_CONNECTIONS"
	case RoundRobinAll:
		return "ROUND_ROBIN_ALL"
	case UsePrimaryOnly:
		return "USE_PRIMARY_ONLY"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Five-Tuple
// =============================================================================

// FiveTuple represents a flow identifier.
type FiveTuple struct {
	// SrcIP is the source IP address.
	SrcIP string
	// DstIP is the destination IP address.
	DstIP string
	// SrcPort is the source port.
	SrcPort uint16
	// DstPort is the destination port.
	DstPort uint16
	// Protocol is the IP protocol (6=TCP, 17=UDP, 1=ICMP).
	Protocol uint8
}

// Hash returns a 64-bit hash of the five-tuple.
func (f FiveTuple) Hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte(f.SrcIP))
	h.Write([]byte(f.DstIP))
	h.Write([]byte{byte(f.SrcPort >> 8), byte(f.SrcPort)})
	h.Write([]byte{byte(f.DstPort >> 8), byte(f.DstPort)})
	h.Write([]byte{f.Protocol})
	return h.Sum64()
}

// =============================================================================
// WAN Candidate
// =============================================================================

// WANCandidate represents an evaluated WAN with current metrics.
type WANCandidate struct {
	// WANID is the WAN identifier.
	WANID string
	// HealthScore is the current health (0-100).
	HealthScore float64
	// Weight is the calculated selection weight.
	Weight float64
	// ActiveConnections is the current connection count.
	ActiveConnections int
	// Latency is the current latency.
	Latency time.Duration
	// Capacity is the link bandwidth capacity.
	Capacity uint64
	// IsAvailable indicates whether WAN meets minimum criteria.
	IsAvailable bool
	// Priority is the manual priority override.
	Priority int
}

// =============================================================================
// Routing Decision
// =============================================================================

// RoutingDecision represents the WAN selection result.
type RoutingDecision struct {
	// SelectedWAN is the chosen WAN ID.
	SelectedWAN string
	// Reason is the selection reason code.
	Reason string
	// FallbackChain is the ordered list of backup WANs.
	FallbackChain []string
	// SessionAffinity indicates decision based on existing flow mapping.
	SessionAffinity bool
	// AlgorithmUsed is the strategy that made the decision.
	AlgorithmUsed BalancingStrategy
	// Timestamp is the decision timestamp.
	Timestamp time.Time
}

// =============================================================================
// Connection State
// =============================================================================

// ConnectionState tracks per-WAN connection state.
type ConnectionState struct {
	// WANID is the WAN identifier.
	WANID string
	// ActiveConnections is the current connection count.
	ActiveConnections int64
	// TotalConnections is the lifetime connection count.
	TotalConnections uint64
	// LastUpdate is when last updated.
	LastUpdate time.Time
}

// =============================================================================
// Algorithm Configuration
// =============================================================================

// AlgorithmConfig contains configuration for the routing algorithm.
type AlgorithmConfig struct {
	// Strategy is the default algorithm.
	Strategy BalancingStrategy
	// MinHealthScore is the minimum health to include WAN.
	MinHealthScore float64
	// SessionAffinityTimeout is the flow-to-WAN mapping timeout.
	SessionAffinityTimeout time.Duration
	// MaxConnectionsPerWAN is the per-WAN connection limit.
	MaxConnectionsPerWAN int
	// RebalanceInterval is the weight recalculation frequency.
	RebalanceInterval time.Duration
	// EnableStickySessions enables source IP affinity.
	EnableStickySessions bool
	// FallbackMode is the behavior when all WANs unhealthy.
	FallbackMode FallbackMode
	// HealthWeightExponent is the exponential weight scaling factor.
	HealthWeightExponent float64
	// EnableConnectionLimit enforces MaxConnectionsPerWAN.
	EnableConnectionLimit bool
}

// DefaultAlgorithmConfig returns the default configuration.
func DefaultAlgorithmConfig() *AlgorithmConfig {
	return &AlgorithmConfig{
		Strategy:               WeightedRoundRobin,
		MinHealthScore:         20.0,
		SessionAffinityTimeout: 300 * time.Second,
		MaxConnectionsPerWAN:   10000,
		RebalanceInterval:      10 * time.Second,
		EnableStickySessions:   true,
		FallbackMode:           UseBestAvailable,
		HealthWeightExponent:   1.0,
		EnableConnectionLimit:  true,
	}
}

// =============================================================================
// Algorithm Statistics
// =============================================================================

// AlgorithmStatistics contains algorithm performance stats.
type AlgorithmStatistics struct {
	// Strategy is the current strategy.
	Strategy BalancingStrategy
	// TotalSelections is the total WAN selections made.
	TotalSelections uint64
	// SessionCacheHitRate is the percentage of flows with affinity.
	SessionCacheHitRate float64
	// PerWANSelections is selections per WAN.
	PerWANSelections map[string]uint64
	// PerWANConnections is active connections per WAN.
	PerWANConnections map[string]int64
	// Weights is the current WAN weights.
	Weights map[string]float64
	// LastRebalance is when weights last updated.
	LastRebalance time.Time
	// FallbackCount is the total fallback invocations.
	FallbackCount uint64
	// BlacklistedWANs is the currently blacklisted WANs.
	BlacklistedWANs []string
}

// =============================================================================
// Session Cache Entry
// =============================================================================

type sessionCacheEntry struct {
	WANID     string
	ExpiresAt time.Time
}

// =============================================================================
// Routing Algorithm
// =============================================================================

// RoutingAlgorithm manages WAN selection for load balancing.
type RoutingAlgorithm struct {
	// Current strategy.
	strategy BalancingStrategy
	// Metrics provider.
	metricsCollector *MetricsCollector
	// Configuration.
	config *AlgorithmConfig
	// Per-WAN connection tracking.
	connectionState map[string]*ConnectionState
	connectionMu    sync.RWMutex
	// Session affinity cache.
	sessionCache   map[FiveTuple]*sessionCacheEntry
	sessionCacheMu sync.RWMutex
	// Pre-computed WAN weights.
	weights   map[string]float64
	weightsMu sync.RWMutex
	// Last rebalance time.
	lastRebalance time.Time
	// Round-robin counter.
	roundRobinIndex uint64
	// Blacklisted WANs.
	blacklist   map[string]time.Time
	blacklistMu sync.RWMutex
	// Manual weight overrides.
	manualWeights   map[string]float64
	manualWeightsMu sync.RWMutex
	// Statistics counters.
	totalSelections  uint64
	perWANSelections map[string]uint64
	sessionCacheHits uint64
	sessionCacheMiss uint64
	fallbackCount    uint64
	statsMu          sync.RWMutex
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewRoutingAlgorithm creates a new routing algorithm.
func NewRoutingAlgorithm(metricsCollector *MetricsCollector, config *AlgorithmConfig) *RoutingAlgorithm {
	if config == nil {
		config = DefaultAlgorithmConfig()
	}

	return &RoutingAlgorithm{
		strategy:         config.Strategy,
		metricsCollector: metricsCollector,
		config:           config,
		connectionState:  make(map[string]*ConnectionState),
		sessionCache:     make(map[FiveTuple]*sessionCacheEntry),
		weights:          make(map[string]float64),
		blacklist:        make(map[string]time.Time),
		manualWeights:    make(map[string]float64),
		perWANSelections: make(map[string]uint64),
		stopChan:         make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the routing algorithm.
func (ra *RoutingAlgorithm) Start(ctx context.Context) error {
	ra.runningMu.Lock()
	defer ra.runningMu.Unlock()

	if ra.running {
		return nil
	}

	// Initial weight calculation.
	ra.updateWeights()

	// Start weight recalculation goroutine.
	ra.wg.Add(1)
	go ra.rebalanceLoop()

	// Start session cache cleanup goroutine.
	ra.wg.Add(1)
	go ra.sessionCleanupLoop()

	ra.running = true
	return nil
}

// Stop stops the routing algorithm.
func (ra *RoutingAlgorithm) Stop() error {
	ra.runningMu.Lock()
	if !ra.running {
		ra.runningMu.Unlock()
		return nil
	}
	ra.running = false
	ra.runningMu.Unlock()

	close(ra.stopChan)
	ra.wg.Wait()

	return nil
}

// rebalanceLoop periodically recalculates weights.
func (ra *RoutingAlgorithm) rebalanceLoop() {
	defer ra.wg.Done()

	ticker := time.NewTicker(ra.config.RebalanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ra.stopChan:
			return
		case <-ticker.C:
			ra.updateWeights()
		}
	}
}

// sessionCleanupLoop periodically cleans expired session cache entries.
func (ra *RoutingAlgorithm) sessionCleanupLoop() {
	defer ra.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ra.stopChan:
			return
		case <-ticker.C:
			ra.cleanupSessionCache()
		}
	}
}

// cleanupSessionCache removes expired entries.
func (ra *RoutingAlgorithm) cleanupSessionCache() {
	ra.sessionCacheMu.Lock()
	defer ra.sessionCacheMu.Unlock()

	now := time.Now()
	for flow, entry := range ra.sessionCache {
		if now.After(entry.ExpiresAt) {
			delete(ra.sessionCache, flow)
		}
	}
}

// =============================================================================
// WAN Selection
// =============================================================================

// SelectWAN selects a WAN for a new connection.
func (ra *RoutingAlgorithm) SelectWAN(ctx context.Context, flow FiveTuple) (*RoutingDecision, error) {
	decision := &RoutingDecision{
		AlgorithmUsed: ra.strategy,
		Timestamp:     time.Now(),
	}

	// Step 1: Check session affinity.
	if ra.config.EnableStickySessions {
		if wanID, found := ra.getSessionAffinity(flow); found {
			if ra.isWANAvailable(wanID) {
				decision.SelectedWAN = wanID
				decision.Reason = "AFFINITY_MATCH"
				decision.SessionAffinity = true
				ra.recordSelection(wanID, true)
				return decision, nil
			}
		}
	}

	// Step 2: Get available candidates.
	candidates := ra.getAvailableCandidates()
	if len(candidates) == 0 {
		return ra.handleFallback(flow)
	}

	// Step 3: Apply strategy.
	selectedWAN, reason, err := ra.selectByStrategy(candidates, flow)
	if err != nil {
		return nil, err
	}

	decision.SelectedWAN = selectedWAN
	decision.Reason = reason

	// Step 4: Update session cache.
	if ra.config.EnableStickySessions {
		ra.setSessionAffinity(flow, selectedWAN)
	}

	// Step 5: Increment connection counter.
	ra.IncrementConnections(selectedWAN)

	// Step 6: Record selection.
	ra.recordSelection(selectedWAN, false)

	// Step 7: Build fallback chain.
	decision.FallbackChain = ra.buildFallbackChain(candidates, selectedWAN)

	return decision, nil
}

// =============================================================================
// Strategy Dispatcher
// =============================================================================

// selectByStrategy dispatches to specific algorithm implementation.
func (ra *RoutingAlgorithm) selectByStrategy(candidates []WANCandidate, flow FiveTuple) (string, string, error) {
	switch ra.strategy {
	case WeightedRoundRobin:
		return ra.selectWeightedRoundRobin(candidates)
	case LeastConnections:
		return ra.selectLeastConnections(candidates)
	case LatencyBased:
		return ra.selectLatencyBased(candidates)
	case HashBased:
		return ra.selectHashBased(candidates, flow)
	case Adaptive:
		return ra.selectAdaptive(candidates, flow)
	case FailoverOnly:
		return ra.selectFailoverOnly(candidates)
	default:
		return "", "", ErrInvalidStrategy
	}
}

// =============================================================================
// Weighted Round-Robin
// =============================================================================

// selectWeightedRoundRobin distributes proportionally to weights.
func (ra *RoutingAlgorithm) selectWeightedRoundRobin(candidates []WANCandidate) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	ra.weightsMu.RLock()
	defer ra.weightsMu.RUnlock()

	// Calculate cumulative weights.
	var totalWeight float64
	for _, c := range candidates {
		if w, ok := ra.weights[c.WANID]; ok {
			totalWeight += w
		}
	}

	if totalWeight == 0 {
		// Fall back to simple round-robin.
		idx := atomic.AddUint64(&ra.roundRobinIndex, 1)
		selected := candidates[idx%uint64(len(candidates))]
		return selected.WANID, "ROUND_ROBIN_FALLBACK", nil
	}

	// Select based on weighted position.
	idx := atomic.AddUint64(&ra.roundRobinIndex, 1)
	selection := float64(idx%1000) / 1000.0 * totalWeight

	var cumulative float64
	for _, c := range candidates {
		if w, ok := ra.weights[c.WANID]; ok {
			cumulative += w
			if selection <= cumulative {
				return c.WANID, "HEALTH_WEIGHTED", nil
			}
		}
	}

	// Fallback to last candidate.
	return candidates[len(candidates)-1].WANID, "HEALTH_WEIGHTED", nil
}

// =============================================================================
// Least Connections
// =============================================================================

// selectLeastConnections selects WAN with fewest active connections.
func (ra *RoutingAlgorithm) selectLeastConnections(candidates []WANCandidate) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	ra.connectionMu.RLock()
	defer ra.connectionMu.RUnlock()

	var bestWAN string
	var bestScore float64 = -1

	for _, c := range candidates {
		var activeConns int64
		if state, ok := ra.connectionState[c.WANID]; ok {
			activeConns = atomic.LoadInt64(&state.ActiveConnections)
		}

		// Normalize by capacity (higher capacity = can handle more).
		capacity := float64(c.Capacity)
		if capacity == 0 {
			capacity = 1000000000 // 1 Gbps default.
		}
		normalized := float64(activeConns) / (capacity / 1000000000.0)

		// Lower is better; use health as tie-breaker.
		score := 1000.0 - normalized + (c.HealthScore / 100.0)

		if bestScore < 0 || score > bestScore {
			bestScore = score
			bestWAN = c.WANID
		}
	}

	return bestWAN, "LEAST_CONNECTIONS", nil
}

// =============================================================================
// Latency-Based
// =============================================================================

// selectLatencyBased routes to lowest-latency WAN.
func (ra *RoutingAlgorithm) selectLatencyBased(candidates []WANCandidate) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	// Sort by latency ascending.
	sorted := make([]WANCandidate, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Latency < sorted[j].Latency
	})

	return sorted[0].WANID, "LATENCY_OPTIMIZED", nil
}

// =============================================================================
// Hash-Based
// =============================================================================

// selectHashBased uses flow hash for deterministic selection.
func (ra *RoutingAlgorithm) selectHashBased(candidates []WANCandidate, flow FiveTuple) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	// Sort candidates for consistent ordering.
	sorted := make([]WANCandidate, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].WANID < sorted[j].WANID
	})

	// Select based on hash.
	hash := flow.Hash()
	idx := hash % uint64(len(sorted))

	return sorted[idx].WANID, "HASH_AFFINITY", nil
}

// =============================================================================
// Adaptive
// =============================================================================

// selectAdaptive switches strategies based on network conditions.
func (ra *RoutingAlgorithm) selectAdaptive(candidates []WANCandidate, flow FiveTuple) (string, string, error) {
	_ = flow // Will be used for flow-specific adaptive routing.
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	// Analyze conditions.
	var maxLatencyVariance time.Duration
	var maxUtilization float64
	var avgHealth float64

	for _, c := range candidates {
		avgHealth += c.HealthScore
		// Would need jitter data for variance analysis.
	}
	avgHealth /= float64(len(candidates))

	// Decision logic.
	if maxLatencyVariance > 50*time.Millisecond {
		// High jitter: use latency-based.
		wanID, _, err := ra.selectLatencyBased(candidates)
		return wanID, "ADAPTIVE_LATENCY", err
	}

	if maxUtilization > 80 {
		// Uneven load: use least-connections.
		wanID, _, err := ra.selectLeastConnections(candidates)
		return wanID, "ADAPTIVE_CONNECTIONS", err
	}

	if avgHealth > 80 {
		// All healthy: use weighted round-robin.
		wanID, _, err := ra.selectWeightedRoundRobin(candidates)
		return wanID, "ADAPTIVE_WEIGHTED", err
	}

	// Default: failover-only.
	wanID, _, err := ra.selectFailoverOnly(candidates)
	return wanID, "ADAPTIVE_FAILOVER", err
}

// =============================================================================
// Failover-Only
// =============================================================================

// selectFailoverOnly uses simple primary/backup selection.
func (ra *RoutingAlgorithm) selectFailoverOnly(candidates []WANCandidate) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", ErrNoHealthyWANs
	}

	// Sort by priority (descending), then health (descending).
	sorted := make([]WANCandidate, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].HealthScore > sorted[j].HealthScore
	})

	return sorted[0].WANID, "PRIMARY_WAN", nil
}

// =============================================================================
// Weight Management
// =============================================================================

// updateWeights recalculates WAN weights.
func (ra *RoutingAlgorithm) updateWeights() {
	if ra.metricsCollector == nil {
		return
	}

	allMetrics := ra.metricsCollector.GetAllWANMetrics()
	if len(allMetrics) == 0 {
		return
	}

	ra.manualWeightsMu.RLock()
	manualWeights := make(map[string]float64)
	for k, v := range ra.manualWeights {
		manualWeights[k] = v
	}
	ra.manualWeightsMu.RUnlock()

	newWeights := make(map[string]float64)
	var totalWeight float64

	for wanID, metrics := range allMetrics {
		// Check for manual override.
		if w, ok := manualWeights[wanID]; ok {
			newWeights[wanID] = w
			totalWeight += w
			continue
		}

		// Calculate from health with exponential scaling.
		health := metrics.HealthScore
		if health < ra.config.MinHealthScore {
			continue // Exclude unhealthy WANs.
		}

		weight := health
		if ra.config.HealthWeightExponent != 1.0 {
			weight = pow(health, ra.config.HealthWeightExponent)
		}

		newWeights[wanID] = weight
		totalWeight += weight
	}

	// Normalize to sum = 1.0.
	if totalWeight > 0 {
		for wanID := range newWeights {
			newWeights[wanID] /= totalWeight
		}
	}

	ra.weightsMu.Lock()
	ra.weights = newWeights
	ra.lastRebalance = time.Now()
	ra.weightsMu.Unlock()
}

// pow calculates x^y for float64.
func pow(x, y float64) float64 {
	if y == 0 {
		return 1
	}
	if y == 1 {
		return x
	}
	result := x
	for i := 1; i < int(y); i++ {
		result *= x
	}
	return result
}

// SetWANWeight sets a manual weight override.
func (ra *RoutingAlgorithm) SetWANWeight(wanID string, weight float64) error {
	if weight < 0 || weight > 1 {
		return errors.New("weight must be between 0 and 1")
	}

	ra.manualWeightsMu.Lock()
	ra.manualWeights[wanID] = weight
	ra.manualWeightsMu.Unlock()

	ra.updateWeights()
	return nil
}

// ClearWANWeight removes a manual weight override.
func (ra *RoutingAlgorithm) ClearWANWeight(wanID string) error {
	ra.manualWeightsMu.Lock()
	delete(ra.manualWeights, wanID)
	ra.manualWeightsMu.Unlock()

	ra.updateWeights()
	return nil
}

// =============================================================================
// Connection Tracking
// =============================================================================

// IncrementConnections increments the connection count for a WAN.
func (ra *RoutingAlgorithm) IncrementConnections(wanID string) {
	ra.connectionMu.Lock()
	state, ok := ra.connectionState[wanID]
	if !ok {
		state = &ConnectionState{WANID: wanID}
		ra.connectionState[wanID] = state
	}
	ra.connectionMu.Unlock()

	atomic.AddInt64(&state.ActiveConnections, 1)
	atomic.AddUint64(&state.TotalConnections, 1)
	state.LastUpdate = time.Now()
}

// DecrementConnections decrements the connection count for a WAN.
func (ra *RoutingAlgorithm) DecrementConnections(wanID string) {
	ra.connectionMu.RLock()
	state, ok := ra.connectionState[wanID]
	ra.connectionMu.RUnlock()

	if ok {
		atomic.AddInt64(&state.ActiveConnections, -1)
		state.LastUpdate = time.Now()
	}
}

// GetConnectionCount returns the active connection count for a WAN.
func (ra *RoutingAlgorithm) GetConnectionCount(wanID string) int64 {
	ra.connectionMu.RLock()
	state, ok := ra.connectionState[wanID]
	ra.connectionMu.RUnlock()

	if ok {
		return atomic.LoadInt64(&state.ActiveConnections)
	}
	return 0
}

// =============================================================================
// Session Affinity
// =============================================================================

// getSessionAffinity checks if a flow has an existing WAN mapping.
func (ra *RoutingAlgorithm) getSessionAffinity(flow FiveTuple) (string, bool) {
	ra.sessionCacheMu.RLock()
	defer ra.sessionCacheMu.RUnlock()

	entry, ok := ra.sessionCache[flow]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.WANID, true
}

// setSessionAffinity stores a flow-to-WAN mapping.
func (ra *RoutingAlgorithm) setSessionAffinity(flow FiveTuple, wanID string) {
	ra.sessionCacheMu.Lock()
	defer ra.sessionCacheMu.Unlock()

	ra.sessionCache[flow] = &sessionCacheEntry{
		WANID:     wanID,
		ExpiresAt: time.Now().Add(ra.config.SessionAffinityTimeout),
	}
}

// RemoveSessionAffinity removes a flow-to-WAN mapping.
func (ra *RoutingAlgorithm) RemoveSessionAffinity(flow FiveTuple) {
	ra.sessionCacheMu.Lock()
	defer ra.sessionCacheMu.Unlock()
	delete(ra.sessionCache, flow)
}

// =============================================================================
// Candidate Management
// =============================================================================

// getAvailableCandidates returns WANs meeting minimum criteria.
func (ra *RoutingAlgorithm) getAvailableCandidates() []WANCandidate {
	if ra.metricsCollector == nil {
		return nil
	}

	allMetrics := ra.metricsCollector.GetAllWANMetrics()
	candidates := make([]WANCandidate, 0, len(allMetrics))

	for wanID, metrics := range allMetrics {
		// Check blacklist.
		if ra.isBlacklisted(wanID) {
			continue
		}

		// Check health threshold.
		if metrics.HealthScore < ra.config.MinHealthScore {
			continue
		}

		// Check connection limit.
		if ra.config.EnableConnectionLimit {
			conns := ra.GetConnectionCount(wanID)
			if int(conns) >= ra.config.MaxConnectionsPerWAN {
				continue
			}
		}

		candidates = append(candidates, WANCandidate{
			WANID:             wanID,
			HealthScore:       metrics.HealthScore,
			ActiveConnections: int(ra.GetConnectionCount(wanID)),
			Latency:           metrics.Latency,
			Capacity:          metrics.Throughput.LinkCapacity,
			IsAvailable:       true,
		})
	}

	return candidates
}

// isWANAvailable checks if a specific WAN is available.
func (ra *RoutingAlgorithm) isWANAvailable(wanID string) bool {
	if ra.isBlacklisted(wanID) {
		return false
	}

	if ra.metricsCollector == nil {
		return false
	}

	metrics, err := ra.metricsCollector.GetWANMetrics(wanID)
	if err != nil {
		return false
	}

	if metrics.HealthScore < ra.config.MinHealthScore {
		return false
	}

	if ra.config.EnableConnectionLimit {
		conns := ra.GetConnectionCount(wanID)
		if int(conns) >= ra.config.MaxConnectionsPerWAN {
			return false
		}
	}

	return true
}

// buildFallbackChain creates ordered list of backup WANs.
func (ra *RoutingAlgorithm) buildFallbackChain(candidates []WANCandidate, primary string) []string {
	chain := make([]string, 0, len(candidates)-1)
	for _, c := range candidates {
		if c.WANID != primary {
			chain = append(chain, c.WANID)
		}
	}
	return chain
}

// =============================================================================
// Fallback Handling
// =============================================================================

// handleFallback handles scenarios when no healthy WANs available.
func (ra *RoutingAlgorithm) handleFallback(flow FiveTuple) (*RoutingDecision, error) {
	_ = flow // Flow preserved for potential future use in fallback logic.
	atomic.AddUint64(&ra.fallbackCount, 1)

	decision := &RoutingDecision{
		AlgorithmUsed: ra.strategy,
		Timestamp:     time.Now(),
	}

	switch ra.config.FallbackMode {
	case UseBestAvailable:
		// Get all WANs ignoring health threshold.
		if ra.metricsCollector == nil {
			return nil, ErrNoHealthyWANs
		}
		allMetrics := ra.metricsCollector.GetAllWANMetrics()
		if len(allMetrics) == 0 {
			return nil, ErrNoHealthyWANs
		}

		// Find least-unhealthy.
		var bestWAN string
		var bestHealth float64 = -1
		for wanID, metrics := range allMetrics {
			if !ra.isBlacklisted(wanID) && metrics.HealthScore > bestHealth {
				bestHealth = metrics.HealthScore
				bestWAN = wanID
			}
		}

		if bestWAN == "" {
			return nil, ErrNoHealthyWANs
		}

		decision.SelectedWAN = bestWAN
		decision.Reason = "FALLBACK_BEST_AVAILABLE"
		return decision, nil

	case RejectNewConnections:
		return nil, ErrNoHealthyWANs

	case RoundRobinAll:
		if ra.metricsCollector == nil {
			return nil, ErrNoHealthyWANs
		}
		allMetrics := ra.metricsCollector.GetAllWANMetrics()
		wanIDs := make([]string, 0, len(allMetrics))
		for wanID := range allMetrics {
			if !ra.isBlacklisted(wanID) {
				wanIDs = append(wanIDs, wanID)
			}
		}
		if len(wanIDs) == 0 {
			return nil, ErrNoHealthyWANs
		}

		idx := atomic.AddUint64(&ra.roundRobinIndex, 1)
		decision.SelectedWAN = wanIDs[idx%uint64(len(wanIDs))]
		decision.Reason = "FALLBACK_ROUND_ROBIN"
		return decision, nil

	case UsePrimaryOnly:
		// Select highest priority WAN.
		if ra.metricsCollector == nil {
			return nil, ErrNoHealthyWANs
		}
		allMetrics := ra.metricsCollector.GetAllWANMetrics()
		if len(allMetrics) == 0 {
			return nil, ErrNoHealthyWANs
		}

		// Just use first available.
		for wanID := range allMetrics {
			if !ra.isBlacklisted(wanID) {
				decision.SelectedWAN = wanID
				decision.Reason = "FALLBACK_PRIMARY_FORCED"
				return decision, nil
			}
		}
		return nil, ErrNoHealthyWANs

	default:
		return nil, ErrNoHealthyWANs
	}
}

// =============================================================================
// Blacklist Management
// =============================================================================

// BlacklistWAN temporarily excludes a WAN from selection.
func (ra *RoutingAlgorithm) BlacklistWAN(wanID string, duration time.Duration) error {
	ra.blacklistMu.Lock()
	ra.blacklist[wanID] = time.Now().Add(duration)
	ra.blacklistMu.Unlock()

	// Purge session cache entries for this WAN.
	ra.purgeSessionCacheForWAN(wanID)

	return nil
}

// UnblacklistWAN removes a WAN from the blacklist.
func (ra *RoutingAlgorithm) UnblacklistWAN(wanID string) error {
	ra.blacklistMu.Lock()
	delete(ra.blacklist, wanID)
	ra.blacklistMu.Unlock()
	return nil
}

// isBlacklisted checks if a WAN is blacklisted.
func (ra *RoutingAlgorithm) isBlacklisted(wanID string) bool {
	ra.blacklistMu.RLock()
	defer ra.blacklistMu.RUnlock()

	expires, ok := ra.blacklist[wanID]
	if !ok {
		return false
	}

	if time.Now().After(expires) {
		// Expired, will be cleaned up.
		return false
	}

	return true
}

// purgeSessionCacheForWAN removes all session cache entries for a WAN.
func (ra *RoutingAlgorithm) purgeSessionCacheForWAN(wanID string) {
	ra.sessionCacheMu.Lock()
	defer ra.sessionCacheMu.Unlock()

	for flow, entry := range ra.sessionCache {
		if entry.WANID == wanID {
			delete(ra.sessionCache, flow)
		}
	}
}

// =============================================================================
// Strategy Management
// =============================================================================

// SetStrategy changes the balancing strategy.
func (ra *RoutingAlgorithm) SetStrategy(newStrategy BalancingStrategy) error {
	if newStrategy < WeightedRoundRobin || newStrategy > FailoverOnly {
		return ErrInvalidStrategy
	}

	ra.strategy = newStrategy
	return nil
}

// GetStrategy returns the current strategy.
func (ra *RoutingAlgorithm) GetStrategy() BalancingStrategy {
	return ra.strategy
}

// =============================================================================
// Statistics
// =============================================================================

// recordSelection records a WAN selection for statistics.
func (ra *RoutingAlgorithm) recordSelection(wanID string, cacheHit bool) {
	atomic.AddUint64(&ra.totalSelections, 1)

	ra.statsMu.Lock()
	ra.perWANSelections[wanID]++
	ra.statsMu.Unlock()

	if cacheHit {
		atomic.AddUint64(&ra.sessionCacheHits, 1)
	} else {
		atomic.AddUint64(&ra.sessionCacheMiss, 1)
	}
}

// GetStatistics returns algorithm statistics.
func (ra *RoutingAlgorithm) GetStatistics() AlgorithmStatistics {
	ra.statsMu.RLock()
	perWAN := make(map[string]uint64)
	for k, v := range ra.perWANSelections {
		perWAN[k] = v
	}
	ra.statsMu.RUnlock()

	ra.connectionMu.RLock()
	perWANConns := make(map[string]int64)
	for k, v := range ra.connectionState {
		perWANConns[k] = atomic.LoadInt64(&v.ActiveConnections)
	}
	ra.connectionMu.RUnlock()

	ra.weightsMu.RLock()
	weights := make(map[string]float64)
	for k, v := range ra.weights {
		weights[k] = v
	}
	ra.weightsMu.RUnlock()

	ra.blacklistMu.RLock()
	blacklisted := make([]string, 0, len(ra.blacklist))
	now := time.Now()
	for wanID, expires := range ra.blacklist {
		if now.Before(expires) {
			blacklisted = append(blacklisted, wanID)
		}
	}
	ra.blacklistMu.RUnlock()

	hits := atomic.LoadUint64(&ra.sessionCacheHits)
	misses := atomic.LoadUint64(&ra.sessionCacheMiss)
	var hitRate float64
	if hits+misses > 0 {
		hitRate = float64(hits) / float64(hits+misses) * 100.0
	}

	return AlgorithmStatistics{
		Strategy:            ra.strategy,
		TotalSelections:     atomic.LoadUint64(&ra.totalSelections),
		SessionCacheHitRate: hitRate,
		PerWANSelections:    perWAN,
		PerWANConnections:   perWANConns,
		Weights:             weights,
		LastRebalance:       ra.lastRebalance,
		FallbackCount:       atomic.LoadUint64(&ra.fallbackCount),
		BlacklistedWANs:     blacklisted,
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the algorithm is operational.
func (ra *RoutingAlgorithm) HealthCheck() error {
	ra.runningMu.Lock()
	running := ra.running
	ra.runningMu.Unlock()

	if !running {
		return errors.New("algorithm not running")
	}

	// Check weights updated recently.
	maxAge := 2 * ra.config.RebalanceInterval
	if time.Since(ra.lastRebalance) > maxAge {
		return errors.New("weights not updated recently")
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// GetConfig returns the current configuration.
func (ra *RoutingAlgorithm) GetConfig() *AlgorithmConfig {
	return ra.config
}

// IsRunning returns whether the algorithm is running.
func (ra *RoutingAlgorithm) IsRunning() bool {
	ra.runningMu.Lock()
	defer ra.runningMu.Unlock()
	return ra.running
}
