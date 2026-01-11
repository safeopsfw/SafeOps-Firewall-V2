// Package integration provides cross-service integration components
// for the NIC Management service.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// QoS Errors
// =============================================================================

var (
	// ErrQoSNotInitialized indicates QoS hooks not initialized.
	ErrQoSNotInitialized = errors.New("qos hooks not initialized")
	// ErrQoSServiceUnavailable indicates QoS service is unavailable.
	ErrQoSServiceUnavailable = errors.New("qos service unavailable")
	// ErrQoSRateLimited indicates rate limiting applied.
	ErrQoSRateLimited = errors.New("rate limited by qos policy")
	// ErrQoSInvalidClass indicates invalid traffic class.
	ErrQoSInvalidClass = errors.New("invalid traffic class")
	// ErrQoSBandwidthExceeded indicates bandwidth limit exceeded.
	ErrQoSBandwidthExceeded = errors.New("bandwidth limit exceeded")
)

// =============================================================================
// Traffic Class Constants
// =============================================================================

// TrafficClass represents QoS traffic classification.
type TrafficClass int

const (
	// TrafficClassBestEffort is default, lowest priority traffic.
	TrafficClassBestEffort TrafficClass = iota
	// TrafficClassBulk is for bulk data transfers (backups, updates).
	TrafficClassBulk
	// TrafficClassStandard is for normal web/email traffic.
	TrafficClassStandard
	// TrafficClassInteractive is for interactive applications.
	TrafficClassInteractive
	// TrafficClassStreaming is for video/audio streaming.
	TrafficClassStreaming
	// TrafficClassVoIP is for voice over IP, highest priority.
	TrafficClassVoIP
	// TrafficClassCritical is for critical business applications.
	TrafficClassCritical
)

// String returns the string representation of a traffic class.
func (tc TrafficClass) String() string {
	switch tc {
	case TrafficClassBestEffort:
		return "best-effort"
	case TrafficClassBulk:
		return "bulk"
	case TrafficClassStandard:
		return "standard"
	case TrafficClassInteractive:
		return "interactive"
	case TrafficClassStreaming:
		return "streaming"
	case TrafficClassVoIP:
		return "voip"
	case TrafficClassCritical:
		return "critical"
	default:
		return fmt.Sprintf("unknown(%d)", tc)
	}
}

// Priority returns the numeric priority (higher = more important).
func (tc TrafficClass) Priority() int {
	switch tc {
	case TrafficClassBestEffort:
		return 0
	case TrafficClassBulk:
		return 1
	case TrafficClassStandard:
		return 2
	case TrafficClassInteractive:
		return 3
	case TrafficClassStreaming:
		return 4
	case TrafficClassVoIP:
		return 5
	case TrafficClassCritical:
		return 6
	default:
		return 0
	}
}

// =============================================================================
// QoS Action Constants
// =============================================================================

// QoSAction represents the action to take on traffic.
type QoSAction int

const (
	// QoSActionAllow permits the packet with current class.
	QoSActionAllow QoSAction = iota
	// QoSActionRateLimit applies rate limiting to the flow.
	QoSActionRateLimit
	// QoSActionShape applies traffic shaping.
	QoSActionShape
	// QoSActionDrop drops the packet (queue full).
	QoSActionDrop
	// QoSActionMark marks the packet with DSCP value.
	QoSActionMark
)

// String returns the string representation.
func (a QoSAction) String() string {
	switch a {
	case QoSActionAllow:
		return "allow"
	case QoSActionRateLimit:
		return "rate-limit"
	case QoSActionShape:
		return "shape"
	case QoSActionDrop:
		return "drop"
	case QoSActionMark:
		return "mark"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// =============================================================================
// DSCP Values
// =============================================================================

// DSCPValue represents Differentiated Services Code Point.
type DSCPValue uint8

const (
	// DSCPDefault is best effort (0).
	DSCPDefault DSCPValue = 0
	// DSCPCS1 is low priority (8).
	DSCPCS1 DSCPValue = 8
	// DSCPAF11 is high-throughput data (10).
	DSCPAF11 DSCPValue = 10
	// DSCPAF21 is low-latency data (18).
	DSCPAF21 DSCPValue = 18
	// DSCPAF31 is multimedia streaming (26).
	DSCPAF31 DSCPValue = 26
	// DSCPAF41 is multimedia conferencing (34).
	DSCPAF41 DSCPValue = 34
	// DSCPEF is expedited forwarding for VoIP (46).
	DSCPEF DSCPValue = 46
)

// =============================================================================
// QoS Classification Request
// =============================================================================

// QoSClassificationRequest contains packet info for classification.
type QoSClassificationRequest struct {
	// FiveTuple identifies the connection.
	FiveTuple *FiveTuple
	// Direction is the packet direction.
	Direction PacketDirection
	// PacketSize is the size in bytes.
	PacketSize int
	// WanInterface is the WAN interface involved.
	WanInterface string
	// ApplicationID is the detected application (if DPI available).
	ApplicationID string
}

// =============================================================================
// QoS Classification Result
// =============================================================================

// QoSClassificationResult contains classification decision.
type QoSClassificationResult struct {
	// Class is the assigned traffic class.
	Class TrafficClass
	// Action is the QoS action to apply.
	Action QoSAction
	// DSCPMark is the DSCP value to apply (if marking).
	DSCPMark DSCPValue
	// BandwidthLimit is the max bandwidth in bps (0 = unlimited).
	BandwidthLimit uint64
	// Priority is the queue priority (higher = more urgent).
	Priority int
	// PolicyName is the matching policy name.
	PolicyName string
}

// =============================================================================
// Flow Statistics
// =============================================================================

// FlowStats contains per-flow QoS statistics.
type FlowStats struct {
	// FiveTuple identifies the flow.
	FiveTuple *FiveTuple
	// Class is the assigned traffic class.
	Class TrafficClass
	// BytesSent is total bytes sent.
	BytesSent uint64
	// BytesReceived is total bytes received.
	BytesReceived uint64
	// PacketsSent is total packets sent.
	PacketsSent uint64
	// PacketsReceived is total packets received.
	PacketsReceived uint64
	// DroppedPackets is packets dropped due to QoS.
	DroppedPackets uint64
	// StartTime is when the flow started.
	StartTime time.Time
	// LastActive is when traffic was last seen.
	LastActive time.Time
	// CurrentBandwidth is current bandwidth usage in bps.
	CurrentBandwidth uint64
}

// =============================================================================
// Interface Bandwidth
// =============================================================================

// InterfaceBandwidth contains interface bandwidth info.
type InterfaceBandwidth struct {
	// InterfaceID is the interface identifier.
	InterfaceID string
	// TotalBandwidth is the total bandwidth capacity in bps.
	TotalBandwidth uint64
	// UsedBandwidth is the current used bandwidth in bps.
	UsedBandwidth uint64
	// ReservedBandwidth is bandwidth reserved for priority traffic.
	ReservedBandwidth uint64
	// AvailableBandwidth is remaining available bandwidth.
	AvailableBandwidth uint64
	// QueuedPackets is packets waiting in queues.
	QueuedPackets int
	// DropRate is the current drop rate (0.0 - 1.0).
	DropRate float64
}

// =============================================================================
// QoS Policy
// =============================================================================

// QoSPolicy defines a QoS classification policy.
type QoSPolicy struct {
	// Name is the policy name.
	Name string `json:"name"`
	// Priority is the rule priority (higher = checked first).
	Priority int `json:"priority"`
	// Enabled indicates if policy is active.
	Enabled bool `json:"enabled"`
	// Match criteria.
	MatchSourceIP      *net.IPNet `json:"match_source_ip,omitempty"`
	MatchDestIP        *net.IPNet `json:"match_dest_ip,omitempty"`
	MatchSourcePort    uint16     `json:"match_source_port,omitempty"`
	MatchDestPort      uint16     `json:"match_dest_port,omitempty"`
	MatchProtocol      uint8      `json:"match_protocol,omitempty"`
	MatchApplicationID string     `json:"match_application_id,omitempty"`
	// Classification.
	TrafficClass TrafficClass `json:"traffic_class"`
	DSCPMark     DSCPValue    `json:"dscp_mark"`
	// Rate limiting.
	BandwidthLimit uint64 `json:"bandwidth_limit,omitempty"`
	BurstSize      uint64 `json:"burst_size,omitempty"`
}

// =============================================================================
// QoS Hooks Configuration
// =============================================================================

// QoSHooksConfig contains QoS integration configuration.
type QoSHooksConfig struct {
	// Enabled enables QoS integration.
	Enabled bool `json:"enabled"`
	// ServiceAddress is the QoS service gRPC address.
	ServiceAddress string `json:"service_address"`
	// DefaultClass is the default traffic class.
	DefaultClass TrafficClass `json:"default_class"`
	// ClassificationTimeout is timeout for classification.
	ClassificationTimeout time.Duration `json:"classification_timeout"`
	// ClassificationWorkers is number of worker goroutines.
	ClassificationWorkers int `json:"classification_workers"`
	// QueueSize is the classification queue size.
	QueueSize int `json:"queue_size"`
	// CacheEnabled enables classification caching.
	CacheEnabled bool `json:"cache_enabled"`
	// CacheSize is the classification cache size.
	CacheSize int `json:"cache_size"`
	// CacheTTL is the cache entry TTL.
	CacheTTL time.Duration `json:"cache_ttl"`
	// EnableDPI enables deep packet inspection for app detection.
	EnableDPI bool `json:"enable_dpi"`
	// StrictBandwidth enables strict bandwidth enforcement.
	StrictBandwidth bool `json:"strict_bandwidth"`
	// DefaultBandwidthLimit is default per-flow limit (0 = unlimited).
	DefaultBandwidthLimit uint64 `json:"default_bandwidth_limit"`
}

// DefaultQoSHooksConfig returns the default configuration.
func DefaultQoSHooksConfig() *QoSHooksConfig {
	return &QoSHooksConfig{
		Enabled:               false,
		ServiceAddress:        "localhost:50056",
		DefaultClass:          TrafficClassStandard,
		ClassificationTimeout: 10 * time.Millisecond,
		ClassificationWorkers: 4,
		QueueSize:             10000,
		CacheEnabled:          true,
		CacheSize:             50000,
		CacheTTL:              5 * time.Minute,
		EnableDPI:             false,
		StrictBandwidth:       false,
		DefaultBandwidthLimit: 0,
	}
}

// =============================================================================
// QoS Statistics
// =============================================================================

// QoSStats contains QoS hooks statistics.
type QoSStats struct {
	// Classification stats.
	TotalClassifications uint64
	CacheHits            uint64
	CacheMisses          uint64
	ClassificationErrors uint64
	// Per-class stats.
	ClassCounts map[TrafficClass]uint64
	// Action stats.
	AllowedPackets   uint64
	RateLimitedFlows uint64
	ShapedFlows      uint64
	DroppedPackets   uint64
	MarkedPackets    uint64
	// Bandwidth stats.
	TotalBytesProcessed uint64
	CurrentThroughput   uint64
	// Timing.
	AvgClassificationTimeNs int64
	MaxClassificationTimeNs int64
}

// =============================================================================
// Classification Cache Entry
// =============================================================================

// classificationCacheEntry represents a cached classification.
type classificationCacheEntry struct {
	Result    *QoSClassificationResult
	ExpiresAt time.Time
}

// =============================================================================
// Classification Request (internal)
// =============================================================================

// classificationRequest represents a pending classification.
type classificationRequest struct {
	Request    *QoSClassificationRequest
	ResultChan chan *classificationResponse
}

// classificationResponse contains classification result.
type classificationResponse struct {
	Result *QoSClassificationResult
	Error  error
}

// =============================================================================
// Flow Entry (internal)
// =============================================================================

// flowEntry tracks per-flow state.
type flowEntry struct {
	FiveTuple     *FiveTuple
	Class         TrafficClass
	BytesSent     uint64
	BytesRecv     uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Dropped       uint64
	StartTime     time.Time
	LastActive    time.Time
	BandwidthUsed uint64
	TokenBucket   int64
	LastTokenTime time.Time
	mu            sync.Mutex
}

// =============================================================================
// QoS Hooks
// =============================================================================

// QoSHooks manages QoS integration.
type QoSHooks struct {
	config *QoSHooksConfig

	// State.
	running   atomic.Bool
	connected atomic.Bool

	// Classification cache.
	classCache   map[string]*classificationCacheEntry
	classCacheMu sync.RWMutex

	// Flow tracking.
	flows   map[string]*flowEntry
	flowsMu sync.RWMutex

	// Policies.
	policies   []*QoSPolicy
	policiesMu sync.RWMutex

	// Interface bandwidth tracking.
	interfaceBandwidth   map[string]*InterfaceBandwidth
	interfaceBandwidthMu sync.RWMutex

	// Classification queue.
	classificationQueue chan *classificationRequest

	// Statistics.
	stats   QoSStats
	statsMu sync.RWMutex

	// Lifecycle.
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	workerDone chan struct{}
}

// NewQoSHooks creates a new QoS hooks instance.
func NewQoSHooks(config *QoSHooksConfig) *QoSHooks {
	if config == nil {
		config = DefaultQoSHooksConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &QoSHooks{
		config:              config,
		classCache:          make(map[string]*classificationCacheEntry),
		flows:               make(map[string]*flowEntry),
		policies:            make([]*QoSPolicy, 0),
		interfaceBandwidth:  make(map[string]*InterfaceBandwidth),
		classificationQueue: make(chan *classificationRequest, config.QueueSize),
		stats: QoSStats{
			ClassCounts: make(map[TrafficClass]uint64),
		},
		ctx:        ctx,
		cancel:     cancel,
		workerDone: make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Methods
// =============================================================================

// Start initializes and starts the QoS hooks.
func (q *QoSHooks) Start() error {
	if !q.config.Enabled {
		return nil
	}

	if q.running.Load() {
		return nil
	}

	// Start classification workers.
	for i := 0; i < q.config.ClassificationWorkers; i++ {
		q.wg.Add(1)
		go q.classificationWorker(i)
	}

	// Start cache cleanup.
	q.wg.Add(1)
	go q.cacheCleanupLoop()

	// Start flow cleanup.
	q.wg.Add(1)
	go q.flowCleanupLoop()

	// Start bandwidth monitoring.
	q.wg.Add(1)
	go q.bandwidthMonitorLoop()

	q.running.Store(true)
	q.connected.Store(true) // Local classification, always connected.

	return nil
}

// Stop gracefully shuts down QoS hooks.
func (q *QoSHooks) Stop() error {
	if !q.running.Load() {
		return nil
	}

	q.cancel()
	q.running.Store(false)
	q.connected.Store(false)

	// Close queue to signal workers.
	close(q.classificationQueue)

	// Wait for workers to finish.
	q.wg.Wait()

	return nil
}

// IsConnected returns whether QoS service is connected.
func (q *QoSHooks) IsConnected() bool {
	return q.connected.Load()
}

// =============================================================================
// Classification Methods
// =============================================================================

// ClassifyPacket classifies a packet and returns QoS decision.
func (q *QoSHooks) ClassifyPacket(ctx context.Context, req *QoSClassificationRequest) (*QoSClassificationResult, error) {
	if !q.config.Enabled {
		return q.defaultResult(), nil
	}

	if !q.running.Load() {
		return nil, ErrQoSNotInitialized
	}

	// Check cache first.
	if q.config.CacheEnabled {
		if result := q.checkCache(req.FiveTuple); result != nil {
			q.recordCacheHit()
			return result, nil
		}
		q.recordCacheMiss()
	}

	// Classify locally using policies.
	startTime := time.Now()
	result := q.classifyLocally(req)
	classTime := time.Since(startTime).Nanoseconds()

	// Update timing stats.
	q.updateClassificationTiming(classTime)

	// Cache result.
	if q.config.CacheEnabled {
		q.cacheResult(req.FiveTuple, result)
	}

	// Update flow tracking.
	q.updateFlow(req.FiveTuple, result.Class, req.PacketSize, req.Direction)

	// Update class counts.
	q.recordClassification(result.Class)

	return result, nil
}

// ClassifyPacketAsync submits classification request asynchronously.
func (q *QoSHooks) ClassifyPacketAsync(req *QoSClassificationRequest) <-chan *classificationResponse {
	resultChan := make(chan *classificationResponse, 1)

	if !q.config.Enabled || !q.running.Load() {
		resultChan <- &classificationResponse{Result: q.defaultResult()}
		return resultChan
	}

	select {
	case q.classificationQueue <- &classificationRequest{Request: req, ResultChan: resultChan}:
		// Queued successfully.
	default:
		// Queue full, return default.
		resultChan <- &classificationResponse{Result: q.defaultResult()}
	}

	return resultChan
}

// classifyLocally performs local classification using policies.
func (q *QoSHooks) classifyLocally(req *QoSClassificationRequest) *QoSClassificationResult {
	q.policiesMu.RLock()
	defer q.policiesMu.RUnlock()

	// Check policies in priority order.
	for _, policy := range q.policies {
		if !policy.Enabled {
			continue
		}

		if q.policyMatches(policy, req) {
			return &QoSClassificationResult{
				Class:          policy.TrafficClass,
				Action:         QoSActionAllow,
				DSCPMark:       policy.DSCPMark,
				BandwidthLimit: policy.BandwidthLimit,
				Priority:       policy.TrafficClass.Priority(),
				PolicyName:     policy.Name,
			}
		}
	}

	// Port-based classification (common services).
	class := q.classifyByPort(req.FiveTuple.DstPort)

	return &QoSClassificationResult{
		Class:          class,
		Action:         QoSActionAllow,
		DSCPMark:       q.classToDSCP(class),
		BandwidthLimit: q.config.DefaultBandwidthLimit,
		Priority:       class.Priority(),
		PolicyName:     "default",
	}
}

// policyMatches checks if a policy matches the request.
func (q *QoSHooks) policyMatches(policy *QoSPolicy, req *QoSClassificationRequest) bool {
	// Check protocol.
	if policy.MatchProtocol != 0 && policy.MatchProtocol != req.FiveTuple.Protocol {
		return false
	}

	// Check source IP.
	if policy.MatchSourceIP != nil && !policy.MatchSourceIP.Contains(req.FiveTuple.SrcIP) {
		return false
	}

	// Check destination IP.
	if policy.MatchDestIP != nil && !policy.MatchDestIP.Contains(req.FiveTuple.DstIP) {
		return false
	}

	// Check source port.
	if policy.MatchSourcePort != 0 && policy.MatchSourcePort != req.FiveTuple.SrcPort {
		return false
	}

	// Check destination port.
	if policy.MatchDestPort != 0 && policy.MatchDestPort != req.FiveTuple.DstPort {
		return false
	}

	// Check application ID.
	if policy.MatchApplicationID != "" && policy.MatchApplicationID != req.ApplicationID {
		return false
	}

	return true
}

// classifyByPort classifies traffic by well-known ports.
func (q *QoSHooks) classifyByPort(port uint16) TrafficClass {
	switch port {
	// VoIP.
	case 5060, 5061: // SIP
		return TrafficClassVoIP
	// Streaming.
	case 554, 1935, 8554: // RTSP, RTMP
		return TrafficClassStreaming
	// Interactive.
	case 22, 23, 3389, 5900: // SSH, Telnet, RDP, VNC
		return TrafficClassInteractive
	// Standard web.
	case 80, 443, 8080, 8443:
		return TrafficClassStandard
	// Email.
	case 25, 110, 143, 465, 587, 993, 995:
		return TrafficClassStandard
	// Bulk transfers.
	case 20, 21, 69, 115, 989, 990: // FTP, TFTP, SFTP
		return TrafficClassBulk
	// DNS - interactive.
	case 53:
		return TrafficClassInteractive
	// Critical services.
	case 389, 636, 88, 464: // LDAP, Kerberos
		return TrafficClassCritical
	default:
		return q.config.DefaultClass
	}
}

// classToDSCP maps traffic class to DSCP value.
func (q *QoSHooks) classToDSCP(class TrafficClass) DSCPValue {
	switch class {
	case TrafficClassVoIP:
		return DSCPEF
	case TrafficClassCritical:
		return DSCPAF41
	case TrafficClassStreaming:
		return DSCPAF31
	case TrafficClassInteractive:
		return DSCPAF21
	case TrafficClassStandard:
		return DSCPAF11
	case TrafficClassBulk:
		return DSCPCS1
	default:
		return DSCPDefault
	}
}

// defaultResult returns default classification result.
func (q *QoSHooks) defaultResult() *QoSClassificationResult {
	return &QoSClassificationResult{
		Class:          q.config.DefaultClass,
		Action:         QoSActionAllow,
		DSCPMark:       DSCPDefault,
		BandwidthLimit: q.config.DefaultBandwidthLimit,
		Priority:       q.config.DefaultClass.Priority(),
		PolicyName:     "default",
	}
}

// =============================================================================
// Policy Management
// =============================================================================

// AddPolicy adds a QoS policy.
func (q *QoSHooks) AddPolicy(policy *QoSPolicy) {
	q.policiesMu.Lock()
	defer q.policiesMu.Unlock()

	// Insert in priority order (highest first).
	inserted := false
	for i, p := range q.policies {
		if policy.Priority > p.Priority {
			// Insert before this policy.
			q.policies = append(q.policies[:i], append([]*QoSPolicy{policy}, q.policies[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		q.policies = append(q.policies, policy)
	}

	// Invalidate cache.
	q.clearCache()
}

// RemovePolicy removes a QoS policy by name.
func (q *QoSHooks) RemovePolicy(name string) bool {
	q.policiesMu.Lock()
	defer q.policiesMu.Unlock()

	for i, p := range q.policies {
		if p.Name == name {
			q.policies = append(q.policies[:i], q.policies[i+1:]...)
			q.clearCache()
			return true
		}
	}

	return false
}

// GetPolicies returns all policies.
func (q *QoSHooks) GetPolicies() []*QoSPolicy {
	q.policiesMu.RLock()
	defer q.policiesMu.RUnlock()

	result := make([]*QoSPolicy, len(q.policies))
	copy(result, q.policies)
	return result
}

// =============================================================================
// Rate Limiting
// =============================================================================

// CheckRateLimit checks if a flow exceeds its rate limit.
func (q *QoSHooks) CheckRateLimit(fiveTuple *FiveTuple, bytes int) (bool, error) {
	if !q.config.StrictBandwidth {
		return true, nil
	}

	key := fiveTuple.Key()

	q.flowsMu.RLock()
	flow, exists := q.flows[key]
	q.flowsMu.RUnlock()

	if !exists {
		return true, nil
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	// Token bucket algorithm.
	now := time.Now()
	elapsed := now.Sub(flow.LastTokenTime)

	// Refill tokens based on bandwidth limit.
	result, _ := q.getFlowClassResult(flow.FiveTuple)
	if result.BandwidthLimit == 0 {
		return true, nil // No limit.
	}

	tokensPerSecond := int64(result.BandwidthLimit / 8) // bits/s to bytes/s
	newTokens := int64(elapsed.Seconds() * float64(tokensPerSecond))
	flow.TokenBucket += newTokens

	// Cap at burst size.
	maxBurst := tokensPerSecond // 1 second of tokens.
	if flow.TokenBucket > maxBurst {
		flow.TokenBucket = maxBurst
	}

	flow.LastTokenTime = now

	// Check if enough tokens.
	if flow.TokenBucket >= int64(bytes) {
		flow.TokenBucket -= int64(bytes)
		return true, nil
	}

	// Rate limited.
	atomic.AddUint64(&q.stats.RateLimitedFlows, 1)
	return false, ErrQoSRateLimited
}

// getFlowClassResult gets classification result for a flow.
func (q *QoSHooks) getFlowClassResult(fiveTuple *FiveTuple) (*QoSClassificationResult, bool) {
	if result := q.checkCache(fiveTuple); result != nil {
		return result, true
	}
	return q.defaultResult(), false
}

// =============================================================================
// Flow Tracking
// =============================================================================

// updateFlow updates flow tracking.
func (q *QoSHooks) updateFlow(fiveTuple *FiveTuple, class TrafficClass, bytes int, direction PacketDirection) {
	key := fiveTuple.Key()

	q.flowsMu.Lock()
	flow, exists := q.flows[key]
	if !exists {
		flow = &flowEntry{
			FiveTuple:     fiveTuple,
			Class:         class,
			StartTime:     time.Now(),
			LastTokenTime: time.Now(),
		}
		q.flows[key] = flow
	}
	q.flowsMu.Unlock()

	flow.mu.Lock()
	defer flow.mu.Unlock()

	flow.LastActive = time.Now()
	if direction == DirectionOutbound {
		flow.BytesSent += uint64(bytes)
		flow.PacketsSent++
	} else {
		flow.BytesRecv += uint64(bytes)
		flow.PacketsRecv++
	}
}

// GetFlowStats returns statistics for a flow.
func (q *QoSHooks) GetFlowStats(fiveTuple *FiveTuple) (*FlowStats, bool) {
	key := fiveTuple.Key()

	q.flowsMu.RLock()
	flow, exists := q.flows[key]
	q.flowsMu.RUnlock()

	if !exists {
		return nil, false
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	return &FlowStats{
		FiveTuple:       flow.FiveTuple,
		Class:           flow.Class,
		BytesSent:       flow.BytesSent,
		BytesReceived:   flow.BytesRecv,
		PacketsSent:     flow.PacketsSent,
		PacketsReceived: flow.PacketsRecv,
		DroppedPackets:  flow.Dropped,
		StartTime:       flow.StartTime,
		LastActive:      flow.LastActive,
	}, true
}

// GetAllFlowStats returns all flow statistics.
func (q *QoSHooks) GetAllFlowStats() []*FlowStats {
	q.flowsMu.RLock()
	defer q.flowsMu.RUnlock()

	stats := make([]*FlowStats, 0, len(q.flows))
	for _, flow := range q.flows {
		flow.mu.Lock()
		stats = append(stats, &FlowStats{
			FiveTuple:       flow.FiveTuple,
			Class:           flow.Class,
			BytesSent:       flow.BytesSent,
			BytesReceived:   flow.BytesRecv,
			PacketsSent:     flow.PacketsSent,
			PacketsReceived: flow.PacketsRecv,
			DroppedPackets:  flow.Dropped,
			StartTime:       flow.StartTime,
			LastActive:      flow.LastActive,
		})
		flow.mu.Unlock()
	}

	return stats
}

// =============================================================================
// Interface Bandwidth Management
// =============================================================================

// SetInterfaceBandwidth sets bandwidth info for an interface.
func (q *QoSHooks) SetInterfaceBandwidth(interfaceID string, totalBandwidth uint64) {
	q.interfaceBandwidthMu.Lock()
	defer q.interfaceBandwidthMu.Unlock()

	q.interfaceBandwidth[interfaceID] = &InterfaceBandwidth{
		InterfaceID:        interfaceID,
		TotalBandwidth:     totalBandwidth,
		AvailableBandwidth: totalBandwidth,
	}
}

// GetInterfaceBandwidth returns bandwidth info for an interface.
func (q *QoSHooks) GetInterfaceBandwidth(interfaceID string) (*InterfaceBandwidth, bool) {
	q.interfaceBandwidthMu.RLock()
	defer q.interfaceBandwidthMu.RUnlock()

	bw, exists := q.interfaceBandwidth[interfaceID]
	if !exists {
		return nil, false
	}

	return &InterfaceBandwidth{
		InterfaceID:        bw.InterfaceID,
		TotalBandwidth:     bw.TotalBandwidth,
		UsedBandwidth:      bw.UsedBandwidth,
		ReservedBandwidth:  bw.ReservedBandwidth,
		AvailableBandwidth: bw.AvailableBandwidth,
		QueuedPackets:      bw.QueuedPackets,
		DropRate:           bw.DropRate,
	}, true
}

// =============================================================================
// Cache Methods
// =============================================================================

// checkCache checks the classification cache.
func (q *QoSHooks) checkCache(fiveTuple *FiveTuple) *QoSClassificationResult {
	key := fiveTuple.Key()

	q.classCacheMu.RLock()
	entry, exists := q.classCache[key]
	q.classCacheMu.RUnlock()

	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.Result
}

// cacheResult caches a classification result.
func (q *QoSHooks) cacheResult(fiveTuple *FiveTuple, result *QoSClassificationResult) {
	key := fiveTuple.Key()

	q.classCacheMu.Lock()
	q.classCache[key] = &classificationCacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(q.config.CacheTTL),
	}
	q.classCacheMu.Unlock()
}

// clearCache clears the classification cache.
func (q *QoSHooks) clearCache() {
	q.classCacheMu.Lock()
	q.classCache = make(map[string]*classificationCacheEntry)
	q.classCacheMu.Unlock()
}

// =============================================================================
// Statistics
// =============================================================================

// GetStats returns QoS statistics.
func (q *QoSHooks) GetStats() *QoSStats {
	q.statsMu.RLock()
	defer q.statsMu.RUnlock()

	classCounts := make(map[TrafficClass]uint64)
	for k, v := range q.stats.ClassCounts {
		classCounts[k] = v
	}

	return &QoSStats{
		TotalClassifications:    q.stats.TotalClassifications,
		CacheHits:               q.stats.CacheHits,
		CacheMisses:             q.stats.CacheMisses,
		ClassificationErrors:    q.stats.ClassificationErrors,
		ClassCounts:             classCounts,
		AllowedPackets:          q.stats.AllowedPackets,
		RateLimitedFlows:        q.stats.RateLimitedFlows,
		ShapedFlows:             q.stats.ShapedFlows,
		DroppedPackets:          q.stats.DroppedPackets,
		MarkedPackets:           q.stats.MarkedPackets,
		TotalBytesProcessed:     q.stats.TotalBytesProcessed,
		CurrentThroughput:       q.stats.CurrentThroughput,
		AvgClassificationTimeNs: q.stats.AvgClassificationTimeNs,
		MaxClassificationTimeNs: q.stats.MaxClassificationTimeNs,
	}
}

// recordCacheHit records a cache hit.
func (q *QoSHooks) recordCacheHit() {
	atomic.AddUint64(&q.stats.CacheHits, 1)
}

// recordCacheMiss records a cache miss.
func (q *QoSHooks) recordCacheMiss() {
	atomic.AddUint64(&q.stats.CacheMisses, 1)
}

// recordClassification records a classification.
func (q *QoSHooks) recordClassification(class TrafficClass) {
	atomic.AddUint64(&q.stats.TotalClassifications, 1)
	atomic.AddUint64(&q.stats.AllowedPackets, 1)

	q.statsMu.Lock()
	q.stats.ClassCounts[class]++
	q.statsMu.Unlock()
}

// updateClassificationTiming updates classification timing stats.
func (q *QoSHooks) updateClassificationTiming(nanos int64) {
	q.statsMu.Lock()
	defer q.statsMu.Unlock()

	// Update max.
	if nanos > q.stats.MaxClassificationTimeNs {
		q.stats.MaxClassificationTimeNs = nanos
	}

	// Update average (exponential moving average).
	if q.stats.AvgClassificationTimeNs == 0 {
		q.stats.AvgClassificationTimeNs = nanos
	} else {
		q.stats.AvgClassificationTimeNs = (q.stats.AvgClassificationTimeNs*9 + nanos) / 10
	}
}

// =============================================================================
// Worker Goroutines
// =============================================================================

// classificationWorker processes classification requests.
func (q *QoSHooks) classificationWorker(id int) {
	defer q.wg.Done()

	for req := range q.classificationQueue {
		if req == nil {
			continue
		}

		result, err := q.ClassifyPacket(q.ctx, req.Request)
		req.ResultChan <- &classificationResponse{
			Result: result,
			Error:  err,
		}
	}
}

// cacheCleanupLoop periodically cleans expired cache entries.
func (q *QoSHooks) cacheCleanupLoop() {
	defer q.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			q.cleanupCache()
		}
	}
}

// cleanupCache removes expired cache entries.
func (q *QoSHooks) cleanupCache() {
	now := time.Now()

	q.classCacheMu.Lock()
	for key, entry := range q.classCache {
		if now.After(entry.ExpiresAt) {
			delete(q.classCache, key)
		}
	}
	q.classCacheMu.Unlock()
}

// flowCleanupLoop periodically cleans inactive flows.
func (q *QoSHooks) flowCleanupLoop() {
	defer q.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	inactiveTimeout := 5 * time.Minute

	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			q.cleanupFlows(inactiveTimeout)
		}
	}
}

// cleanupFlows removes inactive flows.
func (q *QoSHooks) cleanupFlows(timeout time.Duration) {
	now := time.Now()

	q.flowsMu.Lock()
	for key, flow := range q.flows {
		flow.mu.Lock()
		inactive := now.Sub(flow.LastActive) > timeout
		flow.mu.Unlock()

		if inactive {
			delete(q.flows, key)
		}
	}
	q.flowsMu.Unlock()
}

// bandwidthMonitorLoop monitors interface bandwidth usage.
func (q *QoSHooks) bandwidthMonitorLoop() {
	defer q.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			q.updateBandwidthStats()
		}
	}
}

// updateBandwidthStats updates bandwidth statistics.
func (q *QoSHooks) updateBandwidthStats() {
	q.flowsMu.RLock()
	var totalBytes uint64
	for _, flow := range q.flows {
		flow.mu.Lock()
		totalBytes += flow.BytesSent + flow.BytesRecv
		flow.mu.Unlock()
	}
	q.flowsMu.RUnlock()

	q.statsMu.Lock()
	q.stats.TotalBytesProcessed = totalBytes
	q.statsMu.Unlock()
}
