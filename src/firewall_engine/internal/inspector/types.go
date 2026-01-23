// Package inspector provides the main packet processing pipeline for the firewall engine.
// It orchestrates inspection, matching, enforcement, and statistics - the "brain coordinator"
// that ties Phase 2 (rule matching) and Phase 3 (enforcement) together.
//
// Architecture:
//
//	SafeOps gRPC Stream (metadata)
//	        ↓
//	  Stream Handler (handler.go)
//	        ↓
//	  Packet Channel (buffered, 10K capacity)
//	        ↓
//	  Worker Pool (8 goroutines)
//	        ↓
//	  ┌─────┴─────┐
//	  ↓           ↓
//	Fast-Path   Full Pipeline
//	  ↓           ↓
//	         Packet Inspector
//	              ↓
//	  ┌─────┬─────┴─────┬─────┐
//	  ↓     ↓           ↓     ↓
//	Cache  Conn       Rules  Enforce
//	Check  Track     Match
//
// Performance Targets:
//   - Cache HIT (80%): ~10-15μs latency
//   - Cache MISS (20%): ~50-60μs latency
//   - Throughput: 100K+ packets/sec sustained
package inspector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrInspectorClosed is returned when operations are attempted on a closed inspector.
	ErrInspectorClosed = errors.New("inspector is closed")

	// ErrPacketNil is returned when a nil packet is provided.
	ErrPacketNil = errors.New("packet metadata is nil")

	// ErrPacketInvalid is returned when packet data is invalid.
	ErrPacketInvalid = errors.New("packet metadata is invalid")

	// ErrStreamDisconnected is returned when the gRPC stream is disconnected.
	ErrStreamDisconnected = errors.New("metadata stream disconnected")

	// ErrChannelFull is returned when the packet channel is at capacity.
	ErrChannelFull = errors.New("packet channel is full")

	// ErrWorkerPoolStopped is returned when the worker pool is not running.
	ErrWorkerPoolStopped = errors.New("worker pool is stopped")

	// ErrEnforcementFailed is returned when verdict enforcement fails.
	ErrEnforcementFailed = errors.New("enforcement failed")

	// ErrCacheMiss is returned when verdict is not in cache.
	ErrCacheMiss = errors.New("cache miss")

	// ErrNoRuleMatch is returned when no rule matches the packet.
	ErrNoRuleMatch = errors.New("no rule matched")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("operation timed out")

	// ErrConnectionNotFound is returned when connection tracking lookup fails.
	ErrConnectionNotFound = errors.New("connection not found")
)

// ============================================================================
// Inspection Result
// ============================================================================

// InspectionResult contains the complete result of inspecting a packet.
type InspectionResult struct {
	// Verdict is the final decision (ALLOW, DROP, BLOCK, REDIRECT, REJECT).
	Verdict models.Verdict `json:"verdict"`

	// MatchedRule is the rule that matched (nil if default policy).
	MatchedRule *models.FirewallRule `json:"matched_rule,omitempty"`

	// RuleID is the ID of the matched rule.
	RuleID string `json:"rule_id,omitempty"`

	// RuleName is the name of the matched rule.
	RuleName string `json:"rule_name,omitempty"`

	// Reason explains why this verdict was reached.
	Reason string `json:"reason"`

	// === Timing ===

	// CacheHit indicates if the verdict came from cache.
	CacheHit bool `json:"cache_hit"`

	// FastPath indicates if fast-path optimization was used.
	FastPath bool `json:"fast_path"`

	// FastPathType identifies which fast-path matched (if any).
	FastPathType FastPathType `json:"fast_path_type,omitempty"`

	// TotalDuration is the total time to process the packet.
	TotalDuration time.Duration `json:"total_duration"`

	// CacheLookupDuration is time spent on cache lookup.
	CacheLookupDuration time.Duration `json:"cache_lookup_duration,omitempty"`

	// RuleMatchDuration is time spent on rule matching.
	RuleMatchDuration time.Duration `json:"rule_match_duration,omitempty"`

	// EnforcementDuration is time spent on enforcement.
	EnforcementDuration time.Duration `json:"enforcement_duration,omitempty"`

	// === Connection State ===

	// ConnectionState is the state of the connection (NEW, ESTABLISHED, etc.).
	ConnectionState models.ConnectionState `json:"connection_state"`

	// IsNewConnection indicates if this is the first packet of a connection.
	IsNewConnection bool `json:"is_new_connection"`

	// === Enforcement ===

	// EnforcementSuccess indicates if enforcement succeeded.
	EnforcementSuccess bool `json:"enforcement_success"`

	// EnforcementError contains any enforcement error message.
	EnforcementError string `json:"enforcement_error,omitempty"`

	// === Metadata ===

	// Timestamp is when the inspection occurred.
	Timestamp time.Time `json:"timestamp"`

	// WorkerID identifies which worker processed this packet.
	WorkerID int `json:"worker_id,omitempty"`

	// PacketID is a unique identifier for tracking.
	PacketID uint64 `json:"packet_id,omitempty"`
}

// NewInspectionResult creates a new inspection result with default values.
func NewInspectionResult() *InspectionResult {
	return &InspectionResult{
		Verdict:   models.VerdictAllow,
		Timestamp: time.Now(),
	}
}

// WithVerdict sets the verdict and returns the result for chaining.
func (r *InspectionResult) WithVerdict(verdict models.Verdict) *InspectionResult {
	r.Verdict = verdict
	return r
}

// WithRule sets the matched rule and returns the result for chaining.
func (r *InspectionResult) WithRule(rule *models.FirewallRule) *InspectionResult {
	r.MatchedRule = rule
	if rule != nil {
		r.RuleID = rule.ID.String()
		r.RuleName = rule.Name
	}
	return r
}

// WithReason sets the reason and returns the result for chaining.
func (r *InspectionResult) WithReason(reason string) *InspectionResult {
	r.Reason = reason
	return r
}

// WithCacheHit marks this as a cache hit.
func (r *InspectionResult) WithCacheHit(duration time.Duration) *InspectionResult {
	r.CacheHit = true
	r.CacheLookupDuration = duration
	return r
}

// WithFastPath marks this as a fast-path hit.
func (r *InspectionResult) WithFastPath(fpType FastPathType) *InspectionResult {
	r.FastPath = true
	r.FastPathType = fpType
	return r
}

// WithTiming sets the total duration.
func (r *InspectionResult) WithTiming(total time.Duration) *InspectionResult {
	r.TotalDuration = total
	return r
}

// WithConnectionState sets connection information.
func (r *InspectionResult) WithConnectionState(state models.ConnectionState, isNew bool) *InspectionResult {
	r.ConnectionState = state
	r.IsNewConnection = isNew
	return r
}

// WithEnforcement sets enforcement result.
func (r *InspectionResult) WithEnforcement(success bool, err error) *InspectionResult {
	r.EnforcementSuccess = success
	if err != nil {
		r.EnforcementError = err.Error()
	}
	return r
}

// WithWorker sets the worker ID.
func (r *InspectionResult) WithWorker(id int) *InspectionResult {
	r.WorkerID = id
	return r
}

// ============================================================================
// Fast-Path Types
// ============================================================================

// FastPathType identifies which fast-path optimization matched.
type FastPathType int8

const (
	// FastPathNone indicates no fast-path matched.
	FastPathNone FastPathType = 0

	// FastPathBlocklist indicates the IP was in the blocklist.
	FastPathBlocklist FastPathType = 1

	// FastPathDNSAllow indicates DNS traffic was auto-allowed.
	FastPathDNSAllow FastPathType = 2

	// FastPathEstablished indicates an established connection to trusted IP.
	FastPathEstablished FastPathType = 3

	// FastPathCDN indicates traffic to CDN IPs was auto-allowed.
	FastPathCDN FastPathType = 4

	// FastPathLocalhost indicates localhost traffic was auto-allowed.
	FastPathLocalhost FastPathType = 5

	// FastPathCacheHit indicates the verdict was cached.
	FastPathCacheHit FastPathType = 6
)

// fastPathTypeNames maps FastPathType to human-readable strings.
var fastPathTypeNames = map[FastPathType]string{
	FastPathNone:        "NONE",
	FastPathBlocklist:   "BLOCKLIST",
	FastPathDNSAllow:    "DNS_ALLOW",
	FastPathEstablished: "ESTABLISHED",
	FastPathCDN:         "CDN",
	FastPathLocalhost:   "LOCALHOST",
	FastPathCacheHit:    "CACHE_HIT",
}

// String returns the human-readable name.
func (f FastPathType) String() string {
	if name, ok := fastPathTypeNames[f]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", f)
}

// FastPathResult contains the result of fast-path evaluation.
type FastPathResult struct {
	// Matched indicates if a fast-path rule matched.
	Matched bool

	// Type identifies which fast-path matched.
	Type FastPathType

	// Verdict is the verdict from fast-path (if matched).
	Verdict models.Verdict

	// Reason explains the fast-path decision.
	Reason string

	// Duration is how long fast-path evaluation took.
	Duration time.Duration
}

// ============================================================================
// Inspector Configuration
// ============================================================================

// InspectorConfig contains configuration for the packet inspector.
type InspectorConfig struct {
	// === Worker Pool ===

	// WorkerCount is the number of parallel worker goroutines.
	// Default: 8 (matching typical CPU core count)
	WorkerCount int `json:"worker_count" toml:"worker_count"`

	// ChannelBufferSize is the capacity of the packet channel.
	// Default: 10000 (absorbs traffic bursts)
	ChannelBufferSize int `json:"channel_buffer_size" toml:"channel_buffer_size"`

	// === gRPC Connection ===

	// SafeOpsAddress is the SafeOps gRPC server address.
	SafeOpsAddress string `json:"safeops_address" toml:"safeops_address"`

	// ReconnectInitialDelay is the initial delay before reconnecting.
	ReconnectInitialDelay time.Duration `json:"reconnect_initial_delay" toml:"reconnect_initial_delay"`

	// ReconnectMaxDelay is the maximum delay between reconnection attempts.
	ReconnectMaxDelay time.Duration `json:"reconnect_max_delay" toml:"reconnect_max_delay"`

	// StreamTimeout is the timeout for stream operations.
	StreamTimeout time.Duration `json:"stream_timeout" toml:"stream_timeout"`

	// === Fast-Path ===

	// EnableFastPath enables fast-path optimizations.
	EnableFastPath bool `json:"enable_fast_path" toml:"enable_fast_path"`

	// EnableBlocklistFastPath enables blocklist fast-path.
	EnableBlocklistFastPath bool `json:"enable_blocklist_fast_path" toml:"enable_blocklist_fast_path"`

	// EnableDNSFastPath enables DNS auto-allow fast-path.
	EnableDNSFastPath bool `json:"enable_dns_fast_path" toml:"enable_dns_fast_path"`

	// EnableEstablishedFastPath enables established connection fast-path.
	EnableEstablishedFastPath bool `json:"enable_established_fast_path" toml:"enable_established_fast_path"`

	// EnableCDNFastPath enables CDN IP fast-path.
	EnableCDNFastPath bool `json:"enable_cdn_fast_path" toml:"enable_cdn_fast_path"`

	// === Caching ===

	// EnableCache enables verdict caching.
	EnableCache bool `json:"enable_cache" toml:"enable_cache"`

	// CacheCapacity is the maximum number of cached verdicts.
	CacheCapacity int `json:"cache_capacity" toml:"cache_capacity"`

	// CacheTTL is the time-to-live for cached verdicts.
	CacheTTL time.Duration `json:"cache_ttl" toml:"cache_ttl"`

	// === Enforcement ===

	// EnableEnforcement enables verdict enforcement.
	EnableEnforcement bool `json:"enable_enforcement" toml:"enable_enforcement"`

	// EnforcementRetries is the number of enforcement retry attempts.
	EnforcementRetries int `json:"enforcement_retries" toml:"enforcement_retries"`

	// FailOpen allows packets through if enforcement fails.
	FailOpen bool `json:"fail_open" toml:"fail_open"`

	// === Logging ===

	// EnableLogging enables detailed logging.
	EnableLogging bool `json:"enable_logging" toml:"enable_logging"`

	// LogAllPackets logs every packet (verbose).
	LogAllPackets bool `json:"log_all_packets" toml:"log_all_packets"`

	// LogDroppedOnly logs only dropped/denied packets.
	LogDroppedOnly bool `json:"log_dropped_only" toml:"log_dropped_only"`

	// === Statistics ===

	// EnableStatistics enables statistics collection.
	EnableStatistics bool `json:"enable_statistics" toml:"enable_statistics"`

	// StatsReportInterval is how often to report statistics.
	StatsReportInterval time.Duration `json:"stats_report_interval" toml:"stats_report_interval"`
}

// DefaultInspectorConfig returns the default configuration.
func DefaultInspectorConfig() *InspectorConfig {
	return &InspectorConfig{
		// Worker Pool
		WorkerCount:       8,
		ChannelBufferSize: 10000,

		// gRPC Connection
		SafeOpsAddress:        "127.0.0.1:50053",
		ReconnectInitialDelay: 1 * time.Second,
		ReconnectMaxDelay:     60 * time.Second,
		StreamTimeout:         30 * time.Second,

		// Fast-Path
		EnableFastPath:            true,
		EnableBlocklistFastPath:   true,
		EnableDNSFastPath:         true,
		EnableEstablishedFastPath: true,
		EnableCDNFastPath:         true,

		// Caching
		EnableCache:   true,
		CacheCapacity: 100000,
		CacheTTL:      60 * time.Second,

		// Enforcement
		EnableEnforcement:  true,
		EnforcementRetries: 3,
		FailOpen:           true,

		// Logging
		EnableLogging:  true,
		LogAllPackets:  false,
		LogDroppedOnly: true,

		// Statistics
		EnableStatistics:    true,
		StatsReportInterval: 60 * time.Second,
	}
}

// Validate checks the configuration for errors.
func (c *InspectorConfig) Validate() error {
	if c.WorkerCount < 1 {
		return fmt.Errorf("worker_count must be >= 1, got %d", c.WorkerCount)
	}
	if c.WorkerCount > 256 {
		return fmt.Errorf("worker_count must be <= 256, got %d", c.WorkerCount)
	}
	if c.ChannelBufferSize < 100 {
		return fmt.Errorf("channel_buffer_size must be >= 100, got %d", c.ChannelBufferSize)
	}
	if c.SafeOpsAddress == "" {
		return fmt.Errorf("safeops_address is required")
	}
	if c.CacheCapacity < 1000 && c.EnableCache {
		return fmt.Errorf("cache_capacity must be >= 1000, got %d", c.CacheCapacity)
	}
	if c.CacheTTL < time.Second && c.EnableCache {
		return fmt.Errorf("cache_ttl must be >= 1s")
	}
	if c.EnforcementRetries < 0 {
		return fmt.Errorf("enforcement_retries must be >= 0")
	}
	return nil
}

// ============================================================================
// Inspector Statistics
// ============================================================================

// InspectorStats contains packet inspection statistics.
type InspectorStats struct {
	// === Packet Counters ===
	PacketsReceived  atomic.Uint64
	PacketsProcessed atomic.Uint64
	PacketsDropped   atomic.Uint64 // Channel full, malformed, etc.

	// === Verdict Counters ===
	VerdictAllow    atomic.Uint64
	VerdictBlock    atomic.Uint64
	VerdictDrop     atomic.Uint64
	VerdictRedirect atomic.Uint64
	VerdictReject   atomic.Uint64

	// === Cache Statistics ===
	CacheHits    atomic.Uint64
	CacheMisses  atomic.Uint64
	CacheInserts atomic.Uint64
	CacheEvicts  atomic.Uint64

	// === Fast-Path Statistics ===
	FastPathHits        atomic.Uint64
	FastPathMisses      atomic.Uint64
	FastPathBlocklist   atomic.Uint64
	FastPathDNS         atomic.Uint64
	FastPathEstablished atomic.Uint64
	FastPathCDN         atomic.Uint64

	// === Connection Tracking ===
	ConnectionsNew         atomic.Uint64
	ConnectionsEstablished atomic.Uint64
	ConnectionsClosing     atomic.Uint64

	// === Enforcement ===
	EnforcementSuccess atomic.Uint64
	EnforcementFailed  atomic.Uint64
	EnforcementRetries atomic.Uint64

	// === Timing (nanoseconds) ===
	TotalProcessingTimeNs atomic.Uint64
	CacheLookupTimeNs     atomic.Uint64
	RuleMatchTimeNs       atomic.Uint64
	EnforcementTimeNs     atomic.Uint64

	// === Worker Statistics ===
	WorkerPacketCounts []atomic.Uint64 // Per-worker packet counts

	// === Errors ===
	ErrorCount atomic.Uint64
}

// NewInspectorStats creates a new statistics container.
func NewInspectorStats(workerCount int) *InspectorStats {
	return &InspectorStats{
		WorkerPacketCounts: make([]atomic.Uint64, workerCount),
	}
}

// GetSnapshot returns a point-in-time copy of statistics.
func (s *InspectorStats) GetSnapshot() map[string]uint64 {
	return map[string]uint64{
		"packets_received":        s.PacketsReceived.Load(),
		"packets_processed":       s.PacketsProcessed.Load(),
		"packets_dropped":         s.PacketsDropped.Load(),
		"verdict_allow":           s.VerdictAllow.Load(),
		"verdict_block":           s.VerdictBlock.Load(),
		"verdict_drop":            s.VerdictDrop.Load(),
		"verdict_redirect":        s.VerdictRedirect.Load(),
		"verdict_reject":          s.VerdictReject.Load(),
		"cache_hits":              s.CacheHits.Load(),
		"cache_misses":            s.CacheMisses.Load(),
		"cache_hit_rate_percent":  s.getCacheHitRate(),
		"fast_path_hits":          s.FastPathHits.Load(),
		"fast_path_misses":        s.FastPathMisses.Load(),
		"fast_path_hit_rate":      s.getFastPathHitRate(),
		"connections_new":         s.ConnectionsNew.Load(),
		"connections_established": s.ConnectionsEstablished.Load(),
		"enforcement_success":     s.EnforcementSuccess.Load(),
		"enforcement_failed":      s.EnforcementFailed.Load(),
		"error_count":             s.ErrorCount.Load(),
	}
}

// getCacheHitRate calculates cache hit rate percentage.
func (s *InspectorStats) getCacheHitRate() uint64 {
	hits := s.CacheHits.Load()
	misses := s.CacheMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return (hits * 100) / total
}

// getFastPathHitRate calculates fast-path hit rate percentage.
func (s *InspectorStats) getFastPathHitRate() uint64 {
	hits := s.FastPathHits.Load()
	misses := s.FastPathMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return (hits * 100) / total
}

// RecordVerdict increments the appropriate verdict counter.
func (s *InspectorStats) RecordVerdict(verdict models.Verdict) {
	switch verdict {
	case models.VerdictAllow:
		s.VerdictAllow.Add(1)
	case models.VerdictBlock:
		s.VerdictBlock.Add(1)
	case models.VerdictDrop:
		s.VerdictDrop.Add(1)
	case models.VerdictRedirect:
		s.VerdictRedirect.Add(1)
	case models.VerdictReject:
		s.VerdictReject.Add(1)
	}
}

// RecordFastPath increments the appropriate fast-path counter.
func (s *InspectorStats) RecordFastPath(fpType FastPathType) {
	s.FastPathHits.Add(1)
	switch fpType {
	case FastPathBlocklist:
		s.FastPathBlocklist.Add(1)
	case FastPathDNSAllow:
		s.FastPathDNS.Add(1)
	case FastPathEstablished:
		s.FastPathEstablished.Add(1)
	case FastPathCDN:
		s.FastPathCDN.Add(1)
	}
}

// RecordTiming records timing statistics.
func (s *InspectorStats) RecordTiming(total, cache, match, enforce time.Duration) {
	s.TotalProcessingTimeNs.Add(uint64(total.Nanoseconds()))
	s.CacheLookupTimeNs.Add(uint64(cache.Nanoseconds()))
	s.RuleMatchTimeNs.Add(uint64(match.Nanoseconds()))
	s.EnforcementTimeNs.Add(uint64(enforce.Nanoseconds()))
}

// Reset clears all statistics.
func (s *InspectorStats) Reset() {
	s.PacketsReceived.Store(0)
	s.PacketsProcessed.Store(0)
	s.PacketsDropped.Store(0)
	s.VerdictAllow.Store(0)
	s.VerdictBlock.Store(0)
	s.VerdictDrop.Store(0)
	s.VerdictRedirect.Store(0)
	s.VerdictReject.Store(0)
	s.CacheHits.Store(0)
	s.CacheMisses.Store(0)
	s.FastPathHits.Store(0)
	s.FastPathMisses.Store(0)
	s.EnforcementSuccess.Store(0)
	s.EnforcementFailed.Store(0)
	s.ErrorCount.Store(0)
}

// ============================================================================
// Inspector Interface
// ============================================================================

// PacketInspector defines the interface for packet inspection.
type PacketInspector interface {
	// Inspect processes a packet through the full inspection pipeline.
	Inspect(ctx context.Context, packet *models.PacketMetadata) (*InspectionResult, error)

	// Start begins the inspection pipeline (workers, handlers).
	Start(ctx context.Context) error

	// Stop gracefully shuts down the inspector.
	Stop() error

	// GetStats returns current statistics.
	GetStats() *InspectorStats

	// IsRunning returns true if the inspector is running.
	IsRunning() bool
}

// ============================================================================
// Fast-Path Evaluator Interface
// ============================================================================

// FastPathEvaluator defines the interface for fast-path evaluation.
type FastPathEvaluator interface {
	// Evaluate checks if a packet matches any fast-path rule.
	Evaluate(ctx context.Context, packet *models.PacketMetadata, connState models.ConnectionState) *FastPathResult

	// AddToBlocklist adds an IP to the blocklist.
	AddToBlocklist(ip net.IP, reason string, ttl time.Duration)

	// RemoveFromBlocklist removes an IP from the blocklist.
	RemoveFromBlocklist(ip net.IP)

	// AddTrustedIP adds an IP to the trusted list.
	AddTrustedIP(ip net.IP)

	// RemoveTrustedIP removes an IP from the trusted list.
	RemoveTrustedIP(ip net.IP)

	// GetBlocklistSize returns the number of blocked IPs.
	GetBlocklistSize() int

	// GetTrustedIPCount returns the number of trusted IPs.
	GetTrustedIPCount() int
}

// ============================================================================
// Stream Handler Interface
// ============================================================================

// StreamHandler defines the interface for gRPC stream handling.
type StreamHandler interface {
	// Connect establishes connection to SafeOps.
	Connect(ctx context.Context) error

	// Disconnect closes the connection.
	Disconnect() error

	// IsConnected returns true if connected.
	IsConnected() bool

	// ReceivePacket blocks until a packet is received.
	ReceivePacket(ctx context.Context) (*models.PacketMetadata, error)

	// GetPacketChannel returns the packet channel for workers.
	GetPacketChannel() <-chan *models.PacketMetadata
}

// ============================================================================
// Worker Pool Interface
// ============================================================================

// WorkerPool defines the interface for parallel packet processing.
type WorkerPool interface {
	// Start begins all workers.
	Start(ctx context.Context) error

	// Stop gracefully stops all workers.
	Stop() error

	// Submit adds a packet to the processing queue.
	Submit(packet *models.PacketMetadata) error

	// GetWorkerCount returns the number of workers.
	GetWorkerCount() int

	// GetQueueSize returns the current queue size.
	GetQueueSize() int

	// GetQueueCapacity returns the queue capacity.
	GetQueueCapacity() int

	// IsRunning returns true if workers are running.
	IsRunning() bool
}

// ============================================================================
// Worker Function Type
// ============================================================================

// WorkerFunc is the function signature for worker processing.
type WorkerFunc func(ctx context.Context, workerID int, packet *models.PacketMetadata) (*InspectionResult, error)

// ============================================================================
// Packet Metadata Extensions
// ============================================================================

// InspectionContext contains additional context for packet inspection.
type InspectionContext struct {
	// Packet is the packet being inspected.
	Packet *models.PacketMetadata

	// ReceivedAt is when the packet was received.
	ReceivedAt time.Time

	// WorkerID identifies which worker is processing.
	WorkerID int

	// PacketID is a unique identifier.
	PacketID uint64

	// ConnectionEntry is the connection state (if tracked).
	ConnectionState models.ConnectionState

	// IsNewConnection indicates first packet of connection.
	IsNewConnection bool

	// CachedVerdict is the cached verdict (if any).
	CachedVerdict *models.VerdictResult

	// FastPathResult is the fast-path result (if any).
	FastPathResult *FastPathResult

	// mu protects concurrent access.
	mu sync.RWMutex
}

// NewInspectionContext creates a new inspection context.
func NewInspectionContext(packet *models.PacketMetadata, workerID int, packetID uint64) *InspectionContext {
	return &InspectionContext{
		Packet:     packet,
		ReceivedAt: time.Now(),
		WorkerID:   workerID,
		PacketID:   packetID,
	}
}

// Elapsed returns time since packet was received.
func (ic *InspectionContext) Elapsed() time.Duration {
	return time.Since(ic.ReceivedAt)
}

// SetConnectionState updates the connection state.
func (ic *InspectionContext) SetConnectionState(state models.ConnectionState, isNew bool) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.ConnectionState = state
	ic.IsNewConnection = isNew
}

// SetCachedVerdict sets the cached verdict.
func (ic *InspectionContext) SetCachedVerdict(v *models.VerdictResult) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.CachedVerdict = v
}

// SetFastPathResult sets the fast-path result.
func (ic *InspectionContext) SetFastPathResult(r *FastPathResult) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.FastPathResult = r
}
