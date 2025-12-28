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
// Firewall Hooks Error Types
// =============================================================================

var (
	// ErrFirewallNotEnabled indicates firewall integration is disabled.
	ErrFirewallNotEnabled = errors.New("firewall integration not enabled")
	// ErrFirewallServiceUnavailable indicates firewall service is down.
	ErrFirewallServiceUnavailable = errors.New("firewall service unavailable")
	// ErrInspectionTimeout indicates inspection request timed out.
	ErrInspectionTimeout = errors.New("inspection timeout")
	// ErrInspectionQueueFull indicates inspection queue is full.
	ErrInspectionQueueFull = errors.New("inspection queue full")
)

// =============================================================================
// Firewall Verdict Constants
// =============================================================================

// Verdict represents a firewall decision.
type Verdict int

const (
	// VerdictAllow permits the packet.
	VerdictAllow Verdict = iota
	// VerdictDeny blocks the packet.
	VerdictDeny
	// VerdictDrop silently drops the packet.
	VerdictDrop
)

// String returns the string representation of a verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictDeny:
		return "DENY"
	case VerdictDrop:
		return "DROP"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Packet Direction Constants
// =============================================================================

// PacketDirection represents traffic direction.
type PacketDirection int

const (
	// DirectionInbound is WAN → LAN traffic.
	DirectionInbound PacketDirection = iota
	// DirectionOutbound is LAN → WAN traffic.
	DirectionOutbound
)

// String returns the string representation of direction.
func (d PacketDirection) String() string {
	switch d {
	case DirectionInbound:
		return "INBOUND"
	case DirectionOutbound:
		return "OUTBOUND"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Connection State Constants
// =============================================================================

// ConnectionState represents connection lifecycle state.
type ConnectionState int

const (
	// ConnectionStateNew is a new connection.
	ConnectionStateNew ConnectionState = iota
	// ConnectionStateEstablished is an established connection.
	ConnectionStateEstablished
	// ConnectionStateClosing is a closing connection.
	ConnectionStateClosing
	// ConnectionStateClosed is a closed connection.
	ConnectionStateClosed
)

// String returns the string representation of state.
func (s ConnectionState) String() string {
	switch s {
	case ConnectionStateNew:
		return "NEW"
	case ConnectionStateEstablished:
		return "ESTABLISHED"
	case ConnectionStateClosing:
		return "CLOSING"
	case ConnectionStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Five Tuple Structure
// =============================================================================

// FiveTuple identifies a connection.
type FiveTuple struct {
	SrcIP    net.IP `json:"src_ip"`
	DstIP    net.IP `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

// String returns the string representation.
func (f *FiveTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (proto: %d)",
		f.SrcIP.String(), f.SrcPort,
		f.DstIP.String(), f.DstPort,
		f.Protocol)
}

// Key returns a cache key for this tuple.
func (f *FiveTuple) Key() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		f.SrcIP.String(), f.SrcPort,
		f.DstIP.String(), f.DstPort,
		f.Protocol)
}

// =============================================================================
// NAT Mapping Structure
// =============================================================================

// NATMapping represents NAT translation info.
type NATMapping struct {
	OriginalIP     net.IP `json:"original_ip"`
	OriginalPort   uint16 `json:"original_port"`
	TranslatedIP   net.IP `json:"translated_ip"`
	TranslatedPort uint16 `json:"translated_port"`
}

// =============================================================================
// Verdict Cache Entry
// =============================================================================

// verdictCacheEntry represents a cached verdict.
type verdictCacheEntry struct {
	Verdict   Verdict
	Reason    string
	ExpiresAt time.Time
}

// =============================================================================
// Inspection Request
// =============================================================================

// inspectionRequest represents a packet awaiting inspection.
type inspectionRequest struct {
	Packet       []byte
	FiveTuple    *FiveTuple
	Direction    PacketDirection
	WanInterface string
	ResultChan   chan *inspectionResult
}

// inspectionResult represents inspection result.
type inspectionResult struct {
	Verdict Verdict
	Reason  string
	Error   error
}

// =============================================================================
// Firewall Hooks Configuration
// =============================================================================

// FirewallHooksConfig contains firewall integration configuration.
type FirewallHooksConfig struct {
	// Enabled enables firewall integration.
	Enabled bool `json:"enabled"`
	// ServiceAddress is the firewall service gRPC address.
	ServiceAddress string `json:"service_address"`
	// VerdictCacheSize is the LRU cache size.
	VerdictCacheSize int `json:"verdict_cache_size"`
	// VerdictCacheTTL is the cache entry TTL.
	VerdictCacheTTL time.Duration `json:"verdict_cache_ttl"`
	// FailMode is "open" (allow on failure) or "closed" (deny on failure).
	FailMode string `json:"fail_mode"`
	// InspectionTimeout is the timeout for firewall inspection.
	InspectionTimeout time.Duration `json:"inspection_timeout"`
	// InspectionWorkers is the number of parallel inspection workers.
	InspectionWorkers int `json:"inspection_workers"`
	// InspectionQueueSize is the inspection queue capacity.
	InspectionQueueSize int `json:"inspection_queue_size"`
}

// DefaultFirewallHooksConfig returns the default configuration.
func DefaultFirewallHooksConfig() *FirewallHooksConfig {
	return &FirewallHooksConfig{
		Enabled:             true,
		ServiceAddress:      "localhost:50062",
		VerdictCacheSize:    100000,
		VerdictCacheTTL:     60 * time.Second,
		FailMode:            "open",
		InspectionTimeout:   50 * time.Millisecond,
		InspectionWorkers:   8,
		InspectionQueueSize: 10000,
	}
}

// =============================================================================
// Firewall Hooks
// =============================================================================

// FirewallHooks manages firewall integration.
type FirewallHooks struct {
	// Configuration.
	config *FirewallHooksConfig

	// Verdict cache.
	verdictCache   map[string]*verdictCacheEntry
	verdictCacheMu sync.RWMutex
	cacheHits      uint64
	cacheMisses    uint64

	// Inspection queue.
	inspectionQueue chan *inspectionRequest

	// Event publisher for blocked packets.
	eventPublisher *EventPublisher

	// Statistics.
	packetsInspected uint64
	packetsAllowed   uint64
	packetsBlocked   uint64
	inspectionErrors uint64
	totalLatencyNs   uint64
	latencyCount     uint64

	// Lifecycle.
	wg        sync.WaitGroup
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewFirewallHooks creates a new firewall hooks instance.
func NewFirewallHooks(config *FirewallHooksConfig, eventPublisher *EventPublisher) *FirewallHooks {
	if config == nil {
		config = DefaultFirewallHooksConfig()
	}

	return &FirewallHooks{
		config:          config,
		verdictCache:    make(map[string]*verdictCacheEntry, config.VerdictCacheSize),
		inspectionQueue: make(chan *inspectionRequest, config.InspectionQueueSize),
		eventPublisher:  eventPublisher,
		stopChan:        make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins firewall integration.
func (fh *FirewallHooks) Start(ctx context.Context) error {
	fh.runningMu.Lock()
	defer fh.runningMu.Unlock()

	if fh.running {
		return nil
	}

	if !fh.config.Enabled {
		fh.running = true
		return nil
	}

	// Start inspection workers.
	for i := 0; i < fh.config.InspectionWorkers; i++ {
		fh.wg.Add(1)
		go fh.inspectionWorker(i)
	}

	// Start cache cleaner.
	fh.wg.Add(1)
	go fh.cacheCleaner()

	fh.running = true
	return nil
}

// Stop gracefully shuts down firewall integration.
func (fh *FirewallHooks) Stop() error {
	fh.runningMu.Lock()
	if !fh.running {
		fh.runningMu.Unlock()
		return nil
	}
	fh.running = false
	fh.runningMu.Unlock()

	close(fh.stopChan)

	// Wait for workers with timeout.
	done := make(chan struct{})
	go func() {
		fh.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished cleanly.
	case <-time.After(30 * time.Second):
		// Timeout waiting for workers.
	}

	return nil
}

// inspectionWorker processes inspection requests.
func (fh *FirewallHooks) inspectionWorker(id int) {
	_ = id // Used for logging in production.
	defer fh.wg.Done()

	for {
		select {
		case <-fh.stopChan:
			return
		case req := <-fh.inspectionQueue:
			if req != nil {
				fh.processInspectionRequest(req)
			}
		}
	}
}

// cacheCleaner periodically evicts expired cache entries.
func (fh *FirewallHooks) cacheCleaner() {
	defer fh.wg.Done()

	ticker := time.NewTicker(fh.config.VerdictCacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-fh.stopChan:
			return
		case <-ticker.C:
			fh.cleanExpiredCache()
		}
	}
}

// cleanExpiredCache removes expired cache entries.
func (fh *FirewallHooks) cleanExpiredCache() {
	fh.verdictCacheMu.Lock()
	defer fh.verdictCacheMu.Unlock()

	now := time.Now()
	for key, entry := range fh.verdictCache {
		if now.After(entry.ExpiresAt) {
			delete(fh.verdictCache, key)
		}
	}
}

// =============================================================================
// Packet Inspection
// =============================================================================

// InspectPacket inspects a packet and returns a verdict.
func (fh *FirewallHooks) InspectPacket(packet []byte, fiveTuple *FiveTuple, direction PacketDirection, wanInterface string) (Verdict, string) {
	if !fh.config.Enabled {
		return VerdictAllow, "firewall disabled"
	}

	startTime := time.Now()
	defer func() {
		atomic.AddUint64(&fh.totalLatencyNs, uint64(time.Since(startTime).Nanoseconds()))
		atomic.AddUint64(&fh.latencyCount, 1)
	}()

	atomic.AddUint64(&fh.packetsInspected, 1)

	// Check cache first.
	cacheKey := fiveTuple.Key()
	if verdict, reason, found := fh.checkCache(cacheKey); found {
		atomic.AddUint64(&fh.cacheHits, 1)
		if verdict == VerdictAllow {
			atomic.AddUint64(&fh.packetsAllowed, 1)
		} else {
			atomic.AddUint64(&fh.packetsBlocked, 1)
		}
		return verdict, reason
	}
	atomic.AddUint64(&fh.cacheMisses, 1)

	// Create inspection request.
	resultChan := make(chan *inspectionResult, 1)
	req := &inspectionRequest{
		Packet:       packet,
		FiveTuple:    fiveTuple,
		Direction:    direction,
		WanInterface: wanInterface,
		ResultChan:   resultChan,
	}

	// Try to enqueue.
	select {
	case fh.inspectionQueue <- req:
		// Enqueued successfully.
	default:
		// Queue full, apply fail mode.
		atomic.AddUint64(&fh.inspectionErrors, 1)
		return fh.applyFailMode("inspection queue full")
	}

	// Wait for result with timeout.
	select {
	case result := <-resultChan:
		if result.Error != nil {
			atomic.AddUint64(&fh.inspectionErrors, 1)
			return fh.applyFailMode(result.Error.Error())
		}

		// Cache the result.
		fh.cacheVerdict(cacheKey, result.Verdict, result.Reason)

		if result.Verdict == VerdictAllow {
			atomic.AddUint64(&fh.packetsAllowed, 1)
		} else {
			atomic.AddUint64(&fh.packetsBlocked, 1)
			fh.onPacketBlocked(packet, fiveTuple, result.Reason, wanInterface)
		}

		return result.Verdict, result.Reason

	case <-time.After(fh.config.InspectionTimeout):
		atomic.AddUint64(&fh.inspectionErrors, 1)
		return fh.applyFailMode("inspection timeout")
	}
}

// processInspectionRequest processes a single inspection request.
func (fh *FirewallHooks) processInspectionRequest(req *inspectionRequest) {
	// In production, this would call the Firewall Engine via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), fh.config.InspectionTimeout)
	// defer cancel()
	//
	// resp, err := fh.firewallClient.InspectPacket(ctx, &pb.InspectPacketRequest{
	//     Packet:       req.Packet,
	//     SrcIp:        req.FiveTuple.SrcIP.String(),
	//     DstIp:        req.FiveTuple.DstIP.String(),
	//     SrcPort:      uint32(req.FiveTuple.SrcPort),
	//     DstPort:      uint32(req.FiveTuple.DstPort),
	//     Protocol:     uint32(req.FiveTuple.Protocol),
	//     Direction:    req.Direction.String(),
	//     WanInterface: req.WanInterface,
	// })
	// if err != nil {
	//     req.ResultChan <- &inspectionResult{Error: err}
	//     return
	// }
	//
	// verdict := VerdictAllow
	// switch resp.Verdict {
	// case pb.Verdict_DENY:
	//     verdict = VerdictDeny
	// case pb.Verdict_DROP:
	//     verdict = VerdictDrop
	// }
	//
	// req.ResultChan <- &inspectionResult{
	//     Verdict: verdict,
	//     Reason:  resp.Reason,
	// }

	// Stub: Allow all traffic.
	req.ResultChan <- &inspectionResult{
		Verdict: VerdictAllow,
		Reason:  "allowed by default policy",
	}
}

// checkCache checks the verdict cache.
func (fh *FirewallHooks) checkCache(key string) (Verdict, string, bool) {
	fh.verdictCacheMu.RLock()
	defer fh.verdictCacheMu.RUnlock()

	entry, exists := fh.verdictCache[key]
	if !exists {
		return VerdictAllow, "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		return VerdictAllow, "", false
	}

	return entry.Verdict, entry.Reason, true
}

// cacheVerdict caches a verdict.
func (fh *FirewallHooks) cacheVerdict(key string, verdict Verdict, reason string) {
	fh.verdictCacheMu.Lock()
	defer fh.verdictCacheMu.Unlock()

	// Check cache size limit.
	if len(fh.verdictCache) >= fh.config.VerdictCacheSize {
		// Evict oldest entry (simplified - would use LRU in production).
		for k := range fh.verdictCache {
			delete(fh.verdictCache, k)
			break
		}
	}

	fh.verdictCache[key] = &verdictCacheEntry{
		Verdict:   verdict,
		Reason:    reason,
		ExpiresAt: time.Now().Add(fh.config.VerdictCacheTTL),
	}
}

// applyFailMode returns verdict based on fail mode.
func (fh *FirewallHooks) applyFailMode(reason string) (Verdict, string) {
	if fh.config.FailMode == "closed" {
		return VerdictDeny, fmt.Sprintf("fail-closed: %s", reason)
	}
	return VerdictAllow, fmt.Sprintf("fail-open: %s", reason)
}

// =============================================================================
// Connection State Management
// =============================================================================

// UpdateConnectionState updates firewall connection tracking.
func (fh *FirewallHooks) UpdateConnectionState(fiveTuple *FiveTuple, state ConnectionState, natMapping *NATMapping) error {
	if !fh.config.Enabled {
		return nil
	}

	// In production, this would call the Firewall Engine via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), fh.config.InspectionTimeout)
	// defer cancel()
	//
	// req := &pb.UpdateConnectionStateRequest{
	//     SrcIp:    fiveTuple.SrcIP.String(),
	//     DstIp:    fiveTuple.DstIP.String(),
	//     SrcPort:  uint32(fiveTuple.SrcPort),
	//     DstPort:  uint32(fiveTuple.DstPort),
	//     Protocol: uint32(fiveTuple.Protocol),
	//     State:    state.String(),
	// }
	//
	// if natMapping != nil {
	//     req.NatMapping = &pb.NatMapping{
	//         OriginalIp:     natMapping.OriginalIP.String(),
	//         OriginalPort:   uint32(natMapping.OriginalPort),
	//         TranslatedIp:   natMapping.TranslatedIP.String(),
	//         TranslatedPort: uint32(natMapping.TranslatedPort),
	//     }
	// }
	//
	// _, err := fh.firewallClient.UpdateConnectionState(ctx, req)
	// return err

	return nil
}

// =============================================================================
// Cache Management
// =============================================================================

// InvalidateCacheEntry removes a verdict from the cache.
func (fh *FirewallHooks) InvalidateCacheEntry(fiveTuple *FiveTuple) {
	fh.verdictCacheMu.Lock()
	defer fh.verdictCacheMu.Unlock()

	delete(fh.verdictCache, fiveTuple.Key())
}

// InvalidateAllCache clears the entire verdict cache.
func (fh *FirewallHooks) InvalidateAllCache() {
	fh.verdictCacheMu.Lock()
	defer fh.verdictCacheMu.Unlock()

	fh.verdictCache = make(map[string]*verdictCacheEntry, fh.config.VerdictCacheSize)
}

// =============================================================================
// Blocked Packet Handling
// =============================================================================

// onPacketBlocked handles a blocked packet.
func (fh *FirewallHooks) onPacketBlocked(packet []byte, fiveTuple *FiveTuple, reason, wanInterface string) {
	// Publish event.
	if fh.eventPublisher != nil {
		_ = fh.eventPublisher.Publish(EventTypeSecurityPolicyViolation, map[string]interface{}{
			"five_tuple":    fiveTuple.String(),
			"reason":        reason,
			"wan_interface": wanInterface,
			"packet_size":   len(packet),
		})
	}
}

// OnPacketBlocked is called by the routing engine when a packet is blocked.
func (fh *FirewallHooks) OnPacketBlocked(packet []byte, fiveTuple *FiveTuple, reason, wanInterface string) {
	atomic.AddUint64(&fh.packetsBlocked, 1)
	fh.onPacketBlocked(packet, fiveTuple, reason, wanInterface)
}

// =============================================================================
// Statistics
// =============================================================================

// FirewallStats contains firewall statistics.
type FirewallStats struct {
	PacketsInspected       uint64  `json:"packets_inspected"`
	PacketsAllowed         uint64  `json:"packets_allowed"`
	PacketsBlocked         uint64  `json:"packets_blocked"`
	InspectionErrors       uint64  `json:"inspection_errors"`
	CacheHitRate           float64 `json:"cache_hit_rate"`
	AvgInspectionLatencyMs float64 `json:"avg_inspection_latency_ms"`
	CacheSize              int     `json:"cache_size"`
	QueueDepth             int     `json:"queue_depth"`
	ServiceStatus          string  `json:"service_status"`
}

// GetFirewallStats returns firewall statistics.
func (fh *FirewallHooks) GetFirewallStats() *FirewallStats {
	cacheHits := atomic.LoadUint64(&fh.cacheHits)
	cacheMisses := atomic.LoadUint64(&fh.cacheMisses)
	totalLatencyNs := atomic.LoadUint64(&fh.totalLatencyNs)
	latencyCount := atomic.LoadUint64(&fh.latencyCount)

	var cacheHitRate float64
	if total := cacheHits + cacheMisses; total > 0 {
		cacheHitRate = float64(cacheHits) / float64(total) * 100
	}

	var avgLatencyMs float64
	if latencyCount > 0 {
		avgLatencyMs = float64(totalLatencyNs) / float64(latencyCount) / 1e6
	}

	fh.verdictCacheMu.RLock()
	cacheSize := len(fh.verdictCache)
	fh.verdictCacheMu.RUnlock()

	status := "UP"
	if !fh.config.Enabled {
		status = "DISABLED"
	}

	return &FirewallStats{
		PacketsInspected:       atomic.LoadUint64(&fh.packetsInspected),
		PacketsAllowed:         atomic.LoadUint64(&fh.packetsAllowed),
		PacketsBlocked:         atomic.LoadUint64(&fh.packetsBlocked),
		InspectionErrors:       atomic.LoadUint64(&fh.inspectionErrors),
		CacheHitRate:           cacheHitRate,
		AvgInspectionLatencyMs: avgLatencyMs,
		CacheSize:              cacheSize,
		QueueDepth:             len(fh.inspectionQueue),
		ServiceStatus:          status,
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies firewall integration is operational.
func (fh *FirewallHooks) HealthCheck() error {
	if !fh.config.Enabled {
		return nil
	}

	fh.runningMu.Lock()
	running := fh.running
	fh.runningMu.Unlock()

	if !running {
		return errors.New("firewall hooks not running")
	}

	// Check queue not full.
	if float64(len(fh.inspectionQueue))/float64(cap(fh.inspectionQueue)) > 0.9 {
		return errors.New("inspection queue near capacity")
	}

	return nil
}

// IsEnabled returns whether firewall integration is enabled.
func (fh *FirewallHooks) IsEnabled() bool {
	return fh.config.Enabled
}

// GetConfig returns the current configuration.
func (fh *FirewallHooks) GetConfig() *FirewallHooksConfig {
	return fh.config
}
