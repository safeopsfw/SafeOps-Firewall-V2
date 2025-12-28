// Package integration provides cross-service integration components
// for the NIC Management service.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// IDS Hooks Error Types
// =============================================================================

var (
	// ErrIDSNotEnabled indicates IDS integration is disabled.
	ErrIDSNotEnabled = errors.New("IDS integration not enabled")
	// ErrIDSServiceUnavailable indicates IDS service is down.
	ErrIDSServiceUnavailable = errors.New("IDS service unavailable")
	// ErrSourceNotBlocked indicates source IP not in blocklist.
	ErrSourceNotBlocked = errors.New("source IP not in blocklist")
)

// =============================================================================
// IDS Verdict Constants
// =============================================================================

// IDSVerdict represents an IDS/IPS decision.
type IDSVerdict int

const (
	// IDSVerdictAllow permits the packet.
	IDSVerdictAllow IDSVerdict = iota
	// IDSVerdictAlert logs but allows the packet (IDS mode).
	IDSVerdictAlert
	// IDSVerdictBlock drops the packet (IPS mode).
	IDSVerdictBlock
)

// String returns the string representation.
func (v IDSVerdict) String() string {
	switch v {
	case IDSVerdictAllow:
		return "ALLOW"
	case IDSVerdictAlert:
		return "ALERT"
	case IDSVerdictBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Threat Severity Constants
// =============================================================================

// ThreatSeverity represents threat severity level.
type ThreatSeverity int

const (
	SeverityLowThreat ThreatSeverity = iota
	SeverityMediumThreat
	SeverityHighThreat
	SeverityCriticalThreat
)

// String returns the string representation.
func (s ThreatSeverity) String() string {
	switch s {
	case SeverityLowThreat:
		return "LOW"
	case SeverityMediumThreat:
		return "MEDIUM"
	case SeverityHighThreat:
		return "HIGH"
	case SeverityCriticalThreat:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Threat Info Structure
// =============================================================================

// ThreatInfo contains threat detection details.
type ThreatInfo struct {
	Name        string         `json:"name"`
	CVEID       string         `json:"cve_id,omitempty"`
	MitreAttack string         `json:"mitre_attack,omitempty"`
	Severity    ThreatSeverity `json:"severity"`
	Description string         `json:"description,omitempty"`
	SignatureID int            `json:"signature_id,omitempty"`
}

// =============================================================================
// Blocked Source Entry
// =============================================================================

// blockedSourceEntry represents a blocked IP with expiry.
type blockedSourceEntry struct {
	IP        net.IP
	Reason    string
	BlockedAt time.Time
	ExpiresAt time.Time
}

// =============================================================================
// Threat Cache Entry
// =============================================================================

// threatCacheEntry represents a cached threat verdict.
type threatCacheEntry struct {
	Verdict   IDSVerdict
	Threat    *ThreatInfo
	ExpiresAt time.Time
}

// =============================================================================
// IDS Inspection Request
// =============================================================================

// idsInspectionRequest represents a packet awaiting IDS inspection.
type idsInspectionRequest struct {
	Packet       []byte
	FiveTuple    *FiveTuple
	Direction    PacketDirection
	WanInterface string
	ResultChan   chan *idsInspectionResult
}

// idsInspectionResult represents IDS inspection result.
type idsInspectionResult struct {
	Verdict IDSVerdict
	Threat  *ThreatInfo
	Error   error
}

// =============================================================================
// IDS Hooks Configuration
// =============================================================================

// IDSHooksConfig contains IDS/IPS integration configuration.
type IDSHooksConfig struct {
	// Enabled enables IDS/IPS integration.
	Enabled bool `json:"enabled"`
	// ServiceAddress is the IDS/IPS gRPC address.
	ServiceAddress string `json:"service_address"`
	// IPSMode enables blocking (IPS) vs alerting-only (IDS).
	IPSMode bool `json:"ips_mode"`
	// SamplingRate is the fraction of packets to inspect (0.0-1.0).
	SamplingRate float64 `json:"sampling_rate"`
	// ThreatCacheTTL is the cache entry TTL.
	ThreatCacheTTL time.Duration `json:"threat_cache_ttl"`
	// BlockDuration is how long IPS blocks last.
	BlockDuration time.Duration `json:"block_duration"`
	// SignatureSyncInterval is signature update frequency.
	SignatureSyncInterval time.Duration `json:"signature_sync_interval"`
	// InspectionWorkers is the number of parallel workers.
	InspectionWorkers int `json:"inspection_workers"`
	// InspectionQueueSize is the queue capacity.
	InspectionQueueSize int `json:"inspection_queue_size"`
	// ThreatCacheSize is max cache entries.
	ThreatCacheSize int `json:"threat_cache_size"`
}

// DefaultIDSHooksConfig returns the default configuration.
func DefaultIDSHooksConfig() *IDSHooksConfig {
	return &IDSHooksConfig{
		Enabled:               true,
		ServiceAddress:        "localhost:50067",
		IPSMode:               true,
		SamplingRate:          0.1, // 10% sampling.
		ThreatCacheTTL:        5 * time.Minute,
		BlockDuration:         30 * time.Minute,
		SignatureSyncInterval: 60 * time.Second,
		InspectionWorkers:     4,
		InspectionQueueSize:   5000,
		ThreatCacheSize:       50000,
	}
}

// =============================================================================
// IDS Hooks
// =============================================================================

// IDSHooks manages IDS/IPS integration.
type IDSHooks struct {
	// Configuration.
	config *IDSHooksConfig

	// Threat cache.
	threatCache   map[string]*threatCacheEntry
	threatCacheMu sync.RWMutex

	// Blocked sources.
	blockedSources   map[string]*blockedSourceEntry
	blockedSourcesMu sync.RWMutex

	// Inspection queue.
	inspectionQueue chan *idsInspectionRequest

	// Event publisher and logger hooks.
	eventPublisher *EventPublisher
	loggerHooks    *LoggerHooks
	firewallHooks  *FirewallHooks

	// Sampling counter for deterministic sampling.
	sampleCounter uint64

	// Statistics.
	packetsInspected uint64
	packetsSkipped   uint64
	threatsDetected  uint64
	ipsBlocks        uint64
	cacheHits        uint64
	cacheMisses      uint64
	inspectionErrors uint64
	totalLatencyNs   uint64
	latencyCount     uint64

	// Threat counters by type.
	threatCounts   map[string]uint64
	threatCountsMu sync.Mutex

	// Lifecycle.
	wg        sync.WaitGroup
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewIDSHooks creates a new IDS hooks instance.
func NewIDSHooks(
	config *IDSHooksConfig,
	eventPublisher *EventPublisher,
	loggerHooks *LoggerHooks,
	firewallHooks *FirewallHooks,
) *IDSHooks {
	if config == nil {
		config = DefaultIDSHooksConfig()
	}

	return &IDSHooks{
		config:          config,
		threatCache:     make(map[string]*threatCacheEntry, config.ThreatCacheSize),
		blockedSources:  make(map[string]*blockedSourceEntry),
		inspectionQueue: make(chan *idsInspectionRequest, config.InspectionQueueSize),
		eventPublisher:  eventPublisher,
		loggerHooks:     loggerHooks,
		firewallHooks:   firewallHooks,
		threatCounts:    make(map[string]uint64),
		stopChan:        make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start begins IDS/IPS integration.
func (ih *IDSHooks) Start(ctx context.Context) error {
	ih.runningMu.Lock()
	defer ih.runningMu.Unlock()

	if ih.running {
		return nil
	}

	if !ih.config.Enabled {
		ih.running = true
		return nil
	}

	// Start inspection workers.
	for i := 0; i < ih.config.InspectionWorkers; i++ {
		ih.wg.Add(1)
		go ih.inspectionWorker(i)
	}

	// Start blocked source expiry goroutine.
	ih.wg.Add(1)
	go ih.blockedSourceExpiry()

	// Start cache cleaner.
	ih.wg.Add(1)
	go ih.cacheCleaner()

	// Start signature sync (stub - would sync with IDS service).
	ih.wg.Add(1)
	go ih.signatureSynchronizer()

	ih.running = true
	return nil
}

// Stop gracefully shuts down IDS/IPS integration.
func (ih *IDSHooks) Stop() error {
	ih.runningMu.Lock()
	if !ih.running {
		ih.runningMu.Unlock()
		return nil
	}
	ih.running = false
	ih.runningMu.Unlock()

	close(ih.stopChan)

	// Wait for workers with timeout.
	done := make(chan struct{})
	go func() {
		ih.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished cleanly.
	case <-time.After(20 * time.Second):
		// Timeout waiting for workers.
	}

	return nil
}

// inspectionWorker processes IDS inspection requests.
func (ih *IDSHooks) inspectionWorker(id int) {
	_ = id // Used for logging in production.
	defer ih.wg.Done()

	for {
		select {
		case <-ih.stopChan:
			return
		case req := <-ih.inspectionQueue:
			if req != nil {
				ih.processInspectionRequest(req)
			}
		}
	}
}

// blockedSourceExpiry removes expired blocked sources.
func (ih *IDSHooks) blockedSourceExpiry() {
	defer ih.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ih.stopChan:
			return
		case <-ticker.C:
			ih.cleanExpiredBlocks()
		}
	}
}

// cacheCleaner removes expired threat cache entries.
func (ih *IDSHooks) cacheCleaner() {
	defer ih.wg.Done()

	ticker := time.NewTicker(ih.config.ThreatCacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ih.stopChan:
			return
		case <-ticker.C:
			ih.cleanExpiredCache()
		}
	}
}

// signatureSynchronizer syncs threat signatures.
func (ih *IDSHooks) signatureSynchronizer() {
	defer ih.wg.Done()

	ticker := time.NewTicker(ih.config.SignatureSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ih.stopChan:
			return
		case <-ticker.C:
			ih.SynchronizeSignatures()
		}
	}
}

// cleanExpiredBlocks removes expired blocked sources.
func (ih *IDSHooks) cleanExpiredBlocks() {
	ih.blockedSourcesMu.Lock()
	defer ih.blockedSourcesMu.Unlock()

	now := time.Now()
	for ip, entry := range ih.blockedSources {
		if now.After(entry.ExpiresAt) {
			delete(ih.blockedSources, ip)
		}
	}
}

// cleanExpiredCache removes expired threat cache entries.
func (ih *IDSHooks) cleanExpiredCache() {
	ih.threatCacheMu.Lock()
	defer ih.threatCacheMu.Unlock()

	now := time.Now()
	for key, entry := range ih.threatCache {
		if now.After(entry.ExpiresAt) {
			delete(ih.threatCache, key)
		}
	}
}

// =============================================================================
// Threat Inspection
// =============================================================================

// InspectForThreats inspects a packet for threats.
func (ih *IDSHooks) InspectForThreats(
	packet []byte,
	fiveTuple *FiveTuple,
	direction PacketDirection,
	wanInterface string,
) (IDSVerdict, *ThreatInfo) {
	if !ih.config.Enabled {
		return IDSVerdictAllow, nil
	}

	startTime := time.Now()
	defer func() {
		atomic.AddUint64(&ih.totalLatencyNs, uint64(time.Since(startTime).Nanoseconds()))
		atomic.AddUint64(&ih.latencyCount, 1)
	}()

	// Check if source is blocked (O(1) hash lookup, ~100ns).
	if ih.isSourceBlocked(fiveTuple.SrcIP) {
		atomic.AddUint64(&ih.ipsBlocks, 1)
		return IDSVerdictBlock, &ThreatInfo{
			Name:     "Source IP Blocked",
			Severity: SeverityHighThreat,
		}
	}

	// Apply sampling rate.
	if !ih.shouldSample() {
		atomic.AddUint64(&ih.packetsSkipped, 1)
		return IDSVerdictAllow, nil
	}

	atomic.AddUint64(&ih.packetsInspected, 1)

	// Check threat cache.
	cacheKey := ih.computeCacheKey(packet)
	if verdict, threat, found := ih.checkThreatCache(cacheKey); found {
		atomic.AddUint64(&ih.cacheHits, 1)
		return verdict, threat
	}
	atomic.AddUint64(&ih.cacheMisses, 1)

	// Create inspection request.
	resultChan := make(chan *idsInspectionResult, 1)
	req := &idsInspectionRequest{
		Packet:       packet,
		FiveTuple:    fiveTuple,
		Direction:    direction,
		WanInterface: wanInterface,
		ResultChan:   resultChan,
	}

	// Try to enqueue.
	select {
	case ih.inspectionQueue <- req:
		// Enqueued successfully.
	default:
		// Queue full, allow (fail-open).
		atomic.AddUint64(&ih.inspectionErrors, 1)
		return IDSVerdictAllow, nil
	}

	// Wait for result with timeout.
	select {
	case result := <-resultChan:
		if result.Error != nil {
			atomic.AddUint64(&ih.inspectionErrors, 1)
			return IDSVerdictAllow, nil // Fail-open.
		}

		// Cache the result.
		ih.cacheThreatVerdict(cacheKey, result.Verdict, result.Threat)

		// Handle threat detection.
		if result.Verdict != IDSVerdictAllow && result.Threat != nil {
			ih.OnThreatDetected(packet, fiveTuple, result.Threat, result.Verdict)
		}

		return result.Verdict, result.Threat

	case <-time.After(50 * time.Millisecond):
		atomic.AddUint64(&ih.inspectionErrors, 1)
		return IDSVerdictAllow, nil // Fail-open on timeout.
	}
}

// processInspectionRequest processes a single inspection request.
func (ih *IDSHooks) processInspectionRequest(req *idsInspectionRequest) {
	// In production, this would call the IDS/IPS Engine via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	// defer cancel()
	//
	// resp, err := ih.idsClient.InspectPacket(ctx, &pb.InspectRequest{
	//     Packet:       req.Packet,
	//     SrcIp:        req.FiveTuple.SrcIP.String(),
	//     DstIp:        req.FiveTuple.DstIP.String(),
	//     SrcPort:      uint32(req.FiveTuple.SrcPort),
	//     DstPort:      uint32(req.FiveTuple.DstPort),
	//     Protocol:     uint32(req.FiveTuple.Protocol),
	//     Direction:    req.Direction.String(),
	// })
	// if err != nil {
	//     req.ResultChan <- &idsInspectionResult{Error: err}
	//     return
	// }
	//
	// verdict := IDSVerdictAllow
	// var threat *ThreatInfo
	// switch resp.Verdict {
	// case pb.IDSVerdict_ALERT:
	//     verdict = IDSVerdictAlert
	//     threat = &ThreatInfo{
	//         Name:        resp.ThreatName,
	//         CVEID:       resp.CveId,
	//         MitreAttack: resp.MitreAttack,
	//         Severity:    ThreatSeverity(resp.Severity),
	//     }
	// case pb.IDSVerdict_BLOCK:
	//     verdict = IDSVerdictBlock
	//     threat = &ThreatInfo{...}
	// }
	//
	// req.ResultChan <- &idsInspectionResult{
	//     Verdict: verdict,
	//     Threat:  threat,
	// }

	// Stub: Allow all traffic.
	req.ResultChan <- &idsInspectionResult{
		Verdict: IDSVerdictAllow,
		Threat:  nil,
	}
}

// shouldSample determines if this packet should be inspected.
func (ih *IDSHooks) shouldSample() bool {
	if ih.config.SamplingRate >= 1.0 {
		return true
	}
	if ih.config.SamplingRate <= 0 {
		return false
	}

	// Deterministic sampling using counter.
	count := atomic.AddUint64(&ih.sampleCounter, 1)
	threshold := uint64(ih.config.SamplingRate * 100)
	return (count % 100) < threshold
}

// computeCacheKey generates a cache key from packet payload.
func (ih *IDSHooks) computeCacheKey(packet []byte) string {
	// Hash first 64 bytes of packet for cache key.
	size := 64
	if len(packet) < size {
		size = len(packet)
	}
	hash := sha256.Sum256(packet[:size])
	return hex.EncodeToString(hash[:16]) // Use first 128 bits.
}

// checkThreatCache checks the threat cache.
func (ih *IDSHooks) checkThreatCache(key string) (IDSVerdict, *ThreatInfo, bool) {
	ih.threatCacheMu.RLock()
	defer ih.threatCacheMu.RUnlock()

	entry, exists := ih.threatCache[key]
	if !exists {
		return IDSVerdictAllow, nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return IDSVerdictAllow, nil, false
	}

	return entry.Verdict, entry.Threat, true
}

// cacheThreatVerdict caches a threat verdict.
func (ih *IDSHooks) cacheThreatVerdict(key string, verdict IDSVerdict, threat *ThreatInfo) {
	ih.threatCacheMu.Lock()
	defer ih.threatCacheMu.Unlock()

	// Check cache size limit.
	if len(ih.threatCache) >= ih.config.ThreatCacheSize {
		// Evict oldest entry (simplified - would use LRU in production).
		for k := range ih.threatCache {
			delete(ih.threatCache, k)
			break
		}
	}

	ih.threatCache[key] = &threatCacheEntry{
		Verdict:   verdict,
		Threat:    threat,
		ExpiresAt: time.Now().Add(ih.config.ThreatCacheTTL),
	}
}

// =============================================================================
// Source Blocking
// =============================================================================

// isSourceBlocked checks if a source IP is blocked.
func (ih *IDSHooks) isSourceBlocked(ip net.IP) bool {
	ih.blockedSourcesMu.RLock()
	defer ih.blockedSourcesMu.RUnlock()

	entry, exists := ih.blockedSources[ip.String()]
	if !exists {
		return false
	}

	// Check expiry.
	if time.Now().After(entry.ExpiresAt) {
		return false
	}

	return true
}

// blockSource adds a source IP to the blocklist.
func (ih *IDSHooks) blockSource(ip net.IP, reason string) {
	ih.blockedSourcesMu.Lock()
	defer ih.blockedSourcesMu.Unlock()

	now := time.Now()
	ih.blockedSources[ip.String()] = &blockedSourceEntry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: now,
		ExpiresAt: now.Add(ih.config.BlockDuration),
	}

	atomic.AddUint64(&ih.ipsBlocks, 1)
}

// UnblockSource removes a source IP from the blocklist.
func (ih *IDSHooks) UnblockSource(ip net.IP) error {
	ih.blockedSourcesMu.Lock()
	defer ih.blockedSourcesMu.Unlock()

	ipStr := ip.String()
	if _, exists := ih.blockedSources[ipStr]; !exists {
		return ErrSourceNotBlocked
	}

	delete(ih.blockedSources, ipStr)

	// In production, would also remove firewall rule:
	// ih.firewallHooks.RemoveDynamicBlock(ip)

	return nil
}

// GetBlockedSources returns all currently blocked sources.
func (ih *IDSHooks) GetBlockedSources() []*blockedSourceEntry {
	ih.blockedSourcesMu.RLock()
	defer ih.blockedSourcesMu.RUnlock()

	result := make([]*blockedSourceEntry, 0, len(ih.blockedSources))
	for _, entry := range ih.blockedSources {
		copy := *entry
		result = append(result, &copy)
	}
	return result
}

// =============================================================================
// Threat Detection Handling
// =============================================================================

// OnThreatDetected handles a detected threat.
func (ih *IDSHooks) OnThreatDetected(
	packet []byte,
	fiveTuple *FiveTuple,
	threat *ThreatInfo,
	verdict IDSVerdict,
) {
	atomic.AddUint64(&ih.threatsDetected, 1)

	// Track threat type.
	ih.threatCountsMu.Lock()
	ih.threatCounts[threat.Name]++
	ih.threatCountsMu.Unlock()

	// Publish event.
	if ih.eventPublisher != nil {
		eventType := EventTypeAnomalousTraffic
		if threat.Severity >= SeverityCriticalThreat {
			eventType = EventTypeDDoSDetected
		}

		_ = ih.eventPublisher.PublishWithMetadata(eventType, map[string]interface{}{
			"threat_name":  threat.Name,
			"cve_id":       threat.CVEID,
			"mitre_attack": threat.MitreAttack,
			"severity":     threat.Severity.String(),
			"verdict":      verdict.String(),
			"source_ip":    fiveTuple.SrcIP.String(),
			"dest_ip":      fiveTuple.DstIP.String(),
			"source_port":  fiveTuple.SrcPort,
			"dest_port":    fiveTuple.DstPort,
			"protocol":     fiveTuple.Protocol,
		}, EventMetadata{
			Severity: threat.Severity.String(),
			Category: "security",
		})
	}

	// Log to logger hooks.
	if ih.loggerHooks != nil {
		action := ThreatActionAlert
		if verdict == IDSVerdictBlock {
			action = ThreatActionBlock
		}

		ih.loggerHooks.LogThreatDetected(
			fiveTuple,
			threat.Name,
			threat.CVEID,
			threat.MitreAttack,
			threat.Severity.String(),
			action,
			packet,
		)
	}

	// IPS mode: block the source.
	if ih.config.IPSMode && verdict == IDSVerdictBlock {
		ih.blockSource(fiveTuple.SrcIP, fmt.Sprintf("IPS block: %s", threat.Name))

		// In production, would install firewall rule:
		// ih.firewallHooks.InstallDynamicBlock(fiveTuple.SrcIP, ih.config.BlockDuration)
	}
}

// =============================================================================
// Signature Synchronization
// =============================================================================

// SynchronizeSignatures updates threat signatures from IDS service.
func (ih *IDSHooks) SynchronizeSignatures() {
	// In production, this would call the IDS/IPS Engine via gRPC:
	//
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	//
	// resp, err := ih.idsClient.GetThreatSignatures(ctx, &pb.GetSignaturesRequest{})
	// if err != nil {
	//     log.Error("Failed to sync signatures", "error", err)
	//     return
	// }
	//
	// log.Info("Synchronized threat signatures",
	//     "count", len(resp.Signatures),
	//     "version", resp.Version,
	// )

	// Stub: No-op in test mode.
}

// =============================================================================
// Statistics
// =============================================================================

// IDSStats contains IDS/IPS statistics.
type IDSStats struct {
	PacketsInspected       uint64            `json:"packets_inspected"`
	PacketsSkipped         uint64            `json:"packets_skipped"`
	ThreatsDetected        uint64            `json:"threats_detected"`
	IPSBlocks              uint64            `json:"ips_blocks"`
	CurrentBlockedSources  int               `json:"current_blocked_sources"`
	CacheHitRate           float64           `json:"cache_hit_rate"`
	AvgInspectionLatencyMs float64           `json:"avg_inspection_latency_ms"`
	SamplingRate           float64           `json:"sampling_rate"`
	IPSModeEnabled         bool              `json:"ips_mode_enabled"`
	InspectionErrors       uint64            `json:"inspection_errors"`
	TopThreats             map[string]uint64 `json:"top_threats"`
	ServiceStatus          string            `json:"service_status"`
}

// GetIDSStats returns IDS/IPS statistics.
func (ih *IDSHooks) GetIDSStats() *IDSStats {
	cacheHits := atomic.LoadUint64(&ih.cacheHits)
	cacheMisses := atomic.LoadUint64(&ih.cacheMisses)
	totalLatencyNs := atomic.LoadUint64(&ih.totalLatencyNs)
	latencyCount := atomic.LoadUint64(&ih.latencyCount)

	var cacheHitRate float64
	if total := cacheHits + cacheMisses; total > 0 {
		cacheHitRate = float64(cacheHits) / float64(total) * 100
	}

	var avgLatencyMs float64
	if latencyCount > 0 {
		avgLatencyMs = float64(totalLatencyNs) / float64(latencyCount) / 1e6
	}

	ih.blockedSourcesMu.RLock()
	blockedCount := len(ih.blockedSources)
	ih.blockedSourcesMu.RUnlock()

	// Get top threats.
	ih.threatCountsMu.Lock()
	topThreats := make(map[string]uint64, len(ih.threatCounts))
	for k, v := range ih.threatCounts {
		topThreats[k] = v
	}
	ih.threatCountsMu.Unlock()

	status := "UP"
	if !ih.config.Enabled {
		status = "DISABLED"
	}

	return &IDSStats{
		PacketsInspected:       atomic.LoadUint64(&ih.packetsInspected),
		PacketsSkipped:         atomic.LoadUint64(&ih.packetsSkipped),
		ThreatsDetected:        atomic.LoadUint64(&ih.threatsDetected),
		IPSBlocks:              atomic.LoadUint64(&ih.ipsBlocks),
		CurrentBlockedSources:  blockedCount,
		CacheHitRate:           cacheHitRate,
		AvgInspectionLatencyMs: avgLatencyMs,
		SamplingRate:           ih.config.SamplingRate,
		IPSModeEnabled:         ih.config.IPSMode,
		InspectionErrors:       atomic.LoadUint64(&ih.inspectionErrors),
		TopThreats:             topThreats,
		ServiceStatus:          status,
	}
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies IDS/IPS integration is operational.
func (ih *IDSHooks) HealthCheck() error {
	if !ih.config.Enabled {
		return nil
	}

	ih.runningMu.Lock()
	running := ih.running
	ih.runningMu.Unlock()

	if !running {
		return errors.New("IDS hooks not running")
	}

	// Check queue not full.
	if float64(len(ih.inspectionQueue))/float64(cap(ih.inspectionQueue)) > 0.9 {
		return errors.New("IDS inspection queue near capacity")
	}

	return nil
}

// IsEnabled returns whether IDS integration is enabled.
func (ih *IDSHooks) IsEnabled() bool {
	return ih.config.Enabled
}

// IsIPSModeEnabled returns whether IPS mode is enabled.
func (ih *IDSHooks) IsIPSModeEnabled() bool {
	return ih.config.IPSMode
}

// GetConfig returns the current configuration.
func (ih *IDSHooks) GetConfig() *IDSHooksConfig {
	return ih.config
}
