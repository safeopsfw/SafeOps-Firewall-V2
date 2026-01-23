// Package inspector provides the main packet processing pipeline for the firewall engine.
package inspector

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/connection"
	"firewall_engine/internal/enforcement"
	"firewall_engine/pkg/models"
)

// ============================================================================
// Packet Inspector - Main 10-Step Inspection Pipeline
// ============================================================================

// Inspector implements the main packet inspection pipeline.
// It orchestrates cache lookup, connection tracking, fast-path evaluation,
// rule matching, verdict caching, enforcement, and statistics.
//
// 10-Step Inspection Pipeline:
//
//  1. Receive Packet Metadata from SafeOps gRPC stream
//  2. Check Verdict Cache (Fast Path) → HIT = skip to step 7
//  3. Update Connection State (connection tracking)
//  4. Check Fast-Path Rules (blocklist, DNS, established)
//  5. Match Against Firewall Rules (full rule engine)
//  6. Cache Verdict (for future packets)
//  7. Enforce Verdict (DROP, BLOCK, REDIRECT, REJECT)
//  8. Update Statistics (atomic counters)
//  9. Log Enforcement Action
//  10. Return Control (next packet)
//
// Performance Targets:
//   - Cache HIT (80%): ~10-15μs latency
//   - Cache MISS (20%): ~50-60μs latency
//   - Throughput: 100K+ packets/sec sustained
type Inspector struct {
	// Configuration
	config *InspectorConfig

	// Dependencies
	connectionTracker  *connection.Tracker
	enforcementHandler *enforcement.VerdictHandler
	fastPathEvaluator  FastPathEvaluator
	verdictCache       VerdictCache
	ruleMatcher        RuleMatcher

	// Statistics
	stats *InspectorStats

	// Logging
	logger *log.Logger

	// Packet ID generator
	packetIDCounter atomic.Uint64

	// Lifecycle
	started   atomic.Bool
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once
}

// ============================================================================
// Dependency Interfaces
// ============================================================================

// VerdictCache provides caching for verdict decisions.
type VerdictCache interface {
	// Get retrieves a cached verdict by key.
	Get(key string) (*models.VerdictResult, bool)

	// Set stores a verdict in the cache with TTL.
	Set(key string, verdict *models.VerdictResult, ttl time.Duration)

	// Delete removes a verdict from the cache.
	Delete(key string)

	// Clear removes all cached verdicts.
	Clear()

	// Size returns the number of cached entries.
	Size() int
}

// RuleMatcher provides rule matching functionality.
type RuleMatcher interface {
	// Match evaluates a packet against all rules and returns the verdict.
	Match(ctx context.Context, packet *models.PacketMetadata, connState models.ConnectionState) (*models.VerdictResult, *models.FirewallRule, error)

	// GetDefaultPolicy returns the default policy for a direction.
	GetDefaultPolicy(direction models.Direction) models.Verdict
}

// ============================================================================
// Constructor
// ============================================================================

// NewInspector creates a new packet inspector with the given configuration.
func NewInspector(config *InspectorConfig) (*Inspector, error) {
	if config == nil {
		config = DefaultInspectorConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid inspector config: %w", err)
	}

	return &Inspector{
		config: config,
		stats:  NewInspectorStats(config.WorkerCount),
		logger: log.New(log.Writer(), "[INSPECTOR] ", log.LstdFlags|log.Lmicroseconds),
	}, nil
}

// ============================================================================
// Dependency Injection
// ============================================================================

// SetConnectionTracker sets the connection tracker.
func (i *Inspector) SetConnectionTracker(tracker *connection.Tracker) {
	i.connectionTracker = tracker
}

// SetEnforcementHandler sets the enforcement handler.
func (i *Inspector) SetEnforcementHandler(handler *enforcement.VerdictHandler) {
	i.enforcementHandler = handler
}

// SetFastPathEvaluator sets the fast-path evaluator.
func (i *Inspector) SetFastPathEvaluator(evaluator FastPathEvaluator) {
	i.fastPathEvaluator = evaluator
}

// SetVerdictCache sets the verdict cache.
func (i *Inspector) SetVerdictCache(cache VerdictCache) {
	i.verdictCache = cache
}

// SetRuleMatcher sets the rule matcher.
func (i *Inspector) SetRuleMatcher(matcher RuleMatcher) {
	i.ruleMatcher = matcher
}

// SetLogger sets a custom logger.
func (i *Inspector) SetLogger(logger *log.Logger) {
	if logger != nil {
		i.logger = logger
	}
}

// ============================================================================
// Main Inspection Pipeline
// ============================================================================

// Inspect processes a packet through the full 10-step inspection pipeline.
// This is the core function that ties all firewall components together.
func (i *Inspector) Inspect(ctx context.Context, packet *models.PacketMetadata) (*InspectionResult, error) {
	startTime := time.Now()

	// === Step 0: Validate Input ===
	if i.closed.Load() {
		return nil, ErrInspectorClosed
	}

	if packet == nil {
		i.stats.ErrorCount.Add(1)
		return nil, ErrPacketNil
	}

	// Generate packet ID for tracking
	packetID := i.packetIDCounter.Add(1)
	i.stats.PacketsReceived.Add(1)

	// Create inspection context
	result := NewInspectionResult()
	result.PacketID = packetID
	result.Timestamp = startTime

	// === Step 1: Validation ===
	if err := i.validatePacket(packet); err != nil {
		i.stats.ErrorCount.Add(1)
		i.stats.PacketsDropped.Add(1)
		return nil, fmt.Errorf("packet validation failed: %w", err)
	}

	// === Step 2: Check Verdict Cache (Fast Path) ===
	cacheStart := time.Now()
	if i.config.EnableCache && i.verdictCache != nil {
		cacheKey := i.generateCacheKey(packet)
		if cached, found := i.verdictCache.Get(cacheKey); found {
			// Cache HIT - skip to enforcement
			result.CacheHit = true
			result.CacheLookupDuration = time.Since(cacheStart)
			result.Verdict = cached.Verdict
			result.RuleID = cached.RuleID
			result.RuleName = cached.RuleName
			result.Reason = "Cached verdict: " + cached.Reason
			i.stats.CacheHits.Add(1)

			// Skip to Step 7: Enforcement
			return i.enforceAndFinish(ctx, packet, result, startTime)
		}
		i.stats.CacheMisses.Add(1)
	}
	result.CacheLookupDuration = time.Since(cacheStart)

	// === Step 3: Update Connection State ===
	connState := models.StateNew
	isNewConnection := true
	if i.connectionTracker != nil {
		connEntry, err := i.connectionTracker.Track(packet)
		if err != nil {
			i.logger.Printf("Connection tracking failed for packet %d: %v", packetID, err)
			// Continue without connection state (fail-open)
		} else if connEntry != nil {
			connState = connEntry.State
			isNewConnection = (connState == models.StateNew)

			// Update statistics
			if isNewConnection {
				i.stats.ConnectionsNew.Add(1)
			} else if connState == models.StateEstablished {
				i.stats.ConnectionsEstablished.Add(1)
			}
		}
	}
	result.WithConnectionState(connState, isNewConnection)

	// === Step 4: Check Fast-Path Rules ===
	if i.config.EnableFastPath && i.fastPathEvaluator != nil {
		fpResult := i.fastPathEvaluator.Evaluate(ctx, packet, connState)
		if fpResult != nil && fpResult.Matched {
			result.FastPath = true
			result.FastPathType = fpResult.Type
			result.Verdict = fpResult.Verdict
			result.Reason = fpResult.Reason
			i.stats.RecordFastPath(fpResult.Type)

			// Cache fast-path verdict
			if i.config.EnableCache && i.verdictCache != nil {
				cacheKey := i.generateCacheKey(packet)
				verdictResult := &models.VerdictResult{
					Verdict:  fpResult.Verdict,
					RuleName: "FastPath:" + fpResult.Type.String(),
					Reason:   fpResult.Reason,
				}
				i.verdictCache.Set(cacheKey, verdictResult, i.config.CacheTTL)
				i.stats.CacheInserts.Add(1)
			}

			// Skip to Step 7: Enforcement
			return i.enforceAndFinish(ctx, packet, result, startTime)
		}
		i.stats.FastPathMisses.Add(1)
	}

	// === Step 5: Match Against Firewall Rules ===
	ruleMatchStart := time.Now()
	if i.ruleMatcher != nil {
		verdictResult, matchedRule, err := i.ruleMatcher.Match(ctx, packet, connState)
		if err != nil {
			i.logger.Printf("Rule matching failed for packet %d: %v", packetID, err)
			// Fall through to default policy
		} else if verdictResult != nil {
			result.Verdict = verdictResult.Verdict
			result.RuleID = verdictResult.RuleID
			result.RuleName = verdictResult.RuleName
			result.Reason = verdictResult.Reason
			result.MatchedRule = matchedRule
		}
	} else {
		// No rule matcher - use default policy
		defaultPolicy := models.VerdictAllow
		if i.config.FailOpen {
			defaultPolicy = models.VerdictAllow
		}
		result.Verdict = defaultPolicy
		result.Reason = "No rule matcher configured, using default policy"
	}
	result.RuleMatchDuration = time.Since(ruleMatchStart)

	// === Step 6: Cache Verdict ===
	if i.config.EnableCache && i.verdictCache != nil {
		cacheKey := i.generateCacheKey(packet)
		verdictResult := &models.VerdictResult{
			Verdict:  result.Verdict,
			RuleID:   result.RuleID,
			RuleName: result.RuleName,
			Reason:   result.Reason,
		}
		i.verdictCache.Set(cacheKey, verdictResult, i.config.CacheTTL)
		i.stats.CacheInserts.Add(1)
	}

	// === Steps 7-10: Enforce and Finish ===
	return i.enforceAndFinish(ctx, packet, result, startTime)
}

// enforceAndFinish handles Steps 7-10 of the pipeline.
func (i *Inspector) enforceAndFinish(
	ctx context.Context,
	packet *models.PacketMetadata,
	result *InspectionResult,
	startTime time.Time,
) (*InspectionResult, error) {
	// === Step 7: Enforce Verdict ===
	enforceStart := time.Now()
	if i.config.EnableEnforcement && i.enforcementHandler != nil {
		enforcementResult := i.enforceVerdict(ctx, packet, result)
		result.EnforcementSuccess = enforcementResult.success
		if enforcementResult.err != nil {
			result.EnforcementError = enforcementResult.err.Error()
			i.stats.EnforcementFailed.Add(1)

			// Fail-open: if enforcement fails, allow the packet
			if i.config.FailOpen {
				i.logger.Printf("Enforcement failed for packet %d, fail-open allowing: %v",
					result.PacketID, enforcementResult.err)
				result.Verdict = models.VerdictAllow
				result.Reason += " (enforcement failed, fail-open)"
			}
		} else {
			i.stats.EnforcementSuccess.Add(1)
		}
	} else {
		result.EnforcementSuccess = true // No enforcement = success
	}
	result.EnforcementDuration = time.Since(enforceStart)

	// === Step 8: Update Statistics ===
	i.stats.PacketsProcessed.Add(1)
	i.stats.RecordVerdict(result.Verdict)

	totalDuration := time.Since(startTime)
	result.TotalDuration = totalDuration
	i.stats.RecordTiming(totalDuration, result.CacheLookupDuration,
		result.RuleMatchDuration, result.EnforcementDuration)

	// === Step 9: Log Enforcement Action ===
	if i.config.EnableLogging {
		i.logInspection(packet, result)
	}

	// === Step 10: Return Control ===
	return result, nil
}

// ============================================================================
// Enforcement Helper
// ============================================================================

type enforcementResult struct {
	success bool
	err     error
}

// enforceVerdict calls the enforcement handler with retry logic.
func (i *Inspector) enforceVerdict(
	ctx context.Context,
	packet *models.PacketMetadata,
	result *InspectionResult,
) enforcementResult {
	// ALLOW verdict needs no enforcement
	if result.Verdict == models.VerdictAllow || result.Verdict == models.VerdictLog {
		return enforcementResult{success: true}
	}

	if i.enforcementHandler == nil {
		return enforcementResult{success: false, err: ErrEnforcementFailed}
	}

	// Create packet context for enforcement
	pktCtx := &enforcement.PacketContext{
		Packet: packet,
		Verdict: &models.VerdictResult{
			Verdict:  result.Verdict,
			RuleID:   result.RuleID,
			RuleName: result.RuleName,
			Reason:   result.Reason,
		},
	}

	// Retry logic with exponential backoff
	var lastErr error
	backoff := 10 * time.Millisecond

	for attempt := 0; attempt <= i.config.EnforcementRetries; attempt++ {
		select {
		case <-ctx.Done():
			return enforcementResult{success: false, err: ctx.Err()}
		default:
		}

		enfResult := i.enforcementHandler.EnforceVerdict(ctx, pktCtx)
		if enfResult.Success {
			return enforcementResult{success: true}
		}

		lastErr = enfResult.Error
		if attempt < i.config.EnforcementRetries {
			i.stats.EnforcementRetries.Add(1)
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
		}
	}

	return enforcementResult{success: false, err: lastErr}
}

// ============================================================================
// Helper Methods
// ============================================================================

// validatePacket checks if the packet metadata is valid.
func (i *Inspector) validatePacket(packet *models.PacketMetadata) error {
	if packet.SrcIP == "" {
		return fmt.Errorf("source IP is empty")
	}
	if packet.DstIP == "" {
		return fmt.Errorf("destination IP is empty")
	}
	return nil
}

// generateCacheKey creates a unique key for caching based on 5-tuple.
func (i *Inspector) generateCacheKey(packet *models.PacketMetadata) string {
	// Key format: protocol:srcIP:srcPort-dstIP:dstPort
	return fmt.Sprintf("%d:%s:%d-%s:%d",
		packet.Protocol,
		packet.SrcIP, packet.SrcPort,
		packet.DstIP, packet.DstPort,
	)
}

// logInspection logs the inspection result.
func (i *Inspector) logInspection(packet *models.PacketMetadata, result *InspectionResult) {
	// Only log if configured
	if i.config.LogDroppedOnly {
		if result.Verdict == models.VerdictAllow || result.Verdict == models.VerdictLog {
			return
		}
	}

	if !i.config.LogAllPackets && !i.config.LogDroppedOnly {
		return
	}

	// Format: [VERDICT] src:port -> dst:port (protocol) - reason [rule] duration
	logLine := fmt.Sprintf("[%s] %s:%d -> %s:%d (%s) - %s",
		result.Verdict,
		packet.SrcIP, packet.SrcPort,
		packet.DstIP, packet.DstPort,
		packet.Protocol,
		result.Reason,
	)

	if result.RuleName != "" {
		logLine += fmt.Sprintf(" [%s]", result.RuleName)
	}

	logLine += fmt.Sprintf(" (%s)", result.TotalDuration)

	if result.CacheHit {
		logLine += " [CACHE]"
	} else if result.FastPath {
		logLine += fmt.Sprintf(" [FAST:%s]", result.FastPathType)
	}

	i.logger.Println(logLine)
}

// ============================================================================
// Batch Processing
// ============================================================================

// InspectBatch processes multiple packets and returns all results.
// Useful for high-throughput scenarios.
func (i *Inspector) InspectBatch(ctx context.Context, packets []*models.PacketMetadata) ([]*InspectionResult, error) {
	if i.closed.Load() {
		return nil, ErrInspectorClosed
	}

	results := make([]*InspectionResult, len(packets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for idx, packet := range packets {
		wg.Add(1)
		go func(index int, pkt *models.PacketMetadata) {
			defer wg.Done()

			result, err := i.Inspect(ctx, pkt)

			mu.Lock()
			results[index] = result
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(idx, packet)
	}

	wg.Wait()
	return results, firstErr
}

// ============================================================================
// Statistics and Lifecycle
// ============================================================================

// Start initializes the inspector for processing.
func (i *Inspector) Start(ctx context.Context) error {
	if i.started.Load() {
		return fmt.Errorf("inspector already started")
	}

	i.started.Store(true)
	i.logger.Println("Inspector started")

	// Start statistics reporter if enabled
	if i.config.EnableStatistics && i.config.StatsReportInterval > 0 {
		go i.statsReporter(ctx)
	}

	return nil
}

// statsReporter periodically logs statistics.
func (i *Inspector) statsReporter(ctx context.Context) {
	ticker := time.NewTicker(i.config.StatsReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.closed.Load() {
				return
			}
			stats := i.stats.GetSnapshot()
			i.logger.Printf("Stats: received=%d processed=%d allow=%d block=%d drop=%d cache_hit=%d%%",
				stats["packets_received"],
				stats["packets_processed"],
				stats["verdict_allow"],
				stats["verdict_block"],
				stats["verdict_drop"],
				stats["cache_hit_rate_percent"],
			)
		}
	}
}

// Stop gracefully shuts down the inspector.
func (i *Inspector) Stop() error {
	i.closeOnce.Do(func() {
		i.closeMu.Lock()
		defer i.closeMu.Unlock()

		i.closed.Store(true)
		i.started.Store(false)

		// Log final statistics
		stats := i.stats.GetSnapshot()
		i.logger.Printf("Inspector stopped. Final stats: processed=%d, allow=%d, block=%d, drop=%d",
			stats["packets_processed"],
			stats["verdict_allow"],
			stats["verdict_block"],
			stats["verdict_drop"],
		)
	})

	return nil
}

// GetStats returns the current statistics.
func (i *Inspector) GetStats() *InspectorStats {
	return i.stats
}

// IsRunning returns true if the inspector is running.
func (i *Inspector) IsRunning() bool {
	return i.started.Load() && !i.closed.Load()
}

// GetConfig returns the current configuration.
func (i *Inspector) GetConfig() *InspectorConfig {
	return i.config
}

// ============================================================================
// Cache Management
// ============================================================================

// InvalidateCache clears all cached verdicts.
func (i *Inspector) InvalidateCache() {
	if i.verdictCache != nil {
		i.verdictCache.Clear()
		i.logger.Println("Verdict cache invalidated")
	}
}

// InvalidateCacheForIP clears cached verdicts for a specific IP.
func (i *Inspector) InvalidateCacheForIP(ip string) {
	// Note: This would require cache to support prefix matching
	// For now, log and skip
	i.logger.Printf("Cache invalidation for IP %s requested (not implemented)", ip)
}

// GetCacheSize returns the number of cached verdicts.
func (i *Inspector) GetCacheSize() int {
	if i.verdictCache != nil {
		return i.verdictCache.Size()
	}
	return 0
}

// ============================================================================
// Fast-Path Management
// ============================================================================

// AddToBlocklist adds an IP to the fast-path blocklist.
func (i *Inspector) AddToBlocklist(ip string, reason string, ttl time.Duration) error {
	if i.fastPathEvaluator == nil {
		return fmt.Errorf("fast-path evaluator not configured")
	}

	parsedIP := parseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	i.fastPathEvaluator.AddToBlocklist(parsedIP, reason, ttl)
	i.InvalidateCacheForIP(ip)
	return nil
}

// RemoveFromBlocklist removes an IP from the fast-path blocklist.
func (i *Inspector) RemoveFromBlocklist(ip string) error {
	if i.fastPathEvaluator == nil {
		return fmt.Errorf("fast-path evaluator not configured")
	}

	parsedIP := parseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	i.fastPathEvaluator.RemoveFromBlocklist(parsedIP)
	i.InvalidateCacheForIP(ip)
	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// parseIP parses an IP address string.
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}
