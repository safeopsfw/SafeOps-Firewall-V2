// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Drop Handler - Silent Packet Discard
// ============================================================================

// DropHandler implements silent packet dropping via kernel-level blocklist.
// When a packet is dropped, its destination IP is added to a blocklist
// maintained by the SafeOps NDIS driver. Future packets to that IP are
// discarded at wire-speed without consuming CPU time.
//
// Use Cases:
//   - Blocking malware C2 (command & control) servers
//   - Dropping DDoS traffic
//   - Blocking port scanners
//   - Blocking brute force attempts
//
// Network Perspective:
//   - Attacker sends packet to target IP
//   - Firewall silently drops packet (no response)
//   - Attacker experiences 30+ second timeout
//   - Attacker can't tell if host is offline or blocked
type DropHandler struct {
	// Configuration
	config *DropHandlerConfig

	// SafeOps verdict engine reference (interface to avoid import cycles)
	verdictEngine VerdictEngineInterface

	// Local blocklist cache for fast lookup
	blocklist  sync.Map // string(IP) → *BlockedEntry
	blockCount atomic.Int64

	// Statistics
	stats *DropStats

	// Shutdown
	closed    atomic.Bool
	closeOnce sync.Once
	closeChan chan struct{}
}

// DropHandlerConfig contains configuration for the drop handler.
type DropHandlerConfig struct {
	// TTLSeconds is how long blocked IPs stay in blocklist.
	TTLSeconds int `json:"ttl_seconds" toml:"ttl_seconds"`

	// MaxBlockedIPs is the maximum IPs in blocklist.
	MaxBlockedIPs int `json:"max_blocked_ips" toml:"max_blocked_ips"`

	// CleanupIntervalSeconds is how often to clean expired entries.
	CleanupIntervalSeconds int `json:"cleanup_interval_seconds" toml:"cleanup_interval_seconds"`

	// EnableLocalCache enables local blocklist caching.
	EnableLocalCache bool `json:"enable_local_cache" toml:"enable_local_cache"`

	// BlockBothDirections blocks both source and destination IPs.
	BlockBothDirections bool `json:"block_both_directions" toml:"block_both_directions"`
}

// DefaultDropHandlerConfig returns the default configuration.
func DefaultDropHandlerConfig() *DropHandlerConfig {
	return &DropHandlerConfig{
		TTLSeconds:             3600, // 1 hour
		MaxBlockedIPs:          100000,
		CleanupIntervalSeconds: 60, // 1 minute
		EnableLocalCache:       true,
		BlockBothDirections:    false,
	}
}

// BlockedEntry represents a blocked IP with metadata.
type BlockedEntry struct {
	IP        string        `json:"ip"`
	BlockedAt time.Time     `json:"blocked_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	Reason    string        `json:"reason,omitempty"`
	RuleID    string        `json:"rule_id,omitempty"`
	HitCount  atomic.Uint64 `json:"-"`
}

// IsExpired checks if the entry has expired.
func (e *BlockedEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// DropStats tracks drop handler statistics.
type DropStats struct {
	DropsInitiated atomic.Uint64
	DropsSucceeded atomic.Uint64
	DropsFailed    atomic.Uint64
	BlocklistSize  atomic.Int64
	BlocklistHits  atomic.Uint64
	EntriesExpired atomic.Uint64
	EntriesEvicted atomic.Uint64
}

// VerdictEngineInterface abstracts the SafeOps verdict engine.
// This allows for testing without direct dependency on ndisapi-go.
type VerdictEngineInterface interface {
	// BlockIP adds an IP to the kernel blocklist.
	BlockIP(ip net.IP, verdict int)

	// UnblockIP removes an IP from the kernel blocklist.
	UnblockIP(ip net.IP)

	// GetBlockedIPCount returns the number of blocked IPs.
	GetBlockedIPCount() int
}

// NewDropHandler creates a new drop handler.
func NewDropHandler(config *DropHandlerConfig, engine VerdictEngineInterface) (*DropHandler, error) {
	if config == nil {
		config = DefaultDropHandlerConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid drop handler config: %w", err)
	}

	handler := &DropHandler{
		config:        config,
		verdictEngine: engine,
		stats:         &DropStats{},
		closeChan:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go handler.cleanupLoop()

	return handler, nil
}

// Validate checks the configuration.
func (c *DropHandlerConfig) Validate() error {
	if c.TTLSeconds < 1 {
		return fmt.Errorf("ttl_seconds must be >= 1, got %d", c.TTLSeconds)
	}
	if c.MaxBlockedIPs < 100 {
		return fmt.Errorf("max_blocked_ips must be >= 100, got %d", c.MaxBlockedIPs)
	}
	if c.CleanupIntervalSeconds < 5 {
		return fmt.Errorf("cleanup_interval_seconds must be >= 5, got %d", c.CleanupIntervalSeconds)
	}
	return nil
}

// ============================================================================
// ActionHandler Interface Implementation
// ============================================================================

// Name returns the handler name.
func (h *DropHandler) Name() string {
	return "DropHandler"
}

// SupportedActions returns the actions this handler supports.
func (h *DropHandler) SupportedActions() []EnforcementAction {
	return []EnforcementAction{ActionDrop}
}

// CanHandle checks if this handler can process the given context.
func (h *DropHandler) CanHandle(ctx *PacketContext) bool {
	if ctx == nil || ctx.Packet == nil {
		return false
	}

	// Drop handler can handle any protocol
	// Just need a valid destination IP
	return ctx.Packet.DstIP != "" || ctx.DstIPParsed != nil
}

// Handle executes the drop action by adding the destination IP to blocklist.
func (h *DropHandler) Handle(ctx context.Context, pktCtx *PacketContext) *EnforcementResult {
	startTime := time.Now()

	// Check if handler is closed
	if h.closed.Load() {
		return NewFailureResult(ActionDrop, pktCtx.GetPacketID(),
			fmt.Errorf("drop handler is closed"), ErrCodeDisabled)
	}

	// Record attempt
	h.stats.DropsInitiated.Add(1)

	// Validate context
	if err := h.validateContext(pktCtx); err != nil {
		h.stats.DropsFailed.Add(1)
		return NewFailureResult(ActionDrop, pktCtx.GetPacketID(), err, ErrCodeInvalidPacket)
	}

	// Get destination IP
	dstIP := h.getDestinationIP(pktCtx)
	if dstIP == nil {
		h.stats.DropsFailed.Add(1)
		return NewFailureResult(ActionDrop, pktCtx.GetPacketID(),
			ErrInvalidIPAddress, ErrCodeInvalidPacket)
	}

	// Check if already blocked
	if h.isBlocked(dstIP.String()) {
		// Already blocked - still a success
		h.stats.BlocklistHits.Add(1)
		return NewSuccessResult(ActionDrop, pktCtx.GetPacketID(), time.Since(startTime)).
			WithHandler(h.Name()).
			WithMetadata("already_blocked", true)
	}

	// Check blocklist capacity
	if h.blockCount.Load() >= int64(h.config.MaxBlockedIPs) {
		// Evict oldest entries to make room
		if err := h.evictOldest(10); err != nil {
			h.stats.DropsFailed.Add(1)
			return NewFailureResult(ActionDrop, pktCtx.GetPacketID(),
				fmt.Errorf("blocklist full and eviction failed: %w", err),
				ErrCodeBlocklistFailed)
		}
	}

	// Add to kernel blocklist via SafeOps engine
	if err := h.blockIP(ctx, dstIP, pktCtx); err != nil {
		h.stats.DropsFailed.Add(1)
		return NewFailureResult(ActionDrop, pktCtx.GetPacketID(), err, ErrCodeBlocklistFailed).
			WithHandler(h.Name())
	}

	// Optionally block source IP too (for bidirectional blocking)
	if h.config.BlockBothDirections && pktCtx.Packet.SrcIP != "" {
		srcIP := h.getSourceIP(pktCtx)
		if srcIP != nil {
			_ = h.blockIP(ctx, srcIP, pktCtx) // Best effort, don't fail on this
		}
	}

	h.stats.DropsSucceeded.Add(1)

	return NewSuccessResult(ActionDrop, pktCtx.GetPacketID(), time.Since(startTime)).
		WithHandler(h.Name()).
		WithMetadata("blocked_ip", dstIP.String())
}

// ============================================================================
// Blocklist Management
// ============================================================================

// blockIP adds an IP to both kernel and local blocklist.
func (h *DropHandler) blockIP(ctx context.Context, ip net.IP, pktCtx *PacketContext) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ipStr := ip.String()

	// Create blocklist entry
	entry := &BlockedEntry{
		IP:        ipStr,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.config.TTLSeconds) * time.Second),
	}

	// Add reason and rule ID if available
	if pktCtx.Verdict != nil {
		entry.Reason = pktCtx.Verdict.Reason
		entry.RuleID = pktCtx.Verdict.RuleID
	}

	// Add to kernel blocklist via SafeOps engine
	if h.verdictEngine != nil {
		h.verdictEngine.BlockIP(ip, 2) // 2 = VerdictDrop in SafeOps engine
	}

	// Add to local cache
	if h.config.EnableLocalCache {
		h.blocklist.Store(ipStr, entry)
		h.blockCount.Add(1)
		h.stats.BlocklistSize.Store(h.blockCount.Load())
	}

	return nil
}

// unblockIP removes an IP from blocklist.
func (h *DropHandler) unblockIP(ip net.IP) error {
	ipStr := ip.String()

	// Remove from kernel blocklist
	if h.verdictEngine != nil {
		h.verdictEngine.UnblockIP(ip)
	}

	// Remove from local cache
	if _, loaded := h.blocklist.LoadAndDelete(ipStr); loaded {
		h.blockCount.Add(-1)
		h.stats.BlocklistSize.Store(h.blockCount.Load())
	}

	return nil
}

// isBlocked checks if an IP is in the blocklist.
func (h *DropHandler) isBlocked(ip string) bool {
	if !h.config.EnableLocalCache {
		return false
	}

	if entry, ok := h.blocklist.Load(ip); ok {
		blocked := entry.(*BlockedEntry)
		if blocked.IsExpired() {
			// Expired - remove it
			h.blocklist.Delete(ip)
			h.blockCount.Add(-1)
			h.stats.EntriesExpired.Add(1)
			return false
		}
		blocked.HitCount.Add(1)
		return true
	}
	return false
}

// evictOldest removes the oldest N entries from blocklist.
func (h *DropHandler) evictOldest(count int) error {
	type entryInfo struct {
		key   string
		entry *BlockedEntry
	}

	var entries []entryInfo

	// Collect all entries with their ages
	h.blocklist.Range(func(key, value interface{}) bool {
		entries = append(entries, entryInfo{
			key:   key.(string),
			entry: value.(*BlockedEntry),
		})
		return true
	})

	// Sort by BlockedAt (oldest first) - simple selection for now
	// In production, use a proper LRU cache
	evicted := 0
	for i := 0; i < len(entries) && evicted < count; i++ {
		oldest := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].entry.BlockedAt.Before(entries[oldest].entry.BlockedAt) {
				oldest = j
			}
		}
		entries[i], entries[oldest] = entries[oldest], entries[i]

		// Evict the oldest
		ip := net.ParseIP(entries[i].key)
		if ip != nil {
			_ = h.unblockIP(ip)
			h.stats.EntriesEvicted.Add(1)
			evicted++
		}
	}

	return nil
}

// cleanupLoop periodically removes expired entries.
func (h *DropHandler) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(h.config.CleanupIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.closeChan:
			return
		case <-ticker.C:
			h.cleanupExpired()
		}
	}
}

// cleanupExpired removes all expired entries.
func (h *DropHandler) cleanupExpired() {
	var expired []string

	h.blocklist.Range(func(key, value interface{}) bool {
		entry := value.(*BlockedEntry)
		if entry.IsExpired() {
			expired = append(expired, key.(string))
		}
		return true
	})

	for _, ipStr := range expired {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			_ = h.unblockIP(ip)
			h.stats.EntriesExpired.Add(1)
		}
	}
}

// ============================================================================
// Helper Methods
// ============================================================================

// validateContext checks if the context has required data.
func (h *DropHandler) validateContext(ctx *PacketContext) error {
	if ctx == nil {
		return ErrNilPacketContext
	}
	if ctx.Packet == nil {
		return ErrInvalidPacketData
	}
	return nil
}

// getDestinationIP extracts the destination IP from context.
func (h *DropHandler) getDestinationIP(ctx *PacketContext) net.IP {
	// Prefer pre-parsed IP
	if ctx.DstIPParsed != nil {
		return ctx.DstIPParsed
	}
	// Fall back to parsing from string
	if ctx.Packet.DstIP != "" {
		return net.ParseIP(ctx.Packet.DstIP)
	}
	return nil
}

// getSourceIP extracts the source IP from context.
func (h *DropHandler) getSourceIP(ctx *PacketContext) net.IP {
	if ctx.SrcIPParsed != nil {
		return ctx.SrcIPParsed
	}
	if ctx.Packet.SrcIP != "" {
		return net.ParseIP(ctx.Packet.SrcIP)
	}
	return nil
}

// ============================================================================
// Public API
// ============================================================================

// GetStats returns the drop handler statistics.
func (h *DropHandler) GetStats() map[string]uint64 {
	return map[string]uint64{
		"drops_initiated": h.stats.DropsInitiated.Load(),
		"drops_succeeded": h.stats.DropsSucceeded.Load(),
		"drops_failed":    h.stats.DropsFailed.Load(),
		"blocklist_size":  uint64(h.stats.BlocklistSize.Load()),
		"blocklist_hits":  h.stats.BlocklistHits.Load(),
		"entries_expired": h.stats.EntriesExpired.Load(),
		"entries_evicted": h.stats.EntriesEvicted.Load(),
	}
}

// GetBlockedIPs returns a list of currently blocked IPs.
func (h *DropHandler) GetBlockedIPs() []string {
	var ips []string
	h.blocklist.Range(func(key, value interface{}) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

// GetBlockedIPCount returns the number of blocked IPs.
func (h *DropHandler) GetBlockedIPCount() int {
	return int(h.blockCount.Load())
}

// IsIPBlocked checks if a specific IP is blocked.
func (h *DropHandler) IsIPBlocked(ip string) bool {
	return h.isBlocked(ip)
}

// ManualBlock manually blocks an IP address.
func (h *DropHandler) ManualBlock(ip string, reason string, ttlSeconds int) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if ttlSeconds <= 0 {
		ttlSeconds = h.config.TTLSeconds
	}

	entry := &BlockedEntry{
		IP:        ip,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		Reason:    reason,
	}

	// Add to kernel blocklist
	if h.verdictEngine != nil {
		h.verdictEngine.BlockIP(parsedIP, 2)
	}

	// Add to local cache
	if h.config.EnableLocalCache {
		h.blocklist.Store(ip, entry)
		h.blockCount.Add(1)
		h.stats.BlocklistSize.Store(h.blockCount.Load())
	}

	return nil
}

// ManualUnblock manually unblocks an IP address.
func (h *DropHandler) ManualUnblock(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return h.unblockIP(parsedIP)
}

// ClearBlocklist removes all blocked IPs.
func (h *DropHandler) ClearBlocklist() {
	h.blocklist.Range(func(key, value interface{}) bool {
		ip := net.ParseIP(key.(string))
		if ip != nil && h.verdictEngine != nil {
			h.verdictEngine.UnblockIP(ip)
		}
		h.blocklist.Delete(key)
		return true
	})
	h.blockCount.Store(0)
	h.stats.BlocklistSize.Store(0)
}

// Close shuts down the drop handler.
func (h *DropHandler) Close() error {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		close(h.closeChan)
		// Clear blocklist on shutdown (optional - could be configurable)
		// h.ClearBlocklist()
	})
	return nil
}

// SetVerdictEngine sets the verdict engine reference.
// Useful for delayed initialization.
func (h *DropHandler) SetVerdictEngine(engine VerdictEngineInterface) {
	h.verdictEngine = engine
}
