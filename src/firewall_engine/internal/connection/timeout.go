// Package connection provides stateful connection tracking for the firewall engine.
package connection

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Timeout Configuration
// ============================================================================

// TimeoutConfig defines timeout values for different connection types and states.
type TimeoutConfig struct {
	// Protocol-specific defaults
	TCPEstablished time.Duration `json:"tcp_established" toml:"tcp_established"`
	TCPSYN         time.Duration `json:"tcp_syn" toml:"tcp_syn"`
	TCPTimeWait    time.Duration `json:"tcp_time_wait" toml:"tcp_time_wait"`
	TCPClose       time.Duration `json:"tcp_close" toml:"tcp_close"`
	UDP            time.Duration `json:"udp" toml:"udp"`
	UDPStream      time.Duration `json:"udp_stream" toml:"udp_stream"`
	ICMP           time.Duration `json:"icmp" toml:"icmp"`
	Generic        time.Duration `json:"generic" toml:"generic"`
}

// DefaultTimeoutConfig returns standard firewall timeout values.
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
		TCPEstablished: 3600 * time.Second, // 1 hour
		TCPSYN:         30 * time.Second,   // 30 seconds
		TCPTimeWait:    120 * time.Second,  // 2 minutes (2×MSL)
		TCPClose:       10 * time.Second,   // 10 seconds
		UDP:            60 * time.Second,   // 1 minute
		UDPStream:      180 * time.Second,  // 3 minutes (bidirectional)
		ICMP:           30 * time.Second,   // 30 seconds
		Generic:        60 * time.Second,   // 1 minute
	}
}

// GetTimeout returns the appropriate timeout for a protocol and state.
func (tc *TimeoutConfig) GetTimeout(protocol models.Protocol, tcpState TCPState, hasBidirectional bool) time.Duration {
	switch protocol {
	case models.ProtocolTCP:
		return tc.getTCPTimeout(tcpState)
	case models.ProtocolUDP:
		if hasBidirectional {
			return tc.UDPStream
		}
		return tc.UDP
	case models.ProtocolICMP, models.ProtocolICMPv6:
		return tc.ICMP
	default:
		return tc.Generic
	}
}

// getTCPTimeout returns the timeout for a TCP state.
func (tc *TimeoutConfig) getTCPTimeout(state TCPState) time.Duration {
	switch state {
	case TCPStateNew, TCPStateSYNSent, TCPStateSYNReceived:
		return tc.TCPSYN
	case TCPStateEstablished:
		return tc.TCPEstablished
	case TCPStateTimeWait:
		return tc.TCPTimeWait
	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck:
		return tc.TCPClose
	case TCPStateClosed:
		return 0 // Immediate cleanup
	default:
		return tc.TCPSYN
	}
}

// ============================================================================
// Timeout Manager
// ============================================================================

// TimeoutManager handles connection timeout and cleanup.
type TimeoutManager struct {
	// Configuration
	config *TimeoutConfig

	// Connection table reference
	table *ConnectionTable

	// Cleanup goroutine control
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	interval time.Duration

	// Statistics
	stats timeoutStats

	// Logging
	logger *log.Logger

	// Lifecycle
	closed atomic.Bool
}

// timeoutStats tracks timeout manager statistics.
type timeoutStats struct {
	cleanupRuns      atomic.Uint64
	expiredRemoved   atomic.Uint64
	closedRemoved    atomic.Uint64
	markedRemoved    atomic.Uint64
	lastCleanupTime  atomic.Int64
	lastCleanupCount atomic.Int64
}

// NewTimeoutManager creates a new timeout manager.
func NewTimeoutManager(config *TimeoutConfig, table *ConnectionTable, interval time.Duration) *TimeoutManager {
	if config == nil {
		config = DefaultTimeoutConfig()
	}
	if interval < time.Second {
		interval = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	tm := &TimeoutManager{
		config:   config,
		table:    table,
		ctx:      ctx,
		cancel:   cancel,
		interval: interval,
		logger:   log.New(log.Writer(), "[TIMEOUT-MGR] ", log.LstdFlags|log.Lmicroseconds),
	}

	return tm
}

// Start begins the background cleanup goroutine.
func (tm *TimeoutManager) Start() {
	tm.wg.Add(1)
	go tm.cleanupLoop()
}

// cleanupLoop runs periodic cleanup.
func (tm *TimeoutManager) cleanupLoop() {
	defer tm.wg.Done()

	ticker := time.NewTicker(tm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.RunCleanup()
		}
	}
}

// RunCleanup performs a single cleanup pass.
func (tm *TimeoutManager) RunCleanup() int {
	if tm.closed.Load() {
		return 0
	}

	start := time.Now()
	tm.stats.cleanupRuns.Add(1)

	var (
		expiredCount int
		closedCount  int
		markedCount  int
	)

	// Iterate and collect expired connections
	var toRemove []ConnectionKey

	tm.table.Range(func(key ConnectionKey, entry *ConnectionEntry) bool {
		// Check if marked for deletion
		if entry.IsMarkedForDeletion() {
			toRemove = append(toRemove, key)
			markedCount++
			return true
		}

		// Check if expired
		if entry.IsExpired() {
			toRemove = append(toRemove, key)
			expiredCount++
			return true
		}

		// Check TCP CLOSED state
		if entry.TCPState == TCPStateClosed {
			toRemove = append(toRemove, key)
			closedCount++
			return true
		}

		// Update timeout based on current state
		tm.updateTimeout(entry)

		return true
	})

	// Remove collected entries
	for _, key := range toRemove {
		tm.table.Delete(key)
	}

	totalRemoved := expiredCount + closedCount + markedCount

	// Update statistics
	tm.stats.expiredRemoved.Add(uint64(expiredCount))
	tm.stats.closedRemoved.Add(uint64(closedCount))
	tm.stats.markedRemoved.Add(uint64(markedCount))
	tm.stats.lastCleanupTime.Store(time.Since(start).Nanoseconds())
	tm.stats.lastCleanupCount.Store(int64(totalRemoved))

	if totalRemoved > 0 {
		tm.logger.Printf("Cleanup: removed %d connections (expired=%d, closed=%d, marked=%d) in %v",
			totalRemoved, expiredCount, closedCount, markedCount, time.Since(start))
	}

	return totalRemoved
}

// updateTimeout updates a connection's expiration based on its current state.
func (tm *TimeoutManager) updateTimeout(entry *ConnectionEntry) {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Determine if bidirectional (for UDP)
	hasBidirectional := entry.PacketsReverse.Load() > 0

	// Get appropriate timeout
	protocol := models.Protocol(entry.Key.Protocol)
	timeout := tm.config.GetTimeout(protocol, entry.TCPState, hasBidirectional)

	// Only extend if current expiration is sooner
	newExpiry := entry.LastSeen.Add(timeout)
	if newExpiry.After(entry.ExpiresAt) {
		entry.ExpiresAt = newExpiry
	}
}

// ============================================================================
// Manual Operations
// ============================================================================

// ForceExpire immediately marks a connection as expired.
func (tm *TimeoutManager) ForceExpire(key ConnectionKey) bool {
	entry, exists := tm.table.Get(key)
	if !exists {
		return false
	}

	entry.mu.Lock()
	entry.ExpiresAt = time.Now().Add(-time.Second) // Set to past
	entry.mu.Unlock()

	return true
}

// ExtendTimeout extends a connection's timeout by the specified duration.
func (tm *TimeoutManager) ExtendTimeout(key ConnectionKey, duration time.Duration) bool {
	entry, exists := tm.table.Get(key)
	if !exists {
		return false
	}

	entry.mu.Lock()
	entry.ExpiresAt = entry.ExpiresAt.Add(duration)
	entry.mu.Unlock()

	return true
}

// SetTimeout sets a specific expiration time for a connection.
func (tm *TimeoutManager) SetTimeout(key ConnectionKey, expiresAt time.Time) bool {
	entry, exists := tm.table.Get(key)
	if !exists {
		return false
	}

	entry.mu.Lock()
	entry.ExpiresAt = expiresAt
	entry.mu.Unlock()

	return true
}

// ============================================================================
// Statistics
// ============================================================================

// TimeoutStats contains timeout manager statistics.
type TimeoutStats struct {
	CleanupRuns      uint64        `json:"cleanup_runs"`
	ExpiredRemoved   uint64        `json:"expired_removed"`
	ClosedRemoved    uint64        `json:"closed_removed"`
	MarkedRemoved    uint64        `json:"marked_removed"`
	TotalRemoved     uint64        `json:"total_removed"`
	LastCleanupTime  time.Duration `json:"last_cleanup_time"`
	LastCleanupCount int64         `json:"last_cleanup_count"`
}

// GetStats returns timeout manager statistics.
func (tm *TimeoutManager) GetStats() TimeoutStats {
	expired := tm.stats.expiredRemoved.Load()
	closed := tm.stats.closedRemoved.Load()
	marked := tm.stats.markedRemoved.Load()

	return TimeoutStats{
		CleanupRuns:      tm.stats.cleanupRuns.Load(),
		ExpiredRemoved:   expired,
		ClosedRemoved:    closed,
		MarkedRemoved:    marked,
		TotalRemoved:     expired + closed + marked,
		LastCleanupTime:  time.Duration(tm.stats.lastCleanupTime.Load()),
		LastCleanupCount: tm.stats.lastCleanupCount.Load(),
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Stop stops the timeout manager.
func (tm *TimeoutManager) Stop() {
	if tm.closed.Load() {
		return
	}
	tm.closed.Store(true)
	tm.cancel()
	tm.wg.Wait()
}

// Close is an alias for Stop.
func (tm *TimeoutManager) Close() error {
	tm.Stop()
	return nil
}

// SetLogger sets a custom logger.
func (tm *TimeoutManager) SetLogger(logger *log.Logger) {
	if logger != nil {
		tm.logger = logger
	}
}

// GetConfig returns the current timeout configuration.
func (tm *TimeoutManager) GetConfig() *TimeoutConfig {
	return tm.config
}

// SetConfig updates the timeout configuration.
func (tm *TimeoutManager) SetConfig(config *TimeoutConfig) {
	if config != nil {
		tm.config = config
	}
}

// GetInterval returns the cleanup interval.
func (tm *TimeoutManager) GetInterval() time.Duration {
	return tm.interval
}
