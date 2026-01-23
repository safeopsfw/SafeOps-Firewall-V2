// Package connection provides stateful connection tracking for the firewall engine.
package connection

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Connection Tracker - Main Implementation
// ============================================================================

// Tracker is the main connection tracking implementation.
// It maintains a table of all active connections and provides
// thread-safe operations for tracking, lookup, and cleanup.
type Tracker struct {
	// Configuration
	config *TrackerConfig

	// Connection table
	table *ConnectionTable

	// Statistics (atomic for thread-safety)
	stats trackerStats

	// State machine for TCP transitions
	stateMachine *TCPStateMachine

	// Cleanup management
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWg     sync.WaitGroup

	// Logging
	logger *log.Logger

	// Lifecycle
	closed    atomic.Bool
	closeOnce sync.Once
}

// trackerStats holds atomic statistics counters.
type trackerStats struct {
	totalTracked        atomic.Uint64
	totalExpired        atomic.Uint64
	totalDeleted        atomic.Uint64
	tcpConnections      atomic.Int64
	udpConnections      atomic.Int64
	icmpConnections     atomic.Int64
	stateNew            atomic.Int64
	stateEstablished    atomic.Int64
	stateClosing        atomic.Int64
	lastCleanupDuration atomic.Int64
}

// NewTracker creates a new connection tracker with the given configuration.
func NewTracker(config *TrackerConfig) (*Tracker, error) {
	if config == nil {
		config = DefaultTrackerConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tracker config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Tracker{
		config:        config,
		table:         NewConnectionTable(config.MaxConnections),
		stateMachine:  NewTCPStateMachine(),
		cleanupCtx:    ctx,
		cleanupCancel: cancel,
		logger:        log.New(log.Writer(), "[CONN-TRACKER] ", log.LstdFlags|log.Lmicroseconds),
	}

	// Start background cleanup
	t.cleanupWg.Add(1)
	go t.cleanupLoop()

	return t, nil
}

// ============================================================================
// Core Tracking Operations
// ============================================================================

// Track processes a packet and returns the associated connection entry.
// If this is the first packet of a connection, a new entry is created.
func (t *Tracker) Track(pkt *models.PacketMetadata) (*ConnectionEntry, error) {
	if t.closed.Load() {
		return nil, fmt.Errorf("tracker is closed")
	}

	if pkt == nil {
		return nil, fmt.Errorf("packet metadata is nil")
	}

	key := NewConnectionKey(pkt)

	// Try to find existing connection
	if entry, exists := t.table.Get(key); exists {
		return t.updateConnection(entry, pkt)
	}

	// Create new connection
	return t.createConnection(key, pkt)
}

// createConnection creates a new connection entry.
func (t *Tracker) createConnection(key ConnectionKey, pkt *models.PacketMetadata) (*ConnectionEntry, error) {
	// Get appropriate timeout
	timeout := t.config.GetTimeout(pkt.Protocol, TCPStateNew)

	// Create entry
	entry := NewConnectionEntry(pkt, timeout)

	// Try to add to table (may fail if at capacity)
	if !t.table.Add(key, entry) {
		// Table is full - try cleanup first
		t.Cleanup()

		// Retry
		if !t.table.Add(key, entry) {
			return nil, fmt.Errorf("connection table is full (%d connections)", t.table.Count())
		}
	}

	// Update statistics
	t.stats.totalTracked.Add(1)
	t.updateProtocolStats(pkt.Protocol, 1)
	t.stats.stateNew.Add(1)

	return entry, nil
}

// updateConnection updates an existing connection with new packet info.
func (t *Tracker) updateConnection(entry *ConnectionEntry, pkt *models.PacketMetadata) (*ConnectionEntry, error) {
	// Determine direction
	isForward := entry.IsForwardDirection(pkt)

	// Get appropriate timeout based on current state
	timeout := t.config.GetTimeout(pkt.Protocol, entry.TCPState)

	// Add packet to counters
	entry.AddPacket(pkt, isForward, timeout)

	// Update TCP state machine if TCP
	if pkt.Protocol == models.ProtocolTCP {
		t.updateTCPState(entry, pkt, isForward)
	} else if pkt.Protocol == models.ProtocolUDP {
		t.updateUDPState(entry, pkt, isForward)
	}

	return entry, nil
}

// updateTCPState updates the TCP state machine for a connection.
func (t *Tracker) updateTCPState(entry *ConnectionEntry, pkt *models.PacketMetadata, isForward bool) {
	oldState := entry.TCPState

	// Get TCP flags from packet
	flags := TCPFlags{
		SYN: pkt.IsSYN,
		ACK: pkt.IsACK,
		FIN: pkt.IsFIN,
		RST: pkt.IsRST,
	}

	// Calculate new state
	newState := t.stateMachine.Transition(oldState, flags, isForward)

	if newState != oldState {
		entry.UpdateTCPState(newState)

		// Update state statistics
		t.updateStateStats(oldState, newState)

		// Map TCP state to connection state
		connState := t.tcpStateToConnectionState(newState)
		if connState != entry.State {
			entry.UpdateState(connState)
		}
	}
}

// updateUDPState updates UDP pseudo-state (bidirectional = established).
func (t *Tracker) updateUDPState(entry *ConnectionEntry, pkt *models.PacketMetadata, isForward bool) {
	if entry.State == models.StateNew {
		// Check if we have bidirectional traffic
		if isForward && entry.PacketsReverse.Load() > 0 {
			entry.UpdateState(models.StateEstablished)
			t.stats.stateNew.Add(-1)
			t.stats.stateEstablished.Add(1)
		} else if !isForward && entry.PacketsForward.Load() > 0 {
			entry.UpdateState(models.StateEstablished)
			t.stats.stateNew.Add(-1)
			t.stats.stateEstablished.Add(1)
		}
	}
}

// tcpStateToConnectionState maps TCP state to generic connection state.
func (t *Tracker) tcpStateToConnectionState(state TCPState) models.ConnectionState {
	switch state {
	case TCPStateNew:
		return models.StateNew
	case TCPStateSYNSent, TCPStateSYNReceived:
		return models.StateSYNSent
	case TCPStateEstablished:
		return models.StateEstablished
	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck:
		return models.StateClosing
	case TCPStateTimeWait:
		return models.StateTimeWait
	case TCPStateClosed:
		return models.StateClosed
	case TCPStateInvalid:
		return models.StateInvalid
	default:
		return models.StateNew
	}
}

// updateProtocolStats updates per-protocol connection counts.
func (t *Tracker) updateProtocolStats(protocol models.Protocol, delta int64) {
	switch protocol {
	case models.ProtocolTCP:
		t.stats.tcpConnections.Add(delta)
	case models.ProtocolUDP:
		t.stats.udpConnections.Add(delta)
	case models.ProtocolICMP, models.ProtocolICMPv6:
		t.stats.icmpConnections.Add(delta)
	}
}

// updateStateStats updates state transition statistics.
func (t *Tracker) updateStateStats(oldState, newState TCPState) {
	// Decrement old state counter
	switch oldState {
	case TCPStateNew:
		t.stats.stateNew.Add(-1)
	case TCPStateEstablished:
		t.stats.stateEstablished.Add(-1)
	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck, TCPStateTimeWait:
		t.stats.stateClosing.Add(-1)
	}

	// Increment new state counter
	switch newState {
	case TCPStateNew:
		t.stats.stateNew.Add(1)
	case TCPStateEstablished:
		t.stats.stateEstablished.Add(1)
	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck, TCPStateTimeWait:
		t.stats.stateClosing.Add(1)
	}
}

// ============================================================================
// Lookup Operations
// ============================================================================

// Lookup finds an existing connection by key.
func (t *Tracker) Lookup(key ConnectionKey) (*ConnectionEntry, bool) {
	if t.closed.Load() {
		return nil, false
	}
	return t.table.Get(key)
}

// LookupByPacket finds a connection for the given packet.
func (t *Tracker) LookupByPacket(pkt *models.PacketMetadata) (*ConnectionEntry, bool) {
	if t.closed.Load() || pkt == nil {
		return nil, false
	}
	key := NewConnectionKey(pkt)
	return t.table.Get(key)
}

// ============================================================================
// Deletion Operations
// ============================================================================

// Delete removes a connection from tracking.
func (t *Tracker) Delete(key ConnectionKey) bool {
	if t.closed.Load() {
		return false
	}

	entry, exists := t.table.Get(key)
	if !exists {
		return false
	}

	// Update statistics before deletion
	t.updateProtocolStats(models.Protocol(entry.Key.Protocol), -1)

	// Remove from table
	t.table.Delete(key)
	t.stats.totalDeleted.Add(1)

	return true
}

// ============================================================================
// Cleanup Operations
// ============================================================================

// Cleanup removes all expired connections.
func (t *Tracker) Cleanup() int {
	if t.closed.Load() {
		return 0
	}

	start := time.Now()
	removed := 0

	// Iterate through all connections
	t.table.Range(func(key ConnectionKey, entry *ConnectionEntry) bool {
		if entry.IsExpired() || entry.IsMarkedForDeletion() {
			// Update protocol stats
			t.updateProtocolStats(models.Protocol(key.Protocol), -1)

			// Delete
			t.table.Delete(key)
			t.stats.totalExpired.Add(1)
			removed++
		}
		return true // continue iteration
	})

	t.stats.lastCleanupDuration.Store(time.Since(start).Nanoseconds())

	return removed
}

// cleanupLoop runs periodic cleanup in the background.
func (t *Tracker) cleanupLoop() {
	defer t.cleanupWg.Done()

	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.cleanupCtx.Done():
			return
		case <-ticker.C:
			removed := t.Cleanup()
			if removed > 0 && t.config.EnableStatistics {
				t.logger.Printf("Cleanup: removed %d expired connections", removed)
			}
		}
	}
}

// ============================================================================
// Statistics
// ============================================================================

// Count returns the number of tracked connections.
func (t *Tracker) Count() int {
	return t.table.Count()
}

// GetStats returns tracker statistics.
func (t *Tracker) GetStats() TrackerStats {
	return TrackerStats{
		ActiveConnections:   int64(t.table.Count()),
		TotalTracked:        t.stats.totalTracked.Load(),
		TotalExpired:        t.stats.totalExpired.Load(),
		TotalDeleted:        t.stats.totalDeleted.Load(),
		TCPConnections:      t.stats.tcpConnections.Load(),
		UDPConnections:      t.stats.udpConnections.Load(),
		ICMPConnections:     t.stats.icmpConnections.Load(),
		StateNew:            t.stats.stateNew.Load(),
		StateEstablished:    t.stats.stateEstablished.Load(),
		StateClosing:        t.stats.stateClosing.Load(),
		LastCleanupDuration: t.stats.lastCleanupDuration.Load(),
	}
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Close shuts down the connection tracker.
func (t *Tracker) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)

		// Stop cleanup goroutine
		t.cleanupCancel()
		t.cleanupWg.Wait()

		// Log final stats
		stats := t.GetStats()
		t.logger.Printf("Shutdown: tracked=%d, expired=%d, active=%d",
			stats.TotalTracked, stats.TotalExpired, stats.ActiveConnections)
	})

	return nil
}

// IsClosed returns true if the tracker has been closed.
func (t *Tracker) IsClosed() bool {
	return t.closed.Load()
}

// ============================================================================
// Utility Methods
// ============================================================================

// SetLogger sets a custom logger.
func (t *Tracker) SetLogger(logger *log.Logger) {
	if logger != nil {
		t.logger = logger
	}
}

// GetConfig returns the current configuration.
func (t *Tracker) GetConfig() *TrackerConfig {
	return t.config
}

// ForEach iterates over all connections with a callback.
func (t *Tracker) ForEach(fn func(key ConnectionKey, entry *ConnectionEntry) bool) {
	t.table.Range(fn)
}

// GetTopConnections returns the top N connections by total bytes.
func (t *Tracker) GetTopConnections(n int) []*ConnectionEntry {
	var connections []*ConnectionEntry

	t.table.Range(func(key ConnectionKey, entry *ConnectionEntry) bool {
		connections = append(connections, entry)
		return true
	})

	// Sort by total bytes (simple bubble sort for small N)
	for i := 0; i < len(connections) && i < n; i++ {
		maxIdx := i
		maxBytes := connections[i].BytesForward.Load() + connections[i].BytesReverse.Load()

		for j := i + 1; j < len(connections); j++ {
			jBytes := connections[j].BytesForward.Load() + connections[j].BytesReverse.Load()
			if jBytes > maxBytes {
				maxIdx = j
				maxBytes = jBytes
			}
		}

		if maxIdx != i {
			connections[i], connections[maxIdx] = connections[maxIdx], connections[i]
		}
	}

	if len(connections) > n {
		connections = connections[:n]
	}

	return connections
}
