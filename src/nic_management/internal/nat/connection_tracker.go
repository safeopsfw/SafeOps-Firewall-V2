// Package nat provides NAT/NAPT translation functionality for the NIC Management service.
package nat

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
// Connection Tracker Errors
// =============================================================================

var (
	// ErrConnectionNotFound indicates connection not found.
	ErrConnectionNotFound = errors.New("connection not found")
	// ErrConnectionExists indicates connection already exists.
	ErrConnectionExists = errors.New("connection already exists")
	// ErrConnectionClosed indicates connection is closed.
	ErrConnectionClosed = errors.New("connection is closed")
	// ErrTrackerNotRunning indicates tracker is not running.
	ErrTrackerNotRunning = errors.New("connection tracker not running")
	// ErrMaxConnectionsReached indicates max connections limit reached.
	ErrMaxConnectionsReached = errors.New("max connections limit reached")
)

// =============================================================================
// TCP State Machine
// =============================================================================

// TCPState represents TCP connection states per RFC 793.
type TCPState int

const (
	// TCPStateNone indicates no connection.
	TCPStateNone TCPState = iota
	// TCPStateSynSent indicates SYN sent.
	TCPStateSynSent
	// TCPStateSynReceived indicates SYN received, SYN-ACK sent.
	TCPStateSynReceived
	// TCPStateEstablished indicates connection established.
	TCPStateEstablished
	// TCPStateFinWait1 indicates FIN sent.
	TCPStateFinWait1
	// TCPStateFinWait2 indicates ACK for FIN received.
	TCPStateFinWait2
	// TCPStateCloseWait indicates FIN received, waiting to close.
	TCPStateCloseWait
	// TCPStateClosing indicates simultaneous close.
	TCPStateClosing
	// TCPStateLastAck indicates waiting for final ACK.
	TCPStateLastAck
	// TCPStateTimeWait indicates waiting for packets to clear.
	TCPStateTimeWait
	// TCPStateClosed indicates connection closed.
	TCPStateClosed
)

// String returns the string representation.
func (s TCPState) String() string {
	switch s {
	case TCPStateNone:
		return "NONE"
	case TCPStateSynSent:
		return "SYN_SENT"
	case TCPStateSynReceived:
		return "SYN_RECEIVED"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFinWait1:
		return "FIN_WAIT1"
	case TCPStateFinWait2:
		return "FIN_WAIT2"
	case TCPStateCloseWait:
		return "CLOSE_WAIT"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastAck:
		return "LAST_ACK"
	case TCPStateTimeWait:
		return "TIME_WAIT"
	case TCPStateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// IsActive returns whether the connection is active.
func (s TCPState) IsActive() bool {
	return s == TCPStateEstablished || s == TCPStateSynReceived ||
		s == TCPStateSynSent || s == TCPStateFinWait1 ||
		s == TCPStateFinWait2 || s == TCPStateCloseWait
}

// =============================================================================
// TCP Flags
// =============================================================================

// TCPFlags represents TCP header flags.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
)

// String returns string representation of flags.
func (f TCPFlags) String() string {
	var flags string
	if f&TCPFlagSYN != 0 {
		flags += "S"
	}
	if f&TCPFlagACK != 0 {
		flags += "A"
	}
	if f&TCPFlagFIN != 0 {
		flags += "F"
	}
	if f&TCPFlagRST != 0 {
		flags += "R"
	}
	if f&TCPFlagPSH != 0 {
		flags += "P"
	}
	if f&TCPFlagURG != 0 {
		flags += "U"
	}
	if flags == "" {
		flags = "."
	}
	return flags
}

// =============================================================================
// Connection Key
// =============================================================================

// ConnectionKey uniquely identifies a connection (5-tuple).
type ConnectionKey struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// String returns the string representation.
func (k *ConnectionKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d",
		k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol)
}

// Key returns a map key string.
func (k *ConnectionKey) Key() string {
	return fmt.Sprintf("%s:%d:%s:%d:%d",
		k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol)
}

// Reverse returns the reverse direction key.
func (k *ConnectionKey) Reverse() *ConnectionKey {
	return &ConnectionKey{
		SrcIP:    k.DstIP,
		DstIP:    k.SrcIP,
		SrcPort:  k.DstPort,
		DstPort:  k.SrcPort,
		Protocol: k.Protocol,
	}
}

// =============================================================================
// Connection Entry
// =============================================================================

// Connection represents a tracked connection.
type Connection struct {
	// Identity.
	Key       *ConnectionKey
	ID        string
	MappingID string

	// State.
	State    TCPState
	Protocol uint8

	// Timestamps.
	CreatedAt     time.Time
	LastSeen      time.Time
	ExpiresAt     time.Time
	EstablishedAt time.Time

	// Counters.
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64

	// TCP-specific.
	ClientSeq uint32
	ServerSeq uint32
	ClientWin uint16
	ServerWin uint16

	// NAT mapping.
	NATSrcIP   net.IP
	NATSrcPort uint16
	NATDstIP   net.IP
	NATDstPort uint16

	// Metadata.
	WanInterface string
	LanInterface string
	Mark         uint32

	// Internal.
	mu sync.Mutex
}

// UpdateActivity updates the last seen time and extends timeout.
func (c *Connection) UpdateActivity(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.LastSeen = time.Now()
	c.ExpiresAt = c.LastSeen.Add(timeout)
}

// IsExpired checks if the connection has expired.
func (c *Connection) IsExpired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return time.Now().After(c.ExpiresAt)
}

// Duration returns how long the connection has been active.
func (c *Connection) Duration() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	return time.Since(c.CreatedAt)
}

// =============================================================================
// Connection Tracker Config
// =============================================================================

// ConnectionTrackerConfig contains configuration.
type ConnectionTrackerConfig struct {
	// Timeouts per state.
	SynSentTimeout     time.Duration `json:"syn_sent_timeout"`
	SynRecvTimeout     time.Duration `json:"syn_recv_timeout"`
	EstablishedTimeout time.Duration `json:"established_timeout"`
	FinWaitTimeout     time.Duration `json:"fin_wait_timeout"`
	CloseWaitTimeout   time.Duration `json:"close_wait_timeout"`
	TimeWaitTimeout    time.Duration `json:"time_wait_timeout"`
	UDPTimeout         time.Duration `json:"udp_timeout"`
	ICMPTimeout        time.Duration `json:"icmp_timeout"`

	// Limits.
	MaxConnections int `json:"max_connections"`
	MaxPerIP       int `json:"max_per_ip"`

	// Cleanup.
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// Features.
	EnableLogging       bool `json:"enable_logging"`
	EnableStateTracking bool `json:"enable_state_tracking"`
	EnableNATTracking   bool `json:"enable_nat_tracking"`
}

// DefaultConnectionTrackerConfig returns the default configuration.
func DefaultConnectionTrackerConfig() *ConnectionTrackerConfig {
	return &ConnectionTrackerConfig{
		SynSentTimeout:      30 * time.Second,
		SynRecvTimeout:      60 * time.Second,
		EstablishedTimeout:  5 * time.Hour,
		FinWaitTimeout:      2 * time.Minute,
		CloseWaitTimeout:    10 * time.Second,
		TimeWaitTimeout:     2 * time.Minute,
		UDPTimeout:          180 * time.Second,
		ICMPTimeout:         30 * time.Second,
		MaxConnections:      262144, // 256K connections.
		MaxPerIP:            1024,
		CleanupInterval:     10 * time.Second,
		EnableLogging:       true,
		EnableStateTracking: true,
		EnableNATTracking:   true,
	}
}

// GetTimeout returns timeout for a given state.
func (c *ConnectionTrackerConfig) GetTimeout(state TCPState, protocol uint8) time.Duration {
	// UDP.
	if protocol == 17 {
		return c.UDPTimeout
	}

	// ICMP.
	if protocol == 1 {
		return c.ICMPTimeout
	}

	// TCP by state.
	switch state {
	case TCPStateSynSent:
		return c.SynSentTimeout
	case TCPStateSynReceived:
		return c.SynRecvTimeout
	case TCPStateEstablished:
		return c.EstablishedTimeout
	case TCPStateFinWait1, TCPStateFinWait2:
		return c.FinWaitTimeout
	case TCPStateCloseWait, TCPStateLastAck, TCPStateClosing:
		return c.CloseWaitTimeout
	case TCPStateTimeWait:
		return c.TimeWaitTimeout
	default:
		return 30 * time.Second
	}
}

// =============================================================================
// Connection Tracker Statistics
// =============================================================================

// ConnectionTrackerStats contains statistics.
type ConnectionTrackerStats struct {
	// Connection counts.
	TotalConnections  uint64
	ActiveConnections uint64
	TCPConnections    uint64
	UDPConnections    uint64
	ICMPConnections   uint64

	// State counts.
	SynSentCount     uint64
	SynRecvCount     uint64
	EstablishedCount uint64
	FinWaitCount     uint64
	CloseWaitCount   uint64
	TimeWaitCount    uint64

	// Lifecycle events.
	ConnectionsCreated  uint64
	ConnectionsClosed   uint64
	ConnectionsExpired  uint64
	ConnectionsRejected uint64

	// Packet counters.
	TotalPackets uint64
	TotalBytes   uint64

	// Errors.
	InvalidPackets     uint64
	StateTransitionErr uint64
}

// =============================================================================
// Connection Tracker
// =============================================================================

// ConnectionTracker tracks network connections.
type ConnectionTracker struct {
	config *ConnectionTrackerConfig

	// Connection storage (by key).
	connections   map[string]*Connection
	connectionsMu sync.RWMutex

	// Reverse mapping for bidirectional lookup.
	reverseMap   map[string]string
	reverseMapMu sync.RWMutex

	// Per-IP connection counts.
	perIPCounts   map[string]int
	perIPCountsMu sync.Mutex

	// Statistics.
	stats   ConnectionTrackerStats
	statsMu sync.RWMutex

	// Lifecycle.
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool

	// Callbacks.
	onConnectionNew     func(*Connection)
	onConnectionClosed  func(*Connection)
	onConnectionExpired func(*Connection)
	onStateChange       func(*Connection, TCPState, TCPState)
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker(config *ConnectionTrackerConfig) *ConnectionTracker {
	if config == nil {
		config = DefaultConnectionTrackerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ConnectionTracker{
		config:      config,
		connections: make(map[string]*Connection),
		reverseMap:  make(map[string]string),
		perIPCounts: make(map[string]int),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// =============================================================================
// Lifecycle Methods
// =============================================================================

// Start starts the connection tracker.
func (ct *ConnectionTracker) Start() error {
	if ct.running.Load() {
		return nil
	}

	ct.running.Store(true)

	// Start cleanup goroutine.
	ct.wg.Add(1)
	go ct.cleanupLoop()

	return nil
}

// Stop stops the connection tracker.
func (ct *ConnectionTracker) Stop() error {
	if !ct.running.Load() {
		return nil
	}

	ct.running.Store(false)
	ct.cancel()
	ct.wg.Wait()

	return nil
}

// IsRunning returns whether the tracker is running.
func (ct *ConnectionTracker) IsRunning() bool {
	return ct.running.Load()
}

// =============================================================================
// Connection Management
// =============================================================================

// CreateConnection creates a new connection entry.
func (ct *ConnectionTracker) CreateConnection(key *ConnectionKey) (*Connection, error) {
	if !ct.running.Load() {
		return nil, ErrTrackerNotRunning
	}

	keyStr := key.Key()

	ct.connectionsMu.Lock()
	defer ct.connectionsMu.Unlock()

	// Check if exists.
	if _, exists := ct.connections[keyStr]; exists {
		return nil, ErrConnectionExists
	}

	// Check max connections.
	if len(ct.connections) >= ct.config.MaxConnections {
		atomic.AddUint64(&ct.stats.ConnectionsRejected, 1)
		return nil, ErrMaxConnectionsReached
	}

	// Check per-IP limit.
	srcIPStr := key.SrcIP.String()
	ct.perIPCountsMu.Lock()
	if ct.perIPCounts[srcIPStr] >= ct.config.MaxPerIP {
		ct.perIPCountsMu.Unlock()
		atomic.AddUint64(&ct.stats.ConnectionsRejected, 1)
		return nil, ErrMaxConnectionsReached
	}
	ct.perIPCounts[srcIPStr]++
	ct.perIPCountsMu.Unlock()

	now := time.Now()
	conn := &Connection{
		Key:       key,
		ID:        keyStr,
		Protocol:  key.Protocol,
		State:     TCPStateNone,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(ct.config.GetTimeout(TCPStateNone, key.Protocol)),
	}

	ct.connections[keyStr] = conn

	// Add reverse mapping.
	ct.reverseMapMu.Lock()
	reverseKey := key.Reverse().Key()
	ct.reverseMap[reverseKey] = keyStr
	ct.reverseMapMu.Unlock()

	// Update stats.
	atomic.AddUint64(&ct.stats.ConnectionsCreated, 1)
	atomic.AddUint64(&ct.stats.TotalConnections, 1)
	atomic.AddUint64(&ct.stats.ActiveConnections, 1)

	switch key.Protocol {
	case 6: // TCP
		atomic.AddUint64(&ct.stats.TCPConnections, 1)
	case 17: // UDP
		atomic.AddUint64(&ct.stats.UDPConnections, 1)
	case 1: // ICMP
		atomic.AddUint64(&ct.stats.ICMPConnections, 1)
	}

	// Callback.
	if ct.onConnectionNew != nil {
		go ct.onConnectionNew(conn)
	}

	return conn, nil
}

// GetConnection retrieves a connection by key.
func (ct *ConnectionTracker) GetConnection(key *ConnectionKey) (*Connection, bool) {
	keyStr := key.Key()

	ct.connectionsMu.RLock()
	conn, exists := ct.connections[keyStr]
	ct.connectionsMu.RUnlock()

	if exists {
		return conn, true
	}

	// Try reverse lookup.
	ct.reverseMapMu.RLock()
	reverseKey := key.Reverse().Key()
	forwardKey, exists := ct.reverseMap[reverseKey]
	ct.reverseMapMu.RUnlock()

	if exists {
		ct.connectionsMu.RLock()
		conn, exists = ct.connections[forwardKey]
		ct.connectionsMu.RUnlock()
		return conn, exists
	}

	return nil, false
}

// GetOrCreateConnection gets an existing connection or creates a new one.
func (ct *ConnectionTracker) GetOrCreateConnection(key *ConnectionKey) (*Connection, bool, error) {
	// Try to get first.
	if conn, exists := ct.GetConnection(key); exists {
		return conn, false, nil
	}

	// Create new.
	conn, err := ct.CreateConnection(key)
	if err != nil {
		return nil, false, err
	}

	return conn, true, nil
}

// DeleteConnection removes a connection.
func (ct *ConnectionTracker) DeleteConnection(key *ConnectionKey) error {
	keyStr := key.Key()

	ct.connectionsMu.Lock()
	conn, exists := ct.connections[keyStr]
	if !exists {
		ct.connectionsMu.Unlock()
		return ErrConnectionNotFound
	}

	delete(ct.connections, keyStr)
	ct.connectionsMu.Unlock()

	// Remove reverse mapping.
	ct.reverseMapMu.Lock()
	reverseKey := key.Reverse().Key()
	delete(ct.reverseMap, reverseKey)
	ct.reverseMapMu.Unlock()

	// Update per-IP count.
	srcIPStr := key.SrcIP.String()
	ct.perIPCountsMu.Lock()
	if ct.perIPCounts[srcIPStr] > 0 {
		ct.perIPCounts[srcIPStr]--
	}
	ct.perIPCountsMu.Unlock()

	// Update stats.
	atomic.AddUint64(&ct.stats.ConnectionsClosed, 1)
	ct.decrementActive()

	// Callback.
	if ct.onConnectionClosed != nil && conn != nil {
		go ct.onConnectionClosed(conn)
	}

	return nil
}

// =============================================================================
// TCP State Machine
// =============================================================================

// ProcessTCPPacket processes a TCP packet and updates connection state.
func (ct *ConnectionTracker) ProcessTCPPacket(key *ConnectionKey, flags TCPFlags, isReply bool) (*Connection, error) {
	conn, created, err := ct.GetOrCreateConnection(key)
	if err != nil {
		return nil, err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	oldState := conn.State
	newState := ct.getNextState(conn.State, flags, isReply)

	if newState != oldState {
		ct.updateStateStats(oldState, newState)
		conn.State = newState

		// Update timeout based on new state.
		timeout := ct.config.GetTimeout(newState, 6)
		conn.ExpiresAt = time.Now().Add(timeout)

		// Track establishment time.
		if newState == TCPStateEstablished && conn.EstablishedAt.IsZero() {
			conn.EstablishedAt = time.Now()
		}

		// Callback.
		if ct.onStateChange != nil {
			go ct.onStateChange(conn, oldState, newState)
		}
	}

	// Update activity.
	conn.LastSeen = time.Now()
	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	// Update sequence numbers and windows (simplified).
	if !created {
		atomic.AddUint64(&ct.stats.TotalPackets, 1)
	}

	return conn, nil
}

// getNextState calculates the next TCP state.
func (ct *ConnectionTracker) getNextState(current TCPState, flags TCPFlags, isReply bool) TCPState {
	syn := flags&TCPFlagSYN != 0
	ack := flags&TCPFlagACK != 0
	fin := flags&TCPFlagFIN != 0
	rst := flags&TCPFlagRST != 0

	// RST always goes to closed.
	if rst {
		return TCPStateClosed
	}

	switch current {
	case TCPStateNone:
		if syn && !ack {
			return TCPStateSynSent
		}

	case TCPStateSynSent:
		if syn && ack && isReply {
			return TCPStateSynReceived
		}

	case TCPStateSynReceived:
		if ack && !syn && !fin {
			return TCPStateEstablished
		}

	case TCPStateEstablished:
		if fin {
			if !isReply {
				return TCPStateFinWait1
			}
			return TCPStateCloseWait
		}

	case TCPStateFinWait1:
		if fin && ack && isReply {
			return TCPStateTimeWait
		}
		if ack && isReply {
			return TCPStateFinWait2
		}
		if fin && isReply {
			return TCPStateClosing
		}

	case TCPStateFinWait2:
		if fin && isReply {
			return TCPStateTimeWait
		}

	case TCPStateCloseWait:
		if fin && !isReply {
			return TCPStateLastAck
		}

	case TCPStateClosing:
		if ack && isReply {
			return TCPStateTimeWait
		}

	case TCPStateLastAck:
		if ack && isReply {
			return TCPStateClosed
		}

	case TCPStateTimeWait:
		// Will eventually timeout to closed.
		return TCPStateTimeWait
	}

	return current
}

// =============================================================================
// UDP Connection Tracking
// =============================================================================

// ProcessUDPPacket processes a UDP packet.
func (ct *ConnectionTracker) ProcessUDPPacket(key *ConnectionKey, isReply bool) (*Connection, error) {
	conn, created, err := ct.GetOrCreateConnection(key)
	if err != nil {
		return nil, err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// UDP is stateless, just track activity.
	if conn.State == TCPStateNone {
		conn.State = TCPStateEstablished
		atomic.AddUint64(&ct.stats.EstablishedCount, 1)
	}

	conn.LastSeen = time.Now()
	conn.ExpiresAt = conn.LastSeen.Add(ct.config.UDPTimeout)

	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	if !created {
		atomic.AddUint64(&ct.stats.TotalPackets, 1)
	}

	return conn, nil
}

// =============================================================================
// ICMP Connection Tracking
// =============================================================================

// ProcessICMPPacket processes an ICMP packet.
func (ct *ConnectionTracker) ProcessICMPPacket(key *ConnectionKey, isReply bool) (*Connection, error) {
	conn, created, err := ct.GetOrCreateConnection(key)
	if err != nil {
		return nil, err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.State = TCPStateEstablished
	conn.LastSeen = time.Now()
	conn.ExpiresAt = conn.LastSeen.Add(ct.config.ICMPTimeout)

	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	if !created {
		atomic.AddUint64(&ct.stats.TotalPackets, 1)
	}

	return conn, nil
}

// =============================================================================
// Query Methods
// =============================================================================

// GetAllConnections returns all active connections.
func (ct *ConnectionTracker) GetAllConnections() []*Connection {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()

	result := make([]*Connection, 0, len(ct.connections))
	for _, conn := range ct.connections {
		result = append(result, conn)
	}
	return result
}

// GetConnectionsByState returns connections in a specific state.
func (ct *ConnectionTracker) GetConnectionsByState(state TCPState) []*Connection {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()

	result := make([]*Connection, 0)
	for _, conn := range ct.connections {
		if conn.State == state {
			result = append(result, conn)
		}
	}
	return result
}

// GetConnectionsByIP returns connections for a specific IP.
func (ct *ConnectionTracker) GetConnectionsByIP(ip net.IP) []*Connection {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()

	result := make([]*Connection, 0)
	for _, conn := range ct.connections {
		if conn.Key.SrcIP.Equal(ip) || conn.Key.DstIP.Equal(ip) {
			result = append(result, conn)
		}
	}
	return result
}

// GetConnectionCount returns the current connection count.
func (ct *ConnectionTracker) GetConnectionCount() int {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()
	return len(ct.connections)
}

// =============================================================================
// Statistics
// =============================================================================

// GetStats returns connection tracker statistics.
func (ct *ConnectionTracker) GetStats() *ConnectionTrackerStats {
	ct.statsMu.RLock()
	defer ct.statsMu.RUnlock()

	return &ConnectionTrackerStats{
		TotalConnections:    ct.stats.TotalConnections,
		ActiveConnections:   ct.stats.ActiveConnections,
		TCPConnections:      ct.stats.TCPConnections,
		UDPConnections:      ct.stats.UDPConnections,
		ICMPConnections:     ct.stats.ICMPConnections,
		SynSentCount:        ct.stats.SynSentCount,
		SynRecvCount:        ct.stats.SynRecvCount,
		EstablishedCount:    ct.stats.EstablishedCount,
		FinWaitCount:        ct.stats.FinWaitCount,
		CloseWaitCount:      ct.stats.CloseWaitCount,
		TimeWaitCount:       ct.stats.TimeWaitCount,
		ConnectionsCreated:  ct.stats.ConnectionsCreated,
		ConnectionsClosed:   ct.stats.ConnectionsClosed,
		ConnectionsExpired:  ct.stats.ConnectionsExpired,
		ConnectionsRejected: ct.stats.ConnectionsRejected,
		TotalPackets:        ct.stats.TotalPackets,
		TotalBytes:          ct.stats.TotalBytes,
		InvalidPackets:      ct.stats.InvalidPackets,
		StateTransitionErr:  ct.stats.StateTransitionErr,
	}
}

// updateStateStats updates state-specific counters.
func (ct *ConnectionTracker) updateStateStats(oldState, newState TCPState) {
	// Decrement old state.
	switch oldState {
	case TCPStateSynSent:
		ct.decrementStat(&ct.stats.SynSentCount)
	case TCPStateSynReceived:
		ct.decrementStat(&ct.stats.SynRecvCount)
	case TCPStateEstablished:
		ct.decrementStat(&ct.stats.EstablishedCount)
	case TCPStateFinWait1, TCPStateFinWait2:
		ct.decrementStat(&ct.stats.FinWaitCount)
	case TCPStateCloseWait, TCPStateLastAck, TCPStateClosing:
		ct.decrementStat(&ct.stats.CloseWaitCount)
	case TCPStateTimeWait:
		ct.decrementStat(&ct.stats.TimeWaitCount)
	}

	// Increment new state.
	switch newState {
	case TCPStateSynSent:
		atomic.AddUint64(&ct.stats.SynSentCount, 1)
	case TCPStateSynReceived:
		atomic.AddUint64(&ct.stats.SynRecvCount, 1)
	case TCPStateEstablished:
		atomic.AddUint64(&ct.stats.EstablishedCount, 1)
	case TCPStateFinWait1, TCPStateFinWait2:
		atomic.AddUint64(&ct.stats.FinWaitCount, 1)
	case TCPStateCloseWait, TCPStateLastAck, TCPStateClosing:
		atomic.AddUint64(&ct.stats.CloseWaitCount, 1)
	case TCPStateTimeWait:
		atomic.AddUint64(&ct.stats.TimeWaitCount, 1)
	}
}

// decrementStat safely decrements a uint64.
func (ct *ConnectionTracker) decrementStat(stat *uint64) {
	for {
		old := atomic.LoadUint64(stat)
		if old == 0 {
			return
		}
		if atomic.CompareAndSwapUint64(stat, old, old-1) {
			return
		}
	}
}

// decrementActive decrements active connection count.
func (ct *ConnectionTracker) decrementActive() {
	ct.decrementStat(&ct.stats.ActiveConnections)
}

// =============================================================================
// Callbacks
// =============================================================================

// SetOnConnectionNew sets callback for new connections.
func (ct *ConnectionTracker) SetOnConnectionNew(fn func(*Connection)) {
	ct.onConnectionNew = fn
}

// SetOnConnectionClosed sets callback for closed connections.
func (ct *ConnectionTracker) SetOnConnectionClosed(fn func(*Connection)) {
	ct.onConnectionClosed = fn
}

// SetOnConnectionExpired sets callback for expired connections.
func (ct *ConnectionTracker) SetOnConnectionExpired(fn func(*Connection)) {
	ct.onConnectionExpired = fn
}

// SetOnStateChange sets callback for state changes.
func (ct *ConnectionTracker) SetOnStateChange(fn func(*Connection, TCPState, TCPState)) {
	ct.onStateChange = fn
}

// =============================================================================
// Cleanup
// =============================================================================

// cleanupLoop periodically removes expired connections.
func (ct *ConnectionTracker) cleanupLoop() {
	defer ct.wg.Done()

	ticker := time.NewTicker(ct.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ct.ctx.Done():
			return
		case <-ticker.C:
			ct.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired connections.
func (ct *ConnectionTracker) cleanupExpired() {
	now := time.Now()
	var expired []*Connection

	ct.connectionsMu.Lock()
	for key, conn := range ct.connections {
		conn.mu.Lock()
		if now.After(conn.ExpiresAt) {
			expired = append(expired, conn)
			delete(ct.connections, key)

			// Remove reverse mapping.
			ct.reverseMapMu.Lock()
			reverseKey := conn.Key.Reverse().Key()
			delete(ct.reverseMap, reverseKey)
			ct.reverseMapMu.Unlock()

			// Update per-IP count.
			srcIPStr := conn.Key.SrcIP.String()
			ct.perIPCountsMu.Lock()
			if ct.perIPCounts[srcIPStr] > 0 {
				ct.perIPCounts[srcIPStr]--
			}
			ct.perIPCountsMu.Unlock()
		}
		conn.mu.Unlock()
	}
	ct.connectionsMu.Unlock()

	// Update stats and callbacks.
	for _, conn := range expired {
		atomic.AddUint64(&ct.stats.ConnectionsExpired, 1)
		ct.decrementActive()

		if ct.onConnectionExpired != nil {
			go ct.onConnectionExpired(conn)
		}
	}
}

// Clear removes all connections.
func (ct *ConnectionTracker) Clear() {
	ct.connectionsMu.Lock()
	ct.connections = make(map[string]*Connection)
	ct.connectionsMu.Unlock()

	ct.reverseMapMu.Lock()
	ct.reverseMap = make(map[string]string)
	ct.reverseMapMu.Unlock()

	ct.perIPCountsMu.Lock()
	ct.perIPCounts = make(map[string]int)
	ct.perIPCountsMu.Unlock()

	// Reset stats.
	ct.statsMu.Lock()
	ct.stats.ActiveConnections = 0
	ct.statsMu.Unlock()
}
