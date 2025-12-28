// Package router provides packet routing and connection tracking functionality.
package router

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
// Errors
// =============================================================================

var (
	// ErrConnectionNotFound indicates connection not found.
	ErrConnectionNotFound = errors.New("connection not found")
	// ErrConnectionExists indicates connection already exists.
	ErrConnectionExists = errors.New("connection already exists")
	// ErrTrackerFull indicates tracker at capacity.
	ErrTrackerFull = errors.New("connection tracker full")
	// ErrInvalidPacket indicates invalid packet format.
	ErrInvalidPacket = errors.New("invalid packet")
)

// =============================================================================
// Protocol Constants
// =============================================================================

const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

// =============================================================================
// TCP Flags
// =============================================================================

// TCPFlags represents TCP header flags.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 0x01
	TCPFlagSYN TCPFlags = 0x02
	TCPFlagRST TCPFlags = 0x04
	TCPFlagPSH TCPFlags = 0x08
	TCPFlagACK TCPFlags = 0x10
	TCPFlagURG TCPFlags = 0x20
)

// HasSYN returns true if SYN flag is set.
func (f TCPFlags) HasSYN() bool { return f&TCPFlagSYN != 0 }

// HasACK returns true if ACK flag is set.
func (f TCPFlags) HasACK() bool { return f&TCPFlagACK != 0 }

// HasFIN returns true if FIN flag is set.
func (f TCPFlags) HasFIN() bool { return f&TCPFlagFIN != 0 }

// HasRST returns true if RST flag is set.
func (f TCPFlags) HasRST() bool { return f&TCPFlagRST != 0 }

// =============================================================================
// Connection State
// =============================================================================

// ConnState represents connection state.
type ConnState int

const (
	ConnStateNew ConnState = iota
	ConnStateSynSent
	ConnStateSynRecv
	ConnStateEstablished
	ConnStateFinWait1
	ConnStateFinWait2
	ConnStateCloseWait
	ConnStateClosing
	ConnStateLastAck
	ConnStateTimeWait
	ConnStateClosed
)

// String returns string representation.
func (s ConnState) String() string {
	switch s {
	case ConnStateNew:
		return "NEW"
	case ConnStateSynSent:
		return "SYN_SENT"
	case ConnStateSynRecv:
		return "SYN_RECV"
	case ConnStateEstablished:
		return "ESTABLISHED"
	case ConnStateFinWait1:
		return "FIN_WAIT1"
	case ConnStateFinWait2:
		return "FIN_WAIT2"
	case ConnStateCloseWait:
		return "CLOSE_WAIT"
	case ConnStateClosing:
		return "CLOSING"
	case ConnStateLastAck:
		return "LAST_ACK"
	case ConnStateTimeWait:
		return "TIME_WAIT"
	case ConnStateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// =============================================================================
// Connection Key
// =============================================================================

// ConnKey uniquely identifies a connection.
type ConnKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// NewConnKey creates a connection key from IP addresses and ports.
func NewConnKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) ConnKey {
	var key ConnKey
	copy(key.SrcIP[:], srcIP.To4())
	copy(key.DstIP[:], dstIP.To4())
	key.SrcPort = srcPort
	key.DstPort = dstPort
	key.Protocol = protocol
	return key
}

// Reverse returns the reverse direction key.
func (k ConnKey) Reverse() ConnKey {
	return ConnKey{
		SrcIP:    k.DstIP,
		DstIP:    k.SrcIP,
		SrcPort:  k.DstPort,
		DstPort:  k.SrcPort,
		Protocol: k.Protocol,
	}
}

// String returns string representation.
func (k ConnKey) String() string {
	srcIP := net.IP(k.SrcIP[:])
	dstIP := net.IP(k.DstIP[:])
	return fmt.Sprintf("%s:%d->%s:%d/%d", srcIP, k.SrcPort, dstIP, k.DstPort, k.Protocol)
}

// =============================================================================
// Connection Entry
// =============================================================================

// ConnEntry represents a tracked connection.
type ConnEntry struct {
	Key          ConnKey
	State        ConnState
	Protocol     uint8
	CreatedAt    time.Time
	LastSeen     time.Time
	ExpiresAt    time.Time
	PacketsIn    uint64
	PacketsOut   uint64
	BytesIn      uint64
	BytesOut     uint64
	WANInterface string
	LANInterface string
	NATMappingID string
	mu           sync.Mutex
}

// UpdateActivity updates last seen and extends expiry.
func (c *ConnEntry) UpdateActivity(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastSeen = time.Now()
	c.ExpiresAt = c.LastSeen.Add(timeout)
}

// IsExpired checks if connection expired.
func (c *ConnEntry) IsExpired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().After(c.ExpiresAt)
}

// =============================================================================
// Connection Tracker Config
// =============================================================================

// ConnTrackerConfig contains configuration.
type ConnTrackerConfig struct {
	MaxConnections      int
	MaxPerIP            int
	TCPEstablishedTTL   time.Duration
	TCPSynTTL           time.Duration
	TCPFinTTL           time.Duration
	TCPTimeWaitTTL      time.Duration
	UDPTTL              time.Duration
	ICMPTTL             time.Duration
	CleanupInterval     time.Duration
	EnableStateTracking bool
}

// DefaultConnTrackerConfig returns default configuration.
func DefaultConnTrackerConfig() *ConnTrackerConfig {
	return &ConnTrackerConfig{
		MaxConnections:      262144,
		MaxPerIP:            1024,
		TCPEstablishedTTL:   5 * time.Hour,
		TCPSynTTL:           30 * time.Second,
		TCPFinTTL:           2 * time.Minute,
		TCPTimeWaitTTL:      2 * time.Minute,
		UDPTTL:              180 * time.Second,
		ICMPTTL:             30 * time.Second,
		CleanupInterval:     10 * time.Second,
		EnableStateTracking: true,
	}
}

// GetTimeout returns timeout for state and protocol.
func (c *ConnTrackerConfig) GetTimeout(state ConnState, protocol uint8) time.Duration {
	switch protocol {
	case ProtocolUDP:
		return c.UDPTTL
	case ProtocolICMP:
		return c.ICMPTTL
	case ProtocolTCP:
		switch state {
		case ConnStateSynSent, ConnStateSynRecv:
			return c.TCPSynTTL
		case ConnStateEstablished:
			return c.TCPEstablishedTTL
		case ConnStateFinWait1, ConnStateFinWait2, ConnStateClosing, ConnStateLastAck:
			return c.TCPFinTTL
		case ConnStateTimeWait:
			return c.TCPTimeWaitTTL
		default:
			return c.TCPSynTTL
		}
	default:
		return 30 * time.Second
	}
}

// =============================================================================
// Connection Tracker Stats
// =============================================================================

// ConnTrackerStats contains statistics.
type ConnTrackerStats struct {
	TotalConnections    uint64
	ActiveConnections   uint64
	TCPConnections      uint64
	UDPConnections      uint64
	ICMPConnections     uint64
	NewConnections      uint64
	ClosedConnections   uint64
	ExpiredConnections  uint64
	RejectedConnections uint64
	TotalPackets        uint64
	TotalBytes          uint64
}

// =============================================================================
// Connection Tracker
// =============================================================================

// ConnTracker tracks network connections for routing decisions.
type ConnTracker struct {
	config *ConnTrackerConfig

	// Connection storage.
	connections   map[ConnKey]*ConnEntry
	connectionsMu sync.RWMutex

	// Reverse mappings for bidirectional lookup.
	reverseMap   map[ConnKey]ConnKey
	reverseMapMu sync.RWMutex

	// Per-IP limits.
	perIPCount   map[[4]byte]int
	perIPCountMu sync.Mutex

	// Statistics.
	stats   ConnTrackerStats
	statsMu sync.RWMutex

	// Lifecycle.
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool

	// Callbacks.
	onNew     func(*ConnEntry)
	onClosed  func(*ConnEntry)
	onExpired func(*ConnEntry)
}

// NewConnTracker creates a new connection tracker.
func NewConnTracker(config *ConnTrackerConfig) *ConnTracker {
	if config == nil {
		config = DefaultConnTrackerConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnTracker{
		config:      config,
		connections: make(map[ConnKey]*ConnEntry),
		reverseMap:  make(map[ConnKey]ConnKey),
		perIPCount:  make(map[[4]byte]int),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// =============================================================================
// Lifecycle
// =============================================================================

// Start starts the connection tracker.
func (ct *ConnTracker) Start() error {
	if ct.running.Load() {
		return nil
	}
	ct.running.Store(true)
	ct.wg.Add(1)
	go ct.cleanupLoop()
	return nil
}

// Stop stops the connection tracker.
func (ct *ConnTracker) Stop() error {
	if !ct.running.Load() {
		return nil
	}
	ct.running.Store(false)
	ct.cancel()
	ct.wg.Wait()
	return nil
}

// IsRunning returns whether tracker is running.
func (ct *ConnTracker) IsRunning() bool {
	return ct.running.Load()
}

// =============================================================================
// Connection Management
// =============================================================================

// Track creates or updates a connection.
func (ct *ConnTracker) Track(key ConnKey, wanIface, lanIface string) (*ConnEntry, error) {
	ct.connectionsMu.Lock()
	defer ct.connectionsMu.Unlock()

	// Check existing.
	if conn, exists := ct.connections[key]; exists {
		timeout := ct.config.GetTimeout(conn.State, conn.Protocol)
		conn.UpdateActivity(timeout)
		return conn, nil
	}

	// Check capacity.
	if len(ct.connections) >= ct.config.MaxConnections {
		atomic.AddUint64(&ct.stats.RejectedConnections, 1)
		return nil, ErrTrackerFull
	}

	// Check per-IP limit.
	ct.perIPCountMu.Lock()
	if ct.perIPCount[key.SrcIP] >= ct.config.MaxPerIP {
		ct.perIPCountMu.Unlock()
		atomic.AddUint64(&ct.stats.RejectedConnections, 1)
		return nil, ErrTrackerFull
	}
	ct.perIPCount[key.SrcIP]++
	ct.perIPCountMu.Unlock()

	// Create new connection.
	now := time.Now()
	conn := &ConnEntry{
		Key:          key,
		State:        ConnStateNew,
		Protocol:     key.Protocol,
		CreatedAt:    now,
		LastSeen:     now,
		ExpiresAt:    now.Add(ct.config.GetTimeout(ConnStateNew, key.Protocol)),
		WANInterface: wanIface,
		LANInterface: lanIface,
	}

	ct.connections[key] = conn

	// Add reverse mapping.
	ct.reverseMapMu.Lock()
	ct.reverseMap[key.Reverse()] = key
	ct.reverseMapMu.Unlock()

	// Update stats.
	atomic.AddUint64(&ct.stats.NewConnections, 1)
	atomic.AddUint64(&ct.stats.TotalConnections, 1)
	atomic.AddUint64(&ct.stats.ActiveConnections, 1)
	switch key.Protocol {
	case ProtocolTCP:
		atomic.AddUint64(&ct.stats.TCPConnections, 1)
	case ProtocolUDP:
		atomic.AddUint64(&ct.stats.UDPConnections, 1)
	case ProtocolICMP:
		atomic.AddUint64(&ct.stats.ICMPConnections, 1)
	}

	if ct.onNew != nil {
		go ct.onNew(conn)
	}

	return conn, nil
}

// Lookup finds a connection by key.
func (ct *ConnTracker) Lookup(key ConnKey) (*ConnEntry, bool) {
	ct.connectionsMu.RLock()
	conn, exists := ct.connections[key]
	ct.connectionsMu.RUnlock()
	if exists {
		return conn, true
	}

	// Try reverse lookup.
	ct.reverseMapMu.RLock()
	fwdKey, exists := ct.reverseMap[key]
	ct.reverseMapMu.RUnlock()
	if exists {
		ct.connectionsMu.RLock()
		conn, exists = ct.connections[fwdKey]
		ct.connectionsMu.RUnlock()
		return conn, exists
	}

	return nil, false
}

// Delete removes a connection.
func (ct *ConnTracker) Delete(key ConnKey) error {
	ct.connectionsMu.Lock()
	conn, exists := ct.connections[key]
	if !exists {
		ct.connectionsMu.Unlock()
		return ErrConnectionNotFound
	}
	delete(ct.connections, key)
	ct.connectionsMu.Unlock()

	// Remove reverse mapping.
	ct.reverseMapMu.Lock()
	delete(ct.reverseMap, key.Reverse())
	ct.reverseMapMu.Unlock()

	// Update per-IP count.
	ct.perIPCountMu.Lock()
	if ct.perIPCount[key.SrcIP] > 0 {
		ct.perIPCount[key.SrcIP]--
	}
	ct.perIPCountMu.Unlock()

	// Update stats.
	atomic.AddUint64(&ct.stats.ClosedConnections, 1)
	ct.decrementActive()

	if ct.onClosed != nil && conn != nil {
		go ct.onClosed(conn)
	}

	return nil
}

// =============================================================================
// TCP State Machine
// =============================================================================

// ProcessTCP processes TCP packet and updates state.
func (ct *ConnTracker) ProcessTCP(key ConnKey, flags TCPFlags, isReply bool) (*ConnEntry, error) {
	conn, exists := ct.Lookup(key)
	if !exists {
		var err error
		conn, err = ct.Track(key, "", "")
		if err != nil {
			return nil, err
		}
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	if !ct.config.EnableStateTracking {
		return conn, nil
	}

	// Update state.
	newState := ct.getNextState(conn.State, flags, isReply)
	if newState != conn.State {
		conn.State = newState
		timeout := ct.config.GetTimeout(newState, ProtocolTCP)
		conn.ExpiresAt = time.Now().Add(timeout)
	}

	conn.LastSeen = time.Now()
	atomic.AddUint64(&ct.stats.TotalPackets, 1)

	return conn, nil
}

// getNextState calculates next TCP state.
func (ct *ConnTracker) getNextState(current ConnState, flags TCPFlags, isReply bool) ConnState {
	if flags.HasRST() {
		return ConnStateClosed
	}

	switch current {
	case ConnStateNew:
		if flags.HasSYN() && !flags.HasACK() {
			return ConnStateSynSent
		}
	case ConnStateSynSent:
		if flags.HasSYN() && flags.HasACK() && isReply {
			return ConnStateSynRecv
		}
	case ConnStateSynRecv:
		if flags.HasACK() && !flags.HasSYN() && !flags.HasFIN() {
			return ConnStateEstablished
		}
	case ConnStateEstablished:
		if flags.HasFIN() {
			if !isReply {
				return ConnStateFinWait1
			}
			return ConnStateCloseWait
		}
	case ConnStateFinWait1:
		if flags.HasFIN() && flags.HasACK() && isReply {
			return ConnStateTimeWait
		}
		if flags.HasACK() && isReply {
			return ConnStateFinWait2
		}
		if flags.HasFIN() && isReply {
			return ConnStateClosing
		}
	case ConnStateFinWait2:
		if flags.HasFIN() && isReply {
			return ConnStateTimeWait
		}
	case ConnStateCloseWait:
		if flags.HasFIN() && !isReply {
			return ConnStateLastAck
		}
	case ConnStateClosing:
		if flags.HasACK() && isReply {
			return ConnStateTimeWait
		}
	case ConnStateLastAck:
		if flags.HasACK() && isReply {
			return ConnStateClosed
		}
	}

	return current
}

// =============================================================================
// UDP/ICMP Processing
// =============================================================================

// ProcessUDP processes UDP packet.
func (ct *ConnTracker) ProcessUDP(key ConnKey, isReply bool) (*ConnEntry, error) {
	conn, exists := ct.Lookup(key)
	if !exists {
		var err error
		conn, err = ct.Track(key, "", "")
		if err != nil {
			return nil, err
		}
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.State == ConnStateNew {
		conn.State = ConnStateEstablished
	}

	conn.LastSeen = time.Now()
	conn.ExpiresAt = conn.LastSeen.Add(ct.config.UDPTTL)

	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	atomic.AddUint64(&ct.stats.TotalPackets, 1)
	return conn, nil
}

// ProcessICMP processes ICMP packet.
func (ct *ConnTracker) ProcessICMP(key ConnKey, isReply bool) (*ConnEntry, error) {
	conn, exists := ct.Lookup(key)
	if !exists {
		var err error
		conn, err = ct.Track(key, "", "")
		if err != nil {
			return nil, err
		}
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.State = ConnStateEstablished
	conn.LastSeen = time.Now()
	conn.ExpiresAt = conn.LastSeen.Add(ct.config.ICMPTTL)

	if !isReply {
		conn.PacketsOut++
	} else {
		conn.PacketsIn++
	}

	atomic.AddUint64(&ct.stats.TotalPackets, 1)
	return conn, nil
}

// =============================================================================
// Query Methods
// =============================================================================

// GetAllConnections returns all connections.
func (ct *ConnTracker) GetAllConnections() []*ConnEntry {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()

	result := make([]*ConnEntry, 0, len(ct.connections))
	for _, conn := range ct.connections {
		result = append(result, conn)
	}
	return result
}

// GetConnectionsByState returns connections in specific state.
func (ct *ConnTracker) GetConnectionsByState(state ConnState) []*ConnEntry {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()

	result := make([]*ConnEntry, 0)
	for _, conn := range ct.connections {
		if conn.State == state {
			result = append(result, conn)
		}
	}
	return result
}

// GetConnectionCount returns current connection count.
func (ct *ConnTracker) GetConnectionCount() int {
	ct.connectionsMu.RLock()
	defer ct.connectionsMu.RUnlock()
	return len(ct.connections)
}

// GetStats returns statistics.
func (ct *ConnTracker) GetStats() *ConnTrackerStats {
	ct.statsMu.RLock()
	defer ct.statsMu.RUnlock()
	return &ConnTrackerStats{
		TotalConnections:    ct.stats.TotalConnections,
		ActiveConnections:   ct.stats.ActiveConnections,
		TCPConnections:      ct.stats.TCPConnections,
		UDPConnections:      ct.stats.UDPConnections,
		ICMPConnections:     ct.stats.ICMPConnections,
		NewConnections:      ct.stats.NewConnections,
		ClosedConnections:   ct.stats.ClosedConnections,
		ExpiredConnections:  ct.stats.ExpiredConnections,
		RejectedConnections: ct.stats.RejectedConnections,
		TotalPackets:        ct.stats.TotalPackets,
		TotalBytes:          ct.stats.TotalBytes,
	}
}

// =============================================================================
// Callbacks
// =============================================================================

// SetOnNew sets callback for new connections.
func (ct *ConnTracker) SetOnNew(fn func(*ConnEntry)) {
	ct.onNew = fn
}

// SetOnClosed sets callback for closed connections.
func (ct *ConnTracker) SetOnClosed(fn func(*ConnEntry)) {
	ct.onClosed = fn
}

// SetOnExpired sets callback for expired connections.
func (ct *ConnTracker) SetOnExpired(fn func(*ConnEntry)) {
	ct.onExpired = fn
}

// =============================================================================
// Cleanup
// =============================================================================

func (ct *ConnTracker) cleanupLoop() {
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

func (ct *ConnTracker) cleanupExpired() {
	now := time.Now()
	var expired []*ConnEntry

	ct.connectionsMu.Lock()
	for key, conn := range ct.connections {
		conn.mu.Lock()
		if now.After(conn.ExpiresAt) {
			expired = append(expired, conn)
			delete(ct.connections, key)

			ct.reverseMapMu.Lock()
			delete(ct.reverseMap, key.Reverse())
			ct.reverseMapMu.Unlock()

			ct.perIPCountMu.Lock()
			if ct.perIPCount[key.SrcIP] > 0 {
				ct.perIPCount[key.SrcIP]--
			}
			ct.perIPCountMu.Unlock()
		}
		conn.mu.Unlock()
	}
	ct.connectionsMu.Unlock()

	for _, conn := range expired {
		atomic.AddUint64(&ct.stats.ExpiredConnections, 1)
		ct.decrementActive()
		if ct.onExpired != nil {
			go ct.onExpired(conn)
		}
	}
}

func (ct *ConnTracker) decrementActive() {
	for {
		old := atomic.LoadUint64(&ct.stats.ActiveConnections)
		if old == 0 {
			return
		}
		if atomic.CompareAndSwapUint64(&ct.stats.ActiveConnections, old, old-1) {
			return
		}
	}
}

// Clear removes all connections.
func (ct *ConnTracker) Clear() {
	ct.connectionsMu.Lock()
	ct.connections = make(map[ConnKey]*ConnEntry)
	ct.connectionsMu.Unlock()

	ct.reverseMapMu.Lock()
	ct.reverseMap = make(map[ConnKey]ConnKey)
	ct.reverseMapMu.Unlock()

	ct.perIPCountMu.Lock()
	ct.perIPCount = make(map[[4]byte]int)
	ct.perIPCountMu.Unlock()

	ct.statsMu.Lock()
	ct.stats.ActiveConnections = 0
	ct.statsMu.Unlock()
}
