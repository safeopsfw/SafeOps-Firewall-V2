// Package connection provides stateful connection tracking for the firewall engine.
// It tracks TCP, UDP, and ICMP connections through their lifecycle, enabling
// stateful packet inspection and connection-aware rule matching.
//
// Architecture:
//
//	Packet arrives from SafeOps Engine
//	        ↓
//	  ConnectionTracker.Track(packet)
//	        ↓
//	  ┌─────┴─────┐
//	  ↓           ↓
//	New Conn?   Existing?
//	  ↓           ↓
//	Create     Update State
//	  ↓           ↓
//	  └─────┬─────┘
//	        ↓
//	  Return ConnectionEntry
//	        ↓
//	  Used by Rule Matcher for stateful rules
package connection

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// TCP State Types
// ============================================================================

// TCPState represents the state of a TCP connection in the state machine.
type TCPState int8

const (
	// TCPStateNew indicates the initial state (no packets seen yet).
	TCPStateNew TCPState = 0

	// TCPStateSYNSent indicates a SYN packet has been sent (client initiated).
	TCPStateSYNSent TCPState = 1

	// TCPStateSYNReceived indicates SYN-ACK received, waiting for final ACK.
	TCPStateSYNReceived TCPState = 2

	// TCPStateEstablished indicates the 3-way handshake is complete.
	TCPStateEstablished TCPState = 3

	// TCPStateFinWait1 indicates FIN sent, waiting for ACK.
	TCPStateFinWait1 TCPState = 4

	// TCPStateFinWait2 indicates FIN acknowledged, waiting for peer's FIN.
	TCPStateFinWait2 TCPState = 5

	// TCPStateCloseWait indicates FIN received, waiting for application to close.
	TCPStateCloseWait TCPState = 6

	// TCPStateClosing indicates both sides sent FIN simultaneously.
	TCPStateClosing TCPState = 7

	// TCPStateLastAck indicates FIN sent after receiving FIN, waiting for ACK.
	TCPStateLastAck TCPState = 8

	// TCPStateTimeWait indicates waiting 2×MSL before final close.
	TCPStateTimeWait TCPState = 9

	// TCPStateClosed indicates the connection is fully closed.
	TCPStateClosed TCPState = 10

	// TCPStateInvalid indicates an invalid state (protocol violation).
	TCPStateInvalid TCPState = 11
)

// tcpStateNames maps TCP state values to human-readable strings.
var tcpStateNames = map[TCPState]string{
	TCPStateNew:         "NEW",
	TCPStateSYNSent:     "SYN_SENT",
	TCPStateSYNReceived: "SYN_RECEIVED",
	TCPStateEstablished: "ESTABLISHED",
	TCPStateFinWait1:    "FIN_WAIT_1",
	TCPStateFinWait2:    "FIN_WAIT_2",
	TCPStateCloseWait:   "CLOSE_WAIT",
	TCPStateClosing:     "CLOSING",
	TCPStateLastAck:     "LAST_ACK",
	TCPStateTimeWait:    "TIME_WAIT",
	TCPStateClosed:      "CLOSED",
	TCPStateInvalid:     "INVALID",
}

// tcpStateValues maps strings to TCP state values.
var tcpStateValues = map[string]TCPState{
	"NEW":          TCPStateNew,
	"SYN_SENT":     TCPStateSYNSent,
	"SYN_RECEIVED": TCPStateSYNReceived,
	"ESTABLISHED":  TCPStateEstablished,
	"FIN_WAIT_1":   TCPStateFinWait1,
	"FIN_WAIT_2":   TCPStateFinWait2,
	"CLOSE_WAIT":   TCPStateCloseWait,
	"CLOSING":      TCPStateClosing,
	"LAST_ACK":     TCPStateLastAck,
	"TIME_WAIT":    TCPStateTimeWait,
	"CLOSED":       TCPStateClosed,
	"INVALID":      TCPStateInvalid,
}

// String returns the human-readable name of the TCP state.
func (s TCPState) String() string {
	if name, ok := tcpStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}

// IsValid checks if the state is a recognized value.
func (s TCPState) IsValid() bool {
	_, ok := tcpStateNames[s]
	return ok
}

// IsActive returns true if the connection is still active.
func (s TCPState) IsActive() bool {
	switch s {
	case TCPStateNew, TCPStateSYNSent, TCPStateSYNReceived,
		TCPStateEstablished, TCPStateFinWait1, TCPStateFinWait2,
		TCPStateCloseWait, TCPStateClosing, TCPStateLastAck:
		return true
	default:
		return false
	}
}

// IsEstablished returns true if data transfer is possible.
func (s TCPState) IsEstablished() bool {
	return s == TCPStateEstablished
}

// IsClosing returns true if the connection is being torn down.
func (s TCPState) IsClosing() bool {
	switch s {
	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck, TCPStateTimeWait:
		return true
	default:
		return false
	}
}

// TCPStateFromString parses a string into a TCPState.
func TCPStateFromString(s string) (TCPState, error) {
	if state, ok := tcpStateValues[s]; ok {
		return state, nil
	}
	return TCPStateNew, fmt.Errorf("unknown TCP state: %q", s)
}

// MarshalJSON implements json.Marshaler.
func (s TCPState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *TCPState) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	state, err := TCPStateFromString(str)
	if err != nil {
		return err
	}
	*s = state
	return nil
}

// ============================================================================
// Connection Key - 5-Tuple Identifier
// ============================================================================

// ConnectionKey uniquely identifies a network connection using the 5-tuple.
// The key is normalized so that the same connection always produces the same key,
// regardless of packet direction.
type ConnectionKey struct {
	// Protocol is the IP protocol number (6=TCP, 17=UDP, 1=ICMP).
	Protocol uint8

	// SrcIP is the source IP address (normalized - lower IP first).
	SrcIP string

	// DstIP is the destination IP address.
	DstIP string

	// SrcPort is the source port (normalized - lower port first for same IPs).
	SrcPort uint16

	// DstPort is the destination port.
	DstPort uint16
}

// NewConnectionKey creates a normalized connection key from packet metadata.
// The key is normalized so forward and reverse packets produce the same key.
func NewConnectionKey(pkt *models.PacketMetadata) ConnectionKey {
	return NewConnectionKeyFromTuple(
		uint8(pkt.Protocol),
		pkt.SrcIP, pkt.DstIP,
		pkt.SrcPort, pkt.DstPort,
	)
}

// NewConnectionKeyFromTuple creates a normalized connection key from explicit values.
func NewConnectionKeyFromTuple(protocol uint8, srcIP, dstIP string, srcPort, dstPort uint16) ConnectionKey {
	// Normalize: ensure consistent ordering regardless of direction
	// Lower IP comes first; if IPs equal, lower port comes first
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return ConnectionKey{
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}
}

// String returns a string representation of the connection key.
func (k ConnectionKey) String() string {
	return fmt.Sprintf("%d:%s:%d-%s:%d", k.Protocol, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// Hash returns a string suitable for use as a map key.
func (k ConnectionKey) Hash() string {
	return k.String()
}

// Matches checks if a packet belongs to this connection.
func (k ConnectionKey) Matches(pkt *models.PacketMetadata) bool {
	other := NewConnectionKey(pkt)
	return k == other
}

// Reverse returns the key with source and destination swapped.
func (k ConnectionKey) Reverse() ConnectionKey {
	return ConnectionKey{
		Protocol: k.Protocol,
		SrcIP:    k.DstIP,
		DstIP:    k.SrcIP,
		SrcPort:  k.DstPort,
		DstPort:  k.SrcPort,
	}
}

// ============================================================================
// Connection Entry - Full Connection State
// ============================================================================

// ConnectionEntry represents a tracked network connection with full state.
type ConnectionEntry struct {
	// Key is the normalized 5-tuple identifying this connection.
	Key ConnectionKey `json:"key"`

	// === State ===

	// State is the current connection state (maps to models.ConnectionState).
	State models.ConnectionState `json:"state"`

	// TCPState is the detailed TCP state machine state (TCP only).
	TCPState TCPState `json:"tcp_state,omitempty"`

	// PreviousState stores the last state for transition tracking.
	PreviousState models.ConnectionState `json:"previous_state,omitempty"`

	// === Timestamps ===

	// CreatedAt is when the connection was first seen.
	CreatedAt time.Time `json:"created_at"`

	// LastSeen is when the last packet was seen.
	LastSeen time.Time `json:"last_seen"`

	// StateChangedAt is when the state last changed.
	StateChangedAt time.Time `json:"state_changed_at,omitempty"`

	// ExpiresAt is when the connection will expire if no packets seen.
	ExpiresAt time.Time `json:"expires_at"`

	// === Counters (atomic for thread-safety) ===

	// PacketsForward is packets in the original direction.
	PacketsForward atomic.Uint64 `json:"-"`

	// PacketsReverse is packets in the reverse direction.
	PacketsReverse atomic.Uint64 `json:"-"`

	// BytesForward is bytes in the original direction.
	BytesForward atomic.Uint64 `json:"-"`

	// BytesReverse is bytes in the reverse direction.
	BytesReverse atomic.Uint64 `json:"-"`

	// === JSON Exports (populated on serialization) ===

	PacketsForwardJSON uint64 `json:"packets_forward"`
	PacketsReverseJSON uint64 `json:"packets_reverse"`
	BytesForwardJSON   uint64 `json:"bytes_forward"`
	BytesReverseJSON   uint64 `json:"bytes_reverse"`

	// === TCP-Specific ===

	// OriginalSrcIP stores the initiator's IP (before normalization).
	OriginalSrcIP string `json:"original_src_ip,omitempty"`

	// OriginalDstIP stores the responder's IP (before normalization).
	OriginalDstIP string `json:"original_dst_ip,omitempty"`

	// SeqNumber tracks the last sequence number seen.
	SeqNumber uint32 `json:"seq_number,omitempty"`

	// AckNumber tracks the last acknowledgment number seen.
	AckNumber uint32 `json:"ack_number,omitempty"`

	// === Metadata ===

	// Domain is the extracted domain name (from DNS/SNI).
	Domain string `json:"domain,omitempty"`

	// DomainSource indicates how the domain was extracted.
	DomainSource models.DomainSource `json:"domain_source,omitempty"`

	// SourceZone is the security zone of the initiator.
	SourceZone string `json:"source_zone,omitempty"`

	// DestZone is the security zone of the responder.
	DestZone string `json:"dest_zone,omitempty"`

	// CachedVerdict stores the firewall verdict for this connection.
	CachedVerdict *models.VerdictResult `json:"cached_verdict,omitempty"`

	// === Internal ===

	// mu protects non-atomic fields during updates.
	mu sync.RWMutex `json:"-"`

	// marked indicates this entry is marked for deletion.
	marked atomic.Bool `json:"-"`
}

// NewConnectionEntry creates a new connection entry from a packet.
func NewConnectionEntry(pkt *models.PacketMetadata, timeout time.Duration) *ConnectionEntry {
	now := time.Now()

	entry := &ConnectionEntry{
		Key:            NewConnectionKey(pkt),
		State:          models.StateNew,
		TCPState:       TCPStateNew,
		CreatedAt:      now,
		LastSeen:       now,
		StateChangedAt: now,
		ExpiresAt:      now.Add(timeout),
		OriginalSrcIP:  pkt.SrcIP,
		OriginalDstIP:  pkt.DstIP,
		Domain:         pkt.Domain,
		DomainSource:   pkt.DomainSource,
		SourceZone:     pkt.SourceZone,
		DestZone:       pkt.DestinationZone,
	}

	// Initialize first packet in forward direction
	entry.PacketsForward.Store(1)
	entry.BytesForward.Store(uint64(pkt.PacketSize))

	// Set initial TCP state if TCP
	if pkt.Protocol == models.ProtocolTCP {
		if pkt.IsSYN && !pkt.IsACK {
			entry.TCPState = TCPStateSYNSent
		}
	}

	return entry
}

// IsExpired checks if the connection has timed out.
func (e *ConnectionEntry) IsExpired() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Now().After(e.ExpiresAt)
}

// IsMarkedForDeletion checks if the entry is marked for removal.
func (e *ConnectionEntry) IsMarkedForDeletion() bool {
	return e.marked.Load()
}

// MarkForDeletion marks this entry for removal.
func (e *ConnectionEntry) MarkForDeletion() {
	e.marked.Store(true)
}

// Touch updates the last seen time and extends expiration.
func (e *ConnectionEntry) Touch(timeout time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.LastSeen = now
	e.ExpiresAt = now.Add(timeout)
}

// UpdateState changes the connection state.
func (e *ConnectionEntry) UpdateState(newState models.ConnectionState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.State != newState {
		e.PreviousState = e.State
		e.State = newState
		e.StateChangedAt = time.Now()
	}
}

// UpdateTCPState changes the TCP state machine state.
func (e *ConnectionEntry) UpdateTCPState(newState TCPState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.TCPState = newState
}

// AddPacket records a packet passing through this connection.
func (e *ConnectionEntry) AddPacket(pkt *models.PacketMetadata, isForward bool, timeout time.Duration) {
	if isForward {
		e.PacketsForward.Add(1)
		e.BytesForward.Add(uint64(pkt.PacketSize))
	} else {
		e.PacketsReverse.Add(1)
		e.BytesReverse.Add(uint64(pkt.PacketSize))
	}
	e.Touch(timeout)

	// Update domain if we didn't have one
	if pkt.Domain != "" {
		e.mu.Lock()
		if e.Domain == "" {
			e.Domain = pkt.Domain
			e.DomainSource = pkt.DomainSource
		}
		e.mu.Unlock()
	}
}

// IsForwardDirection determines if a packet is in the forward direction.
func (e *ConnectionEntry) IsForwardDirection(pkt *models.PacketMetadata) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return pkt.SrcIP == e.OriginalSrcIP && pkt.DstIP == e.OriginalDstIP
}

// GetStats returns connection statistics.
func (e *ConnectionEntry) GetStats() ConnectionStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return ConnectionStats{
		Key:            e.Key.String(),
		State:          e.State.String(),
		TCPState:       e.TCPState.String(),
		PacketsForward: e.PacketsForward.Load(),
		PacketsReverse: e.PacketsReverse.Load(),
		BytesForward:   e.BytesForward.Load(),
		BytesReverse:   e.BytesReverse.Load(),
		Duration:       time.Since(e.CreatedAt),
		IdleTime:       time.Since(e.LastSeen),
	}
}

// PrepareForJSON populates JSON export fields.
func (e *ConnectionEntry) PrepareForJSON() {
	e.PacketsForwardJSON = e.PacketsForward.Load()
	e.PacketsReverseJSON = e.PacketsReverse.Load()
	e.BytesForwardJSON = e.BytesForward.Load()
	e.BytesReverseJSON = e.BytesReverse.Load()
}

// SetCachedVerdict stores a verdict for fast-lane processing.
func (e *ConnectionEntry) SetCachedVerdict(verdict *models.VerdictResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.CachedVerdict = verdict
}

// GetCachedVerdict returns the cached verdict.
func (e *ConnectionEntry) GetCachedVerdict() *models.VerdictResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.CachedVerdict
}

// ============================================================================
// Connection Statistics
// ============================================================================

// ConnectionStats contains aggregated connection statistics.
type ConnectionStats struct {
	Key            string        `json:"key"`
	State          string        `json:"state"`
	TCPState       string        `json:"tcp_state,omitempty"`
	PacketsForward uint64        `json:"packets_forward"`
	PacketsReverse uint64        `json:"packets_reverse"`
	BytesForward   uint64        `json:"bytes_forward"`
	BytesReverse   uint64        `json:"bytes_reverse"`
	Duration       time.Duration `json:"duration"`
	IdleTime       time.Duration `json:"idle_time"`
}

// TotalPackets returns total packets in both directions.
func (s ConnectionStats) TotalPackets() uint64 {
	return s.PacketsForward + s.PacketsReverse
}

// TotalBytes returns total bytes in both directions.
func (s ConnectionStats) TotalBytes() uint64 {
	return s.BytesForward + s.BytesReverse
}

// ============================================================================
// Tracker Configuration
// ============================================================================

// TrackerConfig contains configuration for the connection tracker.
type TrackerConfig struct {
	// MaxConnections is the maximum number of tracked connections.
	MaxConnections int `json:"max_connections" toml:"max_connections"`

	// DefaultTCPTimeout is the timeout for established TCP connections.
	DefaultTCPTimeout time.Duration `json:"default_tcp_timeout" toml:"default_tcp_timeout"`

	// DefaultUDPTimeout is the timeout for UDP connections.
	DefaultUDPTimeout time.Duration `json:"default_udp_timeout" toml:"default_udp_timeout"`

	// DefaultICMPTimeout is the timeout for ICMP connections.
	DefaultICMPTimeout time.Duration `json:"default_icmp_timeout" toml:"default_icmp_timeout"`

	// TCPSYNTimeout is the timeout for TCP connections in SYN_SENT state.
	TCPSYNTimeout time.Duration `json:"tcp_syn_timeout" toml:"tcp_syn_timeout"`

	// TCPTimeWaitTimeout is the timeout for TCP TIME_WAIT state (2×MSL).
	TCPTimeWaitTimeout time.Duration `json:"tcp_time_wait_timeout" toml:"tcp_time_wait_timeout"`

	// CleanupInterval is how often to run the cleanup routine.
	CleanupInterval time.Duration `json:"cleanup_interval" toml:"cleanup_interval"`

	// EnableStatistics enables detailed statistics collection.
	EnableStatistics bool `json:"enable_statistics" toml:"enable_statistics"`
}

// DefaultTrackerConfig returns the default tracker configuration.
func DefaultTrackerConfig() *TrackerConfig {
	return &TrackerConfig{
		MaxConnections:     1000000,            // 1 million connections
		DefaultTCPTimeout:  3600 * time.Second, // 1 hour
		DefaultUDPTimeout:  60 * time.Second,   // 1 minute
		DefaultICMPTimeout: 30 * time.Second,   // 30 seconds
		TCPSYNTimeout:      30 * time.Second,   // 30 seconds
		TCPTimeWaitTimeout: 120 * time.Second,  // 2 minutes (2×MSL)
		CleanupInterval:    30 * time.Second,   // 30 seconds
		EnableStatistics:   true,
	}
}

// Validate checks the configuration for errors.
func (c *TrackerConfig) Validate() error {
	if c.MaxConnections < 100 {
		return fmt.Errorf("max_connections must be >= 100, got %d", c.MaxConnections)
	}
	if c.DefaultTCPTimeout < time.Second {
		return fmt.Errorf("default_tcp_timeout must be >= 1s")
	}
	if c.DefaultUDPTimeout < time.Second {
		return fmt.Errorf("default_udp_timeout must be >= 1s")
	}
	if c.DefaultICMPTimeout < time.Second {
		return fmt.Errorf("default_icmp_timeout must be >= 1s")
	}
	if c.CleanupInterval < time.Second {
		return fmt.Errorf("cleanup_interval must be >= 1s")
	}
	return nil
}

// GetTimeout returns the appropriate timeout for a protocol and state.
func (c *TrackerConfig) GetTimeout(protocol models.Protocol, tcpState TCPState) time.Duration {
	switch protocol {
	case models.ProtocolTCP:
		switch tcpState {
		case TCPStateNew, TCPStateSYNSent, TCPStateSYNReceived:
			return c.TCPSYNTimeout
		case TCPStateTimeWait:
			return c.TCPTimeWaitTimeout
		default:
			return c.DefaultTCPTimeout
		}
	case models.ProtocolUDP:
		return c.DefaultUDPTimeout
	case models.ProtocolICMP, models.ProtocolICMPv6:
		return c.DefaultICMPTimeout
	default:
		return c.DefaultUDPTimeout
	}
}

// ============================================================================
// Tracker Interface
// ============================================================================

// ConnectionTracker defines the interface for connection tracking.
type ConnectionTracker interface {
	// Track processes a packet and returns the connection entry.
	// Creates a new entry if this is the first packet of a connection.
	Track(pkt *models.PacketMetadata) (*ConnectionEntry, error)

	// Lookup finds an existing connection by key.
	Lookup(key ConnectionKey) (*ConnectionEntry, bool)

	// LookupByPacket finds a connection for the given packet.
	LookupByPacket(pkt *models.PacketMetadata) (*ConnectionEntry, bool)

	// Delete removes a connection from tracking.
	Delete(key ConnectionKey) bool

	// Count returns the number of tracked connections.
	Count() int

	// GetStats returns tracker statistics.
	GetStats() TrackerStats

	// Cleanup removes expired connections.
	Cleanup() int

	// Close shuts down the tracker.
	Close() error
}

// TrackerStats contains connection tracker statistics.
type TrackerStats struct {
	ActiveConnections   int64  `json:"active_connections"`
	TotalTracked        uint64 `json:"total_tracked"`
	TotalExpired        uint64 `json:"total_expired"`
	TotalDeleted        uint64 `json:"total_deleted"`
	TCPConnections      int64  `json:"tcp_connections"`
	UDPConnections      int64  `json:"udp_connections"`
	ICMPConnections     int64  `json:"icmp_connections"`
	StateNew            int64  `json:"state_new"`
	StateEstablished    int64  `json:"state_established"`
	StateClosing        int64  `json:"state_closing"`
	LastCleanupDuration int64  `json:"last_cleanup_duration_ns"`
}
