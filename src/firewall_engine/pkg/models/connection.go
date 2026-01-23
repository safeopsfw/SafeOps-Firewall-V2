// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Connection State Types
// ============================================================================

// ConnectionState represents the current state of a network connection.
// Used for stateful packet inspection and connection tracking.
type ConnectionState int8

const (
	// StateNew indicates the first packet of a new connection.
	// For TCP: SYN packet received
	// For UDP/ICMP: First packet in this 5-tuple
	StateNew ConnectionState = 0

	// StateEstablished indicates an active, established connection.
	// For TCP: 3-way handshake completed (SYN, SYN-ACK, ACK)
	// For UDP: Reply received from server
	StateEstablished ConnectionState = 1

	// StateRelated indicates traffic related to an existing connection.
	// Examples: ICMP error messages, FTP data connections
	StateRelated ConnectionState = 2

	// StateClosing indicates the connection is being torn down.
	// For TCP: FIN or FIN-ACK received, waiting for final ACK
	StateClosing ConnectionState = 3

	// StateClosed indicates the connection has been terminated.
	// Ready for cleanup from the connection table.
	StateClosed ConnectionState = 4

	// StateInvalid indicates an invalid packet that doesn't match state machine.
	// Examples: ACK without prior SYN, malformed packets
	StateInvalid ConnectionState = 5

	// StateTimeWait is the TIME_WAIT state for TCP connections.
	// Waiting for 2*MSL before removing from connection table.
	StateTimeWait ConnectionState = 6

	// StateSYNSent indicates a SYN has been sent, waiting for SYN-ACK.
	StateSYNSent ConnectionState = 7

	// StateSYNReceived indicates SYN-ACK received, waiting for final ACK.
	StateSYNReceived ConnectionState = 8
)

// connectionStateNames maps connection state values to strings.
var connectionStateNames = map[ConnectionState]string{
	StateNew:         "NEW",
	StateEstablished: "ESTABLISHED",
	StateRelated:     "RELATED",
	StateClosing:     "CLOSING",
	StateClosed:      "CLOSED",
	StateInvalid:     "INVALID",
	StateTimeWait:    "TIME_WAIT",
	StateSYNSent:     "SYN_SENT",
	StateSYNReceived: "SYN_RECEIVED",
}

// connectionStateValues maps strings to connection state values.
var connectionStateValues = map[string]ConnectionState{
	"NEW":          StateNew,
	"ESTABLISHED":  StateEstablished,
	"RELATED":      StateRelated,
	"CLOSING":      StateClosing,
	"CLOSED":       StateClosed,
	"INVALID":      StateInvalid,
	"TIME_WAIT":    StateTimeWait,
	"SYN_SENT":     StateSYNSent,
	"SYN_RECEIVED": StateSYNReceived,
}

// String returns the human-readable name of the connection state.
func (cs ConnectionState) String() string {
	if name, ok := connectionStateNames[cs]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", cs)
}

// IsValid checks if the connection state is a recognized value.
func (cs ConnectionState) IsValid() bool {
	_, ok := connectionStateNames[cs]
	return ok
}

// IsActive returns true if the connection is still active (not closed/invalid).
func (cs ConnectionState) IsActive() bool {
	switch cs {
	case StateNew, StateEstablished, StateRelated, StateSYNSent, StateSYNReceived:
		return true
	default:
		return false
	}
}

// Matches checks if this state matches a list of allowed states.
func (cs ConnectionState) Matches(allowed []ConnectionState) bool {
	if len(allowed) == 0 {
		return true // No restriction
	}
	for _, a := range allowed {
		if cs == a {
			return true
		}
	}
	return false
}

// ConnectionStateFromString parses a string into a ConnectionState.
func ConnectionStateFromString(s string) (ConnectionState, error) {
	if v, ok := connectionStateValues[s]; ok {
		return v, nil
	}
	return StateNew, fmt.Errorf("unknown connection state: %q", s)
}

// ParseConnectionStates parses a comma-separated list of states.
// Example: "NEW,ESTABLISHED" parses to []ConnectionState{StateNew, StateEstablished}
func ParseConnectionStates(s string) ([]ConnectionState, error) {
	if s == "" {
		return nil, nil
	}
	var states []ConnectionState
	for _, part := range splitAndTrim(s, ",") {
		if part == "" {
			continue
		}
		state, err := ConnectionStateFromString(part)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, nil
}

// MarshalJSON implements json.Marshaler.
func (cs ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(cs.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (cs *ConnectionState) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ConnectionStateFromString(s)
	if err != nil {
		return err
	}
	*cs = parsed
	return nil
}

// ============================================================================
// Connection Info - Core connection tracking structure
// ============================================================================

// ConnectionInfo represents tracking information for a single network connection.
// Used for stateful packet inspection and connection table management.
type ConnectionInfo struct {
	// Connection identification
	mu sync.RWMutex `json:"-"` // Protects concurrent access

	// ID is a unique identifier for this connection (hash of 5-tuple).
	ID string `json:"id"`

	// Protocol is the IP protocol (TCP, UDP, ICMP).
	Protocol Protocol `json:"protocol"`

	// Source information
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`

	// Destination information
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`

	// State tracking
	State         ConnectionState `json:"state"`
	PreviousState ConnectionState `json:"previous_state,omitempty"`

	// Timestamps
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	StateChanged time.Time `json:"state_changed,omitempty"`

	// Counters (using atomic for thread-safe updates)
	PacketCount     atomic.Uint64 `json:"-"`
	ByteCount       atomic.Uint64 `json:"-"`
	PacketCountJSON uint64        `json:"packet_count"`
	ByteCountJSON   uint64        `json:"byte_count"`

	// Direction counters
	InboundPackets  atomic.Uint64 `json:"-"`
	OutboundPackets atomic.Uint64 `json:"-"`
	InboundBytes    atomic.Uint64 `json:"-"`
	OutboundBytes   atomic.Uint64 `json:"-"`

	// TCP-specific state tracking
	TCPState *TCPConnectionState `json:"tcp_state,omitempty"`

	// Timeout configuration
	TimeoutSeconds int `json:"timeout_seconds"`

	// Associated metadata
	Domain       string       `json:"domain,omitempty"`
	DomainSource DomainSource `json:"domain_source,omitempty"`

	// Zone information
	SourceZone      string `json:"source_zone,omitempty"`
	DestinationZone string `json:"destination_zone,omitempty"`

	// Cached verdict for fast-lane processing
	CachedVerdict    *VerdictResult `json:"cached_verdict,omitempty"`
	VerdictCacheTime time.Time      `json:"verdict_cache_time,omitempty"`

	// Adapter information
	InboundAdapter  string `json:"inbound_adapter,omitempty"`
	OutboundAdapter string `json:"outbound_adapter,omitempty"`

	// Flags
	IsNAT        bool `json:"is_nat,omitempty"`
	IsTracked    bool `json:"is_tracked"`
	MarkedForDel bool `json:"marked_for_del,omitempty"`
}

// TCPConnectionState tracks the TCP state machine for a connection.
type TCPConnectionState struct {
	// Sequence numbers
	ClientISN uint32 `json:"client_isn,omitempty"`
	ServerISN uint32 `json:"server_isn,omitempty"`

	// Window sizes
	ClientWindow uint16 `json:"client_window,omitempty"`
	ServerWindow uint16 `json:"server_window,omitempty"`

	// Handshake tracking
	SYNSent     bool      `json:"syn_sent"`
	SYNACKSent  bool      `json:"syn_ack_sent"`
	ACKSent     bool      `json:"ack_sent"`
	HandshakeAt time.Time `json:"handshake_at,omitempty"`

	// Teardown tracking
	ClientFIN   bool      `json:"client_fin,omitempty"`
	ServerFIN   bool      `json:"server_fin,omitempty"`
	TeardownAt  time.Time `json:"teardown_at,omitempty"`
	TimeWaitEnd time.Time `json:"time_wait_end,omitempty"`
}

// Default timeout values in seconds.
const (
	DefaultTCPTimeout  = 3600 // 1 hour for established TCP
	DefaultUDPTimeout  = 180  // 3 minutes for UDP
	DefaultICMPTimeout = 30   // 30 seconds for ICMP
	TimeWaitDuration   = 120  // 2 minutes for TIME_WAIT (2*MSL)
)

// NewConnectionInfo creates a new connection info from packet metadata.
func NewConnectionInfo(pkt *PacketMetadata) *ConnectionInfo {
	now := time.Now()

	conn := &ConnectionInfo{
		Protocol:       pkt.Protocol,
		SrcIP:          pkt.SrcIP,
		SrcPort:        pkt.SrcPort,
		DstIP:          pkt.DstIP,
		DstPort:        pkt.DstPort,
		State:          StateNew,
		FirstSeen:      now,
		LastSeen:       now,
		StateChanged:   now,
		TimeoutSeconds: getDefaultTimeout(pkt.Protocol),
		Domain:         pkt.Domain,
		DomainSource:   pkt.DomainSource,
		SourceZone:     pkt.SourceZone,
		IsTracked:      true,
	}

	// Generate connection ID
	conn.ID = conn.generateID()

	// Initialize TCP state if needed
	if pkt.Protocol == ProtocolTCP {
		conn.TCPState = &TCPConnectionState{}
		if pkt.IsSYN && !pkt.IsACK {
			conn.TCPState.SYNSent = true
			conn.State = StateSYNSent
		}
	}

	// Initialize counters
	conn.PacketCount.Store(1)
	conn.ByteCount.Store(uint64(pkt.PacketSize))

	if pkt.Direction == DirectionInbound {
		conn.InboundPackets.Store(1)
		conn.InboundBytes.Store(uint64(pkt.PacketSize))
		conn.InboundAdapter = pkt.AdapterName
	} else {
		conn.OutboundPackets.Store(1)
		conn.OutboundBytes.Store(uint64(pkt.PacketSize))
		conn.OutboundAdapter = pkt.AdapterName
	}

	return conn
}

// generateID creates a unique ID for this connection based on 5-tuple.
func (c *ConnectionInfo) generateID() string {
	// Create a normalized key (lower IP:port first for bidirectional matching)
	var key string
	if c.SrcIP < c.DstIP || (c.SrcIP == c.DstIP && c.SrcPort < c.DstPort) {
		key = fmt.Sprintf("%d:%s:%d:%s:%d", c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
	} else {
		key = fmt.Sprintf("%d:%s:%d:%s:%d", c.Protocol, c.DstIP, c.DstPort, c.SrcIP, c.SrcPort)
	}

	// Hash for consistent length ID
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:8]) // First 16 hex chars
}

// getDefaultTimeout returns the default timeout for a protocol.
func getDefaultTimeout(proto Protocol) int {
	switch proto {
	case ProtocolTCP:
		return DefaultTCPTimeout
	case ProtocolUDP:
		return DefaultUDPTimeout
	case ProtocolICMP, ProtocolICMPv6:
		return DefaultICMPTimeout
	default:
		return DefaultUDPTimeout
	}
}

// Update updates the connection with new packet information.
// Returns the new connection state.
func (c *ConnectionInfo) Update(pkt *PacketMetadata) ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.LastSeen = time.Now()

	// Update counters
	c.PacketCount.Add(1)
	c.ByteCount.Add(uint64(pkt.PacketSize))

	if pkt.Direction == DirectionInbound {
		c.InboundPackets.Add(1)
		c.InboundBytes.Add(uint64(pkt.PacketSize))
	} else {
		c.OutboundPackets.Add(1)
		c.OutboundBytes.Add(uint64(pkt.PacketSize))
	}

	// Update domain if found
	if pkt.Domain != "" && c.Domain == "" {
		c.Domain = pkt.Domain
		c.DomainSource = pkt.DomainSource
	}

	// Update TCP state machine
	if c.Protocol == ProtocolTCP && c.TCPState != nil {
		c.updateTCPState(pkt)
	} else if c.Protocol == ProtocolUDP {
		c.updateUDPState(pkt)
	}

	return c.State
}

// updateTCPState updates the TCP connection state based on flags.
func (c *ConnectionInfo) updateTCPState(pkt *PacketMetadata) {
	previousState := c.State

	switch c.State {
	case StateNew, StateSYNSent:
		if pkt.IsSYN && !pkt.IsACK {
			c.TCPState.SYNSent = true
			c.State = StateSYNSent
		} else if pkt.IsSYN && pkt.IsACK {
			c.TCPState.SYNACKSent = true
			c.State = StateSYNReceived
		}

	case StateSYNReceived:
		if pkt.IsACK && !pkt.IsSYN && !pkt.IsFIN && !pkt.IsRST {
			c.TCPState.ACKSent = true
			c.TCPState.HandshakeAt = time.Now()
			c.State = StateEstablished
		}

	case StateEstablished:
		if pkt.IsFIN {
			if pkt.Direction == DirectionOutbound {
				c.TCPState.ClientFIN = true
			} else {
				c.TCPState.ServerFIN = true
			}
			c.State = StateClosing
			c.TCPState.TeardownAt = time.Now()
		}

	case StateClosing:
		if pkt.IsFIN {
			// Other side also sending FIN
			if pkt.Direction == DirectionOutbound {
				c.TCPState.ClientFIN = true
			} else {
				c.TCPState.ServerFIN = true
			}
		}
		if c.TCPState.ClientFIN && c.TCPState.ServerFIN && pkt.IsACK {
			// Both sides have sent FIN and we got final ACK
			c.State = StateTimeWait
			c.TCPState.TimeWaitEnd = time.Now().Add(time.Duration(TimeWaitDuration) * time.Second)
		}

	case StateTimeWait:
		// Still in TIME_WAIT, ignore packets
	}

	// Handle RST at any state
	if pkt.IsRST {
		c.State = StateClosed
	}

	// Track state changes
	if c.State != previousState {
		c.PreviousState = previousState
		c.StateChanged = time.Now()
	}
}

// updateUDPState updates UDP connection state (pseudo-stateful).
func (c *ConnectionInfo) updateUDPState(pkt *PacketMetadata) {
	// For UDP, we consider it established when we see bidirectional traffic
	if c.State == StateNew && c.PacketCount.Load() > 1 {
		// Check if we have traffic in both directions (using pkt direction)
		if (pkt.Direction == DirectionInbound && c.OutboundPackets.Load() > 0) ||
			(pkt.Direction == DirectionOutbound && c.InboundPackets.Load() > 0) {
			// Reply received, consider established
			c.State = StateEstablished
			c.StateChanged = time.Now()
		}
	}
}

// IsExpired checks if the connection has timed out.
func (c *ConnectionInfo) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check TIME_WAIT expiration
	if c.State == StateTimeWait && c.TCPState != nil {
		return time.Now().After(c.TCPState.TimeWaitEnd)
	}

	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	return time.Since(c.LastSeen) > timeout
}

// MatchesPacket checks if a packet belongs to this connection.
func (c *ConnectionInfo) MatchesPacket(pkt *PacketMetadata) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Protocol != pkt.Protocol {
		return false
	}

	// Check forward direction
	if c.SrcIP == pkt.SrcIP && c.DstIP == pkt.DstIP &&
		c.SrcPort == pkt.SrcPort && c.DstPort == pkt.DstPort {
		return true
	}

	// Check reverse direction
	if c.SrcIP == pkt.DstIP && c.DstIP == pkt.SrcIP &&
		c.SrcPort == pkt.DstPort && c.DstPort == pkt.SrcPort {
		return true
	}

	return false
}

// GetStats returns current connection statistics.
func (c *ConnectionInfo) GetStats() ConnectionStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ConnectionStats{
		ID:              c.ID,
		Protocol:        c.Protocol.String(),
		State:           c.State.String(),
		Duration:        time.Since(c.FirstSeen),
		PacketCount:     c.PacketCount.Load(),
		ByteCount:       c.ByteCount.Load(),
		InboundPackets:  c.InboundPackets.Load(),
		OutboundPackets: c.OutboundPackets.Load(),
		InboundBytes:    c.InboundBytes.Load(),
		OutboundBytes:   c.OutboundBytes.Load(),
	}
}

// SetCachedVerdict stores a verdict for fast-lane processing.
func (c *ConnectionInfo) SetCachedVerdict(verdict *VerdictResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.CachedVerdict = verdict
	c.VerdictCacheTime = time.Now()
}

// GetCachedVerdict returns the cached verdict if still valid.
func (c *ConnectionInfo) GetCachedVerdict() *VerdictResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.CachedVerdict == nil {
		return nil
	}

	// Check if cache has expired
	if c.CachedVerdict.CacheTTL > 0 {
		if time.Since(c.VerdictCacheTime) > time.Duration(c.CachedVerdict.CacheTTL)*time.Second {
			return nil
		}
	}

	return c.CachedVerdict
}

// PrepareForJSON prepares the struct for JSON serialization.
func (c *ConnectionInfo) PrepareForJSON() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.PacketCountJSON = c.PacketCount.Load()
	c.ByteCountJSON = c.ByteCount.Load()
}

// ConnectionStats contains aggregated connection statistics.
type ConnectionStats struct {
	ID              string        `json:"id"`
	Protocol        string        `json:"protocol"`
	State           string        `json:"state"`
	Duration        time.Duration `json:"duration"`
	PacketCount     uint64        `json:"packet_count"`
	ByteCount       uint64        `json:"byte_count"`
	InboundPackets  uint64        `json:"inbound_packets"`
	OutboundPackets uint64        `json:"outbound_packets"`
	InboundBytes    uint64        `json:"inbound_bytes"`
	OutboundBytes   uint64        `json:"outbound_bytes"`
}

// ============================================================================
// Helper functions
// ============================================================================

// splitAndTrim splits a string and trims whitespace from each part.
func splitAndTrim(s string, sep string) []string {
	parts := make([]string, 0)
	for _, p := range splitString(s, sep) {
		trimmed := trimString(p)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitString splits a string by separator.
func splitString(s, sep string) []string {
	result := make([]string, 0)
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

// trimString trims whitespace from a string.
func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
