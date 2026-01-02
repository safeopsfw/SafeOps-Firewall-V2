// Package models defines core data structures for TLS Proxy packet handling.
package models

import (
	"time"
)

// =============================================================================
// DIRECTION CONSTANTS
// =============================================================================

const (
	// DirectionOutbound indicates LAN to WAN traffic
	DirectionOutbound = "OUTBOUND"
	// DirectionInbound indicates WAN to LAN traffic
	DirectionInbound = "INBOUND"
)

// =============================================================================
// PROTOCOL CONSTANTS
// =============================================================================

const (
	// ProtocolTCP represents TCP transport protocol
	ProtocolTCP = "TCP"
	// ProtocolUDP represents UDP transport protocol
	ProtocolUDP = "UDP"
	// ProtocolICMP represents ICMP control protocol
	ProtocolICMP = "ICMP"
)

// =============================================================================
// PROCESSING STATE CONSTANTS
// =============================================================================

const (
	// StatePending indicates packet waiting for processing
	StatePending = "PENDING"
	// StateDNSResolving indicates DNS query in progress
	StateDNSResolving = "DNS_RESOLVING"
	// StateResolved indicates DNS resolution completed
	StateResolved = "RESOLVED"
	// StateForwarding indicates packet being forwarded
	StateForwarding = "FORWARDING"
	// StateCompleted indicates processing finished successfully
	StateCompleted = "COMPLETED"
	// StateFailed indicates processing failed
	StateFailed = "FAILED"
)

// =============================================================================
// ACTION CONSTANTS (Phase 1)
// =============================================================================

const (
	// ActionForwardUnchanged indicates pass-through mode (Phase 1 only)
	ActionForwardUnchanged = "FORWARD_UNCHANGED"
	// ActionForwardModified indicates packet was modified (Phase 2+)
	ActionForwardModified = "FORWARD_MODIFIED"
	// ActionDrop indicates packet should be dropped (Phase 2+)
	ActionDrop = "DROP"
)

// =============================================================================
// CONNECTION STATE CONSTANTS
// =============================================================================

const (
	// ConnectionNew indicates first packet seen
	ConnectionNew = "NEW"
	// ConnectionEstablished indicates active connection
	ConnectionEstablished = "ESTABLISHED"
	// ConnectionClosing indicates connection teardown in progress
	ConnectionClosing = "CLOSING"
	// ConnectionClosed indicates connection terminated
	ConnectionClosed = "CLOSED"
)

// =============================================================================
// PACKET STRUCTURE
// =============================================================================

// Packet represents a single intercepted network packet from NIC Management.
// Fields mirror the tls_proxy.proto InterceptPacketRequest message.
type Packet struct {
	// ConnectionID links related packets from the same TCP/UDP flow
	// Format: "192.168.1.100:54321->93.184.216.34:443"
	ConnectionID string

	// SourceIP is the originating device IP address
	SourceIP string

	// DestinationIP is the target server IP address
	DestinationIP string

	// SourcePort is the source (client) connection port
	SourcePort int

	// DestinationPort is the destination (server) connection port
	DestinationPort int

	// Protocol is the transport protocol ("TCP", "UDP", "ICMP")
	Protocol string

	// Direction indicates packet flow: "OUTBOUND" or "INBOUND"
	Direction string

	// RawData contains the complete packet payload
	RawData []byte

	// Timestamp is when packet was intercepted by NIC Management
	Timestamp time.Time

	// InterfaceName is the network interface where packet was captured
	InterfaceName string
}

// IsHTTPS returns true if this packet is HTTPS traffic (port 443).
func (p *Packet) IsHTTPS() bool {
	return p.DestinationPort == 443
}

// IsOutbound returns true if packet direction is outbound (LAN to WAN).
func (p *Packet) IsOutbound() bool {
	return p.Direction == DirectionOutbound
}

// IsInbound returns true if packet direction is inbound (WAN to LAN).
func (p *Packet) IsInbound() bool {
	return p.Direction == DirectionInbound
}

// IsTCP returns true if packet uses TCP protocol.
func (p *Packet) IsTCP() bool {
	return p.Protocol == ProtocolTCP
}

// GetSize returns the length of the raw packet data.
func (p *Packet) GetSize() int {
	return len(p.RawData)
}

// =============================================================================
// BUFFER ENTRY STRUCTURE
// =============================================================================

// BufferEntry represents a packet stored in the buffer awaiting processing.
type BufferEntry struct {
	// Packet contains all original packet data
	Packet Packet

	// SNI is the extracted Server Name Indication domain
	// Empty if not HTTPS or extraction failed
	SNI string

	// ResolvedIP is the IP address resolved from DNS query for SNI
	// Empty if DNS resolution failed or not yet performed
	ResolvedIP string

	// BufferTimestamp is when packet was added to buffer
	BufferTimestamp time.Time

	// ExpiresAt is when this entry should be evicted if not processed
	ExpiresAt time.Time

	// ProcessingState indicates current processing stage
	ProcessingState string

	// ErrorMessage contains error description if processing failed
	ErrorMessage string
}

// IsExpired returns true if the buffer entry has exceeded its TTL.
func (be *BufferEntry) IsExpired() bool {
	return time.Now().After(be.ExpiresAt)
}

// HasSNI returns true if SNI was successfully extracted.
func (be *BufferEntry) HasSNI() bool {
	return be.SNI != ""
}

// HasResolvedIP returns true if DNS resolution completed successfully.
func (be *BufferEntry) HasResolvedIP() bool {
	return be.ResolvedIP != ""
}

// SetError marks the entry as failed with the given error.
func (be *BufferEntry) SetError(err error) {
	be.ProcessingState = StateFailed
	if err != nil {
		be.ErrorMessage = err.Error()
	}
}

// SetPending sets the processing state to pending.
func (be *BufferEntry) SetPending() {
	be.ProcessingState = StatePending
}

// SetDNSResolving sets the processing state to DNS resolving.
func (be *BufferEntry) SetDNSResolving() {
	be.ProcessingState = StateDNSResolving
}

// SetResolved sets the processing state to resolved.
func (be *BufferEntry) SetResolved() {
	be.ProcessingState = StateResolved
}

// SetCompleted sets the processing state to completed.
func (be *BufferEntry) SetCompleted() {
	be.ProcessingState = StateCompleted
}

// =============================================================================
// PROCESSING RESULT STRUCTURE
// =============================================================================

// ProcessingResult indicates what action should be taken with a packet.
// Phase 1: Only FORWARD_UNCHANGED is used (pass-through mode).
type ProcessingResult struct {
	// Action indicates the forwarding decision
	// Phase 1: Always "FORWARD_UNCHANGED"
	Action string

	// ModifiedPacket contains modified packet data
	// Phase 1: Always nil (no modification)
	ModifiedPacket []byte

	// DropReason explains why packet was dropped
	// Phase 1: Always empty (no dropping)
	DropReason string

	// ProcessingDuration is how long processing took
	ProcessingDuration time.Duration

	// SNIHostname is the extracted SNI (for response enrichment)
	SNIHostname string

	// ResolvedIP is the DNS-resolved IP (for response enrichment)
	ResolvedIP string
}

// IsForward returns true if the action is to forward the packet.
func (pr *ProcessingResult) IsForward() bool {
	return pr.Action == ActionForwardUnchanged || pr.Action == ActionForwardModified
}

// IsDrop returns true if the action is to drop the packet.
func (pr *ProcessingResult) IsDrop() bool {
	return pr.Action == ActionDrop
}

// =============================================================================
// CONNECTION STATE STRUCTURE
// =============================================================================

// ConnectionState tracks active TCP/UDP connections across multiple packets.
type ConnectionState struct {
	// ConnectionID matches the Packet.ConnectionID format
	ConnectionID string

	// FirstSeen is when first packet of this connection was observed
	FirstSeen time.Time

	// LastSeen is when most recent packet was observed
	LastSeen time.Time

	// PacketCount is total packets seen for this connection
	PacketCount int

	// SNI is cached from first extraction (avoids redundant processing)
	SNI string

	// State indicates connection lifecycle stage
	State string
}

// UpdateLastSeen updates the last seen timestamp and increments packet count.
func (cs *ConnectionState) UpdateLastSeen() {
	cs.LastSeen = time.Now()
	cs.PacketCount++
}

// GetDuration returns the time between first and last seen packets.
func (cs *ConnectionState) GetDuration() time.Duration {
	return cs.LastSeen.Sub(cs.FirstSeen)
}

// IsNew returns true if this is a new connection.
func (cs *ConnectionState) IsNew() bool {
	return cs.State == ConnectionNew
}

// IsEstablished returns true if connection is established.
func (cs *ConnectionState) IsEstablished() bool {
	return cs.State == ConnectionEstablished
}

// HasCachedSNI returns true if SNI has been cached for this connection.
func (cs *ConnectionState) HasCachedSNI() bool {
	return cs.SNI != ""
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

// NewBufferEntry creates a new buffer entry for the given packet.
func NewBufferEntry(packet Packet, ttl time.Duration) *BufferEntry {
	now := time.Now()
	return &BufferEntry{
		Packet:          packet,
		BufferTimestamp: now,
		ExpiresAt:       now.Add(ttl),
		ProcessingState: StatePending,
	}
}

// NewConnectionState creates a new connection state for tracking.
func NewConnectionState(connectionID string) *ConnectionState {
	now := time.Now()
	return &ConnectionState{
		ConnectionID: connectionID,
		FirstSeen:    now,
		LastSeen:     now,
		PacketCount:  1,
		State:        ConnectionNew,
	}
}

// NewProcessingResult creates a Phase 1 pass-through result.
func NewProcessingResult(duration time.Duration) *ProcessingResult {
	return &ProcessingResult{
		Action:             ActionForwardUnchanged,
		ProcessingDuration: duration,
	}
}
