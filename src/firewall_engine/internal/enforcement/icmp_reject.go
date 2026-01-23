// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// ICMP Reject Handler - Polite Packet Rejection
// ============================================================================

// ICMPRejectHandler implements ICMP "Destination Unreachable" responses.
// When a REJECT verdict is issued, this handler sends an ICMP Type 3
// (Destination Unreachable) message back to the sender, politely informing
// them that the packet was rejected by policy.
//
// ICMP Message Structure:
//
//	Type: 3 (Destination Unreachable)
//	Code: 13 (Communication Administratively Prohibited - RFC 1812)
//
//	Payload includes original IP header + first 8 bytes of original data
//	(allows sender to match ICMP to original packet)
//
// ICMP Codes:
//
//	Code 0: Network unreachable
//	Code 1: Host unreachable
//	Code 3: Port unreachable
//	Code 9: Network administratively prohibited (Cisco)
//	Code 13: Communication administratively prohibited (RFC 1812)
//
// Use Cases:
//   - Enterprise policy enforcement (users know it's blocked)
//   - Debugging (faster feedback than DROP timeout)
//   - RFC compliance (polite rejection per internet standards)
//   - Transparent firewalling (users aware of filtering)
//
// Comparison:
//   - REJECT: Instant ICMP response → user knows it's blocked
//   - DROP: 30s timeout → user thinks network is down
//   - BLOCK: TCP RST → TCP only, instant "connection refused"
type ICMPRejectHandler struct {
	// Configuration
	config *ICMPRejectConfig

	// Packet injector interface
	injector PacketInjectorInterface

	// Statistics
	stats *ICMPRejectStats

	// Shutdown
	closed atomic.Bool
}

// ICMPRejectConfig contains configuration for the ICMP reject handler.
type ICMPRejectConfig struct {
	// Code is the ICMP code to use (default: 13 = admin prohibited).
	Code uint8 `json:"code" toml:"code"`

	// TTL is the IP TTL for injected ICMP packets.
	TTL uint8 `json:"ttl" toml:"ttl"`

	// IncludeOriginalData includes part of original packet in ICMP payload.
	IncludeOriginalData bool `json:"include_original_data" toml:"include_original_data"`

	// MaxOriginalDataBytes is the max bytes of original data to include.
	MaxOriginalDataBytes int `json:"max_original_data_bytes" toml:"max_original_data_bytes"`

	// IPv6Enabled enables ICMPv6 for IPv6 packets.
	IPv6Enabled bool `json:"ipv6_enabled" toml:"ipv6_enabled"`
}

// DefaultICMPRejectConfig returns the default configuration.
func DefaultICMPRejectConfig() *ICMPRejectConfig {
	return &ICMPRejectConfig{
		Code:                 13, // Administratively prohibited
		TTL:                  64,
		IncludeOriginalData:  true,
		MaxOriginalDataBytes: 8, // First 8 bytes per RFC 792
		IPv6Enabled:          true,
	}
}

// Validate checks the configuration.
func (c *ICMPRejectConfig) Validate() error {
	if c.Code > 15 {
		return fmt.Errorf("code must be 0-15, got %d", c.Code)
	}
	if c.TTL == 0 {
		return fmt.Errorf("ttl must be > 0")
	}
	if c.MaxOriginalDataBytes < 0 {
		return fmt.Errorf("max_original_data_bytes must be >= 0")
	}
	return nil
}

// ICMPRejectStats tracks ICMP reject handler statistics.
type ICMPRejectStats struct {
	RejectsAttempted atomic.Uint64
	RejectsSucceeded atomic.Uint64
	RejectsFailed    atomic.Uint64
	PacketsInjected  atomic.Uint64
	IPv4Rejects      atomic.Uint64
	IPv6Rejects      atomic.Uint64
	ProtocolMismatch atomic.Uint64
	MissingContext   atomic.Uint64
}

// PacketInjectorInterface abstracts low-level packet injection.
type PacketInjectorInterface interface {
	// SendPacket sends a raw packet via the NDIS driver.
	SendPacket(adapterHandle interface{}, packet []byte) error
}

// NewICMPRejectHandler creates a new ICMP reject handler.
func NewICMPRejectHandler(config *ICMPRejectConfig, injector PacketInjectorInterface) (*ICMPRejectHandler, error) {
	if config == nil {
		config = DefaultICMPRejectConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid icmp reject config: %w", err)
	}

	return &ICMPRejectHandler{
		config:   config,
		injector: injector,
		stats:    &ICMPRejectStats{},
	}, nil
}

// ============================================================================
// ActionHandler Interface Implementation
// ============================================================================

// Name returns the handler name.
func (h *ICMPRejectHandler) Name() string {
	return "ICMPRejectHandler"
}

// SupportedActions returns the actions this handler supports.
func (h *ICMPRejectHandler) SupportedActions() []EnforcementAction {
	return []EnforcementAction{ActionReject}
}

// CanHandle checks if this handler can process the given context.
func (h *ICMPRejectHandler) CanHandle(ctx *PacketContext) bool {
	if ctx == nil || ctx.Packet == nil {
		return false
	}

	// Can handle TCP, UDP, and other protocols (not ICMP itself)
	// ICMP packets should not trigger more ICMP responses (loop prevention)
	if ctx.Packet.Protocol == models.ProtocolICMP || ctx.Packet.Protocol == models.ProtocolICMPv6 {
		return false
	}

	// Need valid source IP to send ICMP back
	if ctx.Packet.SrcIP == "" {
		return false
	}

	return true
}

// Handle executes the ICMP reject by sending an ICMP Destination Unreachable.
func (h *ICMPRejectHandler) Handle(ctx context.Context, pktCtx *PacketContext) *EnforcementResult {
	startTime := time.Now()

	// Check if handler is closed
	if h.closed.Load() {
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(),
			fmt.Errorf("icmp reject handler is closed"), ErrCodeDisabled)
	}

	h.stats.RejectsAttempted.Add(1)

	// Validate we can handle this packet
	if !h.CanHandle(pktCtx) {
		h.stats.ProtocolMismatch.Add(1)
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(),
			fmt.Errorf("cannot send ICMP reject for this packet type"),
			ErrCodeProtocolMismatch).
			WithHandler(h.Name())
	}

	// Validate context for injection
	if err := pktCtx.ValidateForInjection(); err != nil {
		h.stats.MissingContext.Add(1)
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(), err, ErrCodeMissingContext).
			WithHandler(h.Name())
	}

	// Check if injector is available
	if h.injector == nil {
		h.stats.RejectsFailed.Add(1)
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(),
			ErrEngineNotConnected, ErrCodeEngineUnavailable).
			WithHandler(h.Name())
	}

	// Determine if IPv4 or IPv6
	isIPv6 := pktCtx.Packet.IsIPv6()

	// Check context cancellation
	select {
	case <-ctx.Done():
		h.stats.RejectsFailed.Add(1)
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(),
			ctx.Err(), ErrCodeTimeout).
			WithHandler(h.Name())
	default:
	}

	// Build and inject ICMP packet
	var err error
	if isIPv6 && h.config.IPv6Enabled {
		err = h.injectICMPv6(pktCtx)
		if err == nil {
			h.stats.IPv6Rejects.Add(1)
		}
	} else if !isIPv6 {
		err = h.injectICMPv4(pktCtx)
		if err == nil {
			h.stats.IPv4Rejects.Add(1)
		}
	} else {
		err = fmt.Errorf("IPv6 reject disabled")
	}

	if err != nil {
		h.stats.RejectsFailed.Add(1)
		return NewFailureResult(ActionReject, pktCtx.GetPacketID(),
			fmt.Errorf("ICMP injection failed: %w", err),
			ErrCodeInjectionFailed).
			WithHandler(h.Name())
	}

	h.stats.RejectsSucceeded.Add(1)
	h.stats.PacketsInjected.Add(1)

	return NewSuccessResult(ActionReject, pktCtx.GetPacketID(), time.Since(startTime)).
		WithHandler(h.Name()).
		WithMetadata("icmp_code", h.config.Code).
		WithMetadata("is_ipv6", isIPv6)
}

// ============================================================================
// ICMP Packet Building
// ============================================================================

// injectICMPv4 builds and injects an ICMPv4 Destination Unreachable message.
func (h *ICMPRejectHandler) injectICMPv4(ctx *PacketContext) error {
	// Parse IPs
	srcIP := net.ParseIP(ctx.Packet.SrcIP)
	gatewayIP := h.getGatewayIP(ctx)

	if srcIP == nil || gatewayIP == nil {
		return fmt.Errorf("invalid IP addresses")
	}

	// Build ICMP packet
	// Total size: Ethernet(14) + IP(20) + ICMP(8) + Original IP Header(20) + Original Data(8) = 70
	originalDataLen := 0
	if h.config.IncludeOriginalData && len(ctx.RawPacket) > 34 {
		originalDataLen = min(h.config.MaxOriginalDataBytes, len(ctx.RawPacket)-34)
	}

	packetSize := 14 + 20 + 8 + 20 + originalDataLen
	packet := make([]byte, packetSize)

	// === Ethernet Header (14 bytes) ===
	// Swap source and destination MAC for response
	copy(packet[0:6], ctx.SrcMAC[:])  // Dest MAC = original source
	copy(packet[6:12], ctx.DstMAC[:]) // Src MAC = our MAC
	packet[12] = 0x08                 // EtherType: IPv4
	packet[13] = 0x00

	// === IP Header (20 bytes) ===
	ipHeader := packet[14:34]
	ipHeader[0] = 0x45                                                         // Version 4, IHL 5
	ipHeader[1] = 0x00                                                         // DSCP/ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+8+20+originalDataLen)) // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)                               // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)                          // Flags: Don't Fragment
	ipHeader[8] = h.config.TTL                                                 // TTL
	ipHeader[9] = 1                                                            // Protocol: ICMP
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)                             // Checksum (calculate later)
	copy(ipHeader[12:16], gatewayIP.To4())                                     // Source IP (gateway/firewall)
	copy(ipHeader[16:20], srcIP.To4())                                         // Dest IP (original source)

	// Calculate IP checksum
	ipChecksum := h.calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// === ICMP Header (8 bytes) ===
	icmpHeader := packet[34:42]
	icmpHeader[0] = 3                              // Type: Destination Unreachable
	icmpHeader[1] = h.config.Code                  // Code: Admin Prohibited (13)
	binary.BigEndian.PutUint16(icmpHeader[2:4], 0) // Checksum (calculate later)
	binary.BigEndian.PutUint32(icmpHeader[4:8], 0) // Unused (for Type 3)

	// === ICMP Payload (Original IP Header + 8 bytes of data) ===
	icmpPayload := packet[42:]

	// Copy original IP header (20 bytes) from raw packet
	// Assuming raw packet starts with Ethernet header (14 bytes)
	if len(ctx.RawPacket) >= 34 {
		copy(icmpPayload[0:20], ctx.RawPacket[14:34])
	} else {
		// Build a minimal original header
		h.buildMinimalIPHeader(icmpPayload[0:20], ctx)
	}

	// Copy first 8 bytes of original payload (TCP/UDP header usually)
	if originalDataLen > 0 && len(ctx.RawPacket) > 34+originalDataLen {
		copy(icmpPayload[20:20+originalDataLen], ctx.RawPacket[34:34+originalDataLen])
	}

	// Calculate ICMP checksum (header + payload)
	icmpWithPayload := packet[34:packetSize]
	icmpChecksum := h.calculateChecksum(icmpWithPayload)
	binary.BigEndian.PutUint16(icmpHeader[2:4], icmpChecksum)

	// Send packet
	return h.injector.SendPacket(ctx.AdapterHandle, packet)
}

// injectICMPv6 builds and injects an ICMPv6 Destination Unreachable message.
func (h *ICMPRejectHandler) injectICMPv6(ctx *PacketContext) error {
	// ICMPv6 Type 1: Destination Unreachable
	// Code 1: Communication administratively prohibited

	srcIP := net.ParseIP(ctx.Packet.SrcIP)
	gatewayIP := h.getGatewayIP(ctx)

	if srcIP == nil || gatewayIP == nil {
		return fmt.Errorf("invalid IPv6 addresses")
	}

	// For IPv6, we need a more complex packet structure
	// Ethernet(14) + IPv6(40) + ICMPv6(8) + Original Data (as much as possible up to MTU)

	originalDataLen := 0
	if h.config.IncludeOriginalData && len(ctx.RawPacket) > 54 {
		// Include as much as possible without exceeding MTU (1280 min for IPv6)
		maxOriginal := 1280 - 14 - 40 - 8 // ~1218 bytes
		originalDataLen = min(maxOriginal, len(ctx.RawPacket)-14)
	}

	packetSize := 14 + 40 + 8 + originalDataLen
	packet := make([]byte, packetSize)

	// === Ethernet Header ===
	copy(packet[0:6], ctx.SrcMAC[:])
	copy(packet[6:12], ctx.DstMAC[:])
	packet[12] = 0x86 // EtherType: IPv6
	packet[13] = 0xDD

	// === IPv6 Header (40 bytes) ===
	ipv6Header := packet[14:54]
	ipv6Header[0] = 0x60                                                   // Version 6, Traffic Class
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(8+originalDataLen)) // Payload length
	ipv6Header[6] = 58                                                     // Next Header: ICMPv6
	ipv6Header[7] = h.config.TTL                                           // Hop Limit

	// Source and dest IPv6 addresses
	copy(ipv6Header[8:24], gatewayIP.To16())
	copy(ipv6Header[24:40], srcIP.To16())

	// === ICMPv6 Header (8 bytes) ===
	icmpv6Header := packet[54:62]
	icmpv6Header[0] = 1                              // Type: Destination Unreachable
	icmpv6Header[1] = 1                              // Code: Admin prohibited
	binary.BigEndian.PutUint16(icmpv6Header[2:4], 0) // Checksum (calculate later)
	binary.BigEndian.PutUint32(icmpv6Header[4:8], 0) // Unused

	// === ICMPv6 Payload ===
	if originalDataLen > 0 && len(ctx.RawPacket) > 14+originalDataLen {
		copy(packet[62:], ctx.RawPacket[14:14+originalDataLen])
	}

	// Calculate ICMPv6 checksum (includes pseudo-header)
	icmpv6Checksum := h.calculateICMPv6Checksum(gatewayIP, srcIP, packet[54:packetSize])
	binary.BigEndian.PutUint16(icmpv6Header[2:4], icmpv6Checksum)

	return h.injector.SendPacket(ctx.AdapterHandle, packet)
}

// ============================================================================
// Helper Methods
// ============================================================================

// getGatewayIP returns the IP to use as ICMP source (firewall/gateway IP).
func (h *ICMPRejectHandler) getGatewayIP(ctx *PacketContext) net.IP {
	// Use destination IP of original packet as the "gateway" that's sending the ICMP
	if ctx.DstIPParsed != nil {
		return ctx.DstIPParsed
	}
	return net.ParseIP(ctx.Packet.DstIP)
}

// buildMinimalIPHeader builds a minimal IP header when raw packet isn't available.
func (h *ICMPRejectHandler) buildMinimalIPHeader(header []byte, ctx *PacketContext) {
	if len(header) < 20 {
		return
	}

	srcIP := net.ParseIP(ctx.Packet.SrcIP)
	dstIP := net.ParseIP(ctx.Packet.DstIP)

	header[0] = 0x45                            // Version 4, IHL 5
	header[1] = 0x00                            // DSCP/ECN
	binary.BigEndian.PutUint16(header[2:4], 40) // Total length (minimum)
	binary.BigEndian.PutUint16(header[4:6], 0)  // ID
	binary.BigEndian.PutUint16(header[6:8], 0)  // Flags
	header[8] = 64                              // TTL
	header[9] = uint8(ctx.Packet.Protocol)      // Protocol

	if srcIP != nil {
		copy(header[12:16], srcIP.To4())
	}
	if dstIP != nil {
		copy(header[16:20], dstIP.To4())
	}
}

// calculateChecksum calculates IP/ICMP checksum.
func (h *ICMPRejectHandler) calculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateICMPv6Checksum calculates ICMPv6 checksum with pseudo-header.
func (h *ICMPRejectHandler) calculateICMPv6Checksum(src, dst net.IP, icmpv6Segment []byte) uint16 {
	var sum uint32

	// Pseudo-header
	srcBytes := src.To16()
	dstBytes := dst.To16()

	// Source address
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcBytes[i : i+2]))
	}

	// Destination address
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstBytes[i : i+2]))
	}

	// Upper-layer length
	sum += uint32(len(icmpv6Segment))

	// Next header (58 = ICMPv6)
	sum += 58

	// ICMPv6 segment
	for i := 0; i < len(icmpv6Segment); i += 2 {
		if i+1 < len(icmpv6Segment) {
			sum += uint32(binary.BigEndian.Uint16(icmpv6Segment[i : i+2]))
		} else {
			sum += uint32(icmpv6Segment[i]) << 8
		}
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// ============================================================================
// Statistics and Lifecycle
// ============================================================================

// GetStats returns the ICMP reject handler statistics.
func (h *ICMPRejectHandler) GetStats() map[string]uint64 {
	return map[string]uint64{
		"rejects_attempted": h.stats.RejectsAttempted.Load(),
		"rejects_succeeded": h.stats.RejectsSucceeded.Load(),
		"rejects_failed":    h.stats.RejectsFailed.Load(),
		"packets_injected":  h.stats.PacketsInjected.Load(),
		"ipv4_rejects":      h.stats.IPv4Rejects.Load(),
		"ipv6_rejects":      h.stats.IPv6Rejects.Load(),
		"protocol_mismatch": h.stats.ProtocolMismatch.Load(),
		"missing_context":   h.stats.MissingContext.Load(),
	}
}

// Close shuts down the ICMP reject handler.
func (h *ICMPRejectHandler) Close() error {
	h.closed.Store(true)
	return nil
}

// SetInjector sets the packet injector reference.
func (h *ICMPRejectHandler) SetInjector(injector PacketInjectorInterface) {
	h.injector = injector
}

// GetConfig returns the current configuration.
func (h *ICMPRejectHandler) GetConfig() *ICMPRejectConfig {
	return h.config
}
