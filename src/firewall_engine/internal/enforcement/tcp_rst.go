// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// ============================================================================
// TCP Reset Handler - Active Connection Termination
// ============================================================================

// TCPResetHandler implements TCP RST injection to actively terminate connections.
// When a BLOCK/DENY verdict is issued for a TCP connection, this handler crafts
// and injects TCP RST packets to both the client and server, causing immediate
// connection termination.
//
// TCP RST Packet Structure:
//
//	Ethernet Header (14 bytes)
//	├─ Dest MAC (6)
//	├─ Source MAC (6)
//	└─ EtherType (2) = 0x0800 (IPv4)
//
//	IP Header (20 bytes)
//	├─ Source IP (spoofed - opposite endpoint)
//	├─ Dest IP (target endpoint)
//	└─ Protocol = 6 (TCP)
//
//	TCP Header (20 bytes)
//	├─ Source Port (opposite endpoint)
//	├─ Dest Port (target endpoint)
//	├─ Sequence Number (next expected)
//	├─ Flags = RST|ACK
//	└─ Checksum
//
// Use Cases:
//   - Blocking social media during work hours (fast feedback)
//   - Blocking specific applications (gaming, P2P)
//   - Enforcing acceptable use policies
//   - Domain-based blocking (facebook.com, twitter.com)
//
// Network Perspective:
//   - User's browser connects to facebook.com
//   - Firewall intercepts SYN or data packet
//   - Firewall injects RST to browser: "Connection refused"
//   - Browser immediately shows error (no 30s timeout)
type TCPResetHandler struct {
	// Configuration
	config *TCPResetConfig

	// SafeOps verdict engine for RST injection
	verdictEngine TCPResetEngineInterface

	// Statistics
	stats *TCPResetStats

	// Shutdown
	closed atomic.Bool
}

// TCPResetConfig contains configuration for the TCP RST handler.
type TCPResetConfig struct {
	// SendToClient sends RST to the client (source of blocked traffic).
	SendToClient bool `json:"send_to_client" toml:"send_to_client"`

	// SendToServer sends RST to the server (destination of blocked traffic).
	SendToServer bool `json:"send_to_server" toml:"send_to_server"`

	// UseACK includes ACK flag with RST for better compatibility.
	UseACK bool `json:"use_ack" toml:"use_ack"`

	// DefaultTTL is the IP TTL for injected packets.
	DefaultTTL uint8 `json:"default_ttl" toml:"default_ttl"`
}

// DefaultTCPResetConfig returns the default configuration.
func DefaultTCPResetConfig() *TCPResetConfig {
	return &TCPResetConfig{
		SendToClient: true,
		SendToServer: true,
		UseACK:       true,
		DefaultTTL:   64,
	}
}

// TCPResetStats tracks TCP RST handler statistics.
type TCPResetStats struct {
	ResetsAttempted  atomic.Uint64
	ResetsSucceeded  atomic.Uint64
	ResetsFailed     atomic.Uint64
	PacketsInjected  atomic.Uint64
	ClientRstsSent   atomic.Uint64
	ServerRstsSent   atomic.Uint64
	ProtocolMismatch atomic.Uint64
}

// TCPResetEngineInterface abstracts the SafeOps verdict engine for RST injection.
type TCPResetEngineInterface interface {
	// SendTCPReset sends TCP RST packets to terminate a connection.
	// Sends RST to both endpoints with correct MAC addresses.
	SendTCPReset(
		adapterHandle interface{},
		srcIP, dstIP net.IP,
		srcPort, dstPort uint16,
		srcMAC, dstMAC [6]byte,
	) error
}

// NewTCPResetHandler creates a new TCP RST handler.
func NewTCPResetHandler(config *TCPResetConfig, engine TCPResetEngineInterface) (*TCPResetHandler, error) {
	if config == nil {
		config = DefaultTCPResetConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tcp reset config: %w", err)
	}

	return &TCPResetHandler{
		config:        config,
		verdictEngine: engine,
		stats:         &TCPResetStats{},
	}, nil
}

// Validate checks the configuration.
func (c *TCPResetConfig) Validate() error {
	if !c.SendToClient && !c.SendToServer {
		return fmt.Errorf("at least one of send_to_client or send_to_server must be true")
	}
	if c.DefaultTTL == 0 {
		return fmt.Errorf("default_ttl must be > 0")
	}
	return nil
}

// ============================================================================
// ActionHandler Interface Implementation
// ============================================================================

// Name returns the handler name.
func (h *TCPResetHandler) Name() string {
	return "TCPResetHandler"
}

// SupportedActions returns the actions this handler supports.
func (h *TCPResetHandler) SupportedActions() []EnforcementAction {
	return []EnforcementAction{ActionBlock}
}

// CanHandle checks if this handler can process the given context.
func (h *TCPResetHandler) CanHandle(ctx *PacketContext) bool {
	if ctx == nil || ctx.Packet == nil {
		return false
	}

	// Only handle TCP packets
	if !ctx.IsTCP() {
		return false
	}

	// Need valid source and destination IPs
	if ctx.Packet.SrcIP == "" || ctx.Packet.DstIP == "" {
		return false
	}

	// Need port information
	if ctx.Packet.SrcPort == 0 || ctx.Packet.DstPort == 0 {
		return false
	}

	return true
}

// Handle executes the TCP RST injection.
func (h *TCPResetHandler) Handle(ctx context.Context, pktCtx *PacketContext) *EnforcementResult {
	startTime := time.Now()

	// Check if handler is closed
	if h.closed.Load() {
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			fmt.Errorf("tcp reset handler is closed"), ErrCodeDisabled)
	}

	h.stats.ResetsAttempted.Add(1)

	// Validate this is a TCP packet
	if !h.CanHandle(pktCtx) {
		h.stats.ProtocolMismatch.Add(1)
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			ErrUnsupportedProtocol, ErrCodeProtocolMismatch).
			WithHandler(h.Name())
	}

	// Validate context for injection
	if err := pktCtx.ValidateForInjection(); err != nil {
		h.stats.ResetsFailed.Add(1)
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(), err, ErrCodeMissingContext).
			WithHandler(h.Name())
	}

	// Check if verdict engine is available
	if h.verdictEngine == nil {
		h.stats.ResetsFailed.Add(1)
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			ErrEngineNotConnected, ErrCodeEngineUnavailable).
			WithHandler(h.Name())
	}

	// Parse IP addresses
	srcIP := h.getIP(pktCtx.SrcIPParsed, pktCtx.Packet.SrcIP)
	dstIP := h.getIP(pktCtx.DstIPParsed, pktCtx.Packet.DstIP)

	if srcIP == nil || dstIP == nil {
		h.stats.ResetsFailed.Add(1)
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			ErrInvalidIPAddress, ErrCodeInvalidPacket).
			WithHandler(h.Name())
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		h.stats.ResetsFailed.Add(1)
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			ctx.Err(), ErrCodeTimeout).
			WithHandler(h.Name())
	default:
	}

	// Send RST packets
	packetsInjected := 0
	var lastError error

	// Send RST to terminate the connection
	// The SafeOps engine's SendTCPReset sends RST to both endpoints
	err := h.verdictEngine.SendTCPReset(
		pktCtx.AdapterHandle,
		srcIP, dstIP,
		pktCtx.Packet.SrcPort, pktCtx.Packet.DstPort,
		pktCtx.SrcMAC, pktCtx.DstMAC,
	)

	if err != nil {
		lastError = err
		h.stats.ResetsFailed.Add(1)
	} else {
		packetsInjected = 2 // RST to both client and server
		h.stats.PacketsInjected.Add(2)
		h.stats.ClientRstsSent.Add(1)
		h.stats.ServerRstsSent.Add(1)
	}

	// Return result
	if lastError != nil {
		return NewFailureResult(ActionBlock, pktCtx.GetPacketID(),
			fmt.Errorf("RST injection failed: %w", lastError),
			ErrCodeInjectionFailed).
			WithHandler(h.Name())
	}

	h.stats.ResetsSucceeded.Add(1)

	return NewSuccessResult(ActionBlock, pktCtx.GetPacketID(), time.Since(startTime)).
		WithHandler(h.Name()).
		WithMetadata("packets_injected", packetsInjected).
		WithMetadata("src_ip", srcIP.String()).
		WithMetadata("dst_ip", dstIP.String())
}

// ============================================================================
// Manual RST Injection
// ============================================================================

// SendReset manually sends TCP RST to terminate a specific connection.
// This can be used outside of the normal verdict enforcement flow.
func (h *TCPResetHandler) SendReset(
	adapterHandle interface{},
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	srcMAC, dstMAC [6]byte,
) error {
	if h.verdictEngine == nil {
		return ErrEngineNotConnected
	}

	parsedSrcIP := net.ParseIP(srcIP)
	parsedDstIP := net.ParseIP(dstIP)

	if parsedSrcIP == nil {
		return fmt.Errorf("invalid source IP: %s", srcIP)
	}
	if parsedDstIP == nil {
		return fmt.Errorf("invalid destination IP: %s", dstIP)
	}

	return h.verdictEngine.SendTCPReset(
		adapterHandle,
		parsedSrcIP, parsedDstIP,
		srcPort, dstPort,
		srcMAC, dstMAC,
	)
}

// ============================================================================
// Helper Methods
// ============================================================================

// getIP returns the parsed IP or parses from string.
func (h *TCPResetHandler) getIP(parsed net.IP, str string) net.IP {
	if parsed != nil {
		return parsed
	}
	return net.ParseIP(str)
}

// ============================================================================
// Statistics and Lifecycle
// ============================================================================

// GetStats returns the TCP RST handler statistics.
func (h *TCPResetHandler) GetStats() map[string]uint64 {
	return map[string]uint64{
		"resets_attempted":  h.stats.ResetsAttempted.Load(),
		"resets_succeeded":  h.stats.ResetsSucceeded.Load(),
		"resets_failed":     h.stats.ResetsFailed.Load(),
		"packets_injected":  h.stats.PacketsInjected.Load(),
		"client_rsts_sent":  h.stats.ClientRstsSent.Load(),
		"server_rsts_sent":  h.stats.ServerRstsSent.Load(),
		"protocol_mismatch": h.stats.ProtocolMismatch.Load(),
	}
}

// Close shuts down the TCP RST handler.
func (h *TCPResetHandler) Close() error {
	h.closed.Store(true)
	return nil
}

// SetVerdictEngine sets the verdict engine reference.
func (h *TCPResetHandler) SetVerdictEngine(engine TCPResetEngineInterface) {
	h.verdictEngine = engine
}

// GetConfig returns the current configuration.
func (h *TCPResetHandler) GetConfig() *TCPResetConfig {
	return h.config
}
