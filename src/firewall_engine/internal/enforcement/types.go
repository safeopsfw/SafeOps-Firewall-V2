// Package enforcement provides verdict enforcement functionality for the firewall engine.
// It transforms firewall decisions (ALLOW/DENY/DROP/REDIRECT/REJECT) into actual
// network actions through integration with the SafeOps kernel-level verdict engine.
//
// Architecture:
//
//	Firewall Rule Matcher
//	        ↓
//	  VerdictResult
//	        ↓
//	  VerdictHandler (Orchestrator)
//	        ↓
//	  ┌─────┴─────┬──────────┬─────────────┬────────────┐
//	  ↓           ↓          ↓             ↓            ↓
//	DropHandler  TCPRst   DNSRedirect   ICMPReject   ActionExecutor
//	  ↓           ↓          ↓             ↓            ↓
//	  └─────┬─────┴──────────┴─────────────┴────────────┘
//	        ↓
//	SafeOps Verdict Engine (Kernel NDIS Driver)
package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Enforcement Action Types
// ============================================================================

// EnforcementAction defines the type of enforcement action to perform.
// These map to the underlying SafeOps verdict engine capabilities.
type EnforcementAction int32

const (
	// ActionNone indicates no enforcement action is needed.
	// Used for ALLOW verdicts where packets flow normally.
	ActionNone EnforcementAction = 0

	// ActionDrop silently discards the packet without any response.
	// The sender will experience a timeout. Implemented via kernel blocklist.
	ActionDrop EnforcementAction = 1

	// ActionBlock drops the packet and sends an active rejection response.
	// For TCP: sends TCP RST to both ends.
	// For UDP: sends ICMP port unreachable.
	ActionBlock EnforcementAction = 2

	// ActionRedirect redirects the traffic to a different destination.
	// Primarily used for DNS sinkholing to captive portal.
	ActionRedirect EnforcementAction = 3

	// ActionReject sends ICMP "administratively prohibited" message.
	// Polite rejection that tells sender the packet was blocked by policy.
	ActionReject EnforcementAction = 4

	// ActionLog allows the packet but marks it for detailed logging.
	// No network-level action, just logging enhancement.
	ActionLog EnforcementAction = 5

	// ActionQueue sends packet to user-space queue for deep inspection.
	// Used for slow-lane processing by IDS/IPS engines.
	ActionQueue EnforcementAction = 6

	// ActionRateLimit applies rate limiting to this flow.
	// Does not block but may delay or drop excess packets.
	ActionRateLimit EnforcementAction = 7
)

// actionNames maps action values to human-readable strings.
var actionNames = map[EnforcementAction]string{
	ActionNone:      "NONE",
	ActionDrop:      "DROP",
	ActionBlock:     "BLOCK",
	ActionRedirect:  "REDIRECT",
	ActionReject:    "REJECT",
	ActionLog:       "LOG",
	ActionQueue:     "QUEUE",
	ActionRateLimit: "RATE_LIMIT",
}

// String returns the human-readable name of the action.
func (a EnforcementAction) String() string {
	if name, ok := actionNames[a]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", a)
}

// IsValid checks if the action is a recognized value.
func (a EnforcementAction) IsValid() bool {
	_, ok := actionNames[a]
	return ok
}

// RequiresPacketInjection returns true if this action requires injecting
// a response packet (RST, ICMP, DNS response, etc.).
func (a EnforcementAction) RequiresPacketInjection() bool {
	switch a {
	case ActionBlock, ActionRedirect, ActionReject:
		return true
	default:
		return false
	}
}

// RequiresKernelBlocklist returns true if this action requires adding
// entries to the kernel-level blocklist.
func (a EnforcementAction) RequiresKernelBlocklist() bool {
	return a == ActionDrop
}

// MarshalJSON implements json.Marshaler.
func (a EnforcementAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *EnforcementAction) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try as integer
		var n int32
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return fmt.Errorf("action must be string or integer: %w", err)
		}
		*a = EnforcementAction(n)
		return nil
	}
	// Parse from string
	for action, name := range actionNames {
		if name == s {
			*a = action
			return nil
		}
	}
	return fmt.Errorf("unknown enforcement action: %q", s)
}

// ============================================================================
// Enforcement Result
// ============================================================================

// EnforcementResult contains the outcome of an enforcement operation.
// It provides detailed information for logging, metrics, and error handling.
type EnforcementResult struct {
	// Success indicates whether the enforcement completed successfully.
	Success bool `json:"success"`

	// Action is the enforcement action that was attempted.
	Action EnforcementAction `json:"action"`

	// PacketID is the ID of the packet this enforcement applied to.
	PacketID uint64 `json:"packet_id"`

	// Duration is how long the enforcement operation took.
	Duration time.Duration `json:"duration_ns"`

	// RetryCount is how many retry attempts were made (0 = first attempt succeeded).
	RetryCount int `json:"retry_count,omitempty"`

	// Error contains error details if Success is false.
	Error error `json:"error,omitempty"`

	// ErrorCode provides a machine-readable error classification.
	ErrorCode EnforcementErrorCode `json:"error_code,omitempty"`

	// HandlerName identifies which handler processed this enforcement.
	HandlerName string `json:"handler_name,omitempty"`

	// Timestamp when the enforcement was executed.
	Timestamp time.Time `json:"timestamp"`

	// PacketsAffected is how many packets were affected (for cached verdicts).
	PacketsAffected uint64 `json:"packets_affected,omitempty"`

	// Metadata contains additional handler-specific information.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewSuccessResult creates a successful enforcement result.
func NewSuccessResult(action EnforcementAction, packetID uint64, duration time.Duration) *EnforcementResult {
	return &EnforcementResult{
		Success:   true,
		Action:    action,
		PacketID:  packetID,
		Duration:  duration,
		Timestamp: time.Now(),
	}
}

// NewFailureResult creates a failed enforcement result.
func NewFailureResult(action EnforcementAction, packetID uint64, err error, code EnforcementErrorCode) *EnforcementResult {
	return &EnforcementResult{
		Success:   false,
		Action:    action,
		PacketID:  packetID,
		Error:     err,
		ErrorCode: code,
		Timestamp: time.Now(),
	}
}

// WithRetryCount adds retry information to the result.
func (r *EnforcementResult) WithRetryCount(count int) *EnforcementResult {
	r.RetryCount = count
	return r
}

// WithHandler adds handler identification to the result.
func (r *EnforcementResult) WithHandler(name string) *EnforcementResult {
	r.HandlerName = name
	return r
}

// WithMetadata adds custom metadata to the result.
func (r *EnforcementResult) WithMetadata(key string, value interface{}) *EnforcementResult {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
	return r
}

// String returns a human-readable summary of the result.
func (r *EnforcementResult) String() string {
	if r.Success {
		return fmt.Sprintf("%s: success (packet=%d, duration=%v)",
			r.Action, r.PacketID, r.Duration)
	}
	return fmt.Sprintf("%s: failed (packet=%d, error=%v, code=%s)",
		r.Action, r.PacketID, r.Error, r.ErrorCode)
}

// ============================================================================
// Error Types and Codes
// ============================================================================

// EnforcementErrorCode provides machine-readable error classification.
type EnforcementErrorCode string

const (
	// ErrCodeNone indicates no error.
	ErrCodeNone EnforcementErrorCode = ""

	// ErrCodeInvalidPacket indicates the packet data is malformed or incomplete.
	ErrCodeInvalidPacket EnforcementErrorCode = "INVALID_PACKET"

	// ErrCodeInvalidVerdict indicates an unrecognized verdict type.
	ErrCodeInvalidVerdict EnforcementErrorCode = "INVALID_VERDICT"

	// ErrCodeEngineUnavailable indicates the SafeOps verdict engine is not accessible.
	ErrCodeEngineUnavailable EnforcementErrorCode = "ENGINE_UNAVAILABLE"

	// ErrCodeInjectionFailed indicates packet injection failed at kernel level.
	ErrCodeInjectionFailed EnforcementErrorCode = "INJECTION_FAILED"

	// ErrCodeBlocklistFailed indicates adding to kernel blocklist failed.
	ErrCodeBlocklistFailed EnforcementErrorCode = "BLOCKLIST_FAILED"

	// ErrCodeRetryExhausted indicates all retry attempts failed.
	ErrCodeRetryExhausted EnforcementErrorCode = "RETRY_EXHAUSTED"

	// ErrCodeTimeout indicates the operation timed out.
	ErrCodeTimeout EnforcementErrorCode = "TIMEOUT"

	// ErrCodeProtocolMismatch indicates the handler doesn't support this protocol.
	ErrCodeProtocolMismatch EnforcementErrorCode = "PROTOCOL_MISMATCH"

	// ErrCodeMissingContext indicates required context data is missing.
	ErrCodeMissingContext EnforcementErrorCode = "MISSING_CONTEXT"

	// ErrCodeInternalError indicates an unexpected internal error.
	ErrCodeInternalError EnforcementErrorCode = "INTERNAL_ERROR"

	// ErrCodeDisabled indicates enforcement is disabled by configuration.
	ErrCodeDisabled EnforcementErrorCode = "DISABLED"
)

// Sentinel errors for common enforcement failures.
var (
	// ErrEnforcementDisabled indicates enforcement is disabled by configuration.
	ErrEnforcementDisabled = errors.New("enforcement is disabled")

	// ErrEngineNotConnected indicates the SafeOps verdict engine is not connected.
	ErrEngineNotConnected = errors.New("verdict engine not connected")

	// ErrInvalidPacketData indicates the packet data is malformed.
	ErrInvalidPacketData = errors.New("invalid or malformed packet data")

	// ErrMissingAdapterHandle indicates the adapter handle is not available.
	ErrMissingAdapterHandle = errors.New("missing adapter handle")

	// ErrMissingMACAddresses indicates required MAC addresses are not available.
	ErrMissingMACAddresses = errors.New("missing MAC addresses")

	// ErrUnsupportedProtocol indicates the protocol is not supported by this handler.
	ErrUnsupportedProtocol = errors.New("unsupported protocol for this action")

	// ErrRetryExhausted indicates all retry attempts have been exhausted.
	ErrRetryExhausted = errors.New("all retry attempts exhausted")

	// ErrOperationTimeout indicates the operation timed out.
	ErrOperationTimeout = errors.New("enforcement operation timed out")

	// ErrNilPacketContext indicates the packet context is nil.
	ErrNilPacketContext = errors.New("packet context is nil")

	// ErrNilVerdictResult indicates the verdict result is nil.
	ErrNilVerdictResult = errors.New("verdict result is nil")

	// ErrInvalidIPAddress indicates an IP address is invalid or empty.
	ErrInvalidIPAddress = errors.New("invalid or empty IP address")

	// ErrDNSQueryRequired indicates this action requires a DNS query packet.
	ErrDNSQueryRequired = errors.New("DNS query packet required for redirect")
)

// EnforcementError wraps an error with additional context.
type EnforcementError struct {
	Code      EnforcementErrorCode
	Action    EnforcementAction
	PacketID  uint64
	Cause     error
	Retryable bool
}

// Error implements the error interface.
func (e *EnforcementError) Error() string {
	return fmt.Sprintf("enforcement error [%s] action=%s packet=%d: %v",
		e.Code, e.Action, e.PacketID, e.Cause)
}

// Unwrap returns the underlying error.
func (e *EnforcementError) Unwrap() error {
	return e.Cause
}

// NewEnforcementError creates a new enforcement error with context.
func NewEnforcementError(code EnforcementErrorCode, action EnforcementAction, packetID uint64, cause error, retryable bool) *EnforcementError {
	return &EnforcementError{
		Code:      code,
		Action:    action,
		PacketID:  packetID,
		Cause:     cause,
		Retryable: retryable,
	}
}

// IsRetryable checks if an error is retryable.
func IsRetryable(err error) bool {
	var enfErr *EnforcementError
	if errors.As(err, &enfErr) {
		return enfErr.Retryable
	}
	// Default: injection and blocklist failures are typically retryable
	return errors.Is(err, ErrEngineNotConnected)
}

// ============================================================================
// Packet Context - Enhanced packet info for enforcement
// ============================================================================

// PacketContext contains all information needed to enforce a verdict on a packet.
// It extends PacketMetadata with low-level networking details required for
// packet injection and kernel-level operations.
type PacketContext struct {
	// Packet is the firewall packet metadata.
	Packet *models.PacketMetadata `json:"packet"`

	// Verdict is the firewall decision to enforce.
	Verdict *models.VerdictResult `json:"verdict"`

	// === Low-level Networking ===

	// AdapterHandle is the NDIS adapter handle for packet injection.
	// Type is interface{} to avoid direct dependency on ndisapi-go.
	AdapterHandle interface{} `json:"-"`

	// SrcMAC is the source MAC address (6 bytes).
	SrcMAC [6]byte `json:"-"`

	// DstMAC is the destination MAC address (6 bytes).
	DstMAC [6]byte `json:"-"`

	// GatewayMAC is the next-hop gateway MAC address.
	GatewayMAC [6]byte `json:"-"`

	// RawPacket contains the original raw packet bytes (for inspection).
	// May be nil if not needed.
	RawPacket []byte `json:"-"`

	// === Parsed IP Addresses ===

	// SrcIPParsed is the parsed source IP address.
	SrcIPParsed net.IP `json:"-"`

	// DstIPParsed is the parsed destination IP address.
	DstIPParsed net.IP `json:"-"`

	// === TCP State (for RST injection) ===

	// TCPSeqNum is the current TCP sequence number.
	TCPSeqNum uint32 `json:"tcp_seq_num,omitempty"`

	// TCPAckNum is the current TCP acknowledgment number.
	TCPAckNum uint32 `json:"tcp_ack_num,omitempty"`

	// === DNS Context (for DNS redirect) ===

	// DNSTransactionID is the DNS query transaction ID.
	DNSTransactionID uint16 `json:"dns_transaction_id,omitempty"`

	// DNSQueryName is the queried domain name.
	DNSQueryName string `json:"dns_query_name,omitempty"`

	// === Redirect Configuration ===

	// RedirectIP is the IP to redirect traffic to (captive portal).
	RedirectIP net.IP `json:"redirect_ip,omitempty"`

	// RedirectPort is the port to redirect to.
	RedirectPort uint16 `json:"redirect_port,omitempty"`

	// === Metadata ===

	// CreatedAt is when this context was created.
	CreatedAt time.Time `json:"created_at"`

	// TraceID is for distributed tracing.
	TraceID string `json:"trace_id,omitempty"`

	// Tags are custom key-value pairs for context.
	Tags map[string]string `json:"tags,omitempty"`
}

// NewPacketContext creates a new packet context from packet metadata and verdict.
func NewPacketContext(packet *models.PacketMetadata, verdict *models.VerdictResult) *PacketContext {
	ctx := &PacketContext{
		Packet:    packet,
		Verdict:   verdict,
		CreatedAt: time.Now(),
	}

	// Parse IP addresses if available
	if packet != nil {
		ctx.SrcIPParsed = net.ParseIP(packet.SrcIP)
		ctx.DstIPParsed = net.ParseIP(packet.DstIP)

		// Copy DNS query name from domain
		if packet.IsDNSQuery && packet.Domain != "" {
			ctx.DNSQueryName = packet.Domain
		}

		// Copy redirect info from verdict
		if verdict != nil && verdict.Verdict == models.VerdictRedirect {
			ctx.RedirectIP = net.ParseIP(verdict.RedirectIP)
			ctx.RedirectPort = verdict.RedirectPort
		}
	}

	return ctx
}

// WithAdapterHandle sets the NDIS adapter handle.
func (c *PacketContext) WithAdapterHandle(handle interface{}) *PacketContext {
	c.AdapterHandle = handle
	return c
}

// WithMACs sets the MAC addresses.
func (c *PacketContext) WithMACs(src, dst, gateway [6]byte) *PacketContext {
	c.SrcMAC = src
	c.DstMAC = dst
	c.GatewayMAC = gateway
	return c
}

// WithRawPacket sets the raw packet bytes.
func (c *PacketContext) WithRawPacket(raw []byte) *PacketContext {
	c.RawPacket = raw
	return c
}

// WithTCPState sets TCP sequence and acknowledgment numbers.
func (c *PacketContext) WithTCPState(seq, ack uint32) *PacketContext {
	c.TCPSeqNum = seq
	c.TCPAckNum = ack
	return c
}

// WithDNSInfo sets DNS transaction ID and query name.
func (c *PacketContext) WithDNSInfo(txID uint16, queryName string) *PacketContext {
	c.DNSTransactionID = txID
	c.DNSQueryName = queryName
	return c
}

// WithRedirect sets redirect destination.
func (c *PacketContext) WithRedirect(ip net.IP, port uint16) *PacketContext {
	c.RedirectIP = ip
	c.RedirectPort = port
	return c
}

// WithTag adds a tag to the context.
func (c *PacketContext) WithTag(key, value string) *PacketContext {
	if c.Tags == nil {
		c.Tags = make(map[string]string)
	}
	c.Tags[key] = value
	return c
}

// Validate checks if the context has required data for enforcement.
func (c *PacketContext) Validate() error {
	if c == nil {
		return ErrNilPacketContext
	}
	if c.Packet == nil {
		return ErrInvalidPacketData
	}
	if c.Verdict == nil {
		return ErrNilVerdictResult
	}
	if c.Packet.SrcIP == "" || c.Packet.DstIP == "" {
		return ErrInvalidIPAddress
	}
	return nil
}

// ValidateForInjection checks if context has data needed for packet injection.
func (c *PacketContext) ValidateForInjection() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.AdapterHandle == nil {
		return ErrMissingAdapterHandle
	}
	// Check if MACs are set (not all zeros)
	emptyMAC := [6]byte{}
	if c.SrcMAC == emptyMAC && c.DstMAC == emptyMAC {
		return ErrMissingMACAddresses
	}
	return nil
}

// IsTCP returns true if this is a TCP packet.
func (c *PacketContext) IsTCP() bool {
	return c.Packet != nil && c.Packet.Protocol == models.ProtocolTCP
}

// IsUDP returns true if this is a UDP packet.
func (c *PacketContext) IsUDP() bool {
	return c.Packet != nil && c.Packet.Protocol == models.ProtocolUDP
}

// IsDNS returns true if this is a DNS packet.
func (c *PacketContext) IsDNS() bool {
	return c.Packet != nil && c.Packet.IsDNS()
}

// GetPacketID returns the packet ID for correlation.
func (c *PacketContext) GetPacketID() uint64 {
	if c.Packet != nil {
		return c.Packet.PacketID
	}
	return 0
}

// ============================================================================
// Handler Interface
// ============================================================================

// ActionHandler is the interface that all enforcement handlers must implement.
// Each handler is responsible for one type of enforcement action.
type ActionHandler interface {
	// Name returns the handler name for logging and metrics.
	Name() string

	// SupportedActions returns the actions this handler can process.
	SupportedActions() []EnforcementAction

	// CanHandle checks if this handler can process the given context.
	CanHandle(ctx *PacketContext) bool

	// Handle executes the enforcement action.
	// Context is used for cancellation and timeout.
	// Returns an EnforcementResult with success/failure details.
	Handle(ctx context.Context, pktCtx *PacketContext) *EnforcementResult
}

// HandlerRegistry manages a collection of enforcement handlers.
type HandlerRegistry interface {
	// Register adds a handler to the registry.
	Register(handler ActionHandler) error

	// GetHandler returns the handler for a specific action.
	GetHandler(action EnforcementAction) (ActionHandler, bool)

	// GetHandlerForVerdict returns the appropriate handler for a verdict.
	GetHandlerForVerdict(verdict *models.VerdictResult) (ActionHandler, bool)

	// ListHandlers returns all registered handlers.
	ListHandlers() []ActionHandler
}

// ============================================================================
// Configuration Types
// ============================================================================

// EnforcementConfig contains configuration for the enforcement system.
type EnforcementConfig struct {
	// Enabled controls whether enforcement is active.
	Enabled bool `json:"enabled" toml:"enabled"`

	// FailOpen determines behavior on enforcement failure.
	// If true (default), packets are allowed on failure (prioritize availability).
	// If false, packets are dropped on failure (prioritize security).
	FailOpen bool `json:"fail_open" toml:"fail_open"`

	// MaxRetries is the maximum number of retry attempts (default: 3).
	MaxRetries int `json:"max_retries" toml:"max_retries"`

	// RetryBaseDelayMs is the base delay for exponential backoff (default: 10ms).
	RetryBaseDelayMs int `json:"retry_base_delay_ms" toml:"retry_base_delay_ms"`

	// OperationTimeoutMs is the timeout for a single enforcement operation (default: 100ms).
	OperationTimeoutMs int `json:"operation_timeout_ms" toml:"operation_timeout_ms"`

	// EnableLogging enables detailed enforcement logging.
	EnableLogging bool `json:"enable_logging" toml:"enable_logging"`

	// LogSuccesses controls whether successful enforcements are logged.
	// If false, only failures are logged (reduces log volume).
	LogSuccesses bool `json:"log_successes" toml:"log_successes"`

	// === Drop Handler Config ===

	// BlocklistTTLSeconds is how long blocked IPs stay in blocklist (default: 3600).
	BlocklistTTLSeconds int `json:"blocklist_ttl_seconds" toml:"blocklist_ttl_seconds"`

	// MaxBlockedIPs is the maximum IPs in blocklist (default: 100000).
	MaxBlockedIPs int `json:"max_blocked_ips" toml:"max_blocked_ips"`

	// === DNS Redirect Config ===

	// CaptivePortalIP is the IP to redirect blocked domains to.
	CaptivePortalIP string `json:"captive_portal_ip" toml:"captive_portal_ip"`

	// CaptivePortalPort is the port for the captive portal (default: 80).
	CaptivePortalPort int `json:"captive_portal_port" toml:"captive_portal_port"`

	// DNSResponseTTL is the TTL for injected DNS responses (default: 60).
	DNSResponseTTL int `json:"dns_response_ttl" toml:"dns_response_ttl"`

	// === ICMP Reject Config ===

	// ICMPCode is the ICMP code for reject messages (default: 13 = admin prohibited).
	ICMPCode int `json:"icmp_code" toml:"icmp_code"`

	// === Advanced ===

	// EnableMetrics enables Prometheus metrics collection.
	EnableMetrics bool `json:"enable_metrics" toml:"enable_metrics"`

	// WorkerPoolSize is the number of concurrent enforcement workers.
	WorkerPoolSize int `json:"worker_pool_size" toml:"worker_pool_size"`
}

// DefaultEnforcementConfig returns the default configuration.
func DefaultEnforcementConfig() *EnforcementConfig {
	return &EnforcementConfig{
		Enabled:             true,
		FailOpen:            true, // Prioritize availability
		MaxRetries:          3,
		RetryBaseDelayMs:    10,
		OperationTimeoutMs:  100,
		EnableLogging:       true,
		LogSuccesses:        false, // Only log failures by default
		BlocklistTTLSeconds: 3600,
		MaxBlockedIPs:       100000,
		CaptivePortalIP:     "192.168.1.1",
		CaptivePortalPort:   80,
		DNSResponseTTL:      60,
		ICMPCode:            13, // Administratively prohibited
		EnableMetrics:       true,
		WorkerPoolSize:      8,
	}
}

// Validate checks the configuration for errors.
func (c *EnforcementConfig) Validate() error {
	if c.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be >= 0, got %d", c.MaxRetries)
	}
	if c.RetryBaseDelayMs < 1 {
		return fmt.Errorf("retry_base_delay_ms must be >= 1, got %d", c.RetryBaseDelayMs)
	}
	if c.OperationTimeoutMs < 10 {
		return fmt.Errorf("operation_timeout_ms must be >= 10, got %d", c.OperationTimeoutMs)
	}
	if c.BlocklistTTLSeconds < 1 {
		return fmt.Errorf("blocklist_ttl_seconds must be >= 1, got %d", c.BlocklistTTLSeconds)
	}
	if c.MaxBlockedIPs < 100 {
		return fmt.Errorf("max_blocked_ips must be >= 100, got %d", c.MaxBlockedIPs)
	}
	if c.CaptivePortalIP != "" {
		if ip := net.ParseIP(c.CaptivePortalIP); ip == nil {
			return fmt.Errorf("invalid captive_portal_ip: %q", c.CaptivePortalIP)
		}
	}
	if c.CaptivePortalPort < 0 || c.CaptivePortalPort > 65535 {
		return fmt.Errorf("captive_portal_port must be 0-65535, got %d", c.CaptivePortalPort)
	}
	if c.DNSResponseTTL < 1 {
		return fmt.Errorf("dns_response_ttl must be >= 1, got %d", c.DNSResponseTTL)
	}
	if c.ICMPCode < 0 || c.ICMPCode > 15 {
		return fmt.Errorf("icmp_code must be 0-15, got %d", c.ICMPCode)
	}
	if c.WorkerPoolSize < 1 {
		return fmt.Errorf("worker_pool_size must be >= 1, got %d", c.WorkerPoolSize)
	}
	return nil
}

// GetRetryDelay calculates the delay for a specific retry attempt.
// Uses exponential backoff: base * 2^attempt (10ms, 20ms, 40ms, ...)
func (c *EnforcementConfig) GetRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	multiplier := 1 << uint(attempt) // 2^attempt
	delay := time.Duration(c.RetryBaseDelayMs*multiplier) * time.Millisecond

	// Cap at 1 second
	if delay > time.Second {
		delay = time.Second
	}
	return delay
}

// GetOperationTimeout returns the operation timeout as a Duration.
func (c *EnforcementConfig) GetOperationTimeout() time.Duration {
	return time.Duration(c.OperationTimeoutMs) * time.Millisecond
}

// ============================================================================
// Statistics Types
// ============================================================================

// EnforcementStats tracks enforcement engine statistics.
// Uses atomic operations for thread-safe updates.
type EnforcementStats struct {
	// Total enforcement operations attempted
	TotalAttempted atomic.Uint64

	// Successful enforcements
	TotalSucceeded atomic.Uint64

	// Failed enforcements (after all retries)
	TotalFailed atomic.Uint64

	// Retries attempted
	TotalRetries atomic.Uint64

	// Fail-open invocations (allowed despite failure)
	TotalFailOpen atomic.Uint64

	// Per-action counters
	DropsExecuted     atomic.Uint64
	BlocksExecuted    atomic.Uint64
	RedirectsExecuted atomic.Uint64
	RejectsExecuted   atomic.Uint64

	// Per-action failures
	DropsFailed     atomic.Uint64
	BlocksFailed    atomic.Uint64
	RedirectsFailed atomic.Uint64
	RejectsFailed   atomic.Uint64

	// Performance metrics
	TotalDurationNs atomic.Uint64
	MaxDurationNs   atomic.Uint64
}

// NewEnforcementStats creates a new stats tracker.
func NewEnforcementStats() *EnforcementStats {
	return &EnforcementStats{}
}

// RecordSuccess records a successful enforcement.
func (s *EnforcementStats) RecordSuccess(action EnforcementAction, duration time.Duration) {
	s.TotalAttempted.Add(1)
	s.TotalSucceeded.Add(1)

	durationNs := uint64(duration.Nanoseconds())
	s.TotalDurationNs.Add(durationNs)

	// Update max duration (using compare-and-swap)
	for {
		current := s.MaxDurationNs.Load()
		if durationNs <= current {
			break
		}
		if s.MaxDurationNs.CompareAndSwap(current, durationNs) {
			break
		}
	}

	// Update per-action counter
	switch action {
	case ActionDrop:
		s.DropsExecuted.Add(1)
	case ActionBlock:
		s.BlocksExecuted.Add(1)
	case ActionRedirect:
		s.RedirectsExecuted.Add(1)
	case ActionReject:
		s.RejectsExecuted.Add(1)
	}
}

// RecordFailure records a failed enforcement.
func (s *EnforcementStats) RecordFailure(action EnforcementAction, failOpen bool) {
	s.TotalAttempted.Add(1)
	s.TotalFailed.Add(1)

	if failOpen {
		s.TotalFailOpen.Add(1)
	}

	// Update per-action failure counter
	switch action {
	case ActionDrop:
		s.DropsFailed.Add(1)
	case ActionBlock:
		s.BlocksFailed.Add(1)
	case ActionRedirect:
		s.RedirectsFailed.Add(1)
	case ActionReject:
		s.RejectsFailed.Add(1)
	}
}

// RecordRetry records a retry attempt.
func (s *EnforcementStats) RecordRetry() {
	s.TotalRetries.Add(1)
}

// GetSnapshot returns a point-in-time snapshot of all stats.
func (s *EnforcementStats) GetSnapshot() map[string]uint64 {
	return map[string]uint64{
		"total_attempted":    s.TotalAttempted.Load(),
		"total_succeeded":    s.TotalSucceeded.Load(),
		"total_failed":       s.TotalFailed.Load(),
		"total_retries":      s.TotalRetries.Load(),
		"total_fail_open":    s.TotalFailOpen.Load(),
		"drops_executed":     s.DropsExecuted.Load(),
		"blocks_executed":    s.BlocksExecuted.Load(),
		"redirects_executed": s.RedirectsExecuted.Load(),
		"rejects_executed":   s.RejectsExecuted.Load(),
		"drops_failed":       s.DropsFailed.Load(),
		"blocks_failed":      s.BlocksFailed.Load(),
		"redirects_failed":   s.RedirectsFailed.Load(),
		"rejects_failed":     s.RejectsFailed.Load(),
		"total_duration_ns":  s.TotalDurationNs.Load(),
		"max_duration_ns":    s.MaxDurationNs.Load(),
		"avg_duration_ns":    s.GetAverageDurationNs(),
		"success_rate_pct":   s.GetSuccessRatePercent(),
	}
}

// GetAverageDurationNs returns the average enforcement duration in nanoseconds.
func (s *EnforcementStats) GetAverageDurationNs() uint64 {
	succeeded := s.TotalSucceeded.Load()
	if succeeded == 0 {
		return 0
	}
	return s.TotalDurationNs.Load() / succeeded
}

// GetSuccessRatePercent returns the success rate as a percentage (0-100).
func (s *EnforcementStats) GetSuccessRatePercent() uint64 {
	attempted := s.TotalAttempted.Load()
	if attempted == 0 {
		return 100 // No attempts = 100% success (vacuously true)
	}
	succeeded := s.TotalSucceeded.Load()
	return (succeeded * 100) / attempted
}

// Reset resets all statistics to zero.
func (s *EnforcementStats) Reset() {
	s.TotalAttempted.Store(0)
	s.TotalSucceeded.Store(0)
	s.TotalFailed.Store(0)
	s.TotalRetries.Store(0)
	s.TotalFailOpen.Store(0)
	s.DropsExecuted.Store(0)
	s.BlocksExecuted.Store(0)
	s.RedirectsExecuted.Store(0)
	s.RejectsExecuted.Store(0)
	s.DropsFailed.Store(0)
	s.BlocksFailed.Store(0)
	s.RedirectsFailed.Store(0)
	s.RejectsFailed.Store(0)
	s.TotalDurationNs.Store(0)
	s.MaxDurationNs.Store(0)
}
