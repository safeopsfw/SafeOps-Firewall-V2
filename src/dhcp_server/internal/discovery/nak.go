// Package discovery handles DHCP message processing.
// This file implements DHCP NAK (Negative Acknowledgment) packet construction.
package discovery

import (
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// NAK Reason Codes
// ============================================================================

// NAKReason represents the reason for sending a NAK.
type NAKReason int

const (
	// NAKReasonUnknown is used when reason is not specified
	NAKReasonUnknown NAKReason = iota
	// NAKReasonIPNotAvailable when requested IP is unavailable
	NAKReasonIPNotAvailable
	// NAKReasonWrongSubnet when client is on wrong subnet
	NAKReasonWrongSubnet
	// NAKReasonServerMismatch when server ID doesn't match
	NAKReasonServerMismatch
	// NAKReasonPoolExhausted when pool has no IPs
	NAKReasonPoolExhausted
	// NAKReasonIPConflict when IP already assigned to another client
	NAKReasonIPConflict
	// NAKReasonAuthFailed when client authorization failed
	NAKReasonAuthFailed
	// NAKReasonDatabaseError when database commit failed
	NAKReasonDatabaseError
	// NAKReasonInvalidRequest when request is malformed
	NAKReasonInvalidRequest
)

// String returns human-readable NAK reason.
func (r NAKReason) String() string {
	switch r {
	case NAKReasonIPNotAvailable:
		return "Requested IP address not available"
	case NAKReasonWrongSubnet:
		return "Client on wrong network segment"
	case NAKReasonServerMismatch:
		return "Server identifier mismatch"
	case NAKReasonPoolExhausted:
		return "No IP addresses available in pool"
	case NAKReasonIPConflict:
		return "IP address already in use"
	case NAKReasonAuthFailed:
		return "Client authorization failed"
	case NAKReasonDatabaseError:
		return "Server internal error"
	case NAKReasonInvalidRequest:
		return "Invalid DHCP request"
	default:
		return "Request rejected"
	}
}

// ============================================================================
// NAK Builder Configuration
// ============================================================================

// NAKBuilderConfig holds NAK construction settings.
type NAKBuilderConfig struct {
	IncludeReason bool
	RateLimit     int // Max NAKs per client per minute
	NAKTimeout    time.Duration
	ServerIP      net.IP
	LogDetails    bool
}

// DefaultNAKBuilderConfig returns sensible defaults.
func DefaultNAKBuilderConfig() *NAKBuilderConfig {
	return &NAKBuilderConfig{
		IncludeReason: true,
		RateLimit:     10,
		NAKTimeout:    50 * time.Millisecond,
		LogDetails:    true,
	}
}

// ============================================================================
// NAK Builder
// ============================================================================

// NAKBuilder constructs DHCP NAK packets.
type NAKBuilder struct {
	mu     sync.RWMutex
	config *NAKBuilderConfig

	// Rate limiting
	clientNAKCount map[string]int
	lastReset      time.Time

	// Statistics
	stats NAKBuilderStats
}

// NAKBuilderStats tracks NAK construction metrics.
type NAKBuilderStats struct {
	TotalBuilt         int64
	ByReason           map[NAKReason]int64
	RateLimited        int64
	ConstructionErrors int64
	AvgBuildTimeMs     float64
}

// NewNAKBuilder creates a new NAK builder.
func NewNAKBuilder(config *NAKBuilderConfig) *NAKBuilder {
	if config == nil {
		config = DefaultNAKBuilderConfig()
	}

	return &NAKBuilder{
		config:         config,
		clientNAKCount: make(map[string]int),
		lastReset:      time.Now(),
		stats: NAKBuilderStats{
			ByReason: make(map[NAKReason]int64),
		},
	}
}

// SetServerIP sets the server IP address.
func (b *NAKBuilder) SetServerIP(ip net.IP) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config.ServerIP = ip
}

// ============================================================================
// Main Build Function
// ============================================================================

// BuildNAK constructs a DHCP NAK packet.
func (b *NAKBuilder) BuildNAK(req *NAKRequest) (*DHCPPacket, error) {
	startTime := time.Now()

	// Validate request
	if err := b.validateRequest(req); err != nil {
		b.stats.ConstructionErrors++
		return nil, err
	}

	// Check rate limit
	if b.isRateLimited(req.ClientMAC) {
		b.stats.RateLimited++
		return nil, ErrNAKRateLimited
	}

	// Create NAK packet
	packet := b.createNAKPacket(req)

	// Build options
	packet.Options = b.buildOptions(req)

	// Update statistics
	b.stats.TotalBuilt++
	b.stats.ByReason[req.Reason]++
	b.incrementClientNAKCount(req.ClientMAC)

	// Update timing
	elapsed := float64(time.Since(startTime).Milliseconds())
	b.updateAvgBuildTime(elapsed)

	return packet, nil
}

// NAKRequest contains parameters for NAK construction.
type NAKRequest struct {
	TransactionID uint32
	HType         byte
	HLen          byte
	ClientMAC     net.HardwareAddr
	GIAddr        net.IP
	Reason        NAKReason
	Message       string // Custom message override
}

// ============================================================================
// Packet Construction
// ============================================================================

func (b *NAKBuilder) createNAKPacket(req *NAKRequest) *DHCPPacket {
	packet := &DHCPPacket{
		Op:     BootReply,
		HType:  req.HType,
		HLen:   req.HLen,
		Hops:   0,
		XID:    req.TransactionID,
		Secs:   0,
		Flags:  0x8000, // Force broadcast for NAK
		CIAddr: net.IPv4zero,
		YIAddr: net.IPv4zero, // No IP assigned
		SIAddr: b.config.ServerIP,
		CHAddr: req.ClientMAC,
	}

	// Set gateway IP if relayed
	if req.GIAddr != nil && !req.GIAddr.IsUnspecified() {
		packet.GIAddr = req.GIAddr
	} else {
		packet.GIAddr = net.IPv4zero
	}

	return packet
}

// ============================================================================
// Options Building
// ============================================================================

func (b *NAKBuilder) buildOptions(req *NAKRequest) []DHCPOption {
	options := make([]DHCPOption, 0, 4)

	// Option 53: DHCP Message Type (NAK)
	options = append(options, DHCPOption{
		Code:   OptMessageType,
		Length: 1,
		Data:   []byte{DHCPNak},
	})

	// Option 54: Server Identifier
	if b.config.ServerIP != nil {
		options = append(options, DHCPOption{
			Code:   OptServerID,
			Length: 4,
			Data:   b.config.ServerIP.To4(),
		})
	}

	// Option 56: Message (rejection reason)
	if b.config.IncludeReason {
		message := req.Message
		if message == "" {
			message = req.Reason.String()
		}

		// Limit message length
		if len(message) > 255 {
			message = message[:255]
		}

		if message != "" {
			options = append(options, DHCPOption{
				Code:   56, // DHCP Message
				Length: byte(len(message)),
				Data:   []byte(message),
			})
		}
	}

	// Option 255: End
	options = append(options, DHCPOption{
		Code:   OptEnd,
		Length: 0,
		Data:   nil,
	})

	return options
}

// ============================================================================
// Validation
// ============================================================================

func (b *NAKBuilder) validateRequest(req *NAKRequest) error {
	if req == nil {
		return ErrNilNAKRequest
	}

	if len(req.ClientMAC) == 0 {
		return ErrMissingClientMAC
	}

	if req.TransactionID == 0 {
		return ErrMissingXID
	}

	return nil
}

// ============================================================================
// Rate Limiting
// ============================================================================

func (b *NAKBuilder) isRateLimited(mac net.HardwareAddr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset counts every minute
	if time.Since(b.lastReset) > time.Minute {
		b.clientNAKCount = make(map[string]int)
		b.lastReset = time.Now()
	}

	key := mac.String()
	count := b.clientNAKCount[key]

	return count >= b.config.RateLimit
}

func (b *NAKBuilder) incrementClientNAKCount(mac net.HardwareAddr) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := mac.String()
	b.clientNAKCount[key]++
}

// ============================================================================
// Delivery Configuration
// ============================================================================

// GetDeliveryAddress returns the destination for NAK (always broadcast).
func (p *DHCPPacket) GetNAKDeliveryAddress() net.IP {
	// If relayed, send to relay agent
	if p.GIAddr != nil && !p.GIAddr.IsUnspecified() {
		return p.GIAddr
	}

	// Otherwise broadcast
	return net.IPv4bcast
}

// IsNAKBroadcast returns true since NAKs should be broadcast.
func IsNAKBroadcast(packet *DHCPPacket) bool {
	// NAKs are always broadcast unless relayed
	if packet.GIAddr != nil && !packet.GIAddr.IsUnspecified() {
		return false
	}
	return true
}

// ============================================================================
// Helper Functions
// ============================================================================

func (b *NAKBuilder) updateAvgBuildTime(elapsed float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.stats.TotalBuilt <= 1 {
		b.stats.AvgBuildTimeMs = elapsed
	} else {
		b.stats.AvgBuildTimeMs = (b.stats.AvgBuildTimeMs + elapsed) / 2
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns NAK builder statistics.
func (b *NAKBuilder) GetStats() NAKBuilderStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Copy the map to avoid race conditions
	stats := NAKBuilderStats{
		TotalBuilt:         b.stats.TotalBuilt,
		RateLimited:        b.stats.RateLimited,
		ConstructionErrors: b.stats.ConstructionErrors,
		AvgBuildTimeMs:     b.stats.AvgBuildTimeMs,
		ByReason:           make(map[NAKReason]int64),
	}

	for k, v := range b.stats.ByReason {
		stats.ByReason[k] = v
	}

	return stats
}

// GetNAKRate returns NAKs per minute.
func (b *NAKBuilder) GetNAKRate() float64 {
	// Calculate rate based on recent activity
	return float64(b.stats.TotalBuilt)
}

// GetTopNAKReasons returns the most common NAK reasons.
func (b *NAKBuilder) GetTopNAKReasons() map[string]int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]int64)
	for reason, count := range b.stats.ByReason {
		result[reason.String()] = count
	}
	return result
}

// ============================================================================
// Validation Utilities
// ============================================================================

// ValidateNAKPacket validates a NAK packet structure.
func ValidateNAKPacket(p *DHCPPacket) error {
	if p == nil {
		return errors.New("packet is nil")
	}

	if p.Op != BootReply {
		return errors.New("NAK must be BOOTREPLY")
	}

	// Check for NAK message type option
	hasNAKType := false
	for _, opt := range p.Options {
		if opt.Code == OptMessageType {
			if len(opt.Data) == 1 && opt.Data[0] == DHCPNak {
				hasNAKType = true
				break
			}
		}
	}

	if !hasNAKType {
		return errors.New("missing NAK message type option")
	}

	// NAK should not have yiaddr
	if p.YIAddr != nil && !p.YIAddr.IsUnspecified() {
		return errors.New("NAK should not include yiaddr")
	}

	return nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilNAKRequest is returned when request is nil
	ErrNilNAKRequest = errors.New("NAK request is nil")

	// ErrNAKRateLimited is returned when client exceeded NAK limit
	ErrNAKRateLimited = errors.New("NAK rate limited for this client")

	// ErrNAKConstructionFailed is returned when NAK building fails
	ErrNAKConstructionFailed = errors.New("NAK packet construction failed")
)
