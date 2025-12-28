// Package server implements the DHCP server core components.
// This file implements the UDP packet sender for DHCP responses.
package server

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Sender Configuration
// ============================================================================

// SenderConfig holds UDP sender settings.
type SenderConfig struct {
	MaxRetries     int
	RetryInterval  time.Duration
	SendTimeout    time.Duration
	ValidatePacket bool
}

// DefaultSenderConfig returns sensible defaults.
func DefaultSenderConfig() *SenderConfig {
	return &SenderConfig{
		MaxRetries:     3,
		RetryInterval:  100 * time.Millisecond,
		SendTimeout:    time.Second,
		ValidatePacket: true,
	}
}

// ============================================================================
// Send Request
// ============================================================================

// SendRequest contains information needed to send a DHCP response.
type SendRequest struct {
	Data          []byte
	ClientAddr    *net.UDPAddr
	ClientMAC     net.HardwareAddr
	ClientIP      net.IP
	RelayAgentIP  net.IP
	GatewayIP     net.IP
	BroadcastFlag bool
	MessageType   string
	TransactionID uint32
}

// SendResult contains the result of a send operation.
type SendResult struct {
	Success     bool
	Destination *net.UDPAddr
	Method      string // "broadcast", "unicast", "relay"
	BytesSent   int
	RetryCount  int
	Duration    time.Duration
	Error       error
}

// ============================================================================
// UDP Sender
// ============================================================================

// UDPSender sends DHCP response packets.
type UDPSender struct {
	mu     sync.RWMutex
	config *SenderConfig

	// Connection (shared with listener)
	conn *net.UDPConn

	// Statistics
	stats SenderStats
}

// SenderStats tracks sender metrics.
type SenderStats struct {
	PacketsSent    int64
	BroadcastsSent int64
	UnicastsSent   int64
	RelaysSent     int64
	SendErrors     int64
	RetryAttempts  int64
	BytesSent      int64
	LastSendTime   time.Time
}

// ============================================================================
// Sender Creation
// ============================================================================

// NewUDPSender creates a new UDP sender.
func NewUDPSender(config *SenderConfig) *UDPSender {
	if config == nil {
		config = DefaultSenderConfig()
	}

	return &UDPSender{
		config: config,
	}
}

// SetConnection sets the UDP connection (shared with listener).
func (s *UDPSender) SetConnection(conn *net.UDPConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
}

// ============================================================================
// Send Response
// ============================================================================

// SendResponse sends a DHCP response packet.
func (s *UDPSender) SendResponse(req *SendRequest) (*SendResult, error) {
	if req == nil {
		return nil, ErrNilSendRequest
	}

	if len(req.Data) == 0 {
		return nil, ErrEmptyPacket
	}

	startTime := time.Now()
	result := &SendResult{
		Method: "unknown",
	}

	// Validate packet if enabled
	if s.config.ValidatePacket {
		if err := s.validatePacket(req.Data); err != nil {
			result.Error = err
			return result, err
		}
	}

	// Determine destination
	destAddr, method := s.determineDestination(req)
	result.Destination = destAddr
	result.Method = method

	// Send with retry
	bytesSent, retries, err := s.sendWithRetry(req.Data, destAddr)
	result.BytesSent = bytesSent
	result.RetryCount = retries
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Error = err
		atomic.AddInt64(&s.stats.SendErrors, 1)
		return result, err
	}

	// Update statistics
	result.Success = true
	atomic.AddInt64(&s.stats.PacketsSent, 1)
	atomic.AddInt64(&s.stats.BytesSent, int64(bytesSent))
	s.updateMethodStats(method)
	s.stats.LastSendTime = time.Now()

	return result, nil
}

// ============================================================================
// Destination Determination
// ============================================================================

func (s *UDPSender) determineDestination(req *SendRequest) (*net.UDPAddr, string) {
	// Check for relay agent (giaddr non-zero)
	if len(req.RelayAgentIP) > 0 && !req.RelayAgentIP.IsUnspecified() {
		return &net.UDPAddr{
			IP:   req.RelayAgentIP,
			Port: DHCPServerPort, // Relay receives on port 67
		}, "relay"
	}

	// Check for gateway IP (alternative relay field)
	if len(req.GatewayIP) > 0 && !req.GatewayIP.IsUnspecified() {
		return &net.UDPAddr{
			IP:   req.GatewayIP,
			Port: DHCPServerPort,
		}, "relay"
	}

	// Determine broadcast vs unicast
	shouldBroadcast := s.shouldBroadcast(req)

	if shouldBroadcast {
		return &net.UDPAddr{
			IP:   net.IPv4bcast, // 255.255.255.255
			Port: DHCPClientPort,
		}, "broadcast"
	}

	// Unicast to client
	destIP := req.ClientIP
	if destIP == nil || destIP.IsUnspecified() {
		// Fallback to broadcast if no client IP
		return &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: DHCPClientPort,
		}, "broadcast"
	}

	return &net.UDPAddr{
		IP:   destIP,
		Port: DHCPClientPort,
	}, "unicast"
}

func (s *UDPSender) shouldBroadcast(req *SendRequest) bool {
	// Broadcast flag set - always broadcast
	if req.BroadcastFlag {
		return true
	}

	// No client IP - must broadcast
	if req.ClientIP == nil || req.ClientIP.IsUnspecified() {
		return true
	}

	// Client IP is 0.0.0.0 - must broadcast
	if req.ClientIP.Equal(net.IPv4zero) {
		return true
	}

	// OFFER messages typically broadcast
	if req.MessageType == "OFFER" {
		return true
	}

	// NAK messages must broadcast
	if req.MessageType == "NAK" {
		return true
	}

	// Otherwise unicast
	return false
}

// ============================================================================
// Send with Retry
// ============================================================================

func (s *UDPSender) sendWithRetry(data []byte, destAddr *net.UDPAddr) (int, int, error) {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return 0, 0, ErrNoConnection
	}

	var lastErr error
	retries := 0

	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			retries++
			atomic.AddInt64(&s.stats.RetryAttempts, 1)
			time.Sleep(s.config.RetryInterval * time.Duration(attempt))
		}

		// Set write deadline
		if s.config.SendTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(s.config.SendTimeout))
		}

		n, err := conn.WriteToUDP(data, destAddr)
		if err == nil {
			return n, retries, nil
		}

		lastErr = err

		// Check if error is retryable
		if !s.isRetryableError(err) {
			break
		}
	}

	return 0, retries, lastErr
}

func (s *UDPSender) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for temporary network errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Some errors are not retryable
	if errors.Is(err, net.ErrClosed) {
		return false
	}

	return true
}

// ============================================================================
// Packet Validation
// ============================================================================

func (s *UDPSender) validatePacket(data []byte) error {
	// Check minimum size
	if len(data) < MinDHCPPacketSize {
		return ErrPacketTooSmall
	}

	// Check maximum size
	if len(data) > MaxDHCPPacketSize {
		return ErrPacketTooLarge
	}

	// Validate magic cookie
	if len(data) >= 240 {
		cookie := uint32(data[236])<<24 | uint32(data[237])<<16 | uint32(data[238])<<8 | uint32(data[239])
		if cookie != DHCPMagicCookie {
			return ErrInvalidMagicCookie
		}
	}

	// Validate op code (should be BOOTREPLY = 2 for responses)
	if data[0] != 2 {
		return ErrInvalidOpCode
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

func (s *UDPSender) updateMethodStats(method string) {
	switch method {
	case "broadcast":
		atomic.AddInt64(&s.stats.BroadcastsSent, 1)
	case "unicast":
		atomic.AddInt64(&s.stats.UnicastsSent, 1)
	case "relay":
		atomic.AddInt64(&s.stats.RelaysSent, 1)
	}
}

// GetStats returns sender statistics.
func (s *UDPSender) GetStats() SenderStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return SenderStats{
		PacketsSent:    atomic.LoadInt64(&s.stats.PacketsSent),
		BroadcastsSent: atomic.LoadInt64(&s.stats.BroadcastsSent),
		UnicastsSent:   atomic.LoadInt64(&s.stats.UnicastsSent),
		RelaysSent:     atomic.LoadInt64(&s.stats.RelaysSent),
		SendErrors:     atomic.LoadInt64(&s.stats.SendErrors),
		RetryAttempts:  atomic.LoadInt64(&s.stats.RetryAttempts),
		BytesSent:      atomic.LoadInt64(&s.stats.BytesSent),
		LastSendTime:   s.stats.LastSendTime,
	}
}

// GetSuccessRate returns transmission success rate.
func (s *UDPSender) GetSuccessRate() float64 {
	sent := atomic.LoadInt64(&s.stats.PacketsSent)
	errors := atomic.LoadInt64(&s.stats.SendErrors)
	total := sent + errors
	if total == 0 {
		return 100.0
	}
	return float64(sent) / float64(total) * 100
}

// GetBroadcastRatio returns percentage of broadcasts.
func (s *UDPSender) GetBroadcastRatio() float64 {
	total := atomic.LoadInt64(&s.stats.PacketsSent)
	if total == 0 {
		return 0
	}
	broadcasts := atomic.LoadInt64(&s.stats.BroadcastsSent)
	return float64(broadcasts) / float64(total) * 100
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilSendRequest is returned when send request is nil
	ErrNilSendRequest = errors.New("send request is nil")

	// ErrEmptyPacket is returned when packet data is empty
	ErrEmptyPacket = errors.New("packet data is empty")

	// ErrNoConnection is returned when no UDP connection available
	ErrNoConnection = errors.New("no UDP connection available")

	// ErrPacketTooSmall is returned when packet is too small
	ErrPacketTooSmall = errors.New("packet too small for DHCP")

	// ErrPacketTooLarge is returned when packet is too large
	ErrPacketTooLarge = errors.New("packet too large for DHCP")

	// ErrInvalidMagicCookie is returned when magic cookie is invalid
	ErrInvalidMagicCookie = errors.New("invalid DHCP magic cookie")

	// ErrInvalidOpCode is returned when op code is invalid
	ErrInvalidOpCode = errors.New("invalid DHCP op code for response")

	// ErrSendFailed is returned when send fails
	ErrSendFailed = errors.New("failed to send DHCP packet")
)
