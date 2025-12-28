// Package server implements the DHCP server core components.
// This file implements the UDP network listener for DHCP packets.
package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Listener Configuration
// ============================================================================

// ListenerConfig holds UDP listener settings.
type ListenerConfig struct {
	ListenAddress string
	Port          int
	BufferSize    int
	ReadTimeout   time.Duration
	ReuseAddress  bool
}

// DefaultListenerConfig returns sensible defaults.
func DefaultListenerConfig() *ListenerConfig {
	return &ListenerConfig{
		ListenAddress: "0.0.0.0",
		Port:          67, // Standard DHCP server port
		BufferSize:    4096,
		ReadTimeout:   0, // No timeout - block indefinitely
		ReuseAddress:  true,
	}
}

// ============================================================================
// DHCP Constants
// ============================================================================

const (
	// DHCPServerPort is the standard DHCP server port
	DHCPServerPort = 67
	// DHCPClientPort is the standard DHCP client port
	DHCPClientPort = 68
	// MinDHCPPacketSize is the minimum valid DHCP packet size
	MinDHCPPacketSize = 240
	// MaxDHCPPacketSize is the maximum DHCP packet size
	MaxDHCPPacketSize = 4096
	// DHCPMagicCookie is the DHCP options magic cookie
	DHCPMagicCookie = 0x63825363
)

// ============================================================================
// Packet Handler Interface
// ============================================================================

// PacketHandler defines the interface for processing DHCP packets.
type PacketHandler interface {
	HandleDHCPPacket(ctx context.Context, data []byte, clientAddr *net.UDPAddr) error
}

// ============================================================================
// UDP Listener
// ============================================================================

// UDPListener listens for DHCP packets on UDP port 67.
type UDPListener struct {
	mu     sync.RWMutex
	config *ListenerConfig

	// Network
	conn *net.UDPConn
	addr *net.UDPAddr

	// Handler
	handler PacketHandler

	// Lifecycle
	running  atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Statistics
	stats ListenerStats
}

// ListenerStats tracks listener metrics.
type ListenerStats struct {
	PacketsReceived  int64
	PacketsProcessed int64
	PacketsDropped   int64
	InvalidPackets   int64
	ProcessingErrors int64
	BytesReceived    int64
	LastPacketTime   time.Time
	StartTime        time.Time
}

// ReceivedPacket contains a received DHCP packet.
type ReceivedPacket struct {
	Data       []byte
	ClientAddr *net.UDPAddr
	ReceivedAt time.Time
}

// ============================================================================
// Listener Creation
// ============================================================================

// NewUDPListener creates a new UDP listener.
func NewUDPListener(config *ListenerConfig) *UDPListener {
	if config == nil {
		config = DefaultListenerConfig()
	}

	return &UDPListener{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// SetPacketHandler sets the packet handler.
func (l *UDPListener) SetPacketHandler(handler PacketHandler) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handler = handler
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the UDP listener.
func (l *UDPListener) Start(ctx context.Context) error {
	if l.running.Load() {
		return ErrListenerAlreadyRunning
	}

	// Resolve listen address
	addr := &net.UDPAddr{
		IP:   net.ParseIP(l.config.ListenAddress),
		Port: l.config.Port,
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}

	// Set socket options
	if err := l.configureSocket(conn); err != nil {
		conn.Close()
		return err
	}

	l.conn = conn
	l.addr = addr
	l.running.Store(true)
	l.stopChan = make(chan struct{})
	l.stats.StartTime = time.Now()

	// Start packet reception loop
	l.wg.Add(1)
	go l.receiveLoop(ctx)

	return nil
}

// Stop stops the UDP listener.
func (l *UDPListener) Stop() error {
	if !l.running.Load() {
		return nil
	}

	// Signal stop
	close(l.stopChan)

	// Close connection to unblock reads
	if l.conn != nil {
		l.conn.Close()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(5 * time.Second):
		// Timeout waiting for goroutines
	}

	l.running.Store(false)
	return nil
}

// ============================================================================
// Socket Configuration
// ============================================================================

func (l *UDPListener) configureSocket(conn *net.UDPConn) error {
	// Set read buffer size
	if err := conn.SetReadBuffer(l.config.BufferSize * 10); err != nil {
		// Log warning but continue - default buffer may be sufficient
		_ = err
	}

	// Set write buffer size
	if err := conn.SetWriteBuffer(l.config.BufferSize * 10); err != nil {
		_ = err
	}

	// Set read timeout if configured
	if l.config.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(l.config.ReadTimeout)); err != nil {
			_ = err
		}
	}

	return nil
}

// ============================================================================
// Packet Reception Loop
// ============================================================================

func (l *UDPListener) receiveLoop(ctx context.Context) {
	defer l.wg.Done()

	buffer := make([]byte, l.config.BufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopChan:
			return
		default:
		}

		// Read packet from UDP socket
		n, clientAddr, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			if l.handleReadError(err) {
				continue
			}
			return
		}

		// Update statistics
		atomic.AddInt64(&l.stats.PacketsReceived, 1)
		atomic.AddInt64(&l.stats.BytesReceived, int64(n))
		l.stats.LastPacketTime = time.Now()

		// Copy packet data to avoid buffer reuse issues
		packetData := make([]byte, n)
		copy(packetData, buffer[:n])

		// Validate packet
		if !l.validatePacket(packetData) {
			atomic.AddInt64(&l.stats.InvalidPackets, 1)
			continue
		}

		// Process packet concurrently
		l.wg.Add(1)
		go l.processPacket(ctx, packetData, clientAddr)
	}
}

func (l *UDPListener) handleReadError(err error) bool {
	// Check if listener is stopping
	select {
	case <-l.stopChan:
		return false
	default:
	}

	// Check for temporary errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Timeout - continue listening
		return true
	}

	// Check for closed connection
	if errors.Is(err, net.ErrClosed) {
		return false
	}

	// Log other errors and continue
	atomic.AddInt64(&l.stats.ProcessingErrors, 1)
	return true
}

// ============================================================================
// Packet Validation
// ============================================================================

func (l *UDPListener) validatePacket(data []byte) bool {
	// Check minimum size
	if len(data) < MinDHCPPacketSize {
		return false
	}

	// Check maximum size
	if len(data) > MaxDHCPPacketSize {
		return false
	}

	// Validate magic cookie at offset 236 (after BOOTP header)
	if len(data) >= 240 {
		cookie := uint32(data[236])<<24 | uint32(data[237])<<16 | uint32(data[238])<<8 | uint32(data[239])
		if cookie != DHCPMagicCookie {
			return false
		}
	}

	return true
}

// ============================================================================
// Packet Processing
// ============================================================================

func (l *UDPListener) processPacket(ctx context.Context, data []byte, clientAddr *net.UDPAddr) {
	defer l.wg.Done()

	l.mu.RLock()
	handler := l.handler
	l.mu.RUnlock()

	if handler == nil {
		atomic.AddInt64(&l.stats.PacketsDropped, 1)
		return
	}

	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Handle packet
	err := handler.HandleDHCPPacket(processCtx, data, clientAddr)
	if err != nil {
		atomic.AddInt64(&l.stats.ProcessingErrors, 1)
		return
	}

	atomic.AddInt64(&l.stats.PacketsProcessed, 1)
}

// ============================================================================
// Status Methods
// ============================================================================

// IsRunning returns whether the listener is running.
func (l *UDPListener) IsRunning() bool {
	return l.running.Load()
}

// GetStats returns listener statistics.
func (l *UDPListener) GetStats() ListenerStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return ListenerStats{
		PacketsReceived:  atomic.LoadInt64(&l.stats.PacketsReceived),
		PacketsProcessed: atomic.LoadInt64(&l.stats.PacketsProcessed),
		PacketsDropped:   atomic.LoadInt64(&l.stats.PacketsDropped),
		InvalidPackets:   atomic.LoadInt64(&l.stats.InvalidPackets),
		ProcessingErrors: atomic.LoadInt64(&l.stats.ProcessingErrors),
		BytesReceived:    atomic.LoadInt64(&l.stats.BytesReceived),
		LastPacketTime:   l.stats.LastPacketTime,
		StartTime:        l.stats.StartTime,
	}
}

// GetLocalAddr returns the local address the listener is bound to.
func (l *UDPListener) GetLocalAddr() *net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.addr
}

// GetConnection returns the underlying UDP connection.
func (l *UDPListener) GetConnection() *net.UDPConn {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.conn
}

// GetPacketRate returns packets per second.
func (l *UDPListener) GetPacketRate() float64 {
	uptime := time.Since(l.stats.StartTime).Seconds()
	if uptime == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&l.stats.PacketsReceived)) / uptime
}

// GetSuccessRate returns processing success rate.
func (l *UDPListener) GetSuccessRate() float64 {
	received := atomic.LoadInt64(&l.stats.PacketsReceived)
	if received == 0 {
		return 100.0
	}
	processed := atomic.LoadInt64(&l.stats.PacketsProcessed)
	return float64(processed) / float64(received) * 100
}

// ============================================================================
// Health Check
// ============================================================================

// ListenerHealthStatus contains listener health information.
type ListenerHealthStatus struct {
	Running         bool
	ListenAddress   string
	Uptime          time.Duration
	PacketsReceived int64
	PacketRate      float64
	SuccessRate     float64
	LastPacketAge   time.Duration
}

// GetHealthStatus returns listener health status.
func (l *UDPListener) GetHealthStatus() *ListenerHealthStatus {
	status := &ListenerHealthStatus{
		Running:         l.running.Load(),
		PacketsReceived: atomic.LoadInt64(&l.stats.PacketsReceived),
		PacketRate:      l.GetPacketRate(),
		SuccessRate:     l.GetSuccessRate(),
	}

	if l.addr != nil {
		status.ListenAddress = l.addr.String()
	}

	if !l.stats.StartTime.IsZero() {
		status.Uptime = time.Since(l.stats.StartTime)
	}

	if !l.stats.LastPacketTime.IsZero() {
		status.LastPacketAge = time.Since(l.stats.LastPacketTime)
	}

	return status
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrListenerAlreadyRunning is returned when listener already running
	ErrListenerAlreadyRunning = errors.New("listener already running")

	// ErrListenerNotRunning is returned when listener not running
	ErrListenerNotRunning = errors.New("listener not running")

	// ErrNoPacketHandler is returned when no packet handler set
	ErrNoPacketHandler = errors.New("no packet handler configured")

	// ErrInvalidPacket is returned for invalid DHCP packets
	ErrInvalidPacket = errors.New("invalid DHCP packet")

	// ErrBindFailed is returned when port binding fails
	ErrBindFailed = errors.New("failed to bind to DHCP port")
)
