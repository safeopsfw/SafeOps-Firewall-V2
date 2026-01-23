// Package inspector provides the main packet processing pipeline for the firewall engine.
package inspector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// ============================================================================
// Metadata Stream Handler
// ============================================================================

// MetadataHandler handles the gRPC stream connection to SafeOps Engine
// and feeds packet metadata to the worker pool for processing.
//
// Architecture:
//
//	SafeOps Engine (127.0.0.1:50053)
//	        ↓ (gRPC bidirectional stream)
//	MetadataHandler.receiveLoop()
//	        ↓ (non-blocking send to channel)
//	Packet Channel (buffered, 10K capacity)
//	        ↓ (consumed by worker pool)
//	Worker Pool → Packet Inspector
//
// Features:
//   - Automatic reconnection with exponential backoff
//   - Buffered channel to absorb traffic bursts
//   - Fail-open on channel full (drop packet, log warning)
//   - Graceful shutdown with drain timeout
type MetadataHandler struct {
	// Configuration
	config *HandlerConfig

	// gRPC connection
	conn   *grpc.ClientConn
	client SafeOpsMetadataClient // Interface to SafeOps gRPC client
	stream SafeOpsMetadataStream // The active stream

	// Packet channel (output to worker pool)
	packetChan chan *models.PacketMetadata

	// Statistics
	stats *HandlerStats

	// Reconnection state
	reconnectAttempts atomic.Int32
	lastConnectTime   atomic.Int64

	// Logging
	logger *log.Logger

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	connected atomic.Bool
	running   atomic.Bool
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once
}

// HandlerConfig contains configuration for the metadata handler.
type HandlerConfig struct {
	// gRPC connection
	SafeOpsAddress string        `json:"safeops_address" toml:"safeops_address"`
	ConnectTimeout time.Duration `json:"connect_timeout" toml:"connect_timeout"`
	StreamTimeout  time.Duration `json:"stream_timeout" toml:"stream_timeout"`

	// Reconnection
	ReconnectInitialDelay time.Duration `json:"reconnect_initial_delay" toml:"reconnect_initial_delay"`
	ReconnectMaxDelay     time.Duration `json:"reconnect_max_delay" toml:"reconnect_max_delay"`
	ReconnectMaxAttempts  int           `json:"reconnect_max_attempts" toml:"reconnect_max_attempts"` // 0 = unlimited

	// Channel
	ChannelBufferSize int `json:"channel_buffer_size" toml:"channel_buffer_size"`

	// Keepalive
	KeepaliveTime    time.Duration `json:"keepalive_time" toml:"keepalive_time"`
	KeepaliveTimeout time.Duration `json:"keepalive_timeout" toml:"keepalive_timeout"`

	// Behavior
	DropOnFull bool `json:"drop_on_full" toml:"drop_on_full"` // Drop packets when channel full
}

// DefaultHandlerConfig returns the default configuration.
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		SafeOpsAddress:        "127.0.0.1:50053",
		ConnectTimeout:        10 * time.Second,
		StreamTimeout:         30 * time.Second,
		ReconnectInitialDelay: 1 * time.Second,
		ReconnectMaxDelay:     60 * time.Second,
		ReconnectMaxAttempts:  0, // Unlimited
		ChannelBufferSize:     10000,
		KeepaliveTime:         30 * time.Second,
		KeepaliveTimeout:      10 * time.Second,
		DropOnFull:            true,
	}
}

// Validate checks the configuration.
func (c *HandlerConfig) Validate() error {
	if c.SafeOpsAddress == "" {
		return errors.New("safeops_address is required")
	}
	if c.ChannelBufferSize < 100 {
		return fmt.Errorf("channel_buffer_size must be >= 100, got %d", c.ChannelBufferSize)
	}
	if c.ReconnectInitialDelay < 100*time.Millisecond {
		return errors.New("reconnect_initial_delay must be >= 100ms")
	}
	return nil
}

// HandlerStats contains handler statistics.
type HandlerStats struct {
	PacketsReceived    atomic.Uint64
	PacketsQueued      atomic.Uint64
	PacketsDropped     atomic.Uint64 // Channel full
	StreamErrors       atomic.Uint64
	ReconnectAttempts  atomic.Uint64
	ReconnectSuccesses atomic.Uint64
	ConnectionUptime   atomic.Int64 // Nanoseconds
}

// ============================================================================
// gRPC Client Interfaces (for dependency injection/mocking)
// ============================================================================

// SafeOpsMetadataClient is the interface for the SafeOps gRPC client.
type SafeOpsMetadataClient interface {
	// StreamMetadata opens a bidirectional stream for packet metadata.
	StreamMetadata(ctx context.Context, opts ...grpc.CallOption) (SafeOpsMetadataStream, error)
}

// SafeOpsMetadataStream is the interface for the metadata stream.
type SafeOpsMetadataStream interface {
	// Recv receives the next packet metadata from the stream.
	Recv() (*models.PacketMetadata, error)

	// Send sends a verdict back to SafeOps (if bidirectional).
	Send(*models.VerdictResult) error

	// CloseSend closes the send side of the stream.
	CloseSend() error
}

// ============================================================================
// Constructor
// ============================================================================

// NewMetadataHandler creates a new metadata stream handler.
func NewMetadataHandler(config *HandlerConfig) (*MetadataHandler, error) {
	if config == nil {
		config = DefaultHandlerConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid handler config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &MetadataHandler{
		config:     config,
		packetChan: make(chan *models.PacketMetadata, config.ChannelBufferSize),
		stats:      &HandlerStats{},
		ctx:        ctx,
		cancel:     cancel,
		logger:     log.New(log.Writer(), "[HANDLER] ", log.LstdFlags|log.Lmicroseconds),
	}, nil
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes connection to SafeOps gRPC server.
func (h *MetadataHandler) Connect(ctx context.Context) error {
	if h.closed.Load() {
		return ErrInspectorClosed
	}

	h.logger.Printf("Connecting to SafeOps at %s...", h.config.SafeOpsAddress)

	// Create connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, h.config.ConnectTimeout)
	defer cancel()

	// gRPC dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                h.config.KeepaliveTime,
			Timeout:             h.config.KeepaliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(connectCtx, h.config.SafeOpsAddress, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to SafeOps: %w", err)
	}

	h.conn = conn
	h.connected.Store(true)
	h.lastConnectTime.Store(time.Now().UnixNano())
	h.reconnectAttempts.Store(0)

	h.logger.Printf("Connected to SafeOps at %s", h.config.SafeOpsAddress)
	return nil
}

// Disconnect closes the gRPC connection.
func (h *MetadataHandler) Disconnect() error {
	h.connected.Store(false)

	if h.stream != nil {
		_ = h.stream.CloseSend()
		h.stream = nil
	}

	if h.conn != nil {
		err := h.conn.Close()
		h.conn = nil
		return err
	}

	return nil
}

// IsConnected returns true if connected to SafeOps.
func (h *MetadataHandler) IsConnected() bool {
	return h.connected.Load()
}

// ============================================================================
// Stream Management
// ============================================================================

// Start begins receiving packets from SafeOps.
func (h *MetadataHandler) Start(ctx context.Context) error {
	if h.running.Load() {
		return errors.New("handler already running")
	}

	// Connect if not already connected
	if !h.connected.Load() {
		if err := h.Connect(ctx); err != nil {
			return fmt.Errorf("initial connection failed: %w", err)
		}
	}

	h.running.Store(true)

	// Start receive loop
	h.wg.Add(1)
	go h.receiveLoop()

	h.logger.Println("Handler started, receiving packets...")
	return nil
}

// receiveLoop continuously receives packets from the stream.
func (h *MetadataHandler) receiveLoop() {
	defer h.wg.Done()
	defer h.running.Store(false)

	backoff := h.config.ReconnectInitialDelay

	for {
		select {
		case <-h.ctx.Done():
			h.logger.Println("Receive loop shutting down...")
			return
		default:
		}

		// Ensure we have a stream
		if err := h.ensureStream(); err != nil {
			h.logger.Printf("Failed to establish stream: %v", err)
			h.stats.StreamErrors.Add(1)

			// Reconnection backoff
			select {
			case <-h.ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff
			backoff = h.nextBackoff(backoff)
			continue
		}

		// Reset backoff on successful stream
		backoff = h.config.ReconnectInitialDelay

		// Receive packets
		h.receivePackets()
	}
}

// ensureStream ensures we have an active stream.
func (h *MetadataHandler) ensureStream() error {
	// If we have a stream, it's good
	if h.stream != nil {
		return nil
	}

	// Ensure connection
	if !h.connected.Load() {
		if err := h.Connect(h.ctx); err != nil {
			h.stats.ReconnectAttempts.Add(1)
			return fmt.Errorf("reconnection failed: %w", err)
		}
		h.stats.ReconnectSuccesses.Add(1)
	}

	// Open stream
	if h.client != nil {
		stream, err := h.client.StreamMetadata(h.ctx)
		if err != nil {
			return fmt.Errorf("failed to open stream: %w", err)
		}
		h.stream = stream
		h.logger.Println("Metadata stream established")
	} else {
		// No client set - this is for testing or when using mock
		return errors.New("no gRPC client configured")
	}

	return nil
}

// receivePackets receives packets until error or shutdown.
func (h *MetadataHandler) receivePackets() {
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		if h.stream == nil {
			return
		}

		// Receive packet
		packet, err := h.stream.Recv()
		if err != nil {
			h.handleStreamError(err)
			return
		}

		h.stats.PacketsReceived.Add(1)

		// Send to channel
		h.queuePacket(packet)
	}
}

// queuePacket sends a packet to the channel.
func (h *MetadataHandler) queuePacket(packet *models.PacketMetadata) {
	if packet == nil {
		return
	}

	select {
	case h.packetChan <- packet:
		h.stats.PacketsQueued.Add(1)
	default:
		// Channel full
		if h.config.DropOnFull {
			h.stats.PacketsDropped.Add(1)
			// Log periodically (not every packet)
			if h.stats.PacketsDropped.Load()%1000 == 1 {
				h.logger.Printf("WARNING: Packet channel full, dropped %d packets",
					h.stats.PacketsDropped.Load())
			}
		} else {
			// Block until space available
			select {
			case h.packetChan <- packet:
				h.stats.PacketsQueued.Add(1)
			case <-h.ctx.Done():
				return
			}
		}
	}
}

// handleStreamError handles stream errors and resets state.
func (h *MetadataHandler) handleStreamError(err error) {
	if err == io.EOF {
		h.logger.Println("Stream closed by server (EOF)")
	} else if status.Code(err) == codes.Canceled {
		h.logger.Println("Stream canceled (shutting down)")
		return
	} else if status.Code(err) == codes.Unavailable {
		h.logger.Println("SafeOps server unavailable, will reconnect...")
	} else {
		h.logger.Printf("Stream error: %v", err)
	}

	h.stats.StreamErrors.Add(1)
	h.stream = nil
	h.connected.Store(false)
}

// nextBackoff calculates the next backoff duration.
func (h *MetadataHandler) nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > h.config.ReconnectMaxDelay {
		next = h.config.ReconnectMaxDelay
	}
	return next
}

// ============================================================================
// Channel Access
// ============================================================================

// GetPacketChannel returns the packet channel for workers to consume.
func (h *MetadataHandler) GetPacketChannel() <-chan *models.PacketMetadata {
	return h.packetChan
}

// ReceivePacket blocks until a packet is received.
func (h *MetadataHandler) ReceivePacket(ctx context.Context) (*models.PacketMetadata, error) {
	select {
	case packet := <-h.packetChan:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.ctx.Done():
		return nil, ErrStreamDisconnected
	}
}

// GetQueueSize returns the current queue size.
func (h *MetadataHandler) GetQueueSize() int {
	return len(h.packetChan)
}

// GetQueueCapacity returns the queue capacity.
func (h *MetadataHandler) GetQueueCapacity() int {
	return cap(h.packetChan)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns handler statistics.
func (h *MetadataHandler) GetStats() map[string]uint64 {
	// Calculate uptime
	uptime := uint64(0)
	if h.connected.Load() {
		connectTime := h.lastConnectTime.Load()
		if connectTime > 0 {
			uptime = uint64(time.Now().UnixNano() - connectTime)
		}
	}

	return map[string]uint64{
		"packets_received":     h.stats.PacketsReceived.Load(),
		"packets_queued":       h.stats.PacketsQueued.Load(),
		"packets_dropped":      h.stats.PacketsDropped.Load(),
		"stream_errors":        h.stats.StreamErrors.Load(),
		"reconnect_attempts":   h.stats.ReconnectAttempts.Load(),
		"reconnect_successes":  h.stats.ReconnectSuccesses.Load(),
		"queue_size":           uint64(len(h.packetChan)),
		"queue_capacity":       uint64(cap(h.packetChan)),
		"connection_uptime_ns": uptime,
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Stop gracefully stops the handler.
func (h *MetadataHandler) Stop() error {
	h.closeOnce.Do(func() {
		h.closeMu.Lock()
		defer h.closeMu.Unlock()

		h.logger.Println("Stopping handler...")
		h.closed.Store(true)

		// Cancel context to stop loops
		h.cancel()

		// Wait for goroutines with timeout
		done := make(chan struct{})
		go func() {
			h.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			h.logger.Println("Handler stopped gracefully")
		case <-time.After(5 * time.Second):
			h.logger.Println("Handler stop timed out")
		}

		// Disconnect
		_ = h.Disconnect()

		// Close channel
		close(h.packetChan)

		// Log final stats
		stats := h.GetStats()
		h.logger.Printf("Final stats: received=%d, queued=%d, dropped=%d, errors=%d",
			stats["packets_received"],
			stats["packets_queued"],
			stats["packets_dropped"],
			stats["stream_errors"],
		)
	})

	return nil
}

// IsRunning returns true if the handler is running.
func (h *MetadataHandler) IsRunning() bool {
	return h.running.Load() && !h.closed.Load()
}

// ============================================================================
// Dependency Injection
// ============================================================================

// SetClient sets the gRPC client (for dependency injection/testing).
func (h *MetadataHandler) SetClient(client SafeOpsMetadataClient) {
	h.client = client
}

// SetLogger sets a custom logger.
func (h *MetadataHandler) SetLogger(logger *log.Logger) {
	if logger != nil {
		h.logger = logger
	}
}

// GetConfig returns the current configuration.
func (h *MetadataHandler) GetConfig() *HandlerConfig {
	return h.config
}

// ============================================================================
// Mock Stream for Testing
// ============================================================================

// MockMetadataStream is a mock implementation for testing.
type MockMetadataStream struct {
	packets  []*models.PacketMetadata
	index    int
	mu       sync.Mutex
	sendFunc func(*models.VerdictResult) error
}

// NewMockMetadataStream creates a mock stream with predefined packets.
func NewMockMetadataStream(packets []*models.PacketMetadata) *MockMetadataStream {
	return &MockMetadataStream{
		packets: packets,
	}
}

// Recv returns the next packet from the mock.
func (m *MockMetadataStream) Recv() (*models.PacketMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.index >= len(m.packets) {
		return nil, io.EOF
	}

	pkt := m.packets[m.index]
	m.index++
	return pkt, nil
}

// Send handles sending verdicts (mock).
func (m *MockMetadataStream) Send(verdict *models.VerdictResult) error {
	if m.sendFunc != nil {
		return m.sendFunc(verdict)
	}
	return nil
}

// CloseSend closes the send side.
func (m *MockMetadataStream) CloseSend() error {
	return nil
}

// AddPacket adds a packet to the mock stream.
func (m *MockMetadataStream) AddPacket(packet *models.PacketMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = append(m.packets, packet)
}

// Reset resets the mock stream.
func (m *MockMetadataStream) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.index = 0
}
