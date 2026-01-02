// Package integration provides external service clients for NIC Management.
package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrNilPacket        = errors.New("packet is nil")
	ErrEmptyPacketData  = errors.New("packet data is empty")
	ErrNotConnected     = errors.New("not connected to TLS Proxy")
	ErrConnectionFailed = errors.New("failed to connect to TLS Proxy")
)

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

const (
	// DefaultTLSProxyAddress is the default TLS Proxy server address
	DefaultTLSProxyAddress = "localhost:50054"

	// DefaultRequestTimeout is the default RPC timeout
	DefaultRequestTimeout = 5 * time.Second
)

// =============================================================================
// gRPC ACTION CONSTANTS
// =============================================================================

const (
	// ActionForward indicates packet should be forwarded unchanged
	ActionForward = "FORWARD"
	// ActionDrop indicates packet should be dropped (Phase 2+)
	ActionDrop = "DROP"
	// ActionModify indicates packet was modified (Phase 2+)
	ActionModify = "MODIFY"
)

// =============================================================================
// PACKET STRUCTURES
// =============================================================================

// CapturedPacket represents a network packet captured by NIC Management.
type CapturedPacket struct {
	ConnectionID    string
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string // "TCP", "UDP", "ICMP"
	Direction       string // "OUTBOUND", "INBOUND"
	RawData         []byte
	InterfaceName   string
	Timestamp       time.Time
}

// InterceptionResult contains the TLS Proxy's decision for a packet.
type InterceptionResult struct {
	Action           string
	PacketData       []byte
	Success          bool
	ErrorMessage     string
	ProcessingTimeMs int64
	SNIHostname      string
	ResolvedIP       string
}

// =============================================================================
// STATISTICS
// =============================================================================

// ClientStats tracks TLS Proxy client metrics.
type ClientStats struct {
	TotalRequests      uint64
	SuccessfulRequests uint64
	FailedRequests     uint64
	TimeoutErrors      uint64
	ConnectionErrors   uint64
	TotalLatency       time.Duration
	PeakLatency        time.Duration
	LastRequestTime    time.Time
}

// AverageLatency returns the mean request duration.
func (s *ClientStats) AverageLatency() time.Duration {
	if s.TotalRequests == 0 {
		return 0
	}
	return s.TotalLatency / time.Duration(s.TotalRequests)
}

// SuccessRate returns the percentage of successful requests.
func (s *ClientStats) SuccessRate() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.SuccessfulRequests) / float64(s.TotalRequests) * 100
}

// =============================================================================
// TLS PROXY CLIENT
// =============================================================================

// TLSProxyClient sends intercepted packets to TLS Proxy for analysis.
type TLSProxyClient struct {
	// serverAddress is the TLS Proxy endpoint
	serverAddress string

	// requestTimeout is the RPC deadline
	requestTimeout time.Duration

	// connection is the gRPC connection
	connection *grpc.ClientConn

	// connected indicates if connection is established
	connected bool

	// stats tracks client metrics
	stats ClientStats

	// mutex protects stats and connected state
	mutex sync.RWMutex
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewTLSProxyClient creates a new client for TLS Proxy communication.
func NewTLSProxyClient(serverAddress string, timeout time.Duration) (*TLSProxyClient, error) {
	if serverAddress == "" {
		serverAddress = DefaultTLSProxyAddress
	}
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}

	client := &TLSProxyClient{
		serverAddress:  serverAddress,
		requestTimeout: timeout,
		stats:          ClientStats{},
	}

	return client, nil
}

// Connect establishes the gRPC connection to TLS Proxy.
func (c *TLSProxyClient) Connect() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.connected {
		return nil
	}

	// Create connection with insecure credentials (localhost only)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.serverAddress, opts...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	c.connection = conn
	c.connected = true
	return nil
}

// =============================================================================
// SEND PACKET
// =============================================================================

// SendPacket sends a captured packet to TLS Proxy for analysis.
// Returns the interception result with forwarding decision.
// Implements fail-open: errors result in FORWARD action.
func (c *TLSProxyClient) SendPacket(packet *CapturedPacket) (*InterceptionResult, error) {
	startTime := time.Now()

	// Validate input
	if packet == nil {
		c.incrementFailed()
		return c.failOpenResult(ErrNilPacket), ErrNilPacket
	}

	if len(packet.RawData) == 0 {
		c.incrementFailed()
		return c.failOpenResult(ErrEmptyPacketData), ErrEmptyPacketData
	}

	// Check connection
	c.mutex.RLock()
	connected := c.connected
	c.mutex.RUnlock()

	if !connected {
		c.incrementConnectionError()
		return c.failOpenResult(ErrNotConnected), ErrNotConnected
	}

	// Create request context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	defer cancel()

	// Format ConnectionID
	connectionID := fmt.Sprintf("%s:%d->%s:%d",
		packet.SourceIP, packet.SourcePort,
		packet.DestinationIP, packet.DestinationPort)

	// In Phase 1, we simulate the gRPC call since proto files aren't generated yet.
	// This will be replaced with actual gRPC client call when protos are compiled.
	result := c.simulateInterceptPacket(ctx, connectionID, packet)

	// Record statistics
	latency := time.Since(startTime)
	c.recordRequest(latency, result.Success)

	return result, nil
}

// simulateInterceptPacket simulates the gRPC call for Phase 1.
// Will be replaced with actual client.InterceptPacket() when protos are generated.
func (c *TLSProxyClient) simulateInterceptPacket(ctx context.Context, connectionID string, packet *CapturedPacket) *InterceptionResult {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		c.incrementTimeout()
		return &InterceptionResult{
			Action:       ActionForward,
			PacketData:   packet.RawData,
			Success:      false,
			ErrorMessage: ctx.Err().Error(),
		}
	default:
	}

	// Phase 1: Always return FORWARD with original packet data
	// TODO: Replace with actual gRPC call: client.InterceptPacket(ctx, &pb.InterceptPacketRequest{ConnectionId: connectionID, ...})
	_ = connectionID // Used when gRPC is enabled
	return &InterceptionResult{
		Action:           ActionForward,
		PacketData:       packet.RawData, // Unchanged
		Success:          true,
		ErrorMessage:     "",
		ProcessingTimeMs: 0,
		SNIHostname:      "", // Would be populated by actual TLS Proxy
		ResolvedIP:       "", // Would be populated by actual TLS Proxy
	}
}

// SendPacketAsync sends a packet asynchronously and returns result via channel.
func (c *TLSProxyClient) SendPacketAsync(packet *CapturedPacket) <-chan *InterceptionResult {
	resultChan := make(chan *InterceptionResult, 1)

	go func() {
		result, _ := c.SendPacket(packet)
		resultChan <- result
		close(resultChan)
	}()

	return resultChan
}

// =============================================================================
// RESULT HELPERS
// =============================================================================

// failOpenResult creates a FORWARD result for error conditions.
// Implements fail-open design: errors don't block packet flow.
func (c *TLSProxyClient) failOpenResult(err error) *InterceptionResult {
	return &InterceptionResult{
		Action:       ActionForward,
		PacketData:   nil, // Caller should use original packet
		Success:      false,
		ErrorMessage: err.Error(),
	}
}

// =============================================================================
// STATISTICS
// =============================================================================

// incrementFailed increments failed request count.
func (c *TLSProxyClient) incrementFailed() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.stats.TotalRequests++
	c.stats.FailedRequests++
	c.stats.LastRequestTime = time.Now()
}

// incrementTimeout increments timeout error count.
func (c *TLSProxyClient) incrementTimeout() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.stats.TimeoutErrors++
}

// incrementConnectionError increments connection error count.
func (c *TLSProxyClient) incrementConnectionError() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.stats.TotalRequests++
	c.stats.FailedRequests++
	c.stats.ConnectionErrors++
	c.stats.LastRequestTime = time.Now()
}

// recordRequest records a completed request.
func (c *TLSProxyClient) recordRequest(latency time.Duration, success bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.stats.TotalRequests++
	c.stats.TotalLatency += latency
	c.stats.LastRequestTime = time.Now()

	if latency > c.stats.PeakLatency {
		c.stats.PeakLatency = latency
	}

	if success {
		c.stats.SuccessfulRequests++
	} else {
		c.stats.FailedRequests++
	}
}

// GetStats returns a copy of client statistics.
func (c *TLSProxyClient) GetStats() ClientStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return ClientStats{
		TotalRequests:      c.stats.TotalRequests,
		SuccessfulRequests: c.stats.SuccessfulRequests,
		FailedRequests:     c.stats.FailedRequests,
		TimeoutErrors:      c.stats.TimeoutErrors,
		ConnectionErrors:   c.stats.ConnectionErrors,
		TotalLatency:       c.stats.TotalLatency,
		PeakLatency:        c.stats.PeakLatency,
		LastRequestTime:    c.stats.LastRequestTime,
	}
}

// =============================================================================
// CONNECTION MANAGEMENT
// =============================================================================

// IsConnected returns whether the client is connected.
func (c *TLSProxyClient) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.connected
}

// Close terminates the gRPC connection.
func (c *TLSProxyClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.connected {
		return nil
	}

	if c.connection != nil {
		if err := c.connection.Close(); err != nil {
			return err
		}
	}

	c.connected = false
	return nil
}

// GetServerAddress returns the configured server address.
func (c *TLSProxyClient) GetServerAddress() string {
	return c.serverAddress
}

// classifyError determines the type of gRPC error.
func classifyError(err error) string {
	if err == nil {
		return ""
	}

	st, ok := status.FromError(err)
	if !ok {
		return "unknown"
	}

	switch st.Code() {
	case codes.DeadlineExceeded:
		return "timeout"
	case codes.Unavailable:
		return "connection"
	case codes.InvalidArgument:
		return "validation"
	case codes.Internal:
		return "internal"
	default:
		return "other"
	}
}
