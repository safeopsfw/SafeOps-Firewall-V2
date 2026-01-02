// Package grpc implements the gRPC server for TLS Proxy packet interception.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"tls_proxy/internal/config"
	"tls_proxy/internal/forwarder"
	"tls_proxy/internal/models"
	"tls_proxy/internal/processor"
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrNilRequest      = errors.New("request is nil")
	ErrEmptyPacketData = errors.New("packet data is empty")
	ErrMissingFields   = errors.New("required fields missing")
	ErrServerNotReady  = errors.New("server not ready")
)

// =============================================================================
// STATISTICS
// =============================================================================

// ServiceStats tracks gRPC service metrics.
type ServiceStats struct {
	// TotalRequests is the count of all InterceptPacket invocations
	TotalRequests uint64

	// SuccessfulResponses is successful InterceptPacketResponse returns
	SuccessfulResponses uint64

	// ErrorResponses is gRPC error status returns
	ErrorResponses uint64

	// TotalLatency is cumulative request processing time
	TotalLatency time.Duration

	// ActiveRequests is current in-flight handlers
	ActiveRequests int32

	// PeakActiveRequests is maximum concurrent requests observed
	PeakActiveRequests int32

	// LastRequestTime is timestamp of last processed request
	LastRequestTime time.Time
}

// AverageLatency returns the mean request duration.
func (s *ServiceStats) AverageLatency() time.Duration {
	if s.TotalRequests == 0 {
		return 0
	}
	return s.TotalLatency / time.Duration(s.TotalRequests)
}

// SuccessRate returns the percentage of successful responses.
func (s *ServiceStats) SuccessRate() float64 {
	total := s.SuccessfulResponses + s.ErrorResponses
	if total == 0 {
		return 0
	}
	return float64(s.SuccessfulResponses) / float64(total) * 100
}

// =============================================================================
// INTERCEPT PACKET REQUEST/RESPONSE
// =============================================================================

// InterceptPacketRequest represents an incoming packet interception request.
// This mirrors the gRPC InterceptPacketRequest protobuf message.
type InterceptPacketRequest struct {
	ConnectionID    string
	SourceIP        string
	DestinationIP   string
	SourcePort      int32
	DestinationPort int32
	Protocol        string
	Direction       string
	PacketData      []byte
	InterfaceName   string
}

// InterceptPacketResponse represents the response sent back to NIC Management.
// This mirrors the gRPC InterceptPacketResponse protobuf message.
type InterceptPacketResponse struct {
	Action           string
	PacketData       []byte
	Success          bool
	ErrorMessage     string
	ProcessingTimeMs int64
	SNIHostname      string
	ResolvedIP       string
}

// =============================================================================
// TLS PROXY SERVICE
// =============================================================================

// TLSProxyService implements the gRPC service for packet interception.
type TLSProxyService struct {
	// config contains service configuration
	config *config.Config

	// processor handles packet analysis
	processor *processor.PacketProcessor

	// forwarder generates responses
	forwarder *forwarder.PacketForwarder

	// server is the gRPC server instance
	server *grpc.Server

	// listener is the TCP listener
	listener net.Listener

	// running indicates if server is accepting connections
	running bool
	runMu   sync.RWMutex

	// stats tracks service metrics
	stats   ServiceStats
	statsMu sync.RWMutex

	// activeRequests tracks in-flight requests
	activeRequests int32
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewTLSProxyService creates a new gRPC service with all dependencies.
func NewTLSProxyService(
	cfg *config.Config,
	proc *processor.PacketProcessor,
	fwd *forwarder.PacketForwarder,
) *TLSProxyService {
	// Create gRPC server with options
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(cfg.MaxPacketSize + 1024), // Packet + headers
		grpc.MaxSendMsgSize(cfg.MaxPacketSize + 1024),
	}

	return &TLSProxyService{
		config:    cfg,
		processor: proc,
		forwarder: fwd,
		server:    grpc.NewServer(serverOpts...),
		stats:     ServiceStats{},
	}
}

// =============================================================================
// INTERCEPT PACKET HANDLER
// =============================================================================

// InterceptPacket handles a single packet interception request.
// This is the core RPC handler called for every packet from NIC Management.
func (s *TLSProxyService) InterceptPacket(ctx context.Context, req *InterceptPacketRequest) (*InterceptPacketResponse, error) {
	startTime := time.Now()

	// Track active requests
	active := atomic.AddInt32(&s.activeRequests, 1)
	defer atomic.AddInt32(&s.activeRequests, -1)

	// Update peak active requests
	s.updatePeakActive(active)

	// Increment total requests
	s.incrementRequests()

	// Step 1: Validate Request
	if req == nil {
		s.incrementErrors()
		return s.buildErrorResponse(ErrNilRequest, time.Since(startTime)), nil
	}

	if len(req.PacketData) == 0 {
		s.incrementErrors()
		return s.buildErrorResponse(ErrEmptyPacketData, time.Since(startTime)), nil
	}

	// Step 2: Check context for cancellation
	select {
	case <-ctx.Done():
		s.incrementErrors()
		return s.buildErrorResponse(ctx.Err(), time.Since(startTime)), nil
	default:
	}

	// Step 3: Create Internal Packet Model
	packet := &models.Packet{
		ConnectionID:    req.ConnectionID,
		SourceIP:        req.SourceIP,
		DestinationIP:   req.DestinationIP,
		SourcePort:      int(req.SourcePort),
		DestinationPort: int(req.DestinationPort),
		Protocol:        req.Protocol,
		Direction:       req.Direction,
		RawData:         req.PacketData,
		Timestamp:       time.Now(),
		InterfaceName:   req.InterfaceName,
	}

	// Step 4: Invoke Processor
	result, err := s.processor.Process(packet)
	if err != nil {
		// Log error but continue with pass-through
		// Don't return error - forward packet unchanged
	}

	// Step 5: Invoke Forwarder
	var response *InterceptPacketResponse
	if result != nil {
		fwdResponse, fwdErr := s.forwarder.Forward(result, packet)
		if fwdErr != nil {
			s.incrementErrors()
			return s.buildErrorResponse(fwdErr, time.Since(startTime)), nil
		}
		response = s.convertForwardResponse(fwdResponse, time.Since(startTime))
	} else {
		// Fallback: forward unchanged
		response = s.buildPassThroughResponse(packet, time.Since(startTime))
	}

	// Step 6: Record Success
	s.recordSuccess(time.Since(startTime))

	return response, nil
}

// =============================================================================
// RESPONSE BUILDERS
// =============================================================================

// buildErrorResponse creates an error response.
func (s *TLSProxyService) buildErrorResponse(err error, duration time.Duration) *InterceptPacketResponse {
	return &InterceptPacketResponse{
		Action:           forwarder.GRPCActionForward,
		PacketData:       nil,
		Success:          false,
		ErrorMessage:     err.Error(),
		ProcessingTimeMs: duration.Milliseconds(),
	}
}

// buildPassThroughResponse creates a pass-through response for fallback.
func (s *TLSProxyService) buildPassThroughResponse(packet *models.Packet, duration time.Duration) *InterceptPacketResponse {
	return &InterceptPacketResponse{
		Action:           forwarder.GRPCActionForward,
		PacketData:       packet.RawData,
		Success:          true,
		ErrorMessage:     "",
		ProcessingTimeMs: duration.Milliseconds(),
	}
}

// convertForwardResponse converts forwarder response to gRPC response.
func (s *TLSProxyService) convertForwardResponse(fwdResp *forwarder.ForwardResponse, duration time.Duration) *InterceptPacketResponse {
	return &InterceptPacketResponse{
		Action:           fwdResp.Action,
		PacketData:       fwdResp.PacketData,
		Success:          fwdResp.Success,
		ErrorMessage:     fwdResp.ErrorMessage,
		ProcessingTimeMs: duration.Milliseconds(),
		SNIHostname:      fwdResp.SNIHostname,
		ResolvedIP:       fwdResp.ResolvedIP,
	}
}

// =============================================================================
// SERVER LIFECYCLE
// =============================================================================

// Start begins listening for gRPC connections on the specified port.
func (s *TLSProxyService) Start(port int) error {
	addr := fmt.Sprintf(":%d", port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	s.setRunning(true)

	// Start serving in goroutine
	go func() {
		if err := s.server.Serve(listener); err != nil {
			// Server stopped (normal during shutdown)
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *TLSProxyService) Stop() {
	s.setRunning(false)

	// Graceful stop waits for pending requests
	s.server.GracefulStop()

	if s.listener != nil {
		s.listener.Close()
	}
}

// IsRunning returns whether the server is accepting connections.
func (s *TLSProxyService) IsRunning() bool {
	s.runMu.RLock()
	defer s.runMu.RUnlock()
	return s.running
}

// setRunning updates the running state.
func (s *TLSProxyService) setRunning(running bool) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.running = running
}

// =============================================================================
// STATISTICS
// =============================================================================

// incrementRequests safely increments total request count.
func (s *TLSProxyService) incrementRequests() {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.stats.TotalRequests++
	s.stats.LastRequestTime = time.Now()
}

// incrementErrors safely increments error count.
func (s *TLSProxyService) incrementErrors() {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.stats.ErrorResponses++
}

// recordSuccess records a successful response.
func (s *TLSProxyService) recordSuccess(duration time.Duration) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.stats.SuccessfulResponses++
	s.stats.TotalLatency += duration
}

// updatePeakActive updates peak active request count.
func (s *TLSProxyService) updatePeakActive(current int32) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if current > s.stats.PeakActiveRequests {
		s.stats.PeakActiveRequests = current
	}
}

// GetStats returns a copy of service statistics.
func (s *TLSProxyService) GetStats() ServiceStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	return ServiceStats{
		TotalRequests:       s.stats.TotalRequests,
		SuccessfulResponses: s.stats.SuccessfulResponses,
		ErrorResponses:      s.stats.ErrorResponses,
		TotalLatency:        s.stats.TotalLatency,
		ActiveRequests:      atomic.LoadInt32(&s.activeRequests),
		PeakActiveRequests:  s.stats.PeakActiveRequests,
		LastRequestTime:     s.stats.LastRequestTime,
	}
}

// GetActiveRequests returns the current number of in-flight requests.
func (s *TLSProxyService) GetActiveRequests() int32 {
	return atomic.LoadInt32(&s.activeRequests)
}

// GetServer returns the underlying gRPC server for registration.
func (s *TLSProxyService) GetServer() *grpc.Server {
	return s.server
}
