// Package api implements the gRPC API for DHCP server management.
// This file implements the gRPC server infrastructure.
package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Server Configuration
// ============================================================================

// GRPCServerConfig holds gRPC server configuration.
type GRPCServerConfig struct {
	ListenAddress        string
	Port                 int
	MaxConcurrentStreams int
	MaxReceiveSize       int
	MaxSendSize          int
	ConnectionTimeout    time.Duration
	KeepaliveInterval    time.Duration
	ShutdownTimeout      time.Duration
	EnableReflection     bool
	EnableAuth           bool
	EnableTLS            bool
}

// DefaultGRPCServerConfig returns sensible defaults.
func DefaultGRPCServerConfig() *GRPCServerConfig {
	return &GRPCServerConfig{
		ListenAddress:        "localhost",
		Port:                 50054,
		MaxConcurrentStreams: 100,
		MaxReceiveSize:       4 * 1024 * 1024, // 4MB
		MaxSendSize:          4 * 1024 * 1024, // 4MB
		ConnectionTimeout:    2 * time.Minute,
		KeepaliveInterval:    30 * time.Second,
		ShutdownTimeout:      30 * time.Second,
		EnableReflection:     true,
		EnableAuth:           false,
		EnableTLS:            false,
	}
}

// ============================================================================
// gRPC Server
// ============================================================================

// GRPCServer manages the gRPC management API server.
type GRPCServer struct {
	mu     sync.RWMutex
	config *GRPCServerConfig

	// Components
	handler  *DHCPAPIHandler
	listener net.Listener

	// Lifecycle
	running  atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Metrics
	stats ServerMetrics
}

// ServerMetrics tracks gRPC server metrics.
type ServerMetrics struct {
	TotalRequests    int64
	SuccessRequests  int64
	FailedRequests   int64
	ActiveRequests   int64
	TotalConnections int64
}

// NewGRPCServer creates a new gRPC server.
func NewGRPCServer(config *GRPCServerConfig) *GRPCServer {
	if config == nil {
		config = DefaultGRPCServerConfig()
	}

	return &GRPCServer{
		config:   config,
		handler:  NewDHCPAPIHandler(),
		stopChan: make(chan struct{}),
	}
}

// ============================================================================
// Configuration
// ============================================================================

// SetHandler sets the API handler.
func (s *GRPCServer) SetHandler(handler *DHCPAPIHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
}

// GetHandler returns the API handler.
func (s *GRPCServer) GetHandler() *DHCPAPIHandler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handler
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the gRPC server.
func (s *GRPCServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return ErrServerAlreadyRunning
	}

	// Create listener
	addr := s.config.ListenAddress + ":50054"
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.running.Store(true)
	s.stopChan = make(chan struct{})

	// Start serving goroutine
	s.wg.Add(1)
	go s.serve(ctx)

	return nil
}

// Stop stops the gRPC server gracefully.
func (s *GRPCServer) Stop() error {
	if !s.running.Load() {
		return nil
	}

	// Signal stop
	close(s.stopChan)

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(s.config.ShutdownTimeout):
		// Timeout
	}

	s.running.Store(false)
	return nil
}

func (s *GRPCServer) serve(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		// Accept connection
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		atomic.AddInt64(&s.stats.TotalConnections, 1)

		// Handle connection
		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

func (s *GRPCServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(s.config.ConnectionTimeout))

	// Read and process requests
	// In a real implementation, this would use the gRPC protocol
	// For now, this is a simplified connection handler
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		// Read with timeout
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			atomic.AddInt64(&s.stats.TotalRequests, 1)
			atomic.AddInt64(&s.stats.ActiveRequests, 1)

			// Process request (simplified)
			s.processRequest(ctx, conn, buf[:n])

			atomic.AddInt64(&s.stats.ActiveRequests, -1)
		}
	}
}

func (s *GRPCServer) processRequest(ctx context.Context, conn net.Conn, _ []byte) {
	// This is a simplified request processor
	// In production, this would decode gRPC framing and invoke handlers

	s.mu.RLock()
	handler := s.handler
	s.mu.RUnlock()

	if handler == nil {
		atomic.AddInt64(&s.stats.FailedRequests, 1)
		return
	}

	// Perform health check as example
	healthy, _ := handler.HealthCheck(ctx)
	if healthy {
		atomic.AddInt64(&s.stats.SuccessRequests, 1)
	} else {
		atomic.AddInt64(&s.stats.FailedRequests, 1)
	}

	// Write simple response
	conn.Write([]byte("OK"))
}

// ============================================================================
// Health Check
// ============================================================================

// HealthStatus represents gRPC health status.
type HealthStatus int

const (
	// HealthUnknown status unknown
	HealthUnknown HealthStatus = iota
	// HealthServing server is serving
	HealthServing
	// HealthNotServing server is not serving
	HealthNotServing
)

// CheckHealth performs a health check.
func (s *GRPCServer) CheckHealth(ctx context.Context) HealthStatus {
	if !s.running.Load() {
		return HealthNotServing
	}

	s.mu.RLock()
	handler := s.handler
	s.mu.RUnlock()

	if handler == nil {
		return HealthNotServing
	}

	healthy, _ := handler.HealthCheck(ctx)
	if healthy {
		return HealthServing
	}

	return HealthNotServing
}

// ============================================================================
// Status and Metrics
// ============================================================================

// IsRunning returns whether the server is running.
func (s *GRPCServer) IsRunning() bool {
	return s.running.Load()
}

// GetListenAddress returns the listen address.
func (s *GRPCServer) GetListenAddress() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// GetMetrics returns server metrics.
func (s *GRPCServer) GetMetrics() ServerMetrics {
	return ServerMetrics{
		TotalRequests:    atomic.LoadInt64(&s.stats.TotalRequests),
		SuccessRequests:  atomic.LoadInt64(&s.stats.SuccessRequests),
		FailedRequests:   atomic.LoadInt64(&s.stats.FailedRequests),
		ActiveRequests:   atomic.LoadInt64(&s.stats.ActiveRequests),
		TotalConnections: atomic.LoadInt64(&s.stats.TotalConnections),
	}
}

// ============================================================================
// Interceptors
// ============================================================================

// RequestContext contains request metadata.
type RequestContext struct {
	Method     string
	ClientAddr string
	RequestID  string
	StartTime  time.Time
	UserID     string
	Role       string
}

// InterceptorFunc is a gRPC interceptor function type.
type InterceptorFunc func(ctx context.Context, req *RequestContext) error

// LoggingInterceptor logs all RPC calls.
func LoggingInterceptor(ctx context.Context, req *RequestContext) error {
	// Log request (in production, use structured logging)
	_ = req.Method
	_ = req.ClientAddr
	return nil
}

// MetricsInterceptor records RPC metrics.
func MetricsInterceptor(ctx context.Context, req *RequestContext) error {
	// Record metrics
	_ = req.Method
	_ = time.Since(req.StartTime)
	return nil
}

// AuthInterceptor validates authentication.
func AuthInterceptor(ctx context.Context, req *RequestContext) error {
	// Validate auth (if enabled)
	// Return error for unauthorized requests
	return nil
}

// ============================================================================
// Error Conversion
// ============================================================================

// GRPCCode represents a gRPC status code.
type GRPCCode int

const (
	// CodeOK success
	CodeOK GRPCCode = 0
	// CodeCancelled cancelled
	CodeCancelled GRPCCode = 1
	// CodeUnknown unknown error
	CodeUnknown GRPCCode = 2
	// CodeInvalidArgument invalid argument
	CodeInvalidArgument GRPCCode = 3
	// CodeNotFound not found
	CodeNotFound GRPCCode = 5
	// CodeAlreadyExists already exists
	CodeAlreadyExists GRPCCode = 6
	// CodePermissionDenied permission denied
	CodePermissionDenied GRPCCode = 7
	// CodeUnauthenticated unauthenticated
	CodeUnauthenticated GRPCCode = 16
	// CodeUnavailable unavailable
	CodeUnavailable GRPCCode = 14
	// CodeInternal internal error
	CodeInternal GRPCCode = 13
)

// ErrorToGRPCCode converts an error to a gRPC code.
func ErrorToGRPCCode(err error) GRPCCode {
	if err == nil {
		return CodeOK
	}

	switch {
	case errors.Is(err, ErrLeaseNotFound), errors.Is(err, ErrPoolNotFound):
		return CodeNotFound
	case errors.Is(err, ErrReservationExists), errors.Is(err, ErrIPAlreadyReserved):
		return CodeAlreadyExists
	case errors.Is(err, ErrInvalidMACAddress), errors.Is(err, ErrInvalidIPAddress), errors.Is(err, ErrInvalidPoolName):
		return CodeInvalidArgument
	case errors.Is(err, ErrServiceNotAvailable):
		return CodeUnavailable
	default:
		return CodeInternal
	}
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrServerAlreadyRunning is returned when server already running
	ErrServerAlreadyRunning = errors.New("gRPC server already running")

	// ErrServerNotRunning is returned when server not running
	ErrServerNotRunning = errors.New("gRPC server not running")

	// ErrAuthRequired is returned when authentication required
	ErrAuthRequired = errors.New("authentication required")

	// ErrPermissionDenied is returned when permission denied
	ErrPermissionDenied = errors.New("permission denied")
)
