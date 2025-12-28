// Package grpc provides gRPC server and handlers for the NIC Management service.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Server Error Types
// =============================================================================

var (
	// ErrServerNotRunning indicates server is not running.
	ErrServerNotRunning = errors.New("gRPC server not running")
	// ErrServerAlreadyRunning indicates server is already running.
	ErrServerAlreadyRunning = errors.New("gRPC server already running")
	// ErrInvalidTLSConfig indicates invalid TLS configuration.
	ErrInvalidTLSConfig = errors.New("invalid TLS configuration")
	// ErrPortInUse indicates the port is already in use.
	ErrPortInUse = errors.New("port already in use")
)

// =============================================================================
// Server Configuration
// =============================================================================

// ServerConfig contains gRPC server configuration.
type ServerConfig struct {
	// Port is the listening port.
	Port int `json:"port"`
	// TLSEnabled enables TLS.
	TLSEnabled bool `json:"tls_enabled"`
	// TLSCertPath is the path to server certificate.
	TLSCertPath string `json:"tls_cert_path"`
	// TLSKeyPath is the path to server private key.
	TLSKeyPath string `json:"tls_key_path"`
	// TLSClientCAPath is the path to client CA for mTLS.
	TLSClientCAPath string `json:"tls_client_ca_path"`
	// MaxConcurrentStreams is the max concurrent streams per connection.
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams"`
	// MaxMessageSizeMB is the max message size in MB.
	MaxMessageSizeMB int `json:"max_message_size_mb"`
	// ConnectionTimeout is the connection timeout.
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	// KeepaliveInterval is the keepalive ping interval.
	KeepaliveInterval time.Duration `json:"keepalive_interval"`
	// KeepaliveTimeout is the keepalive timeout.
	KeepaliveTimeout time.Duration `json:"keepalive_timeout"`
	// RateLimitRPS is the rate limit per client (requests/second).
	RateLimitRPS int `json:"rate_limit_rps"`
	// EnableReflection enables server reflection for debugging.
	EnableReflection bool `json:"enable_reflection"`
	// EnableHealthCheck enables gRPC health check service.
	EnableHealthCheck bool `json:"enable_health_check"`
}

// DefaultServerConfig returns the default server configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:                 50054,
		TLSEnabled:           false,
		MaxConcurrentStreams: 1000,
		MaxMessageSizeMB:     10,
		ConnectionTimeout:    120 * time.Second,
		KeepaliveInterval:    60 * time.Second,
		KeepaliveTimeout:     20 * time.Second,
		RateLimitRPS:         100,
		EnableReflection:     true,
		EnableHealthCheck:    true,
	}
}

// =============================================================================
// Client Rate Limiter
// =============================================================================

// clientRateLimiter tracks rate limits per client.
type clientRateLimiter struct {
	clients map[string]*rateLimitBucket
	mu      sync.RWMutex
	limit   int
}

// rateLimitBucket is a token bucket for rate limiting.
type rateLimitBucket struct {
	tokens     int
	lastRefill time.Time
}

// newClientRateLimiter creates a new rate limiter.
func newClientRateLimiter(limit int) *clientRateLimiter {
	return &clientRateLimiter{
		clients: make(map[string]*rateLimitBucket),
		limit:   limit,
	}
}

// Allow checks if a request from client is allowed.
func (rl *clientRateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = &rateLimitBucket{
			tokens:     rl.limit,
			lastRefill: now,
		}
		rl.clients[clientIP] = bucket
	}

	// Refill tokens (1 token per 1/limit second).
	elapsed := now.Sub(bucket.lastRefill)
	refillTokens := int(elapsed.Seconds() * float64(rl.limit))
	if refillTokens > 0 {
		bucket.tokens += refillTokens
		if bucket.tokens > rl.limit {
			bucket.tokens = rl.limit
		}
		bucket.lastRefill = now
	}

	// Check if request allowed.
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	return false
}

// =============================================================================
// Server Info
// =============================================================================

// ServerInfo contains server runtime information.
type ServerInfo struct {
	ListeningAddress    string        `json:"listening_address"`
	TLSEnabled          bool          `json:"tls_enabled"`
	ActiveConnections   int           `json:"active_connections"`
	TotalRequestsServed uint64        `json:"total_requests_served"`
	ActiveStreams       int           `json:"active_streams"`
	Uptime              time.Duration `json:"uptime"`
}

// =============================================================================
// gRPC Server
// =============================================================================

// GrpcServer manages the gRPC server.
type GrpcServer struct {
	// Core components.
	server         *grpc.Server
	handlers       *Handlers
	streamHandlers *StreamHandlers

	// Network.
	listener net.Listener
	config   *ServerConfig

	// TLS.
	tlsConfig *tls.Config

	// Rate limiter.
	rateLimiter *clientRateLimiter

	// Statistics.
	totalRequests     uint64
	activeConnections int32
	startTime         time.Time

	// Lifecycle.
	shutdownChan chan struct{}
	running      bool
	runningMu    sync.RWMutex
}

// NewGrpcServer creates a new gRPC server.
func NewGrpcServer(
	handlers *Handlers,
	streamHandlers *StreamHandlers,
	config *ServerConfig,
) (*GrpcServer, error) {
	if config == nil {
		config = DefaultServerConfig()
	}

	server := &GrpcServer{
		handlers:       handlers,
		streamHandlers: streamHandlers,
		config:         config,
		rateLimiter:    newClientRateLimiter(config.RateLimitRPS),
		shutdownChan:   make(chan struct{}),
	}

	// Load TLS configuration if enabled.
	if config.TLSEnabled {
		tlsConfig, err := server.loadTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
		server.tlsConfig = tlsConfig
	}

	// Create gRPC server with options.
	opts := server.buildServerOptions()
	server.server = grpc.NewServer(opts...)

	return server, nil
}

// loadTLSConfig loads TLS certificates.
func (s *GrpcServer) loadTLSConfig() (*tls.Config, error) {
	// Load server certificate and key.
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertPath, s.config.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Load client CA for mTLS if configured.
	if s.config.TLSClientCAPath != "" {
		caCert, err := os.ReadFile(s.config.TLSClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse client CA certificate")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// buildServerOptions builds gRPC server options.
func (s *GrpcServer) buildServerOptions() []grpc.ServerOption {
	opts := make([]grpc.ServerOption, 0, 10)

	// Max message size.
	maxMsgSize := s.config.MaxMessageSizeMB * 1024 * 1024
	opts = append(opts, grpc.MaxRecvMsgSize(maxMsgSize))
	opts = append(opts, grpc.MaxSendMsgSize(maxMsgSize))

	// Max concurrent streams.
	opts = append(opts, grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams))

	// Keepalive settings.
	kaParams := keepalive.ServerParameters{
		Time:    s.config.KeepaliveInterval,
		Timeout: s.config.KeepaliveTimeout,
	}
	opts = append(opts, grpc.KeepaliveParams(kaParams))

	// Keepalive enforcement policy.
	kaPolicy := keepalive.EnforcementPolicy{
		MinTime:             30 * time.Second,
		PermitWithoutStream: true,
	}
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaPolicy))

	// Connection timeout.
	opts = append(opts, grpc.ConnectionTimeout(s.config.ConnectionTimeout))

	// TLS credentials.
	if s.tlsConfig != nil {
		creds := credentials.NewTLS(s.tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}

	// Interceptors.
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		s.createRecoveryInterceptor(),
		s.createLoggingInterceptor(),
		s.createMetricsInterceptor(),
		s.createRateLimitInterceptor(),
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(unaryInterceptors...))

	streamInterceptors := []grpc.StreamServerInterceptor{
		s.createStreamRecoveryInterceptor(),
		s.createStreamLoggingInterceptor(),
		s.createStreamMetricsInterceptor(),
		s.createStreamRateLimitInterceptor(),
	}
	opts = append(opts, grpc.ChainStreamInterceptor(streamInterceptors...))

	return opts
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the gRPC server.
func (s *GrpcServer) Start(ctx context.Context) error {
	_ = ctx // Used in production for startup context.

	s.runningMu.Lock()
	if s.running {
		s.runningMu.Unlock()
		return ErrServerAlreadyRunning
	}

	// Create TCP listener.
	addr := fmt.Sprintf(":%d", s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.runningMu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener
	s.running = true
	s.startTime = time.Now()
	s.runningMu.Unlock()

	// Start serving in goroutine.
	go func() {
		if err := s.server.Serve(listener); err != nil {
			// Log error in production.
		}
	}()

	return nil
}

// Stop gracefully stops the gRPC server.
func (s *GrpcServer) Stop() error {
	s.runningMu.Lock()
	if !s.running {
		s.runningMu.Unlock()
		return nil
	}
	s.running = false
	s.runningMu.Unlock()

	// Close all streaming connections.
	if s.streamHandlers != nil {
		s.streamHandlers.CloseAllStreams()
	}

	// Graceful stop with timeout.
	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		// Graceful stop completed.
	case <-time.After(30 * time.Second):
		// Force stop.
		s.server.Stop()
	}

	// Close listener.
	if s.listener != nil {
		s.listener.Close()
	}

	close(s.shutdownChan)
	return nil
}

// IsRunning returns whether the server is running.
func (s *GrpcServer) IsRunning() bool {
	s.runningMu.RLock()
	defer s.runningMu.RUnlock()
	return s.running
}

// GetListeningAddress returns the listening address.
func (s *GrpcServer) GetListeningAddress() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// =============================================================================
// Unary Interceptors
// =============================================================================

// createRecoveryInterceptor creates a panic recovery interceptor.
func (s *GrpcServer) createRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				// Log panic in production.
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// createLoggingInterceptor creates a logging interceptor.
func (s *GrpcServer) createLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		start := time.Now()
		clientIP := s.getClientIP(ctx)

		resp, err = handler(ctx, req)

		duration := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code()
			}
		}

		// Log in production.
		_ = clientIP
		_ = duration
		_ = statusCode
		_ = info.FullMethod

		return resp, err
	}
}

// createMetricsInterceptor creates a metrics interceptor.
func (s *GrpcServer) createMetricsInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		start := time.Now()
		atomic.AddUint64(&s.totalRequests, 1)

		resp, err = handler(ctx, req)

		duration := time.Since(start)

		// Record metrics in production:
		// - grpc_requests_total{method=...,status=...}
		// - grpc_request_duration_seconds{method=...}
		_ = duration
		_ = info.FullMethod

		return resp, err
	}
}

// createRateLimitInterceptor creates a rate limiting interceptor.
func (s *GrpcServer) createRateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		clientIP := s.getClientIP(ctx)

		if !s.rateLimiter.Allow(clientIP) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// =============================================================================
// Stream Interceptors
// =============================================================================

// createStreamRecoveryInterceptor creates a stream panic recovery interceptor.
func (s *GrpcServer) createStreamRecoveryInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				// Log panic in production.
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(srv, ss)
	}
}

// createStreamLoggingInterceptor creates a stream logging interceptor.
func (s *GrpcServer) createStreamLoggingInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		clientIP := s.getClientIP(ss.Context())

		err := handler(srv, ss)

		duration := time.Since(start)

		// Log in production.
		_ = clientIP
		_ = duration
		_ = info.FullMethod

		return err
	}
}

// createStreamMetricsInterceptor creates a stream metrics interceptor.
func (s *GrpcServer) createStreamMetricsInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		atomic.AddInt32(&s.activeConnections, 1)
		defer atomic.AddInt32(&s.activeConnections, -1)

		err := handler(srv, ss)

		duration := time.Since(start)

		// Record metrics in production:
		// - grpc_active_streams{method=...}
		// - grpc_stream_duration_seconds{method=...}
		_ = duration
		_ = info.FullMethod

		return err
	}
}

// createStreamRateLimitInterceptor creates a stream rate limiting interceptor.
func (s *GrpcServer) createStreamRateLimitInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		clientIP := s.getClientIP(ss.Context())

		if !s.rateLimiter.Allow(clientIP) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, ss)
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// getClientIP extracts client IP from context.
func (s *GrpcServer) getClientIP(ctx context.Context) string {
	// Try to get from peer.
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if addr, ok := p.Addr.(*net.TCPAddr); ok {
			return addr.IP.String()
		}
		return p.Addr.String()
	}

	// Try to get from metadata (if behind proxy).
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			return xff[0]
		}
		if realIP := md.Get("x-real-ip"); len(realIP) > 0 {
			return realIP[0]
		}
	}

	return "unknown"
}

// =============================================================================
// Server Information
// =============================================================================

// GetServerInfo returns server runtime information.
func (s *GrpcServer) GetServerInfo() *ServerInfo {
	s.runningMu.RLock()
	running := s.running
	startTime := s.startTime
	s.runningMu.RUnlock()

	var uptime time.Duration
	if running && !startTime.IsZero() {
		uptime = time.Since(startTime)
	}

	var activeStreams int
	if s.streamHandlers != nil {
		activeStreams = s.streamHandlers.getActiveStreamCount()
	}

	return &ServerInfo{
		ListeningAddress:    s.GetListeningAddress(),
		TLSEnabled:          s.config.TLSEnabled,
		ActiveConnections:   int(atomic.LoadInt32(&s.activeConnections)),
		TotalRequestsServed: atomic.LoadUint64(&s.totalRequests),
		ActiveStreams:       activeStreams,
		Uptime:              uptime,
	}
}

// GetConfig returns the server configuration.
func (s *GrpcServer) GetConfig() *ServerConfig {
	return s.config
}

// GetServer returns the underlying gRPC server.
func (s *GrpcServer) GetServer() *grpc.Server {
	return s.server
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the server is operational.
func (s *GrpcServer) HealthCheck() error {
	s.runningMu.RLock()
	running := s.running
	s.runningMu.RUnlock()

	if !running {
		return ErrServerNotRunning
	}

	return nil
}
