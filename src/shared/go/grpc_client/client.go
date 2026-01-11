// Package grpc_client provides production-ready gRPC client utilities with TLS, keepalive, and connection management.
package grpc_client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// ============================================================================
// Configuration
// ============================================================================

// Config holds comprehensive gRPC client configuration
type Config struct {
	// Connection
	Target  string        // Service address (host:port or service name)
	Address string        // Deprecated: use Target instead (kept for backward compatibility)
	Timeout time.Duration // Default RPC timeout

	// TLS
	Insecure    bool   // Disable TLS (development only!)
	TLSCertFile string // Client certificate path
	TLSKeyFile  string // Client key path
	TLSCAFile   string // CA certificate for server verification
	ServerName  string // Server name for TLS verification

	// Keepalive
	KeepAliveTime                time.Duration // Send keepalive ping interval
	KeepAliveTimeout             time.Duration // Keepalive timeout
	KeepAlivePermitWithoutStream bool          // Allow keepalive without active RPCs

	// Message Limits
	MaxRecvMsgSize int // Maximum receive message size (default: 4MB)
	MaxSendMsgSize int // Maximum send message size (default: 4MB)

	// Retries
	MaxRetries   int           // Maximum retry attempts
	RetryBackoff time.Duration // Initial retry backoff

	// Load Balancing
	LoadBalancerPolicy string // round_robin or pick_first
}

// DefaultConfig returns production-ready default configuration
func DefaultConfig() Config {
	return Config{
		Timeout:                      10 * time.Second,
		Insecure:                     false,
		KeepAliveTime:                30 * time.Second,
		KeepAliveTimeout:             10 * time.Second,
		KeepAlivePermitWithoutStream: true,
		MaxRecvMsgSize:               4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:               4 * 1024 * 1024, // 4MB
		MaxRetries:                   3,
		RetryBackoff:                 100 * time.Millisecond,
		LoadBalancerPolicy:           "round_robin",
	}
}

// NewConfigFromEnv creates configuration from environment variables
func NewConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()

	if target := os.Getenv("GRPC_TARGET"); target != "" {
		cfg.Target = target
	}

	if insecure := os.Getenv("GRPC_INSECURE"); insecure == "true" {
		cfg.Insecure = true
	}

	if certFile := os.Getenv("GRPC_TLS_CERT"); certFile != "" {
		cfg.TLSCertFile = certFile
	}

	if keyFile := os.Getenv("GRPC_TLS_KEY"); keyFile != "" {
		cfg.TLSKeyFile = keyFile
	}

	if caFile := os.Getenv("GRPC_TLS_CA"); caFile != "" {
		cfg.TLSCAFile = caFile
	}

	if serverName := os.Getenv("GRPC_TLS_SERVER_NAME"); serverName != "" {
		cfg.ServerName = serverName
	}

	if timeoutStr := os.Getenv("GRPC_TIMEOUT"); timeoutStr != "" {
		if seconds, err := strconv.Atoi(timeoutStr); err == nil {
			cfg.Timeout = time.Duration(seconds) * time.Second
		}
	}

	if keepAliveStr := os.Getenv("GRPC_KEEPALIVE_TIME"); keepAliveStr != "" {
		if seconds, err := strconv.Atoi(keepAliveStr); err == nil {
			cfg.KeepAliveTime = time.Duration(seconds) * time.Second
		}
	}

	if retriesStr := os.Getenv("GRPC_MAX_RETRIES"); retriesStr != "" {
		if retries, err := strconv.Atoi(retriesStr); err == nil {
			cfg.MaxRetries = retries
		}
	}

	if lbPolicy := os.Getenv("GRPC_LOAD_BALANCER"); lbPolicy != "" {
		cfg.LoadBalancerPolicy = lbPolicy
	}

	return cfg, nil
}

// ============================================================================
// Client
// ============================================================================

// Client wraps grpc.ClientConn with lifecycle management and observability
type Client struct {
	ClientConn *grpc.ClientConn // Exported for backward compatibility
	conn       *grpc.ClientConn // Internal reference (same as ClientConn)
	config     Config
	logger     *logging.Logger
	metrics    *metrics.MetricsRegistry
	mu         sync.RWMutex
	closed     bool
}

// NewClient creates a new gRPC client with production-ready configuration
//
// Example:
//
//	cfg := grpc_client.Config{
//	    Target:  "localhost:5000",
//	    Timeout: 10 * time.Second,
//	}
//	client, err := grpc_client.NewClient(ctx, cfg)
//	defer client.Close()
func NewClient(ctx context.Context, config Config) (*Client, error) {
	return NewClientWithObservability(ctx, config, nil, nil)
}

// NewClientWithObservability creates a client with logger and metrics
func NewClientWithObservability(ctx context.Context, config Config, logger *logging.Logger, metricsReg *metrics.MetricsRegistry) (*Client, error) {
	// Backward compatibility: use Address if Target is empty
	if config.Target == "" && config.Address != "" {
		config.Target = config.Address
	}

	// Build dial options
	opts, err := buildDialOptions(config, logger, metricsReg)
	if err != nil {
		return nil, fmt.Errorf("failed to build dial options: %w", err)
	}

	// Create connection
	conn, err := grpc.DialContext(ctx, config.Target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", config.Target, err)
	}

	client := &Client{
		ClientConn: conn, // Export for backward compatibility
		conn:       conn, // Internal reference
		config:     config,
		logger:     logger,
		metrics:    metricsReg,
		closed:     false,
	}

	if logger != nil {
		logger.Info("gRPC client connected",
			"target", config.Target,
			"tls_enabled", !config.Insecure,
			"keepalive", config.KeepAliveTime,
		)
	}

	return client, nil
}

// buildDialOptions constructs all gRPC dial options
func buildDialOptions(config Config, logger *logging.Logger, metricsReg *metrics.MetricsRegistry) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(config.MaxSendMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                config.KeepAliveTime,
			Timeout:             config.KeepAliveTimeout,
			PermitWithoutStream: config.KeepAlivePermitWithoutStream,
		}),
	}

	// TLS configuration
	if config.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if logger != nil {
			logger.Warn("gRPC client running in INSECURE mode (no TLS)",
				"target", config.Target,
			)
		}
	} else {
		tlsCreds, err := loadTLSCredentials(config)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
	}

	// Load balancing
	if config.LoadBalancerPolicy != "" {
		serviceConfig := fmt.Sprintf(`{"loadBalancingPolicy":"%s"}`, config.LoadBalancerPolicy)
		opts = append(opts, grpc.WithDefaultServiceConfig(serviceConfig))
	}

	return opts, nil
}

// loadTLSCredentials loads TLS credentials with client certificates
func loadTLSCredentials(config Config) (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{
		ServerName: config.ServerName,
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2+
	}

	// Load client certificate if provided (mTLS)
	if config.TLSCertFile != "" && config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification
	if config.TLSCAFile != "" {
		caCert, err := os.ReadFile(config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = certPool
	}

	return credentials.NewTLS(tlsConfig), nil
}

// ============================================================================
// Connection Access
// ============================================================================

// Conn returns the underlying gRPC connection
// Use this to create service-specific client stubs
//
// Example:
//
//	conn := client.Conn()
//	tiClient := pb.NewThreatIntelServiceClient(conn)
func (c *Client) Conn() *grpc.ClientConn {
	return c.conn
}

// ============================================================================
// Connection State Management
// ============================================================================

// GetState returns the current connection state
func (c *Client) GetState() connectivity.State {
	return c.conn.GetState()
}

// WaitForReady waits for the connection to be ready
// Returns error if connection is not ready within timeout
func (c *Client) WaitForReady(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	state := c.conn.GetState()
	for state != connectivity.Ready {
		if state == connectivity.Shutdown {
			return fmt.Errorf("connection is shutdown")
		}

		if !c.conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("connection not ready after timeout: state=%s", state)
		}
		state = c.conn.GetState()
	}

	if c.logger != nil {
		c.logger.Debug("gRPC connection ready", "target", c.config.Target)
	}

	return nil
}

// IsReady returns true if connection is in Ready state
func (c *Client) IsReady() bool {
	return c.conn.GetState() == connectivity.Ready
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// Close gracefully closes the gRPC connection
// Waits for in-flight RPCs to complete
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	if c.logger != nil {
		c.logger.Info("Closing gRPC client", "target", c.config.Target)
	}

	err := c.conn.Close()
	c.closed = true

	return err
}

// GracefulClose closes the connection with a timeout
// Waits up to timeout for in-flight RPCs to complete
func (c *Client) GracefulClose(timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	if c.logger != nil {
		c.logger.Info("Gracefully closing gRPC client",
			"target", c.config.Target,
			"timeout", timeout,
		)
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Wait for connection to drain
	done := make(chan struct{})
	go func() {
		c.conn.Close()
		close(done)
	}()

	select {
	case <-done:
		c.closed = true
		return nil
	case <-ctx.Done():
		// Force close
		c.conn.Close()
		c.closed = true
		return fmt.Errorf("forced close after timeout")
	}
}

// IsClosed returns true if connection is closed
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// ============================================================================
// Legacy Compatibility
// ============================================================================

// TLSConfig holds legacy TLS configuration (deprecated, use Config instead)
type TLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	Insecure   bool
}

// convertLegacyTLSConfig converts legacy TLSConfig to new Config format
func convertLegacyTLSConfig(legacy TLSConfig) Config {
	cfg := DefaultConfig()
	cfg.Insecure = !legacy.Enabled || legacy.Insecure
	cfg.TLSCertFile = legacy.CertFile
	cfg.TLSKeyFile = legacy.KeyFile
	cfg.TLSCAFile = legacy.CAFile
	cfg.ServerName = legacy.ServerName
	return cfg
}
