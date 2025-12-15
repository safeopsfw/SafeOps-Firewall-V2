// Package grpc_client provides gRPC client utilities.
package grpc_client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config holds gRPC client configuration
type Config struct {
	Address        string
	Timeout        time.Duration
	KeepAlive      time.Duration
	MaxRecvMsgSize int
	MaxSendMsgSize int
	TLS            TLSConfig
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	Insecure   bool
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Timeout:        30 * time.Second,
		KeepAlive:      30 * time.Second,
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
	}
}

// Client wraps grpc.ClientConn with additional functionality
type Client struct {
	*grpc.ClientConn
	cfg Config
}

// NewClient creates a new gRPC client
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(cfg.MaxSendMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                cfg.KeepAlive,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	// TLS configuration
	if cfg.TLS.Enabled {
		creds, err := loadTLSCredentials(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(ctx, cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	return &Client{
		ClientConn: conn,
		cfg:        cfg,
	}, nil
}

// loadTLSCredentials loads TLS credentials
func loadTLSCredentials(cfg TLSConfig) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		}), nil
	}

	tlsConfig := &tls.Config{
		ServerName: cfg.ServerName,
	}

	// Load client certificate if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to add CA cert")
		}
		tlsConfig.RootCAs = certPool
	}

	return credentials.NewTLS(tlsConfig), nil
}

// Close closes the connection
func (c *Client) Close() error {
	return c.ClientConn.Close()
}

// ClientPool manages a pool of client connections
type ClientPool struct {
	clients []*Client
	cfg     Config
	mu      sync.Mutex
	index   int
}

// NewClientPool creates a new client pool
func NewClientPool(ctx context.Context, cfg Config, size int) (*ClientPool, error) {
	clients := make([]*Client, size)

	for i := 0; i < size; i++ {
		client, err := NewClient(ctx, cfg)
		if err != nil {
			// Cleanup any created clients
			for j := 0; j < i; j++ {
				clients[j].Close()
			}
			return nil, err
		}
		clients[i] = client
	}

	return &ClientPool{
		clients: clients,
		cfg:     cfg,
	}, nil
}

// Get returns a client from the pool (round-robin)
func (p *ClientPool) Get() *Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	client := p.clients[p.index]
	p.index = (p.index + 1) % len(p.clients)
	return client
}

// Close closes all clients in the pool
func (p *ClientPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for _, client := range p.clients {
		if err := client.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Size returns the pool size
func (p *ClientPool) Size() int {
	return len(p.clients)
}

// DialOptions builds common dial options
func DialOptions(cfg Config) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(cfg.MaxSendMsgSize),
		),
	}

	if !cfg.TLS.Enabled {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts
}
