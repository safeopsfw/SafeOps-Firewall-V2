// Package config provides configuration loading for the TLS Proxy service.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// CONFIGURATION DEFAULTS
// =============================================================================

const (
	// DefaultGRPCPort is the default gRPC server port
	DefaultGRPCPort = 50054

	// DefaultDNSServerAddress is the default DNS resolver endpoint
	DefaultDNSServerAddress = "localhost:53"

	// DefaultPacketBufferSize is the default maximum buffered packets
	DefaultPacketBufferSize = 10000

	// DefaultDNSQueryTimeout is the default DNS resolution timeout
	DefaultDNSQueryTimeout = 3 * time.Second

	// DefaultGRPCRequestTimeout is the default gRPC request processing timeout
	DefaultGRPCRequestTimeout = 5 * time.Second

	// DefaultBufferTTL is the default packet buffer expiration time
	DefaultBufferTTL = 30 * time.Second

	// DefaultMaxPacketSize is the default maximum packet data size
	DefaultMaxPacketSize = 65535
)

// =============================================================================
// CONFIGURATION STRUCTURE
// =============================================================================

// Config holds all runtime parameters for the TLS Proxy service.
type Config struct {
	// GRPCPort is the port number where TLS Proxy listens for incoming
	// packet interception requests from NIC Management (default: 50054)
	GRPCPort int

	// DNSServerAddress is the complete address string (host:port) for the
	// DNS Server that resolves SNI domains (default: "localhost:53")
	DNSServerAddress string

	// PacketBufferSize is the maximum number of packets that can be held
	// in memory simultaneously before overflow (default: 10000 entries)
	PacketBufferSize int

	// DNSQueryTimeout is the maximum duration to wait for DNS resolution
	// responses before marking queries as failed (default: 3 seconds)
	DNSQueryTimeout time.Duration

	// GRPCRequestTimeout is the maximum duration to process a single
	// InterceptPacket request before returning error (default: 5 seconds)
	GRPCRequestTimeout time.Duration

	// BufferTTL is how long packets remain in buffer before automatic
	// cleanup (default: 30 seconds)
	BufferTTL time.Duration

	// MaxPacketSize is the maximum raw packet data size accepted from
	// NIC Management (default: 65535 bytes for jumbo frames)
	MaxPacketSize int
}

// =============================================================================
// CONFIGURATION LOADING
// =============================================================================

// Load reads environment variables and returns a populated Config struct.
// If environment variables are not set, default values are used.
// Returns an error if validation fails for any parameter.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:           getEnvIntOrDefault("GRPC_SERVER_PORT", DefaultGRPCPort),
		DNSServerAddress:   getEnvOrDefault("DNS_SERVER_ADDRESS", DefaultDNSServerAddress),
		PacketBufferSize:   getEnvIntOrDefault("PACKET_BUFFER_SIZE", DefaultPacketBufferSize),
		DNSQueryTimeout:    getEnvDurationOrDefault("DNS_QUERY_TIMEOUT", DefaultDNSQueryTimeout),
		GRPCRequestTimeout: getEnvDurationOrDefault("GRPC_REQUEST_TIMEOUT", DefaultGRPCRequestTimeout),
		BufferTTL:          getEnvDurationOrDefault("BUFFER_TTL", DefaultBufferTTL),
		MaxPacketSize:      getEnvIntOrDefault("MAX_PACKET_SIZE", DefaultMaxPacketSize),
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// MustLoad loads configuration or panics if validation fails.
// Used for convenience during startup when errors are unrecoverable.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	return cfg
}

// =============================================================================
// VALIDATION
// =============================================================================

// Validate checks all configuration parameters for acceptable values.
func (c *Config) Validate() error {
	// Validate gRPC port (1024-65535, no privileged ports)
	if c.GRPCPort < 1024 || c.GRPCPort > 65535 {
		return fmt.Errorf("GRPC_SERVER_PORT must be between 1024-65535, got %d", c.GRPCPort)
	}

	// Validate DNS server address format (host:port)
	if !isValidHostPort(c.DNSServerAddress) {
		return fmt.Errorf("DNS_SERVER_ADDRESS must be in 'host:port' format, got %q", c.DNSServerAddress)
	}

	// Validate packet buffer size (positive integer, minimum 1000)
	if c.PacketBufferSize <= 0 {
		return errors.New("PACKET_BUFFER_SIZE must be a positive integer")
	}
	if c.PacketBufferSize < 1000 {
		// Warning but not error - allow small buffers for testing
	}

	// Validate DNS query timeout (positive, max 10 seconds)
	if c.DNSQueryTimeout <= 0 {
		return errors.New("DNS_QUERY_TIMEOUT must be a positive duration")
	}
	if c.DNSQueryTimeout > 10*time.Second {
		return fmt.Errorf("DNS_QUERY_TIMEOUT should not exceed 10s, got %v", c.DNSQueryTimeout)
	}

	// Validate gRPC request timeout (must be greater than DNS query timeout)
	if c.GRPCRequestTimeout <= 0 {
		return errors.New("GRPC_REQUEST_TIMEOUT must be a positive duration")
	}
	if c.GRPCRequestTimeout <= c.DNSQueryTimeout {
		return fmt.Errorf("GRPC_REQUEST_TIMEOUT (%v) must be greater than DNS_QUERY_TIMEOUT (%v)",
			c.GRPCRequestTimeout, c.DNSQueryTimeout)
	}

	// Validate buffer TTL (positive, minimum 10 seconds)
	if c.BufferTTL <= 0 {
		return errors.New("BUFFER_TTL must be a positive duration")
	}
	if c.BufferTTL < 10*time.Second {
		return fmt.Errorf("BUFFER_TTL should be at least 10s, got %v", c.BufferTTL)
	}

	// Validate max packet size (576-65535 bytes)
	if c.MaxPacketSize < 576 || c.MaxPacketSize > 65535 {
		return fmt.Errorf("MAX_PACKET_SIZE must be between 576-65535, got %d", c.MaxPacketSize)
	}

	return nil
}

// =============================================================================
// DISPLAY METHODS
// =============================================================================

// String returns a human-readable representation of the configuration.
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{GRPCPort: %d, DNSServerAddress: %q, PacketBufferSize: %d, "+
			"DNSQueryTimeout: %v, GRPCRequestTimeout: %v, BufferTTL: %v, MaxPacketSize: %d}",
		c.GRPCPort, c.DNSServerAddress, c.PacketBufferSize,
		c.DNSQueryTimeout, c.GRPCRequestTimeout, c.BufferTTL, c.MaxPacketSize,
	)
}

// Print logs the configuration to stdout for debugging.
func (c *Config) Print() {
	fmt.Println("TLS Proxy Configuration:")
	fmt.Printf("  gRPC Server Port:     %d\n", c.GRPCPort)
	fmt.Printf("  DNS Server Address:   %s\n", c.DNSServerAddress)
	fmt.Printf("  Packet Buffer Size:   %d\n", c.PacketBufferSize)
	fmt.Printf("  DNS Query Timeout:    %v\n", c.DNSQueryTimeout)
	fmt.Printf("  gRPC Request Timeout: %v\n", c.GRPCRequestTimeout)
	fmt.Printf("  Buffer TTL:           %v\n", c.BufferTTL)
	fmt.Printf("  Max Packet Size:      %d bytes\n", c.MaxPacketSize)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getEnvOrDefault returns environment variable value or default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvIntOrDefault returns parsed int environment variable or default.
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvDurationOrDefault returns parsed duration environment variable or default.
func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// isValidHostPort checks if address is in "host:port" format.
func isValidHostPort(address string) bool {
	// Must contain exactly one colon
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return false
	}

	// Host can be empty (listen on all interfaces) or non-empty
	// Port must be a valid number
	host := parts[0]
	port := parts[1]

	// Port must be a number
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}

	// Port must be in valid range
	if portNum < 1 || portNum > 65535 {
		return false
	}

	// Host can be "localhost", IP address, or empty
	_ = host // Host validation is lenient

	return true
}
