// ============================================================================
// SafeOps Captive Portal - DHCP Monitor gRPC Client
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\database\dhcp_client.go
// Purpose: gRPC client for communicating with DHCP Monitor service
//
// The Captive Portal uses this client to:
//   1. Look up device information by IP address (when user visits portal)
//   2. Look up device information by MAC address (for certificate tracking)
//   3. Update trust status to TRUSTED after CA certificate installation
//   4. Check if a device is already trusted (trust verification)
//
// DHCP Monitor gRPC Service runs on port 50055 (Phase 2)
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package database

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ============================================================================
// Trust Status Constants
// ============================================================================

const (
	// TrustStatusUntrusted - Device has not installed the CA certificate
	TrustStatusUntrusted = "UNTRUSTED"

	// TrustStatusTrusted - Device has installed the CA certificate
	TrustStatusTrusted = "TRUSTED"

	// TrustStatusBlocked - Device is blocked from network access
	TrustStatusBlocked = "BLOCKED"
)

// ============================================================================
// Device Data Structures
// ============================================================================

// Device represents a network device from DHCP Monitor
// This mirrors the proto Device message but as a Go-friendly struct
type Device struct {
	DeviceID        string    `json:"device_id"`
	MACAddress      string    `json:"mac_address"`
	CurrentIP       string    `json:"current_ip"`
	Hostname        string    `json:"hostname"`
	DeviceType      string    `json:"device_type"`
	Vendor          string    `json:"vendor"`
	TrustStatus     string    `json:"trust_status"`
	InterfaceName   string    `json:"interface_name"`
	InterfaceIndex  int32     `json:"interface_index"`
	Status          string    `json:"status"`
	DetectionMethod string    `json:"detection_method"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	IsOnline        bool      `json:"is_online"`
}

// DeviceStats contains aggregate statistics from DHCP Monitor
type DeviceStats struct {
	TotalDevices     int32 `json:"total_devices"`
	ActiveDevices    int32 `json:"active_devices"`
	TrustedDevices   int32 `json:"trusted_devices"`
	UntrustedDevices int32 `json:"untrusted_devices"`
	BlockedDevices   int32 `json:"blocked_devices"`
	OfflineDevices   int32 `json:"offline_devices"`
	OnlineDevices    int32 `json:"online_devices"`
}

// ============================================================================
// DHCPClient Configuration
// ============================================================================

// DHCPClientConfig holds configuration for the DHCP Monitor client
type DHCPClientConfig struct {
	// GRPCAddress is the address of the DHCP Monitor gRPC server (e.g., "localhost:50055")
	GRPCAddress string

	// Timeout is the default timeout for gRPC calls
	Timeout time.Duration

	// RetryAttempts is the number of times to retry failed calls
	RetryAttempts int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration

	// MaxConnectionAge is how long to keep the connection before reconnecting
	MaxConnectionAge time.Duration
}

// DefaultDHCPClientConfig returns default configuration values
func DefaultDHCPClientConfig() DHCPClientConfig {
	return DHCPClientConfig{
		GRPCAddress:      "localhost:50055",
		Timeout:          5 * time.Second,
		RetryAttempts:    3,
		RetryDelay:       1 * time.Second,
		MaxConnectionAge: 5 * time.Minute,
	}
}

// ============================================================================
// DHCPClient Implementation
// ============================================================================

// DHCPClient is a gRPC client for the DHCP Monitor service
type DHCPClient struct {
	config     DHCPClientConfig
	conn       *grpc.ClientConn
	mu         sync.RWMutex
	connected  bool
	lastError  error
	queryCount int64
}

// NewDHCPClient creates a new DHCP Monitor client
func NewDHCPClient(config DHCPClientConfig) (*DHCPClient, error) {
	client := &DHCPClient{
		config:    config,
		connected: false,
	}

	// Establish initial connection
	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to DHCP Monitor: %w", err)
	}

	return client, nil
}

// connect establishes the gRPC connection
func (c *DHCPClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close existing connection if any
	if c.conn != nil {
		c.conn.Close()
	}

	// Create gRPC connection with options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	// Use context with timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.config.GRPCAddress, opts...)
	if err != nil {
		c.connected = false
		c.lastError = err
		return fmt.Errorf("failed to dial DHCP Monitor at %s: %w", c.config.GRPCAddress, err)
	}

	c.conn = conn
	c.connected = true
	c.lastError = nil

	log.Printf("[DHCPClient] Connected to DHCP Monitor at %s", c.config.GRPCAddress)
	return nil
}

// ensureConnected checks connection and reconnects if necessary
func (c *DHCPClient) ensureConnected() error {
	c.mu.RLock()
	connected := c.connected && c.conn != nil
	c.mu.RUnlock()

	if connected {
		return nil
	}

	return c.connect()
}

// ============================================================================
// Device Lookup Methods
// ============================================================================

// GetDeviceByIP retrieves device information by IP address
// This is the PRIMARY lookup method used when a device visits the portal
//
// The portal extracts the client IP from the HTTP request and uses this
// method to get the device's MAC address and current trust status.
//
// Returns:
//   - Device info if found
//   - ErrDeviceNotFound if IP not in DHCP Monitor database
//   - Other errors for connection/service issues
func (c *DHCPClient) GetDeviceByIP(ctx context.Context, ipAddress string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	// Simulate gRPC call - in real implementation, use generated proto client
	// For now, we'll return a placeholder that demonstrates the expected behavior
	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] GetDeviceByIP called for: %s", ipAddress)

	// TODO: Replace with actual gRPC call when proto is generated
	// request := &pb.IPRequest{IpAddress: ipAddress}
	// response, err := c.client.GetDeviceByIP(ctx, request)

	// For now, return error indicating gRPC client not yet implemented
	// This will be replaced with actual gRPC calls
	return nil, fmt.Errorf("gRPC client not yet implemented - waiting for proto generation")
}

// GetDeviceByMAC retrieves device information by MAC address
// Used for precise device identification after initial IP lookup
//
// Parameters:
//   - macAddress: Hardware address in AA:BB:CC:DD:EE:FF format
//
// Returns:
//   - Device info if found
//   - ErrDeviceNotFound if MAC not in database
func (c *DHCPClient) GetDeviceByMAC(ctx context.Context, macAddress string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] GetDeviceByMAC called for: %s", macAddress)

	// TODO: Replace with actual gRPC call
	return nil, fmt.Errorf("gRPC client not yet implemented - waiting for proto generation")
}

// ============================================================================
// Trust Management Methods
// ============================================================================

// UpdateTrustStatus updates a device's trust status in the DHCP Monitor database
// This is called AFTER a user confirms they've installed the CA certificate
//
// Parameters:
//   - deviceID: UUID of the device to update
//   - trustStatus: New status (TRUSTED, UNTRUSTED, BLOCKED)
//
// Returns:
//   - Updated device info on success
//   - Error on failure
func (c *DHCPClient) UpdateTrustStatus(ctx context.Context, deviceID string, trustStatus string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	// Validate trust status
	if trustStatus != TrustStatusTrusted &&
		trustStatus != TrustStatusUntrusted &&
		trustStatus != TrustStatusBlocked {
		return nil, fmt.Errorf("invalid trust status: %s (must be TRUSTED, UNTRUSTED, or BLOCKED)", trustStatus)
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] UpdateTrustStatus called: deviceID=%s, status=%s", deviceID, trustStatus)

	// TODO: Replace with actual gRPC call
	return nil, fmt.Errorf("gRPC client not yet implemented - waiting for proto generation")
}

// MarkDeviceTrusted is a convenience method to mark a device as TRUSTED
// This is the primary method called by the Captive Portal after CA installation
func (c *DHCPClient) MarkDeviceTrusted(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusTrusted)
}

// MarkDeviceUntrusted is a convenience method to mark a device as UNTRUSTED
// Used if a user needs to re-install the certificate
func (c *DHCPClient) MarkDeviceUntrusted(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusUntrusted)
}

// MarkDeviceBlocked is a convenience method to block a device
// Used by administrators to deny network access
func (c *DHCPClient) MarkDeviceBlocked(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusBlocked)
}

// ============================================================================
// Trust Verification Methods
// ============================================================================

// IsTrusted checks if a device is currently marked as trusted
// Used by the auto-verification JavaScript to poll for trust status changes
func (c *DHCPClient) IsTrusted(ctx context.Context, ipAddress string) (bool, error) {
	device, err := c.GetDeviceByIP(ctx, ipAddress)
	if err != nil {
		// If we can't find the device, assume untrusted
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}

	return device.TrustStatus == TrustStatusTrusted, nil
}

// IsBlocked checks if a device is blocked
func (c *DHCPClient) IsBlocked(ctx context.Context, ipAddress string) (bool, error) {
	device, err := c.GetDeviceByIP(ctx, ipAddress)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}

	return device.TrustStatus == TrustStatusBlocked, nil
}

// ============================================================================
// Statistics and Health Methods
// ============================================================================

// GetDeviceStats retrieves aggregate device statistics
// Used for dashboard displays and monitoring
func (c *DHCPClient) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] GetDeviceStats called")

	// TODO: Replace with actual gRPC call
	return nil, fmt.Errorf("gRPC client not yet implemented - waiting for proto generation")
}

// HealthCheck verifies the DHCP Monitor service is healthy
func (c *DHCPClient) HealthCheck(ctx context.Context) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("connection check failed: %w", err)
	}

	// TODO: Implement actual health check RPC
	log.Printf("[DHCPClient] HealthCheck called - connection OK")
	return nil
}

// ============================================================================
// Connection Management Methods
// ============================================================================

// IsConnected returns the current connection status
func (c *DHCPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetLastError returns the last error encountered
func (c *DHCPClient) GetLastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastError
}

// GetQueryCount returns the total number of queries made
func (c *DHCPClient) GetQueryCount() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.queryCount
}

// Reconnect forces a reconnection to the DHCP Monitor service
func (c *DHCPClient) Reconnect() error {
	log.Printf("[DHCPClient] Forcing reconnection to DHCP Monitor")
	return c.connect()
}

// Close closes the gRPC connection
func (c *DHCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.connected = false
		log.Printf("[DHCPClient] Connection closed")
		return err
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// isNotFoundError checks if an error indicates "not found"
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Check for gRPC NOT_FOUND status code
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.NotFound {
		return true
	}

	// Also check for common error messages
	errMsg := err.Error()
	return errMsg == "device not found" ||
		errMsg == "not found" ||
		errMsg == "no device found"
}

// parseTimestamp converts ISO 8601 string to time.Time
func parseTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	// Try common formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t
		}
	}

	return time.Time{}
}
