// ============================================================================
// SafeOps Captive Portal - DHCP Monitor gRPC Client
// ============================================================================
// REAL IMPLEMENTATION - Uses actual gRPC calls to DHCP Monitor service
// ============================================================================

package database

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	pb "captive_portal/proto/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Trust Status Constants
const (
	TrustStatusUntrusted = "UNTRUSTED"
	TrustStatusTrusted   = "TRUSTED"
	TrustStatusBlocked   = "BLOCKED"
)

// Device represents a network device from DHCP Monitor
type Device struct {
	DeviceID          string    `json:"device_id"`
	MACAddress        string    `json:"mac_address"`
	CurrentIP         string    `json:"current_ip"`
	Hostname          string    `json:"hostname"`
	DeviceType        string    `json:"device_type"`
	Vendor            string    `json:"vendor"`
	TrustStatus       string    `json:"trust_status"`
	InterfaceName     string    `json:"interface_name"`
	InterfaceIndex    int32     `json:"interface_index"`
	Status            string    `json:"status"`
	DetectionMethod   string    `json:"detection_method"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	IsOnline          bool      `json:"is_online"`
	PortalShown       bool      `json:"portal_shown"`
	PortalShownAt     time.Time `json:"portal_shown_at"`
	CACertInstalled   bool      `json:"ca_cert_installed"`
	CACertInstalledAt time.Time `json:"ca_cert_installed_at"`
}

// DeviceStats contains aggregate statistics
type DeviceStats struct {
	TotalDevices     int32 `json:"total_devices"`
	ActiveDevices    int32 `json:"active_devices"`
	TrustedDevices   int32 `json:"trusted_devices"`
	UntrustedDevices int32 `json:"untrusted_devices"`
	BlockedDevices   int32 `json:"blocked_devices"`
	OfflineDevices   int32 `json:"offline_devices"`
	OnlineDevices    int32 `json:"online_devices"`
}

// DHCPClientConfig holds configuration
type DHCPClientConfig struct {
	GRPCAddress      string
	Timeout          time.Duration
	RetryAttempts    int
	RetryDelay       time.Duration
	MaxConnectionAge time.Duration
}

// DefaultDHCPClientConfig returns default configuration
func DefaultDHCPClientConfig() DHCPClientConfig {
	return DHCPClientConfig{
		GRPCAddress:      "localhost:50055",
		Timeout:          5 * time.Second,
		RetryAttempts:    3,
		RetryDelay:       1 * time.Second,
		MaxConnectionAge: 5 * time.Minute,
	}
}

// DHCPClient is the gRPC client for DHCP Monitor service
type DHCPClient struct {
	config     DHCPClientConfig
	conn       *grpc.ClientConn
	client     pb.DHCPMonitorClient // Real gRPC client!
	mu         sync.RWMutex
	connected  bool
	lastError  error
	queryCount int64
}

// NewDHCPClient creates a new DHCP Monitor client with real gRPC connection
func NewDHCPClient(config DHCPClientConfig) (*DHCPClient, error) {
	client := &DHCPClient{
		config:    config,
		connected: false,
	}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to DHCP Monitor: %w", err)
	}

	return client, nil
}

// connect establishes the gRPC connection
func (c *DHCPClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.config.GRPCAddress, opts...)
	if err != nil {
		c.connected = false
		c.lastError = err
		return fmt.Errorf("failed to dial DHCP Monitor at %s: %w", c.config.GRPCAddress, err)
	}

	c.conn = conn
	c.client = pb.NewDHCPMonitorClient(conn) // Create real gRPC client!
	c.connected = true
	c.lastError = nil

	log.Printf("[DHCPClient] ✅ Connected to DHCP Monitor at %s", c.config.GRPCAddress)
	return nil
}

// ensureConnected checks connection and reconnects if necessary
func (c *DHCPClient) ensureConnected() error {
	c.mu.RLock()
	connected := c.connected && c.conn != nil && c.client != nil
	c.mu.RUnlock()

	if connected {
		return nil
	}
	return c.connect()
}

// ============================================================================
// Device Lookup Methods - REAL gRPC CALLS
// ============================================================================

// GetDeviceByIP retrieves device information by IP address
func (c *DHCPClient) GetDeviceByIP(ctx context.Context, ipAddress string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] GetDeviceByIP: %s", ipAddress)

	// REAL gRPC call!
	request := &pb.IPRequest{IpAddress: ipAddress}
	response, err := c.client.GetDeviceByIP(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("GetDeviceByIP failed: %w", err)
	}

	return protoToDevice(response), nil
}

// GetDeviceByMAC retrieves device information by MAC address
func (c *DHCPClient) GetDeviceByMAC(ctx context.Context, macAddress string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] GetDeviceByMAC: %s", macAddress)

	request := &pb.MACRequest{MacAddress: macAddress}
	response, err := c.client.GetDeviceByMAC(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("GetDeviceByMAC failed: %w", err)
	}

	return protoToDevice(response), nil
}

// ============================================================================
// Trust Management Methods - REAL gRPC CALLS
// ============================================================================

// UpdateTrustStatus updates a device's trust status
func (c *DHCPClient) UpdateTrustStatus(ctx context.Context, deviceID string, trustStatus string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	if trustStatus != TrustStatusTrusted &&
		trustStatus != TrustStatusUntrusted &&
		trustStatus != TrustStatusBlocked {
		return nil, fmt.Errorf("invalid trust status: %s", trustStatus)
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] UpdateTrustStatus: deviceID=%s, status=%s", deviceID, trustStatus)

	request := &pb.TrustUpdateRequest{
		DeviceId:    deviceID,
		TrustStatus: trustStatus,
	}
	response, err := c.client.UpdateTrustStatus(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("UpdateTrustStatus failed: %w", err)
	}

	return protoToDevice(response), nil
}

// MarkDeviceTrusted marks a device as TRUSTED
func (c *DHCPClient) MarkDeviceTrusted(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusTrusted)
}

// MarkDeviceUntrusted marks a device as UNTRUSTED
func (c *DHCPClient) MarkDeviceUntrusted(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusUntrusted)
}

// MarkDeviceBlocked marks a device as BLOCKED
func (c *DHCPClient) MarkDeviceBlocked(ctx context.Context, deviceID string) (*Device, error) {
	return c.UpdateTrustStatus(ctx, deviceID, TrustStatusBlocked)
}

// MarkPortalShown marks that a device has seen the captive portal
func (c *DHCPClient) MarkPortalShown(ctx context.Context, deviceID string) (*Device, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] MarkPortalShown: deviceID=%s", deviceID)

	request := &pb.MarkPortalShownRequest{DeviceId: deviceID}
	response, err := c.client.MarkPortalShown(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("MarkPortalShown failed: %w", err)
	}

	return protoToDevice(response), nil
}

// MarkCACertInstalled marks that device has installed CA certificate
// This is called when user downloads the CA certificate from the portal
func (c *DHCPClient) MarkCACertInstalled(ctx context.Context, ipAddress string) error {
	if err := c.ensureConnected(); err != nil {
		return err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	log.Printf("[DHCPClient] ✅ MarkCACertInstalled: IP=%s", ipAddress)

	request := &pb.MarkCACertInstalledRequest{IpAddress: ipAddress}
	response, err := c.client.MarkCACertInstalled(ctx, request)
	if err != nil {
		return fmt.Errorf("MarkCACertInstalled failed: %w", err)
	}

	log.Printf("[DHCPClient] ✅ Device marked as CA Cert Installed: %s (MAC: %s, Trust: %s)",
		response.CurrentIp, response.MacAddress, response.TrustStatus)

	return nil
}

// ============================================================================
// Trust Verification Methods
// ============================================================================

// IsTrusted checks if a device is currently marked as trusted
func (c *DHCPClient) IsTrusted(ctx context.Context, ipAddress string) (bool, error) {
	device, err := c.GetDeviceByIP(ctx, ipAddress)
	if err != nil {
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
func (c *DHCPClient) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	response, err := c.client.GetDeviceStats(ctx, &pb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("GetDeviceStats failed: %w", err)
	}

	return &DeviceStats{
		TotalDevices:     response.TotalDevices,
		ActiveDevices:    response.ActiveDevices,
		TrustedDevices:   response.TrustedDevices,
		UntrustedDevices: response.UntrustedDevices,
		BlockedDevices:   response.BlockedDevices,
		OfflineDevices:   response.OfflineDevices,
		OnlineDevices:    response.OnlineDevices,
	}, nil
}

// HealthCheck verifies the DHCP Monitor service is healthy
func (c *DHCPClient) HealthCheck(ctx context.Context) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("connection check failed: %w", err)
	}

	response, err := c.client.HealthCheck(ctx, &pb.Empty{})
	if err != nil {
		return fmt.Errorf("HealthCheck failed: %w", err)
	}

	if !response.Healthy {
		return fmt.Errorf("DHCP Monitor unhealthy: %s", response.DatabaseStatus)
	}

	log.Printf("[DHCPClient] HealthCheck OK - uptime: %s, queries: %d",
		response.Uptime, response.TotalQueries)
	return nil
}

// ============================================================================
// Connection Management
// ============================================================================

func (c *DHCPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *DHCPClient) GetLastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastError
}

func (c *DHCPClient) GetQueryCount() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.queryCount
}

func (c *DHCPClient) Reconnect() error {
	log.Printf("[DHCPClient] Forcing reconnection")
	return c.connect()
}

func (c *DHCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		c.connected = false
		log.Printf("[DHCPClient] Connection closed")
		return err
	}
	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// protoToDevice converts proto Device to local Device struct
func protoToDevice(p *pb.Device) *Device {
	if p == nil {
		return nil
	}
	return &Device{
		DeviceID:          p.DeviceId,
		MACAddress:        p.MacAddress,
		CurrentIP:         p.CurrentIp,
		Hostname:          p.Hostname,
		DeviceType:        p.DeviceType,
		Vendor:            p.Vendor,
		TrustStatus:       p.TrustStatus,
		InterfaceName:     p.InterfaceName,
		InterfaceIndex:    p.InterfaceIndex,
		Status:            p.Status,
		DetectionMethod:   p.DetectionMethod,
		FirstSeen:         parseTimestamp(p.FirstSeen),
		LastSeen:          parseTimestamp(p.LastSeen),
		IsOnline:          p.IsOnline,
		PortalShown:       p.PortalShown,
		PortalShownAt:     parseTimestamp(p.PortalShownAt),
		CACertInstalled:   p.CaCertInstalled,
		CACertInstalledAt: parseTimestamp(p.CaCertInstalledAt),
	}
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.NotFound {
		return true
	}
	errMsg := err.Error()
	return errMsg == "device not found" || errMsg == "not found"
}

func parseTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
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
