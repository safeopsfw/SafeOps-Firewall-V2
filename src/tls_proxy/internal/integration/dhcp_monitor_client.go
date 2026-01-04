package integration

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DHCPMonitorClient manages gRPC connection to DHCP Monitor service
type DHCPMonitorClient struct {
	address string
	conn    *grpc.ClientConn
	client  interface{} // Will be replaced with actual proto client
	mu      sync.RWMutex
	timeout time.Duration
}

// DeviceTrustInfo contains device trust status information
type DeviceTrustInfo struct {
	DeviceID        string
	MACAddress      string
	IP              string
	TrustStatus     string // TRUSTED, UNTRUSTED, BLOCKED
	Hostname        string
	DeviceType      string
	IsOnline        bool
	PortalShown     bool // Phase 3A: Has device seen captive portal?
	CaCertInstalled bool // Phase 3B: Has device installed CA certificate?
}

// NewDHCPMonitorClient creates a new DHCP Monitor gRPC client
func NewDHCPMonitorClient(address string, timeout time.Duration) (*DHCPMonitorClient, error) {
	if address == "" {
		return nil, fmt.Errorf("DHCP Monitor address cannot be empty")
	}

	client := &DHCPMonitorClient{
		address: address,
		timeout: timeout,
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to DHCP Monitor: %w", err)
	}

	log.Printf("[DHCP Monitor Client] Connected to DHCP Monitor at %s", address)
	return client, nil
}

// Connect establishes gRPC connection to DHCP Monitor
func (c *DHCPMonitorClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to dial DHCP Monitor: %w", err)
	}

	c.conn = conn
	// TODO: Initialize actual proto client when proto is integrated
	// c.client = dhcp_monitor.NewDHCPMonitorServiceClient(conn)

	return nil
}

// GetDeviceByIP queries DHCP Monitor for device information by IP address
func (c *DHCPMonitorClient) GetDeviceByIP(ctx context.Context, ipAddress string) (*DeviceTrustInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return nil, fmt.Errorf("DHCP Monitor client not connected")
	}

	// Create request context with timeout
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// TODO: Replace with actual gRPC call when proto is integrated
	// For now, simulate response for Phase 3A
	_ = callCtx // Use context to avoid unused var error

	// Temporary Phase 3A stub: Return UNTRUSTED for all devices
	// Real implementation will call:
	// req := &dhcp_monitor.IPRequest{IpAddress: ipAddress}
	// resp, err := c.client.GetDeviceByIP(callCtx, req)

	log.Printf("[DHCP Monitor] Query for IP %s (stub response: UNTRUSTED)", ipAddress)

	return &DeviceTrustInfo{
		DeviceID:    "stub-device-id",
		MACAddress:  "00:00:00:00:00:00",
		IP:          ipAddress,
		TrustStatus: "UNTRUSTED", // Phase 3A: All devices untrusted by default
		Hostname:    "unknown",
		DeviceType:  "Unknown",
		IsOnline:    true,
		PortalShown: false, // Phase 3A: Portal not shown yet (stub)
	}, nil
}

// GetDeviceByMAC queries DHCP Monitor for device information by MAC address
func (c *DHCPMonitorClient) GetDeviceByMAC(ctx context.Context, macAddress string) (*DeviceTrustInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return nil, fmt.Errorf("DHCP Monitor client not connected")
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_ = callCtx

	log.Printf("[DHCP Monitor] Query for MAC %s (stub response: UNTRUSTED)", macAddress)

	return &DeviceTrustInfo{
		DeviceID:    "stub-device-id",
		MACAddress:  macAddress,
		IP:          "0.0.0.0",
		TrustStatus: "UNTRUSTED",
		Hostname:    "unknown",
		DeviceType:  "Unknown",
		IsOnline:    true,
	}, nil
}

// UpdateTrustStatus updates the trust status of a device
func (c *DHCPMonitorClient) UpdateTrustStatus(ctx context.Context, deviceID, trustStatus string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return fmt.Errorf("DHCP Monitor client not connected")
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_ = callCtx

	log.Printf("[DHCP Monitor] Update trust status for device %s to %s (stub)", deviceID, trustStatus)

	// TODO: Real implementation
	// req := &dhcp_monitor.TrustUpdateRequest{DeviceId: deviceID, TrustStatus: trustStatus}
	// _, err := c.client.UpdateTrustStatus(callCtx, req)

	return nil
}

// Close closes the gRPC connection
func (c *DHCPMonitorClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}

// IsConnected returns whether the client is connected
func (c *DHCPMonitorClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// Reconnect attempts to reconnect to DHCP Monitor
func (c *DHCPMonitorClient) Reconnect() error {
	c.Close()
	return c.Connect()
}
