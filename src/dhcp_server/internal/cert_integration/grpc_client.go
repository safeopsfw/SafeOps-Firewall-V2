// Package cert_integration provides CA certificate integration for DHCP server.
// This file implements the real gRPC client for Certificate Manager communication.
package cert_integration

import (
	"context"
	"fmt"
	"net"
	"time"

	pb "safeops/build/proto/go/certificate_manager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// ============================================================================
// Real gRPC Certificate Provider Implementation
// ============================================================================

// RealGRPCCertProvider implements CACertProvider using actual gRPC client.
type RealGRPCCertProvider struct {
	*GRPCCertProvider // Embed base provider for caching and stats

	// gRPC connection
	conn   *grpc.ClientConn
	client pb.CertificateManagerServiceClient
}

// NewRealGRPCCertProvider creates a new real gRPC-based CA provider.
func NewRealGRPCCertProvider(config *CAProviderConfig) (*RealGRPCCertProvider, error) {
	if config == nil {
		config = DefaultCAProviderConfig()
	}

	base := NewGRPCCertProvider(config)

	provider := &RealGRPCCertProvider{
		GRPCCertProvider: base,
	}

	return provider, nil
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes gRPC connection to Certificate Manager.
func (p *RealGRPCCertProvider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close existing connection if any
	if p.conn != nil {
		p.conn.Close()
	}

	// Configure gRPC dial options
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	// Add TLS credentials if configured
	if p.config.TLSCertPath != "" && p.config.TLSKeyPath != "" {
		// TODO: Add TLS credentials when needed
		// creds, err := credentials.NewClientTLSFromFile(p.config.TLSCertPath, "")
		// dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}

	// Create connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(connectCtx, p.config.Address, dialOpts...)
	if err != nil {
		p.lastError = err
		return fmt.Errorf("failed to connect to Certificate Manager at %s: %w", p.config.Address, err)
	}

	p.conn = conn
	p.client = pb.NewCertificateManagerServiceClient(conn)
	p.connected.Store(true)
	p.lastConnected = time.Now()
	p.lastError = nil

	return nil
}

// Close closes the gRPC connection.
func (p *RealGRPCCertProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop health checker
	if p.healthChecker != nil {
		p.healthChecker.Stop()
	}

	close(p.stopChan)

	if p.conn != nil {
		err := p.conn.Close()
		p.conn = nil
		p.client = nil
		p.connected.Store(false)
		return err
	}

	return nil
}

// IsHealthy returns true if connected to Certificate Manager.
func (p *RealGRPCCertProvider) IsHealthy() bool {
	if p.conn == nil {
		return false
	}

	state := p.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// ============================================================================
// Certificate Info Retrieval (Override base implementation)
// ============================================================================

// fetchCertificateInfo makes the actual gRPC call to Certificate Manager.
func (p *RealGRPCCertProvider) fetchCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CertificateInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	if p.client == nil {
		return nil, ErrNotConnected
	}

	// Call GetCertificateInfo RPC
	req := &pb.GetCertificateInfoRequest{}
	resp, err := p.client.GetCertificateInfo(ctx, req)
	if err != nil {
		p.mu.Lock()
		p.lastError = err
		p.mu.Unlock()
		return nil, fmt.Errorf("GetCertificateInfo RPC failed: %w", err)
	}

	// Check if CA is available
	if !resp.CaAvailable {
		return nil, fmt.Errorf("CA certificate not available on Certificate Manager")
	}

	// Convert proto response to CertificateInfo
	info := &CertificateInfo{
		CAURL:             resp.CaUrl,
		InstallScriptURLs: resp.InstallScriptUrls,
		CRLURL:            resp.CrlUrl,
		OCSPURL:           resp.OcspUrl,
		FetchedAt:         time.Now(),
	}

	// Parse CA expiry if provided
	if resp.CaValidUntil != nil {
		info.ExpiresAt = time.Unix(resp.CaValidUntil.Seconds, int64(resp.CaValidUntil.Nanos))
	}

	// Set WPAD URL as first script URL if available
	if len(resp.InstallScriptUrls) > 0 {
		info.WPADURL = resp.InstallScriptUrls[0]
	}

	// Validate the info
	if err := info.Validate(); err != nil {
		return nil, fmt.Errorf("invalid certificate info from server: %w", err)
	}

	return info, nil
}

// ============================================================================
// Device Status Management
// ============================================================================

// GetDeviceStatus retrieves device CA installation status from Certificate Manager.
func (p *RealGRPCCertProvider) GetDeviceStatus(ctx context.Context, deviceIP net.IP, macAddr string) (*DeviceStatus, error) {
	if p.client == nil {
		return nil, ErrNotConnected
	}

	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req := &pb.GetDeviceStatusRequest{
		DeviceIp:   deviceIP.String(),
		MacAddress: macAddr,
	}

	resp, err := p.client.GetDeviceStatus(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetDeviceStatus RPC failed: %w", err)
	}

	status := &DeviceStatus{
		DeviceIP:      deviceIP,
		MACAddress:    macAddr,
		Hostname:      resp.Hostname,
		CAInstalled:   resp.CaInstalled,
		TrustStatus:   resp.TrustStatus,
		DownloadCount: int(resp.DownloadCount),
		OSType:        resp.OsType,
		Found:         resp.Found,
	}

	if resp.DetectedAt != nil {
		status.DetectedAt = time.Unix(resp.DetectedAt.Seconds, int64(resp.DetectedAt.Nanos))
	}

	if resp.LastSeen != nil {
		status.LastSeen = time.Unix(resp.LastSeen.Seconds, int64(resp.LastSeen.Nanos))
	}

	return status, nil
}

// UpdateDeviceStatus updates device CA installation status in Certificate Manager.
func (p *RealGRPCCertProvider) UpdateDeviceStatus(ctx context.Context, status *DeviceStatus) error {
	if p.client == nil {
		return ErrNotConnected
	}

	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req := &pb.UpdateDeviceStatusRequest{
		DeviceIp:    status.DeviceIP.String(),
		MacAddress:  status.MACAddress,
		Hostname:    status.Hostname,
		CaInstalled: status.CAInstalled,
		OsType:      status.OSType,
		UserAgent:   status.UserAgent,
	}

	_, err := p.client.UpdateDeviceStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateDeviceStatus RPC failed: %w", err)
	}

	return nil
}

// ============================================================================
// Device Status Structure
// ============================================================================

// DeviceStatus holds device CA installation status.
type DeviceStatus struct {
	DeviceIP      net.IP
	MACAddress    string
	Hostname      string
	CAInstalled   bool
	TrustStatus   string // "unknown", "trusted", "untrusted", "pending"
	DetectedAt    time.Time
	LastSeen      time.Time
	DownloadCount int
	OSType        string
	UserAgent     string
	Found         bool
}

// ============================================================================
// Connection State Monitoring
// ============================================================================

// WatchConnectionState monitors connection state changes.
func (p *RealGRPCCertProvider) WatchConnectionState(ctx context.Context) {
	if p.conn == nil {
		return
	}

	go func() {
		for {
			state := p.conn.GetState()
			p.conn.WaitForStateChange(ctx, state)

			select {
			case <-ctx.Done():
				return
			default:
				newState := p.conn.GetState()
				p.onStateChange(state, newState)
			}
		}
	}()
}

func (p *RealGRPCCertProvider) onStateChange(oldState, newState connectivity.State) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch newState {
	case connectivity.Ready:
		p.connected.Store(true)
		p.lastConnected = time.Now()
	case connectivity.TransientFailure, connectivity.Shutdown:
		p.connected.Store(false)
	}
}

// ============================================================================
// Health Check Override
// ============================================================================

func (p *RealGRPCCertProvider) performHealthCheck() {
	if p.client == nil {
		p.connected.Store(false)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get certificate info as health check
	_, err := p.client.GetCertificateInfo(ctx, &pb.GetCertificateInfoRequest{})
	if err != nil {
		p.mu.Lock()
		p.stats.ConsecutiveErrs++
		p.lastError = err
		p.mu.Unlock()

		if p.stats.ConsecutiveErrs > 5 {
			p.connected.Store(false)
		}
	} else {
		p.mu.Lock()
		p.stats.ConsecutiveErrs = 0
		p.lastError = nil
		p.mu.Unlock()
		p.connected.Store(true)
	}
}

// ============================================================================
// Automatic Reconnection
// ============================================================================

// StartAutoReconnect starts automatic reconnection on failures.
func (p *RealGRPCCertProvider) StartAutoReconnect(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stopChan:
				return
			case <-ticker.C:
				if !p.IsHealthy() {
					// Try to reconnect
					reconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := p.Connect(reconnectCtx); err != nil {
						// Reconnection failed, will retry next interval
						_ = err
					}
					cancel()
				}
			}
		}
	}()
}
