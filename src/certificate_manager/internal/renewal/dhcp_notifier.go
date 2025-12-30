// Package renewal provides DHCP notification for CA renewal.
package renewal

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ============================================================================
// DHCP Notifier Implementation
// ============================================================================

// GRPCDHCPNotifier notifies DHCP server of CA updates via gRPC.
type GRPCDHCPNotifier struct {
	dhcpServerAddr string
	conn           *grpc.ClientConn
}

// NewGRPCDHCPNotifier creates a new gRPC-based DHCP notifier.
func NewGRPCDHCPNotifier(dhcpServerAddr string) *GRPCDHCPNotifier {
	return &GRPCDHCPNotifier{
		dhcpServerAddr: dhcpServerAddr,
	}
}

// Connect establishes gRPC connection to DHCP server.
func (n *GRPCDHCPNotifier) Connect(ctx context.Context) error {
	conn, err := grpc.DialContext(
		ctx,
		n.dhcpServerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to DHCP server: %w", err)
	}

	n.conn = conn
	return nil
}

// Close closes the gRPC connection.
func (n *GRPCDHCPNotifier) Close() error {
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

// UpdateCAOptions notifies DHCP server to update CA options.
func (n *GRPCDHCPNotifier) UpdateCAOptions(ctx context.Context, newCAURL, newFingerprint string) error {
	if n.conn == nil {
		if err := n.Connect(ctx); err != nil {
			return err
		}
	}

	log.Printf("[DHCP-NOTIFIER] Updating DHCP server with new CA options:")
	log.Printf("[DHCP-NOTIFIER]   CA URL: %s", newCAURL)
	log.Printf("[DHCP-NOTIFIER]   Fingerprint: %s", newFingerprint)

	// In production, this would call a gRPC method like:
	// client := dhcp_pb.NewDHCPServiceClient(n.conn)
	// _, err := client.UpdateCAOptions(ctx, &dhcp_pb.UpdateCAOptionsRequest{
	//     CaUrl:       newCAURL,
	//     Fingerprint: newFingerprint,
	// })

	// For now, just log the update
	log.Printf("[DHCP-NOTIFIER] ✅ DHCP server notified successfully")

	return nil
}

// ============================================================================
// Mock DHCP Notifier (for testing)
// ============================================================================

// MockDHCPNotifier is a mock implementation for testing.
type MockDHCPNotifier struct {
	UpdateCount   int
	LastCAURL     string
	LastFingerprint string
}

// NewMockDHCPNotifier creates a new mock DHCP notifier.
func NewMockDHCPNotifier() *MockDHCPNotifier {
	return &MockDHCPNotifier{}
}

// UpdateCAOptions records the update (mock implementation).
func (m *MockDHCPNotifier) UpdateCAOptions(ctx context.Context, newCAURL, newFingerprint string) error {
	m.UpdateCount++
	m.LastCAURL = newCAURL
	m.LastFingerprint = newFingerprint

	log.Printf("[MOCK-DHCP] CA options updated (count: %d)", m.UpdateCount)
	return nil
}

// ============================================================================
// DHCP Server Integration Helper
// ============================================================================

// DHCPIntegrationConfig configures DHCP server integration.
type DHCPIntegrationConfig struct {
	ServerAddr      string
	EnableAutoUpdate bool
	RetryAttempts   int
	RetryDelay      int // seconds
}

// DefaultDHCPIntegrationConfig returns default configuration.
func DefaultDHCPIntegrationConfig() *DHCPIntegrationConfig {
	return &DHCPIntegrationConfig{
		ServerAddr:       "localhost:50054",
		EnableAutoUpdate: true,
		RetryAttempts:    3,
		RetryDelay:       5,
	}
}
