// Package cert_integration provides CA certificate integration for DHCP server.
// This file adapts the gRPC CA provider for use by DHCP message handlers.
package cert_integration

import (
	"context"
	"net"
)

// ============================================================================
// Certificate Manager Integration Adapter
// ============================================================================

// IntegrationAdapter adapts CACertProvider for DHCP discovery layer.
// This provides the bridge between cert_integration and discovery packages.
type IntegrationAdapter struct {
	provider CACertProvider
}

// NewIntegrationAdapter creates a new integration adapter.
func NewIntegrationAdapter(provider CACertProvider) *IntegrationAdapter {
	return &IntegrationAdapter{
		provider: provider,
	}
}

// GetCertificateInfo retrieves CA certificate info for DHCP integration.
// This method signature matches the discovery.CACertProviderInterface.
func (a *IntegrationAdapter) GetCertificateInfo(ctx context.Context, gatewayIP net.IP) (*DHCPCertInfo, error) {
	// Call the underlying provider
	info, err := a.provider.GetCertificateInfo(ctx, gatewayIP)
	if err != nil {
		return nil, err
	}

	// Convert to DHCP-specific format
	dhcpInfo := &DHCPCertInfo{
		CAURL:             info.CAURL,
		InstallScriptURLs: info.InstallScriptURLs,
		WPADURL:           info.WPADURL,
		CRLURL:            info.CRLURL,
		OCSPURL:           info.OCSPURL,
	}

	return dhcpInfo, nil
}

// IsHealthy returns the health status of the CA provider.
func (a *IntegrationAdapter) IsHealthy() bool {
	if a.provider == nil {
		return false
	}
	return a.provider.IsHealthy()
}

// ============================================================================
// DHCP-Specific Certificate Info
// ============================================================================

// DHCPCertInfo contains CA certificate info formatted for DHCP options.
// This matches the format expected by discovery.ACKBuilder.
type DHCPCertInfo struct {
	CAURL             string   // Option 224 - CA certificate URL
	InstallScriptURLs []string // Option 225 - Install script URLs
	WPADURL           string   // Option 252 - WPAD URL
	CRLURL            string   // Option 226 - CRL URL
	OCSPURL           string   // Option 227 - OCSP URL
}

// ============================================================================
// Provider Factory
// ============================================================================

// ProviderFactory creates CA providers based on configuration.
type ProviderFactory struct{}

// NewProviderFactory creates a new provider factory.
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}

// CreateProvider creates a CA provider based on configuration.
func (f *ProviderFactory) CreateProvider(config *CAProviderConfig) (CACertProvider, error) {
	// Create real gRPC provider
	provider, err := NewRealGRPCCertProvider(config)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

// CreateMockProvider creates a mock provider for testing.
func (f *ProviderFactory) CreateMockProvider() CACertProvider {
	return NewMockCertProvider()
}

// ============================================================================
// Configuration Helper
// ============================================================================

// BuildCAProviderConfig creates CA provider config from DHCP server config.
func BuildCAProviderConfig(certManagerAddr string, timeout int) *CAProviderConfig {
	config := DefaultCAProviderConfig()

	if certManagerAddr != "" {
		config.Address = certManagerAddr
	}

	if timeout > 0 {
		config.Timeout = (timeout * 1000) * 1000 // Convert to time.Duration
	}

	return config
}
