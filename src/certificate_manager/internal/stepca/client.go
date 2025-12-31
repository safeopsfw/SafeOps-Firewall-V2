// Package stepca provides a client for step-ca Certificate Authority integration.
package stepca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client represents a step-ca API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	rootCA     *x509.Certificate
}

// ClientConfig holds configuration for step-ca client
type ClientConfig struct {
	BaseURL    string // Base URL of step-ca server (e.g., "https://localhost:9000")
	RootCAPath string // Path to root CA certificate for verification
	Timeout    time.Duration
}

// CertificateRequest represents a certificate signing request
type CertificateRequest struct {
	CommonName string
	SANs       []string // Subject Alternative Names
	NotBefore  time.Time
	NotAfter   time.Time
}

// CertificateResponse represents a signed certificate response
type CertificateResponse struct {
	Certificate string `json:"crt"`
	CertChain   string `json:"crtChain,omitempty"`
	CA          string `json:"ca"`
}

// NewClient creates a new step-ca client
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://localhost:9000"
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	// Load root CA if provided
	var rootCA *x509.Certificate
	if cfg.RootCAPath != "" {
		certPEM, err := os.ReadFile(cfg.RootCAPath)
		if err == nil {
			block, _ := decodePEM(certPEM)
			if block != nil {
				rootCA, _ = x509.ParseCertificate(block.Bytes)
			}
		}
	}

	// Create HTTP client with TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For now, since we're using self-signed certs
	}

	if rootCA != nil {
		certPool := x509.NewCertPool()
		certPool.AddCert(rootCA)
		tlsConfig.RootCAs = certPool
		tlsConfig.InsecureSkipVerify = false
	}

	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Client{
		baseURL:    cfg.BaseURL,
		httpClient: httpClient,
		rootCA:     rootCA,
	}, nil
}

// Health checks if the step-ca server is healthy
func (c *Client) Health(ctx context.Context) error {
	url := c.baseURL + "/health"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// GetRootCA retrieves the root CA certificate from step-ca
func (c *Client) GetRootCA(ctx context.Context) ([]byte, error) {
	url := c.baseURL + "/root"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create root CA request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get root CA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get root CA returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SignCertificate signs a certificate using step-ca's sign endpoint
// This is a simplified version - in production you'd use the full ACME protocol
func (c *Client) SignCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	// For now, we'll use the ACME protocol which step-ca supports
	// This is a placeholder - full ACME implementation would go here

	// In production, you would:
	// 1. Create ACME account
	// 2. Create ACME order for the domain
	// 3. Complete challenges (DNS-01 or HTTP-01)
	// 4. Finalize order and retrieve certificate

	return nil, fmt.Errorf("direct certificate signing not implemented - use ACME protocol")
}

// GetACMEDirectory returns the ACME directory URL for the SafeOps provisioner
func (c *Client) GetACMEDirectory() string {
	return c.baseURL + "/acme/safeops-acme/directory"
}

// Close closes the client connection
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// Helper function to decode PEM
func decodePEM(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}
	return block, nil
}
