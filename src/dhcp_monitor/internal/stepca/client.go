// Package stepca provides integration with Step-CA for certificate management
package stepca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"
)

// Client handles Step-CA integration for certificate verification and distribution
type Client struct {
	rootCertPath string
	rootCA       *x509.Certificate
	rootCertPEM  []byte
	mu           sync.RWMutex
}

// Config holds Step-CA client configuration
type Config struct {
	RootCertPath string
	APIURL       string // For future Step-CA API integration
	Timeout      time.Duration
}

// NewClient creates a new Step-CA client
func NewClient(cfg Config) (*Client, error) {
	client := &Client{
		rootCertPath: cfg.RootCertPath,
	}

	// Load root certificate
	if err := client.loadRootCert(); err != nil {
		return nil, fmt.Errorf("failed to load root certificate: %w", err)
	}

	return client, nil
}

// loadRootCert loads and parses the Step-CA root certificate
func (c *Client) loadRootCert() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read certificate file
	certPEM, err := os.ReadFile(c.rootCertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file %s: %w", c.rootCertPath, err)
	}

	// Decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from certificate file")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	c.rootCA = cert
	c.rootCertPEM = certPEM

	return nil
}

// GetRootCertificate returns the parsed root CA certificate
func (c *Client) GetRootCertificate() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rootCA
}

// GetRootCertPEM returns the raw PEM bytes for the root certificate
func (c *Client) GetRootCertPEM() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rootCertPEM
}

// GetRootCertInfo returns information about the root CA
func (c *Client) GetRootCertInfo() *CertInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.rootCA == nil {
		return nil
	}

	now := time.Now()
	daysRemaining := int(c.rootCA.NotAfter.Sub(now).Hours() / 24)
	validityYears := int(c.rootCA.NotAfter.Sub(c.rootCA.NotBefore).Hours() / 24 / 365)

	return &CertInfo{
		Subject:       c.rootCA.Subject.CommonName,
		Issuer:        c.rootCA.Issuer.CommonName,
		SerialNumber:  c.rootCA.SerialNumber.String(),
		NotBefore:     c.rootCA.NotBefore,
		NotAfter:      c.rootCA.NotAfter,
		DaysRemaining: daysRemaining,
		ValidityYears: validityYears,
		IsCA:          c.rootCA.IsCA,
	}
}

// CertInfo contains certificate information
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	ValidityYears int       `json:"validity_years"`
	IsCA          bool      `json:"is_ca"`
}

// Reload reloads the root certificate from disk
func (c *Client) Reload() error {
	return c.loadRootCert()
}
