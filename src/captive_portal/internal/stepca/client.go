// ============================================================================
// SafeOps Captive Portal - Step-CA HTTP Client
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\stepca\client.go
// Purpose: HTTP client for fetching CA certificates from Step-CA server
//
// The Captive Portal uses this client to:
//   1. Fetch the Root CA certificate for download by devices
//   2. Check Step-CA server health status
//   3. Cache certificates locally to reduce API calls
//   4. Convert certificates to multiple formats (PEM, DER, PKCS#12)
//
// Step-CA HTTPS API runs on port 9000 (Phase 3A)
//
// API Endpoints Used:
//   - GET /health              - Health check
//   - GET /roots.pem           - Root CA certificate chain (PEM format)
//   - GET /root/{fingerprint}  - Specific root CA by fingerprint
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package stepca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// ============================================================================
// Certificate Format Constants
// ============================================================================

const (
	// FormatPEM - PEM encoded certificate (most universal)
	FormatPEM = "pem"

	// FormatDER - DER encoded certificate (Windows native)
	FormatDER = "der"

	// FormatPKCS12 - PKCS#12 format (iOS/Android)
	FormatPKCS12 = "p12"
)

// ============================================================================
// Step-CA Client Configuration
// ============================================================================

// StepCAClientConfig holds configuration for the Step-CA client
type StepCAClientConfig struct {
	// BaseURL is the Step-CA API base URL (e.g., "https://localhost:9000")
	BaseURL string

	// VerifySSL controls whether to verify Step-CA's TLS certificate
	// Set to false since Step-CA uses a self-signed cert initially
	VerifySSL bool

	// Timeout is the HTTP request timeout
	Timeout time.Duration

	// CacheTTL is how long to cache the root CA certificate
	CacheTTL time.Duration

	// RetryAttempts is the number of times to retry failed requests
	RetryAttempts int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration
}

// DefaultStepCAClientConfig returns default configuration values
func DefaultStepCAClientConfig() StepCAClientConfig {
	return StepCAClientConfig{
		BaseURL:       "https://localhost:9000",
		VerifySSL:     false, // Step-CA uses self-signed cert
		Timeout:       10 * time.Second,
		CacheTTL:      5 * time.Minute,
		RetryAttempts: 3,
		RetryDelay:    1 * time.Second,
	}
}

// ============================================================================
// Cached Certificate Data
// ============================================================================

// CachedCertificate holds a cached certificate with metadata
type CachedCertificate struct {
	// PEMData is the raw PEM-encoded certificate
	PEMData []byte

	// DERData is the DER-encoded certificate (computed from PEM)
	DERData []byte

	// Certificate is the parsed X.509 certificate
	Certificate *x509.Certificate

	// FetchedAt is when the certificate was fetched
	FetchedAt time.Time

	// ExpiresAt is when the certificate expires
	ExpiresAt time.Time

	// Fingerprint is the SHA-256 fingerprint
	Fingerprint string

	// Subject is the certificate subject
	Subject string

	// Issuer is the certificate issuer
	Issuer string
}

// ============================================================================
// Health Check Response
// ============================================================================

// HealthResponse represents Step-CA health check response
type HealthResponse struct {
	Status string `json:"status"` // "ok" if healthy
}

// ============================================================================
// Step-CA Client Implementation
// ============================================================================

// StepCAClient is an HTTP client for the Step-CA server
type StepCAClient struct {
	config     StepCAClientConfig
	httpClient *http.Client
	mu         sync.RWMutex

	// Cached root CA
	rootCA       *CachedCertificate
	rootCACached time.Time

	// Statistics
	requestCount  int64
	cacheHits     int64
	cacheMisses   int64
	lastError     error
	lastErrorTime time.Time
}

// NewStepCAClient creates a new Step-CA client
func NewStepCAClient(config StepCAClientConfig) *StepCAClient {
	// Create HTTP transport with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 5,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	client := &StepCAClient{
		config:     config,
		httpClient: httpClient,
	}

	log.Printf("[StepCAClient] Initialized with base URL: %s", config.BaseURL)
	return client
}

// ============================================================================
// Health Check Methods
// ============================================================================

// HealthCheck verifies the Step-CA server is running and healthy
func (c *StepCAClient) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/health", c.config.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordError(err)
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	c.mu.Lock()
	c.requestCount++
	c.mu.Unlock()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	// Parse response
	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("failed to parse health response: %w", err)
	}

	if health.Status != "ok" {
		return fmt.Errorf("step-CA unhealthy: status=%s", health.Status)
	}

	log.Printf("[StepCAClient] Health check passed")
	return nil
}

// IsHealthy returns true if Step-CA is reachable and healthy
func (c *StepCAClient) IsHealthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.HealthCheck(ctx) == nil
}

// ============================================================================
// Root CA Certificate Methods
// ============================================================================

// GetRootCA fetches and caches the root CA certificate
// Returns cached version if still valid
func (c *StepCAClient) GetRootCA(ctx context.Context) (*CachedCertificate, error) {
	// Check cache first
	c.mu.RLock()
	if c.rootCA != nil && time.Since(c.rootCACached) < c.config.CacheTTL {
		c.cacheHits++
		c.mu.RUnlock()
		log.Printf("[StepCAClient] Returning cached root CA")
		return c.rootCA, nil
	}
	c.mu.RUnlock()

	// Cache miss - fetch from Step-CA
	c.mu.Lock()
	c.cacheMisses++
	c.mu.Unlock()

	log.Printf("[StepCAClient] Fetching root CA from Step-CA")
	return c.fetchRootCA(ctx)
}

// fetchRootCA fetches the root CA from Step-CA API
func (c *StepCAClient) fetchRootCA(ctx context.Context) (*CachedCertificate, error) {
	url := fmt.Sprintf("%s/roots.pem", c.config.BaseURL)

	var lastErr error
	for attempt := 1; attempt <= c.config.RetryAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[StepCAClient] Attempt %d failed: %v", attempt, err)
			time.Sleep(c.config.RetryDelay)
			continue
		}
		defer resp.Body.Close()

		c.mu.Lock()
		c.requestCount++
		c.mu.Unlock()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("step-CA returned status %d", resp.StatusCode)
			log.Printf("[StepCAClient] Attempt %d: %v", attempt, lastErr)
			time.Sleep(c.config.RetryDelay)
			continue
		}

		// Read PEM data
		pemData, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			time.Sleep(c.config.RetryDelay)
			continue
		}

		// Parse and cache the certificate
		cached, err := c.parseCertificate(pemData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		// Update cache
		c.mu.Lock()
		c.rootCA = cached
		c.rootCACached = time.Now()
		c.lastError = nil
		c.mu.Unlock()

		log.Printf("[StepCAClient] Root CA fetched and cached: subject=%s, expires=%s",
			cached.Subject, cached.ExpiresAt.Format("2006-01-02"))
		return cached, nil
	}

	c.recordError(lastErr)
	return nil, fmt.Errorf("failed to fetch root CA after %d attempts: %w",
		c.config.RetryAttempts, lastErr)
}

// parseCertificate parses PEM data and creates a CachedCertificate
func (c *StepCAClient) parseCertificate(pemData []byte) (*CachedCertificate, error) {
	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Calculate fingerprint
	fingerprint := fmt.Sprintf("%x", cert.Raw)[:64] // First 32 bytes (64 hex chars)

	cached := &CachedCertificate{
		PEMData:     pemData,
		DERData:     block.Bytes,
		Certificate: cert,
		FetchedAt:   time.Now(),
		ExpiresAt:   cert.NotAfter,
		Fingerprint: fingerprint,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
	}

	return cached, nil
}

// ============================================================================
// Certificate Format Conversion Methods
// ============================================================================

// GetRootCAPEM returns the root CA in PEM format
func (c *StepCAClient) GetRootCAPEM(ctx context.Context) ([]byte, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return nil, err
	}
	return cached.PEMData, nil
}

// GetRootCADER returns the root CA in DER format
func (c *StepCAClient) GetRootCADER(ctx context.Context) ([]byte, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return nil, err
	}
	return cached.DERData, nil
}

// GetRootCAPKCS12 returns the root CA in PKCS#12 format
// Note: This requires OpenSSL to be available in PATH
func (c *StepCAClient) GetRootCAPKCS12(ctx context.Context) ([]byte, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return nil, err
	}

	// Use OpenSSL to convert PEM to PKCS#12
	// Note: This creates a certificate-only PKCS#12 (no private key)
	cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-nokeys",
		"-in", "-", // Read from stdin
		"-out", "-", // Write to stdout
		"-passout", "pass:", // No password
		"-name", "SafeOps Root CA",
	)

	cmd.Stdin = bytes.NewReader(cached.PEMData)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to convert to PKCS#12: %w", err)
	}

	return output, nil
}

// GetCertificateInFormat returns the root CA in the specified format
func (c *StepCAClient) GetCertificateInFormat(ctx context.Context, format string) ([]byte, string, error) {
	switch format {
	case FormatPEM, "crt", "cer":
		data, err := c.GetRootCAPEM(ctx)
		return data, "application/x-pem-file", err

	case FormatDER:
		data, err := c.GetRootCADER(ctx)
		return data, "application/x-x509-ca-cert", err

	case FormatPKCS12, "pfx":
		data, err := c.GetRootCAPKCS12(ctx)
		return data, "application/x-pkcs12", err

	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// ============================================================================
// Certificate Information Methods
// ============================================================================

// GetCertificateInfo returns information about the cached root CA
func (c *StepCAClient) GetCertificateInfo(ctx context.Context) (map[string]interface{}, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return nil, err
	}

	info := map[string]interface{}{
		"subject":           cached.Subject,
		"issuer":            cached.Issuer,
		"fingerprint":       cached.Fingerprint,
		"not_before":        cached.Certificate.NotBefore.Format(time.RFC3339),
		"not_after":         cached.ExpiresAt.Format(time.RFC3339),
		"fetched_at":        cached.FetchedAt.Format(time.RFC3339),
		"is_ca":             cached.Certificate.IsCA,
		"key_usage":         cached.Certificate.KeyUsage,
		"serial":            cached.Certificate.SerialNumber.String(),
		"days_until_expiry": int(time.Until(cached.ExpiresAt).Hours() / 24),
	}

	return info, nil
}

// IsCertificateExpired checks if the root CA is expired
func (c *StepCAClient) IsCertificateExpired(ctx context.Context) (bool, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return false, err
	}
	return time.Now().After(cached.ExpiresAt), nil
}

// DaysUntilExpiry returns the number of days until the root CA expires
func (c *StepCAClient) DaysUntilExpiry(ctx context.Context) (int, error) {
	cached, err := c.GetRootCA(ctx)
	if err != nil {
		return 0, err
	}
	days := int(time.Until(cached.ExpiresAt).Hours() / 24)
	return days, nil
}

// ============================================================================
// Cache Management Methods
// ============================================================================

// InvalidateCache clears the cached root CA
func (c *StepCAClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rootCA = nil
	c.rootCACached = time.Time{}
	log.Printf("[StepCAClient] Cache invalidated")
}

// RefreshCache forces a refresh of the cached root CA
func (c *StepCAClient) RefreshCache(ctx context.Context) error {
	c.InvalidateCache()
	_, err := c.GetRootCA(ctx)
	return err
}

// GetCacheInfo returns information about the cache state
func (c *StepCAClient) GetCacheInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info := map[string]interface{}{
		"has_cached_cert": c.rootCA != nil,
		"cache_hits":      c.cacheHits,
		"cache_misses":    c.cacheMisses,
		"request_count":   c.requestCount,
	}

	if c.rootCA != nil {
		info["cached_at"] = c.rootCACached.Format(time.RFC3339)
		info["cache_age_seconds"] = int(time.Since(c.rootCACached).Seconds())
		info["cache_ttl_seconds"] = int(c.config.CacheTTL.Seconds())
		info["cache_expires_in"] = int((c.config.CacheTTL - time.Since(c.rootCACached)).Seconds())
	}

	return info
}

// ============================================================================
// Error Handling Methods
// ============================================================================

// recordError stores the last error encountered
func (c *StepCAClient) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = err
	c.lastErrorTime = time.Now()
}

// GetLastError returns the last error encountered
func (c *StepCAClient) GetLastError() (error, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastError, c.lastErrorTime
}

// ============================================================================
// Cleanup Methods
// ============================================================================

// Close closes the HTTP client and clears the cache
func (c *StepCAClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rootCA = nil
	c.httpClient.CloseIdleConnections()
	log.Printf("[StepCAClient] Client closed")
}
