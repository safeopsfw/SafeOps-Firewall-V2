// Package captive provides gRPC client for Certificate Manager integration.
package captive

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// CertClient provides integration with Certificate Manager service
type CertClient struct {
	address    string
	httpClient *http.Client

	// Cache for enrollment status
	cache    map[string]*enrollmentCache
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
}

type enrollmentCache struct {
	enrolled  bool
	expiresAt time.Time
}

// CertClientConfig holds configuration for the certificate client
type CertClientConfig struct {
	Address  string        // Certificate Manager address (e.g., "localhost:50055")
	CacheTTL time.Duration // How long to cache enrollment status
}

// NewCertClient creates a new Certificate Manager client
func NewCertClient(cfg *CertClientConfig) *CertClient {
	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	return &CertClient{
		address: cfg.Address,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache:    make(map[string]*enrollmentCache),
		cacheTTL: cacheTTL,
	}
}

// IsDeviceEnrolled checks if a device has a valid certificate installed
func (c *CertClient) IsDeviceEnrolled(ctx context.Context, ipAddress string) bool {
	// Check cache first
	if cached := c.checkCache(ipAddress); cached != nil {
		return *cached
	}

	// Query Certificate Manager
	enrolled := c.queryEnrollmentStatus(ctx, ipAddress)

	// Cache result
	c.cacheResult(ipAddress, enrolled)

	return enrolled
}

// checkCache checks the enrollment cache
func (c *CertClient) checkCache(ipAddress string) *bool {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	if entry, ok := c.cache[ipAddress]; ok {
		if time.Now().Before(entry.expiresAt) {
			return &entry.enrolled
		}
	}
	return nil
}

// cacheResult stores enrollment result in cache
func (c *CertClient) cacheResult(ipAddress string, enrolled bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[ipAddress] = &enrollmentCache{
		enrolled:  enrolled,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
}

// queryEnrollmentStatus queries Certificate Manager for device enrollment
func (c *CertClient) queryEnrollmentStatus(ctx context.Context, ipAddress string) bool {
	// Try HTTP API first (simpler than gRPC for this check)
	url := fmt.Sprintf("http://%s/api/enrollment/check?ip=%s", c.address, ipAddress)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Printf("[CertClient] Request error: %v", err)
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[CertClient] Connection error to %s: %v", c.address, err)
		// If can't reach cert manager, assume not enrolled (safer default)
		return false
	}
	defer resp.Body.Close()

	// 200 = enrolled, 404 = not enrolled, other = error
	return resp.StatusCode == http.StatusOK
}

// MarkDeviceEnrolled notifies Certificate Manager that a device is enrolled
func (c *CertClient) MarkDeviceEnrolled(ctx context.Context, ipAddress, osType, method string) error {
	url := fmt.Sprintf("http://%s/api/enrollment/mark", c.address)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("ip", ipAddress)
	q.Add("os", osType)
	q.Add("method", method)
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to notify cert manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cert manager returned status %d", resp.StatusCode)
	}

	// Update cache
	c.cacheResult(ipAddress, true)

	return nil
}

// ClearCache clears the enrollment cache
func (c *CertClient) ClearCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = make(map[string]*enrollmentCache)
}

// Close closes the client connections
func (c *CertClient) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
