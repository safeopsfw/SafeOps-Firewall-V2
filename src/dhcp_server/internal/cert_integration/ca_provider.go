// Package cert_integration provides CA certificate integration for DHCP server.
// This file implements the gRPC client for Certificate Manager communication.
package cert_integration

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Configuration
// ============================================================================

// CAProviderConfig holds Certificate Manager client configuration.
type CAProviderConfig struct {
	Address           string
	Timeout           time.Duration
	MaxRetries        int
	CacheTTL          time.Duration
	HealthInterval    time.Duration
	TLSCertPath       string
	TLSKeyPath        string
	BackoffMultiplier float64
}

// DefaultCAProviderConfig returns sensible defaults.
func DefaultCAProviderConfig() *CAProviderConfig {
	return &CAProviderConfig{
		Address:           "localhost:50053",
		Timeout:           5 * time.Second,
		MaxRetries:        3,
		CacheTTL:          time.Hour,
		HealthInterval:    30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// ============================================================================
// Certificate Information
// ============================================================================

// CertificateInfo holds CA certificate distribution information.
type CertificateInfo struct {
	CAURL             string
	InstallScriptURLs []string
	WPADURL           string
	CRLURL            string
	OCSPURL           string
	ExpiresAt         time.Time
	FetchedAt         time.Time
}

// IsExpired checks if the certificate info is expired.
func (c *CertificateInfo) IsExpired(ttl time.Duration) bool {
	return time.Since(c.FetchedAt) > ttl
}

// Validate checks if all URLs are properly formatted.
func (c *CertificateInfo) Validate() error {
	// Validate CA URL (required)
	if c.CAURL == "" {
		return ErrMissingCAURL
	}
	if _, err := url.Parse(c.CAURL); err != nil {
		return ErrInvalidCAURL
	}

	// Validate optional URLs
	for _, scriptURL := range c.InstallScriptURLs {
		if _, err := url.Parse(scriptURL); err != nil {
			return ErrInvalidScriptURL
		}
	}

	if c.WPADURL != "" {
		if _, err := url.Parse(c.WPADURL); err != nil {
			return ErrInvalidWPADURL
		}
	}

	return nil
}

// ============================================================================
// CA Provider Interface
// ============================================================================

// CACertProvider defines the interface for CA certificate retrieval.
type CACertProvider interface {
	GetCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CertificateInfo, error)
	IsHealthy() bool
	Close() error
}

// ============================================================================
// gRPC CA Provider
// ============================================================================

// GRPCCertProvider implements CACertProvider using gRPC.
type GRPCCertProvider struct {
	mu     sync.RWMutex
	config *CAProviderConfig

	// Connection state
	connected     atomic.Bool
	lastConnected time.Time
	lastError     error

	// Cache
	cache   map[string]*CertificateInfo
	cacheMu sync.RWMutex

	// Health monitoring
	healthChecker *time.Ticker
	stopChan      chan struct{}

	// Statistics
	stats ProviderStats
}

// ProviderStats tracks CA provider metrics.
type ProviderStats struct {
	TotalRequests   int64
	SuccessfulCalls int64
	FailedCalls     int64
	CacheHits       int64
	CacheMisses     int64
	RetryAttempts   int64
	LastSuccessAt   time.Time
	ConsecutiveErrs int64
}

// NewGRPCCertProvider creates a new gRPC-based CA provider.
func NewGRPCCertProvider(config *CAProviderConfig) *GRPCCertProvider {
	if config == nil {
		config = DefaultCAProviderConfig()
	}

	p := &GRPCCertProvider{
		config:   config,
		cache:    make(map[string]*CertificateInfo),
		stopChan: make(chan struct{}),
	}

	return p
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes connection to Certificate Manager.
func (p *GRPCCertProvider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// In actual implementation, this would dial gRPC
	// For now, we simulate connection management
	p.connected.Store(true)
	p.lastConnected = time.Now()

	return nil
}

// Close closes the gRPC connection.
func (p *GRPCCertProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop health checker
	if p.healthChecker != nil {
		p.healthChecker.Stop()
	}

	close(p.stopChan)
	p.connected.Store(false)

	return nil
}

// IsHealthy returns the health status.
func (p *GRPCCertProvider) IsHealthy() bool {
	return p.connected.Load()
}

// ============================================================================
// Certificate Info Retrieval
// ============================================================================

// GetCertificateInfo retrieves CA certificate information.
func (p *GRPCCertProvider) GetCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CertificateInfo, error) {
	atomic.AddInt64(&p.stats.TotalRequests, 1)

	// Check cache first
	cacheKey := gatewayIP.String()
	if cached := p.getCachedInfo(cacheKey); cached != nil {
		atomic.AddInt64(&p.stats.CacheHits, 1)
		return cached, nil
	}
	atomic.AddInt64(&p.stats.CacheMisses, 1)

	// Fetch from Certificate Manager with retry
	var lastErr error
	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		if attempt > 0 {
			atomic.AddInt64(&p.stats.RetryAttempts, 1)
			backoff := p.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		info, err := p.fetchCertificateInfo(ctx, gatewayIP)
		if err == nil {
			p.cacheInfo(cacheKey, info)
			atomic.AddInt64(&p.stats.SuccessfulCalls, 1)
			atomic.StoreInt64(&p.stats.ConsecutiveErrs, 0)
			p.stats.LastSuccessAt = time.Now()
			return info, nil
		}

		lastErr = err
		if !p.isRetryable(err) {
			break
		}
	}

	atomic.AddInt64(&p.stats.FailedCalls, 1)
	atomic.AddInt64(&p.stats.ConsecutiveErrs, 1)

	// Try fallback to cached data (even if expired)
	if cached := p.getCachedInfoFallback(cacheKey); cached != nil {
		return cached, nil
	}

	return nil, lastErr
}

// fetchCertificateInfo makes the actual gRPC call.
func (p *GRPCCertProvider) fetchCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CertificateInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	if !p.connected.Load() {
		return nil, ErrNotConnected
	}

	// In actual implementation, this would call gRPC
	// For now, return mock data for compilation
	info := &CertificateInfo{
		CAURL:             "http://" + gatewayIP.String() + "/ca.crt",
		InstallScriptURLs: []string{"http://" + gatewayIP.String() + "/install.ps1"},
		WPADURL:           "http://" + gatewayIP.String() + "/wpad.dat",
		CRLURL:            "http://" + gatewayIP.String() + "/ca.crl",
		OCSPURL:           "http://" + gatewayIP.String() + "/ocsp",
		FetchedAt:         time.Now(),
	}

	if err := info.Validate(); err != nil {
		return nil, err
	}

	return info, nil
}

// ============================================================================
// Cache Management
// ============================================================================

func (p *GRPCCertProvider) getCachedInfo(key string) *CertificateInfo {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()

	cached, ok := p.cache[key]
	if !ok {
		return nil
	}

	if cached.IsExpired(p.config.CacheTTL) {
		return nil
	}

	return cached
}

func (p *GRPCCertProvider) getCachedInfoFallback(key string) *CertificateInfo {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()

	// Return cached even if expired as fallback
	return p.cache[key]
}

func (p *GRPCCertProvider) cacheInfo(key string, info *CertificateInfo) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache[key] = info
}

// InvalidateCache removes a cache entry.
func (p *GRPCCertProvider) InvalidateCache(gatewayIP net.IP) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	delete(p.cache, gatewayIP.String())
}

// ClearCache removes all cache entries.
func (p *GRPCCertProvider) ClearCache() {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache = make(map[string]*CertificateInfo)
}

// ============================================================================
// Retry Logic
// ============================================================================

func (p *GRPCCertProvider) calculateBackoff(attempt int) time.Duration {
	backoff := time.Duration(float64(100*time.Millisecond) * p.config.BackoffMultiplier * float64(attempt))
	if backoff > 10*time.Second {
		backoff = 10 * time.Second
	}
	return backoff
}

func (p *GRPCCertProvider) isRetryable(err error) bool {
	// Retryable errors
	if errors.Is(err, ErrNotConnected) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Non-retryable (validation errors, etc.)
	return false
}

// ============================================================================
// Health Monitoring
// ============================================================================

// StartHealthChecker starts the background health checker.
func (p *GRPCCertProvider) StartHealthChecker() {
	p.healthChecker = time.NewTicker(p.config.HealthInterval)
	go p.healthCheckLoop()
}

func (p *GRPCCertProvider) healthCheckLoop() {
	for {
		select {
		case <-p.healthChecker.C:
			p.performHealthCheck()
		case <-p.stopChan:
			return
		}
	}
}

func (p *GRPCCertProvider) performHealthCheck() {
	// Simulate health check
	// In actual implementation, would call gRPC health check
	if p.stats.ConsecutiveErrs > 5 {
		p.connected.Store(false)
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns provider statistics.
func (p *GRPCCertProvider) GetStats() ProviderStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// GetCacheHitRate returns the cache hit rate percentage.
func (p *GRPCCertProvider) GetCacheHitRate() float64 {
	total := p.stats.CacheHits + p.stats.CacheMisses
	if total == 0 {
		return 0
	}
	return float64(p.stats.CacheHits) / float64(total) * 100
}

// GetSuccessRate returns the success rate percentage.
func (p *GRPCCertProvider) GetSuccessRate() float64 {
	total := p.stats.SuccessfulCalls + p.stats.FailedCalls
	if total == 0 {
		return 0
	}
	return float64(p.stats.SuccessfulCalls) / float64(total) * 100
}

// ============================================================================
// Mock Provider for Testing
// ============================================================================

// MockCertProvider implements CACertProvider for testing.
type MockCertProvider struct {
	mu           sync.RWMutex
	mockResponse *CertificateInfo
	mockError    error
	callCount    int
	healthy      bool
}

// NewMockCertProvider creates a mock provider for testing.
func NewMockCertProvider() *MockCertProvider {
	return &MockCertProvider{
		healthy: true,
		mockResponse: &CertificateInfo{
			CAURL:             "http://192.168.1.1/ca.crt",
			InstallScriptURLs: []string{"http://192.168.1.1/install.ps1"},
			WPADURL:           "http://192.168.1.1/wpad.dat",
			CRLURL:            "http://192.168.1.1/ca.crl",
			OCSPURL:           "http://192.168.1.1/ocsp",
			FetchedAt:         time.Now(),
		},
	}
}

// SetResponse sets the mock response.
func (m *MockCertProvider) SetResponse(info *CertificateInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockResponse = info
}

// SetError sets the mock error.
func (m *MockCertProvider) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockError = err
}

// SetHealthy sets the health status.
func (m *MockCertProvider) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

// GetCertificateInfo returns mock certificate info.
func (m *MockCertProvider) GetCertificateInfo(ctx context.Context, gatewayIP net.IP) (*CertificateInfo, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mockError != nil {
		return nil, m.mockError
	}
	return m.mockResponse, nil
}

// IsHealthy returns mock health status.
func (m *MockCertProvider) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

// Close closes the mock provider.
func (m *MockCertProvider) Close() error {
	return nil
}

// GetCallCount returns number of calls made.
func (m *MockCertProvider) GetCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCount
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNotConnected is returned when not connected to Certificate Manager
	ErrNotConnected = errors.New("not connected to Certificate Manager")

	// ErrMissingCAURL is returned when CA URL is missing
	ErrMissingCAURL = errors.New("CA URL is required")

	// ErrInvalidCAURL is returned for malformed CA URL
	ErrInvalidCAURL = errors.New("invalid CA URL format")

	// ErrInvalidScriptURL is returned for malformed script URL
	ErrInvalidScriptURL = errors.New("invalid install script URL format")

	// ErrInvalidWPADURL is returned for malformed WPAD URL
	ErrInvalidWPADURL = errors.New("invalid WPAD URL format")

	// ErrCertManagerUnavailable is returned when service is unavailable
	ErrCertManagerUnavailable = errors.New("Certificate Manager service unavailable")
)
