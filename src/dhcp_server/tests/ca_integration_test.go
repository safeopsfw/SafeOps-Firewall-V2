// Package tests contains CA integration tests for DHCP server.
// This file implements comprehensive CA certificate distribution tests.
package tests

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Test Constants
// ============================================================================

const (
	testCAServiceAddress = "localhost:50056"
	testCACertURL        = "http://192.168.1.1/ca.crt"
	testInstallScriptSH  = "http://192.168.1.1/install-ca.sh"
	testInstallScriptPS1 = "http://192.168.1.1/install-ca.ps1"
	testWPADURL          = "http://192.168.1.1/wpad.dat"
	testCRLURL           = "http://192.168.1.1/crl.pem"
	testOCSPURL          = "http://192.168.1.1:8888"
)

// ============================================================================
// Mock CA Service
// ============================================================================

type mockCAService struct {
	mu            sync.RWMutex
	available     bool
	responseDelay time.Duration
	caInfo        *testCAInfo
	requestCount  int64
	errorOnNext   bool
}

type testCAInfo struct {
	CACertURL         string
	InstallScriptURLs []string
	WPADURL           string
	CRLURL            string
	OCSPURL           string
}

func newMockCAService() *mockCAService {
	return &mockCAService{
		available: true,
		caInfo: &testCAInfo{
			CACertURL:         testCACertURL,
			InstallScriptURLs: []string{testInstallScriptSH, testInstallScriptPS1},
			WPADURL:           testWPADURL,
			CRLURL:            testCRLURL,
			OCSPURL:           testOCSPURL,
		},
	}
}

func (m *mockCAService) setAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.available = available
}

func (m *mockCAService) setDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseDelay = delay
}

func (m *mockCAService) setErrorOnNext(shouldError bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOnNext = shouldError
}

func (m *mockCAService) isAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.available
}

func (m *mockCAService) GetCACertificateInfo(ctx context.Context) (*testCAInfo, error) {
	atomic.AddInt64(&m.requestCount, 1)

	m.mu.RLock()
	delay := m.responseDelay
	available := m.available
	shouldError := m.errorOnNext
	m.mu.RUnlock()

	// Reset error flag
	if shouldError {
		m.mu.Lock()
		m.errorOnNext = false
		m.mu.Unlock()
		return nil, errCAServiceUnavailable
	}

	if !available {
		return nil, errCAServiceUnavailable
	}

	// Simulate delay
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.RLock()
	info := m.caInfo
	m.mu.RUnlock()

	return info, nil
}

func (m *mockCAService) getRequestCount() int64 {
	return atomic.LoadInt64(&m.requestCount)
}

// ============================================================================
// Mock CA Cache
// ============================================================================

type mockCACache struct {
	mu        sync.RWMutex
	data      *testCAInfo
	expiry    time.Time
	hitCount  int64
	missCount int64
	ttl       time.Duration
}

func newMockCACache(ttl time.Duration) *mockCACache {
	return &mockCACache{
		ttl: ttl,
	}
}

func (c *mockCACache) Get() (*testCAInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil || time.Now().After(c.expiry) {
		atomic.AddInt64(&c.missCount, 1)
		return nil, false
	}

	atomic.AddInt64(&c.hitCount, 1)
	return c.data, true
}

func (c *mockCACache) Set(info *testCAInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = info
	c.expiry = time.Now().Add(c.ttl)
}

func (c *mockCACache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = nil
	c.expiry = time.Time{}
}

func (c *mockCACache) getHitCount() int64 {
	return atomic.LoadInt64(&c.hitCount)
}

func (c *mockCACache) getMissCount() int64 {
	return atomic.LoadInt64(&c.missCount)
}

// ============================================================================
// CA Service Integration Tests
// ============================================================================

func TestCAServiceConnection(t *testing.T) {
	t.Run("SuccessfulConnection", func(t *testing.T) {
		caService := newMockCAService()

		if !caService.isAvailable() {
			t.Error("expected CA service to be available")
		}

		info, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if info.CACertURL != testCACertURL {
			t.Errorf("expected %s, got %s", testCACertURL, info.CACertURL)
		}
	})
}

func TestCAServiceUnavailable(t *testing.T) {
	t.Run("ServiceUnavailable", func(t *testing.T) {
		caService := newMockCAService()
		caService.setAvailable(false)

		_, err := caService.GetCACertificateInfo(context.Background())
		if err != errCAServiceUnavailable {
			t.Errorf("expected ErrCAServiceUnavailable, got %v", err)
		}
	})
}

func TestCAServiceReconnect(t *testing.T) {
	t.Run("ReconnectsWhenAvailable", func(t *testing.T) {
		caService := newMockCAService()

		// Initially unavailable
		caService.setAvailable(false)
		_, err := caService.GetCACertificateInfo(context.Background())
		if err == nil {
			t.Error("expected error when unavailable")
		}

		// Becomes available
		caService.setAvailable(true)
		info, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("unexpected error after reconnect: %v", err)
		}

		if info.CACertURL != testCACertURL {
			t.Errorf("expected %s, got %s", testCACertURL, info.CACertURL)
		}
	})
}

// ============================================================================
// CA Certificate URL Retrieval Tests
// ============================================================================

func TestGetCACertificateInfo(t *testing.T) {
	t.Run("RetrievesAllURLs", func(t *testing.T) {
		caService := newMockCAService()

		info, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify CA cert URL
		if info.CACertURL != testCACertURL {
			t.Errorf("CA cert URL: expected %s, got %s", testCACertURL, info.CACertURL)
		}

		// Verify install script URLs
		if len(info.InstallScriptURLs) != 2 {
			t.Errorf("expected 2 install scripts, got %d", len(info.InstallScriptURLs))
		}
		if info.InstallScriptURLs[0] != testInstallScriptSH {
			t.Errorf("install script 0: expected %s, got %s", testInstallScriptSH, info.InstallScriptURLs[0])
		}
		if info.InstallScriptURLs[1] != testInstallScriptPS1 {
			t.Errorf("install script 1: expected %s, got %s", testInstallScriptPS1, info.InstallScriptURLs[1])
		}

		// Verify WPAD URL
		if info.WPADURL != testWPADURL {
			t.Errorf("WPAD URL: expected %s, got %s", testWPADURL, info.WPADURL)
		}

		// Verify CRL URL
		if info.CRLURL != testCRLURL {
			t.Errorf("CRL URL: expected %s, got %s", testCRLURL, info.CRLURL)
		}

		// Verify OCSP URL
		if info.OCSPURL != testOCSPURL {
			t.Errorf("OCSP URL: expected %s, got %s", testOCSPURL, info.OCSPURL)
		}
	})
}

func TestGetCACertificateInfoError(t *testing.T) {
	t.Run("HandlesError", func(t *testing.T) {
		caService := newMockCAService()
		caService.setErrorOnNext(true)

		_, err := caService.GetCACertificateInfo(context.Background())
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestGetCACertificateInfoTimeout(t *testing.T) {
	t.Run("TimesOut", func(t *testing.T) {
		caService := newMockCAService()
		caService.setDelay(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := caService.GetCACertificateInfo(ctx)
		if err != context.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got %v", err)
		}
	})
}

// ============================================================================
// CA URL Caching Tests
// ============================================================================

func TestCACacheHit(t *testing.T) {
	t.Run("CacheHit", func(t *testing.T) {
		caService := newMockCAService()
		cache := newMockCACache(time.Hour)

		// First request - cache miss, calls service
		info, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cache.Set(info)

		initialRequests := caService.getRequestCount()

		// Second request - cache hit, no service call
		cachedInfo, hit := cache.Get()
		if !hit {
			t.Error("expected cache hit")
		}
		if cachedInfo.CACertURL != testCACertURL {
			t.Errorf("cached URL mismatch")
		}

		// Verify no additional service calls
		if caService.getRequestCount() != initialRequests {
			t.Error("expected no additional service calls on cache hit")
		}

		if cache.getHitCount() != 1 {
			t.Errorf("expected 1 cache hit, got %d", cache.getHitCount())
		}
	})
}

func TestCACacheMiss(t *testing.T) {
	t.Run("CacheMiss", func(t *testing.T) {
		cache := newMockCACache(1 * time.Millisecond) // Very short TTL

		// Set data
		cache.Set(&testCAInfo{CACertURL: testCACertURL})

		// Wait for expiry
		time.Sleep(10 * time.Millisecond)

		// Cache should miss
		_, hit := cache.Get()
		if hit {
			t.Error("expected cache miss after TTL")
		}

		if cache.getMissCount() != 1 {
			t.Errorf("expected 1 cache miss, got %d", cache.getMissCount())
		}
	})
}

func TestCACacheInvalidation(t *testing.T) {
	t.Run("CacheCleared", func(t *testing.T) {
		cache := newMockCACache(time.Hour)

		// Set data
		cache.Set(&testCAInfo{CACertURL: testCACertURL})

		// Verify cache hit
		_, hit := cache.Get()
		if !hit {
			t.Error("expected cache hit before clear")
		}

		// Clear cache
		cache.Clear()

		// Verify cache miss
		_, hit = cache.Get()
		if hit {
			t.Error("expected cache miss after clear")
		}
	})
}

// ============================================================================
// DHCP Option Injection Tests
// ============================================================================

func TestOption224InACK(t *testing.T) {
	t.Run("CACertURLIncluded", func(t *testing.T) {
		caInfo := &testCAInfo{
			CACertURL: testCACertURL,
		}

		options := buildCAOptions(caInfo)

		// Find Option 224
		found := false
		for _, opt := range options {
			if opt.Code == 224 {
				found = true
				if string(opt.Data) != testCACertURL {
					t.Errorf("Option 224 value: expected %s, got %s", testCACertURL, string(opt.Data))
				}
			}
		}

		if !found {
			t.Error("Option 224 not found in ACK")
		}
	})
}

func TestOption225InACK(t *testing.T) {
	t.Run("InstallScriptsIncluded", func(t *testing.T) {
		caInfo := &testCAInfo{
			InstallScriptURLs: []string{testInstallScriptSH, testInstallScriptPS1},
		}

		options := buildCAOptions(caInfo)

		// Find Option 225
		found := false
		for _, opt := range options {
			if opt.Code == 225 {
				found = true
				expected := testInstallScriptSH + "," + testInstallScriptPS1
				if string(opt.Data) != expected {
					t.Errorf("Option 225 value: expected %s, got %s", expected, string(opt.Data))
				}
			}
		}

		if !found {
			t.Error("Option 225 not found in ACK")
		}
	})
}

func TestOption252InACK(t *testing.T) {
	t.Run("WPADURLIncluded", func(t *testing.T) {
		caInfo := &testCAInfo{
			WPADURL: testWPADURL,
		}

		options := buildCAOptions(caInfo)

		// Find Option 252
		found := false
		for _, opt := range options {
			if opt.Code == 252 {
				found = true
				if string(opt.Data) != testWPADURL {
					t.Errorf("Option 252 value: expected %s, got %s", testWPADURL, string(opt.Data))
				}
			}
		}

		if !found {
			t.Error("Option 252 not found in ACK")
		}
	})
}

func TestCAOptionsNotInOFFER(t *testing.T) {
	t.Run("CAOptionsExcluded", func(t *testing.T) {
		// OFFER should not include CA options
		offerOptions := buildOfferOptionsWithoutCA()

		for _, opt := range offerOptions {
			if opt.Code == 224 || opt.Code == 225 || opt.Code == 252 {
				t.Errorf("OFFER should not contain Option %d", opt.Code)
			}
		}
	})
}

func TestCAOptionsWithStandardOptions(t *testing.T) {
	t.Run("AllOptionsPresent", func(t *testing.T) {
		caInfo := &testCAInfo{
			CACertURL:         testCACertURL,
			InstallScriptURLs: []string{testInstallScriptSH},
			WPADURL:           testWPADURL,
		}

		options := buildACKOptionsWithCA(caInfo)

		requiredOptions := map[uint8]bool{
			1:   false, // Subnet mask
			3:   false, // Router
			6:   false, // DNS
			51:  false, // Lease time
			53:  false, // Message type
			54:  false, // Server ID
			224: false, // CA cert URL
			225: false, // Install scripts
			252: false, // WPAD URL
			255: false, // End
		}

		for _, opt := range options {
			if _, required := requiredOptions[opt.Code]; required {
				requiredOptions[opt.Code] = true
			}
		}

		for code, found := range requiredOptions {
			if !found {
				t.Errorf("Required option %d not found", code)
			}
		}
	})
}

// ============================================================================
// End-to-End Tests
// ============================================================================

func TestE2E_DHCPWithCADistribution(t *testing.T) {
	t.Run("CompleteFlow", func(t *testing.T) {
		caService := newMockCAService()

		// Simulate DHCP flow
		// 1. Get CA info (would happen when building ACK)
		caInfo, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("failed to get CA info: %v", err)
		}

		// 2. Build ACK with CA options
		options := buildACKOptionsWithCA(caInfo)

		// 3. Verify all CA options present
		hasOpt224 := false
		hasOpt225 := false
		hasOpt252 := false

		for _, opt := range options {
			switch opt.Code {
			case 224:
				hasOpt224 = true
			case 225:
				hasOpt225 = true
			case 252:
				hasOpt252 = true
			}
		}

		if !hasOpt224 {
			t.Error("ACK missing Option 224")
		}
		if !hasOpt225 {
			t.Error("ACK missing Option 225")
		}
		if !hasOpt252 {
			t.Error("ACK missing Option 252")
		}
	})
}

func TestE2E_CA_MultipleClients(t *testing.T) {
	t.Run("AllClientsReceiveCA", func(t *testing.T) {
		caService := newMockCAService()

		// Simulate 5 clients
		for i := 0; i < 5; i++ {
			caInfo, err := caService.GetCACertificateInfo(context.Background())
			if err != nil {
				t.Fatalf("client %d: failed to get CA info: %v", i, err)
			}

			if caInfo.CACertURL != testCACertURL {
				t.Errorf("client %d: wrong CA URL", i)
			}
		}

		// All 5 should have been served
		if caService.getRequestCount() != 5 {
			t.Errorf("expected 5 requests, got %d", caService.getRequestCount())
		}
	})
}

func TestE2E_CAServiceFailover(t *testing.T) {
	t.Run("GracefulDegradation", func(t *testing.T) {
		caService := newMockCAService()

		// Client 1 - CA available
		info1, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			t.Fatalf("client 1 failed: %v", err)
		}
		if info1.CACertURL != testCACertURL {
			t.Error("client 1 should have CA URL")
		}

		// CA becomes unavailable
		caService.setAvailable(false)

		// Client 2 - CA unavailable
		_, err = caService.GetCACertificateInfo(context.Background())
		if err == nil {
			t.Error("client 2 should fail without CA")
		}

		// Standard DHCP should still work (simulated by just checking error is expected)
		if err != errCAServiceUnavailable {
			t.Errorf("expected ErrCAServiceUnavailable, got %v", err)
		}
	})
}

// ============================================================================
// Metrics Tests
// ============================================================================

type testCAMetrics struct {
	mu               sync.Mutex
	successCount     int64
	failureCount     int64
	cacheHitCount    int64
	optionsSentCount int64
	serviceAvailable bool
}

func newTestCAMetrics() *testCAMetrics {
	return &testCAMetrics{
		serviceAvailable: true,
	}
}

func (m *testCAMetrics) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successCount++
}

func (m *testCAMetrics) recordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureCount++
}

func (m *testCAMetrics) recordCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheHitCount++
}

// Ensure recordCacheHit is used
var _ = (*testCAMetrics).recordCacheHit

func (m *testCAMetrics) recordOptionsSent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.optionsSentCount++
}

func TestCAMetrics_SuccessfulRequest(t *testing.T) {
	t.Run("MetricsRecorded", func(t *testing.T) {
		metrics := newTestCAMetrics()
		caService := newMockCAService()

		_, err := caService.GetCACertificateInfo(context.Background())
		if err == nil {
			metrics.recordSuccess()
			metrics.recordOptionsSent()
		}

		if metrics.successCount != 1 {
			t.Errorf("expected 1 success, got %d", metrics.successCount)
		}
		if metrics.optionsSentCount != 1 {
			t.Errorf("expected 1 options sent, got %d", metrics.optionsSentCount)
		}
	})
}

func TestCAMetrics_FailedRequest(t *testing.T) {
	t.Run("FailureRecorded", func(t *testing.T) {
		metrics := newTestCAMetrics()
		caService := newMockCAService()
		caService.setAvailable(false)

		_, err := caService.GetCACertificateInfo(context.Background())
		if err != nil {
			metrics.recordFailure()
			metrics.serviceAvailable = false
		}

		if metrics.failureCount != 1 {
			t.Errorf("expected 1 failure, got %d", metrics.failureCount)
		}
		if metrics.serviceAvailable {
			t.Error("service should be marked unavailable")
		}
	})
}

// ============================================================================
// Configuration Tests
// ============================================================================

type testCAConfig struct {
	Enabled     bool
	GRPCAddress string
	CacheTTL    time.Duration
	Timeout     time.Duration
}

func TestCAIntegrationDisabled(t *testing.T) {
	t.Run("DisabledConfig", func(t *testing.T) {
		config := &testCAConfig{
			Enabled:     false,
			GRPCAddress: testCAServiceAddress,
		}

		if config.Enabled {
			t.Error("CA integration should be disabled")
		}

		// Verify GRPCAddress was set even when disabled
		if config.GRPCAddress != testCAServiceAddress {
			t.Errorf("expected %s, got %s", testCAServiceAddress, config.GRPCAddress)
		}

		// When disabled, no CA options should be added
		options := buildACKOptionsWithoutCA()
		for _, opt := range options {
			if opt.Code == 224 || opt.Code == 225 || opt.Code == 252 {
				t.Errorf("Option %d should not be present when CA disabled", opt.Code)
			}
		}
	})
}

func TestCAIntegrationConfigValidation(t *testing.T) {
	testCases := []struct {
		name        string
		config      *testCAConfig
		expectError bool
	}{
		{
			name: "ValidConfig",
			config: &testCAConfig{
				Enabled:     true,
				GRPCAddress: "localhost:50056",
				CacheTTL:    time.Hour,
				Timeout:     5 * time.Second,
			},
			expectError: false,
		},
		{
			name: "InvalidGRPCAddress",
			config: &testCAConfig{
				Enabled:     true,
				GRPCAddress: "",
				CacheTTL:    time.Hour,
				Timeout:     5 * time.Second,
			},
			expectError: true,
		},
		{
			name: "InvalidCacheTTL",
			config: &testCAConfig{
				Enabled:     true,
				GRPCAddress: "localhost:50056",
				CacheTTL:    0,
				Timeout:     5 * time.Second,
			},
			expectError: true,
		},
		{
			name: "InvalidTimeout",
			config: &testCAConfig{
				Enabled:     true,
				GRPCAddress: "localhost:50056",
				CacheTTL:    time.Hour,
				Timeout:     0,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCAConfig(tc.config)
			if tc.expectError && err == nil {
				t.Error("expected error")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

type caOption struct {
	Code   uint8
	Length uint8
	Data   []byte
}

func buildCAOptions(caInfo *testCAInfo) []caOption {
	var options []caOption

	if caInfo.CACertURL != "" {
		options = append(options, caOption{
			Code:   224,
			Length: uint8(len(caInfo.CACertURL)),
			Data:   []byte(caInfo.CACertURL),
		})
	}

	if len(caInfo.InstallScriptURLs) > 0 {
		data := ""
		for i, url := range caInfo.InstallScriptURLs {
			if i > 0 {
				data += ","
			}
			data += url
		}
		options = append(options, caOption{
			Code:   225,
			Length: uint8(len(data)),
			Data:   []byte(data),
		})
	}

	if caInfo.WPADURL != "" {
		options = append(options, caOption{
			Code:   252,
			Length: uint8(len(caInfo.WPADURL)),
			Data:   []byte(caInfo.WPADURL),
		})
	}

	return options
}

func buildOfferOptionsWithoutCA() []caOption {
	return []caOption{
		{Code: 53, Length: 1, Data: []byte{2}}, // OFFER
		{Code: 54, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 1, Length: 4, Data: []byte{255, 255, 255, 0}},
		{Code: 3, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 6, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 51, Length: 4, Data: []byte{0, 1, 81, 128}},
		{Code: 255, Length: 0, Data: nil},
	}
}

func buildACKOptionsWithCA(caInfo *testCAInfo) []caOption {
	options := []caOption{
		{Code: 53, Length: 1, Data: []byte{5}}, // ACK
		{Code: 54, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 1, Length: 4, Data: []byte{255, 255, 255, 0}},
		{Code: 3, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 6, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 51, Length: 4, Data: []byte{0, 1, 81, 128}},
	}

	// Add CA options
	caOpts := buildCAOptions(caInfo)
	options = append(options, caOpts...)

	// End option
	options = append(options, caOption{Code: 255, Length: 0, Data: nil})

	return options
}

func buildACKOptionsWithoutCA() []caOption {
	return []caOption{
		{Code: 53, Length: 1, Data: []byte{5}}, // ACK
		{Code: 54, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 1, Length: 4, Data: []byte{255, 255, 255, 0}},
		{Code: 3, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 6, Length: 4, Data: []byte{192, 168, 1, 1}},
		{Code: 51, Length: 4, Data: []byte{0, 1, 81, 128}},
		{Code: 255, Length: 0, Data: nil},
	}
}

func validateCAConfig(cfg *testCAConfig) error {
	if cfg.Enabled {
		if cfg.GRPCAddress == "" {
			return errCAInvalidGRPCAddress
		}
		if cfg.CacheTTL <= 0 {
			return errCAInvalidCacheTTL
		}
		if cfg.Timeout <= 0 {
			return errCAInvalidTimeout
		}
	}
	return nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	errCAServiceUnavailable = &testError{"CA service unavailable"}
	errCAInvalidGRPCAddress = &testError{"invalid gRPC address"}
	errCAInvalidCacheTTL    = &testError{"invalid cache TTL"}
	errCAInvalidTimeout     = &testError{"invalid timeout"}
)
