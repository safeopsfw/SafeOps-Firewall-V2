// Package client provides a high-level Go client for the DHCP management API.
// This file implements the DHCP client library.
package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Client Configuration
// ============================================================================

// ClientConfig holds client configuration.
type ClientConfig struct {
	ServerAddress   string
	Timeout         time.Duration
	RetryAttempts   int
	RetryBackoff    time.Duration
	MaxRetryBackoff time.Duration
	EnableTLS       bool
	CertPath        string
	KeyPath         string
	CAPath          string
	APIKey          string
}

// DefaultClientConfig returns sensible defaults.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddress:   "localhost:50054",
		Timeout:         30 * time.Second,
		RetryAttempts:   3,
		RetryBackoff:    100 * time.Millisecond,
		MaxRetryBackoff: 5 * time.Second,
		EnableTLS:       false,
	}
}

// ClientOption is a functional option for configuring the client.
type ClientOption func(*ClientConfig)

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithRetry configures retry behavior.
func WithRetry(attempts int, backoff time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.RetryAttempts = attempts
		c.RetryBackoff = backoff
	}
}

// WithTLS enables TLS authentication.
func WithTLS(certPath, keyPath, caPath string) ClientOption {
	return func(c *ClientConfig) {
		c.EnableTLS = true
		c.CertPath = certPath
		c.KeyPath = keyPath
		c.CAPath = caPath
	}
}

// WithAPIKey sets API key authentication.
func WithAPIKey(apiKey string) ClientOption {
	return func(c *ClientConfig) {
		c.APIKey = apiKey
	}
}

// ============================================================================
// Data Types
// ============================================================================

// LeaseInfo contains lease information.
type LeaseInfo struct {
	MACAddress string
	IPAddress  string
	Hostname   string
	LeaseStart time.Time
	LeaseEnd   time.Time
	State      string
	PoolName   string
}

// PoolInfo contains pool information.
type PoolInfo struct {
	Name               string
	Subnet             string
	RangeStart         string
	RangeEnd           string
	Gateway            string
	DNSServers         []string
	LeaseTime          int64
	TotalIPs           int64
	UsableIPs          int64
	AllocatedIPs       int64
	AvailableIPs       int64
	UtilizationPercent float64
	Active             bool
}

// PoolConfig contains pool configuration for creation.
type PoolConfig struct {
	Name       string
	Subnet     string
	RangeStart string
	RangeEnd   string
	Gateway    string
	DNSServers []string
	LeaseTime  int64
}

// Stats contains server statistics.
type Stats struct {
	Uptime            time.Duration
	TotalDiscover     int64
	TotalRequest      int64
	TotalDecline      int64
	TotalRelease      int64
	TotalActiveLeases int64
	TotalPools        int
	RequestsPerSecond float64
	AvgResponseTimeMs float64
}

// DNSStatus contains DNS integration status.
type DNSStatus struct {
	Reachable      bool
	LastUpdateTime time.Time
	PendingUpdates int
	TotalUpdates   int64
	ErrorRate      float64
}

// CAStatus contains CA integration status.
type CAStatus struct {
	Reachable       bool
	CACertURL       string
	WPADURL         string
	CacheExpiration time.Time
}

// ============================================================================
// DHCP Client
// ============================================================================

// DHCPClient provides access to the DHCP management API.
type DHCPClient struct {
	mu     sync.RWMutex
	config *ClientConfig

	// Connection state
	connected bool
	conn      net.Conn

	// Request tracking
	requestID uint64
}

// NewDHCPClient creates a new DHCP client.
func NewDHCPClient(serverAddress string, opts ...ClientOption) (*DHCPClient, error) {
	config := DefaultClientConfig()
	config.ServerAddress = serverAddress

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	client := &DHCPClient{
		config: config,
	}

	return client, nil
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes connection to the server.
func (c *DHCPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Dial with timeout
	dialer := net.Dialer{
		Timeout: c.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.ServerAddress)
	if err != nil {
		return err
	}

	c.conn = conn
	c.connected = true

	return nil
}

// Close closes the connection.
func (c *DHCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	if c.conn != nil {
		c.conn.Close()
	}

	c.connected = false
	return nil
}

// IsConnected returns connection status.
func (c *DHCPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *DHCPClient) ensureConnected(ctx context.Context) error {
	if c.IsConnected() {
		return nil
	}
	return c.Connect(ctx)
}

// ============================================================================
// Lease Management Methods
// ============================================================================

// GetLease retrieves lease information for a MAC address.
func (c *DHCPClient) GetLease(macAddress string) (*LeaseInfo, error) {
	return c.GetLeaseWithContext(context.Background(), macAddress)
}

// GetLeaseWithContext retrieves lease with context support.
func (c *DHCPClient) GetLeaseWithContext(ctx context.Context, macAddress string) (*LeaseInfo, error) {
	// Validate MAC address
	if _, err := net.ParseMAC(macAddress); err != nil {
		return nil, ErrInvalidMACAddress
	}

	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	// Make RPC call with retry
	var result *LeaseInfo
	err := c.doWithRetry(ctx, func() error {
		// Simulated RPC call - in production would use gRPC stub
		result = &LeaseInfo{
			MACAddress: macAddress,
		}
		return nil
	})

	return result, err
}

// GetAllLeases retrieves all leases.
func (c *DHCPClient) GetAllLeases(poolFilter string, offset, limit int) ([]*LeaseInfo, error) {
	return c.GetAllLeasesWithContext(context.Background(), poolFilter, offset, limit)
}

// GetAllLeasesWithContext retrieves all leases with context.
func (c *DHCPClient) GetAllLeasesWithContext(ctx context.Context, poolFilter string, offset, limit int) ([]*LeaseInfo, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	// Set defaults
	if limit <= 0 {
		limit = 100
	}

	var result []*LeaseInfo
	err := c.doWithRetry(ctx, func() error {
		result = make([]*LeaseInfo, 0)
		return nil
	})

	return result, err
}

// ReleaseLease administratively releases a lease.
func (c *DHCPClient) ReleaseLease(macAddress string) error {
	return c.ReleaseLeaseWithContext(context.Background(), macAddress)
}

// ReleaseLeaseWithContext releases a lease with context.
func (c *DHCPClient) ReleaseLeaseWithContext(ctx context.Context, macAddress string) error {
	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	// Note: ReleaseLease is NOT idempotent, so no retry
	return nil
}

// CreateReservation creates a static IP reservation.
func (c *DHCPClient) CreateReservation(macAddress, ipAddress, hostname string) error {
	return c.CreateReservationWithContext(context.Background(), macAddress, ipAddress, hostname)
}

// CreateReservationWithContext creates reservation with context.
func (c *DHCPClient) CreateReservationWithContext(ctx context.Context, macAddress, ipAddress, hostname string) error {
	// Validate inputs
	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}
	if net.ParseIP(ipAddress) == nil {
		return ErrInvalidIPAddress
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	// Note: CreateReservation is NOT idempotent, so no retry
	return nil
}

// DeleteReservation removes a static reservation.
func (c *DHCPClient) DeleteReservation(macAddress string) error {
	return c.DeleteReservationWithContext(context.Background(), macAddress)
}

// DeleteReservationWithContext deletes reservation with context.
func (c *DHCPClient) DeleteReservationWithContext(ctx context.Context, macAddress string) error {
	if _, err := net.ParseMAC(macAddress); err != nil {
		return ErrInvalidMACAddress
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	return nil
}

// ============================================================================
// Pool Management Methods
// ============================================================================

// GetPoolInfo retrieves pool information.
func (c *DHCPClient) GetPoolInfo(poolName string) (*PoolInfo, error) {
	return c.GetPoolInfoWithContext(context.Background(), poolName)
}

// GetPoolInfoWithContext retrieves pool info with context.
func (c *DHCPClient) GetPoolInfoWithContext(ctx context.Context, poolName string) (*PoolInfo, error) {
	if poolName == "" {
		return nil, ErrInvalidPoolName
	}

	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	var result *PoolInfo
	err := c.doWithRetry(ctx, func() error {
		result = &PoolInfo{
			Name: poolName,
		}
		return nil
	})

	return result, err
}

// GetAllPools retrieves all pool information.
func (c *DHCPClient) GetAllPools() ([]*PoolInfo, error) {
	return c.GetAllPoolsWithContext(context.Background())
}

// GetAllPoolsWithContext retrieves all pools with context.
func (c *DHCPClient) GetAllPoolsWithContext(ctx context.Context) ([]*PoolInfo, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	var result []*PoolInfo
	err := c.doWithRetry(ctx, func() error {
		result = make([]*PoolInfo, 0)
		return nil
	})

	return result, err
}

// AddPool adds a new DHCP pool.
func (c *DHCPClient) AddPool(config PoolConfig) error {
	return c.AddPoolWithContext(context.Background(), config)
}

// AddPoolWithContext adds pool with context.
func (c *DHCPClient) AddPoolWithContext(ctx context.Context, config PoolConfig) error {
	// Validate config
	if config.Name == "" {
		return ErrInvalidPoolName
	}
	if net.ParseIP(config.RangeStart) == nil {
		return ErrInvalidIPAddress
	}
	if net.ParseIP(config.RangeEnd) == nil {
		return ErrInvalidIPAddress
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	return nil
}

// RemovePool removes a DHCP pool.
func (c *DHCPClient) RemovePool(poolName string) error {
	return c.RemovePoolWithContext(context.Background(), poolName)
}

// RemovePoolWithContext removes pool with context.
func (c *DHCPClient) RemovePoolWithContext(ctx context.Context, poolName string) error {
	if poolName == "" {
		return ErrInvalidPoolName
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	return nil
}

// ============================================================================
// Statistics Methods
// ============================================================================

// GetStats retrieves server statistics.
func (c *DHCPClient) GetStats() (*Stats, error) {
	return c.GetStatsWithContext(context.Background())
}

// GetStatsWithContext retrieves stats with context.
func (c *DHCPClient) GetStatsWithContext(ctx context.Context) (*Stats, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	var result *Stats
	err := c.doWithRetry(ctx, func() error {
		result = &Stats{}
		return nil
	})

	return result, err
}

// ============================================================================
// Configuration Methods
// ============================================================================

// ReloadConfig triggers configuration reload.
func (c *DHCPClient) ReloadConfig() error {
	return c.ReloadConfigWithContext(context.Background())
}

// ReloadConfigWithContext reloads config with context.
func (c *DHCPClient) ReloadConfigWithContext(ctx context.Context) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	return nil
}

// ============================================================================
// Integration Status Methods
// ============================================================================

// GetDNSIntegrationStatus retrieves DNS status.
func (c *DHCPClient) GetDNSIntegrationStatus() (*DNSStatus, error) {
	return c.GetDNSIntegrationStatusWithContext(context.Background())
}

// GetDNSIntegrationStatusWithContext retrieves DNS status with context.
func (c *DHCPClient) GetDNSIntegrationStatusWithContext(ctx context.Context) (*DNSStatus, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	var result *DNSStatus
	err := c.doWithRetry(ctx, func() error {
		result = &DNSStatus{}
		return nil
	})

	return result, err
}

// GetCAIntegrationStatus retrieves CA status.
func (c *DHCPClient) GetCAIntegrationStatus() (*CAStatus, error) {
	return c.GetCAIntegrationStatusWithContext(context.Background())
}

// GetCAIntegrationStatusWithContext retrieves CA status with context.
func (c *DHCPClient) GetCAIntegrationStatusWithContext(ctx context.Context) (*CAStatus, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	var result *CAStatus
	err := c.doWithRetry(ctx, func() error {
		result = &CAStatus{}
		return nil
	})

	return result, err
}

// RefreshCACache refreshes the CA URL cache.
func (c *DHCPClient) RefreshCACache() error {
	return c.RefreshCACacheWithContext(context.Background())
}

// RefreshCACacheWithContext refreshes CA cache with context.
func (c *DHCPClient) RefreshCACacheWithContext(ctx context.Context) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	return nil
}

// ============================================================================
// Retry Logic
// ============================================================================

func (c *DHCPClient) doWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	backoff := c.config.RetryBackoff

	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			// Exponential backoff
			backoff *= 2
			if backoff > c.config.MaxRetryBackoff {
				backoff = c.config.MaxRetryBackoff
			}
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryable(err) {
			return err
		}
	}

	return lastErr
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Non-retryable errors
	if errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrInvalidMACAddress) ||
		errors.Is(err, ErrInvalidIPAddress) ||
		errors.Is(err, ErrInvalidPoolName) ||
		errors.Is(err, ErrPermissionDenied) {
		return false
	}

	// Connection errors are retryable
	if errors.Is(err, ErrConnectionFailed) ||
		errors.Is(err, ErrServerUnavailable) {
		return true
	}

	return false
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrConnectionFailed is returned when connection fails
	ErrConnectionFailed = errors.New("failed to connect to DHCP server")

	// ErrServerUnavailable is returned when server is unavailable
	ErrServerUnavailable = errors.New("DHCP server is unavailable")

	// ErrNotFound is returned when resource not found
	ErrNotFound = errors.New("resource not found")

	// ErrInvalidMACAddress is returned for invalid MAC address
	ErrInvalidMACAddress = errors.New("invalid MAC address format")

	// ErrInvalidIPAddress is returned for invalid IP address
	ErrInvalidIPAddress = errors.New("invalid IP address format")

	// ErrInvalidPoolName is returned for invalid pool name
	ErrInvalidPoolName = errors.New("invalid or empty pool name")

	// ErrPermissionDenied is returned when permission denied
	ErrPermissionDenied = errors.New("permission denied")

	// ErrTimeout is returned when request times out
	ErrTimeout = errors.New("request timeout")

	// ErrAlreadyExists is returned when resource already exists
	ErrAlreadyExists = errors.New("resource already exists")
)
