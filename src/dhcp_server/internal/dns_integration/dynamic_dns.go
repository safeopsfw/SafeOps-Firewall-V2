// Package dns_integration provides DNS integration for DHCP server.
// This file implements the dynamic DNS manager orchestrating all DNS operations.
package dns_integration

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Dynamic DNS Manager Configuration
// ============================================================================

// DynamicDNSConfig holds DNS manager settings.
type DynamicDNSConfig struct {
	Enabled       bool
	UpdateMode    string // "sync" or "async"
	UpdateTimeout time.Duration
	QueueSize     int
	Workers       int
	RetryEnabled  bool
	MaxRetries    int
	RetryInterval time.Duration
	CreatePTR     bool
	DefaultDomain string
}

// DefaultDynamicDNSConfig returns sensible defaults.
func DefaultDynamicDNSConfig() *DynamicDNSConfig {
	return &DynamicDNSConfig{
		Enabled:       true,
		UpdateMode:    "async",
		UpdateTimeout: 3 * time.Second,
		QueueSize:     1000,
		Workers:       5,
		RetryEnabled:  true,
		MaxRetries:    3,
		RetryInterval: time.Second,
		CreatePTR:     true,
		DefaultDomain: "local",
	}
}

// ============================================================================
// Lease Info for DNS
// ============================================================================

// DNSLeaseInfo contains lease information for DNS operations.
type DNSLeaseInfo struct {
	IP           net.IP
	MAC          net.HardwareAddr
	Hostname     string
	Domain       string
	ExpiresAt    time.Time
	PoolName     string
	PrevHostname string // For hostname change detection
}

// ============================================================================
// Dynamic DNS Manager Interface
// ============================================================================

// DynamicDNSManager defines the public API for DNS integration.
type DynamicDNSManager interface {
	UpdateDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error
	RemoveDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error
	RefreshDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error
	IsEnabled() bool
	IsHealthy() bool
	GetStats() DynamicDNSStats
	Close() error
}

// ============================================================================
// Dynamic DNS Manager Implementation
// ============================================================================

// DynamicDNS implements DynamicDNSManager.
type DynamicDNS struct {
	mu     sync.RWMutex
	config *DynamicDNSConfig

	// Components
	dnsClient      DNSClient
	hostnameMapper *HostnameMapper
	syncer         *DNSSyncer

	// Update queue
	updateQueue chan *dnsUpdateRequest
	stopChan    chan struct{}
	wg          sync.WaitGroup
	running     atomic.Bool

	// Statistics
	stats DynamicDNSStats
}

// DynamicDNSStats tracks DNS operation metrics.
type DynamicDNSStats struct {
	TotalUpdates      int64
	SuccessfulUpdates int64
	FailedUpdates     int64
	TotalDeletes      int64
	SuccessfulDeletes int64
	FailedDeletes     int64
	TotalRefreshes    int64
	QueuedOperations  int64
	QueueOverflows    int64
	HostnameChanges   int64
	RetryAttempts     int64
}

type dnsUpdateRequest struct {
	operation string // "update", "delete", "refresh"
	lease     *DNSLeaseInfo
	resultCh  chan error
}

// ============================================================================
// Manager Creation
// ============================================================================

// NewDynamicDNS creates a new dynamic DNS manager.
func NewDynamicDNS(config *DynamicDNSConfig) *DynamicDNS {
	if config == nil {
		config = DefaultDynamicDNSConfig()
	}

	return &DynamicDNS{
		config:      config,
		updateQueue: make(chan *dnsUpdateRequest, config.QueueSize),
		stopChan:    make(chan struct{}),
	}
}

// ============================================================================
// Component Setters
// ============================================================================

// SetDNSClient sets the DNS gRPC client.
func (d *DynamicDNS) SetDNSClient(client DNSClient) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dnsClient = client
}

// SetHostnameMapper sets the hostname mapper.
func (d *DynamicDNS) SetHostnameMapper(mapper *HostnameMapper) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hostnameMapper = mapper
}

// SetSyncer sets the DNS syncer.
func (d *DynamicDNS) SetSyncer(syncer *DNSSyncer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.syncer = syncer
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the dynamic DNS manager.
func (d *DynamicDNS) Start() error {
	if !d.config.Enabled {
		return nil
	}

	if d.running.Load() {
		return ErrDNSManagerRunning
	}

	d.running.Store(true)
	d.stopChan = make(chan struct{})

	// Start workers for async mode
	if d.config.UpdateMode == "async" {
		for i := 0; i < d.config.Workers; i++ {
			d.wg.Add(1)
			go d.worker(i)
		}
	}

	return nil
}

// Close stops the dynamic DNS manager.
func (d *DynamicDNS) Close() error {
	if !d.running.Load() {
		return nil
	}

	close(d.stopChan)
	d.wg.Wait()
	d.running.Store(false)

	return nil
}

// ============================================================================
// Public API: Update DNS for Lease
// ============================================================================

// UpdateDNSForLease creates or updates DNS records for a lease.
func (d *DynamicDNS) UpdateDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	if !d.config.Enabled {
		return nil
	}

	if lease == nil {
		return ErrNilLease
	}

	d.stats.TotalUpdates++

	// Check for hostname change
	if lease.PrevHostname != "" && lease.PrevHostname != lease.Hostname {
		d.stats.HostnameChanges++
		// Remove old hostname first
		oldLease := &DNSLeaseInfo{
			IP:       lease.IP,
			MAC:      lease.MAC,
			Hostname: lease.PrevHostname,
			Domain:   lease.Domain,
		}
		_ = d.executeDelete(ctx, oldLease)
	}

	// Execute update
	if d.config.UpdateMode == "sync" {
		return d.executeUpdate(ctx, lease)
	}

	// Async mode
	return d.queueOperation("update", lease)
}

// ============================================================================
// Public API: Remove DNS for Lease
// ============================================================================

// RemoveDNSForLease deletes DNS records for a lease.
func (d *DynamicDNS) RemoveDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	if !d.config.Enabled {
		return nil
	}

	if lease == nil {
		return ErrNilLease
	}

	d.stats.TotalDeletes++

	if d.config.UpdateMode == "sync" {
		return d.executeDelete(ctx, lease)
	}

	return d.queueOperation("delete", lease)
}

// ============================================================================
// Public API: Refresh DNS for Lease
// ============================================================================

// RefreshDNSForLease updates TTL for existing DNS records.
func (d *DynamicDNS) RefreshDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	if !d.config.Enabled {
		return nil
	}

	if lease == nil {
		return ErrNilLease
	}

	d.stats.TotalRefreshes++

	// Refresh is essentially an update with new TTL
	if d.config.UpdateMode == "sync" {
		return d.executeUpdate(ctx, lease)
	}

	return d.queueOperation("refresh", lease)
}

// ============================================================================
// Execute Operations
// ============================================================================

func (d *DynamicDNS) executeUpdate(ctx context.Context, lease *DNSLeaseInfo) error {
	d.mu.RLock()
	client := d.dnsClient
	mapper := d.hostnameMapper
	d.mu.RUnlock()

	if client == nil {
		return ErrNoDNSClient
	}

	// Extract/normalize hostname
	hostname := lease.Hostname
	domain := lease.Domain
	if domain == "" {
		domain = d.config.DefaultDomain
	}

	if hostname == "" && mapper != nil {
		options := make(map[byte][]byte) // Empty options for fallback generation
		result, err := mapper.ExtractHostname(ctx, options, lease.MAC, domain)
		if err == nil && result != nil {
			hostname = result.Hostname
		}
	}

	if hostname == "" {
		// Generate fallback
		hostname = d.generateFallbackHostname(lease.MAC)
	}

	// Calculate TTL
	ttl := time.Until(lease.ExpiresAt)
	if ttl < time.Minute {
		ttl = time.Hour // Default TTL if expiration passed
	}

	// Build and execute update
	req := &DNSUpdateRequest{
		Hostname:    hostname,
		IP:          lease.IP,
		MAC:         lease.MAC,
		TTL:         ttl,
		Domain:      domain,
		CreatePTR:   d.config.CreatePTR,
		Synchronous: true,
	}

	updateCtx, cancel := context.WithTimeout(ctx, d.config.UpdateTimeout)
	defer cancel()

	err := client.DynamicUpdate(updateCtx, req)
	if err != nil {
		d.stats.FailedUpdates++

		// Retry if enabled
		if d.config.RetryEnabled {
			err = d.retryUpdate(ctx, req)
		}

		if err != nil {
			return err
		}
	}

	d.stats.SuccessfulUpdates++
	return nil
}

func (d *DynamicDNS) executeDelete(ctx context.Context, lease *DNSLeaseInfo) error {
	d.mu.RLock()
	client := d.dnsClient
	d.mu.RUnlock()

	if client == nil {
		return ErrNoDNSClient
	}

	hostname := lease.Hostname
	if hostname == "" {
		// Can't delete without hostname
		return nil
	}

	req := &DNSDeleteRequest{
		Hostname:  hostname,
		IP:        lease.IP,
		DeletePTR: d.config.CreatePTR,
	}

	deleteCtx, cancel := context.WithTimeout(ctx, d.config.UpdateTimeout)
	defer cancel()

	err := client.DeleteRecord(deleteCtx, req)
	if err != nil {
		d.stats.FailedDeletes++
		return err
	}

	d.stats.SuccessfulDeletes++
	return nil
}

func (d *DynamicDNS) retryUpdate(ctx context.Context, req *DNSUpdateRequest) error {
	d.mu.RLock()
	client := d.dnsClient
	d.mu.RUnlock()

	if client == nil {
		return ErrNoDNSClient
	}

	var lastErr error
	for i := 0; i < d.config.MaxRetries; i++ {
		d.stats.RetryAttempts++

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.config.RetryInterval):
		}

		retryCtx, cancel := context.WithTimeout(ctx, d.config.UpdateTimeout)
		err := client.DynamicUpdate(retryCtx, req)
		cancel()

		if err == nil {
			return nil
		}
		lastErr = err
	}

	return lastErr
}

// ============================================================================
// Queue Operations
// ============================================================================

func (d *DynamicDNS) queueOperation(operation string, lease *DNSLeaseInfo) error {
	req := &dnsUpdateRequest{
		operation: operation,
		lease:     lease,
	}

	select {
	case d.updateQueue <- req:
		d.stats.QueuedOperations++
		return nil
	default:
		d.stats.QueueOverflows++
		return ErrQueueFull
	}
}

func (d *DynamicDNS) worker(id int) {
	defer d.wg.Done()

	_ = id // Worker ID for logging

	for {
		select {
		case <-d.stopChan:
			return
		case req := <-d.updateQueue:
			if req == nil {
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), d.config.UpdateTimeout*2)

			var err error
			switch req.operation {
			case "update", "refresh":
				err = d.executeUpdate(ctx, req.lease)
			case "delete":
				err = d.executeDelete(ctx, req.lease)
			}

			cancel()

			if req.resultCh != nil {
				req.resultCh <- err
			}
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func (d *DynamicDNS) generateFallbackHostname(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return "dhcp-unknown"
	}

	macStr := mac.String()
	macStr = strings.ReplaceAll(macStr, ":", "")
	macStr = strings.ReplaceAll(macStr, "-", "")
	macStr = strings.ToLower(macStr)

	return "dhcp-" + macStr
}

// ============================================================================
// Status Methods
// ============================================================================

// IsEnabled returns whether DNS updates are enabled.
func (d *DynamicDNS) IsEnabled() bool {
	return d.config.Enabled
}

// IsHealthy returns DNS integration health status.
func (d *DynamicDNS) IsHealthy() bool {
	d.mu.RLock()
	client := d.dnsClient
	d.mu.RUnlock()

	if client == nil {
		return false
	}

	return client.IsHealthy()
}

// GetStats returns DNS operation statistics.
func (d *DynamicDNS) GetStats() DynamicDNSStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stats
}

// GetQueueDepth returns current queue depth.
func (d *DynamicDNS) GetQueueDepth() int {
	return len(d.updateQueue)
}

// GetSuccessRate returns the update success rate.
func (d *DynamicDNS) GetSuccessRate() float64 {
	total := d.stats.TotalUpdates
	if total == 0 {
		return 100.0
	}
	return float64(d.stats.SuccessfulUpdates) / float64(total) * 100
}

// ============================================================================
// Mock DNS Manager for Testing
// ============================================================================

// MockDynamicDNS is a mock implementation for testing.
type MockDynamicDNS struct {
	mu         sync.RWMutex
	enabled    bool
	healthy    bool
	updateErr  error
	deleteErr  error
	refreshErr error
	updates    []*DNSLeaseInfo
	deletes    []*DNSLeaseInfo
	refreshes  []*DNSLeaseInfo
}

// NewMockDynamicDNS creates a mock DNS manager.
func NewMockDynamicDNS() *MockDynamicDNS {
	return &MockDynamicDNS{
		enabled:   true,
		healthy:   true,
		updates:   make([]*DNSLeaseInfo, 0),
		deletes:   make([]*DNSLeaseInfo, 0),
		refreshes: make([]*DNSLeaseInfo, 0),
	}
}

// SetEnabled sets enabled status.
func (m *MockDynamicDNS) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// SetHealthy sets health status.
func (m *MockDynamicDNS) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

// SetUpdateError sets error for updates.
func (m *MockDynamicDNS) SetUpdateError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateErr = err
}

// SetDeleteError sets error for deletes.
func (m *MockDynamicDNS) SetDeleteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteErr = err
}

// UpdateDNSForLease records the update.
func (m *MockDynamicDNS) UpdateDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, lease)
	return m.updateErr
}

// RemoveDNSForLease records the delete.
func (m *MockDynamicDNS) RemoveDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, lease)
	return m.deleteErr
}

// RefreshDNSForLease records the refresh.
func (m *MockDynamicDNS) RefreshDNSForLease(ctx context.Context, lease *DNSLeaseInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshes = append(m.refreshes, lease)
	return m.refreshErr
}

// IsEnabled returns enabled status.
func (m *MockDynamicDNS) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// IsHealthy returns health status.
func (m *MockDynamicDNS) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

// GetStats returns empty stats.
func (m *MockDynamicDNS) GetStats() DynamicDNSStats {
	return DynamicDNSStats{}
}

// Close is a no-op.
func (m *MockDynamicDNS) Close() error {
	return nil
}

// GetUpdates returns recorded updates.
func (m *MockDynamicDNS) GetUpdates() []*DNSLeaseInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.updates
}

// GetDeletes returns recorded deletes.
func (m *MockDynamicDNS) GetDeletes() []*DNSLeaseInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deletes
}

// Reset clears recorded operations.
func (m *MockDynamicDNS) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = make([]*DNSLeaseInfo, 0)
	m.deletes = make([]*DNSLeaseInfo, 0)
	m.refreshes = make([]*DNSLeaseInfo, 0)
	m.updateErr = nil
	m.deleteErr = nil
	m.refreshErr = nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrDNSManagerRunning is returned when manager already running
	ErrDNSManagerRunning = errors.New("DNS manager already running")

	// ErrNilLease is returned when lease is nil
	ErrNilLease = errors.New("lease is nil")

	// ErrDNSUpdateFailed is returned when DNS update fails
	ErrDNSUpdateFailed = errors.New("DNS update failed")

	// ErrDNSDeleteFailed is returned when DNS delete fails
	ErrDNSDeleteFailed = errors.New("DNS delete failed")
)
