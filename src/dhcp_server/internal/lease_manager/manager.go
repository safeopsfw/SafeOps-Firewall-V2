// Package lease_manager handles DHCP lease lifecycle operations.
// This file implements the central lease lifecycle coordinator.
package lease_manager

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Manager Configuration
// ============================================================================

// ManagerConfig holds lease manager settings.
type ManagerConfig struct {
	AllocationTimeout time.Duration
	RenewalTimeout    time.Duration
	ReleaseTimeout    time.Duration
	ShutdownTimeout   time.Duration
	EnableDNS         bool
	EnableConflict    bool
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		AllocationTimeout: 10 * time.Second,
		RenewalTimeout:    5 * time.Second,
		ReleaseTimeout:    5 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		EnableDNS:         true,
		EnableConflict:    true,
	}
}

// ============================================================================
// Lease State Constants
// ============================================================================

// LeaseState represents the state of a lease.
type LeaseState string

const (
	LeaseStateOffered  LeaseState = "OFFERED"
	LeaseStateActive   LeaseState = "ACTIVE"
	LeaseStateReleased LeaseState = "RELEASED"
	LeaseStateExpired  LeaseState = "EXPIRED"
	LeaseStateDeclined LeaseState = "DECLINED"
)

// ============================================================================
// Lease Structure
// ============================================================================

// Lease represents a DHCP lease.
type Lease struct {
	ID            int64
	MAC           net.HardwareAddr
	IP            net.IP
	Hostname      string
	PoolName      string
	State         LeaseState
	LeaseStart    time.Time
	LeaseEnd      time.Time
	LeaseDuration time.Duration
	ConfirmedAt   *time.Time
	ReleasedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ============================================================================
// Manager Dependencies Interface
// ============================================================================

// LeaseRepository defines database operations.
type LeaseRepository interface {
	CreateLease(ctx context.Context, lease *Lease) error
	GetLeaseByMAC(ctx context.Context, mac net.HardwareAddr) (*Lease, error)
	GetLeaseByIP(ctx context.Context, ip net.IP) (*Lease, error)
	UpdateLease(ctx context.Context, lease *Lease) error
	DeleteLease(ctx context.Context, id int64) error
	GetActiveLeases(ctx context.Context) ([]*Lease, error)
	GetExpiredLeases(ctx context.Context, limit int) ([]*ExpiredLease, error)
	GetLeaseCountByPool(ctx context.Context, poolName string) (int, error)
}

// DNSClient defines DNS operations.
type DNSClient interface {
	CreateARecord(ctx context.Context, hostname string, ip net.IP) error
	CreatePTRRecord(ctx context.Context, ip net.IP, hostname string) error
	RemoveARecord(ctx context.Context, hostname string, ip net.IP) error
	RemovePTRRecord(ctx context.Context, ip net.IP) error
	Flush(ctx context.Context) error
}

// ============================================================================
// Lease Manager
// ============================================================================

// LeaseManager coordinates all lease lifecycle operations.
type LeaseManager struct {
	mu     sync.RWMutex
	config *ManagerConfig

	// Sub-handlers
	allocator        *Allocator
	renewalManager   *RenewalManager
	releaseHandler   *ReleaseHandler
	expiryHandler    *ExpiryHandler
	conflictDetector *ConflictDetector

	// Dependencies
	leaseRepo   LeaseRepository
	poolManager PoolManagerInterface
	dnsClient   DNSClient

	// State
	initialized bool
	startTime   time.Time

	// Statistics
	stats ManagerStats
}

// ManagerStats tracks overall manager statistics.
type ManagerStats struct {
	TotalAllocations   int64
	TotalConfirmations int64
	TotalRenewals      int64
	TotalReleases      int64
	TotalExpirations   int64
	ConflictsDetected  int64
	DNSUpdateFailures  int64
	Errors             int64
}

// ============================================================================
// Manager Creation
// ============================================================================

// NewLeaseManager creates a new lease manager.
func NewLeaseManager(config *ManagerConfig) *LeaseManager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	m := &LeaseManager{
		config:    config,
		startTime: time.Now(),
	}

	// Initialize sub-handlers
	m.allocator = NewAllocator(nil, nil, nil)
	m.renewalManager = NewRenewalManager(nil)
	m.releaseHandler = NewReleaseHandler(nil)
	m.expiryHandler = NewExpiryHandler(nil)
	m.conflictDetector = NewConflictDetector(nil)

	return m
}

// ============================================================================
// Dependency Injection
// ============================================================================

// SetLeaseRepository sets the lease repository.
func (m *LeaseManager) SetLeaseRepository(repo LeaseRepository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaseRepo = repo

	// Wire up expiry handler
	m.expiryHandler.SetGetExpiredFunc(func(ctx context.Context, limit int) ([]*ExpiredLease, error) {
		return repo.GetExpiredLeases(ctx, limit)
	})
	m.expiryHandler.SetDeleteLeaseFunc(func(ctx context.Context, id int64) error {
		return repo.DeleteLease(ctx, id)
	})
}

// SetPoolManager sets the pool manager.
func (m *LeaseManager) SetPoolManager(pm PoolManagerInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.poolManager = pm

	// Recreate allocator with pool manager
	m.allocator = NewAllocator(pm, m.conflictDetector, nil)
}

// SetDNSClient sets the DNS client.
func (m *LeaseManager) SetDNSClient(dns DNSClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsClient = dns

	// Wire up DNS cleanup for handlers
	dnsCleanup := func(ctx context.Context, hostname string, ip net.IP) error {
		if err := dns.RemoveARecord(ctx, hostname, ip); err != nil {
			return err
		}
		return dns.RemovePTRRecord(ctx, ip)
	}

	m.releaseHandler.SetDNSCleanupFunc(dnsCleanup)
	m.expiryHandler.SetDNSCleanupFunc(dnsCleanup)
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Initialize initializes the lease manager.
func (m *LeaseManager) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	// Validate dependencies
	if m.leaseRepo == nil {
		return ErrMissingLeaseRepository
	}
	if m.poolManager == nil {
		return ErrMissingPoolManager
	}

	// Start conflict detector
	if m.config.EnableConflict {
		m.conflictDetector.Start()
	}

	// Start expiry handler
	m.expiryHandler.Start()

	m.initialized = true
	m.startTime = time.Now()

	return nil
}

// Shutdown gracefully shuts down the lease manager.
func (m *LeaseManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return nil
	}

	// Stop expiry handler
	m.expiryHandler.Stop()

	// Stop conflict detector
	m.conflictDetector.Stop()

	// Flush DNS updates
	if m.dnsClient != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, m.config.ShutdownTimeout)
		defer cancel()
		m.dnsClient.Flush(shutdownCtx)
	}

	m.initialized = false
	return nil
}

// IsInitialized returns whether the manager is initialized.
func (m *LeaseManager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initialized
}

// ============================================================================
// Core Lease Operations
// ============================================================================

// AllocateLease allocates a new IP for a client.
func (m *LeaseManager) AllocateLease(ctx context.Context, req *AllocationRequest) (*Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, m.config.AllocationTimeout)
	defer cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for existing lease
	if m.leaseRepo != nil {
		existing, err := m.leaseRepo.GetLeaseByMAC(ctx, req.MAC)
		if err == nil && existing != nil && existing.State == LeaseStateActive {
			// Return existing active lease
			return existing, nil
		}
	}

	// Allocate from pool
	result, err := m.allocator.Allocate(ctx, req)
	if err != nil {
		m.stats.Errors++
		return nil, err
	}

	// Create lease record
	now := time.Now()
	lease := &Lease{
		MAC:           req.MAC,
		IP:            result.IP,
		Hostname:      req.Hostname,
		PoolName:      result.Pool.Name,
		State:         LeaseStateOffered,
		LeaseStart:    now,
		LeaseEnd:      now.Add(result.LeaseTime),
		LeaseDuration: result.LeaseTime,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Save to database
	if m.leaseRepo != nil {
		if err := m.leaseRepo.CreateLease(ctx, lease); err != nil {
			m.stats.Errors++
			return nil, err
		}
	}

	m.stats.TotalAllocations++
	return lease, nil
}

// ConfirmLease confirms a lease (OFFERED → ACTIVE).
func (m *LeaseManager) ConfirmLease(ctx context.Context, mac net.HardwareAddr, ip net.IP) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.AllocationTimeout)
	defer cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.leaseRepo == nil {
		return ErrMissingLeaseRepository
	}

	// Get lease
	lease, err := m.leaseRepo.GetLeaseByMAC(ctx, mac)
	if err != nil {
		return err
	}
	if lease == nil {
		return ErrLeaseNotFound
	}

	// Validate state
	if lease.State != LeaseStateOffered {
		return ErrInvalidStateTransition
	}

	// Validate IP
	if !lease.IP.Equal(ip) {
		return ErrIPMismatch
	}

	// Update state
	now := time.Now()
	lease.State = LeaseStateActive
	lease.ConfirmedAt = &now
	lease.UpdatedAt = now

	if err := m.leaseRepo.UpdateLease(ctx, lease); err != nil {
		m.stats.Errors++
		return err
	}

	// Create DNS records
	if m.config.EnableDNS && m.dnsClient != nil && lease.Hostname != "" {
		if err := m.dnsClient.CreateARecord(ctx, lease.Hostname, lease.IP); err != nil {
			m.stats.DNSUpdateFailures++
		}
		if err := m.dnsClient.CreatePTRRecord(ctx, lease.IP, lease.Hostname); err != nil {
			m.stats.DNSUpdateFailures++
		}
	}

	m.stats.TotalConfirmations++
	return nil
}

// RenewLease renews an existing active lease.
func (m *LeaseManager) RenewLease(ctx context.Context, mac net.HardwareAddr) (*Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, m.config.RenewalTimeout)
	defer cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.leaseRepo == nil {
		return nil, ErrMissingLeaseRepository
	}

	// Get lease
	lease, err := m.leaseRepo.GetLeaseByMAC(ctx, mac)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, ErrLeaseNotFound
	}

	// Convert to LeaseRecord for renewal manager
	record := &LeaseRecord{
		ID:            lease.ID,
		MAC:           lease.MAC,
		IP:            lease.IP,
		Hostname:      lease.Hostname,
		PoolName:      lease.PoolName,
		LeaseStart:    lease.LeaseStart,
		LeaseEnd:      lease.LeaseEnd,
		OriginalLease: lease.LeaseDuration,
		State:         StateBound,
	}

	// Process renewal
	req := &RenewalRequest{
		MAC:       mac,
		CurrentIP: lease.IP,
	}

	result, err := m.renewalManager.ProcessRenewal(ctx, req, record)
	if err != nil {
		m.stats.Errors++
		return nil, err
	}

	if !result.Success {
		return nil, result.Error
	}

	// Update lease in database
	now := time.Now()
	lease.LeaseStart = now
	lease.LeaseEnd = now.Add(result.LeaseTime)
	lease.UpdatedAt = now

	if err := m.leaseRepo.UpdateLease(ctx, lease); err != nil {
		m.stats.Errors++
		return nil, err
	}

	m.stats.TotalRenewals++
	return lease, nil
}

// ReleaseLease releases a lease.
func (m *LeaseManager) ReleaseLease(ctx context.Context, mac net.HardwareAddr, ip net.IP) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.ReleaseTimeout)
	defer cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.leaseRepo == nil {
		return ErrMissingLeaseRepository
	}

	// Get lease
	lease, err := m.leaseRepo.GetLeaseByMAC(ctx, mac)
	if err != nil {
		return err
	}
	if lease == nil {
		return ErrLeaseNotFound
	}

	// Convert to LeaseRecord
	record := &LeaseRecord{
		ID:            lease.ID,
		MAC:           lease.MAC,
		IP:            lease.IP,
		Hostname:      lease.Hostname,
		PoolName:      lease.PoolName,
		LeaseStart:    lease.LeaseStart,
		LeaseEnd:      lease.LeaseEnd,
		OriginalLease: lease.LeaseDuration,
		State:         StateBound,
	}

	// Process release
	req := &ReleaseRequest{
		MAC:      mac,
		ClientIP: ip,
	}

	result, err := m.releaseHandler.HandleRelease(ctx, req, record)
	if err != nil {
		m.stats.Errors++
		return err
	}

	if !result.Success {
		return result.Error
	}

	// Update lease in database
	now := time.Now()
	lease.State = LeaseStateReleased
	lease.ReleasedAt = &now
	lease.UpdatedAt = now

	if err := m.leaseRepo.UpdateLease(ctx, lease); err != nil {
		m.stats.Errors++
		return err
	}

	// Release IP back to pool
	m.allocator.RemoveClientHistory(mac)

	m.stats.TotalReleases++
	return nil
}

// DeclineLease marks an IP as declined/conflicted.
func (m *LeaseManager) DeclineLease(ctx context.Context, mac net.HardwareAddr, ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Blacklist the IP
	if m.conflictDetector != nil {
		m.conflictDetector.AddToBlacklist(ip, "Client declined", mac)
	}

	m.stats.ConflictsDetected++
	return nil
}

// ============================================================================
// Query Methods
// ============================================================================

// GetLease retrieves a lease by MAC.
func (m *LeaseManager) GetLease(ctx context.Context, mac net.HardwareAddr) (*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.leaseRepo == nil {
		return nil, ErrMissingLeaseRepository
	}

	return m.leaseRepo.GetLeaseByMAC(ctx, mac)
}

// GetLeaseByIP retrieves a lease by IP.
func (m *LeaseManager) GetLeaseByIP(ctx context.Context, ip net.IP) (*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.leaseRepo == nil {
		return nil, ErrMissingLeaseRepository
	}

	return m.leaseRepo.GetLeaseByIP(ctx, ip)
}

// GetActiveLeases retrieves all active leases.
func (m *LeaseManager) GetActiveLeases(ctx context.Context) ([]*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.leaseRepo == nil {
		return nil, ErrMissingLeaseRepository
	}

	return m.leaseRepo.GetActiveLeases(ctx)
}

// ============================================================================
// Pool Statistics
// ============================================================================

// PoolStatistics holds pool usage statistics.
type PoolStatistics struct {
	PoolName     string
	TotalIPs     int
	ActiveLeases int
	AvailableIPs int
	Utilization  float64
}

// GetPoolStatistics returns statistics for a pool.
func (m *LeaseManager) GetPoolStatistics(ctx context.Context, poolName string) (*PoolStatistics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.leaseRepo == nil {
		return nil, ErrMissingLeaseRepository
	}

	activeCount, err := m.leaseRepo.GetLeaseCountByPool(ctx, poolName)
	if err != nil {
		return nil, err
	}

	// Estimate total (would come from pool manager)
	totalIPs := 254 // Default /24 assumption

	utilization := float64(activeCount) / float64(totalIPs) * 100

	return &PoolStatistics{
		PoolName:     poolName,
		TotalIPs:     totalIPs,
		ActiveLeases: activeCount,
		AvailableIPs: totalIPs - activeCount,
		Utilization:  utilization,
	}, nil
}

// ============================================================================
// Manager Statistics
// ============================================================================

// GetStats returns manager statistics.
func (m *LeaseManager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// GetUptime returns manager uptime.
func (m *LeaseManager) GetUptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Since(m.startTime)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrMissingLeaseRepository is returned when lease repo not set
	ErrMissingLeaseRepository = errors.New("lease repository not configured")

	// ErrMissingPoolManager is returned when pool manager not set
	ErrMissingPoolManager = errors.New("pool manager not configured")

	// ErrInvalidStateTransition is returned for invalid state changes
	ErrInvalidStateTransition = errors.New("invalid lease state transition")
)
