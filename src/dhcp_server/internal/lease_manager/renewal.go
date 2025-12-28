// Package lease_manager handles DHCP lease lifecycle operations.
// This file implements lease renewal and rebinding per RFC 2131.
package lease_manager

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Renewal Configuration
// ============================================================================

// RenewalConfig holds renewal settings.
type RenewalConfig struct {
	T1Percentage       float64       // Default 0.5 (50%)
	T2Percentage       float64       // Default 0.875 (87.5%)
	GracePeriod        time.Duration // Time after expiration to allow renewal
	MaxLeaseLifetime   time.Duration // Maximum total lease time
	MaxRenewalCount    int           // 0 = unlimited
	AuthRequired       bool          // Require authentication for renewal
	AsyncStorageUpdate bool          // Use async storage updates
	CacheSize          int           // Recently renewed lease cache size
}

// DefaultRenewalConfig returns RFC 2131 compliant defaults.
func DefaultRenewalConfig() *RenewalConfig {
	return &RenewalConfig{
		T1Percentage:       0.5,
		T2Percentage:       0.875,
		GracePeriod:        5 * time.Minute,
		MaxLeaseLifetime:   7 * 24 * time.Hour, // 1 week
		MaxRenewalCount:    0,                  // unlimited
		AuthRequired:       false,
		AsyncStorageUpdate: false,
		CacheSize:          1000,
	}
}

// ============================================================================
// Lease State
// ============================================================================

// LeaseRenewalState represents client state in renewal process.
type LeaseRenewalState int

const (
	StateInit LeaseRenewalState = iota
	StateBound
	StateRenewing
	StateRebinding
	StateExpired
)

func (s LeaseRenewalState) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateBound:
		return "BOUND"
	case StateRenewing:
		return "RENEWING"
	case StateRebinding:
		return "REBINDING"
	case StateExpired:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Renewal Request/Response
// ============================================================================

// RenewalRequest contains information for lease renewal.
type RenewalRequest struct {
	MAC           net.HardwareAddr
	ClientID      string
	CurrentIP     net.IP
	ServerIP      net.IP // For unicast renewals
	IsBroadcast   bool   // Rebinding uses broadcast
	TransactionID uint32
}

// RenewalResult contains the renewal outcome.
type RenewalResult struct {
	Success    bool
	IP         net.IP
	LeaseTime  time.Duration
	T1         time.Duration
	T2         time.Duration
	Gateway    net.IP
	DNSServers []net.IP
	Error      error
}

// ============================================================================
// Lease Record for Renewal
// ============================================================================

// LeaseRecord represents a lease for renewal operations.
type LeaseRecord struct {
	ID            int64
	MAC           net.HardwareAddr
	IP            net.IP
	ClientID      string
	Hostname      string
	PoolName      string
	LeaseStart    time.Time
	LeaseEnd      time.Time
	OriginalLease time.Duration
	RenewalCount  int
	LastRenewed   time.Time
	State         LeaseRenewalState
}

// T1Time calculates when client should enter RENEWING state.
func (l *LeaseRecord) T1Time(config *RenewalConfig) time.Time {
	duration := l.LeaseEnd.Sub(l.LeaseStart)
	t1Duration := time.Duration(float64(duration) * config.T1Percentage)
	return l.LeaseStart.Add(t1Duration)
}

// T2Time calculates when client should enter REBINDING state.
func (l *LeaseRecord) T2Time(config *RenewalConfig) time.Time {
	duration := l.LeaseEnd.Sub(l.LeaseStart)
	t2Duration := time.Duration(float64(duration) * config.T2Percentage)
	return l.LeaseStart.Add(t2Duration)
}

// IsExpired checks if lease has expired.
func (l *LeaseRecord) IsExpired() bool {
	return time.Now().After(l.LeaseEnd)
}

// IsInGracePeriod checks if lease is in grace period after expiration.
func (l *LeaseRecord) IsInGracePeriod(gracePeriod time.Duration) bool {
	return time.Now().After(l.LeaseEnd) && time.Now().Before(l.LeaseEnd.Add(gracePeriod))
}

// ============================================================================
// Renewal Manager
// ============================================================================

// RenewalManager handles lease renewal operations.
type RenewalManager struct {
	mu     sync.RWMutex
	config *RenewalConfig

	// Lease cache for fast lookups
	cache   map[string]*LeaseRecord // Key: MAC string
	cacheMu sync.RWMutex

	// Statistics
	stats RenewalStats
}

// RenewalStats tracks renewal metrics.
type RenewalStats struct {
	TotalRenewals       int64
	SuccessfulRenewals  int64
	FailedRenewals      int64
	RebindingAttempts   int64
	GracePeriodRenewals int64
	PolicyDenials       int64
}

// NewRenewalManager creates a new renewal manager.
func NewRenewalManager(config *RenewalConfig) *RenewalManager {
	if config == nil {
		config = DefaultRenewalConfig()
	}

	return &RenewalManager{
		config: config,
		cache:  make(map[string]*LeaseRecord, config.CacheSize),
	}
}

// ============================================================================
// Main Renewal Entry Point
// ============================================================================

// ProcessRenewal handles a lease renewal request.
func (m *RenewalManager) ProcessRenewal(ctx context.Context, req *RenewalRequest, lease *LeaseRecord) (*RenewalResult, error) {
	m.mu.Lock()
	m.stats.TotalRenewals++
	m.mu.Unlock()

	// Validate request
	if err := m.validateRenewalRequest(req, lease); err != nil {
		m.recordFailure()
		return &RenewalResult{Success: false, Error: err}, err
	}

	// Check lease state
	now := time.Now()

	// Determine if this is renewal or rebinding
	if req.IsBroadcast {
		m.stats.RebindingAttempts++
	}

	// Check if within valid renewal window
	if lease.IsExpired() {
		if lease.IsInGracePeriod(m.config.GracePeriod) {
			m.stats.GracePeriodRenewals++
		} else {
			m.recordFailure()
			return &RenewalResult{Success: false, Error: ErrLeaseExpired}, ErrLeaseExpired
		}
	}

	// Apply renewal policies
	if err := m.applyRenewalPolicies(lease); err != nil {
		m.stats.PolicyDenials++
		m.recordFailure()
		return &RenewalResult{Success: false, Error: err}, err
	}

	// Calculate new lease times
	newLeaseDuration := m.calculateNewLeaseDuration(lease)
	newExpiry := now.Add(newLeaseDuration)
	t1 := time.Duration(float64(newLeaseDuration) * m.config.T1Percentage)
	t2 := time.Duration(float64(newLeaseDuration) * m.config.T2Percentage)

	// Update lease record
	lease.LeaseStart = now
	lease.LeaseEnd = newExpiry
	lease.RenewalCount++
	lease.LastRenewed = now
	lease.State = StateBound

	// Update cache
	m.updateCache(lease)

	m.recordSuccess()

	return &RenewalResult{
		Success:   true,
		IP:        lease.IP,
		LeaseTime: newLeaseDuration,
		T1:        t1,
		T2:        t2,
	}, nil
}

// ============================================================================
// Validation
// ============================================================================

func (m *RenewalManager) validateRenewalRequest(req *RenewalRequest, lease *LeaseRecord) error {
	if req == nil {
		return errors.New("renewal request is nil")
	}

	if lease == nil {
		return ErrLeaseNotFound
	}

	// Verify MAC address matches
	if req.MAC.String() != lease.MAC.String() {
		return ErrOwnershipMismatch
	}

	// Verify IP address matches
	if !req.CurrentIP.Equal(lease.IP) {
		return ErrIPMismatch
	}

	// Verify client ID if present
	if req.ClientID != "" && lease.ClientID != "" {
		if req.ClientID != lease.ClientID {
			return ErrClientIDMismatch
		}
	}

	return nil
}

// ============================================================================
// Policy Enforcement
// ============================================================================

func (m *RenewalManager) applyRenewalPolicies(lease *LeaseRecord) error {
	// Check maximum renewal count
	if m.config.MaxRenewalCount > 0 && lease.RenewalCount >= m.config.MaxRenewalCount {
		return ErrMaxRenewalsExceeded
	}

	// Check maximum lease lifetime
	totalLifetime := time.Since(lease.LeaseStart) + lease.OriginalLease
	if totalLifetime > m.config.MaxLeaseLifetime {
		return ErrMaxLifetimeExceeded
	}

	// Authentication check (placeholder - would integrate with auth subsystem)
	if m.config.AuthRequired {
		// TODO: Implement authentication check
	}

	return nil
}

// ============================================================================
// Lease Duration Calculation
// ============================================================================

func (m *RenewalManager) calculateNewLeaseDuration(lease *LeaseRecord) time.Duration {
	// Start with original lease duration
	newDuration := lease.OriginalLease

	// Check if would exceed max lifetime
	currentLifetime := time.Since(lease.LeaseStart)
	remainingAllowed := m.config.MaxLeaseLifetime - currentLifetime

	if remainingAllowed < newDuration {
		newDuration = remainingAllowed
	}

	// Minimum 1 hour lease
	if newDuration < time.Hour {
		newDuration = time.Hour
	}

	return newDuration
}

// ============================================================================
// T1/T2 Timer Helpers
// ============================================================================

// CalculateT1 calculates T1 timer value for a lease duration.
func (m *RenewalManager) CalculateT1(leaseDuration time.Duration) time.Duration {
	return time.Duration(float64(leaseDuration) * m.config.T1Percentage)
}

// CalculateT2 calculates T2 timer value for a lease duration.
func (m *RenewalManager) CalculateT2(leaseDuration time.Duration) time.Duration {
	return time.Duration(float64(leaseDuration) * m.config.T2Percentage)
}

// GetTimerValues returns T1 and T2 for a given lease.
func (m *RenewalManager) GetTimerValues(lease *LeaseRecord) (t1, t2 time.Duration) {
	duration := lease.LeaseEnd.Sub(lease.LeaseStart)
	t1 = m.CalculateT1(duration)
	t2 = m.CalculateT2(duration)
	return
}

// ============================================================================
// Cache Management
// ============================================================================

func (m *RenewalManager) updateCache(lease *LeaseRecord) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	// Evict if at capacity
	if len(m.cache) >= m.config.CacheSize {
		// Remove oldest entry (simple strategy)
		for k := range m.cache {
			delete(m.cache, k)
			break
		}
	}

	m.cache[lease.MAC.String()] = lease
}

// GetCachedLease retrieves a lease from cache.
func (m *RenewalManager) GetCachedLease(mac net.HardwareAddr) *LeaseRecord {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return m.cache[mac.String()]
}

// InvalidateCache removes a lease from cache.
func (m *RenewalManager) InvalidateCache(mac net.HardwareAddr) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	delete(m.cache, mac.String())
}

// ClearCache clears the entire cache.
func (m *RenewalManager) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.cache = make(map[string]*LeaseRecord, m.config.CacheSize)
}

// ============================================================================
// State Transitions
// ============================================================================

// TransitionToBound moves lease to BOUND state after successful renewal.
func (m *RenewalManager) TransitionToBound(lease *LeaseRecord) {
	lease.State = StateBound
	m.updateCache(lease)
}

// TransitionToRenewing marks lease as entering RENEWING state.
func (m *RenewalManager) TransitionToRenewing(lease *LeaseRecord) {
	lease.State = StateRenewing
	m.updateCache(lease)
}

// TransitionToRebinding marks lease as entering REBINDING state.
func (m *RenewalManager) TransitionToRebinding(lease *LeaseRecord) {
	lease.State = StateRebinding
	m.updateCache(lease)
}

// TransitionToExpired marks lease as EXPIRED.
func (m *RenewalManager) TransitionToExpired(lease *LeaseRecord) {
	lease.State = StateExpired
	m.InvalidateCache(lease.MAC)
}

// ============================================================================
// Rebinding Handling
// ============================================================================

// ProcessRebinding handles rebinding (broadcast) requests.
func (m *RenewalManager) ProcessRebinding(ctx context.Context, req *RenewalRequest, lease *LeaseRecord) (*RenewalResult, error) {
	// Rebinding is essentially a renewal via broadcast
	req.IsBroadcast = true
	return m.ProcessRenewal(ctx, req, lease)
}

// ============================================================================
// Statistics
// ============================================================================

func (m *RenewalManager) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.SuccessfulRenewals++
}

func (m *RenewalManager) recordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.FailedRenewals++
}

// GetStats returns renewal statistics.
func (m *RenewalManager) GetStats() RenewalStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// GetSuccessRate returns the renewal success rate.
func (m *RenewalManager) GetSuccessRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.stats.TotalRenewals == 0 {
		return 0
	}
	return float64(m.stats.SuccessfulRenewals) / float64(m.stats.TotalRenewals) * 100
}

// ============================================================================
// Lease Expiration Check
// ============================================================================

// ShouldRenew checks if a lease should be renewed based on T1.
func (m *RenewalManager) ShouldRenew(lease *LeaseRecord) bool {
	t1Time := lease.T1Time(m.config)
	return time.Now().After(t1Time)
}

// ShouldRebind checks if a lease should rebind based on T2.
func (m *RenewalManager) ShouldRebind(lease *LeaseRecord) bool {
	t2Time := lease.T2Time(m.config)
	return time.Now().After(t2Time)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrLeaseExpired is returned when lease has expired
	ErrLeaseExpired = errors.New("lease has expired")

	// ErrOwnershipMismatch is returned when MAC doesn't match lease
	ErrOwnershipMismatch = errors.New("lease ownership mismatch")

	// ErrIPMismatch is returned when IP doesn't match lease
	ErrIPMismatch = errors.New("IP address mismatch")

	// ErrClientIDMismatch is returned when client ID doesn't match
	ErrClientIDMismatch = errors.New("client ID mismatch")

	// ErrMaxRenewalsExceeded is returned when renewal limit reached
	ErrMaxRenewalsExceeded = errors.New("maximum renewals exceeded")

	// ErrMaxLifetimeExceeded is returned when max lease lifetime reached
	ErrMaxLifetimeExceeded = errors.New("maximum lease lifetime exceeded")

	// ErrLeaseNotFound is returned when lease record not found
	ErrLeaseNotFound = errors.New("lease not found")
)
