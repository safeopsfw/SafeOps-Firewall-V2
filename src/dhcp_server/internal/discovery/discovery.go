// Package discovery handles DHCP message processing.
// This file implements DHCP DISCOVER message handling.
package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Discovery Handler Configuration
// ============================================================================

// DiscoveryConfig holds configuration for DISCOVER processing.
type DiscoveryConfig struct {
	ProcessingTimeout        time.Duration
	ConflictDetectionEnabled bool
	ConflictTimeout          time.Duration
	PreferLeaseRenewal       bool
	ReservationPriority      bool
	PoolExhaustionAlertPct   int
	MaxAllocationRetries     int
}

// DefaultDiscoveryConfig returns sensible defaults.
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		ProcessingTimeout:        5 * time.Second,
		ConflictDetectionEnabled: true,
		ConflictTimeout:          500 * time.Millisecond,
		PreferLeaseRenewal:       true,
		ReservationPriority:      true,
		PoolExhaustionAlertPct:   80,
		MaxAllocationRetries:     3,
	}
}

// ============================================================================
// Client Identifier
// ============================================================================

// ClientIdentifier represents client identification information.
type ClientIdentifier struct {
	MAC         net.HardwareAddr
	ClientID    string
	Hostname    string
	VendorClass string
}

// Key returns a unique key for this client.
func (c *ClientIdentifier) Key() string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return c.MAC.String()
}

// ============================================================================
// Discover Request
// ============================================================================

// DiscoverRequest contains parsed DHCP DISCOVER information.
type DiscoverRequest struct {
	TransactionID      uint32
	Client             *ClientIdentifier
	RequestedIP        net.IP
	RelayAgentIP       net.IP
	BroadcastFlag      bool
	ReceivedAt         time.Time
	ReceivingInterface string
}

// DiscoverResult contains the result of DISCOVER processing.
type DiscoverResult struct {
	Success       bool
	AllocatedIP   net.IP
	PoolName      string
	LeaseTime     time.Duration
	Gateway       net.IP
	SubnetMask    net.IPMask
	DNSServers    []net.IP
	IsRenewal     bool
	IsReservation bool
	Error         error
}

// ============================================================================
// Discovery Handler
// ============================================================================

// DiscoveryHandler processes DHCP DISCOVER messages.
type DiscoveryHandler struct {
	mu     sync.RWMutex
	config *DiscoveryConfig

	// Dependencies (set via setters)
	leaseManager     LeaseManagerInterface
	poolManager      PoolManagerInterface
	conflictDetector ConflictDetectorInterface
	offerBuilder     OfferBuilderInterface

	// Statistics
	stats DiscoveryStats
}

// DiscoveryStats tracks DISCOVER processing metrics.
type DiscoveryStats struct {
	TotalReceived     int64
	SuccessfulOffers  int64
	FailedOffers      int64
	Renewals          int64
	Reservations      int64
	ConflictsDetected int64
	PoolExhaustions   int64
	ProcessingTimeMs  int64 // Cumulative
}

// ============================================================================
// Dependency Interfaces
// ============================================================================

// LeaseManagerInterface defines lease manager operations.
type LeaseManagerInterface interface {
	GetLeaseByMAC(ctx context.Context, mac net.HardwareAddr) (*LeaseInfo, error)
	AllocateLease(ctx context.Context, req *AllocationRequest) (*LeaseInfo, error)
}

// PoolManagerInterface defines pool manager operations.
type PoolManagerInterface interface {
	GetPoolBySubnet(subnet *net.IPNet) (*PoolInfo, error)
	GetPoolByRelayIP(relayIP net.IP) (*PoolInfo, error)
	GetDefaultPool() *PoolInfo
	GetReservation(mac net.HardwareAddr) (*ReservationInfo, error)
}

// ConflictDetectorInterface defines conflict detection operations.
type ConflictDetectorInterface interface {
	CheckConflict(ctx context.Context, ip net.IP) (bool, error)
}

// OfferBuilderInterface defines OFFER construction operations.
type OfferBuilderInterface interface {
	BuildOffer(ctx context.Context, req *OfferRequest) (*OfferResponse, error)
}

// ============================================================================
// Supporting Types
// ============================================================================

// LeaseInfo represents lease information.
type LeaseInfo struct {
	IP        net.IP
	MAC       net.HardwareAddr
	PoolName  string
	LeaseTime time.Duration
	ExpiresAt time.Time
	State     string
}

// PoolInfo represents pool configuration.
type PoolInfo struct {
	Name         string
	Subnet       *net.IPNet
	Gateway      net.IP
	SubnetMask   net.IPMask
	DNSServers   []net.IP
	DefaultLease time.Duration
	Available    int
	Total        int
}

// ReservationInfo represents a static reservation.
type ReservationInfo struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
	Active   bool
}

// AllocationRequest for lease manager.
type AllocationRequest struct {
	MAC         net.HardwareAddr
	ClientID    string
	Hostname    string
	RequestedIP net.IP
	PoolName    string
}

// OfferRequest for offer builder.
type OfferRequest struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	AllocatedIP   net.IP
	Pool          *PoolInfo
	LeaseTime     time.Duration
	BroadcastFlag bool
	ServerIP      net.IP
}

// OfferResponse from offer builder.
type OfferResponse struct {
	Packet  []byte
	Success bool
	Error   error
}

// ============================================================================
// Handler Creation
// ============================================================================

// NewDiscoveryHandler creates a new DISCOVER handler.
func NewDiscoveryHandler(config *DiscoveryConfig) *DiscoveryHandler {
	if config == nil {
		config = DefaultDiscoveryConfig()
	}

	return &DiscoveryHandler{
		config: config,
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetLeaseManager sets the lease manager.
func (h *DiscoveryHandler) SetLeaseManager(lm LeaseManagerInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leaseManager = lm
}

// SetPoolManager sets the pool manager.
func (h *DiscoveryHandler) SetPoolManager(pm PoolManagerInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.poolManager = pm
}

// SetConflictDetector sets the conflict detector.
func (h *DiscoveryHandler) SetConflictDetector(cd ConflictDetectorInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conflictDetector = cd
}

// SetOfferBuilder sets the offer builder.
func (h *DiscoveryHandler) SetOfferBuilder(ob OfferBuilderInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.offerBuilder = ob
}

// ============================================================================
// Main DISCOVER Processing
// ============================================================================

// HandleDiscover processes a DHCP DISCOVER message.
func (h *DiscoveryHandler) HandleDiscover(ctx context.Context, req *DiscoverRequest) (*DiscoverResult, error) {
	ctx, cancel := context.WithTimeout(ctx, h.config.ProcessingTimeout)
	defer cancel()

	startTime := time.Now()
	h.stats.TotalReceived++

	result := &DiscoverResult{}

	// Validate request
	if err := h.validateRequest(req); err != nil {
		h.stats.FailedOffers++
		result.Error = err
		return result, err
	}

	// Step 1: Check for static reservation
	if h.config.ReservationPriority {
		if res := h.checkReservation(req.Client.MAC); res != nil {
			result.AllocatedIP = res.IP
			result.IsReservation = true
			h.stats.Reservations++
		}
	}

	// Step 2: Check for existing lease
	if result.AllocatedIP == nil && h.config.PreferLeaseRenewal {
		if lease := h.checkExistingLease(ctx, req.Client.MAC); lease != nil {
			result.AllocatedIP = lease.IP
			result.PoolName = lease.PoolName
			result.LeaseTime = lease.LeaseTime
			result.IsRenewal = true
			h.stats.Renewals++
		}
	}

	// Step 3: Select pool
	pool := h.selectPool(req)
	if pool == nil {
		h.stats.FailedOffers++
		h.stats.PoolExhaustions++
		result.Error = ErrNoPoolAvailable
		return result, ErrNoPoolAvailable
	}
	result.PoolName = pool.Name
	result.Gateway = pool.Gateway
	result.SubnetMask = pool.SubnetMask
	result.DNSServers = pool.DNSServers

	// Step 4: Allocate IP if not already assigned
	if result.AllocatedIP == nil {
		allocatedIP, err := h.allocateIP(ctx, req, pool)
		if err != nil {
			h.stats.FailedOffers++
			result.Error = err
			return result, err
		}
		result.AllocatedIP = allocatedIP
		result.LeaseTime = pool.DefaultLease
	}

	// Step 5: Conflict detection
	if h.config.ConflictDetectionEnabled {
		hasConflict, _ := h.checkConflict(ctx, result.AllocatedIP)
		if hasConflict {
			h.stats.ConflictsDetected++
			// Retry with different IP
			for retry := 0; retry < h.config.MaxAllocationRetries; retry++ {
				newIP, err := h.allocateIP(ctx, req, pool)
				if err != nil {
					continue
				}
				hasConflict, _ = h.checkConflict(ctx, newIP)
				if !hasConflict {
					result.AllocatedIP = newIP
					break
				}
				h.stats.ConflictsDetected++
			}
		}
	}

	// Record processing time
	h.stats.ProcessingTimeMs += time.Since(startTime).Milliseconds()

	result.Success = true
	h.stats.SuccessfulOffers++

	return result, nil
}

// ============================================================================
// Validation
// ============================================================================

func (h *DiscoveryHandler) validateRequest(req *DiscoverRequest) error {
	if req == nil {
		return ErrNilRequest
	}

	if req.Client == nil {
		return ErrMissingClient
	}

	if len(req.Client.MAC) == 0 {
		return ErrMissingMAC
	}

	if req.TransactionID == 0 {
		return ErrMissingTransactionID
	}

	return nil
}

// ============================================================================
// Reservation Check
// ============================================================================

func (h *DiscoveryHandler) checkReservation(mac net.HardwareAddr) *ReservationInfo {
	h.mu.RLock()
	pm := h.poolManager
	h.mu.RUnlock()

	if pm == nil {
		return nil
	}

	res, err := pm.GetReservation(mac)
	if err != nil || res == nil {
		return nil
	}

	if !res.Active {
		return nil
	}

	return res
}

// ============================================================================
// Existing Lease Check
// ============================================================================

func (h *DiscoveryHandler) checkExistingLease(ctx context.Context, mac net.HardwareAddr) *LeaseInfo {
	h.mu.RLock()
	lm := h.leaseManager
	h.mu.RUnlock()

	if lm == nil {
		return nil
	}

	lease, err := lm.GetLeaseByMAC(ctx, mac)
	if err != nil || lease == nil {
		return nil
	}

	// Check if lease is still valid
	if time.Now().After(lease.ExpiresAt) {
		return nil
	}

	if lease.State != "ACTIVE" {
		return nil
	}

	return lease
}

// ============================================================================
// Pool Selection
// ============================================================================

func (h *DiscoveryHandler) selectPool(req *DiscoverRequest) *PoolInfo {
	h.mu.RLock()
	pm := h.poolManager
	h.mu.RUnlock()

	if pm == nil {
		return nil
	}

	// Try relay agent IP first
	if req.RelayAgentIP != nil && !req.RelayAgentIP.IsUnspecified() {
		if pool, err := pm.GetPoolByRelayIP(req.RelayAgentIP); err == nil && pool != nil {
			return pool
		}
	}

	// Fall back to default pool
	return pm.GetDefaultPool()
}

// ============================================================================
// IP Allocation
// ============================================================================

func (h *DiscoveryHandler) allocateIP(ctx context.Context, req *DiscoverRequest, pool *PoolInfo) (net.IP, error) {
	h.mu.RLock()
	lm := h.leaseManager
	h.mu.RUnlock()

	if lm == nil {
		return nil, ErrLeaseManagerNotSet
	}

	allocReq := &AllocationRequest{
		MAC:         req.Client.MAC,
		ClientID:    req.Client.ClientID,
		Hostname:    req.Client.Hostname,
		RequestedIP: req.RequestedIP,
		PoolName:    pool.Name,
	}

	lease, err := lm.AllocateLease(ctx, allocReq)
	if err != nil {
		return nil, err
	}

	return lease.IP, nil
}

// ============================================================================
// Conflict Detection
// ============================================================================

func (h *DiscoveryHandler) checkConflict(ctx context.Context, ip net.IP) (bool, error) {
	h.mu.RLock()
	cd := h.conflictDetector
	h.mu.RUnlock()

	if cd == nil {
		return false, nil
	}

	conflictCtx, cancel := context.WithTimeout(ctx, h.config.ConflictTimeout)
	defer cancel()

	return cd.CheckConflict(conflictCtx, ip)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns discovery handler statistics.
func (h *DiscoveryHandler) GetStats() DiscoveryStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GetSuccessRate returns the OFFER success rate.
func (h *DiscoveryHandler) GetSuccessRate() float64 {
	total := h.stats.SuccessfulOffers + h.stats.FailedOffers
	if total == 0 {
		return 0
	}
	return float64(h.stats.SuccessfulOffers) / float64(total) * 100
}

// GetAverageProcessingTime returns average processing time in milliseconds.
func (h *DiscoveryHandler) GetAverageProcessingTime() float64 {
	if h.stats.TotalReceived == 0 {
		return 0
	}
	return float64(h.stats.ProcessingTimeMs) / float64(h.stats.TotalReceived)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilRequest is returned when request is nil
	ErrNilRequest = errors.New("discover request is nil")

	// ErrMissingClient is returned when client info missing
	ErrMissingClient = errors.New("client information missing")

	// ErrMissingMAC is returned when MAC address missing
	ErrMissingMAC = errors.New("client MAC address missing")

	// ErrMissingTransactionID is returned when XID missing
	ErrMissingTransactionID = errors.New("transaction ID missing")

	// ErrNoPoolAvailable is returned when no pool found
	ErrNoPoolAvailable = errors.New("no suitable DHCP pool available")

	// ErrLeaseManagerNotSet is returned when lease manager not configured
	ErrLeaseManagerNotSet = errors.New("lease manager not configured")

	// ErrPoolExhausted is returned when pool has no available IPs
	ErrPoolExhausted = errors.New("DHCP pool exhausted")
)
