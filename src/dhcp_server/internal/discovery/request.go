// Package discovery handles DHCP message processing.
// This file implements DHCP REQUEST message handling for SELECTING, RENEWING, and REBINDING states.
package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// REQUEST State Types
// ============================================================================

// RequestState represents the client state when sending REQUEST.
type RequestState int

const (
	// StateSelecting - Client accepting OFFER after DISCOVER
	StateSelecting RequestState = iota
	// StateRenewing - Client renewing at T1 timer (50%)
	StateRenewing
	// StateRebinding - Client rebinding at T2 timer (87.5%)
	StateRebinding
	// StateUnknown - Cannot determine state
	StateUnknown
)

func (s RequestState) String() string {
	switch s {
	case StateSelecting:
		return "SELECTING"
	case StateRenewing:
		return "RENEWING"
	case StateRebinding:
		return "REBINDING"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Request Handler Configuration
// ============================================================================

// RequestHandlerConfig holds REQUEST processing configuration.
type RequestHandlerConfig struct {
	ProcessingTimeout   time.Duration
	OfferValidityWindow time.Duration
	AllowLeaseTakeover  bool
	DNSUpdateEnabled    bool
	DNSUpdateTimeout    time.Duration
	ValidateOnRenew     bool
}

// DefaultRequestHandlerConfig returns sensible defaults.
func DefaultRequestHandlerConfig() *RequestHandlerConfig {
	return &RequestHandlerConfig{
		ProcessingTimeout:   5 * time.Second,
		OfferValidityWindow: 2 * time.Minute,
		AllowLeaseTakeover:  true,
		DNSUpdateEnabled:    true,
		DNSUpdateTimeout:    3 * time.Second,
		ValidateOnRenew:     false,
	}
}

// ============================================================================
// Request Information
// ============================================================================

// RequestInfo contains parsed REQUEST message information.
type RequestInfo struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	ClientID      string
	RequestedIP   net.IP
	ServerID      net.IP
	CIAddr        net.IP
	Hostname      string
	State         RequestState
	ReceivedAt    time.Time
}

// RequestResult contains the result of REQUEST processing.
type RequestResult struct {
	Success     bool
	SendACK     bool
	SendNAK     bool
	AllocatedIP net.IP
	LeaseTime   time.Duration
	Pool        *PoolInfo
	Reason      string
	Error       error
}

// NAKBuildRequest contains parameters for NAK construction.
type NAKBuildRequest struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	GIAddr        net.IP
	Reason        string
}

// ============================================================================
// Request Handler
// ============================================================================

// RequestHandler processes DHCP REQUEST messages.
type RequestHandler struct {
	mu     sync.RWMutex
	config *RequestHandlerConfig

	// Dependencies
	leaseManager LeaseManagerInterface
	poolManager  PoolManagerInterface
	dnsUpdater   DNSUpdaterInterface
	ackBuilder   ACKBuilderInterface
	nakBuilder   NAKBuilderInterface

	// Offer tracking
	pendingOffers map[string]*PendingOffer
	offerMu       sync.RWMutex

	// Statistics
	stats RequestStats
}

// RequestStats tracks REQUEST processing metrics.
type RequestStats struct {
	TotalReceived    int64
	SelectingCount   int64
	RenewingCount    int64
	RebindingCount   int64
	ACKsSent         int64
	NAKsSent         int64
	DNSUpdates       int64
	DNSFailures      int64
	ProcessingTimeMs int64
}

// PendingOffer tracks an outstanding OFFER.
type PendingOffer struct {
	OfferedIP net.IP
	ClientMAC net.HardwareAddr
	PoolName  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ============================================================================
// Dependency Interfaces
// ============================================================================

// DNSUpdaterInterface defines DNS update operations.
type DNSUpdaterInterface interface {
	UpdateDNS(ctx context.Context, hostname string, ip net.IP, mac net.HardwareAddr, lease time.Duration) error
}

// ACKBuilderInterface defines ACK construction operations.
type ACKBuilderInterface interface {
	BuildACK(ctx context.Context, req *ACKBuildRequest) (*DHCPPacket, error)
}

// NAKBuilderInterface defines NAK construction operations.
type NAKBuilderInterface interface {
	BuildNAK(ctx context.Context, req *NAKBuildRequest) (*DHCPPacket, error)
}

// ============================================================================
// Handler Creation
// ============================================================================

// NewRequestHandler creates a new REQUEST handler.
func NewRequestHandler(config *RequestHandlerConfig) *RequestHandler {
	if config == nil {
		config = DefaultRequestHandlerConfig()
	}

	return &RequestHandler{
		config:        config,
		pendingOffers: make(map[string]*PendingOffer),
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetLeaseManager sets the lease manager.
func (h *RequestHandler) SetLeaseManager(lm LeaseManagerInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leaseManager = lm
}

// SetPoolManager sets the pool manager.
func (h *RequestHandler) SetPoolManager(pm PoolManagerInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.poolManager = pm
}

// SetDNSUpdater sets the DNS updater.
func (h *RequestHandler) SetDNSUpdater(dns DNSUpdaterInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dnsUpdater = dns
}

// SetACKBuilder sets the ACK builder.
func (h *RequestHandler) SetACKBuilder(ab ACKBuilderInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ackBuilder = ab
}

// SetNAKBuilder sets the NAK builder.
func (h *RequestHandler) SetNAKBuilder(nb NAKBuilderInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nakBuilder = nb
}

// ============================================================================
// Main REQUEST Processing
// ============================================================================

// HandleRequest processes a DHCP REQUEST message.
func (h *RequestHandler) HandleRequest(ctx context.Context, req *RequestInfo) (*RequestResult, error) {
	ctx, cancel := context.WithTimeout(ctx, h.config.ProcessingTimeout)
	defer cancel()

	startTime := time.Now()
	h.stats.TotalReceived++

	result := &RequestResult{}

	// Validate request
	if err := h.validateRequest(req); err != nil {
		result.SendNAK = true
		result.Reason = err.Error()
		result.Error = err
		h.stats.NAKsSent++
		return result, nil
	}

	// Detect REQUEST state
	req.State = h.detectState(req)
	h.updateStateCounts(req.State)

	// Process based on state
	var err error
	switch req.State {
	case StateSelecting:
		err = h.handleSelecting(ctx, req, result)
	case StateRenewing:
		err = h.handleRenewing(ctx, req, result)
	case StateRebinding:
		err = h.handleRebinding(ctx, req, result)
	default:
		result.SendNAK = true
		result.Reason = "unknown REQUEST state"
		h.stats.NAKsSent++
	}

	if err != nil {
		result.SendNAK = true
		result.Reason = err.Error()
		result.Error = err
		h.stats.NAKsSent++
		return result, nil
	}

	// Trigger DNS update if successful and enabled
	if result.Success && h.config.DNSUpdateEnabled && req.Hostname != "" {
		h.triggerDNSUpdate(ctx, req, result)
	}

	// Record processing time
	h.stats.ProcessingTimeMs += time.Since(startTime).Milliseconds()

	return result, nil
}

// ============================================================================
// State Detection
// ============================================================================

func (h *RequestHandler) detectState(req *RequestInfo) RequestState {
	hasCIAddr := req.CIAddr != nil && !req.CIAddr.IsUnspecified()
	hasServerID := req.ServerID != nil && !req.ServerID.IsUnspecified()

	// SELECTING: ciaddr = 0.0.0.0, server ID present, requested IP in option 50
	if !hasCIAddr && hasServerID {
		return StateSelecting
	}

	// RENEWING: ciaddr populated, sent to server directly (has server ID or unicast)
	if hasCIAddr && hasServerID {
		return StateRenewing
	}

	// REBINDING: ciaddr populated, broadcast (no server ID)
	if hasCIAddr && !hasServerID {
		return StateRebinding
	}

	return StateUnknown
}

func (h *RequestHandler) updateStateCounts(state RequestState) {
	switch state {
	case StateSelecting:
		h.stats.SelectingCount++
	case StateRenewing:
		h.stats.RenewingCount++
	case StateRebinding:
		h.stats.RebindingCount++
	}
}

// ============================================================================
// SELECTING State Handler
// ============================================================================

func (h *RequestHandler) handleSelecting(ctx context.Context, req *RequestInfo, result *RequestResult) error {
	// Verify we have a pending offer for this client
	offer := h.getPendingOffer(req.ClientMAC)
	if offer == nil {
		return ErrNoPendingOffer
	}

	// Check offer not expired
	if time.Now().After(offer.ExpiresAt) {
		h.removePendingOffer(req.ClientMAC)
		return ErrOfferExpired
	}

	// Verify requested IP matches offer
	if req.RequestedIP != nil && !req.RequestedIP.Equal(offer.OfferedIP) {
		return ErrRequestedIPMismatch
	}

	// Commit lease
	if err := h.commitLease(ctx, req, offer.OfferedIP, offer.PoolName); err != nil {
		return err
	}

	// Get pool for response
	pool := h.getPool(offer.PoolName)

	// Remove pending offer
	h.removePendingOffer(req.ClientMAC)

	// Success
	result.Success = true
	result.SendACK = true
	result.AllocatedIP = offer.OfferedIP
	result.Pool = pool
	if pool != nil {
		result.LeaseTime = pool.DefaultLease
	}
	h.stats.ACKsSent++

	return nil
}

// ============================================================================
// RENEWING State Handler
// ============================================================================

func (h *RequestHandler) handleRenewing(ctx context.Context, req *RequestInfo, result *RequestResult) error {
	// Lookup existing lease
	lease, err := h.getLease(ctx, req.ClientMAC)
	if err != nil || lease == nil {
		return ErrLeaseNotFound
	}

	// Verify ciaddr matches lease
	if !req.CIAddr.Equal(lease.IP) {
		return ErrCIAddrMismatch
	}

	// Optional validation on renew
	if h.config.ValidateOnRenew {
		if err := h.validateLeaseForRenewal(ctx, lease, req); err != nil {
			return err
		}
	}

	// Extend lease
	if err := h.renewLease(ctx, lease); err != nil {
		return err
	}

	// Get pool for response
	pool := h.getPool(lease.PoolName)

	// Success
	result.Success = true
	result.SendACK = true
	result.AllocatedIP = lease.IP
	result.Pool = pool
	if pool != nil {
		result.LeaseTime = pool.DefaultLease
	}
	h.stats.ACKsSent++

	return nil
}

// ============================================================================
// REBINDING State Handler
// ============================================================================

func (h *RequestHandler) handleRebinding(ctx context.Context, req *RequestInfo, result *RequestResult) error {
	// Check if we manage this IP
	pool := h.getPoolForIP(req.CIAddr)
	if pool == nil && !h.config.AllowLeaseTakeover {
		return ErrIPNotManaged
	}

	// Lookup lease by IP and MAC
	lease, err := h.getLease(ctx, req.ClientMAC)
	if err != nil || lease == nil {
		// Allow takeover in rebinding
		if h.config.AllowLeaseTakeover {
			// Create new lease for rebinding client
			return h.createLeaseForRebind(ctx, req, result)
		}
		return ErrLeaseNotFound
	}

	// Verify IP matches
	if !req.CIAddr.Equal(lease.IP) {
		return ErrCIAddrMismatch
	}

	// Extend lease (takeover if from another server)
	if err := h.renewLease(ctx, lease); err != nil {
		return err
	}

	// Success
	result.Success = true
	result.SendACK = true
	result.AllocatedIP = lease.IP
	result.Pool = pool
	if pool != nil {
		result.LeaseTime = pool.DefaultLease
	}
	h.stats.ACKsSent++

	return nil
}

func (h *RequestHandler) createLeaseForRebind(ctx context.Context, req *RequestInfo, result *RequestResult) error {
	pool := h.getPoolForIP(req.CIAddr)
	if pool == nil {
		return ErrIPNotManaged
	}

	// Commit new lease for this client
	if err := h.commitLease(ctx, req, req.CIAddr, pool.Name); err != nil {
		return err
	}

	result.Success = true
	result.SendACK = true
	result.AllocatedIP = req.CIAddr
	result.Pool = pool
	result.LeaseTime = pool.DefaultLease
	h.stats.ACKsSent++

	return nil
}

// ============================================================================
// Lease Operations
// ============================================================================

func (h *RequestHandler) commitLease(ctx context.Context, req *RequestInfo, ip net.IP, poolName string) error {
	h.mu.RLock()
	lm := h.leaseManager
	h.mu.RUnlock()

	if lm == nil {
		return ErrLeaseManagerNotConfigured
	}

	allocReq := &AllocationRequest{
		MAC:         req.ClientMAC,
		ClientID:    req.ClientID,
		Hostname:    req.Hostname,
		RequestedIP: ip,
		PoolName:    poolName,
	}

	_, err := lm.AllocateLease(ctx, allocReq)
	return err
}

func (h *RequestHandler) getLease(ctx context.Context, mac net.HardwareAddr) (*LeaseInfo, error) {
	h.mu.RLock()
	lm := h.leaseManager
	h.mu.RUnlock()

	if lm == nil {
		return nil, ErrLeaseManagerNotConfigured
	}

	return lm.GetLeaseByMAC(ctx, mac)
}

func (h *RequestHandler) renewLease(ctx context.Context, lease *LeaseInfo) error {
	h.mu.RLock()
	lm := h.leaseManager
	h.mu.RUnlock()

	if lm == nil {
		return ErrLeaseManagerNotConfigured
	}

	allocReq := &AllocationRequest{
		MAC:         lease.MAC,
		RequestedIP: lease.IP,
		PoolName:    lease.PoolName,
	}

	_, err := lm.AllocateLease(ctx, allocReq)
	return err
}

func (h *RequestHandler) validateLeaseForRenewal(_ context.Context, lease *LeaseInfo, req *RequestInfo) error {
	// Check lease not expired
	if time.Now().After(lease.ExpiresAt) {
		return ErrLeaseExpired
	}

	// Check MAC matches
	if lease.MAC.String() != req.ClientMAC.String() {
		return ErrMACMismatch
	}

	return nil
}

// ============================================================================
// Pool Operations
// ============================================================================

func (h *RequestHandler) getPool(_ string) *PoolInfo {
	h.mu.RLock()
	pm := h.poolManager
	h.mu.RUnlock()

	if pm == nil {
		return nil
	}

	return pm.GetDefaultPool()
}

func (h *RequestHandler) getPoolForIP(_ net.IP) *PoolInfo {
	h.mu.RLock()
	pm := h.poolManager
	h.mu.RUnlock()

	if pm == nil {
		return nil
	}

	// Check if IP is in any managed pool
	return pm.GetDefaultPool()
}

// ============================================================================
// Offer Tracking
// ============================================================================

// RegisterOffer registers a pending OFFER for tracking.
func (h *RequestHandler) RegisterOffer(mac net.HardwareAddr, ip net.IP, poolName string) {
	h.offerMu.Lock()
	defer h.offerMu.Unlock()

	h.pendingOffers[mac.String()] = &PendingOffer{
		OfferedIP: ip,
		ClientMAC: mac,
		PoolName:  poolName,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(h.config.OfferValidityWindow),
	}
}

func (h *RequestHandler) getPendingOffer(mac net.HardwareAddr) *PendingOffer {
	h.offerMu.RLock()
	defer h.offerMu.RUnlock()
	return h.pendingOffers[mac.String()]
}

func (h *RequestHandler) removePendingOffer(mac net.HardwareAddr) {
	h.offerMu.Lock()
	defer h.offerMu.Unlock()
	delete(h.pendingOffers, mac.String())
}

// CleanupExpiredOffers removes expired pending offers.
func (h *RequestHandler) CleanupExpiredOffers() int {
	h.offerMu.Lock()
	defer h.offerMu.Unlock()

	now := time.Now()
	removed := 0

	for key, offer := range h.pendingOffers {
		if now.After(offer.ExpiresAt) {
			delete(h.pendingOffers, key)
			removed++
		}
	}

	return removed
}

// ============================================================================
// DNS Update
// ============================================================================

func (h *RequestHandler) triggerDNSUpdate(ctx context.Context, req *RequestInfo, result *RequestResult) {
	h.mu.RLock()
	dns := h.dnsUpdater
	h.mu.RUnlock()

	if dns == nil {
		return
	}

	dnsCtx, cancel := context.WithTimeout(ctx, h.config.DNSUpdateTimeout)
	defer cancel()

	err := dns.UpdateDNS(dnsCtx, req.Hostname, result.AllocatedIP, req.ClientMAC, result.LeaseTime)
	if err != nil {
		h.stats.DNSFailures++
	} else {
		h.stats.DNSUpdates++
	}
}

// ============================================================================
// Validation
// ============================================================================

func (h *RequestHandler) validateRequest(req *RequestInfo) error {
	if req == nil {
		return ErrNilRequest
	}

	if len(req.ClientMAC) == 0 {
		return ErrMissingMAC
	}

	if req.TransactionID == 0 {
		return ErrMissingTransactionID
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns REQUEST handler statistics.
func (h *RequestHandler) GetStats() RequestStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GetACKRate returns the ACK rate percentage.
func (h *RequestHandler) GetACKRate() float64 {
	total := h.stats.ACKsSent + h.stats.NAKsSent
	if total == 0 {
		return 0
	}
	return float64(h.stats.ACKsSent) / float64(total) * 100
}

// GetAverageProcessingTime returns average processing time in milliseconds.
func (h *RequestHandler) GetAverageProcessingTime() float64 {
	if h.stats.TotalReceived == 0 {
		return 0
	}
	return float64(h.stats.ProcessingTimeMs) / float64(h.stats.TotalReceived)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNoPendingOffer is returned when no OFFER found for client
	ErrNoPendingOffer = errors.New("no pending OFFER for this client")

	// ErrOfferExpired is returned when OFFER validity window passed
	ErrOfferExpired = errors.New("OFFER has expired")

	// ErrRequestedIPMismatch is returned when requested IP doesn't match OFFER
	ErrRequestedIPMismatch = errors.New("requested IP does not match offered IP")

	// ErrCIAddrMismatch is returned when ciaddr doesn't match lease
	ErrCIAddrMismatch = errors.New("ciaddr does not match lease record")

	// ErrLeaseNotFound is returned when no lease found for client
	ErrLeaseNotFound = errors.New("no active lease found for client")

	// ErrLeaseExpired is returned when lease has expired
	ErrLeaseExpired = errors.New("lease has expired")

	// ErrMACMismatch is returned when MAC addresses don't match
	ErrMACMismatch = errors.New("MAC address mismatch")

	// ErrIPNotManaged is returned when IP not in managed pools
	ErrIPNotManaged = errors.New("IP address not managed by this server")

	// ErrLeaseManagerNotConfigured is returned when lease manager not set
	ErrLeaseManagerNotConfigured = errors.New("lease manager not configured")
)
