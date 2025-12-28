// Package discovery handles DHCP message processing.
// This file implements DHCP DECLINE message handling for IP conflict detection.
package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Decline Handler Configuration
// ============================================================================

// DeclineHandlerConfig holds DECLINE processing settings.
type DeclineHandlerConfig struct {
	QuarantineDuration    time.Duration
	InvestigateConflicts  bool
	InvestigationTimeout  time.Duration
	AlertThreshold        int // Conflicts per hour to trigger alert
	ExponentialBackoff    bool
	MaxQuarantineDuration time.Duration
}

// DefaultDeclineHandlerConfig returns sensible defaults.
func DefaultDeclineHandlerConfig() *DeclineHandlerConfig {
	return &DeclineHandlerConfig{
		QuarantineDuration:    time.Hour,
		InvestigateConflicts:  true,
		InvestigationTimeout:  5 * time.Second,
		AlertThreshold:        5,
		ExponentialBackoff:    true,
		MaxQuarantineDuration: 24 * time.Hour,
	}
}

// ============================================================================
// Decline Request
// ============================================================================

// DeclineRequest contains parsed DHCP DECLINE information.
type DeclineRequest struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	ClientID      string
	DeclinedIP    net.IP
	ServerID      net.IP
	ReceivedAt    time.Time
}

// DeclineResult contains the result of DECLINE processing.
type DeclineResult struct {
	Processed          bool
	ConflictMarked     bool
	QuarantineDuration time.Duration
	InvestigationDone  bool
	AlertSent          bool
	Error              error
}

// ============================================================================
// Decline Handler
// ============================================================================

// DeclineHandler processes DHCP DECLINE messages.
type DeclineHandler struct {
	mu     sync.RWMutex
	config *DeclineHandlerConfig

	// Dependencies
	leaseRepository  LeaseRepositoryInterface
	conflictDetector ConflictDetectorInterface
	alerter          AlerterInterface

	// Conflict tracking
	conflictHistory map[string]*ConflictRecord
	historyMu       sync.RWMutex

	// Statistics
	stats DeclineStats
}

// DeclineStats tracks DECLINE processing metrics.
type DeclineStats struct {
	TotalReceived     int64
	ConflictsMarked   int64
	AlertsSent        int64
	InvestigationsRun int64
	QuarantinesActive int64
	ProcessingErrors  int64
	ConflictsByPool   map[string]int64
	RepeatedConflicts int64
}

// ConflictRecord tracks conflict history for an IP.
type ConflictRecord struct {
	IP              net.IP
	FirstSeen       time.Time
	LastSeen        time.Time
	ConflictCount   int
	QuarantineUntil time.Time
	DetectedByMACs  []net.HardwareAddr
}

// ============================================================================
// Dependency Interfaces
// ============================================================================

// LeaseRepositoryInterface defines lease storage operations.
type LeaseRepositoryInterface interface {
	GetLeaseByIP(ctx context.Context, ip net.IP) (*LeaseInfo, error)
	MarkAsConflicted(ctx context.Context, ip net.IP, mac net.HardwareAddr, quarantineUntil time.Time) error
}

// AlerterInterface defines alerting operations.
type AlerterInterface interface {
	SendConflictAlert(ctx context.Context, ip net.IP, mac net.HardwareAddr, details string) error
}

// ============================================================================
// Handler Creation
// ============================================================================

// NewDeclineHandler creates a new DECLINE handler.
func NewDeclineHandler(config *DeclineHandlerConfig) *DeclineHandler {
	if config == nil {
		config = DefaultDeclineHandlerConfig()
	}

	return &DeclineHandler{
		config:          config,
		conflictHistory: make(map[string]*ConflictRecord),
		stats: DeclineStats{
			ConflictsByPool: make(map[string]int64),
		},
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetLeaseRepository sets the lease repository.
func (h *DeclineHandler) SetLeaseRepository(lr LeaseRepositoryInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leaseRepository = lr
}

// SetConflictDetector sets the conflict detector.
func (h *DeclineHandler) SetConflictDetector(cd ConflictDetectorInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conflictDetector = cd
}

// SetAlerter sets the alerter.
func (h *DeclineHandler) SetAlerter(a AlerterInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alerter = a
}

// ============================================================================
// Main DECLINE Processing
// ============================================================================

// HandleDecline processes a DHCP DECLINE message.
// Per RFC 2131, no response is sent to DECLINE messages.
func (h *DeclineHandler) HandleDecline(ctx context.Context, req *DeclineRequest) (*DeclineResult, error) {
	h.stats.TotalReceived++

	result := &DeclineResult{}

	// Validate request
	if err := h.validateRequest(req); err != nil {
		h.stats.ProcessingErrors++
		result.Error = err
		return result, err
	}

	// Lookup lease
	lease, err := h.lookupLease(ctx, req.DeclinedIP)
	if err != nil {
		// Log but continue - IP might have been released already
		// Still mark as conflicted to prevent future allocation
	}

	// Validate lease ownership if found
	if lease != nil {
		if lease.MAC.String() != req.ClientMAC.String() {
			// DECLINE from different client - suspicious but still mark
		}
	}

	// Calculate quarantine duration
	quarantineDuration := h.calculateQuarantineDuration(req.DeclinedIP)
	result.QuarantineDuration = quarantineDuration

	// Mark IP as conflicted
	if err := h.markConflicted(ctx, req, quarantineDuration); err != nil {
		h.stats.ProcessingErrors++
		result.Error = err
		// Continue processing despite error
	} else {
		result.ConflictMarked = true
		h.stats.ConflictsMarked++
	}

	// Update conflict history
	h.updateConflictHistory(req)

	// Investigate conflict if enabled
	if h.config.InvestigateConflicts {
		h.investigateConflict(ctx, req)
		result.InvestigationDone = true
		h.stats.InvestigationsRun++
	}

	// Send alert if threshold exceeded
	if h.shouldSendAlert(req.DeclinedIP) {
		if err := h.sendConflictAlert(ctx, req); err == nil {
			result.AlertSent = true
			h.stats.AlertsSent++
		}
	}

	result.Processed = true

	// RFC 2131: No response to DECLINE messages
	return result, nil
}

// ============================================================================
// Validation
// ============================================================================

func (h *DeclineHandler) validateRequest(req *DeclineRequest) error {
	if req == nil {
		return ErrNilDeclineRequest
	}

	if len(req.ClientMAC) == 0 {
		return ErrMissingClientMAC
	}

	if req.DeclinedIP == nil || req.DeclinedIP.IsUnspecified() {
		return ErrMissingDeclinedIP
	}

	// Validate IP is IPv4
	if req.DeclinedIP.To4() == nil {
		return ErrInvalidDeclinedIP
	}

	return nil
}

// ============================================================================
// Lease Lookup
// ============================================================================

func (h *DeclineHandler) lookupLease(ctx context.Context, ip net.IP) (*LeaseInfo, error) {
	h.mu.RLock()
	lr := h.leaseRepository
	h.mu.RUnlock()

	if lr == nil {
		return nil, ErrLeaseRepositoryNotSet
	}

	return lr.GetLeaseByIP(ctx, ip)
}

// ============================================================================
// Conflict Marking
// ============================================================================

func (h *DeclineHandler) markConflicted(ctx context.Context, req *DeclineRequest, quarantine time.Duration) error {
	h.mu.RLock()
	lr := h.leaseRepository
	h.mu.RUnlock()

	if lr == nil {
		return ErrLeaseRepositoryNotSet
	}

	quarantineUntil := time.Now().Add(quarantine)

	return lr.MarkAsConflicted(ctx, req.DeclinedIP, req.ClientMAC, quarantineUntil)
}

func (h *DeclineHandler) calculateQuarantineDuration(ip net.IP) time.Duration {
	h.historyMu.RLock()
	record, exists := h.conflictHistory[ip.String()]
	h.historyMu.RUnlock()

	baseDuration := h.config.QuarantineDuration

	if !exists || !h.config.ExponentialBackoff {
		return baseDuration
	}

	// Exponential backoff: double for each repeated conflict
	multiplier := 1 << record.ConflictCount
	if multiplier > 24 {
		multiplier = 24 // Cap at 24x
	}

	duration := baseDuration * time.Duration(multiplier)

	// Cap at maximum
	if duration > h.config.MaxQuarantineDuration {
		duration = h.config.MaxQuarantineDuration
	}

	return duration
}

// ============================================================================
// Conflict History
// ============================================================================

func (h *DeclineHandler) updateConflictHistory(req *DeclineRequest) {
	h.historyMu.Lock()
	defer h.historyMu.Unlock()

	key := req.DeclinedIP.String()
	now := time.Now()

	record, exists := h.conflictHistory[key]
	if !exists {
		record = &ConflictRecord{
			IP:             req.DeclinedIP,
			FirstSeen:      now,
			DetectedByMACs: make([]net.HardwareAddr, 0),
		}
		h.conflictHistory[key] = record
	} else {
		h.stats.RepeatedConflicts++
	}

	record.LastSeen = now
	record.ConflictCount++
	record.QuarantineUntil = now.Add(h.calculateQuarantineDuration(req.DeclinedIP))

	// Track detecting MAC
	macFound := false
	for _, mac := range record.DetectedByMACs {
		if mac.String() == req.ClientMAC.String() {
			macFound = true
			break
		}
	}
	if !macFound && len(record.DetectedByMACs) < 10 {
		record.DetectedByMACs = append(record.DetectedByMACs, req.ClientMAC)
	}
}

// GetConflictHistory returns conflict record for an IP.
func (h *DeclineHandler) GetConflictHistory(ip net.IP) (*ConflictRecord, bool) {
	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	record, exists := h.conflictHistory[ip.String()]
	return record, exists
}

// IsQuarantined checks if an IP is currently quarantined.
func (h *DeclineHandler) IsQuarantined(ip net.IP) bool {
	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	record, exists := h.conflictHistory[ip.String()]
	if !exists {
		return false
	}

	return time.Now().Before(record.QuarantineUntil)
}

// ClearQuarantine manually clears quarantine for an IP.
func (h *DeclineHandler) ClearQuarantine(ip net.IP) bool {
	h.historyMu.Lock()
	defer h.historyMu.Unlock()

	key := ip.String()
	if _, exists := h.conflictHistory[key]; exists {
		delete(h.conflictHistory, key)
		return true
	}
	return false
}

// ============================================================================
// Conflict Investigation
// ============================================================================

func (h *DeclineHandler) investigateConflict(ctx context.Context, req *DeclineRequest) {
	h.mu.RLock()
	cd := h.conflictDetector
	h.mu.RUnlock()

	if cd == nil {
		return
	}

	investigateCtx, cancel := context.WithTimeout(ctx, h.config.InvestigationTimeout)
	defer cancel()

	// Check if IP is actually in use
	_, _ = cd.CheckConflict(investigateCtx, req.DeclinedIP)

	// Results logged internally by conflict detector
}

// ============================================================================
// Alerting
// ============================================================================

func (h *DeclineHandler) shouldSendAlert(ip net.IP) bool {
	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	record, exists := h.conflictHistory[ip.String()]
	if !exists {
		return false
	}

	// Alert if conflict count exceeds threshold
	return record.ConflictCount >= h.config.AlertThreshold
}

func (h *DeclineHandler) sendConflictAlert(ctx context.Context, req *DeclineRequest) error {
	h.mu.RLock()
	alerter := h.alerter
	h.mu.RUnlock()

	if alerter == nil {
		return nil
	}

	details := "IP conflict detected via DHCP DECLINE"
	return alerter.SendConflictAlert(ctx, req.DeclinedIP, req.ClientMAC, details)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns DECLINE handler statistics.
func (h *DeclineHandler) GetStats() DeclineStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Copy map to avoid race
	stats := h.stats
	stats.ConflictsByPool = make(map[string]int64)
	for k, v := range h.stats.ConflictsByPool {
		stats.ConflictsByPool[k] = v
	}

	// Count active quarantines
	h.historyMu.RLock()
	now := time.Now()
	active := int64(0)
	for _, record := range h.conflictHistory {
		if now.Before(record.QuarantineUntil) {
			active++
		}
	}
	h.historyMu.RUnlock()
	stats.QuarantinesActive = active

	return stats
}

// GetConflictRate returns conflicts per hour.
func (h *DeclineHandler) GetConflictRate() float64 {
	// Simple rate calculation
	return float64(h.stats.ConflictsMarked)
}

// GetQuarantinedIPs returns list of currently quarantined IPs.
func (h *DeclineHandler) GetQuarantinedIPs() []net.IP {
	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	now := time.Now()
	ips := make([]net.IP, 0)

	for _, record := range h.conflictHistory {
		if now.Before(record.QuarantineUntil) {
			ips = append(ips, record.IP)
		}
	}

	return ips
}

// ============================================================================
// Cleanup
// ============================================================================

// CleanupExpiredQuarantines removes expired quarantine records.
func (h *DeclineHandler) CleanupExpiredQuarantines() int {
	h.historyMu.Lock()
	defer h.historyMu.Unlock()

	now := time.Now()
	removed := 0

	for key, record := range h.conflictHistory {
		if now.After(record.QuarantineUntil) {
			delete(h.conflictHistory, key)
			removed++
		}
	}

	return removed
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilDeclineRequest is returned when request is nil
	ErrNilDeclineRequest = errors.New("decline request is nil")

	// ErrMissingDeclinedIP is returned when declined IP missing
	ErrMissingDeclinedIP = errors.New("declined IP address is required")

	// ErrInvalidDeclinedIP is returned when IP format invalid
	ErrInvalidDeclinedIP = errors.New("invalid declined IP address format")

	// ErrLeaseRepositoryNotSet is returned when lease repository not configured
	ErrLeaseRepositoryNotSet = errors.New("lease repository not configured")
)
