// Package lease_manager handles DHCP lease lifecycle operations.
// This file implements the DHCP RELEASE message handler.
package lease_manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Release Handler Configuration
// ============================================================================

// ReleaseConfig holds release handler settings.
type ReleaseConfig struct {
	Timeout     time.Duration
	DNSCleanup  bool
	DNSTimeout  time.Duration
	DNSRetries  int
	LogReleases bool
}

// DefaultReleaseConfig returns sensible defaults.
func DefaultReleaseConfig() *ReleaseConfig {
	return &ReleaseConfig{
		Timeout:     10 * time.Second,
		DNSCleanup:  true,
		DNSTimeout:  5 * time.Second,
		DNSRetries:  2,
		LogReleases: true,
	}
}

// ============================================================================
// Release Request/Response
// ============================================================================

// ReleaseRequest contains information for lease release.
type ReleaseRequest struct {
	MAC           net.HardwareAddr
	ClientIP      net.IP
	ClientID      string
	TransactionID uint32
	VendorClass   string
}

// ReleaseResult contains the release outcome.
type ReleaseResult struct {
	Success       bool
	IP            net.IP
	Hostname      string
	LeaseDuration time.Duration
	DNSCleaned    bool
	ReleasedAt    time.Time
	Error         error
}

// ============================================================================
// Release Handler
// ============================================================================

// ReleaseHandler processes DHCP RELEASE messages.
type ReleaseHandler struct {
	mu     sync.RWMutex
	config *ReleaseConfig

	// DNS integration callback
	dnsCleanupFunc func(ctx context.Context, hostname string, ip net.IP) error

	// Statistics
	stats ReleaseStats
}

// ReleaseStats tracks release metrics.
type ReleaseStats struct {
	TotalReleases      int64
	SuccessfulReleases int64
	FailedReleases     int64
	DuplicateReleases  int64
	DNSCleanupFailures int64
}

// NewReleaseHandler creates a new release handler.
func NewReleaseHandler(config *ReleaseConfig) *ReleaseHandler {
	if config == nil {
		config = DefaultReleaseConfig()
	}

	return &ReleaseHandler{
		config: config,
	}
}

// SetDNSCleanupFunc sets the DNS cleanup callback.
func (h *ReleaseHandler) SetDNSCleanupFunc(fn func(ctx context.Context, hostname string, ip net.IP) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dnsCleanupFunc = fn
}

// ============================================================================
// Main Release Processing
// ============================================================================

// HandleRelease processes a DHCP RELEASE request.
func (h *ReleaseHandler) HandleRelease(ctx context.Context, req *ReleaseRequest, lease *LeaseRecord) (*ReleaseResult, error) {
	ctx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	h.mu.Lock()
	h.stats.TotalReleases++
	h.mu.Unlock()

	result := &ReleaseResult{
		ReleasedAt: time.Now(),
	}

	// Validate request
	if err := h.validateReleaseRequest(req); err != nil {
		h.recordFailure()
		result.Error = err
		return result, err
	}

	// Validate lease
	if lease == nil {
		h.recordFailure()
		result.Error = ErrLeaseNotFound
		return result, ErrLeaseNotFound
	}

	// Check lease state
	switch lease.State {
	case StateExpired:
		h.recordFailure()
		result.Error = ErrLeaseAlreadyExpired
		return result, ErrLeaseAlreadyExpired

	case StateBound, StateRenewing, StateRebinding:
		// Valid states for release, proceed

	default:
		// Already released - idempotent handling
		h.stats.DuplicateReleases++
		result.Success = true
		result.IP = lease.IP
		result.Hostname = lease.Hostname
		return result, nil
	}

	// Verify ownership
	if err := h.verifyOwnership(req, lease); err != nil {
		h.recordFailure()
		result.Error = err
		return result, err
	}

	// Calculate lease duration
	leaseDuration := time.Since(lease.LeaseStart)

	// Update lease state to RELEASED
	lease.State = StateExpired // Using expired state for released
	lease.LastRenewed = time.Now()

	// Perform DNS cleanup if enabled
	if h.config.DNSCleanup && lease.Hostname != "" {
		if err := h.cleanupDNSRecords(ctx, lease); err != nil {
			h.stats.DNSCleanupFailures++
			// Log but don't fail - DNS cleanup is best-effort
		} else {
			result.DNSCleaned = true
		}
	}

	// Log the release
	if h.config.LogReleases {
		h.logRelease(lease, leaseDuration)
	}

	h.recordSuccess()

	result.Success = true
	result.IP = lease.IP
	result.Hostname = lease.Hostname
	result.LeaseDuration = leaseDuration

	return result, nil
}

// ============================================================================
// Validation
// ============================================================================

func (h *ReleaseHandler) validateReleaseRequest(req *ReleaseRequest) error {
	if req == nil {
		return errors.New("release request is nil")
	}

	if len(req.MAC) == 0 {
		return ErrInvalidMACAddress
	}

	// MAC should not be all zeros
	allZero := true
	for _, b := range req.MAC {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ErrInvalidMACAddress
	}

	return nil
}

func (h *ReleaseHandler) verifyOwnership(req *ReleaseRequest, lease *LeaseRecord) error {
	// Verify MAC matches
	if req.MAC.String() != lease.MAC.String() {
		return ErrOwnershipMismatch
	}

	// If client IP is provided, verify it matches (log warning if mismatch)
	if req.ClientIP != nil && !req.ClientIP.Equal(lease.IP) {
		// Log warning but proceed with database record
		// Client may have stale IP info
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
// DNS Cleanup
// ============================================================================

func (h *ReleaseHandler) cleanupDNSRecords(ctx context.Context, lease *LeaseRecord) error {
	h.mu.RLock()
	cleanupFn := h.dnsCleanupFunc
	h.mu.RUnlock()

	if cleanupFn == nil {
		return nil
	}

	dnsCtx, cancel := context.WithTimeout(ctx, h.config.DNSTimeout)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt <= h.config.DNSRetries; attempt++ {
		if err := cleanupFn(dnsCtx, lease.Hostname, lease.IP); err != nil {
			lastErr = err
			// Exponential backoff
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
			continue
		}
		return nil
	}

	return lastErr
}

// ============================================================================
// Logging
// ============================================================================

func (h *ReleaseHandler) logRelease(lease *LeaseRecord, duration time.Duration) {
	// Calculate utilization
	var utilization float64
	if lease.OriginalLease > 0 {
		utilization = float64(duration) / float64(lease.OriginalLease) * 100
	}

	_ = map[string]interface{}{
		"event":           "lease_released",
		"mac_address":     lease.MAC.String(),
		"ip_address":      lease.IP.String(),
		"hostname":        lease.Hostname,
		"pool_name":       lease.PoolName,
		"lease_duration":  duration.String(),
		"utilization_pct": utilization,
		"released_at":     time.Now().Format(time.RFC3339),
	}

	// Logger would be called here
}

// ============================================================================
// Statistics
// ============================================================================

func (h *ReleaseHandler) recordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stats.SuccessfulReleases++
}

func (h *ReleaseHandler) recordFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stats.FailedReleases++
}

// GetStats returns release statistics.
func (h *ReleaseHandler) GetStats() ReleaseStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GetSuccessRate returns the release success rate.
func (h *ReleaseHandler) GetSuccessRate() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.stats.TotalReleases == 0 {
		return 0
	}
	return float64(h.stats.SuccessfulReleases) / float64(h.stats.TotalReleases) * 100
}

// ============================================================================
// Helper Functions
// ============================================================================

// ExtractMACFromPacket extracts MAC address from chaddr field.
func ExtractMACFromPacket(chaddr []byte) (net.HardwareAddr, error) {
	if len(chaddr) < 6 {
		return nil, ErrInvalidMACAddress
	}
	return net.HardwareAddr(chaddr[:6]), nil
}

// ExtractIPFromPacket extracts IP address from ciaddr field.
func ExtractIPFromPacket(ciaddr []byte) (net.IP, error) {
	if len(ciaddr) < 4 {
		return nil, errors.New("invalid IP address")
	}
	ip := net.IP(ciaddr[:4])
	if ip.IsUnspecified() {
		return nil, errors.New("IP address is 0.0.0.0")
	}
	return ip, nil
}

// IPToReverseDNS converts an IP address to reverse DNS format.
func IPToReverseDNS(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}

	// Reverse the octets and append in-addr.arpa
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
		ip4[3], ip4[2], ip4[1], ip4[0])
}

// NormalizeMACAddress converts MAC to lowercase colon-separated format.
func NormalizeMACAddress(mac string) string {
	mac = strings.ReplaceAll(mac, "-", ":")
	return strings.ToLower(mac)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrInvalidMACAddress is returned for malformed MAC
	ErrInvalidMACAddress = errors.New("invalid MAC address")

	// ErrLeaseAlreadyExpired is returned when releasing expired lease
	ErrLeaseAlreadyExpired = errors.New("lease already expired")

	// ErrLeaseAlreadyReleased is returned for duplicate release
	ErrLeaseAlreadyReleased = errors.New("lease already released")
)
