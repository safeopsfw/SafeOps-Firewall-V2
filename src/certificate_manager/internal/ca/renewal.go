// Package ca implements automatic certificate renewal scheduling.
package ca

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultCheckInterval      = 24 * time.Hour
	DefaultRenewalThreshold   = 30 // Days before expiry
	DefaultConcurrentRenewals = 5
	DefaultRetryBackoff       = time.Hour
	GracefulShutdownTimeout   = 30 * time.Second
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrSchedulerAlreadyRunning = errors.New("renewal scheduler is already running")
	ErrSchedulerNotRunning     = errors.New("renewal scheduler is not running")
	ErrRenewalFailed           = errors.New("certificate renewal failed")
	ErrDistributionFailed      = errors.New("certificate distribution failed")
)

// ============================================================================
// Renewal Scheduler Structure
// ============================================================================

// RenewalScheduler manages automatic certificate renewal
type RenewalScheduler struct {
	certManager *CertificateManager
	config      RenewalConfig

	// Scheduling state
	ticker   *time.Ticker
	stopChan chan struct{}
	doneChan chan struct{}
	running  atomic.Bool

	// Concurrency control
	semaphore chan struct{}
	mu        sync.RWMutex

	// Metrics
	metrics *RenewalMetrics
}

// RenewalConfig holds scheduler configuration
type RenewalConfig struct {
	CheckInterval        time.Duration
	RenewalThresholdDays int
	ConcurrentRenewals   int
	RetryBackoff         time.Duration
	EnableAutoRenewal    bool
	RunImmediately       bool
}

// RenewalMetrics tracks renewal statistics
type RenewalMetrics struct {
	TotalManaged      int64     `json:"total_managed"`
	RenewalsAttempted int64     `json:"renewals_attempted"`
	RenewalsSucceeded int64     `json:"renewals_succeeded"`
	RenewalsFailed    int64     `json:"renewals_failed"`
	LastCheckTime     time.Time `json:"last_check_time"`
	LastRenewalTime   time.Time `json:"last_renewal_time"`
	NextCheckTime     time.Time `json:"next_check_time"`
	mu                sync.RWMutex
}

// RenewalResult contains outcome of individual renewal
type RenewalResult struct {
	Domain      string
	Success     bool
	OldExpiry   time.Time
	NewExpiry   time.Time
	Error       string
	ProcessedAt time.Time
}

// RenewalStatus reports scheduler state
type RenewalStatus struct {
	Running              bool             `json:"running"`
	Enabled              bool             `json:"enabled"`
	Metrics              *RenewalMetrics  `json:"metrics"`
	ExpiringCertificates []CertExpiryInfo `json:"expiring_certificates"`
	RecentFailures       []RenewalResult  `json:"recent_failures"`
}

// CertExpiryInfo contains certificate expiration details
type CertExpiryInfo struct {
	Domain        string    `json:"domain"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	NeedsRenewal  bool      `json:"needs_renewal"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewRenewalScheduler creates a new renewal scheduler
func NewRenewalScheduler(certManager *CertificateManager, config RenewalConfig) (*RenewalScheduler, error) {
	if certManager == nil {
		return nil, errors.New("certificate manager is required")
	}

	// Apply defaults
	if config.CheckInterval <= 0 {
		config.CheckInterval = DefaultCheckInterval
	}
	if config.RenewalThresholdDays <= 0 {
		config.RenewalThresholdDays = DefaultRenewalThreshold
	}
	if config.ConcurrentRenewals <= 0 {
		config.ConcurrentRenewals = DefaultConcurrentRenewals
	}
	if config.RetryBackoff <= 0 {
		config.RetryBackoff = DefaultRetryBackoff
	}

	return &RenewalScheduler{
		certManager: certManager,
		config:      config,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		semaphore:   make(chan struct{}, config.ConcurrentRenewals),
		metrics:     &RenewalMetrics{},
	}, nil
}

// ============================================================================
// Scheduler Lifecycle
// ============================================================================

// Start begins the renewal scheduler in background
func (rs *RenewalScheduler) Start(ctx context.Context) error {
	if rs.running.Load() {
		return ErrSchedulerAlreadyRunning
	}

	if !rs.config.EnableAutoRenewal {
		return nil // Auto-renewal disabled
	}

	rs.running.Store(true)
	rs.ticker = time.NewTicker(rs.config.CheckInterval)
	rs.stopChan = make(chan struct{})
	rs.doneChan = make(chan struct{})

	// Update next check time
	rs.metrics.mu.Lock()
	rs.metrics.NextCheckTime = time.Now().Add(rs.config.CheckInterval)
	rs.metrics.mu.Unlock()

	go rs.run(ctx)

	// Optionally run immediately at startup
	if rs.config.RunImmediately {
		go func() {
			rs.CheckAndRenewCertificates(ctx)
		}()
	}

	return nil
}

// Stop gracefully shuts down the scheduler
func (rs *RenewalScheduler) Stop() error {
	if !rs.running.Load() {
		return ErrSchedulerNotRunning
	}

	// Signal stop
	close(rs.stopChan)

	// Wait for completion with timeout
	select {
	case <-rs.doneChan:
		// Clean shutdown
	case <-time.After(GracefulShutdownTimeout):
		// Force shutdown
	}

	if rs.ticker != nil {
		rs.ticker.Stop()
	}

	rs.running.Store(false)
	return nil
}

// IsRunning returns scheduler state
func (rs *RenewalScheduler) IsRunning() bool {
	return rs.running.Load()
}

// run is the main scheduler loop
func (rs *RenewalScheduler) run(ctx context.Context) {
	defer close(rs.doneChan)

	for {
		select {
		case <-ctx.Done():
			return
		case <-rs.stopChan:
			return
		case <-rs.ticker.C:
			rs.CheckAndRenewCertificates(ctx)

			// Update next check time
			rs.metrics.mu.Lock()
			rs.metrics.NextCheckTime = time.Now().Add(rs.config.CheckInterval)
			rs.metrics.mu.Unlock()
		}
	}
}

// ============================================================================
// Core Renewal Logic
// ============================================================================

// CheckAndRenewCertificates checks all certificates and renews expiring ones
func (rs *RenewalScheduler) CheckAndRenewCertificates(ctx context.Context) {
	rs.metrics.mu.Lock()
	rs.metrics.LastCheckTime = time.Now()
	rs.metrics.mu.Unlock()

	// Get certificates due for renewal
	expiringCerts, err := rs.certManager.GetExpiringCertificates(ctx, rs.config.RenewalThresholdDays)
	if err != nil {
		return
	}

	if len(expiringCerts) == 0 {
		return
	}

	rs.metrics.mu.Lock()
	rs.metrics.TotalManaged = int64(len(expiringCerts))
	rs.metrics.mu.Unlock()

	// Process renewals concurrently
	var wg sync.WaitGroup
	results := make(chan RenewalResult, len(expiringCerts))

	for _, cert := range expiringCerts {
		wg.Add(1)
		go func(c *types.Certificate) {
			defer wg.Done()

			// Acquire semaphore for rate limiting
			select {
			case rs.semaphore <- struct{}{}:
				defer func() { <-rs.semaphore }()
			case <-ctx.Done():
				return
			}

			result := rs.renewCertificate(ctx, c)
			results <- result
		}(cert)
	}

	// Wait for all renewals to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		if result.Success {
			atomic.AddInt64(&rs.metrics.RenewalsSucceeded, 1)
			rs.metrics.mu.Lock()
			rs.metrics.LastRenewalTime = result.ProcessedAt
			rs.metrics.mu.Unlock()
		} else {
			atomic.AddInt64(&rs.metrics.RenewalsFailed, 1)
		}
		atomic.AddInt64(&rs.metrics.RenewalsAttempted, 1)
	}
}

// renewCertificate handles individual certificate renewal
func (rs *RenewalScheduler) renewCertificate(ctx context.Context, cert *types.Certificate) RenewalResult {
	result := RenewalResult{
		Domain:      cert.CommonName,
		OldExpiry:   cert.NotAfter,
		ProcessedAt: time.Now(),
	}

	// Check if renewal is needed
	if !rs.shouldRenew(cert) {
		result.Success = true // No renewal needed
		return result
	}

	// Build domain list
	domains := []string{cert.CommonName}
	domains = append(domains, cert.SubjectAltNames...)

	// Request new certificate
	newCert, err := rs.certManager.IssueCertificate(ctx, domains)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		rs.handleRenewalFailure(cert, err)
		return result
	}

	// Verify new certificate has later expiry
	if !newCert.NotAfter.After(cert.NotAfter) {
		result.Success = false
		result.Error = "new certificate does not extend validity"
		return result
	}

	result.Success = true
	result.NewExpiry = newCert.NotAfter

	// Notify services if needed
	rs.notifyServicesOfRenewal(ctx, cert.CommonName, newCert)

	return result
}

// ============================================================================
// Decision Logic
// ============================================================================

// shouldRenew determines if certificate needs renewal
func (rs *RenewalScheduler) shouldRenew(cert *types.Certificate) bool {
	daysRemaining := rs.calculateDaysUntilExpiry(cert)

	// Already expired - definitely renew
	if daysRemaining <= 0 {
		return true
	}

	// Within renewal window
	return daysRemaining <= rs.config.RenewalThresholdDays
}

// calculateDaysUntilExpiry returns days until certificate expires
func (rs *RenewalScheduler) calculateDaysUntilExpiry(cert *types.Certificate) int {
	duration := time.Until(cert.NotAfter)
	days := int(duration.Hours() / 24)

	if days < 0 {
		return 0
	}
	return days
}

// ============================================================================
// Error Handling
// ============================================================================

// handleRenewalFailure processes renewal errors
func (rs *RenewalScheduler) handleRenewalFailure(cert *types.Certificate, err error) {
	// Log the failure
	// In production, this would trigger alerts for persistent failures

	// Check if error is rate limit related
	if isRateLimitError(err) {
		// Wait longer before next attempt
		// This would be handled by backing off the scheduler
	}
}

// isRateLimitError checks if error is from rate limiting
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsStr(errStr, "rate") && containsStr(errStr, "limit")
}

// containsStr checks if s contains substr (simple helper)
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && findSubstr(s, substr)
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// Service Notification
// ============================================================================

// notifyServicesOfRenewal triggers certificate distribution
func (rs *RenewalScheduler) notifyServicesOfRenewal(ctx context.Context, domain string, newCert *types.Certificate) {
	// This would call the distributor to push the new certificate
	// to all services that depend on it
	//
	// if rs.distributor != nil {
	//     rs.distributor.DistributeCertificate(ctx, domain, newCert)
	// }
}

// ============================================================================
// Status and Metrics
// ============================================================================

// GetRenewalStatus returns current scheduler status
func (rs *RenewalScheduler) GetRenewalStatus(ctx context.Context) (*RenewalStatus, error) {
	status := &RenewalStatus{
		Running: rs.running.Load(),
		Enabled: rs.config.EnableAutoRenewal,
		Metrics: rs.getMetricsSnapshot(),
	}

	// Get expiring certificates
	expiring, err := rs.certManager.GetExpiringCertificates(ctx, rs.config.RenewalThresholdDays+30)
	if err == nil {
		status.ExpiringCertificates = make([]CertExpiryInfo, len(expiring))
		for i, cert := range expiring {
			days := rs.calculateDaysUntilExpiry(cert)
			status.ExpiringCertificates[i] = CertExpiryInfo{
				Domain:        cert.CommonName,
				NotAfter:      cert.NotAfter,
				DaysRemaining: days,
				NeedsRenewal:  days <= rs.config.RenewalThresholdDays,
			}
		}
	}

	return status, nil
}

// getMetricsSnapshot returns copy of current metrics
func (rs *RenewalScheduler) getMetricsSnapshot() *RenewalMetrics {
	rs.metrics.mu.RLock()
	defer rs.metrics.mu.RUnlock()

	return &RenewalMetrics{
		TotalManaged:      rs.metrics.TotalManaged,
		RenewalsAttempted: rs.metrics.RenewalsAttempted,
		RenewalsSucceeded: rs.metrics.RenewalsSucceeded,
		RenewalsFailed:    rs.metrics.RenewalsFailed,
		LastCheckTime:     rs.metrics.LastCheckTime,
		LastRenewalTime:   rs.metrics.LastRenewalTime,
		NextCheckTime:     rs.metrics.NextCheckTime,
	}
}

// GetMetrics returns current renewal metrics
func (rs *RenewalScheduler) GetMetrics() *RenewalMetrics {
	return rs.getMetricsSnapshot()
}

// ============================================================================
// Manual Renewal Triggers
// ============================================================================

// RenewNow triggers immediate renewal for a specific domain
func (rs *RenewalScheduler) RenewNow(ctx context.Context, domain string) (*RenewalResult, error) {
	cert, err := rs.certManager.GetCertificate(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	result := rs.renewCertificate(ctx, cert)
	return &result, nil
}

// RenewAll triggers immediate renewal check for all certificates
func (rs *RenewalScheduler) RenewAll(ctx context.Context) {
	rs.CheckAndRenewCertificates(ctx)
}

// ============================================================================
// Configuration Updates
// ============================================================================

// UpdateConfig updates scheduler configuration
func (rs *RenewalScheduler) UpdateConfig(config RenewalConfig) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	wasRunning := rs.running.Load()

	// Stop if running
	if wasRunning {
		rs.Stop()
	}

	// Update configuration
	if config.CheckInterval > 0 {
		rs.config.CheckInterval = config.CheckInterval
	}
	if config.RenewalThresholdDays > 0 {
		rs.config.RenewalThresholdDays = config.RenewalThresholdDays
	}
	if config.ConcurrentRenewals > 0 {
		rs.config.ConcurrentRenewals = config.ConcurrentRenewals
		rs.semaphore = make(chan struct{}, config.ConcurrentRenewals)
	}
	rs.config.EnableAutoRenewal = config.EnableAutoRenewal

	// Restart if was running
	if wasRunning && config.EnableAutoRenewal {
		return rs.Start(context.Background())
	}

	return nil
}
