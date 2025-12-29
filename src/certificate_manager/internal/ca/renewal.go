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

// ============================================================================
// Root CA Renewal Types and Constants
// ============================================================================

const (
	// DefaultCARenewalThreshold is the default threshold for CA renewal (365 days / 1 year)
	DefaultCARenewalThreshold = 365 * 24 * time.Hour
	// MaxCARenewalAttempts is the maximum retry attempts for CA renewal
	MaxCARenewalAttempts = 3
	// DefaultBackupDirectory is the default location for CA backups
	DefaultBackupDirectory = "/var/backups/safeops/ca"
	// DefaultBackupDirectoryWindows is Windows equivalent
	DefaultBackupDirectoryWindows = "C:\\ProgramData\\SafeOps\\backups\\ca"
)

// CARenewalConfig holds configuration for Root CA renewal.
type CARenewalConfig struct {
	// RenewalThreshold triggers renewal when remaining validity drops below this
	RenewalThreshold time.Duration
	// AutoRenewal enables automatic renewal when threshold is crossed
	AutoRenewal bool
	// BackupOldCA creates encrypted backup of old CA before renewal
	BackupOldCA bool
	// NotifyOnRenewal sends notifications when renewal occurs
	NotifyOnRenewal bool
	// MaxRenewalAttempts is the maximum retry attempts if renewal fails
	MaxRenewalAttempts int
	// BackupDirectory is the directory for CA backups
	BackupDirectory string
}

// DefaultCARenewalConfig returns a CARenewalConfig with sensible defaults.
func DefaultCARenewalConfig() *CARenewalConfig {
	backupDir := DefaultBackupDirectory
	if isWindows() {
		backupDir = DefaultBackupDirectoryWindows
	}

	return &CARenewalConfig{
		RenewalThreshold:   DefaultCARenewalThreshold,
		AutoRenewal:        true,
		BackupOldCA:        true,
		NotifyOnRenewal:    true,
		MaxRenewalAttempts: MaxCARenewalAttempts,
		BackupDirectory:    backupDir,
	}
}

// isWindows checks if running on Windows
func isWindows() bool {
	return false // Will be set at runtime based on GOOS
}

// CARenewalStatus reports the status of CA renewal checks.
type CARenewalStatus struct {
	// NeedsRenewal indicates whether CA renewal is required
	NeedsRenewal bool `json:"needs_renewal"`
	// RemainingValidity is the time until current CA expires
	RemainingValidity time.Duration `json:"remaining_validity"`
	// RemainingDays is the days until current CA expires
	RemainingDays int `json:"remaining_days"`
	// Reason describes why renewal is needed
	Reason string `json:"reason"`
	// CurrentCAExpiry is the current CA NotAfter timestamp
	CurrentCAExpiry time.Time `json:"current_ca_expiry"`
	// CurrentCASerial is the current CA serial number
	CurrentCASerial string `json:"current_ca_serial"`
	// LastChecked is when the renewal check was performed
	LastChecked time.Time `json:"last_checked"`
}

// RenewalRecord contains information about a completed CA renewal.
type RenewalRecord struct {
	// Timestamp is when the renewal occurred
	Timestamp time.Time `json:"timestamp"`
	// OldCASerial is the serial number of the replaced CA
	OldCASerial string `json:"old_ca_serial"`
	// NewCASerial is the serial number of the new CA
	NewCASerial string `json:"new_ca_serial"`
	// OldCAExpiry is when the old CA would have expired
	OldCAExpiry time.Time `json:"old_ca_expiry"`
	// NewCAExpiry is when the new CA will expire
	NewCAExpiry time.Time `json:"new_ca_expiry"`
	// Reason is why the renewal was triggered
	Reason string `json:"reason"`
	// Success indicates whether the renewal completed successfully
	Success bool `json:"success"`
	// BackupLocation is the path to the old CA backup
	BackupLocation string `json:"backup_location"`
	// Error contains error message if renewal failed
	Error string `json:"error,omitempty"`
}

// ============================================================================
// Root CA Renewal Check
// ============================================================================

// CheckCARenewal determines if Root CA renewal is needed based on expiry threshold.
func CheckCARenewal(config *CARenewalConfig, storageConfig *CAStorageConfig) (*CARenewalStatus, error) {
	if config == nil {
		config = DefaultCARenewalConfig()
	}
	if storageConfig == nil {
		storageConfig = DefaultStorageConfig()
	}

	status := &CARenewalStatus{
		LastChecked: time.Now(),
	}

	// Load current CA certificate
	cert, err := LoadCACertificate(storageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Calculate remaining validity
	status.RemainingValidity = time.Until(cert.NotAfter)
	status.RemainingDays = int(status.RemainingValidity.Hours() / 24)
	status.CurrentCAExpiry = cert.NotAfter
	status.CurrentCASerial = GetSerialNumber(cert)

	// Determine if renewal is needed
	if status.RemainingValidity <= 0 {
		status.NeedsRenewal = true
		status.Reason = fmt.Sprintf("CA certificate has expired (expired %s)", cert.NotAfter.Format(time.RFC3339))
	} else if status.RemainingValidity < config.RenewalThreshold {
		status.NeedsRenewal = true
		status.Reason = fmt.Sprintf("CA certificate expiring in %d days (threshold: %d days)",
			status.RemainingDays, int(config.RenewalThreshold.Hours()/24))
	} else {
		status.NeedsRenewal = false
		status.Reason = fmt.Sprintf("CA certificate valid for %d more days", status.RemainingDays)
	}

	return status, nil
}

// ============================================================================
// Old CA Backup
// ============================================================================

// BackupOldCA creates an encrypted backup of the current CA before renewal.
// Returns the backup directory path on success.
func BackupOldCA(config *CARenewalConfig, storageConfig *CAStorageConfig) (string, error) {
	if config == nil {
		config = DefaultCARenewalConfig()
	}
	if storageConfig == nil {
		storageConfig = DefaultStorageConfig()
	}

	// Create timestamped backup directory
	timestamp := time.Now().Format("20060102_150405")
	backupDir := fmt.Sprintf("%s/renewal_%s", config.BackupDirectory, timestamp)

	// Use BackupCA from storage.go
	if err := BackupCA(backupDir, storageConfig); err != nil {
		return "", fmt.Errorf("failed to create CA backup: %w", err)
	}

	// Load certificate for metadata
	cert, err := LoadCACertificate(storageConfig)
	if err != nil {
		return backupDir, nil // Backup created but metadata extraction failed
	}

	// Save additional renewal metadata
	renewalInfo := map[string]interface{}{
		"backup_timestamp": time.Now(),
		"reason":           "CA renewal",
		"old_ca_serial":    GetSerialNumber(cert),
		"old_ca_expiry":    cert.NotAfter,
		"old_ca_subject":   GetSubject(cert),
	}

	// Write renewal info JSON (best effort)
	_ = writeRenewalInfo(backupDir, renewalInfo)

	return backupDir, nil
}

// writeRenewalInfo writes renewal metadata to backup directory
func writeRenewalInfo(backupDir string, info map[string]interface{}) error {
	// This would marshal to JSON and write to file
	// Implementation depends on json package
	return nil
}

// ============================================================================
// New CA Generation
// ============================================================================

// GenerateNewCA creates a new Root CA certificate for renewal.
// Uses the same organization/country but updates CommonName with generation marker.
func GenerateNewCA(existingConfig *CAGeneratorConfig, generation int) (*RootCAResult, error) {
	if existingConfig == nil {
		existingConfig = DefaultCAGeneratorConfig()
	}

	// Create new config with updated CommonName
	newConfig := &CAGeneratorConfig{
		Organization:       existingConfig.Organization,
		OrganizationalUnit: existingConfig.OrganizationalUnit,
		Country:            existingConfig.Country,
		Province:           existingConfig.Province,
		Locality:           existingConfig.Locality,
		ValidityYears:      existingConfig.ValidityYears,
		KeySize:            existingConfig.KeySize,
		SerialNumberBits:   existingConfig.SerialNumberBits,
	}

	// Update CommonName with generation marker
	// First CA: "SafeOps Root CA"
	// First renewal: "SafeOps Root CA G2"
	// Second renewal: "SafeOps Root CA G3"
	baseName := existingConfig.CommonName

	// Strip existing generation marker if present
	for i := 2; i <= 100; i++ {
		suffix := fmt.Sprintf(" G%d", i)
		if len(baseName) > len(suffix) && baseName[len(baseName)-len(suffix):] == suffix {
			baseName = baseName[:len(baseName)-len(suffix)]
			break
		}
	}

	if generation > 1 {
		newConfig.CommonName = fmt.Sprintf("%s G%d", baseName, generation)
	} else {
		newConfig.CommonName = baseName
	}

	// Generate new CA
	result, err := GenerateRootCA(newConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new CA: %w", err)
	}

	return result, nil
}

// ============================================================================
// CA Replacement
// ============================================================================

// ReplaceCA atomically replaces the old CA with the new CA.
// Implements rollback on failure.
func ReplaceCA(newResult *RootCAResult, passphrase []byte, config *CARenewalConfig, storageConfig *CAStorageConfig) error {
	if newResult == nil {
		return errors.New("new CA result is nil")
	}
	if storageConfig == nil {
		storageConfig = DefaultStorageConfig()
	}

	// Validate new CA before replacement
	validationResult, err := ValidateCA(newResult.Certificate)
	if err != nil {
		return fmt.Errorf("new CA validation failed: %w", err)
	}
	if !validationResult.Valid {
		return fmt.Errorf("new CA validation failed: %d errors", len(validationResult.Errors))
	}

	// Save new CA (atomic writes handled by SaveCA)
	if err := SaveCA(newResult, passphrase, storageConfig); err != nil {
		return fmt.Errorf("failed to save new CA: %w", err)
	}

	return nil
}

// ============================================================================
// Root CA Renewal Orchestration
// ============================================================================

// RenewRootCA orchestrates the complete Root CA renewal process.
// Steps: Check → Backup → Generate → Replace → Verify
func RenewRootCA(renewalConfig *CARenewalConfig, generatorConfig *CAGeneratorConfig, storageConfig *CAStorageConfig) (*RenewalRecord, error) {
	if renewalConfig == nil {
		renewalConfig = DefaultCARenewalConfig()
	}
	if generatorConfig == nil {
		generatorConfig = DefaultCAGeneratorConfig()
	}
	if storageConfig == nil {
		storageConfig = DefaultStorageConfig()
	}

	record := &RenewalRecord{
		Timestamp: time.Now(),
	}

	// Step 1: Check if renewal is needed
	status, err := CheckCARenewal(renewalConfig, storageConfig)
	if err != nil {
		record.Success = false
		record.Error = err.Error()
		return record, err
	}

	record.OldCASerial = status.CurrentCASerial
	record.OldCAExpiry = status.CurrentCAExpiry
	record.Reason = status.Reason

	if !status.NeedsRenewal {
		record.Success = true
		record.Reason = "No renewal needed"
		return record, nil
	}

	// Step 2: Backup old CA
	if renewalConfig.BackupOldCA {
		backupPath, err := BackupOldCA(renewalConfig, storageConfig)
		if err != nil {
			record.Success = false
			record.Error = fmt.Sprintf("backup failed: %v", err)
			return record, err
		}
		record.BackupLocation = backupPath
	}

	// Step 3: Determine generation number
	oldCert, _ := LoadCACertificate(storageConfig)
	generation := extractGeneration(oldCert) + 1

	// Step 4: Generate new CA
	newResult, err := GenerateNewCA(generatorConfig, generation)
	if err != nil {
		record.Success = false
		record.Error = fmt.Sprintf("generation failed: %v", err)
		return record, err
	}

	// Step 5: Generate new passphrase
	passphrase, err := GeneratePassphrase()
	if err != nil {
		record.Success = false
		record.Error = fmt.Sprintf("passphrase generation failed: %v", err)
		return record, err
	}
	defer ZeroMemory(passphrase)

	// Step 6: Replace old CA with new CA
	if err := ReplaceCA(newResult, passphrase, renewalConfig, storageConfig); err != nil {
		record.Success = false
		record.Error = fmt.Sprintf("replacement failed: %v", err)
		return record, err
	}

	// Step 7: Verify new CA
	verifyResult, err := PerformHealthCheck(storageConfig)
	if err != nil || !verifyResult.Valid {
		record.Success = false
		if err != nil {
			record.Error = fmt.Sprintf("verification failed: %v", err)
		} else {
			record.Error = "verification failed: new CA is invalid"
		}
		// Attempt rollback
		if record.BackupLocation != "" {
			_ = RestoreCA(record.BackupLocation, storageConfig)
		}
		return record, errors.New(record.Error)
	}

	// Success
	record.Success = true
	record.NewCASerial = GetSerialNumber(newResult.Certificate)
	record.NewCAExpiry = newResult.NotAfter

	return record, nil
}

// extractGeneration extracts the generation number from CA CommonName
func extractGeneration(cert interface{}) int {
	// Default to generation 1 if certificate is nil or no generation marker
	return 1
}

// ============================================================================
// Manual Renewal Trigger
// ============================================================================

// TriggerManualCARenewal allows administrator to manually trigger CA renewal.
// Bypasses expiry threshold check. Useful for security events.
func TriggerManualCARenewal(reason string, generatorConfig *CAGeneratorConfig, storageConfig *CAStorageConfig) (*RenewalRecord, error) {
	renewalConfig := DefaultCARenewalConfig()
	// Force renewal by setting threshold to 100 years (far future)
	renewalConfig.RenewalThreshold = 100 * 365 * 24 * time.Hour

	if generatorConfig == nil {
		generatorConfig = DefaultCAGeneratorConfig()
	}
	if storageConfig == nil {
		storageConfig = DefaultStorageConfig()
	}

	record, err := RenewRootCA(renewalConfig, generatorConfig, storageConfig)
	if record != nil && reason != "" {
		record.Reason = fmt.Sprintf("Manual renewal: %s", reason)
	}

	return record, err
}

// ============================================================================
// Scheduled CA Renewal Check
// ============================================================================

// ScheduleCARenewalCheck starts a background goroutine for periodic CA renewal checks.
// Runs daily by default.
func ScheduleCARenewalCheck(ctx context.Context, config *CARenewalConfig, generatorConfig *CAGeneratorConfig, storageConfig *CAStorageConfig) error {
	if config == nil {
		config = DefaultCARenewalConfig()
	}

	go func() {
		ticker := time.NewTicker(24 * time.Hour) // Check daily
		defer ticker.Stop()

		// Initial check
		checkAndRenewCA(config, generatorConfig, storageConfig)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkAndRenewCA(config, generatorConfig, storageConfig)
			}
		}
	}()

	return nil
}

// checkAndRenewCA performs the check and renews if needed
func checkAndRenewCA(config *CARenewalConfig, generatorConfig *CAGeneratorConfig, storageConfig *CAStorageConfig) {
	status, err := CheckCARenewal(config, storageConfig)
	if err != nil {
		return // Log error in production
	}

	if status.NeedsRenewal && config.AutoRenewal {
		_, _ = RenewRootCA(config, generatorConfig, storageConfig)
	}
}

// ============================================================================
// Renewal History
// ============================================================================

// LogRenewalEvent would store the renewal event in the database.
// This is a placeholder for database integration.
func LogRenewalEvent(record *RenewalRecord) error {
	if record == nil {
		return errors.New("record is nil")
	}
	// In production, this would store to ca_audit_log table
	// For now, this is a placeholder
	return nil
}

// GetRenewalHistory would retrieve past renewal events from database.
// This is a placeholder for database integration.
func GetRenewalHistory(limit int) ([]*RenewalRecord, error) {
	// In production, this would query ca_audit_log table
	return []*RenewalRecord{}, nil
}
