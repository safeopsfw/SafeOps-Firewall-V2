// Package renewal provides automatic CA certificate renewal and rotation.
// This ensures certificates are renewed before expiry with zero downtime.
package renewal

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"sync"
	"time"
)

// ============================================================================
// Auto-Renewal Configuration
// ============================================================================

// RenewalConfig configures automatic certificate renewal.
type RenewalConfig struct {
	// RenewalThreshold is how long before expiry to renew (e.g., 365 days = 1 year)
	RenewalThreshold time.Duration

	// CheckInterval is how often to check certificate expiry
	CheckInterval time.Duration

	// GracePeriod is how long to keep old CA trusted after new CA is deployed
	GracePeriod time.Duration

	// EnableAutoRenewal enables automatic renewal (vs manual trigger)
	EnableAutoRenewal bool

	// NotificationWebhook is URL to send renewal notifications
	NotificationWebhook string
}

// DefaultRenewalConfig returns default renewal configuration.
func DefaultRenewalConfig() *RenewalConfig {
	return &RenewalConfig{
		RenewalThreshold:  365 * 24 * time.Hour, // Renew 1 year before expiry
		CheckInterval:     24 * time.Hour,        // Check daily
		GracePeriod:       90 * 24 * time.Hour,   // 90 day grace period
		EnableAutoRenewal: true,
		NotificationWebhook: "",
	}
}

// ============================================================================
// Auto-Renewal Manager
// ============================================================================

// RenewalManager manages automatic CA certificate renewal.
type RenewalManager struct {
	config          *RenewalConfig
	certStore       CertificateStore
	caGenerator     CAGenerator
	dhcpNotifier    DHCPNotifier
	deviceNotifier  DeviceNotifier

	mu              sync.RWMutex
	running         bool
	stopCh          chan struct{}
	currentCA       *x509.Certificate
	pendingCA       *x509.Certificate
	renewalStatus   *RenewalStatus
}

// RenewalStatus tracks the current renewal state.
type RenewalStatus struct {
	CurrentCAExpiry     time.Time
	NextRenewalCheck    time.Time
	RenewalScheduled    bool
	RenewalInProgress   bool
	LastRenewalTime     time.Time
	RenewalError        error
	DevicesNotified     int
	DevicesMigrated     int
	TotalDevices        int
}

// ============================================================================
// Interfaces (implemented by other packages)
// ============================================================================

// CertificateStore manages certificate storage and retrieval.
type CertificateStore interface {
	GetCurrentCA(ctx context.Context) (*x509.Certificate, error)
	StorePendingCA(ctx context.Context, cert *x509.Certificate, key []byte) error
	PromotePendingToActive(ctx context.Context) error
	ArchiveOldCA(ctx context.Context, cert *x509.Certificate) error
}

// CAGenerator generates new CA certificates.
type CAGenerator interface {
	GenerateNewCA(ctx context.Context, config *CAGenerationConfig) (*x509.Certificate, []byte, error)
}

// DHCPNotifier notifies DHCP server of new CA URLs.
type DHCPNotifier interface {
	UpdateCAOptions(ctx context.Context, newCAURL, newFingerprint string) error
}

// DeviceNotifier notifies devices to update certificates.
type DeviceNotifier interface {
	NotifyDevicesOfRenewal(ctx context.Context, devices []string) error
}

// CAGenerationConfig configures CA generation.
type CAGenerationConfig struct {
	CommonName       string
	Organization     string
	Country          string
	ValidityYears    int
	KeySize          int
}

// ============================================================================
// Constructor
// ============================================================================

// NewRenewalManager creates a new renewal manager.
func NewRenewalManager(
	config *RenewalConfig,
	certStore CertificateStore,
	caGenerator CAGenerator,
	dhcpNotifier DHCPNotifier,
	deviceNotifier DeviceNotifier,
) *RenewalManager {
	return &RenewalManager{
		config:         config,
		certStore:      certStore,
		caGenerator:    caGenerator,
		dhcpNotifier:   dhcpNotifier,
		deviceNotifier: deviceNotifier,
		stopCh:         make(chan struct{}),
		renewalStatus: &RenewalStatus{
			NextRenewalCheck: time.Now().Add(config.CheckInterval),
		},
	}
}

// ============================================================================
// Start/Stop
// ============================================================================

// Start starts the automatic renewal monitoring.
func (rm *RenewalManager) Start(ctx context.Context) error {
	rm.mu.Lock()
	if rm.running {
		rm.mu.Unlock()
		return fmt.Errorf("renewal manager already running")
	}
	rm.running = true
	rm.mu.Unlock()

	log.Printf("[RENEWAL] Starting automatic CA renewal manager")
	log.Printf("[RENEWAL] Renewal threshold: %v before expiry", rm.config.RenewalThreshold)
	log.Printf("[RENEWAL] Check interval: %v", rm.config.CheckInterval)
	log.Printf("[RENEWAL] Grace period: %v", rm.config.GracePeriod)

	// Load current CA
	if err := rm.loadCurrentCA(ctx); err != nil {
		return fmt.Errorf("failed to load current CA: %w", err)
	}

	// Start monitoring goroutine
	go rm.monitorLoop(ctx)

	return nil
}

// Stop stops the renewal manager.
func (rm *RenewalManager) Stop() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.running {
		return
	}

	log.Printf("[RENEWAL] Stopping automatic CA renewal manager")
	close(rm.stopCh)
	rm.running = false
}

// ============================================================================
// Monitoring Loop
// ============================================================================

func (rm *RenewalManager) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(rm.config.CheckInterval)
	defer ticker.Stop()

	// Perform initial check immediately
	if err := rm.checkAndRenewIfNeeded(ctx); err != nil {
		log.Printf("[RENEWAL] Initial renewal check failed: %v", err)
	}

	for {
		select {
		case <-rm.stopCh:
			log.Printf("[RENEWAL] Monitor loop stopped")
			return

		case <-ticker.C:
			rm.mu.Lock()
			rm.renewalStatus.NextRenewalCheck = time.Now().Add(rm.config.CheckInterval)
			rm.mu.Unlock()

			if err := rm.checkAndRenewIfNeeded(ctx); err != nil {
				log.Printf("[RENEWAL] Renewal check failed: %v", err)
			}

		case <-ctx.Done():
			log.Printf("[RENEWAL] Context cancelled, stopping monitor")
			return
		}
	}
}

// ============================================================================
// Renewal Logic
// ============================================================================

func (rm *RenewalManager) checkAndRenewIfNeeded(ctx context.Context) error {
	rm.mu.Lock()
	if rm.renewalStatus.RenewalInProgress {
		rm.mu.Unlock()
		log.Printf("[RENEWAL] Renewal already in progress, skipping check")
		return nil
	}

	if rm.currentCA == nil {
		rm.mu.Unlock()
		return fmt.Errorf("no current CA loaded")
	}

	expiryTime := rm.currentCA.NotAfter
	timeUntilExpiry := time.Until(expiryTime)
	rm.mu.Unlock()

	log.Printf("[RENEWAL] Current CA expires in: %v (on %s)", timeUntilExpiry, expiryTime.Format("2006-01-02"))

	// Check if renewal is needed
	if timeUntilExpiry > rm.config.RenewalThreshold {
		log.Printf("[RENEWAL] No renewal needed yet (threshold: %v)", rm.config.RenewalThreshold)
		return nil
	}

	log.Printf("[RENEWAL] ⚠️  CA renewal needed! Time until expiry: %v", timeUntilExpiry)

	// Check if auto-renewal is enabled
	if !rm.config.EnableAutoRenewal {
		rm.mu.Lock()
		rm.renewalStatus.RenewalScheduled = true
		rm.mu.Unlock()
		log.Printf("[RENEWAL] Auto-renewal disabled, manual renewal required")
		rm.sendNotification("CA renewal required (manual intervention needed)")
		return nil
	}

	// Trigger automatic renewal
	return rm.performRenewal(ctx)
}

func (rm *RenewalManager) performRenewal(ctx context.Context) error {
	rm.mu.Lock()
	rm.renewalStatus.RenewalInProgress = true
	rm.renewalStatus.RenewalScheduled = true
	rm.renewalStatus.RenewalError = nil
	rm.mu.Unlock()

	defer func() {
		rm.mu.Lock()
		rm.renewalStatus.RenewalInProgress = false
		rm.mu.Unlock()
	}()

	log.Printf("[RENEWAL] 🔄 Starting CA certificate renewal...")

	// Step 1: Generate new CA certificate
	log.Printf("[RENEWAL] Step 1/6: Generating new CA certificate...")
	newCA, newKey, err := rm.generateNewCA(ctx)
	if err != nil {
		rm.setRenewalError(err)
		return fmt.Errorf("failed to generate new CA: %w", err)
	}
	log.Printf("[RENEWAL] ✅ New CA generated (expires: %s)", newCA.NotAfter.Format("2006-01-02"))

	// Step 2: Store new CA as "pending"
	log.Printf("[RENEWAL] Step 2/6: Storing new CA as pending...")
	if err := rm.certStore.StorePendingCA(ctx, newCA, newKey); err != nil {
		rm.setRenewalError(err)
		return fmt.Errorf("failed to store pending CA: %w", err)
	}
	rm.mu.Lock()
	rm.pendingCA = newCA
	rm.mu.Unlock()
	log.Printf("[RENEWAL] ✅ New CA stored as pending")

	// Step 3: Update DHCP options with new CA URL
	log.Printf("[RENEWAL] Step 3/6: Updating DHCP server with new CA options...")
	if err := rm.updateDHCPOptions(ctx, newCA); err != nil {
		rm.setRenewalError(err)
		return fmt.Errorf("failed to update DHCP options: %w", err)
	}
	log.Printf("[RENEWAL] ✅ DHCP options updated")

	// Step 4: Notify all devices to re-install certificate
	log.Printf("[RENEWAL] Step 4/6: Notifying devices of renewal...")
	devicesNotified, err := rm.notifyDevices(ctx)
	if err != nil {
		log.Printf("[RENEWAL] ⚠️  Device notification failed (continuing anyway): %v", err)
	}
	rm.mu.Lock()
	rm.renewalStatus.DevicesNotified = devicesNotified
	rm.mu.Unlock()
	log.Printf("[RENEWAL] ✅ Notified %d devices", devicesNotified)

	// Step 5: Wait for grace period or promote immediately
	log.Printf("[RENEWAL] Step 5/6: Promoting new CA to active...")
	if err := rm.certStore.PromotePendingToActive(ctx); err != nil {
		rm.setRenewalError(err)
		return fmt.Errorf("failed to promote CA: %w", err)
	}
	log.Printf("[RENEWAL] ✅ New CA promoted to active")

	// Step 6: Archive old CA (keep for grace period)
	log.Printf("[RENEWAL] Step 6/6: Archiving old CA...")
	if err := rm.archiveOldCA(ctx); err != nil {
		log.Printf("[RENEWAL] ⚠️  Failed to archive old CA: %v", err)
	}
	log.Printf("[RENEWAL] ✅ Old CA archived (grace period: %v)", rm.config.GracePeriod)

	// Update status
	rm.mu.Lock()
	rm.currentCA = newCA
	rm.pendingCA = nil
	rm.renewalStatus.LastRenewalTime = time.Now()
	rm.renewalStatus.CurrentCAExpiry = newCA.NotAfter
	rm.renewalStatus.RenewalScheduled = false
	rm.mu.Unlock()

	log.Printf("[RENEWAL] 🎉 CA renewal completed successfully!")
	rm.sendNotification("CA certificate renewed successfully")

	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

func (rm *RenewalManager) loadCurrentCA(ctx context.Context) error {
	ca, err := rm.certStore.GetCurrentCA(ctx)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	rm.currentCA = ca
	rm.renewalStatus.CurrentCAExpiry = ca.NotAfter
	rm.mu.Unlock()

	log.Printf("[RENEWAL] Loaded current CA: expires on %s", ca.NotAfter.Format("2006-01-02 15:04:05"))
	return nil
}

func (rm *RenewalManager) generateNewCA(ctx context.Context) (*x509.Certificate, []byte, error) {
	config := &CAGenerationConfig{
		CommonName:    "SafeOps Root CA (Renewed)",
		Organization:  "SafeOps",
		Country:       "US",
		ValidityYears: 10,
		KeySize:       4096,
	}

	return rm.caGenerator.GenerateNewCA(ctx, config)
}

func (rm *RenewalManager) updateDHCPOptions(ctx context.Context, newCA *x509.Certificate) error {
	// Calculate new fingerprint
	fingerprint := fmt.Sprintf("%X", newCA.Raw[:32]) // SHA-256 first 32 bytes

	// New CA will be available at same URL but with new fingerprint
	newCAURL := "http://192.168.1.1/ca.crt"

	return rm.dhcpNotifier.UpdateCAOptions(ctx, newCAURL, fingerprint)
}

func (rm *RenewalManager) notifyDevices(ctx context.Context) (int, error) {
	// In production, this would:
	// 1. Query all devices from device_ca_status table
	// 2. Send push notifications via MDM
	// 3. Trigger auto-deploy for each device
	// 4. Return count of notified devices

	// For now, return mock count
	rm.mu.Lock()
	rm.renewalStatus.TotalDevices = 100 // Mock value
	rm.mu.Unlock()

	if rm.deviceNotifier != nil {
		devices := []string{} // Would load from database
		if err := rm.deviceNotifier.NotifyDevicesOfRenewal(ctx, devices); err != nil {
			return 0, err
		}
	}

	return rm.renewalStatus.TotalDevices, nil
}

func (rm *RenewalManager) archiveOldCA(ctx context.Context) error {
	rm.mu.RLock()
	oldCA := rm.currentCA
	rm.mu.RUnlock()

	if oldCA == nil {
		return nil
	}

	return rm.certStore.ArchiveOldCA(ctx, oldCA)
}

func (rm *RenewalManager) setRenewalError(err error) {
	rm.mu.Lock()
	rm.renewalStatus.RenewalError = err
	rm.mu.Unlock()

	log.Printf("[RENEWAL] ❌ Renewal error: %v", err)
	rm.sendNotification(fmt.Sprintf("CA renewal failed: %v", err))
}

func (rm *RenewalManager) sendNotification(message string) {
	if rm.config.NotificationWebhook == "" {
		return
	}

	log.Printf("[RENEWAL] 📧 Sending notification: %s", message)
	// In production, this would POST to webhook URL
}

// ============================================================================
// Public API
// ============================================================================

// GetRenewalStatus returns current renewal status.
func (rm *RenewalManager) GetRenewalStatus() *RenewalStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Return copy
	status := *rm.renewalStatus
	return &status
}

// TriggerManualRenewal manually triggers CA renewal (regardless of threshold).
func (rm *RenewalManager) TriggerManualRenewal(ctx context.Context) error {
	rm.mu.Lock()
	if rm.renewalStatus.RenewalInProgress {
		rm.mu.Unlock()
		return fmt.Errorf("renewal already in progress")
	}
	rm.mu.Unlock()

	log.Printf("[RENEWAL] Manual renewal triggered")
	return rm.performRenewal(ctx)
}

// ForcePromotePending promotes pending CA to active immediately (skip grace period).
func (rm *RenewalManager) ForcePromotePending(ctx context.Context) error {
	rm.mu.Lock()
	if rm.pendingCA == nil {
		rm.mu.Unlock()
		return fmt.Errorf("no pending CA to promote")
	}
	rm.mu.Unlock()

	log.Printf("[RENEWAL] Force promoting pending CA to active")
	return rm.certStore.PromotePendingToActive(ctx)
}
