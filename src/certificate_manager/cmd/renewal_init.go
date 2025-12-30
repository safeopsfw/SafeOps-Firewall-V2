// Package main provides initialization helpers for certificate renewal system.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"certificate_manager/internal/renewal"
)

// ============================================================================
// Renewal System Initialization
// ============================================================================

// RenewalSystemConfig configures the entire renewal system.
type RenewalSystemConfig struct {
	// Renewal configuration
	RenewalThreshold  time.Duration
	CheckInterval     time.Duration
	GracePeriod       time.Duration
	EnableAutoRenewal bool

	// Database connection
	DatabaseURL string

	// DHCP server integration
	DHCPServerAddr   string
	EnableDHCPNotify bool

	// Device notification
	AutoDeployURL      string
	NotificationURL    string
	EnableDeviceNotify bool

	// Webhook for admin notifications
	NotificationWebhook string
}

// DefaultRenewalSystemConfig returns default configuration.
func DefaultRenewalSystemConfig() *RenewalSystemConfig {
	return &RenewalSystemConfig{
		RenewalThreshold:  365 * 24 * time.Hour, // 1 year before expiry
		CheckInterval:     24 * time.Hour,       // Check daily
		GracePeriod:       90 * 24 * time.Hour,  // 90 day grace period
		EnableAutoRenewal: true,

		DatabaseURL: "postgresql://user:pass@localhost/safeops",

		DHCPServerAddr:   "localhost:50054",
		EnableDHCPNotify: true,

		AutoDeployURL:      "http://192.168.1.1/install-ca.sh",
		NotificationURL:    "http://192.168.1.1/android",
		EnableDeviceNotify: true,

		NotificationWebhook: "",
	}
}

// ============================================================================
// Initialize Renewal Manager
// ============================================================================

// InitializeRenewalSystem initializes the complete renewal system.
func InitializeRenewalSystem(config *RenewalSystemConfig) (*renewal.RenewalManager, error) {
	log.Printf("[INIT] Initializing certificate renewal system...")

	// Step 1: Initialize database connection
	db, err := initializeDatabase(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	log.Printf("[INIT] ✅ Database connection established")

	// Step 2: Initialize certificate store
	certStore := renewal.NewDBCertificateStore(db)
	log.Printf("[INIT] ✅ Certificate store initialized")

	// Step 3: Initialize CA generator
	caGenerator := renewal.NewDefaultCAGenerator()
	log.Printf("[INIT] ✅ CA generator initialized")

	// Step 4: Initialize DHCP notifier
	var dhcpNotifier renewal.DHCPNotifier
	if config.EnableDHCPNotify {
		dhcpNotifier = renewal.NewGRPCDHCPNotifier(config.DHCPServerAddr)
		log.Printf("[INIT] ✅ DHCP notifier initialized (addr: %s)", config.DHCPServerAddr)
	} else {
		dhcpNotifier = renewal.NewMockDHCPNotifier()
		log.Printf("[INIT] ⚠️  DHCP notifier disabled (using mock)")
	}

	// Step 5: Initialize device notifier
	var deviceNotifier renewal.DeviceNotifier
	if config.EnableDeviceNotify {
		deviceNotifier = renewal.NewDefaultDeviceNotifier(db, config.AutoDeployURL, config.NotificationURL)
		log.Printf("[INIT] ✅ Device notifier initialized")
	} else {
		deviceNotifier = renewal.NewMockDeviceNotifier()
		log.Printf("[INIT] ⚠️  Device notifier disabled (using mock)")
	}

	// Step 6: Create renewal configuration
	renewalConfig := &renewal.RenewalConfig{
		RenewalThreshold:    config.RenewalThreshold,
		CheckInterval:       config.CheckInterval,
		GracePeriod:         config.GracePeriod,
		EnableAutoRenewal:   config.EnableAutoRenewal,
		NotificationWebhook: config.NotificationWebhook,
	}

	// Step 7: Create renewal manager
	renewalManager := renewal.NewRenewalManager(
		renewalConfig,
		certStore,
		caGenerator,
		dhcpNotifier,
		deviceNotifier,
	)
	log.Printf("[INIT] ✅ Renewal manager created")

	// Step 8: Start renewal monitoring
	ctx := context.Background()
	if err := renewalManager.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start renewal manager: %w", err)
	}
	log.Printf("[INIT] ✅ Renewal monitoring started")

	log.Printf("[INIT] 🎉 Certificate renewal system initialized successfully!")

	return renewalManager, nil
}

// ============================================================================
// Database Initialization
// ============================================================================

func initializeDatabase(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Initialize database schema
	if err := initializeSchema(db); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

func initializeSchema(db *sql.DB) error {
	// Create ca_certificates table if not exists
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS ca_certificates (
			id SERIAL PRIMARY KEY,
			certificate_pem TEXT NOT NULL,
			private_key_pem TEXT NOT NULL,
			fingerprint VARCHAR(128) NOT NULL UNIQUE,
			status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'pending', 'archived')),
			subject TEXT NOT NULL,
			issuer TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP NOT NULL,
			activated_at TIMESTAMP,
			archived_at TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_ca_status ON ca_certificates (status);
		CREATE INDEX IF NOT EXISTS idx_ca_fingerprint ON ca_certificates (fingerprint);
		CREATE INDEX IF NOT EXISTS idx_ca_expires_at ON ca_certificates (expires_at);

		-- Ensure only one active CA at a time
		CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_ca ON ca_certificates (status) WHERE status = 'active';
	`

	_, err := db.Exec(createTableSQL)
	return err
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// ShutdownRenewalSystem gracefully shuts down the renewal system.
func ShutdownRenewalSystem(manager *renewal.RenewalManager) {
	log.Printf("[SHUTDOWN] Stopping certificate renewal system...")
	manager.Stop()
	log.Printf("[SHUTDOWN] ✅ Renewal system stopped")
}

// ============================================================================
// Health Check
// ============================================================================

// CheckRenewalSystemHealth checks the health of the renewal system.
func CheckRenewalSystemHealth(manager *renewal.RenewalManager) error {
	status := manager.GetRenewalStatus()

	log.Printf("[HEALTH] Renewal System Status:")
	log.Printf("[HEALTH]   Current CA Expiry: %s", status.CurrentCAExpiry.Format("2006-01-02"))
	log.Printf("[HEALTH]   Next Renewal Check: %s", status.NextRenewalCheck.Format("2006-01-02 15:04:05"))
	log.Printf("[HEALTH]   Renewal Scheduled: %v", status.RenewalScheduled)
	log.Printf("[HEALTH]   Renewal In Progress: %v", status.RenewalInProgress)

	if status.RenewalError != nil {
		log.Printf("[HEALTH]   ❌ Renewal Error: %v", status.RenewalError)
		return status.RenewalError
	}

	if status.RenewalScheduled {
		log.Printf("[HEALTH]   ⚠️  Renewal scheduled")
	}

	log.Printf("[HEALTH] ✅ Renewal system healthy")
	return nil
}

// ============================================================================
// Manual Renewal Trigger
// ============================================================================

// TriggerManualRenewal manually triggers certificate renewal.
func TriggerManualRenewal(manager *renewal.RenewalManager) error {
	log.Printf("[MANUAL] Triggering manual CA renewal...")

	ctx := context.Background()
	if err := manager.TriggerManualRenewal(ctx); err != nil {
		log.Printf("[MANUAL] ❌ Manual renewal failed: %v", err)
		return err
	}

	log.Printf("[MANUAL] ✅ Manual renewal completed successfully")
	return nil
}

// ============================================================================
// Example Usage in Main Function
// ============================================================================

/*
func main() {
	// Initialize renewal system
	config := DefaultRenewalSystemConfig()
	renewalManager, err := InitializeRenewalSystem(config)
	if err != nil {
		log.Fatalf("Failed to initialize renewal system: %v", err)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received")

	// Graceful shutdown
	ShutdownRenewalSystem(renewalManager)
}
*/
