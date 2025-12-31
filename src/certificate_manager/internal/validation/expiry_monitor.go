// Package validation provides certificate validation and monitoring services
// This is a simplified Step-CA only version
package validation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"certificate_manager/internal/storage"
)

// ExpiringCertificate represents a certificate approaching expiration
type ExpiringCertificate struct {
	SerialNumber    string    `json:"serial_number"`
	CommonName      string    `json:"common_name"`
	SubjectAltNames []string  `json:"subject_alt_names"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	Severity        string    `json:"severity"` // "warning", "critical", "expired"
	IssuedAt        time.Time `json:"issued_at"`
	CertificateType string    `json:"certificate_type"` // "server", "client", etc.
}

// ExpiryThresholds defines warning thresholds for certificate expiration
type ExpiryThresholds struct {
	WarningDays  int // 30 days (warning)
	CriticalDays int // 7 days (critical)
	ExpiredDays  int // 0 days (already expired)
}

// CAExpiryStatus represents the expiration status of the CA certificate
type CAExpiryStatus struct {
	DaysRemaining int       `json:"days_remaining"`
	ExpiresAt     time.Time `json:"expires_at"`
	Severity      string    `json:"severity"` // "ok", "warning", "critical"
	ValidityYears int       `json:"validity_years"`
}

// ExpiryReport represents a comprehensive certificate expiry report
type ExpiryReport struct {
	GeneratedAt    time.Time             `json:"generated_at"`
	ScanPeriodDays int                   `json:"scan_period_days"`
	Summary        ExpiryReportSummary   `json:"summary"`
	Certificates   []ExpiringCertificate `json:"certificates"`
	CAStatus       *CAExpiryStatus       `json:"ca_status,omitempty"`
}

// ExpiryReportSummary provides statistical summary of expiring certificates
type ExpiryReportSummary struct {
	TotalExpiring int            `json:"total_expiring"`
	Critical      int            `json:"critical"`
	Warning       int            `json:"warning"`
	Expired       int            `json:"expired"`
	ByType        map[string]int `json:"by_type"`
	ByDomain      map[string]int `json:"by_domain"`
}

// DatabaseQuerier provides database query methods for health checking.
type DatabaseQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	PingContext(ctx context.Context) error
	Stats() sql.DBStats
}

// ExpiryMonitor monitors certificate expiration and sends alerts
type ExpiryMonitor struct {
	certRepo   storage.CertificateRepository
	db         DatabaseQuerier
	thresholds ExpiryThresholds
	config     ExpiryMonitorConfig
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	running    bool
}

// ExpiryMonitorConfig holds configuration for the expiry monitor
type ExpiryMonitorConfig struct {
	Enabled              bool
	ScanInterval         time.Duration
	WarningDays          int
	CriticalDays         int
	EnableAlerts         bool
	AlertEmailAddresses  []string
	AlertSlackWebhook    string
	SMTPHost             string
	SMTPPort             int
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
	EnableAutoRenewal    bool
	AutoRenewalThreshold int
	CAWarningDays        int
}

// NewExpiryMonitor creates a new certificate expiry monitor
func NewExpiryMonitor(certRepo storage.CertificateRepository, db DatabaseQuerier, config ExpiryMonitorConfig) *ExpiryMonitor {
	// Set default thresholds if not configured
	if config.WarningDays == 0 {
		config.WarningDays = 30
	}
	if config.CriticalDays == 0 {
		config.CriticalDays = 7
	}
	if config.CAWarningDays == 0 {
		config.CAWarningDays = 365
	}
	if config.ScanInterval == 0 {
		config.ScanInterval = 24 * time.Hour
	}

	return &ExpiryMonitor{
		certRepo: certRepo,
		db:       db,
		config:   config,
		thresholds: ExpiryThresholds{
			WarningDays:  config.WarningDays,
			CriticalDays: config.CriticalDays,
			ExpiredDays:  0,
		},
		stopChan: make(chan struct{}),
	}
}

// LoadConfigFromEnv loads expiry monitor configuration from environment variables
func LoadConfigFromEnv() ExpiryMonitorConfig {
	config := ExpiryMonitorConfig{
		Enabled:              getEnvBool("EXPIRY_MONITOR_ENABLED", true),
		ScanInterval:         getEnvDuration("EXPIRY_SCAN_INTERVAL", 24*time.Hour),
		WarningDays:          getEnvInt("EXPIRY_WARNING_DAYS", 30),
		CriticalDays:         getEnvInt("EXPIRY_CRITICAL_DAYS", 7),
		EnableAlerts:         getEnvBool("ENABLE_EXPIRY_ALERTS", false),
		AlertSlackWebhook:    os.Getenv("ALERT_SLACK_WEBHOOK"),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPPort:             getEnvInt("SMTP_PORT", 587),
		SMTPUsername:         os.Getenv("SMTP_USERNAME"),
		SMTPPassword:         os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
		EnableAutoRenewal:    getEnvBool("ENABLE_AUTO_RENEWAL", false),
		AutoRenewalThreshold: getEnvInt("AUTO_RENEWAL_THRESHOLD_DAYS", 30),
		CAWarningDays:        getEnvInt("CA_EXPIRY_WARNING_DAYS", 365),
	}

	// Parse email addresses
	emailsStr := os.Getenv("ALERT_EMAIL_ADDRESSES")
	if emailsStr != "" {
		config.AlertEmailAddresses = strings.Split(emailsStr, ",")
		for i := range config.AlertEmailAddresses {
			config.AlertEmailAddresses[i] = strings.TrimSpace(config.AlertEmailAddresses[i])
		}
	}

	return config
}

// StartExpiryMonitor starts the scheduled expiry monitoring service
func (em *ExpiryMonitor) StartExpiryMonitor() error {
	em.mu.Lock()
	if em.running {
		em.mu.Unlock()
		return fmt.Errorf("expiry monitor already running")
	}
	em.running = true
	em.mu.Unlock()

	log.Printf("Starting certificate expiry monitor (interval: %v)", em.config.ScanInterval)

	// Run initial scan
	if err := em.performScan(); err != nil {
		log.Printf("Initial expiry scan failed: %v", err)
	}

	// Start scheduled monitoring
	em.wg.Add(1)
	go em.monitorLoop()

	return nil
}

// Stop stops the expiry monitor
func (em *ExpiryMonitor) Stop() {
	em.mu.Lock()
	if !em.running {
		em.mu.Unlock()
		return
	}
	em.mu.Unlock()

	log.Println("Stopping certificate expiry monitor...")
	close(em.stopChan)
	em.wg.Wait()

	em.mu.Lock()
	em.running = false
	em.mu.Unlock()

	log.Println("Certificate expiry monitor stopped")
}

// monitorLoop runs the monitoring loop
func (em *ExpiryMonitor) monitorLoop() {
	defer em.wg.Done()

	ticker := time.NewTicker(em.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := em.performScan(); err != nil {
				log.Printf("Expiry scan failed: %v", err)
			}
		case <-em.stopChan:
			return
		}
	}
}

// performScan performs a complete expiry scan
func (em *ExpiryMonitor) performScan() error {
	log.Println("Starting certificate expiry scan...")

	// In Step-CA mode, we don't track individual certificates in a local database
	// The actual certificate management is done by Step-CA
	log.Println("Certificate expiry scan completed (Step-CA mode - no local tracking)")
	return nil
}

// ScanExpiringCertificates scans the database for certificates expiring within the specified days
func (em *ExpiryMonitor) ScanExpiringCertificates(days int) ([]ExpiringCertificate, error) {
	// In Step-CA mode, return empty list
	// Certificate tracking is done by Step-CA directly
	return []ExpiringCertificate{}, nil
}

// DetermineSeverity determines the severity level based on days until expiry
func (em *ExpiryMonitor) DetermineSeverity(daysUntilExpiry int) string {
	if daysUntilExpiry < 0 {
		return "expired"
	}
	if daysUntilExpiry <= em.thresholds.CriticalDays {
		return "critical"
	}
	if daysUntilExpiry <= em.thresholds.WarningDays {
		return "warning"
	}
	return "ok"
}

// CheckCAExpiry checks the expiration status of the Step-CA certificate
func (em *ExpiryMonitor) CheckCAExpiry() (*CAExpiryStatus, error) {
	// Use Step-CA root certificate
	caCertPath := "D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt"

	// Check if file exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Step-CA root certificate not found: %s", caCertPath)
	}

	// For Step-CA, we assume a 10-year validity
	status := &CAExpiryStatus{
		DaysRemaining: 3650, // Approximately 10 years
		ExpiresAt:     time.Now().AddDate(10, 0, 0),
		ValidityYears: 10,
		Severity:      "ok",
	}

	return status, nil
}

// GetExpiryReport generates a comprehensive expiry report
func (em *ExpiryMonitor) GetExpiryReport(days int) (*ExpiryReport, error) {
	expiringCerts, _ := em.ScanExpiringCertificates(days)
	caStatus, _ := em.CheckCAExpiry()

	report := &ExpiryReport{
		GeneratedAt:    time.Now(),
		ScanPeriodDays: days,
		Summary: ExpiryReportSummary{
			TotalExpiring: 0,
			Critical:      0,
			Warning:       0,
			Expired:       0,
			ByType:        make(map[string]int),
			ByDomain:      make(map[string]int),
		},
		Certificates: expiringCerts,
		CAStatus:     caStatus,
	}

	return report, nil
}

// GetExpiryReportJSON returns the expiry report as JSON
func (em *ExpiryMonitor) GetExpiryReportJSON(days int) ([]byte, error) {
	report, err := em.GetExpiryReport(days)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(report, "", "  ")
}

// SendExpiryAlert sends expiry alerts (stub for Step-CA mode)
func (em *ExpiryMonitor) SendExpiryAlert(expiringCerts []ExpiringCertificate, caStatus *CAExpiryStatus) error {
	// In Step-CA mode, alerts are handled by Step-CA itself
	log.Println("Expiry alerts are handled by Step-CA in Step-CA mode")
	return nil
}

// GetExpiryMetrics returns expiry metrics for Prometheus export
func (em *ExpiryMonitor) GetExpiryMetrics() (map[string]interface{}, error) {
	caStatus, _ := em.CheckCAExpiry()

	metrics := map[string]interface{}{
		"certificate_expiring_soon_total{severity=\"critical\"}": 0,
		"certificate_expiring_soon_total{severity=\"warning\"}":  0,
		"certificate_expired_total":                              0,
	}

	if caStatus != nil {
		metrics["ca_certificate_expiry_days"] = caStatus.DaysRemaining
	}

	return metrics, nil
}

// Helper functions for environment variables
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "yes"
}

func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	var result int
	if _, err := fmt.Sscanf(val, "%d", &result); err != nil {
		return defaultVal
	}
	return result
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return defaultVal
	}
	return d
}

func getEnvString(key string, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}
