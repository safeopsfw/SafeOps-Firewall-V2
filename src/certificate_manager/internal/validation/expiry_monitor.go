// Package validation provides certificate validation and monitoring services
package validation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"certificate_manager/internal/ca"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
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
	GeneratedAt    time.Time              `json:"generated_at"`
	ScanPeriodDays int                    `json:"scan_period_days"`
	Summary        ExpiryReportSummary    `json:"summary"`
	Certificates   []ExpiringCertificate  `json:"certificates"`
	CAStatus       *CAExpiryStatus        `json:"ca_status,omitempty"`
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

// ExpiryMonitor monitors certificate expiration and sends alerts
type ExpiryMonitor struct {
	certRepo   *storage.CertificateRepository
	caStorage  *ca.CAStorage
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
func NewExpiryMonitor(certRepo *storage.CertificateRepository, caStorage *ca.CAStorage, config ExpiryMonitorConfig) *ExpiryMonitor {
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
		certRepo:  certRepo,
		caStorage: caStorage,
		config:    config,
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

// performScan performs a complete expiry scan and sends alerts
func (em *ExpiryMonitor) performScan() error {
	log.Println("Starting certificate expiry scan...")

	// Scan expiring certificates
	expiringCerts, err := em.ScanExpiringCertificates(em.thresholds.WarningDays)
	if err != nil {
		return fmt.Errorf("failed to scan expiring certificates: %w", err)
	}

	log.Printf("Found %d certificates expiring within %d days", len(expiringCerts), em.thresholds.WarningDays)

	// Check CA expiry
	caStatus, err := em.CheckCAExpiry()
	if err != nil {
		log.Printf("Failed to check CA expiry: %v", err)
	} else if caStatus.Severity != "ok" {
		log.Printf("WARNING: CA certificate expires in %d days (%s)", caStatus.DaysRemaining, caStatus.Severity)
	}

	// Send alerts if enabled and there are certificates requiring attention
	if em.config.EnableAlerts && len(expiringCerts) > 0 {
		if err := em.SendExpiryAlert(expiringCerts, caStatus); err != nil {
			log.Printf("Failed to send expiry alerts: %v", err)
		}
	}

	// Auto-renewal if enabled
	if em.config.EnableAutoRenewal {
		log.Println("Auto-renewal is enabled but not yet implemented")
		// TODO: Implement auto-renewal logic
	}

	log.Println("Certificate expiry scan completed")
	return nil
}

// ScanExpiringCertificates scans the database for certificates expiring within the specified days
func (em *ExpiryMonitor) ScanExpiringCertificates(days int) ([]ExpiringCertificate, error) {
	ctx := context.Background()

	// Query certificates expiring within the threshold
	query := `
		SELECT serial_number, common_name, subject_alt_names, not_after,
		       issued_at, certificate_type
		FROM issued_certificates
		WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'
		   OR not_after < NOW()
		ORDER BY not_after ASC
	`

	rows, err := em.certRepo.DB.QueryContext(ctx, fmt.Sprintf(query, days))
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var expiringCerts []ExpiringCertificate
	now := time.Now()

	for rows.Next() {
		var cert ExpiringCertificate
		var sanJSON sql.NullString

		err := rows.Scan(
			&cert.SerialNumber,
			&cert.CommonName,
			&sanJSON,
			&cert.NotAfter,
			&cert.IssuedAt,
			&cert.CertificateType,
		)
		if err != nil {
			log.Printf("Failed to scan certificate row: %v", err)
			continue
		}

		// Parse SANs
		if sanJSON.Valid && sanJSON.String != "" {
			if err := json.Unmarshal([]byte(sanJSON.String), &cert.SubjectAltNames); err != nil {
				log.Printf("Failed to parse SANs for certificate %s: %v", cert.SerialNumber, err)
			}
		}

		// Calculate days until expiry
		duration := cert.NotAfter.Sub(now)
		cert.DaysUntilExpiry = int(duration.Hours() / 24)

		// Determine severity
		cert.Severity = em.DetermineSeverity(cert.DaysUntilExpiry)

		expiringCerts = append(expiringCerts, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return expiringCerts, nil
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

// CheckCAExpiry checks the expiration status of the CA certificate
func (em *ExpiryMonitor) CheckCAExpiry() (*CAExpiryStatus, error) {
	// Load CA certificate
	caCert, err := em.caStorage.LoadCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	now := time.Now()
	duration := caCert.NotAfter.Sub(now)
	daysRemaining := int(duration.Hours() / 24)

	// Calculate validity period in years
	validityDuration := caCert.NotAfter.Sub(caCert.NotBefore)
	validityYears := int(validityDuration.Hours() / 24 / 365)

	status := &CAExpiryStatus{
		DaysRemaining: daysRemaining,
		ExpiresAt:     caCert.NotAfter,
		ValidityYears: validityYears,
	}

	// Determine severity (CA expiry is critical infrastructure event)
	if daysRemaining < 0 {
		status.Severity = "expired"
	} else if daysRemaining <= em.config.CAWarningDays {
		status.Severity = "critical"
	} else if daysRemaining <= em.config.CAWarningDays*2 {
		status.Severity = "warning"
	} else {
		status.Severity = "ok"
	}

	return status, nil
}

// GetExpiryReport generates a comprehensive expiry report
func (em *ExpiryMonitor) GetExpiryReport(days int) (*ExpiryReport, error) {
	// Scan expiring certificates
	expiringCerts, err := em.ScanExpiringCertificates(days)
	if err != nil {
		return nil, fmt.Errorf("failed to scan expiring certificates: %w", err)
	}

	// Check CA expiry
	caStatus, err := em.CheckCAExpiry()
	if err != nil {
		log.Printf("Failed to check CA expiry: %v", err)
	}

	// Generate summary statistics
	summary := em.generateSummary(expiringCerts)

	report := &ExpiryReport{
		GeneratedAt:    time.Now(),
		ScanPeriodDays: days,
		Summary:        summary,
		Certificates:   expiringCerts,
		CAStatus:       caStatus,
	}

	return report, nil
}

// generateSummary generates summary statistics from expiring certificates
func (em *ExpiryMonitor) generateSummary(certs []ExpiringCertificate) ExpiryReportSummary {
	summary := ExpiryReportSummary{
		TotalExpiring: len(certs),
		ByType:        make(map[string]int),
		ByDomain:      make(map[string]int),
	}

	for _, cert := range certs {
		// Count by severity
		switch cert.Severity {
		case "critical":
			summary.Critical++
		case "warning":
			summary.Warning++
		case "expired":
			summary.Expired++
		}

		// Count by type
		summary.ByType[cert.CertificateType]++

		// Count by domain (extract from common name)
		summary.ByDomain[cert.CommonName]++
	}

	return summary
}

// SendExpiryAlert sends expiry alerts via configured channels
func (em *ExpiryMonitor) SendExpiryAlert(expiringCerts []ExpiringCertificate, caStatus *CAExpiryStatus) error {
	var errors []error

	// Filter certificates by severity (only send alerts for critical and warning)
	alertCerts := make([]ExpiringCertificate, 0)
	for _, cert := range expiringCerts {
		if cert.Severity == "critical" || cert.Severity == "warning" || cert.Severity == "expired" {
			alertCerts = append(alertCerts, cert)
		}
	}

	if len(alertCerts) == 0 && (caStatus == nil || caStatus.Severity == "ok") {
		return nil // No alerts needed
	}

	// Send email alerts
	if len(em.config.AlertEmailAddresses) > 0 && em.config.SMTPHost != "" {
		if err := em.sendEmailAlert(alertCerts, caStatus); err != nil {
			errors = append(errors, fmt.Errorf("email alert failed: %w", err))
		}
	}

	// Send Slack alerts
	if em.config.AlertSlackWebhook != "" {
		if err := em.sendSlackAlert(alertCerts, caStatus); err != nil {
			errors = append(errors, fmt.Errorf("slack alert failed: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("alert errors: %v", errors)
	}

	log.Printf("Sent expiry alerts for %d certificates", len(alertCerts))
	return nil
}

// sendEmailAlert sends email alerts to configured recipients
func (em *ExpiryMonitor) sendEmailAlert(certs []ExpiringCertificate, caStatus *CAExpiryStatus) error {
	// Group certificates by severity
	critical := make([]ExpiringCertificate, 0)
	warning := make([]ExpiringCertificate, 0)
	expired := make([]ExpiringCertificate, 0)

	for _, cert := range certs {
		switch cert.Severity {
		case "critical":
			critical = append(critical, cert)
		case "warning":
			warning = append(warning, cert)
		case "expired":
			expired = append(expired, cert)
		}
	}

	// Build email subject
	subject := fmt.Sprintf("Certificate Expiry Alert - %d certificates requiring attention", len(certs))

	// Build email body
	body := em.formatEmailBody(critical, warning, expired, caStatus)

	// Send email
	auth := smtp.PlainAuth("", em.config.SMTPUsername, em.config.SMTPPassword, em.config.SMTPHost)

	for _, recipient := range em.config.AlertEmailAddresses {
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
			em.config.SMTPFrom, recipient, subject, body)

		addr := fmt.Sprintf("%s:%d", em.config.SMTPHost, em.config.SMTPPort)
		if err := smtp.SendMail(addr, auth, em.config.SMTPFrom, []string{recipient}, []byte(msg)); err != nil {
			return fmt.Errorf("failed to send email to %s: %w", recipient, err)
		}
	}

	return nil
}

// formatEmailBody formats the email body with certificate details
func (em *ExpiryMonitor) formatEmailBody(critical, warning, expired []ExpiringCertificate, caStatus *CAExpiryStatus) string {
	var body strings.Builder

	body.WriteString("SafeOps Certificate Expiry Alert\n")
	body.WriteString("================================\n\n")

	// CA Status
	if caStatus != nil && caStatus.Severity != "ok" {
		body.WriteString(fmt.Sprintf("   CA CERTIFICATE STATUS: %s\n", strings.ToUpper(caStatus.Severity)))
		body.WriteString(fmt.Sprintf("    Expires: %s (%d days remaining)\n\n",
			caStatus.ExpiresAt.Format("2006-01-02"), caStatus.DaysRemaining))
	}

	// Expired certificates
	if len(expired) > 0 {
		body.WriteString(fmt.Sprintf("EXPIRED (%d certificates):\n", len(expired)))
		for _, cert := range expired {
			body.WriteString(fmt.Sprintf("  - %s (expired %d days ago)\n",
				cert.CommonName, -cert.DaysUntilExpiry))
		}
		body.WriteString("\n")
	}

	// Critical certificates
	if len(critical) > 0 {
		body.WriteString(fmt.Sprintf("CRITICAL - Expires within %d days (%d certificates):\n",
			em.thresholds.CriticalDays, len(critical)))
		for _, cert := range critical {
			body.WriteString(fmt.Sprintf("  - %s (expires %s, %d days remaining)\n",
				cert.CommonName, cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry))
		}
		body.WriteString("\n")
	}

	// Warning certificates
	if len(warning) > 0 {
		body.WriteString(fmt.Sprintf("WARNING - Expires within %d days (%d certificates):\n",
			em.thresholds.WarningDays, len(warning)))
		for _, cert := range warning {
			body.WriteString(fmt.Sprintf("  - %s (expires %s, %d days remaining)\n",
				cert.CommonName, cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry))
		}
		body.WriteString("\n")
	}

	body.WriteString("Please renew these certificates to prevent service disruptions.\n")
	body.WriteString("\nGenerated by SafeOps Certificate Manager\n")

	return body.String()
}

// sendSlackAlert sends Slack webhook alerts
func (em *ExpiryMonitor) sendSlackAlert(certs []ExpiringCertificate, caStatus *CAExpiryStatus) error {
	// Group certificates by severity
	critical := 0
	warning := 0
	expired := 0

	for _, cert := range certs {
		switch cert.Severity {
		case "critical":
			critical++
		case "warning":
			warning++
		case "expired":
			expired++
		}
	}

	// Build Slack message
	message := map[string]interface{}{
		"text": fmt.Sprintf("= Certificate Expiry Alert - %d certificates requiring attention", len(certs)),
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": "*SafeOps Certificate Expiry Alert*",
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Expired:*\n%d certificates", expired),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Critical:*\n%d certificates", critical),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Warning:*\n%d certificates", warning),
					},
				},
			},
		},
	}

	// Add CA status if relevant
	if caStatus != nil && caStatus.Severity != "ok" {
		message["blocks"] = append(message["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("  *CA Certificate:* %s (%d days remaining)",
					strings.ToUpper(caStatus.Severity), caStatus.DaysRemaining),
			},
		})
	}

	// Send webhook request
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	resp, err := http.Post(em.config.AlertSlackWebhook, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to send Slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// GetExpiryReportJSON returns the expiry report as JSON
func (em *ExpiryMonitor) GetExpiryReportJSON(days int) ([]byte, error) {
	report, err := em.GetExpiryReport(days)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(report, "", "  ")
}

// GetExpiryReportHTML returns the expiry report as HTML
func (em *ExpiryMonitor) GetExpiryReportHTML(days int) (string, error) {
	report, err := em.GetExpiryReport(days)
	if err != nil {
		return "", err
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Certificate Expiry Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .critical { color: #d32f2f; }
        .warning { color: #f57c00; }
        .expired { color: #c62828; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Certificate Expiry Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        <p><strong>Scan Period:</strong> {{.ScanPeriodDays}} days</p>
        <p><strong>Total Expiring:</strong> {{.Summary.TotalExpiring}}</p>
        <p><strong>Critical:</strong> <span class="critical">{{.Summary.Critical}}</span></p>
        <p><strong>Warning:</strong> <span class="warning">{{.Summary.Warning}}</span></p>
        <p><strong>Expired:</strong> <span class="expired">{{.Summary.Expired}}</span></p>
    </div>

    {{if .CAStatus}}
    <div class="summary">
        <h2>CA Certificate Status</h2>
        <p><strong>Expires:</strong> {{.CAStatus.ExpiresAt.Format "2006-01-02"}}</p>
        <p><strong>Days Remaining:</strong> {{.CAStatus.DaysRemaining}}</p>
        <p><strong>Severity:</strong> {{.CAStatus.Severity}}</p>
    </div>
    {{end}}

    <h2>Expiring Certificates</h2>
    <table>
        <tr>
            <th>Common Name</th>
            <th>Expires</th>
            <th>Days Remaining</th>
            <th>Severity</th>
            <th>Type</th>
        </tr>
        {{range .Certificates}}
        <tr>
            <td>{{.CommonName}}</td>
            <td>{{.NotAfter.Format "2006-01-02"}}</td>
            <td>{{.DaysUntilExpiry}}</td>
            <td class="{{.Severity}}">{{.Severity}}</td>
            <td>{{.CertificateType}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>
`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, report); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.String(), nil
}

// GetExpiryMetrics returns expiry metrics for Prometheus export
func (em *ExpiryMonitor) GetExpiryMetrics() (map[string]interface{}, error) {
	// Scan all expiring certificates
	expiringCerts, err := em.ScanExpiringCertificates(em.thresholds.WarningDays)
	if err != nil {
		return nil, err
	}

	// Check CA expiry
	caStatus, err := em.CheckCAExpiry()
	if err != nil {
		return nil, err
	}

	metrics := make(map[string]interface{})

	// Count by severity
	critical := 0
	warning := 0
	expired := 0

	for _, cert := range expiringCerts {
		// Individual certificate metrics
		metricName := fmt.Sprintf("certificate_expiry_days{common_name=\"%s\"}", cert.CommonName)
		metrics[metricName] = cert.DaysUntilExpiry

		// Count by severity
		switch cert.Severity {
		case "critical":
			critical++
		case "warning":
			warning++
		case "expired":
			expired++
		}
	}

	// Aggregate metrics
	metrics["certificate_expiring_soon_total{severity=\"critical\"}"] = critical
	metrics["certificate_expiring_soon_total{severity=\"warning\"}"] = warning
	metrics["certificate_expired_total"] = expired
	metrics["ca_certificate_expiry_days"] = caStatus.DaysRemaining

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
	duration, err := time.ParseDuration(val)
	if err != nil {
		return defaultVal
	}
	return duration
}
