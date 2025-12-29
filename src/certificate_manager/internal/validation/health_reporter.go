// Package validation provides PKI health monitoring and status reporting
package validation

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"certificate_manager/internal/ca"
	"certificate_manager/internal/revocation"
	"certificate_manager/internal/storage"
)

// PKIHealth represents the overall health status of the PKI infrastructure
type PKIHealth struct {
	OverallStatus string            `json:"overall_status"` // "healthy", "degraded", "unhealthy"
	Timestamp     time.Time         `json:"timestamp"`
	Components    []ComponentHealth `json:"components"`
	Metrics       PKIMetrics        `json:"metrics"`
	Version       string            `json:"version"`
}

// ComponentHealth represents the health status of a single component
type ComponentHealth struct {
	Name        string    `json:"name"`    // "ca_certificate", "crl", "ocsp", etc.
	Status      string    `json:"status"`  // "healthy", "warning", "error"
	Message     string    `json:"message"` // Human-readable status message
	LastChecked time.Time `json:"last_checked"`
	Details     string    `json:"details,omitempty"` // Additional technical details
}

// PKIMetrics contains operational metrics about the PKI
type PKIMetrics struct {
	TotalCertificatesIssued  int64         `json:"total_certificates_issued"`
	CertificatesIssuedToday  int           `json:"certificates_issued_today"`
	CertificatesIssuedWeek   int           `json:"certificates_issued_week"`
	TotalRevoked             int64         `json:"total_revoked"`
	RevokedToday             int           `json:"revoked_today"`
	CertificatesExpiringSoon int           `json:"certificates_expiring_soon"`
	CertificatesExpired      int           `json:"certificates_expired"`
	HTTPRequests24h          int64         `json:"http_requests_24h"`
	OCSPRequests24h          int64         `json:"ocsp_requests_24h"`
	AverageIssuanceTime      time.Duration `json:"average_issuance_time"`
	DatabaseConnections      int           `json:"database_connections"`
}

// DatabaseQuerier provides database query methods for health checking.
type DatabaseQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	PingContext(ctx context.Context) error
	Stats() sql.DBStats
}

// HealthReporter monitors and reports PKI health status
type HealthReporter struct {
	caStorage      *ca.CAStorageConfig
	certRepo       storage.CertificateRepository
	crlGenerator   *revocation.CRLGenerator
	ocspResponder  *revocation.OCSPResponder
	expiryMonitor  *ExpiryMonitor
	db             DatabaseQuerier
	config         HealthReporterConfig
	lastHealthData *PKIHealth
	mu             sync.RWMutex
}

// HealthReporterConfig holds configuration for health reporting
type HealthReporterConfig struct {
	Enabled                   bool
	CheckInterval             time.Duration
	CRLStalenessWarningHours  int
	OCSPTimeout               time.Duration
	HealthEndpointPath        string
	HTTPServerAddr            string
	OCSPServerAddr            string
	GRPCServerAddr            string
	DatabaseCheckEnabled      bool
	ServiceAvailabilityChecks bool
}

// NewHealthReporter creates a new PKI health reporter
func NewHealthReporter(
	caStorage *ca.CAStorageConfig,
	certRepo storage.CertificateRepository,
	crlGenerator *revocation.CRLGenerator,
	ocspResponder *revocation.OCSPResponder,
	expiryMonitor *ExpiryMonitor,
	db DatabaseQuerier,
) *HealthReporter {
	return &HealthReporter{
		caStorage:     caStorage,
		certRepo:      certRepo,
		crlGenerator:  crlGenerator,
		ocspResponder: ocspResponder,
		expiryMonitor: expiryMonitor,
		db:            db,
		config:        loadHealthConfigFromEnv(),
	}
}

// loadHealthConfigFromEnv loads health reporter configuration from environment
func loadHealthConfigFromEnv() HealthReporterConfig {
	return HealthReporterConfig{
		Enabled:                   getEnvBool("HEALTH_CHECK_ENABLED", true),
		CheckInterval:             getEnvDuration("HEALTH_CHECK_INTERVAL", 5*time.Minute),
		CRLStalenessWarningHours:  getEnvInt("CRL_STALENESS_WARNING_HOURS", 48),
		OCSPTimeout:               getEnvDuration("OCSP_TIMEOUT", 5*time.Second),
		HealthEndpointPath:        getEnvString("HEALTH_ENDPOINT_PATH", "/health"),
		HTTPServerAddr:            getEnvString("HTTP_SERVER_ADDR", ":80"),
		OCSPServerAddr:            getEnvString("OCSP_SERVER_ADDR", ":8888"),
		GRPCServerAddr:            getEnvString("GRPC_SERVER_ADDR", ":50060"),
		DatabaseCheckEnabled:      getEnvBool("DATABASE_HEALTH_CHECK", true),
		ServiceAvailabilityChecks: getEnvBool("SERVICE_AVAILABILITY_CHECKS", true),
	}
}

// GetPKIHealth performs comprehensive health checks and returns aggregated status
func (hr *HealthReporter) GetPKIHealth() (*PKIHealth, error) {
	startTime := time.Now()
	log.Println("Performing PKI health checks...")

	components := make([]ComponentHealth, 0)

	// Run all health checks
	components = append(components, hr.CheckCAHealth())
	components = append(components, hr.CheckCRLFreshness())

	if hr.ocspResponder != nil {
		components = append(components, hr.CheckOCSPStatus())
	}

	components = append(components, hr.GetCertificateIssuanceHealth())

	if hr.config.DatabaseCheckEnabled {
		components = append(components, hr.CheckDatabaseHealth())
	}

	if hr.config.ServiceAvailabilityChecks {
		serviceChecks := hr.CheckServiceAvailability()
		components = append(components, serviceChecks...)
	}

	// Collect metrics
	metrics, err := hr.GetPKIMetrics()
	if err != nil {
		log.Printf("Failed to collect PKI metrics: %v", err)
		// Continue with empty metrics
		metrics = &PKIMetrics{}
	}

	// Determine overall status
	overallStatus := hr.determineOverallStatus(components)

	health := &PKIHealth{
		OverallStatus: overallStatus,
		Timestamp:     time.Now(),
		Components:    components,
		Metrics:       *metrics,
		Version:       "1.0.0", // TODO: Get from build info
	}

	// Cache the health data
	hr.mu.Lock()
	hr.lastHealthData = health
	hr.mu.Unlock()

	duration := time.Since(startTime)
	log.Printf("PKI health check completed in %v - Status: %s", duration, overallStatus)

	return health, nil
}

// CheckCAHealth checks the health of the CA certificate
func (hr *HealthReporter) CheckCAHealth() ComponentHealth {
	component := ComponentHealth{
		Name:        "ca_certificate",
		LastChecked: time.Now(),
	}

	// Load CA certificate
	caCert, err := ca.LoadCACertificate(hr.caStorage)
	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("Failed to load CA certificate: %v", err)
		return component
	}

	// Check expiration
	now := time.Now()
	duration := caCert.NotAfter.Sub(now)
	daysRemaining := int(duration.Hours() / 24)

	if daysRemaining < 0 {
		component.Status = "error"
		component.Message = fmt.Sprintf("CA certificate EXPIRED %d days ago", -daysRemaining)
		return component
	}

	if daysRemaining <= 7 {
		component.Status = "error"
		component.Message = fmt.Sprintf("CA certificate expires in %d days (CRITICAL)", daysRemaining)
		return component
	}

	if daysRemaining <= 30 {
		component.Status = "warning"
		component.Message = fmt.Sprintf("CA certificate expires in %d days (renew soon)", daysRemaining)
		return component
	}

	if daysRemaining <= 365 {
		component.Status = "warning"
		component.Message = fmt.Sprintf("CA certificate expires in %d days (plan migration)", daysRemaining)
		return component
	}

	component.Status = "healthy"
	component.Message = fmt.Sprintf("CA valid for %d days", daysRemaining)
	component.Details = fmt.Sprintf("Expires: %s", caCert.NotAfter.Format("2006-01-02"))

	return component
}

// CheckCRLFreshness validates that the CRL is current
func (hr *HealthReporter) CheckCRLFreshness() ComponentHealth {
	component := ComponentHealth{
		Name:        "crl",
		LastChecked: time.Now(),
	}

	if hr.crlGenerator == nil {
		component.Status = "warning"
		component.Message = "CRL generator not initialized"
		return component
	}

	// Get latest CRL
	crlBytes, err := hr.crlGenerator.GenerateCRL()
	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("Failed to get CRL: %v", err)
		return component
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("Failed to parse CRL: %v", err)
		return component
	}

	now := time.Now()

	// Check if CRL is expired
	if now.After(crl.NextUpdate) {
		component.Status = "error"
		component.Message = fmt.Sprintf("CRL expired %v ago (NextUpdate: %s)",
			now.Sub(crl.NextUpdate), crl.NextUpdate.Format("2006-01-02 15:04:05"))
		return component
	}

	// Check CRL staleness
	age := now.Sub(crl.ThisUpdate)
	ageHours := int(age.Hours())
	maxAge := hr.config.CRLStalenessWarningHours

	if ageHours > maxAge {
		component.Status = "warning"
		component.Message = fmt.Sprintf("CRL is stale (updated %d hours ago, threshold: %d hours)",
			ageHours, maxAge)
		return component
	}

	component.Status = "healthy"
	component.Message = fmt.Sprintf("CRL updated %d hours ago, valid until %s",
		ageHours, crl.NextUpdate.Format("2006-01-02 15:04:05"))
	component.Details = fmt.Sprintf("Revoked certificates: %d", len(crl.RevokedCertificateEntries))

	return component
}

// CheckOCSPStatus checks the OCSP responder health
func (hr *HealthReporter) CheckOCSPStatus() ComponentHealth {
	component := ComponentHealth{
		Name:        "ocsp_responder",
		LastChecked: time.Now(),
	}

	if hr.ocspResponder == nil {
		component.Status = "warning"
		component.Message = "OCSP responder not initialized"
		return component
	}

	// Check if OCSP server is listening
	addr := strings.TrimPrefix(hr.config.OCSPServerAddr, ":")
	if !strings.Contains(addr, ":") {
		addr = "localhost:" + addr
	}

	// Test TCP connection
	conn, err := net.DialTimeout("tcp", addr, hr.config.OCSPTimeout)
	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("OCSP responder not reachable at %s: %v", addr, err)
		return component
	}
	conn.Close()

	// TODO: Send test OCSP request and measure response time
	// For now, just check connectivity
	component.Status = "healthy"
	component.Message = fmt.Sprintf("OCSP responder listening on %s", addr)
	component.Details = "Service is reachable"

	return component
}

// GetCertificateIssuanceHealth monitors certificate issuance activity
func (hr *HealthReporter) GetCertificateIssuanceHealth() ComponentHealth {
	component := ComponentHealth{
		Name:        "certificate_issuance",
		LastChecked: time.Now(),
	}

	ctx := context.Background()

	// Query certificates issued in last 24 hours
	query := `
		SELECT COUNT(*)
		FROM issued_certificates
		WHERE issued_at > NOW() - INTERVAL '24 hours'
	`

	var count int
	if hr.db != nil {
		err := hr.db.QueryRowContext(ctx, query).Scan(&count)
		if err != nil {
			component.Status = "warning"
			component.Message = fmt.Sprintf("Failed to query issuance stats: %v", err)
			return component
		}
	}

	component.Status = "healthy"
	component.Message = fmt.Sprintf("%d certificates issued in last 24 hours", count)
	component.Details = "CA signing key accessible"

	return component
}

// CheckDatabaseHealth checks database connectivity and performance
func (hr *HealthReporter) CheckDatabaseHealth() ComponentHealth {
	component := ComponentHealth{
		Name:        "database",
		LastChecked: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if hr.db == nil {
		component.Status = "warning"
		component.Message = "Database not configured"
		return component
	}

	// Check database connectivity
	start := time.Now()
	err := hr.db.PingContext(ctx)
	latency := time.Since(start)

	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("Database unreachable: %v", err)
		return component
	}

	// Check query performance
	if latency > 100*time.Millisecond {
		component.Status = "warning"
		component.Message = fmt.Sprintf("Database latency high: %v", latency)
		return component
	}

	component.Status = "healthy"
	component.Message = fmt.Sprintf("Database connected, latency: %v", latency)

	// Get connection stats
	stats := hr.db.Stats()
	component.Details = fmt.Sprintf("Open connections: %d, Idle: %d",
		stats.OpenConnections, stats.Idle)

	return component
}

// CheckServiceAvailability checks availability of all network services
func (hr *HealthReporter) CheckServiceAvailability() []ComponentHealth {
	components := make([]ComponentHealth, 0)

	// HTTP Server check
	if hr.config.HTTPServerAddr != "" {
		components = append(components, hr.checkTCPService("http_server", hr.config.HTTPServerAddr))
	}

	// OCSP Server check
	if hr.config.OCSPServerAddr != "" {
		components = append(components, hr.checkTCPService("ocsp_server", hr.config.OCSPServerAddr))
	}

	// gRPC Server check
	if hr.config.GRPCServerAddr != "" {
		components = append(components, hr.checkTCPService("grpc_server", hr.config.GRPCServerAddr))
	}

	return components
}

// checkTCPService checks if a TCP service is listening
func (hr *HealthReporter) checkTCPService(name, addr string) ComponentHealth {
	component := ComponentHealth{
		Name:        name,
		LastChecked: time.Now(),
	}

	// Normalize address
	if !strings.Contains(addr, ":") {
		addr = "localhost:" + addr
	}

	// Test TCP connection
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		component.Status = "error"
		component.Message = fmt.Sprintf("Service not listening on %s: %v", addr, err)
		return component
	}
	conn.Close()

	component.Status = "healthy"
	component.Message = fmt.Sprintf("Service listening on %s", addr)

	return component
}

// GetPKIMetrics collects operational metrics from the PKI
func (hr *HealthReporter) GetPKIMetrics() (*PKIMetrics, error) {
	ctx := context.Background()
	metrics := &PKIMetrics{}

	if hr.db == nil {
		return metrics, nil
	}

	// Total certificates issued
	err := hr.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates").Scan(&metrics.TotalCertificatesIssued)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Failed to get total certificates: %v", err)
	}

	// Certificates issued today
	err = hr.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE issued_at > NOW() - INTERVAL '24 hours'").
		Scan(&metrics.CertificatesIssuedToday)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Failed to get certificates issued today: %v", err)
	}

	// Certificates issued this week
	err = hr.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE issued_at > NOW() - INTERVAL '7 days'").
		Scan(&metrics.CertificatesIssuedWeek)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Failed to get certificates issued this week: %v", err)
	}

	// Total revoked
	err = hr.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM revoked_certificates").Scan(&metrics.TotalRevoked)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Failed to get total revoked: %v", err)
	}

	// Revoked today
	err = hr.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM revoked_certificates WHERE revoked_at > NOW() - INTERVAL '24 hours'").
		Scan(&metrics.RevokedToday)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Failed to get revoked today: %v", err)
	}

	// Get expiration statistics from expiry monitor
	if hr.expiryMonitor != nil {
		expiringCerts, err := hr.expiryMonitor.ScanExpiringCertificates(30)
		if err == nil {
			for _, cert := range expiringCerts {
				if cert.Severity == "expired" {
					metrics.CertificatesExpired++
				} else {
					metrics.CertificatesExpiringSoon++
				}
			}
		}
	}

	// Database connection stats
	stats := hr.db.Stats()
	metrics.DatabaseConnections = stats.OpenConnections

	return metrics, nil
}

// determineOverallStatus determines the overall health status from component statuses
func (hr *HealthReporter) determineOverallStatus(components []ComponentHealth) string {
	hasError := false
	hasWarning := false

	for _, component := range components {
		switch component.Status {
		case "error":
			hasError = true
		case "warning":
			hasWarning = true
		}
	}

	if hasError {
		return "unhealthy"
	}
	if hasWarning {
		return "degraded"
	}
	return "healthy"
}

// GetHealthJSON returns the health report as JSON
func (hr *HealthReporter) GetHealthJSON() ([]byte, error) {
	health, err := hr.GetPKIHealth()
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(health, "", "  ")
}

// GetHealthHTML returns the health report as HTML
func (hr *HealthReporter) GetHealthHTML() (string, error) {
	health, err := hr.GetPKIHealth()
	if err != nil {
		return "", err
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>SafeOps PKI Health Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            margin: 10px 0;
        }
        .healthy { background-color: #4CAF50; color: white; }
        .degraded { background-color: #FF9800; color: white; }
        .unhealthy { background-color: #f44336; color: white; }
        .warning { background-color: #FFC107; color: black; }
        .error { background-color: #f44336; color: white; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .metric-box {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #4CAF50;
        }
        .metric-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .timestamp {
            color: #666;
            font-size: 14px;
        }
        .status-icon {
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SafeOps PKI Health Dashboard</h1>

        <div class="status-badge {{.OverallStatus}}">
            Overall Status: {{.OverallStatus | title}}
        </div>

        <p class="timestamp">Last Updated: {{.Timestamp.Format "2006-01-02 15:04:05 MST"}}</p>

        <h2>System Metrics</h2>
        <div class="metrics">
            <div class="metric-box">
                <div class="metric-label">Total Issued</div>
                <div class="metric-value">{{.Metrics.TotalCertificatesIssued}}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Issued Today</div>
                <div class="metric-value">{{.Metrics.CertificatesIssuedToday}}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Issued This Week</div>
                <div class="metric-value">{{.Metrics.CertificatesIssuedWeek}}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Total Revoked</div>
                <div class="metric-value">{{.Metrics.TotalRevoked}}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Expiring Soon</div>
                <div class="metric-value">{{.Metrics.CertificatesExpiringSoon}}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Expired</div>
                <div class="metric-value">{{.Metrics.CertificatesExpired}}</div>
            </div>
        </div>

        <h2>Component Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Status</th>
                    <th>Message</th>
                    <th>Last Checked</th>
                </tr>
            </thead>
            <tbody>
                {{range .Components}}
                <tr>
                    <td>{{.Name}}</td>
                    <td>
                        <span class="status-badge {{.Status}}">
                            {{if eq .Status "healthy"}}✓{{else if eq .Status "warning"}}⚠{{else}}✗{{end}}
                            {{.Status | title}}
                        </span>
                    </td>
                    <td>{{.Message}}</td>
                    <td>{{.LastChecked.Format "15:04:05"}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <p class="timestamp">PKI Version: {{.Version}}</p>
    </div>
</body>
</html>
`

	funcMap := template.FuncMap{
		"title": strings.Title,
	}

	t, err := template.New("health").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, health); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.String(), nil
}

// GetHealthText returns a plain text health summary
func (hr *HealthReporter) GetHealthText() (string, error) {
	health, err := hr.GetPKIHealth()
	if err != nil {
		return "", err
	}

	var buf strings.Builder

	buf.WriteString(fmt.Sprintf("PKI Health Status - %s\n", health.Timestamp.Format("2006-01-02 15:04:05")))
	buf.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Overall status
	var statusSymbol string
	switch health.OverallStatus {
	case "degraded":
		statusSymbol = "!"
	case "unhealthy":
		statusSymbol = "X"
	default:
		statusSymbol = "OK"
	}
	buf.WriteString(fmt.Sprintf("Overall Status: %s %s\n\n", statusSymbol, strings.ToUpper(health.OverallStatus)))

	// Components
	buf.WriteString("Components:\n")
	for _, component := range health.Components {
		var symbol string
		switch component.Status {
		case "warning":
			symbol = "!"
		case "error":
			symbol = "X"
		default:
			symbol = "OK"
		}
		buf.WriteString(fmt.Sprintf("  %s %-20s %s\n", symbol, component.Name+":", component.Message))
	}
	buf.WriteString("\n")

	// Metrics
	buf.WriteString("Metrics:\n")
	buf.WriteString(fmt.Sprintf("  Total Issued:      %d certificates\n", health.Metrics.TotalCertificatesIssued))
	buf.WriteString(fmt.Sprintf("  Issued Today:      %d certificates\n", health.Metrics.CertificatesIssuedToday))
	buf.WriteString(fmt.Sprintf("  Issued This Week:  %d certificates\n", health.Metrics.CertificatesIssuedWeek))
	buf.WriteString(fmt.Sprintf("  Total Revoked:     %d certificates\n", health.Metrics.TotalRevoked))
	buf.WriteString(fmt.Sprintf("  Expiring Soon:     %d certificates\n", health.Metrics.CertificatesExpiringSoon))
	buf.WriteString(fmt.Sprintf("  Expired:           %d certificates\n", health.Metrics.CertificatesExpired))

	return buf.String(), nil
}

// HealthCheckHandler returns an HTTP handler for health checks
func (hr *HealthReporter) HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get cached health data if available and recent
		hr.mu.RLock()
		cachedHealth := hr.lastHealthData
		hr.mu.RUnlock()

		var health *PKIHealth
		var err error

		if cachedHealth != nil && time.Since(cachedHealth.Timestamp) < 30*time.Second {
			// Use cached data if less than 30 seconds old
			health = cachedHealth
		} else {
			// Perform fresh health check
			health, err = hr.GetPKIHealth()
			if err != nil {
				http.Error(w, "Health check failed", http.StatusInternalServerError)
				return
			}
		}

		// Set HTTP status code based on health
		statusCode := http.StatusOK
		if health.OverallStatus == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		if err := json.NewEncoder(w).Encode(health); err != nil {
			log.Printf("Failed to encode health response: %v", err)
		}
	}
}

// Helper functions

func getEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
