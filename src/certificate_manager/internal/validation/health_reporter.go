// Package validation provides PKI health monitoring and status reporting
// This is a simplified Step-CA only version
package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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
	Name        string    `json:"name"`    // "ca_certificate", "step_ca", etc.
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
	AverageIssuanceTime      time.Duration `json:"average_issuance_time"`
	DatabaseConnections      int           `json:"database_connections"`
}

// HealthReporter monitors and reports PKI health status
type HealthReporter struct {
	certRepo       storage.CertificateRepository
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
	HealthEndpointPath        string
	HTTPServerAddr            string
	StepCAServerAddr          string
	DatabaseCheckEnabled      bool
	ServiceAvailabilityChecks bool
}

// NewHealthReporter creates a new PKI health reporter
func NewHealthReporter(
	certRepo storage.CertificateRepository,
	expiryMonitor *ExpiryMonitor,
	db DatabaseQuerier,
) *HealthReporter {
	return &HealthReporter{
		certRepo:      certRepo,
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
		HealthEndpointPath:        getEnvString("HEALTH_ENDPOINT_PATH", "/health"),
		HTTPServerAddr:            getEnvString("HTTP_SERVER_ADDR", ":8082"),
		StepCAServerAddr:          getEnvString("STEP_CA_SERVER_ADDR", "localhost:9000"),
		DatabaseCheckEnabled:      getEnvBool("DATABASE_HEALTH_CHECK", true),
		ServiceAvailabilityChecks: getEnvBool("SERVICE_AVAILABILITY_CHECKS", true),
	}
}

// GetPKIHealth performs comprehensive health checks and returns aggregated status
func (hr *HealthReporter) GetPKIHealth() (*PKIHealth, error) {
	startTime := time.Now()
	log.Println("Performing PKI health checks...")

	components := make([]ComponentHealth, 0)

	// Run health checks
	components = append(components, hr.CheckStepCAHealth())

	if hr.config.DatabaseCheckEnabled {
		components = append(components, hr.CheckDatabaseHealth())
	}

	if hr.config.ServiceAvailabilityChecks {
		serviceChecks := hr.CheckServiceAvailability()
		components = append(components, serviceChecks...)
	}

	// Collect metrics
	metrics := &PKIMetrics{}

	// Determine overall status
	overallStatus := hr.determineOverallStatus(components)

	health := &PKIHealth{
		OverallStatus: overallStatus,
		Timestamp:     time.Now(),
		Components:    components,
		Metrics:       *metrics,
		Version:       "2.0.0-stepca",
	}

	// Cache the health data
	hr.mu.Lock()
	hr.lastHealthData = health
	hr.mu.Unlock()

	duration := time.Since(startTime)
	log.Printf("PKI health check completed in %v - Status: %s", duration, overallStatus)

	return health, nil
}

// CheckStepCAHealth checks the health of Step-CA
func (hr *HealthReporter) CheckStepCAHealth() ComponentHealth {
	component := ComponentHealth{
		Name:        "step_ca",
		LastChecked: time.Now(),
	}

	// Check if Step-CA root certificate exists
	caCertPath := "D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt"
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		component.Status = "error"
		component.Message = "Step-CA root certificate not found"
		return component
	}

	// Try to connect to Step-CA server
	addr := hr.config.StepCAServerAddr
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		component.Status = "warning"
		component.Message = fmt.Sprintf("Step-CA server not reachable at %s", addr)
		component.Details = "Root CA certificate exists, but server may be offline"
		return component
	}
	conn.Close()

	component.Status = "healthy"
	component.Message = "Step-CA server is running"
	component.Details = fmt.Sprintf("Connected to %s", addr)

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

// HealthCheckHandler returns an HTTP handler for health checks
func (hr *HealthReporter) HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health, err := hr.GetPKIHealth()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if health.OverallStatus == "unhealthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(health)
	}
}
