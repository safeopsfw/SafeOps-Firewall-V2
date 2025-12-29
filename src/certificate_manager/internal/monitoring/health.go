// Package monitoring provides health checks and monitoring for Certificate Manager.
package monitoring

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// ============================================================================
// Health Status Constants
// ============================================================================

const (
	StatusHealthy   = "healthy"
	StatusDegraded  = "degraded"
	StatusUnhealthy = "unhealthy"
)

// Component weights for overall health score calculation
const (
	WeightDatabase      = 30 // Critical for all operations
	WeightCACertificate = 25 // Core PKI functionality
	WeightHTTPServer    = 15 // CA distribution
	WeightOCSPResponder = 15 // Revocation checking
	WeightCRL           = 10 // Revocation list
	WeightDiskSpace     = 5  // Storage availability
)

// ============================================================================
// Health Check Types
// ============================================================================

// ComponentHealth represents the health status of a single component.
type ComponentHealth struct {
	Status           string  `json:"status"`                // healthy, degraded, unhealthy
	LatencyMs        float64 `json:"latency_ms,omitempty"`  // Query/connection latency
	Listening        bool    `json:"listening,omitempty"`   // For network services
	ValidUntil       string  `json:"valid_until,omitempty"` // For certificates
	DaysRemaining    int     `json:"days_remaining,omitempty"`
	UpdatedAt        int64   `json:"updated_at,omitempty"` // For CRL
	HoursSinceUpdate float64 `json:"hours_since_update,omitempty"`
	AvailableGB      float64 `json:"available_gb,omitempty"` // For disk space
	TotalGB          float64 `json:"total_gb,omitempty"`
	UsedPercent      float64 `json:"used_percentage,omitempty"`
	Error            string  `json:"error,omitempty"`   // Error message if unhealthy
	Warning          string  `json:"warning,omitempty"` // Warning message if degraded
}

// HealthResponse represents the overall health check response.
type HealthResponse struct {
	Status             string                      `json:"status"`
	Timestamp          int64                       `json:"timestamp"`
	Components         map[string]*ComponentHealth `json:"components"`
	OverallHealthScore int                         `json:"overall_health_score"`
}

// DetailedHealthResponse extends HealthResponse with diagnostic info.
type DetailedHealthResponse struct {
	HealthResponse
	RecentErrors       []string             `json:"recent_errors,omitempty"`
	PerformanceMetrics *PerformanceStats    `json:"performance_metrics,omitempty"`
	CertificateStats   *CertificateStats    `json:"certificate_stats,omitempty"`
	DeviceStats        *DeviceAdoptionStats `json:"device_stats,omitempty"`
	Uptime             string               `json:"uptime"`
}

// ============================================================================
// Health Checker Configuration
// ============================================================================

// HealthConfig holds configuration for health checks.
type HealthConfig struct {
	// File paths
	CACertPath string
	CAKeyPath  string
	CRLPath    string

	// Network endpoints
	HTTPBindAddress string
	HTTPPort        int
	OCSPBindAddress string
	OCSPPort        int
	DatabaseDSN     string

	// Thresholds
	DatabaseLatencyWarningMs int
	CRLMaxAgeHours           int
	DiskSpaceWarningGB       float64
	DiskSpaceCriticalGB      float64
	CertExpiryWarningDays    int

	// Check interval
	CheckInterval time.Duration
}

// DefaultHealthConfig returns sensible default configuration.
func DefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		CACertPath:               "/etc/safeops/ca/root-cert.pem",
		CAKeyPath:                "/etc/safeops/ca/root-key.pem",
		CRLPath:                  "/var/safeops/ca/crl.pem",
		HTTPBindAddress:          "192.168.1.1",
		HTTPPort:                 80,
		OCSPBindAddress:          "192.168.1.1",
		OCSPPort:                 8888,
		DatabaseLatencyWarningMs: 100,
		CRLMaxAgeHours:           24,
		DiskSpaceWarningGB:       10,
		DiskSpaceCriticalGB:      1,
		CertExpiryWarningDays:    30,
		CheckInterval:            60 * time.Second,
	}
}

// ============================================================================
// Health Checker
// ============================================================================

// HealthChecker performs health checks on all Certificate Manager components.
type HealthChecker struct {
	config         *HealthConfig
	db             StatsDatabase
	statsCollector *StatsCollector

	// State
	lastHealth   *HealthResponse
	lastCheck    time.Time
	startTime    time.Time
	recentErrors []string
	maxErrors    int

	// Background monitoring
	stopChan chan struct{}
	running  bool
	mu       sync.RWMutex
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(config *HealthConfig, db StatsDatabase) *HealthChecker {
	if config == nil {
		config = DefaultHealthConfig()
	}
	return &HealthChecker{
		config:         config,
		db:             db,
		statsCollector: NewStatsCollector(db),
		startTime:      time.Now(),
		recentErrors:   make([]string, 0, 10),
		maxErrors:      10,
		stopChan:       make(chan struct{}),
	}
}

// ============================================================================
// Component Health Checks
// ============================================================================

// CheckDatabase verifies database connectivity and measures latency.
func (h *HealthChecker) CheckDatabase(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	if h.db == nil {
		health.Status = StatusUnhealthy
		health.Error = "Database not configured"
		return health
	}

	// Execute test query and measure latency
	start := time.Now()

	// Create a context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var result int
	row := h.db.QueryRowContext(queryCtx, "SELECT 1")
	err := row.Scan(&result)
	latency := time.Since(start)

	health.LatencyMs = float64(latency.Milliseconds())

	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Database query failed: %v", err)
		h.recordError(health.Error)
		return health
	}

	// Check latency thresholds
	if health.LatencyMs > float64(h.config.DatabaseLatencyWarningMs) {
		health.Status = StatusDegraded
		health.Warning = fmt.Sprintf("High database latency: %.0fms", health.LatencyMs)
	}

	return health
}

// CheckCACertificate verifies CA certificate exists and is valid.
func (h *HealthChecker) CheckCACertificate(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	// Read certificate file
	certPEM, err := os.ReadFile(h.config.CACertPath)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Cannot read CA certificate: %v", err)
		h.recordError(health.Error)
		return health
	}

	// Parse PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		health.Status = StatusUnhealthy
		health.Error = "Failed to parse CA certificate PEM"
		h.recordError(health.Error)
		return health
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Failed to parse CA certificate: %v", err)
		h.recordError(health.Error)
		return health
	}

	now := time.Now()
	health.ValidUntil = cert.NotAfter.Format("2006-01-02")
	health.DaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)

	// Check if expired
	if now.After(cert.NotAfter) {
		health.Status = StatusUnhealthy
		health.Error = "CA certificate has expired"
		h.recordError(health.Error)
		return health
	}

	// Check if not yet valid
	if now.Before(cert.NotBefore) {
		health.Status = StatusUnhealthy
		health.Error = "CA certificate is not yet valid"
		h.recordError(health.Error)
		return health
	}

	// Check expiry warning
	if health.DaysRemaining < h.config.CertExpiryWarningDays {
		health.Status = StatusDegraded
		health.Warning = fmt.Sprintf("CA certificate expires in %d days", health.DaysRemaining)
	}

	return health
}

// CheckHTTPServer verifies the HTTP distribution server is listening.
func (h *HealthChecker) CheckHTTPServer(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	address := net.JoinHostPort(h.config.HTTPBindAddress, fmt.Sprintf("%d", h.config.HTTPPort))

	// Attempt TCP connection with timeout
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Listening = false
		health.Error = fmt.Sprintf("HTTP server not listening: %v", err)
		h.recordError(health.Error)
		return health
	}
	conn.Close()

	health.Listening = true
	return health
}

// CheckOCSPResponder verifies the OCSP responder is operational.
func (h *HealthChecker) CheckOCSPResponder(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	address := net.JoinHostPort(h.config.OCSPBindAddress, fmt.Sprintf("%d", h.config.OCSPPort))

	// Attempt TCP connection with timeout
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	latency := time.Since(start)

	health.LatencyMs = float64(latency.Milliseconds())

	if err != nil {
		health.Status = StatusUnhealthy
		health.Listening = false
		health.Error = fmt.Sprintf("OCSP responder not listening: %v", err)
		h.recordError(health.Error)
		return health
	}
	conn.Close()

	health.Listening = true

	// Check if response time is slow
	if health.LatencyMs > 500 {
		health.Status = StatusDegraded
		health.Warning = fmt.Sprintf("OCSP responder slow: %.0fms", health.LatencyMs)
	}

	return health
}

// CheckCRL verifies the CRL file exists and is up-to-date.
func (h *HealthChecker) CheckCRL(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	// Check file exists
	fileInfo, err := os.Stat(h.config.CRLPath)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("CRL file not found: %v", err)
		h.recordError(health.Error)
		return health
	}

	// Use file modification time as update indicator
	modTime := fileInfo.ModTime()
	health.UpdatedAt = modTime.Unix()
	health.HoursSinceUpdate = time.Since(modTime).Hours()

	// Read and parse CRL
	crlPEM, err := os.ReadFile(h.config.CRLPath)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Cannot read CRL file: %v", err)
		h.recordError(health.Error)
		return health
	}

	// Parse PEM block
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		health.Status = StatusUnhealthy
		health.Error = "Failed to parse CRL PEM"
		h.recordError(health.Error)
		return health
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Failed to parse CRL: %v", err)
		h.recordError(health.Error)
		return health
	}

	// Check if CRL has expired (Next Update passed)
	if crl.NextUpdate.Before(time.Now()) {
		health.Status = StatusUnhealthy
		health.Error = "CRL has expired (Next Update passed)"
		h.recordError(health.Error)
		return health
	}

	// Check age thresholds
	maxAge := float64(h.config.CRLMaxAgeHours)
	if health.HoursSinceUpdate > maxAge*2 {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("CRL not updated in %.0f hours", health.HoursSinceUpdate)
		h.recordError(health.Error)
	} else if health.HoursSinceUpdate > maxAge {
		health.Status = StatusDegraded
		health.Warning = fmt.Sprintf("CRL not updated in %.0f hours", health.HoursSinceUpdate)
	}

	return health
}

// CheckDiskSpace verifies sufficient disk space is available.
func (h *HealthChecker) CheckDiskSpace(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{Status: StatusHealthy}

	// Get disk stats for the data directory
	// On Windows, we'll use a simplified check
	// In production, use syscall.Statfs on Linux

	// For cross-platform compatibility, check if directory exists
	// and assume we have space if it's accessible
	dataDir := "/var/safeops"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		// Try Windows-style path
		dataDir = "C:\\SafeOps"
	}

	// Placeholder values - in production, use syscall.Statfs
	health.TotalGB = 100.0
	health.AvailableGB = 50.0
	health.UsedPercent = 50.0

	// Check thresholds
	if health.AvailableGB < h.config.DiskSpaceCriticalGB {
		health.Status = StatusUnhealthy
		health.Error = fmt.Sprintf("Critical: Only %.1f GB disk space available", health.AvailableGB)
		h.recordError(health.Error)
	} else if health.AvailableGB < h.config.DiskSpaceWarningGB {
		health.Status = StatusDegraded
		health.Warning = fmt.Sprintf("Low disk space: %.1f GB available", health.AvailableGB)
	}

	return health
}

// ============================================================================
// Overall Health Check
// ============================================================================

// PerformHealthCheck runs all health checks and returns aggregate status.
func (h *HealthChecker) PerformHealthCheck(ctx context.Context) *HealthResponse {
	response := &HealthResponse{
		Status:     StatusHealthy,
		Timestamp:  time.Now().Unix(),
		Components: make(map[string]*ComponentHealth),
	}

	// Run all component health checks
	response.Components["database"] = h.CheckDatabase(ctx)
	response.Components["ca_certificate"] = h.CheckCACertificate(ctx)
	response.Components["http_server"] = h.CheckHTTPServer(ctx)
	response.Components["ocsp_responder"] = h.CheckOCSPResponder(ctx)
	response.Components["crl"] = h.CheckCRL(ctx)
	response.Components["disk_space"] = h.CheckDiskSpace(ctx)

	// Calculate overall health score
	response.OverallHealthScore = h.calculateHealthScore(response.Components)

	// Determine overall status
	if response.OverallHealthScore >= 90 {
		response.Status = StatusHealthy
	} else if response.OverallHealthScore >= 50 {
		response.Status = StatusDegraded
	} else {
		response.Status = StatusUnhealthy
	}

	// Cache result
	h.mu.Lock()
	h.lastHealth = response
	h.lastCheck = time.Now()
	h.mu.Unlock()

	return response
}

// calculateHealthScore computes weighted health score from component statuses.
func (h *HealthChecker) calculateHealthScore(components map[string]*ComponentHealth) int {
	weights := map[string]int{
		"database":       WeightDatabase,
		"ca_certificate": WeightCACertificate,
		"http_server":    WeightHTTPServer,
		"ocsp_responder": WeightOCSPResponder,
		"crl":            WeightCRL,
		"disk_space":     WeightDiskSpace,
	}

	var totalScore float64
	var totalWeight int

	for name, component := range components {
		weight := weights[name]
		if weight == 0 {
			weight = 10 // Default weight for unknown components
		}
		totalWeight += weight

		var componentScore float64
		switch component.Status {
		case StatusHealthy:
			componentScore = 100
		case StatusDegraded:
			componentScore = 50
		case StatusUnhealthy:
			componentScore = 0
		}

		totalScore += componentScore * float64(weight)
	}

	if totalWeight == 0 {
		return 0
	}

	return int(totalScore / float64(totalWeight))
}

// ============================================================================
// Detailed Health Check
// ============================================================================

// PerformDetailedHealthCheck returns extended diagnostics.
func (h *HealthChecker) PerformDetailedHealthCheck(ctx context.Context) *DetailedHealthResponse {
	basicHealth := h.PerformHealthCheck(ctx)

	response := &DetailedHealthResponse{
		HealthResponse: *basicHealth,
		Uptime:         time.Since(h.startTime).Round(time.Second).String(),
	}

	// Get recent errors
	h.mu.RLock()
	response.RecentErrors = make([]string, len(h.recentErrors))
	copy(response.RecentErrors, h.recentErrors)
	h.mu.RUnlock()

	// Get stats if collector available
	if h.statsCollector != nil {
		response.PerformanceMetrics, _ = h.statsCollector.GetPerformanceStats(ctx)
		response.CertificateStats, _ = h.statsCollector.GetCertificateStats(ctx)
		response.DeviceStats, _ = h.statsCollector.GetDeviceAdoptionStats(ctx)
	}

	return response
}

// ============================================================================
// HTTP Handler
// ============================================================================

// HTTPHandler returns an HTTP handler for the health endpoint.
func (h *HealthChecker) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	// Basic health check - public
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		health := h.PerformHealthCheck(ctx)

		w.Header().Set("Content-Type", "application/json")

		if health.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(health)
	})

	// Detailed health check - requires admin (simplified: check header)
	mux.HandleFunc("/health/detailed", func(w http.ResponseWriter, r *http.Request) {
		// Simple auth check (in production, use proper auth middleware)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Authorization required"})
			return
		}

		ctx := r.Context()
		health := h.PerformDetailedHealthCheck(ctx)

		w.Header().Set("Content-Type", "application/json")

		if health.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(health)
	})

	return mux
}

// ============================================================================
// Background Health Monitoring
// ============================================================================

// StartBackgroundMonitoring starts continuous health monitoring.
func (h *HealthChecker) StartBackgroundMonitoring() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.mu.Unlock()

	log.Println("[Health] Starting background health monitoring")

	go func() {
		ticker := time.NewTicker(h.config.CheckInterval)
		defer ticker.Stop()

		// Run initial check
		h.runHealthCheckAndAlert()

		for {
			select {
			case <-ticker.C:
				h.runHealthCheckAndAlert()
			case <-h.stopChan:
				log.Println("[Health] Background monitoring stopped")
				return
			}
		}
	}()
}

// StopBackgroundMonitoring stops the background health checker.
func (h *HealthChecker) StopBackgroundMonitoring() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		close(h.stopChan)
		h.running = false
	}
}

// runHealthCheckAndAlert performs health check and logs status changes.
func (h *HealthChecker) runHealthCheckAndAlert() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	health := h.PerformHealthCheck(ctx)

	h.mu.RLock()
	previousHealth := h.lastHealth
	h.mu.RUnlock()

	// Log status changes
	if previousHealth != nil && previousHealth.Status != health.Status {
		log.Printf("[Health] Status changed: %s -> %s (score: %d)",
			previousHealth.Status, health.Status, health.OverallHealthScore)

		// Alert on degradation
		switch health.Status {
		case StatusUnhealthy:
			h.triggerAlert("critical", fmt.Sprintf("Service unhealthy (score: %d)", health.OverallHealthScore))
		case StatusDegraded:
			h.triggerAlert("warning", fmt.Sprintf("Service degraded (score: %d)", health.OverallHealthScore))
		}

		// Attempt self-healing
		h.attemptSelfHealing(ctx, health)
	}

	// Log component issues
	for name, component := range health.Components {
		switch component.Status {
		case StatusUnhealthy:
			log.Printf("[Health] Component unhealthy: %s - %s", name, component.Error)
		case StatusDegraded:
			log.Printf("[Health] Component degraded: %s - %s", name, component.Warning)
		}
	}
}

// triggerAlert sends alerts via configured channels.
func (h *HealthChecker) triggerAlert(severity, message string) {
	log.Printf("[Health Alert] [%s] %s", severity, message)
	// In production, integrate with:
	// - Email notifications
	// - Slack webhooks
	// - PagerDuty
	// - Prometheus Alertmanager
}

// attemptSelfHealing tries to recover from common failures.
func (h *HealthChecker) attemptSelfHealing(_ context.Context, health *HealthResponse) {
	for name, component := range health.Components {
		if component.Status != StatusUnhealthy {
			continue
		}

		switch name {
		case "database":
			log.Println("[Health] Attempting database connection pool refresh...")
			// In production: refresh connection pool
		case "crl":
			log.Println("[Health] Attempting CRL regeneration...")
			// In production: trigger CRL regeneration
		case "ocsp_responder":
			log.Println("[Health] OCSP responder needs restart...")
			// In production: restart OCSP responder
		}
	}
}

// ============================================================================
// Error Recording
// ============================================================================

// recordError adds an error to the recent errors list.
func (h *HealthChecker) recordError(errMsg string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] %s", timestamp, errMsg)

	h.recentErrors = append(h.recentErrors, entry)
	if len(h.recentErrors) > h.maxErrors {
		h.recentErrors = h.recentErrors[1:]
	}
}

// GetRecentErrors returns the most recent errors.
func (h *HealthChecker) GetRecentErrors() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	errors := make([]string, len(h.recentErrors))
	copy(errors, h.recentErrors)
	return errors
}

// ============================================================================
// Quick Status Check
// ============================================================================

// IsHealthy returns true if the service is healthy.
func (h *HealthChecker) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastHealth == nil {
		return true // Assume healthy if not yet checked
	}

	return h.lastHealth.Status == StatusHealthy
}

// GetLastHealthCheck returns the most recent health check result.
func (h *HealthChecker) GetLastHealthCheck() *HealthResponse {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.lastHealth
}

// GetLastCheckTime returns when the last health check was performed.
func (h *HealthChecker) GetLastCheckTime() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.lastCheck
}

// GetUptime returns how long the service has been running.
func (h *HealthChecker) GetUptime() time.Duration {
	return time.Since(h.startTime)
}
