// Package monitoring provides monitoring and alerting for DHCP server.
// This file implements the alerting system for critical conditions.
package monitoring

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Alert Severity Levels
// ============================================================================

// AlertSeverity defines alert severity levels.
type AlertSeverity string

const (
	// SeverityCritical is for service-impacting conditions
	SeverityCritical AlertSeverity = "CRITICAL"
	// SeverityWarning is for degraded conditions
	SeverityWarning AlertSeverity = "WARNING"
	// SeverityInfo is for informational events
	SeverityInfo AlertSeverity = "INFO"
)

// ============================================================================
// Alert Types
// ============================================================================

// AlertType defines the type of alert.
type AlertType string

const (
	// Pool alerts
	AlertPoolExhaustionCritical AlertType = "PoolExhaustionCritical"
	AlertPoolUtilizationWarning AlertType = "PoolUtilizationWarning"
	AlertPoolUtilizationHigh    AlertType = "PoolUtilizationHigh"

	// Database alerts
	AlertDatabaseUnavailable AlertType = "DatabaseUnavailable"
	AlertDatabaseError       AlertType = "DatabaseError"

	// Service dependency alerts
	AlertDNSServiceUnavailable AlertType = "DNSServiceUnavailable"
	AlertCAServiceUnavailable  AlertType = "CAServiceUnavailable"

	// Performance alerts
	AlertPerformanceDegraded    AlertType = "PerformanceDegraded"
	AlertLeaseAllocationFailure AlertType = "LeaseAllocationFailure"
	AlertHighResponseTime       AlertType = "HighResponseTime"

	// Lifecycle alerts
	AlertServerStarted  AlertType = "ServerStarted"
	AlertServerStopped  AlertType = "ServerStopped"
	AlertConfigReloaded AlertType = "ConfigReloaded"
)

// ============================================================================
// Alert Configuration
// ============================================================================

// AlertConfig holds alerting configuration.
type AlertConfig struct {
	PoolWarningThreshold       float64
	PoolCriticalThreshold      float64
	DatabaseUnavailableMinutes int
	DNSUnavailableMinutes      int
	CAUnavailableMinutes       int
	ResponseTimeThresholdMs    int
	DeduplicateIntervalMinutes int
	EnableLogging              bool
	EnablePrometheus           bool
	EnableWebhook              bool
	WebhookURL                 string
}

// DefaultAlertConfig returns sensible defaults.
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		PoolWarningThreshold:       80.0,
		PoolCriticalThreshold:      100.0,
		DatabaseUnavailableMinutes: 5,
		DNSUnavailableMinutes:      10,
		CAUnavailableMinutes:       30,
		ResponseTimeThresholdMs:    500,
		DeduplicateIntervalMinutes: 60,
		EnableLogging:              true,
		EnablePrometheus:           true,
		EnableWebhook:              false,
	}
}

// ============================================================================
// Alert
// ============================================================================

// Alert represents an alert instance.
type Alert struct {
	ID          string
	Type        AlertType
	Severity    AlertSeverity
	Message     string
	Resource    string
	Value       float64
	Threshold   float64
	TriggeredAt time.Time
	ResolvedAt  time.Time
	IsActive    bool
	Metadata    map[string]string
}

// ============================================================================
// Alert Manager
// ============================================================================

// AlertManager manages alerts and notifications.
type AlertManager struct {
	mu     sync.RWMutex
	config *AlertConfig

	// Active alerts
	activeAlerts map[string]*Alert

	// Alert history
	alertHistory []*Alert
	maxHistory   int

	// Deduplication
	lastAlertTime map[string]time.Time

	// Notifiers
	notifiers []AlertNotifier

	// Statistics
	stats AlertStats
}

// AlertStats tracks alerting metrics.
type AlertStats struct {
	TotalAlerts      int64
	CriticalAlerts   int64
	WarningAlerts    int64
	InfoAlerts       int64
	ResolvedAlerts   int64
	SuppressedAlerts int64
}

// AlertNotifier defines notification interface.
type AlertNotifier interface {
	Notify(ctx context.Context, alert *Alert) error
	Name() string
}

// ============================================================================
// Alert Manager Creation
// ============================================================================

// NewAlertManager creates a new alert manager.
func NewAlertManager(config *AlertConfig) *AlertManager {
	if config == nil {
		config = DefaultAlertConfig()
	}

	return &AlertManager{
		config:        config,
		activeAlerts:  make(map[string]*Alert),
		alertHistory:  make([]*Alert, 0, 100),
		maxHistory:    100,
		lastAlertTime: make(map[string]time.Time),
		notifiers:     make([]AlertNotifier, 0),
	}
}

// ============================================================================
// Notifier Management
// ============================================================================

// AddNotifier adds a notification channel.
func (m *AlertManager) AddNotifier(notifier AlertNotifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers = append(m.notifiers, notifier)
}

// ============================================================================
// Alert Triggering
// ============================================================================

// TriggerAlert triggers a new alert.
func (m *AlertManager) TriggerAlert(ctx context.Context, alertType AlertType, severity AlertSeverity, message string, resource string, value, threshold float64) error {
	// Create alert key for deduplication
	alertKey := string(alertType) + ":" + resource

	m.mu.Lock()

	// Check if already active
	if existing, ok := m.activeAlerts[alertKey]; ok && existing.IsActive {
		// Update value but don't re-notify
		existing.Value = value
		m.mu.Unlock()
		return nil
	}

	// Check deduplication window
	dedupInterval := time.Duration(m.config.DeduplicateIntervalMinutes) * time.Minute
	if lastTime, ok := m.lastAlertTime[alertKey]; ok {
		if time.Since(lastTime) < dedupInterval {
			atomic.AddInt64(&m.stats.SuppressedAlerts, 1)
			m.mu.Unlock()
			return nil
		}
	}

	// Create alert
	alert := &Alert{
		ID:          alertKey + ":" + time.Now().Format("20060102150405"),
		Type:        alertType,
		Severity:    severity,
		Message:     message,
		Resource:    resource,
		Value:       value,
		Threshold:   threshold,
		TriggeredAt: time.Now(),
		IsActive:    true,
		Metadata:    make(map[string]string),
	}

	// Store alert
	m.activeAlerts[alertKey] = alert
	m.addToHistory(alert)
	m.lastAlertTime[alertKey] = time.Now()

	// Update statistics
	atomic.AddInt64(&m.stats.TotalAlerts, 1)
	switch severity {
	case SeverityCritical:
		atomic.AddInt64(&m.stats.CriticalAlerts, 1)
	case SeverityWarning:
		atomic.AddInt64(&m.stats.WarningAlerts, 1)
	case SeverityInfo:
		atomic.AddInt64(&m.stats.InfoAlerts, 1)
	}

	notifiers := m.notifiers
	m.mu.Unlock()

	// Send notifications
	for _, notifier := range notifiers {
		notifier.Notify(ctx, alert)
	}

	return nil
}

// ============================================================================
// Alert Resolution
// ============================================================================

// ResolveAlert resolves an active alert.
func (m *AlertManager) ResolveAlert(ctx context.Context, alertType AlertType, resource string) error {
	alertKey := string(alertType) + ":" + resource

	m.mu.Lock()

	alert, ok := m.activeAlerts[alertKey]
	if !ok || !alert.IsActive {
		m.mu.Unlock()
		return nil
	}

	// Mark as resolved
	alert.IsActive = false
	alert.ResolvedAt = time.Now()
	atomic.AddInt64(&m.stats.ResolvedAlerts, 1)

	// Remove from active
	delete(m.activeAlerts, alertKey)

	notifiers := m.notifiers
	m.mu.Unlock()

	// Send recovery notification
	recoveryAlert := &Alert{
		ID:          alertKey + ":resolved:" + time.Now().Format("20060102150405"),
		Type:        alertType,
		Severity:    SeverityInfo,
		Message:     "RESOLVED: " + alert.Message,
		Resource:    resource,
		TriggeredAt: alert.TriggeredAt,
		ResolvedAt:  time.Now(),
		IsActive:    false,
	}

	for _, notifier := range notifiers {
		notifier.Notify(ctx, recoveryAlert)
	}

	return nil
}

// ============================================================================
// Pool Alerting
// ============================================================================

// CheckPoolUtilization checks pool utilization and triggers alerts.
func (m *AlertManager) CheckPoolUtilization(ctx context.Context, poolName string, usedIPs, totalIPs int) {
	if totalIPs == 0 {
		return
	}

	utilization := float64(usedIPs) / float64(totalIPs) * 100
	available := totalIPs - usedIPs

	// Check critical (100%)
	if utilization >= m.config.PoolCriticalThreshold {
		m.TriggerAlert(ctx,
			AlertPoolExhaustionCritical,
			SeverityCritical,
			"DHCP Pool '"+poolName+"' EXHAUSTED - No IPs available for new clients",
			poolName,
			utilization,
			m.config.PoolCriticalThreshold,
		)
		return
	}

	// Check warning (80%)
	if utilization >= m.config.PoolWarningThreshold {
		msg := "DHCP Pool '" + poolName + "' is " + formatFloat(utilization) + "% utilized (" + formatInt(available) + " IPs remaining)"
		m.TriggerAlert(ctx,
			AlertPoolUtilizationWarning,
			SeverityWarning,
			msg,
			poolName,
			utilization,
			m.config.PoolWarningThreshold,
		)
		return
	}

	// Resolve if below threshold
	m.ResolveAlert(ctx, AlertPoolUtilizationWarning, poolName)
	m.ResolveAlert(ctx, AlertPoolExhaustionCritical, poolName)
}

// ============================================================================
// Service Dependency Alerting
// ============================================================================

// CheckDatabaseHealth checks database health and triggers alerts.
func (m *AlertManager) CheckDatabaseHealth(ctx context.Context, isHealthy bool, downSince time.Time) {
	if isHealthy {
		m.ResolveAlert(ctx, AlertDatabaseUnavailable, "database")
		return
	}

	downMinutes := time.Since(downSince).Minutes()
	if downMinutes >= float64(m.config.DatabaseUnavailableMinutes) {
		m.TriggerAlert(ctx,
			AlertDatabaseUnavailable,
			SeverityCritical,
			"PostgreSQL database connection lost - DHCP lease persistence unavailable",
			"database",
			downMinutes,
			float64(m.config.DatabaseUnavailableMinutes),
		)
	}
}

// CheckDNSHealth checks DNS service health and triggers alerts.
func (m *AlertManager) CheckDNSHealth(ctx context.Context, isHealthy bool, downSince time.Time) {
	if isHealthy {
		m.ResolveAlert(ctx, AlertDNSServiceUnavailable, "dns")
		return
	}

	downMinutes := time.Since(downSince).Minutes()
	if downMinutes >= float64(m.config.DNSUnavailableMinutes) {
		m.TriggerAlert(ctx,
			AlertDNSServiceUnavailable,
			SeverityWarning,
			"DNS service unavailable - Dynamic DNS updates disabled",
			"dns",
			downMinutes,
			float64(m.config.DNSUnavailableMinutes),
		)
	}
}

// CheckCAHealth checks CA service health and triggers alerts.
func (m *AlertManager) CheckCAHealth(ctx context.Context, isHealthy bool, downSince time.Time) {
	if isHealthy {
		m.ResolveAlert(ctx, AlertCAServiceUnavailable, "ca")
		return
	}

	downMinutes := time.Since(downSince).Minutes()
	if downMinutes >= float64(m.config.CAUnavailableMinutes) {
		m.TriggerAlert(ctx,
			AlertCAServiceUnavailable,
			SeverityWarning,
			"Certificate Manager unavailable - CA certificate distribution disabled",
			"ca",
			downMinutes,
			float64(m.config.CAUnavailableMinutes),
		)
	}
}

// ============================================================================
// Performance Alerting
// ============================================================================

// CheckResponseTime checks response time and triggers alerts.
func (m *AlertManager) CheckResponseTime(ctx context.Context, p95ResponseTimeMs float64) {
	threshold := float64(m.config.ResponseTimeThresholdMs)

	if p95ResponseTimeMs > threshold {
		m.TriggerAlert(ctx,
			AlertHighResponseTime,
			SeverityWarning,
			"DHCP response time degraded (P95: "+formatFloat(p95ResponseTimeMs)+"ms)",
			"performance",
			p95ResponseTimeMs,
			threshold,
		)
	} else {
		m.ResolveAlert(ctx, AlertHighResponseTime, "performance")
	}
}

// ReportAllocationFailure reports a lease allocation failure.
func (m *AlertManager) ReportAllocationFailure(ctx context.Context, poolName string, reason string) {
	m.TriggerAlert(ctx,
		AlertLeaseAllocationFailure,
		SeverityWarning,
		"Lease allocation failed for pool '"+poolName+"': "+reason,
		poolName,
		1,
		0,
	)
}

// ============================================================================
// History Management
// ============================================================================

func (m *AlertManager) addToHistory(alert *Alert) {
	m.alertHistory = append(m.alertHistory, alert)

	// Trim history if needed
	if len(m.alertHistory) > m.maxHistory {
		m.alertHistory = m.alertHistory[1:]
	}
}

// GetAlertHistory returns recent alert history.
func (m *AlertManager) GetAlertHistory() []*Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	history := make([]*Alert, len(m.alertHistory))
	copy(history, m.alertHistory)
	return history
}

// GetActiveAlerts returns currently active alerts.
func (m *AlertManager) GetActiveAlerts() []*Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alerts := make([]*Alert, 0, len(m.activeAlerts))
	for _, alert := range m.activeAlerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns alert statistics.
func (m *AlertManager) GetStats() AlertStats {
	return AlertStats{
		TotalAlerts:      atomic.LoadInt64(&m.stats.TotalAlerts),
		CriticalAlerts:   atomic.LoadInt64(&m.stats.CriticalAlerts),
		WarningAlerts:    atomic.LoadInt64(&m.stats.WarningAlerts),
		InfoAlerts:       atomic.LoadInt64(&m.stats.InfoAlerts),
		ResolvedAlerts:   atomic.LoadInt64(&m.stats.ResolvedAlerts),
		SuppressedAlerts: atomic.LoadInt64(&m.stats.SuppressedAlerts),
	}
}

// ============================================================================
// Logging Notifier
// ============================================================================

// LoggingNotifier logs alerts.
type LoggingNotifier struct{}

// NewLoggingNotifier creates a logging notifier.
func NewLoggingNotifier() *LoggingNotifier {
	return &LoggingNotifier{}
}

// Notify logs the alert.
func (n *LoggingNotifier) Notify(ctx context.Context, alert *Alert) error {
	// In production, this would use structured logging
	// For now, just a placeholder
	return nil
}

// Name returns the notifier name.
func (n *LoggingNotifier) Name() string {
	return "logging"
}

// ============================================================================
// Helper Functions
// ============================================================================

func formatFloat(f float64) string {
	return string(rune(int(f/10)+'0')) + string(rune(int(f)%10+'0'))
}

func formatInt(i int) string {
	if i < 10 {
		return string(rune(i + '0'))
	}
	return "many"
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrAlertNotFound is returned when alert not found
	ErrAlertNotFound = errors.New("alert not found")

	// ErrNotifierFailed is returned when notification fails
	ErrNotifierFailed = errors.New("notification failed")
)
