// Package monitoring provides statistical reporting and health monitoring for Certificate Manager.
package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Database Interface
// ============================================================================

// StatsDatabase provides database query methods for statistics.
type StatsDatabase interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// ============================================================================
// Certificate Statistics
// ============================================================================

// CertificateStats contains metrics related to issued certificates.
type CertificateStats struct {
	TotalIssued             int       `json:"total_issued"`
	ActiveCertificates      int       `json:"active_certificates"`
	ExpiredCertificates     int       `json:"expired_certificates"`
	RevokedCertificates     int       `json:"revoked_certificates"`
	ExpiringSoon30Days      int       `json:"expiring_soon_30d"`
	ExpiringSoon7Days       int       `json:"expiring_soon_7d"`
	AverageValidityDays     float64   `json:"average_validity_days"`
	CertificatesIssuedToday int       `json:"certificates_issued_today"`
	CertificatesIssuedWeek  int       `json:"certificates_issued_this_week"`
	CertificatesIssuedMonth int       `json:"certificates_issued_this_month"`
	LastUpdated             time.Time `json:"last_updated"`
}

// ============================================================================
// Device Adoption Statistics
// ============================================================================

// DeviceAdoptionStats contains metrics on CA adoption across devices.
type DeviceAdoptionStats struct {
	TotalDevices          int       `json:"total_devices"`
	DevicesWithCA         int       `json:"devices_with_ca"`
	DevicesWithoutCA      int       `json:"devices_without_ca"`
	AdoptionPercentage    float64   `json:"adoption_percentage"`
	NewDevicesToday       int       `json:"new_devices_today"`
	InstallationsToday    int       `json:"installations_today"`
	InstallationsThisWeek int       `json:"installations_this_week"`
	GrowthVelocity        float64   `json:"growth_velocity_per_day"`
	LastUpdated           time.Time `json:"last_updated"`
}

// ============================================================================
// Download Statistics
// ============================================================================

// DownloadStats contains metrics on CA certificate downloads.
type DownloadStats struct {
	TotalDownloads         int            `json:"total_downloads"`
	DownloadsToday         int            `json:"downloads_today"`
	DownloadsThisWeek      int            `json:"downloads_this_week"`
	DownloadsByFormat      map[string]int `json:"downloads_by_format"`
	UniqueIPs              int            `json:"unique_ips"`
	MostPopularFormat      string         `json:"most_popular_format"`
	DownloadConversionRate float64        `json:"download_conversion_rate"`
	LastUpdated            time.Time      `json:"last_updated"`
}

// ============================================================================
// Revocation Statistics
// ============================================================================

// RevocationStats contains metrics on certificate revocations.
type RevocationStats struct {
	TotalRevoked        int            `json:"total_revoked"`
	RevokedToday        int            `json:"revoked_today"`
	RevokedThisWeek     int            `json:"revoked_this_week"`
	RevocationsByReason map[string]int `json:"revocations_by_reason"`
	MostCommonReason    string         `json:"most_common_reason"`
	RevocationRate      float64        `json:"revocation_rate"`
	CRLSizeBytes        int64          `json:"crl_size_bytes"`
	CRLUpdatedAt        time.Time      `json:"crl_updated_at"`
	LastUpdated         time.Time      `json:"last_updated"`
}

// ============================================================================
// Performance Statistics
// ============================================================================

// PerformanceStats contains system performance metrics.
type PerformanceStats struct {
	AvgCertificateSigningMs float64   `json:"avg_certificate_signing_ms"`
	AvgRevocationCheckMs    float64   `json:"avg_revocation_check_ms"`
	CacheHitRate            float64   `json:"cache_hit_rate"`
	DatabaseQueryAvgMs      float64   `json:"database_query_avg_ms"`
	GRPCRequestCount        int64     `json:"grpc_request_count"`
	GRPCErrorRate           float64   `json:"grpc_error_rate"`
	LastUpdated             time.Time `json:"last_updated"`
}

// ============================================================================
// Alert Thresholds
// ============================================================================

// AlertThresholds defines thresholds for alerting.
type AlertThresholds struct {
	// Certificate alerts
	ExpiringSoonWarning int     // Warn if > N certificates expiring soon
	RevocationRateMax   float64 // Alert if revocation rate > N%
	IssuanceSpikeFactor float64 // Alert if issuance > N * average

	// Device adoption alerts
	AdoptionRateMin   float64 // Alert if adoption < N%
	ConversionRateMin float64 // Alert if download→install < N%
	StaleGrowthDays   int     // Alert if no growth in N days

	// Performance alerts
	CertSigningMaxMs float64 // Alert if signing > N ms
	CacheHitRateMin  float64 // Alert if cache hit < N%
	GRPCErrorRateMax float64 // Alert if error rate > N%

	// System health alerts
	CRLStaleHours int // Alert if CRL not updated in N hours
}

// DefaultAlertThresholds returns sensible default thresholds.
func DefaultAlertThresholds() *AlertThresholds {
	return &AlertThresholds{
		ExpiringSoonWarning: 10,
		RevocationRateMax:   5.0,
		IssuanceSpikeFactor: 2.0,
		AdoptionRateMin:     90.0,
		ConversionRateMin:   80.0,
		StaleGrowthDays:     7,
		CertSigningMaxMs:    500.0,
		CacheHitRateMin:     70.0,
		GRPCErrorRateMax:    5.0,
		CRLStaleHours:       25,
	}
}

// ============================================================================
// Stats Collector
// ============================================================================

// StatsCollector aggregates statistics from multiple sources.
type StatsCollector struct {
	db         StatsDatabase
	thresholds *AlertThresholds

	// Cache
	certStatsCache        *CertificateStats
	deviceStatsCache      *DeviceAdoptionStats
	downloadStatsCache    *DownloadStats
	revocationStatsCache  *RevocationStats
	performanceStatsCache *PerformanceStats
	cacheTTL              time.Duration
	mu                    sync.RWMutex
}

// NewStatsCollector creates a new statistics collector.
func NewStatsCollector(db StatsDatabase) *StatsCollector {
	return &StatsCollector{
		db:         db,
		thresholds: DefaultAlertThresholds(),
		cacheTTL:   5 * time.Minute,
	}
}

// SetThresholds updates alert thresholds.
func (s *StatsCollector) SetThresholds(thresholds *AlertThresholds) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thresholds = thresholds
}

// InvalidateCache clears all cached statistics.
func (s *StatsCollector) InvalidateCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certStatsCache = nil
	s.deviceStatsCache = nil
	s.downloadStatsCache = nil
	s.revocationStatsCache = nil
	s.performanceStatsCache = nil
	log.Println("[Stats] Cache invalidated")
}

// ============================================================================
// Certificate Statistics
// ============================================================================

// GetCertificateStats returns certificate-related statistics.
func (s *StatsCollector) GetCertificateStats(ctx context.Context) (*CertificateStats, error) {
	s.mu.RLock()
	if s.certStatsCache != nil && time.Since(s.certStatsCache.LastUpdated) < s.cacheTTL {
		defer s.mu.RUnlock()
		return s.certStatsCache, nil
	}
	s.mu.RUnlock()

	log.Println("[Stats] Fetching certificate statistics from database")

	stats := &CertificateStats{
		LastUpdated: time.Now(),
	}

	if s.db == nil {
		return stats, nil
	}

	// Total issued
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates").Scan(&stats.TotalIssued)

	// Active certificates (valid and not revoked)
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE not_after > NOW() 
		AND serial_number NOT IN (SELECT serial_number FROM revoked_certificates)`).
		Scan(&stats.ActiveCertificates)

	// Expired certificates
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE not_after < NOW()").
		Scan(&stats.ExpiredCertificates)

	// Revoked certificates
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM revoked_certificates").Scan(&stats.RevokedCertificates)

	// Expiring soon (30 days)
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
		AND serial_number NOT IN (SELECT serial_number FROM revoked_certificates)`).
		Scan(&stats.ExpiringSoon30Days)

	// Expiring soon (7 days)
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '7 days'
		AND serial_number NOT IN (SELECT serial_number FROM revoked_certificates)`).
		Scan(&stats.ExpiringSoon7Days)

	// Average validity days
	s.db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(EXTRACT(DAY FROM (not_after - not_before))), 0) 
		FROM issued_certificates`).Scan(&stats.AverageValidityDays)

	// Issued today
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE created_at::DATE = CURRENT_DATE`).Scan(&stats.CertificatesIssuedToday)

	// Issued this week
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE created_at > NOW() - INTERVAL '7 days'`).Scan(&stats.CertificatesIssuedWeek)

	// Issued this month
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM issued_certificates 
		WHERE created_at > NOW() - INTERVAL '30 days'`).Scan(&stats.CertificatesIssuedMonth)

	// Cache results
	s.mu.Lock()
	s.certStatsCache = stats
	s.mu.Unlock()

	return stats, nil
}

// ============================================================================
// Device Adoption Statistics
// ============================================================================

// GetDeviceAdoptionStats returns device CA adoption statistics.
func (s *StatsCollector) GetDeviceAdoptionStats(ctx context.Context) (*DeviceAdoptionStats, error) {
	s.mu.RLock()
	if s.deviceStatsCache != nil && time.Since(s.deviceStatsCache.LastUpdated) < s.cacheTTL {
		defer s.mu.RUnlock()
		return s.deviceStatsCache, nil
	}
	s.mu.RUnlock()

	log.Println("[Stats] Fetching device adoption statistics from database")

	stats := &DeviceAdoptionStats{
		LastUpdated: time.Now(),
	}

	if s.db == nil {
		return stats, nil
	}

	// Total devices
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM device_ca_status").Scan(&stats.TotalDevices)

	// Devices with CA installed
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM device_ca_status WHERE ca_installed = true").
		Scan(&stats.DevicesWithCA)

	// Devices without CA
	stats.DevicesWithoutCA = stats.TotalDevices - stats.DevicesWithCA

	// Adoption percentage
	if stats.TotalDevices > 0 {
		stats.AdoptionPercentage = float64(stats.DevicesWithCA) / float64(stats.TotalDevices) * 100
	}

	// New devices today
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM device_ca_status 
		WHERE created_at::DATE = CURRENT_DATE`).Scan(&stats.NewDevicesToday)

	// Installations today
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM device_ca_status 
		WHERE detected_at::DATE = CURRENT_DATE AND ca_installed = true`).
		Scan(&stats.InstallationsToday)

	// Installations this week
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM device_ca_status 
		WHERE detected_at > NOW() - INTERVAL '7 days' AND ca_installed = true`).
		Scan(&stats.InstallationsThisWeek)

	// Growth velocity (installations per day over past 7 days)
	if stats.InstallationsThisWeek > 0 {
		stats.GrowthVelocity = float64(stats.InstallationsThisWeek) / 7.0
	}

	// Cache results
	s.mu.Lock()
	s.deviceStatsCache = stats
	s.mu.Unlock()

	return stats, nil
}

// ============================================================================
// Download Statistics
// ============================================================================

// GetDownloadStats returns CA certificate download statistics.
func (s *StatsCollector) GetDownloadStats(ctx context.Context) (*DownloadStats, error) {
	s.mu.RLock()
	if s.downloadStatsCache != nil && time.Since(s.downloadStatsCache.LastUpdated) < s.cacheTTL {
		defer s.mu.RUnlock()
		return s.downloadStatsCache, nil
	}
	s.mu.RUnlock()

	log.Println("[Stats] Fetching download statistics from database")

	stats := &DownloadStats{
		DownloadsByFormat: make(map[string]int),
		LastUpdated:       time.Now(),
	}

	if s.db == nil {
		return stats, nil
	}

	// Total downloads
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM certificate_downloads").Scan(&stats.TotalDownloads)

	// Downloads today
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM certificate_downloads 
		WHERE downloaded_at::DATE = CURRENT_DATE`).Scan(&stats.DownloadsToday)

	// Downloads this week
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM certificate_downloads 
		WHERE downloaded_at > NOW() - INTERVAL '7 days'`).Scan(&stats.DownloadsThisWeek)

	// Downloads by format
	rows, err := s.db.QueryContext(ctx, `
		SELECT format, COUNT(*) FROM certificate_downloads 
		GROUP BY format`)
	if err == nil {
		defer rows.Close()
		maxCount := 0
		for rows.Next() {
			var format string
			var count int
			if err := rows.Scan(&format, &count); err == nil {
				stats.DownloadsByFormat[format] = count
				if count > maxCount {
					maxCount = count
					stats.MostPopularFormat = format
				}
			}
		}
	}

	// Unique IPs
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT device_ip) FROM certificate_downloads`).
		Scan(&stats.UniqueIPs)

	// Download conversion rate
	var devicesWithCA int
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM device_ca_status WHERE ca_installed = true").
		Scan(&devicesWithCA)
	if stats.TotalDownloads > 0 {
		stats.DownloadConversionRate = float64(devicesWithCA) / float64(stats.TotalDownloads) * 100
		// Cap at 100% (some devices may install without download tracking)
		if stats.DownloadConversionRate > 100 {
			stats.DownloadConversionRate = 100
		}
	}

	// Cache results
	s.mu.Lock()
	s.downloadStatsCache = stats
	s.mu.Unlock()

	return stats, nil
}

// ============================================================================
// Revocation Statistics
// ============================================================================

// GetRevocationStats returns certificate revocation statistics.
func (s *StatsCollector) GetRevocationStats(ctx context.Context) (*RevocationStats, error) {
	s.mu.RLock()
	if s.revocationStatsCache != nil && time.Since(s.revocationStatsCache.LastUpdated) < s.cacheTTL {
		defer s.mu.RUnlock()
		return s.revocationStatsCache, nil
	}
	s.mu.RUnlock()

	log.Println("[Stats] Fetching revocation statistics from database")

	stats := &RevocationStats{
		RevocationsByReason: make(map[string]int),
		LastUpdated:         time.Now(),
	}

	if s.db == nil {
		return stats, nil
	}

	// Total revoked
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM revoked_certificates").Scan(&stats.TotalRevoked)

	// Revoked today
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM revoked_certificates 
		WHERE revoked_at::DATE = CURRENT_DATE`).Scan(&stats.RevokedToday)

	// Revoked this week
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM revoked_certificates 
		WHERE revoked_at > NOW() - INTERVAL '7 days'`).Scan(&stats.RevokedThisWeek)

	// Revocations by reason
	rows, err := s.db.QueryContext(ctx, `
		SELECT revocation_reason, COUNT(*) FROM revoked_certificates 
		GROUP BY revocation_reason`)
	if err == nil {
		defer rows.Close()
		maxCount := 0
		for rows.Next() {
			var reason string
			var count int
			if err := rows.Scan(&reason, &count); err == nil {
				stats.RevocationsByReason[reason] = count
				if count > maxCount {
					maxCount = count
					stats.MostCommonReason = reason
				}
			}
		}
	}

	// Revocation rate
	var totalIssued int
	s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates").Scan(&totalIssued)
	if totalIssued > 0 {
		stats.RevocationRate = float64(stats.TotalRevoked) / float64(totalIssued) * 100
	}

	// Cache results
	s.mu.Lock()
	s.revocationStatsCache = stats
	s.mu.Unlock()

	return stats, nil
}

// ============================================================================
// Performance Statistics
// ============================================================================

// GetPerformanceStats returns system performance statistics.
func (s *StatsCollector) GetPerformanceStats(ctx context.Context) (*PerformanceStats, error) {
	s.mu.RLock()
	if s.performanceStatsCache != nil && time.Since(s.performanceStatsCache.LastUpdated) < s.cacheTTL {
		defer s.mu.RUnlock()
		return s.performanceStatsCache, nil
	}
	s.mu.RUnlock()

	log.Println("[Stats] Fetching performance statistics")

	stats := &PerformanceStats{
		LastUpdated: time.Now(),
	}

	// In a real implementation, these would come from Prometheus metrics
	// or an internal metrics collector. For now, returning placeholder values.
	stats.AvgCertificateSigningMs = 50.0
	stats.AvgRevocationCheckMs = 5.0
	stats.CacheHitRate = 95.0
	stats.DatabaseQueryAvgMs = 15.0
	stats.GRPCRequestCount = 0
	stats.GRPCErrorRate = 0.1

	// Cache results
	s.mu.Lock()
	s.performanceStatsCache = stats
	s.mu.Unlock()

	return stats, nil
}

// ============================================================================
// Alert Checking
// ============================================================================

// Alert represents a triggered alert.
type Alert struct {
	Severity    string    `json:"severity"` // warning, critical
	Category    string    `json:"category"` // certificate, device, performance, system
	Message     string    `json:"message"`
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
	TriggeredAt time.Time `json:"triggered_at"`
}

// CheckAlerts evaluates all statistics against thresholds.
func (s *StatsCollector) CheckAlerts(ctx context.Context) ([]Alert, error) {
	var alerts []Alert

	// Get all stats
	certStats, _ := s.GetCertificateStats(ctx)
	deviceStats, _ := s.GetDeviceAdoptionStats(ctx)
	revocationStats, _ := s.GetRevocationStats(ctx)
	perfStats, _ := s.GetPerformanceStats(ctx)

	s.mu.RLock()
	thresholds := s.thresholds
	s.mu.RUnlock()

	// Certificate alerts
	if certStats.ExpiringSoon7Days > thresholds.ExpiringSoonWarning {
		alerts = append(alerts, Alert{
			Severity:    "warning",
			Category:    "certificate",
			Message:     fmt.Sprintf("%d certificates expiring within 7 days", certStats.ExpiringSoon7Days),
			Value:       float64(certStats.ExpiringSoon7Days),
			Threshold:   float64(thresholds.ExpiringSoonWarning),
			TriggeredAt: time.Now(),
		})
	}

	// Revocation rate alert
	if revocationStats.RevocationRate > thresholds.RevocationRateMax {
		alerts = append(alerts, Alert{
			Severity:    "critical",
			Category:    "certificate",
			Message:     fmt.Sprintf("Revocation rate %.2f%% exceeds threshold", revocationStats.RevocationRate),
			Value:       revocationStats.RevocationRate,
			Threshold:   thresholds.RevocationRateMax,
			TriggeredAt: time.Now(),
		})
	}

	// Device adoption alert
	if deviceStats.TotalDevices > 0 && deviceStats.AdoptionPercentage < thresholds.AdoptionRateMin {
		alerts = append(alerts, Alert{
			Severity:    "warning",
			Category:    "device",
			Message:     fmt.Sprintf("CA adoption rate %.2f%% below target", deviceStats.AdoptionPercentage),
			Value:       deviceStats.AdoptionPercentage,
			Threshold:   thresholds.AdoptionRateMin,
			TriggeredAt: time.Now(),
		})
	}

	// Performance alerts
	if perfStats.AvgCertificateSigningMs > thresholds.CertSigningMaxMs {
		alerts = append(alerts, Alert{
			Severity:    "warning",
			Category:    "performance",
			Message:     fmt.Sprintf("Certificate signing avg %.2fms exceeds threshold", perfStats.AvgCertificateSigningMs),
			Value:       perfStats.AvgCertificateSigningMs,
			Threshold:   thresholds.CertSigningMaxMs,
			TriggeredAt: time.Now(),
		})
	}

	if perfStats.CacheHitRate < thresholds.CacheHitRateMin {
		alerts = append(alerts, Alert{
			Severity:    "warning",
			Category:    "performance",
			Message:     fmt.Sprintf("Cache hit rate %.2f%% below threshold", perfStats.CacheHitRate),
			Value:       perfStats.CacheHitRate,
			Threshold:   thresholds.CacheHitRateMin,
			TriggeredAt: time.Now(),
		})
	}

	if perfStats.GRPCErrorRate > thresholds.GRPCErrorRateMax {
		alerts = append(alerts, Alert{
			Severity:    "critical",
			Category:    "performance",
			Message:     fmt.Sprintf("gRPC error rate %.2f%% exceeds threshold", perfStats.GRPCErrorRate),
			Value:       perfStats.GRPCErrorRate,
			Threshold:   thresholds.GRPCErrorRateMax,
			TriggeredAt: time.Now(),
		})
	}

	return alerts, nil
}

// ============================================================================
// Reporting Functions
// ============================================================================

// DailyReport contains aggregated daily statistics.
type DailyReport struct {
	Date                string               `json:"date"`
	CertificateStats    *CertificateStats    `json:"certificate_stats"`
	DeviceAdoptionStats *DeviceAdoptionStats `json:"device_adoption_stats"`
	DownloadStats       *DownloadStats       `json:"download_stats"`
	RevocationStats     *RevocationStats     `json:"revocation_stats"`
	PerformanceStats    *PerformanceStats    `json:"performance_stats"`
	Alerts              []Alert              `json:"alerts"`
	GeneratedAt         time.Time            `json:"generated_at"`
}

// GenerateDailyReport generates a comprehensive daily report.
func (s *StatsCollector) GenerateDailyReport(ctx context.Context) (*DailyReport, error) {
	log.Println("[Stats] Generating daily report")

	certStats, _ := s.GetCertificateStats(ctx)
	deviceStats, _ := s.GetDeviceAdoptionStats(ctx)
	downloadStats, _ := s.GetDownloadStats(ctx)
	revocationStats, _ := s.GetRevocationStats(ctx)
	perfStats, _ := s.GetPerformanceStats(ctx)
	alerts, _ := s.CheckAlerts(ctx)

	return &DailyReport{
		Date:                time.Now().Format("2006-01-02"),
		CertificateStats:    certStats,
		DeviceAdoptionStats: deviceStats,
		DownloadStats:       downloadStats,
		RevocationStats:     revocationStats,
		PerformanceStats:    perfStats,
		Alerts:              alerts,
		GeneratedAt:         time.Now(),
	}, nil
}

// WeeklyReport contains aggregated weekly statistics with trends.
type WeeklyReport struct {
	WeekStartDate         string               `json:"week_start_date"`
	WeekEndDate           string               `json:"week_end_date"`
	CertificateStats      *CertificateStats    `json:"certificate_stats"`
	DeviceAdoptionStats   *DeviceAdoptionStats `json:"device_adoption_stats"`
	DownloadStats         *DownloadStats       `json:"download_stats"`
	RevocationStats       *RevocationStats     `json:"revocation_stats"`
	PerformanceStats      *PerformanceStats    `json:"performance_stats"`
	AdoptionGrowthPercent float64              `json:"adoption_growth_percent"`
	IssuanceVelocity      float64              `json:"issuance_velocity_per_day"`
	Alerts                []Alert              `json:"alerts"`
	GeneratedAt           time.Time            `json:"generated_at"`
}

// GenerateWeeklyReport generates a comprehensive weekly report.
func (s *StatsCollector) GenerateWeeklyReport(ctx context.Context) (*WeeklyReport, error) {
	log.Println("[Stats] Generating weekly report")

	certStats, _ := s.GetCertificateStats(ctx)
	deviceStats, _ := s.GetDeviceAdoptionStats(ctx)
	downloadStats, _ := s.GetDownloadStats(ctx)
	revocationStats, _ := s.GetRevocationStats(ctx)
	perfStats, _ := s.GetPerformanceStats(ctx)
	alerts, _ := s.CheckAlerts(ctx)

	now := time.Now()
	weekStart := now.AddDate(0, 0, -7)

	report := &WeeklyReport{
		WeekStartDate:       weekStart.Format("2006-01-02"),
		WeekEndDate:         now.Format("2006-01-02"),
		CertificateStats:    certStats,
		DeviceAdoptionStats: deviceStats,
		DownloadStats:       downloadStats,
		RevocationStats:     revocationStats,
		PerformanceStats:    perfStats,
		Alerts:              alerts,
		GeneratedAt:         time.Now(),
	}

	// Calculate issuance velocity
	if certStats.CertificatesIssuedWeek > 0 {
		report.IssuanceVelocity = float64(certStats.CertificatesIssuedWeek) / 7.0
	}

	// Adoption growth would compare to previous week (placeholder)
	report.AdoptionGrowthPercent = deviceStats.GrowthVelocity * 7 / float64(max(deviceStats.TotalDevices, 1)) * 100

	return report, nil
}

// HealthReport contains overall PKI health assessment.
type HealthReport struct {
	HealthScore         int                  `json:"health_score"` // 0-100
	Status              string               `json:"status"`       // healthy, degraded, unhealthy
	Checks              []HealthCheck        `json:"checks"`
	CertificateStats    *CertificateStats    `json:"certificate_stats"`
	DeviceAdoptionStats *DeviceAdoptionStats `json:"device_adoption_stats"`
	Alerts              []Alert              `json:"alerts"`
	GeneratedAt         time.Time            `json:"generated_at"`
}

// HealthCheck represents a single health check result.
type HealthCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // pass, warn, fail
	Message     string `json:"message"`
	ScoreImpact int    `json:"score_impact"`
}

// GenerateHealthReport generates an overall PKI health assessment.
func (s *StatsCollector) GenerateHealthReport(ctx context.Context) (*HealthReport, error) {
	log.Println("[Stats] Generating health report")

	certStats, _ := s.GetCertificateStats(ctx)
	deviceStats, _ := s.GetDeviceAdoptionStats(ctx)
	alerts, _ := s.CheckAlerts(ctx)

	report := &HealthReport{
		HealthScore:         100,
		Status:              "healthy",
		Checks:              []HealthCheck{},
		CertificateStats:    certStats,
		DeviceAdoptionStats: deviceStats,
		Alerts:              alerts,
		GeneratedAt:         time.Now(),
	}

	// Check: Active certificates exist
	if certStats.ActiveCertificates > 0 {
		report.Checks = append(report.Checks, HealthCheck{
			Name:    "Active Certificates",
			Status:  "pass",
			Message: fmt.Sprintf("%d active certificates", certStats.ActiveCertificates),
		})
	} else {
		report.Checks = append(report.Checks, HealthCheck{
			Name:        "Active Certificates",
			Status:      "warn",
			Message:     "No active certificates",
			ScoreImpact: -10,
		})
		report.HealthScore -= 10
	}

	// Check: Expiring soon
	if certStats.ExpiringSoon7Days > 10 {
		report.Checks = append(report.Checks, HealthCheck{
			Name:        "Expiring Certificates",
			Status:      "warn",
			Message:     fmt.Sprintf("%d certificates expiring within 7 days", certStats.ExpiringSoon7Days),
			ScoreImpact: -15,
		})
		report.HealthScore -= 15
	} else {
		report.Checks = append(report.Checks, HealthCheck{
			Name:    "Expiring Certificates",
			Status:  "pass",
			Message: fmt.Sprintf("%d certificates expiring within 7 days", certStats.ExpiringSoon7Days),
		})
	}

	// Check: Device adoption
	if deviceStats.TotalDevices > 0 {
		if deviceStats.AdoptionPercentage >= 90 {
			report.Checks = append(report.Checks, HealthCheck{
				Name:    "Device CA Adoption",
				Status:  "pass",
				Message: fmt.Sprintf("%.1f%% adoption rate", deviceStats.AdoptionPercentage),
			})
		} else if deviceStats.AdoptionPercentage >= 70 {
			report.Checks = append(report.Checks, HealthCheck{
				Name:        "Device CA Adoption",
				Status:      "warn",
				Message:     fmt.Sprintf("%.1f%% adoption rate (target: 90%%)", deviceStats.AdoptionPercentage),
				ScoreImpact: -10,
			})
			report.HealthScore -= 10
		} else {
			report.Checks = append(report.Checks, HealthCheck{
				Name:        "Device CA Adoption",
				Status:      "fail",
				Message:     fmt.Sprintf("%.1f%% adoption rate (target: 90%%)", deviceStats.AdoptionPercentage),
				ScoreImpact: -25,
			})
			report.HealthScore -= 25
		}
	}

	// Adjust status based on score
	if report.HealthScore < 70 {
		report.Status = "unhealthy"
	} else if report.HealthScore < 90 {
		report.Status = "degraded"
	}

	// Apply alert impacts
	for _, alert := range alerts {
		switch alert.Severity {
		case "critical":
			report.HealthScore -= 20
		case "warning":
			report.HealthScore -= 5
		}
	}

	// Clamp score to 0-100
	if report.HealthScore < 0 {
		report.HealthScore = 0
	}

	return report, nil
}

// ============================================================================
// Report Formatting
// ============================================================================

// FormatReportAsJSON formats a report as JSON string.
func FormatReportAsJSON(report interface{}) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatReportAsText formats a report as plain text.
func FormatDailyReportAsText(report *DailyReport) string {
	var sb strings.Builder

	sb.WriteString("SafeOps Certificate Manager - Daily Report\n")
	sb.WriteString(fmt.Sprintf("Date: %s\n", report.Date))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("CERTIFICATE STATISTICS:\n")
	sb.WriteString(fmt.Sprintf("  Total Issued:     %d\n", report.CertificateStats.TotalIssued))
	sb.WriteString(fmt.Sprintf("  Active:           %d\n", report.CertificateStats.ActiveCertificates))
	sb.WriteString(fmt.Sprintf("  Expired:          %d\n", report.CertificateStats.ExpiredCertificates))
	sb.WriteString(fmt.Sprintf("  Revoked:          %d\n", report.CertificateStats.RevokedCertificates))
	sb.WriteString(fmt.Sprintf("  Issued Today:     %d\n", report.CertificateStats.CertificatesIssuedToday))
	sb.WriteString(fmt.Sprintf("  Expiring (7d):    %d\n", report.CertificateStats.ExpiringSoon7Days))
	sb.WriteString("\n")

	sb.WriteString("DEVICE CA ADOPTION:\n")
	sb.WriteString(fmt.Sprintf("  Total Devices:    %d\n", report.DeviceAdoptionStats.TotalDevices))
	sb.WriteString(fmt.Sprintf("  With CA:          %d\n", report.DeviceAdoptionStats.DevicesWithCA))
	sb.WriteString(fmt.Sprintf("  Adoption Rate:    %.1f%%\n", report.DeviceAdoptionStats.AdoptionPercentage))
	sb.WriteString(fmt.Sprintf("  Installed Today:  %d\n", report.DeviceAdoptionStats.InstallationsToday))
	sb.WriteString("\n")

	sb.WriteString("DOWNLOADS:\n")
	sb.WriteString(fmt.Sprintf("  Total Downloads:  %d\n", report.DownloadStats.TotalDownloads))
	sb.WriteString(fmt.Sprintf("  Today:            %d\n", report.DownloadStats.DownloadsToday))
	sb.WriteString(fmt.Sprintf("  Unique IPs:       %d\n", report.DownloadStats.UniqueIPs))
	sb.WriteString("\n")

	if len(report.Alerts) > 0 {
		sb.WriteString("ALERTS:\n")
		for _, alert := range report.Alerts {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n",
				strings.ToUpper(alert.Severity), alert.Category, alert.Message))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339)))

	return sb.String()
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
