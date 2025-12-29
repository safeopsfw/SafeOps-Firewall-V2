package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ============================================================================
// Certificate Download Model
// ============================================================================

// CertificateDownload represents a CA certificate download record from the database.
// Maps to the certificate_downloads table.
type CertificateDownload struct {
	ID        int       `json:"id"`
	DeviceIP  string    `json:"device_ip"`
	Format    string    `json:"format"`
	Timestamp time.Time `json:"timestamp"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// DownloadStats contains aggregated download statistics for reporting.
type DownloadStats struct {
	TotalDownloads       int       `json:"total_downloads"`
	UniqueIPs            int       `json:"unique_ips"`
	PEMDownloads         int       `json:"pem_downloads"`
	DERDownloads         int       `json:"der_downloads"`
	P7BDownloads         int       `json:"p7b_downloads"`
	PKCS12Downloads      int       `json:"pkcs12_downloads"`
	MostRecentDownload   time.Time `json:"most_recent_download"`
	DownloadsLast24Hours int       `json:"downloads_last_24h"`
	DownloadsLast7Days   int       `json:"downloads_last_7_days"`
}

// Valid certificate formats
var validFormats = map[string]bool{
	"PEM":    true,
	"DER":    true,
	"P7B":    true,
	"PKCS12": true,
}

// ============================================================================
// Download Repository Interface
// ============================================================================

// DownloadRepository defines the contract for download tracking data access.
type DownloadRepository interface {
	// Core Operations
	RecordDownload(ctx context.Context, download *CertificateDownload) error
	GetDownloadHistory(ctx context.Context, deviceIP string) ([]*CertificateDownload, error)
	GetDownloadsByFormat(ctx context.Context, format string) ([]*CertificateDownload, error)
	GetRecentDownloads(ctx context.Context, withinDuration time.Duration) ([]*CertificateDownload, error)

	// Counting
	CountTotalDownloads(ctx context.Context) (int, error)
	CountUniqueIPs(ctx context.Context) (int, error)
	GetDownloadCountByIP(ctx context.Context, deviceIP string) (int, error)

	// Statistics
	GetDownloadStats(ctx context.Context) (*DownloadStats, error)
	GetFormatDistribution(ctx context.Context) (map[string]int, error)
	GetFirstDownload(ctx context.Context, deviceIP string) (time.Time, error)

	// Maintenance
	DeleteOldDownloads(ctx context.Context, olderThan time.Duration) (int, error)

	// Bulk Operations
	BulkRecordDownloads(ctx context.Context, downloads []*CertificateDownload) error
}

// ============================================================================
// Download Repository Implementation
// ============================================================================

// downloadRepository is the concrete implementation of DownloadRepository.
type downloadRepository struct {
	db *Database
}

// NewDownloadRepository creates a new download repository instance.
func NewDownloadRepository(db *Database) DownloadRepository {
	return &downloadRepository{
		db: db,
	}
}

// ============================================================================
// Validation Helpers
// ============================================================================

// validateDownloadFormat validates that the format is one of the supported types.
func validateDownloadFormat(format string) error {
	normalized := strings.ToUpper(format)
	if !validFormats[normalized] {
		return fmt.Errorf("invalid certificate format: %s (must be PEM, DER, P7B, or PKCS12)", format)
	}
	return nil
}

// normalizeFormat normalizes the format string to uppercase.
func normalizeFormat(format string) string {
	return strings.ToUpper(format)
}

// ============================================================================
// Core Operations
// ============================================================================

// RecordDownload inserts a new download record into the database.
// Called by HTTP distribution server after successful CA certificate download.
func (r *downloadRepository) RecordDownload(ctx context.Context, download *CertificateDownload) error {
	if download == nil {
		return errors.New("download record cannot be nil")
	}

	// Validate IP address
	if err := validateIPAddress(download.DeviceIP); err != nil {
		return fmt.Errorf("RecordDownload: %w", err)
	}

	// Validate and normalize format
	if err := validateDownloadFormat(download.Format); err != nil {
		return fmt.Errorf("RecordDownload: %w", err)
	}
	normalizedFormat := normalizeFormat(download.Format)

	// Set timestamp to now if not provided
	timestamp := download.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	query := `
		INSERT INTO certificate_downloads (
			device_ip,
			format,
			timestamp,
			user_agent
		) VALUES ($1, $2, $3, $4)
		RETURNING id
	`

	err := r.db.db.QueryRowContext(ctx, query,
		download.DeviceIP,
		normalizedFormat,
		timestamp,
		download.UserAgent,
	).Scan(&download.ID)

	if err != nil {
		return fmt.Errorf("RecordDownload: %w", err)
	}

	return nil
}

// GetDownloadHistory retrieves all download records for a specific device IP.
// Returns download history ordered by timestamp (newest first).
func (r *downloadRepository) GetDownloadHistory(ctx context.Context, deviceIP string) ([]*CertificateDownload, error) {
	if err := validateIPAddress(deviceIP); err != nil {
		return nil, fmt.Errorf("GetDownloadHistory: %w", err)
	}

	query := `
		SELECT id, device_ip, format, timestamp, COALESCE(user_agent, '')
		FROM certificate_downloads
		WHERE device_ip = $1
		ORDER BY timestamp DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query, deviceIP)
	if err != nil {
		return nil, fmt.Errorf("GetDownloadHistory: %w", err)
	}
	defer rows.Close()

	return r.scanDownloads(rows)
}

// GetDownloadsByFormat retrieves all downloads for a specific certificate format.
func (r *downloadRepository) GetDownloadsByFormat(ctx context.Context, format string) ([]*CertificateDownload, error) {
	if err := validateDownloadFormat(format); err != nil {
		return nil, fmt.Errorf("GetDownloadsByFormat: %w", err)
	}

	normalizedFormat := normalizeFormat(format)

	query := `
		SELECT id, device_ip, format, timestamp, COALESCE(user_agent, '')
		FROM certificate_downloads
		WHERE format = $1
		ORDER BY timestamp DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query, normalizedFormat)
	if err != nil {
		return nil, fmt.Errorf("GetDownloadsByFormat: %w", err)
	}
	defer rows.Close()

	return r.scanDownloads(rows)
}

// GetRecentDownloads returns downloads within the specified time window.
func (r *downloadRepository) GetRecentDownloads(ctx context.Context, withinDuration time.Duration) ([]*CertificateDownload, error) {
	query := `
		SELECT id, device_ip, format, timestamp, COALESCE(user_agent, '')
		FROM certificate_downloads
		WHERE timestamp >= NOW() - $1::interval
		ORDER BY timestamp DESC
	`

	// Convert duration to PostgreSQL interval format
	intervalStr := fmt.Sprintf("%d seconds", int(withinDuration.Seconds()))

	rows, err := r.db.db.QueryContext(ctx, query, intervalStr)
	if err != nil {
		return nil, fmt.Errorf("GetRecentDownloads: %w", err)
	}
	defer rows.Close()

	return r.scanDownloads(rows)
}

// ============================================================================
// Counting Operations
// ============================================================================

// CountTotalDownloads returns the total count of all downloads.
func (r *downloadRepository) CountTotalDownloads(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM certificate_downloads`

	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountTotalDownloads: %w", err)
	}

	return count, nil
}

// CountUniqueIPs returns the count of distinct IP addresses that have downloaded the CA.
func (r *downloadRepository) CountUniqueIPs(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(DISTINCT device_ip) FROM certificate_downloads`

	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountUniqueIPs: %w", err)
	}

	return count, nil
}

// GetDownloadCountByIP returns the count of downloads for a specific IP address.
// Indicates if device has downloaded multiple times (possibly installation trouble).
func (r *downloadRepository) GetDownloadCountByIP(ctx context.Context, deviceIP string) (int, error) {
	if err := validateIPAddress(deviceIP); err != nil {
		return 0, fmt.Errorf("GetDownloadCountByIP: %w", err)
	}

	var count int
	query := `SELECT COUNT(*) FROM certificate_downloads WHERE device_ip = $1`

	err := r.db.db.QueryRowContext(ctx, query, deviceIP).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("GetDownloadCountByIP: %w", err)
	}

	return count, nil
}

// ============================================================================
// Statistics Operations
// ============================================================================

// GetDownloadStats aggregates comprehensive download statistics in a single query.
func (r *downloadRepository) GetDownloadStats(ctx context.Context) (*DownloadStats, error) {
	query := `
		SELECT
			COUNT(*) AS total_downloads,
			COUNT(DISTINCT device_ip) AS unique_ips,
			SUM(CASE WHEN format = 'PEM' THEN 1 ELSE 0 END) AS pem_downloads,
			SUM(CASE WHEN format = 'DER' THEN 1 ELSE 0 END) AS der_downloads,
			SUM(CASE WHEN format = 'P7B' THEN 1 ELSE 0 END) AS p7b_downloads,
			SUM(CASE WHEN format = 'PKCS12' THEN 1 ELSE 0 END) AS pkcs12_downloads,
			COALESCE(MAX(timestamp), '1970-01-01'::timestamp) AS most_recent_download,
			SUM(CASE WHEN timestamp >= NOW() - INTERVAL '24 hours' THEN 1 ELSE 0 END) AS downloads_24h,
			SUM(CASE WHEN timestamp >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END) AS downloads_7d
		FROM certificate_downloads
	`

	stats := &DownloadStats{}
	err := r.db.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalDownloads,
		&stats.UniqueIPs,
		&stats.PEMDownloads,
		&stats.DERDownloads,
		&stats.P7BDownloads,
		&stats.PKCS12Downloads,
		&stats.MostRecentDownload,
		&stats.DownloadsLast24Hours,
		&stats.DownloadsLast7Days,
	)
	if err != nil {
		return nil, fmt.Errorf("GetDownloadStats: %w", err)
	}

	return stats, nil
}

// GetFormatDistribution returns download count per certificate format.
func (r *downloadRepository) GetFormatDistribution(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT format, COUNT(*) AS count
		FROM certificate_downloads
		GROUP BY format
		ORDER BY count DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetFormatDistribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int)
	for rows.Next() {
		var format string
		var count int
		if err := rows.Scan(&format, &count); err != nil {
			return nil, fmt.Errorf("GetFormatDistribution: scan error: %w", err)
		}
		distribution[format] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetFormatDistribution: rows error: %w", err)
	}

	return distribution, nil
}

// GetFirstDownload returns the timestamp of a device's first download.
func (r *downloadRepository) GetFirstDownload(ctx context.Context, deviceIP string) (time.Time, error) {
	if err := validateIPAddress(deviceIP); err != nil {
		return time.Time{}, fmt.Errorf("GetFirstDownload: %w", err)
	}

	query := `SELECT MIN(timestamp) FROM certificate_downloads WHERE device_ip = $1`

	var firstDownload sql.NullTime
	err := r.db.db.QueryRowContext(ctx, query, deviceIP).Scan(&firstDownload)
	if err != nil {
		return time.Time{}, fmt.Errorf("GetFirstDownload: %w", err)
	}

	if !firstDownload.Valid {
		return time.Time{}, fmt.Errorf("GetFirstDownload: no downloads found for IP: %s", deviceIP)
	}

	return firstDownload.Time, nil
}

// ============================================================================
// Maintenance Operations
// ============================================================================

// DeleteOldDownloads deletes download records older than the specified duration.
// Returns the number of rows deleted.
func (r *downloadRepository) DeleteOldDownloads(ctx context.Context, olderThan time.Duration) (int, error) {
	query := `
		DELETE FROM certificate_downloads
		WHERE timestamp < NOW() - $1::interval
	`

	// Convert duration to PostgreSQL interval format
	intervalStr := fmt.Sprintf("%d seconds", int(olderThan.Seconds()))

	result, err := r.db.db.ExecContext(ctx, query, intervalStr)
	if err != nil {
		return 0, fmt.Errorf("DeleteOldDownloads: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("DeleteOldDownloads: %w", err)
	}

	return int(rowsAffected), nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkRecordDownloads inserts multiple download records in a single transaction.
func (r *downloadRepository) BulkRecordDownloads(ctx context.Context, downloads []*CertificateDownload) error {
	if len(downloads) == 0 {
		return nil
	}

	// Validate all downloads first
	for i, download := range downloads {
		if download == nil {
			return fmt.Errorf("BulkRecordDownloads: download at index %d is nil", i)
		}
		if err := validateIPAddress(download.DeviceIP); err != nil {
			return fmt.Errorf("BulkRecordDownloads: download %d: %w", i, err)
		}
		if err := validateDownloadFormat(download.Format); err != nil {
			return fmt.Errorf("BulkRecordDownloads: download %d: %w", i, err)
		}
	}

	// Begin transaction
	tx, err := r.db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BulkRecordDownloads: begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare the insert statement
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO certificate_downloads (
			device_ip,
			format,
			timestamp,
			user_agent
		) VALUES ($1, $2, $3, $4)
		RETURNING id
	`)
	if err != nil {
		return fmt.Errorf("BulkRecordDownloads: prepare statement: %w", err)
	}
	defer stmt.Close()

	// Execute for each download
	for i, download := range downloads {
		normalizedFormat := normalizeFormat(download.Format)
		timestamp := download.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		err := stmt.QueryRowContext(ctx,
			download.DeviceIP,
			normalizedFormat,
			timestamp,
			download.UserAgent,
		).Scan(&download.ID)

		if err != nil {
			return fmt.Errorf("BulkRecordDownloads: insert %d: %w", i, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("BulkRecordDownloads: commit: %w", err)
	}

	return nil
}

// ============================================================================
// Additional Query Methods
// ============================================================================

// GetDownloadsNotInstalled returns downloads from devices that haven't installed the CA.
// Requires correlation with device_ca_status table.
func (r *downloadRepository) GetDownloadsNotInstalled(ctx context.Context) ([]*CertificateDownload, error) {
	query := `
		SELECT DISTINCT ON (cd.device_ip)
			cd.id, cd.device_ip, cd.format, cd.timestamp, COALESCE(cd.user_agent, '')
		FROM certificate_downloads cd
		LEFT JOIN device_ca_status dcs ON cd.device_ip = dcs.device_ip
		WHERE dcs.ca_installed IS NULL OR dcs.ca_installed = false
		ORDER BY cd.device_ip, cd.timestamp DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetDownloadsNotInstalled: %w", err)
	}
	defer rows.Close()

	return r.scanDownloads(rows)
}

// GetDailyDownloadCounts returns download counts grouped by date for the last N days.
func (r *downloadRepository) GetDailyDownloadCounts(ctx context.Context, days int) (map[string]int, error) {
	if days <= 0 {
		days = 30
	}

	query := `
		SELECT DATE(timestamp) AS download_date, COUNT(*) AS count
		FROM certificate_downloads
		WHERE timestamp >= NOW() - $1::interval
		GROUP BY DATE(timestamp)
		ORDER BY download_date DESC
	`

	intervalStr := fmt.Sprintf("%d days", days)

	rows, err := r.db.db.QueryContext(ctx, query, intervalStr)
	if err != nil {
		return nil, fmt.Errorf("GetDailyDownloadCounts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			return nil, fmt.Errorf("GetDailyDownloadCounts: scan error: %w", err)
		}
		counts[date.Format("2006-01-02")] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDailyDownloadCounts: rows error: %w", err)
	}

	return counts, nil
}

// GetTopDownloadIPs returns the IP addresses with the most downloads.
func (r *downloadRepository) GetTopDownloadIPs(ctx context.Context, limit int) ([]struct {
	DeviceIP string
	Count    int
}, error) {
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT device_ip, COUNT(*) AS count
		FROM certificate_downloads
		GROUP BY device_ip
		ORDER BY count DESC
		LIMIT $1
	`

	rows, err := r.db.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("GetTopDownloadIPs: %w", err)
	}
	defer rows.Close()

	var results []struct {
		DeviceIP string
		Count    int
	}

	for rows.Next() {
		var item struct {
			DeviceIP string
			Count    int
		}
		if err := rows.Scan(&item.DeviceIP, &item.Count); err != nil {
			return nil, fmt.Errorf("GetTopDownloadIPs: scan error: %w", err)
		}
		results = append(results, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetTopDownloadIPs: rows error: %w", err)
	}

	return results, nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// scanDownloads scans rows into a slice of CertificateDownload.
func (r *downloadRepository) scanDownloads(rows *sql.Rows) ([]*CertificateDownload, error) {
	downloads := make([]*CertificateDownload, 0)

	for rows.Next() {
		download := &CertificateDownload{}
		err := rows.Scan(
			&download.ID,
			&download.DeviceIP,
			&download.Format,
			&download.Timestamp,
			&download.UserAgent,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		downloads = append(downloads, download)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return downloads, nil
}

// validateIPForDownload validates IP address for download tracking.
// Reuses the validateIPAddress helper from device_repository.go.
func validateIPForDownload(ip string) error {
	if ip == "" {
		return errors.New("IP address cannot be empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	return nil
}
