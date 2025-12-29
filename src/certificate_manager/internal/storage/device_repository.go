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
// Device CA Status Model
// ============================================================================

// DeviceCAStatus represents a device's CA installation status from the database.
// Maps to the device_ca_status table.
type DeviceCAStatus struct {
	ID          int       `json:"id"`
	DeviceIP    string    `json:"device_ip"`
	MACAddress  string    `json:"mac_address"`
	CAInstalled bool      `json:"ca_installed"`
	DetectedAt  time.Time `json:"detected_at"`
	CreatedAt   time.Time `json:"created_at"`
	LastChecked time.Time `json:"last_checked"`
}

// DeviceStats contains statistics about device CA installation coverage.
type DeviceStats struct {
	TotalDevices      int     `json:"total_devices"`
	DevicesWithCA     int     `json:"devices_with_ca"`
	DevicesWithoutCA  int     `json:"devices_without_ca"`
	InstallationRate  float64 `json:"installation_rate"`
	LastCheckedWithin int     `json:"last_checked_within_24h"`
	OldestUnchecked   string  `json:"oldest_unchecked_device"`
}

// ============================================================================
// Device Repository Interface
// ============================================================================

// DeviceRepository defines the contract for device CA status data access.
type DeviceRepository interface {
	// CRUD Operations
	SaveDeviceStatus(ctx context.Context, device *DeviceCAStatus) error
	GetDeviceStatus(ctx context.Context, deviceIP string) (*DeviceCAStatus, error)
	GetDeviceStatusByMAC(ctx context.Context, macAddress string) (*DeviceCAStatus, error)
	ListDevices(ctx context.Context, limit int, offset int) ([]*DeviceCAStatus, error)
	UpdateCAInstalledStatus(ctx context.Context, deviceIP string, installed bool) error
	DeleteDevice(ctx context.Context, deviceIP string) error

	// Counting and Statistics
	CountDevices(ctx context.Context) (int, error)
	CountDevicesWithCA(ctx context.Context) (int, error)
	GetInstallationCoverage(ctx context.Context) (float64, error)
	GetDeviceStats(ctx context.Context) (*DeviceStats, error)

	// Filtered Queries
	GetDevicesWithoutCA(ctx context.Context) ([]*DeviceCAStatus, error)
	GetDevicesByStatus(ctx context.Context, installed bool) ([]*DeviceCAStatus, error)
	GetRecentlyCheckedDevices(ctx context.Context, withinDuration time.Duration) ([]*DeviceCAStatus, error)

	// Bulk Operations
	BulkUpdateCAStatus(ctx context.Context, deviceIPs []string, installed bool) error
}

// ============================================================================
// Device Repository Implementation
// ============================================================================

// deviceRepository is the concrete implementation of DeviceRepository.
type deviceRepository struct {
	db *Database
}

// NewDeviceRepository creates a new device repository instance.
func NewDeviceRepository(db *Database) DeviceRepository {
	return &deviceRepository{
		db: db,
	}
}

// ============================================================================
// Validation Helpers
// ============================================================================

// validateIPAddress validates that the given string is a valid IP address.
func validateIPAddress(ip string) error {
	if ip == "" {
		return errors.New("IP address cannot be empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	return nil
}

// validateMACAddress validates that the given string is a valid MAC address.
func validateMACAddress(mac string) error {
	if mac == "" {
		return errors.New("MAC address cannot be empty")
	}
	// Normalize MAC address format
	_, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address format: %s", mac)
	}
	return nil
}

// normalizeMACAddress normalizes a MAC address to uppercase with colons.
func normalizeMACAddress(mac string) string {
	// Parse and re-format to ensure consistent format
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return strings.ToUpper(mac)
	}
	return strings.ToUpper(hwAddr.String())
}

// ============================================================================
// CRUD Operations
// ============================================================================

// SaveDeviceStatus inserts or updates a device CA status record.
// Uses UPSERT (INSERT ... ON CONFLICT) for idempotency.
func (r *deviceRepository) SaveDeviceStatus(ctx context.Context, device *DeviceCAStatus) error {
	if device == nil {
		return errors.New("device cannot be nil")
	}

	// Validate IP address
	if err := validateIPAddress(device.DeviceIP); err != nil {
		return fmt.Errorf("SaveDeviceStatus: %w", err)
	}

	// Validate MAC address
	if err := validateMACAddress(device.MACAddress); err != nil {
		return fmt.Errorf("SaveDeviceStatus: %w", err)
	}

	// Normalize MAC address
	normalizedMAC := normalizeMACAddress(device.MACAddress)

	// Set detected_at if CA is installed and not already set
	detectedAt := device.DetectedAt
	if device.CAInstalled && detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	query := `
		INSERT INTO device_ca_status (
			device_ip,
			mac_address,
			ca_installed,
			detected_at,
			created_at,
			last_checked
		) VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (device_ip)
		DO UPDATE SET
			mac_address = EXCLUDED.mac_address,
			ca_installed = EXCLUDED.ca_installed,
			detected_at = CASE 
				WHEN EXCLUDED.ca_installed = true AND device_ca_status.ca_installed = false 
				THEN EXCLUDED.detected_at 
				ELSE device_ca_status.detected_at 
			END,
			last_checked = NOW()
	`

	_, err := r.db.db.ExecContext(ctx, query,
		device.DeviceIP,
		normalizedMAC,
		device.CAInstalled,
		detectedAt,
	)
	if err != nil {
		return fmt.Errorf("SaveDeviceStatus: %w", err)
	}

	return nil
}

// GetDeviceStatus retrieves device CA status by IP address.
func (r *deviceRepository) GetDeviceStatus(ctx context.Context, deviceIP string) (*DeviceCAStatus, error) {
	if err := validateIPAddress(deviceIP); err != nil {
		return nil, fmt.Errorf("GetDeviceStatus: %w", err)
	}

	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		WHERE device_ip = $1
	`

	device := &DeviceCAStatus{}
	var detectedAt sql.NullTime

	err := r.db.db.QueryRowContext(ctx, query, deviceIP).Scan(
		&device.ID,
		&device.DeviceIP,
		&device.MACAddress,
		&device.CAInstalled,
		&detectedAt,
		&device.CreatedAt,
		&device.LastChecked,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetDeviceStatus: device not found: %s", deviceIP)
		}
		return nil, fmt.Errorf("GetDeviceStatus: %w", err)
	}

	if detectedAt.Valid {
		device.DetectedAt = detectedAt.Time
	}

	return device, nil
}

// GetDeviceStatusByMAC retrieves device CA status by MAC address.
// Useful when IP address changes (DHCP renewal).
func (r *deviceRepository) GetDeviceStatusByMAC(ctx context.Context, macAddress string) (*DeviceCAStatus, error) {
	if err := validateMACAddress(macAddress); err != nil {
		return nil, fmt.Errorf("GetDeviceStatusByMAC: %w", err)
	}

	normalizedMAC := normalizeMACAddress(macAddress)

	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		WHERE mac_address = $1
	`

	device := &DeviceCAStatus{}
	var detectedAt sql.NullTime

	err := r.db.db.QueryRowContext(ctx, query, normalizedMAC).Scan(
		&device.ID,
		&device.DeviceIP,
		&device.MACAddress,
		&device.CAInstalled,
		&detectedAt,
		&device.CreatedAt,
		&device.LastChecked,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetDeviceStatusByMAC: device not found: %s", macAddress)
		}
		return nil, fmt.Errorf("GetDeviceStatusByMAC: %w", err)
	}

	if detectedAt.Valid {
		device.DetectedAt = detectedAt.Time
	}

	return device, nil
}

// ListDevices returns a paginated list of all tracked devices.
// Orders by most recently checked first.
func (r *deviceRepository) ListDevices(ctx context.Context, limit int, offset int) ([]*DeviceCAStatus, error) {
	// Enforce reasonable limits
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		ORDER BY last_checked DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("ListDevices: %w", err)
	}
	defer rows.Close()

	devices := make([]*DeviceCAStatus, 0)
	for rows.Next() {
		device := &DeviceCAStatus{}
		var detectedAt sql.NullTime

		err := rows.Scan(
			&device.ID,
			&device.DeviceIP,
			&device.MACAddress,
			&device.CAInstalled,
			&detectedAt,
			&device.CreatedAt,
			&device.LastChecked,
		)
		if err != nil {
			return nil, fmt.Errorf("ListDevices: scan error: %w", err)
		}

		if detectedAt.Valid {
			device.DetectedAt = detectedAt.Time
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListDevices: rows error: %w", err)
	}

	return devices, nil
}

// UpdateCAInstalledStatus updates the CA installation status for a specific device.
// Called when TLS handshake detects CA installation or removal.
func (r *deviceRepository) UpdateCAInstalledStatus(ctx context.Context, deviceIP string, installed bool) error {
	if err := validateIPAddress(deviceIP); err != nil {
		return fmt.Errorf("UpdateCAInstalledStatus: %w", err)
	}

	query := `
		UPDATE device_ca_status
		SET ca_installed = $2,
			detected_at = CASE WHEN $2 = true AND ca_installed = false THEN NOW() ELSE detected_at END,
			last_checked = NOW()
		WHERE device_ip = $1
	`

	result, err := r.db.db.ExecContext(ctx, query, deviceIP, installed)
	if err != nil {
		return fmt.Errorf("UpdateCAInstalledStatus: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("UpdateCAInstalledStatus: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("UpdateCAInstalledStatus: device not found: %s", deviceIP)
	}

	return nil
}

// DeleteDevice removes a device from the tracking database.
// Used for device decommissioning.
func (r *deviceRepository) DeleteDevice(ctx context.Context, deviceIP string) error {
	if err := validateIPAddress(deviceIP); err != nil {
		return fmt.Errorf("DeleteDevice: %w", err)
	}

	query := `DELETE FROM device_ca_status WHERE device_ip = $1`

	result, err := r.db.db.ExecContext(ctx, query, deviceIP)
	if err != nil {
		return fmt.Errorf("DeleteDevice: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("DeleteDevice: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("DeleteDevice: device not found: %s", deviceIP)
	}

	return nil
}

// ============================================================================
// Counting and Statistics
// ============================================================================

// CountDevices returns the total count of tracked devices.
func (r *deviceRepository) CountDevices(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM device_ca_status`

	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountDevices: %w", err)
	}

	return count, nil
}

// CountDevicesWithCA returns the count of devices with CA installed.
func (r *deviceRepository) CountDevicesWithCA(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM device_ca_status WHERE ca_installed = true`

	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountDevicesWithCA: %w", err)
	}

	return count, nil
}

// GetInstallationCoverage calculates the percentage of devices with CA installed.
// Returns a value between 0.0 and 100.0.
func (r *deviceRepository) GetInstallationCoverage(ctx context.Context) (float64, error) {
	total, err := r.CountDevices(ctx)
	if err != nil {
		return 0, fmt.Errorf("GetInstallationCoverage: %w", err)
	}

	if total == 0 {
		return 100.0, nil // No devices = 100% coverage (nothing to install)
	}

	withCA, err := r.CountDevicesWithCA(ctx)
	if err != nil {
		return 0, fmt.Errorf("GetInstallationCoverage: %w", err)
	}

	coverage := (float64(withCA) / float64(total)) * 100.0
	return coverage, nil
}

// GetDeviceStats returns comprehensive statistics about device CA installation.
func (r *deviceRepository) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	stats := &DeviceStats{}

	// Get total and with CA counts
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE ca_installed = true) as with_ca,
			COUNT(*) FILTER (WHERE last_checked >= NOW() - INTERVAL '24 hours') as checked_24h
		FROM device_ca_status
	`

	err := r.db.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalDevices,
		&stats.DevicesWithCA,
		&stats.LastCheckedWithin,
	)
	if err != nil {
		return nil, fmt.Errorf("GetDeviceStats: %w", err)
	}

	stats.DevicesWithoutCA = stats.TotalDevices - stats.DevicesWithCA

	if stats.TotalDevices > 0 {
		stats.InstallationRate = (float64(stats.DevicesWithCA) / float64(stats.TotalDevices)) * 100.0
	} else {
		stats.InstallationRate = 100.0
	}

	// Get oldest unchecked device
	oldestQuery := `
		SELECT device_ip
		FROM device_ca_status
		WHERE ca_installed = false
		ORDER BY last_checked ASC
		LIMIT 1
	`

	var oldestIP sql.NullString
	err = r.db.db.QueryRowContext(ctx, oldestQuery).Scan(&oldestIP)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("GetDeviceStats: oldest query: %w", err)
	}
	if oldestIP.Valid {
		stats.OldestUnchecked = oldestIP.String
	}

	return stats, nil
}

// ============================================================================
// Filtered Queries
// ============================================================================

// GetDevicesWithoutCA returns all devices that don't have CA installed.
// Used for proactive outreach and troubleshooting.
func (r *deviceRepository) GetDevicesWithoutCA(ctx context.Context) ([]*DeviceCAStatus, error) {
	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		WHERE ca_installed = false
		ORDER BY created_at ASC
	`

	return r.queryDevices(ctx, query)
}

// GetDevicesByStatus returns all devices with specific CA installation status.
func (r *deviceRepository) GetDevicesByStatus(ctx context.Context, installed bool) ([]*DeviceCAStatus, error) {
	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		WHERE ca_installed = $1
		ORDER BY last_checked DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query, installed)
	if err != nil {
		return nil, fmt.Errorf("GetDevicesByStatus: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// GetRecentlyCheckedDevices returns devices checked within the specified time window.
// Used for monitoring detection job effectiveness.
func (r *deviceRepository) GetRecentlyCheckedDevices(ctx context.Context, withinDuration time.Duration) ([]*DeviceCAStatus, error) {
	query := `
		SELECT id, device_ip, mac_address, ca_installed, detected_at, created_at, last_checked
		FROM device_ca_status
		WHERE last_checked >= NOW() - $1::interval
		ORDER BY last_checked DESC
	`

	// Convert duration to PostgreSQL interval format
	intervalStr := fmt.Sprintf("%d seconds", int(withinDuration.Seconds()))

	rows, err := r.db.db.QueryContext(ctx, query, intervalStr)
	if err != nil {
		return nil, fmt.Errorf("GetRecentlyCheckedDevices: %w", err)
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkUpdateCAStatus updates CA status for multiple devices in a single transaction.
// Performance optimization for bulk operations like CA renewal.
func (r *deviceRepository) BulkUpdateCAStatus(ctx context.Context, deviceIPs []string, installed bool) error {
	if len(deviceIPs) == 0 {
		return nil
	}

	// Validate all IP addresses first
	for _, ip := range deviceIPs {
		if err := validateIPAddress(ip); err != nil {
			return fmt.Errorf("BulkUpdateCAStatus: %w", err)
		}
	}

	// Begin transaction
	tx, err := r.db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BulkUpdateCAStatus: begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare the update statement
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE device_ca_status
		SET ca_installed = $2,
			detected_at = CASE WHEN $2 = true AND ca_installed = false THEN NOW() ELSE detected_at END,
			last_checked = NOW()
		WHERE device_ip = $1
	`)
	if err != nil {
		return fmt.Errorf("BulkUpdateCAStatus: prepare statement: %w", err)
	}
	defer stmt.Close()

	// Execute for each device
	var updateCount int
	for _, ip := range deviceIPs {
		result, err := stmt.ExecContext(ctx, ip, installed)
		if err != nil {
			return fmt.Errorf("BulkUpdateCAStatus: update %s: %w", ip, err)
		}
		affected, _ := result.RowsAffected()
		updateCount += int(affected)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("BulkUpdateCAStatus: commit: %w", err)
	}

	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// queryDevices executes a query and returns a slice of devices.
func (r *deviceRepository) queryDevices(ctx context.Context, query string, args ...interface{}) ([]*DeviceCAStatus, error) {
	rows, err := r.db.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

// scanDevices scans rows into a slice of DeviceCAStatus.
func (r *deviceRepository) scanDevices(rows *sql.Rows) ([]*DeviceCAStatus, error) {
	devices := make([]*DeviceCAStatus, 0)

	for rows.Next() {
		device := &DeviceCAStatus{}
		var detectedAt sql.NullTime

		err := rows.Scan(
			&device.ID,
			&device.DeviceIP,
			&device.MACAddress,
			&device.CAInstalled,
			&detectedAt,
			&device.CreatedAt,
			&device.LastChecked,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}

		if detectedAt.Valid {
			device.DetectedAt = detectedAt.Time
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return devices, nil
}
