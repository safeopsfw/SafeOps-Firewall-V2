// Package captive implements persistent device enrollment tracking.
package captive

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// ============================================================================
// Device Tracker - Database Persistence
// ============================================================================

// DeviceTracker manages persistent device enrollment tracking
type DeviceTracker struct {
	db *sql.DB
}

// NewDeviceTracker creates a new device tracker with database connection
func NewDeviceTracker(db *sql.DB) *DeviceTracker {
	return &DeviceTracker{db: db}
}

// ============================================================================
// Device Operations
// ============================================================================

// RecordDeviceSeen records a device making a DNS query
func (t *DeviceTracker) RecordDeviceSeen(ctx context.Context, deviceID, ipAddress, macAddress, osType, userAgent string) error {
	query := `
		INSERT INTO device_enrollment (device_id, ip_address, mac_address, os_type, user_agent, first_seen, last_seen)
		VALUES ($1, $2::inet, $3::macaddr, $4, $5, NOW(), NOW())
		ON CONFLICT (device_id) DO UPDATE SET
			ip_address = EXCLUDED.ip_address,
			last_seen = NOW()
	`

	_, err := t.db.ExecContext(ctx, query, deviceID, ipAddress, macAddress, osType, userAgent)
	if err != nil {
		return fmt.Errorf("failed to record device: %w", err)
	}

	return nil
}

// MarkDeviceEnrolled marks a device as having the CA installed
func (t *DeviceTracker) MarkDeviceEnrolled(ctx context.Context, deviceID, installMethod, certFingerprint string) error {
	query := `
		UPDATE device_enrollment
		SET ca_installed = true,
		    installed_at = NOW(),
		    install_method = $2,
		    certificate_fingerprint = $3,
		    updated_at = NOW()
		WHERE device_id = $1
	`

	result, err := t.db.ExecContext(ctx, query, deviceID, installMethod, certFingerprint)
	if err != nil {
		return fmt.Errorf("failed to mark enrolled: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	log.Printf("Device enrollment recorded: %s (method: %s)", deviceID, installMethod)
	return nil
}

// IsDeviceEnrolled checks if a device has the CA installed
func (t *DeviceTracker) IsDeviceEnrolled(ctx context.Context, ipAddress string) (bool, error) {
	var enrolled bool
	query := `
		SELECT ca_installed FROM device_enrollment 
		WHERE ip_address = $1::inet
		ORDER BY last_seen DESC
		LIMIT 1
	`

	err := t.db.QueryRowContext(ctx, query, ipAddress).Scan(&enrolled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check enrollment: %w", err)
	}

	return enrolled, nil
}

// GetDeviceByIP retrieves device info by IP address
func (t *DeviceTracker) GetDeviceByIP(ctx context.Context, ipAddress string) (*TrackedDevice, error) {
	query := `
		SELECT device_id, ip_address, mac_address, os_type, user_agent,
		       ca_installed, installed_at, install_method, certificate_fingerprint,
		       first_seen, last_seen
		FROM device_enrollment
		WHERE ip_address = $1::inet
		ORDER BY last_seen DESC
		LIMIT 1
	`

	device := &TrackedDevice{}
	var macAddr, osType, userAgent, installMethod, certFP sql.NullString
	var installedAt sql.NullTime

	err := t.db.QueryRowContext(ctx, query, ipAddress).Scan(
		&device.DeviceID, &device.IPAddress, &macAddr, &osType, &userAgent,
		&device.CAInstalled, &installedAt, &installMethod, &certFP,
		&device.FirstSeen, &device.LastSeen,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	device.MACAddress = macAddr.String
	device.OSType = osType.String
	device.UserAgent = userAgent.String
	device.InstallMethod = installMethod.String
	device.CertFingerprint = certFP.String
	if installedAt.Valid {
		device.InstalledAt = &installedAt.Time
	}

	return device, nil
}

// ============================================================================
// Listing & Statistics
// ============================================================================

// ListPendingDevices returns devices that haven't enrolled
func (t *DeviceTracker) ListPendingDevices(ctx context.Context) ([]*TrackedDevice, error) {
	query := `
		SELECT device_id, ip_address, mac_address, os_type, user_agent,
		       first_seen, last_seen
		FROM device_enrollment
		WHERE ca_installed = false
		ORDER BY last_seen DESC
		LIMIT 100
	`

	rows, err := t.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending: %w", err)
	}
	defer rows.Close()

	var devices []*TrackedDevice
	for rows.Next() {
		device := &TrackedDevice{}
		var macAddr, osType, userAgent sql.NullString

		err := rows.Scan(
			&device.DeviceID, &device.IPAddress, &macAddr, &osType, &userAgent,
			&device.FirstSeen, &device.LastSeen,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		device.MACAddress = macAddr.String
		device.OSType = osType.String
		device.UserAgent = userAgent.String
		devices = append(devices, device)
	}

	return devices, nil
}

// GetEnrollmentStats returns enrollment statistics from database
func (t *DeviceTracker) GetEnrollmentStats(ctx context.Context) (*TrackerStats, error) {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE ca_installed = true) as enrolled,
			COUNT(*) FILTER (WHERE ca_installed = false) as pending
		FROM device_enrollment
	`

	stats := &TrackerStats{}
	err := t.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalDevices,
		&stats.EnrolledDevices,
		&stats.PendingDevices,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return stats, nil
}

// ============================================================================
// Types
// ============================================================================

// TrackedDevice represents a device in the enrollment database
type TrackedDevice struct {
	DeviceID        string
	IPAddress       string
	MACAddress      string
	OSType          string
	UserAgent       string
	CAInstalled     bool
	InstalledAt     *time.Time
	InstallMethod   string
	CertFingerprint string
	FirstSeen       time.Time
	LastSeen        time.Time
}

// TrackerStats contains enrollment statistics
type TrackerStats struct {
	TotalDevices    int
	EnrolledDevices int
	PendingDevices  int
}
