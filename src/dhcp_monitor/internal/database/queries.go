// Package database provides SQL CRUD operations for DHCP Monitor
package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// =============================================================================
// DEVICE QUERIES
// =============================================================================

// CreateDevice inserts a new device record
func (c *DatabaseClient) CreateDevice(ctx context.Context, device *Device) error {
	if device.DeviceID == uuid.Nil {
		device.DeviceID = uuid.New()
	}

	query := `
		INSERT INTO devices (
			device_id, mac_address, current_ip, previous_ip, hostname,
			device_type, vendor, trust_status, interface_name, interface_index,
			interface_guid, status, is_online, detection_method, first_seen,
			last_seen, notes
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)
		RETURNING created_at, updated_at`

	return c.DB.QueryRowContext(ctx, query,
		device.DeviceID, device.MACAddress, device.CurrentIP.String(),
		device.PreviousIP, device.Hostname, device.DeviceType, device.Vendor,
		device.TrustStatus, device.InterfaceName, device.InterfaceIndex,
		device.InterfaceGUID, device.Status, device.IsOnline, device.DetectionMethod,
		device.FirstSeen, device.LastSeen, device.Notes,
	).Scan(&device.CreatedAt, &device.UpdatedAt)
}

// GetDeviceByIP retrieves device by IP address
func (c *DatabaseClient) GetDeviceByIP(ctx context.Context, ip string) (*Device, error) {
	query := `SELECT * FROM devices WHERE current_ip = $1`
	device := &Device{}

	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, ip).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes,
	)

	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows // Return unwrapped so callers can check with ==
	}
	if err != nil {
		return nil, fmt.Errorf("query error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// GetDeviceByMAC retrieves device by MAC address
func (c *DatabaseClient) GetDeviceByMAC(ctx context.Context, mac string) (*Device, error) {
	query := `SELECT * FROM devices WHERE mac_address = $1`
	device := &Device{}

	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, mac).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes,
	)

	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows // Return unwrapped so callers can check with ==
	}
	if err != nil {
		return nil, fmt.Errorf("query error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// GetDeviceByID retrieves device by UUID
func (c *DatabaseClient) GetDeviceByID(ctx context.Context, deviceID uuid.UUID) (*Device, error) {
	query := `SELECT * FROM devices WHERE device_id = $1`
	device := &Device{}

	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, deviceID).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("query error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// UpdateDevice updates an existing device record
func (c *DatabaseClient) UpdateDevice(ctx context.Context, device *Device) error {
	query := `
		UPDATE devices SET
			current_ip = $1, previous_ip = $2, hostname = $3, device_type = $4,
			vendor = $5, trust_status = $6, interface_name = $7, interface_index = $8,
			status = $9, is_online = $10, detection_method = $11, last_seen = $12,
			notes = $13
		WHERE device_id = $14`

	result, err := c.DB.ExecContext(ctx, query,
		device.CurrentIP.String(), device.PreviousIP, device.Hostname, device.DeviceType,
		device.Vendor, device.TrustStatus, device.InterfaceName, device.InterfaceIndex,
		device.Status, device.IsOnline, device.DetectionMethod, time.Now(),
		device.Notes, device.DeviceID,
	)
	if err != nil {
		return fmt.Errorf("update error: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("device not found: %s", device.DeviceID)
	}

	return nil
}

// UpdateTrustStatus updates device trust status
func (c *DatabaseClient) UpdateTrustStatus(ctx context.Context, deviceID uuid.UUID, status TrustStatus) error {
	query := `UPDATE devices SET trust_status = $1, last_seen = NOW() WHERE device_id = $2`

	result, err := c.DB.ExecContext(ctx, query, status, deviceID)
	if err != nil {
		return fmt.Errorf("update error: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	return nil
}

// MarkPortalShown marks that device has seen the captive portal (Phase 3A ALLOW_ONCE)
func (c *DatabaseClient) MarkPortalShown(ctx context.Context, deviceID uuid.UUID) (*Device, error) {
	query := `UPDATE devices 
              SET portal_shown = true, portal_shown_at = NOW(), last_seen = NOW()
              WHERE device_id = $1
              RETURNING *`

	device := &Device{}
	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, deviceID).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes, &device.PortalShown, &device.PortalShownAt,
		&device.CACertInstalled, &device.CACertInstalledAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("update error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// MarkPortalShownByIP marks portal shown using IP address (convenience method)
func (c *DatabaseClient) MarkPortalShownByIP(ctx context.Context, ipAddress string) (*Device, error) {
	query := `UPDATE devices 
              SET portal_shown = true, portal_shown_at = NOW(), last_seen = NOW()
              WHERE current_ip = $1
              RETURNING *`

	device := &Device{}
	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, ipAddress).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes, &device.PortalShown, &device.PortalShownAt,
		&device.CACertInstalled, &device.CACertInstalledAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found for IP: %s", ipAddress)
	}
	if err != nil {
		return nil, fmt.Errorf("update error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// MarkCACertInstalled marks that device has installed CA certificate (Phase 3B)
func (c *DatabaseClient) MarkCACertInstalled(ctx context.Context, deviceID uuid.UUID) (*Device, error) {
	query := `UPDATE devices
              SET ca_cert_installed = true, ca_cert_installed_at = NOW(), last_seen = NOW()
              WHERE device_id = $1
              RETURNING *`

	device := &Device{}
	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, deviceID).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes, &device.PortalShown, &device.PortalShownAt,
		&device.CACertInstalled, &device.CACertInstalledAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("update error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// MarkCACertInstalledByIP marks CA cert installed using IP address
func (c *DatabaseClient) MarkCACertInstalledByIP(ctx context.Context, ipAddress string) (*Device, error) {
	query := `UPDATE devices
              SET ca_cert_installed = true, ca_cert_installed_at = NOW(), last_seen = NOW()
              WHERE current_ip = $1
              RETURNING *`

	device := &Device{}
	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, ipAddress).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes, &device.PortalShown, &device.PortalShownAt,
		&device.CACertInstalled, &device.CACertInstalledAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found for IP: %s", ipAddress)
	}
	if err != nil {
		return nil, fmt.Errorf("update error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// MarkCACertInstalledByMAC marks CA cert installed using MAC address
func (c *DatabaseClient) MarkCACertInstalledByMAC(ctx context.Context, macAddress string) (*Device, error) {
	query := `UPDATE devices
              SET ca_cert_installed = true, ca_cert_installed_at = NOW(), last_seen = NOW()
              WHERE mac_address = $1
              RETURNING *`

	device := &Device{}
	var currentIP, previousIP sql.NullString

	err := c.DB.QueryRowContext(ctx, query, macAddress).Scan(
		&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
		&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
		&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
		&device.Status, &device.IsOnline, &device.DetectionMethod,
		&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
		&device.Notes, &device.PortalShown, &device.PortalShownAt,
		&device.CACertInstalled, &device.CACertInstalledAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found for MAC: %s", macAddress)
	}
	if err != nil {
		return nil, fmt.Errorf("update error: %w", err)
	}

	if currentIP.Valid {
		device.CurrentIP = net.ParseIP(currentIP.String)
	}
	device.PreviousIP = previousIP

	return device, nil
}

// UpdateDeviceOnlineStatus marks device online/offline
func (c *DatabaseClient) UpdateDeviceOnlineStatus(ctx context.Context, deviceID uuid.UUID, isOnline bool) error {
	status := DeviceStatusActive
	if !isOnline {
		status = DeviceStatusOffline
	}

	query := `UPDATE devices SET is_online = $1, status = $2, last_seen = NOW() WHERE device_id = $3`

	_, err := c.DB.ExecContext(ctx, query, isOnline, status, deviceID)
	return err
}

// ListDevices retrieves filtered, paginated device list
func (c *DatabaseClient) ListDevices(ctx context.Context, filter *DeviceFilter) ([]*Device, int32, error) {
	baseQuery := `FROM devices WHERE 1=1`
	args := []interface{}{}
	argCount := 0

	if filter.TrustStatus != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND trust_status = $%d", argCount)
		args = append(args, filter.TrustStatus)
	}
	if filter.DeviceType != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND device_type = $%d", argCount)
		args = append(args, filter.DeviceType)
	}
	if filter.Status != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND status = $%d", argCount)
		args = append(args, filter.Status)
	}
	if filter.InterfaceName != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND interface_name = $%d", argCount)
		args = append(args, filter.InterfaceName)
	}
	if filter.OnlineOnly {
		baseQuery += " AND is_online = true"
	}

	// Get total count
	var totalCount int32
	countQuery := "SELECT COUNT(*) " + baseQuery
	err := c.DB.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("count query error: %w", err)
	}

	// Get devices with pagination
	selectQuery := "SELECT * " + baseQuery + " ORDER BY last_seen DESC"

	if filter.Limit > 0 {
		argCount++
		selectQuery += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		argCount++
		selectQuery += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := c.DB.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

	devices := []*Device{}
	for rows.Next() {
		device := &Device{}
		var currentIP, previousIP sql.NullString

		err := rows.Scan(
			&device.DeviceID, &device.MACAddress, &currentIP, &previousIP,
			&device.Hostname, &device.DeviceType, &device.Vendor, &device.TrustStatus,
			&device.InterfaceName, &device.InterfaceIndex, &device.InterfaceGUID,
			&device.Status, &device.IsOnline, &device.DetectionMethod,
			&device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt,
			&device.Notes,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan error: %w", err)
		}

		if currentIP.Valid {
			device.CurrentIP = net.ParseIP(currentIP.String)
		}
		device.PreviousIP = previousIP
		devices = append(devices, device)
	}

	return devices, totalCount, nil
}

// GetDeviceStats returns aggregate device statistics
func (c *DatabaseClient) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'ACTIVE') as active,
			COUNT(*) FILTER (WHERE trust_status = 'TRUSTED') as trusted,
			COUNT(*) FILTER (WHERE trust_status = 'UNTRUSTED') as untrusted,
			COUNT(*) FILTER (WHERE trust_status = 'BLOCKED') as blocked,
			COUNT(*) FILTER (WHERE status = 'OFFLINE') as offline,
			COUNT(*) FILTER (WHERE is_online = true) as online
		FROM devices`

	stats := &DeviceStats{}
	err := c.DB.QueryRowContext(ctx, query).Scan(
		&stats.TotalDevices, &stats.ActiveDevices, &stats.TrustedDevices,
		&stats.UntrustedDevices, &stats.BlockedDevices, &stats.OfflineDevices,
		&stats.OnlineDevices,
	)
	if err != nil {
		return nil, fmt.Errorf("stats query error: %w", err)
	}

	return stats, nil
}

// DeleteDevice removes a device (cascades to leases and history)
func (c *DatabaseClient) DeleteDevice(ctx context.Context, deviceID uuid.UUID) error {
	query := `DELETE FROM devices WHERE device_id = $1`
	result, err := c.DB.ExecContext(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("delete error: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	return nil
}

// =============================================================================
// DHCP LEASE QUERIES
// =============================================================================

// CreateLease inserts a new DHCP lease record
func (c *DatabaseClient) CreateLease(ctx context.Context, lease *DHCPLease) error {
	if lease.LeaseID == uuid.Nil {
		lease.LeaseID = uuid.New()
	}

	query := `
		INSERT INTO dhcp_leases (
			lease_id, device_id, ip_address, interface_name,
			lease_start, lease_end, lease_state, lease_renewals
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`

	return c.DB.QueryRowContext(ctx, query,
		lease.LeaseID, lease.DeviceID, lease.IPAddress.String(), lease.InterfaceName,
		lease.LeaseStart, lease.LeaseEnd, lease.LeaseState, lease.LeaseRenewals,
	).Scan(&lease.CreatedAt)
}

// ExpireOldLeases marks old active leases as expired
func (c *DatabaseClient) ExpireOldLeases(ctx context.Context, cutoff time.Time) (int64, error) {
	query := `
		UPDATE dhcp_leases 
		SET lease_state = 'EXPIRED' 
		WHERE lease_end < $1 AND lease_state = 'ACTIVE'`

	result, err := c.DB.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// =============================================================================
// IP HISTORY QUERIES
// =============================================================================

// CreateIPHistory logs an IP address change
func (c *DatabaseClient) CreateIPHistory(ctx context.Context, history *IPHistory) error {
	if history.HistoryID == uuid.Nil {
		history.HistoryID = uuid.New()
	}

	query := `
		INSERT INTO ip_history (
			history_id, device_id, ip_address, previous_ip,
			interface_name, interface_index, change_reason, assigned_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`

	return c.DB.QueryRowContext(ctx, query,
		history.HistoryID, history.DeviceID, history.IPAddress.String(),
		history.PreviousIP, history.InterfaceName, history.InterfaceIndex,
		history.ChangeReason, history.AssignedAt,
	).Scan(&history.CreatedAt)
}

// PurgeOldIPHistory deletes old IP history records
func (c *DatabaseClient) PurgeOldIPHistory(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM ip_history WHERE assigned_at < NOW() - INTERVAL '1 day' * $1`

	result, err := c.DB.ExecContext(ctx, query, retentionDays)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Suppress unused import warning
var _ = pq.Array
