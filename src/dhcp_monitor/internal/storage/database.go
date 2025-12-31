// Package storage provides device tracking database
package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Database handles device tracking storage
type Database struct {
	conn *sql.DB
}

// Device represents a tracked device
type Device struct {
	IP                string
	MAC               string
	Hostname          string
	HasCertificate    bool
	CertInstallTime   *time.Time
	FirstSeen         time.Time
	LastSeen          time.Time
	OS                string // Detected OS: ios, android, windows, macos, linux
	UserAgent         string
	AccessGranted     bool
	AccessGrantedTime *time.Time

	// One-time captive portal tracking
	SeenPortal     bool       // Has device been shown the captive portal?
	SeenPortalTime *time.Time // When was the portal first shown?

	// NIC Integration
	NICInterfaceID   string // NIC interface ID
	NICInterfaceName string // NIC interface name (e.g., "Ethernet 1", "WiFi")
	NICType          string // NIC type: WAN, LAN, WIFI, Hotspot
	WiFiSSID         string // WiFi SSID (if connected via WiFi)
}

// NewDatabase creates or opens the device tracking database
func NewDatabase(path string) (*Database, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &Database{conn: conn}

	// Initialize schema
	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// initSchema creates database tables
func (db *Database) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS devices (
		ip TEXT PRIMARY KEY,
		mac TEXT NOT NULL,
		hostname TEXT,
		has_certificate BOOLEAN NOT NULL DEFAULT 0,
		cert_install_time DATETIME,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		os TEXT,
		user_agent TEXT,
		access_granted BOOLEAN NOT NULL DEFAULT 0,
		access_granted_time DATETIME,
		seen_portal BOOLEAN NOT NULL DEFAULT 0,
		seen_portal_time DATETIME,
		nic_interface_id TEXT,
		nic_interface_name TEXT,
		nic_type TEXT,
		wifi_ssid TEXT,
		UNIQUE(mac)
	);

	CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
	CREATE INDEX IF NOT EXISTS idx_devices_has_cert ON devices(has_certificate);
	CREATE INDEX IF NOT EXISTS idx_devices_access_granted ON devices(access_granted);
	CREATE INDEX IF NOT EXISTS idx_devices_nic_type ON devices(nic_type);

	CREATE TABLE IF NOT EXISTS device_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_ip TEXT NOT NULL,
		event_type TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		details TEXT,
		FOREIGN KEY(device_ip) REFERENCES devices(ip)
	);

	CREATE INDEX IF NOT EXISTS idx_events_device_ip ON device_events(device_ip);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON device_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_type ON device_events(event_type);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// AddOrUpdateDevice adds a new device or updates an existing one
func (db *Database) AddOrUpdateDevice(device *Device) error {
	query := `
	INSERT INTO devices (ip, mac, hostname, has_certificate, cert_install_time, first_seen, last_seen, os, user_agent, access_granted, access_granted_time, nic_interface_id, nic_interface_name, nic_type, wifi_ssid)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		mac = excluded.mac,
		hostname = excluded.hostname,
		last_seen = excluded.last_seen,
		os = COALESCE(excluded.os, os),
		user_agent = COALESCE(excluded.user_agent, user_agent),
		nic_interface_id = COALESCE(excluded.nic_interface_id, nic_interface_id),
		nic_interface_name = COALESCE(excluded.nic_interface_name, nic_interface_name),
		nic_type = COALESCE(excluded.nic_type, nic_type),
		wifi_ssid = COALESCE(excluded.wifi_ssid, wifi_ssid)
	`

	_, err := db.conn.Exec(query,
		device.IP,
		device.MAC,
		device.Hostname,
		device.HasCertificate,
		device.CertInstallTime,
		device.FirstSeen,
		device.LastSeen,
		device.OS,
		device.UserAgent,
		device.AccessGranted,
		device.AccessGrantedTime,
		device.NICInterfaceID,
		device.NICInterfaceName,
		device.NICType,
		device.WiFiSSID,
	)

	return err
}

// GetDeviceByIP retrieves a device by IP address
func (db *Database) GetDeviceByIP(ip string) (*Device, error) {
	query := `
	SELECT ip, mac, hostname, has_certificate, cert_install_time, first_seen, last_seen, os, user_agent, access_granted, access_granted_time, seen_portal, seen_portal_time, nic_interface_id, nic_interface_name, nic_type, wifi_ssid
	FROM devices
	WHERE ip = ?
	`

	var device Device
	var certInstallTime, accessGrantedTime, seenPortalTime sql.NullTime

	err := db.conn.QueryRow(query, ip).Scan(
		&device.IP,
		&device.MAC,
		&device.Hostname,
		&device.HasCertificate,
		&certInstallTime,
		&device.FirstSeen,
		&device.LastSeen,
		&device.OS,
		&device.UserAgent,
		&device.AccessGranted,
		&accessGrantedTime,
		&device.SeenPortal,
		&seenPortalTime,
		&device.NICInterfaceID,
		&device.NICInterfaceName,
		&device.NICType,
		&device.WiFiSSID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if certInstallTime.Valid {
		device.CertInstallTime = &certInstallTime.Time
	}
	if accessGrantedTime.Valid {
		device.AccessGrantedTime = &accessGrantedTime.Time
	}
	if seenPortalTime.Valid {
		device.SeenPortalTime = &seenPortalTime.Time
	}

	return &device, nil
}

// MarkDeviceSeenPortal marks a device as having seen the captive portal (one-time)
func (db *Database) MarkDeviceSeenPortal(ip string) error {
	query := `
	UPDATE devices 
	SET seen_portal = 1, seen_portal_time = ?
	WHERE ip = ? AND seen_portal = 0
	`
	_, err := db.conn.Exec(query, time.Now(), ip)
	return err
}

// GetDeviceByMAC retrieves a device by MAC address
func (db *Database) GetDeviceByMAC(mac string) (*Device, error) {
	query := `
	SELECT ip, mac, hostname, has_certificate, cert_install_time, first_seen, last_seen, os, user_agent, access_granted, access_granted_time, nic_interface_id, nic_interface_name, nic_type, wifi_ssid
	FROM devices
	WHERE mac = ?
	`

	var device Device
	var certInstallTime, accessGrantedTime sql.NullTime

	err := db.conn.QueryRow(query, mac).Scan(
		&device.IP,
		&device.MAC,
		&device.Hostname,
		&device.HasCertificate,
		&certInstallTime,
		&device.FirstSeen,
		&device.LastSeen,
		&device.OS,
		&device.UserAgent,
		&device.AccessGranted,
		&accessGrantedTime,
		&device.NICInterfaceID,
		&device.NICInterfaceName,
		&device.NICType,
		&device.WiFiSSID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if certInstallTime.Valid {
		device.CertInstallTime = &certInstallTime.Time
	}
	if accessGrantedTime.Valid {
		device.AccessGrantedTime = &accessGrantedTime.Time
	}

	return &device, nil
}

// UpdateCertificateStatus marks a device as having the certificate installed
func (db *Database) UpdateCertificateStatus(ip string, hasCert bool) error {
	now := time.Now()
	query := `
	UPDATE devices
	SET has_certificate = ?, cert_install_time = ?, access_granted = ?, access_granted_time = ?
	WHERE ip = ?
	`

	var certInstallTime, accessGrantedTime *time.Time
	if hasCert {
		certInstallTime = &now
		accessGrantedTime = &now
	}

	_, err := db.conn.Exec(query, hasCert, certInstallTime, hasCert, accessGrantedTime, ip)
	return err
}

// UpdateDeviceOS updates the detected OS for a device
func (db *Database) UpdateDeviceOS(ip string, os string, userAgent string) error {
	query := `
	UPDATE devices
	SET os = ?, user_agent = ?
	WHERE ip = ?
	`

	_, err := db.conn.Exec(query, os, userAgent, ip)
	return err
}

// GetAllDevices returns all tracked devices
func (db *Database) GetAllDevices() ([]Device, error) {
	query := `
	SELECT ip, mac, hostname, has_certificate, cert_install_time, first_seen, last_seen, os, user_agent, access_granted, access_granted_time, seen_portal, seen_portal_time, nic_interface_id, nic_interface_name, nic_type, wifi_ssid
	FROM devices
	ORDER BY last_seen DESC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var certInstallTime, accessGrantedTime, seenPortalTime sql.NullTime

		err := rows.Scan(
			&device.IP,
			&device.MAC,
			&device.Hostname,
			&device.HasCertificate,
			&certInstallTime,
			&device.FirstSeen,
			&device.LastSeen,
			&device.OS,
			&device.UserAgent,
			&device.AccessGranted,
			&accessGrantedTime,
			&device.SeenPortal,
			&seenPortalTime,
			&device.NICInterfaceID,
			&device.NICInterfaceName,
			&device.NICType,
			&device.WiFiSSID,
		)
		if err != nil {
			return nil, err
		}

		if certInstallTime.Valid {
			device.CertInstallTime = &certInstallTime.Time
		}
		if accessGrantedTime.Valid {
			device.AccessGrantedTime = &accessGrantedTime.Time
		}
		if seenPortalTime.Valid {
			device.SeenPortalTime = &seenPortalTime.Time
		}

		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// GetUnenrolledDevices returns devices without certificate installed
func (db *Database) GetUnenrolledDevices() ([]Device, error) {
	query := `
	SELECT ip, mac, hostname, has_certificate, cert_install_time, first_seen, last_seen, os, user_agent, access_granted, access_granted_time, nic_interface_id, nic_interface_name, nic_type, wifi_ssid
	FROM devices
	WHERE has_certificate = 0
	ORDER BY last_seen DESC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var certInstallTime, accessGrantedTime sql.NullTime

		err := rows.Scan(
			&device.IP,
			&device.MAC,
			&device.Hostname,
			&device.HasCertificate,
			&certInstallTime,
			&device.FirstSeen,
			&device.LastSeen,
			&device.OS,
			&device.UserAgent,
			&device.AccessGranted,
			&accessGrantedTime,
			&device.NICInterfaceID,
			&device.NICInterfaceName,
			&device.NICType,
			&device.WiFiSSID,
		)
		if err != nil {
			return nil, err
		}

		if certInstallTime.Valid {
			device.CertInstallTime = &certInstallTime.Time
		}
		if accessGrantedTime.Valid {
			device.AccessGrantedTime = &accessGrantedTime.Time
		}

		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// LogEvent logs a device-related event
func (db *Database) LogEvent(deviceIP string, eventType string, details string) error {
	query := `
	INSERT INTO device_events (device_ip, event_type, timestamp, details)
	VALUES (?, ?, ?, ?)
	`

	_, err := db.conn.Exec(query, deviceIP, eventType, time.Now(), details)
	return err
}

// GetDeviceEvents retrieves events for a specific device
func (db *Database) GetDeviceEvents(deviceIP string, limit int) ([]DeviceEvent, error) {
	query := `
	SELECT id, device_ip, event_type, timestamp, details
	FROM device_events
	WHERE device_ip = ?
	ORDER BY timestamp DESC
	LIMIT ?
	`

	rows, err := db.conn.Query(query, deviceIP, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []DeviceEvent
	for rows.Next() {
		var event DeviceEvent
		err := rows.Scan(&event.ID, &event.DeviceIP, &event.EventType, &event.Timestamp, &event.Details)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

// GetStats returns database statistics
func (db *Database) GetStats() (Stats, error) {
	var stats Stats

	// Total devices
	err := db.conn.QueryRow("SELECT COUNT(*) FROM devices").Scan(&stats.TotalDevices)
	if err != nil {
		return stats, err
	}

	// Enrolled devices
	err = db.conn.QueryRow("SELECT COUNT(*) FROM devices WHERE has_certificate = 1").Scan(&stats.EnrolledDevices)
	if err != nil {
		return stats, err
	}

	// Unenrolled devices
	stats.UnenrolledDevices = stats.TotalDevices - stats.EnrolledDevices

	// Devices seen in last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	err = db.conn.QueryRow("SELECT COUNT(*) FROM devices WHERE last_seen > ?", oneHourAgo).Scan(&stats.ActiveDevicesLastHour)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// CleanupOldDevices removes devices not seen for the specified number of days
func (db *Database) CleanupOldDevices(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	query := `DELETE FROM devices WHERE last_seen < ?`

	result, err := db.conn.Exec(query, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Close closes the database connection
func (db *Database) Close() error {
	return db.conn.Close()
}

// DeviceEvent represents a device event
type DeviceEvent struct {
	ID        int64
	DeviceIP  string
	EventType string
	Timestamp time.Time
	Details   string
}

// Stats holds database statistics
type Stats struct {
	TotalDevices          int
	EnrolledDevices       int
	UnenrolledDevices     int
	ActiveDevicesLastHour int
}
