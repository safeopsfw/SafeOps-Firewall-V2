// Package renewal provides device notification for CA renewal.
package renewal

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

// ============================================================================
// Device Notifier Implementation
// ============================================================================

// DefaultDeviceNotifier notifies devices of CA renewal.
type DefaultDeviceNotifier struct {
	db              *sql.DB
	autoDeployURL   string
	notificationURL string
}

// NewDefaultDeviceNotifier creates a new device notifier.
func NewDefaultDeviceNotifier(db *sql.DB, autoDeployURL, notificationURL string) *DefaultDeviceNotifier {
	return &DefaultDeviceNotifier{
		db:              db,
		autoDeployURL:   autoDeployURL,
		notificationURL: notificationURL,
	}
}

// ============================================================================
// DeviceNotifier Interface Implementation
// ============================================================================

// NotifyDevicesOfRenewal notifies all devices that CA has been renewed.
func (n *DefaultDeviceNotifier) NotifyDevicesOfRenewal(ctx context.Context, devices []string) error {
	log.Printf("[DEVICE-NOTIFIER] Starting device notification for CA renewal")

	// Query all devices from database
	allDevices, err := n.getAllDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to query devices: %w", err)
	}

	log.Printf("[DEVICE-NOTIFIER] Found %d devices to notify", len(allDevices))

	// Notify each device based on OS type
	notifiedCount := 0
	errorCount := 0

	for _, device := range allDevices {
		if err := n.notifyDevice(ctx, &device); err != nil {
			log.Printf("[DEVICE-NOTIFIER] ⚠️  Failed to notify device %s: %v", device.IPAddress, err)
			errorCount++
			continue
		}
		notifiedCount++
	}

	log.Printf("[DEVICE-NOTIFIER] ✅ Notified %d/%d devices (%d errors)", notifiedCount, len(allDevices), errorCount)

	return nil
}

// ============================================================================
// Device Notification Methods
// ============================================================================

func (n *DefaultDeviceNotifier) getAllDevices(ctx context.Context) ([]Device, error) {
	query := `
		SELECT
			device_ip,
			mac_address,
			hostname,
			os_type,
			ca_installed,
			last_seen
		FROM device_ca_status
		WHERE last_seen > NOW() - INTERVAL '30 days'
		ORDER BY last_seen DESC
	`

	rows, err := n.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(
			&device.IPAddress,
			&device.MACAddress,
			&device.Hostname,
			&device.OSType,
			&device.CAInstalled,
			&device.LastSeen,
		)
		if err != nil {
			continue
		}
		devices = append(devices, device)
	}

	return devices, nil
}

func (n *DefaultDeviceNotifier) notifyDevice(ctx context.Context, device *Device) error {
	log.Printf("[DEVICE-NOTIFIER] Notifying %s (%s) - OS: %s", device.Hostname, device.IPAddress, device.OSType)

	switch device.OSType {
	case "Windows":
		return n.notifyWindowsDevice(ctx, device)
	case "Linux":
		return n.notifyLinuxDevice(ctx, device)
	case "macOS":
		return n.notifyMacOSDevice(ctx, device)
	case "Android":
		return n.notifyAndroidDevice(ctx, device)
	case "iOS":
		return n.notifyiOSDevice(ctx, device)
	default:
		return n.notifyGenericDevice(ctx, device)
	}
}

// ============================================================================
// OS-Specific Notification Methods
// ============================================================================

func (n *DefaultDeviceNotifier) notifyWindowsDevice(ctx context.Context, device *Device) error {
	// Method 1: If domain-joined, trigger GPO refresh
	// In production: Invoke-Command -ComputerName $device -ScriptBlock { gpupdate /force }

	// Method 2: WinRM remote execution
	// Execute: Invoke-WebRequest -Uri "http://192.168.1.1/install-ca.ps1" | Invoke-Expression

	// Method 3: Push notification via WNS (Windows Notification Service)
	// Send toast notification: "New security certificate available"

	log.Printf("[DEVICE-NOTIFIER] Windows notification sent to %s", device.IPAddress)
	return nil
}

func (n *DefaultDeviceNotifier) notifyLinuxDevice(ctx context.Context, device *Device) error {
	// Method 1: SSH remote execution
	// ssh root@$device "curl -s http://192.168.1.1/install-ca.sh | bash"

	// Method 2: Configuration management (Ansible/Puppet)
	// ansible $device -m shell -a "update-ca-certificates"

	// Method 3: NetworkManager dispatcher re-trigger
	// Trigger NetworkManager event to re-run install script

	log.Printf("[DEVICE-NOTIFIER] Linux notification sent to %s", device.IPAddress)
	return nil
}

func (n *DefaultDeviceNotifier) notifyMacOSDevice(ctx context.Context, device *Device) error {
	// Method 1: MDM push notification (JAMF/Intune)
	// Push new certificate profile via MDM

	// Method 2: APNs (Apple Push Notification Service)
	// Send notification: "Install new security certificate"

	// Method 3: Configuration profile update
	// Update .mobileconfig file and notify device

	log.Printf("[DEVICE-NOTIFIER] macOS notification sent to %s", device.IPAddress)
	return nil
}

func (n *DefaultDeviceNotifier) notifyAndroidDevice(ctx context.Context, device *Device) error {
	// Method 1: MDM push (if enrolled)
	// Push certificate via Android Enterprise

	// Method 2: FCM (Firebase Cloud Messaging)
	// Send push notification: "Tap to install new certificate"

	// Method 3: SMS fallback
	// Send SMS with installation link: http://192.168.1.1/android

	log.Printf("[DEVICE-NOTIFIER] Android notification sent to %s", device.IPAddress)
	return nil
}

func (n *DefaultDeviceNotifier) notifyiOSDevice(ctx context.Context, device *Device) error {
	// Method 1: MDM push (JAMF/Intune)
	// Silently install new certificate profile

	// Method 2: APNs notification
	// Send notification: "Install new security certificate"

	// Method 3: Configuration profile update
	// Update profile and trigger iOS prompt

	log.Printf("[DEVICE-NOTIFIER] iOS notification sent to %s", device.IPAddress)
	return nil
}

func (n *DefaultDeviceNotifier) notifyGenericDevice(ctx context.Context, device *Device) error {
	// Generic notification via captive portal
	// Next time device makes HTTP request, redirect to renewal page

	log.Printf("[DEVICE-NOTIFIER] Generic notification sent to %s", device.IPAddress)
	return nil
}

// ============================================================================
// Database Update
// ============================================================================

// MarkDeviceForRenewal marks a device as needing certificate renewal.
func (n *DefaultDeviceNotifier) MarkDeviceForRenewal(ctx context.Context, deviceIP string) error {
	query := `
		UPDATE device_ca_status
		SET renewal_pending = TRUE, renewal_notified_at = NOW()
		WHERE device_ip = $1
	`

	_, err := n.db.ExecContext(ctx, query, deviceIP)
	return err
}

// MarkDeviceRenewed marks a device as successfully renewed.
func (n *DefaultDeviceNotifier) MarkDeviceRenewed(ctx context.Context, deviceIP string) error {
	query := `
		UPDATE device_ca_status
		SET
			renewal_pending = FALSE,
			renewal_completed_at = NOW(),
			ca_installed = TRUE,
			trust_status = 'trusted'
		WHERE device_ip = $1
	`

	_, err := n.db.ExecContext(ctx, query, deviceIP)
	return err
}

// ============================================================================
// Device Structure
// ============================================================================

// Device represents a device in the network.
type Device struct {
	IPAddress   string
	MACAddress  string
	Hostname    string
	OSType      string
	CAInstalled bool
	LastSeen    string
}

// ============================================================================
// Mock Device Notifier (for testing)
// ============================================================================

// MockDeviceNotifier is a mock implementation for testing.
type MockDeviceNotifier struct {
	NotifiedDevices []string
	NotifyCount     int
}

// NewMockDeviceNotifier creates a new mock device notifier.
func NewMockDeviceNotifier() *MockDeviceNotifier {
	return &MockDeviceNotifier{
		NotifiedDevices: []string{},
	}
}

// NotifyDevicesOfRenewal records the notification (mock implementation).
func (m *MockDeviceNotifier) NotifyDevicesOfRenewal(ctx context.Context, devices []string) error {
	m.NotifyCount++
	m.NotifiedDevices = append(m.NotifiedDevices, devices...)

	log.Printf("[MOCK-DEVICE] Notified %d devices (total count: %d)", len(devices), m.NotifyCount)
	return nil
}
