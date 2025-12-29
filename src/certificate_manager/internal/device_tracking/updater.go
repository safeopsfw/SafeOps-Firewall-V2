// Package device_tracking provides device CA installation tracking for the Certificate Manager.
package device_tracking

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// Updater handles bulk device updates and background maintenance
type Updater struct {
	tracker  *Tracker
	detector *Detector

	// Background task control
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Configuration
	scanInterval  time.Duration
	purgeInterval time.Duration
	redetectStale bool
}

// UpdaterConfig configures the device updater
type UpdaterConfig struct {
	ScanInterval  time.Duration // How often to scan for new devices
	PurgeInterval time.Duration // How often to purge stale devices
	RedetectStale bool          // Re-detect CA on stale devices
}

// DefaultUpdaterConfig returns default updater configuration
func DefaultUpdaterConfig() *UpdaterConfig {
	return &UpdaterConfig{
		ScanInterval:  1 * time.Hour,
		PurgeInterval: 24 * time.Hour,
		RedetectStale: true,
	}
}

// NewUpdater creates a new device updater
func NewUpdater(tracker *Tracker, detector *Detector, cfg *UpdaterConfig) *Updater {
	if cfg == nil {
		cfg = DefaultUpdaterConfig()
	}

	return &Updater{
		tracker:       tracker,
		detector:      detector,
		stopCh:        make(chan struct{}),
		scanInterval:  cfg.ScanInterval,
		purgeInterval: cfg.PurgeInterval,
		redetectStale: cfg.RedetectStale,
	}
}

// Start begins background maintenance tasks
func (u *Updater) Start() {
	u.wg.Add(2)

	// Stale device purge task
	go u.purgeTask()

	// Re-detection task
	if u.redetectStale {
		go u.redetectTask()
	} else {
		u.wg.Done()
	}
}

// Stop stops all background tasks
func (u *Updater) Stop() {
	close(u.stopCh)
	u.wg.Wait()
}

// purgeTask periodically purges stale devices
func (u *Updater) purgeTask() {
	defer u.wg.Done()

	ticker := time.NewTicker(u.purgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			purged, err := u.tracker.PurgeStaleDevices(ctx)
			if err != nil {
				log.Printf("[device_tracking] purge error: %v", err)
			} else if purged > 0 {
				log.Printf("[device_tracking] purged %d stale devices", purged)
			}
			cancel()
		}
	}
}

// redetectTask periodically re-detects CA installation on stale devices
func (u *Updater) redetectTask() {
	defer u.wg.Done()

	ticker := time.NewTicker(u.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			u.redetectStaleDevices(ctx)
			cancel()
		}
	}
}

// redetectStaleDevices re-checks CA installation on devices that need verification
func (u *Updater) redetectStaleDevices(ctx context.Context) {
	// Get devices with unknown or pending status
	unknownStatus := types.TrustStatusUnknown
	query := &types.DeviceQuery{
		TrustStatus: &unknownStatus,
		Limit:       100,
	}

	result, err := u.tracker.ListDevices(ctx, query)
	if err != nil {
		log.Printf("[device_tracking] failed to list unknown devices: %v", err)
		return
	}

	redetected := 0
	for _, device := range result.Devices {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if device.IPAddress == nil {
			continue
		}

		_, err := u.detector.DetectAndUpdate(ctx, device.IPAddress)
		if err != nil {
			log.Printf("[device_tracking] redetect failed for %s: %v", device.DeviceID, err)
			continue
		}
		redetected++
	}

	if redetected > 0 {
		log.Printf("[device_tracking] re-detected %d devices", redetected)
	}
}

// BulkUpdate updates multiple devices from external source (e.g., DHCP lease data)
func (u *Updater) BulkUpdate(ctx context.Context, devices []types.DeviceInfo) (updated, created int, err error) {
	for _, info := range devices {
		select {
		case <-ctx.Done():
			return updated, created, ctx.Err()
		default:
		}

		device, err := u.tracker.GetDeviceStatus(ctx, info.IPAddress)
		if err != nil {
			continue
		}

		if device == nil {
			// Create new device
			_, err = u.tracker.TrackDevice(ctx, info)
			if err == nil {
				created++
			}
		} else {
			// Update existing device
			needsUpdate := false

			if info.Hostname != "" && device.Hostname != info.Hostname {
				device.Hostname = info.Hostname
				needsUpdate = true
			}

			if info.MACAddress != "" && device.MACAddress != info.MACAddress {
				normalizedMAC, _ := types.NormalizeMACAddress(info.MACAddress)
				if normalizedMAC != "" {
					device.MACAddress = normalizedMAC
					needsUpdate = true
				}
			}

			if needsUpdate {
				device.UpdateLastSeen()
				// Note: This would require direct repo access, using tracker for now
				_, _ = u.tracker.TrackDevice(ctx, info)
				updated++
			}
		}
	}

	return updated, created, nil
}

// SyncWithDHCP synchronizes device tracking with DHCP lease data
func (u *Updater) SyncWithDHCP(ctx context.Context, leases []DHCPLease) error {
	devices := make([]types.DeviceInfo, 0, len(leases))

	for _, lease := range leases {
		if lease.IP == nil {
			continue
		}

		devices = append(devices, types.DeviceInfo{
			IPAddress:  lease.IP,
			MACAddress: lease.MAC,
			Hostname:   lease.Hostname,
		})
	}

	_, _, err := u.BulkUpdate(ctx, devices)
	return err
}

// DHCPLease represents a DHCP lease for sync purposes
type DHCPLease struct {
	IP       net.IP
	MAC      string
	Hostname string
	Expires  time.Time
}

// UpdateDeviceHostname updates just the hostname for a device
func (u *Updater) UpdateDeviceHostname(ctx context.Context, ip net.IP, hostname string) error {
	device, err := u.tracker.GetDeviceStatus(ctx, ip)
	if err != nil {
		return err
	}

	if device == nil {
		// Create new device with hostname
		_, err = u.tracker.TrackDevice(ctx, types.DeviceInfo{
			IPAddress: ip,
			Hostname:  hostname,
		})
		return err
	}

	// Update hostname via tracking
	_, err = u.tracker.TrackDevice(ctx, types.DeviceInfo{
		IPAddress:  ip,
		MACAddress: device.MACAddress,
		Hostname:   hostname,
	})

	return err
}

// UpdateDeviceUserAgent updates the user agent for a device
func (u *Updater) UpdateDeviceUserAgent(ctx context.Context, ip net.IP, userAgent string) error {
	device, err := u.tracker.GetDeviceStatus(ctx, ip)
	if err != nil {
		return err
	}

	if device == nil {
		return ErrDeviceNotFound
	}

	// Detect OS from user agent
	osType := detectOSFromUserAgent(userAgent)
	device.UserAgent = userAgent
	device.OSType = osType
	device.UpdateLastSeen()

	// Would need direct repo access here
	// For now, just track to update last seen
	_, err = u.tracker.TrackDevice(ctx, device.ToInfo())
	return err
}

// detectOSFromUserAgent attempts to detect the OS from user agent string
func detectOSFromUserAgent(ua string) string {
	switch {
	case contains(ua, "Windows"):
		return "windows"
	case contains(ua, "Macintosh") || contains(ua, "Mac OS"):
		return "macos"
	case contains(ua, "iPhone") || contains(ua, "iPad"):
		return "ios"
	case contains(ua, "Android"):
		return "android"
	case contains(ua, "Linux"):
		return "linux"
	case contains(ua, "CrOS"):
		return "chromeos"
	default:
		return "other"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
