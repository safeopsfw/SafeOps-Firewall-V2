// Package device_tracking provides device CA installation tracking for the Certificate Manager.
// It monitors network devices to track which have downloaded and installed the SafeOps root CA.
package device_tracking

import (
	"context"
	"net"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// DeviceRepository defines the interface for device persistence
type DeviceRepository interface {
	// GetDevice retrieves device status by IP or MAC
	GetDevice(ctx context.Context, ip net.IP, mac string) (*types.DeviceStatus, error)

	// GetDeviceByID retrieves device by its unique ID
	GetDeviceByID(ctx context.Context, deviceID string) (*types.DeviceStatus, error)

	// SaveDevice saves or updates a device status
	SaveDevice(ctx context.Context, device *types.DeviceStatus) error

	// ListDevices returns devices matching the query
	ListDevices(ctx context.Context, query *types.DeviceQuery) (*types.DeviceListResult, error)

	// DeleteDevice removes a device from tracking
	DeleteDevice(ctx context.Context, deviceID string) error

	// GetStatistics returns aggregate device statistics
	GetStatistics(ctx context.Context) (*types.DeviceStatistics, error)
}

// DownloadRepository defines the interface for download record persistence
type DownloadRepository interface {
	// RecordDownload saves a new download record
	RecordDownload(ctx context.Context, record *types.DownloadRecord) error

	// GetDownloads retrieves download records for a device
	GetDownloads(ctx context.Context, deviceID string, limit int) ([]*types.DownloadRecord, error)

	// GetDownloadCount returns total downloads for a device
	GetDownloadCount(ctx context.Context, deviceID string) (int64, error)
}

// Tracker manages device CA installation tracking
type Tracker struct {
	deviceRepo   DeviceRepository
	downloadRepo DownloadRepository

	// In-memory cache for fast lookups
	cache       map[string]*types.DeviceStatus
	cacheMu     sync.RWMutex
	cacheMaxAge time.Duration

	// Configuration
	staleDuration time.Duration // How long before a device is considered stale
}

// TrackerConfig configures the device tracker
type TrackerConfig struct {
	CacheMaxAge   time.Duration // Maximum age of cached entries
	StaleDuration time.Duration // Device stale threshold
}

// DefaultTrackerConfig returns default tracker configuration
func DefaultTrackerConfig() *TrackerConfig {
	return &TrackerConfig{
		CacheMaxAge:   5 * time.Minute,
		StaleDuration: 24 * time.Hour,
	}
}

// NewTracker creates a new device tracker
func NewTracker(deviceRepo DeviceRepository, downloadRepo DownloadRepository, cfg *TrackerConfig) *Tracker {
	if cfg == nil {
		cfg = DefaultTrackerConfig()
	}

	return &Tracker{
		deviceRepo:    deviceRepo,
		downloadRepo:  downloadRepo,
		cache:         make(map[string]*types.DeviceStatus),
		cacheMaxAge:   cfg.CacheMaxAge,
		staleDuration: cfg.StaleDuration,
	}
}

// TrackDevice registers a device for CA installation tracking
func (t *Tracker) TrackDevice(ctx context.Context, info types.DeviceInfo) (*types.DeviceStatus, error) {
	deviceID := types.GenerateDeviceID(info.IPAddress, info.MACAddress)

	// Check cache first
	if cached := t.getCached(deviceID); cached != nil {
		cached.UpdateLastSeen()
		return cached, nil
	}

	// Check database
	existing, err := t.deviceRepo.GetDeviceByID(ctx, deviceID)
	if err == nil && existing != nil {
		existing.UpdateLastSeen()
		if err := t.deviceRepo.SaveDevice(ctx, existing); err != nil {
			return nil, err
		}
		t.updateCache(existing)
		return existing, nil
	}

	// Create new device status
	device := types.DeviceStatusFromInfo(info)
	if err := t.deviceRepo.SaveDevice(ctx, device); err != nil {
		return nil, err
	}

	t.updateCache(device)
	return device, nil
}

// GetDeviceStatus returns the current status of a device
func (t *Tracker) GetDeviceStatus(ctx context.Context, ip net.IP) (*types.DeviceStatus, error) {
	// Check cache by iterating (IP lookup)
	t.cacheMu.RLock()
	for _, device := range t.cache {
		if device.IPAddress.Equal(ip) {
			t.cacheMu.RUnlock()
			return device, nil
		}
	}
	t.cacheMu.RUnlock()

	// Check database
	device, err := t.deviceRepo.GetDevice(ctx, ip, "")
	if err != nil {
		return nil, err
	}

	if device != nil {
		t.updateCache(device)
	}

	return device, nil
}

// GetDeviceByMAC returns device status by MAC address
func (t *Tracker) GetDeviceByMAC(ctx context.Context, mac string) (*types.DeviceStatus, error) {
	normalizedMAC, err := types.NormalizeMACAddress(mac)
	if err != nil {
		return nil, err
	}

	// Check cache
	t.cacheMu.RLock()
	for _, device := range t.cache {
		if device.MACAddress == normalizedMAC {
			t.cacheMu.RUnlock()
			return device, nil
		}
	}
	t.cacheMu.RUnlock()

	// Check database
	device, err := t.deviceRepo.GetDevice(ctx, nil, normalizedMAC)
	if err != nil {
		return nil, err
	}

	if device != nil {
		t.updateCache(device)
	}

	return device, nil
}

// MarkCAInstalled marks a device as having the CA installed
func (t *Tracker) MarkCAInstalled(ctx context.Context, deviceID string, method types.DetectionMethod) error {
	device, err := t.deviceRepo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}

	if device == nil {
		return ErrDeviceNotFound
	}

	device.MarkAsTrusted(method)
	if err := t.deviceRepo.SaveDevice(ctx, device); err != nil {
		return err
	}

	t.updateCache(device)
	return nil
}

// MarkCANotInstalled marks a device as not having the CA installed
func (t *Tracker) MarkCANotInstalled(ctx context.Context, deviceID string, method types.DetectionMethod) error {
	device, err := t.deviceRepo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}

	if device == nil {
		return ErrDeviceNotFound
	}

	device.MarkAsUntrusted(method)
	if err := t.deviceRepo.SaveDevice(ctx, device); err != nil {
		return err
	}

	t.updateCache(device)
	return nil
}

// RecordDownload records a CA certificate download
func (t *Tracker) RecordDownload(ctx context.Context, record *types.DownloadRecord) error {
	// Ensure device exists - use IP only since DownloadRecord doesn't have MAC
	_, err := t.TrackDevice(ctx, types.DeviceInfo{
		IPAddress: record.IPAddress,
	})
	if err != nil {
		return err
	}

	// Set device ID using IP only
	record.DeviceID = types.GenerateDeviceID(record.IPAddress, "")

	return t.downloadRepo.RecordDownload(ctx, record)
}

// ListDevices returns devices matching the query
func (t *Tracker) ListDevices(ctx context.Context, query *types.DeviceQuery) (*types.DeviceListResult, error) {
	return t.deviceRepo.ListDevices(ctx, query)
}

// GetStatistics returns aggregate device tracking statistics
func (t *Tracker) GetStatistics(ctx context.Context) (*types.DeviceStatistics, error) {
	return t.deviceRepo.GetStatistics(ctx)
}

// IsCAInstalled checks if a device has the CA installed
func (t *Tracker) IsCAInstalled(ctx context.Context, ip net.IP) (bool, error) {
	device, err := t.GetDeviceStatus(ctx, ip)
	if err != nil {
		return false, err
	}

	if device == nil {
		return false, nil
	}

	return device.CAInstalled, nil
}

// GetStaleDevices returns devices that haven't been seen recently
func (t *Tracker) GetStaleDevices(ctx context.Context) ([]*types.DeviceStatus, error) {
	staleTime := time.Now().Add(-t.staleDuration)
	query := &types.DeviceQuery{
		LastSeenBefore: &staleTime,
		Limit:          1000,
	}

	result, err := t.deviceRepo.ListDevices(ctx, query)
	if err != nil {
		return nil, err
	}

	return result.Devices, nil
}

// PurgeStaleDevices removes devices that haven't been seen recently
func (t *Tracker) PurgeStaleDevices(ctx context.Context) (int, error) {
	staleDevices, err := t.GetStaleDevices(ctx)
	if err != nil {
		return 0, err
	}

	purged := 0
	for _, device := range staleDevices {
		if err := t.deviceRepo.DeleteDevice(ctx, device.DeviceID); err != nil {
			continue // Log error but continue purging
		}
		t.removeFromCache(device.DeviceID)
		purged++
	}

	return purged, nil
}

// Cache helpers
func (t *Tracker) getCached(deviceID string) *types.DeviceStatus {
	t.cacheMu.RLock()
	defer t.cacheMu.RUnlock()

	device, exists := t.cache[deviceID]
	if !exists {
		return nil
	}

	// Check if cache entry is stale
	if time.Since(device.LastSeen) > t.cacheMaxAge {
		return nil
	}

	return device
}

func (t *Tracker) updateCache(device *types.DeviceStatus) {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	t.cache[device.DeviceID] = device
}

func (t *Tracker) removeFromCache(deviceID string) {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	delete(t.cache, deviceID)
}

// ClearCache clears the in-memory cache
func (t *Tracker) ClearCache() {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	t.cache = make(map[string]*types.DeviceStatus)
}

// CacheSize returns the number of cached devices
func (t *Tracker) CacheSize() int {
	t.cacheMu.RLock()
	defer t.cacheMu.RUnlock()
	return len(t.cache)
}
