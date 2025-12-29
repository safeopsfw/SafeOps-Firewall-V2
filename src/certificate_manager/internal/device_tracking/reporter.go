// Package device_tracking provides device CA installation tracking for the Certificate Manager.
package device_tracking

import (
	"context"
	"time"

	"certificate_manager/pkg/types"
)

// Reporter generates device tracking reports and statistics
type Reporter struct {
	tracker *Tracker
}

// NewReporter creates a new device tracking reporter
func NewReporter(tracker *Tracker) *Reporter {
	return &Reporter{
		tracker: tracker,
	}
}

// GetInstallationCoverage returns the CA installation coverage percentage
func (r *Reporter) GetInstallationCoverage(ctx context.Context) (float64, error) {
	stats, err := r.tracker.GetStatistics(ctx)
	if err != nil {
		return 0, err
	}

	return stats.InstallationRate, nil
}

// GetDevicesByStatus returns devices grouped by trust status
func (r *Reporter) GetDevicesByStatus(ctx context.Context) (map[types.TrustStatus][]*types.DeviceStatus, error) {
	result := make(map[types.TrustStatus][]*types.DeviceStatus)

	statuses := []types.TrustStatus{
		types.TrustStatusTrusted,
		types.TrustStatusUntrusted,
		types.TrustStatusPending,
		types.TrustStatusUnknown,
		types.TrustStatusError,
	}

	for _, status := range statuses {
		statusCopy := status
		query := &types.DeviceQuery{
			TrustStatus: &statusCopy,
			Limit:       1000,
		}

		devices, err := r.tracker.ListDevices(ctx, query)
		if err != nil {
			return nil, err
		}

		result[status] = devices.Devices
	}

	return result, nil
}

// GetRecentInstallations returns devices that recently installed the CA
func (r *Reporter) GetRecentInstallations(ctx context.Context, since time.Duration) ([]*types.DeviceStatus, error) {
	cutoff := time.Now().Add(-since)
	installed := true

	query := &types.DeviceQuery{
		CAInstalled:   &installed,
		LastSeenAfter: &cutoff,
		Limit:         1000,
	}

	result, err := r.tracker.ListDevices(ctx, query)
	if err != nil {
		return nil, err
	}

	return result.Devices, nil
}

// GetPendingDevices returns devices that haven't installed the CA
func (r *Reporter) GetPendingDevices(ctx context.Context) ([]*types.DeviceStatus, error) {
	notInstalled := false

	query := &types.DeviceQuery{
		CAInstalled: &notInstalled,
		Limit:       1000,
	}

	result, err := r.tracker.ListDevices(ctx, query)
	if err != nil {
		return nil, err
	}

	return result.Devices, nil
}

// GetDevicesByOS returns devices grouped by operating system
func (r *Reporter) GetDevicesByOS(ctx context.Context) (map[string][]*types.DeviceStatus, error) {
	result := make(map[string][]*types.DeviceStatus)

	osTypes := []string{"windows", "macos", "linux", "ios", "android", "chromeos", "other", ""}

	for _, osType := range osTypes {
		query := &types.DeviceQuery{
			OSType: osType,
			Limit:  500,
		}

		devices, err := r.tracker.ListDevices(ctx, query)
		if err != nil {
			return nil, err
		}

		if len(devices.Devices) > 0 {
			key := osType
			if key == "" {
				key = "unknown"
			}
			result[key] = devices.Devices
		}
	}

	return result, nil
}

// GenerateReport generates a comprehensive device tracking report
func (r *Reporter) GenerateReport(ctx context.Context) (*DeviceReport, error) {
	stats, err := r.tracker.GetStatistics(ctx)
	if err != nil {
		return nil, err
	}

	report := &DeviceReport{
		GeneratedAt:      time.Now(),
		Statistics:       stats,
		InstallationRate: stats.InstallationRate,
	}

	// Get recent installations (last 24 hours)
	recent, err := r.GetRecentInstallations(ctx, 24*time.Hour)
	if err == nil {
		report.RecentInstallations = len(recent)
	}

	// Get pending devices
	pending, err := r.GetPendingDevices(ctx)
	if err == nil {
		report.PendingDevices = len(pending)
	}

	// Get stale devices
	stale, err := r.tracker.GetStaleDevices(ctx)
	if err == nil {
		report.StaleDevices = len(stale)
	}

	return report, nil
}

// DeviceReport contains a comprehensive device tracking report
type DeviceReport struct {
	GeneratedAt         time.Time               `json:"generated_at"`
	Statistics          *types.DeviceStatistics `json:"statistics"`
	InstallationRate    float64                 `json:"installation_rate"`
	RecentInstallations int                     `json:"recent_installations"` // Last 24 hours
	PendingDevices      int                     `json:"pending_devices"`
	StaleDevices        int                     `json:"stale_devices"`
}

// GetActiveDeviceCount returns count of devices seen within duration
func (r *Reporter) GetActiveDeviceCount(ctx context.Context, within time.Duration) (int64, error) {
	cutoff := time.Now().Add(-within)

	query := &types.DeviceQuery{
		LastSeenAfter: &cutoff,
		Limit:         1, // We just need the count
	}

	result, err := r.tracker.ListDevices(ctx, query)
	if err != nil {
		return 0, err
	}

	return result.TotalCount, nil
}

// GetHostnameStats returns devices with/without hostnames
func (r *Reporter) GetHostnameStats(ctx context.Context) (withHostname, withoutHostname int64, err error) {
	// Get all devices (limited)
	query := &types.DeviceQuery{
		Limit: 10000,
	}

	result, err := r.tracker.ListDevices(ctx, query)
	if err != nil {
		return 0, 0, err
	}

	for _, device := range result.Devices {
		if device.Hostname != "" {
			withHostname++
		} else {
			withoutHostname++
		}
	}

	return withHostname, withoutHostname, nil
}
