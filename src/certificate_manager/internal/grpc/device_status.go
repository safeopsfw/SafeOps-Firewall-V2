// Package grpc implements gRPC service handlers for the Certificate Manager.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Device Status Response Types (mirrors proto messages)
// ============================================================================

// DeviceStatusResponse contains CA installation status for a device.
type DeviceStatusResponse struct {
	DeviceIP           string    `json:"device_ip"`
	MACAddress         string    `json:"mac_address"`
	Hostname           string    `json:"hostname"`
	CAInstalled        bool      `json:"ca_installed"`
	TrustStatus        string    `json:"trust_status"`        // unknown, trusted, untrusted, pending
	Status             string    `json:"status"`              // installed, not_installed, unknown
	Message            string    `json:"message"`             // Human readable status message
	InstallationMethod string    `json:"installation_method"` // http_download, dhcp_push, manual
	DetectedAt         time.Time `json:"detected_at"`
	DetectedAtUnix     int64     `json:"detected_at_unix"`
	LastSeen           time.Time `json:"last_seen"`
	DownloadCount      int       `json:"download_count"`
	OSType             string    `json:"os_type"`
	Found              bool      `json:"found"`
}

// DeviceStatusRequest for querying device status.
type DeviceStatusRequest struct {
	DeviceIP   string `json:"device_ip"`
	MACAddress string `json:"mac_address"`
}

// UpdateDeviceStatusRequest for updating device CA status.
type UpdateDeviceStatusRequest struct {
	DeviceIP           string `json:"device_ip"`
	MACAddress         string `json:"mac_address"`
	Hostname           string `json:"hostname"`
	CAInstalled        bool   `json:"ca_installed"`
	InstallationMethod string `json:"installation_method"` // http_download, dhcp_push, manual, tls_detected
	OSType             string `json:"os_type"`
	UserAgent          string `json:"user_agent"`
}

// ============================================================================
// Device Status Store Interface
// ============================================================================

// DeviceStatusStore defines the interface for device status persistence.
type DeviceStatusStore interface {
	GetDevice(ctx context.Context, ip string, mac string) (*DeviceRecord, error)
	SaveDevice(ctx context.Context, record *DeviceRecord) error
	UpdateDevice(ctx context.Context, record *DeviceRecord) error
	ListDevices(ctx context.Context, filter DeviceFilter) ([]*DeviceRecord, error)
	IncrementDownloadCount(ctx context.Context, ip string) error
}

// DeviceRecord represents a device in the database.
type DeviceRecord struct {
	ID                 int64     `json:"id"`
	DeviceIP           string    `json:"device_ip"`
	MACAddress         string    `json:"mac_address"`
	Hostname           string    `json:"hostname"`
	CAInstalled        bool      `json:"ca_installed"`
	TrustStatus        string    `json:"trust_status"`
	InstallationMethod string    `json:"installation_method"`
	DetectedAt         time.Time `json:"detected_at"`
	LastSeen           time.Time `json:"last_seen"`
	DownloadCount      int       `json:"download_count"`
	OSType             string    `json:"os_type"`
	UserAgent          string    `json:"user_agent"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// DeviceFilter for listing devices.
type DeviceFilter struct {
	CAInstalled *bool
	TrustStatus string
	OSType      string
	Limit       int
	Offset      int
}

// ============================================================================
// In-Memory Device Store (for development/testing)
// ============================================================================

// InMemoryDeviceStore provides an in-memory implementation of DeviceStatusStore.
type InMemoryDeviceStore struct {
	devices map[string]*DeviceRecord // key: IP or MAC
	mu      sync.RWMutex
}

// NewInMemoryDeviceStore creates a new in-memory device store.
func NewInMemoryDeviceStore() *InMemoryDeviceStore {
	return &InMemoryDeviceStore{
		devices: make(map[string]*DeviceRecord),
	}
}

// GetDevice retrieves a device by IP or MAC.
func (s *InMemoryDeviceStore) GetDevice(ctx context.Context, ip string, mac string) (*DeviceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try IP first
	if ip != "" {
		if device, exists := s.devices[ip]; exists {
			return device, nil
		}
	}

	// Try MAC
	if mac != "" {
		for _, device := range s.devices {
			if device.MACAddress == mac {
				return device, nil
			}
		}
	}

	return nil, errors.New("device not found")
}

// SaveDevice stores a new device record.
func (s *InMemoryDeviceStore) SaveDevice(ctx context.Context, record *DeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record.CreatedAt = time.Now()
	record.UpdatedAt = time.Now()
	s.devices[record.DeviceIP] = record
	return nil
}

// UpdateDevice updates an existing device record.
func (s *InMemoryDeviceStore) UpdateDevice(ctx context.Context, record *DeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record.UpdatedAt = time.Now()
	s.devices[record.DeviceIP] = record
	return nil
}

// ListDevices returns devices matching the filter.
func (s *InMemoryDeviceStore) ListDevices(ctx context.Context, filter DeviceFilter) ([]*DeviceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*DeviceRecord
	for _, device := range s.devices {
		// Apply filters
		if filter.CAInstalled != nil && device.CAInstalled != *filter.CAInstalled {
			continue
		}
		if filter.TrustStatus != "" && device.TrustStatus != filter.TrustStatus {
			continue
		}
		if filter.OSType != "" && device.OSType != filter.OSType {
			continue
		}
		results = append(results, device)
	}

	// Apply limit/offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results, nil
}

// IncrementDownloadCount increases the download counter for a device.
func (s *InMemoryDeviceStore) IncrementDownloadCount(ctx context.Context, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if device, exists := s.devices[ip]; exists {
		device.DownloadCount++
		device.LastSeen = time.Now()
		device.UpdatedAt = time.Now()
	}
	return nil
}

// ============================================================================
// Device Status Handler
// ============================================================================

// DeviceStatusHandler handles device CA status RPC requests.
type DeviceStatusHandler struct {
	store  DeviceStatusStore
	config *types.Config
}

// NewDeviceStatusHandler creates a new device status handler.
func NewDeviceStatusHandler(store DeviceStatusStore, cfg *types.Config) *DeviceStatusHandler {
	if store == nil {
		store = NewInMemoryDeviceStore()
	}
	return &DeviceStatusHandler{
		store:  store,
		config: cfg,
	}
}

// GetDeviceStatus retrieves the CA installation status for a device.
// Called by TLS proxy or DHCP server to check if a device has the CA certificate installed.
// This is a read-only operation - it never modifies device records.
func (h *DeviceStatusHandler) GetDeviceStatus(ctx context.Context, req *DeviceStatusRequest) (*DeviceStatusResponse, error) {
	// Validate request - at least one identifier required
	if req.DeviceIP == "" && req.MACAddress == "" {
		return nil, errors.New("at least one identifier required (IP or MAC address)")
	}

	// Validate and normalize IP address
	normalizedIP := req.DeviceIP
	if req.DeviceIP != "" {
		parsed := net.ParseIP(req.DeviceIP)
		if parsed == nil {
			return nil, fmt.Errorf("invalid IP address format: %s", req.DeviceIP)
		}
		normalizedIP = parsed.String()
	}

	// Validate and normalize MAC address
	normalizedMAC := req.MACAddress
	if req.MACAddress != "" {
		// Normalize: uppercase, use colons
		normalizedMAC = strings.ToUpper(strings.ReplaceAll(req.MACAddress, "-", ":"))
		// Validate format (17 chars: AA:BB:CC:DD:EE:FF)
		if len(normalizedMAC) != 17 {
			return nil, fmt.Errorf("invalid MAC address format (expected AA:BB:CC:DD:EE:FF): %s", req.MACAddress)
		}
	}

	log.Printf("[DeviceStatus] Looking up device: ip=%s mac=%s", normalizedIP, normalizedMAC)

	// Query store
	record, err := h.store.GetDevice(ctx, normalizedIP, normalizedMAC)
	if err != nil {
		// Device not found - return as unknown (read-only, no DB write)
		log.Printf("[DeviceStatus] Device not found: ip=%s mac=%s", normalizedIP, normalizedMAC)
		return &DeviceStatusResponse{
			DeviceIP:       normalizedIP,
			MACAddress:     normalizedMAC,
			CAInstalled:    false,
			TrustStatus:    "unknown",
			Status:         "unknown",
			Message:        "Device has not been seen by Certificate Manager",
			DetectedAtUnix: 0,
			Found:          false,
		}, nil
	}

	// Update last seen (read-only for status tracking)
	record.LastSeen = time.Now()
	h.store.UpdateDevice(ctx, record)

	// Build response with status and message
	response := &DeviceStatusResponse{
		DeviceIP:           record.DeviceIP,
		MACAddress:         record.MACAddress,
		Hostname:           record.Hostname,
		CAInstalled:        record.CAInstalled,
		TrustStatus:        record.TrustStatus,
		InstallationMethod: record.InstallationMethod,
		DetectedAt:         record.DetectedAt,
		DetectedAtUnix:     record.DetectedAt.Unix(),
		LastSeen:           record.LastSeen,
		DownloadCount:      record.DownloadCount,
		OSType:             record.OSType,
		Found:              true,
	}

	// Set status and message based on CA installation state
	if record.CAInstalled {
		response.Status = "installed"
		response.Message = "CA certificate is trusted by this device"
	} else {
		response.Status = "not_installed"
		response.Message = "CA certificate not detected on this device"
	}

	return response, nil
}

// UpdateDeviceStatus updates the CA installation status for a device.
// Called after TLS handshake detection or when device downloads CA certificate.
func (h *DeviceStatusHandler) UpdateDeviceStatus(ctx context.Context, req *UpdateDeviceStatusRequest) (*DeviceStatusResponse, error) {
	if req.DeviceIP == "" {
		return nil, errors.New("device_ip required")
	}

	log.Printf("[DeviceStatus] Updating device: ip=%s mac=%s ca_installed=%v",
		req.DeviceIP, req.MACAddress, req.CAInstalled)

	// Try to get existing record
	record, err := h.store.GetDevice(ctx, req.DeviceIP, req.MACAddress)
	if err != nil {
		// Create new record
		record = &DeviceRecord{
			DeviceIP:    req.DeviceIP,
			MACAddress:  req.MACAddress,
			Hostname:    req.Hostname,
			CAInstalled: req.CAInstalled,
			TrustStatus: determineTrustStatus(req.CAInstalled),
			DetectedAt:  time.Now(),
			LastSeen:    time.Now(),
			OSType:      req.OSType,
			UserAgent:   req.UserAgent,
		}
		if err := h.store.SaveDevice(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to save device: %w", err)
		}
	} else {
		// Update existing record
		record.Hostname = req.Hostname
		record.CAInstalled = req.CAInstalled
		record.TrustStatus = determineTrustStatus(req.CAInstalled)
		record.LastSeen = time.Now()
		record.OSType = req.OSType
		record.UserAgent = req.UserAgent
		if req.CAInstalled && !record.CAInstalled {
			record.DetectedAt = time.Now() // Update detection time when CA is first installed
		}
		if err := h.store.UpdateDevice(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to update device: %w", err)
		}
	}

	log.Printf("[DeviceStatus] Device updated: ip=%s trust_status=%s",
		record.DeviceIP, record.TrustStatus)

	return &DeviceStatusResponse{
		DeviceIP:      record.DeviceIP,
		MACAddress:    record.MACAddress,
		Hostname:      record.Hostname,
		CAInstalled:   record.CAInstalled,
		TrustStatus:   record.TrustStatus,
		DetectedAt:    record.DetectedAt,
		LastSeen:      record.LastSeen,
		DownloadCount: record.DownloadCount,
		OSType:        record.OSType,
		Found:         true,
	}, nil
}

// RecordCADownload records that a device downloaded the CA certificate.
// Called by the HTTP distribution server when /ca.crt is accessed.
func (h *DeviceStatusHandler) RecordCADownload(ctx context.Context, deviceIP string) error {
	log.Printf("[DeviceStatus] Recording CA download from: %s", deviceIP)

	// Try to get existing record
	record, err := h.store.GetDevice(ctx, deviceIP, "")
	if err != nil {
		// Create new record for unknown device
		record = &DeviceRecord{
			DeviceIP:      deviceIP,
			CAInstalled:   false, // Downloaded but not yet verified
			TrustStatus:   "pending",
			DetectedAt:    time.Now(),
			LastSeen:      time.Now(),
			DownloadCount: 1,
		}
		return h.store.SaveDevice(ctx, record)
	}

	// Increment download count
	return h.store.IncrementDownloadCount(ctx, deviceIP)
}

// determineTrustStatus returns the trust status based on CA installation.
func determineTrustStatus(caInstalled bool) string {
	if caInstalled {
		return "trusted"
	}
	return "untrusted"
}

// ============================================================================
// Device Status Statistics
// ============================================================================

// DeviceStats contains aggregate device statistics.
type DeviceStats struct {
	TotalDevices       int `json:"total_devices"`
	TrustedDevices     int `json:"trusted_devices"`
	UntrustedDevices   int `json:"untrusted_devices"`
	PendingDevices     int `json:"pending_devices"`
	TotalDownloads     int `json:"total_downloads"`
	DevicesWithCAToday int `json:"devices_with_ca_today"`
}

// GetDeviceStats returns aggregate statistics about device CA status.
func (h *DeviceStatusHandler) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	store, ok := h.store.(*InMemoryDeviceStore)
	if !ok {
		// For other store implementations, would need different approach
		return &DeviceStats{}, nil
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	stats := &DeviceStats{}
	today := time.Now().Truncate(24 * time.Hour)

	for _, device := range store.devices {
		stats.TotalDevices++
		stats.TotalDownloads += device.DownloadCount

		switch device.TrustStatus {
		case "trusted":
			stats.TrustedDevices++
		case "untrusted":
			stats.UntrustedDevices++
		case "pending":
			stats.PendingDevices++
		}

		if device.CAInstalled && device.DetectedAt.After(today) {
			stats.DevicesWithCAToday++
		}
	}

	return stats, nil
}
