// Package manager provides the core device management business logic
package manager

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"dhcp_monitor/internal/database"
	"dhcp_monitor/internal/watcher"
)

// =============================================================================
// MANAGER STATISTICS
// =============================================================================

// ManagerStatistics contains runtime metrics
type ManagerStatistics struct {
	EventsProcessed      int64     `json:"events_processed"`
	DevicesCreated       int64     `json:"devices_created"`
	IPChanges            int64     `json:"ip_changes"`
	HostnamesEnriched    int64     `json:"hostnames_enriched"`
	DevicesMarkedOffline int64     `json:"devices_marked_offline"`
	LastEventProcessed   time.Time `json:"last_event_processed"`
	ErrorCount           int64     `json:"error_count"`
}

// =============================================================================
// DEVICE MANAGER STRUCT
// =============================================================================

// DeviceManager coordinates all device management operations
type DeviceManager struct {
	db                  *database.DatabaseClient
	eventChannel        watcher.EventChannel
	unknownHandler      *UnknownDeviceHandler
	fingerprintEnricher *FingerprintEnricher // Background fingerprint collection

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	isRunning bool
	mutex     sync.Mutex

	// Configuration
	cleanupInterval time.Duration
	inactiveTimeout time.Duration

	// Statistics
	stats      ManagerStatistics
	statsMutex sync.RWMutex
}

// NewDeviceManager creates a new device manager
func NewDeviceManager(db *database.DatabaseClient, eventChan watcher.EventChannel, cleanupInterval, inactiveTimeout time.Duration) (*DeviceManager, error) {
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}
	if inactiveTimeout <= 0 {
		inactiveTimeout = 10 * time.Minute
	}
	if inactiveTimeout < cleanupInterval {
		inactiveTimeout = cleanupInterval * 2
	}

	// Create unknown device handler
	unknownHandler := NewUnknownDeviceHandler(db, PolicyAutoCreate)

	// Create fingerprint enricher for background device info collection
	fingerprintEnricher := NewFingerprintEnricher(db)

	return &DeviceManager{
		db:                  db,
		eventChannel:        eventChan,
		unknownHandler:      unknownHandler,
		fingerprintEnricher: fingerprintEnricher,
		cleanupInterval:     cleanupInterval,
		inactiveTimeout:     inactiveTimeout,
		isRunning:           false,
	}, nil
}

// =============================================================================
// LIFECYCLE METHODS
// =============================================================================

// Start begins event processing and cleanup jobs
func (m *DeviceManager) Start(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.isRunning {
		return fmt.Errorf("device manager already running")
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Launch event processing goroutine
	m.wg.Add(1)
	go m.processEvents()

	// Launch cleanup job goroutine
	m.wg.Add(1)
	go m.runCleanupJob()

	// Start fingerprint enricher (background device info collection)
	if err := m.fingerprintEnricher.Start(m.ctx); err != nil {
		log.Printf("[DEVICE_MANAGER] Warning: fingerprint enricher failed to start: %v", err)
	}

	m.isRunning = true
	log.Printf("[DEVICE_MANAGER] Started with cleanup_interval=%v inactive_timeout=%v",
		m.cleanupInterval, m.inactiveTimeout)

	return nil
}

// Stop gracefully shuts down the manager
func (m *DeviceManager) Stop() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isRunning {
		return nil
	}

	// Stop fingerprint enricher
	if m.fingerprintEnricher != nil {
		m.fingerprintEnricher.Stop()
	}

	if m.cancel != nil {
		m.cancel()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[DEVICE_MANAGER] Stopped cleanly")
	case <-time.After(10 * time.Second):
		log.Println("[DEVICE_MANAGER] Warning: shutdown timeout")
	}

	m.statsMutex.RLock()
	log.Printf("[DEVICE_MANAGER] Final stats: events=%d devices=%d errors=%d",
		m.stats.EventsProcessed, m.stats.DevicesCreated, m.stats.ErrorCount)
	m.statsMutex.RUnlock()

	m.isRunning = false
	return nil
}

// IsRunning returns manager status
func (m *DeviceManager) IsRunning() bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.isRunning
}

// =============================================================================
// EVENT PROCESSING
// =============================================================================

// processEvents is the main event loop
func (m *DeviceManager) processEvents() {
	defer m.wg.Done()

	log.Println("[DEVICE_MANAGER] Event processing started")

	for {
		select {
		case <-m.ctx.Done():
			log.Println("[DEVICE_MANAGER] Event processing stopped")
			return

		case event, ok := <-m.eventChannel:
			if !ok {
				log.Println("[DEVICE_MANAGER] Event channel closed")
				return
			}

			m.handleEvent(event)
		}
	}
}

// handleEvent routes and processes a single event
func (m *DeviceManager) handleEvent(event *watcher.NetworkEvent) {
	// Validate event
	if err := m.validateEvent(event); err != nil {
		log.Printf("[DEVICE_MANAGER] Invalid event: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	var err error

	// Route by event type
	switch event.EventType {
	case watcher.EventTypeDeviceDetected:
		err = m.handleDeviceDetected(ctx, event)
	case watcher.EventTypeIPChanged:
		err = m.handleIPChanged(ctx, event)
	case watcher.EventTypeHostnameUpdated:
		err = m.handleHostnameUpdated(ctx, event)
	case watcher.EventTypeLeaseRenewed:
		err = m.handleLeaseRenewed(ctx, event)
	case watcher.EventTypeDeviceOffline:
		err = m.handleDeviceOffline(ctx, event)
	case watcher.EventTypeInterfaceChanged:
		err = m.handleInterfaceChanged(ctx, event)
	case watcher.EventTypeDeviceOnline:
		err = m.handleDeviceOnline(ctx, event)
	case watcher.EventTypeDeviceHeartbeat:
		err = m.handleDeviceHeartbeat(ctx, event)
	default:
		log.Printf("[DEVICE_MANAGER] Unknown event type: %s", event.EventType)
		return
	}

	// Handle errors gracefully
	if err != nil {
		m.handleEventError(event, err)
	}

	// Update statistics
	atomic.AddInt64(&m.stats.EventsProcessed, 1)
	m.statsMutex.Lock()
	m.stats.LastEventProcessed = time.Now()
	m.statsMutex.Unlock()
}

// =============================================================================
// EVENT HANDLERS
// =============================================================================

// handleDeviceDetected processes new device detection
func (m *DeviceManager) handleDeviceDetected(ctx context.Context, event *watcher.NetworkEvent) error {
	// Try to find existing device
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		// New device - create via unknown handler
		newDevice, createErr := m.unknownHandler.HandleUnknownDevice(ctx, event)
		if createErr != nil {
			return fmt.Errorf("failed to create device: %w", createErr)
		}

		atomic.AddInt64(&m.stats.DevicesCreated, 1)
		log.Printf("[DEVICE_MANAGER] New device: MAC=%s IP=%s Trust=%s",
			newDevice.MACAddress, newDevice.CurrentIP.String(), newDevice.TrustStatus)

		// Queue device for fingerprinting
		m.fingerprintEnricher.EnrichDevice(newDevice)

		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	// Existing device - update if needed
	needsUpdate := false

	// Check if IP changed
	if !device.CurrentIP.Equal(event.IPAddress) {
		// Create IP history record
		m.createIPHistory(ctx, device, event.IPAddress, "IP_CHANGE_CALLBACK")
		device.CurrentIP = event.IPAddress
		atomic.AddInt64(&m.stats.IPChanges, 1)
		needsUpdate = true
	}

	// Update online status and last seen
	if !device.IsOnline {
		device.IsOnline = true
		needsUpdate = true
	}
	device.LastSeen = time.Now()
	needsUpdate = true

	if needsUpdate {
		if err := m.db.UpdateDevice(ctx, device); err != nil {
			return fmt.Errorf("failed to update device: %w", err)
		}
	}

	return nil
}

// handleIPChanged processes IP address change events
func (m *DeviceManager) handleIPChanged(ctx context.Context, event *watcher.NetworkEvent) error {
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		// Treat as new device
		return m.handleDeviceDetected(ctx, event)
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	// Record IP change
	oldIP := device.CurrentIP
	device.CurrentIP = event.IPAddress
	device.LastSeen = time.Now()
	device.IsOnline = true

	// Create IP history
	m.createIPHistory(ctx, device, event.IPAddress, "IP_CHANGE_CALLBACK")

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	atomic.AddInt64(&m.stats.IPChanges, 1)
	log.Printf("[DEVICE_MANAGER] IP changed: MAC=%s %s → %s",
		device.MACAddress, oldIP.String(), event.IPAddress.String())

	return nil
}

// handleHostnameUpdated processes hostname enrichment events
func (m *DeviceManager) handleHostnameUpdated(ctx context.Context, event *watcher.NetworkEvent) error {
	if event.Hostname == "" {
		return nil // No hostname to update
	}

	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		log.Printf("[DEVICE_MANAGER] Warning: hostname for unknown device: %s", event.MACAddress)
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	// Update hostname
	device.Hostname = sql.NullString{String: event.Hostname, Valid: true}
	device.LastSeen = time.Now()

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	atomic.AddInt64(&m.stats.HostnamesEnriched, 1)
	log.Printf("[DEVICE_MANAGER] Hostname enriched: MAC=%s Hostname=%s",
		device.MACAddress, event.Hostname)

	return nil
}

// handleLeaseRenewed processes DHCP lease renewal events
func (m *DeviceManager) handleLeaseRenewed(ctx context.Context, event *watcher.NetworkEvent) error {
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		return nil // Skip orphaned lease events
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	// Update device last seen
	device.LastSeen = time.Now()
	device.IsOnline = true

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	log.Printf("[DEVICE_MANAGER] Lease renewed: MAC=%s", device.MACAddress)
	return nil
}

// handleDeviceOffline processes device offline events
func (m *DeviceManager) handleDeviceOffline(ctx context.Context, event *watcher.NetworkEvent) error {
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		return nil // Already removed or never existed
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	if device.IsOnline {
		device.IsOnline = false

		if err := m.db.UpdateDevice(ctx, device); err != nil {
			return fmt.Errorf("failed to update device: %w", err)
		}

		atomic.AddInt64(&m.stats.DevicesMarkedOffline, 1)
		log.Printf("[DEVICE_MANAGER] Device offline: MAC=%s", device.MACAddress)
	}

	return nil
}

// handleDeviceOnline processes device coming online events
func (m *DeviceManager) handleDeviceOnline(ctx context.Context, event *watcher.NetworkEvent) error {
	return m.handleDeviceDetected(ctx, event)
}

// handleDeviceHeartbeat updates last_seen for devices still present in ARP table
func (m *DeviceManager) handleDeviceHeartbeat(ctx context.Context, event *watcher.NetworkEvent) error {
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)
	if err != nil {
		// Device doesn't exist, ignore heartbeat (will be created on next detection)
		return nil
	}

	// Update last_seen timestamp
	device.LastSeen = time.Now()
	device.IsOnline = true

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to update device heartbeat: %w", err)
	}

	return nil
}

// handleInterfaceChanged processes interface switch events
func (m *DeviceManager) handleInterfaceChanged(ctx context.Context, event *watcher.NetworkEvent) error {
	device, err := m.db.GetDeviceByMAC(ctx, event.MACAddress)

	if err == sql.ErrNoRows {
		return m.handleDeviceDetected(ctx, event)
	}

	if err != nil {
		return fmt.Errorf("failed to query device: %w", err)
	}

	oldInterface := device.InterfaceName
	device.InterfaceName = event.InterfaceName
	device.InterfaceIndex = int32(event.InterfaceIndex)
	device.LastSeen = time.Now()
	device.IsOnline = true

	// Create IP history for interface change
	m.createIPHistory(ctx, device, event.IPAddress, "NIC_SWITCH")

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	log.Printf("[DEVICE_MANAGER] Interface changed: MAC=%s %s → %s",
		device.MACAddress, oldInterface, event.InterfaceName)

	return nil
}

// =============================================================================
// CLEANUP JOB
// =============================================================================

// runCleanupJob runs periodic maintenance
func (m *DeviceManager) runCleanupJob() {
	defer m.wg.Done()

	log.Printf("[DEVICE_MANAGER] Cleanup job started (interval=%v)", m.cleanupInterval)

	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			log.Println("[DEVICE_MANAGER] Cleanup job stopped")
			return

		case <-ticker.C:
			m.runCleanup()
		}
	}
}

// runCleanup performs a single cleanup cycle
func (m *DeviceManager) runCleanup() {
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	// Mark inactive devices as offline
	offlineCount := m.markInactiveDevicesOffline(ctx)

	if offlineCount > 0 {
		log.Printf("[DEVICE_MANAGER] Cleanup: marked %d devices offline", offlineCount)
	}
}

// markInactiveDevicesOffline marks devices as offline if LastSeen > inactiveTimeout
func (m *DeviceManager) markInactiveDevicesOffline(ctx context.Context) int {
	cutoff := time.Now().Add(-m.inactiveTimeout)

	// Get all online devices
	filter := &database.DeviceFilter{OnlineOnly: true}
	devices, _, err := m.db.ListDevices(ctx, filter)
	if err != nil {
		log.Printf("[DEVICE_MANAGER] Cleanup error: %v", err)
		return 0
	}

	count := 0
	for _, device := range devices {
		if device.LastSeen.Before(cutoff) {
			device.IsOnline = false
			if err := m.db.UpdateDevice(ctx, device); err != nil {
				log.Printf("[DEVICE_MANAGER] Failed to mark device offline: %v", err)
				continue
			}
			count++
			atomic.AddInt64(&m.stats.DevicesMarkedOffline, 1)
		}
	}

	return count
}

// =============================================================================
// PUBLIC API METHODS
// =============================================================================

// GetDeviceByIP returns device by IP address (critical path for Packet Engine)
func (m *DeviceManager) GetDeviceByIP(ctx context.Context, ip string) (*database.Device, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	return m.db.GetDeviceByIP(ctx, ip)
}

// GetDeviceByMAC returns device by MAC address
func (m *DeviceManager) GetDeviceByMAC(ctx context.Context, mac string) (*database.Device, error) {
	if mac == "" {
		return nil, fmt.Errorf("MAC address is empty")
	}

	return m.db.GetDeviceByMAC(ctx, mac)
}

// GetDeviceByID returns device by UUID
func (m *DeviceManager) GetDeviceByID(ctx context.Context, deviceID uuid.UUID) (*database.Device, error) {
	return m.db.GetDeviceByID(ctx, deviceID)
}

// UpdateTrustStatus updates device trust status (called by Captive Portal)
func (m *DeviceManager) UpdateTrustStatus(ctx context.Context, deviceID uuid.UUID, status string) (*database.Device, error) {
	// Validate status enum
	switch status {
	case "UNTRUSTED", "TRUSTED", "BLOCKED":
		// Valid
	default:
		return nil, fmt.Errorf("invalid trust status: %s", status)
	}

	// Get current device
	device, err := m.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device not found: %w", err)
	}

	oldStatus := device.TrustStatus
	device.TrustStatus = database.TrustStatus(status)

	if err := m.db.UpdateDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("failed to update trust status: %w", err)
	}

	log.Printf("[DEVICE_MANAGER] Trust status updated: MAC=%s %s → %s",
		device.MACAddress, oldStatus, status)

	return device, nil
}

// ListDevices returns devices matching filter
func (m *DeviceManager) ListDevices(ctx context.Context, filter *database.DeviceFilter) ([]*database.Device, int32, error) {
	return m.db.ListDevices(ctx, filter)
}

// GetDeviceStats returns aggregate device statistics
func (m *DeviceManager) GetDeviceStats(ctx context.Context) (*database.DeviceStats, error) {
	return m.db.GetDeviceStats(ctx)
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// createIPHistory creates an IP history record
func (m *DeviceManager) createIPHistory(ctx context.Context, device *database.Device, newIP net.IP, reason string) {
	history := &database.IPHistory{
		HistoryID:      uuid.New(),
		DeviceID:       device.DeviceID,
		IPAddress:      newIP,
		InterfaceName:  device.InterfaceName,
		InterfaceIndex: device.InterfaceIndex,
		ChangeReason:   database.ChangeReason(reason),
		AssignedAt:     time.Now(),
	}

	if err := m.db.CreateIPHistory(ctx, history); err != nil {
		log.Printf("[DEVICE_MANAGER] Warning: failed to create IP history: %v", err)
	}
}

// validateEvent validates a network event before processing
func (m *DeviceManager) validateEvent(event *watcher.NetworkEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	if err := event.Validate(); err != nil {
		return err
	}

	// Check for future timestamp (clock skew)
	if event.Timestamp.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("event timestamp is in future")
	}

	return nil
}

// handleEventError handles errors from event processing
func (m *DeviceManager) handleEventError(event *watcher.NetworkEvent, err error) {
	atomic.AddInt64(&m.stats.ErrorCount, 1)

	log.Printf("[DEVICE_MANAGER] Event error: type=%s mac=%s error=%v",
		event.EventType, event.MACAddress, err)

	// Continue processing - don't crash on individual event errors
}

// GetStatistics returns manager runtime metrics
func (m *DeviceManager) GetStatistics() *ManagerStatistics {
	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	return &ManagerStatistics{
		EventsProcessed:      atomic.LoadInt64(&m.stats.EventsProcessed),
		DevicesCreated:       atomic.LoadInt64(&m.stats.DevicesCreated),
		IPChanges:            atomic.LoadInt64(&m.stats.IPChanges),
		HostnamesEnriched:    atomic.LoadInt64(&m.stats.HostnamesEnriched),
		DevicesMarkedOffline: atomic.LoadInt64(&m.stats.DevicesMarkedOffline),
		LastEventProcessed:   m.stats.LastEventProcessed,
		ErrorCount:           atomic.LoadInt64(&m.stats.ErrorCount),
	}
}

// GetUnknownDeviceHandler returns the unknown device handler
func (m *DeviceManager) GetUnknownDeviceHandler() *UnknownDeviceHandler {
	return m.unknownHandler
}
