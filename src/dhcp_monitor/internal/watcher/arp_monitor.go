// Package watcher provides the primary device detection engine
package watcher

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// DETECTION METHOD CONSTANTS
// =============================================================================

const (
	DetectionMethodIPCallback = "IP_CALLBACK" // Primary: IP Helper API (15-35ms)
	DetectionMethodARPPoll    = "ARP_POLL"    // Fallback: Periodic ARP scan
	DetectionMethodManual     = "MANUAL"      // Admin-triggered discovery
)

// =============================================================================
// MONITOR STATISTICS
// =============================================================================

// MonitorStatistics contains runtime metrics
type MonitorStatistics struct {
	TotalDetections    int64     `json:"total_detections"`
	DuplicatesFiltered int64     `json:"duplicates_filtered"`
	CacheSize          int       `json:"cache_size"`
	IPCallbackCount    int64     `json:"ip_callback_count"`
	ARPPollCount       int64     `json:"arp_poll_count"`
	LastDetection      time.Time `json:"last_detection"`
}

// =============================================================================
// ARP MONITOR STRUCT
// =============================================================================

// ARPMonitor orchestrates primary device detection
type ARPMonitor struct {
	arpTable     *ARPTable
	ipNotifier   *IPChangeNotifier
	eventChannel EventChannel

	// Deduplication cache
	detectionCache map[string]time.Time
	cacheMutex     sync.RWMutex

	// Configuration
	pollInterval    time.Duration
	cacheExpiry     time.Duration
	interfaceFilter *regexp.Regexp

	// Lifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	isRunning  bool
	startMutex sync.Mutex

	// Statistics
	totalDetections    int64
	duplicatesFiltered int64
	ipCallbackCount    int64
	arpPollCount       int64
	lastDetection      time.Time
	statsMutex         sync.RWMutex

	// Previous ARP snapshot for diff detection
	prevSnapshot []ARPEntry
}

// NewARPMonitor creates a new detection coordinator
func NewARPMonitor(eventChan EventChannel, pollInterval, cacheExpiry time.Duration, interfaceFilter string) (*ARPMonitor, error) {
	// Validate configuration
	if pollInterval < 10*time.Second {
		pollInterval = 30 * time.Second
	}
	if cacheExpiry < pollInterval {
		cacheExpiry = 5 * time.Minute
	}

	// Create ARP table with 5-second refresh
	arpTable := NewARPTable(5 * time.Second)

	// Create IP change notifier
	ipNotifier := NewIPChangeNotifier(eventChan, arpTable)

	// Compile interface filter
	var filter *regexp.Regexp
	if interfaceFilter != "" && interfaceFilter != ".*" {
		var err error
		filter, err = regexp.Compile(interfaceFilter)
		if err != nil {
			return nil, fmt.Errorf("invalid interface filter: %w", err)
		}
	}

	return &ARPMonitor{
		arpTable:        arpTable,
		ipNotifier:      ipNotifier,
		eventChannel:    eventChan,
		detectionCache:  make(map[string]time.Time),
		pollInterval:    pollInterval,
		cacheExpiry:     cacheExpiry,
		interfaceFilter: filter,
		isRunning:       false,
	}, nil
}

// =============================================================================
// LIFECYCLE METHODS
// =============================================================================

// Start begins all detection mechanisms
func (m *ARPMonitor) Start(ctx context.Context) error {
	m.startMutex.Lock()
	defer m.startMutex.Unlock()

	if m.isRunning {
		return fmt.Errorf("ARP monitor already running")
	}

	// Store context for lifecycle
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Start IP change notifier (primary detection)
	if err := m.ipNotifier.Start(m.ctx); err != nil {
		log.Printf("[ARP_MONITOR] Warning: IP callback registration failed: %v", err)
		log.Println("[ARP_MONITOR] Falling back to ARP polling only")
	} else {
		log.Println("[ARP_MONITOR] IP change callback registered (primary detection)")
	}

	// Launch ARP polling goroutine (fallback detection)
	m.wg.Add(1)
	go m.runARPPolling()

	// Launch cache cleanup goroutine
	m.wg.Add(1)
	go m.runCacheCleanup()

	m.isRunning = true
	log.Printf("[ARP_MONITOR] Started with poll_interval=%v cache_expiry=%v",
		m.pollInterval, m.cacheExpiry)

	return nil
}

// Stop gracefully shuts down the monitor
func (m *ARPMonitor) Stop() error {
	m.startMutex.Lock()
	defer m.startMutex.Unlock()

	if !m.isRunning {
		return nil
	}

	// Cancel context to stop goroutines
	if m.cancel != nil {
		m.cancel()
	}

	// Stop IP notifier
	if err := m.ipNotifier.Stop(); err != nil {
		log.Printf("[ARP_MONITOR] Warning: IP notifier stop error: %v", err)
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[ARP_MONITOR] All goroutines stopped cleanly")
	case <-time.After(5 * time.Second):
		log.Println("[ARP_MONITOR] Warning: goroutine shutdown timeout")
	}

	// Clear cache
	m.cacheMutex.Lock()
	m.detectionCache = make(map[string]time.Time)
	m.cacheMutex.Unlock()

	m.isRunning = false
	log.Println("[ARP_MONITOR] Stopped")

	return nil
}

// IsRunning returns monitor status
func (m *ARPMonitor) IsRunning() bool {
	m.startMutex.Lock()
	defer m.startMutex.Unlock()
	return m.isRunning
}

// =============================================================================
// DETECTION GOROUTINES
// =============================================================================

// runARPPolling periodically scans ARP table for device changes
func (m *ARPMonitor) runARPPolling() {
	defer m.wg.Done()

	log.Printf("[ARP_MONITOR] ARP polling started (interval=%v)", m.pollInterval)

	// Get initial snapshot AND SEND EVENTS for existing devices
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	entries, err := m.arpTable.Query(ctx)
	cancel()
	if err == nil {
		m.prevSnapshot = entries

		// Send DEVICE_DETECTED events for all existing devices at startup!
		log.Printf("[ARP_MONITOR] Initial scan found %d ARP entries", len(entries))
		for _, entry := range entries {
			log.Printf("[ARP_MONITOR] Found: IP=%s MAC=%s State=%s Type=%s Interface=%s",
				entry.IPAddress, entry.MACAddress, entry.State, entry.Type, entry.InterfaceName)
			m.handleARPDetection(&entry, EventTypeDeviceDetected)
		}
	}

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			log.Println("[ARP_MONITOR] ARP polling stopped")
			return

		case <-ticker.C:
			m.pollARPTable()
		}
	}
}

// pollARPTable performs a single ARP table scan and diff
func (m *ARPMonitor) pollARPTable() {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	entries, err := m.arpTable.Query(ctx)
	if err != nil {
		log.Printf("[ARP_MONITOR] ARP query failed: %v", err)
		return
	}

	// Apply interface filter
	if m.interfaceFilter != nil {
		entries = m.arpTable.FilterByInterface(entries, m.interfaceFilter.String())
	}

	// Diff with previous snapshot
	added, changed, _ := m.arpTable.Diff(m.prevSnapshot, entries)

	// Process new devices
	for _, entry := range added {
		m.handleARPDetection(&entry, EventTypeDeviceDetected)
	}

	// Process IP changes
	for _, entry := range changed {
		m.handleARPDetection(&entry, EventTypeIPChanged)
	}

	// Update snapshot for next poll
	m.prevSnapshot = entries
}

// handleARPDetection processes a detection from ARP polling
func (m *ARPMonitor) handleARPDetection(entry *ARPEntry, eventType string) {
	// Check deduplication
	if m.isDuplicate(entry.MACAddress, entry.IPAddress) {
		atomic.AddInt64(&m.duplicatesFiltered, 1)
		return
	}

	// Create event
	event := &NetworkEvent{
		EventType:       eventType,
		Timestamp:       time.Now(),
		MACAddress:      entry.MACAddress,
		IPAddress:       entry.IPAddress,
		InterfaceName:   entry.InterfaceName,
		InterfaceIndex:  entry.InterfaceIndex,
		DetectionSource: DetectionSourceARPTable,
		Metadata:        make(map[string]string),
	}
	event.Metadata["detection_method"] = DetectionMethodARPPoll
	event.Metadata["arp_state"] = entry.State

	// Add to cache and send
	m.addToCache(entry.MACAddress, entry.IPAddress)

	if err := m.sendEvent(event); err != nil {
		log.Printf("[ARP_MONITOR] Failed to send event: %v", err)
		return
	}

	// Update statistics
	atomic.AddInt64(&m.totalDetections, 1)
	atomic.AddInt64(&m.arpPollCount, 1)
	m.statsMutex.Lock()
	m.lastDetection = time.Now()
	m.statsMutex.Unlock()

	log.Printf("[ARP_MONITOR] %s via ARP poll: MAC=%s IP=%s Interface=%s",
		eventType, entry.MACAddress, entry.IPAddress.String(), entry.InterfaceName)
}

// runCacheCleanup periodically removes expired cache entries
func (m *ARPMonitor) runCacheCleanup() {
	defer m.wg.Done()

	cleanupInterval := m.cacheExpiry / 2
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return

		case <-ticker.C:
			m.cleanupCache()
		}
	}
}

// cleanupCache removes expired entries
func (m *ARPMonitor) cleanupCache() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	now := time.Now()
	purged := 0

	for key, timestamp := range m.detectionCache {
		if now.Sub(timestamp) > m.cacheExpiry {
			delete(m.detectionCache, key)
			purged++
		}
	}

	if purged > 0 {
		log.Printf("[ARP_MONITOR] Cache cleanup: purged %d expired entries", purged)
	}
}

// =============================================================================
// DEDUPLICATION METHODS
// =============================================================================

// cacheKey generates a unique key for MAC:IP pair
func cacheKey(mac string, ip net.IP) string {
	return fmt.Sprintf("%s:%s", mac, ip.String())
}

// isDuplicate checks if this detection was recently seen
func (m *ARPMonitor) isDuplicate(mac string, ip net.IP) bool {
	key := cacheKey(mac, ip)

	m.cacheMutex.RLock()
	timestamp, exists := m.detectionCache[key]
	m.cacheMutex.RUnlock()

	if !exists {
		return false
	}

	// Check if entry is expired
	if time.Since(timestamp) > m.cacheExpiry {
		return false
	}

	return true
}

// addToCache records a detection
func (m *ARPMonitor) addToCache(mac string, ip net.IP) {
	key := cacheKey(mac, ip)

	m.cacheMutex.Lock()
	m.detectionCache[key] = time.Now()
	m.cacheMutex.Unlock()
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// sendEvent sends an event with timeout
func (m *ARPMonitor) sendEvent(event *NetworkEvent) error {
	select {
	case m.eventChannel <- event:
		return nil
	case <-time.After(100 * time.Millisecond):
		return fmt.Errorf("event channel send timeout")
	case <-m.ctx.Done():
		return fmt.Errorf("monitor shutting down")
	}
}

// TriggerDiscovery forces an immediate ARP scan
func (m *ARPMonitor) TriggerDiscovery(ctx context.Context) (int, error) {
	m.arpTable.InvalidateCache()

	entries, err := m.arpTable.Query(ctx)
	if err != nil {
		return 0, fmt.Errorf("ARP query failed: %w", err)
	}

	discovered := 0
	for _, entry := range entries {
		if m.isDuplicate(entry.MACAddress, entry.IPAddress) {
			continue
		}

		event := ARPEntryToNetworkEvent(&entry, EventTypeDeviceDetected)
		event.Metadata["detection_method"] = DetectionMethodManual

		m.addToCache(entry.MACAddress, entry.IPAddress)

		if err := m.sendEvent(event); err == nil {
			discovered++
			atomic.AddInt64(&m.totalDetections, 1)
		}
	}

	log.Printf("[ARP_MONITOR] Manual discovery: found %d new devices", discovered)
	return discovered, nil
}

// GetStatistics returns runtime metrics
func (m *ARPMonitor) GetStatistics() *MonitorStatistics {
	m.cacheMutex.RLock()
	cacheSize := len(m.detectionCache)
	m.cacheMutex.RUnlock()

	m.statsMutex.RLock()
	lastDetection := m.lastDetection
	m.statsMutex.RUnlock()

	return &MonitorStatistics{
		TotalDetections:    atomic.LoadInt64(&m.totalDetections),
		DuplicatesFiltered: atomic.LoadInt64(&m.duplicatesFiltered),
		CacheSize:          cacheSize,
		IPCallbackCount:    atomic.LoadInt64(&m.ipCallbackCount),
		ARPPollCount:       atomic.LoadInt64(&m.arpPollCount),
		LastDetection:      lastDetection,
	}
}

// shouldMonitorInterface checks if interface matches filter
func (m *ARPMonitor) shouldMonitorInterface(interfaceName string) bool {
	if m.interfaceFilter == nil {
		return true
	}
	return m.interfaceFilter.MatchString(interfaceName)
}

// SetInterfaceFilter updates the interface filter pattern
func (m *ARPMonitor) SetInterfaceFilter(pattern string) error {
	if pattern == "" || pattern == ".*" {
		m.interfaceFilter = nil
		return nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid interface filter: %w", err)
	}

	m.interfaceFilter = re
	return nil
}
