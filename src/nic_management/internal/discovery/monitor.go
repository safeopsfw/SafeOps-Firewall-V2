// Package discovery provides network interface enumeration and discovery capabilities.
// This file implements the continuous network interface monitoring system that detects
// real-time changes to network adapters including hotplug events, cable connection state
// changes, IP address changes, and interface state transitions.
package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Monitor Event Types
// =============================================================================

const (
	// MonitorEventNICAdded is published when a new interface is discovered.
	MonitorEventNICAdded = "NIC_ADDED"
	// MonitorEventNICRemoved is published when an interface is removed.
	MonitorEventNICRemoved = "NIC_REMOVED"
	// MonitorEventLinkStateChanged is published when link state changes (cable plug/unplug).
	MonitorEventLinkStateChanged = "NIC_LINK_STATE_CHANGED"
	// MonitorEventIPChanged is published when IP address changes.
	MonitorEventIPChanged = "NIC_IP_CHANGED"
	// MonitorEventSpeedChanged is published when link speed changes.
	MonitorEventSpeedChanged = "NIC_SPEED_CHANGED"
)

// =============================================================================
// Monitor Configuration
// =============================================================================

// MonitorConfig holds configuration settings for monitoring behavior.
type MonitorConfig struct {
	// PollInterval is how often to check for changes (default: 5s).
	PollInterval time.Duration `json:"poll_interval" yaml:"poll_interval"`
	// EnableHotplugDetection monitors for device additions/removals (default: true).
	EnableHotplugDetection bool `json:"enable_hotplug_detection" yaml:"enable_hotplug_detection"`
	// EnableLinkStateMonitoring monitors for cable up/down events (default: true).
	EnableLinkStateMonitoring bool `json:"enable_link_state_monitoring" yaml:"enable_link_state_monitoring"`
	// EnableIPChangeMonitoring monitors for IP address changes (default: true).
	EnableIPChangeMonitoring bool `json:"enable_ip_change_monitoring" yaml:"enable_ip_change_monitoring"`
	// EnableStateChangeMonitoring monitors for interface state changes (default: true).
	EnableStateChangeMonitoring bool `json:"enable_state_change_monitoring" yaml:"enable_state_change_monitoring"`
	// DebounceInterval is the delay before processing rapid changes (default: 2s).
	DebounceInterval time.Duration `json:"debounce_interval" yaml:"debounce_interval"`
}

// DefaultMonitorConfig returns a configuration with sensible defaults.
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		PollInterval:                5 * time.Second,
		EnableHotplugDetection:      true,
		EnableLinkStateMonitoring:   true,
		EnableIPChangeMonitoring:    true,
		EnableStateChangeMonitoring: true,
		DebounceInterval:            2 * time.Second,
	}
}

// Validate ensures the configuration is valid.
func (c *MonitorConfig) Validate() error {
	if c.PollInterval < time.Second {
		return fmt.Errorf("poll interval must be at least 1 second, got %v", c.PollInterval)
	}
	if c.PollInterval > 5*time.Minute {
		return fmt.Errorf("poll interval should not exceed 5 minutes, got %v", c.PollInterval)
	}
	if c.DebounceInterval < 0 {
		return fmt.Errorf("debounce interval cannot be negative")
	}
	return nil
}

// =============================================================================
// Interface State Snapshot
// =============================================================================

// InterfaceState captures a point-in-time interface state for change comparison.
type InterfaceState struct {
	InterfaceName string               `json:"interface_name"`
	MACAddress    string               `json:"mac_address"`
	IPAddresses   []string             `json:"ip_addresses"`
	State         types.InterfaceState `json:"state"`
	OperStatus    string               `json:"oper_status"`
	SpeedMbps     int                  `json:"speed_mbps"`
	IsEnabled     bool                 `json:"is_enabled"`
	LastSeen      time.Time            `json:"last_seen"`
}

// =============================================================================
// Change Structures
// =============================================================================

// InterfaceChange represents a single interface change.
type InterfaceChange struct {
	Interface  *types.NetworkInterface `json:"interface"`
	ChangeType string                  `json:"change_type"`
	OldValue   interface{}             `json:"old_value,omitempty"`
	NewValue   interface{}             `json:"new_value,omitempty"`
	Timestamp  time.Time               `json:"timestamp"`
}

// ChangeSet contains all detected changes from a scan.
type ChangeSet struct {
	Added            []*types.NetworkInterface `json:"added,omitempty"`
	Removed          []*types.NetworkInterface `json:"removed,omitempty"`
	LinkStateChanged []*InterfaceChange        `json:"link_state_changed,omitempty"`
	IPChanged        []*InterfaceChange        `json:"ip_changed,omitempty"`
	SpeedChanged     []*InterfaceChange        `json:"speed_changed,omitempty"`
	Timestamp        time.Time                 `json:"timestamp"`
}

// HasChanges returns true if the ChangeSet contains any changes.
func (cs *ChangeSet) HasChanges() bool {
	return len(cs.Added) > 0 || len(cs.Removed) > 0 ||
		len(cs.LinkStateChanged) > 0 || len(cs.IPChanged) > 0 ||
		len(cs.SpeedChanged) > 0
}

// TotalChanges returns the total number of changes.
func (cs *ChangeSet) TotalChanges() int {
	return len(cs.Added) + len(cs.Removed) +
		len(cs.LinkStateChanged) + len(cs.IPChanged) +
		len(cs.SpeedChanged)
}

// =============================================================================
// Monitor Event Handler
// =============================================================================

// MonitorEventHandler is a callback function for monitor events.
type MonitorEventHandler func(eventType string, change *InterfaceChange)

// =============================================================================
// Monitor Structure
// =============================================================================

// Monitor is the network interface monitoring engine.
type Monitor struct {
	// Dependencies
	enumerator *Enumerator
	classifier *Classifier

	// Configuration
	config *MonitorConfig

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// State tracking
	previousState   map[string]*InterfaceState
	previousMu      sync.RWMutex
	debounceTracker map[string]time.Time
	debounceMu      sync.Mutex

	// Event handlers
	eventHandlers []MonitorEventHandler
	handlersMu    sync.RWMutex

	// Status
	running   bool
	runningMu sync.RWMutex
	startTime time.Time
	scanCount uint64
	scanMu    sync.RWMutex
}

// =============================================================================
// Constructor
// =============================================================================

// NewMonitor creates a new monitor instance.
func NewMonitor(enumerator *Enumerator, classifier *Classifier, config *MonitorConfig) (*Monitor, error) {
	if enumerator == nil {
		return nil, fmt.Errorf("enumerator is required")
	}

	if config == nil {
		config = DefaultMonitorConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Monitor{
		enumerator:      enumerator,
		classifier:      classifier,
		config:          config,
		previousState:   make(map[string]*InterfaceState),
		debounceTracker: make(map[string]time.Time),
		eventHandlers:   make([]MonitorEventHandler, 0),
	}, nil
}

// =============================================================================
// Event Handler Registration
// =============================================================================

// RegisterEventHandler adds an event handler callback.
func (m *Monitor) RegisterEventHandler(handler MonitorEventHandler) {
	m.handlersMu.Lock()
	defer m.handlersMu.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// publishEvent sends an event to all registered handlers.
func (m *Monitor) publishEvent(eventType string, iface *types.NetworkInterface, oldValue, newValue interface{}) {
	change := &InterfaceChange{
		Interface:  iface,
		ChangeType: eventType,
		OldValue:   oldValue,
		NewValue:   newValue,
		Timestamp:  time.Now(),
	}

	m.handlersMu.RLock()
	handlers := make([]MonitorEventHandler, len(m.eventHandlers))
	copy(handlers, m.eventHandlers)
	m.handlersMu.RUnlock()

	for _, handler := range handlers {
		go handler(eventType, change)
	}

	// Also publish to the enumerator's event system for backward compatibility.
	if m.enumerator != nil {
		m.enumerator.publishEvent(eventType, iface)
	}
}

// =============================================================================
// Monitor Lifecycle - Start
// =============================================================================

// Start starts the background monitoring goroutine.
func (m *Monitor) Start(ctx context.Context) error {
	m.runningMu.Lock()
	if m.running {
		m.runningMu.Unlock()
		return fmt.Errorf("monitor is already running")
	}
	m.running = true
	m.startTime = time.Now()
	m.runningMu.Unlock()

	// Create monitoring context with cancellation.
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Perform initial scan to establish baseline state.
	if err := m.initializeBaseline(); err != nil {
		m.runningMu.Lock()
		m.running = false
		m.runningMu.Unlock()
		return fmt.Errorf("failed to initialize baseline: %w", err)
	}

	// Launch background monitoring goroutine.
	m.wg.Add(1)
	go m.monitorLoop()

	// Start platform-specific event listeners (if available).
	m.wg.Add(1)
	go m.platformEventListener()

	return nil
}

// initializeBaseline performs the initial scan and establishes baseline state.
func (m *Monitor) initializeBaseline() error {
	interfaces, err := m.enumerator.EnumerateInterfaces(m.ctx)
	if err != nil {
		return fmt.Errorf("initial enumeration failed: %w", err)
	}

	// Classify interfaces if classifier is available.
	if m.classifier != nil {
		_ = m.classifier.ClassifyInterfaces(m.ctx, interfaces)
	}

	// Create initial state snapshot.
	m.previousMu.Lock()
	m.previousState = m.createStateSnapshot(interfaces)
	m.previousMu.Unlock()

	return nil
}

// =============================================================================
// Monitor Lifecycle - Stop
// =============================================================================

// Stop gracefully stops monitoring.
func (m *Monitor) Stop() error {
	m.runningMu.Lock()
	if !m.running {
		m.runningMu.Unlock()
		return nil
	}
	m.running = false
	m.runningMu.Unlock()

	// Signal shutdown.
	if m.cancel != nil {
		m.cancel()
	}

	// Wait for goroutines to exit.
	m.wg.Wait()

	// Clean up state.
	m.previousMu.Lock()
	m.previousState = make(map[string]*InterfaceState)
	m.previousMu.Unlock()

	return nil
}

// IsRunning returns true if the monitor is currently running.
func (m *Monitor) IsRunning() bool {
	m.runningMu.RLock()
	defer m.runningMu.RUnlock()
	return m.running
}

// =============================================================================
// Main Monitoring Loop
// =============================================================================

// monitorLoop is the main monitoring goroutine.
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performScan()
		}
	}
}

// performScan executes a single monitoring scan cycle.
func (m *Monitor) performScan() {
	// Increment scan count.
	m.scanMu.Lock()
	m.scanCount++
	m.scanMu.Unlock()

	// Enumerate current interfaces.
	interfaces, err := m.enumerator.EnumerateInterfaces(m.ctx)
	if err != nil {
		// Log error but continue monitoring.
		return
	}

	// Create current state snapshot.
	currentState := m.createStateSnapshot(interfaces)

	// Detect changes.
	m.previousMu.RLock()
	changes := m.detectChanges(currentState, m.previousState, interfaces)
	m.previousMu.RUnlock()

	// Process changes if any detected.
	if changes.HasChanges() {
		m.handleChanges(m.ctx, changes, interfaces)
	}

	// Update previous state.
	m.previousMu.Lock()
	m.previousState = currentState
	m.previousMu.Unlock()
}

// =============================================================================
// Change Detection
// =============================================================================

// detectChanges compares current and previous state to identify changes.
func (m *Monitor) detectChanges(current, previous map[string]*InterfaceState, interfaces []*types.NetworkInterface) *ChangeSet {
	changes := &ChangeSet{
		Timestamp: time.Now(),
	}

	// Create interface map for easy lookup.
	ifaceMap := make(map[string]*types.NetworkInterface)
	for _, iface := range interfaces {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		ifaceMap[key] = iface
	}

	// Detect added interfaces (in current but not in previous).
	if m.config.EnableHotplugDetection {
		for mac, _ := range current {
			if _, exists := previous[mac]; !exists {
				if iface, ok := ifaceMap[mac]; ok {
					changes.Added = append(changes.Added, iface)
				}
			}
		}
	}

	// Detect removed interfaces (in previous but not in current).
	if m.config.EnableHotplugDetection {
		for mac, prevState := range previous {
			if _, exists := current[mac]; !exists {
				// Create a minimal interface object for the removed interface.
				removedIface := &types.NetworkInterface{
					Name:       prevState.InterfaceName,
					MACAddress: prevState.MACAddress,
					State:      prevState.State,
				}
				changes.Removed = append(changes.Removed, removedIface)
			}
		}
	}

	// Detect state changes for existing interfaces.
	for mac, currState := range current {
		prevState, exists := previous[mac]
		if !exists {
			continue // Already handled as "added"
		}

		iface, ok := ifaceMap[mac]
		if !ok {
			continue
		}

		// Check link state changes.
		if m.config.EnableLinkStateMonitoring || m.config.EnableStateChangeMonitoring {
			if currState.State != prevState.State {
				changes.LinkStateChanged = append(changes.LinkStateChanged, &InterfaceChange{
					Interface:  iface,
					ChangeType: MonitorEventLinkStateChanged,
					OldValue:   prevState.State,
					NewValue:   currState.State,
					Timestamp:  time.Now(),
				})
			}
		}

		// Check IP address changes.
		if m.config.EnableIPChangeMonitoring {
			if !stringSlicesEqual(currState.IPAddresses, prevState.IPAddresses) {
				changes.IPChanged = append(changes.IPChanged, &InterfaceChange{
					Interface:  iface,
					ChangeType: MonitorEventIPChanged,
					OldValue:   prevState.IPAddresses,
					NewValue:   currState.IPAddresses,
					Timestamp:  time.Now(),
				})
			}
		}

		// Check speed changes.
		if currState.SpeedMbps != prevState.SpeedMbps {
			changes.SpeedChanged = append(changes.SpeedChanged, &InterfaceChange{
				Interface:  iface,
				ChangeType: MonitorEventSpeedChanged,
				OldValue:   prevState.SpeedMbps,
				NewValue:   currState.SpeedMbps,
				Timestamp:  time.Now(),
			})
		}
	}

	return changes
}

// stringSlicesEqual compares two string slices for equality.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// Change Handling
// =============================================================================

// handleChanges processes detected changes and triggers actions.
func (m *Monitor) handleChanges(ctx context.Context, changes *ChangeSet, interfaces []*types.NetworkInterface) {
	// Handle added interfaces.
	for _, iface := range changes.Added {
		if !m.debounceChange(iface.MACAddress) {
			continue
		}

		// Re-classify if classifier is available.
		if m.classifier != nil {
			_, _ = m.classifier.ClassifyInterface(ctx, iface)
		}

		// Publish event.
		m.publishEvent(MonitorEventNICAdded, iface, nil, iface)
	}

	// Handle removed interfaces.
	for _, iface := range changes.Removed {
		if !m.debounceChange(iface.MACAddress) {
			continue
		}

		// Publish event.
		m.publishEvent(MonitorEventNICRemoved, iface, iface, nil)
	}

	// Handle link state changes.
	for _, change := range changes.LinkStateChanged {
		if !m.debounceChange(change.Interface.MACAddress) {
			continue
		}

		// Publish event.
		m.publishEvent(MonitorEventLinkStateChanged, change.Interface, change.OldValue, change.NewValue)
	}

	// Handle IP address changes.
	for _, change := range changes.IPChanged {
		if !m.debounceChange(change.Interface.MACAddress) {
			continue
		}

		// Publish event.
		m.publishEvent(MonitorEventIPChanged, change.Interface, change.OldValue, change.NewValue)
	}

	// Handle speed changes.
	for _, change := range changes.SpeedChanged {
		if !m.debounceChange(change.Interface.MACAddress) {
			continue
		}

		// Publish event.
		m.publishEvent(MonitorEventSpeedChanged, change.Interface, change.OldValue, change.NewValue)
	}
}

// =============================================================================
// Debouncing Logic
// =============================================================================

// debounceChange prevents processing of rapid repeated changes.
func (m *Monitor) debounceChange(identifier string) bool {
	if identifier == "" {
		return true // No identifier, can't debounce.
	}

	if m.config.DebounceInterval <= 0 {
		return true // Debouncing disabled.
	}

	m.debounceMu.Lock()
	defer m.debounceMu.Unlock()

	lastChange, exists := m.debounceTracker[identifier]
	now := time.Now()

	if exists && now.Sub(lastChange) < m.config.DebounceInterval {
		// Change is within debounce interval, skip it.
		return false
	}

	// Update tracker and process change.
	m.debounceTracker[identifier] = now
	return true
}

// cleanupDebounceTracker removes old entries from the debounce tracker.
func (m *Monitor) cleanupDebounceTracker() {
	m.debounceMu.Lock()
	defer m.debounceMu.Unlock()

	threshold := time.Now().Add(-10 * m.config.DebounceInterval)
	for id, lastChange := range m.debounceTracker {
		if lastChange.Before(threshold) {
			delete(m.debounceTracker, id)
		}
	}
}

// =============================================================================
// Platform-Specific Event Listeners
// =============================================================================

// platformEventListener handles platform-specific change notifications.
// This is a placeholder that can be enhanced with OS-specific implementations.
func (m *Monitor) platformEventListener() {
	defer m.wg.Done()

	// For now, this is a no-op placeholder.
	// Windows would use NotifyAddrChange/NotifyRouteChange.
	// Linux would use netlink with RTMGRP_LINK and RTMGRP_IPV4_IFADDR.

	// Wait for context cancellation.
	<-m.ctx.Done()
}

// =============================================================================
// State Snapshot Creation
// =============================================================================

// createStateSnapshot creates state snapshot from interface list.
func (m *Monitor) createStateSnapshot(interfaces []*types.NetworkInterface) map[string]*InterfaceState {
	snapshot := make(map[string]*InterfaceState, len(interfaces))
	now := time.Now()

	for _, iface := range interfaces {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}

		// Collect IP addresses.
		ips := make([]string, 0)
		if iface.IPAddress != "" {
			ips = append(ips, iface.IPAddress)
		}
		if iface.IPv6Address != "" {
			ips = append(ips, iface.IPv6Address)
		}

		snapshot[key] = &InterfaceState{
			InterfaceName: iface.Name,
			MACAddress:    iface.MACAddress,
			IPAddresses:   ips,
			State:         iface.State,
			OperStatus:    string(iface.State),
			SpeedMbps:     iface.SpeedMbps,
			IsEnabled:     iface.IsEnabled,
			LastSeen:      now,
		}
	}

	return snapshot
}

// =============================================================================
// Status and Statistics
// =============================================================================

// GetScanCount returns the number of scans performed.
func (m *Monitor) GetScanCount() uint64 {
	m.scanMu.RLock()
	defer m.scanMu.RUnlock()
	return m.scanCount
}

// GetStartTime returns when the monitor was started.
func (m *Monitor) GetStartTime() time.Time {
	m.runningMu.RLock()
	defer m.runningMu.RUnlock()
	return m.startTime
}

// GetUptime returns how long the monitor has been running.
func (m *Monitor) GetUptime() time.Duration {
	m.runningMu.RLock()
	defer m.runningMu.RUnlock()
	if !m.running || m.startTime.IsZero() {
		return 0
	}
	return time.Since(m.startTime)
}

// GetConfig returns the monitor configuration.
func (m *Monitor) GetConfig() *MonitorConfig {
	return m.config
}

// GetCurrentState returns the current state snapshot.
func (m *Monitor) GetCurrentState() map[string]*InterfaceState {
	m.previousMu.RLock()
	defer m.previousMu.RUnlock()

	// Return a copy to prevent external modification.
	result := make(map[string]*InterfaceState, len(m.previousState))
	for k, v := range m.previousState {
		stateCopy := *v
		result[k] = &stateCopy
	}
	return result
}

// GetTrackedInterfaceCount returns the number of tracked interfaces.
func (m *Monitor) GetTrackedInterfaceCount() int {
	m.previousMu.RLock()
	defer m.previousMu.RUnlock()
	return len(m.previousState)
}

// =============================================================================
// Manual Scan Trigger
// =============================================================================

// TriggerScan forces an immediate interface scan.
func (m *Monitor) TriggerScan() error {
	m.runningMu.RLock()
	running := m.running
	m.runningMu.RUnlock()

	if !running {
		return fmt.Errorf("monitor is not running")
	}

	m.performScan()
	return nil
}
