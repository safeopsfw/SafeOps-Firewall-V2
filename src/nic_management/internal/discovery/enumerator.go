// Package discovery provides network interface enumeration and discovery capabilities.
// This file implements the core network interface enumeration engine that discovers
// all network adapters on the system regardless of platform (Windows or Linux).
package discovery

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Event Types
// =============================================================================

const (
	// EventNICAdded is published when a new network interface is detected.
	EventNICAdded = "NIC_ADDED"
	// EventNICRemoved is published when a network interface is removed.
	EventNICRemoved = "NIC_REMOVED"
	// EventNICStateChanged is published when an interface's operational state changes.
	EventNICStateChanged = "NIC_STATE_CHANGED"
	// EventNICIPChanged is published when an interface's IP address changes.
	EventNICIPChanged = "NIC_IP_CHANGED"
)

// =============================================================================
// Enumerator Configuration
// =============================================================================

// EnumeratorConfig holds configuration settings for enumeration behavior.
type EnumeratorConfig struct {
	// AutoDetect enables automatic interface discovery (default: true).
	AutoDetect bool `json:"auto_detect" yaml:"auto_detect"`
	// IncludeVirtual includes virtual interfaces in results (default: true).
	IncludeVirtual bool `json:"include_virtual" yaml:"include_virtual"`
	// IncludeLoopback includes loopback interfaces (default: false).
	IncludeLoopback bool `json:"include_loopback" yaml:"include_loopback"`
	// ScanInterval is the continuous scan interval (default: 30s).
	ScanInterval time.Duration `json:"scan_interval" yaml:"scan_interval"`
	// EnableHotplug enables monitoring for hotplug events (default: true).
	EnableHotplug bool `json:"enable_hotplug" yaml:"enable_hotplug"`
	// PlatformSpecific holds platform-specific options.
	PlatformSpecific map[string]interface{} `json:"platform_specific,omitempty" yaml:"platform_specific,omitempty"`
}

// DefaultEnumeratorConfig returns a configuration with sensible defaults.
func DefaultEnumeratorConfig() *EnumeratorConfig {
	return &EnumeratorConfig{
		AutoDetect:       true,
		IncludeVirtual:   true,
		IncludeLoopback:  false,
		ScanInterval:     30 * time.Second,
		EnableHotplug:    true,
		PlatformSpecific: make(map[string]interface{}),
	}
}

// Validate ensures the configuration is valid.
func (c *EnumeratorConfig) Validate() error {
	if c.ScanInterval < time.Second {
		return fmt.Errorf("scan interval must be at least 1 second, got %v", c.ScanInterval)
	}
	if c.ScanInterval > 5*time.Minute {
		return fmt.Errorf("scan interval should not exceed 5 minutes, got %v", c.ScanInterval)
	}
	return nil
}

// =============================================================================
// Interface Event
// =============================================================================

// InterfaceEvent represents an interface discovery event.
type InterfaceEvent struct {
	Type      string                  `json:"type"`
	Interface *types.NetworkInterface `json:"interface"`
	Timestamp time.Time               `json:"timestamp"`
}

// EventHandler is a callback function for interface events.
type EventHandler func(event InterfaceEvent)

// =============================================================================
// Enumerator Structure
// =============================================================================

// Enumerator is the NIC enumeration engine.
type Enumerator struct {
	// Configuration
	config *EnumeratorConfig

	// In-memory cache of discovered interfaces.
	interfaceCache map[string]*types.NetworkInterface
	cacheMutex     sync.RWMutex

	// Last scan tracking.
	lastScanTime time.Time
	lastScanMu   sync.RWMutex

	// Previous scan results for change detection.
	previousInterfaces []*types.NetworkInterface
	previousMu         sync.RWMutex

	// Continuous scanning.
	scanContext    context.Context
	scanCancelFunc context.CancelFunc
	scanWg         sync.WaitGroup
	scanning       bool
	scanningMu     sync.RWMutex

	// Event handlers.
	eventHandlers []EventHandler
	handlersMu    sync.RWMutex

	// Windows-specific notification handle.
	notificationHandle uintptr
}

// =============================================================================
// Constructor
// =============================================================================

// NewEnumerator creates a new enumerator instance.
func NewEnumerator(config *EnumeratorConfig) (*Enumerator, error) {
	if config == nil {
		config = DefaultEnumeratorConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Enumerator{
		config:             config,
		interfaceCache:     make(map[string]*types.NetworkInterface),
		previousInterfaces: make([]*types.NetworkInterface, 0),
		eventHandlers:      make([]EventHandler, 0),
	}, nil
}

// =============================================================================
// Event Handler Registration
// =============================================================================

// RegisterEventHandler adds an event handler callback.
func (e *Enumerator) RegisterEventHandler(handler EventHandler) {
	e.handlersMu.Lock()
	defer e.handlersMu.Unlock()
	e.eventHandlers = append(e.eventHandlers, handler)
}

// publishEvent sends an event to all registered handlers.
func (e *Enumerator) publishEvent(eventType string, iface *types.NetworkInterface) {
	event := InterfaceEvent{
		Type:      eventType,
		Interface: iface,
		Timestamp: time.Now(),
	}

	e.handlersMu.RLock()
	handlers := make([]EventHandler, len(e.eventHandlers))
	copy(handlers, e.eventHandlers)
	e.handlersMu.RUnlock()

	for _, handler := range handlers {
		go handler(event)
	}
}

// =============================================================================
// Platform-Specific Enumeration Dispatch
// =============================================================================

// EnumerateInterfaces is the main enumeration method.
// It detects the operating system and routes to the appropriate platform implementation.
func (e *Enumerator) EnumerateInterfaces(ctx context.Context) ([]*types.NetworkInterface, error) {
	var interfaces []*types.NetworkInterface
	var err error

	switch runtime.GOOS {
	case "windows":
		interfaces, err = e.enumerateWindows(ctx)
	case "linux":
		interfaces, err = e.enumerateLinux(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return nil, fmt.Errorf("enumeration failed on %s: %w", runtime.GOOS, err)
	}

	// Filter results based on configuration.
	filtered := e.filterInterfaces(interfaces)

	// Update interface cache.
	e.updateCache(filtered)

	// Update last scan time.
	e.lastScanMu.Lock()
	e.lastScanTime = time.Now()
	e.lastScanMu.Unlock()

	return filtered, nil
}

// GetLastScanTime returns the timestamp of the last successful scan.
func (e *Enumerator) GetLastScanTime() time.Time {
	e.lastScanMu.RLock()
	defer e.lastScanMu.RUnlock()
	return e.lastScanTime
}

// =============================================================================
// Interface Cache Management
// =============================================================================

// updateCache updates the in-memory interface cache and detects changes.
func (e *Enumerator) updateCache(interfaces []*types.NetworkInterface) {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Detect changes.
	e.previousMu.Lock()
	added := e.detectAddedInterfaces(interfaces, e.previousInterfaces)
	removed := e.detectRemovedInterfaces(interfaces, e.previousInterfaces)
	changed := e.detectChangedInterfaces(interfaces, e.previousInterfaces)
	e.previousMu.Unlock()

	// Update cache.
	newCache := make(map[string]*types.NetworkInterface)
	for _, iface := range interfaces {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		newCache[key] = iface
	}
	e.interfaceCache = newCache

	// Update previous interfaces.
	e.previousMu.Lock()
	e.previousInterfaces = interfaces
	e.previousMu.Unlock()

	// Publish events.
	for _, iface := range added {
		e.publishEvent(EventNICAdded, iface)
	}
	for _, iface := range removed {
		e.publishEvent(EventNICRemoved, iface)
	}
	for _, iface := range changed {
		e.publishEvent(EventNICStateChanged, iface)
	}
}

// GetFromCache retrieves an interface from cache by name.
func (e *Enumerator) GetFromCache(interfaceName string) (*types.NetworkInterface, bool) {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	for _, iface := range e.interfaceCache {
		if iface.Name == interfaceName || iface.Alias == interfaceName {
			return iface, true
		}
	}
	return nil, false
}

// GetCachedInterfaces returns all cached interfaces.
func (e *Enumerator) GetCachedInterfaces() []*types.NetworkInterface {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	interfaces := make([]*types.NetworkInterface, 0, len(e.interfaceCache))
	for _, iface := range e.interfaceCache {
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

// =============================================================================
// Interface Addition/Removal Detection
// =============================================================================

// detectAddedInterfaces finds interfaces in current but not in previous scan.
func (e *Enumerator) detectAddedInterfaces(current, previous []*types.NetworkInterface) []*types.NetworkInterface {
	if len(previous) == 0 {
		return nil // First scan, don't report all as added.
	}

	prevMap := make(map[string]bool)
	for _, iface := range previous {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		prevMap[key] = true
	}

	var added []*types.NetworkInterface
	for _, iface := range current {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		if !prevMap[key] {
			added = append(added, iface)
		}
	}

	return added
}

// detectRemovedInterfaces finds interfaces in previous but not in current scan.
func (e *Enumerator) detectRemovedInterfaces(current, previous []*types.NetworkInterface) []*types.NetworkInterface {
	currMap := make(map[string]bool)
	for _, iface := range current {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		currMap[key] = true
	}

	var removed []*types.NetworkInterface
	for _, iface := range previous {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		if !currMap[key] {
			removed = append(removed, iface)
		}
	}

	return removed
}

// detectChangedInterfaces finds interfaces with changed properties.
func (e *Enumerator) detectChangedInterfaces(current, previous []*types.NetworkInterface) []*types.NetworkInterface {
	prevMap := make(map[string]*types.NetworkInterface)
	for _, iface := range previous {
		key := iface.MACAddress
		if key == "" {
			key = iface.Name
		}
		prevMap[key] = iface
	}

	var changed []*types.NetworkInterface
	for _, curr := range current {
		key := curr.MACAddress
		if key == "" {
			key = curr.Name
		}
		if prev, ok := prevMap[key]; ok {
			if e.hasInterfaceChanged(curr, prev) {
				changed = append(changed, curr)
			}
		}
	}

	return changed
}

// hasInterfaceChanged checks if important interface properties have changed.
func (e *Enumerator) hasInterfaceChanged(current, previous *types.NetworkInterface) bool {
	// Check operational state.
	if current.State != previous.State {
		return true
	}
	// Check IP address.
	if current.IPAddress != previous.IPAddress {
		return true
	}
	// Check enabled status.
	if current.IsEnabled != previous.IsEnabled {
		return true
	}
	// Check speed.
	if current.SpeedMbps != previous.SpeedMbps {
		return true
	}
	return false
}

// =============================================================================
// Filtering Logic
// =============================================================================

// filterInterfaces applies configuration filters to the interface list.
func (e *Enumerator) filterInterfaces(interfaces []*types.NetworkInterface) []*types.NetworkInterface {
	filtered := make([]*types.NetworkInterface, 0, len(interfaces))

	for _, iface := range interfaces {
		// Skip loopback if not configured to include.
		if !e.config.IncludeLoopback && e.isLoopback(iface) {
			continue
		}

		// Skip virtual if not configured to include.
		if !e.config.IncludeVirtual && iface.IsVirtual {
			continue
		}

		filtered = append(filtered, iface)
	}

	return filtered
}

// isLoopback determines if an interface is a loopback interface.
func (e *Enumerator) isLoopback(iface *types.NetworkInterface) bool {
	if iface.Type == types.InterfaceTypeLOOPBACK {
		return true
	}
	// Check by name patterns.
	nameLower := strings.ToLower(iface.Name)
	if strings.Contains(nameLower, "loopback") || nameLower == "lo" {
		return true
	}
	// Check by IP address.
	if strings.HasPrefix(iface.IPAddress, "127.") || iface.IPAddress == "::1" {
		return true
	}
	return false
}

// =============================================================================
// Continuous Scanning
// =============================================================================

// StartContinuousScan starts background scanning for hotplug detection.
func (e *Enumerator) StartContinuousScan(ctx context.Context) error {
	e.scanningMu.Lock()
	if e.scanning {
		e.scanningMu.Unlock()
		return fmt.Errorf("continuous scanning already running")
	}
	e.scanning = true
	e.scanContext, e.scanCancelFunc = context.WithCancel(ctx)
	e.scanningMu.Unlock()

	e.scanWg.Add(1)
	go e.continuousScanLoop()

	return nil
}

// continuousScanLoop runs the periodic enumeration for hotplug detection.
func (e *Enumerator) continuousScanLoop() {
	defer e.scanWg.Done()

	ticker := time.NewTicker(e.config.ScanInterval)
	defer ticker.Stop()

	// Perform initial scan.
	_, _ = e.EnumerateInterfaces(e.scanContext)

	for {
		select {
		case <-e.scanContext.Done():
			return
		case <-ticker.C:
			// Perform periodic enumeration.
			_, err := e.EnumerateInterfaces(e.scanContext)
			if err != nil {
				// Log error but continue scanning.
				_ = err
			}
		}
	}
}

// StopContinuousScan stops the background scanning.
func (e *Enumerator) StopContinuousScan() {
	e.scanningMu.Lock()
	if !e.scanning {
		e.scanningMu.Unlock()
		return
	}
	e.scanning = false
	e.scanningMu.Unlock()

	if e.scanCancelFunc != nil {
		e.scanCancelFunc()
	}
	e.scanWg.Wait()
}

// IsScanning returns true if continuous scanning is active.
func (e *Enumerator) IsScanning() bool {
	e.scanningMu.RLock()
	defer e.scanningMu.RUnlock()
	return e.scanning
}

// =============================================================================
// Platform Information
// =============================================================================

// GetPlatform returns the current operating system.
func (e *Enumerator) GetPlatform() string {
	return runtime.GOOS
}

// SupportsHotplug returns true if the platform supports hotplug notifications.
func (e *Enumerator) SupportsHotplug() bool {
	switch runtime.GOOS {
	case "windows":
		return true // Windows supports NotifyIpInterfaceChange
	case "linux":
		return true // Linux supports netlink notifications
	default:
		return false
	}
}

// =============================================================================
// Cleanup
// =============================================================================

// Close cleans up resources and stops any background operations.
func (e *Enumerator) Close() error {
	// Stop continuous scanning.
	e.StopContinuousScan()

	// Clear cache.
	e.cacheMutex.Lock()
	e.interfaceCache = make(map[string]*types.NetworkInterface)
	e.cacheMutex.Unlock()

	// Clear event handlers.
	e.handlersMu.Lock()
	e.eventHandlers = nil
	e.handlersMu.Unlock()

	return nil
}
