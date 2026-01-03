// Package watcher provides IP address change notification handling
package watcher

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"sync"
	"time"

	"dhcp_monitor/internal/platform"
)

// =============================================================================
// NOTIFICATION TYPE CONSTANTS
// =============================================================================

// Notification types from Windows API
const (
	MibAddInstance         = 0 // New IP address added
	MibDeleteInstance      = 1 // IP address removed
	MibModifyInstance      = 2 // IP address parameters changed
	MibInitialNotification = 3 // Initial callback after registration
)

// String representations for logging
const (
	NotifyTypeIPAdded    = "IP_ADDED"
	NotifyTypeIPRemoved  = "IP_REMOVED"
	NotifyTypeIPModified = "IP_MODIFIED"
	NotifyTypeInitial    = "INITIAL"
)

// =============================================================================
// IP CHANGE NOTIFIER STRUCT
// =============================================================================

// IPChangeNotifier manages IP address change notifications
type IPChangeNotifier struct {
	eventChannel    EventChannel
	arpTable        *ARPTable
	isRunning       bool
	mutex           sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	interfaceFilter *regexp.Regexp
	sendTimeout     time.Duration

	// Interface name cache
	interfaceCache map[uint32]string
	cacheMutex     sync.RWMutex
}

// NewIPChangeNotifier creates a new IP change notifier
func NewIPChangeNotifier(eventChan EventChannel, arpTable *ARPTable) *IPChangeNotifier {
	return &IPChangeNotifier{
		eventChannel:   eventChan,
		arpTable:       arpTable,
		isRunning:      false,
		sendTimeout:    100 * time.Millisecond,
		interfaceCache: make(map[uint32]string),
	}
}

// =============================================================================
// LIFECYCLE METHODS
// =============================================================================

// Start registers for IP change notifications
func (n *IPChangeNotifier) Start(ctx context.Context) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.isRunning {
		return fmt.Errorf("IP change notifier already running")
	}

	// Create cancellable context
	n.ctx, n.cancel = context.WithCancel(ctx)

	// Register callback with Windows API
	err := platform.RegisterIPChangeCallback(n.handleIPNotification)
	if err != nil {
		return fmt.Errorf("failed to register IP change callback: %w", err)
	}

	n.isRunning = true
	log.Println("[IP_NOTIFIER] Started IP change notification listener")

	return nil
}

// Stop unregisters from IP change notifications
func (n *IPChangeNotifier) Stop() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if !n.isRunning {
		return nil // Already stopped
	}

	// Cancel context
	if n.cancel != nil {
		n.cancel()
	}

	// Unregister callback
	err := platform.UnregisterIPChangeCallback()
	if err != nil {
		log.Printf("[IP_NOTIFIER] Warning: failed to unregister callback: %v", err)
	}

	// Brief grace period for in-flight callbacks
	time.Sleep(50 * time.Millisecond)

	n.isRunning = false
	log.Println("[IP_NOTIFIER] Stopped IP change notification listener")

	return nil
}

// IsRunning returns whether the notifier is active
func (n *IPChangeNotifier) IsRunning() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.isRunning
}

// =============================================================================
// CALLBACK HANDLING
// =============================================================================

// handleIPNotification processes IP change notifications from Windows API
func (n *IPChangeNotifier) handleIPNotification(notification platform.IPNotification) {
	// Check if we should process this notification
	if !n.isRunning {
		return
	}

	// Check context cancellation
	select {
	case <-n.ctx.Done():
		return
	default:
	}

	// Process in goroutine to not block callback
	go n.processIPChange(notification)
}

// processIPChange handles the IP change event
func (n *IPChangeNotifier) processIPChange(notification platform.IPNotification) {
	ip := net.ParseIP(notification.IPAddress)
	if ip == nil {
		log.Printf("[IP_NOTIFIER] Invalid IP address in notification: %s", notification.IPAddress)
		return
	}

	// Skip loopback addresses
	if ip.IsLoopback() {
		return
	}

	// Skip link-local addresses (169.254.x.x)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return
		}
	}

	// Get interface name
	interfaceName := n.getInterfaceName(notification.InterfaceIndex)

	// Apply interface filter if set
	if n.interfaceFilter != nil && !n.interfaceFilter.MatchString(interfaceName) {
		return
	}

	// Convert notification type
	notifyType := n.notificationTypeString(notification.NotifyType)
	log.Printf("[IP_NOTIFIER] %s: IP=%s Interface=%s (index=%d)",
		notifyType, notification.IPAddress, interfaceName, notification.InterfaceIndex)

	// Try to get MAC address from ARP table
	var macAddress string
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	arpEntry, err := n.arpTable.LookupIP(ctx, ip)
	if err == nil && arpEntry != nil {
		macAddress = arpEntry.MACAddress
	} else {
		// MAC not in ARP table yet, try direct lookup
		if entry, err := platform.GetARPEntryByIP(notification.IPAddress); err == nil {
			macAddress = entry.MACAddress
		}
	}

	if macAddress == "" {
		log.Printf("[IP_NOTIFIER] No MAC address found for IP %s (may appear in ARP table shortly)",
			notification.IPAddress)
		return
	}

	// Create appropriate event based on notification type
	var event *NetworkEvent

	switch notification.NotifyType {
	case platform.NotifyTypeAdd:
		event = NewDeviceDetectedEvent(macAddress, notification.IPAddress,
			interfaceName, notification.InterfaceIndex, DetectionSourceIPHelper)

	case platform.NotifyTypeDelete:
		event = &NetworkEvent{
			EventType:       EventTypeDeviceOffline,
			Timestamp:       time.Now(),
			MACAddress:      macAddress,
			IPAddress:       ip,
			InterfaceName:   interfaceName,
			InterfaceIndex:  notification.InterfaceIndex,
			DetectionSource: DetectionSourceIPHelper,
			Metadata:        make(map[string]string),
		}

	case platform.NotifyTypeParameterChange:
		event = &NetworkEvent{
			EventType:       EventTypeIPChanged,
			Timestamp:       time.Now(),
			MACAddress:      macAddress,
			IPAddress:       ip,
			InterfaceName:   interfaceName,
			InterfaceIndex:  notification.InterfaceIndex,
			DetectionSource: DetectionSourceIPHelper,
			Metadata:        make(map[string]string),
		}

	default:
		return
	}

	// Send event to channel
	if err := n.sendEvent(event); err != nil {
		log.Printf("[IP_NOTIFIER] Warning: failed to send event: %v", err)
	}
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// getInterfaceName converts interface index to friendly name with caching
func (n *IPChangeNotifier) getInterfaceName(interfaceIndex uint32) string {
	// Check cache first
	n.cacheMutex.RLock()
	name, exists := n.interfaceCache[interfaceIndex]
	n.cacheMutex.RUnlock()

	if exists {
		return name
	}

	// Query interface name
	name, err := platform.GetInterfaceName(interfaceIndex)
	if err != nil {
		name = fmt.Sprintf("Interface %d", interfaceIndex)
	}

	// Cache result
	n.cacheMutex.Lock()
	n.interfaceCache[interfaceIndex] = name
	n.cacheMutex.Unlock()

	return name
}

// notificationTypeString converts notification type to string
func (n *IPChangeNotifier) notificationTypeString(notifyType platform.NotificationType) string {
	switch notifyType {
	case platform.NotifyTypeAdd:
		return NotifyTypeIPAdded
	case platform.NotifyTypeDelete:
		return NotifyTypeIPRemoved
	case platform.NotifyTypeParameterChange:
		return NotifyTypeIPModified
	default:
		return NotifyTypeInitial
	}
}

// sendEvent sends an event with timeout to prevent blocking
func (n *IPChangeNotifier) sendEvent(event *NetworkEvent) error {
	select {
	case n.eventChannel <- event:
		return nil
	case <-time.After(n.sendTimeout):
		return fmt.Errorf("event channel send timeout")
	case <-n.ctx.Done():
		return fmt.Errorf("notifier shutting down")
	}
}

// =============================================================================
// CONFIGURATION METHODS
// =============================================================================

// SetInterfaceFilter sets a regex pattern for interface filtering
func (n *IPChangeNotifier) SetInterfaceFilter(pattern string) error {
	if pattern == "" || pattern == ".*" {
		n.interfaceFilter = nil
		return nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid interface filter pattern: %w", err)
	}

	n.interfaceFilter = re
	log.Printf("[IP_NOTIFIER] Interface filter set: %s", pattern)
	return nil
}

// SetSendTimeout sets the event channel send timeout
func (n *IPChangeNotifier) SetSendTimeout(timeout time.Duration) {
	n.sendTimeout = timeout
}

// InvalidateInterfaceCache clears the interface name cache
func (n *IPChangeNotifier) InvalidateInterfaceCache() {
	n.cacheMutex.Lock()
	defer n.cacheMutex.Unlock()
	n.interfaceCache = make(map[uint32]string)
}
