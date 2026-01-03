// Package watcher provides network event detection and monitoring
package watcher

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// EVENT TYPE CONSTANTS
// =============================================================================

// Event types for network state changes
const (
	EventTypeDeviceDetected   = "DEVICE_DETECTED"   // New device appeared
	EventTypeIPChanged        = "IP_CHANGED"        // Existing device changed IP
	EventTypeDeviceOnline     = "DEVICE_ONLINE"     // Offline device became active
	EventTypeDeviceOffline    = "DEVICE_OFFLINE"    // Device inactive for timeout
	EventTypeHostnameUpdated  = "HOSTNAME_UPDATED"  // DHCP Event Log provided hostname
	EventTypeInterfaceChanged = "INTERFACE_CHANGED" // Device moved between NICs
	EventTypeLeaseRenewed     = "LEASE_RENEWED"     // DHCP lease renewal
	EventTypeLeaseExpired     = "LEASE_EXPIRED"     // DHCP lease expiration
)

// Detection sources
const (
	DetectionSourceIPHelper  = "IP_HELPER_API"
	DetectionSourceDHCPEvent = "DHCP_EVENT_LOG"
	DetectionSourceARPTable  = "ARP_TABLE"
	DetectionSourceManual    = "MANUAL"
)

// Event priorities for processing order
const (
	EventPriorityHigh   = 1 // DEVICE_DETECTED - blocks internet, must be fast
	EventPriorityMedium = 2 // IP_CHANGED, INTERFACE_CHANGED - affects routing
	EventPriorityLow    = 3 // HOSTNAME_UPDATED, LEASE_RENEWED - enrichment only
)

// =============================================================================
// NETWORK EVENT STRUCT
// =============================================================================

// NetworkEvent represents a network state change from any detection source
type NetworkEvent struct {
	EventType       string            `json:"event_type"`
	Timestamp       time.Time         `json:"timestamp"`
	DeviceID        uuid.UUID         `json:"device_id,omitempty"`
	MACAddress      string            `json:"mac_address"`
	IPAddress       net.IP            `json:"ip_address"`
	PreviousIP      net.IP            `json:"previous_ip,omitempty"`
	InterfaceName   string            `json:"interface_name"`
	InterfaceIndex  uint32            `json:"interface_index"`
	DetectionSource string            `json:"detection_source"`
	Hostname        string            `json:"hostname,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// =============================================================================
// DEVICE INFO STRUCT
// =============================================================================

// DeviceInfo represents compact device information from detection sources
type DeviceInfo struct {
	MACAddress      string `json:"mac_address"`
	IPAddress       net.IP `json:"ip_address"`
	InterfaceName   string `json:"interface_name"`
	InterfaceIndex  uint32 `json:"interface_index"`
	Hostname        string `json:"hostname,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	DetectionMethod string `json:"detection_method"`
}

// =============================================================================
// CHANNEL TYPES
// =============================================================================

// EventChannel is a buffered channel for event distribution
type EventChannel chan *NetworkEvent

// EventHandler is a function that processes network events
type EventHandler func(*NetworkEvent) error

// =============================================================================
// EVENT CONSTRUCTOR FUNCTIONS
// =============================================================================

// NewDeviceDetectedEvent creates a DEVICE_DETECTED event
func NewDeviceDetectedEvent(mac, ip, interfaceName string, ifIndex uint32, source string) *NetworkEvent {
	return &NetworkEvent{
		EventType:       EventTypeDeviceDetected,
		Timestamp:       time.Now(),
		MACAddress:      normalizeMACAddress(mac),
		IPAddress:       net.ParseIP(ip),
		InterfaceName:   interfaceName,
		InterfaceIndex:  ifIndex,
		DetectionSource: source,
		Metadata:        make(map[string]string),
	}
}

// NewIPChangedEvent creates an IP_CHANGED event
func NewIPChangedEvent(deviceID uuid.UUID, mac string, newIP, oldIP string, interfaceName string, ifIndex uint32) *NetworkEvent {
	return &NetworkEvent{
		EventType:       EventTypeIPChanged,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		IPAddress:       net.ParseIP(newIP),
		PreviousIP:      net.ParseIP(oldIP),
		InterfaceName:   interfaceName,
		InterfaceIndex:  ifIndex,
		DetectionSource: DetectionSourceIPHelper,
		Metadata:        make(map[string]string),
	}
}

// NewHostnameUpdatedEvent creates a HOSTNAME_UPDATED event
func NewHostnameUpdatedEvent(deviceID uuid.UUID, mac, hostname string) *NetworkEvent {
	return &NetworkEvent{
		EventType:       EventTypeHostnameUpdated,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		Hostname:        hostname,
		DetectionSource: DetectionSourceDHCPEvent,
		Metadata:        make(map[string]string),
	}
}

// NewDeviceOfflineEvent creates a DEVICE_OFFLINE event
func NewDeviceOfflineEvent(deviceID uuid.UUID, mac string, lastSeen time.Time) *NetworkEvent {
	event := &NetworkEvent{
		EventType:       EventTypeDeviceOffline,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		DetectionSource: DetectionSourceARPTable,
		Metadata:        make(map[string]string),
	}
	event.Metadata["last_seen"] = lastSeen.Format(time.RFC3339)
	return event
}

// NewDeviceOnlineEvent creates a DEVICE_ONLINE event
func NewDeviceOnlineEvent(deviceID uuid.UUID, mac, ip, interfaceName string, ifIndex uint32) *NetworkEvent {
	return &NetworkEvent{
		EventType:       EventTypeDeviceOnline,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		IPAddress:       net.ParseIP(ip),
		InterfaceName:   interfaceName,
		InterfaceIndex:  ifIndex,
		DetectionSource: DetectionSourceIPHelper,
		Metadata:        make(map[string]string),
	}
}

// NewInterfaceChangedEvent creates an INTERFACE_CHANGED event
func NewInterfaceChangedEvent(deviceID uuid.UUID, mac, ip, newIface string, newIfIndex uint32, oldIface string) *NetworkEvent {
	event := &NetworkEvent{
		EventType:       EventTypeInterfaceChanged,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		IPAddress:       net.ParseIP(ip),
		InterfaceName:   newIface,
		InterfaceIndex:  newIfIndex,
		DetectionSource: DetectionSourceIPHelper,
		Metadata:        make(map[string]string),
	}
	event.Metadata["previous_interface"] = oldIface
	return event
}

// NewLeaseRenewedEvent creates a LEASE_RENEWED event
func NewLeaseRenewedEvent(deviceID uuid.UUID, mac, ip string, leaseEnd time.Time) *NetworkEvent {
	event := &NetworkEvent{
		EventType:       EventTypeLeaseRenewed,
		Timestamp:       time.Now(),
		DeviceID:        deviceID,
		MACAddress:      normalizeMACAddress(mac),
		IPAddress:       net.ParseIP(ip),
		DetectionSource: DetectionSourceDHCPEvent,
		Metadata:        make(map[string]string),
	}
	event.Metadata["lease_end"] = leaseEnd.Format(time.RFC3339)
	return event
}

// =============================================================================
// VALIDATION METHODS
// =============================================================================

// Validate checks that required fields are populated
func (e *NetworkEvent) Validate() error {
	if e.EventType == "" {
		return fmt.Errorf("event type is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if e.MACAddress == "" && e.EventType != EventTypeLeaseExpired {
		return fmt.Errorf("MAC address is required for %s events", e.EventType)
	}
	if e.IPAddress == nil && e.requiresIP() {
		return fmt.Errorf("IP address is required for %s events", e.EventType)
	}
	return nil
}

// requiresIP returns true if event type requires IP address
func (e *NetworkEvent) requiresIP() bool {
	switch e.EventType {
	case EventTypeDeviceDetected, EventTypeIPChanged, EventTypeDeviceOnline:
		return true
	default:
		return false
	}
}

// IsDeviceEvent returns true if event affects a device record
func (e *NetworkEvent) IsDeviceEvent() bool {
	switch e.EventType {
	case EventTypeDeviceDetected, EventTypeIPChanged, EventTypeDeviceOnline,
		EventTypeDeviceOffline, EventTypeHostnameUpdated, EventTypeInterfaceChanged:
		return true
	default:
		return false
	}
}

// RequiresIPHistory returns true if event should log IP change
func (e *NetworkEvent) RequiresIPHistory() bool {
	switch e.EventType {
	case EventTypeDeviceDetected, EventTypeIPChanged, EventTypeInterfaceChanged:
		return true
	default:
		return false
	}
}

// RequiresLeaseUpdate returns true if event affects DHCP lease
func (e *NetworkEvent) RequiresLeaseUpdate() bool {
	switch e.EventType {
	case EventTypeLeaseRenewed, EventTypeLeaseExpired:
		return true
	default:
		return false
	}
}

// =============================================================================
// STRING REPRESENTATION
// =============================================================================

// String returns human-readable event description
func (e *NetworkEvent) String() string {
	ip := ""
	if e.IPAddress != nil {
		ip = e.IPAddress.String()
	}

	return fmt.Sprintf("%s: MAC=%s IP=%s Interface='%s' Source=%s",
		e.EventType, e.MACAddress, ip, e.InterfaceName, e.DetectionSource)
}

// LogFields returns structured logging fields
func (e *NetworkEvent) LogFields() map[string]interface{} {
	fields := map[string]interface{}{
		"event_type":       e.EventType,
		"timestamp":        e.Timestamp.Format(time.RFC3339Nano),
		"mac_address":      e.MACAddress,
		"detection_source": e.DetectionSource,
	}

	if e.DeviceID != uuid.Nil {
		fields["device_id"] = e.DeviceID.String()
	}
	if e.IPAddress != nil {
		fields["ip_address"] = e.IPAddress.String()
	}
	if e.PreviousIP != nil {
		fields["previous_ip"] = e.PreviousIP.String()
	}
	if e.InterfaceName != "" {
		fields["interface_name"] = e.InterfaceName
	}
	if e.InterfaceIndex > 0 {
		fields["interface_index"] = e.InterfaceIndex
	}
	if e.Hostname != "" {
		fields["hostname"] = e.Hostname
	}

	return fields
}

// =============================================================================
// PRIORITY AND HELPER FUNCTIONS
// =============================================================================

// Priority returns the processing priority for this event type
func (e *NetworkEvent) Priority() int {
	switch e.EventType {
	case EventTypeDeviceDetected:
		return EventPriorityHigh
	case EventTypeIPChanged, EventTypeInterfaceChanged, EventTypeDeviceOnline:
		return EventPriorityMedium
	default:
		return EventPriorityLow
	}
}

// normalizeMACAddress converts MAC to AA:BB:CC:DD:EE:FF format
func normalizeMACAddress(mac string) string {
	// Remove common separators
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")
	mac = strings.ToUpper(mac)

	// If no separators, add them
	if len(mac) == 12 && !strings.Contains(mac, ":") {
		mac = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" +
			mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
	}

	return mac
}

// NewEventChannel creates a buffered event channel
func NewEventChannel(bufferSize int) EventChannel {
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size
	}
	return make(EventChannel, bufferSize)
}

// DeviceInfoFromEvent extracts DeviceInfo from a NetworkEvent
func DeviceInfoFromEvent(e *NetworkEvent) *DeviceInfo {
	return &DeviceInfo{
		MACAddress:      e.MACAddress,
		IPAddress:       e.IPAddress,
		InterfaceName:   e.InterfaceName,
		InterfaceIndex:  e.InterfaceIndex,
		Hostname:        e.Hostname,
		DetectionMethod: e.DetectionSource,
	}
}
