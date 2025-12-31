// Package arp_monitor provides ARP-based device detection for all NICs
package arp_monitor

import (
	"context"
	"dhcp_monitor/internal/storage"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Device represents a detected device from ARP table
type Device struct {
	IP            string
	MAC           string
	InterfaceID   string
	InterfaceName string
	State         string // reachable, stale, incomplete
	FirstSeen     time.Time
	LastSeen      time.Time
}

// Monitor polls the ARP table to detect devices on all NICs
type Monitor struct {
	pollInterval time.Duration
	db           *storage.Database
	eventCh      chan DeviceEvent
	stopCh       chan struct{}
	wg           sync.WaitGroup

	mu           sync.RWMutex
	knownDevices map[string]*Device // key: MAC address
}

// DeviceEvent represents a device change event
type DeviceEvent struct {
	Type   EventType
	Device *Device
}

// EventType represents the type of device event
type EventType string

const (
	EventDeviceConnected    EventType = "connected"
	EventDeviceDisconnected EventType = "disconnected"
	EventDeviceUpdated      EventType = "updated"
)

// Config holds ARP monitor configuration
type Config struct {
	PollInterval time.Duration
	Database     *storage.Database
}

// New creates a new ARP monitor
func New(cfg Config) *Monitor {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Second
	}

	return &Monitor{
		pollInterval: cfg.PollInterval,
		db:           cfg.Database,
		eventCh:      make(chan DeviceEvent, 100),
		stopCh:       make(chan struct{}),
		knownDevices: make(map[string]*Device),
	}
}

// Start begins ARP monitoring
func (m *Monitor) Start(ctx context.Context) error {
	// Initial scan
	if err := m.scan(); err != nil {
		fmt.Printf("[WARN] Initial ARP scan failed: %v\n", err)
	}

	m.wg.Add(1)
	go m.pollLoop(ctx)

	fmt.Printf("[INFO] ARP Monitor started (polling every %v)\n", m.pollInterval)
	return nil
}

// Stop stops the monitor
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	close(m.eventCh)
}

// Events returns the device event channel
func (m *Monitor) Events() <-chan DeviceEvent {
	return m.eventCh
}

// GetDevices returns all currently known devices
func (m *Monitor) GetDevices() []Device {
	m.mu.RLock()
	defer m.mu.RUnlock()

	devices := make([]Device, 0, len(m.knownDevices))
	for _, d := range m.knownDevices {
		devices = append(devices, *d)
	}
	return devices
}

// pollLoop runs the periodic polling loop
func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.scan(); err != nil {
				fmt.Printf("[ERROR] ARP scan failed: %v\n", err)
			}
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// scan reads the ARP table and detects changes
func (m *Monitor) scan() error {
	// Get ARP entries using PowerShell
	devices, err := m.getARPTable()
	if err != nil {
		fmt.Printf("[ERROR] ARP scan failed: %v\n", err)
		return err
	}

	// Debug: Log how many devices were found
	fmt.Printf("[DEBUG] ARP scan found %d devices\n", len(devices))

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	currentMACs := make(map[string]bool)

	for _, device := range devices {
		currentMACs[device.MAC] = true

		existing, exists := m.knownDevices[device.MAC]
		if !exists {
			// New device detected
			device.FirstSeen = now
			device.LastSeen = now
			m.knownDevices[device.MAC] = device

			m.emitEvent(DeviceEvent{
				Type:   EventDeviceConnected,
				Device: device,
			})

			// Add to database
			m.saveToDatabase(device)

			fmt.Printf("[INFO] New device detected: IP=%s, MAC=%s, NIC=%s\n",
				device.IP, device.MAC, device.InterfaceName)
		} else {
			// Update existing device
			existing.LastSeen = now
			existing.IP = device.IP // IP might change
			existing.State = device.State

			// Update database
			m.saveToDatabase(existing)
		}
	}

	// Check for disconnected devices (not seen for 5 minutes)
	staleThreshold := now.Add(-5 * time.Minute)
	for mac, device := range m.knownDevices {
		if !currentMACs[mac] && device.LastSeen.Before(staleThreshold) {
			m.emitEvent(DeviceEvent{
				Type:   EventDeviceDisconnected,
				Device: device,
			})
			delete(m.knownDevices, mac)

			fmt.Printf("[INFO] Device disconnected: IP=%s, MAC=%s\n", device.IP, device.MAC)
		}
	}

	return nil
}

// getARPTable retrieves ARP entries using PowerShell
func (m *Monitor) getARPTable() ([]*Device, error) {
	// Get ALL devices (IPv4 and IPv6) - exclude invalid, broadcast, and multicast MACs
	// Also exclude multicast IPv4 (224.x.x.x) and IPv6 link-local multicast (ff0x::)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", `
		Get-NetNeighbor | Where-Object { 
			$_.LinkLayerAddress -ne '' -and
			$_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
			$_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and
			-not $_.LinkLayerAddress.StartsWith('01-00-5E') -and
			-not $_.LinkLayerAddress.StartsWith('33-33') -and
			-not $_.IPAddress.StartsWith('224.') -and
			-not $_.IPAddress.StartsWith('239.') -and
			-not $_.IPAddress.StartsWith('ff0') -and
			-not $_.IPAddress.StartsWith('fe80::1') -and
			$_.IPAddress -ne '127.0.0.1' -and
			$_.IPAddress -ne '::1'
		} | Select-Object IPAddress, LinkLayerAddress, InterfaceIndex, InterfaceAlias, State | 
		ConvertTo-Json -Depth 2 -Compress
	`)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("PowerShell command failed: %w", err)
	}

	return m.parseARPOutput(string(output))
}

// parseARPOutput parses PowerShell JSON output
func (m *Monitor) parseARPOutput(output string) ([]*Device, error) {
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return nil, nil
	}

	var devices []*Device

	// Simple regex-based parsing (more reliable than JSON for PowerShell output)
	// Match IP addresses and MAC addresses
	ipPattern := regexp.MustCompile(`"IPAddress"\s*:\s*"([^"]+)"`)
	macPattern := regexp.MustCompile(`"LinkLayerAddress"\s*:\s*"([^"]+)"`)
	ifIndexPattern := regexp.MustCompile(`"InterfaceIndex"\s*:\s*(\d+)`)
	ifAliasPattern := regexp.MustCompile(`"InterfaceAlias"\s*:\s*"([^"]+)"`)
	statePattern := regexp.MustCompile(`"State"\s*:\s*(\d+)`)

	// Split by entries (look for IPAddress patterns)
	entries := strings.Split(output, "IPAddress")

	for _, entry := range entries[1:] { // Skip first empty part
		entry = "IPAddress" + entry

		ipMatch := ipPattern.FindStringSubmatch(entry)
		macMatch := macPattern.FindStringSubmatch(entry)

		if len(ipMatch) < 2 || len(macMatch) < 2 {
			continue
		}

		ip := ipMatch[1]
		mac := strings.ToUpper(strings.ReplaceAll(macMatch[1], "-", ":"))

		// Skip loopback and link-local (except for hotspot IPs)
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
			continue
		}

		// Skip multicast
		if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "ff") {
			continue
		}

		device := &Device{
			IP:  ip,
			MAC: mac,
		}

		if ifIndexMatch := ifIndexPattern.FindStringSubmatch(entry); len(ifIndexMatch) >= 2 {
			device.InterfaceID = ifIndexMatch[1]
		}
		if ifAliasMatch := ifAliasPattern.FindStringSubmatch(entry); len(ifAliasMatch) >= 2 {
			device.InterfaceName = ifAliasMatch[1]
		}
		if stateMatch := statePattern.FindStringSubmatch(entry); len(stateMatch) >= 2 {
			device.State = m.parseState(stateMatch[1])
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// parseState converts state number to string
func (m *Monitor) parseState(state string) string {
	switch state {
	case "0":
		return "unreachable"
	case "1":
		return "incomplete"
	case "2":
		return "probe"
	case "3":
		return "delay"
	case "4":
		return "stale"
	case "5":
		return "reachable"
	case "6":
		return "permanent"
	default:
		return "unknown"
	}
}

// saveToDatabase saves device to database
func (m *Monitor) saveToDatabase(device *Device) {
	if m.db == nil {
		return
	}

	// Determine NIC type from interface name
	nicType := m.detectNICType(device.InterfaceName)

	dbDevice := &storage.Device{
		IP:               device.IP,
		MAC:              device.MAC,
		FirstSeen:        device.FirstSeen,
		LastSeen:         device.LastSeen,
		NICInterfaceID:   device.InterfaceID,
		NICInterfaceName: device.InterfaceName,
		NICType:          nicType,
	}

	if err := m.db.AddOrUpdateDevice(dbDevice); err != nil {
		fmt.Printf("[ERROR] Failed to save device to database: %v\n", err)
	}
}

// detectNICType determines NIC type from interface name
func (m *Monitor) detectNICType(interfaceName string) string {
	lower := strings.ToLower(interfaceName)

	if strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") || strings.Contains(lower, "wireless") {
		return "WiFi"
	}
	if strings.Contains(lower, "ethernet") {
		return "Ethernet"
	}
	if strings.Contains(lower, "local area connection") {
		// This is typically hotspot
		return "Hotspot"
	}
	if strings.Contains(lower, "bluetooth") {
		return "Bluetooth"
	}
	if strings.Contains(lower, "vmware") || strings.Contains(lower, "virtualbox") {
		return "Virtual"
	}

	return "Unknown"
}

// emitEvent sends event to channel (non-blocking)
func (m *Monitor) emitEvent(event DeviceEvent) {
	select {
	case m.eventCh <- event:
	default:
		// Channel full, drop event
	}
}

// GetLocalIPs returns all local IP addresses
func GetLocalIPs() []string {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	return ips
}
