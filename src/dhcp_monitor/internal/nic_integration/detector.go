// Package nic_integration provides NIC detection for DHCP monitor
package nic_integration

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// NICDetector integrates with system NICs for interface detection
type NICDetector struct {
	mu       sync.RWMutex
	nicCache map[string]*NICInfo // key: interface name
	ipToNIC  map[string]string   // key: IP, value: interface name
	macToNIC map[string]string   // key: MAC, value: interface name

	ctx    context.Context
	cancel context.CancelFunc
}

// NICInfo holds NIC information for a device
type NICInfo struct {
	InterfaceName string
	InterfaceType string
	MACAddress    string
	IPAddress     string
	Netmask       string
	IsWireless    bool
	WiFiSSID      string
	WiFiMode      string
	WiFiChannel   int
	Found         bool
	InterfaceID   string
}

// New creates a new NIC detector
func New() (*NICDetector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	detector := &NICDetector{
		nicCache: make(map[string]*NICInfo),
		ipToNIC:  make(map[string]string),
		macToNIC: make(map[string]string),
		ctx:      ctx,
		cancel:   cancel,
	}

	return detector, nil
}

// Start starts the NIC detector
func (d *NICDetector) Start(ctx context.Context) error {
	// Initial scan
	if err := d.Refresh(ctx); err != nil {
		return fmt.Errorf("initial NIC scan failed: %w", err)
	}

	// Start periodic refresh
	go d.refreshLoop()

	return nil
}

// Stop stops the NIC detector
func (d *NICDetector) Stop() error {
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

// refreshLoop periodically refreshes NIC information
func (d *NICDetector) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.Refresh(d.ctx)
		}
	}
}

// Refresh performs a fresh scan of all NICs
func (d *NICDetector) Refresh(ctx context.Context) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.nicCache = make(map[string]*NICInfo)
	d.ipToNIC = make(map[string]string)
	d.macToNIC = make(map[string]string)

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only process IPv4
			if ipNet.IP.To4() == nil {
				continue
			}

			nicInfo := &NICInfo{
				InterfaceName: iface.Name,
				InterfaceID:   iface.Name,
				InterfaceType: classifyInterface(iface.Name),
				MACAddress:    iface.HardwareAddr.String(),
				IPAddress:     ipNet.IP.String(),
				Netmask:       net.IP(ipNet.Mask).String(),
				IsWireless:    isWirelessInterface(iface.Name),
				Found:         true,
			}

			// Store in caches
			d.nicCache[iface.Name] = nicInfo

			// Map IP to NIC
			d.ipToNIC[nicInfo.IPAddress] = iface.Name

			// Map MAC to NIC
			if nicInfo.MACAddress != "" {
				normalizedMAC := normalizeMAC(nicInfo.MACAddress)
				d.macToNIC[normalizedMAC] = iface.Name
			}
		}
	}

	return nil
}

// GetNICInfo returns detailed NIC information for a device
func (d *NICDetector) GetNICInfo(deviceIP string) *NICInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Method 1: Check if device IP is in our IP map
	if nicName, found := d.ipToNIC[deviceIP]; found {
		if nic, exists := d.nicCache[nicName]; exists {
			return nic
		}
	}

	// Method 2: Check if device is in NIC's subnet
	deviceIPAddr := net.ParseIP(deviceIP)
	if deviceIPAddr == nil {
		return &NICInfo{
			InterfaceName: "Unknown",
			InterfaceType: "Unknown",
			Found:         false,
		}
	}

	for _, nic := range d.nicCache {
		if isIPInSubnet(deviceIP, nic.IPAddress, nic.Netmask) {
			return nic
		}
	}

	return &NICInfo{
		InterfaceName: "Unknown",
		InterfaceType: "Unknown",
		Found:         false,
	}
}

// Helper functions

func normalizeMAC(mac string) string {
	// Remove common separators and convert to uppercase
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	return strings.ToUpper(mac)
}

func isIPInSubnet(ip, nicIP, netmask string) bool {
	// Parse IP addresses
	deviceIP := net.ParseIP(ip)
	interfaceIP := net.ParseIP(nicIP)
	mask := net.ParseIP(netmask)

	if deviceIP == nil || interfaceIP == nil || mask == nil {
		return false
	}

	// Convert mask to IPMask
	ipMask := net.IPMask(mask.To4())
	if ipMask == nil {
		return false
	}

	// Create network from interface IP and mask
	network := &net.IPNet{
		IP:   interfaceIP.Mask(ipMask),
		Mask: ipMask,
	}

	// Check if device IP is in this network
	return network.Contains(deviceIP)
}

func classifyInterface(name string) string {
	nameLower := strings.ToLower(name)

	// Wireless indicators
	if strings.Contains(nameLower, "wi-fi") || strings.Contains(nameLower, "wifi") ||
		strings.Contains(nameLower, "wireless") || strings.Contains(nameLower, "wlan") {
		return "WIFI"
	}

	// Ethernet indicators
	if strings.Contains(nameLower, "ethernet") || strings.Contains(nameLower, "eth") ||
		strings.Contains(nameLower, "local area connection") {
		return "LAN"
	}

	// Virtual indicators
	if strings.Contains(nameLower, "virtual") || strings.Contains(nameLower, "veth") ||
		strings.Contains(nameLower, "vmware") || strings.Contains(nameLower, "hyper-v") ||
		strings.Contains(nameLower, "virtualbox") {
		return "VIRTUAL"
	}

	// Bridge indicators
	if strings.Contains(nameLower, "bridge") || strings.Contains(nameLower, "br-") {
		return "BRIDGE"
	}

	return "LAN" // Default to LAN
}

func isWirelessInterface(name string) bool {
	nameLower := strings.ToLower(name)
	return strings.Contains(nameLower, "wi-fi") || strings.Contains(nameLower, "wifi") ||
		strings.Contains(nameLower, "wireless") || strings.Contains(nameLower, "wlan")
}
