package hotspot

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// DeviceTracker tracks devices connected to Windows hotspot
type DeviceTracker struct {
	devices   map[string]*models.HotspotDevice
	mu        sync.RWMutex
	macVendor *MACVendorLookup
}

// NewDeviceTracker creates a new device tracker
func NewDeviceTracker() *DeviceTracker {
	return &DeviceTracker{
		devices:   make(map[string]*models.HotspotDevice),
		macVendor: NewMACVendorLookup(),
	}
}

// TrackDevice tracks a device by IP and MAC
func (t *DeviceTracker) TrackDevice(ip, mac string) *models.HotspotDevice {
	t.mu.Lock()
	defer t.mu.Unlock()

	device, exists := t.devices[ip]
	if !exists {
		vendor := t.macVendor.Lookup(mac)
		deviceType := guessDeviceType(vendor)

		device = &models.HotspotDevice{
			IP:         ip,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
		}

		t.devices[ip] = device
	} else {
		device.LastSeen = time.Now()
	}

	return device
}

// GetDeviceInfo retrieves device information
func (t *DeviceTracker) GetDeviceInfo(ip string) *models.HotspotDevice {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.devices[ip]
}

// UpdateStats updates traffic statistics for a device
func (t *DeviceTracker) UpdateStats(ip string, bytes int, isSent bool, iface string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	device, exists := t.devices[ip]
	if !exists {
		return
	}

	device.LastSeen = time.Now()
	if iface != "" {
		device.Interface = iface
	}

	if isSent {
		device.BytesSent += int64(bytes)
		device.PacketsSent++
	} else {
		device.BytesRecv += int64(bytes)
		device.PacketsRecv++
	}
}

// IsHotspotIP checks if an IP is in the hotspot subnet
func (t *DeviceTracker) IsHotspotIP(ip string) bool {
	// Windows Mobile Hotspot default subnet: 192.168.137.0/24
	_, hotspotNet, _ := net.ParseCIDR("192.168.137.0/24")
	parsedIP := net.ParseIP(ip)

	if parsedIP == nil || hotspotNet == nil {
		return false
	}

	return hotspotNet.Contains(parsedIP)
}

// GetAllDevices returns all tracked devices
func (t *DeviceTracker) GetAllDevices() []*models.HotspotDevice {
	t.mu.RLock()
	defer t.mu.RUnlock()

	devices := make([]*models.HotspotDevice, 0, len(t.devices))
	for _, device := range t.devices {
		devices = append(devices, device)
	}

	return devices
}

// guessDeviceType attempts to guess device type from vendor
func guessDeviceType(vendor string) string {
	vendorL := strings.ToLower(vendor)

	// Mobile vendors
	mobileVendors := []string{
		"apple", "samsung", "huawei", "xiaomi", "oneplus",
		"oppo", "vivo", "realme", "motorola", "lg", "sony",
		"google", "nokia", "htc",
	}

	for _, mv := range mobileVendors {
		if strings.Contains(vendorL, mv) {
			return "mobile"
		}
	}

	// Laptop/PC vendors
	laptopVendors := []string{
		"dell", "hp", "lenovo", "asus", "acer",
		"msi", "toshiba", "fujitsu", "microsoft",
	}

	for _, lv := range laptopVendors {
		if strings.Contains(vendorL, lv) {
			return "laptop"
		}
	}

	// IoT/Smart devices
	if strings.Contains(vendorL, "amazon") || strings.Contains(vendorL, "alexa") {
		return "iot"
	}

	return "unknown"
}

// MACVendorLookup provides MAC address vendor lookup
type MACVendorLookup struct {
	ouiMap map[string]string
}

// NewMACVendorLookup creates a new MAC vendor lookup
func NewMACVendorLookup() *MACVendorLookup {
	return &MACVendorLookup{
		ouiMap: getOUIDatabase(),
	}
}

// Lookup returns vendor for a MAC address
func (m *MACVendorLookup) Lookup(mac string) string {
	// Extract OUI (first 3 bytes)
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	mac = strings.ReplaceAll(mac, "-", "")

	if len(mac) < 6 {
		return "Unknown"
	}

	oui := mac[:6]

	// Try 6-char lookup
	if vendor, ok := m.ouiMap[oui]; ok {
		return vendor
	}

	// Try 8-char lookup (for MA-M and MA-S)
	if len(mac) >= 8 {
		oui8 := mac[:8]
		if vendor, ok := m.ouiMap[oui8]; ok {
			return vendor
		}
	}

	return "Unknown"
}

// getOUIDatabase returns embedded OUI database (top vendors)
func getOUIDatabase() map[string]string {
	return map[string]string{
		// Apple
		"001CB3": "Apple",
		"286ABA": "Apple",
		"ACDE48": "Apple",
		"F0F61C": "Apple",
		"8866F4": "Apple",
		"5CF7E6": "Apple",
		"38C986": "Apple",
		"B8E856": "Apple",

		// Samsung
		"A477B3": "Samsung",
		"E850B8": "Samsung",
		"08D4C5": "Samsung",
		"5C0947": "Samsung",
		"DC71B3": "Samsung",
		"B4F0AB": "Samsung",

		// Google
		"001A11": "Google",
		"F88FCA": "Google",
		"3C5A37": "Google",
		"F4F5E8": "Google",

		// Huawei
		"00E0FC": "Huawei",
		"84A134": "Huawei",
		"D0C637": "Huawei",
		"F8E81A": "Huawei",

		// Xiaomi
		"34CE00": "Xiaomi",
		"64B473": "Xiaomi",
		"F4F524": "Xiaomi",

		// Dell
		"001C23": "Dell",
		"B8CA3A": "Dell",
		"D4AE52": "Dell",

		// HP
		"009C02": "HP",
		"708BCD": "HP",
		"D48564": "HP",

		// Lenovo
		"00216A": "Lenovo",
		"5CF938": "Lenovo",

		// Asus
		"107B44": "Asus",
		"1CBF2E": "Asus",
		"D850E6": "Asus",

		// Microsoft
		"00155D": "Microsoft",
		"0050F2": "Microsoft",
		"64006A": "Microsoft",

		// Amazon
		"F0D2F1":   "Amazon",
		"FC A6 67": "Amazon",

		// Intel
		"001B77": "Intel",
		"A45D36": "Intel",

		// TP-Link
		"F4F2A3": "TP-Link",
		"C006C3": "TP-Link",

		// D-Link
		"001B11": "D-Link",
		"C0A0BB": "D-Link",

		// Sony
		"001EA9": "Sony",
		"8C7712": "Sony",

		// LG
		"E8039A": "LG",
		"609217": "LG",

		// OnePlus
		"AC37B4": "OnePlus",
		"806F74": "OnePlus",
	}
}
