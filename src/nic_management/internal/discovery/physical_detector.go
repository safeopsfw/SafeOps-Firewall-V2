// Package discovery provides network interface enumeration and discovery capabilities.
// This file implements the physical versus virtual network interface detector that
// distinguishes between real hardware network adapters and software-based virtual adapters
// created by virtualization platforms, containers, VPNs, and network bridges.
package discovery

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Virtual Pattern Definitions
// =============================================================================

// VirtualPatterns contains known patterns that indicate virtual adapters.
type VirtualPatterns struct {
	// DriverNames are virtual driver name patterns.
	DriverNames []string `json:"driver_names" yaml:"driver_names"`
	// InterfaceNames are virtual interface name patterns.
	InterfaceNames []string `json:"interface_names" yaml:"interface_names"`
	// MACPrefixes are virtual adapter MAC address prefixes (vendor OUI).
	MACPrefixes []string `json:"mac_prefixes" yaml:"mac_prefixes"`
}

// DefaultVirtualPatterns returns the default virtual adapter patterns.
func DefaultVirtualPatterns() *VirtualPatterns {
	return &VirtualPatterns{
		DriverNames: []string{
			// Windows virtual drivers
			"hyper-v virtual ethernet adapter",
			"vmware virtual ethernet adapter",
			"virtualbox host-only ethernet adapter",
			"microsoft km-test loopback adapter",
			"tap-windows adapter",
			"openvpn virtual ethernet adapter",
			"microsoft wi-fi direct virtual adapter",
			"microsoft hosted network virtual adapter",
			"wsl adapter",
			"npf loopback adapter",
			// Linux virtual drivers
			"veth",
			"bridge",
			"tun",
			"tap",
			"dummy",
			"vxlan",
			"ipvlan",
			"macvlan",
		},
		InterfaceNames: []string{
			// Docker/Container
			"veth",
			"docker",
			"br-",
			"cni",
			"flannel",
			"calico",
			"weave",
			// VMware
			"vmnet",
			"vmxnet",
			// VirtualBox
			"vboxnet",
			// Hyper-V
			"vethernet",
			"vswitch",
			// TAP/TUN
			"tap",
			"tun",
			// Linux bridges/virtual
			"virbr",
			"vnet",
			"dummy",
			"lo",
			"loopback",
			// VPN
			"vpn",
			"ppp",
			"pptp",
			"l2tp",
			"ipsec",
			"wg", // WireGuard
			// WSL
			"wsl",
			// Others
			"vlan",
			"bond",
			"team",
		},
		MACPrefixes: []string{
			// VMware
			"00:50:56",
			"00:0c:29",
			"00:05:69",
			// VirtualBox
			"08:00:27",
			// Hyper-V
			"00:15:5d",
			// Microsoft Virtual
			"00:ff:00",
			// QEMU/KVM
			"52:54:00",
			// Xen
			"00:16:3e",
			// Parallels
			"00:1c:42",
			// Docker (locally administered)
			"02:42:",
		},
	}
}

// =============================================================================
// Detector Configuration
// =============================================================================

// DetectorConfig holds configuration for detection behavior and rules.
type DetectorConfig struct {
	// EnableDriverAnalysis checks driver names for virtual indicators (default: true).
	EnableDriverAnalysis bool `json:"enable_driver_analysis" yaml:"enable_driver_analysis"`
	// EnablePCIBusCheck checks for PCI bus presence (default: true).
	EnablePCIBusCheck bool `json:"enable_pci_bus_check" yaml:"enable_pci_bus_check"`
	// EnableNamePatternCheck checks interface names for virtual patterns (default: true).
	EnableNamePatternCheck bool `json:"enable_name_pattern_check" yaml:"enable_name_pattern_check"`
	// EnableHardwareCapabilityCheck queries hardware capabilities (default: true).
	EnableHardwareCapabilityCheck bool `json:"enable_hardware_capability_check" yaml:"enable_hardware_capability_check"`
	// EnableMACPrefixCheck checks MAC address vendor prefix (default: true).
	EnableMACPrefixCheck bool `json:"enable_mac_prefix_check" yaml:"enable_mac_prefix_check"`
	// TreatWiFiAsPhysical considers WiFi adapters as physical (default: true).
	TreatWiFiAsPhysical bool `json:"treat_wifi_as_physical" yaml:"treat_wifi_as_physical"`
	// CustomVirtualPatterns are user-defined virtual adapter patterns.
	CustomVirtualPatterns []string `json:"custom_virtual_patterns" yaml:"custom_virtual_patterns"`
}

// DefaultDetectorConfig returns a configuration with sensible defaults.
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		EnableDriverAnalysis:          true,
		EnablePCIBusCheck:             true,
		EnableNamePatternCheck:        true,
		EnableHardwareCapabilityCheck: true,
		EnableMACPrefixCheck:          true,
		TreatWiFiAsPhysical:           true,
		CustomVirtualPatterns:         []string{},
	}
}

// =============================================================================
// Physical Detector Structure
// =============================================================================

// PhysicalDetector is the physical vs virtual interface detection engine.
type PhysicalDetector struct {
	config          *DetectorConfig
	virtualPatterns *VirtualPatterns
	patternsMu      sync.RWMutex
}

// =============================================================================
// Constructor
// =============================================================================

// NewPhysicalDetector creates a new physical detector instance.
func NewPhysicalDetector(config *DetectorConfig) *PhysicalDetector {
	if config == nil {
		config = DefaultDetectorConfig()
	}

	patterns := DefaultVirtualPatterns()

	// Merge custom virtual patterns from config.
	if len(config.CustomVirtualPatterns) > 0 {
		patterns.InterfaceNames = append(patterns.InterfaceNames, config.CustomVirtualPatterns...)
	}

	return &PhysicalDetector{
		config:          config,
		virtualPatterns: patterns,
	}
}

// =============================================================================
// Main Detection Method
// =============================================================================

// IsPhysical determines if an interface is physical hardware or virtual.
// Returns true if physical, false if virtual.
func (d *PhysicalDetector) IsPhysical(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("interface is nil")
	}

	// Check 1: Loopback is always virtual.
	if d.isLoopback(iface) {
		return false, nil
	}

	// Check 2: If already marked as virtual, trust that.
	if iface.IsVirtual {
		return false, nil
	}

	// Check 3: WiFi handling - if configured, treat WiFi as physical.
	if d.config.TreatWiFiAsPhysical && d.isWiFiAdapter(iface) {
		return true, nil
	}

	// Check 4: Name pattern check.
	if d.config.EnableNamePatternCheck {
		if d.matchesVirtualNamePattern(iface) {
			return false, nil
		}
	}

	// Check 5: MAC address prefix check.
	if d.config.EnableMACPrefixCheck {
		if d.hasVirtualMACPrefix(iface) {
			return false, nil
		}
	}

	// Check 6: Driver analysis (platform-specific).
	if d.config.EnableDriverAnalysis {
		isVirtualDriver, err := d.hasVirtualDriver(ctx, iface)
		if err == nil && isVirtualDriver {
			return false, nil
		}
	}

	// Check 7: PCI bus check (platform-specific).
	if d.config.EnablePCIBusCheck {
		hasPCI, err := d.hasPCIBusAddress(ctx, iface)
		if err == nil {
			if !hasPCI {
				// No PCI bus address suggests virtual.
				// But don't make this definitive - some physical adapters may not report PCI.
			} else {
				// Has PCI bus address - strong indicator of physical.
				return true, nil
			}
		}
	}

	// Check 8: Hardware capability check.
	if d.config.EnableHardwareCapabilityCheck {
		hasHWCaps, err := d.hasPhysicalHardwareCapabilities(ctx, iface)
		if err == nil && hasHWCaps {
			return true, nil
		}
	}

	// Default: If no virtual indicators found, assume physical.
	// This is a safe default because most real adapters won't match virtual patterns.
	return true, nil
}

// =============================================================================
// Loopback Detection
// =============================================================================

// isLoopback detects loopback interfaces.
func (d *PhysicalDetector) isLoopback(iface *types.NetworkInterface) bool {
	if iface == nil {
		return false
	}

	// Check interface type.
	if iface.Type == types.InterfaceTypeLOOPBACK {
		return true
	}

	// Check interface name.
	nameLower := strings.ToLower(iface.Name)
	if nameLower == "lo" || nameLower == "loopback" ||
		strings.Contains(nameLower, "loopback") {
		return true
	}

	// Check IP address.
	if strings.HasPrefix(iface.IPAddress, "127.") {
		return true
	}
	if iface.IPAddress == "::1" || iface.IPv6Address == "::1" {
		return true
	}

	return false
}

// =============================================================================
// Name Pattern Analysis
// =============================================================================

// matchesVirtualNamePattern checks interface name against virtual patterns.
func (d *PhysicalDetector) matchesVirtualNamePattern(iface *types.NetworkInterface) bool {
	if iface == nil {
		return false
	}

	d.patternsMu.RLock()
	patterns := d.virtualPatterns.InterfaceNames
	d.patternsMu.RUnlock()

	nameLower := strings.ToLower(iface.Name)
	descLower := strings.ToLower(iface.Description)
	aliasLower := strings.ToLower(iface.Alias)

	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern)

		// Check name matches.
		if nameLower == patternLower ||
			strings.HasPrefix(nameLower, patternLower) ||
			strings.Contains(nameLower, patternLower) {
			return true
		}

		// Check description matches.
		if descLower != "" && strings.Contains(descLower, patternLower) {
			return true
		}

		// Check alias matches.
		if aliasLower != "" &&
			(aliasLower == patternLower ||
				strings.HasPrefix(aliasLower, patternLower) ||
				strings.Contains(aliasLower, patternLower)) {
			return true
		}
	}

	return false
}

// =============================================================================
// Driver Analysis
// =============================================================================

// hasVirtualDriver checks if the driver indicates a virtual adapter.
func (d *PhysicalDetector) hasVirtualDriver(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("interface is nil")
	}

	// Check driver name from interface struct first.
	driverName := strings.ToLower(iface.DriverName)
	if driverName != "" {
		d.patternsMu.RLock()
		patterns := d.virtualPatterns.DriverNames
		d.patternsMu.RUnlock()

		for _, pattern := range patterns {
			if strings.Contains(driverName, strings.ToLower(pattern)) {
				return true, nil
			}
		}
	}

	// Also check description for driver-like names.
	descLower := strings.ToLower(iface.Description)
	if descLower != "" {
		d.patternsMu.RLock()
		patterns := d.virtualPatterns.DriverNames
		d.patternsMu.RUnlock()

		for _, pattern := range patterns {
			if strings.Contains(descLower, strings.ToLower(pattern)) {
				return true, nil
			}
		}
	}

	return false, nil
}

// =============================================================================
// MAC Address Analysis
// =============================================================================

// hasVirtualMACPrefix checks if MAC address has a virtual vendor prefix.
func (d *PhysicalDetector) hasVirtualMACPrefix(iface *types.NetworkInterface) bool {
	if iface == nil || iface.MACAddress == "" {
		return false
	}

	macUpper := strings.ToUpper(iface.MACAddress)

	// Handle different MAC address formats.
	// Convert to uppercase format with colons: "00:50:56:..."
	macUpper = strings.ReplaceAll(macUpper, "-", ":")

	d.patternsMu.RLock()
	prefixes := d.virtualPatterns.MACPrefixes
	d.patternsMu.RUnlock()

	for _, prefix := range prefixes {
		prefixUpper := strings.ToUpper(prefix)
		if strings.HasPrefix(macUpper, prefixUpper) {
			return true
		}
	}

	// Check for locally administered bit (bit 1 of first octet).
	// Many virtual adapters use locally administered MAC addresses.
	if len(macUpper) >= 2 {
		firstOctet := macUpper[0:2]
		var firstByte uint8
		if _, err := fmt.Sscanf(firstOctet, "%02X", &firstByte); err == nil {
			// Bit 1 set indicates locally administered address.
			if firstByte&0x02 != 0 {
				// This is commonly used by virtual adapters, but not definitive.
				// Some physical adapters may also use locally administered addresses.
				// We'll use this as a weak signal only.
			}
		}
	}

	return false
}

// =============================================================================
// PCI Bus Enumeration
// =============================================================================

// hasPCIBusAddress checks if the interface has a PCI bus address.
func (d *PhysicalDetector) hasPCIBusAddress(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("interface is nil")
	}

	// Check if PCI address is already set in the interface.
	if iface.PCIAddress != "" {
		return true, nil
	}

	// Platform-specific detection would be done here.
	// For now, rely on the PCIAddress field being set by the enumerator.
	switch runtime.GOOS {
	case "windows":
		return d.hasPCIBusAddressWindows(ctx, iface)
	case "linux":
		return d.hasPCIBusAddressLinux(ctx, iface)
	default:
		return false, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// hasPCIBusAddressWindows checks for PCI bus on Windows.
func (d *PhysicalDetector) hasPCIBusAddressWindows(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	// On Windows, physical adapters typically have PCI location info.
	// This would query WMI for PNPDeviceID.
	// For now, return true if we have HardwareID (suggests real hardware).
	if iface.HardwareID != "" {
		// Check if it's a PCI device.
		hwIDLower := strings.ToLower(iface.HardwareID)
		if strings.Contains(hwIDLower, "pci\\") ||
			strings.Contains(hwIDLower, "pci&") {
			return true, nil
		}
		// USB NICs are also physical.
		if strings.Contains(hwIDLower, "usb\\") ||
			strings.Contains(hwIDLower, "usb&") {
			return true, nil
		}
	}

	return false, nil
}

// hasPCIBusAddressLinux checks for PCI bus on Linux.
func (d *PhysicalDetector) hasPCIBusAddressLinux(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	// On Linux, check /sys/class/net/{interface}/device for PCI symlink.
	// For now, this is a placeholder - would read sysfs in real implementation.
	if iface.PCIAddress != "" {
		return true, nil
	}
	return false, nil
}

// =============================================================================
// Hardware Capability Analysis
// =============================================================================

// hasPhysicalHardwareCapabilities checks for hardware offload features.
func (d *PhysicalDetector) hasPhysicalHardwareCapabilities(ctx context.Context, iface *types.NetworkInterface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("interface is nil")
	}

	// Check various indicators of physical hardware.

	// 1. Speed > 0 usually indicates real hardware.
	if iface.SpeedMbps > 0 {
		// Very high speeds (10Gbps+) are almost certainly physical.
		if iface.SpeedMbps >= 10000 {
			return true, nil
		}
	}

	// 2. Physical adapters usually support jumbo frames.
	if iface.MTU > 1500 {
		return true, nil
	}

	// 3. If vendor/device info is present, likely physical.
	if iface.VendorName != "" || iface.DeviceModel != "" {
		return true, nil
	}

	// 4. Physical adapters have firmware versions.
	if iface.FirmwareVersion != "" {
		return true, nil
	}

	return false, nil
}

// =============================================================================
// WiFi Adapter Detection
// =============================================================================

// isWiFiAdapter detects if the interface is a WiFi adapter.
func (d *PhysicalDetector) isWiFiAdapter(iface *types.NetworkInterface) bool {
	if iface == nil {
		return false
	}

	// Check if already marked as wireless.
	if iface.IsWireless {
		return true
	}

	// Check interface type.
	if iface.Type == types.InterfaceTypeWIFI {
		return true
	}

	// Check for WiFiInfo.
	if iface.WiFiInfo != nil {
		return true
	}

	// Check name patterns.
	nameLower := strings.ToLower(iface.Name)
	wifiPatterns := []string{"wlan", "wifi", "wlp", "wlx", "ath", "iwl", "wireless"}
	for _, pattern := range wifiPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Check description.
	descLower := strings.ToLower(iface.Description)
	for _, pattern := range wifiPatterns {
		if strings.Contains(descLower, pattern) {
			return true
		}
	}

	return false
}

// =============================================================================
// Batch Detection
// =============================================================================

// DetectPhysicalInterfaces detects physical/virtual status for multiple interfaces.
func (d *PhysicalDetector) DetectPhysicalInterfaces(ctx context.Context, interfaces []*types.NetworkInterface) error {
	var firstErr error

	for _, iface := range interfaces {
		isPhysical, err := d.IsPhysical(ctx, iface)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// Update the IsVirtual flag.
		iface.IsVirtual = !isPhysical
	}

	return firstErr
}

// =============================================================================
// Pattern Management
// =============================================================================

// AddVirtualPattern adds a custom virtual pattern.
func (d *PhysicalDetector) AddVirtualPattern(pattern string) {
	d.patternsMu.Lock()
	defer d.patternsMu.Unlock()
	d.virtualPatterns.InterfaceNames = append(d.virtualPatterns.InterfaceNames, pattern)
}

// RemoveVirtualPattern removes a virtual pattern.
func (d *PhysicalDetector) RemoveVirtualPattern(pattern string) {
	d.patternsMu.Lock()
	defer d.patternsMu.Unlock()

	patternLower := strings.ToLower(pattern)
	filtered := make([]string, 0, len(d.virtualPatterns.InterfaceNames))
	for _, p := range d.virtualPatterns.InterfaceNames {
		if strings.ToLower(p) != patternLower {
			filtered = append(filtered, p)
		}
	}
	d.virtualPatterns.InterfaceNames = filtered
}

// GetVirtualPatterns returns a copy of the current virtual patterns.
func (d *PhysicalDetector) GetVirtualPatterns() *VirtualPatterns {
	d.patternsMu.RLock()
	defer d.patternsMu.RUnlock()

	// Create deep copy.
	copy := &VirtualPatterns{
		DriverNames:    make([]string, len(d.virtualPatterns.DriverNames)),
		InterfaceNames: make([]string, len(d.virtualPatterns.InterfaceNames)),
		MACPrefixes:    make([]string, len(d.virtualPatterns.MACPrefixes)),
	}
	for i, v := range d.virtualPatterns.DriverNames {
		copy.DriverNames[i] = v
	}
	for i, v := range d.virtualPatterns.InterfaceNames {
		copy.InterfaceNames[i] = v
	}
	for i, v := range d.virtualPatterns.MACPrefixes {
		copy.MACPrefixes[i] = v
	}

	return copy
}

// AddDriverPattern adds a custom virtual driver pattern.
func (d *PhysicalDetector) AddDriverPattern(pattern string) {
	d.patternsMu.Lock()
	defer d.patternsMu.Unlock()
	d.virtualPatterns.DriverNames = append(d.virtualPatterns.DriverNames, pattern)
}

// AddMACPrefix adds a custom virtual MAC prefix.
func (d *PhysicalDetector) AddMACPrefix(prefix string) {
	d.patternsMu.Lock()
	defer d.patternsMu.Unlock()
	d.virtualPatterns.MACPrefixes = append(d.virtualPatterns.MACPrefixes, prefix)
}

// =============================================================================
// Configuration Access
// =============================================================================

// GetConfig returns the detector configuration.
func (d *PhysicalDetector) GetConfig() *DetectorConfig {
	return d.config
}
