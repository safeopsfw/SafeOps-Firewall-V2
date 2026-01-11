// Package discovery provides network interface enumeration and discovery capabilities.
// This file implements the intelligent network interface classification engine that
// automatically categorizes discovered network interfaces as WAN, LAN, WiFi, or Virtual
// based on multiple heuristics including gateway presence, IP address ranges, routing tables,
// interface naming conventions, and user-defined configuration overrides.
package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"safeops/nic_management/pkg/types"
)

// =============================================================================
// Classification Indicators
// =============================================================================

// WANIndicators defines heuristics for WAN interface detection.
type WANIndicators struct {
	// RequireDefaultRoute requires WAN to have a default gateway (0.0.0.0/0 route).
	RequireDefaultRoute bool `json:"require_default_route" yaml:"require_default_route"`
	// RequirePublicIP requires WAN to have a public (non-RFC1918) IP address.
	RequirePublicIP bool `json:"require_public_ip" yaml:"require_public_ip"`
	// RequireInternetConnectivity requires WAN to pass an internet reachability test.
	RequireInternetConnectivity bool `json:"require_internet_connectivity" yaml:"require_internet_connectivity"`
	// NamePatterns are interface name patterns that indicate WAN (e.g., "eth0", "wan", "ppp", "wwan").
	NamePatterns []string `json:"name_patterns" yaml:"name_patterns"`
	// ExcludePrivateIPRanges excludes interfaces with private IPs from WAN classification.
	ExcludePrivateIPRanges bool `json:"exclude_private_ip_ranges" yaml:"exclude_private_ip_ranges"`
}

// LANIndicators defines heuristics for LAN interface detection.
type LANIndicators struct {
	// RequirePrivateIP requires LAN to have a private (RFC1918) IP address.
	RequirePrivateIP bool `json:"require_private_ip" yaml:"require_private_ip"`
	// RequireNoDefaultRoute requires LAN to not have a default gateway.
	RequireNoDefaultRoute bool `json:"require_no_default_route" yaml:"require_no_default_route"`
	// NamePatterns are interface name patterns that indicate LAN (e.g., "eth1", "lan", "br0").
	NamePatterns []string `json:"name_patterns" yaml:"name_patterns"`
	// DHCPServerEnabled indicates LAN if DHCP server is enabled on the interface.
	DHCPServerEnabled bool `json:"dhcp_server_enabled" yaml:"dhcp_server_enabled"`
}

// WiFiIndicators defines heuristics for WiFi interface detection.
type WiFiIndicators struct {
	// NamePatterns are WiFi interface name patterns (e.g., "wlan", "wifi", "ath", "wlp").
	NamePatterns []string `json:"name_patterns" yaml:"name_patterns"`
	// RequireWirelessCapability requires 802.11 wireless support.
	RequireWirelessCapability bool `json:"require_wireless_capability" yaml:"require_wireless_capability"`
}

// VirtualIndicators defines heuristics for virtual interface detection.
type VirtualIndicators struct {
	// NamePatterns are virtual interface patterns (e.g., "veth", "docker", "vmnet", "vbox", "tap", "tun").
	NamePatterns []string `json:"name_patterns" yaml:"name_patterns"`
	// DriverPatterns are virtual driver patterns (e.g., "Hyper-V", "VMware", "VirtualBox").
	DriverPatterns []string `json:"driver_patterns" yaml:"driver_patterns"`
}

// =============================================================================
// Classifier Configuration
// =============================================================================

// ClassifierConfig holds configuration for interface classification behavior and rules.
type ClassifierConfig struct {
	// Mode is the classification mode: "automatic", "manual", or "hybrid".
	Mode string `json:"mode" yaml:"mode"`
	// WANIndicators are heuristics for WAN detection.
	WANIndicators *WANIndicators `json:"wan_indicators" yaml:"wan_indicators"`
	// LANIndicators are heuristics for LAN detection.
	LANIndicators *LANIndicators `json:"lan_indicators" yaml:"lan_indicators"`
	// WiFiIndicators are heuristics for WiFi detection.
	WiFiIndicators *WiFiIndicators `json:"wifi_indicators" yaml:"wifi_indicators"`
	// VirtualIndicators are heuristics for virtual interface detection.
	VirtualIndicators *VirtualIndicators `json:"virtual_indicators" yaml:"virtual_indicators"`
	// ManualAssignments are manual interface type assignments (name → "WAN"/"LAN"/"WIFI").
	ManualAssignments map[string]string `json:"manual_assignments" yaml:"manual_assignments"`
}

// DefaultClassifierConfig returns a configuration with sensible defaults.
func DefaultClassifierConfig() *ClassifierConfig {
	return &ClassifierConfig{
		Mode: "automatic",
		WANIndicators: &WANIndicators{
			RequireDefaultRoute:         true,
			RequirePublicIP:             false,
			RequireInternetConnectivity: false,
			ExcludePrivateIPRanges:      false,
			NamePatterns: []string{
				"wan*", "ppp*", "wwan*", "lte*", "4g*", "5g*",
				"Ethernet", "eth0", "enp*s*f0",
			},
		},
		LANIndicators: &LANIndicators{
			RequirePrivateIP:      true,
			RequireNoDefaultRoute: false,
			DHCPServerEnabled:     false,
			NamePatterns: []string{
				"lan*", "br*", "bridge*", "eth1", "enp*s*f1",
			},
		},
		WiFiIndicators: &WiFiIndicators{
			RequireWirelessCapability: true,
			NamePatterns: []string{
				"wlan*", "wifi*", "wlp*", "wlx*", "ath*", "iwl*",
				"Wi-Fi*", "Wireless*", "WLAN*",
			},
		},
		VirtualIndicators: &VirtualIndicators{
			NamePatterns: []string{
				"veth*", "docker*", "br-*", "vmnet*", "vbox*",
				"tap*", "tun*", "virbr*", "vnet*", "Hyper-V*",
				"vEthernet*", "WSL*", "VPN*",
			},
			DriverPatterns: []string{
				"hyper-v", "vmware", "virtualbox", "virtual",
				"docker", "wsl", "vpn", "tunnel",
			},
		},
		ManualAssignments: make(map[string]string),
	}
}

// =============================================================================
// Classifier Structure
// =============================================================================

// Classifier is the network interface classification engine.
type Classifier struct {
	config          *ClassifierConfig
	manualOverrides map[string]types.InterfaceType
	overridesMu     sync.RWMutex

	// Platform-specific routing table accessor.
	routingTableFn func() ([]RouteInfo, error)
}

// RouteInfo represents a routing table entry for classification purposes.
type RouteInfo struct {
	Destination    string
	PrefixLength   uint8
	Gateway        string
	InterfaceIndex uint32
	InterfaceName  string
	Metric         uint32
}

// =============================================================================
// Constructor
// =============================================================================

// NewClassifier creates a new classifier instance.
func NewClassifier(config *ClassifierConfig) *Classifier {
	if config == nil {
		config = DefaultClassifierConfig()
	}

	c := &Classifier{
		config:          config,
		manualOverrides: make(map[string]types.InterfaceType),
	}

	// Load manual assignments from config.
	if config.ManualAssignments != nil {
		for name, typeStr := range config.ManualAssignments {
			if ifaceType := parseInterfaceType(typeStr); ifaceType != types.InterfaceTypeUNKNOWN {
				c.manualOverrides[name] = ifaceType
			}
		}
	}

	return c
}

// parseInterfaceType converts a string to InterfaceType.
func parseInterfaceType(s string) types.InterfaceType {
	switch strings.ToUpper(s) {
	case "WAN":
		return types.InterfaceTypeWAN
	case "LAN":
		return types.InterfaceTypeLAN
	case "WIFI", "WIRELESS":
		return types.InterfaceTypeWIFI
	case "VIRTUAL":
		return types.InterfaceTypeVIRTUAL
	case "LOOPBACK":
		return types.InterfaceTypeLOOPBACK
	case "BRIDGE":
		return types.InterfaceTypeBRIDGE
	default:
		return types.InterfaceTypeUNKNOWN
	}
}

// SetRoutingTableFunc sets the platform-specific routing table accessor.
func (c *Classifier) SetRoutingTableFunc(fn func() ([]RouteInfo, error)) {
	c.routingTableFn = fn
}

// =============================================================================
// Main Classification Methods
// =============================================================================

// ClassifyInterface classifies a single network interface.
func (c *Classifier) ClassifyInterface(ctx context.Context, iface *types.NetworkInterface) (types.InterfaceType, error) {
	if iface == nil {
		return types.InterfaceTypeUNKNOWN, fmt.Errorf("interface is nil")
	}

	// Step 1: Check manual overrides first.
	if c.config.Mode != "automatic" {
		c.overridesMu.RLock()
		if override, ok := c.manualOverrides[iface.Name]; ok {
			c.overridesMu.RUnlock()
			iface.Type = override
			return override, nil
		}
		// Also check by alias.
		if iface.Alias != "" {
			if override, ok := c.manualOverrides[iface.Alias]; ok {
				c.overridesMu.RUnlock()
				iface.Type = override
				return override, nil
			}
		}
		c.overridesMu.RUnlock()
	}

	// If mode is "manual", require explicit assignment.
	if c.config.Mode == "manual" {
		return types.InterfaceTypeUNKNOWN, fmt.Errorf("no manual assignment for interface %s", iface.Name)
	}

	// Step 2: Check if already classified as loopback.
	if iface.Type == types.InterfaceTypeLOOPBACK {
		return types.InterfaceTypeLOOPBACK, nil
	}

	// Step 3: Check virtual indicators.
	if c.isVirtual(ctx, iface) {
		iface.Type = types.InterfaceTypeVIRTUAL
		iface.IsVirtual = true
		return types.InterfaceTypeVIRTUAL, nil
	}

	// Step 4: Check WiFi indicators.
	if c.isWiFi(ctx, iface) {
		iface.Type = types.InterfaceTypeWIFI
		iface.IsWireless = true
		// WiFi can still be WAN or LAN - check further.
		if c.isWAN(ctx, iface) {
			iface.Type = types.InterfaceTypeWAN
			return types.InterfaceTypeWAN, nil
		}
		return types.InterfaceTypeWIFI, nil
	}

	// Step 5: Check WAN indicators.
	if c.isWAN(ctx, iface) {
		iface.Type = types.InterfaceTypeWAN
		return types.InterfaceTypeWAN, nil
	}

	// Step 6: Check LAN indicators.
	if c.isLAN(ctx, iface) {
		iface.Type = types.InterfaceTypeLAN
		return types.InterfaceTypeLAN, nil
	}

	// Step 7: Default classification - LAN is the safe default.
	iface.Type = types.InterfaceTypeLAN
	return types.InterfaceTypeLAN, nil
}

// ClassifyInterfaces classifies multiple interfaces at once.
func (c *Classifier) ClassifyInterfaces(ctx context.Context, interfaces []*types.NetworkInterface) error {
	var firstErr error

	for _, iface := range interfaces {
		_, err := c.ClassifyInterface(ctx, iface)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// =============================================================================
// WAN Detection Logic
// =============================================================================

// isWAN determines if an interface is a WAN interface.
func (c *Classifier) isWAN(ctx context.Context, iface *types.NetworkInterface) bool {
	if c.config.WANIndicators == nil {
		return false
	}

	indicators := c.config.WANIndicators

	// Check for default route (primary WAN indicator).
	if indicators.RequireDefaultRoute {
		if !c.hasDefaultRoute(ctx, iface) {
			return false
		}
	}

	// Check for public IP.
	if indicators.RequirePublicIP {
		if !isPublicIP(iface.IPAddress) {
			return false
		}
	}

	// Exclude private IP ranges if configured.
	if indicators.ExcludePrivateIPRanges {
		if isPrivateIP(iface.IPAddress) {
			return false
		}
	}

	// Check internet connectivity.
	if indicators.RequireInternetConnectivity {
		if !c.testInternetConnectivity(ctx, iface) {
			return false
		}
	}

	// Check name patterns - if interface matches WAN patterns, it's a strong indicator.
	if len(indicators.NamePatterns) > 0 {
		if matchesPattern(iface.Name, indicators.NamePatterns) {
			return true
		}
		if iface.Alias != "" && matchesPattern(iface.Alias, indicators.NamePatterns) {
			return true
		}
	}

	// If interface has a default route and we get here, it's likely WAN.
	if c.hasDefaultRoute(ctx, iface) {
		return true
	}

	return false
}

// =============================================================================
// LAN Detection Logic
// =============================================================================

// isLAN determines if an interface is a LAN interface.
func (c *Classifier) isLAN(ctx context.Context, iface *types.NetworkInterface) bool {
	if c.config.LANIndicators == nil {
		return true // Default to LAN if no indicators.
	}

	indicators := c.config.LANIndicators

	// Check for private IP.
	if indicators.RequirePrivateIP {
		if !isPrivateIP(iface.IPAddress) {
			return false
		}
	}

	// Check for no default route.
	if indicators.RequireNoDefaultRoute {
		if c.hasDefaultRoute(ctx, iface) {
			return false
		}
	}

	// Check name patterns.
	if len(indicators.NamePatterns) > 0 {
		if matchesPattern(iface.Name, indicators.NamePatterns) {
			return true
		}
		if iface.Alias != "" && matchesPattern(iface.Alias, indicators.NamePatterns) {
			return true
		}
	}

	// Private IP is a strong LAN indicator.
	if isPrivateIP(iface.IPAddress) {
		return true
	}

	return false
}

// =============================================================================
// WiFi Detection Logic
// =============================================================================

// isWiFi determines if an interface is a WiFi interface.
func (c *Classifier) isWiFi(ctx context.Context, iface *types.NetworkInterface) bool {
	// Check if already marked as wireless.
	if iface.IsWireless {
		return true
	}

	if c.config.WiFiIndicators == nil {
		return false
	}

	indicators := c.config.WiFiIndicators

	// Check name patterns.
	if len(indicators.NamePatterns) > 0 {
		if matchesPattern(iface.Name, indicators.NamePatterns) {
			return true
		}
		if matchesPattern(iface.Description, indicators.NamePatterns) {
			return true
		}
		if iface.Alias != "" && matchesPattern(iface.Alias, indicators.NamePatterns) {
			return true
		}
	}

	// Check wireless capability via WiFiInfo.
	if indicators.RequireWirelessCapability && iface.WiFiInfo != nil {
		return true
	}

	return false
}

// =============================================================================
// Virtual Interface Detection Logic
// =============================================================================

// isVirtual determines if an interface is a virtual interface.
func (c *Classifier) isVirtual(ctx context.Context, iface *types.NetworkInterface) bool {
	// Check if already marked as virtual.
	if iface.IsVirtual {
		return true
	}

	if c.config.VirtualIndicators == nil {
		return false
	}

	indicators := c.config.VirtualIndicators

	// Check name patterns.
	if len(indicators.NamePatterns) > 0 {
		if matchesPattern(iface.Name, indicators.NamePatterns) {
			return true
		}
		if matchesPattern(iface.Description, indicators.NamePatterns) {
			return true
		}
		if iface.Alias != "" && matchesPattern(iface.Alias, indicators.NamePatterns) {
			return true
		}
	}

	// Check driver patterns.
	if len(indicators.DriverPatterns) > 0 {
		if matchesPattern(iface.DriverName, indicators.DriverPatterns) {
			return true
		}
		// Also check description for driver keywords.
		descLower := strings.ToLower(iface.Description)
		for _, pattern := range indicators.DriverPatterns {
			if strings.Contains(descLower, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

// =============================================================================
// Helper Functions - IP Address Classification
// =============================================================================

// isPublicIP checks if an IP address is publicly routable.
func isPublicIP(ipAddress string) bool {
	if ipAddress == "" {
		return false
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Check if in private or special ranges.
	privateRanges := []string{
		"10.0.0.0/8",      // Class A private
		"172.16.0.0/12",   // Class B private
		"192.168.0.0/16",  // Class C private
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved
		"100.64.0.0/10",   // Carrier-grade NAT
		"192.0.0.0/24",    // IETF Protocol Assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"192.88.99.0/24",  // 6to4 Relay Anycast
		"198.18.0.0/15",   // Benchmarking
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}

	return true
}

// isPrivateIP checks if an IP address is in RFC1918 private ranges.
func isPrivateIP(ipAddress string) bool {
	if ipAddress == "" {
		return false
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// IPv4 private ranges.
	privateRanges := []string{
		"10.0.0.0/8",     // Class A private
		"172.16.0.0/12",  // Class B private
		"192.168.0.0/16", // Class C private
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isLinkLocal checks if an IP address is link-local.
func isLinkLocal(ipAddress string) bool {
	if ipAddress == "" {
		return false
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// IPv4 link-local: 169.254.0.0/16
	_, linkLocal4, _ := net.ParseCIDR("169.254.0.0/16")
	if linkLocal4.Contains(ip) {
		return true
	}

	// IPv6 link-local: fe80::/10
	_, linkLocal6, _ := net.ParseCIDR("fe80::/10")
	if linkLocal6.Contains(ip) {
		return true
	}

	return false
}

// =============================================================================
// Helper Functions - Routing Table Queries
// =============================================================================

// hasDefaultRoute checks if an interface has a default gateway route.
func (c *Classifier) hasDefaultRoute(ctx context.Context, iface *types.NetworkInterface) bool {
	if c.routingTableFn == nil {
		// If no routing table function is set, check if gateway is set on interface.
		return iface.Gateway != ""
	}

	routes, err := c.routingTableFn()
	if err != nil {
		// Fallback to gateway field.
		return iface.Gateway != ""
	}

	// Look for 0.0.0.0/0 route for this interface.
	for _, route := range routes {
		if route.Destination == "0.0.0.0" && route.PrefixLength == 0 {
			// Match by interface name or gateway.
			if route.InterfaceName == iface.Name {
				return true
			}
			if route.Gateway == iface.Gateway && iface.Gateway != "" {
				return true
			}
		}
	}

	// Also consider interface having a gateway as having a default route.
	return iface.Gateway != ""
}

// GetGateway retrieves the gateway IP for an interface.
func (c *Classifier) GetGateway(ctx context.Context, iface *types.NetworkInterface) (string, error) {
	if iface.Gateway != "" {
		return iface.Gateway, nil
	}

	if c.routingTableFn == nil {
		return "", fmt.Errorf("no gateway configured for interface %s", iface.Name)
	}

	routes, err := c.routingTableFn()
	if err != nil {
		return "", fmt.Errorf("failed to get routing table: %w", err)
	}

	for _, route := range routes {
		if route.Destination == "0.0.0.0" && route.PrefixLength == 0 {
			if route.InterfaceName == iface.Name {
				return route.Gateway, nil
			}
		}
	}

	return "", fmt.Errorf("no default gateway for interface %s", iface.Name)
}

// =============================================================================
// Helper Functions - Connectivity Testing
// =============================================================================

// testInternetConnectivity tests if an interface has internet access.
// Note: This is a simplified implementation. Full implementation would bind to specific interface.
func (c *Classifier) testInternetConnectivity(ctx context.Context, iface *types.NetworkInterface) bool {
	// Try to establish a brief TCP connection to well-known DNS servers.
	targets := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}

	for _, target := range targets {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// =============================================================================
// Helper Functions - Name Pattern Matching
// =============================================================================

// matchesPattern checks if a name matches any of the given patterns.
// Supports simple wildcard matching with * (matches any characters).
func matchesPattern(name string, patterns []string) bool {
	if name == "" {
		return false
	}

	nameLower := strings.ToLower(name)

	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern)

		// Exact match.
		if nameLower == patternLower {
			return true
		}

		// Wildcard matching.
		if strings.Contains(patternLower, "*") {
			if matchWildcard(nameLower, patternLower) {
				return true
			}
		}

		// Prefix match (pattern without wildcard matches start of name).
		if strings.HasPrefix(nameLower, strings.TrimSuffix(patternLower, "*")) {
			return true
		}
	}

	return false
}

// matchWildcard performs simple wildcard matching.
// * matches zero or more characters.
func matchWildcard(name, pattern string) bool {
	// Simple implementation for common cases.
	if pattern == "*" {
		return true
	}

	// Pattern ends with *: prefix match.
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(name, prefix)
	}

	// Pattern starts with *: suffix match.
	if strings.HasPrefix(pattern, "*") && !strings.Contains(pattern[1:], "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(name, suffix)
	}

	// Pattern has * in middle: contains match.
	if idx := strings.Index(pattern, "*"); idx > 0 && idx < len(pattern)-1 {
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}

	return false
}

// =============================================================================
// Manual Override Management
// =============================================================================

// SetManualOverride sets a manual classification for an interface.
func (c *Classifier) SetManualOverride(interfaceName string, interfaceType types.InterfaceType) {
	c.overridesMu.Lock()
	defer c.overridesMu.Unlock()
	c.manualOverrides[interfaceName] = interfaceType
}

// RemoveManualOverride removes a manual classification override.
func (c *Classifier) RemoveManualOverride(interfaceName string) {
	c.overridesMu.Lock()
	defer c.overridesMu.Unlock()
	delete(c.manualOverrides, interfaceName)
}

// GetManualOverrides returns a copy of all manual overrides.
func (c *Classifier) GetManualOverrides() map[string]types.InterfaceType {
	c.overridesMu.RLock()
	defer c.overridesMu.RUnlock()

	result := make(map[string]types.InterfaceType, len(c.manualOverrides))
	for k, v := range c.manualOverrides {
		result[k] = v
	}
	return result
}

// HasManualOverride checks if an interface has a manual override.
func (c *Classifier) HasManualOverride(interfaceName string) bool {
	c.overridesMu.RLock()
	defer c.overridesMu.RUnlock()
	_, ok := c.manualOverrides[interfaceName]
	return ok
}

// =============================================================================
// Configuration Access
// =============================================================================

// GetConfig returns the classifier configuration.
func (c *Classifier) GetConfig() *ClassifierConfig {
	return c.config
}

// GetMode returns the classification mode.
func (c *Classifier) GetMode() string {
	return c.config.Mode
}

// SetMode sets the classification mode.
func (c *Classifier) SetMode(mode string) error {
	switch mode {
	case "automatic", "manual", "hybrid":
		c.config.Mode = mode
		return nil
	default:
		return fmt.Errorf("invalid mode: %s (must be automatic, manual, or hybrid)", mode)
	}
}
