//go:build windows
// +build windows

// Package platform provides Windows-specific device information collection
// using IP Helper API, NetBIOS, registry, and network fingerprinting
package platform

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// =============================================================================
// DEVICE FINGERPRINT STRUCTURE
// =============================================================================

// DeviceFingerprint contains comprehensive device identification data
type DeviceFingerprint struct {
	// Timestamps
	CollectedAt time.Time `json:"collected_at"`

	// Network Identification
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`

	// NetBIOS Info (Windows API)
	NetBIOSName   string `json:"netbios_name,omitempty"`
	NetBIOSDomain string `json:"netbios_domain,omitempty"`
	NetBIOSUser   string `json:"netbios_user,omitempty"`

	// DNS/Hostname
	ResolvedHostname string   `json:"resolved_hostname,omitempty"`
	DNSAliases       []string `json:"dns_aliases,omitempty"`

	// OS Detection
	OSType        string `json:"os_type,omitempty"`        // Windows, iOS, Android, Linux, macOS
	OSVersion     string `json:"os_version,omitempty"`     // Detected version
	OSFingerprint string `json:"os_fingerprint,omitempty"` // Full fingerprint string
	InitialTTL    int    `json:"initial_ttl,omitempty"`    // TTL for OS detection

	// DHCP Fingerprint
	DHCPVendorClass string `json:"dhcp_vendor_class,omitempty"` // DHCP Option 60
	DHCPHostname    string `json:"dhcp_hostname,omitempty"`     // DHCP Option 12
	DHCPParamList   string `json:"dhcp_param_list,omitempty"`   // DHCP Option 55

	// Device Classification
	DeviceClass  string `json:"device_class,omitempty"` // Phone, Laptop, IoT, Router
	Manufacturer string `json:"manufacturer,omitempty"` // Enhanced vendor
	Model        string `json:"model,omitempty"`        // If detectable

	// mDNS/Bonjour Services
	MDNSHostname string   `json:"mdns_hostname,omitempty"`
	MDNSServices []string `json:"mdns_services,omitempty"`

	// Connection Info
	ConnectionType string `json:"connection_type,omitempty"` // WiFi, Ethernet
	SignalStrength int    `json:"signal_strength,omitempty"` // If available

	// Collection Status
	CollectionErrors []string `json:"collection_errors,omitempty"`
}

// =============================================================================
// DEVICE INFO COLLECTOR
// =============================================================================

// DeviceInfoCollector collects device information using Windows APIs
type DeviceInfoCollector struct {
	timeout    time.Duration
	mu         sync.RWMutex
	cache      map[string]*DeviceFingerprint
	cacheTTL   time.Duration
	maxWorkers int
}

// NewDeviceInfoCollector creates a new collector with default settings
func NewDeviceInfoCollector() *DeviceInfoCollector {
	return &DeviceInfoCollector{
		timeout:    10 * time.Second,
		cache:      make(map[string]*DeviceFingerprint),
		cacheTTL:   5 * time.Minute,
		maxWorkers: 4,
	}
}

// CollectAll gathers all available device information
func (c *DeviceInfoCollector) CollectAll(ip, mac string) *DeviceFingerprint {
	fp := &DeviceFingerprint{
		CollectedAt: time.Now(),
		IPAddress:   ip,
		MACAddress:  mac,
	}

	// Check cache first
	c.mu.RLock()
	if cached, ok := c.cache[mac]; ok {
		if time.Since(cached.CollectedAt) < c.cacheTTL {
			c.mu.RUnlock()
			return cached
		}
	}
	c.mu.RUnlock()

	// Collect data in parallel with timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. Reverse DNS lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if hostname, aliases, err := c.resolveHostname(ctx, ip); err == nil {
			mu.Lock()
			fp.ResolvedHostname = hostname
			fp.DNSAliases = aliases
			mu.Unlock()
		} else {
			mu.Lock()
			fp.CollectionErrors = append(fp.CollectionErrors, fmt.Sprintf("DNS: %v", err))
			mu.Unlock()
		}
	}()

	// 2. NetBIOS lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if name, domain, user, err := c.getNetBIOSInfo(ctx, ip); err == nil {
			mu.Lock()
			fp.NetBIOSName = name
			fp.NetBIOSDomain = domain
			fp.NetBIOSUser = user
			mu.Unlock()
		} else {
			mu.Lock()
			fp.CollectionErrors = append(fp.CollectionErrors, fmt.Sprintf("NetBIOS: %v", err))
			mu.Unlock()
		}
	}()

	// 3. TTL-based OS detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ttl, err := c.getTTL(ctx, ip); err == nil {
			mu.Lock()
			fp.InitialTTL = ttl
			fp.OSType, fp.OSVersion = c.classifyOSByTTL(ttl)
			mu.Unlock()
		} else {
			mu.Lock()
			fp.CollectionErrors = append(fp.CollectionErrors, fmt.Sprintf("TTL: %v", err))
			mu.Unlock()
		}
	}()

	// 4. MAC vendor lookup (enhanced)
	wg.Add(1)
	go func() {
		defer wg.Done()
		manufacturer, deviceClass := c.classifyByMAC(mac)
		mu.Lock()
		fp.Manufacturer = manufacturer
		fp.DeviceClass = deviceClass
		mu.Unlock()
	}()

	// 5. DHCP info from registry (if available)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vendorClass, hostname, paramList, err := c.getDHCPInfoFromRegistry(ctx, mac); err == nil {
			mu.Lock()
			fp.DHCPVendorClass = vendorClass
			fp.DHCPHostname = hostname
			fp.DHCPParamList = paramList
			// Enhance OS detection with DHCP info
			if vendorClass != "" {
				osType, osVersion := c.classifyOSByDHCP(vendorClass)
				if osType != "" && fp.OSType == "" {
					fp.OSType = osType
					fp.OSVersion = osVersion
				}
			}
			mu.Unlock()

		}
	}()

	// 6. mDNS Hostname Resolution (New)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if name, err := c.getMDNSInfo(ctx, ip); err == nil {
			mu.Lock()
			fp.MDNSHostname = name
			if fp.ResolvedHostname == "" {
				fp.ResolvedHostname = name
			}
			mu.Unlock()
		}
	}()

	// Wait for all collectors
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All done
	case <-ctx.Done():
		mu.Lock()
		fp.CollectionErrors = append(fp.CollectionErrors, "timeout")
		mu.Unlock()
	}

	// Generate fingerprint string
	fp.OSFingerprint = c.generateFingerprint(fp)

	// Classify device if not yet done
	if fp.DeviceClass == "" {
		fp.DeviceClass = c.classifyDevice(fp)
	}

	// Update cache
	c.mu.Lock()
	c.cache[mac] = fp
	c.mu.Unlock()

	return fp
}

// =============================================================================
// DNS/HOSTNAME RESOLUTION
// =============================================================================

func (c *DeviceInfoCollector) resolveHostname(ctx context.Context, ip string) (string, []string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", nil, err
	}
	if len(names) == 0 {
		return "", nil, fmt.Errorf("no PTR record")
	}

	hostname := strings.TrimSuffix(names[0], ".")
	var aliases []string
	for i := 1; i < len(names); i++ {
		aliases = append(aliases, strings.TrimSuffix(names[i], "."))
	}

	return hostname, aliases, nil
}

// =============================================================================
// NETBIOS LOOKUP (using nbtstat)
// =============================================================================

func (c *DeviceInfoCollector) getNetBIOSInfo(ctx context.Context, ip string) (name, domain, user string, err error) {
	// Use nbtstat command - available on all Windows
	cmd := exec.CommandContext(ctx, "nbtstat", "-A", ip)
	output, err := cmd.Output()
	if err != nil {
		return "", "", "", fmt.Errorf("nbtstat failed: %w", err)
	}

	// Parse nbtstat output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for <00> entries (computer name)
		if strings.Contains(line, "<00>") && strings.Contains(line, "UNIQUE") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				name = parts[0]
			}
		}
		// Look for <1E> or <00> GROUP entries (domain/workgroup)
		if (strings.Contains(line, "<1E>") || strings.Contains(line, "<00>")) && strings.Contains(line, "GROUP") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain = parts[0]
			}
		}
		// Look for <03> entries (logged-in user)
		if strings.Contains(line, "<03>") && strings.Contains(line, "UNIQUE") {
			parts := strings.Fields(line)
			if len(parts) > 0 && parts[0] != name {
				user = parts[0]
			}
		}
	}

	if name == "" && domain == "" {
		return "", "", "", fmt.Errorf("no NetBIOS info found")
	}

	return name, domain, user, nil
}

// =============================================================================
// TTL-BASED OS DETECTION
// =============================================================================

func (c *DeviceInfoCollector) getTTL(ctx context.Context, ip string) (int, error) {
	// Use ping to get TTL
	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "2000", ip)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ping failed: %w", err)
	}

	// Parse TTL from ping output
	// Example: "Reply from x.x.x.x: bytes=32 time<1ms TTL=64"
	re := regexp.MustCompile(`TTL[=:](\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) >= 2 {
		var ttl int
		fmt.Sscanf(matches[1], "%d", &ttl)
		return ttl, nil
	}

	return 0, fmt.Errorf("TTL not found in ping output")
}

func (c *DeviceInfoCollector) classifyOSByTTL(ttl int) (osType, osVersion string) {
	// Initial TTL values by OS:
	// 64: Linux, Android, macOS, iOS, FreeBSD
	// 128: Windows
	// 255: Cisco/Network equipment, Solaris
	// 60: Some IoT devices

	switch {
	case ttl > 0 && ttl <= 64:
		// Linux family (TTL starts at 64)
		if ttl == 64 {
			return "Linux/Unix", "Unknown"
		}
		// Decremented from 64
		return "Linux/Unix", fmt.Sprintf("~%d hops", 64-ttl)

	case ttl > 64 && ttl <= 128:
		// Windows family (TTL starts at 128)
		if ttl == 128 {
			return "Windows", "Unknown"
		}
		// Decremented from 128
		return "Windows", fmt.Sprintf("~%d hops", 128-ttl)

	case ttl > 128 && ttl <= 255:
		// Network equipment/Solaris (TTL starts at 255)
		if ttl == 255 {
			return "Network/Solaris", "Router/Switch"
		}
		return "Network/Solaris", fmt.Sprintf("~%d hops", 255-ttl)

	default:
		return "Unknown", ""
	}
}

// =============================================================================
// DHCP FINGERPRINTING
// =============================================================================

func (c *DeviceInfoCollector) getDHCPInfoFromRegistry(ctx context.Context, mac string) (vendorClass, hostname, paramList string, err error) {
	// DHCP lease info is stored in registry under:
	// HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.READ|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot open registry: %w", err)
	}
	defer key.Close()

	// Enumerate interface GUIDs
	guids, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", "", "", err
	}

	for _, guid := range guids {
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid),
			registry.READ)
		if err != nil {
			continue
		}

		// Check for DHCP info
		if domain, _, err := subKey.GetStringValue("Domain"); err == nil && domain != "" {
			hostname = domain
		}
		if hn, _, err := subKey.GetStringValue("Hostname"); err == nil && hn != "" {
			hostname = hn
		}

		// Option vendor class is often stored after DHCP exchange
		if vc, _, err := subKey.GetBinaryValue("DhcpVendorSpecificInfo"); err == nil {
			vendorClass = string(vc)
		}

		subKey.Close()
	}

	return vendorClass, hostname, paramList, nil
}

func (c *DeviceInfoCollector) classifyOSByDHCP(vendorClass string) (osType, osVersion string) {
	vendorClass = strings.ToLower(vendorClass)

	// Common DHCP vendor class identifiers (Option 60)
	switch {
	case strings.Contains(vendorClass, "msft 5.0"):
		return "Windows", "2000/XP+"
	case strings.Contains(vendorClass, "msft"):
		return "Windows", "Unknown"
	case strings.Contains(vendorClass, "android-dhcp"):
		// Format: android-dhcp-<version>
		parts := strings.Split(vendorClass, "-")
		if len(parts) >= 3 {
			return "Android", parts[2]
		}
		return "Android", "Unknown"
	case strings.Contains(vendorClass, "dhcpcd"):
		return "Linux", "dhcpcd client"
	case strings.Contains(vendorClass, "udhcp"):
		return "Linux", "BusyBox/Embedded"
	case strings.Contains(vendorClass, "isc-dhcp"):
		return "Linux/Unix", "ISC DHCP"
	case strings.Contains(vendorClass, "apple"):
		return "macOS/iOS", "Unknown"
	default:
		return "", ""
	}
}

// =============================================================================
// MAC ADDRESS VENDOR LOOKUP
// =============================================================================

// Common MAC OUI prefixes for quick classification
var macVendorDB = map[string]struct {
	Vendor      string
	DeviceClass string
}{
	// Apple
	"00:1C:B3": {"Apple", "Phone/Tablet/Computer"},
	"00:1E:C2": {"Apple", "Phone/Tablet/Computer"},
	"00:25:00": {"Apple", "Phone/Tablet/Computer"},
	"3C:06:30": {"Apple", "Phone/Tablet/Computer"},
	"A4:83:E7": {"Apple", "Phone/Tablet/Computer"},
	"F0:DB:E2": {"Apple", "Phone/Tablet/Computer"},
	"8C:85:90": {"Apple", "Phone/Tablet/Computer"},

	// Samsung
	"00:21:19": {"Samsung", "Phone/Tablet/TV"},
	"00:26:37": {"Samsung", "Phone/Tablet/TV"},
	"5C:0A:5B": {"Samsung", "Phone/Tablet/TV"},
	"78:47:1D": {"Samsung", "Phone/Tablet/TV"},
	"A0:82:1F": {"Samsung", "Phone/Tablet/TV"},
	"E4:7C:F9": {"Samsung", "Phone/Tablet/TV"},

	// Google/Android
	"00:1A:11": {"Google", "Phone/IoT"},
	"3C:5A:B4": {"Google", "Phone/IoT"},
	"F4:F5:D8": {"Google", "Phone/IoT"},

	// Microsoft
	"00:03:FF": {"Microsoft", "Computer/Xbox"},
	"00:0D:3A": {"Microsoft", "Computer/Xbox"},
	"00:15:5D": {"Microsoft", "Computer/VM"},
	"00:17:FA": {"Microsoft", "Computer/Xbox"},

	// Intel (common in laptops)
	"00:1B:21": {"Intel", "Computer"},
	"00:1E:67": {"Intel", "Computer"},
	"00:21:5D": {"Intel", "Computer"},
	"3C:97:0E": {"Intel", "Computer"},
	"8C:8D:28": {"Intel", "Computer"},

	// Dell
	"00:14:22": {"Dell", "Computer"},
	"00:1A:A0": {"Dell", "Computer"},
	"18:03:73": {"Dell", "Computer"},
	"34:E6:D7": {"Dell", "Computer"},

	// HP
	"00:1E:0B": {"HP", "Computer/Printer"},
	"00:21:5A": {"HP", "Computer/Printer"},
	"2C:44:FD": {"HP", "Computer/Printer"},

	// Lenovo
	"00:06:1B": {"Lenovo", "Computer"},
	"00:1A:6B": {"Lenovo", "Computer"},
	"28:D2:44": {"Lenovo", "Computer"},

	// Espressif (IoT)
	"24:0A:C4": {"Espressif", "IoT"},
	"30:AE:A4": {"Espressif", "IoT"},
	"A4:CF:12": {"Espressif", "IoT"},
	"BC:DD:C2": {"Espressif", "IoT"},
	"CC:50:E3": {"Espressif", "IoT"},

	// Raspberry Pi
	"B8:27:EB": {"Raspberry Pi", "IoT/Computer"},
	"DC:A6:32": {"Raspberry Pi", "IoT/Computer"},
	"E4:5F:01": {"Raspberry Pi", "IoT/Computer"},

	// TP-Link
	"00:0A:EB": {"TP-Link", "Router/IoT"},
	"14:CC:20": {"TP-Link", "Router/IoT"},
	"50:C7:BF": {"TP-Link", "Router/IoT"},

	// Cisco
	"00:00:0C": {"Cisco", "Router/Switch"},
	"00:1A:A1": {"Cisco", "Router/Switch"},
	"00:1B:2A": {"Cisco", "Router/Switch"},

	// Amazon
	"00:FC:8B": {"Amazon", "Echo/Fire/IoT"},
	"34:D2:70": {"Amazon", "Echo/Fire/IoT"},
	"44:65:0D": {"Amazon", "Echo/Fire/IoT"},
	"74:C2:46": {"Amazon", "Echo/Fire/IoT"},

	// Xiaomi
	"00:9E:C8": {"Xiaomi", "Phone/IoT"},
	"28:6C:07": {"Xiaomi", "Phone/IoT"},
	"64:CC:2E": {"Xiaomi", "Phone/IoT"},
	"78:02:F8": {"Xiaomi", "Phone/IoT"},

	// Huawei
	"00:25:9E": {"Huawei", "Phone/Router"},
	"00:46:4B": {"Huawei", "Phone/Router"},
	"48:46:FB": {"Huawei", "Phone/Router"},
	"88:53:2E": {"Huawei", "Phone/Router"},

	// OnePlus
	"94:65:2D": {"OnePlus", "Phone"},
	"C0:EE:FB": {"OnePlus", "Phone"},

	// Ring
	"18:B4:30": {"Ring", "IoT/Camera"},
	"34:3E:A4": {"Ring", "IoT/Camera"},

	// Sonos
	"00:0E:58": {"Sonos", "IoT/Speaker"},
	"5C:AA:FD": {"Sonos", "IoT/Speaker"},
	"94:9F:3E": {"Sonos", "IoT/Speaker"},

	// Nest (Google)
	"64:16:66": {"Nest/Google", "IoT/Thermostat"},

	// PlayStation
	"00:04:1F": {"Sony PlayStation", "Gaming"},
	"00:D9:D1": {"Sony PlayStation", "Gaming"},
	"F8:46:1C": {"Sony PlayStation", "Gaming"},

	// Nintendo
	"00:1B:EA": {"Nintendo", "Gaming"},
	"00:1F:32": {"Nintendo", "Gaming"},
	"E8:4E:CE": {"Nintendo", "Gaming"},
}

func (c *DeviceInfoCollector) classifyByMAC(mac string) (manufacturer, deviceClass string) {
	// Normalize MAC for lookup
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))

	// Check first 3 octets (OUI)
	if len(mac) >= 8 {
		oui := mac[:8]
		if info, ok := macVendorDB[oui]; ok {
			return info.Vendor, info.DeviceClass
		}
	}

	// Default vendor lookup
	return lookupMACVendor(mac), "Unknown"
}

// lookupMACVendor performs OUI lookup (simplified version)
func lookupMACVendor(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(mac) < 6 {
		return "Unknown"
	}

	// This is a simplified lookup - in production, use a full OUI database
	oui := mac[:6]
	switch oui[:2] {
	case "00":
		return "Various Vendors"
	case "FC", "AC":
		return "Various Vendors"
	default:
		return "Unknown Vendor"
	}
}

// =============================================================================
// mDNS RESOLUTION
// =============================================================================

func (c *DeviceInfoCollector) getMDNSInfo(ctx context.Context, ip string) (string, error) {
	// Simple mDNS Reverse Lookup: (reversed-ip).in-addr.arpa PTR -> hostname
	// 5353 is mDNS port

	// Create reverse IP name
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP")
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return "", fmt.Errorf("not IPv4")
	}

	// Format: 4.3.2.1.in-addr.arpa
	name := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ipv4[3], ipv4[2], ipv4[1], ipv4[0])

	// Construct DNS Query Packet manually (Header + Question)
	// ID: 0, Flags: 0, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
	packet := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags (Standard Query)
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}

	// Append QNAME (length prefixed labels)
	parts := strings.Split(name, ".")
	for _, part := range parts {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00) // Root label

	// Append QTYPE (PTR=12 -> 0x000C) and QCLASS (IN=1 -> 0x0001)
	packet = append(packet, 0x00, 0x0C) // QTYPE: PTR
	packet = append(packet, 0x00, 0x01) // QCLASS: IN

	// Send to mDNS Multicast Address (IPv4)
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.251:5353")
	if err != nil {
		return "", err
	}

	conn, err := net.ListenUDP("udp", nil) // Ephemeral port
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.WriteToUDP(packet, addr); err != nil {
		return "", err
	}

	// Read response
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", err
	}

	// Very basic response parsing: look for domain name strings in answer
	// Skip header (12 bytes) and question (variable) to find answer
	// A simple heuristic: scan for sequences of readable chars ending in .local
	resp := buf[:n]

	// Search for ".local" in response
	s := string(resp)
	idx := strings.Index(s, ".local")
	if idx > 0 {
		// Backtrack to length byte
		// This is unsafe/sloppy, but without a DNS lib, it's a best-attempt heuristic
		// We try to extract printable string before .local
		start := idx
		for start > 12 {
			c := s[start-1]
			if c < 32 || c > 126 { // Unprintable likely length byte
				break
			}
			start--
		}
		if start < idx {
			return s[start : idx+6], nil // Include .local
		}
	}

	return "", fmt.Errorf("no mDNS name found")
}

// =============================================================================
// DEVICE CLASSIFICATION
// =============================================================================

func (c *DeviceInfoCollector) classifyDevice(fp *DeviceFingerprint) string {
	// Priority classification
	if fp.DeviceClass != "" && fp.DeviceClass != "Unknown" {
		return fp.DeviceClass
	}

	// Use OS type to guess device class
	switch fp.OSType {
	case "Android":
		return "Phone/Tablet"
	case "iOS":
		return "iPhone/iPad"
	case "Windows":
		return "Computer"
	case "Linux/Unix":
		// Could be server, IoT, or computer
		if strings.Contains(strings.ToLower(fp.Manufacturer), "raspberry") {
			return "IoT/SBC"
		}
		if strings.Contains(strings.ToLower(fp.Manufacturer), "espressif") {
			return "IoT"
		}
		return "Computer/Server"
	case "Network/Solaris":
		return "Network Equipment"
	default:
		return "Unknown"
	}
}

// =============================================================================
// FINGERPRINT STRING GENERATION
// =============================================================================

func (c *DeviceInfoCollector) generateFingerprint(fp *DeviceFingerprint) string {
	// Create a unique fingerprint string for this device
	parts := []string{}

	if fp.OSType != "" {
		parts = append(parts, fmt.Sprintf("OS:%s", fp.OSType))
	}
	if fp.InitialTTL > 0 {
		parts = append(parts, fmt.Sprintf("TTL:%d", fp.InitialTTL))
	}
	if fp.Manufacturer != "" {
		parts = append(parts, fmt.Sprintf("MFR:%s", fp.Manufacturer))
	}
	if fp.DHCPVendorClass != "" {
		parts = append(parts, fmt.Sprintf("DHCP:%s", fp.DHCPVendorClass))
	}
	if fp.NetBIOSName != "" {
		parts = append(parts, fmt.Sprintf("NB:%s", fp.NetBIOSName))
	}

	if len(parts) == 0 {
		return "unknown"
	}

	return strings.Join(parts, "|")
}

// =============================================================================
// UTILITY: SUPPRESS UNUSED
// =============================================================================

var (
	_ = windows.AF_INET
	_ = unsafe.Sizeof(0)
	_ = hex.EncodeToString
)
