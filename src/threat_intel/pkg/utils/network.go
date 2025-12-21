// Package utils provides common utility functions for threat intelligence
package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
)

// ============================================================================
// IP Address Validation
// ============================================================================

// IsValidIP checks if a string is a valid IPv4 or IPv6 address
func IsValidIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// GetIPVersion returns the IP version (4 or 6) or 0 if invalid
func GetIPVersion(ipStr string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// IsPrivateIP checks if an IP address is in private ranges
// RFC 1918 (IPv4): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
// RFC 4193 (IPv6): fc00::/7
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// IPv4 private ranges
	privateIPv4Ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	// IPv6 private range
	privateIPv6Ranges := []string{
		"fc00::/7",  // Unique local addresses
		"fe80::/10", // Link-local addresses
	}

	// Check IPv4 private ranges
	if ip.To4() != nil {
		for _, cidr := range privateIPv4Ranges {
			if IPInCIDR(ipStr, cidr) {
				return true
			}
		}
		return false
	}

	// Check IPv6 private ranges
	for _, cidr := range privateIPv6Ranges {
		if IPInCIDR(ipStr, cidr) {
			return true
		}
	}

	return false
}

// IsReservedIP checks if an IP is in reserved/special ranges
func IsReservedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// IPv4 reserved ranges
	if ip.To4() != nil {
		reservedRanges := []string{
			"0.0.0.0/8",          // Current network
			"127.0.0.0/8",        // Loopback
			"169.254.0.0/16",     // Link-local
			"224.0.0.0/4",        // Multicast
			"240.0.0.0/4",        // Reserved
			"255.255.255.255/32", // Broadcast
		}
		for _, cidr := range reservedRanges {
			if IPInCIDR(ipStr, cidr) {
				return true
			}
		}
		return false
	}

	// IPv6 reserved ranges
	reservedIPv6Ranges := []string{
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"ff00::/8",      // Multicast
		"2001:db8::/32", // Documentation
	}
	for _, cidr := range reservedIPv6Ranges {
		if IPInCIDR(ipStr, cidr) {
			return true
		}
	}

	return false
}

// IsMulticastIP checks if an IP is a multicast address
func IsMulticastIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		return IPInCIDR(ipStr, "224.0.0.0/4")
	}
	return IPInCIDR(ipStr, "ff00::/8")
}

// IsLoopbackIP checks if an IP is a loopback address
func IsLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		return IPInCIDR(ipStr, "127.0.0.0/8")
	}
	return IPInCIDR(ipStr, "::1/128")
}

// ============================================================================
// CIDR Parsing and Validation
// ============================================================================

// CIDRInfo holds parsed CIDR information
type CIDRInfo struct {
	Network   string // Network address (e.g., "192.168.1.0")
	Prefix    int    // Prefix length (e.g., 24)
	Netmask   string // Netmask (e.g., "255.255.255.0")
	FirstIP   string // First usable IP
	LastIP    string // Last usable IP
	Broadcast string // Broadcast address (IPv4 only)
	TotalIPs  uint64 // Total IPs in range
	UsableIPs uint64 // Usable IPs (excluding network and broadcast)
	IPVersion int    // 4 or 6
}

// ParseCIDR parses a CIDR notation string into structured information
func ParseCIDR(cidr string) (*CIDRInfo, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	prefixLen, bits := ipNet.Mask.Size()

	info := &CIDRInfo{
		Network:   ipNet.IP.String(),
		Prefix:    prefixLen,
		Netmask:   net.IP(ipNet.Mask).String(),
		IPVersion: 4,
	}

	if bits == 128 {
		info.IPVersion = 6
	}

	// Calculate total IPs
	info.TotalIPs = 1 << uint(bits-prefixLen)

	// Calculate first and last IP
	firstIP := ipNet.IP
	lastIP := make(net.IP, len(firstIP))
	copy(lastIP, firstIP)

	// Set all host bits to 1 for last IP
	for i := range lastIP {
		lastIP[i] |= ^ipNet.Mask[i]
	}

	info.FirstIP = firstIP.String()
	info.LastIP = lastIP.String()

	// IPv4 specific calculations
	if info.IPVersion == 4 {
		info.Broadcast = lastIP.String()
		if info.TotalIPs > 2 {
			info.UsableIPs = info.TotalIPs - 2 // Exclude network and broadcast
		} else {
			info.UsableIPs = info.TotalIPs
		}
	} else {
		info.UsableIPs = info.TotalIPs
	}

	return info, nil
}

// ValidateCIDR checks if a CIDR notation is valid
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	return nil
}

// CIDRToRange converts CIDR to start and end IP addresses
func CIDRToRange(cidr string) (startIP, endIP string, err error) {
	info, err := ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	return info.FirstIP, info.LastIP, nil
}

// CalculateNetmask returns the netmask for a given prefix length
func CalculateNetmask(prefixLen, ipVersion int) (string, error) {
	var bits int
	switch ipVersion {
	case 4:
		bits = 32
	case 6:
		bits = 128
	default:
		return "", errors.New("invalid IP version, must be 4 or 6")
	}

	if prefixLen < 0 || prefixLen > bits {
		return "", fmt.Errorf("invalid prefix length %d for IPv%d", prefixLen, ipVersion)
	}

	mask := net.CIDRMask(prefixLen, bits)
	return net.IP(mask).String(), nil
}

// ============================================================================
// IP Range Calculations
// ============================================================================

// IPInRange checks if an IP is within a start-end IP range
func IPInRange(ipStr, startIP, endIP string) bool {
	ip := net.ParseIP(ipStr)
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if ip == nil || start == nil || end == nil {
		return false
	}

	return CompareIPs(ip.String(), start.String()) >= 0 &&
		CompareIPs(ip.String(), end.String()) <= 0
}

// CountIPsInRange returns the number of IPs in a range
func CountIPsInRange(startIP, endIP string) (uint64, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil || end == nil {
		return 0, errors.New("invalid IP addresses")
	}

	// Ensure both are same version
	if (start.To4() != nil) != (end.To4() != nil) {
		return 0, errors.New("IP addresses must be same version")
	}

	// For IPv4
	if start.To4() != nil {
		startInt := IPv4ToInt(startIP)
		endInt := IPv4ToInt(endIP)
		if endInt < startInt {
			return 0, errors.New("end IP must be >= start IP")
		}
		return uint64(endInt-startInt) + 1, nil
	}

	// For IPv6, use byte comparison (simplified)
	return 0, errors.New("IPv6 range counting not implemented")
}

// ============================================================================
// Subnet Membership Testing
// ============================================================================

// IPInCIDR checks if an IP address is within a CIDR block
func IPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(ip)
}

// FindMatchingCIDR finds the smallest CIDR that contains the IP
func FindMatchingCIDR(ipStr string, cidrs []string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}

	var bestMatch string
	var bestPrefix int = -1

	for _, cidr := range cidrs {
		if IPInCIDR(ipStr, cidr) {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			prefixLen, _ := ipNet.Mask.Size()

			// Prefer longer prefix (more specific match)
			if prefixLen > bestPrefix {
				bestPrefix = prefixLen
				bestMatch = cidr
			}
		}
	}

	if bestMatch != "" {
		return bestMatch, true
	}
	return "", false
}

// CIDRContainsCIDR checks if network1 contains network2
func CIDRContainsCIDR(network1, network2 string) bool {
	_, net1, err1 := net.ParseCIDR(network1)
	_, net2, err2 := net.ParseCIDR(network2)

	if err1 != nil || err2 != nil {
		return false
	}

	// Check if net2's network address is in net1
	// and net2's prefix is >= net1's prefix (more specific)
	prefix1, _ := net1.Mask.Size()
	prefix2, _ := net2.Mask.Size()

	return net1.Contains(net2.IP) && prefix2 >= prefix1
}

// CIDRsOverlap checks if two CIDR blocks overlap
func CIDRsOverlap(cidr1, cidr2 string) bool {
	_, net1, err1 := net.ParseCIDR(cidr1)
	_, net2, err2 := net.ParseCIDR(cidr2)

	if err1 != nil || err2 != nil {
		return false
	}

	// Check if either network contains the other's network address
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// ============================================================================
// IP Address Sorting and Comparison
// ============================================================================

// CompareIPs compares two IP addresses
// Returns: -1 if ip1 < ip2, 0 if equal, 1 if ip1 > ip2
func CompareIPs(ip1Str, ip2Str string) int {
	ip1 := net.ParseIP(ip1Str)
	ip2 := net.ParseIP(ip2Str)

	if ip1 == nil || ip2 == nil {
		return 0 // Invalid IPs considered equal
	}

	// Normalize to 16-byte representation
	ip1 = ip1.To16()
	ip2 = ip2.To16()

	// Byte-by-byte comparison
	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// SortIPs sorts a slice of IP addresses in ascending order
func SortIPs(ips []string) []string {
	sorted := make([]string, len(ips))
	copy(sorted, ips)

	sort.Slice(sorted, func(i, j int) bool {
		return CompareIPs(sorted[i], sorted[j]) < 0
	})

	return sorted
}

// RemoveDuplicateIPs removes duplicate IP addresses from a slice
func RemoveDuplicateIPs(ips []string) []string {
	seen := make(map[string]bool, len(ips))
	result := make([]string, 0, len(ips))

	for _, ip := range ips {
		normalized := NormalizeIP(ip)
		if normalized == "" {
			continue // Skip invalid IPs
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}

	return result
}

// ============================================================================
// Network Address Conversions
// ============================================================================

// IPToBytes converts an IP string to byte array
func IPToBytes(ipStr string) ([]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}

	// Return IPv4 as 4 bytes, IPv6 as 16 bytes
	if ip.To4() != nil {
		return []byte(ip.To4()), nil
	}
	return []byte(ip.To16()), nil
}

// IPv4ToInt converts an IPv4 address to a 32-bit integer
func IPv4ToInt(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}

	ip = ip.To4()
	if ip == nil {
		return 0 // Not an IPv4 address
	}

	return binary.BigEndian.Uint32(ip)
}

// IntToIPv4 converts a 32-bit integer to an IPv4 address string
func IntToIPv4(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

// NormalizeIP normalizes an IP address string
// Removes leading zeros, expands IPv6 shorthand
func NormalizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Return canonical representation
	if ip.To4() != nil {
		return ip.To4().String()
	}
	return ip.To16().String()
}

// ExpandIPv6 expands an IPv6 address to full notation
func ExpandIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	ip = ip.To16()
	if ip == nil {
		return ""
	}

	// Format as full IPv6
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// CompressIPv6 compresses an IPv6 address to shortest notation
func CompressIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	ip = ip.To16()
	if ip == nil {
		return ""
	}

	return ip.String()
}

// ============================================================================
// Utility Functions
// ============================================================================

// IsIPv4 checks if an IP address is IPv4
func IsIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

// IsIPv6 checks if an IP address is IPv6
func IsIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}

// GetIPFamily returns "ipv4", "ipv6", or "" for invalid IPs
func GetIPFamily(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
