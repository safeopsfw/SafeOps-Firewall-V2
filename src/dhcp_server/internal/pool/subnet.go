// Package pool provides DHCP IP pool management.
// This file implements subnet-level operations including network math and CIDR handling.
package pool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ============================================================================
// Subnet Data Structures
// ============================================================================

// Subnet represents a network subnet with calculated properties.
type Subnet struct {
	Network      net.IP     `json:"network"`
	Mask         net.IPMask `json:"mask"`
	PrefixLength int        `json:"prefix_length"`
	Broadcast    net.IP     `json:"broadcast"`
	FirstUsable  net.IP     `json:"first_usable"`
	LastUsable   net.IP     `json:"last_usable"`
	TotalHosts   uint32     `json:"total_hosts"`
	UsableHosts  uint32     `json:"usable_hosts"`
	Name         string     `json:"name,omitempty"`
	VLANID       uint16     `json:"vlan_id,omitempty"`
	WildcardMask net.IPMask `json:"wildcard_mask"`
}

// ============================================================================
// Subnet Creation Functions
// ============================================================================

// NewSubnet creates a subnet from IP and mask strings.
func NewSubnet(ipStr, maskStr string) (*Subnet, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("only IPv4 addresses are supported")
	}

	mask := parseMask(maskStr)
	if mask == nil {
		return nil, fmt.Errorf("invalid subnet mask: %s", maskStr)
	}

	return createSubnet(ip4, mask)
}

// NewSubnetFromCIDR creates a subnet from CIDR notation (e.g., "192.168.1.0/24").
func NewSubnetFromCIDR(cidr string) (*Subnet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	return createSubnet(ipNet.IP.To4(), ipNet.Mask)
}

// NewSubnetFromNetwork creates a subnet from Go's net.IPNet type.
func NewSubnetFromNetwork(network *net.IPNet) (*Subnet, error) {
	if network == nil {
		return nil, errors.New("network cannot be nil")
	}

	ip4 := network.IP.To4()
	if ip4 == nil {
		return nil, errors.New("only IPv4 networks are supported")
	}

	return createSubnet(ip4, network.Mask)
}

// createSubnet performs all subnet calculations.
func createSubnet(ip net.IP, mask net.IPMask) (*Subnet, error) {
	if len(mask) != 4 {
		return nil, errors.New("invalid IPv4 mask length")
	}

	// Calculate network address
	network := CalculateNetworkAddress(ip, mask)

	// Calculate prefix length
	prefixLen, _ := mask.Size()

	// Calculate broadcast address
	broadcast := CalculateBroadcastAddress(network, mask)

	// Calculate host counts
	totalHosts := CalculateTotalHosts(mask)
	usableHosts := CalculateUsableHosts(mask)

	// Calculate usable range
	firstUsable := CalculateFirstUsableIP(network)
	lastUsable := CalculateLastUsableIP(broadcast)

	// Calculate wildcard mask
	wildcard := MaskToWildcard(mask)

	return &Subnet{
		Network:      network,
		Mask:         mask,
		PrefixLength: prefixLen,
		Broadcast:    broadcast,
		FirstUsable:  firstUsable,
		LastUsable:   lastUsable,
		TotalHosts:   totalHosts,
		UsableHosts:  usableHosts,
		WildcardMask: wildcard,
	}, nil
}

// parseMask parses a mask from CIDR or dotted decimal notation.
func parseMask(maskStr string) net.IPMask {
	// Try CIDR prefix
	if strings.HasPrefix(maskStr, "/") {
		var prefix int
		_, err := fmt.Sscanf(maskStr, "/%d", &prefix)
		if err == nil && prefix >= 0 && prefix <= 32 {
			return CIDRToMask(prefix)
		}
	}

	// Try as integer
	var prefix int
	if _, err := fmt.Sscanf(maskStr, "%d", &prefix); err == nil {
		if prefix >= 0 && prefix <= 32 {
			return CIDRToMask(prefix)
		}
	}

	// Try dotted decimal
	ip := net.ParseIP(maskStr)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return net.IPMask(ip4)
		}
	}

	return nil
}

// ============================================================================
// Network Address Calculations
// ============================================================================

// CalculateNetworkAddress performs bitwise AND (IP & mask).
func CalculateNetworkAddress(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil || len(mask) != 4 {
		return nil
	}

	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip4[i] & mask[i]
	}
	return network
}

// CalculateBroadcastAddress performs bitwise OR (network OR inverted_mask).
func CalculateBroadcastAddress(network net.IP, mask net.IPMask) net.IP {
	if network == nil || len(mask) != 4 {
		return nil
	}

	net4 := network.To4()
	if net4 == nil {
		return nil
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = net4[i] | ^mask[i]
	}
	return broadcast
}

// CalculateFirstUsableIP returns network address + 1.
func CalculateFirstUsableIP(network net.IP) net.IP {
	return IncrementIP(network, 1)
}

// CalculateLastUsableIP returns broadcast address - 1.
func CalculateLastUsableIP(broadcast net.IP) net.IP {
	return DecrementIP(broadcast, 1)
}

// CalculateTotalHosts returns total addresses in subnet (2^(32-prefix)).
func CalculateTotalHosts(mask net.IPMask) uint32 {
	prefix, _ := mask.Size()
	if prefix >= 32 {
		return 1
	}
	return 1 << (32 - prefix)
}

// CalculateUsableHosts returns usable host count (total - 2 for network/broadcast).
func CalculateUsableHosts(mask net.IPMask) uint32 {
	total := CalculateTotalHosts(mask)
	if total <= 2 {
		return 0
	}
	return total - 2
}

// ============================================================================
// Subnet Mask Conversions
// ============================================================================

// MaskToCIDR counts contiguous 1 bits to determine prefix length.
func MaskToCIDR(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// CIDRToMask creates a mask from prefix length.
func CIDRToMask(prefix int) net.IPMask {
	if prefix < 0 {
		prefix = 0
	}
	if prefix > 32 {
		prefix = 32
	}
	return net.CIDRMask(prefix, 32)
}

// MaskToDottedDecimal converts net.IPMask to string.
func MaskToDottedDecimal(mask net.IPMask) string {
	if len(mask) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// MaskToWildcard inverts mask bits to create wildcard mask.
func MaskToWildcard(mask net.IPMask) net.IPMask {
	if len(mask) != 4 {
		return nil
	}
	wildcard := make(net.IPMask, 4)
	for i := 0; i < 4; i++ {
		wildcard[i] = ^mask[i]
	}
	return wildcard
}

// MaskToBinary converts mask to binary string representation.
func MaskToBinary(mask net.IPMask) string {
	if len(mask) != 4 {
		return ""
	}
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		parts[i] = fmt.Sprintf("%08b", mask[i])
	}
	return strings.Join(parts, ".")
}

// ============================================================================
// IP Address Containment Checks
// ============================================================================

// ContainsIP checks if IP is within subnet range.
func (s *Subnet) ContainsIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || s.Network == nil || s.Mask == nil {
		return false
	}

	network := CalculateNetworkAddress(ip4, s.Mask)
	return s.Network.Equal(network)
}

// ContainsRange verifies both start and end IPs are within subnet.
func (s *Subnet) ContainsRange(startIP, endIP net.IP) bool {
	return s.ContainsIP(startIP) && s.ContainsIP(endIP)
}

// IsNetworkAddress checks if IP equals network address.
func (s *Subnet) IsNetworkAddress(ip net.IP) bool {
	return s.Network.Equal(ip.To4())
}

// IsBroadcastAddress checks if IP equals broadcast address.
func (s *Subnet) IsBroadcastAddress(ip net.IP) bool {
	return s.Broadcast.Equal(ip.To4())
}

// IsUsableIP verifies IP is within subnet and not network/broadcast.
func (s *Subnet) IsUsableIP(ip net.IP) bool {
	if !s.ContainsIP(ip) {
		return false
	}
	if s.IsNetworkAddress(ip) || s.IsBroadcastAddress(ip) {
		return false
	}
	return true
}

// ============================================================================
// Subnet Relationship Functions
// ============================================================================

// IsSupernet checks if 's' completely contains 'other'.
func (s *Subnet) IsSupernet(other *Subnet) bool {
	if s == nil || other == nil {
		return false
	}

	// Supernet has shorter prefix (larger network)
	if s.PrefixLength >= other.PrefixLength {
		return false
	}

	// Check if other's network is within s
	return s.ContainsIP(other.Network)
}

// IsSubnet checks if 's' is contained within 'other'.
func (s *Subnet) IsSubnet(other *Subnet) bool {
	return other.IsSupernet(s)
}

// Overlaps checks if two subnets share any address space.
func (s *Subnet) Overlaps(other *Subnet) bool {
	if s == nil || other == nil {
		return false
	}

	// Check if either network address is in the other subnet
	return s.ContainsIP(other.Network) || other.ContainsIP(s.Network)
}

// IsAdjacent checks if subnets are contiguous.
func (s *Subnet) IsAdjacent(other *Subnet) bool {
	if s == nil || other == nil {
		return false
	}

	// Check if s.Broadcast + 1 == other.Network
	nextAfterS := IncrementIP(s.Broadcast, 1)
	if other.Network.Equal(nextAfterS) {
		return true
	}

	// Or if other.Broadcast + 1 == s.Network
	nextAfterOther := IncrementIP(other.Broadcast, 1)
	return s.Network.Equal(nextAfterOther)
}

// ============================================================================
// Subnet Partitioning Functions
// ============================================================================

// SplitSubnet divides subnet into smaller subnets with new prefix.
func (s *Subnet) SplitSubnet(newPrefix int) ([]*Subnet, error) {
	if newPrefix <= s.PrefixLength {
		return nil, fmt.Errorf("new prefix /%d must be greater than current /%d",
			newPrefix, s.PrefixLength)
	}

	if newPrefix > 30 {
		return nil, fmt.Errorf("new prefix /%d too long (max /30)", newPrefix)
	}

	count := 1 << (newPrefix - s.PrefixLength)
	subnets := make([]*Subnet, 0, count)

	newMask := CIDRToMask(newPrefix)
	subnetSize := CalculateTotalHosts(newMask)

	currentNetwork := s.Network
	for i := 0; i < count; i++ {
		subnet, err := createSubnet(currentNetwork, newMask)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, subnet)

		// Move to next subnet
		currentNetwork = IncrementIP(currentNetwork, int(subnetSize))
	}

	return subnets, nil
}

// GetSubnetCount returns how many subnets of targetPrefix fit in this subnet.
func (s *Subnet) GetSubnetCount(targetPrefix int) int {
	if targetPrefix <= s.PrefixLength {
		return 0
	}
	return 1 << (targetPrefix - s.PrefixLength)
}

// GetNextSubnet calculates the adjacent subnet with same prefix.
func (s *Subnet) GetNextSubnet() (*Subnet, error) {
	nextNetwork := IncrementIP(s.Broadcast, 1)
	return createSubnet(nextNetwork, s.Mask)
}

// ============================================================================
// Subnet Math Utilities
// ============================================================================

// IncrementIP adds increment to IP address.
func IncrementIP(ip net.IP, increment int) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	val := binary.BigEndian.Uint32(ip4)
	val += uint32(increment)

	result := make(net.IP, 4)
	binary.BigEndian.PutUint32(result, val)
	return result
}

// DecrementIP subtracts from IP address.
func DecrementIP(ip net.IP, decrement int) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	val := binary.BigEndian.Uint32(ip4)
	val -= uint32(decrement)

	result := make(net.IP, 4)
	binary.BigEndian.PutUint32(result, val)
	return result
}

// CompareIPs returns -1, 0, or 1 for comparison.
func CompareIPs(ip1, ip2 net.IP) int {
	v1 := binary.BigEndian.Uint32(ip1.To4())
	v2 := binary.BigEndian.Uint32(ip2.To4())

	if v1 < v2 {
		return -1
	}
	if v1 > v2 {
		return 1
	}
	return 0
}

// IPRangeSize calculates number of IPs between start and end (inclusive).
func IPRangeSize(start, end net.IP) uint32 {
	s := binary.BigEndian.Uint32(start.To4())
	e := binary.BigEndian.Uint32(end.To4())
	if e < s {
		return 0
	}
	return e - s + 1
}

// ============================================================================
// Subnet Formatting and Display
// ============================================================================

// ToCIDRString returns canonical CIDR notation.
func (s *Subnet) ToCIDRString() string {
	return fmt.Sprintf("%s/%d", s.Network, s.PrefixLength)
}

// ToRangeString returns IP range format.
func (s *Subnet) ToRangeString() string {
	return fmt.Sprintf("%s - %s", s.FirstUsable, s.LastUsable)
}

// ToVerboseString returns detailed multi-line string.
func (s *Subnet) ToVerboseString() string {
	return fmt.Sprintf(`Subnet: %s
  Network:     %s
  Broadcast:   %s
  Mask:        %s (/%d)
  Wildcard:    %s
  Usable:      %s - %s
  Host Count:  %d usable of %d total`,
		s.ToCIDRString(),
		s.Network,
		s.Broadcast,
		MaskToDottedDecimal(s.Mask),
		s.PrefixLength,
		MaskToDottedDecimal(s.WildcardMask),
		s.FirstUsable,
		s.LastUsable,
		s.UsableHosts,
		s.TotalHosts,
	)
}

// ToJSON serializes subnet to JSON.
func (s *Subnet) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// SubnetFromJSON deserializes subnet from JSON.
func SubnetFromJSON(data []byte) (*Subnet, error) {
	var s Subnet
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// String returns CIDR notation.
func (s *Subnet) String() string {
	return s.ToCIDRString()
}

// ============================================================================
// Errors
// ============================================================================

var (
	ErrInvalidCIDR      = errors.New("invalid CIDR notation")
	ErrInvalidIP        = errors.New("invalid IP address")
	ErrInvalidMask      = errors.New("invalid subnet mask")
	ErrIPv6NotSupported = errors.New("IPv6 not supported")
)
