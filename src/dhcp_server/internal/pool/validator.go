// Package pool provides DHCP IP pool management.
// This file implements comprehensive validation for pools, subnets, ranges, and reservations.
package pool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Validation Result Types
// ============================================================================

// ValidationSeverity indicates the severity of a validation issue.
type ValidationSeverity int

const (
	SeverityWarning  ValidationSeverity = iota // Suboptimal but functional
	SeverityError                              // Configuration invalid
	SeverityCritical                           // Will break DHCP
)

func (s ValidationSeverity) String() string {
	switch s {
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ValidationError represents a specific validation issue.
type ValidationError struct {
	Severity ValidationSeverity
	Code     string
	Field    string
	Message  string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("[%s] %s: %s (%s)", e.Severity, e.Field, e.Message, e.Code)
}

// ValidationResult contains the outcome of a validation operation.
type ValidationResult struct {
	Valid    bool
	Errors   []*ValidationError
	Warnings []*ValidationError
}

// NewValidationResult creates an empty valid result.
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Valid:    true,
		Errors:   make([]*ValidationError, 0),
		Warnings: make([]*ValidationError, 0),
	}
}

// AddError adds an error and marks result as invalid.
func (r *ValidationResult) AddError(code, field, message string) {
	r.Valid = false
	r.Errors = append(r.Errors, &ValidationError{
		Severity: SeverityError,
		Code:     code,
		Field:    field,
		Message:  message,
	})
}

// AddCritical adds a critical error.
func (r *ValidationResult) AddCritical(code, field, message string) {
	r.Valid = false
	r.Errors = append(r.Errors, &ValidationError{
		Severity: SeverityCritical,
		Code:     code,
		Field:    field,
		Message:  message,
	})
}

// AddWarning adds a warning (doesn't invalidate).
func (r *ValidationResult) AddWarning(code, field, message string) {
	r.Warnings = append(r.Warnings, &ValidationError{
		Severity: SeverityWarning,
		Code:     code,
		Field:    field,
		Message:  message,
	})
}

// Merge combines another result into this one.
func (r *ValidationResult) Merge(other *ValidationResult) {
	if other == nil {
		return
	}
	if !other.Valid {
		r.Valid = false
	}
	r.Errors = append(r.Errors, other.Errors...)
	r.Warnings = append(r.Warnings, other.Warnings...)
}

// ============================================================================
// Subnet Validation Functions
// ============================================================================

// ValidateSubnetAddress verifies IP and mask form a valid network address.
func ValidateSubnetAddress(ip net.IP, mask net.IPMask) *ValidationResult {
	result := NewValidationResult()

	ip4 := ip.To4()
	if ip4 == nil {
		result.AddCritical("INVALID_IPV4", "subnet", "IP address must be IPv4")
		return result
	}

	// Check mask length is reasonable for DHCP (8-30 bits)
	ones, bits := mask.Size()
	if bits != 32 {
		result.AddError("INVALID_MASK", "mask", "Mask must be for IPv4 (32 bits)")
		return result
	}

	if ones < 8 || ones > 30 {
		result.AddError("MASK_SIZE", "mask",
			fmt.Sprintf("Mask /%d outside reasonable range (8-30)", ones))
	}

	// Verify network address has host bits zeroed
	network := ip4.Mask(mask)
	if !network.Equal(ip4) {
		result.AddError("HOST_BITS", "subnet",
			fmt.Sprintf("Network address should be %s (host bits must be zero)", network))
	}

	// Validate mask is contiguous
	if !isContiguousMask(mask) {
		result.AddCritical("NON_CONTIGUOUS_MASK", "mask", "Subnet mask must have contiguous 1s")
	}

	return result
}

// ValidateSubnetMask confirms mask is valid CIDR.
func ValidateSubnetMask(mask net.IPMask) *ValidationResult {
	result := NewValidationResult()

	if len(mask) != 4 {
		result.AddError("INVALID_MASK_LEN", "mask", "Mask must be 4 bytes for IPv4")
		return result
	}

	if !isContiguousMask(mask) {
		result.AddCritical("NON_CONTIGUOUS_MASK", "mask",
			"Subnet mask must have contiguous 1s followed by 0s")
	}

	return result
}

// isContiguousMask checks if mask has contiguous 1s followed by 0s.
func isContiguousMask(mask net.IPMask) bool {
	if len(mask) != 4 {
		return false
	}

	val := binary.BigEndian.Uint32(mask)
	if val == 0 {
		return true
	}

	// Valid mask: flip bits should result in 2^n - 1
	inverted := ^val
	return (inverted & (inverted + 1)) == 0
}

// ValidateSubnetSize checks subnet provides minimum usable hosts.
func ValidateSubnetSize(mask net.IPMask) *ValidationResult {
	result := NewValidationResult()

	ones, bits := mask.Size()
	if bits != 32 {
		return result
	}

	hostBits := 32 - ones
	totalHosts := (1 << hostBits) - 2 // Exclude network and broadcast

	if totalHosts < 4 {
		result.AddError("SUBNET_TOO_SMALL", "mask",
			fmt.Sprintf("Subnet must have at least 4 usable hosts (has %d)", totalHosts))
	}

	if totalHosts > 1024 {
		result.AddWarning("LARGE_SUBNET", "mask",
			fmt.Sprintf("Large subnet with %d hosts may need to be split", totalHosts))
	}

	return result
}

// ============================================================================
// Range Validation Functions
// ============================================================================

// ValidateIPRange verifies start and end IPs form a valid range within subnet.
func ValidateIPRange(startIP, endIP net.IP, subnet *net.IPNet) *ValidationResult {
	result := NewValidationResult()

	start4 := startIP.To4()
	end4 := endIP.To4()

	if start4 == nil {
		result.AddCritical("INVALID_START_IP", "range_start", "Start IP must be valid IPv4")
		return result
	}

	if end4 == nil {
		result.AddCritical("INVALID_END_IP", "range_end", "End IP must be valid IPv4")
		return result
	}

	// Verify start < end
	startVal := ipToUint32(start4)
	endVal := ipToUint32(end4)

	if startVal > endVal {
		result.AddError("INVALID_RANGE_ORDER", "range",
			fmt.Sprintf("Start IP %s must be <= End IP %s", startIP, endIP))
	}

	if subnet != nil {
		// Check both within subnet
		if !subnet.Contains(start4) {
			result.AddError("START_OUTSIDE_SUBNET", "range_start",
				fmt.Sprintf("Start IP %s not within subnet %s", startIP, subnet))
		}

		if !subnet.Contains(end4) {
			result.AddError("END_OUTSIDE_SUBNET", "range_end",
				fmt.Sprintf("End IP %s not within subnet %s", endIP, subnet))
		}

		// Check not network or broadcast
		network := subnet.IP.Mask(subnet.Mask)
		broadcast := calculateBroadcast(subnet)

		if start4.Equal(network) {
			result.AddError("START_IS_NETWORK", "range_start",
				"Start IP cannot be network address")
		}

		if end4.Equal(broadcast) {
			result.AddError("END_IS_BROADCAST", "range_end",
				"End IP cannot be broadcast address")
		}
	}

	// Minimum range size
	rangeSize := endVal - startVal + 1
	if rangeSize < 1 {
		result.AddError("EMPTY_RANGE", "range", "Range must contain at least 1 IP")
	}

	if rangeSize < 10 && rangeSize >= 1 {
		result.AddWarning("SMALL_RANGE", "range",
			fmt.Sprintf("Range only contains %d IPs", rangeSize))
	}

	return result
}

// ValidateRangeBoundaries validates IP addresses are properly formatted.
func ValidateRangeBoundaries(start, end net.IP) *ValidationResult {
	result := NewValidationResult()

	for _, ip := range []net.IP{start, end} {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}

		// Check for special addresses
		if ip4.Equal(net.IPv4zero) {
			result.AddError("ZERO_IP", "range", "Cannot use 0.0.0.0 in range")
		}

		if ip4.Equal(net.IPv4bcast) {
			result.AddError("BROADCAST_IP", "range", "Cannot use 255.255.255.255 in range")
		}

		// Check for loopback
		if ip4[0] == 127 {
			result.AddError("LOOPBACK_IP", "range", "Cannot use loopback addresses in range")
		}

		// Check for multicast
		if ip4[0] >= 224 && ip4[0] <= 239 {
			result.AddError("MULTICAST_IP", "range", "Cannot use multicast addresses in range")
		}
	}

	return result
}

// ============================================================================
// Reservation Validation Functions
// ============================================================================

// MACAddressRegex matches common MAC address formats.
var MACAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)

// ValidateReservation validates a static IP reservation.
func ValidateReservation(mac string, ip net.IP, poolStart, poolEnd net.IP) *ValidationResult {
	result := NewValidationResult()

	// Validate MAC format
	macResult := ValidateMACAddress(mac)
	result.Merge(macResult)

	// Validate IP
	ip4 := ip.To4()
	if ip4 == nil {
		result.AddError("INVALID_IP", "reservation_ip", "Reservation IP must be valid IPv4")
		return result
	}

	// Check IP within pool range
	ipVal := ipToUint32(ip4)
	startVal := ipToUint32(poolStart.To4())
	endVal := ipToUint32(poolEnd.To4())

	if ipVal < startVal || ipVal > endVal {
		result.AddError("IP_OUTSIDE_POOL", "reservation_ip",
			fmt.Sprintf("Reservation IP %s not within pool range", ip))
	}

	return result
}

// ValidateMACAddress validates MAC address format.
func ValidateMACAddress(mac string) *ValidationResult {
	result := NewValidationResult()

	if mac == "" {
		result.AddError("EMPTY_MAC", "mac", "MAC address required")
		return result
	}

	if !MACAddressRegex.MatchString(mac) {
		result.AddError("INVALID_MAC_FORMAT", "mac",
			"MAC address must be in format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX")
		return result
	}

	// Parse and check for special MACs
	normalized := strings.ReplaceAll(strings.ToLower(mac), "-", ":")
	hw, err := net.ParseMAC(normalized)
	if err != nil {
		result.AddError("PARSE_MAC_FAILED", "mac", "Failed to parse MAC address")
		return result
	}

	// Check for all-zeros
	if isZeroMAC(hw) {
		result.AddError("ZERO_MAC", "mac", "Cannot use all-zero MAC address")
	}

	// Check for broadcast MAC
	if isBroadcastMAC(hw) {
		result.AddError("BROADCAST_MAC", "mac", "Cannot use broadcast MAC address")
	}

	return result
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0xFF {
			return false
		}
	}
	return true
}

// ============================================================================
// Overlap Detection Functions
// ============================================================================

// DetectRangeOverlap checks if two IP ranges overlap.
func DetectRangeOverlap(start1, end1, start2, end2 net.IP) (bool, net.IP, net.IP) {
	s1 := ipToUint32(start1.To4())
	e1 := ipToUint32(end1.To4())
	s2 := ipToUint32(start2.To4())
	e2 := ipToUint32(end2.To4())

	// No overlap if one range entirely before or after the other
	if e1 < s2 || e2 < s1 {
		return false, nil, nil
	}

	// Calculate overlap range
	overlapStart := max(s1, s2)
	overlapEnd := min(e1, e2)

	return true, uint32ToIP(overlapStart), uint32ToIP(overlapEnd)
}

// DetectSubnetOverlap checks if two subnets overlap.
func DetectSubnetOverlap(subnet1, subnet2 *net.IPNet) bool {
	if subnet1 == nil || subnet2 == nil {
		return false
	}

	// Check if network addresses are contained in each other
	return subnet1.Contains(subnet2.IP) || subnet2.Contains(subnet1.IP)
}

// ============================================================================
// Configuration Constraint Validation
// ============================================================================

// ValidateLeaseTimeConstraints validates lease time parameters.
func ValidateLeaseTimeConstraints(leaseTime, renewalTime, rebindingTime time.Duration) *ValidationResult {
	result := NewValidationResult()

	// Minimum lease time (5 minutes)
	if leaseTime < 5*time.Minute {
		result.AddError("LEASE_TOO_SHORT", "lease_time",
			fmt.Sprintf("Lease time %v too short (minimum 5 minutes)", leaseTime))
	}

	// Maximum lease time (7 days)
	if leaseTime > 7*24*time.Hour {
		result.AddWarning("LEASE_TOO_LONG", "lease_time",
			fmt.Sprintf("Lease time %v unusually long (>7 days)", leaseTime))
	}

	// T1 < T2 < lease time
	if renewalTime > 0 && rebindingTime > 0 {
		if renewalTime >= rebindingTime {
			result.AddError("T1_GE_T2", "renewal_time",
				"Renewal time (T1) must be less than rebinding time (T2)")
		}

		if rebindingTime >= leaseTime {
			result.AddError("T2_GE_LEASE", "rebinding_time",
				"Rebinding time (T2) must be less than lease time")
		}
	}

	return result
}

// ValidateGatewayAssignment confirms gateway configuration.
func ValidateGatewayAssignment(gateway net.IP, subnet *net.IPNet, rangeStart, rangeEnd net.IP) *ValidationResult {
	result := NewValidationResult()

	if gateway == nil || gateway.IsUnspecified() {
		return result // Gateway optional
	}

	gw4 := gateway.To4()
	if gw4 == nil {
		result.AddError("INVALID_GATEWAY", "gateway", "Gateway must be valid IPv4")
		return result
	}

	// Gateway must be in subnet
	if subnet != nil && !subnet.Contains(gw4) {
		result.AddError("GATEWAY_OUTSIDE_SUBNET", "gateway",
			fmt.Sprintf("Gateway %s not within subnet %s", gateway, subnet))
	}

	// Gateway should not be in allocation range
	if rangeStart != nil && rangeEnd != nil {
		gwVal := ipToUint32(gw4)
		startVal := ipToUint32(rangeStart.To4())
		endVal := ipToUint32(rangeEnd.To4())

		if gwVal >= startVal && gwVal <= endVal {
			result.AddError("GATEWAY_IN_RANGE", "gateway",
				"Gateway IP should not be in allocation range")
		}
	}

	return result
}

// ============================================================================
// RFC Compliance Validation
// ============================================================================

// ValidateRFC1918PrivateAddresses checks for private address space.
func ValidateRFC1918PrivateAddresses(ip net.IP) (bool, string) {
	ip4 := ip.To4()
	if ip4 == nil {
		return false, ""
	}

	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true, "10.0.0.0/8"
	}

	// 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true, "172.16.0.0/12"
	}

	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true, "192.168.0.0/16"
	}

	return false, ""
}

// ValidateReservedAddresses checks pool doesn't include reserved ranges.
func ValidateReservedAddresses(ip net.IP) *ValidationResult {
	result := NewValidationResult()

	ip4 := ip.To4()
	if ip4 == nil {
		return result
	}

	// 0.0.0.0/8 - This network
	if ip4[0] == 0 {
		result.AddError("RESERVED_THIS_NETWORK", "ip", "Cannot use 0.0.0.0/8 addresses")
	}

	// 127.0.0.0/8 - Loopback
	if ip4[0] == 127 {
		result.AddError("RESERVED_LOOPBACK", "ip", "Cannot use loopback addresses")
	}

	// 169.254.0.0/16 - Link-local
	if ip4[0] == 169 && ip4[1] == 254 {
		result.AddError("RESERVED_LINK_LOCAL", "ip", "Cannot use link-local addresses")
	}

	// 224.0.0.0/4 - Multicast
	if ip4[0] >= 224 && ip4[0] <= 239 {
		result.AddError("RESERVED_MULTICAST", "ip", "Cannot use multicast addresses")
	}

	// 240.0.0.0/4 - Experimental
	if ip4[0] >= 240 {
		result.AddError("RESERVED_EXPERIMENTAL", "ip", "Cannot use experimental addresses")
	}

	return result
}

// ============================================================================
// Helper Functions
// ============================================================================

func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

func calculateBroadcast(subnet *net.IPNet) net.IP {
	if subnet == nil {
		return nil
	}

	ip := subnet.IP.To4()
	mask := subnet.Mask

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

// ============================================================================
// Common Errors
// ============================================================================

var (
	ErrInvalidSubnet      = errors.New("invalid subnet configuration")
	ErrInvalidRange       = errors.New("invalid IP range")
	ErrInvalidReservation = errors.New("invalid reservation")
	ErrOverlappingRanges  = errors.New("overlapping IP ranges detected")
	ErrValidationFailed   = errors.New("validation failed")
)
