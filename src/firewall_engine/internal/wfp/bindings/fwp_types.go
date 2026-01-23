// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// ============================================================================
// FWP_BYTE_BLOB - Binary data blob
// ============================================================================
// Used for variable-length binary data like application paths, SIDs, etc.

// FWP_BYTE_BLOB contains a variable-length binary data buffer.
// This is the Go representation of the Windows FWP_BYTE_BLOB structure.
type FWP_BYTE_BLOB struct {
	Size uint32         // Size in bytes of the data
	Data unsafe.Pointer // Pointer to the data (use with care)
}

// NewByteBlob creates a new FWP_BYTE_BLOB from a byte slice.
// The data is NOT copied - the blob points to the original slice.
// IMPORTANT: Keep the original slice alive while the blob is in use.
func NewByteBlob(data []byte) *FWP_BYTE_BLOB {
	if len(data) == 0 {
		return &FWP_BYTE_BLOB{Size: 0, Data: nil}
	}
	return &FWP_BYTE_BLOB{
		Size: uint32(len(data)),
		Data: unsafe.Pointer(&data[0]),
	}
}

// NewByteBlobCopy creates a new FWP_BYTE_BLOB with a copy of the data.
// The returned blob owns its data and doesn't depend on the original slice.
func NewByteBlobCopy(data []byte) (*FWP_BYTE_BLOB, []byte) {
	if len(data) == 0 {
		return &FWP_BYTE_BLOB{Size: 0, Data: nil}, nil
	}

	// Make a copy
	copied := make([]byte, len(data))
	copy(copied, data)

	return &FWP_BYTE_BLOB{
		Size: uint32(len(copied)),
		Data: unsafe.Pointer(&copied[0]),
	}, copied
}

// GetData returns the data as a byte slice.
// Returns nil if Size is 0 or Data is nil.
func (b *FWP_BYTE_BLOB) GetData() []byte {
	if b == nil || b.Size == 0 || b.Data == nil {
		return nil
	}
	return unsafe.Slice((*byte)(b.Data), b.Size)
}

// IsEmpty returns true if the blob is empty.
func (b *FWP_BYTE_BLOB) IsEmpty() bool {
	return b == nil || b.Size == 0 || b.Data == nil
}

// ============================================================================
// FWP_BYTE_ARRAY16 - Fixed 16-byte array (IPv6 addresses)
// ============================================================================

// FWP_BYTE_ARRAY16 is a fixed 16-byte array, used for IPv6 addresses.
type FWP_BYTE_ARRAY16 [16]byte

// NewByteArray16 creates a FWP_BYTE_ARRAY16 from a byte slice.
func NewByteArray16(data []byte) FWP_BYTE_ARRAY16 {
	var arr FWP_BYTE_ARRAY16
	if len(data) >= 16 {
		copy(arr[:], data[:16])
	} else {
		copy(arr[:], data)
	}
	return arr
}

// NewByteArray16FromIP creates a FWP_BYTE_ARRAY16 from a net.IP (IPv6).
func NewByteArray16FromIP(ip net.IP) FWP_BYTE_ARRAY16 {
	var arr FWP_BYTE_ARRAY16
	ip6 := ip.To16()
	if ip6 != nil {
		copy(arr[:], ip6)
	}
	return arr
}

// ToIP converts to net.IP.
func (a FWP_BYTE_ARRAY16) ToIP() net.IP {
	return net.IP(a[:])
}

// ============================================================================
// FWP_BYTE_ARRAY6 - Fixed 6-byte array (MAC addresses)
// ============================================================================

// FWP_BYTE_ARRAY6 is a fixed 6-byte array, used for MAC addresses.
type FWP_BYTE_ARRAY6 [6]byte

// NewByteArray6 creates a FWP_BYTE_ARRAY6 from a byte slice.
func NewByteArray6(data []byte) FWP_BYTE_ARRAY6 {
	var arr FWP_BYTE_ARRAY6
	if len(data) >= 6 {
		copy(arr[:], data[:6])
	} else {
		copy(arr[:], data)
	}
	return arr
}

// String returns the MAC address as a string.
func (a FWP_BYTE_ARRAY6) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		a[0], a[1], a[2], a[3], a[4], a[5])
}

// ============================================================================
// FWP_V4_ADDR_AND_MASK - IPv4 address with subnet mask (CIDR)
// ============================================================================

// FWP_V4_ADDR_AND_MASK represents an IPv4 address and subnet mask.
// Used for prefix matching (CIDR notation like 192.168.0.0/16).
type FWP_V4_ADDR_AND_MASK struct {
	Addr uint32 // IPv4 address in network byte order
	Mask uint32 // Subnet mask in network byte order
}

// NewV4AddrAndMask creates a FWP_V4_ADDR_AND_MASK from IP and prefix length.
// Example: NewV4AddrAndMask(net.ParseIP("192.168.0.0"), 16)
func NewV4AddrAndMask(ip net.IP, prefixLen int) *FWP_V4_ADDR_AND_MASK {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	// Convert IP to uint32 (network byte order)
	addr := binary.BigEndian.Uint32(ip4)

	// Calculate mask from prefix length
	var mask uint32 = 0
	if prefixLen > 0 && prefixLen <= 32 {
		mask = ^uint32(0) << (32 - prefixLen)
	}

	return &FWP_V4_ADDR_AND_MASK{
		Addr: addr,
		Mask: mask,
	}
}

// NewV4AddrAndMaskFromCIDR creates a FWP_V4_ADDR_AND_MASK from CIDR string.
// Example: NewV4AddrAndMaskFromCIDR("192.168.0.0/16")
func NewV4AddrAndMaskFromCIDR(cidr string) (*FWP_V4_ADDR_AND_MASK, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}

	prefixLen, _ := ipNet.Mask.Size()
	return NewV4AddrAndMask(ipNet.IP, prefixLen), nil
}

// NewV4AddrExact creates a FWP_V4_ADDR_AND_MASK for exact IP match (/32).
func NewV4AddrExact(ip net.IP) *FWP_V4_ADDR_AND_MASK {
	return NewV4AddrAndMask(ip, 32)
}

// ToIP converts the address to net.IP.
func (v *FWP_V4_ADDR_AND_MASK) ToIP() net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v.Addr)
	return ip
}

// ToCIDR returns the CIDR string representation.
func (v *FWP_V4_ADDR_AND_MASK) ToCIDR() string {
	ip := v.ToIP()
	mask := net.IPMask(make([]byte, 4))
	binary.BigEndian.PutUint32(mask, v.Mask)
	prefixLen, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}

// Contains checks if the given IP is within this network.
func (v *FWP_V4_ADDR_AND_MASK) Contains(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	ipVal := binary.BigEndian.Uint32(ip4)
	return (ipVal & v.Mask) == (v.Addr & v.Mask)
}

// ============================================================================
// FWP_V6_ADDR_AND_PREFIX - IPv6 address with prefix length
// ============================================================================

// FWP_V6_ADDR_AND_PREFIX represents an IPv6 address and prefix length.
type FWP_V6_ADDR_AND_PREFIX struct {
	Addr         FWP_BYTE_ARRAY16 // IPv6 address (16 bytes)
	PrefixLength uint8            // Prefix length (0-128)
	_            [3]byte          // Padding for alignment
}

// NewV6AddrAndPrefix creates a FWP_V6_ADDR_AND_PREFIX from IP and prefix length.
func NewV6AddrAndPrefix(ip net.IP, prefixLen int) *FWP_V6_ADDR_AND_PREFIX {
	if prefixLen < 0 || prefixLen > 128 {
		prefixLen = 128
	}
	return &FWP_V6_ADDR_AND_PREFIX{
		Addr:         NewByteArray16FromIP(ip),
		PrefixLength: uint8(prefixLen),
	}
}

// NewV6AddrExact creates a FWP_V6_ADDR_AND_PREFIX for exact IP match (/128).
func NewV6AddrExact(ip net.IP) *FWP_V6_ADDR_AND_PREFIX {
	return NewV6AddrAndPrefix(ip, 128)
}

// ToCIDR returns the CIDR string representation.
func (v *FWP_V6_ADDR_AND_PREFIX) ToCIDR() string {
	return fmt.Sprintf("%s/%d", v.Addr.ToIP().String(), v.PrefixLength)
}

// ============================================================================
// FWP_RANGE0 - Value range (for port ranges, etc.)
// ============================================================================

// FWP_RANGE0 represents a range of values (low to high, inclusive).
// Used for port ranges like 1000-2000.
type FWP_RANGE0 struct {
	ValueLow  FWP_VALUE0 // Lower bound (inclusive)
	ValueHigh FWP_VALUE0 // Upper bound (inclusive)
}

// NewUint16Range creates a FWP_RANGE0 for a uint16 range (e.g., port range).
func NewUint16Range(low, high uint16) *FWP_RANGE0 {
	return &FWP_RANGE0{
		ValueLow:  NewUint16Value(low),
		ValueHigh: NewUint16Value(high),
	}
}

// NewUint32Range creates a FWP_RANGE0 for a uint32 range.
func NewUint32Range(low, high uint32) *FWP_RANGE0 {
	return &FWP_RANGE0{
		ValueLow:  NewUint32Value(low),
		ValueHigh: NewUint32Value(high),
	}
}

// ============================================================================
// FWP_VALUE0 - Universal value container (union type)
// ============================================================================
// FWP_VALUE0 is WFP's universal value container that can hold different data types.
// In C, this is implemented as a union. In Go, we use a type field and interface{}.

// FWP_VALUE0 represents a value that can be of different types.
// This is the Go representation of the Windows FWP_VALUE0 union.
type FWP_VALUE0 struct {
	Type  FWP_DATA_TYPE // The type of value stored
	Value interface{}   // The actual value (type depends on Type field)
}

// NewEmptyValue creates an empty FWP_VALUE0.
func NewEmptyValue() FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_EMPTY, Value: nil}
}

// NewUint8Value creates a FWP_VALUE0 containing a uint8.
// Used for: IP protocol (TCP=6, UDP=17), ICMP type/code.
func NewUint8Value(v uint8) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_UINT8, Value: v}
}

// NewUint16Value creates a FWP_VALUE0 containing a uint16.
// Used for: Port numbers.
func NewUint16Value(v uint16) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_UINT16, Value: v}
}

// NewUint32Value creates a FWP_VALUE0 containing a uint32.
// Used for: IPv4 addresses, flags.
func NewUint32Value(v uint32) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_UINT32, Value: v}
}

// NewUint64Value creates a FWP_VALUE0 containing a uint64.
// Used for: Large numeric values.
func NewUint64Value(v uint64) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_UINT64, Value: v}
}

// NewInt8Value creates a FWP_VALUE0 containing an int8.
func NewInt8Value(v int8) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_INT8, Value: v}
}

// NewInt16Value creates a FWP_VALUE0 containing an int16.
func NewInt16Value(v int16) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_INT16, Value: v}
}

// NewInt32Value creates a FWP_VALUE0 containing an int32.
func NewInt32Value(v int32) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_INT32, Value: v}
}

// NewInt64Value creates a FWP_VALUE0 containing an int64.
func NewInt64Value(v int64) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_INT64, Value: v}
}

// NewFloatValue creates a FWP_VALUE0 containing a float32.
func NewFloatValue(v float32) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_FLOAT, Value: v}
}

// NewDoubleValue creates a FWP_VALUE0 containing a float64.
func NewDoubleValue(v float64) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_DOUBLE, Value: v}
}

// NewByteArray16Value creates a FWP_VALUE0 containing a 16-byte array (IPv6).
func NewByteArray16Value(arr FWP_BYTE_ARRAY16) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_BYTE_ARRAY16_TYPE, Value: arr}
}

// NewByteBlobValue creates a FWP_VALUE0 containing a byte blob.
func NewByteBlobValue(blob *FWP_BYTE_BLOB) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_BYTE_BLOB_TYPE, Value: blob}
}

// NewV4AddrMaskValue creates a FWP_VALUE0 containing an IPv4 address/mask.
func NewV4AddrMaskValue(v *FWP_V4_ADDR_AND_MASK) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_V4_ADDR_MASK, Value: v}
}

// NewV6AddrPrefixValue creates a FWP_VALUE0 containing an IPv6 address/prefix.
func NewV6AddrPrefixValue(v *FWP_V6_ADDR_AND_PREFIX) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_V6_ADDR_MASK, Value: v}
}

// NewRangeValue creates a FWP_VALUE0 containing a range.
func NewRangeValue(r *FWP_RANGE0) FWP_VALUE0 {
	return FWP_VALUE0{Type: FWP_RANGE_TYPE, Value: r}
}

// ============================================================================
// FWP_VALUE0 High-Level Constructors
// ============================================================================

// NewIPv4Value creates a FWP_VALUE0 for an IPv4 address (exact match).
func NewIPv4Value(ip net.IP) FWP_VALUE0 {
	ip4 := ip.To4()
	if ip4 == nil {
		return NewEmptyValue()
	}
	// Convert to uint32 in network byte order
	addr := binary.BigEndian.Uint32(ip4)
	return NewUint32Value(addr)
}

// NewIPv6Value creates a FWP_VALUE0 for an IPv6 address (exact match).
func NewIPv6Value(ip net.IP) FWP_VALUE0 {
	return NewByteArray16Value(NewByteArray16FromIP(ip))
}

// NewIPValue creates a FWP_VALUE0 for an IP address (detects v4 or v6).
func NewIPValue(ip net.IP) FWP_VALUE0 {
	if ip4 := ip.To4(); ip4 != nil {
		return NewIPv4Value(ip)
	}
	return NewIPv6Value(ip)
}

// NewPortValue creates a FWP_VALUE0 for a port number.
func NewPortValue(port uint16) FWP_VALUE0 {
	return NewUint16Value(port)
}

// NewProtocolValue creates a FWP_VALUE0 for an IP protocol.
func NewProtocolValue(protocol uint8) FWP_VALUE0 {
	return NewUint8Value(protocol)
}

// NewDirectionValue creates a FWP_VALUE0 for packet direction.
func NewDirectionValue(outbound bool) FWP_VALUE0 {
	if outbound {
		return NewUint32Value(uint32(FWP_DIRECTION_OUTBOUND))
	}
	return NewUint32Value(uint32(FWP_DIRECTION_INBOUND))
}

// ============================================================================
// FWP_VALUE0 Getters
// ============================================================================

// GetUint8 returns the uint8 value, or 0 if type doesn't match.
func (v FWP_VALUE0) GetUint8() uint8 {
	if v.Type == FWP_UINT8 {
		if val, ok := v.Value.(uint8); ok {
			return val
		}
	}
	return 0
}

// GetUint16 returns the uint16 value, or 0 if type doesn't match.
func (v FWP_VALUE0) GetUint16() uint16 {
	if v.Type == FWP_UINT16 {
		if val, ok := v.Value.(uint16); ok {
			return val
		}
	}
	return 0
}

// GetUint32 returns the uint32 value, or 0 if type doesn't match.
func (v FWP_VALUE0) GetUint32() uint32 {
	if v.Type == FWP_UINT32 {
		if val, ok := v.Value.(uint32); ok {
			return val
		}
	}
	return 0
}

// GetUint64 returns the uint64 value, or 0 if type doesn't match.
func (v FWP_VALUE0) GetUint64() uint64 {
	if v.Type == FWP_UINT64 {
		if val, ok := v.Value.(uint64); ok {
			return val
		}
	}
	return 0
}

// GetByteBlob returns the byte blob value, or nil if type doesn't match.
func (v FWP_VALUE0) GetByteBlob() *FWP_BYTE_BLOB {
	if v.Type == FWP_BYTE_BLOB_TYPE {
		if val, ok := v.Value.(*FWP_BYTE_BLOB); ok {
			return val
		}
	}
	return nil
}

// GetV4AddrMask returns the IPv4 address/mask, or nil if type doesn't match.
func (v FWP_VALUE0) GetV4AddrMask() *FWP_V4_ADDR_AND_MASK {
	if v.Type == FWP_V4_ADDR_MASK {
		if val, ok := v.Value.(*FWP_V4_ADDR_AND_MASK); ok {
			return val
		}
	}
	return nil
}

// GetRange returns the range value, or nil if type doesn't match.
func (v FWP_VALUE0) GetRange() *FWP_RANGE0 {
	if v.Type == FWP_RANGE_TYPE {
		if val, ok := v.Value.(*FWP_RANGE0); ok {
			return val
		}
	}
	return nil
}

// IsEmpty returns true if the value is empty.
func (v FWP_VALUE0) IsEmpty() bool {
	return v.Type == FWP_EMPTY
}

// String returns a string representation of the value.
func (v FWP_VALUE0) String() string {
	switch v.Type {
	case FWP_EMPTY:
		return "<empty>"
	case FWP_UINT8:
		return fmt.Sprintf("%d (uint8)", v.GetUint8())
	case FWP_UINT16:
		return fmt.Sprintf("%d (uint16)", v.GetUint16())
	case FWP_UINT32:
		return fmt.Sprintf("%d (uint32)", v.GetUint32())
	case FWP_UINT64:
		return fmt.Sprintf("%d (uint64)", v.GetUint64())
	case FWP_BYTE_BLOB_TYPE:
		blob := v.GetByteBlob()
		if blob != nil {
			return fmt.Sprintf("<blob: %d bytes>", blob.Size)
		}
		return "<blob: nil>"
	case FWP_V4_ADDR_MASK:
		mask := v.GetV4AddrMask()
		if mask != nil {
			return mask.ToCIDR()
		}
		return "<v4mask: nil>"
	case FWP_RANGE_TYPE:
		r := v.GetRange()
		if r != nil {
			return fmt.Sprintf("%v-%v", r.ValueLow, r.ValueHigh)
		}
		return "<range: nil>"
	default:
		return fmt.Sprintf("<type:%d>", v.Type)
	}
}

// ============================================================================
// FWP_CONDITION_VALUE0 - Condition value for filter matching
// ============================================================================
// This is similar to FWP_VALUE0 but used specifically in filter conditions.

// FWP_CONDITION_VALUE0 holds a value for filter condition matching.
// Alias for FWP_VALUE0 (in Windows they have identical structure).
type FWP_CONDITION_VALUE0 = FWP_VALUE0

// ============================================================================
// FWP_ACTION0 - Filter action
// ============================================================================

// FWP_ACTION0 specifies the action to take when a filter matches.
type FWP_ACTION0 struct {
	Type FWP_ACTION_TYPE // Action type (BLOCK, PERMIT, CALLOUT)
	// For callouts, this would also contain the callout GUID
	// But we're not implementing callouts in Phase 4
}

// NewBlockAction creates an action that blocks packets.
func NewBlockAction() FWP_ACTION0 {
	return FWP_ACTION0{Type: FWP_ACTION_BLOCK}
}

// NewPermitAction creates an action that permits packets.
func NewPermitAction() FWP_ACTION0 {
	return FWP_ACTION0{Type: FWP_ACTION_PERMIT}
}

// IsBlock returns true if this is a block action.
func (a FWP_ACTION0) IsBlock() bool {
	return a.Type == FWP_ACTION_BLOCK
}

// IsPermit returns true if this is a permit action.
func (a FWP_ACTION0) IsPermit() bool {
	return a.Type == FWP_ACTION_PERMIT
}

// String returns a string representation.
func (a FWP_ACTION0) String() string {
	return a.Type.String()
}

// ============================================================================
// Weight Types
// ============================================================================

// FilterWeight represents filter priority (higher = evaluated first).
type FilterWeight struct {
	Type  uint8  // 0 = empty, 1 = uint8, 2 = uint64
	Value uint64 // The weight value
}

// NewEmptyWeight creates an empty weight (Windows assigns default).
func NewEmptyWeight() FilterWeight {
	return FilterWeight{Type: 0, Value: 0}
}

// NewUint8Weight creates a weight from a uint8 (0-255, commonly used).
func NewUint8Weight(w uint8) FilterWeight {
	return FilterWeight{Type: 1, Value: uint64(w)}
}

// NewUint64Weight creates a weight from a uint64 (full range).
func NewUint64Weight(w uint64) FilterWeight {
	return FilterWeight{Type: 2, Value: w}
}

// IsEmpty returns true if weight is empty.
func (w FilterWeight) IsEmpty() bool {
	return w.Type == 0
}

// ============================================================================
// Convenience Functions for Common Conditions
// ============================================================================

// NewRemoteIPv4Condition creates a condition for matching remote IPv4 address.
func NewRemoteIPv4Condition(ip net.IP, prefixLen int) (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	if prefixLen == 32 {
		// Exact match
		return FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, NewIPv4Value(ip)
	}
	// Prefix match
	mask := NewV4AddrAndMask(ip, prefixLen)
	return FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_PREFIX, NewV4AddrMaskValue(mask)
}

// NewRemotePortCondition creates a condition for matching remote port.
func NewRemotePortCondition(port uint16) (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	return FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, NewPortValue(port)
}

// GetRemotePortRangeCondition returns condition components for matching port range.
// Use NewRemotePortRangeCondition in fwpm_types.go for the full condition struct.
func GetRemotePortRangeCondition(lowPort, highPort uint16) (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	r := NewUint16Range(lowPort, highPort)
	return FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_RANGE, NewRangeValue(r)
}

// NewProtocolCondition creates a condition for matching IP protocol.
func NewProtocolCondition(protocol uint8) (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	return FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, NewProtocolValue(protocol)
}

// NewTCPCondition creates a condition for matching TCP protocol.
func NewTCPCondition() (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	return NewProtocolCondition(IPPROTO_TCP)
}

// NewUDPCondition creates a condition for matching UDP protocol.
func NewUDPCondition() (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	return NewProtocolCondition(IPPROTO_UDP)
}

// NewICMPCondition creates a condition for matching ICMP protocol.
func NewICMPCondition() (GUID, FWP_MATCH_TYPE, FWP_VALUE0) {
	return NewProtocolCondition(IPPROTO_ICMP)
}
