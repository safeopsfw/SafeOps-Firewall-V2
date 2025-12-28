// Package models defines core DHCP data structures.
// This file implements DHCP options including standard RFC 2132 and custom CA options.
package models

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ============================================================================
// OptionType Enumeration
// ============================================================================

// OptionType defines the data type for DHCP option values
type OptionType int

const (
	OptionTypeNone   OptionType = iota
	OptionTypeIP                // Single IPv4 address (4 bytes)
	OptionTypeIPList            // Multiple IPv4 addresses
	OptionTypeString            // ASCII string
	OptionTypeUint8             // 1-byte unsigned integer
	OptionTypeUint16            // 2-byte unsigned integer
	OptionTypeUint32            // 4-byte unsigned integer
	OptionTypeBool              // Boolean (1 byte)
	OptionTypeBinary            // Raw binary data
)

// String returns human-readable type name
func (t OptionType) String() string {
	switch t {
	case OptionTypeNone:
		return "None"
	case OptionTypeIP:
		return "IP"
	case OptionTypeIPList:
		return "IPList"
	case OptionTypeString:
		return "String"
	case OptionTypeUint8:
		return "Uint8"
	case OptionTypeUint16:
		return "Uint16"
	case OptionTypeUint32:
		return "Uint32"
	case OptionTypeBool:
		return "Bool"
	case OptionTypeBinary:
		return "Binary"
	default:
		return "Unknown"
	}
}

// ============================================================================
// DHCPOption Structure
// ============================================================================

// DHCPOption represents a DHCP option in TLV format.
type DHCPOption struct {
	Code   uint8      // Option code (1-255)
	Length uint8      // Option data length
	Data   []byte     // Raw option value
	Type   OptionType // Parsed data type
}

// ============================================================================
// Option Constructor Functions
// ============================================================================

// NewDHCPOption creates an option with the given code and data.
func NewDHCPOption(code uint8, data []byte) *DHCPOption {
	return &DHCPOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
		Type:   inferOptionType(code),
	}
}

// NewIPOption creates an option with a single IPv4 address.
func NewIPOption(code uint8, ip net.IP) *DHCPOption {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   []byte(ip4),
		Type:   OptionTypeIP,
	}
}

// NewIPListOption creates an option with multiple IPv4 addresses.
func NewIPListOption(code uint8, ips []net.IP) *DHCPOption {
	data := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			data = append(data, ip4...)
		}
	}
	return &DHCPOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
		Type:   OptionTypeIPList,
	}
}

// NewStringOption creates an option with an ASCII string.
func NewStringOption(code uint8, value string) *DHCPOption {
	return &DHCPOption{
		Code:   code,
		Length: uint8(len(value)),
		Data:   []byte(value),
		Type:   OptionTypeString,
	}
}

// NewUint8Option creates an option with a 1-byte integer.
func NewUint8Option(code uint8, value uint8) *DHCPOption {
	return &DHCPOption{
		Code:   code,
		Length: 1,
		Data:   []byte{value},
		Type:   OptionTypeUint8,
	}
}

// NewUint16Option creates an option with a 2-byte integer.
func NewUint16Option(code uint8, value uint16) *DHCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return &DHCPOption{
		Code:   code,
		Length: 2,
		Data:   data,
		Type:   OptionTypeUint16,
	}
}

// NewUint32Option creates an option with a 4-byte integer.
func NewUint32Option(code uint8, value uint32) *DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   data,
		Type:   OptionTypeUint32,
	}
}

// NewBoolOption creates an option with a boolean value.
func NewBoolOption(code uint8, value bool) *DHCPOption {
	data := []byte{0}
	if value {
		data[0] = 1
	}
	return &DHCPOption{
		Code:   code,
		Length: 1,
		Data:   data,
		Type:   OptionTypeBool,
	}
}

// ============================================================================
// Option Parsing Methods
// ============================================================================

// AsIP parses the option data as a single IPv4 address.
func (o *DHCPOption) AsIP() (net.IP, error) {
	if len(o.Data) != 4 {
		return nil, fmt.Errorf("invalid IP option length: %d (expected 4)", len(o.Data))
	}
	return net.IP(o.Data), nil
}

// AsIPList parses the option data as multiple IPv4 addresses.
func (o *DHCPOption) AsIPList() ([]net.IP, error) {
	if len(o.Data)%4 != 0 {
		return nil, fmt.Errorf("invalid IP list length: %d (must be multiple of 4)", len(o.Data))
	}

	ips := make([]net.IP, 0, len(o.Data)/4)
	for i := 0; i < len(o.Data); i += 4 {
		ips = append(ips, net.IP(o.Data[i:i+4]))
	}
	return ips, nil
}

// AsString parses the option data as an ASCII string.
func (o *DHCPOption) AsString() string {
	// Trim null terminator if present
	s := string(o.Data)
	return strings.TrimRight(s, "\x00")
}

// AsUint8 parses the option data as a 1-byte integer.
func (o *DHCPOption) AsUint8() (uint8, error) {
	if len(o.Data) < 1 {
		return 0, errors.New("option data too short for uint8")
	}
	return o.Data[0], nil
}

// AsUint16 parses the option data as a 2-byte integer.
func (o *DHCPOption) AsUint16() (uint16, error) {
	if len(o.Data) < 2 {
		return 0, errors.New("option data too short for uint16")
	}
	return binary.BigEndian.Uint16(o.Data), nil
}

// AsUint32 parses the option data as a 4-byte integer.
func (o *DHCPOption) AsUint32() (uint32, error) {
	if len(o.Data) < 4 {
		return 0, errors.New("option data too short for uint32")
	}
	return binary.BigEndian.Uint32(o.Data), nil
}

// AsBool parses the option data as a boolean.
func (o *DHCPOption) AsBool() (bool, error) {
	if len(o.Data) < 1 {
		return false, errors.New("option data too short for bool")
	}
	return o.Data[0] != 0, nil
}

// ============================================================================
// Option Validation Methods
// ============================================================================

// Validate checks option data integrity.
func (o *DHCPOption) Validate() error {
	if int(o.Length) != len(o.Data) {
		return fmt.Errorf("length mismatch: field=%d actual=%d", o.Length, len(o.Data))
	}
	if len(o.Data) > 255 {
		return fmt.Errorf("option data exceeds maximum length: %d > 255", len(o.Data))
	}
	return nil
}

// ============================================================================
// String Representation
// ============================================================================

// String returns a human-readable option description.
func (o *DHCPOption) String() string {
	var value string

	switch o.Type {
	case OptionTypeIP:
		if ip, err := o.AsIP(); err == nil {
			value = ip.String()
		}
	case OptionTypeIPList:
		if ips, err := o.AsIPList(); err == nil {
			strs := make([]string, len(ips))
			for i, ip := range ips {
				strs[i] = ip.String()
			}
			value = strings.Join(strs, ",")
		}
	case OptionTypeString:
		value = o.AsString()
	case OptionTypeUint8:
		if v, err := o.AsUint8(); err == nil {
			value = fmt.Sprintf("%d", v)
		}
	case OptionTypeUint16:
		if v, err := o.AsUint16(); err == nil {
			value = fmt.Sprintf("%d", v)
		}
	case OptionTypeUint32:
		if v, err := o.AsUint32(); err == nil {
			value = fmt.Sprintf("%d", v)
		}
	case OptionTypeBool:
		if v, err := o.AsBool(); err == nil {
			value = fmt.Sprintf("%v", v)
		}
	default:
		value = fmt.Sprintf("%x", o.Data)
	}

	return fmt.Sprintf("Option[Code=%d Type=%s Value=%s]", o.Code, o.Type, value)
}

// ============================================================================
// OptionList Container
// ============================================================================

// OptionList is a container for multiple DHCP options.
type OptionList struct {
	Options []*DHCPOption
}

// NewOptionList creates an empty option list.
func NewOptionList() *OptionList {
	return &OptionList{
		Options: make([]*DHCPOption, 0),
	}
}

// Add appends an option, replacing any existing option with the same code.
func (l *OptionList) Add(opt *DHCPOption) {
	// Remove existing option with same code
	l.Remove(opt.Code)
	l.Options = append(l.Options, opt)
}

// Get retrieves an option by code.
func (l *OptionList) Get(code uint8) (*DHCPOption, bool) {
	for _, opt := range l.Options {
		if opt.Code == code {
			return opt, true
		}
	}
	return nil, false
}

// Remove deletes an option by code.
func (l *OptionList) Remove(code uint8) {
	filtered := make([]*DHCPOption, 0, len(l.Options))
	for _, opt := range l.Options {
		if opt.Code != code {
			filtered = append(filtered, opt)
		}
	}
	l.Options = filtered
}

// Has returns true if an option with the code exists.
func (l *OptionList) Has(code uint8) bool {
	_, found := l.Get(code)
	return found
}

// Len returns the count of options.
func (l *OptionList) Len() int {
	return len(l.Options)
}

// ToBytes serializes all options to TLV wire format.
func (l *OptionList) ToBytes() []byte {
	var buf []byte
	for _, opt := range l.Options {
		if opt.Code == 0 { // Pad
			buf = append(buf, 0)
		} else {
			buf = append(buf, opt.Code, opt.Length)
			buf = append(buf, opt.Data...)
		}
	}
	buf = append(buf, 255) // End option
	return buf
}

// ============================================================================
// ⭐ Custom CA Certificate Option Structures
// ============================================================================

// CACertURLOption represents Option 224 for CA certificate URL.
// ⭐ CA INTEGRATION - Zero-touch TLS proxy setup
type CACertURLOption struct {
	URL string // e.g., "http://192.168.1.1/ca.crt"
}

// ToOption converts to DHCPOption.
func (o *CACertURLOption) ToOption() *DHCPOption {
	return NewStringOption(224, o.URL)
}

// InstallScriptURLsOption represents Option 225 for CA install scripts.
// ⭐ CA INTEGRATION - Automated CA deployment
type InstallScriptURLsOption struct {
	URLs []string // e.g., ["http://192.168.1.1/install-ca.sh", "...ps1"]
}

// ToOption converts to DHCPOption (comma-separated URLs).
func (o *InstallScriptURLsOption) ToOption() *DHCPOption {
	return NewStringOption(225, strings.Join(o.URLs, ","))
}

// ParseInstallScriptURLs parses comma-separated URLs from option data.
func ParseInstallScriptURLs(opt *DHCPOption) *InstallScriptURLsOption {
	s := opt.AsString()
	urls := strings.Split(s, ",")
	return &InstallScriptURLsOption{URLs: urls}
}

// WPADURLOption represents Option 252 for Web Proxy Auto-Discovery.
// ⭐ CA INTEGRATION - Proxy auto-configuration
type WPADURLOption struct {
	URL string // e.g., "http://192.168.1.1/wpad.dat"
}

// ToOption converts to DHCPOption.
func (o *WPADURLOption) ToOption() *DHCPOption {
	return NewStringOption(252, o.URL)
}

// ============================================================================
// Standard Option Structures
// ============================================================================

// SubnetMaskOption represents Option 1.
type SubnetMaskOption struct {
	Mask net.IPMask
}

// ToOption converts to DHCPOption.
func (o *SubnetMaskOption) ToOption() *DHCPOption {
	return NewIPOption(1, net.IP(o.Mask))
}

// RouterOption represents Option 3 (default gateway).
type RouterOption struct {
	Routers []net.IP
}

// ToOption converts to DHCPOption.
func (o *RouterOption) ToOption() *DHCPOption {
	return NewIPListOption(3, o.Routers)
}

// DNSServerOption represents Option 6.
type DNSServerOption struct {
	Servers []net.IP
}

// ToOption converts to DHCPOption.
func (o *DNSServerOption) ToOption() *DHCPOption {
	return NewIPListOption(6, o.Servers)
}

// HostnameOption represents Option 12.
type HostnameOption struct {
	Hostname string
}

// ToOption converts to DHCPOption.
func (o *HostnameOption) ToOption() *DHCPOption {
	return NewStringOption(12, o.Hostname)
}

// DomainNameOption represents Option 15.
type DomainNameOption struct {
	DomainName string
}

// ToOption converts to DHCPOption.
func (o *DomainNameOption) ToOption() *DHCPOption {
	return NewStringOption(15, o.DomainName)
}

// LeaseTimeOption represents Option 51.
type LeaseTimeOption struct {
	Seconds uint32
}

// ToOption converts to DHCPOption.
func (o *LeaseTimeOption) ToOption() *DHCPOption {
	return NewUint32Option(51, o.Seconds)
}

// MessageTypeOption represents Option 53.
type MessageTypeOption struct {
	Type uint8 // 1-8 (DISCOVER, OFFER, etc.)
}

// ToOption converts to DHCPOption.
func (o *MessageTypeOption) ToOption() *DHCPOption {
	return NewUint8Option(53, o.Type)
}

// ServerIdentifierOption represents Option 54.
type ServerIdentifierOption struct {
	ServerIP net.IP
}

// ToOption converts to DHCPOption.
func (o *ServerIdentifierOption) ToOption() *DHCPOption {
	return NewIPOption(54, o.ServerIP)
}

// NTPServerOption represents Option 42.
type NTPServerOption struct {
	Servers []net.IP
}

// ToOption converts to DHCPOption.
func (o *NTPServerOption) ToOption() *DHCPOption {
	return NewIPListOption(42, o.Servers)
}

// ============================================================================
// Helper Functions
// ============================================================================

// inferOptionType returns the expected type for an option code.
func inferOptionType(code uint8) OptionType {
	switch code {
	case 1, 28, 50, 54: // Subnet mask, broadcast, requested IP, server ID
		return OptionTypeIP
	case 3, 4, 5, 6, 7, 41, 42, 44, 45: // Routers, DNS, NTP, etc.
		return OptionTypeIPList
	case 12, 14, 15, 56, 66, 67, 224, 225, 252: // Hostnames, strings, CA URLs
		return OptionTypeString
	case 51, 58, 59: // Lease time, renewal, rebinding
		return OptionTypeUint32
	case 57: // Max message size
		return OptionTypeUint16
	case 53, 52: // Message type, overload
		return OptionTypeUint8
	case 19, 20, 27, 29, 30, 31: // Boolean options
		return OptionTypeBool
	default:
		return OptionTypeBinary
	}
}
