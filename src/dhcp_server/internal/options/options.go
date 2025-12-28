// Package options provides DHCP option handling including parsing and building.
// This file coordinates standard RFC 2132 options and custom CA certificate options.
package options

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// Constants
// ============================================================================

const (
	OptionEnd       uint8 = 255
	OptionPad       uint8 = 0
	MaxOptionLength       = 255
	OptionsOffset         = 236 // Start of options in DHCP packet
)

// ============================================================================
// OptionHandler Structure
// ============================================================================

// OptionHandler coordinates all DHCP option processing.
type OptionHandler struct {
	serverIP net.IP // Server identifier for Option 54
}

// NewOptionHandler creates a new options handler.
func NewOptionHandler(serverIP net.IP) *OptionHandler {
	return &OptionHandler{
		serverIP: serverIP,
	}
}

// ============================================================================
// DHCPOption Structure (local to this package)
// ============================================================================

// DHCPOption represents a DHCP option in TLV format.
type DHCPOption struct {
	Code   uint8
	Length uint8
	Data   []byte
}

// ============================================================================
// Parse Methods
// ============================================================================

// ParseOptions extracts all options from raw DHCP packet bytes.
// Starts parsing at offset 240 (after magic cookie).
func (h *OptionHandler) ParseOptions(packet []byte) ([]*DHCPOption, error) {
	if len(packet) < OptionsOffset+4 {
		return nil, errors.New("packet too short for options")
	}

	// Skip to options (after magic cookie at 236-240)
	offset := 240
	options := make([]*DHCPOption, 0)

	for offset < len(packet) {
		code := packet[offset]

		if code == OptionEnd {
			break
		}

		if code == OptionPad {
			offset++
			continue
		}

		if offset+1 >= len(packet) {
			return nil, errors.New("truncated option: no length byte")
		}

		length := int(packet[offset+1])
		if offset+2+length > len(packet) {
			return nil, fmt.Errorf("truncated option %d: need %d bytes", code, length)
		}

		data := make([]byte, length)
		copy(data, packet[offset+2:offset+2+length])

		options = append(options, &DHCPOption{
			Code:   code,
			Length: uint8(length),
			Data:   data,
		})

		offset += 2 + length
	}

	return options, nil
}

// ParseSingleOption extracts a specific option from the packet.
func (h *OptionHandler) ParseSingleOption(packet []byte, code uint8) (*DHCPOption, error) {
	options, err := h.ParseOptions(packet)
	if err != nil {
		return nil, err
	}

	for _, opt := range options {
		if opt.Code == code {
			return opt, nil
		}
	}

	return nil, nil // Not found
}

// GetMessageType extracts the DHCP message type (option 53).
func (h *OptionHandler) GetMessageType(packet []byte) (uint8, error) {
	opt, err := h.ParseSingleOption(packet, 53)
	if err != nil {
		return 0, err
	}
	if opt == nil || len(opt.Data) < 1 {
		return 0, errors.New("missing message type option")
	}
	return opt.Data[0], nil
}

// GetRequestedIP extracts the requested IP address (option 50).
func (h *OptionHandler) GetRequestedIP(packet []byte) net.IP {
	opt, err := h.ParseSingleOption(packet, 50)
	if err != nil || opt == nil || len(opt.Data) != 4 {
		return nil
	}
	return net.IP(opt.Data)
}

// GetServerIdentifier extracts the server identifier (option 54).
func (h *OptionHandler) GetServerIdentifier(packet []byte) net.IP {
	opt, err := h.ParseSingleOption(packet, 54)
	if err != nil || opt == nil || len(opt.Data) != 4 {
		return nil
	}
	return net.IP(opt.Data)
}

// GetHostname extracts the client hostname (option 12).
func (h *OptionHandler) GetHostname(packet []byte) string {
	opt, err := h.ParseSingleOption(packet, 12)
	if err != nil || opt == nil {
		return ""
	}
	return string(opt.Data)
}

// GetClientIdentifier extracts the client identifier (option 61).
func (h *OptionHandler) GetClientIdentifier(packet []byte) []byte {
	opt, err := h.ParseSingleOption(packet, 61)
	if err != nil || opt == nil {
		return nil
	}
	return opt.Data
}

// GetParameterRequestList extracts the parameter request list (option 55).
func (h *OptionHandler) GetParameterRequestList(packet []byte) []uint8 {
	opt, err := h.ParseSingleOption(packet, 55)
	if err != nil || opt == nil {
		return nil
	}
	return opt.Data
}

// ============================================================================
// Build Methods
// ============================================================================

// OptionsConfig holds parameters for building DHCP options.
type OptionsConfig struct {
	MessageType   uint8
	ServerIP      net.IP
	SubnetMask    net.IPMask
	Router        net.IP
	DNSServers    []net.IP
	DomainName    string
	NTPServers    []net.IP
	LeaseTime     time.Duration
	RenewalTime   time.Duration // T1
	RebindingTime time.Duration // T2

	// ⭐ CA Integration Options
	CACertURL        string   // Option 224
	CAInstallScripts []string // Option 225
	WPADURL          string   // Option 252
}

// BuildOptions builds all DHCP options for a response.
func (h *OptionHandler) BuildOptions(cfg *OptionsConfig) []*DHCPOption {
	options := make([]*DHCPOption, 0, 16)

	// Option 53: Message Type (required)
	options = append(options, &DHCPOption{
		Code:   53,
		Length: 1,
		Data:   []byte{cfg.MessageType},
	})

	// Option 54: Server Identifier (required)
	if cfg.ServerIP != nil {
		options = append(options, newIPOption(54, cfg.ServerIP))
	} else if h.serverIP != nil {
		options = append(options, newIPOption(54, h.serverIP))
	}

	// Option 1: Subnet Mask
	if cfg.SubnetMask != nil {
		options = append(options, &DHCPOption{
			Code:   1,
			Length: 4,
			Data:   []byte(cfg.SubnetMask),
		})
	}

	// Option 3: Router (Gateway)
	if cfg.Router != nil {
		options = append(options, newIPOption(3, cfg.Router))
	}

	// Option 6: DNS Servers
	if len(cfg.DNSServers) > 0 {
		options = append(options, newIPListOption(6, cfg.DNSServers))
	}

	// Option 15: Domain Name
	if cfg.DomainName != "" {
		options = append(options, newStringOption(15, cfg.DomainName))
	}

	// Option 42: NTP Servers
	if len(cfg.NTPServers) > 0 {
		options = append(options, newIPListOption(42, cfg.NTPServers))
	}

	// Option 51: Lease Time
	if cfg.LeaseTime > 0 {
		leaseSeconds := uint32(cfg.LeaseTime.Seconds())
		options = append(options, newUint32Option(51, leaseSeconds))
	}

	// Option 58: Renewal Time (T1)
	if cfg.RenewalTime > 0 {
		t1Seconds := uint32(cfg.RenewalTime.Seconds())
		options = append(options, newUint32Option(58, t1Seconds))
	}

	// Option 59: Rebinding Time (T2)
	if cfg.RebindingTime > 0 {
		t2Seconds := uint32(cfg.RebindingTime.Seconds())
		options = append(options, newUint32Option(59, t2Seconds))
	}

	// ⭐ CA Integration Options
	options = append(options, h.buildCAOptions(cfg)...)

	return options
}

// buildCAOptions builds custom CA certificate options (224, 225, 252).
func (h *OptionHandler) buildCAOptions(cfg *OptionsConfig) []*DHCPOption {
	options := make([]*DHCPOption, 0, 3)

	// Option 224: CA Certificate URL
	if cfg.CACertURL != "" {
		options = append(options, newStringOption(224, cfg.CACertURL))
	}

	// Option 225: Install Script URLs (comma-separated)
	if len(cfg.CAInstallScripts) > 0 {
		scripts := ""
		for i, s := range cfg.CAInstallScripts {
			if i > 0 {
				scripts += ","
			}
			scripts += s
		}
		options = append(options, newStringOption(225, scripts))
	}

	// Option 252: WPAD URL
	if cfg.WPADURL != "" {
		options = append(options, newStringOption(252, cfg.WPADURL))
	}

	return options
}

// ============================================================================
// Validation Methods
// ============================================================================

// ValidateOptions checks all options for correctness.
func (h *OptionHandler) ValidateOptions(options []*DHCPOption) error {
	for _, opt := range options {
		if int(opt.Length) != len(opt.Data) {
			return fmt.Errorf("option %d: length mismatch (%d != %d)",
				opt.Code, opt.Length, len(opt.Data))
		}
		if len(opt.Data) > MaxOptionLength {
			return fmt.Errorf("option %d: data exceeds max length (%d > %d)",
				opt.Code, len(opt.Data), MaxOptionLength)
		}
	}
	return nil
}

// ValidateRequiredOptions checks for options required by RFC 2131.
func (h *OptionHandler) ValidateRequiredOptions(options []*DHCPOption, msgType uint8) error {
	hasMessageType := false
	hasServerID := false
	hasLeaseTime := false

	for _, opt := range options {
		switch opt.Code {
		case 53:
			hasMessageType = true
		case 54:
			hasServerID = true
		case 51:
			hasLeaseTime = true
		}
	}

	if !hasMessageType {
		return errors.New("missing required Option 53 (Message Type)")
	}

	// Server ID required for OFFER (2), ACK (5), NAK (6)
	if (msgType == 2 || msgType == 5 || msgType == 6) && !hasServerID {
		return errors.New("missing required Option 54 (Server Identifier)")
	}

	// Lease Time required for OFFER (2) and ACK (5)
	if (msgType == 2 || msgType == 5) && !hasLeaseTime {
		return errors.New("missing required Option 51 (Lease Time)")
	}

	return nil
}

// ============================================================================
// Option Manipulation Methods
// ============================================================================

// GetOption retrieves an option by code from a list.
func (h *OptionHandler) GetOption(options []*DHCPOption, code uint8) *DHCPOption {
	for _, opt := range options {
		if opt.Code == code {
			return opt
		}
	}
	return nil
}

// HasOption checks if an option code exists in the list.
func (h *OptionHandler) HasOption(options []*DHCPOption, code uint8) bool {
	return h.GetOption(options, code) != nil
}

// AddOption adds or replaces an option in the list.
func (h *OptionHandler) AddOption(options []*DHCPOption, newOpt *DHCPOption) []*DHCPOption {
	// Remove existing with same code
	filtered := make([]*DHCPOption, 0, len(options))
	for _, opt := range options {
		if opt.Code != newOpt.Code {
			filtered = append(filtered, opt)
		}
	}
	return append(filtered, newOpt)
}

// RemoveOption removes an option from the list.
func (h *OptionHandler) RemoveOption(options []*DHCPOption, code uint8) []*DHCPOption {
	filtered := make([]*DHCPOption, 0, len(options))
	for _, opt := range options {
		if opt.Code != code {
			filtered = append(filtered, opt)
		}
	}
	return filtered
}

// ============================================================================
// Serialization Methods
// ============================================================================

// SerializeOptions converts options to TLV wire format.
func (h *OptionHandler) SerializeOptions(options []*DHCPOption) []byte {
	size := h.CalculateOptionsLength(options)
	buf := make([]byte, 0, size)

	for _, opt := range options {
		if opt.Code == OptionPad {
			buf = append(buf, 0)
		} else {
			buf = append(buf, opt.Code, opt.Length)
			buf = append(buf, opt.Data...)
		}
	}

	// Append END marker
	buf = append(buf, OptionEnd)

	return buf
}

// CalculateOptionsLength returns total byte length of serialized options.
func (h *OptionHandler) CalculateOptionsLength(options []*DHCPOption) int {
	length := 1 // END marker
	for _, opt := range options {
		if opt.Code == OptionPad {
			length++
		} else {
			length += 2 + len(opt.Data)
		}
	}
	return length
}

// ============================================================================
// Helper Methods
// ============================================================================

// IsStandardOption returns true for RFC 2132 standard options (1-81).
func IsStandardOption(code uint8) bool {
	return code >= 1 && code <= 81
}

// IsCustomOption returns true for CA certificate options (224, 225, 252).
func IsCustomOption(code uint8) bool {
	return code == 224 || code == 225 || code == 252
}

// GetOptionDescription returns a human-readable description of an option.
func GetOptionDescription(code uint8) string {
	descriptions := map[uint8]string{
		1:   "Subnet Mask",
		3:   "Router",
		6:   "DNS Servers",
		12:  "Hostname",
		15:  "Domain Name",
		42:  "NTP Servers",
		50:  "Requested IP",
		51:  "Lease Time",
		53:  "Message Type",
		54:  "Server Identifier",
		55:  "Parameter Request List",
		58:  "Renewal Time (T1)",
		59:  "Rebinding Time (T2)",
		61:  "Client Identifier",
		224: "CA Certificate URL",
		225: "CA Install Scripts",
		252: "WPAD URL",
	}
	if desc, ok := descriptions[code]; ok {
		return desc
	}
	return fmt.Sprintf("Option %d", code)
}

// ============================================================================
// Option Constructors (internal helpers)
// ============================================================================

func newIPOption(code uint8, ip net.IP) *DHCPOption {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   []byte(ip4),
	}
}

func newIPListOption(code uint8, ips []net.IP) *DHCPOption {
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
	}
}

func newStringOption(code uint8, value string) *DHCPOption {
	return &DHCPOption{
		Code:   code,
		Length: uint8(len(value)),
		Data:   []byte(value),
	}
}

func newUint32Option(code uint8, value uint32) *DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   data,
	}
}
