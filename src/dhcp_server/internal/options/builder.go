// Package options provides DHCP option handling.
// This file implements the builder engine for constructing options in DHCP responses.
package options

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
)

// ============================================================================
// Builder Constants
// ============================================================================

const (
	// MaxOptionDataLength is the maximum bytes for a single option's data
	MaxOptionDataLength = 255

	// MaxOptionsFieldSize is maximum bytes for entire options field
	// (576 min UDP - 236 fixed header = 340, minus 1 for end marker = 339)
	MaxOptionsFieldSize = 339

	// Priority tiers for option ordering
	PriorityRequired  = 1
	PriorityCritical  = 2
	PriorityRequested = 3
	PriorityCustom    = 4
	PriorityStandard  = 5
	PriorityOptional  = 6
)

// ============================================================================
// Builder Configuration
// ============================================================================

// BuilderConfig holds builder behavior settings.
type BuilderConfig struct {
	MaxPacketSize    int  // Maximum total options size
	StrictMode       bool // Fail on any error vs. skip problematic options
	IncludeEndMarker bool // Append option 255
	ValidateSizes    bool // Validate option sizes before adding
}

// DefaultBuilderConfig returns sensible defaults.
func DefaultBuilderConfig() BuilderConfig {
	return BuilderConfig{
		MaxPacketSize:    MaxOptionsFieldSize,
		StrictMode:       false,
		IncludeEndMarker: true,
		ValidateSizes:    true,
	}
}

// ============================================================================
// Options Builder
// ============================================================================

// OptionsBuilder accumulates options and produces wire-format output.
type OptionsBuilder struct {
	options     []*DHCPOption
	config      BuilderConfig
	requestList []uint8 // Client's parameter request list
}

// NewOptionsBuilder creates a new builder with the given config.
func NewOptionsBuilder(config BuilderConfig) *OptionsBuilder {
	return &OptionsBuilder{
		options: make([]*DHCPOption, 0, 16),
		config:  config,
	}
}

// NewDefaultBuilder creates a builder with default settings.
func NewDefaultBuilder() *OptionsBuilder {
	return NewOptionsBuilder(DefaultBuilderConfig())
}

// ============================================================================
// Adding Options
// ============================================================================

// AddOption adds a pre-built option to the builder.
func (b *OptionsBuilder) AddOption(opt *DHCPOption) error {
	if opt == nil {
		return nil
	}

	if b.config.ValidateSizes && len(opt.Data) > MaxOptionDataLength {
		return fmt.Errorf("%w: option %d has %d bytes", ErrOptionTooLarge, opt.Code, len(opt.Data))
	}

	// Replace if exists
	b.removeOption(opt.Code)
	b.options = append(b.options, opt)
	return nil
}

// AddOptions adds multiple options.
func (b *OptionsBuilder) AddOptions(opts []*DHCPOption) error {
	for _, opt := range opts {
		if err := b.AddOption(opt); err != nil {
			if b.config.StrictMode {
				return err
			}
		}
	}
	return nil
}

// removeOption removes an existing option by code (internal).
func (b *OptionsBuilder) removeOption(code uint8) {
	filtered := make([]*DHCPOption, 0, len(b.options))
	for _, opt := range b.options {
		if opt.Code != code {
			filtered = append(filtered, opt)
		}
	}
	b.options = filtered
}

// ============================================================================
// Convenience Methods for Adding Common Options
// ============================================================================

// AddMessageType adds Option 53 (DHCP Message Type).
func (b *OptionsBuilder) AddMessageType(msgType uint8) error {
	return b.AddOption(&DHCPOption{Code: 53, Length: 1, Data: []byte{msgType}})
}

// AddServerID adds Option 54 (Server Identifier).
func (b *OptionsBuilder) AddServerID(ip net.IP) error {
	return b.AddOption(encodeIPOption(54, ip))
}

// AddSubnetMask adds Option 1 (Subnet Mask).
func (b *OptionsBuilder) AddSubnetMask(mask net.IPMask) error {
	if len(mask) == 4 {
		return b.AddOption(&DHCPOption{Code: 1, Length: 4, Data: []byte(mask)})
	}
	// IPv6 mask, get last 4 bytes
	if len(mask) >= 4 {
		return b.AddOption(&DHCPOption{Code: 1, Length: 4, Data: []byte(mask[len(mask)-4:])})
	}
	return ErrInvalidOptionValue
}

// AddRouter adds Option 3 (Router/Gateway).
func (b *OptionsBuilder) AddRouter(gateways ...net.IP) error {
	return b.AddOption(encodeIPListOption(3, gateways))
}

// AddDNSServers adds Option 6 (Domain Name Server).
func (b *OptionsBuilder) AddDNSServers(servers ...net.IP) error {
	return b.AddOption(encodeIPListOption(6, servers))
}

// AddDomainName adds Option 15 (Domain Name).
func (b *OptionsBuilder) AddDomainName(domain string) error {
	return b.AddOption(encodeStringOption(15, domain))
}

// AddLeaseTime adds Option 51 (IP Address Lease Time).
func (b *OptionsBuilder) AddLeaseTime(seconds uint32) error {
	return b.AddOption(encodeUint32Option(51, seconds))
}

// AddRenewalTime adds Option 58 (Renewal Time T1).
func (b *OptionsBuilder) AddRenewalTime(seconds uint32) error {
	return b.AddOption(encodeUint32Option(58, seconds))
}

// AddRebindingTime adds Option 59 (Rebinding Time T2).
func (b *OptionsBuilder) AddRebindingTime(seconds uint32) error {
	return b.AddOption(encodeUint32Option(59, seconds))
}

// AddNTPServers adds Option 42 (NTP Servers).
func (b *OptionsBuilder) AddNTPServers(servers ...net.IP) error {
	return b.AddOption(encodeIPListOption(42, servers))
}

// AddHostname adds Option 12 (Host Name).
func (b *OptionsBuilder) AddHostname(hostname string) error {
	return b.AddOption(encodeStringOption(12, hostname))
}

// AddBroadcastAddress adds Option 28 (Broadcast Address).
func (b *OptionsBuilder) AddBroadcastAddress(ip net.IP) error {
	return b.AddOption(encodeIPOption(28, ip))
}

// ============================================================================
// CA Certificate Options (224, 225, 252)
// ============================================================================

// AddRootCAURL adds Option 224 (Root CA Certificate URL).
func (b *OptionsBuilder) AddRootCAURL(url string) error {
	opt, err := BuildRootCAOption(url)
	if err != nil {
		return err
	}
	return b.AddOption(opt)
}

// AddInstallScripts adds Option 225 (CA Install Scripts).
func (b *OptionsBuilder) AddInstallScripts(urls ...string) error {
	opt, err := BuildIntermediateCAOption(urls...)
	if err != nil {
		return err
	}
	return b.AddOption(opt)
}

// AddWPADURL adds Option 252 (WPAD URL).
func (b *OptionsBuilder) AddWPADURL(url string) error {
	opt, err := BuildWPADOption(url)
	if err != nil {
		return err
	}
	return b.AddOption(opt)
}

// AddCAOptionSet adds all CA options from a set.
func (b *OptionsBuilder) AddCAOptionSet(set *CAOptionSet) error {
	if set == nil || !set.Enabled {
		return nil
	}

	opts, err := EncodeCustomOptionSet(set)
	if err != nil {
		return err
	}

	return b.AddOptions(opts)
}

// ============================================================================
// Parameter Request List Handling
// ============================================================================

// SetParameterRequestList sets the client's requested options.
func (b *OptionsBuilder) SetParameterRequestList(codes []uint8) {
	b.requestList = codes
}

// IsRequested returns true if code is in parameter request list.
func (b *OptionsBuilder) IsRequested(code uint8) bool {
	for _, c := range b.requestList {
		if c == code {
			return true
		}
	}
	return false
}

// ============================================================================
// Building Output
// ============================================================================

// Build produces the final wire-format byte array.
func (b *OptionsBuilder) Build() ([]byte, error) {
	// Sort by priority
	b.sortByPriority()

	// Calculate total size
	totalSize := b.calculateSize()
	if b.config.IncludeEndMarker {
		totalSize++
	}

	if totalSize > b.config.MaxPacketSize {
		if b.config.StrictMode {
			return nil, fmt.Errorf("%w: %d bytes exceeds limit %d",
				ErrPacketTooLarge, totalSize, b.config.MaxPacketSize)
		}
		// Trim optional options to fit
		b.trimToFit()
	}

	// Build output buffer
	buf := make([]byte, 0, totalSize)

	for _, opt := range b.options {
		buf = append(buf, opt.Code, opt.Length)
		buf = append(buf, opt.Data...)
	}

	// Append end marker
	if b.config.IncludeEndMarker {
		buf = append(buf, 255)
	}

	return buf, nil
}

// BuildOptionsField is an alias for Build.
func (b *OptionsBuilder) BuildOptionsField() ([]byte, error) {
	return b.Build()
}

// calculateSize returns total encoded size of all options.
func (b *OptionsBuilder) calculateSize() int {
	size := 0
	for _, opt := range b.options {
		size += 2 + len(opt.Data) // code + length + data
	}
	return size
}

// trimToFit removes low-priority options until size fits.
func (b *OptionsBuilder) trimToFit() {
	maxData := b.config.MaxPacketSize
	if b.config.IncludeEndMarker {
		maxData--
	}

	// Sort by priority (highest priority = lowest number first)
	b.sortByPriority()

	// Remove from end (lowest priority) until it fits
	for b.calculateSize() > maxData && len(b.options) > 0 {
		b.options = b.options[:len(b.options)-1]
	}
}

// ============================================================================
// Priority and Ordering
// ============================================================================

// sortByPriority sorts options by priority tier, then by code.
func (b *OptionsBuilder) sortByPriority() {
	sort.Slice(b.options, func(i, j int) bool {
		pi := b.getPriority(b.options[i].Code)
		pj := b.getPriority(b.options[j].Code)
		if pi != pj {
			return pi < pj
		}
		return b.options[i].Code < b.options[j].Code
	})
}

// getPriority returns priority tier for an option code.
func (b *OptionsBuilder) getPriority(code uint8) int {
	switch code {
	case 53, 54: // Message Type, Server ID
		return PriorityRequired
	case 51, 58, 59: // Lease Time, Renewal, Rebinding
		return PriorityCritical
	case 224, 225, 252: // CA options
		return PriorityCustom
	case 1, 3, 6, 15: // Subnet, Router, DNS, Domain
		return PriorityStandard
	default:
		if b.IsRequested(code) {
			return PriorityRequested
		}
		return PriorityOptional
	}
}

// ============================================================================
// Validation
// ============================================================================

// ValidateRequiredOptions checks that required options are present.
func (b *OptionsBuilder) ValidateRequiredOptions(msgType uint8) error {
	hasMessageType := false
	hasServerID := false
	hasLeaseTime := false

	for _, opt := range b.options {
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
		return fmt.Errorf("%w: Message Type (53)", ErrRequiredOptionMissing)
	}

	// Server ID required for OFFER (2), ACK (5), NAK (6)
	if (msgType == 2 || msgType == 5 || msgType == 6) && !hasServerID {
		return fmt.Errorf("%w: Server Identifier (54)", ErrRequiredOptionMissing)
	}

	// Lease Time required for OFFER (2) and ACK (5)
	if (msgType == 2 || msgType == 5) && !hasLeaseTime {
		return fmt.Errorf("%w: Lease Time (51)", ErrRequiredOptionMissing)
	}

	return nil
}

// ============================================================================
// Encoding Helpers
// ============================================================================

func encodeIPOption(code uint8, ip net.IP) *DHCPOption {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return &DHCPOption{Code: code, Length: 4, Data: []byte(ip4)}
}

func encodeIPListOption(code uint8, ips []net.IP) *DHCPOption {
	data := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			data = append(data, ip4...)
		}
	}
	return &DHCPOption{Code: code, Length: uint8(len(data)), Data: data}
}

func encodeStringOption(code uint8, value string) *DHCPOption {
	return &DHCPOption{Code: code, Length: uint8(len(value)), Data: []byte(value)}
}

func encodeUint32Option(code uint8, value uint32) *DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return &DHCPOption{Code: code, Length: 4, Data: data}
}

func encodeUint16Option(code uint8, value uint16) *DHCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return &DHCPOption{Code: code, Length: 2, Data: data}
}

// Ensure encodeUint16Option is available for future use
var _ = encodeUint16Option

// ============================================================================
// Buffer Write Helpers
// ============================================================================

// WriteByte appends a single byte to buffer.
func WriteByte(buf *[]byte, value byte) {
	*buf = append(*buf, value)
}

// WriteUint16 appends big-endian uint16 to buffer.
func WriteUint16(buf *[]byte, value uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, value)
	*buf = append(*buf, b...)
}

// WriteUint32 appends big-endian uint32 to buffer.
func WriteUint32(buf *[]byte, value uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	*buf = append(*buf, b...)
}

// WriteBytes appends byte slice to buffer.
func WriteBytes(buf *[]byte, data []byte) {
	*buf = append(*buf, data...)
}

// WriteIPv4 appends 4-byte IP address to buffer.
func WriteIPv4(buf *[]byte, ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	*buf = append(*buf, ip4...)
}

// WriteString appends string bytes to buffer (no null terminator).
func WriteString(buf *[]byte, str string) {
	*buf = append(*buf, []byte(str)...)
}

// WriteOptionHeader appends code + length bytes.
func WriteOptionHeader(buf *[]byte, code, length uint8) {
	*buf = append(*buf, code, length)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrOptionTooLarge is returned when single option exceeds 255 bytes
	ErrOptionTooLarge = errors.New("option data exceeds maximum size (255 bytes)")

	// ErrPacketTooLarge is returned when total options exceed limit
	ErrPacketTooLarge = errors.New("total options field exceeds maximum size")

	// ErrInvalidOptionValue is returned when option value cannot be encoded
	ErrInvalidOptionValue = errors.New("invalid option value")

	// ErrRequiredOptionMissing is returned when required option is not present
	ErrRequiredOptionMissing = errors.New("required option missing")

	// ErrEncodingFailed is returned when encoding fails
	ErrEncodingFailed = errors.New("option encoding failed")
)
