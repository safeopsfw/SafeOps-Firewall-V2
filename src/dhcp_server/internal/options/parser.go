// Package options provides DHCP option handling.
// This file implements the parsing engine for decoding raw bytes into option structures.
package options

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// ============================================================================
// Parser Configuration
// ============================================================================

// ParserConfig holds parser behavior settings.
type ParserConfig struct {
	StrictMode          bool // Reject unknown options
	AllowUnknownOptions bool // Allow unknown options in lenient mode
	MaxOptionCount      int  // Maximum number of options to parse (0=unlimited)
	ValidateLengths     bool // Validate option data lengths
}

// DefaultParserConfig returns sensible parser defaults.
func DefaultParserConfig() ParserConfig {
	return ParserConfig{
		StrictMode:          false,
		AllowUnknownOptions: true,
		MaxOptionCount:      50,
		ValidateLengths:     true,
	}
}

// ============================================================================
// Parser State
// ============================================================================

// ParserState maintains parsing context while iterating.
type ParserState struct {
	Data     []byte        // Input buffer
	Position int           // Current position
	Options  []*DHCPOption // Parsed options
	Errors   []error       // Non-fatal errors encountered
	Config   ParserConfig  // Parser configuration
	Context  *ParseContext // Optional packet context
}

// ParseContext contains packet metadata for error reporting.
type ParseContext struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	SourceIP      net.IP
}

// ============================================================================
// Main Parsing Functions
// ============================================================================

// ParseOptionsFromBytes parses DHCP options from raw bytes.
// Options are in TLV format: Type (1 byte), Length (1 byte), Value (Length bytes).
func ParseOptionsFromBytes(data []byte, config ParserConfig) ([]*DHCPOption, error) {
	state := &ParserState{
		Data:    data,
		Options: make([]*DHCPOption, 0, 16),
		Config:  config,
	}

	return parseWithState(state)
}

// ParseOptionsWithContext parses options with packet metadata for error reporting.
func ParseOptionsWithContext(data []byte, config ParserConfig, ctx *ParseContext) ([]*DHCPOption, error) {
	state := &ParserState{
		Data:    data,
		Options: make([]*DHCPOption, 0, 16),
		Config:  config,
		Context: ctx,
	}

	return parseWithState(state)
}

// parseWithState is the core parsing loop.
func parseWithState(state *ParserState) ([]*DHCPOption, error) {
	for state.Position < len(state.Data) {
		// Check option count limit
		if state.Config.MaxOptionCount > 0 && len(state.Options) >= state.Config.MaxOptionCount {
			break
		}

		// Read option code
		code := state.Data[state.Position]

		// Handle special codes
		if code == 255 { // End marker
			break
		}

		if code == 0 { // Pad
			state.Position++
			continue
		}

		// Need at least length byte
		if state.Position+1 >= len(state.Data) {
			return state.Options, wrapParseError(ErrBufferUnderrun, code, state.Position, state.Context)
		}

		length := int(state.Data[state.Position+1])

		// Validate buffer has enough data
		if state.Position+2+length > len(state.Data) {
			return state.Options, wrapParseError(ErrBufferUnderrun, code, state.Position, state.Context)
		}

		// Extract option data
		optData := make([]byte, length)
		copy(optData, state.Data[state.Position+2:state.Position+2+length])

		// Create option
		opt := &DHCPOption{
			Code:   code,
			Length: uint8(length),
			Data:   optData,
		}

		// Validate if configured
		if state.Config.ValidateLengths {
			if err := validateOptionLength(opt); err != nil {
				if state.Config.StrictMode {
					return state.Options, wrapParseError(err, code, state.Position, state.Context)
				}
				state.Errors = append(state.Errors, err)
			}
		}

		state.Options = append(state.Options, opt)
		state.Position += 2 + length
	}

	return state.Options, nil
}

// ============================================================================
// Type-Specific Parsers
// ============================================================================

// ParseIPAddress parses a 4-byte IPv4 address option.
func ParseIPAddress(opt *DHCPOption) (net.IP, error) {
	if opt == nil || len(opt.Data) != 4 {
		return nil, ErrInvalidOptionLength
	}
	return net.IP(opt.Data), nil
}

// ParseIPList parses multiple 4-byte IPv4 addresses.
func ParseIPList(opt *DHCPOption) ([]net.IP, error) {
	if opt == nil || len(opt.Data) == 0 {
		return nil, ErrInvalidOptionLength
	}
	if len(opt.Data)%4 != 0 {
		return nil, fmt.Errorf("%w: IP list length %d not multiple of 4", ErrInvalidOptionLength, len(opt.Data))
	}

	ips := make([]net.IP, 0, len(opt.Data)/4)
	for i := 0; i < len(opt.Data); i += 4 {
		ips = append(ips, net.IP(opt.Data[i:i+4]))
	}
	return ips, nil
}

// ParseUint32 parses a 4-byte unsigned integer.
func ParseUint32(opt *DHCPOption) (uint32, error) {
	if opt == nil || len(opt.Data) != 4 {
		return 0, ErrInvalidOptionLength
	}
	return binary.BigEndian.Uint32(opt.Data), nil
}

// ParseUint16 parses a 2-byte unsigned integer.
func ParseUint16(opt *DHCPOption) (uint16, error) {
	if opt == nil || len(opt.Data) != 2 {
		return 0, ErrInvalidOptionLength
	}
	return binary.BigEndian.Uint16(opt.Data), nil
}

// ParseUint8 parses a 1-byte unsigned integer.
func ParseUint8(opt *DHCPOption) (uint8, error) {
	if opt == nil || len(opt.Data) != 1 {
		return 0, ErrInvalidOptionLength
	}
	return opt.Data[0], nil
}

// ParseString parses an ASCII string option.
func ParseString(opt *DHCPOption) (string, error) {
	if opt == nil {
		return "", ErrInvalidOptionLength
	}
	return string(opt.Data), nil
}

// ParseBinary returns raw binary data.
func ParseBinary(opt *DHCPOption) ([]byte, error) {
	if opt == nil {
		return nil, ErrInvalidOptionLength
	}
	result := make([]byte, len(opt.Data))
	copy(result, opt.Data)
	return result, nil
}

// ============================================================================
// Routing & Dispatch
// ============================================================================

// RouteToParser selects the appropriate parser based on option code.
func RouteToParser(opt *DHCPOption) (interface{}, error) {
	if opt == nil {
		return nil, ErrInvalidOptionLength
	}

	switch opt.Code {
	// IP address options
	case 1, 28, 50, 54: // Subnet mask, broadcast, requested IP, server ID
		return ParseIPAddress(opt)

	// IP list options
	case 3, 4, 5, 6, 7, 41, 42, 44, 45: // Routers, time servers, DNS, etc.
		return ParseIPList(opt)

	// Uint32 options
	case 51, 58, 59: // Lease time, renewal, rebinding
		return ParseUint32(opt)

	// Uint16 options
	case 57: // Max message size
		return ParseUint16(opt)

	// Uint8 options
	case 53, 52: // Message type, overload
		return ParseUint8(opt)

	// String options
	case 12, 14, 15, 56, 66, 67: // Hostname, merit dump, domain, etc.
		return ParseString(opt)

	// Custom CA options
	case OptionRootCAURL:
		return DecodeRootCAURL(opt)
	case OptionIntermediateCAURL:
		return DecodeIntermediateCAURL(opt)
	case OptionEnrollmentURL:
		return DecodeEnrollmentURL(opt)

	default:
		return ParseBinary(opt)
	}
}

// ============================================================================
// Validation Functions
// ============================================================================

// validateOptionLength checks if option data matches expected length.
func validateOptionLength(opt *DHCPOption) error {
	if opt == nil {
		return ErrInvalidOptionLength
	}

	expected := getExpectedLength(opt.Code)
	if expected < 0 {
		return nil // Variable length, always valid
	}

	if len(opt.Data) != expected {
		return fmt.Errorf("%w: option %d expected %d bytes, got %d",
			ErrInvalidOptionLength, opt.Code, expected, len(opt.Data))
	}

	return nil
}

// getExpectedLength returns expected length for fixed-length options (-1 for variable).
func getExpectedLength(code uint8) int {
	switch code {
	case 1, 28, 50, 54: // IP address options
		return 4
	case 51, 58, 59: // Time options
		return 4
	case 53, 52: // Uint8 options
		return 1
	case 57: // Max message size
		return 2
	default:
		return -1 // Variable length
	}
}

// ValidateFixedLength validates an option has exact expected length.
func ValidateFixedLength(opt *DHCPOption, expectedLen int) error {
	if opt == nil {
		return ErrInvalidOptionLength
	}
	if len(opt.Data) != expectedLen {
		return fmt.Errorf("%w: expected %d bytes, got %d",
			ErrInvalidOptionLength, expectedLen, len(opt.Data))
	}
	return nil
}

// ValidateVariableLength validates length is within range.
func ValidateVariableLength(opt *DHCPOption, minLen, maxLen int) error {
	if opt == nil {
		return ErrInvalidOptionLength
	}
	if len(opt.Data) < minLen || len(opt.Data) > maxLen {
		return fmt.Errorf("%w: length %d not in range [%d, %d]",
			ErrInvalidOptionLength, len(opt.Data), minLen, maxLen)
	}
	return nil
}

// CheckBufferBoundary validates read won't exceed buffer.
func CheckBufferBoundary(position, length, totalSize int) error {
	if position+length > totalSize {
		return ErrBufferUnderrun
	}
	return nil
}

// ============================================================================
// Data Extraction Helpers
// ============================================================================

// ReadByte reads a single byte with boundary check.
func ReadByte(buffer []byte, position int) (byte, error) {
	if position >= len(buffer) {
		return 0, ErrBufferUnderrun
	}
	return buffer[position], nil
}

// ReadUint16 reads 2 bytes as big-endian uint16.
func ReadUint16(buffer []byte, position int) (uint16, error) {
	if position+2 > len(buffer) {
		return 0, ErrBufferUnderrun
	}
	return binary.BigEndian.Uint16(buffer[position:]), nil
}

// ReadUint32 reads 4 bytes as big-endian uint32.
func ReadUint32(buffer []byte, position int) (uint32, error) {
	if position+4 > len(buffer) {
		return 0, ErrBufferUnderrun
	}
	return binary.BigEndian.Uint32(buffer[position:]), nil
}

// ReadBytes reads length bytes starting at position.
func ReadBytes(buffer []byte, position, length int) ([]byte, error) {
	if position+length > len(buffer) {
		return nil, ErrBufferUnderrun
	}
	result := make([]byte, length)
	copy(result, buffer[position:position+length])
	return result, nil
}

// ReadIPv4 reads 4 bytes as IPv4 address.
func ReadIPv4(buffer []byte, position int) (net.IP, error) {
	if position+4 > len(buffer) {
		return nil, ErrBufferUnderrun
	}
	return net.IP(buffer[position : position+4]), nil
}

// ReadString reads length bytes as ASCII/UTF-8 string.
func ReadString(buffer []byte, position, length int) (string, error) {
	data, err := ReadBytes(buffer, position, length)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============================================================================
// Error Handling
// ============================================================================

var (
	// ErrInvalidOptionLength is returned when option length is incorrect
	ErrInvalidOptionLength = errors.New("invalid option length")

	// ErrBufferUnderrun is returned when reading past end of buffer
	ErrBufferUnderrun = errors.New("buffer underrun: attempted to read past end")

	// ErrUnknownOptionCode is returned in strict mode for unsupported options
	ErrUnknownOptionCode = errors.New("unknown option code")

	// ErrMalformedOption is returned when option data format is invalid
	ErrMalformedOption = errors.New("malformed option data")

	// ErrMissingEndMarker is returned when options don't end with code 255
	ErrMissingEndMarker = errors.New("missing end marker (option 255)")

	// ErrDuplicateOption is returned when option appears multiple times
	ErrDuplicateOption = errors.New("duplicate option detected")
)

// ParseError provides detailed context for parsing failures.
type ParseError struct {
	Err      error
	Code     uint8
	Position int
	Context  *ParseContext
}

func (e *ParseError) Error() string {
	msg := fmt.Sprintf("parse error at position %d, option %d: %v", e.Position, e.Code, e.Err)
	if e.Context != nil {
		msg += fmt.Sprintf(" (xid=0x%08x)", e.Context.TransactionID)
	}
	return msg
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// wrapParseError creates a ParseError with context.
func wrapParseError(err error, code uint8, position int, ctx *ParseContext) error {
	return &ParseError{
		Err:      err,
		Code:     code,
		Position: position,
		Context:  ctx,
	}
}

// ============================================================================
// Convenience Functions
// ============================================================================

// FindOption searches for an option by code in a parsed list.
func FindOption(options []*DHCPOption, code uint8) *DHCPOption {
	for _, opt := range options {
		if opt.Code == code {
			return opt
		}
	}
	return nil
}

// GetMessageType extracts message type (option 53) from parsed options.
func GetParsedMessageType(options []*DHCPOption) (uint8, error) {
	opt := FindOption(options, 53)
	if opt == nil {
		return 0, fmt.Errorf("%w: message type (53)", ErrMalformedOption)
	}
	return ParseUint8(opt)
}

// GetRequestedIP extracts requested IP (option 50) from parsed options.
func GetParsedRequestedIP(options []*DHCPOption) (net.IP, error) {
	opt := FindOption(options, 50)
	if opt == nil {
		return nil, nil // Not required
	}
	return ParseIPAddress(opt)
}

// GetServerID extracts server identifier (option 54) from parsed options.
func GetParsedServerID(options []*DHCPOption) (net.IP, error) {
	opt := FindOption(options, 54)
	if opt == nil {
		return nil, nil // Not required
	}
	return ParseIPAddress(opt)
}

// ExtractCAOptions extracts all custom CA options from parsed list.
func ExtractCAOptions(options []*DHCPOption) (*CAOptionSet, error) {
	set := &CAOptionSet{Enabled: false}

	if opt := FindOption(options, OptionRootCAURL); opt != nil {
		rootCA, err := DecodeRootCAURL(opt)
		if err != nil {
			return nil, err
		}
		set.RootCA = rootCA
		set.Enabled = true
	}

	if opt := FindOption(options, OptionIntermediateCAURL); opt != nil {
		intermediate, err := DecodeIntermediateCAURL(opt)
		if err != nil {
			return nil, err
		}
		set.Intermediate = intermediate
		set.Enabled = true
	}

	if opt := FindOption(options, OptionEnrollmentURL); opt != nil {
		enrollment, err := DecodeEnrollmentURL(opt)
		if err != nil {
			return nil, err
		}
		set.Enrollment = enrollment
		set.Enabled = true
	}

	return set, nil
}
