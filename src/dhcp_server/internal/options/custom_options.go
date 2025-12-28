// Package options provides DHCP option handling.
// This file implements custom options 224, 225, 252 for CA certificate distribution.
package options

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ============================================================================
// Constants - Custom Option Codes
// ============================================================================

const (
	// OptionRootCAURL (224) - Root CA certificate download URL
	OptionRootCAURL uint8 = 224

	// OptionIntermediateCAURL (225) - Intermediate CA / Install script URLs
	OptionIntermediateCAURL uint8 = 225

	// OptionEnrollmentURL (252) - WPAD / Certificate enrollment URL
	OptionEnrollmentURL uint8 = 252

	// MaxURLLength is the maximum URL length for DHCP options (255 bytes)
	MaxURLLength = 255

	// Protocol identifiers for enrollment option
	ProtocolSCEP uint8 = 1 // Simple Certificate Enrollment Protocol
	ProtocolEST  uint8 = 2 // Enrollment over Secure Transport
	ProtocolWPAD uint8 = 3 // Web Proxy Auto-Discovery
)

// ============================================================================
// Custom Option Type Definitions
// ============================================================================

// RootCAURLOption represents Option 224 (Root CA URL).
type RootCAURLOption struct {
	URL      string // Root CA certificate download URL
	Checksum string // Optional SHA256 checksum of CA certificate
}

// IntermediateCAURLOption represents Option 225 (Intermediate CA URLs).
type IntermediateCAURLOption struct {
	URLs []string // Installation script or intermediate CA URLs
}

// EnrollmentURLOption represents Option 252 (Enrollment/WPAD URL).
type EnrollmentURLOption struct {
	URL      string // Enrollment endpoint URL
	Protocol uint8  // Protocol type (SCEP=1, EST=2, WPAD=3)
}

// CustomOptionMetadata contains versioning and compatibility info.
type CustomOptionMetadata struct {
	Version     uint8  // Option format version
	Flags       uint8  // Feature flags
	Description string // Human-readable description
}

// CAOptionSet contains all CA-related custom options.
type CAOptionSet struct {
	RootCA       *RootCAURLOption
	Intermediate *IntermediateCAURLOption
	Enrollment   *EnrollmentURLOption
	Enabled      bool
}

// ============================================================================
// Encoding Functions
// ============================================================================

// EncodeRootCAURL serializes Option 224 with length-prefixed URL string.
func EncodeRootCAURL(opt *RootCAURLOption) (*DHCPOption, error) {
	if opt == nil || opt.URL == "" {
		return nil, ErrMissingRequiredOption
	}

	if err := ValidateURLFormat(opt.URL); err != nil {
		return nil, err
	}

	data := []byte(opt.URL)
	if len(data) > MaxURLLength {
		return nil, ErrOptionTooLong
	}

	return &DHCPOption{
		Code:   OptionRootCAURL,
		Length: uint8(len(data)),
		Data:   data,
	}, nil
}

// EncodeIntermediateCAURL serializes Option 225 with comma-separated URLs.
func EncodeIntermediateCAURL(opt *IntermediateCAURLOption) (*DHCPOption, error) {
	if opt == nil || len(opt.URLs) == 0 {
		return nil, ErrMissingRequiredOption
	}

	// Validate each URL
	for _, u := range opt.URLs {
		if err := ValidateURLFormat(u); err != nil {
			return nil, fmt.Errorf("invalid URL in list: %w", err)
		}
	}

	// Join URLs with comma
	joined := strings.Join(opt.URLs, ",")
	data := []byte(joined)

	if len(data) > MaxURLLength {
		return nil, ErrOptionTooLong
	}

	return &DHCPOption{
		Code:   OptionIntermediateCAURL,
		Length: uint8(len(data)),
		Data:   data,
	}, nil
}

// EncodeEnrollmentURL serializes Option 252 with protocol type + URL.
func EncodeEnrollmentURL(opt *EnrollmentURLOption) (*DHCPOption, error) {
	if opt == nil || opt.URL == "" {
		return nil, ErrMissingRequiredOption
	}

	if err := ValidateURLFormat(opt.URL); err != nil {
		return nil, err
	}

	// For WPAD, just encode the URL directly (standard behavior)
	data := []byte(opt.URL)

	if len(data) > MaxURLLength {
		return nil, ErrOptionTooLong
	}

	return &DHCPOption{
		Code:   OptionEnrollmentURL,
		Length: uint8(len(data)),
		Data:   data,
	}, nil
}

// EncodeCustomOptionSet encodes all CA-related options.
func EncodeCustomOptionSet(set *CAOptionSet) ([]*DHCPOption, error) {
	if set == nil || !set.Enabled {
		return nil, nil
	}

	options := make([]*DHCPOption, 0, 3)

	if set.RootCA != nil {
		opt, err := EncodeRootCAURL(set.RootCA)
		if err != nil {
			return nil, fmt.Errorf("encoding root CA: %w", err)
		}
		options = append(options, opt)
	}

	if set.Intermediate != nil {
		opt, err := EncodeIntermediateCAURL(set.Intermediate)
		if err != nil {
			return nil, fmt.Errorf("encoding intermediate CA: %w", err)
		}
		options = append(options, opt)
	}

	if set.Enrollment != nil {
		opt, err := EncodeEnrollmentURL(set.Enrollment)
		if err != nil {
			return nil, fmt.Errorf("encoding enrollment URL: %w", err)
		}
		options = append(options, opt)
	}

	return options, nil
}

// ============================================================================
// Decoding Functions
// ============================================================================

// DecodeRootCAURL parses Option 224 bytes into RootCAURLOption.
func DecodeRootCAURL(opt *DHCPOption) (*RootCAURLOption, error) {
	if opt == nil || opt.Code != OptionRootCAURL {
		return nil, ErrDecodingFailed
	}

	urlStr := string(opt.Data)
	if err := ValidateURLFormat(urlStr); err != nil {
		return nil, fmt.Errorf("invalid decoded URL: %w", err)
	}

	return &RootCAURLOption{
		URL: urlStr,
	}, nil
}

// DecodeIntermediateCAURL parses Option 225 bytes into IntermediateCAURLOption.
func DecodeIntermediateCAURL(opt *DHCPOption) (*IntermediateCAURLOption, error) {
	if opt == nil || opt.Code != OptionIntermediateCAURL {
		return nil, ErrDecodingFailed
	}

	urlStr := string(opt.Data)
	urls := strings.Split(urlStr, ",")

	// Validate each URL
	validURLs := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			validURLs = append(validURLs, u)
		}
	}

	if len(validURLs) == 0 {
		return nil, ErrDecodingFailed
	}

	return &IntermediateCAURLOption{
		URLs: validURLs,
	}, nil
}

// DecodeEnrollmentURL parses Option 252 bytes into EnrollmentURLOption.
func DecodeEnrollmentURL(opt *DHCPOption) (*EnrollmentURLOption, error) {
	if opt == nil || opt.Code != OptionEnrollmentURL {
		return nil, ErrDecodingFailed
	}

	urlStr := string(opt.Data)

	// Detect protocol from URL
	protocol := ProtocolWPAD
	lowerURL := strings.ToLower(urlStr)
	if strings.Contains(lowerURL, "scep") {
		protocol = ProtocolSCEP
	} else if strings.Contains(lowerURL, "est") || strings.Contains(lowerURL, ".well-known/est") {
		protocol = ProtocolEST
	}

	return &EnrollmentURLOption{
		URL:      urlStr,
		Protocol: protocol,
	}, nil
}

// DecodeCustomOption is a generic decoder that routes to specific decoder.
func DecodeCustomOption(opt *DHCPOption) (interface{}, error) {
	if opt == nil {
		return nil, ErrDecodingFailed
	}

	switch opt.Code {
	case OptionRootCAURL:
		return DecodeRootCAURL(opt)
	case OptionIntermediateCAURL:
		return DecodeIntermediateCAURL(opt)
	case OptionEnrollmentURL:
		return DecodeEnrollmentURL(opt)
	default:
		return nil, fmt.Errorf("unknown custom option code: %d", opt.Code)
	}
}

// ============================================================================
// Validation Functions
// ============================================================================

// ValidateURLFormat ensures URL is properly formatted.
func ValidateURLFormat(urlStr string) error {
	if urlStr == "" {
		return ErrInvalidURLFormat
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURLFormat, err)
	}

	// Must have scheme
	if parsed.Scheme == "" {
		return fmt.Errorf("%w: missing scheme", ErrInvalidURLFormat)
	}

	// Must be http or https
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %s", ErrInvalidURLFormat, scheme)
	}

	// Must have host
	if parsed.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidURLFormat)
	}

	return nil
}

// ValidateOptionLength checks that encoded option doesn't exceed limit.
func ValidateOptionLength(data []byte) error {
	if len(data) > MaxURLLength {
		return ErrOptionTooLong
	}
	return nil
}

// ValidateEnrollmentProtocol ensures protocol is supported.
func ValidateEnrollmentProtocol(protocol uint8) error {
	switch protocol {
	case ProtocolSCEP, ProtocolEST, ProtocolWPAD:
		return nil
	default:
		return ErrUnsupportedProtocol
	}
}

// ValidateOptionCombination checks CA options are provided correctly.
func ValidateOptionCombination(set *CAOptionSet) error {
	if set == nil || !set.Enabled {
		return nil // Not enabled, no validation needed
	}

	// If any CA option is provided, root CA should be present
	if (set.Intermediate != nil || set.Enrollment != nil) && set.RootCA == nil {
		return fmt.Errorf("%w: root CA (224) required when other CA options are present", ErrMissingRequiredOption)
	}

	return nil
}

// SanitizeURLInput removes dangerous characters and normalizes URL.
func SanitizeURLInput(urlStr string) string {
	// Trim whitespace
	urlStr = strings.TrimSpace(urlStr)

	// Remove null bytes and control characters
	urlStr = strings.ReplaceAll(urlStr, "\x00", "")

	return urlStr
}

// ============================================================================
// Builder Functions
// ============================================================================

// BuildRootCAOption creates Option 224 from a raw URL string.
func BuildRootCAOption(urlStr string) (*DHCPOption, error) {
	urlStr = SanitizeURLInput(urlStr)
	return EncodeRootCAURL(&RootCAURLOption{URL: urlStr})
}

// BuildIntermediateCAOption creates Option 225 from URL strings.
func BuildIntermediateCAOption(urls ...string) (*DHCPOption, error) {
	sanitized := make([]string, 0, len(urls))
	for _, u := range urls {
		sanitized = append(sanitized, SanitizeURLInput(u))
	}
	return EncodeIntermediateCAURL(&IntermediateCAURLOption{URLs: sanitized})
}

// BuildEnrollmentOption creates Option 252 from enrollment URL.
func BuildEnrollmentOption(urlStr string, protocol uint8) (*DHCPOption, error) {
	urlStr = SanitizeURLInput(urlStr)
	if err := ValidateEnrollmentProtocol(protocol); err != nil {
		return nil, err
	}
	return EncodeEnrollmentURL(&EnrollmentURLOption{URL: urlStr, Protocol: protocol})
}

// BuildWPADOption creates Option 252 for WPAD auto-config.
func BuildWPADOption(urlStr string) (*DHCPOption, error) {
	return BuildEnrollmentOption(urlStr, ProtocolWPAD)
}

// BuildCAOptionSet creates all CA options from a configuration.
func BuildCAOptionSet(rootCAURL, wpadURL string, installScripts []string) (*CAOptionSet, error) {
	set := &CAOptionSet{Enabled: true}

	if rootCAURL != "" {
		set.RootCA = &RootCAURLOption{URL: SanitizeURLInput(rootCAURL)}
	}

	if len(installScripts) > 0 {
		sanitized := make([]string, len(installScripts))
		for i, s := range installScripts {
			sanitized[i] = SanitizeURLInput(s)
		}
		set.Intermediate = &IntermediateCAURLOption{URLs: sanitized}
	}

	if wpadURL != "" {
		set.Enrollment = &EnrollmentURLOption{
			URL:      SanitizeURLInput(wpadURL),
			Protocol: ProtocolWPAD,
		}
	}

	if err := ValidateOptionCombination(set); err != nil {
		return nil, err
	}

	return set, nil
}

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrInvalidURLFormat is returned when URL doesn't meet format requirements
	ErrInvalidURLFormat = errors.New("invalid URL format")

	// ErrOptionTooLong is returned when encoded option exceeds 255 byte limit
	ErrOptionTooLong = errors.New("option data exceeds maximum length (255 bytes)")

	// ErrMissingRequiredOption is returned when a required option is missing
	ErrMissingRequiredOption = errors.New("missing required option data")

	// ErrUnsupportedProtocol is returned when enrollment URL uses unsupported protocol
	ErrUnsupportedProtocol = errors.New("unsupported enrollment protocol")

	// ErrDecodingFailed is returned when wire format cannot be parsed
	ErrDecodingFailed = errors.New("failed to decode option data")

	// ErrValidationFailed is returned when option content fails validation
	ErrValidationFailed = errors.New("option validation failed")
)

// IsCustomOptionCode returns true if code is a custom CA option.
func IsCustomOptionCode(code uint8) bool {
	return code == OptionRootCAURL || code == OptionIntermediateCAURL || code == OptionEnrollmentURL
}
