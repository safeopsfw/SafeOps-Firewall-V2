package utils

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safeops/shared/go/errors"
)

// ============================================================================
// Network Validation
// ============================================================================

// IsValidIPv4 checks if the string is a valid IPv4 address.
func IsValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

// IsValidIPv6 checks if the string is a valid IPv6 address.
func IsValidIPv6(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() == nil && ip.To16() != nil
}

// IsValidIP checks if the string is a valid IPv4 or IPv6 address.
func IsValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// ValidateIP validates an IP address and returns an error if invalid.
func ValidateIP(ip string) error {
	if !IsValidIP(ip) {
		return errors.New(errors.ErrInvalidFormat, "Invalid IP address").
			WithField("ip", ip)
	}
	return nil
}

// ValidateIPv4 validates an IPv4 address and returns an error if invalid.
func ValidateIPv4(ip string) error {
	if !IsValidIPv4(ip) {
		return errors.New(errors.ErrInvalidFormat, "Invalid IPv4 address").
			WithField("ip", ip)
	}
	return nil
}

// ValidateIPv6 validates an IPv6 address and returns an error if invalid.
func ValidateIPv6(ip string) error {
	if !IsValidIPv6(ip) {
		return errors.New(errors.ErrInvalidFormat, "Invalid IPv6 address").
			WithField("ip", ip)
	}
	return nil
}

// IsValidPort checks if the port number is in the valid range (1-65535).
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// ValidatePort validates a port number and returns an error if invalid.
func ValidatePort(port int) error {
	if !IsValidPort(port) {
		return errors.New(errors.ErrOutOfRange, "Port number out of valid range (1-65535)").
			WithField("port", port)
	}
	return nil
}

// IsValidCIDR validates CIDR notation (e.g., "192.168.1.0/24").
func IsValidCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// ValidateCIDR validates CIDR notation and returns an error if invalid.
func ValidateCIDR(cidr string) error {
	if !IsValidCIDR(cidr) {
		return errors.New(errors.ErrInvalidFormat, "Invalid CIDR notation").
			WithField("cidr", cidr)
	}
	return nil
}

// IsValidMACAddress validates MAC address format.
// Accepts formats: 00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A.2B3C.4D5E
func IsValidMACAddress(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

// ValidateMACAddress validates a MAC address and returns an error if invalid.
func ValidateMACAddress(mac string) error {
	if !IsValidMACAddress(mac) {
		return errors.New(errors.ErrInvalidFormat, "Invalid MAC address").
			WithField("mac", mac)
	}
	return nil
}

// IsPrivateIP checks if an IP address is in a private range (RFC 1918).
// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateBlocks := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
	}

	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// ============================================================================
// Domain and Hostname Validation
// ============================================================================

var (
	// domainRegex validates RFC-compliant domain names
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	// labelRegex validates individual DNS labels
	labelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	// Special label regex allows underscores for special records like _dmarc
	specialLabelRegex = regexp.MustCompile(`^_?[a-zA-Z0-9]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?$`)
)

// IsValidLabel validates a single DNS label.
func IsValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	return labelRegex.MatchString(s) || specialLabelRegex.MatchString(s)
}

// IsValidDomain checks if the string is a valid RFC-compliant domain name.
func IsValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	// Remove trailing dot if present (FQDN)
	s = strings.TrimSuffix(s, ".")

	// Check for wildcard domain
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
		// After removing wildcard, must have remaining domain
		if len(s) == 0 {
			return false
		}
	}

	// Validate overall format
	if !domainRegex.MatchString(s) {
		return false
	}

	// Validate each label
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !IsValidLabel(label) {
			return false
		}
	}

	return true
}

// IsValidHostname validates a hostname (allows single labels).
func IsValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	// Hostnames can be single labels or full domains
	if !strings.Contains(s, ".") {
		return IsValidLabel(s)
	}

	return IsValidDomain(s)
}

// IsValidFQDN checks if the string is a fully qualified domain name.
// FQDNs must have a TLD or end with a dot.
func IsValidFQDN(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	// FQDN can end with dot
	hasDot := strings.HasSuffix(s, ".")
	s = strings.TrimSuffix(s, ".")

	if !IsValidDomain(s) {
		return false
	}

	// Must have at least one dot (TLD) or had trailing dot
	return strings.Contains(s, ".") || hasDot
}

// ValidateDomain validates a domain name and returns an error if invalid.
func ValidateDomain(domain string) error {
	if !IsValidDomain(domain) {
		return errors.New(errors.ErrInvalidFormat, "Invalid domain name").
			WithField("domain", domain)
	}
	return nil
}

// ============================================================================
// Email Validation
// ============================================================================

var (
	// Simple email regex - not full RFC 5322 parser
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// IsValidEmail validates an email address format.
func IsValidEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 {
		return false
	}

	if !emailRegex.MatchString(s) {
		return false
	}

	// Split into local and domain parts
	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	// Validate local part
	if len(local) == 0 || len(local) > 64 {
		return false
	}

	// No consecutive dots
	if strings.Contains(local, "..") {
		return false
	}

	// No leading/trailing dots
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}

	// Validate domain part
	return IsValidDomain(domain)
}

// ValidateEmail validates an email address and returns an error if invalid.
func ValidateEmail(email string) error {
	if !IsValidEmail(email) {
		return errors.New(errors.ErrInvalidFormat, "Invalid email address").
			WithField("email", email)
	}
	return nil
}

// ============================================================================
// URL Validation
// ============================================================================

var dangerousSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"vbscript":   true,
}

// IsValidScheme checks if a URL scheme is valid and safe.
func IsValidScheme(scheme string) bool {
	scheme = strings.ToLower(scheme)
	if dangerousSchemes[scheme] {
		return false
	}
	return regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`).MatchString(scheme)
}

// IsValidURL checks if a string is a valid URL.
func IsValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}

	// Must have scheme
	if u.Scheme == "" {
		return false
	}

	// Check for dangerous schemes
	if !IsValidScheme(u.Scheme) {
		return false
	}

	// Must have host for http/https schemes
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return false
	}

	return true
}

// IsValidHTTPURL checks if a string is a valid HTTP or HTTPS URL.
func IsValidHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}

	if u.Host == "" {
		return false
	}

	return true
}

// ValidateURL validates a URL and returns an error if invalid.
func ValidateURL(urlStr string) error {
	if !IsValidURL(urlStr) {
		return errors.New(errors.ErrInvalidFormat, "Invalid URL").
			WithField("url", urlStr)
	}
	return nil
}

// ValidateHTTPURL validates an HTTP/HTTPS URL and returns an error if invalid.
func ValidateHTTPURL(urlStr string) error {
	if !IsValidHTTPURL(urlStr) {
		return errors.New(errors.ErrInvalidFormat, "Invalid HTTP/HTTPS URL").
			WithField("url", urlStr)
	}
	return nil
}

// ============================================================================
// File Path Validation
// ============================================================================

var (
	// Windows reserved names
	windowsReservedNames = map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
		"COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
		"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}

	// Invalid filename characters (Windows and Unix)
	invalidFilenameChars = regexp.MustCompile(`[<>:"|?*\x00-\x1f]`)
)

// IsValidFileName checks if a filename has no invalid characters.
func IsValidFileName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}

	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return false
	}

	// Check for invalid characters
	if invalidFilenameChars.MatchString(name) {
		return false
	}

	// Check for path separators
	if strings.ContainsAny(name, "/\\") {
		return false
	}

	// Check for Windows reserved names
	upperName := strings.ToUpper(name)
	// Extract base name (before first dot, if any)
	baseName := upperName
	if dotIndex := strings.Index(upperName, "."); dotIndex > 0 {
		baseName = upperName[:dotIndex]
	}
	if windowsReservedNames[baseName] {
		return false
	}

	return true
}

// IsValidFilePath checks if a path format is valid.
func IsValidFilePath(path string) bool {
	if path == "" {
		return false
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Check if cleaning changed it significantly (suspicious path)
	if cleaned == "." || cleaned == ".." {
		return false
	}

	return true
}

// IsSafePath checks if a path is safe relative to a base directory.
// This prevents directory traversal attacks.
func IsSafePath(path, baseDir string) bool {
	if !IsValidFilePath(path) {
		return false
	}

	// Clean both paths
	cleanPath := filepath.Clean(path)
	cleanBase := filepath.Clean(baseDir)

	// If path is absolute, check it's within base
	if filepath.IsAbs(cleanPath) {
		rel, err := filepath.Rel(cleanBase, cleanPath)
		if err != nil {
			return false
		}
		// Must not escape base directory
		return !strings.HasPrefix(rel, "..") && rel != ".."
	}

	// For relative paths, join with base and check
	fullPath := filepath.Join(cleanBase, cleanPath)
	rel, err := filepath.Rel(cleanBase, fullPath)
	if err != nil {
		return false
	}

	// Must not escape base directory
	return !strings.HasPrefix(rel, "..") && rel != ".."
}

// SanitizePath removes dangerous path components.
func SanitizePath(path string) string {
	// Clean the path
	cleaned := filepath.Clean(path)

	// Remove any .. components
	parts := strings.Split(cleaned, string(filepath.Separator))
	safe := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != ".." && part != "." && part != "" {
			safe = append(safe, part)
		}
	}

	return filepath.Join(safe...)
}

// ValidateFilePath validates a file path and returns an error if invalid.
func ValidateFilePath(path string) error {
	if !IsValidFilePath(path) {
		return errors.New(errors.ErrInvalidFormat, "Invalid file path").
			WithField("path", path)
	}
	return nil
}

// ValidateSafePath validates that a path is safe relative to a base directory.
func ValidateSafePath(path, baseDir string) error {
	if !IsSafePath(path, baseDir) {
		return errors.New(errors.ErrInvalidFormat, "Unsafe file path - potential directory traversal").
			WithField("path", path).
			WithField("base_dir", baseDir)
	}
	return nil
}

// ============================================================================
// String Length Validation
// ============================================================================

// ValidateLength checks if a string length is within the specified range.
func ValidateLength(s string, min, max int) error {
	length := len(s)
	if length < min || length > max {
		return errors.New(errors.ErrOutOfRange, fmt.Sprintf("String length must be between %d and %d characters", min, max)).
			WithField("length", length).
			WithField("min", min).
			WithField("max", max)
	}
	return nil
}

// ValidateMinLength checks if a string meets the minimum length requirement.
func ValidateMinLength(s string, min int) error {
	if len(s) < min {
		return errors.New(errors.ErrOutOfRange, fmt.Sprintf("String must be at least %d characters", min)).
			WithField("length", len(s)).
			WithField("min", min)
	}
	return nil
}

// ValidateMaxLength checks if a string doesn't exceed the maximum length.
func ValidateMaxLength(s string, max int) error {
	if len(s) > max {
		return errors.New(errors.ErrOutOfRange, fmt.Sprintf("String must not exceed %d characters", max)).
			WithField("length", len(s)).
			WithField("max", max)
	}
	return nil
}

// ValidateExactLength checks if a string has the exact required length.
func ValidateExactLength(s string, length int) error {
	if len(s) != length {
		return errors.New(errors.ErrOutOfRange, fmt.Sprintf("String must be exactly %d characters", length)).
			WithField("length", len(s)).
			WithField("required", length)
	}
	return nil
}

// ============================================================================
// Pattern Matching Validation
// ============================================================================

var (
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	alphaRegex        = regexp.MustCompile(`^[a-zA-Z]+$`)
	numericRegex      = regexp.MustCompile(`^[0-9]+$`)
	hexadecimalRegex  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// MatchesPattern checks if a string matches a regex pattern.
func MatchesPattern(s, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// IsAlphanumeric checks if a string contains only letters and numbers.
func IsAlphanumeric(s string) bool {
	return alphanumericRegex.MatchString(s)
}

// IsAlpha checks if a string contains only letters.
func IsAlpha(s string) bool {
	return alphaRegex.MatchString(s)
}

// IsNumeric checks if a string contains only numbers.
func IsNumeric(s string) bool {
	return numericRegex.MatchString(s)
}

// IsHexadecimal checks if a string is a valid hexadecimal string.
func IsHexadecimal(s string) bool {
	return hexadecimalRegex.MatchString(s)
}

// ValidateAlphanumeric validates that a string is alphanumeric.
func ValidateAlphanumeric(s string) error {
	if !IsAlphanumeric(s) {
		return errors.New(errors.ErrInvalidFormat, "String must contain only letters and numbers").
			WithField("value", s)
	}
	return nil
}

// ValidatePattern validates that a string matches a regex pattern.
func ValidatePattern(s, pattern, description string) error {
	if !MatchesPattern(s, pattern) {
		return errors.New(errors.ErrInvalidFormat, fmt.Sprintf("String does not match required pattern: %s", description)).
			WithField("value", s).
			WithField("pattern", pattern)
	}
	return nil
}
