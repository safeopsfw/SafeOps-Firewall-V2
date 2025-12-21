// Package utils provides common utility functions for threat intelligence
package utils

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ============================================================================
// Domain Validation
// ============================================================================

const (
	maxDomainLength = 253 // RFC 1035
	maxLabelLength  = 63  // RFC 1035
)

var (
	// Domain label pattern: alphanumeric, may contain hyphens (not at start/end)
	labelPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	// Simple IP address pattern (to reject IPs as domains)
	ipPattern = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
)

// IsValidDomain checks if a string is a syntactically valid domain name
func IsValidDomain(domain string) bool {
	return ValidateDomain(domain) == nil
}

// ValidateDomain validates a domain name and returns specific error if invalid
func ValidateDomain(domain string) error {
	if domain == "" {
		return errors.New("domain is empty")
	}

	// Trim whitespace
	domain = strings.TrimSpace(domain)

	// Check total length
	if len(domain) > maxDomainLength {
		return fmt.Errorf("domain exceeds %d characters", maxDomainLength)
	}

	// Reject if it looks like an IP address
	if ipPattern.MatchString(domain) {
		return errors.New("IP address is not a valid domain")
	}

	// Remove trailing dot if present (optional in DNS)
	domain = strings.TrimSuffix(domain, ".")

	// Must contain at least one dot (except localhost)
	if !strings.Contains(domain, ".") && domain != "localhost" {
		return errors.New("domain must contain at least one dot")
	}

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) < 2 && domain != "localhost" {
		return errors.New("domain must have at least two labels")
	}

	// Validate each label
	for i, label := range labels {
		if label == "" {
			return errors.New("domain contains empty label (consecutive dots)")
		}

		if len(label) > maxLabelLength {
			return fmt.Errorf("label '%s' exceeds %d characters", label, maxLabelLength)
		}

		// Check label pattern
		if !labelPattern.MatchString(label) {
			return fmt.Errorf("label '%s' contains invalid characters or format", label)
		}

		// TLD (last label) should be at least 2 characters (with exceptions)
		if i == len(labels)-1 && len(label) < 2 {
			// Allow single-letter TLDs like .x for testing
			if len(label) < 1 {
				return errors.New("TLD must be at least one character")
			}
		}
	}

	return nil
}

// ============================================================================
// Domain Extraction from URLs
// ============================================================================

// ExtractDomain extracts the domain from a URL, email, or mixed-format string
func ExtractDomain(input string) (string, error) {
	if input == "" {
		return "", errors.New("empty input")
	}

	input = strings.TrimSpace(input)

	// Check if it's an email address
	if strings.Contains(input, "@") && !strings.Contains(input, "://") {
		parts := strings.Split(input, "@")
		if len(parts) == 2 {
			domain := strings.TrimSpace(parts[1])
			// Remove trailing semicolons, commas, etc.
			domain = strings.TrimRight(domain, ".,;>")
			if ValidateDomain(domain) == nil {
				return NormalizeDomain(domain, false)
			}
		}
	}

	// If it looks like a plain domain, validate and return
	if !strings.Contains(input, "/") && !strings.Contains(input, ":") {
		domain := strings.TrimRight(input, ".,;>")
		if ValidateDomain(domain) == nil {
			return NormalizeDomain(domain, false)
		}
	}

	// Try to parse as URL
	parsedURL, err := parseURL(input)
	if err == nil && parsedURL.Host != "" {
		// Extract hostname (may include port)
		host := parsedURL.Host

		// Remove port if present
		if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
			// Check if it's actually a port (not IPv6)
			if !strings.Contains(host, "[") { // Not IPv6
				host = host[:colonIndex]
			}
		}

		// Remove [ ] from IPv6
		host = strings.Trim(host, "[]")

		if ValidateDomain(host) == nil {
			return NormalizeDomain(host, false)
		}

		// Might be IP, return error
		if ipPattern.MatchString(host) {
			return "", errors.New("IP address found, not a domain")
		}

		return host, nil
	}

	return "", fmt.Errorf("could not extract valid domain from input")
}

// parseURL attempts to parse a URL, adding scheme if missing
func parseURL(input string) (*url.URL, error) {
	// Try parsing as-is
	parsedURL, err := url.Parse(input)
	if err == nil && parsedURL.Host != "" {
		return parsedURL, nil
	}

	// Try adding http:// scheme
	if !strings.Contains(input, "://") {
		parsedURL, err = url.Parse("http://" + input)
		if err == nil && parsedURL.Host != "" {
			return parsedURL, nil
		}
	}

	return nil, errors.New("failed to parse URL")
}

// ExtractDomainBatch extracts domains from multiple inputs
func ExtractDomainBatch(inputs []string) []string {
	domains := make([]string, 0, len(inputs))
	seen := make(map[string]bool)

	for _, input := range inputs {
		domain, err := ExtractDomain(input)
		if err == nil && !seen[domain] {
			domains = append(domains, domain)
			seen[domain] = true
		}
	}

	return domains
}

// ============================================================================
// Domain Normalization
// ============================================================================

// NormalizeDomain converts domain to canonical lowercase format
// removeWWW: if true, removes www. prefix
func NormalizeDomain(domain string, removeWWW bool) (string, error) {
	// Validate first
	if err := ValidateDomain(domain); err != nil {
		return "", err
	}

	// Trim whitespace
	normalized := strings.TrimSpace(domain)

	// Convert to lowercase (domains are case-insensitive)
	normalized = strings.ToLower(normalized)

	// Remove trailing dot
	normalized = strings.TrimSuffix(normalized, ".")

	// Remove www prefix if requested
	if removeWWW {
		normalized = strings.TrimPrefix(normalized, "www.")
	}

	// Try to convert from Punycode if it's an IDN
	if strings.HasPrefix(normalized, "xn--") || strings.Contains(normalized, ".xn--") {
		// Already in Punycode, keep as-is for storage
		return normalized, nil
	}

	// If it contains non-ASCII, convert to Punycode
	if !isASCII(normalized) {
		punycode, err := idna.ToASCII(normalized)
		if err != nil {
			return "", fmt.Errorf("failed to convert to Punycode: %w", err)
		}
		normalized = punycode
	}

	return normalized, nil
}

// NormalizeDomainUnicode normalizes and returns Unicode representation
func NormalizeDomainUnicode(domain string) (string, error) {
	// First normalize to ASCII/Punycode
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return "", err
	}

	// Convert back to Unicode for display
	unicode, err := idna.ToUnicode(normalized)
	if err != nil {
		return normalized, nil // Return Punycode if conversion fails
	}

	return unicode, nil
}

// isASCII checks if a string contains only ASCII characters
func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// ============================================================================
// Subdomain Analysis
// ============================================================================

// GetApexDomain extracts the apex domain (root domain) from a FQDN
// Example: www.api.example.com → example.com
func GetApexDomain(domain string) (string, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return "", err
	}

	// Use Public Suffix List to get eTLD+1
	apex, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to extract apex domain: %w", err)
	}

	return apex, nil
}

// GetEffectiveTLD returns the effective TLD using Public Suffix List
// Example: example.co.uk → co.uk
func GetEffectiveTLD(domain string) (string, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return "", err
	}

	etld, _ := publicsuffix.PublicSuffix(normalized)
	return etld, nil
}

// GetSubdomainDepth returns the number of subdomain levels
func GetSubdomainDepth(domain string) (int, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return 0, err
	}

	apex, err := GetApexDomain(normalized)
	if err != nil {
		return 0, err
	}

	// If domain equals apex, depth is 0
	if normalized == apex {
		return 0, nil
	}

	// Count subdomain levels
	domainLabels := strings.Split(normalized, ".")
	apexLabels := strings.Split(apex, ".")

	return len(domainLabels) - len(apexLabels), nil
}

// SplitDomainLabels splits a domain into its component labels
func SplitDomainLabels(domain string) ([]string, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return nil, err
	}

	return strings.Split(normalized, "."), nil
}

// IsApexDomain checks if the domain is an apex domain (no subdomains)
func IsApexDomain(domain string) (bool, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return false, err
	}

	apex, err := GetApexDomain(normalized)
	if err != nil {
		return false, err
	}

	return normalized == apex, nil
}

// GetParentDomain returns the parent domain
// Example: api.example.com → example.com
func GetParentDomain(domain string) (string, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return "", err
	}

	labels := strings.Split(normalized, ".")
	if len(labels) <= 2 {
		// Already at apex or TLD
		return "", errors.New("domain has no parent")
	}

	parent := strings.Join(labels[1:], ".")
	return parent, nil
}

// IsSubdomainOf checks if domain1 is a subdomain of domain2
func IsSubdomainOf(subdomain, parent string) (bool, error) {
	norm1, err1 := NormalizeDomain(subdomain, false)
	norm2, err2 := NormalizeDomain(parent, false)

	if err1 != nil || err2 != nil {
		return false, errors.New("invalid domain")
	}

	// Subdomain must end with parent domain
	return strings.HasSuffix(norm1, "."+norm2), nil
}

// ============================================================================
// TLD Identification
// ============================================================================

// GetTLD extracts the top-level domain
func GetTLD(domain string) (string, error) {
	normalized, err := NormalizeDomain(domain, false)
	if err != nil {
		return "", err
	}

	labels := strings.Split(normalized, ".")
	return labels[len(labels)-1], nil
}

// IsHighRiskTLD checks if a TLD is commonly associated with abuse
func IsHighRiskTLD(domain string) bool {
	tld, err := GetTLD(domain)
	if err != nil {
		return false
	}

	// High-risk free TLDs frequently abused
	highRiskTLDs := map[string]bool{
		"tk":   true, // Tokelau
		"ml":   true, // Mali
		"ga":   true, // Gabon
		"cf":   true, // Central African Republic
		"gq":   true, // Equatorial Guinea
		"top":  true, // Frequently abused new gTLD
		"xyz":  true, // Frequently abused
		"club": true, // Often used for spam
		"work": true, // Frequently abused
		"live": true, // Often used for phishing
	}

	return highRiskTLDs[tld]
}

// ============================================================================
// Internationalized Domain Name (IDN) Handling
// ============================================================================

// ToASCII converts a Unicode domain to ASCII-compatible Punycode
func ToASCII(domain string) (string, error) {
	punycode, err := idna.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("failed to convert to ASCII: %w", err)
	}
	return punycode, nil
}

// ToUnicode converts a Punycode domain to Unicode representation
func ToUnicode(domain string) (string, error) {
	unicode, err := idna.ToUnicode(domain)
	if err != nil {
		return "", fmt.Errorf("failed to convert to Unicode: %w", err)
	}
	return unicode, nil
}

// IsPunycode checks if a domain is in Punycode format
func IsPunycode(domain string) bool {
	return strings.HasPrefix(domain, "xn--") || strings.Contains(domain, ".xn--")
}

// DetectHomographAttack checks for visually similar characters from different scripts
func DetectHomographAttack(domain string) bool {
	// Convert to Unicode if Punycode
	unicodeDomain := domain
	if IsPunycode(domain) {
		var err error
		unicodeDomain, err = ToUnicode(domain)
		if err != nil {
			return false
		}
	}

	// Check for mixed scripts (potential homograph attack)
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range unicodeDomain {
		if unicode.Is(unicode.Latin, r) {
			hasLatin = true
		}
		if unicode.Is(unicode.Cyrillic, r) {
			hasCyrillic = true
		}
		if unicode.Is(unicode.Greek, r) {
			hasGreek = true
		}
	}

	// If mixing multiple scripts, potential homograph attack
	scriptsCount := 0
	if hasLatin {
		scriptsCount++
	}
	if hasCyrillic {
		scriptsCount++
	}
	if hasGreek {
		scriptsCount++
	}

	return scriptsCount > 1
}

// ============================================================================
// Utility Functions
// ============================================================================

// CompareDomains compares two domains for equality (normalized)
func CompareDomains(domain1, domain2 string) bool {
	norm1, err1 := NormalizeDomain(domain1, false)
	norm2, err2 := NormalizeDomain(domain2, false)

	if err1 != nil || err2 != nil {
		return false
	}

	return norm1 == norm2
}

// RemoveDuplicateDomains removes duplicate domains from a slice
func RemoveDuplicateDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	result := make([]string, 0, len(domains))

	for _, domain := range domains {
		normalized, err := NormalizeDomain(domain, false)
		if err != nil {
			continue // Skip invalid domains
		}

		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}

	return result
}

// GetDomainWithoutWWW returns domain with www. prefix removed
func GetDomainWithoutWWW(domain string) (string, error) {
	return NormalizeDomain(domain, true)
}
