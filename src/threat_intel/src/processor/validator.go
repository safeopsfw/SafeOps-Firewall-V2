package processor

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Validator provides validation utilities for threat intelligence data
type Validator struct {
	allowPrivateIPs bool
	isoCountryCodes map[string]bool
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		allowPrivateIPs: false,
		isoCountryCodes: buildISOCountryCodes(),
	}
}

// ValidateIP validates an IP address and returns parsed IP
func (v *Validator) ValidateIP(ipStr string) (net.IP, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return nil, fmt.Errorf("empty IP address")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format: %s", ipStr)
	}

	// Check for private/reserved IPs
	if !v.allowPrivateIPs {
		if v.IsPrivateIP(ip) {
			return nil, fmt.Errorf("private IP not allowed: %s", ipStr)
		}
		if v.IsLoopbackIP(ip) {
			return nil, fmt.Errorf("loopback IP not allowed: %s", ipStr)
		}
	}

	return ip, nil
}

// IsPrivateIP checks if IP is in private range
func (v *Validator) IsPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
		"fc00::/7",       // IPv6 private
		"fe80::/10",      // IPv6 link-local
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsLoopbackIP checks if IP is loopback
func (v *Validator) IsLoopbackIP(ip net.IP) bool {
	return ip.IsLoopback()
}

// ValidateCountryCode validates ISO 3166-1 alpha-2 country code
func (v *Validator) ValidateCountryCode(code string) (string, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	if len(code) != 2 {
		return "", fmt.Errorf("country code must be 2 characters: %s", code)
	}

	if !v.isoCountryCodes[code] {
		return "", fmt.Errorf("invalid ISO 3166-1 country code: %s", code)
	}

	return code, nil
}

// ValidateLatitude validates latitude range
func (v *Validator) ValidateLatitude(lat float64) bool {
	return lat >= -90 && lat <= 90
}

// ValidateLongitude validates longitude range
func (v *Validator) ValidateLongitude(lon float64) bool {
	return lon >= -180 && lon <= 180
}

// ValidateTimezone validates IANA timezone format
func (v *Validator) ValidateTimezone(tz string) bool {
	if tz == "" || tz == "UTC" {
		return true
	}
	// IANA format: Region/City
	matched, _ := regexp.MatchString(`^[A-Za-z]+/[A-Za-z_]+$`, tz)
	return matched
}

// ValidateDomain validates domain format
func (v *Validator) ValidateDomain(domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("empty domain")
	}

	// Basic domain regex
	pattern := `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	if !matched {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	return nil
}

// ValidateHash validates hash format (MD5, SHA1, SHA256)
func (v *Validator) ValidateHash(hash string) (string, string, error) {
	hash = strings.TrimSpace(strings.ToLower(hash))
	if hash == "" {
		return "", "", fmt.Errorf("empty hash")
	}

	switch len(hash) {
	case 32:
		if matched, _ := regexp.MatchString(`^[a-f0-9]{32}$`, hash); matched {
			return hash, "md5", nil
		}
	case 40:
		if matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, hash); matched {
			return hash, "sha1", nil
		}
	case 64:
		if matched, _ := regexp.MatchString(`^[a-f0-9]{64}$`, hash); matched {
			return hash, "sha256", nil
		}
	}

	return "", "", fmt.Errorf("invalid hash format: %s", hash)
}

// ValidateURL validates URL format
func (v *Validator) ValidateURL(urlStr string) error {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return fmt.Errorf("empty URL")
	}

	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}

	return nil
}

// SetAllowPrivateIPs sets whether private IPs are allowed
func (v *Validator) SetAllowPrivateIPs(allow bool) {
	v.allowPrivateIPs = allow
}

// NormalizeString trims and normalizes string
func NormalizeString(s string) string {
	s = strings.TrimSpace(s)
	// Collapse multiple spaces
	space := regexp.MustCompile(`\s+`)
	s = space.ReplaceAllString(s, " ")
	return s
}

// NormalizeCityName normalizes city name to proper case
func NormalizeCityName(city string) string {
	city = NormalizeString(city)
	if city == "" {
		return ""
	}

	// Simple title case
	words := strings.Fields(city)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

// buildISOCountryCodes returns map of valid ISO 3166-1 alpha-2 codes
func buildISOCountryCodes() map[string]bool {
	codes := []string{
		"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
		"BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
		"BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
		"CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
		"EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
		"GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
		"HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
		"JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
		"LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
		"ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
		"NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
		"PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
		"SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
		"ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
		"TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
		"VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
	}

	m := make(map[string]bool)
	for _, code := range codes {
		m[code] = true
	}
	return m
}
