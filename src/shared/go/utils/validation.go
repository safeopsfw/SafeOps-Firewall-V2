// Package utils provides validation utilities.
package utils

import (
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Validator provides validation functions
type Validator struct {
	errors []string
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		errors: make([]string, 0),
	}
}

// Errors returns all validation errors
func (v *Validator) Errors() []string {
	return v.errors
}

// HasErrors returns true if there are errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// AddError adds an error
func (v *Validator) AddError(msg string) {
	v.errors = append(v.errors, msg)
}

// Required validates that a string is not empty
func (v *Validator) Required(field, value string) bool {
	if strings.TrimSpace(value) == "" {
		v.AddError(field + " is required")
		return false
	}
	return true
}

// MinLength validates minimum string length
func (v *Validator) MinLength(field, value string, min int) bool {
	if len(value) < min {
		v.AddError(field + " must be at least " + string(rune(min)) + " characters")
		return false
	}
	return true
}

// MaxLength validates maximum string length
func (v *Validator) MaxLength(field, value string, max int) bool {
	if len(value) > max {
		v.AddError(field + " must be at most " + string(rune(max)) + " characters")
		return false
	}
	return true
}

// Email validates email format
func (v *Validator) Email(field, value string) bool {
	if !IsEmail(value) {
		v.AddError(field + " must be a valid email")
		return false
	}
	return true
}

// URL validates URL format
func (v *Validator) URL(field, value string) bool {
	if !IsURL(value) {
		v.AddError(field + " must be a valid URL")
		return false
	}
	return true
}

// Standalone validation functions

// IsEmail checks if a string is a valid email
func IsEmail(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}

// IsURL checks if a string is a valid URL
func IsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// IsIP checks if a string is a valid IP address
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsIPv4 checks if a string is a valid IPv4 address
func IsIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// IsIPv6 checks if a string is a valid IPv6 address
func IsIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// IsCIDR checks if a string is valid CIDR notation
func IsCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// IsPort checks if a number is a valid port
func IsPort(port int) bool {
	return port >= 1 && port <= 65535
}

// IsAlphanumeric checks if a string contains only alphanumeric characters
func IsAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

// IsAlpha checks if a string contains only letters
func IsAlpha(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return len(s) > 0
}

// IsNumeric checks if a string contains only digits
func IsNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

// IsHex checks if a string is valid hexadecimal
func IsHex(s string) bool {
	matched, _ := regexp.MatchString("^[0-9a-fA-F]+$", s)
	return matched
}

// IsUUID checks if a string is a valid UUID
func IsUUID(s string) bool {
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	matched, _ := regexp.MatchString(pattern, strings.ToLower(s))
	return matched
}

// IsSlug checks if a string is a valid URL slug
func IsSlug(s string) bool {
	matched, _ := regexp.MatchString(`^[a-z0-9]+(?:-[a-z0-9]+)*$`, s)
	return matched
}

// IsJSON checks if a string is valid JSON (basic check)
func IsJSON(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

// ContainsUppercase checks if string contains uppercase letters
func ContainsUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// ContainsLowercase checks if string contains lowercase letters
func ContainsLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

// ContainsDigit checks if string contains digits
func ContainsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// ContainsSpecial checks if string contains special characters
func ContainsSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// Sanitize removes potentially dangerous characters
func Sanitize(s string) string {
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")
	// Trim whitespace
	s = strings.TrimSpace(s)
	return s
}

// SanitizeHTML escapes HTML special characters
func SanitizeHTML(s string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
