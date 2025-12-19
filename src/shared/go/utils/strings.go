// Package utils provides comprehensive string manipulation utilities for SafeOps services.
// This file includes functions for safe string parsing, sanitization, case-insensitive
// operations, string transformations, and efficient string building.
package utils

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ============================================================================
// Safe String Parsing
// ============================================================================

// ParseInt parses a string to int with a default fallback value.
// Returns defaultValue if the string cannot be parsed.
func ParseInt(s string, defaultValue int) int {
	val, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return defaultValue
	}
	return val
}

// ParseFloat parses a string to float64 with a default fallback value.
// Returns defaultValue if the string cannot be parsed.
func ParseFloat(s string, defaultValue float64) float64 {
	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return defaultValue
	}
	return val
}

// ParseBool parses a string to bool with a default fallback value.
// Accepts: true/false, 1/0, yes/no, on/off (case-insensitive).
// Returns defaultValue if the string cannot be parsed.
func ParseBool(s string, defaultValue bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "true", "1", "yes", "on", "t", "y":
		return true
	case "false", "0", "no", "off", "f", "n":
		return false
	default:
		return defaultValue
	}
}

// ParseDuration parses a string to time.Duration with a default fallback value.
// Accepts standard duration strings like "300ms", "1.5h", "2h45m".
// Returns defaultValue if the string cannot be parsed.
func ParseDuration(s string, defaultValue time.Duration) time.Duration {
	val, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return defaultValue
	}
	return val
}

// ============================================================================
// String Sanitization
// ============================================================================

var (
	// controlCharRegex matches control characters except tab
	controlCharRegex = regexp.MustCompile(`[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]`)
	// newlineRegex matches newlines and carriage returns
	newlineRegex = regexp.MustCompile(`[\r\n]+`)
	// multiSpaceRegex matches multiple consecutive spaces
	multiSpaceRegex = regexp.MustCompile(`\s+`)
	// slugifyRegex matches characters that are not alphanumeric or hyphens
	slugifyRegex = regexp.MustCompile(`[^a-z0-9-]+`)
	// multiHyphenRegex matches multiple consecutive hyphens
	multiHyphenRegex = regexp.MustCompile(`-+`)
)

// SanitizeForLog removes control characters and newlines to prevent log injection attacks.
// This function converts newlines to spaces and removes other control characters,
// making the string safe for inclusion in log messages.
func SanitizeForLog(s string) string {
	// Replace newlines and carriage returns with spaces
	s = newlineRegex.ReplaceAllString(s, " ")
	// Remove other control characters
	s = controlCharRegex.ReplaceAllString(s, "")
	// Normalize whitespace
	s = strings.TrimSpace(s)
	return s
}

// TruncateWithEllipsis limits string length and appends "..." if truncated.
// The maxLen includes the ellipsis length, so the actual string content
// will be maxLen-3 characters if truncation occurs.
// Returns the original string if it's shorter than maxLen.
func TruncateWithEllipsis(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if maxLen <= 3 {
		// If maxLen is very small, just truncate without ellipsis
		runes := []rune(s)
		if len(runes) <= maxLen {
			return s
		}
		return string(runes[:maxLen])
	}

	// Count runes, not bytes, for proper Unicode handling
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}

	return string(runes[:maxLen-3]) + "..."
}

// RemoveNullBytes strips all null characters (\x00) from the string.
// Null bytes can cause issues in C interop and database operations.
func RemoveNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// NormalizeWhitespace collapses multiple consecutive whitespace characters
// (spaces, tabs, newlines) into a single space and trims leading/trailing whitespace.
func NormalizeWhitespace(s string) string {
	s = multiSpaceRegex.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// ============================================================================
// Case-Insensitive Operations
// ============================================================================

// EqualFold reports whether two strings are equal under Unicode case-folding.
// This is a wrapper around strings.EqualFold for consistency with other functions.
func EqualFold(a, b string) bool {
	return strings.EqualFold(a, b)
}

// ContainsFold reports whether substr is within s, ignoring case.
func ContainsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// HasPrefixFold reports whether s begins with prefix, ignoring case.
func HasPrefixFold(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

// HasSuffixFold reports whether s ends with suffix, ignoring case.
func HasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}

// ============================================================================
// String Slicing and Trimming
// ============================================================================

// SafeSubstring returns a substring from start to end indices (exclusive end).
// Unlike normal slicing, this function never panics on invalid indices.
// Returns empty string if indices are out of bounds or invalid.
// Handles negative indices by treating them as 0.
// Properly handles Unicode (works with runes, not bytes).
func SafeSubstring(s string, start, end int) string {
	runes := []rune(s)
	length := len(runes)

	// Handle negative or invalid start
	if start < 0 {
		start = 0
	}
	if start >= length {
		return ""
	}

	// Handle negative or invalid end
	if end < 0 {
		end = 0
	}
	if end > length {
		end = length
	}

	// Ensure start <= end
	if start > end {
		return ""
	}

	return string(runes[start:end])
}

// TrimPrefix removes the prefix from s if present, otherwise returns s unchanged.
// This is a direct wrapper around strings.TrimPrefix for API consistency.
func TrimPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

// TrimSuffix removes the suffix from s if present, otherwise returns s unchanged.
// This is a direct wrapper around strings.TrimSuffix for API consistency.
func TrimSuffix(s, suffix string) string {
	return strings.TrimSuffix(s, suffix)
}

// TrimSpace removes leading and trailing whitespace from s.
// This is a direct wrapper around strings.TrimSpace for API consistency.
func TrimSpace(s string) string {
	return strings.TrimSpace(s)
}

// TrimQuotes removes surrounding quotes from a string.
// Handles double quotes ("), single quotes ('), and backticks (`).
// Only removes quotes if they match on both sides.
func TrimQuotes(s string) string {
	if len(s) < 2 {
		return s
	}

	// Check for matching quotes
	if (s[0] == '"' && s[len(s)-1] == '"') ||
		(s[0] == '\'' && s[len(s)-1] == '\'') ||
		(s[0] == '`' && s[len(s)-1] == '`') {
		return s[1 : len(s)-1]
	}

	return s
}

// ============================================================================
// String Transformation
// ============================================================================

// ToSnakeCase converts a string from CamelCase to snake_case.
// Example: "CamelCaseString" -> "camel_case_string"
func ToSnakeCase(s string) string {
	if s == "" {
		return ""
	}

	var result strings.Builder
	runes := []rune(s)

	for i, r := range runes {
		// Insert underscore before uppercase letters (except at start)
		if i > 0 && unicode.IsUpper(r) {
			// Check if previous char is lowercase or next char is lowercase
			// to handle sequences like "HTTPServer" -> "http_server"
			prevIsLower := i > 0 && unicode.IsLower(runes[i-1])
			nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])

			if prevIsLower || nextIsLower {
				result.WriteRune('_')
			}
		}
		result.WriteRune(unicode.ToLower(r))
	}

	return result.String()
}

// ToCamelCase converts a string from snake_case to CamelCase (PascalCase).
// Example: "snake_case_string" -> "SnakeCaseString"
func ToCamelCase(s string) string {
	if s == "" {
		return ""
	}

	words := strings.Split(s, "_")
	var result strings.Builder

	for _, word := range words {
		if word == "" {
			continue
		}
		// Capitalize first letter of each word
		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		result.WriteString(string(runes))
	}

	return result.String()
}

// ToKebabCase converts a string from CamelCase to kebab-case.
// Example: "CamelCaseString" -> "camel-case-string"
func ToKebabCase(s string) string {
	snakeCase := ToSnakeCase(s)
	return strings.ReplaceAll(snakeCase, "_", "-")
}

// Slugify converts a string to a URL-safe slug.
// - Converts to lowercase
// - Replaces spaces and underscores with hyphens
// - Removes all non-alphanumeric characters except hyphens
// - Collapses multiple consecutive hyphens into one
// - Trims leading and trailing hyphens
// Example: "Hello World! 123" -> "hello-world-123"
func Slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces and underscores with hyphens
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")

	// Remove all characters that are not alphanumeric or hyphens
	s = slugifyRegex.ReplaceAllString(s, "")

	// Collapse multiple hyphens
	s = multiHyphenRegex.ReplaceAllString(s, "-")

	// Trim hyphens from start and end
	s = strings.Trim(s, "-")

	return s
}

// ============================================================================
// String Builder Helpers
// ============================================================================

// JoinNonEmpty joins strings with a separator, skipping empty strings.
// This is useful for building lists where some values might be optional.
// Example: JoinNonEmpty(", ", "a", "", "b", "c") -> "a, b, c"
func JoinNonEmpty(sep string, parts ...string) string {
	var nonEmpty []string
	for _, part := range parts {
		if part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	return strings.Join(nonEmpty, sep)
}

// BuildString provides a builder pattern helper for efficient string construction.
// The function parameter receives a strings.Builder to write to.
// This is useful for complex string building logic with pre-allocated capacity.
// Example:
//
//	s := BuildString(func(b *strings.Builder) {
//	    b.WriteString("Hello")
//	    b.WriteString(" ")
//	    b.WriteString("World")
//	})
func BuildString(fn func(*strings.Builder)) string {
	var builder strings.Builder
	fn(&builder)
	return builder.String()
}

// RepeatChar efficiently repeats a single character n times.
// More efficient than strings.Repeat for single characters.
// Returns empty string if count <= 0.
func RepeatChar(char rune, count int) string {
	if count <= 0 {
		return ""
	}

	// Pre-allocate with exact capacity needed
	runes := make([]rune, count)
	for i := 0; i < count; i++ {
		runes[i] = char
	}
	return string(runes)
}

// ============================================================================
// Additional Utility Functions (from previous implementation + spec)
// ============================================================================

// Truncate truncates a string to maxLen characters and appends suffix if truncated.
// Unlike TruncateWithEllipsis, this allows custom suffix and doesn't count suffix in maxLen.
// If suffix is longer than maxLen, only the truncated string is returned without suffix.
func Truncate(s string, maxLen int, suffix string) string {
	if maxLen <= 0 {
		return ""
	}

	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}

	// If suffix is too long, just truncate without it
	suffixRunes := []rune(suffix)
	if len(suffixRunes) >= maxLen {
		return string(runes[:maxLen])
	}

	// Truncate and add suffix
	truncateAt := maxLen - len(suffixRunes)
	if truncateAt < 0 {
		truncateAt = 0
	}

	return string(runes[:truncateAt]) + suffix
}

// Capitalize capitalizes the first letter
func Capitalize(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// ToPascalCase converts to PascalCase (alias for ToCamelCase)
func ToPascalCase(s string) string {
	return ToCamelCase(s)
}

// ReverseString reverses a string while properly handling Unicode
func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// DefaultIfEmpty returns default value if string is empty
func DefaultIfEmpty(s, defaultVal string) string {
	if IsEmpty(s) {
		return defaultVal
	}
	return s
}

// RemoveWhitespace removes all whitespace from a string
func RemoveWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// ContainsAny checks if string contains any of the substrings
func ContainsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ContainsAll checks if string contains all of the substrings
func ContainsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// CountWords counts the number of words in a string
func CountWords(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	return len(strings.Fields(s))
}

// SplitLines splits string into lines
func SplitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// JoinLines joins strings with newlines
func JoinLines(lines ...string) string {
	return strings.Join(lines, "\n")
}

// Repeat repeats a string n times
func Repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

// PadLeftStr pads a string on the left
func PadLeftStr(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}

	padding := strings.Repeat(pad, (length-len(s))/len(pad)+1)
	return padding[:length-len(s)] + s
}

// PadRightStr pads a string on the right
func PadRightStr(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}

	padding := strings.Repeat(pad, (length-len(s))/len(pad)+1)
	return s + padding[:length-len(s)]
}

// Center centers a string
func Center(s string, width int) string {
	if len(s) >= width {
		return s
	}

	leftPad := (width - len(s)) / 2
	rightPad := width - len(s) - leftPad

	return strings.Repeat(" ", leftPad) + s + strings.Repeat(" ", rightPad)
}

// StripPrefix removes prefix if present (alias for TrimPrefix)
func StripPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

// StripSuffix removes suffix if present (alias for TrimSuffix)
func StripSuffix(s, suffix string) string {
	return strings.TrimSuffix(s, suffix)
}

// Mask masks part of a string (e.g., for passwords)
func Mask(s string, showFirst, showLast int, maskChar rune) string {
	runes := []rune(s)
	length := len(runes)

	if length <= showFirst+showLast {
		return strings.Repeat(string(maskChar), length)
	}

	var result strings.Builder

	for i := 0; i < showFirst; i++ {
		result.WriteRune(runes[i])
	}

	for i := 0; i < length-showFirst-showLast; i++ {
		result.WriteRune(maskChar)
	}

	for i := length - showLast; i < length; i++ {
		result.WriteRune(runes[i])
	}

	return result.String()
}

// MaskEmail masks an email address
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	local := parts[0]
	domain := parts[1]

	if len(local) <= 2 {
		return Mask(local, 1, 0, '*') + "@" + domain
	}

	return Mask(local, 2, 1, '*') + "@" + domain
}

// RemoveNonPrintable removes all non-printable characters from a string.
// This includes control characters, null bytes, and other invisible characters.
// Preserves spaces, tabs, and newlines.
func RemoveNonPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return -1 // Drop the rune
	}, s)
}

// Sanitize is a comprehensive sanitization function that combines multiple sanitization steps.
// It removes non-printable characters, normalizes whitespace, and removes null bytes.
// Use this for general-purpose sanitization of untrusted input.
func Sanitize(s string) string {
	s = RemoveNonPrintable(s)
	s = RemoveNullBytes(s)
	s = NormalizeWhitespace(s)
	return s
}

// TrimWhitespace is an alias for TrimSpace
func TrimWhitespace(s string) string {
	return strings.TrimSpace(s)
}

// IsValidUTF8 checks if a string contains only valid UTF-8 encoded characters
func IsValidUTF8(s string) bool {
	return utf8.ValidString(s)
}
