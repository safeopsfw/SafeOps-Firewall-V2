// Package utils provides string utilities.
package utils

import (
	"regexp"
	"strings"
	"unicode"
)

// Truncate truncates a string to the given length
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// TruncateWithEllipsis truncates and adds ellipsis
func TruncateWithEllipsis(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
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

// ToSnakeCase converts to snake_case
func ToSnakeCase(s string) string {
	var result strings.Builder

	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				result.WriteByte('_')
			}
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ToCamelCase converts to camelCase
func ToCamelCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i := 1; i < len(parts); i++ {
		parts[i] = Capitalize(parts[i])
	}

	return strings.Join(parts, "")
}

// ToPascalCase converts to PascalCase
func ToPascalCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i := range parts {
		parts[i] = Capitalize(parts[i])
	}

	return strings.Join(parts, "")
}

// ToKebabCase converts to kebab-case
func ToKebabCase(s string) string {
	return strings.ReplaceAll(ToSnakeCase(s), "_", "-")
}

// Reverse reverses a string
func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// IsEmpty checks if a string is empty or whitespace
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

// NormalizeWhitespace replaces multiple whitespace with single space
func NormalizeWhitespace(s string) string {
	re := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(re.ReplaceAllString(s, " "))
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

// CountWords counts words in a string
func CountWords(s string) int {
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

// StripPrefix removes prefix if present
func StripPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

// StripSuffix removes suffix if present
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
