// Package utils provides common utility functions for threat intelligence
package utils

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ============================================================================
// Hash Type Enumeration
// ============================================================================

// HashType represents the type of cryptographic hash
type HashType int

const (
	HashUnknown HashType = iota
	HashMD5              // 128 bits, 32 hex chars
	HashSHA1             // 160 bits, 40 hex chars
	HashSHA256           // 256 bits, 64 hex chars
	HashSHA512           // 512 bits, 128 hex chars
)

// String returns the string representation of a hash type
func (ht HashType) String() string {
	switch ht {
	case HashMD5:
		return "md5"
	case HashSHA1:
		return "sha1"
	case HashSHA256:
		return "sha256"
	case HashSHA512:
		return "sha512"
	default:
		return "unknown"
	}
}

// Length returns the expected hex string length for the hash type
func (ht HashType) Length() int {
	switch ht {
	case HashMD5:
		return 32
	case HashSHA1:
		return 40
	case HashSHA256:
		return 64
	case HashSHA512:
		return 128
	default:
		return 0
	}
}

// ============================================================================
// Hash Format Validation
// ============================================================================

var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// IsValidHash checks if a string is a valid cryptographic hash
func IsValidHash(hashStr string) bool {
	_, err := DetectHashType(hashStr)
	return err == nil
}

// IsValidMD5 checks if a string is a valid MD5 hash
func IsValidMD5(hashStr string) bool {
	cleaned := cleanHashString(hashStr)
	return len(cleaned) == 32 && hexPattern.MatchString(cleaned)
}

// IsValidSHA1 checks if a string is a valid SHA1 hash
func IsValidSHA1(hashStr string) bool {
	cleaned := cleanHashString(hashStr)
	return len(cleaned) == 40 && hexPattern.MatchString(cleaned)
}

// IsValidSHA256 checks if a string is a valid SHA256 hash
func IsValidSHA256(hashStr string) bool {
	cleaned := cleanHashString(hashStr)
	return len(cleaned) == 64 && hexPattern.MatchString(cleaned)
}

// IsValidSHA512 checks if a string is a valid SHA512 hash
func IsValidSHA512(hashStr string) bool {
	cleaned := cleanHashString(hashStr)
	return len(cleaned) == 128 && hexPattern.MatchString(cleaned)
}

// ValidateHash validates a hash string and returns the hash type
func ValidateHash(hashStr string) (HashType, error) {
	hashType, err := DetectHashType(hashStr)
	if err != nil {
		return HashUnknown, err
	}
	return hashType, nil
}

// ============================================================================
// Hash Normalization
// ============================================================================

// NormalizeHash converts a hash to canonical lowercase format
func NormalizeHash(hashStr string) (string, error) {
	// Clean the hash string
	cleaned := cleanHashString(hashStr)

	// Validate it's valid hex
	if !hexPattern.MatchString(cleaned) {
		return "", errors.New("hash contains invalid characters")
	}

	// Validate length matches a known hash type
	hashType, err := DetectHashType(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid hash length: %w", err)
	}

	// Ensure it's the correct length for the detected type
	if len(cleaned) != hashType.Length() {
		return "", fmt.Errorf("hash length %d doesn't match expected %d for %s",
			len(cleaned), hashType.Length(), hashType.String())
	}

	// Return lowercase normalized hash
	return strings.ToLower(cleaned), nil
}

// NormalizeHashWithPrefix normalizes hash and adds algorithm prefix
func NormalizeHashWithPrefix(hashStr string) (string, error) {
	normalized, err := NormalizeHash(hashStr)
	if err != nil {
		return "", err
	}

	hashType, _ := DetectHashType(normalized)
	return hashType.String() + ":" + normalized, nil
}

// cleanHashString removes common formatting from hash strings
func cleanHashString(hashStr string) string {
	// Trim whitespace
	cleaned := strings.TrimSpace(hashStr)

	// Remove common prefixes
	cleaned = strings.TrimPrefix(cleaned, "md5:")
	cleaned = strings.TrimPrefix(cleaned, "MD5:")
	cleaned = strings.TrimPrefix(cleaned, "sha1:")
	cleaned = strings.TrimPrefix(cleaned, "SHA1:")
	cleaned = strings.TrimPrefix(cleaned, "sha256:")
	cleaned = strings.TrimPrefix(cleaned, "SHA256:")
	cleaned = strings.TrimPrefix(cleaned, "sha512:")
	cleaned = strings.TrimPrefix(cleaned, "SHA512:")
	cleaned = strings.TrimPrefix(cleaned, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")

	// Remove spaces, dashes, colons
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ":", "")

	return cleaned
}

// ============================================================================
// Hash Type Detection
// ============================================================================

// DetectHashType automatically identifies the hash algorithm from string
func DetectHashType(hashStr string) (HashType, error) {
	cleaned := cleanHashString(hashStr)

	// Check for explicit prefix (already cleaned above, so check original)
	if strings.HasPrefix(strings.ToLower(hashStr), "md5:") {
		return HashMD5, nil
	}
	if strings.HasPrefix(strings.ToLower(hashStr), "sha1:") {
		return HashSHA1, nil
	}
	if strings.HasPrefix(strings.ToLower(hashStr), "sha256:") {
		return HashSHA256, nil
	}
	if strings.HasPrefix(strings.ToLower(hashStr), "sha512:") {
		return HashSHA512, nil
	}

	// Detect from length
	switch len(cleaned) {
	case 32:
		return HashMD5, nil
	case 40:
		return HashSHA1, nil
	case 64:
		return HashSHA256, nil
	case 128:
		return HashSHA512, nil
	default:
		return HashUnknown, fmt.Errorf("unknown hash length: %d", len(cleaned))
	}
}

// GetHashType returns the HashType enum for a hash string
func GetHashType(hashStr string) HashType {
	hashType, err := DetectHashType(hashStr)
	if err != nil {
		return HashUnknown
	}
	return hashType
}

// ============================================================================
// Hash Comparison
// ============================================================================

// CompareHashes compares two hashes for equality (case-insensitive, constant-time)
func CompareHashes(hash1, hash2 string) bool {
	// Normalize both hashes
	norm1, err1 := NormalizeHash(hash1)
	norm2, err2 := NormalizeHash(hash2)

	// If either is invalid, they're not equal
	if err1 != nil || err2 != nil {
		return false
	}

	// Must be same length (same hash type)
	if len(norm1) != len(norm2) {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(norm1), []byte(norm2)) == 1
}

// HashesEqual checks if two hashes are equal (simple version)
func HashesEqual(hash1, hash2 string) bool {
	return CompareHashes(hash1, hash2)
}

// ============================================================================
// Batch Hash Validation
// ============================================================================

// ValidationResult holds the result of validating a single hash
type ValidationResult struct {
	OriginalHash   string
	NormalizedHash string
	HashType       HashType
	Valid          bool
	Error          string
}

// BatchValidationSummary holds summary statistics for batch validation
type BatchValidationSummary struct {
	Total       int
	Valid       int
	Invalid     int
	MD5Count    int
	SHA1Count   int
	SHA256Count int
	SHA512Count int
	Duplicates  int
}

// ValidateHashBatch validates multiple hashes and returns results
func ValidateHashBatch(hashes []string, deduplicate bool) ([]ValidationResult, BatchValidationSummary) {
	results := make([]ValidationResult, 0, len(hashes))
	summary := BatchValidationSummary{
		Total: len(hashes),
	}

	seen := make(map[string]bool)

	for _, hash := range hashes {
		result := ValidationResult{
			OriginalHash: hash,
		}

		// Normalize the hash
		normalized, err := NormalizeHash(hash)
		if err != nil {
			result.Valid = false
			result.Error = err.Error()
			summary.Invalid++
			results = append(results, result)
			continue
		}

		result.NormalizedHash = normalized

		// Detect hash type
		hashType, err := DetectHashType(normalized)
		if err != nil {
			result.Valid = false
			result.Error = err.Error()
			summary.Invalid++
			results = append(results, result)
			continue
		}

		result.HashType = hashType
		result.Valid = true

		// Check for duplicates if requested
		if deduplicate {
			if seen[normalized] {
				result.Error = "duplicate"
				summary.Duplicates++
			} else {
				seen[normalized] = true
			}
		}

		// Update summary counts
		summary.Valid++
		switch hashType {
		case HashMD5:
			summary.MD5Count++
		case HashSHA1:
			summary.SHA1Count++
		case HashSHA256:
			summary.SHA256Count++
		case HashSHA512:
			summary.SHA512Count++
		}

		results = append(results, result)
	}

	return results, summary
}

// GetValidHashes returns only valid hashes from a batch
func GetValidHashes(hashes []string) []string {
	valid := make([]string, 0, len(hashes))

	for _, hash := range hashes {
		normalized, err := NormalizeHash(hash)
		if err == nil {
			valid = append(valid, normalized)
		}
	}

	return valid
}

// RemoveDuplicateHashes removes duplicate hashes from a slice
func RemoveDuplicateHashes(hashes []string) []string {
	seen := make(map[string]bool, len(hashes))
	result := make([]string, 0, len(hashes))

	for _, hash := range hashes {
		normalized, err := NormalizeHash(hash)
		if err != nil {
			continue // Skip invalid hashes
		}

		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}

	return result
}

// ============================================================================
// Hash Format Conversion
// ============================================================================

// HashToBytes converts a hex hash string to byte array
func HashToBytes(hashStr string) ([]byte, error) {
	normalized, err := NormalizeHash(hashStr)
	if err != nil {
		return nil, err
	}

	bytes, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	return bytes, nil
}

// BytesToHash converts a byte array to a hex hash string
func BytesToHash(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// HashToBase64 converts a hex hash to Base64 encoding
func HashToBase64(hashStr string) (string, error) {
	bytes, err := HashToBytes(hashStr)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Base64ToHash converts a Base64 encoded hash to hex string
func Base64ToHash(b64Str string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	hashStr := hex.EncodeToString(bytes)

	// Validate it's a known hash type
	_, err = DetectHashType(hashStr)
	if err != nil {
		return "", fmt.Errorf("decoded hash has invalid length: %w", err)
	}

	return hashStr, nil
}

// MD5ToInt converts an MD5 hash to a 128-bit integer representation
// Returns as two uint64s (high and low 64 bits)
func MD5ToInt(hashStr string) (high, low uint64, err error) {
	normalized, err := NormalizeHash(hashStr)
	if err != nil {
		return 0, 0, err
	}

	if len(normalized) != 32 {
		return 0, 0, errors.New("not an MD5 hash")
	}

	bytes, err := hex.DecodeString(normalized)
	if err != nil {
		return 0, 0, err
	}

	// MD5 is 16 bytes (128 bits)
	// Split into two 64-bit integers
	for i := 0; i < 8; i++ {
		high = (high << 8) | uint64(bytes[i])
	}
	for i := 8; i < 16; i++ {
		low = (low << 8) | uint64(bytes[i])
	}

	return high, low, nil
}

// IntToMD5 converts a 128-bit integer representation back to MD5 hex string
func IntToMD5(high, low uint64) string {
	bytes := make([]byte, 16)

	// High 64 bits
	for i := 7; i >= 0; i-- {
		bytes[i] = byte(high & 0xFF)
		high >>= 8
	}

	// Low 64 bits
	for i := 15; i >= 8; i-- {
		bytes[i] = byte(low & 0xFF)
		low >>= 8
	}

	return hex.EncodeToString(bytes)
}

// ============================================================================
// Utility Functions
// ============================================================================

// FormatHash formats a hash with optional prefix and separators
func FormatHash(hashStr string, withPrefix bool, separator string) (string, error) {
	normalized, err := NormalizeHash(hashStr)
	if err != nil {
		return "", err
	}

	hashType, _ := DetectHashType(normalized)

	formatted := normalized
	if separator != "" {
		// Insert separator every 2 characters (byte boundaries)
		parts := make([]string, 0, len(normalized)/2)
		for i := 0; i < len(normalized); i += 2 {
			if i+2 <= len(normalized) {
				parts = append(parts, normalized[i:i+2])
			}
		}
		formatted = strings.Join(parts, separator)
	}

	if withPrefix {
		formatted = hashType.String() + ":" + formatted
	}

	return formatted, nil
}

// SplitHashWithPrefix splits a prefixed hash into type and value
func SplitHashWithPrefix(prefixedHash string) (HashType, string, error) {
	parts := strings.SplitN(prefixedHash, ":", 2)
	if len(parts) != 2 {
		// No prefix, try to detect
		hashType, err := DetectHashType(prefixedHash)
		if err != nil {
			return HashUnknown, "", err
		}
		normalized, err := NormalizeHash(prefixedHash)
		if err != nil {
			return HashUnknown, "", err
		}
		return hashType, normalized, nil
	}

	// Parse prefix
	var hashType HashType
	switch strings.ToLower(parts[0]) {
	case "md5":
		hashType = HashMD5
	case "sha1":
		hashType = HashSHA1
	case "sha256":
		hashType = HashSHA256
	case "sha512":
		hashType = HashSHA512
	default:
		return HashUnknown, "", fmt.Errorf("unknown hash type prefix: %s", parts[0])
	}

	normalized, err := NormalizeHash(parts[1])
	if err != nil {
		return HashUnknown, "", err
	}

	return hashType, normalized, nil
}
