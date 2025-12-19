// Package utils provides comprehensive byte manipulation utilities for SafeOps services.
// This file includes functions for byte format conversion, human-readable size formatting,
// safe byte operations, constant-time comparison, buffer pooling, and bit manipulation.
package utils

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ============================================================================
// Byte Format Conversion
// ============================================================================

// BytesToHex converts bytes to lowercase hexadecimal string
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// ToHex is an alias for BytesToHex
func ToHex(b []byte) string {
	return BytesToHex(b)
}

// HexToBytes parses a hexadecimal string to bytes
// Handles both uppercase and lowercase hex, with or without "0x" prefix
func HexToBytes(s string) ([]byte, error) {
	// Remove "0x" prefix if present
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// FromHex is an alias for HexToBytes
func FromHex(s string) ([]byte, error) {
	return HexToBytes(s)
}

// BytesToBase64 encodes bytes as base64 string (standard encoding)
func BytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Base64ToBytes decodes a base64 string to bytes
func Base64ToBytes(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// BytesToBinary converts bytes to binary string (e.g., "01010101")
func BytesToBinary(b []byte) string {
	var result strings.Builder
	for _, byte := range b {
		result.WriteString(fmt.Sprintf("%08b", byte))
	}
	return result.String()
}

// BytesToString converts bytes to string (simple cast)
func BytesToString(b []byte) string {
	return string(b)
}

// StringToBytes converts string to bytes (simple cast)
func StringToBytes(s string) []byte {
	return []byte(s)
}

// ============================================================================
// Human-Readable Byte Sizes
// ============================================================================

// ByteSize represents a size in bytes
type ByteSize int64

// Size constants (binary: 1024-based)
const (
	B  ByteSize = 1
	KB ByteSize = 1024 * B  // KiB
	MB ByteSize = 1024 * KB // MiB
	GB ByteSize = 1024 * MB // GiB
	TB ByteSize = 1024 * GB // TiB
	PB ByteSize = 1024 * TB // PiB
)

// Decimal constants (1000-based)
const (
	KBDecimal int64 = 1000
	MBDecimal int64 = 1000 * KBDecimal
	GBDecimal int64 = 1000 * MBDecimal
	TBDecimal int64 = 1000 * GBDecimal
	PBDecimal int64 = 1000 * TBDecimal
)

// String returns human-readable size (binary units)
func (b ByteSize) String() string {
	switch {
	case b >= PB:
		return fmt.Sprintf("%.1f PiB", float64(b)/float64(PB))
	case b >= TB:
		return fmt.Sprintf("%.1f TiB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatBytes formats byte count as human-readable string (binary units: KiB, MiB, GiB)
func FormatBytes(bytes int64) string {
	return ByteSize(bytes).String()
}

// FormatBytesBinary formats using binary units (1024-based: KiB, MiB, GiB, TiB)
func FormatBytesBinary(bytes int64, precision int) string {
	if bytes < 0 {
		return fmt.Sprintf("-%s", FormatBytesBinary(-bytes, precision))
	}

	fbytes := float64(bytes)

	switch {
	case fbytes >= float64(PB):
		return fmt.Sprintf("%.*f PiB", precision, fbytes/float64(PB))
	case fbytes >= float64(TB):
		return fmt.Sprintf("%.*f TiB", precision, fbytes/float64(TB))
	case fbytes >= float64(GB):
		return fmt.Sprintf("%.*f GiB", precision, fbytes/float64(GB))
	case fbytes >= float64(MB):
		return fmt.Sprintf("%.*f MiB", precision, fbytes/float64(MB))
	case fbytes >= float64(KB):
		return fmt.Sprintf("%.*f KiB", precision, fbytes/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatBytesDecimal formats using decimal units (1000-based: KB, MB, GB, TB)
func FormatBytesDecimal(bytes int64, precision int) string {
	if bytes < 0 {
		return fmt.Sprintf("-%s", FormatBytesDecimal(-bytes, precision))
	}

	fbytes := float64(bytes)

	switch {
	case fbytes >= float64(PBDecimal):
		return fmt.Sprintf("%.*f PB", precision, fbytes/float64(PBDecimal))
	case fbytes >= float64(TBDecimal):
		return fmt.Sprintf("%.*f TB", precision, fbytes/float64(TBDecimal))
	case fbytes >= float64(GBDecimal):
		return fmt.Sprintf("%.*f GB", precision, fbytes/float64(GBDecimal))
	case fbytes >= float64(MBDecimal):
		return fmt.Sprintf("%.*f MB", precision, fbytes/float64(MBDecimal))
	case fbytes >= float64(KBDecimal):
		return fmt.Sprintf("%.*f KB", precision, fbytes/float64(KBDecimal))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

var byteSizeRegex = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*([KMGTP]i?B?|B)?$`)

// ParseBytes parses human-readable byte string to int64
// Supports: "1.5MB", "1024 KiB", "500B", both binary (KiB) and decimal (KB) units
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	matches := byteSizeRegex.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid byte size format: %s", s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", matches[1])
	}

	unit := strings.ToUpper(strings.TrimSpace(matches[2]))

	// Determine multiplier
	var multiplier float64 = 1
	switch unit {
	case "", "B":
		multiplier = 1
	case "KB":
		multiplier = float64(KBDecimal)
	case "MB":
		multiplier = float64(MBDecimal)
	case "GB":
		multiplier = float64(GBDecimal)
	case "TB":
		multiplier = float64(TBDecimal)
	case "PB":
		multiplier = float64(PBDecimal)
	case "KIB", "K":
		multiplier = float64(KB)
	case "MIB", "M":
		multiplier = float64(MB)
	case "GIB", "G":
		multiplier = float64(GB)
	case "TIB", "T":
		multiplier = float64(TB)
	case "PIB", "P":
		multiplier = float64(PB)
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}

	return int64(value * multiplier), nil
}

// ============================================================================
// Safe Byte Slice Operations
// ============================================================================

// SafeSlice returns a slice of b from start to end (exclusive)
// Returns empty slice if indices are out of bounds or invalid
func SafeSlice(b []byte, start, end int) []byte {
	length := len(b)

	// Handle negative or invalid start
	if start < 0 {
		start = 0
	}
	if start >= length {
		return []byte{}
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
		return []byte{}
	}

	return b[start:end]
}

// SafeIndex returns the byte at index i and a boolean indicating success
// Returns (0, false) if index is out of bounds
func SafeIndex(b []byte, i int) (byte, bool) {
	if i < 0 || i >= len(b) {
		return 0, false
	}
	return b[i], true
}

// SafeCopy copies from src to dst and returns the number of bytes copied
// Will not overflow dst, copies min(len(dst), len(src)) bytes
func SafeCopy(dst, src []byte) int {
	return copy(dst, src)
}

// ============================================================================
// Byte Comparison Utilities
// ============================================================================

// Equal performs constant-time comparison of two byte slices
// Use this for comparing cryptographic hashes, passwords, or tokens
// to prevent timing attacks
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// HasPrefix checks if b starts with prefix
func HasPrefix(b, prefix []byte) bool {
	if len(prefix) > len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(b[:len(prefix)], prefix) == 1
}

// HasSuffix checks if b ends with suffix
func HasSuffix(b, suffix []byte) bool {
	if len(suffix) > len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(b[len(b)-len(suffix):], suffix) == 1
}

// Contains checks if b contains subslice
func Contains(b, subslice []byte) bool {
	if len(subslice) == 0 {
		return true
	}
	if len(subslice) > len(b) {
		return false
	}

	for i := 0; i <= len(b)-len(subslice); i++ {
		if subtle.ConstantTimeCompare(b[i:i+len(subslice)], subslice) == 1 {
			return true
		}
	}
	return false
}

// ============================================================================
// Byte Buffer Pool
// ============================================================================

var (
	// Buffer pools for common sizes
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 512)
			return &b
		},
	}

	mediumBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 4096)
			return &b
		},
	}

	largeBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 65536)
			return &b
		},
	}
)

// GetBuffer retrieves a buffer from the pool (4KB default)
func GetBuffer() []byte {
	return *mediumBufferPool.Get().(*[]byte)
}

// GetSmallBuffer retrieves a 512-byte buffer from the pool
func GetSmallBuffer() []byte {
	return *smallBufferPool.Get().(*[]byte)
}

// GetLargeBuffer retrieves a 64KB buffer from the pool
func GetLargeBuffer() []byte {
	return *largeBufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(b []byte) {
	if cap(b) == 512 {
		smallBufferPool.Put(&b)
	} else if cap(b) == 4096 {
		mediumBufferPool.Put(&b)
	} else if cap(b) == 65536 {
		largeBufferPool.Put(&b)
	}
	// If size doesn't match any pool, let GC handle it
}

// ============================================================================
// Bit Manipulation Helpers
// ============================================================================

// SetBit sets the bit at position 'bit' to 1 in byte slice b
// bit 0 is the least significant bit of b[0]
func SetBit(b []byte, bit int) {
	if bit < 0 || bit >= len(b)*8 {
		return // Silently ignore out of bounds
	}
	byteIndex := bit / 8
	bitIndex := uint(bit % 8)
	b[byteIndex] |= 1 << bitIndex
}

// ClearBit sets the bit at position 'bit' to 0 in byte slice b
func ClearBit(b []byte, bit int) {
	if bit < 0 || bit >= len(b)*8 {
		return // Silently ignore out of bounds
	}
	byteIndex := bit / 8
	bitIndex := uint(bit % 8)
	b[byteIndex] &^= 1 << bitIndex
}

// GetBit returns the value of the bit at position 'bit' in byte slice b
func GetBit(b []byte, bit int) bool {
	if bit < 0 || bit >= len(b)*8 {
		return false
	}
	byteIndex := bit / 8
	bitIndex := uint(bit % 8)
	return (b[byteIndex] & (1 << bitIndex)) != 0
}

// CountSetBits counts the number of bits set to 1 in byte slice b
// Uses population count (popcount) for efficiency
func CountSetBits(b []byte) int {
	count := 0
	for _, byte := range b {
		count += bits.OnesCount8(byte)
	}
	return count
}

// ============================================================================
// Binary Conversions (Little Endian)
// ============================================================================

// Uint16ToBytes converts uint16 to 2 bytes (little endian)
func Uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)
	return b
}

// BytesToUint16 converts 2 bytes to uint16 (little endian)
// Returns 0 if slice is too short
func BytesToUint16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

// Uint32ToBytes converts uint32 to 4 bytes (little endian)
func Uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

// BytesToUint32 converts 4 bytes to uint32 (little endian)
// Returns 0 if slice is too short
func BytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// Uint64ToBytes converts uint64 to 8 bytes (little endian)
func Uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// BytesToUint64 converts 8 bytes to uint64 (little endian)
// Returns 0 if slice is too short
func BytesToUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// ============================================================================
// Big Endian Conversions (Network Byte Order)
// ============================================================================

// Uint16ToBytesBE converts uint16 to 2 bytes (big endian / network byte order)
func Uint16ToBytesBE(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

// BytesToUint16BE converts 2 bytes to uint16 (big endian / network byte order)
func BytesToUint16BE(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// Uint32ToBytesBE converts uint32 to 4 bytes (big endian / network byte order)
func Uint32ToBytesBE(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// BytesToUint32BE converts 4 bytes to uint32 (big endian / network byte order)
func BytesToUint32BE(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// Uint64ToBytesBE converts uint64 to 8 bytes (big endian / network byte order)
func Uint64ToBytesBE(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

// BytesToUint64BE converts 8 bytes to uint64 (big endian / network byte order)
func BytesToUint64BE(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// ============================================================================
// Additional Utilities (from previous implementation)
// ============================================================================

// PadLeft pads bytes on the left to reach target length
func PadLeft(b []byte, length int, pad byte) []byte {
	if len(b) >= length {
		return b
	}

	result := make([]byte, length)
	copy(result[length-len(b):], b)
	for i := 0; i < length-len(b); i++ {
		result[i] = pad
	}
	return result
}

// PadRight pads bytes on the right to reach target length
func PadRight(b []byte, length int, pad byte) []byte {
	if len(b) >= length {
		return b
	}

	result := make([]byte, length)
	copy(result, b)
	for i := len(b); i < length; i++ {
		result[i] = pad
	}
	return result
}

// XOR XORs two byte slices
func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Reverse reverses a byte slice
func Reverse(b []byte) []byte {
	result := make([]byte, len(b))
	for i, j := 0, len(b)-1; i < len(b); i, j = i+1, j-1 {
		result[i] = b[j]
	}
	return result
}

// Clone creates a copy of a byte slice
func Clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	result := make([]byte, len(b))
	copy(result, b)
	return result
}
