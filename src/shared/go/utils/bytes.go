// Package utils provides byte utilities.
package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// ByteSize represents a size in bytes
type ByteSize int64

// Size constants
const (
	B  ByteSize = 1
	KB ByteSize = 1024 * B
	MB ByteSize = 1024 * KB
	GB ByteSize = 1024 * MB
	TB ByteSize = 1024 * GB
	PB ByteSize = 1024 * TB
)

// String returns human-readable size
func (b ByteSize) String() string {
	switch {
	case b >= PB:
		return fmt.Sprintf("%.2f PB", float64(b)/float64(PB))
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatBytes formats bytes as human-readable string
func FormatBytes(n int64) string {
	return ByteSize(n).String()
}

// ParseBytes parses a human-readable size string
func ParseBytes(s string) (int64, error) {
	var value float64
	var unit string

	_, err := fmt.Sscanf(s, "%f %s", &value, &unit)
	if err != nil {
		// Try without space
		_, err = fmt.Sscanf(s, "%f%s", &value, &unit)
		if err != nil {
			return 0, fmt.Errorf("invalid byte size: %s", s)
		}
	}

	var multiplier int64
	switch unit {
	case "B", "b", "":
		multiplier = 1
	case "KB", "kb", "K", "k":
		multiplier = int64(KB)
	case "MB", "mb", "M", "m":
		multiplier = int64(MB)
	case "GB", "gb", "G", "g":
		multiplier = int64(GB)
	case "TB", "tb", "T", "t":
		multiplier = int64(TB)
	case "PB", "pb", "P", "p":
		multiplier = int64(PB)
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}

	return int64(value * float64(multiplier)), nil
}

// ToHex converts bytes to hex string
func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// FromHex converts hex string to bytes
func FromHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Uint16ToBytes converts uint16 to bytes (big-endian)
func Uint16ToBytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// BytesToUint16 converts bytes to uint16 (big-endian)
func BytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// Uint32ToBytes converts uint32 to bytes (big-endian)
func Uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// BytesToUint32 converts bytes to uint32 (big-endian)
func BytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// Uint64ToBytes converts uint64 to bytes (big-endian)
func Uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// BytesToUint64 converts bytes to uint64 (big-endian)
func BytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// SafeSlice returns a slice of bytes, handling out of bounds
func SafeSlice(b []byte, start, end int) []byte {
	if start < 0 {
		start = 0
	}
	if end > len(b) {
		end = len(b)
	}
	if start >= end || start >= len(b) {
		return nil
	}
	return b[start:end]
}

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

// Contains checks if b contains sub
func Contains(b, sub []byte) bool {
	return indexOf(b, sub) >= 0
}

// indexOf returns the index of sub in b, or -1 if not found
func indexOf(b, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	if len(sub) > len(b) {
		return -1
	}

	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// Equal compares two byte slices
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
