// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// ============================================================================
// UTF-8 ↔ UTF-16 String Conversion
// ============================================================================
// Windows APIs use UTF-16 (wide characters), while Go uses UTF-8.
// These functions provide safe conversion between the two encodings.

// UTF8ToUTF16 converts a Go string to a null-terminated UTF-16 slice.
// Returns a pointer to the first element, suitable for passing to Windows APIs.
// The returned slice is heap-allocated and must be kept alive until the API call completes.
func UTF8ToUTF16(s string) ([]uint16, error) {
	// Convert to UTF-16 with null terminator
	utf16Str, err := syscall.UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return utf16Str, nil
}

// UTF8ToUTF16Ptr converts a Go string to a pointer to a null-terminated UTF-16 string.
// This is the most common format for Windows API calls.
// IMPORTANT: The returned pointer is only valid while the underlying slice is alive.
// Use runtime.KeepAlive() to prevent garbage collection during the API call.
func UTF8ToUTF16Ptr(s string) (*uint16, error) {
	utf16Str, err := UTF8ToUTF16(s)
	if err != nil {
		return nil, err
	}
	if len(utf16Str) == 0 {
		return nil, nil
	}
	return &utf16Str[0], nil
}

// MustUTF8ToUTF16Ptr converts a Go string to a UTF-16 pointer, panicking on error.
// Use only with known-good constant strings.
func MustUTF8ToUTF16Ptr(s string) *uint16 {
	ptr, err := UTF8ToUTF16Ptr(s)
	if err != nil {
		panic(err)
	}
	return ptr
}

// UTF16ToString converts a null-terminated UTF-16 string to a Go string.
// The pointer must point to a valid null-terminated UTF-16 string.
// Returns empty string if pointer is nil.
func UTF16ToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return syscall.UTF16ToString(utf16PtrToSlice(p))
}

// UTF16ToStringN converts a UTF-16 string with known length to a Go string.
// Does not require null termination.
func UTF16ToStringN(p *uint16, length int) string {
	if p == nil || length <= 0 {
		return ""
	}

	// Create slice from pointer
	slice := unsafe.Slice(p, length)
	return string(utf16.Decode(slice))
}

// utf16PtrToSlice converts a UTF-16 pointer to a slice by finding the null terminator.
func utf16PtrToSlice(p *uint16) []uint16 {
	if p == nil {
		return nil
	}

	// Count characters until null terminator
	length := UTF16PtrLen(p)
	if length == 0 {
		return nil
	}

	// Create slice from pointer
	return unsafe.Slice(p, length)
}

// UTF16PtrLen returns the length of a null-terminated UTF-16 string (excluding null).
func UTF16PtrLen(p *uint16) int {
	if p == nil {
		return 0
	}

	length := 0
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) {
		length++
		// Safety limit to prevent infinite loop on invalid data
		if length > 32768 {
			break
		}
	}
	return length
}

// UTF16ByteLen returns the byte length of a null-terminated UTF-16 string (including null).
func UTF16ByteLen(p *uint16) int {
	return (UTF16PtrLen(p) + 1) * 2
}

// ============================================================================
// LPWSTR Helpers (Windows wide string pointers)
// ============================================================================

// LPWSTR is an alias for *uint16, representing a Windows wide string pointer.
type LPWSTR = *uint16

// NewLPWSTR creates a new LPWSTR from a Go string.
// Returns nil for empty strings.
func NewLPWSTR(s string) (LPWSTR, []uint16, error) {
	if s == "" {
		return nil, nil, nil
	}

	utf16Str, err := UTF8ToUTF16(s)
	if err != nil {
		return nil, nil, err
	}

	return &utf16Str[0], utf16Str, nil
}

// LPWSTRToString converts an LPWSTR to a Go string.
func LPWSTRToString(p LPWSTR) string {
	return UTF16ToString(p)
}

// ============================================================================
// String Arrays
// ============================================================================

// StringsToUTF16Ptrs converts a slice of Go strings to a slice of UTF-16 pointers.
// Also returns the backing slices to prevent garbage collection.
func StringsToUTF16Ptrs(strings []string) ([]*uint16, [][]uint16, error) {
	if len(strings) == 0 {
		return nil, nil, nil
	}

	ptrs := make([]*uint16, len(strings))
	slices := make([][]uint16, len(strings))

	for i, s := range strings {
		utf16Str, err := UTF8ToUTF16(s)
		if err != nil {
			return nil, nil, err
		}
		slices[i] = utf16Str
		if len(utf16Str) > 0 {
			ptrs[i] = &utf16Str[0]
		}
	}

	return ptrs, slices, nil
}

// ============================================================================
// Path Helpers
// ============================================================================

// PathToNTPath converts a Windows path to NT path format.
// WFP application IDs use NT path format: \Device\HarddiskVolume1\...
// This function converts from DOS path: C:\Program Files\...
func PathToNTPath(dosPath string) (string, error) {
	if dosPath == "" {
		return "", nil
	}

	// Get volume path name
	utf16Path, err := syscall.UTF16PtrFromString(dosPath)
	if err != nil {
		return "", err
	}

	// Allocate buffer for device name
	deviceName := make([]uint16, 260) // MAX_PATH

	// Get drive letter (e.g., "C:")
	if len(dosPath) < 2 || dosPath[1] != ':' {
		// Not a drive letter path, return as-is
		return dosPath, nil
	}

	drive := dosPath[0:2]
	drivePtr, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return "", err
	}

	// QueryDosDevice to get NT device name
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDevice := kernel32.NewProc("QueryDosDeviceW")

	ret, _, _ := procQueryDosDevice.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&deviceName[0])),
		uintptr(len(deviceName)),
	)

	if ret == 0 {
		// Failed, return original path
		return dosPath, nil
	}

	// Combine device name with rest of path
	ntDevice := syscall.UTF16ToString(deviceName)

	// Keep utf16Path alive until we're done
	_ = utf16Path

	return ntDevice + dosPath[2:], nil
}

// NTPathToPath converts an NT path to a Windows path.
// Inverse of PathToNTPath.
func NTPathToPath(ntPath string) string {
	// This is complex - requires enumerating volumes
	// For now, return as-is (WFP usually returns NT paths)
	return ntPath
}

// ============================================================================
// Display Data Helpers
// ============================================================================

// DisplayData holds name and description for WFP objects.
type DisplayData struct {
	Name        string
	Description string
}

// ToUTF16 converts DisplayData to UTF-16 pointers required by WFP.
// Returns the pointers and backing slices (keep slices alive during API call).
func (d DisplayData) ToUTF16() (namePtr, descPtr *uint16, nameSlice, descSlice []uint16, err error) {
	if d.Name != "" {
		nameSlice, err = UTF8ToUTF16(d.Name)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		namePtr = &nameSlice[0]
	}

	if d.Description != "" {
		descSlice, err = UTF8ToUTF16(d.Description)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		descPtr = &descSlice[0]
	}

	return namePtr, descPtr, nameSlice, descSlice, nil
}
