// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ============================================================================
// GUID Operations
// ============================================================================
// GUIDs (Globally Unique Identifiers) are 128-bit values used extensively in WFP
// to identify filters, layers, providers, and other objects.
//
// Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// Structure:
//   - Data1: 4 bytes (8 hex chars)
//   - Data2: 2 bytes (4 hex chars)
//   - Data3: 2 bytes (4 hex chars)
//   - Data4: 8 bytes (16 hex chars, split 4-12)

var (
	// DLL and procedure for GUID generation
	ole32            = syscall.NewLazyDLL("ole32.dll")
	procCoCreateGuid = ole32.NewProc("CoCreateGuid")

	// GUID generation mutex for thread safety
	guidMutex sync.Mutex
)

// guidToBytes converts a GUID struct to a [16]byte array.
func guidToBytes(g GUID) [16]byte {
	var b [16]byte

	// Data1 - 4 bytes, little-endian
	b[0] = byte(g.Data1)
	b[1] = byte(g.Data1 >> 8)
	b[2] = byte(g.Data1 >> 16)
	b[3] = byte(g.Data1 >> 24)

	// Data2 - 2 bytes, little-endian
	b[4] = byte(g.Data2)
	b[5] = byte(g.Data2 >> 8)

	// Data3 - 2 bytes, little-endian
	b[6] = byte(g.Data3)
	b[7] = byte(g.Data3 >> 8)

	// Data4 - 8 bytes (as-is, big-endian)
	copy(b[8:], g.Data4[:])

	return b
}

// guidFromBytes converts a [16]byte array to a GUID struct.
func guidFromBytes(b [16]byte) GUID {
	return GUID{
		Data1: uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24,
		Data2: uint16(b[4]) | uint16(b[5])<<8,
		Data3: uint16(b[6]) | uint16(b[7])<<8,
		Data4: [8]byte{b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]},
	}
}

// String returns the standard GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
func (g GUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// ToBytes converts the GUID to a [16]byte array.
func (g GUID) ToBytes() [16]byte {
	return guidToBytes(g)
}

// Equals checks if two GUIDs are equal.
func (g GUID) Equals(other GUID) bool {
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4 == other.Data4
}

// NewGUID generates a new random GUID using Windows CoCreateGuid API.
// Returns an error if the system call fails.
func NewGUID() (GUID, error) {
	guidMutex.Lock()
	defer guidMutex.Unlock()

	var guid GUID

	// Call CoCreateGuid(GUID* pguid)
	ret, _, err := procCoCreateGuid.Call(uintptr(unsafe.Pointer(&guid)))
	if ret != 0 {
		return GUID_NULL, fmt.Errorf("CoCreateGuid failed: %w (HRESULT: 0x%08X)", err, ret)
	}

	return guid, nil
}

// MustNewGUID generates a new GUID and panics on failure.
// Use only in initialization code where failure is unrecoverable.
func MustNewGUID() GUID {
	guid, err := NewGUID()
	if err != nil {
		panic(fmt.Sprintf("failed to generate GUID: %v", err))
	}
	return guid
}

// GUIDFromString parses a GUID string in the format:
// - {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// - XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
// - XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (no dashes)
func GUIDFromString(s string) (GUID, error) {
	// Remove braces and dashes
	s = strings.Trim(s, "{}")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ToLower(s)

	if len(s) != 32 {
		return GUID_NULL, fmt.Errorf("invalid GUID length: expected 32 hex chars, got %d", len(s))
	}

	// Parse hex bytes
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return GUID_NULL, fmt.Errorf("invalid GUID hex: %w", err)
	}

	if len(bytes) != 16 {
		return GUID_NULL, fmt.Errorf("invalid GUID: expected 16 bytes, got %d", len(bytes))
	}

	// Convert to GUID struct (note: Windows uses mixed-endian format)
	return GUID{
		Data1: uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]),
		Data2: uint16(bytes[4])<<8 | uint16(bytes[5]),
		Data3: uint16(bytes[6])<<8 | uint16(bytes[7]),
		Data4: [8]byte{bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]},
	}, nil
}

// MustGUIDFromString parses a GUID string and panics on failure.
// Use only with known-good constant strings.
func MustGUIDFromString(s string) GUID {
	guid, err := GUIDFromString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid GUID string %q: %v", s, err))
	}
	return guid
}

// GUIDFromBytes creates a GUID from a [16]byte array.
func GUIDFromBytes(b [16]byte) GUID {
	return guidFromBytes(b)
}

// GUIDFromSlice creates a GUID from a byte slice.
// Returns error if slice length is not 16.
func GUIDFromSlice(b []byte) (GUID, error) {
	if len(b) != 16 {
		return GUID_NULL, fmt.Errorf("invalid GUID slice length: expected 16, got %d", len(b))
	}

	var arr [16]byte
	copy(arr[:], b)
	return guidFromBytes(arr), nil
}

// GUIDZero returns the null/empty GUID (all zeros).
func GUIDZero() GUID {
	return GUID_NULL
}

// ============================================================================
// GUID Pointer Helpers
// ============================================================================

// GUIDPtr returns a pointer to a copy of the GUID.
// Used for passing GUIDs to Windows APIs that expect GUID*.
func (g GUID) GUIDPtr() *GUID {
	guid := g // Make a copy
	return &guid
}

// GUIDPtrOrNil returns a pointer to the GUID, or nil if it's the null GUID.
// Some WFP APIs treat NULL GUID pointer differently than NULL GUID value.
func (g GUID) GUIDPtrOrNil() *GUID {
	if g.IsNull() {
		return nil
	}
	guid := g
	return &guid
}

// ============================================================================
// GUID Comparison Helpers
// ============================================================================

// IsWellKnown checks if this GUID is a well-known WFP GUID (layer, condition, etc.)
func (g GUID) IsWellKnown() bool {
	wellKnown := []GUID{
		FWPM_LAYER_INBOUND_IPPACKET_V4,
		FWPM_LAYER_OUTBOUND_IPPACKET_V4,
		FWPM_LAYER_INBOUND_TRANSPORT_V4,
		FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		// Add more as needed
	}

	for _, wk := range wellKnown {
		if g.Equals(wk) {
			return true
		}
	}
	return false
}

// ============================================================================
// GUID Set (for tracking installed filters)
// ============================================================================

// GUIDSet is a thread-safe set of GUIDs.
type GUIDSet struct {
	mu    sync.RWMutex
	guids map[GUID]struct{}
}

// NewGUIDSet creates a new empty GUID set.
func NewGUIDSet() *GUIDSet {
	return &GUIDSet{
		guids: make(map[GUID]struct{}),
	}
}

// Add adds a GUID to the set.
func (s *GUIDSet) Add(g GUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.guids[g] = struct{}{}
}

// Remove removes a GUID from the set.
func (s *GUIDSet) Remove(g GUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.guids[g]; ok {
		delete(s.guids, g)
		return true
	}
	return false
}

// Contains checks if a GUID is in the set.
func (s *GUIDSet) Contains(g GUID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.guids[g]
	return ok
}

// Size returns the number of GUIDs in the set.
func (s *GUIDSet) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.guids)
}

// Clear removes all GUIDs from the set.
func (s *GUIDSet) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.guids = make(map[GUID]struct{})
}

// All returns a slice of all GUIDs in the set.
func (s *GUIDSet) All() []GUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]GUID, 0, len(s.guids))
	for g := range s.guids {
		result = append(result, g)
	}
	return result
}

// ============================================================================
// GUID to Rule ID Mapping
// ============================================================================

// GUIDMap is a thread-safe map from string keys (rule IDs) to GUIDs.
type GUIDMap struct {
	mu   sync.RWMutex
	data map[string]GUID
}

// NewGUIDMap creates a new empty GUID map.
func NewGUIDMap() *GUIDMap {
	return &GUIDMap{
		data: make(map[string]GUID),
	}
}

// Set adds or updates a mapping.
func (m *GUIDMap) Set(key string, guid GUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = guid
}

// Get retrieves a GUID by key.
func (m *GUIDMap) Get(key string) (GUID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	guid, ok := m.data[key]
	return guid, ok
}

// Delete removes a mapping.
func (m *GUIDMap) Delete(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[key]; ok {
		delete(m.data, key)
		return true
	}
	return false
}

// Size returns the number of mappings.
func (m *GUIDMap) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

// Clear removes all mappings.
func (m *GUIDMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]GUID)
}

// Keys returns all keys.
func (m *GUIDMap) Keys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, 0, len(m.data))
	for k := range m.data {
		result = append(result, k)
	}
	return result
}

// Values returns all GUIDs.
func (m *GUIDMap) Values() []GUID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]GUID, 0, len(m.data))
	for _, v := range m.data {
		result = append(result, v)
	}
	return result
}
