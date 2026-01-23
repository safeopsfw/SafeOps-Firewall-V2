// Package boottime provides Windows Registry storage for persistent filter metadata.
// The registry store maintains a mapping between SafeOps rule IDs and WFP filter GUIDs,
// enabling filter management across system reboots.
package boottime

import (
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// Registry Constants
// ============================================================================

const (
	// RegistryBasePath is the base registry path for SafeOps firewall.
	RegistryBasePath = `SOFTWARE\SafeOps\Firewall`

	// RegistryFiltersSubKey is the subkey for persistent filter storage.
	RegistryFiltersSubKey = `PersistentFilters`

	// RegistryFullPath is the full path to the persistent filters key.
	RegistryFullPath = RegistryBasePath + `\` + RegistryFiltersSubKey

	// MaxValueNameLen is the maximum length of a registry value name.
	MaxValueNameLen = 256

	// MaxValueDataLen is the maximum length of registry value data.
	MaxValueDataLen = 65536
)

// Registry key access rights
const (
	KEY_READ       = 0x20019
	KEY_WRITE      = 0x20006
	KEY_ALL_ACCESS = 0xF003F

	REG_SZ    = 1
	REG_DWORD = 4
)

// ============================================================================
// Windows API Imports
// ============================================================================

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyExW  = advapi32.NewProc("RegCreateKeyExW")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
	procRegSetValueExW   = advapi32.NewProc("RegSetValueExW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	procRegDeleteValueW  = advapi32.NewProc("RegDeleteValueW")
	procRegEnumValueW    = advapi32.NewProc("RegEnumValueW")
	procRegDeleteKeyExW  = advapi32.NewProc("RegDeleteKeyExW")
	procRegQueryInfoKeyW = advapi32.NewProc("RegQueryInfoKeyW")
)

// HKEY constants
const (
	HKEY_LOCAL_MACHINE = syscall.HKEY_LOCAL_MACHINE
	HKEY_CURRENT_USER  = syscall.HKEY_CURRENT_USER
)

// ============================================================================
// Persistent Filter Record
// ============================================================================

// PersistentFilterRecord is the JSON-serializable record stored in registry.
type PersistentFilterRecord struct {
	// FilterGUID is the WFP filter's unique identifier.
	FilterGUID bindings.GUID `json:"filter_guid"`

	// RuleID is the SafeOps firewall rule ID.
	RuleID string `json:"rule_id"`

	// RuleName is the human-readable rule name.
	RuleName string `json:"rule_name"`

	// Layer is the WFP layer where the filter is installed.
	Layer string `json:"layer"`

	// Action is the filter action (BLOCK/PERMIT).
	Action string `json:"action"`

	// Conditions is a summary of the filter's match conditions.
	Conditions string `json:"conditions"`

	// Created is when the filter was first installed.
	Created time.Time `json:"created"`

	// Updated is when the record was last updated.
	Updated time.Time `json:"updated"`

	// Version is the schema version for future compatibility.
	Version int `json:"version"`
}

// GUIDString returns the filter GUID as a string.
func (r *PersistentFilterRecord) GUIDString() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		r.FilterGUID.Data1, r.FilterGUID.Data2, r.FilterGUID.Data3,
		r.FilterGUID.Data4[0], r.FilterGUID.Data4[1],
		r.FilterGUID.Data4[2], r.FilterGUID.Data4[3],
		r.FilterGUID.Data4[4], r.FilterGUID.Data4[5],
		r.FilterGUID.Data4[6], r.FilterGUID.Data4[7])
}

// ============================================================================
// Registry Store
// ============================================================================

// RegistryStore manages persistent filter metadata in Windows Registry.
type RegistryStore struct {
	mu sync.Mutex

	// Registry key handle
	key    syscall.Handle
	isOpen bool

	// Configuration
	basePath string
	useHKCU  bool // Use HKEY_CURRENT_USER instead of HKEY_LOCAL_MACHINE
}

// RegistryStoreConfig configures the registry store.
type RegistryStoreConfig struct {
	// BasePath overrides the default registry path.
	BasePath string

	// UseHKCU uses HKEY_CURRENT_USER instead of HKEY_LOCAL_MACHINE.
	// Useful for non-admin testing.
	UseHKCU bool
}

// NewRegistryStore creates a new registry store with default configuration.
func NewRegistryStore() (*RegistryStore, error) {
	return NewRegistryStoreWithConfig(nil)
}

// NewRegistryStoreWithConfig creates a registry store with custom configuration.
func NewRegistryStoreWithConfig(cfg *RegistryStoreConfig) (*RegistryStore, error) {
	basePath := RegistryFullPath
	useHKCU := false

	if cfg != nil {
		if cfg.BasePath != "" {
			basePath = cfg.BasePath
		}
		useHKCU = cfg.UseHKCU
	}

	return &RegistryStore{
		basePath: basePath,
		useHKCU:  useHKCU,
	}, nil
}

// ============================================================================
// Registry Operations
// ============================================================================

// Open opens or creates the registry key.
func (rs *RegistryStore) Open() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.isOpen {
		return nil
	}

	// Determine root key
	var rootKey syscall.Handle
	if rs.useHKCU {
		rootKey = syscall.Handle(HKEY_CURRENT_USER)
	} else {
		rootKey = syscall.Handle(HKEY_LOCAL_MACHINE)
	}

	// Convert path to UTF-16
	pathPtr, err := syscall.UTF16PtrFromString(rs.basePath)
	if err != nil {
		return fmt.Errorf("convert path: %w", err)
	}

	// Create or open key
	var key syscall.Handle
	var disposition uint32

	ret, _, err := procRegCreateKeyExW.Call(
		uintptr(rootKey),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0,
		0,
		uintptr(KEY_ALL_ACCESS),
		0,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(&disposition)),
	)

	if ret != 0 {
		return fmt.Errorf("create registry key: %w (code: %d)", err, ret)
	}

	rs.key = key
	rs.isOpen = true
	return nil
}

// Close closes the registry key.
func (rs *RegistryStore) Close() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return nil
	}

	ret, _, err := procRegCloseKey.Call(uintptr(rs.key))
	if ret != 0 {
		return fmt.Errorf("close registry key: %w", err)
	}

	rs.isOpen = false
	rs.key = 0
	return nil
}

// IsOpen returns true if the registry key is open.
func (rs *RegistryStore) IsOpen() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.isOpen
}

// ============================================================================
// Record Management
// ============================================================================

// SaveFilter saves a filter record to the registry.
func (rs *RegistryStore) SaveFilter(record *PersistentFilterRecord) error {
	if record == nil {
		return fmt.Errorf("record is required")
	}
	if record.RuleID == "" {
		return fmt.Errorf("rule ID is required")
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return fmt.Errorf("registry store not open")
	}

	// Serialize to JSON
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	// Convert value name and data to UTF-16
	namePtr, err := syscall.UTF16PtrFromString(record.RuleID)
	if err != nil {
		return fmt.Errorf("convert value name: %w", err)
	}

	dataStr := string(data)
	dataPtr, err := syscall.UTF16PtrFromString(dataStr)
	if err != nil {
		return fmt.Errorf("convert value data: %w", err)
	}

	// Write to registry as REG_SZ
	dataLen := (len(dataStr) + 1) * 2 // UTF-16 with null terminator

	ret, _, regErr := procRegSetValueExW.Call(
		uintptr(rs.key),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(REG_SZ),
		uintptr(unsafe.Pointer(dataPtr)),
		uintptr(dataLen),
	)

	if ret != 0 {
		return fmt.Errorf("set registry value: %w (code: %d)", regErr, ret)
	}

	return nil
}

// LoadFilter loads a filter record from the registry.
func (rs *RegistryStore) LoadFilter(ruleID string) (*PersistentFilterRecord, error) {
	if ruleID == "" {
		return nil, fmt.Errorf("rule ID is required")
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return nil, fmt.Errorf("registry store not open")
	}

	// Convert value name to UTF-16
	namePtr, err := syscall.UTF16PtrFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("convert value name: %w", err)
	}

	// Query value size first
	var dataType uint32
	var dataSize uint32 = 0

	ret, _, _ := procRegQueryValueExW.Call(
		uintptr(rs.key),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("filter not found: %s", ruleID)
	}

	// Allocate buffer and read value
	data := make([]uint16, dataSize/2)

	ret, _, regErr := procRegQueryValueExW.Call(
		uintptr(rs.key),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(&dataSize)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("read registry value: %w", regErr)
	}

	// Convert UTF-16 to string
	jsonStr := syscall.UTF16ToString(data)

	// Parse JSON
	var record PersistentFilterRecord
	if err := json.Unmarshal([]byte(jsonStr), &record); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}

	return &record, nil
}

// DeleteFilter deletes a filter record from the registry.
func (rs *RegistryStore) DeleteFilter(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID is required")
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return fmt.Errorf("registry store not open")
	}

	// Convert value name to UTF-16
	namePtr, err := syscall.UTF16PtrFromString(ruleID)
	if err != nil {
		return fmt.Errorf("convert value name: %w", err)
	}

	ret, _, regErr := procRegDeleteValueW.Call(
		uintptr(rs.key),
		uintptr(unsafe.Pointer(namePtr)),
	)

	// Ignore "not found" errors
	if ret != 0 && ret != 2 { // 2 = ERROR_FILE_NOT_FOUND
		return fmt.Errorf("delete registry value: %w (code: %d)", regErr, ret)
	}

	return nil
}

// LoadAll loads all filter records from the registry.
func (rs *RegistryStore) LoadAll() ([]*PersistentFilterRecord, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return nil, fmt.Errorf("registry store not open")
	}

	// Get number of values
	var valueCount uint32
	var maxValueNameLen uint32
	var maxValueLen uint32

	ret, _, _ := procRegQueryInfoKeyW.Call(
		uintptr(rs.key),
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&valueCount)),
		uintptr(unsafe.Pointer(&maxValueNameLen)),
		uintptr(unsafe.Pointer(&maxValueLen)),
		0, 0,
	)

	if ret != 0 {
		// No values or error
		return []*PersistentFilterRecord{}, nil
	}

	records := make([]*PersistentFilterRecord, 0, valueCount)

	// Enumerate all values
	for i := uint32(0); i < valueCount; i++ {
		var nameLen uint32 = MaxValueNameLen
		name := make([]uint16, MaxValueNameLen)
		var dataType uint32
		var dataLen uint32 = MaxValueDataLen
		data := make([]uint16, MaxValueDataLen/2)

		ret, _, _ := procRegEnumValueW.Call(
			uintptr(rs.key),
			uintptr(i),
			uintptr(unsafe.Pointer(&name[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0,
			uintptr(unsafe.Pointer(&dataType)),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)

		if ret != 0 {
			continue
		}

		// Only process REG_SZ values
		if dataType != REG_SZ {
			continue
		}

		// Parse JSON
		jsonStr := syscall.UTF16ToString(data)
		var record PersistentFilterRecord
		if err := json.Unmarshal([]byte(jsonStr), &record); err != nil {
			continue
		}

		records = append(records, &record)
	}

	return records, nil
}

// ============================================================================
// Utility Methods
// ============================================================================

// DeleteAll deletes all filter records from the registry.
func (rs *RegistryStore) DeleteAll() error {
	records, err := rs.LoadAll()
	if err != nil {
		return fmt.Errorf("load all: %w", err)
	}

	for _, record := range records {
		if err := rs.DeleteFilter(record.RuleID); err != nil {
			// Continue with other deletions
		}
	}

	return nil
}

// Count returns the number of records in the registry.
func (rs *RegistryStore) Count() (int, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !rs.isOpen {
		return 0, fmt.Errorf("registry store not open")
	}

	var valueCount uint32

	ret, _, _ := procRegQueryInfoKeyW.Call(
		uintptr(rs.key),
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&valueCount)),
		0, 0, 0, 0,
	)

	if ret != 0 {
		return 0, nil
	}

	return int(valueCount), nil
}

// Exists checks if a record exists in the registry.
func (rs *RegistryStore) Exists(ruleID string) bool {
	_, err := rs.LoadFilter(ruleID)
	return err == nil
}

// ============================================================================
// Registry Cleanup
// ============================================================================

// DeleteKey deletes the entire registry key (for uninstall).
func (rs *RegistryStore) DeleteKey() error {
	// Close first if open
	if rs.isOpen {
		if err := rs.Close(); err != nil {
			return err
		}
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Determine root key
	var rootKey syscall.Handle
	if rs.useHKCU {
		rootKey = syscall.Handle(HKEY_CURRENT_USER)
	} else {
		rootKey = syscall.Handle(HKEY_LOCAL_MACHINE)
	}

	// Convert path to UTF-16
	pathPtr, err := syscall.UTF16PtrFromString(rs.basePath)
	if err != nil {
		return fmt.Errorf("convert path: %w", err)
	}

	ret, _, regErr := procRegDeleteKeyExW.Call(
		uintptr(rootKey),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(KEY_ALL_ACCESS),
		0,
	)

	// Ignore "not found" errors
	if ret != 0 && ret != 2 {
		return fmt.Errorf("delete registry key: %w (code: %d)", regErr, ret)
	}

	return nil
}

// ============================================================================
// Error Helpers
// ============================================================================

// IsRegistryAccessDenied checks if an error is an access denied error.
func IsRegistryAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	// Windows error code 5 = ERROR_ACCESS_DENIED
	return err == syscall.Errno(5)
}

// IsRegistryNotFound checks if an error is a not found error.
func IsRegistryNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Windows error code 2 = ERROR_FILE_NOT_FOUND
	return err == syscall.Errno(2)
}
