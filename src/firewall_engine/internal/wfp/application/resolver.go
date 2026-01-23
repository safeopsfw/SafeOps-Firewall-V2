// Package application provides application-aware filtering for WFP integration.
// It extends the base wfp package with advanced application identity resolution,
// NT path conversion, and WFP-compatible blob format generation.
package application

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// ============================================================================
// Windows API Imports
// ============================================================================

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDevice    = kernel32.NewProc("QueryDosDeviceW")
	procGetLogicalDrives  = kernel32.NewProc("GetLogicalDrives")
	procCreateToolhelp    = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First    = kernel32.NewProc("Process32FirstW")
	procProcess32Next     = kernel32.NewProc("Process32NextW")
	procQueryFullPath     = kernel32.NewProc("QueryFullProcessImageNameW")
	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procGetModuleFileName = kernel32.NewProc("GetModuleFileNameExW")
)

// psapi for additional process info
var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
)

const (
	// Snapshot flags
	TH32CS_SNAPPROCESS = 0x00000002

	// Process access rights
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_VM_READ                   = 0x0010

	// Invalid handle value
	INVALID_HANDLE_VALUE = ^uintptr(0)

	// Path format flags
	PROCESS_NAME_WIN32  = 0
	PROCESS_NAME_NATIVE = 1

	// Max path length
	MAX_PATH = 260
)

// PROCESSENTRY32W represents a process entry from CreateToolhelp32Snapshot.
type PROCESSENTRY32W struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [MAX_PATH]uint16
}

// ============================================================================
// Error Definitions
// ============================================================================

var (
	// ErrAppNotFound indicates the application could not be found.
	ErrAppNotFound = errors.New("application not found")

	// ErrPathEmpty indicates an empty path was provided.
	ErrPathEmpty = errors.New("empty path provided")

	// ErrInvalidPath indicates the path is invalid or malformed.
	ErrInvalidPath = errors.New("invalid path format")

	// ErrDriveNotMapped indicates a drive letter could not be mapped to NT device.
	ErrDriveNotMapped = errors.New("drive letter could not be mapped to NT device")

	// ErrProcessNotRunning indicates the process is not currently running.
	ErrProcessNotRunning = errors.New("process is not running")

	// ErrAccessDenied indicates insufficient permissions.
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidPID indicates an invalid process ID.
	ErrInvalidPID = errors.New("invalid process ID")
)

// ============================================================================
// AppIdentity - Resolved Application Information
// ============================================================================

// AppIdentity contains fully resolved application information for WFP.
// All paths are validated and the AppIDBlob is ready for WFP filter conditions.
type AppIdentity struct {
	// ProcessName is the executable name (e.g., "chrome.exe").
	ProcessName string

	// Win32Path is the standard Windows path (e.g., "C:\Program Files\...").
	Win32Path string

	// NTPath is the NT kernel path (e.g., "\Device\HarddiskVolume1\...").
	NTPath string

	// AppIDBlob is the WFP-compatible blob for FWPM_CONDITION_ALE_APP_ID.
	// Format: UTF-16LE encoded NT path with null terminator.
	AppIDBlob []byte

	// BlobSize is the size of AppIDBlob in bytes.
	BlobSize uint32

	// Verified indicates the path was verified to exist on disk.
	Verified bool

	// ResolvedAt is when this identity was resolved.
	ResolvedAt time.Time

	// PID is the process ID if resolved from a running process (0 otherwise).
	PID uint32

	// Error contains any non-fatal error encountered during resolution.
	Error error
}

// String returns a human-readable representation of the identity.
func (a *AppIdentity) String() string {
	if a == nil {
		return "<nil identity>"
	}
	status := "unverified"
	if a.Verified {
		status = "verified"
	}
	return fmt.Sprintf("AppIdentity[%s, path=%s, %s]", a.ProcessName, a.Win32Path, status)
}

// IsValid returns true if the identity has all required fields.
func (a *AppIdentity) IsValid() bool {
	return a != nil && a.NTPath != "" && len(a.AppIDBlob) > 0
}

// ============================================================================
// Resolver - Extended Application Resolver
// ============================================================================

// Resolver resolves application names and PIDs to WFP-compatible identities.
// It extends basic path resolution with NT path conversion and blob generation.
type Resolver struct {
	mu sync.RWMutex

	// NT device mapping cache (drive letter -> NT device path)
	driveMapping     map[string]string
	driveMappingTime time.Time

	// Resolved identity cache (path -> identity)
	identityCache map[string]*AppIdentity
	identityLRU   []string
	maxCacheSize  int

	// Configuration
	cacheExpiry        time.Duration
	driveMappingExpiry time.Duration
	verifyPaths        bool
}

// ResolverConfig configures the resolver behavior.
type ResolverConfig struct {
	// MaxCacheSize is the maximum number of cached identities (default: 200).
	MaxCacheSize int

	// CacheExpiry is how long cached identities are valid (default: 5 minutes).
	CacheExpiry time.Duration

	// DriveMappingExpiry is how long drive mappings are cached (default: 1 hour).
	DriveMappingExpiry time.Duration

	// VerifyPaths enables path existence verification (default: true).
	VerifyPaths bool
}

// DefaultResolverConfig returns the default resolver configuration.
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		MaxCacheSize:       200,
		CacheExpiry:        5 * time.Minute,
		DriveMappingExpiry: 1 * time.Hour,
		VerifyPaths:        true,
	}
}

// NewResolver creates a new application resolver with default configuration.
func NewResolver() *Resolver {
	return NewResolverWithConfig(DefaultResolverConfig())
}

// NewResolverWithConfig creates a resolver with custom configuration.
func NewResolverWithConfig(cfg *ResolverConfig) *Resolver {
	if cfg == nil {
		cfg = DefaultResolverConfig()
	}
	if cfg.MaxCacheSize <= 0 {
		cfg.MaxCacheSize = 200
	}
	if cfg.CacheExpiry <= 0 {
		cfg.CacheExpiry = 5 * time.Minute
	}
	if cfg.DriveMappingExpiry <= 0 {
		cfg.DriveMappingExpiry = 1 * time.Hour
	}

	return &Resolver{
		driveMapping:       make(map[string]string),
		identityCache:      make(map[string]*AppIdentity),
		identityLRU:        make([]string, 0, cfg.MaxCacheSize),
		maxCacheSize:       cfg.MaxCacheSize,
		cacheExpiry:        cfg.CacheExpiry,
		driveMappingExpiry: cfg.DriveMappingExpiry,
		verifyPaths:        cfg.VerifyPaths,
	}
}

// ============================================================================
// Core Resolution Methods
// ============================================================================

// ResolveApplication resolves an application name or path to a full identity.
// Accepts: "chrome.exe", "C:\Program Files\...\chrome.exe", or full NT path.
func (r *Resolver) ResolveApplication(nameOrPath string) (*AppIdentity, error) {
	if nameOrPath == "" {
		return nil, ErrPathEmpty
	}

	// Normalize input
	nameOrPath = strings.TrimSpace(nameOrPath)

	// Check cache first
	if identity := r.getCachedIdentity(nameOrPath); identity != nil {
		return identity, nil
	}

	// Determine if input is a full path or just a name
	var win32Path string
	var err error

	if r.isFullPath(nameOrPath) {
		win32Path = nameOrPath
	} else {
		// Resolve process name to full path
		win32Path, err = r.resolveProcessName(nameOrPath)
		if err != nil {
			return nil, fmt.Errorf("resolve process name %q: %w", nameOrPath, err)
		}
	}

	// Build full identity
	identity, err := r.buildIdentity(win32Path)
	if err != nil {
		return nil, fmt.Errorf("build identity for %q: %w", win32Path, err)
	}

	// Cache the result
	r.cacheIdentity(nameOrPath, identity)
	if nameOrPath != win32Path {
		r.cacheIdentity(win32Path, identity)
	}

	return identity, nil
}

// ResolveByPID resolves a running process by its PID.
func (r *Resolver) ResolveByPID(pid uint32) (*AppIdentity, error) {
	if pid == 0 {
		return nil, ErrInvalidPID
	}

	// Get process path from PID
	win32Path, err := r.getProcessPathByPID(pid)
	if err != nil {
		return nil, fmt.Errorf("get process path for PID %d: %w", pid, err)
	}

	// Build identity
	identity, err := r.buildIdentity(win32Path)
	if err != nil {
		return nil, fmt.Errorf("build identity for PID %d: %w", pid, err)
	}

	identity.PID = pid
	return identity, nil
}

// buildIdentity creates a complete AppIdentity from a Win32 path.
func (r *Resolver) buildIdentity(win32Path string) (*AppIdentity, error) {
	identity := &AppIdentity{
		ProcessName: filepath.Base(win32Path),
		Win32Path:   win32Path,
		ResolvedAt:  time.Now(),
	}

	// Verify path exists (if enabled)
	if r.verifyPaths {
		if _, err := os.Stat(win32Path); err != nil {
			if os.IsNotExist(err) {
				identity.Verified = false
				identity.Error = fmt.Errorf("path does not exist: %s", win32Path)
			} else if os.IsPermission(err) {
				identity.Verified = false
				identity.Error = fmt.Errorf("access denied: %s", win32Path)
			} else {
				identity.Verified = false
				identity.Error = err
			}
		} else {
			identity.Verified = true
		}
	}

	// Convert to NT path
	ntPath, err := r.Win32ToNTPath(win32Path)
	if err != nil {
		return nil, fmt.Errorf("convert to NT path: %w", err)
	}
	identity.NTPath = ntPath

	// Generate WFP blob
	blob, err := r.ToWFPAppID(ntPath)
	if err != nil {
		return nil, fmt.Errorf("generate WFP blob: %w", err)
	}
	identity.AppIDBlob = blob
	identity.BlobSize = uint32(len(blob))

	return identity, nil
}

// ============================================================================
// Path Conversion Methods
// ============================================================================

// Win32ToNTPath converts a Win32 path to an NT kernel path.
// Example: "C:\Windows\System32\cmd.exe" -> "\Device\HarddiskVolume1\Windows\System32\cmd.exe"
func (r *Resolver) Win32ToNTPath(win32Path string) (string, error) {
	if win32Path == "" {
		return "", ErrPathEmpty
	}

	// Handle UNC paths (\\server\share\...)
	if strings.HasPrefix(win32Path, `\\`) {
		// UNC paths convert to \Device\Mup\server\share\...
		return `\Device\Mup` + win32Path[1:], nil
	}

	// Handle standard drive paths (C:\...)
	if len(win32Path) >= 2 && win32Path[1] == ':' {
		driveLetter := strings.ToUpper(string(win32Path[0]))

		// Get NT device for this drive
		ntDevice, err := r.getDriveNTDevice(driveLetter)
		if err != nil {
			return "", fmt.Errorf("get NT device for drive %s: %w", driveLetter, err)
		}

		// Replace drive letter with NT device path
		return ntDevice + win32Path[2:], nil
	}

	// Handle relative paths - try to make absolute
	absPath, err := filepath.Abs(win32Path)
	if err != nil {
		return "", fmt.Errorf("get absolute path: %w", err)
	}

	return r.Win32ToNTPath(absPath)
}

// NTToWin32Path converts an NT path back to a Win32 path (if possible).
func (r *Resolver) NTToWin32Path(ntPath string) (string, error) {
	if ntPath == "" {
		return "", ErrPathEmpty
	}

	// Handle UNC paths
	if strings.HasPrefix(ntPath, `\Device\Mup\`) {
		return `\` + ntPath[len(`\Device\Mup`):], nil
	}

	// Refresh drive mapping if needed
	if err := r.refreshDriveMapping(); err != nil {
		return "", fmt.Errorf("refresh drive mapping: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Find matching NT device and replace with drive letter
	for drive, device := range r.driveMapping {
		if strings.HasPrefix(ntPath, device) {
			return drive + ":" + ntPath[len(device):], nil
		}
	}

	return "", fmt.Errorf("no drive mapping found for NT path: %s", ntPath)
}

// ============================================================================
// WFP Blob Generation
// ============================================================================

// ToWFPAppID converts an NT path to a WFP-compatible FWP_BYTE_BLOB.
// The blob contains the UTF-16LE encoded path with null terminator.
// This is the format required by FWPM_CONDITION_ALE_APP_ID.
func (r *Resolver) ToWFPAppID(ntPath string) ([]byte, error) {
	if ntPath == "" {
		return nil, ErrPathEmpty
	}

	// Convert to lowercase for consistent matching
	ntPath = strings.ToLower(ntPath)

	// Convert string to UTF-16LE
	utf16Path := utf16.Encode([]rune(ntPath))

	// Add null terminator
	utf16Path = append(utf16Path, 0)

	// Convert to bytes (little-endian)
	blob := make([]byte, len(utf16Path)*2)
	for i, v := range utf16Path {
		blob[i*2] = byte(v)
		blob[i*2+1] = byte(v >> 8)
	}

	return blob, nil
}

// FromWFPAppID parses a WFP FWP_BYTE_BLOB back to an NT path string.
func (r *Resolver) FromWFPAppID(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", ErrPathEmpty
	}

	if len(blob)%2 != 0 {
		return "", fmt.Errorf("invalid blob size: must be even, got %d", len(blob))
	}

	// Convert bytes to UTF-16
	utf16Path := make([]uint16, len(blob)/2)
	for i := 0; i < len(blob); i += 2 {
		utf16Path[i/2] = uint16(blob[i]) | uint16(blob[i+1])<<8
	}

	// Remove null terminator if present
	for len(utf16Path) > 0 && utf16Path[len(utf16Path)-1] == 0 {
		utf16Path = utf16Path[:len(utf16Path)-1]
	}

	// Convert to string
	return string(utf16.Decode(utf16Path)), nil
}

// ============================================================================
// Drive Mapping
// ============================================================================

// QueryDosDevices returns a mapping of all drive letters to their NT device paths.
func (r *Resolver) QueryDosDevices() (map[string]string, error) {
	if err := r.refreshDriveMapping(); err != nil {
		return nil, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy
	result := make(map[string]string, len(r.driveMapping))
	for k, v := range r.driveMapping {
		result[k] = v
	}
	return result, nil
}

// getDriveNTDevice returns the NT device path for a drive letter.
func (r *Resolver) getDriveNTDevice(driveLetter string) (string, error) {
	if err := r.refreshDriveMapping(); err != nil {
		return "", err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	device, found := r.driveMapping[strings.ToUpper(driveLetter)]
	if !found {
		return "", fmt.Errorf("%w: %s", ErrDriveNotMapped, driveLetter)
	}
	return device, nil
}

// refreshDriveMapping refreshes the drive letter to NT device mapping.
func (r *Resolver) refreshDriveMapping() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if refresh is needed
	if time.Since(r.driveMappingTime) < r.driveMappingExpiry && len(r.driveMapping) > 0 {
		return nil
	}

	// Get logical drives bitmask
	ret, _, err := procGetLogicalDrives.Call()
	if ret == 0 {
		return fmt.Errorf("GetLogicalDrives failed: %w", err)
	}
	driveMask := uint32(ret)

	// Clear existing mapping
	r.driveMapping = make(map[string]string)

	// Iterate through all possible drive letters (A-Z)
	for i := 0; i < 26; i++ {
		if driveMask&(1<<i) == 0 {
			continue // Drive not present
		}

		driveLetter := string(rune('A' + i))
		driveStr := driveLetter + ":"

		// Query the NT device for this drive
		var buf [MAX_PATH]uint16
		drivePtr, _ := syscall.UTF16PtrFromString(driveStr)

		ret, _, _ := procQueryDosDevice.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)

		if ret == 0 {
			// Skip drives that fail to query
			continue
		}

		// Convert to string (first null-terminated string in buffer)
		devicePath := syscall.UTF16ToString(buf[:])
		if devicePath != "" {
			r.driveMapping[driveLetter] = devicePath
		}
	}

	r.driveMappingTime = time.Now()
	return nil
}

// ============================================================================
// Process Resolution
// ============================================================================

// resolveProcessName finds the full path for a process name.
func (r *Resolver) resolveProcessName(name string) (string, error) {
	name = strings.ToLower(name)

	// Ensure .exe extension
	if !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}

	// Try running processes first
	path, err := r.findInRunningProcesses(name)
	if err == nil && path != "" {
		return path, nil
	}

	// Try registry App Paths
	path, err = r.findInRegistry(name)
	if err == nil && path != "" {
		return path, nil
	}

	// Try PATH environment variable
	path, err = r.findInPath(name)
	if err == nil && path != "" {
		return path, nil
	}

	// Try common application paths
	path, err = r.findInCommonPaths(name)
	if err == nil && path != "" {
		return path, nil
	}

	return "", fmt.Errorf("%w: %s", ErrAppNotFound, name)
}

// findInRunningProcesses searches currently running processes.
func (r *Resolver) findInRunningProcesses(name string) (string, error) {
	snapshot, _, err := procCreateToolhelp.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == INVALID_HANDLE_VALUE {
		return "", fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer procCloseHandle.Call(snapshot)

	var pe PROCESSENTRY32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return "", fmt.Errorf("no processes found")
	}

	for {
		exeName := strings.ToLower(syscall.UTF16ToString(pe.szExeFile[:]))
		if exeName == name {
			// Found matching process, get full path
			path, err := r.getProcessPathByPID(pe.th32ProcessID)
			if err == nil {
				return path, nil
			}
		}

		ret, _, _ = procProcess32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}

	return "", ErrProcessNotRunning
}

// getProcessPathByPID gets the full path for a process by PID.
func (r *Resolver) getProcessPathByPID(pid uint32) (string, error) {
	// Open process with query access
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return "", fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer procCloseHandle.Call(handle)

	// Query full path
	var buf [MAX_PATH]uint16
	size := uint32(len(buf))

	ret, _, err := procQueryFullPath.Call(
		handle,
		uintptr(PROCESS_NAME_WIN32),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", fmt.Errorf("QueryFullProcessImageName failed: %w", err)
	}

	return syscall.UTF16ToString(buf[:size]), nil
}

// findInRegistry searches Windows registry App Paths.
func (r *Resolver) findInRegistry(name string) (string, error) {
	keyPath := fmt.Sprintf(`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s`, name)

	var key syscall.Handle
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		syscall.StringToUTF16Ptr(keyPath),
		0,
		syscall.KEY_READ,
		&key,
	)
	if err != nil {
		err = syscall.RegOpenKeyEx(
			syscall.HKEY_CURRENT_USER,
			syscall.StringToUTF16Ptr(keyPath),
			0,
			syscall.KEY_READ,
			&key,
		)
		if err != nil {
			return "", fmt.Errorf("app not in registry: %w", err)
		}
	}
	defer syscall.RegCloseKey(key)

	var buf [MAX_PATH]uint16
	size := uint32(len(buf) * 2)
	var valType uint32

	err = syscall.RegQueryValueEx(
		key,
		nil,
		nil,
		&valType,
		(*byte)(unsafe.Pointer(&buf[0])),
		&size,
	)
	if err != nil {
		return "", fmt.Errorf("read registry value: %w", err)
	}

	path := syscall.UTF16ToString(buf[:])
	// Remove quotes if present
	path = strings.Trim(path, `"`)
	return path, nil
}

// findInPath searches the PATH environment variable.
func (r *Resolver) findInPath(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("PATH is empty")
	}

	paths := strings.Split(pathEnv, ";")
	for _, dir := range paths {
		fullPath := filepath.Join(dir, name)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return fullPath, nil
		}
	}

	return "", fmt.Errorf("not found in PATH: %s", name)
}

// findInCommonPaths searches common application installation paths.
func (r *Resolver) findInCommonPaths(name string) (string, error) {
	commonDirs := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("APPDATA"),
		`C:\Windows\System32`,
		`C:\Windows\SysWOW64`,
	}

	for _, dir := range commonDirs {
		if dir == "" {
			continue
		}

		// Direct match
		fullPath := filepath.Join(dir, name)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return fullPath, nil
		}

		// Search subdirectories (one level deep)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name(), name)
			if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
				return fullPath, nil
			}
		}
	}

	return "", fmt.Errorf("not found in common paths: %s", name)
}

// ============================================================================
// Cache Management
// ============================================================================

// getCachedIdentity retrieves a cached identity if valid.
func (r *Resolver) getCachedIdentity(key string) *AppIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()

	identity, found := r.identityCache[strings.ToLower(key)]
	if !found {
		return nil
	}

	// Check expiry
	if time.Since(identity.ResolvedAt) > r.cacheExpiry {
		return nil
	}

	return identity
}

// cacheIdentity adds an identity to the cache.
func (r *Resolver) cacheIdentity(key string, identity *AppIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key = strings.ToLower(key)

	// Check if already cached
	if _, exists := r.identityCache[key]; exists {
		r.updateLRU(key)
		r.identityCache[key] = identity
		return
	}

	// Evict if full
	for len(r.identityLRU) >= r.maxCacheSize {
		oldest := r.identityLRU[0]
		r.identityLRU = r.identityLRU[1:]
		delete(r.identityCache, oldest)
	}

	// Add new entry
	r.identityCache[key] = identity
	r.identityLRU = append(r.identityLRU, key)
}

// updateLRU moves an entry to the end of the LRU list.
func (r *Resolver) updateLRU(key string) {
	for i, k := range r.identityLRU {
		if k == key {
			r.identityLRU = append(r.identityLRU[:i], r.identityLRU[i+1:]...)
			break
		}
	}
	r.identityLRU = append(r.identityLRU, key)
}

// ClearCache removes all cached entries.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.identityCache = make(map[string]*AppIdentity)
	r.identityLRU = make([]string, 0, r.maxCacheSize)
}

// CacheSize returns the current number of cached identities.
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.identityCache)
}

// RefreshDriveMapping forces a refresh of drive letter mappings.
func (r *Resolver) RefreshDriveMapping() error {
	r.mu.Lock()
	r.driveMappingTime = time.Time{} // Reset expiry
	r.mu.Unlock()
	return r.refreshDriveMapping()
}

// ============================================================================
// Helper Methods
// ============================================================================

// isFullPath checks if the input is a full path (not just a filename).
func (r *Resolver) isFullPath(path string) bool {
	// Check for drive letter (C:\...)
	if len(path) >= 2 && path[1] == ':' {
		return true
	}
	// Check for UNC path (\\server\...)
	if strings.HasPrefix(path, `\\`) {
		return true
	}
	// Check for NT path (\Device\...)
	if strings.HasPrefix(path, `\Device\`) {
		return true
	}
	return false
}

// GetRunningProcesses returns a list of currently running processes.
func (r *Resolver) GetRunningProcesses() ([]ProcessInfo, error) {
	snapshot, _, err := procCreateToolhelp.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == INVALID_HANDLE_VALUE {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer procCloseHandle.Call(snapshot)

	var processes []ProcessInfo
	var pe PROCESSENTRY32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("no processes found")
	}

	for {
		name := syscall.UTF16ToString(pe.szExeFile[:])
		path, _ := r.getProcessPathByPID(pe.th32ProcessID)

		processes = append(processes, ProcessInfo{
			PID:  pe.th32ProcessID,
			PPID: pe.th32ParentProcessID,
			Name: name,
			Path: path,
		})

		ret, _, _ = procProcess32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}

	return processes, nil
}

// ProcessInfo contains basic process information.
type ProcessInfo struct {
	PID  uint32
	PPID uint32
	Name string
	Path string
}

// IsProcessRunning checks if a process with the given name is running.
func (r *Resolver) IsProcessRunning(name string) (bool, uint32) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}

	snapshot, _, _ := procCreateToolhelp.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == INVALID_HANDLE_VALUE {
		return false, 0
	}
	defer procCloseHandle.Call(snapshot)

	var pe PROCESSENTRY32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return false, 0
	}

	for {
		exeName := strings.ToLower(syscall.UTF16ToString(pe.szExeFile[:]))
		if exeName == name {
			return true, pe.th32ProcessID
		}

		ret, _, _ = procProcess32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}

	return false, 0
}
