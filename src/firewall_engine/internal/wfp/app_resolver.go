// Package wfp provides application path resolution for WFP application-aware filtering.
// WFP requires full NT paths for application identification.
package wfp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ============================================================================
// Windows API Imports
// ============================================================================

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First = kernel32.NewProc("Process32FirstW")
	procProcess32Next  = kernel32.NewProc("Process32NextW")
	procQueryFullPath  = kernel32.NewProc("QueryFullProcessImageNameW")
	procOpenProcess    = kernel32.NewProc("OpenProcess")
	procCloseHandle    = kernel32.NewProc("CloseHandle")
)

const (
	// Snapshot flags
	TH32CS_SNAPPROCESS = 0x00000002

	// Process access rights
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	// Invalid handle value
	INVALID_HANDLE_VALUE = ^uintptr(0)

	// Path format flags
	PROCESS_NAME_WIN32  = 0
	PROCESS_NAME_NATIVE = 1
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
	szExeFile           [260]uint16
}

// ============================================================================
// Application Resolver
// ============================================================================

// AppResolver resolves process names to full paths for WFP ALE conditions.
// It maintains an LRU cache of resolved paths for performance.
type AppResolver struct {
	mu      sync.RWMutex
	cache   map[string]string // processName -> fullPath
	lru     []string          // LRU order tracking
	maxSize int
}

// NewAppResolver creates a new application resolver with the given cache size.
// Default cache size is 100 entries.
func NewAppResolver(cacheSize int) *AppResolver {
	if cacheSize <= 0 {
		cacheSize = 100
	}
	return &AppResolver{
		cache:   make(map[string]string),
		lru:     make([]string, 0, cacheSize),
		maxSize: cacheSize,
	}
}

// DefaultAppResolver creates a resolver with default settings.
func DefaultAppResolver() *AppResolver {
	return NewAppResolver(100)
}

// ============================================================================
// Path Resolution
// ============================================================================

// ResolveProcessPath resolves a process name to its full path.
// Search order:
//  1. Cache (LRU)
//  2. Running processes
//  3. Registry App Paths
//  4. %PATH% environment variable
//
// Returns the full Win32 path (e.g., "C:\Program Files\Google\Chrome\chrome.exe").
func (r *AppResolver) ResolveProcessPath(processName string) (string, error) {
	if processName == "" {
		return "", fmt.Errorf("empty process name")
	}

	// Normalize process name
	processName = strings.ToLower(filepath.Base(processName))

	// Check cache first
	r.mu.RLock()
	if path, found := r.cache[processName]; found {
		r.mu.RUnlock()
		r.updateLRU(processName)
		return path, nil
	}
	r.mu.RUnlock()

	// Try finding in running processes
	path, err := r.findRunningProcess(processName)
	if err == nil && path != "" {
		r.cacheAdd(processName, path)
		return path, nil
	}

	// Try registry App Paths
	path, err = r.findInRegistry(processName)
	if err == nil && path != "" {
		r.cacheAdd(processName, path)
		return path, nil
	}

	// Try PATH environment variable
	path, err = r.findInPath(processName)
	if err == nil && path != "" {
		r.cacheAdd(processName, path)
		return path, nil
	}

	return "", fmt.Errorf("could not resolve path for process: %s", processName)
}

// ResolveProcessPID resolves a running process by PID to its full path.
func (r *AppResolver) ResolveProcessPID(pid uint32) (string, error) {
	if pid == 0 {
		return "", fmt.Errorf("invalid PID: 0")
	}

	// Open process with limited query access
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0, // bInheritHandle
		uintptr(pid),
	)
	if handle == 0 {
		return "", fmt.Errorf("failed to open process %d: %w", pid, err)
	}
	defer procCloseHandle.Call(handle)

	// Query full path
	var buf [260]uint16
	size := uint32(len(buf))

	ret, _, err := procQueryFullPath.Call(
		handle,
		uintptr(PROCESS_NAME_WIN32),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to query process path: %w", err)
	}

	return syscall.UTF16ToString(buf[:size]), nil
}

// ToNTPath converts a Win32 path to an NT path for WFP.
// WFP requires NT-style paths in some contexts.
// Example: "C:\Windows\System32\cmd.exe" -> "\Device\HarddiskVolume1\Windows\System32\cmd.exe"
func (r *AppResolver) ToNTPath(win32Path string) (string, error) {
	if win32Path == "" {
		return "", fmt.Errorf("empty path")
	}

	// For now, we use the simpler device path format
	// In a full implementation, we'd call QueryDosDevice to get the real NT path
	if len(win32Path) >= 2 && win32Path[1] == ':' {
		// Convert drive letter to device path
		driveLetter := strings.ToUpper(string(win32Path[0]))
		return fmt.Sprintf("\\??\\%s%s", driveLetter, win32Path[1:]), nil
	}

	return win32Path, nil
}

// ============================================================================
// Process Discovery
// ============================================================================

// findRunningProcess searches running processes for a matching name.
func (r *AppResolver) findRunningProcess(processName string) (string, error) {
	// Create snapshot of all processes
	snapshot, _, err := procCreateToolhelp.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == INVALID_HANDLE_VALUE {
		return "", fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer procCloseHandle.Call(snapshot)

	// Initialize process entry
	var pe PROCESSENTRY32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	// Get first process
	ret, _, _ := procProcess32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return "", fmt.Errorf("no processes found")
	}

	// Iterate through processes
	for {
		exeName := strings.ToLower(syscall.UTF16ToString(pe.szExeFile[:]))

		if exeName == processName {
			// Found matching process, get full path via PID
			path, err := r.ResolveProcessPID(pe.th32ProcessID)
			if err == nil {
				return path, nil
			}
			// Continue to try other instances of the same process
		}

		// Next process
		ret, _, _ = procProcess32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}

	return "", fmt.Errorf("process not found: %s", processName)
}

// findInRegistry searches the Windows App Paths registry for the process.
func (r *AppResolver) findInRegistry(processName string) (string, error) {
	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<exe>
	keyPath := fmt.Sprintf(`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s`, processName)

	var key syscall.Handle
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		syscall.StringToUTF16Ptr(keyPath),
		0,
		syscall.KEY_READ,
		&key,
	)
	if err != nil {
		// Try HKEY_CURRENT_USER
		err = syscall.RegOpenKeyEx(
			syscall.HKEY_CURRENT_USER,
			syscall.StringToUTF16Ptr(keyPath),
			0,
			syscall.KEY_READ,
			&key,
		)
		if err != nil {
			return "", fmt.Errorf("app path not in registry: %w", err)
		}
	}
	defer syscall.RegCloseKey(key)

	// Read the default value (which contains the full path)
	var buf [260]uint16
	size := uint32(len(buf) * 2)
	var valType uint32

	err = syscall.RegQueryValueEx(
		key,
		nil, // Default value
		nil,
		&valType,
		(*byte)(unsafe.Pointer(&buf[0])),
		&size,
	)
	if err != nil {
		return "", fmt.Errorf("failed to read app path: %w", err)
	}

	return syscall.UTF16ToString(buf[:]), nil
}

// findInPath searches the PATH environment variable for the process.
func (r *AppResolver) findInPath(processName string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("PATH environment variable is empty")
	}

	// Ensure .exe extension
	if !strings.HasSuffix(strings.ToLower(processName), ".exe") {
		processName += ".exe"
	}

	// Search each directory in PATH
	paths := strings.Split(pathEnv, ";")
	for _, dir := range paths {
		fullPath := filepath.Join(dir, processName)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return fullPath, nil
		}
	}

	return "", fmt.Errorf("process not found in PATH: %s", processName)
}

// ============================================================================
// Cache Management
// ============================================================================

// cacheAdd adds or updates an entry in the cache.
func (r *AppResolver) cacheAdd(processName, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already in cache
	if _, exists := r.cache[processName]; exists {
		r.cache[processName] = path
		return
	}

	// Evict oldest if cache is full
	if len(r.lru) >= r.maxSize {
		oldest := r.lru[0]
		r.lru = r.lru[1:]
		delete(r.cache, oldest)
	}

	// Add new entry
	r.cache[processName] = path
	r.lru = append(r.lru, processName)
}

// updateLRU moves an entry to the end of the LRU list (most recently used).
func (r *AppResolver) updateLRU(processName string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Find and remove from current position
	for i, name := range r.lru {
		if name == processName {
			r.lru = append(r.lru[:i], r.lru[i+1:]...)
			break
		}
	}

	// Add to end (most recently used)
	r.lru = append(r.lru, processName)
}

// CacheSize returns the current number of cached entries.
func (r *AppResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// ClearCache removes all cached entries.
func (r *AppResolver) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]string)
	r.lru = make([]string, 0, r.maxSize)
}

// GetCachedPath returns a cached path without performing resolution.
func (r *AppResolver) GetCachedPath(processName string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	path, found := r.cache[strings.ToLower(processName)]
	return path, found
}

// ============================================================================
// Common Application Paths
// ============================================================================

// CommonApps is a map of common application names to their typical paths.
// Used as a fallback when other resolution methods fail.
var CommonApps = map[string][]string{
	"chrome.exe": {
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	},
	"firefox.exe": {
		`C:\Program Files\Mozilla Firefox\firefox.exe`,
		`C:\Program Files (x86)\Mozilla Firefox\firefox.exe`,
	},
	"msedge.exe": {
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	},
	"iexplore.exe": {
		`C:\Program Files\Internet Explorer\iexplore.exe`,
		`C:\Program Files (x86)\Internet Explorer\iexplore.exe`,
	},
	"teams.exe": {
		`%LOCALAPPDATA%\Microsoft\Teams\current\Teams.exe`,
	},
	"slack.exe": {
		`%LOCALAPPDATA%\slack\slack.exe`,
	},
	"discord.exe": {
		`%LOCALAPPDATA%\Discord\app-*\Discord.exe`,
	},
}

// ResolveCommonApp tries to resolve an application using common paths.
func (r *AppResolver) ResolveCommonApp(processName string) (string, error) {
	processName = strings.ToLower(processName)
	paths, found := CommonApps[processName]
	if !found {
		return "", fmt.Errorf("not a common application: %s", processName)
	}

	for _, path := range paths {
		// Expand environment variables
		expandedPath := os.ExpandEnv(path)

		// Handle wildcards
		if strings.Contains(expandedPath, "*") {
			matches, _ := filepath.Glob(expandedPath)
			if len(matches) > 0 {
				return matches[0], nil
			}
			continue
		}

		if info, err := os.Stat(expandedPath); err == nil && !info.IsDir() {
			return expandedPath, nil
		}
	}

	return "", fmt.Errorf("common app path not found: %s", processName)
}

// ============================================================================
// Full Resolution with Fallback
// ============================================================================

// ResolveFull attempts all resolution methods in order.
// This is the most comprehensive resolution method.
func (r *AppResolver) ResolveFull(processName string) (string, error) {
	// Try standard resolution first
	if path, err := r.ResolveProcessPath(processName); err == nil {
		return path, nil
	}

	// Try common apps as fallback
	if path, err := r.ResolveCommonApp(processName); err == nil {
		r.cacheAdd(strings.ToLower(processName), path)
		return path, nil
	}

	return "", fmt.Errorf("could not resolve application: %s", processName)
}
