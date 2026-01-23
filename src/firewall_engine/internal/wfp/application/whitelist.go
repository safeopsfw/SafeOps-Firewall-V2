// Package application provides application whitelist management.
// The Whitelist maintains a list of approved/blocked applications with
// optional hash verification for security.
package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Action Types
// ============================================================================

// Action specifies what action to take for an application.
type Action string

const (
	// ActionAllow permits the application's network access.
	ActionAllow Action = "allow"

	// ActionBlock denies the application's network access.
	ActionBlock Action = "block"

	// ActionAudit logs but doesn't block (for monitoring).
	ActionAudit Action = "audit"
)

// IsAllow returns true if the action is allow.
func (a Action) IsAllow() bool {
	return a == ActionAllow
}

// IsBlock returns true if the action is block.
func (a Action) IsBlock() bool {
	return a == ActionBlock
}

// IsAudit returns true if the action is audit.
func (a Action) IsAudit() bool {
	return a == ActionAudit
}

// ============================================================================
// Whitelist Entry
// ============================================================================

// WhitelistEntry represents an application in the whitelist.
type WhitelistEntry struct {
	// Name is a human-readable name for the entry.
	Name string `json:"name"`

	// Path is the application path (can include wildcards).
	// Examples: "C:\Program Files\Chrome\chrome.exe"
	//           "C:\Users\*\AppData\*\Teams\*\Teams.exe"
	Path string `json:"path"`

	// NormalizedPath is the lowercase path for matching.
	NormalizedPath string `json:"normalized_path,omitempty"`

	// SHA256 is the optional hash of the executable for verification.
	SHA256 string `json:"sha256,omitempty"`

	// Publisher is the optional code signing publisher name.
	Publisher string `json:"publisher,omitempty"`

	// Action is what to do when this application is detected.
	Action Action `json:"action"`

	// Enabled indicates if this entry is active.
	Enabled bool `json:"enabled"`

	// AddedAt is when this entry was added.
	AddedAt time.Time `json:"added_at"`

	// AddedBy is who added this entry.
	AddedBy string `json:"added_by,omitempty"`

	// LastVerified is when the hash was last verified.
	LastVerified time.Time `json:"last_verified,omitempty"`

	// LastVerifiedResult is the result of the last verification.
	LastVerifiedResult bool `json:"last_verified_result,omitempty"`

	// Notes contains any additional notes about this entry.
	Notes string `json:"notes,omitempty"`

	// Tags are optional labels for categorization.
	Tags []string `json:"tags,omitempty"`

	// Priority determines evaluation order (higher = first).
	Priority int `json:"priority,omitempty"`
}

// NewWhitelistEntry creates a new whitelist entry.
func NewWhitelistEntry(name, path string, action Action) *WhitelistEntry {
	return &WhitelistEntry{
		Name:           name,
		Path:           path,
		NormalizedPath: strings.ToLower(path),
		Action:         action,
		Enabled:        true,
		AddedAt:        time.Now(),
	}
}

// NewAllowEntry creates a new allow entry.
func NewAllowEntry(name, path string) *WhitelistEntry {
	return NewWhitelistEntry(name, path, ActionAllow)
}

// NewBlockEntry creates a new block entry.
func NewBlockEntry(name, path string) *WhitelistEntry {
	return NewWhitelistEntry(name, path, ActionBlock)
}

// Validate checks if the entry is valid.
func (e *WhitelistEntry) Validate() error {
	if e.Path == "" {
		return fmt.Errorf("path is required")
	}
	if e.Action == "" {
		return fmt.Errorf("action is required")
	}
	if e.Action != ActionAllow && e.Action != ActionBlock && e.Action != ActionAudit {
		return fmt.Errorf("invalid action: %s", e.Action)
	}
	return nil
}

// HasHash returns true if a SHA256 hash is specified.
func (e *WhitelistEntry) HasHash() bool {
	return e.SHA256 != ""
}

// HasPublisher returns true if a publisher is specified.
func (e *WhitelistEntry) HasPublisher() bool {
	return e.Publisher != ""
}

// IsWildcard returns true if the path contains wildcards.
func (e *WhitelistEntry) IsWildcard() bool {
	return strings.Contains(e.Path, "*") || strings.Contains(e.Path, "?")
}

// ============================================================================
// Verification Result
// ============================================================================

// AppVerifyResult contains the result of verifying an application.
type AppVerifyResult struct {
	// Entry is the matching whitelist entry (nil if not found).
	Entry *WhitelistEntry

	// Matched indicates if the path matched an entry.
	Matched bool

	// HashValid indicates if the hash was verified (true if no hash required).
	HashValid bool

	// HashComputed is the computed hash of the file.
	HashComputed string

	// PublisherValid indicates if the publisher was verified.
	PublisherValid bool

	// PublisherFound is the publisher found in the file.
	PublisherFound string

	// Action is the resulting action.
	Action Action

	// Reason is a human-readable explanation.
	Reason string

	// VerifiedAt is when verification was performed.
	VerifiedAt time.Time
}

// IsAllowed returns true if the application should be allowed.
func (r *AppVerifyResult) IsAllowed() bool {
	return r.Matched && r.Entry != nil && r.Entry.Action == ActionAllow &&
		r.HashValid && r.PublisherValid
}

// IsBlocked returns true if the application should be blocked.
func (r *AppVerifyResult) IsBlocked() bool {
	if !r.Matched {
		return false // Not in whitelist - depends on default policy
	}
	if r.Entry == nil {
		return false
	}
	if r.Entry.Action == ActionBlock {
		return true
	}
	// Block if allow entry but verification failed
	if r.Entry.Action == ActionAllow {
		if !r.HashValid || !r.PublisherValid {
			return true
		}
	}
	return false
}

// String returns a summary of the verification result.
func (r *AppVerifyResult) String() string {
	if !r.Matched {
		return "AppVerifyResult[NOT_FOUND]"
	}
	return fmt.Sprintf("AppVerifyResult[%s, hash=%v, publisher=%v, action=%s]",
		r.Entry.Name, r.HashValid, r.PublisherValid, r.Action)
}

// ============================================================================
// Whitelist
// ============================================================================

// Whitelist manages application allow/block entries.
type Whitelist struct {
	mu sync.RWMutex

	// Entries by normalized path
	entries map[string]*WhitelistEntry

	// Wildcard entries (sorted by priority)
	wildcardEntries []*WhitelistEntry

	// Hash cache
	hashCache     map[string]hashCacheEntry
	hashCacheSize int

	// Configuration
	verifyHashes    bool
	verifyPublisher bool
	defaultAction   Action
}

type hashCacheEntry struct {
	hash       string
	size       int64
	modTime    time.Time
	computedAt time.Time
}

// WhitelistConfig configures the whitelist.
type WhitelistConfig struct {
	// VerifyHashes enables hash verification for entries with SHA256.
	VerifyHashes bool

	// VerifyPublisher enables publisher verification.
	VerifyPublisher bool

	// DefaultAction for applications not in the whitelist.
	DefaultAction Action

	// HashCacheSize is the maximum number of cached hashes.
	HashCacheSize int
}

// DefaultWhitelistConfig returns the default configuration.
func DefaultWhitelistConfig() *WhitelistConfig {
	return &WhitelistConfig{
		VerifyHashes:    true,
		VerifyPublisher: false, // Requires additional implementation
		DefaultAction:   ActionBlock,
		HashCacheSize:   500,
	}
}

// NewWhitelist creates a new empty whitelist.
func NewWhitelist() *Whitelist {
	return NewWhitelistWithConfig(DefaultWhitelistConfig())
}

// NewWhitelistWithConfig creates a whitelist with custom configuration.
func NewWhitelistWithConfig(cfg *WhitelistConfig) *Whitelist {
	if cfg == nil {
		cfg = DefaultWhitelistConfig()
	}
	return &Whitelist{
		entries:         make(map[string]*WhitelistEntry),
		wildcardEntries: make([]*WhitelistEntry, 0),
		hashCache:       make(map[string]hashCacheEntry),
		hashCacheSize:   cfg.HashCacheSize,
		verifyHashes:    cfg.VerifyHashes,
		verifyPublisher: cfg.VerifyPublisher,
		defaultAction:   cfg.DefaultAction,
	}
}

// ============================================================================
// Entry Management
// ============================================================================

// Add adds an entry to the whitelist.
func (w *Whitelist) Add(entry *WhitelistEntry) error {
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("invalid entry: %w", err)
	}

	// Normalize path
	entry.NormalizedPath = strings.ToLower(entry.Path)

	w.mu.Lock()
	defer w.mu.Unlock()

	if entry.IsWildcard() {
		// Add to wildcard entries
		w.wildcardEntries = append(w.wildcardEntries, entry)
		// Sort by priority
		w.sortWildcardEntries()
	} else {
		// Add to exact match map
		w.entries[entry.NormalizedPath] = entry
	}

	return nil
}

// Remove removes an entry by path.
func (w *Whitelist) Remove(path string) bool {
	normalizedPath := strings.ToLower(path)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check exact entries
	if _, found := w.entries[normalizedPath]; found {
		delete(w.entries, normalizedPath)
		return true
	}

	// Check wildcard entries
	for i, entry := range w.wildcardEntries {
		if entry.NormalizedPath == normalizedPath {
			w.wildcardEntries = append(w.wildcardEntries[:i], w.wildcardEntries[i+1:]...)
			return true
		}
	}

	return false
}

// Update updates an existing entry.
func (w *Whitelist) Update(entry *WhitelistEntry) error {
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("invalid entry: %w", err)
	}

	normalizedPath := strings.ToLower(entry.Path)
	entry.NormalizedPath = normalizedPath

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if exists
	if _, found := w.entries[normalizedPath]; found {
		w.entries[normalizedPath] = entry
		return nil
	}

	// Check wildcard entries
	for i, existing := range w.wildcardEntries {
		if existing.NormalizedPath == normalizedPath {
			w.wildcardEntries[i] = entry
			w.sortWildcardEntries()
			return nil
		}
	}

	return fmt.Errorf("entry not found: %s", entry.Path)
}

// sortWildcardEntries sorts by priority (higher first).
func (w *Whitelist) sortWildcardEntries() {
	// Simple bubble sort for small lists
	for i := 0; i < len(w.wildcardEntries)-1; i++ {
		for j := 0; j < len(w.wildcardEntries)-i-1; j++ {
			if w.wildcardEntries[j].Priority < w.wildcardEntries[j+1].Priority {
				w.wildcardEntries[j], w.wildcardEntries[j+1] = w.wildcardEntries[j+1], w.wildcardEntries[j]
			}
		}
	}
}

// ============================================================================
// Lookup Methods
// ============================================================================

// Lookup finds an entry by exact path match.
func (w *Whitelist) Lookup(path string) (*WhitelistEntry, bool) {
	normalizedPath := strings.ToLower(path)

	w.mu.RLock()
	defer w.mu.RUnlock()

	entry, found := w.entries[normalizedPath]
	if found && entry.Enabled {
		return entry, true
	}

	// Try wildcard match
	for _, entry := range w.wildcardEntries {
		if entry.Enabled && w.matchWildcard(normalizedPath, entry.NormalizedPath) {
			return entry, true
		}
	}

	return nil, false
}

// matchWildcard checks if a path matches a wildcard pattern.
func (w *Whitelist) matchWildcard(path, pattern string) bool {
	// Simple wildcard matching
	// * matches any sequence of characters
	// ? matches a single character

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// No wildcards, exact match
		return path == pattern
	}

	// Check prefix
	if parts[0] != "" && !strings.HasPrefix(path, parts[0]) {
		return false
	}

	// Check suffix
	lastPart := parts[len(parts)-1]
	if lastPart != "" && !strings.HasSuffix(path, lastPart) {
		return false
	}

	// Check middle parts
	remaining := path
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}

	return true
}

// IsAllowed checks if an application is allowed (quick check).
func (w *Whitelist) IsAllowed(path string) bool {
	entry, found := w.Lookup(path)
	if !found {
		return w.defaultAction == ActionAllow
	}
	return entry.Action == ActionAllow
}

// IsBlocked checks if an application is blocked (quick check).
func (w *Whitelist) IsBlocked(path string) bool {
	entry, found := w.Lookup(path)
	if !found {
		return w.defaultAction == ActionBlock
	}
	return entry.Action == ActionBlock
}

// ============================================================================
// Verification Methods
// ============================================================================

// Verify performs full verification of an application.
func (w *Whitelist) Verify(path string) (*AppVerifyResult, error) {
	result := &AppVerifyResult{
		VerifiedAt:     time.Now(),
		HashValid:      true, // Assume valid until proven otherwise
		PublisherValid: true,
	}

	// Find matching entry
	entry, found := w.Lookup(path)
	result.Matched = found
	result.Entry = entry

	if !found {
		result.Action = w.defaultAction
		result.Reason = "not in whitelist, using default action"
		return result, nil
	}

	result.Action = entry.Action

	// Verify hash if required
	if w.verifyHashes && entry.HasHash() {
		hash, err := w.ComputeFileHash(path)
		if err != nil {
			result.HashValid = false
			result.Reason = fmt.Sprintf("failed to compute hash: %v", err)
			return result, nil
		}
		result.HashComputed = hash
		result.HashValid = strings.EqualFold(hash, entry.SHA256)
		if !result.HashValid {
			result.Reason = "hash mismatch"
			return result, nil
		}

		// Update last verified
		w.mu.Lock()
		entry.LastVerified = time.Now()
		entry.LastVerifiedResult = result.HashValid
		w.mu.Unlock()
	}

	// Verify publisher if required
	if w.verifyPublisher && entry.HasPublisher() {
		publisher, err := w.GetPublisher(path)
		if err != nil {
			result.PublisherValid = false
			result.PublisherFound = ""
			result.Reason = fmt.Sprintf("failed to get publisher: %v", err)
			return result, nil
		}
		result.PublisherFound = publisher
		result.PublisherValid = strings.EqualFold(publisher, entry.Publisher)
		if !result.PublisherValid {
			result.Reason = "publisher mismatch"
			return result, nil
		}
	}

	result.Reason = "verified"
	return result, nil
}

// ============================================================================
// Hash Methods
// ============================================================================

// ComputeFileHash computes the SHA256 hash of a file.
func (w *Whitelist) ComputeFileHash(path string) (string, error) {
	// Check cache
	w.mu.RLock()
	if cached, found := w.hashCache[strings.ToLower(path)]; found {
		// Verify file hasn't changed
		info, err := os.Stat(path)
		if err == nil && info.Size() == cached.size && info.ModTime().Equal(cached.modTime) {
			w.mu.RUnlock()
			return cached.hash, nil
		}
	}
	w.mu.RUnlock()

	// Compute hash
	hash, err := ComputeFileHashSHA256(path)
	if err != nil {
		return "", err
	}

	// Cache result
	info, err := os.Stat(path)
	if err == nil {
		w.mu.Lock()
		// Evict if cache is full
		if len(w.hashCache) >= w.hashCacheSize {
			// Remove oldest entry (simple approach)
			for k := range w.hashCache {
				delete(w.hashCache, k)
				break
			}
		}
		w.hashCache[strings.ToLower(path)] = hashCacheEntry{
			hash:       hash,
			size:       info.Size(),
			modTime:    info.ModTime(),
			computedAt: time.Now(),
		}
		w.mu.Unlock()
	}

	return hash, nil
}

// ComputeFileHashSHA256 computes the SHA256 hash of a file.
func ComputeFileHashSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyHash verifies a file's hash against an expected value.
func (w *Whitelist) VerifyHash(path, expectedHash string) bool {
	hash, err := w.ComputeFileHash(path)
	if err != nil {
		return false
	}
	return strings.EqualFold(hash, expectedHash)
}

// ClearHashCache clears the hash cache.
func (w *Whitelist) ClearHashCache() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hashCache = make(map[string]hashCacheEntry)
}

// ============================================================================
// Publisher Methods
// ============================================================================

// GetPublisher returns the code signing publisher for a file.
// Note: This is a stub implementation - full implementation requires
// Windows Authenticode API calls (WinVerifyTrust, CryptQueryObject, etc.)
func (w *Whitelist) GetPublisher(path string) (string, error) {
	// Basic implementation - just check if file exists
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}

	// TODO: Implement proper code signing verification
	// This would require:
	// 1. Call WinVerifyTrust to verify the signature
	// 2. Call CryptQueryObject to get the certificate
	// 3. Extract the publisher from the certificate

	return "", fmt.Errorf("publisher verification not implemented")
}

// ============================================================================
// Enumeration Methods
// ============================================================================

// GetAll returns all entries.
func (w *Whitelist) GetAll() []*WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()

	entries := make([]*WhitelistEntry, 0, len(w.entries)+len(w.wildcardEntries))

	for _, entry := range w.entries {
		entries = append(entries, entry)
	}

	entries = append(entries, w.wildcardEntries...)

	return entries
}

// GetByAction returns entries with the specified action.
func (w *Whitelist) GetByAction(action Action) []*WhitelistEntry {
	all := w.GetAll()
	filtered := make([]*WhitelistEntry, 0)

	for _, entry := range all {
		if entry.Action == action {
			filtered = append(filtered, entry)
		}
	}

	return filtered
}

// GetAllowed returns all allow entries.
func (w *Whitelist) GetAllowed() []*WhitelistEntry {
	return w.GetByAction(ActionAllow)
}

// GetBlocked returns all block entries.
func (w *Whitelist) GetBlocked() []*WhitelistEntry {
	return w.GetByAction(ActionBlock)
}

// GetEnabled returns all enabled entries.
func (w *Whitelist) GetEnabled() []*WhitelistEntry {
	all := w.GetAll()
	filtered := make([]*WhitelistEntry, 0)

	for _, entry := range all {
		if entry.Enabled {
			filtered = append(filtered, entry)
		}
	}

	return filtered
}

// Count returns the total number of entries.
func (w *Whitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.entries) + len(w.wildcardEntries)
}

// ============================================================================
// Persistence Methods
// ============================================================================

// WhitelistFile is the JSON structure for saving/loading.
type WhitelistFile struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Entries   []*WhitelistEntry `json:"entries"`
}

// LoadFromFile loads entries from a JSON file.
func (w *Whitelist) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	return w.LoadFromReader(file)
}

// LoadFromReader loads entries from a reader.
func (w *Whitelist) LoadFromReader(r io.Reader) error {
	var wf WhitelistFile
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&wf); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	for _, entry := range wf.Entries {
		if err := w.Add(entry); err != nil {
			return fmt.Errorf("add entry %s: %w", entry.Name, err)
		}
	}

	return nil
}

// SaveToFile saves entries to a JSON file.
func (w *Whitelist) SaveToFile(path string) error {
	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	return w.SaveToWriter(file)
}

// SaveToWriter saves entries to a writer.
func (w *Whitelist) SaveToWriter(wr io.Writer) error {
	wf := WhitelistFile{
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Entries:   w.GetAll(),
	}

	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&wf); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}

// ============================================================================
// Default Entries
// ============================================================================

// AddWindowsDefaults adds default Windows system applications.
func (w *Whitelist) AddWindowsDefaults() error {
	defaults := []*WhitelistEntry{
		{
			Name:     "Windows Update",
			Path:     `C:\Windows\System32\svchost.exe`,
			Action:   ActionAllow,
			Enabled:  true,
			AddedBy:  "system",
			Notes:    "Windows core service host",
			Priority: 100,
		},
		{
			Name:     "Windows Defender",
			Path:     `C:\ProgramData\Microsoft\Windows Defender\*\MsMpEng.exe`,
			Action:   ActionAllow,
			Enabled:  true,
			AddedBy:  "system",
			Notes:    "Windows Defender Antimalware Service",
			Priority: 100,
		},
		{
			Name:     "Windows DNS Client",
			Path:     `C:\Windows\System32\svchost.exe`,
			Action:   ActionAllow,
			Enabled:  true,
			AddedBy:  "system",
			Notes:    "Required for DNS resolution",
			Priority: 100,
		},
	}

	for _, entry := range defaults {
		entry.AddedAt = time.Now()
		if err := w.Add(entry); err != nil {
			return fmt.Errorf("add default %s: %w", entry.Name, err)
		}
	}

	return nil
}

// AddCommonBrowsers adds common browser applications as allowed.
func (w *Whitelist) AddCommonBrowsers() error {
	browsers := []struct {
		name string
		path string
	}{
		{"Google Chrome", `C:\Program Files\Google\Chrome\Application\chrome.exe`},
		{"Google Chrome (x86)", `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`},
		{"Microsoft Edge", `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
		{"Mozilla Firefox", `C:\Program Files\Mozilla Firefox\firefox.exe`},
		{"Mozilla Firefox (x86)", `C:\Program Files (x86)\Mozilla Firefox\firefox.exe`},
	}

	for _, b := range browsers {
		entry := NewAllowEntry(b.name, b.path)
		entry.AddedBy = "system"
		entry.Tags = []string{"browser"}
		if err := w.Add(entry); err != nil {
			// Skip if already exists
			continue
		}
	}

	return nil
}
