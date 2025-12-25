// Package distribution implements certificate change monitoring and distribution.
package distribution

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"certificate_manager/internal/storage"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultDebounceWindow   = time.Second
	DefaultReconnectBackoff = 5 * time.Second
	MaxReconnectBackoff     = 2 * time.Minute
	EventBufferSize         = 100
	GracefulStopTimeout     = 10 * time.Second
)

// Change event types
const (
	ChangeTypeCreated = "created"
	ChangeTypeUpdated = "updated"
	ChangeTypeDeleted = "deleted"
)

// Event sources
const (
	SourceDatabase   = "database"
	SourceFilesystem = "filesystem"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrWatcherAlreadyRunning = errors.New("watcher is already running")
	ErrWatcherNotRunning     = errors.New("watcher is not running")
	ErrInvalidEvent          = errors.New("invalid change event")
)

// ============================================================================
// Certificate Watcher Structure
// ============================================================================

// CertificateWatcher monitors certificate storage for changes
type CertificateWatcher struct {
	dbStorage   *storage.Database
	fsStorage   *storage.FilesystemStorage
	distributor *Distributor
	config      WatcherConfig

	// Channels
	eventChan chan ChangeEvent
	stopChan  chan struct{}
	doneChan  chan struct{}

	// State
	running atomic.Bool
	mu      sync.RWMutex

	// Debouncing
	debounceTimers map[string]*time.Timer
	debounceMu     sync.Mutex

	// Metrics
	metrics *WatcherMetrics
}

// WatcherConfig holds watcher configuration
type WatcherConfig struct {
	DebounceWindow        time.Duration
	CertPath              string
	KeyPath               string
	EnableFilesystemWatch bool
	EnableDatabaseWatch   bool
}

// ChangeEvent represents a certificate change notification
type ChangeEvent struct {
	Domain       string    `json:"domain"`
	ChangeType   string    `json:"change_type"`
	Source       string    `json:"source"`
	FilePath     string    `json:"file_path,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Deduplicated bool      `json:"-"`
}

// WatcherMetrics tracks watcher statistics
type WatcherMetrics struct {
	EventsReceived    int64     `json:"events_received"`
	EventsProcessed   int64     `json:"events_processed"`
	EventsDebounced   int64     `json:"events_debounced"`
	DistributionsTrig int64     `json:"distributions_triggered"`
	LastEventTime     time.Time `json:"last_event_time"`
	WatcherErrors     int64     `json:"watcher_errors"`
	ReconnectAttempts int64     `json:"reconnect_attempts"`
	mu                sync.RWMutex
}

// WatcherStatus reports current watcher state
type WatcherStatus struct {
	Running            bool            `json:"running"`
	DatabaseWatching   bool            `json:"database_watching"`
	FilesystemWatching bool            `json:"filesystem_watching"`
	Metrics            *WatcherMetrics `json:"metrics"`
	PendingEvents      int             `json:"pending_events"`
	ActiveDomains      []string        `json:"active_domains"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewCertificateWatcher creates a new certificate watcher
func NewCertificateWatcher(
	dbStorage *storage.Database,
	fsStorage *storage.FilesystemStorage,
	distributor *Distributor,
	config WatcherConfig,
) (*CertificateWatcher, error) {
	// Apply defaults
	if config.DebounceWindow <= 0 {
		config.DebounceWindow = DefaultDebounceWindow
	}

	return &CertificateWatcher{
		dbStorage:      dbStorage,
		fsStorage:      fsStorage,
		distributor:    distributor,
		config:         config,
		eventChan:      make(chan ChangeEvent, EventBufferSize),
		stopChan:       make(chan struct{}),
		doneChan:       make(chan struct{}),
		debounceTimers: make(map[string]*time.Timer),
		metrics:        &WatcherMetrics{},
	}, nil
}

// ============================================================================
// Watcher Lifecycle
// ============================================================================

// Start begins watching for certificate changes
func (cw *CertificateWatcher) Start(ctx context.Context) error {
	if cw.running.Load() {
		return ErrWatcherAlreadyRunning
	}

	cw.running.Store(true)
	cw.stopChan = make(chan struct{})
	cw.doneChan = make(chan struct{})

	// Start main event processor
	go cw.processEvents(ctx)

	// Start database watcher if enabled
	if cw.config.EnableDatabaseWatch && cw.dbStorage != nil {
		go cw.watchDatabase(ctx)
	}

	// Start filesystem watcher if enabled
	if cw.config.EnableFilesystemWatch && cw.fsStorage != nil {
		go cw.watchFilesystem(ctx)
	}

	return nil
}

// Stop gracefully shuts down the watcher
func (cw *CertificateWatcher) Stop() error {
	if !cw.running.Load() {
		return ErrWatcherNotRunning
	}

	// Signal stop
	close(cw.stopChan)

	// Wait for completion with timeout
	select {
	case <-cw.doneChan:
		// Clean shutdown
	case <-time.After(GracefulStopTimeout):
		// Force shutdown
	}

	// Stop all debounce timers
	cw.debounceMu.Lock()
	for _, timer := range cw.debounceTimers {
		timer.Stop()
	}
	cw.debounceTimers = make(map[string]*time.Timer)
	cw.debounceMu.Unlock()

	cw.running.Store(false)
	return nil
}

// IsRunning returns watcher state
func (cw *CertificateWatcher) IsRunning() bool {
	return cw.running.Load()
}

// ============================================================================
// Event Processing
// ============================================================================

// processEvents handles incoming change events
func (cw *CertificateWatcher) processEvents(ctx context.Context) {
	defer close(cw.doneChan)

	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopChan:
			return
		case event := <-cw.eventChan:
			cw.handleChangeEvent(ctx, event)
		}
	}
}

// handleChangeEvent processes a single change event
func (cw *CertificateWatcher) handleChangeEvent(ctx context.Context, event ChangeEvent) {
	atomic.AddInt64(&cw.metrics.EventsReceived, 1)
	cw.metrics.mu.Lock()
	cw.metrics.LastEventTime = event.Timestamp
	cw.metrics.mu.Unlock()

	// Validate event
	if err := cw.validateChangeEvent(event); err != nil {
		return
	}

	// Debounce rapid changes
	if !event.Deduplicated {
		cw.debounceChange(ctx, event)
		return
	}

	// Process the debounced event
	cw.processChangeEvent(ctx, event)
}

// processChangeEvent handles a validated, debounced event
func (cw *CertificateWatcher) processChangeEvent(ctx context.Context, event ChangeEvent) {
	atomic.AddInt64(&cw.metrics.EventsProcessed, 1)

	// Trigger distribution if we have a distributor
	if cw.distributor != nil {
		if event.ChangeType == ChangeTypeDeleted {
			// For deletions, we might want to notify services to reload
		} else {
			// For creates/updates, trigger distribution
			err := cw.distributor.DistributeCertificate(ctx, event.Domain)
			if err == nil {
				atomic.AddInt64(&cw.metrics.DistributionsTrig, 1)
			}
		}
	}
}

// ============================================================================
// Debouncing
// ============================================================================

// debounceChange groups rapid changes to same certificate
func (cw *CertificateWatcher) debounceChange(ctx context.Context, event ChangeEvent) {
	cw.debounceMu.Lock()
	defer cw.debounceMu.Unlock()

	// Cancel existing timer for this domain
	if timer, exists := cw.debounceTimers[event.Domain]; exists {
		timer.Stop()
		atomic.AddInt64(&cw.metrics.EventsDebounced, 1)
	}

	// Create new timer
	cw.debounceTimers[event.Domain] = time.AfterFunc(cw.config.DebounceWindow, func() {
		cw.debounceMu.Lock()
		delete(cw.debounceTimers, event.Domain)
		cw.debounceMu.Unlock()

		// Re-emit event as deduplicated
		dedupEvent := event
		dedupEvent.Deduplicated = true

		select {
		case cw.eventChan <- dedupEvent:
		case <-ctx.Done():
		}
	})
}

// ============================================================================
// Database Watching
// ============================================================================

// watchDatabase monitors PostgreSQL for certificate changes
func (cw *CertificateWatcher) watchDatabase(ctx context.Context) {
	backoff := DefaultReconnectBackoff

	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopChan:
			return
		default:
		}

		// Simulate database NOTIFY/LISTEN
		// In production, this would use PostgreSQL's LISTEN/NOTIFY
		err := cw.listenDatabaseNotifications(ctx)
		if err != nil {
			atomic.AddInt64(&cw.metrics.WatcherErrors, 1)
			atomic.AddInt64(&cw.metrics.ReconnectAttempts, 1)

			// Exponential backoff
			select {
			case <-time.After(backoff):
				if backoff < MaxReconnectBackoff {
					backoff = backoff * 2
				}
			case <-ctx.Done():
				return
			case <-cw.stopChan:
				return
			}
		} else {
			backoff = DefaultReconnectBackoff
		}
	}
}

// listenDatabaseNotifications subscribes to PostgreSQL notifications
func (cw *CertificateWatcher) listenDatabaseNotifications(ctx context.Context) error {
	// This is a placeholder for PostgreSQL LISTEN implementation
	// In production, you would:
	// 1. conn.Exec("LISTEN certificate_updated")
	// 2. conn.WaitForNotification(ctx)
	// 3. Parse payload and emit event

	// For now, just wait (database watcher placeholder)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cw.stopChan:
		return nil
	case <-time.After(30 * time.Second):
		// Periodic wake-up for reconnection checking
		return nil
	}
}

// ============================================================================
// Filesystem Watching
// ============================================================================

// watchFilesystem monitors certificate directories for file changes
func (cw *CertificateWatcher) watchFilesystem(ctx context.Context) {
	// Note: In production, use github.com/fsnotify/fsnotify
	// This is a polling-based fallback for demonstration

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastModTimes := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopChan:
			return
		case <-ticker.C:
			cw.checkFilesystemChanges(ctx, lastModTimes)
		}
	}
}

// checkFilesystemChanges polls for file changes
func (cw *CertificateWatcher) checkFilesystemChanges(ctx context.Context, lastModTimes map[string]time.Time) {
	// This is a placeholder implementation
	// In production, this would:
	// 1. Read certificate directory listing
	// 2. Compare modification times
	// 3. Emit events for changed files

	// For now, we rely on database notifications or manual triggers
	// Filesystem watching would require fsnotify or periodic directory scanning
}

// emitFilesystemEvent sends a filesystem change event
func (cw *CertificateWatcher) emitFilesystemEvent(ctx context.Context, domain, changeType, filePath string, timestamp time.Time) {
	event := ChangeEvent{
		Domain:     domain,
		ChangeType: changeType,
		Source:     SourceFilesystem,
		FilePath:   filePath,
		Timestamp:  timestamp,
	}

	select {
	case cw.eventChan <- event:
	case <-ctx.Done():
	default:
		// Channel full, drop event
	}
}

// FileInfo holds file metadata
type FileInfo struct {
	ModTime time.Time
}

// getFileInfo returns file information (placeholder for actual implementation)
func getFileInfo(_ string) (*FileInfo, error) {
	// In production, use os.Stat
	return &FileInfo{ModTime: time.Now()}, nil
}

// ============================================================================
// Event Validation
// ============================================================================

// validateChangeEvent checks if event is valid
func (cw *CertificateWatcher) validateChangeEvent(event ChangeEvent) error {
	if event.Domain == "" {
		return ErrInvalidEvent
	}
	return nil
}

// ============================================================================
// Domain Extraction
// ============================================================================

// ExtractDomainFromPath parses domain name from certificate file path
func ExtractDomainFromPath(filePath string) string {
	// Get filename without directory
	filename := filepath.Base(filePath)

	// Remove common extensions
	extensions := []string{".crt", ".pem", ".key", ".chain.pem", ".fullchain.pem"}
	for _, ext := range extensions {
		if strings.HasSuffix(filename, ext) {
			filename = filename[:len(filename)-len(ext)]
			break
		}
	}

	// Handle wildcard certificates (stored as _wildcard.example.com)
	if strings.HasPrefix(filename, "_wildcard.") {
		filename = "*." + filename[10:]
	}

	return filename
}

// ============================================================================
// Status and Metrics
// ============================================================================

// GetStatus returns current watcher status
func (cw *CertificateWatcher) GetStatus() *WatcherStatus {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	pendingDomains := make([]string, 0)
	cw.debounceMu.Lock()
	for domain := range cw.debounceTimers {
		pendingDomains = append(pendingDomains, domain)
	}
	pendingCount := len(cw.debounceTimers)
	cw.debounceMu.Unlock()

	return &WatcherStatus{
		Running:            cw.running.Load(),
		DatabaseWatching:   cw.config.EnableDatabaseWatch && cw.dbStorage != nil,
		FilesystemWatching: cw.config.EnableFilesystemWatch && cw.fsStorage != nil,
		Metrics:            cw.getMetricsSnapshot(),
		PendingEvents:      pendingCount,
		ActiveDomains:      pendingDomains,
	}
}

// getMetricsSnapshot returns copy of current metrics
func (cw *CertificateWatcher) getMetricsSnapshot() *WatcherMetrics {
	cw.metrics.mu.RLock()
	defer cw.metrics.mu.RUnlock()

	return &WatcherMetrics{
		EventsReceived:    atomic.LoadInt64(&cw.metrics.EventsReceived),
		EventsProcessed:   atomic.LoadInt64(&cw.metrics.EventsProcessed),
		EventsDebounced:   atomic.LoadInt64(&cw.metrics.EventsDebounced),
		DistributionsTrig: atomic.LoadInt64(&cw.metrics.DistributionsTrig),
		LastEventTime:     cw.metrics.LastEventTime,
		WatcherErrors:     atomic.LoadInt64(&cw.metrics.WatcherErrors),
		ReconnectAttempts: atomic.LoadInt64(&cw.metrics.ReconnectAttempts),
	}
}

// GetMetrics returns current watcher metrics
func (cw *CertificateWatcher) GetMetrics() *WatcherMetrics {
	return cw.getMetricsSnapshot()
}

// ============================================================================
// Manual Event Triggering
// ============================================================================

// TriggerRefresh manually triggers a certificate refresh event
func (cw *CertificateWatcher) TriggerRefresh(ctx context.Context, domain string) error {
	if !cw.running.Load() {
		return ErrWatcherNotRunning
	}

	event := ChangeEvent{
		Domain:       domain,
		ChangeType:   ChangeTypeUpdated,
		Source:       "manual",
		Timestamp:    time.Now(),
		Deduplicated: true, // Skip debouncing for manual triggers
	}

	select {
	case cw.eventChan <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("event channel full")
	}
}

// TriggerRefreshAll manually triggers refresh for all certificates
// Note: This requires a list of domains to be provided since filesystem
// storage doesn't track domains centrally
func (cw *CertificateWatcher) TriggerRefreshAll(ctx context.Context, domains []string) error {
	for _, domain := range domains {
		if err := cw.TriggerRefresh(ctx, domain); err != nil {
			// Continue with other domains
		}
	}
	return nil
}
