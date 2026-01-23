// Package cache provides high-performance verdict caching for the firewall engine.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Error Definitions for TTL
// ============================================================================

var (
	// ErrTTLManagerClosed is returned when operations are attempted on a closed manager.
	ErrTTLManagerClosed = errors.New("TTL manager is closed")

	// ErrTTLZero is returned when TTL is zero or negative.
	ErrTTLZero = errors.New("TTL must be positive")

	// ErrTTLTooShort is returned when TTL is too short.
	ErrTTLTooShort = errors.New("TTL too short (minimum 1 second)")

	// ErrTTLTooLong is returned when TTL is too long.
	ErrTTLTooLong = errors.New("TTL too long (maximum 24 hours)")

	// ErrCleanupIntervalInvalid is returned when cleanup interval is invalid.
	ErrCleanupIntervalInvalid = errors.New("cleanup interval must be >= 1 second")

	// ErrNoCleanupFunc is returned when no cleanup function is set.
	ErrNoCleanupFunc = errors.New("no cleanup function configured")
)

// ============================================================================
// TTL Configuration
// ============================================================================

// TTLConfig contains TTL configuration for the cache.
type TTLConfig struct {
	// DefaultTTL is the default TTL for entries.
	DefaultTTL time.Duration `json:"default_ttl" toml:"default_ttl"`

	// MinTTL is the minimum allowed TTL.
	MinTTL time.Duration `json:"min_ttl" toml:"min_ttl"`

	// MaxTTL is the maximum allowed TTL.
	MaxTTL time.Duration `json:"max_ttl" toml:"max_ttl"`

	// CleanupInterval is how often to run cleanup.
	CleanupInterval time.Duration `json:"cleanup_interval" toml:"cleanup_interval"`

	// BatchSize is how many entries to check per cleanup run.
	BatchSize int `json:"batch_size" toml:"batch_size"`

	// Per-verdict TTLs
	VerdictTTLs map[models.Verdict]time.Duration `json:"verdict_ttls" toml:"-"`

	// EnableExtendOnAccess extends TTL when entry is accessed.
	EnableExtendOnAccess bool `json:"enable_extend_on_access" toml:"enable_extend_on_access"`

	// ExtendDuration is how much to extend TTL on access.
	ExtendDuration time.Duration `json:"extend_duration" toml:"extend_duration"`
}

// DefaultTTLConfig returns the default TTL configuration.
func DefaultTTLConfig() *TTLConfig {
	return &TTLConfig{
		DefaultTTL:      60 * time.Second,
		MinTTL:          1 * time.Second,
		MaxTTL:          24 * time.Hour,
		CleanupInterval: 10 * time.Second,
		BatchSize:       1000,
		VerdictTTLs: map[models.Verdict]time.Duration{
			models.VerdictAllow:    60 * time.Second,  // Allow decisions stable
			models.VerdictBlock:    60 * time.Second,  // Block may change
			models.VerdictDrop:     300 * time.Second, // Drop persistent (malware)
			models.VerdictRedirect: 30 * time.Second,  // Captive portal shorter
			models.VerdictReject:   60 * time.Second,
			models.VerdictLog:      60 * time.Second,
		},
		EnableExtendOnAccess: false,
		ExtendDuration:       30 * time.Second,
	}
}

// Validate checks the configuration for errors.
func (c *TTLConfig) Validate() error {
	if c.DefaultTTL < time.Second {
		return fmt.Errorf("%w: default_ttl must be >= 1s, got %v", ErrTTLTooShort, c.DefaultTTL)
	}
	if c.DefaultTTL > 24*time.Hour {
		return fmt.Errorf("%w: default_ttl must be <= 24h, got %v", ErrTTLTooLong, c.DefaultTTL)
	}
	if c.CleanupInterval < time.Second {
		return fmt.Errorf("%w: got %v", ErrCleanupIntervalInvalid, c.CleanupInterval)
	}
	if c.BatchSize < 1 {
		return fmt.Errorf("batch_size must be >= 1, got %d", c.BatchSize)
	}
	return nil
}

// GetTTLForVerdict returns the TTL for a specific verdict.
func (c *TTLConfig) GetTTLForVerdict(verdict models.Verdict) time.Duration {
	if ttl, ok := c.VerdictTTLs[verdict]; ok && ttl > 0 {
		return ttl
	}
	return c.DefaultTTL
}

// ClampTTL ensures TTL is within valid range.
func (c *TTLConfig) ClampTTL(ttl time.Duration) time.Duration {
	if ttl < c.MinTTL {
		return c.MinTTL
	}
	if ttl > c.MaxTTL {
		return c.MaxTTL
	}
	return ttl
}

// ============================================================================
// TTL Manager
// ============================================================================

// TTLManager handles TTL expiration for cache entries.
// It runs a background goroutine to periodically clean up expired entries.
type TTLManager struct {
	// Configuration
	config *TTLConfig

	// Cleanup function (provided by cache)
	cleanupFunc CleanupFunc

	// Statistics
	stats *TTLStats

	// Logging
	logger *log.Logger

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   atomic.Bool
	closed    atomic.Bool
	closeMu   sync.Mutex
	closeOnce sync.Once
}

// CleanupFunc is called during cleanup to remove expired entries.
// It should return the number of entries removed and any error.
type CleanupFunc func() (removed int, err error)

// TTLStats contains TTL-related statistics.
type TTLStats struct {
	CleanupRuns      atomic.Uint64 `json:"cleanup_runs"`
	EntriesExpired   atomic.Uint64 `json:"entries_expired"`
	EntriesExtended  atomic.Uint64 `json:"entries_extended"`
	CleanupErrors    atomic.Uint64 `json:"cleanup_errors"`
	TotalCleanupNs   atomic.Uint64 `json:"total_cleanup_ns"`
	LastCleanupNs    atomic.Int64  `json:"last_cleanup_ns"`
	LastCleanupCount atomic.Int64  `json:"last_cleanup_count"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewTTLManager creates a new TTL manager.
func NewTTLManager(config *TTLConfig) (*TTLManager, error) {
	if config == nil {
		config = DefaultTTLConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid TTL config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TTLManager{
		config: config,
		stats:  &TTLStats{},
		logger: log.New(log.Writer(), "[TTL-MGR] ", log.LstdFlags|log.Lmicroseconds),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// ============================================================================
// Configuration
// ============================================================================

// SetCleanupFunc sets the cleanup function.
func (m *TTLManager) SetCleanupFunc(fn CleanupFunc) {
	m.cleanupFunc = fn
}

// SetLogger sets a custom logger.
func (m *TTLManager) SetLogger(logger *log.Logger) {
	if logger != nil {
		m.logger = logger
	}
}

// GetConfig returns the current configuration.
func (m *TTLManager) GetConfig() *TTLConfig {
	return m.config
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start begins the background cleanup goroutine.
func (m *TTLManager) Start(ctx context.Context) error {
	if m.closed.Load() {
		return ErrTTLManagerClosed
	}

	if m.running.Load() {
		return fmt.Errorf("TTL manager already running")
	}

	if m.cleanupFunc == nil {
		return ErrNoCleanupFunc
	}

	m.running.Store(true)

	// Start cleanup goroutine
	m.wg.Add(1)
	go m.cleanupLoop()

	m.logger.Printf("TTL manager started (interval=%v, batch=%d)",
		m.config.CleanupInterval, m.config.BatchSize)

	return nil
}

// cleanupLoop runs periodic cleanup.
func (m *TTLManager) cleanupLoop() {
	defer m.wg.Done()
	defer m.running.Store(false)

	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			m.logger.Println("TTL cleanup loop stopping...")
			return

		case <-ticker.C:
			m.runCleanup()
		}
	}
}

// runCleanup executes a single cleanup pass.
func (m *TTLManager) runCleanup() {
	if m.closed.Load() {
		return
	}

	startTime := time.Now()
	m.stats.CleanupRuns.Add(1)

	// Call the cleanup function
	removed, err := m.cleanupFunc()

	duration := time.Since(startTime)
	m.stats.TotalCleanupNs.Add(uint64(duration.Nanoseconds()))
	m.stats.LastCleanupNs.Store(duration.Nanoseconds())
	m.stats.LastCleanupCount.Store(int64(removed))

	if err != nil {
		m.stats.CleanupErrors.Add(1)
		m.logger.Printf("Cleanup error: %v", err)
		return
	}

	if removed > 0 {
		m.stats.EntriesExpired.Add(uint64(removed))
		m.logger.Printf("Cleanup: expired %d entries in %v", removed, duration)
	}
}

// RunCleanupNow triggers an immediate cleanup (for testing or on-demand).
func (m *TTLManager) RunCleanupNow() (int, error) {
	if m.closed.Load() {
		return 0, ErrTTLManagerClosed
	}

	if m.cleanupFunc == nil {
		return 0, ErrNoCleanupFunc
	}

	startTime := time.Now()
	m.stats.CleanupRuns.Add(1)

	removed, err := m.cleanupFunc()

	duration := time.Since(startTime)
	m.stats.TotalCleanupNs.Add(uint64(duration.Nanoseconds()))
	m.stats.LastCleanupNs.Store(duration.Nanoseconds())
	m.stats.LastCleanupCount.Store(int64(removed))

	if err != nil {
		m.stats.CleanupErrors.Add(1)
		return removed, fmt.Errorf("cleanup failed: %w", err)
	}

	if removed > 0 {
		m.stats.EntriesExpired.Add(uint64(removed))
	}

	return removed, nil
}

// Stop gracefully stops the TTL manager.
func (m *TTLManager) Stop() error {
	var err error

	m.closeOnce.Do(func() {
		m.closeMu.Lock()
		defer m.closeMu.Unlock()

		m.logger.Println("Stopping TTL manager...")
		m.closed.Store(true)

		// Cancel context
		m.cancel()

		// Wait for goroutines with timeout
		done := make(chan struct{})
		go func() {
			m.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			m.logger.Println("TTL manager stopped gracefully")
		case <-time.After(5 * time.Second):
			err = fmt.Errorf("TTL manager stop timed out")
			m.logger.Println("TTL manager stop timed out")
		}

		// Log final stats
		stats := m.GetStats()
		m.logger.Printf("Final stats: runs=%d, expired=%d, errors=%d",
			stats["cleanup_runs"],
			stats["entries_expired"],
			stats["cleanup_errors"],
		)
	})

	return err
}

// IsRunning returns true if the manager is running.
func (m *TTLManager) IsRunning() bool {
	return m.running.Load() && !m.closed.Load()
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns TTL manager statistics.
func (m *TTLManager) GetStats() map[string]uint64 {
	totalRuns := m.stats.CleanupRuns.Load()
	totalTime := m.stats.TotalCleanupNs.Load()
	avgTime := uint64(0)
	if totalRuns > 0 {
		avgTime = totalTime / totalRuns
	}

	return map[string]uint64{
		"cleanup_runs":        totalRuns,
		"entries_expired":     m.stats.EntriesExpired.Load(),
		"entries_extended":    m.stats.EntriesExtended.Load(),
		"cleanup_errors":      m.stats.CleanupErrors.Load(),
		"avg_cleanup_time_ns": avgTime,
		"last_cleanup_count":  uint64(m.stats.LastCleanupCount.Load()),
	}
}

// ============================================================================
// TTL Helpers
// ============================================================================

// CalculateExpiry calculates expiry time from now.
func CalculateExpiry(ttl time.Duration) time.Time {
	return time.Now().Add(ttl)
}

// IsExpired checks if the given expiry time has passed.
func IsExpired(expiresAt time.Time) bool {
	return time.Now().After(expiresAt)
}

// TimeToExpiry returns duration until expiry (0 if already expired).
func TimeToExpiry(expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ValidateTTL validates a TTL value.
func ValidateTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return ErrTTLZero
	}
	if ttl < time.Second {
		return ErrTTLTooShort
	}
	if ttl > 24*time.Hour {
		return ErrTTLTooLong
	}
	return nil
}

// ============================================================================
// TTL Entry Wrapper (for entries with TTL tracking)
// ============================================================================

// TTLEntry wraps any value with TTL metadata.
type TTLEntry struct {
	Value     interface{}   `json:"value"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	TTL       time.Duration `json:"ttl"`
}

// NewTTLEntry creates a new TTL entry.
func NewTTLEntry(value interface{}, ttl time.Duration) *TTLEntry {
	now := time.Now()
	return &TTLEntry{
		Value:     value,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		TTL:       ttl,
	}
}

// IsExpired returns true if the entry has expired.
func (e *TTLEntry) IsExpired() bool {
	return IsExpired(e.ExpiresAt)
}

// Extend extends the TTL by the specified duration.
func (e *TTLEntry) Extend(duration time.Duration) {
	e.ExpiresAt = e.ExpiresAt.Add(duration)
	e.TTL += duration
}

// Refresh resets the TTL from now.
func (e *TTLEntry) Refresh() {
	e.ExpiresAt = time.Now().Add(e.TTL)
}

// Age returns how long since the entry was created.
func (e *TTLEntry) Age() time.Duration {
	return time.Since(e.CreatedAt)
}

// Remaining returns the time until expiry.
func (e *TTLEntry) Remaining() time.Duration {
	return TimeToExpiry(e.ExpiresAt)
}
