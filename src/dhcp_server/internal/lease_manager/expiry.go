// Package lease_manager handles DHCP lease lifecycle operations.
// This file implements background cleanup for expired leases.
package lease_manager

import (
	"context"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Expiry Handler Configuration
// ============================================================================

// ExpiryConfig holds cleanup settings.
type ExpiryConfig struct {
	CleanupInterval time.Duration
	CleanupTimeout  time.Duration
	BatchSize       int // 0 = unlimited
	DNSCleanup      bool
	DNSTimeout      time.Duration
}

// DefaultExpiryConfig returns sensible defaults.
func DefaultExpiryConfig() *ExpiryConfig {
	return &ExpiryConfig{
		CleanupInterval: 5 * time.Minute,
		CleanupTimeout:  60 * time.Second,
		BatchSize:       0, // unlimited
		DNSCleanup:      true,
		DNSTimeout:      5 * time.Second,
	}
}

// ============================================================================
// Expired Lease Entry
// ============================================================================

// ExpiredLease represents a lease pending cleanup.
type ExpiredLease struct {
	ID        int64
	PoolName  string
	MAC       net.HardwareAddr
	IP        net.IP
	Hostname  string
	LeaseEnd  time.Time
	ExpiredAt time.Time
}

// ExpiredFor returns how long the lease has been expired.
func (l *ExpiredLease) ExpiredFor() time.Duration {
	return time.Since(l.LeaseEnd)
}

// ============================================================================
// Expiry Handler
// ============================================================================

// ExpiryHandler manages background lease cleanup.
type ExpiryHandler struct {
	mu     sync.RWMutex
	config *ExpiryConfig

	// Background goroutine control
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	running  bool

	// Callbacks for cleanup operations
	getExpiredFunc func(ctx context.Context, limit int) ([]*ExpiredLease, error)
	deleteLeaseFn  func(ctx context.Context, id int64) error
	dnsCleanupFn   func(ctx context.Context, hostname string, ip net.IP) error

	// Statistics
	stats ExpiryStats
}

// ExpiryStats tracks cleanup metrics.
type ExpiryStats struct {
	TotalRuns          int64
	TotalCleaned       int64
	TotalFailed        int64
	DNSCleanupFailures int64
	LastRunAt          time.Time
	LastRunDuration    time.Duration
	LastRunCleaned     int
	LastRunFailed      int
}

// NewExpiryHandler creates a new expiry handler.
func NewExpiryHandler(config *ExpiryConfig) *ExpiryHandler {
	if config == nil {
		config = DefaultExpiryConfig()
	}

	return &ExpiryHandler{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// ============================================================================
// Callback Setters
// ============================================================================

// SetGetExpiredFunc sets the callback for retrieving expired leases.
func (h *ExpiryHandler) SetGetExpiredFunc(fn func(ctx context.Context, limit int) ([]*ExpiredLease, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.getExpiredFunc = fn
}

// SetDeleteLeaseFunc sets the callback for deleting leases.
func (h *ExpiryHandler) SetDeleteLeaseFunc(fn func(ctx context.Context, id int64) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleteLeaseFn = fn
}

// SetDNSCleanupFunc sets the callback for DNS cleanup.
func (h *ExpiryHandler) SetDNSCleanupFunc(fn func(ctx context.Context, hostname string, ip net.IP) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dnsCleanupFn = fn
}

// ============================================================================
// Goroutine Management
// ============================================================================

// Start launches the background cleanup goroutine.
func (h *ExpiryHandler) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}

	h.ticker = time.NewTicker(h.config.CleanupInterval)
	h.stopChan = make(chan struct{})
	h.running = true
	h.mu.Unlock()

	h.wg.Add(1)
	go h.cleanupLoop()
}

// Stop gracefully stops the cleanup goroutine.
func (h *ExpiryHandler) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	h.mu.Unlock()

	close(h.stopChan)
	h.ticker.Stop()
	h.wg.Wait()
}

// IsRunning returns whether the handler is running.
func (h *ExpiryHandler) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// ============================================================================
// Cleanup Loop
// ============================================================================

func (h *ExpiryHandler) cleanupLoop() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ticker.C:
			h.runCleanup()

		case <-h.stopChan:
			return
		}
	}
}

// RunCleanupNow triggers an immediate cleanup run (for testing/manual trigger).
func (h *ExpiryHandler) RunCleanupNow() {
	h.runCleanup()
}

func (h *ExpiryHandler) runCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), h.config.CleanupTimeout)
	defer cancel()

	startTime := time.Now()

	h.mu.Lock()
	h.stats.TotalRuns++
	getExpired := h.getExpiredFunc
	h.mu.Unlock()

	if getExpired == nil {
		return
	}

	// Get expired leases
	limit := h.config.BatchSize
	expiredLeases, err := getExpired(ctx, limit)
	if err != nil {
		return
	}

	if len(expiredLeases) == 0 {
		h.updateLastRun(startTime, 0, 0)
		return
	}

	// Process each expired lease
	cleaned := 0
	failed := 0

	for _, lease := range expiredLeases {
		if err := h.cleanupLease(ctx, lease); err != nil {
			failed++
		} else {
			cleaned++
		}
	}

	h.updateLastRun(startTime, cleaned, failed)
}

func (h *ExpiryHandler) updateLastRun(startTime time.Time, cleaned, failed int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stats.TotalCleaned += int64(cleaned)
	h.stats.TotalFailed += int64(failed)
	h.stats.LastRunAt = time.Now()
	h.stats.LastRunDuration = time.Since(startTime)
	h.stats.LastRunCleaned = cleaned
	h.stats.LastRunFailed = failed
}

// ============================================================================
// Individual Lease Cleanup
// ============================================================================

func (h *ExpiryHandler) cleanupLease(ctx context.Context, lease *ExpiredLease) error {
	// Step 1: DNS cleanup (best-effort)
	if h.config.DNSCleanup && lease.Hostname != "" {
		h.cleanupDNS(ctx, lease)
	}

	// Step 2: Delete lease from database
	h.mu.RLock()
	deleteFn := h.deleteLeaseFn
	h.mu.RUnlock()

	if deleteFn != nil {
		if err := deleteFn(ctx, lease.ID); err != nil {
			return err
		}
	}

	return nil
}

func (h *ExpiryHandler) cleanupDNS(ctx context.Context, lease *ExpiredLease) {
	h.mu.RLock()
	dnsCleanup := h.dnsCleanupFn
	h.mu.RUnlock()

	if dnsCleanup == nil {
		return
	}

	dnsCtx, cancel := context.WithTimeout(ctx, h.config.DNSTimeout)
	defer cancel()

	if err := dnsCleanup(dnsCtx, lease.Hostname, lease.IP); err != nil {
		h.mu.Lock()
		h.stats.DNSCleanupFailures++
		h.mu.Unlock()
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns expiry handler statistics.
func (h *ExpiryHandler) GetStats() ExpiryStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GetCleanedCount returns total leases cleaned.
func (h *ExpiryHandler) GetCleanedCount() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats.TotalCleaned
}

// GetFailedCount returns total cleanup failures.
func (h *ExpiryHandler) GetFailedCount() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats.TotalFailed
}

// GetLastRunInfo returns info about the last cleanup run.
func (h *ExpiryHandler) GetLastRunInfo() (time.Time, time.Duration, int, int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats.LastRunAt, h.stats.LastRunDuration, h.stats.LastRunCleaned, h.stats.LastRunFailed
}

// ============================================================================
// Cleanup Queries (Helper for Repository Integration)
// ============================================================================

// CleanupQuery represents a query for expired leases.
type CleanupQuery struct {
	MaxAge   time.Duration // Leases expired longer than this
	PoolName string        // Filter by pool (empty = all)
	Limit    int           // Max results (0 = unlimited)
}

// DefaultCleanupQuery returns a query for all expired leases.
func DefaultCleanupQuery() *CleanupQuery {
	return &CleanupQuery{
		MaxAge: 0, // Any expired lease
		Limit:  0, // No limit
	}
}

// ============================================================================
// Metrics Export
// ============================================================================

// ExpiryMetrics holds metrics for external consumption.
type ExpiryMetrics struct {
	TotalRuns           int64
	TotalCleaned        int64
	TotalFailed         int64
	DNSCleanupFailures  int64
	LastRunDurationMs   int64
	CleanupIntervalSecs int64
}

// GetMetrics returns metrics for Prometheus export.
func (h *ExpiryHandler) GetMetrics() ExpiryMetrics {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return ExpiryMetrics{
		TotalRuns:           h.stats.TotalRuns,
		TotalCleaned:        h.stats.TotalCleaned,
		TotalFailed:         h.stats.TotalFailed,
		DNSCleanupFailures:  h.stats.DNSCleanupFailures,
		LastRunDurationMs:   h.stats.LastRunDuration.Milliseconds(),
		CleanupIntervalSecs: int64(h.config.CleanupInterval.Seconds()),
	}
}

// ============================================================================
// Configuration Updates
// ============================================================================

// UpdateInterval updates the cleanup interval (restarts ticker).
func (h *ExpiryHandler) UpdateInterval(interval time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.config.CleanupInterval = interval
	if h.running && h.ticker != nil {
		h.ticker.Reset(interval)
	}
}

// UpdateBatchSize updates the batch size limit.
func (h *ExpiryHandler) UpdateBatchSize(size int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.BatchSize = size
}

// EnableDNSCleanup enables or disables DNS cleanup.
func (h *ExpiryHandler) EnableDNSCleanup(enabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.DNSCleanup = enabled
}
