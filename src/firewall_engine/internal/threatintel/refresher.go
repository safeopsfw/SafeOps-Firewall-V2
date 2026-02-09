package threatintel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RefreshStats tracks refresh cycle statistics
type RefreshStats struct {
	LastRefresh   time.Time `json:"last_refresh"`
	RefreshCount  int64     `json:"refresh_count"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error,omitempty"`
	IPCount       int64     `json:"ip_count"`
	VPNCount      int64     `json:"vpn_count"`
	DomainCount   int64     `json:"domain_count"`
	RefreshDurMs  int64     `json:"refresh_duration_ms"`
}

// Refresher periodically reloads IP and domain caches from the database
// to pick up new threat intel data without restarting the engine.
type Refresher struct {
	db          *DB
	ipCache     *IPCache
	domainCache *DomainCache
	interval    time.Duration

	refreshCount atomic.Int64
	errorCount   atomic.Int64
	lastDurMs    atomic.Int64

	mu        sync.Mutex
	lastError string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRefresher creates a new background refresher
func NewRefresher(db *DB, ipCache *IPCache, domainCache *DomainCache, intervalMinutes int) *Refresher {
	if intervalMinutes <= 0 {
		intervalMinutes = 5
	}
	return &Refresher{
		db:          db,
		ipCache:     ipCache,
		domainCache: domainCache,
		interval:    time.Duration(intervalMinutes) * time.Minute,
	}
}

// Start begins the background refresh loop
func (r *Refresher) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.RefreshNow(ctx); err != nil {
					r.errorCount.Add(1)
					r.mu.Lock()
					r.lastError = err.Error()
					r.mu.Unlock()
				}
			}
		}
	}()
}

// Stop halts the background refresh loop
func (r *Refresher) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

// RefreshNow triggers an immediate cache refresh
func (r *Refresher) RefreshNow(ctx context.Context) error {
	start := time.Now()

	// Refresh IP blacklist
	if err := r.ipCache.Load(ctx, r.db.Pool()); err != nil {
		return fmt.Errorf("ip cache refresh: %w", err)
	}

	// Refresh VPN/anonymizer IPs
	if err := r.ipCache.LoadVPNIPs(ctx, r.db.Pool()); err != nil {
		return fmt.Errorf("vpn cache refresh: %w", err)
	}

	// Refresh domain blocklist
	if err := r.domainCache.Load(ctx, r.db.Pool()); err != nil {
		return fmt.Errorf("domain cache refresh: %w", err)
	}

	dur := time.Since(start)
	r.lastDurMs.Store(dur.Milliseconds())
	r.refreshCount.Add(1)

	return nil
}

// Stats returns current refresh statistics
func (r *Refresher) Stats() RefreshStats {
	r.mu.Lock()
	lastErr := r.lastError
	r.mu.Unlock()

	return RefreshStats{
		LastRefresh:  r.ipCache.LastRefresh(),
		RefreshCount: r.refreshCount.Load(),
		ErrorCount:   r.errorCount.Load(),
		LastError:    lastErr,
		IPCount:      r.ipCache.Count(),
		VPNCount:     r.ipCache.VPNCount(),
		DomainCount:  r.domainCache.Count(),
		RefreshDurMs: r.lastDurMs.Load(),
	}
}
