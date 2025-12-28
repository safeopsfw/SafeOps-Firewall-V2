// Package dns_integration provides DNS integration for DHCP server.
// This file implements DNS synchronization and reconciliation.
package dns_integration

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Sync Configuration
// ============================================================================

// DNSSyncConfig holds synchronization settings.
type DNSSyncConfig struct {
	Enabled           bool
	SyncOnStartup     bool
	SyncInterval      time.Duration
	StartupTimeout    time.Duration
	BatchSize         int
	ConcurrentWorkers int
	CleanupStale      bool
}

// DefaultDNSSyncConfig returns sensible defaults.
func DefaultDNSSyncConfig() *DNSSyncConfig {
	return &DNSSyncConfig{
		Enabled:           true,
		SyncOnStartup:     true,
		SyncInterval:      time.Hour,
		StartupTimeout:    60 * time.Second,
		BatchSize:         100,
		ConcurrentWorkers: 10,
		CleanupStale:      true,
	}
}

// ============================================================================
// Lease Info for Sync
// ============================================================================

// SyncLeaseInfo contains lease information for synchronization.
type SyncLeaseInfo struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Hostname  string
	Domain    string
	ExpiresAt time.Time
	State     string
}

// ============================================================================
// Sync Repository Interface
// ============================================================================

// SyncLeaseRepository defines lease operations for sync.
type SyncLeaseRepository interface {
	GetActiveLeases(ctx context.Context) ([]*SyncLeaseInfo, error)
	GetExpiredLeases(ctx context.Context, since time.Time) ([]*SyncLeaseInfo, error)
	MarkDNSSynced(ctx context.Context, ip net.IP) error
}

// ============================================================================
// DNS Syncer
// ============================================================================

// DNSSyncer manages DNS synchronization.
type DNSSyncer struct {
	mu     sync.RWMutex
	config *DNSSyncConfig

	// Dependencies
	dnsClient       DNSClient
	leaseRepository SyncLeaseRepository
	hostnameMapper  *HostnameMapper

	// Lifecycle
	running  atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup

	// State
	lastSyncTime     time.Time
	lastSyncDuration time.Duration
	lastSyncResult   *SyncResult

	// Statistics
	stats SyncStats
}

// SyncResult contains results of a sync operation.
type SyncResult struct {
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	TotalLeases    int
	RecordsCreated int
	RecordsUpdated int
	RecordsDeleted int
	RecordsFailed  int
	ConflictsFound int
	Success        bool
	Error          error
}

// syncResult is used for worker result communication.
type syncResult struct {
	created bool
	updated bool
	failed  bool
}

// SyncStats tracks sync statistics.
type SyncStats struct {
	TotalSyncs          int64
	SuccessfulSyncs     int64
	FailedSyncs         int64
	RecordsCreated      int64
	RecordsUpdated      int64
	RecordsDeleted      int64
	ConflictsResolved   int64
	StaleRecordsCleaned int64
	LastSyncDurationMs  int64
}

// ============================================================================
// Syncer Creation
// ============================================================================

// NewDNSSyncer creates a new DNS syncer.
func NewDNSSyncer(config *DNSSyncConfig) *DNSSyncer {
	if config == nil {
		config = DefaultDNSSyncConfig()
	}

	return &DNSSyncer{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// ============================================================================
// Dependency Setters
// ============================================================================

// SetDNSClient sets the DNS client.
func (s *DNSSyncer) SetDNSClient(client DNSClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsClient = client
}

// SetLeaseRepository sets the lease repository.
func (s *DNSSyncer) SetLeaseRepository(repo SyncLeaseRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaseRepository = repo
}

// SetHostnameMapper sets the hostname mapper.
func (s *DNSSyncer) SetHostnameMapper(mapper *HostnameMapper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostnameMapper = mapper
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Start starts the DNS syncer.
func (s *DNSSyncer) Start(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	if s.running.Load() {
		return ErrAlreadyRunning
	}

	s.running.Store(true)
	s.stopChan = make(chan struct{})

	// Perform startup sync if enabled
	if s.config.SyncOnStartup {
		startupCtx, cancel := context.WithTimeout(ctx, s.config.StartupTimeout)
		result, err := s.PerformSync(startupCtx)
		cancel()

		if err != nil {
			// Log but don't fail - DHCP can continue without sync
		}
		s.lastSyncResult = result
	}

	// Start periodic reconciliation
	s.wg.Add(1)
	go s.reconciliationLoop()

	return nil
}

// Stop stops the DNS syncer.
func (s *DNSSyncer) Stop() error {
	if !s.running.Load() {
		return nil
	}

	close(s.stopChan)
	s.wg.Wait()
	s.running.Store(false)

	return nil
}

// ============================================================================
// Startup Synchronization
// ============================================================================

// PerformSync performs a full DNS synchronization.
func (s *DNSSyncer) PerformSync(ctx context.Context) (*SyncResult, error) {
	result := &SyncResult{
		StartTime: time.Now(),
	}

	s.mu.RLock()
	repo := s.leaseRepository
	client := s.dnsClient
	s.mu.RUnlock()

	if repo == nil {
		result.Error = ErrNoLeaseRepository
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		s.stats.FailedSyncs++
		return result, ErrNoLeaseRepository
	}

	if client == nil {
		result.Error = ErrNoDNSClient
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		s.stats.FailedSyncs++
		return result, ErrNoDNSClient
	}

	// Get all active leases
	leases, err := repo.GetActiveLeases(ctx)
	if err != nil {
		result.Error = err
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		s.stats.FailedSyncs++
		return result, err
	}

	result.TotalLeases = len(leases)

	// Process leases in batches
	s.processSyncBatches(ctx, leases, result)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = result.RecordsFailed == 0

	// Update statistics
	s.updateStats(result)

	s.mu.Lock()
	s.lastSyncTime = result.EndTime
	s.lastSyncDuration = result.Duration
	s.lastSyncResult = result
	s.mu.Unlock()

	return result, nil
}

func (s *DNSSyncer) processSyncBatches(ctx context.Context, leases []*SyncLeaseInfo, result *SyncResult) {
	// Create work channel
	workChan := make(chan *SyncLeaseInfo, len(leases))
	for _, lease := range leases {
		workChan <- lease
	}
	close(workChan)

	// Create results channel
	resultsChan := make(chan syncResult, len(leases))

	// Start workers
	var wg sync.WaitGroup
	workers := s.config.ConcurrentWorkers
	if workers > len(leases) {
		workers = len(leases)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.syncWorker(ctx, workChan, resultsChan)
		}()
	}

	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for res := range resultsChan {
		if res.created {
			result.RecordsCreated++
		}
		if res.updated {
			result.RecordsUpdated++
		}
		if res.failed {
			result.RecordsFailed++
		}
	}
}

func (s *DNSSyncer) syncWorker(ctx context.Context, workChan <-chan *SyncLeaseInfo, resultsChan chan<- syncResult) {
	s.mu.RLock()
	client := s.dnsClient
	s.mu.RUnlock()

	for lease := range workChan {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if lease.Hostname == "" {
			continue
		}

		// Calculate TTL from remaining lease time
		ttl := time.Until(lease.ExpiresAt)
		if ttl < time.Minute {
			ttl = time.Minute
		}

		req := &DNSUpdateRequest{
			Hostname:    lease.Hostname,
			IP:          lease.IP,
			MAC:         lease.MAC,
			TTL:         ttl,
			Domain:      lease.Domain,
			CreatePTR:   true,
			Synchronous: true,
		}

		err := client.DynamicUpdate(ctx, req)
		if err != nil {
			resultsChan <- struct {
				created bool
				updated bool
				failed  bool
			}{failed: true}
		} else {
			resultsChan <- struct {
				created bool
				updated bool
				failed  bool
			}{created: true}
		}
	}
}

// ============================================================================
// Periodic Reconciliation
// ============================================================================

func (s *DNSSyncer) reconciliationLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), s.config.SyncInterval/2)
			s.performReconciliation(ctx)
			cancel()
		}
	}
}

func (s *DNSSyncer) performReconciliation(ctx context.Context) {
	// Perform sync
	result, err := s.PerformSync(ctx)
	if err != nil {
		// Log error but continue
		_ = result
	}

	// Cleanup stale records if enabled
	if s.config.CleanupStale {
		s.cleanupStaleRecords(ctx)
	}
}

// ============================================================================
// Stale Record Cleanup
// ============================================================================

func (s *DNSSyncer) cleanupStaleRecords(ctx context.Context) {
	s.mu.RLock()
	repo := s.leaseRepository
	client := s.dnsClient
	s.mu.RUnlock()

	if repo == nil || client == nil {
		return
	}

	// Get recently expired leases
	since := time.Now().Add(-24 * time.Hour)
	expiredLeases, err := repo.GetExpiredLeases(ctx, since)
	if err != nil {
		return
	}

	for _, lease := range expiredLeases {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if lease.Hostname == "" {
			continue
		}

		req := &DNSDeleteRequest{
			Hostname:  lease.Hostname,
			IP:        lease.IP,
			DeletePTR: true,
		}

		err := client.DeleteRecord(ctx, req)
		if err == nil {
			s.stats.StaleRecordsCleaned++
		}
	}
}

// CleanupExpiredRecords triggers manual stale record cleanup.
func (s *DNSSyncer) CleanupExpiredRecords(ctx context.Context) (int, error) {
	s.mu.RLock()
	repo := s.leaseRepository
	client := s.dnsClient
	s.mu.RUnlock()

	if repo == nil {
		return 0, ErrNoLeaseRepository
	}

	if client == nil {
		return 0, ErrNoDNSClient
	}

	since := time.Now().Add(-24 * time.Hour)
	expiredLeases, err := repo.GetExpiredLeases(ctx, since)
	if err != nil {
		return 0, err
	}

	cleaned := 0
	for _, lease := range expiredLeases {
		if lease.Hostname == "" {
			continue
		}

		req := &DNSDeleteRequest{
			Hostname:  lease.Hostname,
			IP:        lease.IP,
			DeletePTR: true,
		}

		if err := client.DeleteRecord(ctx, req); err == nil {
			cleaned++
		}
	}

	s.stats.StaleRecordsCleaned += int64(cleaned)
	return cleaned, nil
}

// ============================================================================
// Manual Sync Trigger
// ============================================================================

// TriggerSync manually triggers a synchronization.
func (s *DNSSyncer) TriggerSync(ctx context.Context) (*SyncResult, error) {
	return s.PerformSync(ctx)
}

// ============================================================================
// Single Lease Sync
// ============================================================================

// SyncLease synchronizes a single lease to DNS.
func (s *DNSSyncer) SyncLease(ctx context.Context, lease *SyncLeaseInfo) error {
	s.mu.RLock()
	client := s.dnsClient
	s.mu.RUnlock()

	if client == nil {
		return ErrNoDNSClient
	}

	if lease == nil || lease.Hostname == "" {
		return nil
	}

	ttl := time.Until(lease.ExpiresAt)
	if ttl < time.Minute {
		ttl = time.Minute
	}

	req := &DNSUpdateRequest{
		Hostname:    lease.Hostname,
		IP:          lease.IP,
		MAC:         lease.MAC,
		TTL:         ttl,
		Domain:      lease.Domain,
		CreatePTR:   true,
		Synchronous: false, // Async for single lease
	}

	return client.DynamicUpdate(ctx, req)
}

// RemoveLeaseFromDNS removes a lease's DNS records.
func (s *DNSSyncer) RemoveLeaseFromDNS(ctx context.Context, hostname string, ip net.IP) error {
	s.mu.RLock()
	client := s.dnsClient
	s.mu.RUnlock()

	if client == nil {
		return ErrNoDNSClient
	}

	req := &DNSDeleteRequest{
		Hostname:  hostname,
		IP:        ip,
		DeletePTR: true,
	}

	return client.DeleteRecord(ctx, req)
}

// ============================================================================
// Statistics Updates
// ============================================================================

func (s *DNSSyncer) updateStats(result *SyncResult) {
	s.stats.TotalSyncs++
	if result.Success {
		s.stats.SuccessfulSyncs++
	} else {
		s.stats.FailedSyncs++
	}
	s.stats.RecordsCreated += int64(result.RecordsCreated)
	s.stats.RecordsUpdated += int64(result.RecordsUpdated)
	s.stats.RecordsDeleted += int64(result.RecordsDeleted)
	s.stats.ConflictsResolved += int64(result.ConflictsFound)
	s.stats.LastSyncDurationMs = result.Duration.Milliseconds()
}

// ============================================================================
// Status and Statistics
// ============================================================================

// GetStats returns sync statistics.
func (s *DNSSyncer) GetStats() SyncStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// GetLastSyncTime returns the last sync time.
func (s *DNSSyncer) GetLastSyncTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSyncTime
}

// GetLastSyncResult returns the last sync result.
func (s *DNSSyncer) GetLastSyncResult() *SyncResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSyncResult
}

// IsRunning returns whether syncer is running.
func (s *DNSSyncer) IsRunning() bool {
	return s.running.Load()
}

// GetSyncSuccessRate returns the sync success rate.
func (s *DNSSyncer) GetSyncSuccessRate() float64 {
	if s.stats.TotalSyncs == 0 {
		return 100.0
	}
	return float64(s.stats.SuccessfulSyncs) / float64(s.stats.TotalSyncs) * 100
}

// GetSyncHealth returns sync health status.
func (s *DNSSyncer) GetSyncHealth() *SyncHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	health := &SyncHealth{
		Running:         s.running.Load(),
		LastSyncTime:    s.lastSyncTime,
		LastSyncSuccess: s.lastSyncResult != nil && s.lastSyncResult.Success,
		SyncSuccessRate: s.GetSyncSuccessRate(),
	}

	// Check staleness
	if !s.lastSyncTime.IsZero() {
		staleness := time.Since(s.lastSyncTime)
		health.Stale = staleness > s.config.SyncInterval*2
	}

	return health
}

// SyncHealth contains sync health information.
type SyncHealth struct {
	Running         bool
	LastSyncTime    time.Time
	LastSyncSuccess bool
	SyncSuccessRate float64
	Stale           bool
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrAlreadyRunning is returned when syncer already running
	ErrAlreadyRunning = errors.New("syncer already running")

	// ErrNotRunning is returned when syncer not running
	ErrNotRunning = errors.New("syncer not running")

	// ErrNoDNSClient is returned when DNS client not configured
	ErrNoDNSClient = errors.New("DNS client not configured")

	// ErrSyncTimeout is returned when sync times out
	ErrSyncTimeout = errors.New("sync operation timed out")
)
