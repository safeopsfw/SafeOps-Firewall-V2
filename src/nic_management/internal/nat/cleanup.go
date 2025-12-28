// Package nat provides NAT/NAPT translation functionality for the NIC Management service.
package nat

import (
	"context"
	"errors"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrCleanupFailed indicates a general cleanup failure.
	ErrCleanupFailed = errors.New("cleanup failed")
	// ErrDatabaseVacuumFailed indicates database vacuum failed.
	ErrDatabaseVacuumFailed = errors.New("database vacuum failed")
	// ErrOrphanDetectionFailed indicates orphan detection failed.
	ErrOrphanDetectionFailed = errors.New("orphan detection failed")
	// ErrCleanupSyncFailed indicates Rust synchronization failed.
	ErrCleanupSyncFailed = errors.New("Rust sync failed")
)

// =============================================================================
// Resource Pressure
// =============================================================================

// ResourcePressure represents the level of resource pressure.
type ResourcePressure int

const (
	// PressureLow indicates normal operation.
	PressureLow ResourcePressure = iota
	// PressureMedium indicates moderate resource usage.
	PressureMedium
	// PressureHigh indicates resource constraints.
	PressureHigh
)

// =============================================================================
// Cleanup Configuration
// =============================================================================

// CleanupConfig contains configuration for the cleanup manager.
type CleanupConfig struct {
	// CleanupInterval is how often to run cleanup.
	CleanupInterval time.Duration `json:"cleanup_interval"`
	// ExpiredMappingThreshold is the grace period before removing expired mappings.
	ExpiredMappingThreshold time.Duration `json:"expired_mapping_threshold"`
	// OrphanedSessionThreshold is the inactivity threshold for orphan detection.
	OrphanedSessionThreshold time.Duration `json:"orphaned_session_threshold"`
	// EnableDatabaseVacuum runs database VACUUM.
	EnableDatabaseVacuum bool `json:"enable_database_vacuum"`
	// VacuumInterval is how often to vacuum database.
	VacuumInterval time.Duration `json:"vacuum_interval"`
	// EnablePortReclamation reclaims unused ports.
	EnablePortReclamation bool `json:"enable_port_reclamation"`
	// MaxCleanupBatchSize is the max records to clean per batch.
	MaxCleanupBatchSize int `json:"max_cleanup_batch_size"`
	// EnableAggressiveCleanup triggers more frequent cleanup under pressure.
	EnableAggressiveCleanup bool `json:"enable_aggressive_cleanup"`
}

// DefaultCleanupConfig returns the default cleanup configuration.
func DefaultCleanupConfig() *CleanupConfig {
	return &CleanupConfig{
		CleanupInterval:          60 * time.Second,
		ExpiredMappingThreshold:  5 * time.Second,
		OrphanedSessionThreshold: 300 * time.Second,
		EnableDatabaseVacuum:     true,
		VacuumInterval:           24 * time.Hour,
		EnablePortReclamation:    true,
		MaxCleanupBatchSize:      1000,
		EnableAggressiveCleanup:  false,
	}
}

// =============================================================================
// Cleanup Statistics
// =============================================================================

// CleanupStatistics contains cleanup operation statistics.
type CleanupStatistics struct {
	// TotalCleanupRuns is the total cleanup executions.
	TotalCleanupRuns uint64 `json:"total_cleanup_runs"`
	// MappingsRemoved is the total expired mappings removed.
	MappingsRemoved uint64 `json:"mappings_removed"`
	// SessionsRemoved is the total expired sessions removed.
	SessionsRemoved uint64 `json:"sessions_removed"`
	// PortsReclaimed is the total ports returned to pool.
	PortsReclaimed uint64 `json:"ports_reclaimed"`
	// OrphanedMappingsFound is mappings without sessions.
	OrphanedMappingsFound uint64 `json:"orphaned_mappings_found"`
	// OrphanedSessionsFound is sessions without mappings.
	OrphanedSessionsFound uint64 `json:"orphaned_sessions_found"`
	// LastCleanupTime is the last cleanup execution timestamp.
	LastCleanupTime time.Time `json:"last_cleanup_time"`
	// LastCleanupDuration is the duration of last cleanup.
	LastCleanupDuration time.Duration `json:"last_cleanup_duration"`
	// DatabaseVacuums is the total database vacuum operations.
	DatabaseVacuums uint64 `json:"database_vacuums"`
}

// =============================================================================
// Cleanup Result
// =============================================================================

// CleanupResult contains the result of a manual cleanup.
type CleanupResult struct {
	// MappingsRemoved is expired mappings removed.
	MappingsRemoved int `json:"mappings_removed"`
	// SessionsRemoved is expired sessions removed.
	SessionsRemoved int `json:"sessions_removed"`
	// PortsReclaimed is ports returned to pool.
	PortsReclaimed int `json:"ports_reclaimed"`
	// OrphanedMappings is orphaned mappings found.
	OrphanedMappings int `json:"orphaned_mappings"`
	// OrphanedSessions is orphaned sessions found.
	OrphanedSessions int `json:"orphaned_sessions"`
	// Duration is cleanup execution time.
	Duration time.Duration `json:"duration"`
}

// =============================================================================
// Cleanup Manager
// =============================================================================

// CleanupManager manages NAT cleanup operations.
type CleanupManager struct {
	// NAT components.
	mappingTable   *MappingTable
	sessionTracker *SessionTracker
	portAllocator  *PortAllocator
	// Configuration.
	config *CleanupConfig
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
	// Statistics.
	stats   CleanupStatistics
	statsMu sync.Mutex
}

// NewCleanupManager creates a new cleanup manager.
func NewCleanupManager(
	mappingTable *MappingTable,
	sessionTracker *SessionTracker,
	portAllocator *PortAllocator,
	config *CleanupConfig,
) *CleanupManager {
	if config == nil {
		config = DefaultCleanupConfig()
	}

	return &CleanupManager{
		mappingTable:   mappingTable,
		sessionTracker: sessionTracker,
		portAllocator:  portAllocator,
		config:         config,
		stopChan:       make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the cleanup background tasks.
func (cm *CleanupManager) Start(ctx context.Context) error {
	cm.runningMu.Lock()
	defer cm.runningMu.Unlock()

	if cm.running {
		return nil
	}

	// Start cleanup goroutine.
	cm.wg.Add(1)
	go cm.cleanupLoop()

	// Start vacuum goroutine if enabled.
	if cm.config.EnableDatabaseVacuum {
		cm.wg.Add(1)
		go cm.vacuumLoop()
	}

	cm.running = true
	return nil
}

// Stop stops the cleanup background tasks.
func (cm *CleanupManager) Stop() error {
	cm.runningMu.Lock()
	if !cm.running {
		cm.runningMu.Unlock()
		return nil
	}
	cm.running = false
	cm.runningMu.Unlock()

	close(cm.stopChan)
	cm.wg.Wait()

	return nil
}

// cleanupLoop runs the periodic cleanup task.
func (cm *CleanupManager) cleanupLoop() {
	defer cm.wg.Done()

	ticker := time.NewTicker(cm.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), cm.config.CleanupInterval)
			_ = cm.runCleanup(ctx)
			cancel()
		}
	}
}

// vacuumLoop runs the periodic database vacuum.
func (cm *CleanupManager) vacuumLoop() {
	defer cm.wg.Done()

	ticker := time.NewTicker(cm.config.VacuumInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			_ = cm.runDatabaseVacuum(ctx)
			cancel()
		}
	}
}

// =============================================================================
// Main Cleanup Orchestration
// =============================================================================

// runCleanup executes all cleanup tasks in sequence.
func (cm *CleanupManager) runCleanup(ctx context.Context) error {
	startTime := time.Now()

	var mappingsRemoved, sessionsRemoved, portsReclaimed int
	var orphanedMappings, orphanedSessions int

	// Step 1: Remove expired mappings.
	if cm.mappingTable != nil {
		n, _ := cm.cleanupExpiredMappings(ctx)
		mappingsRemoved = n
	}

	// Step 2: Cleanup expired sessions.
	if cm.sessionTracker != nil {
		n, _ := cm.cleanupExpiredSessions(ctx)
		sessionsRemoved = n
	}

	// Step 3: Cleanup orphaned mappings.
	if cm.mappingTable != nil && cm.sessionTracker != nil {
		n, _ := cm.cleanupOrphanedMappings(ctx)
		orphanedMappings = n
	}

	// Step 4: Cleanup orphaned sessions.
	if cm.sessionTracker != nil && cm.mappingTable != nil {
		n, _ := cm.cleanupOrphanedSessions(ctx)
		orphanedSessions = n
	}

	// Step 5: Reclaim ports.
	if cm.config.EnablePortReclamation && cm.portAllocator != nil {
		n, _ := cm.reclaimUnusedPorts(ctx)
		portsReclaimed = n
	}

	// Step 6: Sync with Rust translator.
	_ = cm.syncWithRustTranslator(ctx)

	// Update statistics.
	duration := time.Since(startTime)
	cm.updateStats(mappingsRemoved, sessionsRemoved, portsReclaimed, orphanedMappings, orphanedSessions, duration)

	return nil
}

// =============================================================================
// Cleanup Operations
// =============================================================================

// cleanupExpiredMappings removes expired NAT mappings.
func (cm *CleanupManager) cleanupExpiredMappings(ctx context.Context) (int, error) {
	if cm.mappingTable == nil {
		return 0, nil
	}

	count, err := cm.mappingTable.DeleteExpiredMappings(ctx)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// cleanupExpiredSessions removes expired sessions.
func (cm *CleanupManager) cleanupExpiredSessions(ctx context.Context) (int, error) {
	_ = ctx // Reserved for future use when session tracker supports context.
	if cm.sessionTracker == nil {
		return 0, nil
	}

	// Get session count before timeout check.
	before := cm.sessionTracker.GetSessionCount()

	// Trigger timeout check (this happens automatically but we can force it).
	// The session tracker already runs its own timeout loop.

	// Get session count after.
	after := cm.sessionTracker.GetSessionCount()

	return before - after, nil
}

// cleanupOrphanedMappings finds and removes mappings without sessions.
func (cm *CleanupManager) cleanupOrphanedMappings(ctx context.Context) (int, error) {
	if cm.mappingTable == nil || cm.sessionTracker == nil {
		return 0, nil
	}

	// Get all active mappings.
	mappings, err := cm.mappingTable.ListMappings(ctx, &MappingFilters{OnlyActive: true}, nil)
	if err != nil {
		return 0, err
	}

	orphanCount := 0
	for _, mapping := range mappings {
		// Check if session exists.
		_, err := cm.sessionTracker.GetSession(ctx, mapping.MappingID)
		if err == ErrSessionNotFound {
			// Orphaned mapping - no corresponding session.
			// Only cleanup if mapping is old enough.
			if time.Since(mapping.CreatedAt) > cm.config.OrphanedSessionThreshold {
				_ = cm.mappingTable.DeleteMapping(ctx, mapping.MappingID)
				orphanCount++
			}
		}
	}

	return orphanCount, nil
}

// cleanupOrphanedSessions finds and removes sessions without mappings.
func (cm *CleanupManager) cleanupOrphanedSessions(ctx context.Context) (int, error) {
	if cm.sessionTracker == nil || cm.mappingTable == nil {
		return 0, nil
	}

	// Get all sessions.
	sessions, err := cm.sessionTracker.ListSessions(ctx, nil)
	if err != nil {
		return 0, err
	}

	orphanCount := 0
	for _, session := range sessions {
		// Check if mapping exists.
		_, err := cm.mappingTable.GetMappingByID(ctx, session.MappingID)
		if err == ErrMappingNotFound {
			// Orphaned session - no corresponding mapping.
			_ = cm.sessionTracker.RemoveSession(ctx, session.MappingID)
			orphanCount++
		}
	}

	return orphanCount, nil
}

// reclaimUnusedPorts reclaims ports from deleted mappings.
func (cm *CleanupManager) reclaimUnusedPorts(ctx context.Context) (int, error) {
	// Port reclamation would involve tracking recently deleted mappings
	// and releasing their ports. For now, this is a stub.
	_ = ctx
	return 0, nil
}

// runDatabaseVacuum performs database maintenance.
func (cm *CleanupManager) runDatabaseVacuum(ctx context.Context) error {
	// Database vacuum would execute VACUUM ANALYZE.
	// This requires direct database access.
	_ = ctx

	cm.statsMu.Lock()
	cm.stats.DatabaseVacuums++
	cm.statsMu.Unlock()

	return nil
}

// syncWithRustTranslator syncs cleanup with Rust NAT translator.
func (cm *CleanupManager) syncWithRustTranslator(ctx context.Context) error {
	// TODO: Call Rust FFI rust_cleanup_expired_mappings().
	_ = ctx
	return nil
}

// =============================================================================
// Manual Cleanup
// =============================================================================

// TriggerManualCleanup executes an immediate cleanup.
func (cm *CleanupManager) TriggerManualCleanup(ctx context.Context) (*CleanupResult, error) {
	startTime := time.Now()

	var result CleanupResult

	// Run cleanup steps.
	if cm.mappingTable != nil {
		n, _ := cm.cleanupExpiredMappings(ctx)
		result.MappingsRemoved = n
	}

	if cm.sessionTracker != nil {
		n, _ := cm.cleanupExpiredSessions(ctx)
		result.SessionsRemoved = n
	}

	if cm.mappingTable != nil && cm.sessionTracker != nil {
		n, _ := cm.cleanupOrphanedMappings(ctx)
		result.OrphanedMappings = n

		n, _ = cm.cleanupOrphanedSessions(ctx)
		result.OrphanedSessions = n
	}

	if cm.config.EnablePortReclamation && cm.portAllocator != nil {
		n, _ := cm.reclaimUnusedPorts(ctx)
		result.PortsReclaimed = n
	}

	result.Duration = time.Since(startTime)

	// Update statistics.
	cm.updateStats(
		result.MappingsRemoved,
		result.SessionsRemoved,
		result.PortsReclaimed,
		result.OrphanedMappings,
		result.OrphanedSessions,
		result.Duration,
	)

	return &result, nil
}

// =============================================================================
// Aggressive Cleanup
// =============================================================================

// TriggerAggressiveCleanup runs more frequent cleanup under pressure.
func (cm *CleanupManager) TriggerAggressiveCleanup(ctx context.Context) error {
	if !cm.config.EnableAggressiveCleanup {
		return nil
	}

	// Run cleanup immediately.
	return cm.runCleanup(ctx)
}

// GetResourcePressure evaluates current resource pressure.
func (cm *CleanupManager) GetResourcePressure() ResourcePressure {
	// Evaluate pressure based on port utilization.
	if cm.portAllocator != nil {
		stats, _ := cm.portAllocator.GetPortAllocationStats(context.Background())
		if stats != nil {
			if stats.UtilizationPercent > 90 {
				return PressureHigh
			} else if stats.UtilizationPercent > 70 {
				return PressureMedium
			}
		}
	}

	return PressureLow
}

// =============================================================================
// Statistics
// =============================================================================

// updateStats updates cleanup statistics.
func (cm *CleanupManager) updateStats(mappings, sessions, ports, orphanMappings, orphanSessions int, duration time.Duration) {
	cm.statsMu.Lock()
	defer cm.statsMu.Unlock()

	cm.stats.TotalCleanupRuns++
	cm.stats.MappingsRemoved += uint64(mappings)
	cm.stats.SessionsRemoved += uint64(sessions)
	cm.stats.PortsReclaimed += uint64(ports)
	cm.stats.OrphanedMappingsFound += uint64(orphanMappings)
	cm.stats.OrphanedSessionsFound += uint64(orphanSessions)
	cm.stats.LastCleanupTime = time.Now()
	cm.stats.LastCleanupDuration = duration
}

// GetStatistics returns cleanup statistics.
func (cm *CleanupManager) GetStatistics() CleanupStatistics {
	cm.statsMu.Lock()
	defer cm.statsMu.Unlock()
	return cm.stats
}

// ResetStatistics resets cleanup statistics.
func (cm *CleanupManager) ResetStatistics() {
	cm.statsMu.Lock()
	defer cm.statsMu.Unlock()

	lastTime := cm.stats.LastCleanupTime
	lastDuration := cm.stats.LastCleanupDuration

	cm.stats = CleanupStatistics{}
	cm.stats.LastCleanupTime = lastTime
	cm.stats.LastCleanupDuration = lastDuration
}

// =============================================================================
// Validation
// =============================================================================

// ValidateCleanup checks cleanup consistency.
func (cm *CleanupManager) ValidateCleanup(ctx context.Context) error {
	if cm.mappingTable == nil || cm.sessionTracker == nil {
		return nil
	}

	// Get counts.
	mappingCount, _ := cm.mappingTable.CountMappings(ctx, &MappingFilters{OnlyActive: true})
	sessionCount := cm.sessionTracker.GetSessionCount()

	// Counts should be similar (allow some variance due to timing).
	diff := mappingCount - sessionCount
	if diff < 0 {
		diff = -diff
	}

	// Allow up to 10% variance.
	threshold := mappingCount / 10
	if threshold < 5 {
		threshold = 5
	}

	if diff > threshold {
		return ErrOrphanDetectionFailed
	}

	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the cleanup system is functioning.
func (cm *CleanupManager) HealthCheck() error {
	cm.runningMu.Lock()
	running := cm.running
	cm.runningMu.Unlock()

	if !running {
		return ErrCleanupFailed
	}

	// Check last cleanup was recent.
	cm.statsMu.Lock()
	lastTime := cm.stats.LastCleanupTime
	cm.statsMu.Unlock()

	if !lastTime.IsZero() {
		maxAge := 2 * cm.config.CleanupInterval
		if time.Since(lastTime) > maxAge {
			return ErrCleanupFailed
		}
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// GetConfig returns the current configuration.
func (cm *CleanupManager) GetConfig() *CleanupConfig {
	return cm.config
}

// IsRunning returns whether cleanup is running.
func (cm *CleanupManager) IsRunning() bool {
	cm.runningMu.Lock()
	defer cm.runningMu.Unlock()
	return cm.running
}
