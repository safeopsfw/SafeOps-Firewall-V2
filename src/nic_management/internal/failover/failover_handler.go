// Package failover provides WAN failover management for the NIC Management service.
package failover

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

var (
	// ErrFailoverActive indicates a failover is already in progress.
	ErrFailoverActive = errors.New("failover already in progress")
	// ErrBackupUnhealthy indicates backup WAN health is below threshold.
	ErrBackupUnhealthy = errors.New("backup WAN health below threshold")
	// ErrBackupUnavailable indicates backup WAN is not in ENABLED state.
	ErrBackupUnavailable = errors.New("backup WAN not available")
	// ErrFlowReassignmentFailed indicates flow migration failed.
	ErrFlowReassignmentFailed = errors.New("flow reassignment failed")
	// ErrNATMigrationFailed indicates NAT mapping migration failed.
	ErrNATMigrationFailed = errors.New("NAT migration failed")
	// ErrRoutingUpdateFailed indicates routing table update failed.
	ErrRoutingUpdateFailed = errors.New("routing table update failed")
	// ErrServiceNotificationFailed indicates service notification failed.
	ErrServiceNotificationFailed = errors.New("service notification failed")
	// ErrFailoverTimeout indicates failover exceeded timeout.
	ErrFailoverTimeout = errors.New("failover execution timeout")
	// ErrFailoverRollbackFailed indicates rollback operation failed.
	ErrFailoverRollbackFailed = errors.New("failover rollback failed")
	// ErrNoFailoverActive indicates no failover is in progress.
	ErrNoFailoverActive = errors.New("no failover currently active")
	// ErrInvalidWAN indicates invalid WAN identifier.
	ErrInvalidWAN = errors.New("invalid WAN identifier")
)

// =============================================================================
// Failover Phase
// =============================================================================

// FailoverPhase represents the current phase of failover execution.
type FailoverPhase int

const (
	// FailoverPhaseInit is initialization and validation.
	FailoverPhaseInit FailoverPhase = iota
	// FailoverPhaseValidateBackup verifies backup WAN is healthy.
	FailoverPhaseValidateBackup
	// FailoverPhaseDrainConnections gracefully closes existing connections.
	FailoverPhaseDrainConnections
	// FailoverPhaseReassignFlows moves flows to backup WAN.
	FailoverPhaseReassignFlows
	// FailoverPhaseMigrateNAT updates NAT mappings for backup.
	FailoverPhaseMigrateNAT
	// FailoverPhaseUpdateRouting modifies system routing table.
	FailoverPhaseUpdateRouting
	// FailoverPhaseNotifyServices publishes failover events.
	FailoverPhaseNotifyServices
	// FailoverPhaseComplete indicates failover finished successfully.
	FailoverPhaseComplete
	// FailoverPhaseFailed indicates failover failed.
	FailoverPhaseFailed
)

// String returns the string representation of the phase.
func (p FailoverPhase) String() string {
	switch p {
	case FailoverPhaseInit:
		return "INIT"
	case FailoverPhaseValidateBackup:
		return "VALIDATE_BACKUP"
	case FailoverPhaseDrainConnections:
		return "DRAIN_CONNECTIONS"
	case FailoverPhaseReassignFlows:
		return "REASSIGN_FLOWS"
	case FailoverPhaseMigrateNAT:
		return "MIGRATE_NAT"
	case FailoverPhaseUpdateRouting:
		return "UPDATE_ROUTING"
	case FailoverPhaseNotifyServices:
		return "NOTIFY_SERVICES"
	case FailoverPhaseComplete:
		return "COMPLETE"
	case FailoverPhaseFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Failover Outcome
// =============================================================================

// FailoverOutcome represents the result of a failover operation.
type FailoverOutcome int

const (
	// FailoverOutcomeSuccess indicates failover completed fully.
	FailoverOutcomeSuccess FailoverOutcome = iota
	// FailoverOutcomePartialSuccess indicates failover mostly succeeded with some errors.
	FailoverOutcomePartialSuccess
	// FailoverOutcomeFailure indicates failover failed.
	FailoverOutcomeFailure
	// FailoverOutcomeTimeout indicates failover exceeded timeout.
	FailoverOutcomeTimeout
)

// String returns the string representation of the outcome.
func (o FailoverOutcome) String() string {
	switch o {
	case FailoverOutcomeSuccess:
		return "SUCCESS"
	case FailoverOutcomePartialSuccess:
		return "PARTIAL_SUCCESS"
	case FailoverOutcomeFailure:
		return "FAILURE"
	case FailoverOutcomeTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Failover Configuration
// =============================================================================

// FailoverConfig contains configuration for the failover handler.
type FailoverConfig struct {
	// ExecutionTimeout is max time for complete failover (default: 30s).
	ExecutionTimeout time.Duration `json:"execution_timeout"`
	// ConnectionDrainTimeout is max time for graceful connection drain (default: 10s).
	ConnectionDrainTimeout time.Duration `json:"connection_drain_timeout"`
	// NATMigrationBatchSize is NAT mappings to migrate per batch (default: 1000).
	NATMigrationBatchSize int `json:"nat_migration_batch_size"`
	// EnableGracefulDrain allows existing connections to complete (default: true).
	EnableGracefulDrain bool `json:"enable_graceful_drain"`
	// ForceTerminateAfterTimeout force-closes connections exceeding drain timeout (default: true).
	ForceTerminateAfterTimeout bool `json:"force_terminate_after_timeout"`
	// UpdateRoutingTable modifies system routing table (default: true).
	UpdateRoutingTable bool `json:"update_routing_table"`
	// EnableNATMigration migrates NAT mappings to backup WAN (default: true).
	EnableNATMigration bool `json:"enable_nat_migration"`
	// NotifyDependentServices publishes failover events to event bus (default: true).
	NotifyDependentServices bool `json:"notify_dependent_services"`
	// ValidateBackupHealth checks backup WAN health before failover (default: true).
	ValidateBackupHealth bool `json:"validate_backup_health"`
	// MinBackupHealthScore is minimum backup health to proceed (default: 60.0).
	MinBackupHealthScore float64 `json:"min_backup_health_score"`
	// RollbackOnFailure reverts to primary if failover fails (default: false).
	RollbackOnFailure bool `json:"rollback_on_failure"`
	// MaxConcurrentFlowMigrations is parallel flow reassignments (default: 100).
	MaxConcurrentFlowMigrations int `json:"max_concurrent_flow_migrations"`
}

// DefaultFailoverConfig returns the default failover configuration.
func DefaultFailoverConfig() *FailoverConfig {
	return &FailoverConfig{
		ExecutionTimeout:            30 * time.Second,
		ConnectionDrainTimeout:      10 * time.Second,
		NATMigrationBatchSize:       1000,
		EnableGracefulDrain:         true,
		ForceTerminateAfterTimeout:  true,
		UpdateRoutingTable:          true,
		EnableNATMigration:          true,
		NotifyDependentServices:     true,
		ValidateBackupHealth:        true,
		MinBackupHealthScore:        60.0,
		RollbackOnFailure:           false,
		MaxConcurrentFlowMigrations: 100,
	}
}

// =============================================================================
// Failover Execution
// =============================================================================

// FailoverExecution tracks the state of an active failover operation.
type FailoverExecution struct {
	// ExecutionID is unique execution identifier.
	ExecutionID string `json:"execution_id"`
	// PrimaryWAN is the WAN failing over from.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is the WAN failing over to.
	BackupWAN string `json:"backup_wan"`
	// TriggerReason is why failover was triggered.
	TriggerReason string `json:"trigger_reason"`
	// StartTime is when failover started.
	StartTime time.Time `json:"start_time"`
	// Phase is current execution phase.
	Phase FailoverPhase `json:"phase"`
	// FlowsReassigned is flows migrated to backup.
	FlowsReassigned int `json:"flows_reassigned"`
	// NATMappingsMigrated is NAT entries updated.
	NATMappingsMigrated int `json:"nat_mappings_migrated"`
	// RoutingTableUpdated indicates whether routing was modified.
	RoutingTableUpdated bool `json:"routing_table_updated"`
	// ConnectionsDrained is connections gracefully closed.
	ConnectionsDrained int `json:"connections_drained"`
	// ConnectionsTerminated is connections force-closed.
	ConnectionsTerminated int `json:"connections_terminated"`
	// Errors contains errors encountered during execution.
	Errors []string `json:"errors,omitempty"`
	// IsComplete indicates whether failover finished.
	IsComplete bool `json:"is_complete"`
	// cancelFunc for context cancellation.
	cancelFunc context.CancelFunc `json:"-"`
}

// =============================================================================
// Failover Event
// =============================================================================

// FailoverEvent is a record of a completed failover operation.
type FailoverEvent struct {
	// EventID is unique event identifier.
	EventID string `json:"event_id"`
	// PrimaryWAN is the WAN that failed.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is the WAN that took over.
	BackupWAN string `json:"backup_wan"`
	// TriggerReason is why failover occurred.
	TriggerReason string `json:"trigger_reason"`
	// StartTime is when failover started.
	StartTime time.Time `json:"start_time"`
	// EndTime is when failover completed.
	EndTime time.Time `json:"end_time"`
	// Duration is total failover time.
	Duration time.Duration `json:"duration"`
	// Outcome is the result of the failover.
	Outcome FailoverOutcome `json:"outcome"`
	// FlowsReassigned is total flows migrated.
	FlowsReassigned int `json:"flows_reassigned"`
	// NATMappingsMigrated is total NAT entries updated.
	NATMappingsMigrated int `json:"nat_mappings_migrated"`
	// ConnectionsDrained is connections gracefully closed.
	ConnectionsDrained int `json:"connections_drained"`
	// ConnectionsTerminated is connections force-closed.
	ConnectionsTerminated int `json:"connections_terminated"`
	// RoutingTableUpdated indicates whether routing was modified.
	RoutingTableUpdated bool `json:"routing_table_updated"`
	// PrimaryHealthAtFailover is primary WAN health when failed.
	PrimaryHealthAtFailover float64 `json:"primary_health_at_failover"`
	// BackupHealthAtFailover is backup WAN health at takeover.
	BackupHealthAtFailover float64 `json:"backup_health_at_failover"`
	// ErrorMessages contains errors encountered.
	ErrorMessages []string `json:"error_messages,omitempty"`
}

// =============================================================================
// Failover Statistics
// =============================================================================

// FailoverStatistics contains failover performance metrics.
type FailoverStatistics struct {
	// TotalFailovers is total failover attempts in duration.
	TotalFailovers int `json:"total_failovers"`
	// SuccessfulFailovers is failovers completed successfully.
	SuccessfulFailovers int `json:"successful_failovers"`
	// PartialFailovers is failovers with some errors.
	PartialFailovers int `json:"partial_failovers"`
	// FailedFailovers is failovers that failed completely.
	FailedFailovers int `json:"failed_failovers"`
	// AverageDuration is mean failover time.
	AverageDuration time.Duration `json:"average_duration"`
	// MedianDuration is median failover time.
	MedianDuration time.Duration `json:"median_duration"`
	// P95Duration is 95th percentile duration.
	P95Duration time.Duration `json:"p95_duration"`
	// FastestFailover is minimum duration observed.
	FastestFailover time.Duration `json:"fastest_failover"`
	// SlowestFailover is maximum duration observed.
	SlowestFailover time.Duration `json:"slowest_failover"`
	// SuccessRate is (Successful / Total) × 100.
	SuccessRate float64 `json:"success_rate"`
	// TotalFlowsReassigned is cumulative flows migrated.
	TotalFlowsReassigned int `json:"total_flows_reassigned"`
	// TotalNATMigrations is cumulative NAT mappings updated.
	TotalNATMigrations int `json:"total_nat_migrations"`
}

// =============================================================================
// Phase Timing
// =============================================================================

// PhaseTiming tracks execution time for each phase.
type PhaseTiming struct {
	Phase     FailoverPhase `json:"phase"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
}

// =============================================================================
// Handler Dependencies Interface
// =============================================================================

// TrafficDistributorInterface defines traffic distributor operations needed by failover.
type TrafficDistributorInterface interface {
	// GetFlowsByWAN returns all flows assigned to a WAN.
	GetFlowsByWAN(ctx context.Context, wanID string) ([]string, error)
	// PreemptFlow moves a flow to a different WAN.
	PreemptFlow(ctx context.Context, flowID string, targetWAN string, reason string) error
	// MarkFlowDraining marks a flow as draining (no new packets).
	MarkFlowDraining(ctx context.Context, flowID string) error
	// TerminateFlow force-closes a flow.
	TerminateFlow(ctx context.Context, flowID string) error
}

// NATTranslatorInterface defines NAT translator operations needed by failover.
type NATTranslatorInterface interface {
	// GetMappingsByWAN returns all NAT mappings for a WAN.
	GetMappingsByWAN(ctx context.Context, wanID string) ([]string, error)
	// MigrateMapping updates a NAT mapping to use a different WAN.
	MigrateMapping(ctx context.Context, mappingID string, targetWAN string) error
}

// RoutingEngineInterface defines routing engine operations needed by failover.
type RoutingEngineInterface interface {
	// UpdateDefaultRoute changes the default route to use the specified WAN.
	UpdateDefaultRoute(ctx context.Context, wanID string) error
	// GetCurrentDefaultRoute returns the current default route WAN.
	GetCurrentDefaultRoute(ctx context.Context) (string, error)
}

// WANSelectorInterface defines WAN selector operations needed by failover.
type WANSelectorInterface interface {
	// GetWANHealth returns the health score for a WAN.
	GetWANHealth(ctx context.Context, wanID string) (float64, error)
	// GetWANState returns the state of a WAN.
	GetWANState(ctx context.Context, wanID string) (string, error)
	// WANExists checks if a WAN exists.
	WANExists(wanID string) bool
}

// FailoverDBInterface defines database operations for failover events.
type FailoverDBInterface interface {
	// LoadFailoverHistory loads recent failover events.
	LoadFailoverHistory(ctx context.Context, limit int) ([]*FailoverEvent, error)
	// SaveFailoverEvent saves a failover event.
	SaveFailoverEvent(ctx context.Context, event *FailoverEvent) error
}

// EventPublisherInterface defines event publishing operations.
type EventPublisherInterface interface {
	// PublishFailoverEvent publishes a failover notification.
	PublishFailoverEvent(ctx context.Context, primaryWAN, backupWAN, reason string) error
}

// =============================================================================
// No-Op Implementations
// =============================================================================

type noOpTrafficDistributor struct{}

func (n *noOpTrafficDistributor) GetFlowsByWAN(ctx context.Context, wanID string) ([]string, error) {
	return nil, nil
}
func (n *noOpTrafficDistributor) PreemptFlow(ctx context.Context, flowID string, targetWAN string, reason string) error {
	return nil
}
func (n *noOpTrafficDistributor) MarkFlowDraining(ctx context.Context, flowID string) error {
	return nil
}
func (n *noOpTrafficDistributor) TerminateFlow(ctx context.Context, flowID string) error {
	return nil
}

type noOpNATTranslator struct{}

func (n *noOpNATTranslator) GetMappingsByWAN(ctx context.Context, wanID string) ([]string, error) {
	return nil, nil
}
func (n *noOpNATTranslator) MigrateMapping(ctx context.Context, mappingID string, targetWAN string) error {
	return nil
}

type noOpRoutingEngine struct{}

func (n *noOpRoutingEngine) UpdateDefaultRoute(ctx context.Context, wanID string) error {
	return nil
}
func (n *noOpRoutingEngine) GetCurrentDefaultRoute(ctx context.Context) (string, error) {
	return "", nil
}

type noOpWANSelector struct{}

func (n *noOpWANSelector) GetWANHealth(ctx context.Context, wanID string) (float64, error) {
	return 100.0, nil
}
func (n *noOpWANSelector) GetWANState(ctx context.Context, wanID string) (string, error) {
	return "ENABLED", nil
}
func (n *noOpWANSelector) WANExists(wanID string) bool {
	return true
}

type noOpFailoverDB struct{}

func (n *noOpFailoverDB) LoadFailoverHistory(ctx context.Context, limit int) ([]*FailoverEvent, error) {
	return nil, nil
}
func (n *noOpFailoverDB) SaveFailoverEvent(ctx context.Context, event *FailoverEvent) error {
	return nil
}

type noOpEventPublisher struct{}

func (n *noOpEventPublisher) PublishFailoverEvent(ctx context.Context, primaryWAN, backupWAN, reason string) error {
	return nil
}

// =============================================================================
// UUID Generation
// =============================================================================

// generateFailoverUUID generates a UUID v4 for failover operations.
func generateFailoverUUID() string {
	uuid := make([]byte, 16)
	_, _ = rand.Read(uuid)
	// Set version (4) and variant (10) bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// =============================================================================
// Failover Handler
// =============================================================================

// FailoverHandler manages failover execution workflow.
type FailoverHandler struct {
	// Dependencies.
	trafficDistributor TrafficDistributorInterface
	natTranslator      NATTranslatorInterface
	routingEngine      RoutingEngineInterface
	wanSelector        WANSelectorInterface
	db                 FailoverDBInterface
	eventPublisher     EventPublisherInterface

	// Configuration.
	config *FailoverConfig

	// Current failover state.
	currentFailover *FailoverExecution
	mu              sync.RWMutex

	// Failover history.
	failoverHistory   []*FailoverEvent
	failoverHistoryMu sync.RWMutex

	// Statistics.
	totalAttempts      uint64
	successfulAttempts uint64
	failedAttempts     uint64

	// Phase timing for current execution.
	phaseTimings   []PhaseTiming
	phaseTimingsMu sync.Mutex

	// Control.
	stopChan chan struct{}
	running  bool
}

// NewFailoverHandler creates a new failover handler.
func NewFailoverHandler(
	trafficDistributor TrafficDistributorInterface,
	natTranslator NATTranslatorInterface,
	routingEngine RoutingEngineInterface,
	wanSelector WANSelectorInterface,
	db FailoverDBInterface,
	eventPublisher EventPublisherInterface,
	config *FailoverConfig,
) *FailoverHandler {
	if config == nil {
		config = DefaultFailoverConfig()
	}

	if trafficDistributor == nil {
		trafficDistributor = &noOpTrafficDistributor{}
	}
	if natTranslator == nil {
		natTranslator = &noOpNATTranslator{}
	}
	if routingEngine == nil {
		routingEngine = &noOpRoutingEngine{}
	}
	if wanSelector == nil {
		wanSelector = &noOpWANSelector{}
	}
	if db == nil {
		db = &noOpFailoverDB{}
	}
	if eventPublisher == nil {
		eventPublisher = &noOpEventPublisher{}
	}

	return &FailoverHandler{
		trafficDistributor: trafficDistributor,
		natTranslator:      natTranslator,
		routingEngine:      routingEngine,
		wanSelector:        wanSelector,
		db:                 db,
		eventPublisher:     eventPublisher,
		config:             config,
		failoverHistory:    make([]*FailoverEvent, 0, 100),
		phaseTimings:       make([]PhaseTiming, 0, 9),
		stopChan:           make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start initializes the failover handler.
func (fh *FailoverHandler) Start(ctx context.Context) error {
	// Load failover history from database.
	history, err := fh.db.LoadFailoverHistory(ctx, 100)
	if err != nil {
		// Log warning but continue.
		_ = err
	} else if history != nil {
		fh.failoverHistoryMu.Lock()
		fh.failoverHistory = history
		fh.failoverHistoryMu.Unlock()
	}

	// Validate configuration.
	if fh.config.ExecutionTimeout <= 0 {
		fh.config.ExecutionTimeout = 30 * time.Second
	}
	if fh.config.MinBackupHealthScore < 0 || fh.config.MinBackupHealthScore > 100 {
		fh.config.MinBackupHealthScore = 60.0
	}
	if fh.config.MaxConcurrentFlowMigrations <= 0 {
		fh.config.MaxConcurrentFlowMigrations = 100
	}

	fh.running = true
	return nil
}

// Stop shuts down the failover handler.
func (fh *FailoverHandler) Stop() error {
	fh.running = false

	// Check if failover is active.
	fh.mu.RLock()
	activeFailover := fh.currentFailover
	fh.mu.RUnlock()

	if activeFailover != nil {
		// Wait for active failover to complete (up to 60s).
		timeout := time.After(60 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				return ErrFailoverTimeout
			case <-ticker.C:
				fh.mu.RLock()
				if fh.currentFailover == nil || fh.currentFailover.IsComplete {
					fh.mu.RUnlock()
					return nil
				}
				fh.mu.RUnlock()
			}
		}
	}

	close(fh.stopChan)
	return nil
}

// =============================================================================
// Execute Failover
// =============================================================================

// ExecuteFailover executes a complete failover from primary to backup WAN.
func (fh *FailoverHandler) ExecuteFailover(ctx context.Context, primaryWAN string, backupWAN string, triggerReason string) (*FailoverEvent, error) {
	// Acquire lock and validate preconditions.
	fh.mu.Lock()
	if fh.currentFailover != nil && !fh.currentFailover.IsComplete {
		fh.mu.Unlock()
		return nil, ErrFailoverActive
	}

	// Validate WANs.
	if primaryWAN == "" || backupWAN == "" {
		fh.mu.Unlock()
		return nil, ErrInvalidWAN
	}
	if primaryWAN == backupWAN {
		fh.mu.Unlock()
		return nil, fmt.Errorf("%w: primary and backup WAN cannot be the same", ErrInvalidWAN)
	}
	if !fh.wanSelector.WANExists(primaryWAN) {
		fh.mu.Unlock()
		return nil, fmt.Errorf("%w: primary WAN %s not found", ErrInvalidWAN, primaryWAN)
	}
	if !fh.wanSelector.WANExists(backupWAN) {
		fh.mu.Unlock()
		return nil, fmt.Errorf("%w: backup WAN %s not found", ErrInvalidWAN, backupWAN)
	}

	// Create execution context with timeout.
	execCtx, cancel := context.WithTimeout(ctx, fh.config.ExecutionTimeout)

	// Initialize execution.
	execution := &FailoverExecution{
		ExecutionID:   generateFailoverUUID(),
		PrimaryWAN:    primaryWAN,
		BackupWAN:     backupWAN,
		TriggerReason: triggerReason,
		StartTime:     time.Now(),
		Phase:         FailoverPhaseInit,
		Errors:        make([]string, 0),
		cancelFunc:    cancel,
	}

	fh.currentFailover = execution
	fh.phaseTimings = make([]PhaseTiming, 0, 9)
	fh.mu.Unlock()

	atomic.AddUint64(&fh.totalAttempts, 1)

	// Execute failover phases.
	event, err := fh.executeFailoverPhases(execCtx, execution)

	// Cleanup.
	cancel()

	fh.mu.Lock()
	fh.currentFailover.IsComplete = true
	fh.mu.Unlock()

	// Persist event.
	if event != nil {
		_ = fh.db.SaveFailoverEvent(ctx, event)

		// Add to history.
		fh.failoverHistoryMu.Lock()
		fh.failoverHistory = append(fh.failoverHistory, event)
		if len(fh.failoverHistory) > 100 {
			fh.failoverHistory = fh.failoverHistory[len(fh.failoverHistory)-100:]
		}
		fh.failoverHistoryMu.Unlock()
	}

	return event, err
}

// executeFailoverPhases runs through all failover phases.
func (fh *FailoverHandler) executeFailoverPhases(ctx context.Context, execution *FailoverExecution) (*FailoverEvent, error) {
	var primaryHealth, backupHealth float64

	// Phase 1: Validate Backup.
	fh.startPhase(execution, FailoverPhaseValidateBackup)
	if fh.config.ValidateBackupHealth {
		var err error
		backupHealth, err = fh.wanSelector.GetWANHealth(ctx, execution.BackupWAN)
		if err != nil {
			execution.Errors = append(execution.Errors, fmt.Sprintf("failed to get backup health: %v", err))
			return fh.failFailover(execution, primaryHealth, backupHealth), ErrBackupUnhealthy
		}
		if backupHealth < fh.config.MinBackupHealthScore {
			execution.Errors = append(execution.Errors, fmt.Sprintf("backup health %.2f below threshold %.2f", backupHealth, fh.config.MinBackupHealthScore))
			return fh.failFailover(execution, primaryHealth, backupHealth), ErrBackupUnhealthy
		}

		state, err := fh.wanSelector.GetWANState(ctx, execution.BackupWAN)
		if err != nil || (state != "ENABLED" && state != "DEGRADED") {
			execution.Errors = append(execution.Errors, fmt.Sprintf("backup WAN state invalid: %s", state))
			return fh.failFailover(execution, primaryHealth, backupHealth), ErrBackupUnavailable
		}
	}
	fh.endPhase(execution, FailoverPhaseValidateBackup)

	// Get primary health for metrics.
	primaryHealth, _ = fh.wanSelector.GetWANHealth(ctx, execution.PrimaryWAN)

	// Check context.
	if err := ctx.Err(); err != nil {
		execution.Errors = append(execution.Errors, "execution timeout")
		return fh.failFailover(execution, primaryHealth, backupHealth), ErrFailoverTimeout
	}

	// Phase 2: Drain Connections.
	fh.startPhase(execution, FailoverPhaseDrainConnections)
	if fh.config.EnableGracefulDrain {
		drained, terminated, err := fh.drainConnections(ctx, execution)
		execution.ConnectionsDrained = drained
		execution.ConnectionsTerminated = terminated
		if err != nil {
			execution.Errors = append(execution.Errors, fmt.Sprintf("drain error: %v", err))
		}
	}
	fh.endPhase(execution, FailoverPhaseDrainConnections)

	// Check context.
	if err := ctx.Err(); err != nil {
		execution.Errors = append(execution.Errors, "execution timeout")
		return fh.failFailover(execution, primaryHealth, backupHealth), ErrFailoverTimeout
	}

	// Phase 3: Reassign Flows.
	fh.startPhase(execution, FailoverPhaseReassignFlows)
	reassigned, err := fh.reassignFlows(ctx, execution)
	execution.FlowsReassigned = reassigned
	if err != nil {
		execution.Errors = append(execution.Errors, fmt.Sprintf("flow reassignment error: %v", err))
		if fh.config.RollbackOnFailure {
			_ = fh.rollbackFailover(ctx, execution)
		}
		return fh.failFailover(execution, primaryHealth, backupHealth), ErrFlowReassignmentFailed
	}
	fh.endPhase(execution, FailoverPhaseReassignFlows)

	// Check context.
	if err := ctx.Err(); err != nil {
		execution.Errors = append(execution.Errors, "execution timeout")
		if fh.config.RollbackOnFailure {
			_ = fh.rollbackFailover(ctx, execution)
		}
		return fh.failFailover(execution, primaryHealth, backupHealth), ErrFailoverTimeout
	}

	// Phase 4: Migrate NAT.
	fh.startPhase(execution, FailoverPhaseMigrateNAT)
	if fh.config.EnableNATMigration {
		migrated, err := fh.migrateNAT(ctx, execution)
		execution.NATMappingsMigrated = migrated
		if err != nil {
			execution.Errors = append(execution.Errors, fmt.Sprintf("NAT migration error: %v", err))
		}
	}
	fh.endPhase(execution, FailoverPhaseMigrateNAT)

	// Phase 5: Update Routing.
	fh.startPhase(execution, FailoverPhaseUpdateRouting)
	if fh.config.UpdateRoutingTable {
		err := fh.routingEngine.UpdateDefaultRoute(ctx, execution.BackupWAN)
		if err != nil {
			execution.Errors = append(execution.Errors, fmt.Sprintf("routing update error: %v", err))
		} else {
			execution.RoutingTableUpdated = true
		}
	}
	fh.endPhase(execution, FailoverPhaseUpdateRouting)

	// Phase 6: Notify Services.
	fh.startPhase(execution, FailoverPhaseNotifyServices)
	if fh.config.NotifyDependentServices {
		err := fh.eventPublisher.PublishFailoverEvent(ctx, execution.PrimaryWAN, execution.BackupWAN, execution.TriggerReason)
		if err != nil {
			execution.Errors = append(execution.Errors, fmt.Sprintf("service notification error: %v", err))
		}
	}
	fh.endPhase(execution, FailoverPhaseNotifyServices)

	// Complete.
	return fh.completeFailover(execution, primaryHealth, backupHealth), nil
}

// =============================================================================
// Phase Helpers
// =============================================================================

// startPhase records the start of a phase.
func (fh *FailoverHandler) startPhase(execution *FailoverExecution, phase FailoverPhase) {
	fh.mu.Lock()
	execution.Phase = phase
	fh.mu.Unlock()

	fh.phaseTimingsMu.Lock()
	fh.phaseTimings = append(fh.phaseTimings, PhaseTiming{
		Phase:     phase,
		StartTime: time.Now(),
	})
	fh.phaseTimingsMu.Unlock()
}

// endPhase records the end of a phase.
func (fh *FailoverHandler) endPhase(_ *FailoverExecution, phase FailoverPhase) {
	fh.phaseTimingsMu.Lock()
	for i := len(fh.phaseTimings) - 1; i >= 0; i-- {
		if fh.phaseTimings[i].Phase == phase {
			fh.phaseTimings[i].EndTime = time.Now()
			fh.phaseTimings[i].Duration = fh.phaseTimings[i].EndTime.Sub(fh.phaseTimings[i].StartTime)
			break
		}
	}
	fh.phaseTimingsMu.Unlock()
}

// =============================================================================
// Drain Connections
// =============================================================================

// drainConnections gracefully drains connections on the primary WAN.
func (fh *FailoverHandler) drainConnections(ctx context.Context, execution *FailoverExecution) (drained int, terminated int, err error) {
	// Get all flows on primary WAN.
	flows, err := fh.trafficDistributor.GetFlowsByWAN(ctx, execution.PrimaryWAN)
	if err != nil {
		return 0, 0, err
	}

	if len(flows) == 0 {
		return 0, 0, nil
	}

	// Mark flows as draining.
	for _, flowID := range flows {
		_ = fh.trafficDistributor.MarkFlowDraining(ctx, flowID)
	}

	// Wait for graceful drain with timeout.
	drainCtx, cancel := context.WithTimeout(ctx, fh.config.ConnectionDrainTimeout)
	defer cancel()

	drainedCount := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-drainCtx.Done():
			// Force terminate remaining if configured.
			if fh.config.ForceTerminateAfterTimeout {
				remainingFlows, _ := fh.trafficDistributor.GetFlowsByWAN(ctx, execution.PrimaryWAN)
				for _, flowID := range remainingFlows {
					_ = fh.trafficDistributor.TerminateFlow(ctx, flowID)
					terminated++
				}
			}
			return drainedCount, terminated, nil
		case <-ticker.C:
			remainingFlows, _ := fh.trafficDistributor.GetFlowsByWAN(ctx, execution.PrimaryWAN)
			newDrained := len(flows) - len(remainingFlows)
			if newDrained > drainedCount {
				drainedCount = newDrained
			}
			if len(remainingFlows) == 0 {
				return drainedCount, 0, nil
			}
		}
	}
}

// =============================================================================
// Reassign Flows
// =============================================================================

// reassignFlows moves flows from primary to backup WAN.
func (fh *FailoverHandler) reassignFlows(ctx context.Context, execution *FailoverExecution) (int, error) {
	// Get remaining flows on primary WAN.
	flows, err := fh.trafficDistributor.GetFlowsByWAN(ctx, execution.PrimaryWAN)
	if err != nil {
		return 0, err
	}

	if len(flows) == 0 {
		return 0, nil
	}

	// Create worker pool.
	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	semaphore := make(chan struct{}, fh.config.MaxConcurrentFlowMigrations)
	errorsChan := make(chan string, len(flows))

	for _, flowID := range flows {
		wg.Add(1)
		go func(fid string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			err := fh.trafficDistributor.PreemptFlow(ctx, fid, execution.BackupWAN, "FAILOVER")
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				errorsChan <- fmt.Sprintf("flow %s: %v", fid, err)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}(flowID)
	}

	wg.Wait()
	close(errorsChan)

	// Collect errors.
	for errMsg := range errorsChan {
		execution.Errors = append(execution.Errors, errMsg)
	}

	// Return error if significant portion failed.
	if errorCount > int64(len(flows)/2) {
		return int(successCount), ErrFlowReassignmentFailed
	}

	return int(successCount), nil
}

// =============================================================================
// Migrate NAT
// =============================================================================

// migrateNAT updates NAT mappings to use the backup WAN.
func (fh *FailoverHandler) migrateNAT(ctx context.Context, execution *FailoverExecution) (int, error) {
	// Get NAT mappings for primary WAN.
	mappings, err := fh.natTranslator.GetMappingsByWAN(ctx, execution.PrimaryWAN)
	if err != nil {
		return 0, err
	}

	if len(mappings) == 0 {
		return 0, nil
	}

	// Migrate in batches.
	migratedCount := 0
	batchSize := fh.config.NATMigrationBatchSize

	for i := 0; i < len(mappings); i += batchSize {
		end := i + batchSize
		if end > len(mappings) {
			end = len(mappings)
		}

		batch := mappings[i:end]
		for _, mappingID := range batch {
			err := fh.natTranslator.MigrateMapping(ctx, mappingID, execution.BackupWAN)
			if err != nil {
				execution.Errors = append(execution.Errors, fmt.Sprintf("NAT %s: %v", mappingID, err))
			} else {
				migratedCount++
			}
		}

		// Check context between batches.
		if ctx.Err() != nil {
			return migratedCount, ErrFailoverTimeout
		}
	}

	return migratedCount, nil
}

// =============================================================================
// Rollback
// =============================================================================

// rollbackFailover reverts a partial failover to restore original state.
func (fh *FailoverHandler) rollbackFailover(ctx context.Context, execution *FailoverExecution) error {
	var rollbackErrors []string

	// Rollback flows.
	if execution.FlowsReassigned > 0 {
		flows, _ := fh.trafficDistributor.GetFlowsByWAN(ctx, execution.BackupWAN)
		for _, flowID := range flows {
			err := fh.trafficDistributor.PreemptFlow(ctx, flowID, execution.PrimaryWAN, "ROLLBACK")
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Sprintf("flow rollback %s: %v", flowID, err))
			}
		}
	}

	// Rollback NAT.
	if execution.NATMappingsMigrated > 0 {
		mappings, _ := fh.natTranslator.GetMappingsByWAN(ctx, execution.BackupWAN)
		for _, mappingID := range mappings {
			err := fh.natTranslator.MigrateMapping(ctx, mappingID, execution.PrimaryWAN)
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Sprintf("NAT rollback %s: %v", mappingID, err))
			}
		}
	}

	// Rollback routing.
	if execution.RoutingTableUpdated {
		err := fh.routingEngine.UpdateDefaultRoute(ctx, execution.PrimaryWAN)
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Sprintf("routing rollback: %v", err))
		}
	}

	if len(rollbackErrors) > 0 {
		execution.Errors = append(execution.Errors, rollbackErrors...)
		return ErrFailoverRollbackFailed
	}

	return nil
}

// =============================================================================
// Completion Helpers
// =============================================================================

// failFailover creates a failed failover event.
func (fh *FailoverHandler) failFailover(execution *FailoverExecution, primaryHealth, backupHealth float64) *FailoverEvent {
	fh.mu.Lock()
	execution.Phase = FailoverPhaseFailed
	execution.IsComplete = true
	fh.mu.Unlock()

	atomic.AddUint64(&fh.failedAttempts, 1)

	return &FailoverEvent{
		EventID:                 execution.ExecutionID,
		PrimaryWAN:              execution.PrimaryWAN,
		BackupWAN:               execution.BackupWAN,
		TriggerReason:           execution.TriggerReason,
		StartTime:               execution.StartTime,
		EndTime:                 time.Now(),
		Duration:                time.Since(execution.StartTime),
		Outcome:                 FailoverOutcomeFailure,
		FlowsReassigned:         execution.FlowsReassigned,
		NATMappingsMigrated:     execution.NATMappingsMigrated,
		ConnectionsDrained:      execution.ConnectionsDrained,
		ConnectionsTerminated:   execution.ConnectionsTerminated,
		RoutingTableUpdated:     execution.RoutingTableUpdated,
		PrimaryHealthAtFailover: primaryHealth,
		BackupHealthAtFailover:  backupHealth,
		ErrorMessages:           execution.Errors,
	}
}

// completeFailover creates a successful failover event.
func (fh *FailoverHandler) completeFailover(execution *FailoverExecution, primaryHealth, backupHealth float64) *FailoverEvent {
	fh.mu.Lock()
	execution.Phase = FailoverPhaseComplete
	execution.IsComplete = true
	fh.mu.Unlock()

	// Determine outcome.
	outcome := FailoverOutcomeSuccess
	if len(execution.Errors) > 0 {
		outcome = FailoverOutcomePartialSuccess
	}

	if outcome == FailoverOutcomeSuccess {
		atomic.AddUint64(&fh.successfulAttempts, 1)
	}

	return &FailoverEvent{
		EventID:                 execution.ExecutionID,
		PrimaryWAN:              execution.PrimaryWAN,
		BackupWAN:               execution.BackupWAN,
		TriggerReason:           execution.TriggerReason,
		StartTime:               execution.StartTime,
		EndTime:                 time.Now(),
		Duration:                time.Since(execution.StartTime),
		Outcome:                 outcome,
		FlowsReassigned:         execution.FlowsReassigned,
		NATMappingsMigrated:     execution.NATMappingsMigrated,
		ConnectionsDrained:      execution.ConnectionsDrained,
		ConnectionsTerminated:   execution.ConnectionsTerminated,
		RoutingTableUpdated:     execution.RoutingTableUpdated,
		PrimaryHealthAtFailover: primaryHealth,
		BackupHealthAtFailover:  backupHealth,
		ErrorMessages:           execution.Errors,
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// IsFailoverActive returns whether a failover is currently in progress.
func (fh *FailoverHandler) IsFailoverActive() bool {
	fh.mu.RLock()
	defer fh.mu.RUnlock()
	return fh.currentFailover != nil && !fh.currentFailover.IsComplete
}

// GetCurrentFailover returns the current failover execution state.
func (fh *FailoverHandler) GetCurrentFailover() *FailoverExecution {
	fh.mu.RLock()
	defer fh.mu.RUnlock()

	if fh.currentFailover == nil {
		return nil
	}

	// Return copy.
	copy := *fh.currentFailover
	copy.Errors = make([]string, len(fh.currentFailover.Errors))
	for i, e := range fh.currentFailover.Errors {
		copy.Errors[i] = e
	}

	return &copy
}

// GetFailoverHistory returns recent failover events.
func (fh *FailoverHandler) GetFailoverHistory(limit int) []*FailoverEvent {
	fh.failoverHistoryMu.RLock()
	defer fh.failoverHistoryMu.RUnlock()

	if len(fh.failoverHistory) == 0 {
		return nil
	}

	// Get last N events.
	start := 0
	if len(fh.failoverHistory) > limit {
		start = len(fh.failoverHistory) - limit
	}

	result := make([]*FailoverEvent, len(fh.failoverHistory)-start)
	for i, event := range fh.failoverHistory[start:] {
		copy := *event
		result[i] = &copy
	}

	// Reverse to get most recent first.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// GetFailoverStatistics computes failover performance metrics.
func (fh *FailoverHandler) GetFailoverStatistics(duration time.Duration) (*FailoverStatistics, error) {
	fh.failoverHistoryMu.RLock()
	defer fh.failoverHistoryMu.RUnlock()

	cutoff := time.Now().Add(-duration)
	stats := &FailoverStatistics{}

	var durations []time.Duration
	var totalDuration time.Duration

	for _, event := range fh.failoverHistory {
		if event.StartTime.Before(cutoff) {
			continue
		}

		stats.TotalFailovers++
		stats.TotalFlowsReassigned += event.FlowsReassigned
		stats.TotalNATMigrations += event.NATMappingsMigrated
		durations = append(durations, event.Duration)
		totalDuration += event.Duration

		switch event.Outcome {
		case FailoverOutcomeSuccess:
			stats.SuccessfulFailovers++
		case FailoverOutcomePartialSuccess:
			stats.PartialFailovers++
		case FailoverOutcomeFailure, FailoverOutcomeTimeout:
			stats.FailedFailovers++
		}

		if stats.FastestFailover == 0 || event.Duration < stats.FastestFailover {
			stats.FastestFailover = event.Duration
		}
		if event.Duration > stats.SlowestFailover {
			stats.SlowestFailover = event.Duration
		}
	}

	if stats.TotalFailovers > 0 {
		stats.AverageDuration = totalDuration / time.Duration(stats.TotalFailovers)
		stats.SuccessRate = float64(stats.SuccessfulFailovers) / float64(stats.TotalFailovers) * 100

		// Calculate median.
		if len(durations) > 0 {
			sortDurations(durations)
			mid := len(durations) / 2
			if len(durations)%2 == 0 {
				stats.MedianDuration = (durations[mid-1] + durations[mid]) / 2
			} else {
				stats.MedianDuration = durations[mid]
			}

			// Calculate P95.
			p95Index := int(float64(len(durations)) * 0.95)
			if p95Index >= len(durations) {
				p95Index = len(durations) - 1
			}
			stats.P95Duration = durations[p95Index]
		}
	}

	return stats, nil
}

// sortDurations sorts a slice of durations in ascending order.
func sortDurations(durations []time.Duration) {
	for i := 0; i < len(durations); i++ {
		for j := i + 1; j < len(durations); j++ {
			if durations[j] < durations[i] {
				durations[i], durations[j] = durations[j], durations[i]
			}
		}
	}
}

// =============================================================================
// Abort Failover
// =============================================================================

// AbortFailover cancels an active failover operation.
func (fh *FailoverHandler) AbortFailover(reason string) error {
	fh.mu.Lock()
	if fh.currentFailover == nil || fh.currentFailover.IsComplete {
		fh.mu.Unlock()
		return ErrNoFailoverActive
	}

	execution := fh.currentFailover
	fh.mu.Unlock()

	// Cancel context.
	if execution.cancelFunc != nil {
		execution.cancelFunc()
	}

	// Wait for abort (up to 5s).
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return ErrFailoverTimeout
		case <-ticker.C:
			fh.mu.RLock()
			if fh.currentFailover == nil || fh.currentFailover.IsComplete {
				fh.mu.RUnlock()

				// Rollback on abort.
				ctx := context.Background()
				_ = fh.rollbackFailover(ctx, execution)

				// Record abort reason.
				fh.mu.Lock()
				execution.Errors = append(execution.Errors, fmt.Sprintf("aborted: %s", reason))
				fh.mu.Unlock()

				return nil
			}
			fh.mu.RUnlock()
		}
	}
}

// =============================================================================
// Validate Preconditions
// =============================================================================

// ValidateFailoverPreconditions checks if failover can proceed safely.
func (fh *FailoverHandler) ValidateFailoverPreconditions(primaryWAN string, backupWAN string) (bool, string) {
	// Check no failover active.
	if fh.IsFailoverActive() {
		return false, "failover already in progress"
	}

	// Check primary WAN exists.
	if !fh.wanSelector.WANExists(primaryWAN) {
		return false, fmt.Sprintf("primary WAN %s not found", primaryWAN)
	}

	// Check backup WAN exists.
	if !fh.wanSelector.WANExists(backupWAN) {
		return false, fmt.Sprintf("backup WAN %s not found", backupWAN)
	}

	// Check backup WAN health.
	ctx := context.Background()
	health, err := fh.wanSelector.GetWANHealth(ctx, backupWAN)
	if err != nil {
		return false, fmt.Sprintf("failed to get backup health: %v", err)
	}
	if health < fh.config.MinBackupHealthScore {
		return false, fmt.Sprintf("backup health %.2f below threshold %.2f", health, fh.config.MinBackupHealthScore)
	}

	// Check backup WAN state.
	state, err := fh.wanSelector.GetWANState(ctx, backupWAN)
	if err != nil || state != "ENABLED" {
		return false, fmt.Sprintf("backup WAN state invalid: %s", state)
	}

	return true, ""
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the handler is operational.
func (fh *FailoverHandler) HealthCheck() error {
	if !fh.running {
		return errors.New("handler not running")
	}

	// Check no failover stuck.
	fh.mu.RLock()
	if fh.currentFailover != nil && !fh.currentFailover.IsComplete {
		duration := time.Since(fh.currentFailover.StartTime)
		if duration > fh.config.ExecutionTimeout*2 {
			fh.mu.RUnlock()
			return errors.New("failover stuck")
		}
	}
	fh.mu.RUnlock()

	return nil
}

// =============================================================================
// Configuration Access
// =============================================================================

// GetConfig returns the current configuration.
func (fh *FailoverHandler) GetConfig() *FailoverConfig {
	return fh.config
}

// GetPhaseTimings returns timing information for current/last failover.
func (fh *FailoverHandler) GetPhaseTimings() []PhaseTiming {
	fh.phaseTimingsMu.Lock()
	defer fh.phaseTimingsMu.Unlock()

	result := make([]PhaseTiming, len(fh.phaseTimings))
	copy(result, fh.phaseTimings)
	return result
}
