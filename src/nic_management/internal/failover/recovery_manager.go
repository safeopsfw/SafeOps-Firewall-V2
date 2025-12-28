// Package failover provides WAN failover management for the NIC Management service.
package failover

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Error Types (Recovery Manager Specific)
// =============================================================================

var (
	// ErrRecoveryActive indicates recovery already in progress.
	ErrRecoveryActive = errors.New("recovery already in progress")
	// ErrPrimaryUnhealthy indicates primary health below threshold.
	ErrPrimaryUnhealthy = errors.New("primary WAN unhealthy")
	// ErrHealthUnstable indicates primary health fluctuating.
	ErrHealthUnstable = errors.New("primary health unstable")
	// ErrRecoveryDrainTimeout indicates backup drain exceeded timeout.
	ErrRecoveryDrainTimeout = errors.New("drain timeout exceeded")
	// ErrMigrationFailed indicates flow migration errors exceeded threshold.
	ErrMigrationFailed = errors.New("flow migration failed")
	// ErrPostValidationFailed indicates traffic not flowing after recovery.
	ErrPostValidationFailed = errors.New("post-recovery validation failed")
	// ErrMaxAttemptsExceeded indicates too many consecutive failures.
	ErrMaxAttemptsExceeded = errors.New("max recovery attempts exceeded")
	// ErrRollbackFailed indicates failed to revert to backup WAN.
	ErrRollbackFailed = errors.New("rollback failed")
	// ErrRecoveryNotActive indicates no recovery in progress.
	ErrRecoveryNotActive = errors.New("no recovery in progress")
)

// =============================================================================
// Recovery Phase
// =============================================================================

// RecoveryPhase represents phases of recovery lifecycle.
type RecoveryPhase int

const (
	// PhaseIdle means no recovery in progress.
	PhaseIdle RecoveryPhase = iota
	// PhaseWaiting means waiting for recovery delay.
	PhaseWaiting
	// PhaseHealthValidation means validating primary health.
	PhaseHealthValidation
	// PhaseDrainBackup means preventing new flows on backup.
	PhaseDrainBackup
	// PhaseMigrateFlows means moving flows to primary.
	PhaseMigrateFlows
	// PhasePostValidation means verifying traffic flowing.
	PhasePostValidation
	// PhaseComplete means recovery finished successfully.
	PhaseComplete
	// PhaseAborted means recovery aborted.
	PhaseAborted
	// PhaseRollback means rolling back to backup.
	PhaseRollback
)

// String returns the string representation of the phase.
func (p RecoveryPhase) String() string {
	switch p {
	case PhaseIdle:
		return "IDLE"
	case PhaseWaiting:
		return "WAITING"
	case PhaseHealthValidation:
		return "HEALTH_VALIDATION"
	case PhaseDrainBackup:
		return "DRAIN_BACKUP"
	case PhaseMigrateFlows:
		return "MIGRATE_FLOWS"
	case PhasePostValidation:
		return "POST_VALIDATION"
	case PhaseComplete:
		return "COMPLETE"
	case PhaseAborted:
		return "ABORTED"
	case PhaseRollback:
		return "ROLLBACK"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Recovery Outcome
// =============================================================================

// RecoveryOutcome represents recovery operation results.
type RecoveryOutcome int

const (
	// OutcomeSuccess means recovery completed successfully.
	OutcomeSuccess RecoveryOutcome = iota
	// OutcomeFailure means recovery failed.
	OutcomeFailure
	// OutcomeAborted means recovery was aborted.
	OutcomeAborted
	// OutcomeTimeout means recovery exceeded timeout.
	OutcomeTimeout
)

// String returns the string representation of the outcome.
func (o RecoveryOutcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "SUCCESS"
	case OutcomeFailure:
		return "FAILURE"
	case OutcomeAborted:
		return "ABORTED"
	case OutcomeTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Recovery State
// =============================================================================

// RecoveryState contains state of current recovery operation.
type RecoveryState struct {
	// Phase is the current recovery phase.
	Phase RecoveryPhase `json:"phase"`
	// PrimaryWAN is the WAN recovering to.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is the WAN recovering from.
	BackupWAN string `json:"backup_wan"`
	// StartTime is when recovery started.
	StartTime time.Time `json:"start_time"`
	// ExpectedCompletionTime is estimated completion.
	ExpectedCompletionTime time.Time `json:"expected_completion_time"`
	// FlowsMigrated is flows moved to primary.
	FlowsMigrated int `json:"flows_migrated"`
	// FlowsRemaining is flows still on backup.
	FlowsRemaining int `json:"flows_remaining"`
	// MigrationErrors is failed migration attempts.
	MigrationErrors int `json:"migration_errors"`
	// CurrentHealthScore is primary health during recovery.
	CurrentHealthScore float64 `json:"current_health_score"`
	// RecoveryAttempt is current attempt number.
	RecoveryAttempt int `json:"recovery_attempt"`
	// LastError is last error encountered.
	LastError string `json:"last_error,omitempty"`
	// IsActive indicates recovery in progress.
	IsActive bool `json:"is_active"`
}

// =============================================================================
// Recovery Event
// =============================================================================

// RecoveryEvent records a recovery operation.
type RecoveryEvent struct {
	// EventID is unique event identifier.
	EventID string `json:"event_id"`
	// PrimaryWAN is WAN recovered to.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is WAN recovered from.
	BackupWAN string `json:"backup_wan"`
	// StartTime is when recovery started.
	StartTime time.Time `json:"start_time"`
	// EndTime is when recovery completed/failed.
	EndTime time.Time `json:"end_time"`
	// Duration is total recovery duration.
	Duration time.Duration `json:"duration"`
	// Outcome is the result.
	Outcome RecoveryOutcome `json:"outcome"`
	// FlowsMigrated is total flows moved.
	FlowsMigrated int `json:"flows_migrated"`
	// InitialHealth is primary health at start.
	InitialHealth float64 `json:"initial_health"`
	// FinalHealth is primary health at end.
	FinalHealth float64 `json:"final_health"`
	// FailureReason is reason if failed.
	FailureReason string `json:"failure_reason,omitempty"`
	// RecoveryAttempt is attempt number.
	RecoveryAttempt int `json:"recovery_attempt"`
}

// =============================================================================
// Recovery Statistics
// =============================================================================

// RecoveryStatistics contains recovery performance statistics.
type RecoveryStatistics struct {
	// TotalRecoveries is total recovery attempts.
	TotalRecoveries int `json:"total_recoveries"`
	// SuccessfulRecoveries is recoveries completed.
	SuccessfulRecoveries int `json:"successful_recoveries"`
	// FailedRecoveries is recoveries that failed.
	FailedRecoveries int `json:"failed_recoveries"`
	// AbortedRecoveries is recoveries aborted.
	AbortedRecoveries int `json:"aborted_recoveries"`
	// AverageDuration is mean recovery time.
	AverageDuration time.Duration `json:"average_duration"`
	// SuccessRate is success percentage.
	SuccessRate float64 `json:"success_rate"`
	// TotalFlowsMigrated is cumulative flows switched.
	TotalFlowsMigrated int `json:"total_flows_migrated"`
}

// =============================================================================
// Recovery Configuration
// =============================================================================

// RecoveryConfig contains configuration for recovery.
type RecoveryConfig struct {
	// RecoveryDelay is wait before starting recovery.
	RecoveryDelay time.Duration `json:"recovery_delay"`
	// HealthStabilityDuration is how long primary must be stable.
	HealthStabilityDuration time.Duration `json:"health_stability_duration"`
	// MinHealthScore is minimum health to attempt recovery.
	MinHealthScore float64 `json:"min_health_score"`
	// EnableAutoRecovery automatically recovers when healthy.
	EnableAutoRecovery bool `json:"enable_auto_recovery"`
	// DrainTimeout is max time for connection draining.
	DrainTimeout time.Duration `json:"drain_timeout"`
	// MigrationBatchSize is flows per batch.
	MigrationBatchSize int `json:"migration_batch_size"`
	// MigrationBatchDelay is delay between batches.
	MigrationBatchDelay time.Duration `json:"migration_batch_delay"`
	// HealthCheckInterval is health check frequency.
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	// HealthDegradationThreshold aborts if health drops below.
	HealthDegradationThreshold float64 `json:"health_degradation_threshold"`
	// MaxRecoveryAttempts is max consecutive attempts.
	MaxRecoveryAttempts int `json:"max_recovery_attempts"`
	// RecoveryBackoffDuration is wait between attempts.
	RecoveryBackoffDuration time.Duration `json:"recovery_backoff_duration"`
	// EnableGradualMigration migrates in batches.
	EnableGradualMigration bool `json:"enable_gradual_migration"`
	// ValidatePostRecovery verifies traffic after recovery.
	ValidatePostRecovery bool `json:"validate_post_recovery"`
}

// DefaultRecoveryConfig returns the default configuration.
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		RecoveryDelay:              60 * time.Second,
		HealthStabilityDuration:    120 * time.Second,
		MinHealthScore:             70.0,
		EnableAutoRecovery:         true,
		DrainTimeout:               300 * time.Second,
		MigrationBatchSize:         100,
		MigrationBatchDelay:        1 * time.Second,
		HealthCheckInterval:        5 * time.Second,
		HealthDegradationThreshold: 60.0,
		MaxRecoveryAttempts:        3,
		RecoveryBackoffDuration:    300 * time.Second,
		EnableGradualMigration:     true,
		ValidatePostRecovery:       true,
	}
}

// =============================================================================
// Recovery Subscriber
// =============================================================================

// RecoverySubscriber receives recovery event notifications.
type RecoverySubscriber interface {
	// OnRecoveryStarted is called when recovery begins.
	OnRecoveryStarted(primaryWAN, backupWAN string)
	// OnRecoveryPhaseChange is called when phase changes.
	OnRecoveryPhaseChange(phase RecoveryPhase)
	// OnRecoveryCompleted is called when recovery finishes.
	OnRecoveryCompleted(event *RecoveryEvent)
	// OnRecoveryAborted is called when recovery aborted.
	OnRecoveryAborted(reason string)
}

// =============================================================================
// Database Interface
// =============================================================================

// RecoveryDB defines the database interface.
type RecoveryDB interface {
	// LoadRecoveryHistory loads recent recovery events.
	LoadRecoveryHistory(ctx context.Context, limit int) ([]*RecoveryEvent, error)
	// SaveRecoveryEvent saves a recovery event.
	SaveRecoveryEvent(ctx context.Context, event *RecoveryEvent) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpRecoveryDB struct{}

func (n *noOpRecoveryDB) LoadRecoveryHistory(ctx context.Context, limit int) ([]*RecoveryEvent, error) {
	return nil, nil
}

func (n *noOpRecoveryDB) SaveRecoveryEvent(ctx context.Context, event *RecoveryEvent) error {
	return nil
}

// =============================================================================
// Recovery Manager
// =============================================================================

// RecoveryManager orchestrates WAN recovery operations.
type RecoveryManager struct {
	// Database for recovery history.
	db RecoveryDB
	// Configuration.
	config *RecoveryConfig
	// Recovery state.
	recoveryState *RecoveryState
	// Recovery history.
	recoveryHistory []*RecoveryEvent
	// Protects state.
	mu sync.RWMutex
	// Subscribers.
	subscribers   []RecoverySubscriber
	subscribersMu sync.RWMutex
	// Recent recovery attempts for backoff.
	recentAttempts   []time.Time
	recentAttemptsMu sync.Mutex
	// Primary health samples for stability tracking.
	healthSamples   []float64
	healthSamplesMu sync.Mutex
	// Cancel function for active recovery.
	cancelRecovery context.CancelFunc
	// Statistics.
	totalRecoveries    uint64
	successRecoveries  uint64
	failedRecoveries   uint64
	abortedRecoveries  uint64
	totalFlowsMigrated uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewRecoveryManager creates a new recovery manager.
func NewRecoveryManager(db RecoveryDB, config *RecoveryConfig) *RecoveryManager {
	if config == nil {
		config = DefaultRecoveryConfig()
	}

	if db == nil {
		db = &noOpRecoveryDB{}
	}

	return &RecoveryManager{
		db:     db,
		config: config,
		recoveryState: &RecoveryState{
			Phase: PhaseIdle,
		},
		recoveryHistory: make([]*RecoveryEvent, 0),
		subscribers:     make([]RecoverySubscriber, 0),
		recentAttempts:  make([]time.Time, 0),
		healthSamples:   make([]float64, 0),
		stopChan:        make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the recovery manager.
func (rm *RecoveryManager) Start(ctx context.Context) error {
	rm.runningMu.Lock()
	defer rm.runningMu.Unlock()

	if rm.running {
		return nil
	}

	// Load recovery history.
	history, err := rm.db.LoadRecoveryHistory(ctx, 100)
	if err == nil && history != nil {
		rm.recoveryHistory = history
	}

	rm.running = true
	return nil
}

// Stop stops the recovery manager.
func (rm *RecoveryManager) Stop() error {
	rm.runningMu.Lock()
	if !rm.running {
		rm.runningMu.Unlock()
		return nil
	}
	rm.running = false
	rm.runningMu.Unlock()

	// Abort active recovery.
	if rm.IsRecoveryActive() {
		_ = rm.AbortRecovery("SHUTDOWN")
	}

	close(rm.stopChan)
	rm.wg.Wait()

	return nil
}

// =============================================================================
// Recovery Execution
// =============================================================================

// ExecuteRecovery executes a recovery operation.
func (rm *RecoveryManager) ExecuteRecovery(ctx context.Context, primaryWAN, backupWAN string) error {
	// Check if recovery already active.
	rm.mu.Lock()
	if rm.recoveryState.IsActive {
		rm.mu.Unlock()
		return ErrRecoveryActive
	}

	// Check recent attempts.
	if !rm.canAttemptRecovery() {
		rm.mu.Unlock()
		return ErrMaxAttemptsExceeded
	}

	// Initialize recovery state.
	now := time.Now()
	rm.recoveryState = &RecoveryState{
		Phase:                  PhaseWaiting,
		PrimaryWAN:             primaryWAN,
		BackupWAN:              backupWAN,
		StartTime:              now,
		ExpectedCompletionTime: now.Add(rm.config.RecoveryDelay + rm.config.HealthStabilityDuration + rm.config.DrainTimeout),
		RecoveryAttempt:        rm.getNextAttemptNumber(),
		CurrentHealthScore:     100.0,
		IsActive:               true,
	}

	// Create cancellable context.
	recoveryCtx, cancel := context.WithCancel(ctx)
	rm.cancelRecovery = cancel
	rm.mu.Unlock()

	// Record attempt.
	rm.recordAttempt()
	atomic.AddUint64(&rm.totalRecoveries, 1)

	// Notify subscribers.
	rm.notifyRecoveryStarted(primaryWAN, backupWAN)

	// Execute recovery phases.
	event := &RecoveryEvent{
		EventID:         generateEventID(),
		PrimaryWAN:      primaryWAN,
		BackupWAN:       backupWAN,
		StartTime:       now,
		InitialHealth:   100.0,
		RecoveryAttempt: rm.recoveryState.RecoveryAttempt,
	}

	var err error

	// Phase 1: Waiting
	err = rm.executeWaitingPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	// Phase 2: Health Validation
	err = rm.executeHealthValidationPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	// Phase 3: Drain Backup
	err = rm.executeDrainPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	// Phase 4: Migrate Flows
	err = rm.executeMigrationPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	// Phase 5: Post-Validation
	if rm.config.ValidatePostRecovery {
		err = rm.executePostValidationPhase(recoveryCtx)
		if err != nil {
			return rm.handleRecoveryFailure(event, err)
		}
	}

	// Phase 6: Complete
	return rm.completeRecovery(event)
}

// executeWaitingPhase waits for recovery delay.
func (rm *RecoveryManager) executeWaitingPhase(ctx context.Context) error {
	rm.setPhase(PhaseWaiting)

	timer := time.NewTimer(rm.config.RecoveryDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rm.stopChan:
		return errors.New("shutdown")
	case <-timer.C:
		return nil
	}
}

// executeHealthValidationPhase validates primary health stability.
func (rm *RecoveryManager) executeHealthValidationPhase(ctx context.Context) error {
	rm.setPhase(PhaseHealthValidation)

	rm.healthSamplesMu.Lock()
	rm.healthSamples = make([]float64, 0)
	rm.healthSamplesMu.Unlock()

	stabilityStart := time.Now()
	ticker := time.NewTicker(rm.config.HealthCheckInterval)
	defer ticker.Stop()

	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rm.stopChan:
			return errors.New("shutdown")
		case <-timeout.C:
			return ErrHealthUnstable
		case <-ticker.C:
			// Simulate health check (would use actual health checker).
			health := rm.getCurrentHealth()

			if health < rm.config.MinHealthScore {
				// Reset stability timer.
				stabilityStart = time.Now()
				rm.healthSamplesMu.Lock()
				rm.healthSamples = make([]float64, 0)
				rm.healthSamplesMu.Unlock()
				continue
			}

			rm.healthSamplesMu.Lock()
			rm.healthSamples = append(rm.healthSamples, health)
			rm.healthSamplesMu.Unlock()

			rm.mu.Lock()
			rm.recoveryState.CurrentHealthScore = health
			rm.mu.Unlock()

			// Check if stable for required duration.
			if time.Since(stabilityStart) >= rm.config.HealthStabilityDuration {
				return nil
			}
		}
	}
}

// executeDrainPhase drains the backup WAN.
func (rm *RecoveryManager) executeDrainPhase(ctx context.Context) error {
	rm.setPhase(PhaseDrainBackup)

	// In real implementation, would call traffic distributor.
	// Simulate drain with timeout.
	timer := time.NewTimer(5 * time.Second) // Simulated drain time.
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rm.stopChan:
		return errors.New("shutdown")
	case <-timer.C:
		return nil
	}
}

// executeMigrationPhase migrates flows to primary.
func (rm *RecoveryManager) executeMigrationPhase(ctx context.Context) error {
	rm.setPhase(PhaseMigrateFlows)

	// Simulate flow count (would come from traffic distributor).
	totalFlows := 500
	rm.mu.Lock()
	rm.recoveryState.FlowsRemaining = totalFlows
	rm.mu.Unlock()

	if rm.config.EnableGradualMigration {
		return rm.migrateGradually(ctx, totalFlows)
	}
	return rm.migrateAllAtOnce(ctx, totalFlows)
}

// migrateGradually migrates flows in batches.
func (rm *RecoveryManager) migrateGradually(ctx context.Context, totalFlows int) error {
	migrated := 0

	for migrated < totalFlows {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rm.stopChan:
			return errors.New("shutdown")
		default:
		}

		// Check health during migration.
		health := rm.getCurrentHealth()
		if health < rm.config.HealthDegradationThreshold {
			return ErrMigrationFailed
		}

		// Migrate batch.
		batchSize := rm.config.MigrationBatchSize
		if migrated+batchSize > totalFlows {
			batchSize = totalFlows - migrated
		}

		// Simulate migration (would call traffic distributor).
		migrated += batchSize

		rm.mu.Lock()
		rm.recoveryState.FlowsMigrated = migrated
		rm.recoveryState.FlowsRemaining = totalFlows - migrated
		rm.mu.Unlock()

		// Delay between batches.
		if migrated < totalFlows {
			time.Sleep(rm.config.MigrationBatchDelay)
		}
	}

	atomic.AddUint64(&rm.totalFlowsMigrated, uint64(migrated))
	return nil
}

// migrateAllAtOnce migrates all flows immediately.
func (rm *RecoveryManager) migrateAllAtOnce(ctx context.Context, totalFlows int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Simulate immediate migration.
	rm.mu.Lock()
	rm.recoveryState.FlowsMigrated = totalFlows
	rm.recoveryState.FlowsRemaining = 0
	rm.mu.Unlock()

	atomic.AddUint64(&rm.totalFlowsMigrated, uint64(totalFlows))
	return nil
}

// executePostValidationPhase validates traffic flowing on primary.
func (rm *RecoveryManager) executePostValidationPhase(ctx context.Context) error {
	rm.setPhase(PhasePostValidation)

	// Simulate validation (would verify traffic actually flowing).
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rm.stopChan:
		return errors.New("shutdown")
	case <-timer.C:
		// Verify health still good.
		health := rm.getCurrentHealth()
		if health < rm.config.MinHealthScore {
			return ErrPostValidationFailed
		}
		return nil
	}
}

// completeRecovery marks recovery as complete.
func (rm *RecoveryManager) completeRecovery(event *RecoveryEvent) error {
	rm.setPhase(PhaseComplete)

	rm.mu.Lock()
	rm.recoveryState.IsActive = false
	event.EndTime = time.Now()
	event.Duration = event.EndTime.Sub(event.StartTime)
	event.Outcome = OutcomeSuccess
	event.FlowsMigrated = rm.recoveryState.FlowsMigrated
	event.FinalHealth = rm.recoveryState.CurrentHealthScore
	rm.recoveryHistory = append(rm.recoveryHistory, event)
	rm.mu.Unlock()

	atomic.AddUint64(&rm.successRecoveries, 1)

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rm.db.SaveRecoveryEvent(ctx, event)

	// Notify subscribers.
	rm.notifyRecoveryCompleted(event)

	return nil
}

// handleRecoveryFailure handles recovery failure.
func (rm *RecoveryManager) handleRecoveryFailure(event *RecoveryEvent, err error) error {
	rm.setPhase(PhaseAborted)

	rm.mu.Lock()
	rm.recoveryState.IsActive = false
	rm.recoveryState.LastError = err.Error()
	event.EndTime = time.Now()
	event.Duration = event.EndTime.Sub(event.StartTime)
	event.Outcome = OutcomeFailure
	event.FlowsMigrated = rm.recoveryState.FlowsMigrated
	event.FinalHealth = rm.recoveryState.CurrentHealthScore
	event.FailureReason = err.Error()
	rm.recoveryHistory = append(rm.recoveryHistory, event)
	rm.mu.Unlock()

	atomic.AddUint64(&rm.failedRecoveries, 1)

	// Rollback if flows were migrated.
	if rm.recoveryState.FlowsMigrated > 0 {
		_ = rm.rollbackRecovery()
	}

	// Persist event.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rm.db.SaveRecoveryEvent(ctx, event)

	// Notify subscribers.
	rm.notifyRecoveryAborted(err.Error())

	return err
}

// =============================================================================
// Recovery Control
// =============================================================================

// AbortRecovery cancels active recovery operation.
func (rm *RecoveryManager) AbortRecovery(reason string) error {
	rm.mu.Lock()
	if !rm.recoveryState.IsActive {
		rm.mu.Unlock()
		return ErrRecoveryNotActive
	}
	rm.mu.Unlock()

	// Cancel context.
	if rm.cancelRecovery != nil {
		rm.cancelRecovery()
	}

	rm.setPhase(PhaseAborted)

	rm.mu.Lock()
	rm.recoveryState.IsActive = false
	rm.recoveryState.LastError = reason
	rm.mu.Unlock()

	atomic.AddUint64(&rm.abortedRecoveries, 1)

	// Rollback if flows were migrated.
	if rm.recoveryState.FlowsMigrated > 0 {
		_ = rm.rollbackRecovery()
	}

	rm.notifyRecoveryAborted(reason)

	return nil
}

// rollbackRecovery reverts partially completed recovery.
func (rm *RecoveryManager) rollbackRecovery() error {
	rm.setPhase(PhaseRollback)

	// In real implementation, would move flows back to backup.
	// Simulate rollback.
	rm.mu.Lock()
	rm.recoveryState.FlowsMigrated = 0
	rm.recoveryState.FlowsRemaining = 0
	rm.mu.Unlock()

	return nil
}

// ForceRecovery manually triggers recovery (admin override).
func (rm *RecoveryManager) ForceRecovery(ctx context.Context, primaryWAN, backupWAN string) error {
	// Skip waiting phase, go directly to health validation.
	rm.mu.Lock()
	if rm.recoveryState.IsActive {
		rm.mu.Unlock()
		return ErrRecoveryActive
	}

	now := time.Now()
	rm.recoveryState = &RecoveryState{
		Phase:                  PhaseHealthValidation, // Skip waiting.
		PrimaryWAN:             primaryWAN,
		BackupWAN:              backupWAN,
		StartTime:              now,
		ExpectedCompletionTime: now.Add(rm.config.DrainTimeout),
		RecoveryAttempt:        rm.getNextAttemptNumber(),
		CurrentHealthScore:     100.0,
		IsActive:               true,
	}

	recoveryCtx, cancel := context.WithCancel(ctx)
	rm.cancelRecovery = cancel
	rm.mu.Unlock()

	atomic.AddUint64(&rm.totalRecoveries, 1)
	rm.notifyRecoveryStarted(primaryWAN, backupWAN)

	event := &RecoveryEvent{
		EventID:         generateEventID(),
		PrimaryWAN:      primaryWAN,
		BackupWAN:       backupWAN,
		StartTime:       now,
		InitialHealth:   100.0,
		RecoveryAttempt: rm.recoveryState.RecoveryAttempt,
	}

	// Skip health validation for force recovery.
	rm.setPhase(PhaseDrainBackup)

	// Execute remaining phases.
	var err error

	err = rm.executeDrainPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	err = rm.executeMigrationPhase(recoveryCtx)
	if err != nil {
		return rm.handleRecoveryFailure(event, err)
	}

	if rm.config.ValidatePostRecovery {
		err = rm.executePostValidationPhase(recoveryCtx)
		if err != nil {
			return rm.handleRecoveryFailure(event, err)
		}
	}

	return rm.completeRecovery(event)
}

// =============================================================================
// Helper Methods
// =============================================================================

// setPhase updates the current phase.
func (rm *RecoveryManager) setPhase(phase RecoveryPhase) {
	rm.mu.Lock()
	rm.recoveryState.Phase = phase
	rm.mu.Unlock()

	rm.notifyPhaseChange(phase)
}

// getCurrentHealth returns current primary health (simulated).
func (rm *RecoveryManager) getCurrentHealth() float64 {
	rm.mu.RLock()
	health := rm.recoveryState.CurrentHealthScore
	rm.mu.RUnlock()

	// In real impl, would query health checker.
	return health
}

// canAttemptRecovery checks if recovery attempt allowed.
func (rm *RecoveryManager) canAttemptRecovery() bool {
	rm.recentAttemptsMu.Lock()
	defer rm.recentAttemptsMu.Unlock()

	// Prune old attempts.
	cutoff := time.Now().Add(-rm.config.RecoveryBackoffDuration)
	recent := make([]time.Time, 0)
	for _, t := range rm.recentAttempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rm.recentAttempts = recent

	return len(rm.recentAttempts) < rm.config.MaxRecoveryAttempts
}

// recordAttempt records a recovery attempt.
func (rm *RecoveryManager) recordAttempt() {
	rm.recentAttemptsMu.Lock()
	defer rm.recentAttemptsMu.Unlock()

	rm.recentAttempts = append(rm.recentAttempts, time.Now())
}

// getNextAttemptNumber returns the next attempt number.
func (rm *RecoveryManager) getNextAttemptNumber() int {
	rm.recentAttemptsMu.Lock()
	defer rm.recentAttemptsMu.Unlock()

	return len(rm.recentAttempts) + 1
}

// generateEventID generates a unique event ID.
func generateEventID() string {
	return time.Now().Format("20060102150405") + "-recovery"
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for recovery notifications.
func (rm *RecoveryManager) Subscribe(subscriber RecoverySubscriber) {
	rm.subscribersMu.Lock()
	defer rm.subscribersMu.Unlock()
	rm.subscribers = append(rm.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (rm *RecoveryManager) Unsubscribe(subscriber RecoverySubscriber) {
	rm.subscribersMu.Lock()
	defer rm.subscribersMu.Unlock()

	for i, s := range rm.subscribers {
		if s == subscriber {
			rm.subscribers = append(rm.subscribers[:i], rm.subscribers[i+1:]...)
			return
		}
	}
}

// notifyRecoveryStarted notifies subscribers recovery started.
func (rm *RecoveryManager) notifyRecoveryStarted(primaryWAN, backupWAN string) {
	rm.subscribersMu.RLock()
	subscribers := make([]RecoverySubscriber, len(rm.subscribers))
	copy(subscribers, rm.subscribers)
	rm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s RecoverySubscriber) {
			s.OnRecoveryStarted(primaryWAN, backupWAN)
		}(sub)
	}
}

// notifyPhaseChange notifies subscribers of phase change.
func (rm *RecoveryManager) notifyPhaseChange(phase RecoveryPhase) {
	rm.subscribersMu.RLock()
	subscribers := make([]RecoverySubscriber, len(rm.subscribers))
	copy(subscribers, rm.subscribers)
	rm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s RecoverySubscriber) {
			s.OnRecoveryPhaseChange(phase)
		}(sub)
	}
}

// notifyRecoveryCompleted notifies subscribers recovery completed.
func (rm *RecoveryManager) notifyRecoveryCompleted(event *RecoveryEvent) {
	rm.subscribersMu.RLock()
	subscribers := make([]RecoverySubscriber, len(rm.subscribers))
	copy(subscribers, rm.subscribers)
	rm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s RecoverySubscriber) {
			s.OnRecoveryCompleted(event)
		}(sub)
	}
}

// notifyRecoveryAborted notifies subscribers recovery aborted.
func (rm *RecoveryManager) notifyRecoveryAborted(reason string) {
	rm.subscribersMu.RLock()
	subscribers := make([]RecoverySubscriber, len(rm.subscribers))
	copy(subscribers, rm.subscribers)
	rm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s RecoverySubscriber) {
			s.OnRecoveryAborted(reason)
		}(sub)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetRecoveryState retrieves current recovery state.
func (rm *RecoveryManager) GetRecoveryState() *RecoveryState {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	copy := *rm.recoveryState
	return &copy
}

// GetRecoveryHistory retrieves historical recovery events.
func (rm *RecoveryManager) GetRecoveryHistory(limit int) []*RecoveryEvent {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if limit <= 0 || limit > len(rm.recoveryHistory) {
		limit = len(rm.recoveryHistory)
	}

	// Return most recent first.
	result := make([]*RecoveryEvent, limit)
	for i := 0; i < limit; i++ {
		idx := len(rm.recoveryHistory) - 1 - i
		if idx >= 0 {
			eventCopy := *rm.recoveryHistory[idx]
			result[i] = &eventCopy
		}
	}
	return result
}

// IsRecoveryActive checks if recovery in progress.
func (rm *RecoveryManager) IsRecoveryActive() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.recoveryState.IsActive
}

// CanRecover validates recovery preconditions.
func (rm *RecoveryManager) CanRecover(primaryWAN string) (bool, string) {
	rm.mu.RLock()
	if rm.recoveryState.IsActive {
		rm.mu.RUnlock()
		return false, "recovery already active"
	}
	rm.mu.RUnlock()

	if !rm.canAttemptRecovery() {
		return false, "max attempts exceeded"
	}

	// Would check primary health here.
	return true, ""
}

// GetRecoveryStatistics computes recovery statistics.
func (rm *RecoveryManager) GetRecoveryStatistics(duration time.Duration) *RecoveryStatistics {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	stats := &RecoveryStatistics{}

	var totalDuration time.Duration

	for _, event := range rm.recoveryHistory {
		if event.StartTime.After(cutoff) {
			stats.TotalRecoveries++
			stats.TotalFlowsMigrated += event.FlowsMigrated
			totalDuration += event.Duration

			switch event.Outcome {
			case OutcomeSuccess:
				stats.SuccessfulRecoveries++
			case OutcomeFailure:
				stats.FailedRecoveries++
			case OutcomeAborted:
				stats.AbortedRecoveries++
			}
		}
	}

	if stats.TotalRecoveries > 0 {
		stats.AverageDuration = totalDuration / time.Duration(stats.TotalRecoveries)
		stats.SuccessRate = float64(stats.SuccessfulRecoveries) / float64(stats.TotalRecoveries) * 100
	}

	return stats
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the recovery manager is operational.
func (rm *RecoveryManager) HealthCheck() error {
	rm.runningMu.Lock()
	running := rm.running
	rm.runningMu.Unlock()

	if !running {
		return errors.New("recovery manager not running")
	}

	// Check for stuck recovery.
	rm.mu.RLock()
	if rm.recoveryState.IsActive && time.Since(rm.recoveryState.StartTime) > 30*time.Minute {
		rm.mu.RUnlock()
		return errors.New("recovery stuck")
	}
	rm.mu.RUnlock()

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns recovery manager statistics.
func (rm *RecoveryManager) GetStatistics() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]interface{}{
		"total_recoveries":      atomic.LoadUint64(&rm.totalRecoveries),
		"successful_recoveries": atomic.LoadUint64(&rm.successRecoveries),
		"failed_recoveries":     atomic.LoadUint64(&rm.failedRecoveries),
		"aborted_recoveries":    atomic.LoadUint64(&rm.abortedRecoveries),
		"total_flows_migrated":  atomic.LoadUint64(&rm.totalFlowsMigrated),
		"current_phase":         rm.recoveryState.Phase.String(),
		"is_active":             rm.recoveryState.IsActive,
		"auto_recovery_enabled": rm.config.EnableAutoRecovery,
	}
}

// GetConfig returns the current configuration.
func (rm *RecoveryManager) GetConfig() *RecoveryConfig {
	return rm.config
}

// IsRunning returns whether the manager is running.
func (rm *RecoveryManager) IsRunning() bool {
	rm.runningMu.Lock()
	defer rm.runningMu.Unlock()
	return rm.running
}

// SetPrimaryHealth sets the current primary health (for testing/simulation).
func (rm *RecoveryManager) SetPrimaryHealth(health float64) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.recoveryState.CurrentHealthScore = health
}
