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
// Error Types
// =============================================================================

var (
	// ErrInvalidTransition indicates event not allowed in current state.
	ErrInvalidTransition = errors.New("invalid state transition")
	// ErrTransitionCooldown indicates transition attempted before cooldown expired.
	ErrTransitionCooldown = errors.New("transition cooldown active")
	// ErrTransitionTimeout indicates transition exceeded timeout.
	ErrTransitionTimeout = errors.New("transition timeout")
	// ErrGuardConditionFailed indicates precondition not met for transition.
	ErrGuardConditionFailed = errors.New("guard condition failed")
	// ErrStateActionFailed indicates enter/leave action returned error.
	ErrStateActionFailed = errors.New("state action failed")
	// ErrManualOverrideDisabled indicates admin transition attempted with override disabled.
	ErrManualOverrideDisabled = errors.New("manual override disabled")
	// ErrWANNotConfigured indicates WAN not found in configuration.
	ErrWANNotConfigured = errors.New("WAN not configured")
)

// =============================================================================
// Failover State
// =============================================================================

// FailoverState represents the failover lifecycle state.
type FailoverState int

const (
	// StateUnknown is indeterminate state.
	StateUnknown FailoverState = iota
	// StatePrimaryActive is normal operation.
	StatePrimaryActive
	// StatePrimaryDegraded is primary WAN degraded but usable.
	StatePrimaryDegraded
	// StateBackupReady is backup WAN validated and ready.
	StateBackupReady
	// StateFailoverInProgress is actively failing over.
	StateFailoverInProgress
	// StateBackupActive is backup WAN handling all traffic.
	StateBackupActive
	// StateRecoveryInProgress is actively recovering.
	StateRecoveryInProgress
	// StateDualActive is both WANs handling traffic.
	StateDualActive
	// StateMaintenance is manual maintenance mode.
	StateMaintenance
	// StateEmergency is critical failure mode.
	StateEmergency
)

// String returns the string representation of the state.
func (s FailoverState) String() string {
	switch s {
	case StateUnknown:
		return "UNKNOWN"
	case StatePrimaryActive:
		return "PRIMARY_ACTIVE"
	case StatePrimaryDegraded:
		return "PRIMARY_DEGRADED"
	case StateBackupReady:
		return "BACKUP_READY"
	case StateFailoverInProgress:
		return "FAILOVER_IN_PROGRESS"
	case StateBackupActive:
		return "BACKUP_ACTIVE"
	case StateRecoveryInProgress:
		return "RECOVERY_IN_PROGRESS"
	case StateDualActive:
		return "DUAL_ACTIVE"
	case StateMaintenance:
		return "MAINTENANCE"
	case StateEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// ParseFailoverState parses a string to FailoverState.
func ParseFailoverState(s string) FailoverState {
	switch s {
	case "PRIMARY_ACTIVE":
		return StatePrimaryActive
	case "PRIMARY_DEGRADED":
		return StatePrimaryDegraded
	case "BACKUP_READY":
		return StateBackupReady
	case "FAILOVER_IN_PROGRESS":
		return StateFailoverInProgress
	case "BACKUP_ACTIVE":
		return StateBackupActive
	case "RECOVERY_IN_PROGRESS":
		return StateRecoveryInProgress
	case "DUAL_ACTIVE":
		return StateDualActive
	case "MAINTENANCE":
		return StateMaintenance
	case "EMERGENCY":
		return StateEmergency
	default:
		return StateUnknown
	}
}

// =============================================================================
// State Event
// =============================================================================

// StateEvent represents events triggering state transitions.
type StateEvent int

const (
	// EventNone is no event.
	EventNone StateEvent = iota
	// EventPrimaryHealthy is primary WAN health restored.
	EventPrimaryHealthy
	// EventPrimaryDegraded is primary WAN performance degraded.
	EventPrimaryDegraded
	// EventPrimaryFailed is primary WAN connectivity lost.
	EventPrimaryFailed
	// EventBackupReady is backup WAN validated and available.
	EventBackupReady
	// EventBackupFailed is backup WAN connectivity lost.
	EventBackupFailed
	// EventFailoverComplete is failover execution finished.
	EventFailoverComplete
	// EventFailoverFailed is failover execution failed.
	EventFailoverFailed
	// EventRecoveryStart is recovery initiation requested.
	EventRecoveryStart
	// EventRecoveryComplete is recovery finished successfully.
	EventRecoveryComplete
	// EventRecoveryFailed is recovery execution failed.
	EventRecoveryFailed
	// EventAdminFailover is manual failover triggered.
	EventAdminFailover
	// EventAdminRecovery is manual recovery triggered.
	EventAdminRecovery
	// EventEnterMaintenance is enter maintenance mode.
	EventEnterMaintenance
	// EventExitMaintenance is exit maintenance mode.
	EventExitMaintenance
	// EventEmergency is enter emergency mode.
	EventEmergency
)

// String returns the string representation of the event.
func (e StateEvent) String() string {
	switch e {
	case EventNone:
		return "NONE"
	case EventPrimaryHealthy:
		return "PRIMARY_HEALTHY"
	case EventPrimaryDegraded:
		return "PRIMARY_DEGRADED"
	case EventPrimaryFailed:
		return "PRIMARY_FAILED"
	case EventBackupReady:
		return "BACKUP_READY"
	case EventBackupFailed:
		return "BACKUP_FAILED"
	case EventFailoverComplete:
		return "FAILOVER_COMPLETE"
	case EventFailoverFailed:
		return "FAILOVER_FAILED"
	case EventRecoveryStart:
		return "RECOVERY_START"
	case EventRecoveryComplete:
		return "RECOVERY_COMPLETE"
	case EventRecoveryFailed:
		return "RECOVERY_FAILED"
	case EventAdminFailover:
		return "ADMIN_FAILOVER"
	case EventAdminRecovery:
		return "ADMIN_RECOVERY"
	case EventEnterMaintenance:
		return "ENTER_MAINTENANCE"
	case EventExitMaintenance:
		return "EXIT_MAINTENANCE"
	case EventEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// State Transition
// =============================================================================

// StateTransition records a single state transition.
type StateTransition struct {
	// FromState is the previous state.
	FromState FailoverState `json:"from_state"`
	// ToState is the new state.
	ToState FailoverState `json:"to_state"`
	// Event is the triggering event.
	Event StateEvent `json:"event"`
	// Timestamp is when transition occurred.
	Timestamp time.Time `json:"timestamp"`
	// Duration is how long transition took.
	Duration time.Duration `json:"duration"`
	// Reason is human-readable transition reason.
	Reason string `json:"reason"`
	// TriggeredBy is who/what triggered.
	TriggeredBy string `json:"triggered_by"`
	// PrimaryWAN is primary WAN at time of transition.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is backup WAN at time of transition.
	BackupWAN string `json:"backup_wan"`
	// Success indicates whether transition completed.
	Success bool `json:"success"`
	// ErrorMessage contains error details if failed.
	ErrorMessage string `json:"error_message,omitempty"`
}

// =============================================================================
// State Machine Configuration
// =============================================================================

// StateMachineConfig contains configuration for the state machine.
type StateMachineConfig struct {
	// InitialState is the starting state.
	InitialState FailoverState `json:"initial_state"`
	// PrimaryWANID is the primary WAN identifier.
	PrimaryWANID string `json:"primary_wan_id"`
	// BackupWANIDs are the backup WAN identifiers.
	BackupWANIDs []string `json:"backup_wan_ids"`
	// EnableAutoRecovery automatically recovers to primary.
	EnableAutoRecovery bool `json:"enable_auto_recovery"`
	// RecoveryDelay is wait before recovery attempt.
	RecoveryDelay time.Duration `json:"recovery_delay"`
	// TransitionTimeout is max time for state transition.
	TransitionTimeout time.Duration `json:"transition_timeout"`
	// MinimumStateDuration prevents rapid state changes.
	MinimumStateDuration time.Duration `json:"minimum_state_duration"`
	// EnableStatePersistence saves state to database.
	EnableStatePersistence bool `json:"enable_state_persistence"`
	// MaxHistorySize is maximum transition history entries.
	MaxHistorySize int `json:"max_history_size"`
	// EmergencyThreshold is consecutive failures for emergency.
	EmergencyThreshold int `json:"emergency_threshold"`
	// AllowManualOverride permits admin-triggered transitions.
	AllowManualOverride bool `json:"allow_manual_override"`
}

// DefaultStateMachineConfig returns the default configuration.
func DefaultStateMachineConfig() *StateMachineConfig {
	return &StateMachineConfig{
		InitialState:           StatePrimaryActive,
		PrimaryWANID:           "",
		BackupWANIDs:           []string{},
		EnableAutoRecovery:     true,
		RecoveryDelay:          60 * time.Second,
		TransitionTimeout:      30 * time.Second,
		MinimumStateDuration:   10 * time.Second,
		EnableStatePersistence: true,
		MaxHistorySize:         1000,
		EmergencyThreshold:     5,
		AllowManualOverride:    true,
	}
}

// =============================================================================
// State Subscriber
// =============================================================================

// StateSubscriber receives state change notifications.
type StateSubscriber interface {
	// OnStateChange is called when state changes.
	OnStateChange(transition *StateTransition) error
	// OnTransitionFailed is called when transition rejected/failed.
	OnTransitionFailed(fromState FailoverState, event StateEvent, err error) error
}

// =============================================================================
// Transition Rule
// =============================================================================

// TransitionRule defines a valid state transition.
type TransitionRule struct {
	// FromState is the source state.
	FromState FailoverState
	// Event is the triggering event.
	Event StateEvent
	// ToState is the destination state.
	ToState FailoverState
}

// =============================================================================
// Database Interface
// =============================================================================

// StateMachineDB defines the database interface.
type StateMachineDB interface {
	// LoadState loads persisted state.
	LoadState(ctx context.Context) (*PersistedState, error)
	// SaveState saves current state.
	SaveState(ctx context.Context, state *PersistedState) error
	// SaveTransitions saves transition history.
	SaveTransitions(ctx context.Context, transitions []*StateTransition) error
}

// PersistedState represents persisted state machine state.
type PersistedState struct {
	// CurrentState is the current state.
	CurrentState FailoverState `json:"current_state"`
	// PrimaryWAN is the primary WAN ID.
	PrimaryWAN string `json:"primary_wan"`
	// BackupWAN is the backup WAN ID.
	BackupWAN string `json:"backup_wan"`
	// LastTransition is the last transition time.
	LastTransition time.Time `json:"last_transition"`
	// PreMaintenanceState is the state before maintenance.
	PreMaintenanceState FailoverState `json:"pre_maintenance_state"`
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpStateMachineDB struct{}

func (n *noOpStateMachineDB) LoadState(ctx context.Context) (*PersistedState, error) {
	return nil, nil
}

func (n *noOpStateMachineDB) SaveState(ctx context.Context, state *PersistedState) error {
	return nil
}

func (n *noOpStateMachineDB) SaveTransitions(ctx context.Context, transitions []*StateTransition) error {
	return nil
}

// =============================================================================
// Failover State Machine
// =============================================================================

// FailoverStateMachine manages WAN failover lifecycle states.
type FailoverStateMachine struct {
	// Database for state persistence.
	db StateMachineDB
	// Configuration.
	config *StateMachineConfig
	// Current state.
	currentState FailoverState
	// Primary WAN ID.
	primaryWAN string
	// Backup WAN ID.
	backupWAN string
	// Pre-maintenance state.
	preMaintenanceState FailoverState
	// Transition history.
	stateHistory []*StateTransition
	// Transition rules.
	transitionRules []TransitionRule
	// Protects state.
	mu sync.RWMutex
	// Subscribers.
	subscribers   []StateSubscriber
	subscribersMu sync.RWMutex
	// Transition cooldowns.
	transitionCooldown map[StateEvent]time.Time
	cooldownMu         sync.RWMutex
	// Last transition time.
	lastTransitionTime time.Time
	// Statistics.
	totalTransitions  uint64
	failedTransitions uint64
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
}

// NewFailoverStateMachine creates a new failover state machine.
func NewFailoverStateMachine(db StateMachineDB, config *StateMachineConfig) *FailoverStateMachine {
	if config == nil {
		config = DefaultStateMachineConfig()
	}

	if db == nil {
		db = &noOpStateMachineDB{}
	}

	fsm := &FailoverStateMachine{
		db:                  db,
		config:              config,
		currentState:        config.InitialState,
		primaryWAN:          config.PrimaryWANID,
		backupWAN:           "",
		preMaintenanceState: StateUnknown,
		stateHistory:        make([]*StateTransition, 0, config.MaxHistorySize),
		transitionRules:     make([]TransitionRule, 0),
		subscribers:         make([]StateSubscriber, 0),
		transitionCooldown:  make(map[StateEvent]time.Time),
		lastTransitionTime:  time.Now(),
		stopChan:            make(chan struct{}),
	}

	// Set backup WAN from config.
	if len(config.BackupWANIDs) > 0 {
		fsm.backupWAN = config.BackupWANIDs[0]
	}

	// Initialize transition rules.
	fsm.initializeTransitionRules()

	return fsm
}

// initializeTransitionRules defines the valid state transitions.
func (fsm *FailoverStateMachine) initializeTransitionRules() {
	fsm.transitionRules = []TransitionRule{
		// From PRIMARY_ACTIVE
		{StatePrimaryActive, EventPrimaryDegraded, StatePrimaryDegraded},
		{StatePrimaryActive, EventPrimaryFailed, StateFailoverInProgress},
		{StatePrimaryActive, EventAdminFailover, StateFailoverInProgress},
		{StatePrimaryActive, EventEnterMaintenance, StateMaintenance},
		{StatePrimaryActive, EventEmergency, StateEmergency},

		// From PRIMARY_DEGRADED
		{StatePrimaryDegraded, EventPrimaryHealthy, StatePrimaryActive},
		{StatePrimaryDegraded, EventPrimaryFailed, StateFailoverInProgress},
		{StatePrimaryDegraded, EventAdminFailover, StateFailoverInProgress},
		{StatePrimaryDegraded, EventEnterMaintenance, StateMaintenance},
		{StatePrimaryDegraded, EventEmergency, StateEmergency},

		// From FAILOVER_IN_PROGRESS
		{StateFailoverInProgress, EventFailoverComplete, StateBackupActive},
		{StateFailoverInProgress, EventFailoverFailed, StateEmergency},
		{StateFailoverInProgress, EventEmergency, StateEmergency},

		// From BACKUP_ACTIVE
		{StateBackupActive, EventRecoveryStart, StateRecoveryInProgress},
		{StateBackupActive, EventAdminRecovery, StateRecoveryInProgress},
		{StateBackupActive, EventBackupFailed, StateEmergency},
		{StateBackupActive, EventEnterMaintenance, StateMaintenance},
		{StateBackupActive, EventEmergency, StateEmergency},

		// From RECOVERY_IN_PROGRESS
		{StateRecoveryInProgress, EventRecoveryComplete, StatePrimaryActive},
		{StateRecoveryInProgress, EventRecoveryFailed, StateBackupActive},
		{StateRecoveryInProgress, EventEmergency, StateEmergency},

		// From MAINTENANCE
		{StateMaintenance, EventExitMaintenance, StatePrimaryActive}, // Returns to pre-maintenance state

		// From EMERGENCY
		{StateEmergency, EventPrimaryHealthy, StatePrimaryActive},
		{StateEmergency, EventBackupReady, StateBackupActive},
		{StateEmergency, EventEnterMaintenance, StateMaintenance},

		// From DUAL_ACTIVE
		{StateDualActive, EventPrimaryFailed, StateBackupActive},
		{StateDualActive, EventBackupFailed, StatePrimaryActive},
		{StateDualActive, EventEnterMaintenance, StateMaintenance},
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the state machine.
func (fsm *FailoverStateMachine) Start(ctx context.Context) error {
	fsm.runningMu.Lock()
	defer fsm.runningMu.Unlock()

	if fsm.running {
		return nil
	}

	// Load persisted state.
	if fsm.config.EnableStatePersistence {
		persistedState, err := fsm.db.LoadState(ctx)
		if err == nil && persistedState != nil {
			fsm.currentState = persistedState.CurrentState
			fsm.primaryWAN = persistedState.PrimaryWAN
			fsm.backupWAN = persistedState.BackupWAN
			fsm.lastTransitionTime = persistedState.LastTransition
			fsm.preMaintenanceState = persistedState.PreMaintenanceState
		}
	}

	// Start persistence worker.
	if fsm.config.EnableStatePersistence {
		fsm.wg.Add(1)
		go fsm.persistenceWorker()
	}

	fsm.running = true
	return nil
}

// Stop stops the state machine.
func (fsm *FailoverStateMachine) Stop() error {
	fsm.runningMu.Lock()
	if !fsm.running {
		fsm.runningMu.Unlock()
		return nil
	}
	fsm.running = false
	fsm.runningMu.Unlock()

	close(fsm.stopChan)
	fsm.wg.Wait()

	// Final persistence.
	if fsm.config.EnableStatePersistence {
		fsm.persistState()
	}

	return nil
}

// =============================================================================
// Background Workers
// =============================================================================

// persistenceWorker periodically saves state.
func (fsm *FailoverStateMachine) persistenceWorker() {
	defer fsm.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fsm.stopChan:
			return
		case <-ticker.C:
			fsm.persistState()
		}
	}
}

// persistState saves current state to database.
func (fsm *FailoverStateMachine) persistState() {
	fsm.mu.RLock()
	state := &PersistedState{
		CurrentState:        fsm.currentState,
		PrimaryWAN:          fsm.primaryWAN,
		BackupWAN:           fsm.backupWAN,
		LastTransition:      fsm.lastTransitionTime,
		PreMaintenanceState: fsm.preMaintenanceState,
	}
	fsm.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = fsm.db.SaveState(ctx, state)
}

// =============================================================================
// State Transitions
// =============================================================================

// FireEvent triggers a state transition event.
func (fsm *FailoverStateMachine) FireEvent(event StateEvent, metadata map[string]interface{}) error {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	startTime := time.Now()
	currentState := fsm.currentState

	// Check if transition is valid.
	targetState, valid := fsm.findTransition(currentState, event)
	if !valid {
		atomic.AddUint64(&fsm.failedTransitions, 1)
		fsm.notifyTransitionFailed(currentState, event, ErrInvalidTransition)
		return ErrInvalidTransition
	}

	// Check cooldown.
	if err := fsm.checkCooldown(event); err != nil {
		atomic.AddUint64(&fsm.failedTransitions, 1)
		fsm.notifyTransitionFailed(currentState, event, err)
		return err
	}

	// Check minimum state duration.
	if time.Since(fsm.lastTransitionTime) < fsm.config.MinimumStateDuration {
		atomic.AddUint64(&fsm.failedTransitions, 1)
		err := ErrTransitionCooldown
		fsm.notifyTransitionFailed(currentState, event, err)
		return err
	}

	// Check guard conditions.
	if err := fsm.checkGuardConditions(currentState, event, targetState); err != nil {
		atomic.AddUint64(&fsm.failedTransitions, 1)
		fsm.notifyTransitionFailed(currentState, event, err)
		return err
	}

	// Execute leave actions.
	if err := fsm.executeLeaveActions(currentState, event); err != nil {
		atomic.AddUint64(&fsm.failedTransitions, 1)
		fsm.notifyTransitionFailed(currentState, event, err)
		return err
	}

	// Handle special case for maintenance mode.
	if event == EventEnterMaintenance {
		fsm.preMaintenanceState = currentState
	}
	if event == EventExitMaintenance && fsm.preMaintenanceState != StateUnknown {
		targetState = fsm.preMaintenanceState
		fsm.preMaintenanceState = StateUnknown
	}

	// Update state.
	fsm.currentState = targetState
	fsm.lastTransitionTime = time.Now()

	// Execute enter actions.
	if err := fsm.executeEnterActions(targetState, event); err != nil {
		// Rollback on failure.
		fsm.currentState = currentState
		atomic.AddUint64(&fsm.failedTransitions, 1)
		fsm.notifyTransitionFailed(currentState, event, err)
		return err
	}

	// Set cooldown.
	fsm.setCooldown(event)

	// Record transition.
	reason := ""
	triggeredBy := "system"
	if metadata != nil {
		if r, ok := metadata["reason"].(string); ok {
			reason = r
		}
		if t, ok := metadata["triggered_by"].(string); ok {
			triggeredBy = t
		}
	}

	transition := &StateTransition{
		FromState:   currentState,
		ToState:     targetState,
		Event:       event,
		Timestamp:   startTime,
		Duration:    time.Since(startTime),
		Reason:      reason,
		TriggeredBy: triggeredBy,
		PrimaryWAN:  fsm.primaryWAN,
		BackupWAN:   fsm.backupWAN,
		Success:     true,
	}

	fsm.addTransitionToHistory(transition)
	atomic.AddUint64(&fsm.totalTransitions, 1)

	// Notify subscribers (async).
	go fsm.notifyStateChange(transition)

	return nil
}

// findTransition finds the target state for an event.
func (fsm *FailoverStateMachine) findTransition(currentState FailoverState, event StateEvent) (FailoverState, bool) {
	for _, rule := range fsm.transitionRules {
		if rule.FromState == currentState && rule.Event == event {
			return rule.ToState, true
		}
	}
	return StateUnknown, false
}

// checkCooldown checks if event is in cooldown.
func (fsm *FailoverStateMachine) checkCooldown(event StateEvent) error {
	fsm.cooldownMu.RLock()
	defer fsm.cooldownMu.RUnlock()

	if cooldownEnd, exists := fsm.transitionCooldown[event]; exists {
		if time.Now().Before(cooldownEnd) {
			return ErrTransitionCooldown
		}
	}
	return nil
}

// setCooldown sets cooldown for an event.
func (fsm *FailoverStateMachine) setCooldown(event StateEvent) {
	fsm.cooldownMu.Lock()
	defer fsm.cooldownMu.Unlock()

	fsm.transitionCooldown[event] = time.Now().Add(fsm.config.MinimumStateDuration)
}

// checkGuardConditions validates preconditions for transition.
func (fsm *FailoverStateMachine) checkGuardConditions(currentState FailoverState, event StateEvent, targetState FailoverState) error {
	switch event {
	case EventAdminFailover, EventAdminRecovery:
		if !fsm.config.AllowManualOverride {
			return ErrManualOverrideDisabled
		}
	case EventRecoveryStart:
		// Recovery requires primary WAN to be configured.
		if fsm.primaryWAN == "" {
			return ErrWANNotConfigured
		}
	case EventFailoverComplete:
		// Failover completion requires backup WAN.
		if fsm.backupWAN == "" {
			return ErrWANNotConfigured
		}
	}

	// Suppress unused variable warnings.
	_ = currentState
	_ = targetState

	return nil
}

// executeLeaveActions executes actions when leaving a state.
func (fsm *FailoverStateMachine) executeLeaveActions(currentState FailoverState, event StateEvent) error {
	// Suppress unused variable warning.
	_ = event

	switch currentState {
	case StatePrimaryActive:
		// Log departure from primary.
	case StateBackupActive:
		// Validate primary ready before recovery.
	case StateMaintenance:
		// Re-enable automated transitions.
	}
	return nil
}

// executeEnterActions executes actions when entering a state.
func (fsm *FailoverStateMachine) executeEnterActions(targetState FailoverState, event StateEvent) error {
	// Suppress unused variable warning.
	_ = event

	switch targetState {
	case StateFailoverInProgress:
		// Failover handler would be called here.
	case StateBackupActive:
		// Log failover completion.
	case StateRecoveryInProgress:
		// Recovery manager would be called here.
	case StatePrimaryActive:
		// Log recovery completion.
	case StateMaintenance:
		// Disable automated transitions.
	case StateEmergency:
		// Trigger emergency routing mode.
	}
	return nil
}

// addTransitionToHistory adds a transition to history.
func (fsm *FailoverStateMachine) addTransitionToHistory(transition *StateTransition) {
	fsm.stateHistory = append(fsm.stateHistory, transition)

	// Trim history if needed.
	if len(fsm.stateHistory) > fsm.config.MaxHistorySize {
		fsm.stateHistory = fsm.stateHistory[len(fsm.stateHistory)-fsm.config.MaxHistorySize:]
	}
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for state notifications.
func (fsm *FailoverStateMachine) Subscribe(subscriber StateSubscriber) {
	fsm.subscribersMu.Lock()
	defer fsm.subscribersMu.Unlock()
	fsm.subscribers = append(fsm.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (fsm *FailoverStateMachine) Unsubscribe(subscriber StateSubscriber) {
	fsm.subscribersMu.Lock()
	defer fsm.subscribersMu.Unlock()

	for i, s := range fsm.subscribers {
		if s == subscriber {
			fsm.subscribers = append(fsm.subscribers[:i], fsm.subscribers[i+1:]...)
			return
		}
	}
}

// notifyStateChange notifies subscribers of state change.
func (fsm *FailoverStateMachine) notifyStateChange(transition *StateTransition) {
	fsm.subscribersMu.RLock()
	subscribers := make([]StateSubscriber, len(fsm.subscribers))
	copy(subscribers, fsm.subscribers)
	fsm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s StateSubscriber) {
			_ = s.OnStateChange(transition)
		}(sub)
	}
}

// notifyTransitionFailed notifies subscribers of failed transition.
func (fsm *FailoverStateMachine) notifyTransitionFailed(fromState FailoverState, event StateEvent, err error) {
	fsm.subscribersMu.RLock()
	subscribers := make([]StateSubscriber, len(fsm.subscribers))
	copy(subscribers, fsm.subscribers)
	fsm.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s StateSubscriber) {
			_ = s.OnTransitionFailed(fromState, event, err)
		}(sub)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetCurrentState returns the current state.
func (fsm *FailoverStateMachine) GetCurrentState() FailoverState {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.currentState
}

// GetStateHistory returns transition history.
func (fsm *FailoverStateMachine) GetStateHistory(limit int) []*StateTransition {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()

	if limit <= 0 || limit > len(fsm.stateHistory) {
		limit = len(fsm.stateHistory)
	}

	// Return most recent first.
	result := make([]*StateTransition, limit)
	for i := 0; i < limit; i++ {
		idx := len(fsm.stateHistory) - 1 - i
		result[i] = fsm.stateHistory[idx]
	}
	return result
}

// CanTransition checks if event is allowed in current state.
func (fsm *FailoverStateMachine) CanTransition(event StateEvent) bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()

	_, valid := fsm.findTransition(fsm.currentState, event)
	return valid
}

// GetValidTransitions returns valid events for current state.
func (fsm *FailoverStateMachine) GetValidTransitions() []StateEvent {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()

	events := make([]StateEvent, 0)
	for _, rule := range fsm.transitionRules {
		if rule.FromState == fsm.currentState {
			events = append(events, rule.Event)
		}
	}
	return events
}

// GetPrimaryWAN returns the current primary WAN ID.
func (fsm *FailoverStateMachine) GetPrimaryWAN() string {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.primaryWAN
}

// GetBackupWAN returns the current backup WAN ID.
func (fsm *FailoverStateMachine) GetBackupWAN() string {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return fsm.backupWAN
}

// GetStateDuration returns how long in current state.
func (fsm *FailoverStateMachine) GetStateDuration() time.Duration {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	return time.Since(fsm.lastTransitionTime)
}

// =============================================================================
// WAN Management
// =============================================================================

// SetPrimaryWAN updates the primary WAN.
func (fsm *FailoverStateMachine) SetPrimaryWAN(wanID string) error {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	fsm.primaryWAN = wanID
	return nil
}

// SetBackupWAN updates the backup WAN.
func (fsm *FailoverStateMachine) SetBackupWAN(wanID string) error {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	fsm.backupWAN = wanID
	return nil
}

// =============================================================================
// Manual Override
// =============================================================================

// ForceState manually sets state (emergency override).
func (fsm *FailoverStateMachine) ForceState(state FailoverState, reason string) error {
	if !fsm.config.AllowManualOverride {
		return ErrManualOverrideDisabled
	}

	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	oldState := fsm.currentState
	fsm.currentState = state
	fsm.lastTransitionTime = time.Now()

	transition := &StateTransition{
		FromState:   oldState,
		ToState:     state,
		Event:       EventNone,
		Timestamp:   time.Now(),
		Duration:    0,
		Reason:      reason,
		TriggeredBy: "admin_force",
		PrimaryWAN:  fsm.primaryWAN,
		BackupWAN:   fsm.backupWAN,
		Success:     true,
	}

	fsm.addTransitionToHistory(transition)

	go fsm.notifyStateChange(transition)

	return nil
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the state machine is operational.
func (fsm *FailoverStateMachine) HealthCheck() error {
	fsm.runningMu.Lock()
	running := fsm.running
	fsm.runningMu.Unlock()

	if !running {
		return errors.New("failover state machine not running")
	}

	fsm.mu.RLock()
	currentState := fsm.currentState
	fsm.mu.RUnlock()

	if currentState == StateUnknown {
		return errors.New("state machine in unknown state")
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns state machine statistics.
func (fsm *FailoverStateMachine) GetStatistics() map[string]interface{} {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()

	return map[string]interface{}{
		"current_state":      fsm.currentState.String(),
		"primary_wan":        fsm.primaryWAN,
		"backup_wan":         fsm.backupWAN,
		"total_transitions":  atomic.LoadUint64(&fsm.totalTransitions),
		"failed_transitions": atomic.LoadUint64(&fsm.failedTransitions),
		"history_size":       len(fsm.stateHistory),
		"state_duration":     time.Since(fsm.lastTransitionTime).String(),
		"auto_recovery":      fsm.config.EnableAutoRecovery,
		"manual_override":    fsm.config.AllowManualOverride,
	}
}

// GetConfig returns the current configuration.
func (fsm *FailoverStateMachine) GetConfig() *StateMachineConfig {
	return fsm.config
}

// IsRunning returns whether the state machine is running.
func (fsm *FailoverStateMachine) IsRunning() bool {
	fsm.runningMu.Lock()
	defer fsm.runningMu.Unlock()
	return fsm.running
}

// =============================================================================
// WAN Health Callback
// =============================================================================

// OnWANHealthChange handles WAN health change events.
func (fsm *FailoverStateMachine) OnWANHealthChange(wanID string, oldHealth, newHealth float64) {
	fsm.mu.RLock()
	currentState := fsm.currentState
	primaryWAN := fsm.primaryWAN
	backupWAN := fsm.backupWAN
	autoRecovery := fsm.config.EnableAutoRecovery
	fsm.mu.RUnlock()

	metadata := map[string]interface{}{
		"wan_id":       wanID,
		"old_health":   oldHealth,
		"new_health":   newHealth,
		"triggered_by": "wan_monitor",
	}

	if wanID == primaryWAN {
		if newHealth < 40 && currentState == StatePrimaryActive {
			_ = fsm.FireEvent(EventPrimaryFailed, metadata)
		} else if newHealth >= 40 && newHealth < 70 && currentState == StatePrimaryActive {
			_ = fsm.FireEvent(EventPrimaryDegraded, metadata)
		} else if newHealth >= 70 && currentState == StatePrimaryDegraded {
			_ = fsm.FireEvent(EventPrimaryHealthy, metadata)
		} else if newHealth >= 70 && currentState == StateBackupActive && autoRecovery {
			// Schedule recovery after delay.
			go func() {
				time.Sleep(fsm.config.RecoveryDelay)
				_ = fsm.FireEvent(EventRecoveryStart, metadata)
			}()
		}
	}

	if wanID == backupWAN {
		if newHealth < 40 && currentState == StateBackupActive {
			_ = fsm.FireEvent(EventEmergency, metadata)
		} else if newHealth >= 70 {
			_ = fsm.FireEvent(EventBackupReady, metadata)
		}
	}
}
