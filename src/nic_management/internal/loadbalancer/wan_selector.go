// Package loadbalancer provides multi-WAN load balancing functionality for the NIC Management service.
package loadbalancer

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
	// ErrWANAlreadyExists indicates duplicate WAN ID.
	ErrWANAlreadyExists = errors.New("WAN already exists")
	// ErrInvalidStateTransition indicates an invalid state change.
	ErrInvalidStateTransition = errors.New("invalid state transition")
	// ErrNoEnabledWANs indicates no WANs in ENABLED/DEGRADED state.
	ErrNoEnabledWANs = errors.New("no enabled WANs available")
	// ErrDrainTimeout indicates connection drain exceeded timeout.
	ErrDrainTimeout = errors.New("drain timeout exceeded")
	// ErrPersistenceFailed indicates database state save failed.
	ErrPersistenceFailed = errors.New("state persistence failed")
)

// =============================================================================
// WAN State
// =============================================================================

// WANState represents the lifecycle state of a WAN interface.
type WANState int

const (
	// StateDiscovered indicates interface found but not validated.
	StateDiscovered WANState = iota
	// StateInitializing indicates running connectivity tests.
	StateInitializing
	// StateEnabled indicates active and handling traffic.
	StateEnabled
	// StateDegraded indicates performance degraded but usable.
	StateDegraded
	// StateCritical indicates severely degraded, minimal traffic.
	StateCritical
	// StateDisabled indicates administratively disabled.
	StateDisabled
	// StateFailed indicates connectivity lost.
	StateFailed
	// StateDraining indicates gracefully removing.
	StateDraining
)

// String returns the string representation of the state.
func (s WANState) String() string {
	switch s {
	case StateDiscovered:
		return "DISCOVERED"
	case StateInitializing:
		return "INITIALIZING"
	case StateEnabled:
		return "ENABLED"
	case StateDegraded:
		return "DEGRADED"
	case StateCritical:
		return "CRITICAL"
	case StateDisabled:
		return "DISABLED"
	case StateFailed:
		return "FAILED"
	case StateDraining:
		return "DRAINING"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// WAN Interface
// =============================================================================

// WANInterface represents a complete WAN interface with state and metadata.
type WANInterface struct {
	// ID is the unique WAN identifier (UUID).
	ID string `json:"id"`
	// InterfaceName is the OS interface name.
	InterfaceName string `json:"interface_name"`
	// DisplayName is the human-readable name.
	DisplayName string `json:"display_name"`
	// State is the current state.
	State WANState `json:"state"`
	// PreviousState is the previous state.
	PreviousState WANState `json:"previous_state"`
	// HealthScore is the current health (0-100).
	HealthScore float64 `json:"health_score"`
	// Priority is the manual priority (higher = preferred).
	Priority int `json:"priority"`
	// Weight is the manual weight override (0.0-1.0, 0=auto).
	Weight float64 `json:"weight"`
	// DiscoveredAt is when interface was first discovered.
	DiscoveredAt time.Time `json:"discovered_at"`
	// EnabledAt is when enabled for traffic.
	EnabledAt time.Time `json:"enabled_at"`
	// LastStateChange is when state last changed.
	LastStateChange time.Time `json:"last_state_change"`
	// StateChangeCount is the total state transitions.
	StateChangeCount uint64 `json:"state_change_count"`
	// ManualOverride indicates manual control mode.
	ManualOverride bool `json:"manual_override"`
	// Tags are user-defined metadata.
	Tags map[string]string `json:"tags"`
	// mu protects individual WAN state.
	mu sync.RWMutex
}

// copyWithoutMutex creates a copy of WANInterface without copying the mutex.
// This should be called while holding wan.mu.RLock().
func (w *WANInterface) copyWithoutMutex() *WANInterface {
	tagsCopy := make(map[string]string, len(w.Tags))
	for k, v := range w.Tags {
		tagsCopy[k] = v
	}
	return &WANInterface{
		ID:               w.ID,
		InterfaceName:    w.InterfaceName,
		DisplayName:      w.DisplayName,
		State:            w.State,
		PreviousState:    w.PreviousState,
		HealthScore:      w.HealthScore,
		Priority:         w.Priority,
		Weight:           w.Weight,
		DiscoveredAt:     w.DiscoveredAt,
		EnabledAt:        w.EnabledAt,
		LastStateChange:  w.LastStateChange,
		StateChangeCount: w.StateChangeCount,
		ManualOverride:   w.ManualOverride,
		Tags:             tagsCopy,
	}
}

// =============================================================================
// WAN Transition
// =============================================================================

// WANTransition represents a state change event.
type WANTransition struct {
	// WANID is the WAN that changed state.
	WANID string `json:"wan_id"`
	// OldState is the previous state.
	OldState WANState `json:"old_state"`
	// NewState is the new state.
	NewState WANState `json:"new_state"`
	// Reason is why transition occurred.
	Reason string `json:"reason"`
	// HealthScore is health at time of transition.
	HealthScore float64 `json:"health_score"`
	// Timestamp is when transition occurred.
	Timestamp time.Time `json:"timestamp"`
	// TriggeredBy is who/what triggered.
	TriggeredBy string `json:"triggered_by"`
}

// =============================================================================
// Selection Context
// =============================================================================

// SelectionContext provides per-request filtering context.
type SelectionContext struct {
	// RequireMinHealth is the minimum health score required.
	RequireMinHealth float64
	// RequireMinBandwidth is the minimum bandwidth required (bps).
	RequireMinBandwidth uint64
	// ExcludeWANs are WAN IDs to exclude.
	ExcludeWANs []string
	// PreferredWANs are WAN IDs to prefer.
	PreferredWANs []string
	// RequireTags are tags WAN must have.
	RequireTags map[string]string
	// Protocol is the IP protocol for routing.
	Protocol uint8
}

// =============================================================================
// WAN Selector Configuration
// =============================================================================

// WANSelectorConfig contains configuration for the WAN selector.
type WANSelectorConfig struct {
	// AutoEnable automatically enables newly discovered WANs.
	AutoEnable bool `json:"auto_enable"`
	// HealthCheckTimeout is max time for initial health check.
	HealthCheckTimeout time.Duration `json:"health_check_timeout"`
	// MinUptimeBeforeEnable requires stability before enabling.
	MinUptimeBeforeEnable time.Duration `json:"min_uptime_before_enable"`
	// DegradedThreshold is health score triggering degraded state.
	DegradedThreshold float64 `json:"degraded_threshold"`
	// CriticalThreshold is health score triggering critical state.
	CriticalThreshold float64 `json:"critical_threshold"`
	// FailedThreshold is health score triggering failed state.
	FailedThreshold float64 `json:"failed_threshold"`
	// StateTransitionCooldown is minimum time between state changes.
	StateTransitionCooldown time.Duration `json:"state_transition_cooldown"`
	// DrainTimeout is max time for connection draining.
	DrainTimeout time.Duration `json:"drain_timeout"`
	// EnableStatePersistence saves states to database.
	EnableStatePersistence bool `json:"enable_state_persistence"`
	// PersistenceInterval is how often to sync states to DB.
	PersistenceInterval time.Duration `json:"persistence_interval"`
}

// DefaultWANSelectorConfig returns the default configuration.
func DefaultWANSelectorConfig() *WANSelectorConfig {
	return &WANSelectorConfig{
		AutoEnable:              true,
		HealthCheckTimeout:      30 * time.Second,
		MinUptimeBeforeEnable:   60 * time.Second,
		DegradedThreshold:       40.0,
		CriticalThreshold:       20.0,
		FailedThreshold:         10.0,
		StateTransitionCooldown: 10 * time.Second,
		DrainTimeout:            300 * time.Second,
		EnableStatePersistence:  true,
		PersistenceInterval:     30 * time.Second,
	}
}

// =============================================================================
// WAN State Subscriber
// =============================================================================

// WANStateSubscriber defines the interface for state change notifications.
type WANStateSubscriber interface {
	// OnWANStateChange is called when a WAN state changes.
	OnWANStateChange(transition *WANTransition) error
}

// =============================================================================
// Database Interface
// =============================================================================

// WANSelectorDB defines the database interface for state persistence.
type WANSelectorDB interface {
	// LoadWANStates loads all WAN states from database.
	LoadWANStates(ctx context.Context) ([]*WANInterface, error)
	// SaveWANState saves a WAN state to database.
	SaveWANState(ctx context.Context, wan *WANInterface) error
	// DeleteWANState removes a WAN from database.
	DeleteWANState(ctx context.Context, wanID string) error
	// SaveTransition saves a state transition.
	SaveTransition(ctx context.Context, transition *WANTransition) error
}

// =============================================================================
// No-Op Database
// =============================================================================

type noOpWANDB struct{}

func (n *noOpWANDB) LoadWANStates(ctx context.Context) ([]*WANInterface, error) {
	return nil, nil
}

func (n *noOpWANDB) SaveWANState(ctx context.Context, wan *WANInterface) error {
	return nil
}

func (n *noOpWANDB) DeleteWANState(ctx context.Context, wanID string) error {
	return nil
}

func (n *noOpWANDB) SaveTransition(ctx context.Context, transition *WANTransition) error {
	return nil
}

// =============================================================================
// WAN Selector
// =============================================================================

// WANSelector manages the WAN pool and lifecycle.
type WANSelector struct {
	// WAN pool (key: WAN ID).
	wanPool map[string]*WANInterface
	// Metrics collector.
	metricsCollector *MetricsCollector
	// Database for persistence.
	db WANSelectorDB
	// Configuration.
	config *WANSelectorConfig
	// Protects wanPool.
	mu sync.RWMutex
	// State change subscribers.
	subscribers   []WANStateSubscriber
	subscribersMu sync.RWMutex
	// State history.
	stateHistory   []*WANTransition
	stateHistoryMu sync.RWMutex
	// Control.
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	runningMu sync.Mutex
	// WAN ID counter for generation.
	wanCounter uint64
}

// NewWANSelector creates a new WAN selector.
func NewWANSelector(metricsCollector *MetricsCollector, db WANSelectorDB, config *WANSelectorConfig) *WANSelector {
	if config == nil {
		config = DefaultWANSelectorConfig()
	}

	if db == nil {
		db = &noOpWANDB{}
	}

	return &WANSelector{
		wanPool:          make(map[string]*WANInterface),
		metricsCollector: metricsCollector,
		db:               db,
		config:           config,
		subscribers:      make([]WANStateSubscriber, 0),
		stateHistory:     make([]*WANTransition, 0, 1000),
		stopChan:         make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start starts the WAN selector.
func (ws *WANSelector) Start(ctx context.Context) error {
	ws.runningMu.Lock()
	defer ws.runningMu.Unlock()

	if ws.running {
		return nil
	}

	// Load persisted states.
	if ws.config.EnableStatePersistence {
		states, _ := ws.db.LoadWANStates(ctx)
		for _, wan := range states {
			ws.wanPool[wan.ID] = wan
		}
	}

	// Start state monitoring.
	ws.wg.Add(1)
	go ws.stateMonitorLoop()

	// Start persistence loop.
	if ws.config.EnableStatePersistence {
		ws.wg.Add(1)
		go ws.persistenceLoop()
	}

	ws.running = true
	return nil
}

// Stop stops the WAN selector.
func (ws *WANSelector) Stop() error {
	ws.runningMu.Lock()
	if !ws.running {
		ws.runningMu.Unlock()
		return nil
	}
	ws.running = false
	ws.runningMu.Unlock()

	close(ws.stopChan)
	ws.wg.Wait()

	// Final persistence.
	if ws.config.EnableStatePersistence {
		ws.persistWANStates()
	}

	return nil
}

// stateMonitorLoop monitors health scores for state transitions.
func (ws *WANSelector) stateMonitorLoop() {
	defer ws.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ws.stopChan:
			return
		case <-ticker.C:
			ws.checkStateTransitions()
		}
	}
}

// persistenceLoop periodically persists WAN states.
func (ws *WANSelector) persistenceLoop() {
	defer ws.wg.Done()

	ticker := time.NewTicker(ws.config.PersistenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ws.stopChan:
			return
		case <-ticker.C:
			ws.persistWANStates()
		}
	}
}

// =============================================================================
// WAN Discovery
// =============================================================================

// AddWAN adds a new WAN interface to the pool.
func (ws *WANSelector) AddWAN(interfaceName, displayName string) (*WANInterface, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Check for duplicate interface name.
	for _, wan := range ws.wanPool {
		if wan.InterfaceName == interfaceName {
			return nil, ErrWANAlreadyExists
		}
	}

	// Generate unique ID.
	ws.wanCounter++
	wanID := interfaceName // Use interface name as ID for simplicity.

	now := time.Now()
	wan := &WANInterface{
		ID:              wanID,
		InterfaceName:   interfaceName,
		DisplayName:     displayName,
		State:           StateDiscovered,
		DiscoveredAt:    now,
		LastStateChange: now,
		Priority:        1,
		Tags:            make(map[string]string),
	}

	ws.wanPool[wanID] = wan

	// Notify subscribers.
	transition := &WANTransition{
		WANID:       wanID,
		OldState:    -1, // No previous state.
		NewState:    StateDiscovered,
		Reason:      "DISCOVERED",
		Timestamp:   now,
		TriggeredBy: "system",
	}
	ws.recordTransition(transition)
	ws.notifySubscribers(transition)

	// Add to metrics collector.
	if ws.metricsCollector != nil {
		_ = ws.metricsCollector.AddWAN(wanID, interfaceName)
	}

	// Auto-enable if configured.
	if ws.config.AutoEnable {
		go ws.initializeAndEnableWAN(context.Background(), wanID)
	}

	return wan, nil
}

// RemoveWAN removes a WAN from the pool.
func (ws *WANSelector) RemoveWAN(ctx context.Context, wanID string) error {
	ws.mu.Lock()
	wan, exists := ws.wanPool[wanID]
	if !exists {
		ws.mu.Unlock()
		return ErrWANNotFound
	}

	// If enabled, disable first.
	if wan.State == StateEnabled || wan.State == StateDegraded || wan.State == StateCritical {
		ws.mu.Unlock()
		if err := ws.DisableWAN(ctx, wanID, "REMOVAL"); err != nil {
			return err
		}
		ws.mu.Lock()
	}

	// Remove from pool.
	delete(ws.wanPool, wanID)
	ws.mu.Unlock()

	// Remove from metrics collector.
	if ws.metricsCollector != nil {
		_ = ws.metricsCollector.RemoveWAN(wanID)
	}

	// Remove from database.
	if ws.config.EnableStatePersistence {
		_ = ws.db.DeleteWANState(ctx, wanID)
	}

	return nil
}

// =============================================================================
// WAN Initialization
// =============================================================================

// initializeAndEnableWAN validates and enables a newly discovered WAN.
func (ws *WANSelector) initializeAndEnableWAN(ctx context.Context, wanID string) {
	// Transition to initializing.
	_ = ws.transitionWANState(wanID, StateInitializing, "AUTO_INIT", "system")

	// Wait for minimum uptime.
	select {
	case <-ctx.Done():
		return
	case <-time.After(ws.config.MinUptimeBeforeEnable):
	}

	// Check health.
	if ws.metricsCollector != nil {
		health, err := ws.metricsCollector.GetHealthScore(wanID)
		if err != nil || health < ws.config.FailedThreshold {
			_ = ws.transitionWANState(wanID, StateFailed, "HEALTH_CHECK_FAILED", "system")
			return
		}
	}

	// Enable.
	_ = ws.EnableWAN(wanID)
}

// =============================================================================
// WAN Enable/Disable
// =============================================================================

// EnableWAN enables a WAN for traffic handling.
func (ws *WANSelector) EnableWAN(wanID string) error {
	ws.mu.Lock()
	wan, exists := ws.wanPool[wanID]
	if !exists {
		ws.mu.Unlock()
		return ErrWANNotFound
	}

	// Validate current state.
	wan.mu.Lock()
	currentState := wan.State
	if !isValidTransition(currentState, StateEnabled) {
		wan.mu.Unlock()
		ws.mu.Unlock()
		return ErrInvalidStateTransition
	}

	wan.PreviousState = currentState
	wan.State = StateEnabled
	wan.EnabledAt = time.Now()
	wan.LastStateChange = time.Now()
	wan.StateChangeCount++
	wan.mu.Unlock()
	ws.mu.Unlock()

	// Notify and persist.
	transition := &WANTransition{
		WANID:       wanID,
		OldState:    currentState,
		NewState:    StateEnabled,
		Reason:      "ENABLED",
		Timestamp:   time.Now(),
		TriggeredBy: "admin",
	}
	ws.recordTransition(transition)
	ws.notifySubscribers(transition)
	ws.persistWANState(wanID)

	return nil
}

// DisableWAN disables a WAN gracefully.
func (ws *WANSelector) DisableWAN(ctx context.Context, wanID string, reason string) error {
	ws.mu.Lock()
	wan, exists := ws.wanPool[wanID]
	if !exists {
		ws.mu.Unlock()
		return ErrWANNotFound
	}

	wan.mu.Lock()
	currentState := wan.State
	if currentState != StateEnabled && currentState != StateDegraded && currentState != StateCritical {
		wan.mu.Unlock()
		ws.mu.Unlock()
		return ErrInvalidStateTransition
	}

	// Transition to draining.
	wan.PreviousState = currentState
	wan.State = StateDraining
	wan.LastStateChange = time.Now()
	wan.StateChangeCount++
	wan.mu.Unlock()
	ws.mu.Unlock()

	// Notify draining.
	transition := &WANTransition{
		WANID:       wanID,
		OldState:    currentState,
		NewState:    StateDraining,
		Reason:      "DRAINING",
		Timestamp:   time.Now(),
		TriggeredBy: reason,
	}
	ws.recordTransition(transition)
	ws.notifySubscribers(transition)

	// Wait for drain timeout.
	select {
	case <-ctx.Done():
	case <-time.After(ws.config.DrainTimeout):
	}

	// Transition to disabled.
	ws.mu.Lock()
	wan, exists = ws.wanPool[wanID]
	if exists {
		wan.mu.Lock()
		wan.PreviousState = StateDraining
		wan.State = StateDisabled
		wan.LastStateChange = time.Now()
		wan.StateChangeCount++
		wan.mu.Unlock()
	}
	ws.mu.Unlock()

	// Notify disabled.
	transition = &WANTransition{
		WANID:       wanID,
		OldState:    StateDraining,
		NewState:    StateDisabled,
		Reason:      reason,
		Timestamp:   time.Now(),
		TriggeredBy: reason,
	}
	ws.recordTransition(transition)
	ws.notifySubscribers(transition)
	ws.persistWANState(wanID)

	return nil
}

// DrainWAN transitions to draining without waiting.
func (ws *WANSelector) DrainWAN(wanID string) error {
	return ws.transitionWANState(wanID, StateDraining, "DRAIN_REQUESTED", "admin")
}

// =============================================================================
// State Transitions
// =============================================================================

// transitionWANState executes a state transition.
func (ws *WANSelector) transitionWANState(wanID string, newState WANState, reason, triggeredBy string) error {
	ws.mu.Lock()
	wan, exists := ws.wanPool[wanID]
	if !exists {
		ws.mu.Unlock()
		return ErrWANNotFound
	}

	wan.mu.Lock()
	currentState := wan.State

	// Validate transition.
	if !isValidTransition(currentState, newState) {
		wan.mu.Unlock()
		ws.mu.Unlock()
		return ErrInvalidStateTransition
	}

	// Check cooldown.
	if time.Since(wan.LastStateChange) < ws.config.StateTransitionCooldown {
		wan.mu.Unlock()
		ws.mu.Unlock()
		return nil // Skip, still in cooldown.
	}

	// Execute transition.
	wan.PreviousState = currentState
	wan.State = newState
	wan.LastStateChange = time.Now()
	wan.StateChangeCount++

	if newState == StateEnabled && wan.EnabledAt.IsZero() {
		wan.EnabledAt = time.Now()
	}

	wan.mu.Unlock()
	ws.mu.Unlock()

	// Record and notify.
	transition := &WANTransition{
		WANID:       wanID,
		OldState:    currentState,
		NewState:    newState,
		Reason:      reason,
		Timestamp:   time.Now(),
		TriggeredBy: triggeredBy,
	}
	ws.recordTransition(transition)
	ws.notifySubscribers(transition)
	ws.persistWANState(wanID)

	return nil
}

// isValidTransition validates a state machine transition.
func isValidTransition(from, to WANState) bool {
	validTransitions := map[WANState][]WANState{
		StateDiscovered:   {StateInitializing, StateFailed, StateDisabled},
		StateInitializing: {StateEnabled, StateFailed, StateDisabled},
		StateEnabled:      {StateDegraded, StateCritical, StateFailed, StateDisabled, StateDraining},
		StateDegraded:     {StateEnabled, StateCritical, StateFailed, StateDisabled, StateDraining},
		StateCritical:     {StateDegraded, StateEnabled, StateFailed, StateDisabled, StateDraining},
		StateDraining:     {StateDisabled},
		StateDisabled:     {StateInitializing, StateEnabled},
		StateFailed:       {StateInitializing, StateDisabled},
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}

	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// checkStateTransitions monitors health and triggers state changes.
func (ws *WANSelector) checkStateTransitions() {
	if ws.metricsCollector == nil {
		return
	}

	ws.mu.RLock()
	wanIDs := make([]string, 0, len(ws.wanPool))
	for id, wan := range ws.wanPool {
		if wan.State == StateEnabled || wan.State == StateDegraded || wan.State == StateCritical {
			wanIDs = append(wanIDs, id)
		}
	}
	ws.mu.RUnlock()

	for _, wanID := range wanIDs {
		health, err := ws.metricsCollector.GetHealthScore(wanID)
		if err != nil {
			continue
		}

		ws.mu.RLock()
		wan, exists := ws.wanPool[wanID]
		ws.mu.RUnlock()
		if !exists {
			continue
		}

		wan.mu.Lock()
		wan.HealthScore = health
		currentState := wan.State
		wan.mu.Unlock()

		// Determine target state based on health.
		var targetState WANState
		var reason string

		if health < ws.config.FailedThreshold {
			targetState = StateFailed
			reason = "HEALTH_FAILED"
		} else if health < ws.config.CriticalThreshold {
			targetState = StateCritical
			reason = "HEALTH_CRITICAL"
		} else if health < ws.config.DegradedThreshold {
			targetState = StateDegraded
			reason = "HEALTH_DEGRADED"
		} else {
			targetState = StateEnabled
			reason = "HEALTH_RECOVERED"
		}

		// Transition if needed.
		if targetState != currentState {
			_ = ws.transitionWANState(wanID, targetState, reason, "health_monitor")
		}
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetAvailableWANs returns WANs eligible for routing.
func (ws *WANSelector) GetAvailableWANs() []*WANInterface {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	result := make([]*WANInterface, 0, len(ws.wanPool))
	for _, wan := range ws.wanPool {
		wan.mu.RLock()
		if wan.State == StateEnabled || wan.State == StateDegraded {
			// Create a copy without mutex.
			wanCopy := wan.copyWithoutMutex()
			result = append(result, wanCopy)
		}
		wan.mu.RUnlock()
	}

	return result
}

// GetWANByID retrieves a specific WAN.
func (ws *WANSelector) GetWANByID(wanID string) (*WANInterface, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	wan, exists := ws.wanPool[wanID]
	if !exists {
		return nil, ErrWANNotFound
	}

	wan.mu.RLock()
	wanCopy := wan.copyWithoutMutex()
	wan.mu.RUnlock()

	return wanCopy, nil
}

// GetWANByInterface retrieves WAN by OS interface name.
func (ws *WANSelector) GetWANByInterface(interfaceName string) (*WANInterface, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	for _, wan := range ws.wanPool {
		wan.mu.RLock()
		if wan.InterfaceName == interfaceName {
			wanCopy := wan.copyWithoutMutex()
			wan.mu.RUnlock()
			return wanCopy, nil
		}
		wan.mu.RUnlock()
	}

	return nil, ErrWANNotFound
}

// GetAllWANs returns all WANs including disabled/failed.
func (ws *WANSelector) GetAllWANs() []*WANInterface {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	result := make([]*WANInterface, 0, len(ws.wanPool))
	for _, wan := range ws.wanPool {
		wan.mu.RLock()
		wanCopy := wan.copyWithoutMutex()
		wan.mu.RUnlock()
		result = append(result, wanCopy)
	}

	return result
}

// FilterWANs returns WANs matching criteria.
func (ws *WANSelector) FilterWANs(ctx SelectionContext) []*WANInterface {
	available := ws.GetAvailableWANs()
	result := make([]*WANInterface, 0, len(available))

	excludeSet := make(map[string]bool)
	for _, id := range ctx.ExcludeWANs {
		excludeSet[id] = true
	}

	for _, wan := range available {
		// Check exclusions.
		if excludeSet[wan.ID] {
			continue
		}

		// Check minimum health.
		if ctx.RequireMinHealth > 0 && wan.HealthScore < ctx.RequireMinHealth {
			continue
		}

		// Check tags.
		if len(ctx.RequireTags) > 0 {
			match := true
			for k, v := range ctx.RequireTags {
				if wan.Tags[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		result = append(result, wan)
	}

	return result
}

// =============================================================================
// Priority and Weight Management
// =============================================================================

// SetWANPriority sets the priority for a WAN.
func (ws *WANSelector) SetWANPriority(wanID string, priority int) error {
	if priority < 1 {
		return errors.New("priority must be >= 1")
	}

	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return ErrWANNotFound
	}

	wan.mu.Lock()
	wan.Priority = priority
	wan.mu.Unlock()

	ws.persistWANState(wanID)
	return nil
}

// SetWANWeight sets the manual weight for a WAN.
func (ws *WANSelector) SetWANWeight(wanID string, weight float64) error {
	if weight < 0 || weight > 1 {
		return errors.New("weight must be between 0 and 1")
	}

	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return ErrWANNotFound
	}

	wan.mu.Lock()
	wan.Weight = weight
	wan.ManualOverride = weight > 0
	wan.mu.Unlock()

	ws.persistWANState(wanID)
	return nil
}

// =============================================================================
// Manual Failover
// =============================================================================

// ManualFailover forces traffic migration from one WAN to another.
func (ws *WANSelector) ManualFailover(ctx context.Context, fromWAN, toWAN string) error {
	// Validate source WAN.
	from, err := ws.GetWANByID(fromWAN)
	if err != nil {
		return err
	}
	if from.State != StateEnabled && from.State != StateDegraded && from.State != StateCritical {
		return ErrInvalidStateTransition
	}

	// Validate destination WAN.
	to, err := ws.GetWANByID(toWAN)
	if err != nil {
		return err
	}
	if to.State != StateEnabled && to.State != StateDegraded {
		return ErrInvalidStateTransition
	}

	// Drain source.
	if err := ws.DrainWAN(fromWAN); err != nil {
		return err
	}

	// Disable source.
	if err := ws.DisableWAN(ctx, fromWAN, "MANUAL_FAILOVER"); err != nil {
		return err
	}

	return nil
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe adds a subscriber for state changes.
func (ws *WANSelector) Subscribe(subscriber WANStateSubscriber) {
	ws.subscribersMu.Lock()
	defer ws.subscribersMu.Unlock()
	ws.subscribers = append(ws.subscribers, subscriber)
}

// Unsubscribe removes a subscriber.
func (ws *WANSelector) Unsubscribe(subscriber WANStateSubscriber) {
	ws.subscribersMu.Lock()
	defer ws.subscribersMu.Unlock()

	for i, s := range ws.subscribers {
		if s == subscriber {
			ws.subscribers = append(ws.subscribers[:i], ws.subscribers[i+1:]...)
			return
		}
	}
}

// notifySubscribers notifies all subscribers of state changes.
func (ws *WANSelector) notifySubscribers(transition *WANTransition) {
	ws.subscribersMu.RLock()
	subscribers := make([]WANStateSubscriber, len(ws.subscribers))
	copy(subscribers, ws.subscribers)
	ws.subscribersMu.RUnlock()

	for _, sub := range subscribers {
		go func(s WANStateSubscriber) {
			_ = s.OnWANStateChange(transition)
		}(sub)
	}
}

// =============================================================================
// State History
// =============================================================================

// recordTransition records a state transition.
func (ws *WANSelector) recordTransition(transition *WANTransition) {
	ws.stateHistoryMu.Lock()
	defer ws.stateHistoryMu.Unlock()

	ws.stateHistory = append(ws.stateHistory, transition)

	// Limit history size.
	if len(ws.stateHistory) > 1000 {
		ws.stateHistory = ws.stateHistory[len(ws.stateHistory)-1000:]
	}
}

// GetStateHistory returns state transition history.
func (ws *WANSelector) GetStateHistory(wanID string) []*WANTransition {
	ws.stateHistoryMu.RLock()
	defer ws.stateHistoryMu.RUnlock()

	if wanID == "" {
		result := make([]*WANTransition, len(ws.stateHistory))
		copy(result, ws.stateHistory)
		return result
	}

	result := make([]*WANTransition, 0)
	for _, t := range ws.stateHistory {
		if t.WANID == wanID {
			result = append(result, t)
		}
	}
	return result
}

// =============================================================================
// Tag Management
// =============================================================================

// SetWANTag sets a tag on a WAN.
func (ws *WANSelector) SetWANTag(wanID, key, value string) error {
	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return ErrWANNotFound
	}

	wan.mu.Lock()
	if wan.Tags == nil {
		wan.Tags = make(map[string]string)
	}
	wan.Tags[key] = value
	wan.mu.Unlock()

	ws.persistWANState(wanID)
	return nil
}

// GetWANTag gets a tag from a WAN.
func (ws *WANSelector) GetWANTag(wanID, key string) (string, error) {
	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return "", ErrWANNotFound
	}

	wan.mu.RLock()
	value := wan.Tags[key]
	wan.mu.RUnlock()

	return value, nil
}

// DeleteWANTag deletes a tag from a WAN.
func (ws *WANSelector) DeleteWANTag(wanID, key string) error {
	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return ErrWANNotFound
	}

	wan.mu.Lock()
	delete(wan.Tags, key)
	wan.mu.Unlock()

	ws.persistWANState(wanID)
	return nil
}

// =============================================================================
// Persistence
// =============================================================================

// persistWANStates saves all WAN states to database.
func (ws *WANSelector) persistWANStates() {
	if !ws.config.EnableStatePersistence {
		return
	}

	ws.mu.RLock()
	wans := make([]*WANInterface, 0, len(ws.wanPool))
	for _, wan := range ws.wanPool {
		wan.mu.RLock()
		wanCopy := wan.copyWithoutMutex()
		wan.mu.RUnlock()
		wans = append(wans, wanCopy)
	}
	ws.mu.RUnlock()

	ctx := context.Background()
	for _, wan := range wans {
		_ = ws.db.SaveWANState(ctx, wan)
	}
}

// persistWANState saves a single WAN state.
func (ws *WANSelector) persistWANState(wanID string) {
	if !ws.config.EnableStatePersistence {
		return
	}

	ws.mu.RLock()
	wan, exists := ws.wanPool[wanID]
	ws.mu.RUnlock()

	if !exists {
		return
	}

	wan.mu.RLock()
	wanCopy := wan.copyWithoutMutex()
	wan.mu.RUnlock()

	ctx := context.Background()
	_ = ws.db.SaveWANState(ctx, wanCopy)
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the WAN selector is operational.
func (ws *WANSelector) HealthCheck() error {
	ws.runningMu.Lock()
	running := ws.running
	ws.runningMu.Unlock()

	if !running {
		return errors.New("WAN selector not running")
	}

	ws.mu.RLock()
	count := len(ws.wanPool)
	ws.mu.RUnlock()

	if count == 0 {
		return ErrNoEnabledWANs
	}

	// Check for at least one enabled WAN.
	available := ws.GetAvailableWANs()
	if len(available) == 0 {
		return ErrNoEnabledWANs
	}

	return nil
}

// =============================================================================
// Utility
// =============================================================================

// GetConfig returns the current configuration.
func (ws *WANSelector) GetConfig() *WANSelectorConfig {
	return ws.config
}

// IsRunning returns whether the selector is running.
func (ws *WANSelector) IsRunning() bool {
	ws.runningMu.Lock()
	defer ws.runningMu.Unlock()
	return ws.running
}

// GetWANCount returns the number of WANs in the pool.
func (ws *WANSelector) GetWANCount() int {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	return len(ws.wanPool)
}

// GetEnabledWANCount returns the number of enabled WANs.
func (ws *WANSelector) GetEnabledWANCount() int {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	count := 0
	for _, wan := range ws.wanPool {
		wan.mu.RLock()
		if wan.State == StateEnabled || wan.State == StateDegraded {
			count++
		}
		wan.mu.RUnlock()
	}
	return count
}
