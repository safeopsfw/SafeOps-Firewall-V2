// Package wfp provides a high-level, safe Go API for Windows Filtering Platform.
// It wraps the low-level bindings in internal/wfp/bindings with additional features
// like health monitoring, automatic reconnection, and graceful degradation.
package wfp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/wfp/bindings"
)

// ============================================================================
// Engine States
// ============================================================================

// EngineState represents the current state of the WFP engine.
type EngineState int32

const (
	// EngineStateClosed indicates the engine is not connected.
	EngineStateClosed EngineState = iota
	// EngineStateOpening indicates the engine is currently opening.
	EngineStateOpening
	// EngineStateOpen indicates the engine is connected and healthy.
	EngineStateOpen
	// EngineStateDegraded indicates the engine is running in degraded mode.
	EngineStateDegraded
	// EngineStateReconnecting indicates the engine is attempting to reconnect.
	EngineStateReconnecting
	// EngineStateClosing indicates the engine is shutting down.
	EngineStateClosing
)

// String returns the string representation of the engine state.
func (s EngineState) String() string {
	switch s {
	case EngineStateClosed:
		return "closed"
	case EngineStateOpening:
		return "opening"
	case EngineStateOpen:
		return "open"
	case EngineStateDegraded:
		return "degraded"
	case EngineStateReconnecting:
		return "reconnecting"
	case EngineStateClosing:
		return "closing"
	default:
		return "unknown"
	}
}

// ============================================================================
// Engine Configuration
// ============================================================================

// EngineConfig contains configuration options for the WFP engine.
type EngineConfig struct {
	// SessionName is the display name for the WFP session.
	SessionName string

	// SessionDescription is the description for the WFP session.
	SessionDescription string

	// Dynamic indicates if filters should be deleted when the session closes.
	// If true (default), all filters are automatically removed on close.
	Dynamic bool

	// TransactionTimeout is the timeout for WFP transactions in milliseconds.
	TransactionTimeout uint32

	// HealthCheckInterval is how often to check engine health.
	// Default: 30 seconds. Set to 0 to disable health checks.
	HealthCheckInterval time.Duration

	// MaxReconnectAttempts is the maximum number of reconnection attempts.
	// Default: 3. Set to 0 to disable reconnection.
	MaxReconnectAttempts int

	// ReconnectBackoff is the initial backoff duration between reconnection attempts.
	// Default: 1 second. Backoff doubles after each attempt.
	ReconnectBackoff time.Duration

	// OnStateChange is called whenever the engine state changes.
	OnStateChange func(oldState, newState EngineState)

	// OnFilterInstalled is called whenever a filter is successfully installed.
	OnFilterInstalled func(ruleID string, filterID uint64)

	// OnFilterRemoved is called whenever a filter is removed.
	OnFilterRemoved func(ruleID string)

	// Logger for engine events. If nil, uses default log package.
	Logger Logger
}

// DefaultEngineConfig returns a configuration with sensible defaults.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		SessionName:          "SafeOps Firewall Engine",
		SessionDescription:   "SafeOps Firewall WFP Integration",
		Dynamic:              true,
		TransactionTimeout:   5000,
		HealthCheckInterval:  30 * time.Second,
		MaxReconnectAttempts: 3,
		ReconnectBackoff:     1 * time.Second,
	}
}

// Logger interface for engine logging.
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// defaultLogger wraps the standard log package.
type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, args ...interface{}) {
	log.Printf("[DEBUG] WFP: "+msg, args...)
}

func (l *defaultLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] WFP: "+msg, args...)
}

func (l *defaultLogger) Warn(msg string, args ...interface{}) {
	log.Printf("[WARN] WFP: "+msg, args...)
}

func (l *defaultLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] WFP: "+msg, args...)
}

// ============================================================================
// WFP Engine
// ============================================================================

// Engine provides a high-level, thread-safe interface to Windows Filtering Platform.
// It wraps the low-level bindings.Engine with additional features:
//   - Automatic health monitoring
//   - Reconnection on failure
//   - Graceful degradation
//   - State change callbacks
//   - Enhanced logging
type Engine struct {
	// Configuration
	config *EngineConfig
	logger Logger

	// Low-level bindings engine
	bindings *bindings.Engine

	// State management
	state          int32 // atomic, use EngineState type
	mu             sync.RWMutex
	reconnectCount int

	// Health monitoring
	healthCtx    context.Context
	healthCancel context.CancelFunc
	healthWg     sync.WaitGroup

	// Filter tracking (ruleID -> filterID)
	filterIDs   map[string]uint64
	filterMu    sync.RWMutex
	filterCount int64 // atomic

	// Statistics
	stats EngineStats
}

// EngineStats contains operational statistics.
type EngineStats struct {
	// Connection stats
	OpenTime            time.Time
	LastHealthCheck     time.Time
	HealthCheckCount    int64
	HealthCheckFailures int64
	ReconnectAttempts   int64
	ReconnectSuccesses  int64

	// Filter stats
	FiltersAdded   int64
	FiltersRemoved int64
	FiltersFailed  int64
}

// NewEngine creates a new WFP engine with the given configuration.
// Call Open() to establish a connection to WFP.
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}

	logger := config.Logger
	if logger == nil {
		logger = &defaultLogger{}
	}

	return &Engine{
		config:    config,
		logger:    logger,
		bindings:  bindings.NewEngine(),
		state:     int32(EngineStateClosed),
		filterIDs: make(map[string]uint64),
	}
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Open establishes a connection to the WFP engine.
// Returns an error if the engine is already open or if admin privileges are missing.
func (e *Engine) Open() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	currentState := EngineState(atomic.LoadInt32(&e.state))
	if currentState != EngineStateClosed {
		return fmt.Errorf("engine is not closed (current state: %s)", currentState)
	}

	e.setState(EngineStateOpening)
	e.logger.Info("Opening WFP engine...")

	// Create session configuration
	session := e.createSession()

	// Attempt to open the engine
	if err := e.bindings.Open(session); err != nil {
		e.setState(EngineStateClosed)

		// Check if it's an elevation error
		if errors.Is(err, bindings.ErrNotElevated) {
			e.logger.Warn("WFP requires administrator privileges - running in degraded mode")
			e.setState(EngineStateDegraded)
			return nil // Graceful degradation - not a fatal error
		}

		return fmt.Errorf("failed to open WFP engine: %w", err)
	}

	// Initialize SafeOps provider and sublayer
	if err := e.bindings.InitializeSafeOps(); err != nil {
		e.logger.Warn("Failed to initialize SafeOps provider: %v", err)
		// Continue anyway - filters will work without custom provider
	}

	e.stats.OpenTime = time.Now()
	e.setState(EngineStateOpen)
	e.logger.Info("WFP engine opened successfully")

	// Start health monitoring if enabled
	if e.config.HealthCheckInterval > 0 {
		e.startHealthMonitor()
	}

	return nil
}

// Close shuts down the WFP engine and releases all resources.
// All dynamic filters are automatically removed.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	currentState := EngineState(atomic.LoadInt32(&e.state))
	if currentState == EngineStateClosed || currentState == EngineStateClosing {
		return nil
	}

	e.setState(EngineStateClosing)
	e.logger.Info("Closing WFP engine...")

	// Stop health monitoring
	e.stopHealthMonitor()

	// Skip cleanup if in degraded mode (never fully opened)
	if currentState == EngineStateDegraded {
		e.setState(EngineStateClosed)
		e.logger.Info("WFP engine closed (was in degraded mode)")
		return nil
	}

	// Cleanup SafeOps resources
	if err := e.bindings.CleanupSafeOps(); err != nil {
		e.logger.Warn("Error cleaning up SafeOps: %v", err)
	}

	// Close the underlying engine
	if err := e.bindings.Close(); err != nil {
		e.setState(EngineStateClosed)
		return fmt.Errorf("failed to close WFP engine: %w", err)
	}

	// Clear filter tracking
	e.filterMu.Lock()
	e.filterIDs = make(map[string]uint64)
	atomic.StoreInt64(&e.filterCount, 0)
	e.filterMu.Unlock()

	e.setState(EngineStateClosed)
	e.logger.Info("WFP engine closed successfully")

	return nil
}

// IsOpen returns true if the engine is connected and operational.
func (e *Engine) IsOpen() bool {
	state := EngineState(atomic.LoadInt32(&e.state))
	return state == EngineStateOpen
}

// IsDegraded returns true if the engine is in degraded mode.
func (e *Engine) IsDegraded() bool {
	state := EngineState(atomic.LoadInt32(&e.state))
	return state == EngineStateDegraded
}

// State returns the current engine state.
func (e *Engine) State() EngineState {
	return EngineState(atomic.LoadInt32(&e.state))
}

// ============================================================================
// Session Management
// ============================================================================

// createSession creates a WFP session configuration from engine config.
func (e *Engine) createSession() *bindings.FWPM_SESSION0 {
	if e.config.Dynamic {
		session := bindings.NewDynamicSession()
		session.DisplayData = bindings.NewDisplayData(
			e.config.SessionName,
			e.config.SessionDescription,
		)
		session.TransactionWaitTimeoutMs = e.config.TransactionTimeout
		return session
	}

	session := bindings.NewPersistentSession()
	session.DisplayData = bindings.NewDisplayData(
		e.config.SessionName,
		e.config.SessionDescription,
	)
	session.TransactionWaitTimeoutMs = e.config.TransactionTimeout
	return session
}

// ============================================================================
// Health Monitoring
// ============================================================================

// startHealthMonitor starts the background health check goroutine.
func (e *Engine) startHealthMonitor() {
	if e.healthCancel != nil {
		return // Already running
	}

	e.healthCtx, e.healthCancel = context.WithCancel(context.Background())
	e.healthWg.Add(1)

	go func() {
		defer e.healthWg.Done()
		e.runHealthMonitor()
	}()

	e.logger.Debug("Health monitor started (interval: %v)", e.config.HealthCheckInterval)
}

// stopHealthMonitor stops the background health check goroutine.
func (e *Engine) stopHealthMonitor() {
	if e.healthCancel == nil {
		return
	}

	e.healthCancel()
	e.healthWg.Wait()
	e.healthCancel = nil
	e.healthCtx = nil

	e.logger.Debug("Health monitor stopped")
}

// runHealthMonitor performs periodic health checks.
func (e *Engine) runHealthMonitor() {
	ticker := time.NewTicker(e.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.healthCtx.Done():
			return
		case <-ticker.C:
			e.performHealthCheck()
		}
	}
}

// performHealthCheck checks if the WFP engine is still operational.
func (e *Engine) performHealthCheck() {
	e.mu.RLock()
	state := EngineState(atomic.LoadInt32(&e.state))
	e.mu.RUnlock()

	// Only check health when engine is supposed to be open
	if state != EngineStateOpen {
		return
	}

	atomic.AddInt64(&e.stats.HealthCheckCount, 1)
	e.stats.LastHealthCheck = time.Now()

	// Check if the underlying engine is still open
	if !e.bindings.IsOpen() {
		atomic.AddInt64(&e.stats.HealthCheckFailures, 1)
		e.logger.Warn("Health check failed - engine connection lost")
		e.handleConnectionLost()
		return
	}

	// Try to get engine stats as a connectivity test
	_ = e.bindings.GetStats()
}

// handleConnectionLost handles the case when WFP connection is lost.
func (e *Engine) handleConnectionLost() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config.MaxReconnectAttempts <= 0 {
		e.logger.Error("Connection lost and reconnection disabled - switching to degraded mode")
		e.setState(EngineStateDegraded)
		return
	}

	e.setState(EngineStateReconnecting)
	e.reconnectCount = 0

	go e.attemptReconnect()
}

// attemptReconnect tries to reconnect to the WFP engine.
func (e *Engine) attemptReconnect() {
	backoff := e.config.ReconnectBackoff

	for attempt := 1; attempt <= e.config.MaxReconnectAttempts; attempt++ {
		atomic.AddInt64(&e.stats.ReconnectAttempts, 1)
		e.logger.Info("Reconnection attempt %d/%d...", attempt, e.config.MaxReconnectAttempts)

		e.mu.Lock()
		e.reconnectCount = attempt

		// Close existing connection
		_ = e.bindings.Close()

		// Create new session
		session := e.createSession()

		// Try to reopen
		err := e.bindings.Open(session)
		if err == nil {
			// Reinitialize SafeOps
			if initErr := e.bindings.InitializeSafeOps(); initErr != nil {
				e.logger.Warn("Failed to reinitialize SafeOps: %v", initErr)
			}

			atomic.AddInt64(&e.stats.ReconnectSuccesses, 1)
			e.setState(EngineStateOpen)
			e.mu.Unlock()

			e.logger.Info("Reconnection successful on attempt %d", attempt)

			// Reinstall filters
			e.reinstallFilters()
			return
		}

		e.mu.Unlock()
		e.logger.Warn("Reconnection attempt %d failed: %v", attempt, err)

		// Wait before next attempt (with backoff)
		select {
		case <-e.healthCtx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2 // Exponential backoff
	}

	// All attempts failed
	e.mu.Lock()
	e.setState(EngineStateDegraded)
	e.mu.Unlock()

	e.logger.Error("All reconnection attempts failed - switching to degraded mode")
}

// reinstallFilters reinstalls all previously tracked filters after reconnection.
func (e *Engine) reinstallFilters() {
	e.filterMu.RLock()
	ruleIDs := make([]string, 0, len(e.filterIDs))
	for ruleID := range e.filterIDs {
		ruleIDs = append(ruleIDs, ruleID)
	}
	e.filterMu.RUnlock()

	if len(ruleIDs) == 0 {
		return
	}

	e.logger.Info("Reinstalling %d filters after reconnection...", len(ruleIDs))

	// Note: The actual filter data would need to be stored separately
	// to properly reinstall filters. This is a placeholder for that logic.
	// In practice, the Firewall Engine would need to resync all rules.
}

// ============================================================================
// State Management
// ============================================================================

// setState atomically sets the engine state and notifies callbacks.
func (e *Engine) setState(newState EngineState) {
	oldState := EngineState(atomic.SwapInt32(&e.state, int32(newState)))

	if oldState != newState {
		e.logger.Debug("State changed: %s -> %s", oldState, newState)

		if e.config.OnStateChange != nil {
			// Call in goroutine to avoid blocking
			go e.config.OnStateChange(oldState, newState)
		}
	}
}

// ============================================================================
// Filter Management (Delegated)
// ============================================================================

// GetBindings returns the underlying bindings engine.
// This should only be used by the filter manager and translator.
func (e *Engine) GetBindings() *bindings.Engine {
	return e.bindings
}

// TrackFilter records a filter installation for tracking purposes.
func (e *Engine) TrackFilter(ruleID string, filterID uint64) {
	e.filterMu.Lock()
	defer e.filterMu.Unlock()

	e.filterIDs[ruleID] = filterID
	atomic.AddInt64(&e.filterCount, 1)
	atomic.AddInt64(&e.stats.FiltersAdded, 1)

	if e.config.OnFilterInstalled != nil {
		go e.config.OnFilterInstalled(ruleID, filterID)
	}
}

// UntrackFilter removes a filter from tracking.
func (e *Engine) UntrackFilter(ruleID string) {
	e.filterMu.Lock()
	defer e.filterMu.Unlock()

	if _, exists := e.filterIDs[ruleID]; exists {
		delete(e.filterIDs, ruleID)
		atomic.AddInt64(&e.filterCount, -1)
		atomic.AddInt64(&e.stats.FiltersRemoved, 1)

		if e.config.OnFilterRemoved != nil {
			go e.config.OnFilterRemoved(ruleID)
		}
	}
}

// GetFilterID returns the WFP filter ID for a given rule ID.
func (e *Engine) GetFilterID(ruleID string) (uint64, bool) {
	e.filterMu.RLock()
	defer e.filterMu.RUnlock()

	id, exists := e.filterIDs[ruleID]
	return id, exists
}

// GetFilterCount returns the number of tracked filters.
func (e *Engine) GetFilterCount() int {
	return int(atomic.LoadInt64(&e.filterCount))
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns a copy of the engine statistics.
func (e *Engine) GetStats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := e.stats
	stats.HealthCheckCount = atomic.LoadInt64(&e.stats.HealthCheckCount)
	stats.HealthCheckFailures = atomic.LoadInt64(&e.stats.HealthCheckFailures)
	stats.ReconnectAttempts = atomic.LoadInt64(&e.stats.ReconnectAttempts)
	stats.ReconnectSuccesses = atomic.LoadInt64(&e.stats.ReconnectSuccesses)
	stats.FiltersAdded = atomic.LoadInt64(&e.stats.FiltersAdded)
	stats.FiltersRemoved = atomic.LoadInt64(&e.stats.FiltersRemoved)
	stats.FiltersFailed = atomic.LoadInt64(&e.stats.FiltersFailed)

	return stats
}

// GetBindingsStats returns statistics from the underlying bindings engine.
func (e *Engine) GetBindingsStats() bindings.Stats {
	return e.bindings.GetStats()
}

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrEngineClosed is returned when an operation requires an open engine.
	ErrEngineClosed = errors.New("wfp engine is closed")

	// ErrEngineDegraded is returned when an operation requires a fully functional engine.
	ErrEngineDegraded = errors.New("wfp engine is in degraded mode")

	// ErrEngineReconnecting is returned when the engine is currently reconnecting.
	ErrEngineReconnecting = errors.New("wfp engine is reconnecting")
)

// RequireOpen returns an error if the engine is not in the open state.
func (e *Engine) RequireOpen() error {
	state := e.State()
	switch state {
	case EngineStateOpen:
		return nil
	case EngineStateClosed:
		return ErrEngineClosed
	case EngineStateDegraded:
		return ErrEngineDegraded
	case EngineStateReconnecting:
		return ErrEngineReconnecting
	default:
		return fmt.Errorf("engine in unexpected state: %s", state)
	}
}
