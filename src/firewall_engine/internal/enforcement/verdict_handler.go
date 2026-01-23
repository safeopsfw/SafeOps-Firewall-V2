// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Verdict Handler - Main Orchestrator
// ============================================================================

// VerdictHandler is the main orchestrator for verdict enforcement.
// It receives verdicts from the rule matching engine and routes them to
// the appropriate enforcement handlers (drop, block, redirect, reject).
//
// Design Philosophy:
//   - Fail-Open: If enforcement fails, allow packet (prioritize availability)
//   - Retry Logic: Exponential backoff for transient failures
//   - Graceful Degradation: Fall back when SafeOps engine unavailable
//   - Never Crash: Log errors but never panic
type VerdictHandler struct {
	// Configuration
	config *EnforcementConfig

	// Handler registry
	handlers   map[EnforcementAction]ActionHandler
	handlersMu sync.RWMutex

	// Statistics
	stats *EnforcementStats

	// Logging
	logger *log.Logger

	// Engine availability
	engineAvailable   bool
	engineAvailableMu sync.RWMutex

	// Shutdown control
	closed    bool
	closedMu  sync.RWMutex
	closeOnce sync.Once
}

// NewVerdictHandler creates a new verdict handler with the given configuration.
func NewVerdictHandler(config *EnforcementConfig) (*VerdictHandler, error) {
	if config == nil {
		config = DefaultEnforcementConfig()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid enforcement config: %w", err)
	}

	handler := &VerdictHandler{
		config:          config,
		handlers:        make(map[EnforcementAction]ActionHandler),
		stats:           NewEnforcementStats(),
		logger:          log.New(log.Writer(), "[ENFORCEMENT] ", log.LstdFlags|log.Lmicroseconds),
		engineAvailable: true,
	}

	return handler, nil
}

// ============================================================================
// Handler Registry
// ============================================================================

// RegisterHandler registers an action handler for specific actions.
func (v *VerdictHandler) RegisterHandler(handler ActionHandler) error {
	if handler == nil {
		return errors.New("handler cannot be nil")
	}

	v.handlersMu.Lock()
	defer v.handlersMu.Unlock()

	actions := handler.SupportedActions()
	if len(actions) == 0 {
		return fmt.Errorf("handler %s supports no actions", handler.Name())
	}

	for _, action := range actions {
		if existing, exists := v.handlers[action]; exists {
			return fmt.Errorf("action %s already registered to handler %s",
				action, existing.Name())
		}
		v.handlers[action] = handler
		if v.config.EnableLogging {
			v.logger.Printf("Registered handler %s for action %s", handler.Name(), action)
		}
	}

	return nil
}

// GetHandler returns the handler for a specific action.
func (v *VerdictHandler) GetHandler(action EnforcementAction) (ActionHandler, bool) {
	v.handlersMu.RLock()
	defer v.handlersMu.RUnlock()
	handler, exists := v.handlers[action]
	return handler, exists
}

// UnregisterHandler removes a handler from the registry.
func (v *VerdictHandler) UnregisterHandler(action EnforcementAction) {
	v.handlersMu.Lock()
	defer v.handlersMu.Unlock()
	delete(v.handlers, action)
}

// ListHandlers returns all registered handlers.
func (v *VerdictHandler) ListHandlers() []ActionHandler {
	v.handlersMu.RLock()
	defer v.handlersMu.RUnlock()

	// Use map to deduplicate (one handler may handle multiple actions)
	seen := make(map[string]ActionHandler)
	for _, handler := range v.handlers {
		seen[handler.Name()] = handler
	}

	handlers := make([]ActionHandler, 0, len(seen))
	for _, handler := range seen {
		handlers = append(handlers, handler)
	}
	return handlers
}

// ============================================================================
// Main Enforcement Logic
// ============================================================================

// EnforceVerdict processes a verdict and routes it to the appropriate handler.
// This is the main entry point called by the packet inspector.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - pktCtx: Packet context with all information needed for enforcement
//
// Returns:
//   - EnforcementResult with success/failure details
//
// Behavior:
//   - ALLOW verdicts: No action needed, returns immediately
//   - Other verdicts: Routes to registered handler with retry logic
//   - On failure: Applies fail-open policy (allow packet if configured)
func (v *VerdictHandler) EnforceVerdict(ctx context.Context, pktCtx *PacketContext) *EnforcementResult {
	startTime := time.Now()

	// Check if handler is closed
	if v.isClosed() {
		return NewFailureResult(ActionNone, pktCtx.GetPacketID(),
			errors.New("verdict handler is closed"), ErrCodeDisabled)
	}

	// Check if enforcement is enabled
	if !v.config.Enabled {
		return v.handleDisabled(pktCtx)
	}

	// Validate packet context
	if err := pktCtx.Validate(); err != nil {
		return v.handleValidationError(pktCtx, err)
	}

	// Determine enforcement action from verdict
	action := v.verdictToAction(pktCtx.Verdict)

	// Handle ALLOW verdict (no enforcement needed)
	if action == ActionNone || action == ActionLog {
		return v.handleAllow(pktCtx, startTime)
	}

	// Get handler for this action
	handler, exists := v.GetHandler(action)
	if !exists {
		return v.handleNoHandler(action, pktCtx)
	}

	// Check if handler can process this packet
	if !handler.CanHandle(pktCtx) {
		return v.handleCannotProcess(handler, action, pktCtx)
	}

	// Execute with retry logic
	result := v.executeWithRetry(ctx, handler, action, pktCtx)

	// Record statistics
	duration := time.Since(startTime)
	result.Duration = duration

	if result.Success {
		v.stats.RecordSuccess(action, duration)
		if v.config.EnableLogging && v.config.LogSuccesses {
			v.logger.Printf("Enforced %s on packet %d (duration=%v)",
				action, pktCtx.GetPacketID(), duration)
		}
	} else {
		// Apply fail-open policy
		if v.config.FailOpen {
			v.stats.RecordFailure(action, true)
			if v.config.EnableLogging {
				v.logger.Printf("FAIL-OPEN: Enforcement failed for packet %d, allowing (error=%v)",
					pktCtx.GetPacketID(), result.Error)
			}
		} else {
			v.stats.RecordFailure(action, false)
			if v.config.EnableLogging {
				v.logger.Printf("Enforcement failed for packet %d (error=%v)",
					pktCtx.GetPacketID(), result.Error)
			}
		}
	}

	return result
}

// executeWithRetry executes the handler with exponential backoff retry.
func (v *VerdictHandler) executeWithRetry(
	ctx context.Context,
	handler ActionHandler,
	action EnforcementAction,
	pktCtx *PacketContext,
) *EnforcementResult {
	var lastResult *EnforcementResult
	var lastError error

	for attempt := 0; attempt <= v.config.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return NewFailureResult(action, pktCtx.GetPacketID(),
				ctx.Err(), ErrCodeTimeout).WithRetryCount(attempt)
		default:
		}

		// Create timeout context for this attempt
		attemptCtx, cancel := context.WithTimeout(ctx, v.config.GetOperationTimeout())

		// Execute handler
		lastResult = handler.Handle(attemptCtx, pktCtx)
		lastResult.WithHandler(handler.Name())
		cancel()

		if lastResult.Success {
			lastResult.WithRetryCount(attempt)
			return lastResult
		}

		lastError = lastResult.Error

		// Check if error is retryable
		if !IsRetryable(lastError) {
			lastResult.WithRetryCount(attempt)
			return lastResult
		}

		// Don't retry on last attempt
		if attempt >= v.config.MaxRetries {
			break
		}

		// Record retry attempt
		v.stats.RecordRetry()

		// Calculate delay with exponential backoff
		delay := v.config.GetRetryDelay(attempt)

		if v.config.EnableLogging {
			v.logger.Printf("Retry %d/%d for action %s on packet %d (delay=%v, error=%v)",
				attempt+1, v.config.MaxRetries, action, pktCtx.GetPacketID(), delay, lastError)
		}

		// Wait before retry
		select {
		case <-ctx.Done():
			return NewFailureResult(action, pktCtx.GetPacketID(),
				ctx.Err(), ErrCodeTimeout).WithRetryCount(attempt + 1)
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	// All retries exhausted
	return NewFailureResult(action, pktCtx.GetPacketID(),
		fmt.Errorf("%w: %v", ErrRetryExhausted, lastError),
		ErrCodeRetryExhausted).WithRetryCount(v.config.MaxRetries)
}

// ============================================================================
// Verdict to Action Mapping
// ============================================================================

// verdictToAction maps a VerdictResult to an EnforcementAction.
func (v *VerdictHandler) verdictToAction(verdict *models.VerdictResult) EnforcementAction {
	if verdict == nil {
		return ActionNone
	}

	switch verdict.Verdict {
	case models.VerdictAllow:
		return ActionNone
	case models.VerdictDrop:
		return ActionDrop
	case models.VerdictBlock:
		return ActionBlock
	case models.VerdictRedirect:
		return ActionRedirect
	case models.VerdictReject:
		return ActionReject
	case models.VerdictLog:
		return ActionLog
	case models.VerdictQueue:
		return ActionQueue
	default:
		return ActionNone
	}
}

// ============================================================================
// Special Case Handlers
// ============================================================================

// handleDisabled returns a result when enforcement is disabled.
func (v *VerdictHandler) handleDisabled(pktCtx *PacketContext) *EnforcementResult {
	return &EnforcementResult{
		Success:     true,
		Action:      ActionNone,
		PacketID:    pktCtx.GetPacketID(),
		Timestamp:   time.Now(),
		HandlerName: "disabled",
	}
}

// handleValidationError returns a result for validation failures.
func (v *VerdictHandler) handleValidationError(pktCtx *PacketContext, err error) *EnforcementResult {
	var packetID uint64
	if pktCtx != nil {
		packetID = pktCtx.GetPacketID()
	}

	result := NewFailureResult(ActionNone, packetID, err, ErrCodeInvalidPacket)

	if v.config.EnableLogging {
		v.logger.Printf("Validation error for packet %d: %v", packetID, err)
	}

	return result
}

// handleAllow returns a result for ALLOW verdicts.
func (v *VerdictHandler) handleAllow(pktCtx *PacketContext, startTime time.Time) *EnforcementResult {
	return &EnforcementResult{
		Success:     true,
		Action:      ActionNone,
		PacketID:    pktCtx.GetPacketID(),
		Duration:    time.Since(startTime),
		Timestamp:   time.Now(),
		HandlerName: "allow-passthrough",
	}
}

// handleNoHandler returns a result when no handler is registered.
func (v *VerdictHandler) handleNoHandler(action EnforcementAction, pktCtx *PacketContext) *EnforcementResult {
	err := fmt.Errorf("no handler registered for action %s", action)

	if v.config.EnableLogging {
		v.logger.Printf("No handler for action %s on packet %d", action, pktCtx.GetPacketID())
	}

	// In fail-open mode, treat missing handler as success (packet allowed)
	if v.config.FailOpen {
		v.stats.RecordFailure(action, true)
		return &EnforcementResult{
			Success:     true, // Fail-open: treat as success
			Action:      action,
			PacketID:    pktCtx.GetPacketID(),
			Error:       err,
			ErrorCode:   ErrCodeInternalError,
			Timestamp:   time.Now(),
			HandlerName: "fail-open",
		}
	}

	v.stats.RecordFailure(action, false)
	return NewFailureResult(action, pktCtx.GetPacketID(), err, ErrCodeInternalError)
}

// handleCannotProcess returns a result when handler cannot process packet.
func (v *VerdictHandler) handleCannotProcess(
	handler ActionHandler,
	action EnforcementAction,
	pktCtx *PacketContext,
) *EnforcementResult {
	err := fmt.Errorf("handler %s cannot process packet %d",
		handler.Name(), pktCtx.GetPacketID())

	if v.config.EnableLogging {
		v.logger.Printf("Handler %s cannot process packet %d for action %s",
			handler.Name(), pktCtx.GetPacketID(), action)
	}

	// Fail-open behavior
	if v.config.FailOpen {
		v.stats.RecordFailure(action, true)
		return &EnforcementResult{
			Success:     true,
			Action:      action,
			PacketID:    pktCtx.GetPacketID(),
			Error:       err,
			ErrorCode:   ErrCodeProtocolMismatch,
			Timestamp:   time.Now(),
			HandlerName: "fail-open",
		}
	}

	v.stats.RecordFailure(action, false)
	return NewFailureResult(action, pktCtx.GetPacketID(), err, ErrCodeProtocolMismatch)
}

// ============================================================================
// Engine Availability
// ============================================================================

// SetEngineAvailable updates the engine availability status.
func (v *VerdictHandler) SetEngineAvailable(available bool) {
	v.engineAvailableMu.Lock()
	defer v.engineAvailableMu.Unlock()
	v.engineAvailable = available

	if v.config.EnableLogging {
		if available {
			v.logger.Println("SafeOps verdict engine is now available")
		} else {
			v.logger.Println("SafeOps verdict engine is now unavailable - falling back to fail-open")
		}
	}
}

// IsEngineAvailable returns true if the SafeOps engine is available.
func (v *VerdictHandler) IsEngineAvailable() bool {
	v.engineAvailableMu.RLock()
	defer v.engineAvailableMu.RUnlock()
	return v.engineAvailable
}

// ============================================================================
// Lifecycle Management
// ============================================================================

// Close shuts down the verdict handler.
func (v *VerdictHandler) Close() error {
	var closeErr error

	v.closeOnce.Do(func() {
		v.closedMu.Lock()
		v.closed = true
		v.closedMu.Unlock()

		if v.config.EnableLogging {
			v.logger.Println("Verdict handler shutting down")
			v.logger.Printf("Final stats: %+v", v.stats.GetSnapshot())
		}
	})

	return closeErr
}

// isClosed checks if the handler has been closed.
func (v *VerdictHandler) isClosed() bool {
	v.closedMu.RLock()
	defer v.closedMu.RUnlock()
	return v.closed
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

// GetStats returns the current enforcement statistics.
func (v *VerdictHandler) GetStats() *EnforcementStats {
	return v.stats
}

// GetStatsSnapshot returns a point-in-time copy of statistics.
func (v *VerdictHandler) GetStatsSnapshot() map[string]uint64 {
	return v.stats.GetSnapshot()
}

// ResetStats resets all statistics to zero.
func (v *VerdictHandler) ResetStats() {
	v.stats.Reset()
}

// GetConfig returns the current configuration.
func (v *VerdictHandler) GetConfig() *EnforcementConfig {
	return v.config
}

// ============================================================================
// Batch Enforcement
// ============================================================================

// EnforceBatch processes multiple verdicts in sequence.
// Returns results in the same order as input.
func (v *VerdictHandler) EnforceBatch(
	ctx context.Context,
	packets []*PacketContext,
) []*EnforcementResult {
	results := make([]*EnforcementResult, len(packets))

	for i, pktCtx := range packets {
		select {
		case <-ctx.Done():
			// Fill remaining with timeout errors
			for j := i; j < len(packets); j++ {
				var packetID uint64
				if packets[j] != nil {
					packetID = packets[j].GetPacketID()
				}
				results[j] = NewFailureResult(ActionNone, packetID,
					ctx.Err(), ErrCodeTimeout)
			}
			return results
		default:
			results[i] = v.EnforceVerdict(ctx, pktCtx)
		}
	}

	return results
}

// ============================================================================
// Utility Functions
// ============================================================================

// SetLogger sets a custom logger for the verdict handler.
func (v *VerdictHandler) SetLogger(logger *log.Logger) {
	if logger != nil {
		v.logger = logger
	}
}

// GetHandlerCount returns the number of registered handlers.
func (v *VerdictHandler) GetHandlerCount() int {
	v.handlersMu.RLock()
	defer v.handlersMu.RUnlock()
	return len(v.handlers)
}

// HasHandler returns true if a handler is registered for the action.
func (v *VerdictHandler) HasHandler(action EnforcementAction) bool {
	_, exists := v.GetHandler(action)
	return exists
}
