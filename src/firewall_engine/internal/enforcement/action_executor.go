// Package enforcement provides verdict enforcement functionality for the firewall engine.
package enforcement

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/pkg/models"
)

// ============================================================================
// Action Executor - Rule-Specific Action Chaining
// ============================================================================

// ActionExecutor coordinates execution of multiple enforcement actions for a single
// verdict. It supports pre/post hooks, action chaining, and error aggregation.
//
// Use Cases:
//   - Execute DROP + LOG actions together
//   - Run pre-action hooks (e.g., notify monitoring system)
//   - Run post-action hooks (e.g., update dashboards)
//   - Chain BLOCK action with additional actions from rule metadata
//
// Example Flow:
//
//	Verdict: BLOCK (from rule with custom actions)
//	  ↓
//	ActionExecutor receives verdict + custom action list
//	  ↓
//	Execute pre-hooks (logging, metrics)
//	  ↓
//	Execute primary action (TCPResetHandler for BLOCK)
//	  ↓
//	Execute secondary actions (add to threat list, send alert)
//	  ↓
//	Execute post-hooks (update rule hit counter)
//	  ↓
//	Aggregate results and return
type ActionExecutor struct {
	// Configuration
	config *ActionExecutorConfig

	// Verdict handler for primary actions
	verdictHandler *VerdictHandler

	// Pre and post action hooks
	preHooks  []ActionHook
	postHooks []ActionHook
	hooksMu   sync.RWMutex

	// Custom action registry
	customActions   map[string]CustomActionFunc
	customActionsMu sync.RWMutex

	// Statistics
	stats *ActionExecutorStats

	// Shutdown
	closed atomic.Bool
}

// ActionExecutorConfig contains configuration for the action executor.
type ActionExecutorConfig struct {
	// ContinueOnError continues executing remaining actions even if one fails.
	ContinueOnError bool `json:"continue_on_error" toml:"continue_on_error"`

	// MaxConcurrentActions is the max actions to execute in parallel.
	MaxConcurrentActions int `json:"max_concurrent_actions" toml:"max_concurrent_actions"`

	// ActionTimeout is the timeout for individual custom actions.
	ActionTimeoutMs int `json:"action_timeout_ms" toml:"action_timeout_ms"`

	// EnableHooks enables pre/post action hooks.
	EnableHooks bool `json:"enable_hooks" toml:"enable_hooks"`

	// LogAllActions logs all action executions (verbose).
	LogAllActions bool `json:"log_all_actions" toml:"log_all_actions"`
}

// DefaultActionExecutorConfig returns the default configuration.
func DefaultActionExecutorConfig() *ActionExecutorConfig {
	return &ActionExecutorConfig{
		ContinueOnError:      true,
		MaxConcurrentActions: 4,
		ActionTimeoutMs:      100,
		EnableHooks:          true,
		LogAllActions:        false,
	}
}

// Validate checks the configuration.
func (c *ActionExecutorConfig) Validate() error {
	if c.MaxConcurrentActions < 1 {
		return fmt.Errorf("max_concurrent_actions must be >= 1")
	}
	if c.ActionTimeoutMs < 10 {
		return fmt.Errorf("action_timeout_ms must be >= 10")
	}
	return nil
}

// ActionHook is a function called before or after action execution.
type ActionHook func(ctx context.Context, pktCtx *PacketContext, result *EnforcementResult) error

// CustomActionFunc is a user-defined action function.
type CustomActionFunc func(ctx context.Context, pktCtx *PacketContext, params map[string]interface{}) error

// ActionExecutorStats tracks action executor statistics.
type ActionExecutorStats struct {
	ExecutionsAttempted atomic.Uint64
	ExecutionsSucceeded atomic.Uint64
	ExecutionsFailed    atomic.Uint64
	PrimaryActionsRun   atomic.Uint64
	SecondaryActionsRun atomic.Uint64
	PreHooksRun         atomic.Uint64
	PostHooksRun        atomic.Uint64
	HookErrors          atomic.Uint64
	CustomActionsRun    atomic.Uint64
	CustomActionErrors  atomic.Uint64
	TotalDurationNs     atomic.Uint64
}

// ExecutionResult contains the aggregated result of executing all actions.
type ExecutionResult struct {
	// Overall success (all actions succeeded)
	Success bool `json:"success"`

	// Primary enforcement result
	PrimaryResult *EnforcementResult `json:"primary_result"`

	// Secondary action results
	SecondaryResults []*ActionResult `json:"secondary_results,omitempty"`

	// Hook errors (non-fatal)
	HookErrors []error `json:"hook_errors,omitempty"`

	// Total execution time
	Duration time.Duration `json:"duration"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// ActionResult contains the result of a single action.
type ActionResult struct {
	Name     string        `json:"name"`
	Success  bool          `json:"success"`
	Error    error         `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// NewActionExecutor creates a new action executor.
func NewActionExecutor(
	config *ActionExecutorConfig,
	verdictHandler *VerdictHandler,
) (*ActionExecutor, error) {
	if config == nil {
		config = DefaultActionExecutorConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid action executor config: %w", err)
	}

	return &ActionExecutor{
		config:         config,
		verdictHandler: verdictHandler,
		preHooks:       make([]ActionHook, 0),
		postHooks:      make([]ActionHook, 0),
		customActions:  make(map[string]CustomActionFunc),
		stats:          &ActionExecutorStats{},
	}, nil
}

// ============================================================================
// Main Execution Flow
// ============================================================================

// Execute runs the complete action chain for a verdict.
func (e *ActionExecutor) Execute(ctx context.Context, pktCtx *PacketContext) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		Success:   true,
		Timestamp: time.Now(),
	}

	// Check if executor is closed
	if e.closed.Load() {
		result.Success = false
		result.PrimaryResult = NewFailureResult(ActionNone, pktCtx.GetPacketID(),
			fmt.Errorf("action executor is closed"), ErrCodeDisabled)
		return result
	}

	e.stats.ExecutionsAttempted.Add(1)

	// Run pre-hooks
	if e.config.EnableHooks {
		hookErrors := e.runPreHooks(ctx, pktCtx, nil)
		result.HookErrors = append(result.HookErrors, hookErrors...)
	}

	// Execute primary enforcement action
	if e.verdictHandler != nil {
		e.stats.PrimaryActionsRun.Add(1)
		result.PrimaryResult = e.verdictHandler.EnforceVerdict(ctx, pktCtx)

		if !result.PrimaryResult.Success {
			result.Success = false
		}
	}

	// Execute secondary actions from rule metadata
	secondaryResults := e.executeSecondaryActions(ctx, pktCtx)
	result.SecondaryResults = secondaryResults

	// Check if any secondary action failed
	for _, sr := range secondaryResults {
		if !sr.Success {
			result.Success = false
			break
		}
	}

	// Run post-hooks
	if e.config.EnableHooks {
		hookErrors := e.runPostHooks(ctx, pktCtx, result.PrimaryResult)
		result.HookErrors = append(result.HookErrors, hookErrors...)
	}

	result.Duration = time.Since(startTime)
	e.stats.TotalDurationNs.Add(uint64(result.Duration.Nanoseconds()))

	if result.Success {
		e.stats.ExecutionsSucceeded.Add(1)
	} else {
		e.stats.ExecutionsFailed.Add(1)
	}

	return result
}

// executeSecondaryActions runs additional actions from packet context tags.
func (e *ActionExecutor) executeSecondaryActions(ctx context.Context, pktCtx *PacketContext) []*ActionResult {
	if pktCtx == nil || pktCtx.Tags == nil {
		return nil
	}

	// Check for custom actions in packet context tags
	actionsRaw, ok := pktCtx.Tags["actions"]
	if !ok {
		return nil
	}

	// Actions are stored as comma-separated string in tags
	actionNames := splitActions(actionsRaw)
	if len(actionNames) == 0 {
		return nil
	}

	results := make([]*ActionResult, 0, len(actionNames))

	for _, actionName := range actionNames {
		select {
		case <-ctx.Done():
			results = append(results, &ActionResult{
				Name:    actionName,
				Success: false,
				Error:   ctx.Err(),
			})
			return results
		default:
		}

		actionResult := e.executeCustomAction(ctx, actionName, pktCtx, nil)
		results = append(results, actionResult)
		e.stats.SecondaryActionsRun.Add(1)

		if !actionResult.Success && !e.config.ContinueOnError {
			break
		}
	}

	return results
}

// splitActions splits a comma-separated actions string into individual action names.
func splitActions(s string) []string {
	if s == "" {
		return nil
	}
	var actions []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			action := trimString(s[start:i])
			if action != "" {
				actions = append(actions, action)
			}
			start = i + 1
		}
	}
	// Add last segment
	action := trimString(s[start:])
	if action != "" {
		actions = append(actions, action)
	}
	return actions
}

// trimString trims whitespace from a string.
func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// ============================================================================
// Hook Management
// ============================================================================

// AddPreHook adds a hook to run before action execution.
func (e *ActionExecutor) AddPreHook(hook ActionHook) {
	if hook == nil {
		return
	}
	e.hooksMu.Lock()
	defer e.hooksMu.Unlock()
	e.preHooks = append(e.preHooks, hook)
}

// AddPostHook adds a hook to run after action execution.
func (e *ActionExecutor) AddPostHook(hook ActionHook) {
	if hook == nil {
		return
	}
	e.hooksMu.Lock()
	defer e.hooksMu.Unlock()
	e.postHooks = append(e.postHooks, hook)
}

// ClearHooks removes all registered hooks.
func (e *ActionExecutor) ClearHooks() {
	e.hooksMu.Lock()
	defer e.hooksMu.Unlock()
	e.preHooks = make([]ActionHook, 0)
	e.postHooks = make([]ActionHook, 0)
}

// runPreHooks executes all pre-action hooks.
func (e *ActionExecutor) runPreHooks(ctx context.Context, pktCtx *PacketContext, result *EnforcementResult) []error {
	e.hooksMu.RLock()
	hooks := make([]ActionHook, len(e.preHooks))
	copy(hooks, e.preHooks)
	e.hooksMu.RUnlock()

	var errors []error
	for _, hook := range hooks {
		e.stats.PreHooksRun.Add(1)
		if err := hook(ctx, pktCtx, result); err != nil {
			errors = append(errors, err)
			e.stats.HookErrors.Add(1)
		}
	}

	return errors
}

// runPostHooks executes all post-action hooks.
func (e *ActionExecutor) runPostHooks(ctx context.Context, pktCtx *PacketContext, result *EnforcementResult) []error {
	e.hooksMu.RLock()
	hooks := make([]ActionHook, len(e.postHooks))
	copy(hooks, e.postHooks)
	e.hooksMu.RUnlock()

	var errors []error
	for _, hook := range hooks {
		e.stats.PostHooksRun.Add(1)
		if err := hook(ctx, pktCtx, result); err != nil {
			errors = append(errors, err)
			e.stats.HookErrors.Add(1)
		}
	}

	return errors
}

// ============================================================================
// Custom Action Management
// ============================================================================

// RegisterCustomAction registers a named custom action.
func (e *ActionExecutor) RegisterCustomAction(name string, action CustomActionFunc) error {
	if name == "" {
		return fmt.Errorf("action name cannot be empty")
	}
	if action == nil {
		return fmt.Errorf("action function cannot be nil")
	}

	e.customActionsMu.Lock()
	defer e.customActionsMu.Unlock()

	if _, exists := e.customActions[name]; exists {
		return fmt.Errorf("action %q already registered", name)
	}

	e.customActions[name] = action
	return nil
}

// UnregisterCustomAction removes a custom action.
func (e *ActionExecutor) UnregisterCustomAction(name string) {
	e.customActionsMu.Lock()
	defer e.customActionsMu.Unlock()
	delete(e.customActions, name)
}

// ListCustomActions returns all registered custom action names.
func (e *ActionExecutor) ListCustomActions() []string {
	e.customActionsMu.RLock()
	defer e.customActionsMu.RUnlock()

	names := make([]string, 0, len(e.customActions))
	for name := range e.customActions {
		names = append(names, name)
	}
	return names
}

// executeCustomAction runs a named custom action.
func (e *ActionExecutor) executeCustomAction(
	ctx context.Context,
	name string,
	pktCtx *PacketContext,
	params map[string]interface{},
) *ActionResult {
	startTime := time.Now()

	e.customActionsMu.RLock()
	action, exists := e.customActions[name]
	e.customActionsMu.RUnlock()

	if !exists {
		return &ActionResult{
			Name:     name,
			Success:  false,
			Error:    fmt.Errorf("custom action %q not registered", name),
			Duration: time.Since(startTime),
		}
	}

	// Create timeout context for action
	actionCtx, cancel := context.WithTimeout(ctx, time.Duration(e.config.ActionTimeoutMs)*time.Millisecond)
	defer cancel()

	e.stats.CustomActionsRun.Add(1)

	err := action(actionCtx, pktCtx, params)
	duration := time.Since(startTime)

	if err != nil {
		e.stats.CustomActionErrors.Add(1)
		return &ActionResult{
			Name:     name,
			Success:  false,
			Error:    err,
			Duration: duration,
		}
	}

	return &ActionResult{
		Name:     name,
		Success:  true,
		Duration: duration,
	}
}

// ============================================================================
// Utility Methods
// ============================================================================

// ExecuteWithActions runs the primary verdict with additional custom actions.
func (e *ActionExecutor) ExecuteWithActions(
	ctx context.Context,
	pktCtx *PacketContext,
	additionalActions []string,
) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		Success:   true,
		Timestamp: time.Now(),
	}

	if e.closed.Load() {
		result.Success = false
		result.PrimaryResult = NewFailureResult(ActionNone, pktCtx.GetPacketID(),
			fmt.Errorf("action executor is closed"), ErrCodeDisabled)
		return result
	}

	e.stats.ExecutionsAttempted.Add(1)

	// Run pre-hooks
	if e.config.EnableHooks {
		hookErrors := e.runPreHooks(ctx, pktCtx, nil)
		result.HookErrors = append(result.HookErrors, hookErrors...)
	}

	// Execute primary enforcement
	if e.verdictHandler != nil {
		e.stats.PrimaryActionsRun.Add(1)
		result.PrimaryResult = e.verdictHandler.EnforceVerdict(ctx, pktCtx)
		if !result.PrimaryResult.Success {
			result.Success = false
		}
	}

	// Execute additional custom actions
	for _, actionName := range additionalActions {
		select {
		case <-ctx.Done():
			result.SecondaryResults = append(result.SecondaryResults, &ActionResult{
				Name:    actionName,
				Success: false,
				Error:   ctx.Err(),
			})
			result.Success = false
			result.Duration = time.Since(startTime)
			e.stats.TotalDurationNs.Add(uint64(result.Duration.Nanoseconds()))
			e.stats.ExecutionsFailed.Add(1)
			return result
		default:
		}

		actionResult := e.executeCustomAction(ctx, actionName, pktCtx, nil)
		result.SecondaryResults = append(result.SecondaryResults, actionResult)
		e.stats.SecondaryActionsRun.Add(1)

		if !actionResult.Success {
			result.Success = false
			if !e.config.ContinueOnError {
				break
			}
		}
	}

	// Run post-hooks
	if e.config.EnableHooks {
		hookErrors := e.runPostHooks(ctx, pktCtx, result.PrimaryResult)
		result.HookErrors = append(result.HookErrors, hookErrors...)
	}

	result.Duration = time.Since(startTime)
	e.stats.TotalDurationNs.Add(uint64(result.Duration.Nanoseconds()))

	if result.Success {
		e.stats.ExecutionsSucceeded.Add(1)
	} else {
		e.stats.ExecutionsFailed.Add(1)
	}

	return result
}

// ============================================================================
// Statistics and Lifecycle
// ============================================================================

// GetStats returns the action executor statistics.
func (e *ActionExecutor) GetStats() map[string]uint64 {
	return map[string]uint64{
		"executions_attempted":  e.stats.ExecutionsAttempted.Load(),
		"executions_succeeded":  e.stats.ExecutionsSucceeded.Load(),
		"executions_failed":     e.stats.ExecutionsFailed.Load(),
		"primary_actions_run":   e.stats.PrimaryActionsRun.Load(),
		"secondary_actions_run": e.stats.SecondaryActionsRun.Load(),
		"pre_hooks_run":         e.stats.PreHooksRun.Load(),
		"post_hooks_run":        e.stats.PostHooksRun.Load(),
		"hook_errors":           e.stats.HookErrors.Load(),
		"custom_actions_run":    e.stats.CustomActionsRun.Load(),
		"custom_action_errors":  e.stats.CustomActionErrors.Load(),
		"total_duration_ns":     e.stats.TotalDurationNs.Load(),
	}
}

// Close shuts down the action executor.
func (e *ActionExecutor) Close() error {
	e.closed.Store(true)
	return nil
}

// SetVerdictHandler sets the verdict handler reference.
func (e *ActionExecutor) SetVerdictHandler(handler *VerdictHandler) {
	e.verdictHandler = handler
}

// GetConfig returns the current configuration.
func (e *ActionExecutor) GetConfig() *ActionExecutorConfig {
	return e.config
}

// ============================================================================
// Built-in Custom Actions
// ============================================================================

// RegisterBuiltinActions registers commonly used custom actions.
func (e *ActionExecutor) RegisterBuiltinActions() {
	// Log action - logs the packet details
	_ = e.RegisterCustomAction("log", func(ctx context.Context, pktCtx *PacketContext, params map[string]interface{}) error {
		// Logging is typically handled by the logging subsystem
		// This is a no-op placeholder
		return nil
	})

	// Alert action - sends an alert (placeholder)
	_ = e.RegisterCustomAction("alert", func(ctx context.Context, pktCtx *PacketContext, params map[string]interface{}) error {
		// Alert sending would be implemented here
		// Could integrate with SIEM, email, Slack, etc.
		return nil
	})

	// Tag action - adds a tag to the connection
	_ = e.RegisterCustomAction("tag", func(ctx context.Context, pktCtx *PacketContext, params map[string]interface{}) error {
		if tag, ok := params["tag"].(string); ok {
			pktCtx.WithTag("custom_tag", tag)
		}
		return nil
	})
}

// ============================================================================
// Helper: Extract Custom Actions from VerdictResult
// ============================================================================

// GetActionsFromVerdict extracts custom action names from verdict metadata.
func GetActionsFromVerdict(verdict *models.VerdictResult) []string {
	if verdict == nil {
		return nil
	}

	// Check VerdictResult doesn't have Metadata field directly
	// Custom actions would be passed through the enforcement pipeline
	// This is a placeholder for future extension
	return nil
}
