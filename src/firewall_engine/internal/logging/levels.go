// Package logging provides structured logging for the firewall engine.
package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// ============================================================================
// Level Parsing Errors
// ============================================================================

var (
	// ErrUnknownLevel is returned when parsing an unknown log level string.
	ErrUnknownLevel = errors.New("unknown log level")
)

// ============================================================================
// Level Parsing
// ============================================================================

// ParseLevel parses a string into a LogLevel.
// It is case-insensitive and supports common aliases.
func ParseLevel(s string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace", "trc":
		return LevelTrace, nil
	case "debug", "dbg":
		return LevelDebug, nil
	case "info", "inf":
		return LevelInfo, nil
	case "warn", "warning", "wrn":
		return LevelWarn, nil
	case "error", "err":
		return LevelError, nil
	case "fatal", "ftl":
		return LevelFatal, nil
	case "disabled", "off", "none":
		return LevelDisabled, nil
	case "":
		return LevelInfo, nil // Default to info
	default:
		return LevelInfo, fmt.Errorf("%w: %s", ErrUnknownLevel, s)
	}
}

// MustParseLevel parses a log level string or panics on error.
func MustParseLevel(s string) LogLevel {
	level, err := ParseLevel(s)
	if err != nil {
		panic(fmt.Sprintf("invalid log level: %s", s))
	}
	return level
}

// ============================================================================
// Environment-Based Level Detection
// ============================================================================

// LevelFromEnvironment determines the log level from environment variables.
// It checks LOG_LEVEL first, then falls back to ENVIRONMENT-based defaults.
func LevelFromEnvironment() LogLevel {
	// Check LOG_LEVEL environment variable first
	if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
		if level, err := ParseLevel(levelStr); err == nil {
			return level
		}
	}

	// Check SAFEOPS_LOG_LEVEL
	if levelStr := os.Getenv("SAFEOPS_LOG_LEVEL"); levelStr != "" {
		if level, err := ParseLevel(levelStr); err == nil {
			return level
		}
	}

	// Fall back to environment-based defaults
	return LevelFromDeploymentEnvironment()
}

// LevelFromDeploymentEnvironment returns the default log level based on
// the deployment environment (production, staging, development).
func LevelFromDeploymentEnvironment() LogLevel {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	if env == "" {
		env = strings.ToLower(os.Getenv("GO_ENV"))
	}
	if env == "" {
		env = strings.ToLower(os.Getenv("NODE_ENV"))
	}

	switch env {
	case "production", "prod":
		return LevelInfo
	case "staging", "stage", "stg":
		return LevelDebug
	case "development", "dev", "local":
		return LevelDebug
	case "testing", "test":
		return LevelWarn
	default:
		return LevelInfo
	}
}

// ============================================================================
// Level Controller
// ============================================================================

// LevelChangeListener is a callback function invoked when the log level changes.
type LevelChangeListener func(oldLevel, newLevel LogLevel)

// LevelController manages runtime log level changes.
// It supports increasing/decreasing verbosity and notifying listeners.
type LevelController struct {
	logger    Logger
	level     atomic.Int32
	listeners []LevelChangeListener
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	started   atomic.Bool
}

// NewLevelController creates a new LevelController for the given logger.
func NewLevelController(logger Logger) *LevelController {
	ctx, cancel := context.WithCancel(context.Background())
	lc := &LevelController{
		logger:    logger,
		listeners: make([]LevelChangeListener, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
	lc.level.Store(int32(logger.GetLevel()))
	return lc
}

// Start starts the level controller.
// On Windows, this could listen on a named pipe or HTTP endpoint.
// For now, it just marks the controller as started.
func (lc *LevelController) Start(ctx context.Context) error {
	if lc.started.Swap(true) {
		return errors.New("level controller already started")
	}

	lc.mu.Lock()
	lc.ctx, lc.cancel = context.WithCancel(ctx)
	lc.mu.Unlock()

	// Log startup
	if lc.logger != nil {
		lc.logger.Info().
			Str(FieldComponent, "level_controller").
			Str("current_level", LogLevel(lc.level.Load()).String()).
			Msg("Level controller started")
	}

	// Wait for context cancellation
	<-lc.ctx.Done()
	return nil
}

// Stop stops the level controller.
func (lc *LevelController) Stop() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.cancel != nil {
		lc.cancel()
	}
	lc.started.Store(false)
}

// GetLevel returns the current log level.
func (lc *LevelController) GetLevel() LogLevel {
	return LogLevel(lc.level.Load())
}

// SetLevel sets the log level and notifies listeners.
func (lc *LevelController) SetLevel(level LogLevel) {
	if !level.IsValid() {
		return
	}

	oldLevel := LogLevel(lc.level.Swap(int32(level)))
	if oldLevel == level {
		return // No change
	}

	// Update logger
	if lc.logger != nil {
		lc.logger.SetLevel(level)
		lc.logger.Info().
			Str(FieldComponent, "level_controller").
			Str("old_level", oldLevel.String()).
			Str("new_level", level.String()).
			Msg("Log level changed")
	}

	// Notify listeners
	lc.notifyListeners(oldLevel, level)
}

// IncreaseVerbosity increases the log level verbosity by one step.
// Returns the new log level.
func (lc *LevelController) IncreaseVerbosity() LogLevel {
	currentLevel := LogLevel(lc.level.Load())
	newLevel := currentLevel

	switch currentLevel {
	case LevelDisabled:
		newLevel = LevelFatal
	case LevelFatal:
		newLevel = LevelError
	case LevelError:
		newLevel = LevelWarn
	case LevelWarn:
		newLevel = LevelInfo
	case LevelInfo:
		newLevel = LevelDebug
	case LevelDebug:
		newLevel = LevelTrace
	case LevelTrace:
		// Already at maximum verbosity
		return currentLevel
	}

	lc.SetLevel(newLevel)
	return newLevel
}

// DecreaseVerbosity decreases the log level verbosity by one step.
// Returns the new log level.
func (lc *LevelController) DecreaseVerbosity() LogLevel {
	currentLevel := LogLevel(lc.level.Load())
	newLevel := currentLevel

	switch currentLevel {
	case LevelTrace:
		newLevel = LevelDebug
	case LevelDebug:
		newLevel = LevelInfo
	case LevelInfo:
		newLevel = LevelWarn
	case LevelWarn:
		newLevel = LevelError
	case LevelError:
		newLevel = LevelFatal
	case LevelFatal:
		newLevel = LevelDisabled
	case LevelDisabled:
		// Already at minimum verbosity
		return currentLevel
	}

	lc.SetLevel(newLevel)
	return newLevel
}

// OnChange registers a callback for level change events.
func (lc *LevelController) OnChange(fn LevelChangeListener) {
	if fn == nil {
		return
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.listeners = append(lc.listeners, fn)
}

// notifyListeners notifies all registered listeners of a level change.
func (lc *LevelController) notifyListeners(oldLevel, newLevel LogLevel) {
	lc.mu.RLock()
	listeners := make([]LevelChangeListener, len(lc.listeners))
	copy(listeners, lc.listeners)
	lc.mu.RUnlock()

	for _, fn := range listeners {
		// Call listeners in goroutines to prevent blocking
		go func(callback LevelChangeListener) {
			defer func() {
				if r := recover(); r != nil {
					// Log panic but don't crash
					if lc.logger != nil {
						lc.logger.Error().
							Interface("panic", r).
							Msg("Level change listener panicked")
					}
				}
			}()
			callback(oldLevel, newLevel)
		}(fn)
	}
}

// ============================================================================
// Level Utilities
// ============================================================================

// AllLevels returns all valid log levels in order of verbosity.
func AllLevels() []LogLevel {
	return []LogLevel{
		LevelTrace,
		LevelDebug,
		LevelInfo,
		LevelWarn,
		LevelError,
		LevelFatal,
		LevelDisabled,
	}
}

// LevelNames returns all valid log level names.
func LevelNames() []string {
	return []string{
		"trace",
		"debug",
		"info",
		"warn",
		"error",
		"fatal",
		"disabled",
	}
}

// IsMoreVerbose returns true if level a is more verbose than level b.
func IsMoreVerbose(a, b LogLevel) bool {
	return a < b
}

// IsLessVerbose returns true if level a is less verbose than level b.
func IsLessVerbose(a, b LogLevel) bool {
	return a > b
}

// ShouldLog returns true if a message at messageLevel should be logged
// given the current configured level.
func ShouldLog(configuredLevel, messageLevel LogLevel) bool {
	return messageLevel >= configuredLevel
}

// ============================================================================
// Level Accessor Functions
// ============================================================================

// SetGlobalLevel sets the global logger's level.
func SetGlobalLevel(level LogLevel) {
	if globalLogger != nil {
		globalLogger.SetLevel(level)
	}
}

// GetGlobalLevel returns the global logger's level.
func GetGlobalLevel() LogLevel {
	if globalLogger != nil {
		return globalLogger.GetLevel()
	}
	return LevelInfo
}
