package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	globalLogger *slog.Logger
	mu           sync.RWMutex
	initialized  bool
)

func init() {
	// Initialize with a default no-op or stdout logger to prevent panic before Init is called
	globalLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Init initializes the global logger with the provided configuration.
// It returns an error if initialization fails.
func Init(cfg LogConfig) error {
	mu.Lock()
	defer mu.Unlock()

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid log configuration: %w", err)
	}

	if !cfg.Enabled {
		globalLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
		initialized = true
		return nil
	}

	var writers []io.Writer

	// Setup file output
	if cfg.FilePath != "" {
		rotator, err := NewLogRotator(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize log rotator: %w", err)
		}
		writers = append(writers, rotator)
	}

	// Setup console output
	if cfg.Console {
		writers = append(writers, os.Stdout)
	}

	if len(writers) == 0 {
		// Enabled but no output defined? Default to stdout
		writers = append(writers, os.Stdout)
	}

	// Create MultiWriter
	w := io.MultiWriter(writers...)

	// Parse Level
	var level slog.Level
	switch strings.ToLower(string(cfg.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create Handler options
	opts := &slog.HandlerOptions{
		Level: level,
		// AddSource: true, // Optional: Include file/line number (can be expensive)
	}

	// Create Logger
	var handler slog.Handler
	if strings.ToLower(string(cfg.Format)) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	globalLogger = slog.New(handler)
	initialized = true

	// Log initial message
	globalLogger.Info("Logging initialized",
		slog.String("level", level.String()),
		slog.String("format", string(cfg.Format)),
		slog.String("path", cfg.FilePath),
	)

	return nil
}

// Get returns the global logger instance.
func Get() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return globalLogger
}

// Helper functions for quick logging without getting the logger instance

func Debug(msg string, args ...any) {
	Get().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	Get().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	Get().Warn(msg, args...)
}

func Error(msg string, args ...any) {
	Get().Error(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	Get().DebugContext(ctx, msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	Get().InfoContext(ctx, msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	Get().WarnContext(ctx, msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	Get().ErrorContext(ctx, msg, args...)
}

// Sync flushes any buffered log entries.
// Since we use direct writers (os.Stdout, lumberjack), flush is usually automatic,
// but lumberjack Close() might be needed for graceful shutdown.
// We might need to store the rotator to close it.
// For now, OS handles file closing on exit, but explicit Close is better.
// We'd need to change the global variable to store the closer.
