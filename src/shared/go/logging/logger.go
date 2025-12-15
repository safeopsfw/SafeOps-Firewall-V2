// Package logging provides structured logging with logrus.
package logging

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
	fields logrus.Fields
	mu     sync.RWMutex
}

// Entry wraps logrus.Entry
type Entry = logrus.Entry

// Fields type alias
type Fields = logrus.Fields

// Global default logger
var defaultLogger *Logger

func init() {
	defaultLogger = New()
}

// New creates a new logger with default configuration
func New() *Logger {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	l.SetLevel(logrus.InfoLevel)
	l.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	return &Logger{
		Logger: l,
		fields: make(logrus.Fields),
	}
}

// Default returns the default logger
func Default() *Logger {
	return defaultLogger
}

// SetDefault sets the default logger
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Config for logger
type Config struct {
	Level      string
	Format     string
	Output     string
	TimeFormat string
}

// NewWithConfig creates a logger with configuration
func NewWithConfig(cfg Config) *Logger {
	l := New()

	// Set level
	if level, err := ParseLevel(cfg.Level); err == nil {
		l.SetLevel(level)
	}

	// Set format
	switch cfg.Format {
	case "json":
		l.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: cfg.TimeFormat,
		})
	case "text", "console":
		l.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: cfg.TimeFormat,
			FullTimestamp:   true,
		})
	}

	// Set output
	switch cfg.Output {
	case "stdout", "":
		l.SetOutput(os.Stdout)
	case "stderr":
		l.SetOutput(os.Stderr)
	default:
		if f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
			l.SetOutput(f)
		}
	}

	return l
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	fields := make(logrus.Fields)
	for k, v := range l.fields {
		fields[k] = v
	}
	fields[key] = value

	return l.Logger.WithFields(fields)
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	combined := make(logrus.Fields)
	for k, v := range l.fields {
		combined[k] = v
	}
	for k, v := range fields {
		combined[k] = v
	}

	return l.Logger.WithFields(combined)
}

// WithError adds an error field
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.WithField("error", err)
}

// WithContext adds context fields
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.WithFields(l.fields)

	// Extract common context values
	if requestID := ctx.Value("request_id"); requestID != nil {
		entry = entry.WithField("request_id", requestID)
	}
	if userID := ctx.Value("user_id"); userID != nil {
		entry = entry.WithField("user_id", userID)
	}
	if traceID := ctx.Value("trace_id"); traceID != nil {
		entry = entry.WithField("trace_id", traceID)
	}

	return entry
}

// AddPermanentField adds a field that persists across all log calls
func (l *Logger) AddPermanentField(key string, value interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[key] = value
}

// AddPermanentFields adds multiple permanent fields
func (l *Logger) AddPermanentFields(fields Fields) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range fields {
		l.fields[k] = v
	}
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.Logger.SetOutput(w)
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level logrus.Level) {
	l.Logger.SetLevel(level)
}

// SetLevelString sets the log level from string
func (l *Logger) SetLevelString(level string) error {
	lvl, err := ParseLevel(level)
	if err != nil {
		return err
	}
	l.SetLevel(lvl)
	return nil
}

// SetFormatter sets the log formatter
func (l *Logger) SetFormatter(formatter logrus.Formatter) {
	l.Logger.SetFormatter(formatter)
}

// Clone creates a copy of the logger
func (l *Logger) Clone() *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	clone := &Logger{
		Logger: l.Logger,
		fields: make(logrus.Fields),
	}

	for k, v := range l.fields {
		clone.fields[k] = v
	}

	return clone
}

// Child creates a child logger with additional fields
func (l *Logger) Child(fields Fields) *Logger {
	child := l.Clone()
	child.AddPermanentFields(fields)
	return child
}

// Package-level logging functions that use the default logger

// Debug logs a debug message
func Debug(args ...interface{}) {
	defaultLogger.Debug(args...)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

// Info logs an info message
func Info(args ...interface{}) {
	defaultLogger.Info(args...)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	defaultLogger.Warn(args...)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	defaultLogger.Warnf(format, args...)
}

// Error logs an error message
func Error(args ...interface{}) {
	defaultLogger.Error(args...)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func Fatal(args ...interface{}) {
	defaultLogger.Fatal(args...)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

// WithField adds a field to the default logger
func WithField(key string, value interface{}) *logrus.Entry {
	return defaultLogger.WithField(key, value)
}

// WithFields adds fields to the default logger
func WithFields(fields Fields) *logrus.Entry {
	return defaultLogger.WithFields(fields)
}

// WithError adds an error to the default logger
func WithError(err error) *logrus.Entry {
	return defaultLogger.WithError(err)
}
