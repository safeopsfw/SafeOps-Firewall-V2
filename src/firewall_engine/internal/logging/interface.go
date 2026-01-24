// Package logging provides structured logging for the firewall engine.
// It uses zerolog as the backend for high-performance, zero-allocation logging.
package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrInvalidLevel is returned when an invalid log level is specified.
	ErrInvalidLevel = errors.New("invalid log level")

	// ErrInvalidFormat is returned when an invalid log format is specified.
	ErrInvalidFormat = errors.New("invalid log format")

	// ErrInvalidOutput is returned when an invalid output type is specified.
	ErrInvalidOutput = errors.New("invalid output type")

	// ErrNoFilePath is returned when file output is requested but no path is provided.
	ErrNoFilePath = errors.New("file path required for file output")

	// ErrLoggerNotInitialized is returned when the global logger is not set.
	ErrLoggerNotInitialized = errors.New("global logger not initialized")

	// ErrLoggerAlreadyInitialized is returned when trying to initialize an already initialized logger.
	ErrLoggerAlreadyInitialized = errors.New("global logger already initialized")
)

// ============================================================================
// Log Levels
// ============================================================================

// LogLevel represents logging severity level.
type LogLevel int8

const (
	// LevelTrace is the most verbose level, used for detailed debugging.
	LevelTrace LogLevel = iota - 1

	// LevelDebug is used for debugging information.
	LevelDebug

	// LevelInfo is used for general operational information.
	LevelInfo

	// LevelWarn is used for warning conditions.
	LevelWarn

	// LevelError is used for error conditions.
	LevelError

	// LevelFatal is used for fatal errors that cause the application to exit.
	LevelFatal

	// LevelDisabled disables all logging.
	LevelDisabled
)

// String returns the string representation of the log level.
func (l LogLevel) String() string {
	switch l {
	case LevelTrace:
		return "trace"
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelFatal:
		return "fatal"
	case LevelDisabled:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", l)
	}
}

// IsValid returns true if the log level is valid.
func (l LogLevel) IsValid() bool {
	return l >= LevelTrace && l <= LevelDisabled
}

// ============================================================================
// Log Format and Output Types
// ============================================================================

// LogFormat specifies the output format for logs.
type LogFormat string

const (
	// FormatJSON outputs logs in JSON format (production).
	FormatJSON LogFormat = "json"

	// FormatConsole outputs logs in human-readable format (development).
	FormatConsole LogFormat = "console"
)

// IsValid returns true if the format is valid.
func (f LogFormat) IsValid() bool {
	return f == FormatJSON || f == FormatConsole
}

// OutputType specifies where logs are written.
type OutputType string

const (
	// OutputStdout writes logs to stdout only.
	OutputStdout OutputType = "stdout"

	// OutputFile writes logs to a file only.
	OutputFile OutputType = "file"

	// OutputBoth writes logs to both stdout and file.
	OutputBoth OutputType = "both"
)

// IsValid returns true if the output type is valid.
func (o OutputType) IsValid() bool {
	return o == OutputStdout || o == OutputFile || o == OutputBoth
}

// ============================================================================
// Log Configuration
// ============================================================================

// LogConfig holds the configuration for the logger.
type LogConfig struct {
	// Level is the minimum log level to output.
	Level LogLevel `json:"level" toml:"level"`

	// Format specifies the output format (json or console).
	Format LogFormat `json:"format" toml:"format"`

	// Output specifies where to write logs (stdout, file, or both).
	Output OutputType `json:"output" toml:"output"`

	// FilePath is the path for file output (required if Output is file or both).
	FilePath string `json:"file_path" toml:"file_path"`

	// MaxSizeMB is the maximum size of a log file before rotation (in MB).
	MaxSizeMB int `json:"max_size_mb" toml:"max_size_mb"`

	// MaxBackups is the maximum number of old log files to keep.
	MaxBackups int `json:"max_backups" toml:"max_backups"`

	// MaxAgeDays is the maximum number of days to keep old log files.
	MaxAgeDays int `json:"max_age_days" toml:"max_age_days"`

	// Compress determines whether rotated log files should be compressed.
	Compress bool `json:"compress" toml:"compress"`

	// EnableSampling enables log sampling to reduce volume.
	EnableSampling bool `json:"enable_sampling" toml:"enable_sampling"`

	// SamplingInitial is the number of logs to write before sampling starts.
	SamplingInitial int `json:"sampling_initial" toml:"sampling_initial"`

	// SamplingRate is the sampling rate (1 in N logs are written).
	SamplingRate int `json:"sampling_rate" toml:"sampling_rate"`

	// EnableCaller adds caller information (file:line) to log entries.
	EnableCaller bool `json:"enable_caller" toml:"enable_caller"`

	// EnableTimestamp adds a timestamp to log entries.
	EnableTimestamp bool `json:"enable_timestamp" toml:"enable_timestamp"`

	// TimestampFormat specifies the timestamp format (unix_ms or rfc3339).
	TimestampFormat string `json:"timestamp_format" toml:"timestamp_format"`
}

// Validate checks the configuration for errors.
func (c *LogConfig) Validate() error {
	if !c.Level.IsValid() {
		return fmt.Errorf("%w: %d", ErrInvalidLevel, c.Level)
	}

	if !c.Format.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidFormat, c.Format)
	}

	if !c.Output.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidOutput, c.Output)
	}

	if (c.Output == OutputFile || c.Output == OutputBoth) && c.FilePath == "" {
		return ErrNoFilePath
	}

	return nil
}

// ApplyDefaults fills in default values for unset fields.
func (c *LogConfig) ApplyDefaults() {
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 100
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = 10
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = 30
	}
	if c.SamplingInitial == 0 {
		c.SamplingInitial = 100
	}
	if c.SamplingRate == 0 {
		c.SamplingRate = 10
	}
	if c.TimestampFormat == "" {
		c.TimestampFormat = "rfc3339"
	}
	if !c.EnableTimestamp {
		c.EnableTimestamp = true
	}
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() LogConfig {
	return LogConfig{
		Level:           LevelInfo,
		Format:          FormatJSON,
		Output:          OutputStdout,
		MaxSizeMB:       100,
		MaxBackups:      10,
		MaxAgeDays:      30,
		Compress:        true,
		EnableSampling:  false,
		SamplingInitial: 100,
		SamplingRate:    10,
		EnableCaller:    false,
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}
}

// DefaultProductionConfig returns a production-optimized configuration.
func DefaultProductionConfig() LogConfig {
	return LogConfig{
		Level:           LevelInfo,
		Format:          FormatJSON,
		Output:          OutputBoth,
		FilePath:        "logs/firewall.log",
		MaxSizeMB:       100,
		MaxBackups:      10,
		MaxAgeDays:      30,
		Compress:        true,
		EnableSampling:  true,
		SamplingInitial: 100,
		SamplingRate:    10,
		EnableCaller:    true,
		EnableTimestamp: true,
		TimestampFormat: "unix_ms",
	}
}

// DefaultDevelopmentConfig returns a development-friendly configuration.
func DefaultDevelopmentConfig() LogConfig {
	return LogConfig{
		Level:           LevelDebug,
		Format:          FormatConsole,
		Output:          OutputStdout,
		EnableSampling:  false,
		EnableCaller:    true,
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}
}

// ============================================================================
// Logger Interface
// ============================================================================

// Logger is the main logging interface.
type Logger interface {
	// Level methods return an Event for building log entries.
	Trace() Event
	Debug() Event
	Info() Event
	Warn() Event
	Error() Event
	Fatal() Event

	// Level management
	GetLevel() LogLevel
	SetLevel(level LogLevel)

	// Context loggers
	With() Context
	WithComponent(name string) Logger
	WithFlow(flowID string, srcIP, dstIP string, srcPort, dstPort int) Logger
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
	WithError(err error) Logger

	// Output control
	Output() io.Writer
	SetOutput(w io.Writer)

	// Lifecycle
	Sync() error
}

// Event is a log event builder that allows adding fields before sending.
type Event interface {
	// String fields
	Str(key, val string) Event
	Strs(key string, vals []string) Event

	// Integer fields
	Int(key string, val int) Event
	Int8(key string, val int8) Event
	Int16(key string, val int16) Event
	Int32(key string, val int32) Event
	Int64(key string, val int64) Event

	// Unsigned integer fields
	Uint(key string, val uint) Event
	Uint8(key string, val uint8) Event
	Uint16(key string, val uint16) Event
	Uint32(key string, val uint32) Event
	Uint64(key string, val uint64) Event

	// Float fields
	Float32(key string, val float32) Event
	Float64(key string, val float64) Event

	// Boolean field
	Bool(key string, val bool) Event

	// Error field
	Err(err error) Event

	// Time fields
	Time(key string, val time.Time) Event
	Dur(key string, d time.Duration) Event
	TimeDiff(key string, t time.Time, start time.Time) Event

	// Complex types
	Interface(key string, val interface{}) Event
	Fields(fields map[string]interface{}) Event

	// IP address helpers
	IPAddr(key string, ip string) Event

	// Caller info
	Caller() Event
	CallerSkipFrame(skip int) Event

	// Send the log entry
	Msg(msg string)
	Msgf(format string, v ...interface{})
	Send() // Send without a message

	// Enabled returns true if this event will be logged.
	Enabled() bool

	// Discard prevents the event from being logged.
	Discard()
}

// Context is a logger context builder for creating child loggers with fields.
type Context interface {
	// Build the logger
	Logger() Logger

	// String fields
	Str(key, val string) Context
	Strs(key string, vals []string) Context

	// Integer fields
	Int(key string, val int) Context
	Int64(key string, val int64) Context
	Uint64(key string, val uint64) Context

	// Float fields
	Float64(key string, val float64) Context

	// Boolean field
	Bool(key string, val bool) Context

	// Error field
	Err(err error) Context

	// Time fields
	Time(key string, val time.Time) Context
	Dur(key string, d time.Duration) Context

	// Complex types
	Interface(key string, val interface{}) Context
	Fields(fields map[string]interface{}) Context

	// Caller info
	Caller() Context
	CallerWithSkipFrameCount(skipFrameCount int) Context

	// Timestamp
	Timestamp() Context
}

// ============================================================================
// Global Logger
// ============================================================================

var (
	globalLogger Logger
	globalMu     sync.RWMutex
	globalOnce   sync.Once
)

// SetGlobal sets the global logger instance.
// This should be called once at application startup.
func SetGlobal(l Logger) error {
	if l == nil {
		return errors.New("cannot set nil logger as global")
	}

	globalMu.Lock()
	defer globalMu.Unlock()

	globalLogger = l
	return nil
}

// L returns the global logger instance.
// If the global logger is not set, it returns a no-op logger.
func L() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()

	if globalLogger == nil {
		// Return a no-op logger to prevent panics.
		// This allows code to use L() before initialization.
		return &noopLogger{}
	}

	return globalLogger
}

// Global returns the global logger, returning an error if not initialized.
func Global() (Logger, error) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	if globalLogger == nil {
		return nil, ErrLoggerNotInitialized
	}

	return globalLogger, nil
}

// IsInitialized returns true if the global logger has been set.
func IsInitialized() bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger != nil
}

// ============================================================================
// No-op Logger (fallback when global not initialized)
// ============================================================================

// noopLogger is a no-op implementation of Logger.
type noopLogger struct{}

func (n *noopLogger) Trace() Event         { return &noopEvent{} }
func (n *noopLogger) Debug() Event         { return &noopEvent{} }
func (n *noopLogger) Info() Event          { return &noopEvent{} }
func (n *noopLogger) Warn() Event          { return &noopEvent{} }
func (n *noopLogger) Error() Event         { return &noopEvent{} }
func (n *noopLogger) Fatal() Event         { return &noopEvent{} }
func (n *noopLogger) GetLevel() LogLevel   { return LevelDisabled }
func (n *noopLogger) SetLevel(LogLevel)    {}
func (n *noopLogger) With() Context        { return &noopContext{} }
func (n *noopLogger) WithComponent(string) Logger { return n }
func (n *noopLogger) WithFlow(string, string, string, int, int) Logger { return n }
func (n *noopLogger) WithField(string, interface{}) Logger { return n }
func (n *noopLogger) WithFields(map[string]interface{}) Logger { return n }
func (n *noopLogger) WithError(error) Logger { return n }
func (n *noopLogger) Output() io.Writer    { return io.Discard }
func (n *noopLogger) SetOutput(io.Writer)  {}
func (n *noopLogger) Sync() error          { return nil }

// noopEvent is a no-op implementation of Event.
type noopEvent struct{}

func (e *noopEvent) Str(string, string) Event                         { return e }
func (e *noopEvent) Strs(string, []string) Event                      { return e }
func (e *noopEvent) Int(string, int) Event                            { return e }
func (e *noopEvent) Int8(string, int8) Event                          { return e }
func (e *noopEvent) Int16(string, int16) Event                        { return e }
func (e *noopEvent) Int32(string, int32) Event                        { return e }
func (e *noopEvent) Int64(string, int64) Event                        { return e }
func (e *noopEvent) Uint(string, uint) Event                          { return e }
func (e *noopEvent) Uint8(string, uint8) Event                        { return e }
func (e *noopEvent) Uint16(string, uint16) Event                      { return e }
func (e *noopEvent) Uint32(string, uint32) Event                      { return e }
func (e *noopEvent) Uint64(string, uint64) Event                      { return e }
func (e *noopEvent) Float32(string, float32) Event                    { return e }
func (e *noopEvent) Float64(string, float64) Event                    { return e }
func (e *noopEvent) Bool(string, bool) Event                          { return e }
func (e *noopEvent) Err(error) Event                                  { return e }
func (e *noopEvent) Time(string, time.Time) Event                     { return e }
func (e *noopEvent) Dur(string, time.Duration) Event                  { return e }
func (e *noopEvent) TimeDiff(string, time.Time, time.Time) Event      { return e }
func (e *noopEvent) Interface(string, interface{}) Event              { return e }
func (e *noopEvent) Fields(map[string]interface{}) Event              { return e }
func (e *noopEvent) IPAddr(string, string) Event                      { return e }
func (e *noopEvent) Caller() Event                                    { return e }
func (e *noopEvent) CallerSkipFrame(int) Event                        { return e }
func (e *noopEvent) Msg(string)                                       {}
func (e *noopEvent) Msgf(string, ...interface{})                      {}
func (e *noopEvent) Send()                                            {}
func (e *noopEvent) Enabled() bool                                    { return false }
func (e *noopEvent) Discard()                                         {}

// noopContext is a no-op implementation of Context.
type noopContext struct{}

func (c *noopContext) Logger() Logger                           { return &noopLogger{} }
func (c *noopContext) Str(string, string) Context               { return c }
func (c *noopContext) Strs(string, []string) Context            { return c }
func (c *noopContext) Int(string, int) Context                  { return c }
func (c *noopContext) Int64(string, int64) Context              { return c }
func (c *noopContext) Uint64(string, uint64) Context            { return c }
func (c *noopContext) Float64(string, float64) Context          { return c }
func (c *noopContext) Bool(string, bool) Context                { return c }
func (c *noopContext) Err(error) Context                        { return c }
func (c *noopContext) Time(string, time.Time) Context           { return c }
func (c *noopContext) Dur(string, time.Duration) Context        { return c }
func (c *noopContext) Interface(string, interface{}) Context    { return c }
func (c *noopContext) Fields(map[string]interface{}) Context    { return c }
func (c *noopContext) Caller() Context                          { return c }
func (c *noopContext) CallerWithSkipFrameCount(int) Context     { return c }
func (c *noopContext) Timestamp() Context                       { return c }

// ============================================================================
// Factory Function (implemented in zerolog.go)
// ============================================================================

// NewLogger creates a new logger with the given configuration.
// The actual implementation is in zerolog.go.
var NewLogger func(config LogConfig) (Logger, error)

// MustNewLogger creates a new logger or panics on error.
func MustNewLogger(config LogConfig) Logger {
	logger, err := NewLogger(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create logger: %v", err))
	}
	return logger
}

// NewWithOutput creates a new logger with a custom output writer.
var NewWithOutput func(config LogConfig, output io.Writer) (Logger, error)

// ============================================================================
// Utility Functions
// ============================================================================

// Discard returns an io.Writer that discards all writes.
func Discard() io.Writer {
	return io.Discard
}

// Stdout returns os.Stdout.
func Stdout() io.Writer {
	return os.Stdout
}

// Stderr returns os.Stderr.
func Stderr() io.Writer {
	return os.Stderr
}
