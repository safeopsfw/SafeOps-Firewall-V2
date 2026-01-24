// Package logging provides structured logging for the firewall engine.
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// ============================================================================
// Zerolog Logger Implementation
// ============================================================================

// zerologLogger implements the Logger interface using zerolog.
type zerologLogger struct {
	zl     zerolog.Logger
	level  atomic.Int32
	config LogConfig
	output io.Writer
	mu     sync.RWMutex
}

// Verify interface compliance at compile time.
var _ Logger = (*zerologLogger)(nil)

// init registers the NewLogger factory function.
func init() {
	NewLogger = newZerologLogger
	NewWithOutput = newZerologLoggerWithOutput
}

// newZerologLogger creates a new zerolog-based logger with the given configuration.
func newZerologLogger(config LogConfig) (Logger, error) {
	// Apply defaults
	config.ApplyDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid log config: %w", err)
	}

	// Build output writer
	output, err := buildOutput(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build output: %w", err)
	}

	return newZerologLoggerWithOutput(config, output)
}

// newZerologLoggerWithOutput creates a new zerolog logger with a custom output.
func newZerologLoggerWithOutput(config LogConfig, output io.Writer) (Logger, error) {
	// Apply defaults
	config.ApplyDefaults()

	// Configure zerolog globals
	configureZerologGlobals(config)

	// Build the writer (console or JSON)
	var writer io.Writer = output
	if config.Format == FormatConsole {
		writer = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
	}

	// Build logger context
	ctx := zerolog.New(writer).With()

	// Add timestamp if enabled
	if config.EnableTimestamp {
		ctx = ctx.Timestamp()
	}

	// Add caller if enabled
	if config.EnableCaller {
		ctx = ctx.Caller()
	}

	// Build final logger with level
	zl := ctx.Logger().Level(toZerologLevel(config.Level))

	// Create wrapper
	l := &zerologLogger{
		zl:     zl,
		config: config,
		output: output,
	}
	l.level.Store(int32(config.Level))

	return l, nil
}

// buildOutput creates the output writer based on configuration.
func buildOutput(config LogConfig) (io.Writer, error) {
	switch config.Output {
	case OutputStdout:
		return os.Stdout, nil

	case OutputFile:
		// File output will be handled by rotation.go
		// For now, just open the file
		f, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", config.FilePath, err)
		}
		return f, nil

	case OutputBoth:
		// Create file
		f, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", config.FilePath, err)
		}
		// Multi-writer to both
		return io.MultiWriter(os.Stdout, f), nil

	default:
		return os.Stdout, nil
	}
}

// configureZerologGlobals sets zerolog global configuration.
func configureZerologGlobals(config LogConfig) {
	// Set timestamp field name
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "message"
	zerolog.ErrorFieldName = "error"
	zerolog.CallerFieldName = "caller"

	// Set time format
	switch config.TimestampFormat {
	case "unix_ms":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	case "unix":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	case "unix_micro":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMicro
	default:
		zerolog.TimeFieldFormat = time.RFC3339Nano
	}
}

// toZerologLevel converts LogLevel to zerolog.Level.
func toZerologLevel(l LogLevel) zerolog.Level {
	switch l {
	case LevelTrace:
		return zerolog.TraceLevel
	case LevelDebug:
		return zerolog.DebugLevel
	case LevelInfo:
		return zerolog.InfoLevel
	case LevelWarn:
		return zerolog.WarnLevel
	case LevelError:
		return zerolog.ErrorLevel
	case LevelFatal:
		return zerolog.FatalLevel
	case LevelDisabled:
		return zerolog.Disabled
	default:
		return zerolog.InfoLevel
	}
}

// fromZerologLevel converts zerolog.Level to LogLevel.
func fromZerologLevel(l zerolog.Level) LogLevel {
	switch l {
	case zerolog.TraceLevel:
		return LevelTrace
	case zerolog.DebugLevel:
		return LevelDebug
	case zerolog.InfoLevel:
		return LevelInfo
	case zerolog.WarnLevel:
		return LevelWarn
	case zerolog.ErrorLevel:
		return LevelError
	case zerolog.FatalLevel:
		return LevelFatal
	case zerolog.Disabled:
		return LevelDisabled
	default:
		return LevelInfo
	}
}

// ============================================================================
// Logger Interface Implementation
// ============================================================================

// Trace returns a trace-level event.
func (l *zerologLogger) Trace() Event {
	return &zerologEvent{e: l.zl.Trace()}
}

// Debug returns a debug-level event.
func (l *zerologLogger) Debug() Event {
	return &zerologEvent{e: l.zl.Debug()}
}

// Info returns an info-level event.
func (l *zerologLogger) Info() Event {
	return &zerologEvent{e: l.zl.Info()}
}

// Warn returns a warn-level event.
func (l *zerologLogger) Warn() Event {
	return &zerologEvent{e: l.zl.Warn()}
}

// Error returns an error-level event.
func (l *zerologLogger) Error() Event {
	return &zerologEvent{e: l.zl.Error()}
}

// Fatal returns a fatal-level event.
func (l *zerologLogger) Fatal() Event {
	return &zerologEvent{e: l.zl.Fatal()}
}

// GetLevel returns the current log level.
func (l *zerologLogger) GetLevel() LogLevel {
	return LogLevel(l.level.Load())
}

// SetLevel sets the log level atomically.
func (l *zerologLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.level.Store(int32(level))
	l.zl = l.zl.Level(toZerologLevel(level))
}

// With returns a context for building child loggers.
func (l *zerologLogger) With() Context {
	return &zerologContext{
		c:      l.zl.With(),
		config: l.config,
		output: l.output,
	}
}

// WithComponent returns a logger with component field attached.
func (l *zerologLogger) WithComponent(name string) Logger {
	newZl := l.zl.With().Str(FieldComponent, name).Logger()
	return &zerologLogger{
		zl:     newZl,
		config: l.config,
		output: l.output,
	}
}

// WithFlow returns a logger with flow context attached.
func (l *zerologLogger) WithFlow(flowID string, srcIP, dstIP string, srcPort, dstPort int) Logger {
	newZl := l.zl.With().
		Str(FieldFlowID, flowID).
		Str(FieldSrcIP, srcIP).
		Int(FieldSrcPort, srcPort).
		Str(FieldDstIP, dstIP).
		Int(FieldDstPort, dstPort).
		Logger()
	return &zerologLogger{
		zl:     newZl,
		config: l.config,
		output: l.output,
	}
}

// WithField returns a logger with a field attached.
func (l *zerologLogger) WithField(key string, value interface{}) Logger {
	newZl := l.zl.With().Interface(key, value).Logger()
	return &zerologLogger{
		zl:     newZl,
		config: l.config,
		output: l.output,
	}
}

// WithFields returns a logger with multiple fields attached.
func (l *zerologLogger) WithFields(fields map[string]interface{}) Logger {
	ctx := l.zl.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &zerologLogger{
		zl:     ctx.Logger(),
		config: l.config,
		output: l.output,
	}
}

// WithError returns a logger with an error field attached.
func (l *zerologLogger) WithError(err error) Logger {
	newZl := l.zl.With().Err(err).Logger()
	return &zerologLogger{
		zl:     newZl,
		config: l.config,
		output: l.output,
	}
}

// Output returns the current output writer.
func (l *zerologLogger) Output() io.Writer {
	return l.output
}

// SetOutput sets the output writer.
func (l *zerologLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.output = w

	// Rebuild logger with new output
	var writer io.Writer = w
	if l.config.Format == FormatConsole {
		writer = zerolog.ConsoleWriter{
			Out:        w,
			TimeFormat: "15:04:05",
		}
	}

	ctx := zerolog.New(writer).With()
	if l.config.EnableTimestamp {
		ctx = ctx.Timestamp()
	}
	if l.config.EnableCaller {
		ctx = ctx.Caller()
	}

	l.zl = ctx.Logger().Level(toZerologLevel(LogLevel(l.level.Load())))
}

// Sync flushes any buffered logs.
func (l *zerologLogger) Sync() error {
	// Zerolog writes are synchronous, but we can sync file writers
	if f, ok := l.output.(*os.File); ok {
		return f.Sync()
	}
	return nil
}

// ============================================================================
// Zerolog Event Implementation
// ============================================================================

// zerologEvent wraps zerolog.Event to implement the Event interface.
type zerologEvent struct {
	e *zerolog.Event
}

// Verify interface compliance at compile time.
var _ Event = (*zerologEvent)(nil)

// Str adds a string field.
func (e *zerologEvent) Str(key, val string) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Str(key, val)
	return e
}

// Strs adds a string slice field.
func (e *zerologEvent) Strs(key string, vals []string) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Strs(key, vals)
	return e
}

// Int adds an int field.
func (e *zerologEvent) Int(key string, val int) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Int(key, val)
	return e
}

// Int8 adds an int8 field.
func (e *zerologEvent) Int8(key string, val int8) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Int8(key, val)
	return e
}

// Int16 adds an int16 field.
func (e *zerologEvent) Int16(key string, val int16) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Int16(key, val)
	return e
}

// Int32 adds an int32 field.
func (e *zerologEvent) Int32(key string, val int32) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Int32(key, val)
	return e
}

// Int64 adds an int64 field.
func (e *zerologEvent) Int64(key string, val int64) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Int64(key, val)
	return e
}

// Uint adds a uint field.
func (e *zerologEvent) Uint(key string, val uint) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Uint(key, val)
	return e
}

// Uint8 adds a uint8 field.
func (e *zerologEvent) Uint8(key string, val uint8) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Uint8(key, val)
	return e
}

// Uint16 adds a uint16 field.
func (e *zerologEvent) Uint16(key string, val uint16) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Uint16(key, val)
	return e
}

// Uint32 adds a uint32 field.
func (e *zerologEvent) Uint32(key string, val uint32) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Uint32(key, val)
	return e
}

// Uint64 adds a uint64 field.
func (e *zerologEvent) Uint64(key string, val uint64) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Uint64(key, val)
	return e
}

// Float32 adds a float32 field.
func (e *zerologEvent) Float32(key string, val float32) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Float32(key, val)
	return e
}

// Float64 adds a float64 field.
func (e *zerologEvent) Float64(key string, val float64) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Float64(key, val)
	return e
}

// Bool adds a boolean field.
func (e *zerologEvent) Bool(key string, val bool) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Bool(key, val)
	return e
}

// Err adds an error field.
func (e *zerologEvent) Err(err error) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Err(err)
	return e
}

// Time adds a time field.
func (e *zerologEvent) Time(key string, val time.Time) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Time(key, val)
	return e
}

// Dur adds a duration field.
func (e *zerologEvent) Dur(key string, d time.Duration) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Dur(key, d)
	return e
}

// TimeDiff adds a time difference field.
func (e *zerologEvent) TimeDiff(key string, t time.Time, start time.Time) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.TimeDiff(key, t, start)
	return e
}

// Interface adds an interface field.
func (e *zerologEvent) Interface(key string, val interface{}) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Interface(key, val)
	return e
}

// Fields adds multiple fields from a map.
func (e *zerologEvent) Fields(fields map[string]interface{}) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Fields(fields)
	return e
}

// IPAddr adds an IP address field.
func (e *zerologEvent) IPAddr(key string, ip string) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Str(key, ip)
	return e
}

// Caller adds caller information.
func (e *zerologEvent) Caller() Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.Caller()
	return e
}

// CallerSkipFrame adds caller info with frame skip.
func (e *zerologEvent) CallerSkipFrame(skip int) Event {
	if e.e == nil {
		return e
	}
	e.e = e.e.CallerSkipFrame(skip)
	return e
}

// Msg sends the event with a message.
func (e *zerologEvent) Msg(msg string) {
	if e.e == nil {
		return
	}
	e.e.Msg(msg)
	e.e = nil
}

// Msgf sends the event with a formatted message.
func (e *zerologEvent) Msgf(format string, v ...interface{}) {
	if e.e == nil {
		return
	}
	e.e.Msgf(format, v...)
	e.e = nil
}

// Send sends the event without a message.
func (e *zerologEvent) Send() {
	if e.e == nil {
		return
	}
	e.e.Send()
	e.e = nil
}

// Enabled returns true if this event will be logged.
func (e *zerologEvent) Enabled() bool {
	return e.e != nil && e.e.Enabled()
}

// Discard prevents the event from being logged.
func (e *zerologEvent) Discard() {
	if e.e != nil {
		e.e.Discard()
	}
	e.e = nil
}

// ============================================================================
// Zerolog Context Implementation
// ============================================================================

// zerologContext wraps zerolog.Context to implement the Context interface.
type zerologContext struct {
	c      zerolog.Context
	config LogConfig
	output io.Writer
}

// Verify interface compliance at compile time.
var _ Context = (*zerologContext)(nil)

// Logger builds and returns the logger.
func (c *zerologContext) Logger() Logger {
	return &zerologLogger{
		zl:     c.c.Logger(),
		config: c.config,
		output: c.output,
	}
}

// Str adds a string field to the context.
func (c *zerologContext) Str(key, val string) Context {
	c.c = c.c.Str(key, val)
	return c
}

// Strs adds a string slice field to the context.
func (c *zerologContext) Strs(key string, vals []string) Context {
	c.c = c.c.Strs(key, vals)
	return c
}

// Int adds an int field to the context.
func (c *zerologContext) Int(key string, val int) Context {
	c.c = c.c.Int(key, val)
	return c
}

// Int64 adds an int64 field to the context.
func (c *zerologContext) Int64(key string, val int64) Context {
	c.c = c.c.Int64(key, val)
	return c
}

// Uint64 adds a uint64 field to the context.
func (c *zerologContext) Uint64(key string, val uint64) Context {
	c.c = c.c.Uint64(key, val)
	return c
}

// Float64 adds a float64 field to the context.
func (c *zerologContext) Float64(key string, val float64) Context {
	c.c = c.c.Float64(key, val)
	return c
}

// Bool adds a boolean field to the context.
func (c *zerologContext) Bool(key string, val bool) Context {
	c.c = c.c.Bool(key, val)
	return c
}

// Err adds an error field to the context.
func (c *zerologContext) Err(err error) Context {
	c.c = c.c.Err(err)
	return c
}

// Time adds a time field to the context.
func (c *zerologContext) Time(key string, val time.Time) Context {
	c.c = c.c.Time(key, val)
	return c
}

// Dur adds a duration field to the context.
func (c *zerologContext) Dur(key string, d time.Duration) Context {
	c.c = c.c.Dur(key, d)
	return c
}

// Interface adds an interface field to the context.
func (c *zerologContext) Interface(key string, val interface{}) Context {
	c.c = c.c.Interface(key, val)
	return c
}

// Fields adds multiple fields to the context.
func (c *zerologContext) Fields(fields map[string]interface{}) Context {
	c.c = c.c.Fields(fields)
	return c
}

// Caller adds caller information to the context.
func (c *zerologContext) Caller() Context {
	c.c = c.c.Caller()
	return c
}

// CallerWithSkipFrameCount adds caller info with frame skip.
func (c *zerologContext) CallerWithSkipFrameCount(skipFrameCount int) Context {
	c.c = c.c.CallerWithSkipFrameCount(skipFrameCount)
	return c
}

// Timestamp adds a timestamp to the context.
func (c *zerologContext) Timestamp() Context {
	c.c = c.c.Timestamp()
	return c
}
