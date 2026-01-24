// Package logging provides structured logging for the firewall engine.
package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// ============================================================================
// Rotation Errors
// ============================================================================

var (
	// ErrRotationNotConfigured is returned when rotation is not configured.
	ErrRotationNotConfigured = errors.New("log rotation not configured")

	// ErrInvalidRotationConfig is returned when rotation config is invalid.
	ErrInvalidRotationConfig = errors.New("invalid rotation configuration")
)

// ============================================================================
// Rotation Configuration
// ============================================================================

// RotationConfig configures log file rotation behavior.
type RotationConfig struct {
	// Filename is the file to write logs to.
	// Backup log files will be retained in the same directory.
	Filename string `json:"filename" toml:"filename"`

	// MaxSizeMB is the maximum size in megabytes of the log file before it
	// gets rotated. Default is 100 megabytes.
	MaxSizeMB int `json:"max_size_mb" toml:"max_size_mb"`

	// MaxBackups is the maximum number of old log files to retain.
	// Default is 10 files.
	MaxBackups int `json:"max_backups" toml:"max_backups"`

	// MaxAgeDays is the maximum number of days to retain old log files.
	// Default is 30 days.
	MaxAgeDays int `json:"max_age_days" toml:"max_age_days"`

	// Compress determines if the rotated log files should be compressed
	// using gzip. Default is true.
	Compress bool `json:"compress" toml:"compress"`

	// LocalTime determines if the time used for formatting the timestamps
	// in backup files is the local time. Default is true.
	LocalTime bool `json:"local_time" toml:"local_time"`
}

// DefaultRotationConfig returns a rotation config with sensible defaults.
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		MaxSizeMB:  100,
		MaxBackups: 10,
		MaxAgeDays: 30,
		Compress:   true,
		LocalTime:  true,
	}
}

// Validate checks the rotation configuration for errors.
func (c *RotationConfig) Validate() error {
	if c.Filename == "" {
		return fmt.Errorf("%w: filename is required", ErrInvalidRotationConfig)
	}

	if c.MaxSizeMB < 0 {
		return fmt.Errorf("%w: max_size_mb must be non-negative", ErrInvalidRotationConfig)
	}

	if c.MaxBackups < 0 {
		return fmt.Errorf("%w: max_backups must be non-negative", ErrInvalidRotationConfig)
	}

	if c.MaxAgeDays < 0 {
		return fmt.Errorf("%w: max_age_days must be non-negative", ErrInvalidRotationConfig)
	}

	return nil
}

// ApplyDefaults fills in default values for unset fields.
func (c *RotationConfig) ApplyDefaults() {
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 100
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = 10
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = 30
	}
}

// ============================================================================
// Rotating Writer
// ============================================================================

// RotatingWriter is an io.Writer that automatically rotates log files
// based on size and age policies.
type RotatingWriter struct {
	lj     *lumberjack.Logger
	config RotationConfig
	mu     sync.RWMutex
	closed bool
}

// Ensure RotatingWriter implements io.WriteCloser.
var _ io.WriteCloser = (*RotatingWriter)(nil)

// NewRotatingWriter creates a new rotating log writer.
func NewRotatingWriter(config RotationConfig) (*RotatingWriter, error) {
	// Apply defaults
	config.ApplyDefaults()

	// Validate config
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Ensure directory exists
	dir := filepath.Dir(config.Filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
		}
	}

	// Create lumberjack logger
	lj := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSizeMB,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAgeDays,
		Compress:   config.Compress,
		LocalTime:  config.LocalTime,
	}

	return &RotatingWriter{
		lj:     lj,
		config: config,
	}, nil
}

// Write writes data to the log file.
func (rw *RotatingWriter) Write(p []byte) (n int, err error) {
	rw.mu.RLock()
	if rw.closed {
		rw.mu.RUnlock()
		return 0, errors.New("writer is closed")
	}
	rw.mu.RUnlock()

	return rw.lj.Write(p)
}

// Rotate forces an immediate log file rotation.
// This is useful for manual rotation triggers (e.g., via signal or API).
func (rw *RotatingWriter) Rotate() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.closed {
		return errors.New("writer is closed")
	}

	return rw.lj.Rotate()
}

// Close closes the log file.
func (rw *RotatingWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.closed {
		return nil
	}

	rw.closed = true
	return rw.lj.Close()
}

// GetConfig returns the current rotation configuration.
func (rw *RotatingWriter) GetConfig() RotationConfig {
	return rw.config
}

// ============================================================================
// Multi-Writer Support
// ============================================================================

// MultiWriter creates an io.Writer that duplicates writes to multiple writers.
// This is useful for writing to both stdout and a file simultaneously.
func MultiWriter(writers ...io.Writer) io.Writer {
	// Filter out nil writers
	validWriters := make([]io.Writer, 0, len(writers))
	for _, w := range writers {
		if w != nil {
			validWriters = append(validWriters, w)
		}
	}

	if len(validWriters) == 0 {
		return io.Discard
	}

	if len(validWriters) == 1 {
		return validWriters[0]
	}

	return io.MultiWriter(validWriters...)
}

// ============================================================================
// Factory Functions
// ============================================================================

// NewFileWriter creates a simple file writer (without rotation).
func NewFileWriter(filename string) (io.WriteCloser, error) {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", filename, err)
	}

	return f, nil
}

// NewRotatingFileWriter creates a rotating file writer from LogConfig.
func NewRotatingFileWriter(config LogConfig) (*RotatingWriter, error) {
	rotConfig := RotationConfig{
		Filename:   config.FilePath,
		MaxSizeMB:  config.MaxSizeMB,
		MaxBackups: config.MaxBackups,
		MaxAgeDays: config.MaxAgeDays,
		Compress:   config.Compress,
		LocalTime:  true,
	}

	return NewRotatingWriter(rotConfig)
}

// NewLoggerWithRotation creates a logger with rotating file output.
func NewLoggerWithRotation(config LogConfig) (Logger, *RotatingWriter, error) {
	// Validate
	if config.Output != OutputFile && config.Output != OutputBoth {
		return nil, nil, errors.New("rotation requires file output")
	}

	// Create rotating writer
	rw, err := NewRotatingFileWriter(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create rotating writer: %w", err)
	}

	// Build output
	var output io.Writer
	switch config.Output {
	case OutputFile:
		output = rw
	case OutputBoth:
		output = MultiWriter(os.Stdout, rw)
	}

	// Create logger with output
	logger, err := NewWithOutput(config, output)
	if err != nil {
		rw.Close()
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return logger, rw, nil
}

// ============================================================================
// Sync Writer Wrapper
// ============================================================================

// SyncWriter wraps an io.Writer and adds synchronization for thread safety.
type SyncWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewSyncWriter creates a new synchronized writer.
func NewSyncWriter(w io.Writer) *SyncWriter {
	return &SyncWriter{w: w}
}

// Write writes data with synchronization.
func (sw *SyncWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

// ============================================================================
// Buffered Writer (for high-throughput scenarios)
// ============================================================================

// BufferedWriter wraps a writer with buffering for improved throughput.
// Note: This defers writes and should be flushed before shutdown.
type BufferedWriter struct {
	w      io.Writer
	buffer []byte
	size   int
	mu     sync.Mutex
}

// NewBufferedWriter creates a new buffered writer.
func NewBufferedWriter(w io.Writer, bufferSize int) *BufferedWriter {
	if bufferSize <= 0 {
		bufferSize = 4096 // 4KB default
	}
	return &BufferedWriter{
		w:      w,
		buffer: make([]byte, 0, bufferSize),
		size:   bufferSize,
	}
}

// Write buffers data and flushes when buffer is full.
func (bw *BufferedWriter) Write(p []byte) (n int, err error) {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	// If data exceeds buffer, flush and write directly
	if len(p) >= bw.size {
		if err := bw.flushLocked(); err != nil {
			return 0, err
		}
		return bw.w.Write(p)
	}

	// If adding would exceed buffer, flush first
	if len(bw.buffer)+len(p) > bw.size {
		if err := bw.flushLocked(); err != nil {
			return 0, err
		}
	}

	// Append to buffer
	bw.buffer = append(bw.buffer, p...)
	return len(p), nil
}

// Flush flushes the buffer to the underlying writer.
func (bw *BufferedWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked()
}

func (bw *BufferedWriter) flushLocked() error {
	if len(bw.buffer) == 0 {
		return nil
	}

	_, err := bw.w.Write(bw.buffer)
	bw.buffer = bw.buffer[:0]
	return err
}

// Close flushes and closes the writer if it implements io.Closer.
func (bw *BufferedWriter) Close() error {
	if err := bw.Flush(); err != nil {
		return err
	}
	if c, ok := bw.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// ============================================================================
// Time-Based Rotation (for ELK integration)
// ============================================================================

// TimeBasedRotationConfig configures time-based log rotation.
type TimeBasedRotationConfig struct {
	// Filename is the base filename for logs.
	// Rotated files will be named: filename.2006-01-02-15-04-05.log
	Filename string `json:"filename" toml:"filename"`

	// RotationInterval is how often to rotate logs.
	// Default is 5 minutes for ELK integration.
	RotationInterval time.Duration `json:"rotation_interval" toml:"rotation_interval"`

	// MaxBackups is the maximum number of old log files to retain.
	// Default is 12 (1 hour of 5-min logs).
	MaxBackups int `json:"max_backups" toml:"max_backups"`

	// Compress determines if rotated files should be compressed.
	// Default is false (for ELK to read immediately).
	Compress bool `json:"compress" toml:"compress"`

	// LocalTime determines if local time is used for filenames.
	LocalTime bool `json:"local_time" toml:"local_time"`
}

// DefaultTimeBasedRotationConfig returns config optimized for ELK.
func DefaultTimeBasedRotationConfig() TimeBasedRotationConfig {
	return TimeBasedRotationConfig{
		RotationInterval: 5 * time.Minute, // 5 minutes for ELK
		MaxBackups:       12,              // Keep 1 hour of logs
		Compress:         false,           // ELK reads raw files
		LocalTime:        true,
	}
}

// TimeBasedRotatingWriter rotates logs based on time intervals.
// This is ideal for ELK integration where logs are pushed every N minutes.
type TimeBasedRotatingWriter struct {
	config     TimeBasedRotationConfig
	mu         sync.Mutex
	file       *os.File
	filename   string
	lastRotate time.Time
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
}

// NewTimeBasedRotatingWriter creates a time-based rotating writer.
func NewTimeBasedRotatingWriter(config TimeBasedRotationConfig) (*TimeBasedRotatingWriter, error) {
	if config.Filename == "" {
		return nil, fmt.Errorf("filename is required")
	}
	if config.RotationInterval <= 0 {
		config.RotationInterval = 5 * time.Minute
	}
	if config.MaxBackups <= 0 {
		config.MaxBackups = 12
	}

	// Ensure directory exists
	dir := filepath.Dir(config.Filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &TimeBasedRotatingWriter{
		config:     config,
		lastRotate: time.Now(),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Open initial file
	if err := w.rotate(); err != nil {
		cancel()
		return nil, err
	}

	// Start rotation timer
	go w.rotationLoop()

	return w, nil
}

// Write writes data to the current log file.
func (w *TimeBasedRotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, errors.New("writer is closed")
	}

	return w.file.Write(p)
}

// Rotate forces an immediate rotation.
func (w *TimeBasedRotatingWriter) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rotate()
}

func (w *TimeBasedRotatingWriter) rotate() error {
	// Close old file
	if w.file != nil {
		w.file.Close()
	}

	// Generate timestamped filename
	now := time.Now()
	if w.config.LocalTime {
		now = now.Local()
	} else {
		now = now.UTC()
	}

	// Format: logs/firewall.2026-01-24-12-30.log
	ext := filepath.Ext(w.config.Filename)
	base := w.config.Filename[:len(w.config.Filename)-len(ext)]
	w.filename = fmt.Sprintf("%s.%s%s", base, now.Format("2006-01-02-15-04"), ext)

	// Open new file
	f, err := os.OpenFile(w.filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", w.filename, err)
	}

	w.file = f
	w.lastRotate = now

	// Cleanup old files in background
	go w.cleanup()

	return nil
}

func (w *TimeBasedRotatingWriter) rotationLoop() {
	ticker := time.NewTicker(w.config.RotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			if !w.closed {
				w.rotate()
			}
			w.mu.Unlock()
		}
	}
}

func (w *TimeBasedRotatingWriter) cleanup() {
	dir := filepath.Dir(w.config.Filename)
	ext := filepath.Ext(w.config.Filename)
	base := filepath.Base(w.config.Filename[:len(w.config.Filename)-len(ext)])

	// Find all log files matching pattern
	pattern := filepath.Join(dir, base+".*"+ext)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Keep only MaxBackups files (newest)
	if len(matches) <= w.config.MaxBackups {
		return
	}

	// Sort by name (timestamp in name = chronological order)
	// Delete oldest files
	for i := 0; i < len(matches)-w.config.MaxBackups; i++ {
		os.Remove(matches[i])
	}
}

// Close closes the writer.
func (w *TimeBasedRotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true
	w.cancel()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// GetCurrentFilename returns the current log file being written to.
func (w *TimeBasedRotatingWriter) GetCurrentFilename() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.filename
}

// GetLastRotationTime returns when the last rotation occurred.
func (w *TimeBasedRotatingWriter) GetLastRotationTime() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastRotate
}

// NewTimeBasedLoggerForELK creates a logger optimized for ELK integration.
// Logs rotate every 5 minutes for easy shipping to ELK.
func NewTimeBasedLoggerForELK(basePath string, level LogLevel) (Logger, *TimeBasedRotatingWriter, error) {
	// Time-based rotation config for ELK
	rotConfig := TimeBasedRotationConfig{
		Filename:         basePath,
		RotationInterval: 5 * time.Minute,
		MaxBackups:       12, // Keep 1 hour of logs
		Compress:         false,
		LocalTime:        true,
	}

	rotWriter, err := NewTimeBasedRotatingWriter(rotConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create time-based writer: %w", err)
	}

	// Logger config
	logConfig := LogConfig{
		Level:           level,
		Format:          FormatJSON, // JSON for ELK
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}

	logger, err := NewWithOutput(logConfig, rotWriter)
	if err != nil {
		rotWriter.Close()
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return logger, rotWriter, nil
}

// ============================================================================
// Truncating Writer (Single file, cleared every N minutes - for ELK real-time)
// ============================================================================

// TruncatingWriterConfig configures the truncating writer.
type TruncatingWriterConfig struct {
	// Filename is the log file path.
	Filename string `json:"filename" toml:"filename"`

	// TruncateInterval is how often to clear the file.
	// Default is 5 minutes for ELK real-time integration.
	TruncateInterval time.Duration `json:"truncate_interval" toml:"truncate_interval"`
}

// DefaultTruncatingWriterConfig returns config optimized for ELK real-time.
func DefaultTruncatingWriterConfig() TruncatingWriterConfig {
	return TruncatingWriterConfig{
		TruncateInterval: 5 * time.Minute,
	}
}

// TruncatingWriter writes to a single file and clears it every N minutes.
// ELK reads logs in real-time, so we just clear and rewrite to same file.
type TruncatingWriter struct {
	config       TruncatingWriterConfig
	mu           sync.Mutex
	file         *os.File
	lastTruncate time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	closed       bool
}

// NewTruncatingWriter creates a writer that truncates the file every N minutes.
func NewTruncatingWriter(config TruncatingWriterConfig) (*TruncatingWriter, error) {
	if config.Filename == "" {
		return nil, fmt.Errorf("filename is required")
	}
	if config.TruncateInterval <= 0 {
		config.TruncateInterval = 5 * time.Minute
	}

	// Ensure directory exists
	dir := filepath.Dir(config.Filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	// Open file (create or truncate)
	f, err := os.OpenFile(config.Filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &TruncatingWriter{
		config:       config,
		file:         f,
		lastTruncate: time.Now(),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start truncation timer
	go w.truncationLoop()

	return w, nil
}

// Write writes data to the log file.
func (w *TruncatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, errors.New("writer is closed")
	}

	return w.file.Write(p)
}

// Truncate clears the file immediately.
func (w *TruncatingWriter) Truncate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncate()
}

func (w *TruncatingWriter) truncate() error {
	// Truncate the file (clear contents, keep same file)
	if err := w.file.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}

	// Seek to beginning
	if _, err := w.file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to beginning: %w", err)
	}

	w.lastTruncate = time.Now()
	return nil
}

func (w *TruncatingWriter) truncationLoop() {
	ticker := time.NewTicker(w.config.TruncateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			if !w.closed {
				w.truncate()
			}
			w.mu.Unlock()
		}
	}
}

// Close closes the writer.
func (w *TruncatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true
	w.cancel()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Sync flushes buffered data to disk.
func (w *TruncatingWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Sync()
	}
	return nil
}

// GetLastTruncateTime returns when the file was last cleared.
func (w *TruncatingWriter) GetLastTruncateTime() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastTruncate
}

// NewTruncatingLoggerForELK creates a logger that writes to a single file
// and clears it every 5 minutes. ELK reads the file in real-time.
func NewTruncatingLoggerForELK(logPath string, level LogLevel) (Logger, *TruncatingWriter, error) {
	config := TruncatingWriterConfig{
		Filename:         logPath,
		TruncateInterval: 5 * time.Minute,
	}

	truncWriter, err := NewTruncatingWriter(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create truncating writer: %w", err)
	}

	// Logger config - JSON for ELK
	logConfig := LogConfig{
		Level:           level,
		Format:          FormatJSON,
		EnableTimestamp: true,
		TimestampFormat: "rfc3339",
	}

	logger, err := NewWithOutput(logConfig, truncWriter)
	if err != nil {
		truncWriter.Close()
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return logger, truncWriter, nil
}
