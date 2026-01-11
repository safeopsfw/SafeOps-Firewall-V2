// Package logging provides log file rotation.
package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// ============================================================================
// Lumberjack-Based Rotation (Recommended)
// ============================================================================
// These functions use the industry-standard Lumberjack library for automatic
// log rotation. This is the recommended approach for most use cases.

// SetupRotation creates a Lumberjack logger configured for automatic rotation.
// Returns io.Writer that can be passed to logrus.SetOutput() or Logger.SetOutput().
//
// Parameters:
//   - filename: Path to the log file (e.g., "/var/log/safeops/dns-server.log")
//   - maxSizeMB: Max size in MB before rotation (e.g., 100)
//   - maxBackups: Number of old log files to keep (e.g., 5)
//   - maxAgeDays: Max age in days to retain old logs (e.g., 30)
//   - compress: Enable gzip compression of rotated logs (recommended: true)
//
// Rotation Behavior:
//   - Size-based: Rotates when file reaches maxSizeMB
//   - Age-based: Deletes logs older than maxAgeDays
//   - Backup limit: Keeps only maxBackups old files
//   - Compression: Rotated files saved as .log.gz (70-90% space savings)
//   - Thread-safe: Safe for concurrent writes
//   - Atomic: No log loss during rotation
//
// Example:
//
//	logger := logging.New()
//	logger.SetOutput(logging.SetupRotation(
//	    "/var/log/safeops/dns.log",
//	    100,  // 100 MB max size
//	    5,    // Keep 5 backups
//	    30,   // 30 days max age
//	    true, // Enable compression
//	))
func SetupRotation(filename string, maxSizeMB, maxBackups, maxAgeDays int, compress bool) io.Writer {
	return &lumberjack.Logger{
		Filename:   filename,   // Path to log file
		MaxSize:    maxSizeMB,  // MB before rotation
		MaxBackups: maxBackups, // Number of old logs to keep
		MaxAge:     maxAgeDays, // Days to retain old logs
		Compress:   compress,   // Gzip rotated logs
	}
}

// SetupRotationWithConfig creates a Lumberjack logger from RotatingConfig.
// This is a convenience wrapper around SetupRotation() for use with config structs.
//
// Example:
//
//	cfg := logging.RotatingConfig{
//	    Filename:   "/var/log/safeops/dns.log",
//	    MaxSizeMB:  100,
//	    MaxBackups: 5,
//	    MaxAgeDays: 30,
//	    Compress:   true,
//	}
//	logger.SetOutput(logging.SetupRotationWithConfig(cfg))
func SetupRotationWithConfig(cfg RotatingConfig) io.Writer {
	return SetupRotation(cfg.Filename, cfg.MaxSizeMB, cfg.MaxBackups, cfg.MaxAgeDays, cfg.Compress)
}

// ============================================================================
// Custom Rotation Implementation (Advanced Use Cases)
// ============================================================================
// The following custom implementation provides advanced features like MultiWriter
// and AsyncWriter. Use these when you need functionality beyond basic rotation.

// RotatingWriter is a file writer with rotation support
type RotatingWriter struct {
	filename   string
	maxSize    int64 // in bytes
	maxBackups int
	maxAge     int // in days
	compress   bool

	mu   sync.Mutex
	file *os.File
	size int64
}

// RotatingConfig configures the rotating writer
type RotatingConfig struct {
	// Filename is the file to write logs to
	Filename string

	// MaxSizeMB is the maximum size in MB before rotation
	MaxSizeMB int

	// MaxBackups is the maximum number of old files to keep
	MaxBackups int

	// MaxAgeDays is the maximum age in days to keep old files
	MaxAgeDays int

	// Compress determines if old files should be compressed
	Compress bool
}

// NewRotatingWriter creates a new rotating writer
func NewRotatingWriter(cfg RotatingConfig) (*RotatingWriter, error) {
	w := &RotatingWriter{
		filename:   cfg.Filename,
		maxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
		maxBackups: cfg.MaxBackups,
		maxAge:     cfg.MaxAgeDays,
		compress:   cfg.Compress,
	}

	// Create directory if needed
	dir := filepath.Dir(cfg.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open or create the file
	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write writes data to the log file
func (w *RotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if we need to rotate
	if w.maxSize > 0 && w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close closes the writer
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Rotate forces a log rotation
func (w *RotatingWriter) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rotate()
}

// openFile opens or creates the log file
func (w *RotatingWriter) openFile() error {
	info, err := os.Stat(w.filename)
	if os.IsNotExist(err) {
		w.size = 0
	} else if err != nil {
		return err
	} else {
		w.size = info.Size()
	}

	file, err := os.OpenFile(w.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	w.file = file
	return nil
}

// rotate performs the log rotation
func (w *RotatingWriter) rotate() error {
	// Close current file
	if w.file != nil {
		w.file.Close()
	}

	// Rename current file with timestamp
	timestamp := time.Now().UTC().Format("20060102-150405")
	backupName := fmt.Sprintf("%s.%s", w.filename, timestamp)

	if err := os.Rename(w.filename, backupName); err != nil {
		return err
	}

	// Compress if enabled
	if w.compress {
		go w.compressFile(backupName)
	}

	// Cleanup old files
	go w.cleanup()

	// Open new file
	return w.openFile()
}

// compressFile compresses a log file
func (w *RotatingWriter) compressFile(filename string) {
	// Open source file
	src, err := os.Open(filename)
	if err != nil {
		return
	}
	defer src.Close()

	// Create gzip file
	dst, err := os.Create(filename + ".gz")
	if err != nil {
		return
	}
	defer dst.Close()

	// Compress
	gz := gzip.NewWriter(dst)
	defer gz.Close()

	if _, err := io.Copy(gz, src); err != nil {
		return
	}

	// Remove original
	os.Remove(filename)
}

// cleanup removes old log files
func (w *RotatingWriter) cleanup() {
	// Find backup files
	dir := filepath.Dir(w.filename)
	base := filepath.Base(w.filename)

	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []backupFile

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasPrefix(name, base+".") && name != base {
			info, err := f.Info()
			if err != nil {
				continue
			}

			backups = append(backups, backupFile{
				name:    name,
				path:    filepath.Join(dir, name),
				modTime: info.ModTime(),
			})
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	// Remove old backups by count
	if w.maxBackups > 0 && len(backups) > w.maxBackups {
		for _, b := range backups[w.maxBackups:] {
			os.Remove(b.path)
		}
		backups = backups[:w.maxBackups]
	}

	// Remove old backups by age
	if w.maxAge > 0 {
		cutoff := time.Now().AddDate(0, 0, -w.maxAge)
		for _, b := range backups {
			if b.modTime.Before(cutoff) {
				os.Remove(b.path)
			}
		}
	}
}

type backupFile struct {
	name    string
	path    string
	modTime time.Time
}

// MultiWriter writes to multiple writers
type MultiWriter struct {
	writers []io.Writer
}

// NewMultiWriter creates a writer that writes to multiple destinations
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
	}
}

// Write writes to all writers
func (m *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range m.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
	}
	return len(p), nil
}

// Add adds a writer
func (m *MultiWriter) Add(w io.Writer) {
	m.writers = append(m.writers, w)
}

// AsyncWriter writes asynchronously to avoid blocking
type AsyncWriter struct {
	writer  io.Writer
	ch      chan []byte
	done    chan struct{}
	running bool
	mu      sync.Mutex
}

// NewAsyncWriter creates an async writer
func NewAsyncWriter(writer io.Writer, bufferSize int) *AsyncWriter {
	w := &AsyncWriter{
		writer: writer,
		ch:     make(chan []byte, bufferSize),
		done:   make(chan struct{}),
	}

	go w.run()

	return w
}

// Write queues data for async writing
func (w *AsyncWriter) Write(p []byte) (n int, err error) {
	// Make a copy of the data
	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case w.ch <- buf:
		return len(p), nil
	default:
		// Buffer full, drop the message
		return len(p), nil
	}
}

// run processes the write queue
func (w *AsyncWriter) run() {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	for {
		select {
		case data := <-w.ch:
			w.writer.Write(data)
		case <-w.done:
			// Drain remaining messages
			for {
				select {
				case data := <-w.ch:
					w.writer.Write(data)
				default:
					return
				}
			}
		}
	}
}

// Close closes the async writer
func (w *AsyncWriter) Close() error {
	close(w.done)

	if closer, ok := w.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
