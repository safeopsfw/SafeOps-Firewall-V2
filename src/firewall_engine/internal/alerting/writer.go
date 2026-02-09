package alerting

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer handles alert log file output with size-based rotation and gzip compression.
// All alerts write to a single file: firewall-alerts.jsonl
// When the file exceeds maxSize, it is compressed to firewall-alerts-<timestamp>.jsonl.gz
// and a new firewall-alerts.jsonl is created.
type Writer struct {
	mu      sync.Mutex
	dir     string
	maxSize int64 // max bytes per file before rotation
	writer  *bufio.Writer
	file    *os.File
	curSize int64
}

const activeFileName = "firewall-alerts.jsonl"

// NewWriter creates an alert file writer
// dir: directory for alert log files
// maxSizeMB: max file size in MB before rotation (0 = no size limit)
func NewWriter(dir string, maxSizeMB int) (*Writer, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create alert log dir %s: %w", dir, err)
	}

	w := &Writer{
		dir:     dir,
		maxSize: int64(maxSizeMB) * 1024 * 1024,
	}

	if err := w.openActive(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write writes a formatted alert line to the log file
func (w *Writer) Write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check size-based rotation before writing
	if w.maxSize > 0 && w.curSize+int64(len(data)+1) > w.maxSize {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	n, err := w.writer.Write(data)
	if err != nil {
		return err
	}
	w.curSize += int64(n)

	// Add newline
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}
	w.curSize++

	return nil
}

// Flush forces a buffer flush to disk
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writer != nil {
		return w.writer.Flush()
	}
	return nil
}

// Close flushes and closes the writer
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeFile()
}

// openActive opens (or creates) the active alert file for appending
func (w *Writer) openActive() error {
	path := filepath.Join(w.dir, activeFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open alert log %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	w.file = f
	w.writer = bufio.NewWriterSize(f, 64*1024) // 64KB buffer
	w.curSize = info.Size()

	return nil
}

// rotate compresses the current file and opens a new one
func (w *Writer) rotate() error {
	// Flush and close current file
	if err := w.closeFile(); err != nil {
		return err
	}

	activePath := filepath.Join(w.dir, activeFileName)

	// Generate timestamp-based archive name
	ts := time.Now().Format("2006-01-02T150405")
	archiveName := fmt.Sprintf("firewall-alerts-%s.jsonl.gz", ts)
	archivePath := filepath.Join(w.dir, archiveName)

	// Compress the active file to .gz archive
	if err := compressFile(activePath, archivePath); err != nil {
		// If compression fails, rename instead of losing data
		fallback := filepath.Join(w.dir, fmt.Sprintf("firewall-alerts-%s.jsonl", ts))
		os.Rename(activePath, fallback)
	} else {
		// Compression succeeded — remove the uncompressed original
		os.Remove(activePath)
	}

	// Open a fresh active file
	return w.openActive()
}

func (w *Writer) closeFile() error {
	if w.writer != nil {
		if err := w.writer.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
		w.writer = nil
	}
	return nil
}

// compressFile gzip-compresses src into dst
func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	gz, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		return err
	}
	gz.Name = filepath.Base(src)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		return err
	}

	return gz.Close()
}
