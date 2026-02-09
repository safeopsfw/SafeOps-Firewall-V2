package alerting

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer handles alert log file output with daily rotation and buffered writes
type Writer struct {
	mu       sync.Mutex
	dir      string
	maxSize  int64 // max bytes per file before mid-day rotation
	writer   *bufio.Writer
	file     *os.File
	curDate  string
	curSize  int64
	rotIndex int // index for mid-day rotations (e.g., -2, -3)
}

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

	if err := w.rotate(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write writes a formatted alert line to the log file
func (w *Writer) Write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if today != w.curDate {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	// Check size-based rotation
	if w.maxSize > 0 && w.curSize+int64(len(data)+1) > w.maxSize {
		w.rotIndex++
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

func (w *Writer) rotate() error {
	if err := w.closeFile(); err != nil {
		return err
	}

	today := time.Now().Format("2006-01-02")
	if today != w.curDate {
		w.curDate = today
		w.rotIndex = 0
	}

	filename := fmt.Sprintf("firewall-alerts-%s.jsonl", w.curDate)
	if w.rotIndex > 0 {
		filename = fmt.Sprintf("firewall-alerts-%s-%d.jsonl", w.curDate, w.rotIndex)
	}

	path := filepath.Join(w.dir, filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open alert log %s: %w", path, err)
	}

	// Get current file size for size-based rotation tracking
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
