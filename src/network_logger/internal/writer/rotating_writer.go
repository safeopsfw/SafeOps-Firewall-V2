package writer

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RotatingWriter writes JSONL with size-based rotation and gzip compression of old files.
// Used by IDS, NetFlow, and IP Summary collectors.
type RotatingWriter struct {
	basePath    string
	maxBytes    int64 // rotate when file exceeds this size
	maxFiles    int   // keep this many rotated files
	batchQueue  chan []byte
	mu          sync.Mutex
	file        *os.File
	writer      *bufio.Writer
	currentSize int64
	linesWritten int64
}

// NewRotatingWriter creates a rotating JSONL writer.
// maxBytes: rotate at this size (e.g. 50*1024*1024 for 50MB)
// maxFiles: keep N rotated files (older ones deleted)
func NewRotatingWriter(basePath string, maxBytes int64, maxFiles int) *RotatingWriter {
	if maxBytes <= 0 {
		maxBytes = 50 * 1024 * 1024 // 50MB default
	}
	if maxFiles <= 0 {
		maxFiles = 3
	}
	return &RotatingWriter{
		basePath:   basePath,
		maxBytes:   maxBytes,
		maxFiles:   maxFiles,
		batchQueue: make(chan []byte, 10000),
	}
}

// Start opens the file and begins the background writer.
func (w *RotatingWriter) Start(ctx context.Context) error {
	if err := w.openFile(); err != nil {
		return err
	}
	go w.writeLoop(ctx)
	return nil
}

// WriteJSON marshals v to JSON and queues it for writing.
func (w *RotatingWriter) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	select {
	case w.batchQueue <- data:
		return nil
	default:
		return fmt.Errorf("rotating writer queue full")
	}
}

// WriteBatch writes a slice of pre-marshaled JSON lines.
func (w *RotatingWriter) WriteBatch(batch [][]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer == nil {
		return
	}

	for _, data := range batch {
		n, _ := w.writer.Write(data)
		w.writer.WriteByte('\n')
		w.currentSize += int64(n + 1)
		w.linesWritten++
	}
	w.writer.Flush()

	// Check if rotation needed
	if w.currentSize >= w.maxBytes {
		w.rotateUnsafe()
	}
}

func (w *RotatingWriter) writeLoop(ctx context.Context) {
	batch := make([][]byte, 0, 64)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				w.WriteBatch(batch)
			}
			w.close()
			return
		case data := <-w.batchQueue:
			batch = append(batch, data)
			if len(batch) >= 64 {
				w.WriteBatch(batch)
				batch = make([][]byte, 0, 64)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.WriteBatch(batch)
				batch = make([][]byte, 0, 64)
			}
		}
	}
}

func (w *RotatingWriter) openFile() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	dir := filepath.Dir(w.basePath)
	os.MkdirAll(dir, 0755)

	file, err := os.OpenFile(w.basePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	stat, _ := file.Stat()
	w.file = file
	w.writer = bufio.NewWriterSize(file, 64*1024)
	w.currentSize = stat.Size()
	return nil
}

// rotateUnsafe rotates the current file. Caller must hold w.mu.
func (w *RotatingWriter) rotateUnsafe() {
	if w.writer != nil {
		w.writer.Flush()
	}
	if w.file != nil {
		w.file.Close()
	}

	// Rename current to .1, shift old files
	w.shiftFiles()

	// Compress the just-rotated file in background
	rotatedPath := w.basePath + ".1"
	go w.compressFile(rotatedPath)

	// Open fresh file
	file, err := os.OpenFile(w.basePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	w.file = file
	w.writer = bufio.NewWriterSize(file, 64*1024)
	w.currentSize = 0
	w.linesWritten = 0
}

func (w *RotatingWriter) shiftFiles() {
	// Delete the oldest file
	oldest := fmt.Sprintf("%s.%d.gz", w.basePath, w.maxFiles)
	os.Remove(oldest)

	// Shift .N-1.gz -> .N.gz
	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d.gz", w.basePath, i)
		dst := fmt.Sprintf("%s.%d.gz", w.basePath, i+1)
		os.Rename(src, dst)
	}

	// Move current file to .1
	os.Rename(w.basePath, w.basePath+".1")
}

func (w *RotatingWriter) compressFile(path string) {
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	gzPath := path + ".gz"
	// If .gz already exists from shift, remove the uncompressed .1
	if _, err := os.Stat(gzPath); err == nil {
		os.Remove(path)
		return
	}

	dst, err := os.Create(gzPath)
	if err != nil {
		return
	}

	gz := gzip.NewWriter(dst)
	io.Copy(gz, src)
	gz.Close()
	dst.Close()
	src.Close()
	os.Remove(path) // Remove uncompressed

	// Clean up: remove files beyond maxFiles
	w.cleanupOldFiles()
}

func (w *RotatingWriter) cleanupOldFiles() {
	dir := filepath.Dir(w.basePath)
	base := filepath.Base(w.basePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var gzFiles []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, base+".") && strings.HasSuffix(name, ".gz") {
			gzFiles = append(gzFiles, filepath.Join(dir, name))
		}
	}

	if len(gzFiles) <= w.maxFiles {
		return
	}

	// Sort by modification time (oldest first)
	sort.Slice(gzFiles, func(i, j int) bool {
		si, _ := os.Stat(gzFiles[i])
		sj, _ := os.Stat(gzFiles[j])
		if si == nil || sj == nil {
			return false
		}
		return si.ModTime().Before(sj.ModTime())
	})

	// Remove excess
	for i := 0; i < len(gzFiles)-w.maxFiles; i++ {
		os.Remove(gzFiles[i])
	}
}

func (w *RotatingWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer != nil {
		w.writer.Flush()
		w.writer = nil
	}
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
}

// GetStats returns writer stats.
func (w *RotatingWriter) GetStats() map[string]interface{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return map[string]interface{}{
		"lines_written": w.linesWritten,
		"current_size":  w.currentSize,
		"queue_size":    len(w.batchQueue),
	}
}
