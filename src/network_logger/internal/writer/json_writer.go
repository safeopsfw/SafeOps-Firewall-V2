package writer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/safeops/network_logger/pkg/models"
)

// JSONWriter handles JSON master log file writing with 5-minute overwrite cycle
type JSONWriter struct {
	logPath       string
	batchQueue    chan *models.PacketLog
	mu            sync.Mutex
	batchSize     int
	cycleInterval time.Duration // 5 minutes
	packetsLogged int64
	bytesWritten  int64
	currentFile   *os.File
	writer        *bufio.Writer
}

// NewJSONWriter creates a new JSON writer
func NewJSONWriter(logPath string, batchSize int, cycleInterval time.Duration) *JSONWriter {
	return &JSONWriter{
		logPath:       logPath,
		batchQueue:    make(chan *models.PacketLog, 10000),
		batchSize:     batchSize,
		cycleInterval: cycleInterval,
	}
}

// Start begins the writer goroutines
func (w *JSONWriter) Start(ctx context.Context) {
	// Open initial file
	w.openFile()

	// Batch writer goroutine
	go w.batchWriter(ctx)

	// 5-minute cycle goroutine (overwrite file)
	go w.cycleLoop(ctx)
}

// openFile opens/creates the log file (truncates if exists)
func (w *JSONWriter) openFile() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close existing file if open
	if w.currentFile != nil {
		if w.writer != nil {
			w.writer.Flush()
		}
		w.currentFile.Close()
	}

	// Open file in truncate mode (clears existing content)
	file, err := os.OpenFile(w.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	w.currentFile = file
	w.writer = bufio.NewWriter(file)

	// Reset counters
	w.packetsLogged = 0
	w.bytesWritten = 0

	return nil
}

// Write queues a packet log for writing
func (w *JSONWriter) Write(log *models.PacketLog) error {
	select {
	case w.batchQueue <- log:
		return nil
	default:
		// Queue full, drop packet
		return fmt.Errorf("write queue full")
	}
}

// batchWriter writes packets in batches for performance
func (w *JSONWriter) batchWriter(ctx context.Context) {
	batch := make([]*models.PacketLog, 0, w.batchSize)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batch
			if len(batch) > 0 {
				w.writeBatch(batch)
			}
			w.closeFile()
			return

		case log := <-w.batchQueue:
			batch = append(batch, log)

			// Write when batch is full
			if len(batch) >= w.batchSize {
				w.writeBatch(batch)
				batch = make([]*models.PacketLog, 0, w.batchSize)
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				w.writeBatch(batch)
				batch = make([]*models.PacketLog, 0, w.batchSize)
			}
		}
	}
}

// writeBatch writes a batch of logs to file
func (w *JSONWriter) writeBatch(batch []*models.PacketLog) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer == nil {
		return
	}

	for _, log := range batch {
		jsonData, err := json.Marshal(log)
		if err != nil {
			continue
		}

		w.writer.Write(jsonData)
		w.writer.WriteByte('\n')

		w.packetsLogged++
		w.bytesWritten += int64(len(jsonData) + 1)
	}

	// Flush to disk
	w.writer.Flush()
}

// cycleLoop overwrites the file every 5 minutes
func (w *JSONWriter) cycleLoop(ctx context.Context) {
	ticker := time.NewTicker(w.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Overwrite file (truncate and restart)
			if err := w.openFile(); err == nil {
				// Log cycle event
				fmt.Printf("🔄 Master log cycled: %s (overwrote after %v)\n", w.logPath, w.cycleInterval)
			}
		}
	}
}

// closeFile closes the current file
func (w *JSONWriter) closeFile() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer != nil {
		w.writer.Flush()
		w.writer = nil
	}

	if w.currentFile != nil {
		w.currentFile.Close()
		w.currentFile = nil
	}
}

// GetStats returns writer statistics
func (w *JSONWriter) GetStats() WriterStats {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Get file size
	var fileSize int64
	if stat, err := os.Stat(w.logPath); err == nil {
		fileSize = stat.Size()
	}

	return WriterStats{
		PacketsLogged: w.packetsLogged,
		BytesWritten:  w.bytesWritten,
		FileSize:      fileSize,
		QueueSize:     len(w.batchQueue),
	}
}

// WriterStats represents writer statistics
type WriterStats struct {
	PacketsLogged int64
	BytesWritten  int64
	FileSize      int64
	QueueSize     int
}
