package tailer

import (
	"bufio"
	"io"
	"log"
	"os"
	"syscall"
	"time"
)

// LogEntry represents a parsed log line with metadata
type LogEntry struct {
	Line        string
	FilePath    string
	IndexPrefix string
	LogType     string
	Timestamp   time.Time
}

// Tailer monitors a log file for new lines
type Tailer struct {
	path         string
	indexPrefix  string
	logType      string
	pollInterval time.Duration
	maxLineSize  int

	file       *os.File
	reader     *bufio.Reader
	lastOffset int64
	lastInode  uint64

	positionDB *PositionDB
	output     chan<- LogEntry
	stop       chan struct{}
}

// TailerConfig holds tailer configuration
type TailerConfig struct {
	Path         string
	IndexPrefix  string
	LogType      string
	PollInterval time.Duration
	MaxLineSize  int
	PositionDB   *PositionDB
	Output       chan<- LogEntry
}

// NewTailer creates a new file tailer
func NewTailer(cfg TailerConfig) *Tailer {
	return &Tailer{
		path:         cfg.Path,
		indexPrefix:  cfg.IndexPrefix,
		logType:      cfg.LogType,
		pollInterval: cfg.PollInterval,
		maxLineSize:  cfg.MaxLineSize,
		positionDB:   cfg.PositionDB,
		output:       cfg.Output,
		stop:         make(chan struct{}),
	}
}

// Start begins tailing the file
func (t *Tailer) Start() error {
	// Load saved position
	if pos, ok := t.positionDB.Get(t.path); ok {
		t.lastOffset = pos.Offset
		t.lastInode = pos.Inode
	}

	go t.tailLoop()
	return nil
}

// Stop stops the tailer
func (t *Tailer) Stop() {
	close(t.stop)
	if t.file != nil {
		t.file.Close()
	}
}

// tailLoop is the main tailing loop
func (t *Tailer) tailLoop() {
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			if err := t.readNewLines(); err != nil {
				log.Printf("[%s] Error reading file: %v", t.path, err)
			}
		}
	}
}

// readNewLines reads any new lines from the file
func (t *Tailer) readNewLines() error {
	// Check if file exists
	info, err := os.Stat(t.path)
	if os.IsNotExist(err) {
		// File doesn't exist yet, wait for it
		return nil
	}
	if err != nil {
		return err
	}

	// Get current inode
	currentInode := getInode(info)

	// Check for rotation scenarios
	needReopen := false
	if t.file == nil {
		needReopen = true
	} else if currentInode != t.lastInode && t.lastInode != 0 {
		// File was replaced (inode changed)
		log.Printf("[%s] File replaced, reopening from beginning", t.path)
		t.file.Close()
		t.file = nil
		t.lastOffset = 0
		needReopen = true
	} else if info.Size() < t.lastOffset {
		// File was truncated
		log.Printf("[%s] File truncated, resetting position", t.path)
		t.lastOffset = 0
		if t.file != nil {
			t.file.Seek(0, io.SeekStart)
			t.reader = bufio.NewReaderSize(t.file, t.maxLineSize)
		}
	}

	// Open file if needed
	if needReopen {
		f, err := os.Open(t.path)
		if err != nil {
			return err
		}
		t.file = f
		t.lastInode = currentInode

		// Seek to last known position
		if t.lastOffset > 0 {
			if _, err := t.file.Seek(t.lastOffset, io.SeekStart); err != nil {
				// If seek fails, start from beginning
				t.lastOffset = 0
				t.file.Seek(0, io.SeekStart)
			}
		}
		t.reader = bufio.NewReaderSize(t.file, t.maxLineSize)
	}

	// Read new lines
	for {
		line, err := t.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No more data, update position and exit
				if len(line) == 0 {
					break
				}
				// Partial line at EOF, don't process yet
				// Seek back so we can re-read it next time
				t.file.Seek(t.lastOffset, io.SeekStart)
				t.reader = bufio.NewReaderSize(t.file, t.maxLineSize)
				break
			}
			return err
		}

		// Remove trailing newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// Skip empty lines
		if len(line) == 0 {
			// Update offset for the empty line we just read
			pos, _ := t.file.Seek(0, io.SeekCurrent)
			t.lastOffset = pos - int64(t.reader.Buffered())
			continue
		}

		// Get current file position
		pos, _ := t.file.Seek(0, io.SeekCurrent)
		t.lastOffset = pos - int64(t.reader.Buffered())

		// Send to output channel
		entry := LogEntry{
			Line:        line,
			FilePath:    t.path,
			IndexPrefix: t.indexPrefix,
			LogType:     t.logType,
			Timestamp:   time.Now(),
		}

		select {
		case t.output <- entry:
		case <-t.stop:
			return nil
		}

		// Update position in DB
		t.positionDB.Set(t.path, t.lastOffset, t.lastInode)
	}

	return nil
}

// getInode extracts the inode from file info (Windows uses FileIndex)
func getInode(info os.FileInfo) uint64 {
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Win32FileAttributeData); ok {
			// On Windows, use file size and mod time as pseudo-inode
			_ = stat
			return uint64(info.ModTime().UnixNano())
		}
	}
	// Fallback: use modification time as pseudo-inode
	return uint64(info.ModTime().UnixNano())
}
