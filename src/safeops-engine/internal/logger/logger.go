package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"safeops-engine/internal/config"
)

// Logger handles structured JSON logging with rotation support
type Logger struct {
	level            string
	format           string
	file             *os.File
	filePath         string
	rotationInterval time.Duration
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
}

// LogEntry represents a JSON log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// New creates a new logger
func New(cfg config.LoggingConfig) *Logger {
	ctx, cancel := context.WithCancel(context.Background())
	l := &Logger{
		level:            cfg.Level,
		format:           cfg.Format,
		filePath:         cfg.File,
		rotationInterval: 5 * time.Minute, // Default: 5 minute rotation
		ctx:              ctx,
		cancel:           cancel,
	}

	// Open log file if specified
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
		} else {
			l.file = f
		}
	}

	return l
}

// StartRotation starts the background log rotation goroutine
// The log file will be cleared every rotationInterval (default: 5 minutes)
func (l *Logger) StartRotation() {
	go l.rotationLoop()
}

// rotationLoop runs in the background and clears the log file periodically
func (l *Logger) rotationLoop() {
	ticker := time.NewTicker(l.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.rotateLog()
		}
	}
}

// rotateLog clears the log file and starts fresh
func (l *Logger) rotateLog() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil || l.filePath == "" {
		return
	}

	// Close current file
	l.file.Close()

	// Reopen with truncate flag to clear it
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Failed to rotate log file: %v\n", err)
		return
	}

	l.file = f

	// Log rotation event
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "INFO",
		Message:   "Log file rotated",
		Data:      map[string]interface{}{"rotation_interval": l.rotationInterval.String()},
	}
	jsonData, _ := json.Marshal(entry)
	l.file.WriteString(string(jsonData) + "\n")
	l.file.Sync()

	fmt.Printf("[%s] Log file rotated (cleared)\n", time.Now().Format("15:04:05"))
}

// log writes a log entry
func (l *Logger) log(level, message string, data map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   message,
		Data:      data,
	}

	var output string
	if l.format == "json" {
		jsonData, _ := json.Marshal(entry)
		output = string(jsonData)
	} else {
		// Simple text format
		output = fmt.Sprintf("[%s] %s: %s", entry.Timestamp, level, message)
		if data != nil {
			jsonData, _ := json.Marshal(data)
			output += fmt.Sprintf(" %s", string(jsonData))
		}
	}

	// Write to stdout
	fmt.Println(output)

	// Write to file (thread-safe)
	l.mu.Lock()
	if l.file != nil {
		l.file.WriteString(output + "\n")
		l.file.Sync()
	}
	l.mu.Unlock()
}

// Info logs an info message
func (l *Logger) Info(message string, data map[string]interface{}) {
	l.log("INFO", message, data)
}

// Error logs an error message
func (l *Logger) Error(message string, data map[string]interface{}) {
	l.log("ERROR", message, data)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, data map[string]interface{}) {
	l.log("WARN", message, data)
}

// Debug logs a debug message
func (l *Logger) Debug(message string, data map[string]interface{}) {
	if l.level == "debug" || l.level == "DEBUG" {
		l.log("DEBUG", message, data)
	}
}

// Close closes the log file and stops rotation
func (l *Logger) Close() error {
	// Stop rotation goroutine
	if l.cancel != nil {
		l.cancel()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
