package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"safeops-engine/internal/config"
)

// Logger handles structured JSON logging
type Logger struct {
	level  string
	format string
	file   *os.File
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
	l := &Logger{
		level:  cfg.Level,
		format: cfg.Format,
	}

	// Open log file if specified
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
		} else {
			l.file = f
		}
	}

	return l
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

	// Write to file
	if l.file != nil {
		l.file.WriteString(output + "\n")
		l.file.Sync()
	}
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

// Close closes the log file
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
