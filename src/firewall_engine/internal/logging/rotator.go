package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

// NewLogRotator creates a new io.WriteCloser that writes to the specified file
// and handles rotation based on the configuration.
func NewLogRotator(cfg LogConfig) (io.WriteCloser, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("log file path is empty")
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	// Create the lumberjack logger
	rotator := &lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSize,    // megabytes
		MaxBackups: cfg.MaxBackups, // number of files
		MaxAge:     cfg.MaxAge,     // days
		Compress:   cfg.Compress,   // gzip
		LocalTime:  true,           // Use local time for timestamps in filenames
	}

	// Verify we can actually write to the file/directory by doing a dry open?
	// Lumberjack opens on first write, so we might want to check permissions now.
	// But simply returning the rotator is standard.
	// We could return a MultiWriter if Console is enabled here, or handle that in the logger.
	// The Logger will handle MultiWriter. Here we just return the file rotator.

	return rotator, nil
}
