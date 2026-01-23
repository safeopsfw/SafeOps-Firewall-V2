package logging

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// LogLevel represents the severity of the log message.
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// LogFormat represents the format of the log output.
type LogFormat string

const (
	FormatJSON LogFormat = "json"
	FormatText LogFormat = "text"
)

// LogConfig holds the configuration for the logging system.
type LogConfig struct {
	// Enabled determines if logging is active.
	Enabled bool `mapstructure:"enabled" yaml:"enabled" toml:"enabled"`

	// Level is the minimum log level to capture (debug, info, warn, error).
	Level LogLevel `mapstructure:"level" yaml:"level" toml:"level"`

	// Format specifies the output format (json, text).
	Format LogFormat `mapstructure:"format" yaml:"format" toml:"format"`

	// FilePath is the location of the log file.
	FilePath string `mapstructure:"file_path" yaml:"file_path" toml:"file_path"`

	// MaxSize is the maximum size in megabytes of the log file before it gets rotated.
	MaxSize int `mapstructure:"max_size" yaml:"max_size" toml:"max_size"`

	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `mapstructure:"max_backups" yaml:"max_backups" toml:"max_backups"`

	// MaxAge is the maximum number of days to retain old log files.
	MaxAge int `mapstructure:"max_age" yaml:"max_age" toml:"max_age"`

	// Compress determines if the rotated log files should be compressed using gzip.
	Compress bool `mapstructure:"compress" yaml:"compress" toml:"compress"`

	// Console specifies if logs should also be written to stdout.
	Console bool `mapstructure:"console" yaml:"console" toml:"console"`
}

// DefaultConfig returns a safe default configuration.
func DefaultConfig() LogConfig {
	return LogConfig{
		Enabled:    true,
		Level:      LevelInfo,
		Format:     FormatJSON,
		FilePath:   "logs/firewall.log",
		MaxSize:    100, // 100 MB
		MaxBackups: 5,
		MaxAge:     30, // 30 days
		Compress:   true,
		Console:    true,
	}
}

// Validate checks the configuration for errors.
func (c *LogConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Validate Level
	switch strings.ToLower(string(c.Level)) {
	case string(LevelDebug), string(LevelInfo), string(LevelWarn), string(LevelError):
		// Valid
	default:
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, error)", c.Level)
	}

	// Validate Format
	switch strings.ToLower(string(c.Format)) {
	case string(FormatJSON), string(FormatText):
		// Valid
	default:
		return fmt.Errorf("invalid log format: %s (must be json, text)", c.Format)
	}

	// Validate FilePath
	if c.FilePath == "" {
		return errors.New("log file path cannot be empty")
	}
	if filepath.Ext(c.FilePath) == "" {
		return fmt.Errorf("log file path must have an extension: %s", c.FilePath)
	}

	// Validate Rotation Settings
	if c.MaxSize <= 0 {
		return fmt.Errorf("max_size must be greater than 0, got %d", c.MaxSize)
	}
	if c.MaxBackups < 0 {
		return fmt.Errorf("max_backups must be non-negative, got %d", c.MaxBackups)
	}
	if c.MaxAge < 0 {
		return fmt.Errorf("max_age must be non-negative, got %d", c.MaxAge)
	}

	return nil
}
