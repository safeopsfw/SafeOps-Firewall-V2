// Package logging provides log level definitions and utilities.
package logging

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// Level represents a log level
type Level = logrus.Level

// Log levels
const (
	PanicLevel = logrus.PanicLevel
	FatalLevel = logrus.FatalLevel
	ErrorLevel = logrus.ErrorLevel
	WarnLevel  = logrus.WarnLevel
	InfoLevel  = logrus.InfoLevel
	DebugLevel = logrus.DebugLevel
	TraceLevel = logrus.TraceLevel
)

// ParseLevel parses a log level string
func ParseLevel(level string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "panic":
		return PanicLevel, nil
	case "fatal":
		return FatalLevel, nil
	case "error":
		return ErrorLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "info":
		return InfoLevel, nil
	case "debug":
		return DebugLevel, nil
	case "trace":
		return TraceLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

// MustParseLevel parses a log level or panics
func MustParseLevel(level string) Level {
	l, err := ParseLevel(level)
	if err != nil {
		panic(err)
	}
	return l
}

// LevelToString converts a level to string
func LevelToString(level Level) string {
	switch level {
	case PanicLevel:
		return "panic"
	case FatalLevel:
		return "fatal"
	case ErrorLevel:
		return "error"
	case WarnLevel:
		return "warn"
	case InfoLevel:
		return "info"
	case DebugLevel:
		return "debug"
	case TraceLevel:
		return "trace"
	default:
		return "unknown"
	}
}

// AllLevels returns all log levels
func AllLevels() []Level {
	return []Level{
		PanicLevel,
		FatalLevel,
		ErrorLevel,
		WarnLevel,
		InfoLevel,
		DebugLevel,
		TraceLevel,
	}
}

// LevelNames returns all level names
func LevelNames() []string {
	return []string{
		"panic",
		"fatal",
		"error",
		"warn",
		"info",
		"debug",
		"trace",
	}
}

// IsValidLevel checks if a level string is valid
func IsValidLevel(level string) bool {
	_, err := ParseLevel(level)
	return err == nil
}

// LevelFilter is a hook that filters entries by level
type LevelFilter struct {
	MinLevel Level
	MaxLevel Level
	Handler  func(*logrus.Entry) error
}

// Levels returns the levels this hook handles
func (f *LevelFilter) Levels() []Level {
	var levels []Level
	for _, l := range AllLevels() {
		if l >= f.MaxLevel && l <= f.MinLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

// Fire is called when a log entry is made
func (f *LevelFilter) Fire(entry *logrus.Entry) error {
	if f.Handler != nil {
		return f.Handler(entry)
	}
	return nil
}

// NewLevelFilter creates a level filter hook
func NewLevelFilter(minLevel, maxLevel Level, handler func(*logrus.Entry) error) *LevelFilter {
	return &LevelFilter{
		MinLevel: minLevel,
		MaxLevel: maxLevel,
		Handler:  handler,
	}
}

// ErrorOnlyHook routes error-level logs to a handler
type ErrorOnlyHook struct {
	Handler func(*logrus.Entry) error
}

// Levels returns the levels this hook handles
func (h *ErrorOnlyHook) Levels() []Level {
	return []Level{ErrorLevel, FatalLevel, PanicLevel}
}

// Fire is called when a log entry is made
func (h *ErrorOnlyHook) Fire(entry *logrus.Entry) error {
	if h.Handler != nil {
		return h.Handler(entry)
	}
	return nil
}
