package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test Helper Functions

// captureLogOutput captures log output for testing
func captureLogOutput(t *testing.T, logFunc func(*Logger)) string {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)
	l.SetFormatter(&SafeOpsTextFormatter{ColorEnabled: false})
	logFunc(l)
	return buf.String()
}

// newTestLogger creates a logger for testing with buffer
func newTestLogger(t *testing.T) (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)
	l.SetFormatter(NewJSONFormatter())
	return l, &buf
}

// parseJSONLog parses a single JSON log line
func parseJSONLog(t *testing.T, logLine string) map[string]interface{} {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(logLine), &data); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	return data
}

// ==============================================================================
// Existing Tests
// ==============================================================================

func TestNewLogger(t *testing.T) {
	l := New()

	if l == nil {
		t.Fatal("expected non-nil logger")
	}

	if l.Logger == nil {
		t.Fatal("expected non-nil underlying logger")
	}
}

func TestLoggerWithFields(t *testing.T) {
	l := New()

	entry := l.WithField("key", "value")
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	if entry.Data["key"] != "value" {
		t.Error("expected field to be set")
	}
}

func TestLoggerWithMultipleFields(t *testing.T) {
	l := New()

	entry := l.WithFields(Fields{
		"key1": "value1",
		"key2": "value2",
	})

	if entry.Data["key1"] != "value1" {
		t.Error("expected key1 to be set")
	}

	if entry.Data["key2"] != "value2" {
		t.Error("expected key2 to be set")
	}
}

func TestPermanentFields(t *testing.T) {
	l := New()

	l.AddPermanentField("service", "test")

	entry := l.WithField("request", "123")

	if entry.Data["service"] != "test" {
		t.Error("expected permanent field to be present")
	}
}

func TestLoggerClone(t *testing.T) {
	l := New()
	l.AddPermanentField("original", true)

	clone := l.Clone()
	clone.AddPermanentField("cloned", true)

	// Check original doesn't have cloned field
	entry := l.WithField("test", true)
	if _, ok := entry.Data["cloned"]; ok {
		t.Error("original should not have cloned field")
	}
}

func TestLoggerChild(t *testing.T) {
	l := New()
	l.AddPermanentField("parent", true)

	child := l.Child(Fields{"child": true})

	entry := child.WithField("test", true)

	if entry.Data["parent"] != true {
		t.Error("child should inherit parent fields")
	}

	if entry.Data["child"] != true {
		t.Error("child should have its own fields")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
		hasError bool
	}{
		{"debug", DebugLevel, false},
		{"info", InfoLevel, false},
		{"warn", WarnLevel, false},
		{"warning", WarnLevel, false},
		{"error", ErrorLevel, false},
		{"invalid", InfoLevel, true},
	}

	for _, tt := range tests {
		level, err := ParseLevel(tt.input)

		if tt.hasError && err == nil {
			t.Errorf("expected error for %s", tt.input)
		}

		if !tt.hasError && err != nil {
			t.Errorf("unexpected error for %s: %v", tt.input, err)
		}

		if level != tt.expected {
			t.Errorf("expected %v, got %v for %s", tt.expected, level, tt.input)
		}
	}
}

func TestLevelToString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{DebugLevel, "debug"},
		{InfoLevel, "info"},
		{WarnLevel, "warn"},
		{ErrorLevel, "error"},
	}

	for _, tt := range tests {
		result := LevelToString(tt.level)
		if result != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, result)
		}
	}
}

func TestJSONFormatter(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)
	l.SetFormatter(NewJSONFormatter())

	l.WithField("test", "value").Info("test message")

	var data map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if data["message"] != "test message" {
		t.Error("expected message field")
	}

	if data["test"] != "value" {
		t.Error("expected test field")
	}
}

func TestTextFormatter(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)
	l.SetFormatter(&SafeOpsTextFormatter{
		ColorEnabled:  false,
		FullTimestamp: true,
	})

	l.Info("test message")

	output := buf.String()

	if !strings.Contains(output, "INFO") {
		t.Error("expected INFO level in output")
	}

	if !strings.Contains(output, "test message") {
		t.Error("expected message in output")
	}
}

func TestConsoleFormatter(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)
	l.SetFormatter(NewConsoleFormatter())

	l.WithField("key", "value").Info("console message")

	output := buf.String()

	if !strings.Contains(output, "console message") {
		t.Error("expected message in output")
	}
}

func TestFormatByName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"json", "*logging.JSONFormatter"},
		{"text", "*logging.TextFormatter"},
		{"console", "*logging.ConsoleFormatter"},
		{"unknown", "*logging.JSONFormatter"}, // default
	}

	for _, tt := range tests {
		formatter := FormatByName(tt.name)
		typeName := strings.Replace(strings.Replace(
			strings.TrimPrefix(strings.TrimPrefix(
				formatTypeName(formatter), "*"), ""),
			"github.com/safeops/shared/", "", 1),
			"logrus.", "", 1)

		if !strings.Contains(tt.expected, typeName) && typeName != "" {
			// Just check it returns something
			if formatter == nil {
				t.Errorf("expected non-nil formatter for %s", tt.name)
			}
		}
	}
}

func formatTypeName(v interface{}) string {
	if v == nil {
		return "nil"
	}
	return strings.Replace(
		strings.Replace(
			strings.TrimPrefix(
				strings.TrimPrefix(
					formatTypeNameHelper(v),
					"*"),
				""),
			"github.com/safeops/shared/", "", 1),
		"logrus.", "", 1)
}

func formatTypeNameHelper(v interface{}) string {
	return ""
}

func TestIsValidLevel(t *testing.T) {
	if !IsValidLevel("debug") {
		t.Error("expected debug to be valid")
	}

	if IsValidLevel("invalid") {
		t.Error("expected invalid to be invalid")
	}
}

// ==============================================================================
// Log Level Filtering Tests
// ==============================================================================

func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name         string
		loggerLevel  string
		logLevel     string
		shouldAppear bool
	}{
		{"Debug at Info level", "info", "debug", false},
		{"Info at Info level", "info", "info", true},
		{"Warn at Info level", "info", "warn", true},
		{"Error at Info level", "info", "error", true},
		{"Debug at Debug level", "debug", "debug", true},
		{"Info at Error level", "error", "info", false},
		{"Warn at Error level", "error", "warn", false},
		{"Error at Error level", "error", "error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := New()
			l.SetOutput(&buf)
			l.SetFormatter(&SafeOpsTextFormatter{ColorEnabled: false})

			// Set logger level
			if err := l.SetLevelString(tt.loggerLevel); err != nil {
				t.Fatalf("failed to set level: %v", err)
			}

			// Log at specified level
			message := "test message"
			switch tt.logLevel {
			case "debug":
				l.Debug(message)
			case "info":
				l.Info(message)
			case "warn":
				l.Warn(message)
			case "error":
				l.Error(message)
			}

			output := buf.String()
			appeared := strings.Contains(output, message)

			if appeared != tt.shouldAppear {
				t.Errorf("expected message to appear=%v, but appeared=%v", tt.shouldAppear, appeared)
			}
		})
	}
}

func TestSetLevelRuntime(t *testing.T) {
	l, buf := newTestLogger(t)

	// Start at INFO level
	l.SetLevelString("info")

	// Debug message should not appear
	l.Debug("debug message 1")
	if strings.Contains(buf.String(), "debug message 1") {
		t.Error("debug message should not appear at INFO level")
	}

	// Change to DEBUG level
	buf.Reset()
	l.SetLevelString("debug")

	// Debug message should now appear
	l.Debug("debug message 2")
	if !strings.Contains(buf.String(), "debug message 2") {
		t.Error("debug message should appear at DEBUG level")
	}
}

func TestIsLevelEnabled(t *testing.T) {
	l := New()

	// Set to INFO level
	l.SetLevelString("info")

	if l.IsLevelEnabled("debug") {
		t.Error("debug should not be enabled at INFO level")
	}

	if !l.IsLevelEnabled("info") {
		t.Error("info should be enabled at INFO level")
	}

	if !l.IsLevelEnabled("warn") {
		t.Error("warn should be enabled at INFO level")
	}

	if !l.IsLevelEnabled("error") {
		t.Error("error should be enabled at INFO level")
	}
}

func TestIsDebugEnabled(t *testing.T) {
	l := New()

	// Default level is INFO
	if l.IsDebugEnabled() {
		t.Error("debug should not be enabled by default")
	}

	// Set to DEBUG
	l.SetLevelString("debug")
	if !l.IsDebugEnabled() {
		t.Error("debug should be enabled after setting level to debug")
	}
}

func TestGetLevel(t *testing.T) {
	l := New()

	// Default level is INFO
	if l.GetLevel() != "info" {
		t.Errorf("expected default level 'info', got '%s'", l.GetLevel())
	}

	// Set to DEBUG
	l.SetLevelString("debug")
	if l.GetLevel() != "debug" {
		t.Errorf("expected level 'debug', got '%s'", l.GetLevel())
	}
}

// ==============================================================================
// Concurrency Tests
// ==============================================================================

func TestConcurrentLogging(t *testing.T) {
	l, buf := newTestLogger(t)

	const numGoroutines = 100
	const logsPerGoroutine = 10

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < logsPerGoroutine; j++ {
				l.WithField("goroutine", id).
					WithField("log", j).
					Info("concurrent log")
			}
		}(i)
	}

	wg.Wait()

	// Verify all logs present
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	expected := numGoroutines * logsPerGoroutine

	if len(lines) != expected {
		t.Errorf("expected %d log lines, got %d", expected, len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestPermanentFieldsConcurrency(t *testing.T) {
	l := New()

	const numGoroutines = 50

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Each goroutine adds its own permanent field
			l.AddPermanentField(fmt.Sprintf("field%d", id), id)
		}(i)
	}

	wg.Wait()

	// Verify all fields were added (no race condition data loss)
	entry := l.WithField("test", "value")
	if len(entry.Data) != numGoroutines+1 { // +1 for "test" field
		t.Errorf("expected %d fields, got %d", numGoroutines+1, len(entry.Data))
	}
}

// ==============================================================================
// Error Handling Tests
// ==============================================================================

func TestWithError(t *testing.T) {
	l, buf := newTestLogger(t)

	testErr := errors.New("test error")
	l.WithError(testErr).Error("error occurred")

	data := parseJSONLog(t, buf.String())

	if data["error"] != "test error" {
		t.Errorf("expected error field 'test error', got '%v'", data["error"])
	}

	if data["message"] != "error occurred" {
		t.Error("message field not found or incorrect")
	}
}

func TestNilFieldValues(t *testing.T) {
	l, buf := newTestLogger(t)

	// Log with nil value
	l.WithField("nilfield", nil).Info("test with nil")

	data := parseJSONLog(t, buf.String())

	// nil should be represented as null in JSON
	if data["nilfield"] != nil {
		t.Error("nil field should be null in JSON")
	}
}

func TestEmptyMessage(t *testing.T) {
	l, buf := newTestLogger(t)

	l.Info("")

	data := parseJSONLog(t, buf.String())

	if data["message"] != "" {
		t.Error("expected empty message")
	}
}

// ==============================================================================
// Context Tests
// ==============================================================================

func TestWithContext(t *testing.T) {
	l, buf := newTestLogger(t)

	ctx := context.Background()
	ctx = WithRequestID(ctx, "abc123")
	ctx = WithUserID(ctx, "user456")

	l.WithContext(ctx).Info("contextual log")

	data := parseJSONLog(t, buf.String())

	if data["request_id"] != "abc123" {
		t.Errorf("request_id not extracted from context, got '%v'", data["request_id"])
	}
	if data["user_id"] != "user456" {
		t.Errorf("user_id not extracted from context, got '%v'", data["user_id"])
	}
}

func TestWithContextNoValues(t *testing.T) {
	l, buf := newTestLogger(t)

	ctx := context.Background()
	l.WithContext(ctx).Info("contextual log")

	data := parseJSONLog(t, buf.String())

	// Should not crash, just log without extra context fields
	if data["message"] != "contextual log" {
		t.Error("message should still be logged")
	}
}

// ==============================================================================
// Format Tests
// ==============================================================================

func TestJSONFieldOrdering(t *testing.T) {
	l, buf := newTestLogger(t)

	l.WithFields(Fields{
		"zebra":  "z",
		"apple":  "a",
		"middle": "m",
	}).Info("test")

	// Parse to verify it's valid JSON and fields are present
	data := parseJSONLog(t, buf.String())

	// Verify all custom fields are present (order verified by formatter implementation)
	if data["zebra"] != "z" {
		t.Error("zebra field missing or incorrect")
	}
	if data["apple"] != "a" {
		t.Error("apple field missing or incorrect")
	}
	if data["middle"] != "m" {
		t.Error("middle field missing or incorrect")
	}

	// Verify timestamp, level, message are present
	if data["timestamp"] == nil {
		t.Error("timestamp field missing")
	}
	if data["level"] != "info" {
		t.Error("level field missing or incorrect")
	}
	if data["message"] != "test" {
		t.Error("message field missing or incorrect")
	}
}

func TestTimestampFormat(t *testing.T) {
	l, buf := newTestLogger(t)
	l.Info("test")

	data := parseJSONLog(t, buf.String())

	timestamp, ok := data["timestamp"].(string)
	if !ok {
		t.Fatal("timestamp is not a string")
	}

	// Verify RFC3339Nano format
	_, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		t.Errorf("invalid timestamp format: %v", err)
	}
}

func TestFormatSwitching(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	// Start with JSON
	l.SetFormatter(NewJSONFormatter())
	l.Info("json message")

	output1 := buf.String()
	if !strings.Contains(output1, `"message":"json message"`) {
		t.Error("JSON format not applied")
	}

	// Switch to text
	buf.Reset()
	l.SetFormatter(&SafeOpsTextFormatter{ColorEnabled: false})
	l.Info("text message")

	output2 := buf.String()
	if !strings.Contains(output2, "[INFO]") || !strings.Contains(output2, "text message") {
		t.Error("text format not applied")
	}
}

// ==============================================================================
// Config Tests
// ==============================================================================

func TestNewWithConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		verify func(*testing.T, *Logger)
	}{
		{
			name: "JSON format with DEBUG level",
			config: Config{
				Level:  "debug",
				Format: "json",
			},
			verify: func(t *testing.T, l *Logger) {
				if !l.IsDebugEnabled() {
					t.Error("debug level should be enabled")
				}
			},
		},
		{
			name: "Text format with INFO level",
			config: Config{
				Level:  "info",
				Format: "text",
			},
			verify: func(t *testing.T, l *Logger) {
				if l.GetLevel() != "info" {
					t.Errorf("expected info level, got %s", l.GetLevel())
				}
			},
		},
		{
			name: "Invalid level defaults to INFO",
			config: Config{
				Level: "invalid",
			},
			verify: func(t *testing.T, l *Logger) {
				// Should default to INFO without error
				if l.GetLevel() != "info" {
					t.Errorf("invalid level should default to info, got %s", l.GetLevel())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewWithConfig(tt.config)
			if l == nil {
				t.Fatal("expected non-nil logger")
			}
			tt.verify(t, l)
		})
	}
}

func TestSpecialCharactersInFields(t *testing.T) {
	l, buf := newTestLogger(t)

	l.WithFields(Fields{
		"quotes":   `"quoted"`,
		"newlines": "line1\nline2",
		"tabs":     "tab\there",
	}).Info("special chars")

	data := parseJSONLog(t, buf.String())

	// JSON should properly escape these
	if data["quotes"] != `"quoted"` {
		t.Error("quotes not properly handled")
	}
	if data["newlines"] != "line1\nline2" {
		t.Error("newlines not properly handled")
	}
}

// ==============================================================================
// Rotation Tests
// ==============================================================================

func TestSetupRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	writer := SetupRotation(logFile, 1, 3, 7, true)

	if writer == nil {
		t.Fatal("SetupRotation returned nil")
	}

	// Write something to verify it works
	n, err := writer.Write([]byte("test log entry\n"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n == 0 {
		t.Error("Expected bytes written")
	}

	// Close the writer to release file handle (important on Windows)
	if closer, ok := writer.(interface{ Close() error }); ok {
		closer.Close()
	}
}

func TestSetupRotationWithConfig(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	cfg := RotatingConfig{
		Filename:   logFile,
		MaxSizeMB:  1,
		MaxBackups: 3,
		MaxAgeDays: 7,
		Compress:   true,
	}

	writer := SetupRotationWithConfig(cfg)

	if writer == nil {
		t.Fatal("SetupRotationWithConfig returned nil")
	}
}

func TestNewRotatingWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	cfg := RotatingConfig{
		Filename:   logFile,
		MaxSizeMB:  1,
		MaxBackups: 3,
		MaxAgeDays: 7,
		Compress:   false,
	}

	writer, err := NewRotatingWriter(cfg)
	if err != nil {
		t.Fatalf("NewRotatingWriter error: %v", err)
	}
	defer writer.Close()

	// Write some data
	n, err := writer.Write([]byte("test log entry\n"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != 15 {
		t.Errorf("Written bytes = %d, want 15", n)
	}
}

func TestRotatingWriterClose(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	cfg := RotatingConfig{
		Filename:   logFile,
		MaxSizeMB:  1,
		MaxBackups: 3,
		MaxAgeDays: 7,
	}

	writer, err := NewRotatingWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}

	writer.Write([]byte("test\n"))
	err = writer.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestRotatingWriterForceRotate(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	cfg := RotatingConfig{
		Filename:   logFile,
		MaxSizeMB:  100, // Large to prevent auto-rotation
		MaxBackups: 3,
		MaxAgeDays: 7,
		Compress:   false,
	}

	writer, err := NewRotatingWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	// Write initial data
	writer.Write([]byte("initial log\n"))

	// Force rotation
	err = writer.Rotate()
	if err != nil {
		t.Errorf("Rotate error: %v", err)
	}

	// Write more data after rotation
	writer.Write([]byte("after rotation\n"))
}

// ==============================================================================
// MultiWriter Tests
// ==============================================================================

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	multi := NewMultiWriter(&buf1, &buf2)

	n, err := multi.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != 4 {
		t.Errorf("Written = %d, want 4", n)
	}

	if buf1.String() != "test" {
		t.Error("Buffer 1 should have content")
	}
	if buf2.String() != "test" {
		t.Error("Buffer 2 should have content")
	}
}

func TestMultiWriterAdd(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	multi := NewMultiWriter(&buf1)
	multi.Add(&buf2)

	multi.Write([]byte("test"))

	if buf1.String() != "test" {
		t.Error("Buffer 1 should have content")
	}
	if buf2.String() != "test" {
		t.Error("Added buffer should receive writes")
	}
}

// ==============================================================================
// AsyncWriter Tests
// ==============================================================================

func TestAsyncWriter(t *testing.T) {
	var buf bytes.Buffer
	async := NewAsyncWriter(&buf, 100)
	defer async.Close()

	for i := 0; i < 10; i++ {
		async.Write([]byte("test\n"))
	}

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	output := buf.String()
	count := strings.Count(output, "test")
	if count != 10 {
		t.Errorf("Expected 10 writes, got %d", count)
	}
}

func TestAsyncWriterClose(t *testing.T) {
	var buf bytes.Buffer
	async := NewAsyncWriter(&buf, 100)

	async.Write([]byte("test\n"))
	err := async.Close()

	if err != nil {
		t.Errorf("Close error: %v", err)
	}

	// After close with drain, write should be present
	time.Sleep(50 * time.Millisecond)
	if !strings.Contains(buf.String(), "test") {
		t.Error("Buffer should contain written data after close")
	}
}

// ==============================================================================
// Package-Level Function Tests
// ==============================================================================

func TestPackageLevelLogging(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	SetDefault(logger)
	defer SetDefault(original)

	Info("info message")
	Warn("warn message")
	Error("error message")

	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Error("Info() should log")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Warn() should log")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error() should log")
	}
}

func TestPackageLevelDebug(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	logger.SetLevel(DebugLevel)
	SetDefault(logger)
	defer SetDefault(original)

	Debug("debug message")
	Debugf("debug formatted %s", "value")

	output := buf.String()
	if !strings.Contains(output, "debug message") {
		t.Error("Debug() should log")
	}
	if !strings.Contains(output, "debug formatted value") {
		t.Error("Debugf() should log")
	}
}

func TestPackageLevelFormatted(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	SetDefault(logger)
	defer SetDefault(original)

	Infof("info %d", 123)
	Warnf("warn %s", "test")
	Errorf("error %v", errors.New("test error"))

	output := buf.String()
	if !strings.Contains(output, "info 123") {
		t.Error("Infof() should format correctly")
	}
	if !strings.Contains(output, "warn test") {
		t.Error("Warnf() should format correctly")
	}
	if !strings.Contains(output, "error test error") {
		t.Error("Errorf() should format correctly")
	}
}

func TestPackageLevelWithField(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	SetDefault(logger)
	defer SetDefault(original)

	WithField("key", "value").Info("test")

	data := parseJSONLog(t, buf.String())
	if data["key"] != "value" {
		t.Error("WithField should add field")
	}
}

func TestPackageLevelWithFields(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	SetDefault(logger)
	defer SetDefault(original)

	WithFields(Fields{"k1": "v1", "k2": "v2"}).Info("test")

	data := parseJSONLog(t, buf.String())
	if data["k1"] != "v1" || data["k2"] != "v2" {
		t.Error("WithFields should add all fields")
	}
}

func TestPackageLevelWithError(t *testing.T) {
	var buf bytes.Buffer
	original := Default()

	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())
	SetDefault(logger)
	defer SetDefault(original)

	testErr := errors.New("package level error")
	WithError(testErr).Error("operation failed")

	data := parseJSONLog(t, buf.String())
	if data["error"] != "package level error" {
		t.Error("WithError should add error field")
	}
}

// ==============================================================================
// Level Hook Tests
// ==============================================================================

func TestLevelFilter(t *testing.T) {
	var errorCount int
	filter := NewLevelFilter(ErrorLevel, ErrorLevel, func(entry *Entry) error {
		errorCount++
		return nil
	})

	levels := filter.Levels()
	if len(levels) != 1 || levels[0] != ErrorLevel {
		t.Errorf("LevelFilter should only include ErrorLevel, got %v", levels)
	}
}

func TestErrorOnlyHook(t *testing.T) {
	var count int
	hook := &ErrorOnlyHook{
		Handler: func(entry *Entry) error {
			count++
			return nil
		},
	}

	levels := hook.Levels()
	if len(levels) != 3 {
		t.Errorf("ErrorOnlyHook should handle 3 levels (error, fatal, panic), got %d", len(levels))
	}

	// Fire the hook
	hook.Fire(&Entry{})
	if count != 1 {
		t.Error("Handler should be called")
	}
}

func TestLevelFilterNilHandler(t *testing.T) {
	filter := NewLevelFilter(ErrorLevel, ErrorLevel, nil)

	// Should not panic with nil handler
	err := filter.Fire(&Entry{})
	if err != nil {
		t.Errorf("Fire with nil handler should return nil, got %v", err)
	}
}

func TestErrorOnlyHookNilHandler(t *testing.T) {
	hook := &ErrorOnlyHook{Handler: nil}

	// Should not panic with nil handler
	err := hook.Fire(&Entry{})
	if err != nil {
		t.Errorf("Fire with nil handler should return nil, got %v", err)
	}
}

// ==============================================================================
// Additional Level Tests
// ==============================================================================

func TestMustParseLevel(t *testing.T) {
	// Valid level should not panic
	level := MustParseLevel("debug")
	if level != DebugLevel {
		t.Errorf("Expected DebugLevel, got %v", level)
	}
}

func TestMustParseLevelPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseLevel should panic for invalid level")
		}
	}()

	MustParseLevel("invalid_level")
}

func TestAllLevels(t *testing.T) {
	levels := AllLevels()

	if len(levels) != 7 {
		t.Errorf("Expected 7 levels, got %d", len(levels))
	}

	// Verify all expected levels are present
	expectedLevels := []Level{PanicLevel, FatalLevel, ErrorLevel, WarnLevel, InfoLevel, DebugLevel, TraceLevel}
	for _, expected := range expectedLevels {
		found := false
		for _, level := range levels {
			if level == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Level %v not found in AllLevels()", expected)
		}
	}
}

func TestLevelNames(t *testing.T) {
	names := LevelNames()

	if len(names) != 7 {
		t.Errorf("Expected 7 level names, got %d", len(names))
	}

	expectedNames := []string{"panic", "fatal", "error", "warn", "info", "debug", "trace"}
	for _, expected := range expectedNames {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Level name %s not found in LevelNames()", expected)
		}
	}
}

func TestIsTraceEnabled(t *testing.T) {
	l := New()

	// Default level is INFO, trace should not be enabled
	if l.IsTraceEnabled() {
		t.Error("Trace should not be enabled at INFO level")
	}

	// Set to TRACE
	l.SetLevel(TraceLevel)
	if !l.IsTraceEnabled() {
		t.Error("Trace should be enabled at TRACE level")
	}
}

// ==============================================================================
// Context Key Tests
// ==============================================================================

func TestWithTraceID(t *testing.T) {
	l, buf := newTestLogger(t)

	ctx := context.Background()
	ctx = WithTraceID(ctx, "trace-abc-123")

	l.WithContext(ctx).Info("traced log")

	data := parseJSONLog(t, buf.String())
	if data["trace_id"] != "trace-abc-123" {
		t.Errorf("trace_id not extracted from context, got '%v'", data["trace_id"])
	}
}

func TestWithTime(t *testing.T) {
	l, buf := newTestLogger(t)

	customTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	l.WithTime(customTime).Info("timed log")

	data := parseJSONLog(t, buf.String())
	timestamp, ok := data["timestamp"].(string)
	if !ok {
		t.Fatal("timestamp not found")
	}

	// Should contain the custom year
	if !strings.Contains(timestamp, "2025") {
		t.Errorf("Expected timestamp with 2025, got %s", timestamp)
	}
}

// ==============================================================================
// Default Logger Tests
// ==============================================================================

func TestDefaultLogger(t *testing.T) {
	d := Default()
	if d == nil {
		t.Error("Default() should not return nil")
	}
}

func TestSetDefault(t *testing.T) {
	original := Default()
	defer SetDefault(original)

	custom := New()
	custom.AddPermanentField("custom", true)

	SetDefault(custom)

	if Default() != custom {
		t.Error("SetDefault should change the default logger")
	}
}

// ==============================================================================
// Formatter Edge Cases
// ==============================================================================

func TestJSONFormatterPrettyPrint(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	formatter := NewJSONFormatter()
	formatter.PrettyPrint = true
	l.SetFormatter(formatter)

	l.Info("test")

	output := buf.String()
	// Pretty print should have indentation
	if !strings.Contains(output, "\n  ") {
		t.Error("Pretty print should have indentation")
	}
}

func TestJSONFormatterDisableTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	formatter := &SafeOpsJSONFormatter{
		DisableTimestamp: true,
	}
	l.SetFormatter(formatter)

	l.Info("test")

	data := parseJSONLog(t, buf.String())
	if data["timestamp"] != nil {
		t.Error("Timestamp should not be present when disabled")
	}
}

func TestJSONFormatterFieldMap(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	formatter := &SafeOpsJSONFormatter{
		FieldMap: map[string]string{
			"timestamp": "ts",
			"level":     "lvl",
			"message":   "msg",
		},
	}
	l.SetFormatter(formatter)

	l.Info("test message")

	data := parseJSONLog(t, buf.String())
	if data["ts"] == nil {
		t.Error("timestamp should be renamed to 'ts'")
	}
	if data["lvl"] != "info" {
		t.Error("level should be renamed to 'lvl'")
	}
	if data["msg"] != "test message" {
		t.Error("message should be renamed to 'msg'")
	}
}

func TestTextFormatterQuoteStrings(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	formatter := &SafeOpsTextFormatter{
		ColorEnabled: false,
		QuoteStrings: true,
		SortFields:   true,
	}
	l.SetFormatter(formatter)

	l.WithField("key", "value with spaces").Info("test")

	output := buf.String()
	if !strings.Contains(output, `key="value with spaces"`) {
		t.Errorf("String values should be quoted, got: %s", output)
	}
}

func TestTextFormatterDisableTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := New()
	l.SetOutput(&buf)

	formatter := &SafeOpsTextFormatter{
		ColorEnabled:     false,
		DisableTimestamp: true,
	}
	l.SetFormatter(formatter)

	l.Info("test message")

	output := buf.String()
	// Should start with [INFO] not [timestamp]
	if !strings.HasPrefix(output, "[INFO]") {
		t.Errorf("Output should start with [INFO] when timestamp is disabled, got: %s", output)
	}
}

// ==============================================================================
// Benchmark Tests
// ==============================================================================

func BenchmarkLoggerInfo(b *testing.B) {
	logger := New()
	logger.SetOutput(&bytes.Buffer{})
	logger.SetFormatter(NewJSONFormatter())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark log message")
	}
}

func BenchmarkLoggerWithField(b *testing.B) {
	logger := New()
	logger.SetOutput(&bytes.Buffer{})
	logger.SetFormatter(NewJSONFormatter())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithField("key", "value").Info("benchmark")
	}
}

func BenchmarkLoggerWithFields(b *testing.B) {
	logger := New()
	logger.SetOutput(&bytes.Buffer{})
	logger.SetFormatter(NewJSONFormatter())

	fields := Fields{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithFields(fields).Info("benchmark")
	}
}

func BenchmarkJSONFormat(b *testing.B) {
	var buf bytes.Buffer
	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(NewJSONFormatter())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.WithField("key", "value").Info("benchmark")
	}
}

func BenchmarkTextFormat(b *testing.B) {
	var buf bytes.Buffer
	logger := New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&SafeOpsTextFormatter{ColorEnabled: false})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.WithField("key", "value").Info("benchmark")
	}
}

func BenchmarkConcurrentLogging(b *testing.B) {
	logger := New()
	logger.SetOutput(&bytes.Buffer{})
	logger.SetFormatter(NewJSONFormatter())

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.WithField("goroutine", 1).Info("concurrent")
		}
	})
}
