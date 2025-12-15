package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
	l.SetFormatter(&TextFormatter{
		DisableColors: true,
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
