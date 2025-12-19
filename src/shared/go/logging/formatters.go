// Package logging provides log formatters.
package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// SafeOpsJSONFormatter formats logs as JSON with SafeOps conventions
type SafeOpsJSONFormatter struct {
	// TimestampFormat is the format for timestamps (default: RFC3339Nano)
	TimestampFormat string

	// DisableTimestamp disables timestamp output
	DisableTimestamp bool

	// DataKey is the key for the data field (empty = inline)
	DataKey string

	// PrettyPrint enables indented output
	PrettyPrint bool

	// FieldMap allows renaming default fields
	FieldMap map[string]string
}

// Format formats the log entry as JSON with ordered fields
func (f *SafeOpsJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Get field names
	timestampField := "timestamp"
	levelField := "level"
	messageField := "message"

	if f.FieldMap != nil {
		if v, ok := f.FieldMap["timestamp"]; ok {
			timestampField = v
		}
		if v, ok := f.FieldMap["level"]; ok {
			levelField = v
		}
		if v, ok := f.FieldMap["message"]; ok {
			messageField = v
		}
	}

	// Build ordered data map - fixed fields first, then sorted custom fields
	data := make(map[string]interface{})

	// 1. Timestamp (first)
	if !f.DisableTimestamp {
		format := f.TimestampFormat
		if format == "" {
			format = time.RFC3339Nano
		}
		data[timestampField] = entry.Time.Format(format)
	}

	// 2. Level (second)
	data[levelField] = entry.Level.String()

	// 3. Message (third)
	data[messageField] = entry.Message

	// 4. Custom fields (sorted alphabetically)
	// Get sorted keys for custom fields
	customKeys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		customKeys = append(customKeys, k)
	}
	sort.Strings(customKeys)

	// Add custom fields in sorted order
	for _, k := range customKeys {
		v := entry.Data[k]
		switch v := v.(type) {
		case error:
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)

	if f.PrettyPrint {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// SafeOpsTextFormatter formats logs as text with SafeOps conventions
type SafeOpsTextFormatter struct {
	// TimestampFormat is the format for timestamps (default: "2006-01-02 15:04:05")
	TimestampFormat string

	// DisableTimestamp disables timestamp output
	DisableTimestamp bool

	// FullTimestamp shows full timestamp instead of delta
	FullTimestamp bool

	// ColorEnabled enables ANSI colors (auto-detected by default)
	ColorEnabled bool

	// QuoteStrings quotes string values
	QuoteStrings bool

	// SortFields sorts fields alphabetically
	SortFields bool
}

// Color codes
const (
	colorRed     = 31
	colorGreen   = 32
	colorYellow  = 33
	colorBlue    = 34
	colorMagenta = 35
	colorCyan    = 36
	colorWhite   = 37
	colorGray    = 90
	colorRedBold = "1;31" // Bold red for fatal/panic
)

// getLevelColor returns the ANSI color for a level (updated color scheme)
func getLevelColor(level logrus.Level) string {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return colorRedBold // Red bold
	case logrus.ErrorLevel:
		return fmt.Sprintf("%d", colorRed) // Red
	case logrus.WarnLevel:
		return fmt.Sprintf("%d", colorYellow) // Yellow
	case logrus.InfoLevel:
		return fmt.Sprintf("%d", colorGreen) // Green (updated from Cyan)
	case logrus.DebugLevel:
		return fmt.Sprintf("%d", colorCyan) // Cyan (updated from Gray)
	case logrus.TraceLevel:
		return fmt.Sprintf("%d", colorGray) // Gray
	default:
		return fmt.Sprintf("%d", colorWhite)
	}
}

// colorizeLevel wraps level string in ANSI color codes
func colorizeLevel(levelStr string, level logrus.Level) string {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return levelStr
	}
	color := getLevelColor(level)
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", color, levelStr)
}

// isTerminal detects if output is terminal (supports colors) vs file/pipe
func isTerminal(w io.Writer) bool {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

// Format formats the log entry as text with SafeOps format: [TIMESTAMP] [LEVEL] message field=value
func (f *SafeOpsTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf bytes.Buffer

	// [Timestamp]
	if !f.DisableTimestamp {
		format := f.TimestampFormat
		if format == "" {
			format = "2006-01-02 15:04:05" // SafeOps default format
		}
		buf.WriteString("[")
		buf.WriteString(entry.Time.Format(format))
		buf.WriteString("] ")
	}

	// [Level]
	levelText := strings.ToUpper(entry.Level.String())
	buf.WriteString("[")
	if f.ColorEnabled {
		buf.WriteString(colorizeLevel(levelText, entry.Level))
	} else {
		buf.WriteString(levelText)
	}
	buf.WriteString("] ")

	// Message
	buf.WriteString(entry.Message)

	// Fields
	if len(entry.Data) > 0 {
		buf.WriteString(" ")
		f.writeFields(&buf, entry.Data)
	}

	buf.WriteString("\n")
	return buf.Bytes(), nil
}

// writeFields writes fields to the buffer
func (f *SafeOpsTextFormatter) writeFields(buf *bytes.Buffer, fields logrus.Fields) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}

	if f.SortFields {
		sort.Strings(keys)
	}

	for i, k := range keys {
		if i > 0 {
			buf.WriteString(" ")
		}

		v := fields[k]

		if f.QuoteStrings {
			if s, ok := v.(string); ok {
				buf.WriteString(fmt.Sprintf("%s=%q", k, s))
				continue
			}
		}

		buf.WriteString(fmt.Sprintf("%s=%v", k, v))
	}
}

// fieldToString converts field key-value pair to string representation
func fieldToString(key string, value interface{}) string {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%s=%s", key, v)
	case error:
		return fmt.Sprintf("%s=%s", key, v.Error())
	default:
		return fmt.Sprintf("%s=%v", key, v)
	}
}

// ConsoleFormatter provides colored console output
type ConsoleFormatter struct {
	TimestampFormat string
	ShowFields      bool
}

// Format formats the log entry for console
func (f *ConsoleFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf bytes.Buffer

	// Timestamp
	format := f.TimestampFormat
	if format == "" {
		format = "15:04:05"
	}
	buf.WriteString(fmt.Sprintf("\x1b[%dm%s\x1b[0m ", colorGray, entry.Time.Format(format)))

	// Level with color
	color := getLevelColor(entry.Level)
	levelText := strings.ToUpper(entry.Level.String())[:4]
	buf.WriteString(fmt.Sprintf("\x1b[%sm%-4s\x1b[0m ", color, levelText))

	// Message
	buf.WriteString(entry.Message)

	// Fields
	if f.ShowFields && len(entry.Data) > 0 {
		buf.WriteString(fmt.Sprintf(" \x1b[%dm", colorGray))

		first := true
		for k, v := range entry.Data {
			if !first {
				buf.WriteString(" ")
			}
			buf.WriteString(fmt.Sprintf("%s=%v", k, v))
			first = false
		}

		buf.WriteString("\x1b[0m")
	}

	buf.WriteString("\n")
	return buf.Bytes(), nil
}

// NewJSONFormatter creates a new SafeOps JSON formatter
func NewJSONFormatter() *SafeOpsJSONFormatter {
	return &SafeOpsJSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		PrettyPrint:     false, // Production default
	}
}

// NewTextFormatter creates a new SafeOps text formatter
func NewTextFormatter() *SafeOpsTextFormatter {
	return &SafeOpsTextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05", // SafeOps default
		ColorEnabled:    isTerminal(os.Stdout), // Auto-detect
		SortFields:      true,
	}
}

// NewConsoleFormatter creates a new console formatter
func NewConsoleFormatter() *ConsoleFormatter {
	return &ConsoleFormatter{
		TimestampFormat: "15:04:05",
		ShowFields:      true,
	}
}

// FormatByName returns a formatter by name
func FormatByName(name string) logrus.Formatter {
	switch strings.ToLower(name) {
	case "json":
		return NewJSONFormatter()
	case "text":
		return NewTextFormatter()
	case "console":
		return NewConsoleFormatter()
	default:
		return NewJSONFormatter()
	}
}
