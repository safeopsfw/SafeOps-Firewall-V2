// Package logging provides log formatters.
package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// JSONFormatter formats logs as JSON
type JSONFormatter struct {
	// TimestampFormat is the format for timestamps
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

// Format formats the log entry as JSON
func (f *JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(map[string]interface{})

	// Copy fields
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

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

	// Add standard fields
	if !f.DisableTimestamp {
		format := f.TimestampFormat
		if format == "" {
			format = time.RFC3339Nano
		}
		data[timestampField] = entry.Time.Format(format)
	}

	data[levelField] = entry.Level.String()
	data[messageField] = entry.Message

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

// TextFormatter formats logs as text
type TextFormatter struct {
	// TimestampFormat is the format for timestamps
	TimestampFormat string

	// DisableTimestamp disables timestamp output
	DisableTimestamp bool

	// FullTimestamp shows full timestamp instead of delta
	FullTimestamp bool

	// DisableColors disables ANSI colors
	DisableColors bool

	// QuoteStrings quotes string values
	QuoteStrings bool

	// SortFields sorts fields alphabetically
	SortFields bool
}

// Color codes
const (
	colorRed     = 31
	colorYellow  = 33
	colorBlue    = 34
	colorMagenta = 35
	colorCyan    = 36
	colorWhite   = 37
	colorGray    = 90
)

// getLevelColor returns the ANSI color for a level
func getLevelColor(level logrus.Level) int {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return colorMagenta
	case logrus.ErrorLevel:
		return colorRed
	case logrus.WarnLevel:
		return colorYellow
	case logrus.InfoLevel:
		return colorCyan
	case logrus.DebugLevel:
		return colorGray
	case logrus.TraceLevel:
		return colorWhite
	default:
		return colorWhite
	}
}

// Format formats the log entry as text
func (f *TextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf bytes.Buffer

	// Timestamp
	if !f.DisableTimestamp {
		format := f.TimestampFormat
		if format == "" {
			format = time.RFC3339
		}
		buf.WriteString(entry.Time.Format(format))
		buf.WriteString(" ")
	}

	// Level
	levelText := strings.ToUpper(entry.Level.String())
	if !f.DisableColors {
		color := getLevelColor(entry.Level)
		buf.WriteString(fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, levelText))
	} else {
		buf.WriteString(levelText)
	}
	buf.WriteString(" ")

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
func (f *TextFormatter) writeFields(buf *bytes.Buffer, fields logrus.Fields) {
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
	buf.WriteString(fmt.Sprintf("\x1b[%dm%-4s\x1b[0m ", color, levelText))

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

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
}

// NewTextFormatter creates a new text formatter
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
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
