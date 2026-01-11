package errors

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// SafeOpsError is a custom error type that provides structured error handling
// with machine-readable error codes, contextual fields, stack traces, and
// error wrapping capabilities for consistent error handling across all
// SafeOps Go services.
type SafeOpsError struct {
	// Code is the machine-readable error code (e.g., "DB_CONNECTION_FAILED")
	Code string

	// Message is the human-readable error description
	Message string

	// Fields contains additional context key-value pairs
	Fields map[string]interface{}

	// Cause is the underlying error being wrapped (if any)
	Cause error

	// Stack is the stack trace capturing error origin
	Stack []string

	// Timestamp records when the error occurred
	Timestamp time.Time
}

// New creates a new SafeOpsError with the given code and message.
// It captures the stack trace at the point of creation and initializes
// an empty Fields map.
//
// Example:
//
//	err := errors.New("DB_CONNECTION_FAILED", "Could not connect to PostgreSQL")
func New(code, message string) *SafeOpsError {
	return &SafeOpsError{
		Code:      code,
		Message:   message,
		Fields:    make(map[string]interface{}),
		Stack:     captureStack(),
		Timestamp: time.Now(),
	}
}

// Newf creates a new SafeOpsError with formatted message using fmt.Sprintf.
//
// Example:
//
//	err := errors.Newf("DB_QUERY_FAILED", "Query failed on table %s", tableName)
func Newf(code, format string, args ...interface{}) *SafeOpsError {
	return New(code, fmt.Sprintf(format, args...))
}

// Wrap wraps an existing error with a SafeOpsError, preserving the original
// error in the Cause field. This enables error chain navigation while adding
// context at each layer.
//
// Example:
//
//	err := errors.Wrap(sqlErr, "DB_CONNECTION_FAILED", "Could not connect to PostgreSQL")
func Wrap(err error, code, message string) *SafeOpsError {
	if err == nil {
		return nil
	}

	return &SafeOpsError{
		Code:      code,
		Message:   message,
		Fields:    make(map[string]interface{}),
		Cause:     err,
		Stack:     captureStack(),
		Timestamp: time.Now(),
	}
}

// Wrapf wraps an existing error with a formatted message.
//
// Example:
//
//	err := errors.Wrapf(sqlErr, "DB_QUERY_FAILED", "Query failed on table %s", tableName)
func Wrapf(err error, code, format string, args ...interface{}) *SafeOpsError {
	return Wrap(err, code, fmt.Sprintf(format, args...))
}

// WithField adds a single contextual field to the error and returns the same
// error instance, enabling method chaining.
//
// Example:
//
//	err.WithField("user_id", 123).WithField("action", "login")
func (e *SafeOpsError) WithField(key string, value interface{}) *SafeOpsError {
	if e == nil {
		return nil
	}
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}
	e.Fields[key] = value
	return e
}

// WithFields adds multiple contextual fields at once, merging with existing fields.
//
// Example:
//
//	err.WithFields(map[string]interface{}{"query": sql, "duration_ms": 150})
func (e *SafeOpsError) WithFields(fields map[string]interface{}) *SafeOpsError {
	if e == nil {
		return nil
	}
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}
	for k, v := range fields {
		e.Fields[k] = v
	}
	return e
}

// WithCause sets the underlying cause error. This is used when creating an
// error from scratch but having an underlying error to associate.
func (e *SafeOpsError) WithCause(cause error) *SafeOpsError {
	if e == nil {
		return nil
	}
	e.Cause = cause
	return e
}

// Error implements the standard error interface, returning a formatted string
// in the format "[CODE] message".
//
// Example output: "[DB_CONNECTION_FAILED] Could not connect to PostgreSQL"
func (e *SafeOpsError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return fmt.Sprintf("[%s] %s", e.Code, e.Message)
	}
	return e.Message
}

// Unwrap implements the errors.Unwrap interface (Go 1.13+), returning the
// underlying Cause error. This enables errors.Is() and errors.As() checks
// to traverse the error chain.
func (e *SafeOpsError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is implements the errors.Is interface, comparing error codes.
// Returns true if the target error is a SafeOpsError with matching code.
func (e *SafeOpsError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}

	t, ok := target.(*SafeOpsError)
	if !ok {
		return false
	}

	return e.Code == t.Code
}

// captureStack captures the current call stack, skipping internal error
// package frames. It uses runtime.Callers() to get program counters and
// converts them to function names and file:line pairs.
//
// Returns a slice of strings like "main.processRequest (/app/main.go:45)"
func captureStack() []string {
	const maxStackDepth = 32
	pcs := make([]uintptr, maxStackDepth)
	n := runtime.Callers(3, pcs) // Skip captureStack, New/Wrap, and runtime.Callers itself

	if n == 0 {
		return []string{}
	}

	frames := runtime.CallersFrames(pcs[:n])
	stack := make([]string, 0, n)

	for {
		frame, more := frames.Next()

		// Skip internal error package frames
		if !strings.Contains(frame.File, "errors/errors.go") {
			stack = append(stack, fmt.Sprintf("%s (%s:%d)",
				frame.Function,
				frame.File,
				frame.Line,
			))
		}

		if !more {
			break
		}
	}

	return stack
}

// StackTrace returns the captured stack trace as a slice of strings.
// Each element is formatted as "function (file:line)".
func (e *SafeOpsError) StackTrace() []string {
	if e == nil {
		return []string{}
	}
	return e.Stack
}

// FormatStack formats the stack trace as a multi-line string suitable for
// logging or display.
//
// Example output:
//
//	goroutine 1:
//	  main.processRequest (/app/main.go:45)
//	  main.handleHTTP (/app/main.go:30)
//	  main.main (/app/main.go:15)
func (e *SafeOpsError) FormatStack() string {
	if e == nil || len(e.Stack) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("goroutine 1:\n")
	for _, frame := range e.Stack {
		sb.WriteString("  ")
		sb.WriteString(frame)
		sb.WriteString("\n")
	}
	return sb.String()
}

// ToLogFields converts the error to structured log fields suitable for use
// with structured logging libraries like logrus.
//
// Returns a map containing:
//   - error_code: The error code
//   - error_message: The error message
//   - error_stack: The first stack frame (origin of error)
//   - All custom fields from the Fields map
//
// Example return:
//
//	{
//	    "error_code": "DB_CONNECTION_FAILED",
//	    "error_message": "Could not connect to PostgreSQL",
//	    "error_stack": "main.connectDB (/app/db.go:23)",
//	    "user_id": 123,
//	    "database": "safeops_main"
//	}
func (e *SafeOpsError) ToLogFields() map[string]interface{} {
	if e == nil {
		return map[string]interface{}{}
	}

	fields := make(map[string]interface{})

	// Add error metadata
	if e.Code != "" {
		fields["error_code"] = e.Code
	}
	if e.Message != "" {
		fields["error_message"] = e.Message
	}

	// Add first stack frame (origin of error)
	if len(e.Stack) > 0 {
		fields["error_stack"] = e.Stack[0]
	}

	// Add timestamp
	if !e.Timestamp.IsZero() {
		fields["error_timestamp"] = e.Timestamp
	}

	// Merge all custom fields
	for k, v := range e.Fields {
		fields[k] = v
	}

	// Add cause error message if present
	if e.Cause != nil {
		fields["error_cause"] = e.Cause.Error()
	}

	return fields
}

// Is is a standalone function that checks if an error has a specific error code.
// It works with wrapped errors by traversing the error chain.
//
// Example:
//
//	if errors.Is(err, "DB_CONNECTION_FAILED") {
//	    // Handle database connection error
//	}
func Is(err error, code string) bool {
	if err == nil {
		return false
	}

	// Check if it's a SafeOpsError directly
	if se, ok := err.(*SafeOpsError); ok {
		if se.Code == code {
			return true
		}
		// If code doesn't match, continue checking the wrapped error
		if se.Cause != nil {
			return Is(se.Cause, code)
		}
		return false
	}

	// Try to unwrap and check recursively (for non-SafeOpsError wrappers)
	if unwrapped := Unwrap(err); unwrapped != nil {
		return Is(unwrapped, code)
	}

	return false
}

// GetCode extracts the error code from an error, searching the entire error chain.
// Returns an empty string if the error is not a SafeOpsError or has no code.
//
// Example:
//
//	code := errors.GetCode(err)
//	if code == "DB_CONNECTION_FAILED" {
//	    // Handle database connection error
//	}
func GetCode(err error) string {
	if err == nil {
		return ""
	}

	// Check if it's a SafeOpsError
	if se, ok := err.(*SafeOpsError); ok {
		return se.Code
	}

	// Try to unwrap and check recursively
	if unwrapped := Unwrap(err); unwrapped != nil {
		return GetCode(unwrapped)
	}

	return ""
}

// HasCode returns true if the error is a SafeOpsError with a non-empty code.
// Returns false for standard Go errors without codes.
func HasCode(err error) bool {
	return GetCode(err) != ""
}

// Unwrap is a standalone function that unwraps an error, returning its cause.
// This provides compatibility with the standard errors package.
func Unwrap(err error) error {
	if err == nil {
		return nil
	}

	// Check if it implements Unwrap
	type unwrapper interface {
		Unwrap() error
	}

	if u, ok := err.(unwrapper); ok {
		return u.Unwrap()
	}

	return nil
}
