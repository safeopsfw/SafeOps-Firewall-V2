// Package errors provides error handling utilities.
package errors

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Error represents a structured error with code and context
type Error struct {
	Code    Code
	Message string
	Cause   error
	Stack   []Frame
	Context map[string]interface{}
}

// Frame represents a stack frame
type Frame struct {
	Function string
	File     string
	Line     int
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches a target
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Code == t.Code
	}
	return false
}

// WithContext adds context to the error
func (e *Error) WithContext(key string, value interface{}) *Error {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// New creates a new error
func New(code Code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Stack:   captureStack(2),
	}
}

// Newf creates a new formatted error
func Newf(code Code, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Stack:   captureStack(2),
	}
}

// Wrap wraps an error with additional context
func Wrap(err error, code Code, message string) *Error {
	if err == nil {
		return nil
	}

	return &Error{
		Code:    code,
		Message: message,
		Cause:   err,
		Stack:   captureStack(2),
	}
}

// Wrapf wraps an error with formatted message
func Wrapf(err error, code Code, format string, args ...interface{}) *Error {
	if err == nil {
		return nil
	}

	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   err,
		Stack:   captureStack(2),
	}
}

// captureStack captures the call stack
func captureStack(skip int) []Frame {
	var frames []Frame

	for i := skip; i < 20; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		fn := runtime.FuncForPC(pc)
		funcName := "unknown"
		if fn != nil {
			funcName = fn.Name()
		}

		frames = append(frames, Frame{
			Function: funcName,
			File:     file,
			Line:     line,
		})
	}

	return frames
}

// StackTrace returns the stack trace as a string
func (e *Error) StackTrace() string {
	var sb strings.Builder

	for _, frame := range e.Stack {
		sb.WriteString(fmt.Sprintf("%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line))
	}

	return sb.String()
}

// GetCode extracts the error code from an error
func GetCode(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}

	// Check wrapped errors
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}

	return Unknown
}

// GetMessage extracts the error message
func GetMessage(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Message
	}
	return err.Error()
}

// GetContext extracts context from an error
func GetContext(err error) map[string]interface{} {
	if e, ok := err.(*Error); ok {
		return e.Context
	}
	return nil
}

// RootCause returns the root cause of an error
func RootCause(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// IsCode checks if an error has a specific code
func IsCode(err error, code Code) bool {
	return GetCode(err) == code
}

// Is is a convenience wrapper for errors.Is
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As is a convenience wrapper for errors.As
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Join combines multiple errors
func Join(errs ...error) error {
	return errors.Join(errs...)
}

// Multi represents multiple errors
type Multi struct {
	Errors []error
}

// Error implements the error interface
func (m *Multi) Error() string {
	if len(m.Errors) == 0 {
		return ""
	}

	if len(m.Errors) == 1 {
		return m.Errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d errors occurred:\n", len(m.Errors)))

	for i, err := range m.Errors {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, err.Error()))
	}

	return sb.String()
}

// Add adds an error to the collection
func (m *Multi) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// HasErrors returns true if there are any errors
func (m *Multi) HasErrors() bool {
	return len(m.Errors) > 0
}

// ToError returns nil if no errors, or the multi error
func (m *Multi) ToError() error {
	if !m.HasErrors() {
		return nil
	}
	return m
}

// NewMulti creates a new multi-error container
func NewMulti() *Multi {
	return &Multi{
		Errors: make([]error, 0),
	}
}

// Collect collects errors from multiple operations
func Collect(funcs ...func() error) error {
	multi := NewMulti()

	for _, f := range funcs {
		if err := f(); err != nil {
			multi.Add(err)
		}
	}

	return multi.ToError()
}

// Retry error helpers

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if e, ok := err.(*Error); ok {
		switch e.Code {
		case Timeout, Unavailable, ResourceExhausted:
			return true
		}
	}
	return false
}

// IsTemporary checks if an error is temporary
func IsTemporary(err error) bool {
	return IsRetryable(err)
}
