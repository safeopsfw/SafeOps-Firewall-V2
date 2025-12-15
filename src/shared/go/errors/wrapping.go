// Package errors provides error wrapping utilities.
package errors

import (
	"fmt"
)

// Wrapper provides fluent error wrapping
type Wrapper struct {
	err     error
	code    Code
	message string
	context map[string]interface{}
}

// Wrap starts wrapping an error
func WrapBuilder(err error) *Wrapper {
	return &Wrapper{
		err:     err,
		context: make(map[string]interface{}),
	}
}

// WithCode sets the error code
func (w *Wrapper) WithCode(code Code) *Wrapper {
	w.code = code
	return w
}

// WithMessage sets the error message
func (w *Wrapper) WithMessage(msg string) *Wrapper {
	w.message = msg
	return w
}

// WithMessagef sets a formatted error message
func (w *Wrapper) WithMessagef(format string, args ...interface{}) *Wrapper {
	w.message = fmt.Sprintf(format, args...)
	return w
}

// WithContext adds context
func (w *Wrapper) WithContext(key string, value interface{}) *Wrapper {
	w.context[key] = value
	return w
}

// Build creates the wrapped error
func (w *Wrapper) Build() *Error {
	if w.err == nil {
		return nil
	}

	code := w.code
	if code == "" {
		code = Internal
	}

	msg := w.message
	if msg == "" {
		msg = w.err.Error()
	}

	e := &Error{
		Code:    code,
		Message: msg,
		Cause:   w.err,
		Context: w.context,
		Stack:   captureStack(2),
	}

	return e
}

// WrapWith wraps an error with code and message in one call
func WrapWith(err error, code Code, msg string) error {
	if err == nil {
		return nil
	}

	return &Error{
		Code:    code,
		Message: msg,
		Cause:   err,
		Stack:   captureStack(2),
	}
}

// WrapInternal wraps an error as internal
func WrapInternal(err error, msg string) error {
	return WrapWith(err, Internal, msg)
}

// WrapNotFound wraps an error as not found
func WrapNotFound(err error, msg string) error {
	return WrapWith(err, NotFound, msg)
}

// WrapInvalidArgument wraps an error as invalid argument
func WrapInvalidArgument(err error, msg string) error {
	return WrapWith(err, InvalidArgument, msg)
}

// WrapPermissionDenied wraps an error as permission denied
func WrapPermissionDenied(err error, msg string) error {
	return WrapWith(err, PermissionDenied, msg)
}

// WrapTimeout wraps an error as timeout
func WrapTimeout(err error, msg string) error {
	return WrapWith(err, Timeout, msg)
}

// WrapUnavailable wraps an error as unavailable
func WrapUnavailable(err error, msg string) error {
	return WrapWith(err, Unavailable, msg)
}

// Cause chain helpers

// Causes returns all causes in the error chain
func Causes(err error) []error {
	var causes []error

	for err != nil {
		causes = append(causes, err)
		err = Unwrap(err)
	}

	return causes
}

// Unwrap unwraps one level of error
func Unwrap(err error) error {
	if e, ok := err.(*Error); ok {
		return e.Cause
	}

	if u, ok := err.(interface{ Unwrap() error }); ok {
		return u.Unwrap()
	}

	return nil
}

// HasCause checks if an error chain contains a specific error
func HasCause(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		err = Unwrap(err)
	}
	return false
}

// FindCause finds a cause matching a predicate
func FindCause(err error, predicate func(error) bool) error {
	for err != nil {
		if predicate(err) {
			return err
		}
		err = Unwrap(err)
	}
	return nil
}

// Transform error helpers

// Transform applies a transformation to an error
func Transform(err error, fn func(*Error) *Error) error {
	if err == nil {
		return nil
	}

	if e, ok := err.(*Error); ok {
		return fn(e)
	}

	// Wrap first if not already an Error
	wrapped := &Error{
		Code:    Unknown,
		Message: err.Error(),
		Cause:   err,
	}

	return fn(wrapped)
}

// Map applies a function to modify the error code
func Map(err error, mapping map[Code]Code) error {
	if err == nil {
		return nil
	}

	code := GetCode(err)
	if newCode, ok := mapping[code]; ok {
		return Transform(err, func(e *Error) *Error {
			e.Code = newCode
			return e
		})
	}

	return err
}

// Ignore returns nil if error matches any of the codes
func Ignore(err error, codes ...Code) error {
	if err == nil {
		return nil
	}

	errCode := GetCode(err)
	for _, code := range codes {
		if errCode == code {
			return nil
		}
	}

	return err
}

// Must panics if error is not nil
func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// MustOK panics if error is not nil
func MustOK(err error) {
	if err != nil {
		panic(err)
	}
}
