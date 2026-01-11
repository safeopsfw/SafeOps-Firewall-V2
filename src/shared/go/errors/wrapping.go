package errors

import (
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// Error Wrapping Utilities
// ============================================================================

// WrapWithCode wraps an error with a code but reuses the original error message.
// This is a shorthand when you don't need a custom message.
//
// Example:
//
//	err := errors.WrapWithCode(sqlErr, errors.ErrDBQueryFailed)
func WrapWithCode(err error, code string) *SafeOpsError {
	if err == nil {
		return nil
	}
	return Wrap(err, code, err.Error())
}

// WrapMultiple combines multiple errors into a single SafeOpsError.
// The first error becomes the Cause, and the remaining errors are added as fields.
// This is useful for batch operations that collect errors.
//
// Example:
//
//	errs := []error{validationErr1, validationErr2, validationErr3}
//	return errors.WrapMultiple(errs, "VALIDATION_FAILED", "Multiple validation errors")
func WrapMultiple(errs []error, code, message string) *SafeOpsError {
	if len(errs) == 0 {
		return nil
	}

	// First error becomes the cause
	wrapped := Wrap(errs[0], code, message)

	// Add remaining errors as fields
	if len(errs) > 1 {
		otherErrs := make([]string, 0, len(errs)-1)
		for i := 1; i < len(errs); i++ {
			if errs[i] != nil {
				otherErrs = append(otherErrs, errs[i].Error())
			}
		}
		if len(otherErrs) > 0 {
			wrapped.WithField("additional_errors", otherErrs)
		}
	}

	return wrapped
}

// ============================================================================
// Error Unwrapping Utilities
// ============================================================================

// UnwrapAll unwraps the entire error chain and returns all errors from
// outermost to innermost.
//
// Example:
//
//	errors := UnwrapAll(err)
//	// Returns: [SafeOpsError("DB_QUERY_FAILED"), pgx.Error("connection refused"), syscall.Error("ECONNREFUSED")]
func UnwrapAll(err error) []error {
	if err == nil {
		return nil
	}

	chain := []error{err}
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			break
		}
		chain = append(chain, unwrapped)
		err = unwrapped
	}

	return chain
}

// RootCause returns the deepest error in the chain (the original cause).
// It unwraps until no more Unwrap() is possible.
//
// Example:
//
//	root := errors.RootCause(err)
//	if syscallErr, ok := root.(*syscall.Errno); ok {
//	    // Handle syscall error
//	}
func RootCause(err error) error {
	if err == nil {
		return nil
	}

	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// ============================================================================
// Error Type Checking
// ============================================================================

// IsSafeOpsError returns true if the error is or contains a SafeOpsError
// anywhere in the error chain. Uses errors.As() to check the chain.
func IsSafeOpsError(err error) bool {
	if err == nil {
		return false
	}
	var se *SafeOpsError
	return errors.As(err, &se)
}

// AsSafeOpsError extracts a SafeOpsError from the error chain.
// Returns (error, true) if found, (nil, false) if not.
//
// Example:
//
//	if se, ok := errors.AsSafeOpsError(err); ok {
//	    log.WithFields(se.ToLogFields()).Error("Error occurred")
//	}
func AsSafeOpsError(err error) (*SafeOpsError, bool) {
	if err == nil {
		return nil, false
	}
	var se *SafeOpsError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// ============================================================================
// Error Code Extraction
// ============================================================================

// CodeOf extracts the error code from a SafeOpsError in the chain.
// Returns (code, true) if a SafeOpsError is found, ("", false) otherwise.
//
// Example:
//
//	if code, ok := errors.CodeOf(err); ok {
//	    metrics.IncrementErrorCounter(code)
//	}
func CodeOf(err error) (string, bool) {
	if se, ok := AsSafeOpsError(err); ok {
		return se.Code, true
	}
	return "", false
}

// IsAnyOf checks if the error matches any of the provided error codes.
//
// Example:
//
//	if errors.IsAnyOf(err, errors.ErrDBTimeout, errors.ErrNetworkTimeout) {
//	    retry()
//	}
func IsAnyOf(err error, codes ...string) bool {
	if err == nil {
		return false
	}

	for _, code := range codes {
		if Is(err, code) {
			return true
		}
	}
	return false
}

// ============================================================================
// Error Conversion Utilities
// ============================================================================

// ToStandard converts a SafeOpsError to a standard Go error.
// This loses structured fields but preserves the error message.
// Use when interfacing with libraries that expect standard errors.
func ToStandard(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(err.Error())
}

// FromStandard converts a standard error to a SafeOpsError.
// It assigns the provided code and captures a stack trace at the conversion point.
//
// Example:
//
//	safeErr := errors.FromStandard(stdErr, errors.ErrInternalFailure)
func FromStandard(err error, code string) *SafeOpsError {
	if err == nil {
		return nil
	}
	return New(code, err.Error())
}

// ============================================================================
// Error Formatting Utilities
// ============================================================================

// Format formats an error with full context including code, message, fields,
// and stack trace. Returns a multi-line output for detailed debugging.
//
// Example output:
//
//	[DB_QUERY_FAILED] Query failed on table users
//	Fields:
//	  query: SELECT * FROM users WHERE id = $1
//	  duration_ms: 150
//	Stack:
//	  main.queryUser (/app/db.go:45)
//	  main.handleRequest (/app/handler.go:23)
func Format(err error) string {
	if err == nil {
		return ""
	}

	se, ok := AsSafeOpsError(err)
	if !ok {
		return err.Error()
	}

	var sb strings.Builder

	// Error message
	sb.WriteString(se.Error())
	sb.WriteString("\n")

	// Fields
	if len(se.Fields) > 0 {
		sb.WriteString("Fields:\n")
		for k, v := range se.Fields {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}

	// Stack trace
	if len(se.Stack) > 0 {
		sb.WriteString("Stack:\n")
		for _, frame := range se.Stack {
			sb.WriteString(fmt.Sprintf("  %s\n", frame))
		}
	}

	// Cause
	if se.Cause != nil {
		sb.WriteString(fmt.Sprintf("Caused by: %v\n", se.Cause))
	}

	return sb.String()
}

// FormatCompact produces a single-line error format with code, message, and key fields.
//
// Example output:
//
//	[DB_QUERY_FAILED] Query failed: connection refused (duration_ms=150, table=users)
func FormatCompact(err error) string {
	if err == nil {
		return ""
	}

	se, ok := AsSafeOpsError(err)
	if !ok {
		return err.Error()
	}

	var sb strings.Builder
	sb.WriteString(se.Error())

	// Add compact fields
	if len(se.Fields) > 0 {
		sb.WriteString(" (")
		first := true
		for k, v := range se.Fields {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s=%v", k, v))
			first = false
		}
		sb.WriteString(")")
	}

	return sb.String()
}

// ============================================================================
// Error Chain Utilities
// ============================================================================

// Chain returns the error chain as formatted strings.
// Each element is the result of calling Error() on each error in the chain.
//
// Example:
//
//	chain := errors.Chain(err)
//	// Returns: ["[DB_QUERY_FAILED] Query failed", "connection refused", "ECONNREFUSED"]
func Chain(err error) []string {
	if err == nil {
		return nil
	}

	chain := UnwrapAll(err)
	result := make([]string, len(chain))
	for i, e := range chain {
		result[i] = e.Error()
	}
	return result
}

// DepthOf returns the number of wrapped errors in the chain.
// A depth of 1 means a single error with no wrapping.
//
// Example:
//
//	depth := errors.DepthOf(err)
//	if depth > 3 {
//	    log.Warn("Deep error chain detected")
//	}
func DepthOf(err error) int {
	if err == nil {
		return 0
	}
	return len(UnwrapAll(err))
}

// ============================================================================
// Additional Context Utilities
// ============================================================================

// WrapWithContext wraps an error with a code and adds multiple context fields.
// This is a convenience function combining Wrap() and WithFields().
//
// Example:
//
//	err := errors.WrapWithContext(sqlErr, "DB_QUERY_FAILED", map[string]interface{}{
//	    "query": sql,
//	    "duration_ms": 150,
//	})
func WrapWithContext(err error, code string, context map[string]interface{}) *SafeOpsError {
	if err == nil {
		return nil
	}
	return Wrap(err, code, err.Error()).WithFields(context)
}

// GetAllDetails aggregates all context fields from the entire error chain.
// Fields from outer errors override fields from inner errors with the same key.
//
// Example:
//
//	details := errors.GetAllDetails(err)
//	// Returns all Fields from all SafeOpsErrors in the chain
func GetAllDetails(err error) map[string]interface{} {
	if err == nil {
		return nil
	}

	details := make(map[string]interface{})
	chain := UnwrapAll(err)

	// Iterate from innermost to outermost so outer fields override inner ones
	for i := len(chain) - 1; i >= 0; i-- {
		if se, ok := chain[i].(*SafeOpsError); ok {
			for k, v := range se.Fields {
				details[k] = v
			}
		}
	}

	return details
}

// FindCause searches the error chain for an error matching the predicate function.
// Returns the first matching error, or nil if none found.
//
// Example:
//
//	dbErr := errors.FindCause(err, func(e error) bool {
//	    _, ok := e.(*pgx.PgError)
//	    return ok
//	})
func FindCause(err error, predicate func(error) bool) error {
	if err == nil {
		return nil
	}

	chain := UnwrapAll(err)
	for _, e := range chain {
		if predicate(e) {
			return e
		}
	}
	return nil
}

// IsRetryable checks if an error is retryable based on its error code.
// Returns true for timeout, unavailable, and resource exhausted errors.
func IsRetryable(err error) bool {
	return IsAnyOf(err,
		ErrNetworkTimeout,
		ErrDBTimeout,
		ErrGRPCTimeout,
		ErrGRPCUnavailable,
		ErrRedisTimeout,
	)
}
