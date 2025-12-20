// Package errors provides comprehensive test suite for the SafeOps error system.
// This file validates error creation, codes, wrapping chains, context fields,
// stack trace capture, and logging integration.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Error Creation Tests
// ============================================================================

func TestNewError(t *testing.T) {
	err := New(ErrDBConnectionFailed, "Could not connect to PostgreSQL")

	if err == nil {
		t.Fatal("New() returned nil")
	}
	if err.Code != ErrDBConnectionFailed {
		t.Errorf("Code = %s, want %s", err.Code, ErrDBConnectionFailed)
	}
	if err.Message != "Could not connect to PostgreSQL" {
		t.Errorf("Message = %s, want 'Could not connect to PostgreSQL'", err.Message)
	}
	if err.Fields == nil {
		t.Error("Fields should be initialized (non-nil)")
	}
	if err.Cause != nil {
		t.Error("Cause should be nil for new error")
	}
}

func TestNewfError(t *testing.T) {
	tableName := "users"
	err := Newf(ErrDBQueryFailed, "Query failed on table %s", tableName)

	if err == nil {
		t.Fatal("Newf() returned nil")
	}
	expected := "Query failed on table users"
	if err.Message != expected {
		t.Errorf("Message = %s, want %s", err.Message, expected)
	}
}

func TestWrapError(t *testing.T) {
	originalErr := stderrors.New("connection refused")
	wrapped := Wrap(originalErr, ErrDBConnectionFailed, "Could not connect to PostgreSQL")

	if wrapped == nil {
		t.Fatal("Wrap() returned nil")
	}
	if wrapped.Cause != originalErr {
		t.Error("Cause should be the original error")
	}
	if wrapped.Code != ErrDBConnectionFailed {
		t.Errorf("Code = %s, want %s", wrapped.Code, ErrDBConnectionFailed)
	}
}

func TestWrapNilError(t *testing.T) {
	wrapped := Wrap(nil, ErrDBConnectionFailed, "message")
	if wrapped != nil {
		t.Error("Wrap(nil, ...) should return nil")
	}
}

func TestWrapfError(t *testing.T) {
	originalErr := stderrors.New("query timeout")
	wrapped := Wrapf(originalErr, ErrDBQueryFailed, "Query failed on table %s", "users")

	if wrapped == nil {
		t.Fatal("Wrapf() returned nil")
	}
	expected := "Query failed on table users"
	if wrapped.Message != expected {
		t.Errorf("Message = %s, want %s", wrapped.Message, expected)
	}
}

func TestStackTraceCaptured(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test error")

	if len(err.Stack) == 0 {
		t.Error("Stack trace should be captured")
	}

	// Verify stack contains file:line information
	found := false
	for _, frame := range err.Stack {
		if strings.Contains(frame, "errors_test.go") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Stack trace should contain reference to test file")
	}
}

func TestTimestampRecorded(t *testing.T) {
	before := time.Now()
	err := New(ErrDBConnectionFailed, "test error")
	after := time.Now()

	if err.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if err.Timestamp.Before(before) || err.Timestamp.After(after) {
		t.Error("Timestamp should be between before and after creation time")
	}
}

// ============================================================================
// Error Code Tests
// ============================================================================

func TestErrorCodeConstants(t *testing.T) {
	// Verify all error code categories have constants
	codes := []string{
		// Config
		ErrConfigLoadFailed, ErrConfigInvalid, ErrConfigMissingKey, ErrConfigTypeMismatch,
		// Database
		ErrDBConnectionFailed, ErrDBQueryFailed, ErrDBTransactionFailed, ErrDBTimeout,
		ErrDBConstraintViolation, ErrDBRecordNotFound,
		// Redis
		ErrRedisConnectionFailed, ErrRedisCommandFailed, ErrRedisTimeout, ErrRedisPubSubFailed,
		// gRPC
		ErrGRPCCallFailed, ErrGRPCTimeout, ErrGRPCUnavailable, ErrGRPCDeadlineExceeded,
		ErrGRPCPermissionDenied,
		// Validation
		ErrInvalidInput, ErrMissingParameter, ErrInvalidFormat, ErrOutOfRange,
		// Network
		ErrNetworkTimeout, ErrNetworkUnreachable, ErrNetworkDNSFailed,
		// File
		ErrFileNotFound, ErrFilePermissionDenied, ErrFileReadFailed, ErrFileWriteFailed,
		// Internal
		ErrInternalFailure, ErrNotImplemented, ErrUnknown,
	}

	for _, code := range codes {
		if code == "" {
			t.Error("Error code constant should not be empty")
		}
		// Verify uppercase format
		if code != strings.ToUpper(code) {
			t.Errorf("Error code %s should be uppercase", code)
		}
	}
}

func TestGetCode(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	code := GetCode(err)

	if code != ErrDBConnectionFailed {
		t.Errorf("GetCode() = %s, want %s", code, ErrDBConnectionFailed)
	}

	// Test with nil
	if GetCode(nil) != "" {
		t.Error("GetCode(nil) should return empty string")
	}

	// Test with standard error
	stdErr := stderrors.New("standard error")
	if GetCode(stdErr) != "" {
		t.Error("GetCode(standardError) should return empty string")
	}
}

func TestHasCode(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	if !HasCode(err) {
		t.Error("HasCode() should return true for SafeOpsError with code")
	}

	stdErr := stderrors.New("standard error")
	if HasCode(stdErr) {
		t.Error("HasCode() should return false for standard error")
	}

	if HasCode(nil) {
		t.Error("HasCode(nil) should return false")
	}
}

func TestIsCode(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")

	if !Is(err, ErrDBConnectionFailed) {
		t.Error("Is() should return true for matching code")
	}
	if Is(err, ErrDBQueryFailed) {
		t.Error("Is() should return false for non-matching code")
	}
	if Is(nil, ErrDBConnectionFailed) {
		t.Error("Is(nil, code) should return false")
	}
}

func TestCodeCategories(t *testing.T) {
	tests := []struct {
		code     string
		isConfig bool
		isDB     bool
		isRedis  bool
		isGRPC   bool
	}{
		{ErrConfigLoadFailed, true, false, false, false},
		{ErrDBConnectionFailed, false, true, false, false},
		{ErrRedisTimeout, false, false, true, false},
		{ErrGRPCCallFailed, false, false, false, true},
	}

	for _, tt := range tests {
		if IsConfigError(tt.code) != tt.isConfig {
			t.Errorf("IsConfigError(%s) = %v, want %v", tt.code, !tt.isConfig, tt.isConfig)
		}
		if IsDBError(tt.code) != tt.isDB {
			t.Errorf("IsDBError(%s) = %v, want %v", tt.code, !tt.isDB, tt.isDB)
		}
		if IsRedisError(tt.code) != tt.isRedis {
			t.Errorf("IsRedisError(%s) = %v, want %v", tt.code, !tt.isRedis, tt.isRedis)
		}
		if IsGRPCError(tt.code) != tt.isGRPC {
			t.Errorf("IsGRPCError(%s) = %v, want %v", tt.code, !tt.isGRPC, tt.isGRPC)
		}
	}
}

func TestCategoryOfCode(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{ErrConfigLoadFailed, "Configuration"},
		{ErrDBConnectionFailed, "Database"},
		{ErrRedisTimeout, "Redis"},
		{ErrGRPCCallFailed, "gRPC"},
		{ErrInvalidInput, "Validation"},
		{ErrNetworkTimeout, "Network"},
		{ErrFileNotFound, "FileSystem"},
		{ErrInternalFailure, "Internal"},
		{"UNKNOWN_CODE", "Unknown"},
	}

	for _, tt := range tests {
		result := CategoryOfCode(tt.code)
		if result != tt.expected {
			t.Errorf("CategoryOfCode(%s) = %s, want %s", tt.code, result, tt.expected)
		}
	}
}

// ============================================================================
// Error Wrapping Chain Tests
// ============================================================================

func TestUnwrapChain(t *testing.T) {
	root := stderrors.New("root cause")
	wrapped := Wrap(root, ErrDBConnectionFailed, "wrapper")

	unwrapped := wrapped.Unwrap()
	if unwrapped != root {
		t.Error("Unwrap() should return the cause")
	}
}

func TestErrorChainTraversal(t *testing.T) {
	root := stderrors.New("root cause")
	wrapped1 := Wrap(root, ErrDBConnectionFailed, "layer 1")
	wrapped2 := Wrap(wrapped1, ErrDBQueryFailed, "layer 2")

	chain := UnwrapAll(wrapped2)
	if len(chain) != 3 {
		t.Errorf("UnwrapAll() returned %d errors, want 3", len(chain))
	}

	// First should be outermost
	if chain[0] != wrapped2 {
		t.Error("First in chain should be outermost error")
	}
	// Last should be root
	if chain[2] != root {
		t.Error("Last in chain should be root cause")
	}
}

func TestRootCause(t *testing.T) {
	root := stderrors.New("root cause")
	wrapped1 := Wrap(root, ErrDBConnectionFailed, "layer 1")
	wrapped2 := Wrap(wrapped1, ErrDBQueryFailed, "layer 2")

	foundRoot := RootCause(wrapped2)
	if foundRoot != root {
		t.Error("RootCause() should return deepest error")
	}

	// Test nil
	if RootCause(nil) != nil {
		t.Error("RootCause(nil) should return nil")
	}
}

func TestIsAnyOf(t *testing.T) {
	err := New(ErrDBTimeout, "timeout")

	if !IsAnyOf(err, ErrNetworkTimeout, ErrDBTimeout, ErrRedisTimeout) {
		t.Error("IsAnyOf() should return true when code matches")
	}
	if IsAnyOf(err, ErrDBConnectionFailed, ErrDBQueryFailed) {
		t.Error("IsAnyOf() should return false when code doesn't match")
	}
	if IsAnyOf(nil, ErrDBTimeout) {
		t.Error("IsAnyOf(nil) should return false")
	}
}

func TestDepthOf(t *testing.T) {
	root := stderrors.New("root")
	wrapped1 := Wrap(root, ErrDBConnectionFailed, "1")
	wrapped2 := Wrap(wrapped1, ErrDBQueryFailed, "2")

	depth := DepthOf(wrapped2)
	if depth != 3 {
		t.Errorf("DepthOf() = %d, want 3", depth)
	}

	if DepthOf(nil) != 0 {
		t.Error("DepthOf(nil) should be 0")
	}
}

// ============================================================================
// Context Fields Tests
// ============================================================================

func TestWithField(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed")
	err.WithField("table", "users")

	if err.Fields["table"] != "users" {
		t.Errorf("Field 'table' = %v, want 'users'", err.Fields["table"])
	}
}

func TestWithFields(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed")
	err.WithFields(map[string]interface{}{
		"query":       "SELECT * FROM users",
		"duration_ms": 150,
	})

	if err.Fields["query"] != "SELECT * FROM users" {
		t.Error("Field 'query' not set correctly")
	}
	if err.Fields["duration_ms"] != 150 {
		t.Error("Field 'duration_ms' not set correctly")
	}
}

func TestFieldChaining(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed").
		WithField("table", "users").
		WithField("action", "select").
		WithField("count", 10)

	if len(err.Fields) != 3 {
		t.Errorf("Expected 3 fields, got %d", len(err.Fields))
	}
}

func TestFieldInheritance(t *testing.T) {
	original := New(ErrDBConnectionFailed, "connection failed").
		WithField("host", "localhost")

	wrapped := Wrap(original, ErrDBQueryFailed, "query failed").
		WithField("table", "users")

	// Wrapped error should have its own field
	if wrapped.Fields["table"] != "users" {
		t.Error("Wrapped error should have 'table' field")
	}

	// Original error's field still accessible via GetAllDetails
	details := GetAllDetails(wrapped)
	if details["host"] != "localhost" {
		t.Error("GetAllDetails should include fields from wrapped errors")
	}
}

func TestNilErrorWithField(t *testing.T) {
	var err *SafeOpsError
	result := err.WithField("key", "value")
	if result != nil {
		t.Error("nil.WithField() should return nil")
	}
}

// ============================================================================
// Logging Integration Tests
// ============================================================================

func TestToLogFields(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed").
		WithField("table", "users").
		WithField("duration_ms", 150)

	fields := err.ToLogFields()

	if fields["error_code"] != ErrDBQueryFailed {
		t.Errorf("error_code = %v, want %s", fields["error_code"], ErrDBQueryFailed)
	}
	if fields["error_message"] != "query failed" {
		t.Errorf("error_message = %v, want 'query failed'", fields["error_message"])
	}
	if fields["table"] != "users" {
		t.Error("Custom field 'table' should be included")
	}
	if fields["duration_ms"] != 150 {
		t.Error("Custom field 'duration_ms' should be included")
	}
	if fields["error_stack"] == nil {
		t.Error("error_stack should be included")
	}
}

func TestToLogFieldsWithCause(t *testing.T) {
	root := stderrors.New("root cause")
	wrapped := Wrap(root, ErrDBConnectionFailed, "connection failed")

	fields := wrapped.ToLogFields()

	if fields["error_cause"] != "root cause" {
		t.Errorf("error_cause = %v, want 'root cause'", fields["error_cause"])
	}
}

func TestToLogFieldsNil(t *testing.T) {
	var err *SafeOpsError
	fields := err.ToLogFields()
	if len(fields) != 0 {
		t.Error("nil.ToLogFields() should return empty map")
	}
}

func TestStackTraceFormatting(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")

	formatted := err.FormatStack()
	if !strings.Contains(formatted, "goroutine") {
		t.Error("FormatStack should include goroutine header")
	}
	if formatted == "" && len(err.Stack) > 0 {
		t.Error("FormatStack should not be empty when stack exists")
	}
}

// ============================================================================
// Error Interface Tests
// ============================================================================

func TestErrorMethod(t *testing.T) {
	err := New(ErrDBConnectionFailed, "Could not connect")

	errorStr := err.Error()
	expected := "[DB_CONNECTION_FAILED] Could not connect"
	if errorStr != expected {
		t.Errorf("Error() = %s, want %s", errorStr, expected)
	}
}

func TestErrorMethodEmptyCode(t *testing.T) {
	err := New("", "message only")
	if err.Error() != "message only" {
		t.Errorf("Error() with empty code = %s, want 'message only'", err.Error())
	}
}

func TestNilErrorMethod(t *testing.T) {
	var err *SafeOpsError
	if err.Error() != "" {
		t.Error("nil.Error() should return empty string")
	}
}

func TestIsMethod(t *testing.T) {
	err1 := New(ErrDBConnectionFailed, "error 1")
	err2 := New(ErrDBConnectionFailed, "error 2")
	err3 := New(ErrDBQueryFailed, "error 3")

	if !err1.Is(err2) {
		t.Error("Errors with same code should be equal via Is()")
	}
	if err1.Is(err3) {
		t.Error("Errors with different codes should not be equal via Is()")
	}
}

// ============================================================================
// Type Checking Tests
// ============================================================================

func TestIsSafeOpsError(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	if !IsSafeOpsError(err) {
		t.Error("IsSafeOpsError should return true for SafeOpsError")
	}

	stdErr := stderrors.New("standard")
	if IsSafeOpsError(stdErr) {
		t.Error("IsSafeOpsError should return false for standard error")
	}

	if IsSafeOpsError(nil) {
		t.Error("IsSafeOpsError(nil) should return false")
	}
}

func TestAsSafeOpsError(t *testing.T) {
	original := New(ErrDBConnectionFailed, "test")
	wrapped := fmt.Errorf("wrapped: %w", original)

	se, ok := AsSafeOpsError(wrapped)
	if !ok {
		t.Error("AsSafeOpsError should find SafeOpsError in chain")
	}
	if se.Code != ErrDBConnectionFailed {
		t.Error("AsSafeOpsError should return correct error")
	}

	stdErr := stderrors.New("standard")
	_, ok = AsSafeOpsError(stdErr)
	if ok {
		t.Error("AsSafeOpsError should return false for standard error")
	}
}

// ============================================================================
// Conversion Tests
// ============================================================================

func TestToStandard(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test error")
	stdErr := ToStandard(err)

	if stdErr == nil {
		t.Error("ToStandard should not return nil")
	}
	if stdErr.Error() != err.Error() {
		t.Error("ToStandard should preserve error message")
	}

	if ToStandard(nil) != nil {
		t.Error("ToStandard(nil) should return nil")
	}
}

func TestFromStandard(t *testing.T) {
	stdErr := stderrors.New("standard error message")
	se := FromStandard(stdErr, ErrInternalFailure)

	if se == nil {
		t.Error("FromStandard should not return nil")
	}
	if se.Code != ErrInternalFailure {
		t.Errorf("Code = %s, want %s", se.Code, ErrInternalFailure)
	}
	if se.Message != "standard error message" {
		t.Error("Message should be preserved")
	}

	if FromStandard(nil, ErrInternalFailure) != nil {
		t.Error("FromStandard(nil) should return nil")
	}
}

// ============================================================================
// Formatting Tests
// ============================================================================

func TestFormat(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed").
		WithField("table", "users")

	formatted := Format(err)

	if !strings.Contains(formatted, "[DB_QUERY_FAILED]") {
		t.Error("Format should include error code")
	}
	if !strings.Contains(formatted, "query failed") {
		t.Error("Format should include message")
	}
	if !strings.Contains(formatted, "Fields:") {
		t.Error("Format should include fields section")
	}
	if !strings.Contains(formatted, "table") {
		t.Error("Format should include field names")
	}
}

func TestFormatCompact(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed").
		WithField("table", "users")

	formatted := FormatCompact(err)

	if !strings.Contains(formatted, "[DB_QUERY_FAILED]") {
		t.Error("FormatCompact should include error code")
	}
	if !strings.Contains(formatted, "table=users") {
		t.Error("FormatCompact should include compact fields")
	}
}

func TestFormatStandardError(t *testing.T) {
	stdErr := stderrors.New("standard error")

	formatted := Format(stdErr)
	if formatted != "standard error" {
		t.Errorf("Format(stdError) = %s, want 'standard error'", formatted)
	}

	compact := FormatCompact(stdErr)
	if compact != "standard error" {
		t.Errorf("FormatCompact(stdError) = %s, want 'standard error'", compact)
	}
}

// ============================================================================
// Additional Wrapping Utilities Tests
// ============================================================================

func TestWrapWithCode(t *testing.T) {
	original := stderrors.New("original message")
	wrapped := WrapWithCode(original, ErrDBQueryFailed)

	if wrapped.Code != ErrDBQueryFailed {
		t.Errorf("Code = %s, want %s", wrapped.Code, ErrDBQueryFailed)
	}
	if wrapped.Message != "original message" {
		t.Error("WrapWithCode should reuse original error message")
	}
}

func TestWrapMultiple(t *testing.T) {
	errs := []error{
		stderrors.New("error 1"),
		stderrors.New("error 2"),
		stderrors.New("error 3"),
	}

	wrapped := WrapMultiple(errs, ErrInternalFailure, "Multiple errors")

	if wrapped.Cause != errs[0] {
		t.Error("First error should be the cause")
	}
	if wrapped.Fields["additional_errors"] == nil {
		t.Error("Additional errors should be in fields")
	}

	additionalErrs := wrapped.Fields["additional_errors"].([]string)
	if len(additionalErrs) != 2 {
		t.Errorf("Expected 2 additional errors, got %d", len(additionalErrs))
	}
}

func TestWrapMultipleEmpty(t *testing.T) {
	wrapped := WrapMultiple([]error{}, ErrInternalFailure, "message")
	if wrapped != nil {
		t.Error("WrapMultiple([]) should return nil")
	}
}

func TestWrapWithContext(t *testing.T) {
	original := stderrors.New("connection refused")
	wrapped := WrapWithContext(original, ErrDBConnectionFailed, map[string]interface{}{
		"host": "localhost",
		"port": 5432,
	})

	if wrapped.Fields["host"] != "localhost" {
		t.Error("Context field 'host' not set")
	}
	if wrapped.Fields["port"] != 5432 {
		t.Error("Context field 'port' not set")
	}
}

// ============================================================================
// IsRetryable Tests
// ============================================================================

func TestIsRetryable(t *testing.T) {
	retryableErrors := []string{
		ErrNetworkTimeout, ErrDBTimeout, ErrGRPCTimeout,
		ErrGRPCUnavailable, ErrRedisTimeout,
	}

	for _, code := range retryableErrors {
		err := New(code, "test")
		if !IsRetryable(err) {
			t.Errorf("IsRetryable(%s) should return true", code)
		}
	}

	nonRetryable := New(ErrDBRecordNotFound, "not found")
	if IsRetryable(nonRetryable) {
		t.Error("IsRetryable(DB_RECORD_NOT_FOUND) should return false")
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestDatabaseErrorFlow(t *testing.T) {
	// Simulate database error flow
	pgError := stderrors.New("connection refused: localhost:5432")

	// Layer 1: Connection layer
	connErr := Wrap(pgError, ErrDBConnectionFailed, "could not connect").
		WithField("host", "localhost").
		WithField("port", 5432)

	// Layer 2: Query layer
	queryErr := Wrap(connErr, ErrDBQueryFailed, "query failed").
		WithField("query", "SELECT * FROM users")

	// Verify chain
	if DepthOf(queryErr) != 3 {
		t.Errorf("DepthOf = %d, want 3", DepthOf(queryErr))
	}

	// Verify root cause
	root := RootCause(queryErr)
	if root != pgError {
		t.Error("RootCause should be original pgError")
	}

	// Verify code checking
	if !Is(queryErr, ErrDBQueryFailed) {
		t.Error("Should have DB_QUERY_FAILED code")
	}

	// Verify all details aggregated
	details := GetAllDetails(queryErr)
	if details["host"] != "localhost" {
		t.Error("Details should include 'host' from inner error")
	}
	if details["query"] != "SELECT * FROM users" {
		t.Error("Details should include 'query' from outer error")
	}
}

func TestMultiLayerWrapping(t *testing.T) {
	// Create 5-layer error chain
	root := stderrors.New("syscall error")
	layer1 := Wrap(root, ErrNetworkUnreachable, "network error")
	layer2 := Wrap(layer1, ErrDBConnectionFailed, "db connection error")
	layer3 := Wrap(layer2, ErrDBQueryFailed, "query error")
	layer4 := Wrap(layer3, ErrInternalFailure, "service error")

	// Verify depth
	if DepthOf(layer4) != 5 {
		t.Errorf("DepthOf = %d, want 5", DepthOf(layer4))
	}

	// Verify chain strings
	chainStrings := Chain(layer4)
	if len(chainStrings) != 5 {
		t.Errorf("Chain() returned %d strings, want 5", len(chainStrings))
	}

	// Verify IsAnyOf works through chain
	if !IsAnyOf(layer4, ErrNetworkUnreachable) {
		t.Error("IsAnyOf should find code in chain")
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkNewError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrDBConnectionFailed, "test error")
	}
}

func BenchmarkWrapError(b *testing.B) {
	original := stderrors.New("original error")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Wrap(original, ErrDBConnectionFailed, "wrapped error")
	}
}

func BenchmarkStackTraceCapture(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = captureStack()
	}
}

func BenchmarkGetCode(b *testing.B) {
	err := New(ErrDBConnectionFailed, "test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetCode(err)
	}
}

func BenchmarkIsAnyOf(b *testing.B) {
	err := New(ErrDBTimeout, "test")
	codes := []string{ErrNetworkTimeout, ErrRedisTimeout, ErrGRPCTimeout, ErrDBTimeout}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsAnyOf(err, codes...)
	}
}

func BenchmarkToLogFields(b *testing.B) {
	err := New(ErrDBQueryFailed, "test").
		WithField("table", "users").
		WithField("duration_ms", 150)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.ToLogFields()
	}
}

func BenchmarkUnwrapAll(b *testing.B) {
	root := stderrors.New("root")
	layer1 := Wrap(root, ErrDBConnectionFailed, "1")
	layer2 := Wrap(layer1, ErrDBQueryFailed, "2")
	layer3 := Wrap(layer2, ErrInternalFailure, "3")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = UnwrapAll(layer3)
	}
}

// ============================================================================
// Additional Coverage Tests
// ============================================================================

func TestCodeOf(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	code, ok := CodeOf(err)
	if !ok {
		t.Error("CodeOf should return true for SafeOpsError")
	}
	if code != ErrDBConnectionFailed {
		t.Errorf("CodeOf = %s, want %s", code, ErrDBConnectionFailed)
	}

	// Test with standard error
	stdErr := stderrors.New("standard")
	_, ok = CodeOf(stdErr)
	if ok {
		t.Error("CodeOf should return false for standard error")
	}

	// Test with nil
	_, ok = CodeOf(nil)
	if ok {
		t.Error("CodeOf(nil) should return false")
	}

	// Test with wrapped SafeOpsError
	wrapped := fmt.Errorf("wrapped: %w", err)
	code, ok = CodeOf(wrapped)
	if !ok || code != ErrDBConnectionFailed {
		t.Error("CodeOf should find code in wrapped error")
	}
}

func TestWithCause(t *testing.T) {
	err := New(ErrDBQueryFailed, "query failed")
	cause := stderrors.New("original cause")

	result := err.WithCause(cause)

	if result != err {
		t.Error("WithCause should return the same error instance")
	}
	if err.Cause != cause {
		t.Error("WithCause should set the Cause field")
	}
}

func TestNilWithCause(t *testing.T) {
	var err *SafeOpsError
	result := err.WithCause(stderrors.New("cause"))
	if result != nil {
		t.Error("nil.WithCause() should return nil")
	}
}

func TestStackTraceMethod(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	stack := err.StackTrace()

	if len(stack) == 0 {
		t.Error("StackTrace() should return non-empty slice")
	}
	if stack[0] == "" {
		t.Error("StackTrace entries should not be empty")
	}
}

func TestNilStackTrace(t *testing.T) {
	var err *SafeOpsError
	stack := err.StackTrace()
	if len(stack) != 0 {
		t.Error("nil.StackTrace() should return empty slice")
	}
}

func TestNilFormatStack(t *testing.T) {
	var err *SafeOpsError
	formatted := err.FormatStack()
	if formatted != "" {
		t.Error("nil.FormatStack() should return empty string")
	}
}

func TestServiceSpecificErrorChecks(t *testing.T) {
	tests := []struct {
		code      string
		checkFunc func(string) bool
		shouldBe  bool
	}{
		{ErrDNSQueryFailed, IsDNSError, true},
		{ErrDNSInvalidDomain, IsDNSError, true},
		{ErrDNSBlocked, IsDNSError, true},
		{ErrDBConnectionFailed, IsDNSError, false},

		{ErrDHCPNoAvailableIP, IsDHCPError, true},
		{ErrDHCPLeaseConflict, IsDHCPError, true},
		{ErrDBConnectionFailed, IsDHCPError, false},

		{ErrFirewallRuleInvalid, IsFirewallError, true},
		{ErrFirewallRuleConflict, IsFirewallError, true},
		{ErrDBConnectionFailed, IsFirewallError, false},

		{ErrInvalidInput, IsValidationError, true},
		{ErrMissingParameter, IsValidationError, true},
		{ErrInvalidFormat, IsValidationError, true},
		{ErrOutOfRange, IsValidationError, true},
		{ErrDBConnectionFailed, IsValidationError, false},

		{ErrFileNotFound, IsFileSystemError, true},
		{ErrFilePermissionDenied, IsFileSystemError, true},
		{ErrFileReadFailed, IsFileSystemError, true},
		{ErrFileWriteFailed, IsFileSystemError, true},
		{ErrDBConnectionFailed, IsFileSystemError, false},

		{ErrInternalFailure, IsInternalError, true},
		{ErrNotImplemented, IsInternalError, true},
		{ErrUnknown, IsInternalError, true},
		{ErrDBConnectionFailed, IsInternalError, false},

		{ErrNetworkTimeout, IsNetworkError, true},
		{ErrNetworkUnreachable, IsNetworkError, true},
		{ErrNetworkDNSFailed, IsNetworkError, true},
		{ErrDBConnectionFailed, IsNetworkError, false},
	}

	for _, tt := range tests {
		result := tt.checkFunc(tt.code)
		if result != tt.shouldBe {
			t.Errorf("check(%s) = %v, want %v", tt.code, result, tt.shouldBe)
		}
	}
}

func TestFindCause(t *testing.T) {
	root := New(ErrDBConnectionFailed, "connection failed")
	layer1 := Wrap(root, ErrDBQueryFailed, "query failed")
	layer2 := Wrap(layer1, ErrInternalFailure, "internal error")

	found := FindCause(layer2, func(e error) bool {
		if se, ok := e.(*SafeOpsError); ok {
			return se.Code == ErrDBConnectionFailed
		}
		return false
	})

	if found == nil {
		t.Error("FindCause should find matching error")
	}
	if se, ok := found.(*SafeOpsError); !ok || se.Code != ErrDBConnectionFailed {
		t.Error("FindCause returned wrong error")
	}

	// Test not found
	notFound := FindCause(layer2, func(e error) bool {
		return false
	})
	if notFound != nil {
		t.Error("FindCause should return nil when not found")
	}

	// Test nil
	if FindCause(nil, func(e error) bool { return true }) != nil {
		t.Error("FindCause(nil) should return nil")
	}
}

func TestChainWithSingleError(t *testing.T) {
	err := New(ErrDBConnectionFailed, "single error")
	chain := Chain(err)

	if len(chain) != 1 {
		t.Errorf("Chain for single error should have 1 element, got %d", len(chain))
	}
}

func TestWrapWithContextNil(t *testing.T) {
	result := WrapWithContext(nil, ErrDBConnectionFailed, map[string]interface{}{"key": "value"})
	if result != nil {
		t.Error("WrapWithContext(nil, ...) should return nil")
	}
}

func TestGetAllDetailsWithNilFields(t *testing.T) {
	err := New(ErrDBConnectionFailed, "test")
	err.Fields = nil

	details := GetAllDetails(err)
	if details == nil {
		t.Error("GetAllDetails should return non-nil even with nil Fields")
	}
}

func TestWrapfNil(t *testing.T) {
	result := Wrapf(nil, ErrDBConnectionFailed, "message")
	if result != nil {
		t.Error("Wrapf(nil, ...) should return nil")
	}
}

func TestNilWithFields(t *testing.T) {
	var err *SafeOpsError
	result := err.WithFields(map[string]interface{}{"key": "value"})
	if result != nil {
		t.Error("nil.WithFields() should return nil")
	}
}

func TestIsWithStdErrorsWrapping(t *testing.T) {
	safeErr := New(ErrDBConnectionFailed, "connection failed")
	wrapped := fmt.Errorf("layer 1: %w", safeErr)
	wrapped2 := fmt.Errorf("layer 2: %w", wrapped)

	if !Is(wrapped2, ErrDBConnectionFailed) {
		t.Error("Is should find code through fmt.Errorf wrapping")
	}
}

func TestNilIsMethod(t *testing.T) {
	var err *SafeOpsError
	result := err.Is(New(ErrDBConnectionFailed, "test"))
	if result {
		t.Error("nil.Is() should return false")
	}
}
