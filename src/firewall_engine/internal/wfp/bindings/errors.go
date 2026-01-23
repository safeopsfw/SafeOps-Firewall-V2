// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// ============================================================================
// HRESULT Error Codes
// ============================================================================
// Windows APIs return HRESULT values to indicate success or failure.
// HRESULT is a 32-bit value with the following format:
//   Bits 31-16: Severity and facility code
//   Bits 15-0:  Error code

// HRESULT is a Windows error code type.
type HRESULT uint32

// Common HRESULT values
const (
	// S_OK - Success
	S_OK HRESULT = 0x00000000

	// S_FALSE - Success but different meaning
	S_FALSE HRESULT = 0x00000001

	// E_NOTIMPL - Not implemented
	E_NOTIMPL HRESULT = 0x80004001

	// E_NOINTERFACE - No such interface
	E_NOINTERFACE HRESULT = 0x80004002

	// E_POINTER - Invalid pointer
	E_POINTER HRESULT = 0x80004003

	// E_ABORT - Operation aborted
	E_ABORT HRESULT = 0x80004004

	// E_FAIL - Unspecified failure
	E_FAIL HRESULT = 0x80004005

	// E_UNEXPECTED - Unexpected failure
	E_UNEXPECTED HRESULT = 0x8000FFFF

	// E_ACCESSDENIED - Access denied (need admin rights)
	E_ACCESSDENIED HRESULT = 0x80070005

	// E_HANDLE - Invalid handle
	E_HANDLE HRESULT = 0x80070006

	// E_OUTOFMEMORY - Out of memory
	E_OUTOFMEMORY HRESULT = 0x8007000E

	// E_INVALIDARG - Invalid argument
	E_INVALIDARG HRESULT = 0x80070057
)

// WFP-specific error codes (FWP_E_*)
const (
	// FWP_E_CALLOUT_NOT_FOUND - Callout not found
	FWP_E_CALLOUT_NOT_FOUND HRESULT = 0x80320001

	// FWP_E_CONDITION_NOT_FOUND - Condition not found
	FWP_E_CONDITION_NOT_FOUND HRESULT = 0x80320002

	// FWP_E_FILTER_NOT_FOUND - Filter not found
	FWP_E_FILTER_NOT_FOUND HRESULT = 0x80320003

	// FWP_E_LAYER_NOT_FOUND - Layer not found
	FWP_E_LAYER_NOT_FOUND HRESULT = 0x80320004

	// FWP_E_PROVIDER_NOT_FOUND - Provider not found
	FWP_E_PROVIDER_NOT_FOUND HRESULT = 0x80320005

	// FWP_E_PROVIDER_CONTEXT_NOT_FOUND - Provider context not found
	FWP_E_PROVIDER_CONTEXT_NOT_FOUND HRESULT = 0x80320006

	// FWP_E_SUBLAYER_NOT_FOUND - Sublayer not found
	FWP_E_SUBLAYER_NOT_FOUND HRESULT = 0x80320007

	// FWP_E_NOT_FOUND - Generic not found
	FWP_E_NOT_FOUND HRESULT = 0x80320008

	// FWP_E_ALREADY_EXISTS - Object already exists
	FWP_E_ALREADY_EXISTS HRESULT = 0x80320009

	// FWP_E_IN_USE - Object in use, cannot be deleted
	FWP_E_IN_USE HRESULT = 0x8032000A

	// FWP_E_DYNAMIC_SESSION_IN_PROGRESS - Dynamic session in progress
	FWP_E_DYNAMIC_SESSION_IN_PROGRESS HRESULT = 0x8032000B

	// FWP_E_WRONG_SESSION - Wrong session handle
	FWP_E_WRONG_SESSION HRESULT = 0x8032000C

	// FWP_E_NO_TXN_IN_PROGRESS - No transaction in progress
	FWP_E_NO_TXN_IN_PROGRESS HRESULT = 0x8032000D

	// FWP_E_TXN_IN_PROGRESS - Transaction already in progress
	FWP_E_TXN_IN_PROGRESS HRESULT = 0x8032000E

	// FWP_E_TXN_ABORTED - Transaction was aborted
	FWP_E_TXN_ABORTED HRESULT = 0x8032000F

	// FWP_E_SESSION_ABORTED - Session was aborted
	FWP_E_SESSION_ABORTED HRESULT = 0x80320010

	// FWP_E_INCOMPATIBLE_TXN - Incompatible transaction
	FWP_E_INCOMPATIBLE_TXN HRESULT = 0x80320011

	// FWP_E_TIMEOUT - Operation timed out
	FWP_E_TIMEOUT HRESULT = 0x80320012

	// FWP_E_NET_EVENTS_DISABLED - Network events disabled
	FWP_E_NET_EVENTS_DISABLED HRESULT = 0x80320013

	// FWP_E_INCOMPATIBLE_LAYER - Incompatible layer
	FWP_E_INCOMPATIBLE_LAYER HRESULT = 0x80320014

	// FWP_E_KM_CLIENTS_ONLY - Kernel-mode clients only
	FWP_E_KM_CLIENTS_ONLY HRESULT = 0x80320015

	// FWP_E_LIFETIME_MISMATCH - Lifetime mismatch
	FWP_E_LIFETIME_MISMATCH HRESULT = 0x80320016

	// FWP_E_BUILTIN_OBJECT - Cannot modify built-in object
	FWP_E_BUILTIN_OBJECT HRESULT = 0x80320017

	// FWP_E_TOO_MANY_CALLOUTS - Too many callouts
	FWP_E_TOO_MANY_CALLOUTS HRESULT = 0x80320018

	// FWP_E_NOTIFICATION_DROPPED - Notification dropped
	FWP_E_NOTIFICATION_DROPPED HRESULT = 0x80320019

	// FWP_E_TRAFFIC_MISMATCH - Traffic mismatch
	FWP_E_TRAFFIC_MISMATCH HRESULT = 0x8032001A

	// FWP_E_INCOMPATIBLE_SA_STATE - Incompatible SA state
	FWP_E_INCOMPATIBLE_SA_STATE HRESULT = 0x8032001B

	// FWP_E_NULL_POINTER - Null pointer
	FWP_E_NULL_POINTER HRESULT = 0x8032001C

	// FWP_E_INVALID_ENUMERATOR - Invalid enumerator
	FWP_E_INVALID_ENUMERATOR HRESULT = 0x8032001D

	// FWP_E_INVALID_FLAGS - Invalid flags
	FWP_E_INVALID_FLAGS HRESULT = 0x8032001E

	// FWP_E_INVALID_NET_MASK - Invalid network mask
	FWP_E_INVALID_NET_MASK HRESULT = 0x8032001F

	// FWP_E_INVALID_RANGE - Invalid range
	FWP_E_INVALID_RANGE HRESULT = 0x80320020

	// FWP_E_INVALID_INTERVAL - Invalid interval
	FWP_E_INVALID_INTERVAL HRESULT = 0x80320021

	// FWP_E_ZERO_LENGTH_ARRAY - Zero-length array
	FWP_E_ZERO_LENGTH_ARRAY HRESULT = 0x80320022

	// FWP_E_NULL_DISPLAY_NAME - Null display name
	FWP_E_NULL_DISPLAY_NAME HRESULT = 0x80320023

	// FWP_E_INVALID_ACTION_TYPE - Invalid action type
	FWP_E_INVALID_ACTION_TYPE HRESULT = 0x80320024

	// FWP_E_INVALID_WEIGHT - Invalid weight
	FWP_E_INVALID_WEIGHT HRESULT = 0x80320025
)

// ============================================================================
// WFPError - Custom error type for WFP operations
// ============================================================================

// WFPError wraps HRESULT with additional context.
type WFPError struct {
	HRESULT   HRESULT
	Operation string
	Message   string
}

// Error implements the error interface.
func (e *WFPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s (HRESULT: 0x%08X)", e.Operation, e.Message, e.HRESULT)
	}
	return fmt.Sprintf("%s failed (HRESULT: 0x%08X)", e.Operation, e.HRESULT)
}

// Unwrap returns nil (WFPError is a leaf error).
func (e *WFPError) Unwrap() error {
	return nil
}

// IsAccessDenied returns true if the error is E_ACCESSDENIED.
func (e *WFPError) IsAccessDenied() bool {
	return e.HRESULT == E_ACCESSDENIED
}

// IsAlreadyExists returns true if the error is FWP_E_ALREADY_EXISTS.
func (e *WFPError) IsAlreadyExists() bool {
	return e.HRESULT == FWP_E_ALREADY_EXISTS
}

// IsNotFound returns true if the error is any "not found" type.
func (e *WFPError) IsNotFound() bool {
	switch e.HRESULT {
	case FWP_E_NOT_FOUND, FWP_E_FILTER_NOT_FOUND, FWP_E_LAYER_NOT_FOUND,
		FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
		FWP_E_CALLOUT_NOT_FOUND, FWP_E_CONDITION_NOT_FOUND,
		FWP_E_PROVIDER_CONTEXT_NOT_FOUND:
		return true
	}
	return false
}

// IsInUse returns true if the error is FWP_E_IN_USE.
func (e *WFPError) IsInUse() bool {
	return e.HRESULT == FWP_E_IN_USE
}

// IsTimeout returns true if the error is FWP_E_TIMEOUT.
func (e *WFPError) IsTimeout() bool {
	return e.HRESULT == FWP_E_TIMEOUT
}

// IsRetryable returns true if the operation might succeed on retry.
func (e *WFPError) IsRetryable() bool {
	switch e.HRESULT {
	case FWP_E_TIMEOUT, FWP_E_IN_USE, FWP_E_TXN_IN_PROGRESS:
		return true
	}
	return false
}

// ============================================================================
// Error Construction Helpers
// ============================================================================

// NewWFPError creates a new WFPError.
func NewWFPError(hr HRESULT, operation string) *WFPError {
	return &WFPError{
		HRESULT:   hr,
		Operation: operation,
		Message:   hresultMessage(hr),
	}
}

// NewWFPErrorWithMessage creates a new WFPError with custom message.
func NewWFPErrorWithMessage(hr HRESULT, operation, message string) *WFPError {
	return &WFPError{
		HRESULT:   hr,
		Operation: operation,
		Message:   message,
	}
}

// HResultToError converts an HRESULT to an error.
// Returns nil if HRESULT is S_OK or S_FALSE.
func HResultToError(hr HRESULT, operation string) error {
	if hr == S_OK || hr == S_FALSE {
		return nil
	}
	return NewWFPError(hr, operation)
}

// hresultMessage returns a human-readable message for an HRESULT.
func hresultMessage(hr HRESULT) string {
	switch hr {
	case S_OK:
		return "success"
	case S_FALSE:
		return "success (false)"
	case E_ACCESSDENIED:
		return "access denied - run as administrator"
	case E_INVALIDARG:
		return "invalid argument"
	case E_OUTOFMEMORY:
		return "out of memory"
	case E_FAIL:
		return "unspecified failure"
	case E_HANDLE:
		return "invalid handle"
	case FWP_E_CALLOUT_NOT_FOUND:
		return "callout not found"
	case FWP_E_CONDITION_NOT_FOUND:
		return "condition not found"
	case FWP_E_FILTER_NOT_FOUND:
		return "filter not found"
	case FWP_E_LAYER_NOT_FOUND:
		return "layer not found"
	case FWP_E_PROVIDER_NOT_FOUND:
		return "provider not found"
	case FWP_E_PROVIDER_CONTEXT_NOT_FOUND:
		return "provider context not found"
	case FWP_E_SUBLAYER_NOT_FOUND:
		return "sublayer not found"
	case FWP_E_NOT_FOUND:
		return "object not found"
	case FWP_E_ALREADY_EXISTS:
		return "object already exists"
	case FWP_E_IN_USE:
		return "object in use, cannot be deleted"
	case FWP_E_WRONG_SESSION:
		return "wrong session handle"
	case FWP_E_NO_TXN_IN_PROGRESS:
		return "no transaction in progress"
	case FWP_E_TXN_IN_PROGRESS:
		return "transaction already in progress"
	case FWP_E_TXN_ABORTED:
		return "transaction was aborted"
	case FWP_E_SESSION_ABORTED:
		return "session was aborted"
	case FWP_E_TIMEOUT:
		return "operation timed out"
	case FWP_E_INCOMPATIBLE_LAYER:
		return "incompatible layer"
	case FWP_E_BUILTIN_OBJECT:
		return "cannot modify built-in object"
	case FWP_E_NULL_POINTER:
		return "null pointer"
	case FWP_E_INVALID_FLAGS:
		return "invalid flags"
	case FWP_E_INVALID_NET_MASK:
		return "invalid network mask"
	case FWP_E_INVALID_RANGE:
		return "invalid range"
	case FWP_E_INVALID_ACTION_TYPE:
		return "invalid action type"
	case FWP_E_INVALID_WEIGHT:
		return "invalid weight"
	default:
		return fmt.Sprintf("unknown error (0x%08X)", hr)
	}
}

// ============================================================================
// Error Type Checking Functions
// ============================================================================

// IsWFPError checks if the error is a WFPError.
func IsWFPError(err error) bool {
	var wfpErr *WFPError
	return errors.As(err, &wfpErr)
}

// IsAccessDenied checks if the error is E_ACCESSDENIED.
func IsAccessDenied(err error) bool {
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.IsAccessDenied()
	}
	return false
}

// IsAlreadyExists checks if the error is FWP_E_ALREADY_EXISTS.
func IsAlreadyExists(err error) bool {
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.IsAlreadyExists()
	}
	return false
}

// IsNotFound checks if the error is any "not found" type.
func IsNotFound(err error) bool {
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.IsNotFound()
	}
	return false
}

// IsInUse checks if the error is FWP_E_IN_USE.
func IsInUse(err error) bool {
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.IsInUse()
	}
	return false
}

// IsRetryable checks if the error is retryable.
func IsRetryable(err error) bool {
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.IsRetryable()
	}
	return false
}

// GetHResult extracts the HRESULT from an error.
// Returns S_OK if error is nil or not a WFPError.
func GetHResult(err error) HRESULT {
	if err == nil {
		return S_OK
	}
	var wfpErr *WFPError
	if errors.As(err, &wfpErr) {
		return wfpErr.HRESULT
	}
	return E_FAIL
}

// ============================================================================
// Privilege Checking
// ============================================================================

// CheckElevated checks if the current process has administrator privileges.
// WFP operations require elevation.
func CheckElevated() (bool, error) {
	var token syscall.Token

	// Get current process handle
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, fmt.Errorf("failed to get current process: %w", err)
	}

	// Open process token
	err = syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	// Check token elevation
	var elevation tokenElevation
	var returnLength uint32

	err = syscall.GetTokenInformation(
		token,
		syscall.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&returnLength,
	)
	if err != nil {
		return false, fmt.Errorf("failed to get token information: %w", err)
	}

	return elevation.TokenIsElevated != 0, nil
}

// tokenElevation mirrors the Windows TOKEN_ELEVATION structure.
type tokenElevation struct {
	TokenIsElevated uint32
}

// MustBeElevated returns an error if the process is not elevated.
func MustBeElevated() error {
	elevated, err := CheckElevated()
	if err != nil {
		return fmt.Errorf("failed to check elevation: %w", err)
	}
	if !elevated {
		return errors.New("WFP operations require administrator privileges - run as administrator")
	}
	return nil
}

// ============================================================================
// Sentinel Errors
// ============================================================================

var (
	// ErrNotElevated indicates the process lacks administrator privileges.
	ErrNotElevated = errors.New("WFP operations require administrator privileges")

	// ErrSessionNotOpen indicates no WFP session is open.
	ErrSessionNotOpen = errors.New("WFP session not open")

	// ErrFilterNotFound indicates a filter was not found.
	ErrFilterNotFound = errors.New("WFP filter not found")

	// ErrProviderNotFound indicates a provider was not found.
	ErrProviderNotFound = errors.New("WFP provider not found")

	// ErrAlreadyExists indicates the object already exists.
	ErrAlreadyExists = errors.New("WFP object already exists")

	// ErrInvalidHandle indicates an invalid handle was provided.
	ErrInvalidHandle = errors.New("invalid WFP handle")

	// ErrNilPointer indicates a nil pointer was provided.
	ErrNilPointer = errors.New("nil pointer")
)
