// Package errors provides error code definitions.
package errors

import "net/http"

// Code represents an error code
type Code string

// Error codes
const (
	// General errors
	Unknown          Code = "UNKNOWN"
	Internal         Code = "INTERNAL"
	InvalidArgument  Code = "INVALID_ARGUMENT"
	NotFound         Code = "NOT_FOUND"
	AlreadyExists    Code = "ALREADY_EXISTS"
	PermissionDenied Code = "PERMISSION_DENIED"
	Unauthenticated  Code = "UNAUTHENTICATED"

	// Resource errors
	ResourceExhausted  Code = "RESOURCE_EXHAUSTED"
	FailedPrecondition Code = "FAILED_PRECONDITION"
	Aborted            Code = "ABORTED"
	OutOfRange         Code = "OUT_OF_RANGE"

	// Operation errors
	Unimplemented Code = "UNIMPLEMENTED"
	Unavailable   Code = "UNAVAILABLE"
	DataLoss      Code = "DATA_LOSS"
	Timeout       Code = "TIMEOUT"
	Cancelled     Code = "CANCELLED"

	// Validation errors
	ValidationFailed Code = "VALIDATION_FAILED"
	InvalidFormat    Code = "INVALID_FORMAT"
	MissingRequired  Code = "MISSING_REQUIRED"

	// Database errors
	DBConnection  Code = "DB_CONNECTION"
	DBQuery       Code = "DB_QUERY"
	DBTransaction Code = "DB_TRANSACTION"
	DBConstraint  Code = "DB_CONSTRAINT"

	// Network errors
	NetworkError      Code = "NETWORK_ERROR"
	ConnectionRefused Code = "CONNECTION_REFUSED"
	DNSError          Code = "DNS_ERROR"
	TLSError          Code = "TLS_ERROR"

	// Configuration errors
	ConfigError   Code = "CONFIG_ERROR"
	InvalidConfig Code = "INVALID_CONFIG"
	MissingConfig Code = "MISSING_CONFIG"
)

// String returns the code as a string
func (c Code) String() string {
	return string(c)
}

// HTTPStatus returns the HTTP status code for an error code
func (c Code) HTTPStatus() int {
	switch c {
	case InvalidArgument, ValidationFailed, InvalidFormat, MissingRequired:
		return http.StatusBadRequest
	case Unauthenticated:
		return http.StatusUnauthorized
	case PermissionDenied:
		return http.StatusForbidden
	case NotFound:
		return http.StatusNotFound
	case AlreadyExists:
		return http.StatusConflict
	case ResourceExhausted:
		return http.StatusTooManyRequests
	case FailedPrecondition:
		return http.StatusPreconditionFailed
	case Aborted:
		return http.StatusConflict
	case OutOfRange:
		return http.StatusRequestedRangeNotSatisfiable
	case Unimplemented:
		return http.StatusNotImplemented
	case Unavailable:
		return http.StatusServiceUnavailable
	case Timeout:
		return http.StatusGatewayTimeout
	case Cancelled:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}

// GRPCCode returns the gRPC status code (as int)
func (c Code) GRPCCode() int {
	switch c {
	case Unknown:
		return 2 // codes.Unknown
	case InvalidArgument:
		return 3 // codes.InvalidArgument
	case Timeout:
		return 4 // codes.DeadlineExceeded
	case NotFound:
		return 5 // codes.NotFound
	case AlreadyExists:
		return 6 // codes.AlreadyExists
	case PermissionDenied:
		return 7 // codes.PermissionDenied
	case ResourceExhausted:
		return 8 // codes.ResourceExhausted
	case FailedPrecondition:
		return 9 // codes.FailedPrecondition
	case Aborted:
		return 10 // codes.Aborted
	case OutOfRange:
		return 11 // codes.OutOfRange
	case Unimplemented:
		return 12 // codes.Unimplemented
	case Internal:
		return 13 // codes.Internal
	case Unavailable:
		return 14 // codes.Unavailable
	case DataLoss:
		return 15 // codes.DataLoss
	case Unauthenticated:
		return 16 // codes.Unauthenticated
	case Cancelled:
		return 1 // codes.Canceled
	default:
		return 2 // codes.Unknown
	}
}

// Message returns a default message for the code
func (c Code) Message() string {
	switch c {
	case Unknown:
		return "An unknown error occurred"
	case Internal:
		return "An internal error occurred"
	case InvalidArgument:
		return "Invalid argument provided"
	case NotFound:
		return "Resource not found"
	case AlreadyExists:
		return "Resource already exists"
	case PermissionDenied:
		return "Permission denied"
	case Unauthenticated:
		return "Authentication required"
	case ResourceExhausted:
		return "Resource exhausted"
	case FailedPrecondition:
		return "Operation precondition failed"
	case Aborted:
		return "Operation was aborted"
	case OutOfRange:
		return "Value out of range"
	case Unimplemented:
		return "Operation not implemented"
	case Unavailable:
		return "Service unavailable"
	case DataLoss:
		return "Data loss or corruption"
	case Timeout:
		return "Operation timed out"
	case Cancelled:
		return "Operation was cancelled"
	case ValidationFailed:
		return "Validation failed"
	case InvalidFormat:
		return "Invalid format"
	case MissingRequired:
		return "Required field is missing"
	case DBConnection:
		return "Database connection error"
	case DBQuery:
		return "Database query error"
	case DBTransaction:
		return "Database transaction error"
	case DBConstraint:
		return "Database constraint violation"
	case NetworkError:
		return "Network error"
	case ConnectionRefused:
		return "Connection refused"
	case DNSError:
		return "DNS resolution error"
	case TLSError:
		return "TLS/SSL error"
	case ConfigError:
		return "Configuration error"
	case InvalidConfig:
		return "Invalid configuration"
	case MissingConfig:
		return "Missing configuration"
	default:
		return "An error occurred"
	}
}

// FromHTTPStatus creates a code from HTTP status
func FromHTTPStatus(status int) Code {
	switch status {
	case http.StatusBadRequest:
		return InvalidArgument
	case http.StatusUnauthorized:
		return Unauthenticated
	case http.StatusForbidden:
		return PermissionDenied
	case http.StatusNotFound:
		return NotFound
	case http.StatusConflict:
		return AlreadyExists
	case http.StatusTooManyRequests:
		return ResourceExhausted
	case http.StatusNotImplemented:
		return Unimplemented
	case http.StatusServiceUnavailable:
		return Unavailable
	case http.StatusGatewayTimeout:
		return Timeout
	default:
		if status >= 500 {
			return Internal
		}
		return Unknown
	}
}

// IsClientError returns true if the code represents a client error
func (c Code) IsClientError() bool {
	status := c.HTTPStatus()
	return status >= 400 && status < 500
}

// IsServerError returns true if the code represents a server error
func (c Code) IsServerError() bool {
	status := c.HTTPStatus()
	return status >= 500
}
