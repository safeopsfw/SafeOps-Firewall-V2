package errors

// codes.go - Centralized Error Code Registry
//
// This file serves as the authoritative registry of machine-readable error codes
// used across all SafeOps Go services. Centralizing codes ensures consistency,
// prevents typos, enables global search for error usage, and ensures no duplicate
// codes with different meanings.
//
// All error codes follow SCREAMING_SNAKE_CASE naming convention.

// ============================================================================
// Configuration Error Codes
// ============================================================================

const (
	// ErrConfigLoadFailed indicates configuration file could not be read
	ErrConfigLoadFailed = "CONFIG_LOAD_FAILED"

	// ErrConfigInvalid indicates configuration validation failed
	ErrConfigInvalid = "CONFIG_INVALID"

	// ErrConfigMissingKey indicates required configuration key not present
	ErrConfigMissingKey = "CONFIG_MISSING_KEY"

	// ErrConfigTypeMismatch indicates configuration value has wrong type
	ErrConfigTypeMismatch = "CONFIG_TYPE_MISMATCH"
)

// ============================================================================
// Database Error Codes
// ============================================================================

const (
	// ErrDBConnectionFailed indicates database connection could not be established
	ErrDBConnectionFailed = "DB_CONNECTION_FAILED"

	// ErrDBQueryFailed indicates SQL query execution failed
	ErrDBQueryFailed = "DB_QUERY_FAILED"

	// ErrDBTransactionFailed indicates database transaction failed
	ErrDBTransactionFailed = "DB_TRANSACTION_FAILED"

	// ErrDBTimeout indicates database operation timed out
	ErrDBTimeout = "DB_TIMEOUT"

	// ErrDBConstraintViolation indicates unique/foreign key constraint violated
	ErrDBConstraintViolation = "DB_CONSTRAINT_VIOLATION"

	// ErrDBRecordNotFound indicates query returned no rows
	ErrDBRecordNotFound = "DB_RECORD_NOT_FOUND"
)

// ============================================================================
// Redis Error Codes
// ============================================================================

const (
	// ErrRedisConnectionFailed indicates Redis connection failed
	ErrRedisConnectionFailed = "REDIS_CONNECTION_FAILED"

	// ErrRedisCommandFailed indicates Redis command execution failed
	ErrRedisCommandFailed = "REDIS_COMMAND_FAILED"

	// ErrRedisTimeout indicates Redis operation timed out
	ErrRedisTimeout = "REDIS_TIMEOUT"

	// ErrRedisPubSubFailed indicates pub/sub operation failed
	ErrRedisPubSubFailed = "REDIS_PUBSUB_FAILED"
)

// ============================================================================
// gRPC Error Codes
// ============================================================================

const (
	// ErrGRPCCallFailed indicates gRPC call failed
	ErrGRPCCallFailed = "GRPC_CALL_FAILED"

	// ErrGRPCTimeout indicates gRPC call timed out
	ErrGRPCTimeout = "GRPC_TIMEOUT"

	// ErrGRPCUnavailable indicates service unavailable (circuit breaker open)
	ErrGRPCUnavailable = "GRPC_UNAVAILABLE"

	// ErrGRPCDeadlineExceeded indicates deadline exceeded
	ErrGRPCDeadlineExceeded = "GRPC_DEADLINE_EXCEEDED"

	// ErrGRPCPermissionDenied indicates permission denied
	ErrGRPCPermissionDenied = "GRPC_PERMISSION_DENIED"
)

// ============================================================================
// Input Validation Error Codes
// ============================================================================

const (
	// ErrInvalidInput indicates user input failed validation
	ErrInvalidInput = "INVALID_INPUT"

	// ErrMissingParameter indicates required parameter not provided
	ErrMissingParameter = "MISSING_PARAMETER"

	// ErrInvalidFormat indicates input format incorrect (e.g., bad IP address)
	ErrInvalidFormat = "INVALID_FORMAT"

	// ErrOutOfRange indicates numeric value outside valid range
	ErrOutOfRange = "OUT_OF_RANGE"
)

// ============================================================================
// Network Error Codes
// ============================================================================

const (
	// ErrNetworkTimeout indicates network operation timed out
	ErrNetworkTimeout = "NETWORK_TIMEOUT"

	// ErrNetworkUnreachable indicates network destination unreachable
	ErrNetworkUnreachable = "NETWORK_UNREACHABLE"

	// ErrNetworkDNSFailed indicates DNS resolution failed
	ErrNetworkDNSFailed = "NETWORK_DNS_FAILED"
)

// ============================================================================
// File System Error Codes
// ============================================================================

const (
	// ErrFileNotFound indicates file does not exist
	ErrFileNotFound = "FILE_NOT_FOUND"

	// ErrFilePermissionDenied indicates insufficient file permissions
	ErrFilePermissionDenied = "FILE_PERMISSION_DENIED"

	// ErrFileReadFailed indicates file read operation failed
	ErrFileReadFailed = "FILE_READ_FAILED"

	// ErrFileWriteFailed indicates file write operation failed
	ErrFileWriteFailed = "FILE_WRITE_FAILED"
)

// ============================================================================
// Internal Error Codes
// ============================================================================

const (
	// ErrInternalFailure indicates unexpected internal error
	ErrInternalFailure = "INTERNAL_FAILURE"

	// ErrNotImplemented indicates feature not yet implemented
	ErrNotImplemented = "NOT_IMPLEMENTED"

	// ErrUnknown indicates error with unknown cause
	ErrUnknown = "UNKNOWN"
)

// ============================================================================
// Service-Specific Error Codes - DNS Service
// ============================================================================

const (
	// ErrDNSQueryFailed indicates DNS query failed
	ErrDNSQueryFailed = "DNS_QUERY_FAILED"

	// ErrDNSInvalidDomain indicates domain name invalid
	ErrDNSInvalidDomain = "DNS_INVALID_DOMAIN"

	// ErrDNSBlocked indicates domain blocked by filter
	ErrDNSBlocked = "DNS_BLOCKED"
)

// ============================================================================
// Service-Specific Error Codes - DHCP Service
// ============================================================================

const (
	// ErrDHCPNoAvailableIP indicates no IP addresses available in pool
	ErrDHCPNoAvailableIP = "DHCP_NO_AVAILABLE_IP"

	// ErrDHCPLeaseConflict indicates lease conflict (IP already assigned)
	ErrDHCPLeaseConflict = "DHCP_LEASE_CONFLICT"
)

// ============================================================================
// Service-Specific Error Codes - Firewall Service
// ============================================================================

const (
	// ErrFirewallRuleInvalid indicates firewall rule syntax invalid
	ErrFirewallRuleInvalid = "FIREWALL_RULE_INVALID"

	// ErrFirewallRuleConflict indicates conflicting firewall rules
	ErrFirewallRuleConflict = "FIREWALL_RULE_CONFLICT"
)

// ============================================================================
// Helper Functions
// ============================================================================

// IsConfigError returns true if the error code is a configuration error
func IsConfigError(code string) bool {
	switch code {
	case ErrConfigLoadFailed,
		ErrConfigInvalid,
		ErrConfigMissingKey,
		ErrConfigTypeMismatch:
		return true
	default:
		return false
	}
}

// IsDBError returns true if the error code is a database error
func IsDBError(code string) bool {
	switch code {
	case ErrDBConnectionFailed,
		ErrDBQueryFailed,
		ErrDBTransactionFailed,
		ErrDBTimeout,
		ErrDBConstraintViolation,
		ErrDBRecordNotFound:
		return true
	default:
		return false
	}
}

// IsRedisError returns true if the error code is a Redis error
func IsRedisError(code string) bool {
	switch code {
	case ErrRedisConnectionFailed,
		ErrRedisCommandFailed,
		ErrRedisTimeout,
		ErrRedisPubSubFailed:
		return true
	default:
		return false
	}
}

// IsGRPCError returns true if the error code is a gRPC error
func IsGRPCError(code string) bool {
	switch code {
	case ErrGRPCCallFailed,
		ErrGRPCTimeout,
		ErrGRPCUnavailable,
		ErrGRPCDeadlineExceeded,
		ErrGRPCPermissionDenied:
		return true
	default:
		return false
	}
}

// IsValidationError returns true if the error code is an input validation error
func IsValidationError(code string) bool {
	switch code {
	case ErrInvalidInput,
		ErrMissingParameter,
		ErrInvalidFormat,
		ErrOutOfRange:
		return true
	default:
		return false
	}
}

// IsNetworkError returns true if the error code is a network error
func IsNetworkError(code string) bool {
	switch code {
	case ErrNetworkTimeout,
		ErrNetworkUnreachable,
		ErrNetworkDNSFailed:
		return true
	default:
		return false
	}
}

// IsFileSystemError returns true if the error code is a file system error
func IsFileSystemError(code string) bool {
	switch code {
	case ErrFileNotFound,
		ErrFilePermissionDenied,
		ErrFileReadFailed,
		ErrFileWriteFailed:
		return true
	default:
		return false
	}
}

// IsInternalError returns true if the error code is an internal error
func IsInternalError(code string) bool {
	switch code {
	case ErrInternalFailure,
		ErrNotImplemented,
		ErrUnknown:
		return true
	default:
		return false
	}
}

// IsDNSError returns true if the error code is a DNS service error
func IsDNSError(code string) bool {
	switch code {
	case ErrDNSQueryFailed,
		ErrDNSInvalidDomain,
		ErrDNSBlocked:
		return true
	default:
		return false
	}
}

// IsDHCPError returns true if the error code is a DHCP service error
func IsDHCPError(code string) bool {
	switch code {
	case ErrDHCPNoAvailableIP,
		ErrDHCPLeaseConflict:
		return true
	default:
		return false
	}
}

// IsFirewallError returns true if the error code is a Firewall service error
func IsFirewallError(code string) bool {
	switch code {
	case ErrFirewallRuleInvalid,
		ErrFirewallRuleConflict:
		return true
	default:
		return false
	}
}

// CategoryOfCode returns the error category name for use in monitoring dashboards
// and error grouping. Returns "Unknown" if the code is not recognized.
func CategoryOfCode(code string) string {
	switch {
	case IsConfigError(code):
		return "Configuration"
	case IsDBError(code):
		return "Database"
	case IsRedisError(code):
		return "Redis"
	case IsGRPCError(code):
		return "gRPC"
	case IsValidationError(code):
		return "Validation"
	case IsNetworkError(code):
		return "Network"
	case IsFileSystemError(code):
		return "FileSystem"
	case IsInternalError(code):
		return "Internal"
	case IsDNSError(code):
		return "DNS"
	case IsDHCPError(code):
		return "DHCP"
	case IsFirewallError(code):
		return "Firewall"
	default:
		return "Unknown"
	}
}
