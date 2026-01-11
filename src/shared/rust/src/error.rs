//! Error types for SafeOps shared library
//!
//! This module provides a unified error type that consolidates all possible error
//! conditions across the shared library. It supports automatic error conversion,
//! error context chains, and integration with gRPC status codes.

use thiserror::Error;

/// Primary error type representing all error conditions in SafeOps shared library
#[derive(Error, Debug)]
pub enum SafeOpsError {
    /// File system, network socket, or standard I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Network connection failures, timeouts, or DNS errors
    #[error("Network error: {0}")]
    Network(String),

    /// Data format parsing failures (JSON, binary, packets)
    #[error("Parse error: {0}")]
    Parse(String),

    /// Hashing operation failures
    #[error("Hash error: {0}")]
    Hash(String),

    /// gRPC call errors from other services
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    /// Serialization or deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Database connection or query failures
    #[error("Database error: {0}")]
    Database(String),

    /// Configuration loading or validation errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// User or external data validation failures
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Operations exceeding time limits
    #[error("Operation timed out")]
    Timeout,

    /// Resource not found (rules, indicators, connections)
    #[error("Not found: {0}")]
    NotFound(String),

    /// Authorization failures
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Unexpected internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience Result type alias using SafeOpsError
///
/// Allows functions to return `Result<T>` instead of `Result<T, SafeOpsError>`
pub type Result<T> = std::result::Result<T, SafeOpsError>;

/// Error category for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Transient errors that may succeed on retry
    Transient,
    /// Permanent errors that won't succeed on retry
    Permanent,
    /// User-caused errors (invalid input, not found)
    UserError,
    /// System errors (internal failures, database issues)
    SystemError,
}

impl SafeOpsError {
    // ========================================================================
    // Constructor Functions
    // ========================================================================

    /// Creates a Network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Network(msg.into())
    }

    /// Creates an Internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Internal(msg.into())
    }

    /// Creates a Parse error
    pub fn parse<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Parse(msg.into())
    }

    /// Creates an InvalidInput error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::InvalidInput(msg.into())
    }

    /// Creates a Hash error
    pub fn hash_error<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Hash(msg.into())
    }

    /// Creates a Config error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Config(msg.into())
    }

    /// Creates a Database error
    pub fn database<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::Database(msg.into())
    }

    /// Creates a NotFound error
    pub fn not_found<S: Into<String>>(msg: S) -> Self {
        SafeOpsError::NotFound(msg.into())
    }

    // ========================================================================
    // Classification Methods
    // ========================================================================

    /// Returns true if this error is recoverable (transient)
    ///
    /// Recoverable errors may succeed if retried, such as network timeouts,
    /// temporary connection failures, or gRPC unavailable errors.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            SafeOpsError::Network(_)
                | SafeOpsError::Timeout
                | SafeOpsError::Grpc(_)
                | SafeOpsError::Database(_)
        )
    }

    /// Returns true if this error is permanent (non-recoverable)
    ///
    /// Permanent errors will not succeed on retry, such as parse errors,
    /// invalid input, or permission denied.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            SafeOpsError::Parse(_)
                | SafeOpsError::InvalidInput(_)
                | SafeOpsError::PermissionDenied(_)
                | SafeOpsError::Serialization(_)
        )
    }

    /// Returns the error category for classification and handling
    pub fn error_category(&self) -> ErrorCategory {
        match self {
            SafeOpsError::Network(_) | SafeOpsError::Timeout | SafeOpsError::Grpc(_) => {
                ErrorCategory::Transient
            }
            SafeOpsError::Parse(_) | SafeOpsError::Serialization(_) => ErrorCategory::Permanent,
            SafeOpsError::InvalidInput(_)
            | SafeOpsError::NotFound(_)
            | SafeOpsError::PermissionDenied(_) => ErrorCategory::UserError,
            SafeOpsError::Io(_)
            | SafeOpsError::Hash(_)
            | SafeOpsError::Database(_)
            | SafeOpsError::Config(_)
            | SafeOpsError::Internal(_) => ErrorCategory::SystemError,
        }
    }

    // ========================================================================
    // Conversion Methods
    // ========================================================================

    /// Converts SafeOpsError to gRPC tonic::Status for service responses
    ///
    /// Maps error variants to appropriate gRPC status codes:
    /// - InvalidInput, Parse → InvalidArgument
    /// - NotFound → NotFound
    /// - PermissionDenied → PermissionDenied
    /// - Timeout → DeadlineExceeded
    /// - Network → Unavailable
    /// - Others → Internal
    pub fn to_status(&self) -> tonic::Status {
        match self {
            SafeOpsError::InvalidInput(msg) | SafeOpsError::Parse(msg) => {
                tonic::Status::invalid_argument(msg)
            }
            SafeOpsError::NotFound(msg) => tonic::Status::not_found(msg),
            SafeOpsError::PermissionDenied(msg) => tonic::Status::permission_denied(msg),
            SafeOpsError::Timeout => {
                tonic::Status::deadline_exceeded("Operation timed out")
            }
            SafeOpsError::Network(msg) => tonic::Status::unavailable(msg),
            SafeOpsError::Grpc(status) => status.clone(),
            SafeOpsError::Io(err) => tonic::Status::internal(err.to_string()),
            SafeOpsError::Hash(msg)
            | SafeOpsError::Database(msg)
            | SafeOpsError::Config(msg)
            | SafeOpsError::Internal(msg) => tonic::Status::internal(msg),
            SafeOpsError::Serialization(err) => tonic::Status::internal(err.to_string()),
        }
    }
}

/// Extension trait for adding context to errors
///
/// Enables error chaining with context messages:
///
/// ```ignore
/// use safeops_shared::error::{Result, ErrorContext};
///
/// fn read_file() -> Result<()> {
///     Err(safeops_shared::SafeOpsError::not_found("file"))
/// }
///
/// fn process() -> Result<()> {
///     read_file().context("Failed to read configuration")?;
///     Ok(())
/// }
/// ```
pub trait ErrorContext<T> {
    /// Adds context message to the error
    fn context(self, msg: &str) -> Result<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::fmt::Display,
{
    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| SafeOpsError::Internal(format!("{}: {}", msg, e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_constructors() {
        let err = SafeOpsError::network("Connection failed");
        assert!(matches!(err, SafeOpsError::Network(_)));

        let err = SafeOpsError::parse("Invalid format");
        assert!(matches!(err, SafeOpsError::Parse(_)));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(SafeOpsError::network("test").is_recoverable());
        assert!(SafeOpsError::Timeout.is_recoverable());
        assert!(!SafeOpsError::parse("test").is_recoverable());
        assert!(!SafeOpsError::invalid_input("test").is_recoverable());
    }

    #[test]
    fn test_error_category() {
        assert_eq!(
            SafeOpsError::network("test").error_category(),
            ErrorCategory::Transient
        );
        assert_eq!(
            SafeOpsError::parse("test").error_category(),
            ErrorCategory::Permanent
        );
        assert_eq!(
            SafeOpsError::invalid_input("test").error_category(),
            ErrorCategory::UserError
        );
        assert_eq!(
            SafeOpsError::internal("test").error_category(),
            ErrorCategory::SystemError
        );
    }

    #[test]
    fn test_to_status() {
        let err = SafeOpsError::not_found("resource");
        let status = err.to_status();
        assert_eq!(status.code(), tonic::Code::NotFound);

        let err = SafeOpsError::Timeout;
        let status = err.to_status();
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    }
}
