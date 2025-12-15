//! Common error types and error handling utilities
//!
//! Provides consistent error management across all SafeOps services
//! with comprehensive error context, chain traversal, and reporting.
//!
//! # Features
//! - **System Errors**: IO, network, permission, resource exhaustion
//! - **Application Errors**: Configuration, validation, parse, state errors
//! - **Error Context**: Rich context wrapping with source tracking
//! - **Error Codes**: HTTP-style error codes for API responses
//! - **Error Reporting**: Structured logging and metrics integration
//! - **Error Chain**: Full error chain traversal and debugging
//!
//! # Error Handling Patterns
//! ```rust,ignore
//! use safeops_shared::error::{Error, Result, ResultExt};
//!
//! fn example() -> Result<()> {
//!     let data = load_config()
//!         .context("Failed to load configuration")?;
//!     Ok(())
//! }
//! ```

use thiserror::Error;

/// Main error type for the SafeOps shared library
#[derive(Error, Debug)]
pub enum Error {
    /// Parse error (invalid format)
    #[error("Parse error: {0}")]
    Parse(String),
    
    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Memory allocation error
    #[error("Memory allocation failed: {0}")]
    Allocation(String),
    
    /// Pool exhausted error
    #[error("Pool exhausted: {0}")]
    PoolExhausted(String),
    
    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),
    
    /// Lock error
    #[error("Lock acquisition failed: {0}")]
    Lock(String),
    
    /// Queue full error
    #[error("Queue is full")]
    QueueFull,
    
    /// Queue empty error
    #[error("Queue is empty")]
    QueueEmpty,
    
    /// Capacity exceeded error
    #[error("Capacity exceeded: {0}")]
    CapacityExceeded(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Already exists error
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Error code for API responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Client errors (4xx)
    InvalidInput = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    AlreadyExists = 409,
    
    // Server errors (5xx)
    Internal = 500,
    NotImplemented = 501,
    ServiceUnavailable = 503,
    Timeout = 504,
}

impl Error {
    /// Get the error code for this error
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Parse(_) | Error::InvalidInput(_) => ErrorCode::InvalidInput,
            Error::NotFound(_) => ErrorCode::NotFound,
            Error::AlreadyExists(_) => ErrorCode::AlreadyExists,
            Error::Timeout(_) => ErrorCode::Timeout,
            Error::Config(_) | Error::Serialization(_) | Error::Deserialization(_) => {
                ErrorCode::InvalidInput
            }
            Error::Io(_) | Error::Allocation(_) | Error::PoolExhausted(_) | 
            Error::Lock(_) | Error::QueueFull | Error::QueueEmpty | 
            Error::CapacityExceeded(_) | Error::Internal(_) => ErrorCode::Internal,
        }
    }
    
    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            Error::Parse(msg) => format!("Invalid format: {}", msg),
            Error::InvalidInput(msg) => format!("Invalid input: {}", msg),
            Error::NotFound(msg) => format!("{} not found", msg),
            Error::AlreadyExists(msg) => format!("{} already exists", msg),
            Error::Timeout(msg) => format!("Operation timed out: {}", msg),
            Error::Config(msg) => format!("Configuration error: {}", msg),
            Error::Io(_) => "I/O operation failed".to_string(),
            Error::Allocation(_) => "Memory allocation failed".to_string(),
            Error::PoolExhausted(_) => "Resource pool exhausted".to_string(),
            Error::Lock(_) => "Lock acquisition failed".to_string(),
            Error::QueueFull => "Queue is full".to_string(),
            Error::QueueEmpty => "Queue is empty".to_string(),
            Error::CapacityExceeded(_) => "Capacity limit exceeded".to_string(),
            Error::Serialization(_) | Error::Deserialization(_) => {
                "Data conversion failed".to_string()
            }
            Error::Internal(_) => "Internal server error".to_string(),
        }
    }
    
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Timeout(_) | Error::Io(_) | Error::Lock(_) |
            Error::QueueFull | Error::PoolExhausted(_)
        )
    }
}

/// Result type alias for SafeOps operations
pub type Result<T> = std::result::Result<T, Error>;

/// Extension trait for converting Option to Result
pub trait OptionExt<T> {
    /// Convert Option to Result with a custom error message
    fn ok_or_not_found(self, msg: &str) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_not_found(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| Error::NotFound(msg.to_string()))
    }
}

/// Extension trait for adding context to errors
pub trait ResultExt<T> {
    /// Add context to an error
    fn context(self, msg: &str) -> Result<T>;
}

impl<T, E: std::error::Error + 'static> ResultExt<T> for std::result::Result<T, E> {
    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| Error::Internal(format!("{}: {}", msg, e)))
    }
}

// ============================================================================
// Error Context and Chain
// ============================================================================

/// Error with context information
#[derive(Debug)]
pub struct ErrorContext {
    pub error: Error,
    pub context: Vec<String>,
    pub location: Option<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(error: Error) -> Self {
        Self {
            error,
            context: Vec::new(),
            location: None,
        }
    }
    
    /// Add context information
    pub fn with_context(mut self, msg: impl Into<String>) -> Self {
        self.context.push(msg.into());
        self
    }
    
    /// Set the error location
    pub fn with_location(mut self, file: &str, line: u32) -> Self {
        self.location = Some(format!("{}:{}", file, line));
        self
    }
    
    /// Get the full error chain as a string
    pub fn error_chain(&self) -> String {
        let mut chain = vec![format!("Error: {}", self.error)];
        
        if !self.context.is_empty() {
            chain.push(format!("Context: {}", self.context.join(" -> ")));
        }
        
        if let Some(ref loc) = self.location {
            chain.push(format!("Location: {}", loc));
        }
        
        // Add source error if available
        if let Some(source) = std::error::Error::source(&self.error) {
            chain.push(format!("Caused by: {}", source));
        }
        
        chain.join("\n")
    }
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error_chain())
    }
}

impl std::error::Error for ErrorContext {}

/// Macro for creating errors with file/line information
#[macro_export]
macro_rules! error_here {
    ($err:expr) => {
        ErrorContext::new($err).with_location(file!(), line!())
    };
    ($err:expr, $ctx:expr) => {
        ErrorContext::new($err)
            .with_context($ctx)
            .with_location(file!(), line!())
    };
}

// ============================================================================
// Error Reporting
// ============================================================================

/// Error metrics for monitoring
#[derive(Debug, Clone, Default)]
pub struct ErrorMetrics {
    pub total_errors: u64,
    pub retryable_errors: u64,
    pub client_errors: u64,
    pub server_errors: u64,
}

impl ErrorMetrics {
    /// Record an error
    pub fn record(&mut self, error: &Error) {
        self.total_errors += 1;
        
        if error.is_retryable() {
            self.retryable_errors += 1;
        }
        
        match error.code() {
            ErrorCode::InvalidInput | ErrorCode::Unauthorized |
            ErrorCode::Forbidden | ErrorCode::NotFound |
            ErrorCode::AlreadyExists => self.client_errors += 1,
            _ => self.server_errors += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = Error::Parse("invalid IP".to_string());
        assert_eq!(format!("{}", e), "Parse error: invalid IP");
    }

    #[test]
    fn test_option_ext() {
        let opt: Option<i32> = None;
        let result = opt.ok_or_not_found("item");
        assert!(matches!(result, Err(Error::NotFound(_))));
    }

    #[test]
    fn test_result_ext() {
        let result: std::result::Result<i32, std::io::Error> = 
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));
        let wrapped = result.context("loading config");
        assert!(matches!(wrapped, Err(Error::Internal(_))));
    }

    #[test]
    fn test_error_code() {
        assert_eq!(Error::Parse("test".to_string()).code(), ErrorCode::InvalidInput);
        assert_eq!(Error::NotFound("item".to_string()).code(), ErrorCode::NotFound);
        assert_eq!(Error::Timeout("op".to_string()).code(), ErrorCode::Timeout);
    }

    #[test]
    fn test_user_message() {
        let err = Error::NotFound("user".to_string());
        assert_eq!(err.user_message(), "user not found");
        
        let err = Error::QueueFull;
        assert_eq!(err.user_message(), "Queue is full");
    }

    #[test]
    fn test_retryable() {
        assert!(Error::Timeout("test".to_string()).is_retryable());
        assert!(Error::QueueFull.is_retryable());
        assert!(!Error::NotFound("test".to_string()).is_retryable());
    }

    #[test]
    fn test_error_context() {
        let err = Error::Parse("invalid data".to_string());
        let ctx = ErrorContext::new(err)
            .with_context("reading file")
            .with_context("loading config")
            .with_location("test.rs", 100);
        
        let chain = ctx.error_chain();
        assert!(chain.contains("Parse error"));
        assert!(chain.contains("Context:"));
        assert!(chain.contains("Location: test.rs:100"));
    }

    #[test]
    fn test_error_metrics() {
        let mut metrics = ErrorMetrics::default();
        
        metrics.record(&Error::NotFound("test".to_string()));
        metrics.record(&Error::Timeout("op".to_string()));
        metrics.record(&Error::Internal("bug".to_string()));
        
        assert_eq!(metrics.total_errors, 3);
        assert_eq!(metrics.retryable_errors, 1); // Timeout is retryable
        assert_eq!(metrics.client_errors, 1); // NotFound
        assert_eq!(metrics.server_errors, 2); // Timeout + Internal
    }
}
