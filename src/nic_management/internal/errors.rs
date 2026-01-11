//! Error types for NIC Management service.
//!
//! Defines NicError enum covering all failure modes including Phase 1
//! TLS Proxy integration errors with fail-open classification.

use std::io;
use std::net::AddrParseError;
use thiserror::Error;
use tonic::Status;

// =============================================================================
// RESULT TYPE ALIAS
// =============================================================================

/// Result type alias for NIC Management operations.
pub type Result<T> = std::result::Result<T, NicError>;

// =============================================================================
// MAIN ERROR ENUM
// =============================================================================

/// Central error type for all NIC Management failures.
#[derive(Error, Debug)]
pub enum NicError {
    // =========================================================================
    // NETWORK INTERFACE ERRORS
    // =========================================================================
    
    /// Generic network interface error.
    #[error("Network interface error: {0}")]
    InterfaceError(String),
    
    /// Specified network interface not found.
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    
    /// Packet capture operation failed.
    #[error("Packet capture error: {0}")]
    CaptureError(String),
    
    // =========================================================================
    // NAT TRANSLATION ERRORS
    // =========================================================================
    
    /// Generic NAT translation error.
    #[error("NAT translation error: {0}")]
    NatError(String),
    
    /// NAT connection table is full.
    #[error("NAT table full (max {0} connections)")]
    NatTableFull(usize),
    
    // =========================================================================
    // CONFIGURATION ERRORS
    // =========================================================================
    
    /// Configuration loading or parsing error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Invalid configuration value.
    #[error("Invalid configuration value: {field} = {value}")]
    InvalidConfigValue {
        field: String,
        value: String,
    },
    
    // =========================================================================
    // ROUTING ERRORS
    // =========================================================================
    
    /// Packet routing or forwarding error.
    #[error("Routing error: {0}")]
    RoutingError(String),
    
    // =========================================================================
    // I/O ERRORS
    // =========================================================================
    
    /// Standard I/O error wrapper.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    
    // =========================================================================
    // TLS PROXY ERRORS - NEW FOR PHASE 1
    // =========================================================================
    
    /// Failed to connect to TLS Proxy service.
    #[error("TLS Proxy connection failed: {0}")]
    TlsProxyConnectionError(String),
    
    /// TLS Proxy service became unavailable during operation.
    #[error("TLS Proxy unavailable: {0}")]
    TlsProxyUnavailable(String),
    
    /// TLS Proxy request timed out.
    #[error("TLS Proxy request timeout after {0} seconds")]
    TlsProxyTimeout(u64),
    
    /// TLS Proxy returned processing error.
    #[error("TLS Proxy processing error: {0}")]
    TlsProxyError(String),
    
    /// TLS Proxy response was invalid or malformed.
    #[error("Invalid TLS Proxy response: {0}")]
    TlsProxyInvalidResponse(String),
    
    /// gRPC error from TLS Proxy communication.
    #[error("TLS Proxy gRPC error: {0}")]
    TlsProxyGrpcError(#[from] Status),
}

// =============================================================================
// ERROR CLASSIFICATION
// =============================================================================

impl NicError {
    /// Determines if error is recoverable (can trigger fail-open behavior).
    ///
    /// Recoverable errors allow packet forwarding to continue unchanged.
    /// Non-recoverable errors require service restart or configuration fix.
    pub fn is_recoverable(&self) -> bool {
        match self {
            // TLS Proxy errors are recoverable (fail-open)
            NicError::TlsProxyConnectionError(_) => true,
            NicError::TlsProxyUnavailable(_) => true,
            NicError::TlsProxyTimeout(_) => true,
            NicError::TlsProxyError(_) => true,
            NicError::TlsProxyInvalidResponse(_) => true,
            NicError::TlsProxyGrpcError(_) => true,
            
            // NAT table full is recoverable (can evict old entries)
            NicError::NatTableFull(_) => true,
            
            // Generic capture errors may be transient
            NicError::CaptureError(_) => true,
            
            // Non-recoverable: Fatal configuration or system errors
            NicError::InterfaceError(_) => false,
            NicError::InterfaceNotFound(_) => false,
            NicError::ConfigError(_) => false,
            NicError::InvalidConfigValue { .. } => false,
            NicError::RoutingError(_) => false,
            NicError::IoError(_) => false,
            NicError::NatError(_) => false,
        }
    }
    
    /// Returns true if this is a TLS Proxy related error.
    pub fn is_tls_proxy_error(&self) -> bool {
        matches!(
            self,
            NicError::TlsProxyConnectionError(_)
                | NicError::TlsProxyUnavailable(_)
                | NicError::TlsProxyTimeout(_)
                | NicError::TlsProxyError(_)
                | NicError::TlsProxyInvalidResponse(_)
                | NicError::TlsProxyGrpcError(_)
        )
    }
}

// =============================================================================
// ERROR CONVERSIONS
// =============================================================================

impl From<toml::de::Error> for NicError {
    fn from(err: toml::de::Error) -> Self {
        NicError::ConfigError(err.to_string())
    }
}

impl From<AddrParseError> for NicError {
    fn from(err: AddrParseError) -> Self {
        NicError::InvalidConfigValue {
            field: "address".to_string(),
            value: err.to_string(),
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tls_proxy_errors_are_recoverable() {
        assert!(NicError::TlsProxyConnectionError("test".into()).is_recoverable());
        assert!(NicError::TlsProxyUnavailable("test".into()).is_recoverable());
        assert!(NicError::TlsProxyTimeout(5).is_recoverable());
        assert!(NicError::TlsProxyError("test".into()).is_recoverable());
        assert!(NicError::TlsProxyInvalidResponse("test".into()).is_recoverable());
    }
    
    #[test]
    fn test_config_errors_not_recoverable() {
        assert!(!NicError::ConfigError("test".into()).is_recoverable());
        assert!(!NicError::InvalidConfigValue {
            field: "test".into(),
            value: "bad".into(),
        }.is_recoverable());
    }
    
    #[test]
    fn test_interface_errors_not_recoverable() {
        assert!(!NicError::InterfaceNotFound("Ethernet".into()).is_recoverable());
        assert!(!NicError::InterfaceError("permission denied".into()).is_recoverable());
    }
    
    #[test]
    fn test_nat_table_full_is_recoverable() {
        assert!(NicError::NatTableFull(65535).is_recoverable());
    }
    
    #[test]
    fn test_error_message_formatting() {
        let err = NicError::TlsProxyTimeout(5);
        assert_eq!(err.to_string(), "TLS Proxy request timeout after 5 seconds");
        
        let err = NicError::NatTableFull(1000);
        assert_eq!(err.to_string(), "NAT table full (max 1000 connections)");
        
        let err = NicError::InterfaceNotFound("Wi-Fi".into());
        assert_eq!(err.to_string(), "Interface not found: Wi-Fi");
    }
    
    #[test]
    fn test_is_tls_proxy_error() {
        assert!(NicError::TlsProxyTimeout(5).is_tls_proxy_error());
        assert!(NicError::TlsProxyError("test".into()).is_tls_proxy_error());
        assert!(!NicError::ConfigError("test".into()).is_tls_proxy_error());
        assert!(!NicError::NatError("test".into()).is_tls_proxy_error());
    }
}
