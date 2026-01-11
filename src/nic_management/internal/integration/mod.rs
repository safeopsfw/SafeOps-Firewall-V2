//! Integration module for external service communication.
//!
//! This module contains clients and adapters for communicating with external
//! services that NIC Management depends on. Each integration component is
//! isolated in its own submodule to maintain clear separation of concerns.
//!
//! # Current Integrations (Phase 1)
//!
//! - **TLS Proxy** - gRPC client for packet inspection and SNI extraction
//!
//! # Future Integrations (Phase 2+)
//!
//! - DNS client for direct DNS resolution (bypassing TLS Proxy)
//! - Metrics exporter for observability systems
//! - Logging aggregation clients
//! - Certificate management integrations
//!
//! # Design Principles
//!
//! - Each integration is self-contained in its own module
//! - No integration module depends on another integration module
//! - All integrations use error types from `crate::internal::errors`
//! - Integration failures should be gracefully handled by calling code

// =============================================================================
// SUBMODULE DECLARATIONS
// =============================================================================

/// TLS Proxy gRPC client for packet inspection.
pub mod tls_proxy_client;

// Future modules (Phase 2+):
// pub mod dns_client;
// pub mod metrics_exporter;
// pub mod log_aggregator;

// =============================================================================
// RE-EXPORTS FOR CONVENIENCE
// =============================================================================

pub use tls_proxy_client::TLSProxyClient;
