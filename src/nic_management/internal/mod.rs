//! Internal implementation modules for NIC Management.
//!
//! This module contains all core subsystems that implement NIC Management's
//! functionality. Each submodule encapsulates a specific domain or capability
//! with minimal coupling to other subsystems.
//!
//! # Module Organization
//!
//! - **capture** - Packet capture and processing pipeline
//! - **nat** - Network Address Translation state management
//! - **routing** - Packet forwarding and routing decisions
//! - **config** - Configuration loading and validation
//! - **errors** - Centralized error type definitions
//! - **integration** - External service clients (TLS Proxy, DNS, etc.)
//!
//! # Visibility Design
//!
//! Modules use `pub` for types exposed to main.rs and tests, and `pub(crate)`
//! for internal-only types shared between modules but not visible outside
//! the crate. This creates a clear public API boundary.
//!
//! # Phase 1 Extensions
//!
//! Phase 1 adds the integration module containing TLS Proxy client for
//! packet inspection functionality.

// =============================================================================
// CORE MODULES
// =============================================================================

/// Packet capture and processing pipeline.
///
/// Handles raw packet capture from network interfaces, parses protocol
/// headers, and coordinates packet flow through NAT, routing, and
/// inspection subsystems.
pub mod capture;

/// Network Address Translation state management.
///
/// Maintains connection tracking table for source/destination NAT,
/// handles port allocation, and manages connection timeout/expiration.
pub mod nat;

/// Packet forwarding and routing decisions.
///
/// Determines which interface to forward packets to based on destination,
/// manages routing tables, and handles default gateway configuration.
pub mod routing;

// =============================================================================
// CONFIGURATION AND ERROR HANDLING
// =============================================================================

/// Configuration loading and validation.
///
/// Parses config.toml, validates settings, and provides typed configuration
/// structs for all subsystems.
pub mod config;

/// Centralized error type definitions.
///
/// Defines NicError enum with variants for all failure modes across
/// subsystems, implements error conversions, and provides Result type alias.
pub mod errors;

// =============================================================================
// EXTERNAL INTEGRATIONS - PHASE 1
// =============================================================================

/// External service integration clients.
///
/// Contains clients and adapters for communicating with external services
/// that NIC Management depends on. Each integration component is isolated
/// in its own submodule.
///
/// # Current Integrations (Phase 1)
///
/// - **tls_proxy_client** - gRPC client for TLS Proxy packet inspection
///
/// # Future Integrations (Phase 2+)
///
/// - DNS client for direct resolution (bypassing TLS Proxy)
/// - Metrics exporters (Prometheus, StatsD)
/// - Logging aggregation clients
pub mod integration;

// =============================================================================
// RE-EXPORTS FOR CONVENIENCE
// =============================================================================

// Error types - used throughout the codebase
pub use errors::{NicError, Result};

// Configuration types
pub use config::Config;

// TLS Proxy client - needed by main.rs and capture module
pub use integration::TLSProxyClient;
