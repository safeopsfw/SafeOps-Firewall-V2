//! # SafeOps Shared Library
//!
//! High-performance utilities and shared code for SafeOps firewall services.
//! Provides packet processing, IP utilities, fast hashing, lock-free data structures,
//! SIMD optimizations, and Protocol Buffer integration.
//!
//! ## Usage
//!
//! For most use cases, import the prelude:
//!
//! ```
//! use safeops_shared::prelude::*;
//! ```
//!
//! For specific functionality, import individual modules:
//!
//! ```
//! use safeops_shared::ip_utils::parse_cidr;
//! use safeops_shared::hash_utils::xxhash64;
//! use safeops_shared::metrics::MetricsRegistry;
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

// ============================================================================
// Module Declarations
// ============================================================================

/// Error types and Result alias
pub mod error;

/// IP address parsing and CIDR utilities
pub mod ip_utils;

/// Fast hashing algorithms (xxHash, aHash)
pub mod hash_utils;

/// Object pooling for zero-allocation performance
pub mod memory_pool;

/// Lock-free data structures for concurrent access
pub mod lock_free;

/// SIMD-optimized packet parsing
pub mod simd_utils;

/// Time and timestamp utilities
pub mod time_utils;

/// Protocol Buffer helper functions
pub mod proto_utils;

/// Prometheus metrics collection
pub mod metrics;

/// Buffer pooling for packet processing
pub mod buffer_pool;

// ============================================================================
// Generated Proto Code
// ============================================================================

/// Generated Protocol Buffer types and gRPC clients
///
/// This module contains auto-generated code from all 14 proto files:
/// - `common` - Common types (Timestamp, Status, IpAddress, etc.)
/// - `backup_restore` - Backup and restore service
/// - `certificate_manager` - TLS certificate management
/// - `dhcp_server` - DHCP server service
/// - `dns_server` - DNS server service
/// - `firewall` - Firewall rule service
/// - `ids_ips` - Intrusion detection/prevention
/// - `network_logger` - Network logging service
/// - `network_manager` - Network management
/// - `orchestrator` - Service orchestration
/// - `threat_intel` - Threat intelligence service
/// - `tls_proxy` - TLS proxy service
/// - `update_manager` - Update management
/// - `wifi_ap` - WiFi access point service
#[allow(clippy::all)]
#[allow(missing_docs)]
#[allow(warnings)]
pub mod proto;

// ============================================================================
// Root Re-exports - Common Types at Crate Root
// ============================================================================

// Error types - most commonly used
pub use error::{ErrorContext, Result, SafeOpsError};

// IP utilities
pub use ip_utils::{IPAddress, parse_cidr, parse_ip, validate_ip};

// Hashing functions
pub use hash_utils::{xxhash64, xxhash3, ahash_hash, hash_connection_tuple};

// Time utilities
pub use time_utils::{now_unix_timestamp, format_duration, Timer};

// Memory pooling
pub use memory_pool::{MemoryPool, PooledObject, Resettable};

// Buffer pooling
pub use buffer_pool::{BufferPool, PooledBuffer, create_buffer_pool};

// Lock-free structures
pub use lock_free::{MpmcQueue, SpscRingBuffer, ConcurrentHashMap, LockFreeCounter, LockFreeStack};

// Metrics
pub use metrics::{MetricsRegistry, METRICS, metrics_handler};

// ============================================================================
// Prelude Module - Convenience Imports
// ============================================================================

/// Prelude module containing the most commonly used types and functions.
///
/// Import this module to get all essential types in one line:
///
/// ```
/// use safeops_shared::prelude::*;
/// ```
///
/// This provides:
/// - Error types (`SafeOpsError`, `Result`, `ErrorContext`)
/// - IP utilities (`IPAddress`, `parse_ip`, `parse_cidr`)
/// - Hash functions (`xxhash64`, `ahash_hash`)
/// - Time utilities (`now_unix_timestamp`, `Timer`)
/// - Metrics registry
/// - Memory pool types
/// - Common traits and functions
pub mod prelude {
    //! Convenient re-exports of commonly used types

    // Error handling
    pub use crate::error::{ErrorContext, Result, SafeOpsError};
    
    // IP utilities
    pub use crate::ip_utils::{IPAddress, parse_ip, parse_cidr, validate_ip};
    
    // Hashing
    pub use crate::hash_utils::{xxhash64, xxhash3, ahash_hash};
    
    // Time
    pub use crate::time_utils::{now_unix_timestamp, format_duration, Timer};
    
    // Memory pooling
    pub use crate::memory_pool::{MemoryPool, PooledObject};
    
    // Buffer pooling
    pub use crate::buffer_pool::{BufferPool, PooledBuffer, create_buffer_pool};
    
    // Lock-free structures
    pub use crate::lock_free::{MpmcQueue, ConcurrentHashMap, LockFreeCounter};
    
    // Metrics
    pub use crate::metrics::{MetricsRegistry, METRICS};
}
