//! SafeOps Shared Rust Library
//!
//! High-performance utilities for packet processing and memory management.

pub mod ip_utils;
pub mod hash_utils;
pub mod memory_pool;
pub mod lock_free;
pub mod simd_utils;
pub mod proto_utils;
pub mod error;
pub mod time_utils;
pub mod buffer_pool;
pub mod metrics;

pub use error::{Error, Result};
