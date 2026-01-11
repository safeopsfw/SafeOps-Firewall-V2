//! NIC Management Rust Library Entry Point

// Import from internal directory
#[path = "../internal/mod.rs"]
pub mod internal;

// Re-export key types
pub use internal::config::Config;
pub use internal::capture::PacketCapture;
pub use internal::integration::TLSProxyClient;
pub use internal::errors::NicError;
