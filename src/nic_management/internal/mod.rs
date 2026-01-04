// Internal modules
pub mod capture;
pub mod config;
pub mod errors;
pub mod integration;

// Generated proto types from packet_processing.proto
pub mod tlsproxy {
    tonic::include_proto!("tlsproxy");
}
