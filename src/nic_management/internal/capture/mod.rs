//! Packet capture module for network interface monitoring.
//!
//! Contains the core packet processing pipeline with TLS Proxy integration.

pub mod packet_capture;

pub use packet_capture::{CaptureStatistics, PacketCapture, Protocol, StatisticsSnapshot};
