//! # NIC Rust Packet Processing Engine
//!
//! High-performance packet processing engine for the NIC Management service.
//!
//! ## Architecture
//! - **Zero-copy packet forwarding** using pre-allocated buffer pools
//! - **Lock-free queues** for multi-threaded packet processing
//! - **SIMD acceleration** for packet parsing and checksum calculation
//!
//! ## FFI Safety
//! All FFI functions are marked `extern "C"` and use C-compatible types.
//! The library is designed to be loaded by Go via CGO.
//!
//! ## Threading Model
//! The engine uses a multi-producer multi-consumer model with:
//! - Capture threads pushing to RX queue
//! - Worker threads processing packets
//! - Transmit threads consuming from TX queue

#![crate_name = "nic_rust"]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![allow(dead_code)]

// =============================================================================
// Module Declarations
// =============================================================================

/// FFI bindings for Go interoperability.
pub mod ffi;

/// Packet processor implementation.
mod packet_processor;

// Note: These modules reference files in internal/router/ and internal/nat/
// They are included via path attributes or will be implemented separately

// =============================================================================
// External Crate Imports
// =============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::queue::{ArrayQueue, SegQueue};
use once_cell::sync::Lazy;
use parking_lot::RwLock;

// =============================================================================
// Constants
// =============================================================================

/// Default packet buffer size (bytes) - standard MTU with overhead.
pub const DEFAULT_BUFFER_SIZE: usize = 2048;

/// Maximum packet size (bytes) - supports jumbo frames.
pub const MAX_PACKET_SIZE: usize = 9000;

/// Minimum Ethernet frame size.
pub const MIN_PACKET_SIZE: usize = 64;

/// Default number of packet processing worker threads.
pub const DEFAULT_WORKER_THREADS: usize = 8;

/// Statistics collection interval in milliseconds.
pub const STATS_INTERVAL_MS: u64 = 1000;

/// Default buffer pool size (number of buffers).
pub const DEFAULT_BUFFER_POOL_SIZE: usize = 65536;

/// Default queue depth.
pub const DEFAULT_QUEUE_DEPTH: usize = 4096;

// =============================================================================
// Type Aliases
// =============================================================================

/// Standard result type for packet processing operations.
pub type Result<T> = std::result::Result<T, PacketError>;

/// Lock-free packet queue type.
pub type PacketQueue = ArrayQueue<PacketBuffer>;

/// Lock-free buffer pool type.
pub type BufferPool = SegQueue<Vec<u8>>;

// =============================================================================
// Error Types
// =============================================================================

/// Packet processing error enumeration.
#[derive(Debug, Clone)]
pub enum PacketError {
    /// Malformed or invalid packet.
    InvalidPacket(String),
    /// Routing lookup failed.
    RoutingFailed(String),
    /// NAT translation failed.
    NATFailed(String),
    /// Packet forwarding failed.
    ForwardingFailed(String),
    /// No packet buffers available.
    BufferExhausted,
    /// Packet queue is full.
    QueueFull,
    /// Configuration error.
    ConfigError(String),
    /// Initialization error.
    InitError(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            PacketError::RoutingFailed(msg) => write!(f, "Routing failed: {}", msg),
            PacketError::NATFailed(msg) => write!(f, "NAT failed: {}", msg),
            PacketError::ForwardingFailed(msg) => write!(f, "Forwarding failed: {}", msg),
            PacketError::BufferExhausted => write!(f, "Buffer pool exhausted"),
            PacketError::QueueFull => write!(f, "Packet queue full"),
            PacketError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            PacketError::InitError(msg) => write!(f, "Initialization error: {}", msg),
        }
    }
}

impl std::error::Error for PacketError {}

// =============================================================================
// Packet Buffer Structure
// =============================================================================

/// A packet buffer for zero-copy packet processing.
#[derive(Debug)]
pub struct PacketBuffer {
    /// Raw packet data.
    pub data: Vec<u8>,
    /// Actual packet length.
    pub len: usize,
    /// Source interface index.
    pub src_interface: u32,
    /// Destination interface index (after routing).
    pub dst_interface: u32,
    /// Timestamp when packet was received.
    pub timestamp: u64,
    /// Flags for packet processing state.
    pub flags: u32,
}

impl PacketBuffer {
    /// Creates a new packet buffer with specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            len: 0,
            src_interface: 0,
            dst_interface: 0,
            timestamp: 0,
            flags: 0,
        }
    }

    /// Creates a packet buffer from existing data.
    pub fn from_data(data: Vec<u8>, src_interface: u32) -> Self {
        let len = data.len();
        Self {
            data,
            len,
            src_interface,
            dst_interface: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            flags: 0,
        }
    }

    /// Returns the packet data slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns mutable packet data slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

// =============================================================================
// Engine Configuration
// =============================================================================

/// Engine configuration structure.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Number of packet buffers in the pool.
    pub buffer_pool_size: usize,
    /// Size of each packet buffer in bytes.
    pub buffer_size: usize,
    /// RX queue depth.
    pub rx_queue_depth: usize,
    /// TX queue depth.
    pub tx_queue_depth: usize,
    /// Number of packet processing worker threads.
    pub worker_threads: usize,
    /// Enable SIMD acceleration.
    pub enable_simd: bool,
    /// Enable zero-copy forwarding.
    pub enable_zerocopy: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            buffer_pool_size: DEFAULT_BUFFER_POOL_SIZE,
            buffer_size: DEFAULT_BUFFER_SIZE,
            rx_queue_depth: DEFAULT_QUEUE_DEPTH,
            tx_queue_depth: DEFAULT_QUEUE_DEPTH,
            worker_threads: DEFAULT_WORKER_THREADS,
            enable_simd: true,
            enable_zerocopy: true,
        }
    }
}

impl EngineConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.buffer_pool_size == 0 {
            return Err(PacketError::ConfigError(
                "buffer_pool_size must be greater than 0".to_string(),
            ));
        }
        if self.buffer_size < MIN_PACKET_SIZE {
            return Err(PacketError::ConfigError(format!(
                "buffer_size must be at least {} bytes",
                MIN_PACKET_SIZE
            )));
        }
        if self.buffer_size > MAX_PACKET_SIZE {
            return Err(PacketError::ConfigError(format!(
                "buffer_size must be at most {} bytes",
                MAX_PACKET_SIZE
            )));
        }
        if self.rx_queue_depth == 0 || self.tx_queue_depth == 0 {
            return Err(PacketError::ConfigError(
                "queue depth must be greater than 0".to_string(),
            ));
        }
        if self.worker_threads == 0 {
            return Err(PacketError::ConfigError(
                "worker_threads must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// Forwarding Statistics
// =============================================================================

/// Performance statistics for the packet forwarding engine.
#[derive(Debug, Clone, Default)]
pub struct ForwardingStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets forwarded.
    pub packets_forwarded: u64,
    /// Total packets dropped.
    pub packets_dropped: u64,
    /// Total NAT translations performed.
    pub nat_translations: u64,
    /// Total routing lookups.
    pub routing_decisions: u64,
    /// Total forwarding errors.
    pub forwarding_errors: u64,
    /// Current RX queue depth.
    pub rx_queue_depth: usize,
    /// Current TX queue depth.
    pub tx_queue_depth: usize,
    /// Available buffer count.
    pub available_buffers: usize,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
}

// =============================================================================
// Route Entry
// =============================================================================

/// Routing table entry.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination network (CIDR format string).
    pub destination: String,
    /// Next hop IP address.
    pub gateway: String,
    /// Outgoing interface index.
    pub interface_index: u32,
    /// Route metric (lower is preferred).
    pub metric: u32,
    /// Route flags.
    pub flags: u32,
}

// =============================================================================
// NAT Mapping
// =============================================================================

/// NAT mapping entry.
#[derive(Debug, Clone)]
pub struct NATMapping {
    /// Original source IP.
    pub original_src_ip: u32,
    /// Original source port.
    pub original_src_port: u16,
    /// Translated source IP.
    pub translated_src_ip: u32,
    /// Translated source port.
    pub translated_src_port: u16,
    /// Protocol (TCP=6, UDP=17).
    pub protocol: u8,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last packet timestamp.
    pub last_used: u64,
    /// Bytes transferred.
    pub bytes_transferred: u64,
}

// =============================================================================
// Global State
// =============================================================================

/// Global engine state (lazily initialized).
static ENGINE_STATE: Lazy<RwLock<Option<EngineState>>> = Lazy::new(|| RwLock::new(None));

/// Engine running flag.
static ENGINE_RUNNING: AtomicBool = AtomicBool::new(false);

/// Global atomic performance counters.
static PACKETS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static PACKETS_FORWARDED: AtomicU64 = AtomicU64::new(0);
static PACKETS_DROPPED: AtomicU64 = AtomicU64::new(0);
static NAT_TRANSLATIONS: AtomicU64 = AtomicU64::new(0);
static ROUTING_DECISIONS: AtomicU64 = AtomicU64::new(0);
static FORWARDING_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Engine state containing all runtime data.
struct EngineState {
    /// Configuration.
    config: EngineConfig,
    /// Buffer pool.
    buffer_pool: Arc<BufferPool>,
    /// RX queue.
    rx_queue: Arc<PacketQueue>,
    /// TX queue.
    tx_queue: Arc<PacketQueue>,
    /// Start time.
    start_time: Instant,
    /// Routing table (interface index -> routes).
    routing_table: Arc<RwLock<HashMap<u32, Vec<RouteEntry>>>>,
    /// NAT table (5-tuple hash -> mapping).
    nat_table: Arc<RwLock<HashMap<u64, NATMapping>>>,
}

// =============================================================================
// Initialization Function
// =============================================================================

/// Initializes the Rust packet processing engine.
///
/// This function should be called once at service startup from Go via FFI.
///
/// # Arguments
/// * `config` - Engine configuration
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub fn initialize_rust_engine(config: EngineConfig) -> std::result::Result<(), String> {
    // Validate configuration.
    config.validate().map_err(|e| e.to_string())?;

    // Check if already initialized.
    if ENGINE_RUNNING.load(Ordering::SeqCst) {
        return Err("Engine already initialized".to_string());
    }

    // Create buffer pool.
    let buffer_pool = Arc::new(SegQueue::new());
    for _ in 0..config.buffer_pool_size {
        buffer_pool.push(vec![0u8; config.buffer_size]);
    }

    // Create packet queues.
    let rx_queue = Arc::new(ArrayQueue::new(config.rx_queue_depth));
    let tx_queue = Arc::new(ArrayQueue::new(config.tx_queue_depth));

    // Create routing and NAT tables.
    let routing_table = Arc::new(RwLock::new(HashMap::new()));
    let nat_table = Arc::new(RwLock::new(HashMap::new()));

    // Create engine state.
    let state = EngineState {
        config,
        buffer_pool,
        rx_queue,
        tx_queue,
        start_time: Instant::now(),
        routing_table,
        nat_table,
    };

    // Store state.
    {
        let mut engine = ENGINE_STATE.write();
        *engine = Some(state);
    }

    // Set running flag.
    ENGINE_RUNNING.store(true, Ordering::SeqCst);

    // Reset counters.
    PACKETS_RECEIVED.store(0, Ordering::Relaxed);
    PACKETS_FORWARDED.store(0, Ordering::Relaxed);
    PACKETS_DROPPED.store(0, Ordering::Relaxed);
    NAT_TRANSLATIONS.store(0, Ordering::Relaxed);
    ROUTING_DECISIONS.store(0, Ordering::Relaxed);
    FORWARDING_ERRORS.store(0, Ordering::Relaxed);

    log::info!("Rust packet processing engine initialized successfully");
    Ok(())
}

/// Initializes the engine with default configuration.
pub fn initialize_default() -> std::result::Result<(), String> {
    initialize_rust_engine(EngineConfig::default())
}

// =============================================================================
// Shutdown Function
// =============================================================================

/// Shuts down the Rust packet processing engine.
///
/// This function should be called at service shutdown from Go via FFI.
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub fn shutdown_rust_engine() -> std::result::Result<(), String> {
    // Check if running.
    if !ENGINE_RUNNING.load(Ordering::SeqCst) {
        return Err("Engine not running".to_string());
    }

    // Signal shutdown.
    ENGINE_RUNNING.store(false, Ordering::SeqCst);

    // Log final statistics.
    let stats = get_forwarding_stats();
    log::info!(
        "Engine shutdown - Received: {}, Forwarded: {}, Dropped: {}",
        stats.packets_received,
        stats.packets_forwarded,
        stats.packets_dropped
    );

    // Clear state.
    {
        let mut engine = ENGINE_STATE.write();
        *engine = None;
    }

    log::info!("Rust packet processing engine shut down successfully");
    Ok(())
}

// =============================================================================
// Status and Statistics
// =============================================================================

/// Returns whether the engine is currently running.
pub fn is_engine_running() -> bool {
    ENGINE_RUNNING.load(Ordering::SeqCst)
}

/// Returns current forwarding statistics.
pub fn get_forwarding_stats() -> ForwardingStats {
    let engine = ENGINE_STATE.read();

    let (rx_depth, tx_depth, available_buffers, uptime) = match engine.as_ref() {
        Some(state) => (
            state.rx_queue.len(),
            state.tx_queue.len(),
            state.buffer_pool.len(),
            state.start_time.elapsed().as_secs(),
        ),
        None => (0, 0, 0, 0),
    };

    ForwardingStats {
        packets_received: PACKETS_RECEIVED.load(Ordering::Relaxed),
        packets_forwarded: PACKETS_FORWARDED.load(Ordering::Relaxed),
        packets_dropped: PACKETS_DROPPED.load(Ordering::Relaxed),
        nat_translations: NAT_TRANSLATIONS.load(Ordering::Relaxed),
        routing_decisions: ROUTING_DECISIONS.load(Ordering::Relaxed),
        forwarding_errors: FORWARDING_ERRORS.load(Ordering::Relaxed),
        rx_queue_depth: rx_depth,
        tx_queue_depth: tx_depth,
        available_buffers,
        uptime_seconds: uptime,
    }
}

// =============================================================================
// Counter Increment Functions
// =============================================================================

/// Increments the packets received counter.
#[inline]
pub fn inc_packets_received() {
    PACKETS_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// Increments the packets forwarded counter.
#[inline]
pub fn inc_packets_forwarded() {
    PACKETS_FORWARDED.fetch_add(1, Ordering::Relaxed);
}

/// Increments the packets dropped counter.
#[inline]
pub fn inc_packets_dropped() {
    PACKETS_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Increments the NAT translations counter.
#[inline]
pub fn inc_nat_translations() {
    NAT_TRANSLATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Increments the routing decisions counter.
#[inline]
pub fn inc_routing_decisions() {
    ROUTING_DECISIONS.fetch_add(1, Ordering::Relaxed);
}

/// Increments the forwarding errors counter.
#[inline]
pub fn inc_forwarding_errors() {
    FORWARDING_ERRORS.fetch_add(1, Ordering::Relaxed);
}

// =============================================================================
// Buffer Pool Operations
// =============================================================================

/// Acquires a buffer from the pool.
pub fn acquire_buffer() -> Option<Vec<u8>> {
    let engine = ENGINE_STATE.read();
    engine.as_ref().and_then(|state| state.buffer_pool.pop())
}

/// Returns a buffer to the pool.
pub fn release_buffer(buffer: Vec<u8>) {
    let engine = ENGINE_STATE.read();
    if let Some(state) = engine.as_ref() {
        state.buffer_pool.push(buffer);
    }
}

// =============================================================================
// Queue Operations
// =============================================================================

/// Enqueues a packet to the RX queue.
pub fn enqueue_rx(packet: PacketBuffer) -> std::result::Result<(), PacketBuffer> {
    let engine = ENGINE_STATE.read();
    if let Some(state) = engine.as_ref() {
        state.rx_queue.push(packet)
    } else {
        Err(packet)
    }
}

/// Dequeues a packet from the RX queue.
pub fn dequeue_rx() -> Option<PacketBuffer> {
    let engine = ENGINE_STATE.read();
    engine.as_ref().and_then(|state| state.rx_queue.pop())
}

/// Enqueues a packet to the TX queue.
pub fn enqueue_tx(packet: PacketBuffer) -> std::result::Result<(), PacketBuffer> {
    let engine = ENGINE_STATE.read();
    if let Some(state) = engine.as_ref() {
        state.tx_queue.push(packet)
    } else {
        Err(packet)
    }
}

/// Dequeues a packet from the TX queue.
pub fn dequeue_tx() -> Option<PacketBuffer> {
    let engine = ENGINE_STATE.read();
    engine.as_ref().and_then(|state| state.tx_queue.pop())
}

// =============================================================================
// Version Information
// =============================================================================

/// Returns the library version.
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the library name.
pub fn get_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

// =============================================================================
// Platform-Specific Modules
// =============================================================================

// Note: Platform-specific modules are located in internal/driver/
// - raw_socket_linux.rs: Linux AF_PACKET implementation
// They are compiled separately and linked via FFI.

// =============================================================================
// Re-exports
// =============================================================================

pub use ffi::*;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.buffer_pool_size, DEFAULT_BUFFER_POOL_SIZE);
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(config.rx_queue_depth, DEFAULT_QUEUE_DEPTH);
        assert_eq!(config.tx_queue_depth, DEFAULT_QUEUE_DEPTH);
        assert_eq!(config.worker_threads, DEFAULT_WORKER_THREADS);
    }

    #[test]
    fn test_config_validation() {
        let mut config = EngineConfig::default();
        assert!(config.validate().is_ok());

        config.buffer_pool_size = 0;
        assert!(config.validate().is_err());

        config.buffer_pool_size = 1000;
        config.buffer_size = 10; // Too small
        assert!(config.validate().is_err());

        config.buffer_size = 10000; // Too large
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_packet_buffer_creation() {
        let buf = PacketBuffer::new(1500);
        assert_eq!(buf.data.len(), 1500);
        assert_eq!(buf.len, 0);
        assert_eq!(buf.src_interface, 0);
    }

    #[test]
    fn test_packet_buffer_from_data() {
        let data = vec![1, 2, 3, 4, 5];
        let buf = PacketBuffer::from_data(data.clone(), 1);
        assert_eq!(buf.len, 5);
        assert_eq!(buf.src_interface, 1);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_packet_error_display() {
        let err = PacketError::InvalidPacket("test".to_string());
        assert_eq!(format!("{}", err), "Invalid packet: test");

        let err = PacketError::BufferExhausted;
        assert_eq!(format!("{}", err), "Buffer pool exhausted");
    }

    #[test]
    fn test_forwarding_stats_default() {
        let stats = ForwardingStats::default();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_forwarded, 0);
        assert_eq!(stats.packets_dropped, 0);
    }

    #[test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}
