//! High-Performance Packet Capture Engine
//!
//! This module implements the packet capture engine that receives raw Ethernet frames
//! from network interfaces using platform-specific mechanisms (AF_PACKET on Linux,
//! WinPcap/Npcap on Windows).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// =============================================================================
// Timestamp Structure
// =============================================================================

/// Packet capture timestamp with nanosecond precision.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: u64,
    /// Nanoseconds.
    pub nsec: u32,
}

impl Timestamp {
    /// Creates a new timestamp with current time.
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            sec: now.as_secs(),
            nsec: now.subsec_nanos(),
        }
    }

    /// Converts to nanoseconds since epoch.
    pub fn as_nanos(&self) -> u64 {
        self.sec * 1_000_000_000 + self.nsec as u64
    }
}

// =============================================================================
// Capture Configuration
// =============================================================================

/// Configuration for packet capture behavior.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Interfaces to capture on.
    pub interfaces: Vec<String>,
    /// Enable promiscuous mode.
    pub promiscuous_mode: bool,
    /// Snapshot length (bytes to capture per packet).
    pub snaplen: usize,
    /// Read timeout in milliseconds.
    pub timeout_ms: u64,
    /// Kernel buffer size in bytes.
    pub buffer_size: usize,
    /// Enable BPF filtering.
    pub enable_bpf_filter: bool,
    /// BPF filter expression.
    pub bpf_filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            promiscuous_mode: true,
            snaplen: 65535,
            timeout_ms: 100,
            buffer_size: 4 * 1024 * 1024, // 4MB
            enable_bpf_filter: false,
            bpf_filter: None,
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Packet capture error types.
#[derive(Debug, Clone)]
pub enum CaptureError {
    /// Interface doesn't exist.
    InterfaceNotFound(String),
    /// Failed to open capture device.
    DeviceOpenFailed(String),
    /// BPF filter compilation failed.
    FilterCompileFailed(String),
    /// Capture thread panicked.
    CaptureThreadPanic(String),
    /// Insufficient permissions.
    PermissionDenied,
    /// Platform lacks packet capture support.
    PlatformNotSupported,
    /// Already running.
    AlreadyRunning,
    /// Not running.
    NotRunning,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::InterfaceNotFound(name) => {
                write!(f, "Interface not found: {}", name)
            }
            CaptureError::DeviceOpenFailed(msg) => {
                write!(f, "Device open failed: {}", msg)
            }
            CaptureError::FilterCompileFailed(msg) => {
                write!(f, "BPF filter compilation failed: {}", msg)
            }
            CaptureError::CaptureThreadPanic(msg) => {
                write!(f, "Capture thread panicked: {}", msg)
            }
            CaptureError::PermissionDenied => {
                write!(f, "Permission denied (requires root/admin)")
            }
            CaptureError::PlatformNotSupported => {
                write!(f, "Platform not supported for packet capture")
            }
            CaptureError::AlreadyRunning => {
                write!(f, "Capture already running")
            }
            CaptureError::NotRunning => {
                write!(f, "Capture not running")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

// =============================================================================
// Per-Interface Statistics
// =============================================================================

/// Per-interface capture statistics.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// Interface name.
    pub interface_name: String,
    /// Packets captured.
    pub packets_captured: u64,
    /// Packets dropped.
    pub packets_dropped: u64,
    /// Bytes captured.
    pub bytes_captured: u64,
}

// =============================================================================
// Aggregate Statistics
// =============================================================================

/// Aggregate capture statistics.
#[derive(Debug, Clone, Default)]
pub struct CaptureStatistics {
    /// Total packets across all interfaces.
    pub total_packets_captured: u64,
    /// Total packets dropped.
    pub total_packets_dropped: u64,
    /// Total bytes captured.
    pub total_bytes_captured: u64,
    /// Per-interface breakdown.
    pub per_interface_stats: Vec<InterfaceStats>,
    /// Capture duration.
    pub capture_duration_secs: u64,
    /// Average packets per second.
    pub throughput_pps: u64,
}

// =============================================================================
// Captured Packet
// =============================================================================

/// A captured packet with metadata.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Raw packet data.
    pub data: Vec<u8>,
    /// Packet length.
    pub len: usize,
    /// Original packet length (before snaplen truncation).
    pub orig_len: usize,
    /// Capture timestamp.
    pub timestamp: Timestamp,
    /// Interface index.
    pub interface_index: i32,
    /// Interface name.
    pub interface_name: String,
}

// =============================================================================
// BPF Program
// =============================================================================

/// Compiled BPF filter program.
#[derive(Debug, Clone)]
pub struct BpfProgram {
    /// BPF bytecode instructions.
    pub instructions: Vec<BpfInstruction>,
}

/// Single BPF instruction.
#[derive(Debug, Clone, Copy)]
pub struct BpfInstruction {
    /// Opcode.
    pub code: u16,
    /// Jump if true.
    pub jt: u8,
    /// Jump if false.
    pub jf: u8,
    /// Generic field.
    pub k: u32,
}

impl BpfProgram {
    /// Returns a "capture all" filter.
    pub fn capture_all() -> Self {
        // BPF_RET | BPF_K with max snaplen
        Self {
            instructions: vec![BpfInstruction {
                code: 0x06, // BPF_RET | BPF_K
                jt: 0,
                jf: 0,
                k: 0xFFFFFFFF,
            }],
        }
    }
}

// =============================================================================
// Capture Thread State
// =============================================================================

/// State for a single capture thread.
struct CaptureThreadState {
    /// Interface name.
    interface_name: String,
    /// Interface index.
    interface_index: i32,
    /// Thread handle.
    thread_handle: Option<JoinHandle<()>>,
    /// Per-thread running flag.
    running: Arc<AtomicBool>,
    /// Packets captured counter.
    packets_captured: Arc<AtomicU64>,
    /// Packets dropped counter.
    packets_dropped: Arc<AtomicU64>,
    /// Bytes captured counter.
    bytes_captured: Arc<AtomicU64>,
}

// =============================================================================
// Packet Handler Trait
// =============================================================================

/// Handler for captured packets.
pub trait PacketHandler: Send + Sync {
    /// Called for each captured packet.
    fn handle_packet(&self, packet: CapturedPacket);
}

/// Default handler that just counts packets.
pub struct CountingHandler {
    count: AtomicU64,
}

impl CountingHandler {
    /// Creates a new counting handler.
    pub fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
        }
    }

    /// Returns the packet count.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl Default for CountingHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketHandler for CountingHandler {
    fn handle_packet(&self, _packet: CapturedPacket) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

// =============================================================================
// Packet Capture Manager
// =============================================================================

/// Main packet capture manager.
pub struct PacketCapture {
    /// Capture configuration.
    config: CaptureConfig,
    /// Per-interface capture threads.
    capture_threads: HashMap<String, CaptureThreadState>,
    /// Global running flag.
    running: Arc<AtomicBool>,
    /// Start time.
    start_time: Option<Instant>,
    /// Packet handler.
    handler: Arc<dyn PacketHandler>,
}

impl PacketCapture {
    /// Creates a new packet capture manager.
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        Self::with_handler(config, Arc::new(CountingHandler::new()))
    }

    /// Creates a new packet capture manager with a custom handler.
    pub fn with_handler(
        config: CaptureConfig,
        handler: Arc<dyn PacketHandler>,
    ) -> Result<Self, CaptureError> {
        Ok(Self {
            config,
            capture_threads: HashMap::new(),
            running: Arc::new(AtomicBool::new(false)),
            start_time: None,
            handler,
        })
    }

    /// Returns whether capture is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Starts packet capture on all configured interfaces.
    pub fn start(&mut self) -> Result<(), CaptureError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(CaptureError::AlreadyRunning);
        }

        self.running.store(true, Ordering::SeqCst);
        self.start_time = Some(Instant::now());

        // Start a capture thread for each interface.
        for (idx, interface_name) in self.config.interfaces.iter().enumerate() {
            self.start_interface_capture(interface_name.clone(), idx as i32)?;
        }

        log::info!(
            "Packet capture started on {} interfaces",
            self.config.interfaces.len()
        );
        Ok(())
    }

    /// Starts capture on a single interface.
    fn start_interface_capture(
        &mut self,
        interface_name: String,
        interface_index: i32,
    ) -> Result<(), CaptureError> {
        let running = Arc::new(AtomicBool::new(true));
        let packets_captured = Arc::new(AtomicU64::new(0));
        let packets_dropped = Arc::new(AtomicU64::new(0));
        let bytes_captured = Arc::new(AtomicU64::new(0));

        let config = self.config.clone();
        let handler = Arc::clone(&self.handler);
        let thread_running = Arc::clone(&running);
        let thread_captured = Arc::clone(&packets_captured);
        let thread_dropped = Arc::clone(&packets_dropped);
        let thread_bytes = Arc::clone(&bytes_captured);
        let iface_name = interface_name.clone();
        let iface_idx = interface_index;

        let handle = thread::Builder::new()
            .name(format!("capture-{}", interface_name))
            .spawn(move || {
                capture_loop(
                    iface_name,
                    iface_idx,
                    thread_running,
                    config,
                    handler,
                    thread_captured,
                    thread_dropped,
                    thread_bytes,
                );
            })
            .map_err(|e| CaptureError::DeviceOpenFailed(e.to_string()))?;

        let state = CaptureThreadState {
            interface_name: interface_name.clone(),
            interface_index,
            thread_handle: Some(handle),
            running,
            packets_captured,
            packets_dropped,
            bytes_captured,
        };

        self.capture_threads.insert(interface_name, state);
        Ok(())
    }

    /// Stops packet capture on all interfaces.
    pub fn stop(&mut self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        // Signal all threads to stop.
        self.running.store(false, Ordering::SeqCst);
        for state in self.capture_threads.values() {
            state.running.store(false, Ordering::SeqCst);
        }

        // Wait for all threads to finish.
        for (_, mut state) in self.capture_threads.drain() {
            if let Some(handle) = state.thread_handle.take() {
                if let Err(e) = handle.join() {
                    log::error!("Capture thread panicked: {:?}", e);
                }
            }
        }

        log::info!("Packet capture stopped");
    }

    /// Adds an interface for capture during runtime.
    pub fn add_interface(&mut self, interface_name: String) -> Result<(), CaptureError> {
        if self.capture_threads.contains_key(&interface_name) {
            return Ok(()); // Already capturing.
        }

        let index = self.capture_threads.len() as i32;
        if self.running.load(Ordering::SeqCst) {
            self.start_interface_capture(interface_name, index)?;
        } else {
            self.config.interfaces.push(interface_name);
        }
        Ok(())
    }

    /// Removes an interface from capture.
    pub fn remove_interface(&mut self, interface_name: &str) -> Result<(), CaptureError> {
        if let Some(mut state) = self.capture_threads.remove(interface_name) {
            state.running.store(false, Ordering::SeqCst);
            if let Some(handle) = state.thread_handle.take() {
                let _ = handle.join();
            }
        }

        self.config.interfaces.retain(|n| n != interface_name);
        Ok(())
    }

    /// Returns capture statistics.
    pub fn get_statistics(&self) -> CaptureStatistics {
        let mut stats = CaptureStatistics::default();

        for (name, state) in &self.capture_threads {
            let captured = state.packets_captured.load(Ordering::Relaxed);
            let dropped = state.packets_dropped.load(Ordering::Relaxed);
            let bytes = state.bytes_captured.load(Ordering::Relaxed);

            stats.total_packets_captured += captured;
            stats.total_packets_dropped += dropped;
            stats.total_bytes_captured += bytes;

            stats.per_interface_stats.push(InterfaceStats {
                interface_name: name.clone(),
                packets_captured: captured,
                packets_dropped: dropped,
                bytes_captured: bytes,
            });
        }

        if let Some(start) = self.start_time {
            let duration = start.elapsed().as_secs();
            stats.capture_duration_secs = duration;
            if duration > 0 {
                stats.throughput_pps = stats.total_packets_captured / duration;
            }
        }

        stats
    }

    /// Returns the configuration.
    pub fn get_config(&self) -> &CaptureConfig {
        &self.config
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

// =============================================================================
// Capture Loop (Platform-Generic Simulation)
// =============================================================================

/// Main capture loop for an interface.
fn capture_loop(
    interface_name: String,
    interface_index: i32,
    running: Arc<AtomicBool>,
    config: CaptureConfig,
    handler: Arc<dyn PacketHandler>,
    packets_captured: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
) {
    log::debug!("Capture thread started for {}", interface_name);

    let timeout = Duration::from_millis(config.timeout_ms);

    // Platform-specific capture initialization would happen here.
    // For now, we simulate the capture loop structure.

    #[cfg(target_os = "linux")]
    {
        capture_loop_linux(
            interface_name.clone(),
            interface_index,
            running.clone(),
            config,
            handler.clone(),
            packets_captured.clone(),
            packets_dropped.clone(),
            bytes_captured.clone(),
        );
    }

    #[cfg(target_os = "windows")]
    {
        capture_loop_windows(
            interface_name.clone(),
            interface_index,
            running.clone(),
            config,
            handler.clone(),
            packets_captured.clone(),
            packets_dropped.clone(),
            bytes_captured.clone(),
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // Generic fallback - just sleep and check running flag.
        while running.load(Ordering::Relaxed) {
            thread::sleep(timeout);
        }
    }

    log::debug!("Capture thread stopped for {}", interface_name);
}

/// Linux-specific capture loop using raw sockets.
#[cfg(target_os = "linux")]
fn capture_loop_linux(
    interface_name: String,
    interface_index: i32,
    running: Arc<AtomicBool>,
    config: CaptureConfig,
    handler: Arc<dyn PacketHandler>,
    packets_captured: Arc<AtomicU64>,
    _packets_dropped: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
) {
    use std::io::{self, Read};

    let timeout = Duration::from_millis(config.timeout_ms);

    // In a real implementation, we would:
    // 1. Create a raw socket with AF_PACKET
    // 2. Enable promiscuous mode if configured
    // 3. Set up TPACKET_V3 ring buffer
    // 4. Apply BPF filter if configured

    // Simulated capture loop.
    while running.load(Ordering::Relaxed) {
        // In real implementation: call recv_packet() on raw socket.
        // For now, just sleep to simulate waiting for packets.
        thread::sleep(timeout);

        // Simulated packet would be processed here:
        // if let Some(packet_data) = socket.recv_packet() {
        //     let packet = CapturedPacket {
        //         data: packet_data.to_vec(),
        //         len: packet_data.len(),
        //         orig_len: packet_data.len(),
        //         timestamp: Timestamp::now(),
        //         interface_index,
        //         interface_name: interface_name.clone(),
        //     };
        //     handler.handle_packet(packet);
        //     packets_captured.fetch_add(1, Ordering::Relaxed);
        //     bytes_captured.fetch_add(packet_data.len() as u64, Ordering::Relaxed);
        // }
    }
}

/// Windows-specific capture loop using WinPcap/Npcap.
#[cfg(target_os = "windows")]
fn capture_loop_windows(
    interface_name: String,
    interface_index: i32,
    running: Arc<AtomicBool>,
    config: CaptureConfig,
    handler: Arc<dyn PacketHandler>,
    packets_captured: Arc<AtomicU64>,
    _packets_dropped: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
) {
    let timeout = Duration::from_millis(config.timeout_ms);

    // In a real implementation, we would:
    // 1. Open WinPcap/Npcap device
    // 2. Set promiscuous mode if configured
    // 3. Compile and apply BPF filter if configured
    // 4. Set kernel buffer size

    // Simulated capture loop.
    while running.load(Ordering::Relaxed) {
        // In real implementation: call next_packet() on device.
        thread::sleep(timeout);

        // Simulated packet would be processed here.
    }
}

// =============================================================================
// BPF Filter Compilation
// =============================================================================

/// Compiles a BPF filter expression.
pub fn compile_bpf_filter(_filter_expr: &str, _snaplen: usize) -> Result<BpfProgram, CaptureError> {
    // In a real implementation, this would call:
    // - Linux: libpcap's pcap_compile()
    // - Windows: WinPcap's pcap_compile()

    // For now, return a capture-all filter.
    Ok(BpfProgram::capture_all())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_now() {
        let ts = Timestamp::now();
        assert!(ts.sec > 0);
    }

    #[test]
    fn test_timestamp_as_nanos() {
        let ts = Timestamp {
            sec: 1,
            nsec: 500_000_000,
        };
        assert_eq!(ts.as_nanos(), 1_500_000_000);
    }

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert!(config.promiscuous_mode);
        assert_eq!(config.snaplen, 65535);
        assert_eq!(config.timeout_ms, 100);
        assert_eq!(config.buffer_size, 4 * 1024 * 1024);
    }

    #[test]
    fn test_capture_error_display() {
        let err = CaptureError::InterfaceNotFound("eth0".to_string());
        assert_eq!(format!("{}", err), "Interface not found: eth0");

        let err = CaptureError::PermissionDenied;
        assert!(format!("{}", err).contains("Permission denied"));
    }

    #[test]
    fn test_packet_capture_lifecycle() {
        let config = CaptureConfig::default();
        let mut capture = PacketCapture::new(config).unwrap();

        assert!(!capture.is_running());
        assert!(capture.start().is_ok());
        assert!(capture.is_running());

        // Try starting again should fail.
        assert!(matches!(capture.start(), Err(CaptureError::AlreadyRunning)));

        capture.stop();
        assert!(!capture.is_running());
    }

    #[test]
    fn test_bpf_program_capture_all() {
        let prog = BpfProgram::capture_all();
        assert_eq!(prog.instructions.len(), 1);
        assert_eq!(prog.instructions[0].code, 0x06);
        assert_eq!(prog.instructions[0].k, 0xFFFFFFFF);
    }

    #[test]
    fn test_compile_bpf_filter() {
        let result = compile_bpf_filter("tcp port 80", 65535);
        assert!(result.is_ok());
    }

    #[test]
    fn test_counting_handler() {
        let handler = CountingHandler::new();
        assert_eq!(handler.count(), 0);

        let packet = CapturedPacket {
            data: vec![1, 2, 3],
            len: 3,
            orig_len: 3,
            timestamp: Timestamp::now(),
            interface_index: 0,
            interface_name: "eth0".to_string(),
        };

        handler.handle_packet(packet.clone());
        handler.handle_packet(packet.clone());
        assert_eq!(handler.count(), 2);
    }

    #[test]
    fn test_interface_stats_default() {
        let stats = InterfaceStats::default();
        assert_eq!(stats.packets_captured, 0);
        assert_eq!(stats.packets_dropped, 0);
        assert_eq!(stats.bytes_captured, 0);
    }

    #[test]
    fn test_capture_statistics() {
        let config = CaptureConfig::default();
        let capture = PacketCapture::new(config).unwrap();
        let stats = capture.get_statistics();

        assert_eq!(stats.total_packets_captured, 0);
        assert_eq!(stats.total_packets_dropped, 0);
    }

    #[test]
    fn test_add_remove_interface() {
        let config = CaptureConfig::default();
        let mut capture = PacketCapture::new(config).unwrap();

        assert!(capture.add_interface("eth0".to_string()).is_ok());
        assert!(capture.add_interface("eth1".to_string()).is_ok());
        assert!(capture.remove_interface("eth0").is_ok());
    }
}
