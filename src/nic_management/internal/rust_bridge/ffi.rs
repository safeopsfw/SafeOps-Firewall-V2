//! FFI Bindings for Go Interoperability
//!
//! This module implements the Foreign Function Interface (FFI) layer that exposes
//! Rust packet processing functions to Go code via C-compatible ABI.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic;
use std::ptr;
use std::slice;
use std::sync::atomic::Ordering;

use crate::{
    acquire_buffer, dequeue_tx, enqueue_rx, get_forwarding_stats, inc_packets_dropped,
    inc_packets_received, initialize_rust_engine, is_engine_running, release_buffer,
    shutdown_rust_engine, EngineConfig, PacketBuffer, DEFAULT_BUFFER_SIZE, MAX_PACKET_SIZE,
};

// =============================================================================
// Thread-Local Error Storage
// =============================================================================

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

/// Sets the last error message for the current thread.
fn set_last_error(err: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err);
    });
}

/// Clears the last error message.
fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// =============================================================================
// FFI-Safe Type Definitions
// =============================================================================

/// C-compatible engine configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CEngineConfig {
    /// Number of packet buffers in the pool.
    pub buffer_pool_size: usize,
    /// Size of each buffer in bytes.
    pub buffer_size: usize,
    /// RX queue depth.
    pub rx_queue_depth: usize,
    /// TX queue depth.
    pub tx_queue_depth: usize,
    /// Number of worker threads.
    pub worker_threads: usize,
    /// Enable SIMD acceleration (1=true, 0=false).
    pub enable_simd: c_int,
    /// Enable zero-copy forwarding (1=true, 0=false).
    pub enable_zerocopy: c_int,
}

impl Default for CEngineConfig {
    fn default() -> Self {
        Self {
            buffer_pool_size: 65536,
            buffer_size: DEFAULT_BUFFER_SIZE,
            rx_queue_depth: 4096,
            tx_queue_depth: 4096,
            worker_threads: 8,
            enable_simd: 1,
            enable_zerocopy: 1,
        }
    }
}

impl From<CEngineConfig> for EngineConfig {
    fn from(c: CEngineConfig) -> Self {
        Self {
            buffer_pool_size: c.buffer_pool_size,
            buffer_size: c.buffer_size,
            rx_queue_depth: c.rx_queue_depth,
            tx_queue_depth: c.tx_queue_depth,
            worker_threads: c.worker_threads,
            enable_simd: c.enable_simd != 0,
            enable_zerocopy: c.enable_zerocopy != 0,
        }
    }
}

/// C-compatible packet buffer.
#[repr(C)]
#[derive(Debug)]
pub struct CPacketBuffer {
    /// Pointer to packet data.
    pub data: *mut u8,
    /// Packet length.
    pub len: usize,
    /// Buffer capacity.
    pub capacity: usize,
    /// Source interface index.
    pub src_interface: u32,
    /// Destination interface index.
    pub dst_interface: u32,
    /// Timestamp seconds.
    pub timestamp_sec: u64,
    /// Timestamp nanoseconds.
    pub timestamp_nsec: u32,
    /// Packet flags.
    pub flags: u32,
}

impl Default for CPacketBuffer {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
            src_interface: 0,
            dst_interface: 0,
            timestamp_sec: 0,
            timestamp_nsec: 0,
            flags: 0,
        }
    }
}

/// C-compatible NAT mapping entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CNATMapping {
    /// Original source IP (host byte order).
    pub original_src_ip: u32,
    /// Original source port.
    pub original_src_port: u16,
    /// Translated source IP (host byte order).
    pub translated_src_ip: u32,
    /// Translated source port.
    pub translated_src_port: u16,
    /// Protocol (6=TCP, 17=UDP, 1=ICMP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _padding: [u8; 3],
    /// Creation timestamp.
    pub created_at: u64,
    /// Last used timestamp.
    pub last_used: u64,
    /// Bytes transferred.
    pub bytes_transferred: u64,
}

/// C-compatible forwarding statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CForwardingStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets forwarded.
    pub packets_forwarded: u64,
    /// Total packets dropped.
    pub packets_dropped: u64,
    /// Total NAT translations.
    pub nat_translations: u64,
    /// Total routing decisions.
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

/// C-compatible route entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CRouteEntry {
    /// Destination IP (host byte order).
    pub destination_ip: u32,
    /// Network mask.
    pub netmask: u32,
    /// Gateway IP.
    pub gateway_ip: u32,
    /// Outgoing interface index.
    pub interface_index: c_int,
    /// Route metric.
    pub metric: u32,
    /// Route flags.
    pub flags: u32,
}

// =============================================================================
// Panic Hook
// =============================================================================

/// Installs a panic hook to catch Rust panics before they cross the FFI boundary.
fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        let location = if let Some(loc) = info.location() {
            format!(" at {}:{}", loc.file(), loc.line())
        } else {
            String::new()
        };

        let error_msg = format!("Rust panic{}: {}", location, msg);
        eprintln!("[RUST PANIC] {}", error_msg);
        set_last_error(error_msg);
    }));
}

// =============================================================================
// Engine Initialization FFI
// =============================================================================

/// Initializes the Rust packet processing engine.
///
/// # Arguments
/// * `config` - Pointer to CEngineConfig structure
///
/// # Returns
/// * 0 on success
/// * -1 on error (call rust_get_last_error for details)
///
/// # Safety
/// The config pointer must be valid and point to a properly initialized CEngineConfig.
#[no_mangle]
pub extern "C" fn rust_engine_initialize(config: *const CEngineConfig) -> c_int {
    clear_last_error();
    install_panic_hook();

    let result = panic::catch_unwind(|| {
        // Validate config pointer.
        if config.is_null() {
            set_last_error("Config pointer is null".to_string());
            return -1;
        }

        // Convert C config to Rust config.
        let c_config = unsafe { *config };
        let rust_config: EngineConfig = c_config.into();

        // Initialize engine.
        match initialize_rust_engine(rust_config) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(e);
                -1
            }
        }
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during engine initialization".to_string());
        -1
    })
}

/// Initializes the engine with default configuration.
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[no_mangle]
pub extern "C" fn rust_engine_initialize_default() -> c_int {
    let config = CEngineConfig::default();
    rust_engine_initialize(&config)
}

// =============================================================================
// Engine Shutdown FFI
// =============================================================================

/// Shuts down the Rust packet processing engine.
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[no_mangle]
pub extern "C" fn rust_engine_shutdown() -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| match shutdown_rust_engine() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during engine shutdown".to_string());
        -1
    })
}

/// Returns whether the engine is currently running.
///
/// # Returns
/// * 1 if running
/// * 0 if not running
#[no_mangle]
pub extern "C" fn rust_engine_is_running() -> c_int {
    if is_engine_running() {
        1
    } else {
        0
    }
}

// =============================================================================
// Packet Submission FFI
// =============================================================================

/// Submits a packet to the Rust engine for processing.
///
/// # Arguments
/// * `data` - Pointer to packet data
/// * `len` - Packet length
/// * `interface_index` - Source interface index
///
/// # Returns
/// * 0 on success
/// * -1 on error (queue full, invalid parameters, etc.)
///
/// # Safety
/// The data pointer must be valid and point to at least `len` bytes.
/// Go retains ownership of the data; Rust copies it.
#[no_mangle]
pub extern "C" fn rust_submit_packet(data: *const u8, len: usize, interface_index: c_int) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // Validate parameters.
        if data.is_null() {
            set_last_error("Packet data pointer is null".to_string());
            return -1;
        }
        if len == 0 {
            set_last_error("Packet length is zero".to_string());
            return -1;
        }
        if len > MAX_PACKET_SIZE {
            set_last_error(format!(
                "Packet length {} exceeds maximum {}",
                len, MAX_PACKET_SIZE
            ));
            return -1;
        }

        // Acquire a buffer from the pool.
        let mut buffer = match acquire_buffer() {
            Some(buf) => buf,
            None => {
                set_last_error("Buffer pool exhausted".to_string());
                inc_packets_dropped();
                return -1;
            }
        };

        // Copy packet data.
        let packet_data = unsafe { slice::from_raw_parts(data, len) };
        buffer.clear();
        buffer.extend_from_slice(packet_data);

        // Create packet buffer.
        let packet = PacketBuffer::from_data(buffer, interface_index as u32);

        // Enqueue packet.
        match enqueue_rx(packet) {
            Ok(()) => {
                inc_packets_received();
                0
            }
            Err(pkt) => {
                // Return buffer to pool.
                release_buffer(pkt.data);
                set_last_error("RX queue full".to_string());
                inc_packets_dropped();
                -1
            }
        }
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during packet submission".to_string());
        -1
    })
}

// =============================================================================
// Packet Retrieval FFI
// =============================================================================

/// Retrieves a processed packet from the Rust engine.
///
/// # Arguments
/// * `out_buffer` - Pointer to CPacketBuffer to receive packet
///
/// # Returns
/// * 0 on success (packet retrieved)
/// * -1 if no packet available or error
///
/// # Safety
/// The out_buffer pointer must be valid.
/// Caller must call rust_free_packet() to release the returned data.
#[no_mangle]
pub extern "C" fn rust_retrieve_packet(out_buffer: *mut CPacketBuffer) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // Validate output pointer.
        if out_buffer.is_null() {
            set_last_error("Output buffer pointer is null".to_string());
            return -1;
        }

        // Try to dequeue a packet.
        let packet = match dequeue_tx() {
            Some(pkt) => pkt,
            None => {
                return -1; // No packet available (not an error).
            }
        };

        // Convert to C-compatible format.
        let mut data = packet.data;
        let len = packet.len;
        let capacity = data.capacity();

        // Transfer ownership to Go.
        let data_ptr = data.as_mut_ptr();
        std::mem::forget(data); // Prevent Rust from dropping the buffer.

        // Fill output structure.
        unsafe {
            (*out_buffer).data = data_ptr;
            (*out_buffer).len = len;
            (*out_buffer).capacity = capacity;
            (*out_buffer).src_interface = packet.src_interface;
            (*out_buffer).dst_interface = packet.dst_interface;
            (*out_buffer).timestamp_sec = packet.timestamp / 1_000_000_000;
            (*out_buffer).timestamp_nsec = (packet.timestamp % 1_000_000_000) as u32;
            (*out_buffer).flags = packet.flags;
        }

        0
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during packet retrieval".to_string());
        -1
    })
}

/// Frees a packet buffer previously returned by rust_retrieve_packet.
///
/// # Arguments
/// * `packet` - Pointer to CPacketBuffer to free
///
/// # Safety
/// Must only be called once per packet retrieved from rust_retrieve_packet.
#[no_mangle]
pub extern "C" fn rust_free_packet(packet: *mut CPacketBuffer) {
    if packet.is_null() {
        return;
    }

    let result = panic::catch_unwind(|| {
        let c_packet = unsafe { &*packet };

        if c_packet.data.is_null() || c_packet.capacity == 0 {
            return;
        }

        // Reconstruct Vec to properly deallocate.
        let buffer = unsafe { Vec::from_raw_parts(c_packet.data, c_packet.len, c_packet.capacity) };

        // Return buffer to pool for reuse.
        release_buffer(buffer);

        // Clear the packet structure.
        unsafe {
            (*packet).data = ptr::null_mut();
            (*packet).len = 0;
            (*packet).capacity = 0;
        }
    });

    if result.is_err() {
        eprintln!("[RUST ERROR] Panic during packet free");
    }
}

// =============================================================================
// Statistics Retrieval FFI
// =============================================================================

/// Retrieves forwarding statistics.
///
/// # Arguments
/// * `out_stats` - Pointer to CForwardingStats to receive statistics
///
/// # Returns
/// * 0 on success
/// * -1 on error
///
/// # Safety
/// The out_stats pointer must be valid.
#[no_mangle]
pub extern "C" fn rust_get_stats(out_stats: *mut CForwardingStats) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        if out_stats.is_null() {
            set_last_error("Stats pointer is null".to_string());
            return -1;
        }

        let stats = get_forwarding_stats();

        unsafe {
            (*out_stats).packets_received = stats.packets_received;
            (*out_stats).packets_forwarded = stats.packets_forwarded;
            (*out_stats).packets_dropped = stats.packets_dropped;
            (*out_stats).nat_translations = stats.nat_translations;
            (*out_stats).routing_decisions = stats.routing_decisions;
            (*out_stats).forwarding_errors = stats.forwarding_errors;
            (*out_stats).rx_queue_depth = stats.rx_queue_depth;
            (*out_stats).tx_queue_depth = stats.tx_queue_depth;
            (*out_stats).available_buffers = stats.available_buffers;
            (*out_stats).uptime_seconds = stats.uptime_seconds;
        }

        0
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during stats retrieval".to_string());
        -1
    })
}

// =============================================================================
// NAT Mapping Query FFI
// =============================================================================

/// Retrieves NAT mappings.
///
/// # Arguments
/// * `out_array` - Pointer to array of CNATMapping
/// * `max_count` - Maximum number of mappings to return
/// * `out_count` - Pointer to receive actual number of mappings
///
/// # Returns
/// * 0 on success
/// * -1 on error
///
/// # Safety
/// out_array must be valid and have space for at least max_count entries.
#[no_mangle]
pub extern "C" fn rust_get_nat_mappings(
    out_array: *mut CNATMapping,
    max_count: usize,
    out_count: *mut usize,
) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        if out_array.is_null() || out_count.is_null() {
            set_last_error("Output pointer is null".to_string());
            return -1;
        }
        if max_count == 0 {
            unsafe { *out_count = 0 };
            return 0;
        }

        // NAT table access would go here.
        // For now, return 0 mappings.
        unsafe { *out_count = 0 };
        0
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during NAT mapping query".to_string());
        -1
    })
}

// =============================================================================
// Route Update FFI
// =============================================================================

/// Updates the routing table.
///
/// # Arguments
/// * `routes` - Pointer to array of CRouteEntry
/// * `count` - Number of routes
///
/// # Returns
/// * 0 on success
/// * -1 on error
///
/// # Safety
/// routes must be valid and have at least count entries.
#[no_mangle]
pub extern "C" fn rust_update_routes(routes: *const CRouteEntry, count: usize) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        if routes.is_null() && count > 0 {
            set_last_error("Routes pointer is null".to_string());
            return -1;
        }

        // Route table update would go here.
        // For now, just return success.
        0
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during route update".to_string());
        -1
    })
}

// =============================================================================
// Interface State Update FFI
// =============================================================================

/// Notifies Rust of interface state changes.
///
/// # Arguments
/// * `interface_index` - Interface index
/// * `state` - State (0=DOWN, 1=UP, 2=DORMANT)
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[no_mangle]
pub extern "C" fn rust_interface_state_changed(interface_index: c_int, state: u8) -> c_int {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // Interface state update would go here.
        // For now, just log and return success.
        let state_str = match state {
            0 => "DOWN",
            1 => "UP",
            2 => "DORMANT",
            _ => "UNKNOWN",
        };

        log::debug!(
            "Interface {} state changed to {}",
            interface_index,
            state_str
        );
        0
    });

    result.unwrap_or_else(|_| {
        set_last_error("Panic during interface state change".to_string());
        -1
    })
}

// =============================================================================
// Error Retrieval FFI
// =============================================================================

/// Retrieves the last error message.
///
/// # Arguments
/// * `buffer` - Pointer to char buffer
/// * `buffer_size` - Size of buffer
///
/// # Returns
/// * Length of error string on success
/// * 0 if no error
/// * -1 on invalid parameters
///
/// # Safety
/// buffer must be valid and have at least buffer_size bytes.
#[no_mangle]
pub extern "C" fn rust_get_last_error(buffer: *mut c_char, buffer_size: usize) -> c_int {
    if buffer.is_null() || buffer_size == 0 {
        return -1;
    }

    LAST_ERROR.with(|e| {
        let error = e.borrow();
        match error.as_ref() {
            Some(msg) => {
                let c_string = match CString::new(msg.as_str()) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };
                let bytes = c_string.as_bytes_with_nul();
                let copy_len = std::cmp::min(bytes.len(), buffer_size);

                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, copy_len);
                    // Ensure null termination
                    if copy_len < buffer_size {
                        *buffer.add(copy_len) = 0;
                    } else {
                        *buffer.add(buffer_size - 1) = 0;
                    }
                }

                (copy_len - 1) as c_int // Exclude null terminator from length
            }
            None => 0,
        }
    })
}

/// Clears the last error.
#[no_mangle]
pub extern "C" fn rust_clear_last_error() {
    clear_last_error();
}

// =============================================================================
// Version Information FFI
// =============================================================================

/// Returns the library version string.
///
/// # Returns
/// Pointer to null-terminated version string (static lifetime).
#[no_mangle]
pub extern "C" fn rust_get_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts a C string to a Rust String.
#[allow(dead_code)]
fn convert_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

/// Converts an IP from u32 to byte array (network byte order).
#[allow(dead_code)]
fn ip_u32_to_bytes(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}

/// Converts an IP from byte array to u32 (network byte order).
#[allow(dead_code)]
fn ip_bytes_to_u32(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_engine_config_default() {
        let config = CEngineConfig::default();
        assert_eq!(config.buffer_pool_size, 65536);
        assert_eq!(config.rx_queue_depth, 4096);
        assert_eq!(config.tx_queue_depth, 4096);
        assert_eq!(config.worker_threads, 8);
    }

    #[test]
    fn test_config_conversion() {
        let c_config = CEngineConfig {
            buffer_pool_size: 1000,
            buffer_size: 2048,
            rx_queue_depth: 512,
            tx_queue_depth: 512,
            worker_threads: 4,
            enable_simd: 1,
            enable_zerocopy: 0,
        };

        let rust_config: EngineConfig = c_config.into();
        assert_eq!(rust_config.buffer_pool_size, 1000);
        assert_eq!(rust_config.rx_queue_depth, 512);
        assert!(rust_config.enable_simd);
        assert!(!rust_config.enable_zerocopy);
    }

    #[test]
    fn test_ip_conversion() {
        let ip: u32 = 0xC0A80001; // 192.168.0.1
        let bytes = ip_u32_to_bytes(ip);
        assert_eq!(bytes, [192, 168, 0, 1]);

        let back = ip_bytes_to_u32(bytes);
        assert_eq!(back, ip);
    }

    #[test]
    fn test_error_handling() {
        clear_last_error();
        set_last_error("Test error".to_string());

        let mut buffer = [0i8; 256];
        let len = rust_get_last_error(buffer.as_mut_ptr(), buffer.len());
        assert!(len > 0);
    }

    #[test]
    fn test_c_packet_buffer_default() {
        let buf = CPacketBuffer::default();
        assert!(buf.data.is_null());
        assert_eq!(buf.len, 0);
        assert_eq!(buf.capacity, 0);
    }

    #[test]
    fn test_null_pointer_handling() {
        assert_eq!(rust_engine_initialize(ptr::null()), -1);
        assert_eq!(rust_submit_packet(ptr::null(), 100, 0), -1);
        assert_eq!(rust_retrieve_packet(ptr::null_mut()), -1);
        assert_eq!(rust_get_stats(ptr::null_mut()), -1);
    }
}
