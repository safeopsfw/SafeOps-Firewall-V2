//! Linux Raw Socket Implementation for High-Performance Packet Capture
//!
//! This module implements high-performance raw socket packet capture and transmission
//! for Linux systems using AF_PACKET sockets. It provides direct access to the data
//! link layer for capturing and injecting raw Ethernet frames with zero-copy support.

#![cfg(target_os = "linux")]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

// =============================================================================
// Protocol Constants
// =============================================================================

/// Capture all protocols.
pub const ETH_P_ALL: u16 = 0x0003;
/// IPv4 protocol.
pub const ETH_P_IP: u16 = 0x0800;
/// IPv6 protocol.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// ARP protocol.
pub const ETH_P_ARP: u16 = 0x0806;

// =============================================================================
// Socket Option Constants
// =============================================================================

/// Enable RX ring buffer.
pub const PACKET_RX_RING: i32 = 5;
/// Enable TX ring buffer.
pub const PACKET_TX_RING: i32 = 13;
/// Packet socket version.
pub const PACKET_VERSION: i32 = 10;
/// Hardware timestamp mode.
pub const PACKET_TIMESTAMP: i32 = 17;
/// Fanout mode for multi-queue.
pub const PACKET_FANOUT: i32 = 18;
/// Add membership (promiscuous).
pub const PACKET_ADD_MEMBERSHIP: i32 = 1;
/// Drop membership.
pub const PACKET_DROP_MEMBERSHIP: i32 = 2;
/// Statistics.
pub const PACKET_STATISTICS: i32 = 6;

/// Promiscuous mode membership request.
pub const PACKET_MR_PROMISC: i32 = 1;
/// All multicast membership request.
pub const PACKET_MR_ALLMULTI: i32 = 2;

/// TPACKET version 3.
pub const TPACKET_V3: i32 = 2;

// =============================================================================
// Ring Buffer Status Constants
// =============================================================================

/// Frame owned by kernel.
pub const TP_STATUS_KERNEL: u32 = 0;
/// Frame owned by userspace.
pub const TP_STATUS_USER: u32 = 1;
/// Copy frame to userspace.
pub const TP_STATUS_COPY: u32 = 2;
/// Kernel dropping packets.
pub const TP_STATUS_LOSING: u32 = 4;
/// Checksum not ready.
pub const TP_STATUS_CSUMNOTREADY: u32 = 8;

// =============================================================================
// Fanout Types
// =============================================================================

/// Hash-based distribution.
pub const PACKET_FANOUT_HASH: u32 = 0;
/// Load balancing.
pub const PACKET_FANOUT_LB: u32 = 1;
/// CPU affinity-based.
pub const PACKET_FANOUT_CPU: u32 = 2;
/// Overflow to next socket.
pub const PACKET_FANOUT_ROLLOVER: u32 = 3;
/// Random distribution.
pub const PACKET_FANOUT_RND: u32 = 4;

// =============================================================================
// FFI Structure Definitions
// =============================================================================

/// Link-layer socket address (sockaddr_ll).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct sockaddr_ll {
    /// Address family (AF_PACKET).
    pub sll_family: u16,
    /// Protocol (ETH_P_ALL, ETH_P_IP, etc.).
    pub sll_protocol: u16,
    /// Interface index.
    pub sll_ifindex: i32,
    /// Hardware address type.
    pub sll_hatype: u16,
    /// Packet type (host, broadcast, multicast).
    pub sll_pkttype: u8,
    /// Hardware address length.
    pub sll_halen: u8,
    /// Hardware address (MAC).
    pub sll_addr: [u8; 8],
}

/// Ring buffer configuration (TPACKET_V3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct tpacket_req3 {
    /// Block size in bytes (power of 2).
    pub tp_block_size: u32,
    /// Number of blocks.
    pub tp_block_nr: u32,
    /// Frame size in bytes.
    pub tp_frame_size: u32,
    /// Number of frames.
    pub tp_frame_nr: u32,
    /// Block timeout in milliseconds.
    pub tp_retire_blk_tov: u32,
    /// Size of private data area.
    pub tp_sizeof_priv: u32,
    /// Feature request flags.
    pub tp_feature_req_word: u32,
}

/// Packet header (TPACKET_V3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct tpacket3_hdr {
    /// Offset to next packet.
    pub tp_next_offset: u32,
    /// Timestamp seconds.
    pub tp_sec: u32,
    /// Timestamp nanoseconds.
    pub tp_nsec: u32,
    /// Captured length.
    pub tp_snaplen: u32,
    /// Actual packet length.
    pub tp_len: u32,
    /// Packet status flags.
    pub tp_status: u32,
    /// Offset to MAC header.
    pub tp_mac: u16,
    /// Offset to network header.
    pub tp_net: u16,
    /// Hardware VLAN TCI.
    pub hv_vlan_tci: u16,
    /// Hardware VLAN TPID.
    pub hv_vlan_tpid: u16,
}

/// Block header (TPACKET_V3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct block_desc {
    /// Version.
    pub version: u32,
    /// Offset to first packet.
    pub offset_to_priv: u32,
    /// Block header.
    pub hdr: tpacket_bd_header_u,
}

/// Block header union (TPACKET_V3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct tpacket_bd_header_u {
    /// Timestamp seconds.
    pub ts_first_pkt_sec: u32,
    /// Timestamp nanoseconds.
    pub ts_first_pkt_nsec: u32,
    /// Timestamp seconds (last).
    pub ts_last_pkt_sec: u32,
    /// Timestamp nanoseconds (last).
    pub ts_last_pkt_nsec: u32,
    /// Number of packets.
    pub num_pkts: u32,
    /// Sequence number.
    pub seq_num: u64,
    /// Block length.
    pub blk_len: u32,
}

/// Packet membership request.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct packet_mreq {
    /// Interface index.
    pub mr_ifindex: i32,
    /// Membership type.
    pub mr_type: u16,
    /// Address length.
    pub mr_alen: u16,
    /// Address.
    pub mr_address: [u8; 8],
}

/// Packet statistics (TPACKET_V3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct tpacket_stats_v3 {
    /// Packets received.
    pub tp_packets: u32,
    /// Packets dropped.
    pub tp_drops: u32,
    /// Frozen queue count.
    pub tp_freeze_q_cnt: u32,
}

/// BPF instruction.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct sock_filter {
    /// Instruction code.
    pub code: u16,
    /// Jump if true.
    pub jt: u8,
    /// Jump if false.
    pub jf: u8,
    /// Generic field.
    pub k: u32,
}

/// BPF program.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct sock_fprog {
    /// Number of instructions.
    pub len: u16,
    /// Pointer to instructions.
    pub filter: *const sock_filter,
}

// =============================================================================
// Error Types
// =============================================================================

/// Raw socket error types.
#[derive(Debug)]
pub enum RawSocketError {
    /// Failed to create socket.
    SocketCreationFailed(String),
    /// Failed to bind to interface.
    BindFailed(String),
    /// Interface not found.
    InterfaceNotFound(String),
    /// Memory mapping failed.
    MmapFailed(String),
    /// Packet send failed.
    SendFailed(String),
    /// Packet receive failed.
    RecvFailed(String),
    /// BPF filter attach failed.
    FilterAttachFailed(String),
    /// Insufficient permissions.
    PermissionDenied,
    /// I/O error.
    IoError(io::Error),
}

impl std::fmt::Display for RawSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawSocketError::SocketCreationFailed(msg) => {
                write!(f, "Socket creation failed: {}", msg)
            }
            RawSocketError::BindFailed(msg) => write!(f, "Bind failed: {}", msg),
            RawSocketError::InterfaceNotFound(msg) => write!(f, "Interface not found: {}", msg),
            RawSocketError::MmapFailed(msg) => write!(f, "Memory mapping failed: {}", msg),
            RawSocketError::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            RawSocketError::RecvFailed(msg) => write!(f, "Receive failed: {}", msg),
            RawSocketError::FilterAttachFailed(msg) => write!(f, "Filter attach failed: {}", msg),
            RawSocketError::PermissionDenied => {
                write!(f, "Permission denied (requires CAP_NET_RAW)")
            }
            RawSocketError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for RawSocketError {}

impl From<io::Error> for RawSocketError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(libc::EPERM) {
            RawSocketError::PermissionDenied
        } else {
            RawSocketError::IoError(err)
        }
    }
}

// =============================================================================
// Timestamp Structure
// =============================================================================

/// Packet capture timestamp.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: u64,
    /// Nanoseconds.
    pub nsec: u32,
}

// =============================================================================
// Packet Structure
// =============================================================================

/// Captured packet data.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Raw packet bytes (Ethernet frame).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: Timestamp,
    /// Captured length (may be truncated).
    pub snaplen: u32,
    /// Original packet length.
    pub len: u32,
    /// Interface where packet was captured.
    pub interface_index: i32,
}

// =============================================================================
// Packet Statistics
// =============================================================================

/// Packet capture statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketStats {
    /// Packets captured.
    pub packets_received: u64,
    /// Packets dropped by kernel.
    pub packets_dropped: u64,
    /// Packets in frozen queue.
    pub packets_frozen: u64,
}

// =============================================================================
// Ring Buffer Configuration
// =============================================================================

/// Ring buffer configuration.
#[derive(Debug, Clone, Copy)]
pub struct RingBufferConfig {
    /// Block size (e.g., 4096 bytes).
    pub block_size: u32,
    /// Number of blocks (e.g., 256).
    pub block_count: u32,
    /// Frame size (e.g., 2048 bytes).
    pub frame_size: u32,
    /// Block timeout in milliseconds (e.g., 100 ms).
    pub timeout_ms: u32,
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            block_count: 256,
            frame_size: 2048,
            timeout_ms: 100,
        }
    }
}

// =============================================================================
// Ring Buffer Structure
// =============================================================================

/// Memory-mapped packet ring buffer.
pub struct RingBuffer {
    /// Pointer to mapped memory.
    memory: *mut u8,
    /// Total mapped memory size.
    size: usize,
    /// Size of each block.
    block_size: u32,
    /// Number of blocks.
    block_count: u32,
    /// Size of each frame.
    frame_size: u32,
    /// Number of frames.
    frame_count: u32,
    /// Current block index for reading.
    current_block: u32,
}

// RingBuffer is safe to send between threads (the pointer is only accessed by one thread at a time).
unsafe impl Send for RingBuffer {}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        if !self.memory.is_null() {
            unsafe {
                libc::munmap(self.memory as *mut libc::c_void, self.size);
            }
        }
    }
}

// =============================================================================
// Fanout Type Enum
// =============================================================================

/// Fanout distribution algorithm.
#[derive(Debug, Clone, Copy)]
pub enum FanoutType {
    /// Hash-based distribution (by 5-tuple).
    Hash,
    /// Load balancing.
    LoadBalance,
    /// CPU affinity-based.
    CPU,
    /// Overflow to next socket.
    RollOver,
    /// Random distribution.
    Random,
}

impl FanoutType {
    fn to_raw(&self) -> u32 {
        match self {
            FanoutType::Hash => PACKET_FANOUT_HASH,
            FanoutType::LoadBalance => PACKET_FANOUT_LB,
            FanoutType::CPU => PACKET_FANOUT_CPU,
            FanoutType::RollOver => PACKET_FANOUT_ROLLOVER,
            FanoutType::Random => PACKET_FANOUT_RND,
        }
    }
}

// =============================================================================
// BPF Program Structure
// =============================================================================

/// BPF filter program.
#[derive(Debug, Clone)]
pub struct BpfProgram {
    /// BPF instruction bytecode.
    pub instructions: Vec<sock_filter>,
}

impl BpfProgram {
    /// Creates a new BPF program from instructions.
    pub fn new(instructions: Vec<sock_filter>) -> Self {
        Self { instructions }
    }

    /// Creates a "capture all" BPF program.
    pub fn capture_all() -> Self {
        // BPF_RET | BPF_K with max snaplen
        let ret_all = sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: 0xFFFFFFFF,
        };
        Self {
            instructions: vec![ret_all],
        }
    }
}

// =============================================================================
// Raw Socket Structure
// =============================================================================

/// Raw packet socket for Linux.
pub struct RawSocket {
    /// Socket file descriptor.
    fd: RawFd,
    /// Interface name (e.g., "eth0").
    interface_name: String,
    /// Interface index.
    interface_index: i32,
    /// Memory-mapped ring buffer.
    ring_buffer: Option<RingBuffer>,
    /// Fanout group ID for multi-queue.
    fanout_group: Option<u32>,
    /// Promiscuous mode flag.
    promisc_enabled: bool,
}

// RawSocket is safe to send between threads.
unsafe impl Send for RawSocket {}

impl RawSocket {
    /// Creates a new raw packet socket bound to the specified interface.
    ///
    /// # Arguments
    /// * `interface_name` - Name of the network interface (e.g., "eth0")
    /// * `protocol` - Ethernet protocol to capture (e.g., ETH_P_ALL)
    ///
    /// # Returns
    /// A new RawSocket instance or an error.
    pub fn new(interface_name: &str, protocol: u16) -> Result<Self, RawSocketError> {
        // Create AF_PACKET socket.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, htons(protocol) as i32) };

        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(RawSocketError::PermissionDenied);
            }
            return Err(RawSocketError::SocketCreationFailed(err.to_string()));
        }

        // Get interface index.
        let if_index = interface_name_to_index(interface_name)?;

        // Create socket address.
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = htons(protocol);
        addr.sll_ifindex = if_index;

        // Bind to interface.
        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            unsafe { libc::close(fd) };
            return Err(RawSocketError::BindFailed(
                io::Error::last_os_error().to_string(),
            ));
        }

        // Set socket to non-blocking mode.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

        Ok(Self {
            fd,
            interface_name: interface_name.to_string(),
            interface_index: if_index,
            ring_buffer: None,
            fanout_group: None,
            promisc_enabled: false,
        })
    }

    /// Returns the socket file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the interface name.
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Returns the interface index.
    pub fn interface_index(&self) -> i32 {
        self.interface_index
    }

    /// Returns whether promiscuous mode is enabled.
    pub fn is_promiscuous(&self) -> bool {
        self.promisc_enabled
    }

    /// Enables or disables promiscuous mode.
    pub fn set_promiscuous(&mut self, enable: bool) -> Result<(), RawSocketError> {
        let mut mreq: packet_mreq = unsafe { mem::zeroed() };
        mreq.mr_ifindex = self.interface_index;
        mreq.mr_type = if enable {
            PACKET_MR_PROMISC as u16
        } else {
            PACKET_MR_ALLMULTI as u16
        };

        let optname = if enable {
            PACKET_ADD_MEMBERSHIP
        } else {
            PACKET_DROP_MEMBERSHIP
        };

        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                optname,
                &mreq as *const packet_mreq as *const libc::c_void,
                mem::size_of::<packet_mreq>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(RawSocketError::IoError(io::Error::last_os_error()));
        }

        self.promisc_enabled = enable;
        Ok(())
    }

    /// Sets up memory-mapped ring buffer for zero-copy capture.
    pub fn setup_ring_buffer(&mut self, config: &RingBufferConfig) -> Result<(), RawSocketError> {
        // Validate configuration.
        if !config.block_size.is_power_of_two() {
            return Err(RawSocketError::MmapFailed(
                "block_size must be a power of 2".to_string(),
            ));
        }

        // Set TPACKET version.
        let version: i32 = TPACKET_V3;
        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_VERSION,
                &version as *const i32 as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(RawSocketError::MmapFailed(format!(
                "Failed to set TPACKET_V3: {}",
                io::Error::last_os_error()
            )));
        }

        // Calculate frame count.
        let frames_per_block = config.block_size / config.frame_size;
        let frame_count = frames_per_block * config.block_count;

        // Create ring buffer request.
        let req = tpacket_req3 {
            tp_block_size: config.block_size,
            tp_block_nr: config.block_count,
            tp_frame_size: config.frame_size,
            tp_frame_nr: frame_count,
            tp_retire_blk_tov: config.timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };

        // Set RX ring.
        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_RX_RING,
                &req as *const tpacket_req3 as *const libc::c_void,
                mem::size_of::<tpacket_req3>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(RawSocketError::MmapFailed(format!(
                "Failed to set RX ring: {}",
                io::Error::last_os_error()
            )));
        }

        // Calculate total memory size.
        let total_size = (config.block_size as usize) * (config.block_count as usize);

        // Memory map the ring buffer.
        let memory = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd,
                0,
            )
        };

        if memory == libc::MAP_FAILED {
            return Err(RawSocketError::MmapFailed(format!(
                "mmap failed: {}",
                io::Error::last_os_error()
            )));
        }

        self.ring_buffer = Some(RingBuffer {
            memory: memory as *mut u8,
            size: total_size,
            block_size: config.block_size,
            block_count: config.block_count,
            frame_size: config.frame_size,
            frame_count,
            current_block: 0,
        });

        Ok(())
    }

    /// Receives the next packet from the ring buffer or socket.
    pub fn recv_packet(&mut self) -> Result<Option<Packet>, RawSocketError> {
        if let Some(ref mut ring) = self.ring_buffer {
            // Ring buffer path.
            let block_offset = (ring.current_block * ring.block_size) as usize;
            let block_ptr = unsafe { ring.memory.add(block_offset) };

            // Read block status.
            let block_hdr = unsafe { &*(block_ptr as *const block_desc) };
            let status = block_hdr.hdr.blk_len; // Use blk_len as status indicator

            if status == 0 {
                // Block not ready.
                return Ok(None);
            }

            // Block is ready - extract first packet.
            // (Simplified - real implementation would iterate through all packets)
            let pkt_offset = mem::size_of::<block_desc>();
            let pkt_ptr = unsafe { block_ptr.add(pkt_offset) };
            let pkt_hdr = unsafe { &*(pkt_ptr as *const tpacket3_hdr) };

            if pkt_hdr.tp_status & TP_STATUS_USER == 0 {
                return Ok(None);
            }

            // Extract packet data.
            let data_offset = pkt_hdr.tp_mac as usize;
            let data_ptr = unsafe { pkt_ptr.add(data_offset) };
            let data_len = pkt_hdr.tp_snaplen as usize;

            let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len).to_vec() };

            let packet = Packet {
                data,
                timestamp: Timestamp {
                    sec: pkt_hdr.tp_sec as u64,
                    nsec: pkt_hdr.tp_nsec,
                },
                snaplen: pkt_hdr.tp_snaplen,
                len: pkt_hdr.tp_len,
                interface_index: self.interface_index,
            };

            // Mark block as processed (return to kernel).
            unsafe {
                let status_ptr = block_ptr as *mut u32;
                *status_ptr = TP_STATUS_KERNEL;
            }

            // Advance to next block.
            ring.current_block = (ring.current_block + 1) % ring.block_count;

            Ok(Some(packet))
        } else {
            // Non-ring buffer path - use recvfrom.
            let mut buffer = vec![0u8; 65535];
            let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
            let mut addr_len = mem::size_of::<sockaddr_ll>() as libc::socklen_t;

            let bytes = unsafe {
                libc::recvfrom(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr as *mut sockaddr_ll as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };

            if bytes < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(RawSocketError::RecvFailed(err.to_string()));
            }

            buffer.truncate(bytes as usize);

            Ok(Some(Packet {
                data: buffer,
                timestamp: Timestamp::default(),
                snaplen: bytes as u32,
                len: bytes as u32,
                interface_index: self.interface_index,
            }))
        }
    }

    /// Sends a raw packet to the network.
    pub fn send_packet(&self, packet: &[u8]) -> Result<usize, RawSocketError> {
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.interface_index;
        addr.sll_halen = 6;

        // Copy destination MAC from packet if available.
        if packet.len() >= 6 {
            addr.sll_addr[..6].copy_from_slice(&packet[..6]);
        }

        let bytes = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            )
        };

        if bytes < 0 {
            return Err(RawSocketError::SendFailed(
                io::Error::last_os_error().to_string(),
            ));
        }

        Ok(bytes as usize)
    }

    /// Attaches a BPF filter for selective packet capture.
    pub fn attach_filter(&self, filter: &BpfProgram) -> Result<(), RawSocketError> {
        if filter.instructions.is_empty() {
            return Err(RawSocketError::FilterAttachFailed(
                "Filter has no instructions".to_string(),
            ));
        }

        let prog = sock_fprog {
            len: filter.instructions.len() as u16,
            filter: filter.instructions.as_ptr(),
        };

        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const sock_fprog as *const libc::c_void,
                mem::size_of::<sock_fprog>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(RawSocketError::FilterAttachFailed(
                io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    /// Configures fanout for multi-queue packet distribution.
    pub fn set_fanout(
        &mut self,
        group_id: u32,
        fanout_type: FanoutType,
    ) -> Result<(), RawSocketError> {
        let fanout_val = group_id | (fanout_type.to_raw() << 16);

        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_FANOUT,
                &fanout_val as *const u32 as *const libc::c_void,
                mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(RawSocketError::IoError(io::Error::last_os_error()));
        }

        self.fanout_group = Some(group_id);
        Ok(())
    }

    /// Retrieves packet capture statistics.
    pub fn get_stats(&self) -> Result<PacketStats, RawSocketError> {
        let mut stats: tpacket_stats_v3 = unsafe { mem::zeroed() };
        let mut stats_len = mem::size_of::<tpacket_stats_v3>() as libc::socklen_t;

        let result = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_STATISTICS,
                &mut stats as *mut tpacket_stats_v3 as *mut libc::c_void,
                &mut stats_len,
            )
        };

        if result < 0 {
            return Err(RawSocketError::IoError(io::Error::last_os_error()));
        }

        Ok(PacketStats {
            packets_received: stats.tp_packets as u64,
            packets_dropped: stats.tp_drops as u64,
            packets_frozen: stats.tp_freeze_q_cnt as u64,
        })
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // Ring buffer is dropped automatically via its Drop impl.
        self.ring_buffer = None;

        // Close socket.
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts host byte order to network byte order (16-bit).
#[inline]
pub fn htons(value: u16) -> u16 {
    value.to_be()
}

/// Converts network byte order to host byte order (16-bit).
#[inline]
pub fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}

/// Converts interface name to index.
pub fn interface_name_to_index(name: &str) -> Result<i32, RawSocketError> {
    let c_name = CString::new(name).map_err(|_| {
        RawSocketError::InterfaceNotFound(format!("Invalid interface name: {}", name))
    })?;

    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        return Err(RawSocketError::InterfaceNotFound(format!(
            "Interface not found: {}",
            name
        )));
    }

    Ok(index as i32)
}

/// Gets the MAC address of an interface.
pub fn get_interface_mac(name: &str) -> Result<[u8; 6], RawSocketError> {
    let path = format!("/sys/class/net/{}/address", name);
    let content = std::fs::read_to_string(&path).map_err(|e| {
        RawSocketError::InterfaceNotFound(format!("Cannot read MAC address: {}", e))
    })?;

    let mac_str = content.trim();
    let mut mac = [0u8; 6];

    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(RawSocketError::InterfaceNotFound(format!(
            "Invalid MAC address format: {}",
            mac_str
        )));
    }

    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            RawSocketError::InterfaceNotFound(format!("Invalid MAC address: {}", mac_str))
        })?;
    }

    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htons() {
        assert_eq!(htons(0x0001), 0x0100);
        assert_eq!(htons(0x0800), 0x0008);
    }

    #[test]
    fn test_ntohs() {
        assert_eq!(ntohs(0x0100), 0x0001);
        assert_eq!(ntohs(0x0008), 0x0800);
    }

    #[test]
    fn test_ring_buffer_config_default() {
        let config = RingBufferConfig::default();
        assert_eq!(config.block_size, 4096);
        assert_eq!(config.block_count, 256);
        assert_eq!(config.frame_size, 2048);
        assert_eq!(config.timeout_ms, 100);
    }

    #[test]
    fn test_bpf_program_capture_all() {
        let prog = BpfProgram::capture_all();
        assert_eq!(prog.instructions.len(), 1);
        assert_eq!(prog.instructions[0].code, 0x06);
        assert_eq!(prog.instructions[0].k, 0xFFFFFFFF);
    }
}
