//! High-Performance Packet Forwarding Engine
//!
//! This module implements the packet forwarding engine that transmits processed
//! packets to network interfaces after routing decisions, NAT translation, and
//! header modifications have been applied.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

// =============================================================================
// Error Types
// =============================================================================

/// Forwarding error types.
#[derive(Debug, Clone)]
pub enum ForwardingError {
    /// Interface not registered for forwarding.
    InterfaceNotRegistered(i32),
    /// Packet transmission failed.
    TransmissionFailed(String),
    /// ARP resolution failed.
    ArpResolutionFailed(IpAddr),
    /// Invalid packet.
    InvalidPacket(String),
    /// Hardware offload not supported.
    HardwareOffloadNotSupported,
    /// Already running.
    AlreadyRunning,
    /// Not running.
    NotRunning,
}

impl std::fmt::Display for ForwardingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardingError::InterfaceNotRegistered(idx) => {
                write!(f, "Interface {} not registered", idx)
            }
            ForwardingError::TransmissionFailed(msg) => {
                write!(f, "Transmission failed: {}", msg)
            }
            ForwardingError::ArpResolutionFailed(ip) => {
                write!(f, "ARP resolution failed for {}", ip)
            }
            ForwardingError::InvalidPacket(msg) => {
                write!(f, "Invalid packet: {}", msg)
            }
            ForwardingError::HardwareOffloadNotSupported => {
                write!(f, "Hardware offload not supported")
            }
            ForwardingError::AlreadyRunning => write!(f, "Already running"),
            ForwardingError::NotRunning => write!(f, "Not running"),
        }
    }
}

impl std::error::Error for ForwardingError {}

// =============================================================================
// ARP Entry
// =============================================================================

/// Single ARP cache entry.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    /// IP address.
    pub ip_address: IpAddr,
    /// Hardware MAC address.
    pub mac_address: [u8; 6],
    /// Interface where this IP is reachable.
    pub interface_index: i32,
    /// Cache insertion time.
    pub cached_at: Instant,
    /// Cache expiration time.
    pub expires_at: Instant,
    /// True if static entry (never expires).
    pub is_static: bool,
}

impl ArpEntry {
    /// Creates a new dynamic ARP entry.
    pub fn new(ip: IpAddr, mac: [u8; 6], interface_index: i32, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            ip_address: ip,
            mac_address: mac,
            interface_index,
            cached_at: now,
            expires_at: now + ttl,
            is_static: false,
        }
    }

    /// Creates a static ARP entry (never expires).
    pub fn static_entry(ip: IpAddr, mac: [u8; 6], interface_index: i32) -> Self {
        let now = Instant::now();
        Self {
            ip_address: ip,
            mac_address: mac,
            interface_index,
            cached_at: now,
            expires_at: now + Duration::from_secs(u64::MAX / 2),
            is_static: true,
        }
    }

    /// Returns whether the entry has expired.
    pub fn is_expired(&self) -> bool {
        !self.is_static && Instant::now() > self.expires_at
    }
}

// =============================================================================
// ARP Cache
// =============================================================================

/// ARP cache for IP to MAC address resolution.
pub struct ArpCache {
    /// IP address → ARP entry mapping.
    cache: HashMap<IpAddr, ArpEntry>,
    /// Maximum cache entries.
    max_entries: usize,
    /// Default TTL for dynamic entries.
    default_ttl: Duration,
    /// Cache hit count.
    hits: u64,
    /// Cache miss count.
    misses: u64,
}

impl ArpCache {
    /// Creates a new ARP cache.
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: HashMap::with_capacity(max_entries),
            max_entries,
            default_ttl: Duration::from_secs(ttl_secs),
            hits: 0,
            misses: 0,
        }
    }

    /// Looks up a MAC address for the given IP.
    pub fn lookup(&mut self, ip: &IpAddr) -> Option<[u8; 6]> {
        if let Some(entry) = self.cache.get(ip) {
            if !entry.is_expired() {
                self.hits += 1;
                return Some(entry.mac_address);
            }
            // Expired - will be cleaned up later.
        }
        self.misses += 1;
        None
    }

    /// Inserts or updates an ARP entry.
    pub fn insert(&mut self, ip: IpAddr, mac: [u8; 6], interface_index: i32) {
        if self.cache.len() >= self.max_entries && !self.cache.contains_key(&ip) {
            self.evict_oldest();
        }

        let entry = ArpEntry::new(ip, mac, interface_index, self.default_ttl);
        self.cache.insert(ip, entry);
    }

    /// Adds a static ARP entry.
    pub fn insert_static(&mut self, ip: IpAddr, mac: [u8; 6], interface_index: i32) {
        let entry = ArpEntry::static_entry(ip, mac, interface_index);
        self.cache.insert(ip, entry);
    }

    /// Gets an ARP entry.
    pub fn get(&self, ip: &IpAddr) -> Option<&ArpEntry> {
        self.cache.get(ip).filter(|e| !e.is_expired())
    }

    /// Removes an ARP entry.
    pub fn remove(&mut self, ip: &IpAddr) -> Option<ArpEntry> {
        self.cache.remove(ip)
    }

    /// Clears all dynamic entries.
    pub fn clear_dynamic(&mut self) {
        self.cache.retain(|_, v| v.is_static);
    }

    /// Evicts expired entries.
    pub fn evict_expired(&mut self) {
        self.cache.retain(|_, v| !v.is_expired());
    }

    /// Evicts the oldest entry.
    fn evict_oldest(&mut self) {
        if let Some((key, _)) = self
            .cache
            .iter()
            .filter(|(_, v)| !v.is_static)
            .min_by_key(|(_, v)| v.cached_at)
            .map(|(k, v)| (*k, v.cached_at))
        {
            self.cache.remove(&key);
        }
    }

    /// Returns the cache size.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

// =============================================================================
// Interface Statistics
// =============================================================================

/// Per-interface forwarding statistics.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// Interface name.
    pub interface_name: String,
    /// Packets sent.
    pub packets_sent: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Transmission errors.
    pub errors: u64,
    /// Throughput in bits per second.
    pub throughput_bps: u64,
}

// =============================================================================
// Forwarding Statistics
// =============================================================================

/// Aggregate forwarding statistics.
#[derive(Debug, Clone, Default)]
pub struct ForwardingStats {
    /// Total packets forwarded.
    pub total_packets_forwarded: u64,
    /// Total bytes forwarded.
    pub total_bytes_forwarded: u64,
    /// Total transmission errors.
    pub total_errors: u64,
    /// Per-interface breakdown.
    pub per_interface_stats: Vec<InterfaceStats>,
    /// Current ARP cache entries.
    pub arp_cache_size: usize,
    /// ARP cache hits.
    pub arp_cache_hits: u64,
    /// ARP cache misses.
    pub arp_cache_misses: u64,
}

// =============================================================================
// Forwarding Configuration
// =============================================================================

/// Forwarding engine configuration.
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Number of forwarding worker threads.
    pub worker_threads: usize,
    /// Enable hardware TX checksum offload.
    pub enable_hardware_offload: bool,
    /// Enable zero-copy transmission.
    pub enable_zerocopy: bool,
    /// Packets processed per batch.
    pub batch_size: usize,
    /// TX queue polling interval in microseconds.
    pub polling_interval_us: u64,
    /// Maximum ARP cache entries.
    pub arp_cache_size: usize,
    /// ARP cache TTL in seconds.
    pub arp_cache_ttl_secs: u64,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            worker_threads: 4,
            enable_hardware_offload: true,
            enable_zerocopy: true,
            batch_size: 32,
            polling_interval_us: 100,
            arp_cache_size: 1000,
            arp_cache_ttl_secs: 300,
        }
    }
}

// =============================================================================
// Interface Transmitter
// =============================================================================

/// Transmitter for a single network interface.
pub struct InterfaceTransmitter {
    /// Interface index.
    pub interface_index: i32,
    /// Interface name.
    pub interface_name: String,
    /// Interface MAC address.
    pub mac_address: [u8; 6],
    /// Packets sent counter.
    packets_sent: AtomicU64,
    /// Bytes sent counter.
    bytes_sent: AtomicU64,
    /// Error counter.
    errors: AtomicU64,
    /// Hardware offload enabled.
    hardware_offload: bool,
}

impl InterfaceTransmitter {
    /// Creates a new interface transmitter.
    pub fn new(interface_index: i32, interface_name: String, mac_address: [u8; 6]) -> Self {
        Self {
            interface_index,
            interface_name,
            mac_address,
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            hardware_offload: false,
        }
    }

    /// Sends a packet on this interface.
    pub fn send_packet(&self, packet: &[u8]) -> Result<usize, ForwardingError> {
        // Platform-specific transmission would happen here.
        // For now, simulate successful transmission.

        #[cfg(target_os = "linux")]
        {
            self.send_packet_linux(packet)?;
        }

        #[cfg(target_os = "windows")]
        {
            self.send_packet_windows(packet)?;
        }

        let len = packet.len();
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);

        Ok(len)
    }

    #[cfg(target_os = "linux")]
    fn send_packet_linux(&self, _packet: &[u8]) -> Result<(), ForwardingError> {
        // In real implementation:
        // socket.send_packet(packet)
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn send_packet_windows(&self, _packet: &[u8]) -> Result<(), ForwardingError> {
        // In real implementation:
        // device.send_packet(packet)
        Ok(())
    }

    /// Enables hardware offload for this interface.
    pub fn enable_hardware_offload(&mut self) -> Result<(), ForwardingError> {
        // Platform-specific offload configuration.
        self.hardware_offload = true;
        Ok(())
    }

    /// Returns interface statistics.
    pub fn get_stats(&self) -> InterfaceStats {
        InterfaceStats {
            interface_name: self.interface_name.clone(),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            throughput_bps: 0,
        }
    }

    /// Increments the error counter.
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

// =============================================================================
// Packet for Forwarding
// =============================================================================

/// A packet queued for forwarding.
#[derive(Debug, Clone)]
pub struct ForwardPacket {
    /// Raw packet data.
    pub data: Vec<u8>,
    /// Output interface index.
    pub output_interface: i32,
    /// Next-hop gateway IP (for ARP resolution).
    pub next_hop_ip: Option<IpAddr>,
}

// =============================================================================
// Forwarding Engine
// =============================================================================

/// Main packet forwarding engine.
pub struct ForwardingEngine {
    /// Per-interface transmitters.
    transmitters: Arc<RwLock<HashMap<i32, InterfaceTransmitter>>>,
    /// ARP cache.
    arp_cache: Arc<Mutex<ArpCache>>,
    /// Packet queue.
    tx_queue: Arc<Mutex<Vec<ForwardPacket>>>,
    /// Worker thread handles.
    worker_threads: Vec<JoinHandle<()>>,
    /// Forwarding configuration.
    config: ForwardingConfig,
    /// Shutdown signal.
    running: Arc<AtomicBool>,
    /// Total packets forwarded.
    total_forwarded: AtomicU64,
    /// Total errors.
    total_errors: AtomicU64,
}

impl ForwardingEngine {
    /// Creates a new forwarding engine.
    pub fn new(config: ForwardingConfig) -> Result<Self, ForwardingError> {
        let arp_cache = ArpCache::new(config.arp_cache_size, config.arp_cache_ttl_secs);

        Ok(Self {
            transmitters: Arc::new(RwLock::new(HashMap::new())),
            arp_cache: Arc::new(Mutex::new(arp_cache)),
            tx_queue: Arc::new(Mutex::new(Vec::with_capacity(1024))),
            worker_threads: Vec::new(),
            config,
            running: Arc::new(AtomicBool::new(false)),
            total_forwarded: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
        })
    }

    /// Creates a forwarding engine with default configuration.
    pub fn with_defaults() -> Result<Self, ForwardingError> {
        Self::new(ForwardingConfig::default())
    }

    /// Returns whether the engine is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Registers an interface for packet transmission.
    pub fn register_interface(
        &self,
        interface_index: i32,
        interface_name: String,
        mac_address: [u8; 6],
    ) -> Result<(), ForwardingError> {
        let transmitter = InterfaceTransmitter::new(interface_index, interface_name, mac_address);

        let mut transmitters = self.transmitters.write();
        transmitters.insert(interface_index, transmitter);

        log::debug!("Registered interface {} for forwarding", interface_index);
        Ok(())
    }

    /// Unregisters an interface.
    pub fn unregister_interface(&self, interface_index: i32) -> Result<(), ForwardingError> {
        let mut transmitters = self.transmitters.write();
        transmitters.remove(&interface_index);
        Ok(())
    }

    /// Starts forwarding worker threads.
    pub fn start(&mut self) -> Result<(), ForwardingError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(ForwardingError::AlreadyRunning);
        }

        self.running.store(true, Ordering::SeqCst);

        for worker_id in 0..self.config.worker_threads {
            let running = Arc::clone(&self.running);
            let transmitters = Arc::clone(&self.transmitters);
            let arp_cache = Arc::clone(&self.arp_cache);
            let tx_queue = Arc::clone(&self.tx_queue);
            let config = self.config.clone();

            let handle = thread::Builder::new()
                .name(format!("fwd-worker-{}", worker_id))
                .spawn(move || {
                    forwarding_loop(running, transmitters, arp_cache, tx_queue, config);
                })
                .map_err(|e| ForwardingError::TransmissionFailed(e.to_string()))?;

            self.worker_threads.push(handle);
        }

        log::info!(
            "Forwarding engine started with {} workers",
            self.config.worker_threads
        );
        Ok(())
    }

    /// Stops the forwarding engine.
    pub fn stop(&mut self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(false, Ordering::SeqCst);

        for handle in self.worker_threads.drain(..) {
            if let Err(e) = handle.join() {
                log::error!("Forwarding worker panicked: {:?}", e);
            }
        }

        log::info!("Forwarding engine stopped");
    }

    /// Enqueues a packet for forwarding.
    pub fn enqueue(&self, packet: ForwardPacket) -> Result<(), ForwardingError> {
        let mut queue = self.tx_queue.lock();
        queue.push(packet);
        Ok(())
    }

    /// Forwards a packet immediately (bypasses queue).
    pub fn forward_immediate(
        &self,
        packet: &mut [u8],
        output_interface: i32,
        next_hop_ip: Option<IpAddr>,
    ) -> Result<usize, ForwardingError> {
        // Resolve next-hop MAC if needed.
        let dst_mac = if let Some(ip) = next_hop_ip {
            self.resolve_next_hop_mac(ip, output_interface)?
        } else {
            // Broadcast or on-link.
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        };

        // Get transmitter.
        let transmitters = self.transmitters.read();
        let transmitter = transmitters
            .get(&output_interface)
            .ok_or(ForwardingError::InterfaceNotRegistered(output_interface))?;

        // Update Ethernet header.
        update_ethernet_header(packet, dst_mac, transmitter.mac_address);

        // Transmit.
        let result = transmitter.send_packet(packet);

        match &result {
            Ok(_) => {
                self.total_forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.total_errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    /// Resolves next-hop IP to MAC address.
    pub fn resolve_next_hop_mac(
        &self,
        next_hop_ip: IpAddr,
        interface_index: i32,
    ) -> Result<[u8; 6], ForwardingError> {
        // Check ARP cache first.
        {
            let mut cache = self.arp_cache.lock();
            if let Some(mac) = cache.lookup(&next_hop_ip) {
                return Ok(mac);
            }
        }

        // Send ARP request (in real implementation).
        // For now, return error.
        Err(ForwardingError::ArpResolutionFailed(next_hop_ip))
    }

    /// Handles an ARP reply by updating the cache.
    pub fn handle_arp_reply(&self, sender_ip: IpAddr, sender_mac: [u8; 6], interface_index: i32) {
        let mut cache = self.arp_cache.lock();
        cache.insert(sender_ip, sender_mac, interface_index);
    }

    /// Adds a static ARP entry.
    pub fn add_static_arp_entry(&self, ip: IpAddr, mac: [u8; 6], interface_index: i32) {
        let mut cache = self.arp_cache.lock();
        cache.insert_static(ip, mac, interface_index);
    }

    /// Gets an ARP entry.
    pub fn get_arp_entry(&self, ip: &IpAddr) -> Option<ArpEntry> {
        let cache = self.arp_cache.lock();
        cache.get(ip).cloned()
    }

    /// Clears the ARP cache.
    pub fn clear_arp_cache(&self) {
        let mut cache = self.arp_cache.lock();
        cache.clear_dynamic();
    }

    /// Evicts expired ARP entries.
    pub fn evict_expired_arp(&self) {
        let mut cache = self.arp_cache.lock();
        cache.evict_expired();
    }

    /// Returns forwarding statistics.
    pub fn get_statistics(&self) -> ForwardingStats {
        let transmitters = self.transmitters.read();
        let cache = self.arp_cache.lock();
        let (hits, misses) = cache.stats();

        let mut stats = ForwardingStats {
            total_packets_forwarded: self.total_forwarded.load(Ordering::Relaxed),
            total_bytes_forwarded: 0,
            total_errors: self.total_errors.load(Ordering::Relaxed),
            per_interface_stats: Vec::with_capacity(transmitters.len()),
            arp_cache_size: cache.len(),
            arp_cache_hits: hits,
            arp_cache_misses: misses,
        };

        for transmitter in transmitters.values() {
            let iface_stats = transmitter.get_stats();
            stats.total_bytes_forwarded += iface_stats.bytes_sent;
            stats.per_interface_stats.push(iface_stats);
        }

        stats
    }

    /// Returns the configuration.
    pub fn get_config(&self) -> &ForwardingConfig {
        &self.config
    }
}

impl Drop for ForwardingEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

// =============================================================================
// Forwarding Loop
// =============================================================================

/// Main forwarding worker loop.
fn forwarding_loop(
    running: Arc<AtomicBool>,
    transmitters: Arc<RwLock<HashMap<i32, InterfaceTransmitter>>>,
    arp_cache: Arc<Mutex<ArpCache>>,
    tx_queue: Arc<Mutex<Vec<ForwardPacket>>>,
    config: ForwardingConfig,
) {
    let polling_interval = Duration::from_micros(config.polling_interval_us);

    while running.load(Ordering::Relaxed) {
        // Dequeue packets.
        let packets: Vec<ForwardPacket> = {
            let mut queue = tx_queue.lock();
            if queue.is_empty() {
                drop(queue);
                thread::sleep(polling_interval);
                continue;
            }
            let batch_size = config.batch_size.min(queue.len());
            queue.drain(..batch_size).collect()
        };

        // Process batch.
        for mut packet in packets {
            // Resolve MAC if next-hop is set.
            let dst_mac = if let Some(ip) = packet.next_hop_ip {
                let mut cache = arp_cache.lock();
                cache.lookup(&ip).unwrap_or([0xFF; 6])
            } else {
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            };

            // Get transmitter.
            let transmitters = transmitters.read();
            if let Some(transmitter) = transmitters.get(&packet.output_interface) {
                // Update Ethernet header.
                if packet.data.len() >= 14 {
                    update_ethernet_header(&mut packet.data, dst_mac, transmitter.mac_address);
                }

                // Transmit.
                if let Err(e) = transmitter.send_packet(&packet.data) {
                    log::error!("Transmission error: {}", e);
                    transmitter.inc_errors();
                }
            }
        }
    }
}

// =============================================================================
// Ethernet Header Utilities
// =============================================================================

/// Updates the Ethernet header with new MAC addresses.
pub fn update_ethernet_header(packet: &mut [u8], dst_mac: [u8; 6], src_mac: [u8; 6]) {
    if packet.len() < 14 {
        return;
    }

    // Destination MAC (bytes 0-5).
    packet[0..6].copy_from_slice(&dst_mac);

    // Source MAC (bytes 6-11).
    packet[6..12].copy_from_slice(&src_mac);
}

/// Builds an ARP request packet.
pub fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0u8; 42];

    // Ethernet header.
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast.
    packet[6..12].copy_from_slice(&sender_mac);
    packet[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType: ARP.

    // ARP header.
    packet[14..16].copy_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet.
    packet[16..18].copy_from_slice(&[0x08, 0x00]); // Protocol type: IPv4.
    packet[18] = 6; // Hardware address length.
    packet[19] = 4; // Protocol address length.
    packet[20..22].copy_from_slice(&[0x00, 0x01]); // Operation: Request.
    packet[22..28].copy_from_slice(&sender_mac); // Sender MAC.
    packet[28..32].copy_from_slice(&sender_ip.octets()); // Sender IP.
    packet[32..38].copy_from_slice(&[0x00; 6]); // Target MAC (unknown).
    packet[38..42].copy_from_slice(&target_ip.octets()); // Target IP.

    packet
}

/// Parses an ARP reply packet.
pub fn parse_arp_reply(packet: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    if packet.len() < 42 {
        return None;
    }

    // Check EtherType is ARP.
    if packet[12] != 0x08 || packet[13] != 0x06 {
        return None;
    }

    // Check operation is Reply (2).
    if packet[20] != 0x00 || packet[21] != 0x02 {
        return None;
    }

    // Extract sender MAC and IP.
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&packet[22..28]);

    let sender_ip = Ipv4Addr::new(packet[28], packet[29], packet[30], packet[31]);

    Some((sender_ip, sender_mac))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_entry_new() {
        let entry = ArpEntry::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            1,
            Duration::from_secs(300),
        );

        assert!(!entry.is_static);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_arp_entry_static() {
        let entry = ArpEntry::static_entry(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            1,
        );

        assert!(entry.is_static);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_arp_cache_lookup() {
        let mut cache = ArpCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Miss.
        assert!(cache.lookup(&ip).is_none());

        // Insert.
        cache.insert(ip, mac, 1);

        // Hit.
        assert_eq!(cache.lookup(&ip), Some(mac));
    }

    #[test]
    fn test_interface_transmitter() {
        let transmitter =
            InterfaceTransmitter::new(1, "eth0".to_string(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let stats = transmitter.get_stats();
        assert_eq!(stats.interface_name, "eth0");
        assert_eq!(stats.packets_sent, 0);
    }

    #[test]
    fn test_update_ethernet_header() {
        let mut packet = vec![0u8; 64];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        update_ethernet_header(&mut packet, dst_mac, src_mac);

        assert_eq!(&packet[0..6], &dst_mac);
        assert_eq!(&packet[6..12], &src_mac);
    }

    #[test]
    fn test_build_arp_request() {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);

        let packet = build_arp_request(sender_mac, sender_ip, target_ip);

        assert_eq!(packet.len(), 42);
        assert_eq!(&packet[0..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast.
        assert_eq!(&packet[12..14], &[0x08, 0x06]); // ARP.
        assert_eq!(&packet[20..22], &[0x00, 0x01]); // Request.
    }

    #[test]
    fn test_forwarding_engine_lifecycle() {
        let config = ForwardingConfig::default();
        let mut engine = ForwardingEngine::new(config).unwrap();

        assert!(!engine.is_running());
        assert!(engine.start().is_ok());
        assert!(engine.is_running());

        engine.stop();
        assert!(!engine.is_running());
    }

    #[test]
    fn test_register_interface() {
        let engine = ForwardingEngine::with_defaults().unwrap();

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        engine
            .register_interface(1, "eth0".to_string(), mac)
            .unwrap();

        let stats = engine.get_statistics();
        assert_eq!(stats.per_interface_stats.len(), 1);
    }

    #[test]
    fn test_forwarding_stats() {
        let engine = ForwardingEngine::with_defaults().unwrap();
        let stats = engine.get_statistics();

        assert_eq!(stats.total_packets_forwarded, 0);
        assert_eq!(stats.total_errors, 0);
        assert_eq!(stats.arp_cache_size, 0);
    }
}
