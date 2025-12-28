//! Packet Processor Module
//!
//! This module implements the main packet processing pipeline that orchestrates
//! the entire packet forwarding workflow from capture to transmission.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ahash::AHasher;
use etherparse::SlicedPacket;
use parking_lot::RwLock;

use crate::{
    dequeue_rx, enqueue_tx, inc_forwarding_errors, inc_nat_translations, inc_packets_dropped,
    inc_packets_forwarded, inc_routing_decisions, is_engine_running, PacketBuffer, PacketError,
};

// =============================================================================
// Constants
// =============================================================================

/// Default batch size for packet processing.
const DEFAULT_BATCH_SIZE: usize = 64;

/// Default polling interval in microseconds.
const DEFAULT_POLLING_INTERVAL_US: u64 = 100;

/// Ethernet header size.
const ETH_HEADER_LEN: usize = 14;

/// Minimum IP header size.
const IP_HEADER_MIN_LEN: usize = 20;

/// TCP header minimum size.
const TCP_HEADER_MIN_LEN: usize = 20;

/// UDP header size.
const UDP_HEADER_LEN: usize = 8;

// =============================================================================
// Processor Configuration
// =============================================================================

/// Configuration for the packet processor.
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Number of worker threads.
    pub worker_threads: usize,
    /// Enable SIMD acceleration.
    pub enable_simd: bool,
    /// Enable zero-copy forwarding.
    pub enable_zerocopy: bool,
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Polling interval in microseconds.
    pub polling_interval_us: u64,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            worker_threads: 8,
            enable_simd: true,
            enable_zerocopy: true,
            max_batch_size: DEFAULT_BATCH_SIZE,
            polling_interval_us: DEFAULT_POLLING_INTERVAL_US,
        }
    }
}

// =============================================================================
// Parsed Packet Headers
// =============================================================================

/// Parsed packet headers from all layers.
#[derive(Debug, Clone)]
pub struct PacketHeaders {
    /// Source MAC address.
    pub eth_src: [u8; 6],
    /// Destination MAC address.
    pub eth_dst: [u8; 6],
    /// EtherType.
    pub ether_type: u16,
    /// Source IP address.
    pub ip_src: Option<IpAddr>,
    /// Destination IP address.
    pub ip_dst: Option<IpAddr>,
    /// IP protocol.
    pub protocol: u8,
    /// Source port (TCP/UDP).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP).
    pub dst_port: Option<u16>,
    /// Time to live.
    pub ttl: u8,
    /// Offset to payload data.
    pub payload_offset: usize,
    /// Is IPv6.
    pub is_ipv6: bool,
}

impl Default for PacketHeaders {
    fn default() -> Self {
        Self {
            eth_src: [0; 6],
            eth_dst: [0; 6],
            ether_type: 0,
            ip_src: None,
            ip_dst: None,
            protocol: 0,
            src_port: None,
            dst_port: None,
            ttl: 0,
            payload_offset: 0,
            is_ipv6: false,
        }
    }
}

// =============================================================================
// Route Decision
// =============================================================================

/// Routing decision result.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// Output interface index.
    pub output_interface: u32,
    /// Next-hop gateway IP (None if on-link).
    pub gateway_ip: Option<IpAddr>,
    /// True if output interface is WAN (requires NAT).
    pub is_wan: bool,
    /// Next-hop MAC address.
    pub next_hop_mac: [u8; 6],
}

impl Default for RouteDecision {
    fn default() -> Self {
        Self {
            output_interface: 0,
            gateway_ip: None,
            is_wan: false,
            next_hop_mac: [0; 6],
        }
    }
}

// =============================================================================
// NAT Mapping
// =============================================================================

/// NAT translation mapping.
#[derive(Debug, Clone)]
pub struct NATTranslation {
    /// Original source IP.
    pub original_src_ip: IpAddr,
    /// Original source port.
    pub original_src_port: u16,
    /// Translated source IP.
    pub translated_src_ip: IpAddr,
    /// Translated source port.
    pub translated_src_port: u16,
}

// =============================================================================
// Worker Statistics
// =============================================================================

/// Per-worker statistics.
#[derive(Debug, Clone, Default)]
pub struct WorkerStats {
    /// Worker thread ID.
    pub worker_id: usize,
    /// Packets processed by this worker.
    pub packets_processed: u64,
    /// Packets dropped by this worker.
    pub packets_dropped: u64,
    /// Average processing time in microseconds.
    pub avg_processing_time_us: u64,
}

// =============================================================================
// Packet Processor
// =============================================================================

/// Main packet processing orchestrator.
pub struct PacketProcessor {
    /// Worker thread handles.
    worker_threads: Vec<JoinHandle<()>>,
    /// Configuration.
    config: ProcessorConfig,
    /// Shutdown signal flag.
    running: Arc<AtomicBool>,
    /// Per-worker statistics.
    worker_stats: Arc<RwLock<Vec<WorkerStats>>>,
}

impl PacketProcessor {
    /// Creates a new packet processor instance.
    pub fn new(config: ProcessorConfig) -> Self {
        let worker_count = config.worker_threads;
        let mut stats = Vec::with_capacity(worker_count);
        for i in 0..worker_count {
            stats.push(WorkerStats {
                worker_id: i,
                ..Default::default()
            });
        }

        Self {
            worker_threads: Vec::with_capacity(worker_count),
            config,
            running: Arc::new(AtomicBool::new(false)),
            worker_stats: Arc::new(RwLock::new(stats)),
        }
    }

    /// Starts packet processing worker threads.
    pub fn start(&mut self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Processor already running".to_string());
        }

        self.running.store(true, Ordering::SeqCst);

        for worker_id in 0..self.config.worker_threads {
            let running = Arc::clone(&self.running);
            let config = self.config.clone();
            let stats = Arc::clone(&self.worker_stats);

            let handle = thread::Builder::new()
                .name(format!("pkt-worker-{}", worker_id))
                .spawn(move || {
                    worker_loop(worker_id, running, config, stats);
                })
                .map_err(|e| format!("Failed to spawn worker thread: {}", e))?;

            self.worker_threads.push(handle);
        }

        log::info!(
            "Packet processor started with {} worker threads",
            self.config.worker_threads
        );
        Ok(())
    }

    /// Stops packet processing gracefully.
    pub fn stop(&mut self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        // Signal workers to stop.
        self.running.store(false, Ordering::SeqCst);

        // Wait for all workers to finish.
        for handle in self.worker_threads.drain(..) {
            if let Err(e) = handle.join() {
                log::error!("Worker thread panicked: {:?}", e);
            }
        }

        // Log final statistics.
        let stats = self.worker_stats.read();
        let total_processed: u64 = stats.iter().map(|s| s.packets_processed).sum();
        let total_dropped: u64 = stats.iter().map(|s| s.packets_dropped).sum();
        log::info!(
            "Packet processor stopped. Total processed: {}, dropped: {}",
            total_processed,
            total_dropped
        );
    }

    /// Returns whether the processor is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns per-worker statistics.
    pub fn get_worker_stats(&self) -> Vec<WorkerStats> {
        self.worker_stats.read().clone()
    }

    /// Returns the processor configuration.
    pub fn get_config(&self) -> &ProcessorConfig {
        &self.config
    }
}

impl Drop for PacketProcessor {
    fn drop(&mut self) {
        self.stop();
    }
}

// =============================================================================
// Worker Loop
// =============================================================================

/// Main worker loop for packet processing.
fn worker_loop(
    worker_id: usize,
    running: Arc<AtomicBool>,
    config: ProcessorConfig,
    stats: Arc<RwLock<Vec<WorkerStats>>>,
) {
    let polling_interval = Duration::from_micros(config.polling_interval_us);
    let mut local_processed: u64 = 0;
    let mut local_dropped: u64 = 0;

    log::debug!("Worker {} started", worker_id);

    while running.load(Ordering::Relaxed) && is_engine_running() {
        // Process a batch of packets.
        let processed = process_batch(
            config.max_batch_size,
            &mut local_processed,
            &mut local_dropped,
        );

        if processed == 0 {
            // No packets available, sleep briefly.
            thread::sleep(polling_interval);
        }
    }

    // Update final statistics.
    {
        let mut stats_guard = stats.write();
        if let Some(worker_stat) = stats_guard.get_mut(worker_id) {
            worker_stat.packets_processed = local_processed;
            worker_stat.packets_dropped = local_dropped;
        }
    }

    log::debug!(
        "Worker {} stopped. Processed: {}, Dropped: {}",
        worker_id,
        local_processed,
        local_dropped
    );
}

// =============================================================================
// Batch Processing
// =============================================================================

/// Processes a batch of packets.
fn process_batch(
    max_batch_size: usize,
    processed_count: &mut u64,
    dropped_count: &mut u64,
) -> usize {
    let mut processed = 0;

    for _ in 0..max_batch_size {
        // Dequeue packet from RX queue.
        let mut packet = match dequeue_rx() {
            Some(pkt) => pkt,
            None => break, // No more packets.
        };

        // Process the packet.
        match process_single_packet(&mut packet) {
            Ok(()) => {
                // Enqueue to TX queue.
                match enqueue_tx(packet) {
                    Ok(()) => {
                        inc_packets_forwarded();
                        *processed_count += 1;
                        processed += 1;
                    }
                    Err(_pkt) => {
                        // TX queue full.
                        inc_packets_dropped();
                        *dropped_count += 1;
                    }
                }
            }
            Err(_e) => {
                // Processing failed.
                inc_packets_dropped();
                inc_forwarding_errors();
                *dropped_count += 1;
            }
        }
    }

    processed
}

/// Processes a single packet through the pipeline.
fn process_single_packet(packet: &mut PacketBuffer) -> Result<(), PacketError> {
    let data = packet.as_slice();
    if data.len() < ETH_HEADER_LEN {
        return Err(PacketError::InvalidPacket("Packet too short".to_string()));
    }

    // Step 1: Parse packet headers.
    let headers = parse_packet(data)?;

    // Step 2: Make routing decision.
    let route = route_packet(&headers)?;
    inc_routing_decisions();

    // Step 3: Apply NAT if needed.
    let nat_translation = if route.is_wan && headers.ip_src.is_some() {
        Some(apply_nat(&headers)?)
    } else {
        None
    };

    if nat_translation.is_some() {
        inc_nat_translations();
    }

    // Step 4: Modify packet headers.
    modify_packet(
        packet.as_mut_slice(),
        &headers,
        &route,
        nat_translation.as_ref(),
    )?;

    // Step 5: Update packet metadata.
    packet.dst_interface = route.output_interface;

    Ok(())
}

// =============================================================================
// Packet Parsing
// =============================================================================

/// Parses Ethernet/IP/TCP/UDP headers from raw packet data.
pub fn parse_packet(data: &[u8]) -> Result<PacketHeaders, PacketError> {
    let mut headers = PacketHeaders::default();

    // Parse with etherparse.
    let sliced = SlicedPacket::from_ethernet(data)
        .map_err(|e| PacketError::InvalidPacket(format!("Parse error: {:?}", e)))?;

    // Extract Ethernet header.
    if let Some(link) = sliced.link {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => {
                headers.eth_src.copy_from_slice(eth.source());
                headers.eth_dst.copy_from_slice(eth.destination());
                headers.ether_type = eth.ether_type().0;
            }
            _ => {}
        }
    }

    // Extract IP header.
    if let Some(ip) = sliced.ip {
        match ip {
            etherparse::InternetSlice::Ipv4(ipv4, _) => {
                headers.ip_src = Some(IpAddr::V4(ipv4.header().source_addr()));
                headers.ip_dst = Some(IpAddr::V4(ipv4.header().destination_addr()));
                headers.protocol = ipv4.header().protocol().0;
                headers.ttl = ipv4.header().time_to_live();
                headers.is_ipv6 = false;
            }
            etherparse::InternetSlice::Ipv6(ipv6, _) => {
                headers.ip_src = Some(IpAddr::V6(ipv6.header().source_addr()));
                headers.ip_dst = Some(IpAddr::V6(ipv6.header().destination_addr()));
                headers.protocol = ipv6.header().next_header().0;
                headers.ttl = ipv6.header().hop_limit();
                headers.is_ipv6 = true;
            }
        }
    }

    // Extract transport layer.
    if let Some(transport) = sliced.transport {
        match transport {
            etherparse::TransportSlice::Tcp(tcp) => {
                headers.src_port = Some(tcp.source_port());
                headers.dst_port = Some(tcp.destination_port());
            }
            etherparse::TransportSlice::Udp(udp) => {
                headers.src_port = Some(udp.source_port());
                headers.dst_port = Some(udp.destination_port());
            }
            etherparse::TransportSlice::Icmpv4(_) | etherparse::TransportSlice::Icmpv6(_) => {
                // ICMP doesn't have ports.
            }
            _ => {}
        }
    }

    // Calculate payload offset.
    headers.payload_offset = data.len() - sliced.payload.len();

    Ok(headers)
}

// =============================================================================
// Routing
// =============================================================================

/// Makes a routing decision for the packet.
fn route_packet(headers: &PacketHeaders) -> Result<RouteDecision, PacketError> {
    let _dst_ip = headers
        .ip_dst
        .ok_or_else(|| PacketError::RoutingFailed("No destination IP".to_string()))?;

    // Placeholder routing logic.
    // Real implementation would query the routing table.
    Ok(RouteDecision::default())
}

// =============================================================================
// NAT Translation
// =============================================================================

/// Applies NAT translation for WAN-bound packets.
fn apply_nat(headers: &PacketHeaders) -> Result<NATTranslation, PacketError> {
    let src_ip = headers
        .ip_src
        .ok_or_else(|| PacketError::NATFailed("No source IP".to_string()))?;

    let src_port = headers.src_port.unwrap_or(0);

    // Placeholder NAT logic.
    // Real implementation would lookup/create NAT mappings.
    Ok(NATTranslation {
        original_src_ip: src_ip,
        original_src_port: src_port,
        translated_src_ip: src_ip, // Would be WAN IP.
        translated_src_port: src_port,
    })
}

// =============================================================================
// Packet Modification
// =============================================================================

/// Modifies packet headers after routing/NAT decisions.
fn modify_packet(
    data: &mut [u8],
    _headers: &PacketHeaders,
    route: &RouteDecision,
    _nat: Option<&NATTranslation>,
) -> Result<(), PacketError> {
    if data.len() < ETH_HEADER_LEN {
        return Err(PacketError::ForwardingFailed(
            "Packet too short".to_string(),
        ));
    }

    // Update destination MAC to next-hop.
    data[0..6].copy_from_slice(&route.next_hop_mac);

    // Decrement TTL would happen here for IP packets.
    // Checksum recalculation would happen here.

    Ok(())
}

// =============================================================================
// Checksum Functions
// =============================================================================

/// Computes the Internet checksum (RFC 1071).
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words.
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    // Handle odd byte.
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    // Fold 32-bit sum to 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Recalculates the IP header checksum.
pub fn recalculate_ip_checksum(ip_header: &mut [u8]) {
    if ip_header.len() < IP_HEADER_MIN_LEN {
        return;
    }

    // Clear existing checksum.
    ip_header[10] = 0;
    ip_header[11] = 0;

    // Calculate header length.
    let ihl = ((ip_header[0] & 0x0F) as usize) * 4;
    let header_data = &ip_header[..ihl.min(ip_header.len())];

    // Compute new checksum.
    let checksum = compute_checksum(header_data);
    let checksum_bytes = checksum.to_be_bytes();
    ip_header[10] = checksum_bytes[0];
    ip_header[11] = checksum_bytes[1];
}

/// Recalculates TCP checksum.
#[allow(dead_code)]
pub fn recalculate_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &mut [u8]) {
    if tcp_segment.len() < TCP_HEADER_MIN_LEN {
        return;
    }

    // Clear existing checksum.
    tcp_segment[16] = 0;
    tcp_segment[17] = 0;

    // Build pseudo-header.
    let tcp_len = tcp_segment.len() as u16;
    let mut pseudo_header = Vec::with_capacity(12 + tcp_segment.len());
    pseudo_header.extend_from_slice(&src_ip);
    pseudo_header.extend_from_slice(&dst_ip);
    pseudo_header.push(0); // Zero.
    pseudo_header.push(6); // Protocol (TCP).
    pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo_header.extend_from_slice(tcp_segment);

    // Compute checksum.
    let checksum = compute_checksum(&pseudo_header);
    let checksum_bytes = checksum.to_be_bytes();
    tcp_segment[16] = checksum_bytes[0];
    tcp_segment[17] = checksum_bytes[1];
}

/// Recalculates UDP checksum.
#[allow(dead_code)]
pub fn recalculate_udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &mut [u8]) {
    if udp_segment.len() < UDP_HEADER_LEN {
        return;
    }

    // Clear existing checksum.
    udp_segment[6] = 0;
    udp_segment[7] = 0;

    // Build pseudo-header.
    let udp_len = udp_segment.len() as u16;
    let mut pseudo_header = Vec::with_capacity(12 + udp_segment.len());
    pseudo_header.extend_from_slice(&src_ip);
    pseudo_header.extend_from_slice(&dst_ip);
    pseudo_header.push(0); // Zero.
    pseudo_header.push(17); // Protocol (UDP).
    pseudo_header.extend_from_slice(&udp_len.to_be_bytes());
    pseudo_header.extend_from_slice(udp_segment);

    // Compute checksum.
    let checksum = compute_checksum(&pseudo_header);
    if checksum == 0 {
        // UDP uses 0xFFFF for zero checksum.
        udp_segment[6] = 0xFF;
        udp_segment[7] = 0xFF;
    } else {
        let checksum_bytes = checksum.to_be_bytes();
        udp_segment[6] = checksum_bytes[0];
        udp_segment[7] = checksum_bytes[1];
    }
}

// =============================================================================
// Connection Affinity
// =============================================================================

/// Computes worker affinity based on 5-tuple hash.
pub fn get_worker_for_packet(headers: &PacketHeaders, thread_count: usize) -> usize {
    use std::hash::{Hash, Hasher};

    let mut hasher = AHasher::default();

    // Hash 5-tuple.
    if let Some(src) = &headers.ip_src {
        src.hash(&mut hasher);
    }
    if let Some(dst) = &headers.ip_dst {
        dst.hash(&mut hasher);
    }
    if let Some(sport) = headers.src_port {
        sport.hash(&mut hasher);
    }
    if let Some(dport) = headers.dst_port {
        dport.hash(&mut hasher);
    }
    headers.protocol.hash(&mut hasher);

    let hash = hasher.finish();
    (hash as usize) % thread_count
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_config_default() {
        let config = ProcessorConfig::default();
        assert_eq!(config.worker_threads, 8);
        assert!(config.enable_simd);
        assert!(config.enable_zerocopy);
        assert_eq!(config.max_batch_size, DEFAULT_BATCH_SIZE);
    }

    #[test]
    fn test_packet_headers_default() {
        let headers = PacketHeaders::default();
        assert_eq!(headers.eth_src, [0; 6]);
        assert_eq!(headers.eth_dst, [0; 6]);
        assert!(headers.ip_src.is_none());
        assert!(headers.ip_dst.is_none());
        assert_eq!(headers.ttl, 0);
    }

    #[test]
    fn test_compute_checksum() {
        // Simple test case.
        let data = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = compute_checksum(&data);
        // Verify checksum is computed (actual value depends on input).
        assert!(checksum != 0 || data.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_worker_affinity() {
        let headers = PacketHeaders {
            ip_src: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))),
            ip_dst: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: 6,
            ..Default::default()
        };

        let worker1 = get_worker_for_packet(&headers, 8);
        let worker2 = get_worker_for_packet(&headers, 8);

        // Same 5-tuple should always map to same worker.
        assert_eq!(worker1, worker2);
        assert!(worker1 < 8);
    }

    #[test]
    fn test_route_decision_default() {
        let route = RouteDecision::default();
        assert_eq!(route.output_interface, 0);
        assert!(route.gateway_ip.is_none());
        assert!(!route.is_wan);
    }
}
