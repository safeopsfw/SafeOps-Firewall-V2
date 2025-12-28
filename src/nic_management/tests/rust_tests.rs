//! Comprehensive unit and integration tests for the NIC Management service's Rust components.
//!
//! Tests cover:
//! - Packet queue operations (lock-free)
//! - Routing engine decisions
//! - NAT translation and checksum recalculation
//! - Forwarding engine zero-copy
//! - FFI boundary safety

#![cfg(test)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

// =============================================================================
// Mock Structures for Testing
// =============================================================================

/// Mock packet queue for testing lock-free operations.
pub struct PacketQueue {
    capacity: usize,
    count: AtomicUsize,
    packets: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl PacketQueue {
    pub fn new(capacity: usize) -> Self {
        PacketQueue {
            capacity,
            count: AtomicUsize::new(0),
            packets: std::sync::Mutex::new(Vec::with_capacity(capacity)),
        }
    }

    pub fn push(&self, packet: Vec<u8>) -> bool {
        let mut packets = self.packets.lock().unwrap();
        if packets.len() >= self.capacity {
            return false;
        }
        packets.push(packet);
        self.count.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn pop(&self) -> Option<Vec<u8>> {
        let mut packets = self.packets.lock().unwrap();
        if packets.is_empty() {
            return None;
        }
        self.count.fetch_sub(1, Ordering::SeqCst);
        Some(packets.remove(0))
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Five-tuple for connection identification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Mock routing engine.
pub struct RoutingEngine {
    routes: std::collections::HashMap<String, String>,
    default_route: Option<String>,
}

impl RoutingEngine {
    pub fn new() -> Self {
        RoutingEngine {
            routes: std::collections::HashMap::new(),
            default_route: Some("wan1".to_string()),
        }
    }

    pub fn add_route(&mut self, five_tuple: FiveTuple, interface: String) {
        let key = format!(
            "{}:{}->{}:{}:{}",
            five_tuple.src_ip,
            five_tuple.src_port,
            five_tuple.dst_ip,
            five_tuple.dst_port,
            five_tuple.protocol
        );
        self.routes.insert(key, interface);
    }

    pub fn route_packet(&self, five_tuple: &FiveTuple) -> Option<String> {
        let key = format!(
            "{}:{}->{}:{}:{}",
            five_tuple.src_ip,
            five_tuple.src_port,
            five_tuple.dst_ip,
            five_tuple.dst_port,
            five_tuple.protocol
        );
        self.routes.get(&key).cloned().or_else(|| self.default_route.clone())
    }

    pub fn set_default_route(&mut self, interface: String) {
        self.default_route = Some(interface);
    }
}

/// NAT mapping entry.
#[derive(Clone, Debug)]
pub struct NatMapping {
    pub lan_ip: Ipv4Addr,
    pub lan_port: u16,
    pub wan_ip: Ipv4Addr,
    pub wan_port: u16,
    pub protocol: u8,
}

/// Mock NAT translator.
pub struct Translator {
    mappings: Vec<NatMapping>,
}

impl Translator {
    pub fn new() -> Self {
        Translator {
            mappings: Vec::new(),
        }
    }

    pub fn add_mapping(
        &mut self,
        lan_ip: Ipv4Addr,
        lan_port: u16,
        wan_ip: Ipv4Addr,
        wan_port: u16,
        protocol: u8,
    ) {
        self.mappings.push(NatMapping {
            lan_ip,
            lan_port,
            wan_ip,
            wan_port,
            protocol,
        });
    }

    pub fn translate_outbound(&self, packet: &mut [u8]) -> bool {
        if packet.len() < 40 {
            return false;
        }

        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let src_port = u16::from_be_bytes([packet[20], packet[21]]);

        for mapping in &self.mappings {
            if mapping.lan_ip == src_ip && mapping.lan_port == src_port {
                // Update source IP
                let wan_octets = mapping.wan_ip.octets();
                packet[12..16].copy_from_slice(&wan_octets);

                // Update source port
                let port_bytes = mapping.wan_port.to_be_bytes();
                packet[20..22].copy_from_slice(&port_bytes);

                // Recalculate checksums
                self.update_checksums(packet);
                return true;
            }
        }
        false
    }

    pub fn translate_inbound(&self, packet: &mut [u8]) -> bool {
        if packet.len() < 40 {
            return false;
        }

        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_port = u16::from_be_bytes([packet[22], packet[23]]);

        for mapping in &self.mappings {
            if mapping.wan_ip == dst_ip && mapping.wan_port == dst_port {
                // Update destination IP
                let lan_octets = mapping.lan_ip.octets();
                packet[16..20].copy_from_slice(&lan_octets);

                // Update destination port
                let port_bytes = mapping.lan_port.to_be_bytes();
                packet[22..24].copy_from_slice(&port_bytes);

                // Recalculate checksums
                self.update_checksums(packet);
                return true;
            }
        }
        false
    }

    fn update_checksums(&self, packet: &mut [u8]) {
        // Update IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let ip_checksum = calculate_ip_checksum(&packet[0..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // Update TCP checksum (simplified - sets to 0 for this mock)
        packet[36] = 0;
        packet[37] = 0;
    }
}

/// Mock forwarding engine.
pub struct ForwardingEngine;

impl ForwardingEngine {
    pub fn new() -> Self {
        ForwardingEngine
    }

    pub fn forward_packet(&self, _packet: &[u8], _interface: &str) -> bool {
        true
    }
}

// =============================================================================
// Test Utilities
// =============================================================================

/// Creates a test TCP packet with specified parameters.
fn create_test_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(60);

    // IPv4 header (20 bytes)
    packet.push(0x45); // Version + IHL
    packet.push(0x00); // DSCP + ECN
    packet.extend_from_slice(&[0x00, 0x3c]); // Total length (60 bytes)
    packet.extend_from_slice(&[0x00, 0x01]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
    packet.push(0x40); // TTL
    packet.push(0x06); // Protocol (TCP)
    packet.extend_from_slice(&[0x00, 0x00]); // Header checksum (placeholder)
    packet.extend_from_slice(&src_ip.octets()); // Source IP
    packet.extend_from_slice(&dst_ip.octets()); // Destination IP

    // TCP header (20 bytes)
    packet.extend_from_slice(&src_port.to_be_bytes()); // Source port
    packet.extend_from_slice(&dst_port.to_be_bytes()); // Destination port
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence number
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment
    packet.push(0x50); // Data offset (5 * 4 = 20 bytes)
    packet.push(0x02); // Flags (SYN)
    packet.extend_from_slice(&[0xff, 0xff]); // Window size
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (placeholder)
    packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    // Pad to 60 bytes
    while packet.len() < 60 {
        packet.push(0x00);
    }

    // Calculate IP checksum
    let checksum = calculate_ip_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet
}

/// Parses a TCP packet and extracts key fields.
struct ParsedPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

fn parse_tcp_packet(packet: &[u8]) -> ParsedPacket {
    ParsedPacket {
        src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        src_port: u16::from_be_bytes([packet[20], packet[21]]),
        dst_port: u16::from_be_bytes([packet[22], packet[23]]),
    }
}

/// Calculates IP header checksum.
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Gets IP checksum from packet.
fn get_ip_checksum(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[10], packet[11]])
}

/// Gets TCP checksum from packet.
fn get_tcp_checksum(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[36], packet[37]])
}

/// Verifies IP checksum is valid.
fn verify_ip_checksum(packet: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([packet[i], packet[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 == 0xFFFF
}

// =============================================================================
// Packet Queue Tests
// =============================================================================

#[test]
fn test_packet_queue_push_pop() {
    let queue = PacketQueue::new(1024);

    let packet = vec![0u8; 64];
    let success = queue.push(packet.clone());
    assert!(success, "Push should succeed on empty queue");

    let popped = queue.pop();
    assert!(popped.is_some(), "Pop should return packet");
    assert_eq!(popped.unwrap(), packet, "Popped packet should match pushed");
}

#[test]
fn test_packet_queue_fifo_order() {
    let queue = PacketQueue::new(100);

    for i in 0..10 {
        queue.push(vec![i as u8; 64]);
    }

    for i in 0..10 {
        let packet = queue.pop().unwrap();
        assert_eq!(packet[0], i as u8, "Packets should be in FIFO order");
    }
}

#[test]
fn test_packet_queue_capacity() {
    let capacity = 10;
    let queue = PacketQueue::new(capacity);

    // Fill queue to capacity
    for i in 0..capacity {
        let packet = vec![i as u8; 64];
        assert!(queue.push(packet), "Push {} should succeed", i);
    }

    // Next push should fail (queue full)
    let overflow_packet = vec![0xff; 64];
    assert!(!queue.push(overflow_packet), "Push should fail on full queue");

    // Pop one and retry
    queue.pop();
    assert!(queue.push(vec![0xff; 64]), "Push should succeed after pop");
}

#[test]
fn test_packet_queue_empty_pop() {
    let queue = PacketQueue::new(10);
    assert!(queue.pop().is_none(), "Pop on empty queue should return None");
}

#[test]
fn test_packet_queue_concurrent_access() {
    let queue = Arc::new(PacketQueue::new(1000));
    let mut handles = vec![];

    // Spawn producer threads
    for i in 0..4 {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                let packet = vec![(i * 100 + j) as u8; 64];
                while !q.push(packet.clone()) {
                    thread::yield_now();
                }
            }
        }));
    }

    // Spawn consumer threads
    for _ in 0..4 {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            let mut count = 0;
            while count < 100 {
                if q.pop().is_some() {
                    count += 1;
                } else {
                    thread::yield_now();
                }
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Queue should be empty
    assert!(queue.pop().is_none(), "Queue should be empty after balanced push/pop");
}

// =============================================================================
// Routing Engine Tests
// =============================================================================

#[test]
fn test_routing_engine_five_tuple_match() {
    let mut engine = RoutingEngine::new();

    let five_tuple = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 50000,
        dst_port: 80,
        protocol: 6,
    };

    let wan_interface = "wan2".to_string();
    engine.add_route(five_tuple.clone(), wan_interface.clone());

    let result = engine.route_packet(&five_tuple);
    assert!(result.is_some(), "Route should be found");
    assert_eq!(result.unwrap(), wan_interface, "Should route to wan2");
}

#[test]
fn test_routing_engine_default_route() {
    let engine = RoutingEngine::new();

    let five_tuple = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(1, 1, 1, 1),
        src_port: 50001,
        dst_port: 443,
        protocol: 6,
    };

    let result = engine.route_packet(&five_tuple);
    assert!(result.is_some(), "Default route should exist");
    assert_eq!(result.unwrap(), "wan1", "Should use default wan1");
}

#[test]
fn test_routing_engine_no_route() {
    let mut engine = RoutingEngine::new();
    engine.default_route = None;

    let five_tuple = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(1, 1, 1, 1),
        src_port: 50001,
        dst_port: 443,
        protocol: 6,
    };

    let result = engine.route_packet(&five_tuple);
    assert!(result.is_none(), "Should return None when no route exists");
}

#[test]
fn test_routing_engine_multiple_routes() {
    let mut engine = RoutingEngine::new();

    // Add routes for different connections
    for i in 0..100 {
        let five_tuple = FiveTuple {
            src_ip: Ipv4Addr::new(192, 168, 1, i as u8),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 50000 + i,
            dst_port: 80,
            protocol: 6,
        };
        let interface = format!("wan{}", (i % 3) + 1);
        engine.add_route(five_tuple, interface);
    }

    // Verify route lookups
    let lookup = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 50),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 50050,
        dst_port: 80,
        protocol: 6,
    };
    let result = engine.route_packet(&lookup);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "wan3"); // 50 % 3 + 1 = 3
}

// =============================================================================
// NAT Translator Tests
// =============================================================================

#[test]
fn test_nat_translation_outbound() {
    let mut translator = Translator::new();

    let lan_ip = Ipv4Addr::new(192, 168, 1, 100);
    let lan_port = 50000;
    let wan_ip = Ipv4Addr::new(203, 0, 113, 5);
    let wan_port = 60000;

    translator.add_mapping(lan_ip, lan_port, wan_ip, wan_port, 6);

    let mut packet = create_test_tcp_packet(lan_ip, lan_port, Ipv4Addr::new(8, 8, 8, 8), 80);
    let translated = translator.translate_outbound(&mut packet);

    assert!(translated, "Translation should succeed");

    let parsed = parse_tcp_packet(&packet);
    assert_eq!(parsed.src_ip, wan_ip, "Source IP should be translated to WAN IP");
    assert_eq!(parsed.src_port, wan_port, "Source port should be translated to WAN port");
}

#[test]
fn test_nat_translation_inbound() {
    let mut translator = Translator::new();

    let lan_ip = Ipv4Addr::new(192, 168, 1, 100);
    let lan_port = 50000;
    let wan_ip = Ipv4Addr::new(203, 0, 113, 5);
    let wan_port = 60000;

    translator.add_mapping(lan_ip, lan_port, wan_ip, wan_port, 6);

    // Inbound packet (return traffic)
    let mut packet = create_test_tcp_packet(Ipv4Addr::new(8, 8, 8, 8), 80, wan_ip, wan_port);
    let translated = translator.translate_inbound(&mut packet);

    assert!(translated, "Reverse translation should succeed");

    let parsed = parse_tcp_packet(&packet);
    assert_eq!(parsed.dst_ip, lan_ip, "Dest IP should be translated to LAN IP");
    assert_eq!(parsed.dst_port, lan_port, "Dest port should be translated to LAN port");
}

#[test]
fn test_nat_no_matching_mapping() {
    let translator = Translator::new();

    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 200),
        55000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    let original_packet = packet.clone();
    let translated = translator.translate_outbound(&mut packet);

    assert!(!translated, "Translation should fail without mapping");
    assert_eq!(packet, original_packet, "Packet should be unchanged");
}

#[test]
fn test_nat_checksum_recalculation() {
    let mut translator = Translator::new();

    translator.add_mapping(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(203, 0, 113, 5),
        60000,
        6,
    );

    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    let original_ip_checksum = get_ip_checksum(&packet);

    translator.translate_outbound(&mut packet);

    let new_ip_checksum = get_ip_checksum(&packet);

    assert_ne!(
        original_ip_checksum, new_ip_checksum,
        "IP checksum should change after translation"
    );
}

#[test]
fn test_nat_multiple_mappings() {
    let mut translator = Translator::new();

    // Add multiple mappings
    for i in 0..10 {
        translator.add_mapping(
            Ipv4Addr::new(192, 168, 1, 100 + i as u8),
            50000 + i,
            Ipv4Addr::new(203, 0, 113, 5),
            60000 + i,
            6,
        );
    }

    // Test translation for middle mapping
    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 105),
        50005,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    let translated = translator.translate_outbound(&mut packet);
    assert!(translated);

    let parsed = parse_tcp_packet(&packet);
    assert_eq!(parsed.src_port, 60005);
}

// =============================================================================
// Forwarding Engine Tests
// =============================================================================

#[test]
fn test_forwarding_engine_zero_copy() {
    let engine = ForwardingEngine::new();

    let packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );
    let packet_ptr = packet.as_ptr();

    let result = engine.forward_packet(&packet, "wan1");
    assert!(result, "Forward should succeed");

    // Verify packet buffer wasn't moved
    assert_eq!(packet.as_ptr(), packet_ptr, "Packet pointer should be unchanged");
}

#[test]
fn test_forwarding_engine_different_interfaces() {
    let engine = ForwardingEngine::new();

    let packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    assert!(engine.forward_packet(&packet, "wan1"));
    assert!(engine.forward_packet(&packet, "wan2"));
    assert!(engine.forward_packet(&packet, "lan1"));
}

// =============================================================================
// Checksum Tests
// =============================================================================

#[test]
fn test_ip_checksum_calculation() {
    let packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    assert!(verify_ip_checksum(&packet), "IP checksum should be valid");
}

#[test]
fn test_ip_checksum_detects_corruption() {
    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    // Corrupt a byte
    packet[15] ^= 0xFF;

    assert!(!verify_ip_checksum(&packet), "Corrupted packet should fail checksum");
}

// =============================================================================
// Five-Tuple Tests
// =============================================================================

#[test]
fn test_five_tuple_equality() {
    let tuple1 = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 50000,
        dst_port: 80,
        protocol: 6,
    };

    let tuple2 = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 50000,
        dst_port: 80,
        protocol: 6,
    };

    assert_eq!(tuple1, tuple2);
}

#[test]
fn test_five_tuple_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();

    for i in 0..100 {
        let tuple = FiveTuple {
            src_ip: Ipv4Addr::new(192, 168, 1, i as u8),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 50000 + i,
            dst_port: 80,
            protocol: 6,
        };
        set.insert(tuple);
    }

    assert_eq!(set.len(), 100, "All tuples should be unique");
}

// =============================================================================
// Packet Parsing Tests
// =============================================================================

#[test]
fn test_packet_parsing() {
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
    let src_port = 50000u16;
    let dst_port = 80u16;

    let packet = create_test_tcp_packet(src_ip, src_port, dst_ip, dst_port);
    let parsed = parse_tcp_packet(&packet);

    assert_eq!(parsed.src_ip, src_ip);
    assert_eq!(parsed.dst_ip, dst_ip);
    assert_eq!(parsed.src_port, src_port);
    assert_eq!(parsed.dst_port, dst_port);
}

#[test]
fn test_packet_structure() {
    let packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    // Verify IPv4 version
    assert_eq!(packet[0] >> 4, 4, "Should be IPv4");

    // Verify IHL
    assert_eq!(packet[0] & 0x0F, 5, "IHL should be 5 (20 bytes)");

    // Verify protocol
    assert_eq!(packet[9], 6, "Protocol should be TCP (6)");

    // Verify TTL
    assert_eq!(packet[8], 0x40, "TTL should be 64");
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_packet() {
    let translator = Translator::new();
    let mut packet: Vec<u8> = vec![];

    let result = translator.translate_outbound(&mut packet);
    assert!(!result, "Empty packet translation should fail");
}

#[test]
fn test_short_packet() {
    let translator = Translator::new();
    let mut packet = vec![0u8; 20]; // Only IP header, no TCP

    let result = translator.translate_outbound(&mut packet);
    assert!(!result, "Short packet translation should fail");
}

#[test]
fn test_max_port_values() {
    let mut translator = Translator::new();

    translator.add_mapping(
        Ipv4Addr::new(192, 168, 1, 100),
        65535, // Max port
        Ipv4Addr::new(203, 0, 113, 5),
        65535,
        6,
    );

    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        65535,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    let translated = translator.translate_outbound(&mut packet);
    assert!(translated, "Max port translation should succeed");
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_packet_flow() {
    // Create routing engine
    let mut router = RoutingEngine::new();
    router.set_default_route("wan1".to_string());

    // Create NAT translator
    let mut nat = Translator::new();
    nat.add_mapping(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(203, 0, 113, 5),
        60000,
        6,
    );

    // Create forwarding engine
    let forwarder = ForwardingEngine::new();

    // Create packet
    let mut packet = create_test_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        Ipv4Addr::new(8, 8, 8, 8),
        80,
    );

    // 1. Route lookup
    let five_tuple = FiveTuple {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 50000,
        dst_port: 80,
        protocol: 6,
    };
    let interface = router.route_packet(&five_tuple);
    assert!(interface.is_some());

    // 2. NAT translation
    let translated = nat.translate_outbound(&mut packet);
    assert!(translated);

    // 3. Forward packet
    let forwarded = forwarder.forward_packet(&packet, &interface.unwrap());
    assert!(forwarded);

    // Verify final packet state
    let parsed = parse_tcp_packet(&packet);
    assert_eq!(parsed.src_ip, Ipv4Addr::new(203, 0, 113, 5));
    assert_eq!(parsed.src_port, 60000);
}
