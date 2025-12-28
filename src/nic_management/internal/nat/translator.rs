//! High-Performance NAT/NAPT Translation Engine
//!
//! This module implements Network Address Translation (NAT) and Network Address
//! Port Translation (NAPT) for translating internal private IP addresses to
//! external public IP addresses.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use parking_lot::RwLock;

// =============================================================================
// Error Types
// =============================================================================

/// NAT translation error types.
#[derive(Debug, Clone)]
pub enum NATError {
    /// Inbound packet has no NAT mapping.
    NoMappingFound,
    /// All ports in range are allocated.
    PortExhausted,
    /// No active WAN interfaces.
    NoWANAvailable,
    /// Maximum mappings limit reached.
    MappingTableFull,
    /// Unsupported protocol.
    InvalidProtocol(u8),
    /// Port already used by static rule.
    StaticMappingConflict,
}

impl std::fmt::Display for NATError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NATError::NoMappingFound => write!(f, "No NAT mapping found"),
            NATError::PortExhausted => write!(f, "NAT port pool exhausted"),
            NATError::NoWANAvailable => write!(f, "No WAN interface available"),
            NATError::MappingTableFull => write!(f, "NAT mapping table full"),
            NATError::InvalidProtocol(p) => write!(f, "Invalid protocol: {}", p),
            NATError::StaticMappingConflict => write!(f, "Static mapping conflict"),
        }
    }
}

impl std::error::Error for NATError {}

// =============================================================================
// NAT Type Enumeration
// =============================================================================

/// NAT behavior type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NATType {
    /// Any external host can send to mapped port.
    FullCone,
    /// Only external hosts contacted by client can send.
    RestrictedCone,
    /// Only specific external IP:port can send.
    PortRestrictedCone,
    /// Different external ports for different destinations.
    Symmetric,
}

impl Default for NATType {
    fn default() -> Self {
        NATType::PortRestrictedCone
    }
}

// =============================================================================
// Connection State
// =============================================================================

/// TCP connection state for stateful NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// SYN sent, no reply yet.
    New,
    /// Connection established.
    Established,
    /// FIN sent.
    Closing,
    /// Connection terminated.
    Closed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::New
    }
}

// =============================================================================
// Five-Tuple Key
// =============================================================================

/// Connection identifier for outbound table lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    /// Source (internal) IP.
    pub src_ip: Ipv4Addr,
    /// Source (internal) port.
    pub src_port: u16,
    /// Destination (external) IP.
    pub dst_ip: Ipv4Addr,
    /// Destination (external) port.
    pub dst_port: u16,
    /// Protocol.
    pub protocol: u8,
}

impl Hash for FiveTuple {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.src_port.hash(state);
        self.dst_ip.hash(state);
        self.dst_port.hash(state);
        self.protocol.hash(state);
    }
}

impl FiveTuple {
    /// Creates a new five-tuple.
    pub fn new(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }
}

// =============================================================================
// Endpoint Types
// =============================================================================

/// External (WAN-side) endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExternalEndpoint {
    /// External IP (WAN IP).
    pub ip: Ipv4Addr,
    /// External port.
    pub port: u16,
    /// Protocol.
    pub protocol: u8,
}

/// Internal (LAN-side) endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalEndpoint {
    /// Internal IP (LAN client IP).
    pub ip: Ipv4Addr,
    /// Internal port.
    pub port: u16,
    /// Protocol.
    pub protocol: u8,
}

// =============================================================================
// NAT Mapping Entry
// =============================================================================

/// Single NAT translation mapping.
#[derive(Debug, Clone)]
pub struct NATMapping {
    /// LAN client IP address.
    pub internal_ip: Ipv4Addr,
    /// LAN client port.
    pub internal_port: u16,
    /// WAN public IP address.
    pub external_ip: Ipv4Addr,
    /// WAN public port.
    pub external_port: u16,
    /// Destination IP (for symmetric NAT).
    pub dest_ip: Ipv4Addr,
    /// Destination port (for symmetric NAT).
    pub dest_port: u16,
    /// Protocol (6=TCP, 17=UDP, 1=ICMP).
    pub protocol: u8,
    /// WAN interface index.
    pub wan_interface_index: i32,
    /// Mapping creation time.
    pub created_at: Instant,
    /// Last packet timestamp.
    pub last_used: Instant,
    /// Mapping expiration time.
    pub expires_at: Instant,
    /// Total bytes through this mapping.
    pub bytes_transferred: u64,
    /// Total packets through this mapping.
    pub packet_count: u64,
    /// TCP connection state.
    pub connection_state: ConnectionState,
    /// Is static mapping (port forwarding).
    pub is_static: bool,
}

impl NATMapping {
    /// Creates a new dynamic NAT mapping.
    pub fn new(
        internal_ip: Ipv4Addr,
        internal_port: u16,
        external_ip: Ipv4Addr,
        external_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        protocol: u8,
        wan_interface_index: i32,
        timeout: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            internal_ip,
            internal_port,
            external_ip,
            external_port,
            dest_ip,
            dest_port,
            protocol,
            wan_interface_index,
            created_at: now,
            last_used: now,
            expires_at: now + timeout,
            bytes_transferred: 0,
            packet_count: 0,
            connection_state: ConnectionState::New,
            is_static: false,
        }
    }

    /// Creates a static NAT mapping (port forwarding).
    pub fn static_mapping(
        internal_ip: Ipv4Addr,
        internal_port: u16,
        external_ip: Ipv4Addr,
        external_port: u16,
        protocol: u8,
        wan_interface_index: i32,
    ) -> Self {
        let now = Instant::now();
        Self {
            internal_ip,
            internal_port,
            external_ip,
            external_port,
            dest_ip: Ipv4Addr::UNSPECIFIED,
            dest_port: 0,
            protocol,
            wan_interface_index,
            created_at: now,
            last_used: now,
            expires_at: now + Duration::from_secs(u64::MAX / 2),
            bytes_transferred: 0,
            packet_count: 0,
            connection_state: ConnectionState::Established,
            is_static: true,
        }
    }

    /// Returns whether the mapping has expired.
    pub fn is_expired(&self) -> bool {
        !self.is_static && Instant::now() > self.expires_at
    }

    /// Extends the mapping timeout.
    pub fn extend_timeout(&mut self, timeout: Duration) {
        self.last_used = Instant::now();
        self.expires_at = self.last_used + timeout;
    }

    /// Updates packet statistics.
    pub fn update_stats(&mut self, bytes: u64) {
        self.last_used = Instant::now();
        self.bytes_transferred += bytes;
        self.packet_count += 1;
    }
}

// =============================================================================
// WAN Interface
// =============================================================================

/// WAN interface for NAT.
#[derive(Debug, Clone)]
pub struct WANInterface {
    /// Interface index.
    pub interface_index: i32,
    /// Interface name.
    pub interface_name: String,
    /// WAN public IP address.
    pub external_ip: Ipv4Addr,
    /// Interface is UP and available.
    pub is_active: bool,
    /// Preference for WAN selection (lower = preferred).
    pub priority: u32,
}

// =============================================================================
// Port Allocator
// =============================================================================

/// Dynamic port allocator for NAT mappings.
struct PortAllocator {
    /// Start of allocatable range.
    port_range_start: u16,
    /// End of allocatable range.
    port_range_end: u16,
    /// Allocated ports map (port → internal IP).
    allocated_ports: AHashMap<(u16, u8), Ipv4Addr>,
    /// Next port to try allocating.
    next_port: u16,
}

impl PortAllocator {
    /// Creates a new port allocator.
    fn new(start: u16, end: u16) -> Self {
        Self {
            port_range_start: start,
            port_range_end: end,
            allocated_ports: AHashMap::new(),
            next_port: start,
        }
    }

    /// Allocates a port.
    fn allocate(
        &mut self,
        internal_ip: Ipv4Addr,
        protocol: u8,
        preferred_port: Option<u16>,
    ) -> Result<u16, NATError> {
        // Try preferred port first (port preservation).
        if let Some(pref) = preferred_port {
            if pref >= self.port_range_start
                && pref <= self.port_range_end
                && !self.allocated_ports.contains_key(&(pref, protocol))
            {
                self.allocated_ports.insert((pref, protocol), internal_ip);
                return Ok(pref);
            }
        }

        // Sequential allocation.
        let range_size = (self.port_range_end - self.port_range_start + 1) as usize;

        for _ in 0..range_size {
            let port = self.next_port;
            self.next_port = if self.next_port >= self.port_range_end {
                self.port_range_start
            } else {
                self.next_port + 1
            };

            if !self.allocated_ports.contains_key(&(port, protocol)) {
                self.allocated_ports.insert((port, protocol), internal_ip);
                return Ok(port);
            }
        }

        Err(NATError::PortExhausted)
    }

    /// Releases a port.
    fn release(&mut self, port: u16, protocol: u8) {
        self.allocated_ports.remove(&(port, protocol));
    }

    /// Returns the utilization percentage.
    fn utilization(&self) -> f64 {
        let total = (self.port_range_end - self.port_range_start + 1) as f64;
        (self.allocated_ports.len() as f64 / total) * 100.0
    }
}

// =============================================================================
// NAT Configuration
// =============================================================================

/// NAT translator configuration.
#[derive(Debug, Clone)]
pub struct NATConfig {
    /// NAT type.
    pub nat_type: NATType,
    /// Start of dynamic port range.
    pub port_range_start: u16,
    /// End of dynamic port range.
    pub port_range_end: u16,
    /// TCP session timeout.
    pub tcp_timeout: Duration,
    /// UDP session timeout.
    pub udp_timeout: Duration,
    /// ICMP session timeout.
    pub icmp_timeout: Duration,
    /// Try to preserve client port.
    pub enable_port_preservation: bool,
    /// Support NAT hairpinning.
    pub enable_hairpinning: bool,
    /// Maximum concurrent NAT mappings.
    pub max_mappings: usize,
}

impl Default for NATConfig {
    fn default() -> Self {
        Self {
            nat_type: NATType::PortRestrictedCone,
            port_range_start: 10000,
            port_range_end: 65535,
            tcp_timeout: Duration::from_secs(300),
            udp_timeout: Duration::from_secs(180),
            icmp_timeout: Duration::from_secs(30),
            enable_port_preservation: false,
            enable_hairpinning: true,
            max_mappings: 65535,
        }
    }
}

// =============================================================================
// NAT Statistics
// =============================================================================

/// NAT performance statistics.
#[derive(Debug, Clone, Default)]
pub struct NATStatistics {
    /// Current active NAT mappings.
    pub active_mappings: usize,
    /// Lifetime mapping count.
    pub total_mappings_created: u64,
    /// Expired mapping count.
    pub total_mappings_expired: u64,
    /// Port pool utilization (0-100).
    pub port_pool_utilization: f64,
    /// Current translation rate.
    pub translations_per_second: u64,
    /// Active TCP mappings.
    pub tcp_mappings: usize,
    /// Active UDP mappings.
    pub udp_mappings: usize,
    /// Active ICMP mappings.
    pub icmp_mappings: usize,
}

// =============================================================================
// NAT Translator
// =============================================================================

/// High-performance NAT/NAPT translation engine.
pub struct NATTranslator {
    /// Outbound mappings (internal → external).
    outbound_table: RwLock<AHashMap<FiveTuple, NATMapping>>,
    /// Inbound mappings (external → internal).
    inbound_table: RwLock<AHashMap<ExternalEndpoint, InternalEndpoint>>,
    /// Dynamic port allocator.
    port_allocator: RwLock<PortAllocator>,
    /// WAN interface pool.
    wan_interfaces: RwLock<Vec<WANInterface>>,
    /// NAT configuration.
    config: NATConfig,
    /// Total mappings created.
    mappings_created: AtomicU64,
    /// Total mappings expired.
    mappings_expired: AtomicU64,
    /// Total translations.
    translations: AtomicU64,
}

impl NATTranslator {
    /// Creates a new NAT translator.
    pub fn new(config: NATConfig) -> Self {
        let port_allocator = PortAllocator::new(config.port_range_start, config.port_range_end);

        Self {
            outbound_table: RwLock::new(AHashMap::new()),
            inbound_table: RwLock::new(AHashMap::new()),
            port_allocator: RwLock::new(port_allocator),
            wan_interfaces: RwLock::new(Vec::new()),
            config,
            mappings_created: AtomicU64::new(0),
            mappings_expired: AtomicU64::new(0),
            translations: AtomicU64::new(0),
        }
    }

    /// Creates a translator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(NATConfig::default())
    }

    /// Adds a WAN interface for NAT.
    pub fn add_wan_interface(&self, interface: WANInterface) {
        let mut interfaces = self.wan_interfaces.write();
        interfaces.push(interface);
        interfaces.sort_by_key(|i| i.priority);
    }

    /// Removes a WAN interface.
    pub fn remove_wan_interface(&self, interface_index: i32) {
        let mut interfaces = self.wan_interfaces.write();
        interfaces.retain(|i| i.interface_index != interface_index);
    }

    /// Gets timeout for protocol.
    fn get_timeout(&self, protocol: u8) -> Duration {
        match protocol {
            6 => self.config.tcp_timeout,  // TCP
            17 => self.config.udp_timeout, // UDP
            1 => self.config.icmp_timeout, // ICMP
            _ => self.config.udp_timeout,  // Default to UDP timeout
        }
    }

    /// Selects a WAN interface for new mapping.
    fn select_wan_interface(&self) -> Result<WANInterface, NATError> {
        let interfaces = self.wan_interfaces.read();
        interfaces
            .iter()
            .find(|i| i.is_active)
            .cloned()
            .ok_or(NATError::NoWANAvailable)
    }

    /// Translates an outbound packet (LAN → WAN).
    pub fn translate_outbound(
        &self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: u8,
        packet_len: u64,
    ) -> Result<NATMapping, NATError> {
        let five_tuple = FiveTuple::new(src_ip, src_port, dst_ip, dst_port, protocol);
        let timeout = self.get_timeout(protocol);

        // Check for existing mapping.
        {
            let mut table = self.outbound_table.write();
            if let Some(mapping) = table.get_mut(&five_tuple) {
                mapping.extend_timeout(timeout);
                mapping.update_stats(packet_len);
                self.translations.fetch_add(1, Ordering::Relaxed);
                return Ok(mapping.clone());
            }
        }

        // Check mapping limit.
        {
            let table = self.outbound_table.read();
            if table.len() >= self.config.max_mappings {
                return Err(NATError::MappingTableFull);
            }
        }

        // Select WAN interface.
        let wan = self.select_wan_interface()?;

        // Allocate external port.
        let preferred_port = if self.config.enable_port_preservation {
            Some(src_port)
        } else {
            None
        };

        let external_port = {
            let mut allocator = self.port_allocator.write();
            allocator.allocate(src_ip, protocol, preferred_port)?
        };

        // Create new mapping.
        let mapping = NATMapping::new(
            src_ip,
            src_port,
            wan.external_ip,
            external_port,
            dst_ip,
            dst_port,
            protocol,
            wan.interface_index,
            timeout,
        );

        // Insert into both tables.
        {
            let mut outbound = self.outbound_table.write();
            outbound.insert(five_tuple, mapping.clone());
        }

        {
            let external = ExternalEndpoint {
                ip: wan.external_ip,
                port: external_port,
                protocol,
            };
            let internal = InternalEndpoint {
                ip: src_ip,
                port: src_port,
                protocol,
            };
            let mut inbound = self.inbound_table.write();
            inbound.insert(external, internal);
        }

        self.mappings_created.fetch_add(1, Ordering::Relaxed);
        self.translations.fetch_add(1, Ordering::Relaxed);

        Ok(mapping)
    }

    /// Translates an inbound packet (WAN → LAN).
    pub fn translate_inbound(
        &self,
        external_ip: Ipv4Addr,
        external_port: u16,
        protocol: u8,
        packet_len: u64,
    ) -> Result<InternalEndpoint, NATError> {
        let external = ExternalEndpoint {
            ip: external_ip,
            port: external_port,
            protocol,
        };

        // Lookup inbound mapping.
        let internal = {
            let table = self.inbound_table.read();
            table.get(&external).cloned()
        };

        match internal {
            Some(endpoint) => {
                // Update statistics in outbound table.
                // (Would need reverse lookup or store stats separately)
                self.translations.fetch_add(1, Ordering::Relaxed);
                Ok(endpoint)
            }
            None => Err(NATError::NoMappingFound),
        }
    }

    /// Updates TCP connection state.
    pub fn update_tcp_state(&self, five_tuple: &FiveTuple, tcp_flags: u8) {
        const TCP_SYN: u8 = 0x02;
        const TCP_ACK: u8 = 0x10;
        const TCP_FIN: u8 = 0x01;
        const TCP_RST: u8 = 0x04;

        let mut table = self.outbound_table.write();
        if let Some(mapping) = table.get_mut(five_tuple) {
            let new_state = if tcp_flags & TCP_RST != 0 {
                ConnectionState::Closed
            } else if tcp_flags & TCP_FIN != 0 {
                ConnectionState::Closing
            } else if tcp_flags & TCP_SYN != 0 && tcp_flags & TCP_ACK != 0 {
                ConnectionState::Established
            } else if tcp_flags & TCP_SYN != 0 {
                ConnectionState::New
            } else {
                mapping.connection_state
            };

            mapping.connection_state = new_state;

            // Shorter timeout for closed connections.
            if new_state == ConnectionState::Closed {
                mapping.expires_at = Instant::now() + Duration::from_secs(10);
            }
        }
    }

    /// Adds a static port forwarding rule.
    pub fn add_static_mapping(
        &self,
        external_port: u16,
        internal_ip: Ipv4Addr,
        internal_port: u16,
        protocol: u8,
        wan_interface_index: i32,
    ) -> Result<(), NATError> {
        // Get WAN IP.
        let wan_ip = {
            let interfaces = self.wan_interfaces.read();
            interfaces
                .iter()
                .find(|i| i.interface_index == wan_interface_index)
                .map(|i| i.external_ip)
                .ok_or(NATError::NoWANAvailable)?
        };

        // Check if port is already allocated.
        {
            let allocator = self.port_allocator.read();
            if allocator
                .allocated_ports
                .contains_key(&(external_port, protocol))
            {
                return Err(NATError::StaticMappingConflict);
            }
        }

        // Reserve port.
        {
            let mut allocator = self.port_allocator.write();
            allocator
                .allocated_ports
                .insert((external_port, protocol), internal_ip);
        }

        // Create static mapping.
        let external = ExternalEndpoint {
            ip: wan_ip,
            port: external_port,
            protocol,
        };
        let internal = InternalEndpoint {
            ip: internal_ip,
            port: internal_port,
            protocol,
        };

        let mut table = self.inbound_table.write();
        table.insert(external, internal);

        Ok(())
    }

    /// Removes a static port forwarding rule.
    pub fn remove_static_mapping(&self, external_port: u16, protocol: u8) -> Result<(), NATError> {
        // Release port.
        {
            let mut allocator = self.port_allocator.write();
            allocator.release(external_port, protocol);
        }

        // Remove from inbound table.
        // (Would need to find the entry by external port)

        Ok(())
    }

    /// Cleans up expired mappings.
    pub fn cleanup_expired_mappings(&self) -> usize {
        let mut expired_count = 0;

        // Find expired outbound mappings.
        let expired_tuples: Vec<(FiveTuple, u16, u8)> = {
            let table = self.outbound_table.read();
            table
                .iter()
                .filter(|(_, m)| m.is_expired())
                .map(|(t, m)| (*t, m.external_port, m.protocol))
                .collect()
        };

        // Remove expired mappings.
        for (five_tuple, port, protocol) in expired_tuples {
            // Remove from outbound table.
            {
                let mut table = self.outbound_table.write();
                if let Some(mapping) = table.remove(&five_tuple) {
                    // Remove from inbound table.
                    let external = ExternalEndpoint {
                        ip: mapping.external_ip,
                        port: mapping.external_port,
                        protocol: mapping.protocol,
                    };
                    let mut inbound = self.inbound_table.write();
                    inbound.remove(&external);
                }
            }

            // Release port.
            {
                let mut allocator = self.port_allocator.write();
                allocator.release(port, protocol);
            }

            expired_count += 1;
        }

        self.mappings_expired
            .fetch_add(expired_count as u64, Ordering::Relaxed);

        expired_count
    }

    /// Returns NAT statistics.
    pub fn get_statistics(&self) -> NATStatistics {
        let outbound = self.outbound_table.read();
        let allocator = self.port_allocator.read();

        let mut tcp_count = 0;
        let mut udp_count = 0;
        let mut icmp_count = 0;

        for (tuple, _) in outbound.iter() {
            match tuple.protocol {
                6 => tcp_count += 1,
                17 => udp_count += 1,
                1 => icmp_count += 1,
                _ => {}
            }
        }

        NATStatistics {
            active_mappings: outbound.len(),
            total_mappings_created: self.mappings_created.load(Ordering::Relaxed),
            total_mappings_expired: self.mappings_expired.load(Ordering::Relaxed),
            port_pool_utilization: allocator.utilization(),
            translations_per_second: 0, // Would need timing.
            tcp_mappings: tcp_count,
            udp_mappings: udp_count,
            icmp_mappings: icmp_count,
        }
    }

    /// Returns active mapping count.
    pub fn active_mappings(&self) -> usize {
        self.outbound_table.read().len()
    }

    /// Returns the configuration.
    pub fn get_config(&self) -> &NATConfig {
        &self.config
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_translator() -> NATTranslator {
        let config = NATConfig::default();
        let translator = NATTranslator::new(config);

        // Add a WAN interface.
        translator.add_wan_interface(WANInterface {
            interface_index: 1,
            interface_name: "eth0".to_string(),
            external_ip: Ipv4Addr::new(203, 0, 113, 1),
            is_active: true,
            priority: 0,
        });

        translator
    }

    #[test]
    fn test_five_tuple_hash() {
        let t1 = FiveTuple::new(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            17,
        );
        let t2 = FiveTuple::new(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            17,
        );

        assert_eq!(t1, t2);
    }

    #[test]
    fn test_nat_mapping_creation() {
        let mapping = NATMapping::new(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(203, 0, 113, 1),
            40000,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            17,
            1,
            Duration::from_secs(180),
        );

        assert_eq!(mapping.internal_port, 12345);
        assert_eq!(mapping.external_port, 40000);
        assert!(!mapping.is_static);
        assert!(!mapping.is_expired());
    }

    #[test]
    fn test_outbound_translation() {
        let translator = create_test_translator();

        let result = translator.translate_outbound(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            17, // UDP
            100,
        );

        assert!(result.is_ok());
        let mapping = result.unwrap();
        assert_eq!(mapping.internal_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(mapping.external_ip, Ipv4Addr::new(203, 0, 113, 1));
    }

    #[test]
    fn test_outbound_reuse() {
        let translator = create_test_translator();

        // First translation.
        let m1 = translator
            .translate_outbound(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                17,
                100,
            )
            .unwrap();

        // Same five-tuple should reuse mapping.
        let m2 = translator
            .translate_outbound(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                17,
                100,
            )
            .unwrap();

        assert_eq!(m1.external_port, m2.external_port);
    }

    #[test]
    fn test_inbound_translation() {
        let translator = create_test_translator();

        // Create outbound mapping first.
        let mapping = translator
            .translate_outbound(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                17,
                100,
            )
            .unwrap();

        // Inbound translation.
        let result =
            translator.translate_inbound(mapping.external_ip, mapping.external_port, 17, 100);

        assert!(result.is_ok());
        let internal = result.unwrap();
        assert_eq!(internal.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(internal.port, 12345);
    }

    #[test]
    fn test_no_mapping_found() {
        let translator = create_test_translator();

        let result = translator.translate_inbound(Ipv4Addr::new(203, 0, 113, 1), 55555, 17, 100);

        assert!(matches!(result, Err(NATError::NoMappingFound)));
    }

    #[test]
    fn test_port_allocation() {
        let mut allocator = PortAllocator::new(10000, 10010);

        // Allocate ports.
        for i in 0..10 {
            let port = allocator.allocate(Ipv4Addr::new(192, 168, 1, i), 17, None);
            assert!(port.is_ok());
        }

        // Should be exhausted.
        let port = allocator.allocate(Ipv4Addr::new(192, 168, 1, 100), 17, None);
        assert!(matches!(port, Err(NATError::PortExhausted)));
    }

    #[test]
    fn test_port_preservation() {
        let mut allocator = PortAllocator::new(10000, 65535);

        let port = allocator.allocate(Ipv4Addr::new(192, 168, 1, 1), 17, Some(50000));

        assert!(port.is_ok());
        assert_eq!(port.unwrap(), 50000);
    }

    #[test]
    fn test_tcp_state_tracking() {
        let translator = create_test_translator();
        const TCP_SYN: u8 = 0x02;
        const TCP_ACK: u8 = 0x10;

        // Create mapping.
        translator
            .translate_outbound(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(8, 8, 8, 8),
                80,
                6, // TCP
                100,
            )
            .unwrap();

        let five_tuple = FiveTuple::new(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            6,
        );

        // SYN-ACK.
        translator.update_tcp_state(&five_tuple, TCP_SYN | TCP_ACK);

        let table = translator.outbound_table.read();
        let mapping = table.get(&five_tuple).unwrap();
        assert_eq!(mapping.connection_state, ConnectionState::Established);
    }

    #[test]
    fn test_static_mapping() {
        let translator = create_test_translator();

        let result = translator.add_static_mapping(
            80,
            Ipv4Addr::new(192, 168, 1, 10),
            8080,
            6, // TCP
            1,
        );

        assert!(result.is_ok());

        // Inbound should work.
        let inbound = translator.translate_inbound(Ipv4Addr::new(203, 0, 113, 1), 80, 6, 100);

        assert!(inbound.is_ok());
        let internal = inbound.unwrap();
        assert_eq!(internal.port, 8080);
    }

    #[test]
    fn test_statistics() {
        let translator = create_test_translator();

        // Create some mappings.
        for i in 0..5 {
            translator
                .translate_outbound(
                    Ipv4Addr::new(192, 168, 1, i),
                    10000 + i as u16,
                    Ipv4Addr::new(8, 8, 8, 8),
                    53,
                    17,
                    100,
                )
                .unwrap();
        }

        let stats = translator.get_statistics();
        assert_eq!(stats.active_mappings, 5);
        assert_eq!(stats.udp_mappings, 5);
        assert_eq!(stats.total_mappings_created, 5);
    }
}
