//! Packet capture and processing pipeline for NIC Management.
//!
//! Orchestrates packet flow: Capture → Parse → TLS Proxy Inspection → NAT → Route
//! Implements fail-open behavior when TLS Proxy is unavailable (Phase 1).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use log::{debug, error, info, warn};
use tokio::time::timeout;

use crate::internal::config::{Config, NetworkConfig, TlsProxyConfig};
use crate::internal::errors::{NicError, Result};
use crate::internal::integration::tls_proxy_client::{
    InterceptPacketResponse, PacketAction, RawPacket, TLSProxyClient,
};

// =============================================================================
// STATISTICS
// =============================================================================

/// Statistics for packet capture operations and TLS Proxy integration.
#[derive(Debug, Default)]
pub struct CaptureStatistics {
    // Standard network statistics (fields 1-9)
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    
    // TLS Proxy integration statistics (fields 10-16) - NEW Phase 1
    pub packets_sent_to_tls_proxy: AtomicU64,
    pub https_packets_detected: AtomicU64,
    pub sni_extractions_successful: AtomicU64,
    pub dns_resolutions_performed: AtomicU64,
    pub tls_proxy_errors: AtomicU64,
    pub packets_forwarded_unchanged: AtomicU64,
    pub tls_proxy_cumulative_latency_ms: AtomicU64,
}

impl CaptureStatistics {
    /// Calculate average TLS Proxy latency.
    pub fn average_tls_proxy_latency_ms(&self) -> u64 {
        let total = self.packets_sent_to_tls_proxy.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        self.tls_proxy_cumulative_latency_ms.load(Ordering::Relaxed) / total
    }
}

// =============================================================================
// PROTOCOL TYPES
// =============================================================================

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Other(n) => write!(f, "OTHER({})", n),
        }
    }
}

// =============================================================================
// PACKET CAPTURE
// =============================================================================

/// Manages packet capture from network interfaces and processing pipeline.
///
/// Coordinates packet flow through capture → parse → TLS Proxy → NAT → route stages.
pub struct PacketCapture {
    /// Network configuration (interfaces, filters)
    config: NetworkConfig,
    
    /// TLS Proxy client for packet inspection (Phase 1)
    tls_proxy_client: Option<Arc<TLSProxyClient>>,
    
    /// TLS Proxy configuration
    tls_proxy_config: TlsProxyConfig,
    
    /// Statistics counters
    stats: Arc<CaptureStatistics>,
    
    /// Running state
    running: bool,
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

impl PacketCapture {
    /// Create new PacketCapture with TLS Proxy integration.
    ///
    /// # Arguments
    ///
    /// * `config` - Complete configuration including TLS Proxy settings
    /// * `tls_proxy_client` - Optional TLS Proxy client (Some if enabled)
    pub fn new(config: Config, tls_proxy_client: Option<TLSProxyClient>) -> Result<Self> {
        info!("Initializing PacketCapture");
        
        // Validate network configuration
        if config.network.wan_interface.is_empty() {
            return Err(NicError::InterfaceError(
                "WAN interface not configured".to_string()
            ));
        }
        
        // Wrap TLS Proxy client in Arc for sharing
        let tls_proxy_client = tls_proxy_client.map(Arc::new);
        
        // Log TLS Proxy status
        if config.tls_proxy.enabled {
            if tls_proxy_client.is_some() {
                info!("TLS Proxy integration enabled at {}", config.tls_proxy.address);
            } else {
                warn!("TLS Proxy enabled in config but client not provided");
            }
        } else {
            info!("TLS Proxy integration disabled");
        }
        
        // Initialize statistics
        let stats = Arc::new(CaptureStatistics::default());
        
        info!("PacketCapture initialized successfully");
        
        Ok(Self {
            config: config.network,
            tls_proxy_client,
            tls_proxy_config: config.tls_proxy,
            stats,
            running: false,
        })
    }
    
    /// Check if TLS Proxy integration is enabled and available.
    pub fn is_tls_proxy_enabled(&self) -> bool {
        self.tls_proxy_config.enabled && self.tls_proxy_client.is_some()
    }
}

// =============================================================================
// PACKET PROCESSING
// =============================================================================

impl PacketCapture {
    /// Process single captured packet through pipeline with TLS Proxy inspection.
    ///
    /// # Phase 1 Flow
    ///
    /// 1. Parse packet headers and metadata
    /// 2. Check if TLS Proxy enabled
    /// 3. If enabled: Send to TLS Proxy for inspection
    /// 4. Handle TLS Proxy response (action + metadata)
    /// 5. Forward packet (NAT/route in real implementation)
    /// 6. Update statistics
    ///
    /// # Fail-Open Behavior
    ///
    /// If TLS Proxy inspection fails and config.tls_proxy.fail_open=true,
    /// packet is forwarded unchanged to maintain network connectivity.
    pub async fn process_packet(&self, packet: &RawPacket) -> Result<()> {
        // Update RX statistics
        self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.rx_bytes.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        
        // TLS Proxy inspection (Phase 1)
        if self.tls_proxy_config.enabled {
            if let Some(client) = &self.tls_proxy_client {
                match self.inspect_with_tls_proxy(packet, client).await {
                    Ok(response) => {
                        // Log inspection results
                        self.log_inspection_result(packet, &response);
                        
                        // Phase 1: Always FORWARD_UNCHANGED
                        // Phase 2+: Handle MODIFY, DROP actions here
                    }
                    Err(e) => {
                        // TLS Proxy error occurred
                        self.handle_tls_proxy_error(&e);
                        
                        // Check fail-open configuration
                        if self.tls_proxy_config.fail_open {
                            warn!("TLS Proxy error (fail-open): {:?} - Forwarding unchanged", e);
                            // Continue to forwarding
                        } else {
                            // Fail-closed: Drop packet
                            error!("TLS Proxy error (fail-closed): {:?} - Dropping packet", e);
                            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                            return Err(e);
                        }
                    }
                }
            } else {
                warn!("TLS Proxy enabled but client not initialized");
            }
        }
        
        // Forward packet (placeholder - real implementation has NAT/routing)
        self.forward_packet(packet)?;
        
        // Track forwarding (Phase 1 validation)
        self.stats.packets_forwarded_unchanged.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Send packet to TLS Proxy for inspection.
    async fn inspect_with_tls_proxy(
        &self,
        packet: &RawPacket,
        client: &Arc<TLSProxyClient>,
    ) -> Result<InterceptPacketResponse> {
        // Increment packets sent counter
        self.stats.packets_sent_to_tls_proxy.fetch_add(1, Ordering::Relaxed);
        
        // Detect HTTPS traffic (port 443)
        if packet.dest_port == 443 {
            self.stats.https_packets_detected.fetch_add(1, Ordering::Relaxed);
        }
        
        debug!(
            "Sending packet to TLS Proxy: {}:{} -> {}:{}",
            packet.source_ip, packet.source_port,
            packet.dest_ip, packet.dest_port
        );
        
        // Call TLS Proxy client (async gRPC)
        let response = client.intercept_packet(packet).await?;
        
        // Track SNI extraction success
        if !response.sni_hostname.is_empty() {
            self.stats.sni_extractions_successful.fetch_add(1, Ordering::Relaxed);
        }
        
        // Track DNS resolution success
        if !response.resolved_ip.is_empty() {
            self.stats.dns_resolutions_performed.fetch_add(1, Ordering::Relaxed);
        }
        
        // Track latency
        if response.processing_time_ms > 0 {
            self.stats.tls_proxy_cumulative_latency_ms
                .fetch_add(response.processing_time_ms as u64, Ordering::Relaxed);
        }
        
        Ok(response)
    }
    
    /// Handle TLS Proxy error and update statistics.
    fn handle_tls_proxy_error(&self, error: &NicError) {
        // Increment error counter
        self.stats.tls_proxy_errors.fetch_add(1, Ordering::Relaxed);
        
        // Log based on error type
        match error {
            NicError::TlsProxyTimeout(secs) => {
                warn!("TLS Proxy timeout after {} seconds", secs);
            }
            NicError::TlsProxyConnectionError(msg) => {
                error!("TLS Proxy connection failed: {}", msg);
            }
            NicError::TlsProxyUnavailable(msg) => {
                warn!("TLS Proxy unavailable: {}", msg);
            }
            NicError::TlsProxyError(msg) => {
                error!("TLS Proxy processing error: {}", msg);
            }
            NicError::TlsProxyInvalidResponse(msg) => {
                error!("TLS Proxy invalid response: {}", msg);
            }
            _ => {
                error!("Unexpected TLS Proxy error: {:?}", error);
            }
        }
    }
    
    /// Log inspection result.
    fn log_inspection_result(&self, packet: &RawPacket, response: &InterceptPacketResponse) {
        if !response.sni_hostname.is_empty() {
            debug!(
                "Packet inspection: {}:{} -> {}:{} SNI={} Action={:?}",
                packet.source_ip, packet.source_port,
                packet.dest_ip, packet.dest_port,
                response.sni_hostname, response.action
            );
        } else {
            debug!(
                "Packet inspection: {}:{} -> {}:{} (no SNI) Action={:?}",
                packet.source_ip, packet.source_port,
                packet.dest_ip, packet.dest_port,
                response.action
            );
        }
    }
    
    /// Forward packet (placeholder for NAT/routing).
    fn forward_packet(&self, packet: &RawPacket) -> Result<()> {
        // In real implementation: NAT translation + routing
        // For Phase 1: Just update TX statistics
        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

// =============================================================================
// STATISTICS EXPORT
// =============================================================================

impl PacketCapture {
    /// Get reference to statistics.
    pub fn stats(&self) -> &CaptureStatistics {
        &self.stats
    }
    
    /// Export statistics snapshot.
    pub fn get_statistics_snapshot(&self) -> StatisticsSnapshot {
        StatisticsSnapshot {
            rx_packets: self.stats.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.stats.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            rx_errors: self.stats.rx_errors.load(Ordering::Relaxed),
            tx_errors: self.stats.tx_errors.load(Ordering::Relaxed),
            rx_dropped: self.stats.rx_dropped.load(Ordering::Relaxed),
            tx_dropped: self.stats.tx_dropped.load(Ordering::Relaxed),
            packets_sent_to_tls_proxy: self.stats.packets_sent_to_tls_proxy.load(Ordering::Relaxed),
            https_packets_detected: self.stats.https_packets_detected.load(Ordering::Relaxed),
            sni_extractions_successful: self.stats.sni_extractions_successful.load(Ordering::Relaxed),
            dns_resolutions_performed: self.stats.dns_resolutions_performed.load(Ordering::Relaxed),
            tls_proxy_errors: self.stats.tls_proxy_errors.load(Ordering::Relaxed),
            packets_forwarded_unchanged: self.stats.packets_forwarded_unchanged.load(Ordering::Relaxed),
            tls_proxy_average_latency_ms: self.stats.average_tls_proxy_latency_ms(),
        }
    }
}

/// Snapshot of capture statistics.
#[derive(Debug, Clone)]
pub struct StatisticsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub packets_sent_to_tls_proxy: u64,
    pub https_packets_detected: u64,
    pub sni_extractions_successful: u64,
    pub dns_resolutions_performed: u64,
    pub tls_proxy_errors: u64,
    pub packets_forwarded_unchanged: u64,
    pub tls_proxy_average_latency_ms: u64,
}

// =============================================================================
// LIFECYCLE
// =============================================================================

impl PacketCapture {
    /// Start packet capture processing.
    pub fn start(&mut self) -> Result<()> {
        info!("Starting packet capture on {}", self.config.wan_interface);
        self.running = true;
        Ok(())
    }
    
    /// Stop packet capture processing.
    pub fn stop(&mut self) {
        info!("Stopping packet capture");
        self.running = false;
        
        // Log final statistics
        let stats = self.get_statistics_snapshot();
        info!(
            "Final stats: {} rx, {} tx, {} sent to TLS Proxy, {} errors",
            stats.rx_packets, stats.tx_packets,
            stats.packets_sent_to_tls_proxy, stats.tls_proxy_errors
        );
    }
    
    /// Check if capture is running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::config::{Config, LoggingConfig, NatConfig, NetworkConfig, TlsProxyConfig};
    
    fn create_test_config() -> Config {
        Config {
            network: NetworkConfig {
                wan_interface: "Ethernet".to_string(),
                lan_interface: "Ethernet 2".to_string(),
                capture_filter: None,
            },
            nat: NatConfig {
                enable: true,
                timeout_secs: 300,
                max_connections: 65535,
                port_range_start: None,
                port_range_end: None,
            },
            routing: None,
            tls_proxy: TlsProxyConfig {
                enabled: true,
                address: "localhost:50054".to_string(),
                timeout_secs: 5,
                fail_open: true,
                retry_attempts: None,
                connection_pool_size: None,
            },
            logging: LoggingConfig::default(),
            statistics: None,
        }
    }
    
    fn create_test_packet() -> RawPacket {
        RawPacket {
            source_ip: "192.168.1.100".to_string(),
            source_port: 54321,
            dest_ip: "8.8.8.8".to_string(),
            dest_port: 443,
            protocol: "TCP".to_string(),
            outbound: true,
            payload: vec![0x16, 0x03, 0x01],
            interface_name: "Ethernet".to_string(),
            timestamp: Instant::now(),
        }
    }
    
    #[test]
    fn test_packet_capture_new() {
        let config = create_test_config();
        let capture = PacketCapture::new(config, None);
        assert!(capture.is_ok());
    }
    
    #[test]
    fn test_tls_proxy_enabled_without_client() {
        let config = create_test_config();
        let capture = PacketCapture::new(config, None).unwrap();
        // Enabled in config but no client
        assert!(!capture.is_tls_proxy_enabled());
    }
    
    #[test]
    fn test_statistics_initial_zero() {
        let config = create_test_config();
        let capture = PacketCapture::new(config, None).unwrap();
        let stats = capture.get_statistics_snapshot();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.packets_sent_to_tls_proxy, 0);
        assert_eq!(stats.tls_proxy_errors, 0);
    }
    
    #[test]
    fn test_statistics_average_latency_zero_requests() {
        let stats = CaptureStatistics::default();
        assert_eq!(stats.average_tls_proxy_latency_ms(), 0);
    }
    
    #[test]
    fn test_statistics_average_latency() {
        let stats = CaptureStatistics::default();
        stats.packets_sent_to_tls_proxy.store(10, Ordering::Relaxed);
        stats.tls_proxy_cumulative_latency_ms.store(500, Ordering::Relaxed);
        assert_eq!(stats.average_tls_proxy_latency_ms(), 50);
    }
    
    #[test]
    fn test_lifecycle() {
        let config = create_test_config();
        let mut capture = PacketCapture::new(config, None).unwrap();
        
        assert!(!capture.is_running());
        capture.start().unwrap();
        assert!(capture.is_running());
        capture.stop();
        assert!(!capture.is_running());
    }
}
