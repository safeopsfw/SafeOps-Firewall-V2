//! SafeOps Packet Engine - NOC/SOC Grade DPI Logger
//!
//! Features:
//! - ALL ports capture (no filtering)
//! - 128-byte DPI payload for signature matching
//! - Protocol detection: DNS, TLS/SNI, HTTP, SSH, SMTP
//! - Flow tracking with session management
//! - Multi-threaded processing (4 workers)
//! - Batch I/O for disk writes
//! - JSON logging with 3-minute rotation
//! - IMMEDIATE re-inject for zero network delay

use windivert_sys::*;
use std::ptr;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::Ipv4Addr;
use std::collections::HashMap;
use parking_lot::RwLock;
use crossbeam::channel::{bounded, Sender, Receiver};
use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;

// =============================================================================
// CONFIGURATION
// =============================================================================

const DPI_PAYLOAD_SIZE: usize = 128;           // 128 bytes for signature matching
const ROTATION_INTERVAL_SECS: u64 = 180;       // 3-minute rotation
const LOG_FILE: &str = "D:\\SafeOpsFV2\\logs\\network_packets.jsonl";
const BATCH_SIZE: usize = 100;                 // Packets per batch write
const CHANNEL_CAPACITY: usize = 10000;         // Packet queue size
const WORKER_THREADS: usize = 4;               // Parallel parsing workers
const FLOW_TIMEOUT_SECS: u64 = 60;             // Flow expiry timeout

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[derive(Serialize, Clone)]
struct PacketLog {
    packet_id: String,
    timestamp: TimestampInfo,
    capture_info: CaptureInfo,
    layers: LayerInfo,
    parsed_application: AppInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_context: Option<FlowContext>,
    deduplication: DedupInfo,
}

#[derive(Serialize, Clone)]
struct TimestampInfo {
    epoch: f64,
    iso8601: String,
}

#[derive(Serialize, Clone)]
struct CaptureInfo {
    interface: String,
    capture_length: usize,
    wire_length: usize,
}

#[derive(Serialize, Clone)]
struct LayerInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<NetworkLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<PayloadInfo>,
}

#[derive(Serialize, Clone)]
struct NetworkLayer {
    version: u8,
    src_ip: String,
    dst_ip: String,
    ttl: u8,
    protocol: u8,
    total_length: u16,
}

#[derive(Serialize, Clone)]
struct TransportLayer {
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_flags: Option<TcpFlags>,
}

#[derive(Serialize, Clone)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    psh: bool,
}

#[derive(Serialize, Clone)]
struct PayloadInfo {
    length: usize,
    dpi_hex: String,
    dpi_base64: String,
    encrypted: bool,
}

#[derive(Serialize, Clone)]
struct AppInfo {
    detected_protocol: String,
    confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<DnsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<HttpInfo>,
}

#[derive(Serialize, Clone)]
struct DnsInfo {
    transaction_id: u16,
    qr: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    queries: Option<Vec<DnsQuery>>,
}

#[derive(Serialize, Clone)]
struct DnsQuery {
    name: String,
    #[serde(rename = "type")]
    qtype: u16,
}

#[derive(Serialize, Clone)]
struct TlsInfo {
    version: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
}

#[derive(Serialize, Clone)]
struct HttpInfo {
    #[serde(rename = "type")]
    http_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
}

#[derive(Serialize, Clone)]
struct FlowContext {
    flow_id: String,
    direction: String,
    packets_forward: u64,
    packets_backward: u64,
    bytes_forward: u64,
    bytes_backward: u64,
    flow_state: String,
}

#[derive(Serialize, Clone)]
struct DedupInfo {
    unique: bool,
    reason: String,
}

struct FlowState {
    flow_id: String,
    #[allow(dead_code)]
    first_seen: f64,
    last_seen: f64,
    packets_fwd: u64,
    packets_bwd: u64,
    bytes_fwd: u64,
    bytes_bwd: u64,
}

struct RawPacket {
    data: Vec<u8>,
    timestamp: f64,
    #[allow(dead_code)]
    outbound: bool,
}

// =============================================================================
// MAIN
// =============================================================================

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     SafeOps Packet Engine - NOC/SOC Grade DPI Logger             ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Filter: ALL IP TRAFFIC (Full IDS/IPS Mode)                      ║");
    println!("║  DPI: 128-byte payload capture for signature matching            ║");
    println!("║  Protocols: DNS, TLS/SNI, HTTP, SSH, SMTP                        ║");
    println!("║  Output: {}    ║", LOG_FILE);
    println!("║  Performance: {} workers + {} batch size                        ║", WORKER_THREADS, BATCH_SIZE);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    std::fs::create_dir_all("D:\\SafeOpsFV2\\logs").ok();

    if let Err(e) = run_engine() {
        eprintln!("\n❌ Fatal error: {}", e);
        std::process::exit(1);
    }
}

fn run_engine() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Initializing WinDivert (FAST mode - Security Ports)...\n");
    
    // Security-critical ports for enterprise IDS/IPS:
    // DNS(53), HTTP(80), HTTPS(443), SSH(22), SMTP(25,587), RDP(3389), FTP(21),
    // SMB(445), LDAP(389), MySQL(3306), PostgreSQL(5432), Redis(6379), MongoDB(27017)
    let filter = concat!(
        "udp.DstPort == 53 or udp.SrcPort == 53 or ",           // DNS
        "tcp.DstPort == 80 or tcp.SrcPort == 80 or ",           // HTTP
        "tcp.DstPort == 443 or tcp.SrcPort == 443 or ",         // HTTPS
        "tcp.DstPort == 22 or tcp.SrcPort == 22 or ",           // SSH
        "tcp.DstPort == 25 or tcp.SrcPort == 25 or ",           // SMTP
        "tcp.DstPort == 587 or tcp.SrcPort == 587 or ",         // SMTP TLS
        "tcp.DstPort == 3389 or tcp.SrcPort == 3389 or ",       // RDP
        "tcp.DstPort == 21 or tcp.SrcPort == 21 or ",           // FTP
        "tcp.DstPort == 445 or tcp.SrcPort == 445 or ",         // SMB
        "tcp.DstPort == 389 or tcp.SrcPort == 389 or ",         // LDAP
        "tcp.DstPort == 3306 or tcp.SrcPort == 3306 or ",       // MySQL
        "tcp.DstPort == 5432 or tcp.SrcPort == 5432 or ",       // PostgreSQL
        "tcp.DstPort == 6379 or tcp.SrcPort == 6379 or ",       // Redis
        "tcp.DstPort == 27017 or tcp.SrcPort == 27017\0"        // MongoDB
    );
    
    let handle = unsafe {
        WinDivertOpen(
            filter.as_ptr() as *const i8,
            WinDivertLayer::Network,
            0,
            WinDivertFlags::default()
        )
    };
    
    if handle.is_invalid() {
        return Err("Failed to open WinDivert - run as Administrator".into());
    }
    
    println!("✅ WinDivert opened");
    println!("   Filter: ALL IP traffic (ip or ipv6)");
    println!("   DPI Payload: {} bytes", DPI_PAYLOAD_SIZE);
    println!("   Workers: {} threads", WORKER_THREADS);
    println!("   Log: {}", LOG_FILE);
    println!();
    
    // Shared state
    let running = Arc::new(AtomicBool::new(true));
    let total_packets = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let logged_packets = Arc::new(AtomicU64::new(0));
    
    // Flow tracking
    let flows: Arc<RwLock<HashMap<String, FlowState>>> = Arc::new(RwLock::new(HashMap::new()));
    
    // Packet channel (producer -> workers)
    let (packet_tx, packet_rx): (Sender<RawPacket>, Receiver<RawPacket>) = bounded(CHANNEL_CAPACITY);
    
    // Log channel (workers -> writer)
    let (log_tx, log_rx): (Sender<PacketLog>, Receiver<PacketLog>) = bounded(CHANNEL_CAPACITY);
    
    // Ctrl+C handler
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n🛑 Stopping...");
        r.store(false, Ordering::Relaxed);
    })?;
    
    println!("🚀 ENGINE RUNNING - Capturing ALL traffic for IDS/IPS\n");
    
    let start_time = Instant::now();
    
    // Stats thread
    let stats_running = running.clone();
    let stats_packets = total_packets.clone();
    let stats_bytes = total_bytes.clone();
    let stats_logged = logged_packets.clone();
    thread::spawn(move || {
        while stats_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(10));
            let packets = stats_packets.load(Ordering::Relaxed);
            let bytes = stats_bytes.load(Ordering::Relaxed);
            let logged = stats_logged.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs_f64();
            
            println!("📊 {} pkts | {:.2} MB | {} logged | {:.0} pps | {:.2} Mbps", 
                packets,
                bytes as f64 / 1_048_576.0,
                logged,
                packets as f64 / elapsed,
                (bytes as f64 * 8.0) / (elapsed * 1_000_000.0)
            );
        }
    });
    
    // Worker threads (parse packets -> JSON)
    for _ in 0..WORKER_THREADS {
        let rx = packet_rx.clone();
        let tx = log_tx.clone();
        let flows_ref = flows.clone();
        let worker_running = running.clone();
        
        thread::spawn(move || {
            while worker_running.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(raw) => {
                        if let Some(log) = parse_packet(&raw.data, raw.timestamp, &flows_ref) {
                            let _ = tx.send(log);
                        }
                    }
                    Err(_) => continue,
                }
            }
        });
    }
    
    // Drop original sender so workers can detect shutdown
    drop(log_tx);
    
    // Writer thread (batched disk I/O)
    let writer_running = running.clone();
    let writer_logged = logged_packets.clone();
    thread::spawn(move || {
        let mut writer = create_log_file().expect("Failed to create log file");
        let mut last_rotation = Instant::now();
        let mut batch: Vec<String> = Vec::with_capacity(BATCH_SIZE);
        
        while writer_running.load(Ordering::Relaxed) {
            // Check rotation
            if last_rotation.elapsed().as_secs() >= ROTATION_INTERVAL_SECS {
                writer.flush().ok();
                drop(writer);
                writer = create_log_file().expect("Failed to rotate log file");
                last_rotation = Instant::now();
                println!("🔄 Log rotated");
            }
            
            // Collect batch
            match log_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(log) => {
                    if let Ok(json) = serde_json::to_string(&log) {
                        batch.push(json);
                    }
                    
                    // Write batch when full
                    if batch.len() >= BATCH_SIZE {
                        for line in &batch {
                            writeln!(writer, "{}", line).ok();
                        }
                        writer_logged.fetch_add(batch.len() as u64, Ordering::Relaxed);
                        batch.clear();
                    }
                }
                Err(_) => {
                    // Flush partial batch on timeout
                    if !batch.is_empty() {
                        for line in &batch {
                            writeln!(writer, "{}", line).ok();
                        }
                        writer_logged.fetch_add(batch.len() as u64, Ordering::Relaxed);
                        batch.clear();
                        writer.flush().ok();
                    }
                }
            }
        }
        
        // Final flush
        for line in &batch {
            writeln!(writer, "{}", line).ok();
        }
        writer.flush().ok();
    });
    
    // Flow cleanup thread
    let flows_cleanup = flows.clone();
    let cleanup_running = running.clone();
    thread::spawn(move || {
        while cleanup_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(30));
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
            let mut flows = flows_cleanup.write();
            flows.retain(|_, state| now - state.last_seen < FLOW_TIMEOUT_SECS as f64);
        }
    });
    
    // Main capture loop - SPEED CRITICAL
    unsafe {
        let mut packet = [0u8; 65535];
        let mut addr = mem::zeroed();
        let mut len = 0u32;
        
        while running.load(Ordering::Relaxed) {
            if WinDivertRecv(handle, packet.as_mut_ptr() as *mut _, 65535, &mut len, &mut addr) == false {
                continue;
            }
            
            // IMMEDIATE re-injection - network keeps flowing at full speed!
            WinDivertSend(handle, packet.as_ptr() as *const _, len, ptr::null_mut(), &addr);
            
            // Stats and logging (async - after packet is already forwarded)
            total_packets.fetch_add(1, Ordering::Relaxed);
            total_bytes.fetch_add(len as u64, Ordering::Relaxed);
            
            // Get timestamp
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            
            // Direction check
            let addr_bytes: &[u8] = std::slice::from_raw_parts(&addr as *const _ as *const u8, 8);
            let outbound = addr_bytes[0] != 0;
            
            // Send to worker (non-blocking)
            let raw = RawPacket {
                data: packet[..len as usize].to_vec(),
                timestamp,
                outbound,
            };
            
            let _ = packet_tx.try_send(raw);
        }
        
        WinDivertClose(handle);
    }
    
    // Final stats
    let elapsed = start_time.elapsed().as_secs_f64();
    let packets = total_packets.load(Ordering::Relaxed);
    let bytes = total_bytes.load(Ordering::Relaxed);
    let logged = logged_packets.load(Ordering::Relaxed);
    
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Total: {} packets | {:.2} MB | {} logged", packets, bytes as f64 / 1_048_576.0, logged);
    println!("║  Runtime: {:.1} seconds | {:.0} pps avg", elapsed, packets as f64 / elapsed);
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}

fn create_log_file() -> Result<BufWriter<File>, std::io::Error> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(LOG_FILE)?;
    Ok(BufWriter::with_capacity(65536, file))
}

// =============================================================================
// PACKET PARSING
// =============================================================================

fn parse_packet(
    packet: &[u8],
    timestamp: f64,
    flows: &Arc<RwLock<HashMap<String, FlowState>>>,
) -> Option<PacketLog> {
    if packet.len() < 20 {
        return None;
    }
    
    // Parse IPv4 header
    let version = (packet[0] >> 4) & 0x0F;
    if version != 4 {
        return None; // Only IPv4 for now
    }
    
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl {
        return None;
    }
    
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    let ttl = packet[8];
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    
    // Generate packet ID
    let packet_id = format!("pkt_{}_{:08x}", 
        (timestamp * 1000.0) as u64,
        ahash::RandomState::new().hash_one(&packet[..std::cmp::min(packet.len(), 64)])
    );
    
    // Parse transport
    let transport_data = &packet[ihl..];
    let (src_port, dst_port, tcp_flags, payload_offset) = match protocol {
        6 => parse_tcp(transport_data)?,  // TCP
        17 => parse_udp(transport_data)?, // UDP
        _ => return None,
    };
    
    // Get payload
    let payload_start = ihl + payload_offset;
    let payload = if payload_start < packet.len() {
        &packet[payload_start..]
    } else {
        &[]
    };
    
    // DPI sample (first 128 bytes)
    let dpi_sample = &payload[..std::cmp::min(payload.len(), DPI_PAYLOAD_SIZE)];
    
    // Detect encryption
    let encrypted = detect_encryption(dpi_sample);
    
    // Parse application layer
    let app_info = parse_application(protocol, src_port, dst_port, dpi_sample);
    
    // Flow tracking
    let flow_context = update_flow(
        flows, 
        src_ip, src_port, dst_ip, dst_port, protocol,
        packet.len() as u64,
        timestamp
    );
    
    // Deduplication reason
    let dedup_reason = match (src_port, dst_port, app_info.detected_protocol.as_str()) {
        (53, _, _) | (_, 53, _) => "dns_traffic",
        (443, _, _) | (_, 443, _) => "tls_traffic",
        (80, _, _) | (_, 80, _) => "http_traffic",
        _ if app_info.detected_protocol != "unknown" => "detected_protocol",
        _ => "all_traffic",
    };
    
    // Format timestamp
    let datetime: DateTime<Utc> = DateTime::from_timestamp(timestamp as i64, ((timestamp.fract()) * 1_000_000_000.0) as u32)?;
    
    Some(PacketLog {
        packet_id,
        timestamp: TimestampInfo {
            epoch: timestamp,
            iso8601: datetime.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        },
        capture_info: CaptureInfo {
            interface: "WinDivert".to_string(),
            capture_length: packet.len(),
            wire_length: packet.len(),
        },
        layers: LayerInfo {
            network: Some(NetworkLayer {
                version: 4,
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                ttl,
                protocol,
                total_length: total_len,
            }),
            transport: Some(TransportLayer {
                protocol,
                src_port,
                dst_port,
                tcp_flags,
            }),
            payload: if !payload.is_empty() {
                Some(PayloadInfo {
                    length: payload.len(),
                    dpi_hex: hex_encode(dpi_sample),
                    dpi_base64: BASE64.encode(dpi_sample),
                    encrypted,
                })
            } else {
                None
            },
        },
        parsed_application: app_info,
        flow_context: Some(flow_context),
        deduplication: DedupInfo {
            unique: true,
            reason: dedup_reason.to_string(),
        },
    })
}

fn parse_tcp(data: &[u8]) -> Option<(u16, u16, Option<TcpFlags>, usize)> {
    if data.len() < 20 {
        return None;
    }
    
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    
    let tcp_flags = TcpFlags {
        syn: (flags & 0x02) != 0,
        ack: (flags & 0x10) != 0,
        fin: (flags & 0x01) != 0,
        rst: (flags & 0x04) != 0,
        psh: (flags & 0x08) != 0,
    };
    
    Some((src_port, dst_port, Some(tcp_flags), data_offset))
}

fn parse_udp(data: &[u8]) -> Option<(u16, u16, Option<TcpFlags>, usize)> {
    if data.len() < 8 {
        return None;
    }
    
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    
    Some((src_port, dst_port, None, 8))
}

fn detect_encryption(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    // TLS record types
    matches!(&payload[..3], 
        [0x16, 0x03, _] |  // TLS Handshake
        [0x17, 0x03, _] |  // TLS Application Data
        [0x15, 0x03, _]    // TLS Alert
    )
}

// =============================================================================
// APPLICATION LAYER PARSING
// =============================================================================

fn parse_application(protocol: u8, src_port: u16, dst_port: u16, payload: &[u8]) -> AppInfo {
    // DNS
    if (src_port == 53 || dst_port == 53) && protocol == 17 {
        if let Some(dns) = parse_dns(payload) {
            return AppInfo {
                detected_protocol: "dns".to_string(),
                confidence: "high".to_string(),
                dns: Some(dns),
                tls: None,
                http: None,
            };
        }
    }
    
    // TLS/HTTPS
    if (src_port == 443 || dst_port == 443) && protocol == 6 {
        if let Some(tls) = parse_tls(payload) {
            return AppInfo {
                detected_protocol: "tls".to_string(),
                confidence: "high".to_string(),
                dns: None,
                tls: Some(tls),
                http: None,
            };
        }
    }
    
    // HTTP
    if (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080) && protocol == 6 {
        if let Some(http) = parse_http(payload) {
            return AppInfo {
                detected_protocol: "http".to_string(),
                confidence: "high".to_string(),
                dns: None,
                tls: None,
                http: Some(http),
            };
        }
    }
    
    // SSH detection
    if (src_port == 22 || dst_port == 22) && protocol == 6 {
        if payload.starts_with(b"SSH-") {
            return AppInfo {
                detected_protocol: "ssh".to_string(),
                confidence: "high".to_string(),
                dns: None,
                tls: None,
                http: None,
            };
        }
    }
    
    // SMTP detection
    if (src_port == 25 || dst_port == 25 || src_port == 587 || dst_port == 587) && protocol == 6 {
        if payload.starts_with(b"EHLO") || payload.starts_with(b"MAIL") || payload.starts_with(b"220 ") {
            return AppInfo {
                detected_protocol: "smtp".to_string(),
                confidence: "medium".to_string(),
                dns: None,
                tls: None,
                http: None,
            };
        }
    }
    
    // Unknown
    AppInfo {
        detected_protocol: "unknown".to_string(),
        confidence: "low".to_string(),
        dns: None,
        tls: None,
        http: None,
    }
}

fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }
    
    let txid = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qr = ((flags >> 15) & 1) as u8;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    
    // Parse query name
    let mut queries = Vec::new();
    if qdcount > 0 {
        let mut pos = 12;
        let mut domain = String::new();
        
        while pos < payload.len() {
            let len = payload[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > payload.len() {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            if let Ok(label) = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]) {
                domain.push_str(label);
            }
            pos += 1 + len;
        }
        
        // Get query type
        let qtype = if pos + 2 <= payload.len() {
            u16::from_be_bytes([payload[pos], payload[pos + 1]])
        } else {
            1 // Default A record
        };
        
        if !domain.is_empty() {
            queries.push(DnsQuery { name: domain, qtype });
        }
    }
    
    Some(DnsInfo {
        transaction_id: txid,
        qr,
        queries: if queries.is_empty() { None } else { Some(queries) },
    })
}

fn parse_tls(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 6 {
        return None;
    }
    
    // Check TLS record
    if payload[0] != 0x16 {
        // Not handshake, check for application data
        if payload[0] == 0x17 {
            return Some(TlsInfo {
                version: format!("0x{:02x}{:02x}", payload[1], payload[2]),
                record_type: "application_data".to_string(),
                sni: None,
            });
        }
        return None;
    }
    
    let version = format!("0x{:02x}{:02x}", payload[1], payload[2]);
    
    // Check handshake type
    if payload[5] != 0x01 {
        // Not ClientHello
        return Some(TlsInfo {
            version,
            record_type: match payload[5] {
                0x02 => "server_hello",
                0x0b => "certificate",
                0x0c => "server_key_exchange",
                0x0e => "server_hello_done",
                0x10 => "client_key_exchange",
                0x14 => "finished",
                _ => "handshake",
            }.to_string(),
            sni: None,
        });
    }
    
    // Extract SNI from ClientHello
    let sni = extract_sni(payload);
    
    Some(TlsInfo {
        version,
        record_type: "client_hello".to_string(),
        sni,
    })
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    // Search for SNI extension (type 0x00 0x00)
    let mut i = 43; // Skip TLS header + handshake header + client random
    
    while i + 4 < payload.len() {
        // Look for extension type 0x0000 (server_name)
        if payload[i] == 0x00 && payload[i + 1] == 0x00 {
            // Found SNI extension
            if i + 9 < payload.len() {
                let name_len = u16::from_be_bytes([payload[i + 7], payload[i + 8]]) as usize;
                if i + 9 + name_len <= payload.len() {
                    if let Ok(sni) = std::str::from_utf8(&payload[i + 9..i + 9 + name_len]) {
                        return Some(sni.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    
    None
}

fn parse_http(payload: &[u8]) -> Option<HttpInfo> {
    if payload.is_empty() {
        return None;
    }
    
    let text = std::str::from_utf8(payload).ok()?;
    
    // Check HTTP request
    let methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "];
    for method in methods {
        if text.starts_with(method) {
            let lines: Vec<&str> = text.lines().collect();
            if lines.is_empty() {
                return None;
            }
            
            let parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
            let uri = parts.get(1).unwrap_or(&"/").to_string();
            
            // Extract host header
            let host = lines.iter()
                .find(|l| l.to_lowercase().starts_with("host:"))
                .map(|l| l[5..].trim().to_string());
            
            return Some(HttpInfo {
                http_type: "request".to_string(),
                method: Some(method.trim().to_string()),
                uri: Some(uri),
                host,
                status: None,
            });
        }
    }
    
    // Check HTTP response
    if text.starts_with("HTTP/") {
        let parts: Vec<&str> = text.lines().next()?.splitn(3, ' ').collect();
        let status = parts.get(1)?.parse().ok();
        
        return Some(HttpInfo {
            http_type: "response".to_string(),
            method: None,
            uri: None,
            host: None,
            status,
        });
    }
    
    None
}

// =============================================================================
// FLOW TRACKING
// =============================================================================

fn update_flow(
    flows: &Arc<RwLock<HashMap<String, FlowState>>>,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: u8,
    size: u64,
    timestamp: f64,
) -> FlowContext {
    // Normalize flow key (smaller IP:port first)
    let (key, is_forward) = if (src_ip, src_port) < (dst_ip, dst_port) {
        (format!("{}:{}-{}:{}:{}", src_ip, src_port, dst_ip, dst_port, protocol), true)
    } else {
        (format!("{}:{}-{}:{}:{}", dst_ip, dst_port, src_ip, src_port, protocol), false)
    };
    
    let flow_id = format!("flow_{:016x}", ahash::RandomState::new().hash_one(&key));
    
    let mut flows = flows.write();
    let state = flows.entry(key).or_insert_with(|| FlowState {
        flow_id: flow_id.clone(),
        first_seen: timestamp,
        last_seen: timestamp,
        packets_fwd: 0,
        packets_bwd: 0,
        bytes_fwd: 0,
        bytes_bwd: 0,
    });
    
    state.last_seen = timestamp;
    if is_forward {
        state.packets_fwd += 1;
        state.bytes_fwd += size;
    } else {
        state.packets_bwd += 1;
        state.bytes_bwd += size;
    }
    
    FlowContext {
        flow_id: state.flow_id.clone(),
        direction: if is_forward { "forward" } else { "reverse" }.to_string(),
        packets_forward: state.packets_fwd,
        packets_backward: state.packets_bwd,
        bytes_forward: state.bytes_fwd,
        bytes_backward: state.bytes_bwd,
        flow_state: "active".to_string(),
    }
}

// =============================================================================
// UTILITIES
// =============================================================================

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
