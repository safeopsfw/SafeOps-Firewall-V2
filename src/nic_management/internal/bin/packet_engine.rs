//! SafeOps Packet Engine - Simplified Security Port Logger
//!
//! Features:
//! - Top 15 security ports ONLY (minimal overhead)
//! - 128-byte DPI payload for signature matching
//! - Protocol detection: DNS, TLS/SNI, HTTP, SSH
//! - Multi-threaded processing (4 workers)
//! - JSON logging with 3-minute rotation
//! - IMMEDIATE re-inject for zero network delay
//! - NO DHCP Monitor integration (removed for performance)

use windivert::prelude::*;
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
    network: Option<NetLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportLayer>,
}

#[derive(Serialize, Clone)]
struct NetLayer {
    protocol: String,
    src_ip: String,
    dst_ip: String,
    ttl: u8,
    length: u16,
}

#[derive(Serialize, Clone)]
struct TransportLayer {
    protocol: String,
    src_port: u16,
    dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u32>,
}

#[derive(Serialize, Clone)]
struct AppInfo {
    protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<AppDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_preview: Option<String>,
}

#[derive(Serialize, Clone)]
struct AppDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_path: Option<String>,
}

#[derive(Serialize, Clone)]
struct FlowContext {
    flow_id: String,
    direction: String,
    packet_in_flow: u32,
}

#[derive(Serialize, Clone)]
struct DedupInfo {
    hash: String,
    is_duplicate: bool,
}

struct FlowState {
    packet_count: u32,
    last_seen: Instant,
}

struct RawPacket {
    data: Vec<u8>,
    timestamp: f64,
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     SafeOps Packet Engine - Security Port Logger                 ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Filter: TOP 15 SECURITY PORTS ONLY                              ║");
    println!("║  DPI: 128-byte payload capture for signature matching            ║");
    println!("║  Protocols: DNS, TLS/SNI, HTTP, SSH, SMTP, RDP, SMB              ║");
    println!("║  Output: {}    ║", LOG_FILE);
    println!("║  Performance: {} workers + {} batch size                         ║", WORKER_THREADS, BATCH_SIZE);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    
    if let Err(e) = run_engine() {
        eprintln!("❌ Error: {}", e);
        std::process::exit(1);
    }
}

fn run_engine() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Initializing WinDivert (High-Risk Security Ports)...\n");
    
    // HIGH-RISK SECURITY PORTS - No HTTP/HTTPS for speed
    // DNS(53), SSH(22), RDP(3389), SMB(445), FTP(21), Telnet(23)
    // SMTP(25), LDAP(389), MySQL(3306), PostgreSQL(5432), Redis(6379)
    let filter = "udp.DstPort == 53 or udp.SrcPort == 53 or \
        tcp.DstPort == 53 or tcp.SrcPort == 53 or \
        tcp.DstPort == 22 or tcp.SrcPort == 22 or \
        tcp.DstPort == 3389 or tcp.SrcPort == 3389 or \
        tcp.DstPort == 445 or tcp.SrcPort == 445 or \
        tcp.DstPort == 21 or tcp.SrcPort == 21 or \
        tcp.DstPort == 23 or tcp.SrcPort == 23 or \
        tcp.DstPort == 25 or tcp.SrcPort == 25 or \
        tcp.DstPort == 389 or tcp.SrcPort == 389 or \
        tcp.DstPort == 3306 or tcp.SrcPort == 3306 or \
        tcp.DstPort == 5432 or tcp.SrcPort == 5432 or \
        tcp.DstPort == 6379 or tcp.SrcPort == 6379";
    
    // Open WinDivert handle with windivert crate
    let wd = WinDivert::<NetworkLayer>::network(filter, 0, WinDivertFlags::new())?;
    
    println!("✅ WinDivert opened");
    println!("   Filter: High-Risk Security Ports (NO HTTP/HTTPS)");
    println!("   Ports: DNS(53), SSH(22), RDP(3389), SMB(445), FTP(21)");
    println!("          Telnet(23), SMTP(25), LDAP(389), MySQL(3306)");
    println!("          PostgreSQL(5432), Redis(6379)");
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
    
    println!("🚀 ENGINE RUNNING - Capturing Security Ports for FW/IDS/IPS\n");
    
    let start_time = Instant::now();
    
    // ==========================================================================
    // STATS THREAD
    // ==========================================================================
    let stats_running = running.clone();
    let stats_packets = total_packets.clone();
    let stats_bytes = total_bytes.clone();
    let stats_logged = logged_packets.clone();
    thread::spawn(move || {
        let mut last_packets: u64 = 0;
        let mut last_bytes: u64 = 0;
        
        while stats_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(10));
            
            let packets = stats_packets.load(Ordering::Relaxed);
            let bytes = stats_bytes.load(Ordering::Relaxed);
            let logged = stats_logged.load(Ordering::Relaxed);
            
            let pps = (packets - last_packets) / 10;
            let mbps = ((bytes - last_bytes) * 8) as f64 / 10_000_000.0;
            
            println!("📊 {} pkts | {:.2} MB | {} logged | {} pps | {:.2} Mbps",
                packets,
                bytes as f64 / 1_048_576.0,
                logged,
                pps,
                mbps
            );
            
            last_packets = packets;
            last_bytes = bytes;
        }
    });
    
    // ==========================================================================
    // WORKER THREADS (parse packets -> log entries)
    // ==========================================================================
    let mut worker_handles = Vec::new();
    
    for _worker_id in 0..WORKER_THREADS {
        let rx = packet_rx.clone();
        let tx = log_tx.clone();
        let flows_ref = flows.clone();
        let logged_ref = logged_packets.clone();
        let running_ref = running.clone();
        
        let h = thread::spawn(move || {
            while running_ref.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(raw) => {
                        if let Some(log) = parse_packet(&raw.data, raw.timestamp, &flows_ref) {
                            let _ = tx.send(log);
                            logged_ref.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => continue,
                }
            }
        });
        
        worker_handles.push(h);
    }
    drop(log_tx);
    
    // ==========================================================================
    // LOG WRITER THREAD (batch JSON writes)
    // ==========================================================================
    let writer_running = running.clone();
    let writer_handle = thread::spawn(move || {
        let mut file = create_log_file();
        let mut batch: Vec<String> = Vec::with_capacity(BATCH_SIZE);
        let mut last_rotation = Instant::now();
        
        while writer_running.load(Ordering::Relaxed) {
            match log_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(log) => {
                    if let Ok(json) = serde_json::to_string(&log) {
                        batch.push(json);
                        
                        if batch.len() >= BATCH_SIZE {
                            write_batch(&mut file, &batch);
                            batch.clear();
                        }
                    }
                }
                Err(_) => {
                    if !batch.is_empty() {
                        write_batch(&mut file, &batch);
                        batch.clear();
                    }
                }
            }
            
            // Rotation check (3 minutes = 180 seconds)
            if last_rotation.elapsed().as_secs() >= ROTATION_INTERVAL_SECS {
                if !batch.is_empty() {
                    write_batch(&mut file, &batch);
                    batch.clear();
                }
                file = create_log_file();  // This truncates the file
                last_rotation = Instant::now();
                println!("🔄 Log rotated");
            }
        }
        
        if !batch.is_empty() {
            write_batch(&mut file, &batch);
        }
    });
    
    // ==========================================================================
    // MAIN CAPTURE LOOP (immediate re-inject)
    // ==========================================================================
    let mut buffer = vec![0u8; 65535];
    
    while running.load(Ordering::Relaxed) {
        // Receive packet using windivert crate
        match wd.recv(Some(&mut buffer)) {
            Ok(packet) => {
                let packet_size = packet.data.len();
                
                // IMMEDIATE re-inject (zero delay)
                let _ = wd.send(&packet);
                
                // Update stats
                total_packets.fetch_add(1, Ordering::Relaxed);
                total_bytes.fetch_add(packet_size as u64, Ordering::Relaxed);
                
                // Get timestamp
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                
                // Send to workers (non-blocking)
                let _ = packet_tx.try_send(RawPacket {
                    data: packet.data.to_vec(),
                    timestamp,
                });
            }
            Err(_) => continue,
        }
    }
    
    // Cleanup
    drop(packet_tx);
    
    for h in worker_handles {
        let _ = h.join();
    }
    let _ = writer_handle.join();
    
    let elapsed = start_time.elapsed();
    println!("\n📊 Final Stats:");
    println!("   Duration: {:.1}s", elapsed.as_secs_f64());
    println!("   Packets: {}", total_packets.load(Ordering::Relaxed));
    println!("   Bytes: {:.2} MB", total_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0);
    println!("   Logged: {}", logged_packets.load(Ordering::Relaxed));
    
    Ok(())
}

// =============================================================================
// PACKET PARSING
// =============================================================================

fn parse_packet(
    data: &[u8],
    timestamp: f64,
    flows: &Arc<RwLock<HashMap<String, FlowState>>>
) -> Option<PacketLog> {
    if data.len() < 20 {
        return None;
    }
    
    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return None; // IPv4 only for now
    }
    
    let ihl = ((data[0] & 0x0F) * 4) as usize;
    if data.len() < ihl {
        return None;
    }
    
    let ttl = data[8];
    let protocol = data[9];
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    
    let network = NetLayer {
        protocol: "IPv4".to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        ttl,
        length: total_len,
    };
    
    let transport_data = &data[ihl..];
    let (transport, payload, src_port, dst_port) = parse_transport(protocol, transport_data)?;
    
    // Flow tracking
    let flow_id = format!("{}:{}-{}:{}-{}", src_ip, src_port, dst_ip, dst_port, protocol);
    let (direction, packet_in_flow) = {
        let mut flows_guard = flows.write();
        let entry = flows_guard.entry(flow_id.clone()).or_insert(FlowState {
            packet_count: 0,
            last_seen: Instant::now(),
        });
        entry.packet_count += 1;
        entry.last_seen = Instant::now();
        
        let dir = if entry.packet_count == 1 { "outbound" } else { "bidirectional" };
        (dir.to_string(), entry.packet_count)
    };
    
    // Application layer parsing
    let (app_protocol, app_details) = parse_application(dst_port, src_port, payload);
    
    // Payload preview (base64 of first N bytes)
    let payload_preview = if !payload.is_empty() {
        let preview_len = payload.len().min(DPI_PAYLOAD_SIZE);
        Some(BASE64.encode(&payload[..preview_len]))
    } else {
        None
    };
    
    // Generate packet hash for deduplication (simple FNV-1a hash)
    let hash = fnv1a_hash(&data[..data.len().min(64)]);
    
    // ISO8601 timestamp
    let datetime: DateTime<Utc> = DateTime::from_timestamp(timestamp as i64, 
        ((timestamp.fract()) * 1_000_000_000.0) as u32).unwrap_or_default();
    
    Some(PacketLog {
        packet_id: format!("{}-{}", datetime.format("%Y%m%d%H%M%S%3f"), &hash[..8]),
        timestamp: TimestampInfo {
            epoch: timestamp,
            iso8601: datetime.to_rfc3339(),
        },
        capture_info: CaptureInfo {
            interface: "WinDivert".to_string(),
            capture_length: data.len(),
            wire_length: total_len as usize,
        },
        layers: LayerInfo {
            network: Some(network),
            transport: Some(transport),
        },
        parsed_application: AppInfo {
            protocol: app_protocol,
            details: app_details,
            payload_preview,
        },
        flow_context: Some(FlowContext {
            flow_id: hash[..16].to_string(),
            direction,
            packet_in_flow,
        }),
        deduplication: DedupInfo {
            hash: hash[..16].to_string(),
            is_duplicate: false,
        },
    })
}

fn parse_transport(protocol: u8, data: &[u8]) -> Option<(TransportLayer, &[u8], u16, u16)> {
    match protocol {
        6 => { // TCP
            if data.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let data_offset = ((data[12] >> 4) * 4) as usize;
            let flags = data[13];
            
            let flag_str = format!("{}{}{}{}{}{}",
                if flags & 0x02 != 0 { "S" } else { "" },
                if flags & 0x10 != 0 { "A" } else { "" },
                if flags & 0x01 != 0 { "F" } else { "" },
                if flags & 0x04 != 0 { "R" } else { "" },
                if flags & 0x08 != 0 { "P" } else { "" },
                if flags & 0x20 != 0 { "U" } else { "" }
            );
            
            let payload = if data.len() > data_offset {
                &data[data_offset..]
            } else {
                &[]
            };
            
            Some((TransportLayer {
                protocol: "TCP".to_string(),
                src_port,
                dst_port,
                flags: Some(flag_str),
                seq: Some(seq),
            }, payload, src_port, dst_port))
        }
        17 => { // UDP
            if data.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let payload = &data[8..];
            
            Some((TransportLayer {
                protocol: "UDP".to_string(),
                src_port,
                dst_port,
                flags: None,
                seq: None,
            }, payload, src_port, dst_port))
        }
        _ => None
    }
}

fn parse_application(dst_port: u16, src_port: u16, payload: &[u8]) -> (String, Option<AppDetails>) {
    // DNS
    if dst_port == 53 || src_port == 53 {
        if let Some(query) = parse_dns_query(payload) {
            return ("DNS".to_string(), Some(AppDetails {
                dns_query: Some(query),
                dns_type: Some("A".to_string()),
                sni: None,
                http_method: None,
                http_host: None,
                http_path: None,
            }));
        }
        return ("DNS".to_string(), None);
    }
    
    // HTTPS/TLS (SNI extraction)
    if dst_port == 443 || src_port == 443 {
        if let Some(sni) = extract_sni(payload) {
            return ("TLS".to_string(), Some(AppDetails {
                dns_query: None,
                dns_type: None,
                sni: Some(sni),
                http_method: None,
                http_host: None,
                http_path: None,
            }));
        }
        return ("TLS".to_string(), None);
    }
    
    // HTTP
    if dst_port == 80 || src_port == 80 {
        if let Some((method, host, path)) = parse_http(payload) {
            return ("HTTP".to_string(), Some(AppDetails {
                dns_query: None,
                dns_type: None,
                sni: None,
                http_method: Some(method),
                http_host: Some(host),
                http_path: Some(path),
            }));
        }
        return ("HTTP".to_string(), None);
    }
    
    // SSH
    if dst_port == 22 || src_port == 22 {
        return ("SSH".to_string(), None);
    }
    
    // RDP
    if dst_port == 3389 || src_port == 3389 {
        return ("RDP".to_string(), None);
    }
    
    // SMB
    if dst_port == 445 || src_port == 445 {
        return ("SMB".to_string(), None);
    }
    
    // SMTP
    if dst_port == 25 || src_port == 25 {
        return ("SMTP".to_string(), None);
    }
    
    // By port number
    let proto = match dst_port {
        21 => "FTP",
        23 => "TELNET",
        110 => "POP3",
        143 => "IMAP",
        389 => "LDAP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        _ => "UNKNOWN",
    };
    
    (proto.to_string(), None)
}

fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    
    let qcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qcount == 0 {
        return None;
    }
    
    let mut pos = 12;
    let mut domain = String::new();
    
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
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
    
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 6 {
        return None;
    }
    
    // TLS handshake
    if payload[0] != 0x16 {
        return None;
    }
    
    // Skip to extensions
    let mut pos = 5;
    if pos >= payload.len() {
        return None;
    }
    
    // Handshake type: ClientHello
    if payload.get(pos)? != &0x01 {
        return None;
    }
    
    // Skip handshake header, version, random, session id, cipher suites, compression
    pos += 4 + 2 + 32; // handshake header + version + random
    if pos >= payload.len() {
        return None;
    }
    
    // Session ID length
    let session_len = *payload.get(pos)? as usize;
    pos += 1 + session_len;
    if pos + 2 >= payload.len() {
        return None;
    }
    
    // Cipher suites
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= payload.len() {
        return None;
    }
    
    // Compression
    let comp_len = *payload.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos + 2 >= payload.len() {
        return None;
    }
    
    // Extensions length
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    
    while pos + 4 < ext_end && pos + 4 < payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        
        if ext_type == 0 && pos + ext_data_len <= payload.len() {
            // SNI extension
            let mut sni_pos = pos + 2; // skip list length
            if sni_pos + 3 < pos + ext_data_len {
                let name_type = payload[sni_pos];
                let name_len = u16::from_be_bytes([payload[sni_pos + 1], payload[sni_pos + 2]]) as usize;
                sni_pos += 3;
                
                if name_type == 0 && sni_pos + name_len <= payload.len() {
                    if let Ok(sni) = std::str::from_utf8(&payload[sni_pos..sni_pos + name_len]) {
                        return Some(sni.to_string());
                    }
                }
            }
        }
        
        pos += ext_data_len;
    }
    
    None
}

fn parse_http(payload: &[u8]) -> Option<(String, String, String)> {
    let text = std::str::from_utf8(payload).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    
    if lines.is_empty() {
        return None;
    }
    
    let first_line: Vec<&str> = lines[0].split_whitespace().collect();
    if first_line.len() < 2 {
        return None;
    }
    
    let method = first_line[0];
    if !["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].contains(&method) {
        return None;
    }
    
    let path = first_line[1].to_string();
    
    let mut host = String::new();
    for line in &lines[1..] {
        if line.to_lowercase().starts_with("host:") {
            host = line[5..].trim().to_string();
            break;
        }
    }
    
    Some((method.to_string(), host, path))
}

// =============================================================================
// FILE I/O
// =============================================================================

fn create_log_file() -> BufWriter<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(LOG_FILE)
        .expect("Failed to create log file");
    
    BufWriter::new(file)
}

fn write_batch(file: &mut BufWriter<File>, batch: &[String]) {
    for json in batch {
        let _ = writeln!(file, "{}", json);
    }
    let _ = file.flush();
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// FNV-1a hash for fast deduplication
fn fnv1a_hash(data: &[u8]) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{:016x}", hash)
}
