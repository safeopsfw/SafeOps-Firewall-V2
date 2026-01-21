# Network Logger - Component Documentation

## Overview
The Network Logger Service is a high-performance packet capture and analysis engine built in Go. It captures raw network traffic from all interfaces, extracts metadata (DNS queries, TLS SNI, HTTP hosts), performs flow tracking, process correlation, TLS decryption, and writes structured logs to multiple outputs for SIEM integration and network forensics.

## Component Information

**Component Type:** Network Traffic Analysis & Logging
**Language:** Go
**Architecture:** Multi-threaded packet processor with specialized collectors
**Platform:** Cross-platform (Windows with Npcap, Linux with libpcap)

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\network_logger\
├── cmd\logger\main.go              # Service entry point
├── internal\
│   ├── config\config.go            # Configuration (hardcoded defaults)
│   ├── capture\
│   │   ├── engine.go               # Packet capture engine
│   │   ├── interface_scanner.go    # NIC discovery
│   │   └── packet_processor.go     # Packet processing pipeline
│   ├── parser\
│   │   ├── ethernet.go             # Ethernet frame parsing
│   │   ├── ip.go                   # IPv4/IPv6 parsing
│   │   ├── transport.go            # TCP/UDP parsing
│   │   ├── dns.go                  # DNS query/response parsing
│   │   ├── http.go                 # HTTP header parsing
│   │   └── tls.go                  # TLS SNI extraction
│   ├── flow\
│   │   └── tracker.go              # Connection flow tracking
│   ├── process\
│   │   └── correlator.go           # Process-to-connection mapping
│   ├── tls\
│   │   └── keylogger.go            # TLS master secret logging
│   ├── hotspot\
│   │   └── device_tracker.go       # Hotspot device tracking
│   ├── geoip\
│   │   ├── geoip.go                # GeoIP lookup (PostgreSQL)
│   │   └── unknown_tracker.go      # Unknown IP tracking
│   ├── dedup\
│   │   └── engine.go               # Packet deduplication
│   ├── stats\
│   │   └── collector.go            # Statistics collection
│   ├── writer\
│   │   └── json_writer.go          # JSONL output writer
│   └── collectors\
│       ├── firewall_log_collector.go  # Firewall log (5-min rotation)
│       ├── idsips_log_collector.go    # IDS/IPS log (5-min rotation)
│       ├── biflow_collector.go        # NetFlow split (E-W, N-S)
│       ├── device_collector.go        # Device inventory analyzer
│       ├── log_analyzer.go            # Log parsing
│       └── mac_vendor_db.go           # MAC vendor lookup
└── pkg\models\
    └── packet.go                   # Packet data models
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\network_logger\
└── network_logger.exe              # Windows executable
```

### Configuration Files
```
D:\SafeOpsFV2\bin\network_logger\config.yaml  # Optional YAML config
(Service uses hardcoded defaults if config missing)
```

### Log Output Files
```
D:\SafeOpsFV2\bin\logs\
├── network_packets_master.jsonl    # Master log (5-min cycle)
├── ids.log                         # IDS events (5-min rotation)
├── firewall.log                    # Firewall events (5-min rotation)
├── netflow\
│   ├── east_west.log               # Internal traffic (5-min rotation)
│   ├── north_south.log             # External traffic (5-min rotation)
│   └── unknown.log                 # Unclassified (5-min rotation)
├── devices.jsonl                   # Device inventory (30s updates)
├── unknown_ips.csv                 # IPs not in GeoIP DB
└── sslkeys.log                     # TLS master secrets (SSLKEYLOGFILE)
```

## Functionality

### Core Functions

#### 1. Packet Capture
- **Multi-interface Support** - Captures from all active NICs simultaneously
- **Promiscuous Mode** - Captures all packets on network segment
- **BPF Filtering** - Berkeley Packet Filter for selective capture
- **Npcap Integration** - Windows packet capture (WinPcap successor)
- **Libpcap Support** - Linux/Unix packet capture
- **Snapshot Length** - 1600 bytes per packet
- **Zero-copy Architecture** - Efficient memory handling

#### 2. Protocol Parsing
**Layer 2 (Data Link):**
- Ethernet II frame parsing
- MAC address extraction
- VLAN tagging support

**Layer 3 (Network):**
- IPv4 packet parsing (protocol, TTL, flags, fragmentation)
- IPv6 packet parsing (flow label, hop limit)
- ICMP message parsing

**Layer 4 (Transport):**
- TCP segment parsing (flags, sequence, acknowledgment)
- UDP datagram parsing
- Port number extraction
- TCP state tracking (SYN, ACK, FIN, RST)

**Layer 7 (Application):**
- DNS query/response parsing (A, AAAA, CNAME, MX, TXT records)
- HTTP header parsing (Host, User-Agent, method, URI)
- TLS ClientHello parsing (SNI extraction)
- DHCP packet parsing

#### 3. Flow Tracking
- **5-tuple Identification** - (src_ip, dst_ip, src_port, dst_port, protocol)
- **Bidirectional Flows** - Tracks both directions of conversation
- **Flow Metadata** - Start time, end time, packet count, byte count
- **Flow Timeout** - 60-second inactivity timeout
- **Flow Cleanup** - 30-second cleanup interval
- **Flow State** - NEW, ESTABLISHED, CLOSING, CLOSED
- **Connection Lifecycle** - Full TCP handshake tracking

#### 4. TLS Decryption Support
- **SSLKEYLOGFILE Integration** - Reads TLS master secrets
- **Key Monitoring** - Watches sslkeys.log for new keys
- **Browser Integration** - Chrome/Firefox TLS key logging
- **Wireshark Compatible** - Keys can be imported to Wireshark
- **Real-time Updates** - Captures keys as sessions are created

#### 5. Process Correlation
- **PID Mapping** - Maps connections to process IDs (Windows)
- **Process Name** - Identifies application (chrome.exe, steam.exe)
- **Cache TTL** - 10-second cache for fast lookups
- **Netstat Integration** - Uses `netstat -ano` for correlation

#### 6. Deduplication
- **Hash-based** - Dedup by (src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
- **Time Window** - 30-second deduplication window
- **Cache Size** - 10,000 entry cache
- **Memory Efficient** - LRU eviction

#### 7. GeoIP Enrichment
- **PostgreSQL GeoIP DB** - IP2Location database
- **Country/City Lookup** - Enriches packets with geolocation
- **ASN Lookup** - Autonomous System Number
- **Unknown IP Tracking** - Logs IPs not in database to unknown_ips.csv

#### 8. Hotspot Device Tracking
- **Subnet Detection** - Identifies Mobile Hotspot subnet (192.168.137.0/24)
- **Device Inventory** - Tracks devices connected to hotspot
- **MAC Vendor Lookup** - Identifies device manufacturer

#### 9. Multi-output Logging

**Master Log (network_packets_master.jsonl):**
- All captured packets in JSONL format
- 5-minute overwrite cycle (continuous rolling)
- 75-packet batch writes
- Complete metadata per packet

**IDS/IPS Log (ids.log):**
- Security events from IDS/IPS engine
- 5-minute rotation (timestamped files)
- Alert severity, signature, action

**Firewall Log (firewall.log):**
- Firewall allow/block decisions
- 5-minute rotation
- Rule name, action, packet details

**NetFlow Logs:**
- East-West Traffic (east_west.log) - Internal LAN traffic
- North-South Traffic (north_south.log) - Internet-bound traffic
- Unknown Traffic (unknown.log) - Unclassified flows
- 5-minute rotation per file

**Device Inventory (devices.jsonl):**
- Aggregated device statistics
- Analyzes master log every 30 seconds
- Per-device packet/byte counts
- Top talkers, protocols used

**Unknown IPs (unknown_ips.csv):**
- Public IPs not found in GeoIP database
- Helps identify missing GeoIP data
- CSV format for easy import

**TLS Keys (sslkeys.log):**
- TLS master secrets for decryption
- SSLKEYLOGFILE format
- Compatible with Wireshark, mitmproxy
- Real-time key logging

#### 10. Statistics & Monitoring
- **Live Statistics** - Displayed every 2 minutes
- **Packet Counters** - Total packets, TCP, UDP, ICMP
- **Protocol Distribution** - HTTP, HTTPS, DNS, SSH, other
- **Top Talkers** - Most active IPs
- **Deduplication Stats** - Cache hits, unique packets
- **TLS Stats** - Total keys, recent keys
- **Throughput Metrics** - Packets/sec, bytes/sec

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| N/A | Packet Capture | Raw packet capture (all ports) | Passive |
| 5432 | PostgreSQL | GeoIP database lookup | Client |

### Captured Protocols
- DNS (53 UDP/TCP)
- HTTP (80 TCP)
- HTTPS (443 TCP)
- SSH (22 TCP)
- FTP (21 TCP)
- SMTP (25, 587 TCP)
- DHCP (67, 68 UDP)
- All other TCP/UDP/ICMP traffic

## API Endpoints

**No API endpoints** - Network Logger is a passive capture service. Outputs are written to log files for consumption by other services (SIEM, IDS/IPS, Firewall).

## Dependencies

### Go Dependencies

**Packet Capture:**
- github.com/google/gopacket - Packet decoding library
- github.com/google/gopacket/pcap - Libpcap/Npcap bindings
- github.com/google/gopacket/layers - Protocol layers

**Database:**
- github.com/lib/pq - PostgreSQL driver (GeoIP lookups)

**Configuration:**
- gopkg.in/yaml.v3 - YAML parsing

**Utilities:**
- encoding/json - JSONL output
- sync - Concurrency primitives
- time - Timing and intervals

### External Dependencies
- **Npcap (Windows)** - Packet capture driver (https://npcap.com/)
- **Libpcap (Linux)** - Packet capture library
- **PostgreSQL 14+** - GeoIP database storage
- **IP2Location LITE** - GeoIP database

### Windows Requirements
- Npcap 1.70+ (must be installed separately)
- Administrator privileges (for raw packet capture)

### Linux Requirements
- libpcap-dev package
- CAP_NET_RAW capability or root privileges

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│      Network Logger (Passive Capture)           │
│   (Packet Capture, Parsing, Logging)            │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[Master Log] [IDS Log]  [FW Log]  [NetFlow]
(JSONL)      (Rotate)   (Rotate)  (E-W/N-S)
    ↓           ↓          ↓          ↓
  [SIEM]   [Kibana]   [Firewall]  [Grafana]
  (ELK)    (Viz)      (Engine)     (Metrics)
    ↓
[PostgreSQL]
(GeoIP DB)
```

### Integration Points

**To Other Components:**
1. **SIEM (Elasticsearch)** - Forwards master log, IDS log, firewall log
2. **IDS/IPS** - Provides packet metadata for signature matching
3. **Firewall Engine** - Logs firewall decisions
4. **Network Analysis Tools** - Provides NetFlow data

**From Other Components:**
- PostgreSQL GeoIP database (IP2Location)
- TLS keys from browsers (SSLKEYLOGFILE)

### Log Consumption
- **Master Log** - Consumed by SIEM forwarder
- **IDS Log** - Parsed by Kibana for dashboards
- **Firewall Log** - Used for firewall analytics
- **NetFlow** - Analyzed for traffic patterns
- **Device Inventory** - Displayed in web portal
- **TLS Keys** - Imported to Wireshark for decryption

## Database Schema

**PostgreSQL 14+ Tables:**

1. **ip_geolocation** - GeoIP database (from Threat Intel)
   - ip_start, ip_end (INET)
   - country_code, country_name
   - city, latitude, longitude
   - timezone

**Note:** Network Logger does not create its own tables. It queries the GeoIP table created by the Threat Intelligence service for IP enrichment.

## Configuration

### Capture Configuration
```yaml
capture:
  interfaces: []               # Empty = all active interfaces
  promiscuous: true            # Capture all packets on segment
  snapshot_length: 1600        # Bytes per packet
  bpf_filter: ""               # Berkeley Packet Filter (e.g., "tcp port 80")
```

### Logging Configuration
```yaml
logging:
  log_path: "D:/SafeOpsFV2/bin/logs/network_packets_master.jsonl"
  batch_size: 75               # Packets per batch write
  cycle_minutes: 5             # Master log overwrite cycle
  log_rotation_minutes: 5      # Rotation for IDS, FW, NetFlow
```

### Flow Configuration
```yaml
flow:
  timeout_seconds: 60          # Flow inactivity timeout
  cleanup_interval_seconds: 30 # Cleanup old flows every 30s
```

### Deduplication Configuration
```yaml
deduplication:
  enabled: true
  window_seconds: 30           # Dedup time window
  cache_size: 10000            # Max cache entries
```

### Process Correlation
```yaml
process:
  cache_ttl_seconds: 10        # Process name cache TTL
```

### TLS Configuration
```yaml
tls:
  enabled: true
  keylog_file: "D:/SafeOpsFV2/bin/logs/sslkeys.log"
```

### Statistics Display
```yaml
stats:
  display_interval_seconds: 120  # Show stats every 2 minutes
```

### Hotspot Configuration
```yaml
hotspot:
  enabled: true
  subnet: "192.168.137.0/24"   # Mobile Hotspot subnet
```

## Important Notes

### Performance
- Multi-interface parallel capture
- Batch writes (75 packets/batch)
- Efficient deduplication (hash-based)
- Goroutine-per-interface architecture
- Lock-free channels for packet passing

### Reliability
- Graceful shutdown (Ctrl+C handling)
- 5-minute log rotation prevents disk fill
- Automatic interface rediscovery (10s interval)
- Error recovery and logging
- Statistics tracking

### Security
- Requires elevated privileges (admin/root)
- Captures ALL network traffic (sensitive data)
- TLS keys stored in plaintext (restrict access)
- Logs may contain passwords, tokens (secure storage required)

### Storage
- Master log: ~50-500 MB per 5-minute cycle (depends on traffic)
- Rotated logs: Timestamped files accumulate (cleanup required)
- TLS keys: Grows continuously (periodic cleanup recommended)
- Device inventory: Small (<1 MB)
- Unknown IPs CSV: Grows slowly

### Capacity
- 10,000+ packets/second capture rate
- 10,000 flow cache entries
- 10,000 deduplication cache entries
- Unlimited packet logging (disk space limited)

### TLS Decryption
- Requires browser/app SSLKEYLOGFILE configuration
- Chrome: Set environment variable `SSLKEYLOGFILE=D:\SafeOpsFV2\bin\logs\sslkeys.log`
- Firefox: about:config → `security.tls.keylog.file`
- Does NOT work with: Perfect Forward Secrecy (PFS) in some cases
- Does NOT work with: TLS 1.3 without PSK

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| SIEM (Elasticsearch) | Log Forwarder | Ingest master log, IDS log, FW log |
| IDS/IPS | Packet Metadata | Security event generation |
| Firewall Engine | Log Consumer | Firewall decision logging |
| PostgreSQL | Database | GeoIP lookup queries |
| Kibana | Visualization | Dashboard display of logs |
| Grafana | Metrics | NetFlow analytics |
| Wireshark | TLS Keys | Manual packet decryption |

---

**Status:** Production Ready
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** Npcap (Windows), PostgreSQL (GeoIP)
**Managed By:** Orchestrator
**Version:** 1.0.0
**Privileges Required:** Administrator (Windows), root or CAP_NET_RAW (Linux)
