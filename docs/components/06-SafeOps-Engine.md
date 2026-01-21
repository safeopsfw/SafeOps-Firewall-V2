# SafeOps Engine - Component Documentation

## Overview
The SafeOps Engine is the core network pipeline orchestrator built in Go. It uses the WinpkFilter kernel driver to intercept ALL network traffic at the kernel level, extract domain metadata (DNS, SNI, HTTP), and forward packets immediately for zero-latency passthrough. It serves as the foundation for the entire SafeOps firewall system.

## Component Information

**Component Type:** Kernel-level Packet Pipeline
**Language:** Go
**Architecture:** Kernel bypass with WinpkFilter (NDIS filter driver)
**Platform:** Windows (NDIS 6.x, Windows 7+)

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\safeops-engine\
├── cmd\main.go                     # Service entry point
├── internal\
│   ├── config\
│   │   └── config.go               # Configuration structures
│   ├── driver\
│   │   ├── winpkfilter.go          # WinpkFilter driver interface
│   │   ├── adapter.go              # Network adapter management
│   │   ├── packet.go               # Packet structure
│   │   └── tunnel.go               # Tunnel mode control
│   ├── parser\
│   │   ├── dns_parser.go           # DNS query extraction
│   │   ├── tls_parser.go           # TLS SNI extraction
│   │   └── http_parser.go          # HTTP Host extraction
│   └── logger\
│       ├── logger.go               # Structured JSON logger
│       └── rotation.go             # 5-minute log rotation
└── configs\
    ├── config.yaml                 # Main configuration
    └── dnsproxy.yaml               # DNS proxy config
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\safeops-engine\
├── safeops-engine.exe              # Windows service
└── config.yaml                     # Runtime configuration
```

### Driver Files
```
C:\Windows\System32\drivers\
└── ndisapi.sys                     # WinpkFilter kernel driver (installed by SafeOps)
```

### Log Files
```
D:\SafeOpsFV2\data\logs\
└── engine.log                      # Engine log (5-min rotation)
```

## Functionality

### Core Functions

#### 1. Kernel-Level Packet Interception
- **WinpkFilter Integration** - Uses NDIS 6.x filter driver for kernel bypass
- **Tunnel Mode** - Sets adapters to tunnel mode for packet interception
- **Zero-Copy** - Packets passed by reference, not copied
- **Multi-NIC Support** - Intercepts on all physical adapters simultaneously
- **Full Duplex** - Captures both inbound and outbound packets
- **Raw Packet Access** - Complete Ethernet frames available

#### 2. Network Adapter Management
- **Adapter Discovery** - Enumerates all network interfaces
- **Physical Adapter Detection** - Skips virtual adapters (VMware, Hyper-V, VPN)
- **Adapter Filtering** - Only monitors physical NICs (Ethernet, WiFi, Mobile Hotspot)
- **MAC Address Tracking** - Identifies adapters by MAC
- **Adapter Metadata** - Name, friendly name, description, MAC
- **Dynamic Adapter Detection** - Detects hotplug NICs (USB, Thunderbolt)

#### 3. Domain Extraction
**DNS Domain Extraction (Port 53):**
- Parses DNS query packets (UDP/TCP)
- Extracts queried domain names
- Logs domain, source IP, destination DNS server
- Handles A, AAAA, CNAME, MX, TXT queries

**TLS SNI Extraction (Port 443):**
- Parses TLS ClientHello handshake
- Extracts Server Name Indication (SNI)
- Identifies HTTPS domains before TLS encryption
- Logs SNI, source IP, destination IP

**HTTP Host Extraction (Port 80):**
- Parses HTTP request headers
- Extracts Host header value
- Logs HTTP domain, source IP, destination IP
- Handles GET, POST, PUT, DELETE methods

#### 4. Pure Passthrough Mode
- **Zero Filtering** - NO packet blocking or modification
- **Immediate Forwarding** - Packets forwarded instantly after metadata extraction
- **No Buffering** - No packet queuing or delay
- **No Inspection** - Only extracts domains, no deep packet inspection
- **Transparent Operation** - Applications unaware of interception
- **Full Speed** - Wire-speed performance (1 Gbps+)

#### 5. Statistics & Monitoring
- **Packet Counters** - Read, written, dropped packets
- **Per-Adapter Stats** - Separate stats for each NIC
- **Real-time Logging** - Domain extraction logged immediately
- **Periodic Stats** - Statistics every 30 seconds
- **Final Stats** - Total counts on shutdown

#### 6. Log Rotation
- **5-Minute Rotation** - Log files rotated every 5 minutes
- **Timestamped Files** - engine.log, engine_YYYYMMDD_HHMMSS.log
- **Automatic Cleanup** - Old logs retained for 24 hours
- **JSON Format** - Structured logging for easy parsing
- **Log Levels** - DEBUG, INFO, WARN, ERROR

#### 7. Graceful Shutdown
- **Signal Handling** - Responds to Ctrl+C, SIGTERM
- **Context Cancellation** - Stops packet processing cleanly
- **Driver Cleanup** - Restores adapters to normal mode
- **Final Statistics** - Logs total packets processed
- **Resource Release** - Closes driver handles, frees memory

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| **9002** | REST API | Engine management API (future) | Server |
| N/A | Packet Pipeline | Kernel-level interception (all ports) | Bidirectional |
| 15353 | DNS Proxy | DNS interception (optional) | Server |
| 8080 | mitmproxy | HTTPS interception (optional) | Server |

### Intercepted Ports
- DNS (53 UDP/TCP) - Domain extraction only
- HTTP (80 TCP) - Host extraction only
- HTTPS (443 TCP) - SNI extraction only
- All other ports - Passthrough without inspection

## API Endpoints

**Future API (Not Yet Implemented):**
- `GET /api/engine/status` - Engine status and stats
- `GET /api/engine/adapters` - List network adapters
- `POST /api/engine/start` - Start packet processing
- `POST /api/engine/stop` - Stop packet processing
- `GET /api/engine/stats` - Real-time statistics

**Current Version:** No API endpoints. Engine is a passive capture service that logs to file.

## Dependencies

### Go Dependencies

**WinpkFilter:**
- Custom CGO bindings to ndisapi.dll
- github.com/wiresock/ndisapi-go (future - currently custom)

**Networking:**
- net - IP address parsing
- syscall - Windows syscalls

**Logging:**
- encoding/json - JSON structured logging
- log - Standard logging
- os - File operations

**Concurrency:**
- context - Cancellation context
- sync/atomic - Atomic counters

**Utilities:**
- time - Timing and intervals
- os/signal - Signal handling

### External Dependencies
- **WinpkFilter Driver (ndisapi.sys)** - NDIS 6.x kernel filter driver
- **ndisapi.dll** - User-mode library for driver communication

### Windows Requirements
- Windows 7+ (NDIS 6.x support)
- Administrator privileges (kernel driver access)
- WinpkFilter driver installed (included with SafeOps)

### Driver Installation
- Installed automatically by SafeOps Launcher
- Driver file: `C:\Windows\System32\drivers\ndisapi.sys`
- DLL file: `C:\Windows\System32\ndisapi.dll`
- Driver version: 6.2.12288

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│         SafeOps Engine (Kernel Pipeline)        │
│    (WinpkFilter → Domain Extraction → Log)      │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[DNS Proxy]  [mitmproxy] [Logger]  [All NICs]
(15353)      (8080)      (file)    (Tunnel)
    ↓           ↓          ↓
[Firewall]  [IDS/IPS]  [Network
(Future)    (Future)    Apps]
```

### Integration Points

**To Other Components:**
1. **DNS Proxy (15353)** - Optional DNS interception (disabled by default)
2. **mitmproxy (8080)** - Optional HTTPS inspection (disabled by default)
3. **Network Logger** - Consumes engine.log for analysis
4. **SIEM** - Parses engine.log for domain tracking

**From Kernel:**
- NDIS filter driver (ndisapi.sys)
- Raw Ethernet frames from all NICs
- Kernel bypass for performance

### Packet Flow
```
Application → TCP/IP Stack → NDIS → WinpkFilter → SafeOps Engine
                                        ↓
                                  [Extract Domain]
                                        ↓
                                  [Log to File]
                                        ↓
                                  [Forward Packet]
                                        ↓
                               Physical NIC → Network
```

## Database Schema

**No database** - SafeOps Engine is a stateless packet pipeline. All data is logged to files.

## Configuration

### Logging Configuration
```yaml
logging:
  level: "info"                # debug, info, warn, error
  format: "json"               # json or text
  file: "D:/SafeOpsFV2/data/logs/engine.log"
```

### API Configuration (Future)
```yaml
api:
  address: "0.0.0.0"
  port: 9002                   # Changed from 9000 to avoid Step CA conflict
```

### Pipeline Configuration
```yaml
pipeline:
  metadata_buffer_size: 20000  # Buffer size for metadata stream
  dns_cache_ttl: 300           # DNS cache TTL in seconds
  flow_cleanup_interval: 60    # Flow cleanup interval
  ipv6_enabled: true           # Enable IPv6 support

  # Feature toggles (disable to reduce overhead)
  extract_dns: true            # Extract DNS queries
  extract_sni: true            # Extract TLS SNI
  extract_http: true           # Extract HTTP Host
  extract_dhcp: true           # Extract DHCP info (future)
```

### DNS Proxy Configuration (Optional)
```yaml
dnsproxy:
  enabled: false               # Disabled by default
  binary_path: "D:/SafeOpsFV2/bin/dnsproxy/windows-amd64/dnsproxy.exe"
  listen_port: 15353           # Changed from 5353 to avoid mDNS conflict
  fallback_ports: [25353, 35353, 45353]
```

### mitmproxy Configuration (Optional)
```yaml
mitm:
  enabled: false               # Disabled by default
  binary_path: "mitmdump"      # Must be in PATH
  listen_port: 8080
  mode: "regular"              # Regular proxy mode
```

### Classifier Configuration
```yaml
classifier:
  # Gaming ports (bypass inspection for low latency)
  gaming_ports:
    - 27000-27050              # Steam
    - 9000-9003                # Epic Games
    - 1119, 6113               # Battle.net
    - 3074                     # Xbox Live
    - 3478, 3479, 3658         # PlayStation

  # VoIP ports (bypass inspection)
  voip_ports:
    - 3478-3479                # Discord
    - 50000, 50019             # Teams
    - 8801, 8810               # Zoom
    - 16384-32767              # WebRTC

  # Bypass these domains (SNI-based)
  bypass_domains:
    - "steampowered.com"
    - "epicgames.com"
    - "discord.gg"
    - "twitch.tv"
    - "youtube.com"
```

### NAT Configuration (Future)
```yaml
nat:
  enabled: false               # Not yet implemented
  external_ip: ""              # Auto-detect
  port_range_start: 60000
  port_range_end: 65535
```

## Important Notes

### Performance
- **Wire-speed** - Minimal latency (<1ms added)
- **Kernel bypass** - No user-space packet copies
- **Zero-copy** - Packets passed by reference
- **Multi-threaded** - Goroutine per adapter
- **Efficient logging** - Buffered writes

### Reliability
- Kernel driver stability (WinpkFilter is mature, stable)
- Graceful degradation if driver fails
- Automatic adapter rediscovery
- Panic recovery in packet handlers
- Signal handling for clean shutdown

### Security
- Requires administrator privileges (kernel driver access)
- Driver signed by NT Kernel Service (kernel-mode code signing)
- Logs ALL domains (privacy concern - secure log storage)
- No TLS inspection (no MITM by default)
- Pure passthrough (no packet modification)

### Capacity
- 1 Gbps+ throughput per adapter
- 10 Gbps total with multiple NICs
- 10,000+ packets/second per core
- Unlimited domain logging (disk space limited)

### Limitations
- **Windows Only** - WinpkFilter is Windows-specific (Linux: use nfqueue, eBPF)
- **No Blocking** - Pure passthrough mode (no firewall rules yet)
- **Domain Only** - Only extracts domains, no payload inspection
- **No TLS Decryption** - Cannot inspect encrypted HTTPS content (by design)

### Comparison to Network Logger
| Feature | SafeOps Engine | Network Logger |
|---------|---------------|----------------|
| Capture Method | Kernel bypass (WinpkFilter) | Libpcap/Npcap |
| Performance | Wire-speed, <1ms latency | ~10ms latency |
| Depth | Domain extraction only | Full packet analysis |
| Purpose | Real-time pipeline | Forensics & logging |
| Storage | Minimal (domains only) | Full packets (JSONL) |
| TLS Decryption | No | Yes (with SSLKEYLOGFILE) |

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| WinpkFilter Driver | Kernel Driver | Raw packet interception |
| DNS Proxy | Process Spawn | DNS filtering (optional) |
| mitmproxy | Process Spawn | HTTPS inspection (optional) |
| Network Logger | Log Consumer | Parses engine.log |
| SIEM | Log Consumer | Domain tracking analytics |
| Firewall (Future) | Packet Filter | Rule enforcement |
| IDS/IPS (Future) | Signature Match | Threat detection |

---

**Status:** Production Ready (Passthrough Mode)
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** WinpkFilter driver (ndisapi.sys)
**Managed By:** Orchestrator
**Version:** 3.0.0
**Mode:** Pure Passthrough (no filtering)
**Privileges Required:** Administrator (kernel driver access)
