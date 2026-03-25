# SafeOps Tools Description

This document provides a comprehensive technical description of every tool in the SafeOps Firewall V2 platform.

---

## Tool 1: SafeOps Launcher

### 1.1 Overview

The SafeOps Launcher is the **unified service orchestrator** that brings the entire SafeOps platform to life with a single executable. It is responsible for starting, monitoring, and gracefully shutting down all 11 platform services in the correct dependency order. Think of it as the "control tower" — without it, each service would need to be started manually in the right sequence, with the right working directories and arguments.

### 1.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.21 |
| **Module Name** | `safeops-launcher` |
| **Source Location** | `src/launcher/main.go` (388 lines, 15 KB) |
| **Binary Output** | `bin/SafeOps-Launcher.exe` |
| **External Dependencies** | `github.com/lib/pq v1.10.9` (PostgreSQL driver) |
| **Admin Required** | Yes (for SafeOps Engine & Firewall Engine) |

### 1.3 What It Does

When you run `SafeOps-Launcher.exe`, it performs the following sequence:

1. **Signal Handler Setup** — Registers `SIGINT` and `SIGTERM` listeners for graceful shutdown
2. **Path Detection** — Intelligently locates the project root and `bin/` directory (supports running from project root, bin folder, or any parent)
3. **Database Initialization** — Connects to PostgreSQL (`localhost:5432`, database `threat_intel_db`) to verify it is reachable
4. **Step-CA Maintenance** — Resets the BadgerDB folder (`bin/step-ca/db/`) to prevent corruption from unclean shutdowns
5. **Sequential Service Startup** — Starts 9 core services with configurable delays between each
6. **UI & Backend Launch** — Opens the Vite dev server and Node.js backend in separate terminal windows
7. **Browser Launch** — Automatically opens `http://localhost:3001` in the default browser after a 3-second delay
8. **Wait for Shutdown** — Blocks on `Enter` key or `Ctrl+C`, then terminates all child processes

### 1.4 Service Startup Order

The services are started in a carefully designed dependency order. Services that other services depend on start first, with staggered delays to allow initialization:

| Order | Service | Executable | Delay After Start | Admin? |
|:-----:|---------|------------|:-----------------:|:------:|
| 1 | NIC Management | `bin/nic_management/nic_management.exe` | 1s | No |
| 2 | DHCP Monitor | `bin/dhcp_monitor/dhcp_monitor.exe` | 1s | No |
| 3 | Step-CA | `bin/step-ca/bin/step-ca.exe` | 2s | No |
| 4 | Captive Portal | `bin/captive_portal/captive_portal.exe` | 1s | No |
| 5 | SafeOps Engine | `bin/safeops-engine/safeops-engine.exe` | 2s | **Yes** |
| 6 | Firewall Engine V5 | `bin/firewall-engine/firewall-engine.exe` | 2s | **Yes** |
| 7 | Network Logger | `bin/network-logger/network-logger.exe` | 1s | No |
| 8 | SIEM Forwarder | `bin/siem-forwarder/siem-forwarder.exe` | 1s | No |
| 9 | Threat Intel Pipeline | `bin/threat_intel/threat_intel.exe` | 1s | No |
| 10 | UI Frontend | `src/ui/dev/` (via `npm run dev`) | 5s | No |
| 11 | Backend API | `backend/` (via `npm start`) | 1s | No |

**Total startup time:** ~18 seconds (sum of all delays)

> **Why this order?** NIC Management and DHCP Monitor must be up before the network interception stack (SafeOps Engine + Firewall Engine). Step-CA must be running before Captive Portal so certificates can be issued. The Firewall Engine needs SafeOps Engine running first because it connects to it via gRPC. SIEM Forwarder starts after Network Logger so there are log files to ship.

### 1.5 Command-Line Arguments Passed to Services

Some services receive specific arguments from the launcher:

| Service | Arguments |
|---------|-----------|
| Step-CA | `config/ca.json --password-file secrets/password.txt` |
| SIEM Forwarder | `-config config.yaml` |
| Threat Intel Pipeline | `-scheduler` |
| All others | (none — use defaults) |

### 1.6 Key Functions

| Function | Purpose |
|----------|---------|
| `main()` | Entry point — sets up signals, detects paths, starts services |
| `detectPaths()` | 4-method path resolution (bin check → bin subdir → src subdir → fallback) |
| `initThreatIntelDB()` | Connects to PostgreSQL to verify the `threat_intel_db` is reachable |
| `resetStepCADatabase()` | Deletes and recreates `bin/step-ca/db/` to prevent BadgerDB corruption |
| `startService()` | Generic service starter — checks exe exists, starts process, tracks PID |
| `startUIAndBackend()` | Launches Vite dev server and Node.js backend in new `cmd.exe` windows |
| `cleanup()` | Kills all tracked PIDs + force-kills known service executables via `taskkill` |

### 1.7 Path Detection Logic

The launcher can be run from multiple locations and will auto-detect the correct paths:

```
Method 1: Exe is inside bin/       → projectRoot = parent of bin/
Method 2: Exe dir has bin/ subdir  → projectRoot = exe dir
Method 3: Exe dir has src/ subdir  → projectRoot = exe dir
Method 4: Fallback                 → projectRoot = exe dir (with warning)
```

### 1.8 Graceful Shutdown

When the user presses `Ctrl+C` or `Enter`:

1. **Phase 1:** Kill all tracked `os.Process` handles (the ones started by `startService()`)
2. **Phase 2:** Force-kill by executable name via `taskkill /IM <name> /F` for 10 known service executables:
   - `threat_intel_api.exe`, `threat_intel.exe`, `nic_management.exe`, `dhcp_monitor.exe`, `step-ca.exe`, `captive_portal.exe`, `safeops-engine.exe`, `firewall-engine.exe`, `network-logger.exe`, `siem-forwarder.exe`
3. **Note:** UI and Backend windows (opened via `cmd /c start`) must be closed manually

### 1.9 Expected Resource Consumption

The launcher displays a CPU/RAM estimate table after startup:

| Service | Idle CPU | Active CPU |
|---------|:--------:|:----------:|
| DHCP Monitor | ~1–3% | (polling ARP) |
| Step-CA | ~0–1% | ~3% (issuing certs) |
| Captive Portal | ~0–1% | ~2% (serving pages) |
| SafeOps Engine | ~2–5% | (packet capture) |
| Firewall Engine V5 | ~2–5% | (dual-engine) |
| Network Logger | ~1–3% | (logging packets) |
| Threat Intel | ~0% | ~10–20% (fetching feeds) |
| NIC Management | ~0–1% | (idle) |
| SIEM Forwarder | ~0–1% | ~2% (shipping logs) |
| UI + Backend | ~2–5% | (Vite HMR + Node) |
| **TOTAL** | **~5–15%** | **~15–35%** |
| **RAM** | | **~500 MB – 1 GB** |

### 1.10 Service Endpoints After Launch

| Service | Endpoint |
|---------|----------|
| PostgreSQL (Threat Intel DB) | `localhost:5432` |
| NIC Management API | `http://localhost:8081` (REST + SSE) |
| DHCP Monitor | `localhost:50055` (gRPC) |
| Step-CA | `https://localhost:9000` (ACME) |
| Captive Portal | `https://localhost:8445` / `http://localhost:8090` |
| SafeOps Engine | (kernel-mode, no HTTP endpoint) |
| Firewall Engine | (connects to SafeOps Engine via gRPC :50051) |
| Network Logger | (writes JSONL files, no HTTP) |
| SIEM Forwarder | (ships logs to Elasticsearch) |
| Threat Intel Pipeline | (background scheduler) |
| Backend API | `http://localhost:5050` |
| UI Frontend | `http://localhost:3001` |

### 1.11 Prerequisites

- **PostgreSQL 16** installed at `C:/Program Files/PostgreSQL/16/`
- **Go 1.21+** installed and in PATH
- **Node.js + npm** installed (for UI and Backend)
- All service executables pre-built in `bin/` directory
- **Administrator privileges** (required for SafeOps Engine and Firewall Engine)

### 1.12 Limitations

- **Development mode only** — UI runs via `npm run dev`, not a production build
- **No auto-restart** — if a service crashes, the launcher does not restart it
- **No log file management** — service output goes to stdout only
- **No health monitoring** — the launcher does not periodically check if services are still alive
- **Manual UI/Backend shutdown** — windows opened via `cmd /c start` are not tracked for cleanup
- **Windows-only** — uses `taskkill`, `cmd /c start`, and Windows-specific paths

### 1.13 File Structure

```
src/launcher/
├── main.go          # 388 lines — entire launcher logic
├── go.mod           # Module: safeops-launcher (Go 1.21)
└── go.sum           # Single dependency: lib/pq v1.10.9
```

### 1.14 Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                  SafeOps Launcher                       │
│                   (main.go)                             │
├─────────────────────────────────────────────────────────┤
│  1. Signal Handler (SIGINT/SIGTERM)                     │
│  2. detectPaths() → projectRoot + binDir                │
│  3. initThreatIntelDB() → PostgreSQL ping               │
│  4. resetStepCADatabase() → BadgerDB cleanup            │
├─────────────────────────────────────────────────────────┤
│                Sequential Service Start                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │NIC Management│→ │ DHCP Monitor │→ │   Step-CA    │  │
│  │   (1s delay) │  │   (1s delay) │  │  (2s delay)  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │Captive Portal│→ │SafeOps Engine│→ │Firewall V5   │  │
│  │   (1s delay) │  │  (2s, Admin) │  │ (2s, Admin)  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │Network Logger│→ │SIEM Forwarder│→ │ Threat Intel │  │
│  │   (1s delay) │  │   (1s delay) │  │  (1s delay)  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────┤
│  startUIAndBackend() → cmd /c start (new windows)       │
│  └─ UI (npm run dev :3001) + Backend (npm start :5050)  │
├─────────────────────────────────────────────────────────┤
│  Browser auto-open → http://localhost:3001              │
│  Wait for Enter/Ctrl+C → cleanup() → taskkill all      │
└─────────────────────────────────────────────────────────┘
```

---

## Tool 2: SafeOps Engine

### 2.1 Overview

The SafeOps Engine is the **kernel-level data plane** — the single most critical component in SafeOps. It sits between the network interface card and the operating system's TCP/IP stack using the **WinPkFilter NDIS** driver, intercepting every single network packet before Windows sees it. Its job is to parse packets at wire speed, extract domain information (DNS/TLS SNI/HTTP Host/QUIC), apply local blocking decisions (domains, DoH servers, VPN ports), and stream rich metadata to downstream consumers (Firewall Engine, IDS/IPS) via gRPC.

**In essence:** If the SafeOps Engine doesn't allow a packet, it never reaches the application — and if it forces a DNS redirect, the blocked domain resolves to 127.0.0.1 where a local block page is served.

### 2.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.25.5 |
| **Module Name** | `safeops-engine` |
| **Source Location** | `src/safeops-engine/` (25 Go files) |
| **Binary Output** | `bin/safeops-engine/safeops-engine.exe` |
| **Version** | 6.1.0 |
| **Admin Required** | **Yes** (kernel driver access) |
| **Key Dependency** | `github.com/wiresock/ndisapi-go v1.0.1` (WinPkFilter NDIS API) |

### 2.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| Metadata Stream | `127.0.0.1:50051` | gRPC | Streams `PacketMetadata` protobuf to subscribers |
| Control API | `127.0.0.1:50052` | gRPC | Admin commands (block domain, get stats, etc.) |
| Block Page (HTTP) | `127.0.0.1:80` | HTTP | Serves HTML block page for DNS-redirected domains |
| Block Page (HTTPS) | `127.0.0.1:443` | HTTPS | Serves HTTPS block page with self-signed cert |

### 2.4 Initialization Sequence

When `engine.Initialize()` is called:

1. **Logger** — Creates JSON-format rotating logger at `data/logs/engine.log`
2. **Driver** — Opens WinPkFilter NDIS driver handle, sets tunnel mode on all adapters
3. **Verdict Engine** — Creates the packet injection engine (TCP RST, DNS response, HTML block page)
4. **Broadcaster** — Creates in-process subscriber hub with 10,000-packet buffer
5. **gRPC Server** — Starts on `:50051` with max 100 concurrent streams (send: 10MB, recv: 1MB)
6. **DNS Cache Flush** — Runs `ipconfig /flushdns` to prevent stale DNS entries bypassing redirects
7. **DoH Blocklist** — Loads `configs/doh_servers.txt` (DNS-over-HTTPS resolver IPs)
8. **VPN Port Blocklist** — Loads `configs/blocked_ports.txt` (port/protocol rules)
9. **Packet Handler** — Registers the fast/slow path handler with the driver
10. **Control API Server** — Starts on `:50052` (non-fatal if port taken)
11. **Block Page Server** — Starts HTTP `:80` + HTTPS `:443` (non-fatal if ports taken)
12. **Packet Processing** — Starts `ProcessPacketsAll()` goroutine — packets begin flowing

### 2.5 Packet Processing Pipeline (The Core)

Every intercepted packet goes through this pipeline:

```
                        ┌──────────────────────┐
                        │  NDIS Driver Capture  │
                        │  (WinPkFilter/Tunnel) │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ VPN Port Block Check  │ → Drop + RST (non-local only)
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ DoH Server IP Block   │ → Drop + RST (port 443 only)
                        └──────────┬───────────┘
                                   │
                     ┌─────────────┴──────────────┐
                     │  isWebTraffic(dstPort)?     │
                     │  (53, 80, 443 = YES)        │
                     └──┬───────────────────────┬──┘
                  NO    │                       │  YES
           ┌────────────▼──┐            ┌───────▼──────────┐
           │   FAST PATH   │            │    SLOW PATH     │
           │  IP blocklist │            │  Domain extract   │
           │  1:100 sample │            │  DNS/SNI/HTTP/QUIC│
           │  to Firewall  │            │  Block/Redirect   │
           │  Cache check  │            │  Flow caching     │
           └───────────────┘            └──────────────────┘
```

#### Fast Path (Non-Web Traffic)
- **O(1) port comparison** — if destination port is NOT 53, 80, or 443, it's fast path
- Checks IP blocklist (`sync.Map.Load` — zero-allocation O(1))
- Sends **1-in-100** packets to Firewall Engine for security monitoring (DDoS, GeoIP, brute force)
- Checks gRPC verdict cache for previously-applied verdicts
- **No domain extraction, no parsing** — microsecond-level latency

#### Slow Path (Web Traffic — DNS/HTTP/HTTPS/QUIC)
1. **Flow Cache Check** — If this TCP flow (on port 80/443) has already been inspected, skip to fast path
2. **IP Blocklist Check** — O(1) sync.Map lookup
3. **MAC Address Caching** — Stores Ethernet header MACs for future RST/injection
4. **DNS (port 53 UDP)** — Extracts queried domain. If blocked → injects fake DNS response pointing to 127.0.0.1
5. **TLS SNI (port 443 TCP)** — Extracts SNI from ClientHello. If blocked → sends TCP RST (unless destination is 127.0.0.1, which is our block page server)
6. **QUIC SNI (port 443 UDP)** — Scans for embedded TLS ClientHello in QUIC Initial packets. If blocked → drop (can't RST UDP)
7. **HTTP Host (port 80 TCP)** — Extracts Host header. If blocked → injects HTML block page + TCP RST
8. **Mark Flow Inspected** — Subsequent data packets on this flow skip slow path
9. **Broadcast via gRPC** — Sends full `PacketMetadata` protobuf to all subscribers

### 2.6 Domain Blocking Mechanisms

The engine uses **four different blocking techniques** depending on the protocol:

| Protocol | Detection | Block Action | User Experience |
|----------|-----------|-------------|----------------|
| DNS (UDP :53) | Query domain parsing | Inject fake `A 127.0.0.1` response | Browser sees block page |
| HTTPS (TCP :443) | TLS ClientHello SNI | TCP RST (connection reset) | "Connection reset" error OR block page via DNS redirect |
| QUIC (UDP :443) | QUIC Initial SNI scan | Silent drop (browser falls back to TCP) | Falls back to TCP → hits SNI block |
| HTTP (TCP :80) | Host header extraction | Inject HTML block page + TCP RST | Sees SafeOps block page |

### 2.7 gRPC Metadata Streaming Architecture

The gRPC server is the bridge between the SafeOps Engine (data plane) and the Firewall Engine (control plane):

| Feature | Value |
|---------|-------|
| **Subscriber Buffer** | 500,000 packets per subscriber channel |
| **Max Concurrent Streams** | 100 |
| **Protocol Filters** | `tcp`, `udp`, `dns`, `http` (pre-computed O(1) flags) |
| **Subscriber Pattern** | Atomic snapshot (lock-free broadcast, mutex-only on add/remove) |
| **Verdict Cache** | `sync.Map` with TTL-based expiry, 60s cleanup interval |
| **Cache Key** | 5-tuple: `srcIP:srcPort:dstIP:dstPort:protocol` (pooled buffer, zero-alloc) |
| **Broadcast Variants** | `BroadcastPacket` (cache-aware) / `BroadcastPacketNoCache` (for DDoS counters) |
| **Drop Monitoring** | Logs every 10,000 dropped packets per subscriber |

The `PacketMetadata` protobuf includes: PacketID, Timestamp, SrcIP, DstIP, SrcPort, DstPort, Protocol, PacketSize, AdapterName, Direction, Domain, DomainSource, CacheKey, TCPFlags (SYN/ACK/RST/FIN), HTTP method, DNS query/response flags.

### 2.8 Internal Packages (8 packages in `internal/`)

| Package | Purpose |
|---------|---------|
| `driver/` | WinPkFilter NDIS wrapper: open/close driver, set tunnel mode, read/write packets, adapter enumeration |
| `parser/` | Protocol parsers: `dns.go` (query/response), `tls.go` (SNI from ClientHello), `http.go` (Host header), `dhcp.go` (lease info) |
| `verdict/` | Packet injection: TCP RST (both directions), DNS response injection, HTML block page injection |
| `config/` | Configuration structs and YAML parsing |
| `logger/` | Async JSON logger with file rotation (`async_packet_logger.go`) |
| `metadata/` | Packet metadata structures for internal use |
| `redirect/` | DNS redirect logic (`dns.go`), HTTP redirect (`http.go`), TCP redirect (`tcp.go`) |
| `sysconfig/` | Windows-specific system configuration (`dns_windows.go`) |

### 2.9 Public API Packages (6 packages in `pkg/`)

| Package | Purpose |
|---------|---------|
| `engine/` | Main Engine struct + `Initialize()`, `handlePacket()`, `Shutdown()`, public APIs for domain blocking |
| `grpc/` | gRPC metadata streaming server: `StreamMetadata`, `ApplyVerdict`, `GetStats` |
| `grpc/pb/` | Auto-generated protobuf code (`metadata_stream.pb.go`, `metadata_stream_grpc.pb.go`) |
| `stream/` | In-process broadcaster for non-gRPC subscribers |
| `control/` | gRPC control API server (`:50052`) for admin commands |
| `blockpage/` | HTTP/HTTPS block page server showing "access denied" page |
| `driver/` | High-level driver wrapper for external consumers |

### 2.10 Configuration Files

| File | Purpose |
|------|---------|
| `configs/doh_servers.txt` | List of DNS-over-HTTPS resolver IPs to block (one per line) |
| `configs/blocked_ports.txt` | VPN port blocklist — format: `port/protocol` (tcp/udp/both) |
| `configs/domains.txt` | Domain blocklist (loaded via Firewall Engine sync, not directly) |

### 2.11 Stats & Monitoring

The engine reports stats every 30 seconds to console:

| Metric | Description |
|--------|-------------|
| `packets_read` | Total packets captured from all adapters |
| `packets_written` | Total packets re-injected to OS |
| `packets_dropped` | Packets silently discarded |
| `fast_path_packets` | Non-web packets (fast path) |
| `slow_path_packets` | Web packets (slow path with parsing) |
| `sampled_packets` | Fast-path packets actually sent to Firewall Engine (1 in 100) |
| `domains_blocked` | DNS redirects + SNI RSTs + HTTP block pages |
| `doh_blocked` | DNS-over-HTTPS connections blocked |
| `vpn_blocked` | VPN/tunnel port connections blocked |
| `grpc_subscribers` | Active gRPC subscriber count |

### 2.12 Key Design Decisions

1. **Fast/Slow Path Split** — Only web traffic (ports 53/80/443) goes through expensive domain extraction. All other traffic uses O(1) checks only.
2. **Flow Caching** — Once a TCP flow on port 80/443 has its domain extracted (from the first packet — ClientHello/GET), subsequent data packets skip slow path entirely. Pruned every 50,000 entries.
3. **1:100 Sampling** — Fast-path packets are only sent to the Firewall Engine at a 1-in-100 rate to avoid flooding the gRPC stream, while still enabling DDoS/port scan detection.
4. **Lock-Free Broadcast** — Uses `atomic.Value` subscriber snapshots so the hot path (packet broadcast) never acquires a mutex. Only add/remove subscriber takes the lock.
5. **DoH Blocking Before DNS** — DoH resolver IPs are blocked BEFORE DNS interception, forcing browsers to fall back to system DNS where our redirect works.
6. **Local IP Exclusion** — VPN/DoH blocking skips RFC1918 private IPs, loopback, link-local, and multicast to avoid killing LAN traffic.
7. **Pre-Block Alerts** — Every blocked packet is broadcast via gRPC BEFORE being dropped, so the Firewall Engine can generate alerts for the SOC log.

### 2.13 File Structure

```
src/safeops-engine/
├── cmd/
│   └── main.go                         # Entry point (78 lines)
├── internal/
│   ├── config/config.go                # Configuration structs
│   ├── driver/
│   │   ├── driver.go                   # WinPkFilter NDIS wrapper
│   │   └── driver_enhanced.go          # Enhanced packet handling
│   ├── logger/
│   │   ├── logger.go                   # Core logger
│   │   └── async_packet_logger.go      # Async packet logging
│   ├── metadata/metadata.go            # Internal metadata structs
│   ├── parser/
│   │   ├── dns.go                      # DNS query/response parser
│   │   ├── tls.go                      # TLS ClientHello SNI extractor
│   │   ├── http.go                     # HTTP Host header extractor
│   │   └── dhcp.go                     # DHCP lease parser
│   ├── redirect/
│   │   ├── dns.go                      # DNS redirect injection
│   │   ├── http.go                     # HTTP redirect logic
│   │   └── tcp.go                      # TCP connection manipulation
│   ├── sysconfig/dns_windows.go        # Windows DNS configuration
│   └── verdict/
│       ├── verdict.go                  # TCP RST, DNS inject, IP block
│       └── html_injection.go           # HTML block page generation
├── pkg/
│   ├── blockpage/server.go             # HTTP/HTTPS block page server
│   ├── control/server.go               # gRPC control API (:50052)
│   ├── driver/wrapper.go               # High-level driver wrapper
│   ├── engine/engine.go                # Main engine (1,110 lines)
│   ├── grpc/
│   │   ├── server.go                   # gRPC streaming server (664 lines)
│   │   └── pb/                         # Protobuf generated code
│   │       ├── metadata_stream.pb.go
│   │       └── metadata_stream_grpc.pb.go
│   └── stream/broadcaster.go           # In-process pub/sub
├── configs/                            # Runtime config files
├── go.mod                              # Dependencies
└── go.sum
```

---

## Tool 3: Firewall Engine

### 3.1 Overview

The Firewall Engine is the **control plane** — the "decision brain" of SafeOps. While the SafeOps Engine intercepts packets at the kernel level (data plane), the Firewall Engine receives packet metadata via gRPC streaming and runs every packet through a sophisticated **8-stage synchronous inspection pipeline** to decide: ALLOW, DROP, BLOCK, or REDIRECT.

It is the single largest component in the entire SafeOps platform — **1,471 lines in `cmd/main.go` alone**, with **29 internal packages** handling everything from threat intelligence to GeoIP blocking to stateful connection tracking to custom rule evaluation.

### 3.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.25.5 |
| **Module Name** | `firewall_engine` |
| **Source Location** | `src/firewall_engine/` |
| **Binary Output** | `bin/firewall-engine/firewall-engine.exe` (28.7 MB) |
| **Admin Required** | **Yes** (WFP kernel integration) |
| **Key Dependencies** | `BurntSushi/toml`, `gofiber/fiber`, `rs/zerolog`, `prometheus/client_golang`, `fsnotify`, `lib/pq`, gRPC, protobuf |
| **Depends On** | `safeops-engine` (imported via `replace` directive for gRPC protobuf types) |

### 3.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| gRPC Client → SafeOps Engine | `127.0.0.1:50051` | gRPC | Receives `PacketMetadata` stream |
| gRPC Management Server | (configurable) | gRPC | Health, stats, control API |
| Web UI API + WebSocket | `:8443` | HTTP | Dashboard data + real-time packet stats |
| Prometheus Metrics | (configurable) | HTTP | `/metrics` endpoint for monitoring |
| Health Server | (configurable) | HTTP | Readiness/liveness probes |
| pprof Profiler | `:6060` | HTTP | CPU/memory/goroutine profiling |

### 3.4 The 8-Stage Pipeline

Every packet received from the SafeOps Engine goes through these stages **synchronously** — the first stage that returns a non-ALLOW verdict wins and the packet is dropped immediately:

```
┌─────────────────────────────────────────────────────────────────┐
│              SafeOps Engine (gRPC :50051)                       │
│              ↓ PacketMetadata stream                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 0: Whitelist Check                                │   │
│  │ blocklist.toml [whitelist] — IP/domain bypass           │   │
│  │ Whitelisted → skip blocking, still goes to Stage 1      │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 1: Security Monitoring (ALWAYS runs)              │   │
│  │ DDoS detection │ Rate limiting │ Port scan detection    │   │
│  │ Brute force (SSH/RDP/FTP) │ Baseline anomaly            │   │
│  │ Result: DROP (60s ban) or PASS                          │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 2: Custom Rule Engine (rules.toml)                │   │
│  │ Port/Protocol/IP/Domain/Flag matching                   │   │
│  │ Supports: DROP, ALERT, LOG actions                      │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│          (if whitelisted → jump to Stage 8)                     │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 3: Manual IP Blocklist                            │   │
│  │ blocklist.toml [ips] — admin-defined IP blocks          │   │
│  │ Checks both src and dst IP                              │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 4: GeoIP / ASN Filter                             │   │
│  │ PostgreSQL-backed IP geolocation (1.1M+ entries)        │   │
│  │ Country deny/allow list + ASN blocking                  │   │
│  │ 1-hour cache, 100K max entries                          │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 5: Threat Intel IP Lookup                         │   │
│  │ In-memory cache: 34K+ malicious IPs, VPN/anonymizer IPs│   │
│  │ Background refresh from PostgreSQL every N minutes      │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 6: Domain Filter                                  │   │
│  │ domains.txt + category patterns (categories.toml)       │   │
│  │ + threat intel domain cache (1.1M+)                     │   │
│  │ CDN-aware: CDN domains get REDIRECT only (no RST)       │   │
│  │ Auto-block: domains exceeding visit threshold           │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Stage 7 + 8: Packet Inspector & Stateful Engine         │   │
│  │ Connection tracker (1M concurrent connections)          │   │
│  │ Fast-path evaluator (gaming/VoIP bypass)                │   │
│  │ Verdict cache (configurable capacity + TTL)             │   │
│  │ States: NEW → ESTABLISHED → RELATED → CLOSING → CLOSED │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ logAndSend() — Verdict Delivery                         │   │
│  │ → gRPC verdict back to SafeOps Engine (DROP/BLOCK only) │   │
│  │ → SOC/NOC JSONL log (firewall.jsonl) with enrichment:   │   │
│  │   GeoIP, CommunityID, FlowID, Direction, TrafficType    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  WFP Engine (Windows Filtering Platform)                        │
│  Session: SafeOps_Firewall_V5 (dynamic mode)                   │
│  Dual-Engine Coordinator: SafeOps+WFP / SafeOps-only / WFP-only│
└─────────────────────────────────────────────────────────────────┘
```

### 3.5 Internal Packages (29 packages)

| Package | Purpose |
|---------|---------|
| `alerting/` | Alert manager with throttling (60s window), JSONL file writer, SOC severity levels |
| `api/` | Fiber HTTP API server for Web Dashboard + WebSocket hub for real-time streaming |
| `blocklist/` | Blocklist parsing and management (IP, domain, port lists) |
| `cache/` | Verdict cache (configurable capacity, TTL, cleanup interval) |
| `config/` | TOML config loader — `firewall.toml`, `blocklist.toml`, `geoip.toml`, `rules.toml`, `categories.toml` |
| `connection/` | Stateful connection tracker (1M concurrent, state machine: NEW→ESTABLISHED→CLOSED) |
| `domain/` | Domain filter: file-based + category + threat intel + CDN-awareness + auto-block |
| `enforcement/` | Verdict handler with fail-open mode, retry logic, metrics. Dual-engine coordinator |
| `filtering/` | Low-level packet filtering primitives |
| `geoip/` | Country/ASN checker with PostgreSQL resolver, 1-hour cache, 100K entries |
| `health/` | Health aggregator with HTTP server, memory monitor (512MB soft, 1GB hard), goroutine leak detector |
| `hotreload/` | fsnotify file watcher — hot-reloads `domains.txt`, `blocklist.toml`, `rules.toml`, `categories.toml` |
| `inspection/` | Core packet inspection primitives |
| `inspector/` | Main packet inspector with worker pool + fast-path evaluator (gaming/VoIP bypass) |
| `integration/` | gRPC client to SafeOps Engine (metadata stream + verdict send + blocklist sync) |
| `logging/` | Structured zerolog logger + SOC verdict JSONL logger with GeoIP enrichment + CommunityID |
| `metrics/` | Prometheus metrics registry and exporter |
| `nat/` | NAT translation support |
| `objects/` | Network objects: PostgreSQL GeoIP resolver, address objects |
| `platform/` | Platform-specific code (Windows service integration) |
| `rate_limiting/` | Token bucket / sliding window rate limiters |
| `rules/` | Custom rule engine: TOML-based rules with port/protocol/IP/domain/flag matching |
| `security/` | Security manager: DDoS, rate limiting, port scan, brute force detection, baseline anomaly |
| `stateful_inspection/` | Deep stateful inspection engine |
| `storage/` | Persistent storage interfaces |
| `threatintel/` | Threat intel integration: PostgreSQL DB, IP cache, domain cache, VPN IP cache, background refresher |
| `validation/` | Input validation utilities |
| `wfp/` | Windows Filtering Platform engine — kernel-level packet filtering via WFP API |
| `zone_manager/` | Network zone definitions and management |

### 3.6 Configuration Files (Hot-Reloadable)

| File | Purpose | Hot-Reload |
|------|---------|:----------:|
| `configs/firewall.toml` | Main config: engine settings, performance tuning, server addresses, database connection | No |
| `configs/blocklist.toml` | Master blocklist: IPs, domains toggle, geo toggle, threat intel toggle, whitelist, categories, CDN | ✅ Yes |
| `configs/domains.txt` | Plain-text domain blocklist (one per line) | ✅ Yes |
| `configs/rules.toml` | Custom firewall rules (port/protocol/IP/domain matching) | ✅ Yes |
| `configs/categories.toml` | Domain category patterns (adult, gambling, malware, etc.) | ✅ Yes |
| `configs/geoip.toml` | GeoIP policy: blocked countries, ASNs, deny/allow mode | No |

### 3.7 Dual-Engine Enforcement

The firewall supports two enforcement engines running simultaneously:

| Mode | Description |
|------|-------------|
| **SafeOps+WFP** (default) | Both SafeOps Engine (NDIS packet interception) AND Windows Filtering Platform working together |
| **SafeOps-Only** | Fallback if WFP fails to initialize |
| **WFP-Only** | Rare — if SafeOps Engine is not connected |

The `DualEngineCoordinator` ensures verdicts are applied consistently across both engines.

### 3.8 Verdict Logging (SOC/NOC)

Every verdict (ALLOW, DROP, BLOCK, REDIRECT) is logged to `firewall.jsonl` with rich enrichment:

| Field | Source |
|-------|--------|
| `src_ip`, `dst_ip`, `src_port`, `dst_port` | Packet metadata |
| `proto`, `flags` | Protocol + TCP flags |
| `action`, `detector`, `reason` | Pipeline stage that triggered the verdict |
| `domain`, `domain_source` | DNS/SNI/HTTP/QUIC |
| `direction` | INBOUND / OUTBOUND / INTERNAL (auto-classified) |
| `traffic_type` | EXTERNAL / INTERNAL / MIXED |
| `community_id` | Standard CommunityID v1 hash (cross-tool correlation) |
| `flow_id` | Unique flow identifier |
| `src_geo`, `dst_geo` | Country codes from GeoIP |
| `src_asn`, `dst_asn` | ASN organization names |
| `cache_ttl` | How long this verdict is cached |

### 3.9 Real-Time Monitoring

| Feature | Details |
|---------|---------|
| **Console Stats** | Every 30 seconds: packet counts, cache hits, connections, alerts, domain blocks |
| **WebSocket** | Every 2 seconds: `packet_stats` event with `total_processed` and `total_blocked` |
| **Prometheus** | Full metrics registry: counters, gauges, histograms |
| **Health Checks** | 5 checks: verdict_cache, connection_tracker, safeops_connection, wfp_engine, threat_intel_db |
| **Memory Monitor** | Soft limit: 512 MB (warn), Hard limit: 1 GB (force GC + critical alert) |
| **Goroutine Monitor** | Leak detection: warns on doubling between checks |
| **pprof** | CPU/memory/goroutine profiling at `:6060` |

### 3.10 Blocklist Sync (Firewall → SafeOps Engine)

The Firewall Engine pushes its domain blocklist to the SafeOps Engine via the Control API (`:50052`). This ensures the SafeOps Engine can do DNS redirect and SNI blocking for domains discovered by the Firewall Engine's threat intel and category systems. The sync is:
- **Initial:** On startup, all blocked domains are pushed
- **Hot-reload:** When `domains.txt` or `blocklist.toml` changes, the updated list is re-synced
- **Latency:** In-process (zero-latency via gRPC)

### 3.11 Windows Service Support

The Firewall Engine can run as a Windows Service:

| Flag | Purpose |
|------|---------|
| `-install` | Register as a Windows service |
| `-remove` | Unregister the service |
| `-service` | Run in service mode (called by SCM) |

It also auto-detects when running inside the Windows Service Control Manager.

### 3.12 Key Design Decisions

1. **Synchronous Pipeline** — The 8 stages run sequentially on each packet. The first DROP wins — no wasted checks on already-blocked traffic.
2. **Whitelist Bypass** — Whitelisted IPs skip blocking stages (3–6) but NOT security monitoring (Stage 1). This means even trusted IPs are monitored for DDoS/port scan.
3. **Hot-Reload Everything** — `domains.txt`, `blocklist.toml`, `rules.toml`, and `categories.toml` can all be changed while the engine is running. Changes take effect within seconds via fsnotify.
4. **Fail-Open** — Configurable: if the inspection pipeline errors, the packet is ALLOWED (fail-open) to avoid breaking connectivity.
5. **CDN Aware** — Domains hosted on CDNs (Cloudflare, Akamai, etc.) get DNS REDIRECT only, never TCP RST. RST-ing a CDN IP would break thousands of other websites.
6. **Atomic Blocklist** — The live blocklist config is stored in an `atomic.Pointer` — the hot-reloader swaps it atomically, so the packet handler never blocks on a mutex.
7. **Pre-Block Alert Broadcast** — Every blocked packet is broadcast to the Firewall Engine's gRPC stream BEFORE being dropped, allowing the SOC log to capture all events.

---

## Tool 4: Threat Intelligence Pipeline

### 4.1 Overview

The Threat Intelligence Pipeline is SafeOps' **OSINT feed ingestion and reputation scoring system**. It continuously fetches threat data from 7+ external sources (abuse.ch, AlienVault OTX, PhishTank, Spamhaus, Emerging Threats, Tor Exit Nodes, and custom feeds), parses it through format-specific processors, and stores the results in 6 PostgreSQL tables. The Firewall Engine then queries these tables at runtime via in-memory caches for real-time IP/domain/hash reputation lookups.

**In essence:** This is what turns SafeOps from a firewall with static rules into one that knows about the latest threats across the internet — malicious IPs, phishing domains, malware hashes, VPN/anonymizer exit nodes, and IP geolocation data.

### 4.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.23 |
| **Module Name** | `threat_intel` |
| **Source Location** | `src/threat_intel/` (79 Go files) |
| **Binary Output** | `bin/threat_intel/threat_intel.exe` |
| **Key Dependencies** | `lib/pq` (PostgreSQL), `gorilla/mux` (HTTP API), `rs/cors`, `yaml.v3` |
| **Database** | PostgreSQL `threat_intel_db` |

### 4.3 Pipeline Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                  Threat Intel Pipeline                             │
│                  (cmd/pipeline/main.go)                            │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────────────────────────────────┐         │
│  │  SCHEDULER (-scheduler flag)                        │         │
│  │  Default: every 30 min | Configurable: -interval N  │         │
│  │  Graceful shutdown via SIGINT/SIGTERM                │         │
│  └───────────────────┬─────────────────────────────────┘         │
│                      ▼                                            │
│  ┌─────────────────────────────────────────────────────┐         │
│  │  STAGE 1: FETCH                                     │         │
│  │                                                     │         │
│  │  Feed Sources (sources.yaml):                       │         │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │         │
│  │  │  abuse.ch    │ │ AlienVault   │ │ PhishTank  │  │         │
│  │  │  (malware)   │ │ OTX (IOCs)   │ │ (phishing) │  │         │
│  │  └──────────────┘ └──────────────┘ └────────────┘  │         │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │         │
│  │  │  Spamhaus    │ │  Emerging    │ │ Tor Exit   │  │         │
│  │  │  (spam IPs)  │ │  Threats     │ │ Nodes      │  │         │
│  │  └──────────────┘ └──────────────┘ └────────────┘  │         │
│  │  ┌──────────────┐                                   │         │
│  │  │ Custom Feeds │ → 5 concurrent downloads          │         │
│  │  └──────────────┘   3 retries, 60s timeout          │         │
│  │                                                     │         │
│  │  Output: data/fetch/<category>/<files>               │         │
│  └───────────────────┬─────────────────────────────────┘         │
│                      ▼                                            │
│  ┌─────────────────────────────────────────────────────┐         │
│  │  STAGE 2: PARSE + PROCESS                           │         │
│  │                                                     │         │
│  │  Format Parsers:                                    │         │
│  │  CSV │ JSON │ TXT │ TSV │ XML │ RSS │ MMDB          │         │
│  │                                                     │         │
│  │  Type Processors:                                   │         │
│  │  ┌────────────────┐ ┌────────────────┐              │         │
│  │  │ IP Geo Proc    │ │ IP Blacklist   │              │         │
│  │  │ → ip_geoloc    │ │ → ip_blacklist │              │         │
│  │  └────────────────┘ └────────────────┘              │         │
│  │  ┌────────────────┐ ┌────────────────┐              │         │
│  │  │ Domain Proc    │ │ Hash Proc      │              │         │
│  │  │ → domains      │ │ → hashes       │              │         │
│  │  └────────────────┘ └────────────────┘              │         │
│  │  ┌────────────────┐                                 │         │
│  │  │ SSL Cert Proc  │ Batch size: 1,000 rows          │         │
│  │  │ → ssl_certs    │ Feed priority-based dedup       │         │
│  │  └────────────────┘                                 │         │
│  └───────────────────┬─────────────────────────────────┘         │
│                      ▼                                            │
│  ┌─────────────────────────────────────────────────────┐         │
│  │  STAGE 3: STORE (PostgreSQL)                        │         │
│  │                                                     │         │
│  │  ┌──────────────────┐  ┌──────────────────┐         │         │
│  │  │ ip_blacklist     │  │ ip_geolocation   │         │         │
│  │  │ (34K+ IPs)       │  │ (1.1M+ entries)  │         │         │
│  │  └──────────────────┘  └──────────────────┘         │         │
│  │  ┌──────────────────┐  ┌──────────────────┐         │         │
│  │  │ domains          │  │ hashes           │         │         │
│  │  │ (1.1M+ domains)  │  │ (malware sigs)   │         │         │
│  │  └──────────────────┘  └──────────────────┘         │         │
│  │  ┌──────────────────┐  ┌──────────────────┐         │         │
│  │  │ ip_anonymization │  │ ssl_certificates │         │         │
│  │  │ (VPN/Tor IPs)    │  │ (revoked certs)  │         │         │
│  │  └──────────────────┘  └──────────────────┘         │         │
│  └─────────────────────────────────────────────────────┘         │
│                                                                   │
│  Optional: ENRICH (-enrich=path.csv)                              │
│  → Takes unknown IPs from CSV, lookups via free geo APIs,         │
│    stores in ip_geolocation table                                 │
│                                                                   │
├───────────────────────────────────────────────────────────────────┤
│  REST API (cmd/api/main.go on :8080)                              │
│  → QueryIP / QueryDomain / QueryHash / GetStatus                  │
│  → Used by Dashboard, Backend, and external tools                 │
└───────────────────────────────────────────────────────────────────┘
```

### 4.4 Entry Points (4 Binaries)

| Entry Point | Purpose |
|-------------|---------|
| `cmd/pipeline/main.go` | **Primary** — unified fetch + process + scheduler + status + enrichment |
| `cmd/fetcher/main.go` | Standalone feed fetcher |
| `cmd/processor/main.go` | Standalone data processor |
| `cmd/api/main.go` | REST API server for querying threat data |

### 4.5 CLI Reference

| Flag | Description |
|------|-------------|
| (no flags) | Run full pipeline: fetch all feeds + process all data |
| `-fetch` | Fetch only (download feeds, don't process) |
| `-process` | Process only (parse already-fetched files) |
| `-category=ip_geo,domain` | Fetch specific categories only |
| `-status` | Show database table row counts |
| `-headers` | Show table column schemas |
| `-scheduler` | Run continuously (default every 30 min) |
| `-interval=60` | Set scheduler interval in minutes |
| `-enrich=file.csv` | Enrich unknown IPs from CSV via free geo APIs |
| `-delete=true` | Delete fetched files after processing (default: true) |

### 4.6 Database Tables (6 tables in `threat_intel_db`)

| Table | Content | Typical Size |
|-------|---------|:------------:|
| `ip_blacklist` | Malicious IPs with source, threat type, confidence | 34,000+ |
| `ip_geolocation` | IP → country, city, ASN, ISP, coordinates | 1,100,000+ |
| `ip_anonymization` | VPN, Tor, proxy, anonymizer exit node IPs | Varies |
| `domains` | Malicious/phishing domains with threat category | 1,100,000+ |
| `hashes` | MD5/SHA256 malware hashes with detection info | Varies |
| `ssl_certificates` | Compromised/revoked SSL certificate fingerprints | Varies |

### 4.7 Feed Categories

| Category | Data Type | Example Sources |
|----------|-----------|-----------------|
| `ip_blacklist` | Malicious IPs | abuse.ch, Spamhaus, Emerging Threats |
| `ip_geo` | IP geolocation | MaxMind, IP2Location, free APIs |
| `ip_anonymization` | VPN/Tor/proxy IPs | Tor Project, VPN detection feeds |
| `domain` | Malicious domains | PhishTank, abuse.ch URLhaus, AlienVault |
| `hash` | Malware hashes | abuse.ch MalwareBazaar, VirusTotal |
| `ioc` | Mixed IOC feeds | AlienVault OTX (IP + domain + hash) |
| `asn` | ASN data | RIR databases |

### 4.8 Source Code Packages

**`src/` packages (31 files):**

| Package | Purpose |
|---------|---------|
| `fetcher/` | Multi-threaded HTTP/GitHub feed downloader (5 concurrent, 3 retries, rate-limited) |
| `parser/` | Format-specific parsers: CSV, JSON, TXT, TSV, XML, RSS. Includes field validator |
| `processor/` | Type-specific processors: IP geo, IP blacklist, domain, hash, SSL cert. Batch inserts (1K rows) |
| `storage/` | PostgreSQL persistence layer: 6 typed stores with UPSERT, dedup, and table info queries |
| `enrichment/` | Free API-based IP geolocation enrichment from CSV input |
| `worker/` | Background worker pool + cleanup scheduler (7-day retention) |
| `api/` | gorilla/mux REST API with CORS middleware and rate limiting |

**`internal/` packages (18 files — advanced features):**

| Package | Purpose |
|---------|---------|
| `feeds/` | Feed manager, updater, validator, and fetcher with scheduling |
| `ioc/` | IOC (Indicator of Compromise) manager: IP, domain, hash, URL matchers |
| `reputation/` | Scoring engine: IP reputation, domain reputation, confidence calculator |
| `enrichment/` | Advanced enrichment: ASN lookup, domain enricher, IP enricher, geolocation |
| `sources/` | Feed-specific adapters: abuse.ch, AlienVault OTX, PhishTank, Spamhaus, Emerging Threats, Tor, custom |
| `cache/` | IOC cache, cache warmer, Redis cache support |
| `storage/` | Database layer, feed store, IOC store |
| `metrics/` | Prometheus-compatible metrics collector, feed metrics |
| `api/` | gRPC server, advanced API handlers |

### 4.9 Fetcher Configuration (`sources.yaml`)

Each feed source is defined in YAML:

```yaml
feeds:
  - name: "abuse_ch_feodo"
    category: "ip_blacklist"
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    format: "csv"
    enabled: true
    update_frequency: 3600  # seconds
    priority: 1             # higher = more trusted (dedup resolution)
    description: "Feodo Tracker botnet C2 IPs"
```

### 4.10 Processing Pipeline Details

| Step | Component | Details |
|------|-----------|---------|
| **Fetch** | `fetcher.FetchAll()` | Downloads all enabled feeds, 5 concurrent, 100 MB max file size |
| **Parse** | `parser.<Format>` | Detects file format, routes to CSV/JSON/TXT/TSV/XML/RSS parser |
| **Validate** | `parser.Validator` | Validates IPs, domains, hashes against format rules |
| **Process** | `processor.<Type>Processor` | Routes parsed rows to type-specific PostgreSQL inserter |
| **Dedup** | Priority-based | When multiple feeds report same IOC, highest-priority feed wins |
| **Store** | `storage.<Type>Storage` | Batch UPSERT (1,000 rows per batch) with conflict resolution |
| **Cleanup** | `worker.Cleanup` | Removes entries older than 7 days (configurable) |

### 4.11 Query API Endpoints

| Endpoint | Method | Purpose |
|----------|:------:|---------|
| `/api/v1/ip/{ip}` | GET | Check IP against blacklist + geolocation + anonymization |
| `/api/v1/domain/{domain}` | GET | Check domain against malicious domain database |
| `/api/v1/hash/{hash}` | GET | Check MD5/SHA256 against malware hash database |
| `/api/v1/status` | GET | Database table row counts |
| `/api/v1/health` | GET | Pipeline health status |

### 4.12 Integration with Firewall Engine

The Threat Intelligence data flows into the Firewall Engine through two mechanisms:

1. **In-Memory Caches** — The Firewall Engine loads IP blacklist, domain blocklist, and VPN IP list from PostgreSQL into `sync.Map` caches at startup
2. **Background Refresher** — A goroutine periodically queries PostgreSQL for new entries (configurable interval)
3. **Decision Engine** — `threatintel.Decision` combines IP cache + domain cache lookups with alert generation

### 4.13 Key Design Decisions

1. **ETL Architecture** — Clean separation: Fetch → Parse → Process → Store. Each stage can run independently
2. **Feed Priority** — When the same IP/domain appears in multiple feeds, the feed with the highest `priority` value wins during dedup
3. **Batch Processing** — All database writes use 1,000-row batch inserts for performance
4. **Scheduler Mode** — `-scheduler` flag keeps the pipeline running continuously with configurable interval, ideal for production deployments
5. **Environment Overrides** — All config values can be overridden via environment variables (DB_HOST, DB_PORT, API_PORT, etc.)
6. **Enrichment Pipeline** — The `-enrich` flag allows backfilling IP geolocation data for IPs found in network logs that aren't in existing databases

---

## Tool 5: Network Logger

### 5.1 Overview

The Network Logger is SafeOps' **passive network forensics engine**. It captures live packets from all active network interfaces using `gopacket/pcap` (libpcap), processes them through a multi-stage enrichment pipeline, and writes structured JSONL logs to multiple output streams — a master packet log, IDS/IPS alerts (Suricata EVE format), NetFlow records (East-West & North-South), and per-IP traffic summaries. Unlike the SafeOps Engine which intercepts packets for blocking, the Network Logger operates in **read-only promiscuous mode** — it observes everything but blocks nothing.

**In essence:** This is the component that gives SOC analysts full visibility into what happened on the network — every connection, every DNS query, every TLS handshake — with GeoIP enrichment, process correlation, and SIEM-ready output.

### 5.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.24 |
| **Module Name** | `github.com/safeops/network_logger` |
| **Source Location** | `src/network_logger/` (29 Go files) |
| **Binary Output** | `bin/network-logger/network-logger.exe` (11.7 MB) |
| **Key Dependencies** | `google/gopacket` (pcap), `shirou/gopsutil` (process info), `lib/pq` (GeoIP from PostgreSQL), `fatih/color` (terminal output) |
| **Admin Required** | No (but promiscuous mode may need elevated privileges) |

### 5.3 Pipeline Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Network Logger                                 │
│                    (cmd/logger/main.go)                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Interface Scanner ──→ Capture Engine (gopacket/pcap)             │
│  (auto-discover)       Promiscuous, 1600-byte snap, multi-NIC    │
│                               │                                   │
│                        ┌──────▼──────┐                            │
│                        │   Packet    │                            │
│                        │  Processor  │                            │
│                        └──────┬──────┘                            │
│                               │                                   │
│            ┌──────────────────┼──────────────────┐                │
│            │                  │                  │                │
│  ┌─────────▼──────┐ ┌────────▼───────┐ ┌────────▼──────┐        │
│  │ Protocol Parse │ │  Enrichment    │ │ Deduplication │        │
│  │ ETH→IP→TCP/UDP │ │ Flow Tracker   │ │ 10K LRU cache │        │
│  │ DNS/HTTP/TLS   │ │ GeoIP (PgSQL)  │ │ 30s window    │        │
│  │                │ │ Process Corr.  │ │               │        │
│  │                │ │ TLS Decrypt    │ │               │        │
│  │                │ │ Hotspot Track  │ │               │        │
│  └────────────────┘ └────────────────┘ └───────────────┘        │
│                               │                                   │
│         ┌─────────────────────┼─────────────────────┐             │
│         │                     │                     │             │
│  ┌──────▼───────┐  ┌──────────▼──────┐  ┌──────────▼──────┐     │
│  │  Master Log  │  │   IDS/IPS Log   │  │  NetFlow BiFlow │     │
│  │  master.jsonl│  │  ids_ips.jsonl  │  │ E-W + N-S .jsonl│     │
│  │  5-min cycle │  │  EVE JSON 50MB  │  │  IPFIX 50MB     │     │
│  └──────────────┘  └─────────────────┘  └─────────────────┘     │
│                            │                                      │
│                    ┌───────▼───────────┐                          │
│                    │  IP Summary Log   │                          │
│                    │ ip_summary.jsonl  │                          │
│                    │ 5-min aggregation │                          │
│                    └──────────────────┘                           │
└──────────────────────────────────────────────────────────────────┘
```

### 5.4 Initialization Sequence

| Step | Component | Details |
|:----:|-----------|---------|
| 1 | Interface Scanner | Auto-discovers active NICs every 10 seconds |
| 2 | Stats Collector | Live statistics aggregation |
| 3 | Flow Tracker | TCP/UDP flow state machine (60s timeout, 30s cleanup) |
| 4 | Dedup Engine | Packet-level deduplication (10K cache, 30s window) |
| 5 | Process Correlator | Maps connections to OS processes via `gopsutil` (10s cache TTL) |
| 6 | Hotspot Device Tracker | Tracks devices on hotspot subnet (192.168.137.0/24) |
| 7 | TLS Key Logger | Monitors SSLKEYLOGFILE for TLS master secrets |
| 8 | TLS Decryptor | Decrypts TLS traffic using captured key material |
| 9 | GeoIP Lookup | PostgreSQL-backed IP geolocation + unknown IP tracker |
| 10 | Packet Processor | Connects all enrichment stages into a unified pipeline |
| 11 | JSON Writer | Master JSONL log with 5-min cycle, 75-record batches |
| 12 | IDS Collector | Suricata EVE JSON format, 50 MB rotation |
| 13 | BiFlow Collector | NetFlow east-west + north-south, IPFIX format, 50 MB rotation |
| 14 | IP Summary Collector | 5-minute per-IP traffic aggregation |
| 15 | Capture Engine | gopacket/pcap on all active interfaces (promiscuous mode) |

### 5.5 Output Files

| File | Format | Rotation | Purpose |
|------|--------|:--------:|---------|
| `network_packets_master.jsonl` | JSONL | 5-min overwrite cycle | Primary forensics log — every packet with full enrichment |
| `ids_ips.jsonl` | Suricata EVE JSON | 50 MB | IDS/IPS-compatible alert log for SIEM ingestion |
| `netflow/east_west.jsonl` | IPFIX JSONL | 50 MB (3 backups) | Internal LAN-to-LAN traffic flows |
| `netflow/north_south.jsonl` | IPFIX JSONL | 50 MB (3 backups) | LAN-to-Internet traffic flows |
| `ip_summary.jsonl` | JSONL | 50 MB (3 backups) | Per-IP bandwidth/connection aggregation (5-min windows) |
| `unknown_ips.csv` | CSV | Append | Public IPs not found in GeoIP database (for enrichment) |
| `sslkeys.log` | NSS Key Log | Append | TLS session keys for decryption |

### 5.6 Internal Packages

| Package | Purpose |
|---------|---------|
| `capture/` | gopacket capture engine, interface scanner, packet processor pipeline |
| `collectors/` | BiFlow (NetFlow), IDS/IPS (EVE JSON), IP summary, firewall log, device collector, log analyzer, MAC vendor DB |
| `config/` | YAML configuration with embedded defaults |
| `dedup/` | Hash-based packet deduplication engine (10K LRU cache, 30s window) |
| `flow/` | Bidirectional flow tracker with state machine (60s timeout) |
| `geoip/` | PostgreSQL-backed GeoIP lookup + unknown IP tracker for enrichment pipeline |
| `hotspot/` | Mobile hotspot device tracker (192.168.137.0/24 subnet) |
| `parser/` | Protocol parsers: Ethernet, IPv4/v6, TCP, UDP, DNS, HTTP, TLS |
| `process/` | OS process correlator — maps `srcIP:srcPort` to process name/PID via gopsutil |
| `stats/` | Live statistics collector with periodic console display |
| `tls/` | TLS key logger (SSLKEYLOGFILE monitor) + TLS session decryptor |
| `writer/` | JSON writer with batching + rotating file writer (size-based rotation) |

### 5.7 Capture Configuration

| Setting | Default | Description |
|---------|:-------:|-------------|
| `interfaces` | (all active) | Specific interfaces to capture, or auto-discover |
| `promiscuous` | `true` | Capture all packets, not just addressed to this host |
| `snapshot_length` | 1600 bytes | Max bytes per packet to capture |
| `bpf_filter` | (none) | Berkeley Packet Filter expression |
| `dedup.cache_size` | 10,000 | Max entries in deduplication cache |
| `dedup.window_seconds` | 30s | Time window for dedup matching |
| `flow.timeout_seconds` | 60s | Flow expiry timeout |
| `stats.display_interval` | 120s | Console stats display interval |
| `hotspot.subnet` | `192.168.137.0/24` | Hotspot subnet for device tracking |

### 5.8 Key Design Decisions

1. **Read-Only Observation** — The Network Logger never modifies or blocks packets. It operates in promiscuous mode as a passive observer for forensics and compliance.
2. **Multi-Collector Architecture** — A single packet processor feeds multiple output collectors simultaneously: master log, IDS alerts, NetFlow records, and IP summaries. Each collector has independent rotation and formatting.
3. **SIEM-Ready Output** — The IDS log uses Suricata EVE JSON format, directly ingestible by Elasticsearch/Splunk/Wazuh. NetFlow uses IPFIX format.
4. **Unknown IP Tracking** — Public IPs not found in the GeoIP database are logged to `unknown_ips.csv` for later enrichment via the Threat Intel pipeline's `-enrich` flag.
5. **TLS Decryption** — Monitors the SSLKEYLOGFILE for TLS master secrets, enabling decryption of HTTPS traffic for deep inspection (requires browser cooperation).
6. **Process Correlation** — Maps every connection to the owning OS process (name + PID) using `gopsutil`, linking network activity to specific applications.

---

## Tool 6: NIC Management

### 6.1 Overview

NIC Management is SafeOps' **multi-WAN orchestration and network infrastructure layer**. It is a **hybrid Go + Rust** service that provides NIC discovery & classification, NAT translation, multi-WAN failover with state machine, traffic load balancing, routing engine, and a high-performance Rust-based packet forwarding engine using WinDivert. It exposes both a gRPC service (for internal SafeOps components) and a REST API (for the dashboard).

**In essence:** This is what makes SafeOps work in complex network environments — multiple internet connections, NAT traversal, automatic failover when a WAN link goes down, and intelligent traffic distribution across links.

### 6.2 Component Information

| Property | Value |
|---|---|
| **Languages** | Go 1.24 + Rust (hybrid) |
| **Go Module** | `safeops/nic_management` |
| **Source Location** | `src/nic_management/` (86 Go+Rust source files) |
| **Key Go Deps** | `google.golang.org/grpc`, `spf13/viper`, `fsnotify`, `StackExchange/wmi`, `google/uuid` |
| **Rust Crate** | WinDivert-based packet capture + forwarding engine |
| **Native Drivers** | `WinDivert.dll` + `WinDivert64.sys` (bundled) |
| **Config** | `config.yaml` (YAML via Viper) |

### 6.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| gRPC Server | `:50056` | gRPC (TLS optional) | NIC operations, failover control, streaming metrics |
| REST API | `:8081` | HTTP | Dashboard data: connected devices, topology, NIC control, DHCP |

### 6.4 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    NIC Management Service                         │
│                    (cmd/main.go — unified entry)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────┐              │
│  │             DISCOVERY LAYER (Go)               │              │
│  │  Enumerator → Classifier → Monitor             │              │
│  │  • Platform-specific (Windows/Linux)            │              │
│  │  • Capabilities detection                       │              │
│  │  • Physical NIC detection (vs virtual)          │              │
│  │  • Continuous monitoring with event callbacks   │              │
│  └────────────────────┬───────────────────────────┘              │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────┐              │
│  │             CONFIGURATION LAYER (Go)           │              │
│  │  Interface Config │ DNS Manager │ Gateway Mgr  │              │
│  │  MTU Manager │ DHCP Integration                │              │
│  └────────────────────┬───────────────────────────┘              │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────┐              │
│  │             NAT LAYER (Go)                     │              │
│  │  Port Allocator → Mapping Table → Session Track│              │
│  │  Cleanup Manager (periodic session expiry)     │              │
│  └────────────────────┬───────────────────────────┘              │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────┐              │
│  │             FAILOVER LAYER (Go)                │              │
│  │  WAN Monitor → State Machine → Failover Handler│              │
│  │  Recovery Manager (auto-recovery after failure) │              │
│  └────────────────────┬───────────────────────────┘              │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────┐              │
│  │    LOAD BALANCER + ROUTER (Go)                 │              │
│  │  Traffic distributor │ WAN selector            │              │
│  │  Routing engine │ Comprehensive metrics        │              │
│  └────────────────────┬───────────────────────────┘              │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────┐              │
│  │    PACKET ENGINE + DRIVER (Rust + Go)          │              │
│  │  WinDivert packet capture (Rust)               │              │
│  │  NDIS interface │ WinPcap wrapper (Go)         │              │
│  │  IP Helper API │ WMI queries (Go)              │              │
│  │  Rust↔Go bridge via FFI                        │              │
│  └────────────────────────────────────────────────┘              │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────────────┐              │
│  │  gRPC Server     │  │  REST API (:8081)        │              │
│  │  (:50056)        │  │  NIC Control │ Topology  │              │
│  │  + TLS support   │  │  DHCP │ Connected Devices│              │
│  │  + Streaming     │  │  NIC Monitor             │              │
│  └──────────────────┘  └──────────────────────────┘              │
│                                                                   │
│  ┌────────────────────────────────────────────────┐              │
│  │  INTEGRATION HOOKS                             │              │
│  │  Firewall │ IDS │ Logger │ QoS │ Event Publisher│              │
│  └────────────────────────────────────────────────┘              │
└──────────────────────────────────────────────────────────────────┘
```

### 6.5 Internal Packages (14 Go packages + 4 Rust modules)

**Go Packages:**

| Package | Purpose |
|---------|---------|
| `discovery/` | NIC enumeration (Windows via WMI, Linux via /sys), classifier (physical/virtual/loopback), capabilities detection, continuous monitor |
| `configuration/` | Interface config, DNS manager, gateway manager, MTU manager, DHCP integration |
| `nat/` | Port allocator, NAT mapping table, session tracker, cleanup manager |
| `failover/` | WAN monitor, state machine (UP→DEGRADED→FAILOVER→RECOVERING), failover handler, recovery manager |
| `loadbalancer/` | Traffic distributor, WAN selector (weighted round-robin), comprehensive metrics |
| `router/` | Routing engine — policy-based routing, route table management |
| `packet_engine/` | High-performance packet processing pipeline |
| `driver/` | Low-level drivers: IP Helper API wrapper, NDIS interface, WinPcap wrapper, WMI queries |
| `performance/` | Performance monitoring and optimization |
| `grpc/` | gRPC server with handlers + streaming handlers (real-time NIC events) |
| `integration/` | Hooks into other SafeOps components: firewall, IDS, logger, QoS, event publisher |
| `rust_bridge/` | Go↔Rust FFI bridge for WinDivert packet engine |

**Rust Modules (via Cargo):**

| Module | Purpose |
|--------|---------|
| `capture/` | WinDivert-based packet capture engine |
| `config/` | Rust-side configuration |
| `integration/` | Rust-side integration interfaces |
| `errors.rs` | Custom error types for Rust layer |

### 6.6 REST API Endpoints

| Endpoint Group | File | Purpose |
|----------------|------|---------|
| NIC API | `api/nic_api.go` | List/get/configure network interfaces |
| NIC Control | `api/nic_control.go` | Enable/disable/restart interfaces |
| NIC Monitor | `api/nic_monitor.go` | Real-time NIC status and bandwidth |
| Topology | `api/topology.go` | Network topology visualization data |
| Connected Devices | `api/connected_devices.go` | List LAN devices with MAC, IP, hostname |
| DHCP API | `api/dhcp_api.go` | DHCP lease management and configuration |

### 6.7 Failover State Machine

```
     ┌──────────┐
     │    UP     │ ← All WANs healthy
     └────┬─────┘
          │ WAN degradation detected
     ┌────▼─────┐
     │ DEGRADED │ ← Some WANs failing, traffic redistributed
     └────┬─────┘
          │ Primary WAN down
     ┌────▼─────────┐
     │  FAILOVER    │ ← Traffic moved to backup WAN(s)
     └────┬─────────┘
          │ Primary WAN recovering
     ┌────▼─────────┐
     │ RECOVERING   │ ← Testing primary, gradual traffic return
     └────┬─────────┘
          │ Primary healthy
     ┌────▼─────┐
     │    UP     │ ← Full recovery
     └──────────┘
```

### 6.8 CLI Flags

| Flag | Default | Purpose |
|------|:-------:|---------|
| `-config` | `/etc/safeops/nic_management.yaml` | Config file path |
| `-api-port` | `8081` | REST API port |
| `-grpc-port` | `50056` | gRPC server port |
| `-version` | — | Print version info |
| `-install-service` | — | Install as Windows service |

### 6.9 Key Design Decisions

1. **Hybrid Go + Rust** — Go handles orchestration, configuration, and APIs. Rust handles the performance-critical packet forwarding path via WinDivert for zero-copy kernel-level operations.
2. **Platform Abstraction** — Discovery has separate `enumerator_windows.go` and `enumerator_linux.go` with the same interface, allowing cross-platform deployment.
3. **State Machine Failover** — The failover system uses a formal state machine (UP → DEGRADED → FAILOVER → RECOVERING → UP) with automatic recovery, avoiding manual intervention.
4. **NAT Session Tracking** — Full NAT implementation with port allocation, bidirectional mapping tables, session state tracking, and automatic cleanup of expired sessions.
5. **3-Phase Graceful Shutdown** — (1) Stop accepting new connections, (2) stop background workers, (3) cleanup sessions/mappings — with a 30-second timeout.
6. **Integration Hooks** — Dedicated hook interfaces for firewall, IDS, logger, and QoS — allowing other SafeOps components to react to NIC state changes.

---

## Tool 7: DHCP Monitor

### 7.1 Overview

The DHCP Monitor is SafeOps' **real-time device discovery and trust management system**. It detects every device that connects to the network by continuously polling the ARP table and Windows DHCP event logs, enriches the device data with hostname, vendor (MAC OUI), and fingerprint information, and classifies each device with a trust status (TRUSTED / UNTRUSTED / BLOCKED). This feeds directly into the Captive Portal — untrusted devices are redirected to the onboarding page.

**In essence:** This is how SafeOps knows "who is on the network right now" — every laptop, phone, IoT device, and printer is tracked with MAC, IP, hostname, vendor, and trust level.

### 7.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.24 |
| **Module Name** | `dhcp_monitor` |
| **Source Location** | `src/dhcp_monitor/` (25 Go files + protobuf) |
| **Version** | 2.0.0 |
| **Key Dependencies** | `google.golang.org/grpc`, `google.golang.org/protobuf`, `lib/pq` (PostgreSQL), `golang.org/x/net` (mDNS), `golang.org/x/sys` |
| **Database** | PostgreSQL `safeops` (shared database) |

### 7.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| gRPC Server | `:50055` | gRPC | Device queries, trust management, event streaming |
| mDNS Responder | `:5353` | mDNS/UDP | Responds to `safeops-portal.local` queries |

### 7.4 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    DHCP Monitor Service v2.0                      │
│                    (cmd/dhcp_monitor/main.go)                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  DETECTION LAYER (watcher/)                        │          │
│  │                                                    │          │
│  │  ┌─────────────────┐   ┌───────────────────┐      │          │
│  │  │  ARP Monitor    │   │  DHCP Enricher    │      │          │
│  │  │  30s polling    │   │  Windows Event Log│      │          │
│  │  │  Dedup cache    │   │  30s polling      │      │          │
│  │  │  (1000 entries) │   │  Hostname extract │      │          │
│  │  └───────┬─────────┘   └─────────┬─────────┘      │          │
│  │          │                       │                 │          │
│  │          └───────────┬───────────┘                 │          │
│  │                      ▼                             │          │
│  │            ┌──────────────────┐                    │          │
│  │            │  Event Channel   │                    │          │
│  │            │ (buffered: 1000) │                    │          │
│  │            └────────┬─────────┘                    │          │
│  └─────────────────────┼──────────────────────────────┘          │
│                        ▼                                          │
│  ┌────────────────────────────────────────────────────┐          │
│  │  MANAGEMENT LAYER (manager/)                       │          │
│  │                                                    │          │
│  │  ┌────────────────────┐  ┌──────────────────────┐ │          │
│  │  │  Device Manager    │  │ Unknown Device Handler│ │          │
│  │  │  Trust assignment  │  │ Auto-create as        │ │          │
│  │  │  Status tracking   │  │ UNTRUSTED             │ │          │
│  │  │  Cleanup (1h cycle)│  │                       │ │          │
│  │  └────────────────────┘  └──────────────────────┘ │          │
│  │  ┌────────────────────┐                           │          │
│  │  │ Fingerprint Enricher│                          │          │
│  │  │ MAC OUI → Vendor    │                          │          │
│  │  │ OS fingerprinting   │                          │          │
│  │  └────────────────────┘                           │          │
│  └────────────────────┬───────────────────────────────┘          │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────────┐          │
│  │  PERSISTENCE LAYER (database/)                     │          │
│  │  PostgreSQL: devices, trust_status, events         │          │
│  │  Connection pool: 2-10 connections                 │          │
│  │  Auto-migration + schema validation                │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────────────┐              │
│  │  gRPC Server     │  │  mDNS Responder          │              │
│  │  (:50055)        │  │  safeops-portal.local     │              │
│  │  Device CRUD     │  │  Multicast on all NICs    │              │
│  │  Trust mgmt      │  │                          │              │
│  └──────────────────┘  └──────────────────────────┘              │
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  PLATFORM LAYER (platform/)                        │          │
│  │  Windows API calls │ Device info collector │ mDNS  │          │
│  └────────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

### 7.5 Internal Packages

| Package | Purpose |
|---------|---------|
| `watcher/` | ARP monitor (30s polling, dedup cache), DHCP enricher (Windows Event Log), ARP table parser, IP change notifier, network event types |
| `manager/` | Device manager (lifecycle + cleanup), unknown device handler (auto-create as UNTRUSTED), fingerprint enricher (MAC OUI → vendor) |
| `database/` | PostgreSQL client with connection pooling, auto-migrations, device/trust CRUD queries, schema models |
| `config/` | YAML configuration with validation and hardcoded defaults |
| `grpc/` | gRPC server with protobuf-defined API for device queries and trust management |
| `platform/` | Windows API integration, device info collector, mDNS responder (`safeops-portal.local`) |

### 7.6 Device Trust Model

| Trust Status | Meaning | Captive Portal |
|:------------:|---------|:--------------:|
| **UNTRUSTED** | New/unknown device (default for auto-created) | ✅ Redirected to onboarding |
| **TRUSTED** | Admin-approved device | ❌ Full network access |
| **BLOCKED** | Explicitly denied device | 🚫 No network access |

### 7.7 Device Lifecycle

```
Device connects to network
        │
    ARP table poll detects new MAC+IP
        │
    Dedup check (1000-entry, 5-min cache)
        │  (new device)
    Event → Event Channel (buffered: 1000)
        │
    Device Manager receives event
        │
    ┌───▼───────────────────────┐
    │ Unknown Device Handler    │
    │ Auto-create in DB         │
    │ Trust: UNTRUSTED          │
    │ Type: "unknown"           │
    └───┬───────────────────────┘
        │
    ┌───▼───────────────────────┐
    │ Fingerprint Enricher      │
    │ MAC OUI → Vendor name     │
    │ DHCP hostname extraction  │
    └───┬───────────────────────┘
        │
    Device stored in PostgreSQL
        │
    Status lifecycle:
    ACTIVE → INACTIVE (10 min) → EXPIRED (24h) → PURGED (30 days)
```

### 7.8 CLI Flags

| Flag | Default | Purpose |
|------|:-------:|---------|
| `-config` | `config/dhcp_monitor.yaml` | Config file path |
| `-validate` | — | Validate config and exit |
| `-version` | — | Print version info |
| `-migrate-only` | — | Run DB migrations and exit |

### 7.9 Configuration Defaults

| Setting | Default | Description |
|---------|:-------:|-------------|
| ARP poll interval | 30s | How often to scan the ARP table |
| Dedup cache | 1000 entries, 5 min | Prevent duplicate events for same device |
| Inactive timeout | 10 min | Mark device as INACTIVE after no ARP activity |
| Expired timeout | 24 hours | Mark device as EXPIRED |
| Purge expired | 30 days | Delete expired devices from DB |
| Cleanup cycle | 1 hour | How often to run the cleanup worker |
| DB pool | 2-10 connections | PostgreSQL connection pool |
| gRPC keepalive | 30s ping, 10s timeout | Connection health monitoring |

### 7.10 Key Design Decisions

1. **ARP-First Detection** — Uses ARP table polling as the primary detection method (works without DHCP server access), with DHCP Event Log as an enrichment source for hostname resolution.
2. **Event Channel Pattern** — A buffered channel (1000 entries) decouples detection (watchers) from processing (device manager), preventing slow DB writes from blocking fast ARP scans.
3. **Untrusted by Default** — New devices are automatically created as UNTRUSTED, following zero-trust principles. Admin must explicitly approve devices.
4. **mDNS Integration** — Responds to `safeops-portal.local` mDNS queries on all interfaces, enabling the Captive Portal redirect without DNS manipulation.
5. **Panic Recovery** — The entire main loop is wrapped in `runWithPanicRecovery()` to prevent crashes from killing the device tracking service.
6. **Exponential Backoff** — Database connection retries use exponential backoff (2s → 4s → 8s) to handle PostgreSQL startup delays.

---

## Tool 8: Captive Portal

### 8.1 Overview

The Captive Portal is SafeOps' **zero-trust device onboarding and CA certificate distribution server**. When a new (UNTRUSTED) device connects to the network, it is redirected to this portal where it can download and install the SafeOps Root CA certificate, after which the device is marked as TRUSTED. This is the user-facing entry point to the SafeOps trust chain — without the CA cert installed, the TLS Proxy cannot perform transparent HTTPS inspection.

**In essence:** This is the "Welcome to SafeOps" page that every new device sees. Download the cert, install it, and you're trusted. Skip it, and you get limited access.

### 8.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.24 |
| **Module Name** | `captive_portal` |
| **Source Location** | `src/captive_portal/` (10 Go files + protobuf) |
| **Version** | 1.0.0 |
| **Key Dependencies** | `google.golang.org/grpc` (DHCP Monitor client), `google.golang.org/protobuf`, `yaml.v3` |
| **Depends On** | DHCP Monitor (gRPC :50055), Step-CA (HTTPS), TLS Proxy (cert source) |

### 8.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| HTTP Server | configurable | HTTP | Portal pages (non-TLS fallback) |
| HTTPS Server | configurable | HTTPS | Portal pages (TLS) |

### 8.4 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Captive Portal v1.0                            │
│                    (cmd/captive_portal/main.go)                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  New device on network                                           │
│        │                                                          │
│  DNS redirect (SafeOps Engine) or mDNS (safeops-portal.local)    │
│        │                                                          │
│  ┌─────▼──────────────────────────────────────────────────┐      │
│  │  HTTP Server (handlers.go)                             │      │
│  │                                                        │      │
│  │  PAGES:                                                │      │
│  │  GET  /            → Welcome page (template rendered)  │      │
│  │                      Shows: device IP, MAC, vendor,    │      │
│  │                      trust status, detected OS         │      │
│  │  GET  /success     → Certificate installed successfully│      │
│  │  GET  /error       → Error page with details           │      │
│  │                                                        │      │
│  │  API:                                                  │      │
│  │  GET  /api/download-ca/{format}                        │      │
│  │       → PEM (desktop default)                          │      │
│  │       → CRT/DER (mobile auto-detect)                   │      │
│  │       → P12/PKCS12                                     │      │
│  │       Source: TLS Proxy cert → Step-CA fallback        │      │
│  │                                                        │      │
│  │  GET  /api/verify-trust  → Check device trust status   │      │
│  │  POST /api/mark-trusted  → Mark device as TRUSTED      │      │
│  │  POST /api/skip           → Allow-once without cert    │      │
│  │  GET  /health             → Health + dependency status  │      │
│  │  GET  /static/*           → CSS, JS static assets      │      │
│  └────────────┬───────────────────────────────────────────┘      │
│               │                                                   │
│       ┌───────┼──────────────────────┐                            │
│       ▼                              ▼                            │
│  ┌──────────────┐           ┌────────────────┐                   │
│  │ DHCP Monitor │           │   Step-CA /    │                   │
│  │ (gRPC:50055) │           │   TLS Proxy    │                   │
│  │              │           │                │                   │
│  │ GetDeviceByIP│           │ Root CA cert   │                   │
│  │ MarkTrusted  │           │ PEM/DER/P12    │                   │
│  │ MarkCAInstall│           │ Health check   │                   │
│  └──────────────┘           └────────────────┘                   │
│                                                                   │
│  ┌──────────────────────────────────────────┐                    │
│  │  OS Detector                             │                    │
│  │  User-Agent → Windows/macOS/Linux/       │                    │
│  │  Android/iOS/ChromeOS detection          │                    │
│  │  → OS-specific install instructions      │                    │
│  └──────────────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
```

### 8.5 Internal Packages

| Package | Purpose |
|---------|---------|
| `server/` | HTTP server (HTTP + HTTPS dual mode), request handlers, OS detection from User-Agent |
| `config/` | YAML configuration with portal title, welcome message, CA cert name, template/static paths |
| `database/` | DHCP Monitor gRPC client — device lookup by IP, mark trusted, mark CA cert installed |
| `stepca/` | Step-CA HTTP client — fetch CA root certificate in multiple formats, health check |

### 8.6 HTTP Endpoints

| Path | Method | Purpose |
|------|:------:|---------|
| `/` | GET | Welcome page — shows device info, OS-specific install instructions |
| `/success` | GET | Success page after certificate installation |
| `/error` | GET | Error page with code, title, message from query params |
| `/api/download-ca/{format}` | GET | Download CA cert (pem/crt/der/p12) — auto-detects mobile |
| `/api/verify-trust` | GET | JSON response: is this IP's device trusted? |
| `/api/mark-trusted` | POST | Mark calling device as TRUSTED in DHCP Monitor |
| `/api/skip` | POST | Allow-once: grant internet without cert (ALLOW_ONCE policy) |
| `/health` | GET | Health status + Step-CA and DHCP Monitor dependency checks |
| `/static/*` | GET | CSS and JavaScript static assets |

### 8.7 Certificate Download Flow

```
User clicks "Download Certificate"
        │
        ▼
OS Auto-Detection (User-Agent)
├── Android/iOS/Mobile → .crt (DER, application/x-x509-ca-cert)
└── Desktop (default)  → .pem (application/x-pem-file)
        │
        ▼
Certificate Source Priority:
1. TLS Proxy generated root CA (D:/SafeOpsFV2/src/tls_proxy/certs/)
2. Step-CA client (HTTPS fallback)
        │
        ▼
Background: MarkCACertInstalled(clientIP) via DHCP Monitor gRPC
        │
        ▼
Device now has CA cert → can trust TLS Proxy → HTTPS inspection works
```

### 8.8 Key Design Decisions

1. **Mobile Auto-Detection** — The certificate download endpoint detects mobile User-Agents (Android/iOS) and automatically serves `.crt` (DER format) instead of `.pem`, because mobile OS certificate installers require the binary DER format.
2. **Dual Certificate Source** — First tries to read the Root CA from the TLS Proxy's local cert file (zero-latency), falls back to Step-CA's HTTP API if unavailable.
3. **DHCP Monitor Integration** — Every welcome page load queries the DHCP Monitor via gRPC to show the device's current trust status, MAC address, vendor, and device type.
4. **Skip Option** — The `/api/skip` endpoint implements ALLOW_ONCE policy — devices can browse without installing the cert, but HTTPS traffic won't be inspectable.
5. **OS-Specific Instructions** — The welcome page detects the client OS and shows platform-specific certificate installation instructions (Windows → certutil, macOS → Keychain, Android → Settings, iOS → Profile).
6. **Background Trust Update** — After a cert download, the trust status update to DHCP Monitor happens in a background goroutine to avoid blocking the HTTP response.

---

## Tool 9: SIEM Forwarder

### 9.1 Overview

The SIEM Forwarder is SafeOps' **log shipping pipeline to Elasticsearch**. It continuously tails multiple JSONL log files produced by other SafeOps components (firewall verdicts, IDS/IPS alerts, NetFlow records), buffers them, adds metadata (`@timestamp`, `log_type`, `source_file`), and bulk-indexes them into date-suffixed Elasticsearch indices. It also manages index retention by automatically deleting indices older than a configurable number of days.

**In essence:** This is a lightweight, purpose-built Filebeat alternative — it gets all SafeOps logs into Elasticsearch/Kibana for SOC analysts to search, visualize, and alert on.

### 9.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.23 |
| **Module Name** | `github.com/safeops/siem-forwarder` |
| **Source Location** | `src/siem-forwarder/` (6 Go files) |
| **Key Dependencies** | `yaml.v3` (zero external deps — pure stdlib HTTP for ES) |
| **Elasticsearch** | Multi-host with basic auth, Bulk API (`/_bulk`) |
| **Config** | `configs/config.yaml` |

### 9.3 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SIEM Forwarder                                  │
│                    (cmd/forwarder/main.go)                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  TAILER LAYER                                      │          │
│  │                                                    │          │
│  │  ┌───────────────┐  ┌───────────────┐             │          │
│  │  │ Tailer #1     │  │ Tailer #2     │  ...        │          │
│  │  │ firewall.jsonl│  │ ids_ips.jsonl │             │          │
│  │  │ → safeops-fw  │  │ → safeops-ids │             │          │
│  │  │ poll: 500ms   │  │ poll: 500ms   │             │          │
│  │  └───────┬───────┘  └───────┬───────┘             │          │
│  │          │                  │                      │          │
│  │          └────────┬─────────┘                      │          │
│  │                   ▼                                │          │
│  │          ┌────────────────┐                        │          │
│  │          │ Log Channel    │                        │          │
│  │          │ (buffered:1000)│                        │          │
│  │          └───────┬────────┘                        │          │
│  └──────────────────┼─────────────────────────────────┘          │
│                     ▼                                             │
│  ┌────────────────────────────────────────────────────┐          │
│  │  SHIPPER                                           │          │
│  │                                                    │          │
│  │  Buffer (500 docs) ──→ Elasticsearch /_bulk API    │          │
│  │  Flush timer (5s)      application/x-ndjson        │          │
│  │                        Date-suffixed indices        │          │
│  │                        Multi-host failover          │          │
│  │                        Basic auth support           │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────┐  ┌──────────────────────────────┐              │
│  │ Position DB  │  │ Retention Manager             │              │
│  │ Track offsets │  │ Delete indices > N days old   │              │
│  │ Auto-save 10s│  │ Check every 6 hours           │              │
│  └──────────────┘  └──────────────────────────────┘              │
└──────────────────────────────────────────────────────────────────┘
```

### 9.4 Internal Packages

| Package | Purpose |
|---------|---------|
| `config/` | YAML configuration: ES hosts, log files, retention policy, tailer settings |
| `tailer/` | File tailer (poll-based, 500ms interval), position database (offset tracking with auto-save) |
| `shipper/` | Elasticsearch Bulk API shipper with buffered batching, retention manager for index lifecycle |

### 9.5 Data Flow

```
SafeOps Log Files (JSONL)
├── logs/firewall_verdicts.jsonl     → index: safeops-fw-YYYY.MM.DD
├── logs/ids_ips.jsonl               → index: safeops-ids-YYYY.MM.DD
├── logs/netflow/east_west.jsonl     → index: safeops-netflow-ew-YYYY.MM.DD
└── logs/netflow/north_south.jsonl   → index: safeops-netflow-ns-YYYY.MM.DD
        │
        ▼
Tailer (reads new lines from last saved position)
        │
        ▼
Log Channel (buffered: 1000 entries)
        │
        ▼
Shipper (batches 500 docs OR 5-second flush timer)
        │
  Add metadata: @timestamp, log_type, source_file, forwarded_at
        │
        ▼
Elasticsearch /_bulk API (NDJSON, multi-host, basic auth)
        │
  Index: {index_prefix}-{YYYY.MM.DD}
```

### 9.6 Timestamp Extraction

The shipper intelligently extracts the original event timestamp from each log type:

| Log Type | Timestamp Fields (priority order) |
|----------|-----------------------------------|
| `firewall` | `ts` → `timestamp` → `timestamp_ist` |
| `ids` | `ts` → `timestamp` → `timestamp_ist` |
| `netflow_eastwest` | `timestamp` → `ts` → `flow_end` → `@timestamp` |
| `netflow_northsouth` | `timestamp` → `ts` → `flow_end` → `@timestamp` |
| (unknown) | `timestamp` → `timestamp_ist` → `@timestamp` → `time` → `datetime` |

### 9.7 Configuration Defaults

| Setting | Default | Description |
|---------|:-------:|-------------|
| `elasticsearch.bulk_size` | 500 | Documents per Bulk API request |
| `elasticsearch.flush_interval` | 5s | Max time before flushing buffer |
| `tailer.poll_interval` | 500ms | How often to check for new log lines |
| `tailer.max_line_size` | 1 MB | Maximum single log line size |
| `position_db.save_interval` | 10s | How often to persist file offsets |
| `retention.max_days` | 14 | Delete ES indices older than this |
| `retention.check_interval` | 6h | How often to run retention cleanup |

### 9.8 Key Design Decisions

1. **Zero External Dependencies** — Uses only `net/http` from the Go stdlib to communicate with Elasticsearch's Bulk API. No official ES client library needed, keeping the binary tiny and avoiding dependency bloat.
2. **Position Tracking** — A position database persists each tailer's file offset to disk every 10 seconds, enabling crash recovery without re-shipping data.
3. **Startup Health Gate** — Blocks until at least one Elasticsearch host responds healthy (`/_cluster/health`), with backoff (2s → 5s → 10s), preventing data loss from shipping to a downed cluster.
4. **Date-Suffixed Indices** — Each log type gets a daily index (`safeops-fw-2026.03.25`), enabling time-based retention and efficient Kibana date range queries.
5. **Graceful Drain** — On shutdown, the shipper drains the input channel completely and flushes the remaining buffer before exiting, guaranteeing no data loss.
6. **Multi-Host Failover** — The shipper tries each configured Elasticsearch host in sequence, continuing to the next if one fails.

---

## Tool 10: Step-CA (Internal PKI)

### 10.1 Overview

Step-CA is SafeOps' **internal Public Key Infrastructure (PKI) certificate authority**. It wraps the open-source [Smallstep `step-ca`](https://smallstep.com/docs/step-ca/) binary with SafeOps-specific management scripts, configuration, and PostgreSQL-based password storage. It issues TLS certificates for internal services and provides the Root CA certificate that the Captive Portal distributes to devices for HTTPS inspection trust.

**In essence:** This is the trust anchor of the entire SafeOps system. Every TLS certificate used internally (TLS Proxy interception, gRPC mTLS, service-to-service) traces back to this CA's root certificate.

### 10.2 Component Information

| Property | Value |
|---|---|
| **Type** | Wrapper around Smallstep `step-ca` binary |
| **Source Location** | `src/step-ca/` (7 PowerShell scripts + config) |
| **Binary** | `bin/step-ca.exe` + `bin/step.exe` (Smallstep open-source) |
| **Listen Address** | `:9000` (HTTPS) |
| **Database** | BadgerV2 (embedded key-value store for cert state) |
| **Password Storage** | PostgreSQL `safeops_network.secrets` table |
| **Key Algorithm** | EC P-256 (ECDSA with ES256) |

### 10.3 Service Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|:----:|----------|---------|
| CA API | `:9000` | HTTPS | Certificate issuance, health, root CA download |
| `/health` | `:9000` | HTTPS | Health status (`{"status": "ok"}`) |
| `/roots.pem` | `:9000` | HTTPS | Root CA certificate download (PEM) |

### 10.4 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Step-CA PKI                                     │
│                    (Smallstep step-ca binary)                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  Certificate Chain                                 │          │
│  │                                                    │          │
│  │  ┌──────────────────┐                              │          │
│  │  │  Root CA          │  root_ca.crt (self-signed)  │          │
│  │  │  "SafeOps Root CA"│  EC P-256 / ES256           │          │
│  │  └────────┬─────────┘                              │          │
│  │           │ signs                                   │          │
│  │  ┌────────▼─────────┐                              │          │
│  │  │  Intermediate CA  │  intermediate_ca.crt        │          │
│  │  │  (signing CA)     │  intermediate_ca_key        │          │
│  │  └────────┬─────────┘                              │          │
│  │           │ issues                                  │          │
│  │  ┌────────▼─────────┐                              │          │
│  │  │  Leaf Certs       │  TLS Proxy, gRPC services   │          │
│  │  │  (per-service)    │                              │          │
│  │  └──────────────────┘                              │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  Configuration (config/ca.json)                    │          │
│  │                                                    │          │
│  │  DNS Names: localhost, safeops-ca.local,            │          │
│  │             192.168.137.1, 127.0.0.1               │          │
│  │  Provisioner: "safeops-admin" (JWK, EC P-256)      │          │
│  │  TLS: 1.2-1.3, ChaCha20-Poly1305 + AES-128-GCM   │          │
│  │  DB: BadgerV2 (embedded key-value)                 │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  Certificate Distribution                          │          │
│  │                                                    │          │
│  │  src/CA Cert/root_ca.crt  (PEM format)             │          │
│  │  src/CA Cert/root_ca.der  (DER for mobile)         │          │
│  │  src/CA Cert/root_ca.p12  (PKCS#12 bundle)         │          │
│  │       ↓                                            │          │
│  │  Captive Portal serves these to new devices        │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  Password Management                              │          │
│  │  PostgreSQL safeops_network.secrets                │          │
│  │  service_name = 'step-ca-master'                   │          │
│  │  Retrieved at startup → temp file → deleted after  │          │
│  └────────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

### 10.5 Management Scripts (PowerShell)

| Script | Purpose |
|--------|---------|
| `start-stepca.ps1` | Retrieves password from PostgreSQL, starts `step-ca.exe`, cleans up temp password file |
| `stop-stepca.ps1` | Gracefully stops the step-ca process |
| `restart-stepca.ps1` | Stop + start sequence |
| `reinit-stepca.ps1` | Backs up existing certs/keys, deletes old DB, re-initializes CA with fresh keys |
| `get-password.ps1` | Queries PostgreSQL `secrets` table for CA master password, outputs to temp file |
| `health-check.ps1` | 6-point health check: process, API /health, root CA download, DB password, cert files, scripts |
| `backup-stepca.ps1` | Backs up certs, keys, config, and DB to timestamped directory |

### 10.6 TLS Configuration

| Setting | Value |
|---------|-------|
| **Min TLS Version** | 1.2 |
| **Max TLS Version** | 1.3 |
| **Cipher Suites** | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` |
| **Renegotiation** | Disabled |
| **Key Algorithm** | EC P-256 (ECDSA ES256) |

### 10.7 Health Check Points

The `health-check.ps1` script validates 6 critical checks:

| # | Check | Method |
|:-:|-------|--------|
| 1 | Process running | `Get-Process -Name "step-ca"` |
| 2 | API health | `GET https://localhost:9000/health` → `{"status": "ok"}` |
| 3 | Root CA downloadable | `GET https://localhost:9000/roots.pem` → PEM content |
| 4 | DB password stored | PostgreSQL query: `SELECT COUNT(*) FROM secrets WHERE service_name = 'step-ca-master'` |
| 5 | Certificate files present | Checks root_ca.crt, intermediate_ca.crt, PEM/DER/P12 distribution copies |
| 6 | Management scripts present | Verifies all 5 core scripts exist |

### 10.8 Key Design Decisions

1. **Smallstep Wrapper** — Instead of building a custom CA, SafeOps wraps the battle-tested Smallstep `step-ca` with operational scripts, leveraging its ACME protocol support, JWK provisioners, and automatic certificate renewal.
2. **PostgreSQL Password Storage** — The CA master password is stored in the `safeops_network.secrets` table, not on the filesystem. Scripts retrieve it at startup and immediately delete the temp file after use.
3. **Three Certificate Formats** — The Root CA is distributed in PEM (desktop), DER (Android/iOS), and PKCS#12 (enterprise) formats via the `src/CA Cert/` directory, consumed by the Captive Portal.
4. **Backup Before Reinit** — The `reinit-stepca.ps1` script creates a timestamped backup of all certs, keys, config, and database before destroying and recreating the CA — enabling rollback.
5. **Embedded BadgerV2 Database** — Uses BadgerV2 (Go embedded key-value store) for certificate state tracking rather than PostgreSQL, keeping the CA's cert issuance path fast and self-contained.
6. **Hardened TLS** — Only allows ECDHE+ECDSA cipher suites with modern algorithms (ChaCha20, AES-128-GCM), no RSA fallback, no renegotiation.

---

## Tool 11: Requirements Setup

### 11.1 Overview

The Requirements Setup is SafeOps' **one-click environment bootstrapper**. It is a self-contained Go binary with 23 SQL schema files embedded via `go:embed` that performs a complete 11-step installation: downloading and silently installing PostgreSQL 16.1, creating 3 databases with full schema pipelines (threat intel, network, DHCP), setting up users and permissions, installing Node.js 20.11.0, and deploying the WinPkFilter kernel driver. It also provides database-only modes (`--db-init` / `--db-reset`) for safe re-initialization without reinstalling system dependencies.

**In essence:** Run this once on a fresh Windows machine, and all SafeOps prerequisites are installed, configured, and seeded — databases, schemas, users, permissions, runtime dependencies, and kernel drivers.

### 11.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.24 |
| **Module Name** | `github.com/safeops/requirements_setup` |
| **Source Location** | `src/requirements_setup/` (2 Go files + 23 embedded SQL) |
| **Binary Output** | `bin/safeops-requirements-setup.exe` |
| **Key Dependencies** | `yaml.v3`, `go:embed` (all SQL schemas compiled into binary) |
| **Config** | `config.yaml` (7,114 bytes) |

### 11.3 Installation Pipeline (11 Steps)

```
┌──────────────────────────────────────────────────────────────────┐
│                Requirements Setup v1.0                            │
│                (main.go — 888 lines)                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  [STEP  1/11] Install PostgreSQL 16.1                            │
│               Silent install via EDB installer                    │
│               --mode unattended --enable-components server,cli    │
│                                                                   │
│  [STEP  2/11] Start PostgreSQL Service                           │
│               net start postgresql-x64-16                        │
│                                                                   │
│  [STEP  3/11] Create Databases                                   │
│               threat_intel_db, safeops_network, safeops           │
│                                                                   │
│  [STEP  4/11] Create Database Users                              │
│               safeops, threat_intel_app, dhcp_server, dns_server  │
│                                                                   │
│  [STEP  5/11] Apply Database Schemas (23 SQL files)              │
│               Threat Intel (13) + SafeOps Network (3) + DHCP (4) │
│                                                                   │
│  [STEP  6/11] Apply Schema Patches                               │
│               001_threat_intel_patches + 002_views_and_functions  │
│                                                                   │
│  [STEP  7/11] Load Seed Data                                     │
│               Feed sources config + initial threat categories     │
│                                                                   │
│  [STEP  8/11] Create Views and Functions                         │
│               (included in patch 002)                             │
│                                                                   │
│  [STEP  9/11] Grant Table-Level Permissions                      │
│               ALL on tables + sequences + default privileges      │
│                                                                   │
│  [STEP 10/11] Install Node.js 20.11.0                            │
│               Silent MSI install via msiexec /quiet               │
│                                                                   │
│  [STEP 11/11] Install WinPkFilter 3.4.8                          │
│               Silent NSIS install for packet capture driver       │
│                                                                   │
│  [CLEANUP]    Remove temporary installer files                    │
└──────────────────────────────────────────────────────────────────┘
```

### 11.4 CLI Modes

| Command | Purpose |
|---------|---------|
| `safeops-requirements-setup.exe` | Full 11-step install (PostgreSQL + DB + Node.js + WinPkFilter) |
| `safeops-requirements-setup.exe --db-init` | Database only — create/update databases, schemas, seeds, permissions (safe to re-run) |
| `safeops-requirements-setup.exe --db-reset` | Database reset — DROP all databases then recreate from scratch |

### 11.5 Databases Created

| Database | Owner | Description |
|----------|-------|-------------|
| `threat_intel_db` | `postgres` | Threat intelligence — IP/domain/hash reputation, threat feeds, GeoIP |
| `safeops_network` | `postgres` | Network management — DHCP devices, NIC config, Step-CA secrets |
| `safeops` | `postgres` | Core application — dashboard config, user settings |

### 11.6 Embedded SQL Schemas (23 files)

**Threat Intel Database (13 schemas):**

| Schema | Description |
|--------|-------------|
| `001_initial_setup.sql` | Base tables and extensions |
| `002_ip_reputation.sql` | IP reputation scoring |
| `003_domain_reputation.sql` | Domain reputation |
| `004_hash_reputation.sql` | File hash reputation (MD5/SHA256) |
| `007_geolocation.sql` | IP to country/city geolocation |
| `008_threat_feeds.sql` | External feed source management |
| `010_whitelist_filters.sql` | Whitelist/exclusion rules |
| `016_firewall_engine.sql` | Firewall rule storage |
| `017_ids_ips.sql` | IDS/IPS signature storage |
| `021_threat_intel.sql` | Aggregated threat intel views |
| `023_ssl_certificates.sql` | SSL certificate tracking |
| `users.sql` | Database user definitions |

**SafeOps Network Database (3 schemas):**

| Schema | Description |
|--------|-------------|
| `013_dhcp_server.sql` | DHCP device tracking |
| `020_nic_management.sql` | NIC configuration and state |
| `022_step_ca.sql` | Step-CA secrets and cert tracking |

**DHCP Migrations (4 schemas):**

| Schema | Description |
|--------|-------------|
| `002_add_portal_tracking.sql` | Captive portal visit tracking |
| `003_add_ca_cert_tracking.sql` | CA certificate installation tracking |
| `004_add_device_fingerprint.sql` | Device fingerprint enrichment |
| `005_fix_missing_columns.sql` | Schema repair migration |

**Patches (2) + Seeds (2):**

| File | Description |
|------|-------------|
| `001_threat_intel_patches.sql` | Column type fixes for threat intel pipeline binary |
| `002_views_and_functions.sql` | Aggregated views and stored functions |
| `feed_sources_config.sql` | Initial OSINT feed source URLs and schedules |
| `initial_threat_categories.sql` | Threat category taxonomy (malware, phishing, C2, etc.) |

### 11.7 Software Installed

| Software | Version | Install Method | Purpose |
|----------|:-------:|:--------------:|---------|
| PostgreSQL | 16.1 | EDB Silent Installer | Shared database for all SafeOps components |
| Node.js | 20.11.0 LTS | MSI Silent | Dashboard UI and backend services |
| WinPkFilter | 3.4.8 | NSIS Silent | Kernel-mode NDIS packet capture driver |

### 11.8 Database Users & Permissions

| User | Password | Databases | Purpose |
|------|----------|-----------|---------|
| `safeops` | `safeops123` | All 3 | Primary application user |
| `threat_intel_app` | `threat_intel_pass` | `threat_intel_db` | Threat Intel pipeline |
| `dhcp_server` | `dhcp_pass` | `threat_intel_db`, `safeops_network` | DHCP Monitor |
| `dns_server` | `dns_pass` | `threat_intel_db`, `safeops_network` | DNS-related services |

### 11.9 Key Design Decisions

1. **Self-Contained Binary** — All 23 SQL schema files are compiled into the binary via `go:embed`, making the installer a single `.exe` with zero external file dependencies.
2. **Idempotent Operations** — Database creation, user creation, and schema application all use `IF NOT EXISTS` / `CREATE OR REPLACE` patterns, making `--db-init` safe to re-run any number of times.
3. **Skip-Existing Detection** — Each installation step checks if the software is already installed (via file existence or `--version` commands) and skips if present, avoiding unnecessary reinstallation.
4. **Silent Installation** — All three components (PostgreSQL, Node.js, WinPkFilter) install silently without user interaction, enabling fully automated deployment.
5. **Separate DB Modes** — `--db-init` and `--db-reset` allow database management without reinstalling system dependencies, useful for development resets and migration reruns.
6. **Security Warning** — The completion summary explicitly warns to change default passwords, with all passwords visible in the summary for initial setup convenience.

---

## Tool 12: Desktop App (Wails + Svelte)

### 12.1 Overview

The Desktop App is SafeOps' **native Windows control center** — a Wails v2 application with a Svelte/Vite frontend that manages all 9 SafeOps services from a single GUI. It provides start/stop controls, real-time status monitoring, system tray integration (minimize-to-tray on close), a first-run setup wizard, SIEM management (Elasticsearch + Kibana), GitHub-based auto-updates, and live system resource stats. This is the primary interface for operators to manage the entire SafeOps platform.

**In essence:** One window to rule them all — start the firewall, monitor services, manage certificates, launch Elasticsearch/Kibana, and update the platform. Closes to system tray so it's always running.

### 12.2 Component Information

| Property | Value |
|---|---|
| **Language** | Go 1.25 (backend) + Svelte/Vite (frontend) |
| **Module Name** | `safeops-launcher-gui` |
| **Source Location** | `safeops-app/` (5 Go files + Svelte SPA) |
| **Framework** | Wails v2.11 (Go ↔ WebView2 bridge) |
| **Frontend** | Svelte + Vite (single `App.svelte` — 61KB) |
| **Key Dependencies** | `wails/v2`, `energye/systray`, `shirou/gopsutil/v3`, `lib/pq` |
| **Window Size** | 1100×720 (min: 800×600) |
| **Version** | 1.0.0 |

### 12.3 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SafeOps Desktop App v1.0                       │
│                    (Wails v2 + Svelte)                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────┐          │
│  │  GO BACKEND (app.go — 1259 lines)                  │          │
│  │                                                    │          │
│  │  Service Manager (9 services)                      │          │
│  │  ├── Core:         SafeOps Engine, Firewall Engine │          │
│  │  ├── Network:      NIC Mgmt, DHCP Monitor,        │          │
│  │  │                 Captive Portal                  │          │
│  │  ├── Certificates: Step-CA                         │          │
│  │  └── Data:         Network Logger, SIEM Forwarder, │          │
│  │                    Threat Intel                     │          │
│  │                                                    │          │
│  │  System Tray (systray.go)                          │          │
│  │  ├── Show / Hide / Quit                            │          │
│  │  ├── Left-click → Show window                      │          │
│  │  └── Close → Hide to tray (not exit)               │          │
│  │                                                    │          │
│  │  Auto-Updater (updater.go)                         │          │
│  │  ├── GitHub Releases API check (8s delay)          │          │
│  │  ├── Semver comparison                             │          │
│  │  ├── Download with progress events (128KB chunks)  │          │
│  │  └── Apply → stop services → launch installer      │          │
│  │                                                    │          │
│  │  SIEM Manager                                      │          │
│  │  ├── Start/Stop Elasticsearch (:9200)              │          │
│  │  ├── Start/Stop Kibana (:5601)                     │          │
│  │  └── Index template setup                          │          │
│  │                                                    │          │
│  │  System Stats (gopsutil)                           │          │
│  │  ├── CPU % / RAM MB / RAM %                        │          │
│  │  └── Go routines count                             │          │
│  └────────────────────────────────────────────────────┘          │
│                         │                                         │
│               Wails Bridge (Go ↔ JS bindings)                    │
│                         │                                         │
│  ┌────────────────────────────────────────────────────┐          │
│  │  SVELTE FRONTEND (App.svelte — 61KB)               │          │
│  │                                                    │          │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │          │
│  │  │ Service  │ │ SIEM     │ │ Setup Wizard     │   │          │
│  │  │ Cards    │ │ Panel    │ │ (First-Run)      │   │          │
│  │  │ Start/   │ │ ES +     │ │ 8-step guided    │   │          │
│  │  │ Stop     │ │ Kibana   │ │ installation     │   │          │
│  │  └──────────┘ └──────────┘ └──────────────────┘   │          │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │          │
│  │  │ Stats    │ │ Update   │ │ Web Console      │   │          │
│  │  │ CPU/RAM  │ │ Checker  │ │ Link (:3001)     │   │          │
│  │  └──────────┘ └──────────┘ └──────────────────┘   │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  WebView2 (Microsoft Edge) · embedded in native window           │
└──────────────────────────────────────────────────────────────────┘
```

### 12.4 Managed Services (9)

| # | Service ID | Name | Group | Port | Description |
|:-:|-----------|------|:-----:|:----:|-------------|
| 1 | `safeops-engine` | SafeOps Engine | Core | `:50051` | NDIS packet capture & injection |
| 2 | `firewall-engine` | Firewall Engine | Core | `:50052` | DDoS, brute-force, domain & geo blocking |
| 3 | `nic-management` | NIC Management | Network | `:8081` | Network interface management |
| 4 | `dhcp-monitor` | DHCP Monitor | Network | `:50055` | DHCP lease tracking & ARP monitor |
| 5 | `captive-portal` | Captive Portal | Network | `:8090` | CA certificate distribution |
| 6 | `step-ca` | Step CA | Certificates | `:9000` | Internal certificate authority |
| 7 | `network-logger` | Network Logger | Data | — | Packet logging to JSONL |
| 8 | `siem-forwarder` | SIEM Forwarder | Data | — | Log shipping → Elasticsearch |
| 9 | `threat-intel` | Threat Intel | Data | — | Threat feed pipeline |

### 12.5 Startup Sequence

```
App launches
    │
    ├── Kill stale processes (taskkill all 8 service .exe names)
    ├── Detect install paths (install-paths.json → SAFEOPS_HOME → relative)
    ├── Write startup diagnostic log to Desktop
    │
    ├── [if installed]
    │   ├── Start Web UI (Node backend :5050 + React :3001)    (400ms delay)
    │   ├── Start SafeOps Engine                                (600ms delay)
    │   ├── Wait for :50051 gRPC ready                          (up to 15s)
    │   └── Start Firewall Engine                               (after :50051 up)
    │
    ├── Start system stats loop (CPU/RAM polling)
    ├── Initialize system tray icon
    └── Check for updates (GitHub API, 8s delay)
```

### 12.6 Go Backend Methods (Wails Bindings)

| Method | Purpose |
|--------|---------|
| `GetServices()` | Returns all 9 service states (status, PID, config) |
| `StartService(id)` / `StopService(id)` | Start/stop individual services |
| `StartAll()` / `StopAll()` | Batch start/stop with 1.2s delay between services |
| `GetSystemStats()` | CPU %, RAM used/total/%, goroutine count |
| `StartWebUI()` / `StopWebUI()` | Manage Node backend + React dev server |
| `OpenWebConsole()` | Open http://localhost:3001 in browser |
| `OpenFirewallUI()` | Open http://localhost:8443 in browser |
| `CheckForUpdates()` | Query GitHub Releases API for new version |
| `DownloadUpdate(url)` | Download installer with progress events (128KB chunks) |
| `ApplyUpdate()` | Stop all services → launch installer → quit app |
| `GetCurrentVersion()` | Returns `"1.0.0"` |
| `IsFirstRun()` | Returns true if install-paths.json not found |
| `RunSetupStep(step)` | Execute first-run setup step (1-8) |
| `GetSIEMState()` | Elasticsearch/Kibana running status + port checks |
| `StartElasticsearch()` / `StartKibana()` | Launch SIEM components |
| `SetupElasticsearchTemplates()` | Configure index templates |
| `CheckPostgresReady()` | Ping PostgreSQL on :5432 |
| `ShowWindow()` / `HideWindow()` / `QuitApp()` | Window management |

### 12.7 System Tray

| Feature | Behavior |
|---------|----------|
| **Left-click** | Show main window |
| **Double-click** | Show main window |
| **Right-click** | Context menu: Show / Hide / Quit |
| **Window close (X)** | Hides to tray (does NOT exit) |
| **"Quit SafeOps"** | Stops all services → exits system tray → `os.Exit(0)` |
| **Tooltip** | "SafeOps Firewall - Running" |
| **Icon** | `icon.ico` from build/windows or exe directory |

### 12.8 Auto-Updater

```
Startup (8s delay, non-blocking)
    │
    ▼
GitHub API: GET /repos/safeopsfw/SafeOps/releases/latest
    │
    ▼
Semver comparison (isNewer): remote > local?
    │  (yes)
    ▼
Emit "update:available" event to frontend
    │
User clicks "Download"
    │
    ▼
Download .exe asset (128KB chunks, progress every 250ms)
    │
    ▼
User clicks "Install"
    │
    ▼
StopAll() → Launch installer → Quit app (500ms delay)
```

### 12.9 Key Design Decisions

1. **Wails v2 + WebView2** — Uses Microsoft's WebView2 (Edge) runtime for the UI, avoiding Electron's bloat. The Go backend binds methods directly to JavaScript, giving the Svelte frontend full access to system operations.
2. **HideWindowOnClose** — Closing the window hides it to the system tray instead of exiting, ensuring services keep running. True exit only via tray "Quit SafeOps".
3. **Ordered Startup** — SafeOps Engine MUST start before Firewall Engine (Firewall connects to Engine's gRPC on :50051). The app waits up to 15 seconds for port readiness before proceeding.
4. **Stale Process Cleanup** — On startup, `taskkill /F` is run against all 8 service executables to free ports from previous unclean shutdowns (crashes, force closes).
5. **Step-CA BadgerDB Auto-Fix** — The BadgerDB vlog file can get corrupted on unclean shutdown (pre-allocated to 2GB). The app pre-emptively detects and truncates it, with a retry-on-error fallback that parses the exact `Endoffset` from the error message.
6. **Single-File Frontend** — The entire Svelte UI is in one 61KB `App.svelte` file with Wails JS bindings, keeping the frontend simple and avoiding routing complexity.
7. **Desktop Diagnostic Log** — Every startup writes a diagnostic log to the user's Desktop with install paths, executable status, port checks, and system info — invaluable for debugging VM deployments.

---

