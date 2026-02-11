# SafeOps V2 — Context Transfer for New Session

**Date:** 2026-02-11
**Working Directory:** D:\SafeOpsFV2
**Platform:** Windows (win32)

---

## 1. PROJECT OVERVIEW

SafeOps is a Windows network security suite with two core engines:

- **SafeOps Engine** (`src/safeops-engine/`) — Go. Kernel-level packet interception via WinpkFilter/NDISAPI. Intercepts all traffic, does DNS redirect, SNI blocking, HTTP block page injection, VPN port blocking, DoH blocking. Streams packet metadata via gRPC to subscribers.
- **Firewall Engine** (`src/firewall_engine/`) — Go. Subscribes to SafeOps Engine via gRPC. Runs security checks (DDoS, brute force, port scan, anomaly, rate limiting), domain filtering, GeoIP blocking, threat intel (37K IPs, 1.28M domains from PostgreSQL). Generates alerts to JSONL files.

Other components:
- `src/threat_intel/` — Go threat intel pipeline (fetcher + processor)
- `src/requirements_setup/` — Go installer (PostgreSQL, Node.js, WinPkFilter + DB schemas)
- `tools/netsim/` — Network attack simulator (11 real-packet tests)
- `database/schemas/` — 14 base SQL schema files
- `database/patches/` — Schema drift fixes
- `database/seeds/` — Feed sources, threat categories

---

## 2. CURRENT STATE & RECENT WORK

### Latest Builds (v6.1.0 SafeOps Engine, fresh Firewall Engine)
- `bin/safeops-engine/safeops-engine.exe` — v6.1.0 (full gRPC broadcast + pre-block alerts)
- `bin/firewall-engine/firewall-engine.exe` — fresh build
- `bin/netsim.exe` — fresh build

### Git Status
- Branch: `main`
- Last commit: `aeef424` "Safeops+firewall blocking working"
- **Uncommitted changes** (4 source files):
  - `src/safeops-engine/cmd/main.go` — version string 6.0.0 → 6.1.0
  - `src/safeops-engine/pkg/engine/engine.go` — sampleRate 10→1, pre-block broadcast
  - `src/safeops-engine/pkg/grpc/server.go` — TCP flags read from RawBuffer[47] instead of Payload[13]
  - `src/firewall_engine/cmd/main.go` — whitelist bypass restructured (security monitoring always runs)

### What Works
- Domain blocking: DNS intercept → 127.0.0.1, SNI RST, HTTP block page, QUIC drop
- Block page HTTPS: dynamic per-domain certs, CA auto-installed to Windows Trusted Root store
- VPN port blocking (16 rules from configs/blocked_ports.txt, LAN exempt)
- DoH resolver blocking (27 IPs on port 443)
- LAN stability: proper adapter filtering (MAC OUI for VirtualBox), virtual adapter skip
- Firewall Engine: all 15+ subsystems initialize, connects to gRPC, processes packets
- Network simulator: all 11/11 tests complete and send packets

### What Was Just Fixed (v6.1.0, UNCOMMITTED)
**Problem:** Netsim produced no alerts in Firewall Engine.
**Root cause:**
1. Fast-path sampled only 1-in-10 packets → attack volumes below detection thresholds
2. VPN/DoH/domain blocking happened BEFORE gRPC broadcast → Firewall Engine never saw them

**Fix applied to `engine.go`:**
- `sampleRate` changed from 10 → 1 (broadcast every fast-path packet)
- Added `e.grpcServer.BroadcastPacket(pkt)` before VPN blocking, DoH blocking, DNS domain blocking, SNI domain blocking, QUIC domain blocking, HTTP domain blocking

### Additional Fixes Found During Live Testing (UNCOMMITTED)
**Problem 2:** Firewall Engine whitelist (`blocklist.toml`) includes `192.168.0.0/16` in `[whitelist].cidrs`. All netsim outbound packets have srcIP=192.168.1.x → whitelist matched → `goto inspectPacket` → **skipped ALL security checks**.
**Fix:** Restructured `cmd/main.go` packet handler so security monitoring (DDoS, port scan, brute force, anomaly) ALWAYS runs, even for whitelisted IPs. Only blocking verdicts (threat intel, manual IP, geo, domain) are bypassed by whitelist.

**Problem 3:** TCP flags in gRPC metadata were read from `pkt.Payload[13]` (application data) instead of `pkt.RawBuffer.Buffer[47]` (raw Ethernet frame). This means TcpFlags=garbage → SYN detection, port scan SYN-only check, and anomaly detection never worked correctly.
**Fix:** Changed `server.go` `convertToProtobuf()` to read TCP flags from `pkt.RawBuffer.Buffer[47]` (Eth:14 + IP:20 + TCP:13).

**Result after all 3 fixes:** Netsim port scan test generates PORT_SCAN alert, IP banned. Real traffic also detecting PROTOCOL_VIOLATION alerts (SYN+FIN, Xmas scans from external IPs).

### What Was Fixed in Previous Session (committed in aeef424)
1. **CRITICAL injection direction bug**: All injected packets (DNS responses, TCP RSTs, HTTP block pages) used `SendPacketToAdapter` (outbound to wire) instead of `SendPacketToMstcp` (inbound to browser). Split into two methods with correct direction flags.
2. **Virtual adapter filtering**: Added MAC OUI detection (VirtualBox 0a:00:27/08:00:27, VMware, Hyper-V) + "Local Area Connection*" skip
3. **Block page CA auto-install**: `certutil -addstore Root` on engine startup
4. Reverted to v9 committed code base, removed all v10-v14 experimental code (safety valve, IP cache, preseed, batch reads)

---

## 3. FIREWALL ENGINE IMPLEMENTATION PLAN

**Full plan:** `docs/FIREWALL_ENGINE_IMPLEMENTATION_PLAN.md` (634 lines, 10 phases)

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | DONE | gRPC performance (lock-free broadcast, atomic snapshot, 500K buffer) |
| 1 | DONE | Config files + alert system (TOML configs, JSONL alert writer, throttle) |
| 2 | DONE | Threat intel DB integration (PostgreSQL, IP/domain caches, refresher) |
| 3 | DONE | Security features (DDoS, rate limit, brute force, port scan, anomaly, baseline, ban escalation) |
| 4 | DONE | Domain filtering (config blocklist, categories, CDN awareness, threat intel domains) |
| 5 | DONE | GeoIP blocking (country/ASN blocking, PostgreSQL ip_geolocation table) |
| 6 | DONE | Blocklist TOML config (unified blocklist.toml, whitelist, per-category toggles) |
| 7 | DONE | Hot-reload (fsnotify watcher, blocklist/domain/detection/geoip reload, rollback) |
| **8** | **NOT STARTED** | **Performance optimization** — sync.Pool, batch processing, lock audit, pprof |
| **9** | **PARTIAL** | **Production hardening** — graceful shutdown done, gRPC reconnect done. Still need: Windows service (`sc create`), resource limits (memory/goroutine monitoring) |
| **10** | **NOT STARTED** | **Web UI Backend API** — REST API (Go Fiber :8443), WebSocket, dashboard stats, blocklist CRUD, security management, logs/alerts endpoints |

---

## 4. CRITICAL LEARNINGS (DO NOT VIOLATE)

These are hard-won lessons from debugging. Violating any of these will break the engine:

- **ndisapi-go ReadPacket()/ReadPackets()**: Return TRUE on ERROR (inverted!). `DeviceIoControl` returns nil on success; wrapper does `return err != nil`. Use `failed := api.ReadPackets(req)` NOT `success :=`
- **isWebTraffic**: ONLY check dstPort, NOT srcPort. srcPort==443 matches ALL HTTPS responses → 99% slow path → LAN dies from queue backlog
- **SendPacketToMstcp vs SendPacketToAdapter**: DNS fake responses, TCP RSTs to browser, and HTTP block pages MUST use `SendPacketToMstcp` (PACKET_FLAG_ON_RECEIVE). RSTs to remote server use `SendPacketToAdapter` (PACKET_FLAG_ON_SEND).
- **VPN/DoH blocking**: Must skip local/LAN IPs (`isLocalIP` check). Blocking IPSec ports (500/4500 UDP) on LAN kills Ethernet adapter.
- **Do NOT block UDP 443 globally** — kills all QUIC/HTTP3 traffic
- **Tunnel ONLY physical adapters**: Filter virtual adapters by name patterns AND MAC OUI prefixes (VirtualBox, VMware, Hyper-V). Tunneling VirtualBox adapter causes issues.
- **Use single-packet ReadPacket** (proven reliable). Batch ReadPackets has inverted return value issues.
- **TCP flags in gRPC protobuf**: Read from `pkt.RawBuffer.Buffer[47]` (Eth:14 + IP:20 + TCP:13), NOT from `pkt.Payload[13]` which is application data. Wrong TCP flags = broken SYN flood detection, port scan detection, anomaly detection.
- **Whitelist bypass must NOT skip security monitoring**: The blocklist.toml whitelist (192.168.0.0/16 etc.) must only bypass blocking verdicts. Security monitoring (DDoS, port scan, brute force, anomaly) must always run so alerts are generated for all traffic.

---

## 5. KEY FILE LOCATIONS

### SafeOps Engine (src/safeops-engine/)
| File | Purpose |
|------|---------|
| `cmd/main.go` | Entry point, v6.1.0, stats loop |
| `pkg/engine/engine.go` | Core packet handler (fast/slow path, domain blocking, gRPC broadcast) |
| `internal/driver/driver.go` | WinpkFilter adapter management, packet read/write, MAC OUI filter |
| `internal/verdict/verdict.go` | sendPacketToAdapter/sendPacketToMstcp, TCP RST, DNS inject |
| `internal/verdict/html_injection.go` | HTTP block page injection |
| `pkg/blockpage/server.go` | HTTPS block page server, dynamic certs, CA auto-install |
| `pkg/grpc/server.go` | gRPC metadata stream server (127.0.0.1:50051) |
| `pkg/control/server.go` | HTTP control API (127.0.0.1:50052) |
| `internal/parser/` | DNS, TLS SNI, HTTP parsers |

### Firewall Engine (src/firewall_engine/)
| File | Purpose |
|------|---------|
| `cmd/main.go` | Entry point (1125 lines), 15+ subsystem init, packet handler pipeline |
| `internal/alerting/manager.go` | Alert dispatcher (10K buffer, throttle, file write) |
| `internal/alerting/writer.go` | JSONL file writer with size-based rotation |
| `internal/alerting/throttle.go` | Dedup by AlertType:SrcIP within 60s |
| `internal/security/manager.go` | Security orchestrator (ban→whitelist→rate→DDoS→anomaly→baseline) |
| `internal/security/ban_manager.go` | Exponential ban escalation |
| `internal/rate_limiting/ddos_protection.go` | SYN/UDP/ICMP flood detection |
| `internal/security/brute_force.go` | Per-IP:port failure tracking |
| `internal/security/port_scan.go` | Random + sequential scan detection |
| `internal/security/anomaly_detector.go` | TCP flag violations, packet size, beaconing |
| `internal/domain/filter.go` | Domain blocking (config + categories + threat intel) |
| `internal/domain/cdn_allowlist.go` | CDN provider detection (12 providers) |
| `internal/geoip/checker.go` | Country/ASN blocking via PostgreSQL |
| `internal/threatintel/` | DB pool, IP cache, domain cache, refresher, decision engine |
| `internal/hotreload/` | fsnotify watcher, config reload handlers |
| `internal/config/` | All TOML config loaders (firewall, detection, geoip, blocklist, paths) |
| `internal/integration/safeops_grpc_client.go` | gRPC client wrapper |
| `pkg/grpc/client.go` | Low-level gRPC client (worker pool, reconnect) |

### Config Files (bin/firewall-engine/configs/)
| File | Purpose |
|------|---------|
| `firewall.toml` | Engine settings, gRPC address, DB connection, performance |
| `detection.toml` | DDoS/rate limit/brute force/port scan/anomaly thresholds |
| `geoip.toml` | Country/ASN deny/allow lists |
| `blocklist.toml` | Unified blocking policy (domains, IPs, categories, whitelist) |
| `domains.txt` | Domain blocklist (17 domains) |

### Config Files (bin/safeops-engine/configs/)
| File | Purpose |
|------|---------|
| `domains.txt` | 17 blocked domains |
| `doh_servers.txt` | 27 DoH resolver IPs |
| `blocked_ports.txt` | 16 VPN port rules |

### Alert Output
- Live: `bin/firewall-engine/data/data/logs/firewall-alerts/firewall-alerts.jsonl`
- Test: `bin/firewall-engine/data/test-alerts/firewall-alerts.jsonl`

### Other
- Engine log: `data/logs/engine.log`
- Security test: `bin/firewall-engine/sectest.exe` (16/17 passing)
- Network simulator: `tools/netsim/main.go` (11 attack tests)
- Full plan: `docs/FIREWALL_ENGINE_IMPLEMENTATION_PLAN.md`

---

## 6. BUILD COMMANDS

```bash
# SafeOps Engine
cd "D:\SafeOpsFV2\src\safeops-engine" && go build -o "../../bin/safeops-engine/safeops-engine.exe" ./cmd/

# Firewall Engine
cd "D:\SafeOpsFV2\src\firewall_engine" && go build -o "../../bin/firewall-engine/firewall-engine.exe" ./cmd/

# Network Simulator
cd "D:\SafeOpsFV2\tools\netsim" && go build -o "../../bin/netsim.exe" .
```

---

## 7. POSTGRESQL

- Password: `admin` (all users)
- Databases: `threat_intel_db`, `safeops_network`, `safeops`
- App users: `safeops`, `threat_intel_app`, `dhcp_server`, `dns_server`
- psql: `"C:\Program Files\PostgreSQL\16\bin\psql.exe"`

---

## 8. ARCHITECTURE DIAGRAM

```
                    ┌──────────────────────────────┐
                    │       Network Packets         │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │    WinpkFilter / NDISAPI      │
                    │   (Kernel-level intercept)    │
                    └──────────────┬───────────────┘
                                   ▼
              ┌────────────────────────────────────────┐
              │         SafeOps Engine (v6.1.0)        │
              │  ┌─────────┐  ┌─────────┐  ┌────────┐ │
              │  │VPN Block │  │DoH Block│  │Domain  │ │
              │  │(16 ports)│  │(27 IPs) │  │Block   │ │
              │  └────┬─────┘  └────┬────┘  └───┬────┘ │
              │       │             │            │      │
              │  ┌────┴─────────────┴────────────┴───┐ │
              │  │  BroadcastPacket (gRPC :50051)     │ │
              │  │  sampleRate=1 (ALL packets)        │ │
              │  └────────────────┬───────────────────┘ │
              │  ┌────────────────┴───────────────────┐ │
              │  │  Fast Path (non-53/80/443)         │ │
              │  │  Slow Path (DNS/HTTP/HTTPS)        │ │
              │  │  → DNS Redirect, SNI RST,          │ │
              │  │    HTTP Block Page, QUIC Drop       │ │
              │  └────────────────────────────────────┘ │
              │  Block Page Server (:443 → dynamic cert)│
              │  Control API (:50052)                   │
              └───────────────────┬────────────────────┘
                                  │ gRPC PacketMetadata
                                  ▼
              ┌────────────────────────────────────────┐
              │         Firewall Engine (v5.2.0)       │
              │  ┌──────────────────────────────────┐  │
              │  │ Whitelist → Security → PortScan  │  │
              │  │ → Manual IP → GeoIP → ThreatIntel│  │
              │  │ → Domain Filter → Packet Inspect │  │
              │  └──────────────────────────────────┘  │
              │  Alert Manager → firewall-alerts.jsonl │
              │  Ban Manager (exponential escalation)  │
              │  Verdict Cache → sends back to SafeOps │
              │  Hot-Reload (fsnotify on configs/)     │
              │  Prometheus Metrics, Health Server      │
              └────────────────────────────────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────┐
              │         PostgreSQL (threat_intel_db)    │
              │  37K blocked IPs, 1.28M domains        │
              │  4.5M IP geolocation rows              │
              └────────────────────────────────────────┘
```

---

## 9. PENDING TASKS (in priority order)

1. **Test v6.1.0 netsim alerts** — Run safeops-engine + firewall-engine + netsim, verify alerts appear in `firewall-alerts.jsonl`
2. **Commit v6.1.0 changes** — Only 2 files changed (engine.go + main.go)
3. **Verify CA auto-install** — Chrome should show block page (not privacy error) for HSTS sites like Facebook
4. **Continue Firewall Engine plan:**
   - Phase 8: Performance optimization (sync.Pool, batch, pprof)
   - Phase 9: Production hardening (Windows service, resource limits)
   - Phase 10: Web UI Backend API (REST + WebSocket)

---

## 10. NETWORK ADAPTER STATE

- Ethernet: Intel I219-LM, MAC 58-11-22-86-FD-C4, Up, 1 Gbps, gateway 192.168.1.1 (INTERNET)
- Wi-Fi: Intel AX201, MAC F4-26-79-73-6F-7C, DISCONNECTED
- Ethernet 2: VirtualBox Host-Only, MAC 0A-00-27-00-00-09, Up, no internet (FILTERED OUT by MAC OUI)
