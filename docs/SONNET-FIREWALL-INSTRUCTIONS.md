# SafeOps Firewall Engine — Remaining Work Instructions

> **For:** Claude Sonnet 4.6 (or any continuation model)
> **Project:** D:\SafeOpsFV2
> **Date:** February 2026
> **Status:** 85% complete — Phases 8, 9, and UI wiring remain

---

## TABLE OF CONTENTS

1. [Architecture Overview](#1-architecture-overview)
2. [What's Already Done (Phases 0-7 + 10)](#2-whats-already-done)
3. [CRITICAL Rules — Read Before Touching Anything](#3-critical-rules)
4. [Phase 8: Performance Optimization](#4-phase-8-performance-optimization)
5. [Phase 9: Production Hardening](#5-phase-9-production-hardening)
6. [Phase 10B: Wire Up Web UI](#6-phase-10b-wire-up-web-ui)
7. [Phase 11: Web UI Polish & Completion](#7-phase-11-web-ui-polish--completion)
8. [Build & Test Commands](#8-build--test-commands)
9. [Key File Map](#9-key-file-map)
10. [Configuration Files Reference](#10-configuration-files-reference)
11. [Package Architecture](#11-package-architecture)
12. [Testing Checklist](#12-testing-checklist)

---

## 1. Architecture Overview

### Two Separate Processes (CRITICAL — DO NOT MERGE)

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│   SafeOps Engine (Process 1)    │     │   Firewall Engine (Process 2)    │
│   bin/safeops-engine/           │     │   bin/firewall-engine/           │
│   safeops-engine.exe            │     │   firewall-engine.exe            │
│                                 │     │                                  │
│ • NDIS packet capture (driver)  │     │ • Decision logic (all detectors) │
│ • Packet injection/blocking     │     │ • DDoS, port scan, brute force   │
│ • DNS redirect (→127.0.0.1)    │     │ • Domain/IP/GeoIP filtering      │
│ • SNI extraction + TCP RST      │     │ • Custom TOML rules engine       │
│ • HTTP block page server        │     │ • Threat intelligence lookups    │
│ • Flow cache (inspectedFlows)   │     │ • Alert management + logging     │
│ • DoH resolver blocking         │     │ • SOC verdict JSONL logging      │
│ • VPN port blocking             │     │ • Web UI dashboard (API + SPA)   │
│                                 │     │ • Hot-reload config watcher      │
│ gRPC server: 127.0.0.1:50051   │◄────│ gRPC client: connects to 50051  │
│ HTTP control: 127.0.0.1:50052  │◄────│ HTTP client: pushes domains     │
│ Block page: 127.0.0.1:443      │     │ Web UI: 127.0.0.1:8443          │
└─────────────────────────────────┘     └──────────────────────────────────┘
```

### Communication Flow
1. SafeOps captures packets via NDIS driver → streams metadata via gRPC (50051)
2. Firewall receives metadata → runs all detection → sends verdict back via gRPC
3. Firewall pushes blocked domain list to SafeOps via HTTP POST to 50052
4. SafeOps uses `isDomainBlocked()` (populated by firewall HTTP push) for DNS/SNI blocking
5. `engine.GetEngine()` returns **nil** in firewall process — NEVER use it there

### Key Ports
| Port | Protocol | Service |
|------|----------|---------|
| 50051 | gRPC | SafeOps metadata stream |
| 50052 | HTTP | SafeOps control API (domain sync, health) |
| 443 | HTTPS | Block page server (dynamic per-domain TLS certs) |
| 8443 | HTTP | Firewall Web UI dashboard |
| 8085 | HTTP | Firewall health check |
| 9090 | HTTP | Prometheus metrics |
| 50054 | gRPC | Firewall management API |

---

## 2. What's Already Done

### Phase 0: Configuration System ✅
- TOML-based config: firewall.toml, detection.toml, geoip.toml, blocklist.toml, rules.toml
- Go config structs with validation in `internal/config/`
- All detection thresholds are TOML-driven — NOTHING is hardcoded

### Phase 1: Alert System ✅
- `internal/alerting/` — manager, writer (JSONL), DB logger, throttle, templates
- Alert files: `bin/firewall-engine/data/logs/firewall-alerts/firewall-alerts.jsonl`
- Triage support: acknowledge, escalate, dismiss, resolve

### Phase 2: Threat Intelligence ✅
- `internal/threatintel/` — DB lookup, IP/domain caches, periodic refresh
- Database: `threat_intel_db` (PostgreSQL, user: safeops, pass: admin)
- IP block threshold: 50, Domain block threshold: 50

### Phase 3: Security Detectors ✅
- `internal/security/manager.go` — orchestrates all detectors
- DDoS detection (SYN/UDP/ICMP flood) with escalating bans (30m→2h→8h→32h→permanent)
- Rate limiting (1000 pps/IP default, 100K global)
- Brute force detection (SSH, RDP, FTP, SMTP, MySQL, PostgreSQL, MSSQL)
- Port scan detection (100 port threshold, sequential detection)
- Traffic baseline (EMA, 3σ deviation)
- Ban manager with escalation levels (L1→L2→L3)

### Phase 4: Domain Filtering ✅
- `internal/domain/filter.go` — blocklist, whitelist, categories
- Categories: social_media, streaming, gaming, ads, trackers, adult, gambling, vpn_proxy
- CDN-aware blocking (DNS-only for CDN-hosted domains)
- Auto-wildcard: blocking "evil.com" blocks "*.evil.com"

### Phase 5: GeoIP Filtering ✅
- `internal/geoip/checker.go` — country/ASN blocking with deny_list/allow_list modes
- MaxMind GeoLite2 database integration
- Datacenter flagging for foreign IPs

### Phase 6: Custom Rule Engine ✅
- `internal/rules/engine.go` + `configs/rules.toml`
- 27 rules: VPN detection, DoH bypass, protocol security, suspicious outbound
- Threshold-based detection with grouping (src_ip, dst_ip, src_ip+dst_port)
- Actions: ALERT, LOG, DROP, BAN

### Phase 7: Hot-Reload ✅
- `internal/hotreload/reloader.go` + `watcher.go`
- Watches: detection.toml, blocklist.toml, geoip.toml, domains.txt, blocked_ips.txt, rules.toml
- Validates before applying, rolls back on error
- Re-syncs blocklist to SafeOps via HTTP on domain changes

### Phase 10A: Web UI Backend ✅ (but NOT wired up — see Phase 10B below)
- `internal/api/server.go` — Fiber-based REST API with 30+ endpoints
- `internal/api/dashboard.go` — KPI aggregation
- `internal/api/alerts.go` — Alert management
- `internal/api/security.go` — Ban management
- `internal/api/rules.go` — Domain/IP/GeoIP/detection config
- `internal/api/tickets.go` — Incident tickets
- `internal/api/websocket.go` — EventHub for real-time events
- `internal/api/health.go` — Health check

### Phase 10A: Web UI Frontend ✅ (embedded SPA, but server not started)
- `internal/api/web/index.html` — 643 lines, 9 pages, 3 modals
- `internal/api/web/app.js` — 1109 lines, vanilla JS SPA
- `internal/api/web/index.css` — 1158 lines, dark glassmorphism UI
- Pages: Dashboard, Alerts, Domain Rules, IP Rules, GeoIP, Detection Config, Bans, Tickets, System Status
- WebSocket client with auto-reconnect
- `//go:embed web/*` directive ready in server.go

### SOC Verdict Logging ✅
- `internal/logging/verdict_logger.go` — JSONL, 5-min rotation, gzip
- Short field names: ts, src, sp, dst, dp, proto, action, detector, domain, reason
- Only DROP/BLOCK/REDIRECT logged (ALLOW filtered for storage)
- `logAndSend` closure in main.go wraps gRPC verdict + file log

### Block Page Server ✅ (in SafeOps Engine)
- Dynamic per-domain TLS cert generation (ECDSA P-256)
- Auto-installs CA to Windows root store via certutil
- CA sharing page at `/ca` endpoint with device tracking
- Cert cache (max 10K entries)

### Domain Sync (Firewall → SafeOps) ✅
- `internal/integration/blocklist_sync.go` — HTTP POST to 127.0.0.1:50052
- Bulk sync: POST `/api/v1/sync/domains` (replaces entire list)
- Single add: POST `/api/v1/block/domain`
- Single remove: DELETE `/api/v1/block/domain`
- `WaitForAPI(10s)` at startup before initial sync
- Hot-reload triggers automatic re-sync

### Performance Fixes ✅
- sampleRate = 100 (was 1 — sent every packet via gRPC)
- Flow cache: `inspectedFlows` sync.Map for TCP 80/443 — after SNI/HTTP extraction, data packets skip slow-path
- Flow cache prunes at 50K entries

---

## 3. CRITICAL Rules — Read Before Touching Anything

These are hard-won lessons from debugging. Violating any of these WILL break the engine:

### NDIS / Packet Handling
1. **ReadPacket() returns TRUE on ERROR** — ndisapi-go has inverted return. Use `failed := api.ReadPacket(req)` NOT `success :=`
2. **Use single-packet ReadPacket()** — batch ReadPackets has inverted return bugs. Single packet is proven reliable.
3. **isWebTraffic must ONLY check dstPort** — if you check srcPort, srcPort==443 matches ALL HTTPS responses → 99% slow path → LAN dies
4. **Tunnel ONLY ONE adapter** — Ethernet preferred, WiFi fallback. Tunneling both kills LAN (single event + read loop can't drain both queues). Use `adapterPriority()`.

### Domain Blocking
5. **Do NOT block UDP 443** — kills all QUIC/HTTP3 traffic
6. **VPN/DoH port blocking must skip local/LAN IPs** — `isLocalIP()` check. Blocking IPSec 500/4500 on LAN kills Ethernet adapter.

### Detection Engine
7. **DDoS must run BEFORE rate limiting** in `Manager.Check()` — order matters
8. **Fast-path must use BroadcastPacketNoCache** — cached DROPs prevent flood counter increment
9. **SYN flood netsim must use single port** — random ports trigger PORT_SCAN first
10. **detection.toml trusted_cidrs must NOT include 192.168.0.0/16** — bypasses ALL security detection. The `bin/` version correctly has empty trusted_cidrs.

### Architecture
11. **Engines are SEPARATE PROCESSES** — `engine.GetEngine()` returns nil in firewall process. Domain sync uses HTTP API, not in-process calls.
12. **sampleRate must NOT be 1** — sends every fast-path packet via gRPC. Use 100+ (1-in-N sampling).
13. **TCP flows on port 80/443 need flow cache** — without it, every HTTPS data packet goes through full gRPC pipeline → 400→180 Mbps speed drop.

---

## 4. Phase 8: Performance Optimization

**Status: NOT STARTED**
**Priority: MEDIUM**
**Estimated scope: ~6 tasks**

### Task 8.1: sync.Pool for Packet Metadata

**File:** `src/firewall_engine/cmd/main.go` (packet processing loop)
**Also:** `src/firewall_engine/pkg/models/metadata.go`

Add `sync.Pool` to reuse packet metadata structs instead of allocating new ones per packet:

```go
var metadataPool = sync.Pool{
    New: func() interface{} {
        return &PacketMetadata{}
    },
}

// In packet processing:
meta := metadataPool.Get().(*PacketMetadata)
defer metadataPool.Put(meta)
meta.Reset() // zero out fields
```

**Where to add:**
- Pool the `PacketMetadata` struct used in the gRPC pipeline
- Pool the verdict response structs
- Reset before reuse (zero all fields)

### Task 8.2: Batch Database Inserts

**File:** `src/firewall_engine/internal/threatintel/db.go`
**Also:** `src/firewall_engine/internal/alerting/db_logger.go`

Current: each threat intel lookup or alert write is a single DB query.
Target: batch 100 inserts or flush every 5 seconds.

```go
type BatchInserter struct {
    buffer    []interface{}
    mu        sync.Mutex
    maxBatch  int           // 100
    flushTime time.Duration // 5s
    ticker    *time.Ticker
}
```

### Task 8.3: Batch Alert Writes

**File:** `src/firewall_engine/internal/alerting/writer.go`

Current: each alert is written immediately to JSONL.
Target: buffer 100 alerts or flush every 1 second.

```go
type BufferedWriter struct {
    buf     *bufio.Writer
    mu      sync.Mutex
    pending int
    ticker  *time.Ticker
}
```

Flush on: 100 alerts OR 1s timer OR shutdown signal.

### Task 8.4: Batch Verdict Sends

**File:** `src/firewall_engine/internal/logging/verdict_logger.go`

Current: each verdict written individually.
Target: buffer and flush in batches. Already has 5-min rotation — just add write buffering.

Use `bufio.Writer` with periodic flush (1s or 50 entries).

### Task 8.5: pprof Endpoints

**File:** `src/firewall_engine/cmd/main.go`

Add HTTP pprof at port 6060 for CPU/memory/goroutine profiling:

```go
import _ "net/http/pprof"

go func() {
    log.Println(http.ListenAndServe(":6060", nil))
}()
```

Then accessible at:
- `http://localhost:6060/debug/pprof/`
- `http://localhost:6060/debug/pprof/goroutine`
- `http://localhost:6060/debug/pprof/heap`
- `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30`

### Task 8.6: Lock Contention Audit

**Files:** All files using `sync.RWMutex`

Review all mutex usage across the codebase:
- Switch read-heavy paths from `RWMutex` to `atomic.Value` where possible
- Check `sync.Map` usage is appropriate (many reads, few writes)
- Verify no mutex held during I/O operations (DB queries, HTTP calls)
- Key areas to check:
  - `internal/security/manager.go` — detector coordination
  - `internal/security/ban_manager.go` — ban lookups
  - `internal/cache/verdict_cache.go` — verdict cache
  - `internal/domain/filter.go` — domain lookup
  - `internal/alerting/manager.go` — alert dispatch

---

## 5. Phase 9: Production Hardening

**Status: ~20% done (basic shutdown only)**
**Priority: HIGH**
**Estimated scope: ~7 tasks**

### What's Done
- Basic signal handling (SIGTERM, SIGINT) with ordered teardown
- Max 10s graceful shutdown timeout
- Final stats printed on shutdown

### Task 9.1: Auto-Reconnect with Exponential Backoff

**File:** `src/firewall_engine/internal/integration/safeops_grpc_client.go`
**Also:** `src/firewall_engine/internal/storage/database.go`

When gRPC connection to SafeOps (50051) drops or PostgreSQL disconnects:

```go
type ReconnectPolicy struct {
    MaxRetries    int           // 10
    InitialDelay  time.Duration // 1s
    MaxDelay      time.Duration // 60s
    Multiplier    float64       // 2.0
    Jitter        float64       // 0.1
}

func (p *ReconnectPolicy) NextDelay(attempt int) time.Duration {
    delay := float64(p.InitialDelay) * math.Pow(p.Multiplier, float64(attempt))
    if delay > float64(p.MaxDelay) {
        delay = float64(p.MaxDelay)
    }
    jitter := delay * p.Jitter * (rand.Float64()*2 - 1)
    return time.Duration(delay + jitter)
}
```

Apply to:
- gRPC stream reconnection (SafeOps metadata stream)
- PostgreSQL connection pool recovery
- HTTP control API reconnection (blocklist sync)

**Important:** During reconnect, engine should `fail_open` (pass all traffic) per config.

### Task 9.2: Health Checks

**File:** `src/firewall_engine/internal/health/checker.go`

Add periodic health checks (every 30s):
- DB ping: `SELECT 1` on threat_intel_db and safeops_network
- gRPC connection state check
- Connection pool stats (active/idle/max)
- Disk space check for log directory

Expose via existing health endpoint (`:8085/health`):
```json
{
    "status": "healthy",
    "components": {
        "threat_intel_db": {"status": "up", "latency_ms": 2},
        "network_db": {"status": "up", "latency_ms": 1},
        "safeops_grpc": {"status": "connected", "stream_active": true},
        "safeops_http": {"status": "up"},
        "disk": {"status": "ok", "free_gb": 45.2}
    },
    "uptime_seconds": 3600
}
```

### Task 9.3: Memory Monitoring

**File:** New: `src/firewall_engine/internal/health/memory_monitor.go`

Monitor `runtime.MemStats` every 30 seconds:

```go
type MemoryMonitor struct {
    softLimitMB  int64 // 512 MB — log warning
    hardLimitMB  int64 // 1024 MB — force GC + alert
    checkInterval time.Duration // 30s
}

func (m *MemoryMonitor) Run(ctx context.Context) {
    ticker := time.NewTicker(m.checkInterval)
    for {
        select {
        case <-ticker.C:
            var stats runtime.MemStats
            runtime.ReadMemStats(&stats)
            allocMB := int64(stats.Alloc / 1024 / 1024)
            if allocMB > m.hardLimitMB {
                runtime.GC()
                // fire alert
            } else if allocMB > m.softLimitMB {
                // log warning
            }
        case <-ctx.Done():
            return
        }
    }
}
```

### Task 9.4: Goroutine Monitoring

**File:** Add to `src/firewall_engine/internal/health/memory_monitor.go` (or separate file)

```go
func monitorGoroutines(ctx context.Context, logger logging.Logger) {
    ticker := time.NewTicker(30 * time.Second)
    var lastCount int
    for {
        select {
        case <-ticker.C:
            count := runtime.NumGoroutine()
            if count > 10000 {
                logger.Error().Int("goroutines", count).Msg("GOROUTINE LEAK — count exceeds 10K")
            }
            if lastCount > 0 && count > lastCount*2 {
                logger.Warn().Int("goroutines", count).Int("previous", lastCount).Msg("Goroutine count doubled")
            }
            lastCount = count
        case <-ctx.Done():
            return
        }
    }
}
```

### Task 9.5: Resource Limits

**File:** `src/firewall_engine/internal/config/firewall_config.go`
**Also:** `src/firewall_engine/cmd/main.go`

Add configurable resource limits:
```toml
# In firewall.toml
[limits]
max_db_connections = 20
max_grpc_streams = 10
max_goroutines = 5000
max_memory_mb = 1024
max_alert_queue = 10000
max_verdict_queue = 50000
```

Apply at startup:
- DB pool: `SetMaxOpenConns(20)`, `SetMaxIdleConns(5)`
- gRPC: `grpc.MaxConcurrentStreams(10)`
- Alert queue: bounded channel `make(chan Alert, 10000)`

### Task 9.6: Windows Service Integration

**File:** New: `src/firewall_engine/cmd/service.go`

Use `golang.org/x/sys/windows/svc` package:

```go
// +build windows

type firewallService struct{}

func (s *firewallService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
    changes <- svc.Status{State: svc.StartPending}
    // ... start engine ...
    changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
    // ... wait for stop signal ...
    changes <- svc.Status{State: svc.StopPending}
    // ... graceful shutdown ...
    return
}
```

Install command:
```
sc create SafeOpsFirewall binPath= "D:\SafeOpsFV2\bin\firewall-engine\firewall-engine.exe" start= auto
sc failure SafeOpsFirewall reset= 86400 actions= restart/5000/restart/10000/restart/30000
```

Also integrate Windows Event Log:
```go
import "golang.org/x/sys/windows/svc/eventlog"

elog, _ := eventlog.Open("SafeOpsFirewall")
elog.Info(1, "Firewall engine started")
```

### Task 9.7: Startup Ordering

**File:** `src/firewall_engine/cmd/main.go`

Current: `WaitForAPI(10s)` before initial domain sync — if SafeOps not ready, defers to hot-reload.

Improve:
1. On startup, check if SafeOps gRPC (50051) is reachable
2. If not, start a background goroutine that retries every 5s
3. Once connected, perform initial domain sync
4. Log clear warnings during the "waiting for SafeOps" state
5. Engine should still process local rules (detection, rules.toml) while waiting

---

## 6. Phase 10B: Wire Up Web UI

**Status: CRITICAL BLOCKER — API server code exists but is NOT started in main.go**
**Priority: HIGH**

### The Problem

The Web UI API server (`internal/api/server.go`) is fully implemented with 30+ endpoints and embedded SPA, but `main.go` never calls `api.NewServer()` or starts the HTTP listener.

### Task 10B.1: Start Web UI Server in main.go

**File:** `src/firewall_engine/cmd/main.go`

Find the section where other servers start (health server ~line 756, gRPC management ~line 780) and add:

```go
// Start Web UI API server
apiServer, err := api.NewServer(api.ServerConfig{
    Address:        cfg.Servers.WebAPIAddress, // ":8443"
    Logger:         logger,
    AlertManager:   alertManager,
    SecurityMgr:    securityManager,
    DomainFilter:   domainFilter,
    GeoIPChecker:   geoipChecker,
    RuleEngine:     ruleEngine,
    HotReloader:    hotReloader,
    BlocklistSync:  blocklistSync,
    ThreatIntel:    threatIntelClient,
    DetectionCfg:   detectionConfig,
    BlocklistCfg:   blocklistConfig,
})
if err != nil {
    logger.Error().Err(err).Msg("Failed to create Web UI server")
} else {
    go func() {
        if err := apiServer.Start(); err != nil {
            logger.Error().Err(err).Msg("Web UI server error")
        }
    }()
    defer apiServer.Shutdown()
    logger.Info().Str("address", cfg.Servers.WebAPIAddress).Msg("Web UI started")
}
```

**IMPORTANT:** You need to check what `api.NewServer()` actually accepts as parameters. Read `internal/api/server.go` to see the constructor signature and match the fields to what's available in main.go. The above is pseudocode — adapt to the real API.

### Task 10B.2: Wire Component References

The API handlers need references to live engine components to return real data. Check each handler file:

| Handler | Needs Reference To |
|---------|-------------------|
| `dashboard.go` | AlertManager, SecurityManager, DomainFilter, GeoIP, HotReloader |
| `alerts.go` | AlertManager |
| `security.go` | SecurityManager (BanManager) |
| `rules.go` | DomainFilter, GeoIPChecker, DetectionConfig, BlocklistConfig |
| `tickets.go` | (self-contained with in-memory store) |
| `health.go` | All components for health check |
| `websocket.go` | EventHub (receives events from all components) |

If the handlers currently return mock data, replace with real component calls.

### Task 10B.3: WebSocket Event Wiring

**File:** `src/firewall_engine/internal/api/websocket.go`

The EventHub exists but needs to receive events from:
- SecurityManager: `ban_created`, `ban_removed` events
- AlertManager: `alert_created`, `alert_triaged` events
- HotReloader: `config_reloaded` event
- DomainFilter: `domain_blocked`, `domain_unblocked` events

Add event hooks in main.go or each component:
```go
securityManager.OnBan(func(ban Ban) {
    apiServer.EventHub.Broadcast("ban_created", ban)
})
alertManager.OnAlert(func(alert Alert) {
    apiServer.EventHub.Broadcast("alert_created", alert)
})
```

---

## 7. Phase 11: Web UI Polish & Completion

**Priority: LOW-MEDIUM (functional first, polish later)**

### Current Frontend Pages (all built, may need real-data wiring)

1. **Dashboard** (`/dashboard`) — KPI grid, security subsystem stats, live threat feed
2. **Alerts & Triage** (`/alerts`) — Searchable table, detail modal, triage buttons, threat intel links
3. **Domain Rules** (`/rules/domains`) — Blocked/whitelisted domains, category toggles
4. **IP Rules** (`/rules/ips`) — Blocked/whitelisted IPs and CIDRs
5. **GeoIP Policy** (`/rules/geoip`) — Mode toggle, country/ASN lists
6. **Detection Config** (`/rules/detection`) — All TOML thresholds editable in UI
7. **Active Bans** (`/bans`) — Ban table, manual ban, unban
8. **Tickets** (`/tickets`) — Incident tracking
9. **System Status** (`/system`) — Engine status, memory, goroutines, component health

### Task 11.1: Verify All Endpoints Return Real Data

Test each API endpoint returns actual data (not mock/empty):

```bash
# Start both engines, then test:
curl http://localhost:8443/api/v1/dashboard/stats
curl http://localhost:8443/api/v1/dashboard/threats
curl http://localhost:8443/api/v1/alerts
curl http://localhost:8443/api/v1/security/bans
curl http://localhost:8443/api/v1/security/stats
curl http://localhost:8443/api/v1/rules/domains
curl http://localhost:8443/api/v1/rules/detection
curl http://localhost:8443/api/v1/rules/geoip
curl http://localhost:8443/api/v1/tickets
curl http://localhost:8443/api/v1/health
curl http://localhost:8443/api/v1/status
```

### Task 11.2: Fix Any Broken Handlers

Some handler files may be stubs (e.g., `handlers.go` appeared empty during audit). Check each:
- `alerts.go` — ensure it reads from AlertManager, not mock data
- `security.go` — ensure bans come from real BanManager
- `dashboard.go` — ensure stats are aggregated from real components
- `rules.go` — ensure domain/IP/GeoIP CRUD actually modifies live config + triggers hot-reload

### Task 11.3: Add Verdict Log Viewer

**New endpoint:** `GET /api/v1/logs/verdicts?limit=100&offset=0&action=DROP`

Read from `bin/logs/firewall-verdicts.jsonl` and return parsed JSON:
```json
{
    "verdicts": [
        {"ts": "2026-02-18T10:30:00Z", "src": "1.2.3.4", "sp": 54321, "dst": "5.6.7.8", "dp": 443, "proto": "TCP", "action": "DROP", "detector": "ddos", "domain": "", "reason": "SYN flood"}
    ],
    "total": 1500,
    "page": 1
}
```

### Task 11.4: Add Real-Time Packet Counter Widget

The dashboard should show live packets/sec stats. Add a lightweight endpoint:

`GET /api/v1/stats/realtime` → returns current packet rates

Or use the existing WebSocket to push stats every 1 second:
```json
{"type": "stats_update", "data": {"pps_in": 15000, "pps_out": 14500, "blocked": 23, "alerts": 2}}
```

---

## 8. Build & Test Commands

### Building

```bash
# Firewall Engine (the decision engine)
cd D:\SafeOpsFV2\src\firewall_engine && go build -o ../../bin/firewall-engine/firewall-engine.exe ./cmd/

# Security Test Tool
cd D:\SafeOpsFV2\src\firewall_engine && go build -o ../../bin/firewall-engine/sectest.exe ./cmd/sectest/

# SafeOps Engine (the packet capture engine) — only if you modify safeops-engine code
cd D:\SafeOpsFV2\src\safeops-engine && go build -o ../../bin/safeops-engine/safeops-engine.exe ./cmd/
```

### Running (MUST be Administrator)

```powershell
# Terminal 1: Start SafeOps Engine first
cd D:\SafeOpsFV2\bin\safeops-engine
.\safeops-engine.exe

# Terminal 2: Start Firewall Engine (after SafeOps is ready)
cd D:\SafeOpsFV2\bin\firewall-engine
.\firewall-engine.exe

# Terminal 3: Run security tests
cd D:\SafeOpsFV2\bin\firewall-engine
.\sectest.exe
```

### Network Simulator (for testing detectors)

```bash
cd D:\SafeOpsFV2\tools\netsim
go run . --test syn-flood      # DDoS test (use single port!)
go run . --test port-scan      # Port scan test
go run . --test brute-force    # Brute force test
go run . --test dns-tunnel     # DNS tunneling test
```

### Config Locations

Firewall engine reads configs from `bin/firewall-engine/configs/`:
- `firewall.toml` — main config
- `detection.toml` — detection thresholds
- `blocklist.toml` — domain/IP blocking
- `geoip.toml` — geographic policy
- `rules.toml` — custom rules
- `domains.txt` — blocked domain list
- `whitelist_domains.txt` — whitelisted domains
- `blocked_ips.txt` — blocked IPs
- `blocked_ports.txt` — VPN ports to block
- `doh_servers.txt` — DoH resolver IPs

---

## 9. Key File Map

### Firewall Engine (src/firewall_engine/)

| File | Lines | Purpose |
|------|-------|---------|
| `cmd/main.go` | ~941 | Main entry — startup, wiring, packet loop |
| `cmd/sectest/main.go` | ~500 | Security test tool (16/17 passing) |
| `internal/api/server.go` | ~697 | Web UI REST API (Fiber) — **NOT STARTED IN MAIN** |
| `internal/api/dashboard.go` | ~432 | Dashboard KPI endpoints |
| `internal/api/web/index.html` | 643 | Embedded SPA shell |
| `internal/api/web/app.js` | 1109 | Frontend logic (vanilla JS) |
| `internal/api/web/index.css` | 1158 | Dark theme CSS |
| `internal/security/manager.go` | ~300 | Security detector orchestrator |
| `internal/domain/filter.go` | ~400 | Domain blocking logic |
| `internal/rules/engine.go` | ~250 | Custom TOML rule engine |
| `internal/integration/blocklist_sync.go` | ~150 | HTTP domain sync to SafeOps |
| `internal/integration/safeops_grpc_client.go` | ~200 | gRPC client (needs auto-reconnect) |
| `internal/hotreload/reloader.go` | ~300 | Config hot-reload orchestrator |
| `internal/logging/verdict_logger.go` | ~200 | SOC verdict JSONL writer |
| `internal/alerting/manager.go` | ~250 | Alert dispatch + throttle |
| `internal/config/detection_config.go` | ~200 | Detection threshold structs |
| `internal/config/firewall_config.go` | ~250 | Main config structs |

### SafeOps Engine (src/safeops-engine/)

| File | Lines | Purpose |
|------|-------|---------|
| `pkg/engine/engine.go` | ~800 | Core packet processing (fast/slow path, flow cache) |
| `pkg/control/server.go` | ~300 | HTTP control API (domain sync, health) |
| `pkg/blockpage/server.go` | ~700 | HTTPS block page (dynamic TLS, CA install, /ca page) |
| `pkg/grpc/server.go` | ~200 | gRPC metadata stream |

---

## 10. Configuration Files Reference

### detection.toml — Key Thresholds

| Detector | Parameter | Value | Meaning |
|----------|-----------|-------|---------|
| DDoS | syn_rate_threshold | 1000 pps | SYN flood detection |
| DDoS | udp_rate_threshold | 5000 pps | UDP flood detection |
| DDoS | icmp_rate_threshold | 100 pps | ICMP flood detection |
| DDoS | ban_duration_minutes | 30 | Initial ban (escalates 4x) |
| Rate Limit | default_rate | 1000 pps | Per-IP packet limit |
| Rate Limit | burst_size | 2000 | Burst allowance |
| Rate Limit | global_rate | 100000 pps | System-wide limit |
| Brute Force | SSH max_failures | 5 in 120s | SSH detection |
| Brute Force | RDP max_failures | 3 in 60s | RDP detection |
| Port Scan | port_threshold | 100 ports | Unique ports in 10s |
| Port Scan | sequential_threshold | 20 ports | Sequential scan detection |
| Baseline | deviation_threshold | 3.0 | 3σ above baseline |

### rules.toml — 27 Custom Rules

- 8 VPN/anonymizer detection rules (OpenVPN, WireGuard, IPSec, PPTP, Tor, SoftEther)
- 3 DoH bypass detection (Google, Cloudflare, Quad9)
- 6 network protocol security (LLMNR, NetBIOS, SMB, Telnet, DNS zone xfer, connection burst)
- 3 suspicious outbound (IRC, reverse shells, crypto mining)
- All LAN-exempt where appropriate (IPSec uses `src_not_cidr`)

### blocklist.toml — Domain/IP Blocking

- 8 domain categories (all off by default): social_media, streaming, gaming, ads, trackers, adult, gambling, vpn_proxy
- CDN enforcement: DNS-only redirect for CDN-hosted domains
- Threat intel thresholds: IP=50, Domain=50
- DNS redirect to 127.0.0.1 (block page server)
- Block cache TTL: 120 seconds

### geoip.toml — Geographic Policy

- Mode: deny_list (block specified countries)
- No countries enabled by default
- ASN blocking available but disabled
- Private networks whitelisted (10/8, 172.16/12, 192.168/16)

---

## 11. Package Architecture

```
src/firewall_engine/
├── cmd/
│   ├── main.go                    # Entry point (~941 lines)
│   └── sectest/main.go            # Security test tool
├── configs/                       # Source TOML configs
├── internal/
│   ├── alerting/        (6 files) # Alert manager, writer, DB logger, throttle
│   ├── api/            (10 files) # REST + WebSocket server, all handlers
│   │   └── web/         (3 files) # Embedded SPA (HTML+JS+CSS)
│   ├── blocklist/       (4 files) # Domain/IP blocklist management
│   ├── cache/           (6 files) # Verdict cache (LRU+TTL)
│   ├── config/         (10 files) # TOML loader, all config structs
│   ├── connection/      (5 files) # Connection tracking + flow cache
│   ├── domain/          (2 files) # Domain filter + CDN allowlist
│   ├── enforcement/     (8 files) # Verdict execution (DROP, RST, redirect)
│   ├── filtering/       (5 files) # IP/port/protocol/zone filtering
│   ├── geoip/           (1 file)  # GeoIP checker
│   ├── health/          (5 files) # Health monitoring
│   ├── hotreload/       (2 files) # Config hot-reload + file watcher
│   ├── inspection/      (3 files) # Rule inspection orchestration
│   ├── inspector/       (5 files) # Packet inspector + fastpath
│   ├── integration/     (6 files) # SafeOps gRPC/HTTP, threat intel, WFP
│   ├── logging/         (8 files) # Verdict JSONL + structured logging
│   ├── metrics/         (6 files) # Prometheus metrics
│   ├── nat/             (4 files) # NAT (SNAT, DNAT, masquerade)
│   ├── rules/           (2 files) # Custom TOML rule engine
│   ├── security/        (5 files) # DDoS, port scan, brute force, bans
│   ├── stateful_inspection/ (4 files) # TCP/UDP state machines
│   ├── storage/         (1 file)  # PostgreSQL access
│   ├── threatintel/     (5 files) # Threat cache + decision logic
│   ├── validation/      (6 files) # Config validation
│   ├── wfp/            (18 files) # Windows Filtering Platform
│   └── zone_manager/    (4 files) # Network zone management
├── pkg/
│   ├── grpc/            (8 files) # gRPC management API
│   └── models/          (7 files) # Shared data models
└── ~200 total Go files
```

---

## 12. Testing Checklist

After completing all phases, verify:

### Functionality Tests
- [ ] Both engines start without errors (SafeOps first, then Firewall)
- [ ] Domain blocking works (add domain to domains.txt → site becomes unreachable)
- [ ] Block page shows for HTTP blocked sites
- [ ] Block page shows for HTTPS blocked sites (CA installed locally)
- [ ] TCP RST sent for HTTPS blocked sites (without CA)
- [ ] DNS queries for blocked domains return 127.0.0.1
- [ ] DoH resolver IPs (8.8.8.8 etc.) blocked on port 443
- [ ] VPN ports blocked (but LAN traffic exempt)
- [ ] Hot-reload works (modify domains.txt → blocking updates within seconds)
- [ ] Hot-reload re-syncs domains to SafeOps via HTTP

### Security Tests (sectest.exe — should pass 16/17)
- [ ] DDoS SYN flood detection
- [ ] DDoS UDP flood detection
- [ ] DDoS ICMP flood detection
- [ ] Rate limiting enforcement
- [ ] Brute force detection (SSH, RDP)
- [ ] Port scan detection (random + sequential)
- [ ] Traffic baseline deviation alert
- [ ] Threat intel IP blocking
- [ ] Threat intel domain blocking
- [ ] Custom rule matching (VPN, DoH, reverse shell)
- [ ] Ban escalation (L1→L2→L3)
- [ ] GeoIP country blocking

### Performance Tests
- [ ] Internet speed > 350 Mbps with engines running (was 400 before, 180 with bug)
- [ ] No LAN connectivity issues
- [ ] Memory stays under 512 MB after 1 hour
- [ ] Goroutine count stable (not growing)
- [ ] pprof accessible at :6060

### Web UI Tests
- [ ] Dashboard loads at http://localhost:8443
- [ ] All 9 pages render correctly
- [ ] Alert triage works (acknowledge, escalate, dismiss, resolve)
- [ ] Domain add/remove updates blocking in real-time
- [ ] Ban/unban works from UI
- [ ] Detection thresholds editable from UI
- [ ] WebSocket events appear in real-time
- [ ] System status shows correct memory/goroutines/uptime

### Production Hardening Tests
- [ ] Kill SafeOps → Firewall auto-reconnects when SafeOps restarts
- [ ] Kill DB → Firewall continues with cached data, reconnects when DB returns
- [ ] Memory monitoring logs warnings at soft limit
- [ ] Goroutine monitoring logs warnings at threshold
- [ ] Graceful shutdown completes within 10 seconds
- [ ] Windows service installs and starts/stops correctly

---

## Priority Order for Implementation

1. **Phase 10B** (Wire Up Web UI) — highest impact, already 95% built
2. **Phase 9** (Production Hardening) — critical for reliability
3. **Phase 8** (Performance) — optimization, do after functional completion
4. **Phase 11** (UI Polish) — last, cosmetic

---

## PostgreSQL Reference

```
Host: localhost:5432
Databases: threat_intel_db, safeops_network, safeops
Users: safeops, threat_intel_app, dhcp_server, dns_server
Password (all): admin
psql: "C:\Program Files\PostgreSQL\16\bin\psql.exe"
```

---

## Quick Start Checklist for New Session

1. Read this document first
2. Read `C:\Users\02arj\.claude\projects\D--SafeOpsFV2\memory\MEMORY.md` for critical rules
3. Start with Phase 10B (wire up Web UI in main.go)
4. Build: `cd src/firewall_engine && go build -o ../../bin/firewall-engine/firewall-engine.exe ./cmd/`
5. Test: Run both engines as admin, open http://localhost:8443
6. Move to Phase 9, then Phase 8, then Phase 11
