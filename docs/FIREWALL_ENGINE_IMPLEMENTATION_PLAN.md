# Firewall Engine Implementation Plan

> **Architecture:** SafeOps Engine handles DPI (DNS parsing, TLS SNI extraction, HTTP Host header). It sends extracted `pkt.Domain`, `pkt.DomainSource` ("DNS"/"SNI"/"HTTP"), and protocol metadata via gRPC to the Firewall Engine. The Firewall Engine makes policy decisions and sends verdicts back (`ALLOW`, `DROP`, `BLOCK/RST`, `REDIRECT`).

> **Config Philosophy:** All configuration lives in `configs/` directory (TOML files + text lists). Config files are soft-coded — the binary discovers them relative to its own executable path. All config files can be modified through the Web UI (Phase 10) and hot-reloaded at runtime (Phase 7) without restarting the engine.

---

## Phase 0: Fix gRPC Performance ✅ COMPLETE

<details>
<summary>Click to expand (28 sub-tasks done)</summary>

### 0.1 SafeOps Engine Server-Side (server.go) ✅
- 0.1.1 `sync.Map` for lock-free verdict cache ✅
- 0.1.2 `atomic.Value` snapshot for subscriber check ✅
- 0.1.3 `sync.Pool` byte buffer for cache key ✅
- 0.1.4 Pre-computed subscriber filter flags ✅
- 0.1.5 50K subscriber channel buffer ✅
- 0.1.6 `int64` unix nano for expiry ✅
- 0.1.7 Removed hot-path logging ✅
- 0.1.8 Pre-built cacheKey passed through ✅
- 0.1.9 Direct byte comparison for HTTP methods ✅
- 0.1.10 Build verified ✅

### 0.2 Firewall Engine Client-Side (client.go) ✅
- 0.2.1 Worker pool architecture ✅
- 0.2.2 100K buffered packet channel ✅
- 0.2.3 `atomic.Bool` connection state ✅
- 0.2.4 gRPC keepalive parameters ✅
- 0.2.5 Exponential backoff reconnection ✅
- 0.2.6 3-return `GetClientStats()` ✅

### 0.3–0.5 Integration + Build ✅

</details>

---

## Phase 1: Config Files & Alert System ✅ COMPLETE

<details>
<summary>Click to expand (30 sub-tasks done)</summary>

### 1.1 Config Files Created ✅
- `configs/firewall.toml` — engine, safeops, database, performance, logging, servers ✅
- `configs/detection.toml` — DDoS, rate limit, brute force, port scan, anomaly, baseline, whitelist ✅
- `configs/geoip.toml` — policy mode, deny/allow lists, ASN block, datacenter, whitelist ✅
- `configs/domains.txt` — domain blocklist (one per line, hot-reloadable) ✅
- `configs/whitelist.txt` — IP/CIDR whitelist ✅

### 1.2 Config Loaders Created ✅
- `internal/config/firewall_config.go` — all structs matching TOML ✅
- `internal/config/detection_config.go` — detection threshold structs + Parse() ✅
- `internal/config/geoip_config.go` — GeoIP policy structs + Parse() ✅
- `internal/config/loader_unified.go` — LoadAll() + AllConfig struct ✅
- `internal/config/paths.go` — ResolveConfigDir() + ResolveDataDir() ✅

### 1.3 Alert System Created ✅
- `internal/alerting/alert.go` — Alert struct, severity/type enums, AlertBuilder ✅
- `internal/alerting/template.go` — JSON + one-line formatters ✅
- `internal/alerting/writer.go` — daily rotation file writer ✅
- `internal/alerting/throttle.go` — dedup by srcIP+alertType ✅
- `internal/alerting/manager.go` — central dispatcher ✅

</details>

---

## Phase 2: Threat Intel DB Integration ✅ COMPLETE

<details>
<summary>Click to expand (24 sub-tasks done)</summary>

### 2.1–2.6 All Complete ✅
- `internal/threatintel/db.go` — PostgreSQL connection pool ✅
- `internal/threatintel/ip_cache.go` — 37K blocked IPs in sync.Map ✅
- `internal/threatintel/domain_cache.go` — 1.28M domains in sync.Map ✅
- `internal/threatintel/refresher.go` — background refresh loop ✅
- `internal/threatintel/decision.go` — unified threat check ✅
- Wired into `cmd/main.go` ✅

</details>

---

## Phase 3: Security Features ✅ COMPLETE

<details>
<summary>Click to expand (40 sub-tasks done)</summary>

### 3.1–3.2 Rate Limiting + DDoS ✅
- `internal/rate_limiting/token_bucket.go` — lock-free atomic token bucket ✅
- `internal/rate_limiting/per_ip_limiter.go` — per-IP rate tracking ✅
- `internal/rate_limiting/rate_limiter.go` — whitelist-aware wrapper ✅
- `internal/rate_limiting/ddos_protection.go` — SYN/UDP/ICMP flood detection ✅

### 3.3–3.6 Detection Algorithms ✅
- `internal/security/brute_force.go` — failed connection tracking per IP+port ✅
- `internal/security/port_scan.go` — random + sequential scan detection ✅
- `internal/security/anomaly_detector.go` — TCP flags, packet size, beaconing/C2 ✅
- `internal/security/baseline.go` — EMA traffic baseline with z-score ✅

### 3.7–3.8 Orchestration ✅
- `internal/security/ban_manager.go` — exponential ban escalation ✅
- `internal/security/manager.go` — central security orchestrator ✅
- Wired into `cmd/main.go` packet handler ✅
- Build verified ✅

</details>

---

## Phase 4: Domain Filtering & Protocol-Aware Blocking ✅ COMPLETE

**Goal:** Block domains from config blocklist + categories, with protocol-aware verdicts (DNS→REDIRECT, SNI→BLOCK, HTTP→BLOCK). CDN-aware enforcement. Threat intel domain integration.

### 4.1 Domain Filter ✅
- [x] `internal/domain/filter.go` — domain filter with config list + category matching
  - [x] Load `domains.txt` config blocklist with auto-wildcard (`evil.com` → also `*.evil.com`)
  - [x] Category matchers: social_media, streaming, gaming, ads, trackers
  - [x] Protocol-aware verdicts: DNS→REDIRECT, SNI→BLOCK, HTTP→BLOCK
  - [x] `Check(domain, domainSource) → FilterResult`
  - [x] `Reload()` for hot-reload
  - [x] `AddDomain()` for runtime API
  - [x] `SetBlockedCategories()` for runtime updates
  - [x] Stats: totalChecks, totalBlocks, dnsBlocks, sniBlocks, httpBlocks
  - [x] Alert firing on block via alerting.Manager

### 4.2 Wire Domain Filter into Packet Handler ✅
- [x] In `cmd/main.go` section 11 (packet handler), add domain check after security checks
  - [x] Check `pkt.Domain` against `domainFilter.Check(pkt.Domain, pkt.DomainSource)`
  - [x] If blocked: map FilterResult.Action to VerdictType
    - [x] `ActionRedirect` → `VerdictType_REDIRECT` (DNS queries)
    - [x] `ActionBlock` → `VerdictType_BLOCK` (SNI/HTTP → TCP RST)
    - [x] `ActionDrop` → `VerdictType_DROP`
  - [x] Send verdict back to SafeOps Engine via `sendVerdict()`
  - [x] Log blocked domain with source protocol
  - [x] Skip domain check if `pkt.Domain` is empty

### 4.3 CDN Allowlist (Prevent Collateral Blocking) ✅
- [x] Create `internal/domain/cdn_allowlist.go`
  - [x] 12 CDN providers: Cloudflare, AWS CloudFront, Akamai, Fastly, Google CDN, Azure, StackPath, Limelight, KeyCDN, Bunny, Incapsula, Sucuri
  - [x] `Check(domain) → CDNCheckResult{IsCDN, Provider}` — O(1) exact + suffix matching
  - [x] When domain matches CDN + blocklist → DNS redirect only (never RST CDN IPs)
  - [x] Thread-safe with `sync.RWMutex`, runtime `AddProvider()`

### 4.4 Wire Threat Intel Domain Check ✅
- [x] `domainFilter.SetThreatDecision(threatDecision)` connects threat intel domain cache
- [x] Pipeline order: CDN check → config blocklist → category → threat intel DB
- [x] If any match → block with appropriate protocol verdict
- [x] Threat intel match = higher severity alert; CDN threat = CRITICAL with restricted enforcement

### 4.5 Build & Verify Phase 4 ✅
- [x] `go build ./cmd/` — compiles clean
- [x] `go vet` — zero warnings
- [x] Binary deployed to `bin/firewall-engine/firewall-engine.exe`

---

## Phase 5: GeoIP Blocking ✅ COMPLETE

**Goal:** Country/ASN-based blocking using PostgreSQL `ip_geolocation` table (4.5M rows)

### 5.1 GeoIP Infrastructure (DONE — exists already)
- [x] `internal/config/geoip_config.go` — config structs + `ParsedGeoPolicy`
- [x] `configs/geoip.toml` — deny/allow list, ASN block, datacenter, whitelist
- [x] `internal/objects/geo_object.go` — GeoObjectManager + GeoResolver interface
- [x] `internal/objects/postgres_geo_resolver.go` — PostgreSQL GeoIP resolver + cache

### 5.2 GeoIP Pipeline Integration ✅
- [x] Create `internal/geoip/checker.go` — high-level GeoIP check
  - [x] Takes `ParsedGeoPolicy` + `GeoResolver` + `alerting.Manager`
  - [x] `Check(srcIP string) → GeoResult`
    - [x] Skip private/RFC1918 IPs (always allowed)
    - [x] Check whitelist (bypass all geo checks)
    - [x] Lookup country + ASN via resolver (cached)
    - [x] Check deny_list / allow_list mode
    - [x] Check ASN blocking
    - [x] Check foreign datacenter flag (alert only, no block)
  - [x] `GeoResult{Blocked, CountryCode, ASN, ASNNumber, Reason, IsWhitelisted, IsPrivate, IsForeignDC, ...}`
  - [x] Fire GEO_BLOCK alert on block (MEDIUM severity)
  - [x] In-memory LRU cache: 100K entries, 1 hour TTL, background cleanup every 5min
  - [x] Fail-open on lookup error (allow traffic)
  - [x] `Stop()` for graceful shutdown

### 5.3 GeoIP Alert Enrichment ✅
- [x] `Enrich(srcIP) → *alerting.GeoInfo` for enriching any alert with geo data
  - [x] When `geoip.enrich_alerts = true` (from config)
  - [x] Returns `country_code`, `asn`, `asn_org` metadata
  - [x] Uses same cache as Check() (no extra DB queries)

### 5.4 Wire into Packet Handler ✅
- [x] In `cmd/main.go`, add GeoIP check between port scan and threat intel
  - [x] Initialize PostgresGeoResolver from `threatDB.Pool()`
  - [x] Parse `geoip.toml` into `ParsedGeoPolicy`
  - [x] Create GeoIP Checker with resolver + policy + alertMgr
  - [x] If GeoIP blocks → send DROP verdict + alert (600s cache TTL)
  - [x] `geoChecker.Stop()` in shutdown sequence
  - [x] Banner shows mode, countries, ASNs, enrich_alerts
  - [x] Stats show checks, blocks, cache hits
  - [x] Final stats show full breakdown

### 5.5 Build & Verify Phase 5 ✅
- [x] `go build ./cmd/` — compiles clean
- [x] `go vet` — zero warnings
- [x] Binary deployed to `bin/firewall-engine/firewall-engine.exe`

---

## Phase 6: Blocklist TOML Config (Web-Updatable) ✅ COMPLETE

**Goal:** Create a unified `blocklist.toml` config file for all blocking policies. This file can be edited manually OR updated through the Web UI (Phase 10). All blocking configs are centralized here.

### 6.1 Create `configs/blocklist.toml` ✅
- [x] Sections: `[domains]`, `[domains.categories]`, `[domains.cdn]`, `[ips]`, `[threat_intel]`, `[geo]`, `[enforcement]`, `[whitelist]`
- [x] Per-category boolean toggles (social_media, streaming, gaming, ads, trackers, adult, gambling, vpn_proxy)
- [x] CDN enforcement config (enforce_dns_only, custom_cdn_domains)
- [x] Manual IP/CIDR blocklist, threat intel thresholds (IP + domain + anonymizer)
- [x] Geo quick-add overrides (extra_blocked_countries, extra_blocked_asns)
- [x] Global whitelist (IPs, CIDRs, domains) that bypass ALL blocking
- [x] Enforcement settings (dns_redirect_ip, block_cache_ttl_seconds, log_all_blocks)

### 6.2 Create `internal/config/blocklist_config.go` ✅
- [x] `BlocklistConfig` top-level struct with 6 sections
- [x] `BlocklistDomainsConfig`, `BlocklistCategoriesConfig`, `BlocklistCDNConfig`
- [x] `BlocklistIPsConfig`, `BlocklistThreatIntelConfig`
- [x] `BlocklistGeoConfig` with `NormalizedExtraCountries()` validation
- [x] `BlocklistEnforcementConfig`, `BlocklistWhitelistConfig`
- [x] `ParsedBlocklist` — pre-computed runtime lookup structures with O(1) IP/domain checks
- [x] `Parse(configDir)` — validates all IPs, CIDRs, thresholds; clamps values to 0-100
- [x] `IsIPWhitelisted()`, `IsDomainWhitelisted()` (with parent domain matching), `IsIPManuallyBlocked()`
- [x] `DefaultBlocklistConfig()`, `LoadBlocklistConfigFromFile()` — TOML loader with fallback defaults
- [x] `EnabledCategories()` — converts boolean toggles to category name list

### 6.3 Integrate Blocklist Config into Pipeline ✅
- [x] `AllConfig.Blocklist *BlocklistConfig` added to `loader_unified.go`
- [x] `LoadAll()` loads `blocklist.toml` from config dir
- [x] `ParsedBlocklistPolicy()` convenience method on AllConfig
- [x] `DomainsFilePath()` now reads from blocklist config
- [x] `BlocklistFilePath()` returns path to blocklist.toml

### 6.4 Rewire main.go ✅
- [x] Parses `ParsedBlocklist` at startup, prints blocklist path
- [x] Section 2b: Threat intel respects `parsedBlocklist.ThreatIntelEnabled` master switch
- [x] Section 2d: Domain filter uses `parsedBlocklist.BlockedCategories` (not empty list)
- [x] Section 2d: Custom CDN domains loaded from blocklist config
- [x] Section 2e: GeoIP merges `extra_blocked_countries` + `extra_blocked_asns` from blocklist
- [x] Section 2e: GeoIP respects `parsedBlocklist.GeoEnabled` master switch
- [x] Section 11: Global whitelist bypass (whitelisted IPs skip all blocking → goto inspectPacket)
- [x] Section 11: Manual IP blocklist check (blocklist.toml [ips])
- [x] Section 11: Domain whitelist check (blocklist.toml [whitelist].domains)
- [x] Section 11: Block cache TTL from `parsedBlocklist.BlockCacheTTLSeconds`
- [x] Banner: Full blocklist config section showing all toggles + counts

### 6.5 Web UI Endpoints (API contract — prep for Phase 10)
Endpoints to implement in Phase 10:
- `GET /api/v1/blocklist` — returns current blocklist as JSON
- `PUT /api/v1/blocklist` — updates entire blocklist config
- `POST /api/v1/blocklist/domains` — add domain
- `DELETE /api/v1/blocklist/domains/:domain` — remove domain
- `PUT /api/v1/blocklist/categories` — toggle categories
- `PUT /api/v1/blocklist/geo` — update geo overrides
- Changes written to `blocklist.toml` → picked up by hot-reload (Phase 7)

### 6.6 Deploy & Verify ✅
- [x] `blocklist.toml` deployed to `bin/firewall-engine/configs/`
- [x] `go build ./cmd/` — compiles clean
- [x] `go vet ./cmd/ ./internal/config/` — clean

---

## Phase 7: Hot-Reload

**Goal:** Change any config file → rules update instantly without restart. This is essential for the Web UI workflow (Web UI writes to config files → hot-reload picks up changes).

### 7.1 File Watcher
- [ ] Create `internal/hotreload/watcher.go`
  - [ ] fsnotify watcher on `configs/` directory
  - [ ] Debounce: 500ms delay (catch partial writes / save-rename patterns)
  - [ ] Watch ALL config files:
    - [ ] `firewall.toml` → engine settings
    - [ ] `detection.toml` → security thresholds
    - [ ] `geoip.toml` → geo policy
    - [ ] `blocklist.toml` → all blocklists
    - [ ] `domains.txt` → domain list
    - [ ] `whitelist.txt` → IP whitelist
  - [ ] File change → identify which file → call appropriate reload handler

### 7.2 Reload Handlers
- [ ] Create `internal/hotreload/reloader.go`
  - [ ] `ReloadBlocklist(path) error` — reload blocklist.toml
    - [ ] Parse new config → validate → swap atomic
    - [ ] Update domain filter categories
    - [ ] Update threat intel thresholds
    - [ ] Update geo policy
  - [ ] `ReloadDomains(path) error` — reload domains.txt
    - [ ] Call `domainFilter.Reload()`
    - [ ] Log added/removed count
  - [ ] `ReloadWhitelist(path) error` — reload whitelist.txt
    - [ ] Update security manager whitelist
    - [ ] Update rate limiter whitelist
  - [ ] `ReloadDetection(path) error` — reload detection.toml
    - [ ] Update DDoS thresholds
    - [ ] Update rate limit settings
    - [ ] Update brute force / port scan settings
  - [ ] `ReloadGeoIP(path) error` — reload geoip.toml
    - [ ] Re-parse policy
    - [ ] Update GeoIP checker
  - [ ] Each handler: backup → validate → load → swap → log

### 7.3 Rollback on Error
- [ ] Create `internal/hotreload/rollback.go`
  - [ ] On reload failure: keep last-good config active
  - [ ] Log error with details (parse error, validation error)
  - [ ] Fire INFO alert: "Config reload failed: {file} — {error}"
  - [ ] Never crash on bad config file

### 7.4 Domain List Sync with SafeOps Engine
- [ ] When `domains.txt` changes:
  - [ ] Diff current vs new domain list
  - [ ] For added domains: call SafeOps control API `POST /api/v1/block/domain`
  - [ ] For removed domains: call SafeOps control API `DELETE /api/v1/block/domain`
  - [ ] SafeOps Engine handles actual DNS/SNI/HTTP enforcement

### 7.5 Wire into main.go
- [ ] Initialize watcher after all components are loaded
- [ ] Register reload callbacks for each component
- [ ] Start watcher goroutine
- [ ] Stop watcher on shutdown

### 7.6 Build & Verify Phase 7
- [ ] `go build ./cmd/` — compiles clean
- [ ] Test: modify `domains.txt` → verify new domain blocked within 1s
- [ ] Test: modify `blocklist.toml` categories → verify change takes effect
- [ ] Test: modify `detection.toml` thresholds → verify new thresholds active
- [ ] Test: bad config file → verify no crash, keeps running with old config

---

## Phase 8: Performance Optimization

**Goal:** 100K+ packets/sec throughput, <1ms decision latency

### 8.1 Memory Pooling
- [ ] `sync.Pool` for packet metadata structs (avoid GC pressure)
  - [ ] Pool for `FilterResult` objects
  - [ ] Pool for `ThreatResult` objects
  - [ ] Pool for `SecurityVerdict` objects
- [ ] Pre-allocated alert buffers
- [ ] Measure: GC pause time before/after

### 8.2 Batch Processing
- [ ] Batch DB inserts for packet_logs (100 per batch or every 5s)
  - [ ] Background goroutine with buffered channel
  - [ ] Flush on buffer full OR timer
- [ ] Batch alert writes (flush every 1s or 100 alerts)
- [ ] Batch verdict sends (group multiple verdicts in one gRPC call if possible)

### 8.3 Lock Contention Audit
- [ ] Profile lock contention across all `sync.RWMutex` usage
  - [ ] Domain filter configMu / categoryMu
  - [ ] Ban manager bans map
  - [ ] Rate limiter maps
- [ ] Replace contended locks with `sync.Map` or sharded maps where needed
- [ ] Benchmark: measure p99 latency before/after

### 8.4 Profiling Endpoints
- [ ] pprof HTTP endpoint on internal port (e.g., :6060)
  - [ ] CPU profiling
  - [ ] Memory profiling
  - [ ] Goroutine dump
  - [ ] Block profiling
- [ ] Only enabled in dev/debug mode (from config)

### 8.5 Build & Verify Phase 8
- [ ] `go build ./cmd/` — compiles clean
- [ ] Benchmark: sustained 100K+ pps without drops
- [ ] Benchmark: p99 decision latency < 1ms
- [ ] Benchmark: memory usage stable over 1 hour

---

## Phase 9: Production Hardening

**Goal:** Graceful shutdown, error recovery, Windows service, resource limits

### 9.1 Graceful Shutdown
- [ ] OS signal handlers (SIGTERM, SIGINT, Ctrl+C on Windows)
  - [ ] Ordered shutdown sequence:
    1. Stop accepting new packets
    2. Flush pending verdicts
    3. Flush alert log buffer
    4. Stop hot-reload watcher
    5. Stop security manager goroutines
    6. Stop threat intel refresher
    7. Close DB connections
    8. Close gRPC connection
  - [ ] Timeout: max 10 seconds for graceful shutdown
  - [ ] Print final stats on shutdown

### 9.2 Error Recovery
- [ ] Auto-reconnect to SafeOps Engine on gRPC disconnect
  - [ ] Exponential backoff: 2s, 4s, 8s, 16s, 32s
  - [ ] Continue security monitoring during reconnect (cached data)
  - [ ] Alert: "SafeOps Engine connection lost — reconnecting"
- [ ] Auto-reconnect to PostgreSQL on connection loss
  - [ ] `lib/pq` handles reconnection via connection pool
  - [ ] Health check every 30s
  - [ ] Continue with cached threat intel if DB is down
  - [ ] Alert: "Database connection lost — using cached data"
- [ ] Fail-open policy: if all systems down, ALLOW traffic (configurable)

### 9.3 Resource Limits
- [ ] Memory monitoring
  - [ ] Track `runtime.MemStats` every 30s
  - [ ] Soft limit (1.5GB): trigger forced GC
  - [ ] Hard limit (2GB): evict oldest cache entries
  - [ ] Alert on approaching limits
- [ ] Goroutine monitoring
  - [ ] Track `runtime.NumGoroutine()` every 30s
  - [ ] Alert if > 10K goroutines (likely leak)
- [ ] Connection pool limits
  - [ ] Max DB connections from config
  - [ ] Max gRPC streams from config

### 9.4 Windows Service
- [ ] Install as Windows service via `sc create`
  - [ ] Service name: `SafeOpsFirewall`
  - [ ] Display name: `SafeOps Firewall Engine`
  - [ ] Start type: automatic
- [ ] Service control handler (start, stop, pause)
- [ ] Auto-recovery on failure
  - [ ] First failure: restart after 10s
  - [ ] Second failure: restart after 30s
  - [ ] Subsequent: restart after 60s
- [ ] Event log integration (Windows Event Log)

### 9.5 Build & Verify Phase 9
- [ ] `go build ./cmd/` — compiles clean
- [ ] Test: kill SafeOps Engine → firewall reconnects
- [ ] Test: stop PostgreSQL → firewall uses cached data
- [ ] Test: Ctrl+C → ordered shutdown, final stats printed
- [ ] Test: install as service → auto-start on boot

---

## Phase 10: Web UI Backend API

**Goal:** REST API + WebSocket for dashboard, config management, real-time events. This is what the frontend web UI talks to.

### 10.1 API Server Setup
- [ ] Create `internal/api/server.go`
  - [ ] Go Fiber HTTP server on `:8443` (configurable in firewall.toml)
  - [ ] CORS middleware (allow frontend origin)
  - [ ] Request logging middleware
  - [ ] Error handling middleware
  - [ ] Auth middleware (API key from config, or disabled for local)

### 10.2 Dashboard Endpoints
- [ ] `GET /api/v1/dashboard/stats` — key metrics
  - [ ] Packets processed, verdicts sent, blocks today
  - [ ] Threat intel stats (IPs loaded, domains loaded)
  - [ ] Security stats (bans active, rate limits, detections)
  - [ ] GeoIP stats (countries blocked, lookups)
  - [ ] Domain filter stats (blocks by protocol, categories active)
- [ ] `GET /api/v1/dashboard/traffic` — traffic time-series
  - [ ] Last 60 minutes, per-minute breakdown
  - [ ] Total / TCP / UDP / ICMP
  - [ ] Blocked vs allowed counts
- [ ] `GET /api/v1/dashboard/threats` — active threats
  - [ ] Currently banned IPs with reason + expiry
  - [ ] Recent alerts (last 100)
  - [ ] Top threat sources (by IP)

### 10.3 Blocklist Management Endpoints
- [ ] `GET /api/v1/blocklist` — full blocklist.toml as JSON
- [ ] `PUT /api/v1/blocklist` — replace entire blocklist config
  - [ ] Validate → write to blocklist.toml → hot-reload picks it up
- [ ] `GET /api/v1/blocklist/domains` — list blocked domains
- [ ] `POST /api/v1/blocklist/domains` — add domain `{"domain": "evil.com"}`
  - [ ] Write to domains.txt → hot-reload → SafeOps Engine sync
- [ ] `DELETE /api/v1/blocklist/domains/:domain` — remove domain
- [ ] `PUT /api/v1/blocklist/categories` — toggle categories `{"ads": true, "trackers": true}`
  - [ ] Write to blocklist.toml → hot-reload
- [ ] `GET /api/v1/blocklist/geo` — geo blocking config
- [ ] `PUT /api/v1/blocklist/geo` — update geo config
  - [ ] Update deny/allow countries, ASNs
  - [ ] Write to blocklist.toml → hot-reload

### 10.4 Security Management Endpoints
- [ ] `GET /api/v1/security/bans` — list active bans
- [ ] `POST /api/v1/security/bans` — manually ban IP `{"ip": "1.2.3.4", "duration": "24h", "reason": "manual"}`
- [ ] `DELETE /api/v1/security/bans/:ip` — unban IP
- [ ] `GET /api/v1/security/detections` — detection config (from detection.toml)
- [ ] `PUT /api/v1/security/detections` — update detection thresholds
  - [ ] Write to detection.toml → hot-reload

### 10.5 Logs & Alerts Endpoints
- [ ] `GET /api/v1/logs/alerts` — security alerts with filtering
  - [ ] Query params: severity, type, srcIP, timeRange, limit, offset
  - [ ] Returns from alert log files (JSON)
- [ ] `GET /api/v1/logs/traffic` — packet logs from DB
  - [ ] Query params: srcIP, dstIP, protocol, action, timeRange
  - [ ] Paginated results
- [ ] `GET /api/v1/logs/audit` — config change audit trail

### 10.6 Real-Time WebSocket
- [ ] `WS /api/v1/ws/events` — stream security events
  - [ ] New alerts as they happen
  - [ ] Ban/unban events
  - [ ] Config reload events
  - [ ] Detection events (DDoS, brute force, port scan)
- [ ] `WS /api/v1/ws/traffic` — stream traffic metrics
  - [ ] Per-second traffic counters
  - [ ] Protocol breakdown
  - [ ] Block counts

### 10.7 Health & Status
- [ ] `GET /api/v1/health` — health check
  - [ ] DB connection status
  - [ ] SafeOps Engine connection status
  - [ ] Config loaded status
  - [ ] Uptime
- [ ] `GET /api/v1/status` — detailed engine status
  - [ ] All component stats
  - [ ] Config source path
  - [ ] Version info

### 10.8 Build & Verify Phase 10
- [ ] `go build ./cmd/` — compiles clean
- [ ] Test all endpoints with curl
- [ ] Test WebSocket streaming
- [ ] Test blocklist update → hot-reload → enforcement

---

## Config Files Summary

All config files live in `configs/` relative to binary. All are editable manually or via Web UI.

| File | Purpose | Hot-Reload | Web UI Editable |
|------|---------|------------|-----------------|
| `firewall.toml` | Engine settings, connections, performance | Yes | Yes (Phase 10) |
| `detection.toml` | Security thresholds (DDoS, brute force, etc.) | Yes | Yes (Phase 10) |
| `geoip.toml` | GeoIP policy (deny/allow countries, ASNs) | Yes | Yes (Phase 10) |
| `blocklist.toml` | Unified blocking policy (NEW) | Yes | Yes (Phase 10) |
| `domains.txt` | Domain blocklist (one per line) | Yes | Yes (Phase 10) |
| `whitelist.txt` | IP/CIDR whitelist (one per line) | Yes | Yes (Phase 10) |

**Config update flow (Web UI):**
```
Web UI → PUT /api/v1/blocklist → write to blocklist.toml → fsnotify detects change
  → hot-reload validates + swaps config → domain filter / geo / threat intel updated
  → SafeOps Engine synced (domain add/remove via control API)
```

---

## File Inventory

### Existing Files (Phases 0–6 complete)
| File | Package | Status |
|------|---------|--------|
| `cmd/main.go` | main | ✅ Working |
| `pkg/grpc/client.go` | grpc | ✅ Working |
| `internal/config/firewall_config.go` | config | ✅ Working |
| `internal/config/detection_config.go` | config | ✅ Working |
| `internal/config/geoip_config.go` | config | ✅ Working |
| `internal/config/loader_unified.go` | config | ✅ Working |
| `internal/config/paths.go` | config | ✅ Working |
| `internal/alerting/alert.go` | alerting | ✅ Working |
| `internal/alerting/template.go` | alerting | ✅ Working |
| `internal/alerting/writer.go` | alerting | ✅ Working |
| `internal/alerting/throttle.go` | alerting | ✅ Working |
| `internal/alerting/manager.go` | alerting | ✅ Working |
| `internal/threatintel/db.go` | threatintel | ✅ Working |
| `internal/threatintel/ip_cache.go` | threatintel | ✅ Working |
| `internal/threatintel/domain_cache.go` | threatintel | ✅ Working |
| `internal/threatintel/refresher.go` | threatintel | ✅ Working |
| `internal/threatintel/decision.go` | threatintel | ✅ Working |
| `internal/rate_limiting/token_bucket.go` | rate_limiting | ✅ Working |
| `internal/rate_limiting/per_ip_limiter.go` | rate_limiting | ✅ Working |
| `internal/rate_limiting/rate_limiter.go` | rate_limiting | ✅ Working |
| `internal/rate_limiting/ddos_protection.go` | rate_limiting | ✅ Working |
| `internal/security/brute_force.go` | security | ✅ Working |
| `internal/security/port_scan.go` | security | ✅ Working |
| `internal/security/anomaly_detector.go` | security | ✅ Working |
| `internal/security/baseline.go` | security | ✅ Working |
| `internal/security/ban_manager.go` | security | ✅ Working |
| `internal/security/manager.go` | security | ✅ Working |
| `internal/domain/filter.go` | domain | ✅ Working |
| `internal/domain/cdn_allowlist.go` | domain | ✅ Working |
| `internal/geoip/checker.go` | geoip | ✅ Working |
| `internal/rules/domain_matcher.go` | rules | ✅ Working |
| `internal/objects/geo_object.go` | objects | ✅ Working |
| `internal/objects/postgres_geo_resolver.go` | objects | ✅ Working |
| `internal/config/blocklist_config.go` | config | ✅ Working |
| `configs/blocklist.toml` | config | ✅ Working |

### New Files (Phases 7–10)
| Phase | File | Purpose |
|-------|------|---------|
| 7 | `internal/hotreload/watcher.go` | fsnotify file watcher |
| 7 | `internal/hotreload/reloader.go` | Config reload handlers |
| 7 | `internal/hotreload/rollback.go` | Rollback on bad config |
| 10 | `internal/api/server.go` | Fiber HTTP server |
| 10 | `internal/api/dashboard.go` | Dashboard endpoints |
| 10 | `internal/api/blocklist.go` | Blocklist CRUD endpoints |
| 10 | `internal/api/security.go` | Security management endpoints |
| 10 | `internal/api/logs.go` | Logs & alerts endpoints |
| 10 | `internal/api/websocket.go` | Real-time WebSocket |
| 10 | `internal/api/health.go` | Health & status endpoints |

---

## Agent Assignment & Model Strategy

| Phase | Agent Type | Model | Rationale |
|-------|-----------|-------|-----------|
| 4.2 (Wire domain) | Direct | opus | Touches packet handler hot path |
| 4.3 (CDN allowlist) | Task agent | sonnet | Simple data file + check function |
| 5.2 (GeoIP checker) | Task agent | sonnet | Follows existing patterns |
| 5.4 (Wire GeoIP) | Direct | opus | Packet handler integration |
| 6.1–6.2 (Blocklist config) | Task agent | sonnet | TOML structs + loader |
| 6.3 (Integrate) | Direct | opus | Cross-cutting config wiring |
| 7.1–7.3 (Hot-reload) | Task agent | sonnet | fsnotify + atomic swap |
| 7.5 (Wire reload) | Direct | opus | Main.go integration |
| 8 (Performance) | Task agent | sonnet | sync.Pool, batch, profiling |
| 9.1–9.3 (Hardening) | Task agent | sonnet | Standard patterns |
| 9.4 (Windows service) | Task agent | sonnet | sc create + service handler |
| 10.1–10.6 (Web API) | Task agent | sonnet | Standard REST API |
| 10.7 (Wire API) | Direct | opus | Integration with all components |
