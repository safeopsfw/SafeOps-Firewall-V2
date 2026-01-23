# PHASE 5: LOGGING, STATISTICS & MONITORING

**Status:** 🔜 Future Phase (After Phase 4 Complete)
**Duration:** 2 weeks
**Goal:** Add comprehensive observability - logs, metrics, health checks, gRPC management API
**Deliverable:** Production-ready monitoring with Prometheus metrics, structured logging, and management API

---

## 📋 Phase Overview

**What Changes in Phase 5:**
- **Phase 4 Reality:** Firewall blocks traffic but visibility is limited (basic console logs)
- **Phase 5 Goal:** Full observability - structured logs, real-time metrics, health monitoring, management API
- **Integration Point:** Expose metrics to Prometheus, provide gRPC API for management tools

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working
- ✅ Phase 2: Rule matching engine functional
- ✅ Phase 3: SafeOps verdict enforcement working
- ✅ Phase 4: WFP dual-engine active

---

## 🎯 Phase 5 Outcomes (What You Should See)

### After Compilation & Execution:

**Console Output Example:**
```
[INFO] Firewall Engine v5.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Dual Engine Mode: ENABLED (SafeOps + WFP)
[INFO] Metrics Server: Listening on :9090 (Prometheus endpoint)
[INFO] Management API: Listening on :50054 (gRPC)
[INFO] Health Check: Listening on :8080 (HTTP /health)

[INFO] Processing traffic...
[2026-01-22T10:15:30.123Z] [ALLOW] TCP 192.168.1.100:54321 -> 8.8.8.8:53 DNS [Rule: Allow_DNS] [Latency: 15μs] [Engine: SafeOps]
[2026-01-22T10:15:30.145Z] [DENY]  TCP 192.168.1.100:54322 -> 157.240.0.35:443 HTTPS [Rule: Block_Facebook] [Latency: 20μs] [Engine: Dual] [App: chrome.exe]
[2026-01-22T10:15:30.167Z] [ALLOW] TCP 192.168.1.100:54323 -> 172.217.0.46:443 HTTPS [Rule: Allow_HTTPS] [Latency: 12μs] [Engine: SafeOps]

[INFO] Statistics (last 60s):
[INFO] ├─ Total Packets: 150,000
[INFO] ├─ Allowed: 120,000 (80%)
[INFO] ├─ Denied: 30,000 (20%)
[INFO] ├─ Throughput: 2,500 pps (avg)
[INFO] ├─ Latency: 15μs (p50), 50μs (p95), 200μs (p99)
[INFO] ├─ Cache Hit Rate: 95%
[INFO] ├─ Top Blocked Domain: facebook.com (5,000 blocks)
[INFO] ├─ Top Allowed Domain: google.com (20,000 allows)
[INFO] ├─ SafeOps Blocks: 25,000 (83%)
[INFO] ├─ WFP Blocks: 5,000 (17%)
[INFO] └─ Memory Usage: 450MB (verdict cache: 300MB, WFP: 100MB)

[INFO] Health Status:
[INFO] ├─ SafeOps Engine: HEALTHY (latency: 2ms)
[INFO] ├─ WFP Engine: HEALTHY (375 filters installed)
[INFO] ├─ Rule Manager: HEALTHY (150 rules loaded)
[INFO] ├─ Verdict Cache: HEALTHY (95% hit rate, 50K entries)
[INFO] └─ Overall Status: HEALTHY
```

**Prometheus Metrics Endpoint (http://localhost:9090/metrics):**
```
# HELP firewall_packets_total Total number of packets processed
# TYPE firewall_packets_total counter
firewall_packets_total{action="allow"} 120000
firewall_packets_total{action="deny"} 30000

# HELP firewall_latency_seconds Packet processing latency
# TYPE firewall_latency_seconds histogram
firewall_latency_seconds_bucket{le="0.00001"} 50000  # <10μs
firewall_latency_seconds_bucket{le="0.00005"} 140000 # <50μs
firewall_latency_seconds_bucket{le="0.0001"} 148000  # <100μs
firewall_latency_seconds_bucket{le="0.001"} 150000   # <1ms
firewall_latency_seconds_sum 2.5
firewall_latency_seconds_count 150000

# HELP firewall_cache_hit_rate Verdict cache hit rate
# TYPE firewall_cache_hit_rate gauge
firewall_cache_hit_rate 0.95

# HELP firewall_rules_loaded Number of firewall rules loaded
# TYPE firewall_rules_loaded gauge
firewall_rules_loaded 150

# HELP firewall_memory_bytes Memory usage in bytes
# TYPE firewall_memory_bytes gauge
firewall_memory_bytes{component="verdict_cache"} 314572800  # 300MB
firewall_memory_bytes{component="wfp"} 104857600           # 100MB
firewall_memory_bytes{component="total"} 471859200         # 450MB

# HELP firewall_engine_health Health status of firewall engines
# TYPE firewall_engine_health gauge
firewall_engine_health{engine="safeops"} 1  # 1=healthy, 0=unhealthy
firewall_engine_health{engine="wfp"} 1
```

**gRPC Management API (Client Example):**
```bash
# Get firewall statistics
$ grpcurl -plaintext localhost:50054 firewall.v1.FirewallManagement/GetStatistics
{
  "totalPackets": "150000",
  "allowed": "120000",
  "denied": "30000",
  "throughput": 2500.0,
  "cacheHitRate": 0.95,
  "latency": {
    "p50": "0.000015",
    "p95": "0.000050",
    "p99": "0.000200"
  }
}

# Get health status
$ grpcurl -plaintext localhost:50054 firewall.v1.FirewallManagement/GetHealth
{
  "status": "HEALTHY",
  "components": [
    {"name": "safeops", "status": "HEALTHY", "latency": "0.002"},
    {"name": "wfp", "status": "HEALTHY", "details": "375 filters installed"},
    {"name": "rules", "status": "HEALTHY", "details": "150 rules loaded"}
  ]
}

# List active rules
$ grpcurl -plaintext localhost:50054 firewall.v1.FirewallManagement/ListRules
{
  "rules": [
    {
      "id": "rule-001",
      "name": "Allow_DNS",
      "action": "ALLOW",
      "hitCount": "50000",
      "lastHit": "2026-01-22T10:15:30Z"
    },
    {
      "id": "rule-002",
      "name": "Block_Facebook",
      "action": "DENY",
      "hitCount": "5000",
      "lastHit": "2026-01-22T10:15:30Z"
    }
  ]
}

# Hot-reload rules (trigger reload)
$ grpcurl -plaintext localhost:50054 firewall.v1.FirewallManagement/ReloadRules
{
  "success": true,
  "rulesLoaded": 151,
  "reloadTime": "1.234s"
}
```

**Grafana Dashboard (Visualization):**
```
Dashboard: SafeOps Firewall Overview

Panel 1: Packet Processing Rate (Graph)
├─ Allowed packets/sec: 2,000 pps (green line)
├─ Denied packets/sec: 500 pps (red line)
└─ Total packets/sec: 2,500 pps (blue line)

Panel 2: Latency Distribution (Heatmap)
├─ P50: 15μs (green)
├─ P95: 50μs (yellow)
└─ P99: 200μs (orange)

Panel 3: Cache Hit Rate (Gauge)
├─ Current: 95% (green, target >90%)
└─ Low water mark: 85% (warning threshold)

Panel 4: Top Blocked Domains (Table)
├─ facebook.com: 5,000 blocks
├─ twitter.com: 2,000 blocks
├─ tiktok.com: 1,500 blocks
└─ malware-c2.com: 500 blocks

Panel 5: Engine Health (Status)
├─ SafeOps: ✅ HEALTHY
├─ WFP: ✅ HEALTHY
├─ Rules: ✅ HEALTHY
└─ Cache: ✅ HEALTHY

Panel 6: Memory Usage (Graph)
├─ Verdict Cache: 300MB (stable)
├─ WFP: 100MB (stable)
└─ Total: 450MB (under 500MB limit)
```

---

## 🏗️ Phase 5 Architecture

### Observability Stack:

```
┌─────────────────────────────────────────────────────────┐
│               Firewall Engine (Go)                      │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Core Processing Loop                      │  │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐ │  │
│  │  │ Packet │→│ Match  │→│Enforce │→│ Log    │ │  │
│  │  │ Recv   │ │ Rule   │ │Verdict │ │ Event  │ │  │
│  │  └────────┘  └────────┘  └────────┘  └───┬────┘ │  │
│  └────────────────────────────────────────────│──────┘  │
│                                               ↓          │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Observability Layer                       │  │
│  │                                                    │  │
│  │  ┌──────────────┐  ┌──────────────┐             │  │
│  │  │   Logger     │  │   Metrics    │             │  │
│  │  │  (Zerolog)   │  │ (Prometheus) │             │  │
│  │  └──────┬───────┘  └──────┬───────┘             │  │
│  │         ↓                  ↓                      │  │
│  │  ┌──────────────────────────────────┐            │  │
│  │  │   Statistics Aggregator          │            │  │
│  │  │  (In-Memory Counters)            │            │  │
│  │  └──────┬───────────────────────────┘            │  │
│  │         ↓                                         │  │
│  │  ┌──────────────────────────────────┐            │  │
│  │  │   Health Monitor                 │            │  │
│  │  │  (Component Status Checks)       │            │  │
│  │  └──────────────────────────────────┘            │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │         External Interfaces                       │  │
│  │                                                    │  │
│  │  ┌──────────────┐  ┌──────────────┐             │  │
│  │  │ HTTP Server  │  │ gRPC Server  │             │  │
│  │  │ :9090        │  │ :50054       │             │  │
│  │  ├──────────────┤  ├──────────────┤             │  │
│  │  │ /metrics     │  │ GetStats()   │             │  │
│  │  │ /health      │  │ GetHealth()  │             │  │
│  │  │ /debug/pprof │  │ ListRules()  │             │  │
│  │  │              │  │ ReloadRules()│             │  │
│  │  └──────────────┘  └──────────────┘             │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                    ↓                  ↓
         ┌──────────────────┐  ┌──────────────────┐
         │   Prometheus     │  │  Management UI   │
         │   (Scraper)      │  │  (gRPC Client)   │
         └─────────┬────────┘  └──────────────────┘
                   ↓
         ┌──────────────────┐
         │     Grafana      │
         │   (Dashboard)    │
         └──────────────────┘
```

---

## 📦 Phase 5 Components (5 Sub-Tasks)

### Sub-Task 5.1: Structured Logging (`internal/logging/`)

**Purpose:** Implement production-ready structured logging with levels, fields, and rotation

**Core Concept:**
Traditional logging: `fmt.Printf("Blocked packet: %s", ip)` - unstructured, hard to parse
Structured logging: `log.Info().Str("action", "deny").Str("ip", ip).Msg("Blocked packet")` - machine-readable, queryable

---

#### What to Create:

**1. Logger Interface**

**Purpose:** Abstract logging to allow swapping implementations (zerolog, zap, logrus)

**Why Interface:**
- Different environments need different loggers (production: JSON, development: pretty console)
- Testing: Mock logger for unit tests (verify logs without side effects)
- Flexibility: Switch from zerolog to zap without rewriting all log calls

**Logger Interface Definition:**
```
Common logging levels (from most to least severe):
├─ FATAL: Application cannot continue (exit code 1)
├─ ERROR: Operation failed, but app continues (lost SafeOps connection)
├─ WARN:  Unexpected but handled (cache miss, slow DNS)
├─ INFO:  Normal operations (rule loaded, packet blocked)
├─ DEBUG: Detailed debugging (cache lookup, rule evaluation)
└─ TRACE: Extremely verbose (every packet header, raw bytes)

Log entry structure:
{
  "timestamp": "2026-01-22T10:15:30.123Z",    // ISO 8601 timestamp
  "level": "info",                             // Log level
  "message": "Blocked packet",                 // Human-readable message
  "fields": {                                  // Structured context
    "action": "deny",
    "protocol": "TCP",
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "dst_ip": "157.240.0.35",
    "dst_port": 443,
    "rule": "Block_Facebook",
    "engine": "safeops",
    "latency_us": 20,
    "flow_id": "abc123"
  }
}
```

**Field Categories:**
```
Connection fields (every log entry):
├─ src_ip, src_port
├─ dst_ip, dst_port
├─ protocol (TCP/UDP/ICMP)
└─ flow_id (unique identifier)

Verdict fields:
├─ action (allow/deny/drop)
├─ rule (matched rule name)
├─ engine (safeops/wfp/dual)
└─ reason (cache_hit/rule_match/default_policy)

Performance fields:
├─ latency_us (microseconds)
├─ cache_hit (true/false)
└─ rule_eval_time_us (rule matching time)

Application fields (if available):
├─ app_name (chrome.exe)
├─ app_path (C:\...\chrome.exe)
└─ pid (process ID)

Domain fields (if resolved):
├─ dst_domain (facebook.com)
├─ dns_ttl (300 seconds)
└─ dns_resolved_at (timestamp)
```

---

**2. Zerolog Implementation**

**Purpose:** Use zerolog as the logging backend (fast, zero-allocation, structured)

**Why Zerolog:**
```
Benchmark comparison (1M log entries):
├─ fmt.Printf: 50ms (unstructured, allocates strings)
├─ logrus: 120ms (structured, but slow reflection)
├─ zap: 30ms (fast, structured)
└─ zerolog: 20ms ✓ FASTEST (zero-allocation, structured)

Zerolog advantages:
1. Zero-allocation: Reuses buffers (no GC pressure)
2. Structured: JSON output by default
3. Fast: Chain API with lazy evaluation
4. Levels: Dynamic level filtering (change at runtime)
5. Context: Attach fields to logger (inherit in sub-loggers)
```

**Zerolog Configuration:**
```
Production Config (JSON output):
{
  "level": "info",              // Filter: Show INFO and above (hide DEBUG/TRACE)
  "output": "stdout",           // Write to stdout (Docker captures this)
  "format": "json",             // Machine-readable JSON
  "sampling": {                 // Rate limiting (prevent log floods)
    "enabled": true,
    "initial": 100,             // First 100 logs always written
    "thereafter": 10            // Then 1 in 10 (10% sampling)
  },
  "caller": true,               // Add file:line to logs (debugging)
  "timestamp": true,            // ISO 8601 timestamp
  "timeFieldFormat": "unix_ms"  // Millisecond precision
}

Development Config (Pretty output):
{
  "level": "debug",             // Show all logs including DEBUG
  "output": "stdout",
  "format": "console",          // Human-readable colored output
  "sampling": false,            // No sampling (see everything)
  "caller": true,
  "timestamp": true,
  "timeFieldFormat": "rfc3339"  // Human-readable timestamp
}

Example console output (development):
10:15:30 INF Blocked packet action=deny protocol=TCP src=192.168.1.100:54321 dst=157.240.0.35:443 rule=Block_Facebook latency=20μs

Example JSON output (production):
{"level":"info","time":"2026-01-22T10:15:30.123Z","caller":"enforcement/engine.go:42","message":"Blocked packet","action":"deny","protocol":"TCP","src_ip":"192.168.1.100","src_port":54321,"dst_ip":"157.240.0.35","dst_port":443,"rule":"Block_Facebook","latency_us":20}
```

---

**3. Log Levels & Filtering**

**Purpose:** Control log verbosity based on environment and debugging needs

**Level Configuration:**
```
Environment-based defaults:
├─ Production: INFO (normal operations only)
├─ Staging: DEBUG (detailed debugging)
├─ Development: TRACE (everything, including packet dumps)
└─ Testing: WARN (quiet, only show problems)

Runtime level changes:
1. User sends signal: kill -USR1 <pid>
2. Firewall receives signal
3. Logger increases level: INFO → DEBUG
4. More verbose logging starts
5. User sends signal again: kill -USR2 <pid>
6. Logger decreases level: DEBUG → INFO
7. Normal logging resumes

Configuration file (firewall.toml):
[logging]
level = "info"              # Default level
format = "json"             # json or console
output = "stdout"           # stdout, file, or both
file = "/var/log/firewall.log"
max_size_mb = 100           # Rotate after 100MB
max_backups = 10            # Keep 10 rotated files
max_age_days = 30           # Delete files older than 30 days
compress = true             # Gzip rotated files
sampling = true             # Enable sampling (prevent floods)
```

**Conditional Logging (Performance):**
```
Problem: DEBUG logs expensive even if disabled
Example:
  log.Debug().Str("packet", dumpPacketHex(pkt)).Msg("Processing packet")
  // dumpPacketHex() called EVEN IF debug logging disabled (waste CPU)

Solution: Check level before expensive operations
  if log.Logger.GetLevel() <= zerolog.DebugLevel {
    log.Debug().Str("packet", dumpPacketHex(pkt)).Msg("Processing packet")
    // dumpPacketHex() only called if debug enabled
  }

Zerolog lazy evaluation:
  log.Debug().Func(func(e *zerolog.Event) {
    e.Str("packet", dumpPacketHex(pkt))  // Only called if debug enabled
  }).Msg("Processing packet")
```

---

**4. Log Rotation & Management**

**Purpose:** Prevent log files from filling disk, implement rotation policies

**Why Rotation:**
```
Problem: Firewall processes 100K pps
- 100K packets/sec × 200 bytes/log = 20MB/sec
- 20MB/sec × 3600 sec/hour = 72GB/hour
- 72GB/hour × 24 hours = 1.7TB/day

Solution: Sampling + Rotation + Compression

Sampling (reduce volume):
- Sample 10% of ALLOW packets (routine traffic)
- Sample 100% of DENY packets (security events, must keep)
- Result: 90% reduction in log volume (170GB/day)

Rotation (split files):
- Max file size: 100MB per file
- When 100MB reached: Close file, start new file
- Old file renamed: firewall.log → firewall.log.2026-01-22-10-15-30
- Result: Many small files instead of one huge file

Compression (save disk):
- After rotation: gzip old file (10:1 compression ratio)
- firewall.log.2026-01-22-10-15-30 (100MB) → firewall.log.2026-01-22-10-15-30.gz (10MB)
- Result: 10× disk space saved

Retention (delete old logs):
- Keep last 30 days of logs
- Delete logs older than 30 days
- Result: Max disk usage = 170GB/day × 30 days × 0.1 (compression) = 510GB
```

**Rotation Library (lumberjack):**
```
Go library: gopkg.in/natefinch/lumberjack.v2

Configuration:
logger := &lumberjack.Logger{
  Filename:   "/var/log/firewall.log",
  MaxSize:    100,  // MB before rotation
  MaxBackups: 10,   // Number of old files to keep
  MaxAge:     30,   // Days to keep old files
  Compress:   true, // Gzip rotated files
}

Automatic rotation:
1. Write log entry → Check if file > 100MB
2. If yes:
   ├─ Close current file
   ├─ Rename: firewall.log → firewall.log.2026-01-22-10-15-30
   ├─ Open new file: firewall.log
   ├─ Background goroutine: Compress old file
   └─ Continue writing to new file (no downtime)

Manual rotation (signal):
1. User sends: kill -HUP <pid>
2. Firewall receives signal
3. Logger rotates immediately (even if <100MB)
4. Use case: Collect logs for analysis, start fresh file
```

---

**5. Context Loggers**

**Purpose:** Attach persistent fields to logger (avoid repeating fields in every log call)

**What is Context Logger:**
```
Problem: Every packet log needs connection info
  log.Info().
    Str("src_ip", "192.168.1.100").
    Int("src_port", 54321).
    Str("dst_ip", "157.240.0.35").
    Int("dst_port", 443).
    Msg("Rule matched")
  // Repeat these 4 fields in every log (verbose, error-prone)

Solution: Context logger with fields attached
  flowLogger := log.With().
    Str("src_ip", "192.168.1.100").
    Int("src_port", 54321).
    Str("dst_ip", "157.240.0.35").
    Int("dst_port", 443).
    Logger()

  flowLogger.Info().Msg("Rule matched")        // Fields auto-included
  flowLogger.Info().Msg("Verdict enforced")    // Fields auto-included
  flowLogger.Info().Msg("Packet allowed")      // Fields auto-included

Output:
{"level":"info","time":"...","message":"Rule matched","src_ip":"192.168.1.100","src_port":54321,"dst_ip":"157.240.0.35","dst_port":443}
{"level":"info","time":"...","message":"Verdict enforced","src_ip":"192.168.1.100","src_port":54321,"dst_ip":"157.240.0.35","dst_port":443}
{"level":"info","time":"...","message":"Packet allowed","src_ip":"192.168.1.100","src_port":54321,"dst_ip":"157.240.0.35","dst_port":443}
```

**Use Cases:**
```
1. Flow Context (per-connection logger):
   ├─ Create logger when connection starts
   ├─ Attach: flow_id, src_ip, src_port, dst_ip, dst_port
   ├─ Use throughout connection lifetime
   └─ All logs include connection context

2. Component Context (per-module logger):
   ├─ Rule Manager: Attach component="rule_manager"
   ├─ SafeOps Client: Attach component="safeops_client"
   ├─ WFP Engine: Attach component="wfp_engine"
   └─ Logs filterable by component (grep component=wfp_engine)

3. Request Context (per-gRPC request):
   ├─ Attach: request_id, user, api_method
   ├─ Use for entire request lifecycle
   └─ Trace request through system (distributed tracing)
```

---

#### Files to Create:
```
internal/logging/
├── interface.go         # Logger interface definition
├── zerolog.go           # Zerolog implementation
├── levels.go            # Log level management (runtime changes)
├── rotation.go          # Log rotation (lumberjack integration)
├── context.go           # Context logger helpers
├── sampling.go          # Log sampling configuration
└── fields.go            # Standard field names (constants)
```

---

### Sub-Task 5.2: Metrics Collection (`internal/metrics/`)

**Purpose:** Export real-time metrics to Prometheus for monitoring and alerting

**Core Concept:**
Metrics answer: "What is the system doing RIGHT NOW?"
Logs answer: "What happened in the PAST?"

Metrics are numerical time-series data:
- Packets processed per second (rate)
- Current memory usage (gauge)
- Latency distribution (histogram)
- Total packets since start (counter)

---

#### What to Create:

**1. Prometheus Integration**

**Purpose:** Expose metrics in Prometheus format for scraping

**What is Prometheus:**
```
Prometheus is a monitoring system:
1. Scraper: Polls firewall's /metrics endpoint every 15s
2. Time-Series Database: Stores metrics over time
3. Query Language (PromQL): Query and aggregate metrics
4. Alerting: Trigger alerts when metrics cross thresholds
5. Grafana: Visualize metrics in dashboards

Firewall → Prometheus → Grafana → Operators
```

**Prometheus Metrics Types:**

**A. Counter (Always Increasing):**
```
Use case: Cumulative counts (total packets since start)
Example: firewall_packets_total

Value over time:
10:00:00 → 0
10:00:15 → 1,250   (1,250 packets in 15s = 83 pps)
10:00:30 → 2,800   (1,550 packets in 15s = 103 pps)
10:00:45 → 4,200   (1,400 packets in 15s = 93 pps)

Prometheus query (rate over 1 minute):
rate(firewall_packets_total[1m])  → 93 pps (average)

When to use:
├─ Total packets processed
├─ Total bytes transferred
├─ Total rule matches
└─ Total cache hits

Never decreases (except on restart, then resets to 0)
```

**B. Gauge (Can Go Up or Down):**
```
Use case: Current state (instantaneous values)
Example: firewall_memory_bytes

Value over time:
10:00:00 → 450,000,000 (450MB)
10:00:15 → 452,000,000 (452MB)
10:00:30 → 449,000,000 (449MB)
10:00:45 → 451,000,000 (451MB)

Prometheus query (current value):
firewall_memory_bytes → 451MB

When to use:
├─ Current memory usage
├─ Number of active connections
├─ Cache size (entries)
├─ Rule count
└─ CPU usage percentage

Can increase or decrease (measures current state)
```

**C. Histogram (Distribution):**
```
Use case: Measure distribution (latency, request size)
Example: firewall_latency_seconds

Buckets (predefined ranges):
├─ 0-10μs: 50,000 packets
├─ 10-50μs: 90,000 packets (total: 140,000)
├─ 50-100μs: 8,000 packets (total: 148,000)
├─ 100-1000μs: 1,950 packets (total: 149,950)
└─ 1000+μs: 50 packets (total: 150,000)

Prometheus automatically calculates:
├─ Sum: Total latency (2.5 seconds)
├─ Count: Total measurements (150,000)
└─ Quantiles (p50, p95, p99):
    ├─ p50 (median): 15μs (50% of packets < 15μs)
    ├─ p95: 50μs (95% of packets < 50μs)
    └─ p99: 200μs (99% of packets < 200μs)

When to use:
├─ Packet processing latency
├─ Rule evaluation time
├─ DNS resolution time
└─ Request size distribution

Allows calculating percentiles (p50, p95, p99) efficiently
```

**D. Summary (Alternative to Histogram):**
```
Use case: Similar to histogram, but client-side quantiles
Example: firewall_latency_summary

Difference from histogram:
├─ Histogram: Server-side quantiles (Prometheus calculates)
├─ Summary: Client-side quantiles (firewall calculates)

Summary advantages:
├─ Exact quantiles (no bucket approximation)
└─ Lower Prometheus storage (no buckets)

Summary disadvantages:
├─ Can't aggregate across instances (each calculates separately)
└─ Higher client CPU usage (firewall does math)

Recommendation: Use Histogram (more flexible, aggregatable)
```

---

**2. Metric Definitions**

**Purpose:** Define all metrics the firewall exposes

**Core Metrics:**

**Packet Metrics (Counters):**
```
firewall_packets_total{action="allow|deny"}
├─ Description: Total packets processed since start
├─ Labels: action (allow/deny)
├─ Type: Counter
└─ Use: Calculate packet rate over time

firewall_bytes_total{action="allow|deny", direction="inbound|outbound"}
├─ Description: Total bytes transferred
├─ Labels: action, direction
├─ Type: Counter
└─ Use: Calculate bandwidth over time

firewall_rule_hits_total{rule="rule_name", action="allow|deny"}
├─ Description: Total rule matches per rule
├─ Labels: rule (rule name), action
├─ Type: Counter
└─ Use: Identify most-used rules, hotspots
```

**Performance Metrics (Histograms):**
```
firewall_latency_seconds{engine="safeops|wfp|dual"}
├─ Description: Packet processing latency
├─ Labels: engine (which engine processed)
├─ Type: Histogram
├─ Buckets: [0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]
└─ Use: Monitor performance, detect slowdowns

firewall_rule_eval_seconds
├─ Description: Rule matching time
├─ Type: Histogram
├─ Buckets: [0.000001, 0.000005, 0.00001, 0.00005, 0.0001]
└─ Use: Identify slow rules, optimize matching
```

**Cache Metrics (Gauges + Counters):**
```
firewall_cache_hit_rate
├─ Description: Verdict cache hit rate (0.0-1.0)
├─ Type: Gauge
└─ Use: Monitor cache effectiveness (target >90%)

firewall_cache_entries
├─ Description: Current number of cache entries
├─ Type: Gauge
└─ Use: Monitor cache size, detect leaks

firewall_cache_hits_total
├─ Description: Total cache hits
├─ Type: Counter
└─ Use: Calculate hit rate over time

firewall_cache_misses_total
├─ Description: Total cache misses
├─ Type: Counter
└─ Use: Calculate miss rate over time
```

**Resource Metrics (Gauges):**
```
firewall_memory_bytes{component="verdict_cache|wfp|total"}
├─ Description: Memory usage in bytes
├─ Labels: component (which subsystem)
├─ Type: Gauge
└─ Use: Monitor memory leaks, plan capacity

firewall_goroutines
├─ Description: Number of active goroutines
├─ Type: Gauge
└─ Use: Detect goroutine leaks (should be stable)

firewall_cpu_percent
├─ Description: CPU usage percentage (0-100)
├─ Type: Gauge
└─ Use: Monitor CPU utilization, detect spikes
```

**System Metrics (Gauges):**
```
firewall_rules_loaded
├─ Description: Number of firewall rules currently loaded
├─ Type: Gauge
└─ Use: Track rule count, detect unexpected changes

firewall_connections_active
├─ Description: Number of active tracked connections
├─ Type: Gauge
└─ Use: Monitor connection table size, detect leaks

firewall_wfp_filters{layer="inbound|outbound|ale"}
├─ Description: Number of WFP filters installed
├─ Labels: layer (WFP layer)
├─ Type: Gauge
└─ Use: Verify WFP filters installed correctly
```

**Health Metrics (Gauges):**
```
firewall_engine_health{engine="safeops|wfp|rules|cache"}
├─ Description: Health status (1=healthy, 0=unhealthy)
├─ Labels: engine (component name)
├─ Type: Gauge
└─ Use: Monitor component health, trigger alerts

firewall_up
├─ Description: Firewall is running (1=up, 0=down)
├─ Type: Gauge
└─ Use: Uptime monitoring (should always be 1)
```

---

**3. Label Strategy**

**Purpose:** Use labels to slice metrics by dimension (avoid metric explosion)

**What are Labels:**
```
Labels add dimensions to metrics:

Without labels (metric explosion):
├─ firewall_packets_allow_tcp_total
├─ firewall_packets_allow_udp_total
├─ firewall_packets_deny_tcp_total
├─ firewall_packets_deny_udp_total
└─ 4 metrics

With labels (efficient):
├─ firewall_packets_total{action="allow", protocol="tcp"}
├─ firewall_packets_total{action="allow", protocol="udp"}
├─ firewall_packets_total{action="deny", protocol="tcp"}
├─ firewall_packets_total{action="deny", protocol="udp"}
└─ 1 metric with 2 labels (4 time-series)

Query by label:
├─ All packets: firewall_packets_total
├─ Allowed packets: firewall_packets_total{action="allow"}
├─ TCP packets: firewall_packets_total{protocol="tcp"}
└─ Denied TCP: firewall_packets_total{action="deny", protocol="tcp"}
```

**Label Guidelines:**
```
Good labels (low cardinality):
├─ action: allow, deny (2 values)
├─ protocol: tcp, udp, icmp (3 values)
├─ engine: safeops, wfp, dual (3 values)
├─ direction: inbound, outbound (2 values)
└─ Total combinations: 2×3×3×2 = 36 time-series (acceptable)

Bad labels (high cardinality):
├─ src_ip: 192.168.1.1, 192.168.1.2, ... (thousands of values)
├─ dst_ip: 8.8.8.8, 1.1.1.1, ... (millions of values)
├─ flow_id: uuid1, uuid2, ... (infinite values)
└─ Result: Metric explosion (millions of time-series, Prometheus OOM)

Cardinality limit:
├─ Target: <100 time-series per metric (fast queries)
├─ Acceptable: <1,000 time-series per metric (ok)
├─ Danger: >10,000 time-series per metric (slow queries)
└─ Critical: >100,000 time-series per metric (Prometheus crashes)

Rule of thumb:
- Use labels for dimensions you query by (action, protocol)
- Don't use labels for unique identifiers (IPs, UUIDs)
- For high-cardinality data (top blocked IPs), use separate aggregation
```

---

**4. Metric Exporter (HTTP Server)**

**Purpose:** Expose /metrics endpoint for Prometheus scraping

**HTTP Metrics Endpoint:**
```
Start HTTP server:
├─ Address: 0.0.0.0:9090 (listen all interfaces)
├─ Endpoint: GET /metrics
├─ Format: Prometheus text format
└─ Response time: <100ms (must be fast, scrape every 15s)

Prometheus scrape config (prometheus.yml):
scrape_configs:
  - job_name: 'safeops-firewall'
    scrape_interval: 15s        # Poll every 15 seconds
    scrape_timeout: 10s         # Timeout if no response in 10s
    static_configs:
      - targets: ['localhost:9090']
        labels:
          instance: 'firewall-01'
          environment: 'production'

Scrape lifecycle:
1. Prometheus sends: GET http://localhost:9090/metrics
2. Firewall collects current metric values (snapshot)
3. Firewall formats in Prometheus text format
4. Firewall returns response (HTTP 200)
5. Prometheus parses metrics, stores in TSDB
6. Wait 15 seconds, repeat

Prometheus text format example:
# HELP firewall_packets_total Total packets processed
# TYPE firewall_packets_total counter
firewall_packets_total{action="allow"} 120000
firewall_packets_total{action="deny"} 30000

# HELP firewall_latency_seconds Packet processing latency
# TYPE firewall_latency_seconds histogram
firewall_latency_seconds_bucket{le="0.00001"} 50000
firewall_latency_seconds_bucket{le="0.00005"} 140000
firewall_latency_seconds_bucket{le="0.0001"} 148000
firewall_latency_seconds_bucket{le="+Inf"} 150000
firewall_latency_seconds_sum 2.5
firewall_latency_seconds_count 150000
```

**Security Considerations:**
```
Problem: /metrics endpoint exposes operational data
- Total packet counts (traffic analysis)
- Blocked domains (security posture)
- Resource usage (system info)

Solutions:
1. Bind to localhost only (127.0.0.1:9090):
   ├─ Only local Prometheus can scrape
   └─ External network cannot access

2. Add authentication (HTTP Basic Auth):
   ├─ Authorization: Basic <base64(user:pass)>
   └─ Only authorized scrapers can access

3. Use mTLS (mutual TLS):
   ├─ Both firewall and Prometheus present certificates
   ├─ Only trusted Prometheus can scrape
   └─ Data encrypted in transit

4. Firewall rules (allow only Prometheus IP):
   ├─ Allow 10.0.0.5:* → firewall:9090 (Prometheus server)
   ├─ Deny *:* → firewall:9090 (everyone else)
   └─ Defense in depth

Recommendation: Localhost + firewall rules (simple, secure)
```

---

**5. Real-Time Statistics**

**Purpose:** Aggregate metrics in-memory for dashboard display (faster than querying Prometheus)

**Why In-Memory Stats:**
```
Problem: Prometheus scrapes every 15s (stale data)
- User asks: "What's the packet rate RIGHT NOW?"
- Prometheus response: "15 seconds ago, it was 2,500 pps"
- Unacceptable for real-time monitoring

Solution: In-memory statistics (updated every second)
- Firewall maintains rolling window (last 60 seconds)
- Calculate: packets/sec, cache hit rate, top blocked domains
- Expose via gRPC API (real-time query)
- User gets: "Right now (last 1 second), it's 2,543 pps"

Trade-off:
├─ Prometheus: Long-term storage (months), historical queries
└─ In-memory: Short-term (minutes), real-time queries
```

**Statistics Data Structure:**
```
Rolling window (ring buffer):
├─ Window size: 60 seconds
├─ Granularity: 1 second per bucket
├─ Storage: Array[60] of per-second stats

bucket[0]:  10:15:00-10:15:01 → 2,500 packets
bucket[1]:  10:15:01-10:15:02 → 2,600 packets
bucket[2]:  10:15:02-10:15:03 → 2,400 packets
...
bucket[59]: 10:15:59-10:16:00 → 2,550 packets

Every second:
1. Increment bucket index (circular: 59 → 0)
2. Clear new bucket (reset counters)
3. Start accumulating for new second
4. Old bucket[0] data lost (after 60 seconds)

Query stats (last 60s):
1. Sum all 60 buckets: 150,000 packets
2. Calculate rate: 150,000 / 60 = 2,500 pps
3. Calculate percentages: 120,000 allow / 150,000 total = 80%
```

**Aggregations:**
```
Per-second bucket contains:
├─ packets_allow: 2,000
├─ packets_deny: 500
├─ bytes_allow: 4,000,000 (4MB)
├─ bytes_deny: 100,000 (100KB)
├─ cache_hits: 1,900
├─ cache_misses: 100
├─ latency_sum: 50,000μs (50ms total)
├─ latency_count: 2,500
└─ top_blocked_domains: map[string]int{"facebook.com": 50, ...}

Query: Get stats for last 60 seconds
Response:
{
  "packets_total": 150,000,
  "packets_allow": 120,000,
  "packets_deny": 30,000,
  "throughput_pps": 2,500,
  "bytes_total": 240,000,000,
  "cache_hit_rate": 0.95,
  "latency_avg_us": 20,
  "top_blocked_domains": [
    {"domain": "facebook.com", "count": 5,000},
    {"domain": "twitter.com", "count": 2,000}
  ]
}
```

---

#### Files to Create:
```
internal/metrics/
├── prometheus.go        # Prometheus metrics registration
├── collector.go         # Metric collection (update counters, histograms)
├── exporter.go          # HTTP /metrics endpoint
├── definitions.go       # Metric definitions (names, help text, labels)
├── labels.go            # Label helpers (validate cardinality)
└── statistics.go        # Real-time statistics (rolling window)
```

---

### Sub-Task 5.3: Health Monitoring (`internal/health/`)

**Purpose:** Monitor component health and expose status for load balancers and orchestrators

**Core Concept:**
Health checks answer: "Is the firewall ready to handle traffic?"
- Kubernetes: Liveness probe (restart if unhealthy)
- Kubernetes: Readiness probe (remove from load balancer if not ready)
- Load balancer: Route traffic only to healthy instances

---

#### What to Create:

**1. Health Check Interface**

**Purpose:** Define how to check if a component is healthy

**Component Health:**
```
Each component implements health check:

interface HealthChecker {
  Name() string           // Component name ("safeops_client")
  Check() HealthStatus    // Perform health check
}

type HealthStatus {
  Healthy  bool           // Is component healthy?
  Message  string         // Status message ("Connected to SafeOps")
  Latency  time.Duration  // Last operation latency
  Details  map[string]any // Additional details
}

Example components:
├─ SafeOps Client: Check if gRPC connection alive
├─ WFP Engine: Check if WFP session open
├─ Rule Manager: Check if rules loaded
├─ Verdict Cache: Check if cache operational
└─ Metadata Stream: Check if receiving packets
```

---

**2. Component Health Checks**

**Purpose:** Implement health checks for each subsystem

**SafeOps Client Health:**
```
Check criteria:
├─ gRPC connection state = READY
├─ Last metadata received < 5 seconds ago (stream active)
├─ Verdict submission working (test with ping)
└─ Latency < 10ms (responsive)

Health check implementation:
1. Check gRPC connection state:
   state := conn.GetState()
   if state != connectivity.Ready {
     return Unhealthy("SafeOps disconnected")
   }

2. Check last metadata timestamp:
   if time.Since(lastMetadataTime) > 5*time.Second {
     return Unhealthy("SafeOps stream stale")
   }

3. Send test verdict (no-op):
   ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
   defer cancel()
   err := client.SubmitTestVerdict(ctx)
   if err != nil {
     return Unhealthy("SafeOps verdict submission failed")
   }

4. Measure latency:
   latency := time.Since(start)
   if latency > 10*time.Millisecond {
     return Degraded("SafeOps high latency", latency)
   }

5. Return healthy:
   return Healthy("SafeOps connected", latency)
```

**WFP Engine Health:**
```
Check criteria:
├─ WFP session open (handle valid)
├─ Expected number of filters installed
├─ No recent WFP errors
└─ Provider registered

Health check implementation:
1. Check session handle:
   if wfpSession == nil {
     return Unhealthy("WFP session not open")
   }

2. Enumerate filters:
   filterCount, err := wfp.GetFilterCount(session)
   if err != nil {
     return Unhealthy("WFP filter enumeration failed")
   }

3. Verify filter count:
   if filterCount != expectedCount {
     return Degraded(fmt.Sprintf("WFP filter mismatch: expected %d, got %d", expectedCount, filterCount))
   }

4. Check error rate:
   if wfpErrorCount > 10 {
     return Degraded("WFP experiencing errors")
   }

5. Return healthy:
   return Healthy(fmt.Sprintf("WFP active (%d filters)", filterCount))
```

**Rule Manager Health:**
```
Check criteria:
├─ Rules loaded successfully
├─ Rule count > 0 (not empty)
├─ No parse errors
└─ File watcher active (for hot-reload)

Health check implementation:
1. Check rule count:
   ruleCount := ruleManager.GetRuleCount()
   if ruleCount == 0 {
     return Unhealthy("No rules loaded")
   }

2. Check for errors:
   if ruleManager.HasErrors() {
     return Degraded("Rule parse errors present")
   }

3. Check file watcher:
   if !ruleManager.IsWatchingFile() {
     return Degraded("File watcher not active (hot-reload disabled)")
   }

4. Return healthy:
   return Healthy(fmt.Sprintf("%d rules loaded", ruleCount))
```

**Verdict Cache Health:**
```
Check criteria:
├─ Cache operational (not nil)
├─ Cache hit rate > 90% (effective)
├─ Cache size within limits (<1M entries)
└─ No memory allocation failures

Health check implementation:
1. Check cache exists:
   if cache == nil {
     return Unhealthy("Cache not initialized")
   }

2. Check hit rate:
   hitRate := cache.GetHitRate()
   if hitRate < 0.90 {
     return Degraded(fmt.Sprintf("Low cache hit rate: %.2f%%", hitRate*100))
   }

3. Check cache size:
   size := cache.GetSize()
   if size > 1000000 {
     return Degraded(fmt.Sprintf("Cache size high: %d entries", size))
   }

4. Return healthy:
   return Healthy(fmt.Sprintf("Cache operational (%.2f%% hit rate)", hitRate*100))
```

---

**3. HTTP Health Endpoint**

**Purpose:** Expose /health HTTP endpoint for load balancers

**Health Endpoint Design:**
```
GET /health
├─ Response: HTTP 200 (healthy) or 503 (unhealthy)
├─ Format: JSON
└─ Response time: <100ms (fast, called frequently)

Response (healthy):
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "healthy",
  "components": [
    {
      "name": "safeops",
      "status": "healthy",
      "message": "SafeOps connected",
      "latency_ms": 2
    },
    {
      "name": "wfp",
      "status": "healthy",
      "message": "WFP active (375 filters)",
      "latency_ms": 0
    },
    {
      "name": "rules",
      "status": "healthy",
      "message": "150 rules loaded",
      "latency_ms": 0
    },
    {
      "name": "cache",
      "status": "healthy",
      "message": "Cache operational (95.0% hit rate)",
      "latency_ms": 0
    }
  ],
  "timestamp": "2026-01-22T10:15:30.123Z"
}

Response (unhealthy):
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "status": "unhealthy",
  "components": [
    {
      "name": "safeops",
      "status": "unhealthy",
      "message": "SafeOps disconnected",
      "latency_ms": 0
    },
    {
      "name": "wfp",
      "status": "healthy",
      "message": "WFP active (375 filters)",
      "latency_ms": 0
    },
    {
      "name": "rules",
      "status": "healthy",
      "message": "150 rules loaded",
      "latency_ms": 0
    },
    {
      "name": "cache",
      "status": "degraded",
      "message": "Low cache hit rate: 85.0%",
      "latency_ms": 0
    }
  ],
  "timestamp": "2026-01-22T10:15:30.123Z"
}
```

**Health Status Logic:**
```
Overall health status:
├─ All components healthy → HTTP 200 (HEALTHY)
├─ Any component degraded → HTTP 200 (DEGRADED, still serving)
└─ Any component unhealthy → HTTP 503 (UNHEALTHY, should restart)

Load balancer behavior:
├─ HTTP 200 → Keep in load balancer pool (serve traffic)
└─ HTTP 503 → Remove from load balancer pool (no traffic)

Kubernetes probe:
├─ Liveness: If HTTP 503 → Restart container
└─ Readiness: If HTTP 503 → Remove from Service endpoints
```

---

**4. Startup/Readiness Checks**

**Purpose:** Separate startup probes from liveness probes (Kubernetes pattern)

**Probe Types:**

**A. Startup Probe (Is the firewall starting up?):**
```
Purpose: Wait for slow initialization (loading 10,000 rules)
Endpoint: GET /startup

Check criteria:
├─ Rules loaded (may take 30s for large files)
├─ SafeOps connection established
├─ WFP filters installed
└─ Verdict cache initialized

Startup timeline:
0s:  Start firewall → /startup returns 503 (not ready)
5s:  Load rules → /startup returns 503 (loading)
10s: Connect SafeOps → /startup returns 503 (connecting)
15s: Install WFP filters → /startup returns 503 (installing)
20s: Initialize cache → /startup returns 200 (READY!)

Kubernetes config:
startupProbe:
  httpGet:
    path: /startup
    port: 8080
  initialDelaySeconds: 0
  periodSeconds: 5       # Check every 5s
  failureThreshold: 12   # Fail after 60s (12 × 5s)
  # If still not ready after 60s: Kill and restart container
```

**B. Liveness Probe (Is the firewall alive?):**
```
Purpose: Detect deadlocks, crashes, infinite loops
Endpoint: GET /health (same as health check)

Check criteria:
├─ HTTP server responding (not deadlocked)
├─ Critical components operational (SafeOps, WFP)
└─ No fatal errors

Liveness check (fast, minimal work):
1. Respond to HTTP request (proves event loop working)
2. Check critical components only (SafeOps, WFP)
3. Return HTTP 200 or 503

Kubernetes config:
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30  # Wait 30s after startup
  periodSeconds: 10        # Check every 10s
  failureThreshold: 3      # Fail after 3 consecutive failures (30s)
  # If 3 failures: Kill and restart container
```

**C. Readiness Probe (Is the firewall ready for traffic?):**
```
Purpose: Should load balancer route traffic to this instance?
Endpoint: GET /ready

Check criteria:
├─ Firewall started (passed startup probe)
├─ All components healthy (not just critical)
├─ Performance acceptable (cache hit rate, latency)
└─ Not overloaded (CPU < 90%)

Readiness scenarios:
├─ Scenario 1: Firewall starting → NOT READY (don't route traffic)
├─ Scenario 2: Cache cold (0% hit rate) → NOT READY (warming up)
├─ Scenario 3: SafeOps disconnected → NOT READY (WFP-only mode insufficient)
├─ Scenario 4: CPU overloaded (95%) → NOT READY (shedding load)
└─ Scenario 5: Everything optimal → READY (route traffic)

Kubernetes config:
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5   # Check shortly after startup
  periodSeconds: 5         # Check every 5s
  failureThreshold: 2      # Fail after 2 consecutive failures (10s)
  # If fails: Remove from Service endpoints (no traffic routed)
  # But DON'T restart (unlike liveness probe)
```

---

**5. Dependency Checks**

**Purpose:** Verify external dependencies are reachable

**External Dependencies:**
```
1. SafeOps Engine (gRPC):
   ├─ Address: 127.0.0.1:50053
   ├─ Check: Send HealthCheck RPC
   └─ Timeout: 5 seconds

2. Configuration File:
   ├─ Path: /etc/safeops/firewall.toml
   ├─ Check: File exists, readable, valid TOML
   └─ Timeout: 1 second

3. WFP Subsystem:
   ├─ Check: Open WFP session (requires admin)
   └─ Timeout: 2 seconds

4. DNS Resolver (optional):
   ├─ Address: 8.8.8.8:53
   ├─ Check: Resolve test domain (test.com)
   └─ Timeout: 5 seconds
```

**Dependency Check Logic:**
```
On health check:
1. Check all dependencies in parallel (goroutines)
2. Collect results with timeout
3. Aggregate: healthy if all dependencies OK

Example:
func checkDependencies() []HealthStatus {
  results := make(chan HealthStatus, 4)

  // Check SafeOps (parallel)
  go func() {
    status := checkSafeOps()
    results <- status
  }()

  // Check WFP (parallel)
  go func() {
    status := checkWFP()
    results <- status
  }()

  // Check config file (parallel)
  go func() {
    status := checkConfigFile()
    results <- status
  }()

  // Check DNS (parallel)
  go func() {
    status := checkDNS()
    results <- status
  }()

  // Collect results (timeout 5s)
  statuses := []HealthStatus{}
  timeout := time.After(5 * time.Second)
  for i := 0; i < 4; i++ {
    select {
    case status := <-results:
      statuses = append(statuses, status)
    case <-timeout:
      statuses = append(statuses, Unhealthy("Dependency check timeout"))
    }
  }

  return statuses
}
```

---

#### Files to Create:
```
internal/health/
├── interface.go         # HealthChecker interface
├── checker.go           # Component health check implementations
├── http.go              # HTTP health endpoints (/health, /ready, /startup)
├── aggregator.go        # Aggregate component health into overall status
└── dependencies.go      # External dependency checks
```

---

### Sub-Task 5.4: gRPC Management API (`pkg/grpc/management/`)

**Purpose:** Expose management operations via gRPC API (runtime control, queries)

**Core Concept:**
Management API allows operators to:
- Query statistics (GetStatistics RPC)
- Control firewall (ReloadRules, FlushCache RPC)
- Monitor health (GetHealth RPC)
- Debug issues (GetActiveConnections RPC)

---

#### What to Create:

**1. Protobuf Service Definition**

**Purpose:** Define gRPC service contract (API spec)

**Service Definition (`proto/management.proto`):**
```protobuf
syntax = "proto3";

package firewall.v1;

option go_package = "github.com/safeops/firewall/pkg/grpc/management";

// FirewallManagement service for runtime control and queries
service FirewallManagement {
  // Statistics queries
  rpc GetStatistics(GetStatisticsRequest) returns (GetStatisticsResponse);
  rpc GetRuleStats(GetRuleStatsRequest) returns (GetRuleStatsResponse);
  rpc GetTopBlockedDomains(GetTopBlockedDomainsRequest) returns (GetTopBlockedDomainsResponse);

  // Health monitoring
  rpc GetHealth(GetHealthRequest) returns (GetHealthResponse);
  rpc GetComponentHealth(GetComponentHealthRequest) returns (GetComponentHealthResponse);

  // Rule management
  rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
  rpc GetRule(GetRuleRequest) returns (GetRuleResponse);
  rpc ReloadRules(ReloadRulesRequest) returns (ReloadRulesResponse);

  // Cache management
  rpc GetCacheStats(GetCacheStatsRequest) returns (GetCacheStatsResponse);
  rpc FlushCache(FlushCacheRequest) returns (FlushCacheResponse);

  // Connection tracking
  rpc GetActiveConnections(GetActiveConnectionsRequest) returns (GetActiveConnectionsResponse);
  rpc GetConnectionByFlowID(GetConnectionByFlowIDRequest) returns (GetConnectionByFlowIDResponse);

  // Engine control
  rpc SetLogLevel(SetLogLevelRequest) returns (SetLogLevelResponse);
  rpc GetEngineInfo(GetEngineInfoRequest) returns (GetEngineInfoResponse);
}

// Message definitions
message GetStatisticsRequest {
  // Time window (seconds) for statistics (default: 60)
  int32 window_seconds = 1;
}

message GetStatisticsResponse {
  uint64 total_packets = 1;
  uint64 allowed_packets = 2;
  uint64 denied_packets = 3;
  double throughput_pps = 4;
  double cache_hit_rate = 5;
  LatencyStats latency = 6;
  map<string, uint64> packets_by_protocol = 7;  // {"TCP": 100000, "UDP": 50000}
  map<string, uint64> packets_by_action = 8;    // {"allow": 120000, "deny": 30000}
}

message LatencyStats {
  double p50_seconds = 1;
  double p95_seconds = 2;
  double p99_seconds = 3;
  double avg_seconds = 4;
  double max_seconds = 5;
}

message GetRuleStatsRequest {
  // Optional: filter by rule name/ID
  string rule_id = 1;
}

message GetRuleStatsResponse {
  repeated RuleStat rules = 1;
}

message RuleStat {
  string id = 1;
  string name = 2;
  string action = 3;
  uint64 hit_count = 4;
  google.protobuf.Timestamp last_hit = 5;
  double avg_latency_seconds = 6;
}

message GetHealthRequest {}

message GetHealthResponse {
  string status = 1;  // "healthy", "degraded", "unhealthy"
  repeated ComponentHealth components = 2;
  google.protobuf.Timestamp timestamp = 3;
}

message ComponentHealth {
  string name = 1;
  string status = 2;
  string message = 3;
  double latency_seconds = 4;
  map<string, string> details = 5;
}

message ListRulesRequest {
  // Optional filters
  string action = 1;  // "ALLOW", "DENY"
  int32 limit = 2;    // Max rules to return
  int32 offset = 3;   // Pagination offset
}

message ListRulesResponse {
  repeated Rule rules = 1;
  int32 total_count = 2;
}

message Rule {
  string id = 1;
  string name = 2;
  string action = 3;
  int32 priority = 4;
  repeated string conditions = 5;  // Human-readable conditions
  uint64 hit_count = 6;
  google.protobuf.Timestamp created_at = 7;
}

message ReloadRulesRequest {}

message ReloadRulesResponse {
  bool success = 1;
  int32 rules_loaded = 2;
  double reload_time_seconds = 3;
  repeated string errors = 4;
}

message FlushCacheRequest {}

message FlushCacheResponse {
  bool success = 1;
  uint64 entries_flushed = 2;
}

message GetActiveConnectionsRequest {
  int32 limit = 1;  // Max connections to return (default: 100)
}

message GetActiveConnectionsResponse {
  repeated Connection connections = 1;
  uint64 total_connections = 2;
}

message Connection {
  string flow_id = 1;
  string src_ip = 2;
  int32 src_port = 3;
  string dst_ip = 4;
  int32 dst_port = 5;
  string protocol = 6;
  string state = 7;  // "ESTABLISHED", "SYN_SENT", etc.
  google.protobuf.Timestamp created_at = 8;
  uint64 packets = 9;
  uint64 bytes = 10;
}

message SetLogLevelRequest {
  string level = 1;  // "trace", "debug", "info", "warn", "error"
}

message SetLogLevelResponse {
  bool success = 1;
  string previous_level = 2;
  string new_level = 3;
}

message GetEngineInfoRequest {}

message GetEngineInfoResponse {
  string version = 1;
  string build_time = 2;
  string go_version = 3;
  google.protobuf.Timestamp start_time = 4;
  double uptime_seconds = 5;
  EngineConfig config = 6;
}

message EngineConfig {
  bool safeops_enabled = 1;
  bool wfp_enabled = 2;
  int32 rule_count = 3;
  int32 cache_size = 4;
  int32 max_connections = 5;
}
```

---

**2. gRPC Server Implementation**

**Purpose:** Implement gRPC service methods

**Server Structure:**
```
type managementServer struct {
  firewall.UnimplementedFirewallManagementServer

  // Dependencies (injected)
  ruleManager    *rules.Manager
  statsCollector *metrics.Collector
  healthMonitor  *health.Monitor
  cacheManager   *cache.Manager
  connTracker    *connections.Tracker
  logger         *logging.Logger
}

Each RPC method:
1. Validate request
2. Query relevant component
3. Format response
4. Return result
```

**Example Implementation (GetStatistics):**
```go
func (s *managementServer) GetStatistics(
  ctx context.Context,
  req *pb.GetStatisticsRequest,
) (*pb.GetStatisticsResponse, error) {
  // Default window: 60 seconds
  window := 60
  if req.WindowSeconds > 0 {
    window = int(req.WindowSeconds)
  }

  // Query statistics collector
  stats := s.statsCollector.GetStats(window)

  // Calculate throughput
  throughput := float64(stats.TotalPackets) / float64(window)

  // Calculate cache hit rate
  cacheHitRate := 0.0
  if stats.CacheHits + stats.CacheMisses > 0 {
    cacheHitRate = float64(stats.CacheHits) / float64(stats.CacheHits + stats.CacheMisses)
  }

  // Format response
  return &pb.GetStatisticsResponse{
    TotalPackets:   stats.TotalPackets,
    AllowedPackets: stats.AllowedPackets,
    DeniedPackets:  stats.DeniedPackets,
    ThroughputPps:  throughput,
    CacheHitRate:   cacheHitRate,
    Latency: &pb.LatencyStats{
      P50Seconds: stats.LatencyP50.Seconds(),
      P95Seconds: stats.LatencyP95.Seconds(),
      P99Seconds: stats.LatencyP99.Seconds(),
      AvgSeconds: stats.LatencyAvg.Seconds(),
      MaxSeconds: stats.LatencyMax.Seconds(),
    },
    PacketsByProtocol: stats.PacketsByProtocol,
    PacketsByAction:   stats.PacketsByAction,
  }, nil
}
```

**Example Implementation (ReloadRules):**
```go
func (s *managementServer) ReloadRules(
  ctx context.Context,
  req *pb.ReloadRulesRequest,
) (*pb.ReloadRulesResponse, error) {
  start := time.Now()

  // Trigger rule reload
  err := s.ruleManager.Reload()
  if err != nil {
    return &pb.ReloadRulesResponse{
      Success: false,
      Errors:  []string{err.Error()},
    }, nil
  }

  // Get rule count
  ruleCount := s.ruleManager.GetRuleCount()

  // Measure reload time
  reloadTime := time.Since(start)

  s.logger.Info().
    Int("rules_loaded", ruleCount).
    Dur("reload_time", reloadTime).
    Msg("Rules reloaded via gRPC API")

  return &pb.ReloadRulesResponse{
    Success:           true,
    RulesLoaded:       int32(ruleCount),
    ReloadTimeSeconds: reloadTime.Seconds(),
  }, nil
}
```

---

**3. Authentication & Authorization**

**Purpose:** Secure management API (only authorized users can call)

**Auth Methods:**

**A. TLS Client Certificates (mTLS):**
```
Setup:
1. Generate CA certificate (trusted authority)
2. Generate server certificate (firewall, signed by CA)
3. Generate client certificates (operators, signed by CA)
4. Firewall validates client certificate on connect

Server config:
tlsConfig := &tls.Config{
  Certificates: []tls.Certificate{serverCert},
  ClientAuth:   tls.RequireAndVerifyClientCert,
  ClientCAs:    caCertPool,  // Trusted CA
}

Client must present valid certificate:
├─ Subject: CN=operator-alice, OU=SafeOps, O=Company
├─ Issuer: CN=SafeOps-CA
├─ Valid: 2026-01-01 to 2027-01-01
└─ Signed by trusted CA

Authorization:
- Extract CN from certificate (operator-alice)
- Check if CN in allowed list
- If yes: Allow RPC
- If no: Return PermissionDenied error
```

**B. API Keys (Simple):**
```
Setup:
1. Generate API keys: openssl rand -hex 32
2. Store in config: allowed_api_keys = ["abc123...", "def456..."]
3. Client sends API key in metadata

Client:
md := metadata.New(map[string]string{
  "authorization": "Bearer abc123...",
})
ctx := metadata.NewOutgoingContext(context.Background(), md)
client.GetStatistics(ctx, &pb.GetStatisticsRequest{})

Server interceptor (validate API key):
func apiKeyInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
  // Extract metadata
  md, ok := metadata.FromIncomingContext(ctx)
  if !ok {
    return nil, status.Error(codes.Unauthenticated, "missing metadata")
  }

  // Extract API key
  authHeaders := md.Get("authorization")
  if len(authHeaders) == 0 {
    return nil, status.Error(codes.Unauthenticated, "missing authorization header")
  }

  apiKey := strings.TrimPrefix(authHeaders[0], "Bearer ")

  // Validate API key
  if !isValidAPIKey(apiKey) {
    return nil, status.Error(codes.Unauthenticated, "invalid API key")
  }

  // Call handler (authorized)
  return handler(ctx, req)
}
```

**C. No Auth (Localhost Only):**
```
If management API binds to localhost (127.0.0.1:50054):
- Only local processes can connect
- No auth needed (trust local users)
- Firewall rules prevent external access

Config:
management_api:
  bind_address = "127.0.0.1:50054"  # Localhost only
  require_auth = false               # No auth (local trust)
```

---

**4. Rate Limiting**

**Purpose:** Prevent management API abuse (DoS, brute force)

**Why Rate Limit:**
```
Problem: Expensive RPCs (GetActiveConnections returns 100K connections)
- Attacker spams: GetActiveConnections RPC
- Firewall CPU spikes (formatting 100K connections)
- Normal traffic processing slows down
- Firewall DoS'd via management API

Solution: Rate limit per RPC method
- Allow: 10 GetStatistics/sec (cheap RPC)
- Allow: 1 GetActiveConnections/sec (expensive RPC)
- Allow: 1 ReloadRules/minute (very expensive)
- Exceed limit: Return ResourceExhausted error
```

**Rate Limiting Implementation:**
```
Use token bucket algorithm:

Bucket config (per RPC method):
{
  "GetStatistics": {
    "capacity": 10,       // 10 tokens in bucket
    "refill_rate": 10,    // 10 tokens/sec refill
    "refill_interval": "1s"
  },
  "GetActiveConnections": {
    "capacity": 1,
    "refill_rate": 1,     // 1 token/sec refill
    "refill_interval": "1s"
  },
  "ReloadRules": {
    "capacity": 1,
    "refill_rate": 1,     // 1 token/minute refill
    "refill_interval": "60s"
  }
}

Interceptor (enforce rate limit):
func rateLimitInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
  method := info.FullMethod  // "/firewall.v1.FirewallManagement/GetStatistics"

  // Get rate limiter for method
  limiter := getRateLimiter(method)

  // Try to consume token
  if !limiter.Allow() {
    return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
  }

  // Call handler (within rate limit)
  return handler(ctx, req)
}
```

---

**5. Management CLI Tool**

**Purpose:** Provide command-line tool for operators (easier than raw gRPC)

**CLI Tool (safeops-firewall-cli):**
```bash
# Get statistics
$ safeops-firewall-cli stats
Total Packets: 150,000
Allowed: 120,000 (80%)
Denied: 30,000 (20%)
Throughput: 2,500 pps
Cache Hit Rate: 95%
Latency (p50/p95/p99): 15μs / 50μs / 200μs

# Get health
$ safeops-firewall-cli health
Status: HEALTHY
Components:
  - safeops: HEALTHY (2ms latency)
  - wfp: HEALTHY (375 filters)
  - rules: HEALTHY (150 rules)
  - cache: HEALTHY (95% hit rate)

# List rules
$ safeops-firewall-cli rules list
ID                                    Name                Action  Hits    Priority
rule-001                              Allow_DNS           ALLOW   50,000  100
rule-002                              Block_Facebook      DENY    5,000   100
rule-003                              Allow_HTTPS         ALLOW   70,000  90
...

# Get rule details
$ safeops-firewall-cli rules get rule-002
ID: rule-002
Name: Block_Facebook
Action: DENY
Priority: 100
Conditions:
  - dst_domain: *.facebook.com
  - dst_port: 443
  - protocol: TCP
Hit Count: 5,000
Last Hit: 2026-01-22T10:15:30Z
Avg Latency: 20μs

# Reload rules
$ safeops-firewall-cli rules reload
Reloading rules...
Success! Loaded 151 rules in 1.234s

# Flush cache
$ safeops-firewall-cli cache flush
Flushing cache...
Success! Flushed 50,000 entries

# Set log level
$ safeops-firewall-cli config set-log-level debug
Log level changed: info → debug

# Get active connections
$ safeops-firewall-cli connections list --limit 10
Flow ID       Src IP:Port            Dst IP:Port            Protocol  State        Packets  Bytes
abc123        192.168.1.100:54321    157.240.0.35:443       TCP       ESTABLISHED  1,500    3MB
def456        192.168.1.100:54322    172.217.0.46:443       TCP       ESTABLISHED  800      1.5MB
...
```

**CLI Implementation:**
```
Use gRPC client library:
├─ Connect to 127.0.0.1:50054
├─ Call management API methods
├─ Format response (human-readable tables)
└─ Exit with code (0=success, 1=error)

Framework: cobra (Go CLI framework)
├─ Root command: safeops-firewall-cli
├─ Subcommands: stats, health, rules, cache, config, connections
└─ Flags: --address (gRPC server), --timeout, --api-key
```

---

#### Files to Create:
```
pkg/grpc/management/
├── management.proto     # Protobuf service definition
├── server.go            # gRPC server implementation
├── interceptors.go      # Auth, rate limiting interceptors
└── client.go            # Go client library (for CLI tool)

cmd/safeops-firewall-cli/
├── main.go              # CLI entry point
├── stats.go             # Stats commands
├── health.go            # Health commands
├── rules.go             # Rule management commands
├── cache.go             # Cache commands
├── config.go            # Configuration commands
└── connections.go       # Connection tracking commands
```

---

### Sub-Task 5.5: Grafana Dashboard Templates (`docs/grafana/`)

**Purpose:** Provide pre-built Grafana dashboards for visualization

**Core Concept:**
Grafana dashboards visualize Prometheus metrics:
- Graphs: Packet rate over time
- Gauges: Cache hit rate (target >90%)
- Tables: Top blocked domains
- Heatmaps: Latency distribution

---

#### What to Create:

**1. Main Dashboard (firewall-overview.json)**

**Purpose:** High-level firewall overview for NOC operators

**Dashboard Panels:**

**Panel 1: Packet Processing Rate (Graph)**
```
Metric: rate(firewall_packets_total[1m])
Query:
  - Allowed: rate(firewall_packets_total{action="allow"}[1m])
  - Denied: rate(firewall_packets_total{action="deny"}[1m])
Visualization: Time-series graph
Y-Axis: Packets/sec
Legend: Allowed (green), Denied (red)
Alert: Denied rate > 1000 pps (potential attack)
```

**Panel 2: Latency Percentiles (Graph)**
```
Metric: histogram_quantile(0.50, rate(firewall_latency_seconds_bucket[1m]))
Query:
  - P50: histogram_quantile(0.50, ...)
  - P95: histogram_quantile(0.95, ...)
  - P99: histogram_quantile(0.99, ...)
Visualization: Time-series graph
Y-Axis: Seconds (log scale)
Legend: P50 (green), P95 (yellow), P99 (red)
Alert: P99 > 1ms (performance degradation)
```

**Panel 3: Cache Hit Rate (Gauge)**
```
Metric: firewall_cache_hit_rate
Visualization: Gauge
Thresholds:
  - <70%: Red (critical)
  - 70-90%: Yellow (warning)
  - >90%: Green (healthy)
Target: >90%
Alert: <85% for 5 minutes
```

**Panel 4: Engine Health (Status)**
```
Metric: firewall_engine_health{engine="safeops|wfp|rules|cache"}
Visualization: Stat panel (status indicator)
Mapping:
  - 1: ✅ Healthy (green)
  - 0: ❌ Unhealthy (red)
Alert: Any engine unhealthy
```

**Panel 5: Top Blocked Domains (Table)**
```
Metric: topk(10, sum by (domain) (firewall_rule_hits_total{action="deny"}))
Visualization: Table
Columns:
  - Domain (dst_domain label)
  - Blocks (sum of hits)
Sorting: Descending by blocks
Refresh: 30 seconds
```

**Panel 6: Memory Usage (Graph)**
```
Metric: firewall_memory_bytes{component="verdict_cache|wfp|total"}
Visualization: Stacked area graph
Y-Axis: Bytes (converted to MB)
Legend: Verdict Cache (blue), WFP (purple), Total (black line)
Alert: Total > 500MB (memory limit)
```

---

**2. Performance Dashboard (firewall-performance.json)**

**Purpose:** Detailed performance metrics for troubleshooting

**Dashboard Panels:**

**Panel 1: Latency Heatmap**
```
Metric: increase(firewall_latency_seconds_bucket[1m])
Visualization: Heatmap
X-Axis: Time
Y-Axis: Latency buckets (<10μs, 10-50μs, 50-100μs, ...)
Color: Packet count (darker = more packets)
Use case: Identify latency spikes over time
```

**Panel 2: Rule Evaluation Time**
```
Metric: histogram_quantile(0.99, rate(firewall_rule_eval_seconds_bucket[1m]))
Visualization: Time-series graph
Y-Axis: Seconds
Alert: P99 > 100μs (slow rule matching)
```

**Panel 3: Throughput by Protocol**
```
Metric: rate(firewall_packets_total[1m]) by (protocol)
Visualization: Stacked area graph
Legend: TCP (blue), UDP (green), ICMP (yellow)
Use case: Identify protocol distribution
```

**Panel 4: Cache Performance**
```
Metrics:
  - Hit rate: firewall_cache_hit_rate
  - Entries: firewall_cache_entries
  - Evictions: rate(firewall_cache_evictions_total[1m])
Visualization: Multi-graph (3 panels stacked)
```

**Panel 5: Goroutine Count**
```
Metric: firewall_goroutines
Visualization: Time-series graph
Alert: Goroutines > 1000 (potential goroutine leak)
```

---

**3. Security Dashboard (firewall-security.json)**

**Purpose:** Security-focused metrics for SOC analysts

**Dashboard Panels:**

**Panel 1: Blocked Connections Map**
```
Metric: sum by (country) (firewall_rule_hits_total{action="deny"})
Visualization: World map (GeoIP plugin)
Color: Block count (darker = more blocks)
Data source: GeoIP lookup on src_ip label
Use case: Visualize attack sources geographically
```

**Panel 2: Top Attackers (Table)**
```
Metric: topk(20, sum by (src_ip) (firewall_rule_hits_total{action="deny"}))
Visualization: Table
Columns:
  - Source IP
  - Blocks
  - Country (GeoIP lookup)
Sorting: Descending by blocks
Use case: Identify persistent attackers
```

**Panel 3: Attack Rate**
```
Metric: rate(firewall_packets_total{action="deny"}[1m])
Visualization: Time-series graph
Y-Axis: Attacks/sec
Annotation: Mark known attack incidents
Alert: Spike detection (>10× baseline)
```

**Panel 4: Blocked Domains Timeline**
```
Metric: increase(firewall_rule_hits_total{action="deny"}[1m]) by (domain)
Visualization: Time-series graph (multi-line)
Legend: Top 10 blocked domains
Use case: Track blocking patterns over time
```

---

**4. System Dashboard (firewall-system.json)**

**Purpose:** Infrastructure metrics for SRE teams

**Dashboard Panels:**

**Panel 1: CPU Usage**
```
Metric: firewall_cpu_percent
Visualization: Gauge
Thresholds:
  - <70%: Green
  - 70-90%: Yellow
  - >90%: Red (overloaded)
Alert: >90% for 5 minutes
```

**Panel 2: Memory Usage**
```
Metric: firewall_memory_bytes{component="total"}
Visualization: Time-series graph
Y-Axis: MB
Limit line: 500MB (threshold)
Alert: >500MB for 10 minutes
```

**Panel 3: Connection Table Size**
```
Metric: firewall_connections_active
Visualization: Time-series graph
Alert: >100,000 connections (table full)
```

**Panel 4: WFP Filter Count**
```
Metric: firewall_wfp_filters by (layer)
Visualization: Stat panels (3 panels)
Layers: Inbound, Outbound, ALE
Use case: Verify WFP filters installed
```

---

**5. Alerting Rules (prometheus-alerts.yml)**

**Purpose:** Define Prometheus alerts for critical events

**Alert Definitions:**
```yaml
groups:
  - name: firewall_alerts
    interval: 30s
    rules:
      # High deny rate (potential attack)
      - alert: HighDenyRate
        expr: rate(firewall_packets_total{action="deny"}[1m]) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet deny rate"
          description: "Denying {{ $value }} packets/sec for 5 minutes"

      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: firewall_cache_hit_rate < 0.85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low cache hit rate"
          description: "Cache hit rate {{ $value }}% (target >90%)"

      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(firewall_latency_seconds_bucket[1m])) > 0.001
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet processing latency"
          description: "P99 latency {{ $value }}s (target <1ms)"

      # Engine unhealthy
      - alert: EngineUnhealthy
        expr: firewall_engine_health == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Firewall engine unhealthy"
          description: "Engine {{ $labels.engine }} is unhealthy"

      # High memory usage
      - alert: HighMemoryUsage
        expr: firewall_memory_bytes{component="total"} > 500000000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage {{ $value | humanize }}B (limit 500MB)"

      # Firewall down
      - alert: FirewallDown
        expr: up{job="safeops-firewall"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Firewall is down"
          description: "Firewall has been down for 1 minute"
```

---

#### Files to Create:
```
docs/grafana/
├── firewall-overview.json       # Main dashboard (NOC)
├── firewall-performance.json    # Performance metrics (SRE)
├── firewall-security.json       # Security metrics (SOC)
├── firewall-system.json         # System metrics (SRE)
├── prometheus-alerts.yml        # Alert definitions
└── README.md                    # Dashboard setup instructions
```

---

## 📊 Phase 5 Success Criteria

**By end of Phase 5, the firewall must demonstrate:**

1. ✅ **Structured Logging:**
   - JSON logs written to stdout (Docker/Kubernetes compatible)
   - Log levels configurable (info, debug, trace)
   - Log rotation enabled (100MB files, 30 day retention)
   - Context loggers used (per-flow, per-component)

2. ✅ **Prometheus Metrics:**
   - /metrics endpoint exposed (http://localhost:9090/metrics)
   - 20+ metrics defined (packets, latency, cache, health)
   - Prometheus successfully scraping (15s interval)
   - Metrics visible in Prometheus UI

3. ✅ **Health Monitoring:**
   - /health endpoint exposed (http://localhost:8080/health)
   - Component health checks implemented (SafeOps, WFP, rules, cache)
   - Kubernetes probes configured (liveness, readiness, startup)
   - Health status accurate (degraded vs unhealthy)

4. ✅ **Management API:**
   - gRPC server running (localhost:50054)
   - All RPCs functional (GetStatistics, ReloadRules, GetHealth)
   - Authentication enabled (API keys or mTLS)
   - CLI tool working (safeops-firewall-cli)

5. ✅ **Grafana Dashboards:**
   - 4 dashboards created (overview, performance, security, system)
   - Dashboards imported to Grafana
   - All panels displaying data correctly
   - Alerts configured in Prometheus

---

## 🚀 Next Steps After Phase 5

After Phase 5 completion, proceed to:
- **Phase 6:** Hot-Reload & Configuration Management (zero-downtime rule updates)
- **Phase 7:** Security Features (DDoS protection, rate limiting, GeoIP blocking)
- **Phase 8:** Testing & Benchmarking (stress tests, integration tests)

**Estimated Total Time for Phase 5:** 2 weeks

---

**END OF PHASE 5 DOCUMENTATION**
