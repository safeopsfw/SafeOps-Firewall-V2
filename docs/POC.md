# SafeOps Firewall V2 — Proof of Concept

> **Version:** 1.0 | **Date:** March 2026 | **Platform:** Windows Server 2022 / Windows 11

This document provides a detailed, file-by-file breakdown of how each SafeOps component works internally, what it does at runtime, and visual proof of its operation.

---

## Tool 1: SafeOps Launcher — `src/launcher/main.go` (The Orchestrator)

**What it does:** The "Conductor" of the entire SafeOps platform. It spawns, monitors, and gracefully shuts down all 11 child services in the correct dependency order — like an orchestra conductor that ensures the violins start before the cellos.

### Active Working:

- **Service Discovery:** On startup, it reads a hardcoded service manifest that defines each service's binary path, working directory, arguments, and startup priority. It resolves all paths relative to the executable location.
- **Ordered Startup:** It spawns services in strict dependency order with configurable delays between each launch:
  1. SafeOps Engine (NDIS packet interception — must be first)
  2. Firewall Engine (connects to Engine's gRPC on `:50051`)
  3. NIC Management, DHCP Monitor, Captive Portal (network services)
  4. Step-CA (certificate authority)
  5. Network Logger, SIEM Forwarder, Threat Intel (data pipeline)
- **PID Tracking:** After spawning each service, it stores the child's PID and polls it every 10 seconds to verify the process is still alive. If a child dies unexpectedly, it logs the exit code.
- **Crucially:** On `Ctrl+C` or `SIGTERM`, it performs a **reverse-order graceful shutdown** — data services stop first, then network services, then the core engine. This prevents data corruption from in-flight packets being dropped mid-write.

### Sample Log Output:

```
╔═══════════════════════════════════════════════════════════╗
║          SafeOps Launcher v1.0 — Starting Services        ║
╚═══════════════════════════════════════════════════════════╝

[14:30:01] [LAUNCH] safeops-engine.exe        → PID 4812
[14:30:04] [LAUNCH] firewall-engine.exe       → PID 5128
[14:30:07] [LAUNCH] nic_management.exe        → PID 5344
[14:30:10] [LAUNCH] dhcp_monitor.exe          → PID 5520
[14:30:13] [LAUNCH] captive_portal.exe        → PID 5692
[14:30:16] [LAUNCH] step-ca.exe               → PID 5880
[14:30:19] [LAUNCH] network-logger.exe        → PID 6044
[14:30:22] [LAUNCH] siem-forwarder.exe        → PID 6216
[14:30:25] [LAUNCH] threat_intel.exe          → PID 6388

[14:30:25] [OK] All 9 services started successfully

^C
[14:45:12] [SHUTDOWN] Signal received — stopping services...
[14:45:12] [STOP] threat_intel.exe           (PID 6388) ✓
[14:45:13] [STOP] siem-forwarder.exe         (PID 6216) ✓
[14:45:14] [STOP] network-logger.exe         (PID 6044) ✓
[14:45:15] [STOP] safeops-engine.exe         (PID 4812) ✓
[14:45:16] [OK] All services stopped. Exiting.
```

### Screenshots:

> **Screenshot 1.1 — Launcher Startup Sequence**
>
> _[Insert screenshot of launcher console showing all services starting with PIDs]_

---

> **Screenshot 1.2 — Task Manager — Running Services**
>
> _[Insert screenshot of Windows Task Manager → Details tab showing all SafeOps processes]_

---

> **Screenshot 1.3 — Graceful Shutdown**
>
> _[Insert screenshot of console showing reverse-order shutdown with cleanup]_

---

---

## Tool 2: SafeOps Engine — `src/safeops-engine/pkg/engine/engine.go` (The Packet Interceptor)

**What it does:** The "Eyes and Hands" of the firewall. It sits between the network adapter and the OS network stack using a kernel-mode WinPkFilter/NDIS driver, inspecting every single packet that enters or leaves the machine. It can see, read, modify, block, or redirect any packet in real-time.

### Active Working:

- **Driver Initialization:** On startup, it loads the WinPkFilter NDIS driver (`.sys` file), opens a handle to the kernel, and enumerates all network adapters. It attaches a packet filter to each active adapter.
- **Fast Path (Hot Loop):** For every packet, it runs a lightweight check:
  1. Extract IP header → source/destination IPs
  2. Extract protocol (TCP/UDP/ICMP)
  3. For TCP port 53 (DNS): Parse DNS query → extract queried domain name
  4. For TCP port 443 (TLS): Parse ClientHello → extract SNI (Server Name Indication)
- **Verdict System:** Each packet gets a verdict:
  - `ALLOW` — packet forwarded normally to OS network stack
  - `BLOCK` — packet silently dropped (never reaches the application)
  - `REDIRECT` — packet modified and forwarded (for captive portal redirection)
- **gRPC Metadata Stream:** On `:50051`, it exposes a gRPC server that streams packet metadata (IP, port, domain, verdict, timestamp) to connected clients — this is how the Firewall Engine receives live traffic data.
- **Crucially:** The engine processes packets in **microseconds** using a zero-allocation hot path. DNS and TLS domain extraction happens inline — no buffering, no queuing. If it can't determine the verdict in <1ms, it defaults to `ALLOW` to avoid blocking legitimate traffic.

### Sample Log Output:

```
[14:30:01] [ENGINE] WinPkFilter driver loaded successfully
[14:30:01] [ENGINE] NDIS handle: 0x00000284
[14:30:01] [ENGINE] Adapter: "Ethernet 2" (Intel I211) — ATTACHED
[14:30:01] [ENGINE] Adapter: "Wi-Fi" (Realtek 8822CE) — ATTACHED
[14:30:01] [ENGINE] gRPC server listening on :50051
[14:30:01] [ENGINE] Packet capture started

[14:30:05] [PKT] TCP 192.168.137.100:52341 → 142.250.193.46:443  TLS-SNI: google.com      ALLOW
[14:30:05] [PKT] UDP 192.168.137.100:55432 → 8.8.8.8:53           DNS: google.com           ALLOW
[14:30:06] [PKT] TCP 192.168.137.100:52345 → 185.220.101.42:443   TLS-SNI: evil-malware.ru  BLOCK ★
[14:30:06] [PKT] TCP 192.168.137.22:49221  → 10.0.0.1:445         SMB                       ALLOW

[STATS] 1,247 pkts/sec | 3.2 MB/sec | ALLOW: 1,241 | BLOCK: 6 | REDIRECT: 0
```

### Screenshots:

> **Screenshot 2.1 — Engine Startup & Adapter Discovery**
>
> _[Insert screenshot of engine console showing NDIS driver loading and adapter attachment]_

---

> **Screenshot 2.2 — Live Packet Interception**
>
> _[Insert screenshot showing real-time packet log with domain extraction and verdicts]_

---

> **Screenshot 2.3 — Statistics Output**
>
> _[Insert screenshot of packets/sec, bytes/sec, and verdict breakdown]_

---

---

## Tool 3: Firewall Engine — `src/firewall_engine/cmd/main.go` (The 8-Stage Decision Pipeline)

**What it does:** The "Judge and Jury" for every network connection. It receives packet metadata from the SafeOps Engine via gRPC and runs each connection through an **8-stage synchronous inspection pipeline** to decide whether to allow or block it. Think of it as 8 security guards, each checking a different badge.

### Active Working:

The pipeline processes each connection in strict order. If any stage issues a `BLOCK`, the connection is immediately dropped and no further stages are checked:

- **Stage 1 — Whitelist Check:** Is this IP/domain on the admin-defined whitelist? If yes, skip ALL remaining stages → `ALLOW`. This is the fast escape hatch for trusted services (e.g., Windows Update, Microsoft telemetry).
- **Stage 2 — Security Monitor:** Check DDoS detection counters. If a source IP exceeds the configured threshold (e.g., >1000 SYN packets in 10 seconds), → `BLOCK` and flag as DDoS.
- **Stage 3 — Custom Rules:** Apply admin-defined custom firewall rules (IP ranges, port ranges, protocol combinations). Rules are loaded from PostgreSQL and **hot-reloaded via atomic pointer swap** — no restart needed.
- **Stage 4 — Manual Blocklist:** Check the manually-curated IP/domain blocklist. Admins can add entries via the API in real-time.
- **Stage 5 — GeoIP Blocking:** Look up the IP's country using the MaxMind GeoIP database. If the country is in the blocked list (e.g., block all traffic from specific high-risk countries), → `BLOCK`.
- **Stage 6 — Threat Intel Lookup:** Query the PostgreSQL `threat_intel_db` for IP/domain reputation scores. If the score exceeds the threshold → `BLOCK`. This is where known malware C2 servers, phishing domains, and botnet IPs get caught.
- **Stage 7 — Domain Filtering:** Category-based domain blocking (adult content, gambling, social media, etc.). Uses the domain name extracted by the SafeOps Engine from DNS/TLS.
- **Stage 8 — Packet Inspector:** Deep packet inspection for protocol anomalies (malformed headers, suspicious payloads, etc.).
- **Crucially:** Rules at Stage 3 can be updated via `POST /api/rules` and take effect **within milliseconds** using Go's `atomic.Value` pointer swap — the pipeline never stops, never restarts, and never drops a single packet during reload.

### Sample Log Output:

```
[14:30:04] [FW] Pipeline initialized — 8 stages loaded
[14:30:04] [FW] Connected to SafeOps Engine gRPC on :50051
[14:30:04] [FW] Threat Intel: 148,293 IPs + 23,847 domains loaded
[14:30:04] [FW] GeoIP database: 2026-03 edition loaded
[14:30:04] [FW] API server listening on :50052 (HTTP) + :8443 (HTTPS UI)

[14:30:08] [PIPELINE] 192.168.1.5 → google.com         Stage 1: WHITELIST → ALLOW ✓
[14:30:08] [PIPELINE] 192.168.1.5 → evil-c2-server.ru  Stage 6: THREAT_INTEL → BLOCK ★ (Cobalt Strike C2, score: 98/100)
[14:30:09] [PIPELINE] 45.33.32.1 → 192.168.1.5         Stage 5: GEOIP → BLOCK ★ (Country: RU, blocked)
[14:30:09] [PIPELINE] 192.168.1.5 → pornhub.com        Stage 7: DOMAIN_FILTER → BLOCK ★ (Category: adult)

[14:31:00] [FW] [HOT-RELOAD] Custom rules updated via API — 3 new rules applied (0 downtime)

[STATS] Pipeline: 3,421 decisions/sec | Avg latency: 0.3ms | Block rate: 4.2%
  Stage 1 (Whitelist):    892 bypasses
  Stage 2 (Security):       0 DDoS blocks
  Stage 3 (Custom):         3 rule blocks
  Stage 4 (Blocklist):     12 manual blocks
  Stage 5 (GeoIP):         41 country blocks
  Stage 6 (Threat Intel):  89 reputation blocks
  Stage 7 (Domain):        38 category blocks
  Stage 8 (Inspector):      0 anomaly blocks
```

### Screenshots:

> **Screenshot 3.1 — Pipeline Initialization**
>
> _[Insert screenshot of console showing all 8 stages loading with threat intel counts]_

---

> **Screenshot 3.2 — Live Pipeline Decisions**
>
> _[Insert screenshot showing packets flowing through stages with ALLOW/BLOCK verdicts]_

---

> **Screenshot 3.3 — Threat Intel Block**
>
> _[Insert screenshot of a known malicious IP/domain blocked at Stage 6 with threat details]_

---

> **Screenshot 3.4 — Hot-Reload Rule Update**
>
> _[Insert screenshot of API rule update and immediate enforcement confirmation]_

---

> **Screenshot 3.5 — Embedded Web UI (localhost:8443)**
>
> _[Insert screenshot of the Firewall Engine's built-in web dashboard]_

---

> **Screenshot 3.6 — Per-Stage Statistics**
>
> _[Insert screenshot of GET /api/stats showing hit counts per pipeline stage]_

---

---

## Tool 4: Threat Intelligence — `src/threat_intel/cmd/pipeline/main.go` (The Intelligence Brain)

**What it does:** The "CIA of the network" — it continuously fetches threat indicators from 7+ public OSINT sources (abuse.ch, Spamhaus, AlienVault OTX, etc.), processes and scores them, and stores everything in PostgreSQL so the Firewall Engine can block known-bad IPs, domains, and file hashes in real-time.

### Active Working:

- **Feed Fetching (Extract):** Downloads threat data from multiple OSINT sources in parallel:
  - abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker)
  - Spamhaus DROP/EDROP lists
  - AlienVault OTX pulse subscriptions
  - Emerging Threats rulesets
  - Custom threat feeds configured in YAML
- **Processing (Transform):** For each indicator:
  1. Normalize format (IPv4/IPv6 → standard notation, domains → lowercase)
  2. Deduplicate across feeds (same IP from 3 sources → single entry, score boosted)
  3. Apply reputation scoring algorithm (source trust × recency × severity = risk score 0-100)
  4. Enrich with GeoIP data (country, city, ASN)
  5. Classify into threat categories (malware, phishing, C2, botnet, spam, scanner)
- **Storage (Load):** Bulk-insert into PostgreSQL tables:
  - `ip_reputation` — millions of IPs with risk scores
  - `domain_reputation` — malicious/suspicious domains
  - `hash_reputation` — malware file hashes (MD5, SHA256)
  - `threat_feeds` — feed source metadata and health
- **Scheduler Mode (`-scheduler`):** Runs the full ETL pipeline on a 6-hour cycle, keeping threat data fresh.
- **Crucially:** After the first run completes, the Firewall Engine's Stage 6 (Threat Intel Lookup) is populated with **100,000+ indicators**. This means a brand-new SafeOps deployment blocks known C2 servers, phishing sites, and malware download URLs within minutes of first boot — without any manual configuration.

### Sample Log Output:

```
[14:30:00] [THREAT-INTEL] Starting ETL pipeline v1.0
[14:30:00] [THREAT-INTEL] Mode: one-shot (use -scheduler for recurring)

[EXTRACT] Fetching feeds...
  [1/7] abuse.ch URLhaus        ████████████████████ 100%  → 48,293 URLs
  [2/7] abuse.ch MalwareBazaar  ████████████████████ 100%  → 12,847 hashes
  [3/7] abuse.ch Feodo Tracker  ████████████████████ 100%  →  1,293 C2 IPs
  [4/7] Spamhaus DROP           ████████████████████ 100%  →    821 CIDRs
  [5/7] Spamhaus EDROP          ████████████████████ 100%  →    394 CIDRs
  [6/7] AlienVault OTX          ████████████████████ 100%  → 23,847 indicators
  [7/7] Emerging Threats        ████████████████████ 100%  → 61,205 IPs

[TRANSFORM] Processing...
  Normalized:     148,700 indicators
  Deduplicated:    12,407 removed (cross-feed overlaps)
  Final count:    136,293 unique indicators
  Scoring:        136,293 scored (avg risk: 67.3/100)

[LOAD] Inserting into PostgreSQL...
  ip_reputation:      98,441 rows (upsert)
  domain_reputation:  23,847 rows (upsert)
  hash_reputation:    14,005 rows (upsert)

[COMPLETE] Pipeline finished in 4m 23s
  Total indicators: 136,293
  New this run:      8,294
  Updated:          41,872
  Unchanged:        86,127
```

### Screenshots:

> **Screenshot 4.1 — Feed Download Progress**
>
> _[Insert screenshot of the pipeline console showing parallel feed downloads with progress bars]_

---

> **Screenshot 4.2 — PostgreSQL Data (ip_reputation table)**
>
> _[Insert screenshot of pgAdmin showing ip_reputation table with IP, score, source, and category columns]_

---

> **Screenshot 4.3 — Pipeline Completion Summary**
>
> _[Insert screenshot of the final stats: indicators processed, deduplicated, time elapsed]_

---

---

## Tool 5: Network Logger — `src/network_logger/cmd/logger/main.go` (The Forensics Recorder)

**What it does:** The "Black Box Flight Recorder" of the network. It passively captures ALL network traffic across every interface and writes it to 5 parallel log collectors in different formats — creating a complete forensic audit trail that can be replayed, searched, and shipped to SIEM.

### Active Working:

- **Multi-Interface Scanner:** On startup, uses `gopacket/pcap` to enumerate all network adapters and starts a packet capture on each active non-loopback interface simultaneously.
- **6-Stage Enrichment Pipeline:** Every captured packet passes through 6 enrichment stages before being written:
  1. **Layer Decode** — Parse Ethernet → IP → TCP/UDP → payload
  2. **DNS Extraction** — Parse DNS queries and responses for domain names
  3. **TLS Extraction** — Parse TLS ClientHello for SNI + certificate info
  4. **GeoIP Lookup** — Map external IPs to country/city/ASN
  5. **Process Correlation** — Map socket → Windows PID → process name
  6. **Flow Classification** — Classify as East-West (internal) or North-South (external)
- **5 Parallel Collectors:** Each enriched packet is written to 5 independent log streams:
  1. `master.jsonl` — Every packet with all fields (complete forensic record)
  2. `ids_ips/eve.json` — Suricata-compatible IDS/IPS event format
  3. `netflow/east_west.jsonl` — Internal-to-internal traffic flows
  4. `netflow/north_south.jsonl` — Internal-to-external traffic flows
  5. `ip_summary.jsonl` — Per-IP aggregate statistics (bytes, packets, connections)
- **Log Rotation:** Files rotate every 5 minutes (configurable), with timestamp suffixes for chronological ordering.
- **Crucially:** Unlike tcpdump or Wireshark which capture raw packets, the Network Logger produces **enriched, structured JSON** with process names, country codes, and domain names already resolved — making SIEM analysis instant without post-processing.

### Sample Log Output:

```
[14:30:19] [LOGGER] gopacket/pcap initialized
[14:30:19] [LOGGER] Interface: "Ethernet 2" (192.168.137.1) — CAPTURING
[14:30:19] [LOGGER] Interface: "Wi-Fi" (192.168.1.5) — CAPTURING
[14:30:19] [LOGGER] Collectors: master | ids_ips | netflow_ew | netflow_ns | ip_summary
[14:30:19] [LOGGER] Rotation interval: 5m0s

[14:30:20] [CAPTURE] 247 pkts/sec across 2 interfaces
[14:35:20] [ROTATE] master.jsonl → master_20260325_143520.jsonl (42,891 events)
[14:35:20] [ROTATE] eve.json → eve_20260325_143520.json (1,247 IDS events)
```

**Sample master.jsonl entry:**
```json
{
  "timestamp": "2026-03-25T14:30:21.847Z",
  "src_ip": "192.168.137.100",
  "dst_ip": "142.250.193.46",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "domain": "google.com",
  "tls_sni": "google.com",
  "process": "chrome.exe",
  "pid": 8844,
  "geo_dst": {"country": "US", "city": "Mountain View", "asn": "AS15169"},
  "flow": "north_south",
  "bytes": 1420,
  "verdict": "ALLOW"
}
```

### Screenshots:

> **Screenshot 5.1 — Interface Discovery & Capture**
>
> _[Insert screenshot of network-logger console showing adapter enumeration and capture start]_

---

> **Screenshot 5.2 — master.jsonl Content**
>
> _[Insert screenshot of master.jsonl showing enriched packet records with domains and GeoIP]_

---

> **Screenshot 5.3 — Log Rotation**
>
> _[Insert screenshot of log directory showing rotated files with timestamps]_

---

---

## Tool 6: NIC Management — `src/nic_management/cmd/main.go` (The Network Controller)

**What it does:** The "Traffic Controller" for network interfaces. It discovers all network adapters, manages Multi-WAN failover, configures NAT/ICS (Internet Connection Sharing), monitors bandwidth in real-time, and exposes everything via a unified REST + gRPC API.

### Active Working:

- **Adapter Discovery:** On startup, it enumerates all physical and virtual network adapters using the Windows Networking API (`iphlpapi.dll`). For each adapter, it captures: MAC address, IP assignments, speed, media type, operational status, and driver info.
- **Failover State Machine:** Each adapter runs through a state machine:
  - `ACTIVE` → primary adapter handling traffic
  - `STANDBY` → healthy but waiting as backup
  - `FAILED` → adapter down, connectivity lost
  - When the ACTIVE adapter goes down, the system automatically promotes the STANDBY adapter and reconfigures NAT routing in under 3 seconds.
- **NAT/ICS Engine:** Configures Windows Internet Connection Sharing to share the primary adapter's internet connection with the LAN. Tracks active NAT sessions and handles port forwarding rules.
- **Bandwidth Monitor:** Polls adapter statistics every 2 seconds, calculating real-time bytes/sec, packets/sec, and error rates per interface.
- **Dual API:** Exposes the same operations via both REST (`:8081`) and gRPC, so the Desktop App and CLI tools can both control NICs.
- **Crucially:** The failover happens **automatically and transparently** — if your primary WAN connection drops, clients on the LAN see a <3 second interruption while the backup adapter takes over. No manual intervention needed.

### Sample Log Output:

```
[14:30:07] [NIC] Service started on :8081 (REST) + :50053 (gRPC)

[DISCOVERY] Found 4 network adapters:
  [1] Ethernet 2      Intel I211        192.168.137.1   1 Gbps    ACTIVE ★
  [2] Wi-Fi            Realtek 8822CE    192.168.1.5     866 Mbps  STANDBY
  [3] Loopback         Software          127.0.0.1       —         SKIP
  [4] vEthernet (WSL)  Hyper-V           172.17.0.1      10 Gbps   SKIP

[NAT] Internet Connection Sharing enabled: Ethernet 2 → LAN
[NAT] Active sessions: 47 | Port forwards: 3

[BANDWIDTH] Live stats (2s interval):
  Ethernet 2:  ↓ 12.4 MB/s  ↑ 1.8 MB/s  (847 pkts/s)
  Wi-Fi:       ↓ 0.0 MB/s   ↑ 0.0 MB/s  (idle - standby)

[14:42:31] [FAILOVER] ★ Ethernet 2 link DOWN detected!
[14:42:31] [FAILOVER] Promoting Wi-Fi to ACTIVE...
[14:42:32] [FAILOVER] NAT reconfigured: Wi-Fi → LAN
[14:42:33] [FAILOVER] ✓ Failover complete in 2.1s
```

### Screenshots:

> **Screenshot 6.1 — Adapter Discovery**
>
> _[Insert screenshot of console showing all discovered NICs with speeds and states]_

---

> **Screenshot 6.2 — REST API Response (GET /api/nics)**
>
> _[Insert screenshot of browser/Postman showing JSON list of all adapters]_

---

> **Screenshot 6.3 — Failover Event**
>
> _[Insert screenshot of console showing automatic failover from primary to backup adapter]_

---

> **Screenshot 6.4 — Bandwidth Monitor**
>
> _[Insert screenshot of real-time per-NIC bandwidth statistics]_

---

---

## Tool 7: DHCP Monitor — `src/dhcp_monitor/cmd/dhcp_monitor/main.go` (The Device Radar)

**What it does:** The "Radar System" of the network. It continuously scans the ARP table to discover every device connected to the LAN, enriches each device with vendor info (from MAC OUI), hostname (from DHCP event logs), and assigns it a trust level — creating a live inventory of everything on the network.

### Active Working:

- **ARP Table Polling (The Scanner):** Every 30 seconds, it reads the Windows ARP table (`arp -a`) to get all IP↔MAC mappings on the LAN. New MACs are flagged as newly discovered devices.
- **Device Enrichment Pipeline:**
  1. **MAC OUI Lookup** — First 3 bytes of MAC → manufacturer (e.g., `AA:BB:CC` → "Apple Inc.")
  2. **DHCP Event Log** — Reads Windows DHCP Event Log (Event ID 10) to extract hostnames assigned during DHCP lease
  3. **mDNS/NetBIOS** — Attempts to resolve device hostname via multicast DNS
  4. **Fingerprinting** — Classifies device type (phone, laptop, IoT, printer) based on MAC vendor + DHCP options
- **Trust Management:** Every new device starts as `UNTRUSTED`. The admin (or Captive Portal) can promote it to `TRUSTED` after CA certificate installation.
  - `UNTRUSTED` → HTTP redirected to Captive Portal for onboarding
  - `TRUSTED` → Full internet access with HTTPS inspection
  - `BLOCKED` → No network access at all
- **Device Lifecycle:** Devices transition through states:
  - `ACTIVE` — seen in ARP table within last 10 minutes
  - `INACTIVE` — not seen for 10 minutes (device may be asleep)
  - `EXPIRED` — not seen for 24 hours
  - `PURGED` — not seen for 30 days (auto-deleted from database)
- **mDNS Responder:** Announces `safeops-portal.local` on all interfaces so new devices can find the Captive Portal without DNS configuration.
- **Crucially:** The moment a new phone or laptop connects to the Wi-Fi, the DHCP Monitor detects it within 30 seconds, identifies the manufacturer, and flags it as `UNTRUSTED` — triggering the Captive Portal onboarding flow automatically.

### Sample Log Output:

```
[14:30:10] [DHCP] Connected to PostgreSQL: safeops_network
[14:30:10] [DHCP] Database migrations applied (4 migrations)
[14:30:10] [DHCP] gRPC server listening on :50055
[14:30:10] [DHCP] mDNS responder started: safeops-portal.local → 192.168.137.1
[14:30:10] [DHCP] ARP scanner started (interval: 30s)

[14:30:40] [ARP SCAN] Discovered 7 devices:
  192.168.137.100  AA:BB:CC:11:22:33  Apple Inc.        "iPhone-John"     TRUSTED
  192.168.137.101  DE:AD:BE:EF:00:01  Samsung           "Galaxy-S24"      TRUSTED
  192.168.137.102  11:22:33:44:55:66  Intel Corp.       "DESKTOP-WORK"    TRUSTED
  192.168.137.103  AA:BB:CC:DD:EE:FF  Espressif         (unknown)         UNTRUSTED ★ NEW

[14:30:41] [NEW DEVICE] ★ 192.168.137.103 — Espressif (ESP32 IoT device)
           MAC: AA:BB:CC:DD:EE:FF | Trust: UNTRUSTED | Redirecting to Captive Portal

[14:31:10] [ARP SCAN] 7 active devices | 0 inactive | 2 expired
```

### Screenshots:

> **Screenshot 7.1 — Device Discovery (ARP Scan)**
>
> _[Insert screenshot of DHCP Monitor console showing discovered devices with vendors]_

---

> **Screenshot 7.2 — PostgreSQL Devices Table**
>
> _[Insert screenshot of pgAdmin showing device table with MAC, IP, vendor, trust status]_

---

> **Screenshot 7.3 — New Device Detection**
>
> _[Insert screenshot of console showing a newly connected device flagged as UNTRUSTED]_

---

> **Screenshot 7.4 — mDNS Resolution**
>
> _[Insert screenshot of nslookup/ping resolving safeops-portal.local]_

---

---

## Tool 8: Captive Portal — `src/captive_portal/internal/server/handlers.go` (The Gatekeeper)

**What it does:** The "Airport Security Checkpoint" for new devices. When an untrusted device connects to the network, all its HTTP traffic is redirected here. The portal provides a friendly web page with OS-specific instructions to install the SafeOps Root CA certificate — the digital equivalent of checking your passport before letting you through.

### Active Working:

- **Device Interception:** When a new device (flagged UNTRUSTED by DHCP Monitor) tries to browse the web, the firewall redirects all port-80 traffic to the Captive Portal on `:8090`.
- **OS Auto-Detection:** The portal reads the device's `User-Agent` header and automatically shows the correct certificate installation instructions:
  - **Windows** → Download `.crt` (PEM) → "Run certutil to install to Trusted Root"
  - **macOS** → Download `.crt` (PEM) → "Open Keychain Access → Trust"
  - **Android** → Download `.crt` (DER) → "Settings → Security → Install Certificate"
  - **iOS** → Download `.crt` (DER profile) → "Settings → Profile Downloaded → Install"
- **Certificate Serving:** The cert download endpoint serves the Root CA in the optimal format:
  - Desktop browsers → PEM (`.crt`)
  - Mobile browsers → DER (`.crt` with binary encoding)
  - Enterprise → PKCS#12 (`.p12` bundle)
  - The certificate is sourced from Step-CA's cert directory (`src/CA Cert/`)
- **Trust Verification:** After the user installs the certificate, they click "Verify" and the portal:
  1. Checks if the device can successfully complete a TLS handshake with a SafeOps-signed cert
  2. If successful → marks device as TRUSTED in DHCP Monitor database
  3. Removes the redirect rule → device gets full internet access
- **Crucially:** The entire onboarding takes under 60 seconds. A user connects to Wi-Fi, sees the portal page automatically (like airport/hotel Wi-Fi), taps "Download", installs the cert, and they're through. No IT support needed.

### Sample Log Output:

```
[14:30:13] [PORTAL] Server started on :8090 (HTTP) + :8445 (HTTPS)
[14:30:13] [PORTAL] CA certificate loaded: SafeOps Root CA (EC P-256)
[14:30:13] [PORTAL] Connected to DHCP Monitor gRPC on :50055

[14:31:02] [PORTAL] → New visitor: 192.168.137.103
           Device:  AA:BB:CC:DD:EE:FF (Espressif)
           OS:      Android 14 (detected from User-Agent)
           Trust:   UNTRUSTED → showing onboarding page

[14:31:15] [PORTAL] ↓ Certificate downloaded by 192.168.137.103
           Format:  DER (.crt) — auto-selected for Android
           Size:    660 bytes

[14:31:45] [PORTAL] ✓ Trust verified for 192.168.137.103
           Device marked TRUSTED in database
           CA cert installed: true
           Redirect rule removed — full internet access granted
```

### Screenshots:

> **Screenshot 8.1 — Captive Portal Welcome Page (Desktop)**
>
> _[Insert screenshot of the portal welcome page in a desktop browser showing cert download button]_

---

> **Screenshot 8.2 — Captive Portal Welcome Page (Mobile)**
>
> _[Insert screenshot of the portal on a mobile device with OS-specific install instructions]_

---

> **Screenshot 8.3 — Certificate Download Dialog**
>
> _[Insert screenshot of the browser download dialog for the CA certificate]_

---

> **Screenshot 8.4 — Trust Verified Confirmation**
>
> _[Insert screenshot of the success page after cert installation showing TRUSTED status]_

---

---

## Tool 9: SIEM Forwarder — `src/siem-forwarder/internal/shipper/shipper.go` (The Log Courier)

**What it does:** A lightweight "Filebeat replacement" built with zero dependencies (pure Go stdlib). It tails SafeOps JSONL log files in real-time, batches them into Elasticsearch Bulk API requests, and ships them to Elasticsearch with proper indexing, timestamp extraction, and retention management.

### Active Working:

- **Tailer (The Watcher):** For each configured log file (firewall, IDS, netflow), it opens a goroutine that `tail -f`s the file, sending each new line to a buffered Go channel (capacity: 1,000 events).
- **Position Tracking (Crash Recovery):** After every successful Elasticsearch batch, it saves the file offset to a local position database (BoltDB-style). On restart, it resumes from the exact byte position — no missed events, no duplicates.
- **Shipper (The Sender):** A separate goroutine reads from the channel and batches events:
  - Collects up to **500 documents** or waits **5 seconds** (whichever comes first)
  - Formats them as an Elasticsearch `_bulk` API request
  - POSTs to Elasticsearch with proper date-suffixed index names (e.g., `safeops-fw-2026.03.25`)
- **Timestamp Extraction:** For each log type, it extracts the original event timestamp from the JSON:
  - Firewall logs: `timestamp` field
  - IDS logs: `timestamp` field
  - NetFlow logs: `flow_start` field
  - Falls back to current time if field is missing
- **Retention Manager:** Every 6 hours, it scans Elasticsearch for SafeOps indices older than `max_days` (default: 14 days) and deletes them automatically.
- **Crucially:** The forwarder uses **zero external dependencies** — pure Go `net/http` for Elasticsearch Bulk API. This means no Java, no JVM, no Beats framework — just a 5MB binary that ships logs reliably.

### Sample Log Output:

```
[14:30:22] [SIEM] SIEM Forwarder v1.0 starting...
[14:30:22] [SIEM] Waiting for Elasticsearch health...
[14:30:23] [SIEM] ✓ Elasticsearch ready at http://localhost:9200 (cluster: safeops)

[14:30:23] [TAILER] Started: logs/firewall.jsonl       → index: safeops-fw
[14:30:23] [TAILER] Started: logs/ids_ips/eve.json     → index: safeops-ids
[14:30:23] [TAILER] Started: logs/netflow/north_south  → index: safeops-netflow

[14:30:28] [SHIP] Batch shipped: 500 docs → safeops-fw-2026.03.25 (124ms)
[14:30:33] [SHIP] Batch shipped: 342 docs → safeops-fw-2026.03.25 (98ms)
[14:30:33] [SHIP] Batch shipped:  47 docs → safeops-ids-2026.03.25 (31ms)

^C
[14:45:00] [SIEM] Shutdown signal received
[14:45:00] [SIEM] Draining buffer: 89 remaining events...
[14:45:01] [SIEM] Final batch shipped: 89 docs (45ms)
[14:45:01] [SIEM] Positions saved. Total shipped: 28,491 docs | Errors: 0
```

### Screenshots:

> **Screenshot 9.1 — Forwarder Startup & ES Connection**
>
> _[Insert screenshot of forwarder console showing Elasticsearch health check and tailer init]_

---

> **Screenshot 9.2 — Kibana — SafeOps Indices**
>
> _[Insert screenshot of Kibana Index Management showing date-suffixed indices]_

---

> **Screenshot 9.3 — Kibana — Log Search**
>
> _[Insert screenshot of Kibana Discover showing SafeOps firewall events with timestamps]_

---

> **Screenshot 9.4 — Graceful Shutdown & Drain**
>
> _[Insert screenshot of forwarder draining buffer and saving positions on shutdown]_

---

---

## Tool 10: Step-CA — `src/step-ca/scripts/start-stepca.ps1` (The Trust Anchor)

**What it does:** The "Government Passport Office" of the network. It is the internal Certificate Authority (CA) that issues TLS certificates for all SafeOps services. Every device on the network must trust this CA's Root Certificate to allow secure communication and HTTPS inspection. It wraps the open-source Smallstep `step-ca` binary with SafeOps-specific management scripts.

### Active Working:

- **PostgreSQL Password Retrieval (start-stepca.ps1):**
  1. Queries `safeops_network.secrets` table for the CA master password (`service_name = 'step-ca-master'`)
  2. Writes password to a temporary file
  3. Starts `step-ca.exe` with `--password-file` pointing to the temp file
  4. **Immediately deletes** the temp file after Step-CA reads it — password never stays on disk
- **Certificate Chain:**
  - **Root CA** (`root_ca.crt`) — Self-signed, EC P-256, "SafeOps Root CA" — this is what devices install
  - **Intermediate CA** (`intermediate_ca.crt`) — Signed by Root CA, used for actual cert issuance
  - **Leaf Certificates** — Issued to individual services (TLS Proxy, gRPC endpoints)
- **3 Distribution Formats:** The Root CA is exported in 3 formats for universal device support:
  - `.crt` (PEM) — Linux, macOS, Windows
  - `.der` (DER) — Android, iOS
  - `.p12` (PKCS#12) — Enterprise MDM systems
- **6-Point Health Check (health-check.ps1):**
  1. Process running (`Get-Process step-ca`)
  2. API health (`GET /health` → `{"status": "ok"}`)
  3. Root CA downloadable (`GET /roots.pem`)
  4. DB password stored (PostgreSQL query)
  5. Certificate files present (root + intermediate + PEM/DER/P12)
  6. Management scripts exist (all 5 core scripts)
- **Crucially:** The entire trust chain is **automated** — password retrieval, CA startup, cert issuance, and distribution all happen without human intervention. A new SafeOps deployment has a working PKI within seconds of first boot.

### Sample Log Output:

```
PS> .\scripts\start-stepca.ps1

================================================
Starting Step-CA Certificate Authority
================================================
Retrieving password from PostgreSQL...
✅ Password retrieved
Starting Step-CA server on :9000...

2026/03/25 14:30:16 Serving HTTPS on :9000 ...
2026/03/25 14:30:16 Using root CA: D:\SafeOpsFV2\src\step-ca\certs\root_ca.crt
2026/03/25 14:30:16 Using intermediate: D:\SafeOpsFV2\src\step-ca\certs\intermediate_ca.crt
🧹 Cleaned up temporary password file

PS> .\scripts\health-check.ps1

================================================
Step-CA Health Check
================================================

✅ Process: Running (PID: 5880)
✅ API Health: OK
✅ Root CA: Downloadable via API
✅ Database Password: Stored
✅ Root CA (source)
✅ Intermediate CA
✅ Root CA (PEM dist)
✅ Root CA (DER dist)
✅ Root CA (PKCS#12 dist)
✅ Management Scripts: All present

================================================
✅ All critical checks passed - Step-CA is healthy
```

### Screenshots:

> **Screenshot 10.1 — Step-CA Startup**
>
> _[Insert screenshot of start-stepca.ps1 showing password retrieval and server start]_

---

> **Screenshot 10.2 — Health Check (6 Points)**
>
> _[Insert screenshot of health-check.ps1 with all ✅ checks passing]_

---

> **Screenshot 10.3 — Root CA Certificate Details**
>
> _[Insert screenshot of certificate viewer showing Root CA subject, EC P-256 algorithm]_

---

> **Screenshot 10.4 — Certificate Distribution Files**
>
> _[Insert screenshot of CA Cert directory showing root_ca.crt, root_ca.der, root_ca.p12]_

---

---

## Tool 11: Requirements Setup — `src/requirements_setup/main.go` (The One-Click Installer)

**What it does:** The "Construction Crew" that builds the entire SafeOps infrastructure from scratch. Run it once on a clean Windows machine and it downloads, installs, and configures everything — PostgreSQL, Node.js, WinPkFilter driver, 3 databases, 23 SQL schemas, users, permissions, and seed data. A single `.exe` with zero external file dependencies (all SQL schemas are compiled into the binary via `go:embed`).

### Active Working:

- **11-Step Installation Pipeline:**
  1. **Download & Install PostgreSQL 16.1** — EDB installer, silent mode (`--mode unattended`), server + CLI tools only
  2. **Start PostgreSQL Service** — `net start postgresql-x64-16`
  3. **Create 3 Databases** — `threat_intel_db`, `safeops_network`, `safeops`
  4. **Create 4 Database Users** — `safeops`, `threat_intel_app`, `dhcp_server`, `dns_server`
  5. **Apply 23 SQL Schemas** — Threat Intel (13) + SafeOps Network (3) + DHCP Migrations (4) + Patches (2) + Seeds (1)
  6. **Apply Schema Patches** — Column type fixes for the threat intel pipeline binary
  7. **Load Seed Data** — Initial OSINT feed source URLs + threat category taxonomy
  8. **Create Views & Functions** — Aggregated views and stored procedures
  9. **Grant Table Permissions** — ALL on tables + sequences + default privileges for all app users
  10. **Download & Install Node.js 20.11.0** — MSI installer, silent mode
  11. **Download & Install WinPkFilter 3.4.8** — NSIS installer, silent mode
- **Self-Contained Binary:** All 23 SQL files are compiled into the `.exe` via Go's `go:embed` — no need to ship SQL files separately. The installer is a single binary.
- **Idempotent Re-run (`--db-init`):** Safe to run multiple times — uses `CREATE IF NOT EXISTS` and `ON CONFLICT` patterns. Won't break existing data.
- **Nuclear Option (`--db-reset`):** Drops ALL databases and recreates from scratch. For development resets only.
- **Crucially:** A fresh Windows Server with nothing installed → run this one `.exe` → within 10 minutes, you have a fully configured database with 23 schemas, 100,000+ seed records, 4 app users, proper permissions, and all runtime dependencies installed. Zero manual steps.

### Sample Log Output:

```
╔═══════════════════════════════════════════════════════════════╗
║       SafeOps Requirements Setup Installer v1.0              ║
╚═══════════════════════════════════════════════════════════════╝

[STEP  1/11] Installing PostgreSQL...
  Downloading from: https://get.enterprisedb.com/postgresql/postgresql-16.1-1-windows-x64.exe
  File size: 314.72 MB
  Running silent installation (this may take several minutes)...
[SUCCESS] PostgreSQL installed

[STEP  2/11] Starting PostgreSQL service...
[SUCCESS] PostgreSQL service started

[STEP  3/11] Creating databases...
  Creating database: threat_intel_db (Threat Intelligence)
  Creating database: safeops_network (SafeOps Network)
  Creating database: safeops (Core Application)
[SUCCESS] Databases created

[STEP  4/11] Creating database users...
  Creating user: safeops (Primary app user)
  Creating user: threat_intel_app (Threat Intel pipeline)
  Creating user: dhcp_server (DHCP Monitor)
  Creating user: dns_server (DNS services)
[SUCCESS] Database users created

[STEP  5/11] Applying database schemas...
  Applying Threat Intel schemas...
    - 001_initial_setup.sql: Base tables
    - 002_ip_reputation.sql: IP scoring
    - 003_domain_reputation.sql: Domain scoring
    ... (13 schemas total)
  Applying SafeOps Network schemas...
    - 013_dhcp_server.sql: DHCP tracking
    - 020_nic_management.sql: NIC config
    - 022_step_ca.sql: CA secrets
  Applying DHCP migrations...
    - 002_add_portal_tracking.sql
    - 003_add_ca_cert_tracking.sql
    - 004_add_device_fingerprint.sql
    - 005_fix_missing_columns.sql
[SUCCESS] All schemas applied

[STEP  6/11] Applying schema patches...
[SUCCESS] Schema patches applied

[STEP  7/11] Loading seed data...
[SUCCESS] Seed data loaded

[STEP  9/11] Granting table-level permissions...
[SUCCESS] Table-level permissions granted

[STEP 10/11] Installing Node.js...
[SUCCESS] Node.js installed

[STEP 11/11] Installing WinPkFilter driver...
[SUCCESS] WinPkFilter installed

╔═══════════════════════════════════════════════════════════════╗
║         Installation Complete Successfully!                   ║
╚═══════════════════════════════════════════════════════════════╝

PostgreSQL: localhost:5432 | Databases: 3 | Users: 4
Node.js:   v20.11.0
WinPkFilter: v3.4.8

⚠ CHANGE DEFAULT PASSWORDS BEFORE PRODUCTION USE ⚠
```

### Screenshots:

> **Screenshot 11.1 — Full Installation Progress**
>
> _[Insert screenshot of the 11-step installation running in console]_

---

> **Screenshot 11.2 — Completion Summary**
>
> _[Insert screenshot of the final success banner with all components listed]_

---

> **Screenshot 11.3 — PostgreSQL Databases in pgAdmin**
>
> _[Insert screenshot of pgAdmin showing 3 databases with their tables and schemas]_

---

> **Screenshot 11.4 — Idempotent Re-run (--db-init)**
>
> _[Insert screenshot of --db-init completing without errors on a second run]_

---

---

## Tool 12: Desktop App — `safeops-app/app.go` (The Command Center)

**What it does:** The "Mission Control Dashboard" — a native Windows desktop application built with Wails v2 (Go backend + Svelte frontend) that provides a single GUI to manage all 9 SafeOps services, monitor system resources, manage SIEM (Elasticsearch + Kibana), perform first-run setup, and auto-update from GitHub.

### Active Working:

- **app.go — The Backend Brain (1,259 lines):**
  - Manages 9 services across 4 groups: Core (Engine, Firewall), Network (NIC, DHCP, Captive Portal), Certificates (Step-CA), Data (Logger, SIEM Forwarder, Threat Intel)
  - Each service has states: `stopped` → `starting` → `running` → `error`
  - Launches services as hidden Windows processes (`CREATE_NO_WINDOW` flag) — no CMD popups
  - Tracks each child by PID, checks for startup crashes within 2 seconds

- **Startup Sequence (The Boot Order):**
  1. Kill any stale processes from previous unclean shutdown (`taskkill /F`)
  2. Detect install paths (`install-paths.json` → `SAFEOPS_HOME` → relative to exe)
  3. Write diagnostic startup log to Desktop (for VM debugging)
  4. Start Web UI backend (Node.js `:5050`) + frontend (React `:3001`)
  5. Start SafeOps Engine → wait up to 15s for `:50051` gRPC port to be ready
  6. Start Firewall Engine (depends on Engine being ready)
  7. Initialize system tray icon
  8. Check for updates via GitHub API (8-second delay, non-blocking)

- **systray.go — The Tray Sentinel:**
  - Adds a SafeOps icon to the Windows system tray
  - **Close (X) button → hides to tray** (does NOT exit!) — services keep running
  - Left-click tray icon → shows window
  - Right-click → menu: Show / Hide / Quit SafeOps
  - "Quit SafeOps" → stops ALL services → exits fully

- **updater.go — The Auto-Updater:**
  - Queries GitHub Releases API: `GET /repos/safeopsfw/SafeOps/releases/latest`
  - Compares semver (e.g., `1.0.0` vs `1.1.0`)
  - Downloads new installer with progress events (128KB chunks, updates every 250ms)
  - Apply: Stop all services → launch downloaded installer → quit app (500ms delay)

- **First-Run Setup Wizard (8 Steps):**
  1. Install PostgreSQL 16 & Node.js 20
  2. Configure databases & schemas
  3. Run SQL schema files
  4. Create default admin user (`admin` / `safeops123`)
  5. Download & extract Elasticsearch
  6. Download & extract Kibana
  7. Install UI & backend npm dependencies
  8. Write install-paths.json & finalize

- **Crucially:** The Desktop App wraps the ENTIRE SafeOps platform into a **single window**. An operator can start the firewall, view service health, open the web dashboard, launch Elasticsearch, check for updates, and manage network devices — all without ever touching a command line. Closing the window keeps everything running in the background via the system tray.

### Sample Log Output (Desktop Startup Diagnostic):

```
═══════════════════════════════════════════════════════════════
  SafeOps Startup Diagnostic Log
  Date    : 2026-03-25 14:30:01
  Machine : SAFEOPS-SERVER
  OS/Arch : windows/amd64
  Go      : go1.25.7
═══════════════════════════════════════════════════════════════

INSTALLATION:
  Installed : true
  BinDir    : D:\SafeOps\bin
  RootDir   : D:\SafeOps
  DataDir   : C:\ProgramData\SafeOps

EXECUTABLE STATUS:
  [OK]   SafeOps Launcher        D:\SafeOps\bin\SafeOps.exe
  [OK]   SafeOps Engine          D:\SafeOps\bin\safeops-engine\safeops-engine.exe
  [OK]   Firewall Engine         D:\SafeOps\bin\firewall-engine\firewall-engine.exe
  [OK]   NIC Management          D:\SafeOps\bin\nic_management\nic_management.exe
  [OK]   DHCP Monitor            D:\SafeOps\bin\dhcp_monitor\dhcp_monitor.exe
  [OK]   Step-CA                 D:\SafeOps\bin\step-ca\bin\step-ca.exe
  [OK]   SIEM Forwarder          D:\SafeOps\bin\siem-forwarder\siem-forwarder.exe
  [OK]   Network Logger          D:\SafeOps\bin\network-logger\network-logger.exe
  [OK]   Threat Intel            D:\SafeOps\bin\threat_intel\threat_intel.exe
  [OK]   Captive Portal          D:\SafeOps\bin\captive_portal\captive_portal.exe

PORTS (at startup):
  [UP]   :50051  SafeOps Engine gRPC
  [UP]   :50052  Firewall Engine HTTP
  [UP]   :3001   Web UI (React)
  [UP]   :5050   Node Backend
  [UP]   :5432   PostgreSQL
  [UP]   :9200   Elasticsearch
  [UP]   :5601   Kibana
  [UP]   :9000   Step-CA
  [DOWN] :8090   Captive Portal

SYSTEM:
  RAM Total : 16384 MB
  RAM Used  : 8742 MB (53.4%)
  CPU Cores : 8
═══════════════════════════════════════════════════════════════
```

### Screenshots:

> **Screenshot 12.1 — First-Run Setup Wizard**
>
> _[Insert screenshot of the 8-step setup wizard during first launch]_

---

> **Screenshot 12.2 — Main Dashboard (All 9 Services)**
>
> _[Insert screenshot of the main dashboard showing all service cards with Running/Stopped status]_

---

> **Screenshot 12.3 — Service Running (Green)**
>
> _[Insert screenshot of a service card showing Running status with PID and port info]_

---

> **Screenshot 12.4 — System Tray Icon & Menu**
>
> _[Insert screenshot of the Windows system tray showing SafeOps icon and right-click menu]_

---

> **Screenshot 12.5 — CPU/RAM Stats Panel**
>
> _[Insert screenshot of the live system stats panel with CPU and memory usage]_

---

> **Screenshot 12.6 — SIEM Panel (Elasticsearch + Kibana)**
>
> _[Insert screenshot of the SIEM management section with ES/Kibana start/stop controls]_

---

> **Screenshot 12.7 — Update Available Notification**
>
> _[Insert screenshot of the auto-update notification with version number and download button]_

---

> **Screenshot 12.8 — Startup Diagnostic Log**
>
> _[Insert screenshot of the SafeOps-Startup-*.log file on the Desktop showing full diagnostics]_

---

---

## Summary

| Tool | Component | Metaphor | Key Proof |
|:----:|-----------|----------|-----------|
| 1 | SafeOps Launcher | The Orchestrator | 11-service ordered startup & graceful shutdown |
| 2 | SafeOps Engine | The Packet Interceptor | NDIS kernel capture, DNS/TLS domain extraction |
| 3 | Firewall Engine | The 8-Stage Pipeline | Per-stage blocking, hot-reload, embedded UI |
| 4 | Threat Intelligence | The Intelligence Brain | 7+ OSINT feeds, 136K+ indicators, reputation scoring |
| 5 | Network Logger | The Forensics Recorder | 5 parallel collectors, enriched JSON, rotation |
| 6 | NIC Management | The Network Controller | Multi-WAN failover, NAT/ICS, bandwidth monitoring |
| 7 | DHCP Monitor | The Device Radar | ARP scanning, trust mgmt, mDNS, vendor lookup |
| 8 | Captive Portal | The Gatekeeper | Zero-trust onboarding, OS-specific cert delivery |
| 9 | SIEM Forwarder | The Log Courier | ES Bulk API, position tracking, retention |
| 10 | Step-CA | The Trust Anchor | PKI cert chain, PostgreSQL password, 3 cert formats |
| 11 | Requirements Setup | The One-Click Installer | 23 embedded schemas, silent install, idempotent |
| 12 | Desktop App | The Command Center | Wails GUI, 9 services, tray, SIEM, auto-update |

---

> **Note:** Replace all `_[Insert screenshot ...]_` placeholders with actual screenshots captured during POC execution.  
> **Naming convention:** `docs/screenshots/poc-{N}-{description}.png`
