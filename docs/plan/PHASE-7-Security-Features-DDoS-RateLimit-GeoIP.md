# PHASE 7: SECURITY FEATURES (DDoS, Rate Limiting, GeoIP)

**Status:** 🔜 Future Phase (After Phase 6 Complete)
**Duration:** 3 weeks
**Goal:** Advanced threat protection - DDoS mitigation, rate limiting, GeoIP blocking, anomaly detection
**Deliverable:** Production-ready security features protecting against modern attacks

---

## 📋 Phase Overview

**What Changes in Phase 7:**
- **Phase 6 Reality:** Firewall enforces static rules (allow/deny based on IP/port/domain)
- **Phase 7 Goal:** Dynamic threat protection - detect and block attacks automatically
- **Integration Point:** Security modules run alongside rule engine, add dynamic rules

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working
- ✅ Phase 2: Rule matching engine functional
- ✅ Phase 3: SafeOps verdict enforcement working
- ✅ Phase 4: WFP dual-engine active
- ✅ Phase 5: Logging, metrics, health monitoring
- ✅ Phase 6: Hot-reload for dynamic rule updates

---

## 🎯 Phase 7 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup:**
```
[INFO] Firewall Engine v7.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Security Features: ENABLED
[INFO] ├─ DDoS Protection: ACTIVE (SYN/UDP/ICMP flood detection)
[INFO] ├─ Rate Limiter: ACTIVE (100 conn/min per IP)
[INFO] ├─ Brute Force Detection: ACTIVE (5 failures = 1 hour ban)
[INFO] ├─ GeoIP Blocking: ACTIVE (loaded 250,000 IP ranges)
[INFO] └─ Anomaly Detection: ACTIVE (protocol violations, port scans)
[INFO] Firewall ready - processing traffic with advanced threat protection
```

**SYN Flood Attack Detection:**
```
# Attacker sends SYN flood from 203.0.113.50
# 10,000 SYN packets in 1 second

[WARN] DDoS: SYN flood detected from 203.0.113.50
[WARN] ├─ SYN rate: 10,000 packets/sec (threshold: 1,000)
[WARN] ├─ Baseline: 50 packets/sec (normal traffic)
[WARN] ├─ Anomaly score: 200× baseline
[WARN] └─ Action: Temporary ban (30 minutes)

[INFO] Security: Auto-generated rule:
[INFO] ├─ Rule: Block_DDoS_203.0.113.50
[INFO] ├─ Action: DROP
[INFO] ├─ Src IP: 203.0.113.50
[INFO] ├─ Duration: 30 minutes (auto-expire)
[INFO] └─ Reason: SYN flood (10,000 pps)

[INFO] [DROP] TCP 203.0.113.50:* -> *:* SYN [Rule: Block_DDoS_203.0.113.50]
[INFO] Dropped 10,000 SYN packets from 203.0.113.50 (DDoS mitigated)

# After 30 minutes:
[INFO] Security: Auto-ban expired for 203.0.113.50 (ban lifted)
[INFO] ├─ Total packets blocked: 180,000
[INFO] └─ Ban duration: 30 minutes
```

**UDP Flood Attack Mitigation:**
```
# Attacker sends UDP flood from 198.51.100.25
# 50,000 UDP packets/sec to port 53 (DNS amplification attack)

[WARN] DDoS: UDP flood detected from 198.51.100.25
[WARN] ├─ UDP rate: 50,000 packets/sec (threshold: 5,000)
[WARN] ├─ Target port: 53 (DNS)
[WARN] ├─ Packet size: 64 bytes (amplification attack signature)
[WARN] └─ Action: Temporary ban (1 hour, escalated)

[INFO] Security: Auto-generated rule:
[INFO] ├─ Rule: Block_DDoS_198.51.100.25
[INFO] ├─ Action: DROP
[INFO] ├─ Src IP: 198.51.100.25
[INFO] ├─ Duration: 1 hour (escalated from 30 min - repeat offender)
[INFO] └─ Reason: UDP flood (50,000 pps)

[INFO] [DROP] UDP 198.51.100.25:* -> *:53 [Rule: Block_DDoS_198.51.100.25]
```

**Rate Limiting (Connection Limit):**
```
# Normal user: 192.168.1.100
# Legitimate browsing: 50 connections/min (allowed)

[DEBUG] Rate Limiter: 192.168.1.100 → 50 connections in last 60s (under limit)

# Aggressive user: 192.168.1.200
# Downloads with 500 parallel connections (excessive)

[WARN] Rate Limiter: Connection limit exceeded for 192.168.1.200
[WARN] ├─ Connections: 500 in last 60s (limit: 100)
[WARN] ├─ Tokens consumed: 500 (bucket capacity: 100)
[WARN] ├─ Burst allowed: 20 connections (consumed)
[WARN] └─ Action: Throttle (drop new connections for 60 seconds)

[INFO] [DENY] TCP 192.168.1.200:54321 -> 8.8.8.8:443 [Rule: RateLimit_Exceeded] [Reason: Connection limit]
[INFO] [DENY] TCP 192.168.1.200:54322 -> 8.8.8.8:443 [Rule: RateLimit_Exceeded]
[INFO] Rate Limiter: Dropped 400 connections from 192.168.1.200 (throttled)

# After 60 seconds:
[INFO] Rate Limiter: Throttle lifted for 192.168.1.200 (tokens refilled)
```

**Brute Force Detection (SSH Attack):**
```
# Attacker: 45.33.32.156
# SSH brute force: 20 failed login attempts in 2 minutes

[WARN] Brute Force: Repeated failed connections from 45.33.32.156
[WARN] ├─ Failed attempts: 20 (threshold: 5)
[WARN] ├─ Target port: 22 (SSH)
[WARN] ├─ Time window: 2 minutes
[WARN] ├─ Pattern: Password brute force (connection closed after handshake)
[WARN] └─ Action: Auto-ban (1 hour)

[INFO] Security: Auto-generated rule:
[INFO] ├─ Rule: Block_BruteForce_45.33.32.156
[INFO] ├─ Action: DROP
[INFO] ├─ Src IP: 45.33.32.156
[INFO] ├─ Dst Port: 22
[INFO] ├─ Duration: 1 hour (exponential backoff)
[INFO] └─ Reason: SSH brute force (20 failures)

# Repeat offender (next day):
[WARN] Brute Force: Repeat offender detected: 45.33.32.156
[WARN] ├─ Previous bans: 1 (1 hour)
[WARN] ├─ Exponential backoff: 1h → 4h
[WARN] └─ Action: Auto-ban (4 hours)

# Third offense:
[WARN] Brute Force: Persistent attacker: 45.33.32.156
[WARN] ├─ Previous bans: 2 (1h, 4h)
[WARN] ├─ Exponential backoff: 4h → 16h
[WARN] └─ Action: Auto-ban (16 hours)

# Fourth offense:
[WARN] Brute Force: Known threat actor: 45.33.32.156
[WARN] ├─ Previous bans: 3 (1h, 4h, 16h)
[WARN] ├─ Escalation: Permanent ban (manual review required)
[WARN] └─ Action: Permanent ban until admin unblocks
```

**GeoIP Blocking (Country-Based):**
```
# Configuration: Block Russia, China, North Korea
[INFO] GeoIP: Loaded 250,000 IP ranges (MaxMind GeoLite2)
[INFO] GeoIP: Blocked countries: RU (Russia), CN (China), KP (North Korea)

# Incoming connection from Russia:
[INFO] GeoIP: Connection from 185.220.101.50 (Russia, Moscow)
[INFO] [DENY] TCP 185.220.101.50:54321 -> *:443 [Rule: Block_Country_RU] [Reason: Blocked country]

# Incoming connection from China:
[INFO] GeoIP: Connection from 223.5.5.5 (China, Hangzhou)
[INFO] [DENY] TCP 223.5.5.5:12345 -> *:22 [Rule: Block_Country_CN] [Reason: Blocked country]

# Incoming connection from USA (allowed):
[DEBUG] GeoIP: Connection from 8.8.8.8 (USA, Mountain View)
[DEBUG] GeoIP: Country allowed, proceeding with rule matching

# Statistics:
[INFO] GeoIP: Blocked 5,000 connections in last hour
[INFO] ├─ Russia (RU): 3,000 blocks
[INFO] ├─ China (CN): 1,800 blocks
[INFO] ├─ North Korea (KP): 200 blocks
[INFO] └─ Top blocked IPs:
[INFO]    1. 185.220.101.50 (RU): 500 attempts
[INFO]    2. 223.5.5.5 (CN): 300 attempts
[INFO]    3. 175.45.176.0 (KP): 200 attempts
```

**GeoIP ASN Blocking (Cloud Provider):**
```
# Configuration: Block hostile cloud providers
# Blocked ASNs: AS396982 (Google Cloud abuse), AS16509 (AWS abuse)

[WARN] GeoIP: Connection from known abuse ASN
[WARN] ├─ IP: 35.186.224.25
[WARN] ├─ ASN: AS396982 (Google Cloud)
[WARN] ├─ Reason: ASN flagged for abuse (botnet C2 servers)
[WARN] └─ Action: Block

[INFO] [DENY] TCP 35.186.224.25:* -> *:* [Rule: Block_ASN_AS396982] [Reason: Hostile ASN]
```

**Port Scan Detection:**
```
# Attacker: 104.28.5.10
# Port scan: Probing 1000 ports in 10 seconds

[WARN] Anomaly: Port scan detected from 104.28.5.10
[WARN] ├─ Ports probed: 1000 (1-1000)
[WARN] ├─ Time window: 10 seconds (100 ports/sec)
[WARN] ├─ TCP flags: SYN (connection attempts)
[WARN] ├─ Pattern: Sequential port scan (nmap signature)
[WARN] └─ Action: Temporary ban (2 hours)

[INFO] Security: Auto-generated rule:
[INFO] ├─ Rule: Block_PortScan_104.28.5.10
[INFO] ├─ Action: DROP
[INFO] ├─ Src IP: 104.28.5.10
[INFO] ├─ Duration: 2 hours
[INFO] └─ Reason: Port scan (1000 ports in 10s)
```

**Protocol Violation Detection:**
```
# Attacker: 192.0.2.100
# Malformed packets: Invalid TCP flags (SYN+FIN simultaneously)

[WARN] Anomaly: Protocol violation from 192.0.2.100
[WARN] ├─ Violation: Invalid TCP flags (SYN+FIN+URG)
[WARN] ├─ Reason: Crafted packet (evasion technique)
[WARN] ├─ Known attack: Xmas scan (nmap -sX)
[WARN] └─ Action: Drop packet + temporary ban (30 minutes)

[INFO] [DROP] TCP 192.0.2.100:* -> *:* [Rule: Block_ProtocolViolation] [Flags: SYN+FIN+URG]
```

**Packet Size Anomaly:**
```
# Attacker: 198.18.0.50
# Sending 0-byte TCP packets (keepalive flood)

[WARN] Anomaly: Abnormal packet size from 198.18.0.50
[WARN] ├─ Packet size: 0 bytes (payload)
[WARN] ├─ Frequency: 10,000 packets/sec
[WARN] ├─ Pattern: Keepalive flood (resource exhaustion)
[WARN] └─ Action: Temporary ban (1 hour)
```

**Statistics Dashboard (Prometheus Metrics):**
```
# http://localhost:9090/metrics

# DDoS metrics
firewall_ddos_attacks_total{type="syn_flood"} 5
firewall_ddos_attacks_total{type="udp_flood"} 3
firewall_ddos_attacks_mitigated_total 8
firewall_ddos_packets_dropped_total 500000

# Rate limiting metrics
firewall_ratelimit_throttled_ips_total 150
firewall_ratelimit_connections_dropped_total 45000
firewall_ratelimit_tokens_consumed{ip="192.168.1.200"} 500

# Brute force metrics
firewall_bruteforce_attacks_total 25
firewall_bruteforce_banned_ips_current 15
firewall_bruteforce_failed_attempts_total 1250

# GeoIP metrics
firewall_geoip_blocks_total{country="RU"} 3000
firewall_geoip_blocks_total{country="CN"} 1800
firewall_geoip_blocks_total{country="KP"} 200
firewall_geoip_cache_hit_rate 0.98

# Anomaly detection metrics
firewall_anomaly_detections_total{type="port_scan"} 10
firewall_anomaly_detections_total{type="protocol_violation"} 5
firewall_anomaly_detections_total{type="packet_size"} 3
```

---

## 🏗️ Phase 7 Architecture

### Security Module Integration:

```
Packet Processing Flow (with Security Modules):
┌──────────────────────────────────────────────────────────┐
│                  Packet Arrives                           │
└────────────────────┬─────────────────────────────────────┘
                     ↓
    ┌────────────────────────────────────────────┐
    │  1. GeoIP Lookup (First Line Defense)     │
    │     - Lookup IP → Country/ASN              │
    │     - If blocked country: DROP (fast exit)│
    └────────────────────┬───────────────────────┘
                         ↓ (if allowed)
    ┌────────────────────────────────────────────┐
    │  2. DDoS Protection (Traffic Analysis)     │
    │     - Check SYN/UDP/ICMP flood             │
    │     - If flood detected: DROP + auto-ban   │
    └────────────────────┬───────────────────────┘
                         ↓ (if not flood)
    ┌────────────────────────────────────────────┐
    │  3. Rate Limiter (Connection Limits)       │
    │     - Check connection rate per IP         │
    │     - If over limit: DROP (throttle)       │
    └────────────────────┬───────────────────────┘
                         ↓ (if under limit)
    ┌────────────────────────────────────────────┐
    │  4. Anomaly Detection (Protocol Analysis)  │
    │     - Check packet size, TCP flags, etc.   │
    │     - If anomaly: DROP + log               │
    └────────────────────┬───────────────────────┘
                         ↓ (if normal)
    ┌────────────────────────────────────────────┐
    │  5. Brute Force Detection (After Verdict) │
    │     - Track connection outcomes            │
    │     - If repeated failures: Auto-ban       │
    └────────────────────┬───────────────────────┘
                         ↓
    ┌────────────────────────────────────────────┐
    │  6. Rule Matching Engine (Phase 2)         │
    │     - Match firewall rules                 │
    │     - Return verdict (ALLOW/DENY)          │
    └────────────────────┬───────────────────────┘
                         ↓
    ┌────────────────────────────────────────────┐
    │  7. Verdict Enforcement (Phase 3)          │
    │     - Enforce verdict (SafeOps + WFP)      │
    └────────────────────────────────────────────┘
```

### Security Module Architecture:

```
┌─────────────────────────────────────────────────────────────┐
│              Firewall Engine (Core)                         │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Security Manager (Coordinator)                │ │
│  │                                                          │ │
│  │  Registers security modules                             │ │
│  │  Runs modules in correct order                          │ │
│  │  Aggregates results (allow/block)                       │ │
│  └────────────────────┬───────────────────────────────────┘ │
│                       ↓                                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Security Modules (Plugins)                    │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │  DDoS        │  │ Rate Limiter │  │ Brute Force  │ │ │
│  │  │  Protection  │  │              │  │  Detector    │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐                    │ │
│  │  │  GeoIP       │  │  Anomaly     │                    │ │
│  │  │  Blocker     │  │  Detector    │                    │ │
│  │  └──────────────┘  └──────────────┘                    │ │
│  └──────────────────────────────────────────────────────┘ │
│                       ↓                                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Shared Data Structures                          │ │
│  │                                                          │ │
│  │  ┌────────────────┐  ┌────────────────┐               │ │
│  │  │ IP Tracker     │  │ Ban Manager    │               │ │
│  │  │ (connections)  │  │ (auto-bans)    │               │ │
│  │  └────────────────┘  └────────────────┘               │ │
│  │                                                          │ │
│  │  ┌────────────────┐  ┌────────────────┐               │ │
│  │  │ GeoIP Cache    │  │ Metrics        │               │ │
│  │  │ (1M entries)   │  │ Collector      │               │ │
│  │  └────────────────┘  └────────────────┘               │ │
│  └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Phase 7 Components (5 Sub-Tasks)

### Sub-Task 7.1: DDoS Protection (`internal/security/ddos_protection.go`)

**Purpose:** Detect and mitigate Distributed Denial of Service attacks

**Core Concept:**
DDoS attacks flood the network with malicious traffic to exhaust resources. Protection involves detecting abnormal traffic patterns and automatically blocking attackers.

---

#### What to Create:

**1. SYN Flood Detection**

**Purpose:** Detect TCP SYN floods (half-open connection attacks)

**What is SYN Flood:**
```
Normal TCP handshake:
Client → Server: SYN (I want to connect)
Server → Client: SYN-ACK (OK, let's connect)
Client → Server: ACK (Connection established)

SYN flood attack:
Attacker → Server: SYN (from spoofed IP 1.1.1.1)
Server → 1.1.1.1: SYN-ACK (sent to spoofed IP, no response)
Server: Wait for ACK... (connection half-open, consuming memory)

Attacker → Server: SYN (from spoofed IP 1.1.1.2)
Server → 1.1.1.2: SYN-ACK (no response)
Server: Wait for ACK... (another half-open connection)

... repeat 10,000 times per second ...

Result:
├─ Server has 10,000 half-open connections (memory exhausted)
├─ Legitimate clients cannot connect (connection table full)
└─ Service unavailable (DoS achieved)
```

**Detection Algorithm:**
```
Track SYN packets per source IP:

Data structure (per IP):
{
  "ip": "203.0.113.50",
  "syn_count": 10000,          // SYN packets sent
  "synack_count": 10000,       // SYN-ACK replies sent
  "ack_count": 5,              // ACK received (established connections)
  "time_window": 60,           // Last 60 seconds
  "syn_rate": 10000 / 60 = 166 pps
}

Baseline (normal traffic):
├─ Legitimate user: 50 SYN/sec (browsing, email)
├─ Baseline established: 50 SYN/sec ± 20%
└─ Threshold: 1000 SYN/sec (20× baseline = anomaly)

Detection logic:
1. Count SYN packets per IP (sliding window: 60 seconds)
2. Calculate SYN rate: syn_count / time_window
3. If syn_rate > threshold:
   ├─ Anomaly detected
   ├─ Check established connections: ack_count / syn_count
   ├─ If ack_rate < 0.01 (< 1% connections established):
   │  └─ SYN flood confirmed (many SYN, few ACK)
   └─ If ack_rate > 0.5 (> 50% established):
      └─ False positive (legitimate high traffic)

Action on detection:
├─ Log warning: "SYN flood from 203.0.113.50 (10,000 pps)"
├─ Increment metric: firewall_ddos_attacks_total{type="syn_flood"}
├─ Auto-ban IP: 30 minutes (temporary)
└─ Drop all future packets from IP during ban
```

**Implementation:**
```
SYN tracker state:
type SYNTracker struct {
  ips map[string]*SYNStats  // Per-IP statistics
  mu  sync.RWMutex          // Protect map
  baseline int              // Normal SYN rate (learned)
  threshold int             // Detection threshold (baseline × 20)
}

type SYNStats struct {
  synCount    uint64        // SYN packets received
  synackCount uint64        // SYN-ACK packets sent
  ackCount    uint64        // ACK packets received
  windowStart time.Time     // Sliding window start
  banned      bool          // Is IP currently banned
  banExpiry   time.Time     // When ban expires
}

Tracking logic:
func (t *SYNTracker) TrackPacket(pkt *Packet) Decision {
  // Only track SYN packets
  if !pkt.IsSYN() {
    return ALLOW
  }

  t.mu.Lock()
  defer t.mu.Unlock()

  // Get or create stats for this IP
  stats, exists := t.ips[pkt.SrcIP]
  if !exists {
    stats = &SYNStats{windowStart: time.Now()}
    t.ips[pkt.SrcIP] = stats
  }

  // Reset window if expired (60 seconds)
  if time.Since(stats.windowStart) > 60*time.Second {
    stats.synCount = 0
    stats.synackCount = 0
    stats.ackCount = 0
    stats.windowStart = time.Now()
  }

  // Increment SYN counter
  stats.synCount++

  // Check if banned
  if stats.banned && time.Now().Before(stats.banExpiry) {
    return DROP  // Still banned
  } else if stats.banned {
    // Ban expired, unban
    stats.banned = false
    log.Info().Str("ip", pkt.SrcIP).Msg("SYN flood ban expired")
  }

  // Check for SYN flood
  synRate := float64(stats.synCount) / 60.0  // SYN per second
  if synRate > float64(t.threshold) {
    // Calculate ACK rate (established connections)
    ackRate := float64(stats.ackCount) / float64(stats.synCount)

    if ackRate < 0.01 {
      // SYN flood confirmed (< 1% established)
      log.Warn().
        Str("ip", pkt.SrcIP).
        Float64("syn_rate", synRate).
        Float64("ack_rate", ackRate).
        Msg("SYN flood detected")

      // Auto-ban
      stats.banned = true
      stats.banExpiry = time.Now().Add(30 * time.Minute)

      // Create auto-ban rule
      createAutoBanRule(pkt.SrcIP, 30*time.Minute, "SYN flood")

      return DROP
    }
  }

  return ALLOW
}
```

---

**2. UDP Flood Protection**

**Purpose:** Detect UDP floods (connectionless flood attacks)

**What is UDP Flood:**
```
UDP characteristics:
├─ Connectionless (no handshake, no state)
├─ Faster than TCP (no ACK required)
└─ Used for: DNS, NTP, gaming, VoIP

UDP flood attack:
Attacker → Server: 50,000 UDP packets/sec
Server: Process each packet (CPU exhaustion)

UDP amplification attack:
Attacker → DNS Server: DNS query (64 bytes, spoofed src IP = victim)
DNS Server → Victim: DNS response (4096 bytes, 64× amplification)

Result:
├─ Victim receives 50,000 × 64 = 3.2M packets/sec
├─ Bandwidth exhausted (200 Gbps)
└─ Service unavailable
```

**Detection Algorithm:**
```
Track UDP packets per source IP:

Data structure:
{
  "ip": "198.51.100.25",
  "udp_count": 50000,          // UDP packets received
  "udp_bytes": 3200000,        // Total bytes
  "avg_packet_size": 64,       // Average packet size
  "time_window": 60,           // Last 60 seconds
  "udp_rate": 50000 / 60 = 833 pps
}

Baseline:
├─ Legitimate UDP: 100 pps (DNS, NTP)
├─ Threshold: 5,000 pps (50× baseline)
└─ Amplification signature: avg_packet_size < 100 bytes (small queries)

Detection logic:
1. Count UDP packets per IP (sliding window: 60s)
2. Calculate UDP rate: udp_count / time_window
3. If udp_rate > threshold:
   ├─ Check packet size: avg_packet_size < 100 bytes?
   ├─ If yes: Amplification attack (small queries, high rate)
   ├─ If no: Legitimate bulk UDP (video streaming, gaming)
   └─ Action: Auto-ban (1 hour, escalated)

Action on detection:
├─ Log warning: "UDP flood from 198.51.100.25 (50,000 pps)"
├─ Increment metric: firewall_ddos_attacks_total{type="udp_flood"}
├─ Auto-ban IP: 1 hour (longer than SYN flood - harder to spoof)
└─ Drop all UDP packets from IP during ban
```

---

**3. ICMP Flood Mitigation**

**Purpose:** Detect ICMP floods (ping floods, smurf attacks)

**What is ICMP Flood:**
```
ICMP (Internet Control Message Protocol):
├─ Used for: ping, traceroute, error messages
├─ ICMP Echo Request (ping): "Are you alive?"
├─ ICMP Echo Reply (pong): "Yes, I'm alive"
└─ Legitimate use: 1-10 pings per minute

ICMP flood attack:
Attacker → Server: 100,000 ICMP Echo Requests/sec
Server: Reply to each (CPU + bandwidth exhaustion)

Smurf attack (amplification):
Attacker → Broadcast IP (spoofed src = victim): ICMP Echo Request
All hosts on network → Victim: ICMP Echo Reply (100× amplification)

Result:
├─ Victim overwhelmed with ICMP replies
├─ Bandwidth + CPU exhausted
└─ Service unavailable
```

**Detection Algorithm:**
```
Track ICMP packets per source IP:

Baseline:
├─ Legitimate ICMP: 10 pings/min = 0.16 pps
├─ Threshold: 100 pps (600× baseline)
└─ Smurf signature: Many replies with no requests (victim of smurf)

Detection logic:
1. Count ICMP packets per IP (sliding window: 60s)
2. Separate counts: echo_requests, echo_replies
3. If icmp_rate > threshold:
   ├─ If echo_requests >> echo_replies: Attack source
   ├─ If echo_replies >> echo_requests: Attack victim (smurf)
   └─ Action: Auto-ban attacker, rate-limit victim (protection)

Action:
├─ Attacker: Ban IP (30 minutes)
├─ Victim: Rate limit ICMP replies (1 reply/sec, don't amplify)
└─ Log: "ICMP flood from X" or "Smurf attack victim: Y"
```

---

**4. Automatic Temporary Bans**

**Purpose:** Automatically block IPs exhibiting malicious behavior

**Ban Lifecycle:**
```
Detection → Ban Creation → Ban Active → Ban Expiry → Unban

Ban data structure:
{
  "ip": "203.0.113.50",
  "reason": "SYN flood",
  "created_at": "2026-01-22T10:00:00Z",
  "duration": 1800,              // 30 minutes (seconds)
  "expiry": "2026-01-22T10:30:00Z",
  "packets_blocked": 0,          // Counter (incremented on drops)
  "auto_rule_id": "rule-auto-001"  // Generated rule ID
}

Ban creation process:
1. DDoS module detects attack
2. Call ban manager: CreateBan(ip, reason, duration)
3. Ban manager:
   ├─ Create ban entry in database
   ├─ Generate auto-rule: "Block_DDoS_<IP>"
   ├─ Inject rule into rule engine (hot-reload)
   ├─ WFP filter installed (OS-level enforcement)
   └─ Log: "Auto-ban created for <IP>"

Ban enforcement:
1. Packet arrives from banned IP
2. Rule engine matches auto-rule
3. Verdict: DROP
4. Increment counter: packets_blocked++
5. Log: "[DROP] <IP> (banned: <reason>)"

Ban expiry (background goroutine):
1. Every 10 seconds: Check ban expiry times
2. For each expired ban:
   ├─ Remove ban entry from database
   ├─ Delete auto-rule from rule engine (hot-reload)
   ├─ Delete WFP filter
   ├─ Log: "Ban expired for <IP> (blocked <N> packets)"
   └─ Metric: firewall_ddos_bans_expired_total++
```

**Ban Manager Implementation:**
```
type BanManager struct {
  bans map[string]*Ban  // IP → Ban info
  mu   sync.RWMutex     // Protect map
  ruleEngine *rules.Manager
  logger *logging.Logger
}

type Ban struct {
  IP           string
  Reason       string
  CreatedAt    time.Time
  Duration     time.Duration
  Expiry       time.Time
  PacketsBlocked uint64
  AutoRuleID   string
}

func (bm *BanManager) CreateBan(ip string, reason string, duration time.Duration) error {
  bm.mu.Lock()
  defer bm.mu.Unlock()

  // Check if already banned
  if existing, exists := bm.bans[ip]; exists {
    // Extend ban duration (max of current or new)
    if existing.Expiry.After(time.Now().Add(duration)) {
      // Current ban longer, keep it
      return nil
    } else {
      // New ban longer, extend
      existing.Expiry = time.Now().Add(duration)
      existing.Duration = duration
      return nil
    }
  }

  // Create new ban
  ban := &Ban{
    IP:        ip,
    Reason:    reason,
    CreatedAt: time.Now(),
    Duration:  duration,
    Expiry:    time.Now().Add(duration),
    AutoRuleID: fmt.Sprintf("rule-auto-%s", generateID()),
  }

  bm.bans[ip] = ban

  // Create auto-rule
  rule := &Rule{
    ID:       ban.AutoRuleID,
    Name:     fmt.Sprintf("Block_DDoS_%s", strings.ReplaceAll(ip, ".", "_")),
    Action:   DROP,
    SrcIP:    ip,
    Priority: 1000,  // Highest priority (evaluated first)
    Temporary: true,
    Expiry:   ban.Expiry,
  }

  // Inject rule into engine
  err := bm.ruleEngine.AddRule(rule)
  if err != nil {
    return fmt.Errorf("failed to create auto-rule: %w", err)
  }

  bm.logger.Info().
    Str("ip", ip).
    Str("reason", reason).
    Dur("duration", duration).
    Msg("Auto-ban created")

  return nil
}

Background expiry checker:
func (bm *BanManager) StartExpiryChecker() {
  ticker := time.NewTicker(10 * time.Second)
  go func() {
    for range ticker.C {
      bm.checkExpiredBans()
    }
  }()
}

func (bm *BanManager) checkExpiredBans() {
  bm.mu.Lock()
  defer bm.mu.Unlock()

  now := time.Now()
  for ip, ban := range bm.bans {
    if now.After(ban.Expiry) {
      // Ban expired
      bm.logger.Info().
        Str("ip", ip).
        Uint64("packets_blocked", ban.PacketsBlocked).
        Msg("Ban expired")

      // Remove auto-rule
      bm.ruleEngine.DeleteRule(ban.AutoRuleID)

      // Delete ban entry
      delete(bm.bans, ip)
    }
  }
}
```

---

**5. Exponential Backoff**

**Purpose:** Escalate ban duration for repeat offenders

**Why Exponential Backoff:**
```
Problem: Attacker waits for ban to expire, attacks again
├─ First attack: Banned 30 minutes
├─ Wait 30 minutes: Ban expires
├─ Second attack: Banned 30 minutes again (same duration)
├─ Wait 30 minutes: Ban expires
└─ Repeat indefinitely (attacker not deterred)

Solution: Exponential backoff (escalate ban duration)
├─ First offense: 30 minutes
├─ Second offense: 2 hours (4× longer)
├─ Third offense: 8 hours (4× longer)
├─ Fourth offense: 32 hours (4× longer)
├─ Fifth offense: Permanent ban (manual review)
└─ Result: Repeat attackers get longer bans (deterrent)
```

**Backoff Algorithm:**
```
Ban history (per IP):
{
  "ip": "45.33.32.156",
  "ban_count": 3,                 // Number of previous bans
  "ban_history": [
    {"offense": 1, "duration": 1800, "reason": "SYN flood"},
    {"offense": 2, "duration": 7200, "reason": "UDP flood"},
    {"offense": 3, "duration": 28800, "reason": "SYN flood"}
  ],
  "last_ban": "2026-01-21T15:30:00Z",
  "total_packets_blocked": 5000000
}

Escalation calculation:
base_duration = 30 minutes (1800 seconds)
multiplier = 4 (exponential factor)

offense_1: duration = base_duration × 1 = 30 min
offense_2: duration = base_duration × 4 = 2 hours
offense_3: duration = base_duration × 16 = 8 hours
offense_4: duration = base_duration × 64 = 32 hours
offense_5: duration = PERMANENT (requires admin to unblock)

Formula:
duration = base_duration × (multiplier ^ (offense_count - 1))

Example:
offense_3 = 1800 × (4 ^ (3-1)) = 1800 × 16 = 28,800 seconds = 8 hours
```

**Implementation:**
```
type BanHistory struct {
  IP             string
  BanCount       int
  BanHistory     []BanRecord
  LastBan        time.Time
  TotalPacketsBlocked uint64
}

type BanRecord struct {
  Offense  int
  Duration time.Duration
  Reason   string
  Timestamp time.Time
}

func (bm *BanManager) CalculateBanDuration(ip string, reason string) time.Duration {
  // Get ban history for IP
  history, exists := bm.history[ip]
  if !exists {
    history = &BanHistory{IP: ip}
    bm.history[ip] = history
  }

  // Increment offense count
  history.BanCount++
  offense := history.BanCount

  // Base duration: 30 minutes
  baseDuration := 30 * time.Minute

  // Exponential backoff
  var duration time.Duration
  if offense <= 4 {
    // Calculate: base × (4 ^ (offense - 1))
    multiplier := math.Pow(4, float64(offense-1))
    duration = time.Duration(float64(baseDuration) * multiplier)
  } else {
    // Fifth offense: Permanent ban
    duration = 0  // 0 = permanent (never expires)
    bm.logger.Warn().
      Str("ip", ip).
      Int("offense", offense).
      Msg("Permanent ban (persistent attacker)")
  }

  // Record ban in history
  history.BanHistory = append(history.BanHistory, BanRecord{
    Offense:   offense,
    Duration:  duration,
    Reason:    reason,
    Timestamp: time.Now(),
  })
  history.LastBan = time.Now()

  bm.logger.Info().
    Str("ip", ip).
    Int("offense", offense).
    Dur("duration", duration).
    Str("reason", reason).
    Msg("Ban duration calculated (exponential backoff)")

  return duration
}
```

---

#### Files to Create:
```
internal/security/
├── ddos_protection.go   # DDoS detection coordinator
├── syn_tracker.go       # SYN flood detection
├── udp_tracker.go       # UDP flood detection
├── icmp_tracker.go      # ICMP flood detection
├── ban_manager.go       # Auto-ban management
└── exponential_backoff.go  # Ban duration escalation
```

---

### Sub-Task 7.2: Rate Limiter (`internal/security/rate_limiter.go`)

**Purpose:** Limit connection rate per IP to prevent resource exhaustion

**Core Concept:**
Rate limiting controls how many connections a single IP can make in a time window, preventing aggressive clients from monopolizing resources.

---

#### What to Create:

**1. Token Bucket Algorithm**

**Purpose:** Allow bursts while maintaining average rate limit

**What is Token Bucket:**
```
Metaphor: Bucket of tokens
├─ Bucket capacity: 100 tokens (max burst)
├─ Refill rate: 10 tokens/second (sustainable rate)
├─ Cost: 1 token per connection

How it works:
1. Client makes connection → Consumes 1 token
2. If tokens available: Allow connection, decrement tokens
3. If no tokens: Deny connection (rate limited)
4. Tokens refill continuously: +10 tokens/sec (up to capacity)

Example:
T=0s:  Bucket has 100 tokens (full)
T=1s:  Client makes 20 connections → 80 tokens remain
T=2s:  Client makes 20 connections → 60 tokens remain
T=3s:  Client makes 50 connections → 10 tokens remain
T=4s:  Client tries 50 connections → Only 10 allowed (rate limited)
       40 connections denied (no tokens)
       Bucket refills: +10 tokens
T=5s:  Bucket has 20 tokens (refilled)
       Client can make 20 connections

Benefits:
├─ Allows bursts (100 tokens = burst capacity)
├─ Enforces average rate (10 tokens/sec = 10 conn/sec sustained)
└─ Fair (all clients get same bucket)
```

**Token Bucket vs Leaky Bucket:**
```
Token Bucket:
├─ Allows bursts (empty bucket fast)
├─ Refills tokens (client regains capacity)
└─ Use case: Web browsing (burst of requests when page loads)

Leaky Bucket:
├─ Smooth rate (water drips out at constant rate)
├─ No bursts (overflow discarded)
└─ Use case: Video streaming (constant bitrate)

Firewall use case: Token Bucket (allow bursts for legitimate users)
```

**Implementation:**
```
Token bucket data structure:
type TokenBucket struct {
  capacity     int       // Max tokens (100)
  tokens       float64   // Current tokens (0-100)
  refillRate   float64   // Tokens added per second (10)
  lastRefill   time.Time // Last refill timestamp
  mu           sync.Mutex
}

Token consumption:
func (tb *TokenBucket) TryConsume(cost int) bool {
  tb.mu.Lock()
  defer tb.mu.Unlock()

  // Refill tokens based on time elapsed
  now := time.Now()
  elapsed := now.Sub(tb.lastRefill).Seconds()
  tb.tokens += elapsed * tb.refillRate

  // Cap at capacity
  if tb.tokens > float64(tb.capacity) {
    tb.tokens = float64(tb.capacity)
  }

  tb.lastRefill = now

  // Check if enough tokens
  if tb.tokens >= float64(cost) {
    // Consume tokens
    tb.tokens -= float64(cost)
    return true  // Allowed
  }

  // Not enough tokens
  return false  // Rate limited
}

Per-IP token buckets:
type RateLimiter struct {
  buckets map[string]*TokenBucket  // IP → TokenBucket
  mu      sync.RWMutex
  config  RateLimitConfig
}

type RateLimitConfig struct {
  Capacity   int     // Max burst (100 connections)
  RefillRate float64 // Sustainable rate (10 conn/sec)
  Enabled    bool
}

Rate limiting logic:
func (rl *RateLimiter) CheckConnection(ip string) Decision {
  if !rl.config.Enabled {
    return ALLOW
  }

  rl.mu.Lock()
  bucket, exists := rl.buckets[ip]
  if !exists {
    // Create new bucket for this IP
    bucket = &TokenBucket{
      capacity:   rl.config.Capacity,
      tokens:     float64(rl.config.Capacity),  // Start full
      refillRate: rl.config.RefillRate,
      lastRefill: time.Now(),
    }
    rl.buckets[ip] = bucket
  }
  rl.mu.Unlock()

  // Try to consume token
  allowed := bucket.TryConsume(1)
  if allowed {
    return ALLOW
  }

  // Rate limited
  log.Warn().
    Str("ip", ip).
    Float64("tokens", bucket.tokens).
    Msg("Rate limit exceeded")

  metrics.IncrementCounter("firewall_ratelimit_connections_dropped_total")

  return DROP
}
```

---

**2. Per-IP Connection Limits**

**Purpose:** Track connection counts per IP address

**Connection Tracking:**
```
Data structure (per IP):
{
  "ip": "192.168.1.200",
  "connections_active": 50,     // Currently open connections
  "connections_total": 500,     // Total connections (last 60s)
  "connections_per_min": 500,   // Rate (conns/min)
  "token_bucket": {
    "capacity": 100,
    "tokens": 10,
    "refill_rate": 10
  },
  "first_seen": "2026-01-22T10:00:00Z",
  "last_connection": "2026-01-22T10:05:30Z"
}

Limits:
├─ Active connections: 50 per IP (prevent resource exhaustion)
├─ Connection rate: 100 per minute (prevent flooding)
└─ Burst capacity: 20 connections (allow brief spikes)

Tracking logic:
1. Connection established → Increment connections_active
2. Connection closed → Decrement connections_active
3. Check limits:
   ├─ If connections_active > 50: Reject new connections
   ├─ If connections_per_min > 100: Rate limit (token bucket)
   └─ If burst > 20: Throttle (deny until tokens refill)
```

**Implementation:**
```
Connection tracker:
type ConnectionTracker struct {
  connections map[string]*IPConnections
  mu          sync.RWMutex
}

type IPConnections struct {
  IP              string
  ActiveCount     int       // Currently open
  TotalCount      uint64    // Total since start
  WindowCount     int       // Last 60 seconds
  WindowStart     time.Time
  FirstSeen       time.Time
  LastConnection  time.Time
}

Track connection:
func (ct *ConnectionTracker) ConnectionEstablished(ip string) Decision {
  ct.mu.Lock()
  defer ct.mu.Unlock()

  // Get or create stats
  stats, exists := ct.connections[ip]
  if !exists {
    stats = &IPConnections{
      IP:         ip,
      FirstSeen:  time.Now(),
      WindowStart: time.Now(),
    }
    ct.connections[ip] = stats
  }

  // Reset window if expired (60 seconds)
  if time.Since(stats.WindowStart) > 60*time.Second {
    stats.WindowCount = 0
    stats.WindowStart = time.Now()
  }

  // Check active connection limit
  if stats.ActiveCount >= 50 {
    log.Warn().
      Str("ip", ip).
      Int("active", stats.ActiveCount).
      Msg("Active connection limit exceeded")
    return DROP
  }

  // Check rate limit (token bucket)
  rateLimited := !rateLimiter.CheckConnection(ip)
  if rateLimited {
    return DROP
  }

  // Allow connection
  stats.ActiveCount++
  stats.TotalCount++
  stats.WindowCount++
  stats.LastConnection = time.Now()

  return ALLOW
}

func (ct *ConnectionTracker) ConnectionClosed(ip string) {
  ct.mu.Lock()
  defer ct.mu.Unlock()

  if stats, exists := ct.connections[ip]; exists {
    stats.ActiveCount--
    if stats.ActiveCount < 0 {
      stats.ActiveCount = 0  // Sanity check
    }
  }
}
```

---

**3. Burst Handling**

**Purpose:** Allow legitimate burst traffic while preventing abuse

**Burst Scenarios:**
```
Legitimate burst (allow):
├─ User loads web page → 20 simultaneous requests (CSS, JS, images)
├─ Duration: 1 second
├─ After burst: Connection rate returns to normal (5 conn/min)
└─ Action: Allow (within burst capacity)

Malicious burst (deny):
├─ Attacker floods → 500 simultaneous connections
├─ Duration: Sustained (doesn't stop)
├─ After burst: Continues at high rate (500 conn/min)
└─ Action: Deny (exceeds burst capacity + sustained rate)

Differentiation:
├─ Legitimate: Burst + return to normal
├─ Malicious: Burst + sustained high rate
└─ Detection: Track connection rate over time (spike vs sustained)
```

**Burst Configuration:**
```
Rate limit config:
{
  "sustainable_rate": 10,   // 10 conn/sec average
  "burst_capacity": 20,     // Allow 20 conn burst
  "burst_duration": 5,      // Burst can last 5 seconds
  "recovery_time": 60,      // 60 seconds to refill tokens
}

Token bucket parameters:
├─ Capacity: 100 tokens (burst_capacity × sustainable_rate)
├─ Refill rate: 10 tokens/sec (sustainable_rate)
├─ Burst: 20 connections in 2 seconds (consumes 20 tokens, OK)
├─ Recovery: 20 tokens / 10 tokens/sec = 2 seconds to refill
└─ Sustained: 100 connections in 10 seconds = 10 conn/sec (at limit)

Burst detection:
1. Track connection rate over 5-second windows
2. If rate > sustainable_rate: Burst detected
3. If burst_duration < 5 seconds: Legitimate burst (allow)
4. If burst_duration > 5 seconds: Attack (rate limit)
```

---

**4. Whitelist for Trusted IPs**

**Purpose:** Exempt trusted IPs from rate limiting

**Whitelist Use Cases:**
```
Trusted IPs (no rate limit):
├─ Internal IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
├─ Load balancers: 10.0.1.100, 10.0.1.101
├─ Monitoring systems: 10.0.2.50 (health checks)
├─ Known partners: 203.0.113.0/24 (API integrations)
└─ CDN providers: Cloudflare IPs, Akamai IPs

Why whitelist:
├─ Internal IPs: Trusted (no rate limit needed)
├─ Load balancers: Aggregate traffic (many users behind one IP)
├─ Monitoring: Frequent health checks (would trigger rate limit)
├─ Partners: High-volume API access (pre-arranged)
└─ CDN: Proxies user traffic (many users behind CDN IP)
```

**Whitelist Implementation:**
```
Whitelist config:
{
  "whitelisted_ips": [
    "10.0.0.0/8",           // Internal network
    "192.168.0.0/16",       // Private network
    "203.0.113.100",        // Partner API server
    "198.51.100.0/24"       // Monitoring subnet
  ],
  "whitelisted_reason": {
    "10.0.0.0/8": "Internal network",
    "203.0.113.100": "Partner API (XYZ Corp)"
  }
}

Whitelist check:
type Whitelist struct {
  cidrs []*net.IPNet
  reasons map[string]string
}

func (wl *Whitelist) IsWhitelisted(ip string) (bool, string) {
  parsedIP := net.ParseIP(ip)
  if parsedIP == nil {
    return false, ""
  }

  // Check each CIDR
  for _, cidr := range wl.cidrs {
    if cidr.Contains(parsedIP) {
      reason := wl.reasons[cidr.String()]
      return true, reason
    }
  }

  return false, ""
}

Rate limiter integration:
func (rl *RateLimiter) CheckConnection(ip string) Decision {
  // Check whitelist first
  whitelisted, reason := rl.whitelist.IsWhitelisted(ip)
  if whitelisted {
    log.Debug().
      Str("ip", ip).
      Str("reason", reason).
      Msg("IP whitelisted (no rate limit)")
    return ALLOW
  }

  // Not whitelisted, apply rate limit
  return rl.checkTokenBucket(ip)
}
```

---

**5. Dynamic Rate Limit Adjustment**

**Purpose:** Adjust rate limits based on load and attack patterns

**Adaptive Rate Limiting:**
```
Problem: Fixed rate limits
├─ Normal load: 1,000 requests/sec → Rate limit: 100 req/sec per IP
├─ Under attack: 100,000 requests/sec → Rate limit: 100 req/sec per IP (insufficient)
└─ Result: Attacker can still exhaust resources (1,000 IPs × 100 req/sec = 100K req/sec)

Solution: Dynamic rate limits
├─ Normal load: Rate limit: 100 req/sec per IP
├─ Under attack: Detect anomaly → Reduce rate limit: 10 req/sec per IP
├─ Result: Attacker limited to 10K req/sec (1,000 IPs × 10 req/sec)
└─ After attack: Gradually restore rate limit: 10 → 50 → 100 req/sec

Adjustment algorithm:
1. Track total request rate (system-wide)
2. Calculate baseline: 1,000 req/sec (normal)
3. Detect anomaly: Current rate: 100,000 req/sec (100× baseline)
4. Reduce rate limit: 100 → 10 req/sec per IP (10× reduction)
5. Monitor: Attack mitigated? Rate drops to 10,000 req/sec
6. Gradually restore: Increase rate limit by 10 req/sec every 5 minutes
7. Return to normal: Rate limit: 100 req/sec per IP
```

**Implementation:**
```
Dynamic adjuster:
type DynamicRateLimiter struct {
  baseRate      float64  // Base rate (100 req/sec)
  currentRate   float64  // Current rate (adjusted)
  adjustmentFactor float64  // Adjustment (0.1 - 2.0)
  lastAdjustment time.Time
}

Adjustment logic:
func (drl *DynamicRateLimiter) AdjustRateLimits() {
  // Calculate system-wide request rate
  totalRate := metrics.GetCounter("firewall_packets_total")
  currentRate := float64(totalRate) / 60.0  // Requests per second

  // Calculate baseline (moving average)
  baseline := drl.calculateBaseline()

  // Detect anomaly
  if currentRate > baseline*5.0 {
    // Under attack (5× baseline)
    log.Warn().
      Float64("current_rate", currentRate).
      Float64("baseline", baseline).
      Msg("Attack detected, reducing rate limits")

    // Reduce rate limit (exponential)
    drl.adjustmentFactor *= 0.5  // Halve rate limit
    if drl.adjustmentFactor < 0.1 {
      drl.adjustmentFactor = 0.1  // Minimum 10% of base rate
    }

    drl.currentRate = drl.baseRate * drl.adjustmentFactor
    drl.lastAdjustment = time.Now()

  } else if currentRate < baseline*1.2 && drl.adjustmentFactor < 1.0 {
    // Normal traffic, gradually restore rate limit
    if time.Since(drl.lastAdjustment) > 5*time.Minute {
      log.Info().Msg("Restoring rate limits (attack mitigated)")

      drl.adjustmentFactor += 0.1  // Increase by 10%
      if drl.adjustmentFactor > 1.0 {
        drl.adjustmentFactor = 1.0  // Cap at base rate
      }

      drl.currentRate = drl.baseRate * drl.adjustmentFactor
      drl.lastAdjustment = time.Now()
    }
  }

  // Update rate limiter config
  rateLimiter.UpdateRefillRate(drl.currentRate)
}

Background adjustment:
go func() {
  ticker := time.NewTicker(30 * time.Second)
  for range ticker.C {
    dynamicRateLimiter.AdjustRateLimits()
  }
}()
```

---

#### Files to Create:
```
internal/security/
├── rate_limiter.go      # Rate limiter coordinator
├── token_bucket.go      # Token bucket algorithm
├── connection_tracker.go # Per-IP connection tracking
├── burst_handler.go     # Burst detection and handling
├── whitelist.go         # Trusted IP whitelist
└── dynamic_adjuster.go  # Adaptive rate limit adjustment
```

---

### Sub-Task 7.3: Brute Force Detection (`internal/security/brute_force.go`)

**Purpose:** Detect and block brute force attacks (password guessing, API abuse)

**Core Concept:**
Brute force attacks involve repeated failed login attempts. Detection tracks failure patterns and automatically bans attackers after threshold reached.

---

#### What to Create:

**1. Failed Connection Tracking**

**Purpose:** Count failed connection attempts per IP

**What Constitutes a "Failure":**
```
Protocol-specific failures:

SSH (port 22):
├─ Connection established → Authentication failed → Connection closed
├─ Indicator: Connection duration < 5 seconds (failed auth)
└─ Legitimate: Duration > 30 seconds (successful SSH session)

HTTP/HTTPS (port 80/443):
├─ 401 Unauthorized (wrong credentials)
├─ 403 Forbidden (access denied)
└─ 429 Too Many Requests (rate limited)

SMTP (port 25/587):
├─ 535 Authentication failed
└─ Repeated EHLO/AUTH commands (trying different credentials)

RDP (port 3389):
├─ Connection established → Authentication failure event
└─ Multiple connection attempts with no successful session

FTP (port 21):
├─ 530 Login incorrect
└─ Repeated USER/PASS commands
```

**Tracking Data Structure:**
```
Per-IP failure tracking:
{
  "ip": "45.33.32.156",
  "protocol": "SSH",
  "target_port": 22,
  "failures": [
    {"timestamp": "2026-01-22T10:00:00Z", "reason": "auth_failed"},
    {"timestamp": "2026-01-22T10:00:05Z", "reason": "auth_failed"},
    {"timestamp": "2026-01-22T10:00:10Z", "reason": "auth_failed"},
    ... (20 failures total)
  ],
  "failure_count": 20,
  "window_start": "2026-01-22T09:58:00Z",
  "window_duration": 120,  // 2 minutes
  "banned": true,
  "ban_expiry": "2026-01-22T11:00:00Z"
}

Failure patterns:
├─ Rapid failures: 20 attempts in 2 minutes (brute force)
├─ Slow failures: 5 attempts in 1 hour (stealthy brute force)
├─ Distributed: Multiple IPs targeting same service (distributed brute force)
└─ Credential stuffing: Many usernames, few passwords (list-based attack)
```

**Implementation:**
```
Failure tracker:
type BruteForceDetector struct {
  failures map[string]*FailureStats  // IP → FailureStats
  mu       sync.RWMutex
  config   BruteForceConfig
}

type FailureStats struct {
  IP            string
  Protocol      string
  TargetPort    int
  Failures      []FailureEvent
  FailureCount  int
  WindowStart   time.Time
  Banned        bool
  BanExpiry     time.Time
  BanCount      int  // Number of times banned (for exponential backoff)
}

type FailureEvent struct {
  Timestamp time.Time
  Reason    string  // "auth_failed", "invalid_credentials", etc.
}

type BruteForceConfig struct {
  Enabled       bool
  FailureThreshold int       // 5 failures = ban
  WindowDuration   time.Duration  // 2 minutes
  BanDuration      time.Duration  // 1 hour
}

Track failure:
func (bfd *BruteForceDetector) TrackFailure(ip string, protocol string, port int, reason string) Decision {
  if !bfd.config.Enabled {
    return ALLOW
  }

  bfd.mu.Lock()
  defer bfd.mu.Unlock()

  // Get or create failure stats
  stats, exists := bfd.failures[ip]
  if !exists {
    stats = &FailureStats{
      IP:          ip,
      Protocol:    protocol,
      TargetPort:  port,
      WindowStart: time.Now(),
    }
    bfd.failures[ip] = stats
  }

  // Check if already banned
  if stats.Banned && time.Now().Before(stats.BanExpiry) {
    return DROP  // Still banned
  } else if stats.Banned {
    // Ban expired, unban
    stats.Banned = false
    log.Info().Str("ip", ip).Msg("Brute force ban expired")
  }

  // Reset window if expired
  if time.Since(stats.WindowStart) > bfd.config.WindowDuration {
    stats.Failures = nil
    stats.FailureCount = 0
    stats.WindowStart = time.Now()
  }

  // Record failure
  stats.Failures = append(stats.Failures, FailureEvent{
    Timestamp: time.Now(),
    Reason:    reason,
  })
  stats.FailureCount++

  // Check threshold
  if stats.FailureCount >= bfd.config.FailureThreshold {
    // Brute force detected
    log.Warn().
      Str("ip", ip).
      Str("protocol", protocol).
      Int("port", port).
      Int("failures", stats.FailureCount).
      Msg("Brute force attack detected")

    // Calculate ban duration (exponential backoff)
    stats.BanCount++
    banDuration := calculateExponentialBackoff(
      bfd.config.BanDuration,
      stats.BanCount,
    )

    // Ban IP
    stats.Banned = true
    stats.BanExpiry = time.Now().Add(banDuration)

    // Create auto-ban rule
    banManager.CreateBan(ip, fmt.Sprintf("Brute force (%s)", protocol), banDuration)

    return DROP
  }

  return ALLOW
}
```

---

**2. Ban After N Failures**

**Purpose:** Automatically ban IPs exceeding failure threshold

**Threshold Configuration:**
```
Service-specific thresholds:

SSH (port 22):
├─ Threshold: 5 failures in 2 minutes
├─ Reason: SSH brute force common, strict limit
└─ Ban duration: 1 hour (first offense)

HTTP/HTTPS (port 80/443):
├─ Threshold: 10 failures in 5 minutes
├─ Reason: Web apps may have legitimate login failures
└─ Ban duration: 30 minutes

SMTP (port 25/587):
├─ Threshold: 3 failures in 1 minute
├─ Reason: Email auth should succeed immediately
└─ Ban duration: 2 hours

RDP (port 3389):
├─ Threshold: 3 failures in 1 minute
├─ Reason: RDP brute force critical (admin access)
└─ Ban duration: 4 hours (longer, more critical)

FTP (port 21):
├─ Threshold: 5 failures in 2 minutes
└─ Ban duration: 1 hour

API endpoints:
├─ Threshold: 20 failures in 10 minutes
├─ Reason: API keys may be misconfigured (higher threshold)
└─ Ban duration: 15 minutes (shorter, may be legitimate error)
```

**Configuration Example:**
```
[security.brute_force]
enabled = true

[[security.brute_force.service]]
name = "SSH"
ports = [22]
failure_threshold = 5
window_duration = "2m"
ban_duration = "1h"

[[security.brute_force.service]]
name = "RDP"
ports = [3389]
failure_threshold = 3
window_duration = "1m"
ban_duration = "4h"

[[security.brute_force.service]]
name = "HTTP"
ports = [80, 443]
failure_threshold = 10
window_duration = "5m"
ban_duration = "30m"
```

---

**3. Exponential Backoff**

**Purpose:** Escalate ban duration for persistent attackers

**Backoff Schedule:**
```
SSH brute force example:

First offense:
├─ Failures: 5 in 2 minutes
├─ Ban duration: 1 hour
└─ Action: Auto-ban for 1 hour

Second offense (after first ban expires):
├─ Failures: 5 in 2 minutes (again)
├─ Ban duration: 4 hours (4× longer)
└─ Action: Auto-ban for 4 hours

Third offense:
├─ Failures: 5 in 2 minutes (persistent attacker)
├─ Ban duration: 16 hours (4× longer)
└─ Action: Auto-ban for 16 hours

Fourth offense:
├─ Failures: 5 in 2 minutes (known threat actor)
├─ Ban duration: 64 hours (2.6 days)
└─ Action: Auto-ban for 64 hours

Fifth offense:
├─ Failures: 5 in 2 minutes (extremely persistent)
├─ Ban duration: Permanent (requires manual unblock)
└─ Action: Permanent ban + alert admin
```

**Exponential Backoff Formula:**
```
duration_n = base_duration × (multiplier ^ (n - 1))

Where:
├─ base_duration: Initial ban duration (1 hour)
├─ multiplier: Exponential factor (4)
├─ n: Offense count (1, 2, 3, ...)

Examples:
offense_1: 1h × (4^0) = 1h × 1 = 1 hour
offense_2: 1h × (4^1) = 1h × 4 = 4 hours
offense_3: 1h × (4^2) = 1h × 16 = 16 hours
offense_4: 1h × (4^3) = 1h × 64 = 64 hours
offense_5: Permanent ban (cap reached)
```

**Implementation:**
```
func calculateExponentialBackoff(baseDuration time.Duration, offenseCount int) time.Duration {
  // Cap at 4 offenses (fifth offense = permanent)
  if offenseCount >= 5 {
    return 0  // 0 = permanent ban
  }

  // Calculate: base × (4 ^ (count - 1))
  multiplier := math.Pow(4, float64(offenseCount-1))
  duration := time.Duration(float64(baseDuration) * multiplier)

  // Cap at 7 days (maximum ban duration)
  maxDuration := 7 * 24 * time.Hour
  if duration > maxDuration {
    duration = maxDuration
  }

  return duration
}
```

---

**4. Integration with Threat Intelligence**

**Purpose:** Cross-reference attackers with known threat databases

**Threat Intelligence Sources:**
```
External threat feeds:
├─ AbuseIPDB: Community-reported malicious IPs
├─ Fail2Ban Global DB: Known brute force IPs
├─ GreyNoise: Internet-wide scanner IPs
├─ AlienVault OTX: Open Threat Exchange
├─ MISP: Malware Information Sharing Platform
└─ Custom feeds: Internal threat intel, partner feeds

Data provided:
├─ IP reputation score (0-100, higher = more malicious)
├─ Last seen attack type (SSH brute force, port scan)
├─ Confidence level (0-100, higher = more confident)
├─ Attack categories (brute force, malware, phishing)
└─ First/last seen dates
```

**Integration Logic:**
```
Threat intel query:
1. Brute force attempt detected from IP
2. Query threat intel API: CheckReputation(ip)
3. Response:
   {
     "ip": "45.33.32.156",
     "reputation_score": 95,  // High risk (0-100)
     "attack_types": ["ssh_brute_force", "port_scan"],
     "confidence": 90,
     "last_seen": "2026-01-22T08:00:00Z",  // 2 hours ago
     "reports_count": 150,  // Reported 150 times
     "categories": ["brute_force", "botnet"]
   }

4. Decision based on reputation:
   ├─ Score > 80: High risk → Immediate ban (no threshold)
   ├─ Score 50-80: Medium risk → Lower threshold (3 failures instead of 5)
   ├─ Score < 50: Low risk → Normal threshold (5 failures)
   └─ Score 0: Unknown → Normal threshold

5. If high risk:
   ├─ Log: "Known threat actor detected: 45.33.32.156 (AbuseIPDB score: 95)"
   ├─ Auto-ban immediately (preemptive)
   ├─ Ban duration: 7 days (longer for known threats)
   └─ Alert admin: "Blocked known threat: <IP>"
```

**Implementation:**
```
Threat intel client:
type ThreatIntelClient struct {
  apiKey    string
  cacheTime time.Duration
  cache     map[string]*ThreatInfo  // IP → ThreatInfo (cached)
  mu        sync.RWMutex
}

type ThreatInfo struct {
  IP             string
  ReputationScore int
  AttackTypes    []string
  Confidence     int
  LastSeen       time.Time
  ReportsCount   int
  Categories     []string
  CachedAt       time.Time
}

Query threat intel:
func (tic *ThreatIntelClient) CheckReputation(ip string) (*ThreatInfo, error) {
  // Check cache first
  tic.mu.RLock()
  if cached, exists := tic.cache[ip]; exists {
    if time.Since(cached.CachedAt) < tic.cacheTime {
      tic.mu.RUnlock()
      return cached, nil  // Cache hit
    }
  }
  tic.mu.RUnlock()

  // Cache miss, query API
  resp, err := http.Get(fmt.Sprintf(
    "https://api.abuseipdb.com/api/v2/check?ipAddress=%s",
    ip,
  ))
  if err != nil {
    return nil, fmt.Errorf("threat intel query failed: %w", err)
  }
  defer resp.Body.Close()

  // Parse response
  var result ThreatInfo
  err = json.NewDecoder(resp.Body).Decode(&result)
  if err != nil {
    return nil, err
  }

  // Cache result
  result.CachedAt = time.Now()
  tic.mu.Lock()
  tic.cache[ip] = &result
  tic.mu.Unlock()

  return &result, nil
}

Integration with brute force detector:
func (bfd *BruteForceDetector) TrackFailure(ip string, protocol string, port int) Decision {
  // Query threat intel
  threatInfo, err := threatIntelClient.CheckReputation(ip)
  if err == nil && threatInfo.ReputationScore > 80 {
    // Known threat actor, immediate ban
    log.Warn().
      Str("ip", ip).
      Int("reputation", threatInfo.ReputationScore).
      Strs("attack_types", threatInfo.AttackTypes).
      Msg("Known threat actor detected (preemptive ban)")

    // Ban for 7 days (known threat)
    banManager.CreateBan(ip, "Known threat actor (threat intel)", 7*24*time.Hour)

    return DROP
  }

  // Continue with normal brute force detection
  // ... (existing logic) ...
}
```

---

**5. Distributed Brute Force Detection**

**Purpose:** Detect attacks from multiple IPs targeting same service

**Distributed Attack Pattern:**
```
Traditional brute force:
├─ Single IP: 45.33.32.156
├─ Target: SSH server (port 22)
├─ Attempts: 100 per minute
└─ Detection: Easy (single IP exceeds threshold)

Distributed brute force:
├─ Multiple IPs: 100 different IPs (botnet)
├─ Target: SSH server (port 22)
├─ Attempts per IP: 1 per minute (below threshold!)
├─ Total attempts: 100 per minute (distributed)
└─ Detection: Hard (each IP below threshold individually)

Need: Aggregate detection (detect coordinated attack)
```

**Aggregate Detection:**
```
Track target service (not just source IP):

Data structure:
{
  "service": "SSH",
  "port": 22,
  "failure_rate": 100,  // Failures per minute (all IPs)
  "unique_ips": 100,    // Number of unique attacker IPs
  "baseline": 5,        // Normal failure rate (baseline)
  "anomaly_score": 20,  // Current rate / baseline
  "coordinated_attack": true
}

Detection logic:
1. Track failures per service (aggregate all IPs)
2. Calculate failure rate: 100 failures/min
3. Compare to baseline: 5 failures/min (normal)
4. Anomaly score: 100 / 5 = 20× baseline
5. Check unique IPs: 100 different IPs (distributed)
6. If anomaly_score > 10 AND unique_ips > 10:
   └─ Distributed brute force detected

Action:
├─ Log: "Distributed brute force attack on SSH (100 IPs)"
├─ Reduce threshold: 5 failures → 1 failure (stricter)
├─ Ban all attacking IPs (even with 1 failure)
├─ Enable rate limiting: 1 SSH attempt per IP per minute
└─ Alert admin: "Coordinated attack detected"
```

**Implementation:**
```
type DistributedAttackDetector struct {
  services map[string]*ServiceStats  // Service → Stats
  mu       sync.RWMutex
}

type ServiceStats struct {
  Service      string
  Port         int
  FailureRate  float64  // Failures per minute
  UniqueIPs    int      // Number of attacking IPs
  Baseline     float64  // Normal failure rate
  AnomalyScore float64  // Current / baseline
  AttackActive bool
}

func (dad *DistributedAttackDetector) DetectDistributedAttack(service string, port int) bool {
  dad.mu.Lock()
  defer dad.mu.Unlock()

  key := fmt.Sprintf("%s:%d", service, port)
  stats, exists := dad.services[key]
  if !exists {
    stats = &ServiceStats{
      Service:  service,
      Port:     port,
      Baseline: 5.0,  // Default baseline
    }
    dad.services[key] = stats
  }

  // Calculate failure rate (from failure tracker)
  failures := failureTracker.GetFailureCount(service, port)
  uniqueIPs := failureTracker.GetUniqueIPCount(service, port)

  stats.FailureRate = float64(failures) / 60.0  // Per minute
  stats.UniqueIPs = uniqueIPs
  stats.AnomalyScore = stats.FailureRate / stats.Baseline

  // Detect distributed attack
  if stats.AnomalyScore > 10.0 && stats.UniqueIPs > 10 {
    if !stats.AttackActive {
      log.Warn().
        Str("service", service).
        Int("port", port).
        Float64("failure_rate", stats.FailureRate).
        Int("unique_ips", stats.UniqueIPs).
        Float64("anomaly_score", stats.AnomalyScore).
        Msg("Distributed brute force attack detected")

      stats.AttackActive = true

      // Reduce threshold globally
      bruteForceDetector.ReduceThreshold(service, 1)  // 1 failure = ban

      // Alert admin
      alertManager.SendAlert("Distributed brute force on "+service)
    }
    return true
  } else {
    if stats.AttackActive {
      log.Info().Str("service", service).Msg("Distributed attack mitigated")
      stats.AttackActive = false

      // Restore normal threshold
      bruteForceDetector.RestoreThreshold(service)
    }
    return false
  }
}
```

---

#### Files to Create:
```
internal/security/
├── brute_force.go       # Brute force detection coordinator
├── failure_tracker.go   # Track failed attempts per IP
├── ban_escalation.go    # Exponential backoff logic
├── threat_intel.go      # Threat intelligence integration
└── distributed_detector.go  # Distributed attack detection
```

---

### Sub-Task 7.4: GeoIP Blocking (`internal/security/geo_blocker.go`)

**Purpose:** Block traffic based on geographic location (country, region, ASN)

**Core Concept:**
GeoIP blocking uses IP geolocation databases to determine packet origin and enforce location-based access policies.

---

#### What to Create:

**1. GeoIP Database Integration**

**Purpose:** Load and query GeoIP database for IP-to-location mapping

**GeoIP Database Options:**
```
MaxMind GeoLite2 (free):
├─ Database: GeoLite2-Country.mmdb (country-level)
├─ Size: ~6MB (compressed)
├─ Records: ~250,000 IP ranges
├─ Accuracy: ~99% country-level
├─ Update frequency: Weekly
└─ License: Creative Commons (attribution required)

MaxMind GeoIP2 (paid):
├─ Database: GeoIP2-Country.mmdb, GeoIP2-City.mmdb
├─ Size: ~60MB (city-level)
├─ Records: ~5M IP ranges
├─ Accuracy: ~99.8% (more accurate)
├─ Update frequency: Daily
└─ Cost: $250/year (commercial license)

IP2Location (alternative):
├─ Similar to MaxMind
├─ Different pricing model
└─ Self-hosted or API-based

Database format:
├─ MMDB (MaxMind Database Format)
├─ Binary format (efficient lookup)
├─ Read-only (no modifications)
└─ Memory-mapped (fast access)
```

**GeoIP Data Structure:**
```
MMDB record structure:
{
  "ip": "8.8.8.8",
  "country": {
    "iso_code": "US",        // Two-letter country code (ISO 3166-1)
    "name": "United States",
    "confidence": 99         // Accuracy confidence (0-100)
  },
  "continent": {
    "code": "NA",            // North America
    "name": "North America"
  },
  "location": {
    "latitude": 37.4056,
    "longitude": -122.0775,
    "accuracy_radius": 1000  // Accuracy (km)
  },
  "registered_country": {
    "iso_code": "US"         // Where IP is registered (may differ from location)
  },
  "traits": {
    "autonomous_system_number": 15169,  // ASN (Google)
    "autonomous_system_organization": "GOOGLE",
    "is_anonymous_proxy": false,
    "is_satellite_provider": false
  }
}

Country codes (ISO 3166-1):
├─ US: United States
├─ RU: Russia
├─ CN: China
├─ KP: North Korea
├─ IR: Iran
├─ SY: Syria
└─ ... (249 total countries)
```

**GeoIP Library (Go):**
```
Library: github.com/oschwald/geoip2-golang

Installation:
go get github.com/oschwald/geoip2-golang

Usage:
import "github.com/oschwald/geoip2-golang"

// Open database
db, err := geoip2.Open("/path/to/GeoLite2-Country.mmdb")
if err != nil {
  return err
}
defer db.Close()

// Lookup IP
ip := net.ParseIP("8.8.8.8")
record, err := db.Country(ip)
if err != nil {
  return err
}

// Extract country
countryCode := record.Country.IsoCode  // "US"
countryName := record.Country.Names["en"]  // "United States"
```

**GeoIP Manager Implementation:**
```
type GeoIPManager struct {
  db         *geoip2.Reader  // GeoIP database
  dbPath     string
  lastUpdate time.Time
  mu         sync.RWMutex
}

func NewGeoIPManager(dbPath string) (*GeoIPManager, error) {
  // Open database
  db, err := geoip2.Open(dbPath)
  if err != nil {
    return nil, fmt.Errorf("failed to open GeoIP database: %w", err)
  }

  gm := &GeoIPManager{
    db:         db,
    dbPath:     dbPath,
    lastUpdate: time.Now(),
  }

  // Start auto-update goroutine
  go gm.autoUpdate()

  return gm, nil
}

func (gm *GeoIPManager) Lookup(ip string) (*GeoIPInfo, error) {
  parsedIP := net.ParseIP(ip)
  if parsedIP == nil {
    return nil, fmt.Errorf("invalid IP address: %s", ip)
  }

  gm.mu.RLock()
  defer gm.mu.RUnlock()

  // Lookup in database
  record, err := gm.db.Country(parsedIP)
  if err != nil {
    return nil, fmt.Errorf("GeoIP lookup failed: %w", err)
  }

  // Extract info
  info := &GeoIPInfo{
    IP:          ip,
    CountryCode: record.Country.IsoCode,
    CountryName: record.Country.Names["en"],
    Continent:   record.Continent.Code,
    ASN:         record.Traits.AutonomousSystemNumber,
    ASNOrg:      record.Traits.AutonomousSystemOrganization,
  }

  return info, nil
}

Auto-update database:
func (gm *GeoIPManager) autoUpdate() {
  ticker := time.NewTicker(24 * time.Hour)  // Check daily
  for range ticker.C {
    // Check if update available
    if gm.updateAvailable() {
      log.Info().Msg("GeoIP database update available")
      err := gm.downloadUpdate()
      if err != nil {
        log.Error().Err(err).Msg("Failed to update GeoIP database")
      } else {
        log.Info().Msg("GeoIP database updated successfully")
      }
    }
  }
}
```

---

**2. Country-Based Blocking**

**Purpose:** Block or allow traffic based on source country

**Blocking Modes:**
```
Mode 1: Deny-list (block specific countries)
├─ Config: blocked_countries = ["RU", "CN", "KP", "IR"]
├─ Logic: If country IN blocked_countries → DROP
├─ Use case: Block hostile nations
└─ Default: Allow all except blocked

Mode 2: Allow-list (allow only specific countries)
├─ Config: allowed_countries = ["US", "CA", "GB", "DE", "FR"]
├─ Logic: If country NOT IN allowed_countries → DROP
├─ Use case: Service only available in certain regions
└─ Default: Deny all except allowed

Mode 3: Mixed (allow-list with exceptions)
├─ Config: allowed_countries = ["US"], blocked_ips = ["203.0.113.50"]
├─ Logic: If country IN allowed → ALLOW, but if IP IN blocked → DROP
├─ Use case: Allow US, but block specific malicious US IPs
└─ Default: Complex logic (allow + exceptions)
```

**Configuration Example:**
```
[security.geoip]
enabled = true
database_path = "/etc/safeops/GeoLite2-Country.mmdb"
mode = "deny_list"  # "deny_list", "allow_list", or "mixed"

# Deny-list mode
blocked_countries = [
  "RU",  # Russia
  "CN",  # China
  "KP",  # North Korea
  "IR",  # Iran
  "SY",  # Syria
  "BY"   # Belarus
]

# Allow-list mode (alternative)
# allowed_countries = ["US", "CA", "GB", "DE", "FR", "AU"]

# Exceptions (apply to both modes)
whitelisted_ips = [
  "203.0.113.100",  # Partner in blocked country
  "198.51.100.0/24" # Trusted subnet
]

# Logging
log_blocked = true   # Log every blocked connection
log_allowed = false  # Don't log allowed (too verbose)
```

**Blocking Logic Implementation:**
```
type GeoBlocker struct {
  geoip          *GeoIPManager
  mode           GeoBlockMode
  blockedCountries map[string]bool  // Country code → blocked
  allowedCountries map[string]bool  // Country code → allowed
  whitelist      *Whitelist
  config         GeoBlockConfig
  mu             sync.RWMutex
}

type GeoBlockMode int
const (
  DenyList GeoBlockMode = iota  // Block specific countries
  AllowList                      // Allow only specific countries
  Mixed                          // Custom logic
)

func (gb *GeoBlocker) CheckConnection(ip string) Decision {
  if !gb.config.Enabled {
    return ALLOW
  }

  // Check whitelist first (bypass GeoIP)
  if whitelisted, _ := gb.whitelist.IsWhitelisted(ip); whitelisted {
    return ALLOW
  }

  // Lookup GeoIP
  geoInfo, err := gb.geoip.Lookup(ip)
  if err != nil {
    // Lookup failed (unknown IP, not in database)
    log.Warn().Str("ip", ip).Err(err).Msg("GeoIP lookup failed")

    // Configurable: Allow or deny unknown IPs
    if gb.config.AllowUnknown {
      return ALLOW
    } else {
      return DROP  // Fail-closed (deny unknown)
    }
  }

  countryCode := geoInfo.CountryCode

  // Apply blocking logic based on mode
  switch gb.mode {
  case DenyList:
    // Block specific countries
    if gb.blockedCountries[countryCode] {
      if gb.config.LogBlocked {
        log.Info().
          Str("ip", ip).
          Str("country", countryCode).
          Msg("Connection blocked (country denied)")
      }
      metrics.IncrementCounter("firewall_geoip_blocks_total", map[string]string{
        "country": countryCode,
      })
      return DROP
    }
    return ALLOW

  case AllowList:
    // Allow only specific countries
    if gb.allowedCountries[countryCode] {
      return ALLOW
    } else {
      if gb.config.LogBlocked {
        log.Info().
          Str("ip", ip).
          Str("country", countryCode).
          Msg("Connection blocked (country not allowed)")
      }
      metrics.IncrementCounter("firewall_geoip_blocks_total", map[string]string{
        "country": countryCode,
      })
      return DROP
    }

  default:
    return ALLOW
  }
}
```

---

**3. ASN-Based Blocking**

**Purpose:** Block traffic from specific Autonomous Systems (hosting providers, cloud networks)

**What is ASN:**
```
ASN (Autonomous System Number):
├─ Identifies networks on the Internet
├─ Assigned by regional registries (IANA, ARIN, RIPE, etc.)
├─ Example: AS15169 = Google, AS16509 = Amazon AWS
└─ Used for BGP routing

Why block by ASN:
├─ Cloud hosting abuse (botnets on AWS, GCP)
├─ VPN providers (Tor exit nodes, VPN networks)
├─ Hosting providers with poor abuse handling
└─ Datacenter IPs (legitimate users typically residential)

Common ASN blocks:
├─ AS396982: Google Cloud (abuse reports)
├─ AS16509: Amazon AWS (malicious instances)
├─ AS14061: DigitalOcean (botnet hosting)
├─ AS200651: Zservers (bulletproof hosting)
└─ AS202425: IP Volume Inc (known for abuse)
```

**ASN Blocking Configuration:**
```
[security.geoip]
enabled = true

# Block specific ASNs
blocked_asns = [
  396982,  # Google Cloud (abuse)
  200651,  # Zservers (bulletproof hosting)
  202425,  # IP Volume Inc (abuse)
  24940    # Hetzner (botnet hosting)
]

# Allow exceptions (trusted cloud IPs)
whitelisted_ips = [
  "35.186.224.0/24"  # Trusted Google Cloud subnet
]

# Logging
log_asn_blocks = true
```

**ASN Blocking Implementation:**
```
type ASNBlocker struct {
  geoip       *GeoIPManager
  blockedASNs map[uint]bool  // ASN → blocked
  whitelist   *Whitelist
  config      ASNBlockConfig
}

func (ab *ASNBlocker) CheckConnection(ip string) Decision {
  if !ab.config.Enabled {
    return ALLOW
  }

  // Check whitelist first
  if whitelisted, _ := ab.whitelist.IsWhitelisted(ip); whitelisted {
    return ALLOW
  }

  // Lookup GeoIP (includes ASN)
  geoInfo, err := ab.geoip.Lookup(ip)
  if err != nil {
    return ALLOW  // ASN unknown, allow
  }

  asn := geoInfo.ASN

  // Check if ASN is blocked
  if ab.blockedASNs[asn] {
    log.Warn().
      Str("ip", ip).
      Uint("asn", asn).
      Str("asn_org", geoInfo.ASNOrg).
      Msg("Connection blocked (hostile ASN)")

    metrics.IncrementCounter("firewall_geoip_asn_blocks_total", map[string]string{
      "asn": fmt.Sprintf("AS%d", asn),
    })

    return DROP
  }

  return ALLOW
}
```

---

**4. Allow-List Mode**

**Purpose:** Only allow connections from specific countries (inverse blocking)

**Use Cases:**
```
Allow-list scenarios:

1. Regional service (US-only):
   ├─ allowed_countries = ["US"]
   ├─ Use case: Streaming service (licensing restrictions)
   └─ Result: Block all non-US IPs

2. Europe-only (GDPR compliance):
   ├─ allowed_countries = ["GB", "DE", "FR", "IT", "ES", "NL", "BE", ...]
   ├─ Use case: EU-only service (data sovereignty)
   └─ Result: Block non-EU IPs

3. Corporate VPN (specific countries):
   ├─ allowed_countries = ["US", "CA"]
   ├─ Use case: Internal corporate network (employees in US/CA only)
   └─ Result: Block all other countries

4. High-security service (trusted nations):
   ├─ allowed_countries = ["US", "GB", "DE", "FR", "AU", "JP"]
   ├─ Use case: Financial service (strict security requirements)
   └─ Result: Block all non-trusted countries
```

**Allow-List Configuration:**
```
[security.geoip]
enabled = true
mode = "allow_list"  # Only allow specific countries

allowed_countries = [
  "US",  # United States
  "CA",  # Canada
  "GB",  # United Kingdom
  "DE",  # Germany
  "FR",  # France
  "AU",  # Australia
  "JP",  # Japan
  "NL",  # Netherlands
  "SE",  # Sweden
  "NO"   # Norway
]

# Default action for non-allowed countries
default_action = "DROP"

# Logging
log_blocked = true  # Log all blocked (non-allowed) countries
log_allowed = false
```

---

**5. GeoIP Cache (1M+ Entries)**

**Purpose:** Cache GeoIP lookups to avoid database queries on every packet

**Why Cache:**
```
Problem: GeoIP lookup overhead
├─ Database query: ~50μs per lookup (disk I/O)
├─ Packet rate: 100,000 packets/sec
├─ Lookups needed: 100,000/sec
├─ Total time: 100,000 × 50μs = 5 seconds per second (500% CPU!)
└─ Result: Performance bottleneck

Solution: Cache GeoIP results
├─ First lookup: 50μs (database query)
├─ Cached lookup: 0.1μs (memory access, 500× faster)
├─ Cache hit rate: 95% (most traffic from same IPs)
├─ Total time: (5,000 × 50μs) + (95,000 × 0.1μs) = 260ms per second
└─ Result: 20× performance improvement
```

**Cache Design:**
```
Cache structure:
├─ Storage: map[string]*GeoIPInfo (IP → GeoIP info)
├─ Size: 1M entries (limit)
├─ Eviction: LRU (Least Recently Used)
├─ TTL: 24 hours (GeoIP data stable)
└─ Memory: ~100MB (100 bytes per entry × 1M)

Cache hit scenarios:
├─ Scenario 1: Popular website (few IPs, high traffic)
│  └─ Hit rate: 99% (most traffic from same CDN IPs)
├─ Scenario 2: Corporate network (employees)
│  └─ Hit rate: 95% (employees reuse same IPs)
├─ Scenario 3: DDoS attack (many IPs)
│  └─ Hit rate: 20% (attacker uses many IPs, low reuse)
└─ Average: 85-95% hit rate

LRU eviction:
├─ Cache full (1M entries)
├─ New IP lookup needed
├─ Evict least recently used entry
└─ Insert new entry
```

**Cache Implementation:**
```
type GeoIPCache struct {
  cache   *lru.Cache  // LRU cache (github.com/hashicorp/golang-lru)
  ttl     time.Duration
  hits    uint64      // Cache hits (metrics)
  misses  uint64      // Cache misses (metrics)
  mu      sync.RWMutex
}

func NewGeoIPCache(size int, ttl time.Duration) (*GeoIPCache, error) {
  // Create LRU cache
  cache, err := lru.New(size)
  if err != nil {
    return nil, err
  }

  return &GeoIPCache{
    cache: cache,
    ttl:   ttl,
  }, nil
}

func (gc *GeoIPCache) Get(ip string) (*GeoIPInfo, bool) {
  gc.mu.RLock()
  defer gc.mu.RUnlock()

  // Check cache
  value, exists := gc.cache.Get(ip)
  if !exists {
    gc.misses++
    return nil, false  // Cache miss
  }

  // Check TTL
  cached := value.(*CachedGeoIPInfo)
  if time.Since(cached.CachedAt) > gc.ttl {
    // Expired, remove from cache
    gc.cache.Remove(ip)
    gc.misses++
    return nil, false  // Cache miss (expired)
  }

  // Cache hit
  gc.hits++
  return cached.Info, true
}

func (gc *GeoIPCache) Set(ip string, info *GeoIPInfo) {
  gc.mu.Lock()
  defer gc.mu.Unlock()

  cached := &CachedGeoIPInfo{
    Info:     info,
    CachedAt: time.Now(),
  }

  // Add to cache (LRU evicts if full)
  gc.cache.Add(ip, cached)
}

func (gc *GeoIPCache) GetHitRate() float64 {
  gc.mu.RLock()
  defer gc.mu.RUnlock()

  total := gc.hits + gc.misses
  if total == 0 {
    return 0.0
  }

  return float64(gc.hits) / float64(total)
}

Integration with GeoIP manager:
func (gm *GeoIPManager) LookupWithCache(ip string) (*GeoIPInfo, error) {
  // Check cache first
  if cached, hit := gm.cache.Get(ip); hit {
    return cached, nil  // Cache hit
  }

  // Cache miss, lookup in database
  info, err := gm.Lookup(ip)
  if err != nil {
    return nil, err
  }

  // Store in cache
  gm.cache.Set(ip, info)

  return info, nil
}
```

---

#### Files to Create:
```
internal/security/
├── geo_blocker.go       # GeoIP blocking coordinator
├── geoip_manager.go     # GeoIP database management
├── geoip_cache.go       # GeoIP lookup cache (LRU)
├── country_blocker.go   # Country-based blocking
├── asn_blocker.go       # ASN-based blocking
└── geoip_updater.go     # Auto-update GeoIP database
```

---

### Sub-Task 7.5: Anomaly Detection (`internal/security/anomaly_detector.go`)

**Purpose:** Detect abnormal packet patterns and protocol violations

**Core Concept:**
Anomaly detection identifies suspicious traffic patterns that don't match known attack signatures but deviate from normal behavior.

---

#### What to Create:

**1. Packet Size Anomalies**

**Purpose:** Detect abnormally sized packets (too small or too large)

**Normal Packet Sizes:**
```
Typical packet sizes by protocol:

TCP:
├─ Minimum: 40 bytes (20-byte IP + 20-byte TCP header, no payload)
├─ Typical: 64-1500 bytes (Ethernet MTU)
├─ Maximum: 65,535 bytes (IP max, jumbo frames)
└─ Normal distribution: 60-1500 bytes (95% of traffic)

UDP:
├─ Minimum: 28 bytes (20-byte IP + 8-byte UDP header, no payload)
├─ Typical: 64-1500 bytes
├─ DNS: 50-512 bytes
├─ NTP: 48-90 bytes
└─ Normal: Varies by application

ICMP:
├─ Echo Request: 64 bytes (default ping)
├─ Echo Reply: 64 bytes
├─ Normal: 64-1500 bytes
└─ Abnormal: >1500 bytes (jumbo ICMP)
```

**Anomaly Scenarios:**
```
Anomaly 1: Zero-byte payload
├─ Packet: TCP with 40 bytes (header only, no data)
├─ Frequency: 10,000 packets/sec
├─ Attack: Keepalive flood (resource exhaustion)
└─ Action: Detect + ban

Anomaly 2: Oversized packets
├─ Packet: UDP with 65,000 bytes (near max)
├─ Frequency: 1,000 packets/sec
├─ Attack: Amplification attack (large payloads)
└─ Action: Detect + ban

Anomaly 3: Undersized packets
├─ Packet: TCP with 20 bytes (invalid, missing TCP header)
├─ Attack: Crafted packet (evasion technique)
└─ Action: Drop + log

Anomaly 4: Inconsistent size
├─ Normal: Client sends 100-200 byte packets consistently
├─ Anomaly: Suddenly sends 5,000 byte packets
├─ Attack: Possible data exfiltration or protocol abuse
└─ Action: Log + alert (investigate)
```

**Detection Algorithm:**
```
Track packet sizes per IP:

Data structure:
{
  "ip": "198.18.0.50",
  "packet_sizes": [0, 0, 0, 0, ...],  // Last 100 packets
  "avg_size": 40,                      // Average size
  "std_dev": 0,                        // Standard deviation
  "anomaly_count": 50,                 // Packets with size 0
  "baseline": {
    "min": 64,
    "max": 1500,
    "avg": 800
  }
}

Detection logic:
1. Track last 100 packet sizes per IP
2. Calculate statistics:
   ├─ Average: 40 bytes (normal: 800 bytes)
   ├─ Std dev: 0 (normal: 200 bytes)
   └─ Anomaly: avg < baseline - (2 × std_dev)

3. If anomaly detected:
   ├─ Count anomalous packets: 50/100 = 50%
   ├─ If anomaly_rate > 30%: Suspicious
   └─ If anomaly_rate > 50%: Attack confirmed

4. Action:
   ├─ Log: "Packet size anomaly from <IP>"
   ├─ Create temp ban: 30 minutes
   └─ Increment metric: firewall_anomaly_detections_total{type="packet_size"}
```

**Implementation:**
```
type PacketSizeAnomaly struct {
  ip          string
  packetSizes []int     // Ring buffer (last 100)
  index       int       // Current position in ring buffer
  avgSize     float64
  stdDev      float64
  baseline    SizeBaseline
}

type SizeBaseline struct {
  Min int
  Max int
  Avg int
}

func (psa *PacketSizeAnomaly) TrackPacket(size int) bool {
  // Add to ring buffer
  psa.packetSizes[psa.index] = size
  psa.index = (psa.index + 1) % len(psa.packetSizes)

  // Calculate statistics (if buffer full)
  if psa.isFull() {
    psa.calculateStats()

    // Check for anomaly
    if psa.isAnomaly() {
      return true  // Anomaly detected
    }
  }

  return false
}

func (psa *PacketSizeAnomaly) calculateStats() {
  // Calculate average
  sum := 0
  for _, size := range psa.packetSizes {
    sum += size
  }
  psa.avgSize = float64(sum) / float64(len(psa.packetSizes))

  // Calculate standard deviation
  variance := 0.0
  for _, size := range psa.packetSizes {
    diff := float64(size) - psa.avgSize
    variance += diff * diff
  }
  variance /= float64(len(psa.packetSizes))
  psa.stdDev = math.Sqrt(variance)
}

func (psa *PacketSizeAnomaly) isAnomaly() bool {
  // Check if average significantly below baseline
  threshold := float64(psa.baseline.Avg) - (2.0 * psa.stdDev)

  if psa.avgSize < threshold {
    // Average too low (possible zero-byte flood)
    return true
  }

  // Check if average significantly above baseline
  thresholdHigh := float64(psa.baseline.Avg) + (2.0 * psa.stdDev)

  if psa.avgSize > thresholdHigh {
    // Average too high (possible amplification)
    return true
  }

  // Check for zero-byte packets (special case)
  zeroCount := 0
  for _, size := range psa.packetSizes {
    if size == 0 || size < 40 {  // Invalid size
      zeroCount++
    }
  }

  anomalyRate := float64(zeroCount) / float64(len(psa.packetSizes))
  if anomalyRate > 0.5 {
    // >50% packets are zero-byte (clear anomaly)
    return true
  }

  return false
}
```

---

**2. Protocol Violations**

**Purpose:** Detect packets with invalid TCP/UDP/ICMP headers

**TCP Flag Violations:**
```
Normal TCP flags:
├─ SYN: Initiate connection
├─ SYN-ACK: Accept connection
├─ ACK: Acknowledge data
├─ FIN: Close connection gracefully
├─ RST: Abort connection
└─ PSH: Push data immediately

Valid combinations:
├─ SYN: Connection start
├─ SYN-ACK: Connection accept
├─ ACK: Normal data transfer
├─ FIN-ACK: Graceful close
├─ RST: Immediate close
└─ PSH-ACK: Push data

Invalid combinations (attacks):
├─ SYN+FIN: Impossible (open + close simultaneously)
├─ SYN+RST: Impossible (open + abort simultaneously)
├─ FIN+RST: Impossible (close + abort simultaneously)
├─ SYN+FIN+PSH+URG: Xmas scan (nmap -sX)
├─ No flags: Null scan (nmap -sN)
└─ FIN only: FIN scan (nmap -sF)

Attack signatures:
├─ Xmas scan: SYN+FIN+PSH+URG (all flags set, lights up like Xmas tree)
├─ Null scan: No flags (TCP packet with no flags)
├─ FIN scan: FIN only (stealthy scan, bypasses some firewalls)
└─ Maimon scan: FIN+ACK (named after Uriel Maimon)
```

**Protocol Violation Detection:**
```
Check TCP flags:

Invalid flag combinations:
1. SYN+FIN: if (SYN && FIN) → Invalid (Xmas scan variant)
2. SYN+RST: if (SYN && RST) → Invalid
3. FIN+RST: if (FIN && RST) → Invalid
4. No flags: if (!SYN && !ACK && !FIN && !RST && !PSH && !URG) → Invalid (Null scan)
5. All flags: if (SYN && FIN && RST && PSH && ACK && URG) → Invalid (Xmas scan)

TCP window size violations:
├─ Window = 0: Valid (flow control), but suspicious if persistent
├─ Window > 65,535: Invalid (exceeds TCP max)
└─ Window changes drastically: Suspicious (covert channel)

TCP sequence number violations:
├─ SEQ = 0: Suspicious (some OS fingerprinting tools)
├─ SEQ out of order: Possible TCP injection attack
└─ SEQ anomalies: Covert timing channel

UDP violations:
├─ Length < 8: Invalid (minimum UDP header = 8 bytes)
├─ Length > IP packet size: Invalid (header corruption)
└─ Checksum = 0: Optional (but suspicious if always 0)

ICMP violations:
├─ Type invalid: Type > 18 (valid types: 0-18)
├─ Code invalid: Code doesn't match type
└─ Payload malformed: Checksum mismatch, invalid length
```

**Implementation:**
```
type ProtocolViolationDetector struct {
  violations map[string]int  // IP → violation count
  mu         sync.RWMutex
}

func (pvd *ProtocolViolationDetector) CheckTCPFlags(pkt *Packet) Decision {
  flags := pkt.TCPFlags

  // Extract individual flags
  syn := (flags & TCP_SYN) != 0
  fin := (flags & TCP_FIN) != 0
  rst := (flags & TCP_RST) != 0
  psh := (flags & TCP_PSH) != 0
  ack := (flags & TCP_ACK) != 0
  urg := (flags & TCP_URG) != 0

  // Check invalid combinations
  violations := []string{}

  if syn && fin {
    violations = append(violations, "SYN+FIN (invalid combination)")
  }

  if syn && rst {
    violations = append(violations, "SYN+RST (invalid combination)")
  }

  if fin && rst {
    violations = append(violations, "FIN+RST (invalid combination)")
  }

  if !syn && !fin && !rst && !psh && !ack && !urg {
    violations = append(violations, "NULL scan (no flags set)")
  }

  if syn && fin && rst && psh && ack && urg {
    violations = append(violations, "Xmas scan (all flags set)")
  }

  if len(violations) > 0 {
    // Protocol violation detected
    log.Warn().
      Str("src_ip", pkt.SrcIP).
      Strs("violations", violations).
      Msg("TCP protocol violation detected")

    // Track violations per IP
    pvd.mu.Lock()
    pvd.violations[pkt.SrcIP]++
    count := pvd.violations[pkt.SrcIP]
    pvd.mu.Unlock()

    // If repeated violations, ban
    if count > 5 {
      log.Warn().
        Str("src_ip", pkt.SrcIP).
        Int("violation_count", count).
        Msg("Repeated protocol violations, banning IP")

      banManager.CreateBan(pkt.SrcIP, "Protocol violations", 30*time.Minute)
    }

    metrics.IncrementCounter("firewall_anomaly_detections_total", map[string]string{
      "type": "protocol_violation",
    })

    return DROP  // Drop violating packet
  }

  return ALLOW
}
```

---

**3. Port Scanning Detection**

**Purpose:** Detect port scans (attacker probing for open ports)

**Port Scan Techniques:**
```
TCP Connect Scan:
├─ Attacker: SYN → Port 22
├─ Server: SYN-ACK (port open) or RST (port closed)
├─ Attacker: ACK → Port 22 (completes handshake if open)
├─ Pattern: Many SYN packets to different ports
└─ Detection: Count unique destination ports per IP

TCP SYN Scan:
├─ Attacker: SYN → Port 22
├─ Server: SYN-ACK (port open) or RST (port closed)
├─ Attacker: RST (aborts connection, stealthy)
├─ Pattern: Many SYN packets, no ACK (incomplete handshake)
└─ Detection: High SYN rate, low ACK rate

UDP Scan:
├─ Attacker: UDP packet → Port 53
├─ Server: ICMP Port Unreachable (port closed) or no response (open/filtered)
├─ Pattern: Many UDP packets to different ports
└─ Detection: Count unique destination ports per IP

Sequential Scan:
├─ Attacker probes: Port 1, 2, 3, 4, 5, ... 65535
├─ Pattern: Sequential port numbers
└─ Detection: port_n+1 = port_n + 1 (sequential)

Random Scan:
├─ Attacker probes: Port 443, 22, 8080, 3389, 80, ...
├─ Pattern: Random port numbers
└─ Detection: Many unique ports, not sequential

Slow Scan:
├─ Attacker probes: 1 port per minute (evade detection)
├─ Pattern: Low rate, long duration
└─ Detection: Track over long time window (hours)
```

**Port Scan Detection Algorithm:**
```
Track port probes per IP:

Data structure:
{
  "ip": "104.28.5.10",
  "ports_probed": [22, 23, 80, 443, 3389, 8080, ...],  // Unique ports
  "probe_count": 1000,
  "time_window": 60,  // Last 60 seconds
  "probe_rate": 16.6, // 1000 / 60 = 16.6 ports/sec
  "sequential": true, // Are ports sequential?
  "scan_type": "TCP SYN scan"
}

Detection logic:
1. Track unique destination ports per source IP
2. If unique_ports > 100 in 60 seconds:
   └─ Port scan detected (normal users probe <10 ports)

3. Check scan pattern:
   ├─ Sequential: ports = [1, 2, 3, 4, 5, ...] → Sequential scan
   └─ Random: ports = [80, 22, 443, 3389, ...] → Random scan

4. Check scan rate:
   ├─ Fast: >10 ports/sec → Aggressive scan (nmap default)
   ├─ Slow: 1 port/min → Stealthy scan (nmap -T0)
   └─ Moderate: 1-10 ports/sec → Normal scan

5. Action:
   ├─ Log: "Port scan detected from <IP> (1000 ports probed)"
   ├─ Ban: 2 hours (port scanning = reconnaissance)
   └─ Alert: "Potential attack reconnaissance from <IP>"
```

**Implementation:**
```
type PortScanDetector struct {
  scanners map[string]*PortScanStats  // IP → Stats
  mu       sync.RWMutex
  config   PortScanConfig
}

type PortScanStats struct {
  IP          string
  PortsProbed map[int]bool  // Unique ports (set)
  ProbeCount  int
  WindowStart time.Time
  LastPort    int           // Last probed port (for sequential detection)
  Sequential  int           // Count of sequential probes
}

type PortScanConfig struct {
  Enabled         bool
  PortThreshold   int           // 100 ports = scan
  TimeWindow      time.Duration // 60 seconds
  BanDuration     time.Duration // 2 hours
}

func (psd *PortScanDetector) TrackConnection(pkt *Packet) Decision {
  if !psd.config.Enabled {
    return ALLOW
  }

  psd.mu.Lock()
  defer psd.mu.Unlock()

  // Get or create scanner stats
  stats, exists := psd.scanners[pkt.SrcIP]
  if !exists {
    stats = &PortScanStats{
      IP:          pkt.SrcIP,
      PortsProbed: make(map[int]bool),
      WindowStart: time.Now(),
    }
    psd.scanners[pkt.SrcIP] = stats
  }

  // Reset window if expired
  if time.Since(stats.WindowStart) > psd.config.TimeWindow {
    stats.PortsProbed = make(map[int]bool)
    stats.ProbeCount = 0
    stats.WindowStart = time.Now()
    stats.Sequential = 0
  }

  // Track port probe
  stats.PortsProbed[pkt.DstPort] = true
  stats.ProbeCount++

  // Check for sequential scan
  if pkt.DstPort == stats.LastPort+1 {
    stats.Sequential++
  }
  stats.LastPort = pkt.DstPort

  // Check threshold
  uniquePorts := len(stats.PortsProbed)
  if uniquePorts > psd.config.PortThreshold {
    // Port scan detected
    scanType := "Random scan"
    if stats.Sequential > uniquePorts/2 {
      scanType = "Sequential scan"
    }

    log.Warn().
      Str("src_ip", pkt.SrcIP).
      Int("ports_probed", uniquePorts).
      Str("scan_type", scanType).
      Msg("Port scan detected")

    // Ban IP
    banManager.CreateBan(pkt.SrcIP, "Port scan", psd.config.BanDuration)

    metrics.IncrementCounter("firewall_anomaly_detections_total", map[string]string{
      "type": "port_scan",
    })

    return DROP
  }

  return ALLOW
}
```

---

**4. Unusual Connection Patterns**

**Purpose:** Detect behavioral anomalies (not signature-based)

**Behavioral Anomalies:**
```
Anomaly 1: Beaconing (C2 communication)
├─ Pattern: Periodic connections (every 60 seconds)
├─ Destination: Same IP/domain repeatedly
├─ Payload: Small, consistent size
├─ Example: Malware beacon to C2 server (185.220.101.50)
└─ Detection: Connection frequency histogram (periodic spikes)

Anomaly 2: Data Exfiltration
├─ Pattern: Large outbound data transfer
├─ Baseline: User typically sends <10MB/hour
├─ Anomaly: User sends 500MB in 10 minutes
├─ Example: Insider exfiltrating data to personal cloud
└─ Detection: Track bytes sent per IP, compare to baseline

Anomaly 3: Lateral Movement
├─ Pattern: Internal IP scanning other internal IPs
├─ Baseline: Workstations don't scan (servers do)
├─ Anomaly: 192.168.1.100 (workstation) probes 100 internal IPs
├─ Example: Compromised workstation scanning for targets
└─ Detection: Track internal IP → internal IP connections

Anomaly 4: Unusual Protocols
├─ Pattern: User suddenly uses obscure protocol (TFTP, Telnet)
├─ Baseline: User only uses HTTP/HTTPS/DNS
├─ Anomaly: User connects to port 69 (TFTP, rarely used)
├─ Example: Attacker using TFTP to exfiltrate data
└─ Detection: Track protocols used per IP, flag new protocols

Anomaly 5: Time-of-Day Anomaly
├─ Pattern: User connects at 3 AM (off-hours)
├─ Baseline: User only active 9 AM - 5 PM (business hours)
├─ Anomaly: Connection at 3 AM
├─ Example: Stolen credentials used by attacker
└─ Detection: Track connection time distribution, flag outliers
```

**Beaconing Detection:**
```
Algorithm:
1. Track connection timestamps per IP+destination pair
2. Calculate inter-arrival times (time between connections)
3. Check for periodicity:
   ├─ Consistent inter-arrival: 60s, 60s, 60s, ... (beacon)
   ├─ Random inter-arrival: 5s, 120s, 30s, ... (normal)
   └─ Metric: Coefficient of variation (CV = stddev / mean)

4. If CV < 0.1 (very consistent timing):
   └─ Beaconing detected (malware beacon)

5. Action:
   ├─ Log: "Beaconing detected: <IP> → <Dest> (60s intervals)"
   ├─ Alert: High priority (possible malware C2)
   └─ Block destination (add to blocklist)

Example:
Connection times: 10:00:00, 10:01:00, 10:02:00, 10:03:00
Inter-arrival: 60s, 60s, 60s
Mean: 60s, Std dev: 0s, CV: 0/60 = 0 (perfect periodicity, beacon!)
```

**Implementation:**
```
type BeaconDetector struct {
  connections map[string]*ConnectionPattern  // IP+Dest → Pattern
  mu          sync.RWMutex
}

type ConnectionPattern struct {
  IP             string
  Destination    string
  Timestamps     []time.Time  // Last 20 connection times
  InterArrivals  []float64    // Time between connections (seconds)
  Mean           float64      // Mean inter-arrival
  StdDev         float64      // Standard deviation
  CV             float64      // Coefficient of variation
}

func (bd *BeaconDetector) TrackConnection(ip string, dest string, timestamp time.Time) bool {
  bd.mu.Lock()
  defer bd.mu.Unlock()

  key := fmt.Sprintf("%s->%s", ip, dest)

  pattern, exists := bd.connections[key]
  if !exists {
    pattern = &ConnectionPattern{
      IP:          ip,
      Destination: dest,
      Timestamps:  []time.Time{},
    }
    bd.connections[key] = pattern
  }

  // Add timestamp
  pattern.Timestamps = append(pattern.Timestamps, timestamp)

  // Keep last 20 timestamps only
  if len(pattern.Timestamps) > 20 {
    pattern.Timestamps = pattern.Timestamps[1:]
  }

  // Need at least 10 samples for detection
  if len(pattern.Timestamps) < 10 {
    return false
  }

  // Calculate inter-arrival times
  pattern.InterArrivals = []float64{}
  for i := 1; i < len(pattern.Timestamps); i++ {
    delta := pattern.Timestamps[i].Sub(pattern.Timestamps[i-1]).Seconds()
    pattern.InterArrivals = append(pattern.InterArrivals, delta)
  }

  // Calculate mean
  sum := 0.0
  for _, delta := range pattern.InterArrivals {
    sum += delta
  }
  pattern.Mean = sum / float64(len(pattern.InterArrivals))

  // Calculate standard deviation
  variance := 0.0
  for _, delta := range pattern.InterArrivals {
    diff := delta - pattern.Mean
    variance += diff * diff
  }
  variance /= float64(len(pattern.InterArrivals))
  pattern.StdDev = math.Sqrt(variance)

  // Calculate coefficient of variation
  if pattern.Mean > 0 {
    pattern.CV = pattern.StdDev / pattern.Mean
  }

  // Check for beaconing (CV < 0.1 = very periodic)
  if pattern.CV < 0.1 && pattern.Mean > 10 {
    // Beaconing detected
    log.Warn().
      Str("src_ip", ip).
      Str("dst", dest).
      Float64("mean_interval", pattern.Mean).
      Float64("cv", pattern.CV).
      Msg("Beaconing detected (potential malware C2)")

    metrics.IncrementCounter("firewall_anomaly_detections_total", map[string]string{
      "type": "beaconing",
    })

    return true  // Beacon detected
  }

  return false
}
```

---

**5. Machine Learning Integration (Future Enhancement)**

**Purpose:** Use ML models to detect complex anomalies

**ML Approach:**
```
Traditional detection (Phase 7):
├─ Rule-based (if X then Y)
├─ Threshold-based (if count > N)
├─ Signature-based (if pattern matches)
└─ Limitations: Can't detect unknown attacks

ML detection (Future Phase 8+):
├─ Train model on normal traffic (baseline)
├─ Model learns: "Normal traffic looks like X"
├─ Detect deviations from normal (anomalies)
└─ Advantage: Detects zero-day attacks (unknown patterns)

ML models:
1. Isolation Forest (unsupervised anomaly detection)
2. Autoencoders (deep learning, reconstruction error)
3. LSTM (recurrent neural network, time-series anomalies)
4. One-Class SVM (support vector machine, novelty detection)

Features for ML:
├─ Packet size distribution
├─ Inter-arrival times
├─ Protocol distribution
├─ Port distribution
├─ Connection duration
├─ Bytes sent/received ratio
└─ Time-of-day patterns

Training:
1. Collect 30 days of normal traffic (baseline)
2. Extract features (1000-dimensional vectors)
3. Train model: "Normal traffic = cluster of points"
4. Deploy model: "New traffic → calculate distance from cluster"
5. If distance > threshold: Anomaly detected

Example:
Normal traffic: avg_packet_size=800, inter_arrival=100ms, ...
Anomaly: avg_packet_size=40, inter_arrival=10ms, ... (distance = 0.9, threshold = 0.5)
Result: Anomaly detected (distance exceeds threshold)
```

**ML Integration (Conceptual):**
```
type MLAnomalyDetector struct {
  model        *MLModel      // Trained model (TensorFlow, PyTorch)
  featureExtractor *FeatureExtractor
  threshold    float64       // Anomaly score threshold
}

func (mlad *MLAnomalyDetector) DetectAnomaly(pkt *Packet, context *TrafficContext) (bool, float64) {
  // Extract features from packet + context
  features := mlad.featureExtractor.Extract(pkt, context)
  // features = [800.0, 100.0, 6.0, ...]  (1000-dimensional vector)

  // Run inference (forward pass through model)
  anomalyScore := mlad.model.Predict(features)
  // anomalyScore = 0.9 (0=normal, 1=anomaly)

  // Check threshold
  if anomalyScore > mlad.threshold {
    return true, anomalyScore  // Anomaly detected
  }

  return false, anomalyScore  // Normal traffic
}

Note: ML integration is advanced feature (Phase 8+)
Phase 7 focuses on rule-based anomaly detection (no ML)
```

---

#### Files to Create:
```
internal/security/
├── anomaly_detector.go      # Anomaly detection coordinator
├── packet_size_anomaly.go   # Packet size anomaly detection
├── protocol_violation.go    # Protocol violation detection
├── port_scan_detector.go    # Port scan detection
├── behavior_anomaly.go      # Behavioral anomaly detection (beaconing, etc.)
└── baseline_tracker.go      # Track baseline behavior (for anomaly comparison)
```

---

## 📊 Phase 7 Success Criteria

**By end of Phase 7, the firewall must demonstrate:**

1. ✅ **DDoS Protection:**
   - SYN flood detection (10,000 SYN/sec → auto-ban)
   - UDP flood mitigation (50,000 UDP/sec → auto-ban)
   - ICMP flood protection (100 ICMP/sec → rate limit)
   - Auto-ban with exponential backoff (1h → 4h → 16h → permanent)

2. ✅ **Rate Limiting:**
   - Per-IP connection limits (100 conn/min enforced)
   - Token bucket algorithm working (burst + sustained rate)
   - Whitelist exemptions (internal IPs, partners)
   - Dynamic adjustment (reduce rate during attack)

3. ✅ **Brute Force Detection:**
   - SSH brute force blocked (5 failures → 1 hour ban)
   - RDP brute force blocked (3 failures → 4 hour ban)
   - Exponential backoff (repeat offenders → longer bans)
   - Distributed attack detection (coordinated attacks)
   - Threat intel integration (known attackers → immediate ban)

4. ✅ **GeoIP Blocking:**
   - Country-based blocking (RU, CN, KP blocked)
   - ASN-based blocking (hostile cloud providers)
   - Allow-list mode (US-only service)
   - GeoIP cache (1M entries, 95% hit rate)
   - Auto-update GeoIP database (weekly)

5. ✅ **Anomaly Detection:**
   - Packet size anomalies (0-byte packets → ban)
   - Protocol violations (SYN+FIN → drop + ban)
   - Port scan detection (100 ports → 2 hour ban)
   - Beaconing detection (periodic C2 → alert)
   - Behavioral anomalies (data exfiltration → alert)

---

## 📈 Phase 7 Metrics

**Prometheus Metrics Exported:**
```
# DDoS metrics
firewall_ddos_attacks_total{type="syn_flood|udp_flood|icmp_flood"}
firewall_ddos_attacks_mitigated_total
firewall_ddos_packets_dropped_total
firewall_ddos_bans_active

# Rate limiting metrics
firewall_ratelimit_throttled_ips_total
firewall_ratelimit_connections_dropped_total
firewall_ratelimit_tokens_consumed{ip="X.X.X.X"}

# Brute force metrics
firewall_bruteforce_attacks_total
firewall_bruteforce_banned_ips_current
firewall_bruteforce_failed_attempts_total

# GeoIP metrics
firewall_geoip_blocks_total{country="RU|CN|KP|..."}
firewall_geoip_cache_hit_rate
firewall_geoip_cache_size

# Anomaly detection metrics
firewall_anomaly_detections_total{type="packet_size|protocol_violation|port_scan|beaconing"}
firewall_anomaly_bans_total
```

---

## 🚀 Next Steps After Phase 7

After Phase 7 completion, proceed to:
- **Phase 8:** Testing & Benchmarking (stress tests, performance tuning, attack simulations)
- **Phase 9:** Production Deployment (Docker, Kubernetes, systemd service, CI/CD)
- **Phase 10:** Advanced Features (Machine Learning, Threat Intelligence feeds, SIEM integration)

**Estimated Total Time for Phase 7:** 3 weeks

---

**END OF PHASE 7 DOCUMENTATION**