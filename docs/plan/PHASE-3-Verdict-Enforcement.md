# PHASE 3: VERDICT ENFORCEMENT & SAFEOPS INTEGRATION

**Status:** 🔄 Next Phase (After Phase 2 Complete)
**Duration:** 2 weeks
**Goal:** Transform firewall decisions into actual network actions
**Deliverable:** Firewall actively enforces verdicts (blocks/allows real traffic)

---

## 📋 Phase Overview

**What Changes in Phase 3:**
- **Phase 2 Reality:** Firewall makes decisions (ALLOW/DENY/DROP) but doesn't enforce them (logging only)
- **Phase 3 Goal:** Firewall actively blocks/allows traffic based on decisions
- **Integration Point:** SafeOps verdict engine for packet manipulation at kernel level

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working (packets flowing in)
- ✅ Phase 2: Rule matching engine functional (decisions being made)

---

## 🎯 Phase 3 Outcomes (What You Should See)

### After Compilation & Execution:

**Console Output Example:**
```
[INFO] Firewall Engine v3.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Verdict enforcement: ENABLED
[INFO] Cache initialized (100,000 entries, 60s TTL)
[INFO] Worker pool started (8 workers)
[INFO] Processing packets...

[INFO] Packet: 192.168.1.100:54321 -> 8.8.8.8:443 TCP [ALLOW] Rule: Allow_Established_Connections
[INFO] Verdict: ALLOW → No action taken (packet forwarded normally)

[INFO] Packet: 192.168.1.100:61234 -> 157.240.0.35:443 TCP [DENY] Rule: Block_Facebook
[WARN] Verdict: DENY → Injecting TCP RST to 157.240.0.35:443
[INFO] Enforcement: TCP RST sent successfully to both ends

[INFO] Packet: 192.168.1.100:52000 -> 185.220.101.50:80 TCP [DROP] Rule: Drop_Malware_IPs
[WARN] Verdict: DROP → Adding 185.220.101.50 to kernel blocklist
[INFO] Enforcement: IP blocked at kernel level (silent drop)

[INFO] DNS Query: 192.168.1.100:54123 -> 8.8.8.8:53 UDP [REDIRECT] Rule: Redirect_Gambling_Sites
[WARN] Verdict: REDIRECT → Injecting fake DNS response for gambling.com
[INFO] Enforcement: DNS response spoofed (captive portal: 192.168.1.1)

[INFO] Statistics: Processed=150,000 | Allowed=120,000 | Blocked=30,000 | Cache_Hit_Rate=82%
```

**Real-World Network Behavior:**
1. **ALLOW Verdict:** Traffic flows normally (Google DNS, HTTPS to trusted sites)
2. **DENY Verdict:** Connection actively reset (browser shows "Connection refused" instantly)
3. **DROP Verdict:** Connection times out silently (30s timeout, no response)
4. **REDIRECT Verdict:** DNS queries redirected to captive portal (block page displayed)

**Performance Metrics Achieved:**
- Packet throughput: 100,000 packets/sec sustained
- Processing latency: <1ms per packet (p99)
- Cache hit rate: >80% (verdict cached for repeat flows)
- Memory usage: <500MB with 100K cached verdicts
- CPU usage: <50% on 8-core system
- Packet loss: 0% (no dropped legitimate traffic)

---

## 📦 Phase 3 Components (5 Sub-Tasks)

### Sub-Task 3.1: Verdict Engine Integration (`internal/enforcement/`)

**Purpose:** Execute firewall decisions by calling SafeOps verdict engine APIs

**Core Concept:**
This is the "muscle" of the firewall - it translates abstract decisions (ALLOW/DENY/DROP) into concrete network actions (forward packet, inject RST, add to blocklist). The enforcement engine doesn't decide anything; it simply executes orders from the rule matching engine.

---

#### What to Create:

**1. Verdict Handler (Main Orchestrator)**

**Purpose:** Routes verdicts to the correct enforcement handler

**Conceptual Flow:**
```
Verdict Decision (from Phase 2 rule matching)
       ↓
Verdict Handler receives verdict + packet metadata + matched rule
       ↓
Switch on verdict type:
  ├─ ALLOW:    No action, let packet through
  ├─ DROP:     Route to drop handler → silent discard
  ├─ DENY:     Route to TCP RST handler → active termination
  ├─ REDIRECT: Route to DNS redirect handler → DNS spoofing
  └─ REJECT:   Route to ICMP reject handler → polite rejection
       ↓
Handler returns success/error
       ↓
Update statistics (verdict counters, rule hit counts)
       ↓
Log enforcement action to firewall.log
```

**Error Handling Philosophy:**
- **Fail-Open Design:** If enforcement fails, allow packet through (don't crash firewall)
- **Retry Logic:** Retry failed enforcements up to 3 times with exponential backoff (10ms → 20ms → 40ms)
- **Graceful Degradation:** If SafeOps verdict engine unavailable, fall back to WFP-only mode
- **Never Crash:** Enforcement errors logged but never crash the firewall process

**Why Fail-Open:**
Better to allow suspicious traffic than to block all legitimate traffic if the firewall encounters an error. Enterprise networks prioritize availability over absolute security.

---

**2. Silent Drop Handler (DROP Verdict)**

**Purpose:** Discard packets silently without any response to the sender

**How It Works:**
When a packet matches a DROP rule, the firewall calls SafeOps kernel driver to add the destination IP to a kernel-level blocklist. All future packets to that IP are discarded at kernel level (before reaching TCP/IP stack), consuming zero CPU time for processing.

**What Happens at Kernel Level:**
1. SafeOps NDIS driver maintains a hash table of blocked IPs
2. When packet arrives, driver checks hash table (O(1) lookup)
3. If IP is in blocklist: packet immediately discarded (wire-speed filtering)
4. If IP not in blocklist: packet forwarded to TCP/IP stack normally

**Network Perspective:**
- Attacker sends packet to target IP
- Firewall silently drops packet (no response)
- Attacker waits... timeout after 30 seconds
- Attacker can't tell if host is offline, firewall is blocking, or network is down
- This is intentional - don't reveal firewall presence to attacker

**Use Cases:**
- Blocking malware C2 (command & control) servers - don't alert malware that it's detected
- Dropping DDoS traffic - conserve resources, no need to respond to attackers
- Blocking port scanners - don't reveal which ports are filtered vs closed
- Blocking brute force login attempts - silent discard after N failed attempts

**Performance Characteristics:**
- Kernel-level blocking (wire-speed, zero CPU overhead after first block)
- Hash table lookup: O(1) constant time
- No packet crafting needed (just discard)
- Scales to millions of packets/sec

---

**3. TCP RST Injection Handler (DENY Verdict)**

**Purpose:** Actively terminate TCP connections by injecting TCP RST packets

**How It Works:**
When a packet matches a DENY rule (TCP only), the firewall crafts two TCP RST (reset) packets:
1. RST to client (spoofed from server)
2. RST to server (spoofed from client)

Both sides of the connection receive a RST, causing immediate termination.

**TCP RST Packet Structure (Conceptual):**
```
Ethernet Header:
  ├─ Source MAC: Client MAC (for RST to client) or Server MAC (for RST to server)
  ├─ Dest MAC: Gateway MAC or Next-hop MAC
  └─ EtherType: IPv4 (0x0800)

IP Header:
  ├─ Source IP: Spoofed (server IP for RST to client, client IP for RST to server)
  ├─ Dest IP: Target IP (client or server)
  ├─ Protocol: TCP (6)
  └─ TTL: 64 (default)

TCP Header:
  ├─ Source Port: Server port (for RST to client) or Client port (for RST to server)
  ├─ Dest Port: Target port
  ├─ Sequence Number: Next expected sequence (from original packet + 1)
  ├─ RST Flag: SET (1)
  ├─ ACK Flag: SET (1) - acknowledges last packet before reset
  └─ Checksum: Calculated for TCP segment
```

**Why Inject RST to Both Ends:**
- TCP connections are bidirectional (both sides maintain state)
- If only client receives RST: client stops, but server keeps retransmitting
- If both receive RST: clean termination, no stale connections

**Network Perspective:**
- User's browser tries to connect to facebook.com (157.240.0.35:443)
- Three-way handshake begins (SYN sent)
- Firewall intercepts SYN packet
- Firewall matches DENY rule for facebook.com
- Firewall injects RST to browser: "Connection refused by server"
- Browser immediately displays error (not a 30s timeout)
- User sees instant feedback (faster than DROP timeout)

**Use Cases:**
- Blocking social media during work hours - fast feedback to user
- Blocking specific applications (gaming, P2P) - immediate termination
- Enforcing acceptable use policies - users know it's blocked (not a network issue)
- Blocking by domain (facebook.com, twitter.com) with DNS/SNI inspection

**Performance:**
- RST injection latency: <500μs (microseconds)
- SafeOps handles low-level packet crafting (firewall just calls API)
- No need to track TCP state (stateless injection works)
- Scales to 100K+ connections/sec

**Limitations:**
- Only works for TCP (UDP has no concept of RST)
- Requires valid sequence number (SafeOps tracks connection state)
- Can be detected by IDS (injected packets have different TTL/fingerprint)

---

**4. DNS Redirect Handler (REDIRECT Verdict)**

**Purpose:** Spoof DNS responses to redirect blocked domains to captive portal

**How It Works:**
When a DNS query (UDP port 53) matches a REDIRECT rule, the firewall intercepts the query and injects a fake DNS response BEFORE the real DNS server can respond. The fake response contains the captive portal IP instead of the real domain IP.

**DNS Query Flow (Normal):**
```
User's Browser
  ↓ (Query: What is facebook.com's IP?)
DNS Resolver (8.8.8.8)
  ↓ (Response: 157.240.0.35)
User's Browser
  ↓ (Connect to 157.240.0.35:443)
Facebook Server
```

**DNS Query Flow (Redirected):**
```
User's Browser
  ↓ (Query: What is facebook.com's IP?)
Firewall Intercepts Query
  ↓ (Inject fake response: 192.168.1.1)
User's Browser
  ↓ (Connect to 192.168.1.1:443)
Captive Portal (Block Page)
  ↓ (Display: "This site is blocked by IT policy")
```

**Fake DNS Response Structure (Conceptual):**
```
DNS Header:
  ├─ Transaction ID: (copied from original query - must match)
  ├─ Flags: Response (0x8180) - authoritative answer
  ├─ Questions: 1 (echo original question)
  ├─ Answers: 1 (fake answer)
  └─ Authority/Additional: 0

DNS Question (Echo):
  ├─ Name: facebook.com (copied from query)
  ├─ Type: A (IPv4 address query)
  └─ Class: IN (Internet)

DNS Answer (Fake):
  ├─ Name: facebook.com
  ├─ Type: A
  ├─ Class: IN
  ├─ TTL: 60 seconds (short TTL - don't cache long)
  └─ Data: 192.168.1.1 (captive portal IP)
```

**Critical Details:**
- **Transaction ID Must Match:** DNS clients reject responses with wrong transaction ID (prevents spoofing)
- **Response Must Arrive First:** If real DNS response arrives before fake, browser uses real IP
- **SafeOps Timing Advantage:** Kernel-level injection is faster than network round-trip to real DNS server
- **TTL = 60s:** Short TTL prevents long-term caching (if rule changes, takes effect in 60s)

**Network Perspective:**
- User types "gambling.com" in browser
- Browser sends DNS query to 8.8.8.8 (Google DNS)
- Firewall intercepts query at kernel level (NDIS driver)
- Firewall crafts fake DNS response: "gambling.com = 192.168.1.1"
- Fake response arrives in <1ms (kernel injection is fast)
- Real response arrives in 10-50ms (network round-trip)
- Browser accepts first response (fake one)
- Browser connects to 192.168.1.1 (captive portal)
- Captive portal displays block page: "This site violates company policy"

**Use Cases:**
- Blocking gambling websites with user-friendly block page
- Blocking adult content with warning message
- Blocking malware domains with security warning
- Device authentication workflow (redirect to certificate install page)
- Guest network captive portal (redirect to login page)

**Performance:**
- DNS response injection: <1ms latency
- User sees redirect immediately (no timeout delay)
- Faster than DROP (30s timeout) or DENY (connection refused)
- Better user experience (block page explains why blocked)

**Limitations:**
- Only works for DNS queries (port 53 UDP)
- Doesn't work for hardcoded IPs (e.g., 8.8.8.8 instead of google.com)
- Doesn't work for DNS over HTTPS (DoH) - encrypted DNS queries
- Doesn't work for DNS over TLS (DoT) - encrypted DNS queries

---

**5. ICMP Unreachable Handler (REJECT Verdict)**

**Purpose:** Politely reject packets with ICMP Destination Unreachable message

**How It Works:**
When a packet matches a REJECT rule, the firewall sends an ICMP Type 3 (Destination Unreachable) message to the sender. This is the "polite" way to reject traffic - it tells the sender "I received your packet, but I'm not allowed to forward it."

**ICMP Unreachable Message Types:**
```
Type 3 (Destination Unreachable):
  ├─ Code 0: Network unreachable (routing issue)
  ├─ Code 1: Host unreachable (host is down)
  ├─ Code 3: Port unreachable (service not running)
  ├─ Code 9: Network administratively prohibited (firewall block - CISCO)
  └─ Code 13: Communication administratively prohibited (firewall block - RFC 1812)
```

**Firewall Uses Code 13:** "Communication administratively prohibited by filtering"

**ICMP Message Structure (Conceptual):**
```
Ethernet Header:
  ├─ Source MAC: Gateway MAC
  ├─ Dest MAC: Client MAC
  └─ EtherType: IPv4

IP Header:
  ├─ Source IP: Gateway IP (firewall IP)
  ├─ Dest IP: Client IP (original sender)
  ├─ Protocol: ICMP (1)
  └─ TTL: 64

ICMP Header:
  ├─ Type: 3 (Destination Unreachable)
  ├─ Code: 13 (Administratively prohibited)
  ├─ Checksum: Calculated
  └─ Unused: 0

ICMP Payload:
  └─ Original IP header + first 8 bytes of original payload
     (allows client to match ICMP to original packet)
```

**Network Perspective:**
- Client sends packet to blocked destination
- Firewall matches REJECT rule
- Firewall sends ICMP unreachable to client
- Client receives ICMP message immediately (<200μs)
- Client knows packet was rejected by firewall (not a network failure)
- Application receives error: "Connection refused" or "Network unreachable"

**REJECT vs DROP vs DENY:**
```
REJECT (ICMP):
  ├─ User Experience: Instant error message
  ├─ Attacker Visibility: Knows firewall exists
  ├─ Compliance: RFC 1122 compliant (polite rejection)
  └─ Use Case: Enterprise policy enforcement (let users know it's blocked)

DROP (Silent):
  ├─ User Experience: 30-second timeout
  ├─ Attacker Visibility: Can't tell if firewall exists
  ├─ Compliance: Violates RFC (should send ICMP)
  └─ Use Case: Blocking malware (don't alert attacker)

DENY (TCP RST):
  ├─ User Experience: Instant "Connection refused"
  ├─ Attacker Visibility: Knows something terminated connection
  ├─ Compliance: Valid TCP behavior
  └─ Use Case: Blocking TCP connections (faster than timeout)
```

**Use Cases:**
- Enterprise policy enforcement (users should know it's blocked, not a network issue)
- Debugging (faster feedback than DROP timeout)
- RFC compliance (polite rejection as per internet standards)
- Transparent firewalling (users aware of filtering)

**Performance:**
- ICMP injection: <200μs latency
- No connection tracking needed (stateless)
- Minimal CPU overhead (simple ICMP message)

**Limitations:**
- Reveals firewall presence to attackers
- Can be used for network mapping (attacker probes filtered ports)
- Some OSes ignore ICMP unreachable (security hardening)

---

#### Files to Create:
```
internal/enforcement/
├── verdict_handler.go       # Main enforcement orchestrator (routes verdicts)
├── drop.go                  # Silent drop (kernel blocklist)
├── tcp_rst.go               # TCP RST injection (active termination)
├── dns_redirect.go          # DNS spoofing (captive portal)
├── icmp_reject.go           # ICMP unreachable (polite rejection)
├── packet_injector.go       # Low-level packet crafting utilities (if needed)
└── action_executor.go       # Execute rule-specific actions
```

---

### Sub-Task 3.2: Connection Tracking (`internal/connection/`)

**Purpose:** Track TCP connection states for stateful inspection

**Core Concept:**
Modern firewalls are **stateful** - they remember connections and track their lifecycle (NEW → ESTABLISHED → CLOSING → CLOSED). This enables powerful rules like "Allow ESTABLISHED connections" (allow responses to outbound requests) and prevents attacks like TCP SYN floods (reject unsolicited inbound SYN packets).

---

#### What to Track:

**1. Connection State Tracker**

**Purpose:** Maintain a table of all active network connections

**Core Data Structure:**
Imagine a massive table where each row represents one active connection:
```
5-Tuple Key         | State       | First Seen  | Last Seen   | Pkts In | Pkts Out | Bytes In | Bytes Out
--------------------+-------------+-------------+-------------+---------+----------+----------+----------
192.168.1.100:54321 | ESTABLISHED | 10:00:00    | 10:00:15    | 150     | 120      | 50KB     | 80KB
→8.8.8.8:443-TCP    |             |             |             |         |          |          |
--------------------+-------------+-------------+-------------+---------+----------+----------+----------
192.168.1.100:61234 | NEW         | 10:00:10    | 10:00:10    | 1       | 0        | 60B      | 0B
→157.240.0.35:443   |             |             |             |         |          |          |
-TCP                |             |             |             |         |          |          |
```

**5-Tuple Key (Unique Connection Identifier):**
- Source IP (192.168.1.100)
- Destination IP (8.8.8.8)
- Source Port (54321)
- Destination Port (443)
- Protocol (TCP/UDP/ICMP)

Combined into a hash key: `192.168.1.100:54321-8.8.8.8:443-TCP`

**Connection States:**
```
NEW:
  ├─ First packet of connection (SYN for TCP)
  ├─ No previous packets seen
  └─ Triggers: First SYN packet

ESTABLISHED:
  ├─ Connection setup complete (SYN-ACK received for TCP)
  ├─ Data is flowing
  └─ Triggers: SYN-ACK, ACK, or data packet

RELATED:
  ├─ Related to existing connection (e.g., FTP data channel)
  ├─ Spawned from ESTABLISHED connection
  └─ Triggers: Protocol-specific (FTP PORT command creates RELATED connection)

CLOSING:
  ├─ Connection terminating (FIN or RST seen)
  ├─ Waiting for final ACK
  └─ Triggers: FIN or RST packet

CLOSED:
  ├─ Connection fully terminated
  ├─ Removed from table after timeout
  └─ Triggers: Final ACK or timeout

INVALID:
  ├─ Malformed packet (bad checksum, invalid flags)
  ├─ Out-of-window packet (sequence number outside expected range)
  └─ Triggers: Protocol violations
```

**Thread Safety:**
Connection table is accessed by multiple worker goroutines simultaneously. Use `sync.Map` (Go's built-in concurrent map) for lock-free reads and writes.

**Automatic Cleanup:**
Background goroutine runs every 30 seconds:
1. Iterate through all connections
2. Check if `time.Now() > LastSeen + Timeout`
3. If timed out: Remove from table
4. Log: "Cleaned up N expired connections"

**Why This Matters:**
Without connection tracking, firewall can't tell:
- Is this packet part of an existing connection (ESTABLISHED)?
- Is this a new connection attempt (NEW)?
- Is this connection related to another (RELATED)?

Result: Can't implement stateful rules like "Allow ESTABLISHED, Deny NEW inbound"

---

**2. TCP State Machine**

**Purpose:** Track TCP connection lifecycle through handshake, data transfer, and termination

**TCP Handshake (3-Way):**
```
Client                           Server
  |                                 |
  |------ SYN (seq=100) ----------->|  (State: SYN_SENT)
  |                                 |
  |<-- SYN-ACK (seq=300, ack=101) --|  (State: SYN_RECEIVED)
  |                                 |
  |------ ACK (seq=101, ack=301) -->|  (State: ESTABLISHED)
  |                                 |
  |<====== DATA EXCHANGE ==========>|  (State: ESTABLISHED)
  |                                 |
```

**TCP Termination (4-Way Close):**
```
Client                           Server
  |                                 |
  |------ FIN (seq=500) ----------->|  (State: FIN_WAIT_1)
  |                                 |
  |<------ ACK (ack=501) -----------|  (State: FIN_WAIT_2)
  |                                 |
  |<------ FIN (seq=800) -----------|  (State: CLOSING)
  |                                 |
  |------ ACK (ack=801) ----------->|  (State: TIME_WAIT)
  |                                 |
  [Wait 60 seconds - 2×MSL]         |
  |                                 |
  (State: CLOSED)                   |
```

**TCP State Transitions:**
```
CLOSED → SYN_SENT (send SYN)
SYN_SENT → SYN_RECEIVED (receive SYN-ACK)
SYN_RECEIVED → ESTABLISHED (receive ACK)
ESTABLISHED → FIN_WAIT_1 (send FIN)
FIN_WAIT_1 → FIN_WAIT_2 (receive ACK)
FIN_WAIT_2 → TIME_WAIT (receive FIN)
TIME_WAIT → CLOSED (timeout 60s)
```

**RST (Reset) Handling:**
Any state + RST → CLOSED immediately (abort connection)

**Why Track TCP State:**
1. **Detect SYN Floods:** Too many SYN_SENT states → attacker sending SYNs without completing handshake
2. **Prevent Half-Open Attacks:** Reject packets to connections that were never ESTABLISHED
3. **Enable Stateful Rules:** "Allow ESTABLISHED" only allows packets to completed connections
4. **Flow Statistics:** Track connection duration, bytes transferred, etc.

---

**3. Flow Statistics**

**Purpose:** Track per-connection metrics for monitoring and anomaly detection

**Per-Connection Metrics:**
```
Connection: 192.168.1.100:54321 → 8.8.8.8:443 (TCP)
├─ Total Packets: 270 (150 inbound, 120 outbound)
├─ Total Bytes: 130KB (50KB inbound, 80KB outbound)
├─ Duration: 15 seconds (10:00:00 → 10:00:15)
├─ Packets/Sec: 18 pps
├─ Bytes/Sec: 8.67 KB/s
├─ Avg Packet Size: 481 bytes
├─ Retransmissions: 0
├─ Out-of-Order Packets: 0
└─ Window Size: 65535 bytes
```

**Why Track Flow Statistics:**
1. **Top Talkers:** Which connections are using most bandwidth?
2. **Anomaly Detection:** Is this connection normal or malicious?
   - 10,000 pps to one IP → DDoS attack
   - 1 packet every 60s → C2 beacon (malware check-in)
   - Retransmissions >10% → network congestion or attack
3. **Capacity Planning:** How much bandwidth do we need?
4. **Billing:** Track usage per user/device for ISP billing
5. **Forensics:** "What connections did this IP make during the attack?"

**Flow Aggregation Example:**
```
Top 10 Connections by Bytes (Last 5 Minutes):
1. 192.168.1.100:54321 → 172.217.0.46:443 (Google) - 150MB (HTTPS video streaming)
2. 192.168.1.105:61234 → 157.240.0.35:443 (Facebook) - 80MB (HTTPS social media)
3. 192.168.1.110:52000 → 185.220.101.50:80 (Malware C2) - 5KB (BLOCKED by firewall)
```

---

**4. Connection Timeout Management**

**Purpose:** Remove stale connections from the table to prevent memory exhaustion

**Timeout Values (Configurable):**
```
Protocol | State       | Timeout | Reason
---------+-------------+---------+---------------------------------------
TCP      | ESTABLISHED | 3600s   | Long-lived connections (file transfers, SSH)
TCP      | SYN_SENT    | 30s     | If no SYN-ACK, connection failed
TCP      | FIN_WAIT    | 30s     | Waiting for final ACK (should be quick)
TCP      | TIME_WAIT   | 60s     | 2×MSL (Maximum Segment Lifetime)
UDP      | Any         | 60s     | No connection state, expire after idle
ICMP     | Any         | 10s     | Ping/traceroute, short-lived
```

**Cleanup Process:**
```
Every 30 seconds:
1. Iterate all connections in table
2. For each connection:
   a. Calculate idle_time = now - last_seen
   b. If idle_time > timeout:
      - Remove from table
      - Free memory
      - Log: "Connection expired: 192.168.1.100:54321 → 8.8.8.8:443"
3. Log: "Cleaned up N expired connections"
```

**Why Timeout Matters:**
Without timeouts, connection table grows indefinitely:
- 100K new connections/day
- After 1 year: 36M connections in table
- Memory: 36M × 200 bytes = 7.2GB RAM
- Lookup time: O(n) = 36M lookups → firewall unusable

With timeouts (60s average):
- Max connections: 100K connections/sec × 60s = 6M concurrent
- Memory: 6M × 200 bytes = 1.2GB RAM
- Lookup time: O(1) hash table → fast

---

**5. Connection Table Implementation**

**Purpose:** High-performance data structure for storing millions of connections

**Why sync.Map:**
Go's `sync.Map` is optimized for:
- **Read-Heavy Workloads:** 80% of operations are lookups (checking if connection exists)
- **Concurrent Access:** Multiple worker goroutines accessing simultaneously
- **Low Lock Contention:** Lock-free reads when key exists (fast path)

**Alternative Considered: RWMutex + map[string]*Connection:**
- Problem: Lock contention when many goroutines reading/writing
- Result: Serializes access, destroys parallelism
- Performance: 10x slower than sync.Map

**Hash Key Generation:**
```
Packet: 192.168.1.100:54321 → 8.8.8.8:443 (TCP)
Hash Key: "192.168.1.100:54321-8.8.8.8:443-TCP"
```

**Collision Handling:**
Hash table uses Go's built-in map hashing (no collisions for different keys)

**Capacity Planning:**
```
Scenario: ISP with 10,000 users
├─ Average 100 connections/user
├─ Total connections: 1,000,000
├─ Memory per connection: 200 bytes
└─ Total memory: 200MB (acceptable)

Scenario: Enterprise with 1,000 users
├─ Average 50 connections/user
├─ Total connections: 50,000
├─ Memory per connection: 200 bytes
└─ Total memory: 10MB (negligible)
```

---

#### Files to Create:
```
internal/connection/
├── tracker.go           # Connection state tracker (main table management)
├── state.go             # TCP state machine (state transitions)
├── flow.go              # Flow statistics calculation (metrics)
├── timeout.go           # Connection timeout management (cleanup logic)
└── table.go             # High-performance sync.Map wrapper
```

---

### Sub-Task 3.3: Packet Inspector (`internal/inspector/`)

**Purpose:** Main packet processing loop - orchestrates inspection, matching, and enforcement

**Core Concept:**
The inspector is the "brain coordinator" - it receives packets from SafeOps, checks the cache, updates connection state, matches rules, enforces verdicts, and updates statistics. It's the main event loop that ties all Phase 2 and Phase 3 components together.

---

#### What to Create:

**1. Packet Inspector (Main Inspection Flow)**

**Purpose:** Process each packet through the complete inspection pipeline

**Inspection Pipeline (Step-by-Step):**
```
1. Receive Packet Metadata from SafeOps gRPC stream
   ├─ Extract: src IP, dst IP, src port, dst port, protocol, TCP flags, domain
   └─ Validate: packet not malformed (checksum valid, flags valid)

2. Check Verdict Cache (Fast Path)
   ├─ Generate cache key: "192.168.1.100:54321-8.8.8.8:443-TCP"
   ├─ Lookup in cache (O(1) hash table)
   ├─ HIT: Return cached verdict (skip steps 3-5) → ~10μs latency
   └─ MISS: Continue to step 3 → ~50μs latency

3. Update Connection State
   ├─ Generate 5-tuple key
   ├─ Lookup connection in table
   ├─ If exists: Update (last_seen, packet_count, byte_count, TCP_state)
   ├─ If new: Create connection (state=NEW)
   └─ Determine connection state: NEW, ESTABLISHED, CLOSING, etc.

4. Check Fast-Path Rules (Common Cases)
   ├─ Is this DNS query (port 53)? → ALLOW (fast-path)
   ├─ Is this ESTABLISHED connection to trusted IP? → ALLOW (fast-path)
   ├─ Is this packet to known-malware IP? → DROP (blocklist lookup)
   ├─ Fast-path HIT: Return verdict, skip full rule matching
   └─ Fast-path MISS: Continue to full rule matching

5. Match Against Firewall Rules (Phase 2 Engine)
   ├─ Call rule matcher: Match(packet)
   ├─ Rules sorted by priority (highest first)
   ├─ First-match-wins: Return immediately on match
   ├─ If no match: Return default policy (ALLOW or DENY)
   └─ Result: (verdict, matched_rule, reason)

6. Cache Verdict (for future packets)
   ├─ Store in cache: key → (verdict, expiry_time)
   ├─ TTL: 60 seconds (configurable)
   └─ LRU eviction if cache full

7. Enforce Verdict (Phase 3 Engine)
   ├─ Call enforcement engine: Enforce(verdict, packet, rule)
   ├─ ALLOW: No action (return immediately)
   ├─ DROP: Call SafeOps BlockIP()
   ├─ DENY: Call SafeOps SendTCPReset()
   ├─ REDIRECT: Call SafeOps InjectDNSResponse()
   └─ Handle errors: Retry 3x, log failure, continue

8. Update Statistics
   ├─ Increment packet counter (total_packets++)
   ├─ Increment verdict counter (allow_count++ or deny_count++)
   ├─ Update rule hit counter (rule.hit_count++)
   ├─ Update cache stats (cache_hits++ or cache_misses++)
   └─ Export to Prometheus metrics

9. Log Enforcement Action
   ├─ Write to firewall.log:
   │   {
   │     "timestamp": "2026-01-22T10:00:15Z",
   │     "src_ip": "192.168.1.100",
   │     "dst_ip": "157.240.0.35",
   │     "verdict": "DENY",
   │     "rule": "Block_Facebook",
   │     "reason": "Policy violation"
   │   }
   └─ Optionally forward to SIEM (existing forwarder)

10. Return Control (Next Packet)
    └─ Inspector ready for next packet from stream
```

**Performance Characteristics:**
```
Cache HIT (80% of traffic):
  ├─ Steps executed: 1, 2 (cache lookup), 7 (enforcement), 8-10
  ├─ Latency: ~10-15μs
  └─ Throughput: 100K+ pps

Cache MISS (20% of traffic):
  ├─ Steps executed: All 10 steps
  ├─ Latency: ~50-60μs
  └─ Throughput: 20K pps (but infrequent)

Overall throughput: 0.8 × 100K + 0.2 × 20K = 84K pps average
```

---

**2. Fast-Path Optimization**

**Purpose:** Skip expensive rule matching for common traffic patterns

**What is Fast-Path:**
Most network traffic is repetitive:
- 80% of packets are established connections (ACK packets)
- 10% are DNS queries (always allowed)
- 5% are HTTPS to known-good sites (Google, Microsoft)
- 5% are new/suspicious (require full inspection)

Fast-path: Detect common patterns and return verdict immediately (without rule matching)

**Fast-Path Checks (in order):**
```
1. Blocklist Check (Malware IPs)
   ├─ Hash table: known_malware_ips = {"185.220.101.50": true, ...}
   ├─ Lookup: O(1) constant time
   ├─ HIT: Return DROP verdict (skip all rules)
   └─ MISS: Continue

2. DNS Allow-All (Port 53 UDP)
   ├─ If dst_port == 53 and protocol == UDP:
   └─ Return ALLOW (DNS always allowed, unless specific REDIRECT rule)

3. Established Connection Whitelist
   ├─ Hash table: trusted_established = {("8.8.8.8", ESTABLISHED): true, ...}
   ├─ If connection_state == ESTABLISHED and dst_ip in trusted_ips:
   └─ Return ALLOW (trusted established connections bypass rules)

4. Common Web Ports to Trusted IPs
   ├─ If dst_port in [80, 443] and dst_ip in CDN_ips:
   └─ Return ALLOW (HTTPS to Cloudflare/Akamai/Google always allowed)

5. Fallback to Full Rule Matching
   └─ No fast-path match, run full rule engine (Phase 2)
```

**Performance Impact:**
```
Without Fast-Path:
  ├─ Every packet runs full rule matching (50μs)
  ├─ Throughput: 20K pps
  └─ Latency: 50μs average

With Fast-Path (80% hit rate):
  ├─ 80% of packets: Fast-path (5μs)
  ├─ 20% of packets: Full matching (50μs)
  ├─ Average latency: 0.8 × 5μs + 0.2 × 50μs = 14μs
  └─ Throughput: 71K pps (3.5x improvement)
```

---

**3. Metadata Stream Handler**

**Purpose:** Subscribe to SafeOps gRPC stream and feed packets to worker pool

**How It Works:**
```
SafeOps gRPC Server (127.0.0.1:50053)
       ↓ (bidirectional stream)
gRPC Client (Metadata Stream Handler)
       ↓ (infinite loop: receive packets)
Packet Channel (buffered, 10,000 capacity)
       ↓ (channel acts as queue)
Worker Pool (8 goroutines)
       ↓ (each worker processes packets independently)
Packet Inspector (per-packet processing)
```

**Infinite Loop (Pseudo-Algorithm):**
```
Connect to SafeOps gRPC stream
while true:
    packet = stream.Receive()  // Blocking call, waits for next packet

    if packet == nil:
        // Stream ended (SafeOps disconnected)
        log.Error("Stream disconnected, reconnecting...")
        sleep(1 second)
        reconnect()
        continue

    // Send packet to worker pool (non-blocking if channel has space)
    select {
        case packetChannel <- packet:
            // Success, packet queued
        default:
            // Channel full (backlog > 10,000 packets)
            stats.dropped_packets++
            log.Warn("Worker pool backlog full, dropped packet")
    }
```

**Error Handling:**
- **Stream Disconnect:** Reconnect with exponential backoff (1s, 2s, 4s, 8s, max 60s)
- **Channel Full:** Drop packet and increment dropped_packets counter (fail-open)
- **Malformed Packet:** Log error, skip packet, continue processing

**Why Buffered Channel:**
Packets arrive in bursts (100K packets in 1 second = 100K pps burst). Buffered channel absorbs bursts without blocking gRPC stream.

---

**4. Worker Pool**

**Purpose:** Parallel packet processing to maximize CPU utilization

**Why Worker Pool:**
Single-threaded processing:
- 1 thread: 20K pps (limited by CPU core)
- Wasted CPU: 7 idle cores (0% usage)

Multi-threaded worker pool (8 workers):
- 8 threads: 160K pps (8 × 20K)
- CPU utilization: 100% (all cores busy)

**Worker Pool Architecture:**
```
Main Thread (Stream Handler)
       ↓
Packet Channel (queue)
       ↓
    ┌──┴──┐
    ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓
Worker Worker Worker Worker Worker Worker Worker Worker
   1      2      3      4      5      6      7      8
    ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓
   (Each independently inspects packets)
    ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓
Verdict Enforcement (SafeOps API calls)
```

**Worker Goroutine (Pseudo-Code):**
```
func worker(id int, packetChannel chan *Packet) {
    log.Infof("Worker %d started", id)

    for packet := range packetChannel {
        // Process packet through full inspection pipeline
        verdict, rule, reason := Inspect(packet)

        // Enforce verdict
        err := Enforce(verdict, packet, rule)
        if err != nil {
            log.Errorf("Worker %d: Enforcement failed: %v", id, err)
        }

        // Update statistics
        stats.UpdateStats(verdict, rule)

        // Log action
        logger.LogVerdict(packet, verdict, rule, reason)
    }

    log.Infof("Worker %d stopped", id)
}
```

**Concurrency Considerations:**
- **Thread-Safe Cache:** sync.Map for verdict cache (no locks needed)
- **Thread-Safe Connection Table:** sync.Map for connection tracking
- **Thread-Safe Statistics:** atomic.AddUint64 for counters
- **No Shared State:** Each worker operates independently (no data races)

**Configurable Worker Count:**
```
config.yaml:
  performance:
    worker_threads: 8  # Number of CPU cores
```

Adjust based on CPU cores:
- 4-core system: 4 workers
- 8-core system: 8 workers
- 16-core system: 16 workers

---

**5. Flow Inspector (Advanced)**

**Purpose:** Detect flow-level anomalies for intrusion detection

**What to Detect:**
1. **TCP Retransmissions:**
   - Normal: <1% retransmission rate
   - Suspicious: >10% retransmissions → network attack or congestion

2. **Out-of-Order Packets:**
   - Normal: Sequential sequence numbers (seq 100, 101, 102...)
   - Suspicious: Out-of-order (seq 100, 150, 101...) → packet injection attack

3. **Window Size Violations:**
   - Normal: Window size increases as data acknowledged
   - Suspicious: Window size = 0 (receiver overwhelmed) → DDoS attack

4. **Packet Rate Anomalies:**
   - Normal: 10-100 pps for web browsing
   - Suspicious: 10,000 pps to one IP → DDoS attack or port scan

5. **Flow Duration Anomalies:**
   - Normal: HTTP connections last 1-10 seconds
   - Suspicious: Connection open for 24 hours → backdoor or data exfiltration

**Feed into IDS/IPS (Future Phase 13):**
Flow anomalies logged and fed into machine learning intrusion detection system.

---

#### Files to Create:
```
internal/inspector/
├── packet_inspector.go  # Main inspection logic (pipeline orchestrator)
├── flow_inspector.go    # Flow-level inspection (anomaly detection)
├── fastpath.go          # Fast-path optimizations (bypass rule matching)
├── handler.go           # Metadata stream handler (gRPC subscription)
└── worker_pool.go       # Parallel worker pool (multi-threading)
```

---

### Sub-Task 3.4: Verdict Caching (`internal/cache/`)

**Purpose:** Cache verdict decisions to avoid re-evaluating identical flows

**Core Concept:**
Network traffic is highly repetitive. A user browsing google.com sends 1,000 packets to the same IP:port. Without caching, the firewall re-evaluates all 1,000 packets against all rules (expensive). With caching, only the first packet is evaluated; the next 999 use the cached verdict (100x faster).

---

#### What to Create:

**1. LRU Verdict Cache**

**Purpose:** Store recent verdicts with automatic eviction of old entries

**LRU (Least Recently Used) Algorithm:**
```
Cache Capacity: 100,000 entries

Scenario: Cache is full (100,000 entries)
New packet arrives: 192.168.1.100:99999 → 8.8.8.8:443

Question: Which cached entry do we evict to make room?
Answer: The LEAST RECENTLY USED entry (oldest access time)

Why LRU:
  ├─ Most recently used entries = active connections (likely to repeat)
  ├─ Least recently used entries = stale connections (not needed anymore)
  └─ Result: Keep hot cache, evict cold cache
```

**LRU Data Structure:**
```
Doubly-Linked List (LRU ordering):
  ┌─────────────────────────────────────────────────────┐
  │ [Most Recent] ← → [Entry 2] ← → ... ← → [Least Recent] │
  └─────────────────────────────────────────────────────┘
        ↑                                         ↑
      HEAD                                      TAIL
   (newest access)                         (oldest access)

Hash Map (O(1) lookup):
  key: "192.168.1.100:54321-8.8.8.8:443-TCP"
  value: pointer to entry in linked list
```

**Cache Operations:**
```
GET (lookup):
  1. Hash key → lookup in map (O(1))
  2. If found:
     a. Move entry to front of list (most recent)
     b. Return cached verdict
  3. If not found:
     a. Return MISS

PUT (insert):
  1. If cache full (size == capacity):
     a. Evict entry at TAIL (least recently used)
     b. Remove from map
  2. Create new entry
  3. Insert at HEAD (most recent)
  4. Add to map

INVALIDATE (clear):
  1. Clear map
  2. Reset linked list
  3. Reset stats
```

**Performance:**
- Lookup: O(1) constant time
- Insert: O(1) constant time
- Eviction: O(1) constant time
- Memory: 100K entries × 100 bytes = 10MB

---

**2. TTL (Time-To-Live) Expiration**

**Purpose:** Automatically expire cached verdicts after a timeout

**Why TTL:**
Rules can change (hot-reload). Without TTL:
- Admin blocks facebook.com at 10:00 AM
- Cached verdict from 9:59 AM says "ALLOW facebook.com"
- User continues accessing facebook.com for hours (stale cache)

With TTL (60 seconds):
- Admin blocks facebook.com at 10:00 AM
- Cached verdict expires at 10:01 AM (60s later)
- Next packet at 10:01 AM: cache MISS → re-evaluate → DENY
- Result: Rule change takes effect within 60 seconds

**TTL Values (Configurable):**
```
Verdict  | TTL  | Reason
---------+------+-----------------------------------------------
ALLOW    | 60s  | Allow decisions stable (rules rarely change)
DROP     | 300s | Drop persistent (malware IPs stay blocked long-term)
DENY     | 60s  | Deny decisions may change (user appeals block)
REDIRECT | 30s  | Captive portal may change (shorter TTL)
```

**TTL Data Structure:**
```
Cache Entry:
  ├─ Key: "192.168.1.100:54321-8.8.8.8:443-TCP"
  ├─ Verdict: ALLOW
  ├─ Created: 10:00:00
  ├─ TTL: 60s
  └─ Expiry: 10:01:00 (created + TTL)
```

**Background Cleanup (Every 10 Seconds):**
```
for each entry in cache:
    if time.Now() > entry.Expiry:
        remove entry from cache
        stats.expired_entries++

log.Info("Expired N cache entries")
```

---

**3. Cache Statistics**

**Purpose:** Monitor cache performance and hit rate

**Key Metrics:**
```
Total Requests: 1,000,000 packets
Cache Hits: 820,000 (verdict found in cache)
Cache Misses: 180,000 (verdict not in cache, ran rule matching)
Hit Rate: 82% (hits / total)
Current Size: 95,000 entries (out of 100,000 capacity)
Evictions: 15,000 (entries evicted due to full cache)
Expirations: 5,000 (entries expired due to TTL)
Average Lookup Time: 8μs
```

**Hit Rate Interpretation:**
```
Hit Rate | Meaning
---------+----------------------------------------------------------
>90%     | Excellent (highly repetitive traffic, cache very effective)
70-90%   | Good (normal enterprise traffic)
50-70%   | Fair (diverse traffic, increase cache size)
<50%     | Poor (cache size too small or TTL too short)
```

**Prometheus Metrics Export:**
```
# HELP firewall_cache_hit_rate Percentage of cache hits
# TYPE firewall_cache_hit_rate gauge
firewall_cache_hit_rate 0.82

# HELP firewall_cache_size Current number of cached entries
# TYPE firewall_cache_size gauge
firewall_cache_size 95000

# HELP firewall_cache_lookups_total Total number of cache lookups
# TYPE firewall_cache_lookups_total counter
firewall_cache_lookups_total 1000000
```

---

**4. Cache Invalidation**

**Purpose:** Clear cache when rules change (hot-reload)

**When to Invalidate:**
1. **Hot-Reload:** User edits firewall.toml and saves
2. **Rule Changes:** New rule added, existing rule modified, rule deleted
3. **Object Changes:** Address object updated (e.g., RFC1918 CIDR list changed)
4. **Manual Command:** Admin runs: `firewall-cli cache clear`

**Invalidation Strategies:**
```
1. Full Invalidation (Safest):
   ├─ Clear entire cache (all 100K entries)
   ├─ Pros: Guarantees no stale verdicts
   ├─ Cons: Cache cold-start (100% miss rate for ~60s)
   └─ Use case: Major rule changes

2. Selective Invalidation by IP:
   ├─ Clear only entries matching specific IP
   ├─ Example: Invalidate all "192.168.1.100:*" entries
   ├─ Pros: Preserves most cache
   ├─ Cons: Requires iterating cache (slower)
   └─ Use case: Blocking specific user/device

3. Selective Invalidation by Rule:
   ├─ Track which rule matched each cached verdict
   ├─ When rule changes: Clear only entries matched by that rule
   ├─ Pros: Minimal cache disruption
   ├─ Cons: Complex bookkeeping
   └─ Use case: Tweaking single rule (e.g., change priority)
```

**Implementation Choice: Full Invalidation**
- Simplest to implement
- Safest (no stale verdicts)
- Cache refills in 60 seconds (acceptable downtime)

---

**5. Performance Impact Analysis**

**Scenario 1: No Cache (Baseline)**
```
All packets: Full rule matching (50μs)
Throughput: 20,000 pps
Latency: 50μs average
```

**Scenario 2: With Cache (80% hit rate)**
```
80% packets: Cache hit (10μs)
20% packets: Cache miss + rule matching (55μs)
Average latency: 0.8 × 10μs + 0.2 × 55μs = 19μs
Throughput: 52,000 pps (2.6x improvement)
```

**Scenario 3: With Cache + Fast-Path (80% cache + 15% fast-path)**
```
80% packets: Cache hit (10μs)
15% packets: Fast-path (5μs)
5% packets: Full matching (50μs)
Average latency: 0.8 × 10μs + 0.15 × 5μs + 0.05 × 50μs = 11.25μs
Throughput: 88,000 pps (4.4x improvement)
```

**Conclusion: Caching is Critical**
Without caching, firewall cannot achieve 100K pps performance target.

---

#### Files to Create:
```
internal/cache/
├── verdict_cache.go     # Main cache interface (LRU + TTL)
├── lru.go               # LRU algorithm implementation (doubly-linked list + hash map)
├── ttl.go               # TTL expiration logic (background cleanup)
├── stats.go             # Cache statistics tracking (hit rate, evictions)
└── invalidation.go      # Cache invalidation strategies (full, selective)
```

---

### Sub-Task 3.5: Testing & Validation

**Purpose:** Verify verdict enforcement works correctly in production

**Core Concept:**
Testing ensures the firewall actually blocks malicious traffic without breaking legitimate traffic. Each test scenario validates one enforcement mechanism (DROP, DENY, REDIRECT, etc.) in isolation.

---

#### Test Scenarios:

**1. ALLOW Verdict Test**

**Setup:**
```
Create rule in firewall.toml:
[[rule]]
name = "Allow_Google_DNS"
action = "ALLOW"
protocol = "UDP"
dst_address = "8.8.8.8"
dst_port = 53
priority = 100
```

**Test Execution:**
```
Command: nslookup google.com 8.8.8.8
Expected Behavior:
  ├─ DNS query sent to 8.8.8.8:53
  ├─ Firewall matches "Allow_Google_DNS" rule
  ├─ Verdict: ALLOW
  ├─ Enforcement: No action (packet forwarded normally)
  └─ Result: DNS query succeeds, returns Google's IP
```

**Console Output:**
```
[INFO] Packet: 192.168.1.100:54123 -> 8.8.8.8:53 UDP [ALLOW] Rule: Allow_Google_DNS
[INFO] Verdict: ALLOW → No enforcement action taken
```

**Success Criteria:**
- ✅ DNS query succeeds
- ✅ Response received within 50ms
- ✅ No errors in firewall log

---

**2. DROP Verdict Test**

**Setup:**
```
Create rule in firewall.toml:
[[rule]]
name = "Drop_Malware_IP"
action = "DROP"
protocol = "ANY"
dst_address = "185.220.101.50"
priority = 50
```

**Test Execution:**
```
Command: ping 185.220.101.50
Expected Behavior:
  ├─ ICMP packet sent to 185.220.101.50
  ├─ Firewall matches "Drop_Malware_IP" rule
  ├─ Verdict: DROP
  ├─ Enforcement: Add 185.220.101.50 to kernel blocklist
  ├─ Result: Packet silently discarded
  └─ User sees: Request timeout after 30 seconds
```

**Console Output:**
```
[INFO] Packet: 192.168.1.100:0 -> 185.220.101.50:0 ICMP [DROP] Rule: Drop_Malware_IP
[WARN] Verdict: DROP → Adding 185.220.101.50 to kernel blocklist
[INFO] Enforcement: IP blocked successfully
```

**Success Criteria:**
- ✅ No ICMP reply received
- ✅ Timeout after 30 seconds
- ✅ No "Connection refused" error (silent drop)
- ✅ Kernel blocklist contains 185.220.101.50 (verify with SafeOps API)

---

**3. DENY Verdict Test (TCP RST)**

**Setup:**
```
Create rule in firewall.toml:
[[rule]]
name = "Deny_Facebook"
action = "DENY"
protocol = "TCP"
dst_domain = "*.facebook.com"
dst_port = 443
priority = 100
```

**Test Execution:**
```
Command: curl https://www.facebook.com
Expected Behavior:
  ├─ DNS query: www.facebook.com → 157.240.0.35
  ├─ TCP SYN sent to 157.240.0.35:443
  ├─ Firewall matches "Deny_Facebook" rule
  ├─ Verdict: DENY
  ├─ Enforcement: Inject TCP RST to both client and server
  ├─ Result: Connection terminated immediately
  └─ User sees: "Connection refused" error (instant, not timeout)
```

**Console Output:**
```
[INFO] Packet: 192.168.1.100:54321 -> 157.240.0.35:443 TCP [DENY] Rule: Deny_Facebook
[WARN] Verdict: DENY → Injecting TCP RST to 157.240.0.35:443
[INFO] Enforcement: TCP RST sent to both endpoints
```

**Success Criteria:**
- ✅ Connection refused error (not timeout)
- ✅ Error occurs within 1 second (immediate rejection)
- ✅ No TCP handshake completes
- ✅ Wireshark shows RST packets sent

---

**4. REDIRECT Verdict Test (DNS Spoofing)**

**Setup:**
```
Create rule in firewall.toml:
[[rule]]
name = "Redirect_Gambling_Sites"
action = "REDIRECT"
protocol = "UDP"
dst_port = 53
dst_domain = "gambling.com"
redirect_ip = "192.168.1.1"
priority = 100
```

**Test Execution:**
```
Command: nslookup gambling.com
Expected Behavior:
  ├─ DNS query sent to 8.8.8.8:53 for gambling.com
  ├─ Firewall intercepts DNS query
  ├─ Firewall matches "Redirect_Gambling_Sites" rule
  ├─ Verdict: REDIRECT
  ├─ Enforcement: Inject fake DNS response (gambling.com → 192.168.1.1)
  ├─ Fake response arrives before real response
  ├─ Browser connects to 192.168.1.1 (captive portal)
  └─ User sees: Block page "This site is prohibited by company policy"
```

**Console Output:**
```
[INFO] DNS Query: 192.168.1.100:54123 -> 8.8.8.8:53 UDP [REDIRECT] Rule: Redirect_Gambling_Sites
[WARN] Verdict: REDIRECT → Injecting fake DNS response for gambling.com
[INFO] Enforcement: DNS spoofed (fake IP: 192.168.1.1)
```

**Success Criteria:**
- ✅ nslookup returns 192.168.1.1 (not real gambling.com IP)
- ✅ Browser displays captive portal page
- ✅ Fake response arrives within 1ms (before real DNS)
- ✅ Wireshark shows two DNS responses (fake first, real second)

---

**5. Connection Tracking Test**

**Setup:**
```
Create rule in firewall.toml:
[[rule]]
name = "Allow_Established_Connections"
action = "ALLOW"
protocol = "TCP"
state = ["ESTABLISHED"]
priority = 1
```

**Test Execution:**
```
Command: curl https://google.com
Expected Behavior:
  ├─ Packet 1 (SYN): State = NEW → Cache MISS → Full rule matching
  ├─ Packet 2 (SYN-ACK): State = ESTABLISHED → Cache HIT → Fast verdict
  ├─ Packet 3-1000 (ACK, data): State = ESTABLISHED → Cache HIT → Fast verdict
  └─ Result: Only first packet runs full rule matching, rest cached
```

**Console Output:**
```
[INFO] Packet: 192.168.1.100:54321 -> 172.217.0.46:443 TCP [NEW] Rule: Allow_Established_Connections
[INFO] Verdict: ALLOW (Cache MISS - 50μs latency)
[INFO] Packet: 192.168.1.100:54321 -> 172.217.0.46:443 TCP [ESTABLISHED] Rule: Allow_Established_Connections
[INFO] Verdict: ALLOW (Cache HIT - 10μs latency)
[INFO] Packet: 192.168.1.100:54321 -> 172.217.0.46:443 TCP [ESTABLISHED] Rule: Allow_Established_Connections
[INFO] Verdict: ALLOW (Cache HIT - 10μs latency)
```

**Success Criteria:**
- ✅ First packet: Cache MISS (expected)
- ✅ Subsequent packets: Cache HIT (>99% hit rate)
- ✅ Connection state transitions: NEW → ESTABLISHED
- ✅ Connection appears in connection table (verify with API)

---

**6. Cache Performance Test**

**Setup:**
```
Generate 100,000 packets to same destination:
for i in 1..100000:
    send packet: 192.168.1.100:54321 -> 8.8.8.8:443
```

**Expected Behavior:**
```
Packet 1: Cache MISS → Full rule matching (50μs)
Packet 2-100,000: Cache HIT → Fast verdict (10μs)

Cache Statistics:
  ├─ Total requests: 100,000
  ├─ Cache hits: 99,999
  ├─ Cache misses: 1
  ├─ Hit rate: 99.999%
  └─ Average latency: 10.0004μs
```

**Success Criteria:**
- ✅ Hit rate >99%
- ✅ Average latency <15μs
- ✅ Throughput >100K pps
- ✅ Memory usage <500MB

---

**7. Hot-Reload Test**

**Setup:**
```
1. Load initial rules (100 rules)
2. Start processing traffic (10,000 packets/sec)
3. Edit firewall.toml: Add new rule "Block_Twitter"
4. Save file
5. Firewall detects file change (fsnotify)
6. Reload rules without restart
```

**Expected Behavior:**
```
Before reload:
  ├─ twitter.com connections: ALLOWED
  └─ Firewall running with 100 rules

File change detected at 10:00:00:
  ├─ Firewall reads new firewall.toml
  ├─ Validates new rules (syntax, semantics)
  ├─ If valid: Swap rules atomically
  ├─ If invalid: Keep old rules, log error
  └─ Cache invalidated (flush all entries)

After reload (10:00:01):
  ├─ twitter.com connections: DENIED
  ├─ Firewall running with 101 rules
  └─ No downtime (processed packets during reload)
```

**Success Criteria:**
- ✅ New rule applied without restart
- ✅ No packet loss during reload
- ✅ Cache invalidated (old verdicts cleared)
- ✅ Latency spike <100ms during reload
- ✅ If validation fails: Old rules retained

---

#### Performance Benchmarks:

**Target Metrics (Phase 3 Completion):**
```
Throughput: 100,000 packets/sec sustained
Latency: <1ms per packet (p99)
Cache Hit Rate: >80%
Memory: <500MB with 100K cached verdicts
CPU: <50% on 8-core system
Packet Loss: 0%
Enforcement Success Rate: >99%
```

**How to Measure:**
```
1. Throughput:
   ├─ Use packet generator (hping3, tcpreplay)
   ├─ Send 1M packets over 10 seconds
   └─ Measure: packets_received / time

2. Latency:
   ├─ Add timestamp to each packet
   ├─ Measure: verdict_time - packet_arrival_time
   └─ Calculate p50, p95, p99 percentiles

3. Cache Hit Rate:
   ├─ Track cache hits and misses
   └─ Calculate: hits / (hits + misses)

4. Memory:
   ├─ Monitor process RSS (Resident Set Size)
   └─ Measure after processing 1M packets

5. CPU:
   ├─ Monitor process CPU usage (top, htop)
   └─ Average over 5 minutes

6. Packet Loss:
   ├─ Compare: packets_sent vs packets_received
   └─ Loss rate = (sent - received) / sent
```

---

#### Why This Matters:

**1. Security Validation:**
- Ensures firewall actually blocks malicious traffic (not just logging)
- Verifies enforcement mechanisms work (DROP, DENY, REDIRECT)
- Confirms no bypass methods (packets escaping firewall)

**2. Performance Validation:**
- Verifies firewall meets 100K pps throughput target
- Confirms sub-1ms latency requirement
- Ensures no packet loss under load

**3. Stability Validation:**
- Tests hot-reload (zero-downtime rule updates)
- Validates error handling (fail-open behavior)
- Confirms long-running stability (24+ hours)

**4. Regression Testing:**
- Future changes don't break existing functionality
- Performance doesn't degrade over time
- New features don't introduce bugs

---

## 📊 Phase 3 Success Criteria

**By end of Phase 3, the firewall must demonstrate:**

1. ✅ **Functional Enforcement:**
   - ALLOW: Traffic flows normally (verified with curl, ping)
   - DROP: Packets silently discarded (30s timeout, no response)
   - DENY: TCP RST sent, connection terminated (<1s rejection)
   - REDIRECT: DNS queries redirected to captive portal (fake IP returned)

2. ✅ **Connection Tracking:**
   - TCP state machine working (NEW → ESTABLISHED → CLOSING → CLOSED)
   - Connection table populated with active connections
   - Timeout cleanup removes expired connections (verified with API)

3. ✅ **Performance Targets:**
   - Throughput: 100,000 packets/sec sustained (measured with tcpreplay)
   - Latency: <1ms per packet p99 (measured with timestamps)
   - Cache hit rate: >80% (measured with cache stats)
   - Memory: <500MB (measured with process monitor)
   - Packet loss: 0% (verified with packet counters)

4. ✅ **Statistics:**
   - Total packets processed (counter increments)
   - Packets allowed/blocked/dropped (verdict counters)
   - Rule hit counts (which rules matched most)
   - Cache hit rate (efficiency metric)

5. ✅ **Error Handling:**
   - Enforcement failures logged but don't crash firewall (fail-open)
   - Automatic retry with exponential backoff (3 attempts max)
   - Graceful degradation if SafeOps unavailable (fall back to WFP)

---

## 📁 File Structure Summary

```
src/firewall_engine/
├── internal/
│   ├── enforcement/
│   │   ├── verdict_handler.go       # Main verdict enforcement orchestrator
│   │   ├── drop.go                  # Silent drop (kernel blocklist)
│   │   ├── tcp_rst.go               # TCP RST injection
│   │   ├── dns_redirect.go          # DNS spoofing for captive portal
│   │   ├── icmp_reject.go           # ICMP unreachable
│   │   ├── packet_injector.go       # Low-level packet crafting utilities (optional)
│   │   └── action_executor.go       # Execute rule-specific actions
│   │
│   ├── connection/
│   │   ├── tracker.go               # Connection state tracker (main)
│   │   ├── state.go                 # TCP state machine
│   │   ├── flow.go                  # Flow statistics calculation
│   │   ├── timeout.go               # Connection timeout management
│   │   └── table.go                 # High-performance sync.Map table
│   │
│   ├── inspector/
│   │   ├── packet_inspector.go      # Main inspection logic
│   │   ├── flow_inspector.go        # Flow-level inspection
│   │   ├── fastpath.go              # Fast-path optimizations
│   │   ├── handler.go               # Metadata stream handler
│   │   └── worker_pool.go           # Parallel worker pool
│   │
│   ├── cache/
│   │   ├── verdict_cache.go         # Main cache interface
│   │   ├── lru.go                   # LRU implementation
│   │   ├── ttl.go                   # TTL expiration
│   │   ├── stats.go                 # Cache statistics
│   │   └── invalidation.go          # Cache invalidation
│   │
│   └── integration/
│       ├── safeops_grpc_client.go   # (existing) gRPC client
│       └── verdict_client.go        # (new) SafeOps verdict API client
│
├── cmd/
│   └── main.go                      # Update: Add enforcement pipeline
│
└── go.mod                           # Update: Add new dependencies
```

---

## 🚀 Next Steps After Phase 3

After Phase 3 completion, proceed to:
- **Phase 4:** Windows WFP Integration (dual engine architecture)
- **Phase 5:** Logging, Statistics & Monitoring (Prometheus, gRPC API)
- **Phase 6:** Hot-Reload & Configuration Management (zero-downtime updates)

**Estimated Total Time for Phase 3:** 2 weeks

---

**END OF PHASE 3 DOCUMENTATION**
