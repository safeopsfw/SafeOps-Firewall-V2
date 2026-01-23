# PHASE 8: DOMAIN-BASED FILTERING & DNS INTEGRATION

**Status:** 🔜 Future Phase (After Phase 7 Complete)
**Duration:** 2 weeks
**Goal:** Block websites by domain name - DNS, TLS SNI, HTTP Host filtering with captive portal
**Deliverable:** Comprehensive domain blocking across all protocols (DNS, HTTPS, HTTP)

---

## 📋 Phase Overview

**What Changes in Phase 8:**
- **Phase 7 Reality:** Firewall blocks by IP address, port, protocol (can't block facebook.com directly)
- **Phase 8 Goal:** Block by domain name - facebook.com, *.twitter.com, youtube.com (user-friendly)
- **Integration Point:** Parse DNS/TLS/HTTP protocols, extract domain names, match rules

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working (provides packet payloads)
- ✅ Phase 2: Rule matching engine functional
- ✅ Phase 3: SafeOps verdict enforcement working
- ✅ Phase 4: WFP dual-engine active
- ✅ Phase 5: Logging, metrics, health monitoring
- ✅ Phase 6: Hot-reload for dynamic rule updates
- ✅ Phase 7: Security features active

---

## 🎯 Phase 8 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup:**
```
[INFO] Firewall Engine v8.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Domain Filtering: ENABLED
[INFO] ├─ DNS Query Filtering: ACTIVE
[INFO] ├─ TLS SNI Extraction: ACTIVE
[INFO] ├─ HTTP Host Filtering: ACTIVE
[INFO] ├─ Domain Blocklist: 10,000 domains loaded
[INFO] ├─ Wildcard Matching: ENABLED (trie-based)
[INFO] └─ DNS Redirect: ENABLED (captive portal: 192.168.1.1)
[INFO] Firewall ready - domain-based filtering active
```

**DNS Query Blocking:**
```
# User tries to access facebook.com via DNS lookup

[DEBUG] DNS: Query received
[DEBUG] ├─ Query ID: 0x1234
[DEBUG] ├─ Domain: facebook.com
[DEBUG] ├─ Type: A (IPv4 address)
[DEBUG] └─ Client: 192.168.1.100:54321

[INFO] Domain Matcher: Checking domain 'facebook.com'
[INFO] ├─ Exact match: facebook.com (rule: Block_Facebook)
[INFO] ├─ Wildcard match: N/A
[INFO] └─ Result: BLOCKED

[INFO] [DROP] DNS 192.168.1.100:54321 -> 8.8.8.8:53 [Query: facebook.com] [Rule: Block_Facebook] [Action: DROP]
[INFO] DNS: Query blocked (facebook.com)

# User receives no DNS response (timeout)
# Result: facebook.com unreachable (name resolution failed)
```

**DNS Redirect to Captive Portal:**
```
# User tries to access twitter.com
# Instead of DROP, redirect to captive portal

[DEBUG] DNS: Query received
[DEBUG] ├─ Domain: twitter.com
[DEBUG] ├─ Client: 192.168.1.100:54322

[INFO] Domain Matcher: Checking domain 'twitter.com'
[INFO] ├─ Match: *.twitter.com (rule: Block_Twitter)
[INFO] └─ Action: REDIRECT (captive portal)

[INFO] DNS: Injecting fake response
[INFO] ├─ Original query: twitter.com → ?
[INFO] ├─ Fake response: twitter.com → 192.168.1.1 (captive portal)
[INFO] ├─ Response injected: DNS Response sent to 192.168.1.100
[INFO] └─ TTL: 60 seconds

[INFO] [REDIRECT] DNS 192.168.1.100:54322 -> 8.8.8.8:53 [Query: twitter.com] [Redirect: 192.168.1.1]

# User receives DNS response: twitter.com = 192.168.1.1
# Browser navigates to 192.168.1.1 (captive portal)
# Captive portal shows block page: "Access to twitter.com denied by firewall policy"
```

**TLS SNI Blocking (HTTPS):**
```
# User tries to access https://facebook.com (encrypted, port 443)
# DNS already resolved: facebook.com = 157.240.0.35

[DEBUG] TLS: ClientHello received
[DEBUG] ├─ Client: 192.168.1.100:54323
[DEBUG] ├─ Server: 157.240.0.35:443
[DEBUG] ├─ TLS Version: 1.3
[DEBUG] └─ Parsing SNI extension...

[INFO] TLS: SNI extracted
[INFO] ├─ SNI: facebook.com
[INFO] ├─ Cipher suites: [TLS_AES_128_GCM_SHA256, ...]
[INFO] └─ Extensions: [SNI, ALPN, supported_groups, ...]

[INFO] Domain Matcher: Checking domain 'facebook.com'
[INFO] ├─ Exact match: facebook.com (rule: Block_Facebook)
[INFO] └─ Result: BLOCKED

[INFO] [DROP] TCP 192.168.1.100:54323 -> 157.240.0.35:443 HTTPS [SNI: facebook.com] [Rule: Block_Facebook] [Action: TCP_RESET]
[INFO] TLS: Connection reset (SNI blocked)

# User's browser receives TCP RST
# Browser shows: "Connection reset by peer" or "Unable to connect"
# Result: facebook.com unreachable (even though DNS resolved)
```

**Wildcard Domain Matching:**
```
# User tries various Facebook subdomains

[DEBUG] DNS: Query received (www.facebook.com)
[INFO] Domain Matcher: Checking domain 'www.facebook.com'
[INFO] ├─ Exact match: NO
[INFO] ├─ Wildcard match: *.facebook.com (rule: Block_Facebook_Wildcard)
[INFO] └─ Result: BLOCKED (wildcard match)
[INFO] [DROP] DNS Query: www.facebook.com

[DEBUG] DNS: Query received (m.facebook.com)
[INFO] Domain Matcher: Checking domain 'm.facebook.com'
[INFO] ├─ Wildcard match: *.facebook.com
[INFO] └─ Result: BLOCKED
[INFO] [DROP] DNS Query: m.facebook.com

[DEBUG] DNS: Query received (graph.facebook.com)
[INFO] Domain Matcher: Checking domain 'graph.facebook.com'
[INFO] ├─ Wildcard match: *.facebook.com
[INFO] └─ Result: BLOCKED
[INFO] [DROP] DNS Query: graph.facebook.com

# All Facebook subdomains blocked with single wildcard rule: *.facebook.com
```

**HTTP Host Header Filtering:**
```
# User tries HTTP (port 80, unencrypted)
# Some sites still use HTTP (IoT devices, legacy systems)

[DEBUG] HTTP: Request received
[DEBUG] ├─ Client: 192.168.1.100:54324
[DEBUG] ├─ Server: 93.184.216.34:80
[DEBUG] ├─ Method: GET
[DEBUG] ├─ Path: /index.html
[DEBUG] └─ Parsing headers...

[INFO] HTTP: Host header extracted
[INFO] ├─ Host: example.com
[INFO] ├─ User-Agent: Mozilla/5.0 ...
[INFO] └─ Referer: http://google.com

[INFO] Domain Matcher: Checking domain 'example.com'
[INFO] ├─ Exact match: example.com (rule: Block_Example)
[INFO] └─ Result: BLOCKED

[INFO] [DROP] TCP 192.168.1.100:54324 -> 93.184.216.34:80 HTTP [Host: example.com] [Rule: Block_Example] [Action: TCP_RESET]
[INFO] HTTP: Connection reset (Host blocked)

# User's browser receives TCP RST
# Browser shows: "Connection reset"
```

**Trie-Based Domain Matching Performance:**
```
# Firewall handles 100,000 DNS queries/sec with 10,000 domain rules

[INFO] Domain Matcher: Performance test
[INFO] ├─ Blocklist size: 10,000 domains
[INFO] ├─ Trie nodes: 45,000 (avg 4.5 nodes per domain)
[INFO] ├─ Memory usage: 2.5MB (trie structure)
[INFO] └─ Trie built in 50ms

[DEBUG] Domain lookup: facebook.com
[DEBUG] ├─ Trie lookup: 8 node traversals (f→a→c→e→b→o→o→k)
[DEBUG] ├─ Lookup time: 0.5μs (500 nanoseconds)
[DEBUG] └─ Match found: YES

[DEBUG] Domain lookup: verylongdomainname.subdomain.example.com
[DEBUG] ├─ Trie lookup: 42 node traversals
[DEBUG] ├─ Lookup time: 2.1μs
[DEBUG] └─ Match found: NO

[INFO] Performance Summary:
[INFO] ├─ Average lookup time: 0.8μs (microseconds)
[INFO] ├─ Throughput: 1,250,000 lookups/sec per core
[INFO] ├─ vs Linear search: 5ms per lookup (6,000× slower!)
[INFO] └─ Scalability: O(k) where k=domain length (not O(n) where n=blocklist size)
```

**Captive Portal Block Page:**
```
# User navigates to blocked domain (redirected to 192.168.1.1)
# Captive portal shows HTML page:

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1234

<!DOCTYPE html>
<html>
<head>
  <title>Access Denied - SafeOps Firewall</title>
  <style>
    body { font-family: Arial; text-align: center; margin-top: 100px; }
    .blocked { color: #d32f2f; font-size: 48px; }
    .message { font-size: 20px; color: #666; }
  </style>
</head>
<body>
  <div class="blocked">🚫 Access Denied</div>
  <div class="message">
    <p>The website you requested has been blocked by firewall policy.</p>
    <p><strong>Blocked Domain:</strong> twitter.com</p>
    <p><strong>Rule:</strong> Block_Social_Media</p>
    <p><strong>Category:</strong> Social Networking</p>
    <p><strong>Reason:</strong> Corporate policy prohibits access during work hours</p>
    <p><strong>Time:</strong> 2026-01-22 10:30:45</p>
    <p><strong>Client IP:</strong> 192.168.1.100</p>
  </div>
  <div style="margin-top: 50px;">
    <p>If you believe this is an error, contact IT support:</p>
    <p>Email: itsupport@company.com | Phone: +1-555-0123</p>
  </div>
</body>
</html>
```

**Statistics Dashboard:**
```
# http://localhost:9090/metrics

# Domain filtering metrics
firewall_domain_blocks_total{protocol="dns"} 15000
firewall_domain_blocks_total{protocol="tls_sni"} 8000
firewall_domain_blocks_total{protocol="http_host"} 2000
firewall_domain_redirects_total 5000

# Top blocked domains
firewall_domain_blocks_by_domain{domain="facebook.com"} 5000
firewall_domain_blocks_by_domain{domain="twitter.com"} 3000
firewall_domain_blocks_by_domain{domain="youtube.com"} 2500
firewall_domain_blocks_by_domain{domain="tiktok.com"} 2000
firewall_domain_blocks_by_domain{domain="instagram.com"} 1500

# Domain matcher performance
firewall_domain_matcher_lookups_total 100000
firewall_domain_matcher_lookup_duration_seconds{quantile="0.5"} 0.0000008  # 0.8μs (p50)
firewall_domain_matcher_lookup_duration_seconds{quantile="0.99"} 0.000003   # 3μs (p99)
firewall_domain_matcher_trie_nodes 45000
firewall_domain_matcher_trie_memory_bytes 2621440  # 2.5MB

# Captive portal metrics
firewall_captive_portal_requests_total 5000
firewall_captive_portal_unique_ips 250
```

---

## 🏗️ Phase 8 Architecture

### Domain Filtering Flow:

```
Packet Arrives → Protocol Detection → Domain Extraction → Domain Matching → Action
```

**Detailed Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Packet Arrives                            │
│         (could be DNS, TLS, HTTP, or other)                  │
└────────────────────┬────────────────────────────────────────┘
                     ↓
    ┌────────────────────────────────────────────┐
    │  1. Protocol Detection (Deep Packet        │
    │     Inspection)                            │
    │     - Check destination port:              │
    │       ├─ Port 53 → DNS                     │
    │       ├─ Port 443 → HTTPS (TLS)            │
    │       ├─ Port 80 → HTTP                    │
    │       └─ Other → Skip domain filtering     │
    │     - Parse packet payload                 │
    └────────────────────┬───────────────────────┘
                         ↓
        ┌────────────────────────────────────────┐
        │  2. Domain Extraction (Parser)         │
        │                                         │
        │  If DNS (port 53):                     │
        │  ├─ Parse DNS query                    │
        │  ├─ Extract QNAME (domain)             │
        │  └─ Example: facebook.com              │
        │                                         │
        │  If HTTPS (port 443):                  │
        │  ├─ Parse TLS ClientHello              │
        │  ├─ Extract SNI extension              │
        │  └─ Example: www.facebook.com          │
        │                                         │
        │  If HTTP (port 80):                    │
        │  ├─ Parse HTTP request                 │
        │  ├─ Extract Host header                │
        │  └─ Example: api.twitter.com           │
        └────────────────────┬───────────────────┘
                             ↓
        ┌────────────────────────────────────────┐
        │  3. Domain Normalization               │
        │     - Lowercase: Facebook.com → facebook.com
        │     - Strip trailing dot: example.com. → example.com
        │     - IDN decode: xn--e1afmkfd.xn--p1ai → пример.рф (Punycode)
        │     - Remove www prefix (optional)     │
        └────────────────────┬───────────────────┘
                             ↓
        ┌────────────────────────────────────────┐
        │  4. Domain Matching (Trie-Based)       │
        │                                         │
        │  Check against blocklist:              │
        │  ├─ Exact match: facebook.com          │
        │  ├─ Wildcard match: *.facebook.com     │
        │  ├─ Regex match: .*\\.ads\\..*        │
        │  └─ Category match: [social_media]     │
        │                                         │
        │  Trie lookup: O(k) where k=length     │
        │  ├─ Traverse: f→a→c→e→b→o→o→k          │
        │  ├─ Time: 0.5-3μs (very fast)          │
        │  └─ Result: MATCH or NO_MATCH          │
        └────────────────────┬───────────────────┘
                             ↓
                 ┌───────────┴────────────┐
                 │ Match Found?           │
                 └───────────┬────────────┘
                     YES ↓        ↓ NO
        ┌────────────────────────┐    ┌────────────────────┐
        │  5A. Domain Blocked    │    │  5B. Domain        │
        │                        │    │      Allowed       │
        │  Choose action:        │    │                    │
        │  ├─ DROP (silent)      │    │  Return: ALLOW     │
        │  ├─ REDIRECT (captive) │    │  Packet continues  │
        │  └─ REJECT (ICMP)      │    │  (normal routing)  │
        └────────────────────────┘    └────────────────────┘
                     ↓
        ┌────────────────────────────────────────┐
        │  6. Execute Action                     │
        │                                         │
        │  If DROP:                              │
        │  ├─ Return DROP verdict                │
        │  ├─ SafeOps drops packet               │
        │  └─ Client timeout (no response)       │
        │                                         │
        │  If REDIRECT (DNS only):               │
        │  ├─ Craft fake DNS response            │
        │  ├─ Answer: domain → 192.168.1.1       │
        │  ├─ Inject response packet             │
        │  └─ Client receives captive portal IP  │
        │                                         │
        │  If REJECT:                            │
        │  ├─ Send TCP RST (TLS/HTTP)            │
        │  ├─ Or ICMP unreachable (DNS/UDP)      │
        │  └─ Client sees "connection refused"   │
        └─────────────────────────────────────────┘
```

### Domain Matcher Architecture (Trie):

```
Domain blocklist: [facebook.com, fb.com, facebook.net, facebookmail.com]

Trie structure (prefix tree):
                 ROOT
                  |
          ┌───────┴────────┬────────┐
          │                │        │
        [f]              [o]      [t]...
          |                |
        [a]              [t]
          |                |
        [c]              [h]
          |                |
        [e]              [e]
          |                |
        [b]              [r]
          |
        [o]
          |
        [o]
          |
    ┌───[k]───┐
    |         |
 [.com]    [mail.com]
  (BLOCKED) (BLOCKED)

Lookup algorithm:
1. Input: "facebook.com"
2. Start at ROOT
3. Traverse: R→f→a→c→e→b→o→o→k
4. Check children: .com found? YES (BLOCKED)
5. Return: MATCH (0.5μs)

Wildcard support:
Domain: *.facebook.com
Trie stores: facebook.com (with wildcard flag)
Lookup: www.facebook.com
  ├─ Extract suffix: facebook.com
  ├─ Lookup facebook.com in trie
  ├─ Check wildcard flag: YES
  └─ Return: MATCH (wildcard)
```

---

## 📦 Phase 8 Components (5 Sub-Tasks)

### Sub-Task 8.1: DNS Query Filtering (`internal/parser/dns_parser.go`)

**Purpose:** Parse DNS queries and block domains at DNS resolution stage

**Core Concept:**
DNS is the first step in accessing any website (domain → IP resolution). Blocking at DNS level prevents connection attempts entirely.

---

#### What to Create:

**1. DNS Protocol Primer**

**What is DNS:**
```
DNS (Domain Name System):
├─ Translates human-readable names (google.com) to IP addresses (142.250.185.46)
├─ UDP-based (port 53), sometimes TCP for large responses
├─ Client sends query, server sends response
└─ Hierarchical: Root → TLD (.com) → Authoritative (google.com)

DNS query flow:
1. Client: "What is facebook.com?"
2. DNS server: "facebook.com is 157.240.0.35"
3. Client: Connects to 157.240.0.35

DNS blocking:
1. Client: "What is facebook.com?"
2. Firewall: Intercepts query
3. Firewall: Checks blocklist → facebook.com BLOCKED
4. Firewall: Drops query (client timeout) OR redirects (fake response)
```

**DNS Packet Structure:**
```
DNS Query packet:
┌─────────────────────────────────────┐
│ DNS Header (12 bytes)               │
├─────────────────────────────────────┤
│ Transaction ID: 0x1234 (2 bytes)    │
│ Flags: 0x0100 (2 bytes)             │
│   ├─ QR: 0 (query)                  │
│   ├─ Opcode: 0 (standard query)     │
│   └─ RD: 1 (recursion desired)      │
│ Questions: 1 (2 bytes)              │
│ Answers: 0 (2 bytes)                │
│ Authority: 0 (2 bytes)              │
│ Additional: 0 (2 bytes)             │
├─────────────────────────────────────┤
│ Question Section (variable)         │
├─────────────────────────────────────┤
│ QNAME: facebook.com (13 bytes)      │
│   ├─ 8 f a c e b o o k             │
│   ├─ 3 c o m                        │
│   └─ 0 (null terminator)            │
│ QTYPE: 1 (A record - IPv4) (2 bytes)│
│ QCLASS: 1 (IN - Internet) (2 bytes) │
└─────────────────────────────────────┘

Total: 12 + 13 + 2 + 2 = 29 bytes

DNS Response packet:
┌─────────────────────────────────────┐
│ DNS Header (12 bytes)               │
├─────────────────────────────────────┤
│ Transaction ID: 0x1234 (matches query)
│ Flags: 0x8180 (2 bytes)             │
│   ├─ QR: 1 (response)               │
│   ├─ AA: 0 (not authoritative)      │
│   └─ RCODE: 0 (no error)            │
│ Questions: 1                        │
│ Answers: 1                          │
│ Authority: 0                        │
│ Additional: 0                       │
├─────────────────────────────────────┤
│ Question Section (echoed from query)│
│ (same as query)                     │
├─────────────────────────────────────┤
│ Answer Section                      │
├─────────────────────────────────────┤
│ NAME: facebook.com (pointer: 0xC00C)│
│ TYPE: 1 (A record)                  │
│ CLASS: 1 (IN)                       │
│ TTL: 300 (5 minutes) (4 bytes)      │
│ RDLENGTH: 4 (4 bytes)               │
│ RDATA: 157.240.0.35 (4 bytes)       │
│   └─ 0x9D 0xF0 0x00 0x23            │
└─────────────────────────────────────┘

Total: 12 + question + 16 = ~45 bytes
```

---

**2. DNS Query Parser**

**Purpose:** Extract domain name from DNS query packet

**Parsing Algorithm:**
```
Input: Raw DNS packet bytes
Output: Domain name string

Steps:
1. Verify packet is DNS:
   ├─ Check destination port: 53 (DNS)
   ├─ Check protocol: UDP (typical) or TCP
   └─ Check minimum length: >= 12 bytes (DNS header)

2. Parse DNS header:
   ├─ Read bytes 0-1: Transaction ID
   ├─ Read bytes 2-3: Flags (check QR bit: 0=query, 1=response)
   ├─ Read bytes 4-5: Question count (must be >= 1)
   └─ If QR=1 (response): Skip (we only filter queries)

3. Parse Question section (starts at byte 12):
   ├─ Read QNAME (domain name):
   │  ├─ Format: Length-prefixed labels
   │  ├─ Example: facebook.com = [8]facebook[3]com[0]
   │  └─ Decode: Read length byte, read N chars, repeat until 0
   ├─ Read QTYPE (2 bytes): 1=A, 28=AAAA, 15=MX, etc.
   └─ Read QCLASS (2 bytes): 1=IN (Internet)

4. Extract domain name:
   ├─ Convert labels to dot-notation: facebook.com
   ├─ Lowercase: Facebook.COM → facebook.com
   ├─ Strip trailing dot: example.com. → example.com
   └─ Return: "facebook.com"
```

**Parser Implementation:**
```
type DNSParser struct {
  logger *logging.Logger
}

type DNSQuery struct {
  TransactionID uint16
  Domain        string
  QueryType     uint16  // 1=A, 28=AAAA
  QueryClass    uint16  // 1=IN
}

func (dp *DNSParser) Parse(packet []byte) (*DNSQuery, error) {
  // Minimum DNS query size: 12 (header) + 5 (min question) = 17 bytes
  if len(packet) < 17 {
    return nil, fmt.Errorf("packet too short for DNS query")
  }

  // Parse DNS header
  txID := binary.BigEndian.Uint16(packet[0:2])
  flags := binary.BigEndian.Uint16(packet[2:4])
  qdCount := binary.BigEndian.Uint16(packet[4:6])

  // Check if this is a query (QR bit = 0)
  qr := (flags >> 15) & 0x1
  if qr != 0 {
    return nil, fmt.Errorf("not a DNS query (QR=1, this is a response)")
  }

  // Check question count
  if qdCount == 0 {
    return nil, fmt.Errorf("no questions in DNS query")
  }

  // Parse Question section (starts at byte 12)
  offset := 12
  domain, newOffset, err := dp.parseQName(packet, offset)
  if err != nil {
    return nil, fmt.Errorf("failed to parse QNAME: %w", err)
  }

  // Parse QTYPE and QCLASS
  if len(packet) < newOffset+4 {
    return nil, fmt.Errorf("truncated DNS query")
  }

  qtype := binary.BigEndian.Uint16(packet[newOffset : newOffset+2])
  qclass := binary.BigEndian.Uint16(packet[newOffset+2 : newOffset+4])

  return &DNSQuery{
    TransactionID: txID,
    Domain:        domain,
    QueryType:     qtype,
    QueryClass:    qclass,
  }, nil
}

func (dp *DNSParser) parseQName(packet []byte, offset int) (string, int, error) {
  labels := []string{}
  originalOffset := offset

  for {
    // Check bounds
    if offset >= len(packet) {
      return "", 0, fmt.Errorf("truncated QNAME")
    }

    // Read length byte
    length := int(packet[offset])
    offset++

    // Check for end of name (length = 0)
    if length == 0 {
      break
    }

    // Check for compression pointer (length >= 192)
    if length >= 192 {
      // DNS compression (pointer to earlier name)
      // Format: 11xxxxxx xxxxxxxx (2 bytes)
      // We don't support compression in queries (uncommon)
      return "", 0, fmt.Errorf("DNS compression not supported in queries")
    }

    // Read label (length bytes)
    if offset+length > len(packet) {
      return "", 0, fmt.Errorf("truncated label")
    }

    label := string(packet[offset : offset+length])
    labels = append(labels, label)
    offset += length
  }

  // Join labels with dots
  domain := strings.ToLower(strings.Join(labels, "."))

  return domain, offset, nil
}
```

---

**3. Domain Matching Integration**

**Purpose:** Check extracted domain against blocklist

**Matching Flow:**
```
1. Parse DNS query → Extract domain: "facebook.com"
2. Query domain matcher:
   ├─ domainMatcher.Match("facebook.com")
   └─ Returns: (BLOCKED, "Block_Facebook") or (ALLOWED, "")

3. If BLOCKED:
   ├─ Log: "DNS query blocked: facebook.com"
   ├─ Increment metric: firewall_domain_blocks_total{protocol="dns"}
   ├─ Choose action:
   │  ├─ DROP: Return DROP verdict (query timeout)
   │  └─ REDIRECT: Inject fake DNS response (captive portal)
   └─ Return verdict to SafeOps

4. If ALLOWED:
   ├─ Return ALLOW verdict
   └─ Query forwarded to real DNS server
```

**Integration Code:**
```
func (dp *DNSParser) Filter(packet *Packet) (Verdict, error) {
  // Parse DNS query
  query, err := dp.Parse(packet.Payload)
  if err != nil {
    // Not a valid DNS query, allow (skip filtering)
    return ALLOW, nil
  }

  // Check domain against blocklist
  match, rule := domainMatcher.Match(query.Domain)

  if match {
    // Domain blocked
    log.Info().
      Str("domain", query.Domain).
      Str("rule", rule.Name).
      Str("client", packet.SrcIP).
      Msg("DNS query blocked")

    // Increment metrics
    metrics.IncrementCounter("firewall_domain_blocks_total", map[string]string{
      "protocol": "dns",
      "domain":   query.Domain,
    })

    // Choose action based on rule
    switch rule.Action {
    case DROP:
      return DROP, nil  // Silent drop (query timeout)

    case REDIRECT:
      // Inject fake DNS response (captive portal)
      return dp.injectFakeDNSResponse(packet, query, rule.RedirectIP)

    case REJECT:
      // Send ICMP unreachable (UDP port unreachable)
      return REJECT, nil

    default:
      return DROP, nil
    }
  }

  // Domain allowed
  return ALLOW, nil
}
```

---

**4. DNS Response Handling (Optional)**

**Purpose:** Filter DNS responses to block resolved IPs

**Use Case:**
```
Problem: DNS over HTTPS (DoH) bypasses DNS filtering
├─ User uses Cloudflare DoH (1.1.1.1:443)
├─ Firewall can't see DNS queries (encrypted HTTPS)
├─ DNS query: facebook.com → 157.240.0.35
├─ User connects to 157.240.0.35 (firewall doesn't know it's Facebook)
└─ Result: Facebook accessed despite DNS block

Solution: Filter DNS responses
├─ Monitor DNS responses (even if queries bypassed)
├─ If response contains: facebook.com → 157.240.0.35
├─ Cache mapping: 157.240.0.35 = facebook.com
├─ When user connects to 157.240.0.35:
│  └─ Lookup cache: 157.240.0.35 → facebook.com (blocked)
└─ Result: Block connection by domain (even with DoH)
```

**Response Parser:**
```
func (dp *DNSParser) ParseResponse(packet []byte) (*DNSResponse, error) {
  // Parse header (similar to query)
  txID := binary.BigEndian.Uint16(packet[0:2])
  flags := binary.BigEndian.Uint16(packet[2:4])
  qdCount := binary.BigEndian.Uint16(packet[4:6])
  anCount := binary.BigEndian.Uint16(packet[6:8])  // Answer count

  // Check if this is a response (QR bit = 1)
  qr := (flags >> 15) & 0x1
  if qr != 1 {
    return nil, fmt.Errorf("not a DNS response")
  }

  // Parse question section (to get domain name)
  offset := 12
  domain, newOffset, err := dp.parseQName(packet, offset)
  if err != nil {
    return nil, err
  }

  // Skip QTYPE and QCLASS
  newOffset += 4

  // Parse answer section (extract IP addresses)
  ips := []string{}
  for i := 0; i < int(anCount); i++ {
    ip, nextOffset, err := dp.parseAnswer(packet, newOffset)
    if err != nil {
      break  // Skip malformed answer
    }
    if ip != "" {
      ips = append(ips, ip)
    }
    newOffset = nextOffset
  }

  return &DNSResponse{
    TransactionID: txID,
    Domain:        domain,
    IPs:           ips,
  }, nil
}

func (dp *DNSParser) parseAnswer(packet []byte, offset int) (string, int, error) {
  // Skip NAME (usually pointer: 0xC00C)
  if packet[offset]&0xC0 == 0xC0 {
    // Compression pointer (2 bytes)
    offset += 2
  } else {
    // Full name (parse like QNAME)
    _, newOffset, err := dp.parseQName(packet, offset)
    if err != nil {
      return "", 0, err
    }
    offset = newOffset
  }

  // Parse TYPE, CLASS, TTL, RDLENGTH
  if offset+10 > len(packet) {
    return "", 0, fmt.Errorf("truncated answer")
  }

  atype := binary.BigEndian.Uint16(packet[offset : offset+2])
  // class := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
  // ttl := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
  rdlength := binary.BigEndian.Uint16(packet[offset+8 : offset+10])

  offset += 10

  // Parse RDATA (IP address if TYPE=A)
  if atype == 1 && rdlength == 4 {
    // A record (IPv4)
    if offset+4 > len(packet) {
      return "", 0, fmt.Errorf("truncated RDATA")
    }
    ip := fmt.Sprintf("%d.%d.%d.%d",
      packet[offset], packet[offset+1],
      packet[offset+2], packet[offset+3])
    offset += 4
    return ip, offset, nil
  } else {
    // Not an A record, skip RDATA
    offset += int(rdlength)
    return "", offset, nil
  }
}

Cache mapping:
func (dp *DNSParser) CacheResponse(resp *DNSResponse) {
  // Store domain → IP mapping
  for _, ip := range resp.IPs {
    dp.domainCache.Set(ip, resp.Domain, 300*time.Second)  // 5 min TTL
  }
}
```

---

**5. Match Against Blocklist**

**Purpose:** Check domain against firewall rules

**Matching Logic:**
```
Blocklist structure:
{
  "facebook.com": {
    "rule": "Block_Facebook",
    "action": "DROP",
    "category": "social_media"
  },
  "*.twitter.com": {
    "rule": "Block_Twitter_Wildcard",
    "action": "REDIRECT",
    "redirect_ip": "192.168.1.1"
  },
  "youtube.com": {
    "rule": "Block_YouTube",
    "action": "DROP"
  }
}

Matching algorithm:
1. Exact match:
   ├─ Domain: "facebook.com"
   ├─ Lookup: blocklist["facebook.com"]
   └─ Result: MATCH (rule: Block_Facebook)

2. Wildcard match:
   ├─ Domain: "www.twitter.com"
   ├─ Exact lookup: blocklist["www.twitter.com"] → NOT FOUND
   ├─ Wildcard lookup: blocklist["*.twitter.com"] → FOUND
   └─ Result: MATCH (rule: Block_Twitter_Wildcard)

3. No match:
   ├─ Domain: "google.com"
   ├─ Exact lookup: NOT FOUND
   ├─ Wildcard lookup: NOT FOUND
   └─ Result: ALLOW
```

---

#### Files to Create:
```
internal/parser/
├── dns_parser.go        # DNS query/response parser
├── dns_types.go         # DNS data structures (DNSQuery, DNSResponse)
├── dns_filter.go        # DNS filtering logic
└── dns_response_inject.go  # Fake DNS response injection (Sub-Task 8.5)
```

---

### Sub-Task 8.2: TLS SNI Extraction (`internal/parser/tls_parser.go`)

**Purpose:** Extract Server Name Indication from TLS handshake to block HTTPS by domain

**Core Concept:**
HTTPS traffic is encrypted, but the TLS handshake (initial connection setup) is unencrypted and contains the SNI extension revealing the destination domain.

---

#### What to Create:

**1. TLS Protocol Primer**

**What is TLS SNI:**
```
TLS (Transport Layer Security):
├─ Encrypts HTTP traffic → HTTPS (port 443)
├─ Handshake: Client and server establish encrypted connection
├─ SNI (Server Name Indication): Extension in ClientHello revealing destination
└─ Purpose: Allow single IP to host multiple HTTPS sites (virtual hosting)

Why SNI exists:
Problem: Single server (IP: 1.2.3.4) hosts 100 websites
├─ www.example.com (1.2.3.4:443)
├─ www.another.com (1.2.3.4:443)
└─ www.yetanother.com (1.2.3.4:443)

Without SNI:
├─ Client connects to 1.2.3.4:443
├─ Server doesn't know which website (all same IP!)
└─ Server presents wrong certificate → browser error

With SNI:
├─ Client sends: "I want to connect to www.example.com"
├─ Server knows: "Ah, serve example.com certificate"
└─ Connection succeeds (correct certificate)

SNI for filtering:
├─ Client sends: "I want to connect to facebook.com"
├─ Firewall intercepts: TLS ClientHello
├─ Firewall reads SNI: "facebook.com"
├─ Firewall checks blocklist: facebook.com → BLOCKED
└─ Firewall drops packet (connection reset)
```

**TLS Handshake Flow:**
```
Client                    Firewall                   Server
  │                          │                         │
  ├─── ClientHello ─────────>│                         │
  │    (SNI: facebook.com)    │                         │
  │                          │                         │
  │                          │ Parse ClientHello       │
  │                          │ Extract SNI: facebook.com
  │                          │ Check blocklist         │
  │                          │ Result: BLOCKED         │
  │                          │                         │
  │<─── TCP RST ─────────────┤                         │
  │    (Connection reset)     │                         │
  │                          │                         │
  X (Connection failed)      │                         │

Normal flow (if allowed):
Client                    Firewall                   Server
  │                          │                         │
  ├─── ClientHello ─────────>│─────────────────────────>│
  │    (SNI: google.com)      │                         │
  │                          │                         │
  │<─────────────────────────│<──── ServerHello ───────┤
  │                          │                         │
  │<─────────────────────────│<──── Certificate ───────┤
  │                          │                         │
  │ (Encrypted connection established)                 │
```

---

**2. TLS ClientHello Parser**

**Purpose:** Parse TLS ClientHello and extract SNI extension

**TLS ClientHello Structure:**
```
TLS Record Layer:
┌─────────────────────────────────────┐
│ Content Type: 22 (Handshake)        │
│ Version: 0x0303 (TLS 1.2) (2 bytes) │
│ Length: 512 bytes (2 bytes)         │
└─────────────────────────────────────┘

Handshake Protocol:
┌─────────────────────────────────────┐
│ Handshake Type: 1 (ClientHello)     │
│ Length: 508 bytes (3 bytes)         │
├─────────────────────────────────────┤
│ ClientHello:                        │
│ ├─ Version: 0x0303 (TLS 1.2)       │
│ ├─ Random: 32 bytes                 │
│ ├─ Session ID Length: 0             │
│ ├─ Cipher Suites Length: 32         │
│ ├─ Cipher Suites: [...]             │
│ ├─ Compression Methods: [0]         │
│ ├─ Extensions Length: 200           │
│ └─ Extensions: [...]                │
└─────────────────────────────────────┘

Extensions (the important part):
┌─────────────────────────────────────┐
│ Extension 1:                        │
│ ├─ Type: 0 (SNI) ← WE WANT THIS    │
│ ├─ Length: 20                       │
│ └─ Data: [...]                      │
├─────────────────────────────────────┤
│ Extension 2:                        │
│ ├─ Type: 16 (ALPN)                  │
│ ├─ Length: 14                       │
│ └─ Data: [h2, http/1.1]             │
├─────────────────────────────────────┤
│ Extension 3:                        │
│ ├─ Type: 13 (signature_algorithms)  │
│ └─ ...                              │
└─────────────────────────────────────┘

SNI Extension (Type 0):
┌─────────────────────────────────────┐
│ Extension Type: 0 (SNI)             │
│ Extension Length: 20 (2 bytes)      │
├─────────────────────────────────────┤
│ Server Name List Length: 18         │
├─────────────────────────────────────┤
│ Server Name Entry:                  │
│ ├─ Name Type: 0 (host_name)        │
│ ├─ Name Length: 15 (2 bytes)       │
│ └─ Name: "www.facebook.com"        │
│          (15 bytes, UTF-8)          │
└─────────────────────────────────────┘

Total SNI extension: 2 + 2 + 2 + 1 + 2 + 15 = 24 bytes
```

---

**3. Parsing Implementation**

**TLS Parser:**
```
type TLSParser struct {
  logger *logging.Logger
}

type TLSClientHello struct {
  Version       uint16   // 0x0301=TLS 1.0, 0x0303=TLS 1.2, 0x0304=TLS 1.3
  Random        []byte   // 32 bytes
  SessionID     []byte   // Variable length
  CipherSuites  []uint16 // List of supported ciphers
  SNI           string   // Server Name Indication (domain)
  ALPN          []string // Application protocols (h2, http/1.1)
}

func (tp *TLSParser) Parse(packet []byte) (*TLSClientHello, error) {
  // Minimum TLS ClientHello size: ~40 bytes
  if len(packet) < 40 {
    return nil, fmt.Errorf("packet too short for TLS ClientHello")
  }

  // Parse TLS Record Layer
  contentType := packet[0]
  if contentType != 22 {
    return nil, fmt.Errorf("not a TLS handshake (content type: %d)", contentType)
  }

  // Parse TLS version
  version := binary.BigEndian.Uint16(packet[1:3])
  recordLength := binary.BigEndian.Uint16(packet[3:5])

  // Check record length
  if len(packet) < 5+int(recordLength) {
    return nil, fmt.Errorf("truncated TLS record")
  }

  // Parse Handshake Protocol
  offset := 5
  handshakeType := packet[offset]
  if handshakeType != 1 {
    return nil, fmt.Errorf("not a ClientHello (handshake type: %d)", handshakeType)
  }

  // Handshake length (3 bytes)
  handshakeLength := int(packet[offset+1])<<16 |
    int(packet[offset+2])<<8 |
    int(packet[offset+3])
  offset += 4

  // Parse ClientHello version
  chVersion := binary.BigEndian.Uint16(packet[offset : offset+2])
  offset += 2

  // Parse Random (32 bytes)
  random := make([]byte, 32)
  copy(random, packet[offset:offset+32])
  offset += 32

  // Parse Session ID
  sessionIDLength := int(packet[offset])
  offset += 1
  sessionID := make([]byte, sessionIDLength)
  if sessionIDLength > 0 {
    copy(sessionID, packet[offset:offset+sessionIDLength])
    offset += sessionIDLength
  }

  // Parse Cipher Suites
  cipherSuitesLength := binary.BigEndian.Uint16(packet[offset : offset+2])
  offset += 2
  cipherSuites := []uint16{}
  for i := 0; i < int(cipherSuitesLength)/2; i++ {
    cs := binary.BigEndian.Uint16(packet[offset : offset+2])
    cipherSuites = append(cipherSuites, cs)
    offset += 2
  }

  // Parse Compression Methods
  compressionMethodsLength := int(packet[offset])
  offset += 1 + compressionMethodsLength

  // Parse Extensions (THE IMPORTANT PART)
  if offset+2 > len(packet) {
    return nil, fmt.Errorf("no extensions in ClientHello")
  }

  extensionsLength := binary.BigEndian.Uint16(packet[offset : offset+2])
  offset += 2

  // Parse each extension
  sni := ""
  alpn := []string{}
  extensionsEnd := offset + int(extensionsLength)

  for offset < extensionsEnd {
    // Check bounds
    if offset+4 > len(packet) {
      break
    }

    // Read extension type and length
    extType := binary.BigEndian.Uint16(packet[offset : offset+2])
    extLength := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
    offset += 4

    // Check bounds
    if offset+int(extLength) > len(packet) {
      break
    }

    // Parse SNI extension (type 0)
    if extType == 0 {
      sni, err := tp.parseSNIExtension(packet[offset : offset+int(extLength)])
      if err == nil {
        return &TLSClientHello{
          Version:      chVersion,
          Random:       random,
          SessionID:    sessionID,
          CipherSuites: cipherSuites,
          SNI:          sni,
        }, nil
      }
    }

    // Parse ALPN extension (type 16, optional)
    if extType == 16 {
      alpn = tp.parseALPNExtension(packet[offset : offset+int(extLength)])
    }

    offset += int(extLength)
  }

  // SNI not found
  if sni == "" {
    return nil, fmt.Errorf("SNI extension not found")
  }

  return &TLSClientHello{
    Version:      chVersion,
    Random:       random,
    SessionID:    sessionID,
    CipherSuites: cipherSuites,
    SNI:          sni,
    ALPN:         alpn,
  }, nil
}

func (tp *TLSParser) parseSNIExtension(data []byte) (string, error) {
  // SNI extension format:
  // Server Name List Length (2 bytes)
  // Server Name Entry:
  //   Name Type (1 byte): 0 = host_name
  //   Name Length (2 bytes)
  //   Name (variable)

  if len(data) < 5 {
    return "", fmt.Errorf("SNI extension too short")
  }

  // Server Name List Length
  listLength := binary.BigEndian.Uint16(data[0:2])
  offset := 2

  if len(data) < 2+int(listLength) {
    return "", fmt.Errorf("truncated SNI extension")
  }

  // Parse first Server Name Entry
  nameType := data[offset]
  offset += 1

  if nameType != 0 {
    return "", fmt.Errorf("invalid SNI name type: %d", nameType)
  }

  nameLength := binary.BigEndian.Uint16(data[offset : offset+2])
  offset += 2

  if offset+int(nameLength) > len(data) {
    return "", fmt.Errorf("truncated SNI name")
  }

  sni := string(data[offset : offset+int(nameLength)])

  return sni, nil
}
```

---

**4. Domain Matching Integration**

**TLS Filtering:**
```
func (tp *TLSParser) Filter(packet *Packet) (Verdict, error) {
  // Only process TLS packets (port 443)
  if packet.DstPort != 443 && packet.DstPort != 8443 {
    return ALLOW, nil  // Not HTTPS
  }

  // Parse TLS ClientHello
  clientHello, err := tp.Parse(packet.Payload)
  if err != nil {
    // Not a valid ClientHello (or SNI missing)
    // Could be:
    // 1. Encrypted packet (not handshake)
    // 2. ServerHello (response, not query)
    // 3. TLS 1.3 with encrypted SNI (ESNI)
    return ALLOW, nil  // Skip filtering
  }

  // Extract SNI
  sni := clientHello.SNI

  // Check domain against blocklist
  match, rule := domainMatcher.Match(sni)

  if match {
    // Domain blocked
    log.Info().
      Str("sni", sni).
      Str("rule", rule.Name).
      Str("client", packet.SrcIP).
      Msg("TLS SNI blocked")

    // Increment metrics
    metrics.IncrementCounter("firewall_domain_blocks_total", map[string]string{
      "protocol": "tls_sni",
      "domain":   sni,
    })

    // Action: Send TCP RST (abort TLS handshake)
    return REJECT, nil  // TCP RST sent to client
  }

  // Domain allowed
  return ALLOW, nil
}
```

---

**5. TLS 1.3 Encrypted SNI (Future)**

**Challenge:**
```
TLS 1.3 introduces Encrypted SNI (ESNI):
├─ SNI encrypted in ClientHello
├─ Firewall cannot read SNI (encrypted)
└─ Domain-based filtering bypassed

ESNI adoption:
├─ Cloudflare: Enabled (opt-in)
├─ Firefox: Supported (disabled by default)
├─ Chrome: Experimental
└─ Adoption: <1% of traffic (2026)

Mitigation strategies:
1. Block ESNI-enabled clients:
   ├─ Detect ESNI extension (type 0xFFCE)
   ├─ Block all ESNI connections (deny encrypted SNI)
   └─ User must disable ESNI to access internet

2. Fallback to IP blocking:
   ├─ If SNI encrypted, cannot filter by domain
   ├─ Fallback: Block by destination IP
   ├─ Limitation: Single IP hosts many domains (CDNs)
   └─ Collateral damage: Block legitimate sites on same IP

3. DNS-based filtering:
   ├─ Even with ESNI, DNS query still visible (if not DoH)
   ├─ Block at DNS stage (before TLS)
   └─ Limitation: DoH bypasses DNS filtering

4. Deep packet inspection + heuristics:
   ├─ Analyze TLS traffic patterns (timing, size)
   ├─ Fingerprint: Facebook traffic looks like X
   ├─ Block based on heuristics (not SNI)
   └─ Limitation: High false positive rate

Current status (Phase 8):
- ESNI not widely adopted (<1%)
- Focus on cleartext SNI (99% of traffic)
- ESNI mitigation: Future phase (Phase 10+)
```

---

#### Files to Create:
```
internal/parser/
├── tls_parser.go        # TLS ClientHello parser
├── tls_types.go         # TLS data structures
├── tls_filter.go        # TLS SNI filtering logic
└── tls_sni_extract.go   # SNI extraction helpers
```

---

### Sub-Task 8.3: HTTP Host Filtering (`internal/parser/http_parser.go`)

**Purpose:** Parse HTTP requests and extract Host header for domain filtering

**Core Concept:**
Plain HTTP (port 80) is unencrypted. The Host header in HTTP requests reveals the destination domain, allowing domain-based filtering for non-HTTPS traffic.

---

#### What to Create:

**1. HTTP Protocol Primer**

**HTTP Request Structure:**
```
HTTP Request (unencrypted, port 80):
GET /index.html HTTP/1.1\r\n
Host: www.example.com\r\n         ← TARGET: Extract this
User-Agent: Mozilla/5.0 ...\r\n
Accept: text/html,...\r\n
Connection: keep-alive\r\n
\r\n
(body, if any)

HTTP headers (line-by-line):
├─ Request line: GET /path HTTP/1.1
├─ Host: www.example.com (REQUIRED in HTTP/1.1)
├─ User-Agent: Browser info
├─ Accept: Content types
└─ Empty line (\r\n\r\n) = end of headers

Host header:
├─ Format: "Host: domain.com" or "Host: domain.com:8080"
├─ Purpose: Virtual hosting (single IP, multiple sites)
├─ Required: HTTP/1.1 mandates Host header
└─ Filtering: Extract domain, check blocklist
```

**HTTP vs HTTPS:**
```
HTTP (port 80):
├─ Unencrypted: Firewall sees all content
├─ Host header: Visible in plaintext
├─ Filtering: Easy (parse Host header)
└─ Usage: Declining (<20% of web traffic in 2026)

HTTPS (port 443):
├─ Encrypted: Firewall sees ciphertext
├─ SNI: Visible in TLS handshake (unencrypted)
├─ Host header: Encrypted (inside TLS tunnel)
├─ Filtering: Use SNI (not Host header)
└─ Usage: Dominant (>80% of web traffic in 2026)

Why HTTP still matters:
├─ IoT devices (many use HTTP)
├─ Internal corporate apps (no TLS needed)
├─ Legacy systems (old software, no HTTPS support)
└─ Local development (localhost, no certificates)
```

---

**2. HTTP Request Parser**

**Purpose:** Extract Host header from HTTP request

**Parsing Algorithm:**
```
Input: Raw HTTP packet bytes
Output: Host header value (domain name)

Steps:
1. Verify packet is HTTP:
   ├─ Check destination port: 80 (HTTP) or 8080 (alt HTTP)
   ├─ Check protocol: TCP
   └─ Check payload starts with HTTP method: GET, POST, PUT, ...

2. Parse request line:
   ├─ Format: METHOD /path HTTP/version\r\n
   ├─ Example: "GET /index.html HTTP/1.1\r\n"
   └─ Extract method (GET, POST, etc.)

3. Parse headers (line by line):
   ├─ Read until \r\n\r\n (double newline = end of headers)
   ├─ Split by \r\n (each line is one header)
   └─ Parse each header: "Name: Value"

4. Find Host header:
   ├─ Search for "Host:" (case-insensitive)
   ├─ Extract value: "www.example.com" or "www.example.com:8080"
   └─ Strip port if present: "www.example.com:8080" → "www.example.com"

5. Normalize domain:
   ├─ Lowercase: "Example.COM" → "example.com"
   ├─ Strip trailing dot: "example.com." → "example.com"
   └─ Return: "example.com"
```

**Parser Implementation:**
```
type HTTPParser struct {
  logger *logging.Logger
}

type HTTPRequest struct {
  Method  string            // GET, POST, PUT, etc.
  Path    string            // /index.html
  Version string            // HTTP/1.1
  Host    string            // www.example.com (extracted from Host header)
  Headers map[string]string // All headers
}

func (hp *HTTPParser) Parse(packet []byte) (*HTTPRequest, error) {
  // Convert to string for easier parsing
  data := string(packet)

  // Check if starts with HTTP method
  methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
  isHTTP := false
  for _, method := range methods {
    if strings.HasPrefix(data, method+" ") {
      isHTTP = true
      break
    }
  }

  if !isHTTP {
    return nil, fmt.Errorf("not an HTTP request")
  }

  // Split into lines
  lines := strings.Split(data, "\r\n")
  if len(lines) < 2 {
    return nil, fmt.Errorf("invalid HTTP request (too few lines)")
  }

  // Parse request line (first line)
  requestLine := lines[0]
  parts := strings.Split(requestLine, " ")
  if len(parts) != 3 {
    return nil, fmt.Errorf("invalid HTTP request line")
  }

  method := parts[0]
  path := parts[1]
  version := parts[2]

  // Parse headers
  headers := make(map[string]string)
  for i := 1; i < len(lines); i++ {
    line := lines[i]

    // Empty line = end of headers
    if line == "" {
      break
    }

    // Parse header: "Name: Value"
    colonIndex := strings.Index(line, ":")
    if colonIndex == -1 {
      continue  // Invalid header, skip
    }

    name := strings.TrimSpace(line[:colonIndex])
    value := strings.TrimSpace(line[colonIndex+1:])

    // Store header (case-insensitive key)
    headers[strings.ToLower(name)] = value
  }

  // Extract Host header
  host, exists := headers["host"]
  if !exists {
    return nil, fmt.Errorf("Host header missing")
  }

  // Strip port if present
  // Example: "www.example.com:8080" → "www.example.com"
  if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
    host = host[:colonIndex]
  }

  // Normalize domain
  host = strings.ToLower(strings.TrimSpace(host))
  host = strings.TrimSuffix(host, ".")

  return &HTTPRequest{
    Method:  method,
    Path:    path,
    Version: version,
    Host:    host,
    Headers: headers,
  }, nil
}
```

---

**3. Domain Matching Integration**

**HTTP Filtering:**
```
func (hp *HTTPParser) Filter(packet *Packet) (Verdict, error) {
  // Only process HTTP packets (port 80, 8080)
  if packet.DstPort != 80 && packet.DstPort != 8080 {
    return ALLOW, nil  // Not HTTP
  }

  // Parse HTTP request
  httpReq, err := hp.Parse(packet.Payload)
  if err != nil {
    // Not a valid HTTP request
    // Could be:
    // 1. HTTP response (not request)
    // 2. Malformed request
    // 3. Non-HTTP traffic on port 80
    return ALLOW, nil  // Skip filtering
  }

  // Extract Host header
  host := httpReq.Host

  // Check domain against blocklist
  match, rule := domainMatcher.Match(host)

  if match {
    // Domain blocked
    log.Info().
      Str("host", host).
      Str("method", httpReq.Method).
      Str("path", httpReq.Path).
      Str("rule", rule.Name).
      Str("client", packet.SrcIP).
      Msg("HTTP Host blocked")

    // Increment metrics
    metrics.IncrementCounter("firewall_domain_blocks_total", map[string]string{
      "protocol": "http_host",
      "domain":   host,
    })

    // Action: Send TCP RST (abort HTTP connection)
    return REJECT, nil  // TCP RST sent to client
  }

  // Domain allowed
  return ALLOW, nil
}
```

---

**4. HTTP Response Filtering (Optional)**

**Purpose:** Block HTTP responses from blocked domains

**Use Case:**
```
Scenario: Reverse proxy/CDN
├─ Client requests: http://cdn.example.com/file.js
├─ CDN responds with: 302 Redirect to http://blocked-site.com/file.js
├─ Problem: Original domain (cdn.example.com) allowed, redirect target (blocked-site.com) blocked
└─ Solution: Filter HTTP responses, check Location header

HTTP Response:
HTTP/1.1 302 Found\r\n
Location: http://blocked-site.com/file.js\r\n
Content-Length: 0\r\n
\r\n

Filter logic:
1. Parse HTTP response
2. Extract Location header (if present)
3. Check domain in Location against blocklist
4. If blocked: Drop response, block redirect
```

---

**5. User-Agent Filtering (Bonus)**

**Purpose:** Block specific applications or bots

**Use Case:**
```
Block download managers:
├─ User-Agent: "Internet Download Manager"
├─ User-Agent: "aria2/1.35.0"
├─ User-Agent: "curl/7.68.0"
└─ Action: Block (prevent bulk downloads)

Block bots:
├─ User-Agent: "bot", "crawler", "spider"
├─ Example: "Googlebot/2.1"
└─ Action: Block (prevent scraping)

Allow browsers:
├─ User-Agent: "Mozilla/5.0 ... Chrome/..."
├─ User-Agent: "Mozilla/5.0 ... Firefox/..."
└─ Action: Allow (legitimate browsing)

Implementation:
func (hp *HTTPParser) FilterUserAgent(req *HTTPRequest) bool {
  ua := strings.ToLower(req.Headers["user-agent"])

  // Block download managers
  blockedUA := []string{"idm", "aria2", "curl", "wget", "download manager"}
  for _, blocked := range blockedUA {
    if strings.Contains(ua, blocked) {
      return true  // Blocked
    }
  }

  return false  // Allowed
}
```

---

#### Files to Create:
```
internal/parser/
├── http_parser.go       # HTTP request parser
├── http_types.go        # HTTP data structures
├── http_filter.go       # HTTP Host filtering logic
└── http_response_filter.go  # HTTP response filtering (optional)
```

---

### Sub-Task 8.4: Wildcard Domain Matching (`internal/matcher/domain_matcher.go`)

**Purpose:** Efficient domain matching with wildcard support (*.facebook.com)

**Core Concept:**
Domain matching must be fast (100K lookups/sec) and flexible (exact, wildcard, regex). Trie data structure provides O(k) lookup where k=domain length.

---

#### What to Create:

**1. Trie Data Structure**

**What is a Trie:**
```
Trie (prefix tree):
├─ Each node represents a character
├─ Path from root to leaf = complete string
├─ Shared prefixes reuse nodes (space efficient)
└─ Lookup time: O(k) where k=string length

Example: Store domains [facebook.com, fb.com, facebook.net]

Trie structure:
                 ROOT
                  |
          ┌───────┴────────┐
          │                │
        [f]              [other]
          |
        [a]
          |
        [c]
          |
        [e]
          |
        [b]
          |
        [o]
          |
        [o]
          |
        [k]
          |
        [.]
          |
    ┌───[c]───┬────[n]
    │         │
  [o]       [e]
    │         │
  [m]       [t]
  (END)    (END)
  Rule:    Rule:
  Block_   Block_
  Facebook Facebook_Net

fb.com shares prefix 'f' with facebook.com (space efficient)
```

**Trie Node:**
```
type TrieNode struct {
  children map[rune]*TrieNode  // Child nodes (char → node)
  isEnd    bool                // Is this the end of a domain?
  rule     *Rule               // Associated firewall rule (if isEnd=true)
  wildcard bool                // Is this a wildcard node? (*.facebook.com)
}

type DomainTrie struct {
  root  *TrieNode
  count int  // Number of domains stored
  mu    sync.RWMutex
}
```

---

**2. Trie Insert (Add Domain)**

**Algorithm:**
```
Insert domain "facebook.com":

1. Start at root node
2. For each character in "facebook.com":
   ├─ Check if child exists for this character
   ├─ If yes: Move to child
   └─ If no: Create new child node

3. After last character:
   ├─ Mark node as end (isEnd = true)
   └─ Attach rule (Block_Facebook)

Example:
Insert "facebook.com":
  ROOT → f (new) → a (new) → c (new) → e (new) → b (new) → o (new) → o (new) → k (new) → . (new) → c (new) → o (new) → m (new, isEnd=true)

Insert "fb.com":
  ROOT → f (exists!) → b (new) → . (new) → c (new) → o (new) → m (new, isEnd=true)
  (Reuses 'f' node from facebook.com)
```

**Implementation:**
```
func (dt *DomainTrie) Insert(domain string, rule *Rule) {
  dt.mu.Lock()
  defer dt.mu.Unlock()

  // Normalize domain
  domain = strings.ToLower(domain)
  domain = strings.TrimSuffix(domain, ".")

  // Handle wildcard: *.facebook.com
  isWildcard := false
  if strings.HasPrefix(domain, "*.") {
    isWildcard = true
    domain = domain[2:]  // Strip "*."
  }

  // Start at root
  node := dt.root

  // Insert each character
  for _, ch := range domain {
    // Check if child exists
    if node.children[ch] == nil {
      // Create new child
      node.children[ch] = &TrieNode{
        children: make(map[rune]*TrieNode),
      }
    }

    // Move to child
    node = node.children[ch]
  }

  // Mark as end of domain
  node.isEnd = true
  node.rule = rule
  node.wildcard = isWildcard

  dt.count++
}
```

---

**3. Trie Lookup (Match Domain)**

**Algorithm:**
```
Lookup domain "www.facebook.com":

1. Exact match attempt:
   ├─ Traverse: w → w → w → . → f → a → c → e → b → o → o → k → . → c → o → m
   ├─ Check if node.isEnd = true
   └─ Result: NOT FOUND (www.facebook.com not in trie)

2. Wildcard match attempt:
   ├─ Extract suffix: facebook.com (remove "www.")
   ├─ Traverse: f → a → c → e → b → o → o → k → . → c → o → m
   ├─ Check if node.isEnd = true AND node.wildcard = true
   └─ Result: FOUND (*.facebook.com matches)

3. Return match result:
   └─ (true, Block_Facebook_Wildcard)
```

**Implementation:**
```
func (dt *DomainTrie) Match(domain string) (bool, *Rule) {
  dt.mu.RLock()
  defer dt.mu.RUnlock()

  // Normalize domain
  domain = strings.ToLower(domain)
  domain = strings.TrimSuffix(domain, ".")

  // 1. Exact match
  if match, rule := dt.exactMatch(domain); match {
    return true, rule
  }

  // 2. Wildcard match (try all suffixes)
  // Example: www.api.facebook.com
  //   Try: api.facebook.com → MISS
  //   Try: facebook.com → MATCH (*.facebook.com)
  parts := strings.Split(domain, ".")
  for i := 1; i < len(parts); i++ {
    suffix := strings.Join(parts[i:], ".")
    if match, rule := dt.wildcardMatch(suffix); match {
      return true, rule
    }
  }

  // No match
  return false, nil
}

func (dt *DomainTrie) exactMatch(domain string) (bool, *Rule) {
  node := dt.root

  // Traverse trie
  for _, ch := range domain {
    if node.children[ch] == nil {
      return false, nil  // Path doesn't exist
    }
    node = node.children[ch]
  }

  // Check if this is end of a domain
  if node.isEnd {
    return true, node.rule
  }

  return false, nil
}

func (dt *DomainTrie) wildcardMatch(domain string) (bool, *Rule) {
  node := dt.root

  // Traverse trie
  for _, ch := range domain {
    if node.children[ch] == nil {
      return false, nil
    }
    node = node.children[ch]
  }

  // Check if this is end AND wildcard
  if node.isEnd && node.wildcard {
    return true, node.rule
  }

  return false, nil
}
```

---

**4. Regex Support**

**Purpose:** Advanced pattern matching (not just wildcards)

**Regex Patterns:**
```
Common regex patterns:

Block all .ads. subdomains:
├─ Regex: .*\\.ads\\..*
├─ Matches: tracking.ads.google.com, server.ads.facebook.com
└─ Implementation: Compile regex, test domain

Block numbered subdomains (CDNs):
├─ Regex: cdn[0-9]+\\.example\\.com
├─ Matches: cdn1.example.com, cdn2.example.com, ...
└─ Use case: Block CDN nodes individually

Block specific TLDs:
├─ Regex: .*\\.(tk|ml|ga|cf|gq)$
├─ Matches: spam.tk, malware.ml, phishing.ga
└─ Use case: Block free TLD domains (high spam rate)
```

**Implementation:**
```
type RegexMatcher struct {
  patterns []*regexp.Regexp  // Compiled regex patterns
  rules    []*Rule           // Associated rules
  mu       sync.RWMutex
}

func (rm *RegexMatcher) AddPattern(pattern string, rule *Rule) error {
  re, err := regexp.Compile(pattern)
  if err != nil {
    return fmt.Errorf("invalid regex: %w", err)
  }

  rm.mu.Lock()
  defer rm.mu.Unlock()

  rm.patterns = append(rm.patterns, re)
  rm.rules = append(rm.rules, rule)

  return nil
}

func (rm *RegexMatcher) Match(domain string) (bool, *Rule) {
  rm.mu.RLock()
  defer rm.mu.RUnlock()

  // Test each regex pattern
  for i, pattern := range rm.patterns {
    if pattern.MatchString(domain) {
      return true, rm.rules[i]
    }
  }

  return false, nil
}

Integration with domain matcher:
func (dm *DomainMatcher) Match(domain string) (bool, *Rule) {
  // 1. Try trie (exact + wildcard, fast)
  if match, rule := dm.trie.Match(domain); match {
    return true, rule
  }

  // 2. Try regex (slower, only if trie misses)
  if match, rule := dm.regex.Match(domain); match {
    return true, rule
  }

  // No match
  return false, nil
}
```

---

**5. Performance Optimization**

**Benchmarks:**
```
Blocklist size: 10,000 domains
Test domain: "www.facebook.com"

Naive linear search:
for each domain in blocklist:
  if domain == "www.facebook.com": MATCH
Time: O(n) = 10,000 comparisons × 0.5μs = 5ms (too slow!)
Throughput: 200 lookups/sec (unacceptable)

Trie search:
Traverse: w → w → w → . → f → ... → m
Time: O(k) = 18 characters × 0.05μs = 0.9μs (fast!)
Throughput: 1,111,000 lookups/sec per core

Improvement: 5,555× faster!

Hash map search (alternative):
map["www.facebook.com"] → lookup
Time: O(1) = 0.2μs (fastest!)
Limitation: No wildcard support (only exact matches)

Hybrid approach:
1. Hash map for exact matches (0.2μs)
2. Trie for wildcard matches (0.9μs)
3. Regex for complex patterns (10μs)
Result: Best balance (speed + flexibility)
```

**Memory Usage:**
```
Trie memory calculation:

10,000 domains, avg length 20 chars:
├─ Nodes: ~45,000 (avg 4.5 nodes per domain, sharing)
├─ Node size: 56 bytes (map[rune]*TrieNode + flags + pointer)
├─ Total: 45,000 × 56 = 2.52MB
└─ Result: 2.5MB for 10,000 domains (acceptable)

Hash map memory:
10,000 domains, avg length 20 chars:
├─ Keys: 10,000 × 20 = 200KB
├─ Values: 10,000 × 8 = 80KB (pointers)
├─ Overhead: ~100KB (hash table)
└─ Total: ~380KB (smaller, but no wildcards)

Trie advantages:
├─ Wildcard support (*.domain.com)
├─ Prefix search (find all facebook.*)
└─ Shared prefixes (space efficient)

Hash map advantages:
├─ Faster lookup (O(1) vs O(k))
├─ Lower memory (no tree structure)
└─ Simpler implementation

Choice: Trie for flexibility, hash map for speed (hybrid)
```

---

#### Files to Create:
```
internal/matcher/
├── domain_matcher.go    # Domain matcher coordinator (trie + regex)
├── trie.go              # Trie data structure
├── trie_node.go         # Trie node definition
├── regex_matcher.go     # Regex pattern matching
└── wildcard.go          # Wildcard matching helpers
```

---

### Sub-Task 8.5: DNS Redirect to Captive Portal (`internal/captive/portal.go`)

**Purpose:** Redirect blocked DNS queries to captive portal instead of silent drop

**Core Concept:**
Instead of dropping DNS queries (timeout), inject fake DNS response pointing to captive portal IP. User sees block page explaining why access was denied.

---

#### What to Create:

**1. DNS Response Injection**

**Purpose:** Craft and inject fake DNS response packet

**Injection Flow:**
```
User queries DNS: "What is facebook.com?"
        ↓
Firewall intercepts query
        ↓
Firewall checks blocklist: facebook.com → BLOCKED
        ↓
Firewall crafts fake DNS response:
  "facebook.com = 192.168.1.1 (captive portal)"
        ↓
Firewall injects fake response into network
        ↓
User receives response: facebook.com = 192.168.1.1
        ↓
User's browser navigates to http://192.168.1.1
        ↓
Captive portal web server shows block page
```

**Fake DNS Response Packet:**
```
Craft DNS response matching original query:

Original query:
┌─────────────────────────────────────┐
│ Transaction ID: 0x1234              │
│ Flags: 0x0100 (query, recursion)   │
│ Questions: 1                        │
│ QNAME: facebook.com                 │
│ QTYPE: A (IPv4)                     │
└─────────────────────────────────────┘

Fake response:
┌─────────────────────────────────────┐
│ Transaction ID: 0x1234 (SAME!)      │
│ Flags: 0x8180 (response, no error) │
│ Questions: 1                        │
│ Answers: 1                          │
│ QNAME: facebook.com (echoed)        │
│ QTYPE: A                            │
│ Answer:                             │
│   NAME: facebook.com                │
│   TYPE: A                           │
│   CLASS: IN                         │
│   TTL: 60 (1 minute)                │
│   RDLENGTH: 4                       │
│   RDATA: 192.168.1.1 (captive)      │
└─────────────────────────────────────┘

Key points:
├─ Transaction ID must match (client correlates response with query)
├─ Question section echoed (RFC compliance)
├─ Answer points to captive portal IP
└─ Low TTL (60s) prevents long-term caching
```

**Implementation:**
```
type DNSRedirector struct {
  captivePortalIP string  // 192.168.1.1
  logger          *logging.Logger
}

func (dr *DNSRedirector) InjectFakeResponse(
  query *DNSQuery,
  originalPacket *Packet,
) error {
  // Build fake DNS response
  response := dr.buildFakeResponse(query, dr.captivePortalIP)

  // Craft network packet (IP + UDP + DNS)
  packet := dr.craftPacket(
    originalPacket.DstIP,   // Source: DNS server (spoofed)
    originalPacket.SrcIP,   // Destination: Client
    originalPacket.DstPort, // Source port: 53 (DNS)
    originalPacket.SrcPort, // Destination port: client port
    response,               // Payload: Fake DNS response
  )

  // Inject packet into network (via SafeOps)
  err := safeops.InjectPacket(packet)
  if err != nil {
    return fmt.Errorf("failed to inject DNS response: %w", err)
  }

  log.Info().
    Str("domain", query.Domain).
    Str("client", originalPacket.SrcIP).
    Str("redirect_ip", dr.captivePortalIP).
    Msg("Injected fake DNS response (captive portal redirect)")

  metrics.IncrementCounter("firewall_domain_redirects_total")

  return nil
}

func (dr *DNSRedirector) buildFakeResponse(query *DNSQuery, captiveIP string) []byte {
  buf := make([]byte, 0, 512)

  // DNS Header
  buf = binary.BigEndian.AppendUint16(buf, query.TransactionID)  // ID (match query)
  buf = binary.BigEndian.AppendUint16(buf, 0x8180)               // Flags (response)
  buf = binary.BigEndian.AppendUint16(buf, 1)                    // Questions: 1
  buf = binary.BigEndian.AppendUint16(buf, 1)                    // Answers: 1
  buf = binary.BigEndian.AppendUint16(buf, 0)                    // Authority: 0
  buf = binary.BigEndian.AppendUint16(buf, 0)                    // Additional: 0

  // Question section (echo from query)
  buf = append(buf, dr.encodeDomainName(query.Domain)...)
  buf = binary.BigEndian.AppendUint16(buf, query.QueryType)      // QTYPE
  buf = binary.BigEndian.AppendUint16(buf, query.QueryClass)     // QCLASS

  // Answer section
  buf = append(buf, 0xC0, 0x0C)                          // NAME (pointer to offset 12)
  buf = binary.BigEndian.AppendUint16(buf, 1)            // TYPE: A (IPv4)
  buf = binary.BigEndian.AppendUint16(buf, 1)            // CLASS: IN
  buf = binary.BigEndian.AppendUint32(buf, 60)           // TTL: 60 seconds
  buf = binary.BigEndian.AppendUint16(buf, 4)            // RDLENGTH: 4 bytes

  // RDATA: Captive portal IP (192.168.1.1)
  ipParts := strings.Split(captiveIP, ".")
  for _, part := range ipParts {
    val, _ := strconv.Atoi(part)
    buf = append(buf, byte(val))
  }

  return buf
}

func (dr *DNSRedirector) encodeDomainName(domain string) []byte {
  // Encode domain name: facebook.com → [8]facebook[3]com[0]
  parts := strings.Split(domain, ".")
  buf := []byte{}

  for _, part := range parts {
    buf = append(buf, byte(len(part)))  // Length prefix
    buf = append(buf, []byte(part)...)  // Label
  }

  buf = append(buf, 0)  // Null terminator

  return buf
}
```

---

**2. Captive Portal Web Server**

**Purpose:** HTTP server showing block page to users

**Web Server:**
```
Captive portal components:
├─ HTTP server (port 80): Serve block page
├─ HTML template: Block page with reason
├─ Static assets: CSS, logo, icons
└─ Certificate installation: Allow HTTPS captive portal

HTTP server:
Listen on: 192.168.1.1:80 (captive portal IP)

Routes:
├─ GET /: Block page (HTML)
├─ GET /block-info: JSON API (for automation)
├─ GET /certificate: Download root CA (for HTTPS inspection)
└─ GET /static/*: CSS, images, favicon

Block page response:
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
  <title>Access Denied - SafeOps Firewall</title>
  <style>
    body { font-family: Arial; background: #f5f5f5; }
    .container { max-width: 600px; margin: 100px auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .icon { text-align: center; font-size: 64px; color: #d32f2f; }
    h1 { text-align: center; color: #333; }
    .info { background: #f9f9f9; padding: 20px; border-radius: 5px; margin: 20px 0; }
    .label { font-weight: bold; color: #666; }
    .value { color: #333; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🚫</div>
    <h1>Access Denied</h1>
    <p style="text-align: center; color: #666;">
      The website you requested has been blocked by firewall policy.
    </p>

    <div class="info">
      <div><span class="label">Blocked Domain:</span> <span class="value">facebook.com</span></div>
      <div><span class="label">Rule:</span> <span class="value">Block_Social_Media</span></div>
      <div><span class="label">Category:</span> <span class="value">Social Networking</span></div>
      <div><span class="label">Reason:</span> <span class="value">Corporate policy prohibits access to social media during work hours</span></div>
      <div><span class="label">Time:</span> <span class="value">2026-01-22 10:30:45</span></div>
      <div><span class="label">Your IP:</span> <span class="value">192.168.1.100</span></div>
    </div>

    <p style="text-align: center; color: #999; font-size: 14px;">
      If you believe this is an error, contact IT support:<br>
      Email: itsupport@company.com | Phone: +1-555-0123
    </p>
  </div>
</body>
</html>
```

**Implementation:**
```
type CaptivePortal struct {
  server *http.Server
  config CaptivePortalConfig
  logger *logging.Logger
}

type CaptivePortalConfig struct {
  ListenAddr string  // 192.168.1.1:80
  TLSEnabled bool    // Serve HTTPS?
  CertPath   string  // Path to TLS certificate
  KeyPath    string  // Path to TLS private key
}

func (cp *CaptivePortal) Start() error {
  // Setup HTTP routes
  mux := http.NewServeMux()
  mux.HandleFunc("/", cp.handleBlockPage)
  mux.HandleFunc("/block-info", cp.handleBlockInfo)
  mux.HandleFunc("/certificate", cp.handleCertificate)
  mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

  // Create HTTP server
  cp.server = &http.Server{
    Addr:    cp.config.ListenAddr,
    Handler: mux,
  }

  // Start server
  log.Info().
    Str("addr", cp.config.ListenAddr).
    Msg("Captive portal HTTP server started")

  if cp.config.TLSEnabled {
    return cp.server.ListenAndServeTLS(cp.config.CertPath, cp.config.KeyPath)
  } else {
    return cp.server.ListenAndServe()
  }
}

func (cp *CaptivePortal) handleBlockPage(w http.ResponseWriter, r *http.Request) {
  // Extract original domain from request
  // (could be in query param: /?blocked=facebook.com)
  blockedDomain := r.URL.Query().Get("blocked")
  if blockedDomain == "" {
    blockedDomain = r.Host  // Fallback: Use Host header
  }

  // Lookup block reason (from database or cache)
  blockInfo := cp.getBlockInfo(blockedDomain, r.RemoteAddr)

  // Render HTML template
  tmpl, err := template.ParseFiles("templates/block_page.html")
  if err != nil {
    http.Error(w, "Internal server error", 500)
    return
  }

  err = tmpl.Execute(w, blockInfo)
  if err != nil {
    log.Error().Err(err).Msg("Failed to render block page")
  }

  // Log captive portal access
  metrics.IncrementCounter("firewall_captive_portal_requests_total")
}

func (cp *CaptivePortal) handleBlockInfo(w http.ResponseWriter, r *http.Request) {
  // JSON API for automation
  blockedDomain := r.URL.Query().Get("domain")
  clientIP := r.RemoteAddr

  blockInfo := cp.getBlockInfo(blockedDomain, clientIP)

  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(blockInfo)
}
```

---

**3. Dynamic Block Information**

**Purpose:** Show user why their access was blocked

**Block Info Retrieval:**
```
Problem: User sees "facebook.com blocked" but doesn't know why

Solution: Show detailed block info:
├─ Blocked domain: facebook.com
├─ Matched rule: Block_Social_Media
├─ Rule category: Social Networking
├─ Block reason: Corporate policy (work hours)
├─ Block time: 2026-01-22 10:30:45
├─ Client IP: 192.168.1.100
└─ Contact info: IT support email/phone

Where to get block info:
1. Rule metadata (from firewall.toml):
   [[rule]]
   name = "Block_Social_Media"
   dst_domain = "*.facebook.com"
   action = "REDIRECT"
   redirect_ip = "192.168.1.1"
   category = "Social Networking"
   reason = "Corporate policy prohibits social media during work hours"
   support_contact = "itsupport@company.com"

2. Block event log (recent blocks):
   - Store last 1000 blocks in memory (ring buffer)
   - Include: domain, client IP, rule, timestamp
   - Captive portal queries this log

3. Database (persistent):
   - Store all blocks in PostgreSQL
   - Query: SELECT * FROM blocks WHERE domain = ? ORDER BY timestamp DESC LIMIT 1
   - Use for historical analysis
```

---

**4. Certificate Installation Page**

**Purpose:** Allow users to install root CA for HTTPS captive portal

**Why Needed:**
```
Problem: HTTPS captive portal
├─ User tries: https://facebook.com
├─ Firewall redirects: DNS facebook.com → 192.168.1.1
├─ User's browser connects: https://192.168.1.1
├─ Browser expects: facebook.com certificate
├─ Portal presents: 192.168.1.1 certificate (or self-signed)
├─ Browser error: "Certificate invalid" (not facebook.com)
└─ User sees: Security warning instead of block page

Solution: Install root CA certificate
├─ Firewall has root CA certificate (SafeOps Root CA)
├─ All captive portal certs signed by this CA
├─ User installs root CA (trusts it)
├─ Browser accepts captive portal certs (signed by trusted CA)
└─ Block page shows without security warning

Certificate installation page:
GET /certificate

HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Install SafeOps Root CA</title></head>
<body>
  <h1>Install SafeOps Root CA Certificate</h1>
  <p>To see block pages for HTTPS sites without security warnings, install the SafeOps Root CA certificate.</p>

  <h2>Windows:</h2>
  <ol>
    <li><a href="/certificate/safeops-root-ca.crt">Download certificate</a></li>
    <li>Double-click certificate file</li>
    <li>Click "Install Certificate"</li>
    <li>Choose "Trusted Root Certification Authorities"</li>
    <li>Click "Finish"</li>
  </ol>

  <h2>macOS:</h2>
  <ol>
    <li><a href="/certificate/safeops-root-ca.crt">Download certificate</a></li>
    <li>Double-click certificate file</li>
    <li>Enter password to add to Keychain</li>
    <li>Open Keychain Access</li>
    <li>Right-click certificate → "Get Info"</li>
    <li>Expand "Trust" → Set to "Always Trust"</li>
  </ol>

  <p><strong>Note:</strong> This certificate allows the firewall to show block pages for HTTPS sites. It does not allow decryption of your traffic.</p>
</body>
</html>
```

---

**5. HTTPS Redirect Handling**

**Purpose:** Handle HTTPS requests to blocked domains

**Challenge:**
```
Problem: HTTPS redirect
├─ DNS redirected: facebook.com → 192.168.1.1
├─ User's browser: https://facebook.com (HTTPS!)
├─ Browser connects to 192.168.1.1:443 (HTTPS port)
├─ Captive portal: Doesn't have HTTPS server (only HTTP:80)
├─ Browser: Connection refused
└─ User sees: "Unable to connect" instead of block page

Solution options:

Option 1: HTTPS captive portal
├─ Captive portal listens on 443 (HTTPS)
├─ Presents certificate (self-signed or CA-signed)
├─ Shows block page over HTTPS
├─ Requires: User install root CA (or accept warning)
└─ Result: Block page shown (HTTPS)

Option 2: HTTP redirect
├─ Captive portal listens on 443 (HTTPS)
├─ Sends HTTP 301 redirect: https://192.168.1.1 → http://192.168.1.1
├─ Browser follows redirect (HTTP)
├─ Block page shown over HTTP
└─ Result: Block page shown (HTTP)

Option 3: TLS SNI drop (current Phase 8)
├─ Firewall drops TLS handshake (SNI: facebook.com)
├─ Browser receives TCP RST (connection reset)
├─ Browser shows: "Connection reset"
├─ No block page shown (silent drop)
└─ Result: User knows blocked, but no reason shown

Recommendation (Phase 8):
- Option 3 (TLS SNI drop) for simplicity
- Option 1 (HTTPS captive portal) for Phase 9 (advanced)
```

---

#### Files to Create:
```
internal/captive/
├── portal.go            # Captive portal HTTP server
├── dns_injector.go      # DNS response injection
├── block_page.go        # Block page HTML generation
├── certificate_handler.go  # Root CA download handler
└── block_info.go        # Block information retrieval

templates/
└── block_page.html      # HTML template for block page

static/
├── style.css            # CSS stylesheet
├── logo.png             # SafeOps logo
└── favicon.ico          # Favicon
```

---

## 📊 Phase 8 Success Criteria

**By end of Phase 8, the firewall must demonstrate:**

1. ✅ **DNS Query Filtering:**
   - Parse DNS queries (extract domain)
   - Block domains at DNS stage (facebook.com → DROP)
   - Redirect to captive portal (twitter.com → 192.168.1.1)
   - DNS response caching (domain → IP mapping for DoH bypass)

2. ✅ **TLS SNI Extraction:**
   - Parse TLS ClientHello (extract SNI)
   - Block HTTPS by domain (facebook.com → TCP RST)
   - Works with TLS 1.2 and 1.3 (cleartext SNI)
   - Logging includes SNI (visibility into HTTPS traffic)

3. ✅ **HTTP Host Filtering:**
   - Parse HTTP requests (extract Host header)
   - Block HTTP by domain (example.com → TCP RST)
   - User-Agent filtering (block download managers)
   - HTTP response filtering (block redirects)

4. ✅ **Wildcard Domain Matching:**
   - Trie data structure (O(k) lookup, k=domain length)
   - Exact match (facebook.com)
   - Wildcard match (*.facebook.com matches www.facebook.com)
   - Regex support (advanced patterns)
   - Performance: 1M lookups/sec per core (<1μs per lookup)

5. ✅ **DNS Redirect to Captive Portal:**
   - Inject fake DNS response (domain → 192.168.1.1)
   - Captive portal HTTP server (block page)
   - Dynamic block information (show user why blocked)
   - Certificate installation page (for HTTPS captive portal)

---

## 📈 Phase 8 Metrics

**Prometheus Metrics:**
```
# Domain filtering
firewall_domain_blocks_total{protocol="dns|tls_sni|http_host"} counter
firewall_domain_redirects_total counter
firewall_domain_blocks_by_domain{domain="facebook.com"} counter

# Domain matcher performance
firewall_domain_matcher_lookups_total counter
firewall_domain_matcher_lookup_duration_seconds histogram
firewall_domain_matcher_trie_nodes gauge
firewall_domain_matcher_trie_memory_bytes gauge

# Captive portal
firewall_captive_portal_requests_total counter
firewall_captive_portal_unique_ips gauge
```

---

## 🚀 Next Steps After Phase 8

After Phase 8 completion, proceed to:
- **Phase 9:** Production Deployment (Docker, Kubernetes, systemd, CI/CD)
- **Phase 10:** Advanced Features (ML-based filtering, HTTPS inspection, Encrypted SNI handling)
- **Phase 11:** Enterprise Integration (Active Directory, SIEM, Threat Intelligence feeds)

**Estimated Total Time for Phase 8:** 2 weeks

---

**END OF PHASE 8 DOCUMENTATION**