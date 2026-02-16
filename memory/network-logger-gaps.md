# Network Logger IDS/IPS Gaps Analysis

## Current State

The SafeOps network logger (`src/network_logger/`) captures comprehensive packet data and produces `network_packets_master.jsonl` with:

✅ **Current Strengths**:
- Full packet capture (all protocols, all ports)
- Layer 2-4 headers (Ethernet, IP, TCP/UDP)
- Application layer parsing (DNS, HTTP, TLS)
- Flow tracking (flow_id, direction, packet/byte counters)
- Process correlation (PID, name, exe path)
- GeoIP enrichment (country, city, ASN)
- TLS decryption (ClientHello, ServerHello, SNI)
- Smart deduplication (preserves alerts, filters spam)
- 5-minute rolling logs for IDS/IPS analysis

---

## IDS/IPS Gap Analysis

### ❌ **CRITICAL GAPS** (Block Threat Detection)

#### 1. **Missing JA3/JA3S TLS Fingerprinting**
- **Why It Matters**: Industry standard for identifying TLS client/server fingerprints even with encrypted traffic
- **Use Case**: Detect malware C2 beacons with consistent TLS signatures; identify trojan families
- **Impact**: ~20-30% of modern malware uses distinctive TLS fingerprints
- **What's Missing**:
  - JA3 hash (from ClientHello: version, ciphers, extensions, curves, formats)
  - JA3S hash (from ServerHello: version, cipher, extensions)
  - Crowd-sourced malware JA3 database correlation

#### 2. **No ALPN Protocol Identification**
- **Why It Matters**: Detects HTTP/2, HTTP/3, gRPC, QUIC tunneling, and obfuscated protocols
- **Use Case**: Catch DoH (DNS-over-HTTPS), malware using HTTP/2 for C2, tunnel evasion
- **Current Gap**: ALPN is parsed in TLSClientHello but not surfaced in IDS logs
- **Risk**: Malware exfiltrating data via ALPN-selected protocols goes undetected

#### 3. **Missing Payload Signatures for Detection**
- **Why It Matters**: IDS needs raw payload (hex) + decoded preview to match malware signatures
- **Current State**: Full 1600-byte payload is captured but NOT included in IDS log output
- **Gap**: `IDSLog` struct only includes DNS, HTTP, TLS metadata—no `payload` field
- **Impact**: Cannot detect:
  - Protocol anomalies (binary data on HTTP port)
  - Shellcode injection patterns
  - Custom protocol beacons
  - Encrypted payload anomalies

#### 4. **Connection State Machine Missing**
- **Why It Matters**: Professional IDS requires TCP state tracking (SYN_SENT, ESTABLISHED, TIME_WAIT, RST, etc.)
- **Current State**: `flow_context.flow_state` exists but only shows "forward" | "backward"
- **Gap**: No state tracking (whether connection is:
  - Attempting (SYN-only)
  - Established (SYN-ACK completed)
  - Half-open (SYN without response)
  - Abnormally terminated
- **Impact**: Cannot detect:
  - Port scanning
  - SYN floods
  - Connection resets
  - Hanging connections

#### 5. **No Packet Loss / RTT / Retransmission Tracking**
- **Why It Matters**: Detect network manipulation, proxy interference, DDoS patterns
- **Missing Fields**:
  - TCP retransmission counter
  - Round-trip time (RTT) estimates
  - Sequence number gaps
  - Out-of-order packet detection
- **Impact**: Cannot identify:
  - Proxy interception
  - Packet injection/manipulation
  - DDoS responses
  - Man-in-the-middle attacks

#### 6. **No Anomaly Score / Risk Assessment**
- **Why It Matters**: Professional IDS outputs risk levels, not just raw data
- **Current State**: Raw packet data only
- **Missing**:
  - Severity/priority field
  - Confidence score
  - Anomaly detection baseline (unusual ports, unusual payload size, geographic anomalies)
  - Rule match information
- **Impact**: Requires external system to score threats—slows incident response

---

### ⚠️ **HIGH-PRIORITY GAPS** (Limit Advanced Detection)

#### 7. **No DNS Anomaly Detection**
- **Current DNS Data**: Name, type, class, TTL, answers only
- **Missing**:
  - DNS response time / TTL anomalies
  - Subdomain explosion (DNS tunneling detection)
  - Null response rates (no-such-domain abuse)
  - DNS query size anomalies
  - EDNS extensions (DNS-over-TCP, DNSSEC validation state)
  - Query entropy (DGA domain detection prep)

#### 8. **Missing MIME Type / Content-Type Analysis**
- **Current HTTP Data**: Headers captured but not parsed for anomalies
- **Missing**:
  - Content-Type classification (application/x-executable, image/jpeg but actually exe, etc.)
  - Suspicious Content-Disposition patterns
  - Archive files (zip, rar, 7z) in HTTP responses
  - Encryption headers (Content-Encoding: gzip, deflate mismatches)
- **Impact**: Cannot detect:
  - Drive-by downloads
  - Encrypted payload downloads
  - Polyglot files

#### 9. **No Session Reassembly / Fragment Tracking**
- **Why It Matters**: IDS needs to track packet fragments and TCP streams
- **Missing**:
  - IP fragment reassembly tracking (is this a fragmented packet?)
  - TCP segment ordering (is this out-of-sequence?)
  - Overall payload reconstruction hint (should be sent to reassembly layer)
- **Impact**: Fragmentation-based IDS evasion goes undetected

#### 10. **No SSL Certificate Validation Errors**
- **Current TLS Data**: SNI, cipher, version captured
- **Missing**:
  - Certificate chain validation failures
  - Self-signed certificate detection
  - Expired certificate usage
  - Subject/SAN mismatches (mismatched SNI vs cert CN)
  - Renegotiation behavior
- **Impact**: Cannot detect:
  - MITM attacks with rogue certificates
  - Malware using self-signed certs
  - Certificate-based C2

#### 11. **No MAC Address Spoofing Detection**
- **Current State**: MAC addresses logged per packet
- **Missing**:
  - MAC vendor validation (intel-signature MAC sending from non-intel source)
  - MAC address change detection (same IP, different MAC)
  - Duplicate MAC detection (two hosts claiming same MAC)
- **Impact**: Cannot detect:
  - ARP spoofing
  - MAC-layer attacks
  - Rogue device injection

---

### 📊 **MEDIUM-PRIORITY GAPS** (Improve Correlation & Context)

#### 12. **No HTTP Body/Payload Sampling**
- **Current**: BodyPreview (text) is captured but BodyLength only
- **Missing**:
  - HTTP body hex dump (for binary payloads)
  - Content hash (MD5/SHA256) of response bodies for deduplication
  - Multipart form data parsing
- **Use Case**: Detect exfiltration patterns, malware uploads, C2 beacons with specific payloads

#### 13. **No Traffic Directionality Metrics**
- **Current Flow Data**: forward vs backward direction
- **Missing**:
  - bytes_orig_sent, bytes_orig_rcvd (for each direction separately)
  - Asymmetric traffic (100MB upload, 10KB download = unusual)
  - Direction switch counts (multiple direction reversals = interactive C2)
- **Impact**: Cannot detect:
  - Data exfiltration patterns
  - Interactive reverse shells
  - Tunnel endpoints with skewed ratios

#### 14. **No Geolocation-Based Alerts**
- **Current State**: Source/destination geolocation enriched
- **Missing**:
  - Country change alerts (IP went from US to China in 1 second = VPN/proxy)
  - Distance/velocity check (impossible travel detection)
  - Unusual country pair combinations
  - Sanctioned country/ASN detection
- **Impact**: Slower detection of compromised accounts with malicious access

#### 15. **No Process Tree / Parent-Child Correlation**
- **Current Process Data**: PID, name, exe, cmdline
- **Missing**:
  - Parent PID (ppid)
  - Process tree depth
  - Command line args parsing (is this rundll32.exe with suspicious DLL?)
  - Process creation time
- **Impact**: Cannot detect:
  - Process injection
  - Living-off-the-land attacks (rundll32 abuse)
  - Lateral movement paths

#### 16. **No Protocol Anomaly Scoring**
- **Why It Matters**: Port 443 should be HTTPS; port 443 with HTTP traffic = anomaly
- **Missing**:
  - Protocol mismatch score (HTTP on HTTPS port, etc.)
  - Unusual port/protocol combinations
  - Rapid protocol switching
- **Impact**: Malware using port masquerading (SSH protocol on port 443, etc.) goes undetected

---

### 📝 **LOWER-PRIORITY GAPS** (Nice-to-Have)

#### 17. **No FTP/SMTP/SSH Command Logging**
- **Why It Matters**: These protocols have application-level commands worth logging
- **Missing**:
  - FTP commands (USER, PASS, RETR, STOR)
  - SMTP commands and RCPT TO addresses
  - SSH key exchange algorithms
  - SFTP file operations
- **Current**: Only generic app protocol detection

#### 18. **No Whois/RIPE/APNIC Enrichment**
- **Current GeoIP**: Country, city, ASN
- **Missing**:
  - Organization name from ASN
  - WHOIS registration contact info
  - IP reputation score (from Abuse.net, etc.)
  - BGP announcements (is this IP actually routed?)
- **Impact**: Slower threat intel lookups

#### 19. **No PCAP Export Trigger**
- **Why It Matters**: IDS alerts should link to full packet capture
- **Missing**:
  - "Extract PCAP from master log" mechanism
  - Ring buffer for immediate packet availability
  - Hash references to packet capture files
- **Current**: Only JSONL logs; forensics requires re-capturing

#### 20. **No CVE / Vulnerability Scoring**
- **Missing**:
  - HTTP User-Agent → known vulnerable software detection
  - TLS version → known CVEs (SSLv3, TLS 1.0, etc.)
  - Service/port → known vulnerable service (unmaintained SSH, etc.)
- **Impact**: Slower vulnerability discovery

---

## Detailed Recommendations

### 🔴 **MUST IMPLEMENT** (For Functional IDS/IPS)

1. **Add JA3/JA3S Fingerprinting**
   - Location: `internal/parser/tls.go` → calculate hash from ClientHello/ServerHello
   - Output: Add `ja3` and `ja3s` fields to TLSCompact in `IDSLog`
   - Library: https://github.com/salesforce/ja3 (Go implementation available)

2. **Include Payload in IDS Logs**
   - Modify `IDSLog` struct to include:
     ```go
     Payload *PayloadInfo `json:"payload,omitempty"`

     type PayloadInfo struct {
         Length      int    `json:"length"`
         DataHex     string `json:"data_hex,omitempty"`     // First 512 bytes
         EntropyScore float64 `json:"entropy,omitempty"`    // 0-8 entropy score
     }
     ```
   - Add entropy calculation for anomaly detection (high entropy = compressed/encrypted)

3. **TCP State Machine Tracking**
   - Modify `flow_context.flow_state` to use enum: "SYN_SENT" | "ESTABLISHED" | "TIME_WAIT" | "RST" | etc.
   - Track SYN flags → track ACKs → determine state
   - Add to IDS log for detection rules

4. **Add Anomaly Detection Fields**
   ```go
   Anomalies struct {
       IsUnusualPort bool `json:"is_unusual_port"`
       PortRarity float64 `json:"port_rarity,omitempty"` // 0-1
       IsPortScan bool `json:"is_port_scan"`
       IsFragmented bool `json:"is_fragmented"`
       IsSuspiciousSize bool `json:"is_suspicious_size"`
       RiskScore float64 `json:"risk_score"` // 0-100
   } `json:"anomalies,omitempty"`
   ```

5. **Add TLS Validation Failures**
   - Parse certificate validation errors
   - Add field: `CertValidationStatus` (valid | expired | self-signed | mismatch | etc.)

### 🟠 **SHOULD IMPLEMENT** (For Advanced Detection)

6. **DNS Anomaly Metrics**
   - Query size, response size, TTL value
   - Domain character entropy (DGA detection)
   - Subdomain depth (DNS tunneling detection)

7. **Traffic Direction Asymmetry Metrics**
   - Separate upload vs download bytes
   - Flag when ratio is >10:1 (data exfiltration)

8. **MIME Type Validation**
   - Parse Content-Type header
   - Flag mismatches (exe with image/jpeg content-type)

9. **Certificate Chain Details**
   - Subject, Issuer, validity dates
   - Certificate pinning violations

10. **MAC Address Spoofing Detection**
    - Validate MAC vendor prefix
    - Flag MAC changes per IP

---

## Implementation Priority

### Phase 1 (Critical - Week 1)
- [ ] JA3/JA3S fingerprinting
- [ ] Payload hex + entropy in IDS logs
- [ ] TCP state machine
- [ ] Anomaly risk score field

### Phase 2 (Important - Week 2)
- [ ] DNS anomaly metrics
- [ ] Certificate validation status
- [ ] MAC spoofing detection
- [ ] Direction asymmetry metrics

### Phase 3 (Enhancements - Week 3+)
- [ ] MIME type validation
- [ ] FTP/SMTP/SSH command logging
- [ ] Whois enrichment
- [ ] PCAP export triggers

---

## Backward Compatibility

✅ **All changes should be additive**:
- Add new optional fields to `IDSLog` and `PacketLog` structs
- Mark with `omitempty` in JSON tags
- Existing parsers will still work
- IDS systems can opt-in to advanced features

---

## Sample Enhanced IDS Log Entry

```json
{
  "timestamp_ist": "2026-02-15T12:34:56.789Z",
  "packet_id": "pkt_abc123",
  "flow_id": "192.168.1.100:12345-8.8.8.8:443/TCP",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "src_port": 12345,
  "dst_port": 443,
  "protocol": "TCP",
  "src_geo": {"country": "US", "asn": 15169, "asn_org": "Google"},
  "dst_geo": {"country": "US", "asn": 15169},
  "tcp_flags": "SA",
  "tcp_state": "ESTABLISHED",
  "tls": {
    "sni": "google.com",
    "version": "TLS1.3",
    "ja3": "772,49195,23-65281-10-11-35,23,0",
    "ja3s": "771,49195,65281",
    "cert_validation_status": "valid",
    "cert_subject": "*.google.com"
  },
  "payload": {
    "length": 512,
    "data_hex": "160303012345...",
    "entropy": 7.2
  },
  "anomalies": {
    "is_unusual_port": false,
    "port_rarity": 0.95,
    "is_fragmented": false,
    "risk_score": 5.0
  }
}
```

---

## Summary

**Current State**: Excellent passive packet capture with solid protocol parsing—sufficient for basic IDS/IPS needs.

**Gaps**: Missing threat detection context (fingerprints, anomaly scores, state tracking, payload signatures).

**Result**: Can log what's happening but cannot automatically distinguish between normal and malicious traffic.

**Recommendation**: Implement Phase 1 enhancements to add fingerprinting, payload data, state tracking, and risk scoring. This transforms from "data logger" → "threat detection engine" ready.

