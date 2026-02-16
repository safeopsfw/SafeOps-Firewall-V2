# IDS/IPS Requirements Comparison

## What SafeOps Network Logger Currently Provides ✅

### Core Data Collection
```
├─ Layer 2 (Ethernet)
│  ├─ Source/Destination MAC ✅
│  ├─ VLAN ID ✅
│  └─ EtherType ✅
│
├─ Layer 3 (IP)
│  ├─ Source/Destination IP ✅
│  ├─ TTL ✅
│  ├─ Fragmentation flags ✅
│  ├─ IP ID, TOS, DSCP ✅
│  └─ GeoIP enrichment ✅
│
├─ Layer 4 (TCP/UDP)
│  ├─ Ports ✅
│  ├─ TCP flags (SYN, ACK, FIN, RST) ✅
│  ├─ Sequence/Ack numbers ✅
│  ├─ TCP options ✅
│  └─ Checksums ✅
│
├─ Layer 7 (Application)
│  ├─ DNS parsing ✅
│  │  ├─ Queries and answers ✅
│  │  ├─ Query types (A, AAAA, MX, TXT) ✅
│  │  └─ TTL values ✅
│  │
│  ├─ HTTP/HTTPS ✅
│  │  ├─ Method, URI, Status Code ✅
│  │  ├─ Headers ✅
│  │  ├─ User-Agent ✅
│  │  ├─ Cookies ✅
│  │  └─ Body preview ✅
│  │
│  └─ TLS ✅
│     ├─ SNI (Server Name Indication) ✅
│     ├─ Client/Server Hello ✅
│     ├─ Cipher suites ✅
│     ├─ TLS version ✅
│     ├─ Certificate presence ✅
│     └─ Key logging + decryption ✅
│
├─ Flow Tracking
│  ├─ Flow ID (5-tuple) ✅
│  ├─ Direction (forward/backward) ✅
│  ├─ Packet counters ✅
│  ├─ Byte counters ✅
│  ├─ Flow start time ✅
│  ├─ Flow duration ✅
│  └─ Flow state ✅
│
├─ Process Correlation
│  ├─ PID ✅
│  ├─ Process name ✅
│  ├─ EXE path ✅
│  └─ Command line ✅
│
├─ Payload Data
│  ├─ Full capture (1600 bytes) ✅
│  ├─ Hex dump ✅
│  └─ Text preview ✅
│
└─ Device Tracking
   ├─ Hotspot device detection ✅
   ├─ MAC vendor lookup ✅
   ├─ Device type classification ✅
   └─ Traffic stats per device ✅
```

---

## What's Missing for Proper IDS/IPS ❌

### Threat Detection Fingerprints
```
Missing:
├─ JA3 TLS Fingerprint (client signature)
├─ JA3S TLS Fingerprint (server signature)
├─ ALPN protocol selection
├─ Certificate validation errors
├─ Protocol fingerprint database matching
└─ Malware signature correlation
```

### Anomaly Detection Fields
```
Missing:
├─ Packet loss / Retransmission tracking
├─ RTT (Round-Trip Time) estimation
├─ Out-of-order packet detection
├─ Entropy score (payload randomness)
├─ Port rarity scoring
├─ Traffic volume anomalies
├─ Asymmetric traffic flags
├─ DNS subdomain explosion detection
├─ Connection state machine details
└─ Risk scoring (0-100)
```

### Signature & Detection Context
```
Missing:
├─ Payload signature matching capability
├─ Rule/signature IDs
├─ Alert classification
├─ Severity/priority levels
├─ Detection confidence score
├─ Threat intelligence feed correlation
└─ CVE / vulnerability scoring
```

### Forensic & Correlation Fields
```
Missing:
├─ Unique session ID (for cross-log correlation)
├─ Direction asymmetry metrics (upload vs download)
├─ Certificate chain details (subject, issuer, dates)
├─ MAC spoofing detection
├─ Impossible travel detection (geolocation velocity)
├─ Protocol anomaly scoring
├─ Fragment reassembly hints
└─ PCAP linkage/export triggers
```

---

## Data Field Comparison Table

| Field | Purpose | SafeOps | Gap? |
|-------|---------|---------|------|
| **Timestamp** | Event ordering | ✅ Epoch + ISO8601 | ❌ Sub-microsecond precision |
| **Source IP** | Attacker identification | ✅ | ✅ Complete |
| **Dest IP** | Target identification | ✅ | ✅ Complete |
| **Ports** | Service targeting | ✅ | ✅ Complete |
| **Protocol** | Layer 4 | ✅ TCP/UDP/ICMP | ✅ Complete |
| **Flags** | TCP state info | ✅ SYN/ACK/RST/FIN | ❌ No state machine |
| **Flow ID** | Session tracking | ✅ | ✅ Complete |
| **Packet Count** | Volume metrics | ✅ | ❌ Only aggregate per direction |
| **Byte Count** | Data transfer | ✅ | ❌ Asymmetry not tracked |
| **Duration** | Connection length | ✅ | ✅ Complete |
| **DNS Query** | Domain resolution | ✅ | ❌ No query entropy/size anomalies |
| **HTTP Method** | Request type | ✅ | ❌ No body signature sampling |
| **HTTP Status** | Response code | ✅ | ❌ No status anomaly scoring |
| **TLS SNI** | Domain indication | ✅ | ❌ No JA3 fingerprint |
| **Certificate** | Domain ownership | ✅ SNI + presence | ❌ No cert validation errors |
| **GeoIP** | Location | ✅ Country/ASN | ❌ No impossible travel |
| **Payload** | Content analysis | ✅ Hex dump | ❌ No entropy/signature matching |
| **Process** | Source application | ✅ Name/PID/exe | ❌ No parent PID/tree |
| **Risk Score** | Threat level | ❌ | ❌ MISSING |
| **Alert Classification** | Threat type | ❌ | ❌ MISSING |
| **Anomaly Flags** | Unusual behavior | ❌ | ❌ MISSING |

---

## IDS/IPS Detection Capabilities Enabled by Missing Fields

### With Current Data (Limited)
- ✅ Traffic volume per IP pair
- ✅ DNS domain lookup tracking
- ✅ HTTPS SNI observation
- ✅ Process-to-network correlation
- ✅ Payload inspection (manual)
- ✅ Protocol parsing

### Blocked Without Missing Fields
- ❌ Malware fingerprint matching (JA3)
- ❌ Connection state violations (TCP state machine)
- ❌ Volumetric anomaly detection (asymmetric bytes)
- ❌ Retransmission attacks (packet loss tracking)
- ❌ Man-in-the-middle (cert validation errors)
- ❌ DGA domain detection (DNS entropy)
- ❌ Data exfiltration (direction asymmetry)
- ❌ Port scanning (connection state tracking)
- ❌ Protocol evasion (ALPN, port mismatches)
- ❌ Impossible travel (geolocation velocity)

---

## Professional IDS Log Example (Suricata EVE JSON)

```json
{
  "timestamp": "2026-02-15T12:34:56.789123Z",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "8.8.8.8",
  "dest_port": 443,
  "proto": "TCP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2027880,
    "rev": 1,
    "signature": "Malware.C2.DOMAIN",
    "category": "Trojan Traffic",
    "severity": 3,
    "metadata": [
      "policy security-ips alert",
      "malware_family zeus",
      "c2 communication"
    ]
  },
  "http": {
    "hostname": "malicious-c2.net",
    "url": "/command?id=abc123",
    "http_user_agent": "curl/7.68.0"
  },
  "tls": {
    "subject": "CN=evil.net",
    "issuer": "CN=self-signed",
    "serial": "abc123",
    "fingerprint": "d8:e8:f9:...",
    "sni": "evil.net",
    "version": "TLS1.2",
    "ja3": "771,49195,...",
    "ja3s": "771,49195,..."
  },
  "dns": {
    "query": [
      {
        "type": "query",
        "rrname": "malicious-c2.net",
        "rrtype": "A"
      }
    ]
  },
  "anomaly": {
    "type": "scanning",
    "flags": ["port_scan", "low_ttl"]
  },
  "stats": {
    "pkts_toserver": 15,
    "pkts_toclient": 8,
    "bytes_toserver": 2048,
    "bytes_toclient": 512
  },
  "app_layer": {
    "protocol": "tls"
  }
}
```

---

## What This Means for SafeOps

### Current Capability
- **Passive Network Logger**: ✅ Excellent
- **Threat Detection Engine**: ❌ Limited to basic heuristics
- **Forensic Investigation**: ✅ Good (has full packet data)
- **Real-time Anomaly Detection**: ❌ Requires external system

### After Recommended Changes
- **Passive Network Logger**: ✅ Still excellent
- **Threat Detection Engine**: ✅ Professional-grade (fingerprints + risk scoring)
- **Forensic Investigation**: ✅ Better (includes validation errors, cert details)
- **Real-time Anomaly Detection**: ✅ Built-in (risk scores, anomaly flags)

---

## Quick Reference: Field Priorities

### 🔴 CRITICAL (Week 1)
1. **JA3/JA3S Fingerprinting** - Malware identification
2. **Payload Encoding** - Signature matching
3. **Risk Score** - Alert prioritization
4. **Connection State** - Scanning detection

### 🟠 HIGH (Week 2)
5. **Anomaly Flags** - Quick filtering
6. **Certificate Validation** - MITM detection
7. **Direction Asymmetry** - Exfiltration detection
8. **DNS Entropy** - DGA detection

### 🟡 MEDIUM (Week 3+)
9. **MIME Type Validation** - Drive-by download detection
10. **MAC Spoofing Detection** - Layer 2 attacks
11. **Impossible Travel** - Compromised account detection
12. **PCAP Export Links** - Forensic speed

---

## Implementation Checklist

- [ ] Add JA3 hashing library to go.mod
- [ ] Compute JA3/JA3S in TLS parser
- [ ] Add payload hex + entropy to IDS log
- [ ] Implement TCP state machine
- [ ] Add risk score calculation
- [ ] Add anomaly detection scoring
- [ ] Add certificate validation tracking
- [ ] Test with sample malicious traffic
- [ ] Update IDS log schema documentation
- [ ] Integrate with firewall engine alerts

