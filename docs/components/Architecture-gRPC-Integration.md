# SafeOps gRPC Integration Architecture

**Version:** 3.0.0
**Last Updated:** 2026-01-22

---

## Overview

SafeOps uses a **microservices architecture** where the core packet capture engine broadcasts network metadata to multiple security components via **gRPC streaming**. This design enables real-time packet processing with minimal latency while maintaining separation of concerns.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Interfaces (NICs)                    │
│                  (Wi-Fi, Ethernet, VPN, etc.)                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    WinpkFilter Driver (NDISAPI)                  │
│                    Kernel-Level Packet Interception              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SAFEOPS ENGINE                              │
│                   (safeops-engine.exe)                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐      │
│  │  Packet Capture Loop (Multi-NIC)                     │      │
│  │  • Read from all adapters (round-robin)              │      │
│  │  • Parse headers (ETH/IP/TCP/UDP/ICMP)              │      │
│  │  • Build packet metadata                             │      │
│  └──────────────────┬───────────────────────────────────┘      │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────────────────┐      │
│  │  gRPC Broadcast Engine                               │      │
│  │  • Manage subscriber connections                     │      │
│  │  • Apply filters (per subscriber)                    │      │
│  │  • Stream metadata to all subscribers                │      │
│  └──────────────────┬───────────────────────────────────┘      │
│                     │                                            │
│  ┌──────────────────▼───────────────────────────────────┐      │
│  │  Verdict Collection (Async)                          │      │
│  │  • Receive DROP/BLOCK/REDIRECT from components       │      │
│  │  • Apply first-verdict-wins logic                    │      │
│  │  • Execute verdict via driver                        │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                  │
│  gRPC Server: 127.0.0.1:50051                                  │
└────────────────────────────┬───┬───┬────────────────────────────┘
                             │   │   │
        ┌────────────────────┘   │   └────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
┌───────────────┐      ┌──────────────────┐      ┌──────────────┐
│   FIREWALL    │      │    IDS ENGINE    │      │   IPS ENGINE │
│    ENGINE     │      │  (ids-engine.exe)│      │(ips-engine.exe)
│               │      │                  │      │              │
│ • Rule eval   │      │ • Signature scan │      │ • Attack det │
│ • ACL check   │      │ • Anomaly detect │      │ • Pattern    │
│ • Rate limit  │      │ • Threat intel   │      │ • Auto-block │
│               │      │                  │      │              │
│ Verdict: ↓    │      │ Verdict: ↓       │      │ Verdict: ↓   │
│ DROP/ALLOW    │      │ ALERT/LOG        │      │ DROP/RESET   │
└───────────────┘      └──────────────────┘      └──────────────┘

        │                        │                        │
        └────────────────────────┴────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   SIEM FORWARDER        │
                    │ (siem-forwarder.exe)    │
                    │                         │
                    │ • Aggregate alerts      │
                    │ • Normalize events      │
                    │ • Forward to SIEM       │
                    └─────────────────────────┘
```

---

## Core Components

### 1. **SafeOps Engine** (safeops-engine.exe)

**Role:** Centralized packet capture and metadata distribution

**Responsibilities:**
- Capture packets from all network interfaces via WinpkFilter
- Parse packet headers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP)
- Extract metadata (5-tuple, flags, payload size)
- Broadcast metadata to all subscribed components via gRPC
- Collect verdicts from components
- Enforce verdicts via kernel driver
- Forward allowed packets back to network

**Performance Characteristics:**
- **Zero-copy metadata extraction** (no full packet duplication)
- **Round-robin NIC polling** (fair scheduling)
- **Async verdict collection** (non-blocking)
- **Target latency:** < 1ms per packet

**gRPC Server:**
- **Address:** `127.0.0.1:50051` (localhost only)
- **Protocol:** HTTP/2 with Protocol Buffers
- **Streaming:** Server-side streaming (one stream per subscriber)

---

### 2. **Firewall Engine** (firewall_engine.exe)

**Role:** Stateful packet filtering and access control

**Responsibilities:**
- Subscribe to SafeOps metadata stream
- Evaluate packets against firewall rules (`firewall.toml`)
- Maintain connection state tables
- Send DROP/ALLOW verdicts back to SafeOps Engine
- Log blocked connections

**Rule Types Supported:**
- IP/subnet filtering (source/destination)
- Port filtering (TCP/UDP)
- Protocol filtering (ICMP, TCP, UDP)
- Direction-based rules (inbound/outbound)
- Rate limiting
- Connection tracking

**Operating Modes:**
1. **MONITORING:** Log all activity, allow all packets (default)
2. **ENFORCING:** Block packets matching DROP rules

**Statistics Tracked:**
- Packets received from SafeOps
- Packets processed (rule evaluation)
- Verdicts sent (DROP/ALLOW)
- Rules matched

---

### 3. **IDS Engine** (Future Component)

**Role:** Intrusion detection and threat intelligence

**Planned Responsibilities:**
- Subscribe to SafeOps metadata stream (filtered: suspicious protocols)
- Perform deep packet inspection (DPI)
- Signature-based detection (Snort/Suricata-compatible)
- Anomaly detection (ML-based)
- Generate ALERT verdicts
- Feed alerts to SIEM forwarder

**Subscription Filters:**
```protobuf
filters {
  protocols: ["TCP", "UDP"]
  dest_ports: [22, 23, 445, 3389]  // High-risk ports
}
```

---

### 4. **IPS Engine** (Future Component)

**Role:** Intrusion prevention and active blocking

**Planned Responsibilities:**
- Subscribe to SafeOps metadata stream
- Detect attack patterns (SQL injection, XSS, buffer overflows)
- Automatic blocking of malicious IPs
- Rate limiting enforcement
- Send DROP/RESET verdicts for attacks

**Integration with Firewall:**
- IPS sends DROP verdicts for detected attacks
- Firewall can import IPS blocklist into permanent rules

---

### 5. **Network Logger** (Future Component)

**Role:** Comprehensive network activity logging

**Planned Responsibilities:**
- Subscribe to SafeOps metadata stream (no filters, receive all)
- Write flow logs to disk
- Provide NetFlow/IPFIX export
- Support PCAP export for forensics

---

### 6. **SIEM Forwarder** (Existing Component)

**Role:** Aggregate and forward security events

**Responsibilities:**
- Collect alerts from IDS/IPS/Firewall
- Normalize event formats
- Forward to external SIEM (Splunk, ELK, Sentinel)
- Support multiple output formats (Syslog, JSON, CEF)

---

## gRPC Protocol

### Protocol Buffer Definition

**File:** `proto/metadata_stream.proto`

```protobuf
service MetadataStream {
  // Subscribe to packet metadata stream
  rpc Subscribe(SubscriptionRequest) returns (stream PacketMetadata);

  // Send verdict for a packet
  rpc SendVerdict(Verdict) returns (VerdictResponse);

  // Get engine statistics
  rpc GetStats(StatsRequest) returns (EngineStats);
}
```

### Message Flow

#### 1. **Subscription (Component → Engine)**

```
Component                     SafeOps Engine
    |                               |
    |──── SubscriptionRequest ─────>|
    |     {                         |
    |       subscriber_id: "fw-1",  |
    |       filters: {...}          |
    |     }                         |
    |                               |
    |<──── PacketMetadata Stream ───|
    |      (continuous)             |
```

**SubscriptionRequest Fields:**
- `subscriber_id`: Unique identifier (e.g., "firewall-engine")
- `filters`: Optional filtering criteria (protocols, ports, IPs)

#### 2. **Metadata Broadcast (Engine → Components)**

```
SafeOps Engine                Components (Firewall, IDS, IPS)
    |                               |
    |────── PacketMetadata ────────>| (broadcast to all)
    |       {                       |
    |         packet_id: 12345,     |
    |         timestamp: ...,       |
    |         src_ip: "192.168.1.10"|
    |         dst_ip: "8.8.8.8",    |
    |         src_port: 54321,      |
    |         dst_port: 443,        |
    |         protocol: "TCP",      |
    |         tcp_flags: ["SYN"],   |
    |         adapter_index: 2      |
    |       }                       |
```

**PacketMetadata Fields:**
- `packet_id`: Unique packet identifier (for verdict correlation)
- `timestamp`: Packet capture time (nanoseconds)
- `src_ip`, `dst_ip`: Source/destination IP addresses
- `src_port`, `dst_port`: TCP/UDP ports
- `protocol`: Protocol name (TCP, UDP, ICMP, etc.)
- `tcp_flags`: TCP flags (SYN, ACK, FIN, RST, PSH)
- `adapter_index`: Which NIC captured the packet
- `direction`: INBOUND or OUTBOUND

#### 3. **Verdict Submission (Component → Engine)**

```
Component                     SafeOps Engine
    |                               |
    |────── SendVerdict ───────────>|
    |       {                       |
    |         packet_id: 12345,     |
    |         verdict: "DROP",      |
    |         reason: "Blocked port"|
    |       }                       |
    |                               |
    |<──── VerdictResponse ─────────|
    |       {                       |
    |         success: true         |
    |       }                       |
```

**Verdict Types:**
- `ALLOW`: Forward packet to destination (default)
- `DROP`: Silently discard packet
- `BLOCK`: Drop packet + log event
- `REDIRECT`: Modify destination (future: transparent proxy)
- `RESET`: Send TCP RST to both ends

**Verdict Priority (First-Verdict-Wins):**
1. First component to send a verdict wins
2. If no verdict received within timeout (10ms), ALLOW by default
3. DROP/BLOCK always takes precedence over ALLOW (safety first)

---

## Adding New Components

### Step-by-Step Integration Guide

#### 1. **Create a New Component Executable**

```go
package main

import (
    "context"
    "log"
    pb "safeops/proto"
    "google.golang.org/grpc"
)

func main() {
    // Connect to SafeOps Engine
    conn, err := grpc.Dial("127.0.0.1:50051",
        grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewMetadataStreamClient(conn)

    // Subscribe to metadata stream
    stream, err := client.Subscribe(context.Background(),
        &pb.SubscriptionRequest{
            SubscriberId: "my-component",
            Filters: &pb.StreamFilters{
                Protocols: []string{"TCP"},
            },
        })
    if err != nil {
        log.Fatal(err)
    }

    // Process packets
    for {
        metadata, err := stream.Recv()
        if err != nil {
            log.Fatal(err)
        }

        // YOUR LOGIC HERE
        processPacket(metadata)

        // Send verdict if needed
        if shouldBlock(metadata) {
            client.SendVerdict(context.Background(),
                &pb.Verdict{
                    PacketId: metadata.PacketId,
                    Verdict: "DROP",
                    Reason: "My custom rule",
                })
        }
    }
}
```

#### 2. **Define Subscription Filters (Optional)**

Filters reduce unnecessary metadata transmission:

```protobuf
filters {
  protocols: ["TCP", "UDP"]           // Only TCP/UDP
  dest_ports: [80, 443, 8080]         // Only HTTP/HTTPS
  src_ips: ["192.168.0.0/16"]         // Only local network
  direction: "OUTBOUND"               // Only outgoing
}
```

#### 3. **Build and Deploy**

```bash
# Build your component
cd src/my_component
go build -o ../../bin/my_component/my_component.exe

# Run SafeOps Engine first
cd ../../bin/safeops-engine
safeops-engine.exe

# Run your component (separate terminal)
cd ../my_component
my_component.exe
```

#### 4. **Monitor Connection**

SafeOps Engine logs will show:
```json
{"level":"INFO","message":"New metadata subscriber",
 "data":{"subscriber_id":"my-component"}}
```

---

## Performance Optimization

### Current Performance Characteristics

**SafeOps Engine:**
- **Packet capture rate:** ~30,000 packets/sec (tested)
- **Metadata broadcast latency:** < 0.5ms per subscriber
- **Memory usage:** ~20MB baseline + 1MB per subscriber
- **CPU usage:** 2-5% idle, 15-20% under load

**Firewall Engine:**
- **Rule evaluation:** < 0.1ms per packet (100 rules)
- **Memory usage:** ~15MB baseline
- **CPU usage:** 1-3% idle, 10-15% under load

### Latency Budget (Target: < 2ms end-to-end)

```
Component                        Latency    Cumulative
─────────────────────────────────────────────────────
Kernel → SafeOps (driver read)     0.1ms      0.1ms
SafeOps packet parsing             0.2ms      0.3ms
gRPC metadata serialization        0.1ms      0.4ms
Network (localhost loopback)       0.05ms     0.45ms
gRPC metadata deserialization      0.1ms      0.55ms
Firewall rule evaluation           0.3ms      0.85ms
gRPC verdict serialization         0.1ms      0.95ms
Network (localhost loopback)       0.05ms     1.0ms
Verdict processing in SafeOps      0.2ms      1.2ms
SafeOps → Kernel (driver write)    0.1ms      1.3ms
─────────────────────────────────────────────────────
TOTAL (best case)                            ~1.3ms
TOTAL (average case)                         ~2.5ms
TOTAL (worst case, 3+ subscribers)           ~4.0ms
```

### Optimization Strategies

#### For Gaming (Priority: Ultra-Low Latency)

1. **Reduce Subscriber Count:**
   - Run only essential components (Firewall only)
   - Disable IDS/IPS during gaming sessions

2. **Optimize Firewall Rules:**
   - Place most-frequently-matched rules at the top
   - Use IP ranges instead of individual IPs
   - Minimize regex/pattern matching

3. **Adjust Polling Strategy:**
   - Increase adapter polling interval (trade CPU for latency)
   - Use interrupt-driven mode (requires driver modification)

4. **Enable Gaming Mode (Future Feature):**
   ```toml
   [performance]
   gaming_mode = true          # Reduces latency to < 1ms
   ```

#### For High Throughput (Priority: Packets/sec)

1. **Batch Processing:**
   - Process packets in batches of 10-100
   - Amortize gRPC overhead

2. **Parallel Rule Evaluation:**
   - Split rule evaluation across CPU cores
   - Use worker pools in Firewall Engine

3. **Connection State Caching:**
   - Cache firewall decisions for established connections
   - Skip rule evaluation for known-good flows

---

## Monitoring and Observability

### Real-Time Statistics

**SafeOps Engine Output:**
```
[STATS] Read=33131 Written=32403 Dropped=0
```

**Firewall Engine Output:**
```
[STATS] Client: Received=2944 Processed=2944 Verdicts=0 |
        Engine: Read=33131 Written=32403 Subscribers=1
```

### Health Checks

```bash
# Check if SafeOps Engine is running
tasklist | findstr safeops-engine

# Check gRPC port is listening
netstat -ano | findstr 50051

# Test gRPC connectivity
grpcurl -plaintext 127.0.0.1:50051 list
```

### Log Aggregation

All components use structured JSON logging:

```json
{
  "timestamp": "2026-01-22T09:46:02.8218889Z",
  "level": "INFO",
  "message": "New metadata subscriber",
  "data": {
    "subscriber_id": "firewall-engine",
    "filters": null
  }
}
```

Use log aggregation tools:
- **Local:** Windows Event Viewer
- **Centralized:** Splunk, ELK, Datadog

---

## Security Considerations

### 1. **Localhost-Only gRPC**

- gRPC server binds to `127.0.0.1:50051` (not `0.0.0.0`)
- No remote network access
- No TLS required (local-only traffic)

### 2. **Subscriber Authentication (Future)**

```protobuf
message SubscriptionRequest {
  string subscriber_id = 1;
  string auth_token = 2;  // HMAC signature
}
```

### 3. **Verdict Validation**

- Only registered subscribers can send verdicts
- Packet ID must exist in pending verdicts map
- Malformed verdicts are rejected

### 4. **Resource Limits**

- Max 10 concurrent subscribers (prevent DoS)
- Max 1MB metadata per packet (prevent memory exhaustion)
- Verdict timeout: 10ms (prevent indefinite blocking)

---

## Troubleshooting

### Issue: Component Can't Connect to SafeOps

**Symptoms:**
```
[ERROR] Failed to connect to SafeOps Engine: connection refused
```

**Solutions:**
1. Verify SafeOps Engine is running: `tasklist | findstr safeops-engine`
2. Check port 50051 is listening: `netstat -ano | findstr 50051`
3. Ensure no firewall blocking localhost traffic
4. Check Windows Defender / antivirus isn't blocking gRPC

### Issue: High Latency / Packet Loss

**Symptoms:**
```
[STATS] Read=10000 Written=9500 Dropped=500
```

**Solutions:**
1. Reduce number of active subscribers
2. Optimize firewall rules (move frequent matches to top)
3. Increase verdict timeout in SafeOps Engine
4. Check CPU usage (should be < 50%)

### Issue: Component Not Receiving Packets

**Symptoms:**
```
[STATS] Client: Received=0 Processed=0
```

**Solutions:**
1. Check subscription filters (may be too restrictive)
2. Verify adapter is capturing packets (check Engine stats)
3. Check gRPC stream didn't disconnect (look for reconnection logs)
4. Ensure metadata matches filter criteria

---

## Future Enhancements

### Planned Features (v4.0)

1. **eBPF Integration (Linux):**
   - Replace WinpkFilter with XDP/eBPF
   - Kernel-level rule evaluation (zero userspace latency)

2. **Connection State Sharing:**
   - Shared memory for connection tables
   - Zero-copy state synchronization between components

3. **WebAssembly Plugins:**
   - Load custom packet processors as WASM modules
   - Sandboxed execution for third-party rules

4. **Distributed Architecture:**
   - Run SafeOps Engine on edge gateway
   - Stream metadata to cloud components (with TLS)

5. **Machine Learning Pipeline:**
   - Real-time feature extraction in SafeOps
   - Stream to ML inference service
   - Adaptive rule generation

---

## Summary

SafeOps gRPC architecture provides:

✅ **Separation of Concerns:** Each component has a single responsibility
✅ **Scalability:** Add new components without modifying core engine
✅ **Performance:** < 2ms latency with multiple subscribers
✅ **Flexibility:** Subscribe to only the metadata you need (filters)
✅ **Reliability:** Auto-reconnection and health monitoring
✅ **Observability:** Comprehensive logging and statistics

**This architecture enables building a complete NGFW (Next-Generation Firewall) with modular, independently-deployable components.**

---

**Questions or contributions?** See `docs/CONTRIBUTING.md`
