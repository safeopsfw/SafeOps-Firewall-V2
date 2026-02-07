# SafeOps Engine Integration Guide

## 📖 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [gRPC API Reference](#grpc-api-reference)
5. [Integration Examples](#integration-examples)
6. [Verdict Types](#verdict-types)
7. [HTML Block Pages](#html-block-pages)
8. [Performance Best Practices](#performance-best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Overview

SafeOps Engine is a **high-performance network packet inspection engine** that captures packets from all network interfaces and provides a **gRPC streaming API** for external programs to analyze and control network traffic.

### Key Features

✅ **Zero-copy packet capture** via WinpkFilter (NDISAPI)
✅ **Multi-NIC support** - monitors all physical network adapters
✅ **gRPC streaming** - real-time packet metadata delivery
✅ **Domain extraction** - DNS, HTTP Host, HTTPS SNI
✅ **Verdict caching** - TTL-based decision caching for performance
✅ **Block/Drop/Redirect** - comprehensive traffic control
✅ **HTML injection** - custom block pages for HTTP traffic
✅ **Zero performance impact** - full network speed maintained

### Use Cases

- **Firewall** - Block malicious domains/IPs
- **IDS/IPS** - Detect and prevent intrusions
- **Parental Control** - Filter inappropriate content
- **DDoS Protection** - Detect and mitigate attacks
- **Network Monitor** - Analyze traffic patterns
- **VPN/Proxy** - Custom routing decisions

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Interfaces                          │
│              (Wi-Fi, Ethernet, Virtual adapters)                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  WinpkFilter Driver (NDISAPI)                   │
│                    Tunnel mode - captures all packets            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     SafeOps Engine                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Packet Parser                                            │  │
│  │  - IPv4/IPv6                                             │  │
│  │  - TCP/UDP                                               │  │
│  │  - DNS/HTTP/HTTPS domain extraction                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Verdict Cache (5-tuple)                                  │  │
│  │  - TTL-based caching                                     │  │
│  │  - Per-connection decisions                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ gRPC Server (127.0.0.1:50051)                            │  │
│  │  - StreamMetadata (packet stream)                        │  │
│  │  - ApplyVerdict (verdict submission)                     │  │
│  │  - GetStats (statistics)                                 │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                External Programs (Your Code)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Firewall   │  │   IDS/IPS    │  │   Monitor    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Start SafeOps Engine

```bash
# Run as Administrator (required for driver access)
safeops-engine.exe
```

Expected output:
```
=== SafeOps Network Pipeline ===
Version: 3.0.0 (Metadata Stream)
{"level":"INFO","message":"gRPC server created","data":{"address":"127.0.0.1:50051"}}
{"level":"INFO","message":"Monitoring adapters","data":{"count":5}}
SafeOps Engine is running
Metadata stream ready for subscribers
Press Ctrl+C to stop...
```

### 2. Connect Your Program

#### Python Example

```python
import grpc
from safeops_pb2 import *
from safeops_pb2_grpc import *

# Connect to SafeOps Engine
channel = grpc.insecure_channel('127.0.0.1:50051')
client = MetadataStreamServiceStub(channel)

# Subscribe to packet stream
request = SubscribeRequest(
    subscriber_id="my-firewall-1",
    filters=["tcp", "udp"]  # Optional: filter by protocol
)

# Receive packets
for packet in client.StreamMetadata(request):
    print(f"Packet #{packet.packet_id}")
    print(f"  {packet.src_ip}:{packet.src_port} → {packet.dst_ip}:{packet.dst_port}")
    print(f"  Domain: {packet.domain} (source: {packet.domain_source})")
    print(f"  Protocol: {packet.protocol}")

    # Make decision
    if packet.domain == "malicious.com":
        # Send BLOCK verdict
        verdict = VerdictRequest(
            packet_id=packet.packet_id,
            verdict=VerdictType.BLOCK,
            reason="Blocked by firewall rule #42",
            rule_id="RULE_42",
            ttl_seconds=300,  # Cache for 5 minutes
            cache_key=packet.cache_key
        )
        client.ApplyVerdict(verdict)
```

#### Go Example

```go
package main

import (
    "context"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "path/to/safeops/proto"
)

func main() {
    // Connect to SafeOps Engine
    conn, err := grpc.Dial("127.0.0.1:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewMetadataStreamServiceClient(conn)

    // Subscribe to packet stream
    stream, err := client.StreamMetadata(context.Background(), &pb.SubscribeRequest{
        SubscriberId: "my-firewall-1",
        Filters:      []string{"tcp", "udp"},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Receive packets
    for {
        pkt, err := stream.Recv()
        if err != nil {
            log.Fatal(err)
        }

        log.Printf("Packet #%d: %s:%d → %s:%d (Domain: %s)",
            pkt.PacketId, pkt.SrcIp, pkt.SrcPort, pkt.DstIp, pkt.DstPort, pkt.Domain)

        // Make decision
        if pkt.Domain == "malicious.com" {
            _, err := client.ApplyVerdict(context.Background(), &pb.VerdictRequest{
                PacketId:    pkt.PacketId,
                Verdict:     pb.VerdictType_BLOCK,
                Reason:      "Blocked by firewall rule #42",
                RuleId:      "RULE_42",
                TtlSeconds:  300, // Cache for 5 minutes
                CacheKey:    pkt.CacheKey,
            })
            if err != nil {
                log.Printf("Failed to apply verdict: %v", err)
            }
        }
    }
}
```

#### C# Example

```csharp
using Grpc.Net.Client;
using SafeOps.Proto;

// Connect to SafeOps Engine
var channel = GrpcChannel.ForAddress("http://127.0.0.1:50051");
var client = new MetadataStreamService.MetadataStreamServiceClient(channel);

// Subscribe to packet stream
var request = new SubscribeRequest
{
    SubscriberId = "my-firewall-1",
    Filters = { "tcp", "udp" }
};

// Receive packets
var stream = client.StreamMetadata(request);
await foreach (var packet in stream.ResponseStream.ReadAllAsync())
{
    Console.WriteLine($"Packet #{packet.PacketId}");
    Console.WriteLine($"  {packet.SrcIp}:{packet.SrcPort} → {packet.DstIp}:{packet.DstPort}");
    Console.WriteLine($"  Domain: {packet.Domain} ({packet.DomainSource})");

    // Make decision
    if (packet.Domain == "malicious.com")
    {
        await client.ApplyVerdictAsync(new VerdictRequest
        {
            PacketId = packet.PacketId,
            Verdict = VerdictType.Block,
            Reason = "Blocked by firewall rule #42",
            RuleId = "RULE_42",
            TtlSeconds = 300, // Cache for 5 minutes
            CacheKey = packet.CacheKey
        });
    }
}
```

---

## gRPC API Reference

### Service Definition

```protobuf
service MetadataStreamService {
    // Stream packet metadata (server-side streaming)
    rpc StreamMetadata(SubscribeRequest) returns (stream PacketMetadata);

    // Apply verdict to packets (unary)
    rpc ApplyVerdict(VerdictRequest) returns (VerdictResponse);

    // Get engine statistics (unary)
    rpc GetStats(StatsRequest) returns (StatsResponse);
}
```

### 1. StreamMetadata - Subscribe to Packet Stream

**Request:**
```protobuf
message SubscribeRequest {
    string subscriber_id = 1;  // Unique identifier for your program
    repeated string filters = 2;  // Optional: ["tcp", "udp", "dns", "http"]
}
```

**Response (Stream):**
```protobuf
message PacketMetadata {
    uint64 packet_id = 1;       // Unique packet ID
    int64 timestamp = 2;        // Unix nanoseconds
    string src_ip = 3;          // Source IP
    uint32 src_port = 4;        // Source port
    string dst_ip = 5;          // Destination IP
    uint32 dst_port = 6;        // Destination port
    uint32 protocol = 7;        // 6=TCP, 17=UDP
    string direction = 8;       // "INBOUND" or "OUTBOUND"
    uint32 packet_size = 9;     // Payload size in bytes
    string adapter_name = 10;   // Network adapter name

    // Domain information (if extracted)
    string domain = 11;         // Extracted domain (e.g., "example.com")
    string domain_source = 12;  // "DNS", "SNI", or "HTTP"

    // TCP flags (if TCP)
    uint32 tcp_flags = 13;      // Raw TCP flags
    bool is_syn = 14;           // SYN flag
    bool is_ack = 15;           // ACK flag
    bool is_rst = 16;           // RST flag
    bool is_fin = 17;           // FIN flag

    // Protocol detection
    bool is_dns_query = 18;     // DNS query (UDP port 53)
    bool is_dns_response = 19;  // DNS response
    bool is_http = 20;          // HTTP request (port 80)
    string http_method = 21;    // "GET", "POST", etc.

    // Verdict caching
    string cache_key = 22;      // Pre-computed 5-tuple key
}
```

**Example:**
```python
for packet in client.StreamMetadata(SubscribeRequest(subscriber_id="fw-1")):
    if packet.domain == "blocked-site.com":
        # Apply verdict (see below)
```

---

### 2. ApplyVerdict - Submit Traffic Decision

**Request:**
```protobuf
message VerdictRequest {
    uint64 packet_id = 1;       // Packet ID from StreamMetadata
    VerdictType verdict = 2;    // ALLOW, DROP, BLOCK, REDIRECT
    string reason = 3;          // Human-readable reason
    string rule_id = 4;         // Rule identifier for logging
    uint32 ttl_seconds = 5;     // Cache duration (0 = no cache)
    string cache_key = 6;       // From PacketMetadata.cache_key
}

enum VerdictType {
    ALLOW = 0;      // Forward packet normally
    DROP = 1;       // Silently discard packet
    BLOCK = 2;      // Send TCP RST or ICMP unreachable
    REDIRECT = 3;   // DNS spoofing (for DNS queries)
}
```

**Response:**
```protobuf
message VerdictResponse {
    bool success = 1;           // true if verdict applied
    string message = 2;         // Status message
    uint64 packets_affected = 3; // Number of packets affected
}
```

**Example:**
```python
# Block a domain (with caching)
client.ApplyVerdict(VerdictRequest(
    packet_id=pkt.packet_id,
    verdict=VerdictType.BLOCK,
    reason="Domain on blocklist",
    rule_id="BLOCKLIST_123",
    ttl_seconds=300,  # Cache for 5 minutes
    cache_key=pkt.cache_key
))

# Drop packet silently (no cache)
client.ApplyVerdict(VerdictRequest(
    packet_id=pkt.packet_id,
    verdict=VerdictType.DROP,
    reason="Port scan detected",
    rule_id="IDS_PORTSCAN",
    ttl_seconds=0  # No caching
))
```

---

### 3. GetStats - Retrieve Engine Statistics

**Request:**
```protobuf
message StatsRequest {}
```

**Response:**
```protobuf
message StatsResponse {
    uint64 packets_read = 1;        // Total packets captured
    uint64 packets_written = 2;     // Total packets forwarded
    uint64 packets_dropped = 3;     // Total packets dropped
    uint64 active_subscribers = 4;  // Current subscriber count
    uint64 verdicts_applied = 5;    // Total verdicts received
    uint64 cached_verdicts = 6;     // Current cache size
}
```

**Example:**
```python
stats = client.GetStats(StatsRequest())
print(f"Packets: {stats.packets_read} read, {stats.packets_dropped} dropped")
print(f"Cache: {stats.cached_verdicts} entries")
```

---

## Verdict Types

### ALLOW (0) - Forward Packet

**Use Case:** Packet is safe, allow through.

**Behavior:**
- Packet is reinjected to network stack
- Connection continues normally

**Example:**
```python
client.ApplyVerdict(VerdictRequest(
    packet_id=pkt.packet_id,
    verdict=VerdictType.ALLOW,
    reason="Safe domain",
    ttl_seconds=600  # Cache for 10 minutes
))
```

---

### DROP (1) - Silent Discard

**Use Case:** Drop malicious packets without notifying attacker.

**Behavior:**
- Packet is discarded silently
- No response sent to client/server
- Connection times out

**When to Use:**
- Port scans
- DDoS attacks
- Unknown/suspicious traffic

**Example:**
```python
if is_port_scan(pkt):
    client.ApplyVerdict(VerdictRequest(
        packet_id=pkt.packet_id,
        verdict=VerdictType.DROP,
        reason="Port scan detected",
        rule_id="IDS_PORTSCAN",
        ttl_seconds=0  # Don't cache (attacks vary)
    ))
```

---

### BLOCK (2) - Terminate Connection

**Use Case:** Block known malicious sites/IPs with immediate feedback.

**Behavior:**
- For **TCP**: Send RST packet to both client and server
- For **HTTP (port 80)**: Inject custom HTML block page
- For **UDP**: Drop silently (same as DROP)

**When to Use:**
- Blocked domains
- Malware C&C servers
- Firewall rules

**Example:**
```python
if domain_in_blocklist(pkt.domain):
    client.ApplyVerdict(VerdictRequest(
        packet_id=pkt.packet_id,
        verdict=VerdictType.BLOCK,
        reason=f"Domain '{pkt.domain}' is on blocklist",
        rule_id="BLOCKLIST_456",
        ttl_seconds=3600,  # Cache for 1 hour
        cache_key=pkt.cache_key
    ))
```

**HTML Block Page** (for HTTP):
- Beautiful custom block page
- Shows reason, rule ID, timestamp
- Branded with SafeOps logo

---

### REDIRECT (3) - DNS Spoofing

**Use Case:** Redirect domains to a safe IP (e.g., block page server).

**Behavior:**
- For **DNS queries**: Inject fake DNS response with your IP
- Client browser connects to your IP instead

**When to Use:**
- Parental control (redirect blocked sites to warning page)
- Corporate policy (redirect social media to policy page)
- Network monitoring (redirect to transparent proxy)

**Example:**
```python
if pkt.is_dns_query and pkt.domain == "blocked-site.com":
    client.ApplyVerdict(VerdictRequest(
        packet_id=pkt.packet_id,
        verdict=VerdictType.REDIRECT,
        reason="Redirected to block page server",
        rule_id="REDIRECT_BLOCKED",
        ttl_seconds=600,  # Cache for 10 minutes
        cache_key=pkt.cache_key
    ))
    # Note: You need a web server at the redirect IP serving the block page
```

---

## HTML Block Pages

SafeOps Engine automatically injects custom HTML block pages for **HTTP (port 80)** traffic when you use `VerdictType.BLOCK`.

### Block Page Features

✅ **Beautiful design** - Modern gradient background, clean layout
✅ **Responsive** - Works on desktop and mobile
✅ **Branded** - SafeOps Firewall logo
✅ **Informative** - Shows reason, rule ID, timestamp
✅ **User-friendly** - Clear message for end users

### Example Block Page

![Block Page Preview](https://via.placeholder.com/600x400/667eea/ffffff?text=Access+Blocked+Block+Page)

**HTML Preview:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked - SafeOps Firewall</title>
    <style>
        /* Modern gradient design with purple theme */
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Access Blocked</h1>
        <p>This website has been blocked by your firewall policy</p>

        <div class="reason-box">
            <div class="label">Block Reason</div>
            <div class="value">Domain 'malicious.com' is on blocklist</div>
        </div>

        <div class="info-grid">
            <div class="info-item">
                <div class="label">Rule ID</div>
                <div class="value">BLOCKLIST_456</div>
            </div>
            <div class="info-item">
                <div class="label">Timestamp</div>
                <div class="value">2026-02-03 14:30:45 UTC</div>
            </div>
        </div>

        <div class="footer">
            <div class="footer-logo">🔒 SafeOps Firewall</div>
            <div>Contact your network administrator if this is a mistake.</div>
        </div>
    </div>
</body>
</html>
```

### HTTPS (Port 443) Limitation

⚠️ **Cannot inject HTML for HTTPS** - TLS encryption prevents HTML injection.
✅ **Use BLOCK verdict instead** - Sends TCP RST to terminate connection.
✅ **Browser shows error** - "Connection reset" or "ERR_CONNECTION_RESET".

---

## Performance Best Practices

### 1. Use Verdict Caching

**Always specify `ttl_seconds` > 0** for established connections:

```python
# ✅ GOOD: Cache verdict for 5 minutes
client.ApplyVerdict(VerdictRequest(
    verdict=VerdictType.BLOCK,
    ttl_seconds=300,  # 5 minutes
    cache_key=pkt.cache_key
))

# ❌ BAD: No caching (slow, 100x overhead)
client.ApplyVerdict(VerdictRequest(
    verdict=VerdictType.BLOCK,
    ttl_seconds=0  # No cache
))
```

**Impact:**
- First packet: ~100μs processing
- Cached packets: ~1μs processing (100x faster!)

---

### 2. Filter Subscriptions

Only subscribe to protocols you need:

```python
# ✅ GOOD: Filter for TCP/UDP only
SubscribeRequest(
    subscriber_id="fw-1",
    filters=["tcp", "udp"]
)

# ❌ BAD: Receive all packets (including gaming/VoIP)
SubscribeRequest(
    subscriber_id="fw-1"
    # No filters = ALL packets
)
```

**Available Filters:**
- `"tcp"` - TCP packets only
- `"udp"` - UDP packets only
- `"dns"` - DNS queries/responses
- `"http"` - HTTP requests

---

### 3. Process Packets Asynchronously

Don't block the packet stream:

```python
# ✅ GOOD: Async processing
async def process_packet(pkt):
    # Do analysis in background
    if await is_malicious(pkt):
        await client.ApplyVerdict(...)

for packet in client.StreamMetadata(request):
    asyncio.create_task(process_packet(packet))

# ❌ BAD: Blocking analysis
for packet in client.StreamMetadata(request):
    time.sleep(1)  # Blocks entire stream!
    if is_malicious(packet):
        client.ApplyVerdict(...)
```

---

### 4. Batch Decisions

For similar packets, use a single cached verdict:

```python
# ✅ GOOD: Cache applies to all packets with same 5-tuple
if domain_in_blocklist(pkt.domain):
    client.ApplyVerdict(VerdictRequest(
        verdict=VerdictType.BLOCK,
        ttl_seconds=3600,  # All future packets to this domain are cached
        cache_key=pkt.cache_key
    ))

# ❌ BAD: Processing every packet individually
for packet in stream:
    if packet.dst_port == 443:
        # This gets called 1000s of times for same connection!
        process_every_packet(packet)
```

---

## Troubleshooting

### Issue: No Packets Received

**Symptoms:**
```python
for packet in client.StreamMetadata(request):
    # Loop never receives packets
```

**Solutions:**

1. **Check SafeOps Engine is running:**
   ```bash
   # Should see "SafeOps Engine is running"
   safeops-engine.exe
   ```

2. **Verify gRPC connection:**
   ```python
   try:
       channel = grpc.insecure_channel('127.0.0.1:50051')
       grpc.channel_ready_future(channel).result(timeout=5)
       print("Connected!")
   except grpc.FutureTimeoutError:
       print("Cannot connect to SafeOps Engine")
   ```

3. **Check filters:**
   ```python
   # Try without filters first
   SubscribeRequest(subscriber_id="test")
   ```

---

### Issue: Low Performance / Dropped Packets

**Symptoms:**
- Slow internet
- `{"level":"WARN","message":"Subscriber channel full, dropping packet"}`

**Solutions:**

1. **Enable verdict caching:**
   ```python
   # Always use ttl_seconds > 0
   VerdictRequest(ttl_seconds=300)
   ```

2. **Increase channel buffer:**
   ```go
   // In SafeOps Engine code (default: 10000)
   Channel: make(chan *pb.PacketMetadata, 50000)
   ```

3. **Process packets faster:**
   ```python
   # Use async/threading to avoid blocking
   import concurrent.futures

   executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

   for packet in client.StreamMetadata(request):
       executor.submit(process_packet, packet)
   ```

---

### Issue: HTML Block Page Not Showing

**Symptoms:**
- `VerdictType.BLOCK` sent but browser shows "connection reset"

**Causes:**

1. **HTTPS traffic (port 443):**
   - Cannot inject HTML into encrypted HTTPS
   - Browser shows connection error (expected behavior)

2. **Not HTTP traffic:**
   - HTML injection only works for HTTP (port 80)
   - Other protocols get TCP RST

**Solution:**
- For HTTPS: Accept that browser will show error page
- For HTTP: HTML block page works automatically

---

### Issue: Verdicts Not Applied

**Symptoms:**
```python
response = client.ApplyVerdict(verdict_request)
# response.success = True, but traffic still flows
```

**Causes:**

1. **Wrong cache_key:**
   ```python
   # ✅ CORRECT: Use packet's cache_key
   VerdictRequest(cache_key=pkt.cache_key)

   # ❌ WRONG: Don't generate your own
   VerdictRequest(cache_key=f"{src_ip}:{dst_ip}")
   ```

2. **Packet already passed:**
   - Verdicts apply to **future packets**
   - First packet of connection always passes

3. **TTL expired:**
   ```python
   # Verdict expired after ttl_seconds
   VerdictRequest(ttl_seconds=1)  # Expires after 1 second
   ```

---

## Advanced Examples

### Example 1: Firewall with Blocklist

```python
import grpc
from safeops_pb2 import *
from safeops_pb2_grpc import *

# Blocklist
BLOCKED_DOMAINS = {"malware.com", "phishing.net", "tracker.biz"}

def run_firewall():
    channel = grpc.insecure_channel('127.0.0.1:50051')
    client = MetadataStreamServiceStub(channel)

    request = SubscribeRequest(
        subscriber_id="simple-firewall-v1",
        filters=["tcp", "udp"]
    )

    print("Firewall started - monitoring traffic...")

    for packet in client.StreamMetadata(request):
        # Check domain against blocklist
        if packet.domain in BLOCKED_DOMAINS:
            print(f"🛡️ BLOCKED: {packet.domain} ({packet.src_ip} → {packet.dst_ip})")

            # Apply BLOCK verdict with 1-hour cache
            client.ApplyVerdict(VerdictRequest(
                packet_id=packet.packet_id,
                verdict=VerdictType.BLOCK,
                reason=f"Domain '{packet.domain}' is on blocklist",
                rule_id="BLOCKLIST_DOMAIN",
                ttl_seconds=3600,
                cache_key=packet.cache_key
            ))
        else:
            # Allow through (implicit - no verdict needed)
            pass

if __name__ == "__main__":
    run_firewall()
```

---

### Example 2: IDS - Port Scan Detection

```python
import grpc
import time
from collections import defaultdict
from safeops_pb2 import *
from safeops_pb2_grpc import *

class PortScanDetector:
    def __init__(self):
        self.port_attempts = defaultdict(set)  # IP → set of ports
        self.last_reset = time.time()

    def is_port_scan(self, src_ip, dst_port):
        # Reset counters every 10 seconds
        if time.time() - self.last_reset > 10:
            self.port_attempts.clear()
            self.last_reset = time.time()

        # Track ports accessed by this IP
        self.port_attempts[src_ip].add(dst_port)

        # Alert if more than 10 ports in 10 seconds
        return len(self.port_attempts[src_ip]) > 10

def run_ids():
    channel = grpc.insecure_channel('127.0.0.1:50051')
    client = MetadataStreamServiceStub(channel)
    detector = PortScanDetector()

    request = SubscribeRequest(
        subscriber_id="ids-portscan-v1",
        filters=["tcp"]
    )

    print("IDS started - detecting port scans...")

    for packet in client.StreamMetadata(request):
        if packet.is_syn:  # SYN packet = connection attempt
            if detector.is_port_scan(packet.src_ip, packet.dst_port):
                print(f"🚨 PORT SCAN DETECTED from {packet.src_ip}")

                # Drop all packets from this IP (silently)
                client.ApplyVerdict(VerdictRequest(
                    packet_id=packet.packet_id,
                    verdict=VerdictType.DROP,
                    reason=f"Port scan detected from {packet.src_ip}",
                    rule_id="IDS_PORTSCAN",
                    ttl_seconds=60,  # Block for 1 minute
                    cache_key=packet.cache_key
                ))

if __name__ == "__main__":
    run_ids()
```

---

### Example 3: Parental Control with Redirect

```python
import grpc
from safeops_pb2 import *
from safeops_pb2_grpc import *

# Blocked categories
SOCIAL_MEDIA = {"facebook.com", "instagram.com", "tiktok.com"}
GAMING = {"steam.com", "twitch.tv", "roblox.com"}

# Redirect IP (run a web server here with block page)
REDIRECT_IP = "192.168.1.100"

def run_parental_control():
    channel = grpc.insecure_channel('127.0.0.1:50051')
    client = MetadataStreamServiceStub(channel)

    request = SubscribeRequest(
        subscriber_id="parental-control-v1",
        filters=["dns", "tcp"]
    )

    print("Parental Control started...")

    for packet in client.StreamMetadata(request):
        domain = packet.domain

        # Check if domain is blocked
        if domain in SOCIAL_MEDIA or domain in GAMING:
            if packet.is_dns_query:
                # Redirect DNS query
                print(f"🔒 REDIRECTED: {domain} → {REDIRECT_IP}")

                client.ApplyVerdict(VerdictRequest(
                    packet_id=packet.packet_id,
                    verdict=VerdictType.REDIRECT,
                    reason=f"Category blocked: {domain}",
                    rule_id="PARENTAL_CATEGORY_BLOCK",
                    ttl_seconds=600,  # Cache for 10 minutes
                    cache_key=packet.cache_key
                ))
            else:
                # Block TCP connections (in case DNS was cached)
                client.ApplyVerdict(VerdictRequest(
                    packet_id=packet.packet_id,
                    verdict=VerdictType.BLOCK,
                    reason=f"Category blocked: {domain}",
                    rule_id="PARENTAL_CATEGORY_BLOCK",
                    ttl_seconds=600,
                    cache_key=packet.cache_key
                ))

if __name__ == "__main__":
    run_parental_control()
```

---

## Support & Resources

### Documentation
- **Protobuf Definition**: `D:\SafeOpsFV2\proto\metadata_stream.proto`
- **Architecture Overview**: `D:\SafeOpsFV2\docs\ARCHITECTURE.md`
- **Performance Guide**: `D:\SafeOpsFV2\docs\PERFORMANCE.md`

### Example Code
- **Python Examples**: `D:\SafeOpsFV2\examples\python\`
- **Go Examples**: `D:\SafeOpsFV2\examples\go\`
- **C# Examples**: `D:\SafeOpsFV2\examples\csharp\`

### Community
- **Issues**: Report bugs and feature requests
- **Discussions**: Ask questions and share implementations

---

## License

SafeOps Engine is proprietary software. See LICENSE for details.

---

**Version**: 3.0.0
**Last Updated**: 2026-02-03
**Author**: SafeOps Team
