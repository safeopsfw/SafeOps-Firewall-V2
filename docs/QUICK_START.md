# SafeOps Engine - Quick Start Guide

Get started with SafeOps Engine in 5 minutes!

---

## Step 1: Start SafeOps Engine

**Requirements:**
- Windows 10/11
- Administrator privileges (required for driver access)

**Start the engine:**
```bash
# Navigate to binary directory
cd D:\SafeOpsFV2\bin\safeops-engine

# Run as Administrator
safeops-engine.exe
```

**Expected output:**
```
=== SafeOps Network Pipeline ===
Version: 3.0.0 (Metadata Stream)
{"level":"INFO","message":"gRPC server created","data":{"address":"127.0.0.1:50051"}}
{"level":"INFO","message":"Monitoring adapters","data":{"count":5}}

SafeOps Engine is running
Metadata stream ready for subscribers
Press Ctrl+C to stop...
```

✅ **Success!** SafeOps Engine is now capturing packets from all network interfaces.

---

## Step 2: Install Python Client (Optional)

If you want to use the Python examples:

```bash
# Install gRPC Python libraries
pip install grpcio grpcio-tools

# Generate Python protobuf files
cd D:\SafeOpsFV2\proto
python -m grpc_tools.protoc -I. --python_out=../examples/python --grpc_python_out=../examples/python metadata_stream.proto
```

---

## Step 3: Run Simple Firewall Example

```bash
cd D:\SafeOpsFV2\examples\python
python simple_firewall.py
```

**Expected output:**
```
🔥 SafeOps Simple Firewall
================================================================================
🔌 Connecting to SafeOps Engine at 127.0.0.1:50051...
✅ Connected successfully!

📊 SafeOps Engine Statistics:
   Packets Read:       12,543
   Packets Written:    12,480
   Packets Dropped:    63
   Active Subscribers: 1
   Verdicts Applied:   125
   Cached Verdicts:    42

🚀 Starting firewall...
   Blocked domains: 4
   Allowed domains: 3

📡 Monitoring traffic... (Press Ctrl+C to stop)

Time     | Status   | Source IP       Port    Destination IP  Port  | Proto | Domain                         | Reason
--------------------------------------------------------------------------------------
14:30:45 | ✅ ALLOWED | 192.168.1.100   12345 → 8.8.8.8          53   | UDP | google.com                     | Domain 'google.com' is whitelisted
14:30:46 | 🛡️ BLOCKED | 192.168.1.100   12346 → 1.2.3.4          80   | TCP | malware.com                    | Domain 'malware.com' is on blocklist
14:30:47 | ✅ ALLOWED | 192.168.1.100   12347 → 140.82.114.4    443  | TCP | github.com                     | Domain 'github.com' is whitelisted
```

---

## Step 4: Test Block Page (HTTP Only)

1. **Add a domain to blocklist:**
   - Edit `simple_firewall.py`
   - Add `"example.com"` to `self.blocked_domains`

2. **Restart firewall:**
   ```bash
   python simple_firewall.py
   ```

3. **Visit HTTP site in browser:**
   ```
   http://example.com
   ```

4. **See custom block page:**
   - Beautiful block page with reason
   - Shows rule ID and timestamp
   - SafeOps branding

**Note:** HTTPS sites (port 443) will show "Connection reset" error instead, since TLS encryption prevents HTML injection.

---

## Step 5: Monitor Statistics

While firewall is running, check stats:

```python
# In separate Python shell
import grpc
import metadata_stream_pb2 as pb
import metadata_stream_pb2_grpc as pb_grpc

channel = grpc.insecure_channel('127.0.0.1:50051')
client = pb_grpc.MetadataStreamServiceStub(channel)

stats = client.GetStats(pb.StatsRequest())
print(f"Packets: {stats.packets_read} read, {stats.packets_dropped} dropped")
print(f"Cache: {stats.cached_verdicts} entries")
```

---

## Common Tasks

### Add Domain to Blocklist

Edit `simple_firewall.py`:
```python
self.blocked_domains = {
    "malware.com",
    "phishing.net",
    "tracker.biz",
    "newdomain.com",  # Add here
}
```

### Change Cache Duration

Edit verdict TTL:
```python
return (
    pb.VerdictType.BLOCK,
    "Reason",
    7200,  # Change from 3600 to 7200 (2 hours)
)
```

### Filter Only DNS Traffic

Change subscription filter:
```python
request = pb.SubscribeRequest(
    subscriber_id="my-app",
    filters=["dns"]  # Only DNS packets
)
```

### Silent Drop Instead of Block

Change verdict type:
```python
return (
    pb.VerdictType.DROP,  # Silent drop (no RST/HTML)
    "Reason",
    ttl
)
```

---

## Next Steps

📖 **Read Full Integration Guide:**
   - `D:\SafeOpsFV2\docs\INTEGRATION_GUIDE.md`

💻 **Explore Examples:**
   - Python: `D:\SafeOpsFV2\examples\python\`
   - Go: `D:\SafeOpsFV2\examples\go\`
   - C#: `D:\SafeOpsFV2\examples\csharp\`

🔧 **Build Your Own:**
   - Firewall with custom rules
   - IDS/IPS for intrusion detection
   - Parental control with time limits
   - DDoS protection
   - Network monitor

---

## Troubleshooting

### "Cannot connect to SafeOps Engine"

**Solution:** Make sure SafeOps Engine is running as Administrator.

```bash
# Check if running
tasklist | findstr safeops-engine

# If not running, start it
safeops-engine.exe
```

---

### "No packets received"

**Solution:** Generate some network traffic.

```bash
# Open browser and visit any website
# Or ping a server
ping google.com
```

---

### "Slow internet speed"

**Solution:** Check verdict caching is enabled.

```python
# ✅ GOOD: Always use ttl_seconds > 0
VerdictRequest(ttl_seconds=300)

# ❌ BAD: No caching
VerdictRequest(ttl_seconds=0)
```

---

### "Block page not showing"

**Possible causes:**
1. **HTTPS site (port 443):** Cannot inject HTML into encrypted traffic
   - Browser shows "Connection reset" - this is expected
   - Only HTTP (port 80) supports custom block pages

2. **Not HTTP traffic:** HTML injection only works for HTTP
   - Other protocols get TCP RST instead

---

## Performance Notes

✅ **Zero impact on network speed:**
- Full 400+ Mbps maintained
- <1μs latency for cached verdicts
- ~100μs for new connections

✅ **Verdict caching is critical:**
- First packet: Full analysis + domain extraction
- Cached packets: Instant decision (100x faster)
- Always use `ttl_seconds > 0`

✅ **Gaming traffic bypassed:**
- No domain extraction for non-standard ports
- Gaming/VoIP traffic unaffected
- Firewall only sees relevant traffic

---

## Support

- **Documentation:** `D:\SafeOpsFV2\docs\`
- **Examples:** `D:\SafeOpsFV2\examples\`
- **Issues:** Report bugs and request features

---

**Happy packet filtering!** 🚀🛡️
