# Network Logger Enhancement Plan

## Goal
Upgrade network logger output to produce 5 log files in IDS/IPS-ready, SIEM-optimized formats. No detection engine yet — just the RIGHT data in the RIGHT format.

## 5 Output Files

| # | File | Mode | Purpose |
|---|------|------|---------|
| 1 | `network_packets_master.jsonl` | 5-min TRUNCATE (keep as-is) | Raw enriched packet data |
| 2 | `ids_ips.jsonl` | APPEND + rotate | Suricata EVE JSON compatible events |
| 3 | `netflow/east_west.log` | APPEND + rotate | LAN↔LAN flows |
| 4 | `netflow/north_south.log` | APPEND + rotate | LAN↔WAN flows |
| 5 | `ip_summary.jsonl` | APPEND + rotate | 5-min per-IP aggregated summaries |

Remove firewall.log and devices.jsonl from default pipeline (user specified these 4+1).

## Implementation Steps

### Step 1: Add rotating writer utility
**New file**: `internal/writer/rotating_writer.go`
- APPEND mode writer with size-based rotation
- Rotate at configurable size (default 50MB)
- Keep N rotated files (default 3)
- Gzip old files for storage optimization
- Used by IDS, NetFlow, and IP Summary collectors

### Step 2: Enrich packet model (`pkg/models/packet.go`)
Add fields the IDS/IPS will need later:
- `community_id` (string) — Community ID v1 hash for cross-tool flow correlation
- `direction` (string) — "inbound"/"outbound"/"internal"
- `event_type` (string) — "packet" (default for master log)
- `app_proto` (string) — Clean app protocol name (dns/http/tls/ssh/etc)
- `icmp_type`, `icmp_code` (uint8) on NetworkLayer — ICMP analysis
- `ja3_hash`, `ja3s_hash` (string) on TLSData — TLS fingerprinting
- Increase payload capture: 256→512 bytes hex default
- Add ARP struct for ARP packet capture

### Step 3: Capture ICMP + ARP layers (`internal/capture/engine.go`)
- Extract `layers.LayerTypeICMPv4` from gopacket
- Extract `layers.LayerTypeARP` from gopacket
- Pass to packet processor

### Step 4: Compute enrichments (`internal/capture/packet_processor.go`)
- Compute Community ID v1 from 5-tuple
- Compute packet direction (inbound/outbound/internal)
- Set `app_proto` field
- Parse ICMP type/code
- Parse ARP opcode/addresses
- Increase payload hex to 512 bytes

### Step 5: Add JA3/JA3S hashing (`internal/parser/tls.go`)
- Compute JA3 hash from ClientHello fields (version + cipher suites + extensions + EC + EC point formats → MD5)
- Compute JA3S hash from ServerHello fields
- Store in TLSData struct

### Step 6: Rewrite IDS collector to EVE JSON format (`internal/collectors/idsips_log_collector.go`)
Complete rewrite. Output one EVE event per logical event (not per packet):
- DNS event: one per query/response pair
- HTTP event: one per request
- TLS event: one per handshake (ClientHello)
- Flow event: on flow close (timeout/FIN/RST)

EVE format:
```json
{
  "timestamp": "ISO8601",
  "event_type": "dns|http|tls|flow",
  "src_ip": "x.x.x.x", "src_port": 54321,
  "dst_ip": "y.y.y.y", "dst_port": 443,
  "proto": "TCP",
  "community_id": "1:hash",
  "flow_id": "flow_xxx",
  "app_proto": "tls",
  "direction": "outbound",
  "dns": { "type": "query", "rrname": "example.com", "rrtype": "A", "rcode": "NOERROR", "answers": [...] },
  "http": { "hostname": "...", "url": "/path", "http_method": "GET", "http_user_agent": "...", "status": 200, "length": 1234 },
  "tls": { "sni": "example.com", "version": "TLS 1.3", "ja3": "hash", "ja3s": "hash" },
  "flow": { "pkts_toserver": 5, "pkts_toclient": 3, "bytes_toserver": 1200, "bytes_toclient": 800, "start": "...", "end": "...", "state": "closed", "reason": "timeout" },
  "process": { "pid": 1234, "name": "chrome.exe" },
  "src_geo": {}, "dst_geo": {}
}
```
- Uses rotating writer (APPEND + 50MB rotation)
- Smart dedup: one event per DNS query, one per HTTP request, one per TLS handshake
- Tracks flows internally and emits flow-end events

### Step 7: Enrich NetFlow collector (`internal/collectors/biflow_collector.go`)
Add missing IPFIX-standard fields:
- `tcp_flags_aggregate` — OR'd flags across entire flow
- `flow_end_reason` — "timeout"/"fin"/"rst"/"eviction"
- `app_proto` — detected application protocol
- `community_id` — for cross-log correlation
- `process` — process info from flow context
- `tos`/`dscp` — QoS fields
- Switch to rotating writer (APPEND + 50MB rotation)

### Step 8: Create IP Summary collector
**New file**: `internal/collectors/ip_summary_collector.go`
- Accumulates per-IP stats from each packet in-memory
- Every 5 minutes, flushes all IPs as one summary block
- Per-IP fields:
  ```json
  {
    "timestamp": "ISO8601",
    "period_start": "ISO8601",
    "period_end": "ISO8601",
    "ip": "192.168.1.100",
    "is_local": true,
    "mac": "AA:BB:CC:DD:EE:FF",
    "total_packets_sent": 15000,
    "total_packets_recv": 12000,
    "total_bytes_sent": 5242880,
    "total_bytes_recv": 10485760,
    "protocols": {"TCP": 80, "UDP": 15, "ICMP": 5},
    "top_destinations": [{"ip":"8.8.8.8","port":443,"bytes":1024000}],
    "top_sources": [{"ip":"203.0.113.50","port":54321,"bytes":2048}],
    "active_flows": 25,
    "dns_queries": 150,
    "processes": [{"name":"chrome.exe","connections":15,"bytes":4000000}]
  }
  ```
- Uses rotating writer

### Step 9: Storage optimization across all logs
- Add `omitempty` to ALL model struct fields (many currently missing it)
- Master log dedup enhancement: for established TCP, only log SYN + app-layer + state changes + 1 sample per 10 data packets
- Remove `deduplication` field from master log output (internal bookkeeping, not needed in output)
- Remove `session_tracking` from master output (redundant with flow_context)

### Step 10: Update config and main.go
- `internal/config/config.go`: Add rotation size, max files, payload size configs
- `cmd/logger/main.go`:
  - Wire up new IP Summary collector
  - Wire up rotating writer for IDS + NetFlow
  - Remove firewall collector and device collector from pipeline
  - Pass ICMP/ARP layers through pipeline

### Step 11: Cleanup
- Remove `internal/collectors/firewall_log_collector.go` from pipeline (keep file, just don't wire)
- Remove `internal/collectors/device_collector.go` from pipeline
- Remove `internal/collectors/log_analyzer.go` from pipeline
- Remove `internal/collectors/mac_vendor.go` from pipeline (if only used by device collector)

## Implementation Order
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11

## Verification
- Build: `cd src/network_logger && go build ./cmd/logger/`
- Run briefly, capture some packets, check each of the 5 output files
- Validate EVE JSON format is parseable
- Check log sizes are reasonable (not flooding)
