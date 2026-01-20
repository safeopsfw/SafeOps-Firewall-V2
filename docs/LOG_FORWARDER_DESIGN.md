# SafeOps Log Forwarder - Design Documentation

## Overview

This document provides comprehensive information about SafeOps logging architecture, log formats, rotation mechanisms, and the design specifications for implementing a log forwarder to the SIEM system.

## Table of Contents

1. [Current Logging Architecture](#current-logging-architecture)
2. [Log File Structure](#log-file-structure)
3. [Log Formats](#log-formats)
4. [Log Rotation Mechanism](#log-rotation-mechanism)
5. [Log Forwarder Design](#log-forwarder-design)
6. [Implementation Specifications](#implementation-specifications)

---

## Current Logging Architecture

### Component Overview

SafeOps uses a multi-component logging system:

```
┌─────────────────────────────────────────────────────────────┐
│                    SafeOps Engine                           │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────┐  │
│  │ Network  │  │   DHCP    │  │ Captive  │  │  Step   │  │
│  │ Logger   │  │  Monitor  │  │  Portal  │  │   CA    │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └────┬────┘  │
└───────┼──────────────┼─────────────┼─────────────┼────────┘
        │              │             │             │
        ▼              ▼             ▼             ▼
   ┌────────────────────────────────────────────────────┐
   │          D:\SafeOpsFV2\bin\logs\                   │
   ├────────────────────────────────────────────────────┤
   │  ├─ netflow/                                       │
   │  │   ├─ north_south.log   (Internet traffic)      │
   │  │   ├─ east_west.log     (Internal traffic)      │
   │  │   └─ unknown.log       (Unclassified)          │
   │  ├─ engine.log            (Engine operations)     │
   │  ├─ ids.log               (IDS events)            │
   │  ├─ firewall.log          (Firewall decisions)    │
   │  └─ network_packets_master.jsonl (All packets)    │
   └────────────────────────────────────────────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Log Forwarder│
                  │  (To Build)  │
                  └──────┬───────┘
                         │
                         ▼
                ┌────────────────┐
                │  ELK Stack     │
                │  (Logstash)    │
                └────────────────┘
```

### Log File Locations

| Log File | Path | Purpose | Format | Rotation |
|----------|------|---------|--------|----------|
| **Network Flow Logs** | `bin/logs/netflow/*.log` | Network traffic flows | JSONL | 5 min |
| **Engine Logs** | `bin/logs/engine.log` | SafeOps engine operations | JSONL | None |
| **IDS Logs** | `bin/logs/ids.log` | Intrusion detection events | JSONL | 5 min |
| **Firewall Logs** | `bin/logs/firewall.log` | Firewall block/allow decisions | JSONL | 5 min |
| **Master Packet Log** | `bin/logs/network_packets_master.jsonl` | All captured packets | JSONL | 5 min (overwrite) |

---

## Log File Structure

### 1. Network Flow Logs (`netflow/`)

#### Directory Structure
```
bin/logs/netflow/
├── north_south.log       # Traffic to/from Internet
├── east_west.log         # Internal LAN-to-LAN traffic
└── unknown.log           # Unclassified traffic
```

#### Classification Logic
- **North-South**: One endpoint is private IP (RFC1918), other is public
- **East-West**: Both endpoints are private IPs
- **Unknown**: Cannot determine direction

#### File Size Characteristics
- **north_south.log**: Largest file (typically 80-90% of all traffic)
- **east_west.log**: Medium (5-15% of traffic)
- **unknown.log**: Smallest (1-5% of traffic)

### 2. Engine Log

**Purpose**: SafeOps engine operational logs
**Location**: `bin/logs/engine.log`
**Characteristics**:
- Contains startup/shutdown events
- Service health checks
- Configuration changes
- Error messages
- Statistics (every 30 seconds)

### 3. IDS Log

**Purpose**: Intrusion Detection System alerts
**Location**: `bin/logs/ids.log`
**Characteristics**:
- Malicious pattern detections
- Threat intelligence matches
- Anomaly detections
- Critical security events

### 4. Firewall Log

**Purpose**: Firewall block/allow decisions
**Location**: `bin/logs/firewall.log`
**Characteristics**:
- Connection blocks
- Connection allows
- Policy violations
- Rule matches

---

## Log Formats

All SafeOps logs use **JSONL** (JSON Lines) format - one JSON object per line.

### Network Flow Log Format

```json
{
  "timestamp": "2026-01-13T12:25:13+05:30",
  "flow_id": "192.168.1.11:63637-20.50.88.242:443/TCP",
  "event_id": "flow_192.168.1.11:636",
  "src_ip": "192.168.1.11",
  "dst_ip": "20.50.88.242",
  "src_port": 63637,
  "dst_port": 443,
  "protocol": "TCP",
  "direction": "north-south",
  "initiator": "local",
  "packets_toserver": 8,
  "packets_toclient": 9,
  "bytes_toserver": 1713,
  "bytes_toclient": 5378,
  "flow_duration": 0.0063434,
  "src_geo": {
    "country": "XX",
    "country_name": "Private"
  },
  "dst_geo": {
    "country": "XX",
    "country_name": "Private"
  }
}
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO8601 | Event timestamp with timezone |
| `flow_id` | string | Unique flow identifier: `srcIP:srcPort-dstIP:dstPort/Protocol` |
| `event_id` | string | Short event ID for correlation |
| `src_ip` | string | Source IP address (IPv4 or IPv6) |
| `dst_ip` | string | Destination IP address |
| `src_port` | integer | Source port (0-65535) |
| `dst_port` | integer | Destination port (0-65535) |
| `protocol` | string | Transport protocol: `TCP`, `UDP`, `ICMP` |
| `direction` | string | Traffic direction: `north-south`, `east-west`, `unknown` |
| `initiator` | string | Who initiated: `local`, `internet` |
| `packets_toserver` | integer | Packets sent to server |
| `packets_toclient` | integer | Packets sent to client |
| `bytes_toserver` | integer | Bytes sent to server |
| `bytes_toclient` | integer | Bytes sent to client |
| `flow_duration` | float | Connection duration in seconds |
| `src_geo` | object | Source IP geolocation |
| `dst_geo` | object | Destination IP geolocation |

### Engine Log Format

```json
{
  "timestamp": "2026-01-17T04:20:46.953474Z",
  "level": "INFO",
  "message": "SafeOps Engine starting",
  "data": {
    "mode": "go-proxy",
    "version": "2.0.0"
  }
}
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO8601 | Event timestamp (UTC) |
| `level` | string | Log level: `INFO`, `WARN`, `ERROR`, `DEBUG` |
| `message` | string | Human-readable message |
| `data` | object | Additional context (optional) |

### Statistics Log Entry

```json
{
  "timestamp": "2026-01-17T04:21:24.0947445Z",
  "level": "INFO",
  "message": "Stats",
  "data": {
    "bypass": 407,
    "dns": 146,
    "dns_redir": 144,
    "drop": 0,
    "dropped": 0,
    "http": 35,
    "packets": 9955,
    "proxy_blocked": 0,
    "proxy_reqs": 41,
    "written": 588
  }
}
```

---

## Log Rotation Mechanism

### Overview

SafeOps implements a **time-based log rotation** system with two strategies:

1. **Overwrite Cycle** (Master Packet Log)
2. **Append Rotation** (NetFlow, IDS, Firewall)

### 1. Overwrite Cycle (Master Log)

**File**: `network_packets_master.jsonl`
**Interval**: 5 minutes
**Behavior**: File is **truncated and overwritten** every 5 minutes

#### Implementation

```go
// From: src/network_logger/internal/writer/json_writer.go

func (w *JSONWriter) cycleLoop(ctx context.Context) {
    ticker := time.NewTicker(w.cycleInterval) // 5 minutes
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            // Truncate file - clears all existing content
            w.openFile() // os.O_TRUNC flag
        case <-ctx.Done():
            return
        }
    }
}

func (w *JSONWriter) openFile() error {
    // Open file in truncate mode (clears existing content)
    file, err := os.OpenFile(
        w.logPath,
        os.O_WRONLY|os.O_CREATE|os.O_TRUNC, // <-- TRUNC clears file
        0644,
    )
    // ...
}
```

**Why Overwrite?**
- Master log captures ALL packets (high volume)
- Only needs last 5 minutes for IDS/IPS analysis
- Prevents disk space exhaustion
- IDS agents process in real-time, don't need historical data

### 2. Append Rotation (NetFlow, IDS, Firewall)

**Files**: `netflow/*.log`, `ids.log`, `firewall.log`
**Interval**: 5 minutes
**Behavior**: Create new file with timestamp, keep old files

#### File Naming Convention

```
# NetFlow logs
bin/logs/netflow/north_south.log                    # Current (symlink or latest)
bin/logs/netflow/north_south.2026-01-20T14-30.log   # Rotated
bin/logs/netflow/north_south.2026-01-20T14-35.log   # Rotated
bin/logs/netflow/north_south.2026-01-20T14-40.log   # Rotated

# IDS logs
bin/logs/ids.log                                     # Current
bin/logs/ids.2026-01-20T14-30.log                   # Rotated
bin/logs/ids.2026-01-20T14-35.log                   # Rotated
```

#### Configuration

```yaml
# bin/network_logger/config.yaml

logging:
  log_path: "D:/SafeOpsFV2/bin/logs/network_packets_master.jsonl"
  batch_size: 75
  cycle_minutes: 5                  # Master log overwrite cycle
  log_rotation_minutes: 5           # NetFlow/IDS/Firewall rotation
```

#### Implementation Details

```go
// From: src/network_logger/internal/config/config.go

// GetLogCycleInterval returns log cycle interval (for master log)
func (c *Config) GetLogCycleInterval() time.Duration {
    return time.Duration(c.Logging.CycleMinutes) * time.Minute  // 5 min
}

// GetLogRotationInterval returns rotation interval (NetFlow, IDS, Firewall)
func (c *Config) GetLogRotationInterval() time.Duration {
    return time.Duration(c.Logging.LogRotationMinutes) * time.Minute  // 5 min
}
```

### Rotation Characteristics

| Aspect | Master Log | NetFlow/IDS/Firewall |
|--------|------------|---------------------|
| **Strategy** | Overwrite | Append + Rotate |
| **Interval** | 5 minutes | 5 minutes |
| **History** | None (5 min window) | All rotated files |
| **Disk Usage** | Constant (~10-50 MB) | Growing (requires cleanup) |
| **Use Case** | Real-time IDS analysis | Historical analysis, SIEM |

---

## Log Forwarder Design

### Requirements

The log forwarder must:

1. ✅ Monitor log files for changes (new data)
2. ✅ Read new log lines incrementally (no re-reading)
3. ✅ Handle log rotation gracefully
4. ✅ Forward logs to Logstash (ELK Stack)
5. ✅ Maintain state (position tracking)
6. ✅ Support multiple log sources simultaneously
7. ✅ Be resilient to failures (retry logic)
8. ✅ Minimal resource usage (CPU, memory)

### Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Log Forwarder                           │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │          File Watcher (inotify/fsnotify)             │ │
│  └──────────────┬───────────────────────────────────────┘ │
│                 │                                          │
│  ┌──────────────▼───────────────────────────────────────┐ │
│  │  File Readers (per log file)                        │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐    │ │
│  │  │ NetFlow    │  │    IDS     │  │  Firewall  │    │ │
│  │  │  Reader    │  │   Reader   │  │   Reader   │    │ │
│  │  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘    │ │
│  └─────────┼────────────────┼────────────────┼──────────┘ │
│            │                │                │            │
│  ┌─────────▼────────────────▼────────────────▼──────────┐ │
│  │          Line Parser & Validator                     │ │
│  └──────────┬───────────────────────────────────────────┘ │
│             │                                              │
│  ┌──────────▼───────────────────────────────────────────┐ │
│  │          Batch Queue (1000 lines)                    │ │
│  └──────────┬───────────────────────────────────────────┘ │
│             │                                              │
│  ┌──────────▼───────────────────────────────────────────┐ │
│  │    Logstash Sender (HTTP/TCP)                        │ │
│  │    - Retry logic                                     │ │
│  │    - Backpressure handling                           │ │
│  └──────────┬───────────────────────────────────────────┘ │
│             │                                              │
│  ┌──────────▼───────────────────────────────────────────┐ │
│  │          State Persistence                           │ │
│  │    (file offsets, last read position)                │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
                ┌────────────────┐
                │   Logstash     │
                │  (Port 5044)   │
                └────────────────┘
```

### Component Breakdown

#### 1. File Watcher

**Technology**: `fsnotify` (Go) or `watchdog` (Python)

**Responsibilities**:
- Monitor log directories for changes
- Detect file creation, modification, deletion
- Handle log rotation (file rename, new file creation)
- Trigger file readers when changes occur

**Events to Watch**:
- `CREATE`: New log file created
- `WRITE`: Data written to log file
- `RENAME`: Log rotation (old file renamed)
- `DELETE`: Log file deleted

#### 2. File Readers

**Per-File State**:
```go
type FileReader struct {
    Path          string
    Offset        int64      // Current read position
    LastInode     uint64     // File inode (rotation detection)
    LastSize      int64      // File size
    BufferedLines chan string
}
```

**Read Strategy**:
1. Open file at current offset
2. Read new lines only (since last position)
3. Update offset after successful send
4. Persist offset to state file

**Rotation Handling**:
```go
// Detect rotation: inode changed or file shrunk
if currentInode != lastInode || currentSize < lastSize {
    // File rotated
    // 1. Read remaining lines from old file
    // 2. Close old file
    // 3. Open new file from beginning
    // 4. Reset offset to 0
}
```

#### 3. Line Parser & Validator

**Responsibilities**:
- Validate JSON syntax
- Add metadata (source file, ingestion timestamp)
- Filter out malformed lines
- Enrich data (add tags, parse timestamps)

**Example Enrichment**:
```json
{
  "original": { /* Original log entry */ },
  "@timestamp": "2026-01-20T14:35:22.123Z",
  "@metadata": {
    "source_file": "/bin/logs/netflow/north_south.log",
    "source_type": "safeops-network",
    "beat": "safeops-forwarder",
    "version": "1.0.0"
  },
  "tags": ["safeops", "network", "north-south"]
}
```

#### 4. Batch Queue

**Purpose**: Improve throughput by batching events

**Configuration**:
- Batch size: 1000 events or 5 seconds (whichever comes first)
- Queue capacity: 10,000 events
- Backpressure: Block readers when queue is full

#### 5. Logstash Sender

**Protocol Options**:

1. **HTTP** (Recommended)
   - Endpoint: `http://localhost:9600/_bulk`
   - Format: JSON bulk API
   - Pros: Simple, HTTP-based, good error messages
   - Cons: Slightly higher overhead

2. **Beats Protocol** (TCP)
   - Port: 5044
   - Format: Lumberjack protocol
   - Pros: Efficient, designed for log shipping
   - Cons: More complex implementation

3. **TCP with JSONL**
   - Port: 5000 (custom Logstash input)
   - Format: Newline-delimited JSON
   - Pros: Simplest implementation
   - Cons: No ACKs, less robust

**Retry Logic**:
```go
func SendBatch(batch []LogEntry) error {
    maxRetries := 3
    backoff := 1 * time.Second

    for attempt := 0; attempt < maxRetries; attempt++ {
        err := sendToLogstash(batch)
        if err == nil {
            return nil  // Success
        }

        // Exponential backoff
        time.Sleep(backoff)
        backoff *= 2
    }

    return fmt.Errorf("failed after %d retries", maxRetries)
}
```

#### 6. State Persistence

**State File Location**: `D:\SafeOpsFV2\data\forwarder_state.json`

**State Format**:
```json
{
  "version": "1.0",
  "last_updated": "2026-01-20T14:35:22Z",
  "files": {
    "D:\\SafeOpsFV2\\bin\\logs\\netflow\\north_south.log": {
      "offset": 1048576,
      "inode": 123456,
      "last_read": "2026-01-20T14:35:00Z"
    },
    "D:\\SafeOpsFV2\\bin\\logs\\ids.log": {
      "offset": 2048,
      "inode": 123457,
      "last_read": "2026-01-20T14:35:00Z"
    }
  }
}
```

**Persistence Strategy**:
- Save state every 10 seconds
- Save state on graceful shutdown
- Load state on startup (resume from last position)

---

## Implementation Specifications

### Technology Options

#### Option 1: Filebeat (Elastic Official - Recommended)

**Pros**:
- Official Elastic product
- Battle-tested, production-ready
- Built-in log rotation handling
- Automatic retry and backpressure
- Minimal configuration

**Cons**:
- External dependency
- Less customization

**Configuration**:
```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/netflow/*.log
    fields:
      log_type: network
      direction: netflow
    json.keys_under_root: true

  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/ids.log
    fields:
      log_type: ids
    json.keys_under_root: true

  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/firewall.log
    fields:
      log_type: firewall
    json.keys_under_root: true

output.logstash:
  hosts: ["localhost:5044"]
  bulk_max_size: 1000
  worker: 2
```

#### Option 2: Custom Go Forwarder

**Pros**:
- Full control
- Lightweight
- Integrated with SafeOps architecture
- Can add custom logic

**Cons**:
- Development time
- Need to handle edge cases

**Dependencies**:
```go
import (
    "github.com/fsnotify/fsnotify"    // File watching
    "github.com/elastic/go-lumber"    // Lumberjack protocol (optional)
    "gopkg.in/yaml.v3"                // Config parsing
)
```

**Project Structure**:
```
src/log_forwarder/
├── main.go
├── config.yaml
├── internal/
│   ├── watcher/
│   │   └── file_watcher.go         # fsnotify wrapper
│   ├── reader/
│   │   ├── file_reader.go          # Read log files
│   │   └── rotation_handler.go     # Handle rotation
│   ├── parser/
│   │   └── json_parser.go          # Parse JSONL
│   ├── sender/
│   │   ├── logstash_sender.go      # Send to Logstash
│   │   └── retry.go                # Retry logic
│   └── state/
│       └── persistence.go           # State management
└── pkg/
    └── models/
        └── log_entry.go             # Data models
```

#### Option 3: Fluentd/Fluent Bit

**Pros**:
- Flexible plugins
- Can route to multiple destinations
- Good performance (Fluent Bit)

**Cons**:
- Ruby dependency (Fluentd) or another binary (Fluent Bit)
- Configuration complexity

**Not Recommended** for SafeOps due to added dependencies.

### Recommended Approach

**Phase 1: Use Filebeat (Immediate)**
- Deploy official Filebeat
- Configure inputs for SafeOps logs
- Send to Logstash
- Minimal development time

**Phase 2: Custom Forwarder (Optional)**
- Build custom Go forwarder if needed
- Add SafeOps-specific features
- Tighter integration

---

## Log Rotation Edge Cases

### Scenario 1: File Rotated While Reading

**Problem**: Log file renamed while forwarder is reading

**Detection**:
```go
// Check if inode changed
currentStat, _ := os.Stat(filePath)
if currentStat.Sys().(*syscall.Stat_t).Ino != lastInode {
    // File rotated
}
```

**Handling**:
1. Finish reading current file (old inode)
2. Close file handle
3. Open new file (new inode) from offset 0
4. Continue reading

### Scenario 2: Multiple Rotations During Downtime

**Problem**: Forwarder offline, multiple log files rotated

**Solution**:
1. Scan log directory for all rotated files
2. Sort by timestamp
3. Process in chronological order
4. Skip already-processed files (check state)

### Scenario 3: Log File Deleted

**Problem**: Log file deleted before forwarder reads it

**Handling**:
- Log warning
- Mark file as processed in state
- Continue with next file

### Scenario 4: Incomplete Lines

**Problem**: File rotated mid-line

**Handling**:
```go
// Buffer incomplete lines
var incompleteLineLine string

for {
    line, err := reader.ReadString('\n')
    if err == io.EOF {
        // No newline yet
        incompleteLine = line
        break
    }
    processLine(line)
}

// On next read
line = incompleteLine + reader.ReadString('\n')
```

---

## Performance Considerations

### Expected Log Volume

| Log Type | Events/Minute | Size/Minute | Daily Volume |
|----------|--------------|-------------|--------------|
| NetFlow | 1,000 - 10,000 | 500 KB - 5 MB | 0.7 - 7 GB |
| IDS | 10 - 100 | 5 - 50 KB | 7 - 70 MB |
| Firewall | 50 - 500 | 25 - 250 KB | 35 - 350 MB |
| Engine | 20 - 200 | 2 - 20 KB | 3 - 30 MB |
| **Total** | **~1,000 - 10,000** | **~0.5 - 5 MB** | **~1 - 10 GB** |

### Resource Requirements

**Forwarder Process**:
- CPU: < 5% (idle), < 15% (peak)
- RAM: 50 - 200 MB
- Disk I/O: Minimal (sequential reads)
- Network: 1 - 10 Mbps (to Logstash)

**Batch Tuning**:
- Small batches (100): Lower latency, higher CPU
- Large batches (5000): Higher latency, lower CPU
- Recommended: 1000 events or 5 seconds

---

## Monitoring & Observability

### Metrics to Collect

```go
type ForwarderMetrics struct {
    LinesRead       int64   // Total lines read
    LinesSent       int64   // Lines sent to Logstash
    LinesFailed     int64   // Failed to send
    BytesRead       int64   // Total bytes read
    BytesSent       int64   // Bytes sent
    FilesWatched    int     // Number of files watched
    SendLatency     float64 // Avg send latency (ms)
    QueueDepth      int     // Current queue size
    RetryCount      int64   // Number of retries
}
```

### Health Checks

**Endpoint**: `http://localhost:9100/health`

**Response**:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "files_watched": 4,
  "lines_sent_last_minute": 1250,
  "queue_depth": 150,
  "logstash_connected": true,
  "last_error": null
}
```

### Logging

**Forwarder Logs**: `D:\SafeOpsFV2\bin\logs\forwarder.log`

**Log Levels**:
- `DEBUG`: Verbose (file reads, batch sends)
- `INFO`: Normal operations (startup, file rotation)
- `WARN`: Recoverable errors (retry attempts)
- `ERROR`: Failures (cannot connect to Logstash)

---

## Configuration Example

### Filebeat Configuration

```yaml
# D:\SafeOpsFV2\bin\log_forwarder\filebeat.yml

filebeat.inputs:
  # NetFlow Logs
  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/netflow/north_south.log
      - D:/SafeOpsFV2/bin/logs/netflow/east_west.log
      - D:/SafeOpsFV2/bin/logs/netflow/unknown.log
    fields:
      log_type: network
      component: netflow
    fields_under_root: true
    json.keys_under_root: true
    json.add_error_key: true
    close_inactive: 5m
    scan_frequency: 10s

  # IDS Logs
  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/ids.log
    fields:
      log_type: ids
      component: intrusion_detection
    fields_under_root: true
    json.keys_under_root: true
    json.add_error_key: true

  # Firewall Logs
  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/firewall.log
    fields:
      log_type: firewall
      component: firewall
    fields_under_root: true
    json.keys_under_root: true
    json.add_error_key: true

  # Engine Logs
  - type: log
    enabled: true
    paths:
      - D:/SafeOpsFV2/bin/logs/engine.log
    fields:
      log_type: engine
      component: safeops_engine
    fields_under_root: true
    json.keys_under_root: true
    json.add_error_key: true

# Output to Logstash
output.logstash:
  hosts: ["localhost:5044"]
  bulk_max_size: 1000
  worker: 2
  compression_level: 3
  ttl: 30s
  pipelining: 2

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: D:/SafeOpsFV2/bin/logs
  name: forwarder.log
  keepfiles: 7
  permissions: 0644

# Registry (state persistence)
filebeat.registry.path: D:/SafeOpsFV2/data/filebeat
filebeat.registry.flush: 1s
```

---

## Integration with SIEM

### Logstash Pipeline Configuration

Already configured in SIEM installer:
`D:\SafeOps-SIEM-Integration\logstash\logstash-*\config\pipeline\safeops-network.conf`

### Kibana Index Patterns

Create these in Kibana:
- `safeops-network-*` - Network flow logs
- `safeops-ids-*` - IDS events
- `safeops-firewall-*` - Firewall logs
- `safeops-engine-*` - Engine logs

### Dashboards

**Network Traffic Dashboard**:
- Top source IPs
- Top destination IPs
- Protocol distribution
- Traffic volume over time
- Geographic map

**IDS Dashboard**:
- Alert timeline
- Alert severity distribution
- Top attacked services
- Attack sources (GeoIP)

---

## Future Enhancements

1. **Real-time Alerting**
   - Critical event notifications
   - Webhook integration
   - Email alerts

2. **Data Enrichment**
   - DNS reverse lookup
   - Threat intelligence lookup
   - User/device correlation

3. **Multiple Destinations**
   - Forward to multiple SIEMs
   - Cloud storage backup
   - S3/Azure Blob integration

4. **Compression**
   - Compress old logs
   - Archive to cold storage
   - Automatic cleanup

5. **Advanced Filtering**
   - Pre-filter noisy logs
   - Sampling for high-volume sources
   - Conditional forwarding

---

## Summary

**Current State**:
- ✅ Logs in JSONL format
- ✅ 5-minute rotation
- ✅ Organized by type
- ✅ Ready for forwarding

**Next Steps**:
1. Deploy Filebeat (recommended)
2. Configure log inputs
3. Connect to Logstash (already running)
4. Verify data flow in Kibana
5. Create dashboards

**Alternative**:
- Build custom Go forwarder for tighter integration

This document provides all necessary information to implement a robust log forwarding solution for SafeOps.
