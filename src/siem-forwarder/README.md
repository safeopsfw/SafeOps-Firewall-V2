# SafeOps SIEM Log Forwarder

A high-performance, Go-based log forwarder that ships SafeOps logs to Elasticsearch in real-time. This is a lightweight alternative to Logstash, specifically designed for SafeOps log formats.

## Features

- **Real-time Log Tailing** - Continuously monitors log files for new entries
- **File Rotation Handling** - Detects truncation and file replacement automatically
- **Position Tracking** - Resumes from last position after restart (sincedb equivalent)
- **Bulk API Shipping** - Batches documents for efficient Elasticsearch ingestion
- **Daily Indices** - Creates date-suffixed indices (e.g., `safeops-netflow-2026.01.21`)
- **Graceful Shutdown** - Flushes all pending documents before exit
- **Zero Dependencies** - Single executable, no JVM or external runtime required

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SIEM Log Forwarder                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Tailer   │ │ Tailer   │ │ Tailer   │ │ Tailer   │  ...  │
│  │ netflow  │ │ firewall │ │   ids    │ │ engine   │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       │            │            │            │              │
│       └────────────┴─────┬──────┴────────────┘              │
│                          ▼                                  │
│                 ┌─────────────────┐                        │
│                 │  Batch Channel  │  (1000 buffer)         │
│                 └────────┬────────┘                        │
│                          ▼                                  │
│                 ┌─────────────────┐                        │
│                 │   ES Shipper    │  (Bulk API)            │
│                 └────────┬────────┘                        │
│                          │                                  │
└──────────────────────────┼──────────────────────────────────┘
                           ▼
                   ┌───────────────┐
                   │ Elasticsearch │
                   │  :9200        │
                   └───────────────┘
```

## Log Files Monitored

| Source File | Elasticsearch Index | Log Type |
|-------------|---------------------|----------|
| `netflow/east_west.log` | `safeops-netflow-YYYY.MM.DD` | East-West network flows |
| `netflow/north_south.log` | `safeops-netflow-YYYY.MM.DD` | North-South network flows |
| `engine.log` | `safeops-engine-YYYY.MM.DD` | SafeOps engine events |
| `firewall.log` | `safeops-firewall-YYYY.MM.DD` | Firewall decisions |
| `ids.log` | `safeops-ids-YYYY.MM.DD` | Intrusion detection alerts |
| `devices.jsonl` | `safeops-devices-YYYY.MM.DD` | Connected device inventory |

## Installation

### Pre-built Binary

The executable is located at:
```
bin/siem-forwarder/siem-forwarder.exe
```

### Build from Source

```batch
cd src\siem-forwarder
go build -o ../../bin/siem-forwarder/siem-forwarder.exe ./cmd/forwarder
```

## Configuration

Edit `bin/siem-forwarder/config.yaml`:

```yaml
# Elasticsearch connection
elasticsearch:
  hosts:
    - "http://127.0.0.1:9200"
  # username: "elastic"        # Uncomment for authentication
  # password: "changeme"
  bulk_size: 500               # Documents per bulk request
  flush_interval: 5s           # Flush interval

# Log paths (relative to executable)
log_base_path: "../logs"

# Log files to monitor
log_files:
  - path: "netflow/east_west.log"
    index_prefix: "safeops-netflow"
    type: "netflow"
  # ... more files

# Position tracking
position_db:
  path: "data/positions.json"
  save_interval: 10s

# Performance tuning
tailer:
  poll_interval: 500ms         # File check frequency
  max_line_size: 1048576       # 1MB max line
```

## Usage

### Start the Forwarder

**Option 1: Using batch script**
```batch
cd bin\siem-forwarder
start-forwarder.bat
```

**Option 2: Direct execution**
```batch
bin\siem-forwarder\siem-forwarder.exe -config config.yaml
```

**Option 3: Custom config path**
```batch
siem-forwarder.exe -config C:\path\to\custom-config.yaml
```

### Stop the Forwarder

Press `Ctrl+C` for graceful shutdown. The forwarder will:
1. Stop all file tailers
2. Flush remaining documents to Elasticsearch
3. Save final positions to disk

### Run as Windows Service

To run as a background service, use [NSSM](https://nssm.cc/):
```batch
nssm install SafeOps-SIEM-Forwarder "D:\SafeOpsFV2\bin\siem-forwarder\siem-forwarder.exe"
nssm set SafeOps-SIEM-Forwarder AppDirectory "D:\SafeOpsFV2\bin\siem-forwarder"
nssm set SafeOps-SIEM-Forwarder AppParameters "-config config.yaml"
nssm start SafeOps-SIEM-Forwarder
```

## File Rotation Handling

The forwarder handles three rotation scenarios:

| Scenario | Detection | Action |
|----------|-----------|--------|
| **Truncation** | File size < last position | Reset to beginning |
| **Replacement** | Inode/FileID changed | Reopen and read from start |
| **Append** | File size > last position | Continue from last position |

## Position Tracking

Positions are stored in `data/positions.json`:
```json
{
  "D:\\SafeOpsFV2\\bin\\logs\\firewall.log": {
    "offset": 45678,
    "inode": 123456789,
    "updated_at": 1705825200
  }
}
```

This ensures no log lines are lost or duplicated after restart.

## Verification

### Check Elasticsearch Indices

```bash
curl http://localhost:9200/_cat/indices/safeops-*?v
```

### View in Kibana

1. Open http://localhost:5601
2. Go to **Stack Management → Index Management**
3. Look for `safeops-*` indices
4. Go to **Discover** and create index pattern `safeops-*`

### Sample Output

```
2026/01/21 11:40:08 SafeOps SIEM Log Forwarder starting...
2026/01/21 11:40:08 Loaded configuration with 6 log files to monitor
2026/01/21 11:40:08 Started tailing: netflow/east_west.log -> safeops-netflow
2026/01/21 11:40:08 Started tailing: firewall.log -> safeops-firewall
2026/01/21 11:40:11 Shipped 500 documents to Elasticsearch
2026/01/21 11:40:16 Shipped 500 documents to Elasticsearch
...
2026/01/21 11:40:37 Shutting down...
2026/01/21 11:40:37 Shutdown complete. Total documents sent: 21096, errors: 0
```

## Troubleshooting

### Forwarder can't connect to Elasticsearch

```
Error connecting to http://127.0.0.1:9200: connection refused
```
**Solution**: Ensure Elasticsearch is running on port 9200.

### Log files not found

```
Warning: Failed to start tailer for ...: no such file or directory
```
**Solution**: Check `log_base_path` in config.yaml. Paths are relative to the executable.

### Documents not appearing in Kibana

1. Check if indices exist: `curl localhost:9200/_cat/indices/safeops-*`
2. Verify the forwarder is running and shipping documents
3. Refresh Kibana index pattern

## Project Structure

```
src/siem-forwarder/
├── cmd/
│   └── forwarder/
│       └── main.go           # Entry point
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration loader
│   ├── tailer/
│   │   ├── tailer.go         # File tailing logic
│   │   └── position.go       # Position tracking
│   └── shipper/
│       └── shipper.go        # Elasticsearch bulk shipper
├── configs/
│   └── config.yaml           # Source config template
├── go.mod
└── README.md

bin/siem-forwarder/
├── siem-forwarder.exe        # Compiled binary
├── config.yaml               # Runtime configuration
├── start-forwarder.bat       # Startup script
└── data/
    └── positions.json        # Position tracking (auto-created)
```

## Performance

Tested performance on SafeOps logs:
- **Throughput**: ~700 documents/second
- **Memory**: ~15 MB RSS
- **CPU**: <1% idle, ~5% during bulk shipping

## License

Part of SafeOps Firewall V2 project.
