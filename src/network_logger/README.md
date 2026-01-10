# SafeOps Network Logger

High-performance Layer 2 network packet capture and logging system written in Go.

## Features

- **Multi-Interface Capture**: Simultaneously captures from multiple network interfaces
- **Layer 2-7 Parsing**: Complete packet dissection (Ethernet → IP → TCP/UDP → DNS/HTTP/TLS)
- **Flow Tracking**: Bidirectional session tracking with statistics
- **Smart Deduplication**: Intelligent filtering to log only relevant packets
- **Process Correlation**: Maps network connections to Windows processes
- **Hotspot Device Tracking**: Identifies and tracks devices connected to Windows Mobile Hotspot
- **TLS Key Logging**: Monitors SSLKEYLOGFILE for TLS decryption keys
- **JSON Output**: Structured JSONL format for easy parsing
- **3-Minute Retention**: Automatic log cleanup (configurable)
- **Real-time Statistics**: Beautiful terminal UI with live packet counters

## Requirements

- Windows 10/11
- [Npcap](https://npcap.com/) driver installed
- Go 1.21+ (for building)
- Administrator privileges (for packet capture)

## Installation

### 1. Install Npcap

Download and install Npcap from https://npcap.com/

**Important**: During installation, ensure "WinPcap API-compatible Mode" is enabled.

### 2. Build the Logger

```cmd
cd src\network_logger
build.bat
```

This will create `bin\safeops-logger.exe`.

## Usage

### List Available Interfaces

```cmd
bin\safeops-logger.exe -list-interfaces
```

### Start Capturing

```cmd
bin\safeops-logger.exe
```

**Note**: Must be run as Administrator.

### Using Custom Configuration

```cmd
bin\safeops-logger.exe -config custom_config.yaml
```

## Configuration

Edit `configs/config.yaml` to customize:

- **Interfaces**: Specific interfaces to capture from (empty = all)
- **BPF Filter**: Berkeley Packet Filter for pre-filtering
- **Log Path**: Where to save packet logs
- **Retention**: How long to keep logs (default: 3 minutes)
- **Batch Size**: Packets per write (default: 75)
- **Deduplication**: Cache size and window
- **TLS Key Logging**: Enable/disable and configure SSLKEYLOGFILE

## TLS Decryption Setup

To capture TLS keys from browsers:

### Chrome/Edge

```cmd
set SSLKEYLOGFILE=D:\SafeOpsFV2\logs\sslkeys.log
"C:\Program Files\Google\Chrome\Application\chrome.exe"
```

### Firefox

Firefox automatically reads the `SSLKEYLOGFILE` environment variable. Set it system-wide:

1. System Properties → Advanced → Environment Variables
2. Add User Variable: `SSLKEYLOGFILE` = `D:\SafeOpsFV2\logs\sslkeys.log`
3. Restart Firefox

## Output Format

Logs are written to `logs/network_packets.jsonl` in JSONL format (one JSON object per line).

Example packet structure:

```json
{
  "packet_id": "pkt_a1b2c3d4",
  "timestamp": {
    "epoch": 1704921600.123456,
    "iso8601": "2024-01-10T12:00:00.123456Z"
  },
  "capture_info": {
    "interface": "\\Device\\NPF_{GUID}",
    "capture_length": 1234,
    "wire_length": 1234
  },
  "layers": {
    "datalink": { "type": "ETHERNET", "src_mac": "...", "dst_mac": "..." },
    "network": { "version": 4, "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8" },
    "transport": { "protocol": 17, "src_port": 54321, "dst_port": 53 }
  },
  "parsed_application": {
    "detected_protocol": "dns",
    "confidence": "high",
    "dns": { "queries": [...], "answers": [...] }
  },
  "flow_context": {
    "flow_id": "flow_abc123",
    "direction": "forward",
    "packets_forward": 5,
    "bytes_forward": 1234
  },
  "deduplication": {
    "unique": true,
    "reason": "dns_protocol"
  }
}
```

## Performance

- **Target**: 50,000-150,000 packets/second
- **Memory**: <500 MB for 1M packets
- **CPU**: <30% on modern processors

## Architecture

```
Network Interfaces
         ↓
   Npcap Capture
         ↓
  Packet Processor
   ├─ Ethernet Parser
   ├─ IP Parser
   ├─ TCP/UDP Parser
   ├─ DNS Parser
   ├─ HTTP Parser
   └─ TLS Parser
         ↓
    Flow Tracker
         ↓
 Process Correlator
         ↓
Deduplication Engine
         ↓
    JSON Writer
         ↓
  logs/network_packets.jsonl
```

## Troubleshooting

### "No interfaces available"

- Ensure Npcap is installed with WinPcap compatibility mode
- Run with Administrator privileges
- Check that network adapters are enabled

### "Failed to open interface"

- Another packet capture program may be running (Wireshark, etc.)
- Try running with Administrator privileges
- Verify interface name with `-list-interfaces`

### High CPU usage

- Reduce traffic with BPF filter in config
- Increase batch size
- Enable deduplication

### Log file not created

- Check that logs directory exists and is writable
- Verify path in configuration (use absolute paths)

## Development

### Project Structure

```
src/network_logger/
├── cmd/logger/           # Main application
├── internal/
│   ├── capture/          # Npcap engine & packet processing
│   ├── parser/           # Protocol parsers
│   ├── flow/             # Flow tracking
│   ├── dedup/            # Deduplication
│   ├── process/          # Windows process correlation
│   ├── hotspot/          # Device tracking
│   ├── tls/              # TLS key logging
│   ├── writer/           # JSON log writer
│   ├── stats/            # Statistics collector
│   └── config/           # Configuration loader
├── pkg/models/           # Data structures
└── configs/              # Configuration files
```

### Building from Source

```cmd
go mod tidy
go build -o bin\safeops-logger.exe cmd\logger\main.go
```

## License

Part of the SafeOps project.

## Support

For issues and questions, please refer to the main SafeOps documentation.
