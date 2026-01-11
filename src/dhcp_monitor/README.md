# DHCP Monitor (Phase 2) - SafeOps Network Security System

Real-time device detection and tracking service for Windows network interfaces using IP Helper API.

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Go Version](https://img.shields.io/badge/go-1.19+-00ADD8)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![License](https://img.shields.io/badge/license-Proprietary-red)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [Version History](#version-history)
- [License](#license)
- [Support](#support)

---

## Overview

DHCP Monitor is a Windows service that provides real-time device detection and tracking across all network interfaces (WiFi, Ethernet, Mobile Hotspot, VPN, Hyper-V, etc.). It serves as the **central device registry** for the SafeOps Network Security System, enabling other components to query device information by IP address.

### Problem Solved

Phase 1 TLS Proxy doesn't know WHO owns an IP address, causing internet breakage when the Packet Engine queries for a device that hasn't been registered yet.

### Solution

DHCP Monitor detects devices **15-35ms after network connection** using Windows IP Helper API callbacks, ensuring device records exist in the database before the Packet Engine needs them.

### Critical Path

```
Packet Engine → Queries GetDeviceByIP(192.168.137.50) → DHCP Monitor returns device → Internet works ✓
```

---

## Key Features

- **Real-Time Detection (15-35ms):** Windows IP Helper API callbacks detect devices immediately upon IP assignment
- **Universal Interface Support:** Monitors ALL network interfaces (WiFi, Ethernet, Mobile Hotspot, VPN, Hyper-V, WSL)
- **Dual Detection Methods:** Primary IP Helper callbacks + Fallback ARP polling for 99.9%+ reliability
- **Hostname Enrichment:** DHCP Event Log polling provides DNS names for human-readable device identification
- **Trust Status Tracking:** Manages device trust levels (UNTRUSTED/TRUSTED/BLOCKED) for Phase 3+ security policies
- **IP History Audit Trail:** Logs all IP address changes for forensic analysis and troubleshooting
- **gRPC API (Port 50055):** Standardized interface for Packet Engine, TLS Proxy, and Captive Portal integration
- **PostgreSQL Persistence:** Durable device registry survives service restarts
- **Automatic Cleanup:** Offline detection and lease expiration prevent stale data accumulation
- **MAC Vendor Lookup:** Identifies device manufacturers for easier device identification

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     DHCP Monitor Service                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐      ┌──────────────┐                         │
│  │ IP Helper    │─────▶│   Event      │                         │
│  │ API Callback │      │   Channel    │                         │
│  └──────────────┘      └──────┬───────┘                         │
│                               │                                  │
│  ┌──────────────┐             │         ┌──────────────┐        │
│  │  ARP Table   │─────────────┼────────▶│   Device     │        │
│  │   Polling    │             │         │   Manager    │        │
│  └──────────────┘             │         └──────┬───────┘        │
│                               │                │                 │
│  ┌──────────────┐             │                │                 │
│  │ DHCP Event   │─────────────┘                │                 │
│  │ Log Polling  │                              │                 │
│  └──────────────┘                              │                 │
│                                                ▼                 │
│                                        ┌────────────────┐        │
│                                        │  PostgreSQL    │        │
│                                        │   Database     │        │
│                                        └────────────────┘        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               gRPC Server (Port 50055)                    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │  Packet  │        │   TLS    │        │ Captive  │
   │  Engine  │        │  Proxy   │        │  Portal  │
   └──────────┘        └──────────┘        └──────────┘
```

### Data Flow

1. Device connects → Windows assigns IP
2. IP Helper API fires callback (15-35ms)
3. ARP Monitor queries ARP table for MAC
4. Creates `NetworkEvent(DEVICE_DETECTED)`
5. Device Manager receives event
6. Unknown Device Handler creates Device with `trust_status=UNTRUSTED`
7. Database record inserted
8. 0-30s later: DHCP enricher finds hostname in Event Log
9. Updates device record with hostname
10. Packet Engine queries `GetDeviceByIP()` → **Success!**

---

## Prerequisites

### Operating System

- **Windows 10/11** or **Windows Server 2019/2022**
- Administrator privileges (required for IP Helper API access)
- DHCP Server role installed (optional, for hostname enrichment)

### Software Dependencies

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.19+ | Building from source |
| MinGW-w64 GCC | Latest | CGO compilation for Windows API |
| PostgreSQL | 12+ | Database server |
| protoc | 3.0+ | Protocol Buffer code generation |
| Git | Latest | Version control |

### Network Configuration

- At least one active network interface
- Network interface must support ARP (excludes loopback)
- For Mobile Hotspot monitoring: Internet Connection Sharing (ICS) enabled

### Port Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 50055 | TCP | gRPC server (Packet Engine, TLS Proxy, Captive Portal) |
| 5432 | TCP | PostgreSQL database |

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/SafeOps/SafeOpsFV2.git
cd SafeOpsFV2/src/dhcp_monitor
```

### 2. Install Dependencies

```bash
# Install Go module dependencies
go mod download

# Verify dependencies
go mod verify
```

### 3. Initialize Database

```powershell
# Create database and user (run as PostgreSQL admin)
psql -U postgres -c "CREATE DATABASE safeops_network;"
psql -U postgres -c "CREATE USER safeops_admin WITH PASSWORD 'YourSecurePassword';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops_admin;"
```

### 4. Configure Service

```powershell
# Copy example config
Copy-Item config/dhcp_monitor.example.yaml config/dhcp_monitor.yaml

# Edit config with your settings
notepad config/dhcp_monitor.yaml

# Set database password (REQUIRED)
$env:DB_PASSWORD = "YourSecurePassword"
```

### 5. Generate Protocol Buffer Code

```bash
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/dhcp_monitor.proto
```

### 6. Build Binary

```bash
go build -o bin/dhcp_monitor.exe ./cmd/dhcp_monitor
```

### 7. Verify Installation

```powershell
# Run validation
./bin/dhcp_monitor.exe --validate --config=config/dhcp_monitor.yaml

# Should output: "Configuration is valid"
```

### 8. Start Service

```powershell
# Run in foreground (for testing)
./bin/dhcp_monitor.exe --config=config/dhcp_monitor.yaml

# Or run as Windows service (for production)
sc create DHCPMonitor binpath="C:\path\to\dhcp_monitor.exe --config=C:\path\to\config.yaml"
sc start DHCPMonitor
```

---

## Configuration

DHCP Monitor is configured via YAML file at `config/dhcp_monitor.yaml`.

### Database Configuration

```yaml
database:
  host: ${DB_HOST:-localhost}     # PostgreSQL server
  port: 5432                       # PostgreSQL port
  name: safeops_network            # Database name
  user: safeops_admin              # Database user
  password: ${DB_PASSWORD}         # REQUIRED via env var
  sslmode: disable                 # disable/require/verify-ca
  pool:
    min_connections: 5
    max_connections: 25
    connection_timeout: 10s
    idle_timeout: 10m
    max_lifetime: 1h
  migration:
    auto_migrate: true             # Run migrations on startup
```

### gRPC Server Configuration

```yaml
grpc:
  host: 0.0.0.0                    # Bind address (0.0.0.0 = all interfaces)
  port: 50055                      # Listening port
  tls:
    enabled: false                 # Enable TLS for production
    cert_file: ""                  # Server certificate path
    key_file: ""                   # Server private key path
  keepalive:
    time: 2h
    timeout: 20s
    min_time: 5s
```

### Network Monitoring Configuration

```yaml
monitoring:
  ip_helper:
    enabled: true
    callback_timeout: 100ms
  arp_table:
    refresh_interval: 5s
    poll_interval: 30s
    cache_duration: 5m
  interfaces:
    include_patterns: [".*"]       # Regex for monitored interfaces
    exclude_patterns:              # Interfaces to ignore
      - "vEthernet (WSL)"
      - "Loopback"
  detection:
    primary_method: "ip_helper"
    secondary_method: "arp_poll"
    dedup_cache_duration: 5m
```

### DHCP Event Log Configuration

```yaml
dhcp_event_log:
  enabled: true                    # Enable hostname enrichment
  channel: "Microsoft-Windows-Dhcp-Server/Operational"
  poll_interval: 30s
  event_ids: [10, 11, 12]
```

### Device Management Configuration

```yaml
device_management:
  status:
    inactive_timeout: 10m          # Mark offline after this
    expired_timeout: 24h           # Mark expired after this
  cleanup:
    enabled: true
    interval: 5m                   # Cleanup job frequency
    purge_expired_after: 90d       # Delete expired devices
  ip_history:
    retention_days: 90             # IP history retention
    max_entries_per_device: 100
  unknown_devices:
    auto_create: true
    default_trust_status: "UNTRUSTED"
```

### Logging Configuration

```yaml
logging:
  level: INFO                      # DEBUG/INFO/WARN/ERROR
  format: json                     # json/text
  output:
    stdout: true
    file:
      enabled: false
      path: C:\ProgramData\SafeOps\logs\dhcp_monitor.log
      rotation:
        max_size_mb: 100
        max_age_days: 30
        max_backups: 10
        compress: true
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_PASSWORD` | **Yes** | - | Database password |
| `DB_HOST` | No | localhost | Database hostname |
| `DB_PORT` | No | 5432 | Database port |
| `GRPC_PORT` | No | 50055 | gRPC server port |
| `LOG_LEVEL` | No | INFO | Log verbosity |

---

## Usage

### Starting the Service

```powershell
# Foreground (development)
./bin/dhcp_monitor.exe --config=config/dhcp_monitor.yaml

# With debug logging
$env:LOG_LEVEL = "DEBUG"
./bin/dhcp_monitor.exe --config=config/dhcp_monitor.yaml

# As Windows Service
sc start DHCPMonitor
```

### Stopping the Service

```powershell
# If running in foreground
# Press Ctrl+C

# Windows service
sc stop DHCPMonitor
```

### Command Line Flags

| Flag | Description |
|------|-------------|
| `--config` | Path to configuration file |
| `--validate` | Validate config and exit |
| `--version` | Show version and exit |
| `--migrate-only` | Run migrations and exit |

### Querying Devices

```powershell
# Using grpcurl (install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)

# Get device by IP
grpcurl -plaintext -d '{"ip_address":"192.168.137.50"}' localhost:50055 dhcp_monitor.DHCPMonitor/GetDeviceByIP

# Get device by MAC
grpcurl -plaintext -d '{"mac_address":"AA:BB:CC:DD:EE:FF"}' localhost:50055 dhcp_monitor.DHCPMonitor/GetDeviceByMAC

# List all devices
grpcurl -plaintext -d '{"limit":50}' localhost:50055 dhcp_monitor.DHCPMonitor/ListDevices

# Get statistics
grpcurl -plaintext -d '{}' localhost:50055 dhcp_monitor.DHCPMonitor/GetDeviceStats
```

### Direct Database Queries

```sql
-- List all devices
SELECT device_id, mac_address, current_ip, hostname, trust_status, is_online
FROM devices ORDER BY last_seen DESC;

-- Find device by IP
SELECT * FROM devices WHERE current_ip = '192.168.137.50';

-- List untrusted online devices
SELECT * FROM devices WHERE trust_status = 'UNTRUSTED' AND is_online = true;

-- View IP history for a device
SELECT * FROM ip_history WHERE device_id = '...' ORDER BY changed_at DESC;
```

---

## API Reference

DHCP Monitor exposes a gRPC API on port **50055**. See `proto/dhcp_monitor.proto` for complete definitions.

### GetDeviceByIP

**Critical for Phase 1 Packet Engine integration**

```protobuf
rpc GetDeviceByIP(IPRequest) returns (Device)
```

| Field | Type | Description |
|-------|------|-------------|
| `ip_address` | string | IPv4 or IPv6 address |

**Error Codes:**
- `NOT_FOUND` - No device with this IP
- `INVALID_ARGUMENT` - Invalid IP format

**Performance:** <10ms typical

### GetDeviceByMAC

```protobuf
rpc GetDeviceByMAC(MACRequest) returns (Device)
```

| Field | Type | Description |
|-------|------|-------------|
| `mac_address` | string | Format: AA:BB:CC:DD:EE:FF |

### GetDeviceByID

```protobuf
rpc GetDeviceByID(DeviceIDRequest) returns (Device)
```

| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | UUID of device |

### UpdateTrustStatus

**Critical for Phase 3 Captive Portal integration**

```protobuf
rpc UpdateTrustStatus(TrustUpdateRequest) returns (Device)
```

| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | UUID of device |
| `trust_status` | string | UNTRUSTED/TRUSTED/BLOCKED |

**Security:** All trust status changes are logged for audit.

### ListDevices

```protobuf
rpc ListDevices(ListDevicesRequest) returns (DeviceList)
```

| Field | Type | Description |
|-------|------|-------------|
| `filter_by_trust` | string | Filter by trust status |
| `online_only` | bool | Only return online devices |
| `limit` | int32 | Max results (default: 100) |
| `offset` | int32 | Pagination offset |

### GetDeviceStats

```protobuf
rpc GetDeviceStats(Empty) returns (DeviceStats)
```

Returns aggregate statistics for dashboards.

### HealthCheck

```protobuf
rpc HealthCheck(Empty) returns (HealthStatus)
```

Returns service health status.

---

## Integration

### Phase 1: Packet Engine

```yaml
# Packet Engine config
dhcp_monitor:
  address: "localhost:50055"
  timeout: 100ms
```

**Flow:**
1. Packet Engine intercepts traffic from 192.168.137.50
2. Calls `GetDeviceByIP("192.168.137.50")`
3. DHCP Monitor returns device info
4. Packet Engine forwards to TLS Proxy

### Phase 3: Captive Portal

```yaml
# Captive Portal config
dhcp_monitor:
  address: "localhost:50055"
```

**Flow:**
1. New device → `trust_status = UNTRUSTED`
2. TLS Proxy redirects to Captive Portal
3. User installs CA certificate
4. Portal calls `UpdateTrustStatus(device_id, TRUSTED)`
5. Device now has internet access

### Phase 4: TLS Proxy

```yaml
# TLS Proxy config
dhcp_monitor:
  address: "localhost:50055"
```

**Flow:**
1. TLS Proxy queries device trust status
2. UNTRUSTED → Redirect to portal
3. TRUSTED → Decrypt traffic
4. BLOCKED → Drop traffic

---

## Troubleshooting

### Device Not Found Errors

**Symptom:** Packet Engine returns NOT_FOUND, internet doesn't work

**Solutions:**

```powershell
# 1. Check DHCP Monitor is running
Get-Process dhcp_monitor

# 2. Check detection in logs
Get-Content dhcp_monitor.log | Select-String "DEVICE_DETECTED"

# 3. Check ARP table
arp -a | Select-String "192.168.137"

# 4. Verify interface not blacklisted in config
```

### Hostname Enrichment Not Working

**Symptom:** Devices detected but hostname is empty

**Solutions:**

```powershell
# 1. Check DHCP Event Log accessible
Get-WinEvent -LogName "Microsoft-Windows-Dhcp-Server/Operational" -MaxEvents 5

# 2. Check config
# Ensure dhcp_event_log.enabled = true

# 3. Check DHCP Server role installed
Get-WindowsFeature DHCP
```

### Database Connection Failures

**Solutions:**

```powershell
# 1. Check PostgreSQL running
Get-Service postgresql*

# 2. Test connection
psql -h localhost -U safeops_admin -d safeops_network -c "SELECT 1"

# 3. Verify environment variable
$env:DB_PASSWORD
```

### High CPU Usage

**Solutions:**

```yaml
# Increase intervals in config
monitoring:
  arp_table:
    poll_interval: 60s    # Was 30s

dhcp_event_log:
  poll_interval: 60s      # Was 30s
```

### Debug Mode

```powershell
$env:LOG_LEVEL = "DEBUG"
./bin/dhcp_monitor.exe --config=config/dhcp_monitor.yaml
```

---

## Development

### Project Structure

```
dhcp_monitor/
├── cmd/dhcp_monitor/           # Entry point
│   └── main.go
├── internal/                   # Private packages
│   ├── config/                 # Configuration
│   ├── database/               # Database layer
│   ├── grpc/                   # gRPC server
│   ├── manager/                # Business logic
│   ├── platform/               # Windows API
│   └── watcher/                # Detection
├── proto/                      # Protocol Buffers
│   ├── dhcp_monitor.proto
│   └── gen/                    # Generated code
├── database/schemas/           # SQL migrations
├── config/                     # Configuration files
├── bin/                        # Compiled binaries
├── Makefile                    # Build automation
├── go.mod                      # Go dependencies
└── README.md                   # This file
```

### Building from Source

```bash
# Install dependencies
go mod download

# Generate protobuf code
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/dhcp_monitor.proto

# Build
go build -o bin/dhcp_monitor.exe ./cmd/dhcp_monitor

# Test
go test -v ./...
```

### Running Tests

```bash
# Unit tests
go test -v -race ./...

# With coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Contributing

This is a private SafeOps project. For internal contributors:

1. Create feature branch from `main`
2. Make changes following code style (`go fmt`)
3. Add tests for new functionality
4. Run `go test ./...` and `go vet ./...`
5. Create pull request
6. Request review from team lead

---

## Version History

### v2.0.0 (2026-01-03) - Initial Release

- Real-time device detection with IP Helper API
- DHCP Event Log hostname enrichment
- gRPC API (7 methods)
- PostgreSQL persistence
- Trust status tracking (UNTRUSTED/TRUSTED/BLOCKED)
- IP history audit trail
- Automatic cleanup jobs

### Roadmap

- v2.1.0 - Prometheus metrics export
- v2.2.0 - Docker containerization
- v2.3.0 - Linux support (netlink API)

---

## License

Copyright © 2026 SafeOps. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

---

## Support

**Internal Support:**
- Slack: #safeops-support
- Email: dev@safeops.internal

**Issue Reporting:**
- GitHub Issues (internal repository)
- Include: Logs, config (sanitized), steps to reproduce
