# DHCP Monitor - Component Documentation

## Overview
The DHCP Monitor Service is a real-time network device detection and trust management system built in Go. It automatically discovers devices connecting to the network through ARP table monitoring and Windows DHCP Event Log parsing, maintaining a comprehensive device registry with trust status, IP history, and lease tracking.

## Component Information

**Component Type:** Network Device Discovery Service
**Language:** Go
**Architecture:** Event-driven, multi-watcher design with device management
**Platform:** Windows (IP Helper API, Windows Event Log) + Linux (ARP polling)

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\dhcp_monitor\
├── cmd\dhcp_monitor\main.go          # Service entry point
├── internal\
│   ├── config\config.go              # YAML configuration
│   ├── database\
│   │   ├── connection.go             # PostgreSQL client
│   │   ├── migrations.go             # Schema migrations
│   │   ├── models.go                 # Device models
│   │   └── queries.go                # SQL operations
│   ├── grpc\
│   │   ├── server.go                 # gRPC server
│   │   └── handlers.go               # gRPC service implementation
│   ├── manager\
│   │   ├── device_manager.go         # Core device lifecycle
│   │   ├── fingerprint_enricher.go   # Device type detection
│   │   └── unknown_device_handler.go # Auto-create unknown devices
│   ├── watcher\
│   │   ├── arp_monitor.go            # ARP table polling
│   │   ├── arp_table.go              # ARP parsing
│   │   ├── dhcp_enricher.go          # DHCP event log monitoring
│   │   ├── network_event.go          # Event model
│   │   └── ip_change_notifier.go     # IP change callbacks
│   └── platform\
│       ├── windows_api.go            # Windows API bindings
│       ├── mdns_responder.go         # mDNS for safeops-portal.local
│       └── device_info_collector.go  # System info gathering
└── proto\
    └── dhcp_monitor.proto            # gRPC service definition
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\dhcp_monitor\
└── dhcp_monitor.exe                  # Windows service executable
```

### Configuration Files
```
D:\SafeOpsFV2\bin\dhcp_monitor\config\config.yaml       # Runtime config
D:\SafeOpsFV2\src\dhcp_monitor\config.yaml              # Dev config
```

### Database Schema
```
D:\SafeOpsFV2\src\dhcp_monitor\database\schemas\020_dhcp_monitor.sql
```

### Web Data
```
D:\SafeOpsFV2\web\data\devices.json                     # Live device data
```

## Functionality

### Core Functions

#### 1. Network Device Detection
- **ARP Table Monitoring** - Primary detection method via continuous ARP polling
- **DHCP Event Log Parsing** - Secondary detection via Windows Event Viewer (Event IDs: 10-13)
- **IP Helper API Integration** - Real-time IP change callbacks on Windows
- **Deduplication Cache** - 5-minute cache prevents duplicate device creation
- **Multi-interface Support** - Monitors hotspot, Ethernet, WiFi interfaces
- **Interface Filtering** - Include/exclude patterns via regex

#### 2. Device Management
- **Automatic Registration** - Creates device entries for unknown MAC addresses
- **Trust Status Management** - UNTRUSTED (default), TRUSTED, BLOCKED states
- **Device Classification** - Laptop, Phone, IoT, Printer, Unknown
- **Vendor Detection** - MAC OUI lookup for manufacturer identification
- **Connection Status Tracking** - ACTIVE, OFFLINE, EXPIRED states
- **Hostname Tracking** - Captures device-reported hostnames
- **IP History** - Maintains complete IP address change audit trail
- **Device Notes** - Administrator-editable notes field

#### 3. DHCP Lease Tracking
- **Lease Lifecycle** - ASSIGNED, RENEWED, EXPIRED, RELEASED states
- **Lease Duration Tracking** - Start time, end time, duration intervals
- **Renewal Counter** - Tracks number of lease renewals
- **Interface Association** - Links leases to specific NICs
- **Historical Records** - Complete lease history per device

#### 4. IP Address Management
- **Current IP Tracking** - Active IPv4/IPv6 address
- **Previous IP Caching** - Last known IP before current
- **IP Change Detection** - Real-time change notifications
- **IP History Audit Trail** - Change reason, timestamps, interface info
- **Change Reasons:** IP_CHANGE_CALLBACK, DHCP_RENEW, NIC_SWITCH, RECONNECT, MANUAL, ARP_DETECTION

#### 5. Device Cleanup & Expiration
- **Automatic Cleanup** - Configurable interval (default: 1 hour)
- **Inactivity Timeout** - Marks devices OFFLINE after 10 minutes
- **Expiration Timeout** - Marks devices EXPIRED after 24 hours
- **Purge Expired Devices** - Auto-delete after 30 days
- **Batch Cleanup** - Efficient database maintenance

#### 6. mDNS Responder
- **Local Domain Resolution** - Responds to safeops-portal.local queries
- **Multi-interface Binding** - Binds to all active network interfaces
- **Dynamic IP Selection** - Auto-detects correct IP per interface
- **Bonjour/Avahi Compatible** - Standard mDNS protocol

#### 7. Fingerprint Enrichment
- **Device Type Detection** - Analyzes hostname patterns, vendor, behavior
- **MAC Vendor Lookup** - OUI database for manufacturer identification
- **Hostname Analysis** - Pattern matching for device classification
- **Behavioral Analysis** - Port usage patterns, traffic characteristics

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| **50055** | gRPC Server | DHCP Monitor API | Bidirectional |
| 5432 | PostgreSQL | Database connection | Client |
| 5353 | mDNS | safeops-portal.local resolution | Server (UDP) |

### gRPC Configuration
- Listen address: 0.0.0.0:50055
- Max message size: 4 MB
- Connection timeout: 10 seconds
- Keepalive time: 30 seconds
- Keepalive timeout: 10 seconds
- Min keepalive time: 10 seconds

## API Endpoints (gRPC Service)

### Device Operations
- `ListDevices(ListDevicesRequest)` - Get all devices with filtering (trust status, interface)
- `GetDevice(GetDeviceRequest)` - Get device by ID or MAC address
- `GetDeviceByMAC(GetDeviceByMACRequest)` - Lookup by MAC address
- `GetDeviceByIP(GetDeviceByIPRequest)` - Lookup by current IP address
- `CreateDevice(CreateDeviceRequest)` - Manually register device
- `UpdateDevice(UpdateDeviceRequest)` - Update device properties
- `DeleteDevice(DeleteDeviceRequest)` - Remove device from registry
- `SetTrustStatus(SetTrustStatusRequest)` - Update trust status (UNTRUSTED/TRUSTED/BLOCKED)

### Lease Operations
- `GetLeaseHistory(GetLeaseHistoryRequest)` - DHCP lease history for device
- `GetActiveLeases(GetActiveLeasesRequest)` - All active DHCP leases
- `GetLeasesByInterface(GetLeasesByInterfaceRequest)` - Leases for specific NIC

### IP History Operations
- `GetIPHistory(GetIPHistoryRequest)` - IP address change history for device
- `GetIPHistoryByIP(GetIPHistoryByIPRequest)` - Devices that used specific IP

### Statistics Operations
- `GetDeviceStatistics(GetDeviceStatisticsRequest)` - Device counts by status, type
- `GetInterfaceStatistics(GetInterfaceStatisticsRequest)` - Device counts per interface
- `GetTrustStatistics(GetTrustStatisticsRequest)` - Trust status distribution

### Service Management
- `HealthCheck(HealthCheckRequest)` - Service health status
- `GetServiceStatus(GetServiceStatusRequest)` - Runtime status and uptime
- `TriggerCleanup(TriggerCleanupRequest)` - Manual cleanup execution

## Dependencies

### Go Dependencies

**Database:**
- github.com/jackc/pgx/v5 - PostgreSQL driver
- github.com/jackc/pgx/v5/pgxpool - Connection pooling

**gRPC & Serialization:**
- google.golang.org/grpc - gRPC framework
- google.golang.org/protobuf - Protocol Buffers
- gopkg.in/yaml.v3 - YAML configuration

**Windows Platform:**
- golang.org/x/sys/windows - Windows syscalls
- Windows IP Helper API (iphlpapi.dll)
- Windows Event Log API (wevtapi.dll)

**Networking:**
- github.com/google/uuid - UUID generation
- github.com/hashicorp/mdns - mDNS responder

**Utilities:**
- github.com/spf13/cobra - CLI framework (optional)

### External Service Dependencies
- PostgreSQL 14+ - Device registry database
- Windows Event Log - DHCP event monitoring (Windows only)

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│       DHCP Monitor Service (50055)              │
│    (Device Discovery & Trust Management)        │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[Firewall]  [Web UI]   [Network    [PostgreSQL]
(50051)     (API)      Logger]      (5432)
                       (50056)
```

### Integration Points

**To Other Components:**
1. **Firewall Engine** - Provides device trust status for rule enforcement
2. **Web Portal** - Supplies device inventory for dashboard display
3. **Network Logger** - Enriches logs with device information
4. **NIC Management** - Receives interface state updates

**From External Sources:**
- Windows ARP Table (netsh, arp -a)
- Windows DHCP Event Log (Event IDs: 10, 11, 12, 13)
- Windows IP Helper API (NotifyIpInterfaceChange)

### Detection Methods

**Primary:** ARP Table Monitoring
- Polls system ARP cache every 30 seconds
- Detects new MAC-IP bindings
- Works across all OS platforms
- Most reliable detection method

**Secondary:** DHCP Event Log (Windows only)
- Monitors Windows Event Log channel
- Event ID 10: Lease assigned
- Event ID 11: Lease renewed
- Event ID 12: Lease expired
- Event ID 13: Lease released

**Fallback:** IP Change Callbacks (Windows only)
- Real-time notifications via IP Helper API
- Detects IP address changes immediately
- Used for validation and enrichment

## Database Schema

**PostgreSQL 14+ Tables:**

1. **devices** - Primary device registry
   - device_id (UUID, PK)
   - mac_address (VARCHAR(17), UNIQUE)
   - current_ip, previous_ip (INET)
   - hostname, device_type, vendor
   - trust_status (UNTRUSTED, TRUSTED, BLOCKED)
   - interface_name, interface_index, interface_guid
   - status (ACTIVE, OFFLINE, EXPIRED)
   - detection_method (IP_HELPER_API, DHCP_EVENT_LOG, ARP_TABLE, MANUAL)
   - first_seen, last_seen, created_at, updated_at
   - notes (TEXT)

2. **dhcp_leases** - DHCP lease lifecycle tracking
   - lease_id (UUID, PK)
   - device_id (UUID, FK)
   - ip_address (INET)
   - interface_name
   - lease_start, lease_end, lease_duration
   - lease_state (ACTIVE, EXPIRED, RELEASED, RENEWED)
   - lease_renewals (INTEGER)
   - event_type (ASSIGNED, RENEWED, EXPIRED, RELEASED)
   - created_at

3. **ip_history** - IP address change audit trail
   - history_id (UUID, PK)
   - device_id (UUID, FK)
   - ip_address, previous_ip (INET)
   - interface_name, interface_index
   - change_reason (enum: IP_CHANGE_CALLBACK, DHCP_RENEW, NIC_SWITCH, etc.)
   - assigned_at, released_at
   - created_at

4. **schema_migrations** - Migration version tracking
   - version (INTEGER, PK)
   - applied_at, description, checksum

**Indexes:**
- devices: current_ip, trust_status, interface_name, status, last_seen, is_online
- dhcp_leases: device_id, ip_address, interface_name, lease_state, lease_start
- ip_history: device_id, ip_address, assigned_at, interface_name

**Triggers:**
- Auto-update updated_at timestamp on devices table

## Configuration

### Device Management
```yaml
device_management:
  status:
    inactive_timeout: 10m        # Mark OFFLINE after 10 minutes
    expired_timeout: 24h         # Mark EXPIRED after 24 hours
  cleanup:
    enabled: true
    interval: 1h                 # Cleanup every hour
    purge_expired_after: 720h    # Delete after 30 days
  unknown_devices:
    auto_create: true            # Auto-register unknown MACs
    default_trust_status: "UNTRUSTED"
    default_device_type: "unknown"
```

### Monitoring Configuration
```yaml
monitoring:
  arp_table:
    refresh_interval: 30s        # ARP poll interval
    poll_interval: 30s
    cache_duration: 5m           # Dedup cache TTL
  detection:
    primary_method: "arp"
    secondary_method: "dhcp_event_log"
    dedup_cache_duration: 5m
    dedup_cache_max_size: 1000
```

### DHCP Event Log
```yaml
dhcp_event_log:
  enabled: true                  # Enable Windows Event Log monitoring
  channel: "Microsoft-Windows-DHCP-Server/Operational"
  poll_interval: 30s
  event_ids: [10, 11, 12, 13]    # DHCP events
```

## Important Notes

### Performance
- Efficient ARP polling (30s intervals)
- Deduplication cache prevents duplicate processing
- Batch database operations
- Indexed queries for fast lookups
- Connection pooling (2-10 connections)

### Reliability
- Panic recovery wrapper
- Graceful shutdown handling
- Database connection retry (3 attempts with exponential backoff)
- Transaction support for data consistency
- Health check validation

### Security
- Trust status enforcement
- MAC address validation (format: AA:BB:CC:DD:EE:FF)
- IP address validation (IPv4/IPv6)
- Device ID UUID validation
- Database prepared statements (SQL injection prevention)

### Capacity
- Unlimited device registry
- 5-minute deduplication cache (1000 entries)
- 30-day IP history retention
- Complete lease history

### mDNS Resolution
- Responds to safeops-portal.local
- Enables discovery without IP knowledge
- Works across all network interfaces
- Compatible with Chrome, Safari, Firefox

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| Firewall Engine | gRPC Server | Device trust status queries |
| Web Portal | gRPC Server | Device inventory display |
| Network Logger | gRPC Server | Device enrichment data |
| PostgreSQL | Database | Persistent device storage |
| Windows Event Log | Event Consumer | DHCP event monitoring |
| Windows IP Helper API | System API | Real-time IP change notifications |

---

**Status:** Production Ready
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** PostgreSQL
**Managed By:** Orchestrator
**Version:** 2.0.0
