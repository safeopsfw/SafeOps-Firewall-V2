# NIC Management API - Component Documentation

## Overview
The NIC Management Service is a high-performance network interface management component built with hybrid Go/Rust architecture. It handles multi-WAN failover, NAT translation, load balancing, and packet processing for the SafeOps firewall system.

## Component Information

**Component Type:** Network Management Service
**Language:** Hybrid Go + Rust
**Architecture:** Multi-threaded, lock-free, zero-copy packet processing
**Platform:** Windows (NDIS, IP Helper API, WMI) + Linux (AF_PACKET, libpcap)

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\nic_management\
├── Cargo.toml                      # Rust dependencies (70+ crates)
├── src\lib.rs                      # Rust library entry point
├── build.rs                        # gRPC proto compilation
├── internal\
│   ├── config\config.rs            # Configuration loading
│   ├── router\routing_engine.rs    # Core packet routing
│   ├── nat\translator.rs           # NAT translation engine
│   ├── capture\packet_capture.rs   # Multi-queue packet capture
│   └── integration\mod.rs          # External service integration
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\nic_management\
└── nic_management.exe              # Windows native executable
```

### Configuration Files
```
D:\SafeOpsFV2\bin\nic_management\config.yaml          # Runtime config
D:\SafeOpsFV2\src\nic_management\config.yaml          # Dev config
D:\SafeOpsFV2\config\templates\nic_management.yaml    # Master template
```

### Database Schema
```
D:\SafeOpsFV2\database\schemas\020_nic_management.sql
```

### Web Data
```
D:\SafeOpsFV2\web\data\nic_management.json            # Live metrics
```

## Functionality

### Core Functions

#### 1. Network Interface Discovery & Management
- Automatic detection of all network interfaces (WAN, LAN, WiFi, Virtual)
- Interface enumeration on Windows (NDIS, IP Helper API, WMI) and Linux
- Physical vs. virtual NIC detection
- Capability detection (speed, duplex, MTU, driver info)
- Interface state monitoring (UP, DOWN, DORMANT, ERROR)
- Dynamic interface hotplug detection (USB/Thunderbolt NICs)

#### 2. Multi-WAN Load Balancing
**Load Balancing Modes:**
- Round-robin distribution
- Weighted load balancing (configurable weights 1-100)
- Least-connections algorithm
- Hash-based (5-tuple consistent hashing)
- Bandwidth-based distribution
- Failover-only mode

**Features:**
- Session affinity (sticky sessions by source IP)
- Per-WAN traffic statistics collection
- Dynamic rebalancing every 5 minutes
- Support for 3+ simultaneous WAN connections

#### 3. Automatic Failover & Recovery
- Continuous WAN health monitoring (ICMP ping, HTTP, DNS methods)
- Automatic failover on link degradation/failure
- Failure thresholds: 3 consecutive failures triggers DOWN state
- Recovery threshold: 5 consecutive successes for UP state
- Latency monitoring (warning at 100ms, critical at 500ms)
- Packet loss monitoring (warning at 5%, critical at 20%)
- Manual or automatic failback with configurable recovery delay (60s default)
- Flap prevention to avoid rapid switching (30s minimum)
- Failover event logging and audit trail

#### 4. NAT/NAPT Translation
**Dynamic NAT:**
- Port allocation: 10,000-65,535 (configurable)
- Support up to 1,000,000 concurrent NAT mappings
- Per-protocol timeouts:
  - TCP established: 5 hours
  - TCP SYN: 30 seconds
  - TCP FIN: 2 minutes
  - UDP: 3 minutes
  - ICMP: 30 seconds

**Static Port Forwarding:**
- External port → Internal IP:port mappings
- Per-WAN interface rules
- Example: External 443 TCP → 192.168.1.10:443

#### 5. Connection Tracking
- Stateful connection tracking up to 262,144 entries
- Connection states: NEW, ESTABLISHED, RELATED, INVALID, CLOSING, CLOSED
- Per-connection statistics (bytes sent/received, packet counts)
- Connection lifecycle management
- Database persistence with automatic cleanup
- Time-based expiration with batch cleanup (every 10s, 1000 entries/batch)

#### 6. Packet Forwarding
- Zero-copy kernel bypass mode
- Multi-queue packet processing (8 queues, 4096 depth)
- Batch processing (64 packets per batch, 100μs timeout)
- Hardware offload: checksum, TSO (TCP Segmentation), GRO (Generic Receive)
- Ring buffer mode for extreme performance
- Cross-platform: WinDivert (Windows), libpcap/AF_PACKET (Linux)

#### 7. Network Configuration
- Static IP address assignment
- DHCP client/server integration
- DNS configuration management
- Gateway management
- MTU/link speed control
- VLAN support (ID assignment)
- IPv4 and IPv6 support

#### 8. Performance Monitoring
Real-time interface statistics:
- RX/TX bytes, packets, errors, drops
- Multicast count, collision count
- Throughput (bps/Mbps)
- Packet rate (pps)
- Utilization percentage
- Error rate tracking

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| **50054** | gRPC Server | NIC Management API | Bidirectional |
| 50051 | Firewall Engine | Integration | Client |
| 50052 | DHCP Server | Integration | Client |
| 50053 | DNS Server | Integration | Client |
| 50055 | Network Logger | Integration | Client |
| 50057 | IDS/IPS | Integration | Client |
| 50058 | Threat Intel | Integration | Client (disabled by default) |
| **8081** | REST API | HTTP interface | Server |
| 9154 | Prometheus | Metrics endpoint | Metrics only |

### gRPC Configuration
- Listen address: 0.0.0.0:50054
- Max concurrent streams: 100
- Max connections: 1000 (configurable)
- Connection idle timeout: 15 minutes
- Keepalive time: 30 seconds
- Max message size: 16 MB

## API Endpoints (gRPC Service)

### Network Interface Operations
- `ListNetworkInterfaces(ListInterfacesRequest)` - Inventory of all NICs
- `GetInterfaceDetails(InterfaceRequest)` - Detailed NIC information
- `GetInterfaceStats(InterfaceRequest)` - Real-time statistics
- `StreamMetrics(MetricsStreamRequest)` - Server streaming metrics (1s intervals)
- `ConfigureInterface(ConfigureInterfaceRequest)` - IP/DNS/gateway configuration
- `EnableInterface(InterfaceRequest)` - Bring NIC online
- `DisableInterface(InterfaceRequest)` - Take NIC offline
- `SetInterfaceTag(SetInterfaceTagRequest)` - Classify as WAN/LAN/WiFi

### Routing Operations
- `GetRoutingTable(GetRoutingTableRequest)` - Complete routing table with IPv4/IPv6 filtering
- `AddRoute(AddRouteRequest)` - Add static route
- `RemoveRoute(RemoveRouteRequest)` - Remove static route

### NAT & Connection Tracking
- `GetNATMappings(NATMappingsRequest)` - NAT translations with pagination
- `GetConnectionTracking(ConnectionTrackingRequest)` - Active connection states
- `ClearNATMapping(ClearNATMappingRequest)` - Flush specific NAT entry
- `FlushNATTable(FlushNATTableRequest)` - Flush all NAT mappings

### WAN & Load Balancing
- `GetWANHealth(GetWANHealthRequest)` - WAN health status (latency, jitter, packet loss)
- `GetLoadBalancerStats(GetLoadBalancerStatsRequest)` - Per-WAN statistics
- `UpdateWANWeights(UpdateWANWeightsRequest)` - Adjust load balancing weights
- `SetWANPriority(SetWANPriorityRequest)` - Configure failover priority
- `SetLoadBalancingMode(SetLoadBalancingModeRequest)` - Change LB algorithm

### Failover Operations
- `TriggerFailover(TriggerFailoverRequest)` - Manual failover
- `GetFailoverHistory(FailoverHistoryRequest)` - Historical failover events
- `RestorePrimaryWAN(RestorePrimaryWANRequest)` - Failback to primary

### Service Management
- `HealthCheck(HealthCheckRequest)` - Service health status
- `RefreshInterfaces(RefreshInterfacesRequest)` - Force interface rescan
- `GetServiceConfig(GetServiceConfigRequest)` - Runtime configuration

## Dependencies

### Rust Dependencies (70+ crates)

**Async Runtime:**
- tokio 1.35 - Async packet processing and WAN health checking
- tokio-stream, tokio-test

**Packet Processing:**
- pnet 0.34 - Network interface and packet access
- pcap 1.1 - libpcap bindings
- windivert 0.6 - Kernel-level packet interception (Windows)
- etherparse 0.14 - Zero-copy Ethernet/IP/TCP/UDP parsing
- smoltcp 0.11 - Lightweight TCP/IP stack

**Performance Optimization:**
- simd-json 0.13 - SIMD-accelerated JSON parsing
- rayon 1.8 - Data parallelism
- parking_lot 0.12 - Faster mutex/rwlock
- ahash 0.8 - Fast hashing for NAT tables
- crossbeam 0.8 - Lock-free concurrent data structures

**gRPC & Serialization:**
- tonic 0.10 - gRPC runtime
- prost 0.12 - Protocol Buffers
- serde 1.0 - Serialization
- toml 0.8 - Configuration parsing

**Error Handling & Logging:**
- anyhow 1.0, thiserror 1.0
- log 0.4, env_logger 0.11

### External Service Dependencies
- PostgreSQL 14+ - Database persistence
- TLS Proxy service (localhost:50054) - SNI extraction
- Firewall Engine (localhost:50051)
- DHCP Server (localhost:50052)
- DNS Server (localhost:50053)
- Network Logger (localhost:50055)
- IDS/IPS (localhost:50057)

### Release Profile Optimization
```toml
opt-level = 3           # Maximum optimization (O3)
lto = "fat"            # Link-time optimization
codegen-units = 1      # Single unit for max inlining
panic = "abort"        # Smaller binary
strip = true           # Strip debug symbols
```

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│         NIC Management Service (50054)          │
│    (Multi-WAN, LB, Failover, NAT, Routing)     │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[Firewall]  [DHCP]     [DNS]    [Network Logger]
(50051)     (50052)    (50053)   (50055)
    ↓           ↓
[IDS/IPS]   [Threat Intel]
(50057)     (50058)
```

### Integration Points

**From SafeOps Core Components:**
1. **Firewall Engine (50051)** - Requests network interface state, routing decisions
2. **DHCP Server (50052)** - Requests interface IP configuration
3. **DNS Server (50053)** - Requests interface DNS configuration
4. **Network Logger (50055)** - Receives connection events
5. **IDS/IPS (50057)** - Sends packet metadata for threat analysis
6. **Threat Intelligence (50058)** - IP reputation lookups (disabled by default)

### Health Check Targets
- 8.8.8.8 (Google DNS)
- 1.1.1.1 (Cloudflare DNS)
- 208.67.222.222 (OpenDNS)
- http://www.gstatic.com/generate_204
- Check interval: 5 seconds
- Check timeout: 2 seconds

## Database Schema

**PostgreSQL 14+ Tables:**

1. **network_interfaces** - Interface inventory
2. **connection_tracking** - Active connections (1M+ entries)
3. **nat_mappings** - NAT translations
4. **wan_health_history** - WAN uptime metrics
5. **failover_events** - Failover audit log
6. **routing_statistics** - Per-interface throughput metrics
7. **load_balancer_config** - LB settings per WAN
8. **static_routes** - Administrator-configured routes
9. **schema_versions** - Migration tracking

**Views:**
- `v_wan_status` - Current WAN health + LB config
- `v_connection_summary` - Active connections by interface
- `v_nat_utilization` - NAT port usage per WAN

## Configuration

### Performance Tuning
```yaml
packet_forwarding:
  workers: 8                    # Packet processing threads
  queue_depth: 4096            # Packets per queue
  batch_size: 64               # Batch processing
  batch_timeout_us: 100        # Microseconds
```

### WAN Health Checks
```yaml
failover:
  health_check:
    interval: "5s"             # Check every 5 seconds
    timeout: "2s"              # 2-second timeout
    ping_targets: [8.8.8.8, 1.1.1.1, 208.67.222.222]
```

### NAT Limits
```yaml
nat:
  max_mappings: 1000000        # 1M concurrent NAT sessions
  port_range: 10000-65535      # Dynamic port range
  tcp_established_timeout: 5h  # 5-hour timeout
  udp_timeout: 3m              # 3-minute timeout
```

## Important Notes

### Performance
- Zero-copy kernel bypass mode
- Multi-queue packet processing (8 queues)
- Batch processing (64 packets per batch)
- Hardware offload support
- Lock-free concurrent data structures

### Capacity
- 1,000,000 concurrent NAT mappings
- 262,144 connection tracking entries
- Support for 3+ WAN connections
- Unlimited static routes

### Security
- Connection state validation
- NAT port randomization
- Secure routing decisions
- Stateful connection tracking

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| Firewall Engine | gRPC Client | Network policy enforcement |
| DHCP Server | gRPC Client | IP address management |
| DNS Server | gRPC Client | DNS configuration |
| Network Logger | gRPC Client | Connection event logging |
| IDS/IPS | gRPC Client | Threat detection integration |
| PostgreSQL | Database | Persistent storage |
| TLS Proxy | gRPC Client | SNI extraction (Phase 1) |

---

**Status:** Production Ready
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** PostgreSQL, gRPC services
**Managed By:** Orchestrator
