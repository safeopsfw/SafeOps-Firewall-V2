# FILE: proto/network_manager.proto

## Purpose

The Network Manager protocol buffer defines the gRPC service interface for centralized network topology management in SafeOps. This service provides comprehensive control over WAN connections, VLAN segmentation, network switches, NAT policies, routing rules, and firewall zones. It acts as the single source of truth for network configuration and enables real-time monitoring of network status across all network segments.

This proto file is the foundation for the Network Manager service, which orchestrates all network-level operations including multi-WAN failover, load balancing, VLAN isolation, and dynamic routing policies.

---

## What This File Should Contain

### Service Definition

**Service Name**: `NetworkManager`
**Package**: `safeops.network`
**Description**: Centralized network topology and configuration management service

The NetworkManager service provides comprehensive network orchestration capabilities including:
- Multi-WAN connection management with failover and load balancing
- VLAN-based network segmentation and isolation
- Switch topology discovery and management
- NAT policy configuration (SNAT and DNAT)
- Policy-based routing and QoS enforcement
- IDS/IPS variable generation for network-aware security
- Real-time network status streaming

---

### RPC Methods

#### Category: Topology Management

##### Method: `GetNetworkTopology`
- **Request**: `GetTopologyRequest`
- **Response**: `NetworkTopology`
- **Purpose**: Retrieves the complete network topology including WAN connections, switches, VLANs, NAT policies, and routing rules
- **Used By**: Web UI (initial load), Orchestrator (validation), Backup Service (configuration snapshots)
- **Stream**: No
- **Idempotent**: Yes

**Request Fields:**
```protobuf
message GetTopologyRequest {
  bool include_switches = 1;    // Include switch topology data
  bool include_segments = 2;     // Include VLAN segments
  bool include_wan = 3;          // Include WAN connection details
}
```

**Use Case**: Web UI dashboard initial load requesting full network map

---

##### Method: `UpdateNetworkTopology`
- **Request**: `NetworkTopology`
- **Response**: `UpdateTopologyResponse`
- **Purpose**: Atomically updates the entire network topology configuration
- **Used By**: Web UI (bulk config updates), Configuration Import
- **Stream**: No
- **Idempotent**: No (creates audit log entries)

**Critical Behavior**: This method applies changes atomically - either all changes succeed or all fail. Used for importing complete network configurations or applying validated topology changes.

---

#### Category: WAN Management

##### Method: `ListWANConnections`
- **Request**: `ListWANRequest` (empty)
- **Response**: `ListWANResponse`
- **Purpose**: Lists all configured WAN connections with current status
- **Used By**: Web UI (WAN dashboard), Monitoring Service, Orchestrator
- **Stream**: No
- **Idempotent**: Yes

**Response Contains**: All WAN connections with real-time status (UP/DOWN/DEGRADED), latency, bandwidth usage, and failover state

---

##### Method: `GetWANConnection`
- **Request**: `GetWANRequest { string id }`
- **Response**: `WANConnection`
- **Purpose**: Retrieves detailed information for a specific WAN connection
- **Used By**: Web UI (WAN details page), Monitoring alerts
- **Stream**: No
- **Idempotent**: Yes

---

##### Method: `UpdateWANConnection`
- **Request**: `WANConnection`
- **Response**: `UpdateResponse`
- **Purpose**: Updates WAN connection configuration (bandwidth, priority, failover settings)
- **Used By**: Web UI (WAN configuration), API clients
- **Stream**: No
- **Idempotent**: No

**Side Effects**: May trigger failover reconfiguration, routing table updates, and load balancer weight adjustments

---

##### Method: `TestWANConnection`
- **Request**: `TestWANRequest { string id }`
- **Response**: `TestWANResponse`
- **Purpose**: Performs connectivity test on specified WAN connection (ping, latency check)
- **Used By**: Web UI (manual connectivity test), Health check service
- **Stream**: No
- **Idempotent**: Yes

**Testing Performed**: ICMP ping to configured monitoring target, measures latency and packet loss

---

#### Category: Network Segments (VLANs)

##### Method: `ListNetworkSegments`
- **Request**: `ListSegmentsRequest { string zone (optional) }`
- **Response**: `ListSegmentsResponse`
- **Purpose**: Lists all VLAN segments, optionally filtered by firewall zone
- **Used By**: Web UI (network segments view), DHCP Service, Firewall Service
- **Stream**: No
- **Idempotent**: Yes

---

##### Method: `GetNetworkSegment`
- **Request**: `GetSegmentRequest { string id }`
- **Response**: `NetworkSegment`
- **Purpose**: Retrieves detailed VLAN configuration including DHCP settings and access controls
- **Used By**: Web UI, DHCP Service (pool configuration), DNS Service
- **Stream**: No
- **Idempotent**: Yes

---

##### Method: `CreateNetworkSegment`
- **Request**: `NetworkSegment`
- **Response**: `CreateResponse { bool success, string id, string message }`
- **Purpose**: Creates new VLAN segment with specified configuration
- **Used By**: Web UI (add VLAN wizard), API clients
- **Stream**: No
- **Idempotent**: No

**Validation**: Ensures VLAN ID is unique (1-4094), subnet doesn't overlap with existing segments

**Side Effects**:
- Kernel driver receives VLAN tagging rules
- DHCP service creates IP pool
- Firewall zones updated
- Switch ports configured (if managed switches present)

---

##### Method: `UpdateNetworkSegment`
- **Request**: `NetworkSegment`
- **Response**: `UpdateResponse`
- **Purpose**: Updates existing VLAN configuration
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: No

**Constraints**: Cannot change VLAN ID or subnet if active devices exist

---

##### Method: `DeleteNetworkSegment`
- **Request**: `DeleteSegmentRequest { string id }`
- **Response**: `DeleteResponse`
- **Purpose**: Removes VLAN segment (requires zero active devices)
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: Yes

**Validation**: Fails if active DHCP leases or connected devices detected

---

#### Category: Switch Management

##### Method: `ListSwitches`
- **Request**: `ListSwitchesRequest { string type (optional) }`
- **Response**: `ListSwitchesResponse`
- **Purpose**: Lists all managed network switches with status
- **Used By**: Web UI (network topology diagram), Monitoring Service
- **Stream**: No
- **Idempotent**: Yes

**Type Filter**: CORE, DISTRIBUTION, ACCESS, WIRELESS_AP

---

##### Method: `GetSwitch`
- **Request**: `GetSwitchRequest { string id }`
- **Response**: `Switch`
- **Purpose**: Retrieves detailed switch information including port status, VLAN configuration
- **Used By**: Web UI (switch details page), Monitoring
- **Stream**: No
- **Idempotent**: Yes

---

##### Method: `UpdateSwitch`
- **Request**: `Switch`
- **Response**: `UpdateResponse`
- **Purpose**: Updates switch configuration (VLAN assignments, spanning tree, PoE)
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: No

**Supported Switches**: Cisco, HP/Aruba, Ubiquiti UniFi, TP-Link managed switches (via SNMP)

---

#### Category: NAT Policies

##### Method: `ListNATPolicies`
- **Request**: `ListNATRequest` (empty)
- **Response**: `ListNATResponse { NATConfiguration }`
- **Purpose**: Lists all Source NAT and Destination NAT (port forward) rules
- **Used By**: Web UI (NAT configuration page), Firewall Engine
- **Stream**: No
- **Idempotent**: Yes

---

##### Method: `CreateNATPolicy`
- **Request**: `NATPolicy { oneof { SourceNAT, DestinationNAT } }`
- **Response**: `CreateResponse`
- **Purpose**: Creates new NAT rule for outbound SNAT or inbound DNAT
- **Used By**: Web UI (add NAT rule), API clients
- **Stream**: No
- **Idempotent**: No

**SNAT Use Case**: Masquerade LAN traffic to specific WAN interface
**DNAT Use Case**: Port forwarding external traffic to internal server

**Side Effects**: Kernel driver receives NAT rules, connection tracking table updated

---

##### Method: `UpdateNATPolicy`
- **Request**: `NATPolicy`
- **Response**: `UpdateResponse`
- **Purpose**: Modifies existing NAT rule
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: No

---

##### Method: `DeleteNATPolicy`
- **Request**: `DeleteNATRequest { string id }`
- **Response**: `DeleteResponse`
- **Purpose**: Removes NAT rule
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: Yes

---

#### Category: Routing Policies

##### Method: `ListRoutingPolicies`
- **Request**: `ListRoutingRequest` (empty)
- **Response**: `ListRoutingResponse`
- **Purpose**: Lists all policy-based routing rules with QoS settings
- **Used By**: Web UI (routing policies), Firewall Engine
- **Stream**: No
- **Idempotent**: Yes

**Routing Policies**: Define which traffic uses which WAN connection based on protocol, port, source VLAN, or DSCP

---

##### Method: `CreateRoutingPolicy`
- **Request**: `RoutingPolicy`
- **Response**: `CreateResponse`
- **Purpose**: Creates policy-based routing rule with QoS parameters
- **Used By**: Web UI (add routing policy), API clients
- **Stream**: No
- **Idempotent**: No

**Example Use Case**: Route VoIP traffic (SIP/RTP ports) to primary WAN with high QoS priority

---

##### Method: `UpdateRoutingPolicy`
- **Request**: `RoutingPolicy`
- **Response**: `UpdateResponse`
- **Purpose**: Modifies existing routing policy
- **Used By**: Web UI, API clients
- **Stream**: No
- **Idempotent**: No

---

#### Category: IDS/IPS Integration

##### Method: `GenerateIDSVariables`
- **Request**: `GenerateIDSVarsRequest { Format format }`
- **Response**: `IDSVariables`
- **Purpose**: Auto-generates Suricata/Snort network variables from network topology
- **Used By**: IDS/IPS Service (startup configuration), Configuration Export
- **Stream**: No
- **Idempotent**: Yes

**Generated Variables**:
- `HOME_NET`: All internal VLAN subnets
- `EXTERNAL_NET`: !$HOME_NET
- `HTTP_SERVERS`, `DNS_SERVERS`, `SSH_SERVERS`: Auto-detected from network segments
- Custom variables from segment configurations

**Output Formats**:
- `SURICATA_YAML`: Suricata-compatible YAML
- `SNORT_CONF`: Snort 3 config format
- `JSON`: Structured JSON for programmatic use

---

#### Category: Real-time Monitoring

##### Method: `StreamNetworkStatus`
- **Request**: `google.protobuf.Empty`
- **Response**: `stream NetworkStatus`
- **Purpose**: Server-side streaming of real-time network status updates
- **Used By**: Web UI (live dashboard), Monitoring Service, Alerting System
- **Stream**: Yes (server streaming)
- **Idempotent**: Yes

**Update Frequency**: 1 second intervals

**Streamed Data**:
- WAN connection status (latency, packet loss, bytes transferred)
- Network segment metrics (active devices, bandwidth usage)
- Switch status (CPU, memory, temperature)
- Overall network health metrics

**Connection Management**: Client must handle reconnection on stream errors

---

## Message Definitions

### Core Messages

#### Message: `NetworkTopology`
```protobuf
message NetworkTopology {
  string version = 1;                              // Config version (e.g., "2.0")
  TopologyMetadata metadata = 2;                   // Organization metadata
  repeated WANConnection wan_connections = 3;       // All WAN interfaces
  LoadBalancing load_balancing = 4;                 // Load balancing config
  repeated NetworkSegment network_segments = 5;     // All VLAN segments
  repeated Switch switches = 6;                     // Managed switches
  NATConfiguration nat_policies = 7;                // NAT rules
  repeated RoutingPolicy routing_policies = 8;      // Routing policies
  IDSVariables ids_ips_variables = 9;              // IDS variables
  FirewallZones firewall_zones = 10;               // Firewall zones
}
```
**Purpose**: Complete network configuration snapshot
**Used In**: GetNetworkTopology, UpdateNetworkTopology, Backup Service
**Typical Size**: 10-50 KB depending on network complexity

---

#### Message: `WANConnection`
```protobuf
message WANConnection {
  string id = 1;                      // Unique ID (e.g., "wan1")
  string name = 2;                    // Display name (e.g., "Primary Fiber")
  string provider = 3;                // ISP name (e.g., "Comcast Business")
  string interface = 4;               // Physical interface (e.g., "eth0")
  ConnectionType type = 5;            // FIBER/CABLE/DSL/CELLULAR/SATELLITE
  int32 bandwidth_mbps = 6;           // Contracted bandwidth (e.g., 1000)
  IPType ip_type = 7;                 // STATIC/DHCP/PPPOE
  string public_ip = 8;               // External IP (e.g., "203.0.113.1")
  string gateway = 9;                 // Gateway IP
  string dns_primary = 10;            // Primary DNS
  string dns_secondary = 11;          // Secondary DNS
  string subnet_mask = 12;            // Subnet mask (e.g., "255.255.255.252")
  int32 vlan_id = 13;                 // VLAN tag (0 = untagged)
  int32 priority = 14;                // Failover priority (1 = highest)
  string failover_group = 15;         // Failover group name
  int32 load_balance_weight = 16;     // Load balance weight (1-100)
  WANMonitoring monitoring = 17;      // Health monitoring settings
  double cost_per_month = 18;         // Monthly cost (for reporting)
  Timestamp contract_end_date = 19;   // Contract expiration
  string notes = 20;                  // Admin notes
  WANStatus status = 21;              // Current runtime status
}
```
**Purpose**: Complete WAN interface configuration and status
**Used In**: All WAN management methods, failover logic, load balancing
**Validation Rules**:
- `bandwidth_mbps`: 1-100000
- `priority`: 1-10 (1 = highest priority)
- `load_balance_weight`: 1-100
- `public_ip`: Must be valid IPv4/IPv6, not RFC1918 private

---

#### Message: `NetworkSegment`
```protobuf
message NetworkSegment {
  string id = 1;                       // Unique ID (e.g., "vlan10")
  string name = 2;                     // Display name (e.g., "Employee WiFi")
  int32 vlan_id = 3;                   // VLAN tag (1-4094)
  string description = 4;              // Purpose description
  string subnet = 5;                   // CIDR (e.g., "192.168.10.0/24")
  string gateway = 6;                  // Gateway IP (e.g., "192.168.10.1")
  string interface = 7;                // Parent interface (e.g., "eth1")
  string zone = 8;                     // Firewall zone (e.g., "TRUSTED")
  DHCPConfig dhcp = 9;                 // DHCP pool settings
  SecurityLevel security_level = 10;   // LOW/MEDIUM/HIGH/CRITICAL
  bool isolation = 11;                 // Client isolation enabled
  AccessControl access_control = 12;   // Firewall rules for segment
  repeated string services = 13;       // Allowed services
  repeated string connected_switches = 14; // Switch IDs
  int32 device_count_estimate = 15;    // Expected device count

  // Runtime metrics (read-only)
  int32 active_devices = 16;           // Currently connected devices
  int64 bytes_in = 17;                 // Bytes received
  int64 bytes_out = 18;                // Bytes transmitted
}
```
**Purpose**: VLAN segment configuration with DHCP and access control
**Used In**: Network segmentation, DHCP service, Firewall service
**Validation Rules**:
- `vlan_id`: 1-4094 (must be unique)
- `subnet`: Must be valid CIDR, cannot overlap with other segments
- `gateway`: Must be within subnet range
- `security_level`: Determines default firewall rules applied

---

#### Message: `SourceNAT`
```protobuf
message SourceNAT {
  string id = 1;                       // Unique ID
  string name = 2;                     // Display name
  repeated int32 source_vlans = 3;     // Source VLANs (e.g., [10, 20, 30])
  string destination = 4;              // Destination CIDR or "any"
  string wan_interface = 5;            // Target WAN (e.g., "wan1")
  NATType nat_type = 6;                // MASQUERADE/STATIC/DYNAMIC
  string nat_pool = 7;                 // IP pool for dynamic NAT
  bool preserve_port_ranges = 8;       // Port preservation (useful for gaming)
}
```
**Purpose**: Outbound NAT (masquerading) configuration
**Used In**: NAT policy management, packet egress processing
**Common Use Case**: Masquerade all LAN traffic (VLAN 10-50) through WAN1

---

#### Message: `DestinationNAT`
```protobuf
message DestinationNAT {
  string id = 1;                       // Unique ID
  string name = 2;                     // Display name (e.g., "Web Server")
  string description = 3;              // Purpose description
  string wan_interface = 4;            // Incoming WAN (e.g., "wan1")
  string protocol = 5;                 // "tcp" or "udp"
  string external_ip = 6;              // Public IP (or "any")
  repeated int32 external_ports = 7;   // External ports (e.g., [80, 443])
  string internal_ip = 8;              // Destination LAN IP
  repeated int32 internal_ports = 9;   // Destination ports (e.g., [80, 443])
  bool enabled = 10;                   // Enable/disable rule

  // Statistics (read-only)
  int64 connection_count = 11;         // Total connections
  int64 bytes_transferred = 12;        // Total bytes
}
```
**Purpose**: Inbound port forwarding (DNAT) configuration
**Used In**: NAT policy management, packet ingress processing
**Common Use Case**: Forward WAN:80,443 → LAN:192.168.1.10:80,443 (web server)

**Port Mapping**: External and internal ports can differ (e.g., external 8080 → internal 80)

---

#### Message: `RoutingPolicy`
```protobuf
message RoutingPolicy {
  string id = 1;                       // Unique ID
  string name = 2;                     // Display name
  int32 priority = 3;                  // Priority (lower = higher priority)
  RoutingMatch match = 4;              // Traffic matching criteria
  RoutingAction action = 5;            // Routing action
}
```
**Purpose**: Policy-based routing rule with QoS
**Used In**: Traffic routing decisions, QoS enforcement
**Evaluation Order**: Sorted by priority (ascending), first match wins

---

#### Message: `RoutingMatch`
```protobuf
message RoutingMatch {
  repeated string protocols = 1;       // ["tcp", "udp", "icmp"]
  repeated int32 ports = 2;            // Destination ports
  repeated int32 source_vlans = 3;     // Source VLAN IDs
  repeated string dscp = 4;            // DSCP markings (e.g., ["EF", "AF41"])
}
```
**Purpose**: Traffic matching criteria for routing policies
**Match Logic**: All specified fields must match (AND logic)

**Example**: Match VoIP traffic: `protocols=["udp"], ports=[5060, 10000-20000], dscp=["EF"]`

---

#### Message: `RoutingAction`
```protobuf
message RoutingAction {
  string wan_connection = 1;             // Single WAN (mutually exclusive with #2)
  repeated string wan_connections = 2;   // Multiple WANs (load balance)
  bool load_balance = 3;                 // Enable load balancing
  QoSPriority qos_priority = 4;          // LOW/MEDIUM/HIGH/CRITICAL
  int32 guaranteed_bandwidth_mbps = 5;   // Minimum guaranteed bandwidth
  int32 bandwidth_limit_mbps = 6;        // Maximum allowed bandwidth
}
```
**Purpose**: Routing action with QoS enforcement
**QoS Priority Mapping**:
- `CRITICAL` (0-7 latency ms, 0% loss) - VoIP, video conferencing
- `HIGH` (8-20 ms, <0.1% loss) - SSH, RDP, interactive apps
- `MEDIUM` (21-50 ms, <1% loss) - Web browsing, email
- `LOW` (>50 ms, <5% loss) - File transfers, backups

---

### Enums

#### Enum: `ConnectionType`
```protobuf
enum ConnectionType {
  FIBER = 0;
  CABLE = 1;
  DSL = 2;
  CELLULAR = 3;
  SATELLITE = 4;
}
```
**Purpose**: WAN connection physical medium type
**Used For**: Display, bandwidth estimation, latency expectations

---

#### Enum: `IPType`
```protobuf
enum IPType {
  STATIC = 0;      // Manual IP configuration
  DHCP = 1;        // DHCP client
  PPPOE = 2;       // PPPoE authentication
}
```
**Purpose**: WAN IP address assignment method

---

#### Enum: `SecurityLevel`
```protobuf
enum SecurityLevel {
  LOW = 0;         // Guest networks, IoT devices
  MEDIUM = 1;      // Employee workstations
  HIGH = 2;        // Servers, critical infrastructure
  CRITICAL = 3;    // Management network, PCI/HIPAA data
}
```
**Purpose**: Network segment security classification
**Impact**: Determines default firewall rules, logging verbosity, IDS sensitivity

---

#### Enum: `NATType`
```protobuf
enum NATType {
  MASQUERADE = 0;  // Dynamic source IP (typical for LAN → WAN)
  STATIC = 1;      // 1:1 static NAT mapping
  DYNAMIC = 2;     // Dynamic NAT pool
}
```
**Purpose**: Source NAT behavior

---

#### Enum: `QoSPriority`
```protobuf
enum QoSPriority {
  LOW = 0;
  MEDIUM = 1;
  HIGH = 2;
  CRITICAL = 3;
}
```
**Purpose**: QoS classification for traffic shaping
**Implementation**: Maps to DSCP markings in IP header

---

## Key Features

### 1. **Multi-WAN Failover & Load Balancing**
- Supports up to 16 WAN connections simultaneously
- Automatic failover based on health monitoring (ICMP ping, latency, packet loss)
- Configurable failover groups for business continuity
- Load balancing modes: Round-robin, weighted round-robin, least connections, source IP hash
- Per-connection bandwidth monitoring and accounting

### 2. **VLAN-Based Network Segmentation**
- Full 802.1Q VLAN support (VLAN IDs 1-4094)
- Per-segment DHCP configuration with custom IP pools
- Client isolation for guest and IoT networks
- Hierarchical security levels (LOW → CRITICAL)
- Bandwidth limiting per segment

### 3. **Managed Switch Integration**
- Auto-discovery of managed switches via SNMP
- Topology visualization (core/distribution/access layers)
- Real-time port status and utilization monitoring
- VLAN configuration synchronization
- PoE monitoring and control

### 4. **Advanced NAT Capabilities**
- Source NAT (SNAT/Masquerading) with WAN selection
- Destination NAT (DNAT/Port Forwarding) with statistics
- NAT pool support for multiple public IPs
- Port preservation for gaming and P2P applications
- Per-rule connection counting and bandwidth tracking

### 5. **Policy-Based Routing**
- Route traffic by protocol, port, source VLAN, or DSCP
- Multi-WAN routing with load balancing
- QoS enforcement with guaranteed/maximum bandwidth
- Priority queuing (4 levels: LOW/MEDIUM/HIGH/CRITICAL)
- Traffic shaping and rate limiting

### 6. **IDS/IPS Network Awareness**
- Auto-generates Suricata/Snort variables from network topology
- Dynamic HOME_NET based on all internal VLANs
- Server role detection (HTTP/DNS/SSH/SMTP servers)
- Custom variable support for advanced IDS rules
- Multiple output formats (YAML/CONF/JSON)

### 7. **Real-Time Monitoring**
- Server-side streaming for live dashboard updates
- WAN latency and packet loss tracking
- Per-segment device count and bandwidth usage
- Switch health monitoring (CPU, memory, temperature)
- Overall network metrics aggregation

### 8. **Atomic Configuration Updates**
- Entire topology can be updated in single transaction
- Configuration validation before apply
- Rollback on partial failure
- Audit logging for all changes
- Configuration versioning

---

## Dependencies

### External Proto Imports
- `google/protobuf/timestamp.proto` - Used for contract_end_date, last_updated, last_check timestamps
- `google/protobuf/empty.proto` - Used for StreamNetworkStatus request (no parameters needed)

### Generated Code Dependencies

**Go:**
```go
import (
  networkpb "github.com/safeops/proto/network"
  "google.golang.org/grpc"
  timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)
```
**Package**: `github.com/safeops/proto/network`

**Rust:**
```rust
use safeops_proto::network::{NetworkManager, NetworkTopology, WANConnection};
```
**Crate**: `safeops_proto::network`

### External Dependencies (Implementation)
- **PostgreSQL**: Network configuration persistence
- **Redis**: Real-time status caching, WAN health metrics
- **SNMP**: Managed switch discovery and monitoring
- **NetLink (Linux)**: VLAN interface creation, routing table manipulation
- **iptables/nftables**: NAT rule implementation

---

## Connected Services

### Services That Call NetworkManager

| Service | Purpose | Methods Used |
|---------|---------|--------------|
| **Orchestrator** | Topology validation, startup config | GetNetworkTopology, StreamNetworkStatus |
| **DHCP Server** | IP pool configuration | ListNetworkSegments, GetNetworkSegment |
| **DNS Server** | Network-aware DNS resolution | ListNetworkSegments (for split-horizon DNS) |
| **Firewall Engine** | Zone-based filtering, NAT rules | GetNetworkTopology, ListNATPolicies |
| **IDS/IPS Service** | Network variable generation | GenerateIDSVariables |
| **Web UI** | All network management operations | All methods (full CRUD) |
| **Backup Service** | Configuration export | GetNetworkTopology |
| **Monitoring Service** | Network health tracking | StreamNetworkStatus, ListWANConnections |

### Services NetworkManager Calls

| Service | Purpose | Methods Used |
|---------|---------|--------------|
| **Kernel Driver** | VLAN tagging, NAT rules | SetVLANRules, SetNATRules (not in this proto) |
| **Switch Controller** | SNMP communication | GetSwitchStatus (external SNMP library) |
| **Health Check Service** | WAN connectivity testing | PingTarget, MeasureLatency |

---

## Build Instructions

### Windows (PowerShell)
```powershell
cd proto
.\build.ps1
```

### Linux/macOS (Bash)
```bash
cd proto
chmod +x build.sh
./build.sh
```

### Clean Build
```powershell
# Windows
.\build.ps1 -Clean

# Linux/macOS
./build.sh --clean
```

### Generates:

**Go Code:**
- `proto/gen/go/network/network_manager.pb.go` - Message type definitions
- `proto/gen/go/network/network_manager_grpc.pb.go` - gRPC service client/server interfaces

**Rust Code:**
- `proto/gen/rust/network/network_manager.rs` - Combined messages and services

---

## Usage Examples

### Example 1: Create New VLAN Segment

**Go Client:**
```go
import (
    networkpb "github.com/safeops/proto/network"
    "google.golang.org/grpc"
)

client := networkpb.NewNetworkManagerClient(conn)

segment := &networkpb.NetworkSegment{
    Name:        "Guest WiFi",
    VlanId:      100,
    Description: "Guest wireless network - isolated from LAN",
    Subnet:      "192.168.100.0/24",
    Gateway:     "192.168.100.1",
    Interface:   "eth1",
    Zone:        "GUEST",
    SecurityLevel: networkpb.SecurityLevel_LOW,
    Isolation:   true,
    Dhcp: &networkpb.DHCPConfig{
        Enabled:    true,
        RangeStart: "192.168.100.100",
        RangeEnd:   "192.168.100.200",
        LeaseTimeHours: 24,
        DnsServers: []string{"8.8.8.8", "8.8.4.4"},
    },
    AccessControl: &networkpb.AccessControl{
        AllowToInternet:  true,
        AllowToServers:   false,
        DenyToManagement: true,
        BandwidthLimitMbps: 50,
    },
}

resp, err := client.CreateNetworkSegment(ctx, segment)
if err != nil {
    log.Fatalf("Failed to create segment: %v", err)
}

log.Printf("Created segment ID: %s", resp.Id)
```

---

### Example 2: Configure Multi-WAN Failover

**Go Client:**
```go
// Primary WAN (Fiber - Priority 1)
wan1 := &networkpb.WANConnection{
    Id:           "wan1",
    Name:         "Primary Fiber",
    Provider:     "AT&T Business Fiber",
    Interface:    "eth0",
    Type:         networkpb.ConnectionType_FIBER,
    BandwidthMbps: 1000,
    IpType:       networkpb.IPType_STATIC,
    PublicIp:     "203.0.113.10",
    Gateway:      "203.0.113.1",
    Priority:     1,  // Highest priority
    FailoverGroup: "primary",
    LoadBalanceWeight: 80,
    Monitoring: &networkpb.WANMonitoring{
        Enabled:             true,
        PingTarget:          "8.8.8.8",
        CheckIntervalSeconds: 5,
    },
}

// Backup WAN (Cable - Priority 2)
wan2 := &networkpb.WANConnection{
    Id:           "wan2",
    Name:         "Backup Cable",
    Provider:     "Comcast Business",
    Interface:    "eth2",
    Type:         networkpb.ConnectionType_CABLE,
    BandwidthMbps: 500,
    IpType:       networkpb.IPType_DHCP,
    Priority:     2,  // Backup priority
    FailoverGroup: "backup",
    LoadBalanceWeight: 20,
    Monitoring: &networkpb.WANMonitoring{
        Enabled:             true,
        PingTarget:          "1.1.1.1",
        CheckIntervalSeconds: 5,
    },
}

client.UpdateWANConnection(ctx, wan1)
client.UpdateWANConnection(ctx, wan2)
```

---

### Example 3: Add Port Forwarding Rule

**Go Client:**
```go
dnat := &networkpb.DestinationNAT{
    Name:         "Web Server HTTPS",
    Description:  "Forward public HTTPS traffic to internal web server",
    WanInterface: "wan1",
    Protocol:     "tcp",
    ExternalIp:   "203.0.113.10",  // Public IP
    ExternalPorts: []int32{443},
    InternalIp:   "192.168.1.100",  // Internal web server
    InternalPorts: []int32{443},
    Enabled:      true,
}

natPolicy := &networkpb.NATPolicy{
    Policy: &networkpb.NATPolicy_Destination{
        Destination: dnat,
    },
}

resp, err := client.CreateNATPolicy(ctx, natPolicy)
if err != nil {
    log.Fatalf("Failed to create DNAT rule: %v", err)
}

log.Printf("Created DNAT rule ID: %s", resp.Id)
```

---

### Example 4: Policy-Based Routing for VoIP

**Go Client:**
```go
// Route VoIP traffic through primary WAN with high QoS
voipPolicy := &networkpb.RoutingPolicy{
    Name:     "VoIP Traffic Routing",
    Priority: 10,  // High priority rule
    Match: &networkpb.RoutingMatch{
        Protocols: []string{"udp"},
        Ports:     []int32{5060, 5061},  // SIP signaling
        SourceVlans: []int32{20},  // VoIP VLAN
        Dscp:      []string{"EF"},  // Expedited Forwarding
    },
    Action: &networkpb.RoutingAction{
        WanConnection:          "wan1",  // Primary WAN only
        QosPriority:            networkpb.QoSPriority_CRITICAL,
        GuaranteedBandwidthMbps: 10,  // Reserve 10 Mbps
        BandwidthLimitMbps:     50,  // Max 50 Mbps
    },
}

resp, err := client.CreateRoutingPolicy(ctx, voipPolicy)
```

---

### Example 5: Real-Time Network Monitoring

**Go Client:**
```go
import (
    "io"
)

stream, err := client.StreamNetworkStatus(ctx, &emptypb.Empty{})
if err != nil {
    log.Fatalf("Failed to start stream: %v", err)
}

for {
    status, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Printf("Stream error: %v", err)
        continue
    }

    // Process real-time network status
    for _, wan := range status.WanStatus {
        log.Printf("WAN %s: State=%s, Latency=%.2fms, Loss=%.2f%%",
            wan.Id,
            wan.Status.State,
            wan.Monitoring.LatencyMs,
            wan.Monitoring.PacketLossPercent,
        )
    }

    // Overall network metrics
    metrics := status.OverallMetrics
    log.Printf("Total Devices: %d, Connections: %d, Avg Latency: %.2fms",
        metrics.TotalDevices,
        metrics.TotalConnections,
        metrics.AverageLatencyMs,
    )
}
```

---

### Example 6: Generate IDS Variables

**Go Client:**
```go
req := &networkpb.GenerateIDSVarsRequest{
    Format: networkpb.GenerateIDSVarsRequest_SURICATA_YAML,
}

vars, err := client.GenerateIDSVariables(ctx, req)
if err != nil {
    log.Fatalf("Failed to generate IDS vars: %v", err)
}

log.Printf("HOME_NET: %v", vars.HomeNet)
// Output: ["192.168.1.0/24", "192.168.10.0/24", "10.0.0.0/8"]

log.Printf("HTTP_SERVERS: %v", vars.HttpServers)
// Output: ["192.168.1.100", "192.168.1.101"]

log.Printf("DNS_SERVERS: %v", vars.DnsServers)
// Output: ["192.168.1.1", "10.0.0.53"]

// Write to Suricata config file
ioutil.WriteFile("/etc/suricata/vars.yaml", []byte(marshalVars(vars)), 0644)
```

---

## Validation Rules

### WAN Connection Validation
- `bandwidth_mbps`: Range 1-100000 (must match physical capability)
- `priority`: Range 1-10 (lower number = higher priority)
- `load_balance_weight`: Range 1-100
- `public_ip`: Must be valid IPv4 or IPv6, cannot be RFC1918 private address
- `vlan_id`: Range 0-4094 (0 = untagged)

### Network Segment Validation
- `vlan_id`: Range 1-4094, must be unique across all segments
- `subnet`: Must be valid CIDR notation, cannot overlap with existing segments
- `gateway`: Must be within subnet range, typically .1 or .254
- `dhcp.range_start` and `dhcp.range_end`: Must be within subnet, cannot include gateway
- `security_level`: Must be valid enum value

### NAT Policy Validation
- **DestinationNAT**:
  - `external_ports` and `internal_ports` must have same count
  - `protocol` must be "tcp" or "udp"
  - `internal_ip` must exist in a configured network segment
- **SourceNAT**:
  - `source_vlans` must reference existing VLANs
  - `wan_interface` must reference existing WAN connection

### Routing Policy Validation
- `priority`: Range 1-1000 (lower number evaluated first)
- `match.ports`: Range 1-65535
- `action.guaranteed_bandwidth_mbps`: Cannot exceed WAN bandwidth
- `action.bandwidth_limit_mbps`: Must be >= guaranteed_bandwidth_mbps

---

## Performance Considerations

- **GetNetworkTopology**: Cached in Redis for 30 seconds, full response ~10-50 KB
- **ListNetworkSegments**: Returns all segments in single call, typically <100 segments
- **StreamNetworkStatus**: 1 update/second, ~5 KB per update, use connection pooling
- **CreateNetworkSegment**: Synchronous operation, applies to kernel driver, ~100ms latency
- **UpdateWANConnection**: May trigger routing table recalculation, ~50-200ms latency

**Optimization Tip**: Use StreamNetworkStatus for dashboard instead of polling Get* methods

---

## Security Considerations

- **gRPC Authentication**: All methods require valid JWT token (issued by Orchestrator)
- **Role-Based Access**: Only `network_admin` role can modify network configuration
- **Audit Logging**: All configuration changes logged to PostgreSQL audit table
- **Rate Limiting**: API calls limited to 100 req/min per client
- **Input Validation**: All IP addresses, CIDRs, and port ranges validated before application

**Sensitive Fields**: `cost_per_month`, `contract_end_date`, `notes` - redacted in non-admin views

---

## Troubleshooting

### Common Issues

**Issue: VLAN creation fails with "subnet overlap"**
**Cause**: New VLAN subnet overlaps with existing segment
**Solution**: Use non-overlapping subnet (e.g., if 192.168.1.0/24 exists, use 192.168.2.0/24)

**Issue: WAN failover not triggering**
**Cause**: Health monitoring disabled or incorrect ping target
**Solution**: Verify `monitoring.enabled = true` and `ping_target` is reachable public IP (8.8.8.8)

**Issue: Port forwarding not working**
**Cause**: Firewall zone blocks incoming traffic
**Solution**: Ensure firewall zone policy allows DNAT traffic from EXTERNAL → DMZ/LAN

**Issue: StreamNetworkStatus disconnects frequently**
**Cause**: Client not handling connection errors
**Solution**: Implement exponential backoff reconnection logic

**Issue: IDS variables missing servers**
**Cause**: Network segments not tagged with service types
**Solution**: Add `services = ["http", "dns"]` to NetworkSegment configuration

---

**Document Version**: 1.0
**Last Updated**: 2025-12-15
**Author**: AGENT 2 - Proto Documentation Specialist
