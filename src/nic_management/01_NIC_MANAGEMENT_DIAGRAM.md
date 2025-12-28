# NIC Management Component - Architecture Diagram

**File:** 01_NIC_MANAGEMENT_DIAGRAM.md
**Component:** NIC Management Service
**Purpose:** Multi-WAN routing, NAT/NAPT translation, load balancing, automatic failover

---

## 🎯 NIC Management Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NIC MANAGEMENT SERVICE                              │
│                         Port: 50054 (gRPC)                                  │
│                         Metrics: 9154 (Prometheus)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
    ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
    │ NIC DISCOVERY     │  │ PACKET ROUTING    │  │ LOAD BALANCING    │
    │ (Go)              │  │ (Rust - Fast)     │  │ (Go)              │
    ├───────────────────┤  ├───────────────────┤  ├───────────────────┤
    │ • WAN Detection   │  │ • Packet Capture  │  │ • WAN Selection   │
    │ • LAN Detection   │  │ • Routing Engine  │  │ • Health Checks   │
    │ • Classification  │  │ • NAT Translation │  │ • Traffic Dist    │
    │ • Hotplug Monitor │  │ • Forwarding      │  │ • Failover        │
    └───────────────────┘  └───────────────────┘  └───────────────────┘
```

---

## 📊 Component Breakdown

### 1. NIC Discovery & Classification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DISCOVERY ENGINE (internal/discovery/)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  enumerator.go                                                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ 1. Scan all network interfaces         │                                 │
│  │ 2. Read from OS (WMI/netlink)          │                                 │
│  │ 3. Detect: Name, MAC, IP, Speed        │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  classifier.go                                                               │
│  ┌────────────────────────────────────────┐                                 │
│  │ WAN Detection Rules:                   │                                 │
│  │ • Has default route (gateway)          │                                 │
│  │ • Public IP address                    │                                 │
│  │ • Manual config override               │                                 │
│  │                                         │                                 │
│  │ LAN Detection Rules:                   │                                 │
│  │ • Private IP (192.168.x.x, 10.x.x.x)  │                                 │
│  │ • No default route                     │                                 │
│  │ • Connected devices                    │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  Database (network_interfaces table)                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ name       │ type │ ip            │ gateway      │ status │ role       │ │
│  ├────────────┼──────┼───────────────┼──────────────┼────────┼───────────┤ │
│  │ Ethernet 1 │ WAN  │ 203.0.113.5   │ 203.0.113.1  │ UP     │ PRIMARY   │ │
│  │ Ethernet 2 │ WAN  │ 198.51.100.10 │ 198.51.100.1 │ UP     │ BACKUP    │ │
│  │ Ethernet 3 │ LAN  │ 192.168.1.1   │ None         │ UP     │ DHCP_SRV  │ │
│  └────────────┴──────┴───────────────┴──────────────┴────────┴───────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**

- `internal/discovery/enumerator.go` - Scans network interfaces
- `internal/discovery/classifier.go` - Classifies as WAN/LAN
- `internal/discovery/monitor.go` - Hotplug detection (cable insert/remove)
- `internal/discovery/physical_detector.go` - Physical vs virtual NIC detection
- `internal/discovery/capabilities.go` - Speed, duplex, MTU detection

---

### 2. Packet Routing & NAT Engine (Performance Critical - Rust)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ RUST PACKET PROCESSING PIPELINE (internal/router/ - Rust)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐           │
│  │ LAN Device  │────────▶│   WAN 1     │────────▶│  Internet   │           │
│  │ 192.168.1.100        │   PRIMARY    │                                   │
│  └─────────────┘         └─────────────┘                                    │
│                                                                              │
│  Packet Flow:                                                                │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  1. CAPTURE (packet_capture.rs)                                             │
│     ┌──────────────────────────────────────────┐                            │
│     │ • libpcap (Windows via Npcap)            │                            │
│     │ • AF_PACKET raw sockets (Linux)          │                            │
│     │ • Multi-queue buffer management          │                            │
│     └──────────────────────────────────────────┘                            │
│          │                                                                   │
│          ▼                                                                   │
│  2. ROUTING DECISION (routing_engine.rs)                                    │
│     ┌──────────────────────────────────────────┐                            │
│     │ 5-Tuple Match:                           │                            │
│     │ • Source IP: 192.168.1.100               │                            │
│     │ • Dest IP: 93.184.216.34 (example.com)   │                            │
│     │ • Source Port: 54321                     │                            │
│     │ • Dest Port: 443                         │                            │
│     │ • Protocol: TCP                          │                            │
│     │                                           │                            │
│     │ → Select WAN: PRIMARY (WAN 1)            │                            │
│     └──────────────────────────────────────────┘                            │
│          │                                                                   │
│          ▼                                                                   │
│  3. NAT TRANSLATION (translator.rs - Rust)                                  │
│     ┌──────────────────────────────────────────┐                            │
│     │ NAPT (Network Address Port Translation) │                            │
│     │                                           │                            │
│     │ Before NAT:                              │                            │
│     │   Src: 192.168.1.100:54321               │                            │
│     │   Dst: 93.184.216.34:443                 │                            │
│     │                                           │                            │
│     │ After NAT:                               │                            │
│     │   Src: 203.0.113.5:10001 ← Allocated    │                            │
│     │   Dst: 93.184.216.34:443                 │                            │
│     │                                           │                            │
│     │ NAT Mapping Stored:                      │                            │
│     │   192.168.1.100:54321 → 203.0.113.5:10001│                            │
│     └──────────────────────────────────────────┘                            │
│          │                                                                   │
│          ▼                                                                   │
│  4. FORWARD (forwarding_engine.rs)                                          │
│     ┌──────────────────────────────────────────┐                            │
│     │ • Rewrite packet headers                 │                            │
│     │ • Update checksums (IP, TCP, UDP)        │                            │
│     │ • Send via WAN 1 interface               │                            │
│     └──────────────────────────────────────────┘                            │
│                                                                              │
│  Return Path (Reverse NAT):                                                 │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Response from Internet:                                                    │
│    Src: 93.184.216.34:443                                                   │
│    Dst: 203.0.113.5:10001 ← Lookup in NAT table                            │
│                                                                              │
│  Translate back:                                                            │
│    Src: 93.184.216.34:443                                                   │
│    Dst: 192.168.1.100:54321 ← Original LAN address                         │
│                                                                              │
│  Forward to LAN device → Packet delivered!                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files (Rust - Performance Critical):**

- `internal/router/packet_capture.rs` - High-speed packet capture
- `internal/router/routing_engine.rs` - Core routing decision logic
- `internal/router/forwarding_engine.rs` - Packet forwarding
- `internal/nat/translator.rs` - NAT/NAPT translation engine

**Key Files (Go - State Management):**

- `internal/nat/port_allocator.go` - Dynamic port allocation (10000-65535)
- `internal/nat/mapping_table.go` - NAT mapping table (LAN IP:Port → WAN IP:Port)
- `internal/nat/session_tracker.go` - Session lifecycle management
- `internal/router/connection_tracker.go` - Connection state tracking

---

### 3. Multi-WAN Load Balancing & Failover

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LOAD BALANCER (internal/loadbalancer/)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  wan_selector.go                                                             │
│  ┌────────────────────────────────────────┐                                 │
│  │ Selection Algorithms:                  │                                 │
│  │                                         │                                 │
│  │ • Round-Robin: WAN1 → WAN2 → WAN1     │                                 │
│  │ • Weighted: 75% WAN1, 25% WAN2         │                                 │
│  │ • Least-Connections: Lowest active     │                                 │
│  │ • Hash-Based: Consistent per source IP │                                 │
│  └────────────────────────────────────────┘                                 │
│          │                                                                   │
│          ▼                                                                   │
│  health_checker.go                                                           │
│  ┌────────────────────────────────────────┐                                 │
│  │ WAN Health Monitoring (every 5s):      │                                 │
│  │                                         │                                 │
│  │ WAN 1: Ping 203.0.113.1                │                                 │
│  │   ✅ Response: 12ms → HEALTHY          │                                 │
│  │                                         │                                 │
│  │ WAN 2: Ping 198.51.100.1               │                                 │
│  │   ✅ Response: 18ms → HEALTHY          │                                 │
│  └────────────────────────────────────────┘                                 │
│                                                                              │
│ ┌──────────────────────────────────────────────────────────────────────────┐│
│ │ FAILOVER STATE MACHINE (internal/failover/)                              ││
│ ├──────────────────────────────────────────────────────────────────────────┤│
│ │                                                                            ││
│ │  State: PRIMARY_ACTIVE                                                    ││
│ │  ┌──────────────────────────────────┐                                     ││
│ │  │ WAN 1: PRIMARY (Active)          │                                     ││
│ │  │ WAN 2: BACKUP (Standby)          │                                     ││
│ │  │ Traffic: 100% via WAN 1          │                                     ││
│ │  └──────────────────────────────────┘                                     ││
│ │          │                                                                 ││
│ │          │ WAN 1 FAILS (3 consecutive ping timeouts)                      ││
│ │          ▼                                                                 ││
│ │  State: FAILOVER                                                          ││
│ │  ┌──────────────────────────────────┐                                     ││
│ │  │ WAN 1: DOWN (Failed)             │                                     ││
│ │  │ WAN 2: ACTIVE (Taking over)      │                                     ││
│ │  │ Action: Remap NAT sessions       │                                     ││
│ │  │ • 1,523 sessions moved to WAN 2  │                                     ││
│ │  │ • Update routing table           │                                     ││
│ │  │ • Publish WAN_FAILOVER_EVENT     │                                     ││
│ │  └──────────────────────────────────┘                                     ││
│ │          │                                                                 ││
│ │          │ WAN 1 RECOVERS (5 consecutive successful pings)                ││
│ │          ▼                                                                 ││
│ │  State: RECOVERING                                                        ││
│ │  ┌──────────────────────────────────┐                                     ││
│ │  │ WAN 1: UP (Detected)             │                                     ││
│ │  │ WAN 2: ACTIVE (Current)          │                                     ││
│ │  │ Action: Wait 60s (avoid flapping)│                                     ││
│ │  └──────────────────────────────────┘                                     ││
│ │          │                                                                 ││
│ │          ▼                                                                 ││
│ │  State: PRIMARY_ACTIVE (Restored)                                         ││
│ │  ┌──────────────────────────────────┐                                     ││
│ │  │ WAN 1: PRIMARY (Active)          │                                     ││
│ │  │ WAN 2: BACKUP (Standby)          │                                     ││
│ │  │ Traffic: 100% via WAN 1          │                                     ││
│ │  └──────────────────────────────────┘                                     ││
│ └──────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Files:**

- `internal/loadbalancer/wan_selector.go` - WAN selection algorithms
- `internal/loadbalancer/health_checker.go` - WAN health monitoring (ICMP ping)
- `internal/loadbalancer/session_affinity.go` - Session persistence (same source → same WAN)
- `internal/failover/state_machine.go` - Failover state machine
- `internal/failover/wan_monitor.go` - Continuous WAN monitoring
- `internal/failover/failover_handler.go` - Automatic failover orchestration

---

## 🗄️ Database Schema (PostgreSQL)

```sql
-- Network interfaces inventory
CREATE TABLE network_interfaces (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),              -- "Ethernet 1"
  type VARCHAR(10),                -- "WAN" or "LAN"
  role VARCHAR(20),                -- "PRIMARY", "BACKUP", "DHCP_SRV"
  ip_address INET,                 -- 203.0.113.5
  gateway INET,                    -- 203.0.113.1
  mac_address VARCHAR(17),         -- AA:BB:CC:DD:EE:FF
  status VARCHAR(20),              -- "UP", "DOWN"
  speed_mbps INTEGER,              -- 1000 (Gigabit)
  detected_at TIMESTAMP DEFAULT NOW()
);

-- Connection tracking (active sessions)
CREATE TABLE connection_tracking (
  id SERIAL PRIMARY KEY,
  src_ip INET,                     -- 192.168.1.100
  src_port INTEGER,                -- 54321
  dst_ip INET,                     -- 93.184.216.34
  dst_port INTEGER,                -- 443
  protocol VARCHAR(10),            -- "TCP", "UDP"
  wan_interface VARCHAR(100),      -- "Ethernet 1"
  state VARCHAR(20),               -- "ESTABLISHED", "CLOSED"
  created_at TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW()
);

-- NAT mappings (LAN → WAN translation)
CREATE TABLE nat_mappings (
  id SERIAL PRIMARY KEY,
  lan_ip INET,                     -- 192.168.1.100
  lan_port INTEGER,                -- 54321
  wan_ip INET,                     -- 203.0.113.5
  wan_port INTEGER,                -- 10001
  protocol VARCHAR(10),            -- "TCP", "UDP"
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  UNIQUE(wan_ip, wan_port, protocol)
);

-- WAN health history
CREATE TABLE wan_health_history (
  id SERIAL PRIMARY KEY,
  interface_name VARCHAR(100),     -- "Ethernet 1"
  status VARCHAR(20),              -- "HEALTHY", "DOWN"
  latency_ms INTEGER,              -- 12
  timestamp TIMESTAMP DEFAULT NOW()
);
```

---

## 📡 gRPC API (Port 50054)

```protobuf
service NICManagement {
  // Interface management
  rpc ListNetworkInterfaces() returns (NICList);
  rpc GetInterfaceStats(NICRequest) returns (InterfaceStats);
  rpc ConfigureInterface(ConfigRequest) returns (ConfigResponse);

  // Routing & NAT
  rpc GetRoutingTable() returns (RoutingTable);
  rpc GetNATMappings() returns (NATMappings);

  // Load balancing & failover
  rpc TriggerFailover(FailoverRequest) returns (FailoverResponse);
  rpc GetWANHealth() returns (WANHealthResponse);

  // Real-time metrics
  rpc StreamMetrics() returns (stream MetricsUpdate);
}
```

**Example Usage:**

```go
// Get WAN health status
healthResp := nicClient.GetWANHealth()
// Returns: WAN1: HEALTHY (12ms), WAN2: HEALTHY (18ms)

// Trigger manual failover
failoverResp := nicClient.TriggerFailover(FailoverRequest{
  from_wan: "Ethernet 1",
  to_wan: "Ethernet 2"
})
```

---

## 📊 Prometheus Metrics (Port 9154)

```
# WAN health status
nic_wan_status{interface="Ethernet 1"} 1  # 1=UP, 0=DOWN
nic_wan_status{interface="Ethernet 2"} 1

# WAN latency (milliseconds)
nic_wan_latency_ms{interface="Ethernet 1"} 12
nic_wan_latency_ms{interface="Ethernet 2"} 18

# Active NAT sessions
nic_nat_sessions_total 1523

# Traffic throughput (bytes/sec)
nic_interface_rx_bytes_per_sec{interface="Ethernet 1"} 987654321
nic_interface_tx_bytes_per_sec{interface="Ethernet 1"} 543210987

# Packet rate (packets/sec)
nic_interface_rx_packets_per_sec{interface="Ethernet 1"} 125000
nic_interface_tx_packets_per_sec{interface="Ethernet 1"} 98000

# Failover events
nic_failover_events_total 3
```

---

## 🔄 Integration with Other Services

### ➡️ Firewall Engine

```
NIC Management → Firewall Hooks (internal/integration/firewall_hooks.go)
• Passes packets through firewall inspection before routing
• Firewall returns: ACCEPT, DROP, or REJECT
```

### ➡️ DHCP Server

```
NIC Management → DHCP Integration (internal/configuration/dhcp_integration.go)
• Coordinates IP address assignment on LAN interfaces
• Reports gateway IP to DHCP for Option 3 (Router)
```

### ➡️ Network Logger

```
NIC Management → Logger Hooks (internal/integration/logger_hooks.go)
• Sends connection logs (new connections, closed connections)
• Logs NAT mappings for forensic analysis
```

---

## 🎯 Performance Characteristics

```
Single WAN Throughput:    1 Gbps
Dual WAN Throughput:      2 Gbps (aggregated)
Routing Engine Speed:     10 Gbps (line-rate, Rust)
NAT Translation Speed:    5 Gbps (Rust)
Max Concurrent Sessions:  1,000,000
Latency per Packet:       <1ms
CPU Usage (normal load):  40-60%
Memory Usage:             8 GB baseline + 2 GB per 100K sessions
```

---

## 📂 File Structure

```
src/nic_management/
├── internal/
│   ├── discovery/          # NIC detection & classification
│   ├── router/             # Packet routing (Rust)
│   ├── nat/                # NAT/NAPT translation
│   ├── loadbalancer/       # Multi-WAN load balancing
│   ├── failover/           # Automatic failover
│   ├── configuration/      # Interface configuration (IP, gateway, DNS)
│   ├── performance/        # Metrics & statistics
│   ├── integration/        # Hooks for firewall, IDS, logger
│   ├── grpc/               # gRPC service
│   └── rust_bridge/        # Rust FFI bindings
├── pkg/
│   ├── types/              # Go types
│   └── client/             # gRPC client library
├── cmd/
│   └── main.go             # Service entry point
├── Cargo.toml              # Rust dependencies
└── go.mod                  # Go dependencies
```

---

**End of NIC Management Diagram**
