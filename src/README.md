# SafeOps Source Code - Data Structures

> **Complete data structure reference for all SafeOps services and components**

---

## 📁 Directory Structure

```
src/
├── kernel_driver/          # Windows WFP/NDIS kernel driver
├── userspace_service/      # Windows service (log management)
├── shared/                 # Shared libraries (Rust, Go, C)
├── firewall_engine/        # Firewall rule engine (Rust)
├── threat_intel/           # Threat intelligence service (Rust)
├── ids_ips/                # Intrusion Detection/Prevention (Go)
├── dns_server/             # DNS filtering server (Go)
├── dhcp_server/            # DHCP service (Go)
├── tls_proxy/              # TLS interception proxy (Go)
├── wifi_ap/                # WiFi Access Point (Go)
├── orchestrator/           # Service orchestration (Go)
├── certificate_manager/    # Certificate management (Go)
├── backup_restore/         # Backup/restore service (Go)
├── update_manager/         # Update management (Go)
└── ui/                     # Web UI (Wails - Go + TypeScript)
```

---

## 🔧 Core Data Structures

### Shared Across All Services

#### Network Address Structures

```go
// src/shared/go/types/network.go

type IPAddress struct {
    Address    string    // "192.168.1.1" or "2001:db8::1"
    Version    int       // 4 or 6
    IsPrivate  bool
    IsLoopback bool
}

type NetworkEndpoint struct {
    IP   IPAddress
    Port uint16
}

type Connection struct {
    Source      NetworkEndpoint
    Destination NetworkEndpoint
    Protocol    Protocol  // TCP, UDP, ICMP
    State       ConnState
}

type Protocol uint8
const (
    ProtocolTCP  Protocol = 6
    ProtocolUDP  Protocol = 17
    ProtocolICMP Protocol = 1
)

type ConnState uint8
const (
    ConnStateNew         ConnState = 0
    ConnStateEstablished ConnState = 1
    ConnStateClosing     ConnState = 2
    ConnStateClosed      ConnState = 3
)
```

#### Firewall Rule Structure

```go
// src/shared/go/types/firewall.go

type FirewallRule struct {
    ID          uint32
    Name        string
    Description string
    Enabled     bool
    Priority    uint8       // 0=highest, 255=lowest
    
    // Match criteria
    Source      AddressMatch
    Destination AddressMatch
    Protocol    Protocol
    Direction   Direction
    
    // Action
    Action      Action      // BLOCK, ALLOW, INSPECT
    
    // Options
    LogMatches  bool
    RateLimit   *RateLimit
    Schedule    *TimeSchedule
    
    // Threat intel integration
    CheckThreatIntel bool
    MinThreatScore   int8  // -100 to 100
    
    // Statistics
    HitCount    uint64
    LastMatch   time.Time
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

type AddressMatch struct {
    IPRanges    []string  // CIDR notation
    Ports       []uint16  // Port list
    PortRanges  [][2]uint16  // Start-end port ranges
}

type Action uint8
const (
    ActionBlock   Action = 0
    ActionAllow   Action = 1
    ActionInspect Action = 2
    ActionLog     Action = 3
)

type Direction uint8
const (
    DirectionAny      Direction = 0
    DirectionInbound  Direction = 1
    DirectionOutbound Direction = 2
)

type RateLimit struct {
    PacketsPerSecond uint32
    BytesPerSecond   uint64
    BurstSize        uint32
}

type TimeSchedule struct {
    DaysOfWeek  []time.Weekday
    StartTime   time.Time
    EndTime     time.Time
    ValidFrom   time.Time
    ValidUntil  time.Time
}
```

#### Threat Intelligence Structures

```rust
// src/shared/rust/src/threat.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub reputation_score: i8,  // -100 to 100
    pub confidence: f32,        // 0.0 to 1.0
    pub severity: Severity,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source_feeds: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    Mutex,
    RegistryKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone)]
pub struct IPReputation {
    pub ip: IpAddr,
    pub score: i8,
    pub confidence: f32,
    pub category: ThreatCategory,
    pub geolocation: Option<GeoLocation>,
    pub asn: Option<u32>,
    pub is_proxy: bool,
    pub is_vpn: bool,
    pub is_tor: bool,
}

#[derive(Debug, Clone)]
pub struct DomainReputation {
    pub domain: String,
    pub score: i8,
    pub confidence: f32,
    pub category: ThreatCategory,
    pub dga_score: f32,  // Domain Generation Algorithm probability
    pub age_days: Option<u32>,
    pub has_ssl: bool,
}

#[derive(Debug, Clone)]
pub struct HashReputation {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub score: i8,
    pub confidence: f32,
    pub malware_family: Option<String>,
    pub file_type: Option<String>,
}
```

#### Packet Metadata

```c
// src/shared/c/packet_structs.h

typedef struct _PACKET_INFO {
    // Network layer
    uint8_t  ip_version;        // 4 or 6
    uint32_t src_ip;            // IPv4 (network byte order)
    uint32_t dst_ip;            // IPv4
    uint8_t  src_ipv6[16];      // IPv6
    uint8_t  dst_ipv6[16];      // IPv6
    
    // Transport layer
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;          // TCP=6, UDP=17
    
    // Metadata
    uint64_t timestamp_ns;      // Nanosecond timestamp
    uint32_t packet_size;       // Total packet size
    uint16_t payload_size;      // Payload data size
    uint8_t  direction;         // 0=inbound, 1=outbound
    
    // Classification
    uint32_t flow_id;           // Connection flow ID
    uint32_t process_id;        // Owning process
    uint8_t  threat_level;      // 0-100
    uint32_t rule_id;           // Matching firewall rule
    uint8_t  action;            // 0=PERMIT, 1=BLOCK
    
} PACKET_INFO;
```

---

## 📊 Service-Specific Structures

### Kernel Driver

See: [src/kernel_driver/README.md](kernel_driver/README.md)

**Key Structures:**
- `PACKET_METADATA` - Complete packet information
- `CONNECTION_ENTRY` - Connection tracking
- `FIREWALL_RULE` - Kernel-mode rule representation
- `RING_BUFFER` - Lock-free kernel-user communication

### Firewall Engine (Rust)

See: [src/firewall_engine/README.md](firewall_engine/README.md)

**Key Structures:**
- `RuleEngine` - Rule matching and evaluation
- `ConnectionTracker` - Stateful connection tracking
- `NATTable` - Network Address Translation
- `DDosProtection` - DDoS mitigation

### Threat Intelligence (Rust)

See: [src/threat_intel/README.md](threat_intel/README.md)

**Key Structures:**
- `FeedManager` - Threat feed orchestration
- `ReputationCache` - LRU reputation cache
- `IOCStorage` - Indicator of Compromise storage
- `ThreatScore` - Threat scoring algorithm

### IDS/IPS (Go)

See: [src/ids_ips/README.md](ids_ips/README.md)

**Key Structures:**
- `Signature` - Attack signature definitions
- `Alert` - Security alert structure
- `AnomalyDetector` - Statistical anomaly detection
- `ProtocolAnalyzer` - Protocol dissection

---

## 🔄 Inter-Service Communication

### gRPC Message Flow

```
┌──────────────┐       ┌─────────────────┐       ┌──────────────┐
│ Kernel       │──────▶│ Firewall Engine │──────▶│ Threat Intel │
│ Driver       │◀──────│ (Rule Engine)   │◀──────│ (Reputation) │
└──────────────┘       └─────────────────┘       └──────────────┘
       │                       │                         │
       │                       ▼                         ▼
       │               ┌──────────────┐         ┌──────────────┐
       └──────────────▶│ IDS/IPS      │         │ Database     │
                       │ (Signatures) │         │ (PostgreSQL) │
                       └──────────────┘         └──────────────┘
```

### Shared Memory Structures

```c
// Ring buffer for kernel → userspace
typedef struct _RING_BUFFER {
    struct {
        uint32_t magic;              // 0x53414645
        uint64_t write_index;        // Atomic, producer
        uint64_t read_index;         // Atomic, consumer
        uint64_t total_written;
        uint64_t total_read;
        uint64_t drops;
    } header;
    
    PACKET_INFO entries[RING_SIZE];  // 16MB total
    
} RING_BUFFER;
```

---

## 🚀 Performance Characteristics

### Memory Layout

| Structure | Size | Alignment | Cache Line |
|-----------|------|-----------|------------|
| `PACKET_INFO` | 512 bytes | 64 bytes | Yes |
| `CONNECTION_ENTRY` | 256 bytes | 64 bytes | Yes |
| `FirewallRule` (Go) | ~200 bytes | 8 bytes | No |
| `ThreatIndicator` (Rust) | ~150 bytes | 8 bytes | No |

### Throughput Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Packet processing | 1M pps | Kernel driver |
| Rule evaluation | 100K rps | Firewall engine |
| Reputation lookup | 500K qps | In-memory cache |
| Database query | 100K qps | PostgreSQL with PgBouncer |
| IDS signature match | 10K pps | Deep packet inspection |

---

## 📝 Type Conventions

### Naming

- **C**: `snake_case` for variables, `UPPER_CASE` for constants
- **Go**: `PascalCase` for exported, `camelCase` for private
- **Rust**: `snake_case` for everything except types (`PascalCase`)

### Sizes

- Use fixed-size types: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`
- Network byte order for wire protocols (big-endian)
- Host byte order for internal structures (little-endian on x86)

### Timestamps

- **C kernel**: 100-nanosecond intervals since epoch
- **Go**: `time.Time` (UTC)
- **Rust**: `chrono::DateTime<Utc>`
- **Database**: `TIMESTAMP WITH TIME ZONE`

---

## 🔗 Cross-References

- [Database Structures](../database/DATA_DICTIONARY.md)
- [Protocol Buffers](../proto/README.md)
- [Configuration Schemas](../config/README.md)
- [Complete Data Structures](../DATA_STRUCTURES.md)

---

**Version:** 2.0.0  
**Last Updated:** 2025-12-17
