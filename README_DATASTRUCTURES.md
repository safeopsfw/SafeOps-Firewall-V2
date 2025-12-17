# SafeOps v2.0 - Complete Data Structure Index

> **Central index for all data structure documentation across the SafeOps project**
>
> Last Updated: 2025-12-17 | Version: 2.0.0

---

## 📚 Documentation Map

This document serves as the master index for all data structure documentation throughout the SafeOps v2.0 project.

---

## 🗂️ Core Documentation Files

### 1. **Master Data Structures Reference**
📄 [DATA_STRUCTURES.md](./DATA_STRUCTURES.md)

**Comprehensive reference covering:**
- Database structures (52 tables)
- Kernel driver structures
- Network protocol structures  
- Configuration structures
- gRPC message structures
- Performance structures
- Quick reference tables

**Use this when:** You need a complete overview of all data structures in one place.

---

### 2. **Database Data Dictionary**
📄 [database/DATA_DICTIONARY.md](./database/DATA_DICTIONARY.md)

**In-depth database documentation:**
- Complete table schemas (all columns, types, constraints)
- Relationship diagrams
- 147 indexes with types and purposes
- Query patterns with performance benchmarks
- Optimization tips and anti-patterns

**Use this when:** Working with PostgreSQL database, writing queries, or optimizing performance.

---

### 3. **Database Quick Reference**
📄 [database/README.md](./database/README.md)

**Quick start guide:**
- Overview and key features
- Installation instructions
- Usage examples
- Maintenance procedures
- Backup/recovery

**Use this when:** Setting up the database or performing routine operations.

---

## 📁 Directory-Specific Documentation

### Source Code (`src/`)

#### 🔹 **Source Overview**
📄 [src/README.md](./src/README.md)

**Covers:**
- Directory structure
- Shared data structures (Go, Rust, C)
- Service-specific overviews
- Inter-service communication
- Performance characteristics

---

#### 🔹 **Kernel Driver**
📄 [src/kernel_driver/README.md](./src/kernel_driver/README.md)

**Kernel-mode structures:**
- `PACKET_METADATA` (512 bytes) - Complete packet information
- `RING_BUFFER` (16 MB) - Lock-free kernel→userspace communication
- `CONNECTION_ENTRY` (192 bytes) - Connection tracking
- `FIREWALL_RULE` (1024 bytes) - Kernel-mode firewall rules
- `PERFORMANCE_STATS` (512 bytes) - Performance metrics
- Memory management and pool allocations
- TCP state machine
- Lock-free algorithms

**Use this when:** Working on kernel driver, debugging packet processing, or optimizing performance.

---

#### 🔹 **Shared Libraries**
📄 [src/shared/README.md](./src/shared/README.md)

**Common utilities:**
- Rust shared library (performance-critical)
- Go shared library (service utilities)
- C headers (kernel compatibility)
- Type definitions
- Error handling
- Logging frameworks

**Use this when:** Using shared code across multiple services.

---

### Configuration (`config/`)

#### 🔹 **Configuration Structures**
📄 [config/README_STRUCTURES.md](./config/README_STRUCTURES.md)

**Configuration schemas:**
- TOML master configuration
- YAML firewall rules
- Network topology
- JSON schema validation
- Template examples

**Use this when:** Configuring services or creating new configuration files.

---

### Protocol Buffers (`proto/`)

#### 🔹 **gRPC Service Definitions**
📄 [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md)

**Protocol definitions:**
- Firewall service messages
- Threat intelligence service
- Network manager service
- Message flow diagrams
- Generated code structure

**Use this when:** Implementing gRPC clients/servers or extending API.

---

## 🎯 Find Documentation By Topic

### By Data Type

| Data Type | Primary Documentation | Additional References |
|-----------|----------------------|----------------------|
| **IP Addresses** | [database/DATA_DICTIONARY.md#ip-reputation](./database/DATA_DICTIONARY.md) | [src/kernel_driver/README.md](./src/kernel_driver/README.md) |
| **Domain Names** | [database/DATA_DICTIONARY.md#domain-reputation](./database/DATA_DICTIONARY.md) | [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) |
| **File Hashes** | [database/DATA_DICTIONARY.md#hash-reputation](./database/DATA_DICTIONARY.md) | - |
| **IOC Indicators** | [database/DATA_DICTIONARY.md#ioc-indicators](./database/DATA_DICTIONARY.md) | - |
| **Firewall Rules** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) | [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) |
| **Packet Metadata** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) | [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) |
| **Connections** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) | [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) |
| **Configuration** | [config/README_STRUCTURES.md](./config/README_STRUCTURES.md) | [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) |

### By Technology

| Technology | Documentation |
|------------|---------------|
| **PostgreSQL** | [database/DATA_DICTIONARY.md](./database/DATA_DICTIONARY.md) |
| **C (Kernel)** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) |
| **Rust** | [src/shared/README.md](./src/shared/README.md), [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) |
| **Go** | [src/shared/README.md](./src/shared/README.md), [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) |
| **Protocol Buffers** | [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) |
| **TOML/YAML** | [config/README_STRUCTURES.md](./config/README_STRUCTURES.md) |

### By Use Case

| Use Case | Start Here |
|----------|------------|
| **Setting up database** | [database/README.md](./database/README.md) |
| **Understanding packet flow** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) |
| **Writing firewall rules** | [config/README_STRUCTURES.md](./config/README_STRUCTURES.md) |
| **Querying threat data** | [database/DATA_DICTIONARY.md](./database/DATA_DICTIONARY.md) |
| **Implementing gRPC service** | [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) |
| **Performance tuning** | [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) |
| **Debugging kernel driver** | [src/kernel_driver/README.md](./src/kernel_driver/README.md) |

---

## 📊 Quick Statistics

### Database
- **Tables:** 52 total
  - 6 core reputation tables
  - 15+ supporting tables
  - 5 partitioned tables
- **Indexes:** 147
- **Expected Rows:** 100M+ (IP), 50M+ (domains), 10M+ (hashes)
- **Expected Size:** ~60 GB total

### Kernel Driver
- **Structures:** 5 primary
- **Ring Buffer:** 16 MB (32,768 entries)
- **Packet Metadata:** 512 bytes per packet
- **Connection Entry:** 192 bytes per connection
- **Max Connections:** 1M concurrent

### Services
- **Total Services:** 14 microservices
- **Languages:** C (kernel), Rust (firewall, threat intel), Go (11 services)
- **gRPC Services:** 10+
- **Configuration Files:** 44

---

## 🔍 Structure Size Reference

### Memory Structures (Kernel)

| Structure | Size | Alignment | Usage |
|-----------|------|-----------|-------|
| `PACKET_METADATA` | 512 bytes | 64 bytes | Per packet |
| `CONNECTION_ENTRY` | 192 bytes | 64 bytes | Per connection |
| `FIREWALL_RULE` | 1024 bytes | 1024 bytes | Per rule |
| `PERFORMANCE_STATS` | 512 bytes | 64 bytes | Global singleton |
| `RING_BUFFER_HEADER` | 512 bytes | 64 bytes | Shared memory |

### Database Row Sizes (Average)

| Table | Row Size | Indexes | Partitioned |
|-------|----------|---------|-------------|
| `ip_reputation` | ~250 bytes | 8 | Yes (7 partitions) |
| `domain_reputation` | ~400 bytes | 9 | No |
| `hash_reputation` | ~600 bytes | 7 | No |
| `ioc_indicators` | ~500 bytes | 8 | Yes (5 partitions) |
| `threat_feeds` | ~800 bytes | 3 | No |
| `geolocation_data` | ~200 bytes | 2 | Yes (7 partitions) |

---

## 🚀 Performance Targets

### Kernel Driver
- **Packet Processing:** 1M packets/second
- **Latency:** <10 μs (P99)
- **CPU Usage:** <25% @ 500K pps
- **Memory:** 192 bytes/connection

### Database
- **IP Lookup:** <1 ms (exact match)
- **Domain Lookup:** <1 ms (case-insensitive)
- **Fuzzy Search:** <100 ms (trigram)
- **Aggregation:** <500 ms (100M rows)

### Services
- **gRPC Latency:** <5 ms (P99)
- **Throughput:** 100K requests/second
- **Cache Hit Rate:** >95%

---

## 📝 Naming Conventions

### C (Kernel)
```c
typedef struct _PACKET_METADATA {  // PascalCase with _prefix
    UINT64 PacketId;               // PascalCase fields
    UINT32 process_id;             // or snake_case (mixed)
} PACKET_METADATA, *PPACKET_METADATA;

#define MAX_BUFFER_SIZE 1024       // UPPER_CASE constants
```

### Go
```go
type FirewallRule struct {         // PascalCase (exported)
    ID       uint32                // PascalCase fields
    Name     string
}

type connectionEntry struct {      // camelCase (private)
    flowID   uint64
}
```

### Rust
```rust
pub struct ThreatIndicator {      // PascalCase types
    pub indicator_type: IndicatorType,  // snake_case fields
    pub value: String,
}

const MAX_ENTRIES: usize = 1000;  // UPPER_CASE constants
```

### SQL
```sql
CREATE TABLE ip_reputation (      -- snake_case tables
    ip_id BIGSERIAL PRIMARY KEY,  -- snake_case columns
    reputation_score INTEGER
);
```

---

## 🔗 External Resources

### Windows API Documentation
- [WFP (Windows Filtering Platform)](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [NDIS (Network Driver Interface Specification)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-drivers)
- [Kernel Mode Driver Framework](https://docs.microsoft.com/en-us/windows-hardware/drivers/wdf/)

### Database Documentation
- [PostgreSQL 16 Documentation](https://www.postgresql.org/docs/16/)
- [pgx Go Driver](https://github.com/jackc/pgx)
- [PgBouncer](https://www.pgbouncer.org/)

### Protocol Buffers
- [Protocol Buffers Language Guide](https://developers.google.com/protocol-buffers/docs/proto3)
- [gRPC Documentation](https://grpc.io/docs/)

---

## 📂 File Organization

```
SafeOps/
│
├── DATA_STRUCTURES.md              ← Master reference (this file's companion)
├── README_DATASTRUCTURES.md        ← This index file
│
├── database/
│   ├── README.md                   ← Quick start
│   └── DATA_DICTIONARY.md          ← Complete schemas
│
├── src/
│   ├── README.md                   ← Source overview
│   ├── kernel_driver/
│   │   └── README.md               ← Kernel structures
│   └── shared/
│       └── README.md               ← Shared libraries
│
├── config/
│   └── README_STRUCTURES.md        ← Configuration schemas
│
└── proto/
    └── README_STRUCTURES.md        ← gRPC definitions
```

---

## 🎓 Learning Path

### For New Developers

1. **Start:** [README.md](./README.md) - Project overview
2. **Architecture:** [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) - Complete picture
3. **Database:** [database/README.md](./database/README.md) - Setup and basics
4. **Code:** [src/README.md](./src/README.md) - Service overview
5. **Deep Dive:** Component-specific READMEs

### For Database Administrators

1. [database/README.md](./database/README.md) - Setup
2. [database/DATA_DICTIONARY.md](./database/DATA_DICTIONARY.md) - Schema reference
3. [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) - Database section

### For Kernel Developers

1. [src/kernel_driver/README.md](./src/kernel_driver/README.md) - Structures
2. [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) - Kernel section
3. Microsoft WFP/NDIS documentation

### For Service Developers

1. [src/README.md](./src/README.md) - Overview
2. [proto/README_STRUCTURES.md](./proto/README_STRUCTURES.md) - gRPC
3. [config/README_STRUCTURES.md](./config/README_STRUCTURES.md) - Configuration
4. [src/shared/README.md](./src/shared/README.md) - Utilities

---

## 🔄 Document Maintenance

### Update Frequency
- **Master documents:** Updated with each major release
- **Directory READMEs:** Updated when structures change
- **This index:** Updated monthly or when new docs are added

### Contributing
When adding new structures:
1. Add detailed documentation to appropriate README
2. Add entry to [DATA_STRUCTURES.md](./DATA_STRUCTURES.md)
3. Update this index with cross-references
4. Add to relevant topic tables above

---

## ✅ Documentation Completeness

| Component | README | Data Structures | Examples | Status |
|-----------|--------|-----------------|----------|--------|
| Database | ✅ Yes | ✅ Complete | ✅ Yes | 100% |
| Kernel Driver | ✅ Yes | ✅ Complete | 🔄 Partial | 90% |
| Shared Libraries | ✅ Yes | 🔄 Partial | ⏳ Planned | 60% |
| Configuration | ✅ Yes | ✅ Complete | ✅ Yes | 100% |
| Protocol Buffers | ✅ Yes | ✅ Complete | 🔄 Partial | 80% |
| Services | 🔄 Partial | ⏳ Planned | ⏳ Planned | 30% |

**Legend:**
- ✅ Complete
- 🔄 In Progress
- ⏳ Planned

---

## 📞 Support

For questions about data structures:
1. Check this index for relevant documentation
2. Review the specific README for your component
3. Consult [DATA_STRUCTURES.md](./DATA_STRUCTURES.md) for comprehensive reference
4. Review code comments in source files

---

**Document Version:** 2.0.0  
**Last Updated:** 2025-12-17  
**Maintained By:** SafeOps Development Team  
**Next Review:** 2025-01-17
