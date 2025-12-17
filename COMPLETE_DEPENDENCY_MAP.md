# SafeOps v2.0 - Complete File-by-File Dependency Map
## Proto → Compiled → Config → src/shared

> **RAW vs COMPILED clearly marked**  
> Flow: Definitions → Generated Code → Runtime Config → Shared Libraries
>
> Total Files: 69 | Generated: 2025-12-17

---

## 📊 File Count & Usage Type

| Component | Files | Usage Type | Build Output |
|-----------|-------|------------|--------------|
| **proto/grpc/** | 14 | 🔧 RAW → GENERATES | → .pb.go + .rs |
| **build/proto/go/** | 14 | ⚙️ COMPILED | Go packages |
| **build/proto/rust/** | 14 | ⚙️ COMPILED | Rust modules |
| **config/** | 44 | 📄 RAW (runtime) | Loaded at startup |
| **src/shared/c/** | 4 | 📄 RAW (headers) | #include'd |
| **src/shared/go/** | 38 | ⚙️ COMPILED | Go packages |
| **src/shared/rust/** | 13 | ⚙️ COMPILED | .rlib library |

**Legend:**
- 🔧 **GENERATES** = Source files compiled to other code
- ⚙️ **COMPILED** = Code compiled into binary/library
- 📄 **RAW** = Used as-is at compile-time or runtime

---

## LEVEL 0: Pure Definitions (Zero Dependencies)

### 📄 proto/grpc/common.proto

```yaml
FILE: proto/grpc/common.proto
LEVEL: 0 (Foundation - no SafeOps deps)
USAGE: 🔧 GENERATES CODE (protoc compiles to Go + Rust)
SIZE: ~100 lines

PURPOSE:
  Base message types for ALL 13 SafeOps gRPC services. Every other proto
  file imports this for Timestamp, Status, Metadata, Pagination, Error types.

CONTAINS:
  message Timestamp { int64 seconds; int32 nanos; }
  message Status { 
    enum Code { OK=0; ERROR=1; NOT_FOUND=2; ... }
    Code code; string message; 
  }
  message Metadata { string request_id; Timestamp timestamp; ... }
  message Pagination { int32 page; int32 page_size; int64 total; }
  message Error { string code; string message; repeated string stack_trace; }

DEPENDENCIES:
  External: google/protobuf/* (stdlib)
  SafeOps: NONE

GENERATES (Build Output):
  ⚙️ build/proto/go/common.pb.go (~500 lines)
     - Go structs with Marshal/Unmarshal methods
     - Used by: ALL Go services
  
  ⚙️ build/proto/rust/common.rs (~400 lines)
     - Rust structs with prost encoding
     - Used by: firewall_engine, threat_intel

IMPORTED BY (13 proto files depend on this):
  ✅ firewall.proto
  ✅ threat_intel.proto
  ✅ network_manager.proto
  ✅ network_logger.proto
  ✅ ids_ips.proto
  ✅ dns_server.proto
  ✅ dhcp_server.proto
  ✅ tls_proxy.proto
  ✅ wifi_ap.proto
  ✅ orchestrator.proto
  ✅ certificate_manager.proto
  ✅ backup_restore.proto
  ✅ update_manager.proto

BUILD COMMAND:
  cd proto && .\build.ps1
  Output: build\proto\go\common.pb.go + build\proto\rust\common.rs

VERIFICATION:
  protoc --version  # Need 3.19+
  ls build/proto/go/common.pb.go
  ls build/proto/rust/common.rs
```

---

## LEVEL 1: Proto Files (All Import common.proto)

### 📄 proto/grpc/firewall.proto

```yaml
FILE: proto/grpc/firewall.proto
LEVEL: 1 (depends on common.proto)
USAGE: 🔧 GENERATES CODE
SIZE: ~300 lines

PURPOSE:
  Firewall engine gRPC API. Rule CRUD, packet inspection, stats.

CONTAINS:
  service FirewallService {
    rpc AddRule(AddRuleRequest) returns (AddRuleResponse);
    rpc DeleteRule(DeleteRuleRequest) returns (DeleteRuleResponse);
    rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
    rpc GetStats(GetStatsRequest) returns (GetStatsResponse);
    rpc GetConnections(GetConnectionsRequest) returns (GetConnectionsResponse);
  }
  
  message FirewallRule {
    uint32 rule_id;
    string name;
    RuleAction action;  // ALLOW, DENY, DROP
    string source_cidr;
    string dest_cidr;
    PortRange source_ports;
    PortRange dest_ports;
    Protocol protocol;  // TCP, UDP, ICMP, ANY
    int32 priority;
    bool enabled;
    Metadata metadata;  // From common.proto
  }

DEPENDENCIES:
  ✅ common.proto (import "common.proto")

GENERATES:
  ⚙️ build/proto/go/firewall.pb.go (structs)
  ⚙️ build/proto/go/firewall_grpc.pb.go (gRPC client/server)
  ⚙️ build/proto/rust/firewall.rs

USED BY (COMPILED into):
  ⚙️ src/firewall_engine/ (future - Rust, implements FirewallService)
  ⚙️ src/orchestrator/ (future - Go, gRPC client to firewall)
```

### 📄 proto/grpc/threat_intel.proto

```yaml
FILE: proto/grpc/threat_intel.proto
LEVEL: 1
USAGE: 🔧 GENERATES CODE
SIZE: ~350 lines

PURPOSE:
  Threat intelligence API. IP/domain/hash reputation, IOC lookups.

CONTAINS:
  service ThreatIntelService {
    rpc CheckIPReputation(CheckIPRequest) returns (ReputationResponse);
    rpc CheckDomainReputation(CheckDomainRequest) returns (ReputationResponse);
    rpc CheckHashReputation(CheckHashRequest) returns (ReputationResponse);
    rpc SearchIOCs(SearchIOCsRequest) returns (SearchIOCsResponse);
    rpc UpdateFeed(UpdateFeedRequest) returns (Status);
  }
  
  message ReputationResponse {
    ThreatLevel level;  // SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
    int32 confidence_score;  // 0-100
    repeated ThreatSource sources;
    repeated IOC related_iocs;
    Timestamp last_seen;
  }

DEPENDENCIES:
  ✅ common.proto

GENERATES:
  ⚙️ build/proto/go/threat_intel.pb.go
  ⚙️ build/proto/rust/threat_intel.rs

USED BY:
  ⚙️ src/threat_intel/ (Rust - implements service)
  ⚙️ src/firewall_engine/ (calls for IP reputation before allowing)
  ⚙️ src/ids_ips/ (calls for signature matching)
  ⚙️ src/dns_server/ (calls for domain reputation)
```

### 📄 proto/grpc/dns_server.proto

```yaml
FILE: proto/grpc/dns_server.proto
LEVEL: 1
USAGE: 🔧 GENERATES
SIZE: ~400 lines

CONTAINS:
  service DNSService {
    rpc Query(DNSQueryRequest) returns (DNSQueryResponse);
    rpc AddRecord(AddRecordRequest) returns (Status);
    rpc DeleteRecord(DeleteRecordRequest) returns (Status);
    rpc GetBlocklist(GetBlocklistRequest) returns (BlocklistResponse);
  }

DEPENDENCIES:
  ✅ common.proto

GENERATES:
  ⚙️ build/proto/go/dns_server.pb.go
  ⚙️ build/proto/go/dns_server_grpc.pb.go

USED BY:
  ⚙️ src/dns_server/ (Go - implements DNSService)
```

### 📄 proto/grpc/dhcp_server.proto, ids_ips.proto, network_logger.proto, network_manager.proto, tls_proxy.proto, wifi_ap.proto, orchestrator.proto, certificate_manager.proto, backup_restore.proto, update_manager.proto

```yaml
All follow same pattern:
  - Import common.proto
  - Define service with RPCs
  - Define request/response messages
  - Generate .pb.go and .rs files
  - Used by corresponding src/ service (future implementation)
```

---

## LEVEL 2: Compiled Proto Code (Generated from Level 1)

### ⚙️ build/proto/go/common.pb.go

```yaml
FILE: build/proto/go/common.pb.go
TYPE: Generated Go Code
LEVEL: 2 (generated from common.proto)
USAGE: ⚙️ COMPILED into Go binaries
SIZE: ~500 lines
SOURCE: proto/grpc/common.proto

CONTAINS:
  type Timestamp struct {
      state         protoimpl.MessageState
      sizeCache     protoimpl.SizeCache
      unknownFields protoimpl.UnknownFields
      
      Seconds int64 `protobuf:"varint,1,opt,name=seconds,proto3" json:"seconds,omitempty"`
      Nanos   int32 `protobuf:"varint,2,opt,name=nanos,proto3" json:"nanos,omitempty"`
  }
  
  func (x *Timestamp) ProtoReflect() protoreflect.Message { ... }
  func (x *Timestamp) Marshal() ([]byte, error) { ... }
  func (x *Timestamp) Unmarshal(b []byte) error { ... }

DEPENDENCIES:
  google.golang.org/protobuf/proto
  google.golang.org/protobuf/reflect/protoreflect
  google.golang.org/protobuf/runtime/protoimpl

REQUIRED BY (COMPILED into):
  ⚙️ build/proto/go/firewall.pb.go (imports this)
  ⚙️ build/proto/go/threat_intel.pb.go
  ⚙️ build/proto/go/dns_server.pb.go
  ⚙️ All other generated Go proto files
  ⚙️ Future Go services (import "github.com/safeops/proto/go")

USAGE IN SERVICES:
  import pb "github.com/safeops/proto/go"
  timestamp := &pb.Timestamp{Seconds: time.Now().Unix()}
```

### ⚙️ build/proto/go/firewall.pb.go

```yaml
FILE: build/proto/go/firewall.pb.go
USAGE: ⚙️ COMPILED
SOURCE: firewall.proto

CONTAINS:
  type FirewallRule struct { ... }
  type AddRuleRequest struct { ... }
  type AddRuleResponse struct { ... }
  // All message types from firewall.proto

DEPENDENCIES:
  ✅ common.pb.go

COMPILED INTO:
  ⚙️ src/orchestrator/ (gRPC client calls firewall)
```

### ⚙️ build/proto/rust/common.rs

```yaml
FILE: build/proto/rust/common.rs
USAGE: ⚙️ COMPILED
SOURCE: common.proto
SIZE: ~400 lines

CONTAINS:
  #[allow(clippy::derive_partial_eq_without_eq)]
  #[derive(Clone, PartialEq, ::prost::Message)]
  pub struct Timestamp {
      #[prost(int64, tag = "1")]
      pub seconds: i64,
      #[prost(int32, tag = "2")]
      pub nanos: i32,
  }
  
  impl ::prost::Name for Timestamp { ... }

DEPENDENCIES:
  prost::Message
  prost::Name

COMPILED INTO:
  ⚙️ build/proto/rust/firewall.rs
  ⚙️ build/proto/rust/threat_intel.rs
  ⚙️ src/firewall_engine/ (links as dependency)
  ⚙️ src/threat_intel/ (links as dependency)
```

---

## LEVEL 3: Configuration Files (Runtime RAW usage)

### 📄 config/templates/dns.toml

```yaml
FILE: config/templates/dns.toml
LEVEL: 3
USAGE: 📄 RAW (loaded at runtime by dns_server)
SIZE: ~150 lines

PURPOSE:
  DNS server configuration template. Copied to /etc/safeops/dns.toml.

CONTAINS:
  [server]
  listen_address = "0.0.0.0"
  listen_port = 53
  protocol = "udp+tcp"
  
  [upstream]
  servers = ["1.1.1.1", "8.8.8.8"]
  timeout_ms = 2000
  
  [caching]
  enabled = true
  max_entries = 10000
  ttl_override_sec = 300
  
  [filtering]
  blocklist_enabled = true
  blocklist_path = "C:\\SafeOps\\data\\dns_blocklist.txt"
  
  [logging]
  level = "info"
  format = "json"

DEPENDENCIES:
  None (root level config)

LOADED BY (RAW at runtime):
  📄 src/dns_server/main.go calls config.Load("/etc/safeops/dns.toml")
  
  Code: cfg, err := config.Load("/etc/safeops/dns.toml")
        server := NewDNSServer(cfg)
```

### 📄 config/templates/firewall.toml

```yaml
FILE: config/templates/firewall.toml
USAGE: 📄 RAW (runtime)

CONTAINS:
  [firewall]
  default_action = "drop"
  log_all_packets = false
  
  [performance]
  ring_buffer_size_mb = 16
  max_connections = 1000000

LOADED BY:
  📄 src/firewall_engine/main.rs loads this via config crate
```

### 📄 config/templates/*.toml (40+ more files)

```yaml
All follow pattern:
  - TOML format configuration
  - 📄 RAW runtime usage
  - Loaded by corresponding service
  - No build step required
```

---

## LEVEL 4: src/shared/c/ (RAW Headers)

### 📄 src/shared/c/shared_constants.h

```yaml
FILE: src/shared/c/shared_constants.h
LEVEL: 4 (no SafeOps deps, but after proto/config conceptually)
USAGE: 📄 RAW (#include in C code)
SIZE: ~150 lines

PURPOSE:
  Compile-time constants for C components.

CONTAINS:
  #define RING_BUFFER_SIZE (16 * 1024 * 1024)
  #define RING_BUFFER_MAGIC 0x53414645
  #define MAX_PACKET_SIZE 65536
  #define MAX_CONNECTIONS 1000000
  #define IOCTL_TIMEOUT_MS 5000

DEPENDENCIES:
  <stdint.h> (external stdlib)

REQUIRED BY (RAW #include):
  📄 packet_structs.h (#include "shared_constants.h")
  📄 ring_buffer.h
  📄 ioctl_codes.h
  ❌ kernel_driver/*.c (future)
  ❌ userspace_service/*.c (future)

CROSS-LANGUAGE:
  When Rust/Go need constants:
    - Rust: bindgen generates Rust constants from this
    - Go: import "C" exposes as C.RING_BUFFER_SIZE
```

### 📄 src/shared/c/packet_structs.h

```yaml
FILE: src/shared/c/packet_structs.h
USAGE: 📄 RAW
SIZE: ~280 lines

CONTAINS:
  typedef struct _PACKET_INFO {
      uint64_t packet_id;
      uint64_t timestamp_ns;
      uint32_t src_ip;
      uint32_t dst_ip;
      uint16_t src_port;
      uint16_t dst_port;
      uint8_t protocol;
      uint8_t action;
      // ... 512 bytes total
  } __attribute__((packed, aligned(512))) PACKET_INFO;

DEPENDENCIES:
  📄 shared_constants.h

REQUIRED BY:
  📄 ring_buffer.h (RING_BUFFER contains PACKET_INFO array)
```

### 📄 src/shared/c/ring_buffer.h

```yaml
FILE: src/shared/c/ring_buffer.h
USAGE: 📄 RAW (inline functions)
SIZE: ~200 lines

CONTAINS:
  typedef struct _RING_BUFFER {
      RING_BUFFER_HEADER header;
      PACKET_INFO entries[32768];
  } RING_BUFFER;
  
  static inline BOOLEAN RingBuffer_Write(...) { ... }
  static inline BOOLEAN RingBuffer_Read(...) { ... }

DEPENDENCIES:
  📄 shared_constants.h
  📄 packet_structs.h
```

### 📄 src/shared/c/ioctl_codes.h

```yaml
FILE: src/shared/c/ioctl_codes.h
USAGE: 📄 RAW

CONTAINS:
  #define IOCTL_SAFEOPS_ADD_RULE CTL_CODE(...)
  #define SAFEOPS_DEVICE_NAME L"\\\\.\\SafeOpsFirewall"

DEPENDENCIES:
  📄 shared_constants.h
```

---

## LEVEL 5: src/shared/go/ (COMPILED Go Packages)

### PACKAGE: errors/ (3 files)

#### ⚙️ src/shared/go/errors/codes.go

```yaml
FILE: src/shared/go/errors/codes.go
PACKAGE: errors
USAGE: ⚙️ COMPILED into Go binaries
SIZE: ~300 lines
LEVEL: 5a (Foundation Go package)

CONTAINS:
  const (
      ErrConfigLoadFailed = "CONFIG_LOAD_FAILED"
      ErrDBConnectionFailed = "DB_CONNECTION_FAILED"
      ErrRedisConnectionFailed = "REDIS_CONNECTION_FAILED"
      ErrGRPCCallFailed = "GRPC_CALL_FAILED"
      // ... 50+ error codes
  )

DEPENDENCIES:
  None (constants only)

COMPILED INTO:
  ⚙️ errors.go (uses these constants)
  ⚙️ ALL Go packages (import ".../ errors", get error codes)
  ⚙️ Future Go services

USAGE IN CODE:
  return errors.New(errors.ErrDBConnectionFailed, "Could not connect")
```

#### ⚙️ src/shared/go/errors/errors.go

```yaml
FILE: src/shared/go/errors/errors.go
USAGE: ⚙️ COMPILED
SIZE: ~400 lines

CONTAINS:
  type SafeOpsError struct {
      Code      string
      Message   string
      Fields    map[string]interface{}
      Cause     error
      Stack     []string
      Timestamp time.Time
  }
  
  func New(code, message string) *SafeOpsError
  func Wrap(err error, code, message string) *SafeOpsError

DEPENDENCIES:
  ⚙️ codes.go
  External: github.com/pkg/errors

COMPILED INTO:
  ⚙️ ALL Go packages
```

#### ⚙️ src/shared/go/errors/wrapping.go

```yaml
FILE: src/shared/go/errors/wrapping.go
USAGE: ⚙️ COMPILED

CONTAINS:
  func UnwrapAll(err error) []error
  func HasCode(err error, code string) bool

DEPENDENCIES:
  ⚙️ errors.go
```

---

### PACKAGE: config/ (5 files)

#### ⚙️ src/shared/go/config/config.go

```yaml
FILE: src/shared/go/config/config.go
PACKAGE: config
USAGE: ⚙️ COMPILED
SIZE: ~400 lines
LEVEL: 5b (depends on errors/)

CONTAINS:
  type Config struct {
      viper    *viper.Viper
      filePath string
  }
  
  func Load(configPath string) (*Config, error)
  func (c *Config) GetString(key string) string

DEPENDENCIES:
  ⚙️ errors package
  External: github.com/spf13/viper

LOADS (RAW files at runtime):
  📄 config/templates/dns.toml
  📄 config/templates/firewall.toml
  📄 /etc/safeops/*.toml

COMPILED INTO:
  ⚙️ logging/logger.go
  ⚙️ postgres/postgres.go
  ⚙️ redis/redis.go
  ⚙️ Future services

USAGE:
  cfg, := config.Load("/etc/safeops/dns.toml")  // Loads RAW TOML
  port := cfg.GetInt("server.port")              // COMPILED code
```

#### ⚙️ src/shared/go/config/env.go, validator.go, watcher.go, config_test.go

```yaml
All COMPILED into config package
Dependencies: config.go, errors package
```

---

### PACKAGE: logging/ (5 files)

#### ⚙️ src/shared/go/logging/logger.go

```yaml
FILE: src/shared/go/logging/logger.go
USAGE: ⚙️ COMPILED
SIZE: ~350 lines

CONTAINS:
  type Logger struct {
      logrus *logrus.Logger
  }
  
  func New(cfg config.LoggingConfig) (*Logger, error)
  func (l *Logger) Info(msg string, fields ...interface{})

DEPENDENCIES:
  ⚙️ config package
  ⚙️ errors package
  External: github.com/sirupsen/logrus

COMPILED INTO:
  ⚙️ postgres/postgres.go
  ⚙️ redis/redis.go
  ⚙️ ALL services
```

#### ⚙️ levels.go, formatters.go, rotation.go, logger_test.go

```yaml
All COMPILED into logging package
```

---

### PACKAGE: postgres/ (4 files), redis/ (4 files), grpc_client/ (7 files), metrics/ (3 files), health/ (2 files), utils/ (5 files)

```yaml
All follow pattern:
  USAGE: ⚙️ COMPILED into service binaries
  Dependencies: errors, config, logging packages
  Pattern: Build bottom-to-top, each depends on previous layers
```

---

## LEVEL 6: src/shared/rust/ (COMPILED Rust Library)

### ⚙️ src/shared/rust/Cargo.toml

```yaml
FILE: src/shared/rust/Cargo.toml
USAGE: ⚙️ Build configuration (cargo uses this)

CONTAINS:
  [package]
  name = "safeops-shared"
  version = "2.0.0"
  
  [lib]
  name = "safeops_shared"
  crate-type = ["rlib"]  # Static library
  
  [dependencies]
  tokio = { version = "1.35", features = ["full"] }
  prost = "0.12"
  xxhash-rust = "0.8"
  # ... 20+ dependencies

BUILDS TO:
  ⚙️ target/release/libsafeops_shared.rlib

USED BY:
  ⚙️ src/firewall_engine/Cargo.toml (depends on safeops-shared)
  ⚙️ src/threat_intel/Cargo.toml
```

### ⚙️ src/shared/rust/build.rs

```yaml
FILE: src/shared/rust/build.rs
USAGE: ⚙️ Build script (runs before compilation)

CONTAINS:
  fn main() {
      tonic_build::configure()
          .build_client(true)
          .build_server(false)
          .compile(&["../../proto/grpc/common.proto"], &["../../proto/grpc"])
          .unwrap();
  }

READS (RAW proto):
  📄 proto/grpc/common.proto
  📄 proto/grpc/firewall.proto
  📄 proto/grpc/threat_intel.proto

GENERATES:
  ⚙️ src/proto/common.rs (in src/shared/rust/)
  ⚙️ src/proto/firewall.rs
  ⚙️ src/proto/threat_intel.rs
```

### ⚙️ src/shared/rust/src/error.rs

```yaml
FILE: src/shared/rust/src/error.rs
USAGE: ⚙️ COMPILED into libsafeops_shared.rlib
SIZE: ~350 lines

CONTAINS:
  #[derive(Debug, thiserror::Error)]
  pub enum SafeOpsError {
      #[error("IO error: {0}")]
      Io(#[from] std::io::Error),
      
      #[error("Network error: {0}")]
      Network(String),
      
      #[error("Parse error: {0}")]
      Parse(String),
  }
  
  pub type Result<T> = std::result::Result<T, SafeOpsError>;

DEPENDENCIES:
  External: thiserror, std::io

COMPILED INTO:
  ⚙️ All other .rs files in src/shared/rust/src/
  ⚙️ libsafeops_shared.rlib
  ⚙️ src/firewall_engine/ (links this library)
  ⚙️ src/threat_intel/ (links this library)
```

### ⚙️ src/shared/rust/src/ip_utils.rs, hash_utils.rs, time_utils.rs, memory_pool.rs, lock_free.rs, simd_utils.rs, proto_utils.rs, metrics.rs, buffer_pool.rs, lib.rs

```yaml
All: USAGE: ⚙️ COMPILED into libsafeops_shared.rlib

DEPENDENCY CHAIN:
  error.rs (Level 6a)
    ↓
  ip_utils.rs, hash_utils.rs, time_utils.rs (Level 6b - basic utils)
    ↓
  memory_pool.rs, buffer_pool.rs (Level 6c - use basic utils)
    ↓
  lock_free.rs, simd_utils.rs (Level 6d - performance features)
    ↓
  proto_utils.rs, metrics.rs (Level 6e - high-level features)
    ↓
  lib.rs (Level 6f - exports all)

BUILD:
  cargo build --release
  Output: target/release/libsafeops_shared.rlib

LINKED INTO (COMPILED):
  ⚙️ src/firewall_engine/target/release/firewall_engine.exe
  ⚙️ src/threat_intel/target/release/threat_intel.exe
```

---

## 📊 Complete Dependency Flow Summary

```
RAW SOURCES (🔧 Generate or 📄 Include):
  proto/*.proto (14 files)
    ↓ protoc compilation
  build/proto/go/*.pb.go (14 files ⚙️ COMPILED)
  build/proto/rust/*.rs (14 files ⚙️ COMPILED)
    ↓
  src/shared/c/*.h (4 files 📄 RAW headers)
    ↓
  src/shared/go/* (38 files ⚙️ COMPILED → Go packages)
  src/shared/rust/* (13 files ⚙️ COMPILED → .rlib library)
    ↓
RUNTIME CONFIGS (📄 RAW loaded):
  config/*.toml (44 files)
    ↓
FUTURE SERVICES (⚙️ COMPILED, not implemented yet):
  src/firewall_engine/ (Rust)
  src/threat_intel/ (Rust)
  src/dns_server/ (Go)
  src/ids_ips/ (Go)
  ... 10 more services
```

---

## Usage Type Legend

| Symbol | Type | Description | Example |
|--------|------|-------------|---------|
| 🔧 | **GENERATES** | Source compiles to other code | .proto → .pb.go |
| ⚙️ | **COMPILED** | Code compiled into binary | Go → .exe, Rust → .rlib |
| 📄 | **RAW** | Used as-is (headers or runtime) | .h #include, .toml loaded |

---

**Total Files Documented: 69**
- Proto definitions: 14 (🔧 generate code)
- Generated Go: 14 (⚙️ compiled)
- Generated Rust: 14 (⚙️ compiled)
- C headers: 4 (📄 raw)
- Go source: 38 (⚙️ compiled)
- Rust source: 13 (⚙️ compiled → .rlib)
- Config files: Listed conceptually (📄 raw runtime)

---

## 📋 COMPLETE src/shared FILES - PAST & FUTURE DEPENDENCIES

### All 61 src/shared Files with Full Dependency Analysis

---

## src/shared/c/ (4 Header Files)

### 📄 shared_constants.h

```yaml
FILE: src/shared/c/shared_constants.h

PAST DEPENDENCIES (What this file uses):
  External Only:
    - <stdint.h> (stdlib)
  SafeOps Files:
    - NONE (Level 0 foundation)
  Config Files:
    - NONE
  Usage Type: Header-only constants

FUTURE DEPENDENCIES (What will use this):
  src/shared files:
    📄 packet_structs.h (#include "shared_constants.h" - RAW)
    📄 ring_buffer.h (#include "shared_constants.h" - RAW)
    📄 ioctl_codes.h (#include "shared_constants.h" - RAW)
  
  Future services:
    ❌ kernel_driver/*.c (RAW #include when implemented)
    ❌ userspace_service/*.c (RAW #include when implemented)
    ⚙️ firewall_engine (via bindgen → Rust constants - COMPILED)
    ⚙️ threat_intel (via bindgen → Rust constants - COMPILED)
```

### 📄 packet_structs.h

```yaml
FILE: src/shared/c/packet_structs.h

PAST DEPENDENCIES:
  SafeOps Files:
    📄 shared_constants.h (RAW #include for MAX_PACKET_SIZE)
  External:
    - <stdint.h>, <winsock2.h>
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared files:
    📄 ring_buffer.h (RAW #include - PACKET_INFO stored in ring)
  
  Future services:
    ❌ kernel_driver/packet_capture.c (RAW #include, fills PACKET_INFO)
    ❌ userspace_service/ring_reader.c (RAW #include, reads PACKET_INFO)
    ⚙️ firewall_engine (bindgen → #[repr(C)] struct PacketInfo - COMPILED)
    ⚙️ threat_intel (bindgen → Rust FFI - COMPILED)
    ⚙️ ids_ips (CGO → C.PACKET_INFO - COMPILED into Go)
```

### 📄 ring_buffer.h

```yaml
FILE: src/shared/c/ring_buffer.h

PAST DEPENDENCIES:
  SafeOps Files:
    📄 shared_constants.h (RAW - RING_BUFFER_SIZE, RING_BUFFER_MAGIC)
    📄 packet_structs.h (RAW - PACKET_INFO type)
  External:
    - <intrin.h> (Windows atomics)
  Config Files:
    - NONE (constants from shared_constants.h)

FUTURE DEPENDENCIES:
  Future services:
    ❌ kernel_driver/shared_memory.c (RAW #include, creates RING_BUFFER)
    ❌ userspace_service/ring_reader.c (RAW #include, reads from ring)
    ⚙️ firewall_engine (may access via FFI if needed - COMPILED)
```

### 📄 ioctl_codes.h

```yaml
FILE: src/shared/c/ioctl_codes.h

PAST DEPENDENCIES:
  SafeOps Files:
    📄 shared_constants.h (RAW - IOCTL_TIMEOUT_MS)
  External:
    - <windows.h> (CTL_CODE macro)
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  Future services:
    ❌ kernel_driver/ioctl_handler.c (RAW #include, dispatch IOCTL)
    ❌ userspace_service/ioctl_client.c (RAW #include, call DeviceIoControl)
    ⚙️ Go services (via CGO wrapper around userspace_service - COMPILED)
    ⚙️ Rust services (via FFI wrapper - COMPILED)
```

---

## src/shared/go/ (38 Go Files)

### PACKAGE: errors/ (3 files)

#### ⚙️ errors/codes.go

```yaml
FILE: src/shared/go/errors/codes.go

PAST DEPENDENCIES:
  SafeOps Files:
    - NONE (constants only)
  External:
    - Standard library only
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ errors/errors.go (uses error codes - COMPILED)
    ⚙️ ALL other Go packages (import error codes - COMPILED)
  
  Future services (ALL Go services):
    ⚙️ ids_ips (COMPILED into binary)
    ⚙️ dns_server (COMPILED)
    ⚙️ dhcp_server (COMPILED)
    ⚙️ tls_proxy (COMPILED)
    ⚙️ wifi_ap (COMPILED)
    ⚙️ orchestrator (COMPILED)
    ⚙️ certificate_manager (COMPILED)
    ⚙️ backup_restore (COMPILED)
    ⚙️ update_manager (COMPILED)
```

#### ⚙️ errors/errors.go

```yaml
FILE: src/shared/go/errors/errors.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ errors/codes.go (uses error codes - COMPILED)
  External:
    - github.com/pkg/errors (stack traces)
    - Standard library (fmt, runtime, time)
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ errors/wrapping.go (COMPILED)
    ⚙️ config/*.go (returns SafeOpsError - COMPILED)
    ⚙️ logging/*.go (logs SafeOpsError - COMPILED)
    ⚙️ postgres/*.go (wraps DB errors - COMPILED)
    ⚙️ redis/*.go (wraps Redis errors - COMPILED)
    ⚙️ grpc_client/*.go (wraps gRPC errors - COMPILED)
    ⚙️ metrics/*.go, health/*.go, utils/*.go (COMPILED)
  
  Future services:
    ⚙️ ALL Go services (every function returns Result<T> - COMPILED)
```

#### ⚙️ errors/wrapping.go

```yaml
FILE: src/shared/go/errors/wrapping.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ errors/errors.go (COMPILED)
    ⚙️ errors/codes.go (COMPILED)
  External:
    - Standard library (errors package)
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ All packages (use UnwrapAll, HasCode - COMPILED)
  
  Future services:
    ⚙️ All Go services (error handling utils - COMPILED)
```

---

### PACKAGE: config/ (5 files)

#### ⚙️ config/config.go

```yaml
FILE: src/shared/go/config/config.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ errors package (returns SafeOpsError - COMPILED)
  External:
    - github.com/spf13/viper
    - gopkg.in/yaml.v3
  Config Files Used (RAW runtime loading):
    📄 config/templates/dns.toml (loads at runtime)
    📄 config/templates/firewall.toml (loads at runtime)
    📄 config/templates/dhcp.toml (loads at runtime)
    📄 config/templates/*.toml (ALL 20 service configs - RAW)
    📄 /etc/safeops/*.toml (production configs - RAW)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ config/env.go, validator.go, watcher.go (COMPILED)
    ⚙️ logging/logger.go (uses LoggingConfig - COMPILED)
    ⚙️ postgres/postgres.go (uses DatabaseConfig - COMPILED)
    ⚙️ redis/redis.go (uses RedisConfig - COMPILED)
    ⚙️ grpc_client/*.go (uses config - COMPILED)
    ⚙️ metrics/metrics.go (uses MetricsConfig - COMPILED)
  
  Future services:
    ⚙️ dns_server (calls config.Load("/etc/safeops/dns.toml") - COMPILED, loads RAW TOML)
    ⚙️ dhcp_server (loads dhcp.toml - COMPILED, loads RAW)
    ⚙️ ids_ips (loads ids_ips.toml - COMPILED, loads RAW)
    ⚙️ ALL Go services (COMPILED package, loads RAW configs)
```

#### ⚙️ config/env.go

```yaml
FILE: src/shared/go/config/env.go

PAST DEPENDENCIES:
  SafeOps Files:
    - NONE (standalone utilities)
  External:
    - Standard library (os, strconv)
  Config Files:
    - Reads environment variables (not files)
  
  Environment Variables Used (RAW):
    - POSTGRES_HOST, POSTGRES_PORT, POSTGRES_PASSWORD
    - REDIS_HOST, REDIS_PORT
    - LOG_LEVEL, METRICS_PORT
    - Any SAFEOPS_* prefixed variables

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ config/config.go (may use GetEnv internally - COMPILED)
    ⚙️ postgres/postgres.go (RequireEnv("POSTGRES_PASSWORD") - COMPILED)
  
  Future services:
    ⚙️ All Go services in Docker/K8s (read env vars - COMPILED)
```

#### ⚙️ config/validator.go

```yaml
FILE: src/shared/go/config/validator.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config/config.go (validates config structs - COMPILED)
  External:
    - Standard library (net/url, os, strconv)
  Config Files:
    - NONE (validates loaded config, doesn't load)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ config/config.go (Config.Validate() - COMPILED)
  
  Future services:
    ⚙️ All Go services (validate config before start - COMPILED)
```

#### ⚙️ config/watcher.go

```yaml
FILE: src/shared/go/config/watcher.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config/config.go (watches config file - COMPILED)
  External:
    - github.com/fsnotify/fsnotify
  Config Files Watched (RAW):
    📄 /etc/safeops/*.toml (watches for changes - RAW runtime)

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ All Go services (hot-reload config - COMPILED, watches RAW files)
```

#### ⚙️ config/config_test.go

```yaml
FILE: src/shared/go/config/config_test.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config/config.go (tests this - COMPILED)
  External:
    - testing (stdlib)
  Config Files:
    - Creates temp test configs (RAW for testing)

FUTURE DEPENDENCIES:
  - Test harness only, not used by services
```

---

### PACKAGE: logging/ (5 files)

#### ⚙️ logging/logger.go

```yaml
FILE: src/shared/go/logging/logger.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config package (uses LoggingConfig - COMPILED)
    ⚙️ errors package (logs SafeOpsError - COMPILED)
  External:
    - github.com/sirupsen/logrus
  Config Files Used (RAW):
    📄 Gets logging config from service .toml (e.g., dns.toml [logging] section)
    📄 Writes to log files at config.logging.file_path

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ postgres/postgres.go (logs DB operations - COMPILED)
    ⚙️ redis/redis.go (logs cache ops - COMPILED)
    ⚙️ grpc_client/*.go (logs RPC calls - COMPILED)
    ⚙️ ALL packages (logging - COMPILED)
  
  Future services:
    ⚙️ ALL Go services (every service has logger - COMPILED)
```

#### ⚙️ logging/levels.go, formatters.go, rotation.go, logger_test.go

```yaml
All follow pattern:
  PAST DEPS: logger.go, config, errors
  FUTURE DEPS: COMPILED into logging package → all services
  Config Usage: rotation.go writes to paths from logging config (RAW)
```

---

### PACKAGE: postgres/ (4 files)

#### ⚙️ postgres/postgres.go

```yaml
FILE: src/shared/go/postgres/postgres.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config package (DatabaseConfig - COMPILED)
    ⚙️ logging package (logs queries - COMPILED)
    ⚙️ errors package (wraps DB errors - COMPILED)
  External:
    - github.com/jackc/pgx/v5
  Config Files Used (RAW):
    📄 Reads [database] section from service .toml files
  Database Files Used (RAW runtime):
    📄 Connects to PostgreSQL using database/schemas/*.sql (DB runtime)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ postgres/transactions.go, bulk_insert.go, migrations.go (COMPILED)
  
  Future services:
    ⚙️ threat_intel (stores IOCs in DB - COMPILED)
    ⚙️ dns_server (stores DNS records - COMPILED)
    ⚙️ dhcp_server (stores leases - COMPILED)
    ⚙️ ids_ips (stores alerts - COMPILED)
    ⚙️ orchestrator (stores service state - COMPILED)
    ⚙️ certificate_manager (stores certs - COMPILED)
    ⚙️ backup_restore (backup DB - COMPILED)
```

#### ⚙️ postgres/transactions.go, bulk_insert.go, migrations.go

```yaml
PAST DEPS:
  ⚙️ postgres/postgres.go (COMPILED)
  
FUTURE DEPS:
  ⚙️ All services using DB transactions/bulk ops (COMPILED)
  
migrations.go specifically:
  Database Files Used (RAW):
    📄 database/schemas/*.sql (runs migrations - RAW SQL)
```

---

### PACKAGE: redis/ (4 files)

#### ⚙️ redis/redis.go

```yaml
FILE: src/shared/go/redis/redis.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config package (RedisConfig - COMPILED)
    ⚙️ logging package (COMPILED)
    ⚙️ errors package (COMPILED)
  External:
    - github.com/go-redis/redis/v8
  Config Files Used (RAW):
    📄 Reads [redis] section from service .toml

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ redis/pubsub.go, pipeline.go, lua_scripts.go (COMPILED)
  
  Future services:
    ⚙️ firewall_engine (caches rules - COMPILED)
    ⚙️ threat_intel (caches reputation - COMPILED)
    ⚙️ dns_server (caches DNS responses - COMPILED)
    ⚙️ ids_ips (caches signatures - COMPILED)
    ⚙️ ALL Go services (session/cache - COMPILED)
```

#### ⚙️ redis/pubsub.go, pipeline.go, lua_scripts.go

```yaml
PAST DEPS:
  ⚙️ redis/redis.go (COMPILED)
  
FUTURE DEPS:
  ⚙️ orchestrator (pub/sub for service coordination - COMPILED)
  ⚙️ ids_ips (pub/sub for real-time alerts - COMPILED)
```

---

### PACKAGE: grpc_client/ (7 files)

#### ⚙️ grpc_client/client.go

```yaml
FILE: src/shared/go/grpc_client/client.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config package (gRPC config - COMPILED)
    ⚙️ logging package (COMPILED)
    ⚙️ errors package (wraps gRPC errors - COMPILED)
  External:
    - google.golang.org/grpc
  Proto Files Used (COMPILED):
    ⚙️ build/proto/go/*.pb.go (imports proto types - COMPILED)
  Config Files:
    📄 Reads [grpc] section from service .toml (endpoints, timeouts)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ grpc_client/interceptors.go, retry.go, circuit_breaker.go, etc. (COMPILED)
  
  Future services:
    ⚙️ orchestrator (calls ALL services via gRPC - COMPILED)
    ⚙️ firewall_engine (calls threat_intel for reputation - COMPILED)
    ⚙️ ids_ips (calls firewall for rule updates - COMPILED)
    ⚙️ dns_server (calls threat_intel for domain reputation - COMPILED)
```

#### ⚙️ grpc_client/interceptors.go, retry.go, circuit_breaker.go, load_balancer.go, retry_budget.go, service_discovery.go

```yaml
PAST DEPS:
  ⚙️ grpc_client/client.go (COMPILED)
  ⚙️ config, logging, errors packages (COMPILED)
  
FUTURE DEPS:
  ⚙️ All gRPC clients (resilience patterns - COMPILED)
  
service_discovery.go specifically:
  Config Files:
    📄 May read service registry from config (RAW)
```

---

### PACKAGE: metrics/ (3 files)

#### ⚙️ metrics/metrics.go

```yaml
FILE: src/shared/go/metrics/metrics.go

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config package (MetricsConfig - COMPILED)
    ⚙️ logging package (COMPILED)
  External:
    - github.com/prometheus/client_golang
  Config Files:
    📄 Reads [metrics] section from service .toml (port, path)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ metrics/registry.go, http_handler.go (COMPILED)
  
  Future services:
    ⚙️ ALL services (expose /metrics endpoint - COMPILED)
```

#### ⚙️ metrics/registry.go, http_handler.go

```yaml
PAST DEPS:
  ⚙️ metrics/metrics.go (COMPILED)
  
FUTURE DEPS:
  ⚙️ All services (Prometheus metrics export - COMPILED)
```

---

### PACKAGE: health/ (2 files)

#### ⚙️ health/health.go, checks.go

```yaml
PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ config, logging, errors packages (COMPILED)
  Config Files:
    📄 Reads [health] section from service .toml

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ ALL services (health check endpoint - COMPILED)
    ⚙️ orchestrator (monitors service health - COMPILED)
```

---

### PACKAGE: utils/ (5 files)

#### ⚙️ utils/retry.go, rate_limit.go, bytes.go, strings.go, validation.go

```yaml
PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ errors package (COMPILED)
  External:
    - Standard library
  Config Files:
    - NONE (pure utilities)

FUTURE DEPENDENCIES:
  src/shared/go files:
    ⚙️ Used by grpc_client, postgres, redis (COMPILED)
  
  Future services:
    ⚙️ ALL services (common utilities - COMPILED)
```

---

## src/shared/rust/ (13 Files)

### ⚙️ Cargo.toml

```yaml
FILE: src/shared/rust/Cargo.toml
USAGE: ⚙️ Build configuration (cargo uses this)

CONTAINS:
  [package]
  name = "safeops-shared"
  version = "2.0.0"
  edition = "2021"
  
  [lib]
  name = "safeops_shared"
  crate-type = ["rlib"]  # Static library
  
  [dependencies]
  tokio = { version = "1.35", features = ["full"] }
  serde = { version = "1.0", features = ["derive"] }
  tonic = { version = "0.10", features = ["transport", "tls"] }
  prost = "0.12"
  xxhash-rust = { version = "0.8", features = ["xxh3"] }
  ahash = "0.8"
  crossbeam = "0.8"
  parking_lot = "0.12"
  rayon = "1.8"
  prometheus = "0.13"
  ring = "0.17"
  # ... 20+ dependencies total

BUILDS TO:
  ⚙️ target/release/libsafeops_shared.rlib (Rust static library)

USED BY:
  ⚙️ src/firewall_engine/Cargo.toml (depends on safeops-shared - COMPILED)
  ⚙️ src/threat_intel/Cargo.toml (depends on safeops-shared - COMPILED)
```

### ⚙️ build.rs

```yaml
FILE: src/shared/rust/build.rs
USAGE: ⚙️ Build script (runs before compilation)

CONTAINS:
  fn main() -> Result<(), Box<dyn std::error::Error>> {
      tonic_build::configure()
          .build_client(true)
          .build_server(false)
          .out_dir("src/proto")
          .compile(
              &[
                  "../../proto/grpc/common.proto",
                  "../../proto/grpc/firewall.proto",
                  "../../proto/grpc/threat_intel.proto",
              ],
              &["../../proto/grpc"]
          )?;
      Ok(())
  }

READS (RAW proto):
  📄 proto/grpc/common.proto
  📄 proto/grpc/firewall.proto
  📄 proto/grpc/threat_intel.proto

GENERATES:
  ⚙️ src/proto/common.rs (COMPILED into crate)
  ⚙️ src/proto/firewall.rs (COMPILED into crate)
  ⚙️ src/proto/threat_intel.rs (COMPILED into crate)

FUTURE DEPENDENCIES:
  - Build system only, generates code used by lib.rs
```

### ⚙️ src/lib.rs

```yaml
FILE: src/shared/rust/src/lib.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs, ip_utils.rs, hash_utils.rs, etc. (COMPILED - declares all modules)
  External:
    - Standard library
  Config Files:
    - NONE (library root, no runtime config)

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (use safeops_shared::prelude::* - COMPILED)
    ⚙️ threat_intel (import shared types - COMPILED)
```

### ⚙️ src/error.rs

```yaml
FILE: src/shared/rust/src/error.rs

PAST DEPENDENCIES:
  SafeOps Files:
    - NONE (foundation error type)
  External:
    - thiserror, std::io
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/rust files:
    ⚙️ ALL .rs files (return Result<T> - COMPILED)
  
  Future services:
    ⚙️ firewall_engine (error handling - COMPILED)
    ⚙️ threat_intel (error handling - COMPILED)
```

### ⚙️ src/ip_utils.rs

```yaml
FILE: src/shared/rust/src/ip_utils.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (returns Result - COMPILED)
  External:
    - ipnet, cidr-utils crates
    - std::net
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/rust files:
    ⚙️ simd_utils.rs (parses IPs from packets - COMPILED)
  
  Future services:
    ⚙️ firewall_engine (parse IPs from rules - COMPILED)
    ⚙️ threat_intel (IP reputation lookups - COMPILED)
```

### ⚙️ src/hash_utils.rs

```yaml
FILE: src/shared/rust/src/hash_utils.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
  External:
    - xxhash-rust, ahash
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/rust files:
    ⚙️ lock_free.rs (hash table keys - COMPILED)
  
  Future services:
    ⚙️ firewall_engine (connection hash table - COMPILED)
    ⚙️ threat_intel (IOC lookups - COMPILED)
```

### ⚙️ src/time_utils.rs

```yaml
FILE: src/shared/rust/src/time_utils.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
  External:
    - chrono
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/rust files:
    ⚙️ metrics.rs (timestamps - COMPILED)
  
  Future services:
    ⚙️ firewall_engine (packet timestamps - COMPILED)
    ⚙️ threat_intel (last_seen timestamps - COMPILED)
```

### ⚙️ src/memory_pool.rs

```yaml
FILE: src/shared/rust/src/memory_pool.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
  External:
    - crossbeam
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  src/shared/rust files:
    ⚙️ buffer_pool.rs (pools packet buffers - COMPILED)
  
  Future services:
    ⚙️ firewall_engine (reuse packet structs - COMPILED)
```

### ⚙️ src/buffer_pool.rs

```yaml
FILE: src/shared/rust/src/buffer_pool.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/memory_pool.rs (uses generic pool - COMPILED)
    ⚙️ src/error.rs (COMPILED)
  External:
    - crossbeam
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (zero-copy packet processing - COMPILED)
```

### ⚙️ src/lock_free.rs

```yaml
FILE: src/shared/rust/src/lock_free.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
    ⚙️ src/hash_utils.rs (hash functions - COMPILED)
  External:
    - crossbeam, parking_lot
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (lock-free connection tracking - COMPILED)
    ⚙️ threat_intel (lock-free IOC cache - COMPILED)
```

### ⚙️ src/simd_utils.rs

```yaml
FILE: src/shared/rust/src/simd_utils.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
    ⚙️ src/ip_utils.rs (IP parsing - COMPILED)
  External:
    - packed_simd_2
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (SIMD packet parsing for multi-gigabit throughput - COMPILED)
```

### ⚙️ src/proto_utils.rs

```yaml
FILE: src/shared/rust/src/proto_utils.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
  External:
    - prost
  Proto Files (COMPILED):
    ⚙️ Uses generated proto types from build.rs (COMPILED)
  Config Files:
    - NONE

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (protobuf conversions - COMPILED)
    ⚙️ threat_intel (gRPC message handling - COMPILED)
```

### ⚙️ src/metrics.rs

```yaml
FILE: src/shared/rust/src/metrics.rs

PAST DEPENDENCIES:
  SafeOps Files:
    ⚙️ src/error.rs (COMPILED)
    ⚙️ src/time_utils.rs (timestamps - COMPILED)
  External:
    - prometheus
  Config Files:
    📄 May read [metrics] section from Rust service .toml

FUTURE DEPENDENCIES:
  Future services:
    ⚙️ firewall_engine (packet/connection metrics - COMPILED)
    ⚙️ threat_intel (IOC lookup metrics - COMPILED)
```

---

## 📊 Summary: src/shared Files Usage Patterns

### RAW Usage (14 files):
```
C Headers (4):
  - shared_constants.h, packet_structs.h, ring_buffer.h, ioctl_codes.h
  - Used RAW via #include by future C code
  - Converted to Rust/Go via bindgen/CGO (then COMPILED)

Config Files (loaded at runtime):
  - config/config.go LOADS 📄 *.toml files (RAW runtime)
  - logging/rotation.go WRITES to 📄 log files (RAW runtime)
  - postgres/migrations.go RUNS 📄 *.sql files (RAW runtime)
```

### COMPILED Usage (51 files):
```
Go Packages (38 files):
  - ALL compiled into Go service binaries
  - Import path: github.com/safeops/shared/go/{package}
  
Rust Library (13 files):
  - ALL compiled into libsafeops_shared.rlib
  - Linked into firewall_engine, threat_intel binaries
```

### Config File Dependencies:
```
Files that LOAD config (📄 RAW runtime):
  ⚙️ config/config.go → loads *.toml
  ⚙️ config/watcher.go → watches *.toml
  ⚙️ logging/rotation.go → writes log files from config path
  ⚙️ postgres/migrations.go → runs *.sql migrations
  ⚙️ rust metrics.rs → may load metrics config
```

Phase 1 Complete ✅
