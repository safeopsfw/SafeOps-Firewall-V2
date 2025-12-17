# Shared Libraries - Data Structures

> **Common data structures and utilities shared across all SafeOps services**

---

## 📁 Directory Layout

```
shared/
├── rust/          # Rust shared library (performance-critical)
├── go/            # Go shared library (services)
└── c/             # C header files (kernel compatibility)
```

---

## 🦀 Rust Shared Library

### Location
`src/shared/rust/src/`

### Core Type Definitions

```rust
// src/shared/rust/src/lib.rs

pub mod error;         // Error types
pub mod ip_utils;      // IP address utilities
pub mod hash_utils;    // Hashing algorithms
pub mod memory_pool;   // Object pooling
pub mod lock_free;     // Lock-free data structures
pub mod simd_utils;    // SIMD optimizations
pub mod time_utils;    // Time/timestamp utilities
pub mod proto_utils;   // Protobuf helpers
pub mod buffer_pool;   // Buffer pooling
pub mod metrics;       // Prometheus metrics

---

## 🎯 Protocol Buffers

### Location
`proto/`

### gRPC Service Definitions

Each service exports gRPC interfaces defined in `.proto` files:

```protobuf
// proto/firewall_service.proto

syntax = "proto3";
package safeops.firewall.v1;

service FirewallService {
  rpc AddRule(AddRuleRequest) returns (AddRuleResponse);
  rpc DeleteRule(DeleteRuleRequest) returns (DeleteRuleResponse);
  rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
  rpc GetStats(GetStatsRequest) returns (GetStatsResponse);
}

message FirewallRule {
  uint32 id = 1;
  string name = 2;
  string description = 3;
  bool enabled = 4;
  uint32 priority = 5;
  Action action = 6;
  Direction direction = 7;
  AddressMatch source = 8;
  AddressMatch destination = 9;
  Protocol protocol = 10;
}
```

---

## ⚙️ Configuration

### Location
`config/templates/`

### TOML Structure

```toml
# config/templates/safeops.toml

[system]
version = "2.0.0"
node_id = "node-001"

[kernel_driver]
enabled = true
ring_buffer_size_mb = 16

[firewall]
default_policy = "BLOCK"
max_connections = 1000000

[threat_intelligence]
database_host = "localhost"
cache_ttl_seconds = 300
```

---

**Version:** 2.0.0  
**Last Updated:** 2025-12-17
