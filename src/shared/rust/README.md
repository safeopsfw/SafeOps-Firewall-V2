# SafeOps v2.0 - Rust Shared Library

## 📦 Overview

**Location:** `src/shared/rust/`  
**Purpose:** High-performance shared utilities and Protocol Buffer bindings for SafeOps services  
**Language:** Rust  
**Build System:** Cargo

This library provides zero-cost abstractions, memory-safe utilities, and high-performance data structures used across all SafeOps Rust-based services and components.

---

## 📁 Library Structure

### Core Modules

#### `lib.rs` - Library Entry Point
- **Purpose:** Main library module that re-exports all public APIs
- **Exports:** All public modules and their APIs
- **Safety:** Carefully manages unsafe code blocks for FFI and performance-critical operations
- **Features:** Conditional compilation for SIMD and other CPU-specific optimizations

#### `error.rs` - Error Handling
- **Purpose:** Unified error type for the entire shared library
- **Key Types:**
  - `SafeOpsError` - Main error enum covering all module errors
  - `Result<T>` - Type alias for `std::result::Result<T, SafeOpsError>`
- **Features:**
  - Error code propagation
  - Error context chaining
  - Integration with `anyhow` and `thiserror`
- **Usage:** All library functions return `Result<T>` for consistent error handling

---

### Memory Management

#### `memory_pool.rs` - Object Pool Allocator
- **Purpose:** Thread-safe object pooling for reducing allocator pressure
- **Key Types:**
  - `MemoryPool<T>` - Generic memory pool with configurable capacity
- **Features:**
  - Zero-allocation object reuse
  - Thread-safe design with lock-free operations where possible
  - Automatic growth and shrinking
  - Drop-based object return to pool
- **Use Cases:**
  - Packet buffer allocation
  - Temporary object reuse in hot paths
  - Reducing GC pressure in high-throughput services

#### `buffer_pool.rs` - Byte Buffer Pool
- **Purpose:** Specialized pool for byte buffers (Vec<u8>)
- **Key Types:**
  - `BufferPool` - Pool of reusable byte buffers
  - `PooledBuffer` - RAII wrapper for auto-return to pool
- **Features:**
  - Pre-sized buffer allocation
  - Automatic capacity management
  - Zero-copy buffer reuse
- **Use Cases:**
  - Network packet processing
  - Log message buffering
  - Temporary I/O buffers

---

### Data Structures

#### `lock_free.rs` - Lock-Free Data Structures
- **Purpose:** Wait-free and lock-free concurrent data structures
- **Key Types:**
  - `LockFreeQueue<T>` - Multi-producer, multi-consumer queue
  - `LockFreeStack<T>` - Lock-free stack
- **Features:**
  - Atomic operations using `crossbeam`
  - Memory ordering guarantees
  - ABA problem protection
- **Use Cases:**
  - Inter-thread communication
  - Work stealing schedulers
  - High-throughput event processing

---

### Network Utilities

#### `ip_utils.rs` - IP Address Utilities
- **Purpose:** Fast IP address parsing, validation, and manipulation
- **Key Functions:**
  - `parse_ipv4()` - Fast IPv4 parsing
  - `parse_ipv6()` - Fast IPv6 parsing
  - `is_private_ip()` - Check if IP is in private range (RFC 1918)
  - `is_multicast()` - Check multicast addresses
  - `ip_to_network()` - Calculate network address from IP/CIDR
- **Features:**
  - SIMD-accelerated parsing (if enabled)
  - Zero-allocation parsing
  - Subnet calculations
- **Use Cases:**
  - Firewall rule matching
  - DHCP lease management
  - Network traffic analysis

---

### Cryptographic Utilities

#### `hash_utils.rs` - Hashing Functions
- **Purpose:** High-performance non-cryptographic hashing
- **Key Functions:**
  - `fast_hash()` - xxHash-based fast hashing
  - `hash_bytes()` - Hash arbitrary byte slices
  - `hash_string()` - String hashing
- **Features:**
  - SIMD-accelerated xxHash implementation
  - Streaming hash support
  - Seeded hashing
- **Use Cases:**
  - Hash tables and hash maps
  - Cache key generation
  - Data deduplication
- **⚠️ Not Suitable For:** Cryptographic purposes (use `ring` for crypto)

---

### Performance Utilities

#### `simd_utils.rs` - SIMD Operations
- **Purpose:** SIMD-accelerated operations for hot paths
- **Key Functions:**
  - `simd_memcpy()` - Fast memory copy using SIMD
  - `simd_compare()` - Fast byte comparison
  - `simd_search()` - Substring search with SIMD
- **Requirements:**
  - CPU with AVX2 support (x86_64)
  - Falls back to scalar operations on unsupported CPUs
- **Features:**
  - Runtime CPU feature detection
  - Compile-time feature gating
  - Benchmarked performance gains

#### `time_utils.rs` - Time Utilities
- **Purpose:** High-resolution timing and duration formatting
- **Key Functions:**
  - `now()` - Get current timestamp (nanosecond precision)
  - `duration_since()` - Calculate elapsed time
  - `format_duration()` - Human-readable duration formatting
  - `parse_duration()` - Parse duration strings ("1h30m", "500ms")
- **Features:**
  - Monotonic clock support
  - Nanosecond precision
  - Cross-platform compatibility
- **Use Cases:**
  - Performance monitoring
  - Request latency tracking
  - Timeout management

---

### Observability

#### `metrics.rs` - Metrics Collection
- **Purpose:** High-performance metrics aggregation and export
- **Key Types:**
  - `Counter` - Monotonically increasing counter
  - `Gauge` - Point-in-time value
  - `Histogram` - Value distribution tracking
  - `MetricsRegistry` - Global metrics registry
- **Features:**
  - Lock-free atomic counters
  - Thread-safe metric registration
  - Prometheus-compatible export format
  - Low-overhead instrumentation
- **Use Cases:**
  - Request counting
  - Latency histograms
  - Resource usage tracking
  - Service health monitoring

---

### Protocol Buffers

#### `proto/` - Generated Protocol Buffer Code
- **Purpose:** Rust bindings for gRPC service definitions
- **Generated Files:**
  - `safeops.common.rs` - Common message types
  - `safeops.orchestrator.rs` - Orchestrator service
  - `safeops.dns_server.rs` - DNS server service
  - `safeops.dhcp_server.rs` - DHCP server service
  - `safeops.firewall.rs` - Firewall service
  - `safeops.ids_ips.rs` - IDS/IPS service
  - `safeops.network_logger.rs` - Network logger service
  - `safeops.network_manager.rs` - Network manager service
  - `safeops.tls_proxy.rs` - TLS proxy service
  - `safeops.wifi_ap.rs` - WiFi AP service
  - `safeops.certificate_manager.rs` - Certificate manager service
  - `safeops.backup_restore.rs` - Backup/restore service
  - `safeops.update_manager.rs` - Update manager service
  - `safeops.threat_intel.rs` - Threat intelligence service

#### `proto_utils.rs` - Protocol Buffer Utilities
- **Purpose:** Helper functions for Protocol Buffer message handling
- **Key Functions:**
  - `serialize_proto()` - Serialize message to bytes
  - `deserialize_proto()` - Deserialize bytes to message
  - `proto_to_json()` - Convert proto to JSON
  - `json_to_proto()` - Parse JSON to proto
- **Features:**
  - Error handling for malformed messages
  - Efficient serialization
  - JSON interoperability

---

## 🛠️ Build System

### `build.rs` - Build Script
- **Purpose:** Compiles Protocol Buffer definitions during build
- **Tasks:**
  - Generates Rust code from `.proto` files in `proto/`
  - Configures protobuf compiler (`prost`)
  - Sets up include paths
  - Triggers rebuilds when proto files change
- **Output:** Generated files in `src/proto/`

### `Cargo.toml` - Dependencies
**Key Dependencies:**
- `prost` - Protocol Buffer runtime
- `tokio` - Async runtime
- `crossbeam` - Lock-free data structures
- `ring` - Cryptographic operations
- `parking_lot` - Fast synchronization primitives
- `thiserror` / `anyhow` - Error handling
- `tracing` - Structured logging
- `packed_simd` - SIMD operations

---

## 📊 Benchmarks

### `benches/` - Performance Benchmarks
- **`hash_performance.rs`** - Hash function benchmarks
  - Compares xxHash vs. SipHash vs. FNV
  - Measures throughput for various input sizes
- **`ip_parsing.rs`** - IP parsing benchmarks
  - SIMD vs. scalar parsing comparison
  - IPv4 and IPv6 parsing performance

**Running Benchmarks:**
```bash
cd src/shared/rust
cargo bench
```

---

## 🧪 Testing

**Run all tests:**
```bash
cargo test
```

**Run with backtrace:**
```bash
RUST_BACKTRACE=1 cargo test
```

**Run specific module tests:**
```bash
cargo test --lib memory_pool
cargo test --lib ip_utils
```

---

## 🚀 Usage Examples

### Memory Pool
```rust
use safeops_shared::memory_pool::MemoryPool;

let pool = MemoryPool::<Vec<u8>>::new(100); // Capacity of 100
let mut buffer = pool.acquire().unwrap();
buffer.extend_from_slice(b"data");
// Buffer automatically returns to pool on drop
```

### Buffer Pool
```rust
use safeops_shared::buffer_pool::BufferPool;

let pool = BufferPool::new(1024, 10); // 10 buffers of 1KB each
let buffer = pool.get_buffer();
// Use buffer...
// Auto-returns to pool on drop
```

### IP Utilities
```rust
use safeops_shared::ip_utils::{parse_ipv4, is_private_ip};

if let Some(ip) = parse_ipv4("192.168.1.1") {
    if is_private_ip(&ip) {
        println!("Private IP address");
    }
}
```

### Metrics
```rust
use safeops_shared::metrics::{Counter, MetricsRegistry};

let registry = MetricsRegistry::new();
let counter = Counter::new("requests_total");
counter.inc();
```

---

## 🔒 Safety Considerations

### Unsafe Code Usage
This library uses `unsafe` in specific, well-documented locations:
- **SIMD operations** - Requires unsafe for intrinsics
- **Lock-free data structures** - Atomic pointer operations
- **FFI boundaries** - C interop for kernel driver communication

**Safety Guarantees:**
- All unsafe blocks have accompanying safety comments
- Unsafe code is concentrated in tested modules
- Extensive use of Rust's type system to prevent misuse
- No data races (verified by Miri)

---

## 📝 Module Dependency Graph

```
lib.rs
├── error.rs (used by all modules)
├── memory_pool.rs
├── buffer_pool.rs
│   └── memory_pool.rs
├── lock_free.rs
├── ip_utils.rs
│   └── simd_utils.rs (optional)
├── hash_utils.rs
│   └── simd_utils.rs (optional)
├── simd_utils.rs
├── time_utils.rs
├── metrics.rs
├── proto/
│   ├── mod.rs
│   └── *.rs (generated)
└── proto_utils.rs
    └── proto/*
```

---

## 🔧 Build Features

**Available Cargo Features:**
- `simd` - Enable SIMD-accelerated operations (default: enabled)
- `metrics` - Include metrics collection (default: enabled)
- `proto` - Include Protocol Buffer support (default: enabled)

**Building without SIMD:**
```bash
cargo build --no-default-features --features metrics,proto
```

---

## 📚 Documentation

**Generate documentation:**
```bash
cargo doc --open
```

**Generate docs with private items:**
```bash
cargo doc --document-private-items --open
```

---

## 🐛 Debugging

**Enable debug logging:**
```bash
RUST_LOG=safeops_shared=debug cargo test
```

**Run with Miri (detect undefined behavior):**
```bash
cargo +nightly miri test
```

**Memory leak detection:**
```bash
valgrind --leak-check=full target/debug/your_binary
```

---

## 📦 Publishing

This is an internal library and is **not published to crates.io**.

**Local usage:**
```toml
[dependencies]
safeops_shared = { path = "../shared/rust" }
```

---

## 🤝 Contributing

When adding new modules:
1. Add module declaration to `lib.rs`
2. Include comprehensive unit tests
3. Add benchmarks if performance-critical
4. Document all public APIs with rustdoc
5. Update this README with module description
6. Ensure `cargo clippy` passes with no warnings

---

## 📄 License

Internal SafeOps project - All rights reserved.
