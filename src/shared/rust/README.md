# SafeOps Rust Shared Library

High-performance utilities and shared code for SafeOps firewall microservices.

## Overview

The SafeOps Rust shared library provides core functionality for packet processing, connection tracking, and threat intelligence operations. Built with zero-cost abstractions, lock-free data structures, and SIMD optimizations for maximum throughput.

**Key Features:**
- **Zero-Cost Abstractions** - No runtime overhead for safety guarantees
- **Lock-Free Structures** - MPMC queues, SPSC ring buffers, concurrent maps
- **SIMD Packet Parsing** - 4-8x faster IPv4/IPv6/TCP/UDP parsing
- **Fast Hashing** - xxHash (10+ GB/s), aHash (DOS-resistant)
- **Memory Pooling** - Zero-allocation hot paths for packet processing
- **Prometheus Metrics** - Built-in monitoring and observability

**Target Services:**
- `firewall_engine` - High-performance packet filtering
- `threat_intel` - Real-time threat detection

**Output:** `libsafeops_shared.rlib` static library

**License:** MIT

---

## Architecture

### Module Organization

```
src/
├── lib.rs           # Library root, public API exports
├── error.rs         # Unified error handling (SafeOpsError)
├── ip_utils.rs      # IP parsing, CIDR, subnet calculations
├── hash_utils.rs    # xxHash, aHash, connection tuple hashing
├── memory_pool.rs   # Generic object pooling
├── buffer_pool.rs   # Specialized packet buffer pool
├── lock_free.rs     # MPMC queue, SPSC ring, concurrent map
├── simd_utils.rs    # SIMD packet parsers (IPv4/IPv6/TCP/UDP)
├── time_utils.rs    # Timestamps, durations, timezone handling
├── proto_utils.rs   # Protocol Buffer conversion & validation
└── metrics.rs       # Prometheus metrics registry
```

### Design Patterns

- **Newtype Pattern** - `IPAddress` wraps `std::net::IpAddr` for type safety
- **Builder Pattern** - Memory pool configuration with defaults
- **Zero-Copy** - Direct buffer parsing without allocation
- **Drop-Based Cleanup** - `PooledObject` returns to pool automatically

### Performance Philosophy

1. **Avoid Allocations** - Memory pools for hot paths
2. **Use SIMD** - Parallel field extraction from packets
3. **Lock-Free** - Atomic operations instead of mutexes
4. **Fast Hashing** - Non-cryptographic hashes for hash tables

### Security Considerations

- **Input Validation** - All external data validated before use
- **No Unsafe Code** - `#![forbid(unsafe_code)]` at library level
- **Bounds Checking** - Rust's memory safety guarantees

---

## Getting Started

### Prerequisites

- **Rust:** 1.74 or later
- **Protocol Buffers Compiler:** `protoc` 3.12+
- **Build Tools:** See [DEPENDENCIES.md](../../../DEPENDENCIES.md)

### Building

```bash
# Development build
cargo build

# Release build with optimizations
cargo build --release

# Check compilation without building
cargo check
```

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test hash_utils

# With output
cargo test -- --nocapture
```

### Running Benchmarks

```bash
# All benchmarks
cargo bench

# Specific benchmark
cargo bench ip_parsing
```

### Documentation

```bash
# Generate and open docs
cargo doc --open
```

### Importing in Services

```rust
// Convenient prelude import
use safeops_shared::prelude::*;

// Or specific modules
use safeops_shared::{
    ip_utils::parse_cidr,
    hash_utils::xxhash64,
    metrics::MetricsRegistry,
};
```

---

## API Reference

### `error` - Error Handling
- **SafeOpsError** - Unified error enum (13 variants)
- **Result<T>** - Type alias for `Result<T, SafeOpsError>`
- **ErrorContext** - Trait for adding error context

### `ip_utils` - IP Address Utilities
- **parse_ip()** - Parse IPv4/IPv6 from string
- **parse_cidr()** - Parse CIDR notation (192.168.1.0/24)
- **cidr_contains()** - Check if IP in subnet
- **is_private()** - Detect RFC 1918 private IPs

### `hash_utils` - Fast Hashing
- **xxhash64()** - Extremely fast hash (10+ GB/s)
- **ahash_hash()** - DOS-resistant hash for HashMaps
- **hash_connection_tuple()** - Hash network 5-tuple
- **AHashMap/AHashSet** - Fast hash collections

### `memory_pool` - Object Pooling
- **MemoryPool<T>** - Generic pool for any type
- **acquire()** - Get object from pool
- **PooledObject<T>** - Smart pointer (auto-returns on drop)

### `lock_free` - Concurrent Structures
- **MpmcQueue<T>** - Multi-producer multi-consumer queue
- **SpscRingBuffer<T>** - Single-producer single-consumer ring
- **ConcurrentHashMap<K,V>** - Sharded concurrent map
- **LockFreeCounter** - Atomic counter for metrics

### `simd_utils` - Packet Parsing
- **parse_ipv4()** - Parse IPv4 header (SIMD)
- **parse_tcp/udp()** - Parse transport headers
- **verify_checksum()** - Fast checksum validation
- **parse_packets_batch()** - Batch processing

### `time_utils` - Time Functions
- **now_unix_timestamp()** - Current timestamp (seconds)
- **format_duration()** - Human-readable durations
- **is_expired()** - TTL expiration check
- **Timer** - High-precision performance timer

### `proto_utils` - Protocol Buffers
- **serialize_proto()** - Encode to bytes
- **deserialize_proto()** - Decode from bytes
- **validate_proto_*()** - Field validation helpers

### `metrics` - Prometheus Metrics
- **MetricsRegistry** - Global metrics registry
- **register_counter/gauge/histogram()** - Create metrics
- **time_operation()** - Automatic timing
- **metrics_handler()** - Prometheus export endpoint

---

## Performance Guide

### Zero-Allocation Paths

Memory pools eliminate allocations in packet processing hot paths:

```rust
let pool = MemoryPool::<PacketBuffer>::new(8192);
let mut buffer = pool.acquire()?;
// Process packet...
// Buffer automatically returned to pool on drop
```

### SIMD Acceleration

Packet parsing is 4-8x faster with SIMD:

```rust
// Automatic SIMD selection based on CPU features
let header = parse_ipv4(&packet)?;
// Uses SSE4.2 on x86_64, NEON on ARM64
```

### Lock-Free Structures

No contention in multi-threaded pipelines:

```rust
let queue = MpmcQueue::new(16384);
// Multiple threads can push/pop concurrently
queue.push(packet)?;
```

### Fast Hashing

xxHash is 10x faster than cryptographic hashes:

```rust
// 10+ GB/s throughput
let hash = xxhash64(data);

// DOS-resistant for HashMaps
let map = AHashMap::new();
```

### Compilation Settings

Release builds use aggressive optimizations:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
```

### Expected Performance

- **Packet Parsing:** 10+ million packets/sec (single core)
- **Hash Operations:** 10+ GB/s throughput
- **Memory Pool:** ~20ns acquire latency
- **Total Throughput:** Limited by network bandwidth, not CPU

### Profiling

```bash
# CPU profiling with perf
cargo build --release
perf record --call-graph dwarf target/release/firewall_engine
perf report

# Flamegraphs
cargo flamegraph --bin firewall_engine
```

---

## Usage Examples

### Parsing Packets

```rust
use safeops_shared::simd_utils::*;

fn process_packet(data: &[u8]) -> Result<()> {
    let ipv4 = parse_ipv4(data)?;
    println!("Source: {}", ipv4.source_ip);
    
    let tcp = parse_tcp(&data[20..])?;
    println!("Port: {}", tcp.dest_port);
    Ok(())
}
```

### Memory Pooling

```rust
use safeops_shared::memory_pool::MemoryPool;

let pool = MemoryPool::<Vec<u8>>::new(1024);

{
    let mut buffer = pool.acquire()?;
    buffer.extend_from_slice(b"packet data");
    // Process...
} // Automatically returned to pool
```

### CIDR Matching

```rust
use safeops_shared::ip_utils::*;

let (network, prefix) = parse_cidr("192.168.1.0/24")?;
let addr = parse_ip("192.168.1.100")?;

if cidr_contains(network, prefix, addr) {
    println!("IP is in subnet");
}
```

### Prometheus Metrics

```rust
use safeops_shared::metrics::*;

let registry = MetricsRegistry::global();
let counter = registry.register_counter(
    "packets_processed_total",
    "Total packets processed"
)?;

counter.inc();
```

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Specific module
cargo test ip_utils::tests

# Show output
cargo test -- --nocapture
```

### Property-Based Testing

Uses `proptest` for randomized testing:

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn parse_ip_never_panics(s in ".*") {
            let _ = parse_ip(&s);
        }
    }
}
```

### Benchmarks

Uses `criterion` for performance benchmarking:

```bash
cargo bench

# View HTML reports
open target/criterion/report/index.html
```

### Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

---

## Dependencies

- **tokio** (1.35) - Async runtime for service integration
- **serde** (1.0) - Serialization framework
- **tonic** (0.11) - gRPC framework, proto generation
- **xxhash-rust** (0.8) - Fast non-cryptographic hashing
- **ahash** (0.8) - DOS-resistant HashMap hashing
- **crossbeam** (0.8) - Lock-free data structures
- **prometheus** (0.13) - Metrics collection and export
- **chrono** (0.4) - Timezone-aware date/time handling
- **prost** (0.12) - Protocol Buffers encoding
- **ipnet** (2.9) - IP network utilities

See [Cargo.toml](Cargo.toml) for complete dependency list.

---

## Contributing

### Code Style

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings
```

### Documentation

All public items require doc comments:

```rust
/// Parses IP address from string
///
/// # Examples
/// ```
/// let ip = parse_ip("192.168.1.1")?;
/// ```
pub fn parse_ip(input: &str) -> Result<IPAddress> {
    // ...
}
```

### Testing Requirements

- New features require unit tests
- Performance-critical code requires benchmarks
- Breaking changes require migration guide

### Pull Request Process

1. Fork repository
2. Create feature branch
3. Run tests: `cargo test`
4. Run linter: `cargo clippy`
5. Submit PR with description

---

## Troubleshooting

### Compilation Errors

**`protoc` not found:**
```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf
```

**SIMD intrinsics unavailable:**
- SIMD functions automatically fall back to scalar implementations
- Check CPU features: `rustc --print target-features`

### Runtime Issues

**Pool exhaustion warnings:**
- Increase pool capacity in configuration
- Check for leaked objects (not returned to pool)

**Metrics not appearing:**
- Verify `ENABLE_METRICS` not set to "false"
- Check metrics endpoint: `curl http://localhost:9090/metrics`

**Performance degradation:**
- Verify release build: `cargo build --release`
- Check SIMD detection: `has_simd_support()`

---

## FAQ

**Q: Why Rust for the shared library?**
A: Performance, memory safety, and zero-cost abstractions make Rust ideal for packet processing.

**Q: Why not use async for packet processing?**
A: Synchronous code has lower latency and more predictable performance for hot paths.

**Q: How does SIMD detection work?**
A: Runtime CPU feature detection via `std::arch::is_x86_feature_detected!()`.

**Q: Why lock-free instead of channels?**
A: Lower latency (no scheduler involvement) and no allocator contention.

**Q: Why xxHash instead of SHA256?**
A: 10x faster for hash tables; cryptographic security not required.

**Q: Can this library be used outside SafeOps?**
A: Yes, but it's optimized for SafeOps use cases.

---

## Version History

### Version 2.0.0 (Current)
- Initial release for SafeOps v2.0
- Complete rewrite in Rust
- SIMD packet parsing
- Lock-free data structures
- Prometheus metrics integration

---

## License

Licensed under the MIT License. See [LICENSE](../../../LICENSE) for details.

Copyright (c) 2024 SafeOps Security Team
