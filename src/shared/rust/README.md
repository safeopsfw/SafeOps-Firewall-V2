# SafeOps Rust Shared Library

High-performance Rust utilities providing zero-copy operations, SIMD acceleration, and memory-safe implementations for performance-critical components used by firewall_engine, threat_intel, and other services.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Modules](#modules)
  - [ip_utils](#-file-rustsrcip_utilsrs)
  - [error](#-file-rustsrcerrorrs)
  - [hash_utils](#-file-rustsrchash_utilsrs)
  - [memory_pool](#-file-rustsrcmemory_poolrs)
  - [lock_free](#-file-rustsrclock_freers)
  - [simd_utils](#-file-rustsrcsimd_utilsrs)
  - [time_utils](#-file-rustsrctime_utilsrs)
  - [proto_utils](#-file-rustsrcproto_utilsrs)
  - [buffer_pool](#-file-rustsrcbuffer_poolrs)
  - [metrics](#-file-rustsrcmetricsrs)
- [Build Instructions](#build-instructions)
- [Testing](#testing)
- [Benchmarks](#benchmarks)

---

## Overview

| Module | Purpose | Primary Users |
|--------|---------|---------------|
| `ip_utils` | IP parsing, CIDR matching | firewall_engine, threat_intel |
| `error` | Error types and handling | ALL modules |
| `hash_utils` | Fast hash functions | firewall_engine, network_logger |
| `memory_pool` | Object pooling | firewall_engine, network_logger |
| `lock_free` | Lock-free data structures | firewall_engine |
| `simd_utils` | SIMD packet parsing | firewall_engine |
| `time_utils` | Timestamps, rate limiting | ALL services |
| `proto_utils` | Protobuf helpers | ALL services |
| `buffer_pool` | Buffer management | network_logger |
| `metrics` | Prometheus metrics | ALL services |

**Total Lines**: ~3,000 LOC  
**Dependencies**: ipnet, ahash, xxhash-rust, crossbeam, parking_lot, prost, thiserror, prometheus, memchr

---

## 📄 FILE: rust/src/ip_utils.rs

**Purpose:** High-performance IP address parsing, validation, and CIDR matching utilities with zero-copy operations. Supports both IPv4 and IPv6 for firewall rule matching, threat intelligence lookups, and network traffic analysis.

**Key Functions:**

**Core IP Parsing:**
- `parse_ipv4(s: &str) -> Result<Ipv4Addr>` - Parse IPv4 address from string
- `parse_ipv6(s: &str) -> Result<Ipv6Addr>` - Parse IPv6 address from string
- `parse_ip(s: &str) -> Result<IpAddr>` - Auto-detect and parse IPv4 or IPv6
- `parse_cidr(s: &str) -> Result<IpNetwork>` - Parse CIDR notation (e.g., "192.168.1.0/24")

**CIDR Operations:**
- `is_in_cidr(ip: IpAddr, cidr: &IpNetwork) -> bool` - Check if IP is within CIDR range
- `cidrs_overlap(cidr1: &IpNetwork, cidr2: &IpNetwork) -> bool` - Check if two CIDRs overlap
- `network_address(cidr: &IpNetwork) -> IpAddr` - Extract network address from CIDR
- `broadcast_address(cidr: &Ipv4Network) -> Ipv4Addr` - Calculate broadcast address

**IP Classification:**
- `is_private(ip: IpAddr) -> bool` - RFC1918 private address check
- `is_loopback(ip: IpAddr) -> bool` - Loopback address check (127.0.0.0/8)
- `is_multicast(ip: IpAddr) -> bool` - Multicast address check
- `is_link_local(ip: IpAddr) -> bool` - Link-local address check
- `is_global(ip: IpAddr) -> bool` - Globally routable address check

**Performance Optimizations:**
- `ipv4_to_u32(ip: Ipv4Addr) -> u32` - Convert IPv4 to u32 for fast comparisons
- `u32_to_ipv4(n: u32) -> Ipv4Addr` - Convert u32 back to IPv4
- `prefix_to_netmask(prefix: u8) -> u32` - Convert CIDR prefix length to netmask

**Key Features:**
- **Zero Allocation**: Operations work with borrowed data, no unnecessary copies
- **SIMD Acceleration**: Uses AVX2 for batch IP parsing when available
- **IPv6 Support**: Full support for IPv6 addresses and networks
- **RFC Compliance**: Follows RFC1918, RFC4291, RFC4632

**Dependencies:**
- `std::net` - Standard library IP types
- `ipnet` crate - CIDR handling

**Used By Services:**
- firewall_engine - IP address rule matching
- threat_intel - IP reputation lookups
- ids_ips - Packet source/destination analysis
- network_logger - Packet metadata extraction

---

## 📄 FILE: rust/src/error.rs

**Purpose:** Centralized error handling with structured error types using thiserror. Provides consistent error propagation across all Rust modules with detailed context and stack traces.

**Error Types:**

**Core Errors:**
- `Error::Parse(String)` - Parsing failures (IP, config, proto)
- `Error::InvalidInput(String)` - Invalid user/config input
- `Error::Io(io::Error)` - I/O operation failures
- `Error::Allocation` - Memory allocation failures

**Concurrency Errors:**
- `Error::Lock(String)` - Lock acquisition failures
- `Error::Timeout(Duration)` - Operation timeout
- `Error::QueueFull` - Lock-free queue full
- `Error::QueueEmpty` - Lock-free queue empty

**Resource Errors:**
- `Error::PoolExhausted` - Object pool exhausted
- `Error::CapacityExceeded(usize)` - Capacity limit reached
- `Error::NotFound(String)` - Resource not found
- `Error::AlreadyExists(String)` - Resource already exists

**Data Errors:**
- `Error::Config(String)` - Configuration errors
- `Error::Serialization(String)` - Serialization failures
- `Error::Deserialization(String)` - Deserialization failures

**Generic:**
- `Error::Internal(String)` - Internal logic errors

**Key Features:**
- **Automatic From Conversions**: Converts from std::io::Error, parse errors
- **Display Formatting**: Human-readable error messages
- **Debug Formatting**: Detailed error context for debugging
- **Error Chain Support**: Preserves error chains with source()

**Type Aliases:**
- `pub type Result<T> = std::result::Result<T, Error>` - Convenient result type

**Dependencies:**
- `thiserror` - Declarative error derive macros
- `anyhow` - Error trait implementation

**Used By Services:**
- ALL Rust modules - Universal error type

---

## 📄 FILE: rust/src/hash_utils.rs

**Purpose:** High-performance hash functions for hash tables, bloom filters, and connection tracking. Provides non-cryptographic hash functions optimized for speed.

**Hash Functions:**

**xxHash3 (Primary):**
- `xxhash3_64(data: &[u8]) -> u64` - 64-bit xxHash3 (fastest)
- `xxhash3_128(data: &[u8]) -> u128` - 128-bit xxHash3 (better distribution)
- `xxhash3_64_with_seed(data: &[u8], seed: u64) -> u64` - Seeded variant

**aHash (Fallback):**
- `ahash(data: &[u8]) -> u64` - High-quality hash for HashMaps
- `ahash_with_seed(data: &[u8], seed: u64) -> u64` - Seeded variant

**Specialized Hashing:**
- `hash_ipv4(ip: Ipv4Addr) -> u64` - Fast IPv4 hash
- `hash_ipv6(ip: Ipv6Addr) -> u64` - Fast IPv6 hash
- `hash_5tuple(src_ip, dst_ip, src_port, dst_port, proto) -> u64` - Connection hash

**Consistent Hashing:**
- `ConsistentHash::new(nodes: Vec<String>) -> Self` - Create ring
- `add_node(&mut self, node: String)` - Add node to ring
- `remove_node(&mut self, node: &str)` - Remove node from ring
- `get_node(&self, key: &str) -> Option<&str>` - Find node for key

**Bloom Filter:**
- `BloomFilter::new(size: usize, num_hashes: u32) -> Self` - Create filter
- `insert(&mut self, item: &[u8])` - Add item
- `contains(&self, item: &[u8]) -> bool` - Check membership
- `clear(&mut self)` - Reset filter

**Performance:**
- xxHash3: ~50 GB/s on modern CPUs
- aHash: ~40 GB/s, better quality for HashMaps
- 5-tuple hash: <10ns per hash

**Key Features:**
- **Non-Cryptographic**: Optimized for speed, not security
- **Hardware Acceleration**: Uses AES-NI when available (aHash)
- **Deterministic**: Same input always produces same hash

**Dependencies:**
- `xxhash-rust` - xxHash3 implementation
- `ahash` - aHash implementation

**Used By Services:**
- firewall_engine - Connection tracking hash tables
- network_logger - Packet deduplication
- threat_intel - Bloom filters for IP reputation

---

## 📄 FILE: rust/src/memory_pool.rs

**Purpose:** Thread-safe object pooling to reduce allocation overhead. Pre-allocates objects and reuses them to minimize GC pressure and improve performance.

**Core Types:**

**ObjectPool:**
- `ObjectPool::new(capacity, factory, reset) -> Self` - Create pool
- `acquire(&self) -> Option<PooledObject<T>>` - Get object from pool
- `release(&self, obj: T)` - Return object to pool
- `stats(&self) -> PoolStats` - Get pool statistics

**PooledObject (RAII):**
- Automatic return to pool on drop
- Deref to inner object
- Clone creates new pooled instance

**Pool Statistics:**
- `created: usize` - Total objects created
- `acquired: usize` - Total acquisitions
- `released: usize` - Total releases
- `in_use: usize` - Currently in use
- `capacity: usize` - Maximum pool size

**Thread Safety:**
- Uses `crossbeam::queue::ArrayQueue` for lock-free access
- Atomic counters for statistics
- Safe to share across threads

**Memory Management:**
- `factory: Fn() -> T` - Creates new objects when pool empty
- `reset: Fn(&mut T)` - Cleans object before reuse
- Automatic capacity limiting

**Example Use Cases:**
- Packet buffer pooling (4KB buffers)
- Connection state pooling
- Parser object reuse

**Performance:**
- Acquire: O(1) amortized
- Release: O(1)
- No locks on fast path

**Key Features:**
- **Zero-Copy**: Objects reused without cloning
- **Thread-Safe**: Lock-free implementation
- **RAII**: Automatic return via Drop
- **Bounded**: Prevents unbounded growth

**Dependencies:**
- `crossbeam` - Lock-free queue
- `std::sync::atomic` - Atomic counters

**Used By Services:**
- firewall_engine - Connection state pooling
- network_logger - Buffer pooling

---

## 📄 FILE: rust/src/lock_free.rs

**Purpose:** Lock-free data structures for high-concurrency scenarios. Provides wait-free and lock-free queues for multi-producer, multi-consumer patterns.

**Data Structures:**

**LockFreeQueue (MPMC):**
- `LockFreeQueue::new(capacity) -> Self` - Create bounded queue
- `push(&self, item: T) -> Result<()>` - Push item (wait-free)
- `pop(&self) -> Option<T>` - Pop item (wait-free)
- `len(&self) -> usize` - Current size
- `capacity(&self) -> usize` - Maximum capacity

**SPSCChannel (Single Producer, Single Consumer):**
- `channel<T>(capacity) -> (Sender<T>, Receiver<T>)` - Create channel
- `Sender::send(&self, item: T) -> Result<()>` - Send item
- `Receiver::recv(&self) -> Option<T>` - Receive item
- `Receiver::try_recv(&self) -> Option<T>` - Non-blocking receive

**LockFreeStack:**
- `LockFreeStack::new() -> Self` - Create unbounded stack
- `push(&self, item: T)` - Push item
- `pop(&self) -> Option<T>` - Pop item

**Ring Buffer (Producer/Consumer):**
- `RingBuffer::new(capacity) -> Self` - Create ring buffer
- `write(&mut self, data: &[u8]) -> usize` - Write data
- `read(&mut self, buf: &mut [u8]) -> usize` - Read data
- `available(&self) -> usize` - Bytes available to read

**Performance:**
- Push/Pop: ~50ns per operation
- Zero contention on single producer/consumer
- Minimal contention on MPMC

**Key Features:**
- **Wait-Free**: Operations finish in bounded time
- **Lock-Free**: No mutex/spinlock overhead
- **Cache-Friendly**: Minimizes cache line bouncing
- **Bounded**: Prevents OOM with capacity limits

**Dependencies:**
- `crossbeam` - Lock-free queue implementation
- `std::sync::atomic` - Atomic operations

**Used By Services:**
- firewall_engine - Packet queue between threads

---

## 📄 FILE: rust/src/simd_utils.rs

**Purpose:** SIMD-accelerated packet parsing and byte operations. Leverages AVX2/AVX-512 for high-throughput packet processing.

**Packet Parsing:**

**IPv4 Header:**
- `parse_ipv4_header(data: &[u8]) -> Result<Ipv4Header>` - Parse IPv4 header
- `Ipv4Header::version(&self) -> u8` - IP version
- `Ipv4Header::ihl(&self) -> u8` - Header length
- `Ipv4Header::total_length(&self) -> u16` - Total packet length
- `Ipv4Header::protocol(&self) -> u8` - Protocol (TCP/UDP/ICMP)
- `Ipv4Header::src_addr(&self) -> Ipv4Addr` - Source IP
- `Ipv4Header::dst_addr(&self) -> Ipv4Addr` - Destination IP

**TCP Header:**
- `parse_tcp_header(data: &[u8]) -> Result<TcpHeader>` - Parse TCP header
- `TcpHeader::src_port(&self) -> u16` - Source port
- `TcpHeader::dst_port(&self) -> u16` - Destination port
- `TcpHeader::seq_num(&self) -> u32` - Sequence number
- `TcpHeader::ack_num(&self) -> u32` - Acknowledgment number
- `TcpHeader::flags(&self) -> TcpFlags` - TCP flags

**UDP Header:**
- `parse_udp_header(data: &[u8]) -> Result<UdpHeader>` - Parse UDP header
- `UdpHeader::src_port(&self) -> u16` - Source port
- `UdpHeader::dst_port(&self) -> u16` - Destination port
- `UdpHeader::length(&self) -> u16` - Datagram length

**Byte Operations:**
- `find_byte(haystack: &[u8], needle: u8) -> Option<usize>` - SIMD byte search
- `find_pattern(haystack: &[u8], pattern: &[u8]) -> Option<usize>` - Pattern match
- `count_bytes(data: &[u8], byte: u8) -> usize` - Count byte occurrences

**Checksum:**
- `internet_checksum(data: &[u8]) -> u16` - RFC 1071 checksum
- `tcp_checksum(ip_hdr: &Ipv4Header, tcp_data: &[u8]) -> u16` - TCP checksum
- `udp_checksum(ip_hdr: &Ipv4Header, udp_data: &[u8]) -> u16` - UDP checksum

**Performance:**
- IPv4 parse: ~5ns per packet
- TCP parse: ~8ns per packet
- Byte search: ~50 GB/s (with AVX2)

**Key Features:**
- **Zero-Copy**: Works on packet slices directly
- **SIMD**: Uses AVX2/AVX-512 when available
- **Fallback**: Pure Rust fallback for non-AVX CPUs

**Dependencies:**
- `memchr` - SIMD byte searching

**Used By Services:**
- firewall_engine - Fast packet parsing

---

## 📄 FILE: rust/src/time_utils.rs

**Purpose:** High-precision timestamps, stopwatch, and rate limiting utilities. Provides consistent time operations across all services.

**Timestamp Functions:**
- `unix_timestamp_secs() -> u64` - Current Unix timestamp (seconds)
- `unix_timestamp_millis() -> u64` - Current Unix timestamp (milliseconds)
- `unix_timestamp_micros() -> u64` - Current Unix timestamp (microseconds)
- `unix_timestamp_nanos() -> u128` - Current Unix timestamp (nanoseconds)

**Stopwatch:**
- `Stopwatch::new() -> Self` - Create stopped stopwatch
- `start(&mut self)` - Start/resume timing
- `stop(&mut self)` - Stop timing
- `reset(&mut self)` - Reset to zero
- `elapsed(&self) -> Duration` - Get elapsed time
- `elapsed_millis(&self) -> u64` - Get elapsed milliseconds

**Rate Limiting:**
- `TokenBucket::new(rate, capacity) -> Self` - Create token bucket
- `acquire(&mut self) -> bool` - Try to acquire token
- `acquire_n(&mut self, n: u32) -> bool` - Try to acquire n tokens
- `refill(&mut self)` - Refill tokens based on elapsed time

**Timing Utilities:**
- `sleep_until(deadline: Instant)` - Sleep until specific time
- `retry_with_backoff<F>(f: F, max_attempts, base_delay)` - Exponential backoff

**Performance:**
- Timestamp: ~10ns (TSC-based)
- Token bucket: <20ns per acquire

**Key Features:**
- **High Precision**: Nanosecond resolution
- **Monotonic**: Uses Instant for reliable timing
- **Low Overhead**: TSC-based on x86_64

**Dependencies:**
- `std::time` - Standard time types

**Used By Services:**
- ALL services - Metrics, logging, rate limiting

---

## 📄 FILE: rust/src/proto_utils.rs

**Purpose:** Protobuf encoding/decoding helpers with length-prefixed message support. Simplifies protobuf operations for gRPC services.

**Core Functions:**
- `encode<M: Message>(msg: &M) -> Vec<u8>` - Encode protobuf message
- `decode<M: Message + Default>(bytes: &[u8]) -> Result<M>` - Decode message
- `encode_length_delimited<M: Message>(msg: &M) -> Vec<u8>` - Encode with length prefix
- `decode_length_delimited<M: Message + Default>(bytes: &[u8]) -> Result<(M, usize)>` - Decode length-prefixed

**Validation:**
- `validate_message<M: Message>(msg: &M) -> Result<()>` - Validate message fields
- `is_valid<M: Message>(msg: &M) -> bool` - Check if message is valid

**Serialization:**
- `to_json<M: Message>(msg: &M) -> Result<String>` - Convert to JSON
- `from_json<M: Message + Default>(json: &str) -> Result<M>` - Parse from JSON

**Performance:**
- Encode: ~100ns per small message
- Decode: ~150ns per small message

**Key Features:**
- **Type-Safe**: Uses prost generated types
- **Length-Delimited**: Supports streaming protocols
- **JSON Support**: Debug-friendly JSON conversion

**Dependencies:**
- `prost` - Protobuf codec

**Used By Services:**
- ALL Rust services - gRPC communication

---

## 📄 FILE: rust/src/buffer_pool.rs

**Purpose:** Efficient buffer pooling for packet data. Reduces allocation overhead by reusing pre-allocated byte buffers.

**Core Types:**
- `BufferPool::new(buffer_size, capacity) -> Self` - Create pool
- `get(&self) -> Vec<u8>` - Get buffer from pool (or allocate new)
- `put(&self, buf: Vec<u8>)` - Return buffer to pool
- `stats(&self) -> BufferStats` - Get statistics

**Buffer Chain:**
- `BufferChain::new() -> Self` - Create buffer chain
- `append(&mut self, data: &[u8])` - Append data
- `to_vec(&self) -> Vec<u8>` - Flatten to single vector
- `len(&self) -> usize` - Total length

**Zero-Copy View:**
- `BufferView::new(data: &[u8]) -> Self` - Create view
- `slice(&self, start: usize, len: usize) -> &[u8]` - Get slice
- `split_at(&self, mid: usize) -> (BufferView, BufferView)` - Split view

**Performance:**
- Get/Put: <50ns
- Zero allocations on steady state

**Key Features:**
- **Pre-Allocation**: Buffers allocated at startup
- **Size-Based**: Different pools for different sizes
- **Thread-Safe**: Lock-free implementation

**Dependencies:**
- `crossbeam` - Lock-free queue

**Used By Services:**
- network_logger - Packet buffer reuse

---

## 📄 FILE: rust/src/metrics.rs

**Purpose:** Prometheus metrics collection and export. Provides counters, gauges, and histograms for monitoring.

**Metric Types:**

**Counter:**
- `Counter::new() -> Self` - Create counter
- `inc(&self)` - Increment by 1
- `add(&self, n: u64)` - Add value
- `get(&self) -> u64` - Get current value
- `reset(&self)` - Reset to zero

**Gauge:**
- `Gauge::new() -> Self` - Create gauge
- `set(&self, value: f64)` - Set value
- `inc(&self)` - Increment
- `dec(&self)` - Decrement
- `add(&self, delta: f64)` - Add delta
- `sub(&self, delta: f64)` - Subtract delta

**Histogram:**
- `Histogram::new(buckets: Vec<f64>) -> Self` - Create histogram
- `observe(&self, value: f64)` - Record observation
- `time<F: FnOnce() -> R>(&self, f: F) -> R` - Time function execution

**Registry:**
- `MetricsRegistry::new(prefix: String) -> Self` - Create registry
- `register_counter(&mut self, name: &str) -> Arc<Counter>` - Register counter
- `register_gauge(&mut self, name: &str) -> Arc<Gauge>` - Register gauge
- `register_histogram(&mut self, name: &str, buckets: Vec<f64>) -> Arc<Histogram>` - Register histogram
- `export(&self) -> String` - Export Prometheus format

**Performance:**
- Counter inc: ~15ns
- Histogram observe: ~40ns
- Gauge set: ~20ns

**Key Features:**
- **Thread-Safe**: Lock-free atomic operations
- **Prometheus Format**: Standard exposition format
- **Low Overhead**: Minimal performance impact

**Dependencies:**
- `std::sync::atomic` - Atomic operations

**Used By Services:**
- ALL services - Performance monitoring

---

## Build Instructions

```bash
# Build library
cd src/shared/rust
cargo build --release

# Build with all features
cargo build --release --all-features

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check for errors
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

---

## Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test ip_utils::tests

# Run with output
cargo test -- --nocapture

# Run ignored tests (for benchmarks)
cargo test -- --ignored
```

---

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench hash_utils

# Save baseline
cargo bench -- --save-baseline main

# Compare to baseline
cargo bench -- --baseline main
```

**Expected Performance:**
- IP parsing: ~30ns per IP
- xxHash3: ~50 GB/s
- SIMD packet parse: ~5ns per packet
- Token bucket: ~20ns per acquire
- Buffer pool: ~50ns get/put
