# PHASE 10: PERFORMANCE OPTIMIZATION

**Status:** 🔜 Future Phase (After Phase 9 Complete)
**Duration:** 3-4 weeks
**Goal:** Handle 100K+ packets/sec with <1ms latency
**Deliverable:** Production-grade firewall performance with profiling, benchmarks, and optimization

---

## 📋 Phase Overview

**What Changes in Phase 10:**
- **Phase 9 Reality:** Firewall works (rules, filtering, logging), but performance not optimized (20-50K pps, 5-10ms latency)
- **Phase 10 Goal:** Optimize to handle 100K+ packets/sec with <1ms added latency (production-grade performance)
- **Focus Areas:** Memory management, CPU efficiency, batch processing, multi-threading, profiling

**Current Performance (Unoptimized):**
```
Baseline (Phase 9):
├─ Throughput: 20,000-50,000 packets/sec
├─ Latency: 5-10ms added per packet
├─ CPU usage: 80-100% on single core
├─ Memory: 500MB-1GB (growing, GC pressure)
└─ Bottlenecks: Memory allocations, packet copying, lock contention
```

**Target Performance (Phase 10):**
```
Goal:
├─ Throughput: 100,000+ packets/sec (2-5× improvement)
├─ Latency: <1ms added per packet (5-10× improvement)
├─ CPU usage: 40-60% across multiple cores (efficient)
├─ Memory: 200-500MB stable (no growth, minimal GC)
└─ Optimizations: Zero-copy, memory pooling, batching, multi-threading
```

**Dependencies:**
- ✅ Phase 1-9: All firewall functionality complete
- ✅ Phase 8: Logging infrastructure (need to optimize)
- ✅ Phase 9: TLS interception (heaviest workload)
- ✅ External: Production traffic patterns (need realistic benchmarks)

---

## 🎯 Phase 10 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup (Performance Mode):**
```
[INFO] Firewall Engine v10.0.0 Starting...
[INFO] Performance Optimizations: ENABLED
[INFO] ├─ Zero-Copy Mode: ENABLED
[INFO] ├─ Memory Pooling: ENABLED (100K buffers pre-allocated)
[INFO] ├─ Batch Processing: ENABLED (batch size: 100)
[INFO] ├─ Worker Threads: 8 (auto-detected from CPU cores)
[INFO] ├─ CPU Affinity: ENABLED (pinned to cores 0-7)
[INFO] ├─ NUMA Awareness: ENABLED (node 0)
[INFO] └─ Profiling: ENABLED (pprof port: 6060)
[INFO] Memory Pre-Allocation:
[INFO] ├─ Packet buffers: 100,000 × 2KB = 200MB
[INFO] ├─ PacketMetadata pool: 100,000 × 512B = 50MB
[INFO] ├─ Connection objects: 50,000 × 1KB = 50MB
[INFO] └─ Total reserved: 300MB (locked, no GC)
[INFO] Benchmark Results (startup self-test):
[INFO] ├─ Rule matching: 125,000 pps (8μs per packet)
[INFO] ├─ DNS filtering: 200,000 pps (5μs per packet)
[INFO] ├─ TLS SNI parsing: 150,000 pps (6.7μs per packet)
[INFO] ├─ TLS interception: 80,000 pps (12.5μs per packet)
[INFO] └─ Full pipeline: 105,000 pps (9.5μs per packet)
[INFO] Performance Target: ✅ MET (target: 100K pps, actual: 105K pps)
[INFO] Latency Target: ✅ MET (target: <1ms, actual: 0.6ms avg)
[INFO] Firewall Ready (Optimized Mode)
```

**Runtime Metrics (Prometheus /metrics endpoint):**
```
# HELP firewall_packets_per_second Current packet processing rate
# TYPE firewall_packets_per_second gauge
firewall_packets_per_second 102847

# HELP firewall_latency_microseconds Packet processing latency histogram
# TYPE firewall_latency_microseconds histogram
firewall_latency_microseconds_bucket{le="100"} 985342    # <0.1ms: 98.5%
firewall_latency_microseconds_bucket{le="500"} 998521    # <0.5ms: 99.8%
firewall_latency_microseconds_bucket{le="1000"} 999876   # <1ms: 99.98%
firewall_latency_microseconds_bucket{le="5000"} 1000000  # <5ms: 100%
firewall_latency_microseconds_sum 623451000              # Total: 623ms
firewall_latency_microseconds_count 1000000              # Count: 1M packets

# HELP firewall_memory_pool_usage Memory pool utilization
# TYPE firewall_memory_pool_usage gauge
firewall_memory_pool_usage{pool="packet_buffers"} 0.67       # 67% used
firewall_memory_pool_usage{pool="metadata_objects"} 0.54     # 54% used
firewall_memory_pool_usage{pool="connection_objects"} 0.32   # 32% used

# HELP firewall_gc_pause_milliseconds GC pause duration
# TYPE firewall_gc_pause_milliseconds histogram
firewall_gc_pause_milliseconds_bucket{le="1"} 9847      # <1ms: 98.47%
firewall_gc_pause_milliseconds_bucket{le="5"} 9998      # <5ms: 99.98%
firewall_gc_pause_milliseconds_bucket{le="10"} 10000    # <10ms: 100%
firewall_gc_pause_milliseconds_sum 12453                # Total: 12.4s in 24h
firewall_gc_pause_milliseconds_count 10000              # GC runs: 10K in 24h

# HELP firewall_cpu_usage_percent CPU usage per worker
# TYPE firewall_cpu_usage_percent gauge
firewall_cpu_usage_percent{worker="0"} 52.3
firewall_cpu_usage_percent{worker="1"} 54.1
firewall_cpu_usage_percent{worker="2"} 51.8
firewall_cpu_usage_percent{worker="3"} 53.6
firewall_cpu_usage_percent{worker="4"} 52.9
firewall_cpu_usage_percent{worker="5"} 51.4
firewall_cpu_usage_percent{worker="6"} 52.7
firewall_cpu_usage_percent{worker="7"} 53.2
firewall_cpu_usage_percent{total="avg"} 52.75          # Avg: 52.75%

# HELP firewall_batch_efficiency Batch processing efficiency
# TYPE firewall_batch_efficiency gauge
firewall_batch_efficiency{operation="rule_matching"} 0.98     # 98% batched
firewall_batch_efficiency{operation="log_writes"} 0.95        # 95% batched
firewall_batch_efficiency{operation="db_inserts"} 0.92        # 92% batched
```

**CLI Output (Real-Time Stats):**
```
$ ./firewall-engine --performance-mode

╔════════════════════════════════════════════════════════════════╗
║         FIREWALL ENGINE v10.0 - PERFORMANCE MODE               ║
╠════════════════════════════════════════════════════════════════╣
║  Uptime: 1h 23m 47s                                            ║
║  Packets Processed: 428,547,293                                ║
║  Throughput: 102,847 pps (↑ 2.3%)                              ║
║  Latency (avg): 0.62ms  P50: 0.51ms  P95: 0.89ms  P99: 1.2ms  ║
║  CPU Usage: 52.8% (8 cores)  Memory: 347MB / 300MB (stable)   ║
║  GC Pause: 1.2ms avg (last 100 runs)                           ║
╠════════════════════════════════════════════════════════════════╣
║  WORKER POOL STATUS:                                           ║
║  ├─ Worker 0 [Core 0]: 13,245 pps  52.3% CPU  ████████░░      ║
║  ├─ Worker 1 [Core 1]: 13,521 pps  54.1% CPU  █████████░      ║
║  ├─ Worker 2 [Core 2]: 12,987 pps  51.8% CPU  ████████░░      ║
║  ├─ Worker 3 [Core 3]: 13,412 pps  53.6% CPU  █████████░      ║
║  ├─ Worker 4 [Core 4]: 13,198 pps  52.9% CPU  ████████░░      ║
║  ├─ Worker 5 [Core 5]: 12,854 pps  51.4% CPU  ████████░░      ║
║  ├─ Worker 6 [Core 6]: 13,087 pps  52.7% CPU  ████████░░      ║
║  └─ Worker 7 [Core 7]: 13,143 pps  53.2% CPU  █████████░      ║
╠════════════════════════════════════════════════════════════════╣
║  MEMORY POOL STATUS:                                           ║
║  ├─ Packet Buffers: 67,234 / 100,000 (67% used) ██████░░░░    ║
║  ├─ Metadata Objects: 54,128 / 100,000 (54% used) █████░░░░░  ║
║  └─ Connection Objects: 16,543 / 50,000 (32% used) ███░░░░░░░ ║
╠════════════════════════════════════════════════════════════════╣
║  BATCH PROCESSING:                                             ║
║  ├─ Rule Matching: 98% efficiency (avg batch: 87 packets)     ║
║  ├─ Log Writes: 95% efficiency (avg batch: 73 packets)        ║
║  └─ DB Inserts: 92% efficiency (avg batch: 64 packets)        ║
╠════════════════════════════════════════════════════════════════╣
║  BOTTLENECK ANALYSIS:                                          ║
║  ├─ Rule Matching: ✅ 8μs (target: <10μs)                      ║
║  ├─ DNS Filtering: ✅ 5μs (target: <10μs)                      ║
║  ├─ TLS Parsing: ✅ 6.7μs (target: <10μs)                      ║
║  ├─ TLS Interception: ⚠️ 12.5μs (target: <15μs, acceptable)   ║
║  ├─ Log Writes: ✅ 2μs (batched, async)                        ║
║  └─ DB Inserts: ✅ 50μs (batched, async)                       ║
╠════════════════════════════════════════════════════════════════╣
║  PERFORMANCE TARGETS:                                          ║
║  ├─ Throughput: ✅ 102,847 pps (target: 100K pps)              ║
║  ├─ Latency: ✅ 0.62ms avg (target: <1ms)                      ║
║  ├─ P99 Latency: ⚠️ 1.2ms (target: <1ms, close)               ║
║  ├─ CPU Efficiency: ✅ 52.8% (target: <60%)                    ║
║  ├─ Memory Stability: ✅ 347MB (target: <500MB, no growth)     ║
║  └─ GC Impact: ✅ 1.2ms avg (target: <5ms)                     ║
╚════════════════════════════════════════════════════════════════╝

[Press 'p' for profiler, 'b' for benchmark, 'q' to quit]
```

---

## 🔧 Sub-Task Breakdown

### **1. Zero-Copy Optimizations** (`internal/performance/zero_copy.go`)

**Problem (Before Optimization):**
```go
// BEFORE: Copying packet data everywhere (SLOW!)
func processPacket(packet []byte) Verdict {
    // Copy 1: Parse packet (copy to new buffer)
    parsedPacket := parsePacket(packet)  // Allocates new []byte

    // Copy 2: Extract metadata (copy struct)
    metadata := extractMetadata(parsedPacket)  // Copies 512 bytes

    // Copy 3: Log packet (copy for async logging)
    logData := copyForLogging(metadata)  // Another copy

    // Copy 4: Database insert (copy for async DB)
    dbData := copyForDatabase(metadata)  // Yet another copy

    return verdict
}

Result: 4 copies per packet × 2KB per packet × 50K pps = 400MB/sec copied!
        GC pressure: High (allocating 400MB/sec)
        Latency: +5-10ms (memory allocations + GC pauses)
```

**Solution (Zero-Copy Approach):**
```go
// AFTER: Use pointers, avoid copies (FAST!)
package performance

import (
    "sync"
    "unsafe"
)

// ZeroCopyPacket - Reference to original packet data (no copy)
type ZeroCopyPacket struct {
    Data   unsafe.Pointer  // Pointer to original packet buffer
    Length uint32
    RefCount int32  // Reference counter (for safe deallocation)
}

// PacketView - Zero-copy view into packet data
type PacketView struct {
    packet *ZeroCopyPacket
    offset uint32
    length uint32
}

// NewZeroCopyPacket - Wrap existing packet data (no copy)
func NewZeroCopyPacket(data []byte) *ZeroCopyPacket {
    return &ZeroCopyPacket{
        Data:   unsafe.Pointer(&data[0]),
        Length: uint32(len(data)),
        RefCount: 1,
    }
}

// GetBytes - Get byte slice view (no copy)
func (p *ZeroCopyPacket) GetBytes() []byte {
    return (*[1 << 30]byte)(p.Data)[:p.Length:p.Length]
}

// CreateView - Create sub-view of packet (no copy)
func (p *ZeroCopyPacket) CreateView(offset, length uint32) PacketView {
    atomic.AddInt32(&p.RefCount, 1)  // Increment ref count
    return PacketView{
        packet: p,
        offset: offset,
        length: length,
    }
}

// Release - Decrement ref count, free if zero
func (p *ZeroCopyPacket) Release() {
    if atomic.AddInt32(&p.RefCount, -1) == 0 {
        // Last reference released, safe to free
        PacketBufferPool.Put(p)  // Return to pool (no dealloc)
    }
}

// Example: Zero-copy packet processing
func processPacketZeroCopy(packet *ZeroCopyPacket) Verdict {
    // No copies! Just create views (pointers)
    ipHeader := packet.CreateView(0, 20)       // IP header view
    tcpHeader := packet.CreateView(20, 20)     // TCP header view
    payload := packet.CreateView(40, packet.Length - 40)  // Payload view

    // Pass views to functions (no copying)
    metadata := extractMetadataZeroCopy(&ipHeader, &tcpHeader)

    // Async operations use pointers (no copy)
    go logPacketAsync(metadata)      // Pointer to metadata
    go insertDatabaseAsync(metadata) // Same pointer

    return verdict
}

Result: 0 copies per packet (just pointers!)
        Memory allocations: 0 (reuse from pool)
        Latency: -5ms (eliminated copy overhead)
```

**Implementation Details:**
```go
// internal/performance/zero_copy.go

package performance

import (
    "sync"
    "sync/atomic"
    "unsafe"
)

// ZeroCopyConfig - Configuration for zero-copy mode
type ZeroCopyConfig struct {
    Enabled          bool
    MaxPacketSize    uint32  // Max packet size (default: 2KB)
    ValidatePointers bool    // Validate unsafe pointers (debug mode)
}

// ZeroCopyManager - Manages zero-copy packet processing
type ZeroCopyManager struct {
    config  ZeroCopyConfig
    pools   *MemoryPoolManager
    metrics *ZeroCopyMetrics
}

// ZeroCopyMetrics - Performance metrics
type ZeroCopyMetrics struct {
    TotalPackets      uint64
    ZeroCopyPackets   uint64  // Packets processed without copy
    FallbackCopies    uint64  // Packets that needed copy (fallback)
    BytesSaved        uint64  // Bytes not copied (saved)
    AvgRefCount       float64 // Avg references per packet
}

func NewZeroCopyManager(config ZeroCopyConfig, pools *MemoryPoolManager) *ZeroCopyManager {
    return &ZeroCopyManager{
        config:  config,
        pools:   pools,
        metrics: &ZeroCopyMetrics{},
    }
}

// WrapPacket - Wrap existing packet data (zero-copy)
func (m *ZeroCopyManager) WrapPacket(data []byte) *ZeroCopyPacket {
    if !m.config.Enabled {
        // Zero-copy disabled, fallback to copy
        atomic.AddUint64(&m.metrics.FallbackCopies, 1)
        return m.copyPacket(data)
    }

    packet := &ZeroCopyPacket{
        Data:     unsafe.Pointer(&data[0]),
        Length:   uint32(len(data)),
        RefCount: 1,
    }

    atomic.AddUint64(&m.metrics.ZeroCopyPackets, 1)
    atomic.AddUint64(&m.metrics.BytesSaved, uint64(len(data)))

    return packet
}

// SafeRead - Read bytes from packet (with bounds checking)
func (p *ZeroCopyPacket) SafeRead(offset, length uint32) ([]byte, error) {
    if offset+length > p.Length {
        return nil, errors.New("read out of bounds")
    }

    // Safe slice from unsafe pointer
    fullData := (*[1 << 30]byte)(p.Data)[:p.Length:p.Length]
    return fullData[offset : offset+length], nil
}

// GetMetrics - Get zero-copy performance metrics
func (m *ZeroCopyManager) GetMetrics() ZeroCopyMetrics {
    return ZeroCopyMetrics{
        TotalPackets:    atomic.LoadUint64(&m.metrics.TotalPackets),
        ZeroCopyPackets: atomic.LoadUint64(&m.metrics.ZeroCopyPackets),
        FallbackCopies:  atomic.LoadUint64(&m.metrics.FallbackCopies),
        BytesSaved:      atomic.LoadUint64(&m.metrics.BytesSaved),
    }
}

// PrintMetrics - Print zero-copy statistics
func (m *ZeroCopyManager) PrintMetrics() {
    metrics := m.GetMetrics()
    fmt.Printf("Zero-Copy Statistics:\n")
    fmt.Printf("├─ Total Packets: %d\n", metrics.TotalPackets)
    fmt.Printf("├─ Zero-Copy: %d (%.1f%%)\n",
        metrics.ZeroCopyPackets,
        float64(metrics.ZeroCopyPackets)/float64(metrics.TotalPackets)*100)
    fmt.Printf("├─ Fallback Copies: %d (%.1f%%)\n",
        metrics.FallbackCopies,
        float64(metrics.FallbackCopies)/float64(metrics.TotalPackets)*100)
    fmt.Printf("└─ Bytes Saved: %s (not copied)\n",
        humanize.Bytes(metrics.BytesSaved))
}
```

**Performance Impact:**
```
Before Zero-Copy:
├─ Copies per packet: 4
├─ Memory allocated: 400MB/sec (50K pps × 8KB copied)
├─ GC pauses: 50-100ms every 10 seconds (high pressure)
└─ Latency: +5-10ms (allocations + GC)

After Zero-Copy:
├─ Copies per packet: 0 (just pointers)
├─ Memory allocated: 0MB/sec (reuse pool)
├─ GC pauses: 1-5ms every 60 seconds (minimal pressure)
└─ Latency: +0.5-1ms (pointer operations only)

Improvement: 5-10× faster (10ms → 1ms latency)
```

---

### **2. Memory Pooling** (`internal/performance/memory_pool.go`)

**Problem (Before Pooling):**
```go
// BEFORE: Allocate on every packet (SLOW!)
func processPacket(data []byte) {
    // Allocate new buffer (GC pressure!)
    buffer := make([]byte, 2048)
    copy(buffer, data)

    // Allocate new metadata struct
    metadata := &PacketMetadata{
        SrcIP: parseIP(buffer),
        DstIP: parseIP(buffer[4:]),
        // ... more fields
    }

    // Allocate connection object
    conn := &Connection{
        State: STATE_NEW,
        // ... more fields
    }

    // Process packet...

    // Objects go out of scope → GC collects later
}

Result: 50K allocations/sec → GC runs constantly
        GC pause: 50-100ms (stop-the-world)
        Memory: 500MB → 1GB → 500MB (sawtooth pattern)
```

**Solution (Memory Pooling):**
```go
// AFTER: Reuse pre-allocated objects (FAST!)
package performance

import (
    "sync"
)

// Memory pools for different object types
var (
    PacketBufferPool = sync.Pool{
        New: func() interface{} {
            return make([]byte, 2048)  // Pre-allocate 2KB buffer
        },
    }

    MetadataPool = sync.Pool{
        New: func() interface{} {
            return &PacketMetadata{}
        },
    }

    ConnectionPool = sync.Pool{
        New: func() interface{} {
            return &Connection{}
        },
    }
)

// Example: Use pooled objects
func processPacketPooled(data []byte) {
    // Get buffer from pool (reuse!)
    buffer := PacketBufferPool.Get().([]byte)
    copy(buffer, data)

    // Get metadata from pool
    metadata := MetadataPool.Get().(*PacketMetadata)
    metadata.Reset()  // Clear previous data
    metadata.SrcIP = parseIP(buffer)
    metadata.DstIP = parseIP(buffer[4:])

    // Get connection from pool
    conn := ConnectionPool.Get().(*Connection)
    conn.Reset()
    conn.State = STATE_NEW

    // Process packet...

    // Return objects to pool (reuse later!)
    PacketBufferPool.Put(buffer)
    MetadataPool.Put(metadata)
    ConnectionPool.Put(conn)
}

Result: 0 allocations/sec (reuse pool)
        GC pause: 1-5ms (minimal pressure)
        Memory: 300MB stable (no sawtooth)
```

**Advanced Pooling Implementation:**
```go
// internal/performance/memory_pool.go

package performance

import (
    "sync"
    "sync/atomic"
)

// MemoryPoolConfig - Configuration for memory pools
type MemoryPoolConfig struct {
    PacketBufferSize    uint32  // Size per buffer (default: 2KB)
    PacketBufferCount   uint32  // Pre-allocate count (default: 100K)
    MetadataPoolSize    uint32  // Metadata objects (default: 100K)
    ConnectionPoolSize  uint32  // Connection objects (default: 50K)
    EnableWarmup        bool    // Pre-populate pools at startup
}

// MemoryPoolManager - Manages all memory pools
type MemoryPoolManager struct {
    config             MemoryPoolConfig
    packetBufferPool   *sync.Pool
    metadataPool       *sync.Pool
    connectionPool     *sync.Pool
    metrics            *PoolMetrics
}

// PoolMetrics - Pool utilization metrics
type PoolMetrics struct {
    BufferGets      uint64
    BufferPuts      uint64
    BufferMisses    uint64  // Pool empty, allocated new
    MetadataGets    uint64
    MetadataPuts    uint64
    ConnectionGets  uint64
    ConnectionPuts  uint64
}

func NewMemoryPoolManager(config MemoryPoolConfig) *MemoryPoolManager {
    manager := &MemoryPoolManager{
        config:  config,
        metrics: &PoolMetrics{},
    }

    // Create packet buffer pool
    manager.packetBufferPool = &sync.Pool{
        New: func() interface{} {
            atomic.AddUint64(&manager.metrics.BufferMisses, 1)
            return make([]byte, config.PacketBufferSize)
        },
    }

    // Create metadata pool
    manager.metadataPool = &sync.Pool{
        New: func() interface{} {
            return &PacketMetadata{}
        },
    }

    // Create connection pool
    manager.connectionPool = &sync.Pool{
        New: func() interface{} {
            return &Connection{}
        },
    }

    // Warmup pools if enabled
    if config.EnableWarmup {
        manager.warmupPools()
    }

    return manager
}

// warmupPools - Pre-populate pools at startup
func (m *MemoryPoolManager) warmupPools() {
    log.Info("Warming up memory pools...")

    // Pre-allocate packet buffers
    buffers := make([][]byte, m.config.PacketBufferCount)
    for i := range buffers {
        buffers[i] = make([]byte, m.config.PacketBufferSize)
    }
    for _, buf := range buffers {
        m.packetBufferPool.Put(buf)
    }

    // Pre-allocate metadata objects
    metadatas := make([]*PacketMetadata, m.config.MetadataPoolSize)
    for i := range metadatas {
        metadatas[i] = &PacketMetadata{}
    }
    for _, md := range metadatas {
        m.metadataPool.Put(md)
    }

    // Pre-allocate connection objects
    connections := make([]*Connection, m.config.ConnectionPoolSize)
    for i := range connections {
        connections[i] = &Connection{}
    }
    for _, conn := range connections {
        m.connectionPool.Put(conn)
    }

    log.Infof("Memory pools warmed up: %d buffers, %d metadata, %d connections",
        m.config.PacketBufferCount,
        m.config.MetadataPoolSize,
        m.config.ConnectionPoolSize)
}

// GetPacketBuffer - Get buffer from pool
func (m *MemoryPoolManager) GetPacketBuffer() []byte {
    atomic.AddUint64(&m.metrics.BufferGets, 1)
    return m.packetBufferPool.Get().([]byte)
}

// PutPacketBuffer - Return buffer to pool
func (m *MemoryPoolManager) PutPacketBuffer(buf []byte) {
    atomic.AddUint64(&m.metrics.BufferPuts, 1)
    // Clear sensitive data before returning to pool
    for i := range buf {
        buf[i] = 0
    }
    m.packetBufferPool.Put(buf)
}

// GetMetadata - Get metadata from pool
func (m *MemoryPoolManager) GetMetadata() *PacketMetadata {
    atomic.AddUint64(&m.metrics.MetadataGets, 1)
    md := m.metadataPool.Get().(*PacketMetadata)
    md.Reset()  // Clear previous data
    return md
}

// PutMetadata - Return metadata to pool
func (m *MemoryPoolManager) PutMetadata(md *PacketMetadata) {
    atomic.AddUint64(&m.metrics.MetadataPuts, 1)
    m.metadataPool.Put(md)
}

// GetConnection - Get connection from pool
func (m *MemoryPoolManager) GetConnection() *Connection {
    atomic.AddUint64(&m.metrics.ConnectionGets, 1)
    conn := m.connectionPool.Get().(*Connection)
    conn.Reset()
    return conn
}

// PutConnection - Return connection to pool
func (m *MemoryPoolManager) PutConnection(conn *Connection) {
    atomic.AddUint64(&m.metrics.ConnectionPuts, 1)
    m.connectionPool.Put(conn)
}

// GetMetrics - Get pool utilization metrics
func (m *MemoryPoolManager) GetMetrics() PoolMetrics {
    return PoolMetrics{
        BufferGets:     atomic.LoadUint64(&m.metrics.BufferGets),
        BufferPuts:     atomic.LoadUint64(&m.metrics.BufferPuts),
        BufferMisses:   atomic.LoadUint64(&m.metrics.BufferMisses),
        MetadataGets:   atomic.LoadUint64(&m.metrics.MetadataGets),
        MetadataPuts:   atomic.LoadUint64(&m.metrics.MetadataPuts),
        ConnectionGets: atomic.LoadUint64(&m.metrics.ConnectionGets),
        ConnectionPuts: atomic.LoadUint64(&m.metrics.ConnectionPuts),
    }
}

// PrintPoolStats - Print pool utilization
func (m *MemoryPoolManager) PrintPoolStats() {
    metrics := m.GetMetrics()

    bufferUtilization := float64(metrics.BufferGets-metrics.BufferPuts) /
                          float64(m.config.PacketBufferCount) * 100
    metadataUtilization := float64(metrics.MetadataGets-metrics.MetadataPuts) /
                            float64(m.config.MetadataPoolSize) * 100
    connUtilization := float64(metrics.ConnectionGets-metrics.ConnectionPuts) /
                        float64(m.config.ConnectionPoolSize) * 100

    fmt.Printf("Memory Pool Statistics:\n")
    fmt.Printf("├─ Packet Buffers:\n")
    fmt.Printf("│  ├─ Gets: %d  Puts: %d  Misses: %d (%.2f%%)\n",
        metrics.BufferGets, metrics.BufferPuts, metrics.BufferMisses,
        float64(metrics.BufferMisses)/float64(metrics.BufferGets)*100)
    fmt.Printf("│  └─ Utilization: %.1f%%\n", bufferUtilization)
    fmt.Printf("├─ Metadata Objects:\n")
    fmt.Printf("│  ├─ Gets: %d  Puts: %d\n", metrics.MetadataGets, metrics.MetadataPuts)
    fmt.Printf("│  └─ Utilization: %.1f%%\n", metadataUtilization)
    fmt.Printf("└─ Connection Objects:\n")
    fmt.Printf("   ├─ Gets: %d  Puts: %d\n", metrics.ConnectionGets, metrics.ConnectionPuts)
    fmt.Printf("   └─ Utilization: %.1f%%\n", connUtilization)
}
```

**Performance Impact:**
```
Before Memory Pooling:
├─ Allocations: 50,000/sec (new objects)
├─ GC frequency: Every 2-3 seconds
├─ GC pause: 50-100ms (stop-the-world)
├─ Memory pattern: Sawtooth (500MB → 1GB → 500MB)
└─ Latency: +5-10ms (GC pauses)

After Memory Pooling:
├─ Allocations: 0/sec (reuse pool, after warmup)
├─ GC frequency: Every 60-120 seconds
├─ GC pause: 1-5ms (minimal)
├─ Memory pattern: Stable (300MB flat)
└─ Latency: +0.5-1ms (no GC impact)

Improvement: 10× reduction in GC overhead
```

---

### **3. Batch Processing Tuning** (`internal/performance/batch_processor.go`)

**Problem (Individual Processing):**
```go
// BEFORE: Process one packet at a time (SLOW!)
func processPackets() {
    for packet := range packetChannel {
        // Process single packet
        verdict := matchRules(packet)      // 1 packet
        logPacket(packet)                  // 1 database write
        updateMetrics(packet)              // 1 metric update
        sendVerdict(verdict)               // 1 network send
    }
}

Result: High overhead (context switches, system calls)
        Latency: 5-10ms per packet (overhead dominates)
```

**Solution (Batch Processing):**
```go
// AFTER: Process packets in batches (FAST!)
func processPacketsBatched() {
    batch := make([]*Packet, 0, 100)  // Batch size: 100

    for packet := range packetChannel {
        batch = append(batch, packet)

        if len(batch) >= 100 {
            // Process batch together
            verdicts := matchRulesBatch(batch)      // 100 packets at once
            logPacketsBatch(batch)                  // 1 database write (bulk insert)
            updateMetricsBatch(batch)               // 1 metric update (aggregated)
            sendVerdictsBatch(verdicts)             // 1 network send (bulk)

            batch = batch[:0]  // Reset batch (reuse slice)
        }
    }
}

Result: 10-100× less overhead
        Latency: 0.5-1ms per packet (amortized)
```

**Implementation Details:**
```go
// internal/performance/batch_processor.go

package performance

import (
    "context"
    "sync"
    "time"
)

// BatchConfig - Configuration for batch processing
type BatchConfig struct {
    MaxBatchSize    int           // Max packets per batch (default: 100)
    MaxBatchDelay   time.Duration // Max wait time (default: 10ms)
    EnableDynamic   bool          // Dynamically adjust batch size
}

// BatchProcessor - Processes packets in batches
type BatchProcessor struct {
    config    BatchConfig
    batch     []*Packet
    batchLock sync.Mutex
    metrics   *BatchMetrics
}

// BatchMetrics - Batch processing metrics
type BatchMetrics struct {
    TotalBatches   uint64
    TotalPackets   uint64
    AvgBatchSize   float64
    MaxBatchSize   int
    MinBatchSize   int
    TimeoutFlushes uint64  // Batches flushed due to timeout
}

func NewBatchProcessor(config BatchConfig) *BatchProcessor {
    return &BatchProcessor{
        config:  config,
        batch:   make([]*Packet, 0, config.MaxBatchSize),
        metrics: &BatchMetrics{MinBatchSize: config.MaxBatchSize},
    }
}

// AddPacket - Add packet to batch
func (bp *BatchProcessor) AddPacket(packet *Packet) []*Verdict {
    bp.batchLock.Lock()
    defer bp.batchLock.Unlock()

    bp.batch = append(bp.batch, packet)

    if len(bp.batch) >= bp.config.MaxBatchSize {
        // Batch full, process immediately
        return bp.flushBatch()
    }

    return nil  // Wait for more packets
}

// flushBatch - Process current batch
func (bp *BatchProcessor) flushBatch() []*Verdict {
    if len(bp.batch) == 0 {
        return nil
    }

    // Update metrics
    atomic.AddUint64(&bp.metrics.TotalBatches, 1)
    atomic.AddUint64(&bp.metrics.TotalPackets, uint64(len(bp.batch)))

    batchSize := len(bp.batch)
    if batchSize > bp.metrics.MaxBatchSize {
        bp.metrics.MaxBatchSize = batchSize
    }
    if batchSize < bp.metrics.MinBatchSize {
        bp.metrics.MinBatchSize = batchSize
    }

    // Process batch (call optimized batch functions)
    verdicts := bp.processBatch(bp.batch)

    // Reset batch (reuse slice)
    bp.batch = bp.batch[:0]

    return verdicts
}

// processBatch - Process multiple packets efficiently
func (bp *BatchProcessor) processBatch(packets []*Packet) []*Verdict {
    verdicts := make([]*Verdict, len(packets))

    // Batch rule matching (SIMD-optimized)
    matchRulesBatch(packets, verdicts)

    // Batch logging (bulk database insert)
    go logPacketsBatchAsync(packets)  // Async, don't block

    // Batch metrics update (aggregate)
    go updateMetricsBatchAsync(packets)

    return verdicts
}

// StartBatchTimer - Flush batches periodically (timeout)
func (bp *BatchProcessor) StartBatchTimer(ctx context.Context) {
    ticker := time.NewTicker(bp.config.MaxBatchDelay)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            bp.batchLock.Lock()
            if len(bp.batch) > 0 {
                atomic.AddUint64(&bp.metrics.TimeoutFlushes, 1)
                bp.flushBatch()
            }
            bp.batchLock.Unlock()
        case <-ctx.Done():
            return
        }
    }
}

// GetMetrics - Get batch processing metrics
func (bp *BatchProcessor) GetMetrics() BatchMetrics {
    totalBatches := atomic.LoadUint64(&bp.metrics.TotalBatches)
    totalPackets := atomic.LoadUint64(&bp.metrics.TotalPackets)

    return BatchMetrics{
        TotalBatches:   totalBatches,
        TotalPackets:   totalPackets,
        AvgBatchSize:   float64(totalPackets) / float64(totalBatches),
        MaxBatchSize:   bp.metrics.MaxBatchSize,
        MinBatchSize:   bp.metrics.MinBatchSize,
        TimeoutFlushes: atomic.LoadUint64(&bp.metrics.TimeoutFlushes),
    }
}

// PrintBatchStats - Print batch processing statistics
func (bp *BatchProcessor) PrintBatchStats() {
    metrics := bp.GetMetrics()

    fmt.Printf("Batch Processing Statistics:\n")
    fmt.Printf("├─ Total Batches: %d\n", metrics.TotalBatches)
    fmt.Printf("├─ Total Packets: %d\n", metrics.TotalPackets)
    fmt.Printf("├─ Avg Batch Size: %.1f packets\n", metrics.AvgBatchSize)
    fmt.Printf("├─ Batch Size Range: %d - %d packets\n",
        metrics.MinBatchSize, metrics.MaxBatchSize)
    fmt.Printf("└─ Timeout Flushes: %d (%.1f%%)\n",
        metrics.TimeoutFlushes,
        float64(metrics.TimeoutFlushes)/float64(metrics.TotalBatches)*100)
}

// DynamicBatchSizing - Adjust batch size based on load
func (bp *BatchProcessor) DynamicBatchSizing() {
    if !bp.config.EnableDynamic {
        return
    }

    metrics := bp.GetMetrics()

    // If average batch size is low, reduce timeout (more aggressive batching)
    if metrics.AvgBatchSize < 50 {
        bp.config.MaxBatchDelay = 5 * time.Millisecond
    } else if metrics.AvgBatchSize > 80 {
        bp.config.MaxBatchDelay = 15 * time.Millisecond
    }
}
```

**Batch-Optimized Functions:**
```go
// matchRulesBatch - Match rules for batch (SIMD-optimized)
func matchRulesBatch(packets []*Packet, verdicts []*Verdict) {
    // Process multiple packets in parallel (SIMD)
    // Use vectorized comparison (4-8 packets at once)

    for i := 0; i < len(packets); i += 4 {
        // Process 4 packets simultaneously (SSE/AVX)
        // Load 4 src IPs into SIMD register
        srcIPs := _mm_load_si128(&packets[i].SrcIP)

        // Compare against rule IP (parallel comparison)
        matches := _mm_cmpeq_epi32(srcIPs, ruleIP)

        // Extract results
        for j := 0; j < 4 && i+j < len(packets); j++ {
            verdicts[i+j] = processMatch(matches, j)
        }
    }
}

// logPacketsBatchAsync - Bulk database insert (async)
func logPacketsBatchAsync(packets []*Packet) {
    // Build bulk INSERT query
    query := "INSERT INTO packets (src_ip, dst_ip, ...) VALUES "
    values := make([]string, len(packets))

    for i, packet := range packets {
        values[i] = fmt.Sprintf("('%s', '%s', ...)",
            packet.SrcIP, packet.DstIP)
    }

    query += strings.Join(values, ", ")

    // Single database call (100× faster than 100 individual INSERTs)
    db.Exec(query)
}

// updateMetricsBatchAsync - Aggregate metrics (async)
func updateMetricsBatchAsync(packets []*Packet) {
    // Aggregate metrics locally
    var totalBytes uint64
    var totalPackets uint64
    protocolCounts := make(map[string]int)

    for _, packet := range packets {
        totalBytes += uint64(packet.Length)
        totalPackets++
        protocolCounts[packet.Protocol]++
    }

    // Single Prometheus update (atomic)
    metrics.BytesProcessed.Add(float64(totalBytes))
    metrics.PacketsProcessed.Add(float64(totalPackets))
    for protocol, count := range protocolCounts {
        metrics.PacketsByProtocol.With(prometheus.Labels{
            "protocol": protocol,
        }).Add(float64(count))
    }
}
```

**Performance Impact:**
```
Before Batch Processing:
├─ Database writes: 50,000/sec (individual INSERTs)
├─ Metric updates: 50,000/sec (individual counter increments)
├─ Network sends: 50,000/sec (individual packets)
├─ Overhead: 50-100% (context switches, system calls)
└─ Latency: 5-10ms per packet

After Batch Processing (batch size: 100):
├─ Database writes: 500/sec (bulk INSERTs, 100 rows each)
├─ Metric updates: 500/sec (aggregated increments)
├─ Network sends: 500/sec (bulk packets)
├─ Overhead: 5-10% (amortized across batch)
└─ Latency: 0.5-1ms per packet (10× improvement)

Improvement: 10× reduction in system call overhead
```

---

### **4. Multi-Threading Optimization** (`internal/performance/worker_pool.go`)

**Problem (Single-Threaded):**
```go
// BEFORE: Single thread processes all packets (SLOW!)
func processPackets() {
    for packet := range packetChannel {
        verdict := processPacket(packet)
        sendVerdict(verdict)
    }
}

Result: Only 1 CPU core used (12.5% on 8-core CPU)
        Throughput: 20K pps (limited by single core)
```

**Solution (Worker Pool):**
```go
// AFTER: Multiple workers process packets in parallel (FAST!)
func startWorkerPool(numWorkers int) {
    for i := 0; i < numWorkers; i++ {
        go worker(i, packetChannel)
    }
}

func worker(id int, packets <-chan *Packet) {
    for packet := range packets {
        verdict := processPacket(packet)
        sendVerdict(verdict)
    }
}

Result: All 8 CPU cores used (100% utilization)
        Throughput: 160K pps (8× improvement)
```

**Implementation Details:**
```go
// internal/performance/worker_pool.go

package performance

import (
    "context"
    "runtime"
    "sync"
    "sync/atomic"
)

// WorkerPoolConfig - Configuration for worker pool
type WorkerPoolConfig struct {
    NumWorkers    int   // Number of workers (default: NumCPU)
    EnableAffinity bool // Pin workers to CPU cores
    EnableNUMA     bool // NUMA-aware allocation
}

// WorkerPool - Pool of packet processing workers
type WorkerPool struct {
    config   WorkerPoolConfig
    workers  []*Worker
    packets  chan *Packet
    verdicts chan *Verdict
    metrics  *WorkerPoolMetrics
    wg       sync.WaitGroup
}

// Worker - Individual packet processor
type Worker struct {
    id       int
    pool     *WorkerPool
    packets  <-chan *Packet
    verdicts chan<- *Verdict
    metrics  *WorkerMetrics
}

// WorkerMetrics - Per-worker metrics
type WorkerMetrics struct {
    PacketsProcessed uint64
    BytesProcessed   uint64
    CPUTime          uint64  // Nanoseconds
    IdleTime         uint64  // Nanoseconds
}

// WorkerPoolMetrics - Aggregate metrics
type WorkerPoolMetrics struct {
    TotalPackets  uint64
    TotalBytes    uint64
    WorkerMetrics []*WorkerMetrics
}

func NewWorkerPool(config WorkerPoolConfig) *WorkerPool {
    if config.NumWorkers == 0 {
        config.NumWorkers = runtime.NumCPU()
    }

    pool := &WorkerPool{
        config:   config,
        packets:  make(chan *Packet, 10000),  // Buffered channel
        verdicts: make(chan *Verdict, 10000),
        metrics:  &WorkerPoolMetrics{
            WorkerMetrics: make([]*WorkerMetrics, config.NumWorkers),
        },
    }

    // Create workers
    pool.workers = make([]*Worker, config.NumWorkers)
    for i := 0; i < config.NumWorkers; i++ {
        pool.workers[i] = &Worker{
            id:       i,
            pool:     pool,
            packets:  pool.packets,
            verdicts: pool.verdicts,
            metrics:  &WorkerMetrics{},
        }
        pool.metrics.WorkerMetrics[i] = pool.workers[i].metrics
    }

    return pool
}

// Start - Start all workers
func (wp *WorkerPool) Start(ctx context.Context) {
    for i, worker := range wp.workers {
        wp.wg.Add(1)

        // Set CPU affinity if enabled
        if wp.config.EnableAffinity {
            setCPUAffinity(i)
        }

        go worker.run(ctx)
    }
}

// Stop - Stop all workers
func (wp *WorkerPool) Stop() {
    close(wp.packets)
    wp.wg.Wait()
    close(wp.verdicts)
}

// SubmitPacket - Submit packet for processing
func (wp *WorkerPool) SubmitPacket(packet *Packet) {
    wp.packets <- packet
}

// GetVerdict - Get processed verdict
func (wp *WorkerPool) GetVerdict() *Verdict {
    return <-wp.verdicts
}

// run - Worker main loop
func (w *Worker) run(ctx context.Context) {
    defer w.pool.wg.Done()

    for {
        select {
        case packet, ok := <-w.packets:
            if !ok {
                return  // Channel closed
            }

            startTime := time.Now()

            // Process packet
            verdict := w.processPacket(packet)

            // Update metrics
            atomic.AddUint64(&w.metrics.PacketsProcessed, 1)
            atomic.AddUint64(&w.metrics.BytesProcessed, uint64(packet.Length))
            atomic.AddUint64(&w.metrics.CPUTime, uint64(time.Since(startTime)))

            // Send verdict
            w.verdicts <- verdict

        case <-ctx.Done():
            return
        }
    }
}

// processPacket - Process single packet
func (w *Worker) processPacket(packet *Packet) *Verdict {
    // Rule matching
    verdict := matchRules(packet)

    // Async operations (don't block worker)
    go logPacketAsync(packet)
    go updateMetricsAsync(packet)

    return verdict
}

// setCPUAffinity - Pin worker to specific CPU core
func setCPUAffinity(core int) {
    // Platform-specific implementation
    // Linux: pthread_setaffinity_np
    // Windows: SetThreadAffinityMask
    runtime.LockOSThread()

    // Set affinity mask (simplified)
    // In production, use syscall.SYS_SCHED_SETAFFINITY
}

// GetMetrics - Get worker pool metrics
func (wp *WorkerPool) GetMetrics() WorkerPoolMetrics {
    totalPackets := uint64(0)
    totalBytes := uint64(0)

    for _, workerMetrics := range wp.metrics.WorkerMetrics {
        totalPackets += atomic.LoadUint64(&workerMetrics.PacketsProcessed)
        totalBytes += atomic.LoadUint64(&workerMetrics.BytesProcessed)
    }

    return WorkerPoolMetrics{
        TotalPackets:  totalPackets,
        TotalBytes:    totalBytes,
        WorkerMetrics: wp.metrics.WorkerMetrics,
    }
}

// PrintWorkerStats - Print per-worker statistics
func (wp *WorkerPool) PrintWorkerStats() {
    metrics := wp.GetMetrics()

    fmt.Printf("Worker Pool Statistics:\n")
    fmt.Printf("├─ Total Packets: %d\n", metrics.TotalPackets)
    fmt.Printf("├─ Total Bytes: %s\n", humanize.Bytes(metrics.TotalBytes))
    fmt.Printf("└─ Per-Worker Stats:\n")

    for i, workerMetrics := range metrics.WorkerMetrics {
        packets := atomic.LoadUint64(&workerMetrics.PacketsProcessed)
        bytes := atomic.LoadUint64(&workerMetrics.BytesProcessed)
        cpuTime := time.Duration(atomic.LoadUint64(&workerMetrics.CPUTime))

        pctOfTotal := float64(packets) / float64(metrics.TotalPackets) * 100

        fmt.Printf("   ├─ Worker %d: %d packets (%.1f%%)  %s  CPU: %v\n",
            i, packets, pctOfTotal, humanize.Bytes(bytes), cpuTime)
    }
}

// BalanceLoad - Check load balance across workers
func (wp *WorkerPool) BalanceLoad() {
    metrics := wp.GetMetrics()

    // Calculate standard deviation of packet counts
    mean := float64(metrics.TotalPackets) / float64(len(wp.workers))
    variance := 0.0

    for _, workerMetrics := range metrics.WorkerMetrics {
        packets := float64(atomic.LoadUint64(&workerMetrics.PacketsProcessed))
        variance += (packets - mean) * (packets - mean)
    }

    stdDev := math.Sqrt(variance / float64(len(wp.workers)))

    // If standard deviation > 10% of mean, load is imbalanced
    if stdDev > mean*0.1 {
        log.Warnf("Load imbalance detected: stddev=%.1f, mean=%.1f", stdDev, mean)
        // Rebalance workers (adjust channel routing)
    }
}
```

**Performance Impact:**
```
Before Multi-Threading (1 worker):
├─ CPU usage: 100% on 1 core (12.5% total on 8-core)
├─ Throughput: 20,000 pps (single-threaded limit)
├─ Latency: 50μs per packet (processing time)
└─ Bottleneck: Single core saturated

After Multi-Threading (8 workers):
├─ CPU usage: 50-60% on 8 cores (40-50% total)
├─ Throughput: 105,000 pps (5× improvement)
├─ Latency: 9.5μs per packet (parallel processing)
└─ Bottleneck: Network I/O (CPU has headroom)

Improvement: 5× throughput increase (linear scaling)
```

---

### **5. Profiling & Benchmarking** (`internal/performance/profiler.go`)

**Purpose:**
- Identify performance bottlenecks
- Measure optimization impact
- Continuous performance monitoring

**Implementation:**
```go
// internal/performance/profiler.go

package performance

import (
    "context"
    "fmt"
    "net/http"
    _ "net/http/pprof"
    "runtime/pprof"
    "time"
)

// ProfilerConfig - Configuration for profiler
type ProfilerConfig struct {
    EnableCPU      bool
    EnableMemory   bool
    EnableBlock    bool
    EnableMutex    bool
    PProfPort      int     // pprof HTTP server port (default: 6060)
    SampleRate     int     // Profiling sample rate (Hz)
}

// Profiler - Performance profiler
type Profiler struct {
    config  ProfilerConfig
    cpuFile *os.File
    memFile *os.File
}

func NewProfiler(config ProfilerConfig) *Profiler {
    return &Profiler{
        config: config,
    }
}

// Start - Start profiling
func (p *Profiler) Start() error {
    // Start pprof HTTP server
    go func() {
        addr := fmt.Sprintf("localhost:%d", p.config.PProfPort)
        log.Infof("Starting pprof server on %s", addr)
        log.Infof("Access profiles:")
        log.Infof("  CPU:    http://%s/debug/pprof/profile", addr)
        log.Infof("  Heap:   http://%s/debug/pprof/heap", addr)
        log.Infof("  Goroutine: http://%s/debug/pprof/goroutine", addr)

        if err := http.ListenAndServe(addr, nil); err != nil {
            log.Errorf("pprof server error: %v", err)
        }
    }()

    // Start CPU profiling
    if p.config.EnableCPU {
        cpuFile, err := os.Create("cpu.pprof")
        if err != nil {
            return err
        }
        p.cpuFile = cpuFile
        pprof.StartCPUProfile(cpuFile)
        log.Info("CPU profiling enabled (output: cpu.pprof)")
    }

    // Enable memory profiling
    if p.config.EnableMemory {
        runtime.MemProfileRate = p.config.SampleRate
        log.Info("Memory profiling enabled")
    }

    // Enable block profiling
    if p.config.EnableBlock {
        runtime.SetBlockProfileRate(p.config.SampleRate)
        log.Info("Block profiling enabled")
    }

    // Enable mutex profiling
    if p.config.EnableMutex {
        runtime.SetMutexProfileFraction(p.config.SampleRate)
        log.Info("Mutex profiling enabled")
    }

    return nil
}

// Stop - Stop profiling
func (p *Profiler) Stop() {
    if p.cpuFile != nil {
        pprof.StopCPUProfile()
        p.cpuFile.Close()
        log.Info("CPU profile saved to cpu.pprof")
    }

    if p.config.EnableMemory {
        memFile, err := os.Create("mem.pprof")
        if err == nil {
            pprof.WriteHeapProfile(memFile)
            memFile.Close()
            log.Info("Memory profile saved to mem.pprof")
        }
    }
}

// CaptureSnapshot - Capture performance snapshot
func (p *Profiler) CaptureSnapshot() *PerformanceSnapshot {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)

    return &PerformanceSnapshot{
        Timestamp:    time.Now(),
        NumGoroutines: runtime.NumGoroutine(),
        HeapAlloc:    memStats.HeapAlloc,
        HeapSys:      memStats.HeapSys,
        HeapIdle:     memStats.HeapIdle,
        HeapInuse:    memStats.HeapInuse,
        StackInuse:   memStats.StackInuse,
        GCPauses:     memStats.PauseNs[(memStats.NumGC+255)%256],
        NumGC:        memStats.NumGC,
    }
}

// PerformanceSnapshot - Point-in-time performance metrics
type PerformanceSnapshot struct {
    Timestamp     time.Time
    NumGoroutines int
    HeapAlloc     uint64
    HeapSys       uint64
    HeapIdle      uint64
    HeapInuse     uint64
    StackInuse    uint64
    GCPauses      uint64
    NumGC         uint32
}

// PrintSnapshot - Print performance snapshot
func (s *PerformanceSnapshot) Print() {
    fmt.Printf("Performance Snapshot (%s):\n", s.Timestamp.Format(time.RFC3339))
    fmt.Printf("├─ Goroutines: %d\n", s.NumGoroutines)
    fmt.Printf("├─ Heap Allocated: %s\n", humanize.Bytes(s.HeapAlloc))
    fmt.Printf("├─ Heap System: %s\n", humanize.Bytes(s.HeapSys))
    fmt.Printf("├─ Heap In Use: %s (%.1f%%)\n",
        humanize.Bytes(s.HeapInuse),
        float64(s.HeapInuse)/float64(s.HeapSys)*100)
    fmt.Printf("├─ Stack In Use: %s\n", humanize.Bytes(s.StackInuse))
    fmt.Printf("├─ GC Cycles: %d\n", s.NumGC)
    fmt.Printf("└─ Last GC Pause: %v\n", time.Duration(s.GCPauses))
}
```

**Benchmarking Implementation:**
```go
// internal/performance/benchmark.go

package performance

import (
    "testing"
    "time"
)

// BenchmarkRuleMatching - Benchmark rule matching performance
func BenchmarkRuleMatching(b *testing.B) {
    firewall := setupTestFirewall()
    packet := generateTestPacket()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        firewall.matchRules(packet)
    }
}

// BenchmarkDNSFiltering - Benchmark DNS filtering
func BenchmarkDNSFiltering(b *testing.B) {
    firewall := setupTestFirewall()
    dnsQuery := generateTestDNSQuery("facebook.com")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        firewall.filterDNS(dnsQuery)
    }
}

// BenchmarkTLSParsing - Benchmark TLS SNI parsing
func BenchmarkTLSParsing(b *testing.B) {
    firewall := setupTestFirewall()
    tlsPacket := generateTestTLSClientHello("google.com")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        firewall.parseTLSSNI(tlsPacket)
    }
}

// BenchmarkFullPipeline - Benchmark full packet processing
func BenchmarkFullPipeline(b *testing.B) {
    firewall := setupTestFirewall()
    packet := generateTestPacket()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        firewall.processPacket(packet)
    }
}

// LatencyHistogram - Measure latency distribution
func LatencyHistogram() {
    firewall := setupTestFirewall()
    packet := generateTestPacket()

    latencies := make([]time.Duration, 1000000)

    for i := 0; i < 1000000; i++ {
        start := time.Now()
        firewall.processPacket(packet)
        latencies[i] = time.Since(start)
    }

    // Calculate percentiles
    sort.Slice(latencies, func(i, j int) bool {
        return latencies[i] < latencies[j]
    })

    fmt.Printf("Latency Histogram (1M packets):\n")
    fmt.Printf("├─ P50 (median): %v\n", latencies[500000])
    fmt.Printf("├─ P90: %v\n", latencies[900000])
    fmt.Printf("├─ P95: %v\n", latencies[950000])
    fmt.Printf("├─ P99: %v\n", latencies[990000])
    fmt.Printf("└─ P99.9: %v\n", latencies[999000])
}
```

**Usage:**
```bash
# Run benchmarks
go test -bench=. -benchmem ./internal/performance/

# Output:
BenchmarkRuleMatching-8      125000   8.2 μs/op   0 B/op   0 allocs/op
BenchmarkDNSFiltering-8      200000   5.1 μs/op   0 B/op   0 allocs/op
BenchmarkTLSParsing-8        150000   6.7 μs/op   0 B/op   0 allocs/op
BenchmarkFullPipeline-8      105000   9.5 μs/op   0 B/op   0 allocs/op

# CPU profiling
go tool pprof http://localhost:6060/debug/pprof/profile

# Memory profiling
go tool pprof http://localhost:6060/debug/pprof/heap

# Visualize profile (requires graphviz)
go tool pprof -http=:8080 cpu.pprof
```

---

## 📊 Performance Targets & Validation

### **Target Metrics:**
```
┌─────────────────────────────────────────────────────────────┐
│                 PERFORMANCE TARGETS                         │
├─────────────────────────────────────────────────────────────┤
│  Throughput:         ≥ 100,000 pps (packets per second)    │
│  Latency (avg):      < 1ms added per packet                │
│  Latency (P95):      < 2ms                                  │
│  Latency (P99):      < 5ms                                  │
│  CPU Usage:          40-60% (multi-core)                    │
│  Memory:             200-500MB stable (no growth)           │
│  GC Pause:           < 5ms (P99)                            │
│  Allocations:        < 100/sec (after warmup)               │
└─────────────────────────────────────────────────────────────┘
```

### **Validation Tests:**
```go
// Throughput Test
func TestThroughput(t *testing.T) {
    firewall := setupTestFirewall()

    packetsProcessed := atomic.Uint64{}
    duration := 10 * time.Second

    // Start workers
    for i := 0; i < 8; i++ {
        go func() {
            for start := time.Now(); time.Since(start) < duration; {
                packet := generateTestPacket()
                firewall.processPacket(packet)
                packetsProcessed.Add(1)
            }
        }()
    }

    time.Sleep(duration)

    pps := packetsProcessed.Load() / uint64(duration.Seconds())

    if pps < 100000 {
        t.Errorf("Throughput target not met: %d pps (target: 100K pps)", pps)
    } else {
        t.Logf("Throughput: %d pps ✅", pps)
    }
}

// Latency Test
func TestLatency(t *testing.T) {
    firewall := setupTestFirewall()
    packet := generateTestPacket()

    latencies := make([]time.Duration, 1000000)

    for i := 0; i < 1000000; i++ {
        start := time.Now()
        firewall.processPacket(packet)
        latencies[i] = time.Since(start)
    }

    sort.Slice(latencies, func(i, j int) bool {
        return latencies[i] < latencies[j]
    })

    p50 := latencies[500000]
    p95 := latencies[950000]
    p99 := latencies[990000]

    if p50 > 1*time.Millisecond {
        t.Errorf("P50 latency too high: %v (target: <1ms)", p50)
    }
    if p95 > 2*time.Millisecond {
        t.Errorf("P95 latency too high: %v (target: <2ms)", p95)
    }
    if p99 > 5*time.Millisecond {
        t.Errorf("P99 latency too high: %v (target: <5ms)", p99)
    }

    t.Logf("Latency P50: %v, P95: %v, P99: %v ✅", p50, p95, p99)
}

// Memory Stability Test
func TestMemoryStability(t *testing.T) {
    firewall := setupTestFirewall()

    initialMem := getMemUsage()

    // Process 1M packets
    for i := 0; i < 1000000; i++ {
        packet := generateTestPacket()
        firewall.processPacket(packet)
    }

    runtime.GC()  // Force GC

    finalMem := getMemUsage()
    memGrowth := finalMem - initialMem

    if memGrowth > 100*1024*1024 {  // 100MB growth
        t.Errorf("Memory growth too high: %s (target: <100MB)",
            humanize.Bytes(uint64(memGrowth)))
    } else {
        t.Logf("Memory stable: %s growth ✅", humanize.Bytes(uint64(memGrowth)))
    }
}
```

---

## 🚀 Optimization Impact Summary

### **Before Optimization (Phase 9):**
```
Performance Baseline:
├─ Throughput: 20,000-50,000 pps
├─ Latency: 5-10ms per packet
├─ CPU: 80-100% single core
├─ Memory: 500MB-1GB (growing)
├─ GC: Every 2-3 seconds (50-100ms pause)
└─ Bottlenecks: Memory copies, allocations, single-threaded
```

### **After Optimization (Phase 10):**
```
Performance Optimized:
├─ Throughput: 100,000+ pps (2-5× improvement)
├─ Latency: <1ms per packet (5-10× improvement)
├─ CPU: 40-60% across 8 cores (efficient)
├─ Memory: 200-500MB stable (2× improvement)
├─ GC: Every 60-120 seconds (1-5ms pause, 10× improvement)
└─ Optimizations: Zero-copy, pooling, batching, multi-threading
```

### **Optimization Breakdown:**
```
┌─────────────────────────────────────────────────────────────┐
│  Optimization          Improvement       Impact              │
├─────────────────────────────────────────────────────────────┤
│  Zero-Copy             5-10× latency     Eliminated copies   │
│  Memory Pooling        10× GC reduction  Stable memory       │
│  Batch Processing      10× less overhead Efficient I/O       │
│  Multi-Threading       5× throughput     Linear CPU scaling  │
│  Profiling             Continuous        Identify bottlenecks│
└─────────────────────────────────────────────────────────────┘

Combined Impact: 10× overall performance improvement
```

---

## 🎯 Deliverables

### **Code Deliverables:**
```
src/firewall_engine/
├─ internal/performance/
│  ├─ zero_copy.go              # Zero-copy packet handling
│  ├─ memory_pool.go            # Memory pooling (buffers, objects)
│  ├─ batch_processor.go        # Batch processing logic
│  ├─ worker_pool.go            # Multi-threaded worker pool
│  ├─ profiler.go               # Performance profiler (pprof)
│  ├─ benchmark_test.go         # Benchmark tests
│  └─ metrics.go                # Performance metrics
└─ cmd/
   └─ benchmark/
      └─ main.go                # Standalone benchmark tool
```

### **Documentation Deliverables:**
```
docs/
├─ performance/
│  ├─ OPTIMIZATION-GUIDE.md     # Optimization techniques
│  ├─ BENCHMARKING.md           # How to run benchmarks
│  ├─ PROFILING.md              # How to use profiler
│  └─ TUNING.md                 # Performance tuning guide
└─ metrics/
   └─ PERFORMANCE-METRICS.md    # Performance metric definitions
```

### **Testing Deliverables:**
```
tests/
├─ performance/
│  ├─ throughput_test.go        # Throughput validation
│  ├─ latency_test.go           # Latency validation
│  ├─ memory_test.go            # Memory stability test
│  └─ cpu_test.go               # CPU efficiency test
└─ benchmark/
   └─ load_generator.go         # Realistic load generator
```

---

## ✅ Acceptance Criteria

**Phase 10 is complete when:**

1. **Throughput Target Met:**
   - ✅ Firewall processes ≥100,000 packets/sec sustained load
   - ✅ Linear scaling with CPU cores (8 cores = 8× single-core)

2. **Latency Target Met:**
   - ✅ Average latency <1ms per packet
   - ✅ P95 latency <2ms
   - ✅ P99 latency <5ms

3. **Memory Stability:**
   - ✅ Memory usage stable (200-500MB)
   - ✅ No memory growth over 24-hour run
   - ✅ GC pauses <5ms (P99)

4. **CPU Efficiency:**
   - ✅ CPU usage 40-60% (headroom for spikes)
   - ✅ Even load distribution across cores (±10%)

5. **Zero-Copy Implemented:**
   - ✅ 95%+ packets processed without copy
   - ✅ Fallback copy path for edge cases

6. **Memory Pooling Active:**
   - ✅ <100 allocations/sec after warmup
   - ✅ Pool hit rate >99%

7. **Batch Processing Tuned:**
   - ✅ Average batch size 70-90 packets
   - ✅ Batch efficiency >90%

8. **Multi-Threading Optimized:**
   - ✅ Worker pool with CPU affinity
   - ✅ Load balance <10% variance across workers

9. **Profiling Enabled:**
   - ✅ pprof server running (HTTP endpoint)
   - ✅ Continuous performance monitoring
   - ✅ Automated bottleneck detection

10. **Benchmarks Pass:**
    - ✅ All performance tests pass
    - ✅ No regression from optimization
    - ✅ Performance reports generated

---

## 📈 Expected Timeline

```
Week 1: Zero-Copy & Memory Pooling
├─ Day 1-2: Zero-copy packet handling implementation
├─ Day 3-4: Memory pool manager implementation
└─ Day 5: Testing & validation

Week 2: Batch Processing & Multi-Threading
├─ Day 1-2: Batch processor implementation
├─ Day 3-4: Worker pool implementation
└─ Day 5: CPU affinity & NUMA optimization

Week 3: Profiling & Benchmarking
├─ Day 1-2: Profiler implementation (pprof integration)
├─ Day 3-4: Benchmark suite implementation
└─ Day 5: Performance testing & metrics

Week 4: Integration & Tuning
├─ Day 1-2: Integrate all optimizations
├─ Day 3-4: Performance tuning & bottleneck elimination
└─ Day 5: Final validation & documentation

Total: 3-4 weeks
```

---

## 🔄 Continuous Monitoring

**After Phase 10, maintain performance with:**

1. **Automated Benchmarks (CI/CD):**
   - Run benchmarks on every commit
   - Alert on regression >5%

2. **Production Profiling:**
   - Enable pprof in production (low overhead)
   - Daily performance snapshots

3. **Performance Dashboard (Grafana):**
   - Real-time throughput/latency graphs
   - GC pause tracking
   - Memory usage tracking
   - CPU utilization heatmap

4. **Alert Thresholds:**
   - Throughput drops below 90K pps
   - Latency P99 exceeds 10ms
   - Memory growth >100MB in 1 hour
   - GC pause >50ms

---

**END OF PHASE 10 DOCUMENT**
