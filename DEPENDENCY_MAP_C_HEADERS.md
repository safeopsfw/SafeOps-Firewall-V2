# SafeOps v2.0 - C Headers Dependency Map
## Complete Analysis: All 4 Header Files

> **Bottom-to-top dependency analysis for C headers**  
> Used for kernel ↔ userspace communication (when implemented)
>
> [← Back to Master Index](DEPENDENCY_MAP_MASTER.md)

---

## 📊 C Headers Overview

| File | Size | Level | Purpose | Used By |
|------|------|-------|---------|---------|
| shared_constants.h | 150 lines | 0 | Constants | 3 other headers |
| packet_structs.h | 280 lines | 1 | Packet types | ring_buffer.h |
| ring_buffer.h | 200 lines | 1 | Lock-free queue | Future driver/service |
| ioctl_codes.h | 120 lines | 1 | Driver commands | Future driver/service |

**Total:** 4 files, ~750 lines, all header-only (no .c files)

---

## 🔢 Build Order (Bottom-to-Top)

```
Level 0: shared_constants.h (no dependencies)
           ↓
Level 1: packet_structs.h (uses shared_constants.h)
         ring_buffer.h (uses shared_constants.h + packet_structs.h)
         ioctl_codes.h (uses shared_constants.h)
```

---

## 📄 LEVEL 0: shared_constants.h

```yaml
FILE: src/shared/c/shared_constants.h
LEVEL: 0 (Foundation - No SafeOps dependencies)
SIZE: ~150 lines
USAGE: 📄 RAW (#include in C code)

PURPOSE:
  Compile-time constants shared across C components. Defines buffer sizes,
  timeouts, protocol numbers, and magic values. Header-only, no .c file needed.

KEY CONSTANTS:
  Ring Buffer:
    RING_BUFFER_SIZE = 16 * 1024 * 1024  (16 MB)
    RING_BUFFER_MAGIC = 0x53414645        ('SAFE')
    RING_BUFFER_ENTRIES = 32768           (16MB / 512 bytes)
  
  Packets:
    MAX_PACKET_SIZE = 65536               (64 KB)
    MIN_PACKET_SIZE = 64                  (Min Ethernet frame)
    PACKET_INFO_SIZE = 512                (512 bytes per packet)
  
  Connections:
    MAX_CONNECTIONS = 1000000             (1M concurrent)
    CONNECTION_TIMEOUT_SEC = 300          (5 min idle)
    TCP_HANDSHAKE_TIMEOUT_SEC = 60        (SYN flood protection)
  
  IOCTL:
    IOCTL_TIMEOUT_MS = 5000               (5 sec timeout)
    IOCTL_RETRY_COUNT = 3
    IOCTL_RETRY_DELAY_MS = 100
  
  Logging:
    MAX_LOG_MESSAGE_SIZE = 4096
    LOG_ROTATION_INTERVAL_MS = 300000     (5 min)
    LOG_BUFFER_SIZE = 1024 * 1024         (1 MB)
  
  Performance:
    NIC_RSS_QUEUES = 8
    DMA_BUFFER_COUNT = 256
    INTERRUPT_COALESCE_US = 100
  
  Protocols:
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17
    IPPROTO_ICMP = 1

DEPENDENCIES (External):
  <stdint.h> (for uint32_t, uint64_t)

DEPENDENCIES (SafeOps):
  NONE - Level 0 foundation

REQUIRED BY:
  ✅ packet_structs.h (uses MAX_PACKET_SIZE)
  ✅ ring_buffer.h (uses RING_BUFFER_SIZE, RING_BUFFER_MAGIC, RING_BUFFER_ENTRIES)
  ✅ ioctl_codes.h (uses IOCTL_TIMEOUT_MS)
  ❌ kernel_driver/*.c (PLANNED - not implemented)
  ❌ userspace_service/*.c (PLANNED - not implemented)

BUILD IMPACT:
  Changing any constant requires recompiling ALL C code

VERIFICATION:
  gcc -fsyntax-only shared_constants.h
  # Should: No errors
```

---

## 📄 LEVEL 1: packet_structs.h

```yaml
FILE: src/shared/c/packet_structs.h
LEVEL: 1 (Depends on shared_constants.h)
SIZE: ~280 lines
USAGE: 📄 RAW (#include for struct definitions)

PURPOSE:
  Network packet header structures and metadata. Defines IPV4_HEADER, TCP_HEADER,
  UDP_HEADER, and the master PACKET_INFO struct that kernel fills for userspace.

KEY STRUCTURES:
  IPV4_HEADER (20 bytes, RFC 791):
    - version_ihl, tos, total_length
    - identification, flags_fragment
    - ttl, protocol, header_checksum
    - source_ip, dest_ip (network byte order)
  
  TCP_HEADER (20 bytes, RFC 793):
    - source_port, dest_port
    - seq_number, ack_number
    - data_offset, flags (SYN/ACK/FIN/RST/PSH/URG)
    - window, checksum, urgent_pointer
  
  UDP_HEADER (8 bytes, RFC 768):
    - source_port, dest_port
    - length, checksum
  
  PACKET_INFO (512 bytes, cache-aligned):
    Identification:
      - uint64_t packet_id
      - uint64_t timestamp_ns
    
    Network Layer:
      - uint32_t src_ip, dst_ip
      - uint8_t src_ipv6[16], dst_ipv6[16]
      - uint8_t ip_version, protocol, ttl, tos
    
    Transport Layer:
      - uint16_t src_port, dst_port
      - uint32_t tcp_seq, tcp_ack
      - uint8_t tcp_flags
    
    Packet Properties:
      - uint32_t packet_size
      - uint16_t payload_size
      - uint8_t direction (INBOUND/OUTBOUND)
      - uint8_t interface_id
    
    Firewall Decision:
      - uint8_t action (PERMIT/BLOCK/DROP)
      - uint8_t threat_level (0-100)
      - uint32_t rule_id
      - uint32_t connection_id
    
    Performance:
      - uint64_t processing_time_ns
      - uint32_t queue_depth
    
    Payload Preview:
      - uint8_t payload_preview[64]
    
    Reserved:
      - uint8_t reserved[128]

SIZE ASSERTIONS:
  C_ASSERT(sizeof(PACKET_INFO) == 512)
  C_ASSERT(sizeof(IPV4_HEADER) == 20)
  C_ASSERT(sizeof(TCP_HEADER) == 20)
  C_ASSERT(sizeof(UDP_HEADER) == 8)

DEPENDENCIES (External):
  <stdint.h>
  <winsock2.h> (Windows - ntohl/htonl)
  <arpa/inet.h> (Linux - ntohl/htonl)

DEPENDENCIES (SafeOps):
  ✅ shared_constants.h (MAX_PACKET_SIZE)

REQUIRED BY:
  ✅ ring_buffer.h (RING_BUFFER stores PACKET_INFO)
  ❌ kernel_driver/packet_capture.c (fills PACKET_INFO)
  ❌ userspace_service/ring_reader.c (reads PACKET_INFO)
  ❌ userspace_service/log_writer.c (converts to JSON)

CROSS-LANGUAGE USAGE:
  Rust FFI:
    - bindgen generates #[repr(C)] struct PacketInfo
    - Rust code: unsafe { *(ptr as *const PacketInfo) }
  
  Go CGO:
    - import "C" exposes C.PACKET_INFO
    - Go code: packet := (*C.PACKET_INFO)(ptr)

ABI STABILITY:
  CRITICAL: Shared between kernel/userspace/languages
  DO NOT modify without versioning
  Changes require coordinated updates across all consumers

VERIFICATION:
  sizeof(PACKET_INFO) == 512 bytes
  All structs __attribute__((packed))
  Byte order documented for network fields
```

---

## 📄 LEVEL 1: ring_buffer.h

```yaml
FILE: src/shared/c/ring_buffer.h
LEVEL: 1 (Depends on shared_constants.h + packet_structs.h)
SIZE: ~200 lines
USAGE: 📄 RAW (#include, inline functions)

PURPOSE:
  Lock-free ring buffer for kernel → userspace packet transfer. Single-Producer
  Single-Consumer (SPSC) queue using atomic operations. Zero-copy packet passing.

KEY STRUCTURES:
  RING_BUFFER_HEADER (256 bytes):
    Magic & Metadata:
      - uint32_t magic (0x53414645)
      - uint16_t version (1)
      - uint16_t entry_size (512)
      - uint64_t total_entries (32768)
    
    Producer Cache Line (64 bytes):
      - volatile uint64_t write_index
      - uint64_t packets_written
      - uint64_t drops (buffer full)
    
    Consumer Cache Line (64 bytes):
      - volatile uint64_t read_index
      - uint64_t packets_read
    
    Stats Cache Line (64 bytes):
      - uint64_t max_depth
      - uint64_t total_latency_ns
  
  RING_BUFFER (16,777,472 bytes):
    - RING_BUFFER_HEADER header (256 bytes)
    - PACKET_INFO entries[32768] (16 MB)

INLINE FUNCTIONS:
  RingBuffer_Init(RING_BUFFER*) → BOOLEAN
    - Initializes magic, version, indexes
    - Returns TRUE on success
  
  RingBuffer_Write(RING_BUFFER*, const PACKET_INFO*) → BOOLEAN
    - Lock-free write using InterlockedCompareExchange64
    - Returns FALSE if buffer full
    - Updates write_index atomically
  
  RingBuffer_Read(RING_BUFFER*, PACKET_INFO*) → BOOLEAN
    - Lock-free read using atomic load
    - Returns FALSE if buffer empty
    - Updates read_index atomically
  
  RingBuffer_Count(const RING_BUFFER*) → uint64_t
    - Returns current buffer depth
  
  RingBuffer_IsFull(const RING_BUFFER*) → BOOLEAN
  RingBuffer_IsEmpty(const RING_BUFFER*) → BOOLEAN

PERFORMANCE:
  Throughput:
    - Write: ~100ns per packet
    - Read: ~50ns per packet
    - Max: ~10M packets/second
  
  Latency:
    - Best: ~150ns producer → consumer
    - Worst: ~1μs (cache misses)
  
  Lock-Free Guarantees:
    - No mutexes or spinlocks
    - No syscalls (all userspace)
    - Pure atomic operations

MEMORY LAYOUT:
  Total Size: 16,777,472 bytes (~16 MB)
  Offset 0-255: RING_BUFFER_HEADER
  Offset 256+: entries[0..32767]

SHARED MEMORY:
  Windows:
    Name: \\BaseNamedObjects\\SafeOpsRingBuffer
    Size: 16,777,472 bytes
    Kernel: PAGE_READWRITE
    Userspace: PAGE_READONLY
  
  Linux:
    Path: /dev/shm/safeops_ring
    Size: 16,777,472 bytes
    Perms: 0644

DEPENDENCIES (External):
  <stdint.h>
  <string.h> (memcpy)
  <intrin.h> (Windows - InterlockedIncrement64, _mm_sfence)
  <stdatomic.h> (Linux - atomic_fetch_add)

DEPENDENCIES (SafeOps):
  ✅ shared_constants.h (RING_BUFFER_SIZE, RING_BUFFER_MAGIC, RING_BUFFER_ENTRIES)
  ✅ packet_structs.h (PACKET_INFO)

REQUIRED BY:
  ❌ kernel_driver/shared_memory.c (creates shared memory)
  ❌ userspace_service/ring_reader.c (maps and reads)

VERIFICATION:
  sizeof(RING_BUFFER) == 16,777,472
  sizeof(RING_BUFFER_HEADER) == 256
  write_index / read_index on separate cache lines
  No data races (Thread Sanitizer clean)
```

---

## 📄 LEVEL 1: ioctl_codes.h

```yaml
FILE: src/shared/c/ioctl_codes.h
LEVEL: 1 (Depends on shared_constants.h)
SIZE: ~120 lines
USAGE: 📄 RAW (#include for IOCTL codes)

PURPOSE:
  Windows IOCTL command codes for kernel driver communication. Both driver
  (dispatch) and userspace (invoke) use same codes for DeviceIoControl calls.

KEY DEFINITIONS:
  Device Name:
    SAFEOPS_DEVICE_NAME = L"\\\\.\\SafeOpsFirewall"
  
  IOCTL Commands:
    IOCTL_SAFEOPS_GET_STATS
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
      - Get driver statistics
    
    IOCTL_SAFEOPS_ADD_RULE
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
      - Add firewall rule
    
    IOCTL_SAFEOPS_DELETE_RULE
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
      - Delete firewall rule
    
    IOCTL_SAFEOPS_LIST_RULES
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
      - List all rules
    
    IOCTL_SAFEOPS_GET_CONNECTIONS
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
      - Get active connections
    
    IOCTL_SAFEOPS_FLUSH_RING
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
      - Flush ring buffer
    
    IOCTL_SAFEOPS_SET_LOG_LEVEL
      - CTL_CODE(FILE_DEVICE_NETWORK, 0x807, METHOD_BUFFERED, FILE_WRITE_DATA)
      - Change driver log level

IOCTL PATTERN:
  All use:
    - FILE_DEVICE_NETWORK (network driver)
    - METHOD_BUFFERED (safest transfer mode)
    - FILE_READ_DATA or FILE_WRITE_DATA (access rights)

DEPENDENCIES (External):
  <windows.h> (CTL_CODE macro, FILE_DEVICE_*, METHOD_*)

DEPENDENCIES (SafeOps):
  ✅ shared_constants.h (IOCTL_TIMEOUT_MS)

REQUIRED BY:
  ❌ kernel_driver/ioctl_handler.c (dispatch table)
  ❌ userspace_service/ioctl_client.c (DeviceIoControl wrapper)

FUTURE USAGE:
  Go services via CGO:
    - Call userspace service which calls driver
  
  Rust services via FFI:
    - Same as Go, through userspace bridge

VERIFICATION:
  All codes unique (no duplicates)
  Correct access rights (READ_DATA vs WRITE_DATA)
  METHOD_BUFFERED for all (security)
```

---

## 📈 Dependency Graph

```
shared_constants.h (Level 0)
  ↓
  ├→ packet_structs.h (Level 1)
  │    ↓
  │    └→ ring_buffer.h (Level 1, also uses shared_constants.h)
  │
  └→ ioctl_codes.h (Level 1)
```

---

## ⚙️ Compilation Notes

### Raw Usage (Header-Only)
All 4 files are header-only. No .c files exist. They are **#included** directly into:
- Kernel driver C files (when implemented)
- Userspace service C files (when implemented)
- Rust FFI bindings (via bindgen)
- Go CGO code (via import "C")

### Build Commands
**No build needed** - headers are compiled into consumer code.

**Verification:**
```powershell
# Syntax check all headers
gcc -fsyntax-only src/shared/c/*.h

# Generate Rust bindings (future)
bindgen src/shared/c/packet_structs.h -o src/firewall_engine/bindings.rs

# Check sizes
gcc -E src/shared/c/packet_structs.h | grep "sizeof"
```

---

## 🎯 Future Usage (Phase 2)

When kernel_driver and userspace_service are implemented:

**kernel_driver will:**
1. Include all 4 headers
2. Fill PACKET_INFO structures
3. Write to ring_buffer
4. Handle IOCTL commands

**userspace_service will:**
1. Include all 4 headers
2. Read from ring_buffer
3. Send IOCTL commands to driver
4. Convert packets to JSON logs

**Rust services will:**
1. Use bindgen to generate FFI bindings
2. Access ring_buffer if needed
3. Call userspace service via bridge

**Go services will:**
1. Use CGO to access C structs
2. Call userspace service for driver comms

---

## ✅ Complete File List

1. **shared_constants.h** - Compile-time constants (Level 0)
2. **packet_structs.h** - Packet types (Level 1, depends on constants)
3. **ring_buffer.h** - Lock-free queue (Level 1, depends on constants + packets)
4. **ioctl_codes.h** - Driver commands (Level 1, depends on constants)

**Total:** 4 headers, ~750 lines, 100% header-only

---

[← Back to Master Index](DEPENDENCY_MAP_MASTER.md)  
Next: [DEPENDENCY_MAP_GO.md](DEPENDENCY_MAP_GO.md) (37 Go files)
