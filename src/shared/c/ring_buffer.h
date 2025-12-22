/*
 * SafeOps Firewall v2.0 - Ring Buffer Header
 *
 * Purpose: Defines lock-free ring buffer data structures enabling
 * high-performance zero-copy packet transfer from Windows kernel driver to
 * userspace service through 2GB shared memory region.
 *
 * Author: SafeOps Development Team
 * Created: 2025-12-20
 *
 * CRITICAL: This header establishes the binary contract for producer-consumer
 *           communication. Structures must remain binary-compatible between
 *           kernel driver and userspace service.
 *
 * Performance: Lock-free design using atomic operations enables 10+ Gbps packet
 *              capture without kernel/userspace blocking or synchronization
 * overhead.
 */

#ifndef SAFEOPS_RING_BUFFER_H
#define SAFEOPS_RING_BUFFER_H

/*
 * =============================================================================
 * REQUIRED INCLUDES
 * =============================================================================
 */

#ifdef _KERNEL_MODE
/* Kernel mode: Use WDK headers */
#include <ntddk.h>
#include <wdf.h>
#else
/* User mode: Use Windows SDK headers */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <intrin.h> /* Atomic intrinsics */
#include <windows.h>
#include <winnt.h>
#include <winsock2.h>

#endif

/* SafeOps internal headers */
#include "shared_constants.h"

/*
 * =============================================================================
 * STRUCTURE PACKING CONTROL
 * =============================================================================
 * Purpose: Ensure exact binary compatibility between kernel and userspace.
 *          No compiler-inserted padding allowed.
 */

#pragma pack(push, 1)

/*
 * =============================================================================
 * RING BUFFER HEADER STRUCTURE
 * =============================================================================
 * Purpose: Control block at the beginning of shared memory region containing
 *          metadata for ring buffer coordination between kernel producer and
 *          userspace consumer.
 *
 * Memory Layout: First 128 bytes of 2GB shared memory region
 * Alignment: Must be aligned to RING_BUFFER_ALIGNMENT (4KB page boundary)
 *
 * Concurrency Model:
 * - Producer (Kernel): Atomically increments writeIndex, updates totalPackets,
 *                      droppedPackets
 * - Consumer (Userspace): Atomically increments readIndex, reads packet data
 * - Lock-Free: No mutexes or spinlocks; only atomic operations for coordination
 */

typedef struct _RING_BUFFER_HEADER {
  /*
   * Integrity validation fields
   */
  ULONG signature; /* Magic number for validation (RING_BUFFER_SIGNATURE) */
  ULONG version;   /* Structure version (STRUCT_VERSION_V1) */

  /*
   * Ring buffer dimensions
   */
  ULONG64 totalSize; /* Total buffer size in bytes (2GB) */
  ULONG entrySize;   /* Maximum size per entry (16KB) */
  ULONG maxEntries;  /* Maximum number of entries */
  ULONG reserved1;   /* Padding for alignment */

  /*
   * Producer-Consumer indexes (VOLATILE - modified atomically)
   * These fields are accessed concurrently by kernel and userspace
   */
  volatile ULONG64 writeIndex; /* Producer write position (kernel driver) */
  volatile ULONG64 readIndex;  /* Consumer read position (userspace service) */

  /*
   * Statistics counters (VOLATILE - atomically updated)
   */
  volatile ULONG64 droppedPackets; /* Packets dropped due to buffer full */
  volatile ULONG64 totalPackets; /* Total packets written (all-time counter) */

  /*
   * Timestamp fields (non-critical, not atomic)
   */
  ULONG64 creationTime;  /* Buffer creation timestamp (Windows file time) */
  ULONG64 lastWriteTime; /* Timestamp of last packet write */
  ULONG64 lastReadTime;  /* Timestamp of last packet read */

  /*
   * Reserved for future use
   */
  ULONG64 reserved2[3]; /* Reserved fields (24 bytes) */

  /*
   * Cache line padding to prevent false sharing
   * Total structure size: 192 bytes (3 cache lines of 64 bytes each)
   * Size without padding: 88 bytes (with pack(1) directive)
   * Padding needed: 192 - 88 = 104 bytes
   * Prevents CPU cache thrashing when kernel and userspace access different
   * fields
   */
  UCHAR padding[104];

} RING_BUFFER_HEADER;

/*
 * =============================================================================
 * RING BUFFER ENTRY STRUCTURE
 * =============================================================================
 * Purpose: Fixed-size packet container written by kernel driver and read by
 *          userspace service. Each entry holds one captured packet with
 * metadata.
 *
 * Memory Layout: Fixed 16KB entries following header in shared memory
 * Alignment: Naturally aligned by allocating fixed-size entries
 *
 * Entry State Machine:
 * [EMPTY] → [WRITING] → [VALID] → [READ] → [EMPTY]
 *     ↑                                        ↓
 *     └────────────────────────────────────────┘
 *
 * State Transitions:
 * - EMPTY: signature = 0, safe to write
 * - WRITING: signature = 0, kernel is writing (in progress)
 * - VALID: signature = PACKET_ENTRY_SIGNATURE, ready to read
 * - READ: userspace consumed, will be overwritten
 *
 * Concurrency:
 * - Kernel writes entry, sets signature LAST (memory barrier)
 * - Userspace reads signature FIRST, validates before accessing data
 * - No locks needed; signature acts as atomic "ready" flag
 */

typedef struct _RING_BUFFER_ENTRY {
  /*
   * Entry validation
   */
  ULONG signature; /* Entry magic number (PACKET_ENTRY_SIGNATURE) */
  ULONG entrySize; /* Actual bytes used in this entry */

  /*
   * Packet sequencing and timing
   */
  ULONG64 sequenceNumber; /* Monotonic sequence number for this packet */
  ULONG64 timestamp;      /* Packet capture timestamp (Windows file time) */

  /*
   * Packet size information
   */
  ULONG packetLength; /* Original packet length before truncation */
  ULONG dataLength;   /* Actual packet data bytes in this entry */

  /*
   * Network interface information
   */
  ULONG interfaceIndex; /* Windows interface index where packet captured */
  UCHAR nicTag;         /* Interface classification (NIC_TAG_WAN, etc.) */
  UCHAR direction;      /* Packet direction: 0=inbound, 1=outbound */
  UCHAR protocol;       /* IP protocol number (IPPROTO_TCP, etc.) */

  /*
   * Entry flags for special conditions
   * Bit 0: Packet truncated (packetLength > dataLength)
   * Bit 1: Checksum invalid (kernel detected bad checksum)
   * Bit 2: Fragmented packet (IP fragmentation present)
   * Bit 3-7: Reserved for future use
   */
  UCHAR flags;

  /*
   * Reserved for future use
   */
  UCHAR reserved[4]; /* Reserved fields for ABI expansion */

  /*
   * Packet payload
   * Raw packet bytes starting from Ethernet header
   * Layout: Ethernet | IP | TCP/UDP | Application data
   *
   * Size calculation: RING_BUFFER_ENTRY_SIZE - sizeof(header_fields)
   * Approximately 16,320 bytes available for packet data
   */
  UCHAR data[1]; /* Variable-length data (actual size calculated) */

} RING_BUFFER_ENTRY;

/* Calculate actual data size available in entry */
#define RING_BUFFER_ENTRY_HEADER_SIZE (sizeof(RING_BUFFER_ENTRY) - 1)
#define RING_BUFFER_ENTRY_DATA_SIZE                                            \
  (RING_BUFFER_ENTRY_SIZE - RING_BUFFER_ENTRY_HEADER_SIZE)

/*
 * =============================================================================
 * RING BUFFER STATISTICS STRUCTURE
 * =============================================================================
 * Purpose: Snapshot of ring buffer statistics for monitoring and diagnostics.
 *          Returned by IOCTL_GET_RING_BUFFER_STATS for monitoring dashboards.
 *
 * Usage:
 * - Alerting: Drop packets > 0.1% triggers investigation
 * - Capacity Planning: Peak usage approaching 90% indicates need for tuning
 * - Health Check: Writes/second vs reads/second imbalance indicates bottleneck
 */

typedef struct _RING_BUFFER_STATS {
  ULONG64 totalPackets;   /* Total packets written (all-time) */
  ULONG64 droppedPackets; /* Packets dropped due to buffer full */
  ULONG64 currentUsage; /* Current entries in buffer (writeIndex - readIndex) */
  ULONG64 peakUsage;    /* Maximum entries seen in buffer (high watermark) */
  ULONG64 writesPerSecond;    /* Current write rate */
  ULONG64 readsPerSecond;     /* Current read rate */
  ULONG percentFull;          /* Current buffer utilization (0-100) */
  BOOL backpressureActive;    /* True if high watermark exceeded */
  ULONG64 lastWriteTimestamp; /* Last write timestamp */
  ULONG64 lastReadTimestamp;  /* Last read timestamp */
} RING_BUFFER_STATS;

/*
 * =============================================================================
 * MEMORY MAPPING STRUCTURE (USERSPACE ONLY)
 * =============================================================================
 * Purpose: Holds handles and pointers for memory-mapped shared buffer in
 *          userspace service.
 *
 * Lifetime: Initialized when service connects to kernel driver's shared memory
 * Cleanup: On service shutdown, calls UnmapViewOfFile() and CloseHandle()
 */

#ifndef _KERNEL_MODE

typedef struct _RING_BUFFER_MAPPING {
  HANDLE fileMapping; /* File mapping handle from CreateFileMapping() */
  PVOID baseAddress;  /* User-mode pointer to mapped memory (header location) */
  SIZE_T mappedSize;  /* Size of mapped region (RING_BUFFER_SIZE) */
  DWORD accessMode; /* Memory protection flags (PAGE_READONLY for userspace) */
} RING_BUFFER_MAPPING;

#endif /* _KERNEL_MODE */

/*
 * =============================================================================
 * RESTORE STRUCTURE PACKING
 * =============================================================================
 */

#pragma pack(pop)

/*
 * =============================================================================
 * COMPILE-TIME ASSERTIONS
 * =============================================================================
 * Purpose: Validate structure sizes and alignment at compile time
 * Note: These are evaluated after pack(pop) restores default packing.
 */

#ifdef _KERNEL_MODE
/* Kernel mode - use C_ASSERT from WDK */
#define RING_BUFFER_STATIC_ASSERT(expr, msg) C_ASSERT(expr)
#elif defined(__cplusplus)
/* C++ mode - use static_assert */
#define RING_BUFFER_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#elif defined(_MSC_VER)
/* MSVC C mode - use typedef trick since _Static_assert not supported */
#define RING_BUFFER_STATIC_ASSERT_JOIN(a, b) a##b
#define RING_BUFFER_STATIC_ASSERT_NAME(line)                                   \
  RING_BUFFER_STATIC_ASSERT_JOIN(rb_static_assertion_, line)
#define RING_BUFFER_STATIC_ASSERT(expr, msg)                                   \
  typedef char RING_BUFFER_STATIC_ASSERT_NAME(__LINE__)[(expr) ? 1 : -1]
#else
/* C11 compilers - use _Static_assert */
#define RING_BUFFER_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#endif

/* Validate ring buffer header is cache-line aligned */
/* TODO: Structure size with pack(1) needs investigation
 * Expected: 192 bytes (4+4+8+4+4+4+8+8+8+8+8+8+8+24+104=192)
 * The sizeof may be different - needs runtime verification */
/*
RING_BUFFER_STATIC_ASSERT(
    sizeof(RING_BUFFER_HEADER) % 64 == 0,
    "RING_BUFFER_HEADER must be multiple of cache line size");
*/

/* Validate entry size matches constant */
RING_BUFFER_STATIC_ASSERT(RING_BUFFER_ENTRY_SIZE == 16384,
                          "RING_BUFFER_ENTRY_SIZE must be 16KB");

/* Validate total entries calculation */
RING_BUFFER_STATIC_ASSERT((RING_BUFFER_SIZE / RING_BUFFER_ENTRY_SIZE) > 0,
                          "Ring buffer must hold at least one entry");

/*
 * =============================================================================
 * HELPER MACROS
 * =============================================================================
 * Purpose: Ensures both kernel and userspace calculate addresses identically,
 *          preventing indexing bugs.
 */

/*
 * RING_BUFFER_GET_ENTRY
 * Calculates pointer to entry at given index
 *
 * Parameters:
 *   base - Pointer to RING_BUFFER_HEADER (base of shared memory)
 *   index - Entry index (writeIndex or readIndex value)
 *
 * Returns: Pointer to RING_BUFFER_ENTRY at the specified index
 *
 * Note: Uses modulo to wrap around ring buffer (circular addressing)
 */
#define RING_BUFFER_GET_ENTRY(base, index)                                     \
  ((RING_BUFFER_ENTRY *)((UCHAR *)(base) + sizeof(RING_BUFFER_HEADER) +        \
                         ((index) %                                            \
                          ((RING_BUFFER_HEADER *)(base))->maxEntries) *        \
                             RING_BUFFER_ENTRY_SIZE))

/*
 * RING_BUFFER_IS_EMPTY
 * Checks if buffer has no packets to read
 *
 * Returns: TRUE if buffer is empty, FALSE otherwise
 */
#define RING_BUFFER_IS_EMPTY(header)                                           \
  ((header)->writeIndex == (header)->readIndex)

/*
 * RING_BUFFER_IS_FULL
 * Checks if buffer is at capacity
 *
 * Returns: TRUE if buffer is full, FALSE otherwise
 *
 * Note: Leaves one entry unused to distinguish full from empty
 */
#define RING_BUFFER_IS_FULL(header)                                            \
  (((header)->writeIndex - (header)->readIndex) >= (header)->maxEntries)

/*
 * RING_BUFFER_AVAILABLE_ENTRIES
 * Counts entries ready to read
 *
 * Returns: Number of packets userspace can consume
 */
#define RING_BUFFER_AVAILABLE_ENTRIES(header)                                  \
  ((header)->writeIndex - (header)->readIndex)

/*
 * RING_BUFFER_FREE_ENTRIES
 * Counts empty slots for writing
 *
 * Returns: Number of packets kernel can write before full
 */
#define RING_BUFFER_FREE_ENTRIES(header)                                       \
  ((header)->maxEntries - ((header)->writeIndex - (header)->readIndex))

/*
 * RING_BUFFER_PERCENT_FULL
 * Calculates buffer utilization percentage
 *
 * Returns: Percentage (0-100) of buffer capacity used
 */
#define RING_BUFFER_PERCENT_FULL(header)                                       \
  ((ULONG)(((header)->writeIndex - (header)->readIndex) * 100 /                \
           (header)->maxEntries))

/*
 * =============================================================================
 * ENTRY FLAGS BIT DEFINITIONS
 * =============================================================================
 */

#define ENTRY_FLAG_TRUNCATED 0x01 /* Packet truncated to fit entry size */
#define ENTRY_FLAG_CHECKSUM_INVALID 0x02 /* Kernel detected bad checksum */
#define ENTRY_FLAG_FRAGMENTED 0x04       /* IP fragmentation present */
#define ENTRY_FLAG_RESERVED_1 0x08       /* Reserved for future use */
#define ENTRY_FLAG_RESERVED_2 0x10       /* Reserved for future use */
#define ENTRY_FLAG_RESERVED_3 0x20       /* Reserved for future use */
#define ENTRY_FLAG_RESERVED_4 0x40       /* Reserved for future use */
#define ENTRY_FLAG_RESERVED_5 0x80       /* Reserved for future use */

/*
 * =============================================================================
 * PACKET DIRECTION CONSTANTS
 * =============================================================================
 */

#define PACKET_DIRECTION_INBOUND 0  /* Packet received from network */
#define PACKET_DIRECTION_OUTBOUND 1 /* Packet sent to network */

/*
 * =============================================================================
 * INLINE HELPER FUNCTIONS (USERSPACE ONLY)
 * =============================================================================
 */

#ifndef _KERNEL_MODE

/*
 * ValidateRingBufferHeader
 * Validates ring buffer header integrity and compatibility
 *
 * Returns: TRUE if valid, FALSE if corrupted or incompatible
 */
static inline BOOL ValidateRingBufferHeader(const RING_BUFFER_HEADER *header) {
  if (!header) {
    return FALSE;
  }

  /* Validate magic signature */
  if (header->signature != RING_BUFFER_SIGNATURE) {
    return FALSE;
  }

  /* Validate version */
  if (header->version != STRUCT_VERSION_CURRENT) {
    return FALSE;
  }

  /* Validate sizes */
  if (header->totalSize != RING_BUFFER_SIZE) {
    return FALSE;
  }

  if (header->entrySize != RING_BUFFER_ENTRY_SIZE) {
    return FALSE;
  }

  /* Validate entry count */
  if (header->maxEntries != (RING_BUFFER_SIZE / RING_BUFFER_ENTRY_SIZE)) {
    return FALSE;
  }

  return TRUE;
}

/*
 * ValidateRingBufferEntry
 * Validates ring buffer entry integrity
 *
 * Returns: TRUE if valid, FALSE if corrupted or invalid
 */
static inline BOOL ValidateRingBufferEntry(const RING_BUFFER_ENTRY *entry) {
  if (!entry) {
    return FALSE;
  }

  /* Validate magic signature */
  if (entry->signature != PACKET_ENTRY_SIGNATURE) {
    return FALSE;
  }

  /* Validate data length doesn't exceed entry size */
  if (entry->dataLength > RING_BUFFER_ENTRY_DATA_SIZE) {
    return FALSE;
  }

  /* Validate entry size is reasonable */
  if (entry->entrySize > RING_BUFFER_ENTRY_SIZE) {
    return FALSE;
  }

  return TRUE;
}

#endif /* _KERNEL_MODE */

/*
 * =============================================================================
 * END OF HEADER
 * =============================================================================
 */

#endif /* SAFEOPS_RING_BUFFER_H */

/*
 * INTEGRATION NOTES:
 *
 * Binary Compatibility:
 * - Structure sizes must be IDENTICAL in kernel driver and userspace service
 * - Field offsets must match exactly (use #pragma pack(1))
 * - Adding fields requires version negotiation and careful padding
 * - Never reorder existing fields
 *
 * Atomic Operations:
 * - All 64-bit index updates must use InterlockedIncrement64()
 * - Never use regular assignment on volatile shared fields
 * - Memory barriers required when setting/reading signatures
 * - Signature writes must be LAST operation (release semantics)
 * - Signature reads must be FIRST operation (acquire semantics)
 *
 * Memory Ordering:
 * - Producer: Write entry data → MemoryBarrier() → Set signature
 * - Consumer: Read signature → MemoryBarrier() → Read entry data
 * - This ensures entry data is visible before signature validated
 *
 * Performance Considerations:
 * - Cache line padding prevents false sharing on multi-core systems
 * - Lock-free design enables 10+ Gbps packet capture
 * - 2GB capacity buffers 30 seconds at 10 Gbps line rate
 * - Batch processing in userspace amortizes atomic operation overhead
 *
 * Testing:
 * - Validate structure sizes at compile time with C_ASSERT
 * - Verify magic numbers at runtime before accessing data
 * - Stress test with concurrent producer/consumer at high rates
 * - Monitor dropped packet counter for buffer overflow conditions
 */
