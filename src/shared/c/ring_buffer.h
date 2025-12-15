/*
 * ring_buffer.h
 * Shared memory ring buffer for high-performance kernel-to-userspace packet
 * transfer
 *
 * Lock-free, cache-aligned ring buffer with atomic operations for zero-copy
 * packet delivery Total size: 2 GB | Entry count: 16 million | Entry size: 128
 * bytes
 */

#ifndef SAFEOPS_RING_BUFFER_H
#define SAFEOPS_RING_BUFFER_H

#include <stdint.h>

#ifdef _WIN32
#include <intrin.h>
#define CACHE_LINE_SIZE 64
#define ALIGN_CACHE __declspec(align(CACHE_LINE_SIZE))
#define ATOMIC_LOAD(ptr)                                                       \
  _InterlockedCompareExchange((volatile long *)(ptr), 0, 0)
#define ATOMIC_STORE(ptr, val)                                                 \
  _InterlockedExchange((volatile long *)(ptr), (long)(val))
#define ATOMIC_CAS(ptr, expected, desired)                                     \
  (_InterlockedCompareExchange((volatile long *)(ptr), (long)(desired),        \
                               (long)(expected)) == (long)(expected))
#define MEMORY_BARRIER() _ReadWriteBarrier()
#define COMPILER_BARRIER() _ReadWriteBarrier()
#else
#include <stdatomic.h>
#define CACHE_LINE_SIZE 64
#define ALIGN_CACHE __attribute__((aligned(CACHE_LINE_SIZE)))
#define ATOMIC_LOAD(ptr)                                                       \
  atomic_load_explicit((atomic_uint *)(ptr), memory_order_acquire)
#define ATOMIC_STORE(ptr, val)                                                 \
  atomic_store_explicit((atomic_uint *)(ptr), (val), memory_order_release)
#define ATOMIC_CAS(ptr, expected, desired)                                     \
  atomic_compare_exchange_strong_explicit((atomic_uint *)(ptr), &(expected),   \
                                          (desired), memory_order_release,     \
                                          memory_order_acquire)
#define MEMORY_BARRIER() atomic_thread_fence(memory_order_seq_cst)
#define COMPILER_BARRIER() asm volatile("" ::: "memory")
#endif

// Ring buffer configuration
#define RING_BUFFER_ENTRY_SIZE 128                    // 128 bytes per entry
#define RING_BUFFER_ENTRY_COUNT (16ULL * 1024 * 1024) // 16 million entries
#define RING_BUFFER_DATA_SIZE                                                  \
  (RING_BUFFER_ENTRY_COUNT * RING_BUFFER_ENTRY_SIZE) // 2 GB
#define RING_BUFFER_TOTAL_SIZE                                                 \
  (sizeof(ring_buffer_metadata_t) + RING_BUFFER_DATA_SIZE)

// NIC interface tags
typedef enum {
  NIC_TAG_UNKNOWN = 0,
  NIC_TAG_WAN = 1,
  NIC_TAG_LAN = 2,
  NIC_TAG_WIFI = 3,
  NIC_TAG_LOOPBACK = 4
} nic_tag_t;

// Packet direction
typedef enum { PKT_DIR_INBOUND = 0, PKT_DIR_OUTBOUND = 1 } packet_direction_t;

// Packet flags
#define PKT_FLAG_TRUNCATED (1 << 0)    // Packet was truncated
#define PKT_FLAG_CHECKSUM_BAD (1 << 1) // Bad checksum
#define PKT_FLAG_DROPPED (1 << 2)      // Packet dropped by filter
#define PKT_FLAG_FRAGMENTED (1 << 3)   // IP fragment
#define PKT_FLAG_ENCRYPTED (1 << 4)    // Encrypted packet
#define PKT_FLAG_MULTICAST (1 << 5)    // Multicast packet
#define PKT_FLAG_BROADCAST (1 << 6)    // Broadcast packet

// Ring buffer metadata (cache-aligned)
typedef struct ALIGN_CACHE {
  // Buffer configuration (read-only after init)
  uint32_t entry_size;  // Size of each entry (128 bytes)
  uint32_t entry_count; // Total number of entries (16M)
  uint64_t buffer_size; // Total buffer size (2 GB)

  // Producer state (written by kernel, read by userspace) - cache line aligned
  ALIGN_CACHE volatile uint32_t producer_index; // Current write position
  uint32_t _padding1[15];                       // Pad to cache line

  // Consumer state (written by userspace, read by kernel) - cache line aligned
  ALIGN_CACHE volatile uint32_t consumer_index; // Current read position
  uint32_t _padding2[15];                       // Pad to cache line

  // Statistics (updated atomically)
  ALIGN_CACHE volatile uint64_t total_packets; // Total packets written
  volatile uint64_t dropped_packets;           // Packets dropped (buffer full)
  volatile uint64_t total_bytes;               // Total bytes transferred
  volatile uint64_t consumer_reads;            // Total consumer reads

  // Status flags
  volatile uint32_t buffer_full;     // Buffer is full flag
  volatile uint32_t producer_active; // Producer is writing
  volatile uint32_t consumer_active; // Consumer is reading
  volatile uint32_t error_count;     // Error counter

} ring_buffer_metadata_t;

// Packet entry structure (128 bytes total)
typedef struct ALIGN_CACHE {
  // Timestamp (8 bytes)
  uint64_t timestamp; // Packet capture timestamp (nanoseconds since boot)

  // Packet metadata (16 bytes)
  uint32_t packet_length;   // Original packet length
  uint16_t captured_length; // Captured length (may be truncated)
  uint8_t nic_tag;          // NIC interface tag (nic_tag_t)
  uint8_t direction;        // Packet direction (packet_direction_t)
  uint32_t flags;           // Packet flags
  uint32_t hash;            // Flow hash for load balancing

  // Header pointers (offsets into data) (8 bytes)
  uint16_t eth_offset;       // Ethernet header offset
  uint16_t ip_offset;        // IP header offset
  uint16_t transport_offset; // TCP/UDP header offset
  uint16_t payload_offset;   // Payload offset

  // Protocol info (8 bytes)
  uint16_t eth_type;   // Ethernet type (e.g., 0x0800 for IPv4)
  uint8_t ip_version;  // IP version (4 or 6)
  uint8_t ip_protocol; // IP protocol (TCP=6, UDP=17)
  uint16_t src_port;   // Source port (if TCP/UDP)
  uint16_t dst_port;   // Destination port (if TCP/UDP)

  // Reserved for future use (8 bytes)
  uint32_t reserved1;
  uint32_t reserved2;

  // Packet data (80 bytes)
  uint8_t data[80]; // Packet headers + partial payload

} ring_buffer_entry_t;

// Ensure entry is exactly 128 bytes
_Static_assert(sizeof(ring_buffer_entry_t) == 128,
               "ring_buffer_entry_t must be 128 bytes");

// Complete ring buffer structure
typedef struct {
  ring_buffer_metadata_t metadata;
  ring_buffer_entry_t entries[RING_BUFFER_ENTRY_COUNT];
} ring_buffer_t;

// Ring buffer operations (inline for performance)

/**
 * Get next producer index (returns UINT32_MAX if buffer is full)
 */
static inline uint32_t ring_buffer_next_producer(ring_buffer_metadata_t *meta) {
  uint32_t current_producer = ATOMIC_LOAD(&meta->producer_index);
  uint32_t current_consumer = ATOMIC_LOAD(&meta->consumer_index);
  uint32_t next_producer = (current_producer + 1) % meta->entry_count;

  // Check if buffer is full
  if (next_producer == current_consumer) {
    ATOMIC_STORE(&meta->buffer_full, 1);
    return UINT32_MAX;
  }

  return current_producer;
}

/**
 * Advance producer index
 */
static inline void ring_buffer_advance_producer(ring_buffer_metadata_t *meta) {
  uint32_t current = ATOMIC_LOAD(&meta->producer_index);
  uint32_t next = (current + 1) % meta->entry_count;
  ATOMIC_STORE(&meta->producer_index, next);
  ATOMIC_STORE(&meta->buffer_full, 0);
  MEMORY_BARRIER();
}

/**
 * Get current consumer index (returns UINT32_MAX if buffer is empty)
 */
static inline uint32_t ring_buffer_next_consumer(ring_buffer_metadata_t *meta) {
  uint32_t current_consumer = ATOMIC_LOAD(&meta->consumer_index);
  uint32_t current_producer = ATOMIC_LOAD(&meta->producer_index);

  // Check if buffer is empty
  if (current_consumer == current_producer) {
    return UINT32_MAX;
  }

  return current_consumer;
}

/**
 * Advance consumer index
 */
static inline void ring_buffer_advance_consumer(ring_buffer_metadata_t *meta) {
  uint32_t current = ATOMIC_LOAD(&meta->consumer_index);
  uint32_t next = (current + 1) % meta->entry_count;
  ATOMIC_STORE(&meta->consumer_index, next);
  MEMORY_BARRIER();
}

/**
 * Get available entries for reading
 */
static inline uint32_t ring_buffer_available(ring_buffer_metadata_t *meta) {
  uint32_t producer = ATOMIC_LOAD(&meta->producer_index);
  uint32_t consumer = ATOMIC_LOAD(&meta->consumer_index);

  if (producer >= consumer) {
    return producer - consumer;
  } else {
    return meta->entry_count - consumer + producer;
  }
}

/**
 * Get free space for writing
 */
static inline uint32_t ring_buffer_free_space(ring_buffer_metadata_t *meta) {
  return meta->entry_count - ring_buffer_available(meta) - 1;
}

/**
 * Initialize ring buffer metadata
 */
static inline void ring_buffer_init(ring_buffer_metadata_t *meta) {
  meta->entry_size = RING_BUFFER_ENTRY_SIZE;
  meta->entry_count = RING_BUFFER_ENTRY_COUNT;
  meta->buffer_size = RING_BUFFER_DATA_SIZE;

  ATOMIC_STORE(&meta->producer_index, 0);
  ATOMIC_STORE(&meta->consumer_index, 0);
  ATOMIC_STORE(&meta->total_packets, 0);
  ATOMIC_STORE(&meta->dropped_packets, 0);
  ATOMIC_STORE(&meta->total_bytes, 0);
  ATOMIC_STORE(&meta->consumer_reads, 0);
  ATOMIC_STORE(&meta->buffer_full, 0);
  ATOMIC_STORE(&meta->producer_active, 0);
  ATOMIC_STORE(&meta->consumer_active, 0);
  ATOMIC_STORE(&meta->error_count, 0);

  MEMORY_BARRIER();
}

#endif // SAFEOPS_RING_BUFFER_H
