/*
 * shared_constants.h
 * Shared constants, limits, and configuration values used across kernel and
 * userspace
 *
 * Categories: Buffer Sizes, Network Limits, Timing, Performance Tuning, Feature
 * Flags
 */

#ifndef SAFEOPS_SHARED_CONSTANTS_H
#define SAFEOPS_SHARED_CONSTANTS_H

#include <stdint.h>

// ============================================================================
// BUFFER SIZES
// ============================================================================

// Ring buffer configuration
#define RING_BUFFER_SIZE (2ULL * 1024 * 1024 * 1024)  // 2 GB
#define RING_BUFFER_ENTRY_SIZE 128                    // 128 bytes per entry
#define RING_BUFFER_ENTRY_COUNT (16ULL * 1024 * 1024) // 16 million entries

// Packet buffer sizes
#define PACKET_BUFFER_SIZE 2048 // 2 KB per packet buffer
#define MAX_PACKET_SIZE 65536   // 64 KB maximum packet size
#define MIN_PACKET_SIZE 64      // Minimum Ethernet frame
#define JUMBO_FRAME_SIZE 9000   // Jumbo frame MTU

// Batch processing
#define BATCH_SIZE 128     // 128 packets per batch
#define MAX_BATCH_SIZE 256 // Maximum batch size
#define MIN_BATCH_SIZE 16  // Minimum batch size

// Buffer pools
#define SMALL_BUFFER_SIZE 256   // 256 bytes
#define MEDIUM_BUFFER_SIZE 2048 // 2 KB
#define LARGE_BUFFER_SIZE 16384 // 16 KB

// ============================================================================
// NETWORK LIMITS
// ============================================================================

// NIC configuration
#define MAX_NICS 3              // Maximum 3 NICs (WAN/LAN/WiFi)
#define MAX_NIC_NAME_LENGTH 128 // Maximum NIC name length
#define MAX_ADAPTERS 8          // Maximum network adapters

// Firewall rules
#define MAX_FIREWALL_RULES 100000 // 100,000 firewall rules
#define MAX_RULE_NAME_LENGTH 256  // Maximum rule name
#define MAX_RULE_DESCRIPTION 512  // Maximum rule description

// Connection tracking
#define MAX_CONNECTIONS (10ULL * 1000 * 1000) // 10 million connections
#define MAX_SESSIONS (5ULL * 1000 * 1000)     // 5 million sessions
#define MAX_FLOWS (20ULL * 1000 * 1000)       // 20 million flows

// Address limits
#define MAX_IP_ADDRESSES 65536 // Maximum tracked IPs
#define MAX_PORT_RANGES 1024   // Maximum port ranges
#define MAX_PROTOCOL_COUNT 256 // All IP protocols

// Packet queue limits
#define MAX_QUEUE_SIZE 65536     // Maximum queue entries
#define MAX_PENDING_PACKETS 4096 // Maximum pending packets

// ============================================================================
// TIMING CONSTANTS (in seconds unless specified)
// ============================================================================

// Connection timeouts
#define CONNECTION_TIMEOUT 300 // 5 minutes
#define TCP_TIMEOUT 300        // 5 minutes
#define UDP_TIMEOUT 180        // 3 minutes
#define ICMP_TIMEOUT 60        // 1 minute

// TCP specific timeouts
#define TCP_KEEPALIVE_INTERVAL 60 // 60 seconds
#define TCP_SYN_TIMEOUT 30        // 30 seconds
#define TCP_FIN_TIMEOUT 120       // 2 minutes
#define TCP_TIME_WAIT_TIMEOUT 30  // 30 seconds

// Intervals (in seconds)
#define STATISTICS_INTERVAL 1   // 1 second
#define HEALTH_CHECK_INTERVAL 5 // 5 seconds
#define CLEANUP_INTERVAL 60     // 1 minute
#define WATCHDOG_INTERVAL 10    // 10 seconds

// Timeouts (in milliseconds)
#define POLL_INTERVAL_MS 1   // 1 ms
#define SPIN_TIMEOUT_MS 100  // 100 ms
#define LOCK_TIMEOUT_MS 5000 // 5 seconds
#define IO_TIMEOUT_MS 30000  // 30 seconds

// ============================================================================
// PERFORMANCE TUNING
// ============================================================================

// Thread configuration
#define WORKER_THREAD_COUNT 16 // 16 worker threads
#define MIN_WORKER_THREADS 4   // Minimum workers
#define MAX_WORKER_THREADS 64  // Maximum workers

// Queue configuration
#define QUEUE_DEPTH 1024     // Queue depth
#define MAX_QUEUE_DEPTH 8192 // Maximum queue depth
#define MIN_QUEUE_DEPTH 64   // Minimum queue depth

// CPU affinity
#define CPU_CORE_COUNT 16 // Expected CPU cores
#define RSS_QUEUE_COUNT 8 // RSS queues

// Cache optimization
#define CACHE_LINE_SIZE 64  // 64-byte cache line
#define PREFETCH_DISTANCE 8 // Prefetch 8 entries ahead

// ============================================================================
// FEATURE FLAGS
// ============================================================================

// Checksumming
#define FEATURE_ENABLE_CHECKSUMMING (1 << 0) // Enable checksum verification
#define FEATURE_OFFLOAD_CHECKSUM_TX (1 << 1) // Offload TX checksum
#define FEATURE_OFFLOAD_CHECKSUM_RX (1 << 2) // Offload RX checksum

// Fragmentation
#define FEATURE_ENABLE_FRAGMENTATION (1 << 3) // Enable IP fragmentation
#define FEATURE_ENABLE_REASSEMBLY (1 << 4)    // Enable fragment reassembly

// Connection tracking
#define FEATURE_ENABLE_CONNTRACK (1 << 5)      // Enable connection tracking
#define FEATURE_ENABLE_NAT (1 << 6)            // Enable NAT
#define FEATURE_ENABLE_STATE_TRACKING (1 << 7) // Enable stateful firewall

// Statistics
#define FEATURE_ENABLE_STATISTICS (1 << 8) // Enable statistics
#define FEATURE_DETAILED_STATS (1 << 9)    // Enable detailed stats
#define FEATURE_FLOW_STATISTICS (1 << 10)  // Enable per-flow stats

// Offloading
#define FEATURE_ENABLE_TSO (1 << 11) // TCP Segmentation Offload
#define FEATURE_ENABLE_LRO (1 << 12) // Large Receive Offload
#define FEATURE_ENABLE_GSO (1 << 13) // Generic Segmentation Offload
#define FEATURE_ENABLE_GRO (1 << 14) // Generic Receive Offload

// Advanced features
#define FEATURE_ENABLE_DPI (1 << 15)            // Deep Packet Inspection
#define FEATURE_ENABLE_QOS (1 << 16)            // Quality of Service
#define FEATURE_ENABLE_RATE_LIMITING (1 << 17)  // Rate limiting
#define FEATURE_ENABLE_LOAD_BALANCING (1 << 18) // Load balancing

// Default feature set
#define DEFAULT_FEATURES                                                       \
  (FEATURE_ENABLE_CHECKSUMMING | FEATURE_ENABLE_REASSEMBLY |                   \
   FEATURE_ENABLE_CONNTRACK | FEATURE_ENABLE_STATISTICS)

// ============================================================================
// LOG LEVELS
// ============================================================================

#define LOG_LEVEL_TRACE 0    // Trace (most verbose)
#define LOG_LEVEL_DEBUG 1    // Debug
#define LOG_LEVEL_VERBOSE 2  // Verbose
#define LOG_LEVEL_INFO 3     // Info
#define LOG_LEVEL_WARN 4     // Warning
#define LOG_LEVEL_ERROR 5    // Error
#define LOG_LEVEL_CRITICAL 6 // Critical (least verbose)

// Legacy aliases
#define LOG_TRACE LOG_LEVEL_TRACE
#define LOG_DEBUG LOG_LEVEL_DEBUG
#define LOG_VERBOSE LOG_LEVEL_VERBOSE
#define LOG_INFO LOG_LEVEL_INFO
#define LOG_WARN LOG_LEVEL_WARN
#define LOG_ERROR LOG_LEVEL_ERROR

// ============================================================================
// PACKET DIRECTIONS
// ============================================================================

#define PKT_DIR_INBOUND 0x01  // Inbound packet
#define PKT_DIR_OUTBOUND 0x02 // Outbound packet
#define PKT_DIR_BOTH 0x03     // Both directions
#define PKT_DIR_LOCAL 0x04    // Local loopback

// ============================================================================
// PROTOCOLS (IP Protocol Numbers)
// ============================================================================

#define PROTO_HOPOPT 0    // IPv6 Hop-by-Hop
#define PROTO_ICMP 1      // ICMP
#define PROTO_IGMP 2      // IGMP
#define PROTO_TCP 6       // TCP
#define PROTO_UDP 17      // UDP
#define PROTO_IPV6 41     // IPv6 encapsulation
#define PROTO_ROUTING 43  // IPv6 Routing
#define PROTO_FRAGMENT 44 // IPv6 Fragment
#define PROTO_GRE 47      // GRE
#define PROTO_ESP 50      // IPsec ESP
#define PROTO_AH 51       // IPsec AH
#define PROTO_ICMPV6 58   // ICMPv6
#define PROTO_NONE 59     // IPv6 No Next Header
#define PROTO_SCTP 132    // SCTP

// ============================================================================
// FILTER ACTIONS
// ============================================================================

#define FILTER_ACTION_ALLOW 0    // Allow packet
#define FILTER_ACTION_BLOCK 1    // Block packet
#define FILTER_ACTION_DROP 1     // Drop packet (alias)
#define FILTER_ACTION_REJECT 2   // Reject with ICMP
#define FILTER_ACTION_LOG 3      // Log packet
#define FILTER_ACTION_COUNT 4    // Count only
#define FILTER_ACTION_MIRROR 5   // Mirror packet
#define FILTER_ACTION_REDIRECT 6 // Redirect packet

// ============================================================================
// ERROR CODES
// ============================================================================

#define SAFEOPS_SUCCESS 0            // Success
#define SAFEOPS_ERROR -1             // Generic error
#define SAFEOPS_INVALID_PARAM -2     // Invalid parameter
#define SAFEOPS_NO_MEMORY -3         // Out of memory
#define SAFEOPS_BUFFER_FULL -4       // Buffer full
#define SAFEOPS_BUFFER_EMPTY -5      // Buffer empty
#define SAFEOPS_NOT_FOUND -6         // Not found
#define SAFEOPS_ALREADY_EXISTS -7    // Already exists
#define SAFEOPS_TIMEOUT -8           // Timeout
#define SAFEOPS_PERMISSION_DENIED -9 // Permission denied
#define SAFEOPS_NOT_SUPPORTED -10    // Not supported
#define SAFEOPS_BUSY -11             // Resource busy
#define SAFEOPS_INVALID_STATE -12    // Invalid state

// ============================================================================
// VERSION INFORMATION
// ============================================================================

#define SAFEOPS_VERSION_MAJOR 2 // Major version
#define SAFEOPS_VERSION_MINOR 0 // Minor version
#define SAFEOPS_VERSION_PATCH 0 // Patch version
#define SAFEOPS_VERSION_BUILD 1 // Build number

#define SAFEOPS_VERSION_STRING "2.0.0.1"

// ============================================================================
// MEMORY ALIGNMENT
// ============================================================================

#define ALIGNMENT_DEFAULT 8     // Default 8-byte alignment
#define ALIGNMENT_CACHE_LINE 64 // Cache line alignment
#define ALIGNMENT_PAGE 4096     // Page alignment

// ============================================================================
// PRIORITY LEVELS
// ============================================================================

#define PRIORITY_CRITICAL 0   // Critical priority
#define PRIORITY_HIGH 1       // High priority
#define PRIORITY_NORMAL 2     // Normal priority
#define PRIORITY_LOW 3        // Low priority
#define PRIORITY_BACKGROUND 4 // Background priority

#endif // SAFEOPS_SHARED_CONSTANTS_H
