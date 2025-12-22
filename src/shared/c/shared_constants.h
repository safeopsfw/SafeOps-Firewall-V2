/*
 * SafeOps Firewall v2.0 - Shared Constants Header
 *
 * Purpose: Provides foundational constants, limits, and preprocessor
 * definitions shared between the Windows kernel driver and userspace service to
 * ensure consistent behavior and ABI compatibility.
 *
 * Author: SafeOps Development Team
 * Created: 2025-12-20
 *
 * CRITICAL: This header establishes the ABI contract between kernel and
 * userspace. Changes to constants require rebuilding BOTH components. Version
 * mismatches will cause initialization failures.
 */

#ifndef SAFEOPS_SHARED_CONSTANTS_H
#define SAFEOPS_SHARED_CONSTANTS_H

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
/* Define WIN32_LEAN_AND_MEAN to exclude rarely-used Windows headers */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Include winsock2.h BEFORE windows.h to prevent redefinition errors */
#include <windows.h>
#include <winsock2.h>

/* Standard integer types */
#include <stdint.h>
#endif

/*
 * =============================================================================
 * VERSION AND BUILD INFORMATION
 * =============================================================================
 * Purpose: Version tracking enables kernel driver and userspace service to
 *          verify compatibility at initialization. Mismatched versions prevent
 *          incorrect structure interpretations that could cause crashes.
 */

#define SAFEOPS_DRIVER_VERSION_MAJOR 2
#define SAFEOPS_DRIVER_VERSION_MINOR 0
#define SAFEOPS_DRIVER_VERSION_PATCH 0
#define SAFEOPS_DRIVER_BUILD_NUMBER 1

/* ABI version - increment when binary compatibility breaks */
#define SAFEOPS_ABI_VERSION 0x00020000 /* v2.0.0 */

/* String representation for logging */
#define SAFEOPS_VERSION_STRING "2.0.0"

/*
 * =============================================================================
 * RING BUFFER CONFIGURATION
 * =============================================================================
 * Purpose: Defines lock-free ring buffer dimensions used for high-speed packet
 *          capture from kernel to userspace. 2GB size accommodates burst
 * traffic while 16KB entries handle jumbo frames.
 */

/* Memory allocation */
#define RING_BUFFER_SIZE 2147483648ULL /* 2 GB */
#define RING_BUFFER_ENTRY_SIZE 16384   /* 16 KB */
#define RING_BUFFER_MAX_ENTRIES (RING_BUFFER_SIZE / RING_BUFFER_ENTRY_SIZE)
#define RING_BUFFER_ALIGNMENT 4096 /* Page size */

/* Performance indicators */
#define RING_BUFFER_WATERMARK_HIGH 90 /* 90% full - apply backpressure */
#define RING_BUFFER_WATERMARK_LOW 50  /* 50% full - resume normal operation */
#define RING_BUFFER_FLUSH_THRESHOLD 1000 /* Entries before forced flush */

/*
 * =============================================================================
 * PACKET SIZE LIMITS
 * =============================================================================
 * Purpose: Validates packet sizes to prevent buffer overflows and reject
 *          malformed packets. Supports standard MTU (1,500 bytes) and jumbo
 *          frames (9,000 bytes) for high-performance networks.
 */

/* Layer-specific limits */
#define MAX_PACKET_SIZE 16384                    /* 16 KB maximum capture */
#define MAX_ETHERNET_FRAME 9000                  /* Jumbo frame support */
#define MIN_PACKET_SIZE 64                       /* Minimum valid packet */
#define MAX_IP_PACKET_SIZE 65535                 /* Theoretical IP max */
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - 256) /* After headers */

/* Header sizes - used for packet parsing */
#define ETHERNET_HEADER_SIZE 14 /* Ethernet II header */
#define VLAN_TAG_SIZE 4         /* 802.1Q VLAN tag */
#define IPV4_MIN_HEADER_SIZE 20 /* IPv4 no options */
#define IPV4_MAX_HEADER_SIZE 60 /* IPv4 with options */
#define IPV6_HEADER_SIZE 40     /* IPv6 fixed header */
#define TCP_MIN_HEADER_SIZE 20  /* TCP no options */
#define TCP_MAX_HEADER_SIZE 60  /* TCP with options */
#define UDP_HEADER_SIZE 8       /* UDP fixed header */
#define ICMP_HEADER_SIZE 8      /* ICMP header */
#define ICMPV6_HEADER_SIZE 8    /* ICMPv6 header */

/*
 * =============================================================================
 * PROTOCOL IDENTIFIERS
 * =============================================================================
 * Purpose: Enables packet classification and protocol-specific parsing in both
 *          kernel driver and userspace service. Used for filtering and
 * statistics.
 */

/* EtherType values (network byte order) */
#define ETHERTYPE_IPV4 0x0800 /* Internet Protocol v4 */
#define ETHERTYPE_ARP 0x0806  /* Address Resolution Protocol */
#define ETHERTYPE_RARP 0x8035 /* Reverse ARP */
#define ETHERTYPE_IPV6 0x86DD /* Internet Protocol v6 */
#define ETHERTYPE_VLAN 0x8100 /* 802.1Q VLAN tagging */
#define ETHERTYPE_QINQ 0x88A8 /* 802.1ad QinQ */

/* IP Protocol numbers (as defined by IANA) */
#define IPPROTO_ICMP 1    /* Internet Control Message Protocol */
#define IPPROTO_IGMP 2    /* Internet Group Management Protocol */
#define IPPROTO_TCP 6     /* Transmission Control Protocol */
#define IPPROTO_UDP 17    /* User Datagram Protocol */
#define IPPROTO_IPV6 41   /* IPv6 encapsulation */
#define IPPROTO_GRE 47    /* Generic Routing Encapsulation */
#define IPPROTO_ESP 50    /* Encapsulating Security Payload */
#define IPPROTO_AH 51     /* Authentication Header */
#define IPPROTO_ICMPV6 58 /* Internet Control Message Protocol v6 */
#define IPPROTO_SCTP 132  /* Stream Control Transmission Protocol */

/*
 * =============================================================================
 * NETWORK INTERFACE TAGS
 * =============================================================================
 * Purpose: Kernel driver tags each interface based on connectivity type.
 *          Firewall rules, DNS filtering, and IDS policies differ based on
 *          whether traffic originates from WAN (untrusted) vs LAN (trusted).
 */

#define NIC_TAG_UNKNOWN 0x00  /* Unclassified interface */
#define NIC_TAG_WAN 0x01      /* Wide Area Network (Internet) */
#define NIC_TAG_LAN 0x02      /* Local Area Network (Internal) */
#define NIC_TAG_WIFI 0x03     /* Wireless interface */
#define NIC_TAG_VPN 0x04      /* Virtual Private Network */
#define NIC_TAG_LOOPBACK 0x05 /* Loopback interface */
#define NIC_TAG_BRIDGE 0x06   /* Bridge interface */
#define NIC_TAG_VIRTUAL 0x07  /* Virtual adapter */

/*
 * =============================================================================
 * IOCTL COMMAND RANGES
 * =============================================================================
 * Purpose: Organizes 20+ IOCTL commands into logical categories. Ranges prevent
 *          conflicts and enable future expansion within each category.
 */

/* Base codes for CTL_CODE macro */
#define IOCTL_SAFEOPS_BASE 0x8000 /* Device type code */
#define IOCTL_FUNCTION_BASE 0x800 /* Function code base */

/* Command categories (function code ranges) */
#define IOCTL_CATEGORY_GENERAL 0x00     /* 0x00 - 0x0F */
#define IOCTL_CATEGORY_STATS 0x10       /* 0x10 - 0x1F */
#define IOCTL_CATEGORY_FILTER 0x20      /* 0x20 - 0x2F */
#define IOCTL_CATEGORY_CAPTURE 0x30     /* 0x30 - 0x3F */
#define IOCTL_CATEGORY_NIC 0x40         /* 0x40 - 0x4F */
#define IOCTL_CATEGORY_RING_BUFFER 0x50 /* 0x50 - 0x5F */

/* Method codes for data transfer (Windows IOCTL methods) */
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0   /* Buffered I/O */
#define METHOD_IN_DIRECT 1  /* Direct input */
#define METHOD_OUT_DIRECT 2 /* Direct output */
#define METHOD_NEITHER 3    /* Neither (rare) */
#endif

/* Access rights */
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#define FILE_READ_ACCESS 0x0001
#define FILE_WRITE_ACCESS 0x0002
#endif

/*
 * =============================================================================
 * PERFORMANCE AND TIMING CONSTANTS
 * =============================================================================
 * Purpose: Defines timing constraints for real-time packet processing and
 *          monitoring. 100ms packet timeout prevents system hangs on malformed
 *          packets.
 */

/* Thresholds (in milliseconds) */
#define PACKET_PROCESSING_TIMEOUT_MS 100 /* Max time per packet */
#define RING_BUFFER_POLL_INTERVAL_MS 10  /* Userspace poll interval */
#define STATS_UPDATE_INTERVAL_MS 5000    /* Statistics update (5 sec) */
#define HEALTH_CHECK_INTERVAL_MS 30000   /* Health check (30 sec) */
#define WATCHDOG_TIMEOUT_MS 60000        /* Watchdog timeout (60 sec) */

/* Batch processing */
#define BATCH_PROCESS_SIZE 100             /* Packets per batch */
#define MAX_CONCURRENT_FLOWS 1000000       /* 1M concurrent connections */
#define FLOW_TIMEOUT_SEC 300               /* 5 min idle timeout */
#define CONNECTION_CLEANUP_INTERVAL_SEC 60 /* Cleanup every minute */

/*
 * =============================================================================
 * ERROR AND STATUS CODES
 * =============================================================================
 * Purpose: Custom status codes supplement NTSTATUS for SafeOps-specific error
 *          conditions. Enables precise error reporting from kernel to
 * userspace.
 */

/* Success codes */
#define SAFEOPS_SUCCESS 0x00000000 /* Operation succeeded */
#define SAFEOPS_PENDING 0x00000001 /* Operation in progress */

/* Error codes (using NTSTATUS-style 0xC prefix for errors) */
#define SAFEOPS_ERROR_INVALID_PARAMETER 0xC0000001 /* Invalid parameter */
#define SAFEOPS_ERROR_BUFFER_TOO_SMALL 0xC0000002  /* Buffer insufficient */
#define SAFEOPS_ERROR_NOT_INITIALIZED 0xC0000003   /* Driver not initialized */
#define SAFEOPS_ERROR_ALREADY_INITIALIZED 0xC0000004 /* Already initialized */
#define SAFEOPS_ERROR_OUT_OF_MEMORY 0xC0000005 /* Memory allocation failed */
#define SAFEOPS_ERROR_RING_BUFFER_FULL                                         \
  0xC0000006                                      /* Ring buffer at capacity   \
                                                   */
#define SAFEOPS_ERROR_DEVICE_NOT_READY 0xC0000007 /* Device not ready */
#define SAFEOPS_ERROR_VERSION_MISMATCH 0xC0000008 /* ABI version mismatch */
#define SAFEOPS_ERROR_TIMEOUT 0xC0000009          /* Operation timed out */
#define SAFEOPS_ERROR_ACCESS_DENIED 0xC000000A    /* Access denied */
#define SAFEOPS_ERROR_NOT_FOUND 0xC000000B        /* Resource not found */
#define SAFEOPS_ERROR_ALREADY_EXISTS 0xC000000C   /* Resource already exists */
#define SAFEOPS_ERROR_INVALID_STATE 0xC000000D    /* Invalid state */
#define SAFEOPS_ERROR_CORRUPTED_DATA 0xC000000E   /* Data corruption detected */

/*
 * =============================================================================
 * FEATURE FLAGS
 * =============================================================================
 * Purpose: Conditional compilation allows building specialized driver variants.
 *          Production builds disable debug logging; development builds enable
 *          verbose diagnostics.
 */

/* Compilation feature flags (define before including this header) */
#ifdef SAFEOPS_DEBUG
#define SAFEOPS_ENABLE_DEBUG_LOGGING 1
#define SAFEOPS_ENABLE_ASSERTIONS 1
#else
#define SAFEOPS_ENABLE_DEBUG_LOGGING 0
#define SAFEOPS_ENABLE_ASSERTIONS 0
#endif

/* Runtime capability flags (bitmask) */
#define CAP_PACKET_INSPECTION 0x0001 /* Deep packet inspection */
#define CAP_STATEFUL_FIREWALL 0x0002 /* Connection tracking */
#define CAP_NAT_SUPPORT 0x0004       /* Network address translation */
#define CAP_VLAN_SUPPORT 0x0008      /* VLAN tagging */
#define CAP_JUMBO_FRAMES 0x0010      /* Jumbo frame support */
#define CAP_IPV6_SUPPORT 0x0020      /* IPv6 support */
#define CAP_PACKET_CAPTURE 0x0040    /* Packet capture */
#define CAP_TRAFFIC_SHAPING 0x0080   /* QoS/traffic shaping */

/*
 * =============================================================================
 * MEMORY AND RESOURCE LIMITS
 * =============================================================================
 * Purpose: Prevents unbounded memory growth by capping resource usage. 10,000
 *          firewall rules and 1M connection tracking entries support enterprise
 *          deployments.
 */

/* Pool allocations */
#define MAX_FILTER_RULES 10000  /* Maximum firewall rules */
#define MAX_NAT_ENTRIES 100000  /* Maximum NAT translations */
#define MAX_CONNECTIONS 1000000 /* Maximum tracked connections */
#define PACKET_POOL_SIZE 10000  /* Pre-allocated packet buffers */
#define MAX_INTERFACES 64       /* Maximum network interfaces */

/* Cache sizes (power of 2 for hash tables) */
#define HASH_TABLE_SIZE 65536         /* 64K buckets */
#define DNS_CACHE_SIZE 10000          /* DNS resolution cache */
#define IP_REPUTATION_CACHE 100000    /* IP reputation cache */
#define CONNECTION_HASH_BUCKETS 32768 /* 32K buckets for connections */

/* Memory pool tags (for debugging memory leaks) */
#define POOL_TAG_PACKET 'tPFS'     /* SFPt - Packet buffers */
#define POOL_TAG_FILTER 'lFFS'     /* SFFl - Filter rules */
#define POOL_TAG_CONNECTION 'nCFS' /* SFCn - Connection tracking */
#define POOL_TAG_NAT 'aNFS'        /* SFNa - NAT entries */
#define POOL_TAG_GENERAL 'neFS'    /* SFGe - General allocations */

/*
 * =============================================================================
 * STRING AND BUFFER SIZES
 * =============================================================================
 * Purpose: Defines buffer sizes for string fields in structures. Prevents
 *          buffer overflows and ensures consistency across kernel/userspace.
 */

#define MAX_INTERFACE_NAME_LENGTH 256 /* Network interface name */
#define MAX_FILTER_NAME_LENGTH 128    /* Firewall rule name */
#define MAX_ERROR_MESSAGE_LENGTH 512  /* Error message buffer */
#define MAX_PATH_LENGTH 260           /* Windows MAX_PATH */
#define MAX_DOMAIN_NAME_LENGTH 255    /* DNS domain name */
#define MAX_IP_STRING_LENGTH 46       /* IPv6 string (39) + safety */

/*
 * =============================================================================
 * MAGIC NUMBERS AND SIGNATURES
 * =============================================================================
 * Purpose: Magic numbers detect memory corruption and validate structure
 *          integrity. Each structure begins with signature to catch parsing
 *          errors.
 */

/* Structure validation signatures */
#define SAFEOPS_MAGIC_NUMBER 0x53414645       /* "SAFE" in hex */
#define RING_BUFFER_SIGNATURE 0x52494E47      /* "RING" in hex */
#define PACKET_ENTRY_SIGNATURE 0x504B5420     /* "PKT " in hex */
#define FILTER_RULE_SIGNATURE 0x46495220      /* "FIR " in hex */
#define CONNECTION_ENTRY_SIGNATURE 0x434F4E4E /* "CONN" in hex */
#define NAT_ENTRY_SIGNATURE 0x4E415420        /* "NAT " in hex */

/* Version markers for structure versioning */
#define STRUCT_VERSION_V1 0x0001 /* Structure version 1 */
#define STRUCT_VERSION_V2 0x0002 /* Structure version 2 */
#define STRUCT_VERSION_CURRENT STRUCT_VERSION_V1

/*
 * =============================================================================
 * TCP FLAGS AND CONNECTION STATES
 * =============================================================================
 * Purpose: Connection tracking and stateful firewall support
 */

/* TCP flags (standard definitions) */
#define TCP_FLAG_FIN 0x01 /* Finish */
#define TCP_FLAG_SYN 0x02 /* Synchronize */
#define TCP_FLAG_RST 0x04 /* Reset */
#define TCP_FLAG_PSH 0x08 /* Push */
#define TCP_FLAG_ACK 0x10 /* Acknowledgment */
#define TCP_FLAG_URG 0x20 /* Urgent */
#define TCP_FLAG_ECE 0x40 /* ECN Echo */
#define TCP_FLAG_CWR 0x80 /* Congestion Window Reduced */

/* Connection states */
#define CONN_STATE_NEW 0x00         /* New connection */
#define CONN_STATE_ESTABLISHED 0x01 /* Established connection */
#define CONN_STATE_CLOSING 0x02     /* Connection closing */
#define CONN_STATE_CLOSED 0x03      /* Connection closed */
#define CONN_STATE_INVALID 0xFF     /* Invalid state */

/*
 * =============================================================================
 * FIREWALL ACTION CODES
 * =============================================================================
 * Purpose: Define actions for firewall rules
 */

#define ACTION_ALLOW 0x01     /* Allow packet */
#define ACTION_DENY 0x02      /* Drop packet silently */
#define ACTION_REJECT 0x03    /* Drop and send ICMP reject */
#define ACTION_LOG 0x04       /* Log packet */
#define ACTION_LOG_ALLOW 0x05 /* Log and allow */
#define ACTION_LOG_DENY 0x06  /* Log and deny */

/*
 * =============================================================================
 * COMPILE-TIME ASSERTIONS
 * =============================================================================
 * Purpose: Validate constant values at compile time to catch errors early
 */

#ifdef _KERNEL_MODE
/* Kernel mode - use C_ASSERT from WDK */
#define SAFEOPS_STATIC_ASSERT(expr, msg) C_ASSERT(expr)
#elif defined(__cplusplus)
/* C++ mode - use static_assert */
#define SAFEOPS_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#elif defined(_MSC_VER)
/* MSVC C mode - use typedef trick since _Static_assert not supported */
#define SAFEOPS_STATIC_ASSERT_JOIN(a, b) a##b
#define SAFEOPS_STATIC_ASSERT_NAME(line)                                       \
  SAFEOPS_STATIC_ASSERT_JOIN(static_assertion_, line)
#define SAFEOPS_STATIC_ASSERT(expr, msg)                                       \
  typedef char SAFEOPS_STATIC_ASSERT_NAME(__LINE__)[(expr) ? 1 : -1]
#else
/* C11 compilers - use _Static_assert */
#define SAFEOPS_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#endif

/* Validate critical constants */
SAFEOPS_STATIC_ASSERT(RING_BUFFER_SIZE == 2147483648ULL,
                      "Ring buffer must be 2GB");
SAFEOPS_STATIC_ASSERT(RING_BUFFER_ENTRY_SIZE == 16384,
                      "Entry size must be 16KB");
SAFEOPS_STATIC_ASSERT(MAX_PACKET_SIZE == 16384,
                      "Max packet must match entry size");
SAFEOPS_STATIC_ASSERT((RING_BUFFER_SIZE % RING_BUFFER_ALIGNMENT) == 0,
                      "Buffer size must be page-aligned");

/*
 * =============================================================================
 * UTILITY MACROS
 * =============================================================================
 */

/* Alignment macros */
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

/* Min/Max macros */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* Array size */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Bit manipulation */
#define BIT(n) (1UL << (n))
#define SET_BIT(flags, bit) ((flags) |= (bit))
#define CLEAR_BIT(flags, bit) ((flags) &= ~(bit))
#define TEST_BIT(flags, bit) (((flags) & (bit)) != 0)

/*
 * =============================================================================
 * END OF HEADER
 * =============================================================================
 */

#endif /* SAFEOPS_SHARED_CONSTANTS_H */

/*
 * INTEGRATION NOTES:
 *
 * 1. This header MUST be included by both kernel driver and userspace service
 * 2. Constants are compiled directly into binaries - no runtime configuration
 * 3. Changing values requires rebuilding BOTH components
 * 4. ABI version must be validated at initialization
 * 5. Magic numbers in structures prevent memory corruption
 * 6. Protocol identifiers must match proto/network.proto definitions
 *
 * DEPENDENCIES:
 * - Windows SDK 10.0.22621.0+ (userspace)
 * - Windows Driver Kit 10.0.22621.0+ (kernel)
 * - Used by: ring_buffer.h, packet_structs.h, ioctl_codes.h
 *
 * TESTING:
 * - Build-time: Static assertions validate constant relationships
 * - Runtime: Version checking prevents incompatible binaries
 * - Integration: Magic number validation catches memory corruption
 */
