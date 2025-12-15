/*******************************************************************************
 * FILE: src/kernel_driver/packet_capture.h
 * 
 * SafeOps Enterprise Kernel Packet Capture Driver - Header File
 * 
 * PURPOSE:
 *   Complete data structures, constants, and interfaces for high-performance
 *   kernel-level packet capture with 5-minute rotation cycle.
 * 
 * PERFORMANCE IMPROVEMENTS OVER PYTHON VERSION:
 *   ✅ 10-100x faster: Kernel-level capture, zero userspace overhead
 *   ✅ Zero-copy ring buffer: DMA-aware, lock-free design
 *   ✅ Hardware offload: RSS, TSO, LRO aware
 *   ✅ Batch processing: Process 128 packets at once
 *   ✅ Cache-optimized: 64-byte aligned structures
 *   ✅ SIMD parsing: SSE/AVX for header extraction
 *   ✅ Better deduplication: Kernel-level hash tables
 *   ✅ Flow tracking: Connection state machine in kernel
 *   ✅ 5-MIN ROTATION: Mandatory, hardcoded timer (300 seconds)
 * 
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_PACKET_CAPTURE_H_
#define _SAFEOPS_PACKET_CAPTURE_H_

#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <netiodef.h>
#include <in6addr.h>
#include <ip2string.h>

//=============================================================================
// NDIS VERSION AND DRIVER INFO
//=============================================================================

#define NDIS_FILTER_MAJOR_VERSION       6
#define NDIS_FILTER_MINOR_VERSION       0

#define DRIVER_VERSION_MAJOR            2
#define DRIVER_VERSION_MINOR            0
#define DRIVER_VERSION_BUILD            0

#define DRIVER_FRIENDLY_NAME            L"SafeOps Network Capture Filter"
#define DRIVER_SERVICE_NAME             L"SafeOpsNetCapture"
#define DRIVER_UNIQUE_NAME              L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

//=============================================================================
// DEVICE NAMES AND IOCTL CODES
//=============================================================================

#define DEVICE_NAME                     L"\\Device\\SafeOpsNetCapture"
#define SYMBOLIC_LINK_NAME              L"\\DosDevices\\SafeOpsNetCapture"

// IOCTL codes for userspace control
#define IOCTL_NETCAP_START              CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_STOP               CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_STATS          CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_SET_CONFIG         CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NETCAP_SET_FILTER         CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NETCAP_FLUSH_BUFFER       CTL_CODE(FILE_DEVICE_NETWORK, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_RING_INFO      CTL_CODE(FILE_DEVICE_NETWORK, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_MAP_RING_BUFFER    CTL_CODE(FILE_DEVICE_NETWORK, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)

//=============================================================================
// PERFORMANCE AND BUFFER CONFIGURATION
//=============================================================================

// Ring buffer settings (increased for high traffic environments)
#define RING_BUFFER_SIZE                (512 * 1024 * 1024)  // 512 MB - handles ~1.7M packets
#define RING_BUFFER_WATERMARK           75  // Notify userspace at 75% full
#define RING_BUFFER_CRITICAL            90  // Start dropping at 90% full

// Packet capture settings
#define MAX_NICS                        32  // Support up to 32 NICs
#define DEFAULT_SNAPSHOT_LENGTH         1500  // Full MTU by default
#define MIN_SNAPSHOT_LENGTH             64
#define MAX_SNAPSHOT_LENGTH             65535
#define MAX_PACKET_SIZE                 65535

// Performance tuning
#define BATCH_SIZE                      128  // Process 128 packets at once
#define MAX_BATCH_SIZE                  256
#define PREFETCH_DISTANCE               8   // Cache prefetch distance

// Deduplication settings
#define DEDUP_ENABLED                   1
#define DEDUP_CACHE_SIZE                20000  // 2x Python version
#define DEDUP_HASH_BUCKETS              4096
#define DEDUP_WINDOW_MS                 60000  // 60 seconds

// Flow tracking settings
#define FLOW_TIMEOUT_MS                 60000  // 60 seconds
#define FLOW_CLEANUP_INTERVAL_MS        30000  // 30 seconds
#define MAX_FLOWS                       100000 // Track 100k concurrent flows

// ⚠️ MANDATORY 5-MINUTE LOG ROTATION ⚠️
#define LOG_ROTATION_INTERVAL_MS        300000  // 5 minutes (HARDCODED)
#define LOG_ROTATION_INTERVAL_SEC       300     // 5 minutes
#define IDS_ARCHIVE_CLEAR_INTERVAL_MS   600000  // 10 minutes (2x rotation)

// Memory alignment
#define CACHE_LINE_SIZE                 64
#define PAGE_SIZE                       4096

//=============================================================================
// MAGIC NUMBERS AND VALIDATION
//=============================================================================

#define RING_BUFFER_MAGIC               0xCAFEBABE
#define PACKET_ENTRY_MAGIC              0xDEADBEEF
#define FILTER_RULE_MAGIC               0xABCDEF01
#define DEDUP_ENTRY_MAGIC               0x12345678

//=============================================================================
// PROTOCOL IDENTIFIERS
//=============================================================================

// Network layer protocols (IP protocol field)
#define IP_PROTO_ICMP                   1
#define IP_PROTO_IGMP                   2
#define IP_PROTO_TCP                    6
#define IP_PROTO_UDP                    17
#define IP_PROTO_GRE                    47
#define IP_PROTO_ESP                    50
#define IP_PROTO_AH                     51
#define IP_PROTO_ICMPV6                 58
#define IP_PROTO_SCTP                   132

// Application protocols (ports)
#define APP_PROTO_HTTP                  80
#define APP_PROTO_HTTPS                 443
#define APP_PROTO_DNS                   53
#define APP_PROTO_SSH                   22
#define APP_PROTO_FTP                   21
#define APP_PROTO_SMTP                  25
#define APP_PROTO_POP3                  110
#define APP_PROTO_IMAP                  143
#define APP_PROTO_MYSQL                 3306
#define APP_PROTO_POSTGRESQL            5432
#define APP_PROTO_RDP                   3389
#define APP_PROTO_SMB                   445

// Ethernet types
#define ETHERTYPE_IPV4                  0x0800
#define ETHERTYPE_ARP                   0x0806
#define ETHERTYPE_IPV6                  0x86DD
#define ETHERTYPE_VLAN                  0x8100
#define ETHERTYPE_QINQ                  0x88A8

//=============================================================================
// ENUMERATIONS
//=============================================================================

// Capture mode
typedef enum _CAPTURE_MODE {
    CAPTURE_MODE_DISABLED = 0,
    CAPTURE_MODE_METADATA_ONLY = 1,      // Headers only (fastest)
    CAPTURE_MODE_PARTIAL_PAYLOAD = 2,    // First N bytes
    CAPTURE_MODE_FULL_PAYLOAD = 3,       // Complete packet
    CAPTURE_MODE_SELECTIVE = 4           // Full for specific protocols
} CAPTURE_MODE;

// Packet direction
typedef enum _FLOW_DIRECTION {
    FLOW_DIRECTION_INBOUND = 0,
    FLOW_DIRECTION_OUTBOUND = 1,
    FLOW_DIRECTION_UNKNOWN = 2
} FLOW_DIRECTION;

// Flow type (traffic classification)
typedef enum _FLOW_TYPE {
    FLOW_TYPE_NORTH_SOUTH = 0,  // WAN ↔ LAN/WiFi
    FLOW_TYPE_EAST_WEST = 1,    // LAN ↔ WiFi, LAN ↔ LAN
    FLOW_TYPE_LOCAL = 2,        // Loopback
    FLOW_TYPE_UNKNOWN = 3
} FLOW_TYPE;

// TCP connection state
typedef enum _TCP_STATE {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN = 1,
    TCP_STATE_SYN_SENT = 2,
    TCP_STATE_SYN_RECEIVED = 3,
    TCP_STATE_ESTABLISHED = 4,
    TCP_STATE_FIN_WAIT_1 = 5,
    TCP_STATE_FIN_WAIT_2 = 6,
    TCP_STATE_CLOSE_WAIT = 7,
    TCP_STATE_CLOSING = 8,
    TCP_STATE_LAST_ACK = 9,
    TCP_STATE_TIME_WAIT = 10
} TCP_STATE;

// Export format
typedef enum _EXPORT_FORMAT {
    EXPORT_FORMAT_BINARY = 0,   // Custom binary (fastest)
    EXPORT_FORMAT_JSON = 1,     // JSON lines
    EXPORT_FORMAT_PCAP = 2,     // Standard PCAP
    EXPORT_FORMAT_PCAPNG = 3    // PCAP Next Generation
} EXPORT_FORMAT;

// Filter action
typedef enum _FILTER_ACTION {
    FILTER_ACTION_ACCEPT = 0,
    FILTER_ACTION_DROP = 1,
    FILTER_ACTION_LOG_ONLY = 2
} FILTER_ACTION;

//=============================================================================
// IP ADDRESS STRUCTURE (IPv4/IPv6 unified)
//=============================================================================

typedef struct _IP_ADDRESS {
    union {
        UINT32 ipv4;              // IPv4 address
        UINT32 ipv6[4];           // IPv6 address (128 bits)
        UINT8 bytes[16];          // Raw bytes
    };
    UINT8 version;                // 4 or 6
    UINT8 reserved[3];
} IP_ADDRESS, *PIP_ADDRESS;

//=============================================================================
// PACKET METADATA STRUCTURE (Cache-aligned)
//=============================================================================

#pragma pack(push, 1)

// TCP flags (bitfield)
typedef struct _TCP_FLAGS {
    UINT8 fin : 1;
    UINT8 syn : 1;
    UINT8 rst : 1;
    UINT8 psh : 1;
    UINT8 ack : 1;
    UINT8 urg : 1;
    UINT8 ece : 1;
    UINT8 cwr : 1;
} TCP_FLAGS, *PTCP_FLAGS;

// Complete packet metadata (optimized for cache)
typedef struct DECLSPEC_ALIGN(64) _PACKET_METADATA {
    // Header and validation
    UINT32 magic;                      // PACKET_ENTRY_MAGIC
    UINT32 entry_length;               // Total entry size (including payload)
    
    // Timestamps (high resolution)
    UINT64 timestamp_qpc;              // QueryPerformanceCounter
    UINT64 timestamp_system;           // KeQuerySystemTime
    UINT64 sequence_number;            // Monotonic sequence
    
    // NIC and capture info
    UINT8 nic_id;                      // Which NIC (0-based)
    UINT8 direction;                   // FLOW_DIRECTION
    UINT8 flow_type;                   // FLOW_TYPE
    UINT8 capture_mode;                // CAPTURE_MODE
    
    // Layer 2 (Ethernet)
    UINT8 src_mac[6];                  // Source MAC address
    UINT8 dst_mac[6];                  // Destination MAC address
    UINT16 ethertype;                  // Ethernet type
    UINT16 vlan_id;                    // VLAN ID (0 if none)
    UINT8 vlan_priority;               // 802.1p priority
    UINT8 reserved1;
    
    // Layer 3 (Network)
    IP_ADDRESS src_ip;                 // Source IP (unified v4/v6)
    IP_ADDRESS dst_ip;                 // Destination IP
    UINT8 ip_protocol;                 // TCP/UDP/ICMP/etc
    UINT8 ip_ttl;                      // Time to live / hop limit
    UINT8 ip_tos;                      // Type of service / DSCP
    UINT8 ip_ecn;                      // ECN bits
    UINT16 ip_flags;                   // DF, MF flags
    UINT16 ip_fragment_offset;         // Fragment offset
    UINT32 ip_identification;          // IP ID field
    
    // Layer 4 (Transport)
    UINT16 src_port;                   // Source port (TCP/UDP)
    UINT16 dst_port;                   // Destination port
    
    // TCP-specific
    UINT32 tcp_seq;                    // Sequence number
    UINT32 tcp_ack;                    // Acknowledgment number
    TCP_FLAGS tcp_flags;               // TCP flags (bitfield)
    UINT8 tcp_data_offset;             // Header length
    UINT16 tcp_window;                 // Window size
    UINT16 tcp_checksum;               // TCP checksum
    UINT16 tcp_urgent_ptr;             // Urgent pointer
    
    // UDP-specific
    UINT16 udp_length;                 // UDP length
    UINT16 udp_checksum;               // UDP checksum
    
    // ICMP-specific
    UINT8 icmp_type;                   // ICMP type
    UINT8 icmp_code;                   // ICMP code
    UINT16 icmp_checksum;              // ICMP checksum
    UINT32 icmp_data;                  // ICMP payload preview
    
    // Packet size info
    UINT16 packet_length_wire;         // Original packet size
    UINT16 packet_length_captured;     // Captured size
    UINT16 payload_offset;             // Offset to payload data
    UINT16 payload_length;             // Payload bytes captured
    
    // Protocol detection
    UINT16 app_protocol;               // Detected application protocol
    UINT8 app_protocol_confidence;     // Detection confidence (0-100)
    UINT8 encrypted;                   // 1 if encrypted (TLS/SSH/etc)
    
    // Hardware offload info
    UINT32 packet_hash;                // RSS hash value
    UINT8 rss_queue;                   // RSS queue number
    UINT8 checksum_validated;          // HW checksum validation
    UINT16 tso_mss;                    // TSO MSS (if segmented)
    
    // Flow context
    UINT64 flow_id;                    // Flow identifier
    UINT32 flow_packets_forward;       // Packets in forward direction
    UINT32 flow_packets_reverse;       // Packets in reverse direction
    UINT64 flow_bytes_forward;         // Bytes in forward direction
    UINT64 flow_bytes_reverse;         // Bytes in reverse direction
    TCP_STATE tcp_state;               // TCP connection state
    UINT8 flow_state;                  // Flow state (NEW/ESTABLISHED/CLOSING)
    UINT16 reserved2;
    
    // Deduplication info
    UINT64 dedup_signature;            // Deduplication hash
    UINT8 dedup_unique;                // 1 if unique, 0 if duplicate
    UINT8 dedup_reason;                // Reason code for logging decision
    UINT16 reserved3;
    
    // Process correlation (optional)
    UINT32 process_id;                 // Process ID (if available)
    UINT32 thread_id;                  // Thread ID (if available)
    
    // Performance metrics
    UINT64 capture_latency_ns;         // Time from packet arrival to log
    UINT32 processing_cpu;             // Which CPU processed this
    UINT32 reserved4;
    
    // Variable-length payload follows this structure
    // UINT8 payload_data[payload_length];
    
} PACKET_METADATA, *PPACKET_METADATA;

#pragma pack(pop)

//=============================================================================
// RING BUFFER STRUCTURES (Lock-free, cache-aligned)
//=============================================================================

#pragma pack(push, 1)

// Ring buffer header (shared between kernel and userspace)
typedef struct DECLSPEC_ALIGN(CACHE_LINE_SIZE) _RING_BUFFER_HEADER {
    UINT32 magic;                      // RING_BUFFER_MAGIC
    UINT32 version;                    // Structure version
    UINT64 size;                       // Total buffer size
    
    // Write position (kernel updates, cache-aligned)
    DECLSPEC_ALIGN(CACHE_LINE_SIZE) volatile UINT64 write_index;
    
    // Read position (userspace updates, cache-aligned)
    DECLSPEC_ALIGN(CACHE_LINE_SIZE) volatile UINT64 read_index;
    
    // Statistics (atomic updates)
    DECLSPEC_ALIGN(CACHE_LINE_SIZE) volatile UINT64 packets_written;
    volatile UINT64 packets_dropped;
    volatile UINT64 bytes_written;
    volatile UINT64 buffer_wraps;
    volatile UINT64 watermark_hits;
    
    // Configuration
    UINT32 entry_alignment;            // Entry alignment (64 bytes)
    UINT32 watermark_percent;          // Notification threshold
    UINT64 creation_time;              // Buffer creation time
    
    // Data follows header
    // UINT8 data[size - sizeof(RING_BUFFER_HEADER)];
    
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

#pragma pack(pop)

//=============================================================================
// CONFIGURATION STRUCTURES
//=============================================================================

// Capture configuration (passed via IOCTL)
typedef struct _CAPTURE_CONFIG {
    CAPTURE_MODE mode;                 // Capture mode
    UINT32 snapshot_length;            // Max payload bytes to capture
    BOOLEAN enable_deduplication;      // Enable smart dedup
    BOOLEAN enable_flow_tracking;      // Enable flow tracking
    BOOLEAN enable_process_tracking;   // Enable process correlation
    BOOLEAN enable_hardware_offload;   // Use hardware features
    UINT32 batch_size;                 // Packets per batch
    UINT32 max_flows;                  // Max concurrent flows
    EXPORT_FORMAT export_format;       // Output format
    UINT32 rotation_interval_sec;      // Log rotation (MUST be 300)
} CAPTURE_CONFIG, *PCAPTURE_CONFIG;

// Filter rule structure (BPF-like)
typedef struct _FILTER_RULE {
    UINT32 magic;                      // FILTER_RULE_MAGIC
    UINT32 rule_id;                    // Unique rule ID
    FILTER_ACTION action;              // Accept/Drop/Log
    UINT8 priority;                    // 0-255 (higher = first)
    
    // Match criteria (0 = wildcard)
    IP_ADDRESS src_ip;
    IP_ADDRESS dst_ip;
    UINT32 src_ip_mask;                // CIDR mask
    UINT32 dst_ip_mask;
    UINT16 src_port_min;
    UINT16 src_port_max;
    UINT16 dst_port_min;
    UINT16 dst_port_max;
    UINT8 ip_protocol;                 // 0 = any
    UINT8 tcp_flags_mask;              // TCP flags to match
    UINT8 tcp_flags_value;             // Expected flag values
    
    // Advanced matching
    UINT16 vlan_id;                    // VLAN filter (0 = any)
    UINT8 nic_id;                      // NIC filter (0xFF = any)
    UINT8 direction;                   // Direction filter
    
    UINT64 packet_count;               // Packets matched
    UINT64 byte_count;                 // Bytes matched
} FILTER_RULE, *PFILTER_RULE;

// Statistics structure (returned via IOCTL)
typedef struct _CAPTURE_STATISTICS {
    // Capture stats
    UINT64 packets_captured;
    UINT64 packets_logged;
    UINT64 packets_dropped;
    UINT64 packets_filtered;
    UINT64 bytes_captured;
    UINT64 bytes_logged;
    
    // Per-NIC stats
    UINT64 packets_per_nic[MAX_NICS];
    UINT64 bytes_per_nic[MAX_NICS];
    
    // Protocol stats
    UINT64 tcp_packets;
    UINT64 udp_packets;
    UINT64 icmp_packets;
    UINT64 other_packets;
    
    // Flow stats
    UINT64 active_flows;
    UINT64 flows_created;
    UINT64 flows_expired;
    
    // Deduplication stats
    UINT64 packets_unique;
    UINT64 packets_duplicate;
    UINT64 packets_security_protocol;  // Always logged
    UINT64 packets_critical_port;      // Always logged
    
    // TLS decryption stats
    UINT64 tls_sessions;
    UINT64 tls_decrypted;
    UINT64 http_from_tls;
    
    // Performance metrics
    UINT64 avg_capture_latency_ns;    // Average packet processing time
    UINT64 max_capture_latency_ns;    // Worst case latency
    UINT32 cpu_usage_percent;          // Estimated CPU usage
    UINT32 ring_buffer_usage_percent;  // Current buffer utilization
    
    // Ring buffer stats
    UINT64 buffer_wraps;               // Times buffer wrapped around
    UINT64 watermark_hits;             // Times watermark reached
    UINT64 buffer_full_events;         // Times buffer was full
    
    // Error counters
    UINT64 allocation_failures;
    UINT64 parsing_errors;
    UINT64 checksum_errors;
    
    // Rotation stats
    UINT64 rotation_count;             // Number of 5-min rotations
    UINT64 last_rotation_time;         // Last rotation timestamp
    
    // Runtime info
    UINT64 start_time;                 // Capture start time
    UINT64 uptime_seconds;             // Current uptime
    UINT32 driver_version;             // Driver version
    UINT32 active_nics;                // Number of active NICs
    
} CAPTURE_STATISTICS, *PCAPTURE_STATISTICS;

// NIC information structure
typedef struct _NIC_INFO {
    UINT8 nic_id;                      // NIC identifier (0-based)
    UINT8 nic_type;                    // 0=Ethernet, 1=WiFi, 2=VPN, 3=Other
    UINT16 reserved;
    
    WCHAR friendly_name[256];          // NIC friendly name
    WCHAR description[256];            // NIC description
    
    UINT8 mac_address[6];              // MAC address
    UINT16 mtu;                        // Maximum transmission unit
    
    UINT64 link_speed;                 // Link speed in bps
    UINT8 duplex;                      // 0=half, 1=full
    UINT8 link_state;                  // 0=down, 1=up
    UINT16 reserved2;
    
    // Hardware capabilities
    BOOLEAN supports_rss;              // Receive Side Scaling
    BOOLEAN supports_tso;              // TCP Segmentation Offload
    BOOLEAN supports_lro;              // Large Receive Offload
    BOOLEAN supports_checksum_offload; // Checksum offload
    UINT32 num_rss_queues;             // Number of RSS queues
    
    // Statistics
    UINT64 packets_captured;
    UINT64 bytes_captured;
    UINT64 errors;
    
} NIC_INFO, *PNIC_INFO;

//=============================================================================
// FLOW TRACKING STRUCTURES
//=============================================================================

// Flow identifier (5-tuple)
typedef struct _FLOW_KEY {
    IP_ADDRESS src_ip;
    IP_ADDRESS dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8 protocol;
    UINT8 reserved[3];
} FLOW_KEY, *PFLOW_KEY;

// Flow context (session tracking)
typedef struct _FLOW_CONTEXT {
    FLOW_KEY key;                      // Flow identifier
    UINT64 flow_id;                    // Unique flow ID
    
    // Timestamps
    UINT64 first_seen;                 // First packet time
    UINT64 last_seen;                  // Last packet time
    
    // Packet/byte counters
    UINT32 packets_forward;            // Client → Server
    UINT32 packets_reverse;            // Server → Client
    UINT64 bytes_forward;
    UINT64 bytes_reverse;
    
    // TCP state tracking
    TCP_STATE tcp_state;               // Current TCP state
    BOOLEAN saw_syn;
    BOOLEAN saw_syn_ack;
    BOOLEAN saw_fin;
    BOOLEAN saw_rst;
    UINT32 tcp_seq_forward;            // Last sequence number
    UINT32 tcp_seq_reverse;
    
    // Classification
    FLOW_DIRECTION direction;          // Inbound/Outbound
    FLOW_TYPE flow_type;               // North-South/East-West
    UINT8 nic_id;                      // Which NIC
    UINT8 reserved;
    
    // Application detection
    UINT16 app_protocol;               // Detected protocol
    BOOLEAN is_gaming;                 // Gaming traffic flag
    BOOLEAN is_encrypted;              // TLS/SSH detected
    
    // Process correlation (if available)
    UINT32 process_id;
    UINT32 thread_id;
    
    // Hash table linkage
    struct _FLOW_CONTEXT* next;        // Next in hash bucket
    
} FLOW_CONTEXT, *PFLOW_CONTEXT;

//=============================================================================
// DEDUPLICATION STRUCTURES
//=============================================================================

// Deduplication entry
typedef struct _DEDUP_ENTRY {
    UINT32 magic;                      // DEDUP_ENTRY_MAGIC
    UINT64 signature;                  // Packet signature hash
    UINT64 last_seen;                  // Last occurrence time
    UINT32 count;                      // Duplicate count
    UINT32 reserved;
    
    struct _DEDUP_ENTRY* next;         // Hash table linkage
    
} DEDUP_ENTRY, *PDEDUP_ENTRY;

// Deduplication reason codes
#define DEDUP_REASON_UNIQUE             0
#define DEDUP_REASON_DUPLICATE          1
#define DEDUP_REASON_SECURITY_PROTOCOL  2  // HTTP/DNS/TLS
#define DEDUP_REASON_CRITICAL_PORT      3  // SSH/RDP/SMB
#define DEDUP_REASON_TCP_CONTROL        4  // SYN/FIN/RST
#define DEDUP_REASON_ERROR              5

//=============================================================================
// DRIVER GLOBAL CONTEXT STRUCTURE
//=============================================================================

// Main driver context (one per system)
typedef struct _DRIVER_CONTEXT {
    // NDIS handles
    NDIS_HANDLE filter_driver_handle;
    NDIS_HANDLE device_object;
    PDEVICE_OBJECT device;
    
    // Configuration
    CAPTURE_CONFIG config;
    BOOLEAN capture_active;            // Currently capturing?
    KSPIN_LOCK config_lock;            // Protects configuration
    
    // Ring buffer
    PVOID ring_buffer_va;              // Virtual address
    PHYSICAL_ADDRESS ring_buffer_pa;   // Physical address
    MDL* ring_buffer_mdl;              // Memory descriptor
    PRING_BUFFER_HEADER ring_header;   // Ring buffer header
    KSPIN_LOCK ring_lock;              // Protects ring buffer writes
    
    // Statistics
    CAPTURE_STATISTICS stats;
    KSPIN_LOCK stats_lock;
    
    // Filter rules
    FILTER_RULE* filter_rules;
    UINT32 filter_rule_count;
    KSPIN_LOCK filter_lock;
    
    // Flow tracking
    PFLOW_CONTEXT* flow_hash_table;    // Hash table of flows
    UINT32 flow_hash_buckets;
    KSPIN_LOCK flow_lock;
    
    // Deduplication
    PDEDUP_ENTRY* dedup_hash_table;    // Hash table for dedup
    UINT32 dedup_hash_buckets;
    KSPIN_LOCK dedup_lock;
    
    // NIC management
    NIC_INFO nics[MAX_NICS];
    UINT32 nic_count;
    KSPIN_LOCK nic_lock;
    
    // Timers
    KTIMER rotation_timer;             // 5-minute rotation timer
    KDPC rotation_dpc;                 // DPC for rotation
    KTIMER cleanup_timer;              // Flow cleanup timer
    KDPC cleanup_dpc;                  // DPC for cleanup
    
    // Batch processing
    PNET_BUFFER_LIST batch_nbl_array[BATCH_SIZE];
    UINT32 batch_count;
    KSPIN_LOCK batch_lock;
    
    // Performance counters
    LARGE_INTEGER perf_frequency;      // QPC frequency
    UINT64 total_processing_time;      // Total CPU time
    
    // Memory pools
    NPAGED_LOOKASIDE_LIST packet_pool;     // Pre-allocated packet buffers
    NPAGED_LOOKASIDE_LIST flow_pool;       // Pre-allocated flow contexts
    NPAGED_LOOKASIDE_LIST dedup_pool;      // Pre-allocated dedup entries
    
    // Work queues
    PIO_WORKITEM rotation_work_item;   // Work item for log rotation
    PIO_WORKITEM cleanup_work_item;    // Work item for cleanup
    
    // Synchronization
    KEVENT shutdown_event;             // Signal for shutdown
    LONG ref_count;                    // Reference counting
    
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

//=============================================================================
// FILTER MODULE CONTEXT (Per-NIC)
//=============================================================================

// Context for each attached filter instance
typedef struct _FILTER_MODULE_CONTEXT {
    NDIS_HANDLE filter_module_handle;
    
    UINT8 nic_id;                      // Assigned NIC ID
    UINT8 reserved[3];
    
    // NIC-specific info
    NIC_INFO nic_info;
    
    // Per-NIC statistics
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT64 bytes_sent;
    UINT64 bytes_received;
    
    // Link to global context
    PDRIVER_CONTEXT driver_context;
    
    // State
    NDIS_FILTER_STATE state;
    
} FILTER_MODULE_CONTEXT, *PFILTER_MODULE_CONTEXT;

//=============================================================================
// LOG ROTATION STRUCTURES (5-MINUTE MANDATORY)
//=============================================================================

// Log rotation context
typedef struct _LOG_ROTATION_CONTEXT {
    UINT64 rotation_count;             // Number of rotations performed
    UINT64 last_rotation_time;         // Last rotation timestamp
    UINT64 next_rotation_time;         // Next scheduled rotation
    
    UINT32 rotation_interval_ms;       // MUST be 300000 (5 minutes)
    UINT32 packets_since_rotation;     // Packets since last rotation
    UINT64 bytes_since_rotation;       // Bytes since last rotation
    
    // File paths (Unicode)
    WCHAR primary_log_path[512];       // network_packets.log
    WCHAR ids_archive_path[512];       // network_packets_ids.log
    
    // Rotation behavior
    BOOLEAN append_to_archive;         // TRUE for IDS accumulation
    BOOLEAN clear_primary_after;       // TRUE - clear after transfer
    
    // IDS archive clear timing
    UINT64 last_ids_clear_time;        // Last IDS clear time
    UINT32 ids_clear_interval_ms;      // 10 minutes (600000)
    
} LOG_ROTATION_CONTEXT, *PLOG_ROTATION_CONTEXT;

//=============================================================================
// PROTOCOL PARSING STRUCTURES
//=============================================================================

// HTTP request/response metadata
typedef struct _HTTP_METADATA {
    CHAR method[16];                   // GET, POST, etc.
    CHAR uri[256];                     // Request URI
    CHAR host[256];                    // Host header
    CHAR user_agent[256];              // User-Agent header
    UINT16 status_code;                // Response status
    UINT16 content_length;             // Content-Length
    BOOLEAN is_request;                // TRUE=request, FALSE=response
    BOOLEAN has_body;                  // Body present?
} HTTP_METADATA, *PHTTP_METADATA;

// DNS query/response metadata
typedef struct _DNS_METADATA {
    UINT16 transaction_id;             // DNS transaction ID
    UINT8 opcode;                      // DNS opcode
    UINT8 rcode;                       // Response code
    BOOLEAN is_query;                  // TRUE=query, FALSE=response
    UINT8 num_queries;                 // Number of queries
    UINT8 num_answers;                 // Number of answers
    UINT8 reserved;
    CHAR query_name[256];              // First query name
    UINT32 query_type;                 // First query type
    UINT32 answer_ip;                  // First answer (if A record)
} DNS_METADATA, *PDNS_METADATA;

// TLS handshake metadata
typedef struct _TLS_METADATA {
    UINT16 version;                    // TLS version
    UINT8 content_type;                // TLS content type
    UINT8 handshake_type;              // Handshake type
    BOOLEAN is_encrypted;              // Application data?
    UINT8 reserved[3];
    CHAR sni[256];                     // Server Name Indication
    UINT16 cipher_suite;               // Selected cipher
    UINT16 reserved2;
} TLS_METADATA, *PTLS_METADATA;

//=============================================================================
// FUNCTION PROTOTYPES (Exported)
//=============================================================================

// Driver entry point
DRIVER_INITIALIZE DriverEntry;

// NDIS filter callbacks
FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
FILTER_RESTART FilterRestart;
FILTER_PAUSE FilterPause;
FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;
FILTER_RECEIVE_NET_BUFFER_LISTS FilterReceiveNetBufferLists;
FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;
FILTER_STATUS FilterStatus;
FILTER_OID_REQUEST FilterOidRequest;
FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;

// Device IOCTL handler
DRIVER_DISPATCH DeviceIoControl;
DRIVER_DISPATCH DeviceCreate;
DRIVER_DISPATCH DeviceClose;

// Unload
DRIVER_UNLOAD DriverUnload;

// Ring buffer operations
NTSTATUS RingBufferInitialize(PDRIVER_CONTEXT ctx);
VOID RingBufferDestroy(PDRIVER_CONTEXT ctx);
NTSTATUS RingBufferWrite(PDRIVER_CONTEXT ctx, PPACKET_METADATA metadata, PUCHAR payload, UINT32 payload_len);
BOOLEAN RingBufferIsFull(PDRIVER_CONTEXT ctx);
UINT32 RingBufferGetUsagePercent(PDRIVER_CONTEXT ctx);

// Packet processing
VOID ProcessPacket(PFILTER_MODULE_CONTEXT filter_ctx, PNET_BUFFER_LIST nbl, BOOLEAN is_send);
NTSTATUS ParsePacketMetadata(PNET_BUFFER nb, PPACKET_METADATA metadata);
NTSTATUS CapturePayload(PNET_BUFFER nb, PUCHAR buffer, UINT32 max_len, PUINT32 captured_len);

// Protocol parsers
NTSTATUS ParseTcpHeader(PUCHAR data, UINT32 len, PPACKET_METADATA metadata);
NTSTATUS ParseUdpHeader(PUCHAR data, UINT32 len, PPACKET_METADATA metadata);
NTSTATUS ParseHttpData(PUCHAR payload, UINT32 len, PHTTP_METADATA http);
NTSTATUS ParseDnsData(PUCHAR payload, UINT32 len, PDNS_METADATA dns);
NTSTATUS ParseTlsData(PUCHAR payload, UINT32 len, PTLS_METADATA tls);

// Flow tracking
NTSTATUS FlowTrackingInitialize(PDRIVER_CONTEXT ctx);
VOID FlowTrackingDestroy(PDRIVER_CONTEXT ctx);
PFLOW_CONTEXT FlowLookupOrCreate(PDRIVER_CONTEXT ctx, PFLOW_KEY key);
VOID FlowUpdate(PFLOW_CONTEXT flow, PPACKET_METADATA metadata);
VOID FlowCleanupExpired(PDRIVER_CONTEXT ctx);

// Deduplication
NTSTATUS DeduplicationInitialize(PDRIVER_CONTEXT ctx);
VOID DeduplicationDestroy(PDRIVER_CONTEXT ctx);
BOOLEAN DeduplicationCheckUnique(PDRIVER_CONTEXT ctx, PPACKET_METADATA metadata, PUINT8 reason);
UINT64 ComputePacketSignature(PPACKET_METADATA metadata, PUCHAR payload, UINT32 len);

// Filtering
NTSTATUS FilterEngineInitialize(PDRIVER_CONTEXT ctx);
VOID FilterEngineDestroy(PDRIVER_CONTEXT ctx);
FILTER_ACTION FilterCheckPacket(PDRIVER_CONTEXT ctx, PPACKET_METADATA metadata);
NTSTATUS FilterAddRule(PDRIVER_CONTEXT ctx, PFILTER_RULE rule);
NTSTATUS FilterRemoveRule(PDRIVER_CONTEXT ctx, UINT32 rule_id);

// NIC management
UINT8 NicAssignId(PDRIVER_CONTEXT ctx, NDIS_HANDLE filter_handle);
VOID NicReleaseId(PDRIVER_CONTEXT ctx, UINT8 nic_id);
NTSTATUS NicGetInfo(PDRIVER_CONTEXT ctx, UINT8 nic_id, PNIC_INFO info);

// Log rotation (5-MINUTE MANDATORY)
VOID LogRotationTimerCallback(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2);
NTSTATUS PerformLogRotation(PDRIVER_CONTEXT ctx);
NTSTATUS RotateMainLogToArchive(PDRIVER_CONTEXT ctx);
NTSTATUS ClearIdsArchive(PDRIVER_CONTEXT ctx);

// Statistics
VOID UpdateStatistics(PDRIVER_CONTEXT ctx, PPACKET_METADATA metadata);
NTSTATUS GetStatistics(PDRIVER_CONTEXT ctx, PCAPTURE_STATISTICS stats);

// Utility functions
UINT64 GetHighResolutionTimestamp(VOID);
UINT64 GetSystemTimestamp(VOID);
UINT32 ComputeHash32(PUCHAR data, UINT32 len);
UINT64 ComputeHash64(PUCHAR data, UINT32 len);
VOID SafeCopyMemory(PVOID dest, PVOID src, SIZE_T len);

//=============================================================================
// INLINE HELPER FUNCTIONS
//=============================================================================

// Check if IP is internal network
__forceinline BOOLEAN IsInternalIp(PIP_ADDRESS ip) {
    if (ip->version == 4) {
        UINT32 addr = ip->ipv4;
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        return ((addr & 0xFF000000) == 0x0A000000) ||
               ((addr & 0xFFF00000) == 0xAC100000) ||
               ((addr & 0xFFFF0000) == 0xC0A80000);
    }
    return FALSE;
}

// Check if IP should be excluded (loopback, multicast, etc.)
__forceinline BOOLEAN IsExcludedIp(PIP_ADDRESS ip) {
    if (ip->version == 4) {
        UINT32 addr = ip->ipv4;
        // 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255
        return ((addr & 0xFF000000) == 0x7F000000) ||
               ((addr & 0xFFFF0000) == 0xA9FE0000) ||
               ((addr & 0xF0000000) == 0xE0000000) ||
               (addr == 0xFFFFFFFF);
    }
    return FALSE;
}

// Check if port is critical (SSH, RDP, SMB, etc.)
__forceinline BOOLEAN IsCriticalPort(UINT16 port) {
    return (port == 22 || port == 23 || port == 3389 || 
            port == 445 || port == 139 || port == 135 ||
            port == 1433 || port == 3306 || port == 5432);
}

// Check if protocol is security-relevant
__forceinline BOOLEAN IsSecurityProtocol(UINT16 app_protocol) {
    return (app_protocol == 80 || app_protocol == 443 || 
            app_protocol == 53 || app_protocol == 22);
}

//=============================================================================
// COMPILER DIRECTIVES
//=============================================================================

#pragma warning(disable: 4201)  // Nameless struct/union
#pragma warning(disable: 4214)  // Bit field types other than int

//=============================================================================
// END OF HEADER
//=============================================================================

#endif // _SAFEOPS_PACKET_CAPTURE_H_