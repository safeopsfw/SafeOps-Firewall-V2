/**
 * packet_capture.h - SafeOps NDIS Packet Capture Header
 *
 * Purpose: Defines data structures, constants, and function prototypes for
 * NDIS packet capture operations. Establishes the interface between the NDIS
 * filter driver framework and SafeOps packet processing logic, including
 * packet metadata extraction, NET_BUFFER_LIST manipulation, and packet
 * classification for ring buffer storage.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 *
 * CRITICAL: This header is focused exclusively on NDIS layer operations
 * (Layer 2 Ethernet frame processing). WFP callouts are handled separately.
 */

#ifndef SAFEOPS_PACKET_CAPTURE_H
#define SAFEOPS_PACKET_CAPTURE_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header for global context

#ifdef SAFEOPS_WDK_BUILD
#include <ndis.h> // NDIS 6.x APIs for NET_BUFFER_LIST
#else
// IDE Mode - NDIS type stubs for IntelliSense
typedef void *PNET_BUFFER_LIST;
typedef void *PNET_BUFFER;
typedef void *PNDIS_STATUS_INDICATION;
typedef void *PNDIS_OID_REQUEST;
typedef void *PNDIS_FILTER_ATTACH_PARAMETERS;
typedef void *PNDIS_FILTER_RESTART_PARAMETERS;
typedef void *PNDIS_FILTER_PAUSE_PARAMETERS;
typedef ULONG NDIS_STATUS;
typedef void *PKDEFERRED_ROUTINE;
typedef struct _KDPC {
  ULONG64 Reserved;
} KDPC;
typedef struct _KTIMER {
  ULONG64 Reserved;
} KTIMER;
typedef struct _NPAGED_LOOKASIDE_LIST {
  ULONG64 Reserved;
} NPAGED_LOOKASIDE_LIST;

// PWSTR typedef for IDE
typedef WCHAR *PWSTR;

// Note: Filter callback functions (FilterOidRequest, FilterDetach, etc.) are
// implemented in packet_capture.c which is wrapped with SAFEOPS_WDK_BUILD.
// No forward declarations needed in IDE mode since the implementation is
// hidden.

// Log rotation constants
#ifndef LOG_ROTATION_INTERVAL_MS
#define LOG_ROTATION_INTERVAL_MS (5 * 60 * 1000) // 5 minutes
#define LOG_ROTATION_INTERVAL_SEC 300
#endif

// Snapshot length defaults
#ifndef DEFAULT_SNAPSHOT_LENGTH
#define DEFAULT_SNAPSHOT_LENGTH 256
#define MAX_SNAPSHOT_LENGTH 65536
#endif

// RTL_CONSTANT_STRING macro for IDE
#ifndef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s)                                                 \
  ((NDIS_STRING){sizeof(s) - 2, sizeof(s), (PWSTR)(s)})
#endif

// Driver name constants
#ifndef DRIVER_FRIENDLY_NAME
#define DRIVER_FRIENDLY_NAME L"SafeOps Packet Capture"
#define DRIVER_UNIQUE_NAME L"SafeOps_Filter"
#define DRIVER_SERVICE_NAME L"SafeOpsDrv"
#define DRIVER_VERSION_MAJOR 2
#define DRIVER_VERSION_MINOR 0
#define DRIVER_VERSION_BUILD 0
#endif

// NDIS Filter states
typedef enum _NDIS_FILTER_STATE {
  NdisFilterPaused = 0,
  NdisFilterRunning = 1
} NDIS_FILTER_STATE;

// FILTER_MODULE_CONTEXT - Per-NIC filter context
typedef struct _FILTER_MODULE_CONTEXT {
  NDIS_HANDLE filter_module_handle;
  PDRIVER_CONTEXT driver_context;
  NDIS_FILTER_STATE state;
  ULONG nic_id;
  struct {
    WCHAR friendly_name[128];
    ULONG nic_id;
    ULONG link_state;
  } nic_info;
  ULONG64 packets_received;
  ULONG64 bytes_received;
} FILTER_MODULE_CONTEXT, *PFILTER_MODULE_CONTEXT;

// NDIS Filter Driver Characteristics structure
typedef struct _NDIS_FILTER_DRIVER_CHARACTERISTICS {
  struct {
    UCHAR Type;
    USHORT Size;
    UCHAR Revision;
  } Header;
  UCHAR MajorNdisVersion;
  UCHAR MinorNdisVersion;
  UCHAR MajorDriverVersion;
  UCHAR MinorDriverVersion;
  ULONG Flags;
  NDIS_STRING FriendlyName;
  NDIS_STRING UniqueName;
  NDIS_STRING ServiceName;
  PVOID AttachHandler;
  PVOID DetachHandler;
  PVOID RestartHandler;
  PVOID PauseHandler;
  PVOID SendNetBufferListsHandler;
  PVOID SendNetBufferListsCompleteHandler;
  PVOID ReceiveNetBufferListsHandler;
  PVOID ReturnNetBufferListsHandler;
  PVOID OidRequestHandler;
  PVOID OidRequestCompleteHandler;
  PVOID StatusHandler;
} NDIS_FILTER_DRIVER_CHARACTERISTICS;

typedef struct _NDIS_FILTER_ATTRIBUTES {
  struct {
    UCHAR Type;
    USHORT Size;
    UCHAR Revision;
  } Header;
  ULONG Flags;
} NDIS_FILTER_ATTRIBUTES;

// NDIS constants
#define NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS 0x50
#define NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2                   \
  sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS)
#define NDIS_FILTER_CHARACTERISTICS_REVISION_2 2
#define NDIS_FILTER_MAJOR_VERSION 6
#define NDIS_FILTER_MINOR_VERSION 50
#define NDIS_STATUS_SUCCESS 0
#define NDIS_STATUS_RESOURCES 0xC000009A
#define NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES 0x51
#define NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1 sizeof(NDIS_FILTER_ATTRIBUTES)
#define NDIS_FILTER_ATTRIBUTES_REVISION_1 1

// NDIS filter function stubs
#define NdisFRegisterFilterDriver(a, b, c, d) (0)
#define NdisFDeregisterFilterDriver(h) ((void)0)
#define NdisFSetAttributes(a, b, c) (0)
#define NdisFSendNetBufferLists(a, b, c, d) ((void)0)
#define NdisFSendNetBufferListsComplete(a, b, c) ((void)0)
#define NdisFIndicateReceiveNetBufferLists(a, b, c, d, e) ((void)0)
#define NdisFReturnNetBufferLists(a, b, c) ((void)0)
#define NdisFIndicateStatus(a, b) ((void)0)
#define NdisFOidRequest(a, b) (0)
#define NdisFOidRequestComplete(a, b, c) ((void)0)
#define NdisGetDataBuffer(nb, len, stor, align, buf, flag) ((PUCHAR)0)
#define NET_BUFFER_LIST_NEXT_NBL(nbl) ((PNET_BUFFER_LIST)0)
#define NET_BUFFER_LIST_FIRST_NB(nbl) ((PNET_BUFFER)0)
#define NET_BUFFER_DATA_LENGTH(nb) (0UL)

// Timer and DPC stubs
#define KeInitializeTimer(t) ((void)0)
#define KeInitializeDpc(d, r, c) ((void)0)
#define KeSetTimerEx(t, d, p, dpc) ((void)0)
#define KeCancelTimer(t) ((BOOLEAN)0)
#define KeInitializeEvent(e, t, s) ((void)0)
#define KeQueryPerformanceCounter(f) ((LARGE_INTEGER){0})

// Lookaside list stubs
#define ExInitializeNPagedLookasideList(l, a, f, fl, s, t, d) ((void)0)
#define ExDeleteNPagedLookasideList(l) ((void)0)

#endif

// Note: packet_structs.h is included via driver.h or shared headers

//=============================================================================
// SECTION 2: Packet Capture Constants
//=============================================================================

// Packet inspection limits
#define MAX_PACKET_INSPECTION_SIZE 256 // Only inspect first 256 bytes
#define MIN_ETHERNET_FRAME_SIZE 64     // Minimum valid Ethernet frame
#define MAX_ETHERNET_FRAME_SIZE 1518   // Standard MTU without VLAN
#define MAX_JUMBO_FRAME_SIZE 9000      // Jumbo frame support
#define VLAN_TAG_SIZE 4                // 802.1Q VLAN tag
#define ETHERNET_HDR_SIZE 14           // Dest MAC + Src MAC + EtherType
#define IPV4_HEADER_MIN_SIZE 20        // IPv4 without options
#define IPV6_HEADER_SIZE 40            // Fixed IPv6 header
#define TCP_HEADER_MIN_SIZE 20         // TCP without options
#define UDP_HEADER_SIZE_CONST 8        // Fixed UDP header

// Protocol EtherType Values (host byte order)
#ifndef ETHERTYPE_IPV4
#define ETHERTYPE_IPV4 0x0800 // IPv4 protocol
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD // IPv6 protocol
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806 // ARP protocol
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100 // 802.1Q VLAN tag
#endif

// IP Protocol Numbers (already defined in driver.h, guard against redefinition)
#ifndef IPPROTO_ICMP_CONST
#define IPPROTO_ICMP_CONST 1    // ICMP
#define IPPROTO_TCP_CONST 6     // TCP
#define IPPROTO_UDP_CONST 17    // UDP
#define IPPROTO_ICMPV6_CONST 58 // ICMPv6
#endif

// Packet directions
#define PACKET_DIRECTION_INBOUND 0
#define PACKET_DIRECTION_OUTBOUND 1

// Capture mode settings
typedef enum _CAPTURE_MODE {
  CAPTURE_MODE_DISABLED = 0,        // Capture disabled
  CAPTURE_MODE_METADATA_ONLY = 1,   // Headers only (fastest)
  CAPTURE_MODE_PARTIAL_PAYLOAD = 2, // First N bytes of payload
  CAPTURE_MODE_FULL_PAYLOAD = 3,    // Complete packet capture
  CAPTURE_MODE_FILTERED = 4         // Only matching filter rules
} CAPTURE_MODE;

// Capture configuration
#define DEFAULT_PARTIAL_PAYLOAD_SIZE 256 // Bytes to capture in partial mode
#define MAX_PAYLOAD_CAPTURE_SIZE 65535   // Maximum payload capture size
#define CAPTURE_BUFFER_POOL_SIZE 1024    // Pre-allocated capture buffers

// Flow tracking settings
#define FLOW_TIMEOUT_MS 60000          // 60 seconds flow timeout
#define FLOW_CLEANUP_INTERVAL_MS 30000 // 30 seconds cleanup interval
#define MAX_TRACKED_FLOWS 100000       // Maximum concurrent flows

// Deduplication settings
#define DEDUP_ENABLED 1        // Enable packet deduplication
#define DEDUP_CACHE_SIZE 20000 // Dedup cache entries
#define DEDUP_WINDOW_MS 60000  // 60 second dedup window

// Performance tuning
#define BATCH_SIZE 64       // Packets per batch
#define PREFETCH_DISTANCE 8 // Cache prefetch depth
#define CACHE_LINE_SIZE 64  // CPU cache line size

//=============================================================================
// SECTION 3: Packet Metadata Structure (128 bytes)
//=============================================================================

/**
 * PACKET_METADATA_ENTRY - What We Capture For Each Packet
 *
 * This 128-byte structure is written to the ring buffer for EVERY packet
 * that flows through the NDIS filter. The structure captures:
 *
 * TIMING DATA:
 *   - High-resolution timestamp (nanosecond precision)
 *
 * NETWORK INTERFACE DATA:
 *   - Which NIC captured the packet (WAN=1, LAN=2, WiFi=3)
 *   - Packet direction (Inbound=0, Outbound=1)
 *
 * LAYER 2 (ETHERNET) DATA:
 *   - Source MAC address (6 bytes)
 *   - Destination MAC address (6 bytes)
 *   - EtherType (IPv4=0x0800, IPv6=0x86DD, ARP=0x0806)
 *
 * LAYER 3 (IP) DATA:
 *   - IPv4 source/destination addresses (or zeros for IPv6)
 *   - IPv6 source/destination addresses (or zeros for IPv4)
 *   - IP protocol (TCP=6, UDP=17, ICMP=1, ICMPv6=58)
 *
 * LAYER 4 (TRANSPORT) DATA:
 *   - TCP/UDP source port
 *   - TCP/UDP destination port
 *   - TCP flags (SYN, ACK, FIN, RST, PSH, URG)
 *   - TCP sequence and acknowledgment numbers
 *
 * ADDITIONAL DATA:
 *   - Total packet length in bytes
 *   - Originating process ID (when available from WFP)
 *
 * At 128 bytes per entry, the 2GB ring buffer holds 16,777,216 packet records.
 * At 10Gbps line rate with small packets, this provides ~13 seconds of history.
 *
 * Must match the definition in ring_buffer_structs.h for binary compatibility.
 */
#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

typedef struct _PACKET_METADATA_ENTRY {
  // Timestamp (8 bytes)
  LARGE_INTEGER Timestamp; // 8 bytes - KeQueryPerformanceCounter

  // Interface and direction (8 bytes)
  ULONG NICTag;    // 4 bytes - 1=WAN, 2=LAN, 3=WiFi
  ULONG Direction; // 4 bytes - 0=Inbound, 1=Outbound

  // Ethernet info (4 bytes)
  USHORT EtherType; // 2 bytes - 0x0800=IPv4, 0x86DD=IPv6
  UCHAR Protocol;   // 1 byte  - 6=TCP, 17=UDP, 1=ICMP
  UCHAR Reserved1;  // 1 byte  - Padding

  // IPv4 addresses (8 bytes)
  ULONG SourceIPv4; // 4 bytes - Network byte order, 0 if IPv6
  ULONG DestIPv4;   // 4 bytes - Network byte order, 0 if IPv6

  // IPv6 addresses (32 bytes)
  UCHAR SourceIPv6[16]; // 16 bytes - 0s if IPv4
  UCHAR DestIPv6[16];   // 16 bytes - 0s if IPv4

  // Transport ports (4 bytes)
  USHORT SourcePort; // 2 bytes - TCP/UDP source port
  USHORT DestPort;   // 2 bytes - TCP/UDP dest port

  // Packet info (16 bytes)
  ULONG PacketLength;   // 4 bytes - Total packet size
  ULONG TCPFlags;       // 4 bytes - SYN, ACK, FIN, RST, PSH, URG
  ULONG SequenceNumber; // 4 bytes - TCP sequence number
  ULONG AckNumber;      // 4 bytes - TCP acknowledgment number

  // MAC addresses (12 bytes)
  UCHAR SourceMAC[6]; // 6 bytes - Source MAC
  UCHAR DestMAC[6];   // 6 bytes - Destination MAC

  // Process info (4 bytes)
  ULONG ProcessId; // 4 bytes - Process ID if available

  // Reserved for future use (28 bytes) - Total: 128 bytes
  UCHAR Reserved2[28]; // 28 bytes - Must be zeroed

} PACKET_METADATA_ENTRY, *PPACKET_METADATA_ENTRY;

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)

// Compile-time assertion to verify structure size
C_ASSERT(sizeof(PACKET_METADATA_ENTRY) == 128);
#endif

//=============================================================================
// SECTION 4: Packet Classification Flags
//=============================================================================

/**
 * PACKET_CLASSIFICATION_FLAGS
 *
 * Bit flags for packet categorization during inspection.
 */
typedef enum _PACKET_CLASSIFICATION_FLAGS {
  PACKET_FLAG_NONE = 0x00000000,        // No special classification
  PACKET_FLAG_FRAGMENTED = 0x00000001,  // IP packet is fragmented
  PACKET_FLAG_VLAN_TAGGED = 0x00000002, // Contains 802.1Q VLAN tag
  PACKET_FLAG_ENCRYPTED = 0x00000004,   // Likely encrypted (TLS/IPSec)
  PACKET_FLAG_BROADCAST = 0x00000008,   // Broadcast MAC address
  PACKET_FLAG_MULTICAST = 0x00000010,   // Multicast MAC address
  PACKET_FLAG_MALFORMED = 0x00000020,   // Header checksum or length invalid
  PACKET_FLAG_TRUNCATED = 0x00000040,   // Packet truncated or incomplete
  PACKET_FLAG_LOOPBACK = 0x00000080     // Loopback traffic (127.0.0.1)
} PACKET_CLASSIFICATION_FLAGS;

//=============================================================================
// SECTION 5: Packet Capture Context Structure
//=============================================================================

/**
 * PACKET_CAPTURE_CONTEXT
 *
 * Per-packet processing context used internally during NDIS callbacks.
 */
typedef struct _PACKET_CAPTURE_CONTEXT {
  // NDIS handles
  PNET_BUFFER_LIST NetBufferList; // Current NET_BUFFER_LIST
  PNET_BUFFER NetBuffer;          // Current NET_BUFFER
  PMDL CurrentMdl;                // Current MDL in chain

  // Buffer state
  ULONG CurrentMdlOffset; // Byte offset within current MDL
  ULONG BytesRemaining;   // Bytes remaining to process

  // Inspection buffer
  PVOID InspectionBuffer;     // Temp 256-byte buffer for headers
  ULONG InspectionBufferSize; // Size of data in buffer

  // Packet context
  BOOLEAN IsInbound;        // TRUE if inbound, FALSE if outbound
  ULONG NICTag;             // Interface identifier
  NDIS_HANDLE FilterHandle; // Filter instance handle

  // Classification
  ULONG ClassificationFlags; // PACKET_CLASSIFICATION_FLAGS

} PACKET_CAPTURE_CONTEXT, *PPACKET_CAPTURE_CONTEXT;

//=============================================================================
// SECTION 6: Function Prototypes - NDIS Callback Handlers
//=============================================================================

/**
 * NDIS filter callbacks registered during filter initialization.
 * All run at DISPATCH_LEVEL and must not block or allocate paged memory.
 */

// Intercepts outbound packets before reaching NIC
// _IRQL_requires_(DISPATCH_LEVEL)
VOID FilterSendNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                              _In_ PNET_BUFFER_LIST NetBufferLists,
                              _In_ NDIS_PORT_NUMBER PortNumber,
                              _In_ ULONG SendFlags);

// Called when outbound send completes
// _IRQL_requires_(DISPATCH_LEVEL)
VOID FilterSendNetBufferListsComplete(_In_ NDIS_HANDLE FilterModuleContext,
                                      _In_ PNET_BUFFER_LIST NetBufferLists,
                                      _In_ ULONG SendCompleteFlags);

// Intercepts inbound packets after NIC receives them
// _IRQL_requires_(DISPATCH_LEVEL)
VOID FilterReceiveNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                                 _In_ PNET_BUFFER_LIST NetBufferLists,
                                 _In_ NDIS_PORT_NUMBER PortNumber,
                                 _In_ ULONG NumberOfNetBufferLists,
                                 _In_ ULONG ReceiveFlags);

// Called when protocol driver returns buffers
// _IRQL_requires_(DISPATCH_LEVEL)
VOID FilterReturnNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                                _In_ PNET_BUFFER_LIST NetBufferLists,
                                _In_ ULONG ReturnFlags);

//=============================================================================
// SECTION 7: Function Prototypes - Packet Processing
//=============================================================================

/**
 * Packet parsing pipeline functions.
 * Convert NET_BUFFER_LIST data structures into PACKET_METADATA_ENTRY format.
 */

// Main entry point for processing NET_BUFFER_LIST chain
NTSTATUS ProcessPacketChain(_In_ PNET_BUFFER_LIST NetBufferList,
                            _In_ BOOLEAN IsInbound, _In_ ULONG NICTag);

// Process one NET_BUFFER and populate metadata
NTSTATUS ProcessSinglePacket(_In_ PNET_BUFFER NetBuffer, _In_ BOOLEAN IsInbound,
                             _In_ ULONG NICTag,
                             _Out_ PPACKET_METADATA_ENTRY OutMetadata);

// Safe copy from MDL chain to contiguous buffer
NTSTATUS CopyPacketDataToBuffer(_In_ PNET_BUFFER NetBuffer,
                                _Out_ PVOID OutputBuffer, _In_ ULONG BufferSize,
                                _Out_ PULONG BytesCopied);

// Parse Ethernet header, handle VLAN tags
NTSTATUS ExtractEthernetHeader(_In_ PVOID PacketData, _In_ ULONG DataSize,
                               _Out_ PUSHORT OutEtherType,
                               _Out_ PVOID *OutIPHeader);

// Extract IPv4 source/dest IPs, protocol, length
NTSTATUS ExtractIPv4Header(_In_ PVOID IPHeader, _In_ ULONG IPHeaderSize,
                           _Inout_ PPACKET_METADATA_ENTRY Metadata);

// Extract IPv6 source/dest IPs, next header
NTSTATUS ExtractIPv6Header(_In_ PVOID IPHeader, _In_ ULONG IPHeaderSize,
                           _Inout_ PPACKET_METADATA_ENTRY Metadata);

// Extract TCP ports, flags, sequence numbers
NTSTATUS ExtractTCPHeader(_In_ PVOID TCPHeader, _In_ ULONG TCPHeaderSize,
                          _Inout_ PPACKET_METADATA_ENTRY Metadata);

// Extract UDP source/dest ports
NTSTATUS ExtractUDPHeader(_In_ PVOID UDPHeader, _In_ ULONG UDPHeaderSize,
                          _Inout_ PPACKET_METADATA_ENTRY Metadata);

//=============================================================================
// SECTION 8: Function Prototypes - NET_BUFFER_LIST Utilities
//=============================================================================

/**
 * Helper functions for NDIS data structure manipulation.
 */

// Count NET_BUFFER_LISTs in chain
ULONG GetNetBufferListCount(_In_ PNET_BUFFER_LIST NetBufferList);

// Count total NET_BUFFERs across all lists
ULONG GetNetBufferCount(_In_ PNET_BUFFER_LIST NetBufferList);

// Get first NET_BUFFER from list
PNET_BUFFER GetFirstNetBuffer(_In_ PNET_BUFFER_LIST NetBufferList);

// Get next NET_BUFFER in chain
PNET_BUFFER GetNextNetBuffer(_In_ PNET_BUFFER NetBuffer);

// Get total data length in bytes
ULONG GetNetBufferDataLength(_In_ PNET_BUFFER NetBuffer);

// Get contiguous data pointer
PVOID GetNetBufferDataPointer(_In_ PNET_BUFFER NetBuffer,
                              _In_ ULONG BytesNeeded, _In_ PVOID Storage,
                              _Out_ PULONG BytesAvailable);

//=============================================================================
// SECTION 9: Function Prototypes - Packet Validation
//=============================================================================

/**
 * Integrity checks for packet validation.
 */

// Verify minimum frame size and valid EtherType
BOOLEAN ValidateEthernetFrame(_In_ PVOID PacketData, _In_ ULONG DataLength);

// Verify IPv4 header checksum
BOOLEAN ValidateIPv4Checksum(_In_ PVOID IPv4Header);

// Check version, header length, total length consistency
BOOLEAN ValidateIPv4Packet(_In_ PVOID IPv4Header, _In_ ULONG DataLength);

// Check version, payload length
BOOLEAN ValidateIPv6Packet(_In_ PVOID IPv6Header, _In_ ULONG DataLength);

// Check IP fragmentation flags
BOOLEAN IsPacketFragmented(_In_ PVOID IPv4Header);

// Check if address is in 127.0.0.0/8 range
BOOLEAN IsLoopbackAddress(_In_ ULONG IPv4Address);

//=============================================================================
// SECTION 10: Function Prototypes - Performance Optimization
//=============================================================================

/**
 * Optimized packet processing paths.
 */

// Fast path for common TCP/UDP packets
NTSTATUS FastPathProcessPacket(_In_ PNET_BUFFER NetBuffer,
                               _In_ BOOLEAN IsInbound, _In_ ULONG NICTag);

// Full processing for complex packets
NTSTATUS SlowPathProcessPacket(_In_ PNET_BUFFER NetBuffer,
                               _In_ BOOLEAN IsInbound, _In_ ULONG NICTag);

// Quick filter to skip uninteresting packets
BOOLEAN ShouldSkipPacket(_In_ PNET_BUFFER NetBuffer, _In_ ULONG NICTag);

// Batch process for cache efficiency
VOID BatchProcessNetBufferLists(_In_ PNET_BUFFER_LIST NetBufferList,
                                _In_ BOOLEAN IsInbound, _In_ ULONG NICTag);

//=============================================================================
// SECTION 11: Inline Helper Functions
//=============================================================================

/**
 * Frequently called operations inlined for performance.
 */

// Convert network byte order to host (16-bit)
__forceinline USHORT SwapBytes16(USHORT Value) {
  return (USHORT)((Value >> 8) | (Value << 8));
}

// Convert network byte order to host (32-bit)
__forceinline ULONG SwapBytes32(ULONG Value) {
  return ((Value >> 24) & 0x000000FF) | ((Value >> 8) & 0x0000FF00) |
         ((Value << 8) & 0x00FF0000) | ((Value << 24) & 0xFF000000);
}

// Check if protocol is TCP
__forceinline BOOLEAN IsTCPPacket(UCHAR Protocol) { return (Protocol == 6); }

// Check if protocol is UDP
__forceinline BOOLEAN IsUDPPacket(UCHAR Protocol) { return (Protocol == 17); }

// Check if protocol is ICMP/ICMPv6
__forceinline BOOLEAN IsICMPPacket(UCHAR Protocol) {
  return (Protocol == 1 || Protocol == 58);
}

// Check if EtherType is IPv4
__forceinline BOOLEAN IsIPv4Packet(USHORT EtherType) {
  return (EtherType == 0x0800);
}

// Check if EtherType is IPv6
__forceinline BOOLEAN IsIPv6Packet(USHORT EtherType) {
  return (EtherType == 0x86DD);
}

// Check if MAC is broadcast
__forceinline BOOLEAN IsBroadcastMAC(UCHAR *MAC) {
  return (MAC[0] == 0xFF && MAC[1] == 0xFF && MAC[2] == 0xFF &&
          MAC[3] == 0xFF && MAC[4] == 0xFF && MAC[5] == 0xFF);
}

// Check if MAC is multicast
__forceinline BOOLEAN IsMulticastMAC(UCHAR *MAC) {
  return ((MAC[0] & 0x01) != 0);
}

//=============================================================================
// SECTION 12: Debug and Diagnostics
//=============================================================================

#ifdef DBG

// Print packet details to debug console
VOID DbgPrintPacketMetadata(_In_ PPACKET_METADATA_ENTRY Metadata);

// Dump NET_BUFFER_LIST structure
VOID DbgPrintNetBufferList(_In_ PNET_BUFFER_LIST NetBufferList);

// Cross-check parsing correctness
VOID DbgValidatePacketProcessing(_In_ PNET_BUFFER NetBuffer,
                                 _In_ PPACKET_METADATA_ENTRY Metadata);

// Update per-NIC statistics
VOID IncrementPacketCounter(_In_ BOOLEAN IsInbound, _In_ ULONG NICTag);

#endif // DBG

#endif // SAFEOPS_PACKET_CAPTURE_H