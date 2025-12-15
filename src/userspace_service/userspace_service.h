/*******************************************************************************
 * FILE: src/userspace_service/userspace_service.h
 * 
 * SafeOps Userspace Service - Common Header
 * 
 * PURPOSE:
 *   Shared definitions between userspace service components.
 *   Mirrors kernel structures for ring buffer reading.
 * 
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_USERSPACE_SERVICE_H_
#define _SAFEOPS_USERSPACE_SERVICE_H_

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

#define SERVICE_NAME            L"SafeOpsCapture"
#define DEVICE_PATH             L"\\\\.\\SafeOpsNetCapture"
#define LOG_DIRECTORY           L"C:\\SafeOpsData\\logs"
#define PRIMARY_LOG_FILE        L"network_packets.log"
#define IDS_ARCHIVE_FILE        L"network_packets_ids.log"

#define RING_BUFFER_SIZE        (512 * 1024 * 1024)  // 512 MB - matches kernel
#define LOG_ROTATION_INTERVAL   300  // 5 minutes in seconds
#define POLL_INTERVAL_MS        10   // Ring buffer poll interval

//=============================================================================
// IOCTL CODES (Must match kernel driver)
//=============================================================================

#define FILE_DEVICE_NETWORK     0x00000017

#define IOCTL_NETCAP_START      CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_STOP       CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_STATS  CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_SET_CONFIG CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NETCAP_SET_FILTER CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NETCAP_FLUSH      CTL_CODE(FILE_DEVICE_NETWORK, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_MAP_RING   CTL_CODE(FILE_DEVICE_NETWORK, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)

//=============================================================================
// MAGIC NUMBERS
//=============================================================================

#define RING_BUFFER_MAGIC       0xCAFEBABE
#define PACKET_ENTRY_MAGIC      0xDEADBEEF

//=============================================================================
// STRUCTURES (Mirror kernel structures)
//=============================================================================

#pragma pack(push, 1)

// IP Address (unified IPv4/IPv6)
typedef struct _IP_ADDRESS {
    union {
        UINT32 ipv4;
        UINT32 ipv6[4];
        UINT8 bytes[16];
    };
    UINT8 version;
    UINT8 reserved[3];
} IP_ADDRESS, *PIP_ADDRESS;

// TCP Flags
typedef struct _TCP_FLAGS {
    UINT8 fin : 1;
    UINT8 syn : 1;
    UINT8 rst : 1;
    UINT8 psh : 1;
    UINT8 ack : 1;
    UINT8 urg : 1;
    UINT8 ece : 1;
    UINT8 cwr : 1;
} TCP_FLAGS;

// Packet metadata (must match kernel PACKET_METADATA)
typedef struct _PACKET_METADATA {
    UINT32 magic;
    UINT32 entry_length;
    UINT64 timestamp_qpc;
    UINT64 timestamp_system;
    UINT64 sequence_number;
    
    UINT8 nic_id;
    UINT8 direction;
    UINT8 flow_type;
    UINT8 capture_mode;
    
    UINT8 src_mac[6];
    UINT8 dst_mac[6];
    UINT16 ethertype;
    UINT16 vlan_id;
    UINT8 vlan_priority;
    UINT8 reserved1;
    
    IP_ADDRESS src_ip;
    IP_ADDRESS dst_ip;
    UINT8 ip_protocol;
    UINT8 ip_ttl;
    UINT8 ip_tos;
    UINT8 ip_ecn;
    UINT16 ip_flags;
    UINT16 ip_fragment_offset;
    UINT32 ip_identification;
    
    UINT16 src_port;
    UINT16 dst_port;
    
    UINT32 tcp_seq;
    UINT32 tcp_ack;
    TCP_FLAGS tcp_flags;
    UINT8 tcp_data_offset;
    UINT16 tcp_window;
    UINT16 tcp_checksum;
    UINT16 tcp_urgent_ptr;
    
    UINT16 udp_length;
    UINT16 udp_checksum;
    
    UINT8 icmp_type;
    UINT8 icmp_code;
    UINT16 icmp_checksum;
    UINT32 icmp_data;
    
    UINT16 packet_length_wire;
    UINT16 packet_length_captured;
    UINT16 payload_offset;
    UINT16 payload_length;
    
    UINT16 app_protocol;
    UINT8 app_protocol_confidence;
    UINT8 encrypted;
    
    UINT32 packet_hash;
    UINT8 rss_queue;
    UINT8 checksum_validated;
    UINT16 tso_mss;
    
    UINT64 flow_id;
    UINT32 flow_packets_forward;
    UINT32 flow_packets_reverse;
    UINT64 flow_bytes_forward;
    UINT64 flow_bytes_reverse;
    UINT8 tcp_state;
    UINT8 flow_state;
    UINT16 reserved2;
    
    UINT64 dedup_signature;
    UINT8 dedup_unique;
    UINT8 dedup_reason;
    UINT16 reserved3;
    
    UINT32 process_id;
    UINT32 thread_id;
    
    UINT64 capture_latency_ns;
    UINT32 processing_cpu;
    UINT32 reserved4;
    
} PACKET_METADATA, *PPACKET_METADATA;

// Ring buffer header
typedef struct _RING_BUFFER_HEADER {
    UINT32 magic;
    UINT32 version;
    UINT64 size;
    
    volatile UINT64 write_index;
    volatile UINT64 read_index;
    
    volatile UINT64 packets_written;
    volatile UINT64 packets_dropped;
    volatile UINT64 bytes_written;
    volatile UINT64 buffer_wraps;
    volatile UINT64 watermark_hits;
    
    UINT32 entry_alignment;
    UINT32 watermark_percent;
    UINT64 creation_time;
    
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

// Capture statistics
typedef struct _CAPTURE_STATISTICS {
    UINT64 packets_captured;
    UINT64 packets_logged;
    UINT64 packets_dropped;
    UINT64 packets_filtered;
    UINT64 bytes_captured;
    UINT64 bytes_logged;
    UINT64 tcp_packets;
    UINT64 udp_packets;
    UINT64 icmp_packets;
    UINT64 other_packets;
    UINT64 active_flows;
    UINT64 flows_created;
    UINT64 packets_unique;
    UINT64 packets_duplicate;
    UINT64 rotation_count;
    UINT64 last_rotation_time;
    UINT64 start_time;
    UINT64 uptime_seconds;
    UINT32 ring_buffer_usage_percent;
    UINT32 active_nics;
} CAPTURE_STATISTICS, *PCAPTURE_STATISTICS;

#pragma pack(pop)

//=============================================================================
// SERVICE CONTEXT
//=============================================================================

typedef struct _SERVICE_CONTEXT {
    HANDLE hDevice;                     // Handle to kernel driver
    HANDLE hStopEvent;                  // Shutdown signal
    HANDLE hRotationTimer;              // 5-minute rotation timer
    
    // Ring buffer mapping
    PVOID ringBufferBase;               // Mapped ring buffer
    PRING_BUFFER_HEADER ringHeader;     // Ring buffer header
    
    // Log files
    HANDLE hPrimaryLog;                 // primary log file
    HANDLE hIdsArchive;                 // IDS archive file
    
    // Statistics
    UINT64 packetsProcessed;
    UINT64 bytesWritten;
    UINT64 rotationCount;
    
    // State
    BOOL running;
    BOOL captureActive;
    
} SERVICE_CONTEXT, *PSERVICE_CONTEXT;

//=============================================================================
// FUNCTION PROTOTYPES
//=============================================================================

// service_main.c
int ServiceMain(int argc, wchar_t* argv[]);
BOOL InitializeService(PSERVICE_CONTEXT ctx);
void ShutdownService(PSERVICE_CONTEXT ctx);
void ServiceLoop(PSERVICE_CONTEXT ctx);

// ioctl_client.c
HANDLE OpenDriverDevice(void);
void CloseDriverDevice(HANDLE hDevice);
BOOL IoctlStartCapture(HANDLE hDevice);
BOOL IoctlStopCapture(HANDLE hDevice);
BOOL IoctlGetStatistics(HANDLE hDevice, PCAPTURE_STATISTICS stats);
BOOL IoctlFlushBuffer(HANDLE hDevice);
PVOID IoctlMapRingBuffer(HANDLE hDevice);

// ring_reader.c
BOOL InitializeRingReader(PSERVICE_CONTEXT ctx);
void CleanupRingReader(PSERVICE_CONTEXT ctx);
UINT32 ReadPacketsFromRing(PSERVICE_CONTEXT ctx, PPACKET_METADATA* packets, UINT32 maxPackets);
void AdvanceReadIndex(PSERVICE_CONTEXT ctx, UINT64 bytes);

// log_writer.c
BOOL InitializeLogWriter(PSERVICE_CONTEXT ctx);
void CleanupLogWriter(PSERVICE_CONTEXT ctx);
BOOL WritePacketToLog(PSERVICE_CONTEXT ctx, PPACKET_METADATA packet, PUCHAR payload);
BOOL WritePacketJson(HANDLE hFile, PPACKET_METADATA packet, PUCHAR payload);
BOOL FlushLogs(PSERVICE_CONTEXT ctx);

// rotation_manager.c
BOOL InitializeRotationManager(PSERVICE_CONTEXT ctx);
void CleanupRotationManager(PSERVICE_CONTEXT ctx);
BOOL PerformLogRotation(PSERVICE_CONTEXT ctx);
BOOL ArchiveToIdsLog(PSERVICE_CONTEXT ctx);
BOOL ClearPrimaryLog(PSERVICE_CONTEXT ctx);
BOOL ShouldRotate(PSERVICE_CONTEXT ctx);

#endif // _SAFEOPS_USERSPACE_SERVICE_H_
