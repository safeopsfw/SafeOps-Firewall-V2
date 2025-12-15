/**
 * driver.h - SafeOps Kernel Driver Main Header
 * 
 * Driver-wide definitions, structures, and global declarations.
 * 
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#ifndef _SAFEOPS_DRIVER_H_
#define _SAFEOPS_DRIVER_H_

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ndis.h>
#include <ntstrsafe.h>

//=============================================================================
// Version Information
//=============================================================================

#define SAFEOPS_VERSION_MAJOR       2
#define SAFEOPS_VERSION_MINOR       0
#define SAFEOPS_VERSION_PATCH       0
#define SAFEOPS_VERSION_BUILD       1

#define SAFEOPS_VERSION_STRING      "2.0.0.1"
#define SAFEOPS_DRIVER_NAME         L"SafeOps"
#define SAFEOPS_DEVICE_NAME         L"\\Device\\SafeOps"
#define SAFEOPS_SYMBOLIC_LINK       L"\\??\\SafeOps"

//=============================================================================
// Pool Tags
//=============================================================================

#define SAFEOPS_POOL_TAG            'SFOP'  // SafeOps general
#define PACKET_POOL_TAG             'KPKT'  // Packet buffers
#define FILTER_POOL_TAG             'KFLT'  // Filter rules
#define CONN_POOL_TAG               'KCNN'  // Connection tracking
#define SHARED_MEM_TAG              'KSHM'  // Shared memory
#define NIC_POOL_TAG                'KNIC'  // NIC management

//=============================================================================
// Constants
//=============================================================================

#define MAX_FILTER_RULES            100000
#define MAX_CONNECTIONS             1000000
#define SHARED_BUFFER_SIZE          (16 * 1024 * 1024)  // 16 MB ring buffer
#define MAX_PACKET_SIZE             65536
#define MAX_NIC_COUNT               32

// Performance tuning
#define DMA_BUFFER_SIZE             (2 * 1024 * 1024)   // 2 MB DMA buffer
#define RSS_CPU_COUNT               16                  // Max RSS CPUs
#define BATCH_SIZE                  64                  // Packet batch size

//=============================================================================
// Direction and Protocol
//=============================================================================

typedef enum _PACKET_DIRECTION {
    DIRECTION_INBOUND = 0,
    DIRECTION_OUTBOUND = 1,
    DIRECTION_BOTH = 2,
    DIRECTION_UNKNOWN = 3
} PACKET_DIRECTION;

typedef enum _PACKET_ACTION {
    ACTION_ALLOW = 0,
    ACTION_DROP = 1,
    ACTION_REJECT = 2,
    ACTION_LOG = 3,
    ACTION_INSPECT = 4
} PACKET_ACTION;

//=============================================================================
// NIC Management
//=============================================================================

typedef enum _NIC_ZONE {
    NIC_ZONE_UNKNOWN = 0,
    NIC_ZONE_WAN = 1,        // Internet-facing
    NIC_ZONE_LAN = 2,        // Internal network
    NIC_ZONE_DMZ = 3,        // DMZ/Server network
    NIC_ZONE_MANAGEMENT = 4  // Management interface
} NIC_ZONE;

typedef struct _NIC_INFO {
    ULONG Index;
    NIC_ZONE Zone;
    WCHAR FriendlyName[256];
    UCHAR MacAddress[6];
    ULONG IpAddress;
    ULONG SubnetMask;
    BOOLEAN IsActive;
    ULONGLONG PacketsReceived;
    ULONGLONG PacketsSent;
    ULONGLONG BytesReceived;
    ULONGLONG BytesSent;
} NIC_INFO, *PNIC_INFO;

//=============================================================================
// Packet Information
//=============================================================================

typedef struct _PACKET_INFO {
    // Layer 3
    ULONG SourceIP;
    ULONG DestIP;
    UCHAR Protocol;
    UCHAR TTL;
    USHORT TotalLength;
    
    // Layer 4
    USHORT SourcePort;
    USHORT DestPort;
    
    // TCP Flags
    BOOLEAN IsSyn;
    BOOLEAN IsAck;
    BOOLEAN IsFin;
    BOOLEAN IsRst;
    BOOLEAN IsPsh;
    BOOLEAN IsUrg;
    
    // Metadata
    PACKET_DIRECTION Direction;
    NIC_ZONE SourceZone;
    NIC_ZONE DestZone;
    ULONG NicIndex;
    LARGE_INTEGER Timestamp;
    
    // Performance
    ULONG ProcessorNumber;
    ULONG QueueId;
    
    // Payload (for DPI)
    PVOID PayloadBuffer;
    SIZE_T PayloadLength;
} PACKET_INFO, *PPACKET_INFO;

//=============================================================================
// Filter Rule
//=============================================================================

typedef struct _FILTER_RULE {
    ULONG RuleId;
    ULONG Priority;
    BOOLEAN Enabled;
    
    // Match criteria
    ULONG SourceIP;
    ULONG SourceMask;
    ULONG DestIP;
    ULONG DestMask;
    USHORT SourcePortStart;
    USHORT SourcePortEnd;
    USHORT DestPortStart;
    USHORT DestPortEnd;
    UCHAR Protocol;
    PACKET_DIRECTION Direction;
    NIC_ZONE SourceZone;
    NIC_ZONE DestZone;
    
    // Action
    PACKET_ACTION Action;
    
    // Logging
    BOOLEAN LogMatches;
    
    // Statistics
    ULONGLONG MatchCount;
    LARGE_INTEGER LastMatch;
    
    // List linkage
    LIST_ENTRY ListEntry;
} FILTER_RULE, *PFILTER_RULE;

//=============================================================================
// Connection Tracking
//=============================================================================

typedef enum _CONN_STATE {
    CONN_STATE_NEW = 0,
    CONN_STATE_ESTABLISHED = 1,
    CONN_STATE_RELATED = 2,
    CONN_STATE_CLOSING = 3,
    CONN_STATE_CLOSED = 4,
    CONN_STATE_INVALID = 5
} CONN_STATE;

typedef enum _TCP_STATE {
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT = 1,
    TCP_STATE_SYN_RECEIVED = 2,
    TCP_STATE_ESTABLISHED = 3,
    TCP_STATE_FIN_WAIT_1 = 4,
    TCP_STATE_FIN_WAIT_2 = 5,
    TCP_STATE_CLOSE_WAIT = 6,
    TCP_STATE_CLOSING = 7,
    TCP_STATE_LAST_ACK = 8,
    TCP_STATE_TIME_WAIT = 9,
    TCP_STATE_CLOSED = 10
} TCP_STATE;

typedef struct _CONNECTION_ENTRY {
    // 5-tuple
    ULONG SourceIP;
    ULONG DestIP;
    USHORT SourcePort;
    USHORT DestPort;
    UCHAR Protocol;
    
    // State
    CONN_STATE ConnState;
    TCP_STATE TcpState;
    
    // Timestamps
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivity;
    ULONG TimeoutSeconds;
    
    // Statistics
    ULONGLONG PacketsIn;
    ULONGLONG PacketsOut;
    ULONGLONG BytesIn;
    ULONGLONG BytesOut;
    
    // Hash table linkage
    struct _CONNECTION_ENTRY* Next;
} CONNECTION_ENTRY, *PCONNECTION_ENTRY;

//=============================================================================
// Shared Memory Ring Buffer
//=============================================================================

typedef struct _RING_BUFFER_HEADER {
    volatile ULONG WriteOffset;
    volatile ULONG ReadOffset;
    ULONG BufferSize;
    volatile ULONG DroppedPackets;
    KSPIN_LOCK Lock;
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

typedef struct _PACKET_LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    PACKET_INFO PacketInfo;
    PACKET_ACTION Action;
    ULONG RuleId;
    UCHAR PayloadSnippet[128];  // First 128 bytes
} PACKET_LOG_ENTRY, *PPACKET_LOG_ENTRY;

//=============================================================================
// Global Driver Context
//=============================================================================

typedef struct _DRIVER_CONTEXT {
    // WDF Objects
    WDFDEVICE Device;
    WDFQUEUE DefaultQueue;
    
    // WFP Handles
    HANDLE EngineHandle;
    ULONG CalloutIdIPv4Inbound;
    ULONG CalloutIdIPv4Outbound;
    ULONG FilterIdInbound;
    ULONG FilterIdOutbound;
    
    // NDIS Handles
    NDIS_HANDLE NdisFilterHandle;
    NDIS_HANDLE NdisPoolHandle;
    
    // NIC Management
    NIC_INFO NicList[MAX_NIC_COUNT];
    ULONG NicCount;
    KSPIN_LOCK NicLock;
    
    // Filter Rules
    LIST_ENTRY FilterRuleList;
    ULONG FilterRuleCount;
    KSPIN_LOCK FilterLock;
    
    // Connection Tracking
    PCONNECTION_ENTRY* ConnHashTable;
    ULONG ConnHashSize;
    volatile LONG ConnCount;
    KSPIN_LOCK ConnLocks[256];
    
    // Shared Memory
    PVOID SharedMemory;
    PMDL SharedMemoryMdl;
    PVOID UserMappedAddress;
    PRING_BUFFER_HEADER RingBufferHeader;
    
    // Performance
    BOOLEAN RssEnabled;
    ULONG RssCpuCount;
    PVOID DmaBuffer;
    PHYSICAL_ADDRESS DmaPhysicalAddress;
    
    // Statistics
    ULONGLONG PacketsProcessed;
    ULONGLONG PacketsAllowed;
    ULONGLONG PacketsDropped;
    ULONGLONG BytesProcessed;
    LARGE_INTEGER DriverStartTime;
    
    // Configuration
    BOOLEAN LoggingEnabled;
    BOOLEAN DeepInspectionEnabled;
    ULONG MaxPacketSize;
    
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, GetDriverContext)

//=============================================================================
// Function Declarations - driver.c
//=============================================================================

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SafeOpsEvtDriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD SafeOpsEvtDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY SafeOpsEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT SafeOpsEvtDeviceD0Exit;
EVT_WDF_OBJECT_CONTEXT_CLEANUP SafeOpsEvtDeviceContextCleanup;

NTSTATUS
SafeOpsInitializeDriverContext(
    _In_ WDFDEVICE Device
);

VOID
SafeOpsCleanupDriverContext(
    _In_ WDFDEVICE Device
);

//=============================================================================
// Function Declarations - packet_capture.c
//=============================================================================

NTSTATUS
PacketCaptureInitialize(
    _In_ PDRIVER_CONTEXT Context
);

VOID
PacketCaptureCleanup(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
ProcessPacket(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PPACKET_INFO PacketInfo,
    _In_opt_ const BYTE* Payload,
    _In_ SIZE_T PayloadLength,
    _Out_ PPACKET_ACTION Action
);

//=============================================================================
// Function Declarations - filter_engine.c
//=============================================================================

NTSTATUS
FilterEngineInitialize(
    _In_ PDRIVER_CONTEXT Context
);

VOID
FilterEngineCleanup(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
AddFilterRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PFILTER_RULE Rule
);

NTSTATUS
RemoveFilterRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ ULONG RuleId
);

NTSTATUS
EvaluatePacket(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PPACKET_INFO PacketInfo,
    _Out_ PPACKET_ACTION Action,
    _Out_opt_ PULONG MatchedRuleId
);

//=============================================================================
// Function Declarations - shared_memory.c
//=============================================================================

NTSTATUS
SharedMemoryInitialize(
    _In_ PDRIVER_CONTEXT Context
);

VOID
SharedMemoryCleanup(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
SharedMemoryMapToUser(
    _In_ PDRIVER_CONTEXT Context,
    _Out_ PVOID* UserAddress
);

NTSTATUS
LogPacketToRingBuffer(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PPACKET_LOG_ENTRY Entry
);

//=============================================================================
// Function Declarations - ioctl_handler.c
//=============================================================================

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SafeOpsEvtIoDeviceControl;

NTSTATUS
HandleGetStatistics(
    _In_ PDRIVER_CONTEXT Context,
    _Out_ PVOID OutputBuffer,
    _In_ SIZE_T OutputBufferLength,
    _Out_ PSIZE_T BytesReturned
);

NTSTATUS
HandleAddRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength
);

NTSTATUS
HandleRemoveRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength
);

//=============================================================================
// Function Declarations - nic_management.c
//=============================================================================

NTSTATUS
NicManagementInitialize(
    _In_ PDRIVER_CONTEXT Context
);

VOID
NicManagementCleanup(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
EnumerateNetworkInterfaces(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
SetNicZone(
    _In_ PDRIVER_CONTEXT Context,
    _In_ ULONG NicIndex,
    _In_ NIC_ZONE Zone
);

NIC_ZONE
GetNicZone(
    _In_ PDRIVER_CONTEXT Context,
    _In_ ULONG NicIndex
);

//=============================================================================
// Function Declarations - performance.c
//=============================================================================

NTSTATUS
PerformanceInitialize(
    _In_ PDRIVER_CONTEXT Context
);

VOID
PerformanceCleanup(
    _In_ PDRIVER_CONTEXT Context
);

NTSTATUS
EnableRss(
    _In_ PDRIVER_CONTEXT Context,
    _In_ ULONG CpuCount
);

NTSTATUS
AllocateDmaBuffer(
    _In_ PDRIVER_CONTEXT Context,
    _In_ SIZE_T BufferSize
);

VOID
FreeDmaBuffer(
    _In_ PDRIVER_CONTEXT Context
);

//=============================================================================
// Utility Macros
//=============================================================================

#define SAFEOPS_LOG_INFO(format, ...) \
    DbgPrint("[SafeOps] INFO: " format "\n", __VA_ARGS__)

#define SAFEOPS_LOG_WARNING(format, ...) \
    DbgPrint("[SafeOps] WARNING: " format "\n", __VA_ARGS__)

#define SAFEOPS_LOG_ERROR(format, ...) \
    DbgPrint("[SafeOps] ERROR: " format "\n", __VA_ARGS__)

#define SAFEOPS_ASSERT(condition) \
    NT_ASSERT(condition)

//=============================================================================
// IPv4 Helper Macros
//=============================================================================

#define IP_PROTOCOL_TCP    6
#define IP_PROTOCOL_UDP    17
#define IP_PROTOCOL_ICMP   1

#define MAKE_IP_ADDRESS(a, b, c, d) \
    ((ULONG)((((ULONG)(a))<<24) | (((ULONG)(b))<<16) | (((ULONG)(c))<<8) | ((ULONG)(d))))

#define IP_A(ip)  ((UCHAR)((ip) >> 24))
#define IP_B(ip)  ((UCHAR)((ip) >> 16))
#define IP_C(ip)  ((UCHAR)((ip) >> 8))
#define IP_D(ip)  ((UCHAR)(ip))

#endif // _SAFEOPS_DRIVER_H_
