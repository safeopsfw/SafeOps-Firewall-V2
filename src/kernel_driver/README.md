# Kernel Driver - Data Structures

> **Windows WFP/NDIS Kernel Driver Data Structures**

---

## 🎯 Overview

The SafeOps kernel driver operates in Windows kernel mode, intercepting network packets using Windows Filtering Platform (WFP) and Network Driver Interface Specification (NDIS). All structures must be properly aligned and use non-paged memory.

---

## 📦 Core Data Structures

### 1. Packet Metadata

```c
// File: safeops_packet.h

#define MAX_PAYLOAD_SNAPSHOT 128
#define MAX_PROCESS_PATH_LEN 260

typedef struct _PACKET_METADATA {
    // === Identifiers (64 bytes) ===
    UINT64         PacketId;           // Unique packet ID
    UINT64         Timestamp;          // KeQueryPerformanceCounter
    UINT64         FlowId;             // Connection flow identifier
    UINT32         ProcessId;
    UINT32         ThreadId;
    
    // === Network Layer - IPv4 (32 bytes) ===
    UINT32         SourceIp;           // Network byte order
    UINT32         DestIp;
    UINT8          IpVersion;          // 4 or 6
    UINT8          Protocol;           // IPPROTO_TCP, IPPROTO_UDP
    UINT8          Ttl;
    UINT8          Tos;                // Type of Service
    UINT16         IpHeaderLength;
    UINT16         TotalLength;
    UINT16         IpId;               // IP identification
    UINT16         FragmentOffset;
    
    // === Network Layer - IPv6 (40 bytes) ===
    UINT8          SourceIpv6[16];
    UINT8          DestIpv6[16];
    UINT8          TrafficClass;
    UINT8          FlowLabel[3];
    UINT16         PayloadLength;
    UINT8          NextHeader;
    UINT8          HopLimit;
    
    // === Transport Layer (32 bytes) ===
    UINT16         SourcePort;
    UINT16         DestPort;
    UINT32         TcpSeqNumber;
    UINT32         TcpAckNumber;
    UINT8          TcpFlags;           // SYN, ACK, FIN, RST, PSH, URG
    UINT8          TcpDataOffset;      // Header length in 32-bit words
    UINT16         TcpWindowSize;
    UINT16         TcpChecksum;
    UINT16         TcpUrgentPointer;
    UINT16         UdpLength;
    UINT16         UdpChecksum;
    UINT32         Reserved1;
    
    // === Interface & Direction (16 bytes) ===
    UINT64         InterfaceLuid;      // Network interface
    UINT32         InterfaceIndex;
    UINT8          Direction;          // FWP_DIRECTION_INBOUND/OUTBOUND
    UINT8          Compartment;
    UINT16         Reserved2;
    
    // === WFP Classification (32 bytes) ===
    UINT32         FilterId;           // Matching WFP filter
    UINT16         LayerId;            // WFP layer
    UINT16         CalloutId;
    UINT64         ClassifyHandle;
    UINT64         FilterContext;
    UINT64         FlowContext;
    
    // === Decision & Results (32 bytes) ===
    UINT8          Action;             // PERMIT, BLOCK, PENDING
    UINT8          Reason;             // Why this action
    UINT8          RulePriority;
    UINT8          ThreatLevel;        // 0-100
    UINT32         RuleId;             // Matching firewall rule ID
    UINT32         Flags;              // Various boolean flags
    UINT16         PayloadSnapshotLength;
    UINT16         Reserved3;
    UINT64         Reserved4;
    
    // === Deep Packet Inspection (160 bytes) ===
    UINT16         PayloadLength;      // Actual payload size
    UINT16         PayloadOffset;      // Offset to payload in packet
    UINT32         PayloadHash;        // Quick hash of payload
    UINT8          PayloadSnapshot[MAX_PAYLOAD_SNAPSHOT];
    UINT32         Reserved5[6];
    
    // === Connection Tracking (32 bytes) ===
    UINT32         PacketNumberInFlow; // Packet # in this flow
    UINT32         ConnectionState;    // TCP state machine
    UINT64         FlowByteCount;      // Total bytes in flow
    UINT64         FlowPacketCount;    // Total packets in flow
    UINT64         ConnectionStartTime;
    
    // === Performance Metrics (32 bytes) ===
    UINT32         ProcessingTimeMicroseconds;
    UINT32         QueueWaitTimeMicroseconds;
    UINT8          CpuId;              // Which CPU processed
    UINT8          Irql;               // IRQL level
    UINT16         Reserved6;
    UINT64         KernelTime;
    UINT64         Reserved7[2];
    
} PACKET_METADATA, *PPACKET_METADATA;

// Structure size: 512 bytes (aligned to cache line)
C_ASSERT(sizeof(PACKET_METADATA) == 512);
```

**Key Features:**
- **512-byte fixed size** - Optimized for cache performance
- **64-byte alignment** - Prevents false sharing across cache lines
- **Non-paged memory** - Allocated from NonPagedPool
- **Atomic counters** - Flow statistics use `InterlockedIncrement`

### Packet Flags

```c
// PACKET_METADATA.Flags bit definitions

#define PKT_FLAG_FRAGMENTED       0x00000001  // IP fragment
#define PKT_FLAG_REASSEMBLED      0x00000002  // Reassembled from fragments
#define PKT_FLAG_ENCRYPTED        0x00000004  // TLS/IPsec detected
#define PKT_FLAG_SUSPICIOUS       0x00000008  // Heuristic detection
#define PKT_FLAG_MATCHED_RULE     0x00000010  // Matched firewall rule
#define PKT_FLAG_THREAT_DETECTED  0x00000020  // Threat intel hit
#define PKT_FLAG_CONNECTION_START 0x00000040  // First packet (SYN)
#define PKT_FLAG_CONNECTION_END   0x00000080  // Last packet (FIN/RST)
#define PKT_FLAG_LOOPBACK         0x00000100  // Loopback traffic
#define PKT_FLAG_BROADCAST        0x00000200  // Broadcast packet
#define PKT_FLAG_MULTICAST        0x00000400  // Multicast packet
#define PKT_FLAG_INJECT           0x00000800  // Injected by driver
#define PKT_FLAG_CLONE            0x00001000  // Cloned NBL
#define PKT_FLAG_DROPPED          0x00002000  // Packet was dropped
#define PKT_FLAG_MODIFIED         0x00004000  // Packet was modified (NAT)
#define PKT_FLAG_IPV6             0x00008000  // IPv6 packet
```

---

### 2. Ring Buffer Structure

Lock-free circular buffer for kernel → userspace communication.

```c
// File: ring_buffer.h

#define RING_BUFFER_SIZE (16 * 1024 * 1024)  // 16 MB
#define RING_BUFFER_ENTRIES (RING_BUFFER_SIZE / sizeof(PACKET_METADATA))  // 32,768 entries

typedef struct _RING_BUFFER_HEADER {
    // === Magic & Version (8 bytes) ===
    UINT32   Magic;                // 0x53414645 ('SAFE')
    UINT16   Version;              // Buffer format version
    UINT16   EntrySize;            // sizeof(PACKET_METADATA)
    
    // === Capacity (16 bytes) ===
    UINT64   TotalEntries;         // RING_BUFFER_ENTRIES
    UINT64   BufferSizeBytes;      // Total buffer size
    
    // === Producer Index (64 bytes - own cache line) ===
    __declspec(align(64))
    volatile LONG64 WriteIndex;    // Next write position (atomic)
    UINT64   Reserved1[7];
    
    // === Consumer Index (64 bytes - own cache line) ===
    __declspec(align(64))
    volatile LONG64 ReadIndex;     // Next read position (atomic)
    UINT64   Reserved2[7];
    
    // === Statistics - Producer (64 bytes) ===
    __declspec(align(64))
    volatile LONG64 PacketsWritten;   // Total packets written
    volatile LONG64 Drops;             // Packets dropped (buffer full)
    volatile LONG64 Wraps;             // Write index wrap-arounds
    UINT64   Reserved3[5];
    
    // === Statistics - Consumer (64 bytes) ===
    __declspec(align(64))
    volatile LONG64 PacketsRead;      // Total packets read
    volatile LONG64 ReadWraps;        // Read index wrap-arounds
    UINT64   Reserved4[6];
    
    // === Padding to 512 bytes ===
    UINT8    Padding[256];
    
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

C_ASSERT(sizeof(RING_BUFFER_HEADER) == 512);

typedef struct _RING_BUFFER {
    RING_BUFFER_HEADER Header;
    PACKET_METADATA    Entries[RING_BUFFER_ENTRIES];
    
} RING_BUFFER, *PRING_BUFFER;

// Total size: 512 bytes (header) + 16 MB (entries) ≈ 16 MB
```

**Algorithm:**

```c
// Producer (Kernel) - Lock-free write
BOOLEAN RingBuffer_Write(PRING_BUFFER Buffer, PPACKET_METADATA Packet)
{
    LONG64 currentWrite, currentRead, nextWrite;
    
    // Load indices (atomic)
    currentWrite = InterlockedCompareExchange64(&Buffer->Header.WriteIndex, 0, 0);
    currentRead = InterlockedCompareExchange64(&Buffer->Header.ReadIndex, 0, 0);
    
    // Calculate next position
    nextWrite = (currentWrite + 1) % RING_BUFFER_ENTRIES;
    
    // Check if buffer is full
    if (nextWrite == currentRead) {
        InterlockedIncrement64(&Buffer->Header.Drops);
        return FALSE;
    }
    
    // Copy packet to buffer
    RtlCopyMemory(&Buffer->Entries[currentWrite], Packet, sizeof(PACKET_METADATA));
    
    // Memory barrier - ensure write completes before index update
    KeMemoryBarrier();
    
    // Update write index (atomic)
    InterlockedIncrement64(&Buffer->Header.WriteIndex);
    if (currentWrite + 1 >= RING_BUFFER_ENTRIES) {
        InterlockedExchange64(&Buffer->Header.WriteIndex, 0);
        InterlockedIncrement64(&Buffer->Header.Wraps);
    }
    
    InterlockedIncrement64(&Buffer->Header.PacketsWritten);
    return TRUE;
}

// Consumer (Userspace) - Lock-free read
BOOLEAN RingBuffer_Read(PRING_BUFFER Buffer, PPACKET_METADATA Packet)
{
    LONG64 currentRead, currentWrite;
    
    currentRead = InterlockedCompareExchange64(&Buffer->Header.ReadIndex, 0, 0);
    currentWrite = InterlockedCompareExchange64(&Buffer->Header.WriteIndex, 0, 0);
    
    // Check if buffer is empty
    if (currentRead == currentWrite) {
        return FALSE;
    }
    
    // Copy packet from buffer
    RtlCopyMemory(Packet, &Buffer->Entries[currentRead], sizeof(PACKET_METADATA));
    
    // Update read index (atomic)
    InterlockedIncrement64(&Buffer->Header.ReadIndex);
    if (currentRead + 1 >= RING_BUFFER_ENTRIES) {
        InterlockedExchange64(&Buffer->Header.ReadIndex, 0);
        InterlockedIncrement64(&Buffer->Header.ReadWraps);
    }
    
    InterlockedIncrement64(&Buffer->Header.PacketsRead);
    return TRUE;
}
```

**Shared Memory Section:**
```c
#define RING_BUFFER_SECTION_NAME L"\\BaseNamedObjects\\SafeOpsRingBuffer"
```

---

### 3. Connection Tracking

```c
// File: connection_tracker.h

#define MAX_PROCESS_NAME 64
#define CONNECTION_HASH_TABLE_SIZE 65536  // 64K buckets

typedef struct _CONNECTION_ENTRY {
    // === 5-Tuple Key (16 bytes) ===
    UINT32         LocalIp;
    UINT32         RemoteIp;
    UINT16         LocalPort;
    UINT16         RemotePort;
    UINT8          Protocol;
    UINT8          IpVersion;
    UINT16         Reserved1;
    
    // === Connection Identity (32 bytes) ===
    UINT64         FlowId;             // Unique flow ID
    UINT8          State;              // TCP state machine
    UINT8          Direction;          // Inbound/Outbound
    UINT16         Reserved2;
    UINT32         ProcessId;
    WCHAR          ProcessName[MAX_PROCESS_NAME];
    
    // === Timestamps (32 bytes) ===
    UINT64         CreationTime;       // KeQueryInterruptTime
    UINT64         LastSeenTime;
    UINT64         ExpirationTime;     // Timeout deadline
    UINT64         LastActivityTime;
    
    // === Traffic Counters (32 bytes) ===
    UINT64         BytesSent;
    UINT64         BytesReceived;
    UINT32         PacketsSent;
    UINT32         PacketsReceived;
    
    // === Security Classification (32 bytes) ===
    UINT8          ThreatLevel;        // 0-100
    UINT8          Confidence;         // 0-100
    UINT16         RuleId;             // Applied rule
    UINT32         Flags;
    INT32          ReputationScore;    // -100 to +100
    UINT64         ThreatIndicatorId;  // Reference to threat DB
    UINT64         Reserved3;
    
    // === Hash Table Linkage (16 bytes) ===
    struct _CONNECTION_ENTRY* Next;    // Collision chain
    struct _CONNECTION_ENTRY* Prev;
    
} CONNECTION_ENTRY, *PCONNECTION_ENTRY;

C_ASSERT(sizeof(CONNECTION_ENTRY) == 192);  // 3 cache lines

// Connection hash table
typedef struct _CONNECTION_TABLE {
    PCONNECTION_ENTRY    Buckets[CONNECTION_HASH_TABLE_SIZE];
    EX_SPIN_LOCK         Locks[256];  // Fine-grained locking (256 locks)
    UINT64               EntryCount;
    UINT64               MaxEntries;  // Capacity limit
    
} CONNECTION_TABLE, *PCONNECTION_TABLE;
```

**TCP State Machine:**

```c
typedef enum _TCP_STATE {
    TCP_STATE_CLOSED       = 0,
    TCP_STATE_LISTEN       = 1,
    TCP_STATE_SYN_SENT     = 2,
    TCP_STATE_SYN_RECV     = 3,
    TCP_STATE_ESTABLISHED  = 4,
    TCP_STATE_FIN_WAIT_1   = 5,
    TCP_STATE_FIN_WAIT_2   = 6,
    TCP_STATE_CLOSE_WAIT   = 7,
    TCP_STATE_CLOSING      = 8,
    TCP_STATE_LAST_ACK     = 9,
    TCP_STATE_TIME_WAIT    = 10,
} TCP_STATE;

typedef enum _UDP_STATE {
    UDP_STATE_ACTIVE       = 100,
    UDP_STATE_EXPIRED      = 101,
} UDP_STATE;
```

**Hash Function:**

```c
UINT32 ConnectionHash(UINT32 LocalIp, UINT32 RemoteIp, 
                      UINT16 LocalPort, UINT16 RemotePort, UINT8 Protocol)
{
    UINT32 hash = 2166136261U;  // FNV-1a offset basis
    
    hash ^= LocalIp;
    hash *= 16777619;
    hash ^= RemoteIp;
    hash *= 16777619;
    hash ^= (LocalPort << 16) | RemotePort;
    hash *= 16777619;
    hash ^= Protocol;
    hash *= 16777619;
    
    return hash % CONNECTION_HASH_TABLE_SIZE;
}
```

---

### 4. Firewall Rule

```c
// File: firewall_rules.h

#define MAX_RULE_NAME_LEN 128
#define MAX_RULE_DESC_LEN 256
#define MAX_PROCESS_PATH 260

typedef struct _FIREWALL_RULE {
    // === Identity (400 bytes) ===
    UINT32         RuleId;
    WCHAR          RuleName[MAX_RULE_NAME_LEN];
    WCHAR          Description[MAX_RULE_DESC_LEN];
    UINT32         Hash;               // Rule hash for quick compare
    
    // === Status (16 bytes) ===
    BOOLEAN        Enabled;
    UINT8          Priority;           // 0=highest, 255=lowest
    UINT16         Reserved1;
    volatile LONG  HitCount;           // Atomic counter
    BOOLEAN        LogMatches;
    UINT8          Reserved2[7];
    
    // === Match Criteria - Source (24 bytes) ===
    UINT32         SourceIp;           // 0.0.0.0 = any
    UINT32         SourceMask;
    UINT16         SourcePortStart;
    UINT16         SourcePortEnd;
    UINT8          SourceFlags;
    UINT8          Reserved3[7];
    
    // === Match Criteria - Destination (24 bytes) ===
    UINT32         DestIp;
    UINT32         DestMask;
    UINT16         DestPortStart;
    UINT16         DestPortEnd;
    UINT8          DestFlags;
    UINT8          Reserved4[7];
    
    // === Protocol & Direction (8 bytes) ===
    UINT8          Protocol;           // 0=any, 6=TCP, 17=UDP
    UINT8          Direction;          // 0=any, 1=in, 2=out
    UINT16         Reserved5;
    UINT32         ProtocolFlags;
    
    // === Process Filtering (528 bytes) ===
    UINT32         ProcessId;          // 0=any
    WCHAR          ProcessPath[MAX_PROCESS_PATH];
    UINT8          Reserved6[4];
    
    // === Action (16 bytes) ===
    UINT8          Action;             // BLOCK, ALLOW, INSPECT
    UINT8          LogLevel;           // 0-7
    UINT16         Reserved7;
    UINT32         ActionFlags;
    UINT64         NextRuleId;         // Chain to next rule
    
    // === Time-based Rules (16 bytes) ===
    UINT64         ValidFrom;          // UTC file time
    UINT64         ValidUntil;
    
    // === Rate Limiting (16 bytes) ===
    UINT32         RateLimitPPS;       // Packets/sec (0=unlimited)
    UINT32         RateLimitBPS;       // Bytes/sec
    UINT64         LastRateLimitReset;
    
    // === Advanced Options (16 bytes) ===
    BOOLEAN        RequireEstablished;
    BOOLEAN        RequireEncryption;
    BOOLEAN        CheckThreatIntel;
    INT8           MinThreatScore;     // -100 to +100
    UINT32         Options;
    UINT64         Reserved8;
    
    // === Statistics (32 bytes) ===
    UINT64         BytesMatched;
    UINT64         PacketsMatched;
    UINT64         LastMatchTime;
    UINT64         CreationTime;
    
    // === List Linkage (16 bytes) ===
    LIST_ENTRY     ListEntry;
    
} FIREWALL_RULE, *PFIREWALL_RULE;

C_ASSERT(sizeof(FIREWALL_RULE) == 1024);  // Aligned to 1KB
```

---

### 5. Performance Statistics

```c
// File: performance.h

typedef struct _PERFORMANCE_STATS {
    // === Packet Processing (64 bytes) ===
    __declspec(align(64))
    volatile LONG64 TotalPacketsProcessed;
    volatile LONG64 PacketsAllowed;
    volatile LONG64 PacketsBlocked;
    volatile LONG64 PacketsInspected;
    volatile LONG64 PacketsDropped;
    volatile LONG64 PacketsModified;
    UINT64          Reserved1[2];
    
    // === Throughput Metrics (64 bytes) ===
    __declspec(align(64))
    volatile LONG   CurrentPPS;        // Packets per second
    volatile LONG64 CurrentBPS;        // Bytes per second
    UINT32          PeakPPS;
    UINT32          Reserved2;
    UINT64          PeakBPS;
    UINT64          TotalBytesProcessed;
    UINT64          Reserved3[3];
    
    // === Latency Distribution (64 bytes) ===
    __declspec(align(64))
    UINT32          AvgLatencyMicroseconds;
    UINT32          MinLatencyMicroseconds;
    UINT32          MaxLatencyMicroseconds;
    UINT32          P50LatencyMicroseconds;
    UINT32          P95LatencyMicroseconds;
    UINT32          P99LatencyMicroseconds;
    UINT32          P999LatencyMicroseconds;
    UINT32          Reserved4;
    UINT64          Reserved5[4];
    
    // === Connection Tracking (64 bytes) ===
    __declspec(align(64))
    volatile LONG   ActiveConnections;
    UINT32          PeakConnections;
    volatile LONG64 TotalConnectionsCreated;
    volatile LONG64 TotalConnectionsClosed;
    volatile LONG64 ConnectionTimeouts;
    UINT64          Reserved6[3];
    
    // === Resource Usage (64 bytes) ===
    __declspec(align(64))
    UINT32          PoolAllocations;
    UINT32          PoolBytes;
    UINT32          RingBufferUsagePercent;
    UINT32          Reserved7;
    volatile LONG64 RingBufferDrops;
    UINT64          Reserved8[4];
    
    // === Error Counters (64 bytes) ===
    __declspec(align(64))
    volatile LONG64 AllocationFailures;
    volatile LONG64 LockContentions;
    volatile LONG64 BufferOverruns;
    volatile LONG64 InvalidPackets;
    volatile LONG64 ChecksumErrors;
    UINT64          Reserved9[3];
    
    // === CPU Utilization (64 bytes) ===
    __declspec(align(64))
    UINT32          CpuUsagePercent;
    UINT32          IdlePercent;
    UINT64          KernelTime;
    UINT64          UserTime;
    UINT64          Reserved10[4];
    
    // === Timestamp (64 bytes) ===
    __declspec(align(64))
    UINT64          LastUpdateTime;
    UINT64          StartTime;
    UINT64          UptimeSeconds;
    UINT64          Reserved11[5];
    
} PERFORMANCE_STATS, *PPERFORMANCE_STATS;

C_ASSERT(sizeof(PERFORMANCE_STATS) == 512);
```

---

## 🔧 Memory Management

### Pool Allocations

```c
// Non-paged pool (always resident in physical memory)
PVOID AllocatePacketMetadata()
{
    return ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PACKET_METADATA),
        'tPFS'  // Tag: 'SFPt' reversed
    );
}

// Object pool for connection entries
#define CONNECTION_POOL_SIZE 100000

LOOKASIDE_LIST_EX ConnectionLookaside;

NTSTATUS InitializeConnectionPool()
{
    return ExInitializeLookasideListEx(
        &ConnectionLookaside,
        NULL,  // Allocate callback
        NULL,  // Free callback
        NonPagedPool,
        0,     // Flags
        sizeof(CONNECTION_ENTRY),
        'nCFS',  // Tag
        0      // Depth
    );
}
```

### Memory Barriers

```c
// Ensure proper ordering on multi-core systems
KeMemoryBarrier();          // Full memory barrier
_ReadWriteBarrier();        // Compiler barrier
```

---

## 📈 Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Packet processing latency | <10 μs | P99 |
| Throughput | 1M pps | On 10 Gbps NIC |
| Memory overhead per connection | 192 bytes | CONNECTION_ENTRY size |
| Max concurrent connections | 1M | Hash table capacity |
| Ring buffer drops | <0.01% | 99.99% capture rate |
| CPU usage | <25% | At 500K pps |

---

**Version:** 2.0.0  
**Last Updated:** 2025-12-17
