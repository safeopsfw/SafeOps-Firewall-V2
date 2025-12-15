/*******************************************************************************
 * FILE: src/kernel_driver/performance.h
 * 
 * SafeOps Performance Optimization - Header
 * 
 * PURPOSE:
 *   High-performance optimizations for 10+ Gbps throughput with <50µs latency.
 *   Includes DMA, RSS, interrupt coalescing, hardware offload, CPU affinity,
 *   packet batching, memory prefetching, cache optimization, NUMA awareness.
 * 
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_PERFORMANCE_H_
#define _SAFEOPS_PERFORMANCE_H_

#include <ntddk.h>
#include <ndis.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

#define DEFAULT_BATCH_SIZE          128
#define DEFAULT_INTERRUPT_RATE      10000       // 10K interrupts/sec
#define DEFAULT_RSS_QUEUES          16
#define DMA_BUFFER_SIZE             (2 * 1024 * 1024)  // 2 MB
#define CACHE_LINE_SIZE             64
#define MAX_CPU_CORES               64
#define RSS_KEY_SIZE                40

//=============================================================================
// STRUCTURES
//=============================================================================

#pragma pack(push, 1)

// DMA configuration
typedef struct _DMA_CONFIG {
    PVOID dma_adapter;
    PHYSICAL_ADDRESS physical_address;
    PVOID virtual_address;
    UINT32 buffer_size;
    UINT32 alignment;
    UINT32 burst_size;
    BOOLEAN bus_master_enabled;
} DMA_CONFIG, *PDMA_CONFIG;

// RSS configuration
typedef struct _RSS_CONFIG {
    BOOLEAN enabled;
    UINT32 queue_count;
    UINT32 hash_function;           // 0=Toeplitz, 1=XOR
    UINT8 hash_key[RSS_KEY_SIZE];
    UINT8 indirection_table[128];   // Maps hash → CPU
    UINT64 packets_per_queue[MAX_CPU_CORES];
} RSS_CONFIG, *PRSS_CONFIG;

// Interrupt coalescing
typedef struct _INTERRUPT_CONFIG {
    UINT32 moderation_interval_usec;
    UINT32 packet_threshold;
    BOOLEAN adaptive_moderation;
    UINT64 interrupt_count;
    UINT64 last_interrupt_time;
} INTERRUPT_CONFIG, *PINTERRUPT_CONFIG;

// Hardware offload capabilities
typedef struct _OFFLOAD_CONFIG {
    BOOLEAN checksum_rx_ipv4;
    BOOLEAN checksum_rx_ipv6;
    BOOLEAN checksum_rx_tcp;
    BOOLEAN checksum_rx_udp;
    BOOLEAN checksum_tx_ipv4;
    BOOLEAN checksum_tx_ipv6;
    BOOLEAN checksum_tx_tcp;
    BOOLEAN checksum_tx_udp;
    BOOLEAN tso_enabled;
    BOOLEAN lso_enabled;
    BOOLEAN lro_enabled;
    BOOLEAN rsc_enabled;
    BOOLEAN vlan_offload;
} OFFLOAD_CONFIG, *POFFLOAD_CONFIG;

// CPU affinity configuration
typedef struct _CPU_AFFINITY_CONFIG {
    UINT32 driver_core;             // Core for driver processing
    UINT32 packet_cores_start;      // First core for packet processing
    UINT32 packet_cores_end;        // Last core for packet processing
    KAFFINITY affinity_mask;
    BOOLEAN numa_aware;
    UINT32 numa_node;
} CPU_AFFINITY_CONFIG, *PCPU_AFFINITY_CONFIG;

// Performance statistics
typedef struct _PERFORMANCE_STATS {
    UINT64 packets_processed;
    UINT64 bytes_processed;
    UINT64 batches_processed;
    UINT64 dma_transfers;
    UINT64 interrupts;
    UINT64 cache_misses;
    UINT64 zero_copy_ops;
    UINT64 memcpy_ops;
    UINT32 avg_latency_usec;
    UINT32 max_latency_usec;
    UINT32 current_pps;             // Packets per second
    UINT64 current_bps;             // Bytes per second
} PERFORMANCE_STATS, *PPERFORMANCE_STATS;

#pragma pack(pop)

//=============================================================================
// PERFORMANCE CONTEXT
//=============================================================================

typedef struct _PERFORMANCE_CONTEXT {
    // DMA
    DMA_CONFIG dma_config;
    
    // RSS
    RSS_CONFIG rss_config;
    
    // Interrupt coalescing
    INTERRUPT_CONFIG interrupt_config;
    
    // Hardware offload
    OFFLOAD_CONFIG offload_config;
    
    // CPU affinity
    CPU_AFFINITY_CONFIG cpu_config;
    
    // Batching
    UINT32 batch_size;
    PVOID batch_buffer;
    
    // Statistics
    PERFORMANCE_STATS stats;
    
    // Synchronization
    KSPIN_LOCK perf_lock;
    
} PERFORMANCE_CONTEXT, *PPERFORMANCE_CONTEXT;

//=============================================================================
// FUNCTION PROTOTYPES
//=============================================================================

// Initialization
NTSTATUS PerformanceInitialize(_Out_ PPERFORMANCE_CONTEXT* Context);
VOID PerformanceCleanup(_In_ PPERFORMANCE_CONTEXT Context);

// DMA Management
NTSTATUS ConfigureDMA(_In_ PPERFORMANCE_CONTEXT Context, _In_ PDEVICE_OBJECT Device);
NTSTATUS AllocateDMABuffers(_In_ PPERFORMANCE_CONTEXT Context);
VOID FreeDMABuffers(_In_ PPERFORMANCE_CONTEXT Context);
NTSTATUS StartDMATransfer(_In_ PPERFORMANCE_CONTEXT Context, _In_ PVOID Data, _In_ UINT32 Length);
VOID DMACompletionCallback(_In_ PVOID Context);

// RSS Management
NTSTATUS ConfigureRSS(_In_ PPERFORMANCE_CONTEXT Context, _In_ NDIS_HANDLE AdapterHandle);
NTSTATUS SetRSSHashKey(_In_ PPERFORMANCE_CONTEXT Context);
NTSTATUS SetRSSIndirectionTable(_In_ PPERFORMANCE_CONTEXT Context);
NTSTATUS RebalanceRSSQueues(_In_ PPERFORMANCE_CONTEXT Context);
UINT32 GetRSSQueue(_In_ PPERFORMANCE_CONTEXT Context, _In_ UINT32 Hash);

// Interrupt Coalescing
NTSTATUS ConfigureInterruptCoalescing(_In_ PPERFORMANCE_CONTEXT Context, _In_ NDIS_HANDLE AdapterHandle);
VOID UpdateInterruptModeration(_In_ PPERFORMANCE_CONTEXT Context);
BOOLEAN ShouldCoalesceInterrupt(_In_ PPERFORMANCE_CONTEXT Context);

// Hardware Offload
NTSTATUS ConfigureHardwareOffload(_In_ PPERFORMANCE_CONTEXT Context, _In_ NDIS_HANDLE AdapterHandle);
NTSTATUS EnableChecksumOffload(_In_ PPERFORMANCE_CONTEXT Context, _In_ NDIS_HANDLE AdapterHandle);
NTSTATUS EnableSegmentationOffload(_In_ PPERFORMANCE_CONTEXT Context, _In_ NDIS_HANDLE AdapterHandle);

// CPU Affinity
NTSTATUS ConfigureCPUAffinity(_In_ PPERFORMANCE_CONTEXT Context);
NTSTATUS SetThreadAffinity(_In_ PKTHREAD Thread, _In_ UINT32 CoreNumber);
NTSTATUS QueryNUMATopology(_In_ PPERFORMANCE_CONTEXT Context);

// Packet Batching
NTSTATUS InitializeBatching(_In_ PPERFORMANCE_CONTEXT Context);
VOID ProcessPacketBatch(_In_ PPERFORMANCE_CONTEXT Context, _In_ PVOID Packets, _In_ UINT32 Count);

// Memory Prefetching
VOID PrefetchPacketHeader(_In_ PVOID PacketData);
VOID PrefetchRingBufferSlot(_In_ PVOID RingBuffer, _In_ UINT32 Index);

// Cache Optimization
PVOID AllocateCacheAligned(_In_ SIZE_T Size);
VOID FreeCacheAligned(_In_ PVOID Memory);

// NUMA Awareness
NTSTATUS AllocateNUMAAware(_In_ PPERFORMANCE_CONTEXT Context, _In_ SIZE_T Size, _Out_ PVOID* Memory);
VOID FreeNUMAAware(_In_ PVOID Memory);

// Zero-Copy Operations
NTSTATUS SetupZeroCopy(_In_ PPERFORMANCE_CONTEXT Context);
BOOLEAN IsZeroCopyPossible(_In_ PVOID Packet);

// Performance Monitoring
VOID UpdatePerformanceStats(_In_ PPERFORMANCE_CONTEXT Context, _In_ UINT32 PacketCount, _In_ UINT64 ByteCount);
NTSTATUS GetPerformanceStats(_In_ PPERFORMANCE_CONTEXT Context, _Out_ PPERFORMANCE_STATS Stats);
VOID ResetPerformanceStats(_In_ PPERFORMANCE_CONTEXT Context);
UINT32 MeasureLatency(_In_ UINT64 StartTime);

// Self-Check
NTSTATUS VerifyPerformance(_In_ PPERFORMANCE_CONTEXT Context);

#endif // _SAFEOPS_PERFORMANCE_H_
