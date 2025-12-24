/**
 * performance.h - SafeOps Performance Optimization Interface
 *
 * Purpose: Defines the interface for performance optimization features
 * including CPU affinity management, NUMA awareness, DMA operations, RSS
 * configuration, and hardware offload capabilities. Establishes the framework
 * for achieving line-rate packet processing at 10Gbps.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#ifndef SAFEOPS_PERFORMANCE_H
#define SAFEOPS_PERFORMANCE_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header

#ifdef SAFEOPS_WDK_BUILD
#include <ndis.h>  // RSS, VMQ, offload APIs
#include <ntddk.h> // Processor/memory APIs
#include <wdm.h>   // DPC, NUMA APIs

#else
// IDE Mode - Additional type stubs (only if not already defined)
#ifndef PMDL_DEFINED
#define PMDL_DEFINED
typedef void *PMDL;
#endif
#ifndef PKDPC_DEFINED
#define PKDPC_DEFINED
typedef void *PKDPC;
#endif
#ifndef KAFFINITY_DEFINED
#define KAFFINITY_DEFINED
typedef ULONG64 KAFFINITY;
#endif
#endif

//=============================================================================
// SECTION 2: CPU Affinity Constants
//=============================================================================

#define MAX_PROCESSOR_COUNT 64 // Max CPUs on x64 systems
#define MAX_PROCESSOR_GROUPS 4 // Windows processor group limit
#define MAX_NUMA_NODES 8       // Max NUMA nodes

// Preferred CPU assignments for NICs
#define PREFERRED_CPU_FOR_WAN 0  // CPU 0 for WAN processing
#define PREFERRED_CPU_FOR_LAN 1  // CPU 1 for LAN processing
#define PREFERRED_CPU_FOR_WIFI 2 // CPU 2 for WiFi processing

#define DPC_WATCHDOG_TIMEOUT_MS 100 // Max DPC execution time

//=============================================================================
// SECTION 3: RSS Configuration Constants
//=============================================================================

#define RSS_HASH_KEY_SIZE 40           // Toeplitz hash key size
#define RSS_INDIRECTION_TABLE_SIZE 128 // Hash to CPU mapping entries

// RSS Hash Type Flags
#define RSS_HASH_TYPE_IPV4 0x00000100
#define RSS_HASH_TYPE_TCP_IPV4 0x00000200
#define RSS_HASH_TYPE_IPV6 0x00000400
#define RSS_HASH_TYPE_TCP_IPV6 0x00000800
#define RSS_HASH_TYPE_UDP 0x00001000

// Default configuration
#define RSS_DEFAULT_HASH_TYPE (RSS_HASH_TYPE_TCP_IPV4 | RSS_HASH_TYPE_TCP_IPV6)
#define RSS_MAX_QUEUES 16

//=============================================================================
// SECTION 4: DMA Configuration Constants
//=============================================================================

#define DMA_BUFFER_SIZE (2 * 1024 * 1024) // 2MB per buffer
#define DMA_BUFFER_COUNT 8                // One per CPU core
#define DMA_ALIGNMENT 4096                // Page alignment
#define DMA_MAX_TRANSFER_SIZE 65536       // 64KB max transfer
#define DMA_SCATTER_GATHER_MAX 256        // Max SG elements

//=============================================================================
// SECTION 5: Hardware Offload Flags
//=============================================================================

/**
 * HARDWARE_OFFLOAD_FLAGS
 *
 * Bit flags for NIC hardware offload capabilities.
 */
typedef enum _HARDWARE_OFFLOAD_FLAGS {
  OFFLOAD_NONE = 0x00000000,
  OFFLOAD_CHECKSUM_IPV4_TX = 0x00000001,
  OFFLOAD_CHECKSUM_IPV4_RX = 0x00000002,
  OFFLOAD_CHECKSUM_TCP_TX = 0x00000004,
  OFFLOAD_CHECKSUM_TCP_RX = 0x00000008,
  OFFLOAD_CHECKSUM_UDP_TX = 0x00000010,
  OFFLOAD_CHECKSUM_UDP_RX = 0x00000020,
  OFFLOAD_LSO_V1 = 0x00000040,   // Large Send Offload v1
  OFFLOAD_LSO_V2 = 0x00000080,   // Large Send Offload v2
  OFFLOAD_RSC_IPV4 = 0x00000100, // Receive Segment Coalescing
  OFFLOAD_RSC_IPV6 = 0x00000200,
  OFFLOAD_VLAN_TAGGING = 0x00000400,
  OFFLOAD_JUMBO_FRAMES = 0x00000800
} HARDWARE_OFFLOAD_FLAGS;

// Convenience combinations
#define OFFLOAD_ALL_CHECKSUM                                                   \
  (OFFLOAD_CHECKSUM_IPV4_TX | OFFLOAD_CHECKSUM_IPV4_RX |                       \
   OFFLOAD_CHECKSUM_TCP_TX | OFFLOAD_CHECKSUM_TCP_RX |                         \
   OFFLOAD_CHECKSUM_UDP_TX | OFFLOAD_CHECKSUM_UDP_RX)

//=============================================================================
// SECTION 6: Performance Counters Structure (256 bytes)
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

/**
 * PERFORMANCE_COUNTERS
 *
 * Performance metrics tracked per-CPU and globally.
 */
typedef struct _PERFORMANCE_COUNTERS {
  // Cycle counters (32 bytes)
  ULONG64 CyclesSpentInDriver;  // 8 bytes
  ULONG64 DPCExecutionCount;    // 8 bytes
  ULONG64 DPCTotalMicroseconds; // 8 bytes
  ULONG64 ISRExecutionCount;    // 8 bytes

  // Cache/memory (16 bytes)
  ULONG64 CacheMisses;     // 8 bytes (PMU)
  ULONG64 ContextSwitches; // 8 bytes

  // Packet processing (16 bytes)
  ULONG CurrentPacketsInFlight;     // 4 bytes
  ULONG PeakPacketsInFlight;        // 4 bytes
  ULONG AveragePacketLatencyMicros; // 4 bytes
  ULONG PeakPacketLatencyMicros;    // 4 bytes

  // Utilization (8 bytes)
  ULONG CPUUsagePercent;     // 4 bytes
  ULONG MemoryBandwidthMBps; // 4 bytes

  // Reserved (184 bytes)
  UCHAR Reserved[184];                          // 184 bytes
} PERFORMANCE_COUNTERS, *PPERFORMANCE_COUNTERS; // Total: 256 bytes

//=============================================================================
// SECTION 7: CPU Affinity Structure
//=============================================================================

/**
 * CPU_AFFINITY_CONFIG
 *
 * Per-NIC CPU affinity configuration.
 */
typedef struct _CPU_AFFINITY_CONFIG {
  ULONG PreferredCPU;                         // 4 bytes - Specific CPU core
  ULONG Reserved1;                            // 4 bytes - Padding
  KAFFINITY AffinityMask;                     // 8 bytes - Allowed CPUs
  USHORT ProcessorGroup;                      // 2 bytes - For > 64 CPU
  USHORT NUMANode;                            // 2 bytes - Preferred NUMA node
  BOOLEAN IsAffinitySet;                      // 1 byte
  BOOLEAN AllowMigration;                     // 1 byte
  UCHAR Reserved2[2];                         // 2 bytes - Padding
} CPU_AFFINITY_CONFIG, *PCPU_AFFINITY_CONFIG; // Total: 24 bytes

//=============================================================================
// SECTION 8: RSS Configuration Structure
//=============================================================================

/**
 * RSS_CONFIGURATION
 *
 * RSS parameters for multi-queue packet distribution.
 */
typedef struct _RSS_CONFIGURATION {
  ULONG HashType;                                     // 4 bytes
  ULONG HashKeySize;                                  // 4 bytes
  UCHAR HashKey[RSS_HASH_KEY_SIZE];                   // 40 bytes
  ULONG IndirectionTableSize;                         // 4 bytes
  UCHAR IndirectionTable[RSS_INDIRECTION_TABLE_SIZE]; // 128 bytes
  ULONG NumberOfQueues;                               // 4 bytes
  BOOLEAN IsRSSEnabled;                               // 1 byte
  UCHAR Reserved[3];                                  // 3 bytes
} RSS_CONFIGURATION, *PRSS_CONFIGURATION;             // Total: 188 bytes

//=============================================================================
// SECTION 9: DMA Configuration Structure
//=============================================================================

/**
 * DMA_CONFIGURATION
 *
 * DMA buffer and scatter-gather settings.
 */
typedef struct _DMA_CONFIGURATION {
  PVOID DMABufferVirtual[DMA_BUFFER_COUNT];             // 64 bytes
  PHYSICAL_ADDRESS DMABufferPhysical[DMA_BUFFER_COUNT]; // 64 bytes
  SIZE_T DMABufferSize;                                 // 8 bytes
  PMDL DMABufferMdl[DMA_BUFFER_COUNT];                  // 64 bytes
  BOOLEAN IsDMAEnabled;                                 // 1 byte
  UCHAR Reserved1[3];                                   // 3 bytes
  ULONG MaxScatterGatherElements;                       // 4 bytes
  UCHAR Reserved2[48];                                  // 48 bytes
} DMA_CONFIGURATION, *PDMA_CONFIGURATION;               // Total: 256 bytes

//=============================================================================
// SECTION 10: Performance Context Structure
//=============================================================================

// Forward declare NIC_CONTEXT if not already defined
struct _NIC_CONTEXT;

/**
 * PERFORMANCE_CONTEXT
 *
 * Global performance optimization state.
 */
typedef struct _PERFORMANCE_CONTEXT {
  // Metrics (256 bytes)
  PERFORMANCE_COUNTERS Counters;

  // Per-NIC affinity (8 NICs × 24 bytes = 192 bytes)
  CPU_AFFINITY_CONFIG CPUAffinity[8];

  // Per-NIC RSS (8 NICs × 188 bytes = 1504 bytes - variable)
  RSS_CONFIGURATION RSSConfig[8];

  // Global DMA (256 bytes)
  DMA_CONFIGURATION DMAConfig;

  // Hardware capabilities (8 bytes)
  ULONG HardwareOffloadFlags; // 4 bytes
  ULONG Reserved1;            // 4 bytes

  // System topology (16 bytes)
  ULONG SystemProcessorCount; // 4 bytes
  ULONG SystemNUMANodeCount;  // 4 bytes
  BOOLEAN IsNUMASystem;       // 1 byte
  UCHAR Reserved2[7];         // 7 bytes

  // Synchronization (8 bytes)
  KSPIN_LOCK PerfLock; // 8 bytes

} PERFORMANCE_CONTEXT, *PPERFORMANCE_CONTEXT;

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
// SECTION 11: Function Prototypes - Initialization
//=============================================================================

// Initialize performance subsystem
NTSTATUS PerformanceInitialize(_In_ PDRIVER_CONTEXT Context);

// Cleanup resources
VOID PerformanceCleanup(_In_ PDRIVER_CONTEXT Context);

// Query NIC offload support
NTSTATUS DetectHardwareCapabilities(_In_ struct _NIC_CONTEXT *NICContext);

// Enumerate NUMA nodes and CPU mapping
NTSTATUS DetectNUMATopology(VOID);

// Allocate per-CPU DMA buffers
NTSTATUS AllocateDMABuffers(VOID);

//=============================================================================
// SECTION 12: Function Prototypes - CPU Affinity
//=============================================================================

// Pin NIC to CPU core
NTSTATUS SetCPUAffinity(_In_ struct _NIC_CONTEXT *NICContext,
                        _In_ ULONG PreferredCPU);

// Remove CPU pinning
NTSTATUS ClearCPUAffinity(_In_ struct _NIC_CONTEXT *NICContext);

// Calculate best CPU based on NUMA
ULONG GetOptimalCPUForNIC(_In_ struct _NIC_CONTEXT *NICContext);

// Pin DPC to specific CPU
NTSTATUS SetDPCTargetCPU(_In_ PKDPC Dpc, _In_ ULONG TargetCPU);

// Convert CPU number to affinity mask
KAFFINITY GetCPUAffinityMask(_In_ ULONG PreferredCPU);

//=============================================================================
// SECTION 13: Function Prototypes - RSS Management
//=============================================================================

// Enable RSS with N queues
NTSTATUS EnableRSS(_In_ struct _NIC_CONTEXT *NICContext,
                   _In_ ULONG NumberOfQueues);

// Disable RSS
NTSTATUS DisableRSS(_In_ struct _NIC_CONTEXT *NICContext);

// Set hash type
NTSTATUS ConfigureRSSHashFunction(_In_ struct _NIC_CONTEXT *NICContext,
                                  _In_ ULONG HashType);

// Configure indirection table
NTSTATUS SetRSSIndirectionTable(_In_ struct _NIC_CONTEXT *NICContext,
                                _In_ PUCHAR Table, _In_ ULONG Size);

// Generate random RSS key
NTSTATUS GenerateRSSHashKey(_Out_ PUCHAR OutKey, _In_ ULONG KeySize);

// Software RSS hash (testing)
ULONG CalculateRSSHash(_In_ PVOID PacketData, _In_ ULONG DataSize,
                       _In_ PUCHAR HashKey);

//=============================================================================
// SECTION 14: Function Prototypes - DMA Operations
//=============================================================================

// Enable DMA transfers
NTSTATUS EnableDMA(VOID);

// Disable DMA
VOID DisableDMA(VOID);

// Get DMA buffer for specific CPU
PVOID GetDMABufferForCPU(_In_ ULONG CPUNumber);

// Initiate DMA transfer
NTSTATUS StartDMATransfer(_In_ PHYSICAL_ADDRESS SourceAddress,
                          _In_ PVOID DestAddress, _In_ SIZE_T Length);

// Check DMA status
BOOLEAN IsDMATransferComplete(VOID);

// Cancel in-progress DMA
VOID AbortDMATransfer(VOID);

//=============================================================================
// SECTION 15: Function Prototypes - Hardware Offload
//=============================================================================

// Enable checksum offload
NTSTATUS EnableChecksumOffload(_In_ struct _NIC_CONTEXT *NICContext,
                               _In_ ULONG OffloadFlags);

// Disable checksum offload
NTSTATUS DisableChecksumOffload(_In_ struct _NIC_CONTEXT *NICContext);

// Enable Large Send Offload
NTSTATUS EnableLSO(_In_ struct _NIC_CONTEXT *NICContext);

// Enable Receive Segment Coalescing
NTSTATUS EnableRSC(_In_ struct _NIC_CONTEXT *NICContext);

// Check capability
BOOLEAN IsOffloadSupported(_In_ struct _NIC_CONTEXT *NICContext,
                           _In_ ULONG OffloadFlag);

//=============================================================================
// SECTION 16: Function Prototypes - Performance Monitoring
//=============================================================================

// Track latency
VOID RecordPacketProcessingTime(_In_ PLARGE_INTEGER StartTime,
                                _In_ PLARGE_INTEGER EndTime);

// Track DPC executions
VOID IncrementDPCCounter(VOID);

// Update CPU metric
VOID UpdateCPUUsage(_In_ ULONG PercentUsage);

// Export metrics
NTSTATUS GetPerformanceCounters(_Out_ PPERFORMANCE_COUNTERS OutCounters);

// Zero all metrics
VOID ResetPerformanceCounters(VOID);

// Calculate instantaneous PPS
ULONG CalculatePacketsPerSecond(VOID);

//=============================================================================
// SECTION 17: Function Prototypes - NUMA Optimization
//=============================================================================

// Allocate memory on specific NUMA node
NTSTATUS AllocateNUMAMemory(_In_ SIZE_T Size, _In_ ULONG PreferredNode,
                            _Out_ PVOID *OutAddress);

// Free NUMA memory
VOID FreeNUMAMemory(_In_ PVOID Address, _In_ SIZE_T Size);

// Determine NUMA node for CPU
ULONG GetNUMANodeForCPU(_In_ ULONG CPUNumber);

// Determine NUMA node for NIC
ULONG GetNUMANodeForNIC(_In_ struct _NIC_CONTEXT *NICContext);

// Check if system has multiple NUMA nodes
BOOLEAN IsNUMASystemDetected(VOID);

//=============================================================================
// SECTION 18: Debug Functions
//=============================================================================

#ifdef DBG

// Print performance counters
VOID DbgPrintPerformanceCounters(VOID);

// Print RSS configuration
VOID DbgPrintRSSConfig(_In_ PRSS_CONFIGURATION Config);

// Verify performance subsystem
NTSTATUS DbgVerifyPerformance(VOID);

#endif // DBG

#endif // SAFEOPS_PERFORMANCE_H
