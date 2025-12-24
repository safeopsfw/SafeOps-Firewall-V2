/**
 * statistics.h - SafeOps Statistics Collection Interface
 *
 * Purpose: Defines the interface for comprehensive performance counter
 * collection and aggregation for the SafeOps kernel driver. Tracks real-time
 * metrics across all driver subsystems including packet processing rates,
 * memory usage, filter performance, NIC-specific statistics, and error
 * counters.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#ifndef SAFEOPS_STATISTICS_H
#define SAFEOPS_STATISTICS_H

//=============================================================================
// IDE Mode Compatibility - Stub SAL Annotations
//=============================================================================

#ifndef SAFEOPS_WDK_BUILD
// IRQL annotations for IDE IntelliSense (not used during WDK builds)
#ifndef _IRQL_requires_
#define _IRQL_requires_(x)
#endif
#ifndef _IRQL_requires_max_
#define _IRQL_requires_max_(x)
#endif
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif
#ifndef DISPATCH_LEVEL
#define DISPATCH_LEVEL 2
#endif
#endif // !SAFEOPS_WDK_BUILD

#include "driver.h"

//=============================================================================
// SECTION 1: Statistics Constants
//=============================================================================

#define MAX_DROP_REASONS 16    // Maximum drop reason codes
#define MAX_ERROR_TYPES 16     // Maximum error type codes
#define MAX_PROCESSOR_COUNT 64 // Maximum CPU cores for per-CPU stats

// Drop reason codes
#define DROP_REASON_FIREWALL_RULE 0
#define DROP_REASON_RESOURCE_EXHAUSTION 1
#define DROP_REASON_MALFORMED_PACKET 2
#define DROP_REASON_RING_BUFFER_FULL 3
#define DROP_REASON_INVALID_CHECKSUM 4
#define DROP_REASON_FRAGMENT_ERROR 5
#define DROP_REASON_TTL_EXPIRED 6
#define DROP_REASON_BLACKLISTED_IP 7
#define DROP_REASON_RATE_LIMITED 8
#define DROP_REASON_CONNECTION_LIMIT 9
#define DROP_REASON_INVALID_STATE 10
#define DROP_REASON_DPI_BLOCKED 11
#define DROP_REASON_UNKNOWN 15

// Error type codes
#define ERROR_TYPE_MEMORY_ALLOCATION 0
#define ERROR_TYPE_NDIS_ERROR 1
#define ERROR_TYPE_WFP_CALLOUT 2
#define ERROR_TYPE_INVALID_IOCTL 3
#define ERROR_TYPE_RING_BUFFER 4
#define ERROR_TYPE_FILTER_ENGINE 5
#define ERROR_TYPE_NIC_MANAGEMENT 6
#define ERROR_TYPE_CONFIGURATION 7
#define ERROR_TYPE_INTERNAL 15

// Filter decision codes
#define FILTER_DECISION_ALLOW 0
#define FILTER_DECISION_DENY 1
#define FILTER_DECISION_DROP 2

//=============================================================================
// SECTION 2: Statistics Counters Structure (embedded in DRIVER_CONTEXT)
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 8)
#endif

/**
 * STATISTICS_COUNTERS
 *
 * Main statistics structure embedded in DRIVER_CONTEXT.
 * All counters are 64-bit for atomic operations and to prevent overflow.
 * Size: 1024 bytes (aligned to cache lines)
 */
typedef struct _STATISTICS_COUNTERS {
  // Packet counters (64 bytes)
  volatile ULONG64 PacketsReceived;    // 8 bytes - Total RX packets
  volatile ULONG64 PacketsTransmitted; // 8 bytes - Total TX packets
  volatile ULONG64 BytesReceived;      // 8 bytes - Total RX bytes
  volatile ULONG64 BytesTransmitted;   // 8 bytes - Total TX bytes
  volatile ULONG64 PacketsDropped;     // 8 bytes - Total dropped packets
  volatile ULONG64 TotalErrors;        // 8 bytes - Total error events
  ULONG64 Reserved1[2];                // 16 bytes - Padding

  // Per-NIC-type counters (64 bytes)
  volatile ULONG64 WanPacketsReceived;     // 8 bytes
  volatile ULONG64 WanPacketsTransmitted;  // 8 bytes
  volatile ULONG64 LanPacketsReceived;     // 8 bytes
  volatile ULONG64 LanPacketsTransmitted;  // 8 bytes
  volatile ULONG64 WifiPacketsReceived;    // 8 bytes
  volatile ULONG64 WifiPacketsTransmitted; // 8 bytes
  ULONG64 Reserved2[2];                    // 16 bytes - Padding

  // Filter counters (64 bytes)
  volatile ULONG64 FilterAllowCount;          // 8 bytes
  volatile ULONG64 FilterDenyCount;           // 8 bytes
  volatile ULONG64 FilterDropCount;           // 8 bytes
  volatile ULONG64 TotalFilterEvaluationTime; // 8 bytes - Cumulative µs
  volatile ULONG64 FilterEvaluationCount;     // 8 bytes
  volatile ULONG64 FilterCacheHits;           // 8 bytes
  volatile ULONG64 FilterCacheMisses;         // 8 bytes
  ULONG64 Reserved3;                          // 8 bytes - Padding

  // Latency counters (64 bytes)
  volatile ULONG64 TotalLatencyMicroseconds; // 8 bytes - Cumulative latency
  volatile ULONG64 LatencySampleCount;       // 8 bytes - Number of samples
  volatile ULONG64 PeakLatencyMicroseconds;  // 8 bytes - Highest latency
  volatile ULONG64 MinLatencyMicroseconds;   // 8 bytes - Lowest latency
  ULONG64 Reserved4[4];                      // 32 bytes - Padding

  // Memory counters (64 bytes)
  volatile ULONG RingBufferFillPercent;     // 4 bytes - Current fill %
  volatile ULONG RingBufferPeakFillPercent; // 4 bytes - Peak fill %
  volatile ULONG64 NonPagedPoolUsage;       // 8 bytes - Current usage
  volatile ULONG64 NonPagedPoolPeak;        // 8 bytes - Peak usage
  volatile ULONG64 AllocationCount;         // 8 bytes - Total allocations
  volatile ULONG64 AllocationFailures;      // 8 bytes - Failed allocations
  ULONG64 Reserved5[3];                     // 24 bytes - Padding

  // Drop reason counters (128 bytes)
  volatile ULONG64 DropsByReason[MAX_DROP_REASONS]; // 16 * 8 = 128 bytes

  // Error type counters (128 bytes)
  volatile ULONG64 ErrorsByType[MAX_ERROR_TYPES]; // 16 * 8 = 128 bytes

  // Connection tracking (64 bytes)
  volatile ULONG64 ActiveConnections;  // 8 bytes
  volatile ULONG64 TotalConnections;   // 8 bytes
  volatile ULONG64 ConnectionTimeouts; // 8 bytes
  volatile ULONG64 ConnectionRejects;  // 8 bytes
  ULONG64 Reserved6[4];                // 32 bytes - Padding

  // Future expansion (384 bytes)
  ULONG64 Reserved7[48];

} STATISTICS_COUNTERS, *PSTATISTICS_COUNTERS; // Total: 1024 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
// SECTION 3: Statistics Snapshot Structure (for IOCTL export)
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 8)
#endif

/**
 * STATISTICS_SNAPSHOT
 *
 * Point-in-time snapshot of statistics for export to userspace.
 * Includes derived metrics like rates and percentages.
 * Size: 512 bytes
 */
typedef struct _STATISTICS_SNAPSHOT {
  // Timestamp (16 bytes)
  LARGE_INTEGER TimestampUtc; // 8 bytes - Snapshot time
  ULONG64 UptimeSeconds;      // 8 bytes - Driver uptime

  // Packet counters (48 bytes)
  ULONG64 PacketsReceived;    // 8 bytes
  ULONG64 PacketsTransmitted; // 8 bytes
  ULONG64 BytesReceived;      // 8 bytes
  ULONG64 BytesTransmitted;   // 8 bytes
  ULONG64 PacketsDropped;     // 8 bytes
  ULONG64 TotalErrors;        // 8 bytes

  // Per-NIC-type counters (48 bytes)
  ULONG64 WanPacketsReceived;     // 8 bytes
  ULONG64 WanPacketsTransmitted;  // 8 bytes
  ULONG64 LanPacketsReceived;     // 8 bytes
  ULONG64 LanPacketsTransmitted;  // 8 bytes
  ULONG64 WifiPacketsReceived;    // 8 bytes
  ULONG64 WifiPacketsTransmitted; // 8 bytes

  // Filter counters (24 bytes)
  ULONG64 FilterAllowCount; // 8 bytes
  ULONG64 FilterDenyCount;  // 8 bytes
  ULONG64 FilterDropCount;  // 8 bytes

  // Derived metrics (48 bytes)
  ULONG64 PacketsPerSecondRx;         // 8 bytes - Computed rate
  ULONG64 PacketsPerSecondTx;         // 8 bytes - Computed rate
  ULONG64 BytesPerSecondRx;           // 8 bytes - Computed rate
  ULONG64 BytesPerSecondTx;           // 8 bytes - Computed rate
  ULONG64 AverageLatencyMicroseconds; // 8 bytes - Computed average
  ULONG64 PeakLatencyMicroseconds;    // 8 bytes

  // Memory metrics (16 bytes)
  ULONG RingBufferFillPercent;     // 4 bytes
  ULONG RingBufferPeakFillPercent; // 4 bytes
  ULONG DropRatePercent;           // 4 bytes - 0-100%
  ULONG ErrorRatePercent;          // 4 bytes - 0-100%

  // Connection metrics (32 bytes)
  ULONG64 ActiveConnections;  // 8 bytes
  ULONG64 TotalConnections;   // 8 bytes
  ULONG64 ConnectionsPerSec;  // 8 bytes - Computed rate
  ULONG64 ConnectionTimeouts; // 8 bytes

  // Reserved for future expansion (280 bytes)
  ULONG64 Reserved[35];

} STATISTICS_SNAPSHOT, *PSTATISTICS_SNAPSHOT; // Total: 512 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
//=============================================================================
// SECTION 4: Function Prototypes - Initialization and Cleanup
//=============================================================================

// Forward declare DRIVER_CONTEXT (already defined in driver.h)
#ifndef _DRIVER_CONTEXT_DECLARED
struct _DRIVER_CONTEXT;
typedef struct _DRIVER_CONTEXT *PDRIVER_CONTEXT;
#endif

// Forward declare NIC_CONTEXT
struct _NIC_CONTEXT;
typedef struct _NIC_CONTEXT *PNIC_CONTEXT;

/**
 * Initialize statistics subsystem.
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS InitializeStatistics(PDRIVER_CONTEXT DriverContext);

/**
 * Cleanup statistics resources.
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS CleanupStatistics(PDRIVER_CONTEXT DriverContext);

//=============================================================================
// SECTION 5: Function Prototypes - Counter Updates
//=============================================================================

/**
 * Increment packet counter (RX or TX).
 * IRQL: <= DISPATCH_LEVEL
 */
VOID IncrementPacketCounter(PDRIVER_CONTEXT DriverContext, BOOLEAN IsInbound);

/**
 * Add bytes to byte counter.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID IncrementByteCounter(PDRIVER_CONTEXT DriverContext, BOOLEAN IsInbound,
                          ULONG64 ByteCount);

/**
 * Increment drop counter with reason.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID IncrementDropCounter(PDRIVER_CONTEXT DriverContext, ULONG Reason);

/**
 * Increment error counter by type.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID IncrementErrorCounter(PDRIVER_CONTEXT DriverContext, ULONG ErrorType);

/**
 * Record latency sample.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID UpdateLatencyCounter(PDRIVER_CONTEXT DriverContext,
                          ULONG64 LatencyMicroseconds);

//=============================================================================
// SECTION 6: Function Prototypes - NIC and Filter Statistics
//=============================================================================

/**
 * Update per-NIC statistics.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID UpdateNicStatistics(PDRIVER_CONTEXT DriverContext, PNIC_CONTEXT NicContext,
                         BOOLEAN IsInbound, ULONG64 ByteCount);

/**
 * Record filter evaluation result.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID RecordFilterDecision(PDRIVER_CONTEXT DriverContext, ULONG Decision,
                          ULONG64 EvaluationTimeMicroseconds);

/**
 * Update memory usage statistics.
 * IRQL: <= DISPATCH_LEVEL
 */
VOID UpdateMemoryStatistics(PDRIVER_CONTEXT DriverContext);

//=============================================================================
// SECTION 7: Function Prototypes - Snapshot and Reset
//=============================================================================

/**
 * Capture point-in-time statistics snapshot.
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS CaptureStatisticsSnapshot(PDRIVER_CONTEXT DriverContext,
                                   PSTATISTICS_SNAPSHOT Snapshot);

/**
 * Reset all statistics counters (preserves uptime).
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS ResetStatistics(PDRIVER_CONTEXT DriverContext);

//=============================================================================
// SECTION 8: Debug Functions
//=============================================================================

#ifdef DBG

/**
 * Print current statistics to debug output.
 */
VOID DbgPrintStatistics(PDRIVER_CONTEXT DriverContext);

#endif // DBG

#endif // SAFEOPS_STATISTICS_H
