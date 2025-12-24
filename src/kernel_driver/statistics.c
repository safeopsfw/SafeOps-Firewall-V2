/**
 * statistics.c - SafeOps Statistics Collection Implementation
 *
 * Purpose: Implements comprehensive performance counter collection and
 * aggregation for the SafeOps kernel driver. Tracks real-time metrics across
 * all driver subsystems including packet processing rates, memory usage,
 * filter performance, NIC-specific statistics, and error counters.
 *
 * Uses atomic counter operations for lock-free statistics updates from
 * multiple concurrent threads and IRQL contexts.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#include "driver.h"
#include "nic_management.h"
#include "performance.h"
#include "shared_memory.h"


#ifdef SAFEOPS_WDK_BUILD
#include <ntddk.h>
#include <wdm.h>
#endif

//=============================================================================
// SECTION 1: Constants and Macros
//=============================================================================

#define STATISTICS_POOL_TAG 'tatS'  // 'Stat' reversed for pool tag
#define PER_CPU_STATS_ENABLED FALSE // Set TRUE for per-CPU tracking

//=============================================================================
// SECTION 2: Global Statistics Context
//=============================================================================

// Main statistics structure (embedded in g_DriverContext)
// This is accessed globally for performance reasons

static LARGE_INTEGER g_DriverStartTime;
static LARGE_INTEGER g_LastSnapshotTime;
static ULONG64 g_LastSnapshotPacketsRx;
static ULONG64 g_LastSnapshotPacketsTx;

// Per-CPU statistics array (if enabled)
#if PER_CPU_STATS_ENABLED
static PSTATISTICS_COUNTERS g_PerCpuStats = NULL;
static ULONG g_CpuCount = 0;
#endif

//=============================================================================
// SECTION 3: Statistics Initialization
//=============================================================================

/**
 * InitializeStatistics
 *
 * Called during DriverEntry to initialize the statistics subsystem.
 * Zeros all counters and captures driver start timestamp.
 *
 * @param DriverContext - Pointer to global driver context
 * @return NTSTATUS - STATUS_SUCCESS or error code
 *
 * IRQL: PASSIVE_LEVEL (called from DriverEntry)
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    InitializeStatistics(_Inout_ PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  // Zero out all statistics counters
  RtlZeroMemory(&DriverContext->Statistics, sizeof(STATISTICS_COUNTERS));

  // Capture driver start time for uptime calculation
  KeQuerySystemTime(&g_DriverStartTime);
  g_LastSnapshotTime = g_DriverStartTime;
  g_LastSnapshotPacketsRx = 0;
  g_LastSnapshotPacketsTx = 0;

#if PER_CPU_STATS_ENABLED
  // Allocate per-CPU statistics array
  g_CpuCount = KeQueryActiveProcessorCount(NULL);
  if (g_CpuCount > 0 && g_CpuCount <= MAX_PROCESSOR_COUNT) {
    SIZE_T allocSize = g_CpuCount * sizeof(STATISTICS_COUNTERS);
    g_PerCpuStats = (PSTATISTICS_COUNTERS)ExAllocatePoolWithTag(
        NonPagedPool, allocSize, STATISTICS_POOL_TAG);

    if (g_PerCpuStats == NULL) {
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_PerCpuStats, allocSize);
  }
#endif

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 4: Atomic Counter Update Functions
//=============================================================================

/**
 * IncrementPacketCounter
 *
 * Atomically increments packet count for RX or TX direction.
 *
 * @param DriverContext - Pointer to driver context
 * @param IsInbound - TRUE for RX, FALSE for TX
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    IncrementPacketCounter(_Inout_ PDRIVER_CONTEXT DriverContext,
                           _In_ BOOLEAN IsInbound) {
  if (DriverContext == NULL)
    return;

  if (IsInbound) {
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.PacketsReceived);
  } else {
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.PacketsTransmitted);
  }
}

/**
 * IncrementByteCounter
 *
 * Atomically adds byte count to cumulative total.
 *
 * @param DriverContext - Pointer to driver context
 * @param IsInbound - TRUE for RX, FALSE for TX
 * @param ByteCount - Number of bytes to add
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    IncrementByteCounter(_Inout_ PDRIVER_CONTEXT DriverContext,
                         _In_ BOOLEAN IsInbound, _In_ ULONG64 ByteCount) {
  if (DriverContext == NULL)
    return;

  if (IsInbound) {
    InterlockedAdd64((LONG64 *)&DriverContext->Statistics.BytesReceived,
                     (LONG64)ByteCount);
  } else {
    InterlockedAdd64((LONG64 *)&DriverContext->Statistics.BytesTransmitted,
                     (LONG64)ByteCount);
  }
}

/**
 * IncrementDropCounter
 *
 * Increments dropped packet counter with reason code.
 *
 * @param DriverContext - Pointer to driver context
 * @param Reason - Drop reason code
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    IncrementDropCounter(_Inout_ PDRIVER_CONTEXT DriverContext,
                         _In_ ULONG Reason) {
  if (DriverContext == NULL)
    return;

  // Increment total dropped counter
  InterlockedIncrement64((LONG64 *)&DriverContext->Statistics.PacketsDropped);

  // Increment reason-specific counter if valid index
  if (Reason < MAX_DROP_REASONS) {
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.DropsByReason[Reason]);
  }
}

/**
 * IncrementErrorCounter
 *
 * Tracks error events by error type.
 *
 * @param DriverContext - Pointer to driver context
 * @param ErrorType - Error type code
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    IncrementErrorCounter(_Inout_ PDRIVER_CONTEXT DriverContext,
                          _In_ ULONG ErrorType) {
  if (DriverContext == NULL)
    return;

  // Increment total error counter
  InterlockedIncrement64((LONG64 *)&DriverContext->Statistics.TotalErrors);

  // Increment error-type-specific counter if valid index
  if (ErrorType < MAX_ERROR_TYPES) {
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.ErrorsByType[ErrorType]);
  }
}

/**
 * UpdateLatencyCounter
 *
 * Records a packet processing latency sample.
 *
 * @param DriverContext - Pointer to driver context
 * @param LatencyMicroseconds - Processing time in microseconds
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    UpdateLatencyCounter(_Inout_ PDRIVER_CONTEXT DriverContext,
                         _In_ ULONG64 LatencyMicroseconds) {
  if (DriverContext == NULL)
    return;

  // Add to cumulative latency
  InterlockedAdd64(
      (LONG64 *)&DriverContext->Statistics.TotalLatencyMicroseconds,
      (LONG64)LatencyMicroseconds);

  // Increment sample count
  InterlockedIncrement64(
      (LONG64 *)&DriverContext->Statistics.LatencySampleCount);

  // Update peak latency if this is the highest
  ULONG64 currentPeak = DriverContext->Statistics.PeakLatencyMicroseconds;
  while (LatencyMicroseconds > currentPeak) {
    ULONG64 oldPeak = (ULONG64)InterlockedCompareExchange64(
        (LONG64 *)&DriverContext->Statistics.PeakLatencyMicroseconds,
        (LONG64)LatencyMicroseconds, (LONG64)currentPeak);
    if (oldPeak == currentPeak)
      break;
    currentPeak = oldPeak;
  }
}

//=============================================================================
// SECTION 5: NIC-Specific Statistics Functions
//=============================================================================

/**
 * UpdateNicStatistics
 *
 * Updates statistics for a specific NIC interface.
 *
 * @param DriverContext - Pointer to driver context
 * @param NicContext - Pointer to NIC context
 * @param IsInbound - TRUE for RX, FALSE for TX
 * @param ByteCount - Packet size in bytes
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    UpdateNicStatistics(_Inout_ PDRIVER_CONTEXT DriverContext,
                        _Inout_ PNIC_CONTEXT NicContext, _In_ BOOLEAN IsInbound,
                        _In_ ULONG64 ByteCount) {
  if (DriverContext == NULL || NicContext == NULL)
    return;

  // Update per-NIC statistics
  NicIncrementPacketCount(NicContext, IsInbound, ByteCount);

  // Update global statistics
  IncrementPacketCounter(DriverContext, IsInbound);
  IncrementByteCounter(DriverContext, IsInbound, ByteCount);

  // Update interface-type-specific counters based on NIC tag
  switch (NicContext->Configuration.NICType) {
  case NIC_TYPE_WAN:
    if (IsInbound) {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.WanPacketsReceived);
    } else {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.WanPacketsTransmitted);
    }
    break;
  case NIC_TYPE_LAN:
    if (IsInbound) {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.LanPacketsReceived);
    } else {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.LanPacketsTransmitted);
    }
    break;
  case NIC_TYPE_WIFI:
    if (IsInbound) {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.WifiPacketsReceived);
    } else {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->Statistics.WifiPacketsTransmitted);
    }
    break;
  default:
    break;
  }
}

//=============================================================================
// SECTION 6: Filter Performance Statistics
//=============================================================================

/**
 * RecordFilterDecision
 *
 * Records firewall rule evaluation outcome and timing.
 *
 * @param DriverContext - Pointer to driver context
 * @param Decision - ALLOW (0), DENY (1), or DROP (2)
 * @param EvaluationTimeMicroseconds - Time spent in filter evaluation
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    RecordFilterDecision(_Inout_ PDRIVER_CONTEXT DriverContext,
                         _In_ ULONG Decision,
                         _In_ ULONG64 EvaluationTimeMicroseconds) {
  if (DriverContext == NULL)
    return;

  // Update decision counters
  switch (Decision) {
  case 0: // ALLOW
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.FilterAllowCount);
    break;
  case 1: // DENY
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.FilterDenyCount);
    break;
  case 2: // DROP
    InterlockedIncrement64(
        (LONG64 *)&DriverContext->Statistics.FilterDropCount);
    break;
  default:
    break;
  }

  // Update filter evaluation time statistics
  InterlockedAdd64(
      (LONG64 *)&DriverContext->Statistics.TotalFilterEvaluationTime,
      (LONG64)EvaluationTimeMicroseconds);
  InterlockedIncrement64(
      (LONG64 *)&DriverContext->Statistics.FilterEvaluationCount);
}

//=============================================================================
// SECTION 7: Memory Statistics Functions
//=============================================================================

/**
 * UpdateMemoryStatistics
 *
 * Samples current memory usage metrics.
 * Called periodically (every few seconds) rather than per-packet.
 *
 * @param DriverContext - Pointer to driver context
 *
 * IRQL: <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    UpdateMemoryStatistics(_Inout_ PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL)
    return;

  // Query ring buffer fill percentage
  ULONG fillPercent = RingBufferGetFillPercentage(&DriverContext->RingBuffer);
  DriverContext->Statistics.RingBufferFillPercent = fillPercent;

  // Update peak if this is the highest
  if (fillPercent > DriverContext->Statistics.RingBufferPeakFillPercent) {
    DriverContext->Statistics.RingBufferPeakFillPercent = fillPercent;
  }

  // Track NonPagedPool usage (from internal allocation tracking)
  // This would be updated from allocation wrapper functions
}

//=============================================================================
// SECTION 8: Helper Functions for Derived Metrics
//=============================================================================

/**
 * ComputePacketRate
 *
 * Calculates packets per second from counter delta and elapsed time.
 *
 * @param CurrentCount - Current packet count
 * @param PreviousCount - Previous snapshot packet count
 * @param ElapsedMilliseconds - Time between snapshots
 * @return Packets per second
 */
static ULONG64 ComputePacketRate(_In_ ULONG64 CurrentCount,
                                 _In_ ULONG64 PreviousCount,
                                 _In_ ULONG64 ElapsedMilliseconds) {
  if (ElapsedMilliseconds == 0)
    return 0;

  ULONG64 delta = CurrentCount - PreviousCount;
  return (delta * 1000) / ElapsedMilliseconds;
}

/**
 * ComputeDropRate
 *
 * Calculates drop rate as a percentage.
 *
 * @param DroppedPackets - Number of dropped packets
 * @param TotalPackets - Total packets processed
 * @return Drop rate percentage (0-100)
 */
static ULONG ComputeDropRate(_In_ ULONG64 DroppedPackets,
                             _In_ ULONG64 TotalPackets) {
  if (TotalPackets == 0)
    return 0;

  ULONG64 rate = (DroppedPackets * 100) / TotalPackets;
  return (ULONG)(rate > 100 ? 100 : rate);
}

/**
 * ComputeAverageLatency
 *
 * Calculates average latency from cumulative samples.
 *
 * @param TotalLatency - Cumulative latency in microseconds
 * @param SampleCount - Number of samples
 * @return Average latency in microseconds
 */
static ULONG64 ComputeAverageLatency(_In_ ULONG64 TotalLatency,
                                     _In_ ULONG64 SampleCount) {
  if (SampleCount == 0)
    return 0;
  return TotalLatency / SampleCount;
}

//=============================================================================
// SECTION 9: Statistics Snapshot Functions
//=============================================================================

#if PER_CPU_STATS_ENABLED
/**
 * AggregatePerCpuStatistics
 *
 * Sums statistics across all CPU cores.
 *
 * @param Snapshot - Output snapshot structure
 */
static VOID AggregatePerCpuStatistics(_Out_ PSTATISTICS_SNAPSHOT Snapshot) {
  if (g_PerCpuStats == NULL || Snapshot == NULL)
    return;

  for (ULONG i = 0; i < g_CpuCount; i++) {
    Snapshot->PacketsReceived += g_PerCpuStats[i].PacketsReceived;
    Snapshot->PacketsTransmitted += g_PerCpuStats[i].PacketsTransmitted;
    Snapshot->BytesReceived += g_PerCpuStats[i].BytesReceived;
    Snapshot->BytesTransmitted += g_PerCpuStats[i].BytesTransmitted;
    Snapshot->PacketsDropped += g_PerCpuStats[i].PacketsDropped;
  }
}
#endif

/**
 * CaptureStatisticsSnapshot
 *
 * Creates a point-in-time snapshot of all statistics counters.
 *
 * @param DriverContext - Pointer to driver context
 * @param Snapshot - Output snapshot structure
 * @return NTSTATUS - STATUS_SUCCESS or error code
 *
 * IRQL: <= DISPATCH_LEVEL (typically PASSIVE_LEVEL from IOCTL)
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    CaptureStatisticsSnapshot(_In_ PDRIVER_CONTEXT DriverContext,
                              _Out_ PSTATISTICS_SNAPSHOT Snapshot) {
  LARGE_INTEGER currentTime;
  ULONG64 elapsedMs;

  if (DriverContext == NULL || Snapshot == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  // Zero output structure
  RtlZeroMemory(Snapshot, sizeof(STATISTICS_SNAPSHOT));

  // Get current time for calculations
  KeQuerySystemTime(&currentTime);

  // Read all counters atomically
  Snapshot->PacketsReceived = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.PacketsReceived, 0, 0);
  Snapshot->PacketsTransmitted = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.PacketsTransmitted, 0, 0);
  Snapshot->BytesReceived = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.BytesReceived, 0, 0);
  Snapshot->BytesTransmitted = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.BytesTransmitted, 0, 0);
  Snapshot->PacketsDropped = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.PacketsDropped, 0, 0);
  Snapshot->TotalErrors = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.TotalErrors, 0, 0);

  // Per-NIC type statistics
  Snapshot->WanPacketsReceived = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.WanPacketsReceived, 0, 0);
  Snapshot->WanPacketsTransmitted = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.WanPacketsTransmitted, 0, 0);
  Snapshot->LanPacketsReceived = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.LanPacketsReceived, 0, 0);
  Snapshot->LanPacketsTransmitted = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.LanPacketsTransmitted, 0, 0);
  Snapshot->WifiPacketsReceived = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.WifiPacketsReceived, 0, 0);
  Snapshot->WifiPacketsTransmitted = (ULONG64)InterlockedCompareExchange64(
      (LONG64 *)&DriverContext->Statistics.WifiPacketsTransmitted, 0, 0);

  // Filter statistics
  Snapshot->FilterAllowCount = DriverContext->Statistics.FilterAllowCount;
  Snapshot->FilterDenyCount = DriverContext->Statistics.FilterDenyCount;
  Snapshot->FilterDropCount = DriverContext->Statistics.FilterDropCount;

  // Memory statistics
  Snapshot->RingBufferFillPercent =
      DriverContext->Statistics.RingBufferFillPercent;
  Snapshot->RingBufferPeakFillPercent =
      DriverContext->Statistics.RingBufferPeakFillPercent;

#if PER_CPU_STATS_ENABLED
  // Aggregate per-CPU statistics
  AggregatePerCpuStatistics(Snapshot);
#endif

  // Calculate uptime in seconds
  ULONG64 uptimeHundredNs = currentTime.QuadPart - g_DriverStartTime.QuadPart;
  Snapshot->UptimeSeconds = uptimeHundredNs / 10000000ULL;

  // Calculate elapsed time since last snapshot
  elapsedMs = (currentTime.QuadPart - g_LastSnapshotTime.QuadPart) / 10000ULL;

  // Compute packet rates
  Snapshot->PacketsPerSecondRx = ComputePacketRate(
      Snapshot->PacketsReceived, g_LastSnapshotPacketsRx, elapsedMs);
  Snapshot->PacketsPerSecondTx = ComputePacketRate(
      Snapshot->PacketsTransmitted, g_LastSnapshotPacketsTx, elapsedMs);

  // Compute drop rate percentage
  ULONG64 totalPackets =
      Snapshot->PacketsReceived + Snapshot->PacketsTransmitted;
  Snapshot->DropRatePercent =
      ComputeDropRate(Snapshot->PacketsDropped, totalPackets);

  // Compute average latency
  ULONG64 totalLatency = DriverContext->Statistics.TotalLatencyMicroseconds;
  ULONG64 sampleCount = DriverContext->Statistics.LatencySampleCount;
  Snapshot->AverageLatencyMicroseconds =
      ComputeAverageLatency(totalLatency, sampleCount);
  Snapshot->PeakLatencyMicroseconds =
      DriverContext->Statistics.PeakLatencyMicroseconds;

  // Update last snapshot values for next rate calculation
  g_LastSnapshotTime = currentTime;
  g_LastSnapshotPacketsRx = Snapshot->PacketsReceived;
  g_LastSnapshotPacketsTx = Snapshot->PacketsTransmitted;

  // Set snapshot timestamp
  Snapshot->TimestampUtc = currentTime;

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 10: Statistics Reset Functions
//=============================================================================

/**
 * ResetStatistics
 *
 * Zeros all statistics counters while preserving uptime.
 *
 * @param DriverContext - Pointer to driver context
 * @return NTSTATUS - STATUS_SUCCESS
 *
 * IRQL: PASSIVE_LEVEL (called from IOCTL handler)
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    ResetStatistics(_Inout_ PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  // Reset all packet counters atomically
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.PacketsReceived,
                        0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.PacketsTransmitted,
                        0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.BytesReceived, 0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.BytesTransmitted,
                        0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.PacketsDropped, 0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.TotalErrors, 0);

  // Reset NIC-type counters
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.WanPacketsReceived,
                        0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.WanPacketsTransmitted, 0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.LanPacketsReceived,
                        0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.LanPacketsTransmitted, 0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.WifiPacketsReceived, 0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.WifiPacketsTransmitted, 0);

  // Reset filter counters
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.FilterAllowCount,
                        0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.FilterDenyCount,
                        0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.FilterDropCount,
                        0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.TotalFilterEvaluationTime, 0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.FilterEvaluationCount, 0);

  // Reset latency counters
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.TotalLatencyMicroseconds, 0);
  InterlockedExchange64((LONG64 *)&DriverContext->Statistics.LatencySampleCount,
                        0);
  InterlockedExchange64(
      (LONG64 *)&DriverContext->Statistics.PeakLatencyMicroseconds, 0);

  // Reset memory counters (but not peak)
  DriverContext->Statistics.RingBufferFillPercent = 0;
  // Keep RingBufferPeakFillPercent as historical high-water mark

  // Reset drop reason counters
  for (ULONG i = 0; i < MAX_DROP_REASONS; i++) {
    InterlockedExchange64((LONG64 *)&DriverContext->Statistics.DropsByReason[i],
                          0);
  }

  // Reset error type counters
  for (ULONG i = 0; i < MAX_ERROR_TYPES; i++) {
    InterlockedExchange64((LONG64 *)&DriverContext->Statistics.ErrorsByType[i],
                          0);
  }

#if PER_CPU_STATS_ENABLED
  // Reset per-CPU statistics
  if (g_PerCpuStats != NULL) {
    RtlZeroMemory(g_PerCpuStats, g_CpuCount * sizeof(STATISTICS_COUNTERS));
  }
#endif

  // Update snapshot baseline
  KeQuerySystemTime(&g_LastSnapshotTime);
  g_LastSnapshotPacketsRx = 0;
  g_LastSnapshotPacketsTx = 0;

  // NOTE: g_DriverStartTime is NOT reset - uptime should continue

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 11: Statistics Cleanup
//=============================================================================

/**
 * CleanupStatistics
 *
 * Called during DriverUnload to free statistics resources.
 *
 * @param DriverContext - Pointer to driver context
 * @return NTSTATUS - STATUS_SUCCESS
 *
 * IRQL: PASSIVE_LEVEL (called from DriverUnload)
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    CleanupStatistics(_In_ PDRIVER_CONTEXT DriverContext) {
  UNREFERENCED_PARAMETER(DriverContext);

#if PER_CPU_STATS_ENABLED
  // Free per-CPU statistics array
  if (g_PerCpuStats != NULL) {
    ExFreePoolWithTag(g_PerCpuStats, STATISTICS_POOL_TAG);
    g_PerCpuStats = NULL;
    g_CpuCount = 0;
  }
#endif

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 12: Debug Functions
//=============================================================================

#ifdef DBG

/**
 * DbgPrintStatistics
 *
 * Prints current statistics to debug output.
 *
 * @param DriverContext - Pointer to driver context
 */
VOID DbgPrintStatistics(_In_ PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL)
    return;

  DbgPrint("SafeOps Statistics:\n");
  DbgPrint("  PacketsReceived:    %llu\n",
           DriverContext->Statistics.PacketsReceived);
  DbgPrint("  PacketsTransmitted: %llu\n",
           DriverContext->Statistics.PacketsTransmitted);
  DbgPrint("  BytesReceived:      %llu\n",
           DriverContext->Statistics.BytesReceived);
  DbgPrint("  BytesTransmitted:   %llu\n",
           DriverContext->Statistics.BytesTransmitted);
  DbgPrint("  PacketsDropped:     %llu\n",
           DriverContext->Statistics.PacketsDropped);
  DbgPrint("  TotalErrors:        %llu\n",
           DriverContext->Statistics.TotalErrors);
  DbgPrint("  RingBufferFill:     %lu%%\n",
           DriverContext->Statistics.RingBufferFillPercent);
}

#endif // DBG
