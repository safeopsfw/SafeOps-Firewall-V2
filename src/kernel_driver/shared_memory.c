/**
 * shared_memory.c - SafeOps Lock-Free Ring Buffer Implementation
 *
 * Purpose: Implements a high-performance 2GB lock-free ring buffer that enables
 * zero-copy packet data transfer between kernel driver and userspace service.
 * Uses atomic operations for head/tail pointer management ensuring thread-safe
 * concurrent access without locks.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#include "driver.h"

#ifdef SAFEOPS_WDK_BUILD
#include <ntddk.h>
#include <wdm.h>
#else
//=============================================================================
// IDE Mode Stubs - Not used during WDK compilation
//=============================================================================
#define _IRQL_requires_(x)
#define _IRQL_requires_max_(x)
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#define MmAllocateContiguousMemorySpecifyCache(a, b, c, d, e) NULL
#define MmFreeContiguousMemory(x)
#define MmBuildMdlForNonPagedPool(x)
#define MmMapLockedPagesSpecifyCache(a, b, c, d, e, f) NULL
#define MmUnmapLockedPages(a, b)
#define MmProbeAndLockPages(a, b, c)
#define MmUnlockPages(x)
#define IoAllocateMdl(a, b, c, d, e) NULL
#define IoFreeMdl(x)
#ifndef ExAllocatePoolWithTag
#define ExAllocatePoolWithTag(a, b, c) NULL
#endif
#ifndef ExFreePoolWithTag
#define ExFreePoolWithTag(a, b)
#endif
#define KeMemoryBarrier()
#define NonPagedPool 0
#define MmCached 0
#define UserMode 1
#define KernelMode 0
#define NormalPagePriority 0
#define IoReadAccess 0
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

typedef long long LONGLONG;
typedef ULONG64 *PULONG64;

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#endif
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005L)
#endif
#ifndef STATUS_INVALID_ADDRESS
#define STATUS_INVALID_ADDRESS ((NTSTATUS)0xC0000141L)
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define RtlZeroMemory(Dest, Len) memset((Dest), 0, (Len))
#define InterlockedExchange(Target, Value) (*(Target) = (Value))
#define InterlockedIncrement(Target) (++(*(Target)))
#define InterlockedCompareExchange(Target, Exchange, Comparand)                \
  (*(Target) == (Comparand) ? (*(Target) = (Exchange), (Comparand)) : *(Target))
#define InterlockedCompareExchange64(Target, Exchange, Comparand)              \
  (*(Target) == (Comparand) ? (*(Target) = (Exchange), (Comparand)) : *(Target))
#ifndef InterlockedIncrement64
#define InterlockedIncrement64(Target) (++(*(LONG64 *)(Target)))
#endif
#ifndef InterlockedAdd64
#define InterlockedAdd64(Target, Value) ((*(LONG64 *)(Target)) += (Value))
#endif
#define InterlockedExchange64(Target, Value) (*(Target) = (Value))
#define InterlockedExchangeAdd(Target, Value)                                  \
  (*(Target) += (Value), *(Target) - (Value))
#define KeQuerySystemTime(Time) ((Time)->QuadPart = 0)
#define KeQueryPerformanceCounter(Freq) ((LARGE_INTEGER){0})
#define DbgPrint(...) ((void)0)

#define __try if (1)
#define __except(x) else if (0)
#define EXCEPTION_EXECUTE_HANDLER 1

#include <string.h>
#endif

//=============================================================================
// SECTION 1: Constants
//=============================================================================

#define RING_BUFFER_POOL_TAG 'BgnR'
#define RING_BUFFER_SIZE_BYTES (2ULL * 1024 * 1024 * 1024) // 2GB
#define RING_BUFFER_HEADER_SIZE 4096           // First page for header
#define RING_BUFFER_DATA_OFFSET 4096           // Data starts after header
#define RING_BUFFER_ENTRY_ALIGNMENT 64         // Cache line alignment
#define RING_BUFFER_MAX_ENTRY_SIZE 65536       // 64KB max per entry
#define RING_BUFFER_WRAP_THRESHOLD (64 * 1024) // Wrap threshold

// Entry status values
#define ENTRY_STATUS_FREE 0
#define ENTRY_STATUS_IN_PROGRESS 1
#define ENTRY_STATUS_READY 2
#define ENTRY_STATUS_CONSUMED 3
#define ENTRY_STATUS_WRAP_MARKER 0xFF

//=============================================================================
// SECTION 2: Ring Buffer Entry Structure
//=============================================================================

typedef struct _RING_BUFFER_ENTRY {
  volatile LONG Status;    // Entry status
  ULONG DataSize;          // Size of packet data
  ULONG TotalSize;         // Total aligned entry size
  ULONG SequenceNumber;    // Sequence counter
  LARGE_INTEGER Timestamp; // Entry timestamp
  UCHAR Data[1];           // Variable-length data follows
} RING_BUFFER_ENTRY, *PRING_BUFFER_ENTRY;

// Forward declaration
static VOID HandleRingBufferWrapInternal(PDRIVER_CONTEXT DriverContext,
                                         ULONG CurrentTail);

//=============================================================================
// SECTION 3: Ring Buffer Initialization
//=============================================================================

/**
 * InitializeRingBuffer
 *
 * Allocates 2GB NonPagedPool memory for ring buffer and creates MDL
 * for userspace mapping.
 *
 * @param DriverContext - Pointer to driver context
 * @return NTSTATUS
 *
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS InitializeRingBuffer(PDRIVER_CONTEXT DriverContext) {
  PVOID bufferBase = NULL;
  PMDL bufferMdl = NULL;
  PHYSICAL_ADDRESS lowAddress = {0};
  PHYSICAL_ADDRESS highAddress;
  PHYSICAL_ADDRESS skipBytes = {0};

  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  highAddress.QuadPart = (LONGLONG)-1;

  // Allocate 2GB contiguous NonPagedPool memory
  bufferBase = MmAllocateContiguousMemorySpecifyCache(
      RING_BUFFER_SIZE_BYTES, lowAddress, highAddress, skipBytes, MmCached);

  if (bufferBase == NULL) {
    // Try regular pool allocation as fallback
    bufferBase = ExAllocatePoolWithTag(NonPagedPool, RING_BUFFER_SIZE_BYTES,
                                       RING_BUFFER_POOL_TAG);
    if (bufferBase == NULL) {
      return STATUS_INSUFFICIENT_RESOURCES;
    }
  }

  // Zero the buffer
  RtlZeroMemory(bufferBase, RING_BUFFER_SIZE_BYTES);

  // Create MDL for userspace mapping
  bufferMdl = IoAllocateMdl(bufferBase, (ULONG)RING_BUFFER_SIZE_BYTES, FALSE,
                            FALSE, NULL);

  if (bufferMdl == NULL) {
    MmFreeContiguousMemory(bufferBase);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Build MDL for non-paged pool memory
  MmBuildMdlForNonPagedPool(bufferMdl);

  // Initialize ring buffer context in driver context
  DriverContext->RingBuffer.BaseAddress = bufferBase;
  DriverContext->RingBuffer.TotalSize = RING_BUFFER_SIZE_BYTES;
  DriverContext->RingBuffer.Mdl = bufferMdl;
  DriverContext->RingBuffer.UserModeAddress = NULL;
  DriverContext->RingBuffer.IsInitialized = TRUE;

  // Initialize indices to start after header
  DriverContext->RingBuffer.ProducerIndex = (ULONG)RING_BUFFER_DATA_OFFSET;
  DriverContext->RingBuffer.ConsumerIndex = (ULONG)RING_BUFFER_DATA_OFFSET;

  // Initialize statistics
  DriverContext->RingBuffer.TotalPacketsWritten = 0;
  DriverContext->RingBuffer.TotalPacketsRead = 0;
  DriverContext->RingBuffer.PacketsDroppedOverflow = 0;

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 4: Ring Buffer Entry Allocation
//=============================================================================

/**
 * AllocateRingBufferEntry
 *
 * Producer-side function to reserve space for a new entry.
 * Uses atomic CAS loop to advance tail pointer.
 *
 * @param DriverContext - Pointer to driver context
 * @param PacketDataSize - Size of packet data to store
 * @return Pointer to entry or NULL if buffer full
 *
 * IRQL: <= DISPATCH_LEVEL
 */
PRING_BUFFER_ENTRY AllocateRingBufferEntry(PDRIVER_CONTEXT DriverContext,
                                           ULONG PacketDataSize) {
  ULONG currentTail, currentHead, newTail;
  ULONG entrySize, alignedSize;
  PRING_BUFFER_ENTRY entry;
  ULONG usableEnd;

  if (DriverContext == NULL || !DriverContext->RingBuffer.IsInitialized) {
    return NULL;
  }

  if (PacketDataSize > RING_BUFFER_MAX_ENTRY_SIZE) {
    return NULL;
  }

  // Calculate total entry size (header + data, aligned to 64 bytes)
  entrySize = sizeof(RING_BUFFER_ENTRY) + PacketDataSize;
  alignedSize = (entrySize + RING_BUFFER_ENTRY_ALIGNMENT - 1) &
                ~(RING_BUFFER_ENTRY_ALIGNMENT - 1);

  // Usable end of buffer (leave space for wrap handling)
  usableEnd =
      (ULONG)(DriverContext->RingBuffer.TotalSize - RING_BUFFER_WRAP_THRESHOLD);

  // CAS loop to atomically reserve space
  do {
    // Read current pointers
    currentTail = InterlockedCompareExchange(
        (LONG *)&DriverContext->RingBuffer.ProducerIndex, 0, 0);
    currentHead = InterlockedCompareExchange(
        (LONG *)&DriverContext->RingBuffer.ConsumerIndex, 0, 0);

    // Check if we need to wrap
    if (currentTail + alignedSize > usableEnd) {
      HandleRingBufferWrapInternal(DriverContext, currentTail);
      continue;
    }

    newTail = currentTail + alignedSize;

    // Check for buffer full condition
    if (newTail > currentHead && currentTail < currentHead) {
      InterlockedIncrement64(
          (LONG64 *)&DriverContext->RingBuffer.PacketsDroppedOverflow);
      return NULL;
    }

    // Handle wrapped case - tail ahead of head
    if (currentTail >= currentHead) {
      ULONG usedSpace = currentTail - currentHead;
      if (usedSpace + alignedSize > (ULONG)DriverContext->RingBuffer.TotalSize -
                                        RING_BUFFER_DATA_OFFSET) {
        InterlockedIncrement64(
            (LONG64 *)&DriverContext->RingBuffer.PacketsDroppedOverflow);
        return NULL;
      }
    }

  } while (InterlockedCompareExchange(
               (LONG *)&DriverContext->RingBuffer.ProducerIndex, newTail,
               currentTail) != (LONG)currentTail);

  // Successfully reserved space - get pointer to entry
  entry = (PRING_BUFFER_ENTRY)((PUCHAR)DriverContext->RingBuffer.BaseAddress +
                               currentTail);

  // Mark entry as in-progress
  entry->Status = ENTRY_STATUS_IN_PROGRESS;
  entry->DataSize = PacketDataSize;
  entry->TotalSize = alignedSize;

  return entry;
}

//=============================================================================
// SECTION 5: Ring Buffer Entry Commit
//=============================================================================

/**
 * CommitRingBufferEntry
 *
 * Producer commits entry after filling packet data.
 *
 * @param DriverContext - Pointer to driver context
 * @param Entry - Entry to commit
 * @param PacketDataSize - Size of packet data written
 *
 * IRQL: <= DISPATCH_LEVEL
 */
VOID CommitRingBufferEntry(PDRIVER_CONTEXT DriverContext,
                           PRING_BUFFER_ENTRY Entry, ULONG PacketDataSize) {
  LARGE_INTEGER timestamp;

  if (DriverContext == NULL || Entry == NULL) {
    return;
  }

  // Fill entry metadata
  timestamp = KeQueryPerformanceCounter(NULL);
  Entry->Timestamp = timestamp;
  Entry->DataSize = PacketDataSize;
  Entry->SequenceNumber = (ULONG)InterlockedIncrement64(
      (LONG64 *)&DriverContext->RingBuffer.TotalPacketsWritten);

  // Memory barrier to ensure all data writes are visible
  KeMemoryBarrier();

  // Atomically set status to READY
  InterlockedExchange((LONG *)&Entry->Status, ENTRY_STATUS_READY);
}

//=============================================================================
// SECTION 6: Ring Buffer Entry Read
//=============================================================================

/**
 * GetNextRingBufferEntry
 *
 * Consumer-side function to read next available entry.
 *
 * @param DriverContext - Pointer to driver context
 * @return Pointer to entry or NULL if empty
 *
 * IRQL: <= DISPATCH_LEVEL
 */
PRING_BUFFER_ENTRY GetNextRingBufferEntry(PDRIVER_CONTEXT DriverContext) {
  ULONG currentHead, currentTail;
  PRING_BUFFER_ENTRY entry;
  LONG status;

  if (DriverContext == NULL || !DriverContext->RingBuffer.IsInitialized) {
    return NULL;
  }

  // Atomically read head and tail
  currentHead = InterlockedCompareExchange(
      (LONG *)&DriverContext->RingBuffer.ConsumerIndex, 0, 0);
  currentTail = InterlockedCompareExchange(
      (LONG *)&DriverContext->RingBuffer.ProducerIndex, 0, 0);

  // Check if buffer is empty
  if (currentHead == currentTail) {
    return NULL;
  }

  // Get entry at head position
  entry = (PRING_BUFFER_ENTRY)((PUCHAR)DriverContext->RingBuffer.BaseAddress +
                               currentHead);

  // Check for wrap marker
  if (entry->Status == ENTRY_STATUS_WRAP_MARKER) {
    // Reset head to start of data area
    InterlockedExchange((LONG *)&DriverContext->RingBuffer.ConsumerIndex,
                        (LONG)RING_BUFFER_DATA_OFFSET);
    return GetNextRingBufferEntry(DriverContext);
  }

  // Read status with acquire semantics
  status = InterlockedCompareExchange((LONG *)&entry->Status,
                                      ENTRY_STATUS_READY, ENTRY_STATUS_READY);

  if (status != ENTRY_STATUS_READY) {
    return NULL;
  }

  return entry;
}

//=============================================================================
// SECTION 7: Ring Buffer Entry Consume
//=============================================================================

/**
 * ConsumeRingBufferEntry
 *
 * Consumer advances head pointer after processing entry.
 *
 * @param DriverContext - Pointer to driver context
 * @param EntrySize - Size of entry to consume
 *
 * IRQL: <= DISPATCH_LEVEL
 */
VOID ConsumeRingBufferEntry(PDRIVER_CONTEXT DriverContext, ULONG EntrySize) {
  ULONG currentHead;
  PRING_BUFFER_ENTRY entry;
  ULONG alignedSize;

  if (DriverContext == NULL || !DriverContext->RingBuffer.IsInitialized) {
    return;
  }

  currentHead = InterlockedCompareExchange(
      (LONG *)&DriverContext->RingBuffer.ConsumerIndex, 0, 0);

  // Mark entry as consumed
  entry = (PRING_BUFFER_ENTRY)((PUCHAR)DriverContext->RingBuffer.BaseAddress +
                               currentHead);
  entry->Status = ENTRY_STATUS_CONSUMED;

  // Advance head pointer by aligned entry size
  alignedSize = (EntrySize + RING_BUFFER_ENTRY_ALIGNMENT - 1) &
                ~(RING_BUFFER_ENTRY_ALIGNMENT - 1);

  InterlockedExchangeAdd((LONG *)&DriverContext->RingBuffer.ConsumerIndex,
                         alignedSize);

  // Update statistics
  InterlockedIncrement64((LONG64 *)&DriverContext->RingBuffer.TotalPacketsRead);
}

//=============================================================================
// SECTION 8: Ring Buffer Query Functions
//=============================================================================

/**
 * RingBufferGetFillPercentage
 *
 * Returns current buffer utilization (0-100%).
 *
 * @param RingBuffer - Pointer to ring buffer structure
 * @return Fill percentage
 *
 * IRQL: <= DISPATCH_LEVEL
 */
ULONG RingBufferGetFillPercentage(PSAFEOPS_RING_BUFFER_CONTEXT RingBuffer) {
  ULONG head, tail;
  ULONG64 usedBytes;
  ULONG64 usableSize;

  if (RingBuffer == NULL || !RingBuffer->IsInitialized) {
    return 0;
  }

  // Atomically read pointers
  head = InterlockedCompareExchange((LONG *)&RingBuffer->ConsumerIndex, 0, 0);
  tail = InterlockedCompareExchange((LONG *)&RingBuffer->ProducerIndex, 0, 0);

  // Calculate used space
  if (tail >= head) {
    usedBytes = tail - head;
  } else {
    usedBytes =
        (RingBuffer->TotalSize - head) + (tail - RING_BUFFER_DATA_OFFSET);
  }

  // Calculate usable buffer size (excluding header)
  usableSize = RingBuffer->TotalSize - RING_BUFFER_DATA_OFFSET;

  if (usableSize == 0)
    return 0;

  ULONG64 percent = (usedBytes * 100) / usableSize;
  return (ULONG)(percent > 100 ? 100 : percent);
}

//=============================================================================
// SECTION 9: Ring Buffer Wraparound
//=============================================================================

/**
 * HandleRingBufferWrapInternal
 *
 * Internal function to handle buffer wraparound.
 *
 * @param DriverContext - Pointer to driver context
 * @param CurrentTail - Current tail position
 */
static VOID HandleRingBufferWrapInternal(PDRIVER_CONTEXT DriverContext,
                                         ULONG CurrentTail) {
  PRING_BUFFER_ENTRY wrapEntry;
  ULONG expectedTail;

  if (DriverContext == NULL)
    return;

  // Write wrap marker at current position
  wrapEntry =
      (PRING_BUFFER_ENTRY)((PUCHAR)DriverContext->RingBuffer.BaseAddress +
                           CurrentTail);
  wrapEntry->Status = ENTRY_STATUS_WRAP_MARKER;
  wrapEntry->DataSize = 0;
  wrapEntry->TotalSize = 0;

  // Memory barrier
  KeMemoryBarrier();

  // Atomically reset tail to start of data area
  expectedTail = CurrentTail;
  InterlockedCompareExchange((LONG *)&DriverContext->RingBuffer.ProducerIndex,
                             (LONG)RING_BUFFER_DATA_OFFSET, expectedTail);
}

/**
 * HandleRingBufferWrap - Public wrapper
 */
VOID HandleRingBufferWrap(PDRIVER_CONTEXT DriverContext, ULONG64 CurrentTail) {
  HandleRingBufferWrapInternal(DriverContext, (ULONG)CurrentTail);
}

//=============================================================================
// SECTION 10: Userspace Mapping
//=============================================================================

/**
 * MapRingBufferToUserspace
 *
 * Maps ring buffer into userspace address space.
 *
 * @param DriverContext - Pointer to driver context
 * @param UserVirtualAddress - Output userspace address
 * @return NTSTATUS
 *
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS MapRingBufferToUserspace(PDRIVER_CONTEXT DriverContext,
                                  PVOID *UserVirtualAddress) {
  PVOID mappedAddress;

  if (DriverContext == NULL || UserVirtualAddress == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!DriverContext->RingBuffer.IsInitialized) {
    return STATUS_DEVICE_NOT_READY;
  }

  if (DriverContext->RingBuffer.UserModeAddress != NULL) {
    *UserVirtualAddress = DriverContext->RingBuffer.UserModeAddress;
    return STATUS_SUCCESS;
  }

  __try {
    mappedAddress =
        MmMapLockedPagesSpecifyCache(DriverContext->RingBuffer.Mdl, UserMode,
                                     MmCached, NULL, FALSE, NormalPagePriority);

    if (mappedAddress == NULL) {
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    DriverContext->RingBuffer.UserModeAddress = mappedAddress;
    *UserVirtualAddress = mappedAddress;

    return STATUS_SUCCESS;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}

/**
 * UnmapRingBufferFromUserspace
 *
 * Unmaps ring buffer from userspace.
 *
 * @param DriverContext - Pointer to driver context
 * @param UserVirtualAddress - Address to unmap
 * @return NTSTATUS
 *
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS UnmapRingBufferFromUserspace(PDRIVER_CONTEXT DriverContext,
                                      PVOID UserVirtualAddress) {
  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (DriverContext->RingBuffer.UserModeAddress == NULL) {
    return STATUS_SUCCESS;
  }

  if (DriverContext->RingBuffer.UserModeAddress != UserVirtualAddress) {
    return STATUS_INVALID_ADDRESS;
  }

  __try {
    MmUnmapLockedPages(DriverContext->RingBuffer.UserModeAddress,
                       DriverContext->RingBuffer.Mdl);
    DriverContext->RingBuffer.UserModeAddress = NULL;
    return STATUS_SUCCESS;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}

//=============================================================================
// SECTION 11: Ring Buffer Cleanup
//=============================================================================

/**
 * CleanupRingBuffer
 *
 * Frees all ring buffer resources.
 *
 * @param DriverContext - Pointer to driver context
 * @return NTSTATUS
 *
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS CleanupRingBuffer(PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!DriverContext->RingBuffer.IsInitialized) {
    return STATUS_SUCCESS;
  }

  // Unmap from userspace if still mapped
  if (DriverContext->RingBuffer.UserModeAddress != NULL) {
    MmUnmapLockedPages(DriverContext->RingBuffer.UserModeAddress,
                       DriverContext->RingBuffer.Mdl);
    DriverContext->RingBuffer.UserModeAddress = NULL;
  }

  // Free MDL
  if (DriverContext->RingBuffer.Mdl != NULL) {
    IoFreeMdl(DriverContext->RingBuffer.Mdl);
    DriverContext->RingBuffer.Mdl = NULL;
  }

  // Free buffer memory
  if (DriverContext->RingBuffer.BaseAddress != NULL) {
    MmFreeContiguousMemory(DriverContext->RingBuffer.BaseAddress);
    DriverContext->RingBuffer.BaseAddress = NULL;
  }

  DriverContext->RingBuffer.IsInitialized = FALSE;

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 12: Ring Buffer Validation
//=============================================================================

/**
 * ValidateRingBufferIntegrity
 *
 * Checks ring buffer for corruption.
 *
 * @param DriverContext - Pointer to driver context
 * @return TRUE if valid, FALSE if corrupted
 *
 * IRQL: <= DISPATCH_LEVEL
 */
BOOLEAN ValidateRingBufferIntegrity(PDRIVER_CONTEXT DriverContext) {
  ULONG head, tail;
  ULONG bufferEnd;

  if (DriverContext == NULL || !DriverContext->RingBuffer.IsInitialized) {
    return FALSE;
  }

  bufferEnd = (ULONG)DriverContext->RingBuffer.TotalSize;

  // Read pointers
  head = InterlockedCompareExchange(
      (LONG *)&DriverContext->RingBuffer.ConsumerIndex, 0, 0);
  tail = InterlockedCompareExchange(
      (LONG *)&DriverContext->RingBuffer.ProducerIndex, 0, 0);

  // Check bounds
  if (head >= bufferEnd || tail >= bufferEnd) {
    return FALSE;
  }

  // Check minimum offset
  if (head < RING_BUFFER_DATA_OFFSET || tail < RING_BUFFER_DATA_OFFSET) {
    return FALSE;
  }

  // Check alignment
  if ((head % RING_BUFFER_ENTRY_ALIGNMENT) != 0 ||
      (tail % RING_BUFFER_ENTRY_ALIGNMENT) != 0) {
    return FALSE;
  }

  return TRUE;
}

//=============================================================================
// SECTION 13: Statistics Helper
//=============================================================================

/**
 * GetRingBufferStatistics
 *
 * Returns ring buffer statistics.
 *
 * @param DriverContext - Pointer to driver context
 * @param OutWritten - Output: entries written
 * @param OutRead - Output: entries read
 * @param OutDropped - Output: entries dropped
 * @return NTSTATUS
 */
NTSTATUS GetRingBufferStatistics(PDRIVER_CONTEXT DriverContext,
                                 PULONG64 OutWritten, PULONG64 OutRead,
                                 PULONG64 OutDropped) {
  if (DriverContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!DriverContext->RingBuffer.IsInitialized) {
    return STATUS_DEVICE_NOT_READY;
  }

  if (OutWritten != NULL) {
    *OutWritten = DriverContext->RingBuffer.TotalPacketsWritten;
  }
  if (OutRead != NULL) {
    *OutRead = DriverContext->RingBuffer.TotalPacketsRead;
  }
  if (OutDropped != NULL) {
    *OutDropped = DriverContext->RingBuffer.PacketsDroppedOverflow;
  }

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 14: Debug Functions
//=============================================================================

#ifdef DBG

/**
 * DbgPrintRingBufferStatus
 *
 * Prints ring buffer status to debug output.
 *
 * @param DriverContext - Pointer to driver context
 */
VOID DbgPrintRingBufferStatus(PDRIVER_CONTEXT DriverContext) {
  if (DriverContext == NULL || !DriverContext->RingBuffer.IsInitialized) {
    DbgPrint("SafeOps: Ring buffer not initialized\n");
    return;
  }

  DbgPrint("SafeOps Ring Buffer Status:\n");
  DbgPrint("  Buffer Size:     %llu MB\n",
           DriverContext->RingBuffer.TotalSize / (1024 * 1024));
  DbgPrint("  Producer Index:  %lu\n", DriverContext->RingBuffer.ProducerIndex);
  DbgPrint("  Consumer Index:  %lu\n", DriverContext->RingBuffer.ConsumerIndex);
  DbgPrint("  Entries Written: %llu\n",
           DriverContext->RingBuffer.TotalPacketsWritten);
  DbgPrint("  Entries Read:    %llu\n",
           DriverContext->RingBuffer.TotalPacketsRead);
  DbgPrint("  Dropped Entries: %llu\n",
           DriverContext->RingBuffer.PacketsDroppedOverflow);
  DbgPrint("  Fill %%:          %lu%%\n",
           RingBufferGetFillPercentage(&DriverContext->RingBuffer));
}

#endif // DBG
