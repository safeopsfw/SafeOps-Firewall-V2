/**
 * shared_memory.h - SafeOps Ring Buffer Shared Memory Header
 *
 * Purpose: Defines the interface for the 2GB lock-free ring buffer that serves
 * as the high-speed communication channel between the kernel driver (producer)
 * and userspace service (consumer). Establishes all data structures, atomic
 * operation primitives, and function prototypes for zero-copy packet metadata
 * transfer using circular buffer semantics with concurrent access from multiple
 * CPUs.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 *
 * CRITICAL: This is a lock-free implementation. Cache-line alignment and memory
 * barriers are essential for correctness on multi-CPU systems.
 */

#ifndef SAFEOPS_SHARED_MEMORY_H
#define SAFEOPS_SHARED_MEMORY_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header with global context

#ifdef SAFEOPS_WDK_BUILD
#include <intrin.h> // Intrinsic atomic operations
#include <ntddk.h>  // Kernel memory management (MDL, physical memory)

#endif

// Note: ring_buffer_structs.h and shared_constants.h are included via driver.h
// or can be included directly if needed for PACKET_METADATA_ENTRY

//=============================================================================
// SECTION 2: Ring Buffer Size Constants
//=============================================================================

// Memory allocation parameters
#define RING_BUFFER_TOTAL_SIZE 2147483648ULL // 2GB exactly
#define RING_BUFFER_ENTRY_SIZE 128           // Size of PACKET_METADATA_ENTRY
#define RING_BUFFER_MAX_ENTRIES 16777216     // 2GB / 128 bytes
#define RING_BUFFER_INDEX_MASK 0x00FFFFFF    // 16777215 - wraps at max entries
#define RING_BUFFER_ALIGNMENT 4096     // Page alignment for memory mapping
#define RING_BUFFER_CACHE_LINE_SIZE 64 // CPU cache line size

// Memory layout constants
#define RING_BUFFER_HEADER_SIZE 4096 // One page for control data
#define RING_BUFFER_DATA_OFFSET 4096 // Offset where packet data starts
#define RING_BUFFER_DATA_SIZE (RING_BUFFER_TOTAL_SIZE - RING_BUFFER_HEADER_SIZE)

// Validation constants
#define RING_BUFFER_MAGIC_NUMBER 0x53464F50 // "SFOP" in hex
#define RING_BUFFER_VERSION 1               // Current buffer format version

// Watermark thresholds for flow control
#define RING_BUFFER_HIGH_WATERMARK 90 // 90% full - apply backpressure
#define RING_BUFFER_LOW_WATERMARK 50  // 50% full - resume normal

//=============================================================================
// SECTION 3: Ring Buffer Control Header Structure
//=============================================================================

/**
 * RING_BUFFER_HEADER
 *
 * Control header located at offset 0 of the ring buffer (first 4KB).
 * Structured to prevent false sharing by placing producer and consumer
 * data in separate cache lines.
 *
 * Total Size: 256 bytes (4 cache lines of 64 bytes each)
 */

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

// Cache Line 0: Producer-owned data (offset 0-63)
typedef struct _RING_BUFFER_PRODUCER_LINE {
  volatile ULONG ProducerIndex;        // 4 bytes - Current write position
  ULONG ProducerReserved1;             // 4 bytes - Padding
  ULONG64 TotalPacketsWritten;         // 8 bytes - Lifetime write counter
  ULONG64 PacketsDroppedFull;          // 8 bytes - Dropped due to buffer full
  ULONG64 ProducerWriteErrors;         // 8 bytes - Write operation errors
  LARGE_INTEGER ProducerLastWriteTime; // 8 bytes - Timestamp of last write
  ULONG ProducerCPU;                   // 4 bytes - CPU core handling producer
  UCHAR ProducerPadding[20];           // 20 bytes - Pad to 64 bytes
} RING_BUFFER_PRODUCER_LINE;           // Total: 64 bytes

// Cache Line 1: Consumer-owned data (offset 64-127)
typedef struct _RING_BUFFER_CONSUMER_LINE {
  volatile ULONG ConsumerIndex; // 4 bytes - Current read position
  ULONG ConsumerReserved1;      // 4 bytes - Padding
  ULONG64 TotalPacketsRead;     // 8 bytes - Lifetime read counter
  ULONG64 PacketsReadErrors;    // 8 bytes - Read operation errors
  ULONG64 ConsumerReadStalls;   // 8 bytes - Times consumer found buffer empty
  LARGE_INTEGER ConsumerLastReadTime; // 8 bytes - Timestamp of last read
  ULONG ConsumerProcessId;            // 4 bytes - Userspace process ID
  UCHAR ConsumerPadding[20];          // 20 bytes - Pad to 64 bytes
} RING_BUFFER_CONSUMER_LINE;          // Total: 64 bytes

// Cache Line 2: Shared metadata (offset 128-191)
typedef struct _RING_BUFFER_METADATA_LINE {
  ULONG MagicNumber;             // 4 bytes - 0x53464F50 for validation
  ULONG Version;                 // 4 bytes - Ring buffer format version
  ULONG EntrySize;               // 4 bytes - Size of each entry (128)
  ULONG MaxEntries;              // 4 bytes - Maximum entries (16777216)
  ULONG64 BufferBaseAddress;     // 8 bytes - Virtual address of ring buffer
  ULONG64 BufferPhysicalAddress; // 8 bytes - Physical address (for DMA)
  LARGE_INTEGER CreationTime;    // 8 bytes - Buffer creation timestamp
  BOOLEAN IsInitialized;         // 1 byte - TRUE if buffer ready
  UCHAR SharedPadding[23];       // 23 bytes - Pad to 64 bytes
} RING_BUFFER_METADATA_LINE;     // Total: 64 bytes

// Cache Line 3: Statistics (offset 192-255)
typedef struct _RING_BUFFER_STATS_LINE {
  ULONG64 BytesWritten;   // 8 bytes - Total bytes written
  ULONG64 BytesRead;      // 8 bytes - Total bytes read
  ULONG PeakOccupancy;    // 4 bytes - Maximum occupancy reached
  ULONG CurrentOccupancy; // 4 bytes - Current entries in buffer
  ULONG OverflowCount;    // 4 bytes - Number of overflow events
  UCHAR StatsPadding[36]; // 36 bytes - Pad to 64 bytes
} RING_BUFFER_STATS_LINE; // Total: 64 bytes

// Complete control header structure (256 bytes)
// NOTE: Named RING_BUFFER_CONTROL_HEADER to avoid conflict with driver.h's
// RING_BUFFER_HEADER
typedef struct _RING_BUFFER_CONTROL_HEADER {
  RING_BUFFER_PRODUCER_LINE Producer; // Cache line 0: offset 0-63
  RING_BUFFER_CONSUMER_LINE Consumer; // Cache line 1: offset 64-127
  RING_BUFFER_METADATA_LINE Metadata; // Cache line 2: offset 128-191
  RING_BUFFER_STATS_LINE Stats;       // Cache line 3: offset 192-255
} RING_BUFFER_CONTROL_HEADER, *PRING_BUFFER_CONTROL_HEADER; // Total: 256 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
// SECTION 4: Ring Buffer State Structure
//=============================================================================

/**
 * RING_BUFFER_STATE
 *
 * Kernel-side state tracking for the ring buffer including memory mappings,
 * synchronization primitives, and lifecycle management.
 */
typedef struct _RING_BUFFER_STATE {
  // Memory addresses
  PVOID KernelBaseAddress; // Virtual address in kernel space
  PVOID UserBaseAddress;   // Virtual address in userspace (after mapping)
  PHYSICAL_ADDRESS PhysicalAddress; // Physical memory address

  // Memory management
  PMDL Mdl;         // Memory Descriptor List for userspace mapping
  SIZE_T TotalSize; // Total buffer size (2GB)

  // Structure pointers
  PRING_BUFFER_HEADER Header; // Pointer to control header
  PVOID DataRegion;           // Pointer to data region (offset 4096)

  // Section objects
  HANDLE SectionHandle; // Section object for shared memory
  PVOID SectionObject;  // Kernel section object pointer

  // Synchronization
  KSPIN_LOCK InitializationLock; // Protects initialization/cleanup
  KEVENT BufferNotEmptyEvent;    // Signaled when data available
  KEVENT BufferNotFullEvent;     // Signaled when space available

  // State flags
  BOOLEAN IsUserspaceMapped; // TRUE if mapped to userspace
  BOOLEAN IsInitialized;     // TRUE if allocation succeeded

  // Ownership
  ULONG OwningProcessId; // Process ID with active mapping

} RING_BUFFER_STATE, *PRING_BUFFER_STATE;

//=============================================================================
// SECTION 5: Memory Barrier Macros
//=============================================================================

/**
 * CPU memory fence operations for enforcing memory ordering in lock-free code.
 * Essential for correctness on weakly-ordered architectures.
 */

#ifdef SAFEOPS_WDK_BUILD
// Use real WDK intrinsics
#define MEMORY_BARRIER_FULL()                                                  \
  do {                                                                         \
    _ReadWriteBarrier();                                                       \
    MemoryBarrier();                                                           \
  } while (0)
#define MEMORY_BARRIER_READ() _ReadBarrier()
#define MEMORY_BARRIER_WRITE() _WriteBarrier()
#define MEMORY_BARRIER_ACQUIRE() _ReadBarrier()
#define MEMORY_BARRIER_RELEASE() _WriteBarrier()
#else
// Stub definitions for IDE
#define MEMORY_BARRIER_FULL() ((void)0)
#define MEMORY_BARRIER_READ() ((void)0)
#define MEMORY_BARRIER_WRITE() ((void)0)
#define MEMORY_BARRIER_ACQUIRE() ((void)0)
#define MEMORY_BARRIER_RELEASE() ((void)0)
#endif

//=============================================================================
// SECTION 6: Atomic Operation Wrappers
//=============================================================================

/**
 * Type-safe wrappers around Windows interlocked intrinsics with appropriate
 * memory barriers for lock-free index manipulation.
 */

#ifdef SAFEOPS_WDK_BUILD

__forceinline ULONG AtomicReadIndex(volatile ULONG *Index) {
  ULONG value = *Index;
  MEMORY_BARRIER_ACQUIRE();
  return value;
}

__forceinline VOID AtomicWriteIndex(volatile ULONG *Index, ULONG Value) {
  MEMORY_BARRIER_RELEASE();
  *Index = Value;
}

__forceinline ULONG AtomicIncrementIndex(volatile ULONG *Index) {
  return (InterlockedIncrement((volatile LONG *)Index) &
          RING_BUFFER_INDEX_MASK);
}

__forceinline ULONG AtomicCompareExchangeIndex(volatile ULONG *Index,
                                               ULONG NewValue,
                                               ULONG Comparand) {
  return (ULONG)InterlockedCompareExchange((volatile LONG *)Index,
                                           (LONG)NewValue, (LONG)Comparand);
}

__forceinline ULONG64 AtomicIncrement64(volatile ULONG64 *Value) {
  return InterlockedIncrement64((volatile LONG64 *)Value);
}

__forceinline ULONG AtomicAdd(volatile ULONG *Value, ULONG Addend) {
  return (ULONG)InterlockedAdd((volatile LONG *)Value, (LONG)Addend);
}

#else
// Stub definitions for IDE
static inline ULONG AtomicReadIndex(volatile ULONG *Index) { return *Index; }
static inline void AtomicWriteIndex(volatile ULONG *Index, ULONG Value) {
  *Index = Value;
}
static inline ULONG AtomicIncrementIndex(volatile ULONG *Index) {
  return ++(*Index);
}
static inline ULONG AtomicCompareExchangeIndex(volatile ULONG *Index,
                                               ULONG NewValue,
                                               ULONG Comparand) {
  ULONG old = *Index;
  if (old == Comparand)
    *Index = NewValue;
  return old;
}
static inline ULONG64 AtomicIncrement64(volatile ULONG64 *Value) {
  return ++(*Value);
}
static inline ULONG AtomicAdd(volatile ULONG *Value, ULONG Addend) {
  return (*Value += Addend);
}
#endif

//=============================================================================
// SECTION 7: Ring Buffer Capacity Functions
//=============================================================================

/**
 * Lock-free capacity calculation functions.
 * Reserve 1 slot to distinguish full from empty condition.
 */

__forceinline ULONG RingBufferGetUsedEntries(ULONG ProducerIndex,
                                             ULONG ConsumerIndex) {
  return (ProducerIndex - ConsumerIndex) & RING_BUFFER_INDEX_MASK;
}

__forceinline ULONG RingBufferGetFreeEntries(ULONG ProducerIndex,
                                             ULONG ConsumerIndex) {
  ULONG used = RingBufferGetUsedEntries(ProducerIndex, ConsumerIndex);
  return (RING_BUFFER_MAX_ENTRIES - used - 1); // Reserve 1 slot
}

__forceinline BOOLEAN RingBufferIsFull(ULONG ProducerIndex,
                                       ULONG ConsumerIndex) {
  ULONG used = RingBufferGetUsedEntries(ProducerIndex, ConsumerIndex);
  return (used >= (RING_BUFFER_MAX_ENTRIES - 1));
}

__forceinline BOOLEAN RingBufferIsEmpty(ULONG ProducerIndex,
                                        ULONG ConsumerIndex) {
  return (ProducerIndex == ConsumerIndex);
}

__forceinline ULONG RingBufferGetOccupancyPercent(ULONG ProducerIndex,
                                                  ULONG ConsumerIndex) {
  ULONG used = RingBufferGetUsedEntries(ProducerIndex, ConsumerIndex);
  return (used * 100) / RING_BUFFER_MAX_ENTRIES;
}

//=============================================================================
// SECTION 8: Function Prototypes - Initialization and Cleanup
//=============================================================================

/**
 * Ring buffer lifecycle management functions.
 * All run at IRQL <= DISPATCH_LEVEL unless noted.
 */

// Initialize and allocate 2GB ring buffer
// IRQL: PASSIVE_LEVEL only
NTSTATUS RingBufferInitialize(_Out_ PRING_BUFFER_STATE *OutState);

// Free ring buffer and unmap memory
// IRQL: PASSIVE_LEVEL only
VOID RingBufferCleanup(_In_ PRING_BUFFER_STATE State);

// Create userspace mapping
// IRQL: PASSIVE_LEVEL only
NTSTATUS RingBufferMapToUserspace(_In_ PRING_BUFFER_STATE State,
                                  _In_ HANDLE ProcessHandle,
                                  _Out_ PVOID *OutUserAddress);

// Remove userspace mapping
// IRQL: PASSIVE_LEVEL only
NTSTATUS RingBufferUnmapFromUserspace(_In_ PRING_BUFFER_STATE State,
                                      _In_ HANDLE ProcessHandle);

// Reset indices to zero (clear all data)
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferReset(_In_ PRING_BUFFER_STATE State);

// Verify header magic number and version
// IRQL: <= DISPATCH_LEVEL
BOOLEAN RingBufferValidateHeader(_In_ PRING_BUFFER_HEADER Header);

//=============================================================================
// SECTION 9: Function Prototypes - Producer Operations (Kernel)
//=============================================================================

/**
 * Producer-side API used by kernel driver to enqueue packet metadata.
 * All functions are lock-free for maximum performance.
 */

// Write one entry (returns error if full)
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferWrite(_In_ PRING_BUFFER_STATE State, _In_ PVOID Metadata,
                         _In_ SIZE_T MetadataSize);

// Non-blocking write attempt
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferTryWrite(_In_ PRING_BUFFER_STATE State, _In_ PVOID Metadata,
                            _In_ SIZE_T MetadataSize,
                            _Out_ BOOLEAN *OutSuccess);

// Write multiple entries atomically
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferBatchWrite(_In_ PRING_BUFFER_STATE State,
                              _In_ PVOID *MetadataArray, _In_ ULONG Count,
                              _Out_ PULONG OutWritten);

// Get pointer to next write location
// IRQL: <= DISPATCH_LEVEL
PVOID RingBufferGetWritePointer(_In_ PRING_BUFFER_STATE State,
                                _Out_ ULONG *OutIndex);

// Advance producer index after write
// IRQL: <= DISPATCH_LEVEL
VOID RingBufferCommitWrite(_In_ PRING_BUFFER_STATE State, _In_ ULONG Count);

// Reserve space for batch write
// IRQL: <= DISPATCH_LEVEL
BOOLEAN RingBufferReserveSpace(_In_ PRING_BUFFER_STATE State, _In_ ULONG Count);

//=============================================================================
// SECTION 10: Function Prototypes - Consumer Operations (via IOCTL)
//=============================================================================

/**
 * Consumer-side API called via IOCTL from userspace service.
 * Userspace directly reads via mapped memory but updates index through IOCTL.
 */

// Update consumer index from userspace
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferUpdateConsumerIndex(_In_ PRING_BUFFER_STATE State,
                                       _In_ ULONG NewConsumerIndex);

// Query current ring buffer state
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferGetConsumerInfo(_In_ PRING_BUFFER_STATE State,
                                   _Out_ PULONG OutConsumerIndex,
                                   _Out_ PULONG OutProducerIndex,
                                   _Out_ PULONG OutUsedEntries);

// Calculate read address for given index
// IRQL: <= DISPATCH_LEVEL
PVOID RingBufferGetReadPointer(_In_ PRING_BUFFER_STATE State,
                               _In_ ULONG ConsumerIndex);

// Check if enough data available
// IRQL: <= DISPATCH_LEVEL
BOOLEAN RingBufferCanAdvanceConsumer(_In_ PRING_BUFFER_STATE State,
                                     _In_ ULONG RequestedCount);

//=============================================================================
// SECTION 11: Function Prototypes - Statistics and Monitoring
//=============================================================================

/**
 * Performance monitoring and statistics tracking functions.
 */

// Export statistics structure
// IRQL: <= DISPATCH_LEVEL
NTSTATUS RingBufferGetStatistics(_In_ PRING_BUFFER_STATE State,
                                 _Out_ PVOID OutputBuffer,
                                 _In_ ULONG BufferSize,
                                 _Out_ PULONG BytesWritten);

// Recalculate current occupancy and peak
// IRQL: <= DISPATCH_LEVEL
VOID RingBufferUpdateStatistics(_In_ PRING_BUFFER_STATE State);

// Zero all counters
// IRQL: <= DISPATCH_LEVEL
VOID RingBufferResetStatistics(_In_ PRING_BUFFER_STATE State);

// Get overflow counter
// IRQL: <= DISPATCH_LEVEL
ULONG RingBufferGetDroppedPacketCount(_In_ PRING_BUFFER_STATE State);

//=============================================================================
// SECTION 12: Function Prototypes - Memory Management
//=============================================================================

/**
 * Low-level memory allocation functions for ring buffer.
 * IRQL: PASSIVE_LEVEL only for all memory functions.
 */

// Allocate physically contiguous memory
NTSTATUS
AllocateContiguousPhysicalMemory(_In_ SIZE_T Size,
                                 _Out_ PHYSICAL_ADDRESS *OutPhysicalAddress,
                                 _Out_ PVOID *OutVirtualAddress);

// Free contiguous memory
VOID FreeContiguousPhysicalMemory(_In_ PVOID VirtualAddress, _In_ SIZE_T Size);

// Create MDL for mapping
NTSTATUS CreateMemoryDescriptorList(_In_ PVOID VirtualAddress, _In_ SIZE_T Size,
                                    _Out_ PMDL *OutMdl);

// Free MDL
VOID FreeMemoryDescriptorList(_In_ PMDL Mdl);

//=============================================================================
// SECTION 13: Function Prototypes - Synchronization Primitives
//=============================================================================

/**
 * Event signaling between kernel and userspace for optional blocking semantics.
 */

// Wake userspace consumer
// IRQL: <= DISPATCH_LEVEL
NTSTATUS SignalBufferNotEmpty(_In_ PRING_BUFFER_STATE State);

// Wake kernel producer (if blocked)
// IRQL: <= DISPATCH_LEVEL
NTSTATUS SignalBufferNotFull(_In_ PRING_BUFFER_STATE State);

// Block until space available
// IRQL: PASSIVE_LEVEL only
NTSTATUS WaitForBufferSpace(_In_ PRING_BUFFER_STATE State,
                            _In_opt_ PLARGE_INTEGER Timeout);

// Block until data available
// IRQL: PASSIVE_LEVEL only
NTSTATUS WaitForBufferData(_In_ PRING_BUFFER_STATE State,
                           _In_opt_ PLARGE_INTEGER Timeout);

//=============================================================================
// SECTION 14: Debug and Validation Functions
//=============================================================================

#ifdef DBG

// Dump ring buffer state to debug console
VOID DbgPrintRingBufferState(_In_ PRING_BUFFER_STATE State);

// Check for corruption
BOOLEAN DbgValidateRingBufferIntegrity(_In_ PRING_BUFFER_STATE State);

// Print packet entries
VOID DbgDumpRingBufferEntries(_In_ PRING_BUFFER_STATE State,
                              _In_ ULONG StartIndex, _In_ ULONG Count);

// Fill buffer for testing
VOID DbgSimulateBufferOverflow(_In_ PRING_BUFFER_STATE State);

// Write test metadata
NTSTATUS DbgInjectTestPacket(_In_ PRING_BUFFER_STATE State);

#endif // DBG

//=============================================================================
// SECTION 15: Compile-Time Assertions
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
// Validate structure sizes at compile time
C_ASSERT(sizeof(RING_BUFFER_PRODUCER_LINE) == 64);
C_ASSERT(sizeof(RING_BUFFER_CONSUMER_LINE) == 64);
C_ASSERT(sizeof(RING_BUFFER_METADATA_LINE) == 64);
C_ASSERT(sizeof(RING_BUFFER_STATS_LINE) == 64);
C_ASSERT(sizeof(RING_BUFFER_CONTROL_HEADER) == 256);
C_ASSERT(RING_BUFFER_TOTAL_SIZE == 2147483648ULL);
C_ASSERT((RING_BUFFER_TOTAL_SIZE / RING_BUFFER_ENTRY_SIZE) ==
         RING_BUFFER_MAX_ENTRIES);
#endif

#endif // SAFEOPS_SHARED_MEMORY_H
