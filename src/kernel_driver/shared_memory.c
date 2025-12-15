/**
 * shared_memory.c - Shared Memory Ring Buffer Implementation
 * 
 * Lock-free ring buffer for efficient kernel-to-userspace communication.
 * 
 * Copyright (c) 2024 SafeOps Project
 */

#include "shared_memory.h"

//=============================================================================
// SharedMemoryInitialize
//=============================================================================

NTSTATUS
SharedMemoryInitialize(
    _In_ PDRIVER_CONTEXT Context
)
{
    PHYSICAL_ADDRESS lowAddress = {0};
    PHYSICAL_ADDRESS highAddress;
    PHYSICAL_ADDRESS boundaryAddress = {0};
    
    SAFEOPS_LOG_INFO("Initializing shared memory");
    
    highAddress.QuadPart = (ULONGLONG)-1;
    
    // Allocate contiguous physical memory for ring buffer
    Context->SharedMemory = MmAllocateContiguousMemory(
        SHARED_BUFFER_SIZE,
        highAddress
    );
    
    if (!Context->SharedMemory) {
        SAFEOPS_LOG_ERROR("Failed to allocate shared memory");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(Context->SharedMemory, SHARED_BUFFER_SIZE);
    
    // Create MDL for mapping to user space
    Context->SharedMemoryMdl = IoAllocateMdl(
        Context->SharedMemory,
        SHARED_BUFFER_SIZE,
        FALSE,
        FALSE,
        NULL
    );
    
    if (!Context->SharedMemoryMdl) {
        SAFEOPS_LOG_ERROR("Failed to allocate MDL");
        MmFreeContiguousMemory(Context->SharedMemory);
        Context->SharedMemory = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    MmBuildMdlForNonPagedPool(Context->SharedMemoryMdl);
    
    // Initialize ring buffer header
    Context->RingBufferHeader = (PRING_BUFFER_HEADER)Context->SharedMemory;
    Context->RingBufferHeader->WriteOffset = 0;
    Context->RingBufferHeader->ReadOffset = 0;
    Context->RingBufferHeader->BufferSize = SHARED_BUFFER_SIZE - sizeof(RING_BUFFER_HEADER);
    Context->RingBufferHeader->DroppedPackets = 0;
    KeInitializeSpinLock(&Context->RingBufferHeader->Lock);
    
    SAFEOPS_LOG_INFO("Shared memory initialized: %u MB", SHARED_BUFFER_SIZE / (1024*1024));
    
    return STATUS_SUCCESS;
}

//=============================================================================
// SharedMemoryCleanup
//=============================================================================

VOID
SharedMemoryCleanup(
    _In_ PDRIVER_CONTEXT Context
)
{
    SAFEOPS_LOG_INFO("Cleaning up shared memory");
    
    if (Context->UserMappedAddress) {
        MmUnmapLockedPages(Context->UserMappedAddress, Context->SharedMemoryMdl);
        Context->UserMappedAddress = NULL;
    }
    
    if (Context->SharedMemoryMdl) {
        IoFreeMdl(Context->SharedMemoryMdl);
        Context->SharedMemoryMdl = NULL;
    }
    
    if (Context->SharedMemory) {
        MmFreeContiguousMemory(Context->SharedMemory);
        Context->SharedMemory = NULL;
    }
    
    SAFEOPS_LOG_INFO("Shared memory cleaned up");
}

//=============================================================================
// SharedMemoryMapToUser
//=============================================================================

NTSTATUS
SharedMemoryMapToUser(
    _In_ PDRIVER_CONTEXT Context,
    _Out_ PVOID* UserAddress
)
{
    __try {
        Context->UserMappedAddress = MmMapLockedPagesSpecifyCache(
            Context->SharedMemoryMdl,
            UserMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority
        );
        
        if (!Context->UserMappedAddress) {
            SAFEOPS_LOG_ERROR("Failed to map memory to user space");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        *UserAddress = Context->UserMappedAddress;
        
        SAFEOPS_LOG_INFO("Shared memory mapped to user space at 0x%p", *UserAddress);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SAFEOPS_LOG_ERROR("Exception mapping memory to user space");
        return STATUS_ACCESS_VIOLATION;
    }
}

//=============================================================================
// LogPacketToRingBuffer
//=============================================================================

NTSTATUS
LogPacketToRingBuffer(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PPACKET_LOG_ENTRY Entry
)
{
    PVOID bufferStart;
    BOOLEAN success;
    
    if (!Context->RingBufferHeader) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    bufferStart = (PUCHAR)Context->SharedMemory + sizeof(RING_BUFFER_HEADER);
    
    success = RingBufferWrite(
        Context->RingBufferHeader,
        bufferStart,
        Entry,
        sizeof(PACKET_LOG_ENTRY)
    );
    
    if (!success) {
        InterlockedIncrement((LONG*)&Context->RingBufferHeader->DroppedPackets);
        return STATUS_BUFFER_OVERFLOW;
    }
    
    return STATUS_SUCCESS;
}

//=============================================================================
// RingBufferWrite - Lock-free ring buffer write
//=============================================================================

BOOLEAN
RingBufferWrite(
    _In_ PRING_BUFFER_HEADER Header,
    _In_ PVOID Buffer,
    _In_ const PVOID Data,
    _In_ SIZE_T DataSize
)
{
    ULONG writeOffset, readOffset, nextWriteOffset;
    ULONG available;
    PUCHAR bufferPtr = (PUCHAR)Buffer;
    
    // Align size to 8 bytes
    SIZE_T alignedSize = (DataSize + 7) & ~7;
    
    if (alignedSize + sizeof(ULONG) > Header->BufferSize) {
        return FALSE;
    }
    
    do {
        writeOffset = Header->WriteOffset;
        readOffset = Header->ReadOffset;
        
        // Calculate available space
        if (writeOffset >= readOffset) {
            available = Header->BufferSize - (writeOffset - readOffset);
        } else {
            available = readOffset - writeOffset;
        }
        
        // Check if enough space
        if (available < alignedSize + sizeof(ULONG)) {
            return FALSE;
        }
        
        nextWriteOffset = (writeOffset + alignedSize + sizeof(ULONG)) % Header->BufferSize;
        
    } while (InterlockedCompareExchange(&Header->WriteOffset, nextWriteOffset, writeOffset) != writeOffset);
    
    // Write size header
    *(ULONG*)(bufferPtr + writeOffset) = (ULONG)DataSize;
    writeOffset = (writeOffset + sizeof(ULONG)) % Header->BufferSize;
    
    // Write data
    if (writeOffset + DataSize <= Header->BufferSize) {
        // Single contiguous write
        RtlCopyMemory(bufferPtr + writeOffset, Data, DataSize);
    } else {
        // Wrap-around write
        ULONG firstChunk = Header->BufferSize - writeOffset;
        RtlCopyMemory(bufferPtr + writeOffset, Data, firstChunk);
        RtlCopyMemory(bufferPtr, (PUCHAR)Data + firstChunk, DataSize - firstChunk);
    }
    
    return TRUE;
}

//=============================================================================
// RingBufferRead - Lock-free ring buffer read
//=============================================================================

BOOLEAN
RingBufferRead(
    _In_ PRING_BUFFER_HEADER Header,
    _In_ PVOID Buffer,
    _Out_ PVOID Data,
    _In_ SIZE_T DataSize
)
{
    ULONG readOffset, writeOffset, nextReadOffset;
    ULONG entrySize;
    PUCHAR bufferPtr = (PUCHAR)Buffer;
    
    do {
        readOffset = Header->ReadOffset;
        writeOffset = Header->WriteOffset;
        
        // Check if buffer is empty
        if (readOffset == writeOffset) {
            return FALSE;
        }
        
        // Read size header
        entrySize = *(ULONG*)(bufferPtr + readOffset);
        
        if (entrySize > DataSize || entrySize > Header->BufferSize) {
            return FALSE;
        }
        
        SIZE_T alignedSize = (entrySize + 7) & ~7;
        nextReadOffset = (readOffset + alignedSize + sizeof(ULONG)) % Header->BufferSize;
        
    } while (InterlockedCompareExchange(&Header->ReadOffset, nextReadOffset, readOffset) != readOffset);
    
    readOffset = (readOffset + sizeof(ULONG)) % Header->BufferSize;
    
    // Read data
    if (readOffset + entrySize <= Header->BufferSize) {
        // Single contiguous read
        RtlCopyMemory(Data, bufferPtr + readOffset, entrySize);
    } else {
        // Wrap-around read
        ULONG firstChunk = Header->BufferSize - readOffset;
        RtlCopyMemory(Data, bufferPtr + readOffset, firstChunk);
        RtlCopyMemory((PUCHAR)Data + firstChunk, bufferPtr, entrySize - firstChunk);
    }
    
    return TRUE;
}

//=============================================================================
// RingBufferAvailable
//=============================================================================

ULONG
RingBufferAvailable(
    _In_ PRING_BUFFER_HEADER Header
)
{
    ULONG writeOffset = Header->WriteOffset;
    ULONG readOffset = Header->ReadOffset;
    
    if (writeOffset >= readOffset) {
        return writeOffset - readOffset;
    } else {
        return Header->BufferSize - (readOffset - writeOffset);
    }
}
