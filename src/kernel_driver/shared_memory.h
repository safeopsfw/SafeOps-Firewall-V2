/**
 * shared_memory.h - Shared Memory Ring Buffer Header
 */

#ifndef _SHARED_MEMORY_H_
#define _SHARED_MEMORY_H_

#include "driver.h"

// Ring buffer operations
BOOLEAN
RingBufferWrite(
    _In_ PRING_BUFFER_HEADER Header,
    _In_ PVOID Buffer,
    _In_ const PVOID Data,
    _In_ SIZE_T DataSize
);

BOOLEAN
RingBufferRead(
    _In_ PRING_BUFFER_HEADER Header,
    _In_ PVOID Buffer,
    _Out_ PVOID Data,
    _In_ SIZE_T DataSize
);

ULONG
RingBufferAvailable(
    _In_ PRING_BUFFER_HEADER Header
);

#endif // _SHARED_MEMORY_H_
