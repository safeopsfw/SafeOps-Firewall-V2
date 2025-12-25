//==============================================================================
// FILE: src/userspace_service/ring_reader.h
//
// SafeOps Ring Buffer Reader - Header File
//
// PURPOSE:
//   Header file for ring buffer reader component
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
//==============================================================================

#ifndef SAFEOPS_RING_READER_H
#define SAFEOPS_RING_READER_H

#include <windows.h>
#include "service_main.h"

//==============================================================================
// PUBLIC FUNCTION PROTOTYPES
//==============================================================================

// Initialization
NTSTATUS RingReader_Initialize(PRING_READER_CONTEXT ctx, HANDLE driver_handle,
                               UINT64 buffer_size);

// Reading operations
BOOL RingReader_ReadNext(PRING_READER_CONTEXT ctx, PPACKET_ENTRY packet);

// Cleanup
VOID RingReader_Cleanup(PRING_READER_CONTEXT ctx);

// Statistics structure
typedef struct _READ_STATISTICS {
    UINT64 packets_read;
    UINT64 bytes_read;
    UINT64 read_errors;
    UINT64 overflows;
    UINT64 avg_latency_us;
} READ_STATISTICS;

#endif // SAFEOPS_RING_READER_H
