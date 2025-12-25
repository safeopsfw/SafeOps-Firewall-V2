/*******************************************************************************
 * FILE: src/userspace_service/service_main.h
 *
 * SafeOps Userspace Service - Main Entry Point Header
 *
 * PURPOSE:
 *   Type definitions and function prototypes for service_main.c
 *
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_SERVICE_MAIN_H_
#define _SAFEOPS_SERVICE_MAIN_H_

//=============================================================================
// IDE Compatibility Stubs (for non-MSVC editors like clang)
//=============================================================================
#if !defined(_MSC_VER) && !defined(__MINGW32__)
// Stub out Windows types for IDE parsing
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned long long UINT64;
typedef unsigned long long SIZE_T;
typedef void *HANDLE;
typedef void *PVOID;
typedef long NTSTATUS;
typedef unsigned char UCHAR;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define WINAPI
#endif

#include <windows.h>
#include <stdint.h>
// Note: userspace_service.h is NOT included here to avoid struct conflicts
// Each .c file includes the headers it needs

//=============================================================================
// TYPE DEFINITIONS
//=============================================================================

// NTSTATUS type for userspace (compatible with kernel)
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

// Basic types
typedef unsigned char UCHAR;
typedef unsigned int UINT;
typedef uint32_t UINT32;
typedef uint64_t UINT64;

// Forward declaration - defined in userspace_service.h
typedef struct _PACKET_METADATA {
  UINT32 magic;
  UINT32 entry_length;
  UINT64 timestamp_qpc;
  UINT64 timestamp_system;
  UINT64 sequence_number;
  // ... other fields omitted for brevity in forward decl
} PACKET_METADATA, *PPACKET_METADATA;

//=============================================================================
// IOCTL CODES (Must match kernel driver ioctl_handler.h)
//=============================================================================

#ifndef IOCTL_GET_DRIVER_VERSION
#define FILE_DEVICE_SAFEOPS 0x8000
#define IOCTL_GET_DRIVER_VERSION                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif

//=============================================================================
// CONTEXT STRUCTURES
//=============================================================================

// Forward declarations - actual definitions in respective .c files
typedef struct _RING_READER_CONTEXT RING_READER_CONTEXT, *PRING_READER_CONTEXT;
typedef struct _LOG_WRITER_CONTEXT LOG_WRITER_CONTEXT, *PLOG_WRITER_CONTEXT;
typedef struct _ROTATION_CONTEXT ROTATION_CONTEXT, *PROTATION_CONTEXT;

// Statistics collector context
typedef struct _STATS_CONTEXT {
  BOOL enabled;
  DWORD interval_ms;
  UINT64 packets_captured;
  UINT64 packets_dropped;
  UINT64 bytes_captured;
} STATS_CONTEXT, *PSTATS_CONTEXT;

// Service configuration
typedef struct _SERVICE_CONFIG {
  UINT64 ring_buffer_size;
  DWORD rotation_interval_ms;
  DWORD stats_interval_ms;
  BOOL enable_stats;
  BOOL json_format;
  char log_directory[MAX_PATH];
} SERVICE_CONFIG, *PSERVICE_CONFIG;

// Packet entry (simplified for log writing)
typedef struct _PACKET_ENTRY {
  PACKET_METADATA metadata;
  UCHAR payload[1]; // Variable length
} PACKET_ENTRY, *PPACKET_ENTRY;

//=============================================================================
// FUNCTION PROTOTYPES - Ring Reader
//=============================================================================

NTSTATUS RingReader_Initialize(PRING_READER_CONTEXT ctx, HANDLE driver_handle,
                               UINT64 buffer_size);

BOOL RingReader_ReadNext(PRING_READER_CONTEXT ctx, PPACKET_ENTRY packet);

VOID RingReader_Cleanup(PRING_READER_CONTEXT ctx);

//=============================================================================
// FUNCTION PROTOTYPES - Log Writer
//=============================================================================

BOOL LogWriter_Initialize(PLOG_WRITER_CONTEXT ctx, const char *log_directory,
                          BOOL json_format);

BOOL LogWriter_WritePacket(PLOG_WRITER_CONTEXT ctx, PPACKET_ENTRY packet);

VOID LogWriter_Flush(PLOG_WRITER_CONTEXT ctx);

VOID LogWriter_Cleanup(PLOG_WRITER_CONTEXT ctx);

//=============================================================================
// FUNCTION PROTOTYPES - Rotation Manager
//=============================================================================

BOOL RotationManager_Initialize(PROTATION_CONTEXT ctx,
                                PLOG_WRITER_CONTEXT log_writer,
                                DWORD interval_ms);

BOOL RotationManager_Rotate(PROTATION_CONTEXT ctx);

VOID RotationManager_Cleanup(PROTATION_CONTEXT ctx);

#endif // _SAFEOPS_SERVICE_MAIN_H_
