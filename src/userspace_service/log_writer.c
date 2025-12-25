//==============================================================================
// FILE: src/userspace_service/log_writer.c
//
// SafeOps Log Writer - Efficient Packet Logging to Disk
//
// PURPOSE:
//   Writes captured packet metadata to log files in JSON format with buffered
//   I/O, batched writes, and rotation coordination.
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
// DATE: 2024-12-13
//==============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "log_writer.h"
#include "packet_metadata.h"

//==============================================================================
// Section 1: Constants and Definitions
//==============================================================================

// Buffer configuration
#define WRITE_BUFFER_SIZE       (1024 * 1024)  // 1 MB write buffer
#define FLUSH_THRESHOLD_PERCENT 80             // Flush at 80% full
#define FLUSH_INTERVAL_MS       1000           // Flush every 1 second
#define MAX_JSON_LINE_SIZE      4096           // Max size per JSON line

// File configuration
#define LOG_FILE_NAME           "network_packets.log"
#define LOG_DIRECTORY           "C:\\SafeOps\\logs"
#define MAX_PATH_LENGTH         512

// Payload encoding
typedef enum {
    PAYLOAD_ENCODING_NONE = 0,
    PAYLOAD_ENCODING_BASE64 = 1,
    PAYLOAD_ENCODING_HEX = 2
} PAYLOAD_ENCODING;

// Direction strings
static const char* DIRECTION_STRINGS[] = {
    "UNKNOWN",
    "INBOUND",
    "OUTBOUND",
    "NORTH_SOUTH",
    "EAST_WEST"
};

//==============================================================================
// Section 2: Data Structures
//==============================================================================

typedef struct _LOG_WRITER_CONTEXT {
    // File handle
    HANDLE file_handle;
    char log_directory[MAX_PATH_LENGTH];
    char log_path[MAX_PATH_LENGTH];

    // Write buffer
    char* write_buffer;
    UINT32 buffer_size;
    UINT32 buffer_used;

    // Statistics
    UINT64 packets_written;
    UINT64 bytes_written;
    UINT64 flushes_performed;
    UINT64 write_errors;

    // Performance
    LARGE_INTEGER last_flush_time;
    LARGE_INTEGER frequency;

    // Rotation
    BOOL rotation_pending;
    HANDLE rotation_event;

    // State
    BOOL initialized;
    CRITICAL_SECTION lock;

    // Async I/O (optional)
    BOOL async_enabled;
    OVERLAPPED overlapped;
    HANDLE async_event;
} LOG_WRITER_CONTEXT;

typedef struct _WRITE_STATISTICS {
    UINT64 packets_written;
    UINT64 bytes_written;
    UINT64 flushes_performed;
    UINT64 write_errors;
    UINT64 avg_write_latency_ms;
    UINT32 buffer_usage_percent;
    UINT64 disk_space_free_gb;
} WRITE_STATISTICS;

//==============================================================================
// Section 3: Initialization and File Management
//==============================================================================

BOOL LogWriter_Initialize(PLOG_WRITER_CONTEXT ctx, const char* log_directory, BOOL json_format)
{
    if (ctx == NULL || log_directory == NULL) {
        return FALSE;
    }

    memset(ctx, 0, sizeof(LOG_WRITER_CONTEXT));

    // Initialize critical section
    InitializeCriticalSection(&ctx->lock);

    // Store configuration
    strncpy_s(ctx->log_directory, sizeof(ctx->log_directory), log_directory, _TRUNCATE);
    ctx->json_format = json_format;

    // Allocate write buffer
    ctx->write_buffer = (char*)malloc(WRITE_BUFFER_SIZE);
    if (ctx->write_buffer == NULL) {
        DeleteCriticalSection(&ctx->lock);
        return FALSE;
    }

    ctx->buffer_size = WRITE_BUFFER_SIZE;
    ctx->buffer_used = 0;

    // Get performance counter frequency
    QueryPerformanceFrequency(&ctx->frequency);
    QueryPerformanceCounter(&ctx->last_flush_time);

    // Create log directory
    CreateDirectoryA(log_directory, NULL);

    // Build log file path
    sprintf_s(ctx->log_path, sizeof(ctx->log_path), "%s\\%s", log_directory, LOG_FILE_NAME);

    // Open log file
    ctx->file_handle = CreateFileA(
        ctx->log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[LogWriter] ERROR: Failed to open log file: %lu\n", error);
        free(ctx->write_buffer);
        DeleteCriticalSection(&ctx->lock);
        return FALSE;
    }

    ctx->initialized = TRUE;

    printf("[LogWriter] Initialized successfully\n");
    printf("[LogWriter] Log file: %s\n", ctx->log_path);
    printf("[LogWriter] JSON format: %s\n", json_format ? "enabled" : "disabled");
    printf("[LogWriter] Buffer size: %u bytes\n", ctx->buffer_size);

    return TRUE;
}

//==============================================================================
// Section 4: Packet Writing Functions
//==============================================================================

BOOL LogWriter_WritePacket(PLOG_WRITER_CONTEXT ctx, PPACKET_ENTRY packet)
{
    if (ctx == NULL || packet == NULL || !ctx->initialized) {
        return FALSE;
    }

    EnterCriticalSection(&ctx->lock);

    char line_buffer[MAX_JSON_LINE_SIZE];
    int line_len;

    if (ctx->json_format) {
        // Format packet as JSON
        line_len = sprintf_s(line_buffer, sizeof(line_buffer),
            "{\"seq\":%llu,\"ts\":%llu,\"nic\":%u,\"dir\":%u,\"proto\":%u,\"len\":%u}\n",
            packet->metadata.sequence_number,
            packet->metadata.timestamp_system,
            packet->metadata.nic_id,
            packet->metadata.direction,
            packet->metadata.ip_protocol,
            packet->metadata.entry_length
        );
    } else {
        // Simple CSV format
        line_len = sprintf_s(line_buffer, sizeof(line_buffer),
            "%llu,%llu,%u,%u,%u,%u\n",
            packet->metadata.sequence_number,
            packet->metadata.timestamp_system,
            packet->metadata.nic_id,
            packet->metadata.direction,
            packet->metadata.ip_protocol,
            packet->metadata.entry_length
        );
    }

    if (line_len <= 0 || line_len >= (int)sizeof(line_buffer)) {
        ctx->write_errors++;
        LeaveCriticalSection(&ctx->lock);
        return FALSE;
    }

    // Check if buffer has space
    if (ctx->buffer_used + line_len >= ctx->buffer_size) {
        // Flush buffer first
        LogWriter_Flush(ctx);
    }

    // Add to buffer
    memcpy(ctx->write_buffer + ctx->buffer_used, line_buffer, line_len);
    ctx->buffer_used += line_len;

    // Update statistics
    ctx->packets_written++;
    ctx->bytes_written += line_len;

    // Auto-flush if threshold reached
    UINT32 flush_threshold = (ctx->buffer_size * FLUSH_THRESHOLD_PERCENT) / 100;
    if (ctx->buffer_used >= flush_threshold) {
        LogWriter_Flush(ctx);
    }

    LeaveCriticalSection(&ctx->lock);

    return TRUE;
}

//==============================================================================
// Section 5: Buffer Flushing
//==============================================================================

VOID LogWriter_Flush(PLOG_WRITER_CONTEXT ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }

    // Already in critical section from caller

    if (ctx->buffer_used == 0) {
        return;
    }

    // Write buffer to file
    DWORD bytes_written = 0;
    BOOL result = WriteFile(
        ctx->file_handle,
        ctx->write_buffer,
        ctx->buffer_used,
        &bytes_written,
        NULL
    );

    if (!result || bytes_written != ctx->buffer_used) {
        ctx->write_errors++;
        printf("[LogWriter] ERROR: Flush failed (requested %u, written %lu)\n",
               ctx->buffer_used, bytes_written);
    }

    // Reset buffer
    ctx->buffer_used = 0;
    ctx->flushes_performed++;

    // Update timestamp
    QueryPerformanceCounter(&ctx->last_flush_time);
}

//==============================================================================
// Section 6: Cleanup
//==============================================================================

VOID LogWriter_Cleanup(PLOG_WRITER_CONTEXT ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }

    printf("[LogWriter] Cleaning up...\n");

    EnterCriticalSection(&ctx->lock);

    // Final flush
    if (ctx->buffer_used > 0) {
        LogWriter_Flush(ctx);
    }

    // Close file
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
        ctx->file_handle = INVALID_HANDLE_VALUE;
    }

    // Free buffer
    if (ctx->write_buffer != NULL) {
        free(ctx->write_buffer);
        ctx->write_buffer = NULL;
    }

    LeaveCriticalSection(&ctx->lock);

    // Cleanup critical section
    DeleteCriticalSection(&ctx->lock);

    ctx->initialized = FALSE;

    printf("[LogWriter] Cleanup complete\n");
    printf("[LogWriter] Total packets written: %llu\n", ctx->packets_written);
    printf("[LogWriter] Total bytes written: %llu\n", ctx->bytes_written);
    printf("[LogWriter] Total flushes: %llu\n", ctx->flushes_performed);
    printf("[LogWriter] Total errors: %llu\n", ctx->write_errors);
}

//==============================================================================
// END OF FILE
//==============================================================================
