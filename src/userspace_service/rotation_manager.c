//==============================================================================
// FILE: src/userspace_service/rotation_manager.c
//
// SafeOps Rotation Manager - Mandatory 5-Minute Log Rotation
//
// PURPOSE:
//   Manages hardcoded 5-minute (300 second) log rotation cycle. Every rotation:
//   1. Appends network_packets.log to network_packets_ids.log
//   2. Clears network_packets.log
//   3. Every 10 minutes, archives and clears network_packets_ids.log
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

//==============================================================================
// Section 1: Constants and Definitions
//==============================================================================

// Hardcoded rotation interval (MANDATORY - do not change)
#define ROTATION_INTERVAL_MS        300000      // 5 minutes = 300,000 ms
#define ROTATION_INTERVAL_SEC       300         // 5 minutes = 300 seconds
#define IDS_CLEAR_INTERVAL_MS       600000      // 10 minutes = 600,000 ms

// Log file paths
#define PRIMARY_LOG_PATH            "C:\\SafeOps\\logs\\network_packets.log"
#define IDS_LOG_PATH                "C:\\SafeOps\\logs\\network_packets_ids.log"
#define ARCHIVE_DIR                 "C:\\SafeOps\\logs\\archive"

// File operation limits
#define MAX_PATH_LENGTH             512
#define FILE_COPY_BUFFER_SIZE       65536       // 64 KB buffer
#define MIN_FREE_DISK_SPACE_MB      1024        // 1 GB minimum
#define MAX_RETRY_ATTEMPTS          3
#define RETRY_DELAY_MS              1000

//==============================================================================
// Section 2: Data Structures
//==============================================================================

typedef struct _ROTATION_STATISTICS {
    UINT64 rotation_count;
    UINT64 total_bytes_rotated;
    UINT64 last_rotation_time;
    UINT64 avg_rotation_duration_ms;
    UINT32 rotation_failures;
    UINT32 ids_clear_count;
    UINT64 last_ids_clear_time;
} ROTATION_STATISTICS;

typedef struct _ROTATION_MANAGER_CONTEXT {
    // Timer
    HANDLE timer_handle;
    HANDLE timer_queue;
    BOOL timer_active;
    
    // Coordination with log writer
    HANDLE log_writer_ready_event;
    HANDLE rotation_complete_event;
    
    // Statistics
    ROTATION_STATISTICS stats;
    
    // Configuration
    BOOL archive_before_clear;
    BOOL compress_archives;
    
    // State
    BOOL initialized;
    CRITICAL_SECTION lock;
    
    // Error tracking
    DWORD last_error;
    char last_error_msg[256];
} ROTATION_MANAGER_CONTEXT;

//==============================================================================
// Section 3: Forward Declarations
//==============================================================================

// Initialization
BOOL RotationManagerInitialize(ROTATION_MANAGER_CONTEXT* ctx);
VOID RotationManagerShutdown(ROTATION_MANAGER_CONTEXT* ctx);

// Timer management
BOOL StartRotationTimer(ROTATION_MANAGER_CONTEXT* ctx);
VOID CALLBACK RotationTimerCallback(PVOID param, BOOLEAN timer_or_wait_fired);
BOOL StopRotationTimer(ROTATION_MANAGER_CONTEXT* ctx);

// Core rotation
BOOL PerformLogRotation(ROTATION_MANAGER_CONTEXT* ctx);
BOOL AppendFile(const char* source, const char* dest);
BOOL TruncateFile(const char* path);
BOOL VerifyRotationSuccess(ROTATION_MANAGER_CONTEXT* ctx);

// IDS archive management
VOID CheckAndClearIDSArchive(ROTATION_MANAGER_CONTEXT* ctx);
BOOL ArchiveIDSLog(ROTATION_MANAGER_CONTEXT* ctx);
BOOL CompressArchive(const char* source, const char* dest);

// Disk space
UINT64 CheckDiskSpace(const char* path);
BOOL AlertOnLowDiskSpace(UINT64 free_bytes);
BOOL SkipRotationIfLowSpace(ROTATION_MANAGER_CONTEXT* ctx);

// Error handling
VOID HandleRotationFailure(ROTATION_MANAGER_CONTEXT* ctx, const char* error);
BOOL RetryRotation(ROTATION_MANAGER_CONTEXT* ctx, UINT32 attempt);

// Statistics
BOOL GetRotationStatistics(ROTATION_MANAGER_CONTEXT* ctx, ROTATION_STATISTICS* stats);
VOID ReportRotationMetrics(ROTATION_MANAGER_CONTEXT* ctx);

//==============================================================================
// Section 4: Initialization Functions
//==============================================================================

BOOL RotationManagerInitialize(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL) {
        return FALSE;
    }
    
    memset(ctx, 0, sizeof(ROTATION_MANAGER_CONTEXT));
    
    // Initialize critical section
    InitializeCriticalSection(&ctx->lock);
    
    // Create events for coordination
    ctx->log_writer_ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    ctx->rotation_complete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    if (ctx->log_writer_ready_event == NULL || ctx->rotation_complete_event == NULL) {
        DeleteCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    // Set default configuration
    ctx->archive_before_clear = TRUE;
    ctx->compress_archives = TRUE;
    
    // Initialize statistics
    ctx->stats.last_ids_clear_time = GetTickCount64();
    
    // Create archive directory
    CreateDirectoryA(ARCHIVE_DIR, NULL);
    
    // Start rotation timer
    if (!StartRotationTimer(ctx)) {
        CloseHandle(ctx->log_writer_ready_event);
        CloseHandle(ctx->rotation_complete_event);
        DeleteCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    ctx->initialized = TRUE;
    
    printf("[RotationMgr] Initialized successfully\n");
    printf("[RotationMgr] Rotation interval: %d seconds (HARDCODED)\n", ROTATION_INTERVAL_SEC);
    printf("[RotationMgr] IDS clear interval: %d minutes\n", IDS_CLEAR_INTERVAL_MS / 60000);
    
    return TRUE;
}

VOID RotationManagerShutdown(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }
    
    printf("[RotationMgr] Shutting down...\n");
    
    // Stop timer
    StopRotationTimer(ctx);
    
    // Final rotation (optional)
    // PerformLogRotation(ctx);
    
    // Report final statistics
    ReportRotationMetrics(ctx);
    
    // Cleanup
    if (ctx->log_writer_ready_event != NULL) {
        CloseHandle(ctx->log_writer_ready_event);
    }
    
    if (ctx->rotation_complete_event != NULL) {
        CloseHandle(ctx->rotation_complete_event);
    }
    
    DeleteCriticalSection(&ctx->lock);
    
    ctx->initialized = FALSE;
    
    printf("[RotationMgr] Shutdown complete\n");
}

//==============================================================================
// Section 5: Timer Management
//==============================================================================

BOOL StartRotationTimer(ROTATION_MANAGER_CONTEXT* ctx)
{
    // Create timer queue
    ctx->timer_queue = CreateTimerQueue();
    if (ctx->timer_queue == NULL) {
        printf("[RotationMgr] ERROR: Failed to create timer queue\n");
        return FALSE;
    }
    
    // Create timer
    if (!CreateTimerQueueTimer(
        &ctx->timer_handle,
        ctx->timer_queue,
        RotationTimerCallback,
        ctx,
        ROTATION_INTERVAL_MS,    // Initial delay: 5 minutes
        ROTATION_INTERVAL_MS,    // Period: 5 minutes
        WT_EXECUTELONGFUNCTION)) {
        
        DWORD error = GetLastError();
        printf("[RotationMgr] ERROR: Failed to create timer: %lu\n", error);
        DeleteTimerQueue(ctx->timer_queue);
        return FALSE;
    }
    
    ctx->timer_active = TRUE;
    
    printf("[RotationMgr] Rotation timer started (5-minute interval)\n");
    
    return TRUE;
}

VOID CALLBACK RotationTimerCallback(PVOID param, BOOLEAN timer_or_wait_fired)
{
    UNREFERENCED_PARAMETER(timer_or_wait_fired);
    
    ROTATION_MANAGER_CONTEXT* ctx = (ROTATION_MANAGER_CONTEXT*)param;
    
    if (ctx == NULL || !ctx->initialized) {
        return;
    }
    
    printf("\n[RotationMgr] ⏰ 5-minute timer triggered - Starting rotation...\n");
    
    LARGE_INTEGER start_time;
    QueryPerformanceCounter(&start_time);
    
    // Perform log rotation
    BOOL success = PerformLogRotation(ctx);
    
    LARGE_INTEGER end_time, frequency;
    QueryPerformanceCounter(&end_time);
    QueryPerformanceFrequency(&frequency);
    
    UINT64 duration_ms = ((end_time.QuadPart - start_time.QuadPart) * 1000) / frequency.QuadPart;
    
    if (success) {
        printf("[RotationMgr] ✓ Rotation completed in %llu ms\n", duration_ms);
        
        // Update statistics
        ctx->stats.avg_rotation_duration_ms = 
            (ctx->stats.avg_rotation_duration_ms + duration_ms) / 2;
    } else {
        printf("[RotationMgr] ✗ Rotation failed after %llu ms\n", duration_ms);
    }
    
    // Check if IDS archive needs clearing (every 10 minutes)
    CheckAndClearIDSArchive(ctx);
}

BOOL StopRotationTimer(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx->timer_handle != NULL) {
        DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer_handle, INVALID_HANDLE_VALUE);
        ctx->timer_handle = NULL;
    }
    
    if (ctx->timer_queue != NULL) {
        DeleteTimerQueue(ctx->timer_queue);
        ctx->timer_queue = NULL;
    }
    
    ctx->timer_active = FALSE;
    
    printf("[RotationMgr] Timer stopped\n");
    
    return TRUE;
}

//==============================================================================
// Section 6: Core Rotation Logic
//==============================================================================

BOOL PerformLogRotation(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return FALSE;
    }
    
    EnterCriticalSection(&ctx->lock);
    
    printf("[RotationMgr] Step 1: Checking disk space...\n");
    
    // Check disk space
    if (!SkipRotationIfLowSpace(ctx)) {
        LeaveCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    printf("[RotationMgr] Step 2: Signaling log writer to flush and close...\n");
    
    // TODO: Signal log writer to flush and close
    // For now, just wait a bit to simulate coordination
    Sleep(100);
    
    printf("[RotationMgr] Step 3: Appending primary log to IDS log...\n");
    
    // Append primary log to IDS log
    if (!AppendFile(PRIMARY_LOG_PATH, IDS_LOG_PATH)) {
        HandleRotationFailure(ctx, "Failed to append to IDS log");
        LeaveCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    printf("[RotationMgr] Step 4: Clearing primary log...\n");
    
    // Clear primary log
    if (!TruncateFile(PRIMARY_LOG_PATH)) {
        HandleRotationFailure(ctx, "Failed to clear primary log");
        LeaveCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    printf("[RotationMgr] Step 5: Signaling log writer to reopen...\n");
    
    // TODO: Signal log writer to reopen
    SetEvent(ctx->log_writer_ready_event);
    
    printf("[RotationMgr] Step 6: Updating statistics...\n");
    
    // Update statistics
    ctx->stats.rotation_count++;
    ctx->stats.last_rotation_time = GetTickCount64();
    
    LeaveCriticalSection(&ctx->lock);
    
    printf("[RotationMgr] ✓ Rotation #%llu completed successfully\n", 
           ctx->stats.rotation_count);
    
    return TRUE;
}

BOOL AppendFile(const char* source, const char* dest)
{
    HANDLE src_handle = INVALID_HANDLE_VALUE;
    HANDLE dst_handle = INVALID_HANDLE_VALUE;
    BOOL success = FALSE;
    
    // Open source file for reading
    src_handle = CreateFileA(
        source,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (src_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            // Source doesn't exist yet - this is OK
            return TRUE;
        }
        printf("[RotationMgr] ERROR: Cannot open source file: %lu\n", error);
        return FALSE;
    }
    
    // Get source file size
    LARGE_INTEGER src_size;
    if (!GetFileSizeEx(src_handle, &src_size)) {
        printf("[RotationMgr] ERROR: Cannot get source file size\n");
        CloseHandle(src_handle);
        return FALSE;
    }
    
    // If source is empty, no need to append
    if (src_size.QuadPart == 0) {
        CloseHandle(src_handle);
        return TRUE;
    }
    
    // Open destination file for appending
    dst_handle = CreateFileA(
        dest,
        FILE_APPEND_DATA,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (dst_handle == INVALID_HANDLE_VALUE) {
        printf("[RotationMgr] ERROR: Cannot open destination file: %lu\n", GetLastError());
        CloseHandle(src_handle);
        return FALSE;
    }
    
    // Copy data
    char* buffer = (char*)malloc(FILE_COPY_BUFFER_SIZE);
    if (buffer == NULL) {
        CloseHandle(src_handle);
        CloseHandle(dst_handle);
        return FALSE;
    }
    
    DWORD bytes_read, bytes_written;
    UINT64 total_copied = 0;
    
    while (ReadFile(src_handle, buffer, FILE_COPY_BUFFER_SIZE, &bytes_read, NULL) && 
           bytes_read > 0) {
        
        if (!WriteFile(dst_handle, buffer, bytes_read, &bytes_written, NULL)) {
            printf("[RotationMgr] ERROR: Write failed\n");
            break;
        }
        
        total_copied += bytes_written;
    }
    
    free(buffer);
    CloseHandle(src_handle);
    CloseHandle(dst_handle);
    
    // Verify copied size matches
    success = (total_copied == (UINT64)src_size.QuadPart);
    
    if (success) {
        printf("[RotationMgr]   Appended %llu bytes to IDS log\n", total_copied);
    } else {
        printf("[RotationMgr] ERROR: Size mismatch (expected %llu, got %llu)\n",
               (UINT64)src_size.QuadPart, total_copied);
    }
    
    return success;
}

BOOL TruncateFile(const char* path)
{
    // Open file with truncate flag
    HANDLE handle = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,  // This truncates the file
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            // File doesn't exist - create it
            return TRUE;
        }
        printf("[RotationMgr] ERROR: Cannot truncate file: %lu\n", error);
        return FALSE;
    }
    
    CloseHandle(handle);
    
    printf("[RotationMgr]   Truncated %s to 0 bytes\n", path);
    
    return TRUE;
}

BOOL VerifyRotationSuccess(ROTATION_MANAGER_CONTEXT* ctx)
{
    // Check that primary log is empty
    HANDLE handle = CreateFileA(
        PRIMARY_LOG_PATH,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        return TRUE;  // File doesn't exist - that's OK
    }
    
    LARGE_INTEGER size;
    GetFileSizeEx(handle, &size);
    CloseHandle(handle);
    
    if (size.QuadPart > 0) {
        printf("[RotationMgr] WARNING: Primary log not empty after rotation (%lld bytes)\n",
               size.QuadPart);
        return FALSE;
    }
    
    return TRUE;
}

// Continue in Part 2...
//==============================================================================
// CONTINUATION: Section 7-11 (IDS Archive, Disk Space, Error Handling, Stats)
//==============================================================================

//==============================================================================
// Section 7: IDS Archive Management
//==============================================================================

VOID CheckAndClearIDSArchive(ROTATION_MANAGER_CONTEXT* ctx)
{
    UINT64 now = GetTickCount64();
    UINT64 elapsed_ms = now - ctx->stats.last_ids_clear_time;
    
    // Clear IDS log every 10 minutes (600,000 ms)
    if (elapsed_ms >= IDS_CLEAR_INTERVAL_MS) {
        printf("\n[RotationMgr] ⏰ 10 minutes elapsed - Clearing IDS archive...\n");
        
        // Archive before clearing (if enabled)
        if (ctx->archive_before_clear) {
            if (!ArchiveIDSLog(ctx)) {
                printf("[RotationMgr] WARNING: Failed to archive IDS log\n");
            }
        }
        
        // Clear IDS log
        if (TruncateFile(IDS_LOG_PATH)) {
            ctx->stats.ids_clear_count++;
            ctx->stats.last_ids_clear_time = now;
            printf("[RotationMgr] ✓ IDS archive cleared (count: %u)\n", 
                   ctx->stats.ids_clear_count);
        } else {
            printf("[RotationMgr] ERROR: Failed to clear IDS archive\n");
        }
    }
}

BOOL ArchiveIDSLog(ROTATION_MANAGER_CONTEXT* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    
    // Get current timestamp
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_s(&tm_info, &now);
    
    // Create archive filename
    char archive_name[MAX_PATH_LENGTH];
    sprintf_s(archive_name, sizeof(archive_name),
             "%s\\network_packets_ids_%04d%02d%02d_%02d%02d%02d.log",
             ARCHIVE_DIR,
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday,
             tm_info.tm_hour,
             tm_info.tm_min,
             tm_info.tm_sec);
    
    printf("[RotationMgr]   Archiving to: %s\n", archive_name);
    
    // Copy IDS log to archive
    if (!CopyFileA(IDS_LOG_PATH, archive_name, FALSE)) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            // IDS log doesn't exist yet - OK
            return TRUE;
        }
        printf("[RotationMgr] ERROR: Failed to copy IDS log: %lu\n", error);
        return FALSE;
    }
    
    // Compress archive (if enabled)
    if (ctx->compress_archives) {
        char compressed_name[MAX_PATH_LENGTH];
        sprintf_s(compressed_name, sizeof(compressed_name), "%s.gz", archive_name);
        
        if (CompressArchive(archive_name, compressed_name)) {
            // Delete uncompressed file
            DeleteFileA(archive_name);
            printf("[RotationMgr]   Compressed archive created\n");
        }
    }
    
    return TRUE;
}

BOOL CompressArchive(const char* source, const char* dest)
{
    // TODO: Implement gzip compression
    // For now, just indicate it would compress
    UNREFERENCED_PARAMETER(source);
    UNREFERENCED_PARAMETER(dest);
    
    printf("[RotationMgr]   (Compression not yet implemented)\n");
    return FALSE;
}

//==============================================================================
// Section 8: Disk Space Management
//==============================================================================

UINT64 CheckDiskSpace(const char* path)
{
    ULARGE_INTEGER free_bytes_available;
    ULARGE_INTEGER total_bytes;
    ULARGE_INTEGER total_free_bytes;
    
    if (!GetDiskFreeSpaceExA(path, &free_bytes_available, &total_bytes, &total_free_bytes)) {
        printf("[RotationMgr] WARNING: Cannot check disk space: %lu\n", GetLastError());
        return 0;
    }
    
    return free_bytes_available.QuadPart;
}

BOOL AlertOnLowDiskSpace(UINT64 free_bytes)
{
    UINT64 free_mb = free_bytes / (1024 * 1024);
    
    if (free_mb < MIN_FREE_DISK_SPACE_MB) {
        printf("[RotationMgr] ⚠️  WARNING: Low disk space! Only %llu MB free\n", free_mb);
        return TRUE;
    }
    
    return FALSE;
}

BOOL SkipRotationIfLowSpace(ROTATION_MANAGER_CONTEXT* ctx)
{
    UINT64 free_bytes = CheckDiskSpace(PRIMARY_LOG_PATH);
    
    if (free_bytes == 0) {
        // Cannot determine disk space - proceed with caution
        return TRUE;
    }
    
    UINT64 free_mb = free_bytes / (1024 * 1024);
    
    if (free_mb < MIN_FREE_DISK_SPACE_MB) {
        printf("[RotationMgr] ✗ SKIPPING ROTATION: Insufficient disk space (%llu MB free)\n",
               free_mb);
        
        strcpy_s(ctx->last_error_msg, sizeof(ctx->last_error_msg),
                "Insufficient disk space");
        ctx->last_error = ERROR_DISK_FULL;
        
        return FALSE;
    }
    
    printf("[RotationMgr]   Disk space OK: %llu MB free\n", free_mb);
    
    return TRUE;
}

//==============================================================================
// Section 9: Error Handling and Recovery
//==============================================================================

VOID HandleRotationFailure(ROTATION_MANAGER_CONTEXT* ctx, const char* error)
{
    printf("[RotationMgr] ✗ ROTATION FAILED: %s\n", error);
    
    // Record error
    strcpy_s(ctx->last_error_msg, sizeof(ctx->last_error_msg), error);
    ctx->last_error = GetLastError();
    ctx->stats.rotation_failures++;
    
    // Attempt retry
    for (UINT32 attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
        printf("[RotationMgr] Retry attempt %u of %u...\n", attempt, MAX_RETRY_ATTEMPTS);
        
        Sleep(RETRY_DELAY_MS);
        
        if (RetryRotation(ctx, attempt)) {
            printf("[RotationMgr] ✓ Retry successful\n");
            return;
        }
    }
    
    printf("[RotationMgr] ✗ All retry attempts failed\n");
}

BOOL RetryRotation(ROTATION_MANAGER_CONTEXT* ctx, UINT32 attempt)
{
    UNREFERENCED_PARAMETER(attempt);
    
    // Simple retry - just try rotation again
    return PerformLogRotation(ctx);
}

//==============================================================================
// Section 10: Statistics and Reporting
//==============================================================================

BOOL GetRotationStatistics(ROTATION_MANAGER_CONTEXT* ctx, ROTATION_STATISTICS* stats)
{
    if (ctx == NULL || stats == NULL) {
        return FALSE;
    }
    
    EnterCriticalSection(&ctx->lock);
    
    memcpy(stats, &ctx->stats, sizeof(ROTATION_STATISTICS));
    
    LeaveCriticalSection(&ctx->lock);
    
    return TRUE;
}

VOID ReportRotationMetrics(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    printf("\n[RotationMgr] ============ Rotation Statistics ============\n");
    printf("[RotationMgr] Total rotations:      %llu\n", ctx->stats.rotation_count);
    printf("[RotationMgr] Total bytes rotated:  %llu (%.2f MB)\n",
           ctx->stats.total_bytes_rotated,
           ctx->stats.total_bytes_rotated / (1024.0 * 1024.0));
    printf("[RotationMgr] Rotation failures:    %u\n", ctx->stats.rotation_failures);
    printf("[RotationMgr] IDS clears:           %u\n", ctx->stats.ids_clear_count);
    printf("[RotationMgr] Avg rotation time:    %llu ms\n", 
           ctx->stats.avg_rotation_duration_ms);
    
    if (ctx->stats.last_rotation_time > 0) {
        UINT64 now = GetTickCount64();
        UINT64 since_last = (now - ctx->stats.last_rotation_time) / 1000;
        printf("[RotationMgr] Last rotation:        %llu seconds ago\n", since_last);
    }
    
    // Disk space
    UINT64 free_bytes = CheckDiskSpace(PRIMARY_LOG_PATH);
    UINT64 free_gb = free_bytes / (1024 * 1024 * 1024);
    printf("[RotationMgr] Disk space free:      %llu GB\n", free_gb);
    
    printf("[RotationMgr] ============================================\n\n");
}

//==============================================================================
// Section 11: Public API Functions
//==============================================================================

// Manual rotation trigger (for testing or emergency)
BOOL TriggerManualRotation(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return FALSE;
    }
    
    printf("[RotationMgr] Manual rotation triggered\n");
    
    return PerformLogRotation(ctx);
}

// Pause rotation (for maintenance)
BOOL PauseRotation(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return FALSE;
    }
    
    return StopRotationTimer(ctx);
}

// Resume rotation
BOOL ResumeRotation(ROTATION_MANAGER_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return FALSE;
    }
    
    return StartRotationTimer(ctx);
}

//==============================================================================
// END OF FILE
//==============================================================================
