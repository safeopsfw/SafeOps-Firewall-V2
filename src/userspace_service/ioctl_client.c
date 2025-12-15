//==============================================================================
// FILE: src/userspace_service/ioctl_client.c
//
// SafeOps IOCTL Client - Kernel Driver Communication Interface
//
// PURPOSE:
//   Provides interface to communicate with kernel driver via DeviceIoControl.
//   Sends commands (start/stop capture, filters, statistics) and receives
//   responses. Acts as primary control plane between userspace and kernel.
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
// DATE: 2024-12-13
//==============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winioctl.h>

//==============================================================================
// Section 1: Constants and IOCTL Code Definitions
//==============================================================================

// Device path
#define DRIVER_DEVICE_PATH          "\\\\.\\SafeOpsNetCapture"
#define MAX_DEVICE_PATH             512

// IOCTL codes (defined using CTL_CODE macro)
#define FILE_DEVICE_NETWORK         0x00000012

#define IOCTL_NETCAP_START          CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_STOP           CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_STATS      CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_SET_FILTER     CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_FLUSH_BUFFER   CTL_CODE(FILE_DEVICE_NETWORK, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_RING_INFO  CTL_CODE(FILE_DEVICE_NETWORK, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_PAUSE          CTL_CODE(FILE_DEVICE_NETWORK, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_RESUME         CTL_CODE(FILE_DEVICE_NETWORK, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_ADD_FILTER     CTL_CODE(FILE_DEVICE_NETWORK, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_REMOVE_FILTER  CTL_CODE(FILE_DEVICE_NETWORK, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_CLEAR_FILTERS  CTL_CODE(FILE_DEVICE_NETWORK, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_NIC_INFO   CTL_CODE(FILE_DEVICE_NETWORK, 0x80C, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_ENABLE_NIC     CTL_CODE(FILE_DEVICE_NETWORK, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_DISABLE_NIC    CTL_CODE(FILE_DEVICE_NETWORK, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_PING           CTL_CODE(FILE_DEVICE_NETWORK, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_GET_VERSION    CTL_CODE(FILE_DEVICE_NETWORK, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NETCAP_SELF_TEST      CTL_CODE(FILE_DEVICE_NETWORK, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETCAP_MAP_SHARED_MEM CTL_CODE(FILE_DEVICE_NETWORK, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Retry configuration
#define DEFAULT_RETRY_ATTEMPTS      3
#define DEFAULT_RETRY_DELAY_MS      100
#define DEFAULT_IOCTL_TIMEOUT_MS    5000

//==============================================================================
// Section 2: Data Structures
//==============================================================================

// Capture state
typedef enum {
    CAPTURE_STATE_STOPPED,
    CAPTURE_STATE_RUNNING,
    CAPTURE_STATE_PAUSED,
    CAPTURE_STATE_ERROR
} CAPTURE_STATE;

// Filter action
typedef enum {
    FILTER_ACTION_ALLOW,
    FILTER_ACTION_BLOCK,
    FILTER_ACTION_LOG_ONLY
} FILTER_ACTION;

// Capture mode
typedef enum {
    CAPTURE_MODE_NORMAL,
    CAPTURE_MODE_PROMISCUOUS
} CAPTURE_MODE;

// Capture configuration
typedef struct {
    BOOL capture_all_nics;
    BOOL promiscuous_mode;
    UINT32 max_packet_size;
    UINT32 ring_buffer_size_mb;
} CAPTURE_CONFIG;

// Capture config response
typedef struct {
    BOOL success;
    UINT32 error_code;
    char error_message[256];
} CAPTURE_CONFIG_RESPONSE;

// Filter rule
typedef struct {
    UINT32 filter_id;
    FILTER_ACTION action;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8 protocol;
    BOOL bidirectional;
} FILTER_RULE;

// Statistics structures
typedef struct {
    UINT64 packets_captured;
    UINT64 packets_dropped;
    UINT64 bytes_captured;
    UINT64 packets_filtered;
    UINT64 capture_start_time;
    UINT64 capture_duration_ms;
    UINT32 active_nics;
} CAPTURE_STATISTICS;

typedef struct {
    UINT64 write_index;
    UINT64 read_index;
    UINT64 buffer_size;
    UINT32 usage_percent;
    UINT64 overflows;
    UINT64 total_entries_written;
} RING_STATISTICS;

typedef struct {
    UINT32 nic_id;
    WCHAR friendly_name[256];
    UCHAR mac_address[6];
    UINT32 ip_address;
    UINT32 link_speed;
    BOOL is_enabled;
    BOOL is_promiscuous;
} NIC_INFO;

typedef struct {
    UINT32 major;
    UINT32 minor;
    UINT32 build;
    UINT32 revision;
    char version_string[64];
} VERSION_INFO;

typedef struct {
    BOOL ring_test_passed;
    BOOL ndis_test_passed;
    BOOL memory_test_passed;
    BOOL wfp_test_passed;
    char error_details[256];
} SELF_TEST_RESULTS;

// IOCTL statistics
typedef struct {
    UINT64 total_ioctls;
    UINT64 failed_ioctls;
    UINT64 avg_latency_us;
    UINT64 max_latency_us;
    UINT32 active_connections;
} IOCTL_STATISTICS;

// IOCTL client context
typedef struct {
    HANDLE driver_handle;
    BOOL is_connected;
    char device_path[MAX_DEVICE_PATH];
    
    // Statistics
    UINT64 ioctl_count;
    UINT64 ioctl_errors;
    UINT64 total_latency_us;
    UINT64 max_latency_us;
    
    // Configuration
    UINT32 retry_attempts;
    UINT32 retry_delay_ms;
    UINT32 ioctl_timeout_ms;
    
    // Thread safety
    CRITICAL_SECTION lock;
    BOOL initialized;
} IOCTL_CLIENT_CONTEXT;

//==============================================================================
// Section 3: Forward Declarations
//==============================================================================

// Initialization
BOOL IoctlClientInitialize(IOCTL_CLIENT_CONTEXT* ctx, const char* device_path);
VOID IoctlClientShutdown(IOCTL_CLIENT_CONTEXT* ctx);
HANDLE OpenDriverDevice(const char* device_path);
VOID CloseDriverDevice(IOCTL_CLIENT_CONTEXT* ctx);
BOOL VerifyDriverConnectivity(IOCTL_CLIENT_CONTEXT* ctx);

// Core IOCTL operations
BOOL SendIoctl(IOCTL_CLIENT_CONTEXT* ctx, DWORD ioctl_code, 
               PVOID input, DWORD input_size,
               PVOID output, DWORD output_size,
               DWORD* bytes_returned);

// Capture control
BOOL IoctlStartCapture(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_CONFIG* config);
BOOL IoctlStopCapture(IOCTL_CLIENT_CONTEXT* ctx);
BOOL IoctlPauseCapture(IOCTL_CLIENT_CONTEXT* ctx);
BOOL IoctlResumeCapture(IOCTL_CLIENT_CONTEXT* ctx);
BOOL IoctlGetCaptureState(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_STATE* state);

// Filter management
BOOL IoctlAddFilter(IOCTL_CLIENT_CONTEXT* ctx, FILTER_RULE* rule);
BOOL IoctlRemoveFilter(IOCTL_CLIENT_CONTEXT* ctx, UINT32 filter_id);
BOOL IoctlClearFilters(IOCTL_CLIENT_CONTEXT* ctx);
BOOL IoctlSetFilter(IOCTL_CLIENT_CONTEXT* ctx, FILTER_RULE* rule);

// Statistics
BOOL IoctlGetCaptureStats(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_STATISTICS* stats);
BOOL IoctlGetRingStats(IOCTL_CLIENT_CONTEXT* ctx, RING_STATISTICS* stats);
BOOL IoctlResetStatistics(IOCTL_CLIENT_CONTEXT* ctx);

// NIC management
BOOL IoctlEnableNIC(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id);
BOOL IoctlDisableNIC(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id);
BOOL IoctlGetNICInfo(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id, NIC_INFO* info);

// Diagnostics
BOOL IoctlPing(IOCTL_CLIENT_CONTEXT* ctx);
BOOL IoctlGetDriverVersion(IOCTL_CLIENT_CONTEXT* ctx, VERSION_INFO* version);
BOOL IoctlSelfTest(IOCTL_CLIENT_CONTEXT* ctx, SELF_TEST_RESULTS* results);

// Error handling
DWORD GetLastIoctlError(IOCTL_CLIENT_CONTEXT* ctx);
VOID TranslateIoctlError(DWORD error_code, char* error_msg, size_t msg_len);

// Statistics
BOOL GetIoctlStatistics(IOCTL_CLIENT_CONTEXT* ctx, IOCTL_STATISTICS* stats);
VOID LogIoctlPerformance(IOCTL_CLIENT_CONTEXT* ctx);

//==============================================================================
// Section 4: Initialization and Connection
//==============================================================================

BOOL IoctlClientInitialize(IOCTL_CLIENT_CONTEXT* ctx, const char* device_path)
{
    if (ctx == NULL) {
        return FALSE;
    }
    
    memset(ctx, 0, sizeof(IOCTL_CLIENT_CONTEXT));
    
    // Copy device path or use default
    if (device_path != NULL) {
        strncpy_s(ctx->device_path, sizeof(ctx->device_path), device_path, _TRUNCATE);
    } else {
        strncpy_s(ctx->device_path, sizeof(ctx->device_path), DRIVER_DEVICE_PATH, _TRUNCATE);
    }
    
    // Initialize critical section
    InitializeCriticalSection(&ctx->lock);
    
    // Set default configuration
    ctx->retry_attempts = DEFAULT_RETRY_ATTEMPTS;
    ctx->retry_delay_ms = DEFAULT_RETRY_DELAY_MS;
    ctx->ioctl_timeout_ms = DEFAULT_IOCTL_TIMEOUT_MS;
    
    // Open driver device
    ctx->driver_handle = OpenDriverDevice(ctx->device_path);
    if (ctx->driver_handle == INVALID_HANDLE_VALUE) {
        DeleteCriticalSection(&ctx->lock);
        return FALSE;
    }
    
    ctx->is_connected = TRUE;
    
    // Verify connectivity
    if (!VerifyDriverConnectivity(ctx)) {
        printf("[IoctlClient] WARNING: Driver connectivity test failed\n");
    }
    
    ctx->initialized = TRUE;
    
    printf("[IoctlClient] Initialized successfully\n");
    printf("[IoctlClient] Device: %s\n", ctx->device_path);
    
    return TRUE;
}

VOID IoctlClientShutdown(IOCTL_CLIENT_CONTEXT* ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }
    
    printf("[IoctlClient] Shutting down...\n");
    
    // Log final statistics
    LogIoctlPerformance(ctx);
    
    // Close device
    CloseDriverDevice(ctx);
    
    // Cleanup
    DeleteCriticalSection(&ctx->lock);
    
    ctx->initialized = FALSE;
    
    printf("[IoctlClient] Shutdown complete\n");
}

HANDLE OpenDriverDevice(const char* device_path)
{
    HANDLE handle = CreateFileA(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,  // Exclusive access
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[IoctlClient] ERROR: Failed to open driver: %lu\n", error);
        
        if (error == ERROR_FILE_NOT_FOUND) {
            printf("[IoctlClient]   Driver not found - ensure driver is loaded\n");
        } else if (error == ERROR_ACCESS_DENIED) {
            printf("[IoctlClient]   Access denied - run as Administrator\n");
        }
        
        return INVALID_HANDLE_VALUE;
    }
    
    printf("[IoctlClient] Driver device opened: %s\n", device_path);
    
    return handle;
}

VOID CloseDriverDevice(IOCTL_CLIENT_CONTEXT* ctx)
{
    if (ctx->driver_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->driver_handle);
        ctx->driver_handle = INVALID_HANDLE_VALUE;
        ctx->is_connected = FALSE;
        
        printf("[IoctlClient] Driver device closed\n");
    }
}

BOOL VerifyDriverConnectivity(IOCTL_CLIENT_CONTEXT* ctx)
{
    if (!IoctlPing(ctx)) {
        printf("[IoctlClient] Ping failed - driver may not be responding\n");
        return FALSE;
    }
    
    VERSION_INFO version;
    if (IoctlGetDriverVersion(ctx, &version)) {
        printf("[IoctlClient] Driver version: %s\n", version.version_string);
    }
    
    return TRUE;
}

//==============================================================================
// Section 5: Core IOCTL Operations
//==============================================================================

BOOL SendIoctl(
    IOCTL_CLIENT_CONTEXT* ctx,
    DWORD ioctl_code,
    PVOID input,
    DWORD input_size,
    PVOID output,
    DWORD output_size,
    DWORD* bytes_returned
) {
    if (ctx == NULL || !ctx->initialized || !ctx->is_connected) {
        printf("[IoctlClient] ERROR: Not connected to driver\n");
        return FALSE;
    }
    
    EnterCriticalSection(&ctx->lock);
    
    // Measure latency
    LARGE_INTEGER start_time, end_time, frequency;
    QueryPerformanceCounter(&start_time);
    QueryPerformanceFrequency(&frequency);
    
    DWORD local_bytes_returned = 0;
    BOOL result = DeviceIoControl(
        ctx->driver_handle,
        ioctl_code,
        input,
        input_size,
        output,
        output_size,
        &local_bytes_returned,
        NULL
    );
    
    QueryPerformanceCounter(&end_time);
    
    // Calculate latency
    UINT64 latency_us = ((end_time.QuadPart - start_time.QuadPart) * 1000000) / frequency.QuadPart;
    
    if (result) {
        ctx->ioctl_count++;
        ctx->total_latency_us += latency_us;
        
        if (latency_us > ctx->max_latency_us) {
            ctx->max_latency_us = latency_us;
        }
        
        if (bytes_returned != NULL) {
            *bytes_returned = local_bytes_returned;
        }
    } else {
        ctx->ioctl_errors++;
        
        DWORD error = GetLastError();
        char error_msg[256];
        TranslateIoctlError(error, error_msg, sizeof(error_msg));
        
        printf("[IoctlClient] ERROR: IOCTL 0x%08X failed: %s\n", ioctl_code, error_msg);
    }
    
    LeaveCriticalSection(&ctx->lock);
    
    return result;
}

// Continued in Part 2...
//==============================================================================
// CONTINUATION: Sections 6-13 (Capture Control, Filters, Stats, Error Handling)
//==============================================================================

//==============================================================================
// Section 6: Capture Control Functions
//==============================================================================

BOOL IoctlStartCapture(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_CONFIG* config)
{
    if (config == NULL) {
        printf("[IoctlClient] ERROR: NULL config\n");
        return FALSE;
    }
    
    CAPTURE_CONFIG_RESPONSE response;
    DWORD bytes_returned;
    
    printf("[IoctlClient] Starting capture...\n");
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_START,
        config,
        sizeof(CAPTURE_CONFIG),
        &response,
        sizeof(CAPTURE_CONFIG_RESPONSE),
        &bytes_returned
    );
    
    if (result && response.success) {
        printf("[IoctlClient] ✓ Capture started successfully\n");
    } else {
        printf("[IoctlClient] ✗ Capture start failed: %s\n", response.error_message);
    }
    
    return result && response.success;
}

BOOL IoctlStopCapture(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    printf("[IoctlClient] Stopping capture...\n");
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_STOP,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ Capture stopped\n");
    }
    
    return result;
}

BOOL IoctlPauseCapture(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_PAUSE,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
}

BOOL IoctlResumeCapture(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_RESUME,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
}

BOOL IoctlGetCaptureState(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_STATE* state)
{
    if (state == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    // TODO: Implement state query IOCTL
    // For now, return unknown state
    *state = CAPTURE_STATE_STOPPED;
    
    return TRUE;
}

//==============================================================================
// Section 7: Filter Management Functions
//==============================================================================

BOOL IoctlAddFilter(IOCTL_CLIENT_CONTEXT* ctx, FILTER_RULE* rule)
{
    if (rule == NULL) {
        printf("[IoctlClient] ERROR: NULL filter rule\n");
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_ADD_FILTER,
        rule,
        sizeof(FILTER_RULE),
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ Filter added (ID: %u)\n", rule->filter_id);
    }
    
    return result;
}

BOOL IoctlRemoveFilter(IOCTL_CLIENT_CONTEXT* ctx, UINT32 filter_id)
{
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_REMOVE_FILTER,
        &filter_id,
        sizeof(UINT32),
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ Filter removed (ID: %u)\n", filter_id);
    }
    
    return result;
}

BOOL IoctlClearFilters(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_CLEAR_FILTERS,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ All filters cleared\n");
    }
    
    return result;
}

BOOL IoctlSetFilter(IOCTL_CLIENT_CONTEXT* ctx, FILTER_RULE* rule)
{
    if (rule == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_SET_FILTER,
        rule,
        sizeof(FILTER_RULE),
        NULL,
        0,
        &bytes_returned
    );
}

//==============================================================================
// Section 8: Statistics Functions
//==============================================================================

BOOL IoctlGetCaptureStats(IOCTL_CLIENT_CONTEXT* ctx, CAPTURE_STATISTICS* stats)
{
    if (stats == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_GET_STATS,
        NULL,
        0,
        stats,
        sizeof(CAPTURE_STATISTICS),
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] Statistics: %llu packets, %llu dropped\n",
               stats->packets_captured, stats->packets_dropped);
    }
    
    return result;
}

BOOL IoctlGetRingStats(IOCTL_CLIENT_CONTEXT* ctx, RING_STATISTICS* stats)
{
    if (stats == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_GET_RING_INFO,
        NULL,
        0,
        stats,
        sizeof(RING_STATISTICS),
        &bytes_returned
    );
}

BOOL IoctlResetStatistics(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    // TODO: Implement reset statistics IOCTL
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_FLUSH_BUFFER,  // Reuse flush for now
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
}

//==============================================================================
// Section 9: NIC Management Functions
//==============================================================================

BOOL IoctlEnableNIC(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id)
{
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_ENABLE_NIC,
        &nic_id,
        sizeof(UINT32),
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ NIC %u enabled\n", nic_id);
    }
    
    return result;
}

BOOL IoctlDisableNIC(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id)
{
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_DISABLE_NIC,
        &nic_id,
        sizeof(UINT32),
        NULL,
        0,
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] ✓ NIC %u disabled\n", nic_id);
    }
    
    return result;
}

BOOL IoctlGetNICInfo(IOCTL_CLIENT_CONTEXT* ctx, UINT32 nic_id, NIC_INFO* info)
{
    if (info == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_GET_NIC_INFO,
        &nic_id,
        sizeof(UINT32),
        info,
        sizeof(NIC_INFO),
        &bytes_returned
    );
}

//==============================================================================
// Section 10: Diagnostic Functions
//==============================================================================

BOOL IoctlPing(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    UINT32 ping_response = 0;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_PING,
        NULL,
        0,
        &ping_response,
        sizeof(UINT32),
        &bytes_returned
    );
    
    if (result && ping_response == 0xC0FFEE) {  // Expected magic response
        printf("[IoctlClient] ✓ Ping successful\n");
        return TRUE;
    }
    
    printf("[IoctlClient] ✗ Ping failed\n");
    return FALSE;
}

BOOL IoctlGetDriverVersion(IOCTL_CLIENT_CONTEXT* ctx, VERSION_INFO* version)
{
    if (version == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_GET_VERSION,
        NULL,
        0,
        version,
        sizeof(VERSION_INFO),
        &bytes_returned
    );
}

BOOL IoctlSelfTest(IOCTL_CLIENT_CONTEXT* ctx, SELF_TEST_RESULTS* results)
{
    if (results == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    BOOL result = SendIoctl(
        ctx,
        IOCTL_NETCAP_SELF_TEST,
        NULL,
        0,
        results,
        sizeof(SELF_TEST_RESULTS),
        &bytes_returned
    );
    
    if (result) {
        printf("[IoctlClient] Self-test results:\n");
        printf("  Ring buffer:  %s\n", results->ring_test_passed ? "PASS" : "FAIL");
        printf("  NDIS filter:  %s\n", results->ndis_test_passed ? "PASS" : "FAIL");
        printf("  Memory alloc: %s\n", results->memory_test_passed ? "PASS" : "FAIL");
        printf("  WFP callout:  %s\n", results->wfp_test_passed ? "PASS" : "FAIL");
        
        if (results->error_details[0] != '\0') {
            printf("  Details: %s\n", results->error_details);
        }
    }
    
    return result;
}

//==============================================================================
// Section 11: Error Handling Functions
//==============================================================================

DWORD GetLastIoctlError(IOCTL_CLIENT_CONTEXT* ctx)
{
    if (ctx == NULL) {
        return ERROR_INVALID_HANDLE;
    }
    
    return GetLastError();
}

VOID TranslateIoctlError(DWORD error_code, char* error_msg, size_t msg_len)
{
    switch (error_code) {
        case ERROR_ACCESS_DENIED:
            strncpy_s(error_msg, msg_len, "Access denied - run as Administrator", _TRUNCATE);
            break;
        
        case ERROR_FILE_NOT_FOUND:
            strncpy_s(error_msg, msg_len, "Driver not found - ensure driver is loaded", _TRUNCATE);
            break;
        
        case ERROR_DEVICE_NOT_CONNECTED:
            strncpy_s(error_msg, msg_len, "Driver disconnected", _TRUNCATE);
            break;
        
        case ERROR_INSUFFICIENT_BUFFER:
            strncpy_s(error_msg, msg_len, "Buffer too small for response", _TRUNCATE);
            break;
        
        case ERROR_INVALID_PARAMETER:
            strncpy_s(error_msg, msg_len, "Invalid input parameter", _TRUNCATE);
            break;
        
        case ERROR_TIMEOUT:
            strncpy_s(error_msg, msg_len, "IOCTL timed out", _TRUNCATE);
            break;
        
        case ERROR_NOT_READY:
            strncpy_s(error_msg, msg_len, "Driver not ready", _TRUNCATE);
            break;
        
        default:
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error_code,
                0,
                error_msg,
                (DWORD)msg_len,
                NULL
            );
            break;
    }
}

//==============================================================================
// Section 12: Statistics and Monitoring
//==============================================================================

BOOL GetIoctlStatistics(IOCTL_CLIENT_CONTEXT* ctx, IOCTL_STATISTICS* stats)
{
    if (ctx == NULL || stats == NULL) {
        return FALSE;
    }
    
    EnterCriticalSection(&ctx->lock);
    
    stats->total_ioctls = ctx->ioctl_count;
    stats->failed_ioctls = ctx->ioctl_errors;
    
    if (ctx->ioctl_count > 0) {
        stats->avg_latency_us = ctx->total_latency_us / ctx->ioctl_count;
    } else {
        stats->avg_latency_us = 0;
    }
    
    stats->max_latency_us = ctx->max_latency_us;
    stats->active_connections = ctx->is_connected ? 1 : 0;
    
    LeaveCriticalSection(&ctx->lock);
    
    return TRUE;
}

VOID LogIoctlPerformance(IOCTL_CLIENT_CONTEXT* ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    IOCTL_STATISTICS stats;
    if (!GetIoctlStatistics(ctx, &stats)) {
        return;
    }
    
    printf("\n[IoctlClient] ============ Performance Report ============\n");
    printf("[IoctlClient] Total IOCTLs:    %llu\n", stats.total_ioctls);
    printf("[IoctlClient] Failed IOCTLs:   %llu\n", stats.failed_ioctls);
    
    if (stats.total_ioctls > 0) {
        double success_rate = ((double)(stats.total_ioctls - stats.failed_ioctls) / stats.total_ioctls) * 100.0;
        printf("[IoctlClient] Success rate:    %.2f%%\n", success_rate);
    }
    
    printf("[IoctlClient] Avg latency:     %llu μs\n", stats.avg_latency_us);
    printf("[IoctlClient] Max latency:     %llu μs\n", stats.max_latency_us);
    printf("[IoctlClient] Connection:      %s\n", stats.active_connections > 0 ? "Active" : "Disconnected");
    printf("[IoctlClient] ============================================\n\n");
}

//==============================================================================
// Section 13: Helper and Utility Functions
//==============================================================================

BOOL IoctlFlushBuffer(IOCTL_CLIENT_CONTEXT* ctx)
{
    DWORD bytes_returned;
    
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_FLUSH_BUFFER,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned
    );
}

BOOL IoctlMapSharedMemory(IOCTL_CLIENT_CONTEXT* ctx, PVOID* base_address, SIZE_T* size)
{
    if (base_address == NULL || size == NULL) {
        return FALSE;
    }
    
    DWORD bytes_returned;
    
    // Simple mapping request
    return SendIoctl(
        ctx,
        IOCTL_NETCAP_MAP_SHARED_MEM,
        NULL,
        0,
        base_address,
        sizeof(PVOID),
        &bytes_returned
    );
}

// Validation helpers
BOOL ValidateCaptureConfig(CAPTURE_CONFIG* config)
{
    if (config == NULL) {
        return FALSE;
    }
    
    if (config->max_packet_size > 65535 || config->max_packet_size < 64) {
        printf("[IoctlClient] ERROR: Invalid packet size: %u\n", config->max_packet_size);
        return FALSE;
    }
    
    if (config->ring_buffer_size_mb > 4096) {  // Max 4GB
        printf("[IoctlClient] ERROR: Ring buffer too large: %u MB\n", config->ring_buffer_size_mb);
        return FALSE;
    }
    
    return TRUE;
}

BOOL ValidateFilterRule(FILTER_RULE* rule)
{
    if (rule == NULL) {
        return FALSE;
    }
    
    if (rule->action > FILTER_ACTION_LOG_ONLY) {
        printf("[IoctlClient] ERROR: Invalid filter action: %d\n", rule->action);
        return FALSE;
    }
    
    if (rule->protocol != 6 && rule->protocol != 17 && rule->protocol != 1 && rule->protocol != 0) {
        printf("[IoctlClient] WARNING: Unusual protocol: %u\n", rule->protocol);
    }
    
    return TRUE;
}

//==============================================================================
// END OF FILE
//==============================================================================
