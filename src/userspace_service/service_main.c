//==============================================================================
// FILE: src/userspace_service/service_main.c
//
// SafeOps Userspace Service - Main Entry Point and Orchestrator
//
// PURPOSE:
//   Main entry point for the SafeOps Windows Service. Coordinates all userspace
//   components including kernel driver lifecycle, ring buffer reader, log writer,
//   rotation manager, IOCTL client, and statistics collector.
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
// DATE: 2024-12-13
//==============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <strsafe.h>
#include <psapi.h>

// Project headers
#include "service_main.h"
#include "ring_reader.h"
#include "log_writer.h"
#include "rotation_manager.h"
#include "ioctl_client.h"
#include "stats_collector.h"
#include "config_loader.h"

//==============================================================================
// Section 1: Service Configuration and Constants
//==============================================================================

// Service identification
#define SERVICE_NAME            TEXT("SafeOpsCapture")
#define SERVICE_DISPLAY_NAME    TEXT("SafeOps Network Packet Capture Service")
#define SERVICE_DESCRIPTION     TEXT("High-performance kernel-level packet capture with 5-minute rotation")

// Driver configuration
#define DRIVER_NAME             TEXT("SafeOps")
#define DRIVER_PATH             TEXT("C:\\Windows\\System32\\drivers\\SafeOps.sys")
#define DRIVER_DEVICE_NAME      TEXT("\\\\.\\SafeOps")

// Configuration paths
#define CONFIG_DIR              TEXT("C:\\Program Files\\SafeOps\\config")
#define SERVICE_CONFIG_FILE     CONFIG_DIR TEXT("\\service_main.toml")
#define LOG_DIR                 TEXT("C:\\SafeOps\\logs")
#define SERVICE_LOG_FILE        LOG_DIR TEXT("\\service.log")

// Timeouts (milliseconds)
#define DRIVER_LOAD_TIMEOUT     30000
#define THREAD_SHUTDOWN_TIMEOUT 10000
#define GRACEFUL_STOP_TIMEOUT   30000

//==============================================================================
// Section 2: Global Variables
//==============================================================================

// Service status variables
SERVICE_STATUS          g_service_status = {0};
SERVICE_STATUS_HANDLE   g_service_status_handle = NULL;
HANDLE                  g_service_stop_event = NULL;

// Driver handle
HANDLE                  g_driver_handle = INVALID_HANDLE_VALUE;

// Thread handles
HANDLE                  g_reader_thread = NULL;
HANDLE                  g_rotation_thread = NULL;
HANDLE                  g_stats_thread = NULL;
HANDLE                  g_health_thread = NULL;

// Component contexts
RING_READER_CONTEXT     g_ring_reader_context = {0};
LOG_WRITER_CONTEXT      g_log_writer_context = {0};
ROTATION_CONTEXT        g_rotation_context = {0};
STATS_CONTEXT           g_stats_context = {0};

// Configuration
SERVICE_CONFIG          g_service_config = {0};

// Shutdown flag
volatile BOOL           g_shutdown_requested = FALSE;

// Log file handle
HANDLE                  g_log_file = INVALID_HANDLE_VALUE;

//==============================================================================
// Section 3: Forward Declarations
//==============================================================================

// Service callbacks
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD ctrl_code);
VOID ReportServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint);

// Driver management
BOOL LoadDriver(VOID);
BOOL UnloadDriver(VOID);
BOOL OpenDriverDevice(VOID);
BOOL VerifyDriverSignature(VOID);

// Component initialization
BOOL InitializeComponents(VOID);
BOOL InitializeLogging(VOID);
BOOL InitializeRingReader(VOID);
BOOL InitializeLogWriter(VOID);
BOOL InitializeRotationManager(VOID);
BOOL InitializeStatsCollector(VOID);

// Thread management
HANDLE StartReaderThread(VOID);
HANDLE StartRotationThread(VOID);
HANDLE StartStatsThread(VOID);
HANDLE StartHealthThread(VOID);
VOID StopAllThreads(VOID);

// Configuration
BOOL LoadConfiguration(VOID);
BOOL ValidateConfiguration(VOID);
BOOL ApplyConfiguration(VOID);

// Logging
VOID LogInfo(const char *format, ...);
VOID LogWarning(const char *format, ...);
VOID LogError(const char *format, ...);
VOID LogCritical(const char *format, ...);
VOID WriteToEventLog(WORD type, const char *message);

// Cleanup
VOID CleanupComponents(VOID);
VOID GracefulShutdown(VOID);

// Health monitoring
DWORD WINAPI HealthCheckThread(LPVOID param);
BOOL CheckDriverConnectivity(VOID);
BOOL CheckDiskSpace(VOID);
BOOL CheckMemoryUsage(VOID);

// Signal handling
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type);

//==============================================================================
// Section 4: Main Entry Point
//==============================================================================

int _tmain(int argc, TCHAR *argv[])
{
    SERVICE_TABLE_ENTRY service_table[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    // Check for console mode (debug)
    if (argc > 1 && _tcscmp(argv[1], TEXT("-console")) == 0) {
        _tprintf(TEXT("[SafeOps] Running in console mode (debug)\n"));
        
        // Set console control handler
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        
        // Initialize components
        if (!InitializeComponents()) {
            _tprintf(TEXT("[SafeOps] ERROR: Component initialization failed\n"));
            return 1;
        }
        
        _tprintf(TEXT("[SafeOps] Service running. Press Ctrl+C to stop.\n"));
        
        // Wait for stop event
        WaitForSingleObject(g_service_stop_event, INFINITE);
        
        // Cleanup
        CleanupComponents();
        
        _tprintf(TEXT("[SafeOps] Service stopped.\n"));
        return 0;
    }
    
    // Normal service mode - register with SCM
    LogInfo("Starting SafeOps service...");
    
    if (!StartServiceCtrlDispatcher(service_table)) {
        DWORD error = GetLastError();
        LogCritical("StartServiceCtrlDispatcher failed: %lu", error);
        return 1;
    }
    
    return 0;
}

//==============================================================================
// Section 5: Windows Service Callbacks
//==============================================================================

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    
    // Register control handler
    g_service_status_handle = RegisterServiceCtrlHandler(
        SERVICE_NAME,
        ServiceCtrlHandler
    );
    
    if (g_service_status_handle == NULL) {
        LogCritical("RegisterServiceCtrlHandler failed: %lu", GetLastError());
        return;
    }
    
    // Initialize service status structure
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;
    
    // Report initial status
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    
    // Create stop event
    g_service_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_service_stop_event == NULL) {
        LogCritical("CreateEvent failed: %lu", GetLastError());
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }
    
    // Initialize all components
    LogInfo("Initializing SafeOps components...");
    
    if (!InitializeComponents()) {
        LogCritical("Component initialization failed");
        ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        CloseHandle(g_service_stop_event);
        return;
    }
    
    // Report running status
    LogInfo("SafeOps service started successfully");
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    
    // Wait for stop signal
    WaitForSingleObject(g_service_stop_event, INFINITE);
    
    // Cleanup
    LogInfo("SafeOps service stopping...");
    CleanupComponents();
    
    // Report stopped status
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
    
    LogInfo("SafeOps service stopped successfully");
}

VOID WINAPI ServiceCtrlHandler(DWORD ctrl_code)
{
    switch (ctrl_code) {
        case SERVICE_CONTROL_STOP:
            LogInfo("SERVICE_CONTROL_STOP received");
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, GRACEFUL_STOP_TIMEOUT);
            
            // Signal stop event
            SetEvent(g_service_stop_event);
            
            ReportServiceStatus(g_service_status.dwCurrentState, NO_ERROR, 0);
            break;
            
        case SERVICE_CONTROL_PAUSE:
            LogInfo("SERVICE_CONTROL_PAUSE received");
            // Pause not implemented
            break;
            
        case SERVICE_CONTROL_CONTINUE:
            LogInfo("SERVICE_CONTROL_CONTINUE received");
            // Continue not implemented
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            // Report current status
            ReportServiceStatus(g_service_status.dwCurrentState, NO_ERROR, 0);
            break;
            
        case SERVICE_CONTROL_SHUTDOWN:
            LogWarning("SERVICE_CONTROL_SHUTDOWN received - system shutting down");
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, GRACEFUL_STOP_TIMEOUT);
            SetEvent(g_service_stop_event);
            break;
            
        default:
            LogWarning("Unknown service control code: %lu", ctrl_code);
            break;
    }
}

VOID ReportServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
    static DWORD checkpoint = 1;
    
    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = exit_code;
    g_service_status.dwWaitHint = wait_hint;
    
    if (current_state == SERVICE_START_PENDING) {
        g_service_status.dwControlsAccepted = 0;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    
    if ((current_state == SERVICE_RUNNING) || (current_state == SERVICE_STOPPED)) {
        g_service_status.dwCheckPoint = 0;
    } else {
        g_service_status.dwCheckPoint = checkpoint++;
    }
    
    SetServiceStatus(g_service_status_handle, &g_service_status);
}

// Continue in next message due to length...
