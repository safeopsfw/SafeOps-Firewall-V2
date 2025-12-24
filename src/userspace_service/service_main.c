//==============================================================================
// FILE: src/userspace_service/service_main.c
//
// SafeOps Userspace Service - Main Entry Point and Orchestrator
//
// PURPOSE:
//   Main entry point for the SafeOps Windows Service. Coordinates all userspace
//   components including kernel driver lifecycle, ring buffer reader, log
//   writer, rotation manager, IOCTL client, and statistics collector.
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
// DATE: 2024-12-13
//==============================================================================

#include <psapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>

// Project headers
#include "service_main.h"
#include "userspace_service.h"

//==============================================================================
// Section 1: Service Configuration and Constants
//==============================================================================

// Service identification
#define SERVICE_NAME TEXT("SafeOpsCapture")
#define SERVICE_DISPLAY_NAME TEXT("SafeOps Network Packet Capture Service")
#define SERVICE_DESCRIPTION                                                    \
  TEXT("High-performance kernel-level packet capture with 5-minute rotation")

// Driver configuration
#define DRIVER_NAME TEXT("SafeOps")
#define DRIVER_PATH TEXT("C:\\Windows\\System32\\drivers\\SafeOps.sys")
#define DRIVER_DEVICE_NAME TEXT("\\\\.\\SafeOps")

// Configuration paths
#define CONFIG_DIR TEXT("C:\\Program Files\\SafeOps\\config")
#define SERVICE_CONFIG_FILE CONFIG_DIR TEXT("\\service_main.toml")
#define LOG_DIR TEXT("C:\\SafeOps\\logs")
#define SERVICE_LOG_FILE LOG_DIR TEXT("\\service.log")

// Timeouts (milliseconds)
#define DRIVER_LOAD_TIMEOUT 30000
#define THREAD_SHUTDOWN_TIMEOUT 10000
#define GRACEFUL_STOP_TIMEOUT 30000

//==============================================================================
// Section 2: Global Variables
//==============================================================================

// Service status variables
SERVICE_STATUS g_service_status = {0};
SERVICE_STATUS_HANDLE g_service_status_handle = NULL;
HANDLE g_service_stop_event = NULL;

// Driver handle
HANDLE g_driver_handle = INVALID_HANDLE_VALUE;

// Thread handles
HANDLE g_reader_thread = NULL;
HANDLE g_rotation_thread = NULL;
HANDLE g_stats_thread = NULL;
HANDLE g_health_thread = NULL;

// Component contexts
RING_READER_CONTEXT g_ring_reader_context = {0};
LOG_WRITER_CONTEXT g_log_writer_context = {0};
ROTATION_CONTEXT g_rotation_context = {0};
STATS_CONTEXT g_stats_context = {0};

// Configuration
SERVICE_CONFIG g_service_config = {0};

// Shutdown flag
volatile BOOL g_shutdown_requested = FALSE;

// Log file handle
HANDLE g_log_file = INVALID_HANDLE_VALUE;

//==============================================================================
// Section 3: Forward Declarations
//==============================================================================

// Service callbacks (renamed to avoid conflict with userspace_service.h)
VOID WINAPI SvcMain(DWORD argc, LPTSTR *argv);
VOID WINAPI SvcCtrlHandler(DWORD ctrl_code);
VOID ReportSvcStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint);

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

int _tmain(int argc, TCHAR *argv[]) {
  SERVICE_TABLE_ENTRY service_table[] = {
      {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain}, {NULL, NULL}};

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

VOID WINAPI SvcMain(DWORD argc, LPTSTR *argv) {
  UNREFERENCED_PARAMETER(argc);
  UNREFERENCED_PARAMETER(argv);

  // Register control handler
  g_service_status_handle =
      RegisterServiceCtrlHandler(SERVICE_NAME, SvcCtrlHandler);

  if (g_service_status_handle == NULL) {
    LogCritical("RegisterServiceCtrlHandler failed: %lu", GetLastError());
    return;
  }

  // Initialize service status structure
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwServiceSpecificExitCode = 0;

  // Report initial status
  ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

  // Create stop event
  g_service_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (g_service_stop_event == NULL) {
    LogCritical("CreateEvent failed: %lu", GetLastError());
    ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }

  // Initialize all components
  LogInfo("Initializing SafeOps components...");

  if (!InitializeComponents()) {
    LogCritical("Component initialization failed");
    ReportSvcStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
    CloseHandle(g_service_stop_event);
    return;
  }

  // Report running status
  LogInfo("SafeOps service started successfully");
  ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

  // Wait for stop signal
  WaitForSingleObject(g_service_stop_event, INFINITE);

  // Cleanup
  LogInfo("SafeOps service stopping...");
  CleanupComponents();

  // Report stopped status
  ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);

  LogInfo("SafeOps service stopped successfully");
}

VOID WINAPI SvcCtrlHandler(DWORD ctrl_code) {
  switch (ctrl_code) {
  case SERVICE_CONTROL_STOP:
    LogInfo("SERVICE_CONTROL_STOP received");
    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, GRACEFUL_STOP_TIMEOUT);

    // Signal stop event
    SetEvent(g_service_stop_event);

    ReportSvcStatus(g_service_status.dwCurrentState, NO_ERROR, 0);
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
    ReportSvcStatus(g_service_status.dwCurrentState, NO_ERROR, 0);
    break;

  case SERVICE_CONTROL_SHUTDOWN:
    LogWarning("SERVICE_CONTROL_SHUTDOWN received - system shutting down");
    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, GRACEFUL_STOP_TIMEOUT);
    SetEvent(g_service_stop_event);
    break;

  default:
    LogWarning("Unknown service control code: %lu", ctrl_code);
    break;
  }
}

VOID ReportSvcStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint) {
  static DWORD checkpoint = 1;

  g_service_status.dwCurrentState = current_state;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwWaitHint = wait_hint;

  if (current_state == SERVICE_START_PENDING) {
    g_service_status.dwControlsAccepted = 0;
  } else {
    g_service_status.dwControlsAccepted =
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  }

  if ((current_state == SERVICE_RUNNING) ||
      (current_state == SERVICE_STOPPED)) {
    g_service_status.dwCheckPoint = 0;
  } else {
    g_service_status.dwCheckPoint = checkpoint++;
  }

  SetServiceStatus(g_service_status_handle, &g_service_status);
}

//==============================================================================
// Section 6: Component Initialization
//==============================================================================

BOOL InitializeComponents(VOID) {
  // Create stop event if not already created (console mode)
  if (g_service_stop_event == NULL) {
    g_service_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_service_stop_event == NULL) {
      LogCritical("Failed to create stop event: %lu", GetLastError());
      return FALSE;
    }
  }

  // Load configuration
  if (!LoadConfiguration()) {
    LogError("Failed to load configuration, using defaults");
    // Continue with defaults
  }

  // Initialize logging
  if (!InitializeLogging()) {
    LogError("Failed to initialize logging system");
    // Continue without file logging
  }

  // Open driver device
  if (!OpenDriverDevice()) {
    LogCritical("Failed to open driver device");
    return FALSE;
  }

  // Initialize ring reader (maps shared memory)
  if (!InitializeRingReader()) {
    LogCritical("Failed to initialize ring reader");
    CloseHandle(g_driver_handle);
    g_driver_handle = INVALID_HANDLE_VALUE;
    return FALSE;
  }

  // Initialize log writer
  if (!InitializeLogWriter()) {
    LogCritical("Failed to initialize log writer");
    // Cleanup ring reader
    RingReader_Cleanup(&g_ring_reader_context);
    CloseHandle(g_driver_handle);
    g_driver_handle = INVALID_HANDLE_VALUE;
    return FALSE;
  }

  // Initialize rotation manager
  if (!InitializeRotationManager()) {
    LogError("Failed to initialize rotation manager");
    // Continue without rotation
  }

  // Initialize stats collector
  if (!InitializeStatsCollector()) {
    LogError("Failed to initialize stats collector");
    // Continue without stats
  }

  // Start worker threads
  g_reader_thread = StartReaderThread();
  if (g_reader_thread == NULL) {
    LogCritical("Failed to start reader thread");
    CleanupComponents();
    return FALSE;
  }

  g_rotation_thread = StartRotationThread();
  if (g_rotation_thread == NULL) {
    LogWarning("Failed to start rotation thread");
    // Continue without rotation
  }

  g_stats_thread = StartStatsThread();
  if (g_stats_thread == NULL) {
    LogWarning("Failed to start stats thread");
    // Continue without stats
  }

  g_health_thread = StartHealthThread();
  if (g_health_thread == NULL) {
    LogWarning("Failed to start health thread");
    // Continue without health monitoring
  }

  LogInfo("All components initialized successfully");
  return TRUE;
}

BOOL InitializeLogging(VOID) {
  // Create log directory if it doesn't exist
  CreateDirectory(LOG_DIR, NULL);

  // Open service log file
  g_log_file = CreateFile(SERVICE_LOG_FILE, GENERIC_WRITE, FILE_SHARE_READ,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (g_log_file == INVALID_HANDLE_VALUE) {
    return FALSE;
  }

  // Seek to end for appending
  SetFilePointer(g_log_file, 0, NULL, FILE_END);

  LogInfo("Logging initialized: %S", SERVICE_LOG_FILE);
  return TRUE;
}

BOOL InitializeRingReader(VOID) {
  NTSTATUS status =
      RingReader_Initialize(&g_ring_reader_context, g_driver_handle,
                            g_service_config.ring_buffer_size);

  if (status != 0) {
    LogError("RingReader_Initialize failed: 0x%08X", status);
    return FALSE;
  }

  LogInfo("Ring reader initialized, buffer size: %zu bytes",
          g_ring_reader_context.buffer_size);
  return TRUE;
}

BOOL InitializeLogWriter(VOID) {
  BOOL result = LogWriter_Initialize(&g_log_writer_context,
                                     g_service_config.log_directory,
                                     g_service_config.json_format);

  if (!result) {
    LogError("LogWriter_Initialize failed");
    return FALSE;
  }

  LogInfo("Log writer initialized, output: %s", g_service_config.log_directory);
  return TRUE;
}

BOOL InitializeRotationManager(VOID) {
  BOOL result =
      RotationManager_Initialize(&g_rotation_context, &g_log_writer_context,
                                 g_service_config.rotation_interval_ms);

  if (!result) {
    LogError("RotationManager_Initialize failed");
    return FALSE;
  }

  LogInfo("Rotation manager initialized, interval: %lu ms",
          g_service_config.rotation_interval_ms);
  return TRUE;
}

BOOL InitializeStatsCollector(VOID) {
  // Stats collector initialization placeholder
  g_stats_context.enabled = g_service_config.enable_stats;
  g_stats_context.interval_ms = g_service_config.stats_interval_ms;

  LogInfo("Stats collector initialized, enabled: %s",
          g_stats_context.enabled ? "yes" : "no");
  return TRUE;
}

BOOL OpenDriverDevice(VOID) {
  g_driver_handle = CreateFile(DRIVER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (g_driver_handle == INVALID_HANDLE_VALUE) {
    LogError("Failed to open driver device %S: %lu", DRIVER_DEVICE_NAME,
             GetLastError());
    return FALSE;
  }

  LogInfo("Driver device opened: %S", DRIVER_DEVICE_NAME);
  return TRUE;
}

//==============================================================================
// Section 7: Worker Threads
//==============================================================================

DWORD WINAPI ReaderThreadProc(LPVOID param) {
  UNREFERENCED_PARAMETER(param);

  LogInfo("Reader thread started");

  while (WaitForSingleObject(g_service_stop_event, 0) != WAIT_OBJECT_0) {
    // Read packets from ring buffer
    PACKET_ENTRY packet;
    BOOL has_packet = RingReader_ReadNext(&g_ring_reader_context, &packet);

    if (has_packet) {
      // Write packet to log
      LogWriter_WritePacket(&g_log_writer_context, &packet);
    } else {
      // No packets available, sleep briefly
      Sleep(1);
    }
  }

  LogInfo("Reader thread exiting");
  return 0;
}

DWORD WINAPI RotationThreadProc(LPVOID param) {
  UNREFERENCED_PARAMETER(param);

  LogInfo("Rotation thread started");

  while (WaitForSingleObject(g_service_stop_event,
                             g_service_config.rotation_interval_ms) ==
         WAIT_TIMEOUT) {
    // Perform rotation
    LogInfo("Performing log rotation...");
    RotationManager_Rotate(&g_rotation_context);
  }

  LogInfo("Rotation thread exiting");
  return 0;
}

DWORD WINAPI StatsThreadProc(LPVOID param) {
  UNREFERENCED_PARAMETER(param);

  LogInfo("Stats thread started");

  while (WaitForSingleObject(g_service_stop_event,
                             g_service_config.stats_interval_ms) ==
         WAIT_TIMEOUT) {
    if (g_stats_context.enabled) {
      // Collect and report statistics
      // IOCTLClient_GetStatistics(g_driver_handle, &stats);
    }
  }

  LogInfo("Stats thread exiting");
  return 0;
}

DWORD WINAPI HealthCheckThread(LPVOID param) {
  UNREFERENCED_PARAMETER(param);

  LogInfo("Health check thread started");

  DWORD check_interval = 30000; // 30 seconds

  while (WaitForSingleObject(g_service_stop_event, check_interval) ==
         WAIT_TIMEOUT) {
    if (!CheckDriverConnectivity()) {
      LogWarning("Driver connectivity check failed");
    }

    if (!CheckDiskSpace()) {
      LogWarning("Low disk space detected");
    }

    if (!CheckMemoryUsage()) {
      LogWarning("High memory usage detected");
    }
  }

  LogInfo("Health check thread exiting");
  return 0;
}

HANDLE StartReaderThread(VOID) {
  return CreateThread(NULL, 0, ReaderThreadProc, NULL, 0, NULL);
}

HANDLE StartRotationThread(VOID) {
  return CreateThread(NULL, 0, RotationThreadProc, NULL, 0, NULL);
}

HANDLE StartStatsThread(VOID) {
  return CreateThread(NULL, 0, StatsThreadProc, NULL, 0, NULL);
}

HANDLE StartHealthThread(VOID) {
  return CreateThread(NULL, 0, HealthCheckThread, NULL, 0, NULL);
}

//==============================================================================
// Section 8: Cleanup Functions
//==============================================================================

VOID StopAllThreads(VOID) {
  HANDLE threads[4];
  DWORD thread_count = 0;

  if (g_reader_thread)
    threads[thread_count++] = g_reader_thread;
  if (g_rotation_thread)
    threads[thread_count++] = g_rotation_thread;
  if (g_stats_thread)
    threads[thread_count++] = g_stats_thread;
  if (g_health_thread)
    threads[thread_count++] = g_health_thread;

  if (thread_count > 0) {
    LogInfo("Waiting for %lu threads to stop...", thread_count);
    WaitForMultipleObjects(thread_count, threads, TRUE,
                           THREAD_SHUTDOWN_TIMEOUT);
  }

  // Close thread handles
  if (g_reader_thread) {
    CloseHandle(g_reader_thread);
    g_reader_thread = NULL;
  }
  if (g_rotation_thread) {
    CloseHandle(g_rotation_thread);
    g_rotation_thread = NULL;
  }
  if (g_stats_thread) {
    CloseHandle(g_stats_thread);
    g_stats_thread = NULL;
  }
  if (g_health_thread) {
    CloseHandle(g_health_thread);
    g_health_thread = NULL;
  }
}

VOID CleanupComponents(VOID) {
  LogInfo("Cleaning up components...");

  // Signal stop
  g_shutdown_requested = TRUE;

  // Stop all worker threads
  StopAllThreads();

  // Cleanup in reverse initialization order

  // Flush and close log writer
  LogWriter_Flush(&g_log_writer_context);
  LogWriter_Cleanup(&g_log_writer_context);

  // Cleanup rotation manager
  RotationManager_Cleanup(&g_rotation_context);

  // Cleanup ring reader (unmaps shared memory)
  RingReader_Cleanup(&g_ring_reader_context);

  // Close driver handle
  if (g_driver_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(g_driver_handle);
    g_driver_handle = INVALID_HANDLE_VALUE;
  }

  // Close service log file
  if (g_log_file != INVALID_HANDLE_VALUE) {
    CloseHandle(g_log_file);
    g_log_file = INVALID_HANDLE_VALUE;
  }

  // Close stop event
  if (g_service_stop_event) {
    CloseHandle(g_service_stop_event);
    g_service_stop_event = NULL;
  }

  LogInfo("Component cleanup complete");
}

VOID GracefulShutdown(VOID) {
  LogInfo("Initiating graceful shutdown...");

  // Signal stop
  if (g_service_stop_event) {
    SetEvent(g_service_stop_event);
  }
}

//==============================================================================
// Section 9: Logging Functions
//==============================================================================

VOID LogMessage(const char *level, const char *format, va_list args) {
  char timestamp[64];
  char message[1024];
  char full_message[1200];
  DWORD bytes_written;

  // Get current time
  SYSTEMTIME st;
  GetLocalTime(&st);
  sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            st.wMilliseconds);

  // Format message
  vsprintf_s(message, sizeof(message), format, args);

  // Combine timestamp, level, and message
  sprintf_s(full_message, sizeof(full_message), "[%s] [%s] %s\r\n", timestamp,
            level, message);

  // Write to log file
  if (g_log_file != INVALID_HANDLE_VALUE) {
    WriteFile(g_log_file, full_message, (DWORD)strlen(full_message),
              &bytes_written, NULL);
  }

  // Also output to debug console
  OutputDebugStringA(full_message);
}

VOID LogInfo(const char *format, ...) {
  va_list args;
  va_start(args, format);
  LogMessage("INFO", format, args);
  va_end(args);
}

VOID LogWarning(const char *format, ...) {
  va_list args;
  va_start(args, format);
  LogMessage("WARN", format, args);
  va_end(args);
}

VOID LogError(const char *format, ...) {
  va_list args;
  va_start(args, format);
  LogMessage("ERROR", format, args);
  va_end(args);
}

VOID LogCritical(const char *format, ...) {
  va_list args;
  va_start(args, format);
  LogMessage("CRITICAL", format, args);
  va_end(args);

  // Also write to Windows Event Log for critical errors
  char message[1024];
  va_start(args, format);
  vsprintf_s(message, sizeof(message), format, args);
  va_end(args);
  WriteToEventLog(EVENTLOG_ERROR_TYPE, message);
}

VOID WriteToEventLog(WORD type, const char *message) {
  HANDLE event_log = RegisterEventSource(NULL, "SafeOpsCapture");
  if (event_log) {
    const char *messages[1] = {message};
    ReportEventA(event_log, type, 0, 0, NULL, 1, 0, messages, NULL);
    DeregisterEventSource(event_log);
  }
}

//==============================================================================
// Section 10: Configuration Loading
//==============================================================================

BOOL LoadConfiguration(VOID) {
  // Set defaults
  g_service_config.ring_buffer_size = 2ULL * 1024 * 1024 * 1024; // 2GB
  g_service_config.rotation_interval_ms = 5 * 60 * 1000;         // 5 minutes
  g_service_config.stats_interval_ms = 1000;                     // 1 second
  g_service_config.enable_stats = TRUE;
  g_service_config.json_format = TRUE;
  strcpy_s(g_service_config.log_directory,
           sizeof(g_service_config.log_directory), "C:\\SafeOps\\logs");

  // Try to load from registry
  HKEY hKey;
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                   TEXT("SYSTEM\\CurrentControlSet\\Services\\SafeOpsCapture\\P"
                        "arameters"),
                   0, KEY_READ, &hKey) == ERROR_SUCCESS) {

    DWORD value, size = sizeof(DWORD);

    if (RegQueryValueEx(hKey, TEXT("RotationIntervalMs"), NULL, NULL,
                        (LPBYTE)&value, &size) == ERROR_SUCCESS) {
      g_service_config.rotation_interval_ms = value;
    }

    if (RegQueryValueEx(hKey, TEXT("StatsIntervalMs"), NULL, NULL,
                        (LPBYTE)&value, &size) == ERROR_SUCCESS) {
      g_service_config.stats_interval_ms = value;
    }

    if (RegQueryValueEx(hKey, TEXT("EnableStats"), NULL, NULL, (LPBYTE)&value,
                        &size) == ERROR_SUCCESS) {
      g_service_config.enable_stats = (value != 0);
    }

    RegCloseKey(hKey);
  }

  return TRUE;
}

BOOL ValidateConfiguration(VOID) {
  // Validate rotation interval (minimum 1 minute)
  if (g_service_config.rotation_interval_ms < 60000) {
    g_service_config.rotation_interval_ms = 60000;
    LogWarning("Rotation interval too short, set to 1 minute");
  }

  return TRUE;
}

BOOL ApplyConfiguration(VOID) {
  // Configuration applied during component initialization
  return TRUE;
}

//==============================================================================
// Section 11: Health Check Functions
//==============================================================================

BOOL CheckDriverConnectivity(VOID) {
  if (g_driver_handle == INVALID_HANDLE_VALUE) {
    return FALSE;
  }

  // Send a simple IOCTL to verify driver is responsive
  DWORD bytes_returned;
  BOOL result = DeviceIoControl(g_driver_handle, IOCTL_GET_DRIVER_VERSION, NULL,
                                0, NULL, 0, &bytes_returned, NULL);

  return result;
}

BOOL CheckDiskSpace(VOID) {
  ULARGE_INTEGER free_bytes, total_bytes;

  if (GetDiskFreeSpaceEx(TEXT("C:\\"), &free_bytes, &total_bytes, NULL)) {
    // Warn if less than 1GB free
    if (free_bytes.QuadPart < (1ULL * 1024 * 1024 * 1024)) {
      return FALSE;
    }
  }

  return TRUE;
}

BOOL CheckMemoryUsage(VOID) {
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
    // Warn if using more than 512MB
    if (pmc.WorkingSetSize > (512ULL * 1024 * 1024)) {
      return FALSE;
    }
  }

  return TRUE;
}

//==============================================================================
// Section 12: Console Control Handler (Debug Mode)
//==============================================================================

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
  switch (ctrl_type) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    _tprintf(TEXT("\n[SafeOps] Shutdown signal received...\n"));
    GracefulShutdown();
    return TRUE;

  default:
    return FALSE;
  }
}

//==============================================================================
// Section 13: Driver Management (Placeholder)
//==============================================================================

BOOL LoadDriver(VOID) {
  // Driver is loaded via Service Control Manager, not programmatically
  // This is a placeholder for future dynamic loading if needed
  return TRUE;
}

BOOL UnloadDriver(VOID) {
  // Driver is unloaded via Service Control Manager
  return TRUE;
}

BOOL VerifyDriverSignature(VOID) {
  // Placeholder for driver signature verification
  // In production, use WinVerifyTrust API
  return TRUE;
}

//==============================================================================
// END OF FILE
//==============================================================================
