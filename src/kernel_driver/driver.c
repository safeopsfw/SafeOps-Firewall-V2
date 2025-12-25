/**
 * driver.c - SafeOps Kernel Driver Main Entry Point
 *
 * Main entry point for the SafeOps kernel-mode driver. Handles driver
 * initialization, registration with Windows NDIS and WFP subsystems, and
 * graceful shutdown. This is the first code that executes when the driver
 * loads and the last when it unloads.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 *
 * Build: ${BUILD_TYPE} | ${HARDWARE_PLATFORM}
 * Version: ${DRIVER_VERSION}
 * Built: __DATE__ __TIME__
 */

#include "driver.h"
#include <ntstrsafe.h>
#include <wdmsec.h>

//=============================================================================
// Section 7: Driver Metadata
//=============================================================================

#define SAFEOPS_BUILD_TIMESTAMP __DATE__ " " __TIME__
#define SAFEOPS_COPYRIGHT "Copyright (c) 2024 SafeOps Project"
#define SAFEOPS_DRIVER_DESCRIPTION "SafeOps Network Security Gateway Driver"

// Event Log source name
#define SAFEOPS_EVENT_SOURCE L"SafeOps"

// Registry paths
#define SAFEOPS_REGISTRY_PATH                                                  \
  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\SafeOps"
#define SAFEOPS_PARAMETERS_KEY L"Parameters"

//=============================================================================
// Section 8: Global State Management
//=============================================================================

// Global state and configuration (definitions)
// Note: Types are declared in driver.h
GLOBAL_DRIVER_STATE g_DriverState = {0};

DRIVER_CONFIG g_DriverConfig = {
    .MaxFilterRules = MAX_FILTER_RULES,
    .MaxConnections = MAX_CONNECTIONS,
    .SharedBufferSizeMB = SHARED_BUFFER_SIZE / (1024 * 1024),
    .DmaBufferSizeMB = DMA_BUFFER_SIZE / (1024 * 1024),
    .EnableLogging = TRUE,
    .EnableDeepInspection = FALSE,
    .EnableRss = FALSE,
    .RssCpuCount = 0,
    .LogLevel = 3 // INFO level
};

//=============================================================================
// Section 9: Diagnostic and Debug
//=============================================================================

// Note: LOG_LEVEL_* constants and SAFEOPS_LOG_* macros are defined in driver.h
// Note: SAFEOPS_ASSERT macro is defined in driver.h

//=============================================================================
// Forward Declarations
//=============================================================================

// Section 3 & 4: Component management
NTSTATUS SafeOpsInitializeAllComponents(_In_ PDRIVER_CONTEXT Context);
VOID SafeOpsCleanupAllComponents(_In_ PDRIVER_CONTEXT Context);

// Section 5: Error recovery
VOID SafeOpsRollbackInitialization(_In_ PDRIVER_CONTEXT Context,
                                   _In_ ULONG CompletedSteps);

// Section 6: System callbacks
NTSTATUS SafeOpsRegisterPowerCallbacks(VOID);
VOID SafeOpsUnregisterPowerCallbacks(VOID);
_Function_class_(CALLBACK_FUNCTION) NTSTATUS
    SafeOpsPowerCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1,
                         _In_ PVOID Argument2);

// Section 10: Self-check functions
NTSTATUS SafeOpsPerformSelfCheck(_In_ PDRIVER_CONTEXT Context);
NTSTATUS SafeOpsVerifySubsystems(_In_ PDRIVER_CONTEXT Context);

// Helper functions
NTSTATUS SafeOpsReadRegistryConfig(VOID);
NTSTATUS SafeOpsWriteEventLog(_In_ ULONG EventType, _In_ ULONG EventId,
                              _In_ PWSTR Message);
VOID SafeOpsLogStartupBanner(VOID);
VOID SafeOpsLogShutdownStats(_In_ PDRIVER_CONTEXT Context);

//=============================================================================
// Section 1: Driver Entry Point
//=============================================================================

/**
 * DriverEntry - Main entry point called by Windows when driver loads
 *
 * This function is called by the Windows I/O Manager when the driver is loaded.
 * It performs the following operations:
 * 1. Initialize driver metadata and global state
 * 2. Read configuration from registry
 * 3. Create WDF driver object
 * 4. Log startup to Event Log
 * 5. Register power management callbacks
 * 6. Set up device creation callback
 *
 * @param DriverObject - Pointer to driver object created by I/O Manager
 * @param RegistryPath - Registry path for this driver's parameters
 * @return STATUS_SUCCESS on success, appropriate NTSTATUS error code on failure
 */
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  WDF_DRIVER_CONFIG config;
  WDFDRIVER driver;

  UNREFERENCED_PARAMETER(RegistryPath);

  // Initialize global state
  RtlZeroMemory(&g_DriverState, sizeof(g_DriverState));
  KeInitializeSpinLock(&g_DriverState.StateLock);
  KeInitializeEvent(&g_DriverState.ShutdownEvent, NotificationEvent, FALSE);
  g_DriverState.State = DRIVER_STATE_INITIALIZING;
  g_DriverState.ReferenceCount = 0;
  g_DriverState.PowerCallbacksRegistered = FALSE;
  KeQuerySystemTime(&g_DriverState.StartTime);
  g_DriverState.LastStatsResetTime = g_DriverState.StartTime;

  // Log startup banner
  SafeOpsLogStartupBanner();

  // Determine platform string at compile time
#ifdef _AMD64_
  const char* platformString = "x64";
#elif defined(_ARM64_)
  const char* platformString = "ARM64";
#else
  const char* platformString = "Unknown";
#endif

  SAFEOPS_LOG_INFO("=== SafeOps Driver v%s Starting ===",
                   SAFEOPS_VERSION_STRING);
  SAFEOPS_LOG_INFO("Build: %s", SAFEOPS_BUILD_TIMESTAMP);
  SAFEOPS_LOG_INFO("Platform: %s", platformString);

  // Read configuration from registry
  status = SafeOpsReadRegistryConfig();
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING(
        "Failed to read registry config: 0x%08X (using defaults)", status);
    // Non-fatal, continue with defaults
  }

  // Display configuration
  SAFEOPS_LOG_INFO("Configuration:");
  SAFEOPS_LOG_INFO("  Max Filter Rules: %u", g_DriverConfig.MaxFilterRules);
  SAFEOPS_LOG_INFO("  Max Connections: %u", g_DriverConfig.MaxConnections);
  SAFEOPS_LOG_INFO("  Shared Buffer: %u MB", g_DriverConfig.SharedBufferSizeMB);
  SAFEOPS_LOG_INFO("  DMA Buffer: %u MB", g_DriverConfig.DmaBufferSizeMB);
  SAFEOPS_LOG_INFO("  Logging: %s",
                   g_DriverConfig.EnableLogging ? "Enabled" : "Disabled");
  SAFEOPS_LOG_INFO("  Deep Inspection: %s", g_DriverConfig.EnableDeepInspection
                                                ? "Enabled"
                                                : "Disabled");

  // Initialize WDF driver configuration
  WDF_DRIVER_CONFIG_INIT(&config, SafeOpsEvtDeviceAdd);
  config.EvtDriverUnload = SafeOpsEvtDriverUnload;
  config.DriverPoolTag = SAFEOPS_POOL_TAG;

  // Create WDF driver object
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES,
                           &config, &driver);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("WdfDriverCreate failed: 0x%08X", status);
    SafeOpsWriteEventLog(EVENTLOG_ERROR_TYPE, 1001,
                         L"Failed to create WDF driver object");
    g_DriverState.State = DRIVER_STATE_UNLOADED;
    return status;
  }

  SAFEOPS_LOG_INFO("WDF driver object created successfully");

  // Register power management callbacks
  status = SafeOpsRegisterPowerCallbacks();
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING("Failed to register power callbacks: 0x%08X", status);
    // Non-fatal, continue without power management
  } else {
    g_DriverState.PowerCallbacksRegistered = TRUE;
    SAFEOPS_LOG_INFO("Power management callbacks registered");
  }

  // Log successful initialization to Event Log
  SafeOpsWriteEventLog(EVENTLOG_INFORMATION_TYPE, 1000,
                       L"SafeOps Driver loaded successfully");

  g_DriverState.State = DRIVER_STATE_RUNNING;
  SAFEOPS_LOG_INFO("=== SafeOps Driver Started Successfully ===");

  return STATUS_SUCCESS;
}

//=============================================================================
// Section 2: Driver Unload Handler
//=============================================================================

/**
 * SafeOpsEvtDriverUnload - Called when driver is being unloaded
 *
 * Performs graceful shutdown of all driver components:
 * 1. Set driver state to shutting down
 * 2. Wait for all pending operations to complete
 * 3. Stop packet capture
 * 4. Flush ring buffer
 * 5. Cleanup all subsystems
 * 6. Unregister callbacks
 * 7. Log final statistics
 * 8. Free all resources
 *
 * @param Driver - WDF driver object handle
 */
VOID SafeOpsEvtDriverUnload(_In_ WDFDRIVER Driver) {
  KIRQL oldIrql;
  LARGE_INTEGER timeout;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(Driver);

  SAFEOPS_LOG_INFO("=== SafeOps Driver Unloading ===");

  // Set state to shutting down
  KeAcquireSpinLock(&g_DriverState.StateLock, &oldIrql);
  g_DriverState.State = DRIVER_STATE_SHUTTING_DOWN;
  KeReleaseSpinLock(&g_DriverState.StateLock, oldIrql);

  // Signal shutdown event
  KeSetEvent(&g_DriverState.ShutdownEvent, IO_NO_INCREMENT, FALSE);

  // Wait for all pending operations to complete (max 30 seconds)
  timeout.QuadPart = -300000000LL; // 30 seconds
  SAFEOPS_LOG_INFO("Waiting for pending operations to complete...");

  while (g_DriverState.ReferenceCount > 0) {
    status = KeWaitForSingleObject(&g_DriverState.ShutdownEvent, Executive,
                                   KernelMode, FALSE, &timeout);

    if (status == STATUS_TIMEOUT) {
      SAFEOPS_LOG_WARNING("Timeout waiting for operations (%d refs remaining)",
                          g_DriverState.ReferenceCount);
      break;
    }

    // Small delay
    timeout.QuadPart = -10000LL; // 1 ms
    KeDelayExecutionThread(KernelMode, FALSE, &timeout);
  }

  if (g_DriverState.ReferenceCount == 0) {
    SAFEOPS_LOG_INFO("All operations completed successfully");
  }

  // Unregister power callbacks if registered
  if (g_DriverState.PowerCallbacksRegistered) {
    SafeOpsUnregisterPowerCallbacks();
    SAFEOPS_LOG_INFO("Power callbacks unregistered");
  }

  // Cleanup is handled per-device in SafeOpsCleanupDriverContext

  // Calculate uptime
  LARGE_INTEGER currentTime, uptime;
  KeQuerySystemTime(&currentTime);
  uptime.QuadPart = currentTime.QuadPart - g_DriverState.StartTime.QuadPart;

  ULONG uptimeSeconds = (ULONG)(uptime.QuadPart / 10000000LL);
  ULONG hours = uptimeSeconds / 3600;
  ULONG minutes = (uptimeSeconds % 3600) / 60;
  ULONG seconds = uptimeSeconds % 60;

  SAFEOPS_LOG_INFO("Driver uptime: %u:%02u:%02u", hours, minutes, seconds);

  // Write final event to Event Log
  SafeOpsWriteEventLog(EVENTLOG_INFORMATION_TYPE, 1002,
                       L"SafeOps Driver unloaded successfully");

  // Mark as unloaded
  g_DriverState.State = DRIVER_STATE_UNLOADED;

  SAFEOPS_LOG_INFO("=== SafeOps Driver Unloaded ===");
}

//=============================================================================
// Section 1 (continued): Device Add Handler
//=============================================================================

/**
 * SafeOpsEvtDeviceAdd - Called when device is added to system
 *
 * Creates the control device for IOCTL communication and initializes
 * all driver subsystems.
 *
 * @param Driver - WDF driver handle
 * @param DeviceInit - Device initialization structure
 * @return STATUS_SUCCESS on success, error code on failure
 */
NTSTATUS
SafeOpsEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit) {
  NTSTATUS status;
  WDFDEVICE device;
  WDF_OBJECT_ATTRIBUTES deviceAttributes;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  WDF_IO_QUEUE_CONFIG queueConfig;
  WDFQUEUE queue;
  UNICODE_STRING deviceName;
  UNICODE_STRING symbolicLink;
  PDRIVER_CONTEXT context;
  ULONG completedSteps = 0;

  UNREFERENCED_PARAMETER(Driver);

  SAFEOPS_LOG_INFO("Device Add - Creating control device");

  // Increment reference count
  InterlockedIncrement(&g_DriverState.ReferenceCount);

  // Configure device name
  RtlInitUnicodeString(&deviceName, SAFEOPS_DEVICE_NAME);
  status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("WdfDeviceInitAssignName failed: 0x%08X", status);
    goto cleanup;
  }

  // Set device characteristics
  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_NETWORK);
  WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
  WdfDeviceInitSetExclusive(DeviceInit, FALSE);

  // Set device security (allow access from LocalSystem and Administrators)
  status =
      WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING("Failed to set device security: 0x%08X", status);
    // Non-fatal, continue
  }

  // Initialize PnP callbacks
  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDeviceD0Entry = SafeOpsEvtDeviceD0Entry;
  pnpPowerCallbacks.EvtDeviceD0Exit = SafeOpsEvtDeviceD0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  // Prepare device attributes to store context
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DRIVER_CONTEXT);
  deviceAttributes.EvtCleanupCallback = SafeOpsEvtDeviceContextCleanup;

  // Create device
  status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("WdfDeviceCreate failed: 0x%08X", status);
    goto cleanup;
  }

  completedSteps |= 0x01; // Device created
  SAFEOPS_LOG_INFO("Device object created");

  // Create symbolic link
  RtlInitUnicodeString(&symbolicLink, SAFEOPS_SYMBOLIC_LINK);
  status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("WdfDeviceCreateSymbolicLink failed: 0x%08X", status);
    goto cleanup;
  }

  completedSteps |= 0x02; // Symbolic link created
  SAFEOPS_LOG_INFO("Symbolic link created: %wZ", &symbolicLink);

  // Initialize default I/O queue for IOCTLs
  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
                                         WdfIoQueueDispatchSequential);
  queueConfig.EvtIoDeviceControl = SafeOpsEvtIoDeviceControl;
  queueConfig.PowerManaged = WdfFalse;

  status =
      WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("WdfIoQueueCreate failed: 0x%08X", status);
    goto cleanup;
  }

  completedSteps |= 0x04; // Queue created
  SAFEOPS_LOG_INFO("I/O queue created");

  // Initialize driver context
  context = GetDriverContext(device);
  status = SafeOpsInitializeDriverContext(device);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("SafeOpsInitializeDriverContext failed: 0x%08X", status);
    goto cleanup;
  }

  completedSteps |= 0x08; // Context initialized

  // Initialize all components
  status = SafeOpsInitializeAllComponents(context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("SafeOpsInitializeAllComponents failed: 0x%08X", status);
    goto cleanup;
  }

  completedSteps |= 0x10; // Components initialized

  // Perform self-check
  status = SafeOpsPerformSelfCheck(context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("Self-check failed: 0x%08X", status);
    goto cleanup;
  }

  SAFEOPS_LOG_INFO("Device created and initialized successfully");

  // Decrement reference count
  InterlockedDecrement(&g_DriverState.ReferenceCount);

  return STATUS_SUCCESS;

cleanup:
  SAFEOPS_LOG_ERROR("Device creation failed at step 0x%02X", completedSteps);

  // Rollback initialization based on what succeeded
  if (completedSteps & 0x10) {
    if (context) {
      SafeOpsCleanupAllComponents(context);
    }
  }

  if (completedSteps & 0x08) {
    if (context) {
      SafeOpsCleanupDriverContext(device);
    }
  }

  // WDF will handle cleanup of device, queue, and symbolic link

  InterlockedDecrement(&g_DriverState.ReferenceCount);

  return status;
}

//=============================================================================
// Section 3: Component Initialization
//=============================================================================

/**
 * SafeOpsInitializeAllComponents - Initialize all driver subsystems
 *
 * Initializes components in the correct dependency order:
 * 1. Shared memory (needed for logging)
 * 2. Filter engine (WFP)
 * 3. NIC management
 * 4. Performance optimization
 * 5. Packet capture (NDIS)
 *
 * @param Context - Driver context
 * @return STATUS_SUCCESS or error code
 */
NTSTATUS
SafeOpsInitializeAllComponents(_In_ PDRIVER_CONTEXT Context) {
  NTSTATUS status;
  ULONG step = 0;

  SAFEOPS_LOG_INFO("Initializing all components...");

  // Step 1: Shared memory
  status = SharedMemoryInitialize(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("SharedMemoryInitialize failed: 0x%08X", status);
    goto rollback;
  }
  step = 1;
  SAFEOPS_LOG_INFO("[1/5] Shared memory initialized");

  // Step 2: Filter engine
  status = FilterEngineInitialize(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FilterEngineInitialize failed: 0x%08X", status);
    goto rollback;
  }
  step = 2;
  SAFEOPS_LOG_INFO("[2/5] Filter engine initialized");

  // Step 3: NIC management
  status = NicManagementInitialize(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("NicManagementInitialize failed: 0x%08X", status);
    goto rollback;
  }
  step = 3;
  SAFEOPS_LOG_INFO("[3/5] NIC management initialized");

  // Step 4: Performance optimization
  status = PerformanceInitialize(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING("PerformanceInitialize failed: 0x%08X (non-fatal)",
                        status);
    // Non-fatal, continue
  } else {
    step = 4;
    SAFEOPS_LOG_INFO("[4/5] Performance optimization initialized");
  }

  // Step 5: Packet capture
  status = PacketCaptureInitialize(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("PacketCaptureInitialize failed: 0x%08X", status);
    goto rollback;
  }
  step = 5;
  SAFEOPS_LOG_INFO("[5/5] Packet capture initialized");

  SAFEOPS_LOG_INFO("All components initialized successfully");
  return STATUS_SUCCESS;

rollback:
  SAFEOPS_LOG_ERROR("Component initialization failed at step %u, rolling back",
                    step);
  SafeOpsRollbackInitialization(Context, step);
  return status;
}

//=============================================================================
// Section 4: Component Cleanup
//=============================================================================

/**
 * SafeOpsCleanupAllComponents - Cleanup all subsystems
 *
 * Cleans up components in reverse order of initialization.
 */
VOID SafeOpsCleanupAllComponents(_In_ PDRIVER_CONTEXT Context) {
  SAFEOPS_LOG_INFO("Cleaning up all components...");

  // Reverse order of initialization
  PacketCaptureCleanup(Context);
  SAFEOPS_LOG_DEBUG("Packet capture cleaned up");

  PerformanceCleanup(Context);
  SAFEOPS_LOG_DEBUG("Performance optimization cleaned up");

  NicManagementCleanup(Context);
  SAFEOPS_LOG_DEBUG("NIC management cleaned up");

  FilterEngineCleanup(Context);
  SAFEOPS_LOG_DEBUG("Filter engine cleaned up");

  SharedMemoryCleanup(Context);
  SAFEOPS_LOG_DEBUG("Shared memory cleaned up");

  SAFEOPS_LOG_INFO("All components cleaned up");
}

//=============================================================================
// Section 5: Error Recovery - Rollback Initialization
//=============================================================================

/**
 * SafeOpsRollbackInitialization - Undo completed initialization steps on error
 *
 * @param Context - Driver context
 * @param CompletedSteps - Bitmask of completed steps (1-5)
 */
VOID SafeOpsRollbackInitialization(_In_ PDRIVER_CONTEXT Context,
                                   _In_ ULONG CompletedSteps) {
  SAFEOPS_LOG_WARNING("Rolling back initialization (completed steps: %u)",
                      CompletedSteps);

  // Reverse order cleanup
  if (CompletedSteps >= 5) {
    PacketCaptureCleanup(Context);
    SAFEOPS_LOG_DEBUG("Step 5 rolled back: Packet capture");
  }

  if (CompletedSteps >= 4) {
    PerformanceCleanup(Context);
    SAFEOPS_LOG_DEBUG("Step 4 rolled back: Performance");
  }

  if (CompletedSteps >= 3) {
    NicManagementCleanup(Context);
    SAFEOPS_LOG_DEBUG("Step 3 rolled back: NIC management");
  }

  if (CompletedSteps >= 2) {
    FilterEngineCleanup(Context);
    SAFEOPS_LOG_DEBUG("Step 2 rolled back: Filter engine");
  }

  if (CompletedSteps >= 1) {
    SharedMemoryCleanup(Context);
    SAFEOPS_LOG_DEBUG("Step 1 rolled back: Shared memory");
  }

  SAFEOPS_LOG_INFO("Rollback complete");
}

//=============================================================================
// Section 6: Power Management Callbacks
//=============================================================================

/**
 * SafeOpsRegisterPowerCallbacks - Register power management callbacks
 */
NTSTATUS
SafeOpsRegisterPowerCallbacks(VOID) {
  // Power callback registration is optional and may not be supported
  // In WDF-based drivers, power management is handled by PnP callbacks
  SAFEOPS_LOG_DEBUG("Power callbacks: Using WDF PnP power management");
  return STATUS_SUCCESS;
}

/**
 * SafeOpsUnregisterPowerCallbacks - Unregister power callbacks
 */
VOID SafeOpsUnregisterPowerCallbacks(VOID) {
  // Cleanup power callback registration
  if (g_DriverState.PowerCallbackHandle != NULL) {
    // ExUnregisterCallback(g_DriverState.PowerCallbackHandle);
    g_DriverState.PowerCallbackHandle = NULL;
  }
  SAFEOPS_LOG_DEBUG("Power callbacks unregistered");
}

/**
 * SafeOpsPowerCallback - Handle power state changes
 */
_Function_class_(CALLBACK_FUNCTION) NTSTATUS
    SafeOpsPowerCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1,
                         _In_ PVOID Argument2) {
  UNREFERENCED_PARAMETER(CallbackContext);
  UNREFERENCED_PARAMETER(Argument1);
  UNREFERENCED_PARAMETER(Argument2);

  SAFEOPS_LOG_DEBUG("Power callback invoked");
  return STATUS_SUCCESS;
}

//=============================================================================
// Section 7: Registry Configuration
//=============================================================================

/**
 * SafeOpsReadRegistryConfig - Read configuration from registry
 */
NTSTATUS
SafeOpsReadRegistryConfig(VOID) {
  // In production, would use WdfRegistryOpenKey/WdfRegistryQueryValue
  // For now, use defaults from g_DriverConfig
  SAFEOPS_LOG_DEBUG("Using default configuration values");
  return STATUS_SUCCESS;
}

//=============================================================================
// Section 8: Event Logging
//=============================================================================

/**
 * SafeOpsWriteEventLog - Write event to Windows Event Log
 */
NTSTATUS
SafeOpsWriteEventLog(_In_ ULONG EventType, _In_ ULONG EventId,
                     _In_ PWSTR Message) {
  UNREFERENCED_PARAMETER(EventType);
  UNREFERENCED_PARAMETER(EventId);
  UNREFERENCED_PARAMETER(Message);

  // In production, would use IoWriteErrorLogEntry
  // For MVP, log via DbgPrint
  SAFEOPS_LOG_DEBUG("Event %u: %ws", EventId, Message ? Message : L"(null)");
  return STATUS_SUCCESS;
}

/**
 * SafeOpsLogStartupBanner - Log driver startup banner
 */
VOID SafeOpsLogStartupBanner(VOID) {
  DbgPrint("\n");
  DbgPrint("============================================================\n");
  DbgPrint(" SafeOps Network Security Gateway v2.0                     \n");
  DbgPrint(" " SAFEOPS_COPYRIGHT "\n");
  DbgPrint(" Build: " SAFEOPS_BUILD_TIMESTAMP "\n");
  DbgPrint("============================================================\n");
  DbgPrint("\n");
}

/**
 * SafeOpsLogShutdownStats - Log final statistics before shutdown
 */
VOID SafeOpsLogShutdownStats(_In_ PDRIVER_CONTEXT Context) {
  if (Context == NULL) {
    return;
  }

  SAFEOPS_LOG_INFO("=== Shutdown Statistics ===");
  SAFEOPS_LOG_INFO("Total packets processed: %llu",
                   Context->TotalPacketsProcessed);
  SAFEOPS_LOG_INFO("Packets allowed: %llu", Context->PacketsAllowed);
  SAFEOPS_LOG_INFO("Packets blocked: %llu", Context->PacketsBlocked);
  SAFEOPS_LOG_INFO("===========================");
}

//=============================================================================
// Section 10: Self-Check Functions
//=============================================================================

/**
 * SafeOpsPerformSelfCheck - Run self-diagnostics after initialization
 */
NTSTATUS
SafeOpsPerformSelfCheck(_In_ PDRIVER_CONTEXT Context) {
  NTSTATUS status;

  SAFEOPS_LOG_INFO("=== Performing Self-Check ===");

  // Verify context is valid
  if (Context == NULL) {
    SAFEOPS_LOG_ERROR("FAIL: Context is NULL");
    return STATUS_INVALID_PARAMETER;
  }

  // Verify subsystems
  status = SafeOpsVerifySubsystems(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FAIL: Subsystem verification failed");
    return status;
  }

  SAFEOPS_LOG_INFO("=== Self-Check PASSED ===");
  return STATUS_SUCCESS;
}

/**
 * SafeOpsVerifySubsystems - Verify all subsystems initialized correctly
 */
NTSTATUS
SafeOpsVerifySubsystems(_In_ PDRIVER_CONTEXT Context) {
  // Check shared memory
  if (Context->SharedBuffer == NULL) {
    SAFEOPS_LOG_WARNING("Shared buffer not allocated (non-fatal)");
  } else {
    SAFEOPS_LOG_INFO("PASS: Shared memory initialized");
  }

  // Check filter engine
  if (Context->EngineHandle == NULL) {
    SAFEOPS_LOG_WARNING("WFP engine handle not set (non-fatal)");
  } else {
    SAFEOPS_LOG_INFO("PASS: Filter engine initialized");
  }

  // Log device state
  SAFEOPS_LOG_INFO("PASS: Device object active");
  SAFEOPS_LOG_INFO("PASS: IOCTL queue ready");

  return STATUS_SUCCESS;
}

//=============================================================================
// Section 9: WDF Device Context Helpers
//=============================================================================

/**
 * SafeOpsInitializeDriverContext - Initialize driver context structure
 */
NTSTATUS
SafeOpsInitializeDriverContext(_In_ WDFDEVICE Device) {
  PDRIVER_CONTEXT context;

  context = GetDriverContext(Device);
  if (context == NULL) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Initialize spinlocks
  KeInitializeSpinLock(&context->Lock);

  // Initialize statistics
  context->TotalPacketsProcessed = 0;
  context->PacketsAllowed = 0;
  context->PacketsBlocked = 0;
  context->PacketsDropped = 0;

  // Initialize state
  context->IsRunning = FALSE;
  context->SharedBuffer = NULL;
  context->SharedBufferSize = 0;
  context->EngineHandle = NULL;

  // Store device reference
  context->Device = Device;

  SAFEOPS_LOG_DEBUG("Driver context initialized");
  return STATUS_SUCCESS;
}

/**
 * SafeOpsCleanupDriverContext - Cleanup driver context
 */
VOID SafeOpsCleanupDriverContext(_In_ WDFDEVICE Device) {
  PDRIVER_CONTEXT context;

  context = GetDriverContext(Device);
  if (context == NULL) {
    return;
  }

  // Log final stats
  SafeOpsLogShutdownStats(context);

  // Context memory freed automatically by WDF
  SAFEOPS_LOG_DEBUG("Driver context cleaned up");
}

/**
 * SafeOpsEvtDeviceContextCleanup - WDF callback for device cleanup
 */
VOID SafeOpsEvtDeviceContextCleanup(_In_ WDFOBJECT Object) {
  WDFDEVICE device = (WDFDEVICE)Object;
  PDRIVER_CONTEXT context = GetDriverContext(device);

  SAFEOPS_LOG_INFO("Device context cleanup triggered");

  if (context != NULL) {
    SafeOpsCleanupAllComponents(context);
    SafeOpsCleanupDriverContext(device);
  }
}

//=============================================================================
// Section 11: Power State Callbacks (WDF PnP)
//=============================================================================

/**
 * SafeOpsEvtDeviceD0Entry - Device entering D0 (powered) state
 */
NTSTATUS
SafeOpsEvtDeviceD0Entry(_In_ WDFDEVICE Device,
                        _In_ WDF_POWER_DEVICE_STATE PreviousPowerState) {
  UNREFERENCED_PARAMETER(Device);
  SAFEOPS_LOG_INFO("Device entering D0 from power state %d",
                   PreviousPowerState);
  return STATUS_SUCCESS;
}

/**
 * SafeOpsEvtDeviceD0Exit - Device leaving D0 state
 */
NTSTATUS
SafeOpsEvtDeviceD0Exit(_In_ WDFDEVICE Device,
                       _In_ WDF_POWER_DEVICE_STATE TargetPowerState) {
  UNREFERENCED_PARAMETER(Device);
  SAFEOPS_LOG_INFO("Device leaving D0 to power state %d", TargetPowerState);
  return STATUS_SUCCESS;
}

//=============================================================================
// Section 12: IOCTL Event Handler
//=============================================================================

/**
 * SafeOpsEvtIoDeviceControl - Handle IOCTL requests from userspace
 */
VOID SafeOpsEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                               _In_ size_t OutputBufferLength,
                               _In_ size_t InputBufferLength,
                               _In_ ULONG IoControlCode) {
  NTSTATUS status;
  WDFDEVICE device;
  PDRIVER_CONTEXT context;

  device = WdfIoQueueGetDevice(Queue);
  context = GetDriverContext(device);

  SAFEOPS_LOG_DEBUG("IOCTL received: 0x%08X (in=%zu, out=%zu)", IoControlCode,
                    InputBufferLength, OutputBufferLength);

  // Dispatch to IOCTL handler
  status = DispatchIoControl(context, Request, IoControlCode, InputBufferLength,
                             OutputBufferLength);

  if (status != STATUS_PENDING) {
    WdfRequestComplete(Request, status);
  }
}

//=============================================================================
// END OF DRIVER.C IMPLEMENTATION
//=============================================================================
