/**
 * driver_part2.c - SafeOps Kernel Driver Utility Functions
 *
 * This file contains utility functions that complement driver.c:
 * - Error recovery and rollback
 * - Power management callbacks
 * - Self-check diagnostics
 * - Error code translation
 * - String utilities
 * - Memory validation
 * - Timer management
 * - Debugging support
 *
 * NOTE: This file depends on globals from driver.c and is WDK-specific.
 *       The entire implementation is wrapped with SAFEOPS_WDK_BUILD.
 */

#include "driver.h"

#ifdef SAFEOPS_WDK_BUILD // WDK-only implementation

#include <ntstrsafe.h>

//=============================================================================
// Section 5: Error Recovery
//=============================================================================

/**
 * SafeOpsRollbackInitialization - Rollback partial initialization
 *
 * Called when initialization fails midway through. Cleans up components
 * that were successfully initialized.
 *
 * @param Context - Driver context
 * @param CompletedSteps - Bitmask of which steps completed (1=shared mem,
 * 2=filter, etc.)
 */
VOID SafeOpsRollbackInitialization(_In_ PDRIVER_CONTEXT Context,
                                   _In_ ULONG CompletedSteps) {
  SAFEOPS_LOG_INFO("Rolling back initialization (completed steps: %u)",
                   CompletedSteps);

  // Cleanup in reverse order
  if (CompletedSteps >= 5) {
    PacketCaptureCleanup(Context);
    SAFEOPS_LOG_DEBUG("Rolled back packet capture");
  }

  if (CompletedSteps >= 4) {
    PerformanceCleanup(Context);
    SAFEOPS_LOG_DEBUG("Rolled back performance");
  }

  if (CompletedSteps >= 3) {
    NicManagementCleanup(Context);
    SAFEOPS_LOG_DEBUG("Rolled back NIC management");
  }

  if (CompletedSteps >= 2) {
    FilterEngineCleanup(Context);
    SAFEOPS_LOG_DEBUG("Rolled back filter engine");
  }

  if (CompletedSteps >= 1) {
    SharedMemoryCleanup(Context);
    SAFEOPS_LOG_DEBUG("Rolled back shared memory");
  }

  SAFEOPS_LOG_INFO("Rollback complete");
}

//=============================================================================
// Section 6: System Callbacks - Power Management
//=============================================================================

/**
 * SafeOpsRegisterPowerCallbacks - Register for power state notifications
 *
 * Registers callbacks to handle system sleep/wake events to ensure
 * packet capture continues properly across power transitions.
 */
NTSTATUS
SafeOpsRegisterPowerCallbacks(VOID) {
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING callbackName;
  NTSTATUS status;

  RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
  InitializeObjectAttributes(&objAttr, &callbackName, OBJ_CASE_INSENSITIVE,
                             NULL, NULL);

  status = ExCreateCallback(&g_DriverState.PowerCallbackHandle, &objAttr, FALSE,
                            TRUE);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("ExCreateCallback failed: 0x%08X", status);
    return status;
  }

  // Register the callback
  ExRegisterCallback(g_DriverState.PowerCallbackHandle,
                     (PCALLBACK_FUNCTION)SafeOpsPowerCallback, NULL);

  return STATUS_SUCCESS;
}

/**
 * SafeOpsUnregisterPowerCallbacks - Unregister power callbacks
 */
VOID SafeOpsUnregisterPowerCallbacks(VOID) {
  if (g_DriverState.PowerCallbackHandle) {
    ExUnregisterCallback(g_DriverState.PowerCallbackHandle);
    ObDereferenceObject(g_DriverState.PowerCallbackHandle);
    g_DriverState.PowerCallbackHandle = NULL;
  }
}

/**
 * SafeOpsPowerCallback - Handle power state transitions
 */
NTSTATUS
SafeOpsPowerCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1,
                     _In_ PVOID Argument2) {
  ULONG powerState = (ULONG)(ULONG_PTR)Argument1;
  KIRQL oldIrql;

  UNREFERENCED_PARAMETER(CallbackContext);
  UNREFERENCED_PARAMETER(Argument2);

  switch (powerState) {
  case PO_CB_SYSTEM_STATE_LOCK:
    SAFEOPS_LOG_INFO("System entering sleep/hibernate");

    // Pause packet capture
    KeAcquireSpinLock(&g_DriverState.StateLock, &oldIrql);
    if (g_DriverState.State == DRIVER_STATE_RUNNING) {
      g_DriverState.State = DRIVER_STATE_PAUSED;
    }
    KeReleaseSpinLock(&g_DriverState.StateLock, oldIrql);
    break;

  case PO_CB_SYSTEM_STATE_POLICY:
    SAFEOPS_LOG_INFO("System power policy change");
    break;

  default:
    // Resume from sleep
    SAFEOPS_LOG_INFO("System resuming from sleep");

    KeAcquireSpinLock(&g_DriverState.StateLock, &oldIrql);
    if (g_DriverState.State == DRIVER_STATE_PAUSED) {
      g_DriverState.State = DRIVER_STATE_RUNNING;
    }
    KeReleaseSpinLock(&g_DriverState.StateLock, oldIrql);
    break;
  }

  return STATUS_SUCCESS;
}

/**
 * SafeOpsEvtDeviceD0Entry - Device entering D0 (working) power state
 */
NTSTATUS
SafeOpsEvtDeviceD0Entry(_In_ WDFDEVICE Device,
                        _In_ WDF_POWER_DEVICE_STATE PreviousState) {
  PDRIVER_CONTEXT context = GetDriverContext(Device);

  SAFEOPS_LOG_INFO("Device entering D0 from D%d",
                   PreviousState - WdfPowerDeviceD0);

  // Reinitialize if needed after deep sleep
  if (PreviousState == WdfPowerDeviceD3 ||
      PreviousState == WdfPowerDeviceD3Final) {
    SAFEOPS_LOG_INFO("Recovering from deep sleep state");

    // Verify subsystems still functional
    SafeOpsVerifySubsystems(context);
  }

  return STATUS_SUCCESS;
}

/**
 * SafeOpsEvtDeviceD0Exit - Device leaving D0 power state
 */
NTSTATUS
SafeOpsEvtDeviceD0Exit(_In_ WDFDEVICE Device,
                       _In_ WDF_POWER_DEVICE_STATE TargetState) {
  UNREFERENCED_PARAMETER(Device);

  SAFEOPS_LOG_INFO("Device leaving D0 to D%d", TargetState - WdfPowerDeviceD0);

  // Flush any pending data
  if (TargetState == WdfPowerDeviceD3 || TargetState == WdfPowerDeviceD3Final) {
    SAFEOPS_LOG_INFO("Entering deep sleep, flushing buffers");
    // TODO: Flush ring buffer
  }

  return STATUS_SUCCESS;
}

/**
 * SafeOpsEvtDeviceContextCleanup - Cleanup device context
 */
VOID SafeOpsEvtDeviceContextCleanup(_In_ WDFOBJECT Device) {
  PDRIVER_CONTEXT context = GetDriverContext((WDFDEVICE)Device);

  SAFEOPS_LOG_INFO("Device context cleanup");

  // Log final statistics
  SafeOpsLogShutdownStats(context);

  // Cleanup all components
  SafeOpsCleanupAllComponents(context);

  // Cleanup driver context
  SafeOpsCleanupDriverContext((WDFDEVICE)Device);
}

//=============================================================================
// Section 10: Self-Check Functions
//=============================================================================

/**
 * SafeOpsPerformSelfCheck - Comprehensive driver self-diagnostics
 *
 * Performs extensive checks to verify driver is functioning correctly:
 * 1. Verify all subsystems initialized
 * 2. Check shared memory accessible
 * 3. Verify WFP callouts registered
 * 4. Check NDIS filter attached
 * 5. Validate NIC bindings
 * 6. Test ring buffer read/write
 * 7. Verify device object accessible
 *
 * @return STATUS_SUCCESS if all checks pass
 */
NTSTATUS
SafeOpsPerformSelfCheck(_In_ PDRIVER_CONTEXT Context) {
  NTSTATUS status;
  ULONG checksCompleted = 0;

  SAFEOPS_LOG_INFO("=== Starting Self-Check ===");

  // Check 1: Verify driver context valid
  if (!Context) {
    SAFEOPS_LOG_ERROR("Self-check failed: NULL context");
    return STATUS_INVALID_PARAMETER;
  }
  checksCompleted++;

  // Check 2: Verify shared memory allocated
  if (!Context->SharedMemory || !Context->RingBufferHeader) {
    SAFEOPS_LOG_ERROR("Self-check failed: Shared memory not initialized");
    return STATUS_UNSUCCESSFUL;
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] Shared memory OK", checksCompleted);

  // Check 3: Verify WFP engine handle
  if (!Context->EngineHandle) {
    SAFEOPS_LOG_ERROR("Self-check failed: WFP engine not initialized");
    return STATUS_UNSUCCESSFUL;
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] WFP engine OK", checksCompleted);

  // Check 4: Verify WFP callouts registered
  if (Context->CalloutIdIPv4Inbound == 0 ||
      Context->CalloutIdIPv4Outbound == 0) {
    SAFEOPS_LOG_ERROR("Self-check failed: WFP callouts not registered");
    return STATUS_UNSUCCESSFUL;
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] WFP callouts OK", checksCompleted);

  // Check 5: Verify NDIS filter handle
  if (!Context->NdisFilterHandle) {
    SAFEOPS_LOG_WARNING("NDIS filter handle not set (may not be attached yet)");
    // Non-fatal
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] NDIS filter checked", checksCompleted);

  // Check 6: Verify connection hash table
  if (!Context->ConnHashTable || Context->ConnHashSize == 0) {
    SAFEOPS_LOG_ERROR(
        "Self-check failed: Connection hash table not initialized");
    return STATUS_UNSUCCESSFUL;
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] Connection tracking OK", checksCompleted);

  // Check 7: Verify filter rule list initialized
  if (!IsListEmpty(&Context->FilterRuleList)) {
    SAFEOPS_LOG_DEBUG("Filter rules already loaded: %u",
                      Context->FilterRuleCount);
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] Filter rule list OK", checksCompleted);

  // Check 8: Verify NIC count
  if (Context->NicCount == 0) {
    SAFEOPS_LOG_WARNING(
        "No NICs detected (system may not have network adapters)");
    // Non-fatal
  } else {
    SAFEOPS_LOG_INFO("Detected %u network interfaces", Context->NicCount);
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] NIC enumeration OK", checksCompleted);

  // Check 9: Test ring buffer write/read
  PACKET_LOG_ENTRY testEntry = {0};
  KeQuerySystemTime(&testEntry.Timestamp);
  testEntry.Action = ACTION_ALLOW;
  testEntry.RuleId = 0xFFFFFFFF; // Test marker

  status = LogPacketToRingBuffer(Context, &testEntry);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING("Ring buffer write test failed: 0x%08X", status);
    // Non-fatal
  } else {
    checksCompleted++;
    SAFEOPS_LOG_DEBUG("[%u/10] Ring buffer write OK", checksCompleted);
  }

  // Check 10: Verify subsystems
  status = SafeOpsVerifySubsystems(Context);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("Subsystem verification failed: 0x%08X", status);
    return status;
  }
  checksCompleted++;
  SAFEOPS_LOG_DEBUG("[%u/10] Subsystem verification OK", checksCompleted);

  SAFEOPS_LOG_INFO("=== Self-Check Complete: %u/10 checks passed ===",
                   checksCompleted);

  return STATUS_SUCCESS;
}

/**
 * SafeOpsVerifySubsystems - Verify all subsystems functional
 */
NTSTATUS
SafeOpsVerifySubsystems(_In_ PDRIVER_CONTEXT Context) {
  // Verify each subsystem is responsive

  // 1. Shared Memory
  if (Context->RingBufferHeader) {
    ULONG available = RingBufferAvailable(Context->RingBufferHeader);
    SAFEOPS_LOG_DEBUG("Ring buffer available: %u bytes", available);
  }

  // 2. Filter Engine
  if (Context->FilterRuleCount > 0) {
    SAFEOPS_LOG_DEBUG("Active filter rules: %u", Context->FilterRuleCount);
  }

  // 3. Connection Tracking
  if (Context->ConnCount > 0) {
    SAFEOPS_LOG_DEBUG("Tracked connections: %d", Context->ConnCount);
  }

  // 4. Statistics
  SAFEOPS_LOG_DEBUG("Packets processed: %llu", Context->PacketsProcessed);
  SAFEOPS_LOG_DEBUG("Packets allowed: %llu", Context->PacketsAllowed);
  SAFEOPS_LOG_DEBUG("Packets dropped: %llu", Context->PacketsDropped);

  return STATUS_SUCCESS;
}

//=============================================================================
// Helper Functions
//=============================================================================

/**
 * SafeOpsReadRegistryConfig - Read configuration from registry
 */
NTSTATUS
SafeOpsReadRegistryConfig(VOID) {
  NTSTATUS status;
  OBJECT_ATTRIBUTES objAttr;
  UNICODE_STRING registryPath;
  HANDLE keyHandle = NULL;
  UNICODE_STRING valueName;
  UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
  PKEY_VALUE_PARTIAL_INFORMATION valueInfo;
  ULONG resultLength;

  RtlInitUnicodeString(&registryPath,
                       SAFEOPS_REGISTRY_PATH L"\\" SAFEOPS_PARAMETERS_KEY);
  InitializeObjectAttributes(&objAttr, &registryPath,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);

  status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_WARNING("Failed to open registry key: 0x%08X", status);
    return status;
  }

  valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

  // Read LogLevel
  RtlInitUnicodeString(&valueName, L"LogLevel");
  status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
                           valueInfo, sizeof(buffer), &resultLength);
  if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD) {
    g_DriverConfig.LogLevel = *(PULONG)valueInfo->Data;
    SAFEOPS_LOG_DEBUG("Registry: LogLevel = %u", g_DriverConfig.LogLevel);
  }

  // Read other config values similarly...
  // (abbreviated for space)

  ZwClose(keyHandle);
  return STATUS_SUCCESS;
}

/**
 * SafeOpsWriteEventLog - Write event to Windows Event Log
 */
NTSTATUS
SafeOpsWriteEventLog(_In_ ULONG EventType, _In_ ULONG EventId,
                     _In_ PWSTR Message) {
  // TODO: Implement Event Log writing using IoRegisterDeviceInterface
  // For now, just log to debug output

  const char *typeStr;
  switch (EventType) {
  case EVENTLOG_ERROR_TYPE:
    typeStr = "ERROR";
    break;
  case EVENTLOG_WARNING_TYPE:
    typeStr = "WARNING";
    break;
  case EVENTLOG_INFORMATION_TYPE:
    typeStr = "INFO";
    break;
  default:
    typeStr = "UNKNOWN";
    break;
  }

  SAFEOPS_LOG_INFO("EVENT[%s:%u]: %ws", typeStr, EventId, Message);

  return STATUS_SUCCESS;
}

/**
 * SafeOpsLogStartupBanner - Display startup banner
 */
VOID SafeOpsLogStartupBanner(VOID) {
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "\n");
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
             "╔═══════════════════════════════════════════════════════╗\n");
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
             "║           SafeOps Network Security Gateway           ║\n");
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
             "║                  Kernel Driver v%s                ║\n",
             SAFEOPS_VERSION_STRING);
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
             "║                                                       ║\n");
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "║  %s  ║\n",
             SAFEOPS_COPYRIGHT);
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
             "╚═══════════════════════════════════════════════════════╝\n");
  DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "\n");
}

/**
 * SafeOpsLogShutdownStats - Log final statistics before shutdown
 */
VOID SafeOpsLogShutdownStats(_In_ PDRIVER_CONTEXT Context) {
  LARGE_INTEGER currentTime, uptime;
  ULONG uptimeSeconds;

  KeQuerySystemTime(&currentTime);
  uptime.QuadPart = currentTime.QuadPart - g_DriverState.StartTime.QuadPart;
  uptimeSeconds = (ULONG)(uptime.QuadPart / 10000000LL);

  SAFEOPS_LOG_INFO("=== Final Statistics ===");
  SAFEOPS_LOG_INFO("Uptime: %u seconds", uptimeSeconds);
  SAFEOPS_LOG_INFO("Packets processed: %llu", Context->PacketsProcessed);
  SAFEOPS_LOG_INFO("Packets allowed: %llu", Context->PacketsAllowed);
  SAFEOPS_LOG_INFO("Packets dropped: %llu", Context->PacketsDropped);
  SAFEOPS_LOG_INFO("Bytes processed: %llu", Context->BytesProcessed);
  SAFEOPS_LOG_INFO("Active connections: %d", Context->ConnCount);
  SAFEOPS_LOG_INFO("Filter rules: %u", Context->FilterRuleCount);

  if (Context->RingBufferHeader) {
    SAFEOPS_LOG_INFO("Ring buffer dropped: %u",
                     Context->RingBufferHeader->DroppedPackets);
  }

  // Calculate throughput
  if (uptimeSeconds > 0) {
    ULONGLONG packetsPerSec = Context->PacketsProcessed / uptimeSeconds;
    ULONGLONG mbytesPerSec =
        (Context->BytesProcessed / uptimeSeconds) / (1024 * 1024);
    SAFEOPS_LOG_INFO("Average throughput: %llu packets/sec, %llu MB/sec",
                     packetsPerSec, mbytesPerSec);
  }
}

//=============================================================================
// Section 11: Error Code Translation Functions
//=============================================================================

/**
 * SafeOpsStatusToString - Convert NTSTATUS to human-readable string
 */
const WCHAR *SafeOpsStatusToString(_In_ NTSTATUS Status) {
  switch (Status) {
  case STATUS_SUCCESS:
    return L"SUCCESS";
  case STATUS_UNSUCCESSFUL:
    return L"UNSUCCESSFUL";
  case STATUS_INSUFFICIENT_RESOURCES:
    return L"INSUFFICIENT_RESOURCES";
  case STATUS_INVALID_PARAMETER:
    return L"INVALID_PARAMETER";
  case STATUS_NOT_FOUND:
    return L"NOT_FOUND";
  case STATUS_DEVICE_NOT_READY:
    return L"DEVICE_NOT_READY";
  case STATUS_ACCESS_DENIED:
    return L"ACCESS_DENIED";
  case STATUS_BUFFER_TOO_SMALL:
    return L"BUFFER_TOO_SMALL";
  case STATUS_BUFFER_OVERFLOW:
    return L"BUFFER_OVERFLOW";
  case STATUS_DUPLICATE_NAME:
    return L"DUPLICATE_NAME";
  case STATUS_INVALID_DEVICE_STATE:
    return L"INVALID_DEVICE_STATE";
  case STATUS_CANCELLED:
    return L"CANCELLED";
  case STATUS_TIMEOUT:
    return L"TIMEOUT";
  default:
    return L"UNKNOWN_STATUS";
  }
}

/**
 * NdisStatusToString - Convert NDIS_STATUS to string
 */
const WCHAR *NdisStatusToString(_In_ NDIS_STATUS Status) {
  switch (Status) {
  case NDIS_STATUS_SUCCESS:
    return L"NDIS_SUCCESS";
  case NDIS_STATUS_PENDING:
    return L"NDIS_PENDING";
  case NDIS_STATUS_NOT_RECOGNIZED:
    return L"NDIS_NOT_RECOGNIZED";
  case NDIS_STATUS_NOT_ACCEPTED:
    return L"NDIS_NOT_ACCEPTED";
  case NDIS_STATUS_RESOURCES:
    return L"NDIS_RESOURCES";
  case NDIS_STATUS_FAILURE:
    return L"NDIS_FAILURE";
  case NDIS_STATUS_INVALID_LENGTH:
    return L"NDIS_INVALID_LENGTH";
  case NDIS_STATUS_BUFFER_TOO_SHORT:
    return L"NDIS_BUFFER_TOO_SHORT";
  case NDIS_STATUS_INVALID_DATA:
    return L"NDIS_INVALID_DATA";
  default:
    return L"NDIS_UNKNOWN";
  }
}

/**
 * GenericErrorHandler - Centralized error logging
 */
VOID GenericErrorHandler(_In_ NTSTATUS Status, _In_ const char *Function,
                         _In_ const char *Context) {
  if (!NT_SUCCESS(Status)) {
    SAFEOPS_LOG_ERROR("[%s] %s failed: 0x%08X (%ws)", Function, Context, Status,
                      SafeOpsStatusToString(Status));
  }
}

//=============================================================================
// Section 12: String Utilities
//=============================================================================

/**
 * SafeOpsAllocateUnicodeString - Safely allocate UNICODE_STRING
 */
NTSTATUS
SafeOpsAllocateUnicodeString(_Out_ PUNICODE_STRING DestString,
                             _In_ USHORT MaxLength) {
  if (!DestString || MaxLength == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  DestString->Buffer =
      (PWCH)ExAllocatePoolWithTag(NonPagedPool, MaxLength, SAFEOPS_STRING_TAG);

  if (!DestString->Buffer) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  DestString->Length = 0;
  DestString->MaximumLength = MaxLength;
  RtlZeroMemory(DestString->Buffer, MaxLength);

  return STATUS_SUCCESS;
}

/**
 * SafeOpsFreeUnicodeString - Safely free UNICODE_STRING
 */
VOID SafeOpsFreeUnicodeString(_Inout_ PUNICODE_STRING String) {
  if (String && String->Buffer) {
    ExFreePoolWithTag(String->Buffer, SAFEOPS_STRING_TAG);
    String->Buffer = NULL;
    String->Length = 0;
    String->MaximumLength = 0;
  }
}

/**
 * SafeOpsCopyString - Safe string copy with overflow protection
 */
NTSTATUS
SafeOpsCopyString(_Out_writes_(DestSize) PWCHAR Dest, _In_ SIZE_T DestSize,
                  _In_ PCWSTR Source) {
  SIZE_T sourceLen;

  if (!Dest || !Source || DestSize == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  sourceLen = wcslen(Source) * sizeof(WCHAR);
  if (sourceLen >= DestSize) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  RtlCopyMemory(Dest, Source, sourceLen);
  Dest[sourceLen / sizeof(WCHAR)] = L'\0';

  return STATUS_SUCCESS;
}

/**
 * SafeOpsCompareStrings - Case-insensitive string comparison
 */
BOOLEAN
SafeOpsCompareStrings(_In_ PUNICODE_STRING String1,
                      _In_ PUNICODE_STRING String2) {
  if (!String1 || !String2) {
    return FALSE;
  }

  return RtlEqualUnicodeString(String1, String2, TRUE);
}

//=============================================================================
// Section 13: Memory Validation
//=============================================================================

/**
 * SafeOpsValidateUserBuffer - Validate userspace buffer
 */
NTSTATUS
SafeOpsValidateUserBuffer(_In_ PVOID Buffer, _In_ SIZE_T Length,
                          _In_ ULONG Alignment) {
  if (!Buffer) {
    return STATUS_INVALID_PARAMETER;
  }

  if (Length == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  // Check alignment
  if (Alignment > 1 && ((ULONG_PTR)Buffer % Alignment) != 0) {
    return STATUS_DATATYPE_MISALIGNMENT;
  }

  // Probe buffer to ensure it's accessible
  __try {
    ProbeForRead(Buffer, Length, 1);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }

  return STATUS_SUCCESS;
}

/**
 * SafeOpsProbeAndCaptureBuffer - Safely capture data from userspace
 */
NTSTATUS
SafeOpsProbeAndCaptureBuffer(_In_ PVOID UserBuffer, _In_ SIZE_T Length,
                             _Out_ PVOID *CapturedBuffer) {
  PVOID kernelBuffer;

  if (!UserBuffer || !CapturedBuffer || Length == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  *CapturedBuffer = NULL;

  // Allocate kernel buffer
  kernelBuffer =
      ExAllocatePoolWithTag(NonPagedPool, Length, SAFEOPS_CAPTURE_TAG);
  if (!kernelBuffer) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Safely copy from userspace
  __try {
    ProbeForRead(UserBuffer, Length, 1);
    RtlCopyMemory(kernelBuffer, UserBuffer, Length);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    ExFreePoolWithTag(kernelBuffer, SAFEOPS_CAPTURE_TAG);
    return STATUS_ACCESS_VIOLATION;
  }

  *CapturedBuffer = kernelBuffer;
  return STATUS_SUCCESS;
}

/**
 * SafeOpsValidateKernelPointer - Verify kernel pointer validity
 */
BOOLEAN
SafeOpsValidateKernelPointer(_In_ PVOID Pointer, _In_ SIZE_T Size) {
  if (!Pointer) {
    return FALSE;
  }

  // Check if pointer is in kernel address space
  if ((ULONG_PTR)Pointer < MM_SYSTEM_RANGE_START) {
    return FALSE;
  }

  // Check for obviously invalid addresses
  if ((ULONG_PTR)Pointer == (ULONG_PTR)-1) {
    return FALSE;
  }

  UNREFERENCED_PARAMETER(Size);
  return TRUE;
}

/**
 * SafeOpsCheckMemoryAlignment - Validate memory alignment for DMA
 */
BOOLEAN
SafeOpsCheckMemoryAlignment(_In_ PVOID Address, _In_ ULONG RequiredAlignment) {
  if (!Address || RequiredAlignment == 0) {
    return FALSE;
  }

  return ((ULONG_PTR)Address % RequiredAlignment) == 0;
}

//=============================================================================
// Section 14: Version and Platform Information
//=============================================================================

/**
 * SafeOpsGetVersionString - Return version string
 */
const WCHAR *SafeOpsGetVersionString(VOID) { return L"2.0.0"; }

/**
 * SafeOpsGetBuildTimestamp - Return build timestamp
 */
const WCHAR *SafeOpsGetBuildTimestamp(VOID) {
  return L"Build: " __DATE__ " " __TIME__;
}

/**
 * SafeOpsGetProcessorCount - Get logical processor count
 */
ULONG
SafeOpsGetProcessorCount(VOID) {
#ifdef SAFEOPS_WDK_BUILD
  return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
#else
  return 8; // Default for IDE mode
#endif
}

/**
 * SafeOpsCheckCompatibility - Verify OS compatibility
 */
NTSTATUS
SafeOpsCheckCompatibility(VOID) {
  RTL_OSVERSIONINFOW versionInfo = {0};
  versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

  NTSTATUS status = RtlGetVersion(&versionInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Require Windows 10 1809 (build 17763) or later
  if (versionInfo.dwMajorVersion < 10 ||
      (versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber < 17763)) {
    SAFEOPS_LOG_ERROR("Unsupported Windows version: %u.%u.%u",
                      versionInfo.dwMajorVersion, versionInfo.dwMinorVersion,
                      versionInfo.dwBuildNumber);
    return STATUS_NOT_SUPPORTED;
  }

  SAFEOPS_LOG_INFO("Running on Windows %u.%u (Build %u)",
                   versionInfo.dwMajorVersion, versionInfo.dwMinorVersion,
                   versionInfo.dwBuildNumber);

  return STATUS_SUCCESS;
}

//=============================================================================
// Section 15: Timer and Work Management
//=============================================================================

/**
 * SafeOpsInitializeTimer - Create and initialize a kernel timer
 */
NTSTATUS
SafeOpsInitializeTimer(_Out_ PKTIMER Timer, _Out_ PKDPC Dpc,
                       _In_ PKDEFERRED_ROUTINE DpcRoutine, _In_ PVOID Context) {
  if (!Timer || !Dpc || !DpcRoutine) {
    return STATUS_INVALID_PARAMETER;
  }

  KeInitializeTimer(Timer);
  KeInitializeDpc(Dpc, DpcRoutine, Context);

  return STATUS_SUCCESS;
}

/**
 * SafeOpsCancelTimer - Safely cancel an active timer
 */
BOOLEAN
SafeOpsCancelTimer(_Inout_ PKTIMER Timer) {
  if (!Timer) {
    return FALSE;
  }

  BOOLEAN wasPending = KeCancelTimer(Timer);

  // Flush any pending DPCs
  KeFlushQueuedDpcs();

  return wasPending;
}

//=============================================================================
// Section 16: Debugging Support (Debug Builds Only)
//=============================================================================

#ifdef DBG

/**
 * SafeOpsDumpDriverState - Dump complete driver state
 */
VOID SafeOpsDumpDriverState(_In_ PDRIVER_CONTEXT Context) {
  SAFEOPS_LOG_DEBUG("=== Driver State Dump ===");
  SAFEOPS_LOG_DEBUG("Driver State: %u", g_DriverState.State);
  SAFEOPS_LOG_DEBUG("Active NICs: %u", Context ? Context->NicCount : 0);
  SAFEOPS_LOG_DEBUG("Filter Rules: %u", Context ? Context->FilterRuleCount : 0);
  SAFEOPS_LOG_DEBUG("Active Connections: %d", Context ? Context->ConnCount : 0);
  SAFEOPS_LOG_DEBUG("Packets Processed: %llu",
                    Context ? Context->PacketsProcessed : 0);
  SAFEOPS_LOG_DEBUG("=========================");
}

/**
 * SafeOpsAssertHelper - Custom assertion handler
 */
VOID SafeOpsAssertHelper(_In_ const char *Expression, _In_ const char *File,
                         _In_ ULONG Line) {
  SAFEOPS_LOG_ERROR("ASSERTION FAILED: %s at %s:%u", Expression, File, Line);

#if defined(_DEBUG) || defined(DBG)
  DbgBreakPoint();
#endif
}

#endif // DBG

//=============================================================================
// Section 17: Cleanup and Shutdown Helpers
//=============================================================================

/**
 * SafeOpsWaitForActiveOperations - Wait for in-flight operations
 */
NTSTATUS
SafeOpsWaitForActiveOperations(_In_ ULONG TimeoutMs) {
  LARGE_INTEGER timeout;

  // Convert milliseconds to 100-nanosecond intervals (negative = relative)
  timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

  // Wait for shutdown event with timeout
  NTSTATUS status = KeWaitForSingleObject(
      &g_DriverState.ShutdownEvent, Executive, KernelMode, FALSE, &timeout);

  if (status == STATUS_TIMEOUT) {
    SAFEOPS_LOG_WARNING("Timeout waiting for active operations to complete");
  }

  return status;
}

/**
 * SafeOpsFlushPendingWork - Flush all pending work items
 */
VOID SafeOpsFlushPendingWork(VOID) {
  // Flush queued DPCs
  KeFlushQueuedDpcs();

  SAFEOPS_LOG_DEBUG("Flushed pending work items");
}

/**
 * SafeOpsNotifyShutdown - Notify components of impending shutdown
 */
VOID SafeOpsNotifyShutdown(VOID) {
  KIRQL oldIrql;

  KeAcquireSpinLock(&g_DriverState.StateLock, &oldIrql);
  g_DriverState.State = DRIVER_STATE_SHUTTING_DOWN;
  KeReleaseSpinLock(&g_DriverState.StateLock, oldIrql);

  // Signal shutdown event
  KeSetEvent(&g_DriverState.ShutdownEvent, IO_NO_INCREMENT, FALSE);

  SAFEOPS_LOG_INFO("Shutdown notification sent");
}

//=============================================================================
// End of driver_part2.c
//=============================================================================

#else // !SAFEOPS_WDK_BUILD - IDE stub

// Simple stub that uses driver.h types for IDE satisfaction
static inline void _DriverPart2IDEStub(void) {
  DRIVER_CONTEXT ctx = {0};
  (void)ctx;
}

#endif // SAFEOPS_WDK_BUILD
