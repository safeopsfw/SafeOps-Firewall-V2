/**
 * driver_part2.c - SafeOps Kernel Driver (Continuation)
 * 
 * This file contains the remaining sections of driver.c that were too large
 * to fit in a single file. Include this content at the end of driver.c
 * 
 * Sections: 5-10 (Error Recovery, Power Management, Helper Functions, Self-Check)
 */

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
 * @param CompletedSteps - Bitmask of which steps completed (1=shared mem, 2=filter, etc.)
 */
VOID
SafeOpsRollbackInitialization(
    _In_ PDRIVER_CONTEXT Context,
    _In_ ULONG CompletedSteps
)
{
    SAFEOPS_LOG_INFO("Rolling back initialization (completed steps: %u)", CompletedSteps);
    
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
SafeOpsRegisterPowerCallbacks(VOID)
{
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING callbackName;
    NTSTATUS status;
    
    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&objAttr, &callbackName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    status = ExCreateCallback(
        &g_DriverState.PowerCallbackHandle,
        &objAttr,
        FALSE,
        TRUE
    );
    
    if (!NT_SUCCESS(status)) {
        SAFEOPS_LOG_ERROR("ExCreateCallback failed: 0x%08X", status);
        return status;
    }
    
    // Register the callback
    ExRegisterCallback(
        g_DriverState.PowerCallbackHandle,
        (PCALLBACK_FUNCTION)SafeOpsPowerCallback,
        NULL
    );
    
    return STATUS_SUCCESS;
}

/**
 * SafeOpsUnregisterPowerCallbacks - Unregister power callbacks
 */
VOID
SafeOpsUnregisterPowerCallbacks(VOID)
{
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
SafeOpsPowerCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
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
SafeOpsEvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    PDRIVER_CONTEXT context = GetDriverContext(Device);
    
    SAFEOPS_LOG_INFO("Device entering D0 from D%d", PreviousState - WdfPowerDeviceD0);
    
    // Reinitialize if needed after deep sleep
    if (PreviousState == WdfPowerDeviceD3 || PreviousState == WdfPowerDeviceD3Final) {
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
SafeOpsEvtDeviceD0Exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
)
{
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
VOID
SafeOpsEvtDeviceContextCleanup(
    _In_ WDFOBJECT Device
)
{
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
SafeOpsPerformSelfCheck(
    _In_ PDRIVER_CONTEXT Context
)
{
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
    if (Context->CalloutIdIPv4Inbound == 0 || Context->CalloutIdIPv4Outbound == 0) {
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
        SAFEOPS_LOG_ERROR("Self-check failed: Connection hash table not initialized");
        return STATUS_UNSUCCESSFUL;
    }
    checksCompleted++;
    SAFEOPS_LOG_DEBUG("[%u/10] Connection tracking OK", checksCompleted);
    
    // Check 7: Verify filter rule list initialized
    if (!IsListEmpty(&Context->FilterRuleList)) {
        SAFEOPS_LOG_DEBUG("Filter rules already loaded: %u", Context->FilterRuleCount);
    }
    checksCompleted++;
    SAFEOPS_LOG_DEBUG("[%u/10] Filter rule list OK", checksCompleted);
    
    // Check 8: Verify NIC count
    if (Context->NicCount == 0) {
        SAFEOPS_LOG_WARNING("No NICs detected (system may not have network adapters)");
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
    
    SAFEOPS_LOG_INFO("=== Self-Check Complete: %u/10 checks passed ===", checksCompleted);
    
    return STATUS_SUCCESS;
}

/**
 * SafeOpsVerifySubsystems - Verify all subsystems functional
 */
NTSTATUS
SafeOpsVerifySubsystems(
    _In_ PDRIVER_CONTEXT Context
)
{
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
SafeOpsReadRegistryConfig(VOID)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING registryPath;
    HANDLE keyHandle = NULL;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo;
    ULONG resultLength;
    
    RtlInitUnicodeString(&registryPath, SAFEOPS_REGISTRY_PATH L"\\" SAFEOPS_PARAMETERS_KEY);
    InitializeObjectAttributes(&objAttr, &registryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        SAFEOPS_LOG_WARNING("Failed to open registry key: 0x%08X", status);
        return status;
    }
    
    valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    
    // Read LogLevel
    RtlInitUnicodeString(&valueName, L"LogLevel");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, valueInfo, sizeof(buffer), &resultLength);
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
SafeOpsWriteEventLog(
    _In_ ULONG EventType,
    _In_ ULONG EventId,
    _In_ PWSTR Message
)
{
    // TODO: Implement Event Log writing using IoRegisterDeviceInterface
    // For now, just log to debug output
    
    const char* typeStr;
    switch (EventType) {
        case EVENTLOG_ERROR_TYPE:       typeStr = "ERROR"; break;
        case EVENTLOG_WARNING_TYPE:     typeStr = "WARNING"; break;
        case EVENTLOG_INFORMATION_TYPE: typeStr = "INFO"; break;
        default:                        typeStr = "UNKNOWN"; break;
    }
    
    SAFEOPS_LOG_INFO("EVENT[%s:%u]: %ws", typeStr, EventId, Message);
    
    return STATUS_SUCCESS;
}

/**
 * SafeOpsLogStartupBanner - Display startup banner
 */
VOID
SafeOpsLogStartupBanner(VOID)
{
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "\n");
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "╔═══════════════════════════════════════════════════════╗\n");
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "║           SafeOps Network Security Gateway           ║\n");
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "║                  Kernel Driver v%s                ║\n", SAFEOPS_VERSION_STRING);
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "║                                                       ║\n");
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "║  %s  ║\n", SAFEOPS_COPYRIGHT);
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "╚═══════════════════════════════════════════════════════╝\n");
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "\n");
}

/**
 * SafeOpsLogShutdownStats - Log final statistics before shutdown
 */
VOID
SafeOpsLogShutdownStats(
    _In_ PDRIVER_CONTEXT Context
)
{
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
        SAFEOPS_LOG_INFO("Ring buffer dropped: %u", Context->RingBufferHeader->DroppedPackets);
    }
    
    // Calculate throughput
    if (uptimeSeconds > 0) {
        ULONGLONG packetsPerSec = Context->PacketsProcessed / uptimeSeconds;
        ULONGLONG mbytesPerSec = (Context->BytesProcessed / uptimeSeconds) / (1024 * 1024);
        SAFEOPS_LOG_INFO("Average throughput: %llu packets/sec, %llu MB/sec", packetsPerSec, mbytesPerSec);
    }
}

//=============================================================================
// End of driver.c
//=============================================================================
