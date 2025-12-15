/**
 * ioctl_handler.c - IOCTL Handler Implementation
 * 
 * Handles communication between userspace services and kernel driver.
 * 
 * Copyright (c) 2024 SafeOps Project
 */

#include "ioctl_handler.h"

//=============================================================================
// SafeOpsEvtIoDeviceControl - Main IOCTL Dispatch
//=============================================================================

VOID
SafeOpsEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_CONTEXT context;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    SIZE_T bytesReturned = 0;
    
    context = GetDriverContext(WdfIoQueueGetDevice(Queue));
    
    // Get buffers
    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }
    }
    
    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }
    }
    
    // Process IOCTL
    switch (IoControlCode) {
        
        case IOCTL_SAFEOPS_GET_VERSION:
        {
            PSAFEOPS_VERSION_INFO versionInfo = (PSAFEOPS_VERSION_INFO)outputBuffer;
            
            if (OutputBufferLength < sizeof(SAFEOPS_VERSION_INFO)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            versionInfo->Major = SAFEOPS_VERSION_MAJOR;
            versionInfo->Minor = SAFEOPS_VERSION_MINOR;
            versionInfo->Patch = SAFEOPS_VERSION_PATCH;
            versionInfo->Build = SAFEOPS_VERSION_BUILD;
            RtlStringCbCopyA(versionInfo->VersionString, 
                           sizeof(versionInfo->VersionString), 
                           SAFEOPS_VERSION_STRING);
            
            bytesReturned = sizeof(SAFEOPS_VERSION_INFO);
            break;
        }
        
        case IOCTL_SAFEOPS_GET_STATISTICS:
        {
            status = HandleGetStatistics(context, outputBuffer, OutputBufferLength, &bytesReturned);
            break;
        }
        
        case IOCTL_SAFEOPS_ADD_RULE:
        {
            status = HandleAddRule(context, inputBuffer, InputBufferLength);
            break;
        }
        
        case IOCTL_SAFEOPS_REMOVE_RULE:
        {
            status = HandleRemoveRule(context, inputBuffer, InputBufferLength);
            break;
        }
        
        case IOCTL_SAFEOPS_MAP_SHARED_MEMORY:
        {
            PVOID* userAddress = (PVOID*)outputBuffer;
            
            if (OutputBufferLength < sizeof(PVOID)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = SharedMemoryMapToUser(context, userAddress);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(PVOID);
            }
            break;
        }
        
        case IOCTL_SAFEOPS_SET_NIC_ZONE:
        {
            PNIC_ZONE_REQUEST request = (PNIC_ZONE_REQUEST)inputBuffer;
            
            if (InputBufferLength < sizeof(NIC_ZONE_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = SetNicZone(context, request->NicIndex, request->Zone);
            break;
        }
        
        case IOCTL_SAFEOPS_GET_NIC_INFO:
        {
            if (OutputBufferLength < sizeof(NIC_INFO) * MAX_NIC_COUNT) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            KIRQL oldIrql;
            KeAcquireSpinLock(&context->NicLock, &oldIrql);
            RtlCopyMemory(outputBuffer, context->NicList, sizeof(NIC_INFO) * context->NicCount);
            KeReleaseSpinLock(&context->NicLock, oldIrql);
            
            bytesReturned = sizeof(NIC_INFO) * context->NicCount;
            break;
        }
        
        case IOCTL_SAFEOPS_ENABLE_RSS:
        {
            PRSS_REQUEST request = (PRSS_REQUEST)inputBuffer;
            
            if (InputBufferLength < sizeof(RSS_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            if (request->Enable) {
                status = EnableRss(context, request->CpuCount);
            } else {
                context->RssEnabled = FALSE;
            }
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

//=============================================================================
// HandleGetStatistics
//=============================================================================

NTSTATUS
HandleGetStatistics(
    _In_ PDRIVER_CONTEXT Context,
    _Out_ PVOID OutputBuffer,
    _In_ SIZE_T OutputBufferLength,
    _Out_ PSIZE_T BytesReturned
)
{
    PSAFEOPS_STATISTICS stats;
    
    if (OutputBufferLength < sizeof(SAFEOPS_STATISTICS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    stats = (PSAFEOPS_STATISTICS)OutputBuffer;
    
    stats->PacketsProcessed = Context->PacketsProcessed;
    stats->PacketsAllowed = Context->PacketsAllowed;
    stats->PacketsDropped = Context->PacketsDropped;
    stats->BytesProcessed = Context->BytesProcessed;
    stats->FilterRuleCount = Context->FilterRuleCount;
    stats->ConnectionCount = Context->ConnCount;
    stats->DroppedPackets = Context->RingBufferHeader ? 
                           Context->RingBufferHeader->DroppedPackets : 0;
    stats->DriverStartTime = Context->DriverStartTime;
    KeQuerySystemTime(&stats->CurrentTime);
    
    *BytesReturned = sizeof(SAFEOPS_STATISTICS);
    
    return STATUS_SUCCESS;
}

//=============================================================================
// HandleAddRule
//=============================================================================

NTSTATUS
HandleAddRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength
)
{
    PFILTER_RULE rule;
    
    if (InputBufferLength < sizeof(FILTER_RULE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    rule = (PFILTER_RULE)InputBuffer;
    
    return AddFilterRule(Context, rule);
}

//=============================================================================
// HandleRemoveRule
//=============================================================================

NTSTATUS
HandleRemoveRule(
    _In_ PDRIVER_CONTEXT Context,
    _In_ PVOID InputBuffer,
    _In_ SIZE_T InputBufferLength
)
{
    PULONG ruleId;
    
    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    ruleId = (PULONG)InputBuffer;
    
    return RemoveFilterRule(Context, *ruleId);
}
