/**
 * ioctl_handler.c - SafeOps IOCTL Command Dispatcher
 *
 * Purpose: Implements the complete IOCTL command dispatcher that enables
 * bidirectional communication between the kernel driver and userspace services.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#include "ioctl_handler.h"
#include "filter_engine.h"
#include "shared_memory.h"
#include "statistics.h"

#ifdef SAFEOPS_WDK_BUILD
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>

#else
//=============================================================================
// IDE Mode Stubs (types now in driver.h via ioctl_handler.h)
//=============================================================================

// Suppress unused parameter warnings
#define UNREFERENCED_PARAMETER(P) (void)(P)

// NTSTATUS codes - only define if not already defined
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

// Macros
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define RtlCopyMemory(d, s, n) memcpy((d), (s), (n))
#define RtlZeroMemory(d, n) memset((d), 0, (n))
#define InterlockedExchange(t, v) (*(t) = (v))
#define KeQuerySystemTime(t) ((t)->QuadPart = 0)
#define KeAcquireSpinLock(l, i) (void)(i)
#define KeReleaseSpinLock(l, i) (void)(i)
#define IoCompleteRequest(i, b) (void)(i)
#define IO_NO_INCREMENT 0
#define IoGetCurrentIrpStackLocation(Irp) ((PIO_STACK_LOCATION)NULL)

typedef unsigned char KIRQL;

#include <string.h>
#endif

//=============================================================================
// SECTION 1: Global Driver Context Reference
//=============================================================================

extern PDRIVER_CONTEXT g_DriverContext;

//=============================================================================
// SECTION 2: IRP Dispatch Functions
//=============================================================================

/**
 * IoctlCreateHandler
 *
 * Handles IRP_MJ_CREATE when userspace opens the device.
 */
NTSTATUS IoctlCreateHandler(_In_ PDEVICE_OBJECT DeviceObject,
                            _Inout_ PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

/**
 * IoctlCloseHandler
 *
 * Handles IRP_MJ_CLOSE when userspace closes the device handle.
 */
NTSTATUS IoctlCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

/**
 * IoctlCleanupHandler
 *
 * Handles IRP_MJ_CLEANUP on process termination.
 */
NTSTATUS IoctlCleanupHandler(_In_ PDEVICE_OBJECT DeviceObject,
                             _Inout_ PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  // Cleanup any mappings for this process
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

/**
 * IoctlDeviceControlHandler
 *
 * Main IOCTL dispatcher - routes to DispatchIoctlCommand.
 */
NTSTATUS IoctlDeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject,
                                   _Inout_ PIRP Irp) {
  PIO_STACK_LOCATION irpStack;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(DeviceObject);

  irpStack = IoGetCurrentIrpStackLocation(Irp);
  status = DispatchIoctlCommand(Irp, irpStack);

  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

//=============================================================================
// SECTION 3: IOCTL Command Dispatcher
//=============================================================================

/**
 * DispatchIoctlCommand
 *
 * Routes IOCTL code to specific handler function.
 */
NTSTATUS DispatchIoctlCommand(_Inout_ PIRP Irp,
                              _In_ PIO_STACK_LOCATION IrpStack) {
  ULONG ioControlCode;
  NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

  if (IrpStack == NULL)
    return STATUS_INVALID_PARAMETER;

  ioControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  switch (ioControlCode) {

  // Driver Information
  case IOCTL_GET_DRIVER_VERSION:
    status = HandleGetDriverVersion(Irp, IrpStack);
    break;

  case IOCTL_GET_DRIVER_STATUS:
    status = HandleGetDriverStatus(Irp, IrpStack);
    break;

  case IOCTL_GET_CAPABILITIES:
    status = HandleGetCapabilities(Irp, IrpStack);
    break;

  // Statistics
  case IOCTL_GET_STATISTICS:
    status = HandleGetStatistics(Irp, IrpStack);
    break;

  case IOCTL_GET_NIC_STATISTICS:
    status = HandleGetNicStatistics(Irp, IrpStack);
    break;

  case IOCTL_RESET_STATISTICS:
    status = HandleResetStatistics(Irp, IrpStack);
    break;

  case IOCTL_GET_RING_BUFFER_STATS:
    status = HandleGetRingBufferStats(Irp, IrpStack);
    break;

  // NIC Management
  case IOCTL_SET_NIC_TAG:
    status = HandleSetNicTag(Irp, IrpStack);
    break;

  case IOCTL_GET_NIC_LIST:
    status = HandleGetNicList(Irp, IrpStack);
    break;

  case IOCTL_GET_NIC_INFO:
    status = HandleGetNicInfo(Irp, IrpStack);
    break;

  case IOCTL_ENABLE_NIC:
    status = HandleEnableNic(Irp, IrpStack);
    break;

  case IOCTL_DISABLE_NIC:
    status = HandleDisableNic(Irp, IrpStack);
    break;

  // Ring Buffer
  case IOCTL_RING_BUFFER_MAP:
    status = HandleRingBufferMap(Irp, IrpStack);
    break;

  case IOCTL_RING_BUFFER_UNMAP:
    status = HandleRingBufferUnmap(Irp, IrpStack);
    break;

  case IOCTL_RING_BUFFER_GET_INFO:
    status = HandleRingBufferGetInfo(Irp, IrpStack);
    break;

  case IOCTL_RING_BUFFER_UPDATE_CONSUMER:
    status = HandleRingBufferUpdateConsumer(Irp, IrpStack);
    break;

  case IOCTL_RING_BUFFER_RESET:
    status = HandleRingBufferReset(Irp, IrpStack);
    break;

  // Firewall Rules
  case IOCTL_ADD_FIREWALL_RULE:
    status = HandleAddFirewallRule(Irp, IrpStack);
    break;

  case IOCTL_REMOVE_FIREWALL_RULE:
    status = HandleRemoveFirewallRule(Irp, IrpStack);
    break;

  case IOCTL_UPDATE_FIREWALL_RULE:
    status = HandleUpdateFirewallRule(Irp, IrpStack);
    break;

  case IOCTL_GET_FIREWALL_RULES:
    status = HandleGetFirewallRules(Irp, IrpStack);
    break;

  case IOCTL_CLEAR_FIREWALL_RULES:
    status = HandleClearFirewallRules(Irp, IrpStack);
    break;

  case IOCTL_GET_RULE_STATISTICS:
    status = HandleGetRuleStatistics(Irp, IrpStack);
    break;

  // Configuration
  case IOCTL_SET_CAPTURE_MODE:
    status = HandleSetCaptureMode(Irp, IrpStack);
    break;

  case IOCTL_SET_FILTER_MODE:
    status = HandleSetFilterMode(Irp, IrpStack);
    break;

  case IOCTL_SET_LOG_LEVEL:
    status = HandleSetLogLevel(Irp, IrpStack);
    break;

  case IOCTL_SET_BUFFER_BEHAVIOR:
    status = HandleSetBufferBehavior(Irp, IrpStack);
    break;

  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    break;
  }

  return status;
}

//=============================================================================
// SECTION 4: Validation Functions
//=============================================================================

/**
 * ValidateIoctlBuffers
 *
 * Validates input and output buffer sizes.
 */
NTSTATUS ValidateIoctlBuffers(_In_ PIO_STACK_LOCATION IrpStack,
                              _In_ ULONG MinInputSize,
                              _In_ ULONG MinOutputSize) {
  ULONG inputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
  ULONG outputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

  if (MinInputSize > 0 && inputLen < MinInputSize) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  if (MinOutputSize > 0 && outputLen < MinOutputSize) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  return STATUS_SUCCESS;
}

/**
 * CompleteIoctlRequest
 *
 * Completes an IRP and returns to userspace.
 */
VOID CompleteIoctlRequest(_Inout_ PIRP Irp, _In_ NTSTATUS Status,
                          _In_ ULONG_PTR Information) {
  Irp->IoStatus.Status = Status;
  Irp->IoStatus.Information = Information;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

//=============================================================================
// SECTION 5: Driver Information Handlers
//=============================================================================

/**
 * HandleGetDriverVersion
 */
NTSTATUS HandleGetDriverVersion(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_VERSION_OUTPUT output;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_VERSION_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_VERSION_OUTPUT);
    return status;
  }

  output = (PIOCTL_VERSION_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_VERSION_OUTPUT));

  output->MajorVersion = 2;
  output->MinorVersion = 0;
  output->BuildNumber = 0;
  output->RevisionNumber = 1;

  Irp->IoStatus.Information = sizeof(IOCTL_VERSION_OUTPUT);
  return STATUS_SUCCESS;
}

/**
 * HandleGetDriverStatus
 */
NTSTATUS HandleGetDriverStatus(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_STATUS_OUTPUT output;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_STATUS_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_STATUS_OUTPUT);
    return status;
  }

  output = (PIOCTL_STATUS_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_STATUS_OUTPUT));

  output->IsInitialized = TRUE;
  output->IsCapturing = TRUE;
  output->IsFiltering = TRUE;
  output->IsRingBufferMapped = FALSE;
  output->NdisFilterState = 1;
  output->WfpCalloutState = 1;
  output->ActiveNicCount = g_DriverContext ? g_DriverContext->NicCount : 0;

  if (g_DriverContext) {
    output->DriverStartTime = g_DriverContext->DriverStartTime;
  }
  KeQuerySystemTime(&output->CurrentTime);

  Irp->IoStatus.Information = sizeof(IOCTL_STATUS_OUTPUT);
  return STATUS_SUCCESS;
}

/**
 * HandleGetCapabilities
 */
NTSTATUS HandleGetCapabilities(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 6: Statistics Handlers
//=============================================================================

/**
 * HandleGetStatistics
 */
NTSTATUS HandleGetStatistics(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_STATISTICS_OUTPUT output;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_STATISTICS_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_STATISTICS_OUTPUT);
    return status;
  }

  output = (PIOCTL_STATISTICS_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_STATISTICS_OUTPUT));

  if (g_DriverContext) {
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    output->DriverUptime.QuadPart =
        currentTime.QuadPart - g_DriverContext->DriverStartTime.QuadPart;

    output->TotalPacketsReceived = g_DriverContext->Statistics.PacketsReceived;
    output->TotalPacketsTransmitted =
        g_DriverContext->Statistics.PacketsTransmitted;
    output->TotalBytesReceived = g_DriverContext->Statistics.BytesReceived;
    output->TotalBytesTransmitted =
        g_DriverContext->Statistics.BytesTransmitted;
    output->PacketsDropped = g_DriverContext->Statistics.PacketsDropped;
    output->RingBufferOverflows =
        g_DriverContext->RingBuffer.PacketsDroppedOverflow;
    output->CurrentFirewallRuleCount = g_DriverContext->FilterRuleCount;
    output->CurrentConnectionCount = g_DriverContext->ConnCount;
    output->RingBufferUsedPercent =
        RingBufferGetFillPercentage(&g_DriverContext->RingBuffer);
  }

  Irp->IoStatus.Information = sizeof(IOCTL_STATISTICS_OUTPUT);
  return STATUS_SUCCESS;
}

/**
 * HandleGetNicStatistics
 */
NTSTATUS HandleGetNicStatistics(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleResetStatistics
 */
NTSTATUS HandleResetStatistics(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);

  if (g_DriverContext) {
    ResetStatistics(g_DriverContext);
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleGetRingBufferStats
 */
NTSTATUS HandleGetRingBufferStats(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_RING_BUFFER_INFO_OUTPUT output;
  NTSTATUS status;

  status =
      ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_RING_BUFFER_INFO_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_RING_BUFFER_INFO_OUTPUT);
    return status;
  }

  output = (PIOCTL_RING_BUFFER_INFO_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_RING_BUFFER_INFO_OUTPUT));

  if (g_DriverContext) {
    output->ProducerIndex = g_DriverContext->RingBuffer.ProducerIndex;
    output->ConsumerIndex = g_DriverContext->RingBuffer.ConsumerIndex;
    output->TotalPacketsWritten =
        g_DriverContext->RingBuffer.TotalPacketsWritten;
    output->TotalPacketsRead = g_DriverContext->RingBuffer.TotalPacketsRead;
    output->PacketsDroppedOverflow =
        g_DriverContext->RingBuffer.PacketsDroppedOverflow;
    output->UsedPercent =
        RingBufferGetFillPercentage(&g_DriverContext->RingBuffer);
  }

  Irp->IoStatus.Information = sizeof(IOCTL_RING_BUFFER_INFO_OUTPUT);
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 7: NIC Management Handlers
//=============================================================================

/**
 * HandleSetNicTag
 */
NTSTATUS HandleSetNicTag(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_SET_NIC_TAG_INPUT input;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(IOCTL_SET_NIC_TAG_INPUT), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  input = (PIOCTL_SET_NIC_TAG_INPUT)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext && input->InterfaceIndex < g_DriverContext->NicCount) {
    g_DriverContext->NicList[input->InterfaceIndex].Tag = input->NICTag;
  } else {
    return STATUS_NOT_FOUND;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleGetNicList
 */
NTSTATUS HandleGetNicList(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_NIC_LIST_OUTPUT output;
  NTSTATUS status;
  KIRQL oldIrql;

  status = ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_NIC_LIST_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_NIC_LIST_OUTPUT);
    return status;
  }

  output = (PIOCTL_NIC_LIST_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_NIC_LIST_OUTPUT));

  if (g_DriverContext) {
    KeAcquireSpinLock(&g_DriverContext->NicLock, &oldIrql);
    output->NICCount = g_DriverContext->NicCount;
    // Copy NIC info (simplified)
    KeReleaseSpinLock(&g_DriverContext->NicLock, oldIrql);
  }

  Irp->IoStatus.Information = sizeof(IOCTL_NIC_LIST_OUTPUT);
  return STATUS_SUCCESS;
}

/**
 * HandleGetNicInfo
 */
NTSTATUS HandleGetNicInfo(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleEnableNic
 */
NTSTATUS HandleEnableNic(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  PULONG nicIndex;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(ULONG), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  nicIndex = (PULONG)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext && *nicIndex < g_DriverContext->NicCount) {
    g_DriverContext->NicList[*nicIndex].IsActive = TRUE;
  } else {
    return STATUS_NOT_FOUND;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleDisableNic
 */
NTSTATUS HandleDisableNic(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  PULONG nicIndex;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(ULONG), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  nicIndex = (PULONG)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext && *nicIndex < g_DriverContext->NicCount) {
    g_DriverContext->NicList[*nicIndex].IsActive = FALSE;
  } else {
    return STATUS_NOT_FOUND;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 8: Ring Buffer Handlers
//=============================================================================

/**
 * HandleRingBufferMap
 */
NTSTATUS HandleRingBufferMap(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_RING_BUFFER_MAP_OUTPUT output;
  NTSTATUS status;
  PVOID userAddress = NULL;

  status =
      ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_RING_BUFFER_MAP_OUTPUT));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_RING_BUFFER_MAP_OUTPUT);
    return status;
  }

  output = (PIOCTL_RING_BUFFER_MAP_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_RING_BUFFER_MAP_OUTPUT));

  if (g_DriverContext) {
    status = MapRingBufferToUserspace(g_DriverContext, &userAddress);
    if (NT_SUCCESS(status)) {
      output->UserModeAddress = userAddress;
      output->TotalSize = g_DriverContext->RingBuffer.TotalSize;
      output->EntrySize = 128;
      output->MaxEntries = (ULONG)(g_DriverContext->RingBuffer.TotalSize / 128);
    }
  } else {
    status = STATUS_INVALID_PARAMETER;
  }

  Irp->IoStatus.Information = sizeof(IOCTL_RING_BUFFER_MAP_OUTPUT);
  return status;
}

/**
 * HandleRingBufferUnmap
 */
NTSTATUS HandleRingBufferUnmap(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  PVOID userAddress;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(PVOID), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  userAddress = *(PVOID *)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext) {
    status = UnmapRingBufferFromUserspace(g_DriverContext, userAddress);
  } else {
    status = STATUS_INVALID_PARAMETER;
  }

  Irp->IoStatus.Information = 0;
  return status;
}

/**
 * HandleRingBufferGetInfo
 */
NTSTATUS HandleRingBufferGetInfo(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack) {
  return HandleGetRingBufferStats(Irp, IrpStack);
}

/**
 * HandleRingBufferUpdateConsumer
 */
NTSTATUS HandleRingBufferUpdateConsumer(_Inout_ PIRP Irp,
                                        _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT input;
  NTSTATUS status;

  status = ValidateIoctlBuffers(
      IrpStack, sizeof(IOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  input =
      (PIOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext) {
    g_DriverContext->RingBuffer.ConsumerIndex = input->NewConsumerIndex;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleRingBufferReset
 */
NTSTATUS HandleRingBufferReset(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);

  if (g_DriverContext) {
    g_DriverContext->RingBuffer.ProducerIndex = 4096;
    g_DriverContext->RingBuffer.ConsumerIndex = 4096;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 9: Firewall Rule Handlers
//=============================================================================

/**
 * HandleAddFirewallRule
 */
NTSTATUS HandleAddFirewallRule(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack) {
  PFIREWALL_RULE rule;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(FIREWALL_RULE), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  rule = (PFIREWALL_RULE)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext) {
    status = AddFilterRule(g_DriverContext, (PFILTER_RULE)rule);
  } else {
    status = STATUS_INVALID_PARAMETER;
  }

  Irp->IoStatus.Information = 0;
  return status;
}

/**
 * HandleRemoveFirewallRule
 */
NTSTATUS HandleRemoveFirewallRule(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_REMOVE_RULE_INPUT input;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(IOCTL_REMOVE_RULE_INPUT), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  input = (PIOCTL_REMOVE_RULE_INPUT)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext) {
    status = RemoveFilterRule(g_DriverContext, (ULONG)input->RuleId);
  } else {
    status = STATUS_INVALID_PARAMETER;
  }

  Irp->IoStatus.Information = 0;
  return status;
}

/**
 * HandleUpdateFirewallRule
 */
NTSTATUS HandleUpdateFirewallRule(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleGetFirewallRules
 */
NTSTATUS HandleGetFirewallRules(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_GET_RULES_OUTPUT_HEADER output;
  NTSTATUS status;

  status =
      ValidateIoctlBuffers(IrpStack, 0, sizeof(IOCTL_GET_RULES_OUTPUT_HEADER));
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = sizeof(IOCTL_GET_RULES_OUTPUT_HEADER);
    return status;
  }

  output = (PIOCTL_GET_RULES_OUTPUT_HEADER)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory(output, sizeof(IOCTL_GET_RULES_OUTPUT_HEADER));

  if (g_DriverContext) {
    output->TotalRuleCount = g_DriverContext->FilterRuleCount;
    output->RuleCount = 0;
    output->Offset = 0;
  }

  Irp->IoStatus.Information = sizeof(IOCTL_GET_RULES_OUTPUT_HEADER);
  return STATUS_SUCCESS;
}

/**
 * HandleClearFirewallRules
 */
NTSTATUS HandleClearFirewallRules(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);

  if (g_DriverContext) {
    g_DriverContext->FilterRuleCount = 0;
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleGetRuleStatistics
 */
NTSTATUS HandleGetRuleStatistics(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 10: Configuration Handlers
//=============================================================================

/**
 * HandleSetCaptureMode
 */
NTSTATUS HandleSetCaptureMode(_Inout_ PIRP Irp,
                              _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleSetFilterMode
 */
NTSTATUS HandleSetFilterMode(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleSetLogLevel
 */
NTSTATUS HandleSetLogLevel(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack) {
  PIOCTL_SET_LOG_LEVEL_INPUT input;
  NTSTATUS status;

  status = ValidateIoctlBuffers(IrpStack, sizeof(IOCTL_SET_LOG_LEVEL_INPUT), 0);
  if (!NT_SUCCESS(status)) {
    Irp->IoStatus.Information = 0;
    return status;
  }

  input = (PIOCTL_SET_LOG_LEVEL_INPUT)Irp->AssociatedIrp.SystemBuffer;

  if (g_DriverContext && input->LogLevel <= 4) {
    g_DriverContext->LoggingEnabled = (input->LogLevel > 0);
  }

  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

/**
 * HandleSetBufferBehavior
 */
NTSTATUS HandleSetBufferBehavior(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack) {
  UNREFERENCED_PARAMETER(IrpStack);
  Irp->IoStatus.Information = 0;
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 11: Security and Validation Helpers
//=============================================================================

/**
 * ValidateCallerPermissions
 */
BOOLEAN ValidateCallerPermissions(_In_ PIRP Irp) {
  UNREFERENCED_PARAMETER(Irp);
  return TRUE; // Simplified - real implementation would check token
}

/**
 * IsProcessTrusted
 */
BOOLEAN IsProcessTrusted(_In_ HANDLE ProcessId) {
  UNREFERENCED_PARAMETER(ProcessId);
  return TRUE;
}

/**
 * ValidateNicTag
 */
NTSTATUS ValidateNicTag(_In_ ULONG NICTag) {
  if (NICTag > 3)
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}

/**
 * ValidateInterfaceIndex
 */
NTSTATUS ValidateInterfaceIndex(_In_ ULONG InterfaceIndex) {
  if (g_DriverContext && InterfaceIndex < g_DriverContext->NicCount) {
    return STATUS_SUCCESS;
  }
  return STATUS_NOT_FOUND;
}

/**
 * ValidateFirewallRule
 */
NTSTATUS ValidateFirewallRule(_In_ PFIREWALL_RULE Rule) {
  if (Rule == NULL)
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}

/**
 * ValidateConsumerIndex
 */
NTSTATUS ValidateConsumerIndex(_In_ ULONG ConsumerIndex) {
  UNREFERENCED_PARAMETER(ConsumerIndex);
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 12: Buffer Access Helpers
//=============================================================================

/**
 * GetIoctlInputBuffer
 */
PVOID GetIoctlInputBuffer(_In_ PIO_STACK_LOCATION IrpStack,
                          _Out_ PULONG OutSize) {
  if (OutSize)
    *OutSize = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
  return NULL; // Would get from IRP
}

/**
 * GetIoctlOutputBuffer
 */
PVOID GetIoctlOutputBuffer(_In_ PIO_STACK_LOCATION IrpStack,
                           _Out_ PULONG OutSize) {
  if (OutSize)
    *OutSize = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  return NULL;
}

/**
 * CopyToOutputBuffer
 */
NTSTATUS CopyToOutputBuffer(_Out_ PVOID DestBuffer, _In_ SIZE_T DestSize,
                            _In_ PVOID SourceData, _In_ SIZE_T SourceSize,
                            _Out_ PULONG_PTR OutBytesWritten) {
  if (DestSize < SourceSize)
    return STATUS_BUFFER_TOO_SMALL;
  RtlCopyMemory(DestBuffer, SourceData, SourceSize);
  if (OutBytesWritten)
    *OutBytesWritten = SourceSize;
  return STATUS_SUCCESS;
}

/**
 * CopyFromInputBuffer
 */
NTSTATUS CopyFromInputBuffer(_Out_ PVOID DestBuffer, _In_ SIZE_T DestSize,
                             _In_ PVOID SourceBuffer, _In_ SIZE_T SourceSize) {
  if (SourceSize > DestSize)
    return STATUS_BUFFER_TOO_SMALL;
  RtlCopyMemory(DestBuffer, SourceBuffer, SourceSize);
  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 13: Reference Counting
//=============================================================================

/**
 * RegisterDeviceHandle
 */
NTSTATUS RegisterDeviceHandle(_In_ PFILE_OBJECT FileObject) {
  UNREFERENCED_PARAMETER(FileObject);
  return STATUS_SUCCESS;
}

/**
 * UnregisterDeviceHandle
 */
VOID UnregisterDeviceHandle(_In_ PFILE_OBJECT FileObject) {
  UNREFERENCED_PARAMETER(FileObject);
}

/**
 * GetOpenHandleCount
 */
ULONG GetOpenHandleCount(VOID) { return 0; }

/**
 * IsDeviceInUse
 */
BOOLEAN IsDeviceInUse(VOID) { return FALSE; }

//=============================================================================
// SECTION 14: Debug Functions
//=============================================================================

#ifdef DBG

VOID LogIoctlRequest(_In_ ULONG IoControlCode, _In_ ULONG ProcessId) {
  UNREFERENCED_PARAMETER(IoControlCode);
  UNREFERENCED_PARAMETER(ProcessId);
}

VOID LogIoctlCompletion(_In_ ULONG IoControlCode, _In_ NTSTATUS Status,
                        _In_ ULONG BytesReturned) {
  UNREFERENCED_PARAMETER(IoControlCode);
  UNREFERENCED_PARAMETER(Status);
  UNREFERENCED_PARAMETER(BytesReturned);
}

VOID LogIoctlError(_In_ ULONG IoControlCode, _In_ NTSTATUS Status,
                   _In_ const char *ErrorMessage) {
  UNREFERENCED_PARAMETER(IoControlCode);
  UNREFERENCED_PARAMETER(Status);
  UNREFERENCED_PARAMETER(ErrorMessage);
}

VOID DbgPrintIoctlStatistics(VOID) {}

#endif // DBG
