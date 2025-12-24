/**
 * ioctl_handler.h - SafeOps IOCTL Handler Interface
 *
 * Purpose: Defines the complete IOCTL (Input/Output Control) interface between
 * the kernel driver and userspace service. Establishes all command codes,
 * input/output buffer structures, and function prototypes for bidirectional
 * communication. This is the control plane for runtime driver configuration.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 *
 * CRITICAL: IOCTL codes and structures must match EXACTLY between kernel
 * and userspace. Changes require synchronized updates to both sides.
 */

#ifndef SAFEOPS_IOCTL_HANDLER_H
#define SAFEOPS_IOCTL_HANDLER_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header

#ifdef SAFEOPS_WDK_BUILD
#include <ntddk.h>    // IRP processing
#include <ntstatus.h> // NTSTATUS return codes
#else
// IDE Mode - Additional type stubs
typedef void *PFILE_OBJECT;
typedef unsigned long long ULONG_PTR;
typedef ULONG_PTR *PULONG_PTR;
#endif

// Forward declarations for filter_engine.h and shared_memory.h types
// (avoids circular includes - actual includes in .c file)
struct _FIREWALL_RULE;
typedef struct _FIREWALL_RULE FIREWALL_RULE;
typedef struct _FIREWALL_RULE *PFIREWALL_RULE;

//=============================================================================
// SECTION 2: IOCTL Device Control Codes
//=============================================================================

/**
 * Device Type and Function Base
 *
 * Using FILE_DEVICE_NETWORK (0x12) as we're a network driver.
 * Function codes start at 0x800 (user-defined range).
 */
#define FILE_DEVICE_SAFEOPS 0x8000 // Custom device type
#define IOCTL_FUNCTION_BASE 0x800  // Function code base

//-----------------------------------------------------------------------------
// Category: Driver Information (0x800-0x80F)
//-----------------------------------------------------------------------------

#define IOCTL_GET_DRIVER_VERSION                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_DRIVER_STATUS                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_CAPABILITIES                                                 \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

//-----------------------------------------------------------------------------
// Category: Statistics (0x810-0x81F)
//-----------------------------------------------------------------------------

#define IOCTL_GET_STATISTICS                                                   \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_NIC_STATISTICS                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_RESET_STATISTICS                                                 \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x812, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_RING_BUFFER_STATS                                            \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x813, METHOD_BUFFERED, FILE_READ_ACCESS)

//-----------------------------------------------------------------------------
// Category: NIC Management (0x820-0x82F)
//-----------------------------------------------------------------------------

#define IOCTL_SET_NIC_TAG                                                      \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x820, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_NIC_LIST                                                     \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x821, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_NIC_INFO                                                     \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x822, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_ENABLE_NIC                                                       \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x823, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_DISABLE_NIC                                                      \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x824, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//-----------------------------------------------------------------------------
// Category: Ring Buffer (0x830-0x83F)
//-----------------------------------------------------------------------------

#define IOCTL_RING_BUFFER_MAP                                                  \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x830, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_RING_BUFFER_UNMAP                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x831, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RING_BUFFER_GET_INFO                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x832, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_RING_BUFFER_UPDATE_CONSUMER                                      \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x833, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RING_BUFFER_RESET                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x834, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//-----------------------------------------------------------------------------
// Category: Firewall Rules (0x840-0x84F)
//-----------------------------------------------------------------------------

#define IOCTL_ADD_FIREWALL_RULE                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x840, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_REMOVE_FIREWALL_RULE                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x841, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_UPDATE_FIREWALL_RULE                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x842, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_FIREWALL_RULES                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x843, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define IOCTL_CLEAR_FIREWALL_RULES                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x844, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_RULE_STATISTICS                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x845, METHOD_BUFFERED, FILE_READ_ACCESS)

//-----------------------------------------------------------------------------
// Category: Configuration (0x850-0x85F)
//-----------------------------------------------------------------------------

#define IOCTL_SET_CAPTURE_MODE                                                 \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x850, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SET_FILTER_MODE                                                  \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x851, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SET_LOG_LEVEL                                                    \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x852, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SET_BUFFER_BEHAVIOR                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x853, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//=============================================================================
// SECTION 3: IOCTL Input/Output Buffer Structures
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

//-----------------------------------------------------------------------------
// Driver Information Structures
//-----------------------------------------------------------------------------

/**
 * IOCTL_GET_DRIVER_VERSION Output (32 bytes)
 */
typedef struct _IOCTL_VERSION_OUTPUT {
  ULONG MajorVersion;     // 4 bytes
  ULONG MinorVersion;     // 4 bytes
  ULONG BuildNumber;      // 4 bytes
  ULONG RevisionNumber;   // 4 bytes
  WCHAR VersionString[8]; // 16 bytes - e.g. L"2.0.1024"
} IOCTL_VERSION_OUTPUT, *PIOCTL_VERSION_OUTPUT;

/**
 * IOCTL_GET_DRIVER_STATUS Output (64 bytes)
 */
typedef struct _IOCTL_STATUS_OUTPUT {
  BOOLEAN IsInitialized;         // 1 byte
  BOOLEAN IsCapturing;           // 1 byte
  BOOLEAN IsFiltering;           // 1 byte
  BOOLEAN IsRingBufferMapped;    // 1 byte
  ULONG NdisFilterState;         // 4 bytes
  ULONG WfpCalloutState;         // 4 bytes
  ULONG ActiveNicCount;          // 4 bytes
  LARGE_INTEGER DriverStartTime; // 8 bytes
  LARGE_INTEGER CurrentTime;     // 8 bytes
  UCHAR Reserved[32];            // 32 bytes
} IOCTL_STATUS_OUTPUT, *PIOCTL_STATUS_OUTPUT;

//-----------------------------------------------------------------------------
// Statistics Structures
//-----------------------------------------------------------------------------

/**
 * IOCTL_GET_STATISTICS Output (512 bytes)
 */
typedef struct _IOCTL_STATISTICS_OUTPUT {
  // Timing (8 bytes)
  LARGE_INTEGER DriverUptime; // 8 bytes

  // Packet counters (48 bytes)
  ULONG64 TotalPacketsReceived;    // 8 bytes
  ULONG64 TotalPacketsTransmitted; // 8 bytes
  ULONG64 TotalBytesReceived;      // 8 bytes
  ULONG64 TotalBytesTransmitted;   // 8 bytes
  ULONG64 PacketsDropped;          // 8 bytes
  ULONG64 RingBufferOverflows;     // 8 bytes

  // Current state (16 bytes)
  ULONG CurrentFirewallRuleCount; // 4 bytes
  ULONG CurrentConnectionCount;   // 4 bytes
  ULONG CurrentNATMappingCount;   // 4 bytes
  ULONG Reserved1;                // 4 bytes

  // Performance (24 bytes)
  ULONG PacketsPerSecond;      // 4 bytes
  ULONG MegabytesPerSecond;    // 4 bytes
  ULONG CPUUsagePercent;       // 4 bytes
  ULONG RingBufferUsedPercent; // 4 bytes
  ULONG AverageLatencyMicros;  // 4 bytes
  ULONG Reserved2;             // 4 bytes

  // Reserved (416 bytes)
  UCHAR Reserved[416]; // 416 bytes - Future metrics
} IOCTL_STATISTICS_OUTPUT, *PIOCTL_STATISTICS_OUTPUT;

//-----------------------------------------------------------------------------
// NIC Management Structures
//-----------------------------------------------------------------------------

/**
 * NIC_INFO_ENTRY (128 bytes)
 */
typedef struct _NIC_INFO_ENTRY {
  ULONG InterfaceIndex;     // 4 bytes
  ULONG NICTag;             // 4 bytes - 0=Untagged, 1=WAN, 2=LAN, 3=WiFi
  ULONG MediaType;          // 4 bytes - NDIS media type
  ULONG LinkSpeedMbps;      // 4 bytes
  ULONG64 BytesReceived;    // 8 bytes
  ULONG64 BytesTransmitted; // 8 bytes
  BOOLEAN IsEnabled;        // 1 byte
  BOOLEAN IsConnected;      // 1 byte
  UCHAR MACAddress[6];      // 6 bytes
  WCHAR FriendlyName[32];   // 64 bytes - Unicode NIC name
  UCHAR Reserved[24];       // 24 bytes
} NIC_INFO_ENTRY, *PNIC_INFO_ENTRY;

/**
 * IOCTL_SET_NIC_TAG Input (16 bytes)
 */
typedef struct _IOCTL_SET_NIC_TAG_INPUT {
  ULONG InterfaceIndex; // 4 bytes
  ULONG NICTag;         // 4 bytes - 1=WAN, 2=LAN, 3=WiFi
  UCHAR Reserved[8];    // 8 bytes
} IOCTL_SET_NIC_TAG_INPUT, *PIOCTL_SET_NIC_TAG_INPUT;

/**
 * IOCTL_GET_NIC_LIST Output (variable, up to 8 NICs)
 */
typedef struct _IOCTL_NIC_LIST_OUTPUT {
  ULONG NICCount;         // 4 bytes
  UCHAR Reserved[4];      // 4 bytes
  NIC_INFO_ENTRY NICs[8]; // 1024 bytes - Array of NIC info
} IOCTL_NIC_LIST_OUTPUT, *PIOCTL_NIC_LIST_OUTPUT;

//-----------------------------------------------------------------------------
// Ring Buffer Structures
//-----------------------------------------------------------------------------

/**
 * IOCTL_RING_BUFFER_MAP Output (32 bytes)
 */
typedef struct _IOCTL_RING_BUFFER_MAP_OUTPUT {
  PVOID UserModeAddress; // 8 bytes - Mapped address in userspace
  ULONG64 TotalSize;     // 8 bytes - Ring buffer size (2GB)
  ULONG EntrySize;       // 4 bytes - Entry size (128 bytes)
  ULONG MaxEntries;      // 4 bytes - Max entries (16777216)
  UCHAR Reserved[8];     // 8 bytes
} IOCTL_RING_BUFFER_MAP_OUTPUT, *PIOCTL_RING_BUFFER_MAP_OUTPUT;

/**
 * IOCTL_RING_BUFFER_UPDATE_CONSUMER Input (8 bytes)
 */
typedef struct _IOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT {
  ULONG NewConsumerIndex; // 4 bytes
  UCHAR Reserved[4];      // 4 bytes
} IOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT,
    *PIOCTL_RING_BUFFER_UPDATE_CONSUMER_INPUT;

/**
 * IOCTL_RING_BUFFER_GET_INFO Output (64 bytes)
 */
typedef struct _IOCTL_RING_BUFFER_INFO_OUTPUT {
  ULONG ProducerIndex;            // 4 bytes
  ULONG ConsumerIndex;            // 4 bytes
  ULONG UsedEntries;              // 4 bytes
  ULONG FreeEntries;              // 4 bytes
  ULONG64 TotalPacketsWritten;    // 8 bytes
  ULONG64 TotalPacketsRead;       // 8 bytes
  ULONG64 PacketsDroppedOverflow; // 8 bytes
  ULONG UsedPercent;              // 4 bytes
  ULONG PeakUsedPercent;          // 4 bytes
  UCHAR Reserved[16];             // 16 bytes
} IOCTL_RING_BUFFER_INFO_OUTPUT, *PIOCTL_RING_BUFFER_INFO_OUTPUT;

//-----------------------------------------------------------------------------
// Firewall Rule Structures
//-----------------------------------------------------------------------------

/**
 * IOCTL_REMOVE_FIREWALL_RULE Input (16 bytes)
 */
typedef struct _IOCTL_REMOVE_RULE_INPUT {
  ULONG64 RuleId;    // 8 bytes
  UCHAR Reserved[8]; // 8 bytes
} IOCTL_REMOVE_RULE_INPUT, *PIOCTL_REMOVE_RULE_INPUT;

/**
 * IOCTL_GET_FIREWALL_RULES Output header
 */
typedef struct _IOCTL_GET_RULES_OUTPUT_HEADER {
  ULONG RuleCount;      // 4 bytes - Rules in this response
  ULONG TotalRuleCount; // 4 bytes - Total rules in driver
  ULONG Offset;         // 4 bytes - Starting offset
  ULONG Reserved;       // 4 bytes
                        // FIREWALL_RULE Rules[] follows (variable)
} IOCTL_GET_RULES_OUTPUT_HEADER, *PIOCTL_GET_RULES_OUTPUT_HEADER;

//-----------------------------------------------------------------------------
// Configuration Structures
//-----------------------------------------------------------------------------

/**
 * IOCTL_SET_CAPTURE_MODE Input (8 bytes)
 */
typedef struct _IOCTL_SET_CAPTURE_MODE_INPUT {
  ULONG CaptureMode; // 4 bytes - 0=Off, 1=MetadataOnly, 2=Partial, 3=Full
  ULONG PartialPayloadSize; // 4 bytes - Bytes to capture in partial mode
} IOCTL_SET_CAPTURE_MODE_INPUT, *PIOCTL_SET_CAPTURE_MODE_INPUT;

/**
 * IOCTL_SET_FILTER_MODE Input (8 bytes)
 */
typedef struct _IOCTL_SET_FILTER_MODE_INPUT {
  ULONG FilterMode;    // 4 bytes - 0=Off, 1=On
  ULONG DefaultAction; // 4 bytes - 0=Allow, 1=Block
} IOCTL_SET_FILTER_MODE_INPUT, *PIOCTL_SET_FILTER_MODE_INPUT;

/**
 * IOCTL_SET_LOG_LEVEL Input (4 bytes)
 */
typedef struct _IOCTL_SET_LOG_LEVEL_INPUT {
  ULONG LogLevel; // 4 bytes - 0=None, 1=Error, 2=Warning, 3=Info, 4=Debug
} IOCTL_SET_LOG_LEVEL_INPUT, *PIOCTL_SET_LOG_LEVEL_INPUT;

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
// SECTION 4: Device Handle Context (for tracking open handles)
//=============================================================================

/**
 * DEVICE_HANDLE_CONTEXT
 *
 * Tracks per-handle state for cleanup on process termination.
 */
typedef struct _DEVICE_HANDLE_CONTEXT {
  ULONG ProcessId;            // Process that opened device
  PFILE_OBJECT FileObject;    // File object pointer
  BOOLEAN IsRingBufferMapped; // TRUE if ring buffer mapped
  BOOLEAN Reserved1[3];       // Padding
  LARGE_INTEGER OpenTime;     // When handle was opened
  LIST_ENTRY ListEntry;       // Linked list entry
} DEVICE_HANDLE_CONTEXT, *PDEVICE_HANDLE_CONTEXT;

//=============================================================================
// SECTION 5: Function Prototypes - IRP Dispatch Functions
//=============================================================================

/**
 * Main IRP handlers registered in DriverEntry.
 * All run at PASSIVE_LEVEL.
 */

// Handle IRP_MJ_CREATE (device open)
NTSTATUS IoctlCreateHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

// Handle IRP_MJ_CLOSE (device close)
NTSTATUS IoctlCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

// Handle IRP_MJ_DEVICE_CONTROL (all IOCTLs)
NTSTATUS IoctlDeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject,
                                   _Inout_ PIRP Irp);

// Handle IRP_MJ_CLEANUP (process termination)
NTSTATUS IoctlCleanupHandler(_In_ PDEVICE_OBJECT DeviceObject,
                             _Inout_ PIRP Irp);

//=============================================================================
// SECTION 6: Function Prototypes - IOCTL Dispatchers
//=============================================================================

// Route IOCTL code to specific handler
NTSTATUS DispatchIoctlCommand(_Inout_ PIRP Irp,
                              _In_ PIO_STACK_LOCATION IrpStack);

// Validate input/output buffer sizes
NTSTATUS ValidateIoctlBuffers(_In_ PIO_STACK_LOCATION IrpStack,
                              _In_ ULONG MinInputSize,
                              _In_ ULONG MinOutputSize);

// Complete IRP and return to userspace
VOID CompleteIoctlRequest(_Inout_ PIRP Irp, _In_ NTSTATUS Status,
                          _In_ ULONG_PTR Information);

//=============================================================================
// SECTION 7: Function Prototypes - Per-Command Handlers
//=============================================================================

// Driver Information Handlers
NTSTATUS HandleGetDriverVersion(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetDriverStatus(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetCapabilities(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);

// Statistics Handlers
NTSTATUS HandleGetStatistics(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetNicStatistics(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleResetStatistics(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetRingBufferStats(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack);

// NIC Management Handlers
NTSTATUS HandleSetNicTag(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetNicList(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetNicInfo(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleEnableNic(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleDisableNic(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);

// Ring Buffer Handlers
NTSTATUS HandleRingBufferMap(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleRingBufferUnmap(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleRingBufferGetInfo(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleRingBufferUpdateConsumer(_Inout_ PIRP Irp,
                                        _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleRingBufferReset(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);

// Firewall Rule Handlers
NTSTATUS HandleAddFirewallRule(_Inout_ PIRP Irp,
                               _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleRemoveFirewallRule(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleUpdateFirewallRule(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetFirewallRules(_Inout_ PIRP Irp,
                                _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleClearFirewallRules(_Inout_ PIRP Irp,
                                  _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleGetRuleStatistics(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack);

// Configuration Handlers
NTSTATUS HandleSetCaptureMode(_Inout_ PIRP Irp,
                              _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleSetFilterMode(_Inout_ PIRP Irp,
                             _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleSetLogLevel(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack);
NTSTATUS HandleSetBufferBehavior(_Inout_ PIRP Irp,
                                 _In_ PIO_STACK_LOCATION IrpStack);

//=============================================================================
// SECTION 8: Function Prototypes - Security and Validation
//=============================================================================

// Check if caller has administrator privileges
BOOLEAN ValidateCallerPermissions(_In_ PIRP Irp);

// Check if process is trusted userspace service
BOOLEAN IsProcessTrusted(_In_ HANDLE ProcessId);

// Validate NIC tag value (0-3)
NTSTATUS ValidateNicTag(_In_ ULONG NICTag);

// Validate interface index exists
NTSTATUS ValidateInterfaceIndex(_In_ ULONG InterfaceIndex);

// Validate firewall rule fields
NTSTATUS ValidateFirewallRule(_In_ PFIREWALL_RULE Rule);

// Validate consumer index is within bounds
NTSTATUS ValidateConsumerIndex(_In_ ULONG ConsumerIndex);

//=============================================================================
// SECTION 9: Function Prototypes - Buffer Access Helpers
//=============================================================================

// Get input buffer pointer and size
PVOID GetIoctlInputBuffer(_In_ PIO_STACK_LOCATION IrpStack,
                          _Out_ PULONG OutSize);

// Get output buffer pointer and size
PVOID GetIoctlOutputBuffer(_In_ PIO_STACK_LOCATION IrpStack,
                           _Out_ PULONG OutSize);

// Safe copy to output buffer
NTSTATUS CopyToOutputBuffer(_Out_ PVOID DestBuffer, _In_ SIZE_T DestSize,
                            _In_ PVOID SourceData, _In_ SIZE_T SourceSize,
                            _Out_ PULONG_PTR OutBytesWritten);

// Safe copy from input buffer
NTSTATUS CopyFromInputBuffer(_Out_ PVOID DestBuffer, _In_ SIZE_T DestSize,
                             _In_ PVOID SourceBuffer, _In_ SIZE_T SourceSize);

//=============================================================================
// SECTION 10: Function Prototypes - Reference Counting
//=============================================================================

// Track new device open
NTSTATUS RegisterDeviceHandle(_In_ PFILE_OBJECT FileObject);

// Cleanup on device close
VOID UnregisterDeviceHandle(_In_ PFILE_OBJECT FileObject);

// Get number of active handles
ULONG GetOpenHandleCount(VOID);

// Check if any process has device open
BOOLEAN IsDeviceInUse(VOID);

//=============================================================================
// SECTION 11: Debug Functions
//=============================================================================

#ifdef DBG

// Log incoming IOCTL
VOID LogIoctlRequest(_In_ ULONG IoControlCode, _In_ ULONG ProcessId);

// Log IOCTL result
VOID LogIoctlCompletion(_In_ ULONG IoControlCode, _In_ NTSTATUS Status,
                        _In_ ULONG BytesReturned);

// Log failure details
VOID LogIoctlError(_In_ ULONG IoControlCode, _In_ NTSTATUS Status,
                   _In_ const char *ErrorMessage);

// Print IOCTL statistics
VOID DbgPrintIoctlStatistics(VOID);

#endif // DBG

#endif // SAFEOPS_IOCTL_HANDLER_H
