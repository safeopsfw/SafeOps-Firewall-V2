/**
 * driver.h - SafeOps Kernel Driver Master Header
 *
 * Master header file for the SafeOps kernel driver that defines all global
 * driver structures, function prototypes, Windows kernel APIs, and constants
 * shared across all driver modules. Serves as the central contract establishing
 * data types, synchronization primitives, and architectural boundaries between
 * NDIS filter operations, WFP callout processing, shared memory management,
 * and IOCTL communication interfaces.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#ifndef SAFEOPS_DRIVER_H
#define SAFEOPS_DRIVER_H

//=============================================================================
// SECTION 1: Windows Kernel Headers and Definitions
//=============================================================================

// Version compatibility macros - MUST be defined before including NDIS headers
#define NDIS_SUPPORT_NDIS650 1 // NDIS 6.50 support (Windows 10+)
#define NDIS650_MINIPORT 1
#define POOL_NX_OPTIN 1 // Non-executable pool memory (security)

//-----------------------------------------------------------------------------
// Conditional compilation for WDK vs IDE compatibility
// WDK Build: Define SAFEOPS_WDK_BUILD in project properties to use real headers
// IDE Mode: Uses stub definitions for IntelliSense (default when not building)
// During nmake compilation, we always use WDK headers
//-----------------------------------------------------------------------------

// For kernel mode compilation with WDK, always use real headers
#define SAFEOPS_WDK_BUILD 1

#ifdef SAFEOPS_WDK_BUILD
// ============================================================================
// WDK BUILD MODE - Use real Windows kernel headers
// ============================================================================
#include <ntddk.h>
#include <guiddef.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ndis.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <wdf.h>

#else
// ============================================================================
// IDE MODE - Stub definitions for IntelliSense (NOT used during compilation)
// ============================================================================

#include <stdbool.h>
#include <stdint.h>

// Basic Windows kernel types
typedef void VOID;
typedef unsigned char UCHAR;
typedef unsigned char BYTE;
typedef unsigned short USHORT;
typedef unsigned long ULONG;
typedef unsigned long long ULONG64;
typedef unsigned long long ULONGLONG;
typedef long LONG;
typedef long long LONG64;
typedef long long LONGLONG; // Added for performance.c
typedef void *PVOID;
typedef void *HANDLE;
typedef unsigned char BOOLEAN;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
typedef wchar_t WCHAR;
typedef unsigned int UINT32;
typedef unsigned short UINT16;
typedef unsigned long long UINT64;
typedef long NTSTATUS;
typedef unsigned long SIZE_T;

// Pointer types
typedef void *PDRIVER_OBJECT;
typedef void *PDEVICE_OBJECT;

// IRP structure for IDE mode (allows member access)
typedef struct _IO_STATUS_BLOCK_IDE {
  NTSTATUS Status;
  ULONG64 Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IRP_IDE {
  union {
    PVOID SystemBuffer;
    PVOID MasterIrp;
  } AssociatedIrp;
  IO_STATUS_BLOCK IoStatus;
} IRP, *PIRP;

// IO_STACK_LOCATION structure for IDE mode
typedef struct _DEVICE_IO_CONTROL_PARAMS {
  ULONG OutputBufferLength;
  ULONG InputBufferLength;
  ULONG IoControlCode;
  PVOID Type3InputBuffer;
} IO_CONTROL_PARAMS;

typedef struct _IO_STACK_LOCATION_IDE {
  union {
    IO_CONTROL_PARAMS DeviceIoControl;
  } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef void *PUNICODE_STRING;
typedef ULONG *PULONG;
typedef void *PUSHORT;
typedef UCHAR *PUCHAR; // Fixed from void* for performance.c
typedef void *PSIZE_T;
typedef struct _LARGE_INTEGER
    *PLARGE_INTEGER; // Forward declared struct pointer
typedef void *PMDL;
typedef void *PKEVENT;

// NDIS types
typedef void *NDIS_HANDLE;
typedef void *PNDIS_FILTER_ATTACH_PARAMETERS;
typedef void *PNDIS_FILTER_RESTART_PARAMETERS;
typedef void *PNDIS_FILTER_PAUSE_PARAMETERS;
typedef void *PNET_BUFFER_LIST;
typedef unsigned long NDIS_PORT_NUMBER;
typedef unsigned long NDIS_STATUS;
typedef unsigned long NET_IFINDEX;
typedef unsigned long NDIS_MEDIUM;
typedef unsigned long NDIS_PHYSICAL_MEDIUM;

// NDIS_STRING structure
typedef struct _NDIS_STRING {
  USHORT Length;
  USHORT MaximumLength;
  WCHAR *Buffer;
} NDIS_STRING;

// Kernel sync primitives
typedef struct _KSPIN_LOCK {
  ULONG64 Lock;
} KSPIN_LOCK, *PKSPIN_LOCK;
typedef struct _FAST_MUTEX {
  ULONG64 Mutex;
} FAST_MUTEX;
typedef struct _LIST_ENTRY {
  void *Flink;
  void *Blink;
} LIST_ENTRY;
typedef struct _LARGE_INTEGER {
  LONG64 QuadPart;
} LARGE_INTEGER;
typedef struct _PHYSICAL_ADDRESS {
  LONG64 QuadPart;
} PHYSICAL_ADDRESS;
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  WCHAR *Buffer;
} UNICODE_STRING;
typedef LARGE_INTEGER KEVENT;

// WDF types
typedef void *WDFDEVICE;
typedef void *WDFQUEUE;
typedef void *WDFDRIVER;
typedef void *WDFREQUEST;

// WFP types
typedef void *FWPS_INCOMING_VALUES0;
typedef void *FWPS_INCOMING_METADATA_VALUES0;
typedef void *FWPS_FILTER3;
typedef void *FWPS_CLASSIFY_OUT0;
typedef unsigned long FWPS_CALLOUT_NOTIFY_TYPE;

// GUID type
#ifndef _GUID_DEFINED
#define _GUID_DEFINED
typedef struct _GUID {
  ULONG Data1;
  USHORT Data2;
  USHORT Data3;
  UCHAR Data4[8];
} GUID;
#endif

// GUID macro
#ifndef DEFINE_GUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)           \
  static const GUID name = {l, w1, w2, {b1, b2, b3, b4, b5, b6, b7, b8}}
#endif

// WDF callback type macros
#ifndef DRIVER_INITIALIZE
#define DRIVER_INITIALIZE NTSTATUS
#endif
#ifndef EVT_WDF_DRIVER_UNLOAD
#define EVT_WDF_DRIVER_UNLOAD VOID
#endif
#ifndef EVT_WDF_DRIVER_DEVICE_ADD
#define EVT_WDF_DRIVER_DEVICE_ADD NTSTATUS
#endif
#ifndef EVT_WDF_DEVICE_D0_ENTRY
#define EVT_WDF_DEVICE_D0_ENTRY NTSTATUS
#endif
#ifndef EVT_WDF_DEVICE_D0_EXIT
#define EVT_WDF_DEVICE_D0_EXIT NTSTATUS
#endif
#ifndef EVT_WDF_OBJECT_CONTEXT_CLEANUP
#define EVT_WDF_OBJECT_CONTEXT_CLEANUP VOID
#endif
#ifndef EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL
#define EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL VOID
#endif

// IOCTL control code macro for IDE mode
#ifndef CTL_CODE
#define METHOD_BUFFERED 0
#define METHOD_IN_DIRECT 1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define CTL_CODE(DeviceType, Function, Method, Access)                         \
  (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

// WDF context macro
#ifndef WDF_DECLARE_CONTEXT_TYPE_WITH_NAME
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(type, name)                         \
  static inline type *name(WDFDEVICE h) { return (type *)(void *)h; }
#endif

// SAL annotations
#ifndef NTAPI
#define NTAPI
#endif
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif

// Alignment macros (guard against redefinition)
#ifndef ALIGN_UP
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#endif
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#endif

// IRQL type for IDE mode
typedef unsigned char KIRQL;
typedef KIRQL *PKIRQL;

// NTSTATUS codes for IDE mode
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#endif
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif
#ifndef STATUS_DUPLICATE_NAME
#define STATUS_DUPLICATE_NAME ((NTSTATUS)0xC00000BDL)
#endif
#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif
#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_CANCELLED
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((NTSTATUS)0xC0009A00L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NDIS status codes for IDE mode
#ifndef NDIS_STATUS_SUCCESS
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0x00000000L)
#endif
#ifndef NDIS_STATUS_FAILURE
#define NDIS_STATUS_FAILURE ((NDIS_STATUS)0xC0000001L)
#endif
#ifndef NDIS_STATUS_RESOURCES
#define NDIS_STATUS_RESOURCES ((NDIS_STATUS)0xC000009AL)
#endif
#ifndef NDIS_STATUS_NOT_SUPPORTED
#define NDIS_STATUS_NOT_SUPPORTED ((NDIS_STATUS)0xC00000BBL)
#endif

// Kernel function stubs for IDE mode (do-nothing implementations)
#ifndef DbgPrint
#define DbgPrint(...) ((void)0)
#endif
#ifndef RtlZeroMemory
#define RtlZeroMemory(Dest, Length) memset((Dest), 0, (Length))
#endif
#ifndef RtlCopyMemory
#define RtlCopyMemory(Dest, Src, Length) memcpy((Dest), (Src), (Length))
#endif
#ifndef RtlCompareMemory
#define RtlCompareMemory(Src1, Src2, Length)                                   \
  ((memcmp((Src1), (Src2), (Length)) == 0) ? (Length) : 0)
#endif
#ifndef RtlStringCbPrintfW
#define RtlStringCbPrintfW(Dest, Size, Format, ...) ((void)0)
#endif

// Spinlock stubs
#ifndef KeInitializeSpinLock
#define KeInitializeSpinLock(SpinLock) ((void)0)
#endif
#ifndef KeAcquireSpinLock
#define KeAcquireSpinLock(SpinLock, OldIrql) (*(OldIrql) = 0)
#endif
#ifndef KeReleaseSpinLock
#define KeReleaseSpinLock(SpinLock, OldIrql) ((void)0)
#endif

// Event stubs
#ifndef KeQuerySystemTime
#define KeQuerySystemTime(Time) ((Time)->QuadPart = 0)
#endif
#ifndef KeInitializeEvent
#define KeInitializeEvent(Event, Type, State) ((void)0)
#endif
#ifndef KeSetEvent
#define KeSetEvent(Event, Increment, Wait) ((void)0)
#endif
#ifndef KeWaitForSingleObject
#define KeWaitForSingleObject(Object, WaitReason, Mode, Alertable, Timeout) (0)
#endif
#ifndef KeDelayExecutionThread
#define KeDelayExecutionThread(Mode, Alertable, Interval) (0)
#endif
#ifndef NotificationEvent
#define NotificationEvent 0
#endif
#ifndef Executive
#define Executive 0
#endif
#ifndef KernelMode
#define KernelMode 0
#endif
#ifndef IO_NO_INCREMENT
#define IO_NO_INCREMENT 0
#endif

// DbgPrintEx and debug filter stubs
#ifndef DbgPrintEx
#define DbgPrintEx(ComponentId, Level, Format, ...) ((void)0)
#endif
#ifndef DPFLTR_IHVNETWORK_ID
#define DPFLTR_IHVNETWORK_ID 84
#endif
#ifndef DPFLTR_ERROR_LEVEL
#define DPFLTR_ERROR_LEVEL 0
#endif

// WDF additional types for driver.c
typedef void *WDFOBJECT;
typedef void *PWDFDEVICE_INIT;
typedef void *WDF_OBJECT_ATTRIBUTES;
typedef void *PCALLBACK_OBJECT;
typedef ULONG DEVICE_TYPE;

// WDF power device state enumeration for IDE mode
typedef enum _WDF_POWER_DEVICE_STATE {
  WdfPowerDeviceInvalid = 0,
  WdfPowerDeviceD0,
  WdfPowerDeviceD1,
  WdfPowerDeviceD2,
  WdfPowerDeviceD3,
  WdfPowerDeviceD3Final,
  WdfPowerDevicePrepareForHibernation,
  WdfPowerDeviceMaximum
} WDF_POWER_DEVICE_STATE, *PWDF_POWER_DEVICE_STATE;

// WDF structures for driver.c
typedef struct _WDF_DRIVER_CONFIG {
  ULONG Size;
  PVOID EvtDriverDeviceAdd;
  PVOID EvtDriverUnload;
  ULONG DriverPoolTag;
} WDF_DRIVER_CONFIG;

typedef struct _WDF_PNPPOWER_EVENT_CALLBACKS {
  ULONG Size;
  PVOID EvtDeviceD0Entry;
  PVOID EvtDeviceD0Exit;
} WDF_PNPPOWER_EVENT_CALLBACKS;

typedef struct _WDF_IO_QUEUE_CONFIG {
  ULONG Size;
  PVOID EvtIoDeviceControl;
  BOOLEAN PowerManaged;
} WDF_IO_QUEUE_CONFIG;

// WDF function stubs
#ifndef WDF_DRIVER_CONFIG_INIT
#define WDF_DRIVER_CONFIG_INIT(Config, DeviceAdd)                              \
  do {                                                                         \
    (Config)->EvtDriverDeviceAdd = (PVOID)(DeviceAdd);                         \
  } while (0)
#endif
#ifndef WdfDriverCreate
#define WdfDriverCreate(DriverObject, RegistryPath, Attributes, Config,        \
                        Driver)                                                \
  (0)
#endif
#ifndef WdfDeviceInitAssignName
#define WdfDeviceInitAssignName(DeviceInit, DeviceName) (0)
#endif
#ifndef WdfDeviceInitSetDeviceType
#define WdfDeviceInitSetDeviceType(DeviceInit, DeviceType) ((void)0)
#endif
#ifndef WdfDeviceInitSetCharacteristics
#define WdfDeviceInitSetCharacteristics(DeviceInit, Characteristics, AndThese) \
  ((void)0)
#endif
#ifndef WdfDeviceInitSetExclusive
#define WdfDeviceInitSetExclusive(DeviceInit, IsExclusive) ((void)0)
#endif
#ifndef WdfDeviceInitAssignSDDLString
#define WdfDeviceInitAssignSDDLString(DeviceInit, SDDLString) (0)
#endif
#ifndef WdfDeviceCreate
#define WdfDeviceCreate(DeviceInit, Attributes, Device) (0)
#endif
#ifndef WdfDeviceCreateSymbolicLink
#define WdfDeviceCreateSymbolicLink(Device, SymbolicLink) (0)
#endif
#ifndef WdfIoQueueCreate
#define WdfIoQueueCreate(Device, Config, Attributes, Queue) (0)
#endif
#ifndef WdfIoQueueGetDevice
#define WdfIoQueueGetDevice(Queue) ((WDFDEVICE)0)
#endif
#ifndef WdfRequestComplete
#define WdfRequestComplete(Request, Status) ((void)0)
#endif
#ifndef WDF_NO_OBJECT_ATTRIBUTES
#define WDF_NO_OBJECT_ATTRIBUTES ((void *)0)
#endif
#ifndef WdfFalse
#define WdfFalse 0
#endif
#ifndef WDF_PNPPOWER_EVENT_CALLBACKS_INIT
#define WDF_PNPPOWER_EVENT_CALLBACKS_INIT(Callbacks) ((void)0)
#endif
#ifndef WdfDeviceInitSetPnpPowerEventCallbacks
#define WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, Callbacks) ((void)0)
#endif
#ifndef WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(Attributes, Type) ((void)0)
#endif
#ifndef WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(Config, DispatchType) ((void)0)
#endif
#ifndef WdfIoQueueDispatchSequential
#define WdfIoQueueDispatchSequential 1
#endif
#ifndef FILE_DEVICE_NETWORK
#define FILE_DEVICE_NETWORK 0x12
#endif
#ifndef FILE_DEVICE_SECURE_OPEN
#define FILE_DEVICE_SECURE_OPEN 0x100
#endif
#ifndef SDDL_DEVOBJ_SYS_ALL_ADM_ALL
static const UNICODE_STRING SDDL_DEVOBJ_SYS_ALL_ADM_ALL = {0, 0, 0};
#endif
#ifndef RtlInitUnicodeString
#define RtlInitUnicodeString(DestStr, SrcStr) ((void)0)
#endif
#ifndef IoGetCurrentIrpStackLocation
#define IoGetCurrentIrpStackLocation(Irp) ((PIO_STACK_LOCATION)NULL)
#endif
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(Mdl, Priority) ((PVOID)NULL)
#endif
#ifndef MmGetSystemAddressForMdl
#define MmGetSystemAddressForMdl(Mdl) ((PVOID)NULL)
#endif
#ifndef IoAllocateMdl
#define IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp) ((PMDL)NULL)
#endif
#ifndef IoFreeMdl
#define IoFreeMdl(Mdl) ((void)0)
#endif
#ifndef MmBuildMdlForNonPagedPool
#define MmBuildMdlForNonPagedPool(Mdl) ((void)0)
#endif

// Callback function class annotation
#ifndef _Function_class_
#define _Function_class_(x)
#endif
#ifndef CALLBACK_FUNCTION
#define CALLBACK_FUNCTION
#endif

// Event log types
#ifndef EVENTLOG_ERROR_TYPE
#define EVENTLOG_ERROR_TYPE 0x0001
#endif
#ifndef EVENTLOG_WARNING_TYPE
#define EVENTLOG_WARNING_TYPE 0x0002
#endif
#ifndef EVENTLOG_INFORMATION_TYPE
#define EVENTLOG_INFORMATION_TYPE 0x0004
#endif

// Interlocked operations stubs
#ifndef InterlockedIncrement64
#define InterlockedIncrement64(Addend) (++(*(Addend)))
#endif
#ifndef InterlockedAdd64
#define InterlockedAdd64(Addend, Value) ((*(Addend)) += (Value))
#endif
#ifndef InterlockedExchange
#define InterlockedExchange(Target, Value) (*(Target) = (Value))
#endif

// Pool allocation stubs
#ifndef NonPagedPool
#define NonPagedPool 0
#endif
#ifndef ExAllocatePoolWithTag
#define ExAllocatePoolWithTag(PoolType, Size, Tag) malloc(Size)
#endif
#ifndef ExFreePoolWithTag
#define ExFreePoolWithTag(Ptr, Tag) free(Ptr)
#endif

// UNREFERENCED_PARAMETER macro
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#endif

// Include standard headers for IDE stubs (not for kernel mode)
// #include <stdlib.h>
// #include <string.h>

#endif // SAFEOPS_WDK_BUILD

//=============================================================================
// SECTION 2: Driver Version and Identity Constants
//=============================================================================

#define SAFEOPS_DRIVER_VERSION_MAJOR 2
#define SAFEOPS_DRIVER_VERSION_MINOR 0
#define SAFEOPS_DRIVER_VERSION_BUILD 1024
#define SAFEOPS_DRIVER_VERSION_STRING L"2.0.1024"

// Driver identity strings
#define SAFEOPS_DRIVER_NAME L"SafeOps Network Security Driver"
#define SAFEOPS_DEVICE_NAME L"\\Device\\SafeOps"
#define SAFEOPS_SYMBOLIC_LINK L"\\DosDevices\\SafeOps"
#define SAFEOPS_FILTER_NAME L"SafeOps NDIS Filter"
#define SAFEOPS_FILTER_SERVICE_NAME L"SafeOpsFilter"

// GUID Definitions - Unique identifiers for driver components
// Generated using guidgen.exe - DO NOT REUSE from other drivers

// Driver GUID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(SAFEOPS_DRIVER_GUID, 0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90);

// WFP Sublayer GUID: {B2C3D4E5-F678-90AB-CDEF-123456789012}
DEFINE_GUID(SAFEOPS_WFP_SUBLAYER_GUID, 0xb2c3d4e5, 0xf678, 0x90ab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

// WFP Callout GUIDs for IPv4/IPv6 Inbound/Outbound
DEFINE_GUID(SAFEOPS_WFP_CALLOUT_GUID_V4_INBOUND, 0xc3d4e5f6, 0x7890, 0xabcd,
            0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34);

DEFINE_GUID(SAFEOPS_WFP_CALLOUT_GUID_V4_OUTBOUND, 0xd4e5f678, 0x90ab, 0xcdef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56);

DEFINE_GUID(SAFEOPS_WFP_CALLOUT_GUID_V6_INBOUND, 0xe5f67890, 0xabcd, 0xef12,
            0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78);

DEFINE_GUID(SAFEOPS_WFP_CALLOUT_GUID_V6_OUTBOUND, 0xf6789012, 0xcdef, 0x1234,
            0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90);

//=============================================================================
// SECTION 3: Memory and Buffer Size Limits
//=============================================================================

// Ring buffer configuration (2GB total capacity)
#define RING_BUFFER_SIZE ((SIZE_T)2 * 1024 * 1024 * 1024) // 2GB
#define RING_BUFFER_ENTRY_SIZE 128                        // 128 bytes per entry
#define MAX_RING_BUFFER_ENTRIES                                                \
  (RING_BUFFER_SIZE / RING_BUFFER_ENTRY_SIZE) // 16M entries

// Packet and network limits
#define MAX_PACKET_SIZE 65536   // Maximum IPv4/IPv6 packet size
#define MAX_NIC_COUNT 8         // Maximum supported NICs
#define MAX_FILTER_RULES 65536  // Maximum concurrent firewall rules
#define MAX_CONNECTIONS 1000000 // Maximum tracked connections

// Buffer sizes
#define SHARED_BUFFER_SIZE (2ULL * 1024 * 1024 * 1024) // 2GB shared buffer
#define STATISTICS_BUFFER_SIZE 4096         // Statistics export buffer
#define IOCTL_BUFFER_MAX_SIZE (1024 * 1024) // 1MB max IOCTL buffer

// Version string
#define SAFEOPS_VERSION_MAJOR 2
#define SAFEOPS_VERSION_MINOR 0
#define SAFEOPS_VERSION_PATCH 0
#define SAFEOPS_VERSION_STRING "2.0.0"

// Performance tuning
#define DMA_BUFFER_SIZE (2 * 1024 * 1024) // 2MB DMA buffer
#define RSS_CPU_COUNT 16                  // Max RSS CPUs
#define BATCH_SIZE 64                     // Packet batch size
#define CONNECTION_HASH_TABLE_SIZE 65536  // 64K hash buckets

// Memory Pool Tags (4-byte tags for debugging with !poolused)
#define SAFEOPS_POOL_TAG 'pOfS'     // SafeOps general (SfOp reversed)
#define PACKET_POOL_TAG 'tPkP'      // Packet buffers (PkPt reversed)
#define STATISTICS_POOL_TAG 'TatS'  // Statistics (StaT reversed)
#define FILTER_RULE_POOL_TAG 'lRlF' // Filter rules (FlRl reversed)
#define CONN_POOL_TAG 'nnCK'        // Connections (KCnn reversed)
#define SHARED_MEM_TAG 'mhSK'       // Shared memory (KShm reversed)
#define NIC_POOL_TAG 'ciNK'         // NIC management (KNic reversed)
#define SAFEOPS_STRING_TAG 'rtSK'   // String allocations (KStr reversed)
#define SAFEOPS_CAPTURE_TAG 'tpCK'  // Capture buffers (KCpt reversed)

//=============================================================================
// SECTION 4: Direction, Protocol, and Action Enumerations
//=============================================================================

typedef enum _PACKET_DIRECTION {
  DIRECTION_INBOUND = 0,
  DIRECTION_OUTBOUND = 1,
  DIRECTION_BOTH = 2,
  DIRECTION_UNKNOWN = 3
} PACKET_DIRECTION;

typedef enum _PACKET_ACTION {
  ACTION_ALLOW = 0,
  ACTION_DROP = 1,
  ACTION_REJECT = 2,
  ACTION_LOG = 3,
  ACTION_INSPECT = 4,
  ACTION_PENDING = 5
} PACKET_ACTION,
    *PPACKET_ACTION;

// NIC Zone Tags (for WAN/LAN/WiFi classification)
typedef enum _NIC_TAG {
  NIC_TAG_UNKNOWN = 0,
  NIC_TAG_WAN = 1,       // Internet-facing (untrusted)
  NIC_TAG_LAN = 2,       // Internal network (trusted)
  NIC_TAG_WIFI = 3,      // Wireless interface
  NIC_TAG_DMZ = 4,       // DMZ/Server network
  NIC_TAG_MANAGEMENT = 5 // Management interface
} NIC_TAG;

// TCP Connection States
typedef enum _TCP_STATE {
  TCP_STATE_CLOSED = 0,
  TCP_STATE_LISTEN = 1,
  TCP_STATE_SYN_SENT = 2,
  TCP_STATE_SYN_RECV = 3,
  TCP_STATE_ESTABLISHED = 4,
  TCP_STATE_FIN_WAIT_1 = 5,
  TCP_STATE_FIN_WAIT_2 = 6,
  TCP_STATE_CLOSE_WAIT = 7,
  TCP_STATE_CLOSING = 8,
  TCP_STATE_LAST_ACK = 9,
  TCP_STATE_TIME_WAIT = 10
} TCP_STATE;

typedef enum _UDP_STATE {
  UDP_STATE_ACTIVE = 100,
  UDP_STATE_EXPIRED = 101
} UDP_STATE;

// Connection tracking state
typedef enum _CONN_STATE {
  CONN_STATE_NEW = 0,
  CONN_STATE_ESTABLISHED = 1,
  CONN_STATE_RELATED = 2,
  CONN_STATE_CLOSING = 3,
  CONN_STATE_CLOSED = 4,
  CONN_STATE_INVALID = 5
} CONN_STATE;

// Protocol constants
#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_ICMPV6 58

//=============================================================================
// SECTION 5: NDIS Filter Global Context Structure
//=============================================================================

/**
 * SAFEOPS_NDIS_FILTER_GLOBALS
 *
 * Primary data structure representing the NDIS filter driver's global state.
 * Allocated once during DriverEntry and persists until DriverUnload.
 * Consolidates all NDIS-related state for safe concurrent access.
 */
typedef struct _SAFEOPS_NDIS_FILTER_GLOBALS {
  // NDIS registration handles
  NDIS_HANDLE FilterDriverHandle;  // From NdisFRegisterFilterDriver
  NDIS_HANDLE FilterDriverContext; // Driver-allocated context

  // Filter identity
  NDIS_STRING FriendlyName; // Display name
  NDIS_STRING UniqueName;   // Unique identifier
  NDIS_STRING ServiceName;  // Service control manager name

  // Driver references
  PDRIVER_OBJECT DriverObject; // Windows driver object

  // Instance tracking
  volatile LONG FilterInstanceCount; // Number of attached adapters

  // Synchronization
  KSPIN_LOCK GlobalLock; // Protects global state

  // State flags
  BOOLEAN IsFilterRegistered; // Successfully registered with NDIS
  BOOLEAN IsUnloading;        // Driver is unloading

} SAFEOPS_NDIS_FILTER_GLOBALS, *PSAFEOPS_NDIS_FILTER_GLOBALS;

//=============================================================================
// SECTION 6: Per-Adapter Filter Context Structure
//=============================================================================

/**
 * SAFEOPS_FILTER_INSTANCE
 *
 * Per-network-adapter instance data structure. One instance exists for each
 * NIC where the NDIS filter attaches (e.g., WAN, LAN, WiFi).
 * Enables independent packet processing per adapter.
 */
typedef struct _SAFEOPS_FILTER_INSTANCE {
  // NDIS handles
  NDIS_HANDLE FilterHandle;        // NDIS handle for this attachment
  NDIS_HANDLE FilterModuleContext; // Instance context pointer

  // Instance identity
  NDIS_STRING FilterInstanceName; // Instance-specific name

  // NIC classification
  NIC_TAG NicTag;             // WAN/LAN/WiFi assignment
  NET_IFINDEX InterfaceIndex; // Windows network interface index

  // Media information
  NDIS_MEDIUM MediaType;                   // NdisMedium802_3 (Ethernet)
  NDIS_PHYSICAL_MEDIUM PhysicalMediumType; // Physical medium type

  // MAC address
  UCHAR MacAddress[6]; // Hardware address

  // Traffic counters (atomic)
  volatile ULONG64 BytesReceived;      // Total bytes received
  volatile ULONG64 BytesTransmitted;   // Total bytes transmitted
  volatile ULONG64 PacketsReceived;    // Packets received
  volatile ULONG64 PacketsTransmitted; // Packets transmitted
  volatile ULONG64 PacketsDropped;     // Packets dropped by filtering

  // Synchronization
  KSPIN_LOCK InstanceLock; // Protects instance state

  // State flags
  BOOLEAN IsAttached; // Filter attached to adapter
  BOOLEAN IsPaused;   // Adapter in paused state

  // Ring buffer producer
  PVOID RingBufferProducerPtr; // Pointer to ring buffer queue

} SAFEOPS_FILTER_INSTANCE, *PSAFEOPS_FILTER_INSTANCE;

//=============================================================================
// SECTION 7: WFP Callout Global Context Structure
//=============================================================================

/**
 * SAFEOPS_WFP_GLOBALS
 *
 * Global state for Windows Filtering Platform callout driver operations.
 * Manages WFP callout lifecycle and filter references.
 */
typedef struct _SAFEOPS_WFP_GLOBALS {
  // WFP engine handle
  HANDLE EngineHandle; // From FwpmEngineOpen0

  // Callout IDs (runtime assigned)
  UINT32 IPv4InboundCalloutId;  // IPv4 inbound layer
  UINT32 IPv4OutboundCalloutId; // IPv4 outbound layer
  UINT32 IPv6InboundCalloutId;  // IPv6 inbound layer
  UINT32 IPv6OutboundCalloutId; // IPv6 outbound layer

  // Filter IDs (runtime assigned)
  UINT64 IPv4InboundFilterId;  // FWPM_LAYER_INBOUND_IPPACKET_V4
  UINT64 IPv4OutboundFilterId; // FWPM_LAYER_OUTBOUND_IPPACKET_V4
  UINT64 IPv6InboundFilterId;  // FWPM_LAYER_INBOUND_IPPACKET_V6
  UINT64 IPv6OutboundFilterId; // FWPM_LAYER_OUTBOUND_IPPACKET_V6

  // Synchronization
  KSPIN_LOCK WfpLock; // Protects WFP state

  // State flags
  BOOLEAN IsWfpInitialized; // WFP callouts registered
  BOOLEAN IsUnloading;      // Unload in progress

} SAFEOPS_WFP_GLOBALS, *PSAFEOPS_WFP_GLOBALS;

//=============================================================================
// SECTION 8: Shared Memory Ring Buffer Context Structure
//=============================================================================

/**
 * SAFEOPS_RING_BUFFER_CONTEXT
 *
 * Control structure for the 2GB lock-free ring buffer shared between
 * kernel driver (producer) and userspace service (consumer).
 */
typedef struct _SAFEOPS_RING_BUFFER_CONTEXT {
  // Memory addresses
  PVOID BaseAddress;                // Kernel virtual address
  PHYSICAL_ADDRESS PhysicalAddress; // Physical address for DMA
  SIZE_T TotalSize;                 // Total buffer size (2GB)

  // Entry configuration
  ULONG EntrySize;  // Size per entry (128 bytes)
  ULONG MaxEntries; // Maximum entries (16M)

  // Producer/Consumer indices (atomic, lock-free)
  volatile ULONG ProducerIndex; // Write position (kernel)
  volatile ULONG ConsumerIndex; // Read position (userspace)

  // Memory descriptor for userspace mapping
  PMDL Mdl;              // Memory Descriptor List
  PVOID UserModeAddress; // Userspace virtual address

  // Synchronization (used sparingly)
  KSPIN_LOCK BufferLock;      // Critical section protection
  KEVENT BufferNotEmptyEvent; // Signaled when data available

  // State
  BOOLEAN IsInitialized; // Buffer allocated and mapped

  // Statistics (atomic)
  volatile ULONG64 TotalPacketsWritten;    // Lifetime write counter
  volatile ULONG64 TotalPacketsRead;       // Lifetime read counter
  volatile ULONG64 PacketsDroppedOverflow; // Dropped due to overflow

} SAFEOPS_RING_BUFFER_CONTEXT, *PSAFEOPS_RING_BUFFER_CONTEXT;

//=============================================================================
// SECTION 9: NIC Information Structure
//=============================================================================

typedef struct _NIC_INFO {
  ULONG Index;             // NIC index
  NIC_TAG Tag;             // WAN/LAN/WiFi tag
  WCHAR FriendlyName[256]; // Display name
  UCHAR MacAddress[6];     // Hardware address
  ULONG IpAddress;         // IPv4 address
  ULONG SubnetMask;        // Subnet mask
  BOOLEAN IsActive;        // Interface active

  // Statistics
  volatile ULONGLONG PacketsReceived;
  volatile ULONGLONG PacketsSent;
  volatile ULONGLONG BytesReceived;
  volatile ULONGLONG BytesSent;

} NIC_INFO, *PNIC_INFO;

//=============================================================================
// SECTION 10: Packet Information Structure
//=============================================================================

typedef struct _PACKET_INFO {
  // Layer 3 - IP Header
  ULONG SourceIP;
  ULONG DestIP;
  UCHAR Protocol;
  UCHAR TTL;
  USHORT TotalLength;

  // IPv6 (if applicable)
  UCHAR SourceIPv6[16];
  UCHAR DestIPv6[16];
  BOOLEAN IsIPv6;

  // Layer 4 - Transport Header
  USHORT SourcePort;
  USHORT DestPort;

  // TCP Flags
  BOOLEAN IsSyn;
  BOOLEAN IsAck;
  BOOLEAN IsFin;
  BOOLEAN IsRst;
  BOOLEAN IsPsh;
  BOOLEAN IsUrg;
  ULONG TcpSeqNumber;
  ULONG TcpAckNumber;

  // Metadata
  PACKET_DIRECTION Direction;
  NIC_TAG SourceNicTag;
  NIC_TAG DestNicTag;
  ULONG NicIndex;
  LARGE_INTEGER Timestamp;

  // Performance
  ULONG ProcessorNumber;
  ULONG QueueId;

  // Payload (for DPI)
  PVOID PayloadBuffer;
  SIZE_T PayloadLength;

} PACKET_INFO, *PPACKET_INFO;

//=============================================================================
// SECTION 11: Filter Rule Structure
//=============================================================================

typedef struct _FILTER_RULE {
  // Identity
  ULONG RuleId;
  ULONG Priority; // 0=highest, 255=lowest
  BOOLEAN Enabled;

  // Match criteria - Source
  ULONG SourceIP;
  ULONG SourceMask;
  USHORT SourcePortStart;
  USHORT SourcePortEnd;

  // Match criteria - Destination
  ULONG DestIP;
  ULONG DestMask;
  USHORT DestPortStart;
  USHORT DestPortEnd;

  // Protocol and direction
  UCHAR Protocol; // 0=any, 6=TCP, 17=UDP
  PACKET_DIRECTION Direction;
  NIC_TAG SourceNicTag;
  NIC_TAG DestNicTag;

  // Action
  PACKET_ACTION Action;

  // Logging
  BOOLEAN LogMatches;

  // Statistics
  volatile ULONGLONG MatchCount;
  LARGE_INTEGER LastMatch;

  // List linkage
  LIST_ENTRY ListEntry;

} FILTER_RULE, *PFILTER_RULE;

//=============================================================================
// SECTION 12: Connection Tracking Structure
//=============================================================================

typedef struct _CONNECTION_ENTRY {
  // 5-tuple key
  ULONG SourceIP;
  ULONG DestIP;
  USHORT SourcePort;
  USHORT DestPort;
  UCHAR Protocol;
  UCHAR IpVersion; // 4 or 6

  // State
  CONN_STATE ConnState;
  TCP_STATE TcpState;

  // Timestamps
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER LastActivity;
  ULONG TimeoutSeconds;

  // Statistics
  volatile ULONGLONG PacketsIn;
  volatile ULONGLONG PacketsOut;
  volatile ULONGLONG BytesIn;
  volatile ULONGLONG BytesOut;

  // Hash table linkage
  struct _CONNECTION_ENTRY *Next;
  struct _CONNECTION_ENTRY *Prev;

} CONNECTION_ENTRY, *PCONNECTION_ENTRY;

//=============================================================================
// SECTION 13: Ring Buffer Header and Packet Log Entry
//=============================================================================

typedef struct _RING_BUFFER_HEADER {
  volatile ULONG WriteOffset;
  volatile ULONG ReadOffset;
  ULONG BufferSize;
  volatile ULONG DroppedPackets;
  KSPIN_LOCK Lock;
} RING_BUFFER_HEADER, *PRING_BUFFER_HEADER;

typedef struct _PACKET_LOG_ENTRY {
  LARGE_INTEGER Timestamp;
  PACKET_INFO PacketInfo;
  PACKET_ACTION Action;
  ULONG RuleId;
  UCHAR PayloadSnippet[128]; // First 128 bytes
} PACKET_LOG_ENTRY, *PPACKET_LOG_ENTRY;

//=============================================================================
// SECTION 14: Driver State and Configuration Types
//=============================================================================

// Driver state enumeration
typedef enum _DRIVER_STATE {
  DRIVER_STATE_UNINITIALIZED = 0,
  DRIVER_STATE_INITIALIZING = 1,
  DRIVER_STATE_RUNNING = 2,
  DRIVER_STATE_PAUSING = 3,
  DRIVER_STATE_PAUSED = 4,
  DRIVER_STATE_SHUTTING_DOWN = 5,
  DRIVER_STATE_UNLOADING = 6,
  DRIVER_STATE_UNLOADED = 7
} DRIVER_STATE;

// Global driver state structure
typedef struct _GLOBAL_DRIVER_STATE {
  volatile DRIVER_STATE State;
  volatile LONG ReferenceCount;           // Reference counting
  KSPIN_LOCK StateLock;
  KEVENT ShutdownEvent;
  BOOLEAN IsSystemShuttingDown;
  BOOLEAN IsPowerTransition;
  BOOLEAN PowerCallbacksRegistered;       // Power callback state
  PVOID PowerCallbackHandle;
  LARGE_INTEGER StartTime;
  LARGE_INTEGER LastStatsResetTime;
} GLOBAL_DRIVER_STATE, *PGLOBAL_DRIVER_STATE;

// Driver configuration structure
typedef struct _DRIVER_CONFIG {
  ULONG MaxFilterRules;
  ULONG MaxConnections;
  ULONG SharedBufferSizeMB;
  ULONG DmaBufferSizeMB;                  // DMA buffer size in MB
  BOOLEAN EnableLogging;
  BOOLEAN EnableDeepInspection;
  BOOLEAN EnableRss;
  ULONG RssCpuCount;
  ULONG LogLevel;
} DRIVER_CONFIG, *PDRIVER_CONFIG;

// External declarations for global variables
extern GLOBAL_DRIVER_STATE g_DriverState;
extern DRIVER_CONFIG g_DriverConfig;

//=============================================================================
// SECTION 15: Global Driver State Structure (Top-Level)
//=============================================================================

/**
 * SAFEOPS_GLOBAL_CONTEXT (also referred to as DRIVER_CONTEXT)
 *
 * Top-level driver state structure that aggregates all subsystem contexts.
 * This is the single global variable representing the entire driver.
 */
typedef struct _DRIVER_CONTEXT {
  // WDF Objects
  WDFDEVICE Device;
  WDFQUEUE DefaultQueue;

  // Subsystem contexts
  SAFEOPS_NDIS_FILTER_GLOBALS NdisGlobals;
  SAFEOPS_WFP_GLOBALS WfpGlobals;
  SAFEOPS_RING_BUFFER_CONTEXT RingBuffer;

  // WFP Handles (legacy compatibility)
  HANDLE EngineHandle;
  ULONG CalloutIdIPv4Inbound;
  ULONG CalloutIdIPv4Outbound;
  ULONG FilterIdInbound;
  ULONG FilterIdOutbound;

  // NDIS Handles (legacy compatibility)
  NDIS_HANDLE NdisFilterHandle;
  NDIS_HANDLE NdisPoolHandle;

  // NIC Management
  NIC_INFO NicList[MAX_NIC_COUNT];
  ULONG NicCount;
  KSPIN_LOCK NicLock;

  // Filter Rules
  LIST_ENTRY FilterRuleList;
  ULONG FilterRuleCount;
  KSPIN_LOCK FilterLock;

  // Connection Tracking
  PCONNECTION_ENTRY *ConnHashTable;
  ULONG ConnHashSize;
  volatile LONG ConnCount;
  KSPIN_LOCK ConnLocks[256]; // Fine-grained locking

  // Shared Memory (legacy)
  PVOID SharedMemory;
  PMDL SharedMemoryMdl;
  PVOID UserMappedAddress;
  PRING_BUFFER_HEADER RingBufferHeader;

  // Device objects
  PDEVICE_OBJECT DeviceObject; // For IOCTL communication
  UNICODE_STRING DeviceName;
  UNICODE_STRING SymbolicLink;
  FAST_MUTEX DeviceMutex;
  ULONG IoctlOpenCount; // Reference counting
  BOOLEAN IsDeviceCreated;

  // Statistics (1024 bytes - comprehensive counters structure)
  // Note: Forward declared, actual type defined in statistics.h
  struct {
    // Packet counters (64 bytes)
    volatile ULONGLONG PacketsReceived;
    volatile ULONGLONG PacketsTransmitted;
    volatile ULONGLONG BytesReceived;
    volatile ULONGLONG BytesTransmitted;
    volatile ULONGLONG PacketsDropped;
    volatile ULONGLONG TotalErrors;
    ULONGLONG Reserved1[2];

    // Per-NIC-type counters (64 bytes)
    volatile ULONGLONG WanPacketsReceived;
    volatile ULONGLONG WanPacketsTransmitted;
    volatile ULONGLONG LanPacketsReceived;
    volatile ULONGLONG LanPacketsTransmitted;
    volatile ULONGLONG WifiPacketsReceived;
    volatile ULONGLONG WifiPacketsTransmitted;
    ULONGLONG Reserved2[2];

    // Filter counters (64 bytes)
    volatile ULONGLONG FilterAllowCount;
    volatile ULONGLONG FilterDenyCount;
    volatile ULONGLONG FilterDropCount;
    volatile ULONGLONG TotalFilterEvaluationTime;
    volatile ULONGLONG FilterEvaluationCount;
    volatile ULONGLONG FilterCacheHits;
    volatile ULONGLONG FilterCacheMisses;
    ULONGLONG Reserved3;

    // Latency counters (64 bytes)
    volatile ULONGLONG TotalLatencyMicroseconds;
    volatile ULONGLONG LatencySampleCount;
    volatile ULONGLONG PeakLatencyMicroseconds;
    volatile ULONGLONG MinLatencyMicroseconds;
    ULONGLONG Reserved4[4];

    // Memory counters (64 bytes)
    volatile ULONG RingBufferFillPercent;
    volatile ULONG RingBufferPeakFillPercent;
    volatile ULONGLONG NonPagedPoolUsage;
    volatile ULONGLONG NonPagedPoolPeak;
    volatile ULONGLONG AllocationCount;
    volatile ULONGLONG AllocationFailures;
    ULONGLONG Reserved5[3];

    // Drop reason counters (128 bytes)
    volatile ULONGLONG DropsByReason[16];

    // Error type counters (128 bytes)
    volatile ULONGLONG ErrorsByType[16];

    // Connection tracking (64 bytes)
    volatile ULONGLONG ActiveConnections;
    volatile ULONGLONG TotalConnections;
    volatile ULONGLONG ConnectionTimeouts;
    volatile ULONGLONG ConnectionRejects;
    ULONGLONG Reserved6[4];

    // Future expansion (384 bytes)
    ULONGLONG Reserved7[48];
  } Statistics;

  KSPIN_LOCK StatisticsLock;

  // Performance
  BOOLEAN RssEnabled;
  ULONG RssCpuCount;
  PVOID DmaBuffer;
  PHYSICAL_ADDRESS DmaPhysicalAddress;

  // Legacy global statistics (for backward compatibility)
  volatile ULONGLONG PacketsProcessed;
  volatile ULONGLONG PacketsAllowed;
  volatile ULONGLONG PacketsDroppedLegacy;
  volatile ULONGLONG BytesProcessed;
  LARGE_INTEGER DriverStartTime;
  LARGE_INTEGER LastStatisticsReset;

  // Configuration
  BOOLEAN LoggingEnabled;
  BOOLEAN DeepInspectionEnabled;
  ULONG MaxPacketSize;

  // Missing fields for driver operation
  KSPIN_LOCK Lock;
  BOOLEAN IsRunning;
  PVOID SharedBuffer;
  SIZE_T SharedBufferSize;
  volatile ULONGLONG TotalPacketsProcessed;
  volatile ULONGLONG PacketsBlocked;
  volatile ULONGLONG PacketsDropped;      // Dropped packets counter

} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, GetDriverContext)

// Alias for specification compatibility
typedef DRIVER_CONTEXT SAFEOPS_GLOBAL_CONTEXT;
typedef PDRIVER_CONTEXT PSAFEOPS_GLOBAL_CONTEXT;

//=============================================================================
// SECTION 15: Function Prototypes - Driver Lifecycle
//=============================================================================

// Driver entry and unload
// Note: In WDK builds, these use WDF callback macros. For IDE, explicit
// prototypes.
#ifdef SAFEOPS_WDK_BUILD
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SafeOpsEvtDriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD SafeOpsEvtDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY SafeOpsEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT SafeOpsEvtDeviceD0Exit;
EVT_WDF_OBJECT_CONTEXT_CLEANUP SafeOpsEvtDeviceContextCleanup;
#else
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);
VOID SafeOpsEvtDriverUnload(_In_ WDFDRIVER Driver);
NTSTATUS SafeOpsEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PVOID DeviceInit);
NTSTATUS SafeOpsEvtDeviceD0Entry(_In_ WDFDEVICE Device,
                                 _In_ PVOID PreviousState);
NTSTATUS SafeOpsEvtDeviceD0Exit(_In_ WDFDEVICE Device, _In_ PVOID TargetState);
VOID SafeOpsEvtDeviceContextCleanup(_In_ WDFDEVICE Device);
#endif

// Driver initialization helpers
NTSTATUS SafeOpsInitializeDriverContext(_In_ WDFDEVICE Device);
VOID SafeOpsCleanupDriverContext(_In_ WDFDEVICE Device);
NTSTATUS SafeOpsInitializeAllComponents(_In_ PDRIVER_CONTEXT Context);
VOID SafeOpsCleanupAllComponents(_In_ PDRIVER_CONTEXT Context);

// Subsystem initialization
NTSTATUS InitializeNdisFilter(_In_ PDRIVER_OBJECT DriverObject);
VOID CleanupNdisFilter(VOID);
NTSTATUS InitializeWfpCallouts(_In_ PDEVICE_OBJECT DeviceObject);
VOID CleanupWfpCallouts(VOID);
NTSTATUS InitializeRingBuffer(_In_ PDRIVER_CONTEXT DriverContext);
NTSTATUS CleanupRingBuffer(_In_ PDRIVER_CONTEXT DriverContext);
NTSTATUS CreateDeviceObject(_In_ PDRIVER_OBJECT DriverObject);
VOID DeleteDeviceObject(_In_ PDRIVER_OBJECT DriverObject);

//=============================================================================
// SECTION 16: Function Prototypes - NDIS Filter Handlers
//=============================================================================

NDIS_STATUS FilterAttach(_In_ NDIS_HANDLE NdisFilterHandle,
                         _In_ NDIS_HANDLE FilterDriverContext,
                         _In_ PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters);

NDIS_STATUS FilterDetach(_In_ NDIS_HANDLE FilterModuleContext);

NDIS_STATUS
FilterRestart(_In_ NDIS_HANDLE FilterModuleContext,
              _In_ PNDIS_FILTER_RESTART_PARAMETERS RestartParameters);

NDIS_STATUS FilterPause(_In_ NDIS_HANDLE FilterModuleContext,
                        _In_ PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters);

VOID FilterSendNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                              _In_ PNET_BUFFER_LIST NetBufferLists,
                              _In_ NDIS_PORT_NUMBER PortNumber,
                              _In_ ULONG SendFlags);

VOID FilterSendNetBufferListsComplete(_In_ NDIS_HANDLE FilterModuleContext,
                                      _In_ PNET_BUFFER_LIST NetBufferLists,
                                      _In_ ULONG SendCompleteFlags);

VOID FilterReceiveNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                                 _In_ PNET_BUFFER_LIST NetBufferLists,
                                 _In_ NDIS_PORT_NUMBER PortNumber,
                                 _In_ ULONG NumberOfNetBufferLists,
                                 _In_ ULONG ReceiveFlags);

VOID FilterReturnNetBufferLists(_In_ NDIS_HANDLE FilterModuleContext,
                                _In_ PNET_BUFFER_LIST NetBufferLists,
                                _In_ ULONG ReturnFlags);

//=============================================================================
// SECTION 17: Function Prototypes - WFP Callout Handlers
//=============================================================================

VOID NTAPI WfpCalloutClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ VOID *layerData, _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER3 *filter, _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut);

NTSTATUS NTAPI WfpCalloutNotifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                                  _In_ const GUID *filterKey,
                                  _Inout_ FWPS_FILTER3 *filter);

VOID NTAPI WfpCalloutFlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId,
                                  _In_ UINT64 flowContext);

//=============================================================================
// SECTION 18: Function Prototypes - IOCTL Handlers
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SafeOpsEvtIoDeviceControl;
#else
VOID SafeOpsEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ PVOID Request,
                               _In_ SIZE_T OutputBufferLength,
                               _In_ SIZE_T InputBufferLength,
                               _In_ ULONG IoControlCode);
#endif

NTSTATUS IoctlCreateHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS IoctlCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS IoctlDeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject,
                                   _Inout_ PIRP Irp);
NTSTATUS ProcessIoctlCommand(_Inout_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpStack,
                             _In_ ULONG IoControlCode);
NTSTATUS DispatchIoControl(_In_ PDRIVER_CONTEXT Context, _In_ WDFREQUEST Request,
                          _In_ ULONG IoControlCode, _In_ SIZE_T InputBufferLength,
                          _In_ SIZE_T OutputBufferLength);

// Specific IOCTL handlers (see ioctl_handler.h for authoritative declarations)
//=============================================================================
// SECTION 19: Function Prototypes - Packet Capture
//=============================================================================

NTSTATUS PacketCaptureInitialize(_In_ PDRIVER_CONTEXT Context);
VOID PacketCaptureCleanup(_In_ PDRIVER_CONTEXT Context);
NTSTATUS ProcessPacket(_In_ PDRIVER_CONTEXT Context,
                       _In_ PPACKET_INFO PacketInfo,
                       _In_opt_ const BYTE *Payload, _In_ SIZE_T PayloadLength,
                       _Out_ PPACKET_ACTION Action);

//=============================================================================
// SECTION 20: Function Prototypes - Filter Engine
//=============================================================================

NTSTATUS FilterEngineInitialize(_In_ PDRIVER_CONTEXT Context);
VOID FilterEngineCleanup(_In_ PDRIVER_CONTEXT Context);
NTSTATUS AddFilterRule(_In_ PDRIVER_CONTEXT Context, _In_ PFILTER_RULE Rule);
NTSTATUS RemoveFilterRule(_In_ PDRIVER_CONTEXT Context, _In_ ULONG RuleId);
NTSTATUS EvaluatePacket(_In_ PDRIVER_CONTEXT Context,
                        _In_ PPACKET_INFO PacketInfo,
                        _Out_ PPACKET_ACTION Action,
                        _Out_opt_ PULONG MatchedRuleId);

//=============================================================================
// SECTION 21: Function Prototypes - Shared Memory / Ring Buffer
//=============================================================================

NTSTATUS SharedMemoryInitialize(_In_ PDRIVER_CONTEXT Context);
VOID SharedMemoryCleanup(_In_ PDRIVER_CONTEXT Context);
NTSTATUS SharedMemoryMapToUser(_In_ PDRIVER_CONTEXT Context,
                               _Out_ PVOID *UserAddress);
NTSTATUS LogPacketToRingBuffer(_In_ PDRIVER_CONTEXT Context,
                               _In_ PPACKET_LOG_ENTRY Entry);

// Ring buffer operations (lock-free) - See shared_memory.h for inline helpers
NTSTATUS InitializeRingBuffer(_In_ PDRIVER_CONTEXT DriverContext);
NTSTATUS CleanupRingBuffer(_In_ PDRIVER_CONTEXT DriverContext);
NTSTATUS MapRingBufferToUserspace(_In_ PDRIVER_CONTEXT DriverContext,
                                  _Out_ PVOID *UserAddress);
NTSTATUS UnmapRingBufferFromUserspace(_In_ PDRIVER_CONTEXT DriverContext,
                                      _In_ PVOID UserAddress);
ULONG RingBufferGetFillPercentage(_In_ PSAFEOPS_RING_BUFFER_CONTEXT RingBuffer);
NTSTATUS RingBufferWrite(_In_ PVOID PacketData, _In_ ULONG DataSize,
                         _In_ NIC_TAG NicTag);
BOOLEAN RingBufferIsFull(VOID);
BOOLEAN RingBufferIsEmpty(VOID);
ULONG RingBufferAvailable(_In_ PRING_BUFFER_HEADER RingBufferHeader);

//=============================================================================
// SECTION 22: Function Prototypes - NIC Management
//=============================================================================

NTSTATUS NicManagementInitialize(_In_ PDRIVER_CONTEXT Context);
VOID NicManagementCleanup(_In_ PDRIVER_CONTEXT Context);
NTSTATUS EnumerateNetworkInterfaces(_In_ PDRIVER_CONTEXT Context);
NTSTATUS SetNicTag(_In_ PDRIVER_CONTEXT Context, _In_ ULONG NicIndex,
                   _In_ NIC_TAG Tag);
NIC_TAG GetNicTag(_In_ PDRIVER_CONTEXT Context, _In_ ULONG NicIndex);

//=============================================================================
// SECTION 23: Function Prototypes - Performance
//=============================================================================

NTSTATUS PerformanceInitialize(_In_ PDRIVER_CONTEXT Context);
VOID PerformanceCleanup(_In_ PDRIVER_CONTEXT Context);
NTSTATUS EnableRss(_In_ PDRIVER_CONTEXT Context, _In_ ULONG CpuCount);
NTSTATUS AllocateDmaBuffer(_In_ PDRIVER_CONTEXT Context,
                           _In_ SIZE_T BufferSize);
VOID FreeDmaBuffer(_In_ PDRIVER_CONTEXT Context);

//=============================================================================
// SECTION 24: Function Prototypes - Utility Functions
//=============================================================================

VOID GetCurrentTimestamp(_Out_ PLARGE_INTEGER Timestamp);
NTSTATUS AllocateNonPagedMemory(_In_ SIZE_T Size, _In_ ULONG PoolTag,
                                _Out_ PVOID *OutBuffer);
VOID FreeNonPagedMemory(_In_ PVOID Buffer, _In_ ULONG PoolTag);
VOID AcquireSpinLockAtDpcLevel(_In_ PKSPIN_LOCK SpinLock);
VOID ReleaseSpinLockFromDpcLevel(_In_ PKSPIN_LOCK SpinLock);
ULONG CalculateIPv4Checksum(_In_ PVOID PacketData, _In_ ULONG Length);
BOOLEAN IsPacketIPv4(_In_ PVOID PacketData);
BOOLEAN IsPacketIPv6(_In_ PVOID PacketData);
VOID ParseEthernetHeader(_In_ PVOID PacketData, _Out_ PUSHORT EtherType,
                         _Out_ PVOID *IpHeader);
VOID ParseIPv4Header(_In_ PVOID IpHeader, _Out_ PULONG SourceIP,
                     _Out_ PULONG DestIP, _Out_ PUCHAR Protocol);

//=============================================================================
// SECTION 25: Utility Macros and Debug Logging
//=============================================================================

// Debug print levels
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_VERBOSE 5

#define SAFEOPS_LOG_INFO(format, ...)                                          \
  DbgPrint("[SafeOps] INFO: " format "\n", ##__VA_ARGS__)

#define SAFEOPS_LOG_WARNING(format, ...)                                       \
  DbgPrint("[SafeOps] WARNING: " format "\n", ##__VA_ARGS__)

#define SAFEOPS_LOG_ERROR(format, ...)                                         \
  DbgPrint("[SafeOps] ERROR: " format "\n", ##__VA_ARGS__)

#define SAFEOPS_LOG_DEBUG(format, ...)                                         \
  DbgPrint("[SafeOps] DEBUG: " format "\n", ##__VA_ARGS__)

#ifdef DBG
#define SAFEOPS_ASSERT(condition)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      DbgPrint("[SafeOps] ASSERTION FAILED: %s at %s:%d\n", #condition,        \
               __FILE__, __LINE__);                                            \
      DbgBreakPoint();                                                         \
    }                                                                          \
  } while (0)
#else
#define SAFEOPS_ASSERT(condition) ((void)0)
#endif

// IPv4 Helper Macros
#define MAKE_IP_ADDRESS(a, b, c, d)                                            \
  ((ULONG)((((ULONG)(a)) << 24) | (((ULONG)(b)) << 16) | (((ULONG)(c)) << 8) | \
           ((ULONG)(d))))

#define IP_A(ip) ((UCHAR)((ip) >> 24))
#define IP_B(ip) ((UCHAR)((ip) >> 16))
#define IP_C(ip) ((UCHAR)((ip) >> 8))
#define IP_D(ip) ((UCHAR)(ip))

// Alignment macros (guarded to prevent redefinition)
#ifndef ALIGN_UP
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#endif
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#endif

#endif // SAFEOPS_DRIVER_H
