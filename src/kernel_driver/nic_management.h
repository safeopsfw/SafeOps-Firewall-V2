/**
 * nic_management.h - SafeOps NIC Management Interface
 *
 * Purpose: Defines the interface for managing network interface cards (NICs),
 * including NIC identification, tagging (WAN/LAN/WiFi), enable/disable control,
 * and adapter enumeration. Establishes the framework for the three physical
 * NICs and routing traffic based on interface type for multi-homed gateway
 * functionality.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 *
 * CRITICAL: Exactly one NIC must be tagged as WAN, one as LAN, one as WiFi.
 * This is enforced by validation functions.
 */

#ifndef SAFEOPS_NIC_MANAGEMENT_H
#define SAFEOPS_NIC_MANAGEMENT_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header

#ifdef SAFEOPS_WDK_BUILD
#include <ndis.h> // NDIS adapter management APIs
#else
// IDE Mode - NDIS type stubs (only define if not already defined)
#ifndef NET_IFINDEX
typedef unsigned long NET_IFINDEX;
#endif
#ifndef _NDIS_MEDIUM_DEFINED
#define _NDIS_MEDIUM_DEFINED
typedef ULONG NDIS_MEDIUM;
typedef ULONG NDIS_PHYSICAL_MEDIUM;
#endif
#ifndef PGUID_DEFINED
#define PGUID_DEFINED
typedef GUID *PGUID;
#endif
#endif

//=============================================================================
// SECTION 2: NIC Constants
//=============================================================================

#define MAX_NIC_COUNT 8        // Maximum supported NICs
#define MAX_NIC_NAME_LENGTH 32 // Friendly name max chars
#define MAX_NIC_GUID_LENGTH 40 // GUID string length

//=============================================================================
// SECTION 3: NIC Type Enumeration
//=============================================================================

/**
 * NIC_TYPE
 *
 * Classification for the three NIC categories used throughout SafeOps.
 *
 * Usage Rules:
 *   - Exactly one NIC must be tagged as WAN (internet-facing)
 *   - Exactly one NIC must be tagged as LAN (wired local network)
 *   - Exactly one NIC must be tagged as WIFI (wireless access point)
 *   - Tagging is configured via IOCTL from userspace during initialization
 */
typedef enum _NIC_TYPE {
  NIC_TYPE_UNTAGGED = 0, // Not yet classified
  NIC_TYPE_WAN = 1,      // Internet-facing interface (single)
  NIC_TYPE_LAN = 2,      // Wired local area network (single)
  NIC_TYPE_WIFI = 3      // Wireless access point (single)
} NIC_TYPE;

//=============================================================================
// SECTION 4: NIC State Enumeration
//=============================================================================

/**
 * NIC_STATE
 *
 * Operational states for network adapters.
 */
typedef enum _NIC_STATE {
  NIC_STATE_DETACHED = 0,   // Filter not attached to adapter
  NIC_STATE_ATTACHED = 1,   // Filter attached but paused
  NIC_STATE_RUNNING = 2,    // Filter active, capturing packets
  NIC_STATE_PAUSED = 3,     // Filter paused (power mgmt or user)
  NIC_STATE_RESTARTING = 4, // Filter restarting after pause
  NIC_STATE_ERROR = 5       // Filter in error state
} NIC_STATE;

/**
 * NIC_LINK_STATE
 *
 * Physical link status.
 */
typedef enum _NIC_LINK_STATE {
  NIC_LINK_DOWN = 0,
  NIC_LINK_UP = 1,
  NIC_LINK_UNKNOWN = 2
} NIC_LINK_STATE;

//=============================================================================
// SECTION 5: NIC Identification Structure (64 bytes)
//=============================================================================

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

/**
 * NIC_IDENTIFIER
 *
 * Unique identification for one NIC using multiple methods.
 */
typedef struct _NIC_IDENTIFIER {
  NET_IFINDEX InterfaceIndex;       // 4 bytes - Windows interface index
  ULONG Reserved1;                  // 4 bytes - Padding
  NDIS_HANDLE FilterHandle;         // 8 bytes - NDIS filter handle
  GUID InterfaceGuid;               // 16 bytes - Network interface GUID
  UCHAR MACAddress[6];              // 6 bytes - Hardware MAC address
  UCHAR Reserved2[2];               // 2 bytes - Padding
  WCHAR FriendlyName[12];           // 24 bytes - Short display name
} NIC_IDENTIFIER, *PNIC_IDENTIFIER; // Total: 64 bytes

//=============================================================================
// SECTION 6: NIC Configuration Structure (128 bytes)
//=============================================================================

/**
 * NIC_CONFIGURATION
 *
 * User-configurable NIC parameters.
 */
typedef struct _NIC_CONFIGURATION {
  NIC_TYPE NICType;                       // 4 bytes - WAN/LAN/WiFi
  BOOLEAN IsEnabled;                      // 1 byte - Capture enabled
  BOOLEAN IsPromiscuous;                  // 1 byte - Promiscuous mode
  BOOLEAN CaptureInbound;                 // 1 byte - Capture incoming
  BOOLEAN CaptureOutbound;                // 1 byte - Capture outgoing
  ULONG MaxPacketsPerSecond;              // 4 bytes - Rate limit (0=unlimited)
  ULONG CaptureFilterFlags;               // 4 bytes - Packet type filter
  USHORT MTU;                             // 2 bytes - Maximum Transmission Unit
  UCHAR Reserved[110];                    // 110 bytes - Future config
} NIC_CONFIGURATION, *PNIC_CONFIGURATION; // Total: 128 bytes

//=============================================================================
// SECTION 7: NIC Statistics Structure (256 bytes)
//=============================================================================

/**
 * NIC_STATISTICS
 *
 * Per-NIC performance counters.
 */
typedef struct _NIC_STATISTICS {
  // Packet counters (64 bytes)
  ULONG64 PacketsReceived;    // 8 bytes
  ULONG64 PacketsTransmitted; // 8 bytes
  ULONG64 BytesReceived;      // 8 bytes
  ULONG64 BytesTransmitted;   // 8 bytes
  ULONG64 PacketsDropped;     // 8 bytes
  ULONG64 ErrorsReceived;     // 8 bytes
  ULONG64 ErrorsTransmitted;  // 8 bytes
  ULONG64 PacketsWithErrors;  // 8 bytes

  // Performance metrics (32 bytes)
  ULONG LinkSpeedMbps;           // 4 bytes
  ULONG CurrentPacketsPerSecond; // 4 bytes
  ULONG PeakPacketsPerSecond;    // 4 bytes
  ULONG CPUUsagePercent;         // 4 bytes
  LARGE_INTEGER FirstPacketTime; // 8 bytes
  LARGE_INTEGER LastPacketTime;  // 8 bytes

  // Reserved (160 bytes)
  UCHAR Reserved[160];              // 160 bytes
} NIC_STATISTICS, *PNIC_STATISTICS; // Total: 256 bytes

//=============================================================================
// SECTION 8: NIC Context Structure (512 bytes)
//=============================================================================

/**
 * NIC_CONTEXT
 *
 * Complete runtime state for one NIC.
 */
typedef struct _NIC_CONTEXT {
  // Identification (64 bytes)
  NIC_IDENTIFIER Identifier;

  // Configuration (128 bytes)
  NIC_CONFIGURATION Configuration;

  // Statistics (256 bytes)
  NIC_STATISTICS Statistics;

  // State (32 bytes)
  NIC_STATE CurrentState;              // 4 bytes
  NDIS_MEDIUM MediaType;               // 4 bytes
  NDIS_PHYSICAL_MEDIUM PhysicalMedium; // 4 bytes
  NIC_LINK_STATE LinkState;            // 4 bytes
  KSPIN_LOCK StatisticsLock;           // 8 bytes
  PVOID RingBufferQueue;               // 8 bytes (future)

  // Reserved (32 bytes)
  UCHAR Reserved[32];         // 32 bytes
} NIC_CONTEXT, *PNIC_CONTEXT; // Total: 512 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
#endif

//=============================================================================
// SECTION 9: Global NIC Table Structure
//=============================================================================

/**
 * NIC_TABLE
 *
 * Driver-wide NIC management structure.
 */
typedef struct _NIC_TABLE {
  NIC_CONTEXT NICs[MAX_NIC_COUNT]; // Array of NIC contexts
  ULONG AttachedCount;             // Currently attached NICs
  ULONG EnabledCount;              // NICs with capture enabled
  KSPIN_LOCK TableLock;            // Protects modifications
  BOOLEAN IsInitialized;           // TRUE if initialized
  UCHAR Reserved[7];               // Padding
} NIC_TABLE, *PNIC_TABLE;

//=============================================================================
// SECTION 10: Function Prototypes - Initialization
//=============================================================================

// Initialize global NIC table
NTSTATUS NicTableInitialize(VOID);

// Cleanup NIC table
VOID NicTableCleanup(VOID);

// Register new NIC during filter attach
NTSTATUS NicTableRegister(_In_ NDIS_HANDLE FilterHandle,
                          _In_ PVOID AttachParams,
                          _Out_ PNIC_CONTEXT *OutContext);

// Unregister NIC during filter detach
NTSTATUS NicTableUnregister(_In_ NDIS_HANDLE FilterHandle);

// Get number of registered NICs
ULONG NicTableGetCount(VOID);

//=============================================================================
// SECTION 11: Function Prototypes - Lookup Operations
//=============================================================================

// Lookup by NDIS handle
PNIC_CONTEXT NicFindByFilterHandle(_In_ NDIS_HANDLE FilterHandle);

// Lookup by Windows interface index
PNIC_CONTEXT NicFindByInterfaceIndex(_In_ NET_IFINDEX InterfaceIndex);

// Get WAN, LAN, or WiFi NIC
PNIC_CONTEXT NicFindByType(_In_ NIC_TYPE NICType);

// Lookup by MAC address
PNIC_CONTEXT NicFindByMAC(_In_ PUCHAR MACAddress);

// Lookup by interface GUID
PNIC_CONTEXT NicFindByGUID(_In_ PGUID InterfaceGuid);

//=============================================================================
// SECTION 12: Function Prototypes - Configuration
//=============================================================================

// Tag NIC as WAN/LAN/WiFi
NTSTATUS NicSetType(_Inout_ PNIC_CONTEXT Context, _In_ NIC_TYPE NICType);

// Enable/disable capture
NTSTATUS NicSetEnabled(_Inout_ PNIC_CONTEXT Context, _In_ BOOLEAN IsEnabled);

// Set promiscuous mode
NTSTATUS NicSetPromiscuousMode(_Inout_ PNIC_CONTEXT Context,
                               _In_ BOOLEAN IsPromiscuous);

// Configure packet type filter
NTSTATUS NicSetCaptureFlags(_Inout_ PNIC_CONTEXT Context, _In_ ULONG Flags);

// Set rate limit
NTSTATUS NicSetRateLimit(_Inout_ PNIC_CONTEXT Context, _In_ ULONG MaxPPS);

// Query configuration
NTSTATUS NicGetConfiguration(_In_ PNIC_CONTEXT Context,
                             _Out_ PNIC_CONFIGURATION OutConfig);

//=============================================================================
// SECTION 13: Function Prototypes - Statistics
//=============================================================================

// Update packet counters (called from NDIS callbacks at DISPATCH_LEVEL)
VOID NicIncrementPacketCount(_Inout_ PNIC_CONTEXT Context,
                             _In_ BOOLEAN IsInbound, _In_ ULONG64 ByteCount);

// Increment drop counter
VOID NicIncrementDropCount(_Inout_ PNIC_CONTEXT Context, _In_ ULONG64 Count);

// Increment error counter
VOID NicIncrementErrorCount(_Inout_ PNIC_CONTEXT Context,
                            _In_ BOOLEAN IsReceiveError);

// Export statistics
NTSTATUS NicGetStatistics(_In_ PNIC_CONTEXT Context,
                          _Out_ PNIC_STATISTICS OutStats);

// Zero all counters
VOID NicResetStatistics(_Inout_ PNIC_CONTEXT Context);

// Update link speed
VOID NicUpdateLinkSpeed(_Inout_ PNIC_CONTEXT Context, _In_ ULONG SpeedMbps);

//=============================================================================
// SECTION 14: Function Prototypes - State Management
//=============================================================================

// Change operational state
NTSTATUS NicSetState(_Inout_ PNIC_CONTEXT Context, _In_ NIC_STATE NewState);

// Query current state
NIC_STATE NicGetState(_In_ PNIC_CONTEXT Context);

// Check if NIC is actively capturing
BOOLEAN NicIsRunning(_In_ PNIC_CONTEXT Context);

// Check if NIC is paused
BOOLEAN NicIsPaused(_In_ PNIC_CONTEXT Context);

// Pause packet capture
NTSTATUS NicPause(_Inout_ PNIC_CONTEXT Context);

// Resume packet capture
NTSTATUS NicResume(_Inout_ PNIC_CONTEXT Context);

//=============================================================================
// SECTION 15: Function Prototypes - Enumeration
//=============================================================================

// Get all NICs
NTSTATUS NicEnumerate(_Out_ PNIC_CONTEXT *OutArray, _In_ ULONG ArraySize,
                      _Out_ PULONG OutCount);

// Get enabled NICs only
NTSTATUS NicEnumerateEnabled(_Out_ PNIC_CONTEXT *OutArray, _In_ ULONG ArraySize,
                             _Out_ PULONG OutCount);

// Iterate with callback
NTSTATUS NicForEach(_In_ VOID (*Callback)(PNIC_CONTEXT, PVOID),
                    _In_opt_ PVOID CallbackContext);

//=============================================================================
// SECTION 16: Function Prototypes - Validation
//=============================================================================

// Ensure exactly one WAN, one LAN, one WiFi
NTSTATUS ValidateNICTagging(VOID);

// Check if type is in range
BOOLEAN IsValidNICType(_In_ NIC_TYPE Type);

// Validate configuration structure
NTSTATUS ValidateNICConfiguration(_In_ PNIC_CONFIGURATION Config);

// Check if type already assigned to another NIC
BOOLEAN IsNICTagUnique(_In_ NIC_TYPE Type);

//=============================================================================
// SECTION 17: Debug Functions
//=============================================================================

#ifdef DBG

// Print NIC context details
VOID DbgPrintNicContext(_In_ PNIC_CONTEXT Context);

// Print all NIC table
VOID DbgPrintNicTable(VOID);

// Verify NIC management state
NTSTATUS DbgVerifyNicManagement(VOID);

#endif // DBG

#endif // SAFEOPS_NIC_MANAGEMENT_H
