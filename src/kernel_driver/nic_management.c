/*******************************************************************************
 * FILE: src/kernel_driver/nic_management.c
 *
 * SafeOps v2.0 - Network Interface Card Management Implementation
 *
 * PURPOSE:
 *   Implements comprehensive Network Interface Card (NIC) registration,
 *   enumeration, configuration, and state management for the SafeOps kernel
 *   driver. Maintains a registry of all network adapters attached to the NDIS
 *   filter, assigns logical tags (WAN, LAN, WiFi) to each NIC for policy-based
 *   filtering, tracks per-NIC statistics and configuration, handles NIC
 *   attach/detach events, and provides lookup functions for other driver
 *   subsystems to access NIC information.
 *
 * ARCHITECTURE:
 *   - Global NIC_TABLE with fixed-size array (MAX_NIC_COUNT = 8)
 *   - Spinlock-protected concurrent access
 *   - O(1) lookup by index, O(N) lookup by handle/GUID/MAC
 *   - Atomic statistics counters for lock-free per-packet updates
 *   - Registry preservation of NIC context after detach for historical stats
 *
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 * DATE: December 24, 2024
 ******************************************************************************/

#include "nic_management.h"

//=============================================================================
// SECTION 1: Global Variables
//=============================================================================

// Global NIC table (single instance for entire driver)
static NIC_TABLE g_NicTable = {0};

//=============================================================================
// SECTION 2: Initialization Functions
//=============================================================================

/**
 * NicTableInitialize
 *
 * Initializes the global NIC table during driver load. Allocates the NIC
 * context array, initializes the spinlock, and zeros all entries.
 *
 * Parameters: None
 * Returns: NTSTATUS - STATUS_SUCCESS or error code
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicTableInitialize(VOID) {
  DbgPrint("[NicManagement] Initializing NIC table...\n");

  // Zero the entire table structure
  RtlZeroMemory(&g_NicTable, sizeof(NIC_TABLE));

  // Initialize the spinlock for table protection
  KeInitializeSpinLock(&g_NicTable.TableLock);

  // Initialize all NIC context entries
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];

    // Zero the context
    RtlZeroMemory(ctx, sizeof(NIC_CONTEXT));

    // Set default state to DETACHED
    ctx->CurrentState = NIC_STATE_DETACHED;

    // Initialize per-NIC statistics spinlock
    KeInitializeSpinLock(&ctx->StatisticsLock);
  }

  // Mark table as initialized
  g_NicTable.IsInitialized = TRUE;
  g_NicTable.AttachedCount = 0;
  g_NicTable.EnabledCount = 0;

  DbgPrint("[NicManagement] NIC table initialized successfully\n");
  return STATUS_SUCCESS;
}

/**
 * NicTableCleanup
 *
 * Cleans up the NIC table during driver unload. Marks all NICs as detached
 * and resets the table.
 *
 * Parameters: None
 * Returns: None
 * IRQL: PASSIVE_LEVEL
 */
VOID NicTableCleanup(VOID) {
  KIRQL oldIrql;

  DbgPrint("[NicManagement] Cleaning up NIC table...\n");

  if (!g_NicTable.IsInitialized) {
    return;
  }

  // Acquire table lock
  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Mark all NICs as detached
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      ctx->CurrentState = NIC_STATE_DETACHED;
      ctx->Configuration.IsEnabled = FALSE;
    }
  }

  g_NicTable.AttachedCount = 0;
  g_NicTable.EnabledCount = 0;
  g_NicTable.IsInitialized = FALSE;

  // Release lock
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  DbgPrint("[NicManagement] NIC table cleanup complete\n");
}

//=============================================================================
// SECTION 3: Registration Functions
//=============================================================================

/**
 * NicTableRegister
 *
 * Registers a new network adapter when NDIS filter attaches. Allocates a NIC
 * context slot, stores the NDIS filter handle, queries adapter properties
 * (MAC address, friendly name, link speed, GUID), and initializes the context.
 *
 * Parameters:
 *   FilterHandle - NDIS filter handle for this adapter
 *   AttachParams - NDIS attach parameters (contains adapter info)
 *   OutContext - Receives pointer to allocated NIC_CONTEXT
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL (called from NDIS filter attach handler)
 */
NTSTATUS
NicTableRegister(_In_ NDIS_HANDLE FilterHandle, _In_ PVOID AttachParams,
                 _Out_ PNIC_CONTEXT *OutContext) {
  KIRQL oldIrql;
  PNIC_CONTEXT nicCtx = NULL;
  ULONG slotIndex = 0;
  BOOLEAN foundSlot = FALSE;

  UNREFERENCED_PARAMETER(AttachParams);

  if (!g_NicTable.IsInitialized) {
    DbgPrint("[NicManagement] ERROR: Table not initialized\n");
    return STATUS_DEVICE_NOT_READY;
  }

  if (OutContext == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  *OutContext = NULL;

  // Acquire table lock
  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Find available slot (DETACHED state)
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    if (g_NicTable.NICs[i].CurrentState == NIC_STATE_DETACHED) {
      nicCtx = &g_NicTable.NICs[i];
      slotIndex = i;
      foundSlot = TRUE;
      break;
    }
  }

  if (!foundSlot) {
    KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);
    DbgPrint("[NicManagement] ERROR: NIC table full (max %u NICs)\n",
             MAX_NIC_COUNT);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Initialize NIC context
  RtlZeroMemory(nicCtx, sizeof(NIC_CONTEXT));

  // Store NDIS filter handle
  nicCtx->Identifier.FilterHandle = FilterHandle;
  nicCtx->Identifier.InterfaceIndex = slotIndex;

  // Initialize state
  nicCtx->CurrentState = NIC_STATE_ATTACHED;
  nicCtx->Configuration.NICType = NIC_TYPE_UNTAGGED;
  nicCtx->Configuration.IsEnabled = FALSE; // Disabled until explicitly enabled
  nicCtx->Configuration.IsPromiscuous = FALSE;
  nicCtx->Configuration.CaptureInbound = TRUE;
  nicCtx->Configuration.CaptureOutbound = TRUE;
  nicCtx->Configuration.MaxPacketsPerSecond = 0; // Unlimited
  nicCtx->Configuration.MTU = 1500;              // Default Ethernet MTU

  // Initialize statistics spinlock
  KeInitializeSpinLock(&nicCtx->StatisticsLock);

  // Initialize media type (default to Ethernet)
  nicCtx->MediaType = 0;      // NdisMedium802_3 in real NDIS
  nicCtx->PhysicalMedium = 0; // NdisPhysicalMedium802_3
  nicCtx->LinkState = NIC_LINK_UNKNOWN;

  // Increment attached count
  g_NicTable.AttachedCount++;

  // Release lock
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

#ifdef SAFEOPS_WDK_BUILD
  // Query NDIS for adapter properties (only in WDK build)
  // In real implementation, use NdisFGetAttributes, OID queries, etc.
  // For now, we'll set placeholder values
#endif

  // Set default friendly name
  RtlStringCbPrintfW(nicCtx->Identifier.FriendlyName,
                     sizeof(nicCtx->Identifier.FriendlyName), L"NIC%u",
                     slotIndex);

  *OutContext = nicCtx;

  DbgPrint("[NicManagement] Registered NIC at slot %u (Handle: %p)\n",
           slotIndex, FilterHandle);

  return STATUS_SUCCESS;
}

/**
 * NicTableUnregister
 *
 * Unregisters a network adapter when NDIS filter detaches. Marks the NIC
 * context as DETACHED but preserves the entry for historical statistics.
 *
 * Parameters:
 *   FilterHandle - NDIS filter handle to unregister
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicTableUnregister(_In_ NDIS_HANDLE FilterHandle) {
  KIRQL oldIrql;
  PNIC_CONTEXT nicCtx = NULL;
  BOOLEAN found = FALSE;

  if (!g_NicTable.IsInitialized) {
    return STATUS_DEVICE_NOT_READY;
  }

  // Acquire table lock
  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Find NIC by filter handle
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    if (g_NicTable.NICs[i].Identifier.FilterHandle == FilterHandle &&
        g_NicTable.NICs[i].CurrentState != NIC_STATE_DETACHED) {
      nicCtx = &g_NicTable.NICs[i];
      found = TRUE;
      break;
    }
  }

  if (!found) {
    KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);
    DbgPrint("[NicManagement] WARNING: NIC not found for handle %p\n",
             FilterHandle);
    return STATUS_NOT_FOUND;
  }

  // Mark as detached (preserve statistics)
  nicCtx->CurrentState = NIC_STATE_DETACHED;
  nicCtx->Configuration.IsEnabled = FALSE;

  // Decrement counts
  if (g_NicTable.AttachedCount > 0) {
    g_NicTable.AttachedCount--;
  }
  if (nicCtx->Configuration.IsEnabled && g_NicTable.EnabledCount > 0) {
    g_NicTable.EnabledCount--;
  }

  // Release lock
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  DbgPrint("[NicManagement] Unregistered NIC (Handle: %p)\n", FilterHandle);

  return STATUS_SUCCESS;
}

/**
 * NicTableGetCount
 *
 * Returns the number of currently registered (attached) NICs.
 *
 * Parameters: None
 * Returns: ULONG - Number of attached NICs
 * IRQL: <= DISPATCH_LEVEL
 */
ULONG
NicTableGetCount(VOID) {
  KIRQL oldIrql;
  ULONG count;

  if (!g_NicTable.IsInitialized) {
    return 0;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  count = g_NicTable.AttachedCount;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return count;
}

//=============================================================================
// SECTION 4: Lookup Operations
//=============================================================================

/**
 * NicFindByFilterHandle
 *
 * Finds NIC context by NDIS filter handle. This is the fast-path lookup
 * used in packet processing callbacks.
 *
 * Parameters:
 *   FilterHandle - NDIS filter handle to search for
 *
 * Returns: PNIC_CONTEXT - Pointer to NIC context or NULL if not found
 * IRQL: <= DISPATCH_LEVEL
 */
PNIC_CONTEXT
NicFindByFilterHandle(_In_ NDIS_HANDLE FilterHandle) {
  KIRQL oldIrql;
  PNIC_CONTEXT result = NULL;

  if (!g_NicTable.IsInitialized) {
    return NULL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Linear search through table
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->Identifier.FilterHandle == FilterHandle &&
        ctx->CurrentState != NIC_STATE_DETACHED) {
      result = ctx;
      break;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return result;
}

/**
 * NicFindByInterfaceIndex
 *
 * Finds NIC context by Windows interface index (0-7 for our fixed array).
 *
 * Parameters:
 *   InterfaceIndex - Interface index (0 to MAX_NIC_COUNT-1)
 *
 * Returns: PNIC_CONTEXT - Pointer to NIC context or NULL if invalid
 * IRQL: <= DISPATCH_LEVEL
 */
PNIC_CONTEXT
NicFindByInterfaceIndex(_In_ NET_IFINDEX InterfaceIndex) {
  KIRQL oldIrql;
  PNIC_CONTEXT result = NULL;

  if (!g_NicTable.IsInitialized || InterfaceIndex >= MAX_NIC_COUNT) {
    return NULL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  PNIC_CONTEXT ctx = &g_NicTable.NICs[InterfaceIndex];
  if (ctx->CurrentState != NIC_STATE_DETACHED) {
    result = ctx;
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return result;
}

/**
 * NicFindByType
 *
 * Finds NIC context by type tag (WAN, LAN, WiFi). Used by filter engine
 * to determine which NIC handles specific traffic.
 *
 * Parameters:
 *   NICType - Type to search for (NIC_TYPE_WAN, NIC_TYPE_LAN, etc.)
 *
 * Returns: PNIC_CONTEXT - Pointer to NIC context or NULL if not found
 * IRQL: <= DISPATCH_LEVEL
 */
PNIC_CONTEXT
NicFindByType(_In_ NIC_TYPE NICType) {
  KIRQL oldIrql;
  PNIC_CONTEXT result = NULL;

  if (!g_NicTable.IsInitialized || NICType == NIC_TYPE_UNTAGGED) {
    return NULL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->Configuration.NICType == NICType &&
        ctx->CurrentState != NIC_STATE_DETACHED) {
      result = ctx;
      break;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return result;
}

/**
 * NicFindByMAC
 *
 * Finds NIC context by MAC address (6-byte hardware address).
 *
 * Parameters:
 *   MACAddress - Pointer to 6-byte MAC address
 *
 * Returns: PNIC_CONTEXT - Pointer to NIC context or NULL if not found
 * IRQL: <= DISPATCH_LEVEL
 */
PNIC_CONTEXT
NicFindByMAC(_In_ PUCHAR MACAddress) {
  KIRQL oldIrql;
  PNIC_CONTEXT result = NULL;

  if (!g_NicTable.IsInitialized || MACAddress == NULL) {
    return NULL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED &&
        RtlCompareMemory(ctx->Identifier.MACAddress, MACAddress, 6) == 6) {
      result = ctx;
      break;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return result;
}

/**
 * NicFindByGUID
 *
 * Finds NIC context by adapter GUID (persistent identifier across reboots).
 *
 * Parameters:
 *   InterfaceGuid - Pointer to adapter GUID
 *
 * Returns: PNIC_CONTEXT - Pointer to NIC context or NULL if not found
 * IRQL: <= DISPATCH_LEVEL
 */
PNIC_CONTEXT
NicFindByGUID(_In_ PGUID InterfaceGuid) {
  KIRQL oldIrql;
  PNIC_CONTEXT result = NULL;

  if (!g_NicTable.IsInitialized || InterfaceGuid == NULL) {
    return NULL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED &&
        RtlCompareMemory(&ctx->Identifier.InterfaceGuid, InterfaceGuid,
                         sizeof(GUID)) == sizeof(GUID)) {
      result = ctx;
      break;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return result;
}

//=============================================================================
// SECTION 5: Configuration Functions
//=============================================================================

/**
 * NicSetType
 *
 * Tags a NIC as WAN, LAN, or WiFi. Validates that the tag is unique
 * (only one NIC can have each tag).
 *
 * Parameters:
 *   Context - NIC context to configure
 *   NICType - Type tag to assign
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicSetType(_Inout_ PNIC_CONTEXT Context, _In_ NIC_TYPE NICType) {
  KIRQL oldIrql;

  if (Context == NULL || !g_NicTable.IsInitialized) {
    return STATUS_INVALID_PARAMETER;
  }

  // Validate type
  if (NICType != NIC_TYPE_WAN && NICType != NIC_TYPE_LAN &&
      NICType != NIC_TYPE_WIFI && NICType != NIC_TYPE_UNTAGGED) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Check if another NIC already has this type
  if (NICType != NIC_TYPE_UNTAGGED) {
    for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
      PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
      if (ctx != Context && ctx->CurrentState != NIC_STATE_DETACHED &&
          ctx->Configuration.NICType == NICType) {
        KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);
        DbgPrint(
            "[NicManagement] ERROR: Type %u already assigned to another NIC\n",
            NICType);
        return STATUS_DUPLICATE_NAME;
      }
    }
  }

  // Set the type
  Context->Configuration.NICType = NICType;

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  DbgPrint("[NicManagement] NIC type set to %u\n", NICType);
  return STATUS_SUCCESS;
}

/**
 * NicSetEnabled
 *
 * Enables or disables packet capture on a NIC.
 *
 * Parameters:
 *   Context - NIC context
 *   IsEnabled - TRUE to enable, FALSE to disable
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicSetEnabled(_Inout_ PNIC_CONTEXT Context, _In_ BOOLEAN IsEnabled) {
  KIRQL oldIrql;

  if (Context == NULL || !g_NicTable.IsInitialized) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  BOOLEAN wasEnabled = Context->Configuration.IsEnabled;
  Context->Configuration.IsEnabled = IsEnabled;

  // Update enabled count
  if (IsEnabled && !wasEnabled) {
    g_NicTable.EnabledCount++;
  } else if (!IsEnabled && wasEnabled) {
    if (g_NicTable.EnabledCount > 0) {
      g_NicTable.EnabledCount--;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  DbgPrint("[NicManagement] NIC %s\n", IsEnabled ? "enabled" : "disabled");
  return STATUS_SUCCESS;
}

/**
 * NicSetPromiscuousMode
 *
 * Enables or disables promiscuous mode on a NIC.
 *
 * Parameters:
 *   Context - NIC context
 *   IsPromiscuous - TRUE for promiscuous, FALSE for normal
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicSetPromiscuousMode(_Inout_ PNIC_CONTEXT Context,
                      _In_ BOOLEAN IsPromiscuous) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  Context->Configuration.IsPromiscuous = IsPromiscuous;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

/**
 * NicSetCaptureFlags
 *
 * Configures packet type filter flags.
 *
 * Parameters:
 *   Context - NIC context
 *   Flags - Capture filter flags
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicSetCaptureFlags(_Inout_ PNIC_CONTEXT Context, _In_ ULONG Flags) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  Context->Configuration.CaptureFilterFlags = Flags;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

/**
 * NicSetRateLimit
 *
 * Sets maximum packets per second rate limit (0 = unlimited).
 *
 * Parameters:
 *   Context - NIC context
 *   MaxPPS - Maximum packets per second
 *
 * Returns: NTSTATUS
 * IRQL: PASSIVE_LEVEL
 */
NTSTATUS
NicSetRateLimit(_Inout_ PNIC_CONTEXT Context, _In_ ULONG MaxPPS) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  Context->Configuration.MaxPacketsPerSecond = MaxPPS;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

/**
 * NicGetConfiguration
 *
 * Exports current NIC configuration to output buffer.
 *
 * Parameters:
 *   Context - NIC context
 *   OutConfig - Receives configuration copy
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicGetConfiguration(_In_ PNIC_CONTEXT Context,
                    _Out_ PNIC_CONFIGURATION OutConfig) {
  KIRQL oldIrql;

  if (Context == NULL || OutConfig == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  RtlCopyMemory(OutConfig, &Context->Configuration, sizeof(NIC_CONFIGURATION));
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 6: Statistics Functions
//=============================================================================

/**
 * NicIncrementPacketCount
 *
 * Atomically increments packet and byte counters. Called from packet
 * processing fast path (per-packet). Uses atomic operations for lock-free
 * concurrent updates.
 *
 * Parameters:
 *   Context - NIC context
 *   IsInbound - TRUE for RX, FALSE for TX
 *   ByteCount - Number of bytes in packet
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID NicIncrementPacketCount(_Inout_ PNIC_CONTEXT Context,
                             _In_ BOOLEAN IsInbound, _In_ ULONG64 ByteCount) {
  if (Context == NULL) {
    return;
  }

  LARGE_INTEGER timestamp;
  KeQuerySystemTime(&timestamp);

  if (IsInbound) {
    InterlockedIncrement64((LONG64 *)&Context->Statistics.PacketsReceived);
    InterlockedAdd64((LONG64 *)&Context->Statistics.BytesReceived, ByteCount);

    // Update first/last packet times
    if (Context->Statistics.FirstPacketTime.QuadPart == 0) {
      Context->Statistics.FirstPacketTime = timestamp;
    }
    Context->Statistics.LastPacketTime = timestamp;
  } else {
    InterlockedIncrement64((LONG64 *)&Context->Statistics.PacketsTransmitted);
    InterlockedAdd64((LONG64 *)&Context->Statistics.BytesTransmitted,
                     ByteCount);

    if (Context->Statistics.FirstPacketTime.QuadPart == 0) {
      Context->Statistics.FirstPacketTime = timestamp;
    }
    Context->Statistics.LastPacketTime = timestamp;
  }
}

/**
 * NicIncrementDropCount
 *
 * Atomically increments packet drop counter.
 *
 * Parameters:
 *   Context - NIC context
 *   Count - Number of packets dropped
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID NicIncrementDropCount(_Inout_ PNIC_CONTEXT Context, _In_ ULONG64 Count) {
  if (Context == NULL) {
    return;
  }

  InterlockedAdd64((LONG64 *)&Context->Statistics.PacketsDropped, Count);
}

/**
 * NicIncrementErrorCount
 *
 * Atomically increments error counter.
 *
 * Parameters:
 *   Context - NIC context
 *   IsReceiveError - TRUE for RX error, FALSE for TX error
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID NicIncrementErrorCount(_Inout_ PNIC_CONTEXT Context,
                            _In_ BOOLEAN IsReceiveError) {
  if (Context == NULL) {
    return;
  }

  if (IsReceiveError) {
    InterlockedIncrement64((LONG64 *)&Context->Statistics.ErrorsReceived);
  } else {
    InterlockedIncrement64((LONG64 *)&Context->Statistics.ErrorsTransmitted);
  }

  InterlockedIncrement64((LONG64 *)&Context->Statistics.PacketsWithErrors);
}

/**
 * NicGetStatistics
 *
 * Exports NIC statistics snapshot to output buffer.
 *
 * Parameters:
 *   Context - NIC context
 *   OutStats - Receives statistics copy
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicGetStatistics(_In_ PNIC_CONTEXT Context, _Out_ PNIC_STATISTICS OutStats) {
  KIRQL oldIrql;

  if (Context == NULL || OutStats == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&Context->StatisticsLock, &oldIrql);
  RtlCopyMemory(OutStats, &Context->Statistics, sizeof(NIC_STATISTICS));
  KeReleaseSpinLock(&Context->StatisticsLock, oldIrql);

  return STATUS_SUCCESS;
}

/**
 * NicResetStatistics
 *
 * Zeros all statistics counters.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID NicResetStatistics(_Inout_ PNIC_CONTEXT Context) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return;
  }

  KeAcquireSpinLock(&Context->StatisticsLock, &oldIrql);
  RtlZeroMemory(&Context->Statistics, sizeof(NIC_STATISTICS));
  KeReleaseSpinLock(&Context->StatisticsLock, oldIrql);

  DbgPrint("[NicManagement] Statistics reset\n");
}

/**
 * NicUpdateLinkSpeed
 *
 * Updates link speed metadata (in Mbps).
 *
 * Parameters:
 *   Context - NIC context
 *   SpeedMbps - Link speed in Mbps
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID NicUpdateLinkSpeed(_Inout_ PNIC_CONTEXT Context, _In_ ULONG SpeedMbps) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return;
  }

  KeAcquireSpinLock(&Context->StatisticsLock, &oldIrql);
  Context->Statistics.LinkSpeedMbps = SpeedMbps;
  KeReleaseSpinLock(&Context->StatisticsLock, oldIrql);
}

//=============================================================================
// SECTION 7: State Management Functions
//=============================================================================

/**
 * NicSetState
 *
 * Changes NIC operational state.
 *
 * Parameters:
 *   Context - NIC context
 *   NewState - New state to set
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicSetState(_Inout_ PNIC_CONTEXT Context, _In_ NIC_STATE NewState) {
  KIRQL oldIrql;

  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  Context->CurrentState = NewState;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

/**
 * NicGetState
 *
 * Returns current NIC state.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: NIC_STATE - Current state
 * IRQL: <= DISPATCH_LEVEL
 */
NIC_STATE
NicGetState(_In_ PNIC_CONTEXT Context) {
  KIRQL oldIrql;
  NIC_STATE state;

  if (Context == NULL) {
    return NIC_STATE_ERROR;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);
  state = Context->CurrentState;
  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return state;
}

/**
 * NicIsRunning
 *
 * Checks if NIC is actively capturing packets.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: BOOLEAN - TRUE if running
 * IRQL: <= DISPATCH_LEVEL
 */
BOOLEAN
NicIsRunning(_In_ PNIC_CONTEXT Context) {
  if (Context == NULL) {
    return FALSE;
  }

  return (Context->CurrentState == NIC_STATE_RUNNING);
}

/**
 * NicIsPaused
 *
 * Checks if NIC is paused.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: BOOLEAN - TRUE if paused
 * IRQL: <= DISPATCH_LEVEL
 */
BOOLEAN
NicIsPaused(_In_ PNIC_CONTEXT Context) {
  if (Context == NULL) {
    return FALSE;
  }

  return (Context->CurrentState == NIC_STATE_PAUSED);
}

/**
 * NicPause
 *
 * Pauses packet capture on NIC.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicPause(_Inout_ PNIC_CONTEXT Context) {
  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  return NicSetState(Context, NIC_STATE_PAUSED);
}

/**
 * NicResume
 *
 * Resumes packet capture on NIC.
 *
 * Parameters:
 *   Context - NIC context
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicResume(_Inout_ PNIC_CONTEXT Context) {
  if (Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  return NicSetState(Context, NIC_STATE_RUNNING);
}

//=============================================================================
// SECTION 8: Enumeration Functions
//=============================================================================

/**
 * NicEnumerate
 *
 * Fills array with all registered NICs (attached or running).
 *
 * Parameters:
 *   OutArray - Array to fill with NIC context pointers
 *   ArraySize - Maximum entries in array
 *   OutCount - Receives actual count of NICs
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicEnumerate(_Out_ PNIC_CONTEXT *OutArray, _In_ ULONG ArraySize,
             _Out_ PULONG OutCount) {
  KIRQL oldIrql;
  ULONG count = 0;

  if (OutArray == NULL || OutCount == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!g_NicTable.IsInitialized) {
    *OutCount = 0;
    return STATUS_SUCCESS;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT && count < ArraySize; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      OutArray[count++] = ctx;
    }
  }

  *OutCount = count;

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return (count < g_NicTable.AttachedCount) ? STATUS_BUFFER_OVERFLOW
                                            : STATUS_SUCCESS;
}

/**
 * NicEnumerateEnabled
 *
 * Fills array with only enabled NICs.
 *
 * Parameters:
 *   OutArray - Array to fill with NIC context pointers
 *   ArraySize - Maximum entries in array
 *   OutCount - Receives actual count of enabled NICs
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicEnumerateEnabled(_Out_ PNIC_CONTEXT *OutArray, _In_ ULONG ArraySize,
                    _Out_ PULONG OutCount) {
  KIRQL oldIrql;
  ULONG count = 0;

  if (OutArray == NULL || OutCount == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!g_NicTable.IsInitialized) {
    *OutCount = 0;
    return STATUS_SUCCESS;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT && count < ArraySize; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED &&
        ctx->Configuration.IsEnabled) {
      OutArray[count++] = ctx;
    }
  }

  *OutCount = count;

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return (count < g_NicTable.EnabledCount) ? STATUS_BUFFER_OVERFLOW
                                           : STATUS_SUCCESS;
}

/**
 * NicForEach
 *
 * Iterates all NICs with callback function.
 *
 * Parameters:
 *   Callback - Function to call for each NIC
 *   CallbackContext - Optional context passed to callback
 *
 * Returns: NTSTATUS
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
NicForEach(_In_ VOID (*Callback)(PNIC_CONTEXT, PVOID),
           _In_opt_ PVOID CallbackContext) {
  KIRQL oldIrql;

  if (Callback == NULL || !g_NicTable.IsInitialized) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      Callback(ctx, CallbackContext);
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 9: Validation Functions
//=============================================================================

/**
 * ValidateNICTagging
 *
 * Ensures exactly one WAN, one LAN, and one WiFi NIC are configured.
 *
 * Parameters: None
 * Returns: NTSTATUS - STATUS_SUCCESS if valid, error otherwise
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
ValidateNICTagging(VOID) {
  KIRQL oldIrql;
  ULONG wanCount = 0, lanCount = 0, wifiCount = 0;

  if (!g_NicTable.IsInitialized) {
    return STATUS_DEVICE_NOT_READY;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      switch (ctx->Configuration.NICType) {
      case NIC_TYPE_WAN:
        wanCount++;
        break;
      case NIC_TYPE_LAN:
        lanCount++;
        break;
      case NIC_TYPE_WIFI:
        wifiCount++;
        break;
      default:
        break;
      }
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  if (wanCount != 1 || lanCount != 1 || wifiCount != 1) {
    DbgPrint("[NicManagement] Invalid tagging: WAN=%u LAN=%u WiFi=%u (expected "
             "1,1,1)\n",
             wanCount, lanCount, wifiCount);
    return STATUS_INVALID_DEVICE_STATE;
  }

  return STATUS_SUCCESS;
}

/**
 * IsValidNICType
 *
 * Checks if NIC type enum value is valid.
 *
 * Parameters:
 *   Type - NIC type to validate
 *
 * Returns: BOOLEAN - TRUE if valid
 * IRQL: Any
 */
BOOLEAN
IsValidNICType(_In_ NIC_TYPE Type) {
  return (Type >= NIC_TYPE_UNTAGGED && Type <= NIC_TYPE_WIFI);
}

/**
 * ValidateNICConfiguration
 *
 * Validates NIC configuration structure fields.
 *
 * Parameters:
 *   Config - Configuration to validate
 *
 * Returns: NTSTATUS
 * IRQL: Any
 */
NTSTATUS
ValidateNICConfiguration(_In_ PNIC_CONFIGURATION Config) {
  if (Config == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!IsValidNICType(Config->NICType)) {
    return STATUS_INVALID_PARAMETER;
  }

  if (Config->MTU == 0 || Config->MTU > 9000) {
    return STATUS_INVALID_PARAMETER;
  }

  return STATUS_SUCCESS;
}

/**
 * IsNICTagUnique
 *
 * Checks if a NIC type tag is already assigned to another NIC.
 *
 * Parameters:
 *   Type - Type tag to check
 *
 * Returns: BOOLEAN - TRUE if unique (not assigned)
 * IRQL: <= DISPATCH_LEVEL
 */
BOOLEAN
IsNICTagUnique(_In_ NIC_TYPE Type) {
  KIRQL oldIrql;
  BOOLEAN isUnique = TRUE;

  if (!g_NicTable.IsInitialized || Type == NIC_TYPE_UNTAGGED) {
    return TRUE;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED &&
        ctx->Configuration.NICType == Type) {
      isUnique = FALSE;
      break;
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  return isUnique;
}

//=============================================================================
// SECTION 10: Debug Functions
//=============================================================================

#ifdef DBG

/**
 * DbgPrintNicContext
 *
 * Prints detailed information about a NIC context.
 *
 * Parameters:
 *   Context - NIC context to print
 *
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID DbgPrintNicContext(_In_ PNIC_CONTEXT Context) {
  if (Context == NULL) {
    DbgPrint("[NicManagement] NULL context\n");
    return;
  }

  DbgPrint("[NicManagement] === NIC Context ===\n");
  DbgPrint("  Interface Index: %u\n", Context->Identifier.InterfaceIndex);
  DbgPrint("  Filter Handle: %p\n", Context->Identifier.FilterHandle);
  DbgPrint("  Friendly Name: %ws\n", Context->Identifier.FriendlyName);
  DbgPrint("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           Context->Identifier.MACAddress[0], Context->Identifier.MACAddress[1],
           Context->Identifier.MACAddress[2], Context->Identifier.MACAddress[3],
           Context->Identifier.MACAddress[4],
           Context->Identifier.MACAddress[5]);
  DbgPrint("  Type: %u\n", Context->Configuration.NICType);
  DbgPrint("  State: %u\n", Context->CurrentState);
  DbgPrint("  Enabled: %u\n", Context->Configuration.IsEnabled);
  DbgPrint("  Link State: %u\n", Context->LinkState);
  DbgPrint("  Link Speed: %u Mbps\n", Context->Statistics.LinkSpeedMbps);
  DbgPrint("  Packets RX: %llu\n", Context->Statistics.PacketsReceived);
  DbgPrint("  Packets TX: %llu\n", Context->Statistics.PacketsTransmitted);
  DbgPrint("  Bytes RX: %llu\n", Context->Statistics.BytesReceived);
  DbgPrint("  Bytes TX: %llu\n", Context->Statistics.BytesTransmitted);
  DbgPrint("  Drops: %llu\n", Context->Statistics.PacketsDropped);
  DbgPrint("  Errors: %llu\n", Context->Statistics.PacketsWithErrors);
}

/**
 * DbgPrintNicTable
 *
 * Prints the entire NIC table.
 *
 * Parameters: None
 * Returns: None
 * IRQL: <= DISPATCH_LEVEL
 */
VOID DbgPrintNicTable(VOID) {
  KIRQL oldIrql;

  if (!g_NicTable.IsInitialized) {
    DbgPrint("[NicManagement] Table not initialized\n");
    return;
  }

  DbgPrint("[NicManagement] === NIC TABLE ===\n");
  DbgPrint("  Attached: %u\n", g_NicTable.AttachedCount);
  DbgPrint("  Enabled: %u\n", g_NicTable.EnabledCount);

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];
    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      DbgPrint("\n  [Slot %u]\n", i);
      DbgPrintNicContext(ctx);
    }
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  DbgPrint("[NicManagement] === END TABLE ===\n");
}

/**
 * DbgVerifyNicManagement
 *
 * Performs comprehensive self-check of NIC management state.
 *
 * Parameters: None
 * Returns: NTSTATUS - STATUS_SUCCESS if all checks pass
 * IRQL: <= DISPATCH_LEVEL
 */
NTSTATUS
DbgVerifyNicManagement(VOID) {
  KIRQL oldIrql;
  ULONG attachedCount = 0;
  ULONG enabledCount = 0;
  BOOLEAN hasErrors = FALSE;

  DbgPrint("[NicManagement] === SELF-CHECK START ===\n");

  if (!g_NicTable.IsInitialized) {
    DbgPrint("[NicManagement] FAIL: Table not initialized\n");
    return STATUS_UNSUCCESSFUL;
  }

  KeAcquireSpinLock(&g_NicTable.TableLock, &oldIrql);

  // Count NICs and verify consistency
  for (ULONG i = 0; i < MAX_NIC_COUNT; i++) {
    PNIC_CONTEXT ctx = &g_NicTable.NICs[i];

    if (ctx->CurrentState != NIC_STATE_DETACHED) {
      attachedCount++;

      if (ctx->Configuration.IsEnabled) {
        enabledCount++;
      }

      // Verify interface index matches slot
      if (ctx->Identifier.InterfaceIndex != i) {
        DbgPrint("[NicManagement] WARNING: Slot %u has interface index %u\n", i,
                 ctx->Identifier.InterfaceIndex);
      }
    }
  }

  // Verify counts
  if (attachedCount != g_NicTable.AttachedCount) {
    DbgPrint("[NicManagement] FAIL: Attached count mismatch (actual=%u, "
             "stored=%u)\n",
             attachedCount, g_NicTable.AttachedCount);
    hasErrors = TRUE;
  }

  if (enabledCount != g_NicTable.EnabledCount) {
    DbgPrint(
        "[NicManagement] FAIL: Enabled count mismatch (actual=%u, stored=%u)\n",
        enabledCount, g_NicTable.EnabledCount);
    hasErrors = TRUE;
  }

  KeReleaseSpinLock(&g_NicTable.TableLock, oldIrql);

  if (!hasErrors) {
    DbgPrint("[NicManagement] PASS: Attached=%u, Enabled=%u\n", attachedCount,
             enabledCount);
  }

  DbgPrint("[NicManagement] === SELF-CHECK %s ===\n",
           hasErrors ? "FAILED" : "PASSED");

  return hasErrors ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

#endif // DBG

//=============================================================================
// END OF NIC MANAGEMENT IMPLEMENTATION
//=============================================================================
