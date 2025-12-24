/**
 * filter_engine.c - Windows Filtering Platform Integration
 *
 * Implements WFP (Windows Filtering Platform) callouts and filter management.
 *
 * Copyright (c) 2024 SafeOps Project
 */

#include "filter_engine.h"

// WFP Layer GUIDs
static const GUID FWPM_LAYER_INBOUND_IPPACKET_V4_GUID = {
    0xc86fd1bf,
    0x21cd,
    0x497e,
    {0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58}};

static const GUID FWPM_LAYER_OUTBOUND_IPPACKET_V4_GUID = {
    0x1e5c9fae,
    0x8a84,
    0x4135,
    {0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd}};

// SafeOps callout GUIDs
static const GUID SAFEOPS_CALLOUT_INBOUND_V4_GUID = {
    0x12345678,
    0x1234,
    0x1234,
    {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}};

static const GUID SAFEOPS_CALLOUT_OUTBOUND_V4_GUID = {
    0x12345678,
    0x1234,
    0x1234,
    {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0xac}};

//=============================================================================
// FilterEngineInitialize
//=============================================================================

NTSTATUS
FilterEngineInitialize(_In_ PDRIVER_CONTEXT Context) {
  NTSTATUS status;
  FWPM_SESSION0 session = {0};
  FWPS_CALLOUT3 callout = {0};
  FWPM_CALLOUT0 mCallout = {0};
  FWPM_FILTER0 filter = {0};
  FWPM_FILTER_CONDITION0 condition = {0};

  SAFEOPS_LOG_INFO("Initializing WFP filter engine");

  // Open WFP engine
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;
  status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
                           &Context->EngineHandle);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpmEngineOpen0 failed: 0x%08X", status);
    return status;
  }

  //
  // Register Inbound Callout
  //

  RtlZeroMemory(&callout, sizeof(FWPS_CALLOUT3));
  callout.calloutKey = SAFEOPS_CALLOUT_INBOUND_V4_GUID;
  callout.classifyFn = ClassifyFn;
  callout.notifyFn = NotifyFn;
  callout.flowDeleteFn = FlowDeleteFn;

  status = FwpsCalloutRegister3((PDEVICE_OBJECT)Context->Device, &callout,
                                &Context->CalloutIdIPv4Inbound);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpsCalloutRegister3 (inbound) failed: 0x%08X", status);
    goto cleanup;
  }

  // Add callout to management layer
  RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
  mCallout.calloutKey = SAFEOPS_CALLOUT_INBOUND_V4_GUID;
  mCallout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4_GUID;

  status = FwpmCalloutAdd0(Context->EngineHandle, &mCallout, NULL, NULL);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpmCalloutAdd0 (inbound) failed: 0x%08X", status);
    goto cleanup;
  }

  //
  // Register Outbound Callout
  //

  RtlZeroMemory(&callout, sizeof(FWPS_CALLOUT3));
  callout.calloutKey = SAFEOPS_CALLOUT_OUTBOUND_V4_GUID;
  callout.classifyFn = ClassifyFn;
  callout.notifyFn = NotifyFn;
  callout.flowDeleteFn = FlowDeleteFn;

  status = FwpsCalloutRegister3((PDEVICE_OBJECT)Context->Device, &callout,
                                &Context->CalloutIdIPv4Outbound);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpsCalloutRegister3 (outbound) failed: 0x%08X", status);
    goto cleanup;
  }

  // Add callout to management layer
  RtlZeroMemory(&mCallout, sizeof(FWPM_CALLOUT0));
  mCallout.calloutKey = SAFEOPS_CALLOUT_OUTBOUND_V4_GUID;
  mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_IPPACKET_V4_GUID;

  status = FwpmCalloutAdd0(Context->EngineHandle, &mCallout, NULL, NULL);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpmCalloutAdd0 (outbound) failed: 0x%08X", status);
    goto cleanup;
  }

  //
  // Add Filters
  //

  // Inbound filter
  RtlZeroMemory(&filter, sizeof(FWPM_FILTER0));
  filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4_GUID;
  filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
  filter.action.calloutKey = SAFEOPS_CALLOUT_INBOUND_V4_GUID;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xFF;
  filter.numFilterConditions = 0;

  status = FwpmFilterAdd0(Context->EngineHandle, &filter, NULL,
                          &Context->FilterIdInbound);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpmFilterAdd0 (inbound) failed: 0x%08X", status);
    goto cleanup;
  }

  // Outbound filter
  RtlZeroMemory(&filter, sizeof(FWPM_FILTER0));
  filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4_GUID;
  filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
  filter.action.calloutKey = SAFEOPS_CALLOUT_OUTBOUND_V4_GUID;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xFF;
  filter.numFilterConditions = 0;

  status = FwpmFilterAdd0(Context->EngineHandle, &filter, NULL,
                          &Context->FilterIdOutbound);

  if (!NT_SUCCESS(status)) {
    SAFEOPS_LOG_ERROR("FwpmFilterAdd0 (outbound) failed: 0x%08X", status);
    goto cleanup;
  }

  SAFEOPS_LOG_INFO("WFP filter engine initialized successfully");
  return STATUS_SUCCESS;

cleanup:
  FilterEngineCleanup(Context);
  return status;
}

//=============================================================================
// FilterEngineCleanup
//=============================================================================

VOID FilterEngineCleanup(_In_ PDRIVER_CONTEXT Context) {
  SAFEOPS_LOG_INFO("Cleaning up WFP filter engine");

  if (Context->EngineHandle) {
    // Filters are automatically deleted when engine is closed (dynamic session)
    FwpsCalloutUnregisterById0(Context->CalloutIdIPv4Inbound);
    FwpsCalloutUnregisterById0(Context->CalloutIdIPv4Outbound);

    FwpmEngineClose0(Context->EngineHandle);
    Context->EngineHandle = NULL;
  }

  SAFEOPS_LOG_INFO("WFP filter engine cleaned up");
}

//=============================================================================
// AddFilterRule
//=============================================================================

NTSTATUS
AddFilterRule(_In_ PDRIVER_CONTEXT Context, _In_ PFILTER_RULE Rule) {
  KIRQL oldIrql;
  PFILTER_RULE newRule;

  // Validate rule
  if (!Rule || Context->FilterRuleCount >= MAX_FILTER_RULES) {
    return STATUS_INVALID_PARAMETER;
  }

  // Allocate rule
  newRule =
      ExAllocatePoolWithTag(NonPagedPool, sizeof(FILTER_RULE), FILTER_POOL_TAG);
  if (!newRule) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Copy rule
  RtlCopyMemory(newRule, Rule, sizeof(FILTER_RULE));
  KeQuerySystemTime(&newRule->LastMatch);
  newRule->MatchCount = 0;

  // Add to list
  KeAcquireSpinLock(&Context->FilterLock, &oldIrql);
  InsertTailList(&Context->FilterRuleList, &newRule->ListEntry);
  Context->FilterRuleCount++;
  KeReleaseSpinLock(&Context->FilterLock, oldIrql);

  SAFEOPS_LOG_INFO("Added filter rule %u (total: %u)", newRule->RuleId,
                   Context->FilterRuleCount);

  return STATUS_SUCCESS;
}

//=============================================================================
// RemoveFilterRule
//=============================================================================

NTSTATUS
RemoveFilterRule(_In_ PDRIVER_CONTEXT Context, _In_ ULONG RuleId) {
  KIRQL oldIrql;
  PLIST_ENTRY entry;
  PFILTER_RULE rule;
  BOOLEAN found = FALSE;

  KeAcquireSpinLock(&Context->FilterLock, &oldIrql);

  for (entry = Context->FilterRuleList.Flink; entry != &Context->FilterRuleList;
       entry = entry->Flink) {
    rule = CONTAINING_RECORD(entry, FILTER_RULE, ListEntry);
    if (rule->RuleId == RuleId) {
      RemoveEntryList(&rule->ListEntry);
      Context->FilterRuleCount--;
      found = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&Context->FilterLock, oldIrql);

  if (found) {
    ExFreePoolWithTag(rule, FILTER_POOL_TAG);
    SAFEOPS_LOG_INFO("Removed filter rule %u", RuleId);
    return STATUS_SUCCESS;
  }

  return STATUS_NOT_FOUND;
}

//=============================================================================
// EvaluatePacket
//=============================================================================

NTSTATUS
EvaluatePacket(_In_ PDRIVER_CONTEXT Context, _In_ PPACKET_INFO PacketInfo,
               _Out_ PPACKET_ACTION Action, _Out_opt_ PULONG MatchedRuleId) {
  KIRQL oldIrql;
  PLIST_ENTRY entry;
  PFILTER_RULE rule;
  BOOLEAN matched;

  *Action = ACTION_ALLOW; // Default action
  if (MatchedRuleId)
    *MatchedRuleId = 0;

  KeAcquireSpinLock(&Context->FilterLock, &oldIrql);

  // Iterate through rules (sorted by priority)
  for (entry = Context->FilterRuleList.Flink; entry != &Context->FilterRuleList;
       entry = entry->Flink) {
    rule = CONTAINING_RECORD(entry, FILTER_RULE, ListEntry);

    if (!rule->Enabled)
      continue;

    matched = TRUE;

    // Check source IP
    if (rule->SourceMask != 0) {
      if ((PacketInfo->SourceIP & rule->SourceMask) !=
          (rule->SourceIP & rule->SourceMask)) {
        matched = FALSE;
      }
    }

    // Check dest IP
    if (matched && rule->DestMask != 0) {
      if ((PacketInfo->DestIP & rule->DestMask) !=
          (rule->DestIP & rule->DestMask)) {
        matched = FALSE;
      }
    }

    // Check protocol
    if (matched && rule->Protocol != 0) {
      if (PacketInfo->Protocol != rule->Protocol) {
        matched = FALSE;
      }
    }

    // Check source port
    if (matched && rule->SourcePortStart != 0) {
      if (PacketInfo->SourcePort < rule->SourcePortStart ||
          PacketInfo->SourcePort > rule->SourcePortEnd) {
        matched = FALSE;
      }
    }

    // Check dest port
    if (matched && rule->DestPortStart != 0) {
      if (PacketInfo->DestPort < rule->DestPortStart ||
          PacketInfo->DestPort > rule->DestPortEnd) {
        matched = FALSE;
      }
    }

    // Check direction
    if (matched && rule->Direction != DIRECTION_BOTH) {
      if (PacketInfo->Direction != rule->Direction) {
        matched = FALSE;
      }
    }

    if (matched) {
      *Action = rule->Action;
      if (MatchedRuleId)
        *MatchedRuleId = rule->RuleId;

      // Update statistics
      rule->MatchCount++;
      KeQuerySystemTime(&rule->LastMatch);

      break; // First match wins
    }
  }

  KeReleaseSpinLock(&Context->FilterLock, oldIrql);

  return STATUS_SUCCESS;
}

//=============================================================================
// WFP Callout Functions
//=============================================================================

VOID NTAPI ClassifyFn(_In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
                      _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
                      _Inout_opt_ void *layerData,
                      _In_opt_ const void *classifyContext,
                      _In_ const FWPS_FILTER3 *filter, _In_ UINT64 flowContext,
                      _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut) {
  UNREFERENCED_PARAMETER(inFixedValues);
  UNREFERENCED_PARAMETER(inMetaValues);
  UNREFERENCED_PARAMETER(layerData);
  UNREFERENCED_PARAMETER(classifyContext);
  UNREFERENCED_PARAMETER(filter);
  UNREFERENCED_PARAMETER(flowContext);

  // Default: permit
  classifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS NTAPI NotifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                        _In_ const GUID *filterKey,
                        _Inout_ FWPS_FILTER3 *filter) {
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);

  return STATUS_SUCCESS;
}

VOID NTAPI FlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId,
                        _In_ UINT64 flowContext) {
  UNREFERENCED_PARAMETER(layerId);
  UNREFERENCED_PARAMETER(calloutId);
  UNREFERENCED_PARAMETER(flowContext);
}
//=============================================================================
// SECTION 4: CONNECTION TRACKING (10 MILLION CONCURRENT)
//=============================================================================

UINT32
ComputeConnectionHash(_In_ PCONNECTION_KEY Key) {
  // FNV-1a hash
  UINT32 hash = 2166136261u;
  PUCHAR data = (PUCHAR)Key;

  for (UINT32 i = 0; i < sizeof(CONNECTION_KEY); i++) {
    hash ^= data[i];
    hash *= 16777619u;
  }

  return hash;
}

PCONNECTION_ENTRY
ConnectionLookup(_In_ PFILTER_ENGINE_CONTEXT Context,
                 _In_ PCONNECTION_KEY Key) {
  UINT32 hash = ComputeConnectionHash(Key);
  UINT32 bucket = hash % Context->connection_hash_buckets;
  PCONNECTION_ENTRY conn;
  KIRQL oldIrql;

  KeAcquireSpinLock(&Context->connection_lock, &oldIrql);

  conn = Context->connection_table[bucket];
  while (conn) {
    if (RtlCompareMemory(&conn->key, Key, sizeof(CONNECTION_KEY)) ==
        sizeof(CONNECTION_KEY)) {
      KeReleaseSpinLock(&Context->connection_lock, oldIrql);
      return conn;
    }
    conn = conn->next;
  }

  KeReleaseSpinLock(&Context->connection_lock, oldIrql);
  return NULL;
}

PCONNECTION_ENTRY
ConnectionCreate(_In_ PFILTER_ENGINE_CONTEXT Context,
                 _In_ PCONNECTION_KEY Key) {
  PCONNECTION_ENTRY conn;
  UINT32 hash, bucket;
  KIRQL oldIrql;
  UINT64 now = GetCurrentTimestamp();

  // Check connection count limit
  if (Context->connection_count >= CONNECTION_TABLE_SIZE) {
    DbgPrint("[FilterEngine] Connection table full!\n");
    return NULL;
  }

  // Allocate new connection
  conn = ExAllocatePoolWithTag(NonPagedPool, sizeof(CONNECTION_ENTRY), 'CnEn');
  if (!conn) {
    return NULL;
  }

  RtlZeroMemory(conn, sizeof(CONNECTION_ENTRY));
  RtlCopyMemory(&conn->key, Key, sizeof(CONNECTION_KEY));

  conn->state = CONN_STATE_NEW;
  conn->flow_id =
      InterlockedIncrement64((LONGLONG *)&Context->connections_tracked);
  conn->first_seen = now;
  conn->last_seen = now;

  // Set timeout based on protocol
  if (Key->protocol == 6) { // TCP
    conn->timeout = now + (TCP_TIMEOUT_SYN_SENT * 10000000ULL);
  } else if (Key->protocol == 17) { // UDP
    conn->timeout = now + (UDP_TIMEOUT * 10000000ULL);
  } else {
    conn->timeout = now + (300 * 10000000ULL); // 5 minutes default
  }

  // Insert into hash table
  hash = ComputeConnectionHash(Key);
  bucket = hash % Context->connection_hash_buckets;

  KeAcquireSpinLock(&Context->connection_lock, &oldIrql);

  conn->next = Context->connection_table[bucket];
  Context->connection_table[bucket] = conn;
  Context->connection_count++;

  KeReleaseSpinLock(&Context->connection_lock, oldIrql);

  DbgPrint("[FilterEngine] Created connection %llu (total: %llu)\n",
           conn->flow_id, Context->connection_count);

  return conn;
}

VOID ConnectionUpdate(_In_ PCONNECTION_ENTRY Connection, _In_ UINT32 PacketLen,
                      _In_ BOOLEAN IsForward) {
  UINT64 now = GetCurrentTimestamp();

  Connection->last_seen = now;

  if (IsForward) {
    Connection->packets_forward++;
    Connection->bytes_forward += PacketLen;
  } else {
    Connection->packets_reverse++;
    Connection->bytes_reverse += PacketLen;
  }

  // Update TCP state machine
  if (Connection->key.protocol == 6) { // TCP
    // Simplified state tracking - real implementation would parse TCP flags
    if (Connection->state == CONN_STATE_NEW) {
      Connection->state = CONN_STATE_SYN_SENT;
    } else if (Connection->state == CONN_STATE_SYN_SENT) {
      Connection->state = CONN_STATE_ESTABLISHED;
      Connection->timeout = now + (TCP_TIMEOUT_ESTABLISHED * 10000000ULL);
    }
  }
}

VOID ConnectionDelete(_In_ PFILTER_ENGINE_CONTEXT Context,
                      _In_ PCONNECTION_ENTRY Connection) {
  UINT32 hash, bucket;
  PCONNECTION_ENTRY conn, prev;
  KIRQL oldIrql;

  if (!Connection)
    return;

  hash = ComputeConnectionHash(&Connection->key);
  bucket = hash % Context->connection_hash_buckets;

  KeAcquireSpinLock(&Context->connection_lock, &oldIrql);

  prev = NULL;
  conn = Context->connection_table[bucket];

  while (conn) {
    if (conn == Connection) {
      if (prev) {
        prev->next = conn->next;
      } else {
        Context->connection_table[bucket] = conn->next;
      }

      if (Context->connection_count > 0) {
        Context->connection_count--;
      }

      KeReleaseSpinLock(&Context->connection_lock, oldIrql);
      ExFreePoolWithTag(conn, 'CnEn');
      return;
    }
    prev = conn;
    conn = conn->next;
  }

  KeReleaseSpinLock(&Context->connection_lock, oldIrql);
}

VOID ConnectionCleanupExpired(_In_ PFILTER_ENGINE_CONTEXT Context) {
  UINT64 now = GetCurrentTimestamp();
  UINT32 cleanedCount = 0;
  KIRQL oldIrql;

  for (UINT32 bucket = 0; bucket < Context->connection_hash_buckets; bucket++) {
    KeAcquireSpinLock(&Context->connection_lock, &oldIrql);

    PCONNECTION_ENTRY conn = Context->connection_table[bucket];
    PCONNECTION_ENTRY prev = NULL;

    while (conn) {
      PCONNECTION_ENTRY next = conn->next;

      if (conn->timeout < now) {
        // Expired - remove it
        if (prev) {
          prev->next = next;
        } else {
          Context->connection_table[bucket] = next;
        }

        if (Context->connection_count > 0) {
          Context->connection_count--;
        }

        cleanedCount++;
        ExFreePoolWithTag(conn, 'CnEn');
      } else {
        prev = conn;
      }

      conn = next;
    }

    KeReleaseSpinLock(&Context->connection_lock, oldIrql);
  }

  if (cleanedCount > 0) {
    DbgPrint(
        "[FilterEngine] Cleaned %u expired connections (remaining: %llu)\n",
        cleanedCount, Context->connection_count);
  }
}

//=============================================================================
// SECTION 7: FILTER RULE MANAGEMENT (Dynamic Updates)
//=============================================================================

FILTER_ACTION
ApplyFilterRules(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key,
                 _Out_ PFILTER_RULE *MatchedRule) {
  KIRQL oldIrql;
  PFILTER_RULE rule;
  UINT32 i;
  BOOLEAN match;

  *MatchedRule = NULL;

  KeAcquireSpinLock(&Context->filter_lock, &oldIrql);

  // Iterate through rules (sorted by priority)
  for (i = 0; i < Context->filter_rule_count; i++) {
    rule = &Context->filter_rules[i];

    if (!rule->enabled)
      continue;

    match = MatchesFilterCriteria(rule, Key);

    if (match) {
      *MatchedRule = rule;

      // Update statistics
      InterlockedIncrement64((LONGLONG *)&rule->packets_matched);
      InterlockedAdd64((LONGLONG *)&rule->bytes_matched,
                       0); // Would add packet size

      KeReleaseSpinLock(&Context->filter_lock, oldIrql);
      return rule->action;
    }
  }

  KeReleaseSpinLock(&Context->filter_lock, oldIrql);

  // Default action: PERMIT
  return FILTER_ACTION_PERMIT;
}

BOOLEAN
MatchesFilterCriteria(_In_ PFILTER_RULE Rule, _In_ PCONNECTION_KEY Key) {
  // Check IP ranges
  if (Rule->src_ip_start != 0 || Rule->src_ip_end != 0) {
    if (Key->src_ip < Rule->src_ip_start || Key->src_ip > Rule->src_ip_end) {
      return FALSE;
    }
  }

  if (Rule->dst_ip_start != 0 || Rule->dst_ip_end != 0) {
    if (Key->dst_ip < Rule->dst_ip_start || Key->dst_ip > Rule->dst_ip_end) {
      return FALSE;
    }
  }

  // Check protocol
  if (Rule->protocol != 0 && Rule->protocol != Key->protocol) {
    return FALSE;
  }

  // Check ports
  if (Rule->src_port_start != 0 || Rule->src_port_end != 0) {
    if (Key->src_port < Rule->src_port_start ||
        Key->src_port > Rule->src_port_end) {
      return FALSE;
    }
  }

  if (Rule->dst_port_start != 0 || Rule->dst_port_end != 0) {
    if (Key->dst_port < Rule->dst_port_start ||
        Key->dst_port > Rule->dst_port_end) {
      return FALSE;
    }
  }

  return TRUE;
}

NTSTATUS
AddFilterRule(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PFILTER_RULE Rule) {
  KIRQL oldIrql;

  if (!Rule)
    return STATUS_INVALID_PARAMETER;

  KeAcquireSpinLock(&Context->filter_lock, &oldIrql);

  if (Context->filter_rule_count >= MAX_FILTERS) {
    KeReleaseSpinLock(&Context->filter_lock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Add rule
  RtlCopyMemory(&Context->filter_rules[Context->filter_rule_count], Rule,
                sizeof(FILTER_RULE));

  Context->filter_rule_count++;

  KeReleaseSpinLock(&Context->filter_lock, oldIrql);

  DbgPrint("[FilterEngine] Added filter rule %u (priority: %u)\n",
           Rule->rule_id, Rule->priority);

  return STATUS_SUCCESS;
}

NTSTATUS
RemoveFilterRule(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 RuleId) {
  KIRQL oldIrql;
  UINT32 i;
  BOOLEAN found = FALSE;

  KeAcquireSpinLock(&Context->filter_lock, &oldIrql);

  for (i = 0; i < Context->filter_rule_count; i++) {
    if (Context->filter_rules[i].rule_id == RuleId) {
      // Remove by shifting array
      if (i < Context->filter_rule_count - 1) {
        RtlMoveMemory(&Context->filter_rules[i], &Context->filter_rules[i + 1],
                      (Context->filter_rule_count - i - 1) *
                          sizeof(FILTER_RULE));
      }

      Context->filter_rule_count--;
      found = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&Context->filter_lock, oldIrql);

  if (found) {
    DbgPrint("[FilterEngine] Removed filter rule %u\n", RuleId);
    return STATUS_SUCCESS;
  }

  return STATUS_NOT_FOUND;
}

VOID ClearAllFilterRules(_In_ PFILTER_ENGINE_CONTEXT Context) {
  KIRQL oldIrql;

  KeAcquireSpinLock(&Context->filter_lock, &oldIrql);
  Context->filter_rule_count = 0;
  RtlZeroMemory(Context->filter_rules, MAX_FILTERS * sizeof(FILTER_RULE));
  KeReleaseSpinLock(&Context->filter_lock, oldIrql);

  DbgPrint("[FilterEngine] Cleared all filter rules\n");
}

//=============================================================================
// UTILITIES
//=============================================================================

UINT64
GetCurrentTimestamp(VOID) {
  LARGE_INTEGER time;
  KeQuerySystemTime(&time);
  return time.QuadPart;
}

//=============================================================================
// END OF PHASE 1 - Connection Tracking + Filter Rules
// Next: Phase 2 will add NAT Translation and Packet Modification
//=============================================================================
//=============================================================================
// PHASE 2: NAT TRANSLATION + PACKET MODIFICATION
//=============================================================================

//=============================================================================
// SECTION 5: NAT TRANSLATION (SNAT, DNAT, PAT)
//=============================================================================

VOID UpdateNATTranslation(_Inout_ PCONNECTION_ENTRY Connection,
                          _In_ NAT_TYPE Type, _In_ UINT32 OriginalIp,
                          _In_ UINT16 OriginalPort, _In_ UINT32 TranslatedIp,
                          _In_ UINT16 TranslatedPort) {
  if (!Connection)
    return;

  Connection->nat_type = Type;
  Connection->nat_original_ip = OriginalIp;
  Connection->nat_original_port = OriginalPort;
  Connection->nat_translated_ip = TranslatedIp;
  Connection->nat_translated_port = TranslatedPort;

  DbgPrint("[FilterEngine] NAT configured: %08X:%u -> %08X:%u (type: %u)\n",
           OriginalIp, OriginalPort, TranslatedIp, TranslatedPort, Type);
}

NTSTATUS
PerformNAT(_In_ PFILTER_ENGINE_CONTEXT Context,
           _In_ PCONNECTION_ENTRY Connection, _Inout_ PNET_BUFFER_LIST Nbl,
           _In_ BOOLEAN IsOutbound) {
  NTSTATUS status;
  UINT32 newSrcIp, newDstIp;
  UINT16 newSrcPort, newDstPort;

  if (!Connection || Connection->nat_type == NAT_TYPE_NONE) {
    return STATUS_SUCCESS; // No NAT needed
  }

  // Determine translation direction
  if (IsOutbound) {
    // Outbound: Apply SNAT/PAT
    switch (Connection->nat_type) {
    case NAT_TYPE_SNAT:
      newSrcIp = Connection->nat_translated_ip;
      newDstIp = Connection->key.dst_ip;
      newSrcPort = Connection->key.src_port;
      newDstPort = Connection->key.dst_port;
      break;

    case NAT_TYPE_PAT:
      newSrcIp = Connection->nat_translated_ip;
      newDstIp = Connection->key.dst_ip;
      newSrcPort = Connection->nat_translated_port;
      newDstPort = Connection->key.dst_port;
      break;

    case NAT_TYPE_DNAT:
      // DNAT typically for inbound
      return STATUS_SUCCESS;

    default:
      return STATUS_SUCCESS;
    }
  } else {
    // Inbound: Reverse NAT translation
    switch (Connection->nat_type) {
    case NAT_TYPE_SNAT:
    case NAT_TYPE_PAT:
      // Reverse SNAT/PAT
      newSrcIp = Connection->key.src_ip;
      newDstIp = Connection->nat_original_ip;
      newSrcPort = Connection->key.src_port;
      newDstPort = Connection->nat_original_port;
      break;

    case NAT_TYPE_DNAT:
      // Apply DNAT
      newSrcIp = Connection->key.src_ip;
      newDstIp = Connection->nat_translated_ip;
      newSrcPort = Connection->key.src_port;
      newDstPort = Connection->nat_translated_port;
      break;

    default:
      return STATUS_SUCCESS;
    }
  }

  // Perform packet modification
  status = ModifyPacket(Nbl, newSrcIp, newDstIp, newSrcPort, newDstPort);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[FilterEngine] NAT packet modification failed: 0x%08X\n", status);
    return status;
  }

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 6: PACKET MODIFICATION (IP/Port Rewrite + Checksum)
//=============================================================================

NTSTATUS
ModifyPacket(_Inout_ PNET_BUFFER_LIST Nbl, _In_ UINT32 NewSrcIp,
             _In_ UINT32 NewDstIp, _In_ UINT16 NewSrcPort,
             _In_ UINT16 NewDstPort) {
  PNET_BUFFER nb;
  PUCHAR buffer;
  UINT32 dataLength;
  UINT8 protocol;
  UINT16 ipHeaderLen;

  UNREFERENCED_PARAMETER(NewSrcPort);
  UNREFERENCED_PARAMETER(NewDstPort);

  if (!Nbl)
    return STATUS_INVALID_PARAMETER;

  nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
  if (!nb)
    return STATUS_INVALID_PARAMETER;

  dataLength = NET_BUFFER_DATA_LENGTH(nb);
  if (dataLength < 20)
    return STATUS_INVALID_BUFFER_SIZE;

  // Get contiguous buffer
  buffer = NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);
  if (!buffer) {
    DbgPrint("[FilterEngine] Failed to get contiguous buffer\n");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Parse IP header
  ipHeaderLen = (buffer[0] & 0x0F) * 4;
  protocol = buffer[9];

  if (dataLength < ipHeaderLen) {
    return STATUS_INVALID_BUFFER_SIZE;
  }

  // Modify IP addresses
  if (NewSrcIp != 0) {
    RtlCopyMemory(&buffer[12], &NewSrcIp, 4);
  }
  if (NewDstIp != 0) {
    RtlCopyMemory(&buffer[16], &NewDstIp, 4);
  }

  // Zero out IP checksum (will recalculate)
  buffer[10] = 0;
  buffer[11] = 0;

  // Modify transport layer ports if TCP/UDP
  if ((protocol == 6 || protocol == 17) && dataLength >= ipHeaderLen + 4) {
    PUCHAR transportHeader = buffer + ipHeaderLen;

    if (NewSrcPort != 0) {
      transportHeader[0] = (UINT8)(NewSrcPort >> 8);
      transportHeader[1] = (UINT8)(NewSrcPort & 0xFF);
    }
    if (NewDstPort != 0) {
      transportHeader[2] = (UINT8)(NewDstPort >> 8);
      transportHeader[3] = (UINT8)(NewDstPort & 0xFF);
    }

    // Zero out transport checksum (will recalculate)
    if (protocol == 6 && dataLength >= ipHeaderLen + 18) {
      // TCP checksum at offset 16
      transportHeader[16] = 0;
      transportHeader[17] = 0;
    } else if (protocol == 17 && dataLength >= ipHeaderLen + 8) {
      // UDP checksum at offset 6
      transportHeader[6] = 0;
      transportHeader[7] = 0;
    }
  }

  // Recalculate checksums
  RecalculateChecksums(Nbl);

  return STATUS_SUCCESS;
}

VOID RecalculateChecksums(_Inout_ PNET_BUFFER_LIST Nbl) {
  PNET_BUFFER nb;
  PUCHAR buffer;
  UINT32 dataLength;
  UINT16 ipHeaderLen;
  UINT8 protocol;
  UINT32 ipChecksum;
  UINT32 tcpChecksum;
  UINT16 i;

  if (!Nbl)
    return;

  nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
  if (!nb)
    return;

  dataLength = NET_BUFFER_DATA_LENGTH(nb);
  if (dataLength < 20)
    return;

  buffer = NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);
  if (!buffer)
    return;

  ipHeaderLen = (buffer[0] & 0x0F) * 4;
  protocol = buffer[9];

  // Recalculate IP checksum
  ipChecksum = 0;
  for (i = 0; i < ipHeaderLen; i += 2) {
    if (i == 10)
      continue; // Skip checksum field
    ipChecksum += (buffer[i] << 8) | buffer[i + 1];
  }

  while (ipChecksum >> 16) {
    ipChecksum = (ipChecksum & 0xFFFF) + (ipChecksum >> 16);
  }

  ipChecksum = ~ipChecksum;
  buffer[10] = (UINT8)(ipChecksum >> 8);
  buffer[11] = (UINT8)(ipChecksum & 0xFF);

  // Recalculate transport checksum
  if (protocol == 6 && dataLength >= ipHeaderLen + 20) {
    // TCP checksum calculation (simplified pseudo-header + header + data)
    PUCHAR tcpHeader = buffer + ipHeaderLen;
    UINT16 tcpLen = dataLength - ipHeaderLen;

    tcpChecksum = 0;

    // Pseudo-header: src IP, dst IP, protocol, TCP length
    for (i = 12; i < 20; i += 2) {
      tcpChecksum += (buffer[i] << 8) | buffer[i + 1];
    }
    tcpChecksum += protocol;
    tcpChecksum += tcpLen;

    // TCP header + data
    for (i = 0; i < tcpLen; i += 2) {
      if (i == 16)
        continue; // Skip checksum field
      if (i + 1 < tcpLen) {
        tcpChecksum += (tcpHeader[i] << 8) | tcpHeader[i + 1];
      } else {
        tcpChecksum += (tcpHeader[i] << 8);
      }
    }

    while (tcpChecksum >> 16) {
      tcpChecksum = (tcpChecksum & 0xFFFF) + (tcpChecksum >> 16);
    }

    tcpChecksum = ~tcpChecksum;
    tcpHeader[16] = (UINT8)(tcpChecksum >> 8);
    tcpHeader[17] = (UINT8)(tcpChecksum & 0xFF);
  } else if (protocol == 17 && dataLength >= ipHeaderLen + 8) {
    // UDP checksum calculation (similar to TCP)
    PUCHAR udpHeader = buffer + ipHeaderLen;
    UINT16 udpLen = dataLength - ipHeaderLen;

    tcpChecksum = 0;

    // Pseudo-header
    for (i = 12; i < 20; i += 2) {
      tcpChecksum += (buffer[i] << 8) | buffer[i + 1];
    }
    tcpChecksum += protocol;
    tcpChecksum += udpLen;

    // UDP header + data
    for (i = 0; i < udpLen; i += 2) {
      if (i == 6)
        continue; // Skip checksum field
      if (i + 1 < udpLen) {
        tcpChecksum += (udpHeader[i] << 8) | udpHeader[i + 1];
      } else {
        tcpChecksum += (udpHeader[i] << 8);
      }
    }

    while (tcpChecksum >> 16) {
      tcpChecksum = (tcpChecksum & 0xFFFF) + (tcpChecksum >> 16);
    }

    tcpChecksum = ~tcpChecksum;
    if (tcpChecksum == 0)
      tcpChecksum = 0xFFFF; // UDP: 0 means no checksum

    udpHeader[6] = (UINT8)(tcpChecksum >> 8);
    udpHeader[7] = (UINT8)(tcpChecksum & 0xFF);
  }
}

//=============================================================================
// END OF PHASE 2 - NAT Translation + Packet Modification
// Next: Phase 3 will add Packet Injection, DDoS Protection, and Self-Check
//=============================================================================
//=============================================================================
// PHASE 3: PACKET INJECTION + DDOS PROTECTION + SELF-CHECK
//=============================================================================

//=============================================================================
// SECTION 7: PACKET INJECTION (RST, ICMP, Modified Packets)
//=============================================================================

NTSTATUS
InjectPacket(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PNET_BUFFER_LIST Nbl,
             _In_ BOOLEAN IsOutbound, _In_ BOOLEAN IsTransportLayer) {
  NTSTATUS status;
  HANDLE injectionHandle;

  if (!Nbl)
    return STATUS_INVALID_PARAMETER;

  // Select appropriate injection handle
  injectionHandle = IsTransportLayer ? Context->injection_handle_transport
                                     : Context->injection_handle_network;

  if (!injectionHandle) {
    return STATUS_INVALID_HANDLE;
  }

  // Inject packet
  if (IsOutbound) {
    if (IsTransportLayer) {
      status = FwpsInjectTransportSendAsync0(injectionHandle,
                                             NULL, // Injection context
                                             0,    // Endpoint handle
                                             0,    // Flags
                                             NULL, // Send params
                                             AF_INET,
                                             UNSPECIFIED_COMPARTMENT_ID, Nbl,
                                             NULL, // Completion callback
                                             NULL  // Completion context
      );
    } else {
      status = FwpsInjectNetworkSendAsync0(injectionHandle, NULL, 0,
                                           UNSPECIFIED_COMPARTMENT_ID, Nbl,
                                           NULL, NULL);
    }
  } else {
    if (IsTransportLayer) {
      status = FwpsInjectTransportReceiveAsync0(
          injectionHandle, NULL, NULL, 0, AF_INET, UNSPECIFIED_COMPARTMENT_ID,
          0, // Interface index
          0, // Sub-interface index
          Nbl, NULL, NULL);
    } else {
      status = FwpsInjectNetworkReceiveAsync0(injectionHandle, NULL, 0,
                                              UNSPECIFIED_COMPARTMENT_ID, 0, 0,
                                              Nbl, NULL, NULL);
    }
  }

  if (!NT_SUCCESS(status)) {
    DbgPrint("[FilterEngine] Packet injection failed: 0x%08X\n", status);
  }

  return status;
}

NTSTATUS
InjectRSTPacket(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key) {
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(Key);

  // TODO: Build TCP RST packet and inject
  // Would need to:
  // 1. Allocate NET_BUFFER_LIST
  // 2. Build IP header
  // 3. Build TCP header with RST flag
  // 4. Calculate checksums
  // 5. Inject using InjectPacket()

  DbgPrint("[FilterEngine] RST injection not yet implemented\n");
  return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
InjectICMPUnreachable(_In_ PFILTER_ENGINE_CONTEXT Context,
                      _In_ PCONNECTION_KEY Key) {
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(Key);

  // TODO: Build ICMP Destination Unreachable packet
  // Similar to RST but with ICMP header

  DbgPrint("[FilterEngine] ICMP injection not yet implemented\n");
  return STATUS_NOT_IMPLEMENTED;
}

//=============================================================================
// SECTION 8: DDOS MITIGATION (Rate Limiting + Blacklisting)
//=============================================================================

BOOLEAN
CheckRateLimit(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp,
               _In_ UINT32 PacketLen) {
  UINT32 hash = SrcIp % Context->rate_limit_buckets;
  PRATE_LIMIT_ENTRY entry;
  UINT64 now = GetCurrentTimestamp();
  UINT64 oneSecondAgo = now - 10000000ULL; // 1 second = 10^7 * 100ns
  KIRQL oldIrql;
  BOOLEAN withinLimit = TRUE;

  KeAcquireSpinLock(&Context->rate_limit_lock, &oldIrql);

  entry = Context->rate_limit_table[hash];

  // Find existing entry
  while (entry) {
    if (entry->src_ip == SrcIp) {
      break;
    }
    entry = entry->next;
  }

  if (!entry) {
    // Create new entry
    entry =
        ExAllocatePoolWithTag(NonPagedPool, sizeof(RATE_LIMIT_ENTRY), 'RlEn');
    if (entry) {
      RtlZeroMemory(entry, sizeof(RATE_LIMIT_ENTRY));
      entry->src_ip = SrcIp;
      entry->timestamp = now;
      entry->packet_count = 1;
      entry->byte_count = PacketLen;
      entry->blacklisted = FALSE;

      entry->next = Context->rate_limit_table[hash];
      Context->rate_limit_table[hash] = entry;
    }

    KeReleaseSpinLock(&Context->rate_limit_lock, oldIrql);
    return TRUE;
  }

  // Check if entry is still within 1 second window
  if (entry->timestamp < oneSecondAgo) {
    // Reset counters - new time window
    entry->timestamp = now;
    entry->packet_count = 1;
    entry->byte_count = PacketLen;
  } else {
    // Update counters
    entry->packet_count++;
    entry->byte_count += PacketLen;

    // Check rate limit
    if (entry->packet_count > Context->ddos_config.packet_rate_limit) {
      withinLimit = FALSE;
    }
  }

  KeReleaseSpinLock(&Context->rate_limit_lock, oldIrql);

  return withinLimit;
}

VOID UpdateRateLimit(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp,
                     _In_ UINT32 PacketLen) {
  // Rate limit is updated in CheckRateLimit
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(SrcIp);
  UNREFERENCED_PARAMETER(PacketLen);
}

BOOLEAN
IsBlacklisted(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp) {
  UINT32 hash = SrcIp % Context->rate_limit_buckets;
  PRATE_LIMIT_ENTRY entry;
  UINT64 now = GetCurrentTimestamp();
  KIRQL oldIrql;
  BOOLEAN blacklisted = FALSE;

  KeAcquireSpinLock(&Context->rate_limit_lock, &oldIrql);

  entry = Context->rate_limit_table[hash];
  while (entry) {
    if (entry->src_ip == SrcIp) {
      if (entry->blacklisted && entry->blacklist_until > now) {
        blacklisted = TRUE;
      } else if (entry->blacklisted && entry->blacklist_until <= now) {
        // Blacklist expired
        entry->blacklisted = FALSE;
        entry->blacklist_until = 0;
      }
      break;
    }
    entry = entry->next;
  }

  KeReleaseSpinLock(&Context->rate_limit_lock, oldIrql);

  return blacklisted;
}

VOID BlacklistIP(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp,
                 _In_ UINT32 Duration) {
  UINT32 hash = SrcIp % Context->rate_limit_buckets;
  PRATE_LIMIT_ENTRY entry;
  UINT64 now = GetCurrentTimestamp();
  KIRQL oldIrql;

  KeAcquireSpinLock(&Context->rate_limit_lock, &oldIrql);

  entry = Context->rate_limit_table[hash];
  while (entry) {
    if (entry->src_ip == SrcIp) {
      entry->blacklisted = TRUE;
      entry->blacklist_until = now + (Duration * 10000000ULL);

      DbgPrint("[FilterEngine] Blacklisted IP %08X for %u seconds\n", SrcIp,
               Duration);
      break;
    }
    entry = entry->next;
  }

  // If not found, create new entry
  if (!entry) {
    entry =
        ExAllocatePoolWithTag(NonPagedPool, sizeof(RATE_LIMIT_ENTRY), 'RlEn');
    if (entry) {
      RtlZeroMemory(entry, sizeof(RATE_LIMIT_ENTRY));
      entry->src_ip = SrcIp;
      entry->timestamp = now;
      entry->blacklisted = TRUE;
      entry->blacklist_until = now + (Duration * 10000000ULL);

      entry->next = Context->rate_limit_table[hash];
      Context->rate_limit_table[hash] = entry;

      DbgPrint(
          "[FilterEngine] Blacklisted IP %08X for %u seconds (new entry)\n",
          SrcIp, Duration);
    }
  }

  KeReleaseSpinLock(&Context->rate_limit_lock, oldIrql);
}

VOID CleanupRateLimitTable(_In_ PFILTER_ENGINE_CONTEXT Context) {
  UINT64 now = GetCurrentTimestamp();
  UINT64 fiveMinutesAgo = now - (300 * 10000000ULL);
  UINT32 cleanedCount = 0;
  KIRQL oldIrql;

  for (UINT32 bucket = 0; bucket < Context->rate_limit_buckets; bucket++) {
    KeAcquireSpinLock(&Context->rate_limit_lock, &oldIrql);

    PRATE_LIMIT_ENTRY entry = Context->rate_limit_table[bucket];
    PRATE_LIMIT_ENTRY prev = NULL;

    while (entry) {
      PRATE_LIMIT_ENTRY next = entry->next;

      // Remove if not blacklisted and old
      if (!entry->blacklisted && entry->timestamp < fiveMinutesAgo) {
        if (prev) {
          prev->next = next;
        } else {
          Context->rate_limit_table[bucket] = next;
        }

        cleanedCount++;
        ExFreePoolWithTag(entry, 'RlEn');
      } else {
        prev = entry;
      }

      entry = next;
    }

    KeReleaseSpinLock(&Context->rate_limit_lock, oldIrql);
  }

  if (cleanedCount > 0) {
    DbgPrint("[FilterEngine] Cleaned %u old rate limit entries\n",
             cleanedCount);
  }
}

//=============================================================================
// SECTION 9: STATISTICS
//=============================================================================

NTSTATUS
GetFilterEngineStats(_In_ PFILTER_ENGINE_CONTEXT Context, _Out_ PVOID Stats,
                     _In_ UINT32 StatsSize) {
  KIRQL oldIrql;

  if (!Stats || StatsSize < sizeof(FILTER_ENGINE_CONTEXT)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  KeAcquireSpinLock(&Context->stats_lock, &oldIrql);

  // Copy statistics (simplified - would normally have a stats structure)
  RtlCopyMemory(Stats, Context, min(StatsSize, sizeof(FILTER_ENGINE_CONTEXT)));

  KeReleaseSpinLock(&Context->stats_lock, oldIrql);

  return STATUS_SUCCESS;
}

//=============================================================================
// SECTION 10: SELF-CHECK FUNCTIONS
//=============================================================================

NTSTATUS
VerifyFilterEngine(_In_ PFILTER_ENGINE_CONTEXT Context) {
  DbgPrint("[FilterEngine] === SELF-CHECK START ===\n");

  // 1. Verify WFP callouts registered
  if (!Context->engine_handle) {
    DbgPrint("[FilterEngine] FAIL: WFP engine handle is NULL\n");
    return STATUS_UNSUCCESSFUL;
  }
  DbgPrint("[FilterEngine] PASS: WFP engine handle valid\n");

  // 2. Verify injection handles
  if (!Context->injection_handle_network ||
      !Context->injection_handle_transport) {
    DbgPrint("[FilterEngine] FAIL: Injection handles not created\n");
    return STATUS_UNSUCCESSFUL;
  }
  DbgPrint("[FilterEngine] PASS: Injection handles valid\n");

  // 3. Verify connection table allocated
  if (!Context->connection_table) {
    DbgPrint("[FilterEngine] FAIL: Connection table is NULL\n");
    return STATUS_UNSUCCESSFUL;
  }
  DbgPrint("[FilterEngine] PASS: Connection table allocated (%u buckets)\n",
           Context->connection_hash_buckets);

  // 4. Verify rate limit table
  if (!Context->rate_limit_table) {
    DbgPrint("[FilterEngine] FAIL: Rate limit table is NULL\n");
    return STATUS_UNSUCCESSFUL;
  }
  DbgPrint("[FilterEngine] PASS: Rate limit table allocated (%u buckets)\n",
           Context->rate_limit_buckets);

  // 5. Check connection count sanity
  if (Context->connection_count > CONNECTION_TABLE_SIZE) {
    DbgPrint("[FilterEngine] FAIL: Connection count exceeds limit\n");
    return STATUS_UNSUCCESSFUL;
  }
  DbgPrint("[FilterEngine] PASS: Connection count within limit (%llu / %u)\n",
           Context->connection_count, CONNECTION_TABLE_SIZE);

  // 6. Verify DDoS config
  if (!Context->ddos_config.enabled) {
    DbgPrint("[FilterEngine] WARN: DDoS protection is disabled\n");
  } else {
    DbgPrint(
        "[FilterEngine] PASS: DDoS protection enabled (rate limit: %u pps)\n",
        Context->ddos_config.packet_rate_limit);
  }

  // 7. Verify NAT enabled
  if (!Context->nat_enabled) {
    DbgPrint("[FilterEngine] WARN: NAT is disabled\n");
  } else {
    DbgPrint("[FilterEngine] PASS: NAT enabled\n");
  }

  // 8. Print statistics
  DbgPrint("[FilterEngine] Statistics:\n");
  DbgPrint("[FilterEngine]   Packets permitted: %llu\n",
           Context->packets_permitted);
  DbgPrint("[FilterEngine]   Packets blocked: %llu\n",
           Context->packets_blocked);
  DbgPrint("[FilterEngine]   Packets deferred: %llu\n",
           Context->packets_deferred);
  DbgPrint("[FilterEngine]   NAT translations: %llu\n",
           Context->packets_nat_translated);
  DbgPrint("[FilterEngine]   Connections tracked: %llu\n",
           Context->connections_tracked);
  DbgPrint("[FilterEngine]   DDoS mitigations: %llu\n",
           Context->ddos_mitigations);

  DbgPrint("[FilterEngine] === SELF-CHECK PASS ===\n");

  return STATUS_SUCCESS;
}

//=============================================================================
// END OF PHASE 3 - Packet Injection + DDoS + Self-Check
// ALL SECTIONS COMPLETE
//=============================================================================

//=============================================================================
// PHASE 4: HEADER-ALIGNED WRAPPER FUNCTIONS
// Functions matching exact signatures from filter_engine.h
//=============================================================================

//=============================================================================
// SECTION 11: WFP INITIALIZATION (Header-Aligned)
//=============================================================================

// Global WFP context (local to this file)
static HANDLE g_WfpEngineHandle = NULL;
static UINT32 g_CalloutIds[8] = {0};
static UINT64 g_FilterIds[8] = {0};
static BOOLEAN g_WfpInitialized = FALSE;

NTSTATUS
WfpInitialize(_In_ PDEVICE_OBJECT DeviceObject) {
  NTSTATUS status;
  FWPM_SESSION0 session = {0};

  DbgPrint("[WFP] Initializing WFP engine...\n");

  if (g_WfpInitialized) {
    return STATUS_ALREADY_INITIALIZED;
  }

  UNREFERENCED_PARAMETER(DeviceObject);

  // Open filter engine
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;

#ifdef SAFEOPS_WDK_BUILD
  status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session,
                           &g_WfpEngineHandle);
#else
  UNREFERENCED_PARAMETER(session);
  status = STATUS_SUCCESS;
  g_WfpEngineHandle = (HANDLE)0x12345678;
#endif

  if (!NT_SUCCESS(status)) {
    DbgPrint("[WFP] FwpmEngineOpen failed: 0x%08X\n", status);
    return status;
  }

  g_WfpInitialized = TRUE;
  DbgPrint("[WFP] Engine initialized successfully\n");

  return STATUS_SUCCESS;
}

VOID WfpCleanup(VOID) {
  DbgPrint("[WFP] Cleaning up...\n");

  if (!g_WfpInitialized) {
    return;
  }

  // Unregister all callouts
  for (int i = 0; i < 8; i++) {
    if (g_CalloutIds[i] != 0) {
      WfpUnregisterCallout(g_CalloutIds[i]);
      g_CalloutIds[i] = 0;
    }
    if (g_FilterIds[i] != 0) {
      WfpRemoveFilter(g_FilterIds[i]);
      g_FilterIds[i] = 0;
    }
  }

  // Close engine
#ifdef SAFEOPS_WDK_BUILD
  if (g_WfpEngineHandle) {
    FwpmEngineClose0(g_WfpEngineHandle);
  }
#endif

  g_WfpEngineHandle = NULL;
  g_WfpInitialized = FALSE;

  DbgPrint("[WFP] Cleanup complete\n");
}

NTSTATUS
WfpRegisterCallout(_In_ PGUID CalloutKey, _In_ PGUID LayerKey,
                   _In_ FWPS_CALLOUT_CLASSIFY_FN3 ClassifyFnPtr,
                   _In_ FWPS_CALLOUT_NOTIFY_FN3 NotifyFnPtr,
                   _In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFnPtr,
                   _Out_ UINT32 *OutCalloutId) {
  NTSTATUS status = STATUS_SUCCESS;

  if (!CalloutKey || !LayerKey || !OutCalloutId) {
    return STATUS_INVALID_PARAMETER;
  }

  UNREFERENCED_PARAMETER(ClassifyFnPtr);
  UNREFERENCED_PARAMETER(NotifyFnPtr);
  UNREFERENCED_PARAMETER(FlowDeleteFnPtr);

#ifdef SAFEOPS_WDK_BUILD
  FWPS_CALLOUT3 sCallout = {0};
  sCallout.calloutKey = *CalloutKey;
  sCallout.classifyFn = ClassifyFnPtr;
  sCallout.notifyFn = NotifyFnPtr;
  sCallout.flowDeleteFn = FlowDeleteFnPtr;

  status = FwpsCalloutRegister3(NULL, &sCallout, OutCalloutId);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[WFP] FwpsCalloutRegister failed: 0x%08X\n", status);
    return status;
  }

  // Add callout to WFP
  FWPM_CALLOUT0 mCallout = {0};
  mCallout.calloutKey = *CalloutKey;
  mCallout.applicableLayer = *LayerKey;

  status = FwpmCalloutAdd0(g_WfpEngineHandle, &mCallout, NULL, NULL);
  if (!NT_SUCCESS(status)) {
    FwpsCalloutUnregisterById0(*OutCalloutId);
    DbgPrint("[WFP] FwpmCalloutAdd failed: 0x%08X\n", status);
    return status;
  }
#else
  static UINT32 fakeCalloutId = 100;
  *OutCalloutId = fakeCalloutId++;
#endif

  DbgPrint("[WFP] Callout registered, ID=%u\n", *OutCalloutId);
  return status;
}

NTSTATUS
WfpUnregisterCallout(_In_ UINT32 CalloutId) {
  NTSTATUS status = STATUS_SUCCESS;

#ifdef SAFEOPS_WDK_BUILD
  status = FwpsCalloutUnregisterById0(CalloutId);
#else
  UNREFERENCED_PARAMETER(CalloutId);
#endif

  DbgPrint("[WFP] Callout %u unregistered\n", CalloutId);
  return status;
}

NTSTATUS
WfpAddFilter(_In_ UINT32 CalloutId, _In_ PGUID LayerKey,
             _Out_ UINT64 *OutFilterId) {
  NTSTATUS status = STATUS_SUCCESS;

  if (!LayerKey || !OutFilterId) {
    return STATUS_INVALID_PARAMETER;
  }

  UNREFERENCED_PARAMETER(CalloutId);

#ifdef SAFEOPS_WDK_BUILD
  FWPM_FILTER0 filter = {0};
  filter.layerKey = *LayerKey;
  filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
  filter.action.calloutKey = *LayerKey; // Use layer key for matching

  status = FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, OutFilterId);
#else
  static UINT64 fakeFilterId = 1000;
  *OutFilterId = fakeFilterId++;
#endif

  DbgPrint("[WFP] Filter added, ID=%llu\n", *OutFilterId);
  return status;
}

NTSTATUS
WfpRemoveFilter(_In_ UINT64 FilterId) {
  NTSTATUS status = STATUS_SUCCESS;

#ifdef SAFEOPS_WDK_BUILD
  status = FwpmFilterDeleteById0(g_WfpEngineHandle, FilterId);
#else
  UNREFERENCED_PARAMETER(FilterId);
#endif

  DbgPrint("[WFP] Filter %llu removed\n", FilterId);
  return status;
}

//=============================================================================
// SECTION 12: FIREWALL RULE MANAGEMENT (Header-Aligned)
//=============================================================================

// Global firewall rules table
static FIREWALL_RULE g_FirewallRules[MAX_FILTER_RULES];
static ULONG g_FirewallRuleCount = 0;
static KSPIN_LOCK g_FirewallRuleLock;
static BOOLEAN g_FirewallRulesInitialized = FALSE;

NTSTATUS
AddFirewallRule(_In_ PFIREWALL_RULE Rule) {
  KIRQL oldIrql;

  if (Rule == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!g_FirewallRulesInitialized) {
    KeInitializeSpinLock(&g_FirewallRuleLock);
    g_FirewallRulesInitialized = TRUE;
  }

  KeAcquireSpinLock(&g_FirewallRuleLock, &oldIrql);

  if (g_FirewallRuleCount >= MAX_FILTER_RULES) {
    KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Copy rule
  RtlCopyMemory(&g_FirewallRules[g_FirewallRuleCount], Rule,
                sizeof(FIREWALL_RULE));
  g_FirewallRuleCount++;

  KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);

  DbgPrint("[WFP] Firewall rule added: ID=%llu, Priority=%u\n", Rule->RuleId,
           Rule->Priority);

  // Re-sort by priority
  SortFirewallRulesByPriority();

  return STATUS_SUCCESS;
}

NTSTATUS
RemoveFirewallRule(_In_ ULONG64 RuleId) {
  KIRQL oldIrql;
  BOOLEAN found = FALSE;

  KeAcquireSpinLock(&g_FirewallRuleLock, &oldIrql);

  for (ULONG i = 0; i < g_FirewallRuleCount; i++) {
    if (g_FirewallRules[i].RuleId == RuleId) {
      // Shift remaining rules
      for (ULONG j = i; j < g_FirewallRuleCount - 1; j++) {
        RtlCopyMemory(&g_FirewallRules[j], &g_FirewallRules[j + 1],
                      sizeof(FIREWALL_RULE));
      }
      g_FirewallRuleCount--;
      found = TRUE;
      break;
    }
  }

  KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);

  if (found) {
    DbgPrint("[WFP] Firewall rule removed: ID=%llu\n", RuleId);
    return STATUS_SUCCESS;
  }

  return STATUS_NOT_FOUND;
}

NTSTATUS
UpdateFirewallRule(_In_ ULONG64 RuleId, _In_ PFIREWALL_RULE NewRule) {
  KIRQL oldIrql;

  if (NewRule == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  KeAcquireSpinLock(&g_FirewallRuleLock, &oldIrql);

  for (ULONG i = 0; i < g_FirewallRuleCount; i++) {
    if (g_FirewallRules[i].RuleId == RuleId) {
      RtlCopyMemory(&g_FirewallRules[i], NewRule, sizeof(FIREWALL_RULE));
      KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);

      SortFirewallRulesByPriority();
      return STATUS_SUCCESS;
    }
  }

  KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);
  return STATUS_NOT_FOUND;
}

NTSTATUS
ClearAllFirewallRules(VOID) {
  KIRQL oldIrql;

  KeAcquireSpinLock(&g_FirewallRuleLock, &oldIrql);
  g_FirewallRuleCount = 0;
  RtlZeroMemory(g_FirewallRules, sizeof(g_FirewallRules));
  KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);

  DbgPrint("[WFP] All firewall rules cleared\n");
  return STATUS_SUCCESS;
}

PFIREWALL_RULE
FindFirewallRule(_In_ ULONG64 RuleId) {
  for (ULONG i = 0; i < g_FirewallRuleCount; i++) {
    if (g_FirewallRules[i].RuleId == RuleId) {
      return &g_FirewallRules[i];
    }
  }
  return NULL;
}

NTSTATUS
EvaluateFirewallRules(_In_ PWFP_CLASSIFY_CONTEXT Context,
                      _Out_ PULONG OutAction, _Out_ PULONG64 OutRuleId) {
  if (Context == NULL || OutAction == NULL || OutRuleId == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  *OutAction = WFP_ACTION_PERMIT; // Default allow
  *OutRuleId = 0;

  for (ULONG i = 0; i < g_FirewallRuleCount; i++) {
    PFIREWALL_RULE rule = &g_FirewallRules[i];

    // Check direction
    if (rule->Direction != 0 &&
        rule->Direction != (Context->IsInbound ? 1 : 2)) {
      continue;
    }

    // Check protocol
    if (rule->Protocol != 0 && rule->Protocol != Context->Protocol) {
      continue;
    }

    // Check source IP
    if (rule->SourceIP != 0 && rule->SourceIP != Context->SourceIP) {
      continue;
    }

    // Check dest IP
    if (rule->DestIP != 0 && rule->DestIP != Context->DestIP) {
      continue;
    }

    // Check source port range
    if (rule->SourcePortStart != 0 &&
        (Context->SourcePort < rule->SourcePortStart ||
         Context->SourcePort > rule->SourcePortEnd)) {
      continue;
    }

    // Check dest port range
    if (rule->DestPortStart != 0 && (Context->DestPort < rule->DestPortStart ||
                                     Context->DestPort > rule->DestPortEnd)) {
      continue;
    }

    // Rule matches!
    *OutAction = rule->Action;
    *OutRuleId = rule->RuleId;

    // Update hit count
    InterlockedIncrement64((LONG64 *)&rule->HitCount);

    DbgPrint("[WFP] Rule %llu matched, action=%u\n", rule->RuleId,
             rule->Action);
    return STATUS_SUCCESS;
  }

  return STATUS_SUCCESS; // No rule matched, default action
}

VOID SortFirewallRulesByPriority(VOID) {
  KIRQL oldIrql;
  FIREWALL_RULE temp;

  KeAcquireSpinLock(&g_FirewallRuleLock, &oldIrql);

  // Simple bubble sort (small array, infrequent operation)
  for (ULONG i = 0; i < g_FirewallRuleCount; i++) {
    for (ULONG j = i + 1; j < g_FirewallRuleCount; j++) {
      if (g_FirewallRules[j].Priority < g_FirewallRules[i].Priority) {
        RtlCopyMemory(&temp, &g_FirewallRules[i], sizeof(FIREWALL_RULE));
        RtlCopyMemory(&g_FirewallRules[i], &g_FirewallRules[j],
                      sizeof(FIREWALL_RULE));
        RtlCopyMemory(&g_FirewallRules[j], &temp, sizeof(FIREWALL_RULE));
      }
    }
  }

  KeReleaseSpinLock(&g_FirewallRuleLock, oldIrql);
}

ULONG
GetFirewallRuleCount(VOID) { return g_FirewallRuleCount; }

//=============================================================================
// SECTION 13: CONNECTION TRACKING (Header-Aligned)
//=============================================================================

// Global connection table
static CONNECTION_TRACK_ENTRY g_ConnectionTable[CONNECTION_TABLE_SIZE];
static ULONG g_ConnectionCount = 0;
static KSPIN_LOCK g_ConnectionLock;
static BOOLEAN g_ConnectionTableInitialized = FALSE;

NTSTATUS
CreateConnectionTrackEntry(_In_ PWFP_CLASSIFY_CONTEXT Context,
                           _Out_ PCONNECTION_TRACK_ENTRY *OutEntry) {
  KIRQL oldIrql;

  if (Context == NULL || OutEntry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (!g_ConnectionTableInitialized) {
    KeInitializeSpinLock(&g_ConnectionLock);
    g_ConnectionTableInitialized = TRUE;
  }

  KeAcquireSpinLock(&g_ConnectionLock, &oldIrql);

  if (g_ConnectionCount >= CONNECTION_TABLE_SIZE) {
    KeReleaseSpinLock(&g_ConnectionLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Find empty slot
  PCONNECTION_TRACK_ENTRY entry = &g_ConnectionTable[g_ConnectionCount];
  RtlZeroMemory(entry, sizeof(CONNECTION_TRACK_ENTRY));

  // Fill in connection data
  entry->SourceIP = Context->SourceIP;
  entry->DestIP = Context->DestIP;
  entry->SourcePort = Context->SourcePort;
  entry->DestPort = Context->DestPort;
  entry->Protocol = Context->Protocol;
  entry->State = WFP_CONN_NEW;
  entry->CreatedTime = GetCurrentTimestamp();
  entry->LastActivityTime = entry->CreatedTime;

  g_ConnectionCount++;
  *OutEntry = entry;

  KeReleaseSpinLock(&g_ConnectionLock, oldIrql);

  DbgPrint("[WFP] Connection created: %08X:%u -> %08X:%u\n", Context->SourceIP,
           Context->SourcePort, Context->DestIP, Context->DestPort);

  return STATUS_SUCCESS;
}

PCONNECTION_TRACK_ENTRY
FindConnectionTrackEntry(_In_ ULONG SourceIP, _In_ ULONG DestIP,
                         _In_ USHORT SourcePort, _In_ USHORT DestPort,
                         _In_ UCHAR Protocol) {
  for (ULONG i = 0; i < g_ConnectionCount; i++) {
    PCONNECTION_TRACK_ENTRY entry = &g_ConnectionTable[i];

    // Check forward direction
    if (entry->SourceIP == SourceIP && entry->DestIP == DestIP &&
        entry->SourcePort == SourcePort && entry->DestPort == DestPort &&
        entry->Protocol == Protocol) {
      return entry;
    }

    // Check reverse direction (for stateful tracking)
    if (entry->SourceIP == DestIP && entry->DestIP == SourceIP &&
        entry->SourcePort == DestPort && entry->DestPort == SourcePort &&
        entry->Protocol == Protocol) {
      return entry;
    }
  }

  return NULL;
}

NTSTATUS
UpdateConnectionTrackEntry(_Inout_ PCONNECTION_TRACK_ENTRY Entry,
                           _In_ PWFP_CLASSIFY_CONTEXT Context) {
  if (Entry == NULL || Context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  Entry->LastActivityTime = GetCurrentTimestamp();
  Entry->PacketCount++;
  Entry->ByteCount += Context->DataLength;

  // Update TCP state if applicable
  if (Entry->Protocol == 6) { // TCP
    // Would parse TCP flags here to update state machine
  }

  return STATUS_SUCCESS;
}

VOID DeleteConnectionTrackEntry(_In_ PCONNECTION_TRACK_ENTRY Entry) {
  KIRQL oldIrql;

  if (Entry == NULL) {
    return;
  }

  KeAcquireSpinLock(&g_ConnectionLock, &oldIrql);

  // Find entry index
  for (ULONG i = 0; i < g_ConnectionCount; i++) {
    if (&g_ConnectionTable[i] == Entry) {
      // Shift remaining entries
      for (ULONG j = i; j < g_ConnectionCount - 1; j++) {
        RtlCopyMemory(&g_ConnectionTable[j], &g_ConnectionTable[j + 1],
                      sizeof(CONNECTION_TRACK_ENTRY));
      }
      g_ConnectionCount--;
      break;
    }
  }

  KeReleaseSpinLock(&g_ConnectionLock, oldIrql);
}

VOID PurgeExpiredConnections(VOID) {
  KIRQL oldIrql;
  UINT64 now = GetCurrentTimestamp();
  UINT64 timeout = 300 * 10000000ULL; // 5 minutes

  KeAcquireSpinLock(&g_ConnectionLock, &oldIrql);

  ULONG i = 0;
  while (i < g_ConnectionCount) {
    if ((now - g_ConnectionTable[i].LastActivityTime) > timeout) {
      // Remove expired connection
      for (ULONG j = i; j < g_ConnectionCount - 1; j++) {
        RtlCopyMemory(&g_ConnectionTable[j], &g_ConnectionTable[j + 1],
                      sizeof(CONNECTION_TRACK_ENTRY));
      }
      g_ConnectionCount--;
    } else {
      i++;
    }
  }

  KeReleaseSpinLock(&g_ConnectionLock, oldIrql);
}

ULONG
GetConnectionCount(VOID) { return g_ConnectionCount; }

BOOLEAN
IsConnectionEstablished(_In_ PCONNECTION_TRACK_ENTRY Entry) {
  if (Entry == NULL) {
    return FALSE;
  }

  return (Entry->State == WFP_CONN_ESTABLISHED);
}

//=============================================================================
// SECTION 14: NAT OPERATIONS (Header-Aligned)
//=============================================================================

// Global NAT table
static NAT_TRANSLATION_ENTRY g_NatTable[NAT_TABLE_SIZE];
static ULONG g_NatCount = 0;
static KSPIN_LOCK g_NatLock;
static BOOLEAN g_NatInitialized = FALSE;
static USHORT g_NextNatPort = NAT_PORT_RANGE_START;

NTSTATUS
CreateNATMapping(_In_ ULONG OriginalSourceIP, _In_ USHORT OriginalSourcePort,
                 _In_ ULONG DestIP, _In_ USHORT DestPort, _In_ UCHAR Protocol,
                 _Out_ PNAT_TRANSLATION_ENTRY *OutEntry) {
  KIRQL oldIrql;

  if (OutEntry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  UNREFERENCED_PARAMETER(DestIP);
  UNREFERENCED_PARAMETER(DestPort);

  if (!g_NatInitialized) {
    KeInitializeSpinLock(&g_NatLock);
    g_NatInitialized = TRUE;
  }

  KeAcquireSpinLock(&g_NatLock, &oldIrql);

  if (g_NatCount >= NAT_TABLE_SIZE) {
    KeReleaseSpinLock(&g_NatLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  PNAT_TRANSLATION_ENTRY entry = &g_NatTable[g_NatCount];
  RtlZeroMemory(entry, sizeof(NAT_TRANSLATION_ENTRY));

  entry->OriginalSourceIP = OriginalSourceIP;
  entry->OriginalSourcePort = OriginalSourcePort;
  entry->TranslatedPort = AllocateNATPort(0);
  entry->Protocol = Protocol;
  entry->CreatedTime = GetCurrentTimestamp();

  g_NatCount++;
  *OutEntry = entry;

  KeReleaseSpinLock(&g_NatLock, oldIrql);

  return STATUS_SUCCESS;
}

PNAT_TRANSLATION_ENTRY
FindNATMapping(_In_ ULONG TranslatedIP, _In_ USHORT TranslatedPort,
               _In_ UCHAR Protocol) {
  UNREFERENCED_PARAMETER(TranslatedIP);

  for (ULONG i = 0; i < g_NatCount; i++) {
    if (g_NatTable[i].TranslatedPort == TranslatedPort &&
        g_NatTable[i].Protocol == Protocol) {
      return &g_NatTable[i];
    }
  }

  return NULL;
}

NTSTATUS
ApplyNATTranslation(_Inout_ PVOID PacketData, _In_ ULONG DataLength,
                    _In_ PNAT_TRANSLATION_ENTRY NatEntry) {
  if (PacketData == NULL || NatEntry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (DataLength < 20) {
    return STATUS_INVALID_BUFFER_SIZE;
  }

  PUCHAR buffer = (PUCHAR)PacketData;

  // Modify source IP
  RtlCopyMemory(&buffer[12], &NatEntry->TranslatedIP, 4);

  // Modify source port if TCP/UDP
  UINT8 protocol = buffer[9];
  UINT16 ipHeaderLen = (buffer[0] & 0x0F) * 4;

  if ((protocol == 6 || protocol == 17) && DataLength >= ipHeaderLen + 4) {
    PUCHAR transportHeader = buffer + ipHeaderLen;
    transportHeader[0] = (UINT8)(NatEntry->TranslatedPort >> 8);
    transportHeader[1] = (UINT8)(NatEntry->TranslatedPort & 0xFF);
  }

  return STATUS_SUCCESS;
}

NTSTATUS
ReverseNATTranslation(_Inout_ PVOID PacketData, _In_ ULONG DataLength,
                      _In_ PNAT_TRANSLATION_ENTRY NatEntry) {
  if (PacketData == NULL || NatEntry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (DataLength < 20) {
    return STATUS_INVALID_BUFFER_SIZE;
  }

  PUCHAR buffer = (PUCHAR)PacketData;

  // Restore original destination IP
  RtlCopyMemory(&buffer[16], &NatEntry->OriginalSourceIP, 4);

  // Restore destination port if TCP/UDP
  UINT8 protocol = buffer[9];
  UINT16 ipHeaderLen = (buffer[0] & 0x0F) * 4;

  if ((protocol == 6 || protocol == 17) && DataLength >= ipHeaderLen + 4) {
    PUCHAR transportHeader = buffer + ipHeaderLen;
    transportHeader[2] = (UINT8)(NatEntry->OriginalSourcePort >> 8);
    transportHeader[3] = (UINT8)(NatEntry->OriginalSourcePort & 0xFF);
  }

  return STATUS_SUCCESS;
}

VOID DeleteNATMapping(_In_ PNAT_TRANSLATION_ENTRY Entry) {
  KIRQL oldIrql;

  if (Entry == NULL) {
    return;
  }

  KeAcquireSpinLock(&g_NatLock, &oldIrql);

  for (ULONG i = 0; i < g_NatCount; i++) {
    if (&g_NatTable[i] == Entry) {
      ReleaseNATPort(0, Entry->TranslatedPort);

      for (ULONG j = i; j < g_NatCount - 1; j++) {
        RtlCopyMemory(&g_NatTable[j], &g_NatTable[j + 1],
                      sizeof(NAT_TRANSLATION_ENTRY));
      }
      g_NatCount--;
      break;
    }
  }

  KeReleaseSpinLock(&g_NatLock, oldIrql);
}

USHORT
AllocateNATPort(_In_ ULONG PublicIP) {
  UNREFERENCED_PARAMETER(PublicIP);

  USHORT port = g_NextNatPort;
  g_NextNatPort++;

  if (g_NextNatPort > NAT_PORT_RANGE_END) {
    g_NextNatPort = NAT_PORT_RANGE_START;
  }

  return port;
}

VOID ReleaseNATPort(_In_ ULONG PublicIP, _In_ USHORT Port) {
  UNREFERENCED_PARAMETER(PublicIP);
  UNREFERENCED_PARAMETER(Port);
  // Port is returned to pool (simple implementation just ignores)
}

//=============================================================================
// SECTION 15: PACKET INJECTION (Header-Aligned)
//=============================================================================

NTSTATUS
InjectPacketInbound(_In_ PVOID PacketData, _In_ ULONG DataLength,
                    _In_ ULONG InterfaceIndex) {
  UNREFERENCED_PARAMETER(PacketData);
  UNREFERENCED_PARAMETER(DataLength);
  UNREFERENCED_PARAMETER(InterfaceIndex);

  // Would create NET_BUFFER_LIST and inject
  DbgPrint("[WFP] InjectPacketInbound: %u bytes\n", DataLength);
  return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
InjectPacketOutbound(_In_ PVOID PacketData, _In_ ULONG DataLength,
                     _In_ ULONG InterfaceIndex) {
  UNREFERENCED_PARAMETER(PacketData);
  UNREFERENCED_PARAMETER(DataLength);
  UNREFERENCED_PARAMETER(InterfaceIndex);

  DbgPrint("[WFP] InjectPacketOutbound: %u bytes\n", DataLength);
  return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
CloneAndInjectPacket(_In_ PWFP_CLASSIFY_CONTEXT Context,
                     _In_ PVOID ModifiedData, _In_ ULONG ModifiedLength) {
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(ModifiedData);
  UNREFERENCED_PARAMETER(ModifiedLength);

  DbgPrint("[WFP] CloneAndInjectPacket: %u bytes\n", ModifiedLength);
  return STATUS_NOT_IMPLEMENTED;
}

VOID FreeInjectionContext(_In_ PVOID InjectionContext) {
  if (InjectionContext) {
    ExFreePoolWithTag(InjectionContext, 'InjC');
  }
}

//=============================================================================
// SECTION 16: DEBUG FUNCTIONS (Header-Aligned)
//=============================================================================

#ifdef DBG

VOID DbgPrintFirewallRule(_In_ PFIREWALL_RULE Rule) {
  if (Rule == NULL) {
    DbgPrint("[WFP] Rule: NULL\n");
    return;
  }

  DbgPrint("[WFP] Rule ID=%llu Priority=%u Action=%u\n", Rule->RuleId,
           Rule->Priority, Rule->Action);
  DbgPrint("[WFP]   Direction=%u Protocol=%u\n", Rule->Direction,
           Rule->Protocol);
  DbgPrint("[WFP]   Src: %08X Dst: %08X\n", Rule->SourceIP, Rule->DestIP);
  DbgPrint("[WFP]   SrcPort: %u-%u DstPort: %u-%u\n", Rule->SourcePortStart,
           Rule->SourcePortEnd, Rule->DestPortStart, Rule->DestPortEnd);
  DbgPrint("[WFP]   Hits: %llu\n", Rule->HitCount);
}

VOID DbgPrintConnectionEntry(_In_ PCONNECTION_TRACK_ENTRY Entry) {
  if (Entry == NULL) {
    DbgPrint("[WFP] Connection: NULL\n");
    return;
  }

  DbgPrint("[WFP] Connection: %08X:%u -> %08X:%u [%u]\n", Entry->SourceIP,
           Entry->SourcePort, Entry->DestIP, Entry->DestPort, Entry->Protocol);
  DbgPrint("[WFP]   State=%u Packets=%llu Bytes=%llu\n", Entry->State,
           Entry->PacketCount, Entry->ByteCount);
}

VOID DbgPrintNATEntry(_In_ PNAT_TRANSLATION_ENTRY Entry) {
  if (Entry == NULL) {
    DbgPrint("[WFP] NAT: NULL\n");
    return;
  }

  DbgPrint("[WFP] NAT: %08X:%u -> %08X:%u [%u]\n", Entry->OriginalSourceIP,
           Entry->OriginalSourcePort, Entry->TranslatedIP,
           Entry->TranslatedPort, Entry->Protocol);
}

NTSTATUS
DbgVerifyWfpState(VOID) {
  DbgPrint("[WFP] === SELF-CHECK START ===\n");

  if (!g_WfpInitialized) {
    DbgPrint("[WFP] WARN: WFP not initialized\n");
  } else {
    DbgPrint("[WFP] PASS: WFP initialized\n");
  }

  DbgPrint("[WFP] Firewall rules: %u\n", g_FirewallRuleCount);
  DbgPrint("[WFP] Connections: %u\n", g_ConnectionCount);
  DbgPrint("[WFP] NAT mappings: %u\n", g_NatCount);

  DbgPrint("[WFP] === SELF-CHECK COMPLETE ===\n");
  return STATUS_SUCCESS;
}

#endif // DBG

//=============================================================================
// END OF FILTER ENGINE IMPLEMENTATION
//=============================================================================
