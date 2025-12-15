/*******************************************************************************
 * FILE: src/kernel_driver/filter_engine.h
 * 
 * SafeOps WFP Filter Engine - Header
 * 
 * PURPOSE:
 *   Windows Filtering Platform integration for packet filtering, NAT, 
 *   connection tracking, and DDoS mitigation.
 * 
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_FILTER_ENGINE_H_
#define _SAFEOPS_FILTER_ENGINE_H_

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <netiodef.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

#define CONNECTION_TABLE_SIZE       10000000    // 10 million connections
#define CONNECTION_HASH_BUCKETS     65536       // 64K buckets
#define NAT_SESSION_TIMEOUT         300         // 5 minutes
#define TCP_TIMEOUT_ESTABLISHED     7200        // 2 hours
#define TCP_TIMEOUT_SYN_SENT        120         // 2 minutes
#define UDP_TIMEOUT                 180         // 3 minutes
#define RATE_LIMIT_PPS              10000       // Default rate limit
#define BLACKLIST_DURATION          300         // 5 minutes
#define MAX_FILTERS                 10000       // Max filter rules

//=============================================================================
// GUIDs for WFP Callouts
//=============================================================================

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(
    SAFEOPS_CALLOUT_INBOUND_V4,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90
);

// {B2C3D4E5-F6A7-8901-BCDE-F12345678901}
DEFINE_GUID(
    SAFEOPS_CALLOUT_OUTBOUND_V4,
    0xb2c3d4e5, 0xf6a7, 0x8901, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x01
);

// {C3D4E5F6-A7B8-9012-CDEF-123456789012}
DEFINE_GUID(
    SAFEOPS_CALLOUT_CONNECT_V4,
    0xc3d4e5f6, 0xa7b8, 0x9012, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12
);

//=============================================================================
// ENUMERATIONS
//=============================================================================

typedef enum _FILTER_ACTION {
    FILTER_ACTION_PERMIT = 0,
    FILTER_ACTION_BLOCK = 1,
    FILTER_ACTION_DEFER = 2,
    FILTER_ACTION_NAT = 3
} FILTER_ACTION;

typedef enum _NAT_TYPE {
    NAT_TYPE_NONE = 0,
    NAT_TYPE_SNAT = 1,      // Source NAT
    NAT_TYPE_DNAT = 2,      // Destination NAT
    NAT_TYPE_PAT = 3        // Port Address Translation
} NAT_TYPE;

typedef enum _CONNECTION_STATE {
    CONN_STATE_NEW = 0,
    CONN_STATE_SYN_SENT = 1,
    CONN_STATE_SYN_RECEIVED = 2,
    CONN_STATE_ESTABLISHED = 3,
    CONN_STATE_FIN_WAIT = 4,
    CONN_STATE_CLOSING = 5,
    CONN_STATE_CLOSED = 6
} CONNECTION_STATE;

typedef enum _FAIL_MODE {
    FAIL_MODE_OPEN = 0,     // Allow all traffic on error
    FAIL_MODE_CLOSED = 1    // Block all traffic on error
} FAIL_MODE;

//=============================================================================
// STRUCTURES
//=============================================================================

#pragma pack(push, 1)

// 5-tuple connection key
typedef struct _CONNECTION_KEY {
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8 protocol;
    UINT8 reserved[3];
} CONNECTION_KEY, *PCONNECTION_KEY;

// Connection tracking entry
typedef struct _CONNECTION_ENTRY {
    CONNECTION_KEY key;
    CONNECTION_STATE state;
    UINT64 flow_id;
    
    // Timestamps
    UINT64 first_seen;
    UINT64 last_seen;
    UINT64 timeout;
    
    // Statistics
    UINT64 packets_forward;
    UINT64 packets_reverse;
    UINT64 bytes_forward;
    UINT64 bytes_reverse;
    
    // NAT information
    NAT_TYPE nat_type;
    UINT32 nat_original_ip;
    UINT16 nat_original_port;
    UINT32 nat_translated_ip;
    UINT16 nat_translated_port;
    
    // Flags
    BOOLEAN is_gaming;
    BOOLEAN is_encrypted;
    UINT8 reserved[2];
    
    // Hash table linkage
    struct _CONNECTION_ENTRY* next;
    
} CONNECTION_ENTRY, *PCONNECTION_ENTRY;

// Filter rule
typedef struct _FILTER_RULE {
    UINT32 rule_id;
    UINT32 priority;
    FILTER_ACTION action;
    
    // Match criteria
    UINT32 src_ip_start;
    UINT32 src_ip_end;
    UINT32 dst_ip_start;
    UINT32 dst_ip_end;
    UINT16 src_port_start;
    UINT16 src_port_end;
    UINT16 dst_port_start;
    UINT16 dst_port_end;
    UINT8 protocol;
    UINT8 direction;        // 0=both, 1=inbound, 2=outbound
    
    // NAT settings (if action == NAT)
    NAT_TYPE nat_type;
    UINT32 nat_target_ip;
    UINT16 nat_target_port;
    
    // Statistics
    UINT64 packets_matched;
    UINT64 bytes_matched;
    
    BOOLEAN enabled;
    UINT8 reserved[3];
    
} FILTER_RULE, *PFILTER_RULE;

// Rate limit entry
typedef struct _RATE_LIMIT_ENTRY {
    UINT32 src_ip;
    UINT64 timestamp;
    UINT32 packet_count;
    UINT32 byte_count;
    BOOLEAN blacklisted;
    UINT64 blacklist_until;
    
    struct _RATE_LIMIT_ENTRY* next;
} RATE_LIMIT_ENTRY, *PRATE_LIMIT_ENTRY;

// DDoS protection config
typedef struct _DDOS_CONFIG {
    BOOLEAN enabled;
    UINT32 syn_rate_limit;          // SYN packets per second
    UINT32 packet_rate_limit;       // Total packets per second
    UINT32 connection_rate_limit;   // New connections per second
    UINT32 blacklist_threshold;     // Violations before blacklist
    UINT32 blacklist_duration;      // Seconds to blacklist
    BOOLEAN enable_syn_cookies;
} DDOS_CONFIG, *PDDOS_CONFIG;

#pragma pack(pop)

//=============================================================================
// FILTER ENGINE CONTEXT
//=============================================================================

typedef struct _FILTER_ENGINE_CONTEXT {
    // WFP handles
    HANDLE engine_handle;
    UINT32 callout_id_inbound_v4;
    UINT32 callout_id_outbound_v4;
    UINT32 callout_id_connect_v4;
    UINT32 filter_id_inbound;
    UINT32 filter_id_outbound;
    UINT32 filter_id_connect;
    
    // Injection handles
    HANDLE injection_handle_network;
    HANDLE injection_handle_transport;
    
    // Connection tracking
    PCONNECTION_ENTRY* connection_table;
    UINT32 connection_hash_buckets;
    UINT64 connection_count;
    KSPIN_LOCK connection_lock;
    
    // Filter rules
    PFILTER_RULE filter_rules;
    UINT32 filter_rule_count;
    KSPIN_LOCK filter_lock;
    
    // Rate limiting
    PRATE_LIMIT_ENTRY* rate_limit_table;
    UINT32 rate_limit_buckets;
    KSPIN_LOCK rate_limit_lock;
    
    // DDoS protection
    DDOS_CONFIG ddos_config;
    
    // Configuration
    FAIL_MODE fail_mode;
    BOOLEAN nat_enabled;
    BOOLEAN connection_tracking_enabled;
    
    // Statistics
    UINT64 packets_permitted;
    UINT64 packets_blocked;
    UINT64 packets_deferred;
    UINT64 packets_nat_translated;
    UINT64 connections_tracked;
    UINT64 ddos_mitigations;
    
    KSPIN_LOCK stats_lock;
    
} FILTER_ENGINE_CONTEXT, *PFILTER_ENGINE_CONTEXT;

//=============================================================================
// FUNCTION PROTOTYPES
//=============================================================================

// Initialization
NTSTATUS FilterEngineInitialize(_Out_ PFILTER_ENGINE_CONTEXT* Context);
VOID FilterEngineCleanup(_In_ PFILTER_ENGINE_CONTEXT Context);

// WFP Registration
NTSTATUS RegisterWfpCallouts(_In_ PFILTER_ENGINE_CONTEXT Context);
VOID UnregisterWfpCallouts(_In_ PFILTER_ENGINE_CONTEXT Context);
NTSTATUS AddWfpFilters(_In_ PFILTER_ENGINE_CONTEXT Context);
VOID RemoveWfpFilters(_In_ PFILTER_ENGINE_CONTEXT Context);

// Callout Functions
VOID NTAPI ClassifyInbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

VOID NTAPI ClassifyOutbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI NotifyCallback(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER2* filter
);

VOID NTAPI FlowDeleteCallback(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext);

// Connection Tracking
PCONNECTION_ENTRY ConnectionLookup(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key);
PCONNECTION_ENTRY ConnectionCreate(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key);
VOID ConnectionUpdate(_In_ PCONNECTION_ENTRY Connection, _In_ UINT32 PacketLen, _In_ BOOLEAN IsForward);
VOID ConnectionCleanupExpired(_In_ PFILTER_ENGINE_CONTEXT Context);
VOID ConnectionDelete(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_ENTRY Connection);

// Filter Rules
FILTER_ACTION ApplyFilterRules(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key, _Out_ PFILTER_RULE* MatchedRule);
NTSTATUS AddFilterRule(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PFILTER_RULE Rule);
NTSTATUS RemoveFilterRule(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 RuleId);
VOID ClearAllFilterRules(_In_ PFILTER_ENGINE_CONTEXT Context);

// NAT Translation
NTSTATUS PerformNAT(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_ENTRY Connection, 
                    _Inout_ PNET_BUFFER_LIST Nbl, _In_ BOOLEAN IsOutbound);
VOID UpdateNATTranslation(_Inout_ PCONNECTION_ENTRY Connection, _In_ NAT_TYPE Type, 
                         _In_ UINT32 OriginalIp, _In_ UINT16 OriginalPort,
                         _In_ UINT32 TranslatedIp, _In_ UINT16 TranslatedPort);

// Packet Modification
NTSTATUS ModifyPacket(_Inout_ PNET_BUFFER_LIST Nbl, _In_ UINT32 NewSrcIp, _In_ UINT32 NewDstIp,
                      _In_ UINT16 NewSrcPort, _In_ UINT16 NewDstPort);
VOID RecalculateChecksums(_Inout_ PNET_BUFFER_LIST Nbl);

// Packet Injection
NTSTATUS InjectPacket(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PNET_BUFFER_LIST Nbl,
                      _In_ BOOLEAN IsOutbound, _In_ BOOLEAN IsTransportLayer);
NTSTATUS InjectRSTPacket(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key);
NTSTATUS InjectICMPUnreachable(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ PCONNECTION_KEY Key);

// DDoS Mitigation
BOOLEAN CheckRateLimit(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp, _In_ UINT32 PacketLen);
VOID UpdateRateLimit(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp, _In_ UINT32 PacketLen);
BOOLEAN IsBlacklisted(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp);
VOID BlacklistIP(_In_ PFILTER_ENGINE_CONTEXT Context, _In_ UINT32 SrcIp, _In_ UINT32 Duration);
VOID CleanupRateLimitTable(_In_ PFILTER_ENGINE_CONTEXT Context);

// Utilities
UINT32 ComputeConnectionHash(_In_ PCONNECTION_KEY Key);
UINT64 GetCurrentTimestamp(VOID);
BOOLEAN MatchesFilterCriteria(_In_ PFILTER_RULE Rule, _In_ PCONNECTION_KEY Key);

// Statistics
NTSTATUS GetFilterEngineStats(_In_ PFILTER_ENGINE_CONTEXT Context, _Out_ PVOID Stats, _In_ UINT32 StatsSize);

// Self-Check
NTSTATUS VerifyFilterEngine(_In_ PFILTER_ENGINE_CONTEXT Context);

#endif // _SAFEOPS_FILTER_ENGINE_H_
