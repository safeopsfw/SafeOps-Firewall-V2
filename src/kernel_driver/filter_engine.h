/**
 * filter_engine.h - SafeOps WFP Callout Driver Interface
 *
 * Purpose: Defines the Windows Filtering Platform (WFP) callout driver
 * interface for SafeOps, establishing all data structures, constants, and
 * function prototypes needed to implement packet filtering and policy
 * enforcement at eight WFP layers (IPv4/IPv6 × Inbound/Outbound ×
 * Network/Transport layers).
 *
 * Unlike packet_capture.h which focuses on observation, filter_engine.h
 * implements active packet manipulation including permit/deny decisions, packet
 * modification, and connection tracking.
 *
 * Copyright (c) 2024 SafeOps Project
 * License: MIT
 */

#ifndef SAFEOPS_FILTER_ENGINE_H
#define SAFEOPS_FILTER_ENGINE_H

//=============================================================================
// SECTION 1: Include Dependencies
//=============================================================================

#include "driver.h" // Master driver header with global context

#ifdef SAFEOPS_WDK_BUILD
#include <fwpmk.h>   // WFP Management kernel-mode APIs
#include <fwpsk.h>   // WFP callout kernel-mode APIs
#include <guiddef.h> // GUID generation and manipulation
#else
// IDE Mode - WFP type stubs for IntelliSense

// FWPS (Callout) types
typedef void *FWPS_INCOMING_VALUES0;
typedef void *FWPS_INCOMING_METADATA_VALUES0;
typedef void *FWPS_FILTER3;
typedef void *FWPS_CLASSIFY_OUT0;
typedef void (*FWPS_CALLOUT_CLASSIFY_FN3)(const void *, const void *, void *,
                                          const void *, const void *, UINT64,
                                          void *);
typedef LONG (*FWPS_CALLOUT_NOTIFY_FN3)(ULONG, const GUID *, const void *);
typedef void (*FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(USHORT, UINT32, UINT64);
typedef unsigned long FWPS_CALLOUT_NOTIFY_TYPE;
typedef GUID *PGUID;
typedef ULONG64 *PULONG64;
typedef LIST_ENTRY *PLIST_ENTRY;

// FWPM (Management) types - structures used by FilterEngineInitialize
typedef struct _FWPM_SESSION0 {
  ULONG flags;
  ULONG reserved;
} FWPM_SESSION0;

typedef struct _FWPS_CALLOUT3 {
  GUID calloutKey;
  FWPS_CALLOUT_CLASSIFY_FN3 classifyFn;
  FWPS_CALLOUT_NOTIFY_FN3 notifyFn;
  FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn;
} FWPS_CALLOUT3;

typedef struct _FWPM_CALLOUT0 {
  GUID calloutKey;
  GUID applicableLayer;
} FWPM_CALLOUT0;

typedef struct _FWPM_FILTER0 {
  GUID layerKey;
  struct {
    UCHAR type;
    ULONG64 uint8;
  } weight;
  ULONG numFilterConditions;
  void *filterCondition;
  struct {
    ULONG type;
    GUID calloutKey;
  } action;
} FWPM_FILTER0;

typedef struct _FWPM_FILTER_CONDITION0 {
  ULONG fieldKey;
  ULONG matchType;
} FWPM_FILTER_CONDITION0;

// WFP constants
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#define RPC_C_AUTHN_WINNT 10
#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFF
#define FWP_ACTION_CALLOUT_TERMINATING 0x00000003
#define UNSPECIFIED_COMPARTMENT_ID 0
#define AF_INET 2
#define FWP_UINT8 0
#define FWP_ACTION_PERMIT 0x1001

// CONTAINING_RECORD macro for IDE
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field)                                \
  ((type *)((char *)(address) - (unsigned long long)(&((type *)0)->field)))
#endif

// LIST_ENTRY functions for IDE
static inline void InitializeListHead(PLIST_ENTRY h) {
  h->Flink = h->Blink = h;
}
static inline void InsertTailList(PLIST_ENTRY h, PLIST_ENTRY e) {
  e->Blink = h->Blink;
  e->Flink = h;
  ((PLIST_ENTRY)h->Blink)->Flink = e;
  h->Blink = e;
}
static inline BOOLEAN IsListEmpty(PLIST_ENTRY h) { return h->Flink == h; }
static inline PLIST_ENTRY RemoveHeadList(PLIST_ENTRY h) {
  PLIST_ENTRY e = (PLIST_ENTRY)h->Flink;
  ((PLIST_ENTRY)e->Flink)->Blink = h;
  h->Flink = e->Flink;
  return e;
}
static inline void RemoveEntryList(PLIST_ENTRY e) {
  ((PLIST_ENTRY)e->Blink)->Flink = e->Flink;
  ((PLIST_ENTRY)e->Flink)->Blink = e->Blink;
}

// WFP functions (stubs for IDE)
static inline NTSTATUS FwpmEngineOpen0(void *a, ULONG b, void *c, void *d,
                                       void **e) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}
static inline NTSTATUS FwpmEngineClose0(void *a) {
  (void)a;
  return 0;
}
static inline NTSTATUS FwpsCalloutRegister3(void *a, void *b, UINT32 *c) {
  (void)a;
  (void)b;
  (void)c;
  return 0;
}
static inline NTSTATUS FwpsCalloutUnregisterById0(UINT32 a) {
  (void)a;
  return 0;
}
static inline NTSTATUS FwpmCalloutAdd0(void *a, void *b, void *c, UINT32 *d) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  return 0;
}
static inline NTSTATUS FwpmFilterAdd0(void *a, void *b, void *c, UINT64 *d) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  return 0;
}
static inline NTSTATUS FwpmFilterDeleteById0(void *a, UINT64 b) {
  (void)a;
  (void)b;
  return 0;
}
static inline NTSTATUS FwpsInjectTransportSendAsync0(void *a, void *b, UINT64 c,
                                                     ULONG d, void *e, USHORT f,
                                                     ULONG g, void *h, void *i,
                                                     void *j) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  (void)g;
  (void)h;
  (void)i;
  (void)j;
  return 0;
}
static inline NTSTATUS FwpsInjectNetworkSendAsync0(void *a, void *b, ULONG c,
                                                   ULONG d, void *e, void *f,
                                                   void *g) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  (void)g;
  return 0;
}
static inline NTSTATUS
FwpsInjectTransportReceiveAsync0(void *a, void *b, void *c, ULONG d, USHORT e,
                                 ULONG f, ULONG g, ULONG h, void *i, void *j,
                                 void *k) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  (void)g;
  (void)h;
  (void)i;
  (void)j;
  (void)k;
  return 0;
}
static inline NTSTATUS FwpsInjectNetworkReceiveAsync0(void *a, void *b, ULONG c,
                                                      ULONG d, ULONG e, ULONG f,
                                                      void *g, void *h,
                                                      void *i) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  (void)g;
  (void)h;
  (void)i;
  return 0;
}
#endif

//=============================================================================
// SECTION 2: WFP Layer Constants
//=============================================================================

/**
 * WFP Filtering Layers - SafeOps registers callouts at 8 layers:
 *   - Network Layer (IP packets before/after reassembly)
 *   - Transport Layer (TCP/UDP after reassembly)
 *   - Both IPv4 and IPv6
 *   - Both Inbound and Outbound
 */

// Layer weights - higher runs first
#define SAFEOPS_SUBLAYER_WEIGHT 0xFFFF          // Highest priority sublayer
#define SAFEOPS_FILTER_WEIGHT_HIGH 0xFFFFFFFE   // High-priority rules
#define SAFEOPS_FILTER_WEIGHT_MEDIUM 0x80000000 // Medium-priority rules
#define SAFEOPS_FILTER_WEIGHT_LOW 0x00000001    // Low-priority rules

// Maximum limits
#define MAX_FIREWALL_RULES 65536       // Max rules in kernel table
#define MAX_CONNECTIONS_TRACKED 100000 // Max concurrent connections
#define MAX_NAT_MAPPINGS 10000         // Max NAT translations
#define CONNECTION_TIMEOUT_SECONDS 300 // 5 minute connection timeout
#define NAT_PORT_RANGE_START 49152     // Ephemeral port range start
#define NAT_PORT_RANGE_END 65535       // Ephemeral port range end

//=============================================================================
// SECTION 3: WFP Callout GUIDs (8 callouts for 8 layers)
//=============================================================================

// Inbound Network Layer (IPv4) - Pre-reassembly packets
// {A1B2C3D4-1111-1111-AAAA-111111111111}
DEFINE_GUID(SAFEOPS_CALLOUT_INBOUND_NETWORK_V4, 0xa1b2c3d4, 0x1111, 0x1111,
            0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11);

// Outbound Network Layer (IPv4) - Post-fragmentation
// {A1B2C3D4-2222-2222-BBBB-222222222222}
DEFINE_GUID(SAFEOPS_CALLOUT_OUTBOUND_NETWORK_V4, 0xa1b2c3d4, 0x2222, 0x2222,
            0xbb, 0xbb, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22);

// Inbound Network Layer (IPv6)
// {A1B2C3D4-3333-3333-CCCC-333333333333}
DEFINE_GUID(SAFEOPS_CALLOUT_INBOUND_NETWORK_V6, 0xa1b2c3d4, 0x3333, 0x3333,
            0xcc, 0xcc, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33);

// Outbound Network Layer (IPv6)
// {A1B2C3D4-4444-4444-DDDD-444444444444}
DEFINE_GUID(SAFEOPS_CALLOUT_OUTBOUND_NETWORK_V6, 0xa1b2c3d4, 0x4444, 0x4444,
            0xdd, 0xdd, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44);

// Inbound Transport Layer (IPv4) - Post-reassembly, TCP/UDP
// {A1B2C3D4-5555-5555-EEEE-555555555555}
DEFINE_GUID(SAFEOPS_CALLOUT_INBOUND_TRANSPORT_V4, 0xa1b2c3d4, 0x5555, 0x5555,
            0xee, 0xee, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55);

// Outbound Transport Layer (IPv4)
// {A1B2C3D4-6666-6666-FFFF-666666666666}
DEFINE_GUID(SAFEOPS_CALLOUT_OUTBOUND_TRANSPORT_V4, 0xa1b2c3d4, 0x6666, 0x6666,
            0xff, 0xff, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66);

// Inbound Transport Layer (IPv6)
// {A1B2C3D4-7777-7777-AAAA-777777777777}
DEFINE_GUID(SAFEOPS_CALLOUT_INBOUND_TRANSPORT_V6, 0xa1b2c3d4, 0x7777, 0x7777,
            0xaa, 0xaa, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77);

// Outbound Transport Layer (IPv6)
// {A1B2C3D4-8888-8888-BBBB-888888888888}
DEFINE_GUID(SAFEOPS_CALLOUT_OUTBOUND_TRANSPORT_V6, 0xa1b2c3d4, 0x8888, 0x8888,
            0xbb, 0xbb, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88);

// SafeOps Sublayer GUID
// {A1B2C3D4-9999-9999-CCCC-999999999999}
DEFINE_GUID(SAFEOPS_SUBLAYER_GUID, 0xa1b2c3d4, 0x9999, 0x9999, 0xcc, 0xcc, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99);

//=============================================================================
// SECTION 4: Filter Action Constants
//=============================================================================

/**
 * WFP_ACTION_TYPE
 *
 * Packet verdict actions returned by classification functions.
 */
typedef enum _WFP_ACTION_TYPE {
  WFP_ACTION_PERMIT = 0,        // Allow packet to continue
  WFP_ACTION_BLOCK = 1,         // Drop packet silently
  WFP_ACTION_BLOCK_AND_LOG = 2, // Drop packet and log event
  WFP_ACTION_CONTINUE = 3,      // Skip SafeOps, let other filters decide
  WFP_ACTION_DEFER = 4,         // Queue for userspace decision (async)
  WFP_ACTION_MODIFY = 5         // Modify packet and reinject (NAT)
} WFP_ACTION_TYPE;

/**
 * WFP_CONNECTION_STATE
 *
 * TCP connection state for stateful tracking.
 * Prefixed with WFP_ to avoid conflict with driver.h CONN_STATE enum.
 */
typedef enum _WFP_CONNECTION_STATE {
  WFP_CONN_NEW = 0,
  WFP_CONN_SYN_SENT = 1,
  WFP_CONN_SYN_RECEIVED = 2,
  WFP_CONN_ESTABLISHED = 3,
  WFP_CONN_FIN_WAIT_1 = 4,
  WFP_CONN_FIN_WAIT_2 = 5,
  WFP_CONN_CLOSE_WAIT = 6,
  WFP_CONN_CLOSING = 7,
  WFP_CONN_LAST_ACK = 8,
  WFP_CONN_TIME_WAIT = 9,
  WFP_CONN_CLOSED = 10
} WFP_CONNECTION_STATE;

//=============================================================================
// SECTION 5: Firewall Rule Structure (256 bytes)
//=============================================================================

/**
 * FIREWALL_RULE
 *
 * In-kernel representation of firewall rules. Fixed 256-byte size for
 * efficient array allocation and IOCTL transfer.
 *
 * Rules are stored priority-sorted and evaluated sequentially during
 * packet classification. Lower priority number = higher precedence.
 */
#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

typedef struct _FIREWALL_RULE {
  // Identity (16 bytes)
  ULONG64 RuleId; // 8 bytes - Unique rule ID
  ULONG Priority; // 4 bytes - 1-1000, lower = higher priority
  ULONG Action;   // 4 bytes - WFP_ACTION_TYPE

  // Direction and Protocol (8 bytes)
  ULONG Direction; // 4 bytes - 0=Inbound, 1=Outbound, 2=Both
  ULONG Protocol;  // 4 bytes - 6=TCP, 17=UDP, 0=Any

  // IPv4 Source (8 bytes)
  ULONG SourceIPv4;     // 4 bytes - Source IP (0 = any)
  ULONG SourceIPv4Mask; // 4 bytes - Netmask (0xFFFFFFFF = /32)

  // IPv4 Destination (8 bytes)
  ULONG DestIPv4;     // 4 bytes - Dest IP (0 = any)
  ULONG DestIPv4Mask; // 4 bytes - Netmask

  // IPv6 Source (20 bytes)
  UCHAR SourceIPv6[16];      // 16 bytes - Source IPv6 (0s = any)
  UCHAR SourceIPv6PrefixLen; // 1 byte - Prefix length (0-128)
  UCHAR Reserved1[3];        // 3 bytes - Padding

  // IPv6 Destination (20 bytes)
  UCHAR DestIPv6[16];      // 16 bytes - Dest IPv6
  UCHAR DestIPv6PrefixLen; // 1 byte - Prefix length
  UCHAR Reserved2[3];      // 3 bytes - Padding

  // Port Ranges (8 bytes)
  USHORT SourcePortStart; // 2 bytes - Source port range start
  USHORT SourcePortEnd;   // 2 bytes - Source port range end
  USHORT DestPortStart;   // 2 bytes - Dest port range start
  USHORT DestPortEnd;     // 2 bytes - Dest port range end

  // Scope (8 bytes)
  ULONG NICTag;    // 4 bytes - Apply to specific NIC (0=all)
  ULONG ProcessId; // 4 bytes - Apply to process (0=all)

  // Timing (24 bytes)
  ULONG64 ExpirationTime; // 8 bytes - When rule expires (0=never)
  ULONG64 CreatedTime;    // 8 bytes - When rule was created
  ULONG64 HitCount;       // 8 bytes - Match count (atomic)

  // Statistics (8 bytes)
  ULONG64 BytesProcessed; // 8 bytes - Total bytes matched

  // Flags (8 bytes)
  BOOLEAN IsEnabled;  // 1 byte - TRUE if active
  BOOLEAN LogMatches; // 1 byte - TRUE to log every match
  UCHAR Reserved3[6]; // 6 bytes - Padding

  // Rule Name (128 bytes)
  WCHAR RuleName[64]; // 128 bytes - Unicode name

  // Reserved (16 bytes)
  UCHAR Reserved4[16]; // 16 bytes - Future use

} FIREWALL_RULE, *PFIREWALL_RULE; // Total: 256 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
C_ASSERT(sizeof(FIREWALL_RULE) == 256);
#endif

//=============================================================================
// SECTION 6: Connection Tracking Entry (128 bytes)
//=============================================================================

/**
 * CONNECTION_TRACK_ENTRY
 *
 * Tracks stateful TCP/UDP connections for "allow established" semantics.
 */
#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

typedef struct _CONNECTION_TRACK_ENTRY {
  // 5-Tuple Key (16 bytes)
  ULONG SourceIPv4;      // 4 bytes
  ULONG DestIPv4;        // 4 bytes
  USHORT SourcePort;     // 2 bytes
  USHORT DestPort;       // 2 bytes
  UCHAR Protocol;        // 1 byte - TCP or UDP
  UCHAR ConnectionState; // 1 byte - CONNECTION_STATE
  USHORT Reserved1;      // 2 bytes

  // Timestamps (16 bytes)
  LARGE_INTEGER FirstSeen; // 8 bytes
  LARGE_INTEGER LastSeen;  // 8 bytes

  // Byte Counters (16 bytes)
  ULONG64 BytesInbound;  // 8 bytes
  ULONG64 BytesOutbound; // 8 bytes

  // Packet Counters (16 bytes)
  ULONG64 PacketsInbound;  // 8 bytes
  ULONG64 PacketsOutbound; // 8 bytes

  // Metadata (16 bytes)
  ULONG NICTag;          // 4 bytes
  ULONG ProcessId;       // 4 bytes
  ULONG64 RuleIdMatched; // 8 bytes - Rule that permitted

  // Reserved (48 bytes)
  UCHAR Reserved2[48]; // 48 bytes - Future use

} CONNECTION_TRACK_ENTRY, *PCONNECTION_TRACK_ENTRY; // Total: 128 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
C_ASSERT(sizeof(CONNECTION_TRACK_ENTRY) == 128);
#endif

//=============================================================================
// SECTION 7: NAT Translation Entry (64 bytes)
//=============================================================================

/**
 * NAT_TRANSLATION_ENTRY
 *
 * Tracks NAT translations for LAN/WiFi → WAN routing.
 * Sized to fit exactly in one CPU cache line.
 */
#ifdef SAFEOPS_WDK_BUILD
#pragma pack(push, 1)
#endif

typedef struct _NAT_TRANSLATION_ENTRY {
  // Original (Private) Address (8 bytes)
  ULONG OriginalSourceIP;    // 4 bytes
  USHORT OriginalSourcePort; // 2 bytes
  USHORT Reserved1;          // 2 bytes

  // Translated (Public) Address (8 bytes)
  ULONG TranslatedSourceIP;    // 4 bytes
  USHORT TranslatedSourcePort; // 2 bytes
  USHORT Reserved2;            // 2 bytes

  // Destination (8 bytes)
  ULONG DestIP;    // 4 bytes
  USHORT DestPort; // 2 bytes
  UCHAR Protocol;  // 1 byte
  UCHAR Reserved3; // 1 byte

  // Timestamps (16 bytes)
  LARGE_INTEGER CreatedTime;  // 8 bytes
  LARGE_INTEGER LastUsedTime; // 8 bytes

  // Metadata (8 bytes)
  ULONG NICTag;         // 4 bytes
  ULONG ReferenceCount; // 4 bytes

  // Reserved (16 bytes)
  UCHAR Reserved4[16]; // 16 bytes

} NAT_TRANSLATION_ENTRY, *PNAT_TRANSLATION_ENTRY; // Total: 64 bytes

#ifdef SAFEOPS_WDK_BUILD
#pragma pack(pop)
C_ASSERT(sizeof(NAT_TRANSLATION_ENTRY) == 64);
#endif

//=============================================================================
// SECTION 8: WFP Classification Context
//=============================================================================

/**
 * WFP_CLASSIFY_CONTEXT
 *
 * Consolidates all WFP classification parameters for cleaner function
 * signatures.
 */
typedef struct _WFP_CLASSIFY_CONTEXT {
  // WFP-provided data
  const FWPS_INCOMING_VALUES0 *IncomingValues;
  const FWPS_INCOMING_METADATA_VALUES0 *MetadataValues;
  VOID *LayerData;
  const FWPS_FILTER3 *Filter;
  FWPS_CLASSIFY_OUT0 *ClassifyOut;

  // Flow context
  ULONG64 FlowContext; // WFP flow handle
  ULONG LayerId;       // WFP layer ID

  // Packet info
  BOOLEAN IsInbound; // TRUE if inbound
  BOOLEAN IsIPv6;    // TRUE if IPv6
  UCHAR Protocol;    // IP protocol number
  UCHAR Reserved;    // Padding

} WFP_CLASSIFY_CONTEXT, *PWFP_CLASSIFY_CONTEXT;

//=============================================================================
// SECTION 9: WFP Callout Registration
//=============================================================================

/**
 * WFP_CALLOUT_REGISTRATION
 *
 * Encapsulates data needed to register one WFP callout.
 */
typedef struct _WFP_CALLOUT_REGISTRATION {
  GUID CalloutKey;       // 16 bytes - Unique callout GUID
  GUID LayerKey;         // 16 bytes - WFP layer GUID
  UINT32 CalloutId;      // 4 bytes - Runtime ID from FwpsCalloutRegister
  UINT32 Reserved1;      // 4 bytes - Padding
  UINT64 FilterId;       // 8 bytes - Runtime ID from FwpmFilterAdd
  BOOLEAN IsRegistered;  // 1 byte - TRUE if registered
  UCHAR Reserved2[7];    // 7 bytes - Padding
  WCHAR CalloutName[32]; // 64 bytes - Unicode name
} WFP_CALLOUT_REGISTRATION, *PWFP_CALLOUT_REGISTRATION;

//=============================================================================
// SECTION 10: Function Prototypes - WFP Initialization
//=============================================================================

/**
 * WFP subsystem lifecycle management.
 */

// Initialize WFP engine and register sublayer
NTSTATUS WfpInitialize(_In_ PDEVICE_OBJECT DeviceObject);

// Unregister all callouts and close engine handle
VOID WfpCleanup(VOID);

// Register one callout at a specific layer
NTSTATUS
WfpRegisterCallout(_In_ PGUID CalloutKey, _In_ PGUID LayerKey,
                   _In_ FWPS_CALLOUT_CLASSIFY_FN3 ClassifyFn,
                   _In_ FWPS_CALLOUT_NOTIFY_FN3 NotifyFn,
                   _In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFn,
                   _Out_ UINT32 *OutCalloutId);

// Unregister one callout
NTSTATUS WfpUnregisterCallout(_In_ UINT32 CalloutId);

// Add WFP filter that invokes callout
NTSTATUS WfpAddFilter(_In_ UINT32 CalloutId, _In_ PGUID LayerKey,
                      _Out_ UINT64 *OutFilterId);

// Remove WFP filter
NTSTATUS WfpRemoveFilter(_In_ UINT64 FilterId);

//=============================================================================
// SECTION 11: Function Prototypes - WFP Callout Handlers
//=============================================================================

/**
 * WFP callout callback functions.
 * ClassifyFn runs at DISPATCH_LEVEL and must not block.
 */

// Main classification function - called for each packet
VOID NTAPI ClassifyFn(_In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
                      _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
                      _Inout_opt_ VOID *layerData,
                      _In_opt_ const void *classifyContext,
                      _In_ const FWPS_FILTER3 *filter, _In_ UINT64 flowContext,
                      _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut);

// Called when filters are added/deleted
NTSTATUS NTAPI NotifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                        _In_ const GUID *filterKey,
                        _Inout_ const FWPS_FILTER3 *filter);

// Called when TCP/UDP flow is deleted
VOID NTAPI FlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId,
                        _In_ UINT64 flowContext);

//=============================================================================
// SECTION 12: Function Prototypes - Firewall Rule Management
//=============================================================================

/**
 * Manages in-kernel firewall rule table.
 */

// Add new rule to kernel table
NTSTATUS AddFirewallRule(_In_ PFIREWALL_RULE Rule);

// Remove rule by ID
NTSTATUS RemoveFirewallRule(_In_ ULONG64 RuleId);

// Update existing rule
NTSTATUS UpdateFirewallRule(_In_ ULONG64 RuleId, _In_ PFIREWALL_RULE NewRule);

// Remove all rules
NTSTATUS ClearAllFirewallRules(VOID);

// Lookup rule by ID
PFIREWALL_RULE FindFirewallRule(_In_ ULONG64 RuleId);

// Match packet against rules, return verdict
NTSTATUS EvaluateFirewallRules(_In_ PWFP_CLASSIFY_CONTEXT Context,
                               _Out_ PULONG OutAction,
                               _Out_ PULONG64 OutRuleId);

// Re-sort rules after priority changes
VOID SortFirewallRulesByPriority(VOID);

// Get current rule count
ULONG GetFirewallRuleCount(VOID);

//=============================================================================
// SECTION 13: Function Prototypes - Connection Tracking
//=============================================================================

/**
 * Stateful connection tracking for "allow established" semantics.
 */

// Create new connection entry
NTSTATUS CreateConnectionTrackEntry(_In_ PWFP_CLASSIFY_CONTEXT Context,
                                    _Out_ PCONNECTION_TRACK_ENTRY *OutEntry);

// Lookup existing connection
PCONNECTION_TRACK_ENTRY FindConnectionTrackEntry(_In_ ULONG SourceIP,
                                                 _In_ ULONG DestIP,
                                                 _In_ USHORT SourcePort,
                                                 _In_ USHORT DestPort,
                                                 _In_ UCHAR Protocol);

// Update connection statistics
NTSTATUS UpdateConnectionTrackEntry(_Inout_ PCONNECTION_TRACK_ENTRY Entry,
                                    _In_ PWFP_CLASSIFY_CONTEXT Context);

// Remove connection entry
VOID DeleteConnectionTrackEntry(_In_ PCONNECTION_TRACK_ENTRY Entry);

// Remove expired connections
VOID PurgeExpiredConnections(VOID);

// Get active connection count
ULONG GetConnectionCount(VOID);

// Check if TCP connection is established
BOOLEAN IsConnectionEstablished(_In_ PCONNECTION_TRACK_ENTRY Entry);

//=============================================================================
// SECTION 14: Function Prototypes - NAT Operations
//=============================================================================

/**
 * Network Address Translation for LAN/WiFi → WAN.
 */

// Create new NAT mapping
NTSTATUS CreateNATMapping(_In_ ULONG OriginalSourceIP,
                          _In_ USHORT OriginalSourcePort, _In_ ULONG DestIP,
                          _In_ USHORT DestPort, _In_ UCHAR Protocol,
                          _Out_ PNAT_TRANSLATION_ENTRY *OutEntry);

// Lookup NAT entry for return packet
PNAT_TRANSLATION_ENTRY FindNATMapping(_In_ ULONG TranslatedIP,
                                      _In_ USHORT TranslatedPort,
                                      _In_ UCHAR Protocol);

// Modify packet for NAT
NTSTATUS ApplyNATTranslation(_Inout_ PVOID PacketData, _In_ ULONG DataLength,
                             _In_ PNAT_TRANSLATION_ENTRY NatEntry);

// Restore original IP/port for inbound
NTSTATUS ReverseNATTranslation(_Inout_ PVOID PacketData, _In_ ULONG DataLength,
                               _In_ PNAT_TRANSLATION_ENTRY NatEntry);

// Remove NAT entry
VOID DeleteNATMapping(_In_ PNAT_TRANSLATION_ENTRY Entry);

// Allocate port for outbound NAT
USHORT AllocateNATPort(_In_ ULONG PublicIP);

// Return port to pool
VOID ReleaseNATPort(_In_ ULONG PublicIP, _In_ USHORT Port);

//=============================================================================
// SECTION 15: Function Prototypes - Packet Injection
//=============================================================================

/**
 * Inject modified or cloned packets back into network stack.
 */

// Inject packet as inbound
NTSTATUS InjectPacketInbound(_In_ PVOID PacketData, _In_ ULONG DataLength,
                             _In_ ULONG InterfaceIndex);

// Inject packet as outbound
NTSTATUS InjectPacketOutbound(_In_ PVOID PacketData, _In_ ULONG DataLength,
                              _In_ ULONG InterfaceIndex);

// Clone packet with modifications
NTSTATUS CloneAndInjectPacket(_In_ PWFP_CLASSIFY_CONTEXT Context,
                              _In_ PVOID ModifiedData,
                              _In_ ULONG ModifiedLength);

// Cleanup injection resources
VOID FreeInjectionContext(_In_ PVOID InjectionContext);

//=============================================================================
// SECTION 16: Debug Functions
//=============================================================================

#ifdef DBG

// Print firewall rule details
VOID DbgPrintFirewallRule(_In_ PFIREWALL_RULE Rule);

// Print connection entry
VOID DbgPrintConnectionEntry(_In_ PCONNECTION_TRACK_ENTRY Entry);

// Print NAT mapping
VOID DbgPrintNATEntry(_In_ PNAT_TRANSLATION_ENTRY Entry);

// Validate WFP engine state
NTSTATUS DbgVerifyWfpState(VOID);

#endif // DBG

#endif // SAFEOPS_FILTER_ENGINE_H
