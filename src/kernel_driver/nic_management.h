/*******************************************************************************
 * FILE: src/kernel_driver/nic_management.h
 * 
 * SafeOps NIC Management - Header
 * 
 * PURPOSE:
 *   Manages 3-NIC setup (WAN, LAN, WiFi) with enumeration, role assignment,
 *   binding, hotplug detection, and statistics.
 * 
 * AUTHOR: SafeOps Team
 * VERSION: 2.0.0
 ******************************************************************************/

#ifndef _SAFEOPS_NIC_MANAGEMENT_H_
#define _SAFEOPS_NIC_MANAGEMENT_H_

#include <ntddk.h>
#include <ndis.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

#define MAX_NICS                    3
#define MAX_NIC_NAME_LENGTH         256
#define MAX_NIC_DESC_LENGTH         512
#define NIC_GUID_LENGTH             39

//=============================================================================
// NIC ROLES
//=============================================================================

typedef enum _NIC_ROLE {
    NIC_ROLE_UNKNOWN = 0,
    NIC_ROLE_WAN = 1,
    NIC_ROLE_LAN = 2,
    NIC_ROLE_WIFI = 3
} NIC_ROLE;

typedef enum _NIC_LINK_STATE {
    NIC_LINK_DOWN = 0,
    NIC_LINK_UP = 1,
    NIC_LINK_UNKNOWN = 2
} NIC_LINK_STATE;

typedef enum _NIC_DETECT_METHOD {
    NIC_DETECT_REGISTRY = 0,      // User configured
    NIC_DETECT_AUTO = 1,           // Auto-detected
    NIC_DETECT_DEFAULT = 2         // Fallback
} NIC_DETECT_METHOD;

//=============================================================================
// STRUCTURES
//=============================================================================

#pragma pack(push, 1)

// NIC hardware capabilities
typedef struct _NIC_CAPABILITIES {
    BOOLEAN rss_supported;
    BOOLEAN checksum_offload_supported;
    BOOLEAN tso_supported;
    BOOLEAN lso_supported;
    BOOLEAN vlan_supported;
    BOOLEAN jumbo_frames_supported;
    BOOLEAN wake_on_lan_supported;
    UINT32 max_rss_queues;
    UINT32 max_mtu;
} NIC_CAPABILITIES, *PNIC_CAPABILITIES;

// NIC statistics
typedef struct _NIC_STATISTICS {
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT64 bytes_sent;
    UINT64 bytes_received;
    UINT64 errors_tx;
    UINT64 errors_rx;
    UINT64 dropped_tx;
    UINT64 dropped_rx;
    UINT64 crc_errors;
    UINT64 collisions;
} NIC_STATISTICS, *PNIC_STATISTICS;

// NIC information
typedef struct _NIC_INFO {
    // Identification
    UINT8 nic_id;                           // 1, 2, or 3
    NIC_ROLE role;                          // WAN, LAN, WiFi
    NIC_DETECT_METHOD detect_method;
    
    // NDIS info
    NDIS_HANDLE filter_module_context;
    WCHAR friendly_name[MAX_NIC_NAME_LENGTH];
    WCHAR description[MAX_NIC_DESC_LENGTH];
    WCHAR guid[NIC_GUID_LENGTH];
    UINT8 mac_address[6];
    
    // Network config
    UINT32 ipv4_address;
    UINT32 subnet_mask;
    UINT32 gateway;
    BOOLEAN is_dhcp;
    BOOLEAN has_ipv6;
    
    // Link info
    NIC_LINK_STATE link_state;
    UINT32 link_speed_mbps;
    BOOLEAN full_duplex;
    
    // Capabilities
    NIC_CAPABILITIES capabilities;
    
    // Statistics
    NIC_STATISTICS stats;
    
    // State
    BOOLEAN bound;
    BOOLEAN enabled;
    UINT64 bind_time;
    
} NIC_INFO, *PNIC_INFO;

#pragma pack(pop)

//=============================================================================
// NIC MANAGEMENT CONTEXT
//=============================================================================

typedef struct _NIC_MANAGEMENT_CONTEXT {
    // NIC array
    NIC_INFO nics[MAX_NICS];
    UINT32 nic_count;
    
    // Configuration
    BOOLEAN auto_detect_enabled;
    WCHAR wan_guid[NIC_GUID_LENGTH];
    WCHAR lan_guid[NIC_GUID_LENGTH];
    WCHAR wifi_guid[NIC_GUID_LENGTH];
    
    // Hotplug
    PVOID pnp_notification_handle;
    KEVENT hotplug_event;
    
    // Synchronization
    KSPIN_LOCK nic_lock;
    
} NIC_MANAGEMENT_CONTEXT, *PNIC_MANAGEMENT_CONTEXT;

//=============================================================================
// FUNCTION PROTOTYPES
//=============================================================================

// Initialization
NTSTATUS NicManagementInitialize(_Out_ PNIC_MANAGEMENT_CONTEXT* Context);
VOID NicManagementCleanup(_In_ PNIC_MANAGEMENT_CONTEXT Context);

// NIC Enumeration
NTSTATUS EnumerateNetworkAdapters(_In_ PNIC_MANAGEMENT_CONTEXT Context);
BOOLEAN IsVirtualAdapter(_In_ PCWSTR Description);
BOOLEAN IsWirelessAdapter(_In_ PCWSTR Description);

// NIC Role Assignment
NTSTATUS AssignNicRoles(_In_ PNIC_MANAGEMENT_CONTEXT Context);
NTSTATUS AutoDetectNicRoles(_In_ PNIC_MANAGEMENT_CONTEXT Context);
NIC_ROLE DetermineNicRole(_In_ PNIC_INFO Nic);

// NDIS Filter Binding
NTSTATUS BindNdisFilters(_In_ PNIC_MANAGEMENT_CONTEXT Context);
NTSTATUS BindSingleNic(_Inout_ PNIC_INFO Nic);
VOID UnbindSingleNic(_Inout_ PNIC_INFO Nic);

// NIC Properties
NTSTATUS QueryNicProperties(_Inout_ PNIC_INFO Nic);
NTSTATUS QueryMacAddress(_In_ NDIS_HANDLE Handle, _Out_ PUCHAR MacAddress);
NTSTATUS QueryLinkSpeed(_In_ NDIS_HANDLE Handle, _Out_ PUINT32 SpeedMbps);
NTSTATUS QueryLinkState(_In_ NDIS_HANDLE Handle, _Out_ PNIC_LINK_STATE State);
NTSTATUS QueryHardwareCapabilities(_In_ NDIS_HANDLE Handle, _Out_ PNIC_CAPABILITIES Caps);

// NIC Statistics
VOID UpdateNicStatistics(_Inout_ PNIC_INFO Nic, _In_ BOOLEAN IsSend, _In_ UINT32 Bytes, _In_ BOOLEAN IsError);
NTSTATUS GetNicStatistics(_In_ PNIC_MANAGEMENT_CONTEXT Context, _In_ UINT8 NicId, _Out_ PNIC_STATISTICS Stats);
VOID ResetNicStatistics(_Inout_ PNIC_INFO Nic);

// Hotplug
NTSTATUS RegisterHotplugNotification(_In_ PNIC_MANAGEMENT_CONTEXT Context);
VOID UnregisterHotplugNotification(_In_ PNIC_MANAGEMENT_CONTEXT Context);
NTSTATUS NTAPI HotplugCallback(
    _In_ PVOID NotificationStructure,
    _Inout_opt_ PVOID Context
);

// Link State Monitoring
VOID MonitorLinkState(_In_ PNIC_MANAGEMENT_CONTEXT Context);
VOID HandleLinkStateChange(_Inout_ PNIC_INFO Nic, _In_ NIC_LINK_STATE NewState);

// IP Address Tracking
NTSTATUS QueryNicIpAddresses(_Inout_ PNIC_INFO Nic);
BOOLEAN IsPrivateIp(_In_ UINT32 IpAddress);

// Registry Configuration
NTSTATUS LoadNicConfigFromRegistry(_In_ PNIC_MANAGEMENT_CONTEXT Context);
NTSTATUS SaveNicConfigToRegistry(_In_ PNIC_MANAGEMENT_CONTEXT Context);

// NIC Lookup
PNIC_INFO GetNicByRole(_In_ PNIC_MANAGEMENT_CONTEXT Context, _In_ NIC_ROLE Role);
PNIC_INFO GetNicById(_In_ PNIC_MANAGEMENT_CONTEXT Context, _In_ UINT8 NicId);
PNIC_INFO GetNicByGuid(_In_ PNIC_MANAGEMENT_CONTEXT Context, _In_ PCWSTR Guid);

// Self-Check
NTSTATUS VerifyNicManagement(_In_ PNIC_MANAGEMENT_CONTEXT Context);

#endif // _SAFEOPS_NIC_MANAGEMENT_H_
