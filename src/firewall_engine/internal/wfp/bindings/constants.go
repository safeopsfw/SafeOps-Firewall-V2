// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
// This package uses syscall.LazyDLL to dynamically load fwpuclnt.dll and call WFP functions.
//
// WFP is a Windows kernel-mode API that allows applications to interact with the network
// stack at various layers, enabling packet filtering, connection tracking, and more.
//
// This file contains all constants used by WFP including:
// - Layer GUIDs (where filters are applied)
// - Condition field GUIDs (what to match)
// - Action types (permit/block)
// - Match types (equal/range/prefix)
// - Data types (uint8/uint16/blob/etc)
// - Session and filter flags
package bindings

// ============================================================================
// GUID Type Definition
// ============================================================================

// GUID represents a Windows GUID (Globally Unique Identifier).
// Format: {Data1-Data2-Data3-Data4}
// Example: {C38D57D1-05A7-4C33-904F-7FBCEEE60E82}
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// GUIDFromComponents creates a GUID from its components.
func GUIDFromComponents(d1 uint32, d2, d3 uint16, d4 [8]byte) GUID {
	return GUID{Data1: d1, Data2: d2, Data3: d3, Data4: d4}
}

// ============================================================================
// WFP Layer GUIDs
// ============================================================================
// Layers define WHERE in the network stack filters are applied.
// Each layer has a specific purpose and provides different data to filters.

// FWPM_LAYER_INBOUND_IPPACKET_V4 - IPv4 inbound packets (after IP reassembly)
// Use for: Basic IP filtering on incoming traffic
var FWPM_LAYER_INBOUND_IPPACKET_V4 = GUIDFromComponents(
	0xC86FD1BF, 0x21CD, 0x497E,
	[8]byte{0xA0, 0xBB, 0x17, 0x42, 0x5C, 0x88, 0x5C, 0x58},
)

// FWPM_LAYER_INBOUND_IPPACKET_V6 - IPv6 inbound packets
var FWPM_LAYER_INBOUND_IPPACKET_V6 = GUIDFromComponents(
	0xF52032CB, 0x991C, 0x46E7,
	[8]byte{0x97, 0x1D, 0x26, 0x01, 0x45, 0x9A, 0x91, 0xCA},
)

// FWPM_LAYER_OUTBOUND_IPPACKET_V4 - IPv4 outbound packets (before fragmentation)
// Use for: Basic IP filtering on outgoing traffic
var FWPM_LAYER_OUTBOUND_IPPACKET_V4 = GUIDFromComponents(
	0x1E5C9FAE, 0x8A84, 0x4135,
	[8]byte{0xA3, 0x31, 0x95, 0x0B, 0x54, 0x22, 0x9E, 0xC1},
)

// FWPM_LAYER_OUTBOUND_IPPACKET_V6 - IPv6 outbound packets
var FWPM_LAYER_OUTBOUND_IPPACKET_V6 = GUIDFromComponents(
	0xA3B42C97, 0x9F04, 0x4672,
	[8]byte{0xB8, 0x7E, 0xCE, 0xE9, 0xC4, 0x83, 0x25, 0x7F},
)

// FWPM_LAYER_INBOUND_TRANSPORT_V4 - IPv4 transport layer (TCP/UDP headers available)
// Use for: Port-based filtering, transport protocol filtering
var FWPM_LAYER_INBOUND_TRANSPORT_V4 = GUIDFromComponents(
	0x5926DFC8, 0xE3CF, 0x4426,
	[8]byte{0xA2, 0x83, 0xDC, 0x39, 0x3F, 0x5D, 0x0F, 0x9D},
)

// FWPM_LAYER_INBOUND_TRANSPORT_V6 - IPv6 transport layer
var FWPM_LAYER_INBOUND_TRANSPORT_V6 = GUIDFromComponents(
	0x634A869F, 0xFC23, 0x4B90,
	[8]byte{0xB0, 0xC1, 0xBF, 0x62, 0x0A, 0x36, 0xAE, 0x6F},
)

// FWPM_LAYER_OUTBOUND_TRANSPORT_V4 - IPv4 outbound transport layer
var FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = GUIDFromComponents(
	0x09E61AEE, 0x5699, 0x4A73,
	[8]byte{0x92, 0x43, 0x75, 0x3E, 0xBD, 0x64, 0x01, 0xF9},
)

// FWPM_LAYER_OUTBOUND_TRANSPORT_V6 - IPv6 outbound transport layer
var FWPM_LAYER_OUTBOUND_TRANSPORT_V6 = GUIDFromComponents(
	0xE1735BDE, 0x013F, 0x4655,
	[8]byte{0xB3, 0x51, 0xA4, 0x9E, 0x15, 0x76, 0x2D, 0xF0},
)

// FWPM_LAYER_ALE_AUTH_CONNECT_V4 - Application Layer Enforcement: Outbound connections
// Use for: Application-aware filtering (per-process blocking)
// This layer provides process ID and application path
var FWPM_LAYER_ALE_AUTH_CONNECT_V4 = GUIDFromComponents(
	0xC38D57D1, 0x05A7, 0x4C33,
	[8]byte{0x90, 0x4F, 0x7F, 0xBC, 0xEE, 0xE6, 0x0E, 0x82},
)

// FWPM_LAYER_ALE_AUTH_CONNECT_V6 - ALE outbound connections IPv6
var FWPM_LAYER_ALE_AUTH_CONNECT_V6 = GUIDFromComponents(
	0x4A72393B, 0x319F, 0x44BC,
	[8]byte{0x84, 0xC3, 0xBA, 0x54, 0xDC, 0xB3, 0xB6, 0xB4},
)

// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 - ALE inbound connections (accept)
// Use for: Server-side application filtering
var FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = GUIDFromComponents(
	0xE1CD9FE7, 0xF4B5, 0x4273,
	[8]byte{0x96, 0xC0, 0x59, 0x2E, 0x48, 0x7B, 0x86, 0x50},
)

// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 - ALE inbound connections IPv6
var FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = GUIDFromComponents(
	0xA3B3AB6B, 0x3564, 0x488C,
	[8]byte{0x91, 0x17, 0xF3, 0x4E, 0x82, 0x14, 0x27, 0x63},
)

// FWPM_LAYER_ALE_AUTH_LISTEN_V4 - ALE listen (server binding to port)
// Use for: Prevent applications from listening on ports
var FWPM_LAYER_ALE_AUTH_LISTEN_V4 = GUIDFromComponents(
	0x88BB5EAD, 0x5B8A, 0x4C59,
	[8]byte{0x9B, 0x03, 0xD8, 0x5E, 0x93, 0x54, 0x7B, 0x62},
)

// FWPM_LAYER_ALE_AUTH_LISTEN_V6 - ALE listen IPv6
var FWPM_LAYER_ALE_AUTH_LISTEN_V6 = GUIDFromComponents(
	0x7AC9DE24, 0x17DD, 0x4814,
	[8]byte{0xB4, 0xBD, 0xA9, 0xFB, 0xC9, 0x5A, 0x32, 0x1B},
)

// FWPM_LAYER_STREAM_V4 - TCP stream data (payload inspection)
// Use for: Deep packet inspection (DPI), content filtering
var FWPM_LAYER_STREAM_V4 = GUIDFromComponents(
	0x3B89653C, 0xC170, 0x49E4,
	[8]byte{0xB1, 0xCD, 0xE0, 0xEE, 0xEE, 0xE1, 0x9A, 0x3E},
)

// FWPM_LAYER_STREAM_V6 - TCP stream data IPv6
var FWPM_LAYER_STREAM_V6 = GUIDFromComponents(
	0x47C9137A, 0x7EC4, 0x46B3,
	[8]byte{0xB6, 0xE4, 0x48, 0xE9, 0x26, 0xB1, 0xED, 0xA4},
)

// ============================================================================
// WFP Condition Field GUIDs
// ============================================================================
// Condition fields define WHAT data can be matched in a filter.

// FWPM_CONDITION_IP_LOCAL_ADDRESS - Local IP address
var FWPM_CONDITION_IP_LOCAL_ADDRESS = GUIDFromComponents(
	0xD9AC5D99, 0xF6D4, 0x4E5C,
	[8]byte{0x89, 0xB5, 0xD5, 0x32, 0xBC, 0x4A, 0x22, 0x93},
)

// FWPM_CONDITION_IP_REMOTE_ADDRESS - Remote IP address
var FWPM_CONDITION_IP_REMOTE_ADDRESS = GUIDFromComponents(
	0xB235AE9A, 0x1D64, 0x49B8,
	[8]byte{0xA4, 0x4C, 0x5F, 0xF3, 0xD9, 0x09, 0x50, 0x45},
)

// FWPM_CONDITION_IP_LOCAL_PORT - Local port number
var FWPM_CONDITION_IP_LOCAL_PORT = GUIDFromComponents(
	0x0C1BA1AF, 0x5765, 0x453F,
	[8]byte{0xAF, 0x22, 0xA8, 0xF7, 0x91, 0xAC, 0x77, 0x5B},
)

// FWPM_CONDITION_IP_REMOTE_PORT - Remote port number
var FWPM_CONDITION_IP_REMOTE_PORT = GUIDFromComponents(
	0xC35A604D, 0xD22B, 0x4E1A,
	[8]byte{0x91, 0xB4, 0x68, 0xF6, 0x74, 0xEE, 0x67, 0x4B},
)

// FWPM_CONDITION_IP_PROTOCOL - IP protocol (TCP=6, UDP=17, ICMP=1)
var FWPM_CONDITION_IP_PROTOCOL = GUIDFromComponents(
	0x3971EF2B, 0x623E, 0x4F9A,
	[8]byte{0x8C, 0xB1, 0x6E, 0x79, 0xB8, 0x06, 0xB9, 0xA7},
)

// FWPM_CONDITION_IP_LOCAL_INTERFACE - Local network interface
var FWPM_CONDITION_IP_LOCAL_INTERFACE = GUIDFromComponents(
	0x4CD62A49, 0x59C3, 0x4969,
	[8]byte{0xB7, 0xF3, 0xBD, 0xA5, 0xD3, 0x28, 0x27, 0xB8},
)

// FWPM_CONDITION_DIRECTION - Packet direction (inbound/outbound)
var FWPM_CONDITION_DIRECTION = GUIDFromComponents(
	0x8784C146, 0xCA97, 0x44D6,
	[8]byte{0x9F, 0xD1, 0x19, 0xFB, 0x18, 0x40, 0xCB, 0xF7},
)

// FWPM_CONDITION_FLAGS - Condition flags
var FWPM_CONDITION_FLAGS = GUIDFromComponents(
	0x632CE23B, 0x5167, 0x435C,
	[8]byte{0x86, 0xD7, 0xE9, 0x03, 0x68, 0x4A, 0xA8, 0x0C},
)

// FWPM_CONDITION_ALE_APP_ID - Application ID (full path to executable)
// Use for: Per-application filtering (block chrome.exe from facebook.com)
var FWPM_CONDITION_ALE_APP_ID = GUIDFromComponents(
	0xD78E1E87, 0x8644, 0x4EA5,
	[8]byte{0x94, 0x37, 0xD8, 0x09, 0xEC, 0xEF, 0xC9, 0x71},
)

// FWPM_CONDITION_ALE_USER_ID - User SID (Security Identifier)
// Use for: Per-user filtering
var FWPM_CONDITION_ALE_USER_ID = GUIDFromComponents(
	0xAF043A0A, 0xB34D, 0x4F86,
	[8]byte{0x97, 0x9C, 0xC9, 0x04, 0x71, 0x00, 0x5E, 0x1C},
)

// FWPM_CONDITION_ALE_REMOTE_USER_ID - Remote user SID
var FWPM_CONDITION_ALE_REMOTE_USER_ID = GUIDFromComponents(
	0xF63073B7, 0x0189, 0x4AB3,
	[8]byte{0x95, 0xA4, 0x68, 0x29, 0x42, 0x06, 0xF0, 0x24},
)

// FWPM_CONDITION_ALE_PACKAGE_ID - Windows Store app package ID
var FWPM_CONDITION_ALE_PACKAGE_ID = GUIDFromComponents(
	0x71BC78FA, 0xF17C, 0x4997,
	[8]byte{0xA6, 0x02, 0x6A, 0xBB, 0x26, 0x1F, 0x35, 0x1C},
)

// FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE - Unicast/Multicast/Broadcast
var FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE = GUIDFromComponents(
	0x1EC1B7C9, 0x4EEA, 0x4458,
	[8]byte{0x8A, 0x3C, 0xF0, 0x55, 0x0B, 0x4F, 0xBC, 0x78},
)

// FWPM_CONDITION_ICMP_TYPE - ICMP message type
var FWPM_CONDITION_ICMP_TYPE = GUIDFromComponents(
	0x68F32F1, 0x3F7E, 0x4F69,
	[8]byte{0x80, 0x5D, 0x83, 0x0C, 0xBC, 0xDC, 0x66, 0x0E},
)

// FWPM_CONDITION_ICMP_CODE - ICMP message code
var FWPM_CONDITION_ICMP_CODE = GUIDFromComponents(
	0x687A6FBF, 0x997A, 0x4254,
	[8]byte{0x99, 0x68, 0x91, 0x8A, 0xC8, 0x06, 0x9C, 0xBA},
)

// ============================================================================
// WFP Action Types
// ============================================================================

// FWP_ACTION_TYPE defines what happens when a filter matches.
type FWP_ACTION_TYPE uint32

const (
	// FWP_ACTION_BLOCK - Block the packet (silent drop)
	FWP_ACTION_BLOCK FWP_ACTION_TYPE = 0x00000001

	// FWP_ACTION_PERMIT - Allow the packet through
	FWP_ACTION_PERMIT FWP_ACTION_TYPE = 0x00000002

	// FWP_ACTION_CALLOUT_TERMINATING - Call a callout, then terminate (block or permit)
	FWP_ACTION_CALLOUT_TERMINATING FWP_ACTION_TYPE = 0x00000003

	// FWP_ACTION_CALLOUT_INSPECTION - Call a callout for inspection, continue processing
	FWP_ACTION_CALLOUT_INSPECTION FWP_ACTION_TYPE = 0x00000004

	// FWP_ACTION_CALLOUT_UNKNOWN - Callout with unknown action
	FWP_ACTION_CALLOUT_UNKNOWN FWP_ACTION_TYPE = 0x00000005

	// FWP_ACTION_CONTINUE - Continue to next filter (internal use)
	FWP_ACTION_CONTINUE FWP_ACTION_TYPE = 0x00000006

	// FWP_ACTION_NONE - No action (veto power)
	FWP_ACTION_NONE FWP_ACTION_TYPE = 0x00000007
)

// String returns the string representation of the action type.
func (a FWP_ACTION_TYPE) String() string {
	switch a {
	case FWP_ACTION_BLOCK:
		return "BLOCK"
	case FWP_ACTION_PERMIT:
		return "PERMIT"
	case FWP_ACTION_CALLOUT_TERMINATING:
		return "CALLOUT_TERMINATING"
	case FWP_ACTION_CALLOUT_INSPECTION:
		return "CALLOUT_INSPECTION"
	case FWP_ACTION_CALLOUT_UNKNOWN:
		return "CALLOUT_UNKNOWN"
	case FWP_ACTION_CONTINUE:
		return "CONTINUE"
	case FWP_ACTION_NONE:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// WFP Match Types
// ============================================================================

// FWP_MATCH_TYPE defines how a condition value is matched.
type FWP_MATCH_TYPE uint32

const (
	// FWP_MATCH_EQUAL - Exact match
	FWP_MATCH_EQUAL FWP_MATCH_TYPE = 0

	// FWP_MATCH_GREATER - Greater than
	FWP_MATCH_GREATER FWP_MATCH_TYPE = 1

	// FWP_MATCH_LESS - Less than
	FWP_MATCH_LESS FWP_MATCH_TYPE = 2

	// FWP_MATCH_GREATER_OR_EQUAL - Greater than or equal
	FWP_MATCH_GREATER_OR_EQUAL FWP_MATCH_TYPE = 3

	// FWP_MATCH_LESS_OR_EQUAL - Less than or equal
	FWP_MATCH_LESS_OR_EQUAL FWP_MATCH_TYPE = 4

	// FWP_MATCH_RANGE - Value within range (inclusive)
	FWP_MATCH_RANGE FWP_MATCH_TYPE = 5

	// FWP_MATCH_FLAGS_ALL_SET - All specified flags are set
	FWP_MATCH_FLAGS_ALL_SET FWP_MATCH_TYPE = 6

	// FWP_MATCH_FLAGS_ANY_SET - Any specified flag is set
	FWP_MATCH_FLAGS_ANY_SET FWP_MATCH_TYPE = 7

	// FWP_MATCH_FLAGS_NONE_SET - None of the specified flags are set
	FWP_MATCH_FLAGS_NONE_SET FWP_MATCH_TYPE = 8

	// FWP_MATCH_EQUAL_CASE_INSENSITIVE - Case-insensitive string match
	FWP_MATCH_EQUAL_CASE_INSENSITIVE FWP_MATCH_TYPE = 9

	// FWP_MATCH_NOT_EQUAL - Not equal
	FWP_MATCH_NOT_EQUAL FWP_MATCH_TYPE = 10

	// FWP_MATCH_PREFIX - Prefix match (for IP CIDR)
	FWP_MATCH_PREFIX FWP_MATCH_TYPE = 11

	// FWP_MATCH_NOT_PREFIX - Not prefix match
	FWP_MATCH_NOT_PREFIX FWP_MATCH_TYPE = 12
)

// String returns the string representation of the match type.
func (m FWP_MATCH_TYPE) String() string {
	switch m {
	case FWP_MATCH_EQUAL:
		return "EQUAL"
	case FWP_MATCH_GREATER:
		return "GREATER"
	case FWP_MATCH_LESS:
		return "LESS"
	case FWP_MATCH_GREATER_OR_EQUAL:
		return "GREATER_OR_EQUAL"
	case FWP_MATCH_LESS_OR_EQUAL:
		return "LESS_OR_EQUAL"
	case FWP_MATCH_RANGE:
		return "RANGE"
	case FWP_MATCH_FLAGS_ALL_SET:
		return "FLAGS_ALL_SET"
	case FWP_MATCH_FLAGS_ANY_SET:
		return "FLAGS_ANY_SET"
	case FWP_MATCH_FLAGS_NONE_SET:
		return "FLAGS_NONE_SET"
	case FWP_MATCH_EQUAL_CASE_INSENSITIVE:
		return "EQUAL_CASE_INSENSITIVE"
	case FWP_MATCH_NOT_EQUAL:
		return "NOT_EQUAL"
	case FWP_MATCH_PREFIX:
		return "PREFIX"
	case FWP_MATCH_NOT_PREFIX:
		return "NOT_PREFIX"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// WFP Data Types
// ============================================================================

// FWP_DATA_TYPE defines the type of data in a FWP_VALUE.
type FWP_DATA_TYPE uint32

const (
	FWP_EMPTY                    FWP_DATA_TYPE = 0
	FWP_UINT8                    FWP_DATA_TYPE = 1
	FWP_UINT16                   FWP_DATA_TYPE = 2
	FWP_UINT32                   FWP_DATA_TYPE = 3
	FWP_UINT64                   FWP_DATA_TYPE = 4
	FWP_INT8                     FWP_DATA_TYPE = 5
	FWP_INT16                    FWP_DATA_TYPE = 6
	FWP_INT32                    FWP_DATA_TYPE = 7
	FWP_INT64                    FWP_DATA_TYPE = 8
	FWP_FLOAT                    FWP_DATA_TYPE = 9
	FWP_DOUBLE                   FWP_DATA_TYPE = 10
	FWP_BYTE_ARRAY16_TYPE        FWP_DATA_TYPE = 11
	FWP_BYTE_BLOB_TYPE           FWP_DATA_TYPE = 12
	FWP_SID                      FWP_DATA_TYPE = 13
	FWP_SECURITY_DESCRIPTOR      FWP_DATA_TYPE = 14
	FWP_TOKEN_INFORMATION        FWP_DATA_TYPE = 15
	FWP_TOKEN_ACCESS_INFORMATION FWP_DATA_TYPE = 16
	FWP_UNICODE_STRING_TYPE      FWP_DATA_TYPE = 17
	FWP_BYTE_ARRAY6_TYPE         FWP_DATA_TYPE = 18
	FWP_SINGLE_DATA_TYPE_MAX     FWP_DATA_TYPE = 0xFF
	FWP_V4_ADDR_MASK             FWP_DATA_TYPE = FWP_SINGLE_DATA_TYPE_MAX + 1
	FWP_V6_ADDR_MASK             FWP_DATA_TYPE = FWP_SINGLE_DATA_TYPE_MAX + 2
	FWP_RANGE_TYPE               FWP_DATA_TYPE = FWP_SINGLE_DATA_TYPE_MAX + 3
)

// String returns the string representation of the data type.
func (d FWP_DATA_TYPE) String() string {
	switch d {
	case FWP_EMPTY:
		return "EMPTY"
	case FWP_UINT8:
		return "UINT8"
	case FWP_UINT16:
		return "UINT16"
	case FWP_UINT32:
		return "UINT32"
	case FWP_UINT64:
		return "UINT64"
	case FWP_INT8:
		return "INT8"
	case FWP_INT16:
		return "INT16"
	case FWP_INT32:
		return "INT32"
	case FWP_INT64:
		return "INT64"
	case FWP_FLOAT:
		return "FLOAT"
	case FWP_DOUBLE:
		return "DOUBLE"
	case FWP_BYTE_ARRAY16_TYPE:
		return "BYTE_ARRAY16"
	case FWP_BYTE_BLOB_TYPE:
		return "BYTE_BLOB"
	case FWP_SID:
		return "SID"
	case FWP_SECURITY_DESCRIPTOR:
		return "SECURITY_DESCRIPTOR"
	case FWP_TOKEN_INFORMATION:
		return "TOKEN_INFORMATION"
	case FWP_TOKEN_ACCESS_INFORMATION:
		return "TOKEN_ACCESS_INFORMATION"
	case FWP_UNICODE_STRING_TYPE:
		return "UNICODE_STRING"
	case FWP_BYTE_ARRAY6_TYPE:
		return "BYTE_ARRAY6"
	case FWP_V4_ADDR_MASK:
		return "V4_ADDR_MASK"
	case FWP_V6_ADDR_MASK:
		return "V6_ADDR_MASK"
	case FWP_RANGE_TYPE:
		return "RANGE"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// WFP Session Flags
// ============================================================================

// FWPM_SESSION_FLAG defines session behavior options.
type FWPM_SESSION_FLAG uint32

const (
	// FWPM_SESSION_FLAG_DYNAMIC - Filters are deleted when session closes
	// Default behavior: filters are automatically cleaned up
	FWPM_SESSION_FLAG_DYNAMIC FWPM_SESSION_FLAG = 0x00000001

	// FWPM_SESSION_FLAG_RESERVED - Reserved for system use
	FWPM_SESSION_FLAG_RESERVED FWPM_SESSION_FLAG = 0x10000000
)

// ============================================================================
// WFP Filter Flags
// ============================================================================

// FWPM_FILTER_FLAG defines filter behavior options.
type FWPM_FILTER_FLAG uint32

const (
	// FWPM_FILTER_FLAG_NONE - No special flags
	FWPM_FILTER_FLAG_NONE FWPM_FILTER_FLAG = 0x00000000

	// FWPM_FILTER_FLAG_PERSISTENT - Filter survives reboot
	// Stored in registry, active at boot time
	FWPM_FILTER_FLAG_PERSISTENT FWPM_FILTER_FLAG = 0x00000001

	// FWPM_FILTER_FLAG_BOOTTIME - Filter active during boot
	// Applied before non-boot filters
	FWPM_FILTER_FLAG_BOOTTIME FWPM_FILTER_FLAG = 0x00000002

	// FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT - Filter has provider context
	FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT FWPM_FILTER_FLAG = 0x00000004

	// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT - Clears FWPS_RIGHT_ACTION_WRITE
	FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT FWPM_FILTER_FLAG = 0x00000008

	// FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED - Permit if callout not registered
	FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED FWPM_FILTER_FLAG = 0x00000010

	// FWPM_FILTER_FLAG_DISABLED - Filter is disabled
	FWPM_FILTER_FLAG_DISABLED FWPM_FILTER_FLAG = 0x00000020

	// FWPM_FILTER_FLAG_INDEXED - Filter is indexed for faster lookup
	FWPM_FILTER_FLAG_INDEXED FWPM_FILTER_FLAG = 0x00000040
)

// ============================================================================
// WFP Provider Flags
// ============================================================================

// FWPM_PROVIDER_FLAG defines provider behavior options.
type FWPM_PROVIDER_FLAG uint32

const (
	// FWPM_PROVIDER_FLAG_PERSISTENT - Provider survives reboot
	FWPM_PROVIDER_FLAG_PERSISTENT FWPM_PROVIDER_FLAG = 0x00000001

	// FWPM_PROVIDER_FLAG_DISABLED - Provider is disabled
	FWPM_PROVIDER_FLAG_DISABLED FWPM_PROVIDER_FLAG = 0x00000010
)

// ============================================================================
// WFP Direction
// ============================================================================

// FWP_DIRECTION defines packet direction.
type FWP_DIRECTION uint32

const (
	// FWP_DIRECTION_OUTBOUND - Outgoing packets
	FWP_DIRECTION_OUTBOUND FWP_DIRECTION = 0

	// FWP_DIRECTION_INBOUND - Incoming packets
	FWP_DIRECTION_INBOUND FWP_DIRECTION = 1

	// FWP_DIRECTION_MAX - Maximum value (for validation)
	FWP_DIRECTION_MAX FWP_DIRECTION = 2
)

// ============================================================================
// WFP IP Protocol Numbers
// ============================================================================
// Standard IANA protocol numbers used in IP headers.

const (
	// IPPROTO_ICMP - Internet Control Message Protocol
	IPPROTO_ICMP uint8 = 1

	// IPPROTO_IGMP - Internet Group Management Protocol
	IPPROTO_IGMP uint8 = 2

	// IPPROTO_TCP - Transmission Control Protocol
	IPPROTO_TCP uint8 = 6

	// IPPROTO_UDP - User Datagram Protocol
	IPPROTO_UDP uint8 = 17

	// IPPROTO_GRE - Generic Routing Encapsulation
	IPPROTO_GRE uint8 = 47

	// IPPROTO_ESP - Encapsulating Security Payload
	IPPROTO_ESP uint8 = 50

	// IPPROTO_AH - Authentication Header
	IPPROTO_AH uint8 = 51

	// IPPROTO_ICMPV6 - ICMPv6
	IPPROTO_ICMPV6 uint8 = 58

	// IPPROTO_SCTP - Stream Control Transmission Protocol
	IPPROTO_SCTP uint8 = 132
)

// ============================================================================
// SafeOps Provider GUID
// ============================================================================
// Fixed GUID for SafeOps firewall provider registration.
// This GUID identifies all WFP filters as belonging to SafeOps.

// SAFEOPS_PROVIDER_GUID is the unique identifier for SafeOps firewall.
var SAFEOPS_PROVIDER_GUID = GUIDFromComponents(
	0x5AFE0B5F, 0x1234, 0x5678,
	[8]byte{0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78},
)

// SAFEOPS_PROVIDER_NAME is the display name for the SafeOps provider.
const SAFEOPS_PROVIDER_NAME = "SafeOps Firewall Engine"

// SAFEOPS_PROVIDER_DESCRIPTION is the description for the SafeOps provider.
const SAFEOPS_PROVIDER_DESCRIPTION = "Enterprise Network Security Platform - Windows WFP Integration"

// ============================================================================
// WFP Sublayer GUID
// ============================================================================
// Sublayers allow grouping filters for management and priority control.

// SAFEOPS_SUBLAYER_GUID is the sublayer for all SafeOps filters.
var SAFEOPS_SUBLAYER_GUID = GUIDFromComponents(
	0x5AFE50B1, 0x4321, 0x8765,
	[8]byte{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
)

// ============================================================================
// WFP Weight Constants
// ============================================================================
// Filter weights determine evaluation order (higher = first).

const (
	// WEIGHT_MAX - Highest priority (evaluated first)
	WEIGHT_MAX uint64 = 0xFFFFFFFFFFFFFFFF

	// WEIGHT_CRITICAL - Critical security filters
	WEIGHT_CRITICAL uint64 = 0xFFFFFFFFFFFFF000

	// WEIGHT_HIGH - High priority filters
	WEIGHT_HIGH uint64 = 0xFFFFFFFFFFFF0000

	// WEIGHT_MEDIUM - Medium priority filters
	WEIGHT_MEDIUM uint64 = 0xFFFFFFFF00000000

	// WEIGHT_LOW - Low priority filters
	WEIGHT_LOW uint64 = 0xFFFF000000000000

	// WEIGHT_MIN - Lowest priority (evaluated last)
	WEIGHT_MIN uint64 = 0x0000000000000000

	// WEIGHT_DEFAULT - Default weight for SafeOps filters
	WEIGHT_DEFAULT uint64 = WEIGHT_MEDIUM
)

// ============================================================================
// WFP Timeout Constants
// ============================================================================

const (
	// SESSION_TXN_WAIT_TIMEOUT_INFINITE - No timeout for transactions
	SESSION_TXN_WAIT_TIMEOUT_INFINITE uint32 = 0

	// SESSION_TXN_WAIT_TIMEOUT_DEFAULT - Default 10 second timeout
	SESSION_TXN_WAIT_TIMEOUT_DEFAULT uint32 = 10000

	// SESSION_TXN_WAIT_TIMEOUT_SHORT - Short 5 second timeout
	SESSION_TXN_WAIT_TIMEOUT_SHORT uint32 = 5000
)

// ============================================================================
// Empty/Nil GUID
// ============================================================================

// GUID_NULL is the empty/nil GUID (all zeros).
var GUID_NULL = GUID{}

// IsNull returns true if the GUID is the null/empty GUID.
func (g GUID) IsNull() bool {
	return g == GUID_NULL
}

// ============================================================================
// Layer Helper Functions
// ============================================================================

// GetLayerGUID returns the GUID for a layer based on IP version and direction.
func GetLayerGUID(ipv6 bool, outbound bool) GUID {
	if ipv6 {
		if outbound {
			return FWPM_LAYER_OUTBOUND_IPPACKET_V6
		}
		return FWPM_LAYER_INBOUND_IPPACKET_V6
	}
	if outbound {
		return FWPM_LAYER_OUTBOUND_IPPACKET_V4
	}
	return FWPM_LAYER_INBOUND_IPPACKET_V4
}

// GetALELayerGUID returns the ALE layer GUID for application-aware filtering.
func GetALELayerGUID(ipv6 bool, outbound bool) GUID {
	if ipv6 {
		if outbound {
			return FWPM_LAYER_ALE_AUTH_CONNECT_V6
		}
		return FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	}
	if outbound {
		return FWPM_LAYER_ALE_AUTH_CONNECT_V4
	}
	return FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
}

// GetTransportLayerGUID returns the transport layer GUID.
func GetTransportLayerGUID(ipv6 bool, outbound bool) GUID {
	if ipv6 {
		if outbound {
			return FWPM_LAYER_OUTBOUND_TRANSPORT_V6
		}
		return FWPM_LAYER_INBOUND_TRANSPORT_V6
	}
	if outbound {
		return FWPM_LAYER_OUTBOUND_TRANSPORT_V4
	}
	return FWPM_LAYER_INBOUND_TRANSPORT_V4
}
