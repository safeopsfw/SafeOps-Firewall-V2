/*
 * SafeOps Firewall v2.0 - Packet Structures Header
 *
 * Purpose: Defines comprehensive packet data structures representing captured
 *          network traffic from Layer 2 (Ethernet) through Layer 7
 * (Application), enabling zero-copy packet parsing in both kernel driver and
 * userspace service with consistent field interpretation.
 *
 * Author: SafeOps Development Team
 * Created: 2025-12-20
 *
 * CRITICAL: All structures are packed to match on-wire format exactly.
 *           Multi-byte fields are in network byte order (big-endian).
 *           Use ntohs()/ntohl() to convert to host byte order.
 *
 * Zero-Copy: Structures overlay directly on captured packet bytes,
 *            eliminating serialization overhead.
 */

#ifndef SAFEOPS_PACKET_STRUCTS_H
#define SAFEOPS_PACKET_STRUCTS_H

/*
 * =============================================================================
 * REQUIRED INCLUDES
 * =============================================================================
 */

#ifdef _KERNEL_MODE
/* Kernel mode: Use WDK headers */
#include <ntddk.h>
#include <wdf.h>
#else
/* User mode: Use Windows SDK headers */
/* IMPORTANT: winsock2.h MUST come before windows.h */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* Provides IN6_ADDR and other IPv6 types */

#endif

/* SafeOps internal headers */
#include "shared_constants.h"

/*
 * =============================================================================
 * STRUCTURE PACKING CONTROL
 * =============================================================================
 * Purpose: Ensure exact binary compatibility with on-wire packet formats.
 *          No compiler-inserted padding allowed.
 */

#pragma pack(push, 1)

/*
 * =============================================================================
 * ETHERNET LAYER STRUCTURES (LAYER 2)
 * =============================================================================
 */

/*
 * ETHERNET_HEADER
 *
 * Represents 802.3 Ethernet II frame header capturing MAC addresses
 * and payload type.
 *
 * Size: 14 bytes
 * Wire Format: Exact match to IEEE 802.3 standard
 *
 * Usage:
 * - Kernel driver casts first 14 bytes of captured packet to ETHERNET_HEADER*
 * - etherType determines next parsing step (IP, ARP, VLAN)
 */
typedef struct _ETHERNET_HEADER {
  /*
   * Destination MAC address (6 bytes)
   * Format: Byte array in network byte order (big-endian)
   * Example: {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}
   */
  UCHAR destinationMAC[6];

  /*
   * Source MAC address (6 bytes)
   * Format: Byte array in network byte order
   * Usage: MAC filtering rules use this field
   */
  UCHAR sourceMAC[6];

  /*
   * EtherType indicating payload protocol (2 bytes, network byte order)
   * Values:
   *   0x0800 - IPv4
   *   0x86DD - IPv6
   *   0x0806 - ARP
   *   0x8100 - VLAN tagged (802.1Q)
   * Usage: Determines how to parse following bytes
   * Conversion: Use ntohs() to convert to host order
   */
  USHORT etherType;

} ETHERNET_HEADER;

/*
 * VLAN_HEADER
 *
 * Represents 802.1Q VLAN tagging inserted between Ethernet and IP layers.
 *
 * Size: 4 bytes
 * Position: Between Ethernet header and IP header
 * Optional: Present only if ETHERNET_HEADER.etherType == 0x8100
 *
 * Usage:
 * - Firewall rules can filter by VLAN ID for network segmentation
 * - IDS/IPS uses VLAN to determine security policy
 */
typedef struct _VLAN_HEADER {
  /*
   * Tag Control Information (2 bytes, network byte order)
   * Bits 0-11: VLAN ID (0-4095)
   * Bits 12-14: Priority Code Point (PCP) for QoS
   * Bit 15: Drop Eligible Indicator (DEI)
   * Extraction: VLAN ID = (ntohs(tci) & 0x0FFF)
   */
  USHORT tci;

  /*
   * EtherType of encapsulated protocol (2 bytes)
   * Values: Same as ETHERNET_HEADER.etherType (0x0800 for IPv4)
   */
  USHORT etherType;

} VLAN_HEADER;

/*
 * =============================================================================
 * IP LAYER STRUCTURES (LAYER 3)
 * =============================================================================
 */

/*
 * IPV4_HEADER
 *
 * Represents IPv4 packet header (RFC 791) for Layer 3 routing and
 * fragmentation.
 *
 * Minimum Size: 20 bytes
 * Maximum Size: 60 bytes (with 40 bytes of options)
 * Wire Format: RFC 791 compliant
 */
typedef struct _IPV4_HEADER {
  /*
   * Combined version (4 bits) and header length (4 bits)
   * Version: Upper 4 bits, always 4 for IPv4
   * Header Length: Lower 4 bits, in 32-bit words (minimum 5 = 20 bytes)
   * Extraction: version = (vhl >> 4); headerLen = (vhl & 0x0F) * 4;
   */
  UCHAR versionAndHeaderLength;

  /*
   * Type of Service / DSCP / ECN (1 byte)
   * Bits 0-5: DSCP (Differentiated Services Code Point) for QoS
   * Bits 6-7: ECN (Explicit Congestion Notification)
   * Usage: QoS prioritization in firewall and traffic shaping
   */
  UCHAR typeOfService;

  /*
   * Total packet length including header and data (2 bytes, network byte order)
   * Range: 20 (header only) to 65,535 bytes
   * Conversion: totalLen = ntohs(header->totalLength)
   */
  USHORT totalLength;

  /*
   * Fragment identification (2 bytes, network byte order)
   * Purpose: Groups fragments belonging to same original packet
   * Usage: Stateful firewall reassembles fragments using this field
   */
  USHORT identification;

  /*
   * Fragmentation flags (3 bits) and offset (13 bits)
   * Bit 0: Reserved (must be 0)
   * Bit 1: Don't Fragment (DF) flag
   * Bit 2: More Fragments (MF) flag
   * Bits 3-15: Fragment offset in 8-byte units
   * Extraction: df = (value & 0x4000); mf = (value & 0x2000); offset = (value &
   * 0x1FFF) * 8;
   */
  USHORT flagsAndFragmentOffset;

  /*
   * TTL hop count (1 byte)
   * Purpose: Prevents routing loops; decremented at each router
   * Range: 0-255 (0 triggers ICMP Time Exceeded)
   */
  UCHAR timeToLive;

  /*
   * Next-layer protocol (1 byte)
   * Values: 1 (ICMP), 6 (TCP), 17 (UDP), 41 (IPv6-in-IPv4), 47 (GRE)
   * Usage: Determines how to parse data following IP header
   */
  UCHAR protocol;

  /*
   * IP header checksum (2 bytes, network byte order)
   * Purpose: Detects corruption in IP header
   */
  USHORT headerChecksum;

  /*
   * Source IP address (4 bytes, network byte order)
   * Format: 32-bit IPv4 address (e.g., 192.168.1.100)
   * Usage: Firewall rules, reputation lookups, connection tracking
   */
  ULONG sourceAddress;

  /*
   * Destination IP address (4 bytes, network byte order)
   * Format: 32-bit IPv4 address
   * Usage: Routing decisions, NAT translation, firewall rules
   */
  ULONG destinationAddress;

  /*
   * Options follow if headerLength > 5 (0-40 bytes)
   * Not included in fixed structure - access via offset calculation
   */

} IPV4_HEADER;

/*
 * IPV6_HEADER
 *
 * Represents IPv6 packet header (RFC 8200) for next-generation IP addressing.
 *
 * Size: Always 40 bytes (fixed, unlike IPv4)
 * Wire Format: RFC 8200 compliant
 */
typedef struct _IPV6_HEADER {
  /*
   * Combined fields (4 bytes, network byte order)
   * Bits 0-3: Version (always 6 for IPv6)
   * Bits 4-11: Traffic Class (similar to IPv4 TOS/DSCP)
   * Bits 12-31: Flow Label for QoS flow identification
   * Extraction: version = (value >> 28); trafficClass = (value >> 20) & 0xFF;
   */
  ULONG versionTrafficClassFlowLabel;

  /*
   * Length of data after IPv6 header (2 bytes, network byte order)
   * Range: 0-65,535 bytes
   * Note: Excludes IPv6 header itself (always 40 bytes)
   */
  USHORT payloadLength;

  /*
   * Next protocol (1 byte)
   * Values: Same as IPv4 protocol (6=TCP, 17=UDP, 58=ICMPv6)
   * Extension: 0=Hop-by-Hop, 43=Routing, 44=Fragment
   */
  UCHAR nextHeader;

  /*
   * Hop limit (1 byte, equivalent to IPv4 TTL)
   * Purpose: Prevents routing loops
   * Range: 0-255
   */
  UCHAR hopLimit;

  /*
   * Source IPv6 address (16 bytes)
   * Format: 128-bit IPv6 address
   */
  UCHAR sourceAddress[16];

  /*
   * Destination IPv6 address (16 bytes)
   * Format: 128-bit IPv6 address
   */
  UCHAR destinationAddress[16];

} IPV6_HEADER;

/*
 * =============================================================================
 * TRANSPORT LAYER STRUCTURES (LAYER 4)
 * =============================================================================
 */

/*
 * TCP_HEADER
 *
 * Represents TCP segment header (RFC 793) for reliable connection-oriented
 * transport.
 *
 * Minimum Size: 20 bytes
 * Maximum Size: 60 bytes (with 40 bytes of options)
 * Wire Format: RFC 793 compliant
 */
typedef struct _TCP_HEADER {
  /*
   * Source TCP port (2 bytes, network byte order)
   * Range: 0-65,535 (typically ephemeral ports 49152-65535)
   */
  USHORT sourcePort;

  /*
   * Destination TCP port (2 bytes, network byte order)
   * Examples: 80 (HTTP), 443 (HTTPS), 22 (SSH), 25 (SMTP)
   */
  USHORT destinationPort;

  /*
   * Sequence number (4 bytes, network byte order)
   * Purpose: Orders TCP segments; enables reliable delivery
   * Range: 0-4,294,967,295 (wraps around)
   */
  ULONG sequenceNumber;

  /*
   * Acknowledgment number (4 bytes, network byte order)
   * Purpose: Acknowledges received bytes
   * Validity: Only meaningful if ACK flag set
   */
  ULONG acknowledgmentNumber;

  /*
   * Data offset (4 bits) and reserved (4 bits)
   * Data Offset: Upper 4 bits, TCP header length in 32-bit words
   * Extraction: headerLen = (value >> 4) * 4;
   */
  UCHAR dataOffsetAndReserved;

  /*
   * TCP flags (8 bits)
   * Bit 0 (FIN): Finish connection
   * Bit 1 (SYN): Synchronize sequence numbers
   * Bit 2 (RST): Reset connection
   * Bit 3 (PSH): Push data immediately
   * Bit 4 (ACK): Acknowledgment field valid
   * Bit 5 (URG): Urgent pointer valid
   * Bits 6-7: ECN flags (ECE, CWR)
   */
  UCHAR flags;

  /*
   * Receive window size (2 bytes, network byte order)
   * Purpose: Flow control; advertises available buffer space
   * Range: 0-65,535 bytes (can be scaled with TCP options)
   */
  USHORT windowSize;

  /*
   * TCP checksum (2 bytes, network byte order)
   * Coverage: TCP header, payload, and pseudo-header
   */
  USHORT checksum;

  /*
   * Urgent data pointer (2 bytes, network byte order)
   * Validity: Only meaningful if URG flag set
   */
  USHORT urgentPointer;

  /*
   * Options follow if dataOffset > 5 (0-40 bytes)
   * Not included in fixed structure - access via offset calculation
   */

} TCP_HEADER;

/*
 * TCP_FLAGS - Bit definitions for TCP flags field
 */
#define TCP_FLAG_FIN 0x01 /* Finish - no more data from sender */
#define TCP_FLAG_SYN 0x02 /* Synchronize - establish connection */
#define TCP_FLAG_RST 0x04 /* Reset - abort connection */
#define TCP_FLAG_PSH 0x08 /* Push - send data immediately */
#define TCP_FLAG_ACK 0x10 /* Acknowledgment field valid */
#define TCP_FLAG_URG 0x20 /* Urgent pointer valid */
#define TCP_FLAG_ECE 0x40 /* ECN-Echo */
#define TCP_FLAG_CWR 0x80 /* Congestion Window Reduced */

/*
 * UDP_HEADER
 *
 * Represents UDP datagram header (RFC 768) for connectionless transport.
 *
 * Size: Always 8 bytes (fixed)
 * Wire Format: RFC 768 compliant
 */
typedef struct _UDP_HEADER {
  /*
   * Source UDP port (2 bytes, network byte order)
   * Range: 0-65,535
   */
  USHORT sourcePort;

  /*
   * Destination UDP port (2 bytes, network byte order)
   * Examples: 53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP)
   */
  USHORT destinationPort;

  /*
   * UDP datagram length (2 bytes, network byte order)
   * Includes: UDP header (8 bytes) + payload
   * Range: 8-65,535 bytes
   */
  USHORT length;

  /*
   * UDP checksum (2 bytes, network byte order)
   * Optional: May be 0 for IPv4 (not validated); mandatory for IPv6
   */
  USHORT checksum;

} UDP_HEADER;

/*
 * ICMP_HEADER
 *
 * Represents ICMP message header (RFC 792) for network diagnostics
 * and error reporting.
 *
 * Size: 8 bytes + variable data
 * Wire Format: RFC 792 compliant
 */
typedef struct _ICMP_HEADER {
  /*
   * ICMP message type (1 byte)
   * Examples:
   *   0: Echo Reply (ping response)
   *   3: Destination Unreachable
   *   5: Redirect
   *   8: Echo Request (ping)
   *   11: Time Exceeded
   */
  UCHAR type;

  /*
   * ICMP subtype code (1 byte)
   * Purpose: Provides additional context for type
   * Example: Type 3 has codes: 0=Net, 1=Host, 2=Protocol, 3=Port
   */
  UCHAR code;

  /*
   * ICMP checksum (2 bytes, network byte order)
   * Coverage: ICMP header and data
   */
  USHORT checksum;

  /*
   * Type-specific data (4 bytes)
   * Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
   * Destination Unreachable: Unused (must be 0)
   * Redirect: Gateway IP address
   */
  ULONG restOfHeader;

} ICMP_HEADER;

/*
 * ICMP Type Constants
 */
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

/*
 * ICMPV6_HEADER
 *
 * Represents ICMPv6 message header (RFC 4443) for IPv6 diagnostics
 * and Neighbor Discovery.
 *
 * Size: 8 bytes + variable data
 * Wire Format: RFC 4443 compliant
 */
typedef struct _ICMPV6_HEADER {
  /*
   * ICMPv6 message type (1 byte)
   * Examples:
   *   1: Destination Unreachable
   *   128: Echo Request
   *   129: Echo Reply
   *   133: Router Solicitation
   *   134: Router Advertisement
   *   135: Neighbor Solicitation
   *   136: Neighbor Advertisement
   */
  UCHAR type;

  /*
   * ICMPv6 subtype code (1 byte)
   */
  UCHAR code;

  /*
   * ICMPv6 checksum (2 bytes, network byte order, mandatory)
   */
  USHORT checksum;

  /*
   * Type-specific data (4 bytes)
   */
  ULONG messageBody;

} ICMPV6_HEADER;

/*
 * ICMPv6 Type Constants
 */
#define ICMPV6_TYPE_DEST_UNREACHABLE 1
#define ICMPV6_TYPE_ECHO_REQUEST 128
#define ICMPV6_TYPE_ECHO_REPLY 129
#define ICMPV6_TYPE_ROUTER_SOLICIT 133
#define ICMPV6_TYPE_ROUTER_ADVERT 134
#define ICMPV6_TYPE_NEIGHBOR_SOLICIT 135
#define ICMPV6_TYPE_NEIGHBOR_ADVERT 136

/*
 * =============================================================================
 * SAFEOPS UNIFIED PACKET STRUCTURE
 * =============================================================================
 * Purpose: Top-level structure combining all protocol layers with
 * SafeOps-specific metadata for comprehensive packet representation.
 */

/*
 * Packet direction constants
 */
#define PACKET_DIR_INBOUND 0  /* Ingress - received from network */
#define PACKET_DIR_OUTBOUND 1 /* Egress - sent to network */

/*
 * Capture point constants
 */
#define CAPTURE_POINT_PRE_ROUTING 0  /* Raw packet from NIC */
#define CAPTURE_POINT_POST_ROUTING 1 /* After firewall processing */
#define CAPTURE_POINT_PRE_NAT 2      /* Before NAT translation */
#define CAPTURE_POINT_POST_NAT 3     /* After NAT translation */

/*
 * Firewall action constants
 */
#define PACKET_ACTION_ALLOWED 0      /* Passed through firewall */
#define PACKET_ACTION_BLOCKED 1      /* Dropped by firewall */
#define PACKET_ACTION_LOGGED 2       /* Pass-through with logging */
#define PACKET_ACTION_RATE_LIMITED 3 /* Rate limited */

/*
 * Packet flags bit definitions
 */
#define PACKET_FLAG_TRUNCATED 0x01    /* Packet was truncated */
#define PACKET_FLAG_CHECKSUM_BAD 0x02 /* Checksum invalid */
#define PACKET_FLAG_FRAGMENTED 0x04   /* IP fragmented packet */
#define PACKET_FLAG_ENCRYPTED 0x08    /* ESP/AH detected */
#define PACKET_FLAG_TUNNELED 0x10     /* IP-in-IP, GRE, etc. */

/*
 * SAFEOPS_PACKET
 *
 * Unified packet structure containing:
 * - SafeOps metadata (signature, timestamp, NIC tag, action)
 * - Pre-parsed protocol header pointers
 * - Raw packet data for deep inspection
 *
 * Total Size: ~80 bytes metadata + MAX_PACKET_SIZE data
 */
typedef struct _SAFEOPS_PACKET {
  /*
   * ==========================================================================
   * VALIDATION FIELDS
   * ==========================================================================
   */

  /*
   * Magic number for validation (0x504B5420 = "PKT ")
   * Purpose: Detects memory corruption
   * Must be first field checked before accessing other fields
   */
  ULONG signature;

  /*
   * Structure version (STRUCT_VERSION_V1 = 0x0001)
   * Purpose: Enables structure evolution
   */
  ULONG version;

  /*
   * ==========================================================================
   * CAPTURE METADATA
   * ==========================================================================
   */

  /*
   * Capture timestamp (Windows file time, 100ns precision)
   * Source: KeQuerySystemTime() in kernel driver
   * Usage: IDS correlation, forensics, log timestamps
   */
  ULONG64 timestamp;

  /*
   * Windows interface index where captured
   * Usage: Maps to interface name via GetAdaptersAddresses()
   */
  ULONG interfaceIndex;

  /*
   * Interface classification (NIC_TAG_WAN, NIC_TAG_LAN, etc.)
   * Purpose: Fast policy lookup without string comparisons
   */
  UCHAR nicTag;

  /*
   * Traffic direction
   * 0: Inbound (ingress)
   * 1: Outbound (egress)
   */
  UCHAR direction;

  /*
   * Capture point in network stack
   * 0: Pre-routing, 1: Post-routing, 2: Pre-NAT, 3: Post-NAT
   */
  UCHAR capturePoint;

  /*
   * Firewall action taken
   * 0: Allowed, 1: Blocked, 2: Logged, 3: Rate-limited
   */
  UCHAR action;

  /*
   * ==========================================================================
   * PACKET SIZE INFORMATION
   * ==========================================================================
   */

  /*
   * Original packet length before truncation
   * If originalLength > capturedLength, packet was truncated
   */
  USHORT originalLength;

  /*
   * Actual bytes captured in data field
   * Range: 0 to MAX_PACKET_SIZE (16KB)
   */
  USHORT capturedLength;

  /*
   * ==========================================================================
   * CACHED PROTOCOL FIELDS
   * ==========================================================================
   * Purpose: Fast access without re-parsing raw packet data
   */

  /*
   * Ethernet protocol type (cached from Ethernet header)
   * Values: 0x0800 (IPv4), 0x86DD (IPv6)
   */
  USHORT etherType;

  /*
   * IP version (4 or 6, or 0 if not IP)
   */
  UCHAR ipVersion;

  /*
   * Transport protocol (cached from IP header)
   * Values: IPPROTO_TCP (6), IPPROTO_UDP (17), IPPROTO_ICMP (1)
   */
  UCHAR protocol;

  /*
   * VLAN ID (0 if no VLAN tag)
   * Range: 0-4095
   */
  USHORT vlanId;

  /*
   * Source port (cached, 0 for non-TCP/UDP)
   */
  USHORT sourcePort;

  /*
   * Destination port (cached, 0 for non-TCP/UDP)
   */
  USHORT destinationPort;

  /*
   * ==========================================================================
   * FIREWALL TRACKING
   * ==========================================================================
   */

  /*
   * Firewall rule ID that matched this packet (0 if none)
   * Purpose: Forensics; understanding which rule allowed/blocked packet
   */
  ULONG ruleId;

  /*
   * Connection tracking ID (0 for stateless)
   * Purpose: Associates packet with connection state entry
   */
  ULONG connectionId;

  /*
   * ==========================================================================
   * FLAGS AND RESERVED
   * ==========================================================================
   */

  /*
   * Additional flags
   * Bit 0: Packet truncated
   * Bit 1: Checksum invalid
   * Bit 2: Fragmented
   * Bit 3: Encrypted (ESP/AH)
   * Bit 4: Tunneled (IP-in-IP, GRE)
   */
  UCHAR flags;

  /*
   * Reserved for future use (zero-filled)
   */
  UCHAR reserved[3];

  /*
   * ==========================================================================
   * PROTOCOL HEADER OFFSETS
   * ==========================================================================
   * Purpose: Offsets into data[] for quick header access
   */

  /*
   * Offset to Ethernet header in data[] (always 0)
   */
  USHORT ethernetOffset;

  /*
   * Offset to IP header in data[] (typically 14, or 18 with VLAN)
   */
  USHORT ipOffset;

  /*
   * Offset to transport header (TCP/UDP/ICMP) in data[]
   */
  USHORT transportOffset;

  /*
   * Offset to application payload in data[]
   */
  USHORT payloadOffset;

  /*
   * Length of application payload
   */
  USHORT payloadLength;

  /*
   * Reserved for alignment
   */
  USHORT reservedOffset;

  /*
   * ==========================================================================
   * RAW PACKET DATA
   * ==========================================================================
   * Contains raw packet bytes starting from Ethernet header.
   * Layout: Ethernet | [VLAN] | IP | TCP/UDP/ICMP | Payload
   *
   * Use offsets above to access protocol headers:
   *   ETHERNET_HEADER* eth = (ETHERNET_HEADER*)(packet->data +
   * packet->ethernetOffset); IPV4_HEADER* ip = (IPV4_HEADER*)(packet->data +
   * packet->ipOffset); TCP_HEADER* tcp = (TCP_HEADER*)(packet->data +
   * packet->transportOffset);
   */
  UCHAR data[MAX_PACKET_SIZE];

} SAFEOPS_PACKET;

/*
 * =============================================================================
 * RESTORE STRUCTURE PACKING
 * =============================================================================
 */

#pragma pack(pop)

/*
 * =============================================================================
 * HELPER MACROS
 * =============================================================================
 */

/*
 * Get Ethernet header from packet
 */
#define PACKET_GET_ETHERNET(pkt)                                               \
  ((ETHERNET_HEADER *)((pkt)->data + (pkt)->ethernetOffset))

/*
 * Get IPv4 header from packet (check ipVersion == 4 first)
 */
#define PACKET_GET_IPV4(pkt) ((IPV4_HEADER *)((pkt)->data + (pkt)->ipOffset))

/*
 * Get IPv6 header from packet (check ipVersion == 6 first)
 */
#define PACKET_GET_IPV6(pkt) ((IPV6_HEADER *)((pkt)->data + (pkt)->ipOffset))

/*
 * Get TCP header from packet (check protocol == IPPROTO_TCP first)
 */
#define PACKET_GET_TCP(pkt)                                                    \
  ((TCP_HEADER *)((pkt)->data + (pkt)->transportOffset))

/*
 * Get UDP header from packet (check protocol == IPPROTO_UDP first)
 */
#define PACKET_GET_UDP(pkt)                                                    \
  ((UDP_HEADER *)((pkt)->data + (pkt)->transportOffset))

/*
 * Get ICMP header from packet (check protocol == IPPROTO_ICMP first)
 */
#define PACKET_GET_ICMP(pkt)                                                   \
  ((ICMP_HEADER *)((pkt)->data + (pkt)->transportOffset))

/*
 * Get ICMPv6 header from packet (check protocol == IPPROTO_ICMPV6 first)
 */
#define PACKET_GET_ICMPV6(pkt)                                                 \
  ((ICMPV6_HEADER *)((pkt)->data + (pkt)->transportOffset))

/*
 * Get payload pointer from packet
 */
#define PACKET_GET_PAYLOAD(pkt) ((UCHAR *)((pkt)->data + (pkt)->payloadOffset))

/*
 * Check if packet is truncated
 */
#define PACKET_IS_TRUNCATED(pkt) ((pkt)->originalLength > (pkt)->capturedLength)

/*
 * Check if packet is fragmented
 */
#define PACKET_IS_FRAGMENTED(pkt) (((pkt)->flags & PACKET_FLAG_FRAGMENTED) != 0)

/*
 * Extract IPv4 header length in bytes
 */
#define IPV4_HEADER_LENGTH(hdr) (((hdr)->versionAndHeaderLength & 0x0F) * 4)

/*
 * Extract TCP header length in bytes
 */
#define TCP_HEADER_LENGTH(hdr) (((hdr)->dataOffsetAndReserved >> 4) * 4)

/*
 * Extract VLAN ID from TCI field (after ntohs conversion)
 */
#define VLAN_GET_ID(tci) ((tci) & 0x0FFF)

/*
 * Extract VLAN priority from TCI field (after ntohs conversion)
 */
#define VLAN_GET_PRIORITY(tci) (((tci) >> 13) & 0x07)

/*
 * =============================================================================
 * COMPILE-TIME ASSERTIONS
 * =============================================================================
 */

#ifdef _KERNEL_MODE
#define PACKET_STATIC_ASSERT(expr, msg) C_ASSERT(expr)
#elif defined(__cplusplus)
#define PACKET_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#elif defined(_MSC_VER)
#define PACKET_STATIC_ASSERT_JOIN(a, b) a##b
#define PACKET_STATIC_ASSERT_NAME(line)                                        \
  PACKET_STATIC_ASSERT_JOIN(pkt_static_assertion_, line)
#define PACKET_STATIC_ASSERT(expr, msg)                                        \
  typedef char PACKET_STATIC_ASSERT_NAME(__LINE__)[(expr) ? 1 : -1]
#else
#define PACKET_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#endif

/* Validate structure sizes match wire format */
PACKET_STATIC_ASSERT(sizeof(ETHERNET_HEADER) == 14,
                     "ETHERNET_HEADER must be 14 bytes");
PACKET_STATIC_ASSERT(sizeof(VLAN_HEADER) == 4, "VLAN_HEADER must be 4 bytes");
PACKET_STATIC_ASSERT(sizeof(IPV4_HEADER) == 20, "IPV4_HEADER must be 20 bytes");
PACKET_STATIC_ASSERT(sizeof(IPV6_HEADER) == 40, "IPV6_HEADER must be 40 bytes");
PACKET_STATIC_ASSERT(sizeof(TCP_HEADER) == 20, "TCP_HEADER must be 20 bytes");
PACKET_STATIC_ASSERT(sizeof(UDP_HEADER) == 8, "UDP_HEADER must be 8 bytes");
PACKET_STATIC_ASSERT(sizeof(ICMP_HEADER) == 8, "ICMP_HEADER must be 8 bytes");
PACKET_STATIC_ASSERT(sizeof(ICMPV6_HEADER) == 8,
                     "ICMPV6_HEADER must be 8 bytes");

/*
 * =============================================================================
 * END OF HEADER
 * =============================================================================
 */

#endif /* SAFEOPS_PACKET_STRUCTS_H */

/*
 * USAGE EXAMPLES:
 *
 * Parsing a captured packet:
 *
 *   SAFEOPS_PACKET* packet = (SAFEOPS_PACKET*)ringBufferEntry->data;
 *
 *   // Validate signature
 *   if (packet->signature != PACKET_ENTRY_SIGNATURE) {
 *       return ERROR_INVALID_DATA;
 *   }
 *
 *   // Get Ethernet header
 *   ETHERNET_HEADER* eth = PACKET_GET_ETHERNET(packet);
 *   USHORT etherType = ntohs(eth->etherType);
 *
 *   // Check for IPv4 + TCP
 *   if (packet->ipVersion == 4 && packet->protocol == IPPROTO_TCP) {
 *       IPV4_HEADER* ip = PACKET_GET_IPV4(packet);
 *       TCP_HEADER* tcp = PACKET_GET_TCP(packet);
 *
 *       ULONG srcIp = ntohl(ip->sourceAddress);
 *       USHORT srcPort = ntohs(tcp->sourcePort);
 *       USHORT dstPort = ntohs(tcp->destinationPort);
 *       UCHAR tcpFlags = tcp->flags;
 *
 *       // Check for SYN packet
 *       if (tcpFlags & TCP_FLAG_SYN) {
 *           // New connection attempt
 *       }
 *   }
 *
 * INTEGRATION NOTES:
 *
 * - All structures are packed (1-byte alignment) to match wire format
 * - Multi-byte fields are in network byte order (big-endian)
 * - Use ntohs()/ntohl() to convert to host byte order
 * - Use offset fields for reliable header access
 * - Validate packet->signature before accessing any other fields
 * - Check packet->capturedLength before accessing data[]
 */
