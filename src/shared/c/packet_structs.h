/*
 * packet_structs.h
 * Common packet structure definitions for network protocol headers
 *
 * Supports: Ethernet (with VLAN), IPv4, IPv6, TCP, UDP, ICMP/ICMPv6
 * All structures are packed for direct memory mapping
 */

#ifndef SAFEOPS_PACKET_STRUCTS_H
#define SAFEOPS_PACKET_STRUCTS_H

#include <stdint.h>

// Compiler compatibility
#ifdef _MSC_VER
#define PACKED_STRUCT
#pragma pack(push, 1)
#else
#define PACKED_STRUCT __attribute__((packed))
#endif

// ============================================================================
// ETHERNET LAYER
// ============================================================================

// Ethernet header (14 bytes)
typedef struct PACKED_STRUCT {
  uint8_t dst_mac[6]; // Destination MAC address
  uint8_t src_mac[6]; // Source MAC address
  uint16_t ethertype; // EtherType (e.g., 0x0800 for IPv4)
} eth_header_t;

// 802.1Q VLAN header (4 bytes)
typedef struct PACKED_STRUCT {
  uint16_t tci;       // Tag Control Information (PCP + DEI + VID)
  uint16_t ethertype; // EtherType of encapsulated frame
} vlan_header_t;

// Ethernet + VLAN header (18 bytes)
typedef struct PACKED_STRUCT {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t tpid; // Tag Protocol Identifier (0x8100 for 802.1Q)
  uint16_t tci;  // Tag Control Information
  uint16_t ethertype;
} eth_vlan_header_t;

// EtherType constants
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8

// VLAN TCI field extraction
#define VLAN_PCP(tci) (((tci) >> 13) & 0x07) // Priority Code Point (3 bits)
#define VLAN_DEI(tci) (((tci) >> 12) & 0x01) // Drop Eligible Indicator (1 bit)
#define VLAN_VID(tci) ((tci) & 0x0FFF)       // VLAN Identifier (12 bits)

// ============================================================================
// IPv4 LAYER
// ============================================================================

// IPv4 header (20-60 bytes)
typedef struct PACKED_STRUCT {
  uint8_t version_ihl;     // Version (4 bits) + IHL (4 bits)
  uint8_t tos;             // Type of Service / DSCP + ECN
  uint16_t total_length;   // Total length including header and data
  uint16_t identification; // Identification for fragmentation
  uint16_t flags_offset;   // Flags (3 bits) + Fragment Offset (13 bits)
  uint8_t ttl;             // Time To Live
  uint8_t protocol;        // Protocol (TCP=6, UDP=17, ICMP=1)
  uint16_t checksum;       // Header checksum
  uint32_t src_ip;         // Source IP address
  uint32_t dst_ip;         // Destination IP address
} ipv4_header_t;

// IPv4 header field extraction
#define IPV4_VERSION(vh) (((vh) >> 4) & 0x0F)
#define IPV4_IHL(vh) ((vh) & 0x0F)
#define IPV4_HEADER_LEN(vh) (IPV4_IHL(vh) * 4)
#define IPV4_FLAGS(fo) (((fo) >> 13) & 0x07)
#define IPV4_OFFSET(fo) ((fo) & 0x1FFF)

// IPv4 flags
#define IPV4_FLAG_RESERVED 0x4
#define IPV4_FLAG_DF 0x2 // Don't Fragment
#define IPV4_FLAG_MF 0x1 // More Fragments

// IPv4 protocols
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

// ============================================================================
// IPv6 LAYER
// ============================================================================

// IPv6 header (40 bytes)
typedef struct PACKED_STRUCT {
  uint32_t version_tc_fl;  // Version (4) + Traffic Class (8) + Flow Label (20)
  uint16_t payload_length; // Payload length (excluding header)
  uint8_t next_header;     // Next header (same as IPv4 protocol)
  uint8_t hop_limit;       // Hop limit (same as IPv4 TTL)
  uint8_t src_ip[16];      // Source IPv6 address
  uint8_t dst_ip[16];      // Destination IPv6 address
} ipv6_header_t;

// IPv6 header field extraction
#define IPV6_VERSION(vtf) (((vtf) >> 28) & 0x0F)
#define IPV6_TC(vtf) (((vtf) >> 20) & 0xFF)
#define IPV6_FLOW(vtf) ((vtf) & 0xFFFFF)

// ============================================================================
// TCP LAYER
// ============================================================================

// TCP header (20-60 bytes)
typedef struct PACKED_STRUCT {
  uint16_t src_port;          // Source port
  uint16_t dst_port;          // Destination port
  uint32_t seq_num;           // Sequence number
  uint32_t ack_num;           // Acknowledgment number
  uint16_t data_offset_flags; // Data Offset (4) + Reserved (3) + Flags (9)
  uint16_t window;            // Window size
  uint16_t checksum;          // Checksum
  uint16_t urgent_ptr;        // Urgent pointer
} tcp_header_t;

// TCP header field extraction
#define TCP_DATA_OFFSET(df) (((df) >> 12) & 0x0F)
#define TCP_HEADER_LEN(df) (TCP_DATA_OFFSET(df) * 4)
#define TCP_FLAGS(df) ((df) & 0x01FF)

// TCP flags
#define TCP_FLAG_FIN 0x001
#define TCP_FLAG_SYN 0x002
#define TCP_FLAG_RST 0x004
#define TCP_FLAG_PSH 0x008
#define TCP_FLAG_ACK 0x010
#define TCP_FLAG_URG 0x020
#define TCP_FLAG_ECE 0x040
#define TCP_FLAG_CWR 0x080
#define TCP_FLAG_NS 0x100

// ============================================================================
// UDP LAYER
// ============================================================================

// UDP header (8 bytes)
typedef struct PACKED_STRUCT {
  uint16_t src_port; // Source port
  uint16_t dst_port; // Destination port
  uint16_t length;   // Length (header + data)
  uint16_t checksum; // Checksum
} udp_header_t;

// ============================================================================
// ICMP LAYER
// ============================================================================

// ICMPv4 header (variable size, minimum 8 bytes)
typedef struct PACKED_STRUCT {
  uint8_t type;      // ICMP type
  uint8_t code;      // ICMP code
  uint16_t checksum; // Checksum
  union {
    struct {
      uint16_t id;
      uint16_t sequence;
    } echo;           // Echo Request/Reply
    uint32_t gateway; // Redirect
    struct {
      uint16_t unused;
      uint16_t mtu;
    } frag;          // Fragmentation Needed
    uint32_t unused; // Generic
  } rest;
} icmp_header_t;

// ICMPv4 types
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_SOURCE_QUENCH 4
#define ICMP_REDIRECT 5
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAM_PROBLEM 12
#define ICMP_TIMESTAMP_REQUEST 13
#define ICMP_TIMESTAMP_REPLY 14

// ICMPv6 header (variable size, minimum 8 bytes)
typedef struct PACKED_STRUCT {
  uint8_t type;      // ICMPv6 type
  uint8_t code;      // ICMPv6 code
  uint16_t checksum; // Checksum
  union {
    struct {
      uint16_t id;
      uint16_t sequence;
    } echo;           // Echo Request/Reply
    uint32_t mtu;     // Packet Too Big
    uint32_t pointer; // Parameter Problem
    uint32_t unused;  // Generic
  } rest;
} icmpv6_header_t;

// ICMPv6 types
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PACKET_TOO_BIG 2
#define ICMPV6_TIME_EXCEEDED 3
#define ICMPV6_PARAM_PROBLEM 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_ROUTER_SOLICIT 133
#define ICMPV6_ROUTER_ADVERT 134
#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERT 136

// ============================================================================
// ARP LAYER
// ============================================================================

// ARP header (28 bytes for Ethernet/IPv4)
typedef struct PACKED_STRUCT {
  uint16_t hw_type;      // Hardware type (1 = Ethernet)
  uint16_t proto_type;   // Protocol type (0x0800 = IPv4)
  uint8_t hw_len;        // Hardware address length (6 for MAC)
  uint8_t proto_len;     // Protocol address length (4 for IPv4)
  uint16_t operation;    // Operation (1=request, 2=reply)
  uint8_t sender_hw[6];  // Sender hardware address
  uint32_t sender_proto; // Sender protocol address
  uint8_t target_hw[6];  // Target hardware address
  uint32_t target_proto; // Target protocol address
} arp_header_t;

// ARP operations
#define ARP_REQUEST 1
#define ARP_REPLY 2

// ============================================================================
// HELPER MACROS
// ============================================================================

// Byte order conversion (network to host)
#ifdef _WIN32
#include <winsock2.h>
#define ntoh16(x) ntohs(x)
#define ntoh32(x) ntohl(x)
#define hton16(x) htons(x)
#define hton32(x) htonl(x)
#else
#include <arpa/inet.h>
#define ntoh16(x) ntohs(x)
#define ntoh32(x) ntohl(x)
#define hton16(x) htons(x)
#define hton32(x) htonl(x)
#endif

// Common port numbers
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_FTP_DATA 20
#define PORT_FTP_CONTROL 21
#define PORT_SMTP 25
#define PORT_DNS 53
#define PORT_DHCP_SERVER 67
#define PORT_DHCP_CLIENT 68
#define PORT_POP3 110
#define PORT_IMAP 143
#define PORT_SNMP 161
#define PORT_LDAP 389
#define PORT_SMB 445

// Structure size assertions
_Static_assert(sizeof(eth_header_t) == 14, "Ethernet header must be 14 bytes");
_Static_assert(sizeof(vlan_header_t) == 4, "VLAN header must be 4 bytes");
_Static_assert(sizeof(ipv4_header_t) == 20, "IPv4 header must be 20 bytes");
_Static_assert(sizeof(ipv6_header_t) == 40, "IPv6 header must be 40 bytes");
_Static_assert(sizeof(tcp_header_t) == 20, "TCP header must be 20 bytes");
_Static_assert(sizeof(udp_header_t) == 8, "UDP header must be 8 bytes");
_Static_assert(sizeof(icmp_header_t) == 8, "ICMP header must be 8 bytes");
_Static_assert(sizeof(arp_header_t) == 28, "ARP header must be 28 bytes");

#ifdef _MSC_VER
#pragma pack(pop)
#endif

#endif // SAFEOPS_PACKET_STRUCTS_H
