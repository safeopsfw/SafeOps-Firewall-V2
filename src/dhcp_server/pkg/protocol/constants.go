// Package protocol defines DHCP protocol constants from RFC 2131 and RFC 2132.
// These constants ensure protocol compliance and interoperability with all DHCP clients.
package protocol

// ============================================================================
// DHCP Operation Codes (RFC 2131 Section 2)
// ============================================================================

const (
	// BOOTREQUEST is sent by client to server (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM)
	BOOTREQUEST uint8 = 1
	// BOOTREPLY is sent by server to client (OFFER, ACK, NAK)
	BOOTREPLY uint8 = 2
)

// ============================================================================
// Hardware Type Constants (ARP Protocol)
// ============================================================================

const (
	// HTYPE_ETHERNET for Ethernet networks (10Mb, 100Mb, 1Gb, 10Gb)
	HTYPE_ETHERNET uint8 = 1
	// HTYPE_IEEE802 for IEEE 802 Networks (Token Ring)
	HTYPE_IEEE802 uint8 = 6
	// HTYPE_FDDI for Fiber Distributed Data Interface
	HTYPE_FDDI uint8 = 8

	// HLEN_ETHERNET is the Ethernet MAC address length (6 bytes)
	HLEN_ETHERNET uint8 = 6
)

// ============================================================================
// Network Ports (RFC 2131)
// ============================================================================

const (
	// ServerPort is the DHCP server listening port
	ServerPort uint16 = 67
	// ClientPort is the DHCP client listening port
	ClientPort uint16 = 68
)

// ============================================================================
// DHCP Magic Cookie (RFC 1497 Section 3)
// ============================================================================

const (
	// MagicCookie identifies the DHCP options section (99.130.83.99 in dotted decimal)
	MagicCookie uint32 = 0x63825363
)

// MagicCookieBytes is the magic cookie as a byte slice for packet building
var MagicCookieBytes = []byte{99, 130, 83, 99}

// ============================================================================
// Packet Size Constants
// ============================================================================

const (
	// MinPacketSize is the minimum DHCP packet size (legacy BOOTP compatibility)
	MinPacketSize = 300
	// MaxPacketSize is the default maximum size (minimum IP reassembly buffer)
	MaxPacketSize = 576
	// JumboPacketSize is the maximum with jumbo frames support
	JumboPacketSize = 1500
)

// ============================================================================
// DHCP Field Offsets (RFC 2131 Packet Format)
// ============================================================================

const (
	// OffsetOp is the operation code offset (1 byte)
	OffsetOp = 0
	// OffsetHtype is the hardware type offset (1 byte)
	OffsetHtype = 1
	// OffsetHlen is the hardware address length offset (1 byte)
	OffsetHlen = 2
	// OffsetHops is the hop count offset (1 byte)
	OffsetHops = 3
	// OffsetXid is the transaction ID offset (4 bytes)
	OffsetXid = 4
	// OffsetSecs is the seconds elapsed offset (2 bytes)
	OffsetSecs = 8
	// OffsetFlags is the flags offset (2 bytes)
	OffsetFlags = 10
	// OffsetCiaddr is the client IP address offset (4 bytes)
	OffsetCiaddr = 12
	// OffsetYiaddr is the your (client) IP address offset (4 bytes)
	OffsetYiaddr = 16
	// OffsetSiaddr is the server IP address offset (4 bytes)
	OffsetSiaddr = 20
	// OffsetGiaddr is the gateway IP address offset (4 bytes)
	OffsetGiaddr = 24
	// OffsetChaddr is the client hardware address offset (16 bytes)
	OffsetChaddr = 28
	// OffsetSname is the server hostname offset (64 bytes)
	OffsetSname = 44
	// OffsetFile is the boot filename offset (128 bytes)
	OffsetFile = 108
	// OffsetOptions is the options start offset (variable length)
	OffsetOptions = 236
)

// Field sizes in bytes
const (
	// SizeChaddr is the client hardware address field size
	SizeChaddr = 16
	// SizeSname is the server hostname field size
	SizeSname = 64
	// SizeFile is the boot filename field size
	SizeFile = 128
)

// ============================================================================
// Flags Field Constants (RFC 2131 Section 2)
// ============================================================================

const (
	// FlagBroadcast is the broadcast bit (high-order bit of flags field)
	// Used when client cannot receive unicast before IP configuration
	FlagBroadcast uint16 = 0x8000
)

// ============================================================================
// Timeout and Retry Constants
// ============================================================================

const (
	// DefaultLeaseTime is 24 hours in seconds
	DefaultLeaseTime uint32 = 86400
	// MinLeaseTime is 1 hour minimum
	MinLeaseTime uint32 = 3600
	// MaxLeaseTime is 7 days maximum
	MaxLeaseTime uint32 = 604800

	// T1RenewalTimeRatio is T1 at 50% of lease time (RFC 2131)
	T1RenewalTimeRatio float64 = 0.5
	// T2RebindingTimeRatio is T2 at 87.5% of lease time (RFC 2131)
	T2RebindingTimeRatio float64 = 0.875

	// ConflictCheckTimeout is ICMP ping timeout in milliseconds
	ConflictCheckTimeout = 500
	// ConflictCheckRetries is the number of ping attempts
	ConflictCheckRetries = 2
)

// ============================================================================
// gRPC and Metrics Ports
// ============================================================================

const (
	// GRPCPort is the default gRPC management API port
	GRPCPort = 50054
	// MetricsPort is the default Prometheus metrics port
	MetricsPort = 9154
)

// ============================================================================
// Certificate Manager Integration
// ============================================================================

const (
	// CertManagerGRPCPort is the Certificate Manager gRPC port
	CertManagerGRPCPort = 50060
	// DNSServerGRPCPort is the DNS Server gRPC port
	DNSServerGRPCPort = 50053
	// CACacheTTLSeconds is the CA URL cache TTL in seconds
	CACacheTTLSeconds = 3600 // 1 hour
)
