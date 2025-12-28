// Package server implements the DHCP server core components.
// This file implements the DHCP message builder for RFC 2131 compliant packets.
package server

import (
	"encoding/binary"
	"errors"
	"net"
)

// ============================================================================
// DHCP Constants
// ============================================================================

const (
	// BOOTP Operation Codes
	BootRequest = 1
	BootReply   = 2

	// Hardware Types
	HTypeEthernet = 1

	// Hardware Address Length
	HLenEthernet = 6

	// DHCP Message Types
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8

	// DHCP Option Codes
	OptSubnetMask     = 1
	OptRouter         = 3
	OptDNS            = 6
	OptHostname       = 12
	OptDomainName     = 15
	OptBroadcastAddr  = 28
	OptRequestedIP    = 50
	OptLeaseTime      = 51
	OptMessageType    = 53
	OptServerID       = 54
	OptParamRequest   = 55
	OptMessage        = 56
	OptRenewalTime    = 58
	OptRebindingTime  = 59
	OptClientID       = 61
	OptCACertURL      = 224
	OptInstallScripts = 225
	OptCRLURL         = 226
	OptOCSPURL        = 227
	OptWPAD           = 252
	OptEnd            = 255

	// Packet sizes
	MinPacketSize  = 240
	BootpHeaderLen = 236
)

// ============================================================================
// Message Builder Configuration
// ============================================================================

// MessageBuilderConfig holds builder settings.
type MessageBuilderConfig struct {
	ServerIP      net.IP
	DefaultLease  uint32 // seconds
	RenewalTime   uint32 // T1 in seconds
	RebindingTime uint32 // T2 in seconds
	SubnetMask    net.IP
	Router        net.IP
	DNSServers    []net.IP
	DomainName    string
}

// DefaultMessageBuilderConfig returns sensible defaults.
func DefaultMessageBuilderConfig() *MessageBuilderConfig {
	return &MessageBuilderConfig{
		ServerIP:      net.IPv4(192, 168, 1, 1),
		DefaultLease:  86400, // 24 hours
		RenewalTime:   43200, // 12 hours (T1 = 50%)
		RebindingTime: 75600, // 21 hours (T2 = 87.5%)
		SubnetMask:    net.IPv4(255, 255, 255, 0),
		Router:        net.IPv4(192, 168, 1, 1),
		DNSServers:    []net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(8, 8, 4, 4)},
		DomainName:    "local",
	}
}

// ============================================================================
// Build Request
// ============================================================================

// BuildRequest contains parameters for building a DHCP response.
type BuildRequest struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	ClientIP      net.IP
	YourIP        net.IP
	ServerIP      net.IP
	GatewayIP     net.IP
	Flags         uint16
	Hops          uint8
	MessageType   uint8
	LeaseTime     uint32
	SubnetMask    net.IP
	Router        net.IP
	DNSServers    []net.IP
	DomainName    string
	Hostname      string

	// CA Certificate options (for ACK)
	CACertURL      string
	InstallScripts []string
	WPADURL        string
	CRLURL         string
	OCSPURL        string

	// NAK specific
	NAKMessage string
}

// ============================================================================
// Message Builder
// ============================================================================

// MessageBuilder builds DHCP messages.
type MessageBuilder struct {
	config *MessageBuilderConfig
}

// NewMessageBuilder creates a new message builder.
func NewMessageBuilder(config *MessageBuilderConfig) *MessageBuilder {
	if config == nil {
		config = DefaultMessageBuilderConfig()
	}

	return &MessageBuilder{
		config: config,
	}
}

// ============================================================================
// Build Methods
// ============================================================================

// BuildOffer builds a DHCP OFFER message.
func (b *MessageBuilder) BuildOffer(req *BuildRequest) ([]byte, error) {
	if req == nil {
		return nil, ErrNilBuildRequest
	}

	req.MessageType = DHCPOffer
	return b.buildMessage(req, false)
}

// BuildAck builds a DHCP ACK message with CA certificate options.
func (b *MessageBuilder) BuildAck(req *BuildRequest) ([]byte, error) {
	if req == nil {
		return nil, ErrNilBuildRequest
	}

	req.MessageType = DHCPAck
	return b.buildMessage(req, true) // Include CA options
}

// BuildNak builds a DHCP NAK message.
func (b *MessageBuilder) BuildNak(req *BuildRequest) ([]byte, error) {
	if req == nil {
		return nil, ErrNilBuildRequest
	}

	req.MessageType = DHCPNak
	return b.buildNakMessage(req)
}

// ============================================================================
// Core Message Building
// ============================================================================

func (b *MessageBuilder) buildMessage(req *BuildRequest, includeCAOptions bool) ([]byte, error) {
	// Allocate packet buffer (minimum 576 bytes for DHCP)
	packet := make([]byte, 576)

	// Build BOOTP header
	b.writeBootpHeader(packet, req)

	// Write magic cookie at offset 236
	b.writeMagicCookie(packet)

	// Build options starting at offset 240
	optionsLen, err := b.writeOptions(packet[240:], req, includeCAOptions)
	if err != nil {
		return nil, err
	}

	// Calculate total packet size
	totalLen := 240 + optionsLen

	// Ensure minimum packet size
	if totalLen < MinPacketSize {
		totalLen = MinPacketSize
	}

	return packet[:totalLen], nil
}

func (b *MessageBuilder) buildNakMessage(req *BuildRequest) ([]byte, error) {
	// NAK messages are minimal
	packet := make([]byte, 576)

	// Build BOOTP header (YourIP must be 0.0.0.0 for NAK)
	req.YourIP = net.IPv4zero
	req.ClientIP = net.IPv4zero
	b.writeBootpHeader(packet, req)

	// Write magic cookie
	b.writeMagicCookie(packet)

	// NAK has minimal options
	offset := 240

	// Option 53: Message Type (DHCPNAK)
	offset += b.writeOptionByte(packet[offset:], OptMessageType, DHCPNak)

	// Option 54: Server Identifier
	serverIP := req.ServerIP
	if serverIP == nil {
		serverIP = b.config.ServerIP
	}
	offset += b.writeOptionIP(packet[offset:], OptServerID, serverIP)

	// Option 56: Message (optional rejection reason)
	if req.NAKMessage != "" {
		offset += b.writeOptionString(packet[offset:], OptMessage, req.NAKMessage)
	}

	// Option 255: End
	packet[offset] = OptEnd
	offset++

	return packet[:offset], nil
}

// ============================================================================
// BOOTP Header Writing
// ============================================================================

func (b *MessageBuilder) writeBootpHeader(packet []byte, req *BuildRequest) {
	// op: Boot Reply
	packet[0] = BootReply

	// htype: Ethernet
	packet[1] = HTypeEthernet

	// hlen: Hardware address length
	packet[2] = HLenEthernet

	// hops: Preserve from request for relay
	packet[3] = req.Hops

	// xid: Transaction ID (4 bytes)
	binary.BigEndian.PutUint32(packet[4:8], req.TransactionID)

	// secs: 0 for responses
	binary.BigEndian.PutUint16(packet[8:10], 0)

	// flags: Preserve from client request
	binary.BigEndian.PutUint16(packet[10:12], req.Flags)

	// ciaddr: Client IP (for renewals)
	clientIP := req.ClientIP
	if clientIP == nil {
		clientIP = net.IPv4zero
	}
	copy(packet[12:16], clientIP.To4())

	// yiaddr: Your IP (offered/assigned IP)
	yourIP := req.YourIP
	if yourIP == nil {
		yourIP = net.IPv4zero
	}
	copy(packet[16:20], yourIP.To4())

	// siaddr: Server IP
	serverIP := req.ServerIP
	if serverIP == nil {
		serverIP = b.config.ServerIP
	}
	copy(packet[20:24], serverIP.To4())

	// giaddr: Gateway IP (relay agent)
	gatewayIP := req.GatewayIP
	if gatewayIP == nil {
		gatewayIP = net.IPv4zero
	}
	copy(packet[24:28], gatewayIP.To4())

	// chaddr: Client hardware address (16 bytes, zero-padded)
	if len(req.ClientMAC) > 0 {
		copy(packet[28:44], req.ClientMAC)
	}

	// sname: Server name (64 bytes) - leave empty
	// file: Boot filename (128 bytes) - leave empty
	// These are already zero from make()
}

// ============================================================================
// Magic Cookie
// ============================================================================

func (b *MessageBuilder) writeMagicCookie(packet []byte) {
	// DHCP magic cookie: 0x63825363
	packet[236] = 0x63
	packet[237] = 0x82
	packet[238] = 0x53
	packet[239] = 0x63
}

// ============================================================================
// Options Writing
// ============================================================================

func (b *MessageBuilder) writeOptions(options []byte, req *BuildRequest, includeCA bool) (int, error) {
	offset := 0

	// Option 53: DHCP Message Type (MUST be first)
	offset += b.writeOptionByte(options[offset:], OptMessageType, req.MessageType)

	// Option 54: Server Identifier
	serverIP := req.ServerIP
	if serverIP == nil {
		serverIP = b.config.ServerIP
	}
	offset += b.writeOptionIP(options[offset:], OptServerID, serverIP)

	// Option 51: Lease Time
	leaseTime := req.LeaseTime
	if leaseTime == 0 {
		leaseTime = b.config.DefaultLease
	}
	offset += b.writeOptionUint32(options[offset:], OptLeaseTime, leaseTime)

	// Option 58: Renewal Time (T1)
	renewalTime := b.config.RenewalTime
	if renewalTime == 0 {
		renewalTime = leaseTime / 2
	}
	offset += b.writeOptionUint32(options[offset:], OptRenewalTime, renewalTime)

	// Option 59: Rebinding Time (T2)
	rebindingTime := b.config.RebindingTime
	if rebindingTime == 0 {
		rebindingTime = leaseTime * 7 / 8
	}
	offset += b.writeOptionUint32(options[offset:], OptRebindingTime, rebindingTime)

	// Option 1: Subnet Mask
	subnetMask := req.SubnetMask
	if subnetMask == nil {
		subnetMask = b.config.SubnetMask
	}
	offset += b.writeOptionIP(options[offset:], OptSubnetMask, subnetMask)

	// Option 3: Router
	router := req.Router
	if router == nil {
		router = b.config.Router
	}
	offset += b.writeOptionIP(options[offset:], OptRouter, router)

	// Option 6: DNS Servers
	dnsServers := req.DNSServers
	if len(dnsServers) == 0 {
		dnsServers = b.config.DNSServers
	}
	if len(dnsServers) > 0 {
		offset += b.writeOptionIPs(options[offset:], OptDNS, dnsServers)
	}

	// Option 15: Domain Name
	domainName := req.DomainName
	if domainName == "" {
		domainName = b.config.DomainName
	}
	if domainName != "" {
		offset += b.writeOptionString(options[offset:], OptDomainName, domainName)
	}

	// Option 12: Hostname
	if req.Hostname != "" {
		offset += b.writeOptionString(options[offset:], OptHostname, req.Hostname)
	}

	// CA Certificate Options (only for ACK)
	if includeCA {
		// Option 224: CA Certificate URL
		if req.CACertURL != "" {
			offset += b.writeOptionString(options[offset:], OptCACertURL, req.CACertURL)
		}

		// Option 225: Install Scripts
		if len(req.InstallScripts) > 0 {
			scriptsData := b.encodeStringList(req.InstallScripts)
			offset += b.writeOptionBytes(options[offset:], OptInstallScripts, scriptsData)
		}

		// Option 226: CRL URL
		if req.CRLURL != "" {
			offset += b.writeOptionString(options[offset:], OptCRLURL, req.CRLURL)
		}

		// Option 227: OCSP URL
		if req.OCSPURL != "" {
			offset += b.writeOptionString(options[offset:], OptOCSPURL, req.OCSPURL)
		}

		// Option 252: WPAD URL
		if req.WPADURL != "" {
			offset += b.writeOptionString(options[offset:], OptWPAD, req.WPADURL)
		}
	}

	// Option 255: End
	options[offset] = OptEnd
	offset++

	return offset, nil
}

// ============================================================================
// Option Encoding Helpers
// ============================================================================

func (b *MessageBuilder) writeOptionByte(buf []byte, code byte, value byte) int {
	buf[0] = code
	buf[1] = 1
	buf[2] = value
	return 3
}

func (b *MessageBuilder) writeOptionIP(buf []byte, code byte, ip net.IP) int {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	buf[0] = code
	buf[1] = 4
	copy(buf[2:6], ip4)
	return 6
}

func (b *MessageBuilder) writeOptionIPs(buf []byte, code byte, ips []net.IP) int {
	buf[0] = code
	buf[1] = byte(len(ips) * 4)
	offset := 2
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		copy(buf[offset:offset+4], ip4)
		offset += 4
	}
	return offset
}

func (b *MessageBuilder) writeOptionUint32(buf []byte, code byte, value uint32) int {
	buf[0] = code
	buf[1] = 4
	binary.BigEndian.PutUint32(buf[2:6], value)
	return 6
}

func (b *MessageBuilder) writeOptionString(buf []byte, code byte, value string) int {
	length := len(value)
	if length > 255 {
		length = 255
	}
	buf[0] = code
	buf[1] = byte(length)
	copy(buf[2:2+length], value)
	return 2 + length
}

func (b *MessageBuilder) writeOptionBytes(buf []byte, code byte, data []byte) int {
	length := len(data)
	if length > 255 {
		length = 255
	}
	buf[0] = code
	buf[1] = byte(length)
	copy(buf[2:2+length], data)
	return 2 + length
}

func (b *MessageBuilder) encodeStringList(strings []string) []byte {
	// Encode as semicolon-separated values
	result := ""
	for i, s := range strings {
		if i > 0 {
			result += ";"
		}
		result += s
	}
	return []byte(result)
}

// ============================================================================
// Packet Validation
// ============================================================================

// ValidatePacket validates a built DHCP packet.
func (b *MessageBuilder) ValidatePacket(packet []byte) error {
	if len(packet) < MinPacketSize {
		return ErrPacketTooSmall
	}

	if len(packet) > MaxDHCPPacketSize {
		return ErrPacketTooLarge
	}

	// Check op code
	if packet[0] != BootReply {
		return ErrInvalidOpCode
	}

	// Check magic cookie
	if len(packet) >= 240 {
		cookie := uint32(packet[236])<<24 | uint32(packet[237])<<16 | uint32(packet[238])<<8 | uint32(packet[239])
		if cookie != DHCPMagicCookie {
			return ErrInvalidMagicCookie
		}
	}

	// Check first option is message type
	if len(packet) > 240 && packet[240] != OptMessageType {
		return ErrMessageTypeNotFirst
	}

	return nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilBuildRequest is returned when build request is nil
	ErrNilBuildRequest = errors.New("build request is nil")

	// ErrMessageTypeNotFirst is returned when option 53 is not first
	ErrMessageTypeNotFirst = errors.New("message type option must be first")

	// ErrMissingServerID is returned when server ID missing
	ErrMissingServerID = errors.New("missing server identifier option")

	// ErrMissingEndOption is returned when end option missing
	ErrMissingEndOption = errors.New("missing end option")
)
