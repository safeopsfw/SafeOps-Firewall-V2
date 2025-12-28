// Package options provides DHCP option handling.
// This file implements the StandardOptionsHandler for RFC 2132 options (1-81).
package options

import (
	"encoding/binary"
	"net"
	"time"
)

// ============================================================================
// StandardOptionsHandler Structure
// ============================================================================

// StandardOptionsHandler builds RFC 2132 standard DHCP options (codes 1-81).
type StandardOptionsHandler struct {
	serverIP   net.IP // DHCP server IP for Option 54
	domainName string // Default domain name for Option 15
}

// NewStandardOptionsHandler creates a new standard options handler.
func NewStandardOptionsHandler(serverIP net.IP, domainName string) *StandardOptionsHandler {
	return &StandardOptionsHandler{
		serverIP:   serverIP,
		domainName: domainName,
	}
}

// ============================================================================
// Core Network Options (1, 3, 6, 15, 28)
// ============================================================================

// BuildSubnetMask builds Option 1 (Subnet Mask).
func (h *StandardOptionsHandler) BuildSubnetMask(mask net.IPMask) *DHCPOption {
	if len(mask) != 4 {
		mask = mask[len(mask)-4:] // Get last 4 bytes for IPv4
	}
	return &DHCPOption{
		Code:   1,
		Length: 4,
		Data:   []byte(mask),
	}
}

// BuildRouter builds Option 3 (Router/Gateway).
func (h *StandardOptionsHandler) BuildRouter(gateways ...net.IP) *DHCPOption {
	return h.buildIPListOption(3, gateways)
}

// BuildDNSServers builds Option 6 (Domain Name Server).
func (h *StandardOptionsHandler) BuildDNSServers(servers ...net.IP) *DHCPOption {
	return h.buildIPListOption(6, servers)
}

// BuildDomainName builds Option 15 (Domain Name).
func (h *StandardOptionsHandler) BuildDomainName(domain string) *DHCPOption {
	if domain == "" {
		domain = h.domainName
	}
	return &DHCPOption{
		Code:   15,
		Length: uint8(len(domain)),
		Data:   []byte(domain),
	}
}

// BuildBroadcastAddress builds Option 28 (Broadcast Address).
func (h *StandardOptionsHandler) BuildBroadcastAddress(broadcast net.IP) *DHCPOption {
	return h.buildIPOption(28, broadcast)
}

// ============================================================================
// Lease Time Options (51, 58, 59)
// ============================================================================

// BuildLeaseTime builds Option 51 (IP Address Lease Time).
func (h *StandardOptionsHandler) BuildLeaseTime(duration time.Duration) *DHCPOption {
	seconds := uint32(duration.Seconds())
	return h.buildUint32Option(51, seconds)
}

// BuildRenewalTime builds Option 58 (Renewal Time Value - T1).
func (h *StandardOptionsHandler) BuildRenewalTime(duration time.Duration) *DHCPOption {
	seconds := uint32(duration.Seconds())
	return h.buildUint32Option(58, seconds)
}

// BuildRebindingTime builds Option 59 (Rebinding Time Value - T2).
func (h *StandardOptionsHandler) BuildRebindingTime(duration time.Duration) *DHCPOption {
	seconds := uint32(duration.Seconds())
	return h.buildUint32Option(59, seconds)
}

// ============================================================================
// Protocol Options (53, 54, 55, 57)
// ============================================================================

// BuildMessageType builds Option 53 (DHCP Message Type).
func (h *StandardOptionsHandler) BuildMessageType(msgType uint8) *DHCPOption {
	return &DHCPOption{
		Code:   53,
		Length: 1,
		Data:   []byte{msgType},
	}
}

// BuildServerIdentifier builds Option 54 (Server Identifier).
func (h *StandardOptionsHandler) BuildServerIdentifier(serverIP ...net.IP) *DHCPOption {
	ip := h.serverIP
	if len(serverIP) > 0 && serverIP[0] != nil {
		ip = serverIP[0]
	}
	return h.buildIPOption(54, ip)
}

// BuildParameterRequestList builds Option 55 (Parameter Request List).
func (h *StandardOptionsHandler) BuildParameterRequestList(codes []uint8) *DHCPOption {
	return &DHCPOption{
		Code:   55,
		Length: uint8(len(codes)),
		Data:   codes,
	}
}

// BuildMaxMessageSize builds Option 57 (Maximum DHCP Message Size).
func (h *StandardOptionsHandler) BuildMaxMessageSize(size uint16) *DHCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, size)
	return &DHCPOption{
		Code:   57,
		Length: 2,
		Data:   data,
	}
}

// ============================================================================
// Additional Network Services (4, 42, 44)
// ============================================================================

// BuildTimeServer builds Option 4 (Time Server).
func (h *StandardOptionsHandler) BuildTimeServer(servers ...net.IP) *DHCPOption {
	return h.buildIPListOption(4, servers)
}

// BuildNTPServers builds Option 42 (Network Time Protocol Servers).
func (h *StandardOptionsHandler) BuildNTPServers(servers ...net.IP) *DHCPOption {
	return h.buildIPListOption(42, servers)
}

// BuildNetBIOSNameServer builds Option 44 (NetBIOS Name Server/WINS).
func (h *StandardOptionsHandler) BuildNetBIOSNameServer(servers ...net.IP) *DHCPOption {
	return h.buildIPListOption(44, servers)
}

// ============================================================================
// Hostname and FQDN Options (12, 81)
// ============================================================================

// BuildHostname builds Option 12 (Host Name).
func (h *StandardOptionsHandler) BuildHostname(hostname string) *DHCPOption {
	return &DHCPOption{
		Code:   12,
		Length: uint8(len(hostname)),
		Data:   []byte(hostname),
	}
}

// BuildClientFQDN builds Option 81 (Client FQDN).
func (h *StandardOptionsHandler) BuildClientFQDN(fqdn string, flags uint8) *DHCPOption {
	// Format: flags (1 byte) + RCODE1 (1 byte) + RCODE2 (1 byte) + domain name
	data := make([]byte, 3+len(fqdn))
	data[0] = flags
	data[1] = 0 // RCODE1
	data[2] = 0 // RCODE2
	copy(data[3:], fqdn)
	return &DHCPOption{
		Code:   81,
		Length: uint8(len(data)),
		Data:   data,
	}
}

// ============================================================================
// Batch Build Methods
// ============================================================================

// PoolConfig contains pool settings for building options.
type PoolConfig struct {
	SubnetMask       net.IPMask
	Gateway          net.IP
	DNSServers       []net.IP
	DomainName       string
	NTPServers       []net.IP
	BroadcastAddress net.IP
	LeaseTime        time.Duration
	RenewalTime      time.Duration // T1 (typically LeaseTime * 0.5)
	RebindingTime    time.Duration // T2 (typically LeaseTime * 0.875)
}

// BuildAllStandardOptions builds a complete set of standard options.
func (h *StandardOptionsHandler) BuildAllStandardOptions(cfg *PoolConfig, msgType uint8) []*DHCPOption {
	options := make([]*DHCPOption, 0, 12)

	// Required: Message Type
	options = append(options, h.BuildMessageType(msgType))

	// Required: Server Identifier
	options = append(options, h.BuildServerIdentifier())

	// Option 1: Subnet Mask
	if cfg.SubnetMask != nil {
		options = append(options, h.BuildSubnetMask(cfg.SubnetMask))
	}

	// Option 3: Router
	if cfg.Gateway != nil {
		options = append(options, h.BuildRouter(cfg.Gateway))
	}

	// Option 6: DNS Servers
	if len(cfg.DNSServers) > 0 {
		options = append(options, h.BuildDNSServers(cfg.DNSServers...))
	}

	// Option 15: Domain Name
	domainName := cfg.DomainName
	if domainName == "" {
		domainName = h.domainName
	}
	if domainName != "" {
		options = append(options, h.BuildDomainName(domainName))
	}

	// Option 28: Broadcast Address
	if cfg.BroadcastAddress != nil {
		options = append(options, h.BuildBroadcastAddress(cfg.BroadcastAddress))
	}

	// Option 42: NTP Servers
	if len(cfg.NTPServers) > 0 {
		options = append(options, h.BuildNTPServers(cfg.NTPServers...))
	}

	// Option 51: Lease Time
	if cfg.LeaseTime > 0 {
		options = append(options, h.BuildLeaseTime(cfg.LeaseTime))
	}

	// Option 58: Renewal Time (T1)
	if cfg.RenewalTime > 0 {
		options = append(options, h.BuildRenewalTime(cfg.RenewalTime))
	} else if cfg.LeaseTime > 0 {
		// Default T1 = 50% of lease time
		t1 := time.Duration(float64(cfg.LeaseTime) * 0.5)
		options = append(options, h.BuildRenewalTime(t1))
	}

	// Option 59: Rebinding Time (T2)
	if cfg.RebindingTime > 0 {
		options = append(options, h.BuildRebindingTime(cfg.RebindingTime))
	} else if cfg.LeaseTime > 0 {
		// Default T2 = 87.5% of lease time
		t2 := time.Duration(float64(cfg.LeaseTime) * 0.875)
		options = append(options, h.BuildRebindingTime(t2))
	}

	return options
}

// BuildOfferOptions builds options for DHCPOFFER message.
func (h *StandardOptionsHandler) BuildOfferOptions(cfg *PoolConfig) []*DHCPOption {
	return h.BuildAllStandardOptions(cfg, 2) // DHCPOFFER = 2
}

// BuildACKOptions builds options for DHCPACK message.
func (h *StandardOptionsHandler) BuildACKOptions(cfg *PoolConfig) []*DHCPOption {
	return h.BuildAllStandardOptions(cfg, 5) // DHCPACK = 5
}

// BuildNAKOptions builds options for DHCPNAK message.
func (h *StandardOptionsHandler) BuildNAKOptions() []*DHCPOption {
	return []*DHCPOption{
		h.BuildMessageType(6), // DHCPNAK = 6
		h.BuildServerIdentifier(),
	}
}

// ============================================================================
// Helper Methods
// ============================================================================

// buildIPOption builds an option with a single IP address.
func (h *StandardOptionsHandler) buildIPOption(code uint8, ip net.IP) *DHCPOption {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   []byte(ip4),
	}
}

// buildIPListOption builds an option with multiple IP addresses.
func (h *StandardOptionsHandler) buildIPListOption(code uint8, ips []net.IP) *DHCPOption {
	data := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			data = append(data, ip4...)
		}
	}
	return &DHCPOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
	}
}

// buildUint32Option builds an option with a 32-bit value.
func (h *StandardOptionsHandler) buildUint32Option(code uint8, value uint32) *DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return &DHCPOption{
		Code:   code,
		Length: 4,
		Data:   data,
	}
}

// EncodeIPAddress converts an IP to a 4-byte array.
func EncodeIPAddress(ip net.IP) ([]byte, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, ErrInvalidIPv4
	}
	return []byte(ip4), nil
}

// EncodeIPList converts multiple IPs to a concatenated byte array.
func EncodeIPList(ips []net.IP) []byte {
	data := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			data = append(data, ip4...)
		}
	}
	return data
}

// EncodeDuration converts a duration to 4-byte big-endian seconds.
func EncodeDuration(d time.Duration) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(d.Seconds()))
	return data
}

// ValidateStandardOption checks if code is in standard range (1-81).
func ValidateStandardOption(code uint8) bool {
	return code >= 1 && code <= 81
}

// ============================================================================
// Errors
// ============================================================================

// ErrInvalidIPv4 is returned when an IPv6 address is provided where IPv4 is expected.
var ErrInvalidIPv4 = &OptionError{Code: 0, Message: "invalid IPv4 address"}

// OptionError represents an option-related error.
type OptionError struct {
	Code    uint8
	Message string
}

func (e *OptionError) Error() string {
	if e.Code > 0 {
		return "option " + string(rune(e.Code)) + ": " + e.Message
	}
	return e.Message
}
