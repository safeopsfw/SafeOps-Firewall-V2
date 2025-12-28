// Package discovery handles DHCP message processing.
// This file implements DHCP OFFER packet construction.
package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// ============================================================================
// DHCP Packet Constants
// ============================================================================

const (
	// BOOTP Operation Codes
	BootRequest = 1
	BootReply   = 2

	// Hardware Types
	HTypeEthernet = 1

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
	OptPad           = 0
	OptSubnetMask    = 1
	OptRouter        = 3
	OptDNS           = 6
	OptHostname      = 12
	OptDomainName    = 15
	OptMTU           = 26
	OptBroadcastAddr = 28
	OptNTPServers    = 42
	OptRequestedIP   = 50
	OptLeaseTime     = 51
	OptMessageType   = 53
	OptServerID      = 54
	OptParamReqList  = 55
	OptRenewalTime   = 58
	OptRebindingTime = 59
	OptClientID      = 61
	OptEnd           = 255

	// Magic Cookie
	DHCPMagicCookie = 0x63825363

	// Packet Structure Sizes
	MinPacketSize   = 300
	MaxPacketSize   = 576
	FixedHeaderSize = 236
	MaxOptionsSize  = 312
	ServerNameLen   = 64
	BootFileLen     = 128
	HardwareAddrLen = 16
)

// ============================================================================
// Offer Builder Configuration
// ============================================================================

// OfferBuilderConfig holds OFFER construction settings.
type OfferBuilderConfig struct {
	DefaultLeaseTime time.Duration
	MinLeaseTime     time.Duration
	MaxLeaseTime     time.Duration
	ServerIP         net.IP
	PreferUnicast    bool
	DefaultMTU       uint16
}

// DefaultOfferBuilderConfig returns sensible defaults.
func DefaultOfferBuilderConfig() *OfferBuilderConfig {
	return &OfferBuilderConfig{
		DefaultLeaseTime: 24 * time.Hour,
		MinLeaseTime:     5 * time.Minute,
		MaxLeaseTime:     7 * 24 * time.Hour,
		PreferUnicast:    false,
		DefaultMTU:       1500,
	}
}

// ============================================================================
// DHCP Packet Structure
// ============================================================================

// DHCPPacket represents a DHCP message.
type DHCPPacket struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  net.HardwareAddr
	SName   [ServerNameLen]byte
	File    [BootFileLen]byte
	Options []DHCPOption
}

// DHCPOption represents a single DHCP option.
type DHCPOption struct {
	Code   byte
	Length byte
	Data   []byte
}

// ============================================================================
// Offer Builder
// ============================================================================

// OfferBuilder constructs DHCP OFFER packets.
type OfferBuilder struct {
	mu     sync.RWMutex
	config *OfferBuilderConfig

	// Statistics
	stats OfferBuilderStats
}

// OfferBuilderStats tracks OFFER construction metrics.
type OfferBuilderStats struct {
	TotalBuilt       int64
	SuccessfulBuilds int64
	FailedBuilds     int64
	BroadcastOffers  int64
	UnicastOffers    int64
	AvgBuildTimeMs   float64
}

// NewOfferBuilder creates a new OFFER builder.
func NewOfferBuilder(config *OfferBuilderConfig) *OfferBuilder {
	if config == nil {
		config = DefaultOfferBuilderConfig()
	}

	return &OfferBuilder{
		config: config,
	}
}

// ============================================================================
// Main Build Function
// ============================================================================

// BuildOffer constructs a DHCP OFFER packet.
func (b *OfferBuilder) BuildOffer(ctx context.Context, req *OfferBuildRequest) (*DHCPPacket, error) {
	startTime := time.Now()
	b.stats.TotalBuilt++

	// Validate request
	if err := b.validateRequest(req); err != nil {
		b.stats.FailedBuilds++
		return nil, err
	}

	// Create base packet
	packet := &DHCPPacket{
		Op:     BootReply,
		HType:  req.HType,
		HLen:   req.HLen,
		Hops:   0,
		XID:    req.TransactionID,
		Secs:   req.Secs,
		Flags:  req.Flags,
		CIAddr: net.IPv4zero,
		YIAddr: req.OfferedIP,
		SIAddr: b.config.ServerIP,
		GIAddr: req.GatewayIP,
		CHAddr: req.ClientMAC,
	}

	// Build options
	options := b.buildOptions(req)
	packet.Options = options

	// Track delivery method
	if req.Flags&0x8000 != 0 {
		b.stats.BroadcastOffers++
	} else {
		b.stats.UnicastOffers++
	}

	// Update stats
	elapsed := time.Since(startTime).Milliseconds()
	b.updateAvgBuildTime(float64(elapsed))
	b.stats.SuccessfulBuilds++

	return packet, nil
}

// OfferBuildRequest contains parameters for OFFER construction.
type OfferBuildRequest struct {
	TransactionID uint32
	HType         byte
	HLen          byte
	Secs          uint16
	Flags         uint16
	ClientMAC     net.HardwareAddr
	OfferedIP     net.IP
	GatewayIP     net.IP
	SubnetMask    net.IPMask
	RouterIP      net.IP
	DNSServers    []net.IP
	DomainName    string
	LeaseTime     time.Duration
	ServerIP      net.IP
	NTPServers    []net.IP
	MTU           uint16
}

// ============================================================================
// Validation
// ============================================================================

func (b *OfferBuilder) validateRequest(req *OfferBuildRequest) error {
	if req == nil {
		return ErrNilOfferRequest
	}

	if len(req.ClientMAC) == 0 {
		return ErrMissingClientMAC
	}

	if req.OfferedIP == nil || req.OfferedIP.IsUnspecified() {
		return ErrMissingOfferedIP
	}

	if req.TransactionID == 0 {
		return ErrMissingXID
	}

	return nil
}

// ============================================================================
// Options Building
// ============================================================================

func (b *OfferBuilder) buildOptions(req *OfferBuildRequest) []DHCPOption {
	options := make([]DHCPOption, 0, 16)

	// Option 53: DHCP Message Type (OFFER)
	options = append(options, DHCPOption{
		Code:   OptMessageType,
		Length: 1,
		Data:   []byte{DHCPOffer},
	})

	// Option 54: Server Identifier
	serverIP := req.ServerIP
	if serverIP == nil {
		serverIP = b.config.ServerIP
	}
	if serverIP != nil {
		options = append(options, DHCPOption{
			Code:   OptServerID,
			Length: 4,
			Data:   serverIP.To4(),
		})
	}

	// Option 51: IP Address Lease Time
	leaseTime := req.LeaseTime
	if leaseTime == 0 {
		leaseTime = b.config.DefaultLeaseTime
	}
	leaseTime = b.clampLeaseTime(leaseTime)
	leaseSeconds := uint32(leaseTime.Seconds())
	options = append(options, b.encodeUint32Option(OptLeaseTime, leaseSeconds))

	// Option 58: Renewal Time (T1) - 50% of lease time
	t1 := leaseSeconds / 2
	options = append(options, b.encodeUint32Option(OptRenewalTime, t1))

	// Option 59: Rebinding Time (T2) - 87.5% of lease time
	t2 := (leaseSeconds * 7) / 8
	options = append(options, b.encodeUint32Option(OptRebindingTime, t2))

	// Option 1: Subnet Mask
	if len(req.SubnetMask) >= 4 {
		options = append(options, DHCPOption{
			Code:   OptSubnetMask,
			Length: 4,
			Data:   []byte(req.SubnetMask[:4]),
		})
	}

	// Option 3: Router (Default Gateway)
	if req.RouterIP != nil && !req.RouterIP.IsUnspecified() {
		options = append(options, DHCPOption{
			Code:   OptRouter,
			Length: 4,
			Data:   req.RouterIP.To4(),
		})
	}

	// Option 6: DNS Servers
	if len(req.DNSServers) > 0 {
		dnsData := make([]byte, 0, len(req.DNSServers)*4)
		for _, dns := range req.DNSServers {
			if dns4 := dns.To4(); dns4 != nil {
				dnsData = append(dnsData, dns4...)
			}
		}
		if len(dnsData) > 0 {
			options = append(options, DHCPOption{
				Code:   OptDNS,
				Length: byte(len(dnsData)),
				Data:   dnsData,
			})
		}
	}

	// Option 15: Domain Name
	if req.DomainName != "" {
		options = append(options, DHCPOption{
			Code:   OptDomainName,
			Length: byte(len(req.DomainName)),
			Data:   []byte(req.DomainName),
		})
	}

	// Option 28: Broadcast Address
	if req.SubnetMask != nil && req.OfferedIP != nil {
		broadcast := b.calculateBroadcast(req.OfferedIP, req.SubnetMask)
		if broadcast != nil {
			options = append(options, DHCPOption{
				Code:   OptBroadcastAddr,
				Length: 4,
				Data:   broadcast.To4(),
			})
		}
	}

	// Option 26: Interface MTU
	mtu := req.MTU
	if mtu == 0 {
		mtu = b.config.DefaultMTU
	}
	options = append(options, b.encodeUint16Option(OptMTU, mtu))

	// Option 42: NTP Servers
	if len(req.NTPServers) > 0 {
		ntpData := make([]byte, 0, len(req.NTPServers)*4)
		for _, ntp := range req.NTPServers {
			if ntp4 := ntp.To4(); ntp4 != nil {
				ntpData = append(ntpData, ntp4...)
			}
		}
		if len(ntpData) > 0 {
			options = append(options, DHCPOption{
				Code:   OptNTPServers,
				Length: byte(len(ntpData)),
				Data:   ntpData,
			})
		}
	}

	// Option 255: End
	options = append(options, DHCPOption{
		Code:   OptEnd,
		Length: 0,
		Data:   nil,
	})

	return options
}

// ============================================================================
// Helper Functions
// ============================================================================

func (b *OfferBuilder) encodeUint32Option(code byte, value uint32) DHCPOption {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return DHCPOption{
		Code:   code,
		Length: 4,
		Data:   data,
	}
}

func (b *OfferBuilder) encodeUint16Option(code byte, value uint16) DHCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return DHCPOption{
		Code:   code,
		Length: 2,
		Data:   data,
	}
}

func (b *OfferBuilder) clampLeaseTime(lease time.Duration) time.Duration {
	if lease < b.config.MinLeaseTime {
		return b.config.MinLeaseTime
	}
	if lease > b.config.MaxLeaseTime {
		return b.config.MaxLeaseTime
	}
	return lease
}

func (b *OfferBuilder) calculateBroadcast(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil || len(mask) < 4 {
		return nil
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip4[i] | ^mask[i]
	}
	return broadcast
}

func (b *OfferBuilder) updateAvgBuildTime(elapsed float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Rolling average
	if b.stats.SuccessfulBuilds == 0 {
		b.stats.AvgBuildTimeMs = elapsed
	} else {
		b.stats.AvgBuildTimeMs = (b.stats.AvgBuildTimeMs + elapsed) / 2
	}
}

// ============================================================================
// Packet Serialization
// ============================================================================

// Serialize converts the DHCP packet to wire format.
func (p *DHCPPacket) Serialize() ([]byte, error) {
	buf := make([]byte, MaxPacketSize)

	// Fixed header fields
	buf[0] = p.Op
	buf[1] = p.HType
	buf[2] = p.HLen
	buf[3] = p.Hops

	binary.BigEndian.PutUint32(buf[4:8], p.XID)
	binary.BigEndian.PutUint16(buf[8:10], p.Secs)
	binary.BigEndian.PutUint16(buf[10:12], p.Flags)

	// IP addresses
	copy(buf[12:16], p.CIAddr.To4())
	copy(buf[16:20], p.YIAddr.To4())
	copy(buf[20:24], p.SIAddr.To4())
	copy(buf[24:28], p.GIAddr.To4())

	// Hardware address (16 bytes)
	copy(buf[28:44], p.CHAddr)

	// Server name (64 bytes) and boot file (128 bytes)
	copy(buf[44:108], p.SName[:])
	copy(buf[108:236], p.File[:])

	// Magic cookie
	binary.BigEndian.PutUint32(buf[236:240], DHCPMagicCookie)

	// Options
	offset := 240
	for _, opt := range p.Options {
		if opt.Code == OptEnd {
			buf[offset] = OptEnd
			offset++
			break
		}
		if opt.Code == OptPad {
			buf[offset] = OptPad
			offset++
			continue
		}

		buf[offset] = opt.Code
		buf[offset+1] = opt.Length
		copy(buf[offset+2:], opt.Data)
		offset += 2 + int(opt.Length)

		if offset >= MaxPacketSize-2 {
			break
		}
	}

	return buf[:offset], nil
}

// ============================================================================
// Delivery Method
// ============================================================================

// GetDeliveryAddress returns the destination address for the OFFER.
func (p *DHCPPacket) GetDeliveryAddress() net.IP {
	// If broadcast flag is set, use broadcast
	if p.Flags&0x8000 != 0 {
		return net.IPv4bcast
	}

	// If relay agent, send to relay
	if p.GIAddr != nil && !p.GIAddr.IsUnspecified() {
		return p.GIAddr
	}

	// Otherwise, can unicast to offered IP
	return p.YIAddr
}

// IsBroadcast returns whether this packet should be broadcast.
func (p *DHCPPacket) IsBroadcast() bool {
	return p.Flags&0x8000 != 0
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns OFFER builder statistics.
func (b *OfferBuilder) GetStats() OfferBuilderStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stats
}

// GetSuccessRate returns the build success rate.
func (b *OfferBuilder) GetSuccessRate() float64 {
	total := b.stats.SuccessfulBuilds + b.stats.FailedBuilds
	if total == 0 {
		return 0
	}
	return float64(b.stats.SuccessfulBuilds) / float64(total) * 100
}

// ============================================================================
// Validation Utilities
// ============================================================================

// ValidatePacket validates a DHCP packet structure.
func ValidatePacket(p *DHCPPacket) error {
	if p == nil {
		return errors.New("packet is nil")
	}

	if p.Op != BootRequest && p.Op != BootReply {
		return errors.New("invalid operation code")
	}

	if p.YIAddr == nil && p.Op == BootReply {
		return errors.New("missing offered IP in BOOTREPLY")
	}

	// Check for required options
	hasMessageType := false
	for _, opt := range p.Options {
		if opt.Code == OptMessageType {
			hasMessageType = true
			break
		}
	}
	if !hasMessageType {
		return errors.New("missing DHCP message type option")
	}

	return nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilOfferRequest is returned when request is nil
	ErrNilOfferRequest = errors.New("offer build request is nil")

	// ErrMissingClientMAC is returned when client MAC missing
	ErrMissingClientMAC = errors.New("client MAC address is required")

	// ErrMissingOfferedIP is returned when offered IP missing
	ErrMissingOfferedIP = errors.New("offered IP address is required")

	// ErrMissingXID is returned when transaction ID missing
	ErrMissingXID = errors.New("transaction ID is required")

	// ErrPacketTooLarge is returned when packet exceeds max size
	ErrPacketTooLarge = errors.New("DHCP packet exceeds maximum size")
)
