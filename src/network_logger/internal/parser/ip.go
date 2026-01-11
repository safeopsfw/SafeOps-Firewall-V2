package parser

import (
	"github.com/google/gopacket/layers"
	"github.com/safeops/network_logger/pkg/models"
)

// IPParser parses IP (Layer 3) packets
type IPParser struct{}

// NewIPParser creates a new IP parser
func NewIPParser() *IPParser {
	return &IPParser{}
}

// ParseIPv4 extracts IPv4 layer information
func (p *IPParser) ParseIPv4(ipv4 *layers.IPv4) *models.NetworkLayer {
	if ipv4 == nil {
		return nil
	}

	nl := &models.NetworkLayer{
		Version:        4,
		HeaderLength:   int(ipv4.IHL),
		TOS:            ipv4.TOS,
		DSCP:           ipv4.TOS >> 2,
		ECN:            ipv4.TOS & 0x03,
		TotalLength:    ipv4.Length,
		Identification: ipv4.Id,
		FlagsDF:        (ipv4.Flags & layers.IPv4DontFragment) != 0,
		FlagsMF:        (ipv4.Flags & layers.IPv4MoreFragments) != 0,
		FragmentOffset: ipv4.FragOffset,
		TTL:            ipv4.TTL,
		Protocol:       uint8(ipv4.Protocol),
		HeaderChecksum: ipv4.Checksum,
		SrcIP:          ipv4.SrcIP.String(),
		DstIP:          ipv4.DstIP.String(),
	}

	return nl
}

// ParseIPv6 extracts IPv6 layer information
func (p *IPParser) ParseIPv6(ipv6 *layers.IPv6) *models.NetworkLayer {
	if ipv6 == nil {
		return nil
	}

	nl := &models.NetworkLayer{
		Version:       6,
		TrafficClass:  ipv6.TrafficClass,
		FlowLabel:     ipv6.FlowLabel,
		PayloadLength: ipv6.Length,
		NextHeader:    uint8(ipv6.NextHeader),
		HopLimit:      ipv6.HopLimit,
		Protocol:      uint8(ipv6.NextHeader),
		SrcIP:         ipv6.SrcIP.String(),
		DstIP:         ipv6.DstIP.String(),
	}

	return nl
}

// GetProtocolName returns human-readable protocol name
func GetProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	default:
		return "UNKNOWN"
	}
}
