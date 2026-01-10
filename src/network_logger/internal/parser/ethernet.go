package parser

import (
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/safeops/network_logger/pkg/models"
)

// EthernetParser parses Ethernet (Layer 2) frames
type EthernetParser struct{}

// NewEthernetParser creates a new Ethernet parser
func NewEthernetParser() *EthernetParser {
	return &EthernetParser{}
}

// Parse extracts Ethernet layer information
func (p *EthernetParser) Parse(eth *layers.Ethernet) *models.DatalinkLayer {
	if eth == nil {
		return nil
	}

	dl := &models.DatalinkLayer{
		Type:      "ETHERNET",
		SrcMAC:    eth.SrcMAC.String(),
		DstMAC:    eth.DstMAC.String(),
		Ethertype: uint16(eth.EthernetType),
	}

	return dl
}

// ParseVLAN extracts VLAN information if present
func (p *EthernetParser) ParseVLAN(dot1q *layers.Dot1Q) *int {
	if dot1q == nil {
		return nil
	}

	vlanID := int(dot1q.VLANIdentifier)
	return &vlanID
}

// GetEthertypeString returns human-readable ethertype
func GetEthertypeString(ethertype uint16) string {
	switch ethertype {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x86DD:
		return "IPv6"
	case 0x8100:
		return "VLAN"
	default:
		return fmt.Sprintf("0x%04X", ethertype)
	}
}
