package parser

import (
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/safeops/network_logger/pkg/models"
)

// TransportParser parses transport layer (TCP/UDP)
type TransportParser struct{}

// NewTransportParser creates a new transport parser
func NewTransportParser() *TransportParser {
	return &TransportParser{}
}

// ParseTCP extracts TCP layer information
func (p *TransportParser) ParseTCP(tcp *layers.TCP) *models.TransportLayer {
	if tcp == nil {
		return nil
	}

	tl := &models.TransportLayer{
		Protocol:      6, // TCP
		SrcPort:       uint16(tcp.SrcPort),
		DstPort:       uint16(tcp.DstPort),
		TCPSeq:        tcp.Seq,
		TCPAck:        tcp.Ack,
		TCPDataOffset: int(tcp.DataOffset),
		TCPWindow:     tcp.Window,
		TCPChecksum:   tcp.Checksum,
		TCPUrgent:     tcp.Urgent,
		TCPFlags:      parseTCPFlags(tcp),
		TCPOptions:    parseTCPOptions(tcp.Options),
	}

	return tl
}

// ParseUDP extracts UDP layer information
func (p *TransportParser) ParseUDP(udp *layers.UDP) *models.TransportLayer {
	if udp == nil {
		return nil
	}

	tl := &models.TransportLayer{
		Protocol:    17, // UDP
		SrcPort:     uint16(udp.SrcPort),
		DstPort:     uint16(udp.DstPort),
		UDPLength:   udp.Length,
		UDPChecksum: udp.Checksum,
	}

	return tl
}

// parseTCPFlags extracts TCP flags
func parseTCPFlags(tcp *layers.TCP) *models.TCPFlags {
	ns := 0
	if tcp.NS {
		ns = 1
	}
	return &models.TCPFlags{
		FIN: tcp.FIN,
		SYN: tcp.SYN,
		RST: tcp.RST,
		PSH: tcp.PSH,
		ACK: tcp.ACK,
		URG: tcp.URG,
		ECE: tcp.ECE,
		CWR: tcp.CWR,
		NS:  ns,
	}
}

// parseTCPOptions extracts TCP options
func parseTCPOptions(opts []layers.TCPOption) []models.TCPOption {
	if len(opts) == 0 {
		return nil
	}

	result := make([]models.TCPOption, 0, len(opts))
	for _, opt := range opts {
		tcpOpt := models.TCPOption{
			Type: getTCPOptionName(opt.OptionType),
		}

		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				mss := uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
				tcpOpt.Data = mss
			}
		case layers.TCPOptionKindTimestamps:
			if len(opt.OptionData) >= 8 {
				tsval := uint32(opt.OptionData[0])<<24 | uint32(opt.OptionData[1])<<16 |
					uint32(opt.OptionData[2])<<8 | uint32(opt.OptionData[3])
				tsecr := uint32(opt.OptionData[4])<<24 | uint32(opt.OptionData[5])<<16 |
					uint32(opt.OptionData[6])<<8 | uint32(opt.OptionData[7])
				tcpOpt.Data = map[string]uint32{"TSval": tsval, "TSecr": tsecr}
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				tcpOpt.Data = opt.OptionData[0]
			}
		case layers.TCPOptionKindSACKPermitted:
			tcpOpt.Data = "enabled"
		default:
			if len(opt.OptionData) > 0 {
				tcpOpt.Data = fmt.Sprintf("%x", opt.OptionData)
			}
		}

		result = append(result, tcpOpt)
	}

	return result
}

// getTCPOptionName returns human-readable TCP option name
func getTCPOptionName(optType layers.TCPOptionKind) string {
	switch optType {
	case layers.TCPOptionKindEndList:
		return "EOL"
	case layers.TCPOptionKindNop:
		return "NOP"
	case layers.TCPOptionKindMSS:
		return "MSS"
	case layers.TCPOptionKindWindowScale:
		return "WScale"
	case layers.TCPOptionKindSACKPermitted:
		return "SAckOK"
	case layers.TCPOptionKindSACK:
		return "SACK"
	case layers.TCPOptionKindTimestamps:
		return "Timestamp"
	default:
		return fmt.Sprintf("Option-%d", optType)
	}
}

// GetTCPState returns TCP state based on flags
func GetTCPState(flags *models.TCPFlags) string {
	if flags == nil {
		return "UNKNOWN"
	}

	if flags.SYN && !flags.ACK {
		return "SYN"
	}
	if flags.SYN && flags.ACK {
		return "SYN-ACK"
	}
	if flags.FIN {
		return "FIN"
	}
	if flags.RST {
		return "RST"
	}
	if flags.ACK {
		return "ESTABLISHED"
	}

	return "UNKNOWN"
}
