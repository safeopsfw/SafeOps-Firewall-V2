package parser

import (
	"encoding/binary"
)

// DHCPParser extracts hostname from DHCP packets
type DHCPParser struct{}

// NewDHCPParser creates a new DHCP parser
func NewDHCPParser() *DHCPParser {
	return &DHCPParser{}
}

// DHCPMessage represents DHCP packet info
type DHCPMessage struct {
	Hostname   string
	ClientIP   string
	ClientMAC  string
	MessageType uint8 // 1=Discover, 2=Offer, 3=Request, 4=Decline, 5=ACK, 6=NAK, 7=Release, 8=Inform
}

// ExtractHostname extracts hostname from DHCP packet (option 12)
// Returns empty string if not a valid DHCP packet
func (p *DHCPParser) ExtractHostname(payload []byte) string {
	msg := p.Parse(payload)
	if msg == nil {
		return ""
	}
	return msg.Hostname
}

// Parse parses a DHCP packet and extracts information
func (p *DHCPParser) Parse(payload []byte) *DHCPMessage {
	// DHCP packet minimum size: 236 bytes (fixed fields) + 4 bytes (magic cookie)
	if len(payload) < 240 {
		return nil
	}

	// Check DHCP magic cookie (0x63825363)
	magicCookie := binary.BigEndian.Uint32(payload[236:240])
	if magicCookie != 0x63825363 {
		return nil
	}

	msg := &DHCPMessage{}

	// Extract client IP (ciaddr field, offset 12-15)
	if payload[12] != 0 || payload[13] != 0 || payload[14] != 0 || payload[15] != 0 {
		msg.ClientIP = formatIP(payload[12:16])
	}

	// Extract client MAC (chaddr field, offset 28-33)
	msg.ClientMAC = formatMAC(payload[28:34])

	// Parse DHCP options (starts at offset 240)
	offset := 240
	for offset < len(payload) {
		optionCode := payload[offset]

		// End option
		if optionCode == 255 {
			break
		}

		// Pad option
		if optionCode == 0 {
			offset++
			continue
		}

		// Check if we have length byte
		if offset+1 >= len(payload) {
			break
		}

		optionLen := int(payload[offset+1])

		// Check if option data is available
		if offset+2+optionLen > len(payload) {
			break
		}

		optionData := payload[offset+2 : offset+2+optionLen]

		switch optionCode {
		case 12: // Hostname
			msg.Hostname = string(optionData)
		case 53: // DHCP Message Type
			if optionLen == 1 {
				msg.MessageType = optionData[0]
			}
		}

		offset += 2 + optionLen
	}

	return msg
}

// IsDHCP checks if this is a DHCP packet
func (p *DHCPParser) IsDHCP(payload []byte) bool {
	if len(payload) < 240 {
		return false
	}

	// Check magic cookie
	magicCookie := binary.BigEndian.Uint32(payload[236:240])
	return magicCookie == 0x63825363
}

// formatIP formats IP address bytes to string
func formatIP(ip []byte) string {
	if len(ip) != 4 {
		return ""
	}
	return string(rune(ip[0])) + "." + string(rune(ip[1])) + "." + string(rune(ip[2])) + "." + string(rune(ip[3]))
}

// formatMAC formats MAC address bytes to string
func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}

	hexChars := "0123456789abcdef"
	result := make([]byte, 17) // "xx:xx:xx:xx:xx:xx"

	for i := 0; i < 6; i++ {
		result[i*3] = hexChars[mac[i]>>4]
		result[i*3+1] = hexChars[mac[i]&0x0F]
		if i < 5 {
			result[i*3+2] = ':'
		}
	}

	return string(result)
}

// GetMessageTypeName returns human-readable DHCP message type
func GetMessageTypeName(msgType uint8) string {
	switch msgType {
	case 1:
		return "DISCOVER"
	case 2:
		return "OFFER"
	case 3:
		return "REQUEST"
	case 4:
		return "DECLINE"
	case 5:
		return "ACK"
	case 6:
		return "NAK"
	case 7:
		return "RELEASE"
	case 8:
		return "INFORM"
	default:
		return "UNKNOWN"
	}
}
