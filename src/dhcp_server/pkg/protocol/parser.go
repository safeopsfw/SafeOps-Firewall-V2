// Package protocol provides DHCP packet parsing and formatting.
// This file implements the DHCP packet parser.
package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// ============================================================================
// Packet Structure
// ============================================================================

// Packet represents a parsed DHCP packet.
type Packet struct {
	// BOOTP header fields
	Op     uint8            // Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
	HType  uint8            // Hardware address type: 1 = Ethernet
	HLen   uint8            // Hardware address length: 6 for Ethernet
	Hops   uint8            // Relay agent hops
	XID    uint32           // Transaction ID
	Secs   uint16           // Seconds elapsed
	Flags  uint16           // Flags (broadcast bit)
	CIAddr net.IP           // Client IP address
	YIAddr net.IP           // Your (client) IP address
	SIAddr net.IP           // Server IP address
	GIAddr net.IP           // Gateway (relay agent) IP address
	CHAddr net.HardwareAddr // Client hardware address
	SName  [64]byte         // Server host name
	File   [128]byte        // Boot file name

	// Options
	Options map[uint8][]byte
}

// ============================================================================
// Parser
// ============================================================================

// Parser parses DHCP packets.
type Parser struct{}

// NewParser creates a new DHCP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses raw bytes into a DHCP packet.
func (p *Parser) Parse(data []byte) (*Packet, error) {
	if len(data) < MinPacketSize {
		return nil, ErrPacketTooSmall
	}

	// Verify magic cookie
	cookie := binary.BigEndian.Uint32(data[236:240])
	if cookie != MagicCookie {
		return nil, ErrInvalidMagicCookie
	}

	packet := &Packet{
		Op:      data[0],
		HType:   data[1],
		HLen:    data[2],
		Hops:    data[3],
		XID:     binary.BigEndian.Uint32(data[4:8]),
		Secs:    binary.BigEndian.Uint16(data[8:10]),
		Flags:   binary.BigEndian.Uint16(data[10:12]),
		CIAddr:  net.IP(data[12:16]),
		YIAddr:  net.IP(data[16:20]),
		SIAddr:  net.IP(data[20:24]),
		GIAddr:  net.IP(data[24:28]),
		CHAddr:  net.HardwareAddr(data[28:34]),
		Options: make(map[uint8][]byte),
	}

	// Copy server name and file
	copy(packet.SName[:], data[44:108])
	copy(packet.File[:], data[108:236])

	// Parse options
	if err := p.parseOptions(data[240:], packet); err != nil {
		return nil, err
	}

	return packet, nil
}

func (p *Parser) parseOptions(data []byte, packet *Packet) error {
	offset := 0

	for offset < len(data) {
		code := data[offset]

		if code == OptionEnd {
			break
		}

		if code == OptionPad {
			offset++
			continue
		}

		if offset+1 >= len(data) {
			return ErrInvalidOptions
		}

		length := int(data[offset+1])
		if offset+2+length > len(data) {
			return ErrInvalidOptions
		}

		optionData := make([]byte, length)
		copy(optionData, data[offset+2:offset+2+length])
		packet.Options[code] = optionData

		offset += 2 + length
	}

	return nil
}

// ============================================================================
// Packet Methods
// ============================================================================

// GetMessageType returns the DHCP message type.
func (pkt *Packet) GetMessageType() uint8 {
	if data, ok := pkt.Options[OptionMessageType]; ok && len(data) > 0 {
		return data[0]
	}
	return 0
}

// GetRequestedIP returns the requested IP address (option 50).
func (pkt *Packet) GetRequestedIP() net.IP {
	if data, ok := pkt.Options[50]; ok && len(data) == 4 {
		return net.IP(data)
	}
	return nil
}

// GetServerID returns the server identifier (option 54).
func (pkt *Packet) GetServerID() net.IP {
	if data, ok := pkt.Options[OptionServerID]; ok && len(data) == 4 {
		return net.IP(data)
	}
	return nil
}

// GetHostname returns the client hostname (option 12).
func (pkt *Packet) GetHostname() string {
	if data, ok := pkt.Options[OptionHostname]; ok {
		return string(data)
	}
	return ""
}

// GetParamRequestList returns the parameter request list (option 55).
func (pkt *Packet) GetParamRequestList() []uint8 {
	if data, ok := pkt.Options[55]; ok { // Option 55: Parameter Request List
		return data
	}
	return nil
}

// GetClientMAC returns the client MAC address.
func (pkt *Packet) GetClientMAC() net.HardwareAddr {
	return pkt.CHAddr
}

// IsBroadcast returns true if the broadcast flag is set.
func (pkt *Packet) IsBroadcast() bool {
	return (pkt.Flags & 0x8000) != 0
}

// IsRelayed returns true if the packet came through a relay agent.
func (pkt *Packet) IsRelayed() bool {
	return !pkt.GIAddr.Equal(net.IPv4zero)
}

// ============================================================================
// Validation
// ============================================================================

// Validate validates a DHCP packet.
func (pkt *Packet) Validate() error {
	// Check op code
	if pkt.Op != 1 && pkt.Op != 2 {
		return ErrInvalidOpCode
	}

	// Check hardware type (Ethernet)
	if pkt.HType != 1 {
		return ErrInvalidHType
	}

	// Check hardware address length
	if pkt.HLen != 6 {
		return ErrInvalidHLen
	}

	// Check message type
	if pkt.GetMessageType() == 0 {
		return ErrMissingMessageType
	}

	return nil
}

// ValidateRequest validates a client request packet.
func ValidateRequest(data []byte) error {
	if len(data) < MinPacketSize {
		return ErrPacketTooSmall
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(data[236:240])
	if cookie != MagicCookie {
		return ErrInvalidMagicCookie
	}

	// Check op code is BOOTREQUEST
	if data[0] != 1 {
		return ErrInvalidOpCode
	}

	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// ExtractMessageType extracts the message type from raw packet bytes.
func ExtractMessageType(data []byte) (uint8, error) {
	if len(data) < MinPacketSize {
		return 0, ErrPacketTooSmall
	}

	offset := 240
	for offset < len(data) {
		code := data[offset]

		if code == OptionEnd {
			break
		}

		if code == OptionPad {
			offset++
			continue
		}

		if offset+1 >= len(data) {
			return 0, ErrInvalidOptions
		}

		length := int(data[offset+1])
		if offset+2+length > len(data) {
			return 0, ErrInvalidOptions
		}

		if code == OptionMessageType {
			return data[offset+2], nil
		}

		offset += 2 + length
	}

	return 0, ErrMissingMessageType
}

// ExtractXID extracts the transaction ID from raw packet bytes.
func ExtractXID(data []byte) (uint32, error) {
	if len(data) < 8 {
		return 0, ErrPacketTooSmall
	}
	return binary.BigEndian.Uint32(data[4:8]), nil
}

// ExtractClientMAC extracts the client MAC address from raw packet bytes.
func ExtractClientMAC(data []byte) (net.HardwareAddr, error) {
	if len(data) < 34 {
		return nil, ErrPacketTooSmall
	}
	return net.HardwareAddr(data[28:34]), nil
}

// ExtractGIAddr extracts the gateway (relay) address from raw packet bytes.
func ExtractGIAddr(data []byte) (net.IP, error) {
	if len(data) < 28 {
		return nil, ErrPacketTooSmall
	}
	return net.IP(data[24:28]), nil
}

// ExtractCIAddr extracts the client IP address from raw packet bytes.
func ExtractCIAddr(data []byte) (net.IP, error) {
	if len(data) < 16 {
		return nil, ErrPacketTooSmall
	}
	return net.IP(data[12:16]), nil
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrPacketTooSmall is returned when packet is less than 240 bytes
	ErrPacketTooSmall = errors.New("packet too small (minimum 240 bytes)")

	// ErrInvalidMagicCookie is returned when magic cookie is missing
	ErrInvalidMagicCookie = errors.New("invalid or missing DHCP magic cookie")

	// ErrInvalidOptions is returned when options are malformed
	ErrInvalidOptions = errors.New("invalid or truncated options")

	// ErrMissingMessageType is returned when option 53 is missing
	ErrMissingMessageType = errors.New("missing DHCP message type (option 53)")

	// ErrInvalidOpCode is returned for invalid op code
	ErrInvalidOpCode = errors.New("invalid BOOTP op code")

	// ErrInvalidHType is returned for invalid hardware type
	ErrInvalidHType = errors.New("invalid hardware type")

	// ErrInvalidHLen is returned for invalid hardware address length
	ErrInvalidHLen = errors.New("invalid hardware address length")
)
