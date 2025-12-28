// Package models defines core DHCP data structures for packet handling.
// This file implements the RFC 2131 BOOTP/DHCP message format.
package models

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// FixedHeaderSize is the size of the DHCP fixed header (236 bytes)
	FixedHeaderSize = 236

	// MinPacketSize is the minimum valid DHCP packet size
	MinPacketSize = 300

	// MaxPacketSize is the default maximum DHCP packet size
	MaxPacketSize = 576

	// MagicCookie identifies DHCP options section (0x63825363)
	MagicCookie uint32 = 0x63825363

	// Operation codes
	BootRequest uint8 = 1
	BootReply   uint8 = 2

	// Hardware types
	HTypeEthernet uint8 = 1
	HLenEthernet  uint8 = 6

	// Flag bits
	FlagBroadcast uint16 = 0x8000

	// Option markers
	OptionEnd uint8 = 255
	OptionPad uint8 = 0

	// Field sizes
	SNameSize  = 64
	FileSize   = 128
	CHAddrSize = 16
)

// ============================================================================
// PacketOption Structure (for packet-level handling)
// ============================================================================

// PacketOption represents a DHCP option in TLV format for packet operations.
// See options.go for the full-featured DHCPOption with type inference.
type PacketOption struct {
	Code   uint8  // Option code (1-255)
	Length uint8  // Option data length (0-255 bytes)
	Data   []byte // Option value (variable length)
}

// NewPacketOption creates a new packet option with the given code and data
func NewPacketOption(code uint8, data []byte) PacketOption {
	return PacketOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
	}
}

// ============================================================================
// DHCPPacket Structure (RFC 2131)
// ============================================================================

// DHCPPacket represents a DHCP message matching RFC 2131 format.
// The fixed header is 236 bytes, followed by variable-length options.
type DHCPPacket struct {
	// Fixed Header Fields (236 bytes)
	Op     uint8            // Message operation code (BOOTREQUEST=1, BOOTREPLY=2)
	HType  uint8            // Hardware address type (Ethernet=1)
	HLen   uint8            // Hardware address length (6 for Ethernet)
	Hops   uint8            // Hop count (incremented by relay agents)
	XID    uint32           // Transaction ID (random value for matching)
	Secs   uint16           // Seconds elapsed since client began acquisition
	Flags  uint16           // Flags field (broadcast bit 0x8000)
	CIAddr net.IP           // Client IP address (filled by client if known)
	YIAddr net.IP           // Your (client) IP address (filled by server)
	SIAddr net.IP           // Server IP address (next server for bootstrap)
	GIAddr net.IP           // Gateway IP address (relay agent)
	CHAddr net.HardwareAddr // Client hardware address (MAC)

	// Server/file fields (null-terminated strings)
	SName [SNameSize]byte // Server hostname (64 bytes)
	File  [FileSize]byte  // Boot filename (128 bytes)

	// Variable-Length Fields
	Options []PacketOption // Array of DHCP options (TLV format)
}

// ============================================================================
// Packet Constructor Functions
// ============================================================================

// NewDHCPPacket creates a new DHCP reply packet with the specified message type.
// Initializes magic cookie and adds required Option 53 (Message Type).
func NewDHCPPacket(msgType uint8) *DHCPPacket {
	return &DHCPPacket{
		Op:     BootReply,
		HType:  HTypeEthernet,
		HLen:   HLenEthernet,
		CIAddr: net.IPv4zero,
		YIAddr: net.IPv4zero,
		SIAddr: net.IPv4zero,
		GIAddr: net.IPv4zero,
		CHAddr: make(net.HardwareAddr, 6),
		Options: []PacketOption{
			NewPacketOption(53, []byte{msgType}), // DHCP Message Type
		},
	}
}

// NewDHCPRequest creates a new DHCP request packet with a random XID.
func NewDHCPRequest(msgType uint8, xid uint32) *DHCPPacket {
	return &DHCPPacket{
		Op:     BootRequest,
		HType:  HTypeEthernet,
		HLen:   HLenEthernet,
		XID:    xid,
		CIAddr: net.IPv4zero,
		YIAddr: net.IPv4zero,
		SIAddr: net.IPv4zero,
		GIAddr: net.IPv4zero,
		CHAddr: make(net.HardwareAddr, 6),
		Options: []PacketOption{
			NewPacketOption(53, []byte{msgType}),
		},
	}
}

// ============================================================================
// Serialization Methods
// ============================================================================

// ToBytes serializes the DHCP packet to wire format.
// Returns a byte slice ready for UDP transmission.
func (p *DHCPPacket) ToBytes() []byte {
	// Calculate total size
	optionsSize := 4 // Magic cookie
	for _, opt := range p.Options {
		switch opt.Code {
		case OptionPad, OptionEnd:
			optionsSize++
		default:
			optionsSize += 2 + len(opt.Data) // code + length + data
		}
	}
	optionsSize++ // END option

	totalSize := FixedHeaderSize + optionsSize
	if totalSize < MinPacketSize {
		totalSize = MinPacketSize
	}

	buf := make([]byte, totalSize)

	// Fixed header
	buf[0] = p.Op
	buf[1] = p.HType
	buf[2] = p.HLen
	buf[3] = p.Hops
	binary.BigEndian.PutUint32(buf[4:8], p.XID)
	binary.BigEndian.PutUint16(buf[8:10], p.Secs)
	binary.BigEndian.PutUint16(buf[10:12], p.Flags)

	// IP addresses (4 bytes each)
	copy(buf[12:16], p.CIAddr.To4())
	copy(buf[16:20], p.YIAddr.To4())
	copy(buf[20:24], p.SIAddr.To4())
	copy(buf[24:28], p.GIAddr.To4())

	// Client hardware address (16 bytes, padded)
	copy(buf[28:44], p.CHAddr)

	// Server name and boot file (null-terminated)
	copy(buf[44:108], p.SName[:])
	copy(buf[108:236], p.File[:])

	// Magic cookie
	binary.BigEndian.PutUint32(buf[236:240], MagicCookie)

	// Options
	offset := 240
	for _, opt := range p.Options {
		if opt.Code == OptionPad {
			buf[offset] = OptionPad
			offset++
		} else {
			buf[offset] = opt.Code
			buf[offset+1] = opt.Length
			copy(buf[offset+2:], opt.Data)
			offset += 2 + len(opt.Data)
		}
	}

	// END option
	buf[offset] = OptionEnd

	return buf
}

// FromBytes deserializes a byte slice into a DHCP packet.
// Returns an error for malformed packets.
func FromBytes(data []byte) (*DHCPPacket, error) {
	if len(data) < FixedHeaderSize+4 { // header + magic cookie
		return nil, errors.New("packet too short: minimum 240 bytes required")
	}

	// Verify magic cookie
	cookie := binary.BigEndian.Uint32(data[236:240])
	if cookie != MagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: got 0x%08X, expected 0x%08X", cookie, MagicCookie)
	}

	p := &DHCPPacket{
		Op:    data[0],
		HType: data[1],
		HLen:  data[2],
		Hops:  data[3],
		XID:   binary.BigEndian.Uint32(data[4:8]),
		Secs:  binary.BigEndian.Uint16(data[8:10]),
		Flags: binary.BigEndian.Uint16(data[10:12]),
	}

	// IP addresses
	p.CIAddr = net.IP(data[12:16])
	p.YIAddr = net.IP(data[16:20])
	p.SIAddr = net.IP(data[20:24])
	p.GIAddr = net.IP(data[24:28])

	// Client hardware address
	p.CHAddr = make(net.HardwareAddr, p.HLen)
	copy(p.CHAddr, data[28:28+p.HLen])

	// Server name and boot file
	copy(p.SName[:], data[44:108])
	copy(p.File[:], data[108:236])

	// Parse options
	p.Options = make([]PacketOption, 0)
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
			break // Malformed: no length byte
		}

		length := int(data[offset+1])
		if offset+2+length > len(data) {
			break // Malformed: data exceeds packet
		}

		optData := make([]byte, length)
		copy(optData, data[offset+2:offset+2+length])

		p.Options = append(p.Options, PacketOption{
			Code:   code,
			Length: uint8(length),
			Data:   optData,
		})

		offset += 2 + length
	}

	return p, nil
}

// ============================================================================
// Option Manipulation Methods
// ============================================================================

// AddOption adds or replaces an option in the packet.
func (p *DHCPPacket) AddOption(code uint8, data []byte) {
	// Remove existing option with same code
	p.RemoveOption(code)

	// Add new option
	p.Options = append(p.Options, PacketOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
	})
}

// GetOption returns the option data for a given code.
// Returns nil, false if the option is not present.
func (p *DHCPPacket) GetOption(code uint8) ([]byte, bool) {
	for _, opt := range p.Options {
		if opt.Code == code {
			return opt.Data, true
		}
	}
	return nil, false
}

// RemoveOption removes an option by code.
func (p *DHCPPacket) RemoveOption(code uint8) {
	filtered := make([]PacketOption, 0, len(p.Options))
	for _, opt := range p.Options {
		if opt.Code != code {
			filtered = append(filtered, opt)
		}
	}
	p.Options = filtered
}

// HasOption returns true if the option is present.
func (p *DHCPPacket) HasOption(code uint8) bool {
	_, found := p.GetOption(code)
	return found
}

// ============================================================================
// Validation Methods
// ============================================================================

// Validate checks packet integrity and RFC compliance.
// Returns nil if valid, or an error describing the violation.
func (p *DHCPPacket) Validate() error {
	// Check operation code
	if p.Op != BootRequest && p.Op != BootReply {
		return fmt.Errorf("invalid Op: %d (expected 1 or 2)", p.Op)
	}

	// Check hardware type
	if p.HType != HTypeEthernet {
		return fmt.Errorf("unsupported HType: %d (only Ethernet=1 supported)", p.HType)
	}

	// Check hardware address length matches type
	if p.HType == HTypeEthernet && p.HLen != HLenEthernet {
		return fmt.Errorf("invalid HLen for Ethernet: %d (expected 6)", p.HLen)
	}

	// Check for required Option 53 (Message Type)
	if !p.HasOption(53) {
		return errors.New("missing required Option 53 (DHCP Message Type)")
	}

	// Check XID is non-zero
	if p.XID == 0 {
		return errors.New("XID cannot be zero")
	}

	return nil
}

// ============================================================================
// Helper Methods
// ============================================================================

// GetMessageType extracts the DHCP message type from option 53.
// Returns 0 if option 53 is not present.
func (p *DHCPPacket) GetMessageType() uint8 {
	data, ok := p.GetOption(53)
	if !ok || len(data) < 1 {
		return 0
	}
	return data[0]
}

// GetClientMAC returns the client hardware address.
func (p *DHCPPacket) GetClientMAC() net.HardwareAddr {
	return p.CHAddr
}

// GetTransactionID returns the transaction ID.
func (p *DHCPPacket) GetTransactionID() uint32 {
	return p.XID
}

// IsBroadcast returns true if the broadcast flag is set.
func (p *DHCPPacket) IsBroadcast() bool {
	return p.Flags&FlagBroadcast != 0
}

// SetBroadcast sets or clears the broadcast flag.
func (p *DHCPPacket) SetBroadcast(broadcast bool) {
	if broadcast {
		p.Flags |= FlagBroadcast
	} else {
		p.Flags &^= FlagBroadcast
	}
}

// GetRequestedIP extracts the requested IP from option 50.
// Returns nil if option 50 is not present.
func (p *DHCPPacket) GetRequestedIP() net.IP {
	data, ok := p.GetOption(50)
	if !ok || len(data) != 4 {
		return nil
	}
	return net.IP(data)
}

// GetServerID extracts the server identifier from option 54.
// Returns nil if option 54 is not present.
func (p *DHCPPacket) GetServerID() net.IP {
	data, ok := p.GetOption(54)
	if !ok || len(data) != 4 {
		return nil
	}
	return net.IP(data)
}

// GetHostname extracts the hostname from option 12.
// Returns empty string if option 12 is not present.
func (p *DHCPPacket) GetHostname() string {
	data, ok := p.GetOption(12)
	if !ok {
		return ""
	}
	return string(data)
}

// GetClientID extracts the client identifier from option 61.
// Returns nil if option 61 is not present.
func (p *DHCPPacket) GetClientID() []byte {
	data, ok := p.GetOption(61)
	if !ok {
		return nil
	}
	return data
}

// ============================================================================
// String Representation
// ============================================================================

// String returns a human-readable packet description for debugging.
func (p *DHCPPacket) String() string {
	msgType := p.GetMessageType()
	msgTypeName := "UNKNOWN"
	switch msgType {
	case 1:
		msgTypeName = "DISCOVER"
	case 2:
		msgTypeName = "OFFER"
	case 3:
		msgTypeName = "REQUEST"
	case 4:
		msgTypeName = "DECLINE"
	case 5:
		msgTypeName = "ACK"
	case 6:
		msgTypeName = "NAK"
	case 7:
		msgTypeName = "RELEASE"
	case 8:
		msgTypeName = "INFORM"
	}

	optionCodes := make([]uint8, len(p.Options))
	for i, opt := range p.Options {
		optionCodes[i] = opt.Code
	}

	return fmt.Sprintf("DHCP%s from %s XID=0x%08X CIAddr=%s YIAddr=%s Options=%v",
		msgTypeName,
		p.CHAddr.String(),
		p.XID,
		p.CIAddr.String(),
		p.YIAddr.String(),
		optionCodes,
	)
}

// ============================================================================
// Response Builder Helpers
// ============================================================================

// CreateReply creates a reply packet based on a request packet.
// Copies XID, CHAddr, GIAddr, and sets Op to BOOTREPLY.
func (p *DHCPPacket) CreateReply(msgType uint8, serverIP, yourIP net.IP) *DHCPPacket {
	reply := NewDHCPPacket(msgType)
	reply.XID = p.XID
	reply.Flags = p.Flags
	reply.GIAddr = p.GIAddr
	reply.CHAddr = make(net.HardwareAddr, len(p.CHAddr))
	copy(reply.CHAddr, p.CHAddr)
	reply.CIAddr = p.CIAddr
	reply.YIAddr = yourIP
	reply.SIAddr = serverIP
	return reply
}
