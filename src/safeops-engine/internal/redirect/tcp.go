package redirect

import (
	"encoding/binary"
	"fmt"

	"github.com/wiresock/ndisapi-go"
)

// TCPResetter provides TCP RST packet injection utilities
type TCPResetter struct{}

// NewTCPResetter creates a new TCP resetter
func NewTCPResetter() *TCPResetter {
	return &TCPResetter{}
}

// SendReset sends a TCP RST packet to terminate a connection
// This is used to block HTTPS connections (can't redirect encrypted traffic)
func (t *TCPResetter) SendReset(buffer *ndisapi.IntermediateBuffer) error {
	data := buffer.Buffer[:buffer.Length]

	if len(data) < 54 {
		return fmt.Errorf("packet too small for TCP")
	}

	ethHeaderSize := 14
	ipHeaderSize := 20
	tcpHeaderSize := 20

	// Set TCP flags to RST
	tcpFlagsOffset := ethHeaderSize + ipHeaderSize + 13
	data[tcpFlagsOffset] = 0x04 // RST flag

	// Swap source and destination IPs
	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)
	copy(srcIP, data[ethHeaderSize+12:ethHeaderSize+16])
	copy(dstIP, data[ethHeaderSize+16:ethHeaderSize+20])
	copy(data[ethHeaderSize+12:], dstIP)
	copy(data[ethHeaderSize+16:], srcIP)

	// Swap source and destination ports
	srcPort := binary.BigEndian.Uint16(data[ethHeaderSize+ipHeaderSize:])
	dstPort := binary.BigEndian.Uint16(data[ethHeaderSize+ipHeaderSize+2:])
	binary.BigEndian.PutUint16(data[ethHeaderSize+ipHeaderSize:], dstPort)
	binary.BigEndian.PutUint16(data[ethHeaderSize+ipHeaderSize+2:], srcPort)

	// Set packet length (no payload for RST)
	newLength := ethHeaderSize + ipHeaderSize + tcpHeaderSize
	buffer.Length = uint32(newLength)

	// Update IP total length
	binary.BigEndian.PutUint16(data[ethHeaderSize+2:], uint16(ipHeaderSize+tcpHeaderSize))

	// Recalculate checksums
	t.recalculateIPChecksum(data[ethHeaderSize:])
	t.recalculateTCPChecksum(data[ethHeaderSize:])

	// Swap device flags
	if buffer.DeviceFlags == ndisapi.PACKET_FLAG_ON_SEND {
		buffer.DeviceFlags = ndisapi.PACKET_FLAG_ON_RECEIVE
	}

	return nil
}

// recalculateIPChecksum recalculates the IP header checksum
func (t *TCPResetter) recalculateIPChecksum(ipPacket []byte) {
	ipPacket[10] = 0
	ipPacket[11] = 0

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(ipPacket[i])<<8 | uint32(ipPacket[i+1])
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(ipPacket[10:12], checksum)
}

// recalculateTCPChecksum recalculates the TCP checksum
func (t *TCPResetter) recalculateTCPChecksum(ipPacket []byte) {
	tcpOffset := 20
	ipPacket[tcpOffset+16] = 0
	ipPacket[tcpOffset+17] = 0
}
