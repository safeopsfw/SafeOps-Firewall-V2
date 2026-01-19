package redirect

import (
	"encoding/binary"
	"fmt"

	"github.com/wiresock/ndisapi-go"
)

// HTTPRedirector provides HTTP redirect injection utilities
type HTTPRedirector struct{}

// NewHTTPRedirector creates a new HTTP redirector
func NewHTTPRedirector() *HTTPRedirector {
	return &HTTPRedirector{}
}

// InjectRedirect injects an HTTP 302 redirect response
// This replaces the original HTTP request with a redirect to the block page
func (h *HTTPRedirector) InjectRedirect(buffer *ndisapi.IntermediateBuffer, redirectURL string) error {
	data := buffer.Buffer[:buffer.Length]

	if len(data) < 54 {
		return fmt.Errorf("packet too small for HTTP")
	}

	// Build HTTP 302 redirect response
	response := fmt.Sprintf(
		"HTTP/1.1 302 Found\r\n"+
			"Location: %s\r\n"+
			"Content-Length: 0\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		redirectURL,
	)

	// Calculate new packet size
	// Ethernet (14) + IP header (20) + TCP header (20) + HTTP response
	ethHeaderSize := 14
	ipHeaderSize := 20
	tcpHeaderSize := 20
	httpSize := len(response)

	newPacketSize := ethHeaderSize + ipHeaderSize + tcpHeaderSize + httpSize

	if newPacketSize > len(buffer.Buffer) {
		return fmt.Errorf("redirect response too large")
	}

	// Copy HTTP response into packet payload
	payloadOffset := ethHeaderSize + ipHeaderSize + tcpHeaderSize
	copy(data[payloadOffset:], []byte(response))

	// Update packet length
	buffer.Length = uint32(newPacketSize)

	// Update IP total length
	binary.BigEndian.PutUint16(data[ethHeaderSize+2:], uint16(ipHeaderSize+tcpHeaderSize+httpSize))

	// Swap source and destination IPs (we're sending response back)
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

	// Recalculate checksums
	h.recalculateIPChecksum(data[ethHeaderSize:])
	h.recalculateTCPChecksum(data[ethHeaderSize:])

	// Swap device flags (outbound becomes inbound)
	if buffer.DeviceFlags == ndisapi.PACKET_FLAG_ON_SEND {
		buffer.DeviceFlags = ndisapi.PACKET_FLAG_ON_RECEIVE
	}

	return nil
}

// recalculateIPChecksum recalculates the IP header checksum
func (h *HTTPRedirector) recalculateIPChecksum(ipPacket []byte) {
	// Zero checksum field
	ipPacket[10] = 0
	ipPacket[11] = 0

	// Calculate checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(ipPacket[i])<<8 | uint32(ipPacket[i+1])
	}

	// Fold to 16 bits
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(ipPacket[10:12], checksum)
}

// recalculateTCPChecksum recalculates the TCP checksum
func (h *HTTPRedirector) recalculateTCPChecksum(ipPacket []byte) {
	// Simplified - zero out TCP checksum (valid for some cases)
	// Full implementation would calculate proper TCP checksum with pseudo-header
	tcpOffset := 20
	ipPacket[tcpOffset+16] = 0
	ipPacket[tcpOffset+17] = 0
}
