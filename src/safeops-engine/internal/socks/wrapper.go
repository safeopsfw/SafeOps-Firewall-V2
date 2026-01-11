package socks

import (
	"encoding/binary"
	"net"
	"sync"

	"safeops-engine/internal/classifier"
)

// Wrapper handles HTTP/HTTPS packet redirection to mitmproxy transparent proxy
type Wrapper struct {
	proxyIP   net.IP
	proxyPort uint16

	// Connection tracking for responses
	// Maps client port -> original dst info
	connTrack   map[uint16]connEntry
	connTrackMu sync.RWMutex

	// Stats
	redirected uint64
	responses  uint64
}

type connEntry struct {
	OrigDstIP   net.IP
	OrigDstPort uint16
}

// NewWrapper creates a new HTTP/HTTPS redirector pointing to mitmproxy
func NewWrapper() *Wrapper {
	return &Wrapper{
		proxyIP:   net.ParseIP("127.0.0.1"),
		proxyPort: classifier.PortMITMProxy, // 8080
		connTrack: make(map[uint16]connEntry),
	}
}

// RedirectHTTP rewrites an HTTP/HTTPS packet to go to mitmproxy
// Returns true if packet was modified
func (w *Wrapper) RedirectHTTP(packet []byte, srcPort, dstPort uint16, dstIP net.IP) bool {
	// Only redirect HTTP (80) and HTTPS (443)
	if dstPort != classifier.PortHTTP && dstPort != classifier.PortHTTPS {
		return false
	}

	// Need at least Ethernet (14) + IP (20) + TCP (20) = 54 bytes
	if len(packet) < 54 {
		return false
	}

	// Store original destination for response matching
	w.connTrackMu.Lock()
	w.connTrack[srcPort] = connEntry{
		OrigDstIP:   dstIP,
		OrigDstPort: dstPort,
	}
	w.connTrackMu.Unlock()

	// Modify destination IP in IP header (offset 14+16 = 30)
	copy(packet[30:34], w.proxyIP.To4())

	// Modify destination port in TCP header (offset 14+20+2 = 36)
	binary.BigEndian.PutUint16(packet[36:38], w.proxyPort)

	// Recalculate IP header checksum
	w.recalculateIPChecksum(packet)

	// Recalculate TCP checksum (important for TCP!)
	w.recalculateTCPChecksum(packet)

	w.redirected++
	return true
}

// HandleResponse rewrites response from mitmproxy back to original source
// Returns true if packet was modified
func (w *Wrapper) HandleResponse(packet []byte, srcPort, dstPort uint16) bool {
	// Response comes FROM mitmproxy (src port 8080) TO original client port
	if srcPort != w.proxyPort {
		return false
	}

	if len(packet) < 54 {
		return false
	}

	// Look up original destination
	w.connTrackMu.RLock()
	entry, exists := w.connTrack[dstPort]
	w.connTrackMu.RUnlock()

	if !exists {
		return false
	}

	// Rewrite source IP to original server
	copy(packet[26:30], entry.OrigDstIP.To4())

	// Rewrite source port to original (80 or 443)
	binary.BigEndian.PutUint16(packet[34:36], entry.OrigDstPort)

	// Recalculate checksums
	w.recalculateIPChecksum(packet)
	w.recalculateTCPChecksum(packet)

	w.responses++
	return true
}

// recalculateIPChecksum recalculates the IP header checksum
func (w *Wrapper) recalculateIPChecksum(packet []byte) {
	ipHeader := packet[14:]
	headerLen := int(ipHeader[0]&0x0F) * 4

	// Zero checksum field
	ipHeader[10] = 0
	ipHeader[11] = 0

	// Calculate checksum
	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(ipHeader[i])<<8 | uint32(ipHeader[i+1])
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
}

// recalculateTCPChecksum recalculates the TCP checksum
func (w *Wrapper) recalculateTCPChecksum(packet []byte) {
	ipHeader := packet[14:]
	ipHeaderLen := int(ipHeader[0]&0x0F) * 4
	tcpHeader := ipHeader[ipHeaderLen:]

	// Get total IP length
	totalLen := binary.BigEndian.Uint16(ipHeader[2:4])
	tcpLen := int(totalLen) - ipHeaderLen

	if len(tcpHeader) < tcpLen {
		return
	}

	// Zero TCP checksum
	tcpHeader[16] = 0
	tcpHeader[17] = 0

	// Build pseudo header
	var sum uint32

	// Source IP
	sum += uint32(ipHeader[12])<<8 | uint32(ipHeader[13])
	sum += uint32(ipHeader[14])<<8 | uint32(ipHeader[15])

	// Dest IP
	sum += uint32(ipHeader[16])<<8 | uint32(ipHeader[17])
	sum += uint32(ipHeader[18])<<8 | uint32(ipHeader[19])

	// Protocol (TCP = 6) + TCP length
	sum += 6
	sum += uint32(tcpLen)

	// TCP header + data
	for i := 0; i < tcpLen-1; i += 2 {
		sum += uint32(tcpHeader[i])<<8 | uint32(tcpHeader[i+1])
	}

	// Handle odd length
	if tcpLen%2 == 1 {
		sum += uint32(tcpHeader[tcpLen-1]) << 8
	}

	// Fold and complement
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)
}

// CleanupConnection removes a connection tracking entry
func (w *Wrapper) CleanupConnection(srcPort uint16) {
	w.connTrackMu.Lock()
	delete(w.connTrack, srcPort)
	w.connTrackMu.Unlock()
}

// GetStats returns redirection statistics
func (w *Wrapper) GetStats() (redirected, responses uint64) {
	return w.redirected, w.responses
}
