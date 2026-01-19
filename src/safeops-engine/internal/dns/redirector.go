package dns

import (
	"encoding/binary"
	"net"
	"sync"

	"safeops-engine/internal/classifier"
)

// Redirector handles DNS packet redirection to dnsproxy
type Redirector struct {
	proxyIP   net.IP
	proxyPort uint16

	// Connection tracking for responses
	// Maps modified src port -> original dst IP:port
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

// NewRedirector creates a DNS redirector pointing to dnsproxy
func NewRedirector() *Redirector {
	return &Redirector{
		proxyIP:   net.ParseIP("127.0.0.1"),
		proxyPort: classifier.PortDNSProxy, // 15353
		connTrack: make(map[uint16]connEntry),
	}
}

// RedirectDNS rewrites a DNS packet to go to dnsproxy
// Returns true if packet was modified
func (r *Redirector) RedirectDNS(packet []byte, srcPort, dstPort uint16, dstIP net.IP) bool {
	// Only redirect outbound DNS (dst port 53)
	if dstPort != classifier.PortDNS {
		return false
	}

	// CRITICAL: Don't redirect DNS packets going to localhost
	// This prevents dnsproxy from querying itself (infinite loop)
	if dstIP.IsLoopback() || dstIP.Equal(net.ParseIP("127.0.0.1")) {
		return false
	}

	// CRITICAL: Don't redirect packets going to known public DNS servers
	// These are dnsproxy's upstream queries - let them through!
	// Google DNS: 8.8.8.8, 8.8.4.4
	// Cloudflare: 1.1.1.1, 1.0.0.1
	// OpenDNS: 208.67.222.222, 208.67.220.220
	if dstIP.Equal(net.ParseIP("8.8.8.8")) ||
		dstIP.Equal(net.ParseIP("8.8.4.4")) ||
		dstIP.Equal(net.ParseIP("1.1.1.1")) ||
		dstIP.Equal(net.ParseIP("1.0.0.1")) ||
		dstIP.Equal(net.ParseIP("208.67.222.222")) ||
		dstIP.Equal(net.ParseIP("208.67.220.220")) {
		return false // Let dnsproxy's upstream queries through
	}

	// Need at least Ethernet (14) + IP (20) + UDP (8) = 42 bytes
	if len(packet) < 42 {
		return false
	}

	// Store original destination for response matching
	r.connTrackMu.Lock()
	r.connTrack[srcPort] = connEntry{
		OrigDstIP:   dstIP,
		OrigDstPort: dstPort,
	}
	r.connTrackMu.Unlock()

	// Modify destination IP in IP header (offset 14+16 = 30)
	copy(packet[30:34], r.proxyIP.To4())

	// Modify destination port in UDP header (offset 14+20+2 = 36)
	binary.BigEndian.PutUint16(packet[36:38], r.proxyPort)

	// Recalculate IP header checksum
	r.recalculateIPChecksum(packet)

	// Zero out UDP checksum (optional for IPv4 UDP)
	packet[40] = 0
	packet[41] = 0

	r.redirected++
	return true
}

// HandleResponse rewrites DNS response from dnsproxy back to original source
// Returns true if packet was modified
func (r *Redirector) HandleResponse(packet []byte, srcPort, dstPort uint16) bool {
	// Response comes FROM dnsproxy (src port 15353) TO original client port
	if srcPort != r.proxyPort {
		return false
	}

	if len(packet) < 42 {
		return false
	}

	// Look up original destination
	r.connTrackMu.RLock()
	entry, exists := r.connTrack[dstPort]
	r.connTrackMu.RUnlock()

	if !exists {
		return false
	}

	// Rewrite source IP to original DNS server
	copy(packet[26:30], entry.OrigDstIP.To4())

	// Rewrite source port to 53
	binary.BigEndian.PutUint16(packet[34:36], entry.OrigDstPort)

	// Recalculate IP checksum
	r.recalculateIPChecksum(packet)

	// Zero UDP checksum
	packet[40] = 0
	packet[41] = 0

	r.responses++
	return true
}

// recalculateIPChecksum recalculates the IP header checksum
func (r *Redirector) recalculateIPChecksum(packet []byte) {
	// IP header starts at offset 14 (after Ethernet)
	ipHeader := packet[14:]

	// Get header length
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

	// One's complement
	checksum := ^uint16(sum)

	// Write checksum
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
}

// CleanupConnection removes a connection tracking entry
func (r *Redirector) CleanupConnection(srcPort uint16) {
	r.connTrackMu.Lock()
	delete(r.connTrack, srcPort)
	r.connTrackMu.Unlock()
}

// GetStats returns redirection statistics
func (r *Redirector) GetStats() (redirected, responses uint64) {
	return r.redirected, r.responses
}
