package verdict

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wiresock/ndisapi-go"
)

// Verdict represents the decision for a packet/connection
type Verdict int

const (
	VerdictAllow   Verdict = 0 // Forward packet normally
	VerdictBlock   Verdict = 1 // Drop packet and send RST
	VerdictDrop    Verdict = 2 // Silently drop packet
	VerdictRedirect Verdict = 3 // Redirect (DNS spoofing)
)

// Engine handles packet verdicts and enforcement
type Engine struct {
	api *ndisapi.NdisApi

	// IP-based blocking (lock-free)
	blockedIPs   sync.Map // string(IP) → Verdict
	blockedPorts sync.Map // uint16(port) → Verdict

	// DNS redirect mapping
	dnsRedirects sync.Map // string(domain) → net.IP (redirect target)

	// Statistics
	packetsBlocked   uint64
	packetsRedirected uint64
	rstsInjected      uint64
	dnsInjected       uint64

	mu sync.RWMutex
}

// New creates a new verdict engine
func New(api *ndisapi.NdisApi) *Engine {
	return &Engine{
		api: api,
	}
}

// CheckIP checks if an IP should be blocked
func (e *Engine) CheckIP(ip net.IP) Verdict {
	val, exists := e.blockedIPs.Load(ip.String())
	if !exists {
		return VerdictAllow
	}
	return val.(Verdict)
}

// CheckPort checks if a destination port should be blocked
func (e *Engine) CheckPort(port uint16) Verdict {
	val, exists := e.blockedPorts.Load(port)
	if !exists {
		return VerdictAllow
	}
	return val.(Verdict)
}

// CheckDNSRedirect checks if a domain should be redirected
func (e *Engine) CheckDNSRedirect(domain string) (net.IP, bool) {
	val, exists := e.dnsRedirects.Load(domain)
	if !exists {
		return nil, false
	}
	return val.(net.IP), true
}

// BlockIP adds an IP to the blocklist
func (e *Engine) BlockIP(ip net.IP, verdict Verdict) {
	e.blockedIPs.Store(ip.String(), verdict)
}

// UnblockIP removes an IP from the blocklist
func (e *Engine) UnblockIP(ip net.IP) {
	e.blockedIPs.Delete(ip.String())
}

// BlockPort blocks a specific destination port
func (e *Engine) BlockPort(port uint16, verdict Verdict) {
	e.blockedPorts.Store(port, verdict)
}

// UnblockPort unblocks a port
func (e *Engine) UnblockPort(port uint16) {
	e.blockedPorts.Delete(port)
}

// AddDNSRedirect adds a DNS redirect rule (domain → fake IP)
func (e *Engine) AddDNSRedirect(domain string, redirectIP net.IP) {
	e.dnsRedirects.Store(domain, redirectIP)
}

// RemoveDNSRedirect removes a DNS redirect rule
func (e *Engine) RemoveDNSRedirect(domain string) {
	e.dnsRedirects.Delete(domain)
}

// SendTCPReset injects TCP RST packets to kill a connection
func (e *Engine) SendTCPReset(adapterHandle ndisapi.Handle, srcIP, dstIP net.IP, srcPort, dstPort uint16, srcMAC, dstMAC [6]byte) error {
	// Build RST packet to client
	rstToClient := e.buildTCPRst(dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort)

	// Build RST packet to server
	rstToServer := e.buildTCPRst(srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort)

	// Send both RST packets
	if err := e.sendPacket(adapterHandle, rstToClient); err != nil {
		return fmt.Errorf("failed to send RST to client: %w", err)
	}

	if err := e.sendPacket(adapterHandle, rstToServer); err != nil {
		return fmt.Errorf("failed to send RST to server: %w", err)
	}

	atomic.AddUint64(&e.rstsInjected, 2)
	atomic.AddUint64(&e.packetsBlocked, 1)

	return nil
}

// buildTCPRst builds a TCP RST packet
func (e *Engine) buildTCPRst(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 54) // Ethernet(14) + IP(20) + TCP(20)

	// === Ethernet Header ===
	copy(packet[0:6], dstMAC[:])   // Destination MAC
	copy(packet[6:12], srcMAC[:])  // Source MAC
	packet[12] = 0x08              // EtherType: IPv4
	packet[13] = 0x00

	// === IP Header ===
	packet[14] = 0x45                          // Version 4, Header length 5
	packet[15] = 0x00                          // DSCP/ECN
	binary.BigEndian.PutUint16(packet[16:18], 40) // Total length (IP + TCP)
	binary.BigEndian.PutUint16(packet[18:20], 0)  // ID
	binary.BigEndian.PutUint16(packet[20:22], 0)  // Flags/Fragment
	packet[22] = 64                            // TTL
	packet[23] = 6                             // Protocol: TCP
	binary.BigEndian.PutUint16(packet[24:26], 0)  // Checksum (will calculate)
	copy(packet[26:30], srcIP.To4())           // Source IP
	copy(packet[30:34], dstIP.To4())           // Destination IP

	// Calculate IP checksum
	ipChecksum := e.calculateChecksum(packet[14:34])
	binary.BigEndian.PutUint16(packet[24:26], ipChecksum)

	// === TCP Header ===
	binary.BigEndian.PutUint16(packet[34:36], srcPort) // Source port
	binary.BigEndian.PutUint16(packet[36:38], dstPort) // Destination port
	binary.BigEndian.PutUint32(packet[38:42], 0)       // Sequence number
	binary.BigEndian.PutUint32(packet[42:46], 0)       // Acknowledgment number
	packet[46] = 0x50                                  // Data offset (5 * 4 = 20 bytes)
	packet[47] = 0x04                                  // Flags: RST
	binary.BigEndian.PutUint16(packet[48:50], 0)       // Window size
	binary.BigEndian.PutUint16(packet[50:52], 0)       // Checksum (will calculate)
	binary.BigEndian.PutUint16(packet[52:54], 0)       // Urgent pointer

	// Calculate TCP checksum
	tcpChecksum := e.calculateTCPChecksum(packet[26:34], packet[34:54])
	binary.BigEndian.PutUint16(packet[50:52], tcpChecksum)

	return packet
}

// InjectDNSResponse injects a fake DNS response for domain redirection
func (e *Engine) InjectDNSResponse(adapterHandle ndisapi.Handle, queryPacket []byte, domain string, fakeIP net.IP, srcMAC, dstMAC [6]byte) error {
	if len(queryPacket) < 42 { // Eth(14) + IP(20) + UDP(8)
		return fmt.Errorf("query packet too short")
	}

	// Extract DNS query info
	srcIP := net.IP(queryPacket[26:30])
	dstIP := net.IP(queryPacket[30:34])
	srcPort := binary.BigEndian.Uint16(queryPacket[34:36])
	dstPort := binary.BigEndian.Uint16(queryPacket[36:38])
	dnsQuery := queryPacket[42:] // DNS query payload

	// Build DNS response
	response := e.buildDNSResponse(dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort, dnsQuery, fakeIP)

	// Send response
	if err := e.sendPacket(adapterHandle, response); err != nil {
		return fmt.Errorf("failed to inject DNS response: %w", err)
	}

	atomic.AddUint64(&e.dnsInjected, 1)
	atomic.AddUint64(&e.packetsRedirected, 1)

	return nil
}

// buildDNSResponse builds a DNS response packet
func (e *Engine) buildDNSResponse(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, query []byte, answerIP net.IP) []byte {
	// DNS response structure:
	// Header (12 bytes) + Question (from query) + Answer (16 bytes)

	dnsHeaderSize := 12
	questionSize := len(query) - dnsHeaderSize
	answerSize := 16 // Name pointer (2) + Type (2) + Class (2) + TTL (4) + RDLength (2) + IP (4)

	dnsPayload := make([]byte, dnsHeaderSize+questionSize+answerSize)

	// Copy query header and modify flags
	copy(dnsPayload[0:dnsHeaderSize], query[0:dnsHeaderSize])

	// Set QR bit (response), RA bit (recursion available)
	dnsPayload[2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
	dnsPayload[3] = 0x80 // RA=1, Z=0, RCODE=0

	// Answer count = 1
	binary.BigEndian.PutUint16(dnsPayload[6:8], 1)

	// Copy question section
	copy(dnsPayload[dnsHeaderSize:dnsHeaderSize+questionSize], query[dnsHeaderSize:])

	// Build answer section
	answerOffset := dnsHeaderSize + questionSize

	// Name pointer (points to question name)
	binary.BigEndian.PutUint16(dnsPayload[answerOffset:answerOffset+2], 0xC00C)

	// Type A (IPv4)
	binary.BigEndian.PutUint16(dnsPayload[answerOffset+2:answerOffset+4], 1)

	// Class IN
	binary.BigEndian.PutUint16(dnsPayload[answerOffset+4:answerOffset+6], 1)

	// TTL (300 seconds)
	binary.BigEndian.PutUint32(dnsPayload[answerOffset+6:answerOffset+10], 300)

	// RDLength (4 for IPv4)
	binary.BigEndian.PutUint16(dnsPayload[answerOffset+10:answerOffset+12], 4)

	// IP address
	copy(dnsPayload[answerOffset+12:answerOffset+16], answerIP.To4())

	// Build full packet: Ethernet + IP + UDP + DNS
	totalLen := 14 + 20 + 8 + len(dnsPayload)
	packet := make([]byte, totalLen)

	// Ethernet header
	copy(packet[0:6], dstMAC[:])
	copy(packet[6:12], srcMAC[:])
	packet[12] = 0x08
	packet[13] = 0x00

	// IP header
	packet[14] = 0x45
	packet[15] = 0x00
	binary.BigEndian.PutUint16(packet[16:18], uint16(20+8+len(dnsPayload)))
	binary.BigEndian.PutUint16(packet[18:20], 0)
	binary.BigEndian.PutUint16(packet[20:22], 0)
	packet[22] = 64
	packet[23] = 17 // UDP
	binary.BigEndian.PutUint16(packet[24:26], 0)
	copy(packet[26:30], srcIP.To4())
	copy(packet[30:34], dstIP.To4())

	ipChecksum := e.calculateChecksum(packet[14:34])
	binary.BigEndian.PutUint16(packet[24:26], ipChecksum)

	// UDP header
	binary.BigEndian.PutUint16(packet[34:36], srcPort)
	binary.BigEndian.PutUint16(packet[36:38], dstPort)
	binary.BigEndian.PutUint16(packet[38:40], uint16(8+len(dnsPayload)))
	binary.BigEndian.PutUint16(packet[40:42], 0) // Checksum (optional for UDP)

	// DNS payload
	copy(packet[42:], dnsPayload)

	return packet
}

// sendPacket sends a raw packet via NDISAPI
func (e *Engine) sendPacket(adapterHandle ndisapi.Handle, packet []byte) error {
	buffer := &ndisapi.IntermediateBuffer{}
	buffer.DeviceFlags = ndisapi.PACKET_FLAG_ON_SEND
	buffer.Length = uint32(len(packet))
	copy(buffer.Buffer[:], packet)

	request := &ndisapi.EtherRequest{
		AdapterHandle:  adapterHandle,
		EthernetPacket: ndisapi.EthernetPacket{Buffer: buffer},
	}

	return e.api.SendPacketToAdapter(request)
}

// calculateChecksum calculates IP checksum
func (e *Engine) calculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateTCPChecksum calculates TCP checksum with pseudo-header
func (e *Engine) calculateTCPChecksum(ipHeader []byte, tcpSegment []byte) uint16 {
	var sum uint32

	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(ipHeader[0:2]))   // Src IP (first half)
	sum += uint32(binary.BigEndian.Uint16(ipHeader[2:4]))   // Src IP (second half)
	sum += uint32(binary.BigEndian.Uint16(ipHeader[4:6]))   // Dst IP (first half)
	sum += uint32(binary.BigEndian.Uint16(ipHeader[6:8]))   // Dst IP (second half)
	sum += uint32(6)                                         // Protocol (TCP)
	sum += uint32(len(tcpSegment))                           // TCP length

	// TCP segment
	for i := 0; i < len(tcpSegment); i += 2 {
		if i+1 < len(tcpSegment) {
			sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
		} else {
			sum += uint32(tcpSegment[i]) << 8
		}
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// GetStats returns verdict engine statistics
func (e *Engine) GetStats() map[string]uint64 {
	return map[string]uint64{
		"packets_blocked":    atomic.LoadUint64(&e.packetsBlocked),
		"packets_redirected": atomic.LoadUint64(&e.packetsRedirected),
		"rsts_injected":      atomic.LoadUint64(&e.rstsInjected),
		"dns_injected":       atomic.LoadUint64(&e.dnsInjected),
	}
}

// ClearBlocklist clears all IP blocks
func (e *Engine) ClearBlocklist() {
	e.blockedIPs = sync.Map{}
	e.blockedPorts = sync.Map{}
}

// ClearRedirects clears all DNS redirects
func (e *Engine) ClearRedirects() {
	e.dnsRedirects = sync.Map{}
}

// GetBlockedIPs returns list of currently blocked IPs
func (e *Engine) GetBlockedIPs() []string {
	var ips []string
	e.blockedIPs.Range(func(key, value interface{}) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

// GetBlockedIPCount returns count of blocked IPs
func (e *Engine) GetBlockedIPCount() int {
	count := 0
	e.blockedIPs.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
