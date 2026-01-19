package metadata

import (
	"encoding/json"
	"net"
	"time"
)

// PacketMetadata contains extracted packet information for IDS/IPS/Firewall
type PacketMetadata struct {
	// === Basic Info (Always Present) ===
	Timestamp   int64  `json:"timestamp"`    // Unix nanoseconds
	Direction   string `json:"direction"`    // "INBOUND" or "OUTBOUND"
	SrcIP       string `json:"src_ip"`       // Source IP address
	DstIP       string `json:"dst_ip"`       // Destination IP address
	SrcPort     uint16 `json:"src_port"`     // Source port
	DstPort     uint16 `json:"dst_port"`     // Destination port
	Protocol    uint8  `json:"protocol"`     // 1=ICMP, 6=TCP, 17=UDP
	PacketSize  uint16 `json:"packet_size"`  // Total packet size
	AdapterName string `json:"adapter_name"` // Network adapter

	// === Domain Info (If Available) ===
	Domain       string `json:"domain,omitempty"`        // Extracted domain name
	DomainSource string `json:"domain_source,omitempty"` // "DNS", "SNI", "HTTP", "DHCP"

	// === TCP Info (If TCP) ===
	TCPFlags      uint8  `json:"tcp_flags,omitempty"`       // SYN, ACK, RST, FIN flags
	IsSYN         bool   `json:"is_syn,omitempty"`          // TCP SYN flag
	IsACK         bool   `json:"is_ack,omitempty"`          // TCP ACK flag
	IsRST         bool   `json:"is_rst,omitempty"`          // TCP RST flag
	IsFIN         bool   `json:"is_fin,omitempty"`          // TCP FIN flag
	IsNewFlow     bool   `json:"is_new_flow,omitempty"`     // First packet of flow?
	FlowID        string `json:"flow_id,omitempty"`         // Unique flow identifier
	FlowPacketNum uint64 `json:"flow_packet_num,omitempty"` // Packet number in flow

	// === ICMP Info (If ICMP) ===
	ICMPType uint8 `json:"icmp_type,omitempty"` // ICMP message type
	ICMPCode uint8 `json:"icmp_code,omitempty"` // ICMP code

	// === DNS Info (If DNS) ===
	IsDNSQuery    bool `json:"is_dns_query,omitempty"`    // DNS query packet
	IsDNSResponse bool `json:"is_dns_response,omitempty"` // DNS response packet

	// === HTTP Info (If HTTP) ===
	IsHTTP       bool   `json:"is_http,omitempty"`        // HTTP request
	HTTPMethod   string `json:"http_method,omitempty"`    // GET, POST, etc.
	HTTPPath     string `json:"http_path,omitempty"`      // URL path
	IsHTTPSProbe bool   `json:"is_https_probe,omitempty"` // TLS ClientHello

	// === DHCP Info (If DHCP) ===
	DHCPHostname    string `json:"dhcp_hostname,omitempty"`     // Client hostname
	DHCPMessageType string `json:"dhcp_message_type,omitempty"` // DISCOVER, REQUEST, etc.
}

// ProtocolName returns human-readable protocol name
func (m *PacketMetadata) ProtocolName() string {
	switch m.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// ToJSON converts metadata to JSON string
func (m *PacketMetadata) ToJSON() string {
	data, _ := json.Marshal(m)
	return string(data)
}

// FlowStats tracks statistics for a network flow
type FlowStats struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	PacketCount uint64
	ByteCount   uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	Domain      string // Cached domain for this flow
}

// FlowKey uniquely identifies a network flow
type FlowKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// NewFlowKey creates a flow key from IPs and ports
func NewFlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) FlowKey {
	var key FlowKey
	copy(key.SrcIP[:], srcIP.To4())
	copy(key.DstIP[:], dstIP.To4())
	key.SrcPort = srcPort
	key.DstPort = dstPort
	key.Protocol = protocol
	return key
}

// String returns string representation of flow key
func (fk FlowKey) String() string {
	srcIP := net.IP(fk.SrcIP[:]).String()
	dstIP := net.IP(fk.DstIP[:]).String()
	return srcIP + ":" + string(rune(fk.SrcPort)) + " -> " + dstIP + ":" + string(rune(fk.DstPort))
}

// IPStats tracks statistics for a single IP address
type IPStats struct {
	TotalPackets   uint64
	TCPConnections uint64
	UDPFlows       uint64
	ICMPPackets    uint64
	SYNCount       uint64
	UniquePortsMap map[uint16]bool // For port scan detection
	LastReset      time.Time
}

// NewIPStats creates new IP statistics tracker
func NewIPStats() *IPStats {
	return &IPStats{
		UniquePortsMap: make(map[uint16]bool),
		LastReset:      time.Now(),
	}
}

// UniquePortCount returns number of unique ports accessed
func (s *IPStats) UniquePortCount() int {
	return len(s.UniquePortsMap)
}

// MetadataStream manages the channel for sending metadata to IDS/IPS
type MetadataStream struct {
	ch chan *PacketMetadata
}

// NewMetadataStream creates a new metadata stream with buffer size
func NewMetadataStream(bufferSize int) *MetadataStream {
	return &MetadataStream{
		ch: make(chan *PacketMetadata, bufferSize),
	}
}

// Send sends metadata to the stream (non-blocking)
// Returns true if sent, false if channel is full
func (s *MetadataStream) Send(m *PacketMetadata) bool {
	select {
	case s.ch <- m:
		return true
	default:
		return false
	}
}

// Receive receives metadata from the stream
func (s *MetadataStream) Receive() <-chan *PacketMetadata {
	return s.ch
}

// Close closes the metadata stream
func (s *MetadataStream) Close() {
	close(s.ch)
}
