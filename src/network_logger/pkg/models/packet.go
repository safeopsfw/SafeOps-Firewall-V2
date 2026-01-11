package models

import "time"

// PacketLog represents the complete JSON structure for a captured packet
type PacketLog struct {
	PacketID          string             `json:"packet_id"`
	Timestamp         Timestamp          `json:"timestamp"`
	CaptureInfo       CaptureInfo        `json:"capture_info"`
	Layers            Layers             `json:"layers"`
	ParsedApplication ParsedApplication  `json:"parsed_application"`
	FlowContext       *FlowContext       `json:"flow_context,omitempty"`
	SessionTracking   *SessionTracking   `json:"session_tracking,omitempty"`
	HotspotDevice     *HotspotDevice     `json:"hotspot_device,omitempty"`
	Deduplication     Deduplication      `json:"deduplication"`
}

// Timestamp represents packet capture time
type Timestamp struct {
	Epoch   float64 `json:"epoch"`
	ISO8601 string  `json:"iso8601"`
}

// CaptureInfo contains packet capture metadata
type CaptureInfo struct {
	Interface     string `json:"interface"`
	CaptureLength int    `json:"capture_length"`
	WireLength    int    `json:"wire_length"`
}

// Layers contains all protocol layers
type Layers struct {
	Datalink  *DatalinkLayer  `json:"datalink,omitempty"`
	Network   *NetworkLayer   `json:"network,omitempty"`
	Transport *TransportLayer `json:"transport,omitempty"`
	Payload   *PayloadLayer   `json:"payload,omitempty"`
}

// DatalinkLayer represents Layer 2 (Ethernet)
type DatalinkLayer struct {
	Type      string `json:"type"`
	SrcMAC    string `json:"src_mac"`
	DstMAC    string `json:"dst_mac"`
	Ethertype uint16 `json:"ethertype"`
	VlanID    *int   `json:"vlan_id,omitempty"`
}

// NetworkLayer represents Layer 3 (IP)
type NetworkLayer struct {
	Version        int    `json:"version"`
	HeaderLength   int    `json:"header_length,omitempty"`
	TOS            uint8  `json:"tos,omitempty"`
	DSCP           uint8  `json:"dscp,omitempty"`
	ECN            uint8  `json:"ecn,omitempty"`
	TotalLength    uint16 `json:"total_length,omitempty"`
	Identification uint16 `json:"identification,omitempty"`
	FlagsDF        bool   `json:"flags_df,omitempty"`
	FlagsMF        bool   `json:"flags_mf,omitempty"`
	FragmentOffset uint16 `json:"fragment_offset,omitempty"`
	TTL            uint8  `json:"ttl,omitempty"`
	Protocol       uint8  `json:"protocol"`
	HeaderChecksum uint16 `json:"header_checksum,omitempty"`
	SrcIP          string `json:"src_ip"`
	DstIP          string `json:"dst_ip"`
	// IPv6 specific fields
	TrafficClass  uint8  `json:"traffic_class,omitempty"`
	FlowLabel     uint32 `json:"flow_label,omitempty"`
	PayloadLength uint16 `json:"payload_length,omitempty"`
	NextHeader    uint8  `json:"next_header,omitempty"`
	HopLimit      uint8  `json:"hop_limit,omitempty"`
}

// TransportLayer represents Layer 4 (TCP/UDP)
type TransportLayer struct {
	Protocol      uint8       `json:"protocol"`
	SrcPort       uint16      `json:"src_port"`
	DstPort       uint16      `json:"dst_port"`
	TCPSeq        uint32      `json:"tcp_seq,omitempty"`
	TCPAck        uint32      `json:"tcp_ack,omitempty"`
	TCPDataOffset int         `json:"tcp_data_offset,omitempty"`
	TCPFlags      *TCPFlags   `json:"tcp_flags,omitempty"`
	TCPWindow     uint16      `json:"tcp_window,omitempty"`
	TCPChecksum   uint16      `json:"tcp_checksum,omitempty"`
	TCPUrgent     uint16      `json:"tcp_urgent,omitempty"`
	TCPOptions    []TCPOption `json:"tcp_options,omitempty"`
	UDPLength     uint16      `json:"udp_length,omitempty"`
	UDPChecksum   uint16      `json:"udp_checksum,omitempty"`
}

// TCPFlags represents TCP control flags
type TCPFlags struct {
	FIN bool `json:"fin"`
	SYN bool `json:"syn"`
	RST bool `json:"rst"`
	PSH bool `json:"psh"`
	ACK bool `json:"ack"`
	URG bool `json:"urg"`
	ECE bool `json:"ece"`
	CWR bool `json:"cwr"`
	NS  int  `json:"ns"`
}

// TCPOption represents a TCP option
type TCPOption struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

// PayloadLayer contains raw payload data
type PayloadLayer struct {
	Length  int    `json:"length"`
	DataHex string `json:"data_hex,omitempty"`
	Preview string `json:"preview,omitempty"`
}

// ParsedApplication contains application layer protocol data
type ParsedApplication struct {
	DetectedProtocol string      `json:"detected_protocol"`
	Confidence       string      `json:"confidence"`
	UserAgent        string      `json:"user_agent,omitempty"`
	HTTPFromTLS      bool        `json:"http_from_tls,omitempty"`
	DNS              *DNSData    `json:"dns,omitempty"`
	HTTP             *HTTPData   `json:"http,omitempty"`
	TLS              *TLSData    `json:"tls,omitempty"`
	Gaming           *GamingData `json:"gaming,omitempty"`
}

// DNSData represents DNS protocol data
type DNSData struct {
	TransactionID uint16      `json:"transaction_id"`
	Flags         uint16      `json:"flags"`
	QR            uint8       `json:"qr"`
	Opcode        uint8       `json:"opcode"`
	AA            uint8       `json:"aa"`
	TC            uint8       `json:"tc"`
	RD            uint8       `json:"rd"`
	RA            uint8       `json:"ra"`
	Z             uint8       `json:"z"`
	Rcode         uint8       `json:"rcode"`
	Queries       []DNSQuery  `json:"queries,omitempty"`
	Answers       []DNSAnswer `json:"answers,omitempty"`
}

// DNSQuery represents a DNS query
type DNSQuery struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// DNSAnswer represents a DNS answer
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

// HTTPData represents HTTP protocol data
type HTTPData struct {
	Type          string            `json:"type"` // "request" or "response"
	Method        string            `json:"method,omitempty"`
	URI           string            `json:"uri,omitempty"`
	Version       string            `json:"version,omitempty"`
	Host          string            `json:"host,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	StatusMessage string            `json:"status_message,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       string            `json:"cookies,omitempty"`
	Referer       string            `json:"referer,omitempty"`
	BodyPreview   string            `json:"body_preview,omitempty"`
	BodyLength    int               `json:"body_length,omitempty"`
}

// TLSData represents TLS protocol data
type TLSData struct {
	ClientHello         *TLSClientHello `json:"client_hello,omitempty"`
	ServerHello         *TLSServerHello `json:"server_hello,omitempty"`
	CertificatesPresent bool            `json:"certificates_present,omitempty"`
	Decryption          *TLSDecryption  `json:"decryption,omitempty"`
}

// TLSClientHello represents TLS ClientHello message
type TLSClientHello struct {
	Version      string   `json:"version"`
	Random       string   `json:"random"`
	CipherSuites []string `json:"cipher_suites"`
	SNI          string   `json:"sni,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	Extensions   []TLSExt `json:"extensions,omitempty"`
}

// TLSServerHello represents TLS ServerHello message
type TLSServerHello struct {
	Version     string   `json:"version"`
	Random      string   `json:"random"`
	CipherSuite string   `json:"cipher_suite"`
	Extensions  []TLSExt `json:"extensions,omitempty"`
}

// TLSExt represents a TLS extension
type TLSExt struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

// TLSDecryption represents TLS decryption status and data
type TLSDecryption struct {
	Decrypted        bool      `json:"decrypted"`
	KeyAvailable     bool      `json:"key_available"`
	Cipher           string    `json:"cipher,omitempty"`
	DecryptedLength  int       `json:"decrypted_length,omitempty"`
	DecryptedHex     string    `json:"decrypted_payload_hex,omitempty"`
	DecryptedBase64  string    `json:"decrypted_payload_base64,omitempty"`
	DecryptedPreview string    `json:"decrypted_preview,omitempty"`
	HTTPParsed       bool      `json:"http_parsed,omitempty"`
	HTTPData         *HTTPData `json:"http_data,omitempty"`
	Note             string    `json:"note,omitempty"`
}

// GamingData represents gaming protocol detection
type GamingData struct {
	Service   string `json:"service"`
	Detected  bool   `json:"detected"`
	Signature string `json:"signature,omitempty"`
}

// FlowContext represents bidirectional flow tracking
type FlowContext struct {
	FlowID          string       `json:"flow_id"`
	Direction       string       `json:"direction"`
	PacketsForward  int          `json:"packets_forward"`
	PacketsBackward int          `json:"packets_backward"`
	BytesForward    int64        `json:"bytes_forward"`
	BytesBackward   int64        `json:"bytes_backward"`
	FlowStartTime   float64      `json:"flow_start_time"`
	FlowDuration    float64      `json:"flow_duration"`
	FlowState       string       `json:"flow_state"`
	TCPState        string       `json:"tcp_state,omitempty"`
	ProcessInfo     *ProcessInfo `json:"process,omitempty"`
}

// SessionTracking represents session-level tracking
type SessionTracking struct {
	SessionID    string  `json:"session_id"`
	TotalPackets int     `json:"total_packets"`
	TotalBytes   int64   `json:"total_bytes"`
	Duration     float64 `json:"duration"`
}

// ProcessInfo represents Windows process information
type ProcessInfo struct {
	PID     int32  `json:"pid"`
	Name    string `json:"name"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline,omitempty"`
}

// HotspotDevice represents a device connected to Windows hotspot
type HotspotDevice struct {
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	Vendor     string    `json:"vendor"`
	DeviceType string    `json:"device_type"` // "mobile", "laptop", "tablet", "unknown"
	Hostname   string    `json:"hostname,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Deduplication represents deduplication status
type Deduplication struct {
	Unique bool   `json:"unique"`
	Reason string `json:"reason"`
}

// RawPacket represents a captured packet from Npcap
type RawPacket struct {
	Data      []byte
	Timestamp time.Time
	Length    int
	WireLen   int
	Interface string
}
