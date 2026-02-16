package models

import "time"

// GeoInfo contains geolocation data for an IP
type GeoInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"lat,omitempty"`
	Longitude   float64 `json:"lon,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty"`
}

// PacketLog represents the complete JSON structure for a captured packet
type PacketLog struct {
	PacketID          string            `json:"packet_id"`
	Timestamp         Timestamp         `json:"timestamp"`
	EventType         string            `json:"event_type,omitempty"`  // "packet" for master log
	CommunityID       string            `json:"community_id,omitempty"` // Community ID v1 for cross-tool correlation
	Direction         string            `json:"direction,omitempty"`   // "inbound"/"outbound"/"internal"
	AppProto          string            `json:"app_proto,omitempty"`   // Clean protocol name: dns/http/tls/ssh/etc
	CaptureInfo       CaptureInfo       `json:"capture_info"`
	Layers            Layers            `json:"layers"`
	ParsedApplication ParsedApplication `json:"parsed_application"`
	FlowContext       *FlowContext      `json:"flow_context,omitempty"`
	HotspotDevice     *HotspotDevice    `json:"hotspot_device,omitempty"`
	SrcGeo            *GeoInfo          `json:"src_geo,omitempty"`
	DstGeo            *GeoInfo          `json:"dst_geo,omitempty"`
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
	ICMP      *ICMPLayer      `json:"icmp,omitempty"`
	ARP       *ARPLayer       `json:"arp,omitempty"`
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

// ICMPLayer represents ICMP protocol data
type ICMPLayer struct {
	Type     uint8  `json:"type"`
	Code     uint8  `json:"code"`
	Checksum uint16 `json:"checksum,omitempty"`
	ID       uint16 `json:"id,omitempty"`
	Seq      uint16 `json:"seq,omitempty"`
}

// ARPLayer represents ARP protocol data
type ARPLayer struct {
	Operation       uint16 `json:"operation"`         // 1=request, 2=reply
	OperationString string `json:"operation_str,omitempty"`
	SenderMAC       string `json:"sender_mac,omitempty"`
	SenderIP        string `json:"sender_ip,omitempty"`
	TargetMAC       string `json:"target_mac,omitempty"`
	TargetIP        string `json:"target_ip,omitempty"`
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
	FIN bool `json:"fin,omitempty"`
	SYN bool `json:"syn,omitempty"`
	RST bool `json:"rst,omitempty"`
	PSH bool `json:"psh,omitempty"`
	ACK bool `json:"ack,omitempty"`
	URG bool `json:"urg,omitempty"`
	ECE bool `json:"ece,omitempty"`
	CWR bool `json:"cwr,omitempty"`
	NS  int  `json:"ns,omitempty"`
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
	TransactionID uint16      `json:"transaction_id,omitempty"`
	Flags         uint16      `json:"flags,omitempty"`
	QR            uint8       `json:"qr"`
	Opcode        uint8       `json:"opcode,omitempty"`
	AA            uint8       `json:"aa,omitempty"`
	TC            uint8       `json:"tc,omitempty"`
	RD            uint8       `json:"rd,omitempty"`
	RA            uint8       `json:"ra,omitempty"`
	Z             uint8       `json:"z,omitempty"`
	Rcode         uint8       `json:"rcode,omitempty"`
	RcodeString   string      `json:"rcode_str,omitempty"` // "NOERROR","NXDOMAIN","SERVFAIL"
	Queries       []DNSQuery  `json:"queries,omitempty"`
	Answers       []DNSAnswer `json:"answers,omitempty"`
}

// DNSQuery represents a DNS query
type DNSQuery struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class,omitempty"`
}

// DNSAnswer represents a DNS answer
type DNSAnswer struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	Class string `json:"class,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	Data  string `json:"data"`
}

// HTTPData represents HTTP protocol data
type HTTPData struct {
	Type          string            `json:"type,omitempty"`  // "request" or "response"
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
	JA3Hash             string          `json:"ja3,omitempty"`   // JA3 fingerprint from ClientHello
	JA3SHash            string          `json:"ja3s,omitempty"`  // JA3S fingerprint from ServerHello
	CertificatesPresent bool            `json:"certificates_present,omitempty"`
	Decryption          *TLSDecryption  `json:"decryption,omitempty"`
}

// TLSClientHello represents TLS ClientHello message
type TLSClientHello struct {
	Version        string   `json:"version"`
	Random         string   `json:"random,omitempty"`
	CipherSuites   []string `json:"cipher_suites,omitempty"`
	CipherSuiteIDs []uint16 `json:"cipher_suite_ids,omitempty"` // Raw IDs for JA3
	SNI            string   `json:"sni,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	Extensions     []TLSExt `json:"extensions,omitempty"`
	ExtensionIDs   []uint16 `json:"extension_ids,omitempty"`   // Raw extension type IDs for JA3
	ECCurves       []uint16 `json:"ec_curves,omitempty"`       // Supported elliptic curves for JA3
	ECPointFormats []uint8  `json:"ec_point_formats,omitempty"` // EC point formats for JA3
}

// TLSServerHello represents TLS ServerHello message
type TLSServerHello struct {
	Version       string   `json:"version"`
	Random        string   `json:"random,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	CipherSuiteID uint16   `json:"cipher_suite_id,omitempty"` // Raw ID for JA3S
	Extensions    []TLSExt `json:"extensions,omitempty"`
	ExtensionIDs  []uint16 `json:"extension_ids,omitempty"`  // Raw extension type IDs for JA3S
}

// TLSExt represents a TLS extension
type TLSExt struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

// TLSDecryption represents TLS decryption status and data
type TLSDecryption struct {
	Decrypted        bool      `json:"decrypted"`
	KeyAvailable     bool      `json:"key_available,omitempty"`
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
	Service   string `json:"service,omitempty"`
	Detected  bool   `json:"detected,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// FlowContext represents bidirectional flow tracking
type FlowContext struct {
	FlowID          string       `json:"flow_id"`
	Direction       string       `json:"direction,omitempty"`
	PacketsForward  int          `json:"packets_forward,omitempty"`
	PacketsBackward int          `json:"packets_backward,omitempty"`
	BytesForward    int64        `json:"bytes_forward,omitempty"`
	BytesBackward   int64        `json:"bytes_backward,omitempty"`
	FlowStartTime   float64      `json:"flow_start_time,omitempty"`
	FlowDuration    float64      `json:"flow_duration,omitempty"`
	FlowState       string       `json:"flow_state,omitempty"`
	TCPState        string       `json:"tcp_state,omitempty"`
	ProcessInfo     *ProcessInfo `json:"process,omitempty"`
}

// ProcessInfo represents Windows process information
type ProcessInfo struct {
	PID     int32  `json:"pid,omitempty"`
	Name    string `json:"name,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

// HotspotDevice represents a device connected to Windows hotspot
type HotspotDevice struct {
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	Vendor      string    `json:"vendor,omitempty"`
	DeviceType  string    `json:"device_type,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	BytesSent   int64     `json:"bytes_sent,omitempty"`
	BytesRecv   int64     `json:"bytes_recv,omitempty"`
	PacketsSent int64     `json:"packets_sent,omitempty"`
	PacketsRecv int64     `json:"packets_recv,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Deduplication represents deduplication status (internal use only, not written to logs)
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
