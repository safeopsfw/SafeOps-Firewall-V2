// Package models defines all core data structures used throughout the firewall engine.
package models

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	pb "safeops-engine/pkg/grpc/pb"
)

// ============================================================================
// Direction Types - Packet Flow Direction
// ============================================================================

// Direction represents the flow direction of a packet relative to the firewall.
type Direction int8

const (
	// DirectionAny matches both inbound and outbound traffic.
	DirectionAny Direction = 0

	// DirectionInbound represents traffic coming INTO the protected network.
	// WAN → LAN/WIFI direction
	DirectionInbound Direction = 1

	// DirectionOutbound represents traffic going OUT of the protected network.
	// LAN/WIFI → WAN direction
	DirectionOutbound Direction = 2

	// DirectionForward represents traffic passing through between interfaces.
	// LAN ↔ WIFI direction (inter-zone traffic)
	DirectionForward Direction = 3
)

// directionNames maps direction values to human-readable strings.
var directionNames = map[Direction]string{
	DirectionAny:      "ANY",
	DirectionInbound:  "INBOUND",
	DirectionOutbound: "OUTBOUND",
	DirectionForward:  "FORWARD",
}

// directionValues maps string names to direction values.
var directionValues = map[string]Direction{
	"ANY":      DirectionAny,
	"INBOUND":  DirectionInbound,
	"OUTBOUND": DirectionOutbound,
	"FORWARD":  DirectionForward,
	// Aliases
	"IN":  DirectionInbound,
	"OUT": DirectionOutbound,
	"FWD": DirectionForward,
}

// String returns the human-readable name of the direction.
func (d Direction) String() string {
	if name, ok := directionNames[d]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", d)
}

// IsValid checks if the direction is a recognized value.
func (d Direction) IsValid() bool {
	_, ok := directionNames[d]
	return ok
}

// Matches checks if this direction matches another.
// ANY matches everything, otherwise must be equal.
func (d Direction) Matches(other Direction) bool {
	if d == DirectionAny || other == DirectionAny {
		return true
	}
	return d == other
}

// DirectionFromString parses a string into a Direction.
func DirectionFromString(s string) (Direction, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if d, ok := directionValues[upper]; ok {
		return d, nil
	}
	return DirectionAny, fmt.Errorf("unknown direction: %q", s)
}

// MarshalJSON implements json.Marshaler.
func (d Direction) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Direction) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := DirectionFromString(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// ============================================================================
// Protocol Types
// ============================================================================

// Protocol represents the IP protocol number.
type Protocol uint8

const (
	// ProtocolAny matches any protocol.
	ProtocolAny Protocol = 0

	// ProtocolICMP is ICMP (Internet Control Message Protocol).
	ProtocolICMP Protocol = 1

	// ProtocolTCP is TCP (Transmission Control Protocol).
	ProtocolTCP Protocol = 6

	// ProtocolUDP is UDP (User Datagram Protocol).
	ProtocolUDP Protocol = 17

	// ProtocolICMPv6 is ICMPv6 (ICMP for IPv6).
	ProtocolICMPv6 Protocol = 58

	// ProtocolGRE is GRE (Generic Routing Encapsulation).
	ProtocolGRE Protocol = 47

	// ProtocolESP is ESP (Encapsulating Security Payload for IPsec).
	ProtocolESP Protocol = 50

	// ProtocolAH is AH (Authentication Header for IPsec).
	ProtocolAH Protocol = 51
)

// protocolNames maps protocol values to human-readable strings.
var protocolNames = map[Protocol]string{
	ProtocolAny:    "ANY",
	ProtocolICMP:   "ICMP",
	ProtocolTCP:    "TCP",
	ProtocolUDP:    "UDP",
	ProtocolICMPv6: "ICMPv6",
	ProtocolGRE:    "GRE",
	ProtocolESP:    "ESP",
	ProtocolAH:     "AH",
}

// protocolValues maps string names to protocol values.
var protocolValues = map[string]Protocol{
	"ANY":    ProtocolAny,
	"ICMP":   ProtocolICMP,
	"TCP":    ProtocolTCP,
	"UDP":    ProtocolUDP,
	"ICMPV6": ProtocolICMPv6,
	"GRE":    ProtocolGRE,
	"ESP":    ProtocolESP,
	"AH":     ProtocolAH,
	// Numeric aliases
	"0":  ProtocolAny,
	"1":  ProtocolICMP,
	"6":  ProtocolTCP,
	"17": ProtocolUDP,
	"58": ProtocolICMPv6,
}

// String returns the human-readable name of the protocol.
func (p Protocol) String() string {
	if name, ok := protocolNames[p]; ok {
		return name
	}
	return fmt.Sprintf("PROTO(%d)", p)
}

// IsValid checks if the protocol is a recognized value (or ANY).
func (p Protocol) IsValid() bool {
	// All values 0-255 are technically valid IP protocol numbers
	// but we return true for known protocols
	_, ok := protocolNames[p]
	return ok || p > 0 // Unknown but non-zero protocol is still valid
}

// Matches checks if this protocol matches another.
// ANY matches everything, otherwise must be equal.
func (p Protocol) Matches(other Protocol) bool {
	if p == ProtocolAny || other == ProtocolAny {
		return true
	}
	return p == other
}

// ProtocolFromString parses a string into a Protocol.
func ProtocolFromString(s string) (Protocol, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if p, ok := protocolValues[upper]; ok {
		return p, nil
	}
	// Try parsing as number
	if n, err := strconv.ParseUint(upper, 10, 8); err == nil {
		return Protocol(n), nil
	}
	return ProtocolAny, fmt.Errorf("unknown protocol: %q", s)
}

// MarshalJSON implements json.Marshaler.
func (p Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *Protocol) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try as number
		var n uint8
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return err
		}
		*p = Protocol(n)
		return nil
	}
	parsed, err := ProtocolFromString(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ============================================================================
// Domain Source Types
// ============================================================================

// DomainSource indicates how a domain name was extracted from the packet.
type DomainSource string

const (
	// DomainSourceNone indicates no domain was extracted.
	DomainSourceNone DomainSource = ""

	// DomainSourceDNS indicates domain was extracted from DNS query/response.
	DomainSourceDNS DomainSource = "DNS"

	// DomainSourceSNI indicates domain was extracted from TLS SNI extension.
	DomainSourceSNI DomainSource = "SNI"

	// DomainSourceHTTP indicates domain was extracted from HTTP Host header.
	DomainSourceHTTP DomainSource = "HTTP"

	// DomainSourceCache indicates domain was looked up from connection cache.
	DomainSourceCache DomainSource = "CACHE"
)

// ============================================================================
// TCP Flags
// ============================================================================

// TCPFlags represents TCP control flags.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 0x01
	TCPFlagSYN TCPFlags = 0x02
	TCPFlagRST TCPFlags = 0x04
	TCPFlagPSH TCPFlags = 0x08
	TCPFlagACK TCPFlags = 0x10
	TCPFlagURG TCPFlags = 0x20
	TCPFlagECE TCPFlags = 0x40
	TCPFlagCWR TCPFlags = 0x80
)

// HasFIN returns true if FIN flag is set.
func (f TCPFlags) HasFIN() bool { return f&TCPFlagFIN != 0 }

// HasSYN returns true if SYN flag is set.
func (f TCPFlags) HasSYN() bool { return f&TCPFlagSYN != 0 }

// HasRST returns true if RST flag is set.
func (f TCPFlags) HasRST() bool { return f&TCPFlagRST != 0 }

// HasPSH returns true if PSH flag is set.
func (f TCPFlags) HasPSH() bool { return f&TCPFlagPSH != 0 }

// HasACK returns true if ACK flag is set.
func (f TCPFlags) HasACK() bool { return f&TCPFlagACK != 0 }

// HasURG returns true if URG flag is set.
func (f TCPFlags) HasURG() bool { return f&TCPFlagURG != 0 }

// IsSYNOnly returns true if only SYN is set (connection initiation).
func (f TCPFlags) IsSYNOnly() bool { return f&(TCPFlagSYN|TCPFlagACK) == TCPFlagSYN }

// IsSYNACK returns true if both SYN and ACK are set (connection response).
func (f TCPFlags) IsSYNACK() bool { return f&(TCPFlagSYN|TCPFlagACK) == (TCPFlagSYN | TCPFlagACK) }

// IsACKOnly returns true if only ACK is set (established connection).
func (f TCPFlags) IsACKOnly() bool { return f&0x3F == TCPFlagACK }

// String returns a human-readable representation of the flags.
func (f TCPFlags) String() string {
	var flags []string
	if f.HasSYN() {
		flags = append(flags, "SYN")
	}
	if f.HasACK() {
		flags = append(flags, "ACK")
	}
	if f.HasFIN() {
		flags = append(flags, "FIN")
	}
	if f.HasRST() {
		flags = append(flags, "RST")
	}
	if f.HasPSH() {
		flags = append(flags, "PSH")
	}
	if f.HasURG() {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		return "NONE"
	}
	return strings.Join(flags, "|")
}

// ============================================================================
// PacketMetadata - Core packet information for rule matching
// ============================================================================

// PacketMetadata contains all extracted information from a network packet
// that is needed for firewall rule evaluation. This structure is designed
// to be efficient for high-speed matching operations.
type PacketMetadata struct {
	// === Packet Identification ===

	// PacketID is the unique identifier assigned by SafeOps Engine.
	// Used for correlating verdicts back to packets.
	PacketID uint64 `json:"packet_id"`

	// Timestamp is when the packet was captured (nanoseconds since epoch).
	Timestamp int64 `json:"timestamp"`

	// === Network Layer (L3) ===

	// SrcIP is the source IP address as a string.
	SrcIP string `json:"src_ip"`

	// DstIP is the destination IP address as a string.
	DstIP string `json:"dst_ip"`

	// SrcIPParsed is the parsed source IP for efficient matching.
	SrcIPParsed net.IP `json:"-"`

	// DstIPParsed is the parsed destination IP for efficient matching.
	DstIPParsed net.IP `json:"-"`

	// === Transport Layer (L4) ===

	// Protocol is the IP protocol number (6=TCP, 17=UDP, etc.).
	Protocol Protocol `json:"protocol"`

	// SrcPort is the source port number (0 for ICMP).
	SrcPort uint16 `json:"src_port"`

	// DstPort is the destination port number (0 for ICMP).
	DstPort uint16 `json:"dst_port"`

	// === TCP-Specific ===

	// TCPFlags contains the TCP control flags.
	TCPFlags TCPFlags `json:"tcp_flags,omitempty"`

	// IsSYN indicates if this is a SYN packet (connection start).
	IsSYN bool `json:"is_syn,omitempty"`

	// IsACK indicates if ACK flag is set.
	IsACK bool `json:"is_ack,omitempty"`

	// IsRST indicates if RST flag is set (connection reset).
	IsRST bool `json:"is_rst,omitempty"`

	// IsFIN indicates if FIN flag is set (connection close).
	IsFIN bool `json:"is_fin,omitempty"`

	// === Packet Metadata ===

	// PacketSize is the total packet size in bytes.
	PacketSize uint32 `json:"packet_size"`

	// Direction indicates if traffic is inbound or outbound.
	Direction Direction `json:"direction"`

	// AdapterIndex is the network interface index.
	AdapterIndex uint32 `json:"adapter_index,omitempty"`

	// AdapterName is the network interface name (WAN, LAN, WIFI).
	AdapterName string `json:"adapter_name,omitempty"`

	// === Application Layer (L7) ===

	// Domain is the extracted domain name (from DNS, SNI, or HTTP).
	// Empty if no domain could be extracted.
	Domain string `json:"domain,omitempty"`

	// DomainSource indicates how the domain was extracted.
	DomainSource DomainSource `json:"domain_source,omitempty"`

	// === Protocol Detection ===

	// IsDNSQuery is true if this is a DNS query packet.
	IsDNSQuery bool `json:"is_dns_query,omitempty"`

	// IsDNSResponse is true if this is a DNS response packet.
	IsDNSResponse bool `json:"is_dns_response,omitempty"`

	// IsHTTP is true if this is an HTTP request/response.
	IsHTTP bool `json:"is_http,omitempty"`

	// HTTPMethod is the HTTP method (GET, POST, etc.) if IsHTTP is true.
	HTTPMethod string `json:"http_method,omitempty"`

	// === Performance Optimization ===

	// CacheKey is a pre-computed key for verdict caching.
	// Format: "src_ip:dst_ip:proto:dport"
	CacheKey string `json:"cache_key,omitempty"`

	// ConnectionState is the current connection state (for stateful matching).
	ConnectionState ConnectionState `json:"connection_state,omitempty"`

	// === Zone Information ===

	// SourceZone is the security zone of the source interface.
	SourceZone string `json:"source_zone,omitempty"`

	// DestinationZone is the security zone of the destination interface.
	DestinationZone string `json:"destination_zone,omitempty"`
}

// NewPacketMetadata creates a new PacketMetadata with initialized fields.
func NewPacketMetadata() *PacketMetadata {
	return &PacketMetadata{
		Timestamp:       time.Now().UnixNano(),
		ConnectionState: StateNew,
	}
}

// FromProtoMetadata converts a protobuf PacketMetadata to this internal format.
// This is the primary way packets are received from SafeOps Engine.
func FromProtoMetadata(proto *pb.PacketMetadata) *PacketMetadata {
	if proto == nil {
		return nil
	}

	// Parse direction
	dir := DirectionOutbound
	if strings.ToUpper(proto.Direction) == "INBOUND" {
		dir = DirectionInbound
	} else if strings.ToUpper(proto.Direction) == "FORWARD" {
		dir = DirectionForward
	}

	// Create metadata
	pkt := &PacketMetadata{
		PacketID:      proto.PacketId,
		Timestamp:     proto.Timestamp,
		SrcIP:         proto.SrcIp,
		DstIP:         proto.DstIp,
		SrcPort:       uint16(proto.SrcPort),
		DstPort:       uint16(proto.DstPort),
		Protocol:      Protocol(proto.Protocol),
		PacketSize:    proto.PacketSize,
		Direction:     dir,
		AdapterName:   proto.AdapterName,
		Domain:        proto.Domain,
		DomainSource:  DomainSource(proto.DomainSource),
		TCPFlags:      TCPFlags(proto.TcpFlags),
		IsSYN:         proto.IsSyn,
		IsACK:         proto.IsAck,
		IsRST:         proto.IsRst,
		IsFIN:         proto.IsFin,
		IsDNSQuery:    proto.IsDnsQuery,
		IsDNSResponse: proto.IsDnsResponse,
		IsHTTP:        proto.IsHttp,
		HTTPMethod:    proto.HttpMethod,
		CacheKey:      proto.CacheKey,
	}

	// Parse IP addresses for efficient matching
	pkt.SrcIPParsed = net.ParseIP(proto.SrcIp)
	pkt.DstIPParsed = net.ParseIP(proto.DstIp)

	// Determine initial connection state from TCP flags
	if pkt.Protocol == ProtocolTCP {
		pkt.ConnectionState = pkt.inferConnectionState()
	}

	return pkt
}

// inferConnectionState determines the connection state based on TCP flags.
func (p *PacketMetadata) inferConnectionState() ConnectionState {
	if p.Protocol != ProtocolTCP {
		return StateNew
	}

	if p.IsRST {
		return StateInvalid
	}

	if p.IsSYN && !p.IsACK {
		return StateNew // SYN only = new connection
	}

	if p.IsSYN && p.IsACK {
		return StateNew // SYN-ACK = still part of handshake
	}

	if p.IsFIN {
		return StateClosing
	}

	if p.IsACK {
		return StateEstablished
	}

	return StateNew
}

// GenerateCacheKey generates a cache key for verdict caching.
// Format: "protocol:src_ip:dst_ip:dst_port"
func (p *PacketMetadata) GenerateCacheKey() string {
	if p.CacheKey != "" {
		return p.CacheKey
	}
	p.CacheKey = fmt.Sprintf("%d:%s:%s:%d", p.Protocol, p.SrcIP, p.DstIP, p.DstPort)
	return p.CacheKey
}

// GenerateFlowKey generates a bi-directional flow key for connection tracking.
// The key is the same regardless of packet direction.
func (p *PacketMetadata) GenerateFlowKey() string {
	// Normalize by ordering IPs alphabetically
	if p.SrcIP < p.DstIP {
		return fmt.Sprintf("%d:%s:%d:%s:%d", p.Protocol, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	return fmt.Sprintf("%d:%s:%d:%s:%d", p.Protocol, p.DstIP, p.DstPort, p.SrcIP, p.SrcPort)
}

// GetTimestampTime returns the timestamp as a time.Time.
func (p *PacketMetadata) GetTimestampTime() time.Time {
	return time.Unix(0, p.Timestamp)
}

// IsIPv6 returns true if either source or destination is an IPv6 address.
func (p *PacketMetadata) IsIPv6() bool {
	if p.SrcIPParsed != nil {
		return p.SrcIPParsed.To4() == nil
	}
	return strings.Contains(p.SrcIP, ":")
}

// IsTCP returns true if this is a TCP packet.
func (p *PacketMetadata) IsTCP() bool {
	return p.Protocol == ProtocolTCP
}

// IsUDP returns true if this is a UDP packet.
func (p *PacketMetadata) IsUDP() bool {
	return p.Protocol == ProtocolUDP
}

// IsICMP returns true if this is an ICMP or ICMPv6 packet.
func (p *PacketMetadata) IsICMP() bool {
	return p.Protocol == ProtocolICMP || p.Protocol == ProtocolICMPv6
}

// IsDNS returns true if this is a DNS packet (query or response).
func (p *PacketMetadata) IsDNS() bool {
	return p.IsDNSQuery || p.IsDNSResponse ||
		(p.DstPort == 53 || p.SrcPort == 53)
}

// HasDomain returns true if a domain was extracted from the packet.
func (p *PacketMetadata) HasDomain() bool {
	return p.Domain != ""
}

// IsNewConnection returns true if this packet starts a new connection.
func (p *PacketMetadata) IsNewConnection() bool {
	if p.Protocol == ProtocolTCP {
		return p.IsSYN && !p.IsACK
	}
	// For UDP/ICMP, we treat first packet as new
	return p.ConnectionState == StateNew
}

// IsEstablished returns true if this packet is part of an established connection.
func (p *PacketMetadata) IsEstablished() bool {
	return p.ConnectionState == StateEstablished
}

// String returns a human-readable summary of the packet.
func (p *PacketMetadata) String() string {
	proto := p.Protocol.String()
	if p.Protocol == ProtocolTCP || p.Protocol == ProtocolUDP {
		return fmt.Sprintf("[%s] %s:%d → %s:%d (%s, %d bytes)",
			proto, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Direction, p.PacketSize)
	}
	return fmt.Sprintf("[%s] %s → %s (%s, %d bytes)",
		proto, p.SrcIP, p.DstIP, p.Direction, p.PacketSize)
}

// LogFields returns a map of fields suitable for structured logging.
func (p *PacketMetadata) LogFields() map[string]interface{} {
	fields := map[string]interface{}{
		"packet_id":   p.PacketID,
		"src_ip":      p.SrcIP,
		"dst_ip":      p.DstIP,
		"protocol":    p.Protocol.String(),
		"direction":   p.Direction.String(),
		"packet_size": p.PacketSize,
	}

	if p.Protocol == ProtocolTCP || p.Protocol == ProtocolUDP {
		fields["src_port"] = p.SrcPort
		fields["dst_port"] = p.DstPort
	}

	if p.Domain != "" {
		fields["domain"] = p.Domain
		fields["domain_source"] = string(p.DomainSource)
	}

	if p.AdapterName != "" {
		fields["adapter"] = p.AdapterName
	}

	return fields
}

// Clone creates a deep copy of the PacketMetadata.
func (p *PacketMetadata) Clone() *PacketMetadata {
	if p == nil {
		return nil
	}
	clone := *p
	// Deep copy IP slices
	if p.SrcIPParsed != nil {
		clone.SrcIPParsed = make(net.IP, len(p.SrcIPParsed))
		copy(clone.SrcIPParsed, p.SrcIPParsed)
	}
	if p.DstIPParsed != nil {
		clone.DstIPParsed = make(net.IP, len(p.DstIPParsed))
		copy(clone.DstIPParsed, p.DstIPParsed)
	}
	return &clone
}
