// Package dns provides core DNS protocol types and utilities.
// These types abstract the binary DNS wire format (RFC 1035) into clean Go structures.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ============================================================================
// DNS Record Types (IANA registry)
// ============================================================================

// RecordType represents DNS resource record types
type RecordType uint16

const (
	TypeA     RecordType = 1   // IPv4 address
	TypeNS    RecordType = 2   // Authoritative nameserver
	TypeCNAME RecordType = 5   // Canonical name alias
	TypeSOA   RecordType = 6   // Start of authority
	TypePTR   RecordType = 12  // Pointer for reverse DNS
	TypeMX    RecordType = 15  // Mail exchange
	TypeTXT   RecordType = 16  // Text record
	TypeAAAA  RecordType = 28  // IPv6 address
	TypeSRV   RecordType = 33  // Service locator
	TypeANY   RecordType = 255 // Wildcard query
)

// String returns human-readable record type name
func (rt RecordType) String() string {
	switch rt {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeANY:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", rt)
	}
}

// ParseRecordType converts string to RecordType
func ParseRecordType(s string) (RecordType, error) {
	switch strings.ToUpper(s) {
	case "A":
		return TypeA, nil
	case "NS":
		return TypeNS, nil
	case "CNAME":
		return TypeCNAME, nil
	case "SOA":
		return TypeSOA, nil
	case "PTR":
		return TypePTR, nil
	case "MX":
		return TypeMX, nil
	case "TXT":
		return TypeTXT, nil
	case "AAAA":
		return TypeAAAA, nil
	case "SRV":
		return TypeSRV, nil
	case "ANY":
		return TypeANY, nil
	default:
		return 0, fmt.Errorf("unknown record type: %s", s)
	}
}

// ============================================================================
// DNS Classes
// ============================================================================

// Class represents DNS class (namespace for DNS data)
type Class uint16

const (
	ClassIN Class = 1 // Internet (99.9% of queries)
	ClassCS Class = 2 // CSNET (obsolete)
	ClassCH Class = 3 // Chaos (experimental)
	ClassHS Class = 4 // Hesiod (MIT name service)
)

// String returns human-readable class name
func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	case ClassCS:
		return "CS"
	case ClassCH:
		return "CH"
	case ClassHS:
		return "HS"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// ============================================================================
// DNS Response Codes (RCODE)
// ============================================================================

// ResponseCode represents DNS response codes
type ResponseCode uint8

const (
	RCodeNoError        ResponseCode = 0 // Success
	RCodeFormError      ResponseCode = 1 // Query format error
	RCodeServFail       ResponseCode = 2 // Server failure
	RCodeNXDomain       ResponseCode = 3 // Domain doesn't exist
	RCodeNotImplemented ResponseCode = 4 // Operation not implemented
	RCodeRefused        ResponseCode = 5 // Query refused
)

// String returns human-readable response code name
func (rc ResponseCode) String() string {
	switch rc {
	case RCodeNoError:
		return "NOERROR"
	case RCodeFormError:
		return "FORMERR"
	case RCodeServFail:
		return "SERVFAIL"
	case RCodeNXDomain:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rc)
	}
}

// IsError returns true if response code indicates an error
func (rc ResponseCode) IsError() bool {
	return rc != RCodeNoError
}

// ============================================================================
// DNS Message (Query/Response)
// ============================================================================

// Message represents a complete DNS message (query or response)
type Message struct {
	ID         uint16           // Transaction ID
	Flags      MessageFlags     // Control and status flags
	Questions  []Question       // Question section
	Answers    []ResourceRecord // Answer section
	Authority  []ResourceRecord // Authority section
	Additional []ResourceRecord // Additional section
}

// NewMessage creates a new DNS message with given ID
func NewMessage(id uint16) *Message {
	return &Message{
		ID:         id,
		Questions:  make([]Question, 0, 1),
		Answers:    make([]ResourceRecord, 0, 4),
		Authority:  make([]ResourceRecord, 0, 4),
		Additional: make([]ResourceRecord, 0, 4),
	}
}

// IsQuery returns true if message is a query
func (m *Message) IsQuery() bool {
	return !m.Flags.QR
}

// IsResponse returns true if message is a response
func (m *Message) IsResponse() bool {
	return m.Flags.QR
}

// SetResponse marks message as a response
func (m *Message) SetResponse() {
	m.Flags.QR = true
}

// AddQuestion adds a question to the message
func (m *Message) AddQuestion(q Question) {
	m.Questions = append(m.Questions, q)
}

// AddAnswer adds an answer record to the message
func (m *Message) AddAnswer(rr ResourceRecord) {
	m.Answers = append(m.Answers, rr)
}

// AddAuthority adds an authority record to the message
func (m *Message) AddAuthority(rr ResourceRecord) {
	m.Authority = append(m.Authority, rr)
}

// AddAdditional adds an additional record to the message
func (m *Message) AddAdditional(rr ResourceRecord) {
	m.Additional = append(m.Additional, rr)
}

// ============================================================================
// Message Flags
// ============================================================================

// MessageFlags represents the 16-bit DNS flags field
type MessageFlags struct {
	QR     bool         // Query (false) or Response (true)
	Opcode uint8        // Operation code (4 bits)
	AA     bool         // Authoritative Answer
	TC     bool         // Truncated
	RD     bool         // Recursion Desired
	RA     bool         // Recursion Available
	Z      uint8        // Reserved (3 bits)
	RCODE  ResponseCode // Response code (4 bits)
}

// ToUint16 packs flags into 16-bit integer for wire format
func (f *MessageFlags) ToUint16() uint16 {
	var flags uint16
	if f.QR {
		flags |= 0x8000
	}
	flags |= uint16(f.Opcode&0x0F) << 11
	if f.AA {
		flags |= 0x0400
	}
	if f.TC {
		flags |= 0x0200
	}
	if f.RD {
		flags |= 0x0100
	}
	if f.RA {
		flags |= 0x0080
	}
	flags |= uint16(f.Z&0x07) << 4
	flags |= uint16(f.RCODE & 0x0F)
	return flags
}

// FromUint16 unpacks 16-bit integer into flags structure
func (f *MessageFlags) FromUint16(flags uint16) {
	f.QR = (flags & 0x8000) != 0
	f.Opcode = uint8((flags >> 11) & 0x0F)
	f.AA = (flags & 0x0400) != 0
	f.TC = (flags & 0x0200) != 0
	f.RD = (flags & 0x0100) != 0
	f.RA = (flags & 0x0080) != 0
	f.Z = uint8((flags >> 4) & 0x07)
	f.RCODE = ResponseCode(flags & 0x0F)
}

// ============================================================================
// DNS Question
// ============================================================================

// Question represents a DNS question section entry
type Question struct {
	Name  string     // FQDN being queried
	Type  RecordType // Record type (A, AAAA, etc.)
	Class Class      // Class (IN for Internet)
}

// NewQuestion creates a new DNS question
func NewQuestion(name string, qtype RecordType, qclass Class) Question {
	return Question{
		Name:  name,
		Type:  qtype,
		Class: qclass,
	}
}

// String returns human-readable question representation
func (q Question) String() string {
	return fmt.Sprintf("%s %s %s", q.Name, q.Class, q.Type)
}

// ============================================================================
// DNS Resource Record
// ============================================================================

// ResourceRecord represents a DNS resource record
type ResourceRecord struct {
	Name       string      // FQDN
	Type       RecordType  // Record type
	Class      Class       // Class (IN)
	TTL        uint32      // Time-to-live in seconds
	RData      []byte      // Raw binary data
	ParsedData interface{} // Parsed data (type assertion required)
}

// NewResourceRecord creates a new resource record
func NewResourceRecord(name string, rtype RecordType, class Class, ttl uint32) ResourceRecord {
	return ResourceRecord{
		Name:  name,
		Type:  rtype,
		Class: class,
		TTL:   ttl,
	}
}

// String returns human-readable record representation
func (rr ResourceRecord) String() string {
	var value string
	switch rr.Type {
	case TypeA, TypeAAAA:
		if rr.ParsedData != nil {
			if ip, ok := rr.ParsedData.(net.IP); ok {
				value = ip.String()
			}
		}
	case TypeCNAME, TypeNS, TypePTR:
		if rr.ParsedData != nil {
			if s, ok := rr.ParsedData.(string); ok {
				value = s
			}
		}
	case TypeMX:
		if rr.ParsedData != nil {
			if mx, ok := rr.ParsedData.(*MXRecord); ok {
				value = fmt.Sprintf("%d %s", mx.Priority, mx.MailServer)
			}
		}
	default:
		value = fmt.Sprintf("[%d bytes]", len(rr.RData))
	}
	return fmt.Sprintf("%s. %d %s %s %s", rr.Name, rr.TTL, rr.Class, rr.Type, value)
}

// SetA sets record as A type with IPv4 address
func (rr *ResourceRecord) SetA(ip net.IP) {
	rr.Type = TypeA
	ip4 := ip.To4()
	if ip4 == nil {
		rr.RData = ip
	} else {
		rr.RData = ip4
	}
	rr.ParsedData = ip
}

// SetAAAA sets record as AAAA type with IPv6 address
func (rr *ResourceRecord) SetAAAA(ip net.IP) {
	rr.Type = TypeAAAA
	rr.RData = ip.To16()
	rr.ParsedData = ip
}

// SetCNAME sets record as CNAME type
func (rr *ResourceRecord) SetCNAME(target string) {
	rr.Type = TypeCNAME
	rr.RData = EncodeDomainName(target)
	rr.ParsedData = target
}

// SetMX sets record as MX type
func (rr *ResourceRecord) SetMX(priority uint16, mailserver string) {
	rr.Type = TypeMX
	rr.RData = append(PackUint16(priority), EncodeDomainName(mailserver)...)
	rr.ParsedData = &MXRecord{Priority: priority, MailServer: mailserver}
}

// SetTXT sets record as TXT type
func (rr *ResourceRecord) SetTXT(texts []string) {
	rr.Type = TypeTXT
	var buf []byte
	for _, txt := range texts {
		if len(txt) > 255 {
			txt = txt[:255]
		}
		buf = append(buf, byte(len(txt)))
		buf = append(buf, []byte(txt)...)
	}
	rr.RData = buf
	rr.ParsedData = texts
}

// SetNS sets record as NS type
func (rr *ResourceRecord) SetNS(nameserver string) {
	rr.Type = TypeNS
	rr.RData = EncodeDomainName(nameserver)
	rr.ParsedData = nameserver
}

// SetPTR sets record as PTR type for reverse DNS
func (rr *ResourceRecord) SetPTR(hostname string) {
	rr.Type = TypePTR
	rr.RData = EncodeDomainName(hostname)
	rr.ParsedData = hostname
}

// SetSRV sets record as SRV type
func (rr *ResourceRecord) SetSRV(priority, weight, port uint16, target string) {
	rr.Type = TypeSRV
	buf := make([]byte, 0, 6+len(target)+2)
	buf = append(buf, PackUint16(priority)...)
	buf = append(buf, PackUint16(weight)...)
	buf = append(buf, PackUint16(port)...)
	buf = append(buf, EncodeDomainName(target)...)
	rr.RData = buf
	rr.ParsedData = &SRVRecord{Priority: priority, Weight: weight, Port: port, Target: target}
}

// Parse interprets RData based on record type
func (rr *ResourceRecord) Parse() error {
	switch rr.Type {
	case TypeA:
		if len(rr.RData) < 4 {
			return errors.New("A record: insufficient data")
		}
		rr.ParsedData = net.IP(rr.RData[:4])
	case TypeAAAA:
		if len(rr.RData) < 16 {
			return errors.New("AAAA record: insufficient data")
		}
		rr.ParsedData = net.IP(rr.RData[:16])
	case TypeCNAME, TypeNS, TypePTR:
		name, _, err := DecodeDomainName(rr.RData, 0)
		if err != nil {
			return err
		}
		rr.ParsedData = name
	case TypeMX:
		if len(rr.RData) < 3 {
			return errors.New("MX record: insufficient data")
		}
		priority := UnpackUint16(rr.RData[:2])
		mailserver, _, err := DecodeDomainName(rr.RData, 2)
		if err != nil {
			return err
		}
		rr.ParsedData = &MXRecord{Priority: priority, MailServer: mailserver}
	case TypeTXT:
		texts := []string{}
		offset := 0
		for offset < len(rr.RData) {
			length := int(rr.RData[offset])
			offset++
			if offset+length > len(rr.RData) {
				break
			}
			texts = append(texts, string(rr.RData[offset:offset+length]))
			offset += length
		}
		rr.ParsedData = texts
	case TypeSRV:
		if len(rr.RData) < 7 {
			return errors.New("SRV record: insufficient data")
		}
		priority := UnpackUint16(rr.RData[:2])
		weight := UnpackUint16(rr.RData[2:4])
		port := UnpackUint16(rr.RData[4:6])
		target, _, err := DecodeDomainName(rr.RData, 6)
		if err != nil {
			return err
		}
		rr.ParsedData = &SRVRecord{Priority: priority, Weight: weight, Port: port, Target: target}
	}
	return nil
}

// ============================================================================
// Structured Record Data Types
// ============================================================================

// MXRecord represents parsed MX record data
type MXRecord struct {
	Priority   uint16 // Lower = higher priority
	MailServer string // Mail server FQDN
}

// SRVRecord represents parsed SRV record data
type SRVRecord struct {
	Priority uint16 // Lower = higher priority
	Weight   uint16 // Load balancing weight
	Port     uint16 // Service port
	Target   string // Service host FQDN
}

// SOARecord represents parsed SOA record data
type SOARecord struct {
	PrimaryNS  string // Primary nameserver
	AdminEmail string // Admin email (dots replace @)
	Serial     uint32 // Zone version
	Refresh    uint32 // Secondary refresh interval
	Retry      uint32 // Retry after failed refresh
	Expire     uint32 // Zone expiration time
	MinimumTTL uint32 // Negative caching TTL
}

// ============================================================================
// Wire Format Utilities
// ============================================================================

// PackUint16 encodes uint16 to big-endian bytes
func PackUint16(n uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, n)
	return buf
}

// UnpackUint16 decodes big-endian bytes to uint16
func UnpackUint16(data []byte) uint16 {
	return binary.BigEndian.Uint16(data)
}

// PackUint32 encodes uint32 to big-endian bytes
func PackUint32(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// UnpackUint32 decodes big-endian bytes to uint32
func UnpackUint32(data []byte) uint32 {
	return binary.BigEndian.Uint32(data)
}

// EncodeDomainName converts domain name to DNS label format
// Example: "example.com" -> "\x07example\x03com\x00"
func EncodeDomainName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	var buf []byte
	for _, label := range labels {
		if len(label) > 63 {
			label = label[:63]
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	return buf
}

// DecodeDomainName parses DNS label format to domain name string
// Handles pointer compression (RFC 1035 Section 4.1.4)
func DecodeDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, errors.New("offset beyond data length")
	}

	var labels []string
	originalOffset := offset
	jumped := false
	maxJumps := 10 // Prevent infinite loops

	for maxJumps > 0 {
		if offset >= len(data) {
			return "", originalOffset, errors.New("unexpected end of data")
		}

		length := int(data[offset])

		// Check for pointer compression
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", originalOffset, errors.New("pointer compression: incomplete pointer")
			}
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			maxJumps--
			continue
		}

		// End of name
		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		// Regular label
		offset++
		if offset+length > len(data) {
			return "", originalOffset, errors.New("label extends beyond data")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if maxJumps == 0 {
		return "", originalOffset, errors.New("too many compression pointers")
	}

	return strings.Join(labels, "."), originalOffset, nil
}

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrInvalidMessage indicates message format error
	ErrInvalidMessage = errors.New("invalid DNS message format")
	// ErrTruncated indicates message was truncated
	ErrTruncated = errors.New("DNS message truncated")
	// ErrInvalidDomain indicates invalid domain name
	ErrInvalidDomain = errors.New("invalid domain name")
	// ErrTimeout indicates query timeout
	ErrTimeout = errors.New("DNS query timeout")
)
