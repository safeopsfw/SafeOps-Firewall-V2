// Package protocol provides DNS protocol types for wire format handling.
package protocol

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

// ============================================================================
// DNS Classes
// ============================================================================

// Class represents DNS class (namespace for DNS data)
type Class uint16

const (
	ClassIN Class = 1 // Internet (99.9% of queries)
	ClassCH Class = 3 // Chaos (experimental)
)

// ============================================================================
// DNS Response Codes (RCODE)
// ============================================================================

// ResponseCode represents DNS response codes
type ResponseCode uint8

const (
	RCodeNoError   ResponseCode = 0 // Success
	RCodeFormError ResponseCode = 1 // Query format error
	RCodeServFail  ResponseCode = 2 // Server failure
	RCodeNXDomain  ResponseCode = 3 // Domain doesn't exist
	RCodeRefused   ResponseCode = 5 // Query refused
)

// ============================================================================
// DNS Message (Query/Response)
// ============================================================================

// Message represents a complete DNS message
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
		Questions:  make([]Question, 0),
		Answers:    make([]ResourceRecord, 0),
		Authority:  make([]ResourceRecord, 0),
		Additional: make([]ResourceRecord, 0),
	}
}

// IsQuery returns true if message is a query
func (m *Message) IsQuery() bool {
	return !m.Flags.QR
}

// SetResponse marks message as a response
func (m *Message) SetResponse() {
	m.Flags.QR = true
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
	ParsedData interface{} // Parsed data
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
	AdminEmail string // Admin email
	Serial     uint32 // Zone version
	Refresh    uint32 // Secondary refresh interval
	Retry      uint32 // Retry after failed refresh
	Expire     uint32 // Zone expiration time
	MinimumTTL uint32 // Negative caching TTL
}
