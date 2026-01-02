// Package dns implements DNS protocol handling including response building.
package dns

import (
	"net"
	"time"

	"github.com/miekg/dns"

	"dns_server/internal/models"
)

// =============================================================================
// RESPONSE BUILDER - Constructs RFC-compliant DNS response packets
// =============================================================================

// ResponseBuilder constructs binary DNS response packets.
type ResponseBuilder struct {
	// serverName is the authoritative nameserver name for NS records
	serverName string

	// defaultTTL is the fallback TTL when upstream doesn't provide one (seconds)
	defaultTTL uint32

	// enableEDNS enables EDNS0 OPT record for extended DNS features
	enableEDNS bool
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewResponseBuilder creates a new response builder with the specified configuration.
func NewResponseBuilder(serverName string, defaultTTL uint32, enableEDNS bool) *ResponseBuilder {
	if defaultTTL == 0 {
		defaultTTL = 300 // 5 minutes default
	}
	if serverName == "" {
		serverName = "ns1.safeops.local"
	}

	return &ResponseBuilder{
		serverName: serverName,
		defaultTTL: defaultTTL,
		enableEDNS: enableEDNS,
	}
}

// =============================================================================
// RESPONSE BUILDING
// =============================================================================

// BuildResponse constructs a successful DNS response with an A record.
func (rb *ResponseBuilder) BuildResponse(query *models.DNSQuery, ip string, ttl uint32) ([]byte, error) {
	msg := new(dns.Msg)

	// Set response header
	msg.Id = query.QueryID
	msg.Response = true           // QR=1 (response)
	msg.Authoritative = false     // AA=0 (non-authoritative, recursive answer)
	msg.RecursionDesired = true   // RD=1
	msg.RecursionAvailable = true // RA=1
	msg.Rcode = dns.RcodeSuccess  // RCODE=0 (no error)

	// Build question section (echo original query)
	msg.Question = []dns.Question{rb.buildQuestionSection(query)}

	// Build answer section with A record
	if ttl == 0 {
		ttl = rb.defaultTTL
	}
	aRecord := rb.buildAnswerSection(query.Domain, ip, ttl)
	msg.Answer = []dns.RR{aRecord}

	// Add EDNS0 OPT record if enabled
	if rb.enableEDNS {
		rb.addEDNSRecord(msg)
	}

	// Marshal to binary wire format
	return msg.Pack()
}

// BuildResponseFromCache constructs a response using cached data with decremented TTL.
func (rb *ResponseBuilder) BuildResponseFromCache(query *models.DNSQuery, entry *models.CacheEntry) ([]byte, error) {
	remainingTTL := rb.calculateRemainingTTL(entry)
	return rb.BuildResponse(query, entry.IP, remainingTTL)
}

// BuildResponseFromUpstream constructs a response using upstream resolver result.
func (rb *ResponseBuilder) BuildResponseFromUpstream(query *models.DNSQuery, result *models.UpstreamResult) ([]byte, error) {
	if !result.Success {
		// Upstream failed, return SERVFAIL
		return rb.BuildServFailResponse(query)
	}
	return rb.BuildResponse(query, result.IP, uint32(result.TTL))
}

// =============================================================================
// ERROR RESPONSES
// =============================================================================

// BuildErrorResponse constructs an error response with the specified RCODE.
func (rb *ResponseBuilder) BuildErrorResponse(query *models.DNSQuery, rcode int) ([]byte, error) {
	msg := new(dns.Msg)

	// Set response header with error code
	msg.Id = query.QueryID
	msg.Response = true
	msg.Authoritative = false
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Rcode = rcode

	// Include question section (required even for errors per RFC 1035)
	msg.Question = []dns.Question{rb.buildQuestionSection(query)}

	// Add EDNS0 if enabled
	if rb.enableEDNS {
		rb.addEDNSRecord(msg)
	}

	return msg.Pack()
}

// BuildNXDomainResponse constructs an NXDOMAIN response for non-existent domains.
func (rb *ResponseBuilder) BuildNXDomainResponse(query *models.DNSQuery) ([]byte, error) {
	return rb.BuildErrorResponse(query, dns.RcodeNameError) // RCODE=3
}

// BuildServFailResponse constructs a SERVFAIL response for server errors.
func (rb *ResponseBuilder) BuildServFailResponse(query *models.DNSQuery) ([]byte, error) {
	return rb.BuildErrorResponse(query, dns.RcodeServerFailure) // RCODE=2
}

// BuildRefusedResponse constructs a REFUSED response for rejected queries.
func (rb *ResponseBuilder) BuildRefusedResponse(query *models.DNSQuery) ([]byte, error) {
	return rb.BuildErrorResponse(query, dns.RcodeRefused) // RCODE=5
}

// =============================================================================
// PRIVATE HELPER METHODS
// =============================================================================

// buildQuestionSection creates the question section echoing the original query.
func (rb *ResponseBuilder) buildQuestionSection(query *models.DNSQuery) dns.Question {
	domain := query.Domain
	// Ensure domain ends with "." (FQDN requirement)
	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	qtype := dns.TypeA
	switch query.QueryType {
	case models.QueryTypeA:
		qtype = dns.TypeA
	case models.QueryTypeAAAA:
		qtype = dns.TypeAAAA
	case models.QueryTypePTR:
		qtype = dns.TypePTR
	case models.QueryTypeCNAME:
		qtype = dns.TypeCNAME
	}

	return dns.Question{
		Name:   domain,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
}

// buildAnswerSection creates an A record for the answer section.
func (rb *ResponseBuilder) buildAnswerSection(domain string, ip string, ttl uint32) dns.RR {
	// Ensure domain ends with "." (FQDN requirement)
	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP(ip).To4(),
	}
}

// buildAAAARecord creates an AAAA record for IPv6 addresses (future use).
func (rb *ResponseBuilder) buildAAAARecord(domain string, ip string, ttl uint32) dns.RR {
	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		AAAA: net.ParseIP(ip).To16(),
	}
}

// addEDNSRecord appends EDNS0 OPT pseudo-record to the response.
func (rb *ResponseBuilder) addEDNSRecord(msg *dns.Msg) {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	// Set UDP payload size to 4096 bytes (larger than default 512)
	opt.SetUDPSize(4096)

	msg.Extra = append(msg.Extra, opt)
}

// calculateRemainingTTL computes TTL for cached entries.
// Returns the remaining seconds until expiration, minimum 0.
func (rb *ResponseBuilder) calculateRemainingTTL(entry *models.CacheEntry) uint32 {
	elapsed := time.Since(entry.Timestamp)
	remaining := entry.OriginalTTL - int(elapsed.Seconds())

	if remaining < 0 {
		return 0
	}
	return uint32(remaining)
}

// =============================================================================
// CONFIGURATION METHODS
// =============================================================================

// SetServerName updates the nameserver name for NS records.
func (rb *ResponseBuilder) SetServerName(name string) {
	rb.serverName = name
}

// SetDefaultTTL updates the fallback TTL value.
func (rb *ResponseBuilder) SetDefaultTTL(ttl uint32) {
	rb.defaultTTL = ttl
}

// SetEDNS enables or disables EDNS0 support.
func (rb *ResponseBuilder) SetEDNS(enabled bool) {
	rb.enableEDNS = enabled
}

// GetServerName returns the configured server name.
func (rb *ResponseBuilder) GetServerName() string {
	return rb.serverName
}

// GetDefaultTTL returns the configured default TTL.
func (rb *ResponseBuilder) GetDefaultTTL() uint32 {
	return rb.defaultTTL
}
