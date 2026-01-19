package parser

import (
	"encoding/binary"
	"strings"
)

// DNSParser extracts domain names from DNS packets
type DNSParser struct{}

// NewDNSParser creates a new DNS parser
func NewDNSParser() *DNSParser {
	return &DNSParser{}
}

// ExtractDomain extracts the domain name from a DNS query packet
// Returns empty string if not a valid DNS packet
func (p *DNSParser) ExtractDomain(payload []byte) string {
	if len(payload) < 12 {
		return ""
	}

	// DNS header is 12 bytes
	// Questions start at byte 12
	offset := 12

	// Parse question section
	domain := p.parseDNSName(payload, offset)

	// Basic validation
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// parseDNSName parses a DNS name from the packet
func (p *DNSParser) parseDNSName(data []byte, offset int) string {
	var parts []string
	pos := offset

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			break
		}

		// Check for compression pointer
		if length >= 192 {
			// Compression pointer - not handling for now
			break
		}

		pos++
		if pos+length > len(data) {
			break
		}

		part := string(data[pos : pos+length])
		parts = append(parts, part)
		pos += length
	}

	return strings.Join(parts, ".")
}

// IsDNSQuery checks if this is a DNS query (not response)
func (p *DNSParser) IsDNSQuery(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}

	// Check QR bit (bit 15 of flags)
	flags := binary.BigEndian.Uint16(payload[2:4])
	qr := (flags >> 15) & 1

	return qr == 0 // 0 = query, 1 = response
}
