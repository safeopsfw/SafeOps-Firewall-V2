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

// DNSAnswer represents a DNS answer record
type DNSAnswer struct {
	Domain string
	IP     string
	TTL    uint32
}

// ParseDNSResponse extracts domain→IP mappings from DNS response (fast, minimal parsing)
func (p *DNSParser) ParseDNSResponse(payload []byte) []DNSAnswer {
	if len(payload) < 12 {
		return nil
	}

	// Check if it's a response
	flags := binary.BigEndian.Uint16(payload[2:4])
	if (flags>>15)&1 == 0 {
		return nil
	}

	answerCount := binary.BigEndian.Uint16(payload[6:8])
	if answerCount == 0 {
		return nil
	}

	// Skip questions quickly
	offset := 12
	qCount := binary.BigEndian.Uint16(payload[4:6])

	for i := 0; i < int(qCount); i++ {
		for offset < len(payload) {
			length := int(payload[offset])
			if length == 0 {
				offset++
				break
			}
			if length >= 192 {
				offset += 2
				break
			}
			offset += 1 + length
		}
		offset += 4 // Skip type+class
		if offset >= len(payload) {
			return nil
		}
	}

	// Parse answers (fast path - only A/AAAA records)
	answers := make([]DNSAnswer, 0, answerCount)

	for i := 0; i < int(answerCount) && offset < len(payload); i++ {
		domain := p.parseDNSName(payload, offset)

		// Skip name
		for offset < len(payload) {
			length := int(payload[offset])
			if length == 0 {
				offset++
				break
			}
			if length >= 192 {
				offset += 2
				break
			}
			offset += 1 + length
		}

		if offset+10 > len(payload) {
			break
		}

		recordType := binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 4 // Skip type+class
		ttl := binary.BigEndian.Uint32(payload[offset : offset+4])
		offset += 4
		dataLen := binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 2

		if offset+int(dataLen) > len(payload) {
			break
		}

		// Type A (IPv4) = 1
		if recordType == 1 && dataLen == 4 {
			ip := payload[offset : offset+4]
			answers = append(answers, DNSAnswer{
				Domain: domain,
				IP:     formatIPv4(ip),
				TTL:    ttl,
			})
		}

		// Type AAAA (IPv6) = 28
		if recordType == 28 && dataLen == 16 {
			ip := payload[offset : offset+16]
			answers = append(answers, DNSAnswer{
				Domain: domain,
				IP:     formatIPv6(ip),
				TTL:    ttl,
			})
		}

		offset += int(dataLen)
	}

	return answers
}

// formatIPv4 formats IPv4 (fast)
func formatIPv4(ip []byte) string {
	return string(rune('0'+ip[0]/100)) + string(rune('0'+(ip[0]%100)/10)) + string(rune('0'+ip[0]%10)) + "." +
		string(rune('0'+ip[1]/100)) + string(rune('0'+(ip[1]%100)/10)) + string(rune('0'+ip[1]%10)) + "." +
		string(rune('0'+ip[2]/100)) + string(rune('0'+(ip[2]%100)/10)) + string(rune('0'+ip[2]%10)) + "." +
		string(rune('0'+ip[3]/100)) + string(rune('0'+(ip[3]%100)/10)) + string(rune('0'+ip[3]%10))
}

// formatIPv6 formats IPv6 (simple, no compression)
func formatIPv6(ip []byte) string {
	hex := "0123456789abcdef"
	result := make([]byte, 39) // max length xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx

	pos := 0
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			result[pos] = ':'
			pos++
		}
		result[pos] = hex[ip[i]>>4]
		result[pos+1] = hex[ip[i]&0x0f]
		result[pos+2] = hex[ip[i+1]>>4]
		result[pos+3] = hex[ip[i+1]&0x0f]
		pos += 4
	}

	return string(result[:pos])
}
