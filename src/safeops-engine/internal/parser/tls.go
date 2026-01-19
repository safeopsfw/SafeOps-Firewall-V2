package parser

import (
	"bytes"
	"strings"
)

// TLSParser extracts SNI (Server Name Indication) from TLS ClientHello
type TLSParser struct{}

// NewTLSParser creates a new TLS parser
func NewTLSParser() *TLSParser {
	return &TLSParser{}
}

// ExtractSNI extracts the Server Name Indication from TLS ClientHello
// Returns empty string if not a valid TLS ClientHello or no SNI present
func (p *TLSParser) ExtractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	// Check TLS record header
	// 0x16 = Handshake
	if payload[0] != 0x16 {
		return ""
	}

	// TLS version (3.1 = TLS 1.0, 3.3 = TLS 1.2, etc.)
	if payload[1] != 0x03 {
		return ""
	}

	// Check handshake type (0x01 = ClientHello)
	if len(payload) < 6 || payload[5] != 0x01 {
		return ""
	}

	// Find SNI extension
	// This is a simplified search - looks for the SNI pattern
	sni := p.findSNI(payload)

	// Validate hostname
	if len(sni) < 3 || !strings.Contains(sni, ".") {
		return ""
	}

	return sni
}

// findSNI searches for SNI in the TLS extensions
func (p *TLSParser) findSNI(data []byte) string {
	// Look for server_name extension (type 0x0000)
	// Simplified search - looks for hostname patterns

	for i := 40; i < len(data)-10; i++ {
		// Look for potential hostname start
		if data[i] >= 'a' && data[i] <= 'z' || data[i] >= 'A' && data[i] <= 'Z' {
			// Try to extract hostname
			hostname := p.extractHostname(data, i)
			if p.isValidHostname(hostname) {
				return hostname
			}
		}
	}

	return ""
}

// extractHostname tries to extract a hostname starting at the given position
func (p *TLSParser) extractHostname(data []byte, start int) string {
	var buf bytes.Buffer

	for i := start; i < len(data) && i < start+253; i++ {
		c := data[i]

		// Valid hostname characters
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			buf.WriteByte(c)
		} else {
			break
		}
	}

	return buf.String()
}

// isValidHostname checks if the string looks like a valid hostname
func (p *TLSParser) isValidHostname(s string) bool {
	if len(s) < 4 || len(s) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Must not start or end with dot
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}

	// Check for common TLDs
	commonTLDs := []string{".com", ".net", ".org", ".io", ".co", ".app", ".dev"}
	for _, tld := range commonTLDs {
		if strings.HasSuffix(s, tld) {
			return true
		}
	}

	return false
}
