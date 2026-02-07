package parser

import (
	"encoding/binary"
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
// RFC 5246 compliant implementation - handles TLS 1.0 through TLS 1.3
func (p *TLSParser) ExtractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	// Validate TLS record header
	// Byte 0: Content Type (0x16 = Handshake)
	if payload[0] != 0x16 {
		return ""
	}

	// Byte 1-2: TLS version (0x03 0x01 = TLS 1.0, 0x03 0x03 = TLS 1.2, etc.)
	if payload[1] != 0x03 {
		return ""
	}

	// Byte 5: Handshake type (0x01 = ClientHello)
	if len(payload) < 6 || payload[5] != 0x01 {
		return ""
	}

	// Parse ClientHello structure per RFC 5246
	sni := p.parseClientHello(payload)

	// Validate extracted hostname
	if len(sni) < 3 || !strings.Contains(sni, ".") {
		return ""
	}

	return sni
}

// parseClientHello parses TLS ClientHello per RFC 5246 Section 7.4.1.2
func (p *TLSParser) parseClientHello(data []byte) string {
	// ClientHello structure:
	// - HandshakeType: 1 byte (0x01)
	// - Length: 3 bytes
	// - Version: 2 bytes
	// - Random: 32 bytes
	// - SessionID: 1 byte length + variable
	// - CipherSuites: 2 bytes length + variable
	// - CompressionMethods: 1 byte length + variable
	// - Extensions: 2 bytes length + variable

	offset := 6 // Skip TLS record header (5) + HandshakeType (1)

	// Skip Length (3 bytes) + Version (2 bytes) + Random (32 bytes) = 37 bytes
	offset += 37

	if offset >= len(data) {
		return ""
	}

	// Parse SessionID length
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return ""
	}

	// Parse CipherSuites length
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	if offset >= len(data) {
		return ""
	}

	// Parse CompressionMethods length
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	if offset+2 > len(data) {
		return ""
	}

	// Parse Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+extensionsLen > len(data) {
		return ""
	}

	// Search for SNI extension (type 0x0000)
	return p.findSNIExtension(data[offset:offset+extensionsLen])
}

// findSNIExtension searches for SNI in TLS extensions
func (p *TLSParser) findSNIExtension(extensions []byte) string {
	offset := 0

	for offset+4 <= len(extensions) {
		// Extension type (2 bytes)
		extType := binary.BigEndian.Uint16(extensions[offset : offset+2])
		offset += 2

		// Extension length (2 bytes)
		extLen := int(binary.BigEndian.Uint16(extensions[offset : offset+2]))
		offset += 2

		if offset+extLen > len(extensions) {
			return "" // Invalid extension length
		}

		// Check if this is SNI extension (type 0x0000)
		if extType == 0x0000 {
			return p.parseSNIExtension(extensions[offset : offset+extLen])
		}

		offset += extLen
	}

	return ""
}

// parseSNIExtension extracts hostname from SNI extension data
func (p *TLSParser) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI extension structure:
	// - ServerNameList length: 2 bytes
	// - NameType: 1 byte (0x00 = host_name)
	// - HostName length: 2 bytes
	// - HostName: variable

	offset := 2 // Skip ServerNameList length

	// Check NameType (should be 0x00 for hostname)
	if data[offset] != 0x00 {
		return ""
	}
	offset++

	if offset+2 > len(data) {
		return ""
	}

	// Extract HostName length
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+nameLen > len(data) || nameLen == 0 || nameLen > 253 {
		return "" // Invalid hostname length
	}

	// Extract hostname
	hostname := string(data[offset : offset+nameLen])

	// Basic validation
	if !p.isValidHostname(hostname) {
		return ""
	}

	return hostname
}

// isValidHostname validates the extracted hostname
func (p *TLSParser) isValidHostname(s string) bool {
	if len(s) < 3 || len(s) > 253 {
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

	// Check for valid characters (alphanumeric, dot, hyphen)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}

	return true
}
