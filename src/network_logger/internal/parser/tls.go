package parser

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/safeops/network_logger/pkg/models"
)

// TLSParser parses TLS traffic
type TLSParser struct{}

// NewTLSParser creates a new TLS parser
func NewTLSParser() *TLSParser {
	return &TLSParser{}
}

// Parse attempts to detect and parse TLS handshake
func (p *TLSParser) Parse(payload []byte) *models.TLSData {
	if len(payload) < 5 {
		return nil
	}

	// Check TLS record header (0x16 = handshake, 0x17 = application data)
	contentType := payload[0]
	if contentType != 0x16 && contentType != 0x17 {
		return nil
	}

	// TLS version (3.1 = TLS 1.0, 3.3 = TLS 1.2, etc.)
	if payload[1] != 0x03 {
		return nil
	}

	tlsData := &models.TLSData{}

	// Parse handshake messages
	if contentType == 0x16 {
		p.parseHandshake(payload[5:], tlsData)
	}

	// Check for certificates
	if bytes.Contains(payload, []byte{0x0b, 0x00, 0x00}) {
		tlsData.CertificatesPresent = true
	}

	return tlsData
}

// parseHandshake parses TLS handshake messages
func (p *TLSParser) parseHandshake(data []byte, tlsData *models.TLSData) {
	if len(data) < 4 {
		return
	}

	handshakeType := data[0]

	switch handshakeType {
	case 0x01: // ClientHello
		tlsData.ClientHello = p.parseClientHello(data)
	case 0x02: // ServerHello
		tlsData.ServerHello = p.parseServerHello(data)
	}
}

// parseClientHello parses TLS ClientHello message
func (p *TLSParser) parseClientHello(data []byte) *models.TLSClientHello {
	if len(data) < 38 {
		return nil
	}

	ch := &models.TLSClientHello{
		Version: p.getTLSVersion(data[4], data[5]),
		Random:  hex.EncodeToString(data[6:38]),
	}

	// Parse extensions (simplified - SNI detection)
	if sni := p.extractSNI(data); sni != "" {
		ch.SNI = sni
	}

	return ch
}

// parseServerHello parses TLS ServerHello message
func (p *TLSParser) parseServerHello(data []byte) *models.TLSServerHello {
	if len(data) < 38 {
		return nil
	}

	sh := &models.TLSServerHello{
		Version: p.getTLSVersion(data[4], data[5]),
		Random:  hex.EncodeToString(data[6:38]),
	}

	// Cipher suite at offset 38-40
	if len(data) >= 40 {
		cipherSuite := uint16(data[38])<<8 | uint16(data[39])
		sh.CipherSuite = p.getCipherSuiteName(cipherSuite)
	}

	return sh
}

// extractSNI extracts Server Name Indication from ClientHello
func (p *TLSParser) extractSNI(data []byte) string {
	// This is a simplified SNI extraction
	// Full implementation would parse extensions properly
	sniPattern := []byte{0x00, 0x00} // SNI extension type

	idx := bytes.Index(data, sniPattern)
	if idx < 0 || idx+9 >= len(data) {
		return ""
	}

	// Try to extract hostname (simplified)
	for i := idx; i < len(data)-1; i++ {
		if data[i] == 0x00 && data[i+1] > 0 && data[i+1] < 100 {
			nameLen := int(data[i+1])
			if i+2+nameLen <= len(data) {
				hostname := string(data[i+2 : i+2+nameLen])
				if isValidHostname(hostname) {
					return hostname
				}
			}
		}
	}

	return ""
}

// getTLSVersion returns TLS version string
func (p *TLSParser) getTLSVersion(major, minor byte) string {
	if major != 0x03 {
		return "UNKNOWN"
	}

	switch minor {
	case 0x00:
		return "SSL 3.0"
	case 0x01:
		return "TLS 1.0"
	case 0x02:
		return "TLS 1.1"
	case 0x03:
		return "TLS 1.2"
	case 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS %d.%d", major, minor)
	}
}

// getCipherSuiteName returns cipher suite name
func (p *TLSParser) getCipherSuiteName(suite uint16) string {
	// Common cipher suites
	suites := map[uint16]string{
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	}

	if name, ok := suites[suite]; ok {
		return name
	}

	return fmt.Sprintf("0x%04X", suite)
}

// isValidHostname checks if string looks like a hostname
func isValidHostname(s string) bool {
	if len(s) < 4 || len(s) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Basic character validation
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}

	return true
}
