package parser

import (
	"bytes"
	"crypto/md5"
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

	contentType := payload[0]
	if contentType != 0x16 && contentType != 0x17 {
		return nil
	}
	if payload[1] != 0x03 {
		return nil
	}

	tlsData := &models.TLSData{}

	if contentType == 0x16 {
		p.parseHandshake(payload[5:], tlsData)
	}

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

// parseClientHello parses TLS ClientHello message with full JA3 fields
func (p *TLSParser) parseClientHello(data []byte) *models.TLSClientHello {
	if len(data) < 38 {
		return nil
	}

	// handshakeType(1) + length(3) + version(2) + random(32)
	ch := &models.TLSClientHello{
		Version: p.getTLSVersion(data[4], data[5]),
		Random:  hex.EncodeToString(data[6:38]),
	}

	offset := 38

	// Session ID
	if offset >= len(data) {
		return ch
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return ch
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+cipherSuitesLen > len(data) {
		return ch
	}

	var cipherSuiteIDs []uint16
	for i := 0; i < cipherSuitesLen; i += 2 {
		if offset+i+1 < len(data) {
			suite := uint16(data[offset+i])<<8 | uint16(data[offset+i+1])
			// Skip GREASE values for JA3
			if !isGREASE(suite) {
				cipherSuiteIDs = append(cipherSuiteIDs, suite)
				ch.CipherSuites = append(ch.CipherSuites, p.getCipherSuiteName(suite))
			}
		}
	}
	ch.CipherSuiteIDs = cipherSuiteIDs
	offset += cipherSuitesLen

	// Compression Methods
	if offset >= len(data) {
		return ch
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions
	if offset+2 > len(data) {
		return ch
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extEnd := offset + extensionsLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	var extensionIDs []uint16
	var ecCurves []uint16
	var ecPointFormats []uint8

	for offset+4 <= extEnd {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+extLen > extEnd {
			break
		}

		extData := data[offset : offset+extLen]

		// Track extension IDs (skip GREASE)
		if !isGREASE(extType) {
			extensionIDs = append(extensionIDs, extType)
		}

		switch extType {
		case 0x0000: // SNI
			if sni := p.parseSNIExtension(extData); sni != "" {
				ch.SNI = sni
			}
		case 0x0010: // ALPN
			ch.ALPN = p.parseALPNExtension(extData)
		case 0x000a: // supported_groups (elliptic_curves)
			ecCurves = p.parseECCurvesExtension(extData)
		case 0x000b: // ec_point_formats
			ecPointFormats = p.parseECPointFormatsExtension(extData)
		}

		offset += extLen
	}

	ch.ExtensionIDs = extensionIDs
	ch.ECCurves = ecCurves
	ch.ECPointFormats = ecPointFormats

	return ch
}

// parseServerHello parses TLS ServerHello message with JA3S fields
func (p *TLSParser) parseServerHello(data []byte) *models.TLSServerHello {
	if len(data) < 38 {
		return nil
	}

	sh := &models.TLSServerHello{
		Version: p.getTLSVersion(data[4], data[5]),
		Random:  hex.EncodeToString(data[6:38]),
	}

	offset := 38

	// Session ID
	if offset >= len(data) {
		return sh
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher Suite (single)
	if offset+2 > len(data) {
		return sh
	}
	cipherSuite := uint16(data[offset])<<8 | uint16(data[offset+1])
	sh.CipherSuiteID = cipherSuite
	sh.CipherSuite = p.getCipherSuiteName(cipherSuite)
	offset += 2

	// Compression Method
	if offset >= len(data) {
		return sh
	}
	offset++ // skip compression method

	// Extensions
	if offset+2 > len(data) {
		return sh
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extEnd := offset + extensionsLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	var extensionIDs []uint16
	for offset+4 <= extEnd {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if !isGREASE(extType) {
			extensionIDs = append(extensionIDs, extType)
		}

		offset += extLen
	}
	sh.ExtensionIDs = extensionIDs

	return sh
}

// ComputeJA3 computes JA3 hash from ClientHello
// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
func (p *TLSParser) ComputeJA3(ch *models.TLSClientHello) string {
	if ch == nil {
		return ""
	}

	version := p.getTLSVersionID(ch.Version)

	// Cipher suites (comma-separated, GREASE filtered)
	ciphers := uint16SliceToString(ch.CipherSuiteIDs)

	// Extensions (comma-separated, GREASE filtered)
	extensions := uint16SliceToString(ch.ExtensionIDs)

	// Elliptic curves
	curves := uint16SliceToString(ch.ECCurves)

	// EC point formats
	ecpf := uint8SliceToString(ch.ECPointFormats)

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s", version, ciphers, extensions, curves, ecpf)
	hash := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

// ComputeJA3S computes JA3S hash from ServerHello
// Format: TLSVersion,CipherSuite,Extensions
func (p *TLSParser) ComputeJA3S(sh *models.TLSServerHello) string {
	if sh == nil {
		return ""
	}

	version := p.getTLSVersionID(sh.Version)
	extensions := uint16SliceToString(sh.ExtensionIDs)

	ja3sString := fmt.Sprintf("%d,%d,%s", version, sh.CipherSuiteID, extensions)
	hash := md5.Sum([]byte(ja3sString))
	return hex.EncodeToString(hash[:])
}

// parseSNIExtension extracts SNI hostname
func (p *TLSParser) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI list length(2) + type(1) + name length(2) + name
	nameLen := int(data[3])<<8 | int(data[4])
	if 5+nameLen > len(data) {
		return ""
	}
	hostname := string(data[5 : 5+nameLen])
	if isValidHostname(hostname) {
		return hostname
	}
	return ""
}

// parseALPNExtension extracts ALPN protocols
func (p *TLSParser) parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if listLen+2 > len(data) {
		return nil
	}

	var protocols []string
	offset := 2
	for offset < 2+listLen {
		if offset >= len(data) {
			break
		}
		protoLen := int(data[offset])
		offset++
		if offset+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}
	return protocols
}

// parseECCurvesExtension extracts supported elliptic curves
func (p *TLSParser) parseECCurvesExtension(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	var curves []uint16
	for i := 2; i+1 < 2+listLen && i+1 < len(data); i += 2 {
		curve := uint16(data[i])<<8 | uint16(data[i+1])
		if !isGREASE(curve) {
			curves = append(curves, curve)
		}
	}
	return curves
}

// parseECPointFormatsExtension extracts EC point formats
func (p *TLSParser) parseECPointFormatsExtension(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	fmtLen := int(data[0])
	var formats []uint8
	for i := 1; i < 1+fmtLen && i < len(data); i++ {
		formats = append(formats, data[i])
	}
	return formats
}

// isGREASE checks if a value is a TLS GREASE value (should be ignored for JA3)
func isGREASE(val uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	if val&0x0f0f == 0x0a0a {
		return true
	}
	return false
}

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

// getTLSVersionID returns the numeric TLS version for JA3
func (p *TLSParser) getTLSVersionID(version string) uint16 {
	switch version {
	case "SSL 3.0":
		return 768
	case "TLS 1.0":
		return 769
	case "TLS 1.1":
		return 770
	case "TLS 1.2":
		return 771
	case "TLS 1.3":
		return 772
	default:
		return 0
	}
}

func (p *TLSParser) getCipherSuiteName(suite uint16) string {
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

func isValidHostname(s string) bool {
	if len(s) < 4 || len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// uint16SliceToString converts a uint16 slice to dash-separated string
func uint16SliceToString(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// uint8SliceToString converts a uint8 slice to dash-separated string
func uint8SliceToString(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}
