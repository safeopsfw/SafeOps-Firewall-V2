// Package tls implements TLS protocol parsing for SNI extraction.
package tls

import (
	"errors"
	"fmt"

	"tls_proxy/internal/models"
)

// =============================================================================
// TLS PROTOCOL CONSTANTS
// =============================================================================

// Content Types (TLS record layer)
const (
	ContentTypeChangeCipherSpec = 0x14
	ContentTypeAlert            = 0x15
	ContentTypeHandshake        = 0x16
	ContentTypeApplicationData  = 0x17
)

// Handshake Types
const (
	HandshakeTypeClientHello        = 0x01
	HandshakeTypeServerHello        = 0x02
	HandshakeTypeCertificate        = 0x0b
	HandshakeTypeServerKeyExchange  = 0x0c
	HandshakeTypeCertificateRequest = 0x0d
	HandshakeTypeServerHelloDone    = 0x0e
	HandshakeTypeCertificateVerify  = 0x0f
	HandshakeTypeClientKeyExchange  = 0x10
	HandshakeTypeFinished           = 0x14
)

// Extension Types
const (
	ExtensionTypeSNI                 = 0x0000
	ExtensionTypeMaxFragmentLength   = 0x0001
	ExtensionTypeSupportedGroups     = 0x000a
	ExtensionTypeECPointFormats      = 0x000b
	ExtensionTypeSignatureAlgorithms = 0x000d
	ExtensionTypeALPN                = 0x0010
	ExtensionTypeSupportedVersions   = 0x002b
)

// SNI Name Types
const (
	SNINameTypeDNSHostname = 0x00
)

// Minimum sizes
const (
	MinTLSRecordSize   = 5  // ContentType(1) + Version(2) + Length(2)
	MinHandshakeSize   = 4  // Type(1) + Length(3)
	MinClientHelloSize = 38 // Version(2) + Random(32) + SessionIDLen(1) + CipherSuitesLen(2) + CompressionLen(1)
	MinTotalHeaderSize = 43 // MinTLSRecordSize + MinHandshakeSize + basic ClientHello fields
)

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

var (
	ErrNotHTTPS          = errors.New("packet is not HTTPS traffic")
	ErrNotOutbound       = errors.New("SNI only present in outbound ClientHello")
	ErrDataTooShort      = errors.New("packet data too short for TLS handshake")
	ErrNotHandshake      = errors.New("not a TLS handshake packet")
	ErrNotClientHello    = errors.New("not a ClientHello message")
	ErrTruncatedData     = errors.New("truncated ClientHello data")
	ErrNoSNIExtension    = errors.New("no SNI extension present")
	ErrMalformedSNI      = errors.New("malformed SNI extension data")
	ErrNonHostnameSNI    = errors.New("SNI contains non-hostname data")
	ErrInvalidExtensions = errors.New("invalid extensions section")
)

// =============================================================================
// SNI EXTRACTION
// =============================================================================

// ExtractSNI parses a TLS ClientHello packet and extracts the SNI hostname.
// Returns the domain name string and nil error on success.
// Returns empty string and descriptive error if extraction fails.
func ExtractSNI(packet *models.Packet) (string, error) {
	// Step 1: Validate packet is HTTPS (port 443)
	if !packet.IsHTTPS() {
		return "", ErrNotHTTPS
	}

	// Step 2: Verify packet is outbound (client → server)
	if !packet.IsOutbound() {
		return "", ErrNotOutbound
	}

	// Step 3: Check minimum data length
	data := packet.RawData
	if len(data) < MinTotalHeaderSize {
		return "", ErrDataTooShort
	}

	// Step 4: Parse TLS record layer header
	// Byte 0: ContentType
	// Bytes 1-2: Version (ignored for SNI extraction)
	// Bytes 3-4: Record Length
	contentType := data[0]
	if contentType != ContentTypeHandshake {
		return "", ErrNotHandshake
	}

	recordLength := readUint16(data, 3)
	if len(data) < 5+int(recordLength) {
		return "", ErrTruncatedData
	}

	// Step 5: Parse handshake header (starts at byte 5)
	handshakeOffset := 5
	handshakeType := data[handshakeOffset]
	if handshakeType != HandshakeTypeClientHello {
		return "", ErrNotClientHello
	}

	// Handshake length (3 bytes)
	handshakeLength := readUint24(data, handshakeOffset+1)
	if len(data) < handshakeOffset+4+int(handshakeLength) {
		return "", ErrTruncatedData
	}

	// Step 6: Parse ClientHello structure
	// Start after handshake header (type + 3-byte length)
	offset := handshakeOffset + 4

	// Skip Version (2 bytes)
	offset += 2

	// Skip Random (32 bytes)
	offset += 32

	// Skip SessionID (variable length)
	if offset >= len(data) {
		return "", ErrTruncatedData
	}
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	// Skip CipherSuites (variable length, 2-byte length prefix)
	if offset+2 > len(data) {
		return "", ErrTruncatedData
	}
	cipherSuitesLength := int(readUint16(data, offset))
	offset += 2 + cipherSuitesLength

	// Skip CompressionMethods (variable length, 1-byte length prefix)
	if offset >= len(data) {
		return "", ErrTruncatedData
	}
	compressionMethodsLength := int(data[offset])
	offset += 1 + compressionMethodsLength

	// Step 7: Check for extensions section
	if offset+2 > len(data) {
		// No extensions present
		return "", ErrNoSNIExtension
	}

	extensionsLength := int(readUint16(data, offset))
	offset += 2

	if offset+extensionsLength > len(data) {
		return "", ErrInvalidExtensions
	}

	// Step 8: Parse extensions to find SNI
	extensionsEnd := offset + extensionsLength
	for offset+4 <= extensionsEnd {
		extType := readUint16(data, offset)
		extLength := int(readUint16(data, offset+2))
		offset += 4

		if offset+extLength > extensionsEnd {
			return "", ErrInvalidExtensions
		}

		// Check if this is SNI extension
		if extType == ExtensionTypeSNI {
			return parseSNIExtension(data[offset : offset+extLength])
		}

		offset += extLength
	}

	return "", ErrNoSNIExtension
}

// =============================================================================
// SNI EXTENSION PARSER
// =============================================================================

// parseSNIExtension extracts the hostname from SNI extension data.
// SNI Extension Format:
//   - ServerNameList Length (2 bytes)
//   - ServerNameType (1 byte) - 0x00 for DNS hostname
//   - ServerName Length (2 bytes)
//   - ServerName (variable) - UTF-8 hostname
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrMalformedSNI
	}

	// Read ServerNameList length
	listLength := int(readUint16(data, 0))
	if listLength+2 > len(data) {
		return "", ErrMalformedSNI
	}

	// Read ServerNameType
	nameType := data[2]
	if nameType != SNINameTypeDNSHostname {
		return "", ErrNonHostnameSNI
	}

	// Read ServerName length
	if len(data) < 5 {
		return "", ErrMalformedSNI
	}
	nameLength := int(readUint16(data, 3))

	// Extract hostname
	if 5+nameLength > len(data) {
		return "", ErrMalformedSNI
	}
	hostname := string(data[5 : 5+nameLength])

	// Basic validation
	if hostname == "" {
		return "", ErrMalformedSNI
	}

	return hostname, nil
}

// =============================================================================
// BINARY PARSING HELPERS
// =============================================================================

// readUint16 reads a 2-byte big-endian unsigned integer from data at offset.
func readUint16(data []byte, offset int) uint16 {
	return uint16(data[offset])<<8 | uint16(data[offset+1])
}

// readUint24 reads a 3-byte big-endian unsigned integer from data at offset.
func readUint24(data []byte, offset int) uint32 {
	return uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

// ExtractSNIFromBytes extracts SNI directly from raw packet bytes.
// This is a convenience wrapper that creates a temporary Packet struct.
func ExtractSNIFromBytes(rawData []byte, destPort int, direction string) (string, error) {
	packet := &models.Packet{
		RawData:         rawData,
		DestinationPort: destPort,
		Direction:       direction,
	}
	return ExtractSNI(packet)
}

// IsTLSClientHello checks if raw data appears to be a TLS ClientHello.
// Does not perform full parsing, just checks header bytes.
func IsTLSClientHello(data []byte) bool {
	if len(data) < MinTLSRecordSize+MinHandshakeSize {
		return false
	}

	// Check ContentType is Handshake (0x16)
	if data[0] != ContentTypeHandshake {
		return false
	}

	// Check HandshakeType is ClientHello (0x01)
	if data[5] != HandshakeTypeClientHello {
		return false
	}

	return true
}

// SNIExtractionResult contains detailed extraction results.
type SNIExtractionResult struct {
	// SNI is the extracted hostname (empty if extraction failed)
	SNI string

	// Success indicates if extraction succeeded
	Success bool

	// Error contains the extraction error (nil if success)
	Error error

	// ErrorMessage is a human-readable error description
	ErrorMessage string
}

// ExtractSNIWithResult returns detailed extraction results.
func ExtractSNIWithResult(packet *models.Packet) *SNIExtractionResult {
	sni, err := ExtractSNI(packet)

	result := &SNIExtractionResult{
		SNI:     sni,
		Success: err == nil,
		Error:   err,
	}

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("SNI extraction failed: %v", err)
	}

	return result
}
