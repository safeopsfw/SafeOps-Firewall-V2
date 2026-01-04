package sni_parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TLS record types
const (
	recordTypeHandshake = 0x16
)

// TLS handshake types
const (
	handshakeTypeClientHello = 0x01
)

// TLS extension types
const (
	extensionServerName = 0x0000
)

// SNIInfo contains parsed SNI information
type SNIInfo struct {
	Domain      string
	Found       bool
	TLSVersion  uint16
	CipherCount int
}

// ExtractSNI extracts Server Name Indication from TLS ClientHello packet
func ExtractSNI(packet []byte) (*SNIInfo, error) {
	info := &SNIInfo{
		Found: false,
	}

	if len(packet) < 43 {
		return info, fmt.Errorf("packet too short for TLS ClientHello")
	}

	// Check TLS record type (0x16 = Handshake)
	if packet[0] != recordTypeHandshake {
		return info, fmt.Errorf("not a TLS handshake packet (type: 0x%02x)", packet[0])
	}

	// Parse TLS version (bytes 1-2)
	info.TLSVersion = binary.BigEndian.Uint16(packet[1:3])

	// Skip TLS record header (5 bytes)
	// TLS record: [type(1) version(2) length(2)] = 5 bytes
	if len(packet) < 6 {
		return info, fmt.Errorf("packet too short after record header")
	}

	// Check handshake type (byte 5 should be 0x01 = ClientHello)
	if packet[5] != handshakeTypeClientHello {
		return info, fmt.Errorf("not a ClientHello (type: 0x%02x)", packet[5])
	}

	// Parse ClientHello structure:
	// Handshake Type (1) + Length (3) + Version (2) + Random (32) + Session ID Length (1)
	offset := 5 // Start after TLS record header

	// Skip: Handshake type (1) + Length (3) + Client Version (2) + Random (32)
	offset += 1 + 3 + 2 + 32

	if offset >= len(packet) {
		return info, fmt.Errorf("packet too short for session ID")
	}

	// Session ID length
	sessionIDLen := int(packet[offset])
	offset++

	// Skip session ID
	offset += sessionIDLen

	if offset+2 >= len(packet) {
		return info, fmt.Errorf("packet too short for cipher suites")
	}

	// Cipher suites length
	cipherSuitesLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	info.CipherCount = cipherSuitesLen / 2

	// Skip cipher suites
	offset += cipherSuitesLen

	if offset+1 >= len(packet) {
		return info, fmt.Errorf("packet too short for compression methods")
	}

	// Compression methods length
	compressionLen := int(packet[offset])
	offset++

	// Skip compression methods
	offset += compressionLen

	if offset+2 >= len(packet) {
		// No extensions present
		return info, nil
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2

	extensionsEnd := offset + extensionsLen

	// Parse extensions
	for offset+4 <= extensionsEnd && offset+4 <= len(packet) {
		// Extension type
		extType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2

		// Extension length
		extLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
		offset += 2

		if offset+extLen > len(packet) {
			break
		}

		// Check if this is the SNI extension
		if extType == extensionServerName {
			sni, err := parseServerNameExtension(packet[offset : offset+extLen])
			if err == nil && sni != "" {
				info.Domain = sni
				info.Found = true
				return info, nil
			}
		}

		// Move to next extension
		offset += extLen
	}

	return info, nil
}

// parseServerNameExtension parses the SNI extension data
func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("SNI extension too short")
	}

	// Server Name List Length (2 bytes)
	// listLen := binary.BigEndian.Uint16(data[0:2])
	offset := 2

	if offset >= len(data) {
		return "", fmt.Errorf("invalid SNI extension")
	}

	// Server Name Type (1 byte) - should be 0x00 for hostname
	nameType := data[offset]
	offset++

	if nameType != 0x00 {
		return "", fmt.Errorf("unsupported name type: 0x%02x", nameType)
	}

	if offset+2 > len(data) {
		return "", fmt.Errorf("SNI extension too short for name length")
	}

	// Server Name Length (2 bytes)
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+nameLen > len(data) {
		return "", fmt.Errorf("SNI name length exceeds data")
	}

	// Server Name (hostname)
	hostname := string(data[offset : offset+nameLen])

	return hostname, nil
}

// IsClientHello checks if packet is a TLS ClientHello
func IsClientHello(packet []byte) bool {
	if len(packet) < 6 {
		return false
	}

	// Check TLS record type (0x16 = Handshake)
	if packet[0] != recordTypeHandshake {
		return false
	}

	// Check handshake type (0x01 = ClientHello)
	if packet[5] != handshakeTypeClientHello {
		return false
	}

	return true
}

// GetTLSVersion extracts TLS version from packet
func GetTLSVersion(packet []byte) uint16 {
	if len(packet) < 3 {
		return 0
	}
	return binary.BigEndian.Uint16(packet[1:3])
}

// FormatTLSVersion converts TLS version number to string
func FormatTLSVersion(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// QuickExtractSNI is a fast SNI extractor (simplified version)
func QuickExtractSNI(payload []byte) string {
	// Quick pattern matching for SNI
	// Look for common SNI patterns in TLS handshake

	// Search for server_name extension pattern
	// This is a heuristic approach, not fully spec-compliant
	for i := 0; i < len(payload)-50; i++ {
		// Look for extension type 0x0000 (server_name)
		if payload[i] == 0x00 && payload[i+1] == 0x00 {
			// Check if next bytes look like SNI structure
			if i+5 < len(payload) {
				// Extension length
				extLen := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))

				if i+4+extLen <= len(payload) && extLen > 5 && extLen < 300 {
					// List length
					if i+6 < len(payload) {
						// Name type (should be 0x00)
						if payload[i+6] == 0x00 && i+9 < len(payload) {
							// Name length
							nameLen := int(binary.BigEndian.Uint16(payload[i+7 : i+9]))

							if nameLen > 0 && nameLen < 256 && i+9+nameLen <= len(payload) {
								domain := string(payload[i+9 : i+9+nameLen])

								// Basic validation: domain should contain a dot
								if bytes.Contains([]byte(domain), []byte(".")) {
									return domain
								}
							}
						}
					}
				}
			}
		}
	}

	return ""
}
