package distribution

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// Format Constants
// ============================================================================

const (
	// FormatPEM represents PEM-encoded certificate format (base64 with headers)
	FormatPEM = "PEM"
	// FormatDER represents DER-encoded certificate format (raw binary)
	FormatDER = "DER"
	// FormatP7B represents PKCS#7 certificate chain format
	FormatP7B = "P7B"
	// FormatPKCS12 represents PKCS#12 archive format (with private key)
	FormatPKCS12 = "PKCS12"
)

// PEM block type constants
const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypePrivateKey  = "PRIVATE KEY"
	pemTypeRSAPrivKey  = "RSA PRIVATE KEY"
	pemTypeECPrivKey   = "EC PRIVATE KEY"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrInvalidPEMFormat  = errors.New("invalid PEM format")
	ErrInvalidDERFormat  = errors.New("invalid DER format")
	ErrInvalidBlockType  = errors.New("invalid PEM block type")
	ErrNoPEMBlockFound   = errors.New("no PEM block found in input")
	ErrEmptyInput        = errors.New("empty input data")
	ErrUnknownFormat     = errors.New("unknown certificate format")
	ErrUnsupportedFormat = errors.New("unsupported target format")
	ErrConversionFailed  = errors.New("format conversion failed")
)

// ============================================================================
// PEM to DER Conversion
// ============================================================================

// PEMToDER converts PEM-encoded certificate to DER binary format.
// Extracts DER bytes from PEM block structure and validates the certificate.
func PEMToDER(pemBytes []byte) ([]byte, error) {
	if len(pemBytes) == 0 {
		return nil, ErrEmptyInput
	}

	// Parse PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoPEMBlockFound
	}

	// Validate block type is CERTIFICATE
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidBlockType, pemTypeCertificate, block.Type)
	}

	// Validate DER bytes parse as valid X.509 certificate
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDERFormat, err)
	}

	return block.Bytes, nil
}

// PEMToDERNoValidation converts PEM to DER without X.509 validation.
// Use only when performance is critical and input is trusted.
func PEMToDERNoValidation(pemBytes []byte) ([]byte, error) {
	if len(pemBytes) == 0 {
		return nil, ErrEmptyInput
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoPEMBlockFound
	}

	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidBlockType, pemTypeCertificate, block.Type)
	}

	return block.Bytes, nil
}

// ============================================================================
// DER to PEM Conversion
// ============================================================================

// DERToPEM converts DER binary certificate to PEM text format.
// Wraps DER bytes in PEM block with headers and base64 encoding.
func DERToPEM(derBytes []byte) ([]byte, error) {
	if len(derBytes) == 0 {
		return nil, ErrEmptyInput
	}

	// Validate DER bytes parse as valid X.509 certificate
	_, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDERFormat, err)
	}

	// Create PEM block
	block := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: derBytes,
	}

	// Encode PEM block to bytes
	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return nil, fmt.Errorf("%w: pem encoding failed", ErrConversionFailed)
	}

	return pemBytes, nil
}

// DERToPEMNoValidation converts DER to PEM without X.509 validation.
// Use only when performance is critical and input is trusted.
func DERToPEMNoValidation(derBytes []byte) ([]byte, error) {
	if len(derBytes) == 0 {
		return nil, ErrEmptyInput
	}

	block := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return nil, fmt.Errorf("%w: pem encoding failed", ErrConversionFailed)
	}

	return pemBytes, nil
}

// ============================================================================
// PEM Parsing Functions
// ============================================================================

// ParsePEM parses PEM-encoded data and extracts the first PEM block.
// Returns the pem.Block structure for further processing.
func ParsePEM(pemBytes []byte) (*pem.Block, error) {
	if len(pemBytes) == 0 {
		return nil, ErrEmptyInput
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoPEMBlockFound
	}

	return block, nil
}

// ParsePEMCertificate parses PEM and validates it's a certificate block.
func ParsePEMCertificate(pemBytes []byte) (*pem.Block, error) {
	block, err := ParsePEM(pemBytes)
	if err != nil {
		return nil, err
	}

	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidBlockType, pemTypeCertificate, block.Type)
	}

	return block, nil
}

// GetDERBytesFromPEM extracts DER bytes from PEM-encoded certificate.
// Convenience wrapper combining ParsePEM and DER extraction.
func GetDERBytesFromPEM(pemBytes []byte) ([]byte, error) {
	block, err := ParsePEMCertificate(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("GetDERBytesFromPEM: %w", err)
	}

	return block.Bytes, nil
}

// ParsePEMChain parses multiple PEM blocks from a single input (certificate chains).
// Returns a slice of pem.Block structures, one per certificate in the chain.
func ParsePEMChain(pemBytes []byte) ([]*pem.Block, error) {
	if len(pemBytes) == 0 {
		return nil, ErrEmptyInput
	}

	var blocks []*pem.Block
	remaining := pemBytes

	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			// No more PEM blocks found
			break
		}
		blocks = append(blocks, block)
	}

	if len(blocks) == 0 {
		return nil, ErrNoPEMBlockFound
	}

	return blocks, nil
}

// ParseCertificateChain parses a PEM chain and returns only certificate blocks.
func ParseCertificateChain(pemBytes []byte) ([]*pem.Block, error) {
	blocks, err := ParsePEMChain(pemBytes)
	if err != nil {
		return nil, err
	}

	var certBlocks []*pem.Block
	for _, block := range blocks {
		if block.Type == pemTypeCertificate {
			certBlocks = append(certBlocks, block)
		}
	}

	if len(certBlocks) == 0 {
		return nil, fmt.Errorf("%w: no certificate blocks found in chain", ErrNoPEMBlockFound)
	}

	return certBlocks, nil
}

// ============================================================================
// Format Detection and Validation
// ============================================================================

// ValidateCertificateFormat detects whether input is PEM or DER format.
// Returns the format identifier ("PEM" or "DER") or error if unknown.
func ValidateCertificateFormat(certBytes []byte) (string, error) {
	if len(certBytes) == 0 {
		return "", ErrEmptyInput
	}

	// Check for PEM format first (text-based, starts with "-----BEGIN")
	if isPEMFormat(certBytes) {
		// Try to parse as PEM to validate
		block, _ := pem.Decode(certBytes)
		if block != nil {
			return FormatPEM, nil
		}
		// Has BEGIN marker but failed to parse
		return "", fmt.Errorf("%w: has PEM markers but failed to parse", ErrInvalidPEMFormat)
	}

	// Try parsing as DER (binary format)
	_, err := x509.ParseCertificate(certBytes)
	if err == nil {
		return FormatDER, nil
	}

	return "", ErrUnknownFormat
}

// isPEMFormat checks if the bytes start with PEM header markers.
func isPEMFormat(data []byte) bool {
	return bytes.HasPrefix(data, []byte("-----BEGIN"))
}

// ValidatePEMFormat validates PEM format structure.
// Checks for proper BEGIN/END markers and valid base64 content.
func ValidatePEMFormat(pemBytes []byte) error {
	if len(pemBytes) == 0 {
		return ErrEmptyInput
	}

	// Convert to string for marker checking
	pemStr := string(pemBytes)

	// Check for BEGIN marker
	if !strings.Contains(pemStr, "-----BEGIN") {
		return fmt.Errorf("%w: missing -----BEGIN marker", ErrInvalidPEMFormat)
	}

	// Check for END marker
	if !strings.Contains(pemStr, "-----END") {
		return fmt.Errorf("%w: missing -----END marker", ErrInvalidPEMFormat)
	}

	// Check BEGIN appears before END
	beginIdx := strings.Index(pemStr, "-----BEGIN")
	endIdx := strings.Index(pemStr, "-----END")
	if beginIdx >= endIdx {
		return fmt.Errorf("%w: -----BEGIN must appear before -----END", ErrInvalidPEMFormat)
	}

	// Try to parse to validate base64 content
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("%w: failed to decode PEM content (possibly invalid base64)", ErrInvalidPEMFormat)
	}

	return nil
}

// ValidateDERFormat validates DER format structure.
// Checks if bytes parse as valid X.509 certificate.
func ValidateDERFormat(derBytes []byte) error {
	if len(derBytes) == 0 {
		return ErrEmptyInput
	}

	_, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDERFormat, err)
	}

	return nil
}

// ============================================================================
// Unified Conversion Function
// ============================================================================

// ConvertToFormat converts certificate bytes from auto-detected format to target format.
// Supports PEM and DER formats. Returns input unchanged if already in target format.
func ConvertToFormat(certBytes []byte, targetFormat string) ([]byte, error) {
	if len(certBytes) == 0 {
		return nil, ErrEmptyInput
	}

	// Normalize target format
	targetFormat = strings.ToUpper(targetFormat)
	if targetFormat != FormatPEM && targetFormat != FormatDER {
		return nil, fmt.Errorf("%w: %s (supported: PEM, DER)", ErrUnsupportedFormat, targetFormat)
	}

	// Detect source format
	sourceFormat, err := ValidateCertificateFormat(certBytes)
	if err != nil {
		return nil, fmt.Errorf("ConvertToFormat: %w", err)
	}

	// If same format, return as-is
	if sourceFormat == targetFormat {
		return certBytes, nil
	}

	// Perform conversion
	switch {
	case sourceFormat == FormatPEM && targetFormat == FormatDER:
		return PEMToDER(certBytes)
	case sourceFormat == FormatDER && targetFormat == FormatPEM:
		return DERToPEM(certBytes)
	default:
		return nil, fmt.Errorf("%w: %s -> %s not supported", ErrConversionFailed, sourceFormat, targetFormat)
	}
}

// MustConvertToFormat is like ConvertToFormat but panics on error.
// Use only when input is known to be valid.
func MustConvertToFormat(certBytes []byte, targetFormat string) []byte {
	result, err := ConvertToFormat(certBytes, targetFormat)
	if err != nil {
		panic(fmt.Sprintf("MustConvertToFormat: %v", err))
	}
	return result
}

// ============================================================================
// Fingerprint Calculation
// ============================================================================

// GetFingerprintFromBytes calculates SHA-256 fingerprint from certificate bytes.
// Supports both PEM and DER input formats.
// Returns colon-separated hex fingerprint (e.g., "A1:B2:C3:D4:...").
func GetFingerprintFromBytes(certBytes []byte, format string) (string, error) {
	if len(certBytes) == 0 {
		return "", ErrEmptyInput
	}

	var derBytes []byte
	var err error

	// Get DER bytes based on format
	format = strings.ToUpper(format)
	switch format {
	case FormatPEM:
		derBytes, err = PEMToDERNoValidation(certBytes)
		if err != nil {
			return "", fmt.Errorf("GetFingerprintFromBytes: %w", err)
		}
	case FormatDER:
		derBytes = certBytes
	case "": // Auto-detect
		detectedFormat, detectErr := ValidateCertificateFormat(certBytes)
		if detectErr != nil {
			return "", fmt.Errorf("GetFingerprintFromBytes: %w", detectErr)
		}
		if detectedFormat == FormatPEM {
			derBytes, err = PEMToDERNoValidation(certBytes)
			if err != nil {
				return "", fmt.Errorf("GetFingerprintFromBytes: %w", err)
			}
		} else {
			derBytes = certBytes
		}
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(derBytes)

	// Format as colon-separated hex string
	return formatFingerprint(hash[:]), nil
}

// GetFingerprintFromCertificate calculates SHA-256 fingerprint from parsed certificate.
func GetFingerprintFromCertificate(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return formatFingerprint(hash[:])
}

// formatFingerprint converts hash bytes to colon-separated hex string.
func formatFingerprint(hash []byte) string {
	hexStr := hex.EncodeToString(hash)

	// Insert colons every 2 characters
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		end := i + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, strings.ToUpper(hexStr[i:end]))
	}

	return strings.Join(parts, ":")
}

// ============================================================================
// Utility Functions
// ============================================================================

// EncodeCertificateToPEM encodes an X.509 certificate to PEM format.
func EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemTypeCertificate,
		Bytes: cert.Raw,
	})
}

// EncodeCertificateChainToPEM encodes multiple certificates to a PEM chain.
func EncodeCertificateChainToPEM(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		pem.Encode(&buf, &pem.Block{
			Type:  pemTypeCertificate,
			Bytes: cert.Raw,
		})
	}
	return buf.Bytes()
}

// ParseCertificateFromPEM parses an X.509 certificate from PEM bytes.
func ParseCertificateFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	derBytes, err := PEMToDER(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateFromPEM: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateFromPEM: %w", err)
	}

	return cert, nil
}

// ParseCertificateFromDER parses an X.509 certificate from DER bytes.
func ParseCertificateFromDER(derBytes []byte) (*x509.Certificate, error) {
	if len(derBytes) == 0 {
		return nil, ErrEmptyInput
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateFromDER: %w", err)
	}

	return cert, nil
}

// ParseCertificateAuto parses certificate from either PEM or DER format.
func ParseCertificateAuto(certBytes []byte) (*x509.Certificate, error) {
	format, err := ValidateCertificateFormat(certBytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateAuto: %w", err)
	}

	switch format {
	case FormatPEM:
		return ParseCertificateFromPEM(certBytes)
	case FormatDER:
		return ParseCertificateFromDER(certBytes)
	default:
		return nil, fmt.Errorf("ParseCertificateAuto: %w: %s", ErrUnknownFormat, format)
	}
}

// GetCertificateInfo returns basic certificate information for display.
type CertificateInfo struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Fingerprint  string `json:"fingerprint"`
	IsCA         bool   `json:"is_ca"`
	KeyUsage     string `json:"key_usage"`
}

// GetCertificateInfoFromBytes extracts display information from certificate bytes.
func GetCertificateInfoFromBytes(certBytes []byte) (*CertificateInfo, error) {
	cert, err := ParseCertificateAuto(certBytes)
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
		Fingerprint:  GetFingerprintFromCertificate(cert),
		IsCA:         cert.IsCA,
		KeyUsage:     fmt.Sprintf("%d", cert.KeyUsage),
	}, nil
}
