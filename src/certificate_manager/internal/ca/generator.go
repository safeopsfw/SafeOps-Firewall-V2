// Package ca implements root CA certificate generation functionality.
// This file provides the core cryptographic operations for creating self-signed
// root CA certificates with RSA 4096-bit keys and proper X.509v3 extensions.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// DefaultKeySize is the default RSA key size in bits
	DefaultKeySize = 4096
	// MinKeySize is the minimum allowed RSA key size for security compliance
	MinKeySize = 2048
	// MaxKeySize is the maximum supported RSA key size
	MaxKeySize = 8192
	// DefaultValidityYears is the default CA certificate validity in years
	DefaultValidityYears = 10
	// MaxValidityYears is the maximum allowed validity period
	MaxValidityYears = 30
	// DefaultSerialNumberBits is the default serial number bit length
	DefaultSerialNumberBits = 128
	// MinSerialNumberBits is the minimum serial number bit length
	MinSerialNumberBits = 64
)

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrInvalidKeySize indicates the key size is below minimum or invalid
	ErrInvalidKeySize = errors.New("key size must be at least 2048 bits and a power of 2")
	// ErrInvalidValidity indicates invalid validity period
	ErrInvalidValidity = errors.New("validity years must be between 1 and 30")
	// ErrEmptyOrganization indicates organization name is required
	ErrEmptyOrganization = errors.New("organization name is required")
	// ErrEmptyCommonName indicates common name is required
	ErrEmptyCommonName = errors.New("common name is required")
	// ErrInvalidCountryCode indicates country code must be 2 letters
	ErrInvalidCountryCode = errors.New("country must be a 2-letter code")
	// ErrKeyGenerationFailed indicates RSA key generation failure
	ErrKeyGenerationFailed = errors.New("failed to generate RSA key pair")
	// ErrSerialGenerationFailed indicates serial number generation failure
	ErrSerialGenerationFailed = errors.New("failed to generate serial number")
	// ErrCertificateSigningFailed indicates certificate signing failure
	ErrCertificateSigningFailed = errors.New("failed to sign certificate")
	// ErrTemplateCreationFailed indicates template creation failure
	ErrTemplateCreationFailed = errors.New("failed to create certificate template")
)

// ============================================================================
// CA Configuration Structure
// ============================================================================

// CAGeneratorConfig encapsulates all parameters needed for CA generation.
// This structure is used to configure the root CA certificate generation process.
type CAGeneratorConfig struct {
	// Organization is the organization name (e.g., "SafeOps Network")
	Organization string
	// OrganizationalUnit is the organizational unit (optional)
	OrganizationalUnit string
	// Country is the two-letter country code (e.g., "US")
	Country string
	// Province is the state or province (optional)
	Province string
	// Locality is the city or locality (optional)
	Locality string
	// CommonName is the CA common name (e.g., "SafeOps Root CA")
	CommonName string
	// ValidityYears is the validity period in years (default: 10, max: 30)
	ValidityYears int
	// KeySize is the RSA key size in bits (default: 4096, min: 2048)
	KeySize int
	// SerialNumberBits is the serial number bit length (default: 128)
	SerialNumberBits int
}

// DefaultCAGeneratorConfig returns a CAGeneratorConfig with sensible defaults.
func DefaultCAGeneratorConfig() *CAGeneratorConfig {
	return &CAGeneratorConfig{
		Organization:     "SafeOps Network",
		Country:          "US",
		CommonName:       "SafeOps Root CA",
		ValidityYears:    DefaultValidityYears,
		KeySize:          DefaultKeySize,
		SerialNumberBits: DefaultSerialNumberBits,
	}
}

// ============================================================================
// Root CA Result Structure
// ============================================================================

// RootCAResult contains all artifacts from CA generation for storage and distribution.
type RootCAResult struct {
	// PrivateKey is the generated RSA private key (in-memory)
	PrivateKey *rsa.PrivateKey
	// PrivateKeyPEM is the PEM-encoded private key (unencrypted)
	PrivateKeyPEM []byte
	// Certificate is the parsed X.509 certificate object
	Certificate *x509.Certificate
	// CertificatePEM is the PEM-encoded certificate
	CertificatePEM []byte
	// CertificateDER is the DER-encoded certificate
	CertificateDER []byte
	// SerialNumber is the hex-formatted serial number
	SerialNumber string
	// Fingerprint is the SHA-256 fingerprint
	Fingerprint string
	// NotBefore is the validity start timestamp
	NotBefore time.Time
	// NotAfter is the validity end timestamp
	NotAfter time.Time
}

// ============================================================================
// Validation Function
// ============================================================================

// ValidateCAConfig validates CAGeneratorConfig before generation.
// It enforces security requirements and valid parameter ranges.
func ValidateCAConfig(config *CAGeneratorConfig) error {
	if config == nil {
		return errors.New("configuration is nil")
	}

	// Validate Organization
	if config.Organization == "" {
		return ErrEmptyOrganization
	}

	// Validate CommonName
	if config.CommonName == "" {
		return ErrEmptyCommonName
	}

	// Validate Country (must be 2-letter code)
	if config.Country != "" && len(config.Country) != 2 {
		return ErrInvalidCountryCode
	}

	// Validate ValidityYears
	if config.ValidityYears <= 0 || config.ValidityYears > MaxValidityYears {
		return fmt.Errorf("%w: must be between 1 and %d years", ErrInvalidValidity, MaxValidityYears)
	}

	// Validate KeySize (must be >= 2048 and power of 2)
	if config.KeySize < MinKeySize {
		return fmt.Errorf("%w: minimum is %d bits", ErrInvalidKeySize, MinKeySize)
	}
	if !isPowerOfTwo(config.KeySize) {
		return fmt.Errorf("%w: must be power of 2 (2048, 4096, 8192)", ErrInvalidKeySize)
	}
	if config.KeySize > MaxKeySize {
		return fmt.Errorf("%w: maximum is %d bits", ErrInvalidKeySize, MaxKeySize)
	}

	// Validate SerialNumberBits
	if config.SerialNumberBits < MinSerialNumberBits {
		config.SerialNumberBits = DefaultSerialNumberBits
	}

	return nil
}

// isPowerOfTwo checks if n is a power of 2
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// ============================================================================
// RSA Key Pair Generation
// ============================================================================

// GenerateKeyPair generates an RSA private/public key pair using crypto/rand.
// The default key size is 4096 bits, with a minimum of 2048 bits for security.
// Returns the private key (containing both private and public keys) or an error.
//
// Execution time: ~2-5 seconds for 4096-bit keys depending on system entropy.
func GenerateKeyPair(keySize int) (*rsa.PrivateKey, error) {
	// Apply defaults
	if keySize == 0 {
		keySize = DefaultKeySize
	}

	// Validate key size
	if keySize < MinKeySize {
		return nil, fmt.Errorf("%w: got %d bits, minimum is %d", ErrInvalidKeySize, keySize, MinKeySize)
	}

	if !isPowerOfTwo(keySize) {
		return nil, fmt.Errorf("%w: got %d, must be power of 2", ErrInvalidKeySize, keySize)
	}

	// Generate RSA key pair using cryptographically secure random source
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
	}

	return privateKey, nil
}

// ============================================================================
// Serial Number Generation
// ============================================================================

// GenerateSerialNumber generates a cryptographically random serial number.
// The default bit length is 128 bits (16 bytes) for global uniqueness.
// Uses crypto/rand for RFC 5280 compliance.
// Returns a big.Int suitable for x509.Certificate.SerialNumber.
func GenerateSerialNumber(bits int) (*big.Int, error) {
	// Apply defaults
	if bits == 0 {
		bits = DefaultSerialNumberBits
	}

	// Ensure minimum bit length
	if bits < MinSerialNumberBits {
		bits = MinSerialNumberBits
	}

	// Calculate byte length
	byteLen := bits / 8

	// Generate random bytes
	serialBytes := make([]byte, byteLen)
	_, err := rand.Read(serialBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Ensure positive integer (clear MSB to ensure positive)
	serialBytes[0] &= 0x7F

	// Convert to big.Int
	serial := new(big.Int).SetBytes(serialBytes)

	// Ensure non-zero
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	return serial, nil
}

// ============================================================================
// X.509 Certificate Template Creation
// ============================================================================

// CreateCertificateTemplate constructs an x509.Certificate template with CA extensions.
// It sets up the certificate with proper CA fields including BasicConstraints,
// KeyUsage, and validity period.
func CreateCertificateTemplate(config *CAGeneratorConfig) (*x509.Certificate, error) {
	// Validate configuration
	if err := ValidateCAConfig(config); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTemplateCreationFailed, err)
	}

	// Generate serial number
	serialNumber, err := GenerateSerialNumber(config.SerialNumberBits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTemplateCreationFailed, err)
	}

	// Calculate validity period
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(config.ValidityYears, 0, 0)

	// Build subject distinguished name
	subject := pkix.Name{
		CommonName: config.CommonName,
	}

	if config.Organization != "" {
		subject.Organization = []string{config.Organization}
	}
	if config.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{config.OrganizationalUnit}
	}
	if config.Country != "" {
		subject.Country = []string{config.Country}
	}
	if config.Province != "" {
		subject.Province = []string{config.Province}
	}
	if config.Locality != "" {
		subject.Locality = []string{config.Locality}
	}

	// Create certificate template with CA extensions
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		// For self-signed root CA, Issuer equals Subject
		Issuer: subject,

		// Validity period
		NotBefore: notBefore,
		NotAfter:  notAfter,

		// CA-specific flags
		IsCA:                  true,
		BasicConstraintsValid: true,

		// Key Usage for CA certificates (Certificate Sign + CRL Sign)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		// Path length constraint: 0 means this CA cannot issue intermediate CAs
		MaxPathLen:     0,
		MaxPathLenZero: true,

		// Signature algorithm (will be determined during signing based on key type)
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	return template, nil
}

// ============================================================================
// Extension Setting Helper
// ============================================================================

// SetCAExtensions sets CA-specific X.509v3 extensions on the template.
// This includes SubjectKeyIdentifier calculated from the public key.
func SetCAExtensions(template *x509.Certificate, publicKey *rsa.PublicKey) error {
	if template == nil {
		return errors.New("template is nil")
	}
	if publicKey == nil {
		return errors.New("public key is nil")
	}

	// Calculate SubjectKeyIdentifier (SHA-1 hash of public key per RFC 5280)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha1.Sum(publicKeyDER)
	template.SubjectKeyId = hash[:]

	// Ensure CA extensions are set
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.MaxPathLen = 0
	template.MaxPathLenZero = true

	// Root CAs typically don't have ExtendedKeyUsage
	template.ExtKeyUsage = nil

	return nil
}

// ============================================================================
// Self-Signing Function
// ============================================================================

// SignCertificate signs a certificate template with the CA's private key.
// For self-signed root CA, the template is both the certificate and the parent.
// Uses SHA256-RSA signature algorithm.
// Returns DER-encoded certificate bytes.
func SignCertificate(template *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	if template == nil {
		return nil, errors.New("template is nil")
	}
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Set SubjectKeyIdentifier from public key
	if err := SetCAExtensions(template, &privateKey.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: failed to set extensions: %v", ErrCertificateSigningFailed, err)
	}

	// Self-sign: template is both the certificate and the parent
	// The public key from privateKey is embedded in the certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,              // Certificate to create
		template,              // Parent (self for root CA)
		&privateKey.PublicKey, // Public key to embed
		privateKey,            // Signing key
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificateSigningFailed, err)
	}

	return derBytes, nil
}

// ============================================================================
// PEM Encoding Functions
// ============================================================================

// EncodeCertificatePEM converts DER-encoded certificate bytes to PEM format.
// Adds "-----BEGIN CERTIFICATE-----" header and footer.
func EncodeCertificatePEM(derBytes []byte) ([]byte, error) {
	if len(derBytes) == 0 {
		return nil, errors.New("DER bytes are empty")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// EncodePrivateKeyPEM converts an RSA private key to PEM format (PKCS#1).
// Uses "-----BEGIN RSA PRIVATE KEY-----" markers.
// NOTE: The returned PEM is UNENCRYPTED. Encryption is handled separately
// in key_encryption.go.
func EncodePrivateKeyPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Marshal to PKCS#1 DER format
	derBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// EncodePrivateKeyPKCS8PEM converts an RSA private key to PKCS#8 PEM format.
// Uses "-----BEGIN PRIVATE KEY-----" markers.
// This format is more modern and supports multiple key types.
func EncodePrivateKeyPKCS8PEM(privateKey crypto.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Marshal to PKCS#8 DER format
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// ============================================================================
// Main CA Generation Function
// ============================================================================

// GenerateRootCA orchestrates the complete root CA generation process.
// It executes all sub-functions in the correct order:
//  1. Validate configuration
//  2. Generate RSA key pair
//  3. Create certificate template with CA extensions
//  4. Self-sign certificate
//  5. Encode certificate to PEM format
//  6. Encode private key to PEM format (unencrypted)
//  7. Extract metadata
//
// Returns RootCAResult containing all generated artifacts.
func GenerateRootCA(config *CAGeneratorConfig) (*RootCAResult, error) {
	// Apply defaults if config is nil
	if config == nil {
		config = DefaultCAGeneratorConfig()
	}

	// Apply defaults for zero values
	if config.KeySize == 0 {
		config.KeySize = DefaultKeySize
	}
	if config.ValidityYears == 0 {
		config.ValidityYears = DefaultValidityYears
	}
	if config.SerialNumberBits == 0 {
		config.SerialNumberBits = DefaultSerialNumberBits
	}

	// Step 1: Validate configuration
	if err := ValidateCAConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Step 2: Generate RSA key pair
	privateKey, err := GenerateKeyPair(config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Step 3: Create certificate template
	template, err := CreateCertificateTemplate(config)
	if err != nil {
		return nil, fmt.Errorf("template creation failed: %w", err)
	}

	// Step 4: Self-sign certificate
	certDER, err := SignCertificate(template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("certificate signing failed: %w", err)
	}

	// Parse the signed certificate to get the final x509.Certificate object
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	// Step 5: Encode certificate to PEM format
	certPEM, err := EncodeCertificatePEM(certDER)
	if err != nil {
		return nil, fmt.Errorf("certificate PEM encoding failed: %w", err)
	}

	// Step 6: Encode private key to PEM format (unencrypted)
	keyPEM, err := EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("private key PEM encoding failed: %w", err)
	}

	// Step 7: Extract metadata using metadata.go functions
	serialNumber := GetSerialNumber(certificate)
	fingerprint := GetFingerprint(certificate)

	// Build result
	result := &RootCAResult{
		PrivateKey:     privateKey,
		PrivateKeyPEM:  keyPEM,
		Certificate:    certificate,
		CertificatePEM: certPEM,
		CertificateDER: certDER,
		SerialNumber:   serialNumber,
		Fingerprint:    fingerprint,
		NotBefore:      certificate.NotBefore,
		NotAfter:       certificate.NotAfter,
	}

	return result, nil
}

// ============================================================================
// Convenience Functions
// ============================================================================

// GenerateDefaultRootCA generates a root CA with default SafeOps settings.
// Uses 4096-bit RSA key, 10-year validity, and standard organization info.
func GenerateDefaultRootCA() (*RootCAResult, error) {
	return GenerateRootCA(DefaultCAGeneratorConfig())
}

// GenerateRootCAWithOptions generates a root CA with custom options.
// This is a convenience function for common customizations.
func GenerateRootCAWithOptions(organization, commonName, country string, validityYears, keySize int) (*RootCAResult, error) {
	config := &CAGeneratorConfig{
		Organization:     organization,
		CommonName:       commonName,
		Country:          country,
		ValidityYears:    validityYears,
		KeySize:          keySize,
		SerialNumberBits: DefaultSerialNumberBits,
	}

	return GenerateRootCA(config)
}

// ============================================================================
// Utility Functions
// ============================================================================

// ValidateGeneratedCA validates a generated CA certificate meets requirements.
// This is useful for verifying CA certificates loaded from storage.
func ValidateGeneratedCA(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check if it's a CA certificate
	if !cert.IsCA {
		return errors.New("certificate is not a CA")
	}

	// Check BasicConstraints
	if !cert.BasicConstraintsValid {
		return errors.New("BasicConstraints extension is not valid")
	}

	// Check KeyUsage includes CertSign
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate lacks CertSign key usage")
	}

	// Check if self-signed (for root CA)
	if cert.Issuer.String() != cert.Subject.String() {
		return errors.New("root CA must be self-signed (issuer must equal subject)")
	}

	// Check validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (starts %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (ended %s)", cert.NotAfter)
	}

	// Check key size for RSA
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.N.BitLen() < MinKeySize {
			return fmt.Errorf("RSA key size %d bits is below minimum %d", rsaKey.N.BitLen(), MinKeySize)
		}
	}

	return nil
}

// GetCAInfo returns a summary of CA certificate information.
// This is useful for logging and display purposes.
func GetCAInfo(cert *x509.Certificate) map[string]interface{} {
	if cert == nil {
		return nil
	}

	info := map[string]interface{}{
		"subject":        GetSubject(cert),
		"issuer":         GetIssuer(cert),
		"serial_number":  GetSerialNumber(cert),
		"fingerprint":    GetFingerprint(cert),
		"not_before":     cert.NotBefore,
		"not_after":      cert.NotAfter,
		"is_ca":          cert.IsCA,
		"key_usage":      GetKeyUsage(cert),
		"key_size":       GetKeySize(cert),
		"key_type":       GetKeyType(cert),
		"days_remaining": RemainingValidityDays(cert),
		"self_signed":    IsSelfSigned(cert),
	}

	return info
}
