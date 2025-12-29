// Package ca provides X.509 certificate metadata extraction and management utilities.
package ca

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	// ErrNilCertificate indicates a nil certificate was provided
	ErrNilCertificate = errors.New("certificate is nil")
	// ErrInvalidValidityPeriod indicates NotAfter is before NotBefore
	ErrInvalidValidityPeriod = errors.New("invalid validity period: NotAfter is before NotBefore")
)

// ============================================================================
// Certificate Metadata Structure
// ============================================================================

// CertificateMetadata contains comprehensive metadata extracted from an X.509 certificate.
// This struct provides all essential information for tracking, auditing, and managing
// the lifecycle of certificates throughout the certificate manager service.
type CertificateMetadata struct {
	// SerialNumber is the certificate serial number in colon-separated hex format (e.g., "3A:F2:E8:D1:9C:4B")
	SerialNumber string `json:"serial_number"`
	// Fingerprint is the SHA-256 fingerprint of the certificate's DER encoding
	Fingerprint string `json:"fingerprint"`
	// NotBefore is the validity start timestamp
	NotBefore time.Time `json:"not_before"`
	// NotAfter is the validity end timestamp
	NotAfter time.Time `json:"not_after"`
	// Subject is the formatted subject distinguished name (e.g., "CN=SafeOps Root CA, O=SafeOps Network, C=US")
	Subject string `json:"subject"`
	// Issuer is the formatted issuer distinguished name
	Issuer string `json:"issuer"`
	// KeyUsage is a list of key usage purposes (e.g., ["Certificate Sign", "CRL Sign"])
	KeyUsage []string `json:"key_usage"`
	// IsCA indicates whether this certificate is a CA certificate
	IsCA bool `json:"is_ca"`
	// KeySize is the public key size in bits (e.g., 4096 for RSA-4096)
	KeySize int `json:"key_size"`
	// KeyType is the public key algorithm type (e.g., "RSA", "ECDSA")
	KeyType string `json:"key_type"`
	// Version is the X.509 certificate version (typically 3)
	Version int `json:"version"`
}

// ============================================================================
// Serial Number Extraction
// ============================================================================

// GetSerialNumber extracts the serial number from an X.509 certificate.
// It converts the big.Int serial number to a human-readable colon-separated
// hexadecimal string format (e.g., "3A:F2:E8:D1:9C:4B").
// This format is commonly used in database records and audit logs.
//
// Returns an empty string if the certificate is nil.
func GetSerialNumber(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}

	// Convert to hexadecimal bytes
	hexBytes := cert.SerialNumber.Bytes()
	if len(hexBytes) == 0 {
		return "00"
	}

	// Format as colon-separated uppercase hex
	parts := make([]string, len(hexBytes))
	for i, b := range hexBytes {
		parts[i] = fmt.Sprintf("%02X", b)
	}

	return strings.Join(parts, ":")
}

// ============================================================================
// Fingerprint Calculation
// ============================================================================

// GetFingerprint calculates the SHA-256 fingerprint of the certificate's DER encoding.
// It returns the fingerprint as an uppercase hex string with colon separators
// (e.g., "A1:B2:C3:D4:...").
//
// This fingerprint is used for certificate verification and trust validation
// across the system. SHA-256 is used for security compliance (not MD5 or SHA-1).
//
// Returns an empty string if the certificate is nil.
func GetFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// Calculate SHA-256 hash of DER-encoded certificate
	hash := sha256.Sum256(cert.Raw)

	// Format as colon-separated uppercase hex
	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02X", b)
	}

	return strings.Join(parts, ":")
}

// ============================================================================
// Validity Period Extraction
// ============================================================================

// GetValidity extracts the NotBefore and NotAfter timestamps from a certificate.
// It returns two time.Time objects representing the validity window.
//
// The function validates that NotAfter is after NotBefore, returning an error
// if the validity period is invalid.
//
// This is used for expiry monitoring and renewal scheduling.
func GetValidity(cert *x509.Certificate) (notBefore time.Time, notAfter time.Time, err error) {
	if cert == nil {
		return time.Time{}, time.Time{}, ErrNilCertificate
	}

	notBefore = cert.NotBefore
	notAfter = cert.NotAfter

	// Validate that NotAfter is after NotBefore
	if notAfter.Before(notBefore) {
		return time.Time{}, time.Time{}, ErrInvalidValidityPeriod
	}

	return notBefore, notAfter, nil
}

// ============================================================================
// Subject DN Extraction
// ============================================================================

// GetSubject parses and formats the subject Distinguished Name (DN) from a certificate.
// It returns a formatted string following RFC 2253 standard (e.g., "CN=SafeOps Root CA, O=SafeOps Network, C=US").
//
// The function handles multiple RDN components: CN (Common Name), O (Organization),
// OU (Organizational Unit), L (Locality), ST (State/Province), and C (Country).
//
// Returns an empty string if the certificate is nil.
func GetSubject(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return formatDistinguishedName(&cert.Subject)
}

// ============================================================================
// Issuer DN Extraction
// ============================================================================

// GetIssuer parses and formats the issuer Distinguished Name (DN) from a certificate.
// Similar to GetSubject but extracts the issuer DN instead.
//
// For self-signed root CA certificates, the issuer equals the subject.
// This is used for chain validation and display.
//
// Returns an empty string if the certificate is nil.
func GetIssuer(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return formatDistinguishedName(&cert.Issuer)
}

// formatDistinguishedName formats a pkix.Name as an RFC 2253 style DN string.
func formatDistinguishedName(name *pkix.Name) string {
	if name == nil {
		return ""
	}

	var parts []string

	// Common Name (CN)
	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}

	// Organizational Unit (OU) - can have multiple
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, fmt.Sprintf("OU=%s", ou))
	}

	// Organization (O) - can have multiple
	for _, o := range name.Organization {
		parts = append(parts, fmt.Sprintf("O=%s", o))
	}

	// Locality (L) - can have multiple
	for _, l := range name.Locality {
		parts = append(parts, fmt.Sprintf("L=%s", l))
	}

	// State/Province (ST) - can have multiple
	for _, st := range name.Province {
		parts = append(parts, fmt.Sprintf("ST=%s", st))
	}

	// Country (C) - can have multiple
	for _, c := range name.Country {
		parts = append(parts, fmt.Sprintf("C=%s", c))
	}

	return strings.Join(parts, ", ")
}

// ============================================================================
// Key Usage Information
// ============================================================================

// GetKeyUsage extracts key usage flags from certificate extensions.
// It returns a slice of human-readable strings describing the key usage purposes
// (e.g., ["Certificate Sign", "CRL Sign"]).
//
// This parses both KeyUsage and BasicConstraints to identify CA certificates.
// Used for validation and compliance checking.
//
// Returns an empty slice if the certificate is nil or has no key usage.
func GetKeyUsage(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	var usages []string

	// Check each KeyUsage bit
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// GetExtendedKeyUsage extracts extended key usage from certificate extensions.
// It returns a slice of human-readable strings describing the extended key usage purposes
// (e.g., ["Server Authentication", "Client Authentication"]).
func GetExtendedKeyUsage(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	var usages []string

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, "Microsoft Kernel Code Signing")
		default:
			usages = append(usages, "Unknown")
		}
	}

	return usages
}

// ============================================================================
// Key Size Extraction
// ============================================================================

// GetKeySize returns the public key size in bits for the certificate.
// For RSA keys, this returns the modulus size (e.g., 2048, 4096).
// For ECDSA keys, this returns the curve bit size (e.g., 256, 384).
//
// Returns 0 if the key type is unknown or the certificate is nil.
func GetKeySize(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

// GetKeyType returns the public key algorithm type as a human-readable string.
// Returns "RSA", "ECDSA", or "Unknown".
func GetKeyType(cert *x509.Certificate) string {
	if cert == nil {
		return "Unknown"
	}

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	default:
		return "Unknown"
	}
}

// ============================================================================
// Complete Metadata Extraction
// ============================================================================

// ExtractMetadata orchestrates all extraction functions to populate a complete
// CertificateMetadata struct from an X.509 certificate.
//
// This is the primary function used by other components to get comprehensive
// certificate information in a single call.
//
// Returns an error if the certificate is nil.
func ExtractMetadata(cert *x509.Certificate) (*CertificateMetadata, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}

	// Get validity period
	notBefore, notAfter, err := GetValidity(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract validity: %w", err)
	}

	metadata := &CertificateMetadata{
		SerialNumber: GetSerialNumber(cert),
		Fingerprint:  GetFingerprint(cert),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Subject:      GetSubject(cert),
		Issuer:       GetIssuer(cert),
		KeyUsage:     GetKeyUsage(cert),
		IsCA:         cert.IsCA,
		KeySize:      GetKeySize(cert),
		KeyType:      GetKeyType(cert),
		Version:      cert.Version,
	}

	return metadata, nil
}

// ============================================================================
// Validity Check Helpers
// ============================================================================

// IsExpired checks if a certificate has expired relative to the current time.
// Returns true if time.Now() is after NotAfter.
//
// This is a simple helper for quick expiry checks.
// Returns false if the certificate is nil.
func IsExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return time.Now().After(cert.NotAfter)
}

// IsNotYetValid checks if a certificate is not yet valid relative to the current time.
// Returns true if time.Now() is before NotBefore.
func IsNotYetValid(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return time.Now().Before(cert.NotBefore)
}

// IsValid checks if a certificate is currently within its validity period.
// Returns true if time.Now() is between NotBefore and NotAfter.
func IsValid(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

// ============================================================================
// Remaining Validity Function
// ============================================================================

// RemainingValidity calculates the remaining time until the certificate expires.
// Returns a time.Duration representing the time until NotAfter.
//
// If the certificate has already expired, the returned duration will be negative.
// This is used for renewal scheduling and alerting.
//
// Returns 0 if the certificate is nil.
func RemainingValidity(cert *x509.Certificate) time.Duration {
	if cert == nil {
		return 0
	}
	return time.Until(cert.NotAfter)
}

// RemainingValidityDays returns the remaining validity in days as an integer.
// Returns negative value if already expired, 0 if certificate is nil.
func RemainingValidityDays(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	return int(RemainingValidity(cert).Hours() / 24)
}

// ============================================================================
// Self-Signed Detection
// ============================================================================

// IsSelfSigned checks if a certificate is self-signed.
// A certificate is considered self-signed if its subject equals its issuer.
//
// For root CA certificates, this should return true.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Compare the string representations of subject and issuer
	return cert.Subject.String() == cert.Issuer.String()
}

// ============================================================================
// Additional Metadata Helpers
// ============================================================================

// GetDNSNames returns all DNS names from the Subject Alternative Name extension.
func GetDNSNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	return cert.DNSNames
}

// GetIPAddresses returns all IP addresses from the Subject Alternative Name extension.
func GetIPAddresses(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	return ips
}

// GetEmailAddresses returns all email addresses from the Subject Alternative Name extension.
func GetEmailAddresses(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	return cert.EmailAddresses
}

// ============================================================================
// Type alias for pkix.Name to use with formatDistinguishedName
// ============================================================================

// DistinguishedName is an alias for pkix.Name fields we care about
type DistinguishedName = pkix.Name
