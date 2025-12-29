// Package types defines core data structures for the Certificate Manager service.
// This file contains certificate-specific helper methods, parsing, and conversion utilities.
package types

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Section 1: Certificate Parsing
// ============================================================================

// ParseCertificatePEM parses a PEM-encoded certificate into a Certificate struct
func ParseCertificatePEM(pemData []byte) (*Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	return ParseCertificateDER(block.Bytes)
}

// ParseCertificateDER parses a DER-encoded certificate into a Certificate struct
func ParseCertificateDER(derData []byte) (*Certificate, error) {
	x509Cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return X509ToCertificate(x509Cert), nil
}

// X509ToCertificate converts an x509.Certificate to our Certificate type
func X509ToCertificate(x509Cert *x509.Certificate) *Certificate {
	// Extract SANs
	sans := ExtractSANs(x509Cert)

	// Determine status based on validity
	status := CertStatusActive
	now := time.Now()
	if now.After(x509Cert.NotAfter) {
		status = CertStatusExpired
	} else if now.Before(x509Cert.NotBefore) {
		status = CertStatusPending
	}

	// Check if wildcard
	isWildcard := strings.HasPrefix(x509Cert.Subject.CommonName, "*.")

	return &Certificate{
		CommonName:      x509Cert.Subject.CommonName,
		SubjectAltNames: sans,
		IsWildcard:      isWildcard,
		CertificatePEM:  "", // Must be set separately if needed
		SerialNumber:    x509Cert.SerialNumber.Text(16),
		Issuer:          x509Cert.Issuer.String(),
		NotBefore:       x509Cert.NotBefore,
		NotAfter:        x509Cert.NotAfter,
		Status:          status,
	}
}

// ExtractSANs extracts Subject Alternative Names from an X.509 certificate
func ExtractSANs(cert *x509.Certificate) []string {
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses))

	// DNS names
	sans = append(sans, cert.DNSNames...)

	// IP addresses
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Email addresses
	sans = append(sans, cert.EmailAddresses...)

	return sans
}

// ExtractIssuerDN extracts the Issuer Distinguished Name as a string
func ExtractIssuerDN(cert *x509.Certificate) string {
	return cert.Issuer.String()
}

// ExtractSubjectDN extracts the Subject Distinguished Name as a string
func ExtractSubjectDN(cert *x509.Certificate) string {
	return cert.Subject.String()
}

// ParseX509FromPEM parses PEM data into an x509.Certificate
func ParseX509FromPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

// ============================================================================
// Section 2: Certificate Fingerprints
// ============================================================================

// CalculateFingerprint calculates SHA-256 fingerprint of DER-encoded certificate
func CalculateFingerprint(derData []byte) string {
	hash := sha256.Sum256(derData)
	return hex.EncodeToString(hash[:])
}

// CalculateFingerprintPEM calculates SHA-256 fingerprint from PEM-encoded certificate
func CalculateFingerprintPEM(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("failed to decode PEM block")
	}
	return CalculateFingerprint(block.Bytes), nil
}

// CalculateFingerprintX509 calculates SHA-256 fingerprint from x509.Certificate
func CalculateFingerprintX509(cert *x509.Certificate) string {
	return CalculateFingerprint(cert.Raw)
}

// FormatFingerprint formats a fingerprint with colons (e.g., "AB:CD:EF:...")
func FormatFingerprint(fingerprint string) string {
	fingerprint = strings.ToUpper(fingerprint)
	var formatted strings.Builder
	for i, r := range fingerprint {
		if i > 0 && i%2 == 0 {
			formatted.WriteRune(':')
		}
		formatted.WriteRune(r)
	}
	return formatted.String()
}

// ============================================================================
// Section 3: Certificate Comparison
// ============================================================================

// CertificatesEqual compares two certificates for equality
func CertificatesEqual(a, b *Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Compare serial numbers (most reliable identifier)
	if a.SerialNumber != "" && b.SerialNumber != "" {
		return a.SerialNumber == b.SerialNumber
	}

	// Fallback to comparing critical fields
	return a.CommonName == b.CommonName &&
		a.Issuer == b.Issuer &&
		a.NotBefore.Equal(b.NotBefore) &&
		a.NotAfter.Equal(b.NotAfter)
}

// IsRenewal detects if newCert is a renewal of oldCert
func IsRenewal(oldCert, newCert *Certificate) bool {
	if oldCert == nil || newCert == nil {
		return false
	}

	// Same domain, different serial, new cert starts near old one's expiry
	sameSubject := oldCert.CommonName == newCert.CommonName
	differentSerial := oldCert.SerialNumber != newCert.SerialNumber
	sameIssuer := oldCert.Issuer == newCert.Issuer

	// New cert should be issued around when old one expires
	renewalWindow := oldCert.NotAfter.Add(-30 * 24 * time.Hour)
	issuedInRenewalWindow := newCert.NotBefore.After(renewalWindow) ||
		newCert.NotBefore.Before(oldCert.NotAfter.Add(24*time.Hour))

	return sameSubject && differentSerial && sameIssuer && issuedInRenewalWindow
}

// GetCertificateDiff returns a list of differences between two certificates
func GetCertificateDiff(a, b *Certificate) []string {
	var diffs []string

	if a == nil || b == nil {
		if a == nil && b != nil {
			return []string{"first certificate is nil"}
		}
		if a != nil && b == nil {
			return []string{"second certificate is nil"}
		}
		return nil // Both nil
	}

	if a.CommonName != b.CommonName {
		diffs = append(diffs, fmt.Sprintf("CommonName: %q vs %q", a.CommonName, b.CommonName))
	}
	if a.SerialNumber != b.SerialNumber {
		diffs = append(diffs, fmt.Sprintf("SerialNumber: %s vs %s", a.SerialNumber, b.SerialNumber))
	}
	if a.Issuer != b.Issuer {
		diffs = append(diffs, fmt.Sprintf("Issuer: %q vs %q", a.Issuer, b.Issuer))
	}
	if !a.NotBefore.Equal(b.NotBefore) {
		diffs = append(diffs, fmt.Sprintf("NotBefore: %s vs %s", a.NotBefore, b.NotBefore))
	}
	if !a.NotAfter.Equal(b.NotAfter) {
		diffs = append(diffs, fmt.Sprintf("NotAfter: %s vs %s", a.NotAfter, b.NotAfter))
	}
	if a.Status != b.Status {
		diffs = append(diffs, fmt.Sprintf("Status: %s vs %s", a.Status, b.Status))
	}

	// Compare SANs
	sansA := strings.Join(a.SubjectAltNames, ",")
	sansB := strings.Join(b.SubjectAltNames, ",")
	if sansA != sansB {
		diffs = append(diffs, fmt.Sprintf("SANs differ: %d vs %d entries", len(a.SubjectAltNames), len(b.SubjectAltNames)))
	}

	return diffs
}

// ============================================================================
// Section 4: Format Conversion
// ============================================================================

// ConvertPEMToDER converts PEM-encoded certificate to DER format
func ConvertPEMToDER(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return block.Bytes, nil
}

// ConvertDERToPEM converts DER-encoded certificate to PEM format
func ConvertDERToPEM(derData []byte, blockType string) string {
	if blockType == "" {
		blockType = "CERTIFICATE"
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: derData,
	}

	var buf bytes.Buffer
	pem.Encode(&buf, block)
	return buf.String()
}

// EncodeCertificateToPEM encodes an x509.Certificate to PEM format
func EncodeCertificateToPEM(cert *x509.Certificate) string {
	return ConvertDERToPEM(cert.Raw, "CERTIFICATE")
}

// ConcatenatePEMChain concatenates multiple PEM certificates into a chain
func ConcatenatePEMChain(certs ...string) string {
	var chain strings.Builder
	for _, cert := range certs {
		cert = strings.TrimSpace(cert)
		if cert != "" {
			chain.WriteString(cert)
			chain.WriteString("\n")
		}
	}
	return chain.String()
}

// ParsePEMChain parses a PEM chain into multiple x509.Certificates
func ParsePEMChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := chainPEM

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
			}
			certs = append(certs, cert)
		}

		remaining = rest
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM chain")
	}

	return certs, nil
}

// ============================================================================
// Section 5: Advanced Validation
// ============================================================================

// ValidateChainWithRoots validates a certificate chain against system root CAs
func ValidateChainWithRoots(certPEM string, intermediatesPEM string) error {
	cert, err := ParseX509FromPEM([]byte(certPEM))
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Parse intermediates
	var intermediates *x509.CertPool
	if intermediatesPEM != "" {
		intermediates = x509.NewCertPool()
		if !intermediates.AppendCertsFromPEM([]byte(intermediatesPEM)) {
			return errors.New("failed to parse intermediate certificates")
		}
	}

	// Use system roots
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to load system root CAs: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

// VerifyHostname checks if a certificate is valid for the given hostname
func VerifyHostname(certPEM string, hostname string) error {
	cert, err := ParseX509FromPEM([]byte(certPEM))
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.VerifyHostname(hostname)
}

// CheckKeyUsage validates that the certificate has the required key usage
func CheckKeyUsage(cert *x509.Certificate, requiredUsage x509.KeyUsage) error {
	if cert.KeyUsage&requiredUsage != requiredUsage {
		return fmt.Errorf("certificate missing required key usage: want %v, have %v",
			requiredUsage, cert.KeyUsage)
	}
	return nil
}

// CheckExtKeyUsage validates that the certificate has the required extended key usage
func CheckExtKeyUsage(cert *x509.Certificate, requiredUsage x509.ExtKeyUsage) error {
	for _, usage := range cert.ExtKeyUsage {
		if usage == requiredUsage {
			return nil
		}
	}
	return fmt.Errorf("certificate missing required extended key usage: %v", requiredUsage)
}

// IsCA checks if a certificate is a Certificate Authority
func IsCA(cert *x509.Certificate) bool {
	return cert.IsCA
}

// IsSelfSigned checks if a certificate is self-signed
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// GetValidityPeriod returns the validity period as a duration
func GetValidityPeriod(cert *x509.Certificate) time.Duration {
	return cert.NotAfter.Sub(cert.NotBefore)
}

// ============================================================================
// Section 6: Certificate Info Extraction
// ============================================================================

// CertificateInfo contains detailed certificate information
type CertificateInfo struct {
	CommonName         string             `json:"common_name"`
	Organization       []string           `json:"organization"`
	OrganizationalUnit []string           `json:"organizational_unit"`
	Country            []string           `json:"country"`
	State              []string           `json:"state"`
	Locality           []string           `json:"locality"`
	DNSNames           []string           `json:"dns_names"`
	IPAddresses        []string           `json:"ip_addresses"`
	EmailAddresses     []string           `json:"email_addresses"`
	SerialNumber       string             `json:"serial_number"`
	Issuer             string             `json:"issuer"`
	Subject            string             `json:"subject"`
	NotBefore          time.Time          `json:"not_before"`
	NotAfter           time.Time          `json:"not_after"`
	Fingerprint        string             `json:"fingerprint"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	PublicKeyAlgorithm string             `json:"public_key_algorithm"`
	KeySize            int                `json:"key_size"`
	Version            int                `json:"version"`
	IsCA               bool               `json:"is_ca"`
	IsSelfSigned       bool               `json:"is_self_signed"`
	KeyUsage           x509.KeyUsage      `json:"key_usage"`
	ExtKeyUsage        []x509.ExtKeyUsage `json:"ext_key_usage"`
}

// ExtractCertificateInfo extracts detailed information from an X.509 certificate
func ExtractCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	// Extract IP addresses as strings
	ipAddrs := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddrs = append(ipAddrs, ip.String())
	}

	// Determine key size
	var keySize int
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		keySize = pub.Size() * 8
	default:
		keySize = 0
	}

	return &CertificateInfo{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		State:              cert.Subject.Province,
		Locality:           cert.Subject.Locality,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipAddrs,
		EmailAddresses:     cert.EmailAddresses,
		SerialNumber:       cert.SerialNumber.Text(16),
		Issuer:             cert.Issuer.String(),
		Subject:            cert.Subject.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		Fingerprint:        CalculateFingerprintX509(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		KeySize:            keySize,
		Version:            cert.Version,
		IsCA:               cert.IsCA,
		IsSelfSigned:       IsSelfSigned(cert),
		KeyUsage:           cert.KeyUsage,
		ExtKeyUsage:        cert.ExtKeyUsage,
	}
}

// ExtractCertificateInfoFromPEM extracts certificate info from PEM-encoded data
func ExtractCertificateInfoFromPEM(pemData []byte) (*CertificateInfo, error) {
	cert, err := ParseX509FromPEM(pemData)
	if err != nil {
		return nil, err
	}
	return ExtractCertificateInfo(cert), nil
}
