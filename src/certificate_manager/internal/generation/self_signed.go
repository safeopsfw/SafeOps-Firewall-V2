// Package generation provides self-signed certificate generation for development and testing.
package generation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultValidityDuration   = 90 * 24 * time.Hour // 90 days
	TestValidityDuration      = 1 * time.Hour       // 1 hour for tests
	EmergencyValidityDuration = 7 * 24 * time.Hour  // 7 days for emergency
	ClockSkewTolerance        = 5 * time.Minute     // Backdate NotBefore
)

// ============================================================================
// Configuration Options
// ============================================================================

// SelfSignedOptions configures certificate generation
type SelfSignedOptions struct {
	CommonName        string
	SubjectAltNames   []string
	Organization      string
	Country           string
	Validity          time.Duration
	KeyType           types.KeyType
	IsCA              bool
	PathLenConstraint int
	IncludeExtensions bool
}

// DefaultOptions returns sensible defaults for self-signed certificates
func DefaultOptions() *SelfSignedOptions {
	return &SelfSignedOptions{
		Validity:          DefaultValidityDuration,
		KeyType:           types.KeyECDSAP256,
		IsCA:              false,
		PathLenConstraint: -1,
		IncludeExtensions: true,
	}
}

// ============================================================================
// Self-Signed Certificate Generation
// ============================================================================

// SelfSignedResult contains generated certificate and key
type SelfSignedResult struct {
	Certificate      []byte // PEM-encoded certificate
	PrivateKey       []byte // PEM-encoded private key
	CertificateChain []byte // PEM-encoded chain (same as Certificate for self-signed)
	SerialNumber     string
	NotBefore        time.Time
	NotAfter         time.Time
}

// GenerateSelfSigned creates a self-signed certificate
func GenerateSelfSigned(domains []string, opts *SelfSignedOptions) (*SelfSignedResult, error) {
	if len(domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}

	if opts == nil {
		opts = DefaultOptions()
	}

	// Set common name to first domain if not specified
	if opts.CommonName == "" {
		opts.CommonName = domains[0]
	}

	// Generate private key
	keyInfo, err := GeneratePrivateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build certificate template
	template := BuildCertificateTemplate(domains, opts, serialNumber)

	// Sign certificate (self-signed: use same key for signing)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		getPublicKey(keyInfo.Key), keyInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := EncodeCertificatePEM(certDER)

	return &SelfSignedResult{
		Certificate:      certPEM,
		PrivateKey:       []byte(keyInfo.PEM),
		CertificateChain: certPEM, // Self-signed: chain is same as cert
		SerialNumber:     serialNumber.String(),
		NotBefore:        template.NotBefore,
		NotAfter:         template.NotAfter,
	}, nil
}

// ============================================================================
// Certificate Template Builder
// ============================================================================

// BuildCertificateTemplate creates x509 certificate template
func BuildCertificateTemplate(domains []string, opts *SelfSignedOptions, serialNumber *big.Int) *x509.Certificate {
	now := time.Now()
	notBefore := now.Add(-ClockSkewTolerance) // Slightly in past for clock skew
	notAfter := now.Add(opts.Validity)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              domains,
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
	}

	// Add organization if specified
	if opts.Organization != "" {
		template.Subject.Organization = []string{opts.Organization}
	}
	if opts.Country != "" {
		template.Subject.Country = []string{opts.Country}
	}

	// Set key usage based on CA vs leaf cert
	if opts.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if opts.PathLenConstraint >= 0 {
			template.MaxPathLen = opts.PathLenConstraint
			template.MaxPathLenZero = opts.PathLenConstraint == 0
		}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	return template
}

// ============================================================================
// Serial Number Generation
// ============================================================================

// GenerateSerialNumber creates cryptographically random 128-bit serial
func GenerateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// ============================================================================
// Root CA Certificate Generation
// ============================================================================

// CAResult contains generated CA certificate and key
type CAResult struct {
	Certificate []byte // PEM-encoded CA certificate
	PrivateKey  []byte // PEM-encoded private key
}

// GenerateRootCA creates a self-signed CA certificate
func GenerateRootCA(commonName string, validity time.Duration) (*CAResult, error) {
	opts := &SelfSignedOptions{
		CommonName:        commonName,
		Organization:      "SafeOPS Internal CA",
		Validity:          validity,
		KeyType:           types.KeyRSA4096,
		IsCA:              true,
		PathLenConstraint: 1, // Can sign intermediates
	}

	result, err := GenerateSelfSigned([]string{commonName}, opts)
	if err != nil {
		return nil, err
	}

	return &CAResult{
		Certificate: result.Certificate,
		PrivateKey:  result.PrivateKey,
	}, nil
}

// ============================================================================
// Intermediate CA Certificate Generation
// ============================================================================

// GenerateIntermediateCA creates a CA cert signed by root CA
func GenerateIntermediateCA(commonName string, validity time.Duration,
	rootCertPEM, rootKeyPEM []byte) (*CAResult, error) {

	// Parse root certificate
	rootCert, err := parseCertificatePEM(rootCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	// Parse root private key
	rootKeyInfo, err := DecodePrivateKeyFromPEM(string(rootKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse root private key: %w", err)
	}

	// Generate intermediate key
	keyInfo, err := GeneratePrivateKey(types.KeyRSA4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	// Build intermediate CA template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SafeOPS Intermediate CA"},
		},
		NotBefore:             now.Add(-ClockSkewTolerance),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Cannot sign other CAs
		MaxPathLenZero:        true,
	}

	// Sign with root CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert,
		getPublicKey(keyInfo.Key), rootKeyInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate: %w", err)
	}

	return &CAResult{
		Certificate: EncodeCertificatePEM(certDER),
		PrivateKey:  []byte(keyInfo.PEM),
	}, nil
}

// GenerateLeafCertificate creates a certificate signed by CA
func GenerateLeafCertificate(domains []string, validity time.Duration,
	caCertPEM, caKeyPEM []byte) (*SelfSignedResult, error) {

	if len(domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}

	// Parse CA certificate
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKeyInfo, err := DecodePrivateKeyFromPEM(string(caKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate leaf key
	keyInfo, err := GeneratePrivateKey(types.KeyECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	// Build leaf certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domains[0],
		},
		NotBefore:             now.Add(-ClockSkewTolerance),
		NotAfter:              now.Add(validity),
		DNSNames:              domains,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert,
		getPublicKey(keyInfo.Key), caKeyInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	certPEM := EncodeCertificatePEM(certDER)

	// Build chain: leaf + CA
	chain := append(certPEM, caCertPEM...)

	return &SelfSignedResult{
		Certificate:      certPEM,
		PrivateKey:       []byte(keyInfo.PEM),
		CertificateChain: chain,
		SerialNumber:     serialNumber.String(),
		NotBefore:        template.NotBefore,
		NotAfter:         template.NotAfter,
	}, nil
}

// ============================================================================
// Certificate Chain Assembly
// ============================================================================

// AssembleChain combines certificates into a chain (leaf first)
func AssembleChain(certs ...[]byte) []byte {
	var chain []byte
	for _, cert := range certs {
		chain = append(chain, cert...)
	}
	return chain
}

// ============================================================================
// PEM Encoding Functions
// ============================================================================

// EncodeCertificatePEM wraps DER-encoded cert in PEM block
func EncodeCertificatePEM(certDER []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return pem.EncodeToMemory(block)
}

// EncodeCertificateChainPEM concatenates multiple certs into single PEM
func EncodeCertificateChainPEM(certsDER ...[]byte) []byte {
	var chain []byte
	for _, der := range certsDER {
		chain = append(chain, EncodeCertificatePEM(der)...)
	}
	return chain
}

// ============================================================================
// Certificate Validation
// ============================================================================

// ValidateSelfSigned confirms certificate is properly self-signed
func ValidateSelfSigned(certPEM []byte) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	// Self-signed means subject == issuer and signature verifies with own key
	if cert.Subject.CommonName != cert.Issuer.CommonName {
		return errors.New("certificate is not self-signed: subject != issuer")
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("self-signature verification failed: %w", err)
	}

	return nil
}

// CheckDomainCoverage ensures all requested domains appear in certificate
func CheckDomainCoverage(certPEM []byte, domains []string) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	// Build set of covered domains
	covered := make(map[string]bool)
	covered[cert.Subject.CommonName] = true
	for _, san := range cert.DNSNames {
		covered[san] = true
	}

	// Check all requested domains are covered
	for _, domain := range domains {
		if !covered[domain] {
			return fmt.Errorf("domain %s not covered by certificate", domain)
		}
	}

	return nil
}

// ValidateKeyUsage confirms certificate has correct extensions
func ValidateKeyUsage(certPEM []byte, isCA bool) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	if isCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("CA certificate missing KeyUsageCertSign")
		}
	} else {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return errors.New("certificate missing KeyUsageDigitalSignature")
		}

		hasServerAuth := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				hasServerAuth = true
				break
			}
		}
		if !hasServerAuth {
			return errors.New("certificate missing ExtKeyUsageServerAuth")
		}
	}

	return nil
}

// ============================================================================
// Testing Utilities
// ============================================================================

// GenerateTestCertificatePair quickly creates cert+key for unit tests
func GenerateTestCertificatePair(domain string) (*SelfSignedResult, error) {
	opts := &SelfSignedOptions{
		CommonName: domain,
		Validity:   TestValidityDuration,
		KeyType:    types.KeyECDSAP256,
	}
	return GenerateSelfSigned([]string{domain}, opts)
}

// GenerateExpiredCertificate creates cert with past expiry
func GenerateExpiredCertificate(domain string) (*SelfSignedResult, error) {
	opts := &SelfSignedOptions{
		CommonName: domain,
		Validity:   -1 * time.Hour, // Already expired
		KeyType:    types.KeyECDSAP256,
	}
	return GenerateSelfSigned([]string{domain}, opts)
}

// GenerateCertificateSet creates multiple certs for different domains
func GenerateCertificateSet(domains []string) ([]*SelfSignedResult, error) {
	results := make([]*SelfSignedResult, 0, len(domains))
	for _, domain := range domains {
		result, err := GenerateTestCertificatePair(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert for %s: %w", domain, err)
		}
		results = append(results, result)
	}
	return results, nil
}

// ============================================================================
// Emergency Fallback Certificate
// ============================================================================

// GenerateEmergencyFallback creates minimal valid certificate when ACME fails
func GenerateEmergencyFallback(domains []string) (*SelfSignedResult, error) {
	opts := &SelfSignedOptions{
		CommonName:   domains[0],
		Organization: "Emergency Self-Signed",
		Validity:     EmergencyValidityDuration,
		KeyType:      types.KeyECDSAP256,
	}

	result, err := GenerateSelfSigned(domains, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// getPublicKey extracts public key from private key
func getPublicKey(key interface{}) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// parseCertificatePEM parses PEM-encoded certificate
func parseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

// GetDefaultValidity returns 90 days (matches Let's Encrypt)
func GetDefaultValidity() time.Duration {
	return DefaultValidityDuration
}

// GetTestValidity returns 1 hour for short-lived test certificates
func GetTestValidity() time.Duration {
	return TestValidityDuration
}

// GetEmergencyValidity returns 7 days for emergency fallback certificates
func GetEmergencyValidity() time.Duration {
	return EmergencyValidityDuration
}
