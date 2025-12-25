// Package generation handles CSR and private key generation for certificates.
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
	"net"
	"regexp"
	"strings"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	PEMTypeCSR      = "CERTIFICATE REQUEST"
	MaxDomainLength = 253
	MaxLabelLength  = 63
	MinDomainLength = 1
)

// Domain validation regex
var domainLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrInvalidDomain  = errors.New("invalid domain name")
	ErrInvalidKey     = errors.New("invalid private key for CSR")
	ErrMissingSubject = errors.New("missing required subject information")
	ErrEncodingFailed = errors.New("PEM encoding failed")
	ErrCSRParseFailed = errors.New("failed to parse CSR")
)

// ============================================================================
// CSR Generation Core Function
// ============================================================================

// GenerateCSR creates a Certificate Signing Request
func GenerateCSR(keyInfo *types.PrivateKeyInfo, request *types.CSRRequest) ([]byte, error) {
	if keyInfo == nil || keyInfo.Key == nil {
		return nil, ErrInvalidKey
	}

	if request == nil || request.CommonName == "" {
		return nil, ErrMissingSubject
	}

	// Validate private key compatibility
	if err := ValidateKeyCompatibility(keyInfo.Key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	// Validate and prepare domain names
	dnsNames, err := prepareDNSNames(request.CommonName, request.SubjectAltNames)
	if err != nil {
		return nil, err
	}

	// Build subject
	subject := buildSubject(request)

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsNames,
		SignatureAlgorithm: getSignatureAlgorithm(keyInfo.Key),
	}

	// Generate CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, keyInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode to PEM
	pemBytes := EncodeCSRToPEM(csrDER)

	return pemBytes, nil
}

// GenerateCSRFromKey creates CSR using raw private key and domain config
func GenerateCSRFromKey(key interface{}, config *types.DomainConfig) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}

	// Create CSR request from domain config
	request := &types.CSRRequest{
		CommonName:      config.CommonName,
		SubjectAltNames: config.SubjectAltNames,
	}

	// Get key info
	keyInfo, err := GetKeyInfo(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	return GenerateCSR(keyInfo, request)
}

// ============================================================================
// Subject Information Builder
// ============================================================================

// buildSubject constructs the pkix.Name for CSR
func buildSubject(request *types.CSRRequest) pkix.Name {
	subject := pkix.Name{
		CommonName: request.CommonName,
	}

	if request.Country != "" {
		subject.Country = []string{request.Country}
	}
	if request.Organization != "" {
		subject.Organization = []string{request.Organization}
	}
	if request.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{request.OrganizationalUnit}
	}
	if request.Locality != "" {
		subject.Locality = []string{request.Locality}
	}
	if request.Province != "" {
		subject.Province = []string{request.Province}
	}

	return subject
}

// ValidateSubjectInfo ensures required CSR fields are populated
func ValidateSubjectInfo(request *types.CSRRequest) error {
	if request == nil {
		return ErrMissingSubject
	}

	if request.CommonName == "" {
		return fmt.Errorf("%w: CommonName is required", ErrMissingSubject)
	}

	if err := ValidateDomainName(request.CommonName); err != nil {
		return err
	}

	return nil
}

// ============================================================================
// DNS Names Handler
// ============================================================================

// prepareDNSNames processes and validates SAN list
func prepareDNSNames(commonName string, sans []string) ([]string, error) {
	// Use map to track unique domains (case-insensitive)
	seen := make(map[string]bool)
	var dnsNames []string

	// Add common name first
	cnLower := strings.ToLower(commonName)
	if err := ValidateDomainName(commonName); err != nil {
		return nil, fmt.Errorf("invalid CommonName %q: %w", commonName, err)
	}
	seen[cnLower] = true
	dnsNames = append(dnsNames, commonName)

	// Add SANs, removing duplicates
	for _, san := range sans {
		sanLower := strings.ToLower(san)

		// Skip duplicates
		if seen[sanLower] {
			continue
		}

		// Validate domain
		if err := ValidateDomainName(san); err != nil {
			return nil, fmt.Errorf("invalid SAN %q: %w", san, err)
		}

		seen[sanLower] = true
		dnsNames = append(dnsNames, san)
	}

	return dnsNames, nil
}

// ============================================================================
// PEM Encoding Function
// ============================================================================

// EncodeCSRToPEM converts DER-encoded CSR to PEM format
func EncodeCSRToPEM(csrDER []byte) []byte {
	block := &pem.Block{
		Type:  PEMTypeCSR,
		Bytes: csrDER,
	}
	return pem.EncodeToMemory(block)
}

// DecodeCSRFromPEM parses PEM-encoded CSR
func DecodeCSRFromPEM(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrCSRParseFailed)
	}

	if block.Type != PEMTypeCSR {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrCSRParseFailed, PEMTypeCSR, block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRParseFailed, err)
	}

	return csr, nil
}

// ============================================================================
// Validation Functions
// ============================================================================

// ValidateDomainName checks domain syntax following RFC rules
func ValidateDomainName(domain string) error {
	if len(domain) < MinDomainLength {
		return fmt.Errorf("%w: domain too short", ErrInvalidDomain)
	}

	if len(domain) > MaxDomainLength {
		return fmt.Errorf("%w: domain exceeds %d characters", ErrInvalidDomain, MaxDomainLength)
	}

	// Handle wildcard domains
	actualDomain := domain
	if strings.HasPrefix(domain, "*.") {
		actualDomain = domain[2:]
		if len(actualDomain) == 0 {
			return fmt.Errorf("%w: wildcard domain requires base domain", ErrInvalidDomain)
		}
	}

	// Check for IP address (not allowed in SAN for domain validation)
	if net.ParseIP(actualDomain) != nil {
		return fmt.Errorf("%w: IP addresses not allowed, use DNS name", ErrInvalidDomain)
	}

	// Validate each label
	labels := strings.Split(actualDomain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: domain must have at least two labels", ErrInvalidDomain)
	}

	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%w: empty label in domain", ErrInvalidDomain)
		}
		if len(label) > MaxLabelLength {
			return fmt.Errorf("%w: label exceeds %d characters", ErrInvalidDomain, MaxLabelLength)
		}
		if !domainLabelRegex.MatchString(label) {
			return fmt.Errorf("%w: invalid characters in label %q", ErrInvalidDomain, label)
		}
	}

	return nil
}

// ValidateKeyCompatibility confirms private key is acceptable
func ValidateKeyCompatibility(key interface{}) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if bits < MinRSAKeySize {
			return fmt.Errorf("RSA key must be at least %d bits, got %d", MinRSAKeySize, bits)
		}
		return nil

	case *ecdsa.PrivateKey:
		curveName := k.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" {
			return fmt.Errorf("ECDSA curve must be P-256 or P-384, got %s", curveName)
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// getSignatureAlgorithm determines the appropriate signature algorithm
func getSignatureAlgorithm(key interface{}) x509.SignatureAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// ============================================================================
// CSR Information Extractor
// ============================================================================

// CSRInfo contains extracted CSR information
type CSRInfo struct {
	CommonName         string   `json:"common_name"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
	Country            string   `json:"country,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	Province           string   `json:"province,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
}

// ParseCSR extracts information from PEM-encoded CSR
func ParseCSR(pemData []byte) (*CSRInfo, error) {
	csr, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		return nil, err
	}

	return ExtractCSRInfo(csr)
}

// ExtractCSRInfo extracts structured data from parsed CSR
func ExtractCSRInfo(csr *x509.CertificateRequest) (*CSRInfo, error) {
	if csr == nil {
		return nil, errors.New("CSR is nil")
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	info := &CSRInfo{
		CommonName:         csr.Subject.CommonName,
		SubjectAltNames:    csr.DNSNames,
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm.String(),
	}

	// Extract organization info
	if len(csr.Subject.Organization) > 0 {
		info.Organization = csr.Subject.Organization[0]
	}
	if len(csr.Subject.OrganizationalUnit) > 0 {
		info.OrganizationalUnit = csr.Subject.OrganizationalUnit[0]
	}
	if len(csr.Subject.Country) > 0 {
		info.Country = csr.Subject.Country[0]
	}
	if len(csr.Subject.Locality) > 0 {
		info.Locality = csr.Subject.Locality[0]
	}
	if len(csr.Subject.Province) > 0 {
		info.Province = csr.Subject.Province[0]
	}

	return info, nil
}

// GetCSRDomains returns all domains from a CSR (CN + SANs)
func GetCSRDomains(pemData []byte) ([]string, error) {
	csr, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(csr.DNSNames)+1)

	// Add CN if present and not in SANs
	if csr.Subject.CommonName != "" {
		domains = append(domains, csr.Subject.CommonName)
	}

	// Add SANs, avoiding duplicates with CN
	seen := make(map[string]bool)
	seen[strings.ToLower(csr.Subject.CommonName)] = true

	for _, san := range csr.DNSNames {
		if !seen[strings.ToLower(san)] {
			domains = append(domains, san)
			seen[strings.ToLower(san)] = true
		}
	}

	return domains, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// VerifyCSR validates a CSR's signature and structure
func VerifyCSR(pemData []byte) error {
	csr, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		return err
	}

	// Check signature
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature invalid: %w", err)
	}

	// Verify has at least one domain
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 {
		return errors.New("CSR must specify at least one domain name")
	}

	return nil
}

// IsWildcardCSR checks if CSR is for a wildcard certificate
func IsWildcardCSR(pemData []byte) (bool, error) {
	csr, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		return false, err
	}

	// Check CN
	if strings.HasPrefix(csr.Subject.CommonName, "*.") {
		return true, nil
	}

	// Check SANs
	for _, san := range csr.DNSNames {
		if strings.HasPrefix(san, "*.") {
			return true, nil
		}
	}

	return false, nil
}

// GetCSRPublicKey extracts the public key from a CSR
func GetCSRPublicKey(pemData []byte) (crypto.PublicKey, error) {
	csr, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		return nil, err
	}

	return csr.PublicKey, nil
}
