// Package ca implements certificate validation for content and compliance.
package ca

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Constants
// ============================================================================

const (
	MinRSAKeySize      = 2048
	RecommendedRSASize = 4096
	MinECDSACurve      = 256 // P-256
	MaxValidityDays    = 398 // CA/B Forum maximum
	RenewalThreshold   = 30  // Days before expiry to warn
)

// Signature algorithm security classification
var WeakSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.MD2WithRSA:    true,
	x509.MD5WithRSA:    true,
	x509.SHA1WithRSA:   true,
	x509.DSAWithSHA1:   true,
	x509.ECDSAWithSHA1: true,
}

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrCertificateParseFailed = errors.New("failed to parse certificate")
	ErrCertificateExpired     = errors.New("certificate has expired")
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")
	ErrWeakKey                = errors.New("certificate key is too weak")
	ErrWeakSignature          = errors.New("certificate uses weak signature algorithm")
	ErrDomainMismatch         = errors.New("certificate does not cover required domain")
	ErrMissingSAN             = errors.New("certificate missing Subject Alternative Names")
	ErrInvalidChain           = errors.New("certificate chain is invalid")
	ErrSelfSigned             = errors.New("certificate is self-signed")
	ErrMissingKeyUsage        = errors.New("certificate missing required key usage")
)

// ============================================================================
// Validation Result Types
// ============================================================================

// ValidationSeverity indicates issue severity
type ValidationSeverity string

const (
	SeverityCritical ValidationSeverity = "critical"
	SeverityWarning  ValidationSeverity = "warning"
	SeverityInfo     ValidationSeverity = "info"
)

// ValidationIssue represents a single validation problem
type ValidationIssue struct {
	Code        string             `json:"code"`
	Severity    ValidationSeverity `json:"severity"`
	Message     string             `json:"message"`
	Remediation string             `json:"remediation,omitempty"`
}

// CertValidationResult contains complete validation outcome
type CertValidationResult struct {
	Valid         bool              `json:"valid"`
	Certificate   *x509.Certificate `json:"-"`
	Subject       string            `json:"subject"`
	Issuer        string            `json:"issuer"`
	SerialNumber  string            `json:"serial_number"`
	NotBefore     time.Time         `json:"not_before"`
	NotAfter      time.Time         `json:"not_after"`
	DaysRemaining int               `json:"days_remaining"`
	KeyType       string            `json:"key_type"`
	KeySize       int               `json:"key_size"`
	Domains       []string          `json:"domains"`
	IsSelfSigned  bool              `json:"is_self_signed"`
	Issues        []ValidationIssue `json:"issues"`
}

// ============================================================================
// Certificate Validator Structure
// ============================================================================

// CertValidator validates certificate content and compliance
type CertValidator struct {
	MinKeySize      int
	MaxValidityDays int
	RequireSAN      bool
	AllowSelfSigned bool
	CheckRevocation bool
	TrustedRoots    *x509.CertPool
}

// NewCertValidator creates a new certificate validator
func NewCertValidator() *CertValidator {
	return &CertValidator{
		MinKeySize:      MinRSAKeySize,
		MaxValidityDays: MaxValidityDays,
		RequireSAN:      true,
		AllowSelfSigned: false,
		CheckRevocation: false, // Disabled by default
		TrustedRoots:    nil,   // Use system roots
	}
}

// ============================================================================
// Main Validation Interface
// ============================================================================

// ValidateCertificate performs complete validation of a certificate
func (v *CertValidator) ValidateCertificate(certPEM string) (*CertValidationResult, error) {
	// Parse certificate
	cert, err := v.ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	result := &CertValidationResult{
		Valid:        true,
		Certificate:  cert,
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Domains:      v.extractDomains(cert),
		IsSelfSigned: v.isSelfSigned(cert),
		Issues:       []ValidationIssue{},
	}

	// Calculate days remaining
	result.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)

	// Get key info
	result.KeyType, result.KeySize = v.getKeyInfo(cert)

	// Run all validation checks
	v.validateExpiry(cert, result)
	v.validateKeyStrength(cert, result)
	v.validateSignatureAlgorithm(cert, result)
	v.validateDomains(cert, result)
	v.validateExtensions(cert, result)
	v.validateSelfSigned(cert, result)

	// Set overall validity
	for _, issue := range result.Issues {
		if issue.Severity == SeverityCritical {
			result.Valid = false
			break
		}
	}

	return result, nil
}

// ValidateChain validates a complete certificate chain
func (v *CertValidator) ValidateChain(chainPEM string) (*CertValidationResult, error) {
	// Parse all certificates
	certs, err := v.parseChain(chainPEM)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates in chain")
	}

	// Validate leaf certificate
	result, err := v.ValidateCertificate(chainPEM)
	if err != nil {
		return nil, err
	}

	// Validate chain integrity
	v.validateChainIntegrity(certs, result)

	return result, nil
}

// ValidateForDomains validates certificate covers specific domains
func (v *CertValidator) ValidateForDomains(certPEM string, domains []string) (*CertValidationResult, error) {
	result, err := v.ValidateCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	// Check each required domain
	certDomains := make(map[string]bool)
	for _, d := range result.Domains {
		certDomains[d] = true
	}

	for _, domain := range domains {
		if !v.domainMatches(result.Domains, domain) {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "DOMAIN_MISMATCH",
				Severity:    SeverityCritical,
				Message:     fmt.Sprintf("Certificate does not cover domain: %s", domain),
				Remediation: "Request a new certificate that includes this domain in SAN extension",
			})
			result.Valid = false
		}
	}

	return result, nil
}

// ============================================================================
// Certificate Parsing
// ============================================================================

// ParseCertificate parses PEM-encoded certificate
func (v *CertValidator) ParseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid PEM format", ErrCertificateParseFailed)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE, got %s", ErrCertificateParseFailed, block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificateParseFailed, err)
	}

	return cert, nil
}

// parseChain parses PEM-encoded certificate chain
func (v *CertValidator) parseChain(chainPEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data := []byte(chainPEM)

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// ============================================================================
// Expiry Validation
// ============================================================================

// ValidateExpiry checks certificate validity period
func (v *CertValidator) ValidateExpiry(certPEM string) error {
	cert, err := v.ParseCertificate(certPEM)
	if err != nil {
		return err
	}

	now := time.Now()

	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: valid from %s", ErrCertificateNotYetValid, cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired on %s", ErrCertificateExpired, cert.NotAfter)
	}

	return nil
}

// validateExpiry adds expiry issues to result
func (v *CertValidator) validateExpiry(cert *x509.Certificate, result *CertValidationResult) {
	now := time.Now()

	// Check not yet valid
	if now.Before(cert.NotBefore) {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "NOT_YET_VALID",
			Severity:    SeverityCritical,
			Message:     fmt.Sprintf("Certificate is not yet valid (starts %s)", cert.NotBefore.Format(time.RFC3339)),
			Remediation: "Wait until the NotBefore date or request a new certificate",
		})
	}

	// Check expired
	if now.After(cert.NotAfter) {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "EXPIRED",
			Severity:    SeverityCritical,
			Message:     fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
			Remediation: "Renew the certificate immediately",
		})
	}

	// Check expiring soon
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysRemaining > 0 && daysRemaining <= RenewalThreshold {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "EXPIRING_SOON",
			Severity:    SeverityWarning,
			Message:     fmt.Sprintf("Certificate expires in %d days", daysRemaining),
			Remediation: "Schedule certificate renewal before expiration",
		})
	}

	// Check excessive validity
	validity := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
	if validity > float64(v.MaxValidityDays) {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "EXCESSIVE_VALIDITY",
			Severity:    SeverityWarning,
			Message:     fmt.Sprintf("Certificate validity (%.0f days) exceeds maximum (%d days)", validity, v.MaxValidityDays),
			Remediation: "Request certificates with shorter validity periods",
		})
	}
}

// ============================================================================
// Key Strength Validation
// ============================================================================

// ValidateKeyStrength checks certificate key meets security requirements
func (v *CertValidator) ValidateKeyStrength(certPEM string) error {
	cert, err := v.ParseCertificate(certPEM)
	if err != nil {
		return err
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < v.MinKeySize {
			return fmt.Errorf("%w: RSA key is %d bits, minimum is %d", ErrWeakKey, key.N.BitLen(), v.MinKeySize)
		}
	case *ecdsa.PublicKey:
		curveSize := key.Curve.Params().BitSize
		if curveSize < MinECDSACurve {
			return fmt.Errorf("%w: ECDSA curve is %d bits, minimum is %d", ErrWeakKey, curveSize, MinECDSACurve)
		}
	}

	return nil
}

// validateKeyStrength adds key issues to result
func (v *CertValidator) validateKeyStrength(cert *x509.Certificate, result *CertValidationResult) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < v.MinKeySize {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "WEAK_RSA_KEY",
				Severity:    SeverityCritical,
				Message:     fmt.Sprintf("RSA key is %d bits, minimum is %d", key.N.BitLen(), v.MinKeySize),
				Remediation: "Generate a new certificate with a stronger RSA key (4096-bit recommended)",
			})
		} else if key.N.BitLen() < RecommendedRSASize {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "SUBOPTIMAL_RSA_KEY",
				Severity:    SeverityInfo,
				Message:     fmt.Sprintf("RSA key is %d bits, %d-bit recommended", key.N.BitLen(), RecommendedRSASize),
				Remediation: "Consider upgrading to 4096-bit RSA for enhanced security",
			})
		}

	case *ecdsa.PublicKey:
		curveSize := key.Curve.Params().BitSize
		if curveSize < MinECDSACurve {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "WEAK_ECDSA_KEY",
				Severity:    SeverityCritical,
				Message:     fmt.Sprintf("ECDSA curve is %d bits, minimum is %d", curveSize, MinECDSACurve),
				Remediation: "Generate a new certificate with P-256 or P-384 curve",
			})
		}

	default:
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "UNKNOWN_KEY_TYPE",
			Severity:    SeverityWarning,
			Message:     "Certificate uses unknown public key algorithm",
			Remediation: "Ensure certificate uses RSA or ECDSA public key",
		})
	}
}

// getKeyInfo extracts key type and size
func (v *CertValidator) getKeyInfo(cert *x509.Certificate) (string, int) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().BitSize
	default:
		return "Unknown", 0
	}
}

// ============================================================================
// Signature Algorithm Validation
// ============================================================================

// validateSignatureAlgorithm checks for weak signature algorithms
func (v *CertValidator) validateSignatureAlgorithm(cert *x509.Certificate, result *CertValidationResult) {
	if WeakSignatureAlgorithms[cert.SignatureAlgorithm] {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "WEAK_SIGNATURE",
			Severity:    SeverityCritical,
			Message:     fmt.Sprintf("Certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm),
			Remediation: "Request a new certificate signed with SHA-256 or stronger",
		})
	}
}

// ============================================================================
// Domain Validation
// ============================================================================

// ValidateDomains checks certificate covers specific domains
func (v *CertValidator) ValidateDomains(certPEM string, domains []string) error {
	cert, err := v.ParseCertificate(certPEM)
	if err != nil {
		return err
	}

	certDomains := v.extractDomains(cert)

	for _, domain := range domains {
		if !v.domainMatches(certDomains, domain) {
			return fmt.Errorf("%w: %s", ErrDomainMismatch, domain)
		}
	}

	return nil
}

// validateDomains adds domain issues to result
func (v *CertValidator) validateDomains(cert *x509.Certificate, result *CertValidationResult) {
	if v.RequireSAN && len(cert.DNSNames) == 0 {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "MISSING_SAN",
			Severity:    SeverityWarning,
			Message:     "Certificate lacks Subject Alternative Names extension",
			Remediation: "Request certificate with domains in SAN extension (CN-only is deprecated)",
		})
	}
}

// extractDomains gets all domains from certificate
func (v *CertValidator) extractDomains(cert *x509.Certificate) []string {
	domains := make(map[string]bool)

	if cert.Subject.CommonName != "" {
		domains[cert.Subject.CommonName] = true
	}

	for _, san := range cert.DNSNames {
		domains[san] = true
	}

	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}

// domainMatches checks if certificate covers a domain (including wildcards)
func (v *CertValidator) domainMatches(certDomains []string, domain string) bool {
	domain = strings.ToLower(domain)

	for _, certDomain := range certDomains {
		certDomain = strings.ToLower(certDomain)

		// Exact match
		if certDomain == domain {
			return true
		}

		// Wildcard match
		if strings.HasPrefix(certDomain, "*.") {
			// *.example.com matches www.example.com but not example.com
			suffix := certDomain[1:] // .example.com
			if strings.HasSuffix(domain, suffix) && !strings.Contains(domain[0:len(domain)-len(suffix)], ".") {
				return true
			}
		}
	}

	return false
}

// ============================================================================
// Extension Validation
// ============================================================================

// validateExtensions checks required X.509 extensions
func (v *CertValidator) validateExtensions(cert *x509.Certificate, result *CertValidationResult) {
	// Check Key Usage
	if cert.KeyUsage == 0 {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "MISSING_KEY_USAGE",
			Severity:    SeverityWarning,
			Message:     "Certificate lacks Key Usage extension",
			Remediation: "Request certificate with Key Usage extension",
		})
	} else {
		// Check for TLS server requirements
		hasDigitalSignature := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		hasKeyEncipherment := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0

		if !hasDigitalSignature && !hasKeyEncipherment {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "INVALID_KEY_USAGE",
				Severity:    SeverityWarning,
				Message:     "Certificate Key Usage lacks digitalSignature or keyEncipherment",
				Remediation: "Request certificate with appropriate Key Usage for TLS",
			})
		}
	}

	// Check Extended Key Usage
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}

	if len(cert.ExtKeyUsage) > 0 && !hasServerAuth {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "MISSING_SERVER_AUTH",
			Severity:    SeverityWarning,
			Message:     "Certificate Extended Key Usage lacks serverAuth",
			Remediation: "Request certificate with serverAuth in Extended Key Usage",
		})
	}

	// Check Basic Constraints for leaf certificates
	if cert.IsCA {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "CA_CERT_AS_LEAF",
			Severity:    SeverityWarning,
			Message:     "Certificate has CA:TRUE but is being used as leaf certificate",
			Remediation: "Use a non-CA certificate for TLS endpoints",
		})
	}
}

// ============================================================================
// Chain Validation
// ============================================================================

// validateChainIntegrity verifies certificate chain
func (v *CertValidator) validateChainIntegrity(certs []*x509.Certificate, result *CertValidationResult) {
	if len(certs) < 2 {
		// Single certificate, no chain to validate
		return
	}

	// Verify each certificate is signed by the next
	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]

		err := child.CheckSignatureFrom(parent)
		if err != nil {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "CHAIN_SIGNATURE_INVALID",
				Severity:    SeverityCritical,
				Message:     fmt.Sprintf("Certificate at position %d not signed by parent: %v", i, err),
				Remediation: "Ensure certificate chain is complete and in correct order",
			})
			return
		}

		// Check intermediate has CA:TRUE
		if i < len(certs)-1 && !parent.IsCA {
			result.Issues = append(result.Issues, ValidationIssue{
				Code:        "INTERMEDIATE_NOT_CA",
				Severity:    SeverityCritical,
				Message:     fmt.Sprintf("Intermediate certificate at position %d lacks CA:TRUE", i+1),
				Remediation: "Ensure intermediate certificates have Basic Constraints CA:TRUE",
			})
		}
	}
}

// ============================================================================
// Self-Signed Detection
// ============================================================================

// isSelfSigned checks if certificate is self-signed
func (v *CertValidator) isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String()
}

// validateSelfSigned adds self-signed issues to result
func (v *CertValidator) validateSelfSigned(cert *x509.Certificate, result *CertValidationResult) {
	if v.isSelfSigned(cert) && !v.AllowSelfSigned {
		result.Issues = append(result.Issues, ValidationIssue{
			Code:        "SELF_SIGNED",
			Severity:    SeverityWarning,
			Message:     "Certificate is self-signed",
			Remediation: "Use a certificate signed by a trusted CA for production environments",
		})
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// IsValid returns true if certificate passes all critical checks
func (r *CertValidationResult) IsValid() bool {
	return r.Valid
}

// HasCriticalIssues returns true if any critical issues found
func (r *CertValidationResult) HasCriticalIssues() bool {
	for _, issue := range r.Issues {
		if issue.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any warnings found
func (r *CertValidationResult) HasWarnings() bool {
	for _, issue := range r.Issues {
		if issue.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// GetIssuesByCode returns issues with specific code
func (r *CertValidationResult) GetIssuesByCode(code string) []ValidationIssue {
	var issues []ValidationIssue
	for _, issue := range r.Issues {
		if issue.Code == code {
			issues = append(issues, issue)
		}
	}
	return issues
}
