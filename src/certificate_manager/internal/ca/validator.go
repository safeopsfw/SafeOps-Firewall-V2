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

// ============================================================================
// CA-Specific Validation Functions
// ============================================================================

// CAValidationResult provides comprehensive CA validation report.
type CAValidationResult struct {
	Valid           bool      `json:"valid"`
	Errors          []error   `json:"errors"`
	Warnings        []string  `json:"warnings"`
	ChecksPerformed []string  `json:"checks_performed"`
	Timestamp       time.Time `json:"timestamp"`
}

// ValidateCA performs comprehensive validation of a CA certificate.
// This is the master validation function that orchestrates all CA-specific checks.
func ValidateCA(cert *x509.Certificate) (*CAValidationResult, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	result := &CAValidationResult{
		Valid:           true,
		Errors:          []error{},
		Warnings:        []string{},
		ChecksPerformed: []string{},
		Timestamp:       time.Now(),
	}

	// Check 1: Is CA certificate
	result.ChecksPerformed = append(result.ChecksPerformed, "IsCA")
	if !cert.IsCA {
		result.Errors = append(result.Errors, errors.New("certificate is not a CA certificate (IsCA=false)"))
		result.Valid = false
	}

	// Check 2: Expiry
	result.ChecksPerformed = append(result.ChecksPerformed, "Expiry")
	if err := CheckExpiry(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	// Check 3: Add expiry warnings
	warnings := GetExpiryWarnings(cert)
	result.Warnings = append(result.Warnings, warnings...)

	// Check 4: Self-signature verification
	result.ChecksPerformed = append(result.ChecksPerformed, "SelfSignature")
	if err := VerifySignature(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	// Check 5: Key usage
	result.ChecksPerformed = append(result.ChecksPerformed, "KeyUsage")
	if err := CheckKeyUsage(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	// Check 6: Key size
	result.ChecksPerformed = append(result.ChecksPerformed, "KeySize")
	if err := CheckKeySize(cert); err != nil {
		if strings.Contains(err.Error(), "warning") {
			result.Warnings = append(result.Warnings, err.Error())
		} else {
			result.Errors = append(result.Errors, err)
			result.Valid = false
		}
	}

	// Check 7: Validity period
	result.ChecksPerformed = append(result.ChecksPerformed, "ValidityPeriod")
	if err := CheckValidityPeriod(cert); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}

	// Check 8: Subject DN
	result.ChecksPerformed = append(result.ChecksPerformed, "SubjectDN")
	if err := ValidateSubjectDN(cert); err != nil {
		if strings.Contains(err.Error(), "warning") {
			result.Warnings = append(result.Warnings, err.Error())
		} else {
			result.Errors = append(result.Errors, err)
			result.Valid = false
		}
	}

	// Check 9: Self-signed (for root CA)
	result.ChecksPerformed = append(result.ChecksPerformed, "SelfSigned")
	if err := ValidateSelfSignedCA(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	// Check 10: Serial number
	result.ChecksPerformed = append(result.ChecksPerformed, "SerialNumber")
	if err := ValidateSerialNumber(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	// Check 11: Path length constraint
	result.ChecksPerformed = append(result.ChecksPerformed, "PathLength")
	if err := CheckPathLength(cert); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}

	// Check 12: Signature algorithm
	result.ChecksPerformed = append(result.ChecksPerformed, "SignatureAlgorithm")
	if err := ValidateCASignatureAlgorithm(cert); err != nil {
		result.Errors = append(result.Errors, err)
		result.Valid = false
	}

	return result, nil
}

// CheckExpiry verifies certificate is currently valid (within NotBefore and NotAfter).
func CheckExpiry(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	now := time.Now()

	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid: starts at %s", cert.NotBefore.Format(time.RFC3339))
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired: expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// GetExpiryWarnings returns warning messages for certificates nearing expiry.
// Warning thresholds: < 30 days (critical), < 90 days (warning), < 365 days (notice).
func GetExpiryWarnings(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	var warnings []string
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	if daysRemaining < 0 {
		warnings = append(warnings, fmt.Sprintf("CRITICAL: Certificate has expired %d days ago", -daysRemaining))
	} else if daysRemaining < 30 {
		warnings = append(warnings, fmt.Sprintf("CRITICAL: Certificate expires in %d days - immediate renewal required", daysRemaining))
	} else if daysRemaining < 90 {
		warnings = append(warnings, fmt.Sprintf("WARNING: Certificate expires in %d days - schedule renewal soon", daysRemaining))
	} else if daysRemaining < 365 {
		warnings = append(warnings, fmt.Sprintf("NOTICE: Certificate expires in %d days - consider scheduling renewal", daysRemaining))
	}

	return warnings
}

// VerifySignature verifies the certificate's self-signature is valid.
// For root CAs, the certificate signs itself.
func VerifySignature(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check signature algorithm is not weak
	if WeakSignatureAlgorithms[cert.SignatureAlgorithm] {
		return fmt.Errorf("certificate uses weak/deprecated signature algorithm: %s", cert.SignatureAlgorithm)
	}

	// Verify self-signature
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return fmt.Errorf("self-signature verification failed: %w", err)
	}

	return nil
}

// CheckKeyUsage verifies certificate has correct key usage extensions for CA operation.
func CheckKeyUsage(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check IsCA flag
	if !cert.IsCA {
		return errors.New("certificate does not have CA flag set (BasicConstraints CA:TRUE)")
	}

	// Check BasicConstraintsValid
	if !cert.BasicConstraintsValid {
		return errors.New("certificate BasicConstraints extension is not valid")
	}

	// Check KeyUsage includes CertSign
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate lacks KeyUsage CertSign (required for CA)")
	}

	// Check KeyUsage includes CRLSign
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("certificate lacks KeyUsage CRLSign (required for CA)")
	}

	return nil
}

// CheckKeySize validates public key size meets minimum security requirements.
// Minimum: 2048 bits (hard requirement). Recommended: 4096 bits.
func CheckKeySize(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bitLen := key.N.BitLen()
		if bitLen < MinRSAKeySize {
			return fmt.Errorf("RSA key size %d bits is below minimum %d bits (NIST requirement)", bitLen, MinRSAKeySize)
		}
		if bitLen < RecommendedRSASize {
			return fmt.Errorf("warning: RSA key size %d bits is below recommended %d bits for root CAs", bitLen, RecommendedRSASize)
		}
	case *ecdsa.PublicKey:
		curveSize := key.Curve.Params().BitSize
		if curveSize < MinECDSACurve {
			return fmt.Errorf("ECDSA curve size %d bits is below minimum %d bits", curveSize, MinECDSACurve)
		}
	default:
		return errors.New("unsupported public key type")
	}

	return nil
}

// CheckValidityPeriod validates certificate validity period is reasonable.
// Maximum CA lifetime: 30 years.
func CheckValidityPeriod(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check NotBefore is not in the future (with 5 minute tolerance for clock skew)
	if time.Now().Add(5 * time.Minute).Before(cert.NotBefore) {
		return fmt.Errorf("certificate NotBefore is in the future: %s", cert.NotBefore.Format(time.RFC3339))
	}

	// Check NotAfter is after NotBefore
	if cert.NotAfter.Before(cert.NotBefore) {
		return errors.New("certificate NotAfter is before NotBefore")
	}

	// Check validity period doesn't exceed 30 years
	validityYears := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if validityYears > 30 {
		return fmt.Errorf("certificate validity period %.1f years exceeds maximum 30 years", validityYears)
	}

	return nil
}

// ValidateSubjectDN verifies subject Distinguished Name is properly populated.
func ValidateSubjectDN(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// CommonName is required
	if cert.Subject.CommonName == "" {
		return errors.New("certificate Subject CommonName (CN) is empty")
	}

	// Organization is recommended
	if len(cert.Subject.Organization) == 0 {
		return errors.New("warning: certificate Subject Organization (O) is empty")
	}

	// Validate country code if present
	for _, country := range cert.Subject.Country {
		if len(country) != 2 {
			return fmt.Errorf("invalid country code '%s': must be 2 letters", country)
		}
	}

	return nil
}

// ValidateSelfSignedCA verifies certificate is self-signed (Issuer == Subject).
func ValidateSelfSignedCA(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Compare Subject and Issuer strings
	if cert.Issuer.String() != cert.Subject.String() {
		return fmt.Errorf("certificate is not self-signed: Issuer '%s' != Subject '%s'",
			cert.Issuer.String(), cert.Subject.String())
	}

	return nil
}

// ValidateSerialNumber validates certificate serial number is properly formatted.
func ValidateSerialNumber(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	if cert.SerialNumber == nil {
		return errors.New("certificate serial number is nil")
	}

	// Serial number must be positive
	if cert.SerialNumber.Sign() <= 0 {
		return errors.New("certificate serial number must be positive")
	}

	// RFC 5280: Serial number should be no more than 20 octets
	if len(cert.SerialNumber.Bytes()) > 20 {
		return fmt.Errorf("certificate serial number exceeds 20 octets (RFC 5280 limit): %d bytes",
			len(cert.SerialNumber.Bytes()))
	}

	// Check for minimum entropy (at least 64 bits recommended)
	if cert.SerialNumber.BitLen() < 64 {
		return fmt.Errorf("warning: certificate serial number has low entropy: %d bits (recommend >= 64 bits)",
			cert.SerialNumber.BitLen())
	}

	return nil
}

// CheckPathLength validates BasicConstraints pathlen for root CA.
func CheckPathLength(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Root CAs should typically have MaxPathLen = 0
	// This means no intermediate CAs can be issued
	if cert.MaxPathLen > 0 && !cert.MaxPathLenZero {
		return fmt.Errorf("warning: root CA has MaxPathLen=%d, consider restricting to 0", cert.MaxPathLen)
	}

	return nil
}

// ValidateCASignatureAlgorithm verifies signature algorithm meets security requirements.
func ValidateCASignatureAlgorithm(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check against known weak algorithms
	if WeakSignatureAlgorithms[cert.SignatureAlgorithm] {
		return fmt.Errorf("certificate uses deprecated/insecure signature algorithm: %s", cert.SignatureAlgorithm)
	}

	// Verify it's a known secure algorithm
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return nil
	default:
		return fmt.Errorf("unknown or potentially insecure signature algorithm: %s", cert.SignatureAlgorithm)
	}
}

// PerformHealthCheck performs comprehensive health check for stored CA files.
func PerformHealthCheck(config *CAStorageConfig) (*CAValidationResult, error) {
	if config == nil {
		config = DefaultStorageConfig()
	}

	result := &CAValidationResult{
		Valid:           true,
		Errors:          []error{},
		Warnings:        []string{},
		ChecksPerformed: []string{},
		Timestamp:       time.Now(),
	}

	// Check 1: Load certificate
	result.ChecksPerformed = append(result.ChecksPerformed, "LoadCertificate")
	cert, err := LoadCACertificate(config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to load certificate: %w", err))
		result.Valid = false
		return result, nil // Can't continue without certificate
	}

	// Check 2: Validate certificate
	result.ChecksPerformed = append(result.ChecksPerformed, "ValidateCertificate")
	caResult, err := ValidateCA(cert)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("certificate validation error: %w", err))
		result.Valid = false
	} else {
		result.Errors = append(result.Errors, caResult.Errors...)
		result.Warnings = append(result.Warnings, caResult.Warnings...)
		result.ChecksPerformed = append(result.ChecksPerformed, caResult.ChecksPerformed...)
		if !caResult.Valid {
			result.Valid = false
		}
	}

	// Check 3: Validate file permissions
	result.ChecksPerformed = append(result.ChecksPerformed, "FilePermissions")
	permResults := ValidateCAFilePermissions(config)
	for name, err := range permResults {
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Permission check '%s': %v", name, err))
		}
	}

	// Check 4: Verify private key exists and can be loaded
	result.ChecksPerformed = append(result.ChecksPerformed, "LoadPrivateKey")
	privateKey, err := LoadCAPrivateKey(config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to load private key: %w", err))
		result.Valid = false
	} else {
		// Check 5: Verify public key in cert matches private key
		result.ChecksPerformed = append(result.ChecksPerformed, "KeyPairMatch")
		certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok {
			if certPubKey.N.Cmp(privateKey.PublicKey.N) != 0 {
				result.Errors = append(result.Errors, errors.New("certificate public key does not match private key"))
				result.Valid = false
			}
		}
	}

	return result, nil
}

// QuickValidate performs fast validation for critical checks only.
// Used during high-frequency operations like certificate signing.
func QuickValidate(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Quick check 1: Not expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// Quick check 2: Is CA certificate
	if !cert.IsCA {
		return errors.New("not a CA certificate")
	}

	// Quick check 3: Has CertSign key usage
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return ErrMissingKeyUsage
	}

	return nil
}

// GetValidationSummary returns a human-readable summary of validation result.
func GetValidationSummary(result *CAValidationResult) string {
	if result == nil {
		return "No validation result"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CA Validation Summary (performed at %s)\n", result.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Overall Status: %v\n", result.Valid))
	sb.WriteString(fmt.Sprintf("Checks Performed: %d\n", len(result.ChecksPerformed)))
	sb.WriteString(fmt.Sprintf("Errors: %d\n", len(result.Errors)))
	sb.WriteString(fmt.Sprintf("Warnings: %d\n", len(result.Warnings)))

	if len(result.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for i, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for i, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, warning))
		}
	}

	return sb.String()
}
