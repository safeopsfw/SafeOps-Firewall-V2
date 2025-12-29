package tls_integration

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Validation Errors
// ============================================================================

var (
	ErrInvalidDomain      = errors.New("invalid domain name")
	ErrInvalidSAN         = errors.New("invalid subject alternative name")
	ErrWeakKey            = errors.New("key does not meet minimum strength requirements")
	ErrInvalidCertificate = errors.New("certificate is invalid")
	ErrExpiredCertificate = errors.New("certificate has expired")
	ErrChainValidation    = errors.New("certificate chain validation failed")
	ErrMissingExtension   = errors.New("required extension missing")
	ErrInvalidExtension   = errors.New("extension validation failed")
	ErrBlacklistedDomain  = errors.New("domain is blacklisted")
	ErrValidityTooLong    = errors.New("certificate validity period exceeds maximum")
	ErrCertificateRevoked = errors.New("certificate has been revoked")
)

// ============================================================================
// Validation Configuration
// ============================================================================

// ValidationConfig configures certificate validation rules.
type ValidationConfig struct {
	MaxValidityDays       int  // Maximum certificate validity in days
	MinRSAKeySize         int  // Minimum RSA key size in bits
	MinECDSAKeySize       int  // Minimum ECDSA key size in bits
	RequireSAN            bool // Require Subject Alternative Names
	MaxSANEntries         int  // Maximum SAN entries allowed
	AllowedAlgorithms     []x509.SignatureAlgorithm
	DomainBlacklist       []string      // Forbidden domains
	EnableRevocationCheck bool          // Check revocation status
	AllowFutureDated      time.Duration // Max time NotBefore can be in past
}

// DefaultValidationConfig returns default validation configuration.
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		MaxValidityDays: 90,
		MinRSAKeySize:   2048,
		MinECDSAKeySize: 256,
		RequireSAN:      true,
		MaxSANEntries:   50,
		AllowedAlgorithms: []x509.SignatureAlgorithm{
			x509.SHA256WithRSA,
			x509.SHA384WithRSA,
			x509.SHA512WithRSA,
			x509.ECDSAWithSHA256,
			x509.ECDSAWithSHA384,
			x509.ECDSAWithSHA512,
		},
		DomainBlacklist:       []string{},
		EnableRevocationCheck: false,
		AllowFutureDated:      48 * time.Hour,
	}
}

// ============================================================================
// Certificate Validator
// ============================================================================

// CertificateValidator validates TLS certificates.
type CertificateValidator struct {
	config   *ValidationConfig
	rootCA   *x509.Certificate
	rootPool *x509.CertPool
}

// NewCertificateValidator creates a new certificate validator.
func NewCertificateValidator(config *ValidationConfig, rootCA *x509.Certificate) *CertificateValidator {
	if config == nil {
		config = DefaultValidationConfig()
	}

	v := &CertificateValidator{
		config: config,
		rootCA: rootCA,
	}

	if rootCA != nil {
		v.rootPool = x509.NewCertPool()
		v.rootPool.AddCert(rootCA)
	}

	return v
}

// ============================================================================
// Validation Result
// ============================================================================

// ValidationResult contains the result of certificate validation.
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// AddError adds an error to the validation result.
func (r *ValidationResult) AddError(format string, args ...interface{}) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	r.Valid = false
}

// AddWarning adds a warning to the validation result.
func (r *ValidationResult) AddWarning(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// ============================================================================
// Domain Validation
// ============================================================================

// DNS label pattern (RFC 1035)
var dnsLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// ValidateDomain validates a domain name.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("%w: empty domain", ErrInvalidDomain)
	}

	// Normalize
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check total length
	if len(domain) > 253 {
		return fmt.Errorf("%w: domain exceeds 253 characters", ErrInvalidDomain)
	}

	// Handle wildcard
	domain = strings.TrimPrefix(domain, "*.")

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: domain must have at least two labels", ErrInvalidDomain)
	}

	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%w: empty label", ErrInvalidDomain)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: label exceeds 63 characters", ErrInvalidDomain)
		}
		if !dnsLabelPattern.MatchString(label) {
			return fmt.Errorf("%w: invalid characters in label '%s'", ErrInvalidDomain, label)
		}
	}

	return nil
}

// ValidateWildcard validates a wildcard domain.
func ValidateWildcard(domain string) error {
	if !strings.HasPrefix(domain, "*.") {
		return nil // Not a wildcard
	}

	// Wildcard must be only in leftmost position
	remaining := domain[2:]
	if strings.Contains(remaining, "*") {
		return fmt.Errorf("%w: wildcard only allowed in leftmost position", ErrInvalidDomain)
	}

	return ValidateDomain(remaining)
}

// ============================================================================
// SAN Validation
// ============================================================================

// ValidateSANs validates Subject Alternative Names.
func (v *CertificateValidator) ValidateSANs(dnsNames []string, ipAddresses []net.IP) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check if SAN required
	if v.config.RequireSAN && len(dnsNames) == 0 && len(ipAddresses) == 0 {
		result.AddError("at least one SAN entry is required")
		return result
	}

	// Check max entries
	totalEntries := len(dnsNames) + len(ipAddresses)
	if totalEntries > v.config.MaxSANEntries {
		result.AddError("SAN entries (%d) exceed maximum (%d)", totalEntries, v.config.MaxSANEntries)
	}

	// Validate DNS names
	seen := make(map[string]bool)
	for _, dns := range dnsNames {
		normalized := strings.ToLower(dns)

		// Check duplicates
		if seen[normalized] {
			result.AddWarning("duplicate SAN entry: %s", dns)
			continue
		}
		seen[normalized] = true

		// Validate domain
		if err := ValidateDomain(dns); err != nil {
			result.AddError("invalid DNS SAN '%s': %v", dns, err)
		}

		// Validate wildcard
		if err := ValidateWildcard(dns); err != nil {
			result.AddError("invalid wildcard SAN '%s': %v", dns, err)
		}

		// Check blacklist
		if v.isDomainBlacklisted(dns) {
			result.AddError("domain '%s' is blacklisted", dns)
		}
	}

	// Validate IP addresses
	for _, ip := range ipAddresses {
		if ip == nil {
			result.AddError("nil IP address in SAN")
			continue
		}
		if ip.IsUnspecified() {
			result.AddWarning("unspecified IP address (0.0.0.0) in SAN")
		}
	}

	return result
}

// isDomainBlacklisted checks if domain is in blacklist.
func (v *CertificateValidator) isDomainBlacklisted(domain string) bool {
	normalized := strings.ToLower(domain)
	for _, blocked := range v.config.DomainBlacklist {
		if normalized == strings.ToLower(blocked) {
			return true
		}
		// Check if domain is subdomain of blocked
		if strings.HasSuffix(normalized, "."+strings.ToLower(blocked)) {
			return true
		}
	}
	return false
}

// ============================================================================
// Key Validation
// ============================================================================

// ValidatePublicKey validates a public key meets minimum requirements.
func (v *CertificateValidator) ValidatePublicKey(pub interface{}) *ValidationResult {
	result := &ValidationResult{Valid: true}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if bits < v.config.MinRSAKeySize {
			result.AddError("RSA key size (%d bits) below minimum (%d bits)", bits, v.config.MinRSAKeySize)
		}
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		if bits < v.config.MinECDSAKeySize {
			result.AddError("ECDSA key size (%d bits) below minimum (%d bits)", bits, v.config.MinECDSAKeySize)
		}
	default:
		result.AddError("unsupported key type: %T", pub)
	}

	return result
}

// ============================================================================
// Certificate Validation
// ============================================================================

// ValidateCertificate performs comprehensive certificate validation.
func (v *CertificateValidator) ValidateCertificate(cert *x509.Certificate) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if cert == nil {
		result.AddError("certificate is nil")
		return result
	}

	// Validate validity period
	v.validateValidity(cert, result)

	// Validate public key
	keyResult := v.ValidatePublicKey(cert.PublicKey)
	result.Errors = append(result.Errors, keyResult.Errors...)
	result.Warnings = append(result.Warnings, keyResult.Warnings...)
	if !keyResult.Valid {
		result.Valid = false
	}

	// Validate SANs
	sanResult := v.ValidateSANs(cert.DNSNames, cert.IPAddresses)
	result.Errors = append(result.Errors, sanResult.Errors...)
	result.Warnings = append(result.Warnings, sanResult.Warnings...)
	if !sanResult.Valid {
		result.Valid = false
	}

	// Validate signature algorithm
	v.validateSignatureAlgorithm(cert, result)

	// Validate extensions
	v.validateExtensions(cert, result)

	// Validate chain if root CA is set
	if v.rootPool != nil {
		v.validateChain(cert, result)
	}

	return result
}

// validateValidity validates certificate validity period.
func (v *CertificateValidator) validateValidity(cert *x509.Certificate, result *ValidationResult) {
	now := time.Now()

	// Check NotBefore
	if cert.NotBefore.After(now) {
		result.AddError("certificate not yet valid (NotBefore: %s)", cert.NotBefore.Format(time.RFC3339))
	}

	// Check NotBefore not too far in past
	if now.Sub(cert.NotBefore) > v.config.AllowFutureDated {
		result.AddWarning("certificate NotBefore is more than %v in the past", v.config.AllowFutureDated)
	}

	// Check NotAfter
	if cert.NotAfter.Before(now) {
		result.AddError("certificate has expired (NotAfter: %s)", cert.NotAfter.Format(time.RFC3339))
	}

	// Check validity period
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validityDays > v.config.MaxValidityDays {
		result.AddError("certificate validity (%d days) exceeds maximum (%d days)", validityDays, v.config.MaxValidityDays)
	}

	// Check if expires before CA
	if v.rootCA != nil && cert.NotAfter.After(v.rootCA.NotAfter) {
		result.AddError("certificate expires after root CA")
	}
}

// validateSignatureAlgorithm validates the signature algorithm.
func (v *CertificateValidator) validateSignatureAlgorithm(cert *x509.Certificate, result *ValidationResult) {
	allowed := false
	for _, alg := range v.config.AllowedAlgorithms {
		if cert.SignatureAlgorithm == alg {
			allowed = true
			break
		}
	}

	if !allowed {
		result.AddError("signature algorithm %s not allowed", cert.SignatureAlgorithm.String())
	}
}

// validateExtensions validates certificate extensions.
func (v *CertificateValidator) validateExtensions(cert *x509.Certificate, result *ValidationResult) {
	// Check Basic Constraints for end-entity
	if cert.IsCA {
		result.AddError("end-entity certificate has CA flag set")
	}

	// Check Key Usage
	if cert.KeyUsage == 0 {
		result.AddWarning("no Key Usage extension")
	} else {
		// Server cert should have Digital Signature
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			result.AddWarning("missing Digital Signature key usage")
		}
	}

	// Check Extended Key Usage
	if len(cert.ExtKeyUsage) == 0 {
		result.AddWarning("no Extended Key Usage extension")
	}

	// Check Subject Key Identifier
	if len(cert.SubjectKeyId) == 0 {
		result.AddWarning("missing Subject Key Identifier")
	}

	// Check Authority Key Identifier
	if len(cert.AuthorityKeyId) == 0 {
		result.AddWarning("missing Authority Key Identifier")
	}
}

// validateChain validates the certificate chain.
func (v *CertificateValidator) validateChain(cert *x509.Certificate, result *ValidationResult) {
	opts := x509.VerifyOptions{
		Roots:       v.rootPool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		result.AddError("chain validation failed: %v", err)
	}
}

// ============================================================================
// PEM Validation
// ============================================================================

// ValidatePEM validates PEM-encoded certificate data.
func ValidatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidCertificate)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE, got %s", ErrInvalidCertificate, block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	return cert, nil
}

// ValidateDER validates DER-encoded certificate data.
func ValidateDER(derData []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	return cert, nil
}

// ============================================================================
// Certificate Request Validation
// ============================================================================

// CertificateRequest represents a certificate signing request data.
type CertificateRequest struct {
	Domain       string
	DNSNames     []string
	IPAddresses  []net.IP
	ValidityDays int
	KeyType      string // "RSA" or "ECDSA"
	KeySize      int
}

// ValidateCertificateRequest validates a certificate signing request.
func (v *CertificateValidator) ValidateCertificateRequest(req *CertificateRequest) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if req == nil {
		result.AddError("request is nil")
		return result
	}

	// Validate primary domain
	if err := ValidateDomain(req.Domain); err != nil {
		result.AddError("invalid domain: %v", err)
	}

	// Check blacklist
	if v.isDomainBlacklisted(req.Domain) {
		result.AddError("domain '%s' is blacklisted", req.Domain)
	}

	// Validate SANs
	sanResult := v.ValidateSANs(req.DNSNames, req.IPAddresses)
	result.Errors = append(result.Errors, sanResult.Errors...)
	result.Warnings = append(result.Warnings, sanResult.Warnings...)
	if !sanResult.Valid {
		result.Valid = false
	}

	// Validate validity period
	if req.ValidityDays > v.config.MaxValidityDays {
		result.AddError("requested validity (%d days) exceeds maximum (%d days)", req.ValidityDays, v.config.MaxValidityDays)
	}
	if req.ValidityDays <= 0 {
		result.AddError("validity days must be positive")
	}

	// Validate key parameters
	switch strings.ToUpper(req.KeyType) {
	case "RSA":
		if req.KeySize < v.config.MinRSAKeySize {
			result.AddError("RSA key size (%d) below minimum (%d)", req.KeySize, v.config.MinRSAKeySize)
		}
	case "ECDSA":
		if req.KeySize < v.config.MinECDSAKeySize {
			result.AddError("ECDSA key size (%d) below minimum (%d)", req.KeySize, v.config.MinECDSAKeySize)
		}
	case "":
		// Default to RSA if not specified
	default:
		result.AddError("unsupported key type: %s", req.KeyType)
	}

	return result
}

// ============================================================================
// Quick Validation Functions
// ============================================================================

// IsValidCertificate performs quick validation check.
func (v *CertificateValidator) IsValidCertificate(cert *x509.Certificate) bool {
	result := v.ValidateCertificate(cert)
	return result.Valid
}

// IsExpired checks if a certificate is expired.
func IsExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// IsNotYetValid checks if a certificate is not yet valid.
func IsNotYetValid(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().Before(cert.NotBefore)
}

// GetRemainingValidity returns the remaining validity duration.
func GetRemainingValidity(cert *x509.Certificate) time.Duration {
	if cert == nil {
		return 0
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		return 0
	}
	return remaining
}
