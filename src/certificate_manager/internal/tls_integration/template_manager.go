package tls_integration

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"
)

// ============================================================================
// Certificate Types
// ============================================================================

// CertificateType represents the purpose of a certificate.
type CertificateType int

const (
	CertTypeServer CertificateType = iota
	CertTypeClient
	CertTypeEmail
	CertTypeCodeSigning
)

// String returns string representation of certificate type.
func (t CertificateType) String() string {
	switch t {
	case CertTypeServer:
		return "server"
	case CertTypeClient:
		return "client"
	case CertTypeEmail:
		return "email"
	case CertTypeCodeSigning:
		return "code_signing"
	default:
		return "unknown"
	}
}

// ============================================================================
// Template Configuration
// ============================================================================

// TemplateConfig configures certificate templates.
type TemplateConfig struct {
	ServerValidityDays      int           // Server certificate validity
	ClientValidityDays      int           // Client certificate validity
	EmailValidityDays       int           // Email certificate validity
	CodeSigningValidityDays int           // Code signing certificate validity
	CRLDistributionPoint    string        // URL for CRL endpoint
	OCSPResponderURL        string        // URL for OCSP responder
	OrganizationName        string        // Default organization name
	ClockSkewAllowance      time.Duration // Backdate for clock skew
}

// DefaultTemplateConfig returns default template configuration.
func DefaultTemplateConfig() *TemplateConfig {
	return &TemplateConfig{
		ServerValidityDays:      90,
		ClientValidityDays:      365,
		EmailValidityDays:       365,
		CodeSigningValidityDays: 1095, // 3 years
		OrganizationName:        "SafeOps Network",
		ClockSkewAllowance:      5 * time.Minute,
	}
}

// ============================================================================
// Template Manager
// ============================================================================

// TemplateManager provides certificate templates for different purposes.
type TemplateManager struct {
	config *TemplateConfig
}

// NewTemplateManager creates a new template manager.
func NewTemplateManager(config *TemplateConfig) *TemplateManager {
	if config == nil {
		config = DefaultTemplateConfig()
	}
	return &TemplateManager{config: config}
}

// ============================================================================
// Template Retrieval
// ============================================================================

// GetTemplate returns a certificate template for the specified type.
func (m *TemplateManager) GetTemplate(certType CertificateType) *x509.Certificate {
	switch certType {
	case CertTypeServer:
		return m.GetServerTemplate()
	case CertTypeClient:
		return m.GetClientTemplate()
	case CertTypeEmail:
		return m.GetEmailTemplate()
	case CertTypeCodeSigning:
		return m.GetCodeSigningTemplate()
	default:
		return m.GetServerTemplate()
	}
}

// GetServerTemplate returns template for TLS server certificates.
func (m *TemplateManager) GetServerTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: nil, // Set at signing time

		Subject: pkix.Name{
			Organization: []string{m.config.OrganizationName},
		},

		NotBefore: now.Add(-m.config.ClockSkewAllowance),
		NotAfter:  now.Add(time.Duration(m.config.ServerValidityDays) * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		DNSNames:    []string{},
		IPAddresses: []net.IP{},

		CRLDistributionPoints: m.getCRLDistributionPoints(),
		OCSPServer:            m.getOCSPServers(),
	}
}

// GetClientTemplate returns template for TLS client certificates.
func (m *TemplateManager) GetClientTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: nil,

		Subject: pkix.Name{
			Organization: []string{m.config.OrganizationName},
		},

		NotBefore: now.Add(-m.config.ClockSkewAllowance),
		NotAfter:  now.Add(time.Duration(m.config.ClientValidityDays) * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		EmailAddresses: []string{},

		CRLDistributionPoints: m.getCRLDistributionPoints(),
		OCSPServer:            m.getOCSPServers(),
	}
}

// GetEmailTemplate returns template for S/MIME email certificates.
func (m *TemplateManager) GetEmailTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: nil,

		Subject: pkix.Name{
			Organization: []string{m.config.OrganizationName},
		},

		NotBefore: now.Add(-m.config.ClockSkewAllowance),
		NotAfter:  now.Add(time.Duration(m.config.EmailValidityDays) * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		EmailAddresses: []string{},

		CRLDistributionPoints: m.getCRLDistributionPoints(),
		OCSPServer:            m.getOCSPServers(),
	}
}

// GetCodeSigningTemplate returns template for code signing certificates.
func (m *TemplateManager) GetCodeSigningTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: nil,

		Subject: pkix.Name{
			Organization: []string{m.config.OrganizationName},
		},

		NotBefore: now.Add(-m.config.ClockSkewAllowance),
		NotAfter:  now.Add(time.Duration(m.config.CodeSigningValidityDays) * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		CRLDistributionPoints: m.getCRLDistributionPoints(),
		OCSPServer:            m.getOCSPServers(),
	}
}

// getCRLDistributionPoints returns CRL URLs if configured.
func (m *TemplateManager) getCRLDistributionPoints() []string {
	if m.config.CRLDistributionPoint != "" {
		return []string{m.config.CRLDistributionPoint}
	}
	return nil
}

// getOCSPServers returns OCSP URLs if configured.
func (m *TemplateManager) getOCSPServers() []string {
	if m.config.OCSPResponderURL != "" {
		return []string{m.config.OCSPResponderURL}
	}
	return nil
}

// ============================================================================
// Certificate Request
// ============================================================================

// CertRequest represents a certificate signing request.
type CertRequest struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	DNSNames           []string
	IPAddresses        []net.IP
	EmailAddresses     []string
	ValidityDays       int
	CertType           CertificateType
}

// ============================================================================
// Template Customization
// ============================================================================

// CustomizeTemplate creates a customized certificate from a template.
func (m *TemplateManager) CustomizeTemplate(req *CertRequest) (*x509.Certificate, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	// Get base template
	template := m.GetTemplate(req.CertType)

	// Clone the template
	cert := *template

	// Generate unique serial number
	serial, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	cert.SerialNumber = serial

	// Set Subject
	cert.Subject = pkix.Name{
		CommonName: req.CommonName,
	}
	if req.Organization != "" {
		cert.Subject.Organization = []string{req.Organization}
	} else if m.config.OrganizationName != "" {
		cert.Subject.Organization = []string{m.config.OrganizationName}
	}
	if req.OrganizationalUnit != "" {
		cert.Subject.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	if req.Country != "" {
		cert.Subject.Country = []string{req.Country}
	}
	if req.State != "" {
		cert.Subject.Province = []string{req.State}
	}
	if req.Locality != "" {
		cert.Subject.Locality = []string{req.Locality}
	}

	// Set SANs
	if len(req.DNSNames) > 0 {
		cert.DNSNames = make([]string, len(req.DNSNames))
		copy(cert.DNSNames, req.DNSNames)
	}
	if len(req.IPAddresses) > 0 {
		cert.IPAddresses = make([]net.IP, len(req.IPAddresses))
		copy(cert.IPAddresses, req.IPAddresses)
	}
	if len(req.EmailAddresses) > 0 {
		cert.EmailAddresses = make([]string, len(req.EmailAddresses))
		copy(cert.EmailAddresses, req.EmailAddresses)
	}

	// Custom validity period
	if req.ValidityDays > 0 {
		now := time.Now()
		cert.NotBefore = now.Add(-m.config.ClockSkewAllowance)
		cert.NotAfter = now.Add(time.Duration(req.ValidityDays) * 24 * time.Hour)
	}

	return &cert, nil
}

// CustomizeServerTemplate creates a customized server certificate template.
func (m *TemplateManager) CustomizeServerTemplate(domain string, sans []string, ips []net.IP) (*x509.Certificate, error) {
	// Merge domain into SANs
	allDNS := make([]string, 0, len(sans)+1)
	allDNS = append(allDNS, domain)
	for _, san := range sans {
		if san != domain {
			allDNS = append(allDNS, san)
		}
	}

	return m.CustomizeTemplate(&CertRequest{
		CommonName:  domain,
		DNSNames:    allDNS,
		IPAddresses: ips,
		CertType:    CertTypeServer,
	})
}

// ============================================================================
// Serial Number Generation
// ============================================================================

// GenerateSerialNumber generates a cryptographically random serial number.
func GenerateSerialNumber() (*big.Int, error) {
	// Generate 128-bit random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}

// ============================================================================
// Template Validation
// ============================================================================

// TemplateValidationResult contains template validation results.
type TemplateValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
}

// ValidateTemplate validates a certificate template.
func ValidateTemplate(template *x509.Certificate) *TemplateValidationResult {
	result := &TemplateValidationResult{Valid: true}

	if template == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "template is nil")
		return result
	}

	// Check Key Usage
	if template.KeyUsage == 0 {
		result.Warnings = append(result.Warnings, "no Key Usage specified")
	}

	// Check Extended Key Usage
	if len(template.ExtKeyUsage) == 0 {
		result.Warnings = append(result.Warnings, "no Extended Key Usage specified")
	}

	// Check Basic Constraints for end-entity
	if !template.BasicConstraintsValid {
		result.Warnings = append(result.Warnings, "BasicConstraints not set")
	}

	// CA flag should be false for end-entity
	if template.IsCA {
		result.Errors = append(result.Errors, "IsCA should be false for end-entity template")
		result.Valid = false
	}

	// Check validity period
	if !template.NotAfter.After(template.NotBefore) {
		result.Errors = append(result.Errors, "NotAfter must be after NotBefore")
		result.Valid = false
	}

	return result
}

// ============================================================================
// Extension Helpers
// ============================================================================

// SetCRLDistributionPoint sets the CRL distribution point on a template.
func (m *TemplateManager) SetCRLDistributionPoint(template *x509.Certificate, url string) {
	if template != nil && url != "" {
		template.CRLDistributionPoints = []string{url}
	}
}

// SetOCSPServer sets the OCSP server on a template.
func (m *TemplateManager) SetOCSPServer(template *x509.Certificate, url string) {
	if template != nil && url != "" {
		template.OCSPServer = []string{url}
	}
}

// SetSubjectKeyIdentifier generates and sets the Subject Key Identifier.
// Note: This is typically set during signing based on the public key.
func SetSubjectKeyIdentifier(template *x509.Certificate, keyID []byte) {
	if template != nil && len(keyID) > 0 {
		template.SubjectKeyId = keyID
	}
}

// SetAuthorityKeyIdentifier sets the Authority Key Identifier.
func SetAuthorityKeyIdentifier(template *x509.Certificate, keyID []byte) {
	if template != nil && len(keyID) > 0 {
		template.AuthorityKeyId = keyID
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// GetValidityDays returns configured validity days for certificate type.
func (m *TemplateManager) GetValidityDays(certType CertificateType) int {
	switch certType {
	case CertTypeServer:
		return m.config.ServerValidityDays
	case CertTypeClient:
		return m.config.ClientValidityDays
	case CertTypeEmail:
		return m.config.EmailValidityDays
	case CertTypeCodeSigning:
		return m.config.CodeSigningValidityDays
	default:
		return m.config.ServerValidityDays
	}
}

// GetOrganizationName returns the configured organization name.
func (m *TemplateManager) GetOrganizationName() string {
	return m.config.OrganizationName
}

// UpdateConfig updates the template configuration.
func (m *TemplateManager) UpdateConfig(config *TemplateConfig) {
	if config != nil {
		m.config = config
	}
}
