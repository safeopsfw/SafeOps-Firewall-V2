// Package validation provides certificate validation and compliance checking
package validation

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"certificate_manager/internal/storage"

	"gopkg.in/yaml.v3"
)

// ComplianceViolation represents a certificate compliance violation
type ComplianceViolation struct {
	SerialNumber  string    `json:"serial_number"`
	CommonName    string    `json:"common_name"`
	ViolationType string    `json:"violation_type"` // "weak_key", "weak_hash", "too_long_validity", etc.
	Severity      string    `json:"severity"`       // "critical", "warning"
	Details       string    `json:"details"`
	IssuedAt      time.Time `json:"issued_at"`
}

// ComplianceReport contains the results of a compliance check
type ComplianceReport struct {
	Compliant   bool                  `json:"compliant"`
	Violations  []ComplianceViolation `json:"violations"`
	Warnings    []ComplianceViolation `json:"warnings"`
	CheckedAt   time.Time             `json:"checked_at"`
	PolicyLevel string                `json:"policy_level"` // "ca_browser_forum", "nist", "custom"
}

// CompliancePolicy defines certificate compliance requirements
type CompliancePolicy struct {
	KeySize struct {
		RSAMinimum   int    `yaml:"rsa_minimum"`
		ECDSAMinimum string `yaml:"ecdsa_minimum"`
	} `yaml:"key_size"`

	SignatureAlgorithm struct {
		Allowed []string `yaml:"allowed"`
		Blocked []string `yaml:"blocked"`
	} `yaml:"signature_algorithm"`

	Validity struct {
		ServerMaxDays int `yaml:"server_max_days"`
		ClientMaxDays int `yaml:"client_max_days"`
		CAMaxYears    int `yaml:"ca_max_years"`
	} `yaml:"validity"`

	Extensions struct {
		RequireSAN      bool `yaml:"require_san"`
		RequireKeyUsage bool `yaml:"require_key_usage"`
		RequireEKU      bool `yaml:"require_eku"`
		RequireAKI      bool `yaml:"require_aki"`
		RequireSKI      bool `yaml:"require_ski"`
	} `yaml:"extensions"`

	Standards struct {
		EnforceCABrowserForum bool `yaml:"enforce_ca_browser_forum"`
		EnforceNIST           bool `yaml:"enforce_nist"`
	} `yaml:"standards"`
}

// ComplianceChecker validates certificates against compliance standards
type ComplianceChecker struct {
	policy   CompliancePolicy
	certRepo *storage.CertificateRepository
}

// NewComplianceChecker creates a new compliance checker
func NewComplianceChecker(certRepo *storage.CertificateRepository) *ComplianceChecker {
	return &ComplianceChecker{
		certRepo: certRepo,
		policy:   getDefaultCompliancePolicy(),
	}
}

// LoadPolicyFromFile loads compliance policy from a YAML file
func (cc *ComplianceChecker) LoadPolicyFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy CompliancePolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	cc.policy = policy
	log.Printf("Loaded compliance policy from %s", path)
	return nil
}

// LoadPolicyFromEnv loads compliance policy from environment variables
func (cc *ComplianceChecker) LoadPolicyFromEnv() {
	policy := cc.policy // Start with defaults

	// Key size configuration
	if val := os.Getenv("MIN_RSA_KEY_SIZE"); val != "" {
		fmt.Sscanf(val, "%d", &policy.KeySize.RSAMinimum)
	}
	if val := os.Getenv("MIN_ECDSA_CURVE"); val != "" {
		policy.KeySize.ECDSAMinimum = val
	}

	// Validity configuration
	if val := os.Getenv("MAX_SERVER_CERT_DAYS"); val != "" {
		fmt.Sscanf(val, "%d", &policy.Validity.ServerMaxDays)
	}
	if val := os.Getenv("MAX_CLIENT_CERT_DAYS"); val != "" {
		fmt.Sscanf(val, "%d", &policy.Validity.ClientMaxDays)
	}

	// Extension requirements
	policy.Extensions.RequireSAN = getEnvBool("REQUIRE_SAN", true)
	policy.Extensions.RequireKeyUsage = getEnvBool("REQUIRE_KEY_USAGE", true)
	policy.Extensions.RequireEKU = getEnvBool("REQUIRE_EKU", true)

	// Standards enforcement
	policy.Standards.EnforceCABrowserForum = getEnvBool("ENFORCE_CA_BROWSER_FORUM", true)
	policy.Standards.EnforceNIST = getEnvBool("ENFORCE_NIST", false)

	// SHA-1 configuration
	allowSHA1 := getEnvBool("ALLOW_SHA1", false)
	if !allowSHA1 {
		// Ensure SHA-1 algorithms are in blocked list
		blocked := make(map[string]bool)
		for _, alg := range policy.SignatureAlgorithm.Blocked {
			blocked[alg] = true
		}
		sha1Algs := []string{"SHA1WithRSA", "ECDSAWithSHA1", "DSAWithSHA1"}
		for _, alg := range sha1Algs {
			if !blocked[alg] {
				policy.SignatureAlgorithm.Blocked = append(policy.SignatureAlgorithm.Blocked, alg)
			}
		}
	}

	cc.policy = policy
	log.Println("Loaded compliance policy from environment variables")
}

// CheckCertificateCompliance performs comprehensive compliance checks on a certificate
func (cc *ComplianceChecker) CheckCertificateCompliance(cert *x509.Certificate) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Compliant:   true,
		Violations:  make([]ComplianceViolation, 0),
		Warnings:    make([]ComplianceViolation, 0),
		CheckedAt:   time.Now(),
		PolicyLevel: cc.determinePolicyLevel(),
	}

	// Run all compliance checks
	checks := []func(*x509.Certificate, *ComplianceReport){
		cc.checkKeySize,
		cc.checkSignatureAlgorithm,
		cc.checkValidity,
		cc.checkExtensions,
		cc.checkSANCompliance,
		cc.checkSerialNumber,
	}

	for _, check := range checks {
		check(cert, report)
	}

	// Additional standards checks if enabled
	if cc.policy.Standards.EnforceCABrowserForum {
		cc.checkCABrowserForumBaseline(cert, report)
	}

	if cc.policy.Standards.EnforceNIST {
		cc.checkNISTCompliance(cert, report)
	}

	// Set overall compliance status
	report.Compliant = len(report.Violations) == 0

	return report, nil
}

// CheckKeySize validates minimum key sizes
func (cc *ComplianceChecker) CheckKeySize(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkKeySize(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("key size validation failed: %s", report.Violations[0].Details)
	}
	return nil
}

func (cc *ComplianceChecker) checkKeySize(cert *x509.Certificate, report *ComplianceReport) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		if keySize < cc.policy.KeySize.RSAMinimum {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "weak_key",
				Severity:      "critical",
				Details:       fmt.Sprintf("RSA key size %d bits is below minimum %d bits", keySize, cc.policy.KeySize.RSAMinimum),
			})
		} else if keySize == 2048 && cert.IsCA {
			// Warning: CA certificates should use stronger keys
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "weak_key",
				Severity:      "warning",
				Details:       "CA certificate should use 4096-bit RSA key for better security",
			})
		}

	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		minCurve := cc.policy.KeySize.ECDSAMinimum

		// Map curve names to strength order
		curveStrength := map[string]int{
			"P-224": 1,
			"P-256": 2,
			"P-384": 3,
			"P-521": 4,
		}

		currentStrength := curveStrength[curveName]
		minStrength := curveStrength[minCurve]

		if currentStrength < minStrength {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "weak_key",
				Severity:      "critical",
				Details:       fmt.Sprintf("ECDSA curve %s is below minimum %s", curveName, minCurve),
			})
		}

	default:
		// Unknown or deprecated key type
		report.Violations = append(report.Violations, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "unsupported_key_type",
			Severity:      "critical",
			Details:       fmt.Sprintf("Unsupported or deprecated key type: %T", pub),
		})
	}
}

// CheckAlgorithm validates signature algorithms
func (cc *ComplianceChecker) CheckAlgorithm(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkSignatureAlgorithm(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("signature algorithm validation failed: %s", report.Violations[0].Details)
	}
	return nil
}

func (cc *ComplianceChecker) checkSignatureAlgorithm(cert *x509.Certificate, report *ComplianceReport) {
	algName := cert.SignatureAlgorithm.String()

	// Check if algorithm is explicitly blocked
	for _, blocked := range cc.policy.SignatureAlgorithm.Blocked {
		if strings.Contains(algName, blocked) || blocked == algName {
			severity := "critical"
			if strings.Contains(algName, "SHA1") {
				severity = "critical" // SHA-1 is critically weak
			}

			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "weak_hash",
				Severity:      severity,
				Details:       fmt.Sprintf("Signature algorithm %s is not allowed (weak or deprecated)", algName),
			})
			return
		}
	}

	// Check if algorithm is in allowed list (if specified)
	if len(cc.policy.SignatureAlgorithm.Allowed) > 0 {
		allowed := false
		for _, allowedAlg := range cc.policy.SignatureAlgorithm.Allowed {
			if strings.Contains(algName, allowedAlg) || allowedAlg == algName {
				allowed = true
				break
			}
		}

		if !allowed {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "unrecognized_algorithm",
				Severity:      "warning",
				Details:       fmt.Sprintf("Signature algorithm %s is not in allowed list", algName),
			})
		}
	}

	// Specific algorithm checks
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		report.Violations = append(report.Violations, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "weak_hash",
			Severity:      "critical",
			Details:       "SHA-1 signature algorithm is deprecated and insecure (SHAttered attack)",
		})

	case x509.MD5WithRSA, x509.MD2WithRSA:
		report.Violations = append(report.Violations, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "weak_hash",
			Severity:      "critical",
			Details:       "MD5/MD2 signature algorithm is broken and must not be used",
		})
	}
}

// CheckValidity validates certificate validity periods
func (cc *ComplianceChecker) CheckValidity(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkValidity(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("validity period validation failed: %s", report.Violations[0].Details)
	}
	return nil
}

func (cc *ComplianceChecker) checkValidity(cert *x509.Certificate, report *ComplianceReport) {
	duration := cert.NotAfter.Sub(cert.NotBefore)
	days := int(duration.Hours() / 24)

	// Determine certificate type and apply appropriate limits
	if cert.IsCA {
		// CA certificates: typically 10-20 years acceptable
		maxYears := cc.policy.Validity.CAMaxYears
		maxDays := maxYears * 365

		if days > maxDays {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "too_long_validity",
				Severity:      "warning",
				Details:       fmt.Sprintf("CA certificate validity %d days exceeds recommended %d years (%d days)", days, maxYears, maxDays),
			})
		}
	} else {
		// End-entity certificates
		var maxDays int
		certType := "server"

		// Determine if client or server certificate based on EKU
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageClientAuth {
				certType = "client"
				maxDays = cc.policy.Validity.ClientMaxDays
				break
			}
		}

		if certType == "server" || maxDays == 0 {
			maxDays = cc.policy.Validity.ServerMaxDays
		}

		if days > maxDays {
			// CA/Browser Forum requirement: 398 days max for public TLS (as of Sept 2020)
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "too_long_validity",
				Severity:      "critical",
				Details:       fmt.Sprintf("%s certificate validity %d days exceeds maximum %d days (CA/Browser Forum requirement)", certType, days, maxDays),
			})
		} else if days > 90 && certType == "server" {
			// Warning for server certs > 90 days (industry moving toward 90-day certs)
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "long_validity",
				Severity:      "warning",
				Details:       fmt.Sprintf("Server certificate validity %d days; industry best practice recommends ≤90 days", days),
			})
		}
	}
}

// CheckExtensions validates required certificate extensions
func (cc *ComplianceChecker) CheckExtensions(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkExtensions(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("extension validation failed: %s", report.Violations[0].Details)
	}
	return nil
}

func (cc *ComplianceChecker) checkExtensions(cert *x509.Certificate, report *ComplianceReport) {
	// Subject Alternative Name (SAN) - REQUIRED by RFC 6125
	if cc.policy.Extensions.RequireSAN {
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.EmailAddresses) == 0 {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "missing_san",
				Severity:      "critical",
				Details:       "Subject Alternative Name (SAN) extension is required (RFC 6125)",
			})
		}
	}

	// Key Usage - REQUIRED
	if cc.policy.Extensions.RequireKeyUsage {
		if cert.KeyUsage == 0 {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "missing_key_usage",
				Severity:      "critical",
				Details:       "Key Usage extension is required",
			})
		}
	}

	// Extended Key Usage - REQUIRED for end-entity certificates
	if cc.policy.Extensions.RequireEKU && !cert.IsCA {
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "missing_eku",
				Severity:      "critical",
				Details:       "Extended Key Usage (EKU) extension is required for end-entity certificates",
			})
		}
	}

	// Basic Constraints - REQUIRED
	if !cert.IsCA {
		// For end-entity certs, verify CA flag is false
		// (x509 package handles this, but double-check)
		if cert.MaxPathLen != 0 || cert.MaxPathLenZero {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "invalid_basic_constraints",
				Severity:      "warning",
				Details:       "End-entity certificate has unusual Basic Constraints settings",
			})
		}
	}

	// Authority Key Identifier - RECOMMENDED
	if cc.policy.Extensions.RequireAKI {
		if len(cert.AuthorityKeyId) == 0 {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "missing_aki",
				Severity:      "warning",
				Details:       "Authority Key Identifier (AKI) extension is recommended",
			})
		}
	}

	// Subject Key Identifier - RECOMMENDED
	if cc.policy.Extensions.RequireSKI {
		if len(cert.SubjectKeyId) == 0 {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "missing_ski",
				Severity:      "warning",
				Details:       "Subject Key Identifier (SKI) extension is recommended",
			})
		}
	}
}

func (cc *ComplianceChecker) checkSANCompliance(cert *x509.Certificate, report *ComplianceReport) {
	// Check for wildcards in SAN DNS names
	for _, dnsName := range cert.DNSNames {
		if strings.Contains(dnsName, "*") {
			// Wildcard must be in leftmost label only
			if !strings.HasPrefix(dnsName, "*.") {
				report.Violations = append(report.Violations, ComplianceViolation{
					SerialNumber:  cert.SerialNumber.String(),
					CommonName:    cert.Subject.CommonName,
					ViolationType: "invalid_wildcard",
					Severity:      "critical",
					Details:       fmt.Sprintf("Wildcard in SAN '%s' must be in leftmost label only (*.example.com)", dnsName),
				})
			}

			// Check for multiple wildcards
			if strings.Count(dnsName, "*") > 1 {
				report.Violations = append(report.Violations, ComplianceViolation{
					SerialNumber:  cert.SerialNumber.String(),
					CommonName:    cert.Subject.CommonName,
					ViolationType: "invalid_wildcard",
					Severity:      "critical",
					Details:       fmt.Sprintf("Multiple wildcards in SAN '%s' are not allowed", dnsName),
				})
			}
		}

		// Check for internal names (localhost, .local, .internal)
		if cc.policy.Standards.EnforceCABrowserForum {
			internalSuffixes := []string{".local", ".internal", ".localhost"}
			for _, suffix := range internalSuffixes {
				if strings.HasSuffix(dnsName, suffix) || dnsName == "localhost" {
					report.Warnings = append(report.Warnings, ComplianceViolation{
						SerialNumber:  cert.SerialNumber.String(),
						CommonName:    cert.Subject.CommonName,
						ViolationType: "internal_name",
						Severity:      "warning",
						Details:       fmt.Sprintf("Internal name '%s' in SAN (not allowed in publicly-trusted certificates)", dnsName),
					})
				}
			}
		}
	}

	// Check for private IP addresses in SAN
	if cc.policy.Standards.EnforceCABrowserForum {
		for _, ip := range cert.IPAddresses {
			if isPrivateIP(ip) {
				report.Warnings = append(report.Warnings, ComplianceViolation{
					SerialNumber:  cert.SerialNumber.String(),
					CommonName:    cert.Subject.CommonName,
					ViolationType: "private_ip",
					Severity:      "warning",
					Details:       fmt.Sprintf("Private IP address '%s' in SAN (not allowed in publicly-trusted certificates)", ip.String()),
				})
			}
		}
	}
}

func (cc *ComplianceChecker) checkSerialNumber(cert *x509.Certificate, report *ComplianceReport) {
	// Serial number should have at least 64 bits of entropy (CA/Browser Forum)
	serialBytes := cert.SerialNumber.Bytes()
	if len(serialBytes) < 8 {
		report.Warnings = append(report.Warnings, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "weak_serial",
			Severity:      "warning",
			Details:       fmt.Sprintf("Serial number has %d bytes; CA/Browser Forum recommends ≥8 bytes (64 bits) of entropy", len(serialBytes)),
		})
	}
}

// CheckBaselineRequirements checks CA/Browser Forum Baseline Requirements
func (cc *ComplianceChecker) CheckBaselineRequirements(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkCABrowserForumBaseline(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("baseline requirements validation failed: %d violations", len(report.Violations))
	}
	return nil
}

func (cc *ComplianceChecker) checkCABrowserForumBaseline(cert *x509.Certificate, report *ComplianceReport) {
	// CA/Browser Forum Baseline Requirements checks
	// These are already covered by individual checks, but we add specific baseline notes

	// 1. Key sizes: RSA ≥2048 or ECDSA ≥P-256 (covered by checkKeySize)
	// 2. Hash algorithm: SHA-256 or stronger (covered by checkSignatureAlgorithm)
	// 3. Validity: ≤398 days for public TLS (covered by checkValidity)
	// 4. SAN required (covered by checkExtensions)
	// 5. Wildcard rules (covered by checkSANCompliance)
	// 6. Serial number entropy (covered by checkSerialNumber)

	// Additional baseline check: Certificate policies
	if len(cert.PolicyIdentifiers) == 0 && !cert.IsCA {
		report.Warnings = append(report.Warnings, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "missing_policy",
			Severity:      "warning",
			Details:       "Certificate Policies extension recommended for public trust",
		})
	}
}

// CheckNISTCompliance checks NIST cryptographic standards
func (cc *ComplianceChecker) CheckNISTCompliance(cert *x509.Certificate) error {
	report := &ComplianceReport{
		Violations: make([]ComplianceViolation, 0),
	}
	cc.checkNISTCompliance(cert, report)

	if len(report.Violations) > 0 {
		return fmt.Errorf("NIST compliance validation failed: %d violations", len(report.Violations))
	}
	return nil
}

func (cc *ComplianceChecker) checkNISTCompliance(cert *x509.Certificate, report *ComplianceReport) {
	// NIST SP 800-57 Key Management recommendations
	// FIPS 186-4 Digital Signature Standard

	// Key sizes (through 2030)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		if keySize < 2048 {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "nist_key_size",
				Severity:      "critical",
				Details:       fmt.Sprintf("NIST requires RSA ≥2048 bits through 2030 (current: %d bits)", keySize),
			})
		} else if keySize < 3072 {
			report.Warnings = append(report.Warnings, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "nist_key_size",
				Severity:      "warning",
				Details:       "NIST recommends RSA ≥3072 bits for long-term security (post-2030)",
			})
		}

	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		if curveName == "P-224" {
			report.Violations = append(report.Violations, ComplianceViolation{
				SerialNumber:  cert.SerialNumber.String(),
				CommonName:    cert.Subject.CommonName,
				ViolationType: "nist_curve",
				Severity:      "critical",
				Details:       "NIST requires ECDSA ≥P-256 for security through 2030",
			})
		}
	}

	// Hash algorithms - SHA-256 minimum
	algName := cert.SignatureAlgorithm.String()
	if strings.Contains(algName, "SHA1") || strings.Contains(algName, "MD5") || strings.Contains(algName, "MD2") {
		report.Violations = append(report.Violations, ComplianceViolation{
			SerialNumber:  cert.SerialNumber.String(),
			CommonName:    cert.Subject.CommonName,
			ViolationType: "nist_hash",
			Severity:      "critical",
			Details:       "NIST requires SHA-256 or stronger hash algorithms",
		})
	}
}

// ScanNonCompliantCertificates scans the database for non-compliant certificates
func (cc *ComplianceChecker) ScanNonCompliantCertificates() ([]ComplianceViolation, error) {
	// This is a placeholder - implementation would query certificate repository
	// and check each certificate for compliance
	log.Println("Scanning certificates for compliance violations...")

	allViolations := make([]ComplianceViolation, 0)

	// TODO: Query certificates from repository and check each one
	// Example:
	// certs, err := cc.certRepo.GetAllCertificates()
	// for _, cert := range certs {
	//     report, _ := cc.CheckCertificateCompliance(cert)
	//     allViolations = append(allViolations, report.Violations...)
	// }

	return allViolations, nil
}

// Helper functions

func (cc *ComplianceChecker) determinePolicyLevel() string {
	if cc.policy.Standards.EnforceNIST {
		return "nist"
	}
	if cc.policy.Standards.EnforceCABrowserForum {
		return "ca_browser_forum"
	}
	return "custom"
}

func isPrivateIP(ip net.IP) bool {
	// Check for private IP ranges (RFC 1918)
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 private
		"fe80::/10",      // IPv6 link-local
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

func getDefaultCompliancePolicy() CompliancePolicy {
	policy := CompliancePolicy{}

	// Key size defaults
	policy.KeySize.RSAMinimum = 2048
	policy.KeySize.ECDSAMinimum = "P-256"

	// Signature algorithm defaults
	policy.SignatureAlgorithm.Allowed = []string{
		"SHA256WithRSA",
		"SHA384WithRSA",
		"SHA512WithRSA",
		"ECDSAWithSHA256",
		"ECDSAWithSHA384",
		"ECDSAWithSHA512",
	}

	policy.SignatureAlgorithm.Blocked = []string{
		"SHA1WithRSA",
		"ECDSAWithSHA1",
		"DSAWithSHA1",
		"MD5WithRSA",
		"MD2WithRSA",
	}

	// Validity defaults (CA/Browser Forum compliant)
	policy.Validity.ServerMaxDays = 398 // CA/Browser Forum requirement (Sept 2020+)
	policy.Validity.ClientMaxDays = 825
	policy.Validity.CAMaxYears = 10

	// Extension defaults
	policy.Extensions.RequireSAN = true
	policy.Extensions.RequireKeyUsage = true
	policy.Extensions.RequireEKU = true
	policy.Extensions.RequireAKI = false // Recommended but not required
	policy.Extensions.RequireSKI = false // Recommended but not required

	// Standards defaults
	policy.Standards.EnforceCABrowserForum = true
	policy.Standards.EnforceNIST = false

	return policy
}
