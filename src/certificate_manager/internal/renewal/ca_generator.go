// Package renewal provides CA certificate generation for renewal operations.
package renewal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// ============================================================================
// CA Generator Implementation
// ============================================================================

// DefaultCAGenerator generates new CA certificates using crypto/x509.
type DefaultCAGenerator struct {
	// No configuration needed for default implementation
}

// NewDefaultCAGenerator creates a new default CA generator.
func NewDefaultCAGenerator() *DefaultCAGenerator {
	return &DefaultCAGenerator{}
}

// ============================================================================
// CAGenerator Interface Implementation
// ============================================================================

// GenerateNewCA generates a new self-signed CA certificate.
func (g *DefaultCAGenerator) GenerateNewCA(ctx context.Context, config *CAGenerationConfig) (*x509.Certificate, []byte, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.AddDate(config.ValidityYears, 0, 0)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the generated certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Marshal private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	return cert, privateKeyBytes, nil
}

// ============================================================================
// Validation and Helper Methods
// ============================================================================

// ValidateCAConfig validates CA generation configuration.
func ValidateCAConfig(config *CAGenerationConfig) error {
	if config.CommonName == "" {
		return fmt.Errorf("CommonName is required")
	}

	if config.Organization == "" {
		return fmt.Errorf("Organization is required")
	}

	if config.ValidityYears <= 0 {
		return fmt.Errorf("ValidityYears must be positive")
	}

	if config.ValidityYears > 30 {
		return fmt.Errorf("ValidityYears cannot exceed 30 years")
	}

	if config.KeySize < 2048 {
		return fmt.Errorf("KeySize must be at least 2048 bits")
	}

	if config.KeySize > 8192 {
		return fmt.Errorf("KeySize cannot exceed 8192 bits")
	}

	return nil
}

// GetRecommendedCAConfig returns recommended CA generation configuration.
func GetRecommendedCAConfig() *CAGenerationConfig {
	return &CAGenerationConfig{
		CommonName:    "SafeOps Root CA",
		Organization:  "SafeOps",
		Country:       "US",
		ValidityYears: 10,
		KeySize:       4096,
	}
}

// ============================================================================
// CA Chain Support
// ============================================================================

// GenerateIntermediateCA generates an intermediate CA signed by a root CA.
func (g *DefaultCAGenerator) GenerateIntermediateCA(
	ctx context.Context,
	config *CAGenerationConfig,
	rootCert *x509.Certificate,
	rootKey *rsa.PrivateKey,
) (*x509.Certificate, []byte, error) {
	// Generate intermediate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.AddDate(config.ValidityYears, 0, 0)

	// Create intermediate certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	// Sign with root CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create intermediate certificate: %w", err)
	}

	// Parse the generated certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Marshal private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	return cert, privateKeyBytes, nil
}

// ============================================================================
// Certificate Information
// ============================================================================

// GetCertificateInfo returns human-readable information about a certificate.
func GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"subject":         cert.Subject.String(),
		"issuer":          cert.Issuer.String(),
		"serial_number":   cert.SerialNumber.String(),
		"not_before":      cert.NotBefore.Format(time.RFC3339),
		"not_after":       cert.NotAfter.Format(time.RFC3339),
		"is_ca":           cert.IsCA,
		"key_usage":       getKeyUsageString(cert.KeyUsage),
		"signature_algo":  cert.SignatureAlgorithm.String(),
		"public_key_algo": cert.PublicKeyAlgorithm.String(),
	}
}

func getKeyUsageString(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return usages
}
