package tls_integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrCANotLoaded       = errors.New("CA certificate or key not loaded")
	ErrSigningFailed     = errors.New("certificate signing failed")
	ErrKeyGeneration     = errors.New("key generation failed")
	ErrDomainBlacklisted = errors.New("domain is blacklisted")
)

// ============================================================================
// Configuration
// ============================================================================

// SigningServiceConfig configures the signing service.
type SigningServiceConfig struct {
	KeyAlgorithm     string // "RSA" or "ECDSA"
	RSAKeySize       int    // RSA key size (default 2048)
	ECDSACurve       string // ECDSA curve: "P256", "P384"
	DefaultValidity  int    // Default validity in days
	EnableCaching    bool   // Enable certificate caching
	EnableAuditLog   bool   // Enable audit logging
	CACertPath       string // Path to CA certificate
	CAKeyPath        string // Path to CA private key
	CAPassphrasePath string // Path to CA key passphrase
}

// DefaultSigningServiceConfig returns default configuration.
func DefaultSigningServiceConfig() *SigningServiceConfig {
	return &SigningServiceConfig{
		KeyAlgorithm:    "RSA",
		RSAKeySize:      2048,
		ECDSACurve:      "P256",
		DefaultValidity: 90,
		EnableCaching:   true,
		EnableAuditLog:  true,
	}
}

// ============================================================================
// Signing Service
// ============================================================================

// SigningService provides certificate signing capabilities.
type SigningService struct {
	config          *SigningServiceConfig
	caCert          *x509.Certificate
	caKey           crypto.PrivateKey
	cache           *CertificateCache
	templateManager *TemplateManager
	validator       *CertificateValidator

	mu sync.RWMutex

	// Statistics
	signingCount  int64
	cacheHits     int64
	cacheMisses   int64
	signingErrors int64
}

// NewSigningService creates a new signing service.
func NewSigningService(config *SigningServiceConfig) *SigningService {
	if config == nil {
		config = DefaultSigningServiceConfig()
	}

	s := &SigningService{
		config:          config,
		templateManager: NewTemplateManager(nil),
	}

	if config.EnableCaching {
		s.cache = NewCertificateCache(DefaultCacheConfig())
		s.cache.Start()
	}

	return s
}

// LoadCA loads the CA certificate and private key.
func (s *SigningService) LoadCA(certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode CA private key PEM")
	}

	var key crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	s.caCert = cert
	s.caKey = key

	// Initialize validator with CA
	s.validator = NewCertificateValidator(nil, cert)

	log.Printf("[signing] Loaded CA: %s", cert.Subject.CommonName)
	return nil
}

// SetCA sets the CA certificate and key directly.
func (s *SigningService) SetCA(cert *x509.Certificate, key crypto.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCert = cert
	s.caKey = key
	s.validator = NewCertificateValidator(nil, cert)
}

// IsCALoaded returns whether CA is loaded.
func (s *SigningService) IsCALoaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caCert != nil && s.caKey != nil
}

// ============================================================================
// Certificate Signing
// ============================================================================

// SignedCertificate contains the signed certificate and key.
type SignedCertificate struct {
	Certificate  *x509.Certificate
	CertPEM      []byte
	KeyPEM       []byte
	Domain       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	SignedAt     time.Time
}

// SignCertificate signs a certificate for the specified domain.
func (s *SigningService) SignCertificate(domain string, certType CertificateType) (*SignedCertificate, error) {
	return s.SignCertificateWithSANs(domain, nil, nil, certType)
}

// SignCertificateWithSANs signs a certificate with custom SANs.
func (s *SigningService) SignCertificateWithSANs(domain string, dnsNames []string, ips []net.IP, certType CertificateType) (*SignedCertificate, error) {
	// Validate domain
	if err := ValidateDomain(domain); err != nil {
		return nil, err
	}

	// Check cache first
	if s.cache != nil {
		if cached, ok := s.cache.Get(domain); ok {
			atomic.AddInt64(&s.cacheHits, 1)
			return &SignedCertificate{
				Certificate:  cached.Certificate,
				CertPEM:      cached.CertPEM,
				KeyPEM:       cached.KeyPEM,
				Domain:       domain,
				NotBefore:    cached.Certificate.NotBefore,
				NotAfter:     cached.Certificate.NotAfter,
				SerialNumber: cached.Certificate.SerialNumber.String(),
			}, nil
		}
		atomic.AddInt64(&s.cacheMisses, 1)
	}

	// Check CA is loaded
	s.mu.RLock()
	caCert := s.caCert
	caKey := s.caKey
	s.mu.RUnlock()

	if caCert == nil || caKey == nil {
		return nil, ErrCANotLoaded
	}

	// Build SANs
	allDNS := buildDNSNames(domain, dnsNames)

	// Create certificate request
	req := &CertRequest{
		CommonName:  domain,
		DNSNames:    allDNS,
		IPAddresses: ips,
		CertType:    certType,
	}

	// Customize template
	template, err := s.templateManager.CustomizeTemplate(req)
	if err != nil {
		atomic.AddInt64(&s.signingErrors, 1)
		return nil, fmt.Errorf("template customization failed: %w", err)
	}

	// Generate key pair
	keyPair, err := s.generateKeyPair()
	if err != nil {
		atomic.AddInt64(&s.signingErrors, 1)
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}

	// Set authority key identifier
	template.AuthorityKeyId = caCert.SubjectKeyId

	// Get public key
	publicKey := getPublicKey(keyPair)

	// Sign certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	if err != nil {
		atomic.AddInt64(&s.signingErrors, 1)
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	// Parse signed certificate
	signedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		atomic.AddInt64(&s.signingErrors, 1)
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM, err := encodePrivateKey(keyPair)
	if err != nil {
		atomic.AddInt64(&s.signingErrors, 1)
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	result := &SignedCertificate{
		Certificate:  signedCert,
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		Domain:       domain,
		SerialNumber: signedCert.SerialNumber.String(),
		NotBefore:    signedCert.NotBefore,
		NotAfter:     signedCert.NotAfter,
		SignedAt:     time.Now(),
	}

	// Store in cache
	if s.cache != nil {
		s.cache.Set(domain, &CachedCertificate{
			Certificate: signedCert,
			PrivateKey:  keyPair,
			CertPEM:     certPEM,
			KeyPEM:      keyPEM,
			Domain:      domain,
			SANs:        allDNS,
			ExpiresAt:   signedCert.NotAfter,
		})
	}

	atomic.AddInt64(&s.signingCount, 1)

	if s.config.EnableAuditLog {
		log.Printf("[signing] Signed certificate for %s, serial: %s, valid until: %s",
			domain, result.SerialNumber, result.NotAfter.Format(time.RFC3339))
	}

	return result, nil
}

// ============================================================================
// Key Generation
// ============================================================================

// generateKeyPair generates a new key pair based on configuration.
func (s *SigningService) generateKeyPair() (crypto.PrivateKey, error) {
	switch s.config.KeyAlgorithm {
	case "ECDSA":
		return s.generateECDSAKey()
	default:
		return s.generateRSAKey()
	}
}

// generateRSAKey generates an RSA key pair.
func (s *SigningService) generateRSAKey() (*rsa.PrivateKey, error) {
	size := s.config.RSAKeySize
	if size < 2048 {
		size = 2048
	}
	return rsa.GenerateKey(rand.Reader, size)
}

// generateECDSAKey generates an ECDSA key pair.
func (s *SigningService) generateECDSAKey() (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch s.config.ECDSACurve {
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// encodePrivateKey encodes a private key to PEM.
func encodePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// buildDNSNames builds DNS names list with domain and wildcard.
func buildDNSNames(domain string, additional []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(additional)+2)

	// Add primary domain
	result = append(result, domain)
	seen[domain] = true

	// Add wildcard variant
	wildcard := "*." + domain
	result = append(result, wildcard)
	seen[wildcard] = true

	// Add additional SANs
	for _, san := range additional {
		if !seen[san] {
			result = append(result, san)
			seen[san] = true
		}
	}

	return result
}

// getPublicKey extracts the public key from a private key.
func getPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// ============================================================================
// Statistics
// ============================================================================

// SigningStats contains signing service statistics.
type SigningStats struct {
	SigningCount  int64       `json:"signing_count"`
	CacheHits     int64       `json:"cache_hits"`
	CacheMisses   int64       `json:"cache_misses"`
	SigningErrors int64       `json:"signing_errors"`
	HitRate       float64     `json:"hit_rate"`
	CacheStats    *CacheStats `json:"cache_stats,omitempty"`
}

// GetStats returns signing service statistics.
func (s *SigningService) GetStats() *SigningStats {
	hits := atomic.LoadInt64(&s.cacheHits)
	misses := atomic.LoadInt64(&s.cacheMisses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	stats := &SigningStats{
		SigningCount:  atomic.LoadInt64(&s.signingCount),
		CacheHits:     hits,
		CacheMisses:   misses,
		SigningErrors: atomic.LoadInt64(&s.signingErrors),
		HitRate:       hitRate,
	}

	if s.cache != nil {
		stats.CacheStats = s.cache.GetStats()
	}

	return stats
}

// ============================================================================
// Cache Management
// ============================================================================

// GetCache returns the certificate cache.
func (s *SigningService) GetCache() *CertificateCache {
	return s.cache
}

// ClearCache clears the certificate cache.
func (s *SigningService) ClearCache() {
	if s.cache != nil {
		s.cache.Clear()
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Stop stops the signing service and cleans up resources.
func (s *SigningService) Stop() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

// ============================================================================
// Validation
// ============================================================================

// ValidateSignedCertificate validates a signed certificate.
func (s *SigningService) ValidateSignedCertificate(cert *x509.Certificate) *ValidationResult {
	if s.validator == nil {
		return &ValidationResult{Valid: false, Errors: []string{"validator not initialized"}}
	}
	return s.validator.ValidateCertificate(cert)
}

// GetCASubject returns the CA certificate subject.
func (s *SigningService) GetCASubject() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.caCert != nil {
		return s.caCert.Subject.CommonName
	}
	return ""
}

// GetCAExpiry returns the CA certificate expiration time.
func (s *SigningService) GetCAExpiry() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.caCert != nil {
		return s.caCert.NotAfter
	}
	return time.Time{}
}
