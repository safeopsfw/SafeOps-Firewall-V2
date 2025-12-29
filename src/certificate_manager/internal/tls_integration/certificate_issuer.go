package tls_integration

import (
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"crypto/x509"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrRateLimitExceeded   = errors.New("rate limit exceeded")
	ErrIssuanceFailed      = errors.New("certificate issuance failed")
)

// ============================================================================
// Configuration
// ============================================================================

// IssuerConfig configures the certificate issuer.
type IssuerConfig struct {
	RateLimitPerDomain   int  // Max certs per domain per hour
	DailyLimit           int  // Max total certs per day
	EnableRateLimiting   bool // Enable rate limiting
	IncludeRootInChain   bool // Include root CA in full chain
	AutoRenewalThreshold int  // Days before expiry to auto-renew
	DefaultValidityDays  int  // Default validity period
}

// DefaultIssuerConfig returns default issuer configuration.
func DefaultIssuerConfig() *IssuerConfig {
	return &IssuerConfig{
		RateLimitPerDomain:   10,
		DailyLimit:           10000,
		EnableRateLimiting:   true,
		IncludeRootInChain:   true,
		AutoRenewalThreshold: 30,
		DefaultValidityDays:  90,
	}
}

// ============================================================================
// Issue Options
// ============================================================================

// IssueOptions contains options for certificate issuance.
type IssueOptions struct {
	ValidityDays int      // Custom validity period
	DNSNames     []string // Additional DNS SANs
	IPAddresses  []net.IP // IP SANs
	KeyAlgorithm string   // "RSA" or "ECDSA"
	IncludeRoot  bool     // Include root in chain
	SkipCache    bool     // Skip cache lookup
}

// ============================================================================
// Issued Certificate
// ============================================================================

// IssuedCertificate contains the issued certificate and keys.
type IssuedCertificate struct {
	Certificate    *x509.Certificate
	CertificatePEM []byte
	PrivateKey     crypto.PrivateKey
	PrivateKeyPEM  []byte
	FullChainPEM   []byte
	SerialNumber   string
	Domain         string
	NotBefore      time.Time
	NotAfter       time.Time
	IssuedAt       time.Time
	CacheHit       bool
}

// ============================================================================
// Issue Error
// ============================================================================

// IssueError provides detailed error information.
type IssueError struct {
	Code      string
	Message   string
	Domain    string
	Timestamp time.Time
	Cause     error
}

func (e *IssueError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Domain, e.Message)
}

func (e *IssueError) Unwrap() error {
	return e.Cause
}

// ============================================================================
// Certificate Issuer
// ============================================================================

// CertificateIssuer provides the high-level API for certificate issuance.
type CertificateIssuer struct {
	config         *IssuerConfig
	signingService *SigningService
	validator      *CertificateValidator

	// Rate limiting
	rateLimitMu  sync.RWMutex
	domainCounts map[string]*rateLimitEntry
	dailyCount   int64

	// Statistics
	issuedCount    int64
	cacheHitCount  int64
	cacheMissCount int64
	errorCount     int64
	renewalCount   int64
}

type rateLimitEntry struct {
	count     int
	resetTime time.Time
}

// NewCertificateIssuer creates a new certificate issuer.
func NewCertificateIssuer(config *IssuerConfig, signingService *SigningService) *CertificateIssuer {
	if config == nil {
		config = DefaultIssuerConfig()
	}

	return &CertificateIssuer{
		config:         config,
		signingService: signingService,
		domainCounts:   make(map[string]*rateLimitEntry),
	}
}

// SetValidator sets the certificate validator.
func (i *CertificateIssuer) SetValidator(v *CertificateValidator) {
	i.validator = v
}

// ============================================================================
// Certificate Issuance
// ============================================================================

// IssueServerCertificate issues a TLS server certificate for a domain.
func (i *CertificateIssuer) IssueServerCertificate(domain string, options *IssueOptions) (*IssuedCertificate, error) {
	return i.issueCertificate(domain, CertTypeServer, options)
}

// IssueClientCertificate issues a TLS client certificate.
func (i *CertificateIssuer) IssueClientCertificate(commonName string, options *IssueOptions) (*IssuedCertificate, error) {
	return i.issueCertificate(commonName, CertTypeClient, options)
}

// IssueEmailCertificate issues an S/MIME email certificate.
func (i *CertificateIssuer) IssueEmailCertificate(email string, options *IssueOptions) (*IssuedCertificate, error) {
	if options == nil {
		options = &IssueOptions{}
	}
	options.DNSNames = append(options.DNSNames, email)
	return i.issueCertificate(email, CertTypeEmail, options)
}

// issueCertificate is the core issuance method.
func (i *CertificateIssuer) issueCertificate(domain string, certType CertificateType, options *IssueOptions) (*IssuedCertificate, error) {
	if options == nil {
		options = &IssueOptions{}
	}

	// Validate domain
	if err := ValidateDomain(domain); err != nil {
		atomic.AddInt64(&i.errorCount, 1)
		return nil, &IssueError{
			Code:      "INVALID_DOMAIN",
			Message:   err.Error(),
			Domain:    domain,
			Timestamp: time.Now(),
			Cause:     err,
		}
	}

	// Check rate limits
	if i.config.EnableRateLimiting {
		if err := i.checkRateLimit(domain); err != nil {
			atomic.AddInt64(&i.errorCount, 1)
			return nil, err
		}
	}

	// Check cache first (unless skip cache)
	if !options.SkipCache && i.signingService != nil && i.signingService.cache != nil {
		if cached, ok := i.signingService.cache.Get(domain); ok {
			if !cached.IsExpired() {
				atomic.AddInt64(&i.cacheHitCount, 1)
				return i.formatFromCached(cached), nil
			}
		}
	}
	atomic.AddInt64(&i.cacheMissCount, 1)

	// Sign new certificate
	if i.signingService == nil {
		return nil, &IssueError{
			Code:      "SERVICE_UNAVAILABLE",
			Message:   "signing service not initialized",
			Domain:    domain,
			Timestamp: time.Now(),
		}
	}

	signed, err := i.signingService.SignCertificateWithSANs(domain, options.DNSNames, options.IPAddresses, certType)
	if err != nil {
		atomic.AddInt64(&i.errorCount, 1)
		return nil, &IssueError{
			Code:      "SIGNING_FAILED",
			Message:   err.Error(),
			Domain:    domain,
			Timestamp: time.Now(),
			Cause:     err,
		}
	}

	// Build full chain
	fullChain := i.buildFullChain(signed.CertPEM, options.IncludeRoot || i.config.IncludeRootInChain)

	// Format response
	result := &IssuedCertificate{
		Certificate:    signed.Certificate,
		CertificatePEM: signed.CertPEM,
		PrivateKeyPEM:  signed.KeyPEM,
		FullChainPEM:   fullChain,
		SerialNumber:   signed.SerialNumber,
		Domain:         domain,
		NotBefore:      signed.NotBefore,
		NotAfter:       signed.NotAfter,
		IssuedAt:       time.Now(),
		CacheHit:       false,
	}

	atomic.AddInt64(&i.issuedCount, 1)
	i.incrementRateLimit(domain)

	log.Printf("[issuer] Issued certificate for %s, serial: %s", domain, result.SerialNumber)

	return result, nil
}

// formatFromCached formats a cached certificate as IssuedCertificate.
func (i *CertificateIssuer) formatFromCached(cached *CachedCertificate) *IssuedCertificate {
	fullChain := i.buildFullChain(cached.CertPEM, i.config.IncludeRootInChain)

	return &IssuedCertificate{
		Certificate:    cached.Certificate,
		CertificatePEM: cached.CertPEM,
		PrivateKey:     cached.PrivateKey,
		PrivateKeyPEM:  cached.KeyPEM,
		FullChainPEM:   fullChain,
		SerialNumber:   cached.Certificate.SerialNumber.String(),
		Domain:         cached.Domain,
		NotBefore:      cached.Certificate.NotBefore,
		NotAfter:       cached.Certificate.NotAfter,
		IssuedAt:       cached.CreatedAt,
		CacheHit:       true,
	}
}

// ============================================================================
// Certificate Chain Building
// ============================================================================

// buildFullChain builds the full certificate chain.
func (i *CertificateIssuer) buildFullChain(certPEM []byte, includeRoot bool) []byte {
	if !includeRoot || i.signingService == nil {
		return certPEM
	}

	i.signingService.mu.RLock()
	caCert := i.signingService.caCert
	i.signingService.mu.RUnlock()

	if caCert == nil {
		return certPEM
	}

	// Encode CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	// Concatenate: end-entity cert + CA cert
	chain := make([]byte, 0, len(certPEM)+len(caCertPEM))
	chain = append(chain, certPEM...)
	chain = append(chain, caCertPEM...)

	return chain
}

// ============================================================================
// Rate Limiting
// ============================================================================

// checkRateLimit checks if domain or daily limit is exceeded.
func (i *CertificateIssuer) checkRateLimit(domain string) error {
	// Check daily limit
	if atomic.LoadInt64(&i.dailyCount) >= int64(i.config.DailyLimit) {
		return &IssueError{
			Code:      "DAILY_LIMIT_EXCEEDED",
			Message:   fmt.Sprintf("daily limit of %d certificates exceeded", i.config.DailyLimit),
			Domain:    domain,
			Timestamp: time.Now(),
			Cause:     ErrRateLimitExceeded,
		}
	}

	// Check per-domain limit
	i.rateLimitMu.Lock()
	defer i.rateLimitMu.Unlock()

	entry, exists := i.domainCounts[domain]
	now := time.Now()

	if !exists || now.After(entry.resetTime) {
		// New entry or expired - allow
		return nil
	}

	if entry.count >= i.config.RateLimitPerDomain {
		return &IssueError{
			Code:      "DOMAIN_RATE_LIMIT_EXCEEDED",
			Message:   fmt.Sprintf("rate limit of %d per hour exceeded for domain", i.config.RateLimitPerDomain),
			Domain:    domain,
			Timestamp: now,
			Cause:     ErrRateLimitExceeded,
		}
	}

	return nil
}

// incrementRateLimit increments the rate limit counter for a domain.
func (i *CertificateIssuer) incrementRateLimit(domain string) {
	atomic.AddInt64(&i.dailyCount, 1)

	i.rateLimitMu.Lock()
	defer i.rateLimitMu.Unlock()

	now := time.Now()
	entry, exists := i.domainCounts[domain]

	if !exists || now.After(entry.resetTime) {
		i.domainCounts[domain] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(time.Hour),
		}
		return
	}

	entry.count++
}

// ResetDailyLimit resets the daily issuance counter.
func (i *CertificateIssuer) ResetDailyLimit() {
	atomic.StoreInt64(&i.dailyCount, 0)
}

// ============================================================================
// Certificate Retrieval
// ============================================================================

// GetCertificate retrieves a certificate from cache.
func (i *CertificateIssuer) GetCertificate(domain string) (*IssuedCertificate, error) {
	if i.signingService == nil || i.signingService.cache == nil {
		return nil, ErrCertificateNotFound
	}

	cached, ok := i.signingService.cache.Get(domain)
	if !ok {
		return nil, ErrCertificateNotFound
	}

	return i.formatFromCached(cached), nil
}

// ============================================================================
// Certificate Renewal
// ============================================================================

// RenewCertificate renews a certificate if expiring soon.
func (i *CertificateIssuer) RenewCertificate(domain string) (*IssuedCertificate, error) {
	// Get existing certificate
	existing, err := i.GetCertificate(domain)
	if err != nil {
		// No existing cert, issue new one
		return i.IssueServerCertificate(domain, &IssueOptions{SkipCache: true})
	}

	// Check if renewal needed
	daysUntilExpiry := int(time.Until(existing.NotAfter).Hours() / 24)
	if daysUntilExpiry > i.config.AutoRenewalThreshold {
		// Not expiring soon, return existing
		return existing, nil
	}

	// Issue new certificate
	result, err := i.IssueServerCertificate(domain, &IssueOptions{SkipCache: true})
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&i.renewalCount, 1)
	log.Printf("[issuer] Renewed certificate for %s, old expires: %s, new expires: %s",
		domain, existing.NotAfter.Format(time.RFC3339), result.NotAfter.Format(time.RFC3339))

	return result, nil
}

// GetExpiringCertificates returns domains with certificates expiring within threshold.
func (i *CertificateIssuer) GetExpiringCertificates() []string {
	if i.signingService == nil || i.signingService.cache == nil {
		return nil
	}

	threshold := time.Duration(i.config.AutoRenewalThreshold) * 24 * time.Hour
	expiring := i.signingService.cache.GetExpiringSoon(threshold)

	domains := make([]string, 0, len(expiring))
	for _, cert := range expiring {
		domains = append(domains, cert.Domain)
	}

	return domains
}

// ============================================================================
// Statistics
// ============================================================================

// IssuerStats contains issuer statistics.
type IssuerStats struct {
	IssuedCount    int64         `json:"issued_count"`
	CacheHitCount  int64         `json:"cache_hit_count"`
	CacheMissCount int64         `json:"cache_miss_count"`
	ErrorCount     int64         `json:"error_count"`
	RenewalCount   int64         `json:"renewal_count"`
	DailyCount     int64         `json:"daily_count"`
	HitRate        float64       `json:"hit_rate"`
	SigningStats   *SigningStats `json:"signing_stats,omitempty"`
}

// GetStats returns issuer statistics.
func (i *CertificateIssuer) GetStats() *IssuerStats {
	hits := atomic.LoadInt64(&i.cacheHitCount)
	misses := atomic.LoadInt64(&i.cacheMissCount)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	stats := &IssuerStats{
		IssuedCount:    atomic.LoadInt64(&i.issuedCount),
		CacheHitCount:  hits,
		CacheMissCount: misses,
		ErrorCount:     atomic.LoadInt64(&i.errorCount),
		RenewalCount:   atomic.LoadInt64(&i.renewalCount),
		DailyCount:     atomic.LoadInt64(&i.dailyCount),
		HitRate:        hitRate,
	}

	if i.signingService != nil {
		stats.SigningStats = i.signingService.GetStats()
	}

	return stats
}

// ============================================================================
// Lifecycle
// ============================================================================

// IsReady returns whether the issuer is ready to issue certificates.
func (i *CertificateIssuer) IsReady() bool {
	return i.signingService != nil && i.signingService.IsCALoaded()
}

// GetCASubject returns the CA certificate subject.
func (i *CertificateIssuer) GetCASubject() string {
	if i.signingService != nil {
		return i.signingService.GetCASubject()
	}
	return ""
}

// GetCAExpiry returns the CA certificate expiration time.
func (i *CertificateIssuer) GetCAExpiry() time.Time {
	if i.signingService != nil {
		return i.signingService.GetCAExpiry()
	}
	return time.Time{}
}
