// Package client provides a Go client library for the certificate manager service.
// It wraps gRPC calls and provides a simple, idiomatic Go interface for
// requesting certificates, with built-in caching, retry logic, and connection management.
package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultTimeout       = 10 * time.Second
	DefaultRetryAttempts = 3
	DefaultRetryBackoff  = time.Second
	DefaultCacheTTLRatio = 0.8 // Cache until 80% of certificate validity
	MaxCacheSize         = 1000
	IssueTimeout         = 5 * time.Minute
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrConnectionFailed    = errors.New("connection to certificate manager failed")
	ErrInvalidDomain       = errors.New("invalid domain name")
	ErrCacheExpired        = errors.New("cached certificate expired")
	ErrInvalidCertificate  = errors.New("invalid certificate format")
	ErrMaxRetriesExceeded  = errors.New("maximum retry attempts exceeded")
	ErrClientClosed        = errors.New("client has been closed")
)

// ============================================================================
// Client Structure
// ============================================================================

// CertificateClient provides access to the certificate manager service
type CertificateClient struct {
	address string
	config  ClientConfig

	// Cache
	cache   map[string]*CachedCertificate
	cacheMu sync.RWMutex

	// Connection state
	connected atomic.Bool
	closed    atomic.Bool

	// Watch subscribers
	watchCancel context.CancelFunc
}

// ClientConfig holds client configuration
type ClientConfig struct {
	Timeout       time.Duration
	RetryAttempts int
	RetryBackoff  time.Duration
	EnableCache   bool
	CacheTTLRatio float64
	TLSEnabled    bool
	TLSCertPath   string
	TLSKeyPath    string
	TLSCAPath     string
	APIKey        string // API key for authentication
}

// ClientOption is a function that configures the client
type ClientOption func(*ClientConfig)

// CachedCertificate holds a certificate with cache metadata
type CachedCertificate struct {
	Certificate *Certificate
	CachedAt    time.Time
	ExpiresAt   time.Time
}

// Certificate holds certificate data
type Certificate struct {
	Domain         string
	CertificatePEM string
	PrivateKeyPEM  string
	ChainPEM       string
	SerialNumber   string
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	SANs           []string

	// Parsed representations
	x509Cert   *x509.Certificate
	privateKey crypto.PrivateKey
	tlsCert    *tls.Certificate
}

// CertificateSummary contains certificate metadata
type CertificateSummary struct {
	ID            int64
	Domain        string
	SANs          []string
	Status        string
	Issuer        string
	NotAfter      time.Time
	DaysRemaining int
}

// ============================================================================
// Constructor and Options
// ============================================================================

// NewCertificateClient creates a new certificate manager client
func NewCertificateClient(address string, opts ...ClientOption) (*CertificateClient, error) {
	if address == "" {
		return nil, errors.New("certificate manager address is required")
	}

	config := ClientConfig{
		Timeout:       DefaultTimeout,
		RetryAttempts: DefaultRetryAttempts,
		RetryBackoff:  DefaultRetryBackoff,
		EnableCache:   true,
		CacheTTLRatio: DefaultCacheTTLRatio,
	}

	for _, opt := range opts {
		opt(&config)
	}

	client := &CertificateClient{
		address: address,
		config:  config,
		cache:   make(map[string]*CachedCertificate),
	}

	client.connected.Store(true)

	return client, nil
}

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithRetries sets the retry attempts
func WithRetries(attempts int) ClientOption {
	return func(c *ClientConfig) {
		c.RetryAttempts = attempts
	}
}

// WithRetryBackoff sets the initial retry backoff
func WithRetryBackoff(backoff time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.RetryBackoff = backoff
	}
}

// WithCaching enables or disables caching
func WithCaching(enabled bool) ClientOption {
	return func(c *ClientConfig) {
		c.EnableCache = enabled
	}
}

// WithCacheTTL sets the cache TTL ratio (0.0 to 1.0)
func WithCacheTTL(ratio float64) ClientOption {
	return func(c *ClientConfig) {
		c.CacheTTLRatio = ratio
	}
}

// WithTLS enables mTLS authentication
func WithTLS(certPath, keyPath, caPath string) ClientOption {
	return func(c *ClientConfig) {
		c.TLSEnabled = true
		c.TLSCertPath = certPath
		c.TLSKeyPath = keyPath
		c.TLSCAPath = caPath
	}
}

// WithAPIKey sets the API key for authentication
func WithAPIKey(apiKey string) ClientOption {
	return func(c *ClientConfig) {
		c.APIKey = apiKey
	}
}

// ============================================================================
// Certificate Retrieval
// ============================================================================

// GetCertificate retrieves a certificate for the given domain
// Returns a ready-to-use tls.Certificate
func (c *CertificateClient) GetCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	cert, err := c.GetCertificateDetails(ctx, domain)
	if err != nil {
		return nil, err
	}

	return cert.TLSCertificate()
}

// GetCertificateDetails retrieves full certificate details
func (c *CertificateClient) GetCertificateDetails(ctx context.Context, domain string) (*Certificate, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if !ValidateDomainName(domain) {
		return nil, ErrInvalidDomain
	}

	// Check cache first
	if c.config.EnableCache {
		if cached := c.getFromCache(domain); cached != nil {
			return cached, nil
		}
	}

	// Fetch from service with retry
	var cert *Certificate
	var lastErr error

	for attempt := 0; attempt < c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := c.calculateBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		cert, lastErr = c.fetchCertificate(ctx, domain)
		if lastErr == nil {
			break
		}

		if !isRetryable(lastErr) {
			break
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	// Update cache
	if c.config.EnableCache {
		c.addToCache(domain, cert)
	}

	return cert, nil
}

// GetCertificateRaw retrieves certificate in PEM format
func (c *CertificateClient) GetCertificateRaw(ctx context.Context, domain string) (certPEM, keyPEM, chainPEM string, err error) {
	cert, err := c.GetCertificateDetails(ctx, domain)
	if err != nil {
		return "", "", "", err
	}

	return cert.CertificatePEM, cert.PrivateKeyPEM, cert.ChainPEM, nil
}

// fetchCertificate calls the gRPC service to get a certificate
func (c *CertificateClient) fetchCertificate(ctx context.Context, domain string) (*Certificate, error) {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client
	// For now, return placeholder error indicating service needs implementation
	_ = ctx
	_ = domain

	// Placeholder - would be replaced with actual gRPC call:
	// resp, err := c.grpcClient.GetCertificate(ctx, &pb.GetCertificateRequest{Domain: domain})

	return nil, ErrCertificateNotFound
}

// ============================================================================
// Certificate Issuance
// ============================================================================

// IssueCertificate requests a new certificate for the given domains
func (c *CertificateClient) IssueCertificate(ctx context.Context, domains []string) (*Certificate, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if len(domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}

	for _, domain := range domains {
		if !ValidateDomainName(domain) {
			return nil, ErrInvalidDomain
		}
	}

	// Apply longer timeout for issuance
	ctx, cancel := context.WithTimeout(ctx, IssueTimeout)
	defer cancel()

	// In production, this would call gRPC service
	// resp, err := c.grpcClient.IssueCertificate(ctx, &pb.IssueCertificateRequest{Domains: domains})
	_ = ctx
	_ = domains

	return nil, errors.New("certificate issuance not implemented - requires gRPC service")
}

// ============================================================================
// Certificate Renewal
// ============================================================================

// RenewCertificate requests a certificate renewal
func (c *CertificateClient) RenewCertificate(ctx context.Context, domain string) (*Certificate, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if !ValidateDomainName(domain) {
		return nil, ErrInvalidDomain
	}

	// Invalidate cache
	c.invalidateCache(domain)

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout*3) // Longer for renewal
	defer cancel()

	// In production, this would call gRPC service
	// resp, err := c.grpcClient.RenewCertificate(ctx, &pb.RenewCertificateRequest{Domain: domain})
	_ = ctx

	return nil, errors.New("certificate renewal not implemented - requires gRPC service")
}

// ============================================================================
// Certificate Listing
// ============================================================================

// ListCertificates queries the certificate inventory
func (c *CertificateClient) ListCertificates(ctx context.Context, filter string, pageSize int) ([]CertificateSummary, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would call gRPC service
	// resp, err := c.grpcClient.ListCertificates(ctx, &pb.ListCertificatesRequest{...})
	_ = ctx
	_ = filter
	_ = pageSize

	return nil, errors.New("certificate listing not implemented - requires gRPC service")
}

// ============================================================================
// Watch for Changes
// ============================================================================

// ChangeEvent represents a certificate change notification
type ChangeEvent struct {
	Domain     string
	ChangeType string // "created", "updated", "deleted"
	Timestamp  time.Time
}

// ChangeHandler is called when certificate changes are detected
type ChangeHandler func(event ChangeEvent)

// WatchCertificateChanges subscribes to certificate change notifications
func (c *CertificateClient) WatchCertificateChanges(ctx context.Context, domainPattern string, handler ChangeHandler) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	ctx, cancel := context.WithCancel(ctx)
	c.watchCancel = cancel

	// In production, this would establish gRPC stream
	// stream, err := c.grpcClient.WatchCertificateChanges(ctx, &pb.WatchRequest{...})
	_ = ctx
	_ = domainPattern
	_ = handler

	return errors.New("watch not implemented - requires gRPC streaming")
}

// StopWatching stops watching for certificate changes
func (c *CertificateClient) StopWatching() {
	if c.watchCancel != nil {
		c.watchCancel()
	}
}

// ============================================================================
// Certificate Manager RPC Methods
// ============================================================================

// CertificateInfo contains CA distribution URLs and metadata.
type CertificateInfo struct {
	CAURL             string   `json:"ca_url"`
	InstallScriptURLs []string `json:"install_script_urls"`
	WPADURL           string   `json:"wpad_url"`
	CRLURL            string   `json:"crl_url"`
	OCSPURL           string   `json:"ocsp_url"`
	CAFingerprint     string   `json:"ca_fingerprint_sha256"`
}

// DeviceStatus contains device CA installation status.
type DeviceStatus struct {
	DeviceIP           string    `json:"device_ip"`
	MACAddress         string    `json:"mac_address"`
	CAInstalled        bool      `json:"ca_installed"`
	InstallationMethod string    `json:"installation_method"`
	DetectedAt         time.Time `json:"detected_at"`
}

// RevocationStatus contains certificate revocation status.
type RevocationStatus struct {
	IsRevoked        bool      `json:"is_revoked"`
	RevokedAt        time.Time `json:"revoked_at"`
	RevocationReason string    `json:"revocation_reason"`
}

// RevokeResponse contains revocation operation result.
type RevokeResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	CRLUpdatedAt time.Time `json:"crl_updated_at"`
}

// ListFilter for filtering certificate queries.
type ListFilter struct {
	CommonName      string    `json:"common_name"`
	IssuedAfter     time.Time `json:"issued_after"`
	IssuedBefore    time.Time `json:"issued_before"`
	CertificateType string    `json:"certificate_type"`
	Limit           int       `json:"limit"`
	Offset          int       `json:"offset"`
}

// CertificateList contains paginated certificate results.
type CertificateList struct {
	Certificates []CertificateSummary `json:"certificates"`
	TotalCount   int                  `json:"total_count"`
}

// CertificateDetailsResult contains full certificate metadata.
type CertificateDetailsResult struct {
	SerialNumber     string    `json:"serial_number"`
	CommonName       string    `json:"common_name"`
	SubjectAltNames  []string  `json:"subject_alt_names"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	IssuedAt         time.Time `json:"issued_at"`
	CertificatePEM   string    `json:"certificate_pem"`
	CertificateType  string    `json:"certificate_type"`
	Revoked          bool      `json:"revoked"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
}

// GetCertificateInfo retrieves CA distribution URLs for DHCP integration.
// This is the primary integration point for DHCP server.
func (c *CertificateClient) GetCertificateInfo(ctx context.Context) (*CertificateInfo, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.GetCertificateInfo(ctx, &pb.GetCertificateInfoRequest{})
	_ = ctx

	return nil, errors.New("GetCertificateInfo not implemented - requires gRPC connection")
}

// GetDeviceStatus queries the CA installation status of a device.
// At least one of ip or mac must be provided.
func (c *CertificateClient) GetDeviceStatus(ctx context.Context, ip, mac string) (*DeviceStatus, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if ip == "" && mac == "" {
		return nil, errors.New("at least one of IP or MAC address is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.GetDeviceStatus(ctx, &pb.DeviceStatusRequest{DeviceIp: ip, MacAddress: mac})
	_ = ctx

	return nil, errors.New("GetDeviceStatus not implemented - requires gRPC connection")
}

// SignCertificate requests a new certificate for the given domain and SANs.
// Used by TLS proxy for on-the-fly certificate generation.
func (c *CertificateClient) SignCertificate(ctx context.Context, domain string, sans []string) (*Certificate, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if !ValidateDomainName(domain) {
		return nil, ErrInvalidDomain
	}

	// Apply longer timeout for signing
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout*2)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.SignCertificate(ctx, &pb.SignCertificateRequest{
	//     CommonName: domain,
	//     SubjectAltNames: sans,
	// })
	_ = ctx
	_ = sans

	return nil, errors.New("SignCertificate not implemented - requires gRPC connection")
}

// RevokeCertificate revokes a certificate by serial number.
// Requires admin role.
func (c *CertificateClient) RevokeCertificate(ctx context.Context, serial, reason, revokedBy string) (*RevokeResponse, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if serial == "" {
		return nil, errors.New("serial number is required")
	}

	if revokedBy == "" {
		return nil, errors.New("revokedBy (administrator identifier) is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
	//     SerialNumber: serial,
	//     Reason: reason,
	//     RevokedBy: revokedBy,
	// })
	_ = ctx
	_ = reason

	return nil, errors.New("RevokeCertificate not implemented - requires gRPC connection")
}

// CheckRevocationStatus checks if a certificate is revoked.
// No authentication required (public method).
func (c *CertificateClient) CheckRevocationStatus(ctx context.Context, serial string) (*RevocationStatus, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if serial == "" {
		return nil, errors.New("serial number is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.CheckRevocationStatus(ctx, &pb.CheckRevocationStatusRequest{
	//     SerialNumber: serial,
	// })
	_ = ctx

	return nil, errors.New("CheckRevocationStatus not implemented - requires gRPC connection")
}

// ListIssuedCertificates queries the certificate inventory with filters.
func (c *CertificateClient) ListIssuedCertificates(ctx context.Context, filter *ListFilter) (*CertificateList, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	// Apply default limit if not specified
	if filter == nil {
		filter = &ListFilter{}
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.ListIssuedCertificates(ctx, &pb.ListIssuedCertificatesRequest{...})
	_ = ctx
	_ = filter

	return nil, errors.New("ListIssuedCertificates not implemented - requires gRPC connection")
}

// GetCertificateDetailsBySerial retrieves full certificate details by serial number.
func (c *CertificateClient) GetCertificateDetailsBySerial(ctx context.Context, serial string) (*CertificateDetailsResult, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	if serial == "" {
		return nil, errors.New("serial number is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// In production, this would use actual gRPC client:
	// resp, err := c.grpcClient.GetCertificateDetails(ctx, &pb.CertificateDetailsRequest{
	//     SerialNumber: serial,
	// })
	_ = ctx

	return nil, errors.New("GetCertificateDetailsBySerial not implemented - requires gRPC connection")
}

// ============================================================================
// Client Lifecycle
// ============================================================================

// Close shuts down the client and releases resources
func (c *CertificateClient) Close() error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	c.closed.Store(true)

	// Stop any active watches
	c.StopWatching()

	// Clear cache
	c.cacheMu.Lock()
	c.cache = make(map[string]*CachedCertificate)
	c.cacheMu.Unlock()

	// In production, close gRPC connection
	// c.grpcConn.Close()

	return nil
}

// IsConnected returns whether the client is connected
func (c *CertificateClient) IsConnected() bool {
	return c.connected.Load() && !c.closed.Load()
}

// ============================================================================
// Caching Logic
// ============================================================================

// getFromCache retrieves a certificate from cache if valid
func (c *CertificateClient) getFromCache(domain string) *Certificate {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	cached, exists := c.cache[domain]
	if !exists {
		return nil
	}

	// Check if cache entry is expired
	if time.Now().After(cached.ExpiresAt) {
		return nil
	}

	// Check if certificate itself is expired
	if time.Now().After(cached.Certificate.NotAfter) {
		return nil
	}

	return cached.Certificate
}

// addToCache adds a certificate to the cache
func (c *CertificateClient) addToCache(domain string, cert *Certificate) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Calculate cache TTL based on certificate validity
	validity := time.Until(cert.NotAfter)
	cacheTTL := time.Duration(float64(validity) * c.config.CacheTTLRatio)
	expiresAt := time.Now().Add(cacheTTL)

	// Evict if cache is too large
	if len(c.cache) >= MaxCacheSize {
		c.evictOldest()
	}

	c.cache[domain] = &CachedCertificate{
		Certificate: cert,
		CachedAt:    time.Now(),
		ExpiresAt:   expiresAt,
	}
}

// invalidateCache removes a domain from cache
func (c *CertificateClient) invalidateCache(domain string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	delete(c.cache, domain)
}

// evictOldest removes the oldest cache entry
func (c *CertificateClient) evictOldest() {
	var oldestDomain string
	var oldestTime time.Time

	for domain, entry := range c.cache {
		if oldestDomain == "" || entry.CachedAt.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = entry.CachedAt
		}
	}

	if oldestDomain != "" {
		delete(c.cache, oldestDomain)
	}
}

// ClearCache removes all entries from cache
func (c *CertificateClient) ClearCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = make(map[string]*CachedCertificate)
}

// ============================================================================
// Retry Logic
// ============================================================================

// calculateBackoff returns exponential backoff duration
func (c *CertificateClient) calculateBackoff(attempt int) time.Duration {
	backoff := c.config.RetryBackoff * time.Duration(1<<uint(attempt))
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return backoff
}

// isRetryable checks if error is temporary and can be retried
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	retryable := []string{"timeout", "unavailable", "connection", "temporary"}
	for _, pattern := range retryable {
		if containsStr(errStr, pattern) {
			return true
		}
	}
	return false
}

// ============================================================================
// Certificate Parsing Helpers
// ============================================================================

// TLSCertificate returns a tls.Certificate from the certificate data
func (cert *Certificate) TLSCertificate() (*tls.Certificate, error) {
	if cert.tlsCert != nil {
		return cert.tlsCert, nil
	}

	tlsCert, err := tls.X509KeyPair(
		[]byte(cert.CertificatePEM+cert.ChainPEM),
		[]byte(cert.PrivateKeyPEM),
	)
	if err != nil {
		return nil, err
	}

	cert.tlsCert = &tlsCert
	return cert.tlsCert, nil
}

// X509Certificate returns the parsed x509 certificate
func (cert *Certificate) X509Certificate() (*x509.Certificate, error) {
	if cert.x509Cert != nil {
		return cert.x509Cert, nil
	}

	parsed, err := ParsePEMCertificate(cert.CertificatePEM)
	if err != nil {
		return nil, err
	}

	cert.x509Cert = parsed
	return cert.x509Cert, nil
}

// PrivateKey returns the parsed private key
func (cert *Certificate) PrivateKey() (crypto.PrivateKey, error) {
	if cert.privateKey != nil {
		return cert.privateKey, nil
	}

	parsed, err := ParsePEMPrivateKey(cert.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	cert.privateKey = parsed
	return cert.privateKey, nil
}

// DaysUntilExpiry returns days until certificate expires
func (cert *Certificate) DaysUntilExpiry() int {
	return CalculateExpiry(cert.NotAfter)
}

// IsExpiring returns true if certificate expires within days
func (cert *Certificate) IsExpiring(days int) bool {
	return cert.DaysUntilExpiry() <= days
}

// ============================================================================
// Utility Functions
// ============================================================================

// ParsePEMCertificate parses a PEM-encoded certificate
func ParsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrInvalidCertificate
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// ParsePEMPrivateKey parses a PEM-encoded private key
func ParsePEMPrivateKey(pemData string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("unsupported private key type")
		}
	default:
		return nil, errors.New("unknown private key type: " + block.Type)
	}
}

// BuildTLSCertificate constructs a tls.Certificate from PEM data
func BuildTLSCertificate(certPEM, keyPEM, chainPEM string) (*tls.Certificate, error) {
	fullCert := certPEM
	if chainPEM != "" {
		fullCert += chainPEM
	}

	tlsCert, err := tls.X509KeyPair([]byte(fullCert), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

// ValidateDomainName checks if domain format is valid
func ValidateDomainName(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic validation - must have at least one dot, not start/end with dot
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}

	// Check for invalid characters
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '*') {
			return false
		}
	}

	// Must have at least one dot (except wildcards)
	hasDot := false
	for _, c := range domain {
		if c == '.' {
			hasDot = true
			break
		}
	}

	return hasDot
}

// CalculateExpiry returns days until certificate expires
func CalculateExpiry(notAfter time.Time) int {
	duration := time.Until(notAfter)
	days := int(duration.Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// containsStr checks if s contains substr
func containsStr(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
