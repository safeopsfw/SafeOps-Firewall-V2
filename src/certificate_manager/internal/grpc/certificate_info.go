// Package grpc implements gRPC service handlers for the Certificate Manager.
package grpc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"certificate_manager/pkg/types"
)

// ============================================================================
// Certificate Info Response (mirrors proto CertificateInfoResponse)
// ============================================================================

// CertificateInfoResponse contains CA distribution information for DHCP integration.
// This mirrors the protobuf CertificateInfoResponse message.
type CertificateInfoResponse struct {
	// Primary CA certificate URLs
	CAURL    string `json:"ca_url"`
	CADerURL string `json:"ca_der_url"`

	// Platform-specific install script URLs
	InstallScriptURLs []string `json:"install_script_urls"`

	// Revocation URLs
	CRLURL  string `json:"crl_url"`
	OCSPURL string `json:"ocsp_url"`

	// CA certificate metadata
	CAFingerprintSHA256 string    `json:"ca_fingerprint_sha256"`
	CACommonName        string    `json:"ca_common_name"`
	CAValidUntil        time.Time `json:"ca_valid_until"`

	// Availability flag
	CAAvailable bool `json:"ca_available"`
}

// ============================================================================
// Certificate Info Handler
// ============================================================================

// CertificateInfoHandler handles GetCertificateInfo RPC requests.
// This is the primary integration point between DHCP server and Certificate Manager.
type CertificateInfoHandler struct {
	config *types.Config

	// Cache for CertificateInfo response
	cacheMu     sync.RWMutex
	cachedInfo  *CertificateInfoResponse
	cacheExpiry time.Time
	cacheTTL    time.Duration
}

// NewCertificateInfoHandler creates a new handler with configuration.
func NewCertificateInfoHandler(cfg *types.Config) *CertificateInfoHandler {
	return &CertificateInfoHandler{
		config:   cfg,
		cacheTTL: 1 * time.Hour, // Cache for 1 hour
	}
}

// GetCertificateInfo retrieves CA distribution information for DHCP integration.
// This is called by the DHCP server to retrieve CA distribution URLs
// for embedding into DHCP Option 224/225 responses.
func (h *CertificateInfoHandler) GetCertificateInfo() (*CertificateInfoResponse, error) {
	// Check cache first
	if cached := h.getCachedInfo(); cached != nil {
		log.Println("[CertInfo] Returning cached certificate info")
		return cached, nil
	}

	log.Println("[CertInfo] Building certificate info response for DHCP integration")

	// Build response from configuration
	response, err := h.buildCertificateInfo()
	if err != nil {
		log.Printf("[CertInfo] Failed to build certificate info: %v", err)
		// Return partial response rather than error - DHCP should still function
		return h.buildFallbackResponse(), nil
	}

	// Cache the response
	h.cacheInfo(response)

	return response, nil
}

// ============================================================================
// Response Building
// ============================================================================

// buildCertificateInfo constructs the CertificateInfoResponse from config.
func (h *CertificateInfoHandler) buildCertificateInfo() (*CertificateInfoResponse, error) {
	response := &CertificateInfoResponse{
		CAAvailable: false,
	}

	// Get HTTP server configuration for base URL
	baseURL := h.getBaseURL()
	if baseURL == "" {
		return nil, fmt.Errorf("base_url not configured")
	}

	// Build CA certificate URLs
	response.CAURL = baseURL + "/ca.crt"
	response.CADerURL = baseURL + "/ca.der"

	// Build install script URLs for all platforms
	response.InstallScriptURLs = h.buildInstallScriptURLs(baseURL)

	// Build revocation URLs (CRL and OCSP)
	h.addRevocationURLs(response, baseURL)

	// Load CA certificate information if available
	if err := h.loadCACertificateInfo(response); err != nil {
		log.Printf("[CertInfo] Warning: failed to load CA certificate info: %v", err)
		// Continue - CA might not be generated yet
	} else {
		response.CAAvailable = true
	}

	return response, nil
}

// getBaseURL returns the base URL for CA distribution HTTP server.
func (h *CertificateInfoHandler) getBaseURL() string {
	if h.config.HTTPServer == nil || !h.config.HTTPServer.Enabled {
		// Fallback to default SafeOps IP
		return "http://192.168.1.1"
	}

	// Check if base path is explicitly configured
	if h.config.HTTPServer.BasePath != "" {
		return h.config.HTTPServer.BasePath
	}

	// Determine scheme
	scheme := "http"
	if h.config.HTTPServer.TLSEnabled {
		scheme = "https"
	}

	// Get bind address (0.0.0.0 should use a configured IP)
	addr := h.config.HTTPServer.BindAddress
	if addr == "0.0.0.0" || addr == "" {
		addr = "192.168.1.1" // Default SafeOps firewall IP
	}

	port := h.config.HTTPServer.Port
	if port == 0 {
		port = 80
	}

	// Don't include port if using default for scheme
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, addr)
	}

	return fmt.Sprintf("%s://%s:%d", scheme, addr, port)
}

// buildInstallScriptURLs constructs URLs for platform-specific install scripts.
func (h *CertificateInfoHandler) buildInstallScriptURLs(baseURL string) []string {
	return []string{
		baseURL + "/install-ca.sh",           // Linux bash script
		baseURL + "/install-ca.ps1",          // Windows PowerShell
		baseURL + "/install-ca.pkg",          // macOS package
		baseURL + "/install-ca.mobileconfig", // iOS/iPadOS configuration profile
		baseURL + "/trust-guide.html",        // Android/general instructions
	}
}

// addRevocationURLs adds CRL and OCSP URLs to the response.
func (h *CertificateInfoHandler) addRevocationURLs(response *CertificateInfoResponse, baseURL string) {
	// CRL URL
	if h.config.CRL != nil && h.config.CRL.Enabled {
		if h.config.CRL.CRLURL != "" {
			response.CRLURL = h.config.CRL.CRLURL
		} else {
			// Construct from base URL
			response.CRLURL = baseURL + "/crl.pem"
		}
	}

	// OCSP URL
	if h.config.OCSP != nil && h.config.OCSP.Enabled {
		if h.config.OCSP.OCSPURL != "" {
			response.OCSPURL = h.config.OCSP.OCSPURL
		} else {
			// Construct from OCSP bind address and port
			addr := h.config.OCSP.BindAddress
			if addr == "" || addr == "0.0.0.0" {
				addr = "192.168.1.1"
			}
			port := h.config.OCSP.Port
			if port == 0 {
				port = 8888
			}
			response.OCSPURL = fmt.Sprintf("http://%s:%d", addr, port)
		}
	}
}

// loadCACertificateInfo reads the CA certificate and populates metadata.
func (h *CertificateInfoHandler) loadCACertificateInfo(response *CertificateInfoResponse) error {
	if h.config.CA == nil {
		return fmt.Errorf("CA configuration not found")
	}

	certPath := h.config.CA.CACertPath
	if certPath == "" {
		return fmt.Errorf("CA certificate path not configured")
	}

	// Read CA certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Calculate SHA-256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	response.CAFingerprintSHA256 = formatFingerprint(fingerprint[:])

	// Set common name
	response.CACommonName = cert.Subject.CommonName

	// Set expiry
	response.CAValidUntil = cert.NotAfter

	log.Printf("[CertInfo] Loaded CA certificate: CN=%s, expires=%s, fingerprint=%s...",
		cert.Subject.CommonName,
		cert.NotAfter.Format(time.RFC3339),
		response.CAFingerprintSHA256[:20],
	)

	return nil
}

// formatFingerprint formats a certificate fingerprint as colon-separated hex.
func formatFingerprint(fp []byte) string {
	hexStr := hex.EncodeToString(fp)
	result := ""
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result += ":"
		}
		result += hexStr[i : i+2]
	}
	return result
}

// buildFallbackResponse returns a minimal response when config is incomplete.
func (h *CertificateInfoHandler) buildFallbackResponse() *CertificateInfoResponse {
	return &CertificateInfoResponse{
		CAURL:             "",
		CADerURL:          "",
		InstallScriptURLs: []string{},
		CRLURL:            "",
		OCSPURL:           "",
		CAAvailable:       false,
	}
}

// ============================================================================
// Response Caching
// ============================================================================

// getCachedInfo returns cached CertificateInfo if valid, nil otherwise.
func (h *CertificateInfoHandler) getCachedInfo() *CertificateInfoResponse {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()

	if h.cachedInfo == nil {
		return nil
	}

	if time.Now().After(h.cacheExpiry) {
		return nil
	}

	return h.cachedInfo
}

// cacheInfo stores the CertificateInfo response in cache.
func (h *CertificateInfoHandler) cacheInfo(info *CertificateInfoResponse) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	h.cachedInfo = info
	h.cacheExpiry = time.Now().Add(h.cacheTTL)

	log.Printf("[CertInfo] Cached certificate info, TTL=%v", h.cacheTTL)
}

// InvalidateCache clears the cached CertificateInfo response.
// Called when configuration is reloaded.
func (h *CertificateInfoHandler) InvalidateCache() {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	h.cachedInfo = nil
	h.cacheExpiry = time.Time{}

	log.Println("[CertInfo] Cache invalidated")
}

// SetCacheTTL updates the cache TTL duration.
func (h *CertificateInfoHandler) SetCacheTTL(ttl time.Duration) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	h.cacheTTL = ttl
}

// ============================================================================
// Configuration Updates
// ============================================================================

// UpdateConfig updates the handler's configuration reference.
// This should be called when configuration is hot-reloaded.
func (h *CertificateInfoHandler) UpdateConfig(cfg *types.Config) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	h.config = cfg
	// Invalidate cache since config changed
	h.cachedInfo = nil
	h.cacheExpiry = time.Time{}

	log.Println("[CertInfo] Config updated, cache invalidated")
}

// ============================================================================
// DHCP Integration Helpers
// ============================================================================

// GetDHCPOption224Value returns the CA URL for DHCP Option 224.
func (h *CertificateInfoHandler) GetDHCPOption224Value() string {
	info, _ := h.GetCertificateInfo()
	if info == nil {
		return ""
	}
	return info.CAURL
}

// GetDHCPOption225Value returns install script URLs for DHCP Option 225.
// Returns as comma-separated string for DHCP option embedding.
func (h *CertificateInfoHandler) GetDHCPOption225Value() string {
	info, _ := h.GetCertificateInfo()
	if info == nil || len(info.InstallScriptURLs) == 0 {
		return ""
	}

	// Join URLs with comma separator
	result := ""
	for i, url := range info.InstallScriptURLs {
		if i > 0 {
			result += ","
		}
		result += url
	}
	return result
}

// GetCAFingerprint returns the SHA-256 fingerprint for DHCP Option 227.
func (h *CertificateInfoHandler) GetCAFingerprint() string {
	info, _ := h.GetCertificateInfo()
	if info == nil {
		return ""
	}
	return info.CAFingerprintSHA256
}
