// Package cert_integration provides CA certificate integration for DHCP server.
// This file generates URLs for CA certificate downloads and related services.
package cert_integration

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// ============================================================================
// URL Generator Configuration
// ============================================================================

// URLGeneratorConfig holds URL generation settings.
type URLGeneratorConfig struct {
	HTTPPort    int
	HTTPSPort   int
	OCSPPort    int
	PreferHTTPS bool

	// Custom paths
	CAPath     string
	WPADPath   string
	CRLPath    string
	OCSPPath   string
	ScriptPath string
}

// DefaultURLGeneratorConfig returns sensible defaults.
func DefaultURLGeneratorConfig() *URLGeneratorConfig {
	return &URLGeneratorConfig{
		HTTPPort:    8080,
		HTTPSPort:   8443,
		OCSPPort:    8888,
		PreferHTTPS: false,
		CAPath:      "/ca.crt",
		WPADPath:    "/wpad.dat",
		CRLPath:     "/crl.pem",
		OCSPPath:    "/ocsp",
		ScriptPath:  "/scripts",
	}
}

// ============================================================================
// Service Types
// ============================================================================

// ServiceType represents the type of certificate service.
type ServiceType int

const (
	ServiceCACert ServiceType = iota
	ServiceInstallScript
	ServiceWPAD
	ServiceCRL
	ServiceOCSP
)

// Platform represents client OS platform.
type Platform int

const (
	PlatformLinux Platform = iota
	PlatformWindows
	PlatformMacOS
	PlatformUnknown
)

// ============================================================================
// URL Generator
// ============================================================================

// URLGenerator generates URLs for certificate services.
type URLGenerator struct {
	mu     sync.RWMutex
	config *URLGeneratorConfig

	// Validation cache
	validatedURLs map[string]bool
	cacheMu       sync.RWMutex

	// Statistics
	stats URLGenStats
}

// URLGenStats tracks URL generation metrics.
type URLGenStats struct {
	Generated        int64
	ValidationPassed int64
	ValidationFailed int64
}

// NewURLGenerator creates a new URL generator.
func NewURLGenerator(config *URLGeneratorConfig) *URLGenerator {
	if config == nil {
		config = DefaultURLGeneratorConfig()
	}

	return &URLGenerator{
		config:        config,
		validatedURLs: make(map[string]bool),
	}
}

// ============================================================================
// Core URL Generation
// ============================================================================

// GenerateCAURL generates the CA certificate download URL.
func (g *URLGenerator) GenerateCAURL(gatewayIP net.IP) (string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return "", err
	}

	host := g.formatHost(gatewayIP, g.getPort())
	urlStr := fmt.Sprintf("%s://%s%s", g.getScheme(), host, g.config.CAPath)

	g.stats.Generated++
	return urlStr, nil
}

// GenerateWPADURL generates the WPAD configuration URL.
func (g *URLGenerator) GenerateWPADURL(gatewayIP net.IP) (string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return "", err
	}

	host := g.formatHost(gatewayIP, g.getPort())
	urlStr := fmt.Sprintf("%s://%s%s", g.getScheme(), host, g.config.WPADPath)

	g.stats.Generated++
	return urlStr, nil
}

// GenerateCRLURL generates the CRL download URL.
func (g *URLGenerator) GenerateCRLURL(gatewayIP net.IP) (string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return "", err
	}

	host := g.formatHost(gatewayIP, g.getPort())
	urlStr := fmt.Sprintf("%s://%s%s", g.getScheme(), host, g.config.CRLPath)

	g.stats.Generated++
	return urlStr, nil
}

// GenerateOCSPURL generates the OCSP responder URL.
func (g *URLGenerator) GenerateOCSPURL(gatewayIP net.IP) (string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return "", err
	}

	// OCSP uses its own port
	host := g.formatHost(gatewayIP, g.config.OCSPPort)
	urlStr := fmt.Sprintf("%s://%s%s", g.getScheme(), host, g.config.OCSPPath)

	g.stats.Generated++
	return urlStr, nil
}

// ============================================================================
// Install Script URLs
// ============================================================================

// GenerateInstallScriptURL generates a platform-specific install script URL.
func (g *URLGenerator) GenerateInstallScriptURL(gatewayIP net.IP, platform Platform) (string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return "", err
	}

	scriptName := g.getScriptName(platform)
	host := g.formatHost(gatewayIP, g.getPort())
	urlStr := fmt.Sprintf("%s://%s%s/%s", g.getScheme(), host, g.config.ScriptPath, scriptName)

	g.stats.Generated++
	return urlStr, nil
}

// GenerateAllInstallScriptURLs generates URLs for all platforms.
func (g *URLGenerator) GenerateAllInstallScriptURLs(gatewayIP net.IP) ([]string, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return nil, err
	}

	platforms := []Platform{PlatformLinux, PlatformWindows, PlatformMacOS}
	urls := make([]string, 0, len(platforms))

	for _, platform := range platforms {
		urlStr, err := g.GenerateInstallScriptURL(gatewayIP, platform)
		if err != nil {
			continue
		}
		urls = append(urls, urlStr)
	}

	return urls, nil
}

func (g *URLGenerator) getScriptName(platform Platform) string {
	switch platform {
	case PlatformLinux:
		return "install-ca.sh"
	case PlatformWindows:
		return "install-ca.ps1"
	case PlatformMacOS:
		return "install-ca.command"
	default:
		return "install-ca.sh"
	}
}

// ============================================================================
// Complete Certificate Info URLs
// ============================================================================

// GeneratedURLs holds all generated certificate-related URLs.
type GeneratedURLs struct {
	CAURL             string
	InstallScriptURLs []string
	WPADURL           string
	CRLURL            string
	OCSPURL           string
}

// GenerateAllURLs generates all certificate-related URLs.
func (g *URLGenerator) GenerateAllURLs(gatewayIP net.IP) (*GeneratedURLs, error) {
	if err := g.validateGatewayIP(gatewayIP); err != nil {
		return nil, err
	}

	result := &GeneratedURLs{}
	var err error

	// Generate CA URL
	result.CAURL, err = g.GenerateCAURL(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("CA URL: %w", err)
	}

	// Generate install script URLs
	result.InstallScriptURLs, err = g.GenerateAllInstallScriptURLs(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("script URLs: %w", err)
	}

	// Generate WPAD URL
	result.WPADURL, err = g.GenerateWPADURL(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("WPAD URL: %w", err)
	}

	// Generate CRL URL
	result.CRLURL, err = g.GenerateCRLURL(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("CRL URL: %w", err)
	}

	// Generate OCSP URL
	result.OCSPURL, err = g.GenerateOCSPURL(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("OCSP URL: %w", err)
	}

	return result, nil
}

// ============================================================================
// Template Variable Substitution
// ============================================================================

// TemplateVars holds template variable values.
type TemplateVars struct {
	Gateway string
	PoolID  string
	Subnet  string
	Domain  string
}

// SubstituteTemplate replaces template variables in a URL template.
func (g *URLGenerator) SubstituteTemplate(template string, vars *TemplateVars) string {
	result := template

	if vars.Gateway != "" {
		result = strings.ReplaceAll(result, "{gateway}", vars.Gateway)
	}
	if vars.PoolID != "" {
		result = strings.ReplaceAll(result, "{pool_id}", vars.PoolID)
	}
	if vars.Subnet != "" {
		result = strings.ReplaceAll(result, "{subnet}", vars.Subnet)
	}
	if vars.Domain != "" {
		result = strings.ReplaceAll(result, "{domain}", vars.Domain)
	}

	return result
}

// GenerateFromTemplate generates a URL from a template with variable substitution.
func (g *URLGenerator) GenerateFromTemplate(template string, gatewayIP net.IP, poolID, domain string) (string, error) {
	vars := &TemplateVars{
		Gateway: gatewayIP.String(),
		PoolID:  poolID,
		Domain:  domain,
	}

	urlStr := g.SubstituteTemplate(template, vars)

	// Validate the generated URL
	if _, err := url.Parse(urlStr); err != nil {
		return "", fmt.Errorf("invalid URL after substitution: %w", err)
	}

	return urlStr, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func (g *URLGenerator) validateGatewayIP(ip net.IP) error {
	if ip == nil {
		return ErrNilGatewayIP
	}

	if ip.IsUnspecified() {
		return ErrUnspecifiedGateway
	}

	if ip.IsLoopback() {
		// Allow loopback for development
	}

	return nil
}

func (g *URLGenerator) formatHost(ip net.IP, port int) string {
	// Check if IPv6
	if ip.To4() == nil {
		// IPv6 - needs brackets
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}

	// IPv4
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

func (g *URLGenerator) getScheme() string {
	if g.config.PreferHTTPS {
		return "https"
	}
	return "http"
}

func (g *URLGenerator) getPort() int {
	if g.config.PreferHTTPS {
		return g.config.HTTPSPort
	}
	return g.config.HTTPPort
}

// ============================================================================
// URL Validation
// ============================================================================

// ValidateURL checks if a URL is properly formatted.
func (g *URLGenerator) ValidateURL(urlStr string) error {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("URL parse error: %w", err)
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrInvalidScheme
	}

	// Check host
	if parsed.Host == "" {
		return ErrMissingHost
	}

	return nil
}

// ValidateAllURLs validates all URLs in GeneratedURLs.
func (g *URLGenerator) ValidateAllURLs(urls *GeneratedURLs) error {
	if err := g.ValidateURL(urls.CAURL); err != nil {
		return fmt.Errorf("CA URL invalid: %w", err)
	}

	for _, scriptURL := range urls.InstallScriptURLs {
		if err := g.ValidateURL(scriptURL); err != nil {
			return fmt.Errorf("script URL invalid: %w", err)
		}
	}

	if err := g.ValidateURL(urls.WPADURL); err != nil {
		return fmt.Errorf("WPAD URL invalid: %w", err)
	}

	if err := g.ValidateURL(urls.CRLURL); err != nil {
		return fmt.Errorf("CRL URL invalid: %w", err)
	}

	if err := g.ValidateURL(urls.OCSPURL); err != nil {
		return fmt.Errorf("OCSP URL invalid: %w", err)
	}

	return nil
}

// ============================================================================
// URL Truncation (DHCP Option Length Limit)
// ============================================================================

// MaxDHCPOptionLength is the maximum length for a single DHCP option value.
const MaxDHCPOptionLength = 255

// TruncateURL truncates a URL to fit within DHCP option length limits.
func (g *URLGenerator) TruncateURL(urlStr string) string {
	if len(urlStr) <= MaxDHCPOptionLength {
		return urlStr
	}
	return urlStr[:MaxDHCPOptionLength]
}

// TruncateURLs truncates all URLs in a slice.
func (g *URLGenerator) TruncateURLs(urls []string) []string {
	result := make([]string, len(urls))
	for i, u := range urls {
		result[i] = g.TruncateURL(u)
	}
	return result
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns URL generation statistics.
func (g *URLGenerator) GetStats() URLGenStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.stats
}

// ============================================================================
// Configuration Update
// ============================================================================

// UpdateConfig updates the URL generator configuration.
func (g *URLGenerator) UpdateConfig(config *URLGeneratorConfig) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.config = config
}

// GetConfig returns a copy of the current configuration.
func (g *URLGenerator) GetConfig() URLGeneratorConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return *g.config
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNilGatewayIP is returned when gateway IP is nil
	ErrNilGatewayIP = errors.New("gateway IP is nil")

	// ErrUnspecifiedGateway is returned for 0.0.0.0 or ::
	ErrUnspecifiedGateway = errors.New("gateway IP is unspecified (0.0.0.0 or ::)")

	// ErrInvalidScheme is returned for non-HTTP(S) schemes
	ErrInvalidScheme = errors.New("URL scheme must be http or https")

	// ErrMissingHost is returned when URL has no host
	ErrMissingHost = errors.New("URL is missing host")

	// ErrURLTooLong is returned when URL exceeds DHCP limits
	ErrURLTooLong = errors.New("URL exceeds DHCP option length limit")
)
