// Package cert_integration provides CA certificate integration for DHCP server.
// This file builds DHCP options 224, 225, 252 for CA certificate distribution.
package cert_integration

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
)

// ============================================================================
// DHCP Option Codes for CA Certificate Distribution
// ============================================================================

const (
	// OptionCAURL is option 224 - CA certificate download URL
	OptionCAURL = 224

	// OptionInstallScripts is option 225 - Installation script URLs
	OptionInstallScripts = 225

	// OptionCRLURL is option 226 - CRL distribution point URL
	OptionCRLURL = 226

	// OptionOCSPURL is option 227 - OCSP responder URL
	OptionOCSPURL = 227

	// OptionWPAD is option 252 - WPAD configuration URL
	OptionWPAD = 252

	// MaxOptionDataLength is the maximum data length per RFC 2132
	MaxOptionDataLength = 255
)

// ============================================================================
// Option Builder Configuration
// ============================================================================

// OptionBuilderConfig holds option builder settings.
type OptionBuilderConfig struct {
	EnableOption224 bool
	EnableOption225 bool
	EnableOption252 bool
	EnableOption226 bool
	EnableOption227 bool
	ValidateURLs    bool
	FallbackCAURL   string
}

// DefaultOptionBuilderConfig returns sensible defaults.
func DefaultOptionBuilderConfig() *OptionBuilderConfig {
	return &OptionBuilderConfig{
		EnableOption224: true,
		EnableOption225: true,
		EnableOption252: true,
		EnableOption226: true,
		EnableOption227: true,
		ValidateURLs:    true,
	}
}

// ============================================================================
// Encoded DHCP Option
// ============================================================================

// EncodedOption represents a single encoded DHCP option.
type EncodedOption struct {
	Code   byte
	Length byte
	Data   []byte
}

// Bytes returns the wire format of the option.
func (o *EncodedOption) Bytes() []byte {
	result := make([]byte, 2+len(o.Data))
	result[0] = o.Code
	result[1] = o.Length
	copy(result[2:], o.Data)
	return result
}

// CAOptionList holds all CA-related DHCP options.
type CAOptionList struct {
	Options []*EncodedOption
}

// Bytes returns all options concatenated.
func (l *CAOptionList) Bytes() []byte {
	var result []byte
	for _, opt := range l.Options {
		result = append(result, opt.Bytes()...)
	}
	return result
}

// HasOption checks if a specific option is present.
func (l *CAOptionList) HasOption(code byte) bool {
	for _, opt := range l.Options {
		if opt.Code == code {
			return true
		}
	}
	return false
}

// ============================================================================
// Option Builder Interface
// ============================================================================

// OptionBuilder defines the interface for CA option construction.
type OptionBuilder interface {
	BuildCACertOptions(ctx context.Context, gatewayIP net.IP) (*CAOptionList, error)
}

// ============================================================================
// CA Option Builder Implementation
// ============================================================================

// CAOptionBuilder constructs CA certificate DHCP options.
type CAOptionBuilder struct {
	mu       sync.RWMutex
	config   *OptionBuilderConfig
	provider CACertProvider
	urlGen   *URLGenerator

	// Statistics
	stats OptionBuilderStats
}

// OptionBuilderStats tracks option builder metrics.
type OptionBuilderStats struct {
	TotalBuilds        int64
	SuccessfulBuilds   int64
	PartialBuilds      int64
	FailedBuilds       int64
	Option224Count     int64
	Option225Count     int64
	Option252Count     int64
	ValidationFailures int64
}

// NewCAOptionBuilder creates a new CA option builder.
func NewCAOptionBuilder(config *OptionBuilderConfig, provider CACertProvider) *CAOptionBuilder {
	if config == nil {
		config = DefaultOptionBuilderConfig()
	}

	return &CAOptionBuilder{
		config:   config,
		provider: provider,
		urlGen:   NewURLGenerator(nil),
	}
}

// SetProvider sets the CA certificate provider.
func (b *CAOptionBuilder) SetProvider(provider CACertProvider) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.provider = provider
}

// SetURLGenerator sets the URL generator.
func (b *CAOptionBuilder) SetURLGenerator(urlGen *URLGenerator) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.urlGen = urlGen
}

// ============================================================================
// Main Build Function
// ============================================================================

// BuildCACertOptions builds all CA certificate DHCP options.
func (b *CAOptionBuilder) BuildCACertOptions(ctx context.Context, gatewayIP net.IP) (*CAOptionList, error) {
	b.mu.Lock()
	b.stats.TotalBuilds++
	b.mu.Unlock()

	optionList := &CAOptionList{
		Options: make([]*EncodedOption, 0, 5),
	}

	// Get certificate info from provider
	var certInfo *CertificateInfo
	var err error

	b.mu.RLock()
	provider := b.provider
	b.mu.RUnlock()

	if provider != nil {
		certInfo, err = provider.GetCertificateInfo(ctx, gatewayIP)
		if err != nil {
			// Try fallback
			certInfo = b.createFallbackInfo(gatewayIP)
		}
	} else {
		certInfo = b.createFallbackInfo(gatewayIP)
	}

	if certInfo == nil {
		b.stats.FailedBuilds++
		return optionList, nil
	}

	// Build Option 224 - CA Certificate URL
	if b.config.EnableOption224 && certInfo.CAURL != "" {
		opt, err := b.buildOption224(certInfo.CAURL)
		if err == nil {
			optionList.Options = append(optionList.Options, opt)
			b.stats.Option224Count++
		} else {
			b.stats.ValidationFailures++
		}
	}

	// Build Option 225 - Install Script URLs
	if b.config.EnableOption225 && len(certInfo.InstallScriptURLs) > 0 {
		opt, err := b.buildOption225(certInfo.InstallScriptURLs)
		if err == nil {
			optionList.Options = append(optionList.Options, opt)
			b.stats.Option225Count++
		} else {
			b.stats.ValidationFailures++
		}
	}

	// Build Option 252 - WPAD URL
	if b.config.EnableOption252 && certInfo.WPADURL != "" {
		opt, err := b.buildOption252(certInfo.WPADURL)
		if err == nil {
			optionList.Options = append(optionList.Options, opt)
			b.stats.Option252Count++
		} else {
			b.stats.ValidationFailures++
		}
	}

	// Build Option 226 - CRL URL
	if b.config.EnableOption226 && certInfo.CRLURL != "" {
		opt, err := b.buildOption226(certInfo.CRLURL)
		if err == nil {
			optionList.Options = append(optionList.Options, opt)
		}
	}

	// Build Option 227 - OCSP URL
	if b.config.EnableOption227 && certInfo.OCSPURL != "" {
		opt, err := b.buildOption227(certInfo.OCSPURL)
		if err == nil {
			optionList.Options = append(optionList.Options, opt)
		}
	}

	// Track build result
	if len(optionList.Options) == 0 {
		b.stats.FailedBuilds++
	} else if len(optionList.Options) < 3 {
		b.stats.PartialBuilds++
	} else {
		b.stats.SuccessfulBuilds++
	}

	return optionList, nil
}

// ============================================================================
// Individual Option Builders
// ============================================================================

// buildOption224 builds the CA certificate URL option.
func (b *CAOptionBuilder) buildOption224(caURL string) (*EncodedOption, error) {
	if err := b.validateURL(caURL); err != nil {
		return nil, err
	}

	data := []byte(caURL)
	if len(data) > MaxOptionDataLength {
		return nil, ErrOptionDataTooLong
	}

	return &EncodedOption{
		Code:   OptionCAURL,
		Length: byte(len(data)),
		Data:   data,
	}, nil
}

// buildOption225 builds the installation script URLs option.
func (b *CAOptionBuilder) buildOption225(scriptURLs []string) (*EncodedOption, error) {
	// Validate all URLs
	validURLs := make([]string, 0, len(scriptURLs))
	for _, u := range scriptURLs {
		if err := b.validateURL(u); err == nil {
			validURLs = append(validURLs, u)
		}
	}

	if len(validURLs) == 0 {
		return nil, ErrNoValidURLs
	}

	// Join with comma separator
	combined := strings.Join(validURLs, ",")

	// Truncate if necessary
	if len(combined) > MaxOptionDataLength {
		combined = b.truncateURLList(validURLs, MaxOptionDataLength)
	}

	data := []byte(combined)

	return &EncodedOption{
		Code:   OptionInstallScripts,
		Length: byte(len(data)),
		Data:   data,
	}, nil
}

// buildOption252 builds the WPAD URL option.
func (b *CAOptionBuilder) buildOption252(wpadURL string) (*EncodedOption, error) {
	if err := b.validateURL(wpadURL); err != nil {
		return nil, err
	}

	data := []byte(wpadURL)
	if len(data) > MaxOptionDataLength {
		return nil, ErrOptionDataTooLong
	}

	return &EncodedOption{
		Code:   OptionWPAD,
		Length: byte(len(data)),
		Data:   data,
	}, nil
}

// buildOption226 builds the CRL URL option.
func (b *CAOptionBuilder) buildOption226(crlURL string) (*EncodedOption, error) {
	if err := b.validateURL(crlURL); err != nil {
		return nil, err
	}

	data := []byte(crlURL)
	if len(data) > MaxOptionDataLength {
		return nil, ErrOptionDataTooLong
	}

	return &EncodedOption{
		Code:   OptionCRLURL,
		Length: byte(len(data)),
		Data:   data,
	}, nil
}

// buildOption227 builds the OCSP URL option.
func (b *CAOptionBuilder) buildOption227(ocspURL string) (*EncodedOption, error) {
	if err := b.validateURL(ocspURL); err != nil {
		return nil, err
	}

	data := []byte(ocspURL)
	if len(data) > MaxOptionDataLength {
		return nil, ErrOptionDataTooLong
	}

	return &EncodedOption{
		Code:   OptionOCSPURL,
		Length: byte(len(data)),
		Data:   data,
	}, nil
}

// ============================================================================
// URL Validation and Sanitization
// ============================================================================

func (b *CAOptionBuilder) validateURL(urlStr string) error {
	if urlStr == "" {
		return ErrEmptyURL
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ErrInvalidURLFormat
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrUnsafeScheme
	}

	// Check for credentials in URL (security risk)
	if parsed.User != nil {
		return ErrCredentialsInURL
	}

	// Check host is present
	if parsed.Host == "" {
		return ErrMissingHostInURL
	}

	return nil
}

func (b *CAOptionBuilder) truncateURLList(urls []string, maxLen int) string {
	var result strings.Builder
	first := true

	for _, u := range urls {
		prefix := ""
		if !first {
			prefix = ","
		}

		if result.Len()+len(prefix)+len(u) > maxLen {
			break
		}

		result.WriteString(prefix)
		result.WriteString(u)
		first = false
	}

	return result.String()
}

// ============================================================================
// Fallback Info
// ============================================================================

func (b *CAOptionBuilder) createFallbackInfo(gatewayIP net.IP) *CertificateInfo {
	if b.config.FallbackCAURL != "" {
		return &CertificateInfo{
			CAURL: b.config.FallbackCAURL,
		}
	}

	// Generate URLs from gateway IP
	if b.urlGen != nil && gatewayIP != nil {
		urls, err := b.urlGen.GenerateAllURLs(gatewayIP)
		if err == nil {
			return &CertificateInfo{
				CAURL:             urls.CAURL,
				InstallScriptURLs: urls.InstallScriptURLs,
				WPADURL:           urls.WPADURL,
				CRLURL:            urls.CRLURL,
				OCSPURL:           urls.OCSPURL,
			}
		}
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns option builder statistics.
func (b *CAOptionBuilder) GetStats() OptionBuilderStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stats
}

// GetOption224InclusionRate returns percentage of builds including option 224.
func (b *CAOptionBuilder) GetOption224InclusionRate() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.stats.TotalBuilds == 0 {
		return 0
	}
	return float64(b.stats.Option224Count) / float64(b.stats.TotalBuilds) * 100
}

// ============================================================================
// Mock Option Builder for Testing
// ============================================================================

// MockOptionBuilder is a mock implementation for testing.
type MockOptionBuilder struct {
	mu         sync.RWMutex
	mockResult *CAOptionList
	mockError  error
	callCount  int
}

// NewMockOptionBuilder creates a mock option builder.
func NewMockOptionBuilder() *MockOptionBuilder {
	return &MockOptionBuilder{
		mockResult: &CAOptionList{
			Options: []*EncodedOption{
				{Code: OptionCAURL, Length: 30, Data: []byte("http://192.168.1.1:8080/ca.crt")},
				{Code: OptionWPAD, Length: 32, Data: []byte("http://192.168.1.1:8080/wpad.dat")},
			},
		},
	}
}

// SetResult sets the mock result.
func (m *MockOptionBuilder) SetResult(result *CAOptionList) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockResult = result
}

// SetError sets the mock error.
func (m *MockOptionBuilder) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockError = err
}

// BuildCACertOptions returns mock result.
func (m *MockOptionBuilder) BuildCACertOptions(ctx context.Context, gatewayIP net.IP) (*CAOptionList, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mockError != nil {
		return nil, m.mockError
	}
	return m.mockResult, nil
}

// GetCallCount returns number of calls.
func (m *MockOptionBuilder) GetCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCount
}

// ============================================================================
// Option Decoding (for Testing/Debugging)
// ============================================================================

// DecodeOption decodes a DHCP option from bytes.
func DecodeOption(data []byte) (*EncodedOption, error) {
	if len(data) < 2 {
		return nil, errors.New("option data too short")
	}

	code := data[0]
	length := data[1]

	if len(data) < int(2+length) {
		return nil, errors.New("option data length mismatch")
	}

	return &EncodedOption{
		Code:   code,
		Length: length,
		Data:   data[2 : 2+length],
	}, nil
}

// DecodeOptionString decodes option data as string.
func DecodeOptionString(opt *EncodedOption) string {
	return string(opt.Data)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrOptionDataTooLong is returned when option exceeds 255 bytes
	ErrOptionDataTooLong = errors.New("option data exceeds 255 byte limit")

	// ErrEmptyURL is returned for empty URL
	ErrEmptyURL = errors.New("URL is empty")

	// ErrInvalidURLFormat is returned for malformed URLs
	ErrInvalidURLFormat = errors.New("invalid URL format")

	// ErrUnsafeScheme is returned for non-HTTP(S) schemes
	ErrUnsafeScheme = errors.New("URL scheme must be http or https")

	// ErrCredentialsInURL is returned when URL contains credentials
	ErrCredentialsInURL = errors.New("URL must not contain credentials")

	// ErrMissingHostInURL is returned when URL has no host
	ErrMissingHostInURL = errors.New("URL is missing host")

	// ErrNoValidURLs is returned when no URLs pass validation
	ErrNoValidURLs = errors.New("no valid URLs provided")
)
