// Package dns_integration provides DNS integration for DHCP server.
// This file implements hostname extraction and mapping from DHCP packets.
package dns_integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// ============================================================================
// Hostname Mapper Configuration
// ============================================================================

// HostnameMapperConfig holds hostname processing settings.
type HostnameMapperConfig struct {
	FallbackPrefix    string
	MaxLength         int
	AllowUnderscores  bool
	CheckUniqueness   bool
	MaxSuffixAttempts int
	EnableIDN         bool
	DefaultDomain     string
}

// DefaultHostnameMapperConfig returns sensible defaults.
func DefaultHostnameMapperConfig() *HostnameMapperConfig {
	return &HostnameMapperConfig{
		FallbackPrefix:    "dhcp",
		MaxLength:         63,
		AllowUnderscores:  false,
		CheckUniqueness:   true,
		MaxSuffixAttempts: 100,
		EnableIDN:         true,
		DefaultDomain:     "local",
	}
}

// ============================================================================
// DHCP Option Codes
// ============================================================================

const (
	// DHCPOptionHostname is option 12 - Hostname
	DHCPOptionHostname = 12
	// DHCPOptionDomainName is option 15 - Domain Name
	DHCPOptionDomainName = 15
	// DHCPOptionClientFQDN is option 81 - Client FQDN
	DHCPOptionClientFQDN = 81
)

// ============================================================================
// Hostname Source Tracking
// ============================================================================

// HostnameSource indicates where hostname was obtained from.
type HostnameSource int

const (
	// SourceUnknown indicates unknown source
	SourceUnknown HostnameSource = iota
	// SourceOption12 indicates hostname from option 12
	SourceOption12
	// SourceOption81 indicates hostname from option 81 (FQDN)
	SourceOption81
	// SourceGenerated indicates hostname was generated from MAC
	SourceGenerated
)

func (s HostnameSource) String() string {
	switch s {
	case SourceOption12:
		return "option12"
	case SourceOption81:
		return "option81"
	case SourceGenerated:
		return "generated"
	default:
		return "unknown"
	}
}

// ============================================================================
// Hostname Result
// ============================================================================

// HostnameResult contains extracted and processed hostname.
type HostnameResult struct {
	Hostname   string
	FQDN       string
	Domain     string
	Source     HostnameSource
	Normalized bool
	Original   string
}

// ============================================================================
// Lease Repository Interface
// ============================================================================

// HostnameLeaseRepository defines lease operations for hostname mapping.
type HostnameLeaseRepository interface {
	GetHostnameByMAC(ctx context.Context, mac net.HardwareAddr) (string, error)
	GetMACByHostname(ctx context.Context, hostname string) (net.HardwareAddr, error)
	HostnameExists(ctx context.Context, hostname string, excludeMAC net.HardwareAddr) (bool, error)
}

// ============================================================================
// Hostname Mapper
// ============================================================================

// HostnameMapper extracts and processes hostnames from DHCP packets.
type HostnameMapper struct {
	mu        sync.RWMutex
	config    *HostnameMapperConfig
	leaseRepo HostnameLeaseRepository

	// Hostname cache
	hostnameCache map[string]string // MAC -> hostname
	cacheMu       sync.RWMutex

	// Statistics
	stats HostnameMapperStats

	// Validation regex
	validLabelRegex *regexp.Regexp
}

// HostnameMapperStats tracks hostname processing metrics.
type HostnameMapperStats struct {
	FromOption12    int64
	FromOption81    int64
	Generated       int64
	Normalized      int64
	Truncated       int64
	ConflictsFound  int64
	ValidationFails int64
	CacheHits       int64
	CacheMisses     int64
}

// ============================================================================
// Mapper Creation
// ============================================================================

// NewHostnameMapper creates a new hostname mapper.
func NewHostnameMapper(config *HostnameMapperConfig) *HostnameMapper {
	if config == nil {
		config = DefaultHostnameMapperConfig()
	}

	return &HostnameMapper{
		config:          config,
		hostnameCache:   make(map[string]string),
		validLabelRegex: regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`),
	}
}

// SetLeaseRepository sets the lease repository.
func (m *HostnameMapper) SetLeaseRepository(repo HostnameLeaseRepository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaseRepo = repo
}

// ============================================================================
// Main Extraction Function
// ============================================================================

// ExtractHostname extracts and processes hostname from DHCP options.
func (m *HostnameMapper) ExtractHostname(ctx context.Context, options map[byte][]byte, mac net.HardwareAddr, domain string) (*HostnameResult, error) {
	result := &HostnameResult{
		Domain: domain,
	}

	if domain == "" {
		domain = m.config.DefaultDomain
		result.Domain = domain
	}

	// Check cache first
	if cached := m.getCachedHostname(mac); cached != "" {
		result.Hostname = cached
		result.Source = SourceUnknown
		result.FQDN = m.constructFQDN(cached, domain)
		m.stats.CacheHits++
		return result, nil
	}
	m.stats.CacheMisses++

	// Priority 1: Option 81 (Client FQDN)
	if option81, ok := options[DHCPOptionClientFQDN]; ok && len(option81) > 3 {
		hostname := m.parseOption81(option81)
		if hostname != "" {
			result.Original = hostname
			result.Hostname = m.normalize(hostname)
			result.Source = SourceOption81
			result.Normalized = result.Original != result.Hostname
			m.stats.FromOption81++
		}
	}

	// Priority 2: Option 12 (Hostname)
	if result.Hostname == "" {
		if option12, ok := options[DHCPOptionHostname]; ok && len(option12) > 0 {
			hostname := string(option12)
			result.Original = hostname
			result.Hostname = m.normalize(hostname)
			result.Source = SourceOption12
			result.Normalized = result.Original != result.Hostname
			m.stats.FromOption12++
		}
	}

	// Priority 3: Generate from MAC
	if result.Hostname == "" {
		result.Hostname = m.generateFromMAC(mac)
		result.Source = SourceGenerated
		result.Original = result.Hostname
		m.stats.Generated++
	}

	// Validate hostname
	if err := m.validate(result.Hostname); err != nil {
		// Regenerate if validation fails
		result.Hostname = m.generateFromMAC(mac)
		result.Source = SourceGenerated
		m.stats.ValidationFails++
	}

	// Check uniqueness if enabled
	if m.config.CheckUniqueness {
		unique, err := m.ensureUnique(ctx, result.Hostname, mac)
		if err == nil {
			result.Hostname = unique
		}
	}

	// Construct FQDN
	result.FQDN = m.constructFQDN(result.Hostname, domain)

	// Cache the result
	m.cacheHostname(mac, result.Hostname)

	return result, nil
}

// ============================================================================
// Option 81 (FQDN) Parsing
// ============================================================================

func (m *HostnameMapper) parseOption81(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Flags byte
	flags := data[0]
	// RCODE1 and RCODE2 reserved
	// Domain name starts at byte 3

	// E flag (bit 2) indicates DNS encoding
	eFlag := (flags & 0x04) != 0

	domainData := data[3:]
	if len(domainData) == 0 {
		return ""
	}

	if eFlag {
		// DNS label encoding
		return m.decodeDNSLabels(domainData)
	}

	// ASCII encoding
	return strings.TrimSpace(string(domainData))
}

func (m *HostnameMapper) decodeDNSLabels(data []byte) string {
	var labels []string
	offset := 0

	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			break
		}

		offset++
		if offset+labelLen > len(data) {
			break
		}

		label := string(data[offset : offset+labelLen])
		labels = append(labels, label)
		offset += labelLen
	}

	return strings.Join(labels, ".")
}

// ============================================================================
// Hostname Normalization
// ============================================================================

func (m *HostnameMapper) normalize(hostname string) string {
	if hostname == "" {
		return ""
	}

	// Convert to lowercase
	hostname = strings.ToLower(hostname)

	// Replace spaces with hyphens
	hostname = strings.ReplaceAll(hostname, " ", "-")

	// Replace underscores with hyphens if not allowed
	if !m.config.AllowUnderscores {
		hostname = strings.ReplaceAll(hostname, "_", "-")
	}

	// Remove invalid characters
	var sb strings.Builder
	for _, ch := range hostname {
		if isValidDNSChar(ch, m.config.AllowUnderscores) {
			sb.WriteRune(ch)
		}
	}
	hostname = sb.String()

	// Replace consecutive hyphens
	for strings.Contains(hostname, "--") {
		hostname = strings.ReplaceAll(hostname, "--", "-")
	}

	// Remove leading/trailing hyphens and dots
	hostname = strings.Trim(hostname, "-.")

	// Truncate if too long
	if len(hostname) > m.config.MaxLength {
		hostname = hostname[:m.config.MaxLength]
		hostname = strings.TrimRight(hostname, "-")
		m.stats.Truncated++
	}

	if hostname != "" {
		m.stats.Normalized++
	}

	return hostname
}

func isValidDNSChar(ch rune, allowUnderscore bool) bool {
	if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
		return true
	}
	if ch == '-' {
		return true
	}
	if ch == '.' {
		return true
	}
	if allowUnderscore && ch == '_' {
		return true
	}
	return false
}

// ============================================================================
// Domain Suffix
// ============================================================================

func (m *HostnameMapper) constructFQDN(hostname, domain string) string {
	if hostname == "" {
		return ""
	}

	// Check if already FQDN
	if strings.Contains(hostname, ".") {
		// Already has domain part
		return strings.TrimSuffix(hostname, ".")
	}

	if domain == "" {
		domain = m.config.DefaultDomain
	}

	fqdn := hostname + "." + domain

	// Validate total length
	if len(fqdn) > 253 {
		// Truncate hostname to fit
		maxHostLen := 253 - len(domain) - 1
		if maxHostLen > 0 && maxHostLen < len(hostname) {
			hostname = hostname[:maxHostLen]
			hostname = strings.TrimRight(hostname, "-")
			fqdn = hostname + "." + domain
		}
	}

	return fqdn
}

// ============================================================================
// Fallback Generation
// ============================================================================

func (m *HostnameMapper) generateFromMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return m.config.FallbackPrefix + "-unknown"
	}

	// Format: dhcp-aabbccddeeff
	macStr := strings.ToLower(strings.ReplaceAll(mac.String(), ":", ""))
	macStr = strings.ReplaceAll(macStr, "-", "")

	hostname := fmt.Sprintf("%s-%s", m.config.FallbackPrefix, macStr)

	// Ensure it fits in max length
	if len(hostname) > m.config.MaxLength {
		hostname = hostname[:m.config.MaxLength]
	}

	return hostname
}

// ============================================================================
// Uniqueness Checking
// ============================================================================

func (m *HostnameMapper) ensureUnique(ctx context.Context, hostname string, mac net.HardwareAddr) (string, error) {
	m.mu.RLock()
	repo := m.leaseRepo
	m.mu.RUnlock()

	if repo == nil {
		return hostname, nil
	}

	// Check if hostname exists for different MAC
	exists, err := repo.HostnameExists(ctx, hostname, mac)
	if err != nil {
		return hostname, err
	}

	if !exists {
		return hostname, nil
	}

	// Append suffix to make unique
	m.stats.ConflictsFound++

	for suffix := 2; suffix <= m.config.MaxSuffixAttempts; suffix++ {
		candidate := fmt.Sprintf("%s-%d", hostname, suffix)

		// Truncate if needed
		if len(candidate) > m.config.MaxLength {
			// Shorten base hostname
			suffixStr := fmt.Sprintf("-%d", suffix)
			baseLen := m.config.MaxLength - len(suffixStr)
			if baseLen < 1 {
				continue
			}
			candidate = hostname[:baseLen] + suffixStr
		}

		exists, err = repo.HostnameExists(ctx, candidate, mac)
		if err != nil {
			continue
		}

		if !exists {
			return candidate, nil
		}
	}

	return hostname, ErrUniqueHostnameNotFound
}

// ============================================================================
// Validation
// ============================================================================

func (m *HostnameMapper) validate(hostname string) error {
	if hostname == "" {
		return ErrEmptyHostname
	}

	// Check total length
	if len(hostname) > 253 {
		return ErrHostnameTooLong
	}

	// Split into labels
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return ErrEmptyLabel
		}

		if len(label) > 63 {
			return ErrLabelTooLong
		}

		// Check for valid characters
		if !m.validLabelRegex.MatchString(label) {
			// Check if it starts with digit (allowed per RFC 1123)
			if !isValidLabel(label) {
				return ErrInvalidLabel
			}
		}
	}

	// Check for reserved hostnames
	lower := strings.ToLower(hostname)
	reserved := []string{"localhost", "localhost.localdomain", "wpad", "isatap"}
	for _, r := range reserved {
		if lower == r {
			return ErrReservedHostname
		}
	}

	return nil
}

func isValidLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}

	for i, ch := range label {
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			continue
		}
		if ch == '-' && i > 0 && i < len(label)-1 {
			continue
		}
		return false
	}

	return true
}

// ============================================================================
// Hostname Cache
// ============================================================================

func (m *HostnameMapper) getCachedHostname(mac net.HardwareAddr) string {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return m.hostnameCache[mac.String()]
}

func (m *HostnameMapper) cacheHostname(mac net.HardwareAddr, hostname string) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.hostnameCache[mac.String()] = hostname
}

// ClearCache clears the hostname cache.
func (m *HostnameMapper) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.hostnameCache = make(map[string]string)
}

// RemoveFromCache removes a MAC's cached hostname.
func (m *HostnameMapper) RemoveFromCache(mac net.HardwareAddr) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	delete(m.hostnameCache, mac.String())
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns hostname mapper statistics.
func (m *HostnameMapper) GetStats() HostnameMapperStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// GetSourceDistribution returns percentage distribution of hostname sources.
func (m *HostnameMapper) GetSourceDistribution() map[string]float64 {
	total := float64(m.stats.FromOption12 + m.stats.FromOption81 + m.stats.Generated)
	if total == 0 {
		return map[string]float64{
			"option12":  0,
			"option81":  0,
			"generated": 0,
		}
	}

	return map[string]float64{
		"option12":  float64(m.stats.FromOption12) / total * 100,
		"option81":  float64(m.stats.FromOption81) / total * 100,
		"generated": float64(m.stats.Generated) / total * 100,
	}
}

// ============================================================================
// Lookup Functions
// ============================================================================

// GetHostnameForMAC returns the hostname for a MAC address.
func (m *HostnameMapper) GetHostnameForMAC(ctx context.Context, mac net.HardwareAddr) (string, error) {
	// Check cache first
	if cached := m.getCachedHostname(mac); cached != "" {
		return cached, nil
	}

	// Check repository
	m.mu.RLock()
	repo := m.leaseRepo
	m.mu.RUnlock()

	if repo == nil {
		return "", ErrNoLeaseRepository
	}

	return repo.GetHostnameByMAC(ctx, mac)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrEmptyHostname is returned for empty hostnames
	ErrEmptyHostname = errors.New("hostname is empty")

	// ErrHostnameTooLong is returned when hostname exceeds limit
	ErrHostnameTooLong = errors.New("hostname exceeds 253 characters")

	// ErrEmptyLabel is returned for empty label in FQDN
	ErrEmptyLabel = errors.New("hostname contains empty label")

	// ErrLabelTooLong is returned when label exceeds 63 characters
	ErrLabelTooLong = errors.New("hostname label exceeds 63 characters")

	// ErrInvalidLabel is returned for invalid label format
	ErrInvalidLabel = errors.New("hostname label contains invalid characters")

	// ErrReservedHostname is returned for reserved hostnames
	ErrReservedHostname = errors.New("hostname is reserved")

	// ErrUniqueHostnameNotFound is returned when unique hostname cannot be found
	ErrUniqueHostnameNotFound = errors.New("could not find unique hostname")

	// ErrNoLeaseRepository is returned when lease repository not set
	ErrNoLeaseRepository = errors.New("lease repository not configured")
)
