// Package utils provides common utility functions for threat intelligence
package utils

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Public IP Filtering
// ============================================================================

// IsPublicIP checks if an IP is a publicly routable internet address
// Returns true only for IPs that should be included in threat databases
func IsPublicIP(ip string) bool {
	if !IsValidIP(ip) {
		return false
	}

	// Exclude private IPs
	if IsPrivateIP(ip) {
		return false
	}

	// Exclude reserved IPs
	if IsReservedIP(ip) {
		return false
	}

	// Exclude multicast
	if IsMulticastIP(ip) {
		return false
	}

	// Exclude loopback
	if IsLoopbackIP(ip) {
		return false
	}

	// Exclude IPv4 shared address space (100.64.0.0/10 - RFC 6598)
	if IPInCIDR(ip, "100.64.0.0/10") {
		return false
	}

	// Exclude IPv4 documentation ranges
	documentationRanges := []string{
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"192.88.99.0/24",  // 6to4 relay anycast
		"198.18.0.0/15",   // Benchmark testing
		"240.0.0.0/4",     // Reserved for future use
	}

	for _, cidr := range documentationRanges {
		if IPInCIDR(ip, cidr) {
			return false
		}
	}

	// IPv6 documentation and special ranges
	if GetIPVersion(ip) == 6 {
		ipv6SpecialRanges := []string{
			"2001:db8::/32", // Documentation
			"ff00::/8",      // Multicast
			"fe80::/10",     // Link-local
			"fc00::/7",      // Unique local
			"::/128",        // Unspecified
			"::1/128",       // Loopback
			"::ffff:0:0/96", // IPv4-mapped
			"100::/64",      // Discard prefix
			"2001::/32",     // TEREDO
			"2001:10::/28",  // Deprecated
			"2001:20::/28",  // ORCHIDv2
		}

		for _, cidr := range ipv6SpecialRanges {
			if IPInCIDR(ip, cidr) {
				return false
			}
		}
	}

	// If it passed all filters, it's a public IP
	return true
}

// FilterPublicIPs filters a list of IPs to only public routable addresses
func FilterPublicIPs(ips []string) []string {
	public := make([]string, 0, len(ips))
	for _, ip := range ips {
		if IsPublicIP(ip) {
			public = append(public, ip)
		}
	}
	return public
}

// ============================================================================
// IP Extraction from Text
// ============================================================================

var (
	// IPv4 pattern (allows defanged IPs with brackets)
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}[\[\.\]]{1,3}){3}\d{1,3}\b`)

	// IPv6 pattern (simplified)
	ipv6Pattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b`)
)

// ExtractIPsFromText extracts all valid public IPs from unstructured text
func ExtractIPsFromText(text string) []string {
	ips := make([]string, 0)
	seen := make(map[string]bool)

	// Find IPv4 addresses (including defanged)
	ipv4Matches := ipv4Pattern.FindAllString(text, -1)
	for _, match := range ipv4Matches {
		// Unfang: replace [.] with .
		ip := strings.ReplaceAll(match, "[.]", ".")
		ip = strings.ReplaceAll(ip, "[", "")
		ip = strings.ReplaceAll(ip, "]", "")

		if IsPublicIP(ip) && !seen[ip] {
			ips = append(ips, ip)
			seen[ip] = true
		}
	}

	// Find IPv6 addresses
	ipv6Matches := ipv6Pattern.FindAllString(text, -1)
	for _, match := range ipv6Matches {
		if IsPublicIP(match) && !seen[match] {
			ips = append(ips, match)
			seen[match] = true
		}
	}

	return ips
}

// IPExtractionResult holds results from IP extraction
type IPExtractionResult struct {
	TotalFound  int
	ValidPublic int
	PrivateIPs  int
	InvalidIPs  int
	PublicIPs   []string
}

// ExtractIPsWithStats extracts IPs and returns detailed statistics
func ExtractIPsWithStats(text string) IPExtractionResult {
	result := IPExtractionResult{
		PublicIPs: make([]string, 0),
	}

	seen := make(map[string]bool)

	// Find all potential IPv4 addresses
	ipv4Matches := ipv4Pattern.FindAllString(text, -1)
	for _, match := range ipv4Matches {
		result.TotalFound++

		// Unfang
		ip := strings.ReplaceAll(match, "[.]", ".")
		ip = strings.ReplaceAll(ip, "[", "")
		ip = strings.ReplaceAll(ip, "]", "")

		if !IsValidIP(ip) {
			result.InvalidIPs++
			continue
		}

		if !IsPublicIP(ip) {
			result.PrivateIPs++
			continue
		}

		if !seen[ip] {
			result.PublicIPs = append(result.PublicIPs, ip)
			result.ValidPublic++
			seen[ip] = true
		}
	}

	// Find IPv6 addresses
	ipv6Matches := ipv6Pattern.FindAllString(text, -1)
	for _, match := range ipv6Matches {
		result.TotalFound++

		if !IsValidIP(match) {
			result.InvalidIPs++
			continue
		}

		if !IsPublicIP(match) {
			result.PrivateIPs++
			continue
		}

		if !seen[match] {
			result.PublicIPs = append(result.PublicIPs, match)
			result.ValidPublic++
			seen[match] = true
		}
	}

	return result
}

// ============================================================================
// IP Range Expansion for Database Queries
// ============================================================================

// CIDRToSQLCondition converts a CIDR to PostgreSQL WHERE condition
func CIDRToSQLCondition(cidr, columnName string) (string, error) {
	if err := ValidateCIDR(cidr); err != nil {
		return "", err
	}

	// PostgreSQL has native inet type support
	// Use <<= operator for "is contained by or equals"
	return fmt.Sprintf("%s <<= '%s'::inet", columnName, cidr), nil
}

// IPRangeToSQLCondition converts start-end IP range to SQL condition
func IPRangeToSQLCondition(startIP, endIP, columnName string) (string, error) {
	if !IsValidIP(startIP) || !IsValidIP(endIP) {
		return "", fmt.Errorf("invalid IP address")
	}

	// Use BETWEEN for IP range queries in PostgreSQL
	return fmt.Sprintf("%s BETWEEN '%s'::inet AND '%s'::inet", columnName, startIP, endIP), nil
}

// SplitLargeCIDR splits a large CIDR block into smaller chunks
// Useful for preventing query timeout on very large networks
func SplitLargeCIDR(cidr string, maxPrefixLen int) ([]string, error) {
	info, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// If CIDR is already small enough, return as-is
	if info.Prefix >= maxPrefixLen {
		return []string{cidr}, nil
	}

	// Calculate how many times to split
	splitCount := 1 << uint(maxPrefixLen-info.Prefix)
	if splitCount > 256 {
		return nil, fmt.Errorf("CIDR too large to split efficiently")
	}

	// For now, return the original CIDR
	// Full implementation would split into subnets
	// This is a simplified version
	return []string{cidr}, nil
}

// ============================================================================
// Batch IP Processing with Statistics
// ============================================================================

// BatchProcessingResult holds statistics from batch IP processing
type BatchProcessingResult struct {
	TotalProcessed int
	ValidIPs       int
	InvalidIPs     int
	PrivateIPs     int
	DuplicateIPs   int
	PublicIPs      []string
	Errors         []string
}

// ProcessIPBatch validates and filters a batch of IPs
func ProcessIPBatch(ips []string, filterPrivate bool) BatchProcessingResult {
	result := BatchProcessingResult{
		TotalProcessed: len(ips),
		PublicIPs:      make([]string, 0, len(ips)),
		Errors:         make([]string, 0),
	}

	seen := make(map[string]bool)

	for _, ip := range ips {
		// Validate IP
		if !IsValidIP(ip) {
			result.InvalidIPs++
			result.Errors = append(result.Errors, fmt.Sprintf("invalid IP: %s", ip))
			continue
		}

		result.ValidIPs++

		// Check if it's a public IP
		isPublic := IsPublicIP(ip)
		if !isPublic {
			result.PrivateIPs++
			if filterPrivate {
				continue // Skip private IPs
			}
		}

		// Normalize IP
		normalized := NormalizeIP(ip)

		// Check for duplicates
		if seen[normalized] {
			result.DuplicateIPs++
			continue
		}

		seen[normalized] = true
		result.PublicIPs = append(result.PublicIPs, normalized)
	}

	return result
}

// ============================================================================
// IP Context Cache
// ============================================================================

// IPContext holds enriched threat intelligence context for an IP
type IPContext struct {
	IP              string
	IsPublic        bool
	IsThreat        bool
	ThreatTypes     []string
	ConfidenceScore float64
	FirstSeen       time.Time
	LastSeen        time.Time
	Country         string
	CountryCode     string
	ASN             int
	ASNOrg          string
	IsAnonymizer    bool
	AnonymizerType  string // "tor", "vpn", "proxy", "datacenter"
	CachedAt        time.Time
}

// IPContextCache provides in-memory caching for IP context lookups
type IPContextCache struct {
	cache   map[string]*IPContext
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
	hits    int
	misses  int
}

// NewIPContextCache creates a new IP context cache
func NewIPContextCache(maxSize int, ttl time.Duration) *IPContextCache {
	return &IPContextCache{
		cache:   make(map[string]*IPContext, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves IP context from cache
func (c *IPContextCache) Get(ip string) (*IPContext, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ctx, exists := c.cache[ip]
	if !exists {
		c.misses++
		return nil, false
	}

	// Check if expired
	if time.Since(ctx.CachedAt) > c.ttl {
		c.misses++
		return nil, false
	}

	c.hits++
	return ctx, true
}

// Set stores IP context in cache
func (c *IPContextCache) Set(ip string, ctx *IPContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if cache is full, remove random entry
	if len(c.cache) >= c.maxSize {
		// Remove one random entry
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}

	ctx.CachedAt = time.Now()
	c.cache[ip] = ctx
}

// Stats returns cache statistics
func (c *IPContextCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"size":     len(c.cache),
		"max_size": c.maxSize,
		"hits":     c.hits,
		"misses":   c.misses,
		"hit_rate": hitRate,
	}
}

// Clear removes all entries from cache
func (c *IPContextCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*IPContext, c.maxSize)
	c.hits = 0
	c.misses = 0
}

// ============================================================================
// Helper Functions
// ============================================================================

// GetIPContextStub returns a basic IP context (to be enhanced with database lookups)
func GetIPContextStub(ip string) *IPContext {
	return &IPContext{
		IP:              ip,
		IsPublic:        IsPublicIP(ip),
		IsThreat:        false, // Would be populated from database
		ThreatTypes:     []string{},
		ConfidenceScore: 0.0,
		Country:         "unknown",
		CountryCode:     "XX",
		IsAnonymizer:    false,
		CachedAt:        time.Now(),
	}
}

// FormatIPList formats a list of IPs for display
func FormatIPList(ips []string, maxDisplay int) string {
	if len(ips) == 0 {
		return "(none)"
	}

	if len(ips) <= maxDisplay {
		return strings.Join(ips, ", ")
	}

	displayed := strings.Join(ips[:maxDisplay], ", ")
	return fmt.Sprintf("%s ... and %d more", displayed, len(ips)-maxDisplay)
}

// IPListSummary generates a summary of an IP list
func IPListSummary(ips []string) map[string]interface{} {
	ipv4Count := 0
	ipv6Count := 0
	publicCount := 0
	privateCount := 0

	for _, ip := range ips {
		if !IsValidIP(ip) {
			continue
		}

		if GetIPVersion(ip) == 4 {
			ipv4Count++
		} else {
			ipv6Count++
		}

		if IsPublicIP(ip) {
			publicCount++
		} else {
			privateCount++
		}
	}

	return map[string]interface{}{
		"total":   len(ips),
		"ipv4":    ipv4Count,
		"ipv6":    ipv6Count,
		"public":  publicCount,
		"private": privateCount,
	}
}
