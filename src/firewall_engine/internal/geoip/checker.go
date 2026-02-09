// Package geoip provides GeoIP-based traffic filtering for the firewall engine.
// It combines the GeoResolver (PostgreSQL-backed IP→country/ASN lookup) with
// the ParsedGeoPolicy (deny/allow list, ASN blocking, whitelist) to make
// block/allow decisions on incoming packets based on geographic origin.
//
// The checker includes an in-memory LRU cache for fast repeated lookups
// (same IP won't hit DB twice within TTL), and enriches alerts with geo data.
//
// Thread-safe for concurrent packet pipeline access.
package geoip

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall_engine/internal/alerting"
	"firewall_engine/internal/config"
	"firewall_engine/internal/objects"
)

// ============================================================================
// Error types
// ============================================================================

var (
	// ErrCheckerNotInitialized indicates the checker was not properly created.
	ErrCheckerNotInitialized = errors.New("geoip checker not initialized")

	// ErrNoResolver indicates no GeoIP resolver was provided.
	ErrNoResolver = errors.New("no geoip resolver configured")

	// ErrPolicyDisabled indicates GeoIP policy checking is disabled.
	ErrPolicyDisabled = errors.New("geoip policy is disabled")
)

// ============================================================================
// GeoIP lookup result
// ============================================================================

// GeoResult is returned from a GeoIP check.
type GeoResult struct {
	// Block decision
	Blocked bool   // true if this IP should be blocked
	Reason  string // human-readable reason (e.g., "Country blocked: RU")

	// GeoIP data (always populated if resolver is available)
	CountryCode string // ISO 3166-1 alpha-2 (e.g., "US", "RU", "CN")
	ASN         string // e.g., "AS15169"
	ASNNumber   uint32 // numeric ASN (e.g., 15169)

	// Flags
	IsWhitelisted    bool // IP was whitelisted (bypasses all geo checks)
	IsPrivate        bool // IP is RFC1918 private
	IsForeignDC      bool // IP is from a foreign datacenter
	IsASNBlocked     bool // ASN is in blocked list
	IsCountryBlocked bool // Country is in blocked list

	// For alert enrichment
	LookupLatency time.Duration // how long the lookup took
	CacheHit      bool          // true if result came from cache
}

// ToGeoInfo converts GeoResult to alerting.GeoInfo for alert enrichment.
func (r *GeoResult) ToGeoInfo() *alerting.GeoInfo {
	if r.CountryCode == "" && r.ASN == "" {
		return nil
	}
	return &alerting.GeoInfo{
		CountryCode: r.CountryCode,
		ASN:         r.ASNNumber,
		ASNOrg:      r.ASN,
	}
}

// ============================================================================
// IP lookup cache
// ============================================================================

type cachedLookup struct {
	countryCode string
	asn         string
	expiresAt   time.Time
}

// ============================================================================
// Checker stats
// ============================================================================

// CheckerStats holds GeoIP checker statistics.
type CheckerStats struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"` // "deny_list" or "allow_list"
	CountriesCount int    `json:"countries_count"`
	ASNsBlocked    int    `json:"asns_blocked"`
	TotalChecks    int64  `json:"total_checks"`
	TotalBlocks    int64  `json:"total_blocks"`
	CountryBlocks  int64  `json:"country_blocks"`
	ASNBlocks      int64  `json:"asn_blocks"`
	Whitelisted    int64  `json:"whitelisted"`
	PrivateIPs     int64  `json:"private_ips"`
	ForeignDC      int64  `json:"foreign_dc"`
	CacheHits      int64  `json:"cache_hits"`
	CacheMisses    int64  `json:"cache_misses"`
	LookupErrors   int64  `json:"lookup_errors"`
	Enrichments    int64  `json:"enrichments"`
}

// ============================================================================
// Checker
// ============================================================================

// Checker performs GeoIP-based traffic filtering.
//
// Pipeline:
//  1. Skip private/RFC1918 IPs (always allowed)
//  2. Check whitelist (bypass all geo checks)
//  3. Lookup IP → country + ASN (cached)
//  4. Check country against deny/allow list
//  5. Check ASN against blocked ASN list
//  6. Check foreign datacenter flag
//
// Thread-safe for concurrent access from packet pipeline workers.
type Checker struct {
	resolver objects.GeoResolver
	policy   *config.ParsedGeoPolicy
	alertMgr *alerting.Manager

	// Policy mutex (allows hot-reload of policy)
	policyMu sync.RWMutex

	// IP lookup cache (IP string → country+ASN)
	cacheMu  sync.RWMutex
	cache    map[string]*cachedLookup
	cacheTTL time.Duration
	cacheMax int

	// Private IP ranges (pre-computed for fast check)
	privateRanges []*net.IPNet

	// Stats (all atomic)
	totalChecks   atomic.Int64
	totalBlocks   atomic.Int64
	countryBlocks atomic.Int64
	asnBlocks     atomic.Int64
	whitelisted   atomic.Int64
	privateIPs    atomic.Int64
	foreignDC     atomic.Int64
	cacheHits     atomic.Int64
	cacheMisses   atomic.Int64
	lookupErrors  atomic.Int64
	enrichments   atomic.Int64

	// Lifecycle
	initialized atomic.Bool
	stopCh      chan struct{}
	stopped     atomic.Bool
}

// CheckerConfig holds configuration for the GeoIP checker.
type CheckerConfig struct {
	Resolver objects.GeoResolver
	Policy   *config.ParsedGeoPolicy
	AlertMgr *alerting.Manager

	// CacheTTL is how long to cache IP→country/ASN lookups.
	// Default: 1 hour.
	CacheTTL time.Duration

	// CacheMax is the maximum number of cached IP lookups.
	// When exceeded, oldest entries are evicted.
	// Default: 100,000.
	CacheMax int
}

// NewChecker creates a new GeoIP checker.
//
// Parameters:
//   - cfg.Resolver: GeoResolver for IP→country/ASN lookups. Required.
//   - cfg.Policy: ParsedGeoPolicy from geoip.toml. Required.
//   - cfg.AlertMgr: alert manager for firing GEO_BLOCK alerts. May be nil.
//
// Returns error if resolver or policy is nil.
func NewChecker(cfg CheckerConfig) (*Checker, error) {
	if cfg.Resolver == nil {
		return nil, ErrNoResolver
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("geoip policy is nil")
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}
	cacheMax := cfg.CacheMax
	if cacheMax == 0 {
		cacheMax = 100_000
	}

	c := &Checker{
		resolver: cfg.Resolver,
		policy:   cfg.Policy,
		alertMgr: cfg.AlertMgr,
		cache:    make(map[string]*cachedLookup, cacheMax/2),
		cacheTTL: cacheTTL,
		cacheMax: cacheMax,
		stopCh:   make(chan struct{}),
	}

	// Pre-compute private IP ranges for fast check
	c.privateRanges = parsePrivateRanges()

	c.initialized.Store(true)

	// Start background cache cleanup
	go c.cacheCleanupLoop()

	return c, nil
}

// ============================================================================
// Core check
// ============================================================================

// Check performs a full GeoIP check on an IP address.
//
// Pipeline:
//  1. Skip if policy disabled → ALLOW
//  2. Skip private IPs → ALLOW
//  3. Check whitelist → ALLOW (bypass all)
//  4. Lookup IP → country + ASN (cached)
//  5. Check country → BLOCK if in deny list (or not in allow list)
//  6. Check ASN → BLOCK if in blocked ASN list
//  7. Check foreign datacenter → flag only (alert, no block)
//
// Thread-safe for concurrent calls.
func (c *Checker) Check(srcIP string) GeoResult {
	if !c.initialized.Load() {
		return GeoResult{}
	}

	c.totalChecks.Add(1)

	// Step 1: Check if policy is enabled
	c.policyMu.RLock()
	policy := c.policy
	c.policyMu.RUnlock()

	if policy == nil || !policy.Enabled {
		return GeoResult{}
	}

	// Step 2: Skip private/RFC1918 IPs (always allowed)
	if c.isPrivateIP(srcIP) {
		c.privateIPs.Add(1)
		return GeoResult{IsPrivate: true}
	}

	// Step 3: Check whitelist
	if policy.IsWhitelisted(srcIP) {
		c.whitelisted.Add(1)
		return GeoResult{IsWhitelisted: true}
	}

	// Step 4: Lookup country + ASN (with cache)
	start := time.Now()
	countryCode, asn, cacheHit, err := c.lookupWithCache(srcIP)
	lookupLatency := time.Since(start)

	if err != nil {
		c.lookupErrors.Add(1)
		// On lookup error, fail open (allow traffic)
		return GeoResult{
			Reason:        fmt.Sprintf("GeoIP lookup failed: %v", err),
			LookupLatency: lookupLatency,
		}
	}

	// Parse ASN number
	asnNumber := parseASNNumber(asn)

	result := GeoResult{
		CountryCode:   countryCode,
		ASN:           asn,
		ASNNumber:     asnNumber,
		LookupLatency: lookupLatency,
		CacheHit:      cacheHit,
	}

	// Step 5: Check country
	if countryCode != "" && policy.IsCountryBlocked(countryCode) {
		result.Blocked = true
		result.IsCountryBlocked = true
		result.Reason = fmt.Sprintf("Country blocked: %s", countryCode)
		c.totalBlocks.Add(1)
		c.countryBlocks.Add(1)
		c.fireGeoBlockAlert(srcIP, result)
		return result
	}

	// Step 6: Check ASN
	if asnNumber > 0 && policy.IsASNBlocked(asnNumber) {
		result.Blocked = true
		result.IsASNBlocked = true
		result.Reason = fmt.Sprintf("ASN blocked: %s (AS%d)", asn, asnNumber)
		c.totalBlocks.Add(1)
		c.asnBlocks.Add(1)
		c.fireGeoBlockAlert(srcIP, result)
		return result
	}

	// Step 7: Check foreign datacenter (flag only, no block)
	if countryCode != "" && policy.IsForeignDatacenter(countryCode) {
		result.IsForeignDC = true
		c.foreignDC.Add(1)
		// Alert but don't block
		c.fireForeignDCAlert(srcIP, result)
	}

	return result
}

// Enrich returns GeoIP data for an IP without applying policy.
// Used to enrich alerts with geo info when enrich_alerts = true.
// Returns nil GeoInfo if lookup fails.
func (c *Checker) Enrich(srcIP string) *alerting.GeoInfo {
	if !c.initialized.Load() {
		return nil
	}

	c.policyMu.RLock()
	enrich := c.policy != nil && c.policy.EnrichAlerts
	c.policyMu.RUnlock()

	if !enrich {
		return nil
	}

	// Skip private IPs
	if c.isPrivateIP(srcIP) {
		return nil
	}

	countryCode, asn, _, err := c.lookupWithCache(srcIP)
	if err != nil {
		return nil
	}

	if countryCode == "" && asn == "" {
		return nil
	}

	c.enrichments.Add(1)

	return &alerting.GeoInfo{
		CountryCode: countryCode,
		ASN:         parseASNNumber(asn),
		ASNOrg:      asn,
	}
}

// ============================================================================
// Configuration management
// ============================================================================

// UpdatePolicy replaces the GeoIP policy at runtime (hot-reload).
// Thread-safe; takes effect immediately for subsequent Check() calls.
func (c *Checker) UpdatePolicy(newPolicy *config.ParsedGeoPolicy) {
	if newPolicy == nil {
		return
	}
	c.policyMu.Lock()
	c.policy = newPolicy
	c.policyMu.Unlock()
}

// ClearCache empties the IP lookup cache.
// Useful after policy changes that might affect cached results.
func (c *Checker) ClearCache() {
	c.cacheMu.Lock()
	c.cache = make(map[string]*cachedLookup, c.cacheMax/2)
	c.cacheMu.Unlock()
}

// ============================================================================
// Statistics
// ============================================================================

// Stats returns GeoIP checker statistics. Thread-safe.
func (c *Checker) Stats() CheckerStats {
	c.policyMu.RLock()
	enabled := c.policy != nil && c.policy.Enabled
	mode := "disabled"
	countriesCount := 0
	asnsBlocked := 0
	if c.policy != nil {
		if c.policy.IsDenyMode {
			mode = "deny_list"
		} else {
			mode = "allow_list"
		}
		countriesCount = len(c.policy.Countries)
		asnsBlocked = len(c.policy.BlockedASNs)
	}
	c.policyMu.RUnlock()

	return CheckerStats{
		Enabled:        enabled,
		Mode:           mode,
		CountriesCount: countriesCount,
		ASNsBlocked:    asnsBlocked,
		TotalChecks:    c.totalChecks.Load(),
		TotalBlocks:    c.totalBlocks.Load(),
		CountryBlocks:  c.countryBlocks.Load(),
		ASNBlocks:      c.asnBlocks.Load(),
		Whitelisted:    c.whitelisted.Load(),
		PrivateIPs:     c.privateIPs.Load(),
		ForeignDC:      c.foreignDC.Load(),
		CacheHits:      c.cacheHits.Load(),
		CacheMisses:    c.cacheMisses.Load(),
		LookupErrors:   c.lookupErrors.Load(),
		Enrichments:    c.enrichments.Load(),
	}
}

// Stop shuts down the background cache cleanup goroutine.
func (c *Checker) Stop() {
	if c.stopped.CompareAndSwap(false, true) {
		close(c.stopCh)
	}
}

// ============================================================================
// Internal: cache + lookup
// ============================================================================

// lookupWithCache checks the cache first, then falls back to the resolver.
func (c *Checker) lookupWithCache(ipStr string) (countryCode, asn string, cacheHit bool, err error) {
	// Check cache
	c.cacheMu.RLock()
	entry, ok := c.cache[ipStr]
	c.cacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		c.cacheHits.Add(1)
		return entry.countryCode, entry.asn, true, nil
	}

	c.cacheMisses.Add(1)

	// Resolve via database
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", false, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	countryCode, asn, err = c.resolver.LookupIP(ip)
	if err != nil {
		return "", "", false, fmt.Errorf("geoip lookup failed for %s: %w", ipStr, err)
	}

	// Cache the result
	c.cacheMu.Lock()
	// Evict if cache is full (simple: clear half the cache)
	if len(c.cache) >= c.cacheMax {
		c.evictHalfLocked()
	}
	c.cache[ipStr] = &cachedLookup{
		countryCode: countryCode,
		asn:         asn,
		expiresAt:   time.Now().Add(c.cacheTTL),
	}
	c.cacheMu.Unlock()

	return countryCode, asn, false, nil
}

// evictHalfLocked removes approximately half the cache entries.
// Caller must hold c.cacheMu write lock.
func (c *Checker) evictHalfLocked() {
	target := len(c.cache) / 2
	removed := 0
	now := time.Now()

	// First pass: remove expired entries
	for k, v := range c.cache {
		if now.After(v.expiresAt) {
			delete(c.cache, k)
			removed++
		}
		if removed >= target {
			return
		}
	}

	// Second pass: remove remaining to hit target
	for k := range c.cache {
		delete(c.cache, k)
		removed++
		if removed >= target {
			return
		}
	}
}

// cacheCleanupLoop periodically removes expired cache entries.
func (c *Checker) cacheCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanupExpiredCache()
		}
	}
}

// cleanupExpiredCache removes expired entries from the cache.
func (c *Checker) cleanupExpiredCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	now := time.Now()
	for k, v := range c.cache {
		if now.After(v.expiresAt) {
			delete(c.cache, k)
		}
	}
}

// ============================================================================
// Internal: private IP check
// ============================================================================

// isPrivateIP checks if an IP is RFC1918 private, loopback, or link-local.
func (c *Checker) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Loopback
	if ip.IsLoopback() {
		return true
	}

	// Link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check RFC1918 + other private ranges
	for _, cidr := range c.privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// parsePrivateRanges returns pre-computed private IP ranges.
func parsePrivateRanges() []*net.IPNet {
	privateCIDRs := []string{
		"10.0.0.0/8",      // RFC1918 Class A
		"172.16.0.0/12",   // RFC1918 Class B
		"192.168.0.0/16",  // RFC1918 Class C
		"100.64.0.0/10",   // RFC6598 Carrier-grade NAT
		"169.254.0.0/16",  // RFC3927 Link-local
		"127.0.0.0/8",     // Loopback
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
	}

	var ranges []*net.IPNet
	for _, cidr := range privateCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ranges = append(ranges, ipNet)
	}
	return ranges
}

// ============================================================================
// Internal: ASN parsing
// ============================================================================

// parseASNNumber extracts the numeric ASN from a string like "AS15169".
func parseASNNumber(asn string) uint32 {
	if asn == "" {
		return 0
	}
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
	n, err := strconv.ParseUint(asn, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// ============================================================================
// Alert firing
// ============================================================================

// fireGeoBlockAlert fires a GEO_BLOCK alert when an IP is blocked.
func (c *Checker) fireGeoBlockAlert(srcIP string, result GeoResult) {
	if c.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	details := result.Reason

	builder := alerting.NewAlert(alerting.AlertGeoBlock, severity).
		WithSource(srcIP, 0).
		WithDetails(details).
		WithAction(alerting.ActionDropped).
		WithGeoInfo(result.ToGeoInfo()).
		WithMeta("country_code", result.CountryCode).
		WithMeta("asn", result.ASN)

	if result.IsCountryBlocked {
		builder = builder.WithMeta("block_type", "country")
	}
	if result.IsASNBlocked {
		builder = builder.WithMeta("block_type", "asn")
	}
	if result.CacheHit {
		builder = builder.WithMeta("cache_hit", "true")
	}

	c.alertMgr.Alert(builder.Build())
}

// fireForeignDCAlert fires an INFO alert for foreign datacenter traffic.
func (c *Checker) fireForeignDCAlert(srcIP string, result GeoResult) {
	if c.alertMgr == nil {
		return
	}

	details := fmt.Sprintf("Foreign datacenter traffic from %s (country: %s, ASN: %s)",
		srcIP, result.CountryCode, result.ASN)

	builder := alerting.NewAlert(alerting.AlertGeoBlock, alerting.SeverityInfo).
		WithSource(srcIP, 0).
		WithDetails(details).
		WithAction(alerting.ActionLogged).
		WithGeoInfo(result.ToGeoInfo()).
		WithMeta("country_code", result.CountryCode).
		WithMeta("asn", result.ASN).
		WithMeta("foreign_datacenter", "true")

	c.alertMgr.Alert(builder.Build())
}
