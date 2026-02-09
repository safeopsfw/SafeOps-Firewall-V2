// Package domain provides domain-based filtering for the firewall engine.
// cdn_allowlist.go manages a list of known CDN/infrastructure provider domains
// that should never be blocked by IP (only by domain-level DNS redirect).
// Blocking CDN IPs causes collateral damage to thousands of unrelated sites.
package domain

import (
	"strings"
	"sync"
)

// CDNProvider represents a known CDN/infrastructure provider
type CDNProvider struct {
	Name    string   // Human-readable name (e.g., "Cloudflare")
	Domains []string // Wildcard domain patterns
}

// CDNCheckResult is returned when checking if a domain belongs to a CDN
type CDNCheckResult struct {
	IsCDN    bool   // true if domain belongs to a known CDN
	Provider string // CDN provider name (e.g., "Cloudflare")
}

// CDNAllowlist tracks known CDN provider domains.
// When a domain matches both a blocklist AND a CDN allowlist entry,
// the engine should only use DNS-level blocking (REDIRECT), never
// IP-level blocking (DROP), because CDN IPs are shared across
// thousands of unrelated sites.
//
// Thread-safe for concurrent access from the packet pipeline.
type CDNAllowlist struct {
	mu        sync.RWMutex
	providers []CDNProvider

	// Pre-computed lookup structures for fast matching
	exactDomains map[string]string // domain → provider name
	suffixes     []suffixEntry     // suffix → provider name
}

type suffixEntry struct {
	suffix   string // e.g., ".cloudflare.com"
	provider string // e.g., "Cloudflare"
}

// defaultCDNProviders contains the built-in list of known CDN providers.
// This covers the major CDN/infrastructure providers whose IPs are shared
// across many customers and should never be blocked at the IP level.
var defaultCDNProviders = []CDNProvider{
	{
		Name: "Cloudflare",
		Domains: []string{
			"*.cloudflare.com",
			"*.cloudflareinsights.com",
			"*.cloudflare-dns.com",
			"*.cloudflaressl.com",
			"*.cf-ipfs.com",
		},
	},
	{
		Name: "AWS CloudFront",
		Domains: []string{
			"*.cloudfront.net",
			"*.amazonaws.com",
		},
	},
	{
		Name: "Akamai",
		Domains: []string{
			"*.akamai.net",
			"*.akamaized.net",
			"*.akamaihd.net",
			"*.akamaiedge.net",
			"*.akamaitechnologies.com",
			"*.edgekey.net",
			"*.edgesuite.net",
		},
	},
	{
		Name: "Fastly",
		Domains: []string{
			"*.fastly.net",
			"*.fastlylb.net",
			"*.fastly.com",
		},
	},
	{
		Name: "Google CDN",
		Domains: []string{
			"*.googleapis.com",
			"*.gstatic.com",
			"*.googlevideo.com",
			"*.googleusercontent.com",
			"*.ggpht.com",
			"*.gvt1.com",
			"*.gvt2.com",
		},
	},
	{
		Name: "Microsoft Azure CDN",
		Domains: []string{
			"*.azureedge.net",
			"*.azure.com",
			"*.msecnd.net",
			"*.vo.msecnd.net",
			"*.trafficmanager.net",
		},
	},
	{
		Name: "StackPath/MaxCDN",
		Domains: []string{
			"*.stackpathdns.com",
			"*.stackpathcdn.com",
			"*.netdna-cdn.com",
			"*.netdna-ssl.com",
		},
	},
	{
		Name: "Limelight/Edgio",
		Domains: []string{
			"*.llnwd.net",
			"*.limelight.com",
			"*.edgecastcdn.net",
			"*.edgio.net",
		},
	},
	{
		Name: "KeyCDN",
		Domains: []string{
			"*.kxcdn.com",
			"*.keycdn.com",
		},
	},
	{
		Name: "Bunny CDN",
		Domains: []string{
			"*.b-cdn.net",
			"*.bunnycdn.com",
			"*.bunny.net",
		},
	},
	{
		Name: "Incapsula/Imperva",
		Domains: []string{
			"*.incapdns.net",
			"*.impervadns.net",
		},
	},
	{
		Name: "Sucuri",
		Domains: []string{
			"*.sucuri.net",
			"*.sucuridns.com",
		},
	},
}

// NewCDNAllowlist creates a CDN allowlist initialized with default providers.
func NewCDNAllowlist() *CDNAllowlist {
	c := &CDNAllowlist{
		exactDomains: make(map[string]string),
	}
	c.loadProviders(defaultCDNProviders)
	return c
}

// NewCDNAllowlistWithProviders creates a CDN allowlist with custom providers,
// merged on top of the defaults.
func NewCDNAllowlistWithProviders(extra []CDNProvider) *CDNAllowlist {
	c := &CDNAllowlist{
		exactDomains: make(map[string]string),
	}
	c.loadProviders(defaultCDNProviders)
	c.loadProviders(extra)
	return c
}

// Check determines if a domain belongs to a known CDN provider.
// Returns CDNCheckResult with IsCDN=true and the provider name if matched.
// Thread-safe for concurrent access.
func (c *CDNAllowlist) Check(domain string) CDNCheckResult {
	if domain == "" {
		return CDNCheckResult{}
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Exact match (O(1))
	if provider, ok := c.exactDomains[domain]; ok {
		return CDNCheckResult{IsCDN: true, Provider: provider}
	}

	// Suffix match (e.g., "images.example.cloudfront.net" matches ".cloudfront.net")
	for _, entry := range c.suffixes {
		if strings.HasSuffix(domain, entry.suffix) {
			return CDNCheckResult{IsCDN: true, Provider: entry.provider}
		}
	}

	return CDNCheckResult{}
}

// IsCDN is a convenience method returning just the boolean.
func (c *CDNAllowlist) IsCDN(domain string) bool {
	return c.Check(domain).IsCDN
}

// AddProvider adds a new CDN provider to the allowlist at runtime.
// Thread-safe; can be called while the packet pipeline is running.
func (c *CDNAllowlist) AddProvider(provider CDNProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addProviderLocked(provider)
}

// ProviderCount returns the number of registered CDN providers.
func (c *CDNAllowlist) ProviderCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.providers)
}

// DomainCount returns the total number of CDN domain patterns tracked.
func (c *CDNAllowlist) DomainCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.exactDomains) + len(c.suffixes)
}

// Providers returns a copy of the current provider list.
func (c *CDNAllowlist) Providers() []CDNProvider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]CDNProvider, len(c.providers))
	copy(result, c.providers)
	return result
}

// loadProviders adds multiple providers (caller should hold no lock or this is init-time).
func (c *CDNAllowlist) loadProviders(providers []CDNProvider) {
	for _, p := range providers {
		c.addProviderLocked(p)
	}
}

// addProviderLocked adds a single provider. Caller must hold c.mu write lock or be in init.
func (c *CDNAllowlist) addProviderLocked(provider CDNProvider) {
	c.providers = append(c.providers, provider)

	for _, pattern := range provider.Domains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}

		if strings.HasPrefix(pattern, "*.") {
			// Wildcard pattern → suffix entry
			suffix := strings.TrimPrefix(pattern, "*") // e.g., ".cloudflare.com"
			c.suffixes = append(c.suffixes, suffixEntry{
				suffix:   suffix,
				provider: provider.Name,
			})
			// Also add base domain as exact match
			baseDomain := strings.TrimPrefix(suffix, ".")
			if baseDomain != "" {
				c.exactDomains[baseDomain] = provider.Name
			}
		} else {
			// Exact domain pattern
			c.exactDomains[pattern] = provider.Name
		}
	}
}
