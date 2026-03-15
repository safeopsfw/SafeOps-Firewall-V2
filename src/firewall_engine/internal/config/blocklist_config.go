package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// ============================================================================
// BlocklistConfig — loaded from configs/blocklist.toml
// ============================================================================

// BlocklistConfig is the top-level blocklist configuration.
// This is the single source of truth for all blocking rules.
// It can be edited via the TOML file or the web UI (Phase 10).
type BlocklistConfig struct {
	Domains     BlocklistDomainsConfig     `toml:"domains"`
	IPs         BlocklistIPsConfig         `toml:"ips"`
	ThreatIntel BlocklistThreatIntelConfig `toml:"threat_intel"`
	Geo         BlocklistGeoConfig         `toml:"geo"`
	Enforcement BlocklistEnforcementConfig `toml:"enforcement"`
	Whitelist   BlocklistWhitelistConfig   `toml:"whitelist"`
}

// ============================================================================
// Domain blocking
// ============================================================================

// BlocklistDomainsConfig controls all domain-level blocking.
type BlocklistDomainsConfig struct {
	Enabled     bool                         `toml:"enabled"`
	DomainsFile string                       `toml:"domains_file"` // relative to configs/
	Categories  BlocklistCategoriesConfig     `toml:"categories"`
	CDN         BlocklistCDNConfig            `toml:"cdn"`
}

// BlocklistCategoriesConfig toggles individual domain categories on/off.
type BlocklistCategoriesConfig struct {
	SocialMedia bool `toml:"social_media"`
	Streaming   bool `toml:"streaming"`
	Gaming      bool `toml:"gaming"`
	Ads         bool `toml:"ads"`
	Trackers    bool `toml:"trackers"`
	Adult       bool `toml:"adult"`
	Gambling    bool `toml:"gambling"`
	VPNProxy    bool `toml:"vpn_proxy"`
}

// EnabledCategories returns a list of category names that are enabled.
// These names match the keys used by rules.GetCategoryPatterns().
func (c *BlocklistCategoriesConfig) EnabledCategories() []string {
	var cats []string
	if c.SocialMedia {
		cats = append(cats, "social_media")
	}
	if c.Streaming {
		cats = append(cats, "streaming")
	}
	if c.Gaming {
		cats = append(cats, "gaming")
	}
	if c.Ads {
		cats = append(cats, "ads")
	}
	if c.Trackers {
		cats = append(cats, "trackers")
	}
	if c.Adult {
		cats = append(cats, "adult")
	}
	if c.Gambling {
		cats = append(cats, "gambling")
	}
	if c.VPNProxy {
		cats = append(cats, "vpn_proxy")
	}
	return cats
}

// CategoryCount returns how many categories are enabled.
func (c *BlocklistCategoriesConfig) CategoryCount() int {
	return len(c.EnabledCategories())
}

// BlocklistCDNConfig controls CDN-aware enforcement behavior.
type BlocklistCDNConfig struct {
	EnforceDNSOnly   bool     `toml:"enforce_dns_only"`
	CustomCDNDomains []string `toml:"custom_cdn_domains"`
}

// ============================================================================
// IP blocking
// ============================================================================

// BlocklistIPsConfig controls IP-level blocking (manual + threat intel).
type BlocklistIPsConfig struct {
	Enabled        bool     `toml:"enabled"`
	BlockedIPs     []string `toml:"blocked_ips"`
	BlockedCIDRs   []string `toml:"blocked_cidrs"`
	BlockedIPsFile string   `toml:"blocked_ips_file"` // plain-text file with IPs and CIDRs, one per line
}

// ============================================================================
// Threat intel thresholds
// ============================================================================

// BlocklistThreatIntelConfig controls threat intelligence behavior.
type BlocklistThreatIntelConfig struct {
	Enabled                  bool `toml:"enabled"`
	IPBlockThreshold         int  `toml:"ip_block_threshold"`
	DomainBlockThreshold     int  `toml:"domain_block_threshold"`
	BlockAnonymizers         bool `toml:"block_anonymizers"`
	AnonymizerBlockThreshold int  `toml:"anonymizer_block_threshold"`
	// MaliciousVisitThreshold: auto-block a threat-intel-flagged domain after N visits.
	// First N-1 visits fire ALERT only. At N visits the domain is promoted to the
	// runtime config blocklist (in-memory). 0 = disabled (alert-only forever).
	MaliciousVisitThreshold int `toml:"malicious_visit_threshold"`
}

// ============================================================================
// Geo blocking overrides
// ============================================================================

// BlocklistGeoConfig provides quick-toggle geo overrides (merged with geoip.toml).
type BlocklistGeoConfig struct {
	Enabled               bool     `toml:"enabled"`
	ExtraBlockedCountries []string `toml:"extra_blocked_countries"`
	ExtraBlockedASNs      []uint32 `toml:"extra_blocked_asns"`
}

// NormalizedExtraCountries returns country codes in uppercase.
func (g *BlocklistGeoConfig) NormalizedExtraCountries() []string {
	result := make([]string, 0, len(g.ExtraBlockedCountries))
	for _, cc := range g.ExtraBlockedCountries {
		cc = strings.TrimSpace(strings.ToUpper(cc))
		if cc != "" && len(cc) == 2 {
			result = append(result, cc)
		}
	}
	return result
}

// ============================================================================
// Enforcement
// ============================================================================

// BlocklistEnforcementConfig controls global enforcement behavior.
type BlocklistEnforcementConfig struct {
	DNSRedirectIP       string `toml:"dns_redirect_ip"`
	BlockCacheTTLSeconds int   `toml:"block_cache_ttl_seconds"`
	LogAllBlocks         bool  `toml:"log_all_blocks"`
}

// ============================================================================
// Whitelist (global bypass)
// ============================================================================

// BlocklistWhitelistConfig defines IPs, CIDRs, and domains that bypass ALL blocking.
type BlocklistWhitelistConfig struct {
	IPs          []string `toml:"ips"`
	CIDRs        []string `toml:"cidrs"`
	Domains      []string `toml:"domains"`
	DomainsFile  string   `toml:"domains_file"`  // plain-text file with whitelisted domains, one per line
}

// ============================================================================
// Parsed blocklist (pre-computed lookup structures for runtime)
// ============================================================================

// ParsedBlocklist holds pre-computed data structures for fast runtime lookups.
// Created from BlocklistConfig.Parse() — used by the packet handler and domain filter.
type ParsedBlocklist struct {
	// Domain blocking
	DomainsEnabled     bool
	DomainsFilePath    string   // absolute path to domains.txt
	BlockedCategories  []string // list of enabled category names
	CDNEnforceDNSOnly  bool
	CustomCDNDomains   []string

	// IP blocking
	IPsEnabled      bool
	ManualIPs       map[string]bool // O(1) lookup for manually blocked IPs
	ManualCIDRs     []*net.IPNet   // manually blocked CIDRs
	BlockedIPsFile  string         // absolute path to blocked_ips.txt (for hot-reload)

	// Threat intel thresholds
	ThreatIntelEnabled       bool
	IPBlockThreshold         int
	DomainBlockThreshold     int
	BlockAnonymizers         bool
	AnonymizerBlockThreshold int
	MaliciousVisitThreshold  int // auto-block after N visits; 0 = disabled

	// Geo overrides
	GeoEnabled            bool
	ExtraBlockedCountries []string // uppercase ISO 3166-1 alpha-2
	ExtraBlockedASNs      []uint32

	// Enforcement
	DNSRedirectIP        string
	BlockCacheTTLSeconds int
	LogAllBlocks         bool

	// Whitelist (global bypass)
	WhitelistIPs          map[string]bool
	WhitelistCIDRs        []*net.IPNet
	WhitelistDomains      map[string]bool // normalized lowercase
	WhitelistDomainsFile  string          // absolute path to whitelist_domains.txt (for hot-reload)
}

// Parse converts BlocklistConfig into ParsedBlocklist for fast runtime lookups.
// Validates all IP addresses and CIDRs during parsing.
func (b *BlocklistConfig) Parse(configDir string) (*ParsedBlocklist, error) {
	pb := &ParsedBlocklist{
		// Domains
		DomainsEnabled:    b.Domains.Enabled,
		BlockedCategories: b.Domains.Categories.EnabledCategories(),
		CDNEnforceDNSOnly: b.Domains.CDN.EnforceDNSOnly,
		CustomCDNDomains:  b.Domains.CDN.CustomCDNDomains,

		// IPs
		IPsEnabled: b.IPs.Enabled,
		ManualIPs:  make(map[string]bool),

		// Threat intel
		ThreatIntelEnabled:       b.ThreatIntel.Enabled,
		IPBlockThreshold:         b.ThreatIntel.IPBlockThreshold,
		DomainBlockThreshold:     b.ThreatIntel.DomainBlockThreshold,
		BlockAnonymizers:         b.ThreatIntel.BlockAnonymizers,
		AnonymizerBlockThreshold: b.ThreatIntel.AnonymizerBlockThreshold,
		MaliciousVisitThreshold:  b.ThreatIntel.MaliciousVisitThreshold,

		// Geo
		GeoEnabled:            b.Geo.Enabled,
		ExtraBlockedCountries: b.Geo.NormalizedExtraCountries(),
		ExtraBlockedASNs:      b.Geo.ExtraBlockedASNs,

		// Enforcement
		DNSRedirectIP:        b.Enforcement.DNSRedirectIP,
		BlockCacheTTLSeconds: b.Enforcement.BlockCacheTTLSeconds,
		LogAllBlocks:         b.Enforcement.LogAllBlocks,

		// Whitelist
		WhitelistIPs:     make(map[string]bool),
		WhitelistDomains: make(map[string]bool),
	}

	// Resolve domains file path (relative to config dir)
	if b.Domains.DomainsFile != "" {
		pb.DomainsFilePath = resolveRelativePath(configDir, b.Domains.DomainsFile)
	}

	// Validate + parse manual blocked IPs
	for _, ipStr := range b.IPs.BlockedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			return nil, fmt.Errorf("invalid blocked IP in blocklist.toml: %q", ipStr)
		}
		pb.ManualIPs[parsed.String()] = true
	}

	// Validate + parse manual blocked CIDRs
	for _, cidrStr := range b.IPs.BlockedCIDRs {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked CIDR in blocklist.toml %q: %w", cidrStr, err)
		}
		pb.ManualCIDRs = append(pb.ManualCIDRs, ipNet)
	}

	// Load IPs/CIDRs from blocked_ips_file (if configured)
	if b.IPs.BlockedIPsFile != "" {
		pb.BlockedIPsFile = resolveRelativePath(configDir, b.IPs.BlockedIPsFile)
		fileIPs, fileCIDRs, err := loadIPsFromFile(pb.BlockedIPsFile)
		if err != nil {
			// Non-fatal: log warning but continue
			fmt.Printf("Warning: blocked_ips_file %s: %v\n", pb.BlockedIPsFile, err)
		} else {
			for ip := range fileIPs {
				pb.ManualIPs[ip] = true
			}
			pb.ManualCIDRs = append(pb.ManualCIDRs, fileCIDRs...)
		}
	}

	// Validate DNS redirect IP
	if pb.DNSRedirectIP != "" {
		if net.ParseIP(pb.DNSRedirectIP) == nil {
			return nil, fmt.Errorf("invalid dns_redirect_ip in blocklist.toml: %q", pb.DNSRedirectIP)
		}
	} else {
		pb.DNSRedirectIP = "127.0.0.1" // sensible default
	}

	// Validate block cache TTL
	if pb.BlockCacheTTLSeconds <= 0 {
		pb.BlockCacheTTLSeconds = 120 // 2 minute default
	}

	// Validate threat intel thresholds (clamp to 0-100)
	pb.IPBlockThreshold = clampThreshold(pb.IPBlockThreshold)
	pb.DomainBlockThreshold = clampThreshold(pb.DomainBlockThreshold)
	pb.AnonymizerBlockThreshold = clampThreshold(pb.AnonymizerBlockThreshold)

	// Parse whitelist IPs
	for _, ipStr := range b.Whitelist.IPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			return nil, fmt.Errorf("invalid whitelist IP in blocklist.toml: %q", ipStr)
		}
		pb.WhitelistIPs[parsed.String()] = true
	}

	// Parse whitelist CIDRs
	for _, cidrStr := range b.Whitelist.CIDRs {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist CIDR in blocklist.toml %q: %w", cidrStr, err)
		}
		pb.WhitelistCIDRs = append(pb.WhitelistCIDRs, ipNet)
	}

	// Parse whitelist domains (normalize to lowercase, trim trailing dots)
	for _, dom := range b.Whitelist.Domains {
		dom = strings.TrimSpace(strings.ToLower(dom))
		dom = strings.TrimSuffix(dom, ".")
		if dom != "" {
			pb.WhitelistDomains[dom] = true
		}
	}

	// Load whitelist domains from file (if configured)
	if b.Whitelist.DomainsFile != "" {
		pb.WhitelistDomainsFile = resolveRelativePath(configDir, b.Whitelist.DomainsFile)
		fileDomains, err := loadDomainsFromFile(pb.WhitelistDomainsFile)
		if err != nil {
			fmt.Printf("Warning: whitelist domains_file %s: %v\n", pb.WhitelistDomainsFile, err)
		} else {
			for dom := range fileDomains {
				pb.WhitelistDomains[dom] = true
			}
		}
	}

	return pb, nil
}

// IsIPWhitelisted checks if an IP is in the blocklist whitelist.
func (p *ParsedBlocklist) IsIPWhitelisted(ipStr string) bool {
	if p.WhitelistIPs[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range p.WhitelistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsDomainWhitelisted checks if a domain is in the blocklist whitelist.
// Also checks if any parent domain is whitelisted (e.g., whitelisting "example.com"
// also whitelists "sub.example.com").
func (p *ParsedBlocklist) IsDomainWhitelisted(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return false
	}

	// Exact match
	if p.WhitelistDomains[domain] {
		return true
	}

	// Parent domain match: "sub.example.com" → check "example.com"
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if p.WhitelistDomains[parent] {
			return true
		}
	}

	return false
}

// IsIPManuallyBlocked checks if an IP is in the manual block list.
func (p *ParsedBlocklist) IsIPManuallyBlocked(ipStr string) bool {
	if p.ManualIPs[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range p.ManualCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ============================================================================
// Default config + loader
// ============================================================================

// DefaultBlocklistConfig returns sensible defaults with everything enabled
// but no actual blocking rules (empty lists). This is the "clean slate" config.
func DefaultBlocklistConfig() *BlocklistConfig {
	return &BlocklistConfig{
		Domains: BlocklistDomainsConfig{
			Enabled:     true,
			DomainsFile: "domains.txt",
			Categories: BlocklistCategoriesConfig{
				SocialMedia: false,
				Streaming:   false,
				Gaming:      false,
				Ads:         false,
				Trackers:    false,
				Adult:       false,
				Gambling:    false,
				VPNProxy:    false,
			},
			CDN: BlocklistCDNConfig{
				EnforceDNSOnly:   true,
				CustomCDNDomains: []string{},
			},
		},
		IPs: BlocklistIPsConfig{
			Enabled:        true,
			BlockedIPs:     []string{},
			BlockedCIDRs:   []string{},
			BlockedIPsFile: "blocked_ips.txt",
		},
		ThreatIntel: BlocklistThreatIntelConfig{
			Enabled:                  true,
			IPBlockThreshold:         50,
			DomainBlockThreshold:     50,
			BlockAnonymizers:         false,
			AnonymizerBlockThreshold: 70,
			MaliciousVisitThreshold:  10,
		},
		Geo: BlocklistGeoConfig{
			Enabled:               true,
			ExtraBlockedCountries: []string{},
			ExtraBlockedASNs:      []uint32{},
		},
		Enforcement: BlocklistEnforcementConfig{
			DNSRedirectIP:        "127.0.0.1",
			BlockCacheTTLSeconds: 120,
			LogAllBlocks:         true,
		},
		Whitelist: BlocklistWhitelistConfig{
			IPs:         []string{},
			CIDRs:       []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			Domains:     []string{},
			DomainsFile: "whitelist_domains.txt",
		},
	}
}

// LoadBlocklistConfigFromFile loads blocklist.toml from a path.
// Returns defaults if the file doesn't exist (not an error).
func LoadBlocklistConfigFromFile(path string) (*BlocklistConfig, error) {
	cfg := DefaultBlocklistConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // File missing → use defaults
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return cfg, nil
}

// ============================================================================
// Helpers
// ============================================================================

// clampThreshold clamps a threshold to 0-100.
func clampThreshold(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// loadIPsFromFile reads a plain-text file with one IP or CIDR per line.
// Lines starting with # or // are comments. Blank lines are skipped.
// Returns separate maps for IPs and slice for CIDRs.
func loadIPsFromFile(path string) (map[string]bool, []*net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil // file missing = empty list, not an error
		}
		return nil, nil, err
	}
	defer f.Close()

	ips := make(map[string]bool)
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				continue // skip invalid CIDRs
			}
			cidrs = append(cidrs, ipNet)
		} else {
			parsed := net.ParseIP(line)
			if parsed != nil {
				ips[parsed.String()] = true
			}
		}
	}

	return ips, cidrs, scanner.Err()
}

// loadDomainsFromFile reads a plain-text file with one domain per line.
// Lines starting with # or // are comments. Blank lines are skipped.
// Domains are normalized to lowercase with trailing dots stripped.
func loadDomainsFromFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // file missing = empty list
		}
		return nil, err
	}
	defer f.Close()

	domains := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		dom := strings.ToLower(line)
		dom = strings.TrimSuffix(dom, ".")
		if dom != "" {
			domains[dom] = true
		}
	}

	return domains, scanner.Err()
}

// resolveRelativePath resolves a path relative to a base directory.
// If the path is already absolute, it's returned as-is.
func resolveRelativePath(baseDir, path string) string {
	if path == "" {
		return ""
	}
	// Check if already absolute (handles both / and C:\)
	if len(path) > 0 && (path[0] == '/' || path[0] == '\\') {
		return path
	}
	if len(path) > 1 && path[1] == ':' {
		return path
	}
	return baseDir + string(os.PathSeparator) + path
}
