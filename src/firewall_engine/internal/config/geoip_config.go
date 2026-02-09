package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// GeoIPConfig is loaded from configs/geoip.toml
type GeoIPConfig struct {
	Policy     GeoIPPolicyConfig     `toml:"policy"`
	DenyList   GeoIPDenyListConfig   `toml:"deny_list"`
	AllowList  GeoIPAllowListConfig  `toml:"allow_list"`
	ASNBlock   ASNBlockConfig        `toml:"asn_block"`
	Datacenter DatacenterConfig      `toml:"datacenter"`
	Whitelist  GeoIPWhitelistConfig  `toml:"whitelist"`
}

type GeoIPPolicyConfig struct {
	Enabled      bool   `toml:"enabled"`
	Mode         string `toml:"mode"`          // "deny_list" or "allow_list"
	LogBlocked   bool   `toml:"log_blocked"`
	EnrichAlerts bool   `toml:"enrich_alerts"`
}

type GeoIPDenyListConfig struct {
	Countries []string `toml:"countries"`
}

type GeoIPAllowListConfig struct {
	Countries []string `toml:"countries"`
}

type ASNBlockConfig struct {
	Enabled     bool     `toml:"enabled"`
	BlockedASNs []uint32 `toml:"blocked_asns"`
}

type DatacenterConfig struct {
	FlagForeignDatacenter bool   `toml:"flag_foreign_datacenter"`
	HomeCountry           string `toml:"home_country"`
}

type GeoIPWhitelistConfig struct {
	TrustedIPs   []string `toml:"trusted_ips"`
	TrustedCIDRs []string `toml:"trusted_cidrs"`
}

// ParsedGeoPolicy holds pre-computed lookup structures for fast geo-matching
type ParsedGeoPolicy struct {
	Enabled      bool
	IsDenyMode   bool // true = deny_list, false = allow_list
	Countries    map[string]bool
	BlockedASNs  map[uint32]bool
	WhitelistIPs map[string]bool
	WhitelistCIDRs []*net.IPNet
	LogBlocked     bool
	EnrichAlerts   bool
	FlagForeignDC  bool
	HomeCountry    string
}

// Parse converts GeoIPConfig into ParsedGeoPolicy for runtime lookups
func (g *GeoIPConfig) Parse() (*ParsedGeoPolicy, error) {
	pg := &ParsedGeoPolicy{
		Enabled:      g.Policy.Enabled,
		IsDenyMode:   strings.ToLower(g.Policy.Mode) == "deny_list",
		Countries:    make(map[string]bool),
		BlockedASNs:  make(map[uint32]bool),
		WhitelistIPs: make(map[string]bool),
		LogBlocked:   g.Policy.LogBlocked,
		EnrichAlerts: g.Policy.EnrichAlerts,
		FlagForeignDC: g.Datacenter.FlagForeignDatacenter,
		HomeCountry:   strings.ToUpper(g.Datacenter.HomeCountry),
	}

	// Load country list based on mode
	if pg.IsDenyMode {
		for _, c := range g.DenyList.Countries {
			pg.Countries[strings.ToUpper(c)] = true
		}
	} else {
		for _, c := range g.AllowList.Countries {
			pg.Countries[strings.ToUpper(c)] = true
		}
	}

	// Load blocked ASNs
	if g.ASNBlock.Enabled {
		for _, asn := range g.ASNBlock.BlockedASNs {
			pg.BlockedASNs[asn] = true
		}
	}

	// Parse whitelist IPs
	for _, ip := range g.Whitelist.TrustedIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, fmt.Errorf("invalid geoip whitelist IP: %s", ip)
		}
		pg.WhitelistIPs[parsed.String()] = true
	}

	// Parse whitelist CIDRs
	for _, cidr := range g.Whitelist.TrustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid geoip whitelist CIDR %s: %w", cidr, err)
		}
		pg.WhitelistCIDRs = append(pg.WhitelistCIDRs, ipNet)
	}

	return pg, nil
}

// IsCountryBlocked checks if a country code should be blocked
func (pg *ParsedGeoPolicy) IsCountryBlocked(countryCode string) bool {
	if !pg.Enabled {
		return false
	}
	cc := strings.ToUpper(countryCode)
	if pg.IsDenyMode {
		return pg.Countries[cc] // blocked if in deny list
	}
	return !pg.Countries[cc] // blocked if NOT in allow list
}

// IsASNBlocked checks if an ASN is blocked
func (pg *ParsedGeoPolicy) IsASNBlocked(asn uint32) bool {
	return pg.BlockedASNs[asn]
}

// IsWhitelisted checks if an IP bypasses geo-blocking
func (pg *ParsedGeoPolicy) IsWhitelisted(ipStr string) bool {
	if pg.WhitelistIPs[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range pg.WhitelistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsForeignDatacenter checks if traffic from a foreign datacenter should be flagged
func (pg *ParsedGeoPolicy) IsForeignDatacenter(countryCode string) bool {
	if !pg.FlagForeignDC || pg.HomeCountry == "" {
		return false
	}
	return strings.ToUpper(countryCode) != pg.HomeCountry
}

// DefaultGeoIPConfig returns sensible defaults
func DefaultGeoIPConfig() *GeoIPConfig {
	return &GeoIPConfig{
		Policy: GeoIPPolicyConfig{
			Enabled:      true,
			Mode:         "deny_list",
			LogBlocked:   true,
			EnrichAlerts: true,
		},
		DenyList: GeoIPDenyListConfig{
			Countries: []string{},
		},
		AllowList: GeoIPAllowListConfig{
			Countries: []string{},
		},
		ASNBlock: ASNBlockConfig{
			Enabled:     false,
			BlockedASNs: []uint32{},
		},
		Datacenter: DatacenterConfig{
			FlagForeignDatacenter: false,
			HomeCountry:           "IN",
		},
		Whitelist: GeoIPWhitelistConfig{
			TrustedIPs:   []string{},
			TrustedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}
}

// LoadGeoIPConfigFromFile loads geoip.toml from a path
func LoadGeoIPConfigFromFile(path string) (*GeoIPConfig, error) {
	cfg := DefaultGeoIPConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return cfg, nil
}
