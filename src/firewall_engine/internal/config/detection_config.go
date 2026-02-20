package config

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

// DetectionConfig is loaded from configs/detection.toml
type DetectionConfig struct {
	DDoS       DDoSConfig       `toml:"ddos"`
	RateLimit  RateLimitConfig  `toml:"rate_limit"`
	BruteForce BruteForceConfig `toml:"brute_force"`
	PortScan   PortScanConfig   `toml:"port_scan"`
	Baseline   BaselineConfig   `toml:"baseline"`
	Whitelist  WhitelistConfig  `toml:"whitelist"`
}

type DDoSConfig struct {
	Enabled                  bool    `toml:"enabled"`
	SYNRateThreshold         int     `toml:"syn_rate_threshold"`
	UDPRateThreshold         int     `toml:"udp_rate_threshold"`
	ICMPRateThreshold        int     `toml:"icmp_rate_threshold"`
	ConnectionRatioThreshold float64 `toml:"connection_ratio_threshold"`
	BanDurationMinutes       int     `toml:"ban_duration_minutes"`
	MaxBanDurationHours      int     `toml:"max_ban_duration_hours"`
	EscalationMultiplier     int     `toml:"escalation_multiplier"`
	WindowSeconds            int     `toml:"window_seconds"`
}

type RateLimitConfig struct {
	Enabled                bool `toml:"enabled"`
	DefaultRate            int  `toml:"default_rate"`
	BurstSize              int  `toml:"burst_size"`
	GlobalRate             int  `toml:"global_rate"`
	CleanupIntervalSeconds int  `toml:"cleanup_interval_seconds"`
}

type BruteForceConfig struct {
	Enabled       bool                        `toml:"enabled"`
	WindowSeconds int                         `toml:"window_seconds"`
	Services      map[string]BruteForceService `toml:"services"`
}

type BruteForceService struct {
	Port          int `toml:"port"`
	MaxFailures   int `toml:"max_failures"`
	WindowSeconds int `toml:"window_seconds"`
}

type PortScanConfig struct {
	Enabled             bool `toml:"enabled"`
	PortThreshold       int  `toml:"port_threshold"`
	WindowSeconds       int  `toml:"window_seconds"`
	BanDurationMinutes  int  `toml:"ban_duration_minutes"`
	SequentialThreshold int  `toml:"sequential_threshold"`
}

type BaselineConfig struct {
	Enabled              bool    `toml:"enabled"`
	WindowMinutes        int     `toml:"window_minutes"`
	DeviationThreshold   float64 `toml:"deviation_threshold"`
	WarmupMinutes        int     `toml:"warmup_minutes"`
	UpdateIntervalSeconds int    `toml:"update_interval_seconds"`
}

type WhitelistConfig struct {
	TrustedIPs   []string `toml:"trusted_ips"`
	TrustedCIDRs []string `toml:"trusted_cidrs"`
	CDNCIDRs     []string `toml:"cdn_cidrs"`
}

// ParsedWhitelist holds pre-parsed IP and CIDR entries for fast matching
type ParsedWhitelist struct {
	IPs   map[string]bool
	CIDRs []*net.IPNet
}

// Parse converts WhitelistConfig into ParsedWhitelist for runtime lookups
func (w *WhitelistConfig) Parse() (*ParsedWhitelist, error) {
	pw := &ParsedWhitelist{
		IPs: make(map[string]bool),
	}

	for _, ip := range w.TrustedIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, fmt.Errorf("invalid whitelist IP: %s", ip)
		}
		pw.IPs[parsed.String()] = true
	}

	allCIDRs := append(w.TrustedCIDRs, w.CDNCIDRs...)
	for _, cidr := range allCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist CIDR %s: %w", cidr, err)
		}
		pw.CIDRs = append(pw.CIDRs, ipNet)
	}

	return pw, nil
}

// Contains checks if an IP is in the whitelist (O(1) for IPs, O(n) for CIDRs)
func (pw *ParsedWhitelist) Contains(ipStr string) bool {
	if pw.IPs[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range pw.CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// DefaultDetectionConfig returns sensible defaults
func DefaultDetectionConfig() *DetectionConfig {
	return &DetectionConfig{
		DDoS: DDoSConfig{
			Enabled:                  true,
			SYNRateThreshold:         1000,
			UDPRateThreshold:         5000,
			ICMPRateThreshold:        100,
			ConnectionRatioThreshold: 0.01,
			BanDurationMinutes:       30,
			MaxBanDurationHours:      720,
			EscalationMultiplier:     4,
			WindowSeconds:            10,
		},
		RateLimit: RateLimitConfig{
			Enabled:                true,
			DefaultRate:            1000,
			BurstSize:              2000,
			GlobalRate:             100000,
			CleanupIntervalSeconds: 60,
		},
		BruteForce: BruteForceConfig{
			Enabled:       true,
			WindowSeconds: 120,
			Services: map[string]BruteForceService{
				"ssh":      {Port: 22, MaxFailures: 5, WindowSeconds: 120},
				"rdp":      {Port: 3389, MaxFailures: 3, WindowSeconds: 60},
				"ftp":      {Port: 21, MaxFailures: 5, WindowSeconds: 120},
				"smtp":     {Port: 25, MaxFailures: 3, WindowSeconds: 300},
				"mysql":    {Port: 3306, MaxFailures: 3, WindowSeconds: 60},
				"postgres": {Port: 5432, MaxFailures: 3, WindowSeconds: 60},
				"mssql":    {Port: 1433, MaxFailures: 3, WindowSeconds: 60},
			},
		},
		PortScan: PortScanConfig{
			Enabled:             true,
			PortThreshold:       100,
			WindowSeconds:       10,
			BanDurationMinutes:  15,
			SequentialThreshold: 20,
		},
		Baseline: BaselineConfig{
			Enabled:              true,
			WindowMinutes:        60,
			DeviationThreshold:   3.0,
			WarmupMinutes:        10,
			UpdateIntervalSeconds: 10,
		},
		Whitelist: WhitelistConfig{
			TrustedIPs:   []string{"127.0.0.1", "::1"},
			TrustedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			CDNCIDRs:     []string{},
		},
	}
}

// LoadDetectionConfigFromFile loads detection.toml from a path
func LoadDetectionConfigFromFile(path string) (*DetectionConfig, error) {
	cfg := DefaultDetectionConfig()

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
