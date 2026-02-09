package config

import (
	"fmt"
	"path/filepath"
)

// AllConfig holds all configuration loaded from the configs directory
type AllConfig struct {
	Firewall  *FirewallConfig
	Detection *DetectionConfig
	GeoIP     *GeoIPConfig
	Blocklist *BlocklistConfig
	ConfigDir string // absolute path to resolved config directory
	DataDir   string // absolute path to resolved data directory
}

// LoadAll loads all config files from the given config directory.
// Expects: configDir/firewall.toml, configDir/detection.toml, configDir/geoip.toml
func LoadAll(configDir string) (*AllConfig, error) {
	fw, err := LoadFirewallConfigFromFile(filepath.Join(configDir, "firewall.toml"))
	if err != nil {
		return nil, fmt.Errorf("firewall config: %w", err)
	}

	det, err := LoadDetectionConfigFromFile(filepath.Join(configDir, "detection.toml"))
	if err != nil {
		return nil, fmt.Errorf("detection config: %w", err)
	}

	geo, err := LoadGeoIPConfigFromFile(filepath.Join(configDir, "geoip.toml"))
	if err != nil {
		return nil, fmt.Errorf("geoip config: %w", err)
	}

	bl, err := LoadBlocklistConfigFromFile(filepath.Join(configDir, "blocklist.toml"))
	if err != nil {
		return nil, fmt.Errorf("blocklist config: %w", err)
	}

	dataDir, err := ResolveDataDir()
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}

	return &AllConfig{
		Firewall:  fw,
		Detection: det,
		GeoIP:     geo,
		Blocklist: bl,
		ConfigDir: configDir,
		DataDir:   dataDir,
	}, nil
}

// DomainsFilePath returns the path to the domains blocklist file.
// Uses blocklist.toml's domains_file if configured, otherwise defaults to configs/domains.txt.
func (c *AllConfig) DomainsFilePath() string {
	if c.Blocklist != nil && c.Blocklist.Domains.DomainsFile != "" {
		return resolveRelativePath(c.ConfigDir, c.Blocklist.Domains.DomainsFile)
	}
	return filepath.Join(c.ConfigDir, "domains.txt")
}

// BlocklistFilePath returns the path to configs/blocklist.toml
func (c *AllConfig) BlocklistFilePath() string {
	return filepath.Join(c.ConfigDir, "blocklist.toml")
}

// ParsedBlocklistPolicy returns a pre-computed ParsedBlocklist for runtime use.
// This is a convenience method that parses the blocklist config with the config directory.
func (c *AllConfig) ParsedBlocklistPolicy() (*ParsedBlocklist, error) {
	if c.Blocklist == nil {
		return DefaultBlocklistConfig().Parse(c.ConfigDir)
	}
	return c.Blocklist.Parse(c.ConfigDir)
}

// WhitelistFilePath returns the path to configs/whitelist.txt
func (c *AllConfig) WhitelistFilePath() string {
	return filepath.Join(c.ConfigDir, "whitelist.txt")
}

// AlertLogDir resolves the alert log directory (creates if needed)
func (c *AllConfig) AlertLogDir() (string, error) {
	return ResolveAlertDir(c.Firewall.Logging.AlertLogDir, c.DataDir)
}
