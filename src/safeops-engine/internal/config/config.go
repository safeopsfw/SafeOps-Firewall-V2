package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration
type Config struct {
	Logging   LoggingConfig   `yaml:"logging"`
	API       APIConfig       `yaml:"api"`
	DNSProxy  DNSProxyConfig  `yaml:"dnsproxy"`
	MITM      MITMConfig      `yaml:"mitm"`
	Classifier ClassifierConfig `yaml:"classifier"`
	NAT       NATConfig       `yaml:"nat"`
}

// LoggingConfig for logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

// APIConfig for HTTP API server
type APIConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// DNSProxyConfig for dnsproxy process
type DNSProxyConfig struct {
	Enabled       bool   `yaml:"enabled"`
	BinaryPath    string `yaml:"binary_path"`
	ConfigPath    string `yaml:"config_path"`
	ListenPort    int    `yaml:"listen_port"`
	FallbackPorts []int  `yaml:"fallback_ports"`
}

// MITMConfig for mitmproxy process
type MITMConfig struct {
	Enabled    bool   `yaml:"enabled"`
	BinaryPath string `yaml:"binary_path"`
	AddonPath  string `yaml:"addon_path"`
	ListenPort int    `yaml:"listen_port"`
	Mode       string `yaml:"mode"` // socks5, transparent, etc.
}

// ClassifierConfig for traffic classification
type ClassifierConfig struct {
	GamingPorts    []int    `yaml:"gaming_ports"`
	VoIPPorts      []int    `yaml:"voip_ports"`
	StreamingPorts []int    `yaml:"streaming_ports"`
	BypassDomains  []string `yaml:"bypass_domains"`
}

// NATConfig for NAT engine
type NATConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ExternalIP     string `yaml:"external_ip"`
	PortRangeStart int    `yaml:"port_range_start"`
	PortRangeEnd   int    `yaml:"port_range_end"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}
