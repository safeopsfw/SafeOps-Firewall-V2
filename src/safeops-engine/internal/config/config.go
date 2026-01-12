package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration
type Config struct {
	Logging    LoggingConfig    `yaml:"logging"`
	API        APIConfig        `yaml:"api"`
	DNSProxy   DNSProxyConfig   `yaml:"dnsproxy"`
	MITM       MITMConfig       `yaml:"mitm"`
	Classifier ClassifierConfig `yaml:"classifier"`
	NAT        NATConfig        `yaml:"nat"`
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

// LoadDefault returns hardcoded default configuration
func LoadDefault() *Config {
	return &Config{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   "D:/SafeOpsFV2/data/logs/engine.log",
		},
		API: APIConfig{
			Address: "0.0.0.0",
			Port:    9002,
		},
		DNSProxy: DNSProxyConfig{
			Enabled:       true,
			BinaryPath:    "D:/SafeOpsFV2/bin/dnsproxy/windows-amd64/dnsproxy.exe",
			ConfigPath:    "D:/SafeOpsFV2/src/safeops-engine/configs/dnsproxy.yaml",
			ListenPort:    15353,
			FallbackPorts: []int{25353, 35353, 45353},
		},
		MITM: MITMConfig{
			Enabled:    true,
			BinaryPath: "mitmdump",
			AddonPath:  "",
			ListenPort: 8080,
			Mode:       "regular",
		},
		Classifier: ClassifierConfig{
			GamingPorts: []int{
				27000, 27015, 27016, 27030, 27031, 27036, // Steam
				9000, 9001, 9002, 9003, // Epic Games
				1119, 6113, // Battle.net
				3074,             // Xbox Live
				3478, 3479, 3658, // PlayStation
			},
			VoIPPorts: []int{
				3478, 3479, // Discord
				50000, 50019, // Teams
				8801, 8810, // Zoom
				16384, 32767, // WebRTC
			},
			StreamingPorts: []int{443},
			BypassDomains: []string{
				"steampowered.com",
				"epicgames.com",
				"discord.gg",
				"discord.com",
				"twitch.tv",
				"youtube.com",
				"googlevideo.com",
			},
		},
		NAT: NATConfig{
			Enabled:        true,
			ExternalIP:     "",
			PortRangeStart: 60000,
			PortRangeEnd:   65535,
		},
	}
}
