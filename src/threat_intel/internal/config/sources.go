// Package config handles threat feed source configuration
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// FeedSource represents a threat intelligence feed source
type FeedSource struct {
	Name        string            `yaml:"name"`
	URL         string            `yaml:"url"`
	Type        string            `yaml:"type"`   // malicious, phishing, anonymizer, etc.
	Format      string            `yaml:"format"` // csv, json, hostfile, plain, netset
	Enabled     bool              `yaml:"enabled"`
	UpdateFreq  string            `yaml:"update_freq"` // 1h, 6h, 12h, 24h
	Description string            `yaml:"description"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Reputation  string            `yaml:"reputation"` // high, medium, low
	Category    string            `yaml:"category"`
}

// FeedConfig holds multiple feed sources
type FeedConfig struct {
	Sources []FeedSource `yaml:"sources"`
}

// LoadFeedConfig loads feed sources from YAML file
func LoadFeedConfig(path string) (*FeedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg FeedConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadAllFeedConfigs loads all feed configuration files from a directory
func LoadAllFeedConfigs(dir string) ([]FeedSource, error) {
	var allSources []FeedSource

	files := []string{
		"malicious.yaml",
		"phishing.yaml",
		"anonymizers.yaml",
		"geolocation.yaml",
		"asn.yaml",
		"hashes.yaml",
		"reputation.yaml",
	}

	for _, file := range files {
		cfg, err := LoadFeedConfig(dir + "/" + file)
		if err != nil {
			// Skip files that don't exist
			continue
		}
		allSources = append(allSources, cfg.Sources...)
	}

	return allSources, nil
}
