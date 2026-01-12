package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Capture struct {
		Interfaces     []string `yaml:"interfaces"`
		Promiscuous    bool     `yaml:"promiscuous"`
		SnapshotLength int32    `yaml:"snapshot_length"`
		BPFFilter      string   `yaml:"bpf_filter"`
	} `yaml:"capture"`

	Logging struct {
		LogPath      string `yaml:"log_path"`
		BatchSize    int    `yaml:"batch_size"`
		CycleMinutes int    `yaml:"cycle_minutes"` // 5-minute overwrite cycle
	} `yaml:"logging"`

	Flow struct {
		TimeoutSeconds         int `yaml:"timeout_seconds"`
		CleanupIntervalSeconds int `yaml:"cleanup_interval_seconds"`
	} `yaml:"flow"`

	Deduplication struct {
		Enabled       bool  `yaml:"enabled"`
		WindowSeconds int64 `yaml:"window_seconds"`
		CacheSize     int   `yaml:"cache_size"`
	} `yaml:"deduplication"`

	Process struct {
		CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
	} `yaml:"process"`

	TLS struct {
		Enabled    bool   `yaml:"enabled"`
		KeylogFile string `yaml:"keylog_file"`
	} `yaml:"tls"`

	Stats struct {
		DisplayIntervalSeconds int `yaml:"display_interval_seconds"`
	} `yaml:"stats"`

	Hotspot struct {
		Enabled bool   `yaml:"enabled"`
		Subnet  string `yaml:"subnet"`
	} `yaml:"hotspot"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.Capture.SnapshotLength == 0 {
		cfg.Capture.SnapshotLength = 1600
	}
	if cfg.Logging.BatchSize == 0 {
		cfg.Logging.BatchSize = 75
	}
	if cfg.Logging.CycleMinutes == 0 {
		cfg.Logging.CycleMinutes = 5 // Default: 5-minute cycle
	}
	if cfg.Flow.TimeoutSeconds == 0 {
		cfg.Flow.TimeoutSeconds = 60
	}
	if cfg.Flow.CleanupIntervalSeconds == 0 {
		cfg.Flow.CleanupIntervalSeconds = 30
	}
	if cfg.Deduplication.WindowSeconds == 0 {
		cfg.Deduplication.WindowSeconds = 60
	}
	if cfg.Deduplication.CacheSize == 0 {
		cfg.Deduplication.CacheSize = 10000
	}
	if cfg.Process.CacheTTLSeconds == 0 {
		cfg.Process.CacheTTLSeconds = 10
	}
	if cfg.Stats.DisplayIntervalSeconds == 0 {
		cfg.Stats.DisplayIntervalSeconds = 120
	}

	return &cfg, nil
}

// LoadDefault returns hardcoded default configuration
func LoadDefault() *Config {
	cfg := &Config{}

	// Capture settings
	cfg.Capture.Interfaces = []string{} // All active interfaces
	cfg.Capture.Promiscuous = true
	cfg.Capture.SnapshotLength = 1600
	cfg.Capture.BPFFilter = ""

	// Logging settings
	cfg.Logging.LogPath = "D:/SafeOpsFV2/logs/network_packets_master.jsonl"
	cfg.Logging.BatchSize = 75
	cfg.Logging.CycleMinutes = 5

	// Flow settings
	cfg.Flow.TimeoutSeconds = 60
	cfg.Flow.CleanupIntervalSeconds = 30

	// Deduplication settings
	cfg.Deduplication.Enabled = true
	cfg.Deduplication.WindowSeconds = 30
	cfg.Deduplication.CacheSize = 10000

	// Process settings
	cfg.Process.CacheTTLSeconds = 10

	// TLS settings
	cfg.TLS.Enabled = true
	cfg.TLS.KeylogFile = "D:/SafeOpsFV2/logs/sslkeys.log"

	// Stats settings
	cfg.Stats.DisplayIntervalSeconds = 120

	// Hotspot settings
	cfg.Hotspot.Enabled = true
	cfg.Hotspot.Subnet = "192.168.137.0/24"

	return cfg
}

// GetFlowTimeout returns flow timeout as duration
func (c *Config) GetFlowTimeout() time.Duration {
	return time.Duration(c.Flow.TimeoutSeconds) * time.Second
}

// GetFlowCleanupInterval returns flow cleanup interval as duration
func (c *Config) GetFlowCleanupInterval() time.Duration {
	return time.Duration(c.Flow.CleanupIntervalSeconds) * time.Second
}

// GetProcessCacheTTL returns process cache TTL as duration
func (c *Config) GetProcessCacheTTL() time.Duration {
	return time.Duration(c.Process.CacheTTLSeconds) * time.Second
}

// GetStatsDisplayInterval returns stats display interval as duration
func (c *Config) GetStatsDisplayInterval() time.Duration {
	return time.Duration(c.Stats.DisplayIntervalSeconds) * time.Second
}

// GetLogCycleInterval returns log cycle interval as duration
func (c *Config) GetLogCycleInterval() time.Duration {
	return time.Duration(c.Logging.CycleMinutes) * time.Minute
}
