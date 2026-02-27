package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the SIEM forwarder
type Config struct {
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	LogBasePath   string              `yaml:"log_base_path"`
	LogFiles      []LogFileConfig     `yaml:"log_files"`
	Retention     RetentionConfig     `yaml:"retention"`
	PositionDB    PositionDBConfig    `yaml:"position_db"`
	Tailer        TailerConfig        `yaml:"tailer"`
}

// ElasticsearchConfig holds Elasticsearch connection settings
type ElasticsearchConfig struct {
	Hosts         []string      `yaml:"hosts"`
	Username      string        `yaml:"username"`
	Password      string        `yaml:"password"`
	BulkSize      int           `yaml:"bulk_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// LogFileConfig defines a log file to monitor
type LogFileConfig struct {
	Path        string `yaml:"path"`
	IndexPrefix string `yaml:"index_prefix"`
	Type        string `yaml:"type"`
}

// PositionDBConfig holds position tracking settings
type PositionDBConfig struct {
	Path         string        `yaml:"path"`
	SaveInterval time.Duration `yaml:"save_interval"`
}

// TailerConfig holds tailer performance settings
type TailerConfig struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	MaxLineSize  int           `yaml:"max_line_size"`
}

// RetentionConfig holds data retention settings
type RetentionConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxDays       int           `yaml:"max_days"`
	CheckInterval time.Duration `yaml:"check_interval"`
}

// Load reads and parses the configuration file
func Load(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.Elasticsearch.BulkSize == 0 {
		cfg.Elasticsearch.BulkSize = 500
	}
	if cfg.Elasticsearch.FlushInterval == 0 {
		cfg.Elasticsearch.FlushInterval = 5 * time.Second
	}
	if cfg.Tailer.PollInterval == 0 {
		cfg.Tailer.PollInterval = 500 * time.Millisecond
	}
	if cfg.Tailer.MaxLineSize == 0 {
		cfg.Tailer.MaxLineSize = 1024 * 1024 // 1MB
	}
	if cfg.PositionDB.SaveInterval == 0 {
		cfg.PositionDB.SaveInterval = 10 * time.Second
	}
	if cfg.Retention.MaxDays == 0 {
		cfg.Retention.MaxDays = 14
	}
	if cfg.Retention.CheckInterval == 0 {
		cfg.Retention.CheckInterval = 6 * time.Hour
	}

	return &cfg, nil
}

// ResolveLogPath returns the full path to a log file
func (c *Config) ResolveLogPath(relativePath string) string {
	return filepath.Join(c.LogBasePath, relativePath)
}
