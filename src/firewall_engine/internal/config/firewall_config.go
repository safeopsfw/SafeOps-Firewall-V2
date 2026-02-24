package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// FirewallConfig is the top-level config loaded from configs/firewall.toml
type FirewallConfig struct {
	Engine      EngineConfig      `toml:"engine"`
	SafeOps     SafeOpsConfig     `toml:"safeops"`
	Database    DatabaseConfig    `toml:"database"`
	Performance PerformanceConfig `toml:"performance"`
	Servers     ServersConfig     `toml:"servers"`
	Logging     LoggingConfig     `toml:"logging"`
}

type EngineConfig struct {
	Version     string `toml:"version"`
	WorkerCount int    `toml:"worker_count"`
	FailOpen    bool   `toml:"fail_open"`
	LogLevel    string `toml:"log_level"`
}

type SafeOpsConfig struct {
	GRPCAddress            string   `toml:"grpc_address"`
	ControlAPIAddress      string   `toml:"control_api_address"`
	SubscriberID           string   `toml:"subscriber_id"`
	Filters                []string `toml:"filters"`
	ReconnectMaxRetries    int      `toml:"reconnect_max_retries"`
	ReconnectBackoffSeconds int     `toml:"reconnect_backoff_seconds"`
}

type DatabaseConfig struct {
	Host                   string         `toml:"host"`
	Port                   int            `toml:"port"`
	User                   string         `toml:"user"`
	Password               string         `toml:"password"`
	DBName                 string         `toml:"dbname"`
	PoolSize               int            `toml:"pool_size"`
	PoolMaxLifetimeMinutes int            `toml:"pool_max_lifetime_minutes"`
	SSLMode                string         `toml:"ssl_mode"`
	Network                NetworkDBConfig `toml:"network"`
}

type NetworkDBConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	PoolSize int    `toml:"pool_size"`
}

type PerformanceConfig struct {
	VerdictCacheSize           int `toml:"verdict_cache_size"`
	VerdictCacheTTLSeconds     int `toml:"verdict_cache_ttl_seconds"`
	VerdictCacheCleanupSeconds int `toml:"verdict_cache_cleanup_seconds"`
	MaxConnections             int `toml:"max_connections"`
	ConnectionCleanupSeconds   int `toml:"connection_cleanup_seconds"`
	PacketBufferSize           int `toml:"packet_buffer_size"`
	ThreatIntelRefreshMinutes  int `toml:"threat_intel_refresh_minutes"`
	GeoIPCacheSize             int `toml:"geoip_cache_size"`
	GeoIPCacheTTLHours         int `toml:"geoip_cache_ttl_hours"`
}

type ServersConfig struct {
	MetricsAddress    string `toml:"metrics_address"`
	MetricsPath       string `toml:"metrics_path"`
	HealthAddress     string `toml:"health_address"`
	ManagementAddress string `toml:"management_address"`
	WebAPIAddress     string `toml:"web_api_address"`
}

type LoggingConfig struct {
	ConsoleLevel     string `toml:"console_level"`
	FileLevel        string `toml:"file_level"`
	AlertLogDir      string `toml:"alert_log_dir"`
	PacketLogDir     string `toml:"packet_log_dir"`
	MaxFileSizeMB    int    `toml:"max_file_size_mb"`
	MaxBackups       int    `toml:"max_backups"`
	CompressRotated  bool   `toml:"compress_rotated"`
}

// DefaultFirewallConfig returns sensible defaults
func DefaultFirewallConfig() *FirewallConfig {
	return &FirewallConfig{
		Engine: EngineConfig{
			Version:     "5.1.0",
			WorkerCount: 8,
			FailOpen:    true,
			LogLevel:    "info",
		},
		SafeOps: SafeOpsConfig{
			GRPCAddress:            "127.0.0.1:50051",
			ControlAPIAddress:      "127.0.0.1:50052",
			SubscriberID:           "firewall-engine",
			Filters:                []string{"tcp", "udp"},
			ReconnectMaxRetries:    5,
			ReconnectBackoffSeconds: 2,
		},
		Database: DatabaseConfig{
			Host:                   "localhost",
			Port:                   5432,
			User:                   "safeops",
			Password:               "admin",
			DBName:                 "threat_intel_db",
			PoolSize:               10,
			PoolMaxLifetimeMinutes: 30,
			SSLMode:                "disable",
			Network: NetworkDBConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "safeops",
				Password: "admin",
				DBName:   "safeops_network",
				PoolSize: 5,
			},
		},
		Performance: PerformanceConfig{
			VerdictCacheSize:           100000,
			VerdictCacheTTLSeconds:     60,
			VerdictCacheCleanupSeconds: 10,
			MaxConnections:             500000,
			ConnectionCleanupSeconds:   300, // 5 minutes
			PacketBufferSize:           100000,
			ThreatIntelRefreshMinutes:  5,
			GeoIPCacheSize:             500000,
			GeoIPCacheTTLHours:         24,
		},
		Servers: ServersConfig{
			MetricsAddress:    ":9090",
			MetricsPath:       "/metrics",
			HealthAddress:     ":8085",
			ManagementAddress: ":50054",
			WebAPIAddress:     ":8443",
		},
		Logging: LoggingConfig{
			ConsoleLevel:    "info",
			FileLevel:       "debug",
			AlertLogDir:     "data/logs/firewall-alerts",
			PacketLogDir:    "data/logs/firewall-packets",
			MaxFileSizeMB:   100,
			MaxBackups:      10,
			CompressRotated: true,
		},
	}
}

// LoadFirewallConfigFromFile loads firewall.toml from a path
func LoadFirewallConfigFromFile(path string) (*FirewallConfig, error) {
	cfg := DefaultFirewallConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Return defaults if file not found
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return cfg, nil
}

// DSN returns a PostgreSQL connection string for the threat intel database
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

// NetworkDSN returns a PostgreSQL connection string for the network database
func (d *DatabaseConfig) NetworkDSN() string {
	n := d.Network
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		n.Host, n.Port, n.User, n.Password, n.DBName)
}

// ResolveAlertLogDir returns absolute path, creating dir if needed
func (l *LoggingConfig) ResolveAlertLogDir(baseDir string) (string, error) {
	dir := l.AlertLogDir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(baseDir, dir)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create alert log dir %s: %w", dir, err)
	}
	return dir, nil
}
