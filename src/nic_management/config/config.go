// Package config implements configuration loading, parsing, validation, and
// management for the NIC Management service. It reads YAML configuration,
// performs environment variable substitution, validates parameters, and
// provides strongly-typed configuration objects to all service components.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// Configuration Types
// =============================================================================

// Config represents the complete NIC Management service configuration.
type Config struct {
	Service            ServiceConfig            `yaml:"service" mapstructure:"service"`
	WANInterfaces      []WANInterfaceConfig     `yaml:"wan_interfaces" mapstructure:"wan_interfaces"`
	LANInterfaces      []LANInterfaceConfig     `yaml:"lan_interfaces" mapstructure:"lan_interfaces"`
	WiFiInterfaces     []WiFiInterfaceConfig    `yaml:"wifi_interfaces" mapstructure:"wifi_interfaces"`
	InterfaceDiscovery InterfaceDiscoveryConfig `yaml:"interface_discovery" mapstructure:"interface_discovery"`
	LoadBalancing      LoadBalancingConfig      `yaml:"load_balancing" mapstructure:"load_balancing"`
	Failover           FailoverConfig           `yaml:"failover" mapstructure:"failover"`
	NAT                NATConfig                `yaml:"nat" mapstructure:"nat"`
	ConnectionTracking ConnectionTrackingConfig `yaml:"connection_tracking" mapstructure:"connection_tracking"`
	PacketForwarding   PacketForwardingConfig   `yaml:"packet_forwarding" mapstructure:"packet_forwarding"`
	Monitoring         MonitoringConfig         `yaml:"monitoring" mapstructure:"monitoring"`
	Database           DatabaseConfig           `yaml:"database" mapstructure:"database"`
	GRPC               GRPCConfig               `yaml:"grpc" mapstructure:"grpc"`
	Integrations       IntegrationsConfig       `yaml:"integrations" mapstructure:"integrations"`
	RustEngine         RustEngineConfig         `yaml:"rust_engine" mapstructure:"rust_engine"`
	Advanced           AdvancedConfig           `yaml:"advanced" mapstructure:"advanced"`

	// Internal
	configPath string
	mu         sync.RWMutex
}

// ServiceConfig holds service metadata.
type ServiceConfig struct {
	Name        string `yaml:"name" mapstructure:"name"`
	Version     string `yaml:"version" mapstructure:"version"`
	Description string `yaml:"description" mapstructure:"description"`
	LogLevel    string `yaml:"log_level" mapstructure:"log_level"`
	LogFormat   string `yaml:"log_format" mapstructure:"log_format"`
	LogOutput   string `yaml:"log_output" mapstructure:"log_output"`
	LogFile     string `yaml:"log_file" mapstructure:"log_file"`
	Environment string `yaml:"environment" mapstructure:"environment"`
}

// WANInterfaceConfig represents WAN interface configuration.
type WANInterfaceConfig struct {
	Name         string             `yaml:"name" mapstructure:"name"`
	Alias        string             `yaml:"alias" mapstructure:"alias"`
	Description  string             `yaml:"description" mapstructure:"description"`
	Priority     int                `yaml:"priority" mapstructure:"priority"`
	Weight       int                `yaml:"weight" mapstructure:"weight"`
	Enabled      bool               `yaml:"enabled" mapstructure:"enabled"`
	StaticConfig *StaticIPConfig    `yaml:"static_config" mapstructure:"static_config"`
	HealthCheck  *HealthCheckConfig `yaml:"health_check" mapstructure:"health_check"`
}

// StaticIPConfig holds static IP configuration.
type StaticIPConfig struct {
	Enabled    bool     `yaml:"enabled" mapstructure:"enabled"`
	IPAddress  string   `yaml:"ip_address" mapstructure:"ip_address"`
	Netmask    string   `yaml:"netmask" mapstructure:"netmask"`
	Gateway    string   `yaml:"gateway" mapstructure:"gateway"`
	DNSServers []string `yaml:"dns_servers" mapstructure:"dns_servers"`
}

// HealthCheckConfig holds per-interface health check settings.
type HealthCheckConfig struct {
	Targets      []string `yaml:"targets" mapstructure:"targets"`
	CheckGateway bool     `yaml:"check_gateway" mapstructure:"check_gateway"`
	CustomURL    string   `yaml:"custom_url" mapstructure:"custom_url"`
}

// LANInterfaceConfig represents LAN interface configuration.
type LANInterfaceConfig struct {
	Name        string            `yaml:"name" mapstructure:"name"`
	Alias       string            `yaml:"alias" mapstructure:"alias"`
	Description string            `yaml:"description" mapstructure:"description"`
	Enabled     bool              `yaml:"enabled" mapstructure:"enabled"`
	VLAN        *VLANConfig       `yaml:"vlan" mapstructure:"vlan"`
	Network     *NetworkConfig    `yaml:"network" mapstructure:"network"`
	DHCPServer  *DHCPServerConfig `yaml:"dhcp_server" mapstructure:"dhcp_server"`
	Isolation   *IsolationConfig  `yaml:"isolation" mapstructure:"isolation"`
}

// VLANConfig holds VLAN configuration.
type VLANConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	ID      int    `yaml:"id" mapstructure:"id"`
	Name    string `yaml:"name" mapstructure:"name"`
}

// NetworkConfig holds network addressing.
type NetworkConfig struct {
	Subnet  string `yaml:"subnet" mapstructure:"subnet"`
	Gateway string `yaml:"gateway" mapstructure:"gateway"`
}

// DHCPServerConfig holds DHCP server settings.
type DHCPServerConfig struct {
	Enabled    bool     `yaml:"enabled" mapstructure:"enabled"`
	RangeStart string   `yaml:"range_start" mapstructure:"range_start"`
	RangeEnd   string   `yaml:"range_end" mapstructure:"range_end"`
	LeaseTime  string   `yaml:"lease_time" mapstructure:"lease_time"`
	DNSServers []string `yaml:"dns_servers" mapstructure:"dns_servers"`
	Domain     string   `yaml:"domain" mapstructure:"domain"`
}

// IsolationConfig holds network isolation settings.
type IsolationConfig struct {
	BlockLANAccess     bool `yaml:"block_lan_access" mapstructure:"block_lan_access"`
	BlockManagement    bool `yaml:"block_management" mapstructure:"block_management"`
	BandwidthLimitMbps int  `yaml:"bandwidth_limit_mbps" mapstructure:"bandwidth_limit_mbps"`
}

// WiFiInterfaceConfig represents WiFi interface configuration.
type WiFiInterfaceConfig struct {
	Name        string             `yaml:"name" mapstructure:"name"`
	Alias       string             `yaml:"alias" mapstructure:"alias"`
	Description string             `yaml:"description" mapstructure:"description"`
	Enabled     bool               `yaml:"enabled" mapstructure:"enabled"`
	LinkedLAN   string             `yaml:"linked_lan" mapstructure:"linked_lan"`
	AccessPoint *AccessPointConfig `yaml:"access_point" mapstructure:"access_point"`
}

// AccessPointConfig holds WiFi AP settings.
type AccessPointConfig struct {
	SSID     string `yaml:"ssid" mapstructure:"ssid"`
	Security string `yaml:"security" mapstructure:"security"`
	Band     string `yaml:"band" mapstructure:"band"`
}

// InterfaceDiscoveryConfig holds discovery settings.
type InterfaceDiscoveryConfig struct {
	AutoDetect          bool                       `yaml:"auto_detect" mapstructure:"auto_detect"`
	ClassificationMode  string                     `yaml:"classification_mode" mapstructure:"classification_mode"`
	MonitorHotplug      bool                       `yaml:"monitor_hotplug" mapstructure:"monitor_hotplug"`
	ScanInterval        string                     `yaml:"scan_interval" mapstructure:"scan_interval"`
	ClassificationRules *ClassificationRulesConfig `yaml:"classification_rules" mapstructure:"classification_rules"`
}

// ClassificationRulesConfig holds interface classification rules.
type ClassificationRulesConfig struct {
	WANPatterns    []string `yaml:"wan_patterns" mapstructure:"wan_patterns"`
	LANPatterns    []string `yaml:"lan_patterns" mapstructure:"lan_patterns"`
	IgnorePatterns []string `yaml:"ignore_patterns" mapstructure:"ignore_patterns"`
}

// LoadBalancingConfig holds load balancer settings.
type LoadBalancingConfig struct {
	Enabled           bool                     `yaml:"enabled" mapstructure:"enabled"`
	Mode              string                   `yaml:"mode" mapstructure:"mode"`
	SessionAffinity   *SessionAffinityConfig   `yaml:"session_affinity" mapstructure:"session_affinity"`
	HashSettings      *HashSettingsConfig      `yaml:"hash_settings" mapstructure:"hash_settings"`
	Rebalance         *RebalanceConfig         `yaml:"rebalance" mapstructure:"rebalance"`
	BandwidthSettings *BandwidthSettingsConfig `yaml:"bandwidth_settings" mapstructure:"bandwidth_settings"`
}

// SessionAffinityConfig holds session affinity settings.
type SessionAffinityConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Mode    string `yaml:"mode" mapstructure:"mode"`
	Timeout string `yaml:"timeout" mapstructure:"timeout"`
}

// HashSettingsConfig holds hash-based LB settings.
type HashSettingsConfig struct {
	Algorithm         string `yaml:"algorithm" mapstructure:"algorithm"`
	ConsistentHashing bool   `yaml:"consistent_hashing" mapstructure:"consistent_hashing"`
}

// RebalanceConfig holds rebalancing settings.
type RebalanceConfig struct {
	Enabled          bool   `yaml:"enabled" mapstructure:"enabled"`
	Interval         string `yaml:"interval" mapstructure:"interval"`
	ThresholdPercent int    `yaml:"threshold_percent" mapstructure:"threshold_percent"`
}

// BandwidthSettingsConfig holds bandwidth-based LB settings.
type BandwidthSettingsConfig struct {
	MeasureInterval            string `yaml:"measure_interval" mapstructure:"measure_interval"`
	SaturationThresholdPercent int    `yaml:"saturation_threshold_percent" mapstructure:"saturation_threshold_percent"`
}

// FailoverConfig holds failover settings.
type FailoverConfig struct {
	Enabled        bool                      `yaml:"enabled" mapstructure:"enabled"`
	HealthCheck    *FailoverHealthConfig     `yaml:"health_check" mapstructure:"health_check"`
	Thresholds     *FailoverThresholdsConfig `yaml:"thresholds" mapstructure:"thresholds"`
	Recovery       *RecoveryConfig           `yaml:"recovery" mapstructure:"recovery"`
	PriorityGroups []PriorityGroupConfig     `yaml:"priority_groups" mapstructure:"priority_groups"`
}

// FailoverHealthConfig holds failover health check settings.
type FailoverHealthConfig struct {
	Interval     string              `yaml:"interval" mapstructure:"interval"`
	Timeout      string              `yaml:"timeout" mapstructure:"timeout"`
	Method       string              `yaml:"method" mapstructure:"method"`
	PingTargets  []string            `yaml:"ping_targets" mapstructure:"ping_targets"`
	HTTPSettings *HTTPHealthSettings `yaml:"http_settings" mapstructure:"http_settings"`
	DNSSettings  *DNSHealthSettings  `yaml:"dns_settings" mapstructure:"dns_settings"`
}

// HTTPHealthSettings holds HTTP health check settings.
type HTTPHealthSettings struct {
	URL            string `yaml:"url" mapstructure:"url"`
	ExpectedStatus int    `yaml:"expected_status" mapstructure:"expected_status"`
	ExpectedBody   string `yaml:"expected_body" mapstructure:"expected_body"`
}

// DNSHealthSettings holds DNS health check settings.
type DNSHealthSettings struct {
	Query  string `yaml:"query" mapstructure:"query"`
	Server string `yaml:"server" mapstructure:"server"`
}

// FailoverThresholdsConfig holds failover thresholds.
type FailoverThresholdsConfig struct {
	FailureCount          int `yaml:"failure_count" mapstructure:"failure_count"`
	RecoveryCount         int `yaml:"recovery_count" mapstructure:"recovery_count"`
	LatencyWarningMs      int `yaml:"latency_warning_ms" mapstructure:"latency_warning_ms"`
	LatencyCriticalMs     int `yaml:"latency_critical_ms" mapstructure:"latency_critical_ms"`
	PacketLossWarningPct  int `yaml:"packet_loss_warning_percent" mapstructure:"packet_loss_warning_percent"`
	PacketLossCriticalPct int `yaml:"packet_loss_critical_percent" mapstructure:"packet_loss_critical_percent"`
}

// RecoveryConfig holds recovery settings.
type RecoveryConfig struct {
	Delay            string `yaml:"delay" mapstructure:"delay"`
	Mode             string `yaml:"mode" mapstructure:"mode"`
	NotifyOnFailover bool   `yaml:"notify_on_failover" mapstructure:"notify_on_failover"`
	NotifyOnRecovery bool   `yaml:"notify_on_recovery" mapstructure:"notify_on_recovery"`
}

// PriorityGroupConfig holds priority group settings.
type PriorityGroupConfig struct {
	Name       string   `yaml:"name" mapstructure:"name"`
	Interfaces []string `yaml:"interfaces" mapstructure:"interfaces"`
	Mode       string   `yaml:"mode" mapstructure:"mode"`
}

// NATConfig holds NAT settings.
type NATConfig struct {
	Enabled        bool                  `yaml:"enabled" mapstructure:"enabled"`
	Mode           string                `yaml:"mode" mapstructure:"mode"`
	PortAllocation *PortAllocationConfig `yaml:"port_allocation" mapstructure:"port_allocation"`
	Timeouts       *NATTimeoutsConfig    `yaml:"timeouts" mapstructure:"timeouts"`
	PortForwards   []PortForwardConfig   `yaml:"port_forwards" mapstructure:"port_forwards"`
	UPnP           *UPnPConfig           `yaml:"upnp" mapstructure:"upnp"`
}

// PortAllocationConfig holds port allocation settings.
type PortAllocationConfig struct {
	Start      int    `yaml:"start" mapstructure:"start"`
	End        int    `yaml:"end" mapstructure:"end"`
	PoolSize   int    `yaml:"pool_size" mapstructure:"pool_size"`
	ReuseDelay string `yaml:"reuse_delay" mapstructure:"reuse_delay"`
}

// NATTimeoutsConfig holds NAT timeout settings.
type NATTimeoutsConfig struct {
	TCPEstablished string `yaml:"tcp_established" mapstructure:"tcp_established"`
	TCPTransitory  string `yaml:"tcp_transitory" mapstructure:"tcp_transitory"`
	TCPSynSent     string `yaml:"tcp_syn_sent" mapstructure:"tcp_syn_sent"`
	TCPSynRecv     string `yaml:"tcp_syn_recv" mapstructure:"tcp_syn_recv"`
	TCPFinWait     string `yaml:"tcp_fin_wait" mapstructure:"tcp_fin_wait"`
	TCPCloseWait   string `yaml:"tcp_close_wait" mapstructure:"tcp_close_wait"`
	TCPTimeWait    string `yaml:"tcp_time_wait" mapstructure:"tcp_time_wait"`
	UDP            string `yaml:"udp" mapstructure:"udp"`
	UDPStream      string `yaml:"udp_stream" mapstructure:"udp_stream"`
	ICMP           string `yaml:"icmp" mapstructure:"icmp"`
	Generic        string `yaml:"generic" mapstructure:"generic"`
}

// PortForwardConfig holds port forwarding rule.
type PortForwardConfig struct {
	Name         string `yaml:"name" mapstructure:"name"`
	Alias        string `yaml:"alias" mapstructure:"alias"`
	ExternalPort int    `yaml:"external_port" mapstructure:"external_port"`
	InternalIP   string `yaml:"internal_ip" mapstructure:"internal_ip"`
	InternalPort int    `yaml:"internal_port" mapstructure:"internal_port"`
	Protocol     string `yaml:"protocol" mapstructure:"protocol"`
	WANInterface string `yaml:"wan_interface" mapstructure:"wan_interface"`
	Enabled      bool   `yaml:"enabled" mapstructure:"enabled"`
}

// UPnPConfig holds UPnP settings.
type UPnPConfig struct {
	Enabled          bool     `yaml:"enabled" mapstructure:"enabled"`
	AllowFromSubnets []string `yaml:"allow_from_subnets" mapstructure:"allow_from_subnets"`
	DenyFromSubnets  []string `yaml:"deny_from_subnets" mapstructure:"deny_from_subnets"`
	MaxPortForwards  int      `yaml:"max_port_forwards" mapstructure:"max_port_forwards"`
	LeaseTime        string   `yaml:"lease_time" mapstructure:"lease_time"`
}

// ConnectionTrackingConfig holds connection tracking settings.
type ConnectionTrackingConfig struct {
	Enabled     bool                     `yaml:"enabled" mapstructure:"enabled"`
	MaxEntries  int                      `yaml:"max_entries" mapstructure:"max_entries"`
	HashSize    int                      `yaml:"hash_size" mapstructure:"hash_size"`
	ExpectMax   int                      `yaml:"expect_max" mapstructure:"expect_max"`
	Cleanup     *CleanupConfig           `yaml:"cleanup" mapstructure:"cleanup"`
	Persistence *PersistenceConfig       `yaml:"persistence" mapstructure:"persistence"`
	Timeouts    *ConnTrackTimeoutsConfig `yaml:"timeouts" mapstructure:"timeouts"`
}

// CleanupConfig holds cleanup settings.
type CleanupConfig struct {
	Interval  string `yaml:"interval" mapstructure:"interval"`
	BatchSize int    `yaml:"batch_size" mapstructure:"batch_size"`
}

// PersistenceConfig holds persistence settings.
type PersistenceConfig struct {
	Enabled           bool   `yaml:"enabled" mapstructure:"enabled"`
	SyncInterval      string `yaml:"sync_interval" mapstructure:"sync_interval"`
	PersistOnShutdown bool   `yaml:"persist_on_shutdown" mapstructure:"persist_on_shutdown"`
	RestoreOnStartup  bool   `yaml:"restore_on_startup" mapstructure:"restore_on_startup"`
}

// ConnTrackTimeoutsConfig holds connection tracking timeout settings.
type ConnTrackTimeoutsConfig struct {
	TCPEstablished string `yaml:"tcp_established" mapstructure:"tcp_established"`
	TCPClose       string `yaml:"tcp_close" mapstructure:"tcp_close"`
	TCPCloseWait   string `yaml:"tcp_close_wait" mapstructure:"tcp_close_wait"`
	TCPFinWait     string `yaml:"tcp_fin_wait" mapstructure:"tcp_fin_wait"`
	TCPTimeWait    string `yaml:"tcp_time_wait" mapstructure:"tcp_time_wait"`
	UDP            string `yaml:"udp" mapstructure:"udp"`
	UDPStream      string `yaml:"udp_stream" mapstructure:"udp_stream"`
	ICMP           string `yaml:"icmp" mapstructure:"icmp"`
	Generic        string `yaml:"generic" mapstructure:"generic"`
}

// PacketForwardingConfig holds packet forwarding settings.
type PacketForwardingConfig struct {
	Enabled    bool              `yaml:"enabled" mapstructure:"enabled"`
	Mode       string            `yaml:"mode" mapstructure:"mode"`
	Queues     *QueuesConfig     `yaml:"queues" mapstructure:"queues"`
	Workers    *WorkersConfig    `yaml:"workers" mapstructure:"workers"`
	Batch      *BatchConfig      `yaml:"batch" mapstructure:"batch"`
	Offload    *OffloadConfig    `yaml:"offload" mapstructure:"offload"`
	RingBuffer *RingBufferConfig `yaml:"ring_buffer" mapstructure:"ring_buffer"`
}

// QueuesConfig holds queue settings.
type QueuesConfig struct {
	Depth int `yaml:"depth" mapstructure:"depth"`
	Count int `yaml:"count" mapstructure:"count"`
}

// WorkersConfig holds worker settings.
type WorkersConfig struct {
	Count       int    `yaml:"count" mapstructure:"count"`
	CPUAffinity bool   `yaml:"cpu_affinity" mapstructure:"cpu_affinity"`
	Priority    string `yaml:"priority" mapstructure:"priority"`
}

// BatchConfig holds batch processing settings.
type BatchConfig struct {
	Size      int `yaml:"size" mapstructure:"size"`
	TimeoutUs int `yaml:"timeout_us" mapstructure:"timeout_us"`
}

// OffloadConfig holds hardware offload settings.
type OffloadConfig struct {
	Checksum bool `yaml:"checksum" mapstructure:"checksum"`
	TSO      bool `yaml:"tso" mapstructure:"tso"`
	GRO      bool `yaml:"gro" mapstructure:"gro"`
	LRO      bool `yaml:"lro" mapstructure:"lro"`
}

// RingBufferConfig holds ring buffer settings.
type RingBufferConfig struct {
	Size  int `yaml:"size" mapstructure:"size"`
	Burst int `yaml:"burst" mapstructure:"burst"`
}

// MonitoringConfig holds monitoring settings.
type MonitoringConfig struct {
	Enabled    bool              `yaml:"enabled" mapstructure:"enabled"`
	Statistics *StatisticsConfig `yaml:"statistics" mapstructure:"statistics"`
	Prometheus *PrometheusConfig `yaml:"prometheus" mapstructure:"prometheus"`
	Streaming  *StreamingConfig  `yaml:"streaming" mapstructure:"streaming"`
	Retention  *RetentionConfig  `yaml:"retention" mapstructure:"retention"`
}

// StatisticsConfig holds statistics settings.
type StatisticsConfig struct {
	Interval              string `yaml:"interval" mapstructure:"interval"`
	DetailedPerConnection bool   `yaml:"detailed_per_connection" mapstructure:"detailed_per_connection"`
}

// PrometheusConfig holds Prometheus settings.
type PrometheusConfig struct {
	Enabled   bool   `yaml:"enabled" mapstructure:"enabled"`
	Port      int    `yaml:"port" mapstructure:"port"`
	Path      string `yaml:"path" mapstructure:"path"`
	Namespace string `yaml:"namespace" mapstructure:"namespace"`
	Subsystem string `yaml:"subsystem" mapstructure:"subsystem"`
}

// StreamingConfig holds streaming metrics settings.
type StreamingConfig struct {
	Enabled         bool   `yaml:"enabled" mapstructure:"enabled"`
	DefaultInterval string `yaml:"default_interval" mapstructure:"default_interval"`
	MaxSubscribers  int    `yaml:"max_subscribers" mapstructure:"max_subscribers"`
}

// RetentionConfig holds data retention settings.
type RetentionConfig struct {
	StatisticsDays     int `yaml:"statistics_days" mapstructure:"statistics_days"`
	HealthHistoryDays  int `yaml:"health_history_days" mapstructure:"health_history_days"`
	FailoverEventsDays int `yaml:"failover_events_days" mapstructure:"failover_events_days"`
}

// DatabaseConfig holds database settings.
type DatabaseConfig struct {
	Host     string        `yaml:"host" mapstructure:"host"`
	Port     int           `yaml:"port" mapstructure:"port"`
	Database string        `yaml:"database" mapstructure:"database"`
	Username string        `yaml:"username" mapstructure:"username"`
	Password string        `yaml:"password" mapstructure:"password"`
	Pool     *DBPoolConfig `yaml:"pool" mapstructure:"pool"`
	SSL      *DBSSLConfig  `yaml:"ssl" mapstructure:"ssl"`
}

// DBPoolConfig holds database pool settings.
type DBPoolConfig struct {
	MaxConnections      int    `yaml:"max_connections" mapstructure:"max_connections"`
	MinConnections      int    `yaml:"min_connections" mapstructure:"min_connections"`
	MaxIdleTime         string `yaml:"max_idle_time" mapstructure:"max_idle_time"`
	ConnectionTimeout   string `yaml:"connection_timeout" mapstructure:"connection_timeout"`
	HealthCheckInterval string `yaml:"health_check_interval" mapstructure:"health_check_interval"`
}

// DBSSLConfig holds database SSL settings.
type DBSSLConfig struct {
	Enabled    bool   `yaml:"enabled" mapstructure:"enabled"`
	Mode       string `yaml:"mode" mapstructure:"mode"`
	CACert     string `yaml:"ca_cert" mapstructure:"ca_cert"`
	ClientCert string `yaml:"client_cert" mapstructure:"client_cert"`
	ClientKey  string `yaml:"client_key" mapstructure:"client_key"`
}

// GRPCConfig holds gRPC settings.
type GRPCConfig struct {
	ListenAddress        string           `yaml:"listen_address" mapstructure:"listen_address"`
	MaxConcurrentStreams int              `yaml:"max_concurrent_streams" mapstructure:"max_concurrent_streams"`
	MaxConnectionIdle    string           `yaml:"max_connection_idle" mapstructure:"max_connection_idle"`
	MaxConnectionAge     string           `yaml:"max_connection_age" mapstructure:"max_connection_age"`
	MaxRecvMsgSize       int              `yaml:"max_recv_msg_size" mapstructure:"max_recv_msg_size"`
	MaxSendMsgSize       int              `yaml:"max_send_msg_size" mapstructure:"max_send_msg_size"`
	Keepalive            *KeepaliveConfig `yaml:"keepalive" mapstructure:"keepalive"`
	TLS                  *TLSConfig       `yaml:"tls" mapstructure:"tls"`
}

// KeepaliveConfig holds keepalive settings.
type KeepaliveConfig struct {
	Time                string `yaml:"time" mapstructure:"time"`
	Timeout             string `yaml:"timeout" mapstructure:"timeout"`
	PermitWithoutStream bool   `yaml:"permit_without_stream" mapstructure:"permit_without_stream"`
}

// TLSConfig holds TLS settings.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled" mapstructure:"enabled"`
	CertFile   string `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile    string `yaml:"key_file" mapstructure:"key_file"`
	CAFile     string `yaml:"ca_file" mapstructure:"ca_file"`
	ClientAuth string `yaml:"client_auth" mapstructure:"client_auth"`
}

// IntegrationsConfig holds service integration settings.
type IntegrationsConfig struct {
	FirewallEngine *IntegrationEndpointConfig `yaml:"firewall_engine" mapstructure:"firewall_engine"`
	DHCPServer     *IntegrationEndpointConfig `yaml:"dhcp_server" mapstructure:"dhcp_server"`
	DNSServer      *IntegrationEndpointConfig `yaml:"dns_server" mapstructure:"dns_server"`
	NetworkLogger  *IntegrationEndpointConfig `yaml:"network_logger" mapstructure:"network_logger"`
	IDSIPS         *IntegrationEndpointConfig `yaml:"ids_ips" mapstructure:"ids_ips"`
	ThreatIntel    *IntegrationEndpointConfig `yaml:"threat_intel" mapstructure:"threat_intel"`
}

// IntegrationEndpointConfig holds integration endpoint settings.
type IntegrationEndpointConfig struct {
	Endpoint      string   `yaml:"endpoint" mapstructure:"endpoint"`
	Enabled       bool     `yaml:"enabled" mapstructure:"enabled"`
	Timeout       string   `yaml:"timeout" mapstructure:"timeout"`
	RetryAttempts int      `yaml:"retry_attempts" mapstructure:"retry_attempts"`
	LogEvents     []string `yaml:"log_events" mapstructure:"log_events"`
	SendMetadata  bool     `yaml:"send_metadata" mapstructure:"send_metadata"`
}

// RustEngineConfig holds Rust library settings.
type RustEngineConfig struct {
	LibraryPath string `yaml:"library_path" mapstructure:"library_path"`
	Enabled     bool   `yaml:"enabled" mapstructure:"enabled"`
	Workers     int    `yaml:"workers" mapstructure:"workers"`
	QueueDepth  int    `yaml:"queue_depth" mapstructure:"queue_depth"`
	BatchSize   int    `yaml:"batch_size" mapstructure:"batch_size"`
}

// AdvancedConfig holds advanced settings.
type AdvancedConfig struct {
	Experimental *ExperimentalConfig `yaml:"experimental" mapstructure:"experimental"`
	Tuning       *TuningConfig       `yaml:"tuning" mapstructure:"tuning"`
	Debug        *DebugConfig        `yaml:"debug" mapstructure:"debug"`
}

// ExperimentalConfig holds experimental feature settings.
type ExperimentalConfig struct {
	KernelBypass         bool `yaml:"kernel_bypass" mapstructure:"kernel_bypass"`
	HardwareTimestamping bool `yaml:"hardware_timestamping" mapstructure:"hardware_timestamping"`
	BusyPolling          bool `yaml:"busy_polling" mapstructure:"busy_polling"`
}

// TuningConfig holds tuning settings.
type TuningConfig struct {
	SocketBufferSize int  `yaml:"socket_buffer_size" mapstructure:"socket_buffer_size"`
	NetdevBudget     int  `yaml:"netdev_budget" mapstructure:"netdev_budget"`
	RPSEnabled       bool `yaml:"rps_enabled" mapstructure:"rps_enabled"`
	XPSEnabled       bool `yaml:"xps_enabled" mapstructure:"xps_enabled"`
}

// DebugConfig holds debug settings.
type DebugConfig struct {
	PacketCapture    bool   `yaml:"packet_capture" mapstructure:"packet_capture"`
	CapturePath      string `yaml:"capture_path" mapstructure:"capture_path"`
	CaptureMaxSizeMB int    `yaml:"capture_max_size_mb" mapstructure:"capture_max_size_mb"`
	TraceConnections bool   `yaml:"trace_connections" mapstructure:"trace_connections"`
}

// =============================================================================
// Configuration Loading
// =============================================================================

// envVarPattern matches ${VAR_NAME} or ${VAR_NAME:-default}
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// LoadConfig loads and parses the configuration file.
func LoadConfig(configPath string) (*Config, error) {
	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Substitute environment variables
	data, err = substituteEnvVars(data)
	if err != nil {
		return nil, fmt.Errorf("environment variable substitution failed: %w", err)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Store config path for hot reload
	config.configPath = configPath

	// Validate
	if err := ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// LoadConfigWithViper loads configuration using Viper for more flexibility.
func LoadConfigWithViper(configPath string) (*Config, error) {
	v := viper.New()

	// Set config file
	v.SetConfigFile(configPath)

	// Set defaults
	setDefaults(v)

	// Enable environment variable reading
	v.AutomaticEnv()
	v.SetEnvPrefix("NIC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Unmarshal
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	config.configPath = configPath

	// Validate
	if err := ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Service defaults
	v.SetDefault("service.log_level", "info")
	v.SetDefault("service.log_format", "json")
	v.SetDefault("service.environment", "production")

	// Load balancing defaults
	v.SetDefault("load_balancing.mode", "weighted")
	v.SetDefault("load_balancing.enabled", true)

	// Failover defaults
	v.SetDefault("failover.enabled", true)
	v.SetDefault("failover.health_check.interval", "5s")
	v.SetDefault("failover.health_check.timeout", "2s")
	v.SetDefault("failover.thresholds.failure_count", 3)
	v.SetDefault("failover.thresholds.recovery_count", 5)

	// NAT defaults
	v.SetDefault("nat.enabled", true)
	v.SetDefault("nat.port_allocation.start", 10000)
	v.SetDefault("nat.port_allocation.end", 65535)
	v.SetDefault("nat.port_allocation.pool_size", 55000)

	// Connection tracking defaults
	v.SetDefault("connection_tracking.enabled", true)
	v.SetDefault("connection_tracking.max_entries", 1000000)

	// Database defaults
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.pool.max_connections", 25)
	v.SetDefault("database.pool.min_connections", 5)

	// gRPC defaults
	v.SetDefault("grpc.listen_address", "0.0.0.0:50054")
	v.SetDefault("grpc.max_concurrent_streams", 100)

	// Monitoring defaults
	v.SetDefault("monitoring.enabled", true)
	v.SetDefault("monitoring.prometheus.port", 9091)
}

// substituteEnvVars replaces ${VAR} and ${VAR:-default} patterns with environment values.
func substituteEnvVars(data []byte) ([]byte, error) {
	result := envVarPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		matches := envVarPattern.FindSubmatch(match)
		if len(matches) < 2 {
			return match
		}

		varName := string(matches[1])
		defaultValue := ""
		if len(matches) >= 3 {
			defaultValue = string(matches[2])
		}

		value := os.Getenv(varName)
		if value == "" {
			value = defaultValue
		}

		return []byte(value)
	})

	return result, nil
}

// =============================================================================
// Configuration Validation
// =============================================================================

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for '%s': %s", e.Field, e.Message)
}

// ValidateConfig validates the entire configuration.
func ValidateConfig(config *Config) error {
	// Validate WAN interfaces
	if err := validateWANInterfaces(config.WANInterfaces); err != nil {
		return err
	}

	// Validate LAN interfaces
	if err := validateLANInterfaces(config.LANInterfaces); err != nil {
		return err
	}

	// Validate load balancing
	if err := validateLoadBalancing(&config.LoadBalancing); err != nil {
		return err
	}

	// Validate failover
	if err := validateFailover(&config.Failover); err != nil {
		return err
	}

	// Validate NAT
	if err := validateNAT(&config.NAT); err != nil {
		return err
	}

	// Validate connection tracking
	if err := validateConnectionTracking(&config.ConnectionTracking); err != nil {
		return err
	}

	// Validate database
	if err := validateDatabase(&config.Database); err != nil {
		return err
	}

	// Validate gRPC
	if err := validateGRPC(&config.GRPC); err != nil {
		return err
	}

	return nil
}

// validateWANInterfaces validates WAN interface configuration.
func validateWANInterfaces(wans []WANInterfaceConfig) error {
	if len(wans) == 0 {
		return &ValidationError{Field: "wan_interfaces", Message: "at least one WAN interface must be configured"}
	}

	names := make(map[string]bool)
	for i, wan := range wans {
		if wan.Name == "" {
			return &ValidationError{Field: fmt.Sprintf("wan_interfaces[%d].name", i), Message: "interface name is required"}
		}

		if names[wan.Name] {
			return &ValidationError{Field: fmt.Sprintf("wan_interfaces[%d].name", i), Message: fmt.Sprintf("duplicate interface name: %s", wan.Name)}
		}
		names[wan.Name] = true

		if wan.Priority < 1 {
			return &ValidationError{Field: fmt.Sprintf("wan_interfaces[%d].priority", i), Message: "priority must be >= 1"}
		}

		if wan.Weight < 0 || wan.Weight > 100 {
			return &ValidationError{Field: fmt.Sprintf("wan_interfaces[%d].weight", i), Message: "weight must be between 0 and 100"}
		}
	}

	return nil
}

// validateLANInterfaces validates LAN interface configuration.
func validateLANInterfaces(lans []LANInterfaceConfig) error {
	names := make(map[string]bool)
	for i, lan := range lans {
		if lan.Name == "" {
			return &ValidationError{Field: fmt.Sprintf("lan_interfaces[%d].name", i), Message: "interface name is required"}
		}

		if names[lan.Name] {
			return &ValidationError{Field: fmt.Sprintf("lan_interfaces[%d].name", i), Message: fmt.Sprintf("duplicate interface name: %s", lan.Name)}
		}
		names[lan.Name] = true

		// Validate VLAN if configured
		if lan.VLAN != nil && lan.VLAN.Enabled {
			if lan.VLAN.ID < 1 || lan.VLAN.ID > 4094 {
				return &ValidationError{Field: fmt.Sprintf("lan_interfaces[%d].vlan.id", i), Message: "VLAN ID must be between 1 and 4094"}
			}
		}

		// Validate DHCP configuration
		if lan.DHCPServer != nil && lan.DHCPServer.Enabled {
			if lan.DHCPServer.RangeStart == "" || lan.DHCPServer.RangeEnd == "" {
				return &ValidationError{Field: fmt.Sprintf("lan_interfaces[%d].dhcp_server", i), Message: "DHCP range_start and range_end are required when DHCP is enabled"}
			}
		}
	}

	return nil
}

// validateLoadBalancing validates load balancing configuration.
func validateLoadBalancing(lb *LoadBalancingConfig) error {
	if !lb.Enabled {
		return nil
	}

	validModes := map[string]bool{
		"disabled":          true,
		"round_robin":       true,
		"weighted":          true,
		"least_connections": true,
		"hash_based":        true,
		"bandwidth_based":   true,
		"failover_only":     true,
	}

	if !validModes[strings.ToLower(lb.Mode)] {
		return &ValidationError{Field: "load_balancing.mode", Message: fmt.Sprintf("invalid mode '%s', must be one of: disabled, round_robin, weighted, least_connections, hash_based, bandwidth_based, failover_only", lb.Mode)}
	}

	if lb.HashSettings != nil && strings.ToLower(lb.Mode) == "hash_based" {
		validAlgorithms := map[string]bool{
			"src_ip":   true,
			"dst_ip":   true,
			"5tuple":   true,
			"src_port": true,
		}
		if !validAlgorithms[strings.ToLower(lb.HashSettings.Algorithm)] {
			return &ValidationError{Field: "load_balancing.hash_settings.algorithm", Message: "invalid algorithm, must be one of: src_ip, dst_ip, 5tuple, src_port"}
		}
	}

	return nil
}

// validateFailover validates failover configuration.
func validateFailover(fo *FailoverConfig) error {
	if !fo.Enabled {
		return nil
	}

	if fo.HealthCheck != nil {
		interval, err := time.ParseDuration(fo.HealthCheck.Interval)
		if err != nil || interval < time.Second {
			return &ValidationError{Field: "failover.health_check.interval", Message: "must be a valid duration >= 1s"}
		}

		timeout, err := time.ParseDuration(fo.HealthCheck.Timeout)
		if err != nil || timeout < 100*time.Millisecond {
			return &ValidationError{Field: "failover.health_check.timeout", Message: "must be a valid duration >= 100ms"}
		}

		if timeout >= interval {
			return &ValidationError{Field: "failover.health_check.timeout", Message: "timeout must be less than interval"}
		}
	}

	if fo.Thresholds != nil {
		if fo.Thresholds.FailureCount < 1 || fo.Thresholds.FailureCount > 10 {
			return &ValidationError{Field: "failover.thresholds.failure_count", Message: "must be between 1 and 10"}
		}

		if fo.Thresholds.RecoveryCount < 1 || fo.Thresholds.RecoveryCount > 20 {
			return &ValidationError{Field: "failover.thresholds.recovery_count", Message: "must be between 1 and 20"}
		}
	}

	if fo.Recovery != nil {
		delay, err := time.ParseDuration(fo.Recovery.Delay)
		if err != nil || delay < 30*time.Second {
			return &ValidationError{Field: "failover.recovery.delay", Message: "must be a valid duration >= 30s"}
		}
	}

	return nil
}

// validateNAT validates NAT configuration.
func validateNAT(nat *NATConfig) error {
	if !nat.Enabled {
		return nil
	}

	if nat.PortAllocation != nil {
		if nat.PortAllocation.Start < 1024 {
			return &ValidationError{Field: "nat.port_allocation.start", Message: "must be >= 1024 (avoid reserved ports)"}
		}

		if nat.PortAllocation.End > 65535 {
			return &ValidationError{Field: "nat.port_allocation.end", Message: "must be <= 65535"}
		}

		if nat.PortAllocation.Start >= nat.PortAllocation.End {
			return &ValidationError{Field: "nat.port_allocation", Message: "start must be less than end"}
		}

		if nat.PortAllocation.PoolSize < 1 {
			return &ValidationError{Field: "nat.port_allocation.pool_size", Message: "must be > 0"}
		}

		maxPool := nat.PortAllocation.End - nat.PortAllocation.Start + 1
		if nat.PortAllocation.PoolSize > maxPool {
			return &ValidationError{Field: "nat.port_allocation.pool_size", Message: fmt.Sprintf("cannot exceed available port range (%d)", maxPool)}
		}
	}

	return nil
}

// validateConnectionTracking validates connection tracking configuration.
func validateConnectionTracking(ct *ConnectionTrackingConfig) error {
	if !ct.Enabled {
		return nil
	}

	if ct.MaxEntries < 1 {
		return &ValidationError{Field: "connection_tracking.max_entries", Message: "must be > 0"}
	}

	if ct.MaxEntries > 10000000 {
		return &ValidationError{Field: "connection_tracking.max_entries", Message: "exceeds maximum of 10 million"}
	}

	return nil
}

// validateDatabase validates database configuration.
func validateDatabase(db *DatabaseConfig) error {
	if db.Host == "" {
		return &ValidationError{Field: "database.host", Message: "host is required"}
	}

	if db.Port < 1 || db.Port > 65535 {
		return &ValidationError{Field: "database.port", Message: "must be between 1 and 65535"}
	}

	if db.Database == "" {
		return &ValidationError{Field: "database.database", Message: "database name is required"}
	}

	if db.Username == "" {
		return &ValidationError{Field: "database.username", Message: "username is required"}
	}

	if db.Password == "" {
		return &ValidationError{Field: "database.password", Message: "password is required (use ${DB_PASSWORD} environment variable)"}
	}

	if db.Pool != nil {
		if db.Pool.MaxConnections < 1 || db.Pool.MaxConnections > 100 {
			return &ValidationError{Field: "database.pool.max_connections", Message: "must be between 1 and 100"}
		}
	}

	return nil
}

// validateGRPC validates gRPC configuration.
func validateGRPC(grpc *GRPCConfig) error {
	if grpc.ListenAddress == "" {
		return &ValidationError{Field: "grpc.listen_address", Message: "listen address is required"}
	}

	// Validate address format
	host, portStr, err := net.SplitHostPort(grpc.ListenAddress)
	if err != nil {
		return &ValidationError{Field: "grpc.listen_address", Message: fmt.Sprintf("invalid format: %v", err)}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return &ValidationError{Field: "grpc.listen_address", Message: "port must be between 1 and 65535"}
	}

	// Allow empty host (means all interfaces)
	if host != "" && host != "0.0.0.0" && host != "::" {
		if net.ParseIP(host) == nil {
			// Try to resolve as hostname
			if _, err := net.LookupHost(host); err != nil {
				return &ValidationError{Field: "grpc.listen_address", Message: fmt.Sprintf("invalid host: %s", host)}
			}
		}
	}

	// Validate TLS if enabled
	if grpc.TLS != nil && grpc.TLS.Enabled {
		if grpc.TLS.CertFile == "" {
			return &ValidationError{Field: "grpc.tls.cert_file", Message: "certificate file is required when TLS is enabled"}
		}

		if grpc.TLS.KeyFile == "" {
			return &ValidationError{Field: "grpc.tls.key_file", Message: "key file is required when TLS is enabled"}
		}

		// Check if files exist
		if _, err := os.Stat(grpc.TLS.CertFile); os.IsNotExist(err) {
			return &ValidationError{Field: "grpc.tls.cert_file", Message: fmt.Sprintf("file not found: %s", grpc.TLS.CertFile)}
		}

		if _, err := os.Stat(grpc.TLS.KeyFile); os.IsNotExist(err) {
			return &ValidationError{Field: "grpc.tls.key_file", Message: fmt.Sprintf("file not found: %s", grpc.TLS.KeyFile)}
		}
	}

	return nil
}

// =============================================================================
// Configuration Hot Reload
// =============================================================================

// ReloadCallback is called when configuration is successfully reloaded.
type ReloadCallback func(newConfig *Config)

// WatchConfig watches the configuration file for changes and reloads.
func WatchConfig(config *Config, callback ReloadCallback) error {
	if config.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Watch the directory containing the config file
	dir := filepath.Dir(config.configPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Check if this is our config file
				if filepath.Base(event.Name) != filepath.Base(config.configPath) {
					continue
				}

				// Only react to write events
				if event.Op&fsnotify.Write != fsnotify.Write {
					continue
				}

				// Debounce - wait a bit for file to be fully written
				time.Sleep(100 * time.Millisecond)

				// Reload configuration
				newConfig, err := LoadConfig(config.configPath)
				if err != nil {
					fmt.Printf("Failed to reload config: %v\n", err)
					continue
				}

				// Call callback with new config
				if callback != nil {
					callback(newConfig)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("Config watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// GetWANInterfaceByName returns WAN interface config by name or alias.
func (c *Config) GetWANInterfaceByName(name string) *WANInterfaceConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.WANInterfaces {
		if c.WANInterfaces[i].Name == name || c.WANInterfaces[i].Alias == name {
			return &c.WANInterfaces[i]
		}
	}
	return nil
}

// GetLANInterfaceByName returns LAN interface config by name or alias.
func (c *Config) GetLANInterfaceByName(name string) *LANInterfaceConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.LANInterfaces {
		if c.LANInterfaces[i].Name == name || c.LANInterfaces[i].Alias == name {
			return &c.LANInterfaces[i]
		}
	}
	return nil
}

// EnabledWANCount returns the number of enabled WAN interfaces.
func (c *Config) EnabledWANCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, wan := range c.WANInterfaces {
		if wan.Enabled {
			count++
		}
	}
	return count
}

// IsProduction returns true if running in production environment.
func (c *Config) IsProduction() bool {
	return strings.ToLower(c.Service.Environment) == "production"
}

// DatabaseDSN returns the PostgreSQL connection string.
func (c *Config) DatabaseDSN() string {
	sslMode := "disable"
	if c.Database.SSL != nil && c.Database.SSL.Enabled {
		sslMode = c.Database.SSL.Mode
		if sslMode == "" {
			sslMode = "require"
		}
	}

	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.Username,
		c.Database.Password,
		c.Database.Database,
		sslMode,
	)
}
