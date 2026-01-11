//! Configuration module for NIC Management service.
//!
//! Loads and validates configuration from TOML file, providing type-safe
//! access to all runtime settings including Phase 1 TLS Proxy integration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// =============================================================================
// MAIN CONFIG STRUCT
// =============================================================================

/// Complete NIC Management configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub nat: NatConfig,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    pub tls_proxy: TlsProxyConfig, // NEW for Phase 1
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub statistics: Option<StatisticsConfig>,
}

// =============================================================================
// NETWORK CONFIG
// =============================================================================

/// Network interface configuration for packet capture.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// WAN interface name (e.g., "Ethernet", "Wi-Fi")
    pub wan_interface: String,
    /// LAN interface name for internal traffic
    pub lan_interface: String,
    /// Optional BPF filter expression
    #[serde(default)]
    pub capture_filter: Option<String>,
}

// =============================================================================
// NAT CONFIG
// =============================================================================

/// Network Address Translation configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NatConfig {
    /// Enable NAT translation
    pub enable: bool,
    /// Connection tracking timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent NAT mappings
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Start of NAT port allocation range
    #[serde(default)]
    pub port_range_start: Option<u16>,
    /// End of NAT port allocation range
    #[serde(default)]
    pub port_range_end: Option<u16>,
}

fn default_max_connections() -> usize {
    65535
}

// =============================================================================
// ROUTING CONFIG
// =============================================================================

/// Packet routing configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    /// Enable IP forwarding between interfaces
    #[serde(default = "default_true")]
    pub enable_forwarding: bool,
    /// Default action: "forward", "drop", "reject"
    #[serde(default = "default_forward")]
    pub default_action: String,
    /// Maximum Transmission Unit
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_true() -> bool {
    true
}

fn default_forward() -> String {
    "forward".to_string()
}

fn default_mtu() -> u16 {
    1500
}

// =============================================================================
// TLS PROXY CONFIG - NEW FOR PHASE 1
// =============================================================================

/// TLS Proxy integration configuration for packet inspection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsProxyConfig {
    /// Enable TLS Proxy packet inspection
    pub enabled: bool,
    /// gRPC endpoint address (e.g., "localhost:50054")
    pub address: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Forward packets on TLS Proxy failure (true = fail-open)
    pub fail_open: bool,
    /// Retry attempts before fail-open (Phase 2+)
    #[serde(default)]
    pub retry_attempts: Option<u32>,
    /// Connection pool size (Phase 2+)
    #[serde(default)]
    pub connection_pool_size: Option<usize>,
}

// =============================================================================
// LOGGING CONFIG
// =============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level: error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output: console, file, syslog
    #[serde(default = "default_log_output")]
    pub output: String,
    /// Log file path (if output="file")
    #[serde(default)]
    pub file_path: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_output() -> String {
    "console".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            output: default_log_output(),
            file_path: None,
        }
    }
}

// =============================================================================
// STATISTICS CONFIG
// =============================================================================

/// Statistics collection configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatisticsConfig {
    /// Collection interval in seconds
    #[serde(default = "default_interval")]
    pub collection_interval_secs: u64,
    /// Reset statistics on restart
    #[serde(default)]
    pub reset_on_restart: bool,
}

fn default_interval() -> u64 {
    60
}

// =============================================================================
// CONFIG IMPLEMENTATION
// =============================================================================

impl Config {
    /// Load configuration from TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        // Read file
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        // Parse TOML
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse TOML config: {}", path.display()))?;
        
        // Validate
        config.validate()?;
        
        Ok(config)
    }
    
    /// Validate configuration values.
    fn validate(&self) -> Result<()> {
        // Network validation
        if self.network.wan_interface.is_empty() {
            anyhow::bail!("network.wan_interface cannot be empty");
        }
        if self.network.lan_interface.is_empty() {
            anyhow::bail!("network.lan_interface cannot be empty");
        }
        
        // NAT validation
        if self.nat.timeout_secs == 0 {
            anyhow::bail!("nat.timeout_secs must be > 0");
        }
        if let (Some(start), Some(end)) = (self.nat.port_range_start, self.nat.port_range_end) {
            if start >= end {
                anyhow::bail!("nat.port_range_start must be < port_range_end");
            }
        }
        
        // TLS Proxy validation (Phase 1)
        if self.tls_proxy.address.is_empty() {
            anyhow::bail!("tls_proxy.address cannot be empty");
        }
        if !self.tls_proxy.address.contains(':') {
            anyhow::bail!("tls_proxy.address must include port (format: hostname:port)");
        }
        if self.tls_proxy.timeout_secs == 0 {
            anyhow::bail!("tls_proxy.timeout_secs must be > 0");
        }
        
        // Logging validation
        let valid_levels = ["error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            anyhow::bail!("logging.level must be one of: error, warn, info, debug, trace");
        }
        
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                wan_interface: "Ethernet".to_string(),
                lan_interface: "Ethernet 2".to_string(),
                capture_filter: None,
            },
            nat: NatConfig {
                enable: true,
                timeout_secs: 300,
                max_connections: 65535,
                port_range_start: None,
                port_range_end: None,
            },
            routing: None,
            tls_proxy: TlsProxyConfig {
                enabled: true,
                address: "localhost:50054".to_string(),
                timeout_secs: 5,
                fail_open: true,
                retry_attempts: None,
                connection_pool_size: None,
            },
            logging: LoggingConfig::default(),
            statistics: None,
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_empty_wan_interface_rejected() {
        let mut config = Config::default();
        config.network.wan_interface = String::new();
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_zero_timeout_rejected() {
        let mut config = Config::default();
        config.nat.timeout_secs = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_empty_tls_proxy_address_rejected() {
        let mut config = Config::default();
        config.tls_proxy.address = String::new();
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_tls_proxy_address_without_port_rejected() {
        let mut config = Config::default();
        config.tls_proxy.address = "localhost".to_string();
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_zero_tls_proxy_timeout_rejected() {
        let mut config = Config::default();
        config.tls_proxy.timeout_secs = 0;
        assert!(config.validate().is_err());
    }
}
