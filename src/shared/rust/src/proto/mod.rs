//! Generated Protocol Buffer types from proto/grpc/*.proto
//!
//! This module contains auto-generated code from all 14 proto files.
//! Each service has its own submodule to avoid name conflicts.

/// Common types (Timestamp, Status, IpAddress, etc.)
pub mod common {
    include!("safeops.common.rs");
}

/// Backup and restore service
pub mod backup_restore {
    include!("safeops.backup_restore.rs");
}

/// TLS certificate management
pub mod certificate_manager {
    include!("safeops.certificate_manager.rs");
}

/// DHCP server service
pub mod dhcp_server {
    include!("safeops.dhcp_server.rs");
}

/// DNS server service
pub mod dns_server {
    include!("safeops.dns_server.rs");
}

/// Firewall rule service
pub mod firewall {
    include!("safeops.firewall.rs");
}

/// Intrusion detection/prevention
pub mod ids_ips {
    include!("safeops.ids_ips.rs");
}

/// Network logging service
pub mod network_logger {
    include!("safeops.network_logger.rs");
}

/// Network management
pub mod network_manager {
    include!("safeops.network_manager.rs");
}

/// Service orchestration
pub mod orchestrator {
    include!("safeops.orchestrator.rs");
}

/// Threat intelligence service
pub mod threat_intel {
    include!("safeops.threat_intel.rs");
}

/// TLS proxy service
pub mod tls_proxy {
    include!("safeops.tls_proxy.rs");
}

/// Update management
pub mod update_manager {
    include!("safeops.update_manager.rs");
}

/// WiFi access point service
pub mod wifi_ap {
    include!("safeops.wifi_ap.rs");
}
