//! SafeOps Protocol Buffer generated modules
//!
//! This module includes all generated gRPC client stubs and message types
//! from the proto definitions in proto/grpc/.

// Common types used by all services
pub mod common {
    include!("safeops.common.rs");
}

// Service-specific modules
pub mod backup_restore {
    include!("safeops.backup_restore.rs");
}

pub mod certificate_manager {
    include!("safeops.certificate_manager.rs");
}

pub mod dhcp_server {
    include!("safeops.dhcp_server.rs");
}

pub mod dns_server {
    include!("safeops.dns_server.rs");
}

pub mod firewall {
    include!("safeops.firewall.rs");
}

pub mod ids_ips {
    include!("safeops.ids_ips.rs");
}

pub mod network_logger {
    include!("safeops.network_logger.rs");
}

pub mod network_manager {
    include!("safeops.network_manager.rs");
}

pub mod orchestrator {
    include!("safeops.orchestrator.rs");
}

pub mod threat_intel {
    include!("safeops.threat_intel.rs");
}

pub mod tls_proxy {
    include!("safeops.tls_proxy.rs");
}

pub mod update_manager {
    include!("safeops.update_manager.rs");
}

pub mod wifi_ap {
    include!("safeops.wifi_ap.rs");
}
