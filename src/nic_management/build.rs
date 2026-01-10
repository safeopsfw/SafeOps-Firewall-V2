//! Build script for NIC Management
//!
//! This script runs during Rust's compilation process to generate code from
//! protocol buffer definitions. It compiles three proto files:
//! - tls_proxy.proto: TLS Proxy gRPC client for packet interception
//! - nic_management.proto: NIC Management gRPC service definition
//! - network_manager.proto: Network statistics message definitions
//!
//! The generated code provides type-safe gRPC client/server implementations
//! and protobuf message serialization for cross-service communication.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ==========================================================================
    // Proto file paths relative to this build script
    // ==========================================================================
    let proto_dir = PathBuf::from("../../proto/grpc");

    // Verify proto directory exists
    if !proto_dir.exists() {
        eprintln!("Warning: Proto directory not found at {:?}", proto_dir);
        eprintln!("Skipping proto compilation - gRPC features will not be available");
        return Ok(());
    }

    let tls_proxy_proto = proto_dir.join("tls_proxy.proto");
    let nic_management_proto = proto_dir.join("nic_management.proto");
    let network_manager_proto = proto_dir.join("network_manager.proto");
    let common_proto = proto_dir.join("common.proto");

    // Check if proto files exist before attempting compilation
    let protos_exist = tls_proxy_proto.exists()
        && nic_management_proto.exists()
        && network_manager_proto.exists()
        && common_proto.exists();

    if !protos_exist {
        eprintln!("Warning: One or more proto files not found");
        eprintln!("  tls_proxy.proto: {}", tls_proxy_proto.exists());
        eprintln!("  nic_management.proto: {}", nic_management_proto.exists());
        eprintln!("  network_manager.proto: {}", network_manager_proto.exists());
        eprintln!("  common.proto: {}", common_proto.exists());
        eprintln!("Skipping proto compilation");
        return Ok(());
    }

    // ==========================================================================
    // TLS Proxy Packet Processing Proto (for HTTP redirect with INJECT action)
    // ==========================================================================
    // This proto defines PacketProcessingService with INJECT action for HTTP redirects
    // File: src/tls_proxy/proto/packet_processing.proto
    //
    let packet_processing_proto = PathBuf::from("../tls_proxy/proto/packet_processing.proto");
    
    if packet_processing_proto.exists() {
        tonic_build::configure()
            .build_server(false) // Client only
            .build_client(true)
            .compile(
                &[packet_processing_proto.to_str().unwrap()],
                &["../tls_proxy/proto"],
            )?;
        eprintln!("Compiled packet_processing.proto for INJECT action support");
    } else {
        eprintln!("Warning: packet_processing.proto not found at {:?}", packet_processing_proto);
    }
    
    // ==========================================================================
    // TLS Proxy Proto Compilation (Legacy - for SNI extraction)
    // ==========================================================================
    tonic_build::configure()
        .build_server(false) // Client only - we call TLS Proxy, not serve it
        .build_client(true)
        .compile(
            &[tls_proxy_proto.to_str().unwrap()],
            &[proto_dir.to_str().unwrap()],
        )?;

    // ==========================================================================
    // NIC Management Proto Compilation (Client and Server)
    // ==========================================================================
    // NIC Management serves its own gRPC API and may also call itself.
    // Generate both client and server code.
    //
    // Generated code:
    // - NicManagement trait: Server trait to implement for gRPC service
    // - NicManagementClient: Client for calling NIC Management RPCs
    // - All request/response message types
    //
    tonic_build::configure()
        .build_server(true) // Generate server trait for NIC Management service
        .build_client(true) // Also generate client for internal/external calls
        .compile(
            &[nic_management_proto.to_str().unwrap()],
            &[proto_dir.to_str().unwrap()],
        )?;

    // ==========================================================================
    // Network Manager Proto Compilation (Messages-Only)
    // ==========================================================================
    // NIC Management uses InterfaceStatistics message for reporting metrics.
    // Only need message types, not service implementations.
    //
    // Generated code:
    // - InterfaceStatistics: Contains standard metrics (fields 1-9)
    //   and TLS Proxy integration metrics (fields 10-16)
    // - Supporting message types for statistics reporting
    //
    tonic_build::configure()
        .build_server(false) // No server needed - NetworkManager service is separate
        .build_client(false) // No client needed - just using message types
        .compile(
            &[network_manager_proto.to_str().unwrap()],
            &[proto_dir.to_str().unwrap()],
        )?;

    // ==========================================================================
    // Build Script Rebuild Triggers
    // ==========================================================================
    // Tell Cargo to re-run this script if any proto file changes.
    // This ensures generated code stays in sync with proto definitions.
    //
    println!("cargo:rerun-if-changed=../../proto/grpc/tls_proxy.proto");
    println!("cargo:rerun-if-changed=../../proto/grpc/nic_management.proto");
    println!("cargo:rerun-if-changed=../../proto/grpc/network_manager.proto");
    println!("cargo:rerun-if-changed=../../proto/grpc/common.proto");

    // ==========================================================================
    // DHCP Monitor Proto Compilation (Client Only - for Packet Engine)
    // ==========================================================================
    // Packet Engine queries DHCP Monitor to get device info (trust status, MAC, etc.)
    // This enables enriched logging with device context for FW/IDS/IPS.
    //
    let dhcp_monitor_proto = PathBuf::from("proto/dhcp_monitor.proto");
    
    if dhcp_monitor_proto.exists() {
        tonic_build::configure()
            .build_server(false) // Client only - Packet Engine calls DHCP Monitor
            .build_client(true)
            .compile(
                &[dhcp_monitor_proto.to_str().unwrap()],
                &["proto"],
            )?;
        eprintln!("Compiled dhcp_monitor.proto for Packet Engine device lookup");
        println!("cargo:rerun-if-changed=proto/dhcp_monitor.proto");
    } else {
        eprintln!("Warning: dhcp_monitor.proto not found at {:?}", dhcp_monitor_proto);
        eprintln!("Device info enrichment will not be available in packet logs");
    }

    Ok(())
}
