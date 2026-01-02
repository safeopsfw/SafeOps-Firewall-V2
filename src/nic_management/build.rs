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
    // TLS Proxy Proto Compilation (Client-Only)
    // ==========================================================================
    // NIC Management acts as a gRPC CLIENT to TLS Proxy.
    // Generate client code only - no server implementation needed.
    //
    // Generated code:
    // - TlsProxyServiceClient: gRPC client for calling InterceptPacket RPC
    // - InterceptPacketRequest/Response: Message types for packet inspection
    // - PacketAction enum: FORWARD_UNCHANGED, BLOCK, etc.
    //
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

    Ok(())
}
