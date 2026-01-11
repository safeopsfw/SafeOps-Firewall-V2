//! Build script for SafeOps shared Rust library
//!
//! Compiles Protocol Buffer definitions to Rust code before main compilation.
//! Generates structs and gRPC client stubs from all proto files.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Rerun if build script or proto files change
    println!("cargo:rerun-if-changed=build.rs");
    
    // Get the project root directory (SafeOpsFV2)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let manifest_path = PathBuf::from(&manifest_dir);
    
    // Proto files are at SafeOpsFV2/proto/grpc/
    let proto_dir = manifest_path
        .parent()  // src/shared
        .and_then(|p| p.parent())  // src
        .and_then(|p| p.parent())  // SafeOpsFV2
        .map(|p| p.join("proto").join("grpc"))
        .expect("Failed to find proto directory");
    
    println!("cargo:rerun-if-changed={}", proto_dir.display());
    
    // List of ALL proto files to compile
    let proto_files: Vec<PathBuf> = vec![
        "common.proto",
        "backup_restore.proto",
        "certificate_manager.proto",
        "dhcp_server.proto",
        "dns_server.proto",
        "firewall.proto",
        "ids_ips.proto",
        "network_logger.proto",
        "network_manager.proto",
        "orchestrator.proto",
        "threat_intel.proto",
        "tls_proxy.proto",
        "update_manager.proto",
        "wifi_ap.proto",
    ].iter().map(|f| proto_dir.join(f)).collect();
    
    // Output directory for generated files
    let out_dir = manifest_path.join("src").join("proto");
    std::fs::create_dir_all(&out_dir)?;
    
    // Configure and compile proto files
    tonic_build::configure()
        .build_server(false)          // Only client code needed in shared lib
        .build_client(true)           // Generate gRPC client stubs
        .out_dir(&out_dir)            // Output to src/proto/
        .compile(
            &proto_files.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            &[&proto_dir],            // Include path for imports
        )?;
    
    // Enable SIMD features if supported
    #[cfg(target_arch = "x86_64")]
    {
        println!("cargo:rustc-cfg=has_avx2");
    }
    
    Ok(())
}
