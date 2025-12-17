fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build script for Rust shared library
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../proto/grpc");
    
    // Compile proto files to Rust using tonic-build
    // Output: src/proto/common.rs, firewall.rs, threat_intel.rs
    tonic_build::configure()
        .build_server(false)        // Only client code needed
        .build_client(true)          // Generate gRPC client code
        .out_dir("src/proto")        // Output to src/proto/
        .compile(
            &[
                "../../proto/grpc/common.proto",
                "../../proto/grpc/firewall.proto",
                "../../proto/grpc/threat_intel.proto",
            ],
            &["../../proto/grpc"],   // Include path
        )?;
    
    // Enable SIMD features if supported
    #[cfg(target_arch = "x86_64")]
    {
        println!("cargo:rustc-cfg=has_avx2");
        println!("cargo:rustc-env=RUSTFLAGS=-C target-cpu=native");
    }
    
    Ok(())
}
