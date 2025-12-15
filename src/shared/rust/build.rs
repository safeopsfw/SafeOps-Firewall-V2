fn main() {
    // Build script for Rust shared library
    println!("cargo:rerun-if-changed=build.rs");
    
    // Enable SIMD features if supported
    #[cfg(target_arch = "x86_64")]
    {
        println!("cargo:rustc-cfg=has_avx2");
        println!("cargo:rustc-env=RUSTFLAGS=-C target-cpu=native");
    }
}
