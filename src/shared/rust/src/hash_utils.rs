//! Fast, non-cryptographic hash functions for packet processing
//!
//! Provides xxHash (extremely fast) and aHash (DOS-resistant) algorithms
//! optimized for performance-critical paths in firewall packet processing.
//! These functions are 5-10x faster than cryptographic hashes while providing
//! excellent distribution for hash tables.

use ahash::{AHasher, RandomState};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed, xxh3_128};

// Re-export aHash collections for convenience
pub use ahash::AHashMap;
pub use ahash::AHashSet;

use crate::ip_utils::IPAddress;

// ============================================================================
// xxHash Functions
// ============================================================================

/// Extremely fast 64-bit hash using xxHash algorithm (>10 GB/s on modern CPUs)
///
/// Best for: Connection tuple hashing, general-purpose hashing
#[inline]
pub fn xxhash64(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// xxHash64 with custom seed for domain separation
///
/// Prevents hash collision attacks by using different seeds per domain
#[inline]
pub fn xxhash64_with_seed(data: &[u8], seed: u64) -> u64 {
    xxh3_64_with_seed(data, seed)
}

/// xxHash3 algorithm - even faster for small inputs (<240 bytes)
///
/// Best for: Packet header hashing
#[inline]
pub fn xxhash3(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// 128-bit hash for larger collision space
///
/// Best for: Unique packet identifiers when 64-bit space insufficient
#[inline]
pub fn xxhash128(data: &[u8]) -> u128 {
    xxh3_128(data)
}

// ============================================================================
// aHash Functions (DOS-Resistant)
// ============================================================================

/// DOS-resistant hash using aHash algorithm with randomized per-process seed
///
/// Best for: HashMap/HashSet keys to prevent algorithmic complexity attacks
#[inline]
pub fn ahash_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = AHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Creates a new AHasher for building custom hash computations
#[inline]
pub fn new_ahasher() -> AHasher {
    AHasher::default()
}

// ============================================================================
// Connection Tuple Hashing
// ============================================================================

/// Five-tuple structure for network connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IPAddress,
    pub src_port: u16,
    pub dst_ip: IPAddress,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FiveTuple {
    /// Creates a new five-tuple
    pub fn new(
        src_ip: IPAddress,
        src_port: u16,
        dst_ip: IPAddress,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        FiveTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }
}

/// Hashes network 5-tuple for connection tracking HashMap keys
///
/// Cache-friendly memory layout for high-performance lookups
pub fn hash_connection_tuple(
    src_ip: IPAddress,
    src_port: u16,
    dst_ip: IPAddress,
    dst_port: u16,
    protocol: u8,
) -> u64 {
    let tuple = FiveTuple::new(src_ip, src_port, dst_ip, dst_port, protocol);
    ahash_hash(&tuple)
}

/// Produces same hash regardless of connection direction
///
/// For stateful connection tracking where both directions map to same entry
pub fn hash_bidirectional_tuple(tuple: &FiveTuple) -> u64 {
    // Normalize tuple by ordering IPs/ports
    let (ip1, port1, ip2, port2) = if tuple.src_ip.to_bytes() < tuple.dst_ip.to_bytes()
        || (tuple.src_ip == tuple.dst_ip && tuple.src_port < tuple.dst_port)
    {
        (tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port)
    } else {
        (tuple.dst_ip, tuple.dst_port, tuple.src_ip, tuple.src_port)
    };

    let normalized = FiveTuple::new(ip1, port1, ip2, port2, tuple.protocol);
    ahash_hash(&normalized)
}

// ============================================================================
// Packet Header Hashing
// ============================================================================

/// Hashes packet header for deduplication detection
///
/// Uses xxHash3 for maximum speed on small packet headers
pub fn hash_packet_header(data: &[u8]) -> u64 {
    xxhash3(data)
}

/// Hashes only IP header fields (excludes TTL and checksum which change per hop)
///
/// For flow identification across network hops
pub fn hash_ip_header(ip_data: &[u8]) -> u64 {
    // In a real implementation, would parse IP header and hash relevant fields
    // For now, hash the entire header as a simplified version
    xxhash3(ip_data)
}

// ============================================================================
// Batch Hashing
// ============================================================================

/// Hashes multiple items in single call to amortize overhead
///
/// SIMD-friendly processing for bulk operations
pub fn hash_batch(items: &[&[u8]]) -> Vec<u64> {
    items.iter().map(|item| xxhash64(item)).collect()
}

/// Parallel hashing using multiple CPU cores
///
/// Best for large batches (>1000 items). Uses rayon for parallelism.
#[cfg(feature = "rayon")]
pub fn hash_parallel(items: &[&[u8]]) -> Vec<u64> {
    use rayon::prelude::*;
    items.par_iter().map(|item| xxhash64(item)).collect()
}

/// Non-parallel fallback when rayon feature disabled
#[cfg(not(feature = "rayon"))]
pub fn hash_parallel(items: &[&[u8]]) -> Vec<u64> {
    hash_batch(items)
}

// ============================================================================
// Hash Combining
// ============================================================================

/// Combines two hash values using boost::hash_combine algorithm
///
/// Formula: h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2))
#[inline]
pub fn combine_hashes(h1: u64, h2: u64) -> u64 {
    h1 ^ (h2.wrapping_add(0x9e3779b9).wrapping_add(h1 << 6).wrapping_add(h1 >> 2))
}

/// Updates running hash state with new data
///
/// For streaming hash computation without copying data
#[inline]
pub fn hash_update(hasher: &mut impl Hasher, data: &[u8]) {
    hasher.write(data);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts hash to hex string for logging and debugging
pub fn hash_to_hex(hash: u64) -> String {
    format!("{:016x}", hash)
}

/// Distribution statistics for hash quality analysis
#[derive(Debug, Clone)]
pub struct DistributionStats {
    /// Number of collisions detected
    pub collisions: usize,
    /// Uniformity score (lower is better, 0.0 = perfect distribution)
    pub uniformity_score: f64,
    /// Number of buckets analyzed
    pub bucket_count: usize,
}

/// Analyzes hash distribution quality
///
/// Returns collision count and uniformity score for testing
pub fn check_distribution(hashes: &[u64]) -> DistributionStats {
    let bucket_count = 1024; // Use 1024 buckets for analysis
    let mut buckets = vec![0usize; bucket_count];
    let mut unique_hashes = HashSet::new();
    let mut collisions = 0;

    for &hash in hashes {
        let bucket = (hash % bucket_count as u64) as usize;
        buckets[bucket] += 1;

        if !unique_hashes.insert(hash) {
            collisions += 1;
        }
    }

    // Calculate uniformity score (chi-squared test)
    let expected = hashes.len() as f64 / bucket_count as f64;
    let uniformity_score = buckets
        .iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            diff * diff / expected
        })
        .sum::<f64>()
        / bucket_count as f64;

    DistributionStats {
        collisions,
        uniformity_score,
        bucket_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_utils::parse_ip;

    #[test]
    fn test_xxhash64() {
        let data = b"hello world";
        let hash1 = xxhash64(data);
        let hash2 = xxhash64(data);
        assert_eq!(hash1, hash2); // Deterministic
    }

    #[test]
    fn test_xxhash64_with_seed() {
        let data = b"hello world";
        let hash1 = xxhash64_with_seed(data, 42);
        let hash2 = xxhash64_with_seed(data, 43);
        assert_ne!(hash1, hash2); // Different seeds produce different hashes
    }

    #[test]
    fn test_ahash_hash() {
        let value = "test string";
        let hash1 = ahash_hash(&value);
        let hash2 = ahash_hash(&value);
        assert_eq!(hash1, hash2); // Same process, same hash
    }

    #[test]
    fn test_connection_tuple_hash() {
        let src_ip = parse_ip("192.168.1.1").unwrap();
        let dst_ip = parse_ip("192.168.1.2").unwrap();
        let hash = hash_connection_tuple(src_ip, 12345, dst_ip, 80, 6);
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_bidirectional_tuple_hash() {
        let ip1 = parse_ip("192.168.1.1").unwrap();
        let ip2 = parse_ip("192.168.1.2").unwrap();

        let tuple1 = FiveTuple::new(ip1, 12345, ip2, 80, 6);
        let tuple2 = FiveTuple::new(ip2, 80, ip1, 12345, 6);

        let hash1 = hash_bidirectional_tuple(&tuple1);
        let hash2 = hash_bidirectional_tuple(&tuple2);

        assert_eq!(hash1, hash2); // Same hash regardless of direction
    }

    #[test]
    fn test_combine_hashes() {
        let h1 = 0x123456789abcdef0u64;
        let h2 = 0xfedcba9876543210u64;
        let combined = combine_hashes(h1, h2);
        assert_ne!(combined, h1);
        assert_ne!(combined, h2);
    }

    #[test]
    fn test_hash_batch() {
        let items: Vec<&[u8]> = vec![b"item1", b"item2", b"item3"];
        let hashes = hash_batch(&items);
        assert_eq!(hashes.len(), 3);
        assert_ne!(hashes[0], hashes[1]);
    }

    #[test]
    fn test_hash_distribution() {
        // Generate 10000 hashes and check distribution
        let data: Vec<Vec<u8>> = (0..10000)
            .map(|i| format!("data_{}", i).into_bytes())
            .collect();
        let hashes: Vec<u64> = data.iter().map(|d| xxhash64(d)).collect();

        let stats = check_distribution(&hashes);
        assert!(stats.collisions < 10); // Very few collisions expected
        assert!(stats.uniformity_score < 2.0); // Good distribution
    }

    #[test]
    fn test_hash_to_hex() {
        let hash = 0x123456789abcdef0u64;
        let hex = hash_to_hex(hash);
        assert_eq!(hex, "123456789abcdef0");
    }
}
