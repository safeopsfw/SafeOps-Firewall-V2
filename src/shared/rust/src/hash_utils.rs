//! Fast, non-cryptographic hash functions for SafeOps
//!
//! Optimized for hash table lookups, connection tracking, and deduplication.
//! Provides multiple hash algorithms and specialized network hashing functions.
//!
//! # Hash Functions
//! - **FNV-1a**: Fast hash for small keys (32-bit and 64-bit)
//! - **XXHash**: High-performance general purpose hashing
//! - **MurmurHash3**: Excellent distribution for hash tables
//! - **aHash**: DoS-resistant hash for HashMaps
//!
//! # Specialized Network Hashing
//! - IP address pair hashing (src_ip, dst_ip)
//! - TCP/UDP 5-tuple hashing (src_ip, src_port, dst_ip, dst_port, protocol)
//! - Session ID generation
//! - Flow identifier hashing
//!
//! # Performance Features
//! - Inline implementations for hot paths
//! - Branch-free algorithms
//! - Cache-friendly memory access
//! - SIMD-ready batch operations

use ahash::{AHasher, RandomState};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use xxhash_rust::xxh3::{xxh3_64, xxh3_128, Xxh3};

// ============================================================================
// FNV-1a Hash Functions
// ============================================================================

const FNV1A_32_PRIME: u32 = 0x0100_0193;
const FNV1A_32_OFFSET: u32 = 0x811c_9dc5;
const FNV1A_64_PRIME: u64 = 0x0100_0000_01b3;
const FNV1A_64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 32-bit hash (fast for small keys)
#[inline]
pub fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = FNV1A_32_OFFSET;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV1A_32_PRIME);
    }
    hash
}

/// FNV-1a 64-bit hash
#[inline]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV1A_64_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

// ============================================================================
// MurmurHash3 Functions
// ============================================================================

/// MurmurHash3 32-bit (excellent distribution)
#[inline]
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe654_6b64;

    let mut hash = seed;
    let len = data.len();
    let nblocks = len / 4;

    // Process 4-byte blocks
    for i in 0..nblocks {
        let mut k = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);

        k = k.wrapping_mul(C1);
        k = k.rotate_left(R1);
        k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(R2);
        hash = hash.wrapping_mul(M).wrapping_add(N);
    }

    // Process remaining bytes
    let mut k1: u32 = 0;
    let tail = &data[nblocks * 4..];
    
    if tail.len() >= 3 {
        k1 ^= u32::from(tail[2]) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= u32::from(tail[1]) << 8;
    }
    if !tail.is_empty() {
        k1 ^= u32::from(tail[0]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(R1);
        k1 = k1.wrapping_mul(C2);
        hash ^= k1;
    }

    // Finalization
    hash ^= len as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^= hash >> 16;

    hash
}

// ============================================================================
// xxHash Functions
// ============================================================================

/// Compute xxHash3 64-bit hash of bytes
#[inline]
pub fn xxhash64(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// Compute xxHash3 128-bit hash of bytes
#[inline]
pub fn xxhash128(data: &[u8]) -> u128 {
    xxh3_128(data)
}

/// Compute xxHash3 64-bit hash with seed
#[inline]
pub fn xxhash64_seeded(data: &[u8], seed: u64) -> u64 {
    let mut hasher = Xxh3::with_seed(seed);
    hasher.write(data);
    hasher.finish()
}

/// Streaming xxHash3 hasher
pub struct XxHasher {
    inner: Xxh3,
}

impl XxHasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            inner: Xxh3::new(),
        }
    }
    
    /// Create with seed
    pub fn with_seed(seed: u64) -> Self {
        Self {
            inner: Xxh3::with_seed(seed),
        }
    }
    
    /// Update the hasher with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    
    /// Finalize and get the 64-bit hash
    pub fn finish64(&self) -> u64 {
        self.inner.digest()
    }
    
    /// Finalize and get the 128-bit hash
    pub fn finish128(&self) -> u128 {
        self.inner.digest128()
    }
    
    /// Reset the hasher
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for XxHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// aHash Functions
// ============================================================================

/// Compute aHash of any hashable value
#[inline]
pub fn ahash<T: Hash>(value: &T) -> u64 {
    let mut hasher = AHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Compute aHash of bytes
#[inline]
pub fn ahash_bytes(data: &[u8]) -> u64 {
    let mut hasher = AHasher::default();
    hasher.write(data);
    hasher.finish()
}

/// Get aHash RandomState for HashMap
/// 
/// Use this to create a HashMap with aHash for faster lookups:
/// ```
/// use std::collections::HashMap;
/// use safeops_shared::hash_utils::ahash_random_state;
/// 
/// let map: HashMap<String, i32, _> = HashMap::with_hasher(ahash_random_state());
/// ```
pub fn ahash_random_state() -> RandomState {
    RandomState::new()
}

// ============================================================================
// Consistent Hashing
// ============================================================================

/// Consistent hash ring for load balancing
/// 
/// Uses virtual nodes for better distribution.
pub struct ConsistentHashRing<T> {
    ring: Vec<(u64, T)>,
    virtual_nodes: usize,
}

impl<T: Clone + Hash> ConsistentHashRing<T> {
    /// Create a new consistent hash ring
    pub fn new(virtual_nodes: usize) -> Self {
        Self {
            ring: Vec::new(),
            virtual_nodes: virtual_nodes.max(1),
        }
    }
    
    /// Add a node to the ring
    pub fn add_node(&mut self, node: T) {
        let node_hash = ahash(&node);
        
        for i in 0..self.virtual_nodes {
            let virtual_hash = xxhash64(&[
                node_hash.to_le_bytes().as_slice(),
                i.to_le_bytes().as_slice(),
            ].concat());
            
            self.ring.push((virtual_hash, node.clone()));
        }
        
        self.ring.sort_by_key(|(hash, _)| *hash);
    }
    
    /// Remove a node from the ring
    pub fn remove_node(&mut self, node: &T) {
        let node_hash = ahash(node);
        
        for i in 0..self.virtual_nodes {
            let virtual_hash = xxhash64(&[
                node_hash.to_le_bytes().as_slice(),
                i.to_le_bytes().as_slice(),
            ].concat());
            
            self.ring.retain(|(hash, _)| *hash != virtual_hash);
        }
    }
    
    /// Get the node responsible for a key
    pub fn get_node<K: Hash>(&self, key: &K) -> Option<&T> {
        if self.ring.is_empty() {
            return None;
        }
        
        let hash = ahash(key);
        
        // Binary search for the first node with hash >= key hash
        match self.ring.binary_search_by_key(&hash, |(h, _)| *h) {
            Ok(idx) => Some(&self.ring[idx].1),
            Err(idx) => {
                if idx == self.ring.len() {
                    Some(&self.ring[0].1) // Wrap around
                } else {
                    Some(&self.ring[idx].1)
                }
            }
        }
    }
    
    /// Get N nodes responsible for a key (for replication)
    pub fn get_nodes<K: Hash>(&self, key: &K, count: usize) -> Vec<&T> {
        if self.ring.is_empty() || count == 0 {
            return Vec::new();
        }
        
        let hash = ahash(key);
        let start_idx = match self.ring.binary_search_by_key(&hash, |(h, _)| *h) {
            Ok(idx) => idx,
            Err(idx) => idx % self.ring.len(),
        };
        
        let mut result = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::new();
        
        for i in 0..self.ring.len() {
            let idx = (start_idx + i) % self.ring.len();
            let node = &self.ring[idx].1;
            let node_hash = ahash(node);
            
            if seen.insert(node_hash) {
                result.push(node);
                if result.len() >= count {
                    break;
                }
            }
        }
        
        result
    }
    
    /// Get the number of nodes in the ring
    pub fn len(&self) -> usize {
        self.ring.len() / self.virtual_nodes
    }
    
    /// Check if the ring is empty
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

impl<T: Clone + Hash> Default for ConsistentHashRing<T> {
    fn default() -> Self {
        Self::new(150)
    }
}

// ============================================================================
// Specialized Network Hashing
// ============================================================================

/// Hash an IP address pair (for connection tracking)
/// Returns a consistent hash regardless of direction
#[inline]
pub fn hash_ip_pair(ip1: IpAddr, ip2: IpAddr) -> u64 {
    // Ensure consistent ordering
    let (a, b) = if ip1 <= ip2 { (ip1, ip2) } else { (ip2, ip1) };
    
    let mut buf = Vec::with_capacity(32);
    match a {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    match b {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    
    xxhash64(&buf)
}

/// Hash an IPv4 address pair (optimized)
#[inline]
pub fn hash_ipv4_pair(ip1: Ipv4Addr, ip2: Ipv4Addr) -> u64 {
    let (a, b) = if ip1 <= ip2 { (ip1, ip2) } else { (ip2, ip1) };
    
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&a.octets());
    buf[4..8].copy_from_slice(&b.octets());
    
    xxhash64(&buf)
}

/// Hash a TCP/UDP 5-tuple for flow identification
/// (src_ip, src_port, dst_ip, dst_port, protocol)
#[inline]
pub fn hash_5tuple(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: u8,
) -> u64 {
    // Normalize direction for bidirectional flows
    let (ip1, port1, ip2, port2) = if (src_ip, src_port) <= (dst_ip, dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    };
    
    let mut buf = Vec::with_capacity(33);
    match ip1 {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&port1.to_be_bytes());
    match ip2 {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&port2.to_be_bytes());
    buf.push(protocol);
    
    xxhash64(&buf)
}

/// Hash a TCP/UDP 5-tuple for IPv4 (optimized)
#[inline]
pub fn hash_5tuple_v4(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: u8,
) -> u64 {
    // Normalize direction
    let (ip1, port1, ip2, port2) = if (src_ip, src_port) <= (dst_ip, dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    };
    
    let mut buf = [0u8; 13];
    buf[0..4].copy_from_slice(&ip1.octets());
    buf[4..6].copy_from_slice(&port1.to_be_bytes());
    buf[6..10].copy_from_slice(&ip2.octets());
    buf[10..12].copy_from_slice(&port2.to_be_bytes());
    buf[12] = protocol;
    
    xxhash64(&buf)
}

/// Generate a session ID from connection parameters
#[inline]
pub fn generate_session_id(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: u8,
    timestamp: u64,
) -> u128 {
    let mut buf = Vec::with_capacity(41);
    match src_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&src_port.to_be_bytes());
    match dst_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.push(protocol);
    buf.extend_from_slice(&timestamp.to_le_bytes());
    
    xxhash128(&buf)
}

/// Generate a flow identifier (directional, unlike 5-tuple hash)
#[inline]
pub fn hash_flow(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: u8,
) -> u64 {
    let mut buf = Vec::with_capacity(33);
    match src_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&src_port.to_be_bytes());
    match dst_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.push(protocol);
    
    xxhash64(&buf)
}

/// Hash for Bloom filter (generates multiple hashes)
pub fn hash_for_bloom(data: &[u8], num_hashes: usize) -> Vec<u64> {
    fingerprints(data, num_hashes)
}

// ============================================================================
// Hash Combiners
// ============================================================================

/// Combine two hashes into one
#[inline]
pub fn combine_hashes(h1: u64, h2: u64) -> u64 {
    // Use a mixing function similar to boost::hash_combine
    h1 ^ (h2.wrapping_add(0x9e3779b9).wrapping_add(h1 << 6).wrapping_add(h1 >> 2))
}

/// Combine multiple hashes
pub fn combine_hash_slice(hashes: &[u64]) -> u64 {
    hashes.iter().fold(0u64, |acc, &h| combine_hashes(acc, h))
}

// ============================================================================
// Fingerprinting
// ============================================================================

/// Create a fingerprint of data for probabilistic matching
#[inline]
pub fn fingerprint(data: &[u8]) -> u64 {
    xxhash64(data)
}

/// Create multiple fingerprints (for Bloom filters)
pub fn fingerprints(data: &[u8], count: usize) -> Vec<u64> {
    let h1 = xxhash64(data);
    let h2 = ahash_bytes(data);
    
    (0..count)
        .map(|i| h1.wrapping_add((i as u64).wrapping_mul(h2)))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxhash64() {
        let data = b"hello world";
        let hash1 = xxhash64(data);
        let hash2 = xxhash64(data);
        assert_eq!(hash1, hash2);
        
        let hash3 = xxhash64(b"hello world!");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_xxhash_streaming() {
        let data = b"hello world";
        
        let direct = xxhash64(data);
        
        let mut hasher = XxHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let streaming = hasher.finish64();
        
        assert_eq!(direct, streaming);
    }

    #[test]
    fn test_ahash() {
        let hash1 = ahash(&"test");
        let hash2 = ahash(&"test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_consistent_hash_ring() {
        let mut ring = ConsistentHashRing::new(10);
        
        ring.add_node("server1".to_string());
        ring.add_node("server2".to_string());
        ring.add_node("server3".to_string());
        
        // Same key should always map to same node
        let key = "user:123";
        let node1 = ring.get_node(&key);
        let node2 = ring.get_node(&key);
        assert_eq!(node1, node2);
        
        // Get multiple nodes for replication
        let nodes = ring.get_nodes(&key, 2);
        assert_eq!(nodes.len(), 2);
        assert_ne!(nodes[0], nodes[1]);
    }

    #[test]
    fn test_combine_hashes() {
        let h1 = 12345u64;
        let h2 = 67890u64;
        
        let combined = combine_hashes(h1, h2);
        assert_ne!(combined, h1);
        assert_ne!(combined, h2);
        
        // Order matters
        let combined_rev = combine_hashes(h2, h1);
        assert_ne!(combined, combined_rev);
    }

    #[test]
    fn test_fingerprints() {
        let data = b"test data";
        let fps = fingerprints(data, 5);
        
        assert_eq!(fps.len(), 5);
        // All fingerprints should be different
        let unique: std::collections::HashSet<_> = fps.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn test_fnv1a() {
        let data = b"hello world";
        let hash32 = fnv1a_32(data);
        let hash64 = fnv1a_64(data);
        
        // Same data should produce same hash
        assert_eq!(hash32, fnv1a_32(data));
        assert_eq!(hash64, fnv1a_64(data));
        
        // Different data should produce different hash
        assert_ne!(hash32, fnv1a_32(b"hello world!"));
        assert_ne!(hash64, fnv1a_64(b"hello world!"));
    }

    #[test]
    fn test_murmur3() {
        let data = b"test data";
        let hash1 = murmur3_32(data, 0);
        let hash2 = murmur3_32(data, 0);
        assert_eq!(hash1, hash2);
        
        // Different seed produces different hash
        let hash3 = murmur3_32(data, 1);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_ip_pair_hashing() {
        let ip1 = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
        let ip2 = "192.168.1.2".parse::<Ipv4Addr>().unwrap();
        
        // Symmetric hashing
        let hash1 = hash_ipv4_pair(ip1, ip2);
        let hash2 = hash_ipv4_pair(ip2, ip1);
        assert_eq!(hash1, hash2);
        
        // Test with IpAddr
        let hash3 = hash_ip_pair(IpAddr::V4(ip1), IpAddr::V4(ip2));
        let hash4 = hash_ip_pair(IpAddr::V4(ip2), IpAddr::V4(ip1));
        assert_eq!(hash3, hash4);
    }

    #[test]
    fn test_5tuple_hashing() {
        let ip1 = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
        let ip2 = "192.168.1.2".parse::<Ipv4Addr>().unwrap();
        
        // Bidirectional hashing (should be same regardless of direction)
        let hash1 = hash_5tuple_v4(ip1, 1234, ip2, 80, 6);
        let hash2 = hash_5tuple_v4(ip2, 80, ip1, 1234, 6);
        assert_eq!(hash1, hash2);
        
        // Different protocol should give different hash
        let hash3 = hash_5tuple_v4(ip1, 1234, ip2, 80, 17);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_flow_hashing() {
        let ip1 = IpAddr::V4("192.168.1.1".parse().unwrap());
        let ip2 = IpAddr::V4("192.168.1.2".parse().unwrap());
        
        // Directional hashing (different for each direction)
        let hash1 = hash_flow(ip1, 1234, ip2, 80, 6);
        let hash2 = hash_flow(ip2, 80, ip1, 1234, 6);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_session_id_generation() {
        let ip1 = IpAddr::V4("192.168.1.1".parse().unwrap());
        let ip2 = IpAddr::V4("192.168.1.2".parse().unwrap());
        
        let session1 = generate_session_id(ip1, 1234, ip2, 80, 6, 1000);
        let session2 = generate_session_id(ip1, 1234, ip2, 80, 6, 1000);
        assert_eq!(session1, session2);
        
        // Different timestamp should give different session ID
        let session3 = generate_session_id(ip1, 1234, ip2, 80, 6, 2000);
        assert_ne!(session1, session3);
    }

    #[test]
    fn test_bloom_filter_hashing() {
        let data = b"test";
        let hashes = hash_for_bloom(data, 3);
        
        assert_eq!(hashes.len(), 3);
        // All should be unique
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), 3);
    }
}
