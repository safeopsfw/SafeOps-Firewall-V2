//! High-Performance Routing Decision Engine
//!
//! This module implements the routing decision engine that determines the correct
//! output interface for each packet based on destination IP address lookup using
//! longest prefix matching (LPM) with a radix tree data structure.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use parking_lot::RwLock;

// =============================================================================
// Error Types
// =============================================================================

/// Routing error types.
#[derive(Debug, Clone)]
pub enum RoutingError {
    /// No route found for destination.
    NoRouteToHost(IpAddr),
    /// Invalid route entry.
    InvalidRoute(String),
    /// Interface doesn't exist.
    InterfaceNotFound(i32),
    /// Route already exists.
    DuplicateRoute,
    /// Routing table full.
    TableFull,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::NoRouteToHost(ip) => write!(f, "No route to host: {}", ip),
            RoutingError::InvalidRoute(msg) => write!(f, "Invalid route: {}", msg),
            RoutingError::InterfaceNotFound(idx) => write!(f, "Interface not found: {}", idx),
            RoutingError::DuplicateRoute => write!(f, "Route already exists"),
            RoutingError::TableFull => write!(f, "Routing table full"),
        }
    }
}

impl std::error::Error for RoutingError {}

// =============================================================================
// Route Entry
// =============================================================================

/// Individual routing table entry.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination network address.
    pub destination: IpAddr,
    /// Prefix length (0-32 for IPv4, 0-128 for IPv6).
    pub prefix_len: u8,
    /// Next-hop gateway (None if on-link).
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub interface_index: i32,
    /// Route priority/cost (lower = preferred).
    pub metric: u32,
    /// True if default route (0.0.0.0/0).
    pub is_default: bool,
    /// True if route is to WAN interface (requires NAT).
    pub is_wan: bool,
    /// True if static route.
    pub is_static: bool,
    /// Route creation time.
    pub created_at: Instant,
    /// Last update time.
    pub updated_at: Instant,
}

impl RouteEntry {
    /// Creates a new route entry.
    pub fn new(
        destination: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
        interface_index: i32,
    ) -> Self {
        let now = Instant::now();
        Self {
            destination,
            prefix_len,
            gateway,
            interface_index,
            metric: 0,
            is_default: prefix_len == 0,
            is_wan: false,
            is_static: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a default route.
    pub fn default_route(gateway: IpAddr, interface_index: i32) -> Self {
        let dest = match gateway {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let mut entry = Self::new(dest, 0, Some(gateway), interface_index);
        entry.is_default = true;
        entry.is_wan = true;
        entry
    }
}

// =============================================================================
// Route Decision
// =============================================================================

/// Routing decision result.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// Selected route.
    pub route_entry: RouteEntry,
    /// Output interface index.
    pub output_interface: i32,
    /// Next-hop gateway.
    pub gateway: Option<IpAddr>,
    /// True if WAN interface (triggers NAT).
    pub is_wan: bool,
}

// =============================================================================
// Cached Route
// =============================================================================

/// Cached routing decision.
#[derive(Debug, Clone)]
struct CachedRoute {
    /// Cached route.
    route_entry: RouteEntry,
    /// Cache insertion time.
    cached_at: Instant,
    /// Last lookup time.
    last_used: Instant,
}

// =============================================================================
// Route Cache
// =============================================================================

/// LRU cache for frequently-accessed routes.
struct RouteCache {
    /// Destination IP → route mapping.
    cache: AHashMap<IpAddr, CachedRoute>,
    /// Maximum cache entries.
    max_entries: usize,
    /// Cache entry TTL.
    ttl: Duration,
    /// Cache hit count.
    hits: u64,
    /// Cache miss count.
    misses: u64,
}

impl RouteCache {
    /// Creates a new route cache.
    fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: AHashMap::with_capacity(max_entries),
            max_entries,
            ttl: Duration::from_secs(ttl_secs),
            hits: 0,
            misses: 0,
        }
    }

    /// Looks up a route in the cache.
    fn lookup(&mut self, destination: &IpAddr) -> Option<RouteEntry> {
        if let Some(cached) = self.cache.get_mut(destination) {
            let now = Instant::now();
            if now.duration_since(cached.cached_at) < self.ttl {
                cached.last_used = now;
                self.hits += 1;
                return Some(cached.route_entry.clone());
            }
            // Expired entry.
            self.cache.remove(destination);
        }
        self.misses += 1;
        None
    }

    /// Inserts a route into the cache.
    fn insert(&mut self, destination: IpAddr, route: RouteEntry) {
        if self.cache.len() >= self.max_entries {
            self.evict_lru();
        }

        let now = Instant::now();
        self.cache.insert(
            destination,
            CachedRoute {
                route_entry: route,
                cached_at: now,
                last_used: now,
            },
        );
    }

    /// Evicts the least recently used entry.
    fn evict_lru(&mut self) {
        if let Some((key, _)) = self
            .cache
            .iter()
            .min_by_key(|(_, v)| v.last_used)
            .map(|(k, v)| (*k, v.last_used))
        {
            self.cache.remove(&key);
        }
    }

    /// Clears the cache.
    fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Removes expired entries.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, v| now.duration_since(v.cached_at) < self.ttl);
    }
}

// =============================================================================
// Cache Statistics
// =============================================================================

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Hit ratio.
    pub hit_ratio: f64,
    /// Current cache size.
    pub entries: usize,
}

// =============================================================================
// Routing Statistics
// =============================================================================

/// Routing performance statistics.
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Total route lookups.
    pub total_lookups: u64,
    /// Cache hit count.
    pub cache_hits: u64,
    /// Cache miss count.
    pub cache_misses: u64,
    /// NoRouteToHost errors.
    pub no_route_errors: u64,
    /// Average lookup time in nanoseconds.
    pub avg_lookup_time_ns: u64,
    /// Total routes in table.
    pub route_count: usize,
}

// =============================================================================
// Radix Tree Node
// =============================================================================

/// Radix tree node for IP prefix storage.
#[derive(Debug)]
struct RadixNode {
    /// Route entry (if this is a route node).
    value: Option<RouteEntry>,
    /// Children indexed by bit (0 or 1).
    children: [Option<Box<RadixNode>>; 2],
}

impl RadixNode {
    /// Creates a new empty node.
    fn new() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }

    /// Creates a node with a value.
    fn with_value(route: RouteEntry) -> Self {
        Self {
            value: Some(route),
            children: [None, None],
        }
    }
}

// =============================================================================
// Radix Tree
// =============================================================================

/// Radix tree for efficient longest prefix matching.
struct RadixTree {
    /// Tree root.
    root: RadixNode,
    /// Number of routes.
    route_count: usize,
}

impl RadixTree {
    /// Creates a new empty radix tree.
    fn new() -> Self {
        Self {
            root: RadixNode::new(),
            route_count: 0,
        }
    }

    /// Inserts a route into the tree.
    fn insert(&mut self, ip_bytes: &[u8], prefix_len: u8, route: RouteEntry) {
        let mut node = &mut self.root;

        for bit_pos in 0..prefix_len {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = 7 - (bit_pos % 8);
            let bit = if byte_idx < ip_bytes.len() {
                ((ip_bytes[byte_idx] >> bit_idx) & 1) as usize
            } else {
                0
            };

            if node.children[bit].is_none() {
                node.children[bit] = Some(Box::new(RadixNode::new()));
            }
            node = node.children[bit].as_mut().unwrap();
        }

        if node.value.is_none() {
            self.route_count += 1;
        }
        node.value = Some(route);
    }

    /// Looks up the longest matching prefix.
    fn lookup(&self, ip_bytes: &[u8]) -> Option<&RouteEntry> {
        let mut node = &self.root;
        let mut best_match: Option<&RouteEntry> = node.value.as_ref();
        let max_bits = (ip_bytes.len() * 8) as u8;

        for bit_pos in 0..max_bits {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = 7 - (bit_pos % 8);
            let bit = ((ip_bytes[byte_idx] >> bit_idx) & 1) as usize;

            match &node.children[bit] {
                Some(child) => {
                    node = child;
                    if node.value.is_some() {
                        best_match = node.value.as_ref();
                    }
                }
                None => break,
            }
        }

        best_match
    }

    /// Removes a route from the tree.
    fn remove(&mut self, ip_bytes: &[u8], prefix_len: u8) -> Option<RouteEntry> {
        let mut path: Vec<(*mut RadixNode, usize)> = Vec::new();
        let mut node = &mut self.root as *mut RadixNode;

        // Navigate to the node.
        for bit_pos in 0..prefix_len {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = 7 - (bit_pos % 8);
            let bit = if byte_idx < ip_bytes.len() {
                ((ip_bytes[byte_idx] >> bit_idx) & 1) as usize
            } else {
                0
            };

            unsafe {
                path.push((node, bit));
                match &mut (*node).children[bit] {
                    Some(child) => {
                        node = child.as_mut() as *mut RadixNode;
                    }
                    None => return None,
                }
            }
        }

        // Remove the value.
        let removed = unsafe { (*node).value.take() };
        if removed.is_some() {
            self.route_count -= 1;
        }

        removed
    }
}

// =============================================================================
// Route Table
// =============================================================================

/// IPv4/IPv6 routing table.
struct RouteTable {
    /// IPv4 route tree.
    ipv4_routes: RadixTree,
    /// IPv6 route tree.
    ipv6_routes: RadixTree,
}

impl RouteTable {
    /// Creates a new empty route table.
    fn new() -> Self {
        Self {
            ipv4_routes: RadixTree::new(),
            ipv6_routes: RadixTree::new(),
        }
    }

    /// Inserts a route.
    fn insert(&mut self, route: RouteEntry) {
        match route.destination {
            IpAddr::V4(addr) => {
                self.ipv4_routes
                    .insert(&addr.octets(), route.prefix_len, route);
            }
            IpAddr::V6(addr) => {
                self.ipv6_routes
                    .insert(&addr.octets(), route.prefix_len, route);
            }
        }
    }

    /// Looks up a route.
    fn lookup(&self, destination: IpAddr) -> Option<&RouteEntry> {
        match destination {
            IpAddr::V4(addr) => self.ipv4_routes.lookup(&addr.octets()),
            IpAddr::V6(addr) => self.ipv6_routes.lookup(&addr.octets()),
        }
    }

    /// Removes a route.
    fn remove(&mut self, destination: IpAddr, prefix_len: u8) -> Option<RouteEntry> {
        match destination {
            IpAddr::V4(addr) => self.ipv4_routes.remove(&addr.octets(), prefix_len),
            IpAddr::V6(addr) => self.ipv6_routes.remove(&addr.octets(), prefix_len),
        }
    }

    /// Returns the total route count.
    fn route_count(&self) -> usize {
        self.ipv4_routes.route_count + self.ipv6_routes.route_count
    }
}

// =============================================================================
// Routing Configuration
// =============================================================================

/// Routing engine configuration.
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Enable routing cache.
    pub enable_cache: bool,
    /// Maximum cache entries.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Enable policy-based routing.
    pub enable_policy_routing: bool,
    /// Enable ECMP (equal-cost multi-path).
    pub enable_multipath: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: 10000,
            cache_ttl_secs: 60,
            enable_policy_routing: false,
            enable_multipath: false,
        }
    }
}

// =============================================================================
// Routing Engine
// =============================================================================

/// High-performance routing decision engine.
pub struct RoutingEngine {
    /// Main routing table.
    route_table: RwLock<RouteTable>,
    /// Route cache.
    route_cache: RwLock<RouteCache>,
    /// Default gateway route.
    default_route: RwLock<Option<RouteEntry>>,
    /// Routing configuration.
    config: RoutingConfig,
    /// Lookup counter.
    total_lookups: AtomicU64,
    /// No route error counter.
    no_route_errors: AtomicU64,
}

impl RoutingEngine {
    /// Creates a new routing engine.
    pub fn new(config: RoutingConfig) -> Self {
        let cache = RouteCache::new(config.cache_size, config.cache_ttl_secs);

        Self {
            route_table: RwLock::new(RouteTable::new()),
            route_cache: RwLock::new(cache),
            default_route: RwLock::new(None),
            config,
            total_lookups: AtomicU64::new(0),
            no_route_errors: AtomicU64::new(0),
        }
    }

    /// Creates a routing engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RoutingConfig::default())
    }

    /// Looks up a route for the given destination.
    pub fn lookup(&self, destination: IpAddr) -> Result<RouteDecision, RoutingError> {
        self.total_lookups.fetch_add(1, Ordering::Relaxed);

        // Step 1: Check cache.
        if self.config.enable_cache {
            let mut cache = self.route_cache.write();
            if let Some(route) = cache.lookup(&destination) {
                return Ok(RouteDecision {
                    output_interface: route.interface_index,
                    gateway: route.gateway,
                    is_wan: route.is_wan,
                    route_entry: route,
                });
            }
        }

        // Step 2: Lookup in routing table.
        let table = self.route_table.read();
        if let Some(route) = table.lookup(destination) {
            let route = route.clone();
            drop(table);

            // Cache the result.
            if self.config.enable_cache {
                let mut cache = self.route_cache.write();
                cache.insert(destination, route.clone());
            }

            return Ok(RouteDecision {
                output_interface: route.interface_index,
                gateway: route.gateway,
                is_wan: route.is_wan,
                route_entry: route,
            });
        }
        drop(table);

        // Step 3: Check default route.
        let default = self.default_route.read();
        if let Some(route) = default.as_ref() {
            return Ok(RouteDecision {
                output_interface: route.interface_index,
                gateway: route.gateway,
                is_wan: route.is_wan,
                route_entry: route.clone(),
            });
        }

        // No route found.
        self.no_route_errors.fetch_add(1, Ordering::Relaxed);
        Err(RoutingError::NoRouteToHost(destination))
    }

    /// Adds a route to the routing table.
    pub fn add_route(&self, route: RouteEntry) -> Result<(), RoutingError> {
        // Validate route.
        if route.interface_index < 0 {
            return Err(RoutingError::InvalidRoute(
                "Invalid interface index".to_string(),
            ));
        }

        let mut table = self.route_table.write();
        table.insert(route.clone());
        drop(table);

        // Update default route if this is a default route.
        if route.is_default {
            let mut default = self.default_route.write();
            *default = Some(route);
        }

        // Invalidate cache.
        self.invalidate_cache();

        Ok(())
    }

    /// Deletes a route from the routing table.
    pub fn delete_route(&self, destination: IpAddr, prefix_len: u8) -> Result<(), RoutingError> {
        let mut table = self.route_table.write();
        let removed = table.remove(destination, prefix_len);
        drop(table);

        if removed.is_none() {
            return Err(RoutingError::NoRouteToHost(destination));
        }

        // Clear default route if this was the default.
        if prefix_len == 0 {
            let mut default = self.default_route.write();
            *default = None;
        }

        // Invalidate cache.
        self.invalidate_cache();

        Ok(())
    }

    /// Updates multiple routes atomically.
    pub fn update_routes(&self, routes: Vec<RouteEntry>) -> Result<(), RoutingError> {
        let mut table = self.route_table.write();

        for route in routes {
            table.insert(route.clone());

            if route.is_default {
                let mut default = self.default_route.write();
                *default = Some(route);
            }
        }

        drop(table);
        self.invalidate_cache();
        Ok(())
    }

    /// Sets the default gateway.
    pub fn set_default_gateway(
        &self,
        gateway: IpAddr,
        interface_index: i32,
    ) -> Result<(), RoutingError> {
        let route = RouteEntry::default_route(gateway, interface_index);
        self.add_route(route)
    }

    /// Gets the default gateway.
    pub fn get_default_gateway(&self) -> Option<IpAddr> {
        let default = self.default_route.read();
        default.as_ref().and_then(|r| r.gateway)
    }

    /// Invalidates the route cache.
    pub fn invalidate_cache(&self) {
        if self.config.enable_cache {
            let mut cache = self.route_cache.write();
            cache.clear();
        }
    }

    /// Evicts expired cache entries.
    pub fn evict_expired_cache(&self) {
        if self.config.enable_cache {
            let mut cache = self.route_cache.write();
            cache.evict_expired();
        }
    }

    /// Handles interface state changes.
    pub fn interface_state_changed(
        &self,
        interface_index: i32,
        _is_up: bool,
    ) -> Result<(), RoutingError> {
        // In a real implementation, we would:
        // - If DOWN: Mark all routes using this interface as inactive
        // - If UP: Restore routes for this interface

        // For now, just invalidate cache.
        self.invalidate_cache();
        Ok(())
    }

    /// Returns cache statistics.
    pub fn get_cache_stats(&self) -> CacheStats {
        let cache = self.route_cache.read();
        let total = cache.hits + cache.misses;
        CacheStats {
            hits: cache.hits,
            misses: cache.misses,
            hit_ratio: if total > 0 {
                cache.hits as f64 / total as f64
            } else {
                0.0
            },
            entries: cache.cache.len(),
        }
    }

    /// Returns routing statistics.
    pub fn get_statistics(&self) -> RoutingStats {
        let cache = self.route_cache.read();
        let table = self.route_table.read();

        RoutingStats {
            total_lookups: self.total_lookups.load(Ordering::Relaxed),
            cache_hits: cache.hits,
            cache_misses: cache.misses,
            no_route_errors: self.no_route_errors.load(Ordering::Relaxed),
            avg_lookup_time_ns: 0, // Would need timing to calculate.
            route_count: table.route_count(),
        }
    }

    /// Returns the routing configuration.
    pub fn get_config(&self) -> &RoutingConfig {
        &self.config
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_entry_new() {
        let route = RouteEntry::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            1,
        );

        assert_eq!(route.prefix_len, 24);
        assert_eq!(route.interface_index, 1);
        assert!(!route.is_default);
    }

    #[test]
    fn test_default_route() {
        let route = RouteEntry::default_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 2);

        assert!(route.is_default);
        assert!(route.is_wan);
        assert_eq!(route.prefix_len, 0);
    }

    #[test]
    fn test_radix_tree_insert_lookup() {
        let mut tree = RadixTree::new();

        let route = RouteEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, None, 1);
        tree.insert(&[192, 168, 1, 0], 24, route);

        // Exact match.
        let result = tree.lookup(&[192, 168, 1, 100]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().interface_index, 1);

        // No match.
        let result = tree.lookup(&[10, 0, 0, 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut tree = RadixTree::new();

        // Add 192.168.0.0/16 -> interface 1.
        tree.insert(
            &[192, 168, 0, 0],
            16,
            RouteEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16, None, 1),
        );

        // Add 192.168.1.0/24 -> interface 2 (more specific).
        tree.insert(
            &[192, 168, 1, 0],
            24,
            RouteEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, None, 2),
        );

        // Should match /24 (longer prefix).
        let result = tree.lookup(&[192, 168, 1, 100]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().interface_index, 2);

        // Should match /16.
        let result = tree.lookup(&[192, 168, 2, 100]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().interface_index, 1);
    }

    #[test]
    fn test_routing_engine_add_lookup() {
        let engine = RoutingEngine::with_defaults();

        let route = RouteEntry::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            1,
        );
        engine.add_route(route).unwrap();

        let result = engine.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(result.is_ok());
        let decision = result.unwrap();
        assert_eq!(decision.output_interface, 1);
    }

    #[test]
    fn test_default_gateway() {
        let engine = RoutingEngine::with_defaults();

        engine
            .set_default_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1)
            .unwrap();

        let gw = engine.get_default_gateway();
        assert!(gw.is_some());
        assert_eq!(gw.unwrap(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Any IP should match default route.
        let result = engine.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(result.is_ok());
    }

    #[test]
    fn test_route_cache() {
        let config = RoutingConfig {
            enable_cache: true,
            cache_size: 100,
            cache_ttl_secs: 60,
            ..Default::default()
        };
        let engine = RoutingEngine::new(config);

        let route = RouteEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, None, 1);
        engine.add_route(route).unwrap();

        // First lookup - cache miss.
        let _ = engine.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));

        // Second lookup - cache hit.
        let _ = engine.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));

        let stats = engine.get_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_no_route_error() {
        let engine = RoutingEngine::with_defaults();

        let result = engine.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(matches!(result, Err(RoutingError::NoRouteToHost(_))));
    }

    #[test]
    fn test_batch_update() {
        let engine = RoutingEngine::with_defaults();

        let routes = vec![
            RouteEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, None, 1),
            RouteEntry::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12, None, 2),
            RouteEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16, None, 3),
        ];

        engine.update_routes(routes).unwrap();

        let stats = engine.get_statistics();
        assert_eq!(stats.route_count, 3);
    }
}
