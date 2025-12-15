//! Performance metrics collection and reporting
//!
//! Provides thread-safe metric collection including counters, gauges,
//! histograms, timers, and multiple export formats for monitoring.
//!
//! # Metric Types
//! - **Counters**: Monotonically increasing values (packet counts, errors)
//! - **Gauges**: Current state values (active connections, memory usage)
//! - **Histograms**: Distributions with percentiles (latency, packet sizes)
//! - **Timers**: Automatic duration tracking
//!
//! # Export Formats
//! - **Prometheus**: Exposition format for Prometheus scraping
//! - **JSON**: Structured JSON for REST APIs
//! - **StatsD**: UDP protocol for StatsD/Graphite
//!
//! # Performance
//! - Lock-free atomic operations for counters/gauges
//! - Minimal overhead histogram recording
//! - Thread-safe registry

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Counter
// ============================================================================

/// A monotonically increasing counter
#[derive(Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Create a new counter
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }
    
    /// Increment by 1
    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increment by n
    #[inline]
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }
    
    /// Get current value
    #[inline]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
    
    /// Reset and return old value
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

// ============================================================================
// Gauge
// ============================================================================

/// A value that can go up and down
#[derive(Default)]
pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    /// Create a new gauge
    pub fn new() -> Self {
        Self {
            value: AtomicI64::new(0),
        }
    }
    
    /// Set the value
    #[inline]
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }
    
    /// Increment by 1
    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Decrement by 1
    #[inline]
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Add to the value
    #[inline]
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }
    
    /// Subtract from the value
    #[inline]
    pub fn sub(&self, n: i64) {
        self.value.fetch_sub(n, Ordering::Relaxed);
    }
    
    /// Get current value
    #[inline]
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Histogram
// ============================================================================

/// Histogram bucket boundaries
pub struct HistogramBuckets {
    boundaries: Vec<f64>,
}

impl HistogramBuckets {
    /// Create with custom boundaries
    pub fn new(boundaries: Vec<f64>) -> Self {
        let mut sorted = boundaries;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Self { boundaries: sorted }
    }
    
    /// Create linear buckets
    pub fn linear(start: f64, width: f64, count: usize) -> Self {
        let boundaries = (0..count)
            .map(|i| start + width * (i as f64))
            .collect();
        Self { boundaries }
    }
    
    /// Create exponential buckets
    pub fn exponential(start: f64, factor: f64, count: usize) -> Self {
        let boundaries = (0..count)
            .map(|i| start * factor.powi(i as i32))
            .collect();
        Self { boundaries }
    }
    
    /// Default latency buckets (in seconds)
    pub fn latency() -> Self {
        Self::new(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ])
    }
    
    /// Default size buckets (in bytes)
    pub fn size() -> Self {
        Self::exponential(64.0, 2.0, 12) // 64B to 256KB
    }
}

/// A histogram for recording distributions
pub struct Histogram {
    buckets: Vec<AtomicU64>,
    boundaries: Vec<f64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Create a new histogram with the given buckets
    pub fn new(config: HistogramBuckets) -> Self {
        let bucket_count = config.boundaries.len() + 1; // +1 for overflow bucket
        let buckets = (0..bucket_count)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        Self {
            buckets,
            boundaries: config.boundaries,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
    
    /// Create with default latency buckets
    pub fn latency() -> Self {
        Self::new(HistogramBuckets::latency())
    }
    
    /// Record a value
    pub fn observe(&self, value: f64) {
        // Find the bucket
        let bucket_idx = self.boundaries
            .iter()
            .position(|&b| value <= b)
            .unwrap_or(self.boundaries.len());
        
        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        
        // Update sum (as bits)
        let value_bits = value.to_bits();
        self.sum.fetch_add(value_bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a duration
    pub fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_secs_f64());
    }
    
    /// Time a closure
    pub fn time<T, F: FnOnce() -> T>(&self, f: F) -> T {
        let start = Instant::now();
        let result = f();
        self.observe_duration(start.elapsed());
        result
    }
    
    /// Get bucket counts
    pub fn get_buckets(&self) -> Vec<(f64, u64)> {
        self.boundaries
            .iter()
            .zip(self.buckets.iter())
            .map(|(&b, c)| (b, c.load(Ordering::Relaxed)))
            .collect()
    }
    
    /// Get total count
    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    
    /// Get sum of all observations
    pub fn get_sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }
    
    /// Get mean value
    pub fn get_mean(&self) -> f64 {
        let count = self.get_count();
        if count == 0 {
            0.0
        } else {
            self.get_sum() / (count as f64)
        }
    }
    
    /// Calculate percentile
    pub fn percentile(&self, p: f64) -> f64 {
        if p < 0.0 || p > 1.0 {
            return 0.0;
        }
        
        let count = self.get_count();
        if count == 0 {
            return 0.0;
        }
        
        let target = (count as f64 * p).ceil() as u64;
        let mut cumulative = 0u64;
        
        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return if i < self.boundaries.len() {
                    self.boundaries[i]
                } else {
                    std::f64::INFINITY
                };
            }
        }
        
        std::f64::INFINITY
    }
    
    /// Get p50 (median)
    pub fn p50(&self) -> f64 {
        self.percentile(0.5)
    }
    
    /// Get p95
    pub fn p95(&self) -> f64 {
        self.percentile(0.95)
    }
    
    /// Get p99
    pub fn p99(&self) -> f64 {
        self.percentile(0.99)
    }
}

// ============================================================================
// Timer Guard
// ============================================================================

/// A guard that records duration on drop
pub struct TimerGuard<'a> {
    histogram: &'a Histogram,
    start: Instant,
}

impl<'a> TimerGuard<'a> {
    /// Create a new timer guard
    pub fn new(histogram: &'a Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
}

impl<'a> Drop for TimerGuard<'a> {
    fn drop(&mut self) {
        self.histogram.observe_duration(self.start.elapsed());
    }
}

// ============================================================================
// Metrics Registry
// ============================================================================

/// A registry of named metrics
pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    gauges: RwLock<HashMap<String, Arc<Gauge>>>,
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,
    prefix: String,
}

impl MetricsRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            prefix: String::new(),
        }
    }
    
    /// Create with a prefix
    pub fn with_prefix(prefix: &str) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            prefix: format!("{}_", prefix),
        }
    }
    
    /// Get or create a counter
    pub fn counter(&self, name: &str) -> Arc<Counter> {
        let full_name = format!("{}{}", self.prefix, name);
        
        // Try read lock first
        {
            let counters = self.counters.read().unwrap();
            if let Some(counter) = counters.get(&full_name) {
                return counter.clone();
            }
        }
        
        // Need to create
        let mut counters = self.counters.write().unwrap();
        counters
            .entry(full_name)
            .or_insert_with(|| Arc::new(Counter::new()))
            .clone()
    }
    
    /// Get or create a gauge
    pub fn gauge(&self, name: &str) -> Arc<Gauge> {
        let full_name = format!("{}{}", self.prefix, name);
        
        {
            let gauges = self.gauges.read().unwrap();
            if let Some(gauge) = gauges.get(&full_name) {
                return gauge.clone();
            }
        }
        
        let mut gauges = self.gauges.write().unwrap();
        gauges
            .entry(full_name)
            .or_insert_with(|| Arc::new(Gauge::new()))
            .clone()
    }
    
    /// Get or create a histogram
    pub fn histogram(&self, name: &str) -> Arc<Histogram> {
        let full_name = format!("{}{}", self.prefix, name);
        
        {
            let histograms = self.histograms.read().unwrap();
            if let Some(h) = histograms.get(&full_name) {
                return h.clone();
            }
        }
        
        let mut histograms = self.histograms.write().unwrap();
        histograms
            .entry(full_name)
            .or_insert_with(|| Arc::new(Histogram::latency()))
            .clone()
    }
    
    /// Get all counter values
    pub fn get_counters(&self) -> HashMap<String, u64> {
        self.counters
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect()
    }
    
    /// Get all gauge values
    pub fn get_gauges(&self) -> HashMap<String, i64> {
        self.gauges
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect()
    }
    
    /// Export all metrics as Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Export counters
        for (name, counter) in self.counters.read().unwrap().iter() {
            output.push_str(&format!(
                "# TYPE {} counter\n{} {}\n",
                name,
                name,
                counter.get()
            ));
        }
        
        // Export gauges
        for (name, gauge) in self.gauges.read().unwrap().iter() {
            output.push_str(&format!(
                "# TYPE {} gauge\n{} {}\n",
                name,
                name,
                gauge.get()
            ));
        }
        
        // Export histograms
        for (name, histogram) in self.histograms.read().unwrap().iter() {
            output.push_str(&format!("# TYPE {} histogram\n", name));
            
            let mut cumulative = 0u64;
            for (boundary, count) in histogram.get_buckets() {
                cumulative += count;
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    name, boundary, cumulative
                ));
            }
            
            output.push_str(&format!(
                "{}_bucket{{le=\"+Inf\"}} {}\n",
                name,
                histogram.get_count()
            ));
            output.push_str(&format!("{}_count {}\n", name, histogram.get_count()));
        }
        
        output
    }
    
    /// Export all metrics as JSON
    pub fn export_json(&self) -> String {
        let mut output = String::from("{\n");
        
        // Export counters
        output.push_str("  \"counters\": {\n");
        let counters: Vec<_> = self.counters.read().unwrap()
            .iter()
            .map(|(k, v)| format!("    \"{}\": {}", k, v.get()))
            .collect();
        output.push_str(&counters.join(",\n"));
        output.push_str("\n  },\n");
        
        // Export gauges
        output.push_str("  \"gauges\": {\n");
        let gauges: Vec<_> = self.gauges.read().unwrap()
            .iter()
            .map(|(k, v)| format!("    \"{}\": {}", k, v.get()))
            .collect();
        output.push_str(&gauges.join(",\n"));
        output.push_str("\n  },\n");
        
        // Export histograms
        output.push_str("  \"histograms\": {\n");
        let histograms: Vec<_> = self.histograms.read().unwrap()
            .iter()
            .map(|(k, h)| {
                format!(
                    "    \"{}\": {{\"count\": {}, \"mean\": {:.6}, \"p50\": {:.6}, \"p95\": {:.6}, \"p99\": {:.6}}}",
                    k, h.get_count(), h.get_mean(), h.p50(), h.p95(), h.p99()
                )
            })
            .collect();
        output.push_str(&histograms.join(",\n"));
        output.push_str("\n  }\n");
        
        output.push_str("}");
        output
    }
    
    /// Export metrics in StatsD format
    /// Returns a vector of StatsD protocol lines
    pub fn export_statsd(&self) -> Vec<String> {
        let mut lines = Vec::new();
        
        // Export counters
        for (name, counter) in self.counters.read().unwrap().iter() {
            lines.push(format!("{}:{}|c", name, counter.get()));
        }
        
        // Export gauges
        for (name, gauge) in self.gauges.read().unwrap().iter() {
            lines.push(format!("{}:{}|g", name, gauge.get()));
        }
        
        // Export histograms as timing metrics
        for (name, histogram) in self.histograms.read().unwrap().iter() {
            let mean_ms = (histogram.get_mean() * 1000.0) as i64;
            lines.push(format!("{}:{}|ms", name, mean_ms));
            
            // Also export percentiles
            let p95_ms = (histogram.p95() * 1000.0) as i64;
            let p99_ms = (histogram.p99() * 1000.0) as i64;
            lines.push(format!("{}.p95:{}|ms", name, p95_ms));
            lines.push(format!("{}.p99:{}|ms", name, p99_ms));
        }
        
        lines
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Rate Tracker
// ============================================================================

/// Track rate of events over time
pub struct RateTracker {
    counts: Vec<AtomicU64>,
    current_slot: AtomicU64,
    slot_duration_ms: u64,
    start_time: Instant,
}

impl RateTracker {
    /// Create a rate tracker
    /// 
    /// # Arguments
    /// * `window_seconds` - Time window to track
    /// * `resolution` - Number of slots in the window
    pub fn new(window_seconds: u64, resolution: usize) -> Self {
        let counts = (0..resolution)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        let slot_duration_ms = (window_seconds * 1000) / resolution as u64;
        
        Self {
            counts,
            current_slot: AtomicU64::new(0),
            slot_duration_ms,
            start_time: Instant::now(),
        }
    }
    
    /// Record an event
    pub fn record(&self) {
        self.record_n(1);
    }
    
    /// Record n events
    pub fn record_n(&self, n: u64) {
        let elapsed_ms = self.start_time.elapsed().as_millis() as u64;
        let slot = (elapsed_ms / self.slot_duration_ms) as usize % self.counts.len();
        
        let prev_slot = self.current_slot.load(Ordering::Relaxed) as usize;
        if slot != prev_slot {
            // Clear slots between prev and current
            self.current_slot.store(slot as u64, Ordering::Relaxed);
            self.counts[slot].store(0, Ordering::Relaxed);
        }
        
        self.counts[slot].fetch_add(n, Ordering::Relaxed);
    }
    
    /// Get rate per second
    pub fn rate(&self) -> f64 {
        let total: u64 = self.counts.iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        
        let window_secs = (self.slot_duration_ms * self.counts.len() as u64) as f64 / 1000.0;
        total as f64 / window_secs
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        
        counter.inc();
        counter.inc();
        counter.add(5);
        
        assert_eq!(counter.get(), 7);
        assert_eq!(counter.reset(), 7);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        
        gauge.set(10);
        assert_eq!(gauge.get(), 10);
        
        gauge.inc();
        assert_eq!(gauge.get(), 11);
        
        gauge.dec();
        gauge.sub(5);
        assert_eq!(gauge.get(), 5);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(HistogramBuckets::new(vec![1.0, 5.0, 10.0]));
        
        histogram.observe(0.5);
        histogram.observe(3.0);
        histogram.observe(7.0);
        histogram.observe(15.0);
        
        assert_eq!(histogram.get_count(), 4);
        
        let buckets = histogram.get_buckets();
        assert_eq!(buckets[0], (1.0, 1)); // 0.5 <= 1.0
        assert_eq!(buckets[1], (5.0, 1)); // 3.0 <= 5.0
        assert_eq!(buckets[2], (10.0, 1)); // 7.0 <= 10.0
    }

    #[test]
    fn test_histogram_timing() {
        let histogram = Histogram::latency();
        
        let result = histogram.time(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
        assert_eq!(histogram.get_count(), 1);
    }

    #[test]
    fn test_registry() {
        let registry = MetricsRegistry::with_prefix("test");
        
        let counter = registry.counter("requests");
        counter.inc();
        counter.inc();
        
        let gauge = registry.gauge("connections");
        gauge.set(5);
        
        let counters = registry.get_counters();
        assert_eq!(counters.get("test_requests"), Some(&2));
        
        let gauges = registry.get_gauges();
        assert_eq!(gauges.get("test_connections"), Some(&5));
    }

    #[test]
    fn test_prometheus_export() {
        let registry = MetricsRegistry::new();
        
        registry.counter("requests_total").add(100);
        registry.gauge("active_connections").set(42);
        
        let output = registry.export_prometheus();
        
        assert!(output.contains("requests_total 100"));
        assert!(output.contains("active_connections 42"));
    }

    #[test]
    fn test_rate_tracker() {
        let tracker = RateTracker::new(1, 10); // 1 second, 10 slots
        
        for _ in 0..100 {
            tracker.record();
        }
        
        let rate = tracker.rate();
        assert!(rate > 0.0);
    }

    #[test]
    fn test_histogram_percentiles() {
        let histogram = Histogram::new(HistogramBuckets::linear(0.0, 10.0, 10));
        
        // Add 100 values from 0 to 99
        for i in 0..100 {
            histogram.observe(i as f64);
        }
        
        assert_eq!(histogram.get_count(), 100);
        assert!(histogram.get_mean() > 40.0 && histogram.get_mean() < 50.0);
        
        // Check percentiles
        let p50 = histogram.p50();
        let p95 = histogram.p95();
        let p99 = histogram.p99();
        
        assert!(p50 >= 40.0 && p50 <= 60.0);
        assert!(p95 >= 90.0);
        assert!(p99 >= 90.0);
    }

    #[test]
    fn test_json_export() {
        let registry = MetricsRegistry::new();
        
        registry.counter("requests_total").add(100);
        registry.gauge("active_connections").set(42);
        
        let json = registry.export_json();
        
        assert!(json.contains("requests_total"));
        assert!(json.contains("active_connections"));
        assert!(json.contains("counters"));
        assert!(json.contains("gauges"));
    }

    #[test]
    fn test_statsd_export() {
        let registry = MetricsRegistry::new();
        
        registry.counter("requests").add(50);
        registry.gauge("connections").set(10);
        
        let statsd = registry.export_statsd();
        
        assert!(statsd.iter().any(|l| l.contains("requests:50|c")));
        assert!(statsd.iter().any(|l| l.contains("connections:10|g")));
    }

    #[test]
    fn test_histogram_stats() {
        let histogram = Histogram::new(HistogramBuckets::new(vec![1.0, 2.0, 3.0, 4.0, 5.0]));
        
        histogram.observe(1.5);
        histogram.observe(2.5);
        histogram.observe(3.5);
        
        assert_eq!(histogram.get_count(), 3);
        let sum = histogram.get_sum();
        assert!((sum - 7.5).abs() < 0.01);
        
        let mean = histogram.get_mean();
        assert!((mean - 2.5).abs() < 0.01);
    }
}
