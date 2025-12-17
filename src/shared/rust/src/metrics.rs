//! Prometheus metrics collection and export
//!
//! Provides Prometheus metrics for monitoring shared library operations including
//! packet processing, error rates, memory pool utilization, and performance timings.
//! Implements centralized registry with standard metrics for consistent monitoring.

use crate::error::{Result, SafeOpsError};
use once_cell::sync::Lazy;
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder, Encoder,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ============================================================================
// Global Registry
// ============================================================================

/// Global metrics registry singleton
pub static METRICS: Lazy<MetricsRegistry> = Lazy::new(MetricsRegistry::new);

/// Centralized metrics registry
pub struct MetricsRegistry {
    registry: Arc<Registry>,
    enabled: AtomicBool,
}

impl MetricsRegistry {
    /// Creates new metrics registry
    pub fn new() -> Self {
        let enabled = std::env::var("ENABLE_METRICS")
            .map(|v| v != "false")
            .unwrap_or(true);

        MetricsRegistry {
            registry: Arc::new(Registry::new()),
            enabled: AtomicBool::new(enabled),
        }
    }

    /// Returns global singleton instance
    pub fn global() -> &'static MetricsRegistry {
        &METRICS
    }

    /// Registers a counter metric
    pub fn register_counter(&self, name: &str, help: &str) -> Result<IntCounter> {
        let counter = IntCounter::new(name, help)
            .map_err(|e| SafeOpsError::internal(format!("Failed to create counter: {}", e)))?;
        self.registry.register(Box::new(counter.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register counter: {}", e)))?;
        Ok(counter)
    }

    /// Registers a counter vec with labels
    pub fn register_counter_vec(&self, name: &str, help: &str, labels: &[&str]) -> Result<IntCounterVec> {
        let counter = IntCounterVec::new(Opts::new(name, help), labels)
            .map_err(|e| SafeOpsError::internal(format!("Failed to create counter vec: {}", e)))?;
        self.registry.register(Box::new(counter.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register counter vec: {}", e)))?;
        Ok(counter)
    }

    /// Registers a gauge metric
    pub fn register_gauge(&self, name: &str, help: &str) -> Result<IntGauge> {
        let gauge = IntGauge::new(name, help)
            .map_err(|e| SafeOpsError::internal(format!("Failed to create gauge: {}", e)))?;
        self.registry.register(Box::new(gauge.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register gauge: {}", e)))?;
        Ok(gauge)
    }

    /// Registers a gauge vec with labels
    pub fn register_gauge_vec(&self, name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec> {
        let gauge = IntGaugeVec::new(Opts::new(name, help), labels)
            .map_err(|e| SafeOpsError::internal(format!("Failed to create gauge vec: {}", e)))?;
        self.registry.register(Box::new(gauge.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register gauge vec: {}", e)))?;
        Ok(gauge)
    }

    /// Registers a histogram with custom buckets
    pub fn register_histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Result<Histogram> {
        let histogram = Histogram::with_opts(
            HistogramOpts::new(name, help).buckets(buckets)
        ).map_err(|e| SafeOpsError::internal(format!("Failed to create histogram: {}", e)))?;
        
        self.registry.register(Box::new(histogram.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register histogram: {}", e)))?;
        Ok(histogram)
    }

    /// Registers a histogram vec with labels
    pub fn register_histogram_vec(&self, name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> Result<HistogramVec> {
        let histogram = HistogramVec::new(
            HistogramOpts::new(name, help).buckets(buckets),
            labels
        ).map_err(|e| SafeOpsError::internal(format!("Failed to create histogram vec: {}", e)))?;
        
        self.registry.register(Box::new(histogram.clone()))
            .map_err(|e| SafeOpsError::internal(format!("Failed to register histogram vec: {}", e)))?;
        Ok(histogram)
    }

    /// Gathers all metrics for Prometheus scraping
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// Returns the underlying registry
    pub fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    /// Enables metrics collection
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// Disables metrics collection
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Returns whether metrics are enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Standard Histogram Buckets
// ============================================================================

/// Default latency buckets (microseconds to seconds)
pub fn latency_buckets() -> Vec<f64> {
    vec![0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
}

/// Default size buckets (bytes)
pub fn size_buckets() -> Vec<f64> {
    vec![64.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 65536.0]
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Increments named counter by 1
#[inline]
pub fn increment_counter(counter: &IntCounter) {
    if METRICS.is_enabled() {
        counter.inc();
    }
}

/// Increments counter by specific amount
#[inline]
pub fn increment_counter_by(counter: &IntCounter, value: u64) {
    if METRICS.is_enabled() {
        counter.inc_by(value);
    }
}

/// Sets gauge to specific value
#[inline]
pub fn set_gauge(gauge: &IntGauge, value: i64) {
    if METRICS.is_enabled() {
        gauge.set(value);
    }
}

/// Increments gauge by delta
#[inline]
pub fn increment_gauge(gauge: &IntGauge, delta: i64) {
    if METRICS.is_enabled() {
        gauge.add(delta);
    }
}

/// Decrements gauge by delta
#[inline]
pub fn decrement_gauge(gauge: &IntGauge, delta: i64) {
    if METRICS.is_enabled() {
        gauge.sub(delta);
    }
}

/// Records observation in histogram
#[inline]
pub fn observe_histogram(histogram: &Histogram, value: f64) {
    if METRICS.is_enabled() {
        histogram.observe(value);
    }
}

/// Times function execution and records in histogram
pub fn time_operation<F, T>(histogram: &Histogram, f: F) -> T
where
    F: FnOnce() -> T,
{
    if METRICS.is_enabled() {
        let timer = histogram.start_timer();
        let result = f();
        timer.observe_duration();
        result
    } else {
        f()
    }
}

// ============================================================================
// Export Functions
// ============================================================================

/// Returns metrics in Prometheus text format
pub fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = METRICS.gather();
    
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    String::from_utf8(buffer).unwrap()
}

/// Returns metrics as JSON (for debugging)
pub fn metrics_json() -> Result<String> {
    let metric_families = METRICS.gather();
    serde_json::to_string_pretty(&metric_families)
        .map_err(|e| SafeOpsError::internal(format!("JSON serialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry() {
        let registry = MetricsRegistry::new();
        
        let counter = registry.register_counter("test_counter", "Test counter").unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1);

        let gauge = registry.register_gauge("test_gauge", "Test gauge").unwrap();
        gauge.set(42);
        assert_eq!(gauge.get(), 42);

        let metrics = registry.gather();
        assert!(!metrics.is_empty());
    }

    #[test]
    fn test_counter_vec() {
        let registry = MetricsRegistry::new();
        let counter_vec = registry.register_counter_vec(
            "test_counter_vec",
            "Test counter vec",
            &["label1", "label2"]
        ).unwrap();

        counter_vec.with_label_values(&["value1", "value2"]).inc();
        assert_eq!(counter_vec.with_label_values(&["value1", "value2"]).get(), 1);
    }

    #[test]
    fn test_histogram() {
        let registry = MetricsRegistry::new();
        let histogram = registry.register_histogram(
            "test_histogram",
            "Test histogram",
            latency_buckets()
        ).unwrap();

        histogram.observe(0.001);
        histogram.observe(0.01);
        
        assert_eq!(histogram.get_sample_count(), 2);
    }

    #[test]
    fn test_enable_disable() {
        let registry = MetricsRegistry::new();
        
        assert!(registry.is_enabled());
        
        registry.disable();
        assert!(!registry.is_enabled());
        
        registry.enable();
        assert!(registry.is_enabled());
    }

    #[test]
    fn test_time_operation() {
        let registry = MetricsRegistry::new();
        let histogram = registry.register_histogram(
            "test_timer",
            "Test timer",
            latency_buckets()
        ).unwrap();

        let result = time_operation(&histogram, || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        });

        assert_eq!(result, 42);
        assert_eq!(histogram.get_sample_count(), 1);
    }

    #[test]
    fn test_metrics_handler() {
        let handler_output = metrics_handler();
        assert!(handler_output.contains("# HELP"));
        assert!(handler_output.contains("# TYPE"));
    }

    #[test]
    fn test_helper_functions() {
        let registry = MetricsRegistry::new();
        let counter = registry.register_counter("helper_counter", "Helper counter").unwrap();
        let gauge = registry.register_gauge("helper_gauge", "Helper gauge").unwrap();

        increment_counter(&counter);
        increment_counter_by(&counter, 5);
        assert_eq!(counter.get(), 6);

        set_gauge(&gauge, 100);
        assert_eq!(gauge.get(), 100);
        
        increment_gauge(&gauge, 10);
        assert_eq!(gauge.get(), 110);
        
        decrement_gauge(&gauge, 5);
        assert_eq!(gauge.get(), 105);
    }
}
