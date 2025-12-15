//! High-precision time utilities for packet timing and performance measurement
//!
//! Provides nanosecond-precision timestamps, monotonic clocks, time conversions,
//! and time-series operations optimized for network monitoring.
//!
//! # Features
//! - **High Precision**: Nanosecond-resolution timestamps
//! - **Monotonic Clock**: CLOCK_MONOTONIC for reliable duration measurement
//! - **Wall Clock**: UTC timestamps with RFC3339 formatting
//! - **Time Windows**: Rolling windows for time-series analysis
//! - **Performance**: High-resolution timers for packet timing
//!
//! # Precision
//! - Uses `Instant` (monotonic) for relative timing
//! - Uses `SystemTime` for absolute timestamps
//! - Platform-specific optimizations (QueryPerformanceCounter on Windows)
//!
//! # Common Patterns
//! ```rust,ignore
//! use safeops_shared::time_utils::*;
//!
//! // Measure operation time
//! let start = monotonic_now();
//! do_work();
//! let elapsed = elapsed_nanos(start);
//! ```

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Timestamps
// ============================================================================

/// Get current Unix timestamp in seconds
#[inline]
pub fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Get current Unix timestamp in milliseconds
#[inline]
pub fn unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get current Unix timestamp in microseconds
#[inline]
pub fn unix_timestamp_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Get current Unix timestamp in nanoseconds
#[inline]
pub fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Convert Unix timestamp to SystemTime
#[inline]
pub fn from_unix_timestamp_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Convert Unix timestamp in millis to SystemTime
#[inline]
pub fn from_unix_timestamp_millis(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

// ============================================================================
// RFC3339 Formatting
// ============================================================================

/// Format SystemTime as RFC3339 timestamp
pub fn format_rfc3339(time: SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();
    
    // Calculate date/time components
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;
    
    let hours = secs_today / 3600;
    let mins = (secs_today % 3600) / 60;
    let secs_component = secs_today % 60;
    
    // Simplified: assumes ~365.25 days per year
    let year = 1970 + (days_since_epoch / 365);
    let day_of_year = days_since_epoch % 365;
    
    // Simplified month/day calculation
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;
    
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        year, month.min(12), day.min(31), hours, mins, secs_component, nanos
    )
}

/// Get current time as RFC3339 string
pub fn now_rfc3339() -> String {
    format_rfc3339(SystemTime::now())
}

// ============================================================================
// Monotonic Clock
// ============================================================================

/// Get monotonic timestamp for duration measurement
#[inline]
pub fn monotonic_now() -> Instant {
    Instant::now()
}

/// Measure elapsed time since an instant
#[inline]
pub fn elapsed_since(start: Instant) -> Duration {
    start.elapsed()
}

/// Measure elapsed time in nanoseconds
#[inline]
pub fn elapsed_nanos(start: Instant) -> u64 {
    start.elapsed().as_nanos() as u64
}

/// Measure elapsed time in microseconds
#[inline]
pub fn elapsed_micros(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64
}

/// Measure elapsed time in milliseconds
#[inline]
pub fn elapsed_millis(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

// ============================================================================
// Stopwatch
// ============================================================================

/// A simple stopwatch for timing operations
pub struct Stopwatch {
    start: Option<Instant>,
    elapsed: Duration,
}

impl Stopwatch {
    /// Create a new stopped stopwatch
    pub fn new() -> Self {
        Self {
            start: None,
            elapsed: Duration::ZERO,
        }
    }
    
    /// Create and start a stopwatch
    pub fn start_new() -> Self {
        Self {
            start: Some(Instant::now()),
            elapsed: Duration::ZERO,
        }
    }
    
    /// Start the stopwatch
    pub fn start(&mut self) {
        if self.start.is_none() {
            self.start = Some(Instant::now());
        }
    }
    
    /// Stop the stopwatch
    pub fn stop(&mut self) {
        if let Some(start) = self.start.take() {
            self.elapsed += start.elapsed();
        }
    }
    
    /// Reset the stopwatch
    pub fn reset(&mut self) {
        self.start = None;
        self.elapsed = Duration::ZERO;
    }
    
    /// Restart the stopwatch
    pub fn restart(&mut self) {
        self.elapsed = Duration::ZERO;
        self.start = Some(Instant::now());
    }
    
    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        let running = self.start.map(|s| s.elapsed()).unwrap_or_default();
        self.elapsed + running
    }
    
    /// Get elapsed milliseconds
    pub fn elapsed_millis(&self) -> u64 {
        self.elapsed().as_millis() as u64
    }
    
    /// Check if running
    pub fn is_running(&self) -> bool {
        self.start.is_some()
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Duration Formatting
// ============================================================================

/// Format duration as human-readable string
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let nanos = d.subsec_nanos();
    
    if total_secs == 0 {
        if nanos < 1_000 {
            return format!("{}ns", nanos);
        } else if nanos < 1_000_000 {
            return format!("{:.2}µs", nanos as f64 / 1_000.0);
        } else {
            return format!("{:.2}ms", nanos as f64 / 1_000_000.0);
        }
    }
    
    if total_secs < 60 {
        return format!("{:.2}s", d.as_secs_f64());
    }
    
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    
    if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else {
        format!("{}m {}s", mins, secs)
    }
}

/// Format duration as compact string (e.g., "1h2m3s")
pub fn format_duration_compact(d: Duration) -> String {
    let total_secs = d.as_secs();
    
    if total_secs == 0 {
        let millis = d.subsec_millis();
        return format!("{}ms", millis);
    }
    
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    
    let mut result = String::new();
    
    if hours > 0 {
        result.push_str(&format!("{}h", hours));
    }
    if mins > 0 {
        result.push_str(&format!("{}m", mins));
    }
    if secs > 0 || result.is_empty() {
        result.push_str(&format!("{}s", secs));
    }
    
    result
}

/// Parse duration from string (e.g., "1h30m", "500ms")
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();
    
    if s.is_empty() {
        return None;
    }
    
    // Simple formats
    if let Some(ns) = s.strip_suffix("ns") {
        return ns.trim().parse::<u64>().ok().map(Duration::from_nanos);
    }
    if let Some(us) = s.strip_suffix("µs").or_else(|| s.strip_suffix("us")) {
        return us.trim().parse::<u64>().ok().map(Duration::from_micros);
    }
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.trim().parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(secs) = s.strip_suffix('s') {
        if !secs.contains('m') && !secs.contains('h') {
            return secs.trim().parse::<f64>().ok().map(Duration::from_secs_f64);
        }
    }
    
    // Complex format like "1h30m45s"
    let mut total = Duration::ZERO;
    let mut current_num = String::new();
    
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            current_num.push(c);
        } else if !current_num.is_empty() {
            let num: f64 = current_num.parse().ok()?;
            current_num.clear();
            
            let duration = match c {
                'h' => Duration::from_secs_f64(num * 3600.0),
                'm' => Duration::from_secs_f64(num * 60.0),
                's' => Duration::from_secs_f64(num),
                _ => return None,
            };
            total += duration;
        }
    }
    
    if total == Duration::ZERO {
        None
    } else {
        Some(total)
    }
}

// ============================================================================
// Rate Limiting Helper
// ============================================================================

/// Token bucket for rate limiting
pub struct TokenBucket {
    tokens: AtomicU64,
    max_tokens: u64,
    refill_rate: u64,  // tokens per second
    last_refill: AtomicU64,  // timestamp in millis
}

impl TokenBucket {
    /// Create a new token bucket
    pub fn new(max_tokens: u64, refill_rate: u64) -> Self {
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            refill_rate,
            last_refill: AtomicU64::new(unix_timestamp_millis()),
        }
    }
    
    /// Try to acquire tokens
    pub fn try_acquire(&self, count: u64) -> bool {
        self.refill();
        
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < count {
                return false;
            }
            
            if self.tokens.compare_exchange(
                current,
                current - count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let now = unix_timestamp_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);
        
        if elapsed_ms == 0 {
            return;
        }
        
        let new_tokens = (elapsed_ms * self.refill_rate) / 1000;
        if new_tokens == 0 {
            return;
        }
        
        if self.last_refill.compare_exchange(
            last,
            now,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ).is_ok() {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_total = (current + new_tokens).min(self.max_tokens);
            self.tokens.store(new_total, Ordering::Relaxed);
        }
    }
    
    /// Get available tokens
    pub fn available(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Timing Scope Guard
// ============================================================================

/// Guard that measures time when dropped
pub struct TimingGuard<F: FnOnce(Duration)> {
    start: Instant,
    callback: Option<F>,
}

impl<F: FnOnce(Duration)> TimingGuard<F> {
    /// Create a new timing guard
    pub fn new(callback: F) -> Self {
        Self {
            start: Instant::now(),
            callback: Some(callback),
        }
    }
}

impl<F: FnOnce(Duration)> Drop for TimingGuard<F> {
    fn drop(&mut self) {
        if let Some(callback) = self.callback.take() {
            callback(self.start.elapsed());
        }
    }
}

/// Measure the execution time of a closure
#[inline]
pub fn measure<T, F: FnOnce() -> T>(f: F) -> (T, Duration) {
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

// ============================================================================
// Time Window Operations
// ============================================================================

/// Rolling time window for time-series analysis
pub struct TimeWindow {
    window_size: Duration,
    timestamps: Vec<u64>,  // Nanosecond timestamps
    max_entries: usize,
}

impl TimeWindow {
    /// Create a new time window
    pub fn new(window_size: Duration, max_entries: usize) -> Self {
        Self {
            window_size,
            timestamps: Vec::with_capacity(max_entries),
            max_entries,
        }
    }
    
    /// Add a timestamp to the window
    pub fn add(&mut self, timestamp: u64) {
        // Remove expired timestamps
        let cutoff = timestamp.saturating_sub(self.window_size.as_nanos() as u64);
        self.timestamps.retain(|&ts| ts >= cutoff);
        
        // Add new timestamp
        if self.timestamps.len() < self.max_entries {
            self.timestamps.push(timestamp);
        }
    }
    
    /// Add current timestamp
    pub fn add_now(&mut self) {
        self.add(unix_timestamp_nanos() as u64);
    }
    
    /// Get count of events in window
    pub fn count(&self) -> usize {
        self.timestamps.len()
    }
    
    /// Calculate events per second in window
    pub fn rate_per_second(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }
        
        let count = self.timestamps.len() as f64;
        let window_secs = self.window_size.as_secs_f64();
        
        count / window_secs
    }
    
    /// Clear the window
    pub fn clear(&mut self) {
        self.timestamps.clear();
    }
}

/// Time bucket allocator for time-series data
pub struct TimeBucket {
    bucket_size: Duration,
    start_time: u64,
}

impl TimeBucket {
    /// Create a new time bucket allocator
    pub fn new(bucket_size: Duration) -> Self {
        Self {
            bucket_size,
            start_time: unix_timestamp_nanos() as u64,
        }
    }
    
    /// Get bucket index for a timestamp
    pub fn bucket_index(&self, timestamp: u64) -> usize {
        let elapsed = timestamp.saturating_sub(self.start_time);
        (elapsed / self.bucket_size.as_nanos() as u64) as usize
    }
    
    /// Get bucket index for current time
    pub fn current_bucket(&self) -> usize {
        self.bucket_index(unix_timestamp_nanos() as u64)
    }
    
    /// Get timestamp for bucket start
    pub fn bucket_start(&self, index: usize) -> u64 {
        self.start_time + (index as u64 * self.bucket_size.as_nanos() as u64)
    }
}

// ============================================================================
// Time-based Sampling
// ============================================================================

/// Sampler for time-based rate limiting
pub struct TimeSampler {
    last_sample: AtomicU64,
    interval_nanos: u64,
}

impl TimeSampler {
    /// Create a new time sampler
    pub fn new(interval: Duration) -> Self {
        Self {
            last_sample: AtomicU64::new(0),
            interval_nanos: interval.as_nanos() as u64,
        }
    }
    
    /// Check if it's time for a new sample
    pub fn should_sample(&self) -> bool {
        let now = unix_timestamp_nanos() as u64;
        let last = self.last_sample.load(Ordering::Relaxed);
        
        if now.saturating_sub(last) >= self.interval_nanos {
            // Try to update last_sample
            self.last_sample.compare_exchange(
                last,
                now,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok()
        } else {
            false
        }
    }
    
    /// Reset the sampler
    pub fn reset(&self) {
        self.last_sample.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Expiry Checking
// ============================================================================

/// Check if a timestamp has expired
#[inline]
pub fn is_expired(timestamp: u64, ttl: Duration) -> bool {
    let now = unix_timestamp_nanos() as u64;
    let age = now.saturating_sub(timestamp);
    age >= ttl.as_nanos() as u64
}

/// Get remaining time until expiry
#[inline]
pub fn time_until_expiry(timestamp: u64, ttl: Duration) -> Option<Duration> {
    let now = unix_timestamp_nanos() as u64;
    let expiry = timestamp + ttl.as_nanos() as u64;
    
    if now >= expiry {
        None
    } else {
        Some(Duration::from_nanos(expiry - now))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_timestamp() {
        let secs = unix_timestamp_secs();
        assert!(secs > 1700000000); // After Nov 2023
        
        let millis = unix_timestamp_millis();
        assert!(millis > secs * 1000);
    }

    #[test]
    fn test_stopwatch() {
        let mut sw = Stopwatch::start_new();
        std::thread::sleep(Duration::from_millis(10));
        sw.stop();
        
        assert!(sw.elapsed() >= Duration::from_millis(10));
        assert!(!sw.is_running());
        
        sw.restart();
        assert!(sw.is_running());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_nanos(500)), "500ns");
        assert_eq!(format_duration(Duration::from_micros(500)), "500.00µs");
        assert_eq!(format_duration(Duration::from_millis(500)), "500.00ms");
        assert_eq!(format_duration(Duration::from_secs(30)), "30.00s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_compact() {
        assert_eq!(format_duration_compact(Duration::from_secs(3661)), "1h1m1s");
        assert_eq!(format_duration_compact(Duration::from_secs(120)), "2m");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("2s"), Some(Duration::from_secs(2)));
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10, 10);
        
        assert!(bucket.try_acquire(5));
        assert!(bucket.try_acquire(5));
        assert!(!bucket.try_acquire(1)); // No tokens left
    }

    #[test]
    fn test_measure() {
        let (result, duration) = measure(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_rfc3339_formatting() {
        let timestamp = now_rfc3339();
        // Should contain basic RFC3339 structure
        assert!(timestamp.contains('T'));
        assert!(timestamp.ends_with('Z'));
    }

    #[test]
    fn test_time_window() {
        let mut window = TimeWindow::new(Duration::from_secs(1), 100);
        
        let base_time = unix_timestamp_nanos() as u64;
        
        // Add some timestamps
        window.add(base_time);
        window.add(base_time + 100_000_000); // +100ms
        window.add(base_time + 200_000_000); // +200ms
        
        assert_eq!(window.count(), 3);
        
        // Add timestamp outside window
        window.add(base_time + 2_000_000_000); // +2s (outside 1s window)
        
        // Should have purged old entries
        assert_eq!(window.count(), 1);
    }

    #[test]
    fn test_time_bucket() {
        let bucket = TimeBucket::new(Duration::from_secs(60));
        
        let now = unix_timestamp_nanos() as u64;
        let idx = bucket.bucket_index(now);
        
        // Timestamp 60s later should be in next bucket
        let future = now + 60_000_000_000;
        assert_eq!(bucket.bucket_index(future), idx + 1);
    }

    #[test]
    fn test_time_sampler() {
        let sampler = TimeSampler::new(Duration::from_millis(100));
        
        // First sample should succeed
        assert!(sampler.should_sample());
        
        // Immediate next sample should fail
        assert!(!sampler.should_sample());
    }

    #[test]
    fn test_expiry_checking() {
        let now = unix_timestamp_nanos() as u64;
        let old_timestamp = now - 2_000_000_000; // 2 seconds ago
        
        assert!(is_expired(old_timestamp, Duration::from_secs(1)));
        assert!(!is_expired(now, Duration::from_secs(1)));
        
        let remaining = time_until_expiry(now, Duration::from_secs(2));
        assert!(remaining.is_some());
    }

    #[test]
    fn test_time_window_rate() {
        let mut window = TimeWindow::new(Duration::from_secs(1), 1000);
        
        let base_time = unix_timestamp_nanos() as u64;
        
        // Add 10 events
        for i in 0..10 {
            window.add(base_time + (i * 50_000_000)); // Every 50ms
        }
        
        // Rate should be ~10 events per second
        let rate = window.rate_per_second();
        assert!(rate >= 9.0 && rate <= 11.0);
    }
}
