//! Time and timestamp utility functions
//!
//! Provides time and timestamp utilities for packet timestamping, connection timeout
//! tracking, log rotation, and metrics collection. Handles conversion between different
//! time representations with consistent UTC handling and high-precision timing.

use crate::error::{Result, SafeOpsError};
use chrono::{DateTime, Local, TimeZone, Utc};
use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Timestamp Functions
// ============================================================================

/// Returns current Unix timestamp in seconds since epoch
#[inline]
pub fn now_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Returns current Unix timestamp in milliseconds
#[inline]
pub fn now_unix_timestamp_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Returns current Unix timestamp in microseconds
#[inline]
pub fn now_unix_timestamp_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

// ============================================================================
// Time Conversion Functions
// ============================================================================

/// Converts Unix timestamp to SystemTime
pub fn unix_to_system_time(timestamp: i64) -> SystemTime {
    if timestamp >= 0 {
        UNIX_EPOCH + Duration::from_secs(timestamp as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-timestamp) as u64)
    }
}

/// Converts SystemTime to Unix timestamp
pub fn system_time_to_unix(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64), // Before epoch
    }
}

/// Converts Duration to seconds with fractional part
pub fn duration_to_seconds(duration: Duration) -> f64 {
    duration.as_secs() as f64 + duration.subsec_nanos() as f64 / 1_000_000_000.0
}

// ============================================================================
// Time Formatting Functions
// ============================================================================

/// Formats Unix timestamp as string (UTC)
///
/// Default format: "YYYY-MM-DD HH:MM:SS UTC"
pub fn format_timestamp(timestamp: i64, format: &str) -> String {
    match DateTime::from_timestamp(timestamp, 0) {
        Some(dt) => dt.format(format).to_string(),
        None => format!("Invalid timestamp: {}", timestamp),
    }
}

/// Formats Unix timestamp with default format
pub fn format_timestamp_default(timestamp: i64) -> String {
    format_timestamp(timestamp, "%Y-%m-%d %H:%M:%S UTC")
}

/// Formats duration as human-readable string
///
/// Examples: "5m 30s", "2h 15m 30s", "3d 4h"
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    
    if total_secs == 0 {
        return format!("{}ms", duration.as_millis());
    }

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut parts = Vec::new();
    
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{}s", seconds));
    }

    parts.join(" ")
}

/// Formats relative time ("5 minutes ago", "2 hours ago")
pub fn format_relative(timestamp: i64) -> String {
    let now = now_unix_timestamp();
    let diff = now - timestamp;

    if diff < 0 {
        return String::from("in the future");
    }

    match diff {
        0..=59 => format!("{} seconds ago", diff),
        60..=3599 => {
            let minutes = diff / 60;
            if minutes == 1 {
                String::from("1 minute ago")
            } else {
                format!("{} minutes ago", minutes)
            }
        }
        3600..=86399 => {
            let hours = diff / 3600;
            if hours == 1 {
                String::from("1 hour ago")
            } else {
                format!("{} hours ago", hours)
            }
        }
        86400..=2591999 => {
            let days = diff / 86400;
            if days == 1 {
                String::from("1 day ago")
            } else {
                format!("{} days ago", days)
            }
        }
        _ => {
            let months = diff / 2592000; // 30 days
            if months == 1 {
                String::from("1 month ago")
            } else {
                format!("{} months ago", months)
            }
        }
    }
}

// ============================================================================
// Timeout and TTL Functions
// ============================================================================

/// Checks if timestamp + TTL is in the past (expired)
#[inline]
pub fn is_expired(timestamp: i64, ttl_seconds: u64) -> bool {
    let expiry_time = timestamp + ttl_seconds as i64;
    now_unix_timestamp() >= expiry_time
}

/// Calculates remaining time until expiration
///
/// Returns None if already expired
pub fn time_until_expiry(timestamp: i64, ttl_seconds: u64) -> Option<Duration> {
    let expiry_time = timestamp + ttl_seconds as i64;
    let now = now_unix_timestamp();
    
    if now >= expiry_time {
        None
    } else {
        Some(Duration::from_secs((expiry_time - now) as u64))
    }
}

/// Async sleep until specified Unix timestamp
pub async fn sleep_until(timestamp: i64) {
    let now = now_unix_timestamp();
    if timestamp > now {
        let duration = Duration::from_secs((timestamp - now) as u64);
        tokio::time::sleep(duration).await;
    }
}

// ============================================================================
// Performance Timing
// ============================================================================

/// High-precision timer using monotonic clock
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Creates new timer starting now
    pub fn new() -> Self {
        Timer {
            start: Instant::now(),
        }
    }

    /// Returns elapsed time since creation
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Returns elapsed milliseconds
    pub fn elapsed_millis(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Returns elapsed microseconds
    pub fn elapsed_micros(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    /// Resets timer to current time
    pub fn reset(&mut self) {
        self.start = Instant::now();
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

/// Measures execution time of a function
///
/// Returns (result, elapsed_time)
pub fn measure<F, T>(f: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    (result, elapsed)
}

// ============================================================================
// Timezone Handling
// ============================================================================

/// Returns current time in UTC timezone
pub fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

/// Returns current time in system local timezone
pub fn local_now() -> DateTime<Local> {
    Local::now()
}

/// Converts timestamp between timezones (simplified version)
///
/// Note: Full timezone conversion requires chrono-tz crate
pub fn convert_timezone(timestamp: i64, _from_tz: &str, _to_tz: &str) -> Result<i64> {
    // Basic implementation - full timezone support would require chrono-tz
    // For now, assumes all conversions are identity (already UTC)
    Ok(timestamp)
}

// ============================================================================
// Deprecated Aliases (for backward compatibility)
// ============================================================================

/// Alias for now_unix_timestamp (deprecated, use now_unix_timestamp)
#[deprecated(note = "Use now_unix_timestamp instead")]
pub fn current_timestamp() -> u64 {
    now_unix_timestamp() as u64
}

/// Alias for now_unix_timestamp_millis (deprecated)
#[deprecated(note = "Use now_unix_timestamp_millis instead")]
pub fn current_timestamp_millis() -> u64 {
    now_unix_timestamp_millis() as u64
}

/// Alias for now_unix_timestamp_micros (deprecated)
#[deprecated(note = "Use now_unix_timestamp_micros instead")]
pub fn current_timestamp_micros() -> u64 {
    now_unix_timestamp_micros() as u64
}

/// Converts Unix timestamp to DateTime<Utc> (deprecated)
#[deprecated(note = "Use chrono::DateTime::from_timestamp directly")]
pub fn timestamp_to_datetime(timestamp: u64) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(timestamp as i64, 0)
        .ok_or_else(|| SafeOpsError::parse("Invalid timestamp"))
}

/// Parses duration from string (e.g., "5s", "100ms", "1h")
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SafeOpsError::parse("Empty duration string"));
    }

    // Try milliseconds first
    if let Some(value_str) = s.strip_suffix("ms") {
        let value: u64 = value_str.trim().parse()
            .map_err(|_| SafeOpsError::parse(format!("Invalid duration value: {}", value_str)))?;
        return Ok(Duration::from_millis(value));
    }

    // Then single-character suffixes
    if s.len() < 2 {
        return Err(SafeOpsError::parse("Duration too short"));
    }

    let (value_str, unit) = s.split_at(s.len() - 1);
    let value: u64 = value_str.trim().parse()
        .map_err(|_| SafeOpsError::parse(format!("Invalid duration value: {}", value_str)))?;

    match unit {
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 3600)),
        "d" => Ok(Duration::from_secs(value * 86400)),
        _ => Err(SafeOpsError::parse(format!("Invalid duration unit: {}", unit))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_timestamp() {
        let ts = now_unix_timestamp();
        assert!(ts > 1700000000); // After Nov 2023
    }

    #[test]
    fn test_timestamp_millis() {
        let ts_ms = now_unix_timestamp_millis();
        let ts_s = now_unix_timestamp();
        assert!(ts_ms / 1000 >= ts_s);
    }

    #[test]
    fn test_time_conversion() {
        let timestamp = 1234567890i64;
        let sys_time = unix_to_system_time(timestamp);
        let converted = system_time_to_unix(sys_time);
        assert_eq!(converted, timestamp);
    }

    #[test]
    fn test_duration_to_seconds() {
        let duration = Duration::from_millis(1500);
        let seconds = duration_to_seconds(duration);
        assert!((seconds - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_format_timestamp() {
        let timestamp = 1234567890i64;
        let formatted = format_timestamp_default(timestamp);
        assert!(formatted.contains("2009"));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_is_expired() {
        let past_timestamp = now_unix_timestamp() - 100;
        assert!(is_expired(past_timestamp, 50));
        assert!(!is_expired(past_timestamp, 200));
    }

    #[test]
    fn test_time_until_expiry() {
        let future_timestamp = now_unix_timestamp() + 100;
        let remaining = time_until_expiry(future_timestamp, 200);
        assert!(remaining.is_some());

        let past_timestamp = now_unix_timestamp() - 100;
        assert!(time_until_expiry(past_timestamp, 50).is_none());
    }

    #[test]
    fn test_timer() {
        let timer = Timer::new();
        std::thread::sleep(Duration::from_millis(10));
        assert!(timer.elapsed_millis() >= 10);
    }

    #[test]
    fn test_measure() {
        let (result, elapsed) = measure(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });
        assert_eq!(result, 42);
        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn test_format_relative() {
        let now = now_unix_timestamp();
        assert_eq!(format_relative(now - 30), "30 seconds ago");
        assert_eq!(format_relative(now - 90), "1 minute ago");
        assert_eq!(format_relative(now - 3700), "1 hour ago");
    }
}
