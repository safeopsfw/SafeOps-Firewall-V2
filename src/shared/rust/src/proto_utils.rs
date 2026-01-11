//! Protocol Buffer utility functions
//!
//! Helper functions for working with Protocol Buffer generated types, including
//! conversion between proto messages and internal Rust types, validation of proto
//! message fields, and serialization/deserialization utilities.

use crate::error::{Result, SafeOpsError};
use crate::ip_utils::IPAddress;
use crate::time_utils;
use prost::Message;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ============================================================================
// Timestamp Conversion (Common Proto Pattern)
// ============================================================================

/// Converts Unix timestamp to proto Timestamp tuple (seconds, nanos)
pub fn timestamp_to_proto(timestamp: i64) -> (i64, i32) {
    (timestamp, 0)
}

/// Converts proto Timestamp to Unix timestamp
pub fn proto_to_timestamp(seconds: i64, nanos: i32) -> i64 {
    seconds
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validates proto string field
pub fn validate_proto_string(s: &str, field_name: &str, max_len: usize) -> Result<()> {
    if s.is_empty() {
        return Err(SafeOpsError::invalid_input(format!(
            "{} cannot be empty",
            field_name
        )));
    }
    if s.len() > max_len {
        return Err(SafeOpsError::invalid_input(format!(
            "{} exceeds maximum length of {} (got {})",
            field_name, max_len, s.len()
        )));
    }
    Ok(())
}

/// Validates port number is in valid range
pub fn validate_proto_port(port: u32) -> Result<()> {
    if port > 65535 {
        return Err(SafeOpsError::invalid_input(format!(
            "Port {} exceeds maximum of 65535",
            port
        )));
    }
    Ok(())
}

/// Validates port range
pub fn validate_proto_port_range(start: u32, end: u32) -> Result<()> {
    validate_proto_port(start)?;
    validate_proto_port(end)?;
    
    if start > end {
        return Err(SafeOpsError::invalid_input(format!(
            "Port range invalid: start {} > end {}",
            start, end
        )));
    }
    Ok(())
}

/// Validates confidence score (0.0 to 1.0)
pub fn validate_confidence(confidence: f32) -> Result<()> {
    if !(0.0..=1.0).contains(&confidence) {
        return Err(SafeOpsError::invalid_input(format!(
            "Confidence {} must be between 0.0 and 1.0",
            confidence
        )));
    }
    Ok(())
}

/// Validates reputation score (-100 to +100)
pub fn validate_reputation_score(score: i32) -> Result<()> {
    if !(-100..=100).contains(&score) {
        return Err(SafeOpsError::invalid_input(format!(
            "Reputation score {} must be between -100 and +100",
            score
        )));
    }
    Ok(())
}

/// Validates timestamp is positive
pub fn validate_timestamp(timestamp: i64, field_name: &str) -> Result<()> {
    if timestamp < 0 {
        return Err(SafeOpsError::invalid_input(format!(
            "{} timestamp cannot be negative: {}",
            field_name, timestamp
        )));
    }
    Ok(())
}

/// Creates error for missing required field
pub fn missing_field_error(field_name: &str) -> SafeOpsError {
    SafeOpsError::invalid_input(format!("Required field '{}' is missing", field_name))
}

// ============================================================================
// IP Address Conversion
// ============================================================================

/// Converts internal IPAddress to proto-compatible tuple
///
/// Returns (is_v6: bool, bytes: Vec<u8>)
pub fn ip_to_proto_bytes(ip: &IPAddress) -> (bool, Vec<u8>) {
    match ip.0 {
        IpAddr::V4(ipv4) => (false, ipv4.octets().to_vec()),
        IpAddr::V6(ipv6) => (true, ipv6.octets().to_vec()),
    }
}

/// Converts proto IP bytes to IPAddress
pub fn ip_from_proto_bytes(is_v6: bool, bytes: &[u8]) -> Result<IPAddress> {
    if is_v6 {
        if bytes.len() != 16 {
            return Err(SafeOpsError::parse(format!(
                "Invalid IPv6 address length: {} (expected 16)",
                bytes.len()
            )));
        }
        let octets: [u8; 16] = bytes.try_into()
            .map_err(|_| SafeOpsError::parse("Invalid IPv6 bytes"))?;
        Ok(IPAddress::from(Ipv6Addr::from(octets)))
    } else {
        if bytes.len() != 4 {
            return Err(SafeOpsError::parse(format!(
                "Invalid IPv4 address length: {} (expected 4)",
                bytes.len()
            )));
        }
        let octets: [u8; 4] = bytes.try_into()
            .map_err(|_| SafeOpsError::parse("Invalid IPv4 bytes"))?;
        Ok(IPAddress::from(Ipv4Addr::from(octets)))
    }
}

// ============================================================================
// Protocol Conversion
// ============================================================================

/// Protocol numbers for common protocols
/// TCP protocol number (Transmission Control Protocol)
pub const PROTOCOL_TCP: u8 = 6;
/// UDP protocol number (User Datagram Protocol)
pub const PROTOCOL_UDP: u8 = 17;
/// ICMP protocol number (Internet Control Message Protocol for IPv4)
pub const PROTOCOL_ICMP: u8 = 1;
/// ICMPv6 protocol number (Internet Control Message Protocol for IPv6)
pub const PROTOCOL_ICMPV6: u8 = 58;

/// Converts protocol number to name string
pub fn protocol_to_name(protocol: u8) -> &'static str {
    match protocol {
        PROTOCOL_TCP => "TCP",
        PROTOCOL_UDP => "UDP",
        PROTOCOL_ICMP => "ICMP",
        PROTOCOL_ICMPV6 => "ICMPv6",
        _ => "Unknown",
    }
}

/// Converts protocol name to number
pub fn protocol_from_name(name: &str) -> Result<u8> {
    match name.to_uppercase().as_str() {
        "TCP" => Ok(PROTOCOL_TCP),
        "UDP" => Ok(PROTOCOL_UDP),
        "ICMP" => Ok(PROTOCOL_ICMP),
        "ICMPV6" => Ok(PROTOCOL_ICMPV6),
        _ => Err(SafeOpsError::parse(format!("Unknown protocol: {}", name))),
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Serializes any proto message to bytes
pub fn serialize_proto<M: Message>(message: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(message.encoded_len());
    message.encode(&mut buf).expect("Failed to encode proto message");
    buf
}

/// Deserializes bytes to proto message
pub fn deserialize_proto<M: Message + Default>(bytes: &[u8]) -> Result<M> {
    M::decode(bytes).map_err(|e| SafeOpsError::parse(format!("Proto decode error: {}", e)))
}

/// Converts proto message to JSON string (for debugging)
pub fn proto_to_json<M: serde::Serialize>(message: &M) -> Result<String> {
    serde_json::to_string_pretty(message)
        .map_err(|e| SafeOpsError::internal(format!("JSON serialization error: {}", e)))
}

/// Parses JSON to proto message (for config files)
pub fn proto_from_json<M>(json: &str) -> Result<M>
where
    M: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_str(json)
        .map_err(|e| SafeOpsError::parse(format!("JSON parsing error: {}", e)))
}

// ============================================================================
// Error Handling
// ============================================================================

/// Converts prost decode error to SafeOpsError
pub fn proto_error_to_safeops(error: prost::DecodeError) -> SafeOpsError {
    SafeOpsError::parse(format!("Protocol buffer decode error: {}", error))
}

// ============================================================================
// Common Proto Field Helpers
// ============================================================================

/// Extracts required field from Option
pub fn require_field<T>(field: Option<T>, field_name: &str) -> Result<T> {
    field.ok_or_else(|| missing_field_error(field_name))
}

/// Validates and extracts required string field
pub fn require_string(field: &str, field_name: &str, max_len: usize) -> Result<String> {
    validate_proto_string(field, field_name, max_len)?;
    Ok(field.to_string())
}

/// Validates vec is not empty
pub fn require_non_empty<T>(vec: &[T], field_name: &str) -> Result<()> {
    if vec.is_empty() {
        return Err(SafeOpsError::invalid_input(format!(
            "{} cannot be empty",
            field_name
        )));
    }
    Ok(())
}

// ============================================================================
// Duration Conversion
// ============================================================================

/// Converts std::time::Duration to proto seconds
pub fn duration_to_proto_seconds(duration: std::time::Duration) -> i64 {
    duration.as_secs() as i64
}

/// Converts proto seconds to std::time::Duration
pub fn proto_seconds_to_duration(seconds: i64) -> Result<std::time::Duration> {
    if seconds < 0 {
        return Err(SafeOpsError::invalid_input(format!(
            "Duration cannot be negative: {}",
            seconds
        )));
    }
    Ok(std::time::Duration::from_secs(seconds as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_conversion() {
        let ts = 1234567890i64;
        let (secs, nanos) = timestamp_to_proto(ts);
        let converted = proto_to_timestamp(secs, nanos);
        assert_eq!(converted, ts);
    }

    #[test]
    fn test_validate_proto_string() {
        assert!(validate_proto_string("valid", "test", 100).is_ok());
        assert!(validate_proto_string("", "test", 100).is_err());
        assert!(validate_proto_string("too long string", "test", 5).is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_proto_port(80).is_ok());
        assert!(validate_proto_port(65535).is_ok());
        assert!(validate_proto_port(65536).is_err());
    }

    #[test]
    fn test_validate_confidence() {
        assert!(validate_confidence(0.0).is_ok());
        assert!(validate_confidence(0.5).is_ok());
        assert!(validate_confidence(1.0).is_ok());
        assert!(validate_confidence(-0.1).is_err());
        assert!(validate_confidence(1.1).is_err());
    }

    #[test]
    fn test_validate_reputation_score() {
        assert!(validate_reputation_score(0).is_ok());
        assert!(validate_reputation_score(100).is_ok());
        assert!(validate_reputation_score(-100).is_ok());
        assert!(validate_reputation_score(101).is_err());
        assert!(validate_reputation_score(-101).is_err());
    }

    #[test]
    fn test_ip_conversion() {
        let ipv4 = IPAddress::from(Ipv4Addr::new(192, 168, 1, 1));
        let (is_v6, bytes) = ip_to_proto_bytes(&ipv4);
        assert!(!is_v6);
        assert_eq!(bytes, vec![192, 168, 1, 1]);
        
        let converted = ip_from_proto_bytes(is_v6, &bytes).unwrap();
        assert_eq!(converted, ipv4);
    }

    #[test]
    fn test_protocol_conversion() {
        assert_eq!(protocol_to_name(PROTOCOL_TCP), "TCP");
        assert_eq!(protocol_to_name(PROTOCOL_UDP), "UDP");
        assert_eq!(protocol_from_name("TCP").unwrap(), PROTOCOL_TCP);
        assert_eq!(protocol_from_name("udp").unwrap(), PROTOCOL_UDP);
    }

    #[test]
    fn test_duration_conversion() {
        let duration = std::time::Duration::from_secs(300);
        let seconds = duration_to_proto_seconds(duration);
        assert_eq!(seconds, 300);
        
        let converted = proto_seconds_to_duration(seconds).unwrap();
        assert_eq!(converted, duration);
    }

    #[test]
    fn test_missing_field_error() {
        let err = missing_field_error("test_field");
        assert!(format!("{}", err).contains("test_field"));
    }
}
