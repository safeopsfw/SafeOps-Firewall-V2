//! IP address parsing, validation, and CIDR notation handling utilities
//!
//! Provides RFC-compliant IPv4 and IPv6 address validation, CIDR subnet parsing,
//! IP range checking for firewall rule matching, and conversion between string
//! and binary IP representations.

use crate::error::{Result, SafeOpsError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Wrapper around std::net::IpAddr with additional utilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IPAddress(pub IpAddr);

impl IPAddress {
    /// Creates a new IPAddress from std::net::IpAddr
    pub fn new(addr: IpAddr) -> Self {
        IPAddress(addr)
    }

    /// Returns true if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self.0, IpAddr::V4(_))
    }

    /// Returns true if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self.0, IpAddr::V6(_))
    }

    /// Detects loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
    pub fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    /// Detects RFC 1918 private ranges
    /// - 10.0.0.0/8
    /// - 172.16.0.0/12
    /// - 192.168.0.0/16
    /// - fd00::/8 for IPv6
    pub fn is_private(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00 // fc00::/7
            }
        }
    }

    /// Detects link-local addresses
    /// - 169.254.0.0/16 for IPv4
    /// - fe80::/10 for IPv6
    pub fn is_link_local(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 169 && octets[1] == 254
            }
            IpAddr::V6(ipv6) => (ipv6.segments()[0] & 0xffc0) == 0xfe80,
        }
    }

    /// Detects multicast addresses
    pub fn is_multicast(&self) -> bool {
        self.0.is_multicast()
    }

    /// Returns true for globally routable addresses
    pub fn is_global(&self) -> bool {
        !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_multicast()
    }

    /// Converts to byte array representation
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.0 {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        }
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IpAddr> for IPAddress {
    fn from(addr: IpAddr) -> Self {
        IPAddress(addr)
    }
}

impl From<Ipv4Addr> for IPAddress {
    fn from(addr: Ipv4Addr) -> Self {
        IPAddress(IpAddr::V4(addr))
    }
}

impl From<Ipv6Addr> for IPAddress {
    fn from(addr: Ipv6Addr) -> Self {
        IPAddress(IpAddr::V6(addr))
    }
}

// ============================================================================
// IP Parsing Functions
// ============================================================================

/// Parses string into IPAddress type
///
/// Handles both IPv4 dotted decimal format (192.168.1.1) and
/// IPv6 colon format (2001:db8::1)
pub fn parse_ip(input: &str) -> Result<IPAddress> {
    input
        .parse::<IpAddr>()
        .map(IPAddress)
        .map_err(|_| SafeOpsError::parse(format!("Invalid IP address: {}", input)))
}

/// Parses IP or returns default if parsing fails
pub fn parse_ip_or_default(input: &str, default: IPAddress) -> IPAddress {
    parse_ip(input).unwrap_or(default)
}

/// Returns true if string is valid IP address (fast validation without allocation)
pub fn validate_ip(input: &str) -> bool {
    input.parse::<IpAddr>().is_ok()
}

// ============================================================================
// CIDR Notation Functions
// ============================================================================

/// Parses CIDR notation (192.168.1.0/24)
///
/// Returns IP address and prefix length.
/// Validates prefix length range (0-32 for IPv4, 0-128 for IPv6)
pub fn parse_cidr(input: &str) -> Result<(IPAddress, u8)> {
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 2 {
        return Err(SafeOpsError::parse(format!(
            "Invalid CIDR notation: {}",
            input
        )));
    }

    let ip = parse_ip(parts[0])?;
    let prefix_len = parts[1]
        .parse::<u8>()
        .map_err(|_| SafeOpsError::parse(format!("Invalid prefix length: {}", parts[1])))?;

    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_prefix {
        return Err(SafeOpsError::parse(format!(
            "Prefix length {} exceeds maximum {} for {}",
            prefix_len,
            max_prefix,
            if ip.is_ipv4() { "IPv4" } else { "IPv6" }
        )));
    }

    Ok((ip, prefix_len))
}

/// Checks if address is within CIDR subnet
pub fn cidr_contains(network: IPAddress, prefix_len: u8, addr: IPAddress) -> bool {
    // Ensure both are same IP version
    if network.is_ipv4() != addr.is_ipv4() {
        return false;
    }

    match (network.0, addr.0) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let net_bits = u32::from_be_bytes(net.octets());
            let ip_bits = u32::from_be_bytes(ip.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (net_bits & mask) == (ip_bits & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let net_bits = u128::from_be_bytes(net.octets());
            let ip_bits = u128::from_be_bytes(ip.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (net_bits & mask) == (ip_bits & mask)
        }
        _ => false,
    }
}

/// Converts CIDR to first and last address in range
pub fn cidr_to_range(network: IPAddress, prefix_len: u8) -> Result<(IPAddress, IPAddress)> {
    let first = network_address(network, prefix_len)?;
    let last = if network.is_ipv4() {
        broadcast_address(network, prefix_len)?
    } else {
        // IPv6: calculate last address by setting all host bits to 1
        match network.0 {
            IpAddr::V6(net) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let last_bits = net_bits | !mask;
                IPAddress(IpAddr::V6(Ipv6Addr::from(last_bits)))
            }
            _ => unreachable!(),
        }
    };
    Ok((first, last))
}

/// Calculates network address from IP and prefix (zeroes host bits)
pub fn network_address(ip: IPAddress, prefix_len: u8) -> Result<IPAddress> {
    match ip.0 {
        IpAddr::V4(ipv4) => {
            let ip_bits = u32::from_be_bytes(ipv4.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let network_bits = ip_bits & mask;
            Ok(IPAddress(IpAddr::V4(Ipv4Addr::from(network_bits))))
        }
        IpAddr::V6(ipv6) => {
            let ip_bits = u128::from_be_bytes(ipv6.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            let network_bits = ip_bits & mask;
            Ok(IPAddress(IpAddr::V6(Ipv6Addr::from(network_bits))))
        }
    }
}

/// Calculates broadcast address (IPv4 only - sets all host bits to 1)
pub fn broadcast_address(ip: IPAddress, prefix_len: u8) -> Result<IPAddress> {
    match ip.0 {
        IpAddr::V4(ipv4) => {
            let ip_bits = u32::from_be_bytes(ipv4.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let broadcast_bits = ip_bits | !mask;
            Ok(IPAddress(IpAddr::V4(Ipv4Addr::from(broadcast_bits))))
        }
        IpAddr::V6(_) => Err(SafeOpsError::invalid_input(
            "IPv6 does not have broadcast addresses",
        )),
    }
}

// ============================================================================
// IP Range Functions
// ============================================================================

/// Checks if address is between start and end (inclusive)
pub fn ip_in_range(addr: IPAddress, start: IPAddress, end: IPAddress) -> bool {
    // Must be same IP version
    if addr.is_ipv4() != start.is_ipv4() || addr.is_ipv4() != end.is_ipv4() {
        return false;
    }

    match (addr.0, start.0, end.0) {
        (IpAddr::V4(a), IpAddr::V4(s), IpAddr::V4(e)) => {
            let a_bits = u32::from_be_bytes(a.octets());
            let s_bits = u32::from_be_bytes(s.octets());
            let e_bits = u32::from_be_bytes(e.octets());
            a_bits >= s_bits && a_bits <= e_bits
        }
        (IpAddr::V6(a), IpAddr::V6(s), IpAddr::V6(e)) => {
            let a_bits = u128::from_be_bytes(a.octets());
            let s_bits = u128::from_be_bytes(s.octets());
            let e_bits = u128::from_be_bytes(e.octets());
            a_bits >= s_bits && a_bits <= e_bits
        }
        _ => false,
    }
}

/// Returns next IP address in sequence
pub fn next_ip(addr: IPAddress) -> Option<IPAddress> {
    match addr.0 {
        IpAddr::V4(ipv4) => {
            let bits = u32::from_be_bytes(ipv4.octets());
            bits.checked_add(1)
                .map(|b| IPAddress(IpAddr::V4(Ipv4Addr::from(b))))
        }
        IpAddr::V6(ipv6) => {
            let bits = u128::from_be_bytes(ipv6.octets());
            bits.checked_add(1)
                .map(|b| IPAddress(IpAddr::V6(Ipv6Addr::from(b))))
        }
    }
}

/// Returns previous IP address
pub fn prev_ip(addr: IPAddress) -> Option<IPAddress> {
    match addr.0 {
        IpAddr::V4(ipv4) => {
            let bits = u32::from_be_bytes(ipv4.octets());
            bits.checked_sub(1)
                .map(|b| IPAddress(IpAddr::V4(Ipv4Addr::from(b))))
        }
        IpAddr::V6(ipv6) => {
            let bits = u128::from_be_bytes(ipv6.octets());
            bits.checked_sub(1)
                .map(|b| IPAddress(IpAddr::V6(Ipv6Addr::from(b))))
        }
    }
}

// ============================================================================
// Subnet Mask Functions
// ============================================================================

/// Converts prefix length to subnet mask
pub fn prefix_to_mask(prefix_len: u8, is_ipv6: bool) -> Result<IPAddress> {
    if is_ipv6 {
        if prefix_len > 128 {
            return Err(SafeOpsError::invalid_input("IPv6 prefix length max is 128"));
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        Ok(IPAddress(IpAddr::V6(Ipv6Addr::from(mask))))
    } else {
        if prefix_len > 32 {
            return Err(SafeOpsError::invalid_input("IPv4 prefix length max is 32"));
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Ok(IPAddress(IpAddr::V4(Ipv4Addr::from(mask))))
    }
}

/// Converts subnet mask to prefix length (counts leading 1 bits)
/// Validates that the mask has contiguous 1 bits (e.g., rejects 255.0.255.0)
pub fn mask_to_prefix(mask: IPAddress) -> Result<u8> {
    match mask.0 {
        IpAddr::V4(ipv4) => {
            let bits = u32::from_be_bytes(ipv4.octets());
            let prefix = bits.leading_ones() as u8;
            
            // Validate mask is contiguous: after leading ones, all bits must be zero
            let expected_mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            if bits != expected_mask {
                return Err(SafeOpsError::invalid_input(format!(
                    "Invalid subnet mask: {} (not contiguous)",
                    ipv4
                )));
            }
            
            Ok(prefix)
        }
        IpAddr::V6(ipv6) => {
            let bits = u128::from_be_bytes(ipv6.octets());
            let prefix = bits.leading_ones() as u8;
            
            // Validate mask is contiguous
            let expected_mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            if bits != expected_mask {
                return Err(SafeOpsError::invalid_input(format!(
                    "Invalid subnet mask: {} (not contiguous)",
                    ipv6
                )));
            }
            
            Ok(prefix)
        }
    }
}

// ============================================================================
// Conversion Functions
// ============================================================================

/// Converts byte slice to IP address
/// Handles 4 bytes (IPv4) or 16 bytes (IPv6)
pub fn bytes_to_ip(bytes: &[u8]) -> Result<IPAddress> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes
                .try_into()
                .map_err(|_| SafeOpsError::parse("Invalid IPv4 bytes"))?;
            Ok(IPAddress(IpAddr::V4(Ipv4Addr::from(octets))))
        }
        16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| SafeOpsError::parse("Invalid IPv6 bytes"))?;
            Ok(IPAddress(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        _ => Err(SafeOpsError::parse(format!(
            "Invalid IP byte length: {} (expected 4 or 16)",
            bytes.len()
        ))),
    }
}

/// Converts IP to string representation
pub fn ip_to_string(ip: IPAddress) -> String {
    ip.0.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip() {
        let ip = parse_ip("192.168.1.1").unwrap();
        assert!(ip.is_ipv4());

        let ip = parse_ip("2001:db8::1").unwrap();
        assert!(ip.is_ipv6());

        assert!(parse_ip("invalid").is_err());
    }

    #[test]
    fn test_is_private() {
        assert!(parse_ip("10.0.0.1").unwrap().is_private());
        assert!(parse_ip("172.16.0.1").unwrap().is_private());
        assert!(parse_ip("192.168.1.1").unwrap().is_private());
        assert!(!parse_ip("8.8.8.8").unwrap().is_private());
    }

    #[test]
    fn test_parse_cidr() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(prefix, 24);
        assert!(ip.is_ipv4());

        assert!(parse_cidr("invalid/24").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_cidr_contains() {
        let (network, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        let addr = parse_ip("192.168.1.100").unwrap();
        assert!(cidr_contains(network, prefix, addr));

        let addr = parse_ip("192.168.2.1").unwrap();
        assert!(!cidr_contains(network, prefix, addr));
    }

    #[test]
    fn test_network_address() {
        let ip = parse_ip("192.168.1.100").unwrap();
        let network = network_address(ip, 24).unwrap();
        assert_eq!(network.to_string(), "192.168.1.0");
    }

    #[test]
    fn test_broadcast_address() {
        let ip = parse_ip("192.168.1.0").unwrap();
        let broadcast = broadcast_address(ip, 24).unwrap();
        assert_eq!(broadcast.to_string(), "192.168.1.255");
    }

    #[test]
    fn test_ip_range() {
        let addr = parse_ip("192.168.1.100").unwrap();
        let start = parse_ip("192.168.1.1").unwrap();
        let end = parse_ip("192.168.1.200").unwrap();
        assert!(ip_in_range(addr, start, end));

        let addr = parse_ip("192.168.2.1").unwrap();
        assert!(!ip_in_range(addr, start, end));
    }

    #[test]
    fn test_next_prev_ip() {
        let ip = parse_ip("192.168.1.1").unwrap();
        let next = next_ip(ip).unwrap();
        assert_eq!(next.to_string(), "192.168.1.2");

        let prev = prev_ip(next).unwrap();
        assert_eq!(prev.to_string(), "192.168.1.1");
    }
}
