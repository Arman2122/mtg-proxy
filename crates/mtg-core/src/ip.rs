//! Normalized IP accounting units (`IpUnit`) and personal-address classification.
//!
//! Replaces Go's heap-allocated `type addressKey string` with a 16-byte `Copy`
//! value type:
//! - IPv4 (including unmapped IPv4-mapped IPv6 `::ffff:a.b.c.d`) -> `V4(u32)`
//! - IPv6 -> `/64` network prefix `V6Prefix(u64)`

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Error parsing an [`IpUnit`] from text.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IpUnitParseError {
    #[error("invalid IP address or IPv6 /64 prefix: {0:?}")]
    Invalid(String),
}

/// Accounting unit for per-address limits (`ip-limit`, `client-conns`,
/// `client-speed`, `client-fair`), bans, kicks, and handshake hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpUnit {
    /// Unmapped IPv4 address in host byte order (`u32::from(ipv4)`).
    V4(u32),
    /// Top 64 bits of an IPv6 address (representing its `/64` subnet).
    V6Prefix(u64),
}

/// Unmap an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to [`IpAddr::V4`].
#[inline]
pub const fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Reports whether `ip` stands for a single client place (routable unicast),
/// matching Go's `hintKey` / `client_table` classification:
///
/// Loopback, RFC 1918 private / IPv6 ULA (`fc00::/7`), link-local unicast,
/// unspecified, and multicast return `false`. Classification is performed on
/// the whole unmapped address *before* masking IPv6 to `/64`.
#[inline]
pub const fn is_personal_ip(ip: IpAddr) -> bool {
    match unmap_ip(ip) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.is_multicast())
        }
    }
}

impl IpUnit {
    /// Normalize any [`IpAddr`] into its accounting unit (IPv4 or IPv6 `/64`).
    #[inline]
    pub const fn from_ip(ip: IpAddr) -> Self {
        match unmap_ip(ip) {
            IpAddr::V4(v4) => Self::V4(u32::from_be_bytes(v4.octets())),
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let hi = u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
                Self::V6Prefix(hi)
            }
        }
    }

    /// Normalize `ip` only if [`is_personal_ip`] returns `true`.
    #[inline]
    pub const fn from_personal_ip(ip: IpAddr) -> Option<Self> {
        if is_personal_ip(ip) {
            Some(Self::from_ip(ip))
        } else {
            None
        }
    }

    /// First address of this unit (the IPv4 itself, or the base address of the
    /// IPv6 `/64`).
    #[inline]
    pub const fn base_ip(self) -> IpAddr {
        match self {
            Self::V4(v) => IpAddr::V4(Ipv4Addr::from_bits(v)),
            Self::V6Prefix(hi) => IpAddr::V6(Ipv6Addr::from_bits((hi as u128) << 64)),
        }
    }

    /// True if `ip` falls inside this accounting unit.
    #[inline]
    pub const fn contains_ip(self, ip: IpAddr) -> bool {
        matches!(
            (self, Self::from_ip(ip)),
            (Self::V4(a), Self::V4(b)) if a == b
        ) || matches!(
            (self, Self::from_ip(ip)),
            (Self::V6Prefix(a), Self::V6Prefix(b)) if a == b
        )
    }

    /// True if this unit represents a personal/routable client address.
    #[inline]
    pub const fn is_personal(self) -> bool {
        is_personal_ip(self.base_ip())
    }
}

impl From<IpAddr> for IpUnit {
    #[inline]
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

impl From<Ipv4Addr> for IpUnit {
    #[inline]
    fn from(v4: Ipv4Addr) -> Self {
        Self::V4(u32::from(v4))
    }
}

impl fmt::Display for IpUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(v) => write!(f, "{}", Ipv4Addr::from_bits(v)),
            Self::V6Prefix(hi) => write!(f, "{}/64", Ipv6Addr::from_bits(u128::from(hi) << 64)),
        }
    }
}

impl FromStr for IpUnit {
    type Err = IpUnitParseError;

    /// Accepts a plain IPv4 (`1.2.3.4`), IPv4-mapped IPv6 (`::ffff:1.2.3.4`),
    /// plain IPv6 (`2001:db8::1`), or an explicit IPv6 `/64` (`2001:db8::/64`)
    /// or IPv4 `/32` (`1.2.3.4/32`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Self::from_ip(ip));
        }

        if let Some((addr_part, prefix_part)) = trimmed.split_once('/') {
            let prefix_len: u8 = prefix_part
                .parse()
                .map_err(|_| IpUnitParseError::Invalid(s.to_owned()))?;
            let ip: IpAddr = addr_part
                .parse()
                .map_err(|_| IpUnitParseError::Invalid(s.to_owned()))?;
            match (unmap_ip(ip), prefix_len) {
                (IpAddr::V4(v4), 32) => return Ok(Self::V4(u32::from(v4))),
                (IpAddr::V6(v6), 64) => return Ok(Self::from_ip(IpAddr::V6(v6))),
                _ => return Err(IpUnitParseError::Invalid(s.to_owned())),
            }
        }

        Err(IpUnitParseError::Invalid(s.to_owned()))
    }
}

impl Serialize for IpUnit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpUnit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_unit_size_and_normalization() {
        assert!(std::mem::size_of::<IpUnit>() <= 16);

        let v4: IpAddr = "203.0.113.42".parse().unwrap();
        let v4_mapped: IpAddr = "::ffff:203.0.113.42".parse().unwrap();
        assert_eq!(IpUnit::from_ip(v4), IpUnit::from_ip(v4_mapped));
        assert_eq!(IpUnit::from_ip(v4).to_string(), "203.0.113.42");

        let v6a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:abcd:1234:ffff:eeee:dddd:cccc".parse().unwrap();
        assert_eq!(IpUnit::from_ip(v6a), IpUnit::from_ip(v6b));
        assert_eq!(IpUnit::from_ip(v6a).to_string(), "2001:db8:abcd:1234::/64");
        assert_eq!(
            "2001:db8:abcd:1234::/64".parse::<IpUnit>().unwrap(),
            IpUnit::from_ip(v6a)
        );
    }

    #[test]
    fn personal_ip_classification() {
        assert!(is_personal_ip("203.0.113.1".parse().unwrap()));
        assert!(is_personal_ip("::ffff:203.0.113.1".parse().unwrap()));
        assert!(is_personal_ip("2001:db8::1".parse().unwrap()));

        assert!(!is_personal_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_personal_ip("::1".parse().unwrap()));
        assert!(!is_personal_ip("10.0.0.5".parse().unwrap()));
        assert!(!is_personal_ip("172.16.1.1".parse().unwrap()));
        assert!(!is_personal_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_personal_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_personal_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_personal_ip("224.0.0.1".parse().unwrap()));
        assert!(!is_personal_ip("fd00::1".parse().unwrap()));
        assert!(!is_personal_ip("fe80::1".parse().unwrap()));
        assert!(!is_personal_ip("::ffff:10.0.0.1".parse().unwrap()));
    }
}
