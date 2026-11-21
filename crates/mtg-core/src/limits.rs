//! Per-secret governance limits, quota/speed/expiry parsers, and admission deny reasons.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Lowest speed limit accepted: 64 kbit/s = 8,000 bytes/s.
pub const MIN_SPEED_BYTES_PER_SECOND: i64 = 64_000 / 8;

/// Maximum speed limit accepted (1 TiB/s).
const MAX_SPEED_BYTES_PER_SECOND: f64 = (1u64 << 40) as f64;

/// Errors returned while parsing quota, speed, reset policy, or expiry fields.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LimitParseError {
    #[error("quota must be positive ({0:?})")]
    NegativeQuota(String),
    #[error("incorrect quota value ({0:?})")]
    InvalidQuota(String),
    #[error("incorrect speed {0:?}: want a number and a unit, like \"5mbit\" or \"1MB/s\"")]
    InvalidSpeed(String),
    #[error("speed must be positive ({0:?}); leave it out for no limit")]
    NonPositiveSpeed(String),
    #[error("incorrect speed unit in {0:?}")]
    InvalidSpeedUnit(String),
    #[error("speed {0:?} is unreasonably large")]
    SpeedTooLarge(String),
    #[error("speed {0:?} is below the minimum of 64kbit/s (8000 bytes/s)")]
    SpeedTooSmall(String),
    #[error("unknown quota reset {0:?} (want \"none\", \"daily\", \"weekly\", or \"monthly\")")]
    UnknownQuotaReset(String),
    #[error("invalid expiry {0:?} (want RFC3339 or YYYY-MM-DD)")]
    InvalidExpiry(String),
}

/// How a per-secret data quota is replenished.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaReset {
    #[default]
    None,
    Daily,
    Weekly,
    Monthly,
}

impl QuotaReset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Daily => 1,
            Self::Weekly => 2,
            Self::Monthly => 3,
        }
    }

    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Daily,
            2 => Self::Weekly,
            3 => Self::Monthly,
            _ => Self::None,
        }
    }
}

impl fmt::Display for QuotaReset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QuotaReset {
    type Err = LimitParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_quota_reset(s)
    }
}

impl Serialize for QuotaReset {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for QuotaReset {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        parse_quota_reset(&s).map_err(serde::de::Error::custom)
    }
}

/// Totals divided by fair-share scheduling across active client addresses.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FairTotals {
    pub speed: i64,
    pub up: i64,
    pub down: i64,
}

impl FairTotals {
    #[inline]
    pub const fn is_active(self) -> bool {
        self.speed > 0 || self.up > 0 || self.down > 0
    }
}

/// Per-user governance limits attached to a named secret.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecretLimits {
    /// Maximum relayed bytes (up + down) allowed in the current quota period (`0` = unlimited).
    pub quota_bytes: i64,
    /// Quota reset schedule.
    pub quota_reset: QuotaReset,
    /// Optional deadline after which new connections are rejected and active ones cut off.
    pub expires_at: Option<DateTime<Utc>>,
    /// Administrative disable switch.
    pub disabled: bool,
    /// Combined upload + download speed limit in bytes/s (`0` = unlimited).
    pub speed_bytes_per_second: i64,
    /// Upload (client -> Telegram) speed limit in bytes/s (`0` = unlimited).
    pub speed_up_bytes_per_second: i64,
    /// Download (Telegram -> client) speed limit in bytes/s (`0` = unlimited).
    pub speed_down_bytes_per_second: i64,
    /// Maximum distinct client addresses (`IpUnit`) allowed concurrently (`0` = unlimited).
    pub ip_limit: u32,
    /// Maximum live connections per single client address (`0` = unlimited).
    pub client_conns: u32,
    /// Maximum total concurrent connections across all addresses for this secret (`0` = unlimited).
    pub max_connections: u32,
    /// Per-address combined speed ceiling in bytes/s (`0` = unlimited).
    pub client_speed_bytes_per_second: i64,
    /// Per-address upload speed ceiling in bytes/s (`0` = unlimited).
    pub client_speed_up_bytes_per_second: i64,
    /// Per-address download speed ceiling in bytes/s (`0` = unlimited).
    pub client_speed_down_bytes_per_second: i64,
    /// Work-conserving fair share of secret speed limits across active addresses.
    pub client_fair: bool,
    /// Per-TCP-connection combined speed cap in bytes/s (`0` = unlimited; CGNAT-safe!).
    pub conn_speed_bytes_per_second: i64,
    /// Per-TCP-connection upload speed cap in bytes/s (`0` = unlimited).
    pub conn_speed_up_bytes_per_second: i64,
    /// Per-TCP-connection download speed cap in bytes/s (`0` = unlimited).
    pub conn_speed_down_bytes_per_second: i64,
}

impl SecretLimits {
    /// True when no restriction of any kind is configured.
    pub const fn is_zero(&self) -> bool {
        self.quota_bytes == 0
            && matches!(self.quota_reset, QuotaReset::None)
            && self.expires_at.is_none()
            && !self.disabled
            && self.speed_bytes_per_second == 0
            && self.speed_up_bytes_per_second == 0
            && self.speed_down_bytes_per_second == 0
            && self.ip_limit == 0
            && self.client_conns == 0
            && self.max_connections == 0
            && self.client_speed_bytes_per_second == 0
            && self.client_speed_up_bytes_per_second == 0
            && self.client_speed_down_bytes_per_second == 0
            && !self.client_fair
            && self.conn_speed_bytes_per_second == 0
            && self.conn_speed_up_bytes_per_second == 0
            && self.conn_speed_down_bytes_per_second == 0
    }

    /// True if any per-address control (`client-conns`, `client-speed*`, `client-fair`) is active.
    pub const fn has_client_control(&self) -> bool {
        self.client_conns > 0
            || self.client_speed_bytes_per_second > 0
            || self.client_speed_up_bytes_per_second > 0
            || self.client_speed_down_bytes_per_second > 0
            || self.client_fair
    }

    /// Merge unset (`0` / `None` / `false`) fields from `defaults` (used for `[limits.default-secret]`).
    /// Explicit per-secret overrides always take precedence.
    #[must_use]
    pub fn merge_defaults(&self, defaults: &Self) -> Self {
        Self {
            quota_bytes: if self.quota_bytes > 0 {
                self.quota_bytes
            } else {
                defaults.quota_bytes
            },
            quota_reset: if matches!(self.quota_reset, QuotaReset::None) {
                defaults.quota_reset
            } else {
                self.quota_reset
            },
            expires_at: self.expires_at.or(defaults.expires_at),
            disabled: self.disabled || defaults.disabled,
            speed_bytes_per_second: if self.speed_bytes_per_second > 0 {
                self.speed_bytes_per_second
            } else {
                defaults.speed_bytes_per_second
            },
            speed_up_bytes_per_second: if self.speed_up_bytes_per_second > 0 {
                self.speed_up_bytes_per_second
            } else {
                defaults.speed_up_bytes_per_second
            },
            speed_down_bytes_per_second: if self.speed_down_bytes_per_second > 0 {
                self.speed_down_bytes_per_second
            } else {
                defaults.speed_down_bytes_per_second
            },
            ip_limit: if self.ip_limit > 0 {
                self.ip_limit
            } else {
                defaults.ip_limit
            },
            client_conns: if self.client_conns > 0 {
                self.client_conns
            } else {
                defaults.client_conns
            },
            max_connections: if self.max_connections > 0 {
                self.max_connections
            } else {
                defaults.max_connections
            },
            client_speed_bytes_per_second: if self.client_speed_bytes_per_second > 0 {
                self.client_speed_bytes_per_second
            } else {
                defaults.client_speed_bytes_per_second
            },
            client_speed_up_bytes_per_second: if self.client_speed_up_bytes_per_second > 0 {
                self.client_speed_up_bytes_per_second
            } else {
                defaults.client_speed_up_bytes_per_second
            },
            client_speed_down_bytes_per_second: if self.client_speed_down_bytes_per_second > 0 {
                self.client_speed_down_bytes_per_second
            } else {
                defaults.client_speed_down_bytes_per_second
            },
            client_fair: self.client_fair || defaults.client_fair,
            conn_speed_bytes_per_second: if self.conn_speed_bytes_per_second > 0 {
                self.conn_speed_bytes_per_second
            } else {
                defaults.conn_speed_bytes_per_second
            },
            conn_speed_up_bytes_per_second: if self.conn_speed_up_bytes_per_second > 0 {
                self.conn_speed_up_bytes_per_second
            } else {
                defaults.conn_speed_up_bytes_per_second
            },
            conn_speed_down_bytes_per_second: if self.conn_speed_down_bytes_per_second > 0 {
                self.conn_speed_down_bytes_per_second
            } else {
                defaults.conn_speed_down_bytes_per_second
            },
        }
    }

    /// Speed totals divided by fair-share when `client_fair` is enabled.
    pub const fn fair_totals(&self) -> FairTotals {
        if !self.client_fair {
            return FairTotals {
                speed: 0,
                up: 0,
                down: 0,
            };
        }
        FairTotals {
            speed: self.speed_bytes_per_second,
            up: self.speed_up_bytes_per_second,
            down: self.speed_down_bytes_per_second,
        }
    }
}

/// Server-wide traffic, connection, and CGNAT-safe per-connection governance limits (`[limits]`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GlobalLimits {
    /// Server-wide combined (up + down) bandwidth cap in bytes/s across all secrets (`0` = unlimited).
    pub speed_bytes_per_second: i64,
    /// Server-wide upload bandwidth cap in bytes/s (`0` = unlimited).
    pub speed_up_bytes_per_second: i64,
    /// Server-wide download bandwidth cap in bytes/s (`0` = unlimited).
    pub speed_down_bytes_per_second: i64,
    /// Server-wide data quota across all secrets in bytes (`0` = unlimited; e.g. 950GB on 1TB VPS).
    pub quota_bytes: i64,
    /// Server-wide quota reset schedule.
    pub quota_reset: QuotaReset,
    /// Global maximum concurrent TCP connections per IPv4 / IPv6 `/64` across all secrets (`0` = unlimited).
    pub max_connections_per_ip: u32,
    /// Global maximum new connections per second per IPv4 / IPv6 `/64` (burst 2×; `0` = unlimited).
    pub max_new_connections_per_ip: u32,
    /// Global per-TCP-connection combined speed cap in bytes/s (`0` = unlimited; CGNAT-safe!).
    pub conn_speed_bytes_per_second: i64,
    /// Global per-TCP-connection upload speed cap in bytes/s (`0` = unlimited).
    pub conn_speed_up_bytes_per_second: i64,
    /// Global per-TCP-connection download speed cap in bytes/s (`0` = unlimited).
    pub conn_speed_down_bytes_per_second: i64,
}

impl GlobalLimits {
    pub const fn is_zero(&self) -> bool {
        self.speed_bytes_per_second == 0
            && self.speed_up_bytes_per_second == 0
            && self.speed_down_bytes_per_second == 0
            && self.quota_bytes == 0
            && matches!(self.quota_reset, QuotaReset::None)
            && self.max_connections_per_ip == 0
            && self.max_new_connections_per_ip == 0
            && self.conn_speed_bytes_per_second == 0
            && self.conn_speed_up_bytes_per_second == 0
            && self.conn_speed_down_bytes_per_second == 0
    }
}

/// Reason a connection was refused by per-secret governance limits.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DenyReason {
    #[default]
    None = 0,
    Disabled = 1,
    Expired = 2,
    Quota = 3,
    IpLimit = 4,
    ClientConns = 5,
    Banned = 6,
    KeyRevoked = 7,
    MaxConnections = 8,
}

impl DenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "allowed",
            Self::Disabled => "disabled",
            Self::Expired => "expired",
            Self::Quota => "quota_exceeded",
            Self::IpLimit => "ip_limit",
            Self::ClientConns => "client_conns",
            Self::Banned => "banned",
            Self::KeyRevoked => "key_revoked",
            Self::MaxConnections => "max_connections",
        }
    }

    #[inline]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::None)
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a byte size as a bare integer (`"1048576"`) or human-friendly binary
/// unit (`"10GB"`, `"500 MiB"`, `"1KiB"`, `"1KB"`, `"100B"`). Empty yields `0`.
pub fn parse_quota_bytes(s: &str) -> Result<i64, LimitParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    if let Ok(n) = trimmed.parse::<i64>() {
        if n < 0 {
            return Err(LimitParseError::NegativeQuota(s.to_owned()));
        }
        return Ok(n);
    }

    let compact: String = trimmed
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    if compact.starts_with('-') {
        return Err(LimitParseError::NegativeQuota(s.to_owned()));
    }

    let split = compact
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(compact.len());
    let (num_str, unit_raw) = compact.split_at(split);
    if num_str.is_empty() || unit_raw.is_empty() {
        return Err(LimitParseError::InvalidQuota(s.to_owned()));
    }

    let mult: u128 = match unit_raw.to_ascii_uppercase().as_str() {
        "B" => 1,
        "K" | "KB" | "KIB" => 1u128 << 10,
        "M" | "MB" | "MIB" => 1u128 << 20,
        "G" | "GB" | "GIB" => 1u128 << 30,
        "T" | "TB" | "TIB" => 1u128 << 40,
        "P" | "PB" | "PIB" => 1u128 << 50,
        "E" | "EB" | "EIB" => 1u128 << 60,
        _ => return Err(LimitParseError::InvalidQuota(s.to_owned())),
    };

    if !num_str.contains('.') {
        let count = num_str
            .parse::<u128>()
            .map_err(|_| LimitParseError::InvalidQuota(s.to_owned()))?;
        let total = count
            .checked_mul(mult)
            .ok_or_else(|| LimitParseError::InvalidQuota(s.to_owned()))?;
        return i64::try_from(total).map_err(|_| LimitParseError::InvalidQuota(s.to_owned()));
    }

    let val = num_str
        .parse::<f64>()
        .map_err(|_| LimitParseError::InvalidQuota(s.to_owned()))?;
    if !val.is_finite() || val < 0.0 {
        return Err(LimitParseError::InvalidQuota(s.to_owned()));
    }
    let total = val * (mult as f64);
    if total > i64::MAX as f64 {
        return Err(LimitParseError::InvalidQuota(s.to_owned()));
    }
    Ok(total as i64)
}

/// Parse a speed limit into bytes per second. Empty yields `0` (unlimited).
///
/// Fixes Go's `"MBps"` case-folding bug:
/// - `Bps` (capital `B`, lowercase `ps`) is **bytes/s** (`1MBps` = 1 MiB/s),
///   while `bps` (lowercase `b`, e.g. `5mbps` / `5Mbps`) and `bit` (`5mbit`,
///   `5 Mbit/s`) are **bits/s** (decimal SI: k=1e3, M=1e6, G=1e9).
/// - Byte units (`B`, `KB`, `MB`, `GB`, `KiB`, `MiB`, `GiB`, optional `/s`)
///   use binary multiples (`1 << 10`, `1 << 20`, `1 << 30`).
pub fn parse_speed(s: &str) -> Result<i64, LimitParseError> {
    let raw = s.trim();
    if raw.is_empty() {
        return Ok(0);
    }

    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.starts_with('-') {
        return Err(LimitParseError::NonPositiveSpeed(s.to_owned()));
    }

    let split = compact
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(compact.len());
    let (num_str, unit_raw) = compact.split_at(split);

    if num_str.is_empty() {
        return Err(LimitParseError::InvalidSpeed(s.to_owned()));
    }

    let value = num_str
        .parse::<f64>()
        .map_err(|_| LimitParseError::InvalidSpeed(s.to_owned()))?;
    if !value.is_finite() {
        return Err(LimitParseError::InvalidSpeed(s.to_owned()));
    }
    if value <= 0.0 {
        return Err(LimitParseError::NonPositiveSpeed(s.to_owned()));
    }

    // Strip optional trailing `/s` or `/S` preserving unit case for `Bps` vs `bps`.
    let unit_trimmed = unit_raw
        .strip_suffix("/s")
        .or_else(|| unit_raw.strip_suffix("/S"))
        .unwrap_or(unit_raw);

    let bytes_per_second = if unit_trimmed.is_empty() {
        value
    } else if let Some(prefix_byte) = unit_trimmed.strip_suffix("Bps") {
        // Explicit capital `B` + lowercase `ps`: Bytes per second (e.g. `1MBps`, `500KBps`, `1MiBps`).
        let mult = byte_unit_multiplier_prefix(&prefix_byte.to_ascii_lowercase())
            .ok_or_else(|| LimitParseError::InvalidSpeedUnit(s.to_owned()))?;
        value * mult
    } else {
        let lower = unit_trimmed.to_ascii_lowercase();
        if lower.ends_with("bps") || lower.ends_with("bit") {
            let prefix = lower
                .strip_suffix("bps")
                .or_else(|| lower.strip_suffix("bit"))
                .unwrap_or("");
            let mult = match prefix {
                "" => 1.0,
                "k" => 1e3,
                "m" => 1e6,
                "g" => 1e9,
                _ => return Err(LimitParseError::InvalidSpeedUnit(s.to_owned())),
            };
            value * mult / 8.0
        } else {
            let clean = lower.strip_suffix("ps").unwrap_or(&lower);
            let mult = match clean {
                "b" => 1.0,
                "kb" | "kib" => (1u64 << 10) as f64,
                "mb" | "mib" => (1u64 << 20) as f64,
                "gb" | "gib" => (1u64 << 30) as f64,
                _ => return Err(LimitParseError::InvalidSpeedUnit(s.to_owned())),
            };
            value * mult
        }
    };

    if bytes_per_second > MAX_SPEED_BYTES_PER_SECOND {
        return Err(LimitParseError::SpeedTooLarge(s.to_owned()));
    }
    if bytes_per_second < MIN_SPEED_BYTES_PER_SECOND as f64 {
        return Err(LimitParseError::SpeedTooSmall(s.to_owned()));
    }

    Ok(bytes_per_second as i64)
}

fn byte_unit_multiplier_prefix(prefix_lower: &str) -> Option<f64> {
    match prefix_lower {
        "" => Some(1.0),
        "k" | "ki" => Some((1u64 << 10) as f64),
        "m" | "mi" => Some((1u64 << 20) as f64),
        "g" | "gi" => Some((1u64 << 30) as f64),
        _ => None,
    }
}

/// Parse the quota reset policy (`""` / `"none"` / `"daily"` / `"weekly"` / `"monthly"`, case-insensitive).
pub fn parse_quota_reset(s: &str) -> Result<QuotaReset, LimitParseError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(QuotaReset::None),
        "daily" => Ok(QuotaReset::Daily),
        "weekly" => Ok(QuotaReset::Weekly),
        "monthly" => Ok(QuotaReset::Monthly),
        _ => Err(LimitParseError::UnknownQuotaReset(s.to_owned())),
    }
}

/// Parse an expiry deadline in RFC 3339 (`"2026-12-31T00:00:00Z"`) or plain date
/// (`"2026-12-31"`, midnight UTC) form. Empty string yields `None`.
pub fn parse_expiry(s: &str) -> Result<Option<DateTime<Utc>>, LimitParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }

    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        && let Some(ndt) = date.and_hms_opt(0, 0, 0)
    {
        return Ok(Some(ndt.and_utc()));
    }

    Err(LimitParseError::InvalidExpiry(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use chrono::Datelike as _;
    use chrono::Timelike as _;

    use super::*;

    #[test]
    fn quota_parsing_parity() {
        assert_eq!(parse_quota_bytes("").unwrap(), 0);
        assert_eq!(parse_quota_bytes("   ").unwrap(), 0);
        assert_eq!(parse_quota_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_quota_bytes("1KiB").unwrap(), 1024);
        assert_eq!(parse_quota_bytes("1KB").unwrap(), 1024);
        assert_eq!(parse_quota_bytes("10GB").unwrap(), 10 * (1i64 << 30));
        assert_eq!(parse_quota_bytes("500 MiB").unwrap(), 500 * (1i64 << 20));
        assert!(parse_quota_bytes("nonsense").is_err());
        assert!(parse_quota_bytes("-10").is_err());
    }

    #[test]
    fn speed_parsing_parity_and_mbps_fix() {
        assert_eq!(parse_speed("").unwrap(), 0);
        assert_eq!(parse_speed("5mbit").unwrap(), 625_000);
        assert_eq!(parse_speed("5 Mbit/s").unwrap(), 625_000);
        assert_eq!(parse_speed("5mbps").unwrap(), 625_000);
        assert_eq!(parse_speed("5Mbps").unwrap(), 625_000);
        assert_eq!(parse_speed("500kbit").unwrap(), 62_500);
        assert_eq!(parse_speed("1gbit").unwrap(), 125_000_000);
        assert_eq!(parse_speed("64kbit").unwrap(), 8_000);
        assert_eq!(parse_speed("1MB/s").unwrap(), 1 << 20);
        assert_eq!(parse_speed("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse_speed("500KB").unwrap(), 500 << 10);
        assert_eq!(parse_speed("2.5MB/s").unwrap(), 2_621_440);
        assert_eq!(parse_speed("8192").unwrap(), 8192);

        // Fixed bug vs Go: `1MBps` is 1 MiB/s (not 1 Mbit/s = 125,000 B/s)!
        assert_eq!(parse_speed("1MBps").unwrap(), 1 << 20);
        assert_eq!(parse_speed("500KBps").unwrap(), 500 << 10);
        assert_eq!(parse_speed("1GiBps").unwrap(), 1 << 30);

        assert!(parse_speed("100").is_err());
        assert!(parse_speed("0").is_err());
        assert!(parse_speed("-5mbit").is_err());
        assert!(parse_speed("999999GB/s").is_err());
    }

    #[test]
    fn quota_reset_and_expiry_parity() {
        assert_eq!(parse_quota_reset("").unwrap(), QuotaReset::None);
        assert_eq!(parse_quota_reset("NONE").unwrap(), QuotaReset::None);
        assert_eq!(parse_quota_reset("Daily").unwrap(), QuotaReset::Daily);
        assert_eq!(parse_quota_reset("WEEKLY").unwrap(), QuotaReset::Weekly);
        assert_eq!(parse_quota_reset("Monthly").unwrap(), QuotaReset::Monthly);
        assert!(parse_quota_reset("yearly").is_err());

        assert_eq!(parse_expiry("").unwrap(), None);
        let d = parse_expiry("2026-12-31").unwrap().unwrap();
        assert_eq!((d.year(), d.month(), d.day()), (2026, 12, 31));
        let ts = parse_expiry("2026-01-02T15:04:05Z").unwrap().unwrap();
        assert_eq!(ts.hour(), 15);
        assert!(parse_expiry("31/12/2026").is_err());
    }
}
