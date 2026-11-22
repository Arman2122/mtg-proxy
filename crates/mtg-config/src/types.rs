//! Typed configuration value parsers and Go-compatible formatters.

use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use mtg_core::parse_quota_bytes;
use thiserror::Error;

/// Length in bytes of a Telegram advertising tag (`ad-tag`).
pub const AD_TAG_LEN: usize = 16;

/// Errors returned while parsing individual typed configuration values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TypeParseError {
    #[error("incorrect host:port address {0:?}")]
    InvalidHostPort(String),
    #[error("incorrect IP address {0:?}")]
    InvalidIp(String),
    #[error("incorrect port {0}: must be in 1..=65535")]
    InvalidPort(u64),
    #[error("incorrect duration {0:?}")]
    InvalidDuration(String),
    #[error("incorrect ad-tag: must be 32 hex characters")]
    InvalidAdTag,
    #[error(
        "unknown prefer-ip value {0:?} (expected prefer-ipv4, prefer-ipv6, only-ipv4, or only-ipv6)"
    )]
    InvalidPreferIp(String),
    #[error("unknown client-ip source {0:?} (expected \"proxy-protocol\" or \"x-forwarded-for\")")]
    InvalidClientIpSource(String),
    #[error("unknown on-unknown-secret action {0:?} (expected \"close\" or \"drain\")")]
    InvalidUnknownSecretAction(String),
    #[error("unknown ip-filter action {0:?} (expected \"front\" or \"close\")")]
    InvalidIpFilterAction(String),
    #[error(
        "unknown unknown-sni-action {0:?} (expected \"front\", \"reject-handshake\", or \"drop\")"
    )]
    InvalidUnknownSniAction(String),
    #[error(
        "invalid server-hello-fragment-mss {0:?} (expected \"off\", \"extreme\", \"tspu\", \"balanced\", 0, or 88..=1400)"
    )]
    InvalidFragmentMss(String),
    #[error("unknown web CDN preset {0:?} (expected \"cloudflare\" or \"arvancloud\")")]
    InvalidWebCdnPreset(String),
    #[error(
        "unknown web carrier mode {0:?} (expected \"auto\", \"websocket\", \"ws-lanes\", \"https\", or \"https-lanes\")"
    )]
    InvalidWebCarrierMode(String),
    #[error("unknown API persistence mode {0:?} (expected \"memory\", \"overlay\", or \"toml\")")]
    InvalidApiPersistenceMode(String),
    #[error(
        "unknown outbound strategy {0:?} (expected \"ewma-rtt\", \"failover\", \"weighted\", \"round-robin\", or \"hash-dc\")"
    )]
    InvalidOutboundStrategy(String),
    #[error("incorrect IP or CIDR entry {0:?}")]
    InvalidCidr(String),
    #[error("unknown handshake-budget mode {0:?} (expected \"enforce\", \"observe\", or \"off\")")]
    InvalidHandshakeBudgetMode(String),
    #[error("incorrect handshake-budget cpu-percent {0}: must be in 1..=100")]
    InvalidHandshakeBudgetCpu(i64),
    #[error("incorrect handshake-budget per-ip-ms {0}: must be >= 0")]
    InvalidHandshakeBudgetPerIp(i64),
    #[error("unknown statsd tag-format {0:?}")]
    InvalidStatsdTagFormat(String),
    #[error("incorrect error-rate {0}: must be in (0, 1)")]
    InvalidErrorRate(String),
    #[error("incorrect proxy URL: {0}")]
    InvalidProxyUrl(String),
    #[error("incorrect DNS URI {0:?}")]
    InvalidDnsUri(String),
    #[error("incorrect HTTPS URL {0:?}")]
    InvalidHttpsUrl(String),
    #[error("incorrect blocklist URI {0:?}")]
    InvalidBlocklistUri(String),
    #[error("incorrect byte size {0:?}")]
    InvalidBytes(String),
    #[error("incorrect HTTP path {0:?}")]
    InvalidHttpPath(String),
    #[error("incorrect host {0:?}")]
    InvalidHost(String),
}

/// Validated `host:port` binding or target address.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
    raw: String,
}

impl HostPort {
    pub fn parse(s: &str) -> Result<Self, TypeParseError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(TypeParseError::InvalidHostPort(s.to_owned()));
        }

        let (host_part, port_str) = if let Some(rest) = trimmed.strip_prefix('[') {
            let (h, after) = rest
                .split_once("]:")
                .ok_or_else(|| TypeParseError::InvalidHostPort(s.to_owned()))?;
            (h, after)
        } else {
            let (h, p) = trimmed
                .rsplit_once(':')
                .ok_or_else(|| TypeParseError::InvalidHostPort(s.to_owned()))?;
            if h.contains(':') {
                // Unbracketed IPv6 literal is invalid host:port.
                return Err(TypeParseError::InvalidHostPort(s.to_owned()));
            }
            (h, p)
        };

        let port: u16 = port_str
            .parse()
            .map_err(|_| TypeParseError::InvalidHostPort(s.to_owned()))?;
        if port == 0 {
            return Err(TypeParseError::InvalidHostPort(s.to_owned()));
        }

        // Validate IP or hostname (empty host like ":3128" is valid in Go net.SplitHostPort).
        let canonical = if host_part.contains(':') {
            let ip: Ipv6Addr = host_part
                .parse()
                .map_err(|_| TypeParseError::InvalidHostPort(s.to_owned()))?;
            format!("[{ip}]:{port}")
        } else if !host_part.is_empty() {
            if let Ok(ip) = host_part.parse::<Ipv4Addr>() {
                format!("{ip}:{port}")
            } else {
                // Must be a valid hostname (no spaces or slashes).
                if host_part.chars().any(|c| c.is_whitespace() || c == '/') {
                    return Err(TypeParseError::InvalidHostPort(s.to_owned()));
                }
                format!("{host_part}:{port}")
            }
        } else {
            format!(":{port}")
        };

        Ok(Self {
            host: host_part.to_owned(),
            port,
            raw: canonical,
        })
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Compare two `HostPort`s by semantic IP + port equality.
    pub fn same_address(&self, other: &Self) -> bool {
        if self.port != other.port {
            return false;
        }
        match (self.host.parse::<IpAddr>(), other.host.parse::<IpAddr>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => self.host.eq_ignore_ascii_case(&other.host),
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// IP family preference for outbound Telegram DC dialing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreferIp {
    #[default]
    PreferIpv6,
    PreferIpv4,
    OnlyIpv4,
    OnlyIpv6,
}

impl PreferIp {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreferIpv6 => "prefer-ipv6",
            Self::PreferIpv4 => "prefer-ipv4",
            Self::OnlyIpv4 => "only-ipv4",
            Self::OnlyIpv6 => "only-ipv6",
        }
    }
}

impl FromStr for PreferIp {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "prefer-ipv6" => Ok(Self::PreferIpv6),
            "prefer-ipv4" => Ok(Self::PreferIpv4),
            "only-ipv4" => Ok(Self::OnlyIpv4),
            "only-ipv6" => Ok(Self::OnlyIpv6),
            _ => Err(TypeParseError::InvalidPreferIp(s.to_owned())),
        }
    }
}

/// How the WEB relay obtains the browser's client IP.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientIpSource {
    #[default]
    ProxyProtocol,
    XForwardedFor,
}

impl ClientIpSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyProtocol => "proxy-protocol",
            Self::XForwardedFor => "x-forwarded-for",
        }
    }
}

impl FromStr for ClientIpSource {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "proxy-protocol" | "proxy_protocol" | "proxyprotocol" => Ok(Self::ProxyProtocol),
            "x-forwarded-for" | "forwarded-for" | "xff" => Ok(Self::XForwardedFor),
            _ => Err(TypeParseError::InvalidClientIpSource(s.to_owned())),
        }
    }
}

/// Action taken by an obfuscated2 `[[listener]]` when no configured secret matches.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnknownSecretAction {
    #[default]
    Close,
    Drain,
}

impl UnknownSecretAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Close => "close",
            Self::Drain => "drain",
        }
    }
}

impl FromStr for UnknownSecretAction {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "close" => Ok(Self::Close),
            "drain" => Ok(Self::Drain),
            _ => Err(TypeParseError::InvalidUnknownSecretAction(s.to_owned())),
        }
    }
}

/// Action taken when a client IP is rejected by `[defense.allowlist]` or matched
/// by `[defense.blocklist]`.
///
/// - [`Self::Front`] (default for `allowlist`): transparently domain-front the
///   connection directly to the cover website (0 secret matching, 0 HMAC CPU,
///   0 TCP drop fingerprint; in WEB relay, serve the Tier-3 cover site directly).
/// - [`Self::Close`] (default for `blocklist`): drop the TCP connection
///   immediately (or return uncacheable `404` in WEB relay).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFilterAction {
    #[default]
    Front,
    Close,
}

impl IpFilterAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Front => "front",
            Self::Close => "close",
        }
    }
}

impl fmt::Display for IpFilterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IpFilterAction {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "front" => Ok(Self::Front),
            "close" => Ok(Self::Close),
            _ => Err(TypeParseError::InvalidIpFilterAction(s.to_owned())),
        }
    }
}

/// Action taken on unmatched FakeTLS ClientHellos whose SNI does not match any
/// configured secret or `[domain-fronting].host`:
///
/// - [`Self::Front`] (default): transparently splice to the configured cover website.
/// - [`Self::RejectHandshake`]: immediately emit a 7-byte nginx-identical TLS fatal
///   `unrecognized_name` alert (`[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70]`) and close
///   with zero upstream dial!
/// - [`Self::Drop`]: silently close the connection without writing any bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnknownSniAction {
    #[default]
    Front,
    RejectHandshake,
    Drop,
}

impl UnknownSniAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Front => "front",
            Self::RejectHandshake => "reject-handshake",
            Self::Drop => "drop",
        }
    }
}

impl fmt::Display for UnknownSniAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UnknownSniAction {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "front" => Ok(Self::Front),
            "reject-handshake" | "reject_handshake" | "reject" => Ok(Self::RejectHandshake),
            "drop" | "close" => Ok(Self::Drop),
            _ => Err(TypeParseError::InvalidUnknownSniAction(s.to_owned())),
        }
    }
}

/// Parse `[defense.doppelganger] server-hello-fragment-mss` from a preset name
/// (`"off"`, `"extreme"` = 88, `"tspu"` = 92, `"balanced"` = 256) or numeric string (`0` or `88..=1400`).
pub fn parse_server_hello_fragment_mss(s: &str) -> Result<u16, TypeParseError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "off" | "disabled" | "none" | "0" => Ok(0),
        "extreme" => Ok(88),
        "tspu" => Ok(92),
        "balanced" => Ok(256),
        other => {
            let v: u16 = other
                .parse()
                .map_err(|_| TypeParseError::InvalidFragmentMss(s.to_owned()))?;
            if v == 0 || (88..=1400).contains(&v) {
                Ok(v)
            } else {
                Err(TypeParseError::InvalidFragmentMss(s.to_owned()))
            }
        }
    }
}

/// Carrier mode advertised and served by `[web]` (`mtg-webrelay`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCarrierMode {
    /// Classic single WebSocket `/api/v1/ws` (default for 100% backwards compatibility).
    #[default]
    Websocket,
    /// Multi-lane parallel WebSockets (`/api/v1/ws?lane=0..N-1`).
    WsLanes,
    /// Pure HTTPS fetch Conveyor (`POST /up` + event-driven long-poll `GET /down?cursor=N`,
    /// works natively on Telegram iOS WKWebView & proxies blocking WebSocket upgrades!).
    Https,
    /// Multi-lane HTTP/2 HTTPS Conveyor (parallel lanes over one multiplexed HTTP/2 TLS 1.3 stream!).
    HttpsLanes,
    /// Automatic negotiation (`https-lanes` on HTTP/2 & iOS WKWebView, `websocket` on HTTP/1.1
    /// Desktop/Android with automatic self-healing failover to `https` if WS upgrade is blocked!).
    Auto,
}

impl WebCarrierMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Websocket => "websocket",
            Self::WsLanes => "ws-lanes",
            Self::Https => "https",
            Self::HttpsLanes => "https-lanes",
            Self::Auto => "auto",
        }
    }
}

impl fmt::Display for WebCarrierMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WebCarrierMode {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "websocket" | "ws" => Ok(Self::Websocket),
            "ws-lanes" | "ws_lanes" | "websocket-lanes" => Ok(Self::WsLanes),
            "https" | "http" | "fetch" | "conveyor" => Ok(Self::Https),
            "https-lanes" | "https_lanes" | "h2" | "http2" => Ok(Self::HttpsLanes),
            "auto" => Ok(Self::Auto),
            _ => Err(TypeParseError::InvalidWebCarrierMode(s.to_owned())),
        }
    }
}

/// Persistence strategy for runtime Management API mutations (`[api] persistence`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiPersistenceMode {
    /// In-memory only (default — ideal when an external panel DB owns desired state).
    #[default]
    Memory,
    /// Crash-safe atomic `0600` JSON overlay (`state-file` + `flock` + `fsync` + `rename`)
    /// keeping `config.toml` clean/immutable while persisting API mutations across reboots!
    Overlay,
    /// Lossless `toml_edit` + `flock(2)` atomic writeback directly to `config.toml`
    /// (preserves operator comments & formatting on standalone single-file servers).
    Toml,
}

impl ApiPersistenceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Overlay => "overlay",
            Self::Toml => "toml",
        }
    }
}

impl fmt::Display for ApiPersistenceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApiPersistenceMode {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "memory" | "mem" | "none" => Ok(Self::Memory),
            "overlay" | "state-file" | "state_file" | "json" => Ok(Self::Overlay),
            "toml" | "config" | "file" => Ok(Self::Toml),
            _ => Err(TypeParseError::InvalidApiPersistenceMode(s.to_owned())),
        }
    }
}

/// Built-in CDN preset for `[web]` trusted proxy IP ranges and real client-IP header extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCdnPreset {
    Cloudflare,
    ArvanCloud,
}

impl WebCdnPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::ArvanCloud => "arvancloud",
        }
    }

    /// Default authoritative real-client-IP header stamped by this CDN.
    pub const fn default_client_ip_header(self) -> &'static str {
        match self {
            Self::Cloudflare => "cf-connecting-ip",
            Self::ArvanCloud => "ar-real-ip",
        }
    }

    /// Official auto-updating IP range feed URLs for this CDN.
    pub const fn ip_feed_urls(self) -> &'static [&'static str] {
        match self {
            Self::Cloudflare => &[
                "https://www.cloudflare.com/ips-v4",
                "https://www.cloudflare.com/ips-v6",
            ],
            Self::ArvanCloud => &["https://www.arvancloud.ir/en/ips.txt"],
        }
    }

    /// Built-in offline fallback CIDRs so cold boots before the first CDN feed fetch
    /// still recognize genuine CDN edge nodes immediately.
    pub const fn fallback_cidrs(self) -> &'static [&'static str] {
        match self {
            Self::Cloudflare => &[
                // Official Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4)
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "141.101.64.0/18",
                "108.162.192.0/18",
                "190.93.240.0/20",
                "188.114.96.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                "162.158.0.0/15",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/13",
                "131.0.72.0/22",
                // Official Cloudflare IPv6 ranges (https://www.cloudflare.com/ips-v6)
                "2400:cb00::/32",
                "2606:4700::/32",
                "2803:f800::/32",
                "2405:b500::/32",
                "2405:8100::/32",
                "2a06:98c0::/29",
                "2c0f:f248::/32",
            ],
            Self::ArvanCloud => &[],
        }
    }
}

impl fmt::Display for WebCdnPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WebCdnPreset {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cloudflare" | "cf" => Ok(Self::Cloudflare),
            "arvancloud" | "arvan" => Ok(Self::ArvanCloud),
            _ => Err(TypeParseError::InvalidWebCdnPreset(s.to_owned())),
        }
    }
}

/// Validate a single bare IP or CIDR string (e.g. `"5.160.0.0/16"`, `"2001:db8::/32"`, `"127.0.0.1"`).
pub fn validate_ip_or_cidr(raw: &str) -> Result<(), TypeParseError> {
    let token = raw.trim();
    if token.is_empty() {
        return Err(TypeParseError::InvalidCidr(raw.to_owned()));
    }
    if let Some((ip_str, bits_str)) = token.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| TypeParseError::InvalidCidr(raw.to_owned()))?;
        let bits: u8 = bits_str
            .parse()
            .map_err(|_| TypeParseError::InvalidCidr(raw.to_owned()))?;
        let max_bits = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max_bits {
            return Err(TypeParseError::InvalidCidr(raw.to_owned()));
        }
    } else {
        let _: IpAddr = token
            .parse()
            .map_err(|_| TypeParseError::InvalidCidr(raw.to_owned()))?;
    }
    Ok(())
}

/// Mode for `[defense.handshake-budget]`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeBudgetMode {
    #[default]
    Enforce,
    Observe,
    Off,
}

impl HandshakeBudgetMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
            Self::Off => "off",
        }
    }
}

impl FromStr for HandshakeBudgetMode {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "enforce" => Ok(Self::Enforce),
            "observe" => Ok(Self::Observe),
            "off" => Ok(Self::Off),
            _ => Err(TypeParseError::InvalidHandshakeBudgetMode(s.to_owned())),
        }
    }
}

/// StatsD tag dialect.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatsdTagFormat {
    #[default]
    Datadog,
    Influxdb,
    Graphite,
}

impl StatsdTagFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Datadog => "datadog",
            Self::Influxdb => "influxdb",
            Self::Graphite => "graphite",
        }
    }
}

impl FromStr for StatsdTagFormat {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "datadog" => Ok(Self::Datadog),
            "influxdb" => Ok(Self::Influxdb),
            "graphite" => Ok(Self::Graphite),
            _ => Err(TypeParseError::InvalidStatsdTagFormat(s.to_owned())),
        }
    }
}

/// Parse a Go-style duration string (e.g. `"5s"`, `"1m30s"`, `"24h"`, `"500ms"`, `"2d"`, `"0"`).
pub fn parse_duration(s: &str) -> Result<Duration, TypeParseError> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err(TypeParseError::InvalidDuration(s.to_owned()));
    }
    if raw == "0" {
        return Ok(Duration::ZERO);
    }

    let mut rest = raw;
    let mut total_ns: u128 = 0;

    while !rest.is_empty() {
        let num_end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(TypeParseError::InvalidDuration(s.to_owned()));
        }
        let num_str = &rest[..num_end];
        rest = &rest[num_end..];

        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];

        let mult_ns: f64 = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            "d" => 86_400.0 * 1_000_000_000.0,
            _ => return Err(TypeParseError::InvalidDuration(s.to_owned())),
        };

        let val: f64 = num_str
            .parse()
            .map_err(|_| TypeParseError::InvalidDuration(s.to_owned()))?;
        if !val.is_finite() || val < 0.0 {
            return Err(TypeParseError::InvalidDuration(s.to_owned()));
        }
        let part_ns = (val * mult_ns).round() as u128;
        total_ns = total_ns
            .checked_add(part_ns)
            .ok_or_else(|| TypeParseError::InvalidDuration(s.to_owned()))?;
    }

    let secs = (total_ns / 1_000_000_000) as u64;
    let nanos = (total_ns % 1_000_000_000) as u32;
    Ok(Duration::new(secs, nanos))
}

/// Format a [`Duration`] in Go's `time.Duration.String()` format.
pub fn format_duration_go(d: Duration) -> String {
    let total_ns = d.as_nanos();
    if total_ns == 0 {
        return "0s".to_owned();
    }
    if total_ns < 1_000 {
        return format!("{total_ns}ns");
    }
    if total_ns < 1_000_000 {
        let us = total_ns as f64 / 1_000.0;
        return format!("{us}µs");
    }
    if total_ns < 1_000_000_000 {
        let ms = total_ns as f64 / 1_000_000.0;
        return format!("{ms}ms");
    }
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    let sub_ns = d.subsec_nanos();

    let mut out = String::new();
    if hours > 0 {
        let _ = write!(out, "{hours}h{mins}m");
    } else if mins > 0 {
        let _ = write!(out, "{mins}m");
    }
    if sub_ns == 0 {
        let _ = write!(out, "{secs}s");
    } else {
        let frac = format!("{sub_ns:09}");
        let trimmed = frac.trim_end_matches('0');
        let _ = write!(out, "{secs}.{trimmed}s");
    }
    out
}

/// Format a byte count identically to Go's `strings.ToLower(units.Base2Bytes(v).String())`
/// (e.g. `1_073_741_824` -> `"1gib"`, `0` -> `"0b"`).
pub fn format_bytes_go(bytes: u64) -> String {
    const UNITS: &[(u64, &str)] = &[
        (1 << 60, "eib"),
        (1 << 50, "pib"),
        (1 << 40, "tib"),
        (1 << 30, "gib"),
        (1 << 20, "mib"),
        (1 << 10, "kib"),
        (1, "b"),
    ];
    if bytes == 0 {
        return "0b".to_owned();
    }
    let mut rem = bytes;
    let mut out = String::new();
    for &(size, suffix) in UNITS {
        if rem >= size {
            let count = rem / size;
            rem %= size;
            let _ = write!(out, "{count}{suffix}");
        }
    }
    out
}

/// Parse a byte size from a TOML string (`"10GB"`, `"500 MiB"`, `"16KiB"`, `"0B"`)
/// or bare integer (`1048576`).
pub fn parse_bytes_str(s: &str) -> Result<u64, TypeParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(TypeParseError::InvalidBytes(s.to_owned()));
    }
    let parsed =
        parse_quota_bytes(trimmed).map_err(|_| TypeParseError::InvalidBytes(s.to_owned()))?;
    u64::try_from(parsed).map_err(|_| TypeParseError::InvalidBytes(s.to_owned()))
}

/// Parse a 16-byte Telegram ad-tag from 32 hex characters (empty string -> `None`).
pub fn parse_ad_tag(s: &str) -> Result<Option<[u8; AD_TAG_LEN]>, TypeParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let raw = hex::decode(trimmed).map_err(|_| TypeParseError::InvalidAdTag)?;
    if raw.len() != AD_TAG_LEN {
        return Err(TypeParseError::InvalidAdTag);
    }
    let mut arr = [0u8; AD_TAG_LEN];
    arr.copy_from_slice(&raw);
    Ok(Some(arr))
}

/// Canonicalize a `[web] host` using UTS #46 IDNA rules (matching Go `webrelay.CanonicalHost`).
pub fn canonical_web_host(raw: &str) -> Result<String, TypeParseError> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.contains(':') || trimmed.contains('/') || trimmed.contains('@')
    {
        return Err(TypeParseError::InvalidHost(raw.to_owned()));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(TypeParseError::InvalidHost(raw.to_owned()));
    }
    let ascii = idna::domain_to_ascii_strict(trimmed)
        .map_err(|_| TypeParseError::InvalidHost(raw.to_owned()))?;
    if ascii.is_empty() || !ascii.contains('.') {
        return Err(TypeParseError::InvalidHost(raw.to_owned()));
    }
    Ok(ascii.to_ascii_lowercase())
}

/// Redact password from an upstream proxy URL (`socks5://user:pass@host` ->
/// `socks5://user:xxxxx@host`), matching Go's `url.URL.Redacted()`.
pub fn redact_proxy_url(raw: &str) -> String {
    // Parse scheme://userinfo@host
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "[redacted]".to_owned();
    };
    if scheme.is_empty() {
        return "[redacted]".to_owned();
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if let Some((userinfo, hostport)) = authority.rsplit_once('@')
        && let Some((user, _pass)) = userinfo.split_once(':')
    {
        return format!("{scheme}://{user}:xxxxx@{hostport}{tail}");
    }
    raw.to_owned()
}
