//! Upstream SOCKS5 (`socks5://`, `socks5h://`) & HTTP CONNECT proxy dialers,
//! lock-free atomic circuit breaker (zero timers / zero task leaks), and
//! Power-of-Two-Choices (P2C) EWMA latency load-balancing pool.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use mtg_config::redact_proxy_url;
use rand::Rng as _;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::sockopts::{SocketConfig, tune_tokio_stream};
use crate::timer::coarse_now_ns;

/// Default circuit breaker failure threshold before opening.
pub const DEFAULT_CB_OPEN_THRESHOLD: u32 = 5;
/// Default circuit breaker half-open recovery timeout.
pub const DEFAULT_CB_HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Default failure window after which consecutive failures reset lazily.
pub const DEFAULT_CB_RESET_WINDOW: Duration = Duration::from_secs(60);

/// Errors returned by upstream proxy dialing or circuit breaking.
#[derive(Debug, Error)]
pub enum ProxyDialError {
    #[error("invalid proxy URL {0}")]
    InvalidUrl(String),
    #[error("circuit breaker is open for {0}")]
    CircuitOpen(String),
    #[error("all upstream proxies failed: {0}")]
    AllFailed(String),
    #[error("SOCKS5 handshake failed: {0}")]
    Socks5(String),
    #[error("HTTP CONNECT failed: {0}")]
    HttpConnect(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Supported upstream proxy scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    /// SOCKS5 resolving target hostnames locally before sending IP to proxy.
    Socks5,
    /// SOCKS5h delegating hostname resolution to the proxy server (ATYP=0x03).
    Socks5h,
    /// HTTP CONNECT tunnel.
    Http,
}

/// Parsed upstream proxy endpoint (credentials kept internally, never logged).
#[derive(Clone)]
pub struct ProxyEndpoint {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub redacted: String,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("url", &self.redacted)
            .finish_non_exhaustive()
    }
}

impl ProxyEndpoint {
    /// Parse a `socks5://`, `socks5h://`, or `http://` URL (with optional `user:pass@`).
    pub fn parse(raw: &str) -> Result<Self, ProxyDialError> {
        let redacted = redact_proxy_url(raw);
        let (scheme, rest, default_port) = if let Some(r) = raw.strip_prefix("socks5://") {
            (ProxyScheme::Socks5, r, 1080u16)
        } else if let Some(r) = raw.strip_prefix("socks5h://") {
            (ProxyScheme::Socks5h, r, 1080u16)
        } else if let Some(r) = raw.strip_prefix("http://") {
            (ProxyScheme::Http, r, 8080u16)
        } else {
            return Err(ProxyDialError::InvalidUrl(redacted));
        };

        let authority = rest.split('/').next().unwrap_or("");
        let (auth, hostport) = match authority.rsplit_once('@') {
            Some((a, hp)) => (Some(a), hp),
            None => (None, authority),
        };

        let (username, password) = match auth {
            Some(a) => match a.split_once(':') {
                Some((u, p)) => (Some(u.to_owned()), Some(p.to_owned())),
                None => (Some(a.to_owned()), Some(String::new())),
            },
            None => (None, None),
        };

        let (host, port) = split_host_port_default(hostport, default_port)
            .ok_or_else(|| ProxyDialError::InvalidUrl(redacted.clone()))?;

        Ok(Self {
            scheme,
            host,
            port,
            username,
            password,
            redacted,
        })
    }

    pub fn dial_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn split_host_port_default(hp: &str, default_port: u16) -> Option<(String, u16)> {
    if hp.is_empty() {
        return None;
    }
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        if tail.is_empty() {
            return Some((h.to_owned(), default_port));
        }
        let p: u16 = tail.strip_prefix(':')?.parse().ok()?;
        if p == 0 {
            return None;
        }
        return Some((h.to_owned(), p));
    }
    if let Some((h, p_str)) = hp.rsplit_once(':')
        && !h.contains(':')
    {
        let p: u16 = p_str.parse().ok()?;
        if h.is_empty() || p == 0 {
            return None;
        }
        return Some((h.to_owned(), p));
    }
    Some((hp.to_owned(), default_port))
}

/// Lock-free atomic circuit breaker using coarse monotonic timestamps.
///
/// Zero mutexes, zero channels, zero background timers (fixes Go's
/// `circuitBreakerDialer` goroutine/timer leaks!).
///
/// State transitions:
/// - `Closed` -> `Open` when consecutive failures reach `open_threshold` within
///   `reset_window`.
/// - `Open` -> `HalfOpen` lazily once `half_open_timeout` elapses; exactly ONE
///   caller wins the CAS to probe.
/// - `HalfOpen` -> `Closed` on probe success, or `Open` on probe failure.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Packed state:
    /// - bits 0..2: `0 = Closed`, `1 = Open`, `2 = HalfOpenProbeInFlight`
    /// - bits 2..32: consecutive failure count (when Closed)
    /// - bits 32..64: coarse timestamp in milliseconds (`now_ms` truncated to u32)
    packed: AtomicU64,
    open_threshold: u32,
    half_open_ms: u32,
    reset_window_ms: u32,
}

const STATE_CLOSED: u64 = 0;
const STATE_OPEN: u64 = 1;
const STATE_HALF_OPEN: u64 = 2;
const STATE_MASK: u64 = 0b11;

impl CircuitBreaker {
    pub fn new(open_threshold: u32, half_open_timeout: Duration, reset_window: Duration) -> Self {
        Self {
            packed: AtomicU64::new(0),
            open_threshold: open_threshold.max(1),
            half_open_ms: half_open_timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u32,
            reset_window_ms: reset_window.as_millis().clamp(1, u128::from(u32::MAX)) as u32,
        }
    }

    #[inline]
    fn pack(state: u64, fails: u32, ts_ms: u32) -> u64 {
        (state & STATE_MASK) | ((u64::from(fails) & 0x3FFF_FFFF) << 2) | (u64::from(ts_ms) << 32)
    }

    #[inline]
    fn unpack(v: u64) -> (u64, u32, u32) {
        (
            v & STATE_MASK,
            ((v >> 2) & 0x3FFF_FFFF) as u32,
            (v >> 32) as u32,
        )
    }

    #[inline]
    fn now_ms() -> u32 {
        (coarse_now_ns() / 1_000_000) as u32
    }

    /// Check if a dial attempt is permitted now. Returns `Some(is_half_open_probe)`
    /// or `None` if the circuit is currently open.
    pub fn allow(&self) -> Option<bool> {
        self.allow_at(Self::now_ms())
    }

    pub fn allow_at(&self, now_ms: u32) -> Option<bool> {
        loop {
            let cur = self.packed.load(Ordering::Acquire);
            let (state, _fails, ts) = Self::unpack(cur);
            match state {
                STATE_CLOSED => return Some(false),
                STATE_OPEN => {
                    let elapsed = now_ms.wrapping_sub(ts);
                    if elapsed < self.half_open_ms {
                        return None;
                    }
                    let next = Self::pack(STATE_HALF_OPEN, 0, now_ms);
                    if self
                        .packed
                        .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Some(true);
                    }
                }
                STATE_HALF_OPEN => {
                    // If probe hung past half_open_ms, allow another probe.
                    let elapsed = now_ms.wrapping_sub(ts);
                    if elapsed < self.half_open_ms {
                        return None;
                    }
                    let next = Self::pack(STATE_HALF_OPEN, 0, now_ms);
                    if self
                        .packed
                        .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Some(true);
                    }
                }
                _ => return None,
            }
        }
    }

    /// Record a successful dial, closing the circuit and resetting failures.
    pub fn on_success(&self) {
        self.packed
            .store(Self::pack(STATE_CLOSED, 0, 0), Ordering::Release);
    }

    /// Record a failed dial attempt.
    pub fn on_failure(&self) {
        self.on_failure_at(Self::now_ms());
    }

    pub fn on_failure_at(&self, now_ms: u32) {
        loop {
            let cur = self.packed.load(Ordering::Acquire);
            let (state, fails, ts) = Self::unpack(cur);
            let next = match state {
                STATE_HALF_OPEN | STATE_OPEN => Self::pack(STATE_OPEN, 0, now_ms),
                _ => {
                    let eff_fails = if fails > 0 && now_ms.wrapping_sub(ts) >= self.reset_window_ms
                    {
                        1
                    } else {
                        fails.saturating_add(1)
                    };
                    if eff_fails >= self.open_threshold {
                        Self::pack(STATE_OPEN, 0, now_ms)
                    } else {
                        Self::pack(STATE_CLOSED, eff_fails, now_ms)
                    }
                }
            };
            if self
                .packed
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// True if currently open (for observability/tests).
    pub fn is_open(&self) -> bool {
        (self.packed.load(Ordering::Acquire) & STATE_MASK) == STATE_OPEN
    }
}

/// Target address for upstream proxy dialing (either resolved IP or hostname).
#[derive(Debug, Clone)]
pub enum ProxyTarget {
    SocketAddr(SocketAddr),
    Domain(String, u16),
}

impl ProxyTarget {
    pub fn host_port(&self) -> (String, u16) {
        match self {
            Self::SocketAddr(sa) => (sa.ip().to_string(), sa.port()),
            Self::Domain(h, p) => (h.clone(), *p),
        }
    }
}

/// One member of a [`ProxyPool`] carrying its lock-free breaker & EWMA RTT.
#[derive(Debug)]
struct ProxyMember {
    endpoint: ProxyEndpoint,
    breaker: CircuitBreaker,
    /// EWMA connect RTT in microseconds (starts at 50 ms neutral prior).
    ewma_rtt_us: AtomicU64,
}

impl ProxyMember {
    fn new(endpoint: ProxyEndpoint) -> Self {
        Self {
            endpoint,
            breaker: CircuitBreaker::new(
                DEFAULT_CB_OPEN_THRESHOLD,
                DEFAULT_CB_HALF_OPEN_TIMEOUT,
                DEFAULT_CB_RESET_WINDOW,
            ),
            ewma_rtt_us: AtomicU64::new(50_000),
        }
    }

    fn record_rtt_us(&self, sample_us: u64) {
        // EWMA alpha = 0.25 -> new = (3 * old + sample) / 4
        let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
        let next = (prev.saturating_mul(3).saturating_add(sample_us)) >> 2;
        self.ewma_rtt_us.store(next.max(1), Ordering::Relaxed);
    }
}

/// Power-of-Two-Choices (P2C) load-balanced pool of upstream SOCKS5/HTTP proxies.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    members: Arc<Vec<ProxyMember>>,
    sock_cfg: SocketConfig,
    timeout: Duration,
}

impl ProxyPool {
    /// Build a [`ProxyPool`] from raw proxy URL strings.
    pub fn from_urls(
        urls: &[String],
        sock_cfg: SocketConfig,
        timeout: Duration,
    ) -> Result<Self, ProxyDialError> {
        let mut members = Vec::with_capacity(urls.len());
        for raw in urls {
            let ep = ProxyEndpoint::parse(raw)?;
            members.push(ProxyMember::new(ep));
        }
        Ok(Self {
            members: Arc::new(members),
            sock_cfg,
            timeout,
        })
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Dial `target` through the best healthy upstream proxy using P2C EWMA RTT
    /// selection, failing over cleanly across remaining healthy proxies.
    pub async fn dial(&self, target: &ProxyTarget) -> Result<TcpStream, ProxyDialError> {
        self.dial_with_bound_addr(target).await.map(|(s, _)| s)
    }

    /// Dial `target` through the best healthy upstream proxy and also return the
    /// SOCKS5 server-reported `BND.ADDR:BND.PORT` (when IPv4/IPv6 non-unspecified),
    /// enabling exact Telegram MiddleProxy KDF derivation through SOCKS5 chains!
    pub async fn dial_with_bound_addr(
        &self,
        target: &ProxyTarget,
    ) -> Result<(TcpStream, Option<SocketAddr>), ProxyDialError> {
        let n = self.members.len();
        if n == 0 {
            return Err(ProxyDialError::AllFailed(
                "no upstream proxies configured".to_owned(),
            ));
        }

        // Order candidates: pick best of 2 random via P2C first, then remaining in round-robin.
        let mut order: Vec<usize> = (0..n).collect();
        if n >= 2 {
            let mut rng = rand::rng();
            let a = rng.random_range(0..n);
            let mut b = rng.random_range(0..n - 1);
            if b >= a {
                b += 1;
            }
            let best = if self.members[a].ewma_rtt_us.load(Ordering::Relaxed)
                <= self.members[b].ewma_rtt_us.load(Ordering::Relaxed)
            {
                a
            } else {
                b
            };
            order.swap(0, best);
        }

        let mut last_err = String::new();
        for idx in order {
            let member = &self.members[idx];
            if member.breaker.allow().is_none() {
                last_err = format!("circuit open for {}", member.endpoint.redacted);
                continue;
            }
            let started = coarse_now_ns();
            match tokio::time::timeout(
                self.timeout,
                dial_via_endpoint_with_bound_addr(&member.endpoint, target, &self.sock_cfg),
            )
            .await
            {
                Ok(Ok((stream, bound_addr))) => {
                    let rtt_us = coarse_now_ns().saturating_sub(started) / 1_000;
                    member.record_rtt_us(rtt_us.max(1));
                    member.breaker.on_success();
                    debug!(proxy = %member.endpoint.redacted, rtt_us, ?bound_addr, "dialed via upstream proxy");
                    return Ok((stream, bound_addr));
                }
                Ok(Err(e)) => {
                    member.breaker.on_failure();
                    warn!(proxy = %member.endpoint.redacted, error = %e, "upstream proxy dial failed");
                    last_err = e.to_string();
                }
                Err(_) => {
                    member.breaker.on_failure();
                    warn!(proxy = %member.endpoint.redacted, "upstream proxy dial timed out");
                    last_err = format!("timeout dialing {}", member.endpoint.redacted);
                }
            }
        }

        Err(ProxyDialError::AllFailed(last_err))
    }
}

/// Dial `target` directly via a single [`ProxyEndpoint`], applying unified
/// Linux [`SocketConfig`] tuning to the underlying TCP socket.
pub async fn dial_via_endpoint(
    ep: &ProxyEndpoint,
    target: &ProxyTarget,
    sock_cfg: &SocketConfig,
) -> Result<TcpStream, ProxyDialError> {
    dial_via_endpoint_with_bound_addr(ep, target, sock_cfg)
        .await
        .map(|(s, _)| s)
}

/// Dial `target` via a single [`ProxyEndpoint`], also returning the SOCKS5
/// server-reported `BND.ADDR:BND.PORT` when available.
pub async fn dial_via_endpoint_with_bound_addr(
    ep: &ProxyEndpoint,
    target: &ProxyTarget,
    sock_cfg: &SocketConfig,
) -> Result<(TcpStream, Option<SocketAddr>), ProxyDialError> {
    let mut stream = TcpStream::connect(ep.dial_addr()).await?;
    let _ = tune_tokio_stream(&stream, sock_cfg);

    let bound = match ep.scheme {
        ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
            socks5_handshake(&mut stream, ep, target).await?
        }
        ProxyScheme::Http => {
            http_connect_handshake(&mut stream, ep, target).await?;
            None
        }
    };
    Ok((stream, bound))
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    ep: &ProxyEndpoint,
    target: &ProxyTarget,
) -> Result<Option<SocketAddr>, ProxyDialError> {
    // 1. Greeting: VER=5, methods = [NOAUTH] or [NOAUTH, USERPASS]
    let has_auth = ep.username.is_some();
    if has_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut greeting_reply = [0u8; 2];
    stream.read_exact(&mut greeting_reply).await?;
    if greeting_reply[0] != 0x05 {
        return Err(ProxyDialError::Socks5(format!(
            "unexpected version {}",
            greeting_reply[0]
        )));
    }
    match greeting_reply[1] {
        0x00 => {}
        0x02 => {
            let user = ep.username.as_deref().unwrap_or("");
            let pass = ep.password.as_deref().unwrap_or("");
            if user.len() > 255 || pass.len() > 255 {
                return Err(ProxyDialError::Socks5(
                    "credentials exceed 255 bytes".to_owned(),
                ));
            }
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // RFC 1929 subnegotiation version
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await?;
            if auth_reply[1] != 0x00 {
                return Err(ProxyDialError::Socks5("authentication rejected".to_owned()));
            }
        }
        other => {
            return Err(ProxyDialError::Socks5(format!(
                "unsupported auth method 0x{other:02x}"
            )));
        }
    }

    // 2. CONNECT request
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER=5, CMD=CONNECT, RSV=0
    match target {
        ProxyTarget::SocketAddr(sa) => match sa.ip() {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
                req.extend_from_slice(&sa.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
                req.extend_from_slice(&sa.port().to_be_bytes());
            }
        },
        ProxyTarget::Domain(host, port) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
            } else {
                if host.len() > 255 {
                    return Err(ProxyDialError::Socks5(
                        "domain name exceeds 255 bytes".to_owned(),
                    ));
                }
                req.push(0x03);
                req.push(host.len() as u8);
                req.extend_from_slice(host.as_bytes());
            }
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&req).await?;

    // 3. CONNECT reply
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(ProxyDialError::Socks5("bad reply version".to_owned()));
    }
    if hdr[1] != 0x00 {
        return Err(ProxyDialError::Socks5(format!(
            "connect error code 0x{:02x}",
            hdr[1]
        )));
    }
    // Parse BND.ADDR + BND.PORT (used by MiddleProxy KDF when chaining via SOCKS5!).
    let bound_addr = match hdr[3] {
        0x01 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw).await?;
            let ip = std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            (!ip.is_unspecified() && port != 0).then(|| SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut raw = [0u8; 18];
            stream.read_exact(&mut raw).await?;
            let ip_bytes: [u8; 16] = raw[..16].try_into().expect("16 bytes");
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            (!ip.is_unspecified() && port != 0).then(|| SocketAddr::new(IpAddr::V6(ip), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut skip).await?;
            None
        }
        atyp => {
            return Err(ProxyDialError::Socks5(format!(
                "unknown address type 0x{atyp:02x}"
            )));
        }
    };
    Ok(bound_addr)
}

async fn http_connect_handshake(
    stream: &mut TcpStream,
    ep: &ProxyEndpoint,
    target: &ProxyTarget,
) -> Result<(), ProxyDialError> {
    let (host, port) = target.host_port();
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(user) = &ep.username {
        let pass = ep.password.as_deref().unwrap_or("");
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&cred);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        return Err(ProxyDialError::HttpConnect(format!(
            "HTTP status {}: {}",
            code,
            status_line.trim()
        )));
    }
    // Drain headers up to empty CRLF line (bounded to 64 headers).
    for _ in 0..64 {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            return Ok(());
        }
    }
    Err(ProxyDialError::HttpConnect(
        "response header count exceeded limit".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_transitions_without_timers() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(10), Duration::from_secs(60));
        assert!(cb.allow_at(1000).is_some());

        cb.on_failure_at(1000);
        cb.on_failure_at(2000);
        assert!(!cb.is_open());

        cb.on_failure_at(3000);
        assert!(cb.is_open());
        assert!(cb.allow_at(5000).is_none());

        // After 10s half-open timeout, exactly ONE caller gets the probe slot.
        assert_eq!(cb.allow_at(13_000), Some(true));
        assert!(cb.allow_at(13_001).is_none());

        // Probe succeeds -> closes circuit.
        cb.on_success();
        assert!(!cb.is_open());
        assert_eq!(cb.allow_at(13_002), Some(false));
    }

    #[test]
    fn proxy_endpoint_parses_and_redacts_credentials() {
        let ep = ProxyEndpoint::parse("socks5h://alice:supersecret@10.0.0.1:1080").unwrap();
        assert_eq!(ep.scheme, ProxyScheme::Socks5h);
        assert_eq!(ep.host, "10.0.0.1");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.username.as_deref(), Some("alice"));
        assert!(!ep.redacted.contains("supersecret"));
        assert!(!format!("{ep:?}").contains("supersecret"));
    }
}
