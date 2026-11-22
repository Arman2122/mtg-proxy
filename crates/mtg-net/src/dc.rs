//! Telegram Data Center directory, unified hourly `getProxySecret` /
//! `getProxyConfig` / `getProxyConfigV6` fetcher, active `dcprobe` health +
//! EWMA RTT scoring, and RFC 8305 Happy Eyeballs dialer.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::BodyExt as _;
use hyper::Request;
use hyper_util::rt::TokioIo;
use mtg_config::PreferIp;
use mtg_core::ConnectionTag;
use mtg_crypto::obfs2::build_outbound_handshake;
use mtg_protocol::dcprobe::{
    build_req_pq_multi_frame_now, validate_res_pq_len, verify_res_pq_payload,
};
use rustc_hash::FxHashMap;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::dns::DnsResolver;
use crate::outbound::{OutboundRouter, OutboundStream, OutboundTarget};
use crate::proxy_pool::{ProxyPool, ProxyTarget};
use crate::sockopts::{SocketConfig, tune_tokio_stream};
use crate::timer::coarse_now_ns;

/// Default Telegram DC when an unknown DC is requested with fallback enabled.
pub const DEFAULT_DC: i32 = 2;

/// Official Telegram proxy config endpoints.
pub const TELEGRAM_PROXY_SECRET_URL: &str = "https://core.telegram.org/getProxySecret";
pub const TELEGRAM_PROXY_CONFIG_V4_URL: &str = "https://core.telegram.org/getProxyConfig";
pub const TELEGRAM_PROXY_CONFIG_V6_URL: &str = "https://core.telegram.org/getProxyConfigV6";

/// Default refresh cadence (1 hour) and failure retry cadence (1 minute).
pub const REFRESH_PERIOD: Duration = Duration::from_secs(3600);
pub const RETRY_PERIOD: Duration = Duration::from_secs(60);
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum wait for the very first background fetch during startup.
pub const FIRST_FETCH_GRACE: Duration = Duration::from_secs(2);
/// RFC 8305 Happy Eyeballs stagger between preferred and fallback address families.
pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Built-in Telegram core DC addresses (matches `essentials/addresses.go` & TDLib).
pub fn default_core_addresses() -> (
    BTreeMap<i32, Vec<SocketAddr>>,
    BTreeMap<i32, Vec<SocketAddr>>,
) {
    let mut v4: BTreeMap<i32, Vec<SocketAddr>> = BTreeMap::new();
    let mut v6: BTreeMap<i32, Vec<SocketAddr>> = BTreeMap::new();

    let entries: &[(i32, &[&str])] = &[
        (1, &["149.154.175.50:443", "[2001:b28:f23d:f001::a]:443"]),
        (
            2,
            &[
                "149.154.167.51:443",
                "95.161.76.100:443",
                "[2001:67c:04e8:f002::a]:443",
            ],
        ),
        (3, &["149.154.175.100:443", "[2001:b28:f23d:f003::a]:443"]),
        (4, &["149.154.167.91:443", "[2001:67c:04e8:f004::a]:443"]),
        (5, &["149.154.171.5:443", "[2001:b28:f23f:f005::a]:443"]),
        (
            203,
            &[
                "91.105.192.100:443",
                "[2a0a:f280:0203:000a:5000:0000:0000:0100]:443",
            ],
        ),
    ];

    for &(dc, addrs) in entries {
        for &raw in addrs {
            let sa: SocketAddr = raw.parse().expect("valid builtin Telegram DC addr");
            match sa {
                SocketAddr::V4(_) => v4.entry(dc).or_default().push(sa),
                SocketAddr::V6(_) => v6.entry(dc).or_default().push(sa),
            }
        }
    }
    (v4, v6)
}

/// Parse Telegram's `getProxyConfig` / `getProxyConfigV6` text format:
/// `proxy_for <signed_dc> <ip:port>;`
pub fn parse_proxy_config(data: &[u8]) -> BTreeMap<i32, Vec<SocketAddr>> {
    let text = String::from_utf8_lossy(data);
    let mut out: BTreeMap<i32, Vec<SocketAddr>> = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("proxy_for") {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(_kw) = fields.next() else {
            continue;
        };
        let Some(dc_str) = fields.next() else {
            continue;
        };
        let Some(addr_raw) = fields.next() else {
            continue;
        };
        let Ok(dc) = dc_str.parse::<i32>() else {
            continue;
        };
        let addr_clean = addr_raw.trim_end_matches(';');
        if let Ok(sa) = addr_clean.parse::<SocketAddr>() {
            out.entry(dc).or_default().push(sa);
        }
    }
    out
}

/// Immutable atomic snapshot of Telegram direct DC + MiddleProxy endpoints.
#[derive(Debug, Clone)]
pub struct DcDirectory {
    /// Core direct DC IPv4 addresses (built-in + refreshed DC 203 CDN).
    pub direct_v4: BTreeMap<i32, Vec<SocketAddr>>,
    /// Core direct DC IPv6 addresses.
    pub direct_v6: BTreeMap<i32, Vec<SocketAddr>>,
    /// MiddleProxy RPC IPv4 addresses (signed DC keys `+N` and `-N`).
    pub middle_v4: BTreeMap<i32, Vec<SocketAddr>>,
    /// MiddleProxy RPC IPv6 addresses.
    pub middle_v6: BTreeMap<i32, Vec<SocketAddr>>,
    /// Telegram proxy secret bytes fetched from `getProxySecret` (empty if unfetched).
    pub proxy_secret: Option<Arc<Zeroizing<Vec<u8>>>>,
}

impl Default for DcDirectory {
    fn default() -> Self {
        let (direct_v4, direct_v6) = default_core_addresses();
        Self {
            direct_v4,
            direct_v6,
            middle_v4: BTreeMap::new(),
            middle_v6: BTreeMap::new(),
            proxy_secret: None,
        }
    }
}

impl DcDirectory {
    /// True if MiddleProxy `proxy_secret` and at least one middle endpoint are loaded.
    pub fn middle_ready(&self) -> bool {
        self.proxy_secret.as_ref().is_some_and(|s| !s.is_empty())
            && (!self.middle_v4.is_empty() || !self.middle_v6.is_empty())
    }

    /// Return ordered direct DC addresses honoring `prefer_ip` and optional
    /// fallback to [`DEFAULT_DC`] on unknown DC IDs, along with the effective DC
    /// ID actually selected (`DEFAULT_DC` if fallback triggered, else `dc.abs()`).
    pub fn direct_addresses_with_dc(
        &self,
        dc: i32,
        prefer_ip: PreferIp,
        allow_fallback: bool,
    ) -> (Vec<SocketAddr>, i32) {
        let abs_dc = dc.abs();
        let lookup = |d: i32| -> (Vec<SocketAddr>, Vec<SocketAddr>) {
            (
                self.direct_v4.get(&d).cloned().unwrap_or_default(),
                self.direct_v6.get(&d).cloned().unwrap_or_default(),
            )
        };
        let (mut v4, mut v6) = lookup(abs_dc);
        let mut effective_dc = abs_dc;
        if v4.is_empty() && v6.is_empty() && allow_fallback && abs_dc != DEFAULT_DC {
            (v4, v6) = lookup(DEFAULT_DC);
            effective_dc = DEFAULT_DC;
        }
        (order_by_prefer_ip(v4, v6, prefer_ip), effective_dc)
    }

    /// Return ordered direct DC addresses honoring `prefer_ip` and optional
    /// fallback to [`DEFAULT_DC`] on unknown DC IDs.
    pub fn direct_addresses(
        &self,
        dc: i32,
        prefer_ip: PreferIp,
        allow_fallback: bool,
    ) -> Vec<SocketAddr> {
        self.direct_addresses_with_dc(dc, prefer_ip, allow_fallback)
            .0
    }

    /// Return ordered MiddleProxy addresses for `abs(dc)`, collecting both `+dc`
    /// and `-dc` entries per Telegram's `getProxyConfig` format.
    pub fn middle_addresses(&self, dc: i32, prefer_ip: PreferIp) -> Vec<SocketAddr> {
        let abs_dc = dc.abs();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for key in [abs_dc, -abs_dc] {
            if let Some(list) = self.middle_v4.get(&key) {
                v4.extend_from_slice(list);
            }
            if let Some(list) = self.middle_v6.get(&key) {
                v6.extend_from_slice(list);
            }
        }
        order_by_prefer_ip(v4, v6, prefer_ip)
    }
}

fn order_by_prefer_ip(
    v4: Vec<SocketAddr>,
    v6: Vec<SocketAddr>,
    prefer: PreferIp,
) -> Vec<SocketAddr> {
    match prefer {
        PreferIp::OnlyIpv4 => v4,
        PreferIp::OnlyIpv6 => v6,
        PreferIp::PreferIpv4 => {
            let mut out = v4;
            out.extend(v6);
            out
        }
        PreferIp::PreferIpv6 => {
            let mut out = v6;
            out.extend(v4);
            out
        }
    }
}

/// Per-endpoint health & EWMA RTT metrics (updated by active `dcprobe` & real dials).
#[derive(Debug)]
struct EndpointHealth {
    /// EWMA RTT in microseconds (default 100 ms neutral prior).
    ewma_rtt_us: AtomicU64,
    /// Consecutive failures (penalizes selection).
    failures: AtomicU64,
    /// Last probe status (`1 = ok`, `0 = unknown`, `-1 = failed`).
    status: AtomicI64,
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self {
            ewma_rtt_us: AtomicU64::new(100_000),
            failures: AtomicU64::new(0),
            status: AtomicI64::new(0),
        }
    }
}

/// Lock-free DC directory + health-scored Happy Eyeballs dialer.
#[derive(Debug)]
pub struct DcRouter {
    dir: Arc<ArcSwap<DcDirectory>>,
    health: parking_lot::RwLock<FxHashMap<SocketAddr, Arc<EndpointHealth>>>,
    prefer_ip: PreferIp,
    allow_fallback: bool,
    sock_cfg: SocketConfig,
    dial_timeout: Duration,
    proxy_pool: Option<ProxyPool>,
    dns: Option<Arc<DnsResolver>>,
    /// Override URLs (defaults to official `core.telegram.org` endpoints; overridable in tests).
    secret_url: String,
    config_v4_url: String,
    config_v6_url: String,
    first_fetch_done: Arc<tokio::sync::Notify>,
    first_fetch_finished: Arc<std::sync::atomic::AtomicBool>,
    /// Optional pluggable multi-protocol outbound traffic router (`[[outbound]]` / `[routing]`).
    outbound_router: ArcSwap<Option<Arc<OutboundRouter>>>,
    /// Monotonically incremented whenever Telegram `proxy_secret` or MiddleProxy
    /// endpoint lists change so [`MiddleProxyPool`] can gracefully rotate carriers!
    middle_generation: AtomicU64,
}

impl DcRouter {
    pub fn new(
        prefer_ip: PreferIp,
        allow_fallback: bool,
        sock_cfg: SocketConfig,
        dial_timeout: Duration,
        proxy_pool: Option<ProxyPool>,
    ) -> Self {
        Self {
            dir: Arc::new(ArcSwap::from_pointee(DcDirectory::default())),
            health: parking_lot::RwLock::new(FxHashMap::default()),
            prefer_ip,
            allow_fallback,
            sock_cfg,
            dial_timeout,
            proxy_pool,
            dns: None,
            secret_url: TELEGRAM_PROXY_SECRET_URL.to_owned(),
            config_v4_url: TELEGRAM_PROXY_CONFIG_V4_URL.to_owned(),
            config_v6_url: TELEGRAM_PROXY_CONFIG_V6_URL.to_owned(),
            first_fetch_done: Arc::new(tokio::sync::Notify::new()),
            first_fetch_finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            outbound_router: ArcSwap::from_pointee(None),
            middle_generation: AtomicU64::new(1),
        }
    }

    /// Attach a hot-reloadable multi-protocol [`OutboundRouter`].
    pub fn with_outbound_router(self, router: Arc<OutboundRouter>) -> Self {
        self.outbound_router.store(Arc::new(Some(router)));
        self
    }

    /// Atomically swap the active [`OutboundRouter`] (hot reload / `PUT /outbounds`).
    pub fn set_outbound_router(&self, router: Arc<OutboundRouter>) {
        self.outbound_router.store(Arc::new(Some(router)));
    }

    /// Snapshot the active [`OutboundRouter`], if installed.
    pub fn outbound_router(&self) -> Option<Arc<OutboundRouter>> {
        self.outbound_router.load().as_ref().clone()
    }

    /// Attach a configured [`DnsResolver`] (DoH/DoT/custom DNS + `PreferIp`) so
    /// `getProxySecret` / `getProxyConfig` fetches obey operator DNS settings
    /// even on censored or IPv4-only networks.
    pub fn with_dns(mut self, dns: Arc<DnsResolver>) -> Self {
        self.dns = Some(dns);
        self
    }

    /// Override Telegram fetch URLs (for deterministic offline tests).
    pub fn with_urls(mut self, secret: String, v4: String, v6: String) -> Self {
        self.secret_url = secret;
        self.config_v4_url = v4;
        self.config_v6_url = v6;
        self
    }

    /// Wait-free snapshot of the current [`DcDirectory`].
    #[inline]
    pub fn directory(&self) -> arc_swap::Guard<Arc<DcDirectory>> {
        self.dir.load()
    }

    /// Monotonic generation bumped whenever Telegram `proxy_secret` or middle endpoints change.
    #[inline]
    pub fn middle_generation(&self) -> u64 {
        self.middle_generation.load(Ordering::Acquire)
    }

    /// Manually publish a directory snapshot (useful in tests/mock networks).
    pub fn set_directory(&self, dir: DcDirectory) {
        self.dir.store(Arc::new(dir));
        self.middle_generation.fetch_add(1, Ordering::Release);
        self.first_fetch_finished.store(true, Ordering::Release);
        self.first_fetch_done.notify_waiters();
    }

    /// Wait up to `FIRST_FETCH_GRACE` if the initial startup fetch is still in flight.
    pub async fn wait_initial_ready(&self, grace: Duration) -> bool {
        if self.dir.load().middle_ready() {
            return true;
        }
        if self.first_fetch_finished.load(Ordering::Acquire) {
            return self.dir.load().middle_ready();
        }
        let _ = tokio::time::timeout(grace, self.first_fetch_done.notified()).await;
        self.dir.load().middle_ready()
    }

    /// Perform ONE unified concurrent fetch of `getProxySecret`, `getProxyConfig`,
    /// and `getProxyConfigV6`, atomically swapping into `DcDirectory` while
    /// preserving last-known-good state on failure!
    pub async fn refresh_once(&self) -> io::Result<()> {
        let dns_ref = self.dns.as_deref();
        let (sec_res, v4_res, v6_res) = tokio::join!(
            fetch_url_bytes_with_dns(
                &self.secret_url,
                dns_ref,
                self.prefer_ip,
                self.proxy_pool.as_ref(),
                self.sock_cfg,
                FETCH_TIMEOUT
            ),
            fetch_url_bytes_with_dns(
                &self.config_v4_url,
                dns_ref,
                self.prefer_ip,
                self.proxy_pool.as_ref(),
                self.sock_cfg,
                FETCH_TIMEOUT
            ),
            fetch_url_bytes_with_dns(
                &self.config_v6_url,
                dns_ref,
                self.prefer_ip,
                self.proxy_pool.as_ref(),
                self.sock_cfg,
                FETCH_TIMEOUT
            ),
        );

        let current = self.dir.load();
        let mut next = (**current).clone();

        let mut any_ok = false;
        if let Ok(sec) = sec_res
            && !sec.is_empty()
        {
            next.proxy_secret = Some(Arc::new(Zeroizing::new(sec)));
            any_ok = true;
        }
        if let Ok(body_v4) = v4_res {
            let parsed = parse_proxy_config(&body_v4);
            if !parsed.is_empty() {
                if let Some(cdn) = parsed.get(&203)
                    && !cdn.is_empty()
                {
                    next.direct_v4.insert(203, cdn.clone());
                }
                next.middle_v4 = parsed;
                any_ok = true;
            }
        }
        if let Ok(body_v6) = v6_res {
            let parsed = parse_proxy_config(&body_v6);
            if !parsed.is_empty() {
                if let Some(cdn) = parsed.get(&203)
                    && !cdn.is_empty()
                {
                    next.direct_v6.insert(203, cdn.clone());
                }
                next.middle_v6 = parsed;
                any_ok = true;
            }
        }

        if any_ok {
            let secret_changed = current.proxy_secret.as_deref().map(|z| z.as_slice())
                != next.proxy_secret.as_deref().map(|z| z.as_slice());
            let endpoints_changed =
                current.middle_v4 != next.middle_v4 || current.middle_v6 != next.middle_v6;
            info!(
                v4_dcs = next.middle_v4.len(),
                v6_dcs = next.middle_v6.len(),
                has_secret = next.proxy_secret.is_some(),
                rotated = secret_changed || endpoints_changed,
                "Telegram DC & middle-proxy config refreshed"
            );
            self.dir.store(Arc::new(next));
            if secret_changed || endpoints_changed {
                self.middle_generation.fetch_add(1, Ordering::Release);
            }
        }

        self.first_fetch_finished.store(true, Ordering::Release);
        self.first_fetch_done.notify_waiters();

        if any_ok {
            Ok(())
        } else {
            Err(io::Error::other("all Telegram config endpoints failed"))
        }
    }

    /// Spawn the unified hourly background refresh loop (retrying every 60s
    /// until first success, then every 1h; stops cleanly when `shutdown` fires).
    pub fn spawn_refresh_loop(self: &Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let router = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if let Err(e) = router.refresh_once().await {
                    warn!(error = %e, "Telegram config refresh failed; retaining last-known-good");
                }
                let wait = if router.dir.load().middle_ready() {
                    REFRESH_PERIOD
                } else {
                    RETRY_PERIOD
                };
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                }
            }
        });
    }

    /// Score-sorted candidate direct addresses for `dc` along with the effective
    /// DC ID (`DEFAULT_DC` if unknown-DC fallback triggered).
    pub fn ranked_direct_addresses_with_dc(&self, dc: i32) -> (Vec<SocketAddr>, i32) {
        let dir = self.dir.load();
        let (mut addrs, effective_dc) =
            dir.direct_addresses_with_dc(dc, self.prefer_ip, self.allow_fallback);
        self.sort_by_health(&mut addrs);
        (addrs, effective_dc)
    }

    /// Score-sorted candidate direct addresses for `dc`.
    pub fn ranked_direct_addresses(&self, dc: i32) -> Vec<SocketAddr> {
        self.ranked_direct_addresses_with_dc(dc).0
    }

    /// Score-sorted candidate MiddleProxy addresses for `dc`.
    pub fn ranked_middle_addresses(&self, dc: i32) -> Vec<SocketAddr> {
        let dir = self.dir.load();
        let mut addrs = dir.middle_addresses(dc, self.prefer_ip);
        self.sort_by_health(&mut addrs);
        addrs
    }

    fn sort_by_health(&self, addrs: &mut [SocketAddr]) {
        if addrs.len() <= 1 {
            return;
        }
        let map = self.health.read();
        let score = |sa: &SocketAddr| -> (u64, u64) {
            if let Some(h) = map.get(sa) {
                (
                    h.failures.load(Ordering::Relaxed),
                    h.ewma_rtt_us.load(Ordering::Relaxed),
                )
            } else {
                (0, 100_000)
            }
        };
        // Stable sort preserves IPv4/IPv6 family preference order on ties!
        addrs.sort_by_key(score);
    }

    fn health_of(&self, sa: SocketAddr) -> Arc<EndpointHealth> {
        if let Some(h) = self.health.read().get(&sa) {
            return Arc::clone(h);
        }
        let mut w = self.health.write();
        Arc::clone(w.entry(sa).or_default())
    }

    pub fn record_success(&self, sa: SocketAddr, rtt_us: u64) {
        let h = self.health_of(sa);
        h.failures.store(0, Ordering::Relaxed);
        let prev = h.ewma_rtt_us.load(Ordering::Relaxed);
        let next = (prev.saturating_mul(3).saturating_add(rtt_us.max(1))) >> 2;
        h.ewma_rtt_us.store(next.max(1), Ordering::Relaxed);
        h.status.store(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self, sa: SocketAddr) {
        let h = self.health_of(sa);
        h.failures.fetch_add(1, Ordering::Relaxed);
        h.status.store(-1, Ordering::Relaxed);
    }

    /// Dial a direct Telegram DC using RFC 8305 Happy Eyeballs (`250 ms` stagger
    /// between primary and secondary address families when dual-stack, with
    /// immediate failover when the primary family returns a fast error such as
    /// `ENETUNREACH` on IPv4-only Linux VPSs), falling back through upstream
    /// [`ProxyPool`] if configured.
    ///
    /// Returns `(stream, remote_addr, effective_dc)` where `effective_dc` is
    /// [`DEFAULT_DC`] if unknown-DC fallback triggered.
    pub async fn dial_direct(&self, dc: i32) -> io::Result<(TcpStream, SocketAddr, i32)> {
        let (addrs, effective_dc) = self.ranked_direct_addresses_with_dc(dc);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no addresses configured for DC {dc}"),
            ));
        }

        // If upstream proxies are configured, delegate through the P2C proxy pool.
        if let Some(pool) = &self.proxy_pool
            && !pool.is_empty()
        {
            let mut last_err = None;
            for sa in addrs {
                let started = coarse_now_ns();
                match pool.dial(&ProxyTarget::SocketAddr(sa)).await {
                    Ok(s) => {
                        self.record_success(sa, coarse_now_ns().saturating_sub(started) / 1_000);
                        return Ok((s, sa, effective_dc));
                    }
                    Err(e) => {
                        self.record_failure(sa);
                        last_err = Some(io::Error::other(e.to_string()));
                    }
                }
            }
            return Err(last_err.unwrap_or_else(|| io::Error::other("upstream proxy dial failed")));
        }

        let (stream, addr) = self.happy_eyeballs_dial(&addrs).await?;
        Ok((stream, addr, effective_dc))
    }

    /// Policy-routed direct DC dial supporting ANY configured [`OutboundTransport`]
    /// (`direct://` + `SO_BINDTODEVICE`/`SO_MARK`, `socks5://`, `socks4://`, `http://`,
    /// `https://`, Shadowsocks `ss://` AEAD-2022/classic, `unix://` sidecars for
    /// Xray/sing-box/VLESS/Hysteria2, and per-secret/per-DC routing rules!).
    ///
    /// Fast path: when no custom outbound or per-secret route applies, delegates
    /// straight to Happy Eyeballs direct TCP (`OutboundStream::Tcp`, zero overhead!).
    pub async fn dial_direct_routed(
        &self,
        dc: i32,
        secret_outbound: Option<&str>,
    ) -> io::Result<(OutboundStream, SocketAddr, i32)> {
        let router_guard = self.outbound_router.load();
        if let Some(router) = router_guard.as_ref()
            && (secret_outbound.is_some() || !router.is_plain_direct_only())
        {
            let (addrs, effective_dc) = self.ranked_direct_addresses_with_dc(dc);
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no addresses configured for DC {dc}"),
                ));
            }
            let route = router.resolve_route(secret_outbound, Some(effective_dc));
            if route == crate::outbound::DEFAULT_DIRECT_OUTBOUND && router.is_plain_direct_only() {
                let (stream, addr) = self.happy_eyeballs_dial(&addrs).await?;
                return Ok((OutboundStream::from_tcp(stream), addr, effective_dc));
            }
            let mut last_err = None;
            for sa in addrs {
                match router
                    .dial_named(
                        route,
                        &OutboundTarget::Addr(sa),
                        Some(effective_dc),
                        self.dial_timeout,
                    )
                    .await
                {
                    Ok(res) => {
                        self.record_success(sa, res.rtt_us);
                        return Ok((res.stream, sa, effective_dc));
                    }
                    Err(e) => {
                        self.record_failure(sa);
                        last_err = Some(io::Error::other(e.to_string()));
                    }
                }
            }
            return Err(last_err.unwrap_or_else(|| io::Error::other("routed outbound dial failed")));
        }

        let (stream, addr, effective_dc) = self.dial_direct(dc).await?;
        Ok((OutboundStream::from_tcp(stream), addr, effective_dc))
    }

    /// Perform an active MTProto `req_pq_multi` -> `resPQ` probe over an
    /// obfuscated2 padded-intermediate stream against `addr` (used by
    /// `mtg-proxy doctor` and periodic DC health checks).
    pub async fn probe_dc_addr(
        &self,
        dc: i16,
        addr: SocketAddr,
        timeout: Duration,
    ) -> io::Result<Duration> {
        let started = coarse_now_ns();
        let fut = async {
            let mut stream = TcpStream::connect(addr).await?;
            let _ = tune_tokio_stream(&stream, &self.sock_cfg);

            let (handshake, mut ciphers) =
                build_outbound_handshake(dc, ConnectionTag::PADDED_INTERMEDIATE, None);
            stream.write_all(&handshake).await?;

            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
            let mut frame = build_req_pq_multi_frame_now(&nonce);
            ciphers.send.apply_keystream(&mut frame);
            stream.write_all(&frame).await?;

            let mut resp_len_buf = [0u8; 4];
            stream.read_exact(&mut resp_len_buf).await?;
            ciphers.recv.apply_keystream(&mut resp_len_buf);
            let resp_len = u32::from_le_bytes(resp_len_buf) as usize;
            validate_res_pq_len(resp_len)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await?;
            ciphers.recv.apply_keystream(&mut resp);
            verify_res_pq_payload(&resp, &nonce)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(())
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(())) => {
                let elapsed_ns = coarse_now_ns().saturating_sub(started);
                self.record_success(addr, elapsed_ns / 1_000);
                Ok(Duration::from_nanos(elapsed_ns))
            }
            Ok(Err(e)) => {
                self.record_failure(addr);
                Err(e)
            }
            Err(_) => {
                self.record_failure(addr);
                Err(io::Error::new(io::ErrorKind::TimedOut, "dcprobe timed out"))
            }
        }
    }

    async fn happy_eyeballs_dial(
        &self,
        addrs: &[SocketAddr],
    ) -> io::Result<(TcpStream, SocketAddr)> {
        happy_eyeballs_connect_with(addrs, |sa| self.dial_single(sa)).await
    }

    async fn dial_single(&self, addr: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
        let started = coarse_now_ns();
        let res = tokio::time::timeout(self.dial_timeout, async {
            let s = TcpStream::connect(addr).await?;
            let _ = tune_tokio_stream(&s, &self.sock_cfg);
            Ok::<TcpStream, io::Error>(s)
        })
        .await;

        match res {
            Ok(Ok(stream)) => {
                self.record_success(addr, coarse_now_ns().saturating_sub(started) / 1_000);
                Ok((stream, addr))
            }
            Ok(Err(e)) => {
                self.record_failure(addr);
                Err(e)
            }
            Err(_) => {
                self.record_failure(addr);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DC connect timeout",
                ))
            }
        }
    }
}

/// Generic RFC 8305 Happy Eyeballs connector:
/// - Interleaves the first opposite-family candidate as `secondary`.
/// - Races `secondary` after `HAPPY_EYEBALLS_DELAY` (250 ms) if `primary` is
///   still in flight (e.g. blackholed IPv6 route).
/// - If `primary` fails immediately (e.g. `ENETUNREACH` on IPv4-only Linux VPSs),
///   IMMEDIATELY dials `secondary` without waiting for the 250 ms stagger or
///   skipping `secondary`!
pub async fn happy_eyeballs_connect_with<F, Fut>(
    addrs: &[SocketAddr],
    mut dial_fn: F,
) -> io::Result<(TcpStream, SocketAddr)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<(TcpStream, SocketAddr)>>,
{
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no target addresses to connect",
        ));
    }
    if addrs.len() == 1 {
        return dial_fn(addrs[0]).await;
    }

    // RFC 8305: interleave opposite address family as second candidate if present.
    let primary = addrs[0];
    let secondary_idx = addrs[1..]
        .iter()
        .position(|sa| sa.is_ipv4() != primary.is_ipv4())
        .map_or(1, |i| i + 1);
    let secondary = addrs[secondary_idx];

    let mut secondary_attempted = false;
    let mut last_err;

    {
        let mut f1 = std::pin::pin!(dial_fn(primary));
        tokio::select! {
            res = &mut f1 => {
                match res {
                    Ok(ok) => return Ok(ok),
                    Err(e) => {
                        debug!(addr = %primary, error = %e, "Happy Eyeballs primary failed fast; failing over to secondary");
                        last_err = e;
                    }
                }
            }
            () = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                secondary_attempted = true;
                let f2 = std::pin::pin!(dial_fn(secondary));
                match futures_race(f1, f2).await {
                    Ok(ok) => return Ok(ok),
                    Err(e) => {
                        debug!(error = %e, "Happy Eyeballs pair failed; trying remaining endpoints");
                        last_err = e;
                    }
                }
            }
        }
    }

    // CRITICAL: when `primary` failed BEFORE the 250ms stagger fired (e.g. instant
    // `ENETUNREACH` on IPv4-only Linux VPSs), `secondary` has NOT been dialed yet!
    if !secondary_attempted {
        match dial_fn(secondary).await {
            Ok(ok) => return Ok(ok),
            Err(e) => last_err = e,
        }
    }

    for (i, &sa) in addrs.iter().enumerate() {
        if i == 0 || i == secondary_idx {
            continue;
        }
        match dial_fn(sa).await {
            Ok(ok) => return Ok(ok),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Connect to the first reachable address in `addrs` using RFC 8305 Happy Eyeballs
/// and tune the established socket with `sock_cfg`.
pub async fn happy_eyeballs_connect(
    addrs: &[SocketAddr],
    sock_cfg: &SocketConfig,
    timeout: Duration,
) -> io::Result<(TcpStream, SocketAddr)> {
    let cfg = *sock_cfg;
    happy_eyeballs_connect_with(addrs, move |sa| async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(sa))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
        let _ = tune_tokio_stream(&stream, &cfg);
        Ok((stream, sa))
    })
    .await
}

/// Race two pinned futures returning the first `Ok`, or the second `Err` if both fail.
async fn futures_race<T, E, F1, F2>(
    mut f1: std::pin::Pin<&mut F1>,
    mut f2: std::pin::Pin<&mut F2>,
) -> Result<T, E>
where
    F1: std::future::Future<Output = Result<T, E>>,
    F2: std::future::Future<Output = Result<T, E>>,
{
    tokio::select! {
        r1 = &mut f1 => {
            match r1 {
                Ok(v) => Ok(v),
                Err(_) => f2.await,
            }
        }
        r2 = &mut f2 => {
            match r2 {
                Ok(v) => Ok(v),
                Err(_) => f1.await,
            }
        }
    }
}

/// Build a rustls `ClientConfig` backed by embedded Mozilla `webpki-roots`
/// (works even inside `FROM scratch` Linux containers without `/etc/ssl`).
pub fn build_tls_client_config() -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("valid TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Arc::new(cfg)
}

/// Minimal, dependency-free HTTP/HTTPS GET client over Hyper + rustls + optional
/// [`ProxyPool`] (capped at 16 MiB body for safety).
pub async fn fetch_url_bytes(
    url: &str,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: SocketConfig,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    fetch_url_bytes_with_dns(
        url,
        None,
        PreferIp::PreferIpv6,
        proxy_pool,
        sock_cfg,
        timeout,
    )
    .await
}

/// Outcome of a conditional HTTP/HTTPS GET request (`ETag` / `Last-Modified`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalFetch {
    /// Upstream returned `304 Not Modified`; cached body is still current.
    NotModified,
    /// Upstream returned `200 OK` with body bytes and optional cache validators.
    Modified {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// HTTP/HTTPS GET client honoring an optional [`DnsResolver`] (DoH/DoT/custom
/// DNS), [`PreferIp`], RFC 8305 Happy Eyeballs, bounded HTTP redirect following
/// (up to 5 hops for GitHub `/releases/latest/download/...` and CDN URLs), and
/// optional [`ProxyPool`].
pub async fn fetch_url_bytes_with_dns(
    url: &str,
    dns: Option<&DnsResolver>,
    prefer_ip: PreferIp,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: SocketConfig,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    match fetch_url_conditional_with_dns(
        url, dns, prefer_ip, proxy_pool, sock_cfg, timeout, None, None,
    )
    .await?
    {
        ConditionalFetch::Modified { bytes, .. } => Ok(bytes),
        ConditionalFetch::NotModified => Err(io::Error::other(format!(
            "unexpected HTTP 304 without conditional headers from {url}"
        ))),
    }
}

/// Conditional HTTP/HTTPS GET supporting `If-None-Match` / `If-Modified-Since`
/// (`304 Not Modified`), multi-hop redirects (up to 5 hops), 16 MiB body cap,
/// custom [`DnsResolver`], [`PreferIp`], Happy Eyeballs, and [`ProxyPool`].
#[allow(clippy::too_many_arguments)]
pub async fn fetch_url_conditional_with_dns(
    url: &str,
    dns: Option<&DnsResolver>,
    prefer_ip: PreferIp,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: SocketConfig,
    timeout: Duration,
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
) -> io::Result<ConditionalFetch> {
    const MAX_BODY: usize = 16 * 1024 * 1024;
    const MAX_REDIRECTS: usize = 5;

    tokio::time::timeout(timeout, async {
        let mut current_url = url.to_owned();
        let tls_cfg = build_tls_client_config();

        for hop in 0..=MAX_REDIRECTS {
            let uri: hyper::Uri = current_url.parse().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad URL: {e}"))
            })?;
            let scheme = uri.scheme_str().unwrap_or("");
            let is_https = match scheme {
                "https" => true,
                "http" => false,
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsupported URL scheme {other:?}"),
                    ));
                }
            };
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL missing host"))?
                .to_owned();
            let default_port = if is_https { 443 } else { 80 };
            let port = uri.port_u16().unwrap_or(default_port);
            let host_header = if port == default_port {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            let bare_host = host.trim_start_matches('[').trim_end_matches(']');
            let path = uri
                .path_and_query()
                .map_or("/", hyper::http::uri::PathAndQuery::as_str);

            let tcp = if let Some(pool) = proxy_pool
                && !pool.is_empty()
            {
                pool.dial(&ProxyTarget::Domain(bare_host.to_owned(), port))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
            } else {
                let addrs = if let Some(resolver) = dns {
                    resolver.resolve_socket_addrs(bare_host, port).await?
                } else {
                    let raw: Vec<SocketAddr> =
                        tokio::net::lookup_host((bare_host, port)).await?.collect();
                    let (mut v4, mut v6) = (Vec::new(), Vec::new());
                    for sa in raw {
                        match sa {
                            SocketAddr::V4(_) => v4.push(sa),
                            SocketAddr::V6(_) => v6.push(sa),
                        }
                    }
                    order_by_prefer_ip(v4, v6, prefer_ip)
                };
                let per_addr_timeout = timeout.min(Duration::from_secs(10));
                let (s, _) = happy_eyeballs_connect(&addrs, &sock_cfg, per_addr_timeout).await?;
                s
            };

            let mut req_builder = Request::builder()
                .method("GET")
                .uri(path)
                .header("Host", &host_header)
                .header("User-Agent", "mtg-proxy/2.3")
                .header("Accept", "*/*")
                .header("Connection", "close");
            if let Some(etag) = if_none_match
                && !etag.is_empty()
            {
                req_builder = req_builder.header(hyper::header::IF_NONE_MATCH, etag);
            }
            if let Some(ims) = if_modified_since
                && !ims.is_empty()
            {
                req_builder = req_builder.header(hyper::header::IF_MODIFIED_SINCE, ims);
            }
            let req = req_builder
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .map_err(|e| io::Error::other(e.to_string()))?;

            let resp = if is_https {
                let connector = TlsConnector::from(Arc::clone(&tls_cfg));
                let sni = ServerName::try_from(bare_host.to_owned())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                let tls = connector.connect(sni, tcp).await?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
            } else {
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
            };

            let status = resp.status();
            if status == hyper::StatusCode::NOT_MODIFIED {
                return Ok(ConditionalFetch::NotModified);
            }
            if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                if hop == MAX_REDIRECTS {
                    return Err(io::Error::other(format!(
                        "too many HTTP redirects (> {MAX_REDIRECTS}) from {url}"
                    )));
                }
                let loc = resp
                    .headers()
                    .get(hyper::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "HTTP {} redirect missing Location header from {current_url}",
                            status.as_u16()
                        ))
                    })?
                    .trim();
                current_url = resolve_redirect_url(scheme, &host_header, loc)?;
                continue;
            }

            if !status.is_success() {
                return Err(io::Error::other(format!(
                    "HTTP {} from {current_url}",
                    status.as_u16()
                )));
            }

            let etag = resp
                .headers()
                .get(hyper::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let last_modified = resp
                .headers()
                .get(hyper::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            let collected = http_body_util::Limited::new(resp.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                .to_bytes();
            return Ok(ConditionalFetch::Modified {
                bytes: collected.to_vec(),
                etag,
                last_modified,
            });
        }

        Err(io::Error::other(format!(
            "exceeded HTTP redirect limit fetching {url}"
        )))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("GET {url} timed out")))?
}

fn resolve_redirect_url(scheme: &str, host_header: &str, location: &str) -> io::Result<String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_owned());
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{host_header}{location}"));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported redirect Location {location:?}"),
    ))
}

/// Convert an `IpAddr` to a fixed 16-byte representation (IPv4-mapped if v4).
pub fn ip_to_v6_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Extract IPv4 address if v4 or IPv4-mapped IPv6.
pub fn ip_as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Normalize an IPv6 address (keeping native IPv6 unchanged).
pub fn ip_as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_telegram_proxy_config_lines() {
        let body = b"# Telegram proxy config\n\
            default 2;\n\
            proxy_for 1 149.154.175.50:8888;\n\
            proxy_for -1 149.154.175.51:8888;\n\
            proxy_for 203 91.105.192.100:443;\n\
            proxy_for 2 [2001:67c:4e8:f002::a]:8888;\n";
        let parsed = parse_proxy_config(body);
        assert_eq!(parsed[&1].len(), 1);
        assert_eq!(parsed[&-1].len(), 1);
        assert_eq!(parsed[&203].len(), 1);
        assert_eq!(parsed[&2][0].port(), 8888);

        let dir = DcDirectory {
            middle_v4: parsed,
            ..DcDirectory::default()
        };
        let ordered = dir.middle_addresses(1, PreferIp::PreferIpv4);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].to_string(), "149.154.175.50:8888");
        assert_eq!(ordered[1].to_string(), "149.154.175.51:8888");
    }

    #[test]
    fn default_core_addresses_cover_all_6_telegram_dcs() {
        let dir = DcDirectory::default();
        for dc in [1, 2, 3, 4, 5, 203] {
            assert!(
                !dir.direct_addresses(dc, PreferIp::PreferIpv4, false)
                    .is_empty()
            );
            assert!(
                !dir.direct_addresses(dc, PreferIp::OnlyIpv6, false)
                    .is_empty()
            );
        }
        // Unknown DC falls back to DC 2 only when allow_fallback = true.
        assert!(
            dir.direct_addresses(99, PreferIp::PreferIpv4, false)
                .is_empty()
        );
        let (fb_addrs, fb_dc) = dir.direct_addresses_with_dc(99, PreferIp::PreferIpv4, true);
        assert!(!fb_addrs.is_empty());
        assert_eq!(fb_dc, DEFAULT_DC);
    }

    /// Regression test for Showstopper #1: on IPv4-only Linux VPSs with default
    /// `prefer-ip = "prefer-ipv6"`, DC 1/3/4/5/203 have `[IPv6, IPv4]` where the
    /// primary returns an immediate error (`ENETUNREACH` / `ECONNREFUSED`).
    /// Happy Eyeballs MUST immediately dial `secondary` (index 1) without
    /// skipping it or stalling for the 250 ms stagger!
    #[tokio::test]
    async fn happy_eyeballs_falls_back_immediately_to_secondary_on_fast_primary_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_v4 = listener.local_addr().unwrap();

        // Bind-and-drop a closed port (or use an unreachable IPv6 loopback port) so primary fails immediately.
        let bad_primary: SocketAddr = {
            let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tmp.local_addr().unwrap()
        };

        let mut dir = DcDirectory::default();
        dir.direct_v6.insert(1, vec!["[::1]:1".parse().unwrap()]);
        dir.direct_v4.insert(1, vec![ok_v4]);

        let router = DcRouter::new(
            PreferIp::PreferIpv6,
            false,
            SocketConfig::default(),
            Duration::from_secs(2),
            None,
        );
        router.set_directory(dir);

        let started = std::time::Instant::now();
        let (_stream, connected_addr, effective_dc) = router.dial_direct(1).await.unwrap();
        assert_eq!(connected_addr, ok_v4);
        assert_eq!(effective_dc, 1);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "expected immediate failover without waiting 250ms stagger, got {:?}",
            started.elapsed()
        );

        // Also test direct 2-addr IPv4 fast-fail -> secondary path.
        let (_s2, addr2) = happy_eyeballs_connect(
            &[bad_primary, ok_v4],
            &SocketConfig::default(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(addr2, ok_v4);
    }

    #[tokio::test]
    async fn dial_direct_reports_effective_dc_on_unknown_dc_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_dc2 = listener.local_addr().unwrap();

        let mut dir = DcDirectory::default();
        dir.direct_v4.insert(DEFAULT_DC, vec![ok_dc2]);
        dir.direct_v6.remove(&DEFAULT_DC);

        let router = DcRouter::new(
            PreferIp::OnlyIpv4,
            true,
            SocketConfig::default(),
            Duration::from_secs(2),
            None,
        );
        router.set_directory(dir);

        let (_stream, addr, effective_dc) = router.dial_direct(99).await.unwrap();
        assert_eq!(addr, ok_dc2);
        assert_eq!(effective_dc, DEFAULT_DC);
    }

    #[tokio::test]
    async fn fetch_url_follows_github_style_multi_hop_redirects() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, _) = ln.accept().await.unwrap();
                let mut req = [0u8; 1024];
                let n = s.read(&mut req).await.unwrap();
                let txt = String::from_utf8_lossy(&req[..n]);
                let first_line = txt.lines().next().unwrap_or("");
                let resp = if first_line.starts_with("GET /latest/download/ir.txt ") {
                    "HTTP/1.1 302 Found\r\nLocation: /v2026/ir.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else if first_line.starts_with("GET /v2026/ir.txt ") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{addr}/cdn/ir.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n2.144.0.0/14\n"
                        .to_owned()
                };
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let body = fetch_url_bytes_with_dns(
            &format!("http://{addr}/latest/download/ir.txt"),
            None,
            PreferIp::OnlyIpv4,
            None,
            SocketConfig::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(body, b"2.144.0.0/14\n");
        srv.abort();
    }
}
