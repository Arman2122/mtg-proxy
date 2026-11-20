//! Shared control-plane & live runtime state (`ProxyEngine`), bridging the
//! pinned data-plane worker cores with the Management HTTP API (`mtg-api`),
//! `SIGHUP` live reloads, background fair-share / sweep / usage persistence
//! loops, and instant O(K) connection kicks/bans!

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use mtg_config::{Config, HandshakeBudgetMode, ListenerPolicy, PreferIp};
use mtg_core::{
    IpUnit, ModeSet, RetiringSecret, RotationClock, Secret, SecretLimits, SecretMode,
    is_personal_ip,
};
use mtg_crypto::faketls::X25519KeyRing;
use mtg_governance::{
    AddressRegistry, BanEntryJson, BanError, BanList, ClientEntry, ClientTable, ConnHandle,
    EntryInit, FairShareScratch, FakeTlsAntiReplay, LedgerDeny, LiveIpFilter, MatchHints,
    Obfs2AntiReplay, ObfuscatedLimiter, ScanBudget, ScanBudgetConfig, SecretSet,
};
use mtg_net::{
    DEFAULT_CARRIERS_PER_DC, DcRouter, DnsResolver, MiddleProxyPool, ProxyPool, SocketConfig,
    coarse_now_ns, coarse_realtime_ns,
};
use mtg_protocol::doppel::{DoppelParams, ShapingMode};
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use rustc_hash::FxHashMap;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::cancel::CancelToken;
use crate::metrics::ProxyMetrics;

/// vDSO `CLOCK_REALTIME_COARSE` timestamp converted to `DateTime<Utc>` (~2 ns, zero syscalls).
#[inline]
fn coarse_utc_now() -> DateTime<Utc> {
    let ns = coarse_realtime_ns();
    let secs = (ns / 1_000_000_000) as i64;
    let sub_ns = (ns % 1_000_000_000).max(0) as u32;
    DateTime::from_timestamp(secs, sub_ns).unwrap_or_else(Utc::now)
}

#[repr(align(64))]
#[derive(Debug, Default)]
struct PaddedRwLock(RwLock<()>);

/// Cache-line-isolated per-worker admission gate.
///
/// Data-plane workers acquire only their own worker stripe's read lock
/// (zero cross-core cache-line bouncing under handshake floods!), while
/// control-plane mutations (secret swap, ban, kick, snapshot) lock every
/// stripe in ascending order to guarantee strict atomicity with zero deadlocks.
#[derive(Debug)]
struct StripedGate {
    stripes: Box<[PaddedRwLock]>,
}

impl StripedGate {
    fn new(worker_count: usize) -> Self {
        let n = worker_count.max(1);
        let stripes = (0..n)
            .map(|_| PaddedRwLock::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { stripes }
    }

    #[inline]
    fn read(&self, worker_id: u16) -> RwLockReadGuard<'_, ()> {
        let idx = usize::from(worker_id) % self.stripes.len();
        self.stripes[idx].0.read()
    }

    fn write_all(&self) -> Vec<RwLockWriteGuard<'_, ()>> {
        let mut guards = Vec::with_capacity(self.stripes.len());
        for stripe in &self.stripes {
            guards.push(stripe.0.write());
        }
        guards
    }
}

#[repr(align(64))]
#[derive(Debug, Default)]
struct LiveConnShard(Mutex<FxHashMap<u64, LiveConnSlot>>);

/// Public capability list reported in `GET /stats` (`features`), sorted
/// lexicographically to match Go's exact Penhoon panel contract!
pub const SUPPORTED_FEATURES: &[&str] = &[
    "client-bans",
    "client-ip-activity",
    "client-ips",
    "client-limits",
    "client-stats",
    "faketls",
    "handshake-budget",
    "ip-limits",
    "kick",
    "listeners",
    "quota-ceiling",
    "quota-reset",
    "secret-modes",
    "secret-read",
    "secret-rotation",
    "secrets-api",
    "speed-directions",
    "speed-limits",
    "web-relay",
    "web-relay-watch",
];

/// Errors returned by control-plane mutations (`mtg-api` maps these to 400/404/409).
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("secret not found: {0:?}")]
    SecretNotFound(String),
    #[error("cannot delete the last remaining secret")]
    LastSecret,
    #[error("invalid secret or configuration: {0}")]
    Invalid(String),
    #[error(transparent)]
    Ban(#[from] BanError),
    #[error("reload failed: {0}")]
    Reload(String),
}

/// Listener descriptor exposed on `GET /stats` (`listeners`).
#[derive(Debug, Clone, Serialize)]
pub struct ListenerReport {
    pub bind_to: String,
    pub accept: Vec<String>,
    pub public: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_protocol: bool,
}

/// One live connection registration held in per-worker `ProxyEngine::live_conns`
/// so kicks, bans, secret removals, re-keys, and shutdown can abort streams in O(1).
#[derive(Debug)]
struct LiveConnSlot {
    secret_name: Arc<str>,
    cancel: CancelToken,
    key_bytes: [u8; 16],
    retiring: bool,
}

/// Active Doppelganger runtime profile & shaping settings.
#[derive(Debug)]
pub struct DoppelState {
    pub enabled: bool,
    pub shaping: ShapingMode,
    pub drs: bool,
    pub scout_covers: bool,
    pub scout_urls: Vec<String>,
    pub params: ArcSwap<DoppelParams>,
}

/// Configured proxy runtime parameters derived from [`Config`].
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub config_path: Option<PathBuf>,
    pub usage_state_file: Option<PathBuf>,
    pub api_bind_to: Option<String>,
    pub api_token: String,
    pub bind_to: Vec<String>,
    pub listeners: Vec<(String, ListenerPolicy)>,
    pub proxy_protocol_listener: bool,
    pub track_client_ips: bool,
    pub concurrency: u32,
    pub tolerate_time_skewness: Duration,
    pub tcp_timeout: Duration,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
    pub fronting_host: String,
    pub fronting_port: u16,
    pub fronting_proxy_protocol: bool,
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
    pub advertised_port: u16,
    pub sock_cfg: SocketConfig,
    pub worker_count: usize,
    pub force_epoll: bool,
}

/// Central shared engine state owned by `Arc<ProxyEngine>`.
#[derive(Debug)]
pub struct ProxyEngine {
    pub settings: EngineSettings,
    pub listener_modes: ModeSet,
    pub listener_reports: Vec<ListenerReport>,

    pub secrets: ArcSwap<SecretSet>,
    pub rotation_clock: RotationClock,
    pub clients: ClientTable,
    pub addresses: AddressRegistry,
    pub bans: BanList,
    pub hints: MatchHints,
    pub scan_budget: ScanBudget,
    pub obfs_limiter: ObfuscatedLimiter,
    pub faketls_replay: FakeTlsAntiReplay,
    pub obfs2_replay: Obfs2AntiReplay,
    pub blocklist: Option<Arc<LiveIpFilter>>,
    pub allowlist: Option<Arc<LiveIpFilter>>,
    pub dns: Arc<DnsResolver>,
    pub proxy_pool: Option<ProxyPool>,
    pub dc_router: Arc<DcRouter>,
    pub middleproxy: Arc<MiddleProxyPool>,
    pub x25519_keys: X25519KeyRing,
    pub doppel: DoppelState,
    pub metrics: Arc<ProxyMetrics>,

    /// Serializes config reloads & API secret mutations.
    reload_mu: Mutex<()>,
    /// Per-worker cache-line-isolated admission gate (zero cross-core lock contention!).
    live_gate: StripedGate,
    /// Per-worker sharded live connection table keyed by `conn_id` (64B aligned!).
    live_conns: Box<[LiveConnShard]>,
    next_conn_id: AtomicU64,
    background_started: AtomicBool,
    shutting_down: AtomicBool,
}

impl ProxyEngine {
    /// Construct a fully wired [`ProxyEngine`] from a validated [`Config`].
    pub fn from_config(
        cfg: &Config,
        config_path: Option<PathBuf>,
        worker_count: usize,
        force_epoll: bool,
    ) -> Result<Arc<Self>, EngineError> {
        cfg.validate()
            .map_err(|e| EngineError::Invalid(e.to_string()))?;

        let now = Utc::now();
        let (secret_set, retiring_warnings) = SecretSet::from_config(cfg, now, None);
        for w in &retiring_warnings {
            warn!("{w}");
        }

        let prefer_ip = cfg.prefer_ip.unwrap_or(PreferIp::PreferIpv6);
        let tcp_timeout = cfg.network.timeout.tcp.unwrap_or(Duration::from_secs(10));
        let idle_timeout = cfg.network.timeout.idle.unwrap_or(Duration::from_secs(60));
        let handshake_timeout = cfg
            .network
            .timeout
            .handshake
            .unwrap_or(Duration::from_secs(10));

        let sock_cfg = SocketConfig {
            keepalive_enabled: !cfg.network.keep_alive.disabled.unwrap_or(false),
            keepalive_idle: cfg
                .network
                .keep_alive
                .idle
                .unwrap_or(Duration::from_secs(60)),
            keepalive_interval: cfg
                .network
                .keep_alive
                .interval
                .unwrap_or(Duration::from_secs(15)),
            keepalive_count: cfg.network.keep_alive.count.unwrap_or(4),
            tcp_notsent_lowat: cfg
                .network
                .tcp_not_sent_lowat
                .map_or(mtg_net::DEFAULT_TCP_NOTSENT_LOWAT, |v| {
                    v.min(u64::from(u32::MAX)) as u32
                }),
            ..SocketConfig::default()
        };

        let dns = Arc::new(
            DnsResolver::build(cfg.network.dns.as_deref(), cfg.network.doh_ip, prefer_ip)
                .map_err(|e| EngineError::Invalid(format!("dns init failed: {e}")))?,
        );

        let proxy_pool = match &cfg.network.proxies {
            Some(urls) if !urls.is_empty() => Some(
                ProxyPool::from_urls(urls, sock_cfg, tcp_timeout)
                    .map_err(|e| EngineError::Invalid(e.to_string()))?,
            ),
            _ => None,
        };

        let dc_router = Arc::new(
            DcRouter::new(
                prefer_ip,
                cfg.allow_fallback_on_unknown_dc.unwrap_or(false),
                sock_cfg,
                tcp_timeout,
                proxy_pool.clone(),
            )
            .with_dns(Arc::clone(&dns)),
        );

        let middleproxy = Arc::new(MiddleProxyPool::new(
            Arc::clone(&dc_router),
            proxy_pool.clone(),
            sock_cfg,
            tcp_timeout,
            DEFAULT_CARRIERS_PER_DC,
        ));

        let ar_enabled = cfg.defense.anti_replay.enabled.unwrap_or(true);
        let ar_size = cfg.defense.anti_replay.max_size.unwrap_or(1 << 20) as usize;
        let ar_err = cfg.defense.anti_replay.error_rate.unwrap_or(0.001);
        let faketls_replay = if ar_enabled {
            FakeTlsAntiReplay::new(ar_size)
        } else {
            FakeTlsAntiReplay::disabled()
        };
        let obfs2_replay = if ar_enabled {
            Obfs2AntiReplay::new(ar_size, ar_err)
        } else {
            Obfs2AntiReplay::disabled()
        };

        let blocklist = if cfg.defense.blocklist.enabled.unwrap_or(false) {
            let urls = cfg.defense.blocklist.urls.clone().unwrap_or_default();
            let each = cfg
                .defense
                .blocklist
                .update_each
                .unwrap_or(Duration::from_secs(24 * 3600));
            Some(Arc::new(LiveIpFilter::new(
                urls,
                each,
                proxy_pool.clone(),
                sock_cfg,
            )))
        } else {
            None
        };

        let allowlist = if cfg.defense.allowlist.enabled.unwrap_or(false) {
            let urls = cfg.defense.allowlist.urls.clone().unwrap_or_default();
            let each = cfg
                .defense
                .allowlist
                .update_each
                .unwrap_or(Duration::from_secs(24 * 3600));
            Some(Arc::new(LiveIpFilter::new(
                urls,
                each,
                proxy_pool.clone(),
                sock_cfg,
            )))
        } else {
            None
        };

        let mut listeners = Vec::with_capacity(cfg.listeners.len());
        let mut listener_reports = Vec::with_capacity(cfg.listeners.len());
        let mut listener_modes = ModeSet::empty();
        for l in &cfg.listeners {
            let pol = l
                .policy()
                .map_err(|e| EngineError::Invalid(e.to_string()))?;
            let bind_str = l
                .bind_to
                .as_ref()
                .map_or_else(String::new, |h| h.as_str().to_owned());
            listener_modes |= pol.modes;
            listener_reports.push(ListenerReport {
                bind_to: bind_str.clone(),
                accept: pol
                    .modes
                    .sorted_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                public: pol.public,
                proxy_protocol: pol.proxy_protocol,
            });
            listeners.push((bind_str, pol));
        }

        let advertised_port = cfg
            .bind_to
            .first()
            .and_then(|hp| {
                hp.as_str()
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse().ok())
            })
            .unwrap_or(443);

        let workers = if worker_count > 0 {
            worker_count
        } else {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        };

        let metrics = Arc::new(ProxyMetrics::new(
            workers,
            cfg.throttle.max_connections.unwrap_or(0),
            cfg.throttle
                .check_interval
                .unwrap_or(Duration::from_secs(5)),
        ));

        // Pre-register every configured secret & sync ceilings/speed limits.
        for (name, rec) in &secret_set.records {
            metrics.pre_register(name);
            let u = metrics.user(name);
            u.quota_ceiling
                .store(rec.limits.quota_bytes, Ordering::Release);
            u.set_speed_limits(
                rec.limits.speed_bytes_per_second,
                rec.limits.speed_up_bytes_per_second,
                rec.limits.speed_down_bytes_per_second,
            );
        }

        let usage_path =
            (!cfg.usage_state_file.is_empty()).then(|| PathBuf::from(&cfg.usage_state_file));
        if let Some(p) = &usage_path
            && let Err(e) = metrics.load_usage(p)
        {
            warn!(path = %p.display(), error = %e, "could not load usage state file");
        }

        let hb_mode = cfg
            .defense
            .handshake_budget
            .mode
            .unwrap_or(HandshakeBudgetMode::Enforce);
        let hints_enabled = cfg.defense.handshake_budget.hints.unwrap_or(true);

        let scan_budget = ScanBudget::new(ScanBudgetConfig {
            mode: hb_mode,
            per_ip_ms: cfg.defense.handshake_budget.per_ip_ms,
            cpu_percent: cfg.defense.handshake_budget.cpu_percent,
            ..ScanBudgetConfig::default()
        });

        let settings = EngineSettings {
            config_path,
            usage_state_file: usage_path,
            api_bind_to: cfg.api_bind_to.as_ref().map(|h| h.as_str().to_owned()),
            api_token: (*cfg.api_token).clone(),
            bind_to: cfg.bind_to.iter().map(|b| b.as_str().to_owned()).collect(),
            listeners,
            proxy_protocol_listener: cfg.proxy_protocol_listener.unwrap_or(false),
            track_client_ips: cfg.track_client_ips.unwrap_or(false),
            concurrency: cfg.concurrency.unwrap_or(8192),
            tolerate_time_skewness: cfg.tolerate_time_skewness.unwrap_or(Duration::from_secs(5)),
            tcp_timeout,
            idle_timeout,
            handshake_timeout,
            fronting_host: cfg.get_domain_fronting_host().to_owned(),
            fronting_port: cfg.get_domain_fronting_port(443),
            fronting_proxy_protocol: cfg.get_domain_fronting_proxy_protocol(false),
            public_ipv4: cfg.public_ipv4,
            public_ipv6: cfg.public_ipv6,
            advertised_port,
            sock_cfg,
            worker_count: workers,
            force_epoll,
        };

        let doppel_shaping = cfg
            .defense
            .doppelganger
            .shaping
            .unwrap_or(ShapingMode::Record);
        let doppel_drs = cfg.defense.doppelganger.drs.unwrap_or(false);
        let doppel_scout_covers = cfg.defense.doppelganger.scout_covers.unwrap_or(false);
        let doppel_scout_urls = cfg.defense.doppelganger.urls.clone().unwrap_or_default();
        let doppel_enabled = !doppel_scout_urls.is_empty()
            || doppel_drs
            || cfg.defense.doppelganger.shaping.is_some()
            || doppel_scout_covers;
        let doppel = DoppelState {
            enabled: doppel_enabled,
            shaping: doppel_shaping,
            drs: doppel_drs,
            scout_covers: doppel_scout_covers,
            scout_urls: doppel_scout_urls,
            params: ArcSwap::from_pointee(DoppelParams {
                drs: doppel_drs,
                shaping: doppel_shaping,
                ..DoppelParams::default()
            }),
        };

        Ok(Arc::new(Self {
            settings,
            listener_modes,
            listener_reports,
            secrets: ArcSwap::from_pointee(secret_set),
            rotation_clock: RotationClock::new(),
            clients: ClientTable::new(),
            addresses: AddressRegistry::new(),
            bans: BanList::new(),
            hints: MatchHints::new(hints_enabled),
            scan_budget,
            obfs_limiter: ObfuscatedLimiter::new(),
            faketls_replay,
            obfs2_replay,
            blocklist,
            allowlist,
            dns,
            proxy_pool,
            dc_router,
            middleproxy,
            x25519_keys: X25519KeyRing::default(),
            doppel,
            metrics,
            reload_mu: Mutex::new(()),
            live_gate: StripedGate::new(workers),
            live_conns: (0..workers.max(1))
                .map(|_| LiveConnShard::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            next_conn_id: AtomicU64::new(1),
            background_started: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
        }))
    }

    /// True if IP is permitted by configured blocklist / allowlist (`0 ns` when disabled!).
    #[inline]
    pub fn check_ip_filters(&self, ip: IpAddr, worker_id: usize) -> bool {
        if let Some(allow) = &self.allowlist
            && !allow.contains(ip)
        {
            self.metrics
                .core(worker_id)
                .allowlist_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if let Some(block) = &self.blocklist
            && block.contains(ip)
        {
            self.metrics
                .core(worker_id)
                .blocklisted_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Resolve fronting hostname for an unmatched or denied FakeTLS handshake.
    pub fn fronting_host_for(&self, sni_candidates: &[String]) -> String {
        if !self.settings.fronting_host.is_empty() {
            return self.settings.fronting_host.clone();
        }
        let set = self.secrets.load();
        for sni in sni_candidates {
            if set.sni_bucket(sni).is_some() {
                return sni.clone();
            }
        }
        for rec in set.records.values() {
            if rec.secret.is_hosted() {
                return rec.secret.host().to_owned();
            }
        }
        String::new()
    }

    /// Atomically admit a matched connection across all governance checks:
    /// disabled, expired, quota, global throttle, IP ban, `ip-limit`, `client-conns`,
    /// returning `(ConnHandle, Arc<ClientEntry>, CancelToken)`.
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
    pub fn admit_connection(
        &self,
        worker_id: u16,
        secret_name: &Arc<str>,
        key_bytes: [u8; 16],
        retiring: bool,
        client_ip: Option<IpAddr>,
        limits: &SecretLimits,
    ) -> Result<(ConnHandle, Arc<ClientEntry>, CancelToken), ()> {
        let now = coarse_utc_now();

        if limits.disabled {
            return Err(());
        }
        if let Some(exp) = limits.expires_at
            && now >= exp
        {
            return Err(());
        }

        let user = self.metrics.user(secret_name);
        user.rollover_if_needed(limits.quota_reset, now);
        if limits.quota_bytes > 0 && user.quota_used.load(Ordering::Acquire) >= limits.quota_bytes {
            return Err(());
        }

        if !self.metrics.can_connect_throttle(secret_name) {
            self.metrics
                .core(usize::from(worker_id))
                .throttled_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(());
        }

        let unit = client_ip.map(IpUnit::from_ip);
        let keyed = client_ip.is_some_and(is_personal_ip);

        // Per-worker striped read-lock: zero cross-core contention with other workers,
        // while strictly serialized against control-plane bans/kicks/swaps!
        let _live_guard = self.live_gate.read(worker_id);

        // Re-check secret existence & ban inside `live_gate` (prevents race with concurrent ban/delete!).
        if !self.secrets.load().contains(secret_name) {
            return Err(());
        }
        if let Some(u) = unit
            && self.bans.is_banned(secret_name, u, now)
        {
            return Err(());
        }

        let handle = ConnHandle {
            worker_id,
            conn_id: self.next_conn_id.fetch_add(1, Ordering::Relaxed),
        };

        if let Err(deny) = self.addresses.admit_and_register(
            secret_name,
            handle,
            client_ip,
            limits.ip_limit,
            limits.client_conns,
            keyed,
            now,
        ) {
            match deny {
                LedgerDeny::IpLimit => {
                    user.ip_limit_refused.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .core(usize::from(worker_id))
                        .ip_limited_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                LedgerDeny::ClientConns => {
                    user.client_conns_refused.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Err(());
        }

        let entry = self
            .clients
            .acquire(secret_name, unit, keyed, EntryInit::from_limits(limits));

        let cancel = CancelToken::new();
        let shard_idx = usize::from(worker_id) % self.live_conns.len();
        self.live_conns[shard_idx].0.lock().insert(
            handle.conn_id,
            LiveConnSlot {
                secret_name: Arc::clone(secret_name),
                cancel: cancel.clone(),
                key_bytes,
                retiring,
            },
        );

        user.connections.fetch_add(1, Ordering::Relaxed);
        user.last_seen_unix
            .store(now.timestamp(), Ordering::Relaxed);
        if retiring {
            user.retiring_connections.fetch_add(1, Ordering::Relaxed);
            user.retiring_last_seen_ns
                .store(now.timestamp_nanos_opt().unwrap_or(0), Ordering::Relaxed);
        }
        if self.settings.track_client_ips
            && let Some(ip) = client_ip
        {
            // Format IP on stack & check read lock first — zero alloc & zero write lock when unchanged!
            let mut stack_buf = [0u8; 46];
            let mut cursor: &mut [u8] = &mut stack_buf;
            if write!(cursor, "{ip}").is_ok() {
                let written = 46 - cursor.len();
                if let Ok(ip_str) = std::str::from_utf8(&stack_buf[..written])
                    && user.last_ip.read().as_str() != ip_str
                {
                    let mut guard = user.last_ip.write();
                    guard.clear();
                    guard.push_str(ip_str);
                }
            }
        }

        Ok((handle, entry, cancel))
    }

    /// Release all per-connection registrations cleanly on stream termination.
    pub fn release_connection(
        &self,
        secret_name: &str,
        handle: ConnHandle,
        entry: &ClientEntry,
        retiring: bool,
    ) {
        let now = coarse_utc_now();
        {
            let _live_guard = self.live_gate.read(handle.worker_id);
            let shard_idx = usize::from(handle.worker_id) % self.live_conns.len();
            let mut shard = self.live_conns[shard_idx].0.lock();
            shard.remove(&handle.conn_id);
            if shard.is_empty() && shard.capacity() > 512 {
                shard.shrink_to(0);
            }
            drop(shard);
            self.addresses.unregister(secret_name, handle, now);
        }
        self.clients.release(entry);
        let user = self.metrics.user(secret_name);
        user.connections.fetch_sub(1, Ordering::Relaxed);
        if retiring {
            user.retiring_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Signal immediate cancellation to a set of live [`ConnHandle`]s.
    fn cancel_handles(&self, handles: &[ConnHandle]) -> usize {
        if handles.is_empty() {
            return 0;
        }
        let mut closed = 0usize;
        for h in handles {
            let shard_idx = usize::from(h.worker_id) % self.live_conns.len();
            let shard = self.live_conns[shard_idx].0.lock();
            if let Some(slot) = shard.get(&h.conn_id) {
                slot.cancel.cancel();
                closed += 1;
            }
        }
        closed
    }

    /// Reload secrets, limits, ad-tags, and retiring blocks from `config_path`.
    pub fn reload_from_disk(&self) -> Result<Vec<String>, EngineError> {
        let Some(path) = &self.settings.config_path else {
            return Err(EngineError::Reload(
                "no configuration file path configured".to_owned(),
            ));
        };
        let raw = std::fs::read(path)
            .map_err(|e| EngineError::Reload(format!("cannot read {}: {e}", path.display())))?;
        let mut cfg = Config::parse(&raw)
            .map_err(|e| EngineError::Reload(format!("cannot parse config: {e}")))?;
        cfg.apply_environment()
            .map_err(|e| EngineError::Reload(e.to_string()))?;
        cfg.validate()
            .map_err(|e| EngineError::Reload(e.to_string()))?;

        let now = self.rotation_clock.now();
        let retiring_report = cfg.get_retiring_secrets(now);
        let secrets = cfg.get_secrets();
        let limits = cfg.get_secret_limits();
        let ad_tags = cfg.get_secret_ad_tags();
        let default_ad_tag = cfg.ad_tag.as_deref().copied();

        let _reload_guard = self.reload_mu.lock();
        self.swap_secrets_locked(
            &secrets,
            &limits,
            &ad_tags,
            default_ad_tag,
            &retiring_report.usable,
        )?;
        Ok(retiring_report.lines)
    }

    /// `PUT /secrets` — replaces the entire secret set while preserving active
    /// retiring keys of every retained secret name (exact Penhoon contract!).
    pub fn replace_secrets_keeping_retiring(
        &self,
        secrets: &BTreeMap<String, Secret>,
        limits: &BTreeMap<String, SecretLimits>,
        ad_tags: &BTreeMap<String, [u8; 16]>,
        default_ad_tag: Option<[u8; 16]>,
    ) -> Result<(), EngineError> {
        if secrets.is_empty() {
            return Err(EngineError::Invalid(
                "secrets map must contain at least one secret".to_owned(),
            ));
        }
        for name in secrets.keys() {
            if name.is_empty() {
                return Err(EngineError::Invalid(
                    "secret name cannot be empty".to_owned(),
                ));
            }
        }

        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();
        let now = self.rotation_clock.now();

        let mut kept_retiring = Vec::new();
        for (name, rec) in &prev.records {
            if secrets.contains_key(name) {
                for r in &rec.retiring {
                    if now < r.until {
                        // Drop if the new primary matches this retiring key
                        if secrets.get(name).is_some_and(|p| p.key() == r.secret.key()) {
                            continue;
                        }
                        kept_retiring.push(r.clone());
                    }
                }
            }
        }
        drop(prev);

        self.swap_secrets_locked(secrets, limits, ad_tags, default_ad_tag, &kept_retiring)
    }

    /// `POST /secrets` — add or update a single named secret, keeping its retiring keys.
    pub fn put_secret(
        &self,
        name: String,
        secret: Secret,
        ad_tag: Option<[u8; 16]>,
        limits: SecretLimits,
    ) -> Result<(), EngineError> {
        if name.is_empty() {
            return Err(EngineError::Invalid("empty name".to_owned()));
        }
        if !secret.is_valid() {
            return Err(EngineError::Invalid("invalid secret".to_owned()));
        }
        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();

        let mut secrets = BTreeMap::new();
        let mut all_limits = BTreeMap::new();
        let mut all_tags = BTreeMap::new();
        let mut retiring = Vec::new();
        let default_tag = prev.default_ad_tag;

        for (k, rec) in &prev.records {
            secrets.insert(k.clone(), rec.secret.clone());
            if !rec.limits.is_zero() {
                all_limits.insert(k.clone(), rec.limits.clone());
            }
            if let Some(t) = rec.ad_tag {
                all_tags.insert(k.clone(), t);
            }
            for r in &rec.retiring {
                if r.secret.key() != secret.key() {
                    retiring.push(r.clone());
                }
            }
        }
        drop(prev);

        secrets.insert(name.clone(), secret);
        if let Some(t) = ad_tag {
            all_tags.insert(name.clone(), t);
        } else {
            all_tags.remove(&name);
        }
        if limits.is_zero() {
            all_limits.remove(&name);
        } else {
            all_limits.insert(name, limits);
        }

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)
    }

    /// `DELETE /secrets/{name}` — removes one secret (refuses deleting last secret).
    pub fn delete_secret(&self, name: &str) -> Result<(), EngineError> {
        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();
        if !prev.contains(name) {
            return Err(EngineError::SecretNotFound(name.to_owned()));
        }
        if prev.records.len() <= 1 {
            return Err(EngineError::LastSecret);
        }

        let mut secrets = BTreeMap::new();
        let mut all_limits = BTreeMap::new();
        let mut all_tags = BTreeMap::new();
        let mut retiring = Vec::new();
        let default_tag = prev.default_ad_tag;

        for (k, rec) in &prev.records {
            if k == name {
                continue;
            }
            secrets.insert(k.clone(), rec.secret.clone());
            if !rec.limits.is_zero() {
                all_limits.insert(k.clone(), rec.limits.clone());
            }
            if let Some(t) = rec.ad_tag {
                all_tags.insert(k.clone(), t);
            }
            retiring.extend(rec.retiring.iter().cloned());
        }
        drop(prev);

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)
    }

    /// `PUT /adtag` / `DELETE /adtag` — update global default `ad_tag`.
    pub fn set_global_ad_tag(&self, tag: Option<[u8; 16]>) -> Result<(), EngineError> {
        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();
        let mut secrets = BTreeMap::new();
        let mut all_limits = BTreeMap::new();
        let mut all_tags = BTreeMap::new();
        let mut retiring = Vec::new();

        for (k, rec) in &prev.records {
            secrets.insert(k.clone(), rec.secret.clone());
            if !rec.limits.is_zero() {
                all_limits.insert(k.clone(), rec.limits.clone());
            }
            if let Some(t) = rec.ad_tag {
                all_tags.insert(k.clone(), t);
            }
            retiring.extend(rec.retiring.iter().cloned());
        }
        drop(prev);

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, tag, &retiring)
    }

    fn swap_secrets_locked(
        &self,
        secrets: &BTreeMap<String, Secret>,
        limits: &BTreeMap<String, SecretLimits>,
        ad_tags: &BTreeMap<String, [u8; 16]>,
        default_ad_tag: Option<[u8; 16]>,
        retiring: &[RetiringSecret],
    ) -> Result<(), EngineError> {
        if secrets.is_empty() {
            return Err(EngineError::Invalid(
                "secret set cannot be empty".to_owned(),
            ));
        }
        let prev = self.secrets.load();
        let new_set = Arc::new(SecretSet::build(
            secrets,
            limits,
            ad_tags,
            default_ad_tag,
            retiring,
            Some(&prev),
        ));

        // Update per-secret runtime buckets (pre-register, speed limits, quota ceiling).
        for (name, rec) in &new_set.records {
            self.metrics.pre_register(name);
            let u = self.metrics.user(name);
            u.quota_ceiling
                .store(rec.limits.quota_bytes, Ordering::Release);
            u.set_speed_limits(
                rec.limits.speed_bytes_per_second,
                rec.limits.speed_up_bytes_per_second,
                rec.limits.speed_down_bytes_per_second,
            );
            // Reset retiring_last_seen when transitioning from 0 -> >0 retiring keys
            let had_retiring = prev
                .records
                .get(name)
                .is_some_and(|old| !old.retiring.is_empty());
            if !had_retiring && !rec.retiring.is_empty() {
                u.retiring_last_seen_ns.store(0, Ordering::Release);
            }
        }

        // Publish new SecretSet wait-free!
        let removed_names: Vec<String> = prev
            .records
            .keys()
            .filter(|k| !new_set.records.contains_key(*k))
            .cloned()
            .collect();
        self.secrets.store(Arc::clone(&new_set));

        // Synchronize client table ceilings, fair-share totals, bans, and close stale streams!
        let now_ns = coarse_now_ns();
        let now = Utc::now();
        let to_cancel: Vec<CancelToken> = {
            let _live_guard = self.live_gate.write_all();

            self.clients.apply_ceilings(|name| {
                new_set
                    .records
                    .get(name)
                    .map(|r| r.limits.client_speed_bytes_per_second)
            });
            self.clients.apply_fair(now_ns, |name| {
                new_set.records.get(name).map(|r| r.limits.fair_totals())
            });

            for removed in &removed_names {
                self.bans.drop_secret(removed);
                self.clients.drop_secret(removed);
                let _ = self.addresses.drop_secret(removed);
            }

            // Collect live streams whose secret was removed, re-keyed, disabled, or expired!
            let mut stale = Vec::new();
            for shard in &self.live_conns {
                let conns = shard.0.lock();
                for slot in conns.values() {
                    let Some(rec) = new_set.records.get(slot.secret_name.as_ref()) else {
                        stale.push(slot.cancel.clone());
                        continue;
                    };
                    if rec.limits.disabled || rec.limits.expires_at.is_some_and(|exp| now >= exp) {
                        stale.push(slot.cancel.clone());
                        continue;
                    }
                    let key_still_accepted = *rec.secret.key() == slot.key_bytes
                        || rec
                            .retiring
                            .iter()
                            .any(|r| *r.secret.key() == slot.key_bytes && now < r.until);
                    if !key_still_accepted {
                        stale.push(slot.cancel.clone());
                    }
                }
            }
            stale
        };

        let closed = to_cancel.len();
        for tok in to_cancel {
            tok.cancel();
        }
        if closed > 0 {
            info!(closed, "closed stale connections after secret swap");
        }
        Ok(())
    }

    /// `POST /secrets/{name}/kick` — O(K) kick of live streams matching `units`.
    pub fn kick_units(&self, secret_name: &str, units: &[IpUnit]) -> Result<usize, EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        let handles = {
            let _live_guard = self.live_gate.write_all();
            self.addresses.handles_for_units(secret_name, units)
        };
        let closed = self.cancel_handles(&handles);
        Ok(closed)
    }

    /// `POST /secrets/{name}/bans` — atomic ban + O(K) live kick + hint forget.
    pub fn ban_units(
        &self,
        secret_name: &str,
        units: &[IpUnit],
        ttl: Duration,
    ) -> Result<(usize, usize, Vec<String>), EngineError> {
        let now = Utc::now();
        let (dedup, handles) = {
            let _live_guard = self.live_gate.write_all();
            if !self.secrets.load().contains(secret_name) {
                return Err(EngineError::SecretNotFound(secret_name.to_owned()));
            }
            let dedup = self.bans.add(secret_name, units, ttl, now)?;
            let handles = self.addresses.handles_for_units(secret_name, &dedup);
            (dedup, handles)
        };
        let closed = self.cancel_handles(&handles);
        for &u in &dedup {
            self.hints.forget_unit(u, secret_name);
        }
        let mut addresses = Vec::new();
        if self.settings.track_client_ips {
            addresses = dedup.iter().map(ToString::to_string).collect();
            addresses.sort();
        }
        Ok((dedup.len(), closed, addresses))
    }

    /// `DELETE /secrets/{name}/bans/{address...}`.
    pub fn unban_unit(&self, secret_name: &str, unit: IpUnit) -> Result<bool, EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        Ok(self.bans.remove(secret_name, unit, Utc::now()))
    }

    /// `PUT /secrets/{name}/external-ips` / `DELETE /secrets/{name}/external-ips`.
    pub fn set_external_addresses(
        &self,
        secret_name: &str,
        addrs: &[IpAddr],
        ttl: Duration,
    ) -> Result<(), EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        let _live_guard = self.live_gate.write_all();
        self.addresses
            .set_external(secret_name, addrs, ttl, Utc::now());
        Ok(())
    }

    /// `POST /secrets/{name}/reset-quota`.
    pub fn reset_quota(&self, secret_name: &str) -> Result<(), EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        self.metrics.reset_quota(secret_name, Utc::now());
        Ok(())
    }

    /// Trigger graceful shutdown, signalling all active connections.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        for shard in &self.live_conns {
            let conns = shard.0.lock();
            for slot in conns.values() {
                slot.cancel.cancel();
            }
        }
    }

    #[inline]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Check active bans list for `GET /secrets/{name}/bans`.
    pub fn list_bans(
        &self,
        secret_name: &str,
    ) -> Result<(usize, bool, Vec<BanEntryJson>), EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        let now = Utc::now();
        if !self.settings.track_client_ips {
            return Ok((self.bans.count(secret_name, now), false, Vec::new()));
        }
        let list = self.bans.list(secret_name, now);
        Ok((list.len(), true, list))
    }

    /// Snapshot per-address client usage + live connection counts in one
    /// consistent `live_gate -> clients` critical section for `GET /secrets/{name}/clients`.
    pub fn snapshot_clients_view(
        &self,
        secret_name: &str,
    ) -> Result<(mtg_governance::ClientsView, Vec<u32>), EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        if !self.settings.track_client_ips {
            let view = self.clients.view(secret_name, false);
            return Ok((view, Vec::new()));
        }
        let _live_guard = self.live_gate.write_all();
        let view = self.clients.view(secret_name, true);
        let live_counts: Vec<u32> = view
            .entries
            .iter()
            .map(|e| {
                e.key
                    .map_or(0, |u| self.addresses.live_count_for_unit(secret_name, u))
            })
            .collect();
        Ok((view, live_counts))
    }

    /// Spawn periodic background maintenance tasks (1s fair-share ticker, 1m
    /// client table sweep, 30s atomic `usage.json` flusher, throttle recompute,
    /// anti-replay / hint / budget rotations, hourly DC & IP-filter refresh,
    /// and live Doppelganger cover scouting).
    ///
    /// Strictly idempotent: subsequent calls after the first return immediately.
    pub fn spawn_background_tasks(self: &Arc<Self>, shutdown: watch::Receiver<bool>) {
        if self.background_started.swap(true, Ordering::AcqRel) {
            return;
        }

        // 1. Hourly Telegram DC & MiddleProxy config refresh (only fetch if ad_tag exists or DC updates needed)
        self.dc_router.spawn_refresh_loop(shutdown.clone());

        // 2. IP blocklist / allowlist periodic refresh
        if let Some(bl) = &self.blocklist {
            bl.spawn_refresh_loop(shutdown.clone());
        }
        if let Some(al) = &self.allowlist {
            al.spawn_refresh_loop(shutdown.clone());
        }

        // 3. 1-second fair-share water-level ticker (only touches fair-enabled secrets!)
        {
            let engine = Arc::clone(self);
            let mut sd = shutdown.clone();
            tokio::spawn(async move {
                let mut scratch = FairShareScratch::default();
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let set = engine.secrets.load();
                            if !set.fair_secrets.is_empty() {
                                engine.clients.tick_all_fair(&set.fair_secrets, &mut scratch);
                            }
                        }
                        _ = sd.changed() => {
                            if *sd.borrow() { return; }
                        }
                    }
                }
            });
        }

        // 4. 1-minute chunked idle client-table sweep + 30s atomic usage.json flush + throttle loop
        {
            let engine = Arc::clone(self);
            let mut sd = shutdown.clone();
            tokio::spawn(async move {
                let mut sweep_tick = tokio::time::interval(Duration::from_secs(60));
                let mut usage_tick = tokio::time::interval(Duration::from_secs(30));
                let mut throttle_tick = tokio::time::interval(engine.metrics.throttle_interval);
                sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                usage_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                throttle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = sweep_tick.tick() => {
                            let now_unix = Utc::now().timestamp();
                            engine.clients.sweep(now_unix, mtg_governance::CLIENT_SWEEP_CHUNK);
                            // Also close streams of newly-expired retiring keys or expired users
                            engine.sweep_expired_streams();
                        }
                        _ = usage_tick.tick() => {
                            if let Some(path) = &engine.settings.usage_state_file
                                && let Err(e) = engine.metrics.flush_usage_atomic(path)
                            {
                                warn!(path = %path.display(), error = %e, "usage.json atomic flush failed");
                            }
                        }
                        _ = throttle_tick.tick() => {
                            engine.metrics.recompute_throttle_caps();
                        }
                        _ = sd.changed() => {
                            if *sd.borrow() {
                                if let Some(path) = &engine.settings.usage_state_file {
                                    let _ = engine.metrics.flush_usage_atomic(path);
                                }
                                return;
                            }
                        }
                    }
                }
            });
        }

        // 5. Anti-replay, match-hints, scan-budget, and obfs-limiter generation rotations
        {
            let engine = Arc::clone(self);
            let mut sd = shutdown.clone();
            let replay_period = engine
                .settings
                .tolerate_time_skewness
                .max(Duration::from_secs(5));
            tokio::spawn(async move {
                let mut replay_tick = tokio::time::interval(replay_period);
                let mut hints_tick = tokio::time::interval(mtg_governance::HINT_ROTATION);
                let mut obfs_tick =
                    tokio::time::interval(mtg_governance::HANDSHAKE_BUCKET_ROTATION);
                replay_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                hints_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                obfs_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = replay_tick.tick() => engine.faketls_replay.rotate(),
                        _ = hints_tick.tick() => {
                            engine.hints.rotate();
                            engine.scan_budget.rotate();
                        }
                        _ = obfs_tick.tick() => engine.obfs_limiter.rotate(),
                        _ = sd.changed() => {
                            if *sd.borrow() { return; }
                        }
                    }
                }
            });
        }

        // 6. Live Doppelganger cover-site scouting (probes configured `urls` and/or
        //    distinct FakeTLS fronting hosts to calibrate ServerHello noise + Weibull + DRS)
        if self.doppel.enabled && (!self.doppel.scout_urls.is_empty() || self.doppel.scout_covers) {
            let engine = Arc::clone(self);
            let mut sd = shutdown;
            tokio::spawn(async move {
                let mut scout_tick =
                    tokio::time::interval(crate::doppel_scout::SCOUT_REFRESH_INTERVAL);
                scout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = scout_tick.tick() => {
                            let targets = engine.collect_doppel_scout_targets();
                            if let Some(updated) = crate::doppel_scout::run_scout_round(
                                &targets,
                                engine.doppel.drs,
                                engine.doppel.shaping,
                                &engine.dns,
                                engine.proxy_pool.as_ref(),
                                &engine.settings.sock_cfg,
                            )
                            .await
                            {
                                engine.doppel.params.store(Arc::new(updated));
                            }
                        }
                        _ = sd.changed() => {
                            if *sd.borrow() { return; }
                        }
                    }
                }
            });
        }
    }

    /// Collect deduplicated cover-site targets for Doppelganger scouting from
    /// explicit `[defense.doppelganger].urls` and (when `scout-covers = true`)
    /// active FakeTLS secret fronting hosts.
    fn collect_doppel_scout_targets(&self) -> Vec<crate::doppel_scout::ScoutTarget> {
        let mut seen = rustc_hash::FxHashSet::default();
        let mut targets = Vec::new();

        for raw in &self.doppel.scout_urls {
            if let Some(t) = crate::doppel_scout::ScoutTarget::parse(raw)
                && seen.insert(t.clone())
            {
                targets.push(t);
            }
        }

        if self.doppel.scout_covers {
            let set = self.secrets.load();
            for rec in set.records.values() {
                if targets.len() >= crate::doppel_scout::MAX_SCOUT_TARGETS {
                    break;
                }
                if rec.secret.is_hosted()
                    && let Some(t) = crate::doppel_scout::ScoutTarget::parse(rec.secret.host())
                    && seen.insert(t.clone())
                {
                    targets.push(t);
                }
            }
        }

        targets
    }

    fn sweep_expired_streams(&self) {
        let set = self.secrets.load();
        let now = Utc::now();
        let rot_now = self.rotation_clock.now();
        let mut stale = Vec::new();
        for shard in &self.live_conns {
            let conns = shard.0.lock();
            for slot in conns.values() {
                let Some(rec) = set.records.get(slot.secret_name.as_ref()) else {
                    stale.push(slot.cancel.clone());
                    continue;
                };
                if rec.limits.disabled || rec.limits.expires_at.is_some_and(|exp| now >= exp) {
                    stale.push(slot.cancel.clone());
                    continue;
                }
                if rec.limits.quota_bytes > 0
                    && let Some(u) = self.metrics.get_user(&slot.secret_name)
                    && u.quota_used.load(Ordering::Relaxed) >= rec.limits.quota_bytes
                {
                    stale.push(slot.cancel.clone());
                    continue;
                }
                if slot.retiring {
                    let valid = rec
                        .retiring
                        .iter()
                        .any(|r| *r.secret.key() == slot.key_bytes && rot_now < r.until);
                    if !valid {
                        stale.push(slot.cancel.clone());
                    }
                }
            }
        }
        for tok in stale {
            tok.cancel();
        }
    }
}

/// Helper to check whether a secret's mode is served by the configured listeners.
pub fn is_secret_served(secret: &Secret, listener_modes: ModeSet) -> bool {
    if secret.mode() == SecretMode::FakeTls {
        return true;
    }
    listener_modes
        .tags()
        .contains(ModeSet::of(&[secret.mode()]).tags())
}

/// Helper for formatting a `SocketAddr` into a canonical IP string.
pub fn peer_ip_of(addr: SocketAddr) -> IpAddr {
    mtg_core::ip::unmap_ip(addr.ip())
}
