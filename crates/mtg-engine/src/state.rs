//! Shared control-plane & live runtime state (`ProxyEngine`), bridging the
//! pinned data-plane worker cores with the Management HTTP API (`mtg-api`),
//! `SIGHUP` live reloads, background fair-share / sweep / usage persistence
//! loops, and instant O(K) connection kicks/bans!

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use mtg_config::{
    ApiPersistenceMode, Config, HandshakeBudgetMode, IpFilterAction, ListConfig, ListenerPolicy,
    PreferIp, UnknownSniAction,
};
use mtg_core::{
    GlobalLimits, IpUnit, ModeSet, QuotaReset, RetiringSecret, RotationClock, Secret, SecretLimits,
    SecretMode, is_personal_ip,
};
use mtg_crypto::faketls::X25519KeyRing;
use mtg_governance::{
    AddressRegistry, BanEntryJson, BanError, BanList, ClientEntry, ClientTable, ConnHandle,
    EntryInit, FairShareScratch, FakeTlsAntiReplay, GlobalIpGuard, LedgerDeny, LiveIpFilter,
    LiveIpFilterStatus, MatchHints, Obfs2AntiReplay, ObfuscatedLimiter, ScanBudget,
    ScanBudgetConfig, SecretSet,
};
use mtg_net::{
    DEFAULT_CARRIERS_PER_DC, DcRouter, DnsResolver, MiddleProxyPool, OutboundGroupSpec,
    OutboundRouter, OutboundSnapshot, OutboundSpec, OutboundStrategy, OutboundTarget, ProxyPool,
    RoutingSpec, SocketConfig, coarse_now_ns, coarse_realtime_ns,
};
use mtg_protocol::doppel::{DoppelParams, ShapingMode};
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use rustc_hash::FxHashMap;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use crate::cancel::CancelToken;
use crate::metrics::ProxyMetrics;
use crate::persistence::{
    BillingCheckpointReport, BillingTracker, EngineEvent, GlobalLimitsSnapshot,
    RUNTIME_STATE_SCHEMA_VERSION, RuntimeStateSnapshot, SecretLimitsSnapshot, default_overlay_path,
    if_match_satisfied, load_overlay_verified, save_overlay_atomic, save_toml_atomic,
};

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
    #[error("state persistence failed: {0}")]
    Persistence(String),
}

/// Result of evaluating `[defense.blocklist]` and `[defense.allowlist]` for a client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFilterVerdict {
    /// IP is permitted to attempt proxy authentication.
    Allow,
    /// IP is denied proxy access; transparently front directly to the cover website
    /// (zero secret matching, zero HMAC CPU, zero TCP-drop fingerprint!).
    Front,
    /// IP is denied and the connection should be closed immediately.
    Close,
}

/// Hot-reloadable domain-fronting destination parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontingRuntimeConfig {
    pub host: String,
    pub port: u16,
    pub proxy_protocol: bool,
    pub unknown_sni_action: UnknownSniAction,
}

/// Wait-free snapshot of active IP allowlist / blocklist filters and their policies.
#[derive(Debug)]
pub struct IpFiltersState {
    pub blocklist: Option<Arc<LiveIpFilter>>,
    pub blocklist_action: IpFilterAction,
    pub blocklist_cfg: ListConfig,
    pub allowlist: Option<Arc<LiveIpFilter>>,
    pub allowlist_action: IpFilterAction,
    pub allowlist_cfg: ListConfig,
}

/// Observability report for one IP filter (blocklist or allowlist).
#[derive(Debug, Clone, Serialize)]
pub struct IpFilterReportEntry {
    pub enabled: bool,
    pub action: String,
    pub rejected_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<LiveIpFilterStatus>,
}

/// Combined status snapshot returned by `GET /ip-filters`.
#[derive(Debug, Clone, Serialize)]
pub struct IpFiltersReport {
    pub allowlist: IpFilterReportEntry,
    pub blocklist: IpFilterReportEntry,
}

/// Partial update payload for `PATCH /secrets/{name}` (updates only specified fields
/// without requiring the caller to resend the secret key or untouched limits!).
#[derive(Debug, Default, Clone)]
pub struct SecretPatch {
    pub secret: Option<Secret>,
    pub ad_tag: Option<Option<[u8; 16]>>,
    pub quota_bytes: Option<i64>,
    pub add_quota_bytes: Option<i64>,
    pub reset_quota: bool,
    pub quota_reset: Option<QuotaReset>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub disabled: Option<bool>,
    pub speed_bytes_per_second: Option<i64>,
    pub speed_up_bytes_per_second: Option<i64>,
    pub speed_down_bytes_per_second: Option<i64>,
    pub ip_limit: Option<u32>,
    pub client_conns: Option<u32>,
    pub max_connections: Option<u32>,
    pub client_speed_bytes_per_second: Option<i64>,
    pub client_speed_up_bytes_per_second: Option<i64>,
    pub client_speed_down_bytes_per_second: Option<i64>,
    pub client_fair: Option<bool>,
    pub conn_speed_bytes_per_second: Option<i64>,
    pub conn_speed_up_bytes_per_second: Option<i64>,
    pub conn_speed_down_bytes_per_second: Option<i64>,
    /// `Some(Some(name))` sets a named outbound override; `Some(None)` clears it.
    pub outbound: Option<Option<String>>,
}

/// Partial live update payload for `PATCH /limits` (updates only specified global knobs).
#[derive(Debug, Default, Clone, Copy)]
pub struct GlobalLimitsPatch {
    pub concurrency: Option<u32>,
    pub throttle_max_connections: Option<u32>,
    pub speed_bytes_per_second: Option<i64>,
    pub speed_up_bytes_per_second: Option<i64>,
    pub speed_down_bytes_per_second: Option<i64>,
    pub quota_bytes: Option<i64>,
    pub add_quota_bytes: Option<i64>,
    pub reset_quota: bool,
    pub quota_reset: Option<QuotaReset>,
    pub max_connections_per_ip: Option<u32>,
    pub max_new_connections_per_ip: Option<u32>,
    pub conn_speed_bytes_per_second: Option<i64>,
    pub conn_speed_up_bytes_per_second: Option<i64>,
    pub conn_speed_down_bytes_per_second: Option<i64>,
}

/// Live server-wide connection & speed shaping report returned by `GET /limits`.
#[derive(Debug, Clone, Serialize)]
pub struct GlobalLimitsReport {
    pub concurrency: u32,
    pub active_connections: i64,
    pub concurrency_limited_total: u64,
    pub throttle_max_connections: i64,
    pub throttle_active: bool,
    pub speed_limit: i64,
    pub speed_limit_up: i64,
    pub speed_limit_down: i64,
    pub throttled_ms: i64,
    pub quota: i64,
    pub quota_used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_remaining: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quota_reset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_start: Option<DateTime<Utc>>,
    pub quota_cutoffs: i64,
    pub max_connections_per_ip: u32,
    pub max_new_connections_per_ip: u32,
    pub active_tracked_ips: usize,
    pub ip_conn_limited_total: u64,
    pub ip_rate_limited_total: u64,
    pub conn_speed_limit: i64,
    pub conn_speed_limit_up: i64,
    pub conn_speed_limit_down: i64,
}

/// One upsert entry for atomic `POST /secrets/batch`.
#[derive(Debug, Clone)]
pub struct BatchUpsertSecret {
    pub name: String,
    pub secret: Secret,
    pub ad_tag: Option<[u8; 16]>,
    pub limits: SecretLimits,
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

/// Active Doppelganger runtime profile, ServerHello anti-DPI settings & traffic shaping.
#[derive(Debug)]
pub struct DoppelState {
    /// True when post-handshake TLS record pacing / DRS is enabled on relayed streams.
    /// Setting `scout-covers = true` alone profiles the cover's `ServerHelloProfile`
    /// without inserting per-record pacing delays on bulk/chat streams!
    pub enabled: bool,
    pub shaping: ShapingMode,
    pub drs: bool,
    pub scout_covers: bool,
    pub scout_urls: Vec<String>,
    /// Enable Post-Quantum `X25519MLKEM768` (`0x11EC`, `1,210 B` ServerHello) when offered (hot-reloadable!).
    pub pq_key_share: AtomicBool,
    /// Two-speed `MSG_EOR` ServerHello TCP fragmentation target MSS (`0` = disabled, hot-reloadable!).
    pub server_hello_fragment_mss: AtomicU16,
    /// Optional minimum randomized ServerHello reply delay in ms (hot-reloadable!).
    pub server_hello_delay_min_ms: AtomicU32,
    /// Optional maximum randomized ServerHello reply delay in ms (hot-reloadable!).
    pub server_hello_delay_max_ms: AtomicU32,
    pub catalog: ArcSwap<crate::doppel_scout::DoppelCatalog>,
}

impl DoppelState {
    /// Look up the live-calibrated [`DoppelParams`] matching the client's SNI
    /// cover domain (or the aggregated default profile if not scouted per-host),
    /// applying the current hot-reloadable `pq_key_share` policy.
    #[inline]
    pub fn params_for_sni(&self, sni_list: &[String]) -> DoppelParams {
        let mut p = self.catalog.load().params_for_sni(sni_list);
        if !self.pq_key_share.load(Ordering::Relaxed) {
            p.server_hello.prefer_pq_mlkem768 = false;
        }
        p
    }
}

/// Configured proxy runtime parameters derived from [`Config`].
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub config_path: Option<PathBuf>,
    pub usage_state_file: Option<PathBuf>,
    pub api_persistence: ApiPersistenceMode,
    pub state_file: Option<PathBuf>,
    pub legacy_proxies: Vec<String>,
    pub api_bind_to: Option<String>,
    pub api_token: String,
    pub bind_to: Vec<String>,
    /// Obfuscated2 modes (`dd` / `plain`) multiplexed onto the primary `bind-to` port
    /// (empty by default = FakeTLS `ee` only).
    pub bind_to_obfs_modes: ModeSet,
    pub listeners: Vec<(String, ListenerPolicy)>,
    pub proxy_protocol_listener: bool,
    pub prefer_ip: PreferIp,
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
    pub global_ip_guard: Arc<GlobalIpGuard>,
    pub faketls_replay: FakeTlsAntiReplay,
    pub obfs2_replay: Obfs2AntiReplay,
    pub ip_filters: ArcSwap<IpFiltersState>,
    pub fronting_cfg: ArcSwap<FrontingRuntimeConfig>,
    pub concurrency_live: AtomicU32,
    pub track_client_ips_live: AtomicBool,
    pub tolerate_time_skewness_ms: AtomicU64,
    pub ignore_time_skew_live: AtomicBool,
    pub dns: Arc<DnsResolver>,
    pub proxy_pool: Option<ProxyPool>,
    pub dc_router: Arc<DcRouter>,
    pub middleproxy: Arc<MiddleProxyPool>,
    pub fronting_pool: Arc<crate::fronting::FrontingPool>,
    pub x25519_keys: X25519KeyRing,
    pub doppel: DoppelState,
    pub metrics: Arc<ProxyMetrics>,
    pub persistence_mode: ApiPersistenceMode,
    pub state_file: Option<PathBuf>,

    /// Monotonic control-plane state revision (powers strong HTTP `ETag` & `If-Match`).
    state_revision: AtomicU64,
    /// Monotonic SSE event ID sequence.
    event_seq: AtomicU64,
    /// Zero-polling real-time control-plane event broadcast bus (`GET /events`).
    event_tx: broadcast::Sender<EngineEvent>,
    /// Per-consumer distributed multi-node billing delta tracker (`POST /accounting/checkpoint`).
    billing: Mutex<BillingTracker>,
    /// Broadcasts a monotonic revision counter whenever `secrets` swaps (so embedded
    /// `[web] integrated = true` syncs instantaneously without 2s polling!).
    secret_sync_tx: watch::Sender<u64>,
    /// Cancels old IP filter background refresh loops cleanly on hot reload.
    ip_filter_loop_cancel: Mutex<Option<watch::Sender<bool>>>,
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

        let legacy_proxies: Vec<String> = cfg.network.proxies.clone().unwrap_or_default();
        let proxy_pool = if legacy_proxies.is_empty() {
            None
        } else {
            Some(
                ProxyPool::from_urls(&legacy_proxies, sock_cfg, tcp_timeout)
                    .map_err(|e| EngineError::Invalid(e.to_string()))?,
            )
        };

        let api_persistence = cfg.api.persistence.unwrap_or(ApiPersistenceMode::Memory);
        let state_file = match api_persistence {
            ApiPersistenceMode::Overlay => Some(
                cfg.api
                    .state_file
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map_or_else(
                        || default_overlay_path(config_path.as_deref()),
                        PathBuf::from,
                    ),
            ),
            ApiPersistenceMode::Memory | ApiPersistenceMode::Toml => cfg
                .api
                .state_file
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        };

        // Load persisted overlay snapshot BEFORE building SecretSet & OutboundRouter when
        // `[api] persistence = "overlay"` so restarts seamlessly restore live API state!
        let overlay_snap = if api_persistence == ApiPersistenceMode::Overlay
            && let Some(ref sf) = state_file
        {
            match load_overlay_verified(sf) {
                Ok(snap) => snap,
                Err(e) => {
                    return Err(EngineError::Persistence(format!(
                        "failed to load overlay state {}: {e}",
                        sf.display()
                    )));
                }
            }
        } else {
            None
        };

        let (initial_ob_specs, initial_ob_groups, initial_routing) =
            if let Some(ref ov) = overlay_snap {
                (
                    ov.outbounds.clone(),
                    ov.outbound_groups.clone(),
                    ov.routing.clone(),
                )
            } else {
                config_to_outbound_specs(cfg)?
            };
        let outbound_router = Arc::new(
            OutboundRouter::build(
                &initial_ob_specs,
                &initial_ob_groups,
                initial_routing,
                &legacy_proxies,
                &dns,
                sock_cfg,
                Vec::new(),
            )
            .map_err(|e| EngineError::Invalid(format!("outbound router init failed: {e}")))?,
        );

        let dc_router = Arc::new(
            DcRouter::new(
                prefer_ip,
                cfg.allow_fallback_on_unknown_dc.unwrap_or(false),
                sock_cfg,
                tcp_timeout,
                proxy_pool.clone(),
            )
            .with_dns(Arc::clone(&dns))
            .with_outbound_router(outbound_router),
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

        let ip_filters = build_ip_filters_state(cfg, &dns, prefer_ip, proxy_pool.clone(), sock_cfg);

        let bind_to_obfs_modes = cfg.get_bind_to_obfs_modes();
        let mut listeners = Vec::with_capacity(cfg.listeners.len());
        let mut listener_reports = Vec::with_capacity(cfg.listeners.len());
        let mut listener_modes = cfg.get_listener_modes();
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

        // If an overlay snapshot was loaded at boot, overlay secrets/limits/ad-tags/concurrency!
        let (secret_set, initial_concurrency, initial_throttle, initial_global_limits, initial_rev) =
            if let Some(ref ov) = overlay_snap {
                let (ov_secrets, ov_limits, ov_tags, ov_global_tag) =
                    parse_runtime_snapshot_secrets(ov)?;
                let retiring = cfg.get_retiring_secrets(now).usable;
                let merged_set = SecretSet::build(
                    &ov_secrets,
                    &ov_limits,
                    &ov_tags,
                    ov_global_tag,
                    &retiring,
                    None,
                );
                info!(
                    revision = ov.revision,
                    secrets = merged_set.records.len(),
                    outbounds = ov.outbounds.len(),
                    "restored persisted runtime state overlay"
                );
                (
                    merged_set,
                    ov.concurrency,
                    ov.throttle_max_connections,
                    GlobalLimits::from(&ov.global_limits),
                    ov.revision.max(1),
                )
            } else {
                (
                    secret_set,
                    cfg.concurrency.unwrap_or(8192),
                    cfg.throttle.max_connections.unwrap_or(0),
                    cfg.get_global_limits(),
                    1,
                )
            };

        let metrics = Arc::new(ProxyMetrics::new(
            workers,
            initial_throttle,
            cfg.throttle
                .check_interval
                .unwrap_or(Duration::from_secs(5)),
        ));
        metrics.global_limits.apply(&initial_global_limits);

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

        let track_client_ips = cfg.track_client_ips.unwrap_or(false);
        // Default 120s skewness (plus built-in boot-time <120s compatibility) prevents
        // mobile/iOS clock-drift reconnect loops out of the box!
        let tolerate_time_skewness = cfg
            .tolerate_time_skewness
            .unwrap_or(Duration::from_secs(120));
        let ignore_time_skew = cfg.ignore_time_skew.unwrap_or(false);
        let fronting_init = FrontingRuntimeConfig {
            host: cfg.get_domain_fronting_host().to_owned(),
            port: cfg.get_domain_fronting_port(443),
            proxy_protocol: cfg.get_domain_fronting_proxy_protocol(false),
            unknown_sni_action: cfg
                .domain_fronting
                .unknown_sni_action
                .unwrap_or(UnknownSniAction::Front),
        };

        let settings = EngineSettings {
            config_path,
            usage_state_file: usage_path,
            api_persistence,
            state_file: state_file.clone(),
            legacy_proxies,
            api_bind_to: cfg.api_bind_to.as_ref().map(|h| h.as_str().to_owned()),
            api_token: (*cfg.api_token).clone(),
            bind_to: cfg.bind_to.iter().map(|b| b.as_str().to_owned()).collect(),
            bind_to_obfs_modes,
            listeners,
            proxy_protocol_listener: cfg.proxy_protocol_listener.unwrap_or(false),
            prefer_ip,
            track_client_ips,
            concurrency: initial_concurrency,
            tolerate_time_skewness,
            tcp_timeout,
            idle_timeout,
            handshake_timeout,
            fronting_host: fronting_init.host.clone(),
            fronting_port: fronting_init.port,
            fronting_proxy_protocol: fronting_init.proxy_protocol,
            public_ipv4: cfg.public_ipv4,
            public_ipv6: cfg.public_ipv6,
            advertised_port,
            sock_cfg,
            worker_count: workers,
            force_epoll,
        };

        let fronting_pool = Arc::new(crate::fronting::FrontingPool::new(
            cfg.public_ipv4,
            cfg.public_ipv6,
        ));

        let doppel_shaping = cfg
            .defense
            .doppelganger
            .shaping
            .unwrap_or(ShapingMode::Burst);
        let doppel_drs = cfg.defense.doppelganger.drs.unwrap_or(false);
        let doppel_scout_covers = cfg.defense.doppelganger.scout_covers.unwrap_or(false);
        let doppel_scout_urls = cfg.defense.doppelganger.urls.clone().unwrap_or_default();
        // Post-handshake pacing/DRS activates ONLY when explicitly requested (`drs`,
        // `shaping`, or `urls`); `scout-covers = true` alone calibrates live cover
        // `ServerHelloProfile` (PQ X25519MLKEM768 + cipher + cert flight) at zero latency!
        let doppel_enabled = !doppel_scout_urls.is_empty()
            || doppel_drs
            || cfg.defense.doppelganger.shaping.is_some();
        let pq_key_share = cfg.defense.doppelganger.pq_key_share.unwrap_or(true);
        let sh_frag_mss = cfg
            .defense
            .doppelganger
            .server_hello_fragment_mss
            .unwrap_or(0);
        let sh_delay_min = cfg
            .defense
            .doppelganger
            .server_hello_delay_min_ms
            .unwrap_or(0);
        let sh_delay_max = cfg
            .defense
            .doppelganger
            .server_hello_delay_max_ms
            .unwrap_or(sh_delay_min);
        let doppel = DoppelState {
            enabled: doppel_enabled,
            shaping: doppel_shaping,
            drs: doppel_drs,
            scout_covers: doppel_scout_covers,
            scout_urls: doppel_scout_urls,
            pq_key_share: AtomicBool::new(pq_key_share),
            server_hello_fragment_mss: AtomicU16::new(sh_frag_mss),
            server_hello_delay_min_ms: AtomicU32::new(sh_delay_min),
            server_hello_delay_max_ms: AtomicU32::new(sh_delay_max),
            catalog: ArcSwap::from_pointee(crate::doppel_scout::DoppelCatalog::from_default(
                DoppelParams {
                    drs: doppel_drs,
                    shaping: doppel_shaping,
                    ..DoppelParams::default()
                },
            )),
        };

        let (secret_sync_tx, _) = watch::channel(0u64);
        let (event_tx, _) = broadcast::channel(512);

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
            global_ip_guard: Arc::new(GlobalIpGuard::new()),
            faketls_replay,
            obfs2_replay,
            ip_filters: ArcSwap::from_pointee(ip_filters),
            fronting_cfg: ArcSwap::from_pointee(fronting_init),
            concurrency_live: AtomicU32::new(initial_concurrency),
            track_client_ips_live: AtomicBool::new(track_client_ips),
            tolerate_time_skewness_ms: AtomicU64::new(
                tolerate_time_skewness.as_millis().min(u128::from(u64::MAX)) as u64,
            ),
            ignore_time_skew_live: AtomicBool::new(ignore_time_skew),
            dns,
            proxy_pool,
            dc_router,
            middleproxy,
            fronting_pool,
            x25519_keys: X25519KeyRing::default(),
            doppel,
            metrics,
            persistence_mode: api_persistence,
            state_file,
            state_revision: AtomicU64::new(initial_rev),
            event_seq: AtomicU64::new(0),
            event_tx,
            billing: Mutex::new(BillingTracker::new()),
            secret_sync_tx,
            ip_filter_loop_cancel: Mutex::new(None),
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

    /// Current hot-reloadable global hard concurrency cap (`0` = unlimited).
    #[inline]
    pub fn concurrency_limit(&self) -> u32 {
        self.concurrency_live.load(Ordering::Acquire)
    }

    /// Hot-reload global concurrency cap without dropping live streams.
    pub fn set_concurrency_limit(&self, cap: u32) {
        self.concurrency_live.store(cap, Ordering::Release);
    }

    /// Snapshot live global limits, usage, throttled time & rejection counts (`GET /limits`).
    pub fn global_limits_report(&self) -> GlobalLimitsReport {
        let gl = &self.metrics.global_limits;
        let snap = gl.snapshot();
        let now = Utc::now();
        gl.rollover_if_needed(now);
        let used = gl.quota_used.load(Ordering::Relaxed);
        let remaining = (snap.quota_bytes > 0).then(|| (snap.quota_bytes - used).max(0));
        let pstart_ns = gl.period_start_ns.load(Ordering::Relaxed);
        let period_start = (pstart_ns > 0).then(|| DateTime::from_timestamp_nanos(pstart_ns));
        let conc_lim: u64 = self
            .metrics
            .cores
            .iter()
            .map(|c| c.concurrency_limited.load(Ordering::Relaxed))
            .sum();
        GlobalLimitsReport {
            concurrency: self.concurrency_limit(),
            active_connections: self.metrics.total_active_connections(),
            concurrency_limited_total: conc_lim,
            throttle_max_connections: self.metrics.throttle_limit.load(Ordering::Acquire),
            throttle_active: self.metrics.throttle_active.load(Ordering::Acquire),
            speed_limit: snap.speed_bytes_per_second,
            speed_limit_up: snap.speed_up_bytes_per_second,
            speed_limit_down: snap.speed_down_bytes_per_second,
            throttled_ms: (gl.speed_throttled_ns.load(Ordering::Relaxed) / 1_000_000) as i64,
            quota: snap.quota_bytes,
            quota_used: used,
            quota_remaining: remaining,
            quota_reset: if matches!(snap.quota_reset, QuotaReset::None) {
                String::new()
            } else {
                snap.quota_reset.as_str().to_owned()
            },
            period_start,
            quota_cutoffs: gl.quota_cutoffs.load(Ordering::Relaxed),
            max_connections_per_ip: snap.max_connections_per_ip,
            max_new_connections_per_ip: snap.max_new_connections_per_ip,
            active_tracked_ips: self.global_ip_guard.active_tracked_ips(),
            ip_conn_limited_total: gl.ip_conn_limited_total.load(Ordering::Relaxed),
            ip_rate_limited_total: gl.ip_rate_limited_total.load(Ordering::Relaxed),
            conn_speed_limit: snap.conn_speed_bytes_per_second,
            conn_speed_limit_up: snap.conn_speed_up_bytes_per_second,
            conn_speed_limit_down: snap.conn_speed_down_bytes_per_second,
        }
    }

    /// Atomically apply a partial or full live update to global connection & speed limits (`PATCH/PUT /limits`).
    pub fn patch_global_limits(&self, patch: GlobalLimitsPatch) -> GlobalLimitsReport {
        if let Some(c) = patch.concurrency {
            self.set_concurrency_limit(c);
        }
        if let Some(t) = patch.throttle_max_connections {
            self.metrics.set_throttle_limit(i64::from(t));
        }
        let mut next = self.metrics.global_limits.snapshot();
        if let Some(s) = patch.speed_bytes_per_second {
            next.speed_bytes_per_second = s.max(0);
        }
        if let Some(s) = patch.speed_up_bytes_per_second {
            next.speed_up_bytes_per_second = s.max(0);
        }
        if let Some(s) = patch.speed_down_bytes_per_second {
            next.speed_down_bytes_per_second = s.max(0);
        }
        if let Some(q) = patch.quota_bytes {
            next.quota_bytes = q.max(0);
        }
        if let Some(add) = patch.add_quota_bytes {
            next.quota_bytes = next.quota_bytes.saturating_add(add).max(0);
        }
        if let Some(qr) = patch.quota_reset {
            next.quota_reset = qr;
        }
        if let Some(mc) = patch.max_connections_per_ip {
            next.max_connections_per_ip = mc;
        }
        if let Some(mr) = patch.max_new_connections_per_ip {
            next.max_new_connections_per_ip = mr;
        }
        if let Some(s) = patch.conn_speed_bytes_per_second {
            next.conn_speed_bytes_per_second = s.max(0);
        }
        if let Some(s) = patch.conn_speed_up_bytes_per_second {
            next.conn_speed_up_bytes_per_second = s.max(0);
        }
        if let Some(s) = patch.conn_speed_down_bytes_per_second {
            next.conn_speed_down_bytes_per_second = s.max(0);
        }
        self.metrics.global_limits.apply(&next);
        if patch.reset_quota {
            self.metrics.global_limits.reset_quota(Utc::now());
        }
        let _ = self.commit_mutation(
            "limits.updated",
            serde_json::json!({ "scope": "global" }),
            true,
        );
        self.global_limits_report()
    }

    /// Replace all server-wide limits (`PUT /limits`).
    pub fn replace_global_limits(
        &self,
        concurrency: Option<u32>,
        throttle_max_connections: Option<u32>,
        limits: &GlobalLimits,
    ) -> GlobalLimitsReport {
        if let Some(c) = concurrency {
            self.set_concurrency_limit(c);
        }
        if let Some(t) = throttle_max_connections {
            self.metrics.set_throttle_limit(i64::from(t));
        }
        self.metrics.global_limits.apply(limits);
        let _ = self.commit_mutation(
            "limits.updated",
            serde_json::json!({ "scope": "global" }),
            true,
        );
        self.global_limits_report()
    }

    /// Reset server-wide quota usage counter to 0 (`POST /limits/reset-quota`).
    pub fn reset_global_quota(&self) -> GlobalLimitsReport {
        self.metrics.global_limits.reset_quota(Utc::now());
        let _ = self.commit_mutation(
            "limits.quota_reset",
            serde_json::json!({ "scope": "global" }),
            false,
        );
        self.global_limits_report()
    }

    // -------------------------------------------------------------------------
    // Enterprise Control Plane: Revisions, ETag/If-Match, Persistence, Outbounds,
    // SSE Events, Atomic Desired-State Convergence & Distributed Billing Deltas
    // -------------------------------------------------------------------------

    /// Current monotonic control-plane state revision (`>= 1`).
    #[inline]
    pub fn state_revision(&self) -> u64 {
        self.state_revision.load(Ordering::Acquire)
    }

    /// Strong HTTP `ETag` matching the current control-plane state revision (`"rev-N"`).
    pub fn state_etag(&self) -> String {
        format!("\"rev-{}\"", self.state_revision())
    }

    /// Validate an optional HTTP `If-Match` precondition header against current `state_revision`.
    /// Returns `Err(current_etag)` when the precondition fails (`412 Precondition Failed`).
    pub fn check_if_match(&self, header: Option<&str>) -> Result<(), String> {
        let rev = self.state_revision();
        if if_match_satisfied(header, rev) {
            Ok(())
        } else {
            Err(format!("\"rev-{rev}\""))
        }
    }

    /// Process-unique 128-bit random boot identifier (used by multi-node billing panels).
    pub fn boot_id(&self) -> String {
        self.billing.lock().boot_id().to_owned()
    }

    /// Subscribe to real-time control-plane SSE events (`GET /events`).
    pub fn subscribe_events(&self) -> broadcast::Receiver<EngineEvent> {
        self.event_tx.subscribe()
    }

    /// Publish an informational event on the SSE broadcast bus without mutating revision.
    pub fn emit_event(&self, event: &'static str, detail: serde_json::Value) {
        let id = self.event_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let rev = self.state_revision();
        let _ = self.event_tx.send(EngineEvent {
            id,
            event,
            revision: rev,
            timestamp: Utc::now(),
            detail,
        });
    }

    /// Bump `state_revision`, emit an SSE event, and (when `persist && mode != Memory`)
    /// crash-safely write the updated runtime snapshot to disk!
    fn commit_mutation(
        &self,
        event: &'static str,
        detail: serde_json::Value,
        persist: bool,
    ) -> Result<u64, EngineError> {
        let rev = self.state_revision.fetch_add(1, Ordering::AcqRel) + 1;
        if persist && self.persistence_mode != ApiPersistenceMode::Memory {
            let snap = self.export_state_snapshot();
            self.persist_snapshot(&snap)?;
        }
        let id = self.event_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.event_tx.send(EngineEvent {
            id,
            event,
            revision: rev,
            timestamp: Utc::now(),
            detail,
        });
        Ok(rev)
    }

    fn persist_snapshot(&self, snap: &RuntimeStateSnapshot) -> Result<(), EngineError> {
        match self.persistence_mode {
            ApiPersistenceMode::Memory => Ok(()),
            ApiPersistenceMode::Overlay => {
                let path = self
                    .state_file
                    .clone()
                    .unwrap_or_else(|| default_overlay_path(self.settings.config_path.as_deref()));
                save_overlay_atomic(&path, snap).map_err(|e| {
                    warn!(path = %path.display(), error = %e, "overlay persistence failed");
                    EngineError::Persistence(format!("overlay write {}: {e}", path.display()))
                })
            }
            ApiPersistenceMode::Toml => {
                let Some(cfg_path) = &self.settings.config_path else {
                    return Err(EngineError::Persistence(
                        "persistence = \"toml\" requires a config file path".to_owned(),
                    ));
                };
                save_toml_atomic(cfg_path, snap).map_err(|e| {
                    warn!(path = %cfg_path.display(), error = %e, "TOML writeback failed");
                    EngineError::Persistence(format!("TOML writeback {}: {e}", cfg_path.display()))
                })
            }
        }
    }

    /// Export complete current mutable control-plane state (`GET /state` & persistence).
    pub fn export_state_snapshot(&self) -> RuntimeStateSnapshot {
        let set = self.secrets.load();
        let mut secrets = BTreeMap::new();
        let mut secret_ad_tags = BTreeMap::new();
        let mut secret_limits = BTreeMap::new();
        for (name, rec) in &set.records {
            secrets.insert(name.clone(), rec.secret.encode_hex());
            if let Some(tag) = rec.ad_tag {
                secret_ad_tags.insert(name.clone(), hex::encode(tag));
            }
            if !rec.limits.is_zero() {
                secret_limits.insert(name.clone(), SecretLimitsSnapshot::from(&rec.limits));
            }
        }
        let global_ad_tag = set.default_ad_tag.map(hex::encode);
        drop(set);

        let (outbounds, outbound_groups, routing) = self.outbound_config_export();
        let gl = self.metrics.global_limits.snapshot();

        RuntimeStateSnapshot {
            schema_version: RUNTIME_STATE_SCHEMA_VERSION,
            revision: self.state_revision(),
            updated_at: Utc::now(),
            secrets,
            secret_ad_tags,
            secret_limits,
            global_ad_tag,
            concurrency: self.concurrency_limit(),
            throttle_max_connections: self
                .metrics
                .throttle_limit
                .load(Ordering::Acquire)
                .clamp(0, i64::from(u32::MAX)) as u32,
            global_limits: GlobalLimitsSnapshot::from(&gl),
            outbounds,
            outbound_groups,
            routing,
        }
    }

    /// Single-call atomic desired-state convergence (`PUT /state`): validates and
    /// builds the new `OutboundRouter` and secret set BEFORE publishing anything,
    /// then swaps outbounds, secrets, limits, and ad-tags atomically!
    pub fn apply_state_snapshot(
        &self,
        desired: &RuntimeStateSnapshot,
    ) -> Result<RuntimeStateSnapshot, EngineError> {
        let (secrets, limits, ad_tags, global_ad_tag) = parse_runtime_snapshot_secrets(desired)?;
        let new_router = Arc::new(
            OutboundRouter::build(
                &desired.outbounds,
                &desired.outbound_groups,
                desired.routing.clone(),
                &self.settings.legacy_proxies,
                &self.dns,
                self.settings.sock_cfg,
                Vec::new(),
            )
            .map_err(|e| EngineError::Invalid(format!("invalid outbounds: {e}")))?,
        );
        // Validate every secret's named outbound target against the new router.
        for (name, lim) in &limits {
            if let Some(ref target) = lim.outbound
                && !new_router.has_target(target)
            {
                return Err(EngineError::Invalid(format!(
                    "secret {name:?} references unknown outbound {target:?}"
                )));
            }
        }

        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();
        let now = self.rotation_clock.now();
        let mut kept_retiring = Vec::new();
        for (name, rec) in &prev.records {
            if secrets.contains_key(name) {
                for r in &rec.retiring {
                    if now < r.until && secrets.get(name).is_none_or(|p| p.key() != r.secret.key())
                    {
                        kept_retiring.push(r.clone());
                    }
                }
            }
        }
        drop(prev);

        // Publish outbounds + secrets + global limits atomically!
        self.dc_router.set_outbound_router(new_router);
        self.swap_secrets_locked(&secrets, &limits, &ad_tags, global_ad_tag, &kept_retiring)?;
        self.set_concurrency_limit(desired.concurrency);
        self.metrics
            .set_throttle_limit(i64::from(desired.throttle_max_connections));
        self.metrics
            .global_limits
            .apply(&GlobalLimits::from(&desired.global_limits));
        self.commit_mutation(
            "state.converged",
            serde_json::json!({
                "secrets": secrets.len(),
                "outbounds": desired.outbounds.len(),
            }),
            true,
        )?;
        Ok(self.export_state_snapshot())
    }

    /// Snapshot live outbound telemetry (`GET /outbounds` & Prometheus).
    pub fn outbound_snapshots(&self) -> Vec<OutboundSnapshot> {
        self.dc_router
            .outbound_router()
            .map(|r| r.snapshots())
            .unwrap_or_default()
    }

    /// Export current declarative outbound specs, groups, and routing policy.
    pub fn outbound_config_export(
        &self,
    ) -> (Vec<OutboundSpec>, Vec<OutboundGroupSpec>, RoutingSpec) {
        self.dc_router
            .outbound_router()
            .map(|r| r.config_export())
            .unwrap_or_default()
    }

    /// True if `name` is a registered outbound node or outbound group.
    pub fn outbound_target_exists(&self, name: &str) -> bool {
        self.dc_router
            .outbound_router()
            .is_some_and(|r| r.has_target(name))
    }

    /// Hot-swap the entire universal outbound engine (`PUT /outbounds`) with zero dropped connections!
    pub fn replace_outbounds(
        &self,
        specs: &[OutboundSpec],
        groups: &[OutboundGroupSpec],
        routing: RoutingSpec,
    ) -> Result<Vec<OutboundSnapshot>, EngineError> {
        let new_router = Arc::new(
            OutboundRouter::build(
                specs,
                groups,
                routing,
                &self.settings.legacy_proxies,
                &self.dns,
                self.settings.sock_cfg,
                Vec::new(),
            )
            .map_err(|e| EngineError::Invalid(format!("invalid outbounds: {e}")))?,
        );
        // Ensure no existing secret is left pointing at a removed outbound!
        let set = self.secrets.load();
        for (name, rec) in &set.records {
            if let Some(ref target) = rec.limits.outbound
                && !new_router.has_target(target)
            {
                return Err(EngineError::Invalid(format!(
                    "secret {name:?} still references outbound {target:?}"
                )));
            }
        }
        drop(set);

        let _reload_guard = self.reload_mu.lock();
        let snaps = new_router.snapshots();
        self.dc_router.set_outbound_router(new_router);
        self.commit_mutation(
            "outbound.updated",
            serde_json::json!({ "count": snaps.len() }),
            true,
        )?;
        Ok(snaps)
    }

    /// Actively probe a named outbound node against Telegram DC2 (or first known DC endpoint).
    pub async fn probe_outbound(&self, name: &str) -> Result<Duration, EngineError> {
        let Some(router) = self.dc_router.outbound_router() else {
            return Err(EngineError::Invalid(
                "outbound router not initialized".into(),
            ));
        };
        let target_addr = self
            .dc_router
            .ranked_direct_addresses(2)
            .into_iter()
            .next()
            .unwrap_or_else(|| "149.154.167.50:443".parse().expect("valid dc2 addr"));
        router
            .probe_named(
                name,
                &OutboundTarget::Addr(target_addr),
                self.settings.tcp_timeout,
            )
            .await
            .map(|res| Duration::from_micros(res.rtt_us))
            .map_err(|e| EngineError::Invalid(e.to_string()))
    }

    /// Compute exact per-consumer billing deltas since the consumer's last checkpoint
    /// (`POST /accounting/checkpoint`).
    pub fn take_billing_checkpoint(
        &self,
        consumer_id: &str,
        peek: bool,
    ) -> Result<BillingCheckpointReport, EngineError> {
        let users = self.metrics.all_users();
        let rows: Vec<(String, u64, u64, u64, u64, u64, i64)> = users
            .into_iter()
            .map(|(name, u)| {
                (
                    name,
                    u.bytes_in.load(Ordering::Relaxed).max(0) as u64,
                    u.bytes_out.load(Ordering::Relaxed).max(0) as u64,
                    u.total_connections.load(Ordering::Relaxed),
                    u.quota_used.load(Ordering::Relaxed).max(0) as u64,
                    u.quota_cutoffs.load(Ordering::Relaxed).max(0) as u64,
                    u.connections.load(Ordering::Relaxed),
                )
            })
            .collect();
        let report = self
            .billing
            .lock()
            .checkpoint(consumer_id, peek, &rows)
            .map_err(EngineError::Invalid)?;
        if !peek {
            self.emit_event(
                "accounting.checkpoint",
                serde_json::json!({
                    "consumer_id": report.consumer_id,
                    "sequence": report.sequence,
                    "total_delta_bytes": report.total_delta_bytes,
                }),
            );
        }
        Ok(report)
    }

    /// Current hot-reloadable `track-client-ips` state.
    #[inline]
    pub fn track_client_ips(&self) -> bool {
        self.track_client_ips_live.load(Ordering::Acquire)
    }

    /// Current hot-reloadable `tolerate-time-skewness` duration.
    #[inline]
    pub fn tolerate_time_skewness(&self) -> Duration {
        Duration::from_millis(self.tolerate_time_skewness_ms.load(Ordering::Acquire))
    }

    /// Current hot-reloadable `ignore-time-skew` flag.
    #[inline]
    pub fn ignore_time_skew(&self) -> bool {
        self.ignore_time_skew_live.load(Ordering::Acquire)
    }

    /// Snapshot of current hot-reloadable domain-fronting destination config.
    #[inline]
    pub fn fronting_config(&self) -> arc_swap::Guard<Arc<FrontingRuntimeConfig>> {
        self.fronting_cfg.load()
    }

    /// Atomically update domain-fronting destination (used by hot-reload and
    /// integrated single-port `[web]` TLS fallback!).
    pub fn set_fronting_config(&self, cfg: FrontingRuntimeConfig) {
        self.fronting_cfg.store(Arc::new(cfg));
    }

    /// Subscribe to real-time secret/retired mutation revisions (for zero-delay
    /// synchronization with embedded `[web] integrated = true`).
    pub fn subscribe_secret_changes(&self) -> watch::Receiver<u64> {
        self.secret_sync_tx.subscribe()
    }

    /// Evaluate configured blocklist and allowlist (`~1 ns` when both are disabled!).
    ///
    /// Precedence:
    /// 1. Explicit `blocklist` match -> increments `blocklisted_total` and applies
    ///    `blocklist_action` (default: `Close`).
    /// 2. `allowlist` miss -> increments `allowlist_rejected_total` and applies
    ///    `allowlist_action` (default: `Front`, Geo-Stealth cover-only!).
    #[inline]
    pub fn check_ip_filters(&self, ip: IpAddr, worker_id: usize) -> IpFilterVerdict {
        let filters = self.ip_filters.load();
        if filters.blocklist.is_none() && filters.allowlist.is_none() {
            return IpFilterVerdict::Allow;
        }
        if let Some(block) = &filters.blocklist
            && block.contains(ip)
        {
            self.metrics
                .core(worker_id)
                .blocklisted_total
                .fetch_add(1, Ordering::Relaxed);
            return match filters.blocklist_action {
                IpFilterAction::Front => IpFilterVerdict::Front,
                IpFilterAction::Close => IpFilterVerdict::Close,
            };
        }
        if let Some(allow) = &filters.allowlist
            && !allow.contains(ip)
        {
            self.metrics
                .core(worker_id)
                .allowlist_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            return match filters.allowlist_action {
                IpFilterAction::Front => IpFilterVerdict::Front,
                IpFilterAction::Close => IpFilterVerdict::Close,
            };
        }
        IpFilterVerdict::Allow
    }

    /// True when fronting target selection does not depend on ClientHello SNI
    /// (dedicated local/reverse-proxy `[domain-fronting].host` or `<= 1` distinct
    /// hosted cover hostname). Allows Geo-Stealth (`IpFilterVerdict::Front`) to
    /// skip ClientHello parsing completely and enter kernel `splice(2)` at byte 0!
    #[inline]
    pub fn has_fixed_fronting_host(&self) -> bool {
        let fcfg = self.fronting_cfg.load();
        if !fcfg.host.is_empty()
            && (fcfg.port != 443
                || fcfg.host.eq_ignore_ascii_case("localhost")
                || fcfg.host.parse::<IpAddr>().is_ok())
        {
            return true;
        }
        self.secrets.load().sni_buckets.len() <= 1
    }

    /// Cold-boot initialization of active blocklist & allowlist filters.
    pub async fn init_ip_filters(&self) {
        let filters = self.ip_filters.load_full();
        if let Some(bl) = &filters.blocklist {
            match bl.init_load().await {
                Ok(n) => {
                    self.metrics
                        .blocklist_size
                        .store(n as u64, Ordering::Release);
                }
                Err(e) => warn!(error = %e, "initial blocklist load failed"),
            }
        }
        if let Some(al) = &filters.allowlist {
            match al.init_load().await {
                Ok(n) => {
                    self.metrics
                        .allowlist_size
                        .store(n as u64, Ordering::Release);
                }
                Err(e) => warn!(error = %e, "initial allowlist load failed"),
            }
        }
    }

    /// Spawn (or replace) background refresh loops for the currently active `ip_filters`.
    pub fn restart_ip_filter_refresh_loops(&self) {
        let (tx, rx) = watch::channel(false);
        if let Some(prev) = self.ip_filter_loop_cancel.lock().replace(tx) {
            let _ = prev.send(true);
        }
        let filters = self.ip_filters.load_full();
        if let Some(bl) = &filters.blocklist {
            let m = Arc::clone(&self.metrics);
            bl.spawn_refresh_loop_with_hook(rx.clone(), move |n| {
                m.blocklist_size.store(n as u64, Ordering::Release);
            });
        } else {
            self.metrics.blocklist_size.store(0, Ordering::Release);
        }
        if let Some(al) = &filters.allowlist {
            let m = Arc::clone(&self.metrics);
            al.spawn_refresh_loop_with_hook(rx, move |n| {
                m.allowlist_size.store(n as u64, Ordering::Release);
            });
        } else {
            self.metrics.allowlist_size.store(0, Ordering::Release);
        }
    }

    /// Trigger a non-blocking background refresh of active blocklist / allowlist
    /// feeds (e.g. on `SIGHUP`) and update live Prometheus/StatsD size gauges.
    pub fn trigger_ip_filter_refresh(&self) {
        let filters = self.ip_filters.load_full();
        if let Some(bl) = filters.blocklist.clone() {
            let m = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                if let Ok(n) = bl.refresh_once().await {
                    m.blocklist_size.store(n as u64, Ordering::Release);
                }
            });
        }
        if let Some(al) = filters.allowlist.clone() {
            let m = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                if let Ok(n) = al.refresh_once().await {
                    m.allowlist_size.store(n as u64, Ordering::Release);
                }
            });
        }
    }

    /// Synchronously refresh active IP filters and return the fresh status report
    /// (for `POST /ip-filters/refresh`).
    pub async fn refresh_ip_filters_now(&self) -> IpFiltersReport {
        let filters = self.ip_filters.load_full();
        if let Some(bl) = &filters.blocklist
            && let Ok(n) = bl.refresh_once().await
        {
            self.metrics
                .blocklist_size
                .store(n as u64, Ordering::Release);
        }
        if let Some(al) = &filters.allowlist
            && let Ok(n) = al.refresh_once().await
        {
            self.metrics
                .allowlist_size
                .store(n as u64, Ordering::Release);
        }
        self.ip_filters_status()
    }

    /// Snapshot live status of both allowlist and blocklist (for `GET /ip-filters` & `/healthz`).
    pub fn ip_filters_status(&self) -> IpFiltersReport {
        let filters = self.ip_filters.load();
        let mut bl_rej = 0u64;
        let mut al_rej = 0u64;
        for c in &self.metrics.cores {
            bl_rej += c.blocklisted_total.load(Ordering::Relaxed);
            al_rej += c.allowlist_rejected_total.load(Ordering::Relaxed);
        }
        IpFiltersReport {
            allowlist: IpFilterReportEntry {
                enabled: filters.allowlist.is_some(),
                action: filters.allowlist_action.as_str().to_owned(),
                rejected_total: al_rej,
                status: filters.allowlist.as_ref().map(|f| f.status()),
            },
            blocklist: IpFilterReportEntry {
                enabled: filters.blocklist.is_some(),
                action: filters.blocklist_action.as_str().to_owned(),
                rejected_total: bl_rej,
                status: filters.blocklist.as_ref().map(|f| f.status()),
            },
        }
    }

    /// Resolve ordered fronting candidate hostnames (primary SNI-matched cover
    /// first, followed by configured fallback & alternate hosted covers for
    /// automatic failover without ever accepting arbitrary SSRF targets).
    pub fn fronting_hosts_for(&self, sni_candidates: &[String]) -> Vec<String> {
        let fcfg = self.fronting_cfg.load();
        let explicit = &fcfg.host;
        // Dedicated local/reverse-proxy cover (e.g., nginx/caddy on non-443 or loopback/IP literal)
        // always takes strict precedence over public hosted SNI covers.
        if !explicit.is_empty()
            && (fcfg.port != 443
                || explicit.eq_ignore_ascii_case("localhost")
                || explicit.parse::<IpAddr>().is_ok())
        {
            return vec![explicit.clone()];
        }

        let mut out: Vec<String> = Vec::with_capacity(4);
        let push_unique = |list: &mut Vec<String>, host: &str| {
            if host.is_empty() {
                return;
            }
            if !list.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                list.push(host.to_owned());
            }
        };

        let set = self.secrets.load();
        // 1. Exact SNI-matched hosted secret cover (guarantees matching TLS certificate!).
        for sni in sni_candidates {
            if set.sni_bucket(sni).is_some() {
                push_unique(&mut out, sni);
                break;
            }
        }
        // 2. Configured explicit `[domain-fronting].host` fallback.
        if !explicit.is_empty() {
            push_unique(&mut out, explicit);
        }
        // 3. Up to 3 total distinct hosted secret covers for automatic failover.
        for rec in set.records.values() {
            if out.len() >= 3 {
                break;
            }
            if rec.secret.is_hosted() {
                push_unique(&mut out, rec.secret.host());
            }
        }
        out
    }

    /// Resolve primary fronting hostname for an unmatched or denied FakeTLS handshake.
    pub fn fronting_host_for(&self, sni_candidates: &[String]) -> String {
        self.fronting_hosts_for(sni_candidates)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    /// Trigger non-blocking background pre-warming of a standby TCP socket to
    /// the cover origin for `sni_candidates`. Called after valid FakeTLS
    /// handshakes so reactive active DPI probes (replay or fresh TLS probe
    /// arriving seconds later) experience **0 ms proxy->cover TCP RTT**!
    pub fn prewarm_fronting_cover(&self, sni_candidates: &[String]) {
        let fcfg = self.fronting_cfg.load();
        if fcfg.port != 443 || !self.fronting_pool.try_claim_prewarm_tick() {
            return;
        }
        if let Some(primary) = self.fronting_hosts_for(sni_candidates).into_iter().next() {
            self.fronting_pool.schedule_warm_refill(
                &primary,
                fcfg.port,
                self.settings.tcp_timeout,
                Arc::clone(&self.dns),
                self.proxy_pool.clone(),
                self.settings.sock_cfg,
            );
        }
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

        self.metrics.global_limits.rollover_if_needed(now);
        if self.metrics.global_limits.is_quota_exceeded() {
            return Err(());
        }

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
        if limits.max_connections > 0
            && user.connections.load(Ordering::Relaxed) >= i64::from(limits.max_connections)
        {
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
        user.total_connections.fetch_add(1, Ordering::Relaxed);
        user.last_seen_unix
            .store(now.timestamp(), Ordering::Relaxed);
        if retiring {
            user.retiring_connections.fetch_add(1, Ordering::Relaxed);
            user.retiring_last_seen_ns
                .store(now.timestamp_nanos_opt().unwrap_or(0), Ordering::Relaxed);
        }
        if self.track_client_ips()
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

    /// Full async hot-reload from `config_path`: atomically reloads secrets,
    /// per-secret limits, ad-tags, retiring-secrets, `[throttle] max-connections`,
    /// `track-client-ips`, `tolerate-time-skewness`, `[domain-fronting]` destination,
    /// AND `[defense.allowlist]` / `[defense.blocklist]` (pre-loading new IP feeds
    /// BEFORE swapping so zero traffic slips through an empty list!).
    ///
    /// If parsing or validation fails, nothing is mutated and live connections stay untouched.
    pub async fn reload_from_disk_async(&self) -> Result<Vec<String>, EngineError> {
        let cfg = self.read_and_validate_reload_config()?;

        // Check if allowlist / blocklist configuration structurally changed.
        let prev_filters = self.ip_filters.load_full();
        let filters_changed = prev_filters.allowlist_cfg != cfg.defense.allowlist
            || prev_filters.blocklist_cfg != cfg.defense.blocklist;

        if filters_changed {
            let next_filters = build_ip_filters_state(
                &cfg,
                &self.dns,
                self.settings.prefer_ip,
                self.proxy_pool.clone(),
                self.settings.sock_cfg,
            );
            // Warm-load new filters BEFORE swapping so zero requests see an unready filter!
            if let Some(bl) = &next_filters.blocklist {
                match bl.init_load().await {
                    Ok(n) => self
                        .metrics
                        .blocklist_size
                        .store(n as u64, Ordering::Release),
                    Err(e) => warn!(error = %e, "hot-reload blocklist load failed"),
                }
            }
            if let Some(al) = &next_filters.allowlist {
                match al.init_load().await {
                    Ok(n) => self
                        .metrics
                        .allowlist_size
                        .store(n as u64, Ordering::Release),
                    Err(e) => warn!(error = %e, "hot-reload allowlist load failed"),
                }
            }
            self.ip_filters.store(Arc::new(next_filters));
            self.restart_ip_filter_refresh_loops();
            info!("hot-reloaded IP allowlist/blocklist configuration");
        } else {
            self.trigger_ip_filter_refresh();
        }

        self.apply_reloaded_config_sync(&cfg)
    }

    /// Synchronous reload of secrets, limits, ad-tags, retiring blocks, throttle,
    /// tracking, skewness, and fronting config from `config_path`.
    pub fn reload_from_disk(&self) -> Result<Vec<String>, EngineError> {
        let cfg = self.read_and_validate_reload_config()?;
        self.apply_reloaded_config_sync(&cfg)
    }

    fn read_and_validate_reload_config(&self) -> Result<Config, EngineError> {
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
        Ok(cfg)
    }

    fn apply_reloaded_config_sync(&self, cfg: &Config) -> Result<Vec<String>, EngineError> {
        let now = self.rotation_clock.now();
        let retiring_report = cfg.get_retiring_secrets(now);
        let secrets = cfg.get_secrets();
        let limits = cfg.get_secret_limits();
        let ad_tags = cfg.get_secret_ad_tags();
        let default_ad_tag = cfg.ad_tag.as_deref().copied();

        let (ob_specs, ob_groups, ob_routing) = config_to_outbound_specs(cfg)?;
        let legacy_proxies: Vec<String> = cfg.network.proxies.clone().unwrap_or_default();
        let next_router = Arc::new(
            OutboundRouter::build(
                &ob_specs,
                &ob_groups,
                ob_routing,
                &legacy_proxies,
                &self.dns,
                self.settings.sock_cfg,
                Vec::new(),
            )
            .map_err(|e| EngineError::Reload(format!("invalid outbounds in reload: {e}")))?,
        );

        let _reload_guard = self.reload_mu.lock();
        self.dc_router.set_outbound_router(next_router);
        self.swap_secrets_locked(
            &secrets,
            &limits,
            &ad_tags,
            default_ad_tag,
            &retiring_report.usable,
        )?;

        // Hot-reload live operational knobs atomically with zero connection drops!
        self.set_concurrency_limit(cfg.concurrency.unwrap_or(8192));
        self.metrics.global_limits.apply(&cfg.get_global_limits());
        self.metrics
            .set_throttle_limit(i64::from(cfg.throttle.max_connections.unwrap_or(0)));
        self.track_client_ips_live
            .store(cfg.track_client_ips.unwrap_or(false), Ordering::Release);
        let skew = cfg
            .tolerate_time_skewness
            .unwrap_or(Duration::from_secs(120));
        self.tolerate_time_skewness_ms.store(
            skew.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Release,
        );
        self.ignore_time_skew_live
            .store(cfg.ignore_time_skew.unwrap_or(false), Ordering::Release);
        self.doppel.pq_key_share.store(
            cfg.defense.doppelganger.pq_key_share.unwrap_or(true),
            Ordering::Release,
        );
        self.doppel.server_hello_fragment_mss.store(
            cfg.defense
                .doppelganger
                .server_hello_fragment_mss
                .unwrap_or(0),
            Ordering::Release,
        );
        let d_min = cfg
            .defense
            .doppelganger
            .server_hello_delay_min_ms
            .unwrap_or(0);
        let d_max = cfg
            .defense
            .doppelganger
            .server_hello_delay_max_ms
            .unwrap_or(d_min);
        self.doppel
            .server_hello_delay_min_ms
            .store(d_min, Ordering::Release);
        self.doppel
            .server_hello_delay_max_ms
            .store(d_max, Ordering::Release);
        let new_fronting = FrontingRuntimeConfig {
            host: cfg.get_domain_fronting_host().to_owned(),
            port: cfg.get_domain_fronting_port(443),
            proxy_protocol: cfg.get_domain_fronting_proxy_protocol(false),
            unknown_sni_action: cfg
                .domain_fronting
                .unknown_sni_action
                .unwrap_or(UnknownSniAction::Front),
        };
        if !new_fronting.host.is_empty()
            || self.fronting_cfg.load().host != new_fronting.host
            || self.fronting_cfg.load().unknown_sni_action != new_fronting.unknown_sni_action
        {
            // Preserve auto-bound integrated TLS cover when config has no explicit host override.
            let prev = self.fronting_cfg.load();
            let preserve_integrated = cfg.get_domain_fronting_host().is_empty()
                && !prev.host.is_empty()
                && prev.host == "127.0.0.1"
                && prev.port != 443;
            if preserve_integrated {
                self.fronting_cfg.store(Arc::new(FrontingRuntimeConfig {
                    host: prev.host.clone(),
                    port: prev.port,
                    proxy_protocol: prev.proxy_protocol,
                    unknown_sni_action: new_fronting.unknown_sni_action,
                }));
            } else {
                self.fronting_cfg.store(Arc::new(new_fronting));
            }
        }

        let _ = self.commit_mutation(
            "config.reloaded",
            serde_json::json!({ "secrets": secrets.len() }),
            false,
        );
        Ok(retiring_report.lines)
    }

    /// `PATCH /secrets/{name}` — partial atomic update of an existing account
    /// (supports top-up `add_quota_bytes`, `reset_quota`, `disabled`, `expires`,
    /// speed/ip/conn limits, `ad_tag`, or key rotation without resending untouched fields!).
    pub fn patch_secret(&self, name: &str, patch: SecretPatch) -> Result<(), EngineError> {
        let _reload_guard = self.reload_mu.lock();
        let prev = self.secrets.load();
        if !prev.contains(name) {
            return Err(EngineError::SecretNotFound(name.to_owned()));
        }

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
            retiring.extend(rec.retiring.iter().cloned());
        }
        drop(prev);

        if let Some(new_sec) = patch.secret {
            if !new_sec.is_valid() {
                return Err(EngineError::Invalid("invalid secret".to_owned()));
            }
            retiring.retain(|r| r.secret.key() != new_sec.key());
            secrets.insert(name.to_owned(), new_sec);
        }
        if let Some(tag_opt) = patch.ad_tag {
            if let Some(t) = tag_opt {
                all_tags.insert(name.to_owned(), t);
            } else {
                all_tags.remove(name);
            }
        }

        let mut lim = all_limits.remove(name).unwrap_or_default();
        if let Some(q) = patch.quota_bytes {
            lim.quota_bytes = q.max(0);
        }
        if let Some(add_q) = patch.add_quota_bytes {
            if add_q < 0 {
                return Err(EngineError::Invalid(
                    "add_quota must not be negative".to_owned(),
                ));
            }
            lim.quota_bytes = lim.quota_bytes.saturating_add(add_q);
        }
        if let Some(qr) = patch.quota_reset {
            lim.quota_reset = qr;
        }
        if let Some(exp) = patch.expires_at {
            lim.expires_at = exp;
        }
        if let Some(dis) = patch.disabled {
            lim.disabled = dis;
        }
        if let Some(sp) = patch.speed_bytes_per_second {
            lim.speed_bytes_per_second = sp;
        }
        if let Some(sp) = patch.speed_up_bytes_per_second {
            lim.speed_up_bytes_per_second = sp;
        }
        if let Some(sp) = patch.speed_down_bytes_per_second {
            lim.speed_down_bytes_per_second = sp;
        }
        if let Some(il) = patch.ip_limit {
            lim.ip_limit = il;
        }
        if let Some(cc) = patch.client_conns {
            lim.client_conns = cc;
        }
        if let Some(mc) = patch.max_connections {
            lim.max_connections = mc;
        }
        if let Some(cs) = patch.client_speed_bytes_per_second {
            lim.client_speed_bytes_per_second = cs;
        }
        if let Some(csu) = patch.client_speed_up_bytes_per_second {
            lim.client_speed_up_bytes_per_second = csu;
        }
        if let Some(csd) = patch.client_speed_down_bytes_per_second {
            lim.client_speed_down_bytes_per_second = csd;
        }
        if let Some(cf) = patch.client_fair {
            lim.client_fair = cf;
        }
        if let Some(cs) = patch.conn_speed_bytes_per_second {
            lim.conn_speed_bytes_per_second = cs;
        }
        if let Some(csu) = patch.conn_speed_up_bytes_per_second {
            lim.conn_speed_up_bytes_per_second = csu;
        }
        if let Some(csd) = patch.conn_speed_down_bytes_per_second {
            lim.conn_speed_down_bytes_per_second = csd;
        }
        if let Some(ob_opt) = patch.outbound {
            if let Some(ref target) = ob_opt {
                let trimmed = target.trim();
                if trimmed.is_empty() {
                    lim.outbound = None;
                } else {
                    if !self.outbound_target_exists(trimmed) {
                        return Err(EngineError::Invalid(format!(
                            "unknown outbound {trimmed:?}"
                        )));
                    }
                    lim.outbound = Some(trimmed.to_owned());
                }
            } else {
                lim.outbound = None;
            }
        }
        if lim.client_fair && !lim.fair_totals().is_active() {
            return Err(EngineError::Invalid(
                "client_fair requires speed, speed_up, or speed_down".to_owned(),
            ));
        }
        if !lim.is_zero() {
            all_limits.insert(name.to_owned(), lim);
        }

        if patch.reset_quota {
            self.metrics.reset_quota(name, Utc::now());
        }

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)?;
        self.commit_mutation("secret.patched", serde_json::json!({ "name": name }), true)?;
        Ok(())
    }

    /// `POST /secrets/{name}/disconnect` — immediately cancel ALL live streams of `secret_name`.
    pub fn disconnect_secret_all(&self, secret_name: &str) -> Result<usize, EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        let tokens: Vec<CancelToken> = {
            let _live_guard = self.live_gate.write_all();
            let mut out = Vec::new();
            for shard in &self.live_conns {
                let conns = shard.0.lock();
                for slot in conns.values() {
                    if slot.secret_name.as_ref() == secret_name {
                        out.push(slot.cancel.clone());
                    }
                }
            }
            out
        };
        let count = tokens.len();
        for tok in tokens {
            tok.cancel();
        }
        Ok(count)
    }

    /// `POST /secrets/batch` — atomic bulk upsert + delete in a single `ArcSwap` publish!
    pub fn batch_mutate_secrets(
        &self,
        upserts: Vec<BatchUpsertSecret>,
        deletes: &[String],
    ) -> Result<(usize, usize), EngineError> {
        const MAX_BATCH: usize = 1_000;
        if upserts.len() + deletes.len() > MAX_BATCH {
            return Err(EngineError::Invalid(format!(
                "batch exceeds maximum of {MAX_BATCH} operations"
            )));
        }
        for u in &upserts {
            if u.name.is_empty() {
                return Err(EngineError::Invalid(
                    "empty secret name in batch".to_owned(),
                ));
            }
            if !u.secret.is_valid() {
                return Err(EngineError::Invalid(format!(
                    "invalid secret for {:?}",
                    u.name
                )));
            }
            if let Some(ref target) = u.limits.outbound
                && !self.outbound_target_exists(target)
            {
                return Err(EngineError::Invalid(format!(
                    "secret {:?} references unknown outbound {target:?}",
                    u.name
                )));
            }
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
            retiring.extend(rec.retiring.iter().cloned());
        }
        drop(prev);

        let mut deleted_count = 0usize;
        for name in deletes {
            if secrets.remove(name).is_some() {
                all_limits.remove(name);
                all_tags.remove(name);
                retiring.retain(|r| r.name != *name);
                deleted_count += 1;
            }
        }

        let upserted_count = upserts.len();
        for u in upserts {
            retiring.retain(|r| r.secret.key() != u.secret.key());
            secrets.insert(u.name.clone(), u.secret);
            if let Some(t) = u.ad_tag {
                all_tags.insert(u.name.clone(), t);
            } else {
                all_tags.remove(&u.name);
            }
            if u.limits.is_zero() {
                all_limits.remove(&u.name);
            } else {
                all_limits.insert(u.name, u.limits);
            }
        }

        if secrets.is_empty() {
            return Err(EngineError::LastSecret);
        }

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)?;
        self.commit_mutation(
            "secrets.batch",
            serde_json::json!({ "upserted": upserted_count, "deleted": deleted_count }),
            true,
        )?;
        Ok((upserted_count, deleted_count))
    }

    /// Force an immediate atomic flush of `usage-state-file` (returns `Ok(false)` if unset).
    pub fn flush_usage_now(&self) -> Result<bool, EngineError> {
        let Some(path) = &self.settings.usage_state_file else {
            return Ok(false);
        };
        self.metrics
            .flush_usage_atomic(path)
            .map_err(|e| EngineError::Reload(format!("usage flush failed: {e}")))?;
        Ok(true)
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
        for (name, lim) in limits {
            if let Some(ref target) = lim.outbound
                && !self.outbound_target_exists(target)
            {
                return Err(EngineError::Invalid(format!(
                    "secret {name:?} references unknown outbound {target:?}"
                )));
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

        self.swap_secrets_locked(secrets, limits, ad_tags, default_ad_tag, &kept_retiring)?;
        self.commit_mutation(
            "secrets.replaced",
            serde_json::json!({ "count": secrets.len() }),
            true,
        )?;
        Ok(())
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
        if let Some(ref target) = limits.outbound
            && !self.outbound_target_exists(target)
        {
            return Err(EngineError::Invalid(format!(
                "secret {name:?} references unknown outbound {target:?}"
            )));
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
            all_limits.insert(name.clone(), limits);
        }

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)?;
        let mut detail = serde_json::Map::with_capacity(1);
        detail.insert("name".to_owned(), serde_json::Value::String(name));
        self.commit_mutation("secret.upserted", serde_json::Value::Object(detail), true)?;
        Ok(())
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

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, default_tag, &retiring)?;
        self.commit_mutation("secret.deleted", serde_json::json!({ "name": name }), true)?;
        Ok(())
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

        self.swap_secrets_locked(&secrets, &all_limits, &all_tags, tag, &retiring)?;
        self.commit_mutation(
            "adtag.updated",
            serde_json::json!({ "set": tag.is_some() }),
            true,
        )?;
        Ok(())
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
        // Notify embedded `[web] integrated = true` subscribers immediately!
        self.secret_sync_tx.send_modify(|rev| {
            *rev = rev.wrapping_add(1);
        });

        // Synchronize client table ceilings, fair-share totals, bans, and close stale streams!
        let now_ns = coarse_now_ns();
        let now = Utc::now();
        let to_cancel: Vec<CancelToken> = {
            let _live_guard = self.live_gate.write_all();

            self.clients.apply_ceilings(|name| {
                new_set.records.get(name).map(|r| {
                    (
                        r.limits.client_speed_bytes_per_second,
                        r.limits.client_speed_up_bytes_per_second,
                        r.limits.client_speed_down_bytes_per_second,
                    )
                })
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
        self.emit_event(
            "client.kicked",
            serde_json::json!({ "secret": secret_name, "closed": closed }),
        );
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
        if self.track_client_ips() {
            addresses = dedup.iter().map(ToString::to_string).collect();
            addresses.sort();
        }
        self.emit_event(
            "client.banned",
            serde_json::json!({ "secret": secret_name, "banned": dedup.len(), "closed": closed }),
        );
        Ok((dedup.len(), closed, addresses))
    }

    /// `DELETE /secrets/{name}/bans/{address...}`.
    pub fn unban_unit(&self, secret_name: &str, unit: IpUnit) -> Result<bool, EngineError> {
        if !self.secrets.load().contains(secret_name) {
            return Err(EngineError::SecretNotFound(secret_name.to_owned()));
        }
        let removed = self.bans.remove(secret_name, unit, Utc::now());
        if removed {
            self.emit_event(
                "client.unbanned",
                serde_json::json!({ "secret": secret_name }),
            );
        }
        Ok(removed)
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

    /// Trigger graceful shutdown, signalling all active connections and IP filter refreshers.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        if let Some(tx) = self.ip_filter_loop_cancel.lock().take() {
            let _ = tx.send(true);
        }
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
        if !self.track_client_ips() {
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
        if !self.track_client_ips() {
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

        // 2. IP blocklist / allowlist periodic refresh (hot-reloadable, live gauges!)
        self.restart_ip_filter_refresh_loops();

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
                            engine.global_ip_guard.sweep_stale_rates(coarse_now_ns());
                            // Also close streams of newly-expired retiring keys or expired users
                            engine.sweep_expired_streams();
                        }
                        _ = usage_tick.tick() => {
                            if let Some(path) = &engine.settings.usage_state_file
                                && let Err(e) = engine.metrics.flush_usage_if_dirty(path)
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
        //    distinct FakeTLS fronting hosts to calibrate exact cover ServerHelloProfile
        //    — PQ X25519MLKEM768, cipher, extension order, cert-flight noise + Weibull + DRS)
        if !self.doppel.scout_urls.is_empty() || self.doppel.scout_covers {
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
                                engine.doppel.catalog.store(Arc::new(updated));
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

/// Convert declarative `[outbound]` / `[outbound-group]` / `[routing]` config tables into `mtg-net` specs.
fn config_to_outbound_specs(
    cfg: &Config,
) -> Result<(Vec<OutboundSpec>, Vec<OutboundGroupSpec>, RoutingSpec), EngineError> {
    let mut specs = Vec::with_capacity(cfg.outbounds.len());
    for ob in &cfg.outbounds {
        specs.push(OutboundSpec {
            name: ob.name.trim().to_owned(),
            url: ob.url.trim().to_owned(),
            interface: ob
                .interface
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            bind_ipv4: ob.bind_ipv4,
            bind_ipv6: ob.bind_ipv6,
            fwmark: ob.fwmark,
            weight: ob.weight.unwrap_or(100),
            max_fails: ob.max_fails.unwrap_or(5),
            cooldown_secs: ob.cooldown.map_or(30, |d| d.as_secs()),
        });
    }

    let mut groups = Vec::with_capacity(cfg.outbound_groups.len());
    for g in &cfg.outbound_groups {
        let strategy = match g.strategy.as_deref() {
            None => OutboundStrategy::EwmaRtt,
            Some(raw) => raw.parse::<OutboundStrategy>().map_err(|e| {
                EngineError::Invalid(format!("invalid outbound strategy {raw:?}: {e}"))
            })?,
        };
        groups.push(OutboundGroupSpec {
            name: g.name.trim().to_owned(),
            strategy,
            members: g.members.iter().map(|m| m.trim().to_owned()).collect(),
        });
    }

    let mut dc_routes = BTreeMap::new();
    for (&dc_id, target) in &cfg.routing.dc {
        dc_routes.insert(dc_id, target.trim().to_owned());
    }
    let routing = RoutingSpec {
        default_outbound: cfg
            .routing
            .default_outbound
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        dc_routes,
    };

    Ok((specs, groups, routing))
}

#[allow(clippy::type_complexity)]
fn parse_runtime_snapshot_secrets(
    snap: &RuntimeStateSnapshot,
) -> Result<
    (
        BTreeMap<String, Secret>,
        BTreeMap<String, SecretLimits>,
        BTreeMap<String, [u8; 16]>,
        Option<[u8; 16]>,
    ),
    EngineError,
> {
    if snap.secrets.is_empty() {
        return Err(EngineError::Invalid(
            "state snapshot must contain at least one secret".to_owned(),
        ));
    }
    let mut secrets = BTreeMap::new();
    for (name, raw) in &snap.secrets {
        if name.trim().is_empty() {
            return Err(EngineError::Invalid(
                "secret name cannot be empty".to_owned(),
            ));
        }
        let sec = Secret::parse(raw)
            .map_err(|e| EngineError::Invalid(format!("invalid secret for {name:?}: {e}")))?;
        secrets.insert(name.clone(), sec);
    }

    let mut ad_tags = BTreeMap::new();
    for (name, hex_tag) in &snap.secret_ad_tags {
        if !secrets.contains_key(name) {
            continue;
        }
        let tag = parse_hex_ad_tag(hex_tag)?;
        ad_tags.insert(name.clone(), tag);
    }

    let global_ad_tag = match &snap.global_ad_tag {
        Some(raw) if !raw.trim().is_empty() => Some(parse_hex_ad_tag(raw)?),
        _ => None,
    };

    let mut limits = BTreeMap::new();
    for (name, lim_snap) in &snap.secret_limits {
        if !secrets.contains_key(name) {
            continue;
        }
        let lim = SecretLimits::from(lim_snap.clone());
        if lim.client_fair && !lim.fair_totals().is_active() {
            return Err(EngineError::Invalid(format!(
                "secret {name:?}: client_fair requires speed, speed_up, or speed_down"
            )));
        }
        if !lim.is_zero() {
            limits.insert(name.clone(), lim);
        }
    }

    Ok((secrets, limits, ad_tags, global_ad_tag))
}

fn parse_hex_ad_tag(raw: &str) -> Result<[u8; 16], EngineError> {
    let bytes = hex::decode(raw.trim())
        .map_err(|_| EngineError::Invalid(format!("invalid hex ad_tag {raw:?}")))?;
    if bytes.len() != 16 {
        return Err(EngineError::Invalid(format!(
            "ad_tag must be 32 hex chars (16 bytes), got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Helper to build an [`IpFiltersState`] from validated [`Config`].
fn build_ip_filters_state(
    cfg: &Config,
    dns: &Arc<DnsResolver>,
    prefer_ip: PreferIp,
    proxy_pool: Option<ProxyPool>,
    sock_cfg: SocketConfig,
) -> IpFiltersState {
    let blocklist_action = cfg
        .defense
        .blocklist
        .action
        .unwrap_or(IpFilterAction::Close);
    let blocklist = if cfg.defense.blocklist.enabled.unwrap_or(false) {
        Some(Arc::new(LiveIpFilter::from_list_config(
            &cfg.defense.blocklist,
            Some(Arc::clone(dns)),
            prefer_ip,
            proxy_pool.clone(),
            sock_cfg,
        )))
    } else {
        None
    };

    let allowlist_action = cfg
        .defense
        .allowlist
        .action
        .unwrap_or(IpFilterAction::Front);
    let allowlist = if cfg.defense.allowlist.enabled.unwrap_or(false) {
        Some(Arc::new(LiveIpFilter::from_list_config(
            &cfg.defense.allowlist,
            Some(Arc::clone(dns)),
            prefer_ip,
            proxy_pool,
            sock_cfg,
        )))
    } else {
        None
    };

    IpFiltersState {
        blocklist,
        blocklist_action,
        blocklist_cfg: cfg.defense.blocklist.clone(),
        allowlist,
        allowlist_action,
        allowlist_cfg: cfg.defense.allowlist.clone(),
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
