//! Per-core cache-line-aligned counters, per-secret runtime metrics,
//! connection-count fair throttle, crash-safe atomic `usage.json` persistence,
//! Prometheus exposition renderer, and 1-second batched StatsD UDP exporter.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::net::{IpAddr, UdpSocket};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike as _, Utc};
use mtg_config::StatsdTagFormat;
use mtg_core::{GlobalLimits, QuotaReset};
use mtg_governance::{GcraLimiter, secret_burst};
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Cache-line-aligned per-worker hot counters (eliminates false sharing across cores).
#[repr(align(64))]
#[derive(Debug, Default)]
pub struct CoreMetrics {
    pub accepted_total: AtomicU64,
    pub active_conns_v4: AtomicI64,
    pub active_conns_v6: AtomicI64,
    pub fronted_conns_v4: AtomicI64,
    pub fronted_conns_v6: AtomicI64,
    pub fronted_total: AtomicU64,
    pub fronted_bytes_from_client: AtomicU64,
    pub fronted_bytes_to_client: AtomicU64,
    pub replay_attacks: AtomicU64,
    pub concurrency_limited: AtomicU64,
    pub throttled_total: AtomicU64,
    pub ip_limited_total: AtomicU64,
    pub blocklisted_total: AtomicU64,
    pub allowlist_rejected_total: AtomicU64,
}

/// FakeTLS door handshake counters matching `/stats` `faketls_handshake`, plus
/// v2.5 anti-DPI & Post-Quantum telemetry exported to Prometheus.
#[derive(Debug, Default)]
pub struct FakeTlsCounters {
    pub hinted: AtomicI64,
    pub scanned: AtomicI64,
    pub unmatched: AtomicI64,
    pub denied_ip: AtomicI64,
    pub denied_global: AtomicI64,
    pub oversized: AtomicI64,
    pub over_budget_matched: AtomicI64,
    pub pq_handshakes: AtomicU64,
    pub x25519_handshakes: AtomicU64,
    pub boot_time_accepted: AtomicU64,
    pub server_hello_fragmented: AtomicU64,
    pub alert_closes: AtomicU64,
    pub sni_rejected: AtomicU64,
}

impl FakeTlsCounters {
    pub fn any_counted(&self) -> bool {
        self.hinted.load(Ordering::Relaxed) != 0
            || self.scanned.load(Ordering::Relaxed) != 0
            || self.unmatched.load(Ordering::Relaxed) != 0
            || self.denied_ip.load(Ordering::Relaxed) != 0
            || self.denied_global.load(Ordering::Relaxed) != 0
            || self.oversized.load(Ordering::Relaxed) != 0
            || self.over_budget_matched.load(Ordering::Relaxed) != 0
    }
}

/// Obfuscated2 `[[listener]]` counters matching `/stats` `obfuscated`.
#[derive(Debug, Default)]
pub struct ObfsCounters {
    pub trials: AtomicI64,
    pub misses: AtomicI64,
    pub denied: AtomicI64,
    pub draining: AtomicI64,
    pub rate_limited: AtomicI64,
}

/// Persistent runtime counters & lock-free GCRA buckets for a single named secret.
#[derive(Debug)]
pub struct SecretRuntime {
    pub connections: AtomicI64,
    /// Cumulative lifetime accepted connections for this secret (persisted in `usage.json`).
    pub total_connections: AtomicU64,
    pub bytes_in: AtomicI64,
    pub bytes_out: AtomicI64,
    /// Last seen Unix seconds (`0` = never seen).
    pub last_seen_unix: AtomicI64,
    /// Quota used in current period (client read + write).
    pub quota_used: AtomicI64,
    /// Quota period start in Unix nanoseconds (`0` = not started).
    pub period_start_ns: AtomicI64,
    /// Live quota ceiling enforced on data path (`0` = unlimited).
    pub quota_ceiling: AtomicI64,
    pub quota_cutoffs: AtomicI64,
    pub ad_tag_skipped: AtomicI64,
    pub ad_tag_failed: AtomicI64,
    pub ip_limit_refused: AtomicI64,
    pub client_conns_refused: AtomicI64,
    /// Cumulative wait nanoseconds spent at user's own speed buckets.
    pub speed_throttled_ns: AtomicU64,
    /// Cumulative wait nanoseconds spent at per-address limiters (ceiling + fair).
    pub client_throttled_ns: AtomicU64,
    /// Last admission Unix nanoseconds under a retiring key (`0` = none).
    pub retiring_last_seen_ns: AtomicI64,
    /// Live connections authenticated via a retiring key.
    pub retiring_connections: AtomicI64,

    /// Most recently admitted client IP string (populated ONLY when `track-client-ips = true`).
    pub last_ip: RwLock<String>,

    /// Lock-free aggregate speed limiters (`speed`, `speed-up`, `speed-down`).
    pub speed: GcraLimiter,
    pub speed_up: GcraLimiter,
    pub speed_down: GcraLimiter,
}

impl Default for SecretRuntime {
    fn default() -> Self {
        Self {
            connections: AtomicI64::new(0),
            total_connections: AtomicU64::new(0),
            bytes_in: AtomicI64::new(0),
            bytes_out: AtomicI64::new(0),
            last_seen_unix: AtomicI64::new(0),
            quota_used: AtomicI64::new(0),
            period_start_ns: AtomicI64::new(0),
            quota_ceiling: AtomicI64::new(0),
            quota_cutoffs: AtomicI64::new(0),
            ad_tag_skipped: AtomicI64::new(0),
            ad_tag_failed: AtomicI64::new(0),
            ip_limit_refused: AtomicI64::new(0),
            client_conns_refused: AtomicI64::new(0),
            speed_throttled_ns: AtomicU64::new(0),
            client_throttled_ns: AtomicU64::new(0),
            retiring_last_seen_ns: AtomicI64::new(0),
            retiring_connections: AtomicI64::new(0),
            last_ip: RwLock::new(String::new()),
            speed: GcraLimiter::unlimited(),
            speed_up: GcraLimiter::unlimited(),
            speed_down: GcraLimiter::unlimited(),
        }
    }
}

impl SecretRuntime {
    /// Roll over `quota_used` when `reset` is `Daily`, `Weekly` (ISO week), or
    /// `Monthly` and the UTC calendar period boundary has been crossed.
    pub fn rollover_if_needed(&self, reset: QuotaReset, now: DateTime<Utc>) {
        if reset == QuotaReset::None {
            return;
        }
        let now_ns = now.timestamp_nanos_opt().unwrap_or(0);
        let start_ns = self.period_start_ns.load(Ordering::Acquire);
        if start_ns == 0 {
            let _ = self.period_start_ns.compare_exchange(
                0,
                now_ns,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
        let start_dt = DateTime::from_timestamp_nanos(start_ns);
        let crossed = match reset {
            QuotaReset::None => false,
            QuotaReset::Daily => now.date_naive() != start_dt.date_naive(),
            QuotaReset::Weekly => now.iso_week() != start_dt.iso_week(),
            QuotaReset::Monthly => now.year() != start_dt.year() || now.month() != start_dt.month(),
        };
        if crossed
            && self
                .period_start_ns
                .compare_exchange(start_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.quota_used.store(0, Ordering::Release);
        }
    }

    pub fn set_speed_limits(&self, combined: i64, up: i64, down: i64) {
        self.speed.apply(combined, secret_burst(combined));
        self.speed_up.apply(up, secret_burst(up));
        self.speed_down.apply(down, secret_burst(down));
    }

    #[inline]
    pub fn total_throttled_ms(&self) -> i64 {
        let ns = self
            .speed_throttled_ns
            .load(Ordering::Relaxed)
            .saturating_add(self.client_throttled_ns.load(Ordering::Relaxed));
        (ns / 1_000_000) as i64
    }

    /// Record moved bytes (`is_in = true` client->DC) and check live quota ceiling.
    /// Returns `true` if quota ceiling has been reached/exceeded.
    #[inline]
    pub fn record_traffic(&self, bytes: i64, is_in: bool, now_unix: i64) -> bool {
        if is_in {
            self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
        }
        self.last_seen_unix.store(now_unix, Ordering::Relaxed);
        let used = self.quota_used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let ceil = self.quota_ceiling.load(Ordering::Relaxed);
        ceil > 0 && used >= ceil
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Persisted JSON schema for `usage-state-file` (100% backward-compatible with
/// Go `usageRecord` while also preserving full directional accounting across restarts!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub quota_used: i64,
    pub period_start: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_in: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_out: i64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_connections: u64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub quota_cutoffs: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub last_seen_unix: i64,
}

/// Per-Telegram-DC/IP telemetry bucket for Prometheus & StatsD.
#[derive(Debug, Default)]
pub struct DcEndpointStats {
    pub active_conns: AtomicI64,
    pub bytes_from_client: AtomicU64,
    pub bytes_to_client: AtomicU64,
}

/// Reserved key inside `usage.json` for persisting server-wide `[limits]` quota
/// without altering the backward-compatible `BTreeMap<String, UsageRecord>` schema.
pub const GLOBAL_USAGE_KEY: &str = "__global__";

/// Lock-free server-wide bandwidth, quota, per-IP guard knobs, and CGNAT-safe
/// per-connection speed caps (`[limits]`), hot-reloadable with zero drops!
#[derive(Debug)]
pub struct GlobalLimitsRuntime {
    pub speed: GcraLimiter,
    pub speed_up: GcraLimiter,
    pub speed_down: GcraLimiter,
    pub quota_used: AtomicI64,
    pub quota_ceiling: AtomicI64,
    pub quota_reset: AtomicU8,
    pub period_start_ns: AtomicI64,
    pub quota_cutoffs: AtomicI64,
    pub speed_throttled_ns: AtomicU64,
    pub max_connections_per_ip: AtomicU32,
    pub max_new_connections_per_ip: AtomicU32,
    pub conn_speed: AtomicI64,
    pub conn_speed_up: AtomicI64,
    pub conn_speed_down: AtomicI64,
    pub ip_conn_limited_total: AtomicU64,
    pub ip_rate_limited_total: AtomicU64,
}

impl Default for GlobalLimitsRuntime {
    fn default() -> Self {
        Self {
            speed: GcraLimiter::unlimited(),
            speed_up: GcraLimiter::unlimited(),
            speed_down: GcraLimiter::unlimited(),
            quota_used: AtomicI64::new(0),
            quota_ceiling: AtomicI64::new(0),
            quota_reset: AtomicU8::new(0),
            period_start_ns: AtomicI64::new(0),
            quota_cutoffs: AtomicI64::new(0),
            speed_throttled_ns: AtomicU64::new(0),
            max_connections_per_ip: AtomicU32::new(0),
            max_new_connections_per_ip: AtomicU32::new(0),
            conn_speed: AtomicI64::new(0),
            conn_speed_up: AtomicI64::new(0),
            conn_speed_down: AtomicI64::new(0),
            ip_conn_limited_total: AtomicU64::new(0),
            ip_rate_limited_total: AtomicU64::new(0),
        }
    }
}

impl GlobalLimitsRuntime {
    /// Atomically apply a new [`GlobalLimits`] configuration without dropping live streams.
    pub fn apply(&self, lim: &GlobalLimits) {
        self.speed.apply(
            lim.speed_bytes_per_second,
            secret_burst(lim.speed_bytes_per_second),
        );
        self.speed_up.apply(
            lim.speed_up_bytes_per_second,
            secret_burst(lim.speed_up_bytes_per_second),
        );
        self.speed_down.apply(
            lim.speed_down_bytes_per_second,
            secret_burst(lim.speed_down_bytes_per_second),
        );
        self.quota_ceiling
            .store(lim.quota_bytes.max(0), Ordering::Release);
        self.quota_reset
            .store(lim.quota_reset.as_u8(), Ordering::Release);
        self.max_connections_per_ip
            .store(lim.max_connections_per_ip, Ordering::Release);
        self.max_new_connections_per_ip
            .store(lim.max_new_connections_per_ip, Ordering::Release);
        self.conn_speed
            .store(lim.conn_speed_bytes_per_second.max(0), Ordering::Release);
        self.conn_speed_up
            .store(lim.conn_speed_up_bytes_per_second.max(0), Ordering::Release);
        self.conn_speed_down.store(
            lim.conn_speed_down_bytes_per_second.max(0),
            Ordering::Release,
        );
    }

    /// Snapshot current configured [`GlobalLimits`].
    pub fn snapshot(&self) -> GlobalLimits {
        GlobalLimits {
            speed_bytes_per_second: self.speed.rate_bps(),
            speed_up_bytes_per_second: self.speed_up.rate_bps(),
            speed_down_bytes_per_second: self.speed_down.rate_bps(),
            quota_bytes: self.quota_ceiling.load(Ordering::Acquire),
            quota_reset: QuotaReset::from_u8(self.quota_reset.load(Ordering::Acquire)),
            max_connections_per_ip: self.max_connections_per_ip.load(Ordering::Acquire),
            max_new_connections_per_ip: self.max_new_connections_per_ip.load(Ordering::Acquire),
            conn_speed_bytes_per_second: self.conn_speed.load(Ordering::Acquire),
            conn_speed_up_bytes_per_second: self.conn_speed_up.load(Ordering::Acquire),
            conn_speed_down_bytes_per_second: self.conn_speed_down.load(Ordering::Acquire),
        }
    }

    /// Check if server-wide bandwidth shaping is active for direction `is_upload` (2 relaxed loads).
    #[inline]
    pub fn is_speed_limited(&self, is_upload: bool) -> bool {
        self.speed.is_limited()
            || if is_upload {
                self.speed_up.is_limited()
            } else {
                self.speed_down.is_limited()
            }
    }

    /// Roll over global quota when the configured daily/weekly/monthly boundary crosses.
    pub fn rollover_if_needed(&self, now: DateTime<Utc>) {
        let reset = QuotaReset::from_u8(self.quota_reset.load(Ordering::Acquire));
        if matches!(reset, QuotaReset::None) {
            return;
        }
        let now_ns = now.timestamp_nanos_opt().unwrap_or(0);
        let start_ns = self.period_start_ns.load(Ordering::Acquire);
        if start_ns == 0 {
            let _ = self.period_start_ns.compare_exchange(
                0,
                now_ns,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
        let start_dt = DateTime::from_timestamp_nanos(start_ns);
        let crossed = match reset {
            QuotaReset::None => false,
            QuotaReset::Daily => now.date_naive() != start_dt.date_naive(),
            QuotaReset::Weekly => now.iso_week() != start_dt.iso_week(),
            QuotaReset::Monthly => now.year() != start_dt.year() || now.month() != start_dt.month(),
        };
        if crossed
            && self
                .period_start_ns
                .compare_exchange(start_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.quota_used.store(0, Ordering::Release);
        }
    }

    /// Reset server-wide quota counter to 0 and restart the period from `now`.
    pub fn reset_quota(&self, now: DateTime<Utc>) {
        self.quota_used.store(0, Ordering::Release);
        self.period_start_ns
            .store(now.timestamp_nanos_opt().unwrap_or(0), Ordering::Release);
    }

    /// True if a global quota ceiling is configured and currently exceeded.
    #[inline]
    pub fn is_quota_exceeded(&self) -> bool {
        let ceil = self.quota_ceiling.load(Ordering::Relaxed);
        ceil > 0 && self.quota_used.load(Ordering::Acquire) >= ceil
    }

    /// Record moved bytes against server-wide quota (1 relaxed load when unlimited!).
    /// Returns `true` if server-wide quota ceiling has been reached/exceeded.
    #[inline]
    pub fn record_traffic(&self, bytes: i64) -> bool {
        let ceil = self.quota_ceiling.load(Ordering::Relaxed);
        if ceil <= 0 {
            return false;
        }
        let used = self.quota_used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if used >= ceil {
            self.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }
}

/// Global metrics & observability store shared by engine, API, Prometheus, and StatsD.
#[derive(Debug)]
pub struct ProxyMetrics {
    pub started_at: DateTime<Utc>,
    pub started_instant: Instant,
    pub cores: Box<[CoreMetrics]>,
    pub faketls: FakeTlsCounters,
    pub obfs: ObfsCounters,
    pub global_limits: Arc<GlobalLimitsRuntime>,
    users: RwLock<FxHashMap<String, Arc<SecretRuntime>>>,
    dc_endpoints: RwLock<FxHashMap<(IpAddr, i32), Arc<DcEndpointStats>>>,
    pub blocklist_size: AtomicU64,
    pub allowlist_size: AtomicU64,
    last_usage_digest: AtomicU64,

    // Global connection-count fair throttle (`[throttle]`, hot-reloadable!)
    pub throttle_limit: AtomicI64,
    pub throttle_interval: Duration,
    pub throttle_active: AtomicBool,
    throttle_caps: RwLock<BTreeMap<String, i64>>,
}

impl ProxyMetrics {
    pub fn new(num_cores: usize, throttle_limit: u32, throttle_interval: Duration) -> Self {
        let cores = (0..num_cores.max(1))
            .map(|_| CoreMetrics::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            started_at: Utc::now(),
            started_instant: Instant::now(),
            cores,
            faketls: FakeTlsCounters::default(),
            obfs: ObfsCounters::default(),
            global_limits: Arc::new(GlobalLimitsRuntime::default()),
            users: RwLock::new(FxHashMap::default()),
            dc_endpoints: RwLock::new(FxHashMap::default()),
            blocklist_size: AtomicU64::new(0),
            allowlist_size: AtomicU64::new(0),
            last_usage_digest: AtomicU64::new(0),
            throttle_limit: AtomicI64::new(i64::from(throttle_limit)),
            throttle_interval: if throttle_interval.is_zero() {
                Duration::from_secs(5)
            } else {
                throttle_interval
            },
            throttle_active: AtomicBool::new(false),
            throttle_caps: RwLock::new(BTreeMap::new()),
        }
    }

    /// Hot-reload global `[throttle] max-connections` cap without restarting.
    pub fn set_throttle_limit(&self, limit: i64) {
        self.throttle_limit.store(limit.max(0), Ordering::Release);
        if limit <= 0 {
            self.throttle_caps.write().clear();
            self.throttle_active.store(false, Ordering::Release);
        }
    }

    #[inline]
    pub fn core(&self, worker_id: usize) -> &CoreMetrics {
        &self.cores[worker_id % self.cores.len()]
    }

    /// Get or create the persistent [`SecretRuntime`] for `name`.
    pub fn user(&self, name: &str) -> Arc<SecretRuntime> {
        if let Some(u) = self.users.read().get(name) {
            return Arc::clone(u);
        }
        let mut w = self.users.write();
        Arc::clone(w.entry(name.to_owned()).or_default())
    }

    /// Read an existing [`SecretRuntime`] without creating a bucket as a side effect.
    pub fn get_user(&self, name: &str) -> Option<Arc<SecretRuntime>> {
        self.users.read().get(name).cloned()
    }

    /// Snapshot all user runtime buckets.
    pub fn all_users(&self) -> Vec<(String, Arc<SecretRuntime>)> {
        self.users
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect()
    }

    /// Pre-register secret name so it shows up in `/stats` even with 0 connections.
    pub fn pre_register(&self, name: &str) {
        let _ = self.user(name);
    }

    pub fn dc_endpoint(&self, ip: IpAddr, dc: i32) -> Arc<DcEndpointStats> {
        if let Some(s) = self.dc_endpoints.read().get(&(ip, dc)) {
            return Arc::clone(s);
        }
        let mut w = self.dc_endpoints.write();
        Arc::clone(w.entry((ip, dc)).or_default())
    }

    /// Reset a secret's quota usage to 0 and restart its period from `now`.
    pub fn reset_quota(&self, name: &str, now: DateTime<Utc>) {
        let u = self.user(name);
        u.quota_used.store(0, Ordering::Release);
        u.period_start_ns
            .store(now.timestamp_nanos_opt().unwrap_or(0), Ordering::Release);
    }

    /// Check global connection-count fair throttle (`[throttle]`).
    pub fn can_connect_throttle(&self, name: &str) -> bool {
        if self.throttle_limit.load(Ordering::Acquire) <= 0 {
            return true;
        }
        let cap = {
            let caps = self.throttle_caps.read();
            caps.get(name).copied()
        };
        let Some(user_cap) = cap else {
            return true;
        };
        self.user(name).connections.load(Ordering::Relaxed) < user_cap
    }

    /// Recompute global connection-count fair caps (exact port of Go `computeFairCaps`).
    pub fn recompute_throttle_caps(&self) {
        let limit = self.throttle_limit.load(Ordering::Acquire);
        if limit <= 0 {
            return;
        }
        let user_conns: BTreeMap<String, i64> = self
            .users
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.connections.load(Ordering::Relaxed)))
            .collect();
        let caps = compute_fair_caps(&user_conns, limit);
        let active = !caps.is_empty();
        *self.throttle_caps.write() = caps;
        self.throttle_active.store(active, Ordering::Release);
    }

    pub fn throttle_snapshot(&self) -> Option<(bool, i64, BTreeMap<String, i64>)> {
        let limit = self.throttle_limit.load(Ordering::Acquire);
        if limit <= 0 {
            return None;
        }
        let active = self.throttle_active.load(Ordering::Acquire);
        let caps = self.throttle_caps.read().clone();
        Some((active, limit, caps))
    }

    /// Total active client connections summed across all worker cores.
    pub fn total_active_connections(&self) -> i64 {
        self.cores
            .iter()
            .map(|c| {
                c.active_conns_v4.load(Ordering::Relaxed)
                    + c.active_conns_v6.load(Ordering::Relaxed)
            })
            .sum()
    }

    /// Restore persisted accounting & quota usage from `path` (missing file is `Ok(())`).
    pub fn load_usage(&self, path: &Path) -> io::Result<()> {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let records: BTreeMap<String, UsageRecord> = serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        for (name, rec) in records {
            if name == GLOBAL_USAGE_KEY {
                self.global_limits
                    .quota_used
                    .store(rec.quota_used, Ordering::Release);
                self.global_limits
                    .period_start_ns
                    .store(rec.period_start, Ordering::Release);
                self.global_limits
                    .quota_cutoffs
                    .store(rec.quota_cutoffs, Ordering::Release);
                continue;
            }
            let u = self.user(&name);
            u.quota_used.store(rec.quota_used, Ordering::Release);
            u.period_start_ns.store(rec.period_start, Ordering::Release);
            u.bytes_in.store(rec.bytes_in, Ordering::Release);
            u.bytes_out.store(rec.bytes_out, Ordering::Release);
            u.total_connections
                .store(rec.total_connections, Ordering::Release);
            u.quota_cutoffs.store(rec.quota_cutoffs, Ordering::Release);
            u.last_seen_unix
                .store(rec.last_seen_unix, Ordering::Release);
        }
        let digest = self.compute_usage_digest();
        self.last_usage_digest.store(digest, Ordering::Release);
        Ok(())
    }

    fn compute_usage_digest(&self) -> u64 {
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        let mix = |a: &mut u64, v: u64| {
            *a ^= v;
            *a = a.wrapping_mul(0x1000_0000_01b3);
        };
        for (name, st) in self.users.read().iter() {
            for &b in name.as_bytes() {
                mix(&mut acc, u64::from(b));
            }
            mix(&mut acc, st.quota_used.load(Ordering::Relaxed) as u64);
            mix(&mut acc, st.period_start_ns.load(Ordering::Relaxed) as u64);
            mix(&mut acc, st.bytes_in.load(Ordering::Relaxed) as u64);
            mix(&mut acc, st.bytes_out.load(Ordering::Relaxed) as u64);
            mix(&mut acc, st.total_connections.load(Ordering::Relaxed));
            mix(&mut acc, st.quota_cutoffs.load(Ordering::Relaxed) as u64);
            mix(&mut acc, st.last_seen_unix.load(Ordering::Relaxed) as u64);
        }
        mix(
            &mut acc,
            self.global_limits.quota_used.load(Ordering::Relaxed) as u64,
        );
        mix(
            &mut acc,
            self.global_limits.period_start_ns.load(Ordering::Relaxed) as u64,
        );
        mix(
            &mut acc,
            self.global_limits.quota_cutoffs.load(Ordering::Relaxed) as u64,
        );
        acc
    }

    /// Flush `usage.json` ONLY when accounting counters changed since the last flush
    /// (eliminates unnecessary idle SSD writes while adding zero hot-path instructions!).
    pub fn flush_usage_if_dirty(&self, path: &Path) -> io::Result<bool> {
        let cur = self.compute_usage_digest();
        if cur == self.last_usage_digest.load(Ordering::Acquire) && path.exists() {
            return Ok(false);
        }
        self.flush_usage_atomic(path)?;
        Ok(true)
    }

    /// Crash-safe atomic `usage.json` flush: unique temp file (`0600`) ->
    /// `write_all` -> `sync_data` -> atomic `rename` -> parent dir `fsync`!
    pub fn flush_usage_atomic(&self, path: &Path) -> io::Result<()> {
        let digest = self.compute_usage_digest();
        let mut records: BTreeMap<String, UsageRecord> = self
            .users
            .read()
            .iter()
            .map(|(name, st)| {
                (
                    name.clone(),
                    UsageRecord {
                        quota_used: st.quota_used.load(Ordering::Relaxed),
                        period_start: st.period_start_ns.load(Ordering::Relaxed),
                        bytes_in: st.bytes_in.load(Ordering::Relaxed),
                        bytes_out: st.bytes_out.load(Ordering::Relaxed),
                        total_connections: st.total_connections.load(Ordering::Relaxed),
                        quota_cutoffs: st.quota_cutoffs.load(Ordering::Relaxed),
                        last_seen_unix: st.last_seen_unix.load(Ordering::Relaxed),
                    },
                )
            })
            .collect();

        if self.global_limits.quota_ceiling.load(Ordering::Relaxed) > 0
            || self.global_limits.quota_used.load(Ordering::Relaxed) > 0
        {
            records.insert(
                GLOBAL_USAGE_KEY.to_owned(),
                UsageRecord {
                    quota_used: self.global_limits.quota_used.load(Ordering::Relaxed),
                    period_start: self.global_limits.period_start_ns.load(Ordering::Relaxed),
                    bytes_in: 0,
                    bytes_out: 0,
                    total_connections: 0,
                    quota_cutoffs: self.global_limits.quota_cutoffs.load(Ordering::Relaxed),
                    last_seen_unix: 0,
                },
            );
        }

        let data = serde_json::to_vec(&records)
            .map_err(|e| io::Error::other(format!("marshal usage state: {e}")))?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("usage.json");
        let tmp_path = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        let res = (|| -> io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&data)?;
            f.sync_data()?;
            drop(f);

            fs::rename(&tmp_path, path)?;
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();

        if res.is_err() {
            let _ = fs::remove_file(&tmp_path);
        } else {
            self.last_usage_digest.store(digest, Ordering::Release);
        }
        res
    }

    /// Render Prometheus OpenMetrics / text exposition with 100% metric name
    /// and label parity with Go `stats/prometheus.go`.
    pub fn render_prometheus(&self, prefix: &str) -> String {
        let p = if prefix.is_empty() { "mtg" } else { prefix };
        let mut out = String::with_capacity(4096);

        let mut c_v4 = 0i64;
        let mut c_v6 = 0i64;
        let mut f_v4 = 0i64;
        let mut f_v6 = 0i64;
        let mut f_total = 0u64;
        let mut f_from = 0u64;
        let mut f_to = 0u64;
        let mut replays = 0u64;
        let mut conc_lim = 0u64;
        let mut throttled = 0u64;
        let mut ip_lim = 0u64;
        let mut blocklisted = 0u64;
        let mut allow_rej = 0u64;

        for c in &self.cores {
            c_v4 += c.active_conns_v4.load(Ordering::Relaxed);
            c_v6 += c.active_conns_v6.load(Ordering::Relaxed);
            f_v4 += c.fronted_conns_v4.load(Ordering::Relaxed);
            f_v6 += c.fronted_conns_v6.load(Ordering::Relaxed);
            f_total += c.fronted_total.load(Ordering::Relaxed);
            f_from += c.fronted_bytes_from_client.load(Ordering::Relaxed);
            f_to += c.fronted_bytes_to_client.load(Ordering::Relaxed);
            replays += c.replay_attacks.load(Ordering::Relaxed);
            conc_lim += c.concurrency_limited.load(Ordering::Relaxed);
            throttled += c.throttled_total.load(Ordering::Relaxed);
            ip_lim += c.ip_limited_total.load(Ordering::Relaxed);
            blocklisted += c.blocklisted_total.load(Ordering::Relaxed);
            allow_rej += c.allowlist_rejected_total.load(Ordering::Relaxed);
        }

        let _ = writeln!(
            out,
            "# HELP {p}_client_connections A number of actively processing client connections."
        );
        let _ = writeln!(out, "# TYPE {p}_client_connections gauge");
        let _ = writeln!(out, "{p}_client_connections{{ip_family=\"ipv4\"}} {c_v4}");
        let _ = writeln!(out, "{p}_client_connections{{ip_family=\"ipv6\"}} {c_v6}");

        let _ = writeln!(
            out,
            "# HELP {p}_domain_fronting_connections A number of connections which talk to front domain."
        );
        let _ = writeln!(out, "# TYPE {p}_domain_fronting_connections gauge");
        let _ = writeln!(
            out,
            "{p}_domain_fronting_connections{{ip_family=\"ipv4\"}} {f_v4}"
        );
        let _ = writeln!(
            out,
            "{p}_domain_fronting_connections{{ip_family=\"ipv6\"}} {f_v6}"
        );

        let _ = writeln!(
            out,
            "# HELP {p}_domain_fronting A number of routings to front domain."
        );
        let _ = writeln!(out, "# TYPE {p}_domain_fronting counter");
        let _ = writeln!(out, "{p}_domain_fronting {f_total}");

        let _ = writeln!(
            out,
            "# HELP {p}_domain_fronting_traffic Traffic which is generated talking with front domain."
        );
        let _ = writeln!(out, "# TYPE {p}_domain_fronting_traffic counter");
        let _ = writeln!(
            out,
            "{p}_domain_fronting_traffic{{direction=\"from_client\"}} {f_from}"
        );
        let _ = writeln!(
            out,
            "{p}_domain_fronting_traffic{{direction=\"to_client\"}} {f_to}"
        );

        let _ = writeln!(
            out,
            "# HELP {p}_telegram_connections A number of connections to Telegram servers."
        );
        let _ = writeln!(out, "# TYPE {p}_telegram_connections gauge");
        let dc_snap: Vec<((IpAddr, i32), i64, u64, u64)> = self
            .dc_endpoints
            .read()
            .iter()
            .map(|(&k, v)| {
                (
                    k,
                    v.active_conns.load(Ordering::Relaxed),
                    v.bytes_from_client.load(Ordering::Relaxed),
                    v.bytes_to_client.load(Ordering::Relaxed),
                )
            })
            .collect();
        for &((ip, dc), conns, _, _) in &dc_snap {
            let _ = writeln!(
                out,
                "{p}_telegram_connections{{dc=\"{dc}\",telegram_ip=\"{ip}\"}} {conns}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP {p}_telegram_traffic Traffic which is generated talking with Telegram servers."
        );
        let _ = writeln!(out, "# TYPE {p}_telegram_traffic counter");
        for &((ip, dc), _, from_c, to_c) in &dc_snap {
            let _ = writeln!(
                out,
                "{p}_telegram_traffic{{dc=\"{dc}\",direction=\"from_client\",telegram_ip=\"{ip}\"}} {from_c}"
            );
            let _ = writeln!(
                out,
                "{p}_telegram_traffic{{dc=\"{dc}\",direction=\"to_client\",telegram_ip=\"{ip}\"}} {to_c}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP {p}_iplist_size A size of the ip list (blocklist or allowlist)"
        );
        let _ = writeln!(out, "# TYPE {p}_iplist_size gauge");
        let _ = writeln!(
            out,
            "{p}_iplist_size{{ip_list=\"blocklist\"}} {}",
            self.blocklist_size.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "{p}_iplist_size{{ip_list=\"allowlist\"}} {}",
            self.allowlist_size.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP {p}_ip_blocklisted A number of rejected sessions due to ip blocklisting."
        );
        let _ = writeln!(out, "# TYPE {p}_ip_blocklisted counter");
        let _ = writeln!(
            out,
            "{p}_ip_blocklisted{{ip_list=\"blocklist\"}} {blocklisted}"
        );
        let _ = writeln!(
            out,
            "{p}_ip_blocklisted{{ip_list=\"allowlist\"}} {allow_rej}"
        );

        let _ = writeln!(
            out,
            "# HELP {p}_concurrency_limited A number of sessions that were rejected by concurrency limiter."
        );
        let _ = writeln!(out, "# TYPE {p}_concurrency_limited counter");
        let _ = writeln!(out, "{p}_concurrency_limited {conc_lim}");

        let _ = writeln!(
            out,
            "# HELP {p}_throttled A number of sessions that were refused by the per-user connection throttle."
        );
        let _ = writeln!(out, "# TYPE {p}_throttled counter");
        let _ = writeln!(out, "{p}_throttled {throttled}");

        let _ = writeln!(
            out,
            "# HELP {p}_ip_limited A number of sessions that were refused by a per-user address limit."
        );
        let _ = writeln!(out, "# TYPE {p}_ip_limited counter");
        let _ = writeln!(out, "{p}_ip_limited {ip_lim}");

        let _ = writeln!(
            out,
            "# HELP {p}_replay_attacks A number of detected replay attacks."
        );
        let _ = writeln!(out, "# TYPE {p}_replay_attacks counter");
        let _ = writeln!(out, "{p}_replay_attacks {replays}");

        let (active_secrets, sum_in, sum_out) = {
            let users = self.users.read();
            let mut bi = 0i64;
            let mut bo = 0i64;
            for u in users.values() {
                bi = bi.saturating_add(u.bytes_in.load(Ordering::Relaxed));
                bo = bo.saturating_add(u.bytes_out.load(Ordering::Relaxed));
            }
            (users.len(), bi, bo)
        };
        let _ = writeln!(
            out,
            "# HELP {p}_active_secrets Number of tracked secret accounting buckets."
        );
        let _ = writeln!(out, "# TYPE {p}_active_secrets gauge");
        let _ = writeln!(out, "{p}_active_secrets {active_secrets}");
        let _ = writeln!(
            out,
            "# HELP {p}_total_bytes Cumulative relayed bytes across all secrets."
        );
        let _ = writeln!(out, "# TYPE {p}_total_bytes counter");
        let _ = writeln!(out, "{p}_total_bytes{{direction=\"in\"}} {sum_in}");
        let _ = writeln!(out, "{p}_total_bytes{{direction=\"out\"}} {sum_out}");

        let gl = &self.global_limits;
        let _ = writeln!(
            out,
            "# HELP {p}_global_quota_used_bytes Bytes counted toward server-wide [limits] quota."
        );
        let _ = writeln!(out, "# TYPE {p}_global_quota_used_bytes gauge");
        let _ = writeln!(
            out,
            "{p}_global_quota_used_bytes {}",
            gl.quota_used.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_global_quota_limit_bytes Configured server-wide [limits] quota ceiling (0 = unlimited)."
        );
        let _ = writeln!(out, "# TYPE {p}_global_quota_limit_bytes gauge");
        let _ = writeln!(
            out,
            "{p}_global_quota_limit_bytes {}",
            gl.quota_ceiling.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_global_speed_throttled_seconds_total Cumulative pacing wait time spent at global speed limiters."
        );
        let _ = writeln!(
            out,
            "# TYPE {p}_global_speed_throttled_seconds_total counter"
        );
        let _ = writeln!(
            out,
            "{p}_global_speed_throttled_seconds_total {:.6}",
            gl.speed_throttled_ns.load(Ordering::Relaxed) as f64 / 1e9
        );
        let _ = writeln!(
            out,
            "# HELP {p}_global_ip_conn_limited_total Connections rejected by global max-connections-per-ip."
        );
        let _ = writeln!(out, "# TYPE {p}_global_ip_conn_limited_total counter");
        let _ = writeln!(
            out,
            "{p}_global_ip_conn_limited_total {}",
            gl.ip_conn_limited_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_global_ip_rate_limited_total Connections rejected by global max-new-connections-per-ip."
        );
        let _ = writeln!(out, "# TYPE {p}_global_ip_rate_limited_total counter");
        let _ = writeln!(
            out,
            "{p}_global_ip_rate_limited_total {}",
            gl.ip_rate_limited_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP {p}_faketls_handshakes_total Accepted FakeTLS handshakes by negotiated key_share group."
        );
        let _ = writeln!(out, "# TYPE {p}_faketls_handshakes_total counter");
        let _ = writeln!(
            out,
            "{p}_faketls_handshakes_total{{key_share=\"x25519_mlkem768\"}} {}",
            self.faketls.pq_handshakes.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "{p}_faketls_handshakes_total{{key_share=\"x25519\"}} {}",
            self.faketls.x25519_handshakes.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_faketls_boot_time_accepted_total FakeTLS handshakes accepted via boot-time/uptime timestamp compatibility."
        );
        let _ = writeln!(out, "# TYPE {p}_faketls_boot_time_accepted_total counter");
        let _ = writeln!(
            out,
            "{p}_faketls_boot_time_accepted_total {}",
            self.faketls.boot_time_accepted.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_faketls_server_hello_fragmented_total FakeTLS ServerHello flights sent with two-speed MSG_EOR fragmentation."
        );
        let _ = writeln!(
            out,
            "# TYPE {p}_faketls_server_hello_fragmented_total counter"
        );
        let _ = writeln!(
            out,
            "{p}_faketls_server_hello_fragmented_total {}",
            self.faketls.server_hello_fragmented.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_faketls_alert_closes_total FakeTLS streams closed cleanly after receiving a TLS Alert record."
        );
        let _ = writeln!(out, "# TYPE {p}_faketls_alert_closes_total counter");
        let _ = writeln!(
            out,
            "{p}_faketls_alert_closes_total {}",
            self.faketls.alert_closes.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {p}_faketls_sni_rejected_total Unmatched FakeTLS probes rejected via unknown-sni-action."
        );
        let _ = writeln!(out, "# TYPE {p}_faketls_sni_rejected_total counter");
        let _ = writeln!(
            out,
            "{p}_faketls_sni_rejected_total {}",
            self.faketls.sni_rejected.load(Ordering::Relaxed)
        );

        out
    }

    /// Render Prometheus metrics including live per-outbound dial, RTT, and
    /// circuit-breaker telemetry (`mtg_outbound_*`).
    pub fn render_prometheus_with_outbounds(
        &self,
        prefix: &str,
        outbounds: &[mtg_net::OutboundSnapshot],
    ) -> String {
        let mut out = self.render_prometheus(prefix);
        if outbounds.is_empty() {
            return out;
        }
        let p = if prefix.is_empty() { "mtg" } else { prefix };
        let _ = writeln!(
            out,
            "# HELP {p}_outbound_dials_total Total outbound dial attempts per transport."
        );
        let _ = writeln!(out, "# TYPE {p}_outbound_dials_total counter");
        for ob in outbounds {
            let name = escape_prom_label(&ob.name);
            let proto = escape_prom_label(&ob.protocol);
            let _ = writeln!(
                out,
                "{p}_outbound_dials_total{{outbound=\"{name}\",protocol=\"{proto}\",status=\"ok\"}} {}",
                ob.total_dials.saturating_sub(ob.failed_dials)
            );
            let _ = writeln!(
                out,
                "{p}_outbound_dials_total{{outbound=\"{name}\",protocol=\"{proto}\",status=\"failed\"}} {}",
                ob.failed_dials
            );
        }
        let _ = writeln!(
            out,
            "# HELP {p}_outbound_rtt_ms Exponentially weighted moving average dial RTT in milliseconds."
        );
        let _ = writeln!(out, "# TYPE {p}_outbound_rtt_ms gauge");
        for ob in outbounds {
            let name = escape_prom_label(&ob.name);
            let proto = escape_prom_label(&ob.protocol);
            let _ = writeln!(
                out,
                "{p}_outbound_rtt_ms{{outbound=\"{name}\",protocol=\"{proto}\"}} {:.3}",
                ob.ewma_rtt_ms
            );
        }
        let _ = writeln!(
            out,
            "# HELP {p}_outbound_circuit_open Whether an outbound circuit breaker is currently open (1 = open, 0 = closed)."
        );
        let _ = writeln!(out, "# TYPE {p}_outbound_circuit_open gauge");
        for ob in outbounds {
            let name = escape_prom_label(&ob.name);
            let proto = escape_prom_label(&ob.protocol);
            let open_val = u8::from(ob.circuit_open);
            let _ = writeln!(
                out,
                "{p}_outbound_circuit_open{{outbound=\"{name}\",protocol=\"{proto}\"}} {open_val}"
            );
        }
        out
    }

    /// Spawn a 1-second batched StatsD UDP exporter (Datadog / InfluxDB / Graphite tag formats).
    pub fn spawn_statsd_flusher(
        self: &Arc<Self>,
        target_addr: String,
        prefix: String,
        tag_format: StatsdTagFormat,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let metrics = Arc::clone(self);
        tokio::spawn(async move {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
                warn!("cannot bind UDP socket for StatsD");
                return;
            };
            if let Err(e) = sock.connect(&target_addr) {
                warn!(addr = %target_addr, error = %e, "cannot connect StatsD UDP target");
                return;
            }
            let p = if prefix.is_empty() {
                "mtg.".to_owned()
            } else if prefix.ends_with('.') {
                prefix
            } else {
                format!("{prefix}.")
            };
            let mut pkt = String::with_capacity(1400);
            loop {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                }
                pkt.clear();
                let mut v4 = 0i64;
                let mut v6 = 0i64;
                let mut fv4 = 0i64;
                let mut fv6 = 0i64;
                for c in &metrics.cores {
                    v4 += c.active_conns_v4.load(Ordering::Relaxed);
                    v6 += c.active_conns_v6.load(Ordering::Relaxed);
                    fv4 += c.fronted_conns_v4.load(Ordering::Relaxed);
                    fv6 += c.fronted_conns_v6.load(Ordering::Relaxed);
                }
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "client_connections",
                    v4,
                    &[("ip_family", "ipv4")],
                    tag_format,
                );
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "client_connections",
                    v6,
                    &[("ip_family", "ipv6")],
                    tag_format,
                );
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "domain_fronting_connections",
                    fv4,
                    &[("ip_family", "ipv4")],
                    tag_format,
                );
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "domain_fronting_connections",
                    fv6,
                    &[("ip_family", "ipv6")],
                    tag_format,
                );
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "iplist_size",
                    metrics.blocklist_size.load(Ordering::Relaxed) as i64,
                    &[("ip_list", "blocklist")],
                    tag_format,
                );
                push_statsd_gauge(
                    &mut pkt,
                    &p,
                    "iplist_size",
                    metrics.allowlist_size.load(Ordering::Relaxed) as i64,
                    &[("ip_list", "allowlist")],
                    tag_format,
                );
                let _ = sock.send(pkt.as_bytes());
            }
        });
    }
}

fn push_statsd_gauge(
    out: &mut String,
    prefix: &str,
    name: &str,
    val: i64,
    tags: &[(&str, &str)],
    fmt: StatsdTagFormat,
) {
    match fmt {
        StatsdTagFormat::Datadog => {
            let _ = write!(out, "{prefix}{name}:{val}|g");
            if !tags.is_empty() {
                out.push_str("|#");
                for (i, (k, v)) in tags.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{k}:{v}");
                }
            }
            out.push('\n');
        }
        StatsdTagFormat::Influxdb => {
            let _ = write!(out, "{prefix}{name}");
            for (k, v) in tags {
                let _ = write!(out, ",{k}={v}");
            }
            let _ = writeln!(out, ":{val}|g");
        }
        StatsdTagFormat::Graphite => {
            let _ = write!(out, "{prefix}{name}");
            for (k, v) in tags {
                let _ = write!(out, ";{k}={v}");
            }
            let _ = writeln!(out, ":{val}|g");
        }
    }
}

/// Fair-share connection-count capping matching Go `computeFairCaps`.
pub fn compute_fair_caps(user_conns: &BTreeMap<String, i64>, limit: i64) -> BTreeMap<String, i64> {
    let total: i64 = user_conns.values().sum();
    if total <= limit {
        return BTreeMap::new();
    }
    let mut remaining = user_conns.clone();
    let mut budget = limit;
    let mut caps = BTreeMap::new();

    while !remaining.is_empty() {
        let fair_share = budget / (remaining.len() as i64);
        let mut removed = Vec::new();
        for (name, &conns) in &remaining {
            if conns <= fair_share {
                budget -= conns;
                removed.push(name.clone());
            }
        }
        if removed.is_empty() {
            for name in remaining.keys() {
                caps.insert(name.clone(), fair_share);
            }
            break;
        }
        for name in removed {
            remaining.remove(&name);
        }
    }
    caps
}

fn escape_prom_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_usage_persistence_roundtrips_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.json");

        let m1 = ProxyMetrics::new(2, 0, Duration::from_secs(5));
        m1.user("alice")
            .quota_used
            .store(123_456, Ordering::Relaxed);
        m1.user("alice")
            .period_start_ns
            .store(1_700_000_000_000_000_000, Ordering::Relaxed);
        m1.flush_usage_atomic(&path).unwrap();

        let m2 = ProxyMetrics::new(2, 0, Duration::from_secs(5));
        m2.load_usage(&path).unwrap();
        assert_eq!(m2.user("alice").quota_used.load(Ordering::Relaxed), 123_456);
        assert_eq!(
            m2.user("alice").period_start_ns.load(Ordering::Relaxed),
            1_700_000_000_000_000_000
        );
    }

    #[test]
    fn fair_throttle_caps_match_go_algorithm() {
        let mut conns = BTreeMap::new();
        conns.insert("alice".to_owned(), 2);
        conns.insert("bob".to_owned(), 10);
        conns.insert("carol".to_owned(), 10);
        let caps = compute_fair_caps(&conns, 10);
        // Alice (2 <= 3) keeps her 2; remaining budget 8 split between bob & carol = 4 each!
        assert!(!caps.contains_key("alice"));
        assert_eq!(caps.get("bob"), Some(&4));
        assert_eq!(caps.get("carol"), Some(&4));
    }
}
