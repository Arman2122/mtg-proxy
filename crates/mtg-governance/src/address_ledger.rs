//! Per-secret `IpUnit`-keyed address ledger (local + external panel reports)
//! and O(K) indexed live connection registry `(secret, IpUnit) -> SmallVec<ConnHandle>`.
//!
//! Upgrades over Go:
//! - Keys every map by 16-byte `Copy` [`IpUnit`] (zero `String` allocations on
//!   admission or teardown!).
//! - Maintains an exact `(secret, IpUnit) -> SmallVec<[ConnHandle; 4]>` index
//!   so `POST /secrets/{name}/kick` and `POST /secrets/{name}/bans` execute in
//!   **O(K)** (number of matching streams) instead of scanning every stream of
//!   the secret!

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mtg_core::IpUnit;
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use thiserror::Error;

/// Default external address TTL when report omits `ttl` (`2m`).
pub const DEFAULT_EXTERNAL_ADDRESS_TTL: Duration = Duration::from_secs(120);
/// Maximum allowed external address TTL (`1h`).
pub const MAX_EXTERNAL_ADDRESS_TTL: Duration = Duration::from_secs(3600);
/// Maximum addresses allowed in one external report (`64`).
pub const MAX_EXTERNAL_ADDRESSES: usize = 64;

/// Validation error for `PUT /secrets/{name}/external-ips`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExternalAddressError {
    #[error("invalid external addresses: {0}")]
    Invalid(String),
}

/// Unique connection identifier routing kicks/bans back to the owning worker core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnHandle {
    pub worker_id: u16,
    pub conn_id: u64,
}

#[derive(Debug, Clone)]
struct ExternalEntry {
    expires_at: DateTime<Utc>,
    text: String,
}

#[derive(Debug, Clone)]
struct LiveStreamMeta {
    client_ip: Option<IpAddr>,
    unit: Option<IpUnit>,
    last_active_unix: i64,
}

/// Per-secret local + external address ledger & indexed live handles.
#[derive(Debug, Default)]
struct SecretLedger {
    local_counts: FxHashMap<IpUnit, u32>,
    external: FxHashMap<IpUnit, ExternalEntry>,
    /// O(K) index from `IpUnit` to live connections for instant kicks & bans!
    by_unit: FxHashMap<IpUnit, SmallVec<[ConnHandle; 4]>>,
    /// All live connections for this secret (including streams with no IP).
    all_conns: FxHashMap<ConnHandle, LiveStreamMeta>,
    /// Set to `true` under outer `ledgers.write()` before eviction so concurrent
    /// readers retry and never insert into an orphaned ledger.
    removed: bool,
}

impl SecretLedger {
    fn prune(&mut self, now: DateTime<Utc>) {
        if !self.external.is_empty() {
            self.external.retain(|_, e| now < e.expires_at);
        }
    }

    fn has(&self, unit: IpUnit, now: DateTime<Utc>) -> bool {
        if self.local_counts.get(&unit).copied().unwrap_or(0) > 0 {
            return true;
        }
        self.external.get(&unit).is_some_and(|e| now < e.expires_at)
    }

    fn counted(&mut self, now: DateTime<Utc>) -> usize {
        self.prune(now);
        let mut n = self.local_counts.len();
        for unit in self.external.keys() {
            if !self.local_counts.contains_key(unit) {
                n += 1;
            }
        }
        n
    }

    fn is_idle(&mut self, now: DateTime<Utc>) -> bool {
        self.prune(now);
        self.local_counts.is_empty() && self.external.is_empty() && self.all_conns.is_empty()
    }

    fn maybe_shrink(&mut self) {
        if self.all_conns.is_empty() && self.all_conns.capacity() > 256 {
            self.all_conns.shrink_to(0);
        }
        if self.local_counts.is_empty() && self.local_counts.capacity() > 256 {
            self.local_counts.shrink_to(0);
        }
        if self.by_unit.is_empty() && self.by_unit.capacity() > 256 {
            self.by_unit.shrink_to(0);
        }
    }
}

/// Reason why admission into [`AddressRegistry`] was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerDeny {
    IpLimit,
    ClientConns,
}

/// Snapshot report for one secret's addresses (used by `/stats` and `/secrets/{name}`).
#[derive(Debug, Clone, Default)]
pub struct AddressReport {
    pub active_ips: usize,
    pub live_conns: usize,
    pub connected_ips: Vec<String>,
    pub connected_ips_last_seen: Vec<(String, DateTime<Utc>)>,
    pub external_ips: Vec<String>,
    pub external_expires_at: Option<DateTime<Utc>>,
}

/// Thread-safe per-secret sharded registry combining `ip-limit`, `client-conns`,
/// external IP reports, and O(K) live connection lookup for kicks/bans.
///
/// Concurrency design:
/// - Outer `RwLock` maps `secret_name -> Arc<Mutex<SecretLedger>>` so concurrent
///   admissions/releases on distinct secrets proceed in parallel without blocking
///   each other and without allocating `secret_name.to_owned()` on the hot path!
/// - Lock ordering is strictly outer `ledgers` -> inner `SecretLedger` whenever
///   both locks are held (zero deadlock possibility).
#[derive(Debug, Default)]
pub struct AddressRegistry {
    ledgers: RwLock<FxHashMap<String, Arc<Mutex<SecretLedger>>>>,
}

impl AddressRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn get_existing(&self, secret_name: &str) -> Option<Arc<Mutex<SecretLedger>>> {
        self.ledgers.read().get(secret_name).cloned()
    }

    #[inline]
    fn get_or_create(&self, secret_name: &str) -> Arc<Mutex<SecretLedger>> {
        if let Some(existing) = self.ledgers.read().get(secret_name) {
            return Arc::clone(existing);
        }
        let mut map = self.ledgers.write();
        Arc::clone(map.entry(secret_name.to_owned()).or_default())
    }

    /// Re-check idle state under outer write lock and evict if still idle.
    fn try_evict_if_idle(
        &self,
        secret_name: &str,
        candidate: &Arc<Mutex<SecretLedger>>,
        now: DateTime<Utc>,
    ) {
        let mut map = self.ledgers.write();
        let should_remove = if let Some(current) = map.get(secret_name)
            && Arc::ptr_eq(current, candidate)
        {
            let mut ledger = current.lock();
            if ledger.is_idle(now) {
                ledger.removed = true;
                true
            } else {
                false
            }
        } else {
            false
        };
        if should_remove {
            map.remove(secret_name);
        }
    }

    /// Atomically check `ip_limit` and `client_conns` (for personal IPs) and
    /// register `handle` in one per-secret critical section!
    #[allow(clippy::too_many_arguments)]
    pub fn admit_and_register(
        &self,
        secret_name: &str,
        handle: ConnHandle,
        client_ip: Option<IpAddr>,
        ip_limit: u32,
        client_conns_limit: u32,
        keyed_for_client_conns: bool,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerDeny> {
        let unit = client_ip.map(IpUnit::from_ip);
        loop {
            let entry = self.get_or_create(secret_name);
            let mut ledger = entry.lock();
            if ledger.removed {
                drop(ledger);
                continue;
            }

            if let Some(u) = unit {
                if ip_limit > 0 && !ledger.has(u, now) && ledger.counted(now) >= ip_limit as usize {
                    return Err(LedgerDeny::IpLimit);
                }
                if keyed_for_client_conns && client_conns_limit > 0 {
                    let live_u = ledger.local_counts.get(&u).copied().unwrap_or(0);
                    if live_u >= client_conns_limit {
                        return Err(LedgerDeny::ClientConns);
                    }
                }
                *ledger.local_counts.entry(u).or_insert(0) += 1;
                ledger.by_unit.entry(u).or_default().push(handle);
            }

            ledger.all_conns.insert(
                handle,
                LiveStreamMeta {
                    client_ip,
                    unit,
                    last_active_unix: now.timestamp(),
                },
            );
            return Ok(());
        }
    }

    /// Update last-active Unix second for a live stream.
    pub fn touch_active(&self, secret_name: &str, handle: ConnHandle, unix_secs: i64) {
        let Some(entry) = self.get_existing(secret_name) else {
            return;
        };
        let mut ledger = entry.lock();
        if let Some(meta) = ledger.all_conns.get_mut(&handle) {
            meta.last_active_unix = unix_secs;
        }
    }

    /// Unregister `handle` on connection close and drop the ledger if idle.
    pub fn unregister(&self, secret_name: &str, handle: ConnHandle, now: DateTime<Utc>) {
        let Some(entry) = self.get_existing(secret_name) else {
            return;
        };
        let became_idle = {
            let mut ledger = entry.lock();
            let Some(meta) = ledger.all_conns.remove(&handle) else {
                return;
            };
            if let Some(u) = meta.unit {
                if let Some(cnt) = ledger.local_counts.get_mut(&u) {
                    if *cnt <= 1 {
                        ledger.local_counts.remove(&u);
                    } else {
                        *cnt -= 1;
                    }
                }
                if let Some(list) = ledger.by_unit.get_mut(&u) {
                    if let Some(pos) = list.iter().position(|h| *h == handle) {
                        list.swap_remove(pos);
                    }
                    if list.is_empty() {
                        ledger.by_unit.remove(&u);
                    } else if list.capacity() > 64 && list.len() * 4 < list.capacity() {
                        list.shrink_to_fit();
                    }
                }
            }
            ledger.maybe_shrink();
            ledger.is_idle(now)
        };
        if became_idle {
            self.try_evict_if_idle(secret_name, &entry, now);
        }
    }

    /// Return all live [`ConnHandle`]s belonging to `secret_name` (for full kick
    /// or secret removal).
    pub fn handles_for_secret(&self, secret_name: &str) -> Vec<ConnHandle> {
        let Some(entry) = self.get_existing(secret_name) else {
            return Vec::new();
        };
        let ledger = entry.lock();
        ledger.all_conns.keys().copied().collect()
    }

    /// **O(K)** lookup of live [`ConnHandle`]s matching `secret_name` and any
    /// `IpUnit` in `units` (used by `POST /kick` with `ips` and `POST /bans`)!
    pub fn handles_for_units(&self, secret_name: &str, units: &[IpUnit]) -> Vec<ConnHandle> {
        let Some(entry) = self.get_existing(secret_name) else {
            return Vec::new();
        };
        let ledger = entry.lock();
        let mut out = Vec::new();
        for u in units {
            if let Some(list) = ledger.by_unit.get(u) {
                out.extend_from_slice(list);
            }
        }
        out
    }

    /// Live connection count for one `(secret_name, IpUnit)` (for `/clients` API).
    pub fn live_count_for_unit(&self, secret_name: &str, unit: IpUnit) -> u32 {
        let Some(entry) = self.get_existing(secret_name) else {
            return 0;
        };
        let ledger = entry.lock();
        ledger.local_counts.get(&unit).copied().unwrap_or(0)
    }

    /// Replace external reported addresses for `secret_name` with TTL expiry.
    pub fn set_external(
        &self,
        secret_name: &str,
        addrs: &[IpAddr],
        ttl: Duration,
        now: DateTime<Utc>,
    ) {
        let expires_at = now + chrono::Duration::from_std(ttl).unwrap_or_default();
        if addrs.is_empty() {
            let Some(entry) = self.get_existing(secret_name) else {
                return;
            };
            let became_idle = {
                let mut ledger = entry.lock();
                ledger.external.clear();
                ledger.is_idle(now)
            };
            if became_idle {
                self.try_evict_if_idle(secret_name, &entry, now);
            }
            return;
        }
        loop {
            let entry = self.get_or_create(secret_name);
            let mut ledger = entry.lock();
            if ledger.removed {
                drop(ledger);
                continue;
            }
            ledger.external.clear();
            for &ip in addrs {
                ledger.external.insert(
                    IpUnit::from_ip(ip),
                    ExternalEntry {
                        expires_at,
                        text: ip.to_string(),
                    },
                );
            }
            return;
        }
    }

    /// Snapshot address report for one secret (O(1) lookup, no global walk!).
    pub fn report_one(
        &self,
        secret_name: &str,
        track_client_ips: bool,
        now: DateTime<Utc>,
    ) -> AddressReport {
        let Some(entry) = self.get_existing(secret_name) else {
            return AddressReport::default();
        };
        let (report, became_idle) = {
            let mut ledger = entry.lock();
            let report = build_report(&mut ledger, track_client_ips, now);
            let idle = ledger.is_idle(now);
            (report, idle)
        };
        if became_idle {
            self.try_evict_if_idle(secret_name, &entry, now);
        }
        report
    }

    /// Snapshot address reports for all active secrets.
    pub fn report_all(
        &self,
        track_client_ips: bool,
        now: DateTime<Utc>,
    ) -> FxHashMap<String, AddressReport> {
        let entries: Vec<(String, Arc<Mutex<SecretLedger>>)> = {
            let map = self.ledgers.read();
            map.iter()
                .map(|(name, entry)| (name.clone(), Arc::clone(entry)))
                .collect()
        };
        let mut out = FxHashMap::default();
        let mut maybe_idle = Vec::new();
        for (name, entry) in entries {
            let (report, idle) = {
                let mut ledger = entry.lock();
                let report = build_report(&mut ledger, track_client_ips, now);
                let idle = ledger.is_idle(now);
                (report, idle)
            };
            out.insert(name.clone(), report);
            if idle {
                maybe_idle.push((name, entry));
            }
        }
        for (name, entry) in maybe_idle {
            self.try_evict_if_idle(&name, &entry, now);
        }
        out
    }

    /// Remove all tracking state for a deleted secret and return its live handles.
    pub fn drop_secret(&self, secret_name: &str) -> Vec<ConnHandle> {
        let removed = self.ledgers.write().remove(secret_name);
        removed
            .map(|entry| {
                let mut ledger = entry.lock();
                ledger.removed = true;
                ledger.all_conns.keys().copied().collect()
            })
            .unwrap_or_default()
    }
}

fn build_report(
    ledger: &mut SecretLedger,
    track_client_ips: bool,
    now: DateTime<Utc>,
) -> AddressReport {
    let active_ips = ledger.counted(now);
    let live_conns = ledger.all_conns.len();
    let mut rep = AddressReport {
        active_ips,
        live_conns,
        ..AddressReport::default()
    };
    if !track_client_ips {
        return rep;
    }

    // Deduplicated sorted connected IPs + latest activity timestamp per IP string.
    let mut by_ip: std::collections::BTreeMap<String, Option<DateTime<Utc>>> =
        std::collections::BTreeMap::new();
    for meta in ledger.all_conns.values() {
        let Some(ip) = meta.client_ip else {
            continue;
        };
        let key = ip.to_string();
        let ts = (meta.last_active_unix > 0)
            .then(|| DateTime::from_timestamp(meta.last_active_unix, 0))
            .flatten();
        by_ip
            .entry(key)
            .and_modify(|cur| {
                if let (Some(a), Some(b)) = (*cur, ts) {
                    if b > a {
                        *cur = Some(b);
                    }
                } else if cur.is_none() {
                    *cur = ts;
                }
            })
            .or_insert(ts);
    }
    for (ip_str, ts) in by_ip {
        rep.connected_ips.push(ip_str.clone());
        if let Some(t) = ts {
            rep.connected_ips_last_seen.push((ip_str, t));
        }
    }

    let mut ext_ips: Vec<String> = Vec::with_capacity(ledger.external.len());
    let mut max_exp: Option<DateTime<Utc>> = None;
    for entry in ledger.external.values() {
        ext_ips.push(entry.text.clone());
        max_exp = Some(match max_exp {
            Some(prev) => prev.max(entry.expires_at),
            None => entry.expires_at,
        });
    }
    ext_ips.sort();
    rep.external_ips = ext_ips;
    rep.external_expires_at = max_exp;
    rep
}

/// Validate a `PUT /secrets/{name}/external-ips` payload (matches Go `ParseExternalAddresses`).
pub fn parse_external_addresses(
    ips: &[String],
    ttl_str: &str,
) -> Result<(Vec<IpAddr>, Duration), ExternalAddressError> {
    if ips.len() > MAX_EXTERNAL_ADDRESSES {
        return Err(ExternalAddressError::Invalid(format!(
            "{} addresses, the most is {MAX_EXTERNAL_ADDRESSES}",
            ips.len()
        )));
    }
    let mut addrs = Vec::with_capacity(ips.len());
    for raw in ips {
        if raw.contains('%') {
            return Err(ExternalAddressError::Invalid(format!(
                "{raw:?} carries a zone"
            )));
        }
        let ip: IpAddr = raw
            .parse()
            .map_err(|_| ExternalAddressError::Invalid(format!("{raw:?} is not an IP address")))?;
        addrs.push(ip);
    }
    let ttl = if ttl_str.is_empty() {
        DEFAULT_EXTERNAL_ADDRESS_TTL
    } else {
        let d = mtg_config::parse_duration(ttl_str)
            .map_err(|e| ExternalAddressError::Invalid(format!("ttl {ttl_str:?}: {e}")))?;
        if d.is_zero() || d > MAX_EXTERNAL_ADDRESS_TTL {
            return Err(ExternalAddressError::Invalid(format!(
                "ttl {ttl_str:?} is outside (0, 1h]"
            )));
        }
        d
    };
    Ok((addrs, ttl))
}
