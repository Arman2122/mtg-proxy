//! Per-secret sharded, per-address client governance table (`IpUnit`-keyed,
//! zero string allocations on admission) with per-address static ceilings
//! (`client-speed`), per-address fair-share limiters (`client-fair`),
//! overflow/non-personal `rest` entry, chunked idle sweep, and zero-allocation
//! 1-second fair-share ticker!
//!
//! # Scalability Architecture
//! Sharded per secret (`RwLock<FxHashMap<String, Arc<Mutex<SecretClients>>>>`)
//! with lock-free global `MAX_CLIENTS` accounting (`AtomicUsize`), eliminating
//! global admission lock contention across 20+ pinned worker cores and 10,000+
//! concurrent users!

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use mtg_core::{FairTotals, IpUnit, SecretLimits};
use mtg_net::{coarse_now_ns, coarse_unix_secs};
use parking_lot::{Mutex, RwLock};
use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::rate_limit::{
    BlockedTracker, FAIR_ACTIVE_WINDOW_NS, FairBucket, FairEntryInput, FairVerdict, GcraLimiter,
    addr_burst, decide_fair_share,
};
use crate::secret_set::FairSecretSpec;

/// Maximum per-secret keyed address entries (matches Go `maxClientsPerSecret`).
pub const MAX_CLIENTS_PER_SECRET: usize = 4096;
/// Global cap on keyed address entries across all secrets (`maxClients`).
pub const MAX_CLIENTS: usize = 32_768;
/// How long an idle entry persists after its last connection closes (`10m`).
pub const CLIENT_IDLE_RETENTION_SECS: i64 = 10 * 60;
/// Step-back guard window (`1m`).
pub const LAST_SEEN_STEP_BACK_SECS: i64 = 60;
/// Maximum entries inspected per lock hold during idle sweep (`1024`).
pub const CLIENT_SWEEP_CHUNK: usize = 1024;
/// Default sweep cadence (`1m`).
pub const CLIENT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Initial limiter parameters for newly created [`ClientEntry`] instances.
#[derive(Debug, Clone, Copy, Default)]
pub struct EntryInit {
    pub ceiling_rate: i64,
    pub fair_totals: FairTotals,
}

impl EntryInit {
    #[inline]
    pub fn from_limits(lim: &SecretLimits) -> Self {
        Self {
            ceiling_rate: lim.client_speed_bytes_per_second,
            fair_totals: lim.fair_totals(),
        }
    }
}

/// Fair-share per-bucket state carried between 1-second ticks.
#[derive(Debug, Clone, Copy, Default)]
struct FairBucketState {
    hold: u32,
    active_ns: u64,
    participant: bool,
    throttled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct FairEntryState {
    bytes_in: i64,
    bytes_out: i64,
    buckets: [FairBucketState; 3],
}

/// One governed source address (`IpUnit`) — or the secret's `rest` overflow entry.
///
/// Accessed on the data path strictly via lock-free atomics (except when
/// actually throttled by fair-share, where [`BlockedTracker`] records wait duty).
#[derive(Debug)]
pub struct ClientEntry {
    pub key: Option<IpUnit>,
    pub secret_name: Arc<str>,
    pub rest: bool,
    pub first_seen: DateTime<Utc>,
    pub bytes_in: AtomicI64,
    pub bytes_out: AtomicI64,
    pub last_seen_unix: AtomicI64,
    pub throttled_nanos: AtomicU64,

    /// Static per-address ceiling (`client-speed`, combined in+out; never installed on `rest`).
    pub ceiling: GcraLimiter,
    /// Per-address fair-share limiters for `[Speed, Up, Down]`.
    pub fair: [GcraLimiter; 3],
    /// Union blocked-wait trackers for `[Speed, Up, Down]`.
    pub blocked: [BlockedTracker; 3],

    // Mutable table-owned metadata protected by the entry's secret shard lock.
    meta: Mutex<EntryTableMeta>,
}

#[derive(Debug, Default)]
struct EntryTableMeta {
    refs: u32,
    shard_index: Option<usize>,
    fair_state: FairEntryState,
}

impl ClientEntry {
    fn new(
        secret_name: Arc<str>,
        key: Option<IpUnit>,
        rest: bool,
        init: EntryInit,
        levels: [i64; 3],
        now_unix: i64,
    ) -> Self {
        let ceiling = if !rest && init.ceiling_rate > 0 {
            GcraLimiter::new(init.ceiling_rate, addr_burst(init.ceiling_rate))
        } else {
            GcraLimiter::unlimited()
        };

        let make_fair = |b: FairBucket, total: i64| -> GcraLimiter {
            if total <= 0 {
                return GcraLimiter::unlimited();
            }
            let lvl = levels[b as usize];
            let rate = if lvl > 0 && lvl <= total { lvl } else { total };
            GcraLimiter::new(rate, addr_burst(total))
        };

        let fair = [
            make_fair(FairBucket::Speed, init.fair_totals.speed),
            make_fair(FairBucket::Up, init.fair_totals.up),
            make_fair(FairBucket::Down, init.fair_totals.down),
        ];

        Self {
            key,
            secret_name,
            rest,
            first_seen: DateTime::from_timestamp(now_unix, 0).unwrap_or_else(Utc::now),
            bytes_in: AtomicI64::new(0),
            bytes_out: AtomicI64::new(0),
            last_seen_unix: AtomicI64::new(now_unix),
            throttled_nanos: AtomicU64::new(0),
            ceiling,
            fair,
            blocked: [
                BlockedTracker::new(),
                BlockedTracker::new(),
                BlockedTracker::new(),
            ],
            meta: Mutex::new(EntryTableMeta::default()),
        }
    }

    /// Record activity timestamp (only writes atomic when Unix second advances).
    #[inline]
    pub fn mark_seen(&self, now_unix: i64) {
        loop {
            let last = self.last_seen_unix.load(Ordering::Relaxed);
            if now_unix == last || (now_unix < last && last - now_unix < LAST_SEEN_STEP_BACK_SECS) {
                return;
            }
            if self
                .last_seen_unix
                .compare_exchange_weak(last, now_unix, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Fair limiter for bucket `b`.
    #[inline]
    pub fn fair_limiter(&self, b: FairBucket) -> &GcraLimiter {
        &self.fair[b as usize]
    }

    /// Blocked duty tracker for bucket `b`.
    #[inline]
    pub fn fair_blocked(&self, b: FairBucket) -> &BlockedTracker {
        &self.blocked[b as usize]
    }

    /// Snapshot of current `(participant, throttled)` status for API reporting.
    pub fn fair_status(&self) -> [(bool, bool); 3] {
        let m = self.meta.lock();
        [
            (
                m.fair_state.buckets[0].participant,
                m.fair_state.buckets[0].throttled,
            ),
            (
                m.fair_state.buckets[1].participant,
                m.fair_state.buckets[1].throttled,
            ),
            (
                m.fair_state.buckets[2].participant,
                m.fair_state.buckets[2].throttled,
            ),
        ]
    }
}

#[derive(Debug, Default)]
struct FairSecretState {
    totals: FairTotals,
    levels: [i64; 3],
    last_tick_ns: u64,
    epoch: u64,
}

impl FairSecretState {
    fn rate_for(&self, b: FairBucket, total: i64) -> i64 {
        let lvl = self.levels[b as usize];
        if lvl > 0 && lvl <= total { lvl } else { total }
    }
}

#[derive(Debug, Default)]
struct SecretClients {
    entries: FxHashMap<IpUnit, Arc<ClientEntry>>,
    rest: Option<Arc<ClientEntry>>,
    /// Dense slab of all entries (keyed + `rest`) owned by this secret shard
    /// for O(1) chunked idle sweeps without locking any other secret.
    all: Vec<Arc<ClientEntry>>,
    overflow: u64,
    fair: FairSecretState,
    /// Tombstone set by `drop_secret` so racing admissions re-fetch a fresh shard.
    removed: bool,
}

impl SecretClients {
    fn forget_entry(&mut self, entry: &Arc<ClientEntry>) -> bool {
        let idx = {
            let mut m = entry.meta.lock();
            let Some(i) = m.shard_index.take() else {
                return false;
            };
            i
        };
        if idx < self.all.len() && Arc::ptr_eq(&self.all[idx], entry) {
            let last = self.all.len() - 1;
            self.all.swap_remove(idx);
            if idx < last {
                self.all[idx].meta.lock().shard_index = Some(idx);
            }
        }
        if entry.rest {
            if self.rest.as_ref().is_some_and(|r| Arc::ptr_eq(r, entry)) {
                self.rest = None;
            }
            false
        } else if let Some(u) = entry.key
            && self.entries.get(&u).is_some_and(|e| Arc::ptr_eq(e, entry))
        {
            self.entries.remove(&u);
            true
        } else {
            false
        }
    }
}

/// Reusable scratch buffers for zero-allocation 1-second fair-share ticks.
#[derive(Debug, Default)]
pub struct FairShareScratch {
    gathered: Vec<GatheredEntry>,
    inputs: Vec<FairEntryInput>,
    demands: Vec<i64>,
    sort_buf: Vec<i64>,
    verdicts: Vec<FairVerdict>,
}

#[derive(Debug)]
struct GatheredEntry {
    entry: Arc<ClientEntry>,
    live: bool,
    state: FairEntryState,
    delta_in: i64,
    delta_out: i64,
    blocked_ns: [u64; 3],
}

/// Summary counts for `/stats`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientCounts {
    pub clients: usize,
    pub overflow: u64,
}

/// Point-in-time view for `GET /secrets/{name}/clients`.
#[derive(Debug, Default)]
pub struct ClientsView {
    pub entries: Vec<Arc<ClientEntry>>,
    pub rest: Option<Arc<ClientEntry>>,
    pub rest_refs: u32,
    pub total: usize,
    pub overflow: u64,
    pub fair_levels: [i64; 3],
}

/// Per-secret sharded, per-`IpUnit` client governance table.
#[derive(Debug, Default)]
pub struct ClientTable {
    secrets: RwLock<FxHashMap<String, Arc<Mutex<SecretClients>>>>,
    keyed_count: AtomicUsize,
}

impl ClientTable {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn get_shard(&self, name: &str) -> Option<Arc<Mutex<SecretClients>>> {
        self.secrets.read().get(name).cloned()
    }

    fn get_or_create_shard(
        &self,
        secret_name: &str,
        fair_totals: FairTotals,
    ) -> Arc<Mutex<SecretClients>> {
        if let Some(shard) = self.secrets.read().get(secret_name).cloned() {
            return shard;
        }
        let mut w = self.secrets.write();
        Arc::clone(w.entry(secret_name.to_owned()).or_insert_with(|| {
            Arc::new(Mutex::new(SecretClients {
                fair: FairSecretState {
                    totals: fair_totals,
                    ..FairSecretState::default()
                },
                ..SecretClients::default()
            }))
        }))
    }

    #[inline]
    fn try_reserve_keyed_slot(&self) -> bool {
        let mut cur = self.keyed_count.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_CLIENTS {
                return false;
            }
            match self.keyed_count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Acquire or create the [`ClientEntry`] governing a new stream of `secret_name`.
    ///
    /// - Personal `IpUnit` (`keyed = true`) gets its own entry if room remains
    ///   within `MAX_CLIENTS_PER_SECRET` and `MAX_CLIENTS`, else increments
    ///   `overflow` and joins the secret's `rest` entry.
    /// - Non-personal IPs (`keyed = false`: loopback/private/link-local/etc.)
    ///   always join the `rest` entry without counting as overflow.
    pub fn acquire(
        &self,
        secret_name: &Arc<str>,
        unit: Option<IpUnit>,
        keyed: bool,
        init: EntryInit,
    ) -> Arc<ClientEntry> {
        self.acquire_at(secret_name, unit, keyed, init, unix_now_secs())
    }

    pub fn acquire_at(
        &self,
        secret_name: &Arc<str>,
        unit: Option<IpUnit>,
        keyed: bool,
        init: EntryInit,
        now_unix: i64,
    ) -> Arc<ClientEntry> {
        loop {
            let shard = self.get_or_create_shard(secret_name.as_ref(), init.fair_totals);
            let mut sc = shard.lock();
            if sc.removed {
                drop(sc);
                continue;
            }

            if keyed && let Some(u) = unit {
                if let Some(existing) = sc.entries.get(&u).cloned() {
                    let levels = sc.fair.levels;
                    Self::hold_returning(&existing, init.fair_totals, levels, now_unix);
                    return existing;
                }
                if sc.entries.len() < MAX_CLIENTS_PER_SECRET && self.try_reserve_keyed_slot() {
                    let levels = sc.fair.levels;
                    let entry = Arc::new(ClientEntry::new(
                        Arc::clone(secret_name),
                        Some(u),
                        false,
                        init,
                        levels,
                        now_unix,
                    ));
                    let idx = sc.all.len();
                    {
                        let mut m = entry.meta.lock();
                        m.refs = 1;
                        m.shard_index = Some(idx);
                    }
                    sc.all.push(Arc::clone(&entry));
                    sc.entries.insert(u, Arc::clone(&entry));
                    return entry;
                }
                sc.overflow = sc.overflow.saturating_add(1);
            }

            // Fall back to secret's `rest` entry.
            let levels = sc.fair.levels;
            if let Some(rest) = sc.rest.clone() {
                Self::hold_returning(&rest, init.fair_totals, levels, now_unix);
                return rest;
            }

            let rest = Arc::new(ClientEntry::new(
                Arc::clone(secret_name),
                None,
                true,
                init,
                levels,
                now_unix,
            ));
            let idx = sc.all.len();
            {
                let mut m = rest.meta.lock();
                m.refs = 1;
                m.shard_index = Some(idx);
            }
            sc.all.push(Arc::clone(&rest));
            sc.rest = Some(Arc::clone(&rest));
            return rest;
        }
    }

    fn hold_returning(entry: &ClientEntry, totals: FairTotals, levels: [i64; 3], now_unix: i64) {
        let mut m = entry.meta.lock();
        if m.refs == 0 {
            for b in FairBucket::ALL {
                let total = total_of(totals, b);
                if total > 0 {
                    let lvl = levels[b as usize];
                    let rate = if lvl > 0 && lvl <= total { lvl } else { total };
                    entry.fair_limiter(b).set_rate(rate);
                }
            }
        }
        m.refs = m.refs.saturating_add(1);
        entry.mark_seen(now_unix);
    }

    /// Release one stream reference from `entry` and stamp `last_seen`.
    pub fn release(&self, entry: &ClientEntry) {
        self.release_at(entry, unix_now_secs());
    }

    pub fn release_at(&self, entry: &ClientEntry, now_unix: i64) {
        let mut m = entry.meta.lock();
        m.refs = m.refs.saturating_sub(1);
        entry.mark_seen(now_unix);
    }

    /// Sweep entries idle longer than `CLIENT_IDLE_RETENTION_SECS` (or stepped
    /// more than `LAST_SEEN_STEP_BACK_SECS` into the future) per secret shard,
    /// releasing each shard lock every `max_per_hold` entries so concurrent
    /// admissions on all secrets stay unblocked!
    pub fn sweep(&self, now_unix: i64, max_per_hold: usize) -> usize {
        let max_per_hold = max_per_hold.max(1);
        let cutoff = now_unix - CLIENT_IDLE_RETENTION_SECS;
        let future = now_unix + LAST_SEEN_STEP_BACK_SECS;
        let shards: Vec<Arc<Mutex<SecretClients>>> =
            self.secrets.read().values().cloned().collect();

        let mut total_dropped = 0usize;

        for shard in shards {
            let mut cursor = {
                let sc = shard.lock();
                if sc.removed || sc.all.is_empty() {
                    continue;
                }
                sc.all.len() - 1
            };

            loop {
                let mut sc = shard.lock();
                if sc.removed || sc.all.is_empty() {
                    break;
                }
                cursor = cursor.min(sc.all.len() - 1);
                let mut walked = 0usize;
                let mut keyed_evicted = 0usize;
                let mut hit_zero = false;

                loop {
                    walked += 1;
                    let entry = Arc::clone(&sc.all[cursor]);
                    let seen = entry.last_seen_unix.load(Ordering::Relaxed);
                    let idle = {
                        let m = entry.meta.lock();
                        m.refs == 0 && (seen <= cutoff || seen > future)
                    };
                    if idle {
                        if sc.forget_entry(&entry) {
                            keyed_evicted += 1;
                        }
                        total_dropped += 1;
                    }
                    if cursor == 0 {
                        hit_zero = true;
                        break;
                    }
                    cursor -= 1;
                    if walked >= max_per_hold {
                        break;
                    }
                }
                if keyed_evicted > 0 {
                    self.keyed_count.fetch_sub(keyed_evicted, Ordering::Relaxed);
                }
                let done = hit_zero || sc.all.is_empty();
                drop(sc);
                if done {
                    break;
                }
            }
        }

        total_dropped
    }

    /// Re-apply `client-speed` ceilings on live reload for retained secrets.
    pub fn apply_ceilings<F>(&self, mut rate_of: F)
    where
        F: FnMut(&str) -> Option<i64>,
    {
        let shards: Vec<(String, Arc<Mutex<SecretClients>>)> = self
            .secrets
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        for (name, shard) in shards {
            let Some(bps) = rate_of(&name) else {
                continue;
            };
            let burst = addr_burst(bps);
            let sc = shard.lock();
            if sc.removed {
                continue;
            }
            for entry in sc.entries.values() {
                entry.ceiling.apply(bps, burst);
            }
        }
    }

    /// Re-apply `client-fair` totals on live reload for retained secrets.
    pub fn apply_fair<F>(&self, now_ns: u64, mut totals_of: F)
    where
        F: FnMut(&str) -> Option<FairTotals>,
    {
        let shards: Vec<(String, Arc<Mutex<SecretClients>>)> = self
            .secrets
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        for (name, shard) in shards {
            let Some(totals) = totals_of(&name) else {
                continue;
            };
            let mut sc = shard.lock();
            if sc.removed {
                continue;
            }
            let mut changed = sc.fair.totals != totals;
            for b in FairBucket::ALL {
                if total_of(totals, b) != total_of(sc.fair.totals, b) {
                    sc.fair.levels[b as usize] = 0;
                }
            }
            sc.fair.totals = totals;

            let mut apply_entry = |entry: &ClientEntry| {
                for b in FairBucket::ALL {
                    let lim = entry.fair_limiter(b);
                    let was_limited = lim.is_limited();
                    let total = total_of(totals, b);
                    if total > 0 {
                        lim.apply(sc.fair.rate_for(b, total), addr_burst(total));
                    } else {
                        lim.apply(0, 0);
                    }
                    let now_limited = lim.is_limited();
                    if now_limited != was_limited {
                        changed = true;
                        entry.meta.lock().fair_state.buckets[b as usize] =
                            FairBucketState::default();
                        if now_limited {
                            entry.fair_blocked(b).reset(now_ns);
                        }
                    }
                }
            };

            for entry in sc.entries.values() {
                apply_entry(entry);
            }
            if let Some(rest) = &sc.rest {
                apply_entry(rest);
            }

            if changed {
                sc.fair.epoch = sc.fair.epoch.wrapping_add(1);
                sc.fair.last_tick_ns = 0;
            }
        }
    }

    /// Run one zero-allocation fair-share scheduling tick for one fair-enabled
    /// secret at monotonic timestamp `now_ns`.
    pub fn tick_secret(&self, now_ns: u64, spec: &FairSecretSpec, scratch: &mut FairShareScratch) {
        let mut active_buckets = [false; 3];
        let mut any_bucket = false;
        for b in FairBucket::ALL {
            if total_of(spec.totals, b) > 0 {
                active_buckets[b as usize] = true;
                any_bucket = true;
            }
        }
        if !any_bucket {
            return;
        }

        let Some(shard) = self.get_shard(spec.name.as_ref()) else {
            return;
        };

        scratch.gathered.clear();
        let (epoch, last_tick_ns, mut levels) = {
            let sc = shard.lock();
            if sc.removed {
                return;
            }
            for entry in sc.entries.values() {
                let m = entry.meta.lock();
                scratch.gathered.push(GatheredEntry {
                    entry: Arc::clone(entry),
                    live: m.refs > 0,
                    state: m.fair_state,
                    delta_in: 0,
                    delta_out: 0,
                    blocked_ns: [0; 3],
                });
            }
            if let Some(rest) = &sc.rest {
                let m = rest.meta.lock();
                scratch.gathered.push(GatheredEntry {
                    entry: Arc::clone(rest),
                    live: m.refs > 0,
                    state: m.fair_state,
                    delta_in: 0,
                    delta_out: 0,
                    blocked_ns: [0; 3],
                });
            }
            (sc.fair.epoch, sc.fair.last_tick_ns, sc.fair.levels)
        };

        // Outside shard lock: read byte deltas and snapshot blocked-wait trackers.
        for item in &mut scratch.gathered {
            let cur_in = item.entry.bytes_in.load(Ordering::Relaxed);
            let cur_out = item.entry.bytes_out.load(Ordering::Relaxed);
            item.delta_in = (cur_in - item.state.bytes_in).max(0);
            item.delta_out = (cur_out - item.state.bytes_out).max(0);
            item.state.bytes_in = cur_in;
            item.state.bytes_out = cur_out;
            for b in FairBucket::ALL {
                if active_buckets[b as usize] {
                    item.blocked_ns[b as usize] = item.entry.fair_blocked(b).snapshot(now_ns);
                }
            }
        }

        let decided = last_tick_ns > 0 && now_ns > last_tick_ns;
        if decided {
            let elapsed_ns = now_ns - last_tick_ns;
            for b in FairBucket::ALL {
                if !active_buckets[b as usize] {
                    continue;
                }
                let total = total_of(spec.totals, b);
                scratch.inputs.clear();
                for item in &mut scratch.gathered {
                    let moved = match b {
                        FairBucket::Speed => item.delta_in + item.delta_out,
                        FairBucket::Up => item.delta_in,
                        FairBucket::Down => item.delta_out,
                    };
                    let st = &mut item.state.buckets[b as usize];
                    if moved > 0 || item.blocked_ns[b as usize] > 0 {
                        st.active_ns = now_ns;
                    }
                    let active = st.active_ns > 0
                        && now_ns.saturating_sub(st.active_ns) < FAIR_ACTIVE_WINDOW_NS;
                    let rate = if moved > 0 {
                        let r = (moved as f64) * 1e9 / (elapsed_ns as f64);
                        if r >= i64::MAX as f64 {
                            i64::MAX
                        } else {
                            r as i64
                        }
                    } else {
                        0
                    };
                    scratch.inputs.push(FairEntryInput {
                        live: item.live,
                        rest: item.entry.rest,
                        active,
                        rate,
                        blocked_ns: item.blocked_ns[b as usize],
                        hold: st.hold,
                    });
                }

                let new_level = decide_fair_share(
                    total,
                    levels[b as usize],
                    elapsed_ns,
                    &scratch.inputs,
                    &mut scratch.demands,
                    &mut scratch.sort_buf,
                    &mut scratch.verdicts,
                );
                levels[b as usize] = new_level;

                for (item, verdict) in scratch.gathered.iter_mut().zip(&scratch.verdicts) {
                    let st = &mut item.state.buckets[b as usize];
                    st.hold = verdict.hold;
                    st.participant = verdict.participant;
                    st.throttled = verdict.throttled;
                }
            }
        }

        // Publish under shard lock if epoch unchanged and shard still live.
        let mut sc = shard.lock();
        if sc.removed || sc.fair.epoch != epoch {
            return;
        }
        for item in &scratch.gathered {
            item.entry.meta.lock().fair_state = item.state;
        }
        sc.fair.last_tick_ns = now_ns;
        if !decided {
            return;
        }
        for b in FairBucket::ALL {
            if active_buckets[b as usize] {
                sc.fair.levels[b as usize] = levels[b as usize];
            }
        }

        let apply_rate = |entry: &ClientEntry| {
            if entry.meta.lock().refs > 0 {
                for b in FairBucket::ALL {
                    if active_buckets[b as usize] {
                        entry.fair_limiter(b).set_rate(levels[b as usize]);
                    }
                }
            }
        };
        for entry in sc.entries.values() {
            apply_rate(entry);
        }
        if let Some(rest) = &sc.rest {
            apply_rate(rest);
        }
    }

    /// Tick ONLY fair-enabled secrets from the current `SecretSet`.
    pub fn tick_all_fair(&self, fair_secrets: &[FairSecretSpec], scratch: &mut FairShareScratch) {
        if fair_secrets.is_empty() {
            return;
        }
        let now_ns = coarse_now_ns();
        for spec in fair_secrets {
            self.tick_secret(now_ns, spec, scratch);
        }
    }

    /// Forget all entries belonging to a removed secret.
    pub fn drop_secret(&self, name: &str) {
        let removed = self.secrets.write().remove(name);
        if let Some(shard) = removed {
            let mut sc = shard.lock();
            sc.removed = true;
            let keyed = sc.entries.len();
            for entry in &sc.all {
                entry.meta.lock().shard_index = None;
            }
            sc.entries.clear();
            sc.rest = None;
            sc.all.clear();
            if keyed > 0 {
                self.keyed_count.fetch_sub(keyed, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot per-secret `(clients, overflow)` counts.
    pub fn counts(&self) -> FxHashMap<String, ClientCounts> {
        let shards: Vec<(String, Arc<Mutex<SecretClients>>)> = self
            .secrets
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        let mut out = FxHashMap::with_capacity_and_hasher(shards.len(), FxBuildHasher);
        for (k, shard) in shards {
            let sc = shard.lock();
            if sc.removed {
                continue;
            }
            out.insert(
                k,
                ClientCounts {
                    clients: sc.entries.len(),
                    overflow: sc.overflow,
                },
            );
        }
        out
    }

    /// Snapshot one secret's view for `GET /secrets/{name}/clients`.
    pub fn view(&self, name: &str, with_entries: bool) -> ClientsView {
        let Some(shard) = self.get_shard(name) else {
            return ClientsView::default();
        };
        let sc = shard.lock();
        if sc.removed {
            return ClientsView::default();
        }
        let mut view = ClientsView {
            entries: Vec::new(),
            rest: None,
            rest_refs: 0,
            total: sc.entries.len(),
            overflow: sc.overflow,
            fair_levels: sc.fair.levels,
        };
        if with_entries {
            view.entries = sc.entries.values().cloned().collect();
            if let Some(rest) = &sc.rest {
                view.rest = Some(Arc::clone(rest));
                view.rest_refs = rest.meta.lock().refs;
            }
        }
        view
    }
}

#[inline]
const fn total_of(t: FairTotals, b: FairBucket) -> i64 {
    match b {
        FairBucket::Speed => t.speed,
        FairBucket::Up => t.up,
        FairBucket::Down => t.down,
    }
}

#[inline]
fn unix_now_secs() -> i64 {
    coarse_unix_secs()
}
