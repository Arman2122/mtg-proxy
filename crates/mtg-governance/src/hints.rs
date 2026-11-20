//! 16-way sharded FakeTLS `MatchHints` cache (32,768 address cap, 2 generations,
//! 30-minute rotation, never evicts existing hints) and 16-way sharded
//! `ObfuscatedLimiter` (failed-handshake token bucket for public non-FakeTLS
//! listeners).

use std::hash::{Hash as _, Hasher as _};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mtg_config::ListenerPolicy;
use mtg_core::{IpUnit, is_personal_ip};
use mtg_net::coarse_now_ns;
use parking_lot::Mutex;
use rustc_hash::{FxHashMap, FxHasher};
use smallvec::SmallVec;

/// Number of cache-line-aligned shards eliminating cross-core lock contention.
const SHARDS: usize = 16;

/// Max SHA-256 blocks per candidate for FakeTLS hints and budgeted scan (`128` ≈ 8 KiB).
pub const MAX_SCAN_BLOCKS: usize = 128;
/// Max hinted secret names remembered per `IpUnit` (`16`).
pub const MAX_HINT_NAMES: usize = 16;
/// Max total candidate positions resolved from hints before scan (`32`).
pub const MAX_HINT_POSITIONS: usize = 32;
/// Global address cap across both generations (`32,768` -> `2,048` per shard).
pub const MAX_HINT_ADDRESSES: usize = 32_768;
const MAX_HINT_PER_SHARD: usize = MAX_HINT_ADDRESSES / SHARDS;
/// Generation rotation period for `MatchHints` (`30m`).
pub const HINT_ROTATION: Duration = Duration::from_secs(30 * 60);

/// Max tracked failed-handshake IPs per generation (`65,536` -> `4,096` per shard).
pub const MAX_TRACKED_HANDSHAKE_IPS: usize = 65_536;
const MAX_OBFS_PER_SHARD: usize = MAX_TRACKED_HANDSHAKE_IPS / SHARDS;
/// Generation rotation period for `ObfuscatedLimiter` (`10m`).
pub const HANDSHAKE_BUCKET_ROTATION: Duration = Duration::from_secs(10 * 60);
/// Burst multiplier for `ObfuscatedLimiter` (`2x` per-second rate).
pub const HANDSHAKE_BURST_FACTOR: f64 = 2.0;

#[inline]
fn shard_of(unit: IpUnit) -> usize {
    let mut h = FxHasher::default();
    unit.hash(&mut h);
    (h.finish() as usize) & (SHARDS - 1)
}

/// Extract a personal hint/budget key (`None` for loopback, private, link-local,
/// unspecified, or multicast addresses).
#[inline]
pub fn hint_key(ip: IpAddr) -> Option<IpUnit> {
    if !is_personal_ip(ip) {
        return None;
    }
    Some(IpUnit::from_ip(ip))
}

#[derive(Debug, Default)]
struct HintShard {
    current: FxHashMap<IpUnit, SmallVec<[Arc<str>; 4]>>,
    previous: FxHashMap<IpUnit, SmallVec<[Arc<str>; 4]>>,
}

/// 16-way sharded FakeTLS `MatchHints` cache mapping personal `IpUnit`s to up
/// to `MAX_HINT_NAMES` most-recently-matched secret names.
#[derive(Debug)]
pub struct MatchHints {
    shards: [Mutex<HintShard>; SHARDS],
    enabled: bool,
}

impl MatchHints {
    pub fn new(enabled: bool) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HintShard::default())),
            enabled,
        }
    }

    #[inline]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Recall recently matched secret names for `ip`, most recent first.
    pub fn recall(&self, ip: IpAddr) -> SmallVec<[Arc<str>; 4]> {
        if !self.enabled {
            return SmallVec::new();
        }
        let Some(unit) = hint_key(ip) else {
            return SmallVec::new();
        };
        let shard = self.shards[shard_of(unit)].lock();
        if let Some(names) = shard.current.get(&unit) {
            return names.clone();
        }
        if let Some(names) = shard.previous.get(&unit) {
            return names.clone();
        }
        SmallVec::new()
    }

    /// Record a successful FakeTLS match for `ip` -> `secret_name`.
    /// Never evicts existing addresses once the shard cap is reached.
    pub fn remember(&self, ip: IpAddr, secret_name: Arc<str>) {
        if !self.enabled || secret_name.is_empty() {
            return;
        }
        let Some(unit) = hint_key(ip) else {
            return;
        };
        let mut shard = self.shards[shard_of(unit)].lock();
        let entry = if shard.current.contains_key(&unit) {
            shard.current.get_mut(&unit).expect("present")
        } else if let Some(moved) = shard.previous.remove(&unit) {
            shard.current.entry(unit).or_insert(moved)
        } else if shard.current.len() + shard.previous.len() >= MAX_HINT_PER_SHARD {
            return;
        } else {
            shard.current.entry(unit).or_default()
        };

        if let Some(pos) = entry
            .iter()
            .position(|n| n.as_ref() == secret_name.as_ref())
        {
            entry[..=pos].rotate_right(1);
        } else {
            if entry.len() >= MAX_HINT_NAMES {
                entry.pop();
            }
            entry.insert(0, secret_name);
        }
    }

    /// Forget `secret_name` from `unit` in both generations (called on ban).
    pub fn forget_unit(&self, unit: IpUnit, secret_name: &str) {
        if !self.enabled {
            return;
        }
        let mut guard = self.shards[shard_of(unit)].lock();
        let shard = &mut *guard;
        for gen_map in [&mut shard.current, &mut shard.previous] {
            if let Some(names) = gen_map.get_mut(&unit) {
                names.retain(|n| n.as_ref() != secret_name);
                if names.is_empty() {
                    gen_map.remove(&unit);
                }
            }
        }
    }

    /// Drop the oldest generation and demote `current` -> `previous`.
    pub fn rotate(&self) {
        if !self.enabled {
            return;
        }
        for s in &self.shards {
            let mut g = s.lock();
            g.previous = std::mem::take(&mut g.current);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ObfsBucket {
    tokens: f64,
    last_ns: u64,
}

impl ObfsBucket {
    fn refill(&mut self, rate: u32, now_ns: u64) {
        let burst = f64::from(rate) * HANDSHAKE_BURST_FACTOR;
        let elapsed_secs = now_ns.saturating_sub(self.last_ns) as f64 / 1e9;
        self.tokens = (self.tokens + elapsed_secs * f64::from(rate)).min(burst);
        self.last_ns = now_ns;
    }
}

#[derive(Debug, Default)]
struct ObfsShard {
    current: FxHashMap<IpUnit, ObfsBucket>,
    previous: FxHashMap<IpUnit, ObfsBucket>,
}

/// 16-way sharded per-`IpUnit` failed-handshake rate limiter armed ONLY on
/// `public = true` non-FakeTLS `[[listener]]` sockets.
#[derive(Debug)]
pub struct ObfuscatedLimiter {
    shards: [Mutex<ObfsShard>; SHARDS],
}

impl Default for ObfuscatedLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscatedLimiter {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(ObfsShard::default())),
        }
    }

    #[inline]
    pub const fn is_armed(policy: &ListenerPolicy) -> bool {
        policy.public && policy.handshakes_per_ip > 0
    }

    /// Check whether `ip` still has failed-handshake budget (does NOT consume!).
    pub fn allow(&self, policy: &ListenerPolicy, ip: IpAddr) -> bool {
        if !Self::is_armed(policy) {
            return true;
        }
        let unit = IpUnit::from_ip(ip);
        let now_ns = coarse_now_ns();
        let mut shard = self.shards[shard_of(unit)].lock();
        let Some(bucket) = lookup_or_promote(&mut shard, unit) else {
            return true;
        };
        bucket.refill(policy.handshakes_per_ip, now_ns);
        bucket.tokens >= 1.0
    }

    /// Charge 1 failure token against `ip` on a public non-FakeTLS listener.
    pub fn fail(&self, policy: &ListenerPolicy, ip: IpAddr) {
        if !Self::is_armed(policy) {
            return;
        }
        let unit = IpUnit::from_ip(ip);
        let now_ns = coarse_now_ns();
        let mut shard = self.shards[shard_of(unit)].lock();
        if lookup_or_promote(&mut shard, unit).is_none() {
            if shard.current.len() >= MAX_OBFS_PER_SHARD {
                shard.previous = std::mem::take(&mut shard.current);
            }
            shard.current.insert(
                unit,
                ObfsBucket {
                    tokens: f64::from(policy.handshakes_per_ip) * HANDSHAKE_BURST_FACTOR,
                    last_ns: now_ns,
                },
            );
        }
        let bucket = shard.current.get_mut(&unit).expect("present");
        bucket.refill(policy.handshakes_per_ip, now_ns);
        bucket.tokens = (bucket.tokens - 1.0).max(0.0);
    }

    /// Periodic 10-minute generation rotation.
    pub fn rotate(&self) {
        for s in &self.shards {
            let mut g = s.lock();
            g.previous = std::mem::take(&mut g.current);
        }
    }
}

fn lookup_or_promote(shard: &mut ObfsShard, unit: IpUnit) -> Option<&mut ObfsBucket> {
    if shard.current.contains_key(&unit) {
        return shard.current.get_mut(&unit);
    }
    if let Some(b) = shard.previous.remove(&unit) {
        return Some(shard.current.entry(unit).or_insert(b));
    }
    None
}
