//! Global server-wide per-IP connection & connect-rate guard (`GlobalIpGuard`)
//! and CGNAT-safe per-TCP-connection speed limiters (`ConnSpeedLimiters`).
//!
//! # Scalability & DoS Safety
//! - `GlobalIpGuard` is 64-way cache-line-sharded by `IpUnit` hash (IPv4 `/32`
//!   or IPv6 `/64`), skipping loopback/private peers automatically.
//! - Active per-IP connection counts are managed via RAII [`GlobalIpConnPermit`]
//!   so early errors, cancellations, or panics can NEVER leak a slot.
//! - Per-IP connection-rate limiting uses GCRA (`tat_ns`) with strict per-shard
//!   entry caps (`4096` entries × `64` shards = `262,144` max tracked IPs) and
//!   idle eviction so random-IP SYN/accept floods can never exhaust RAM even on
//!   a 1 GiB VPS.

use std::hash::BuildHasher as _;
use std::net::IpAddr;
use std::sync::Arc;

use mtg_core::{GlobalLimits, IpUnit, SecretLimits, is_personal_ip};
use parking_lot::Mutex;
use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::rate_limit::{GcraLimiter, addr_burst};

const GUARD_SHARDS: usize = 64;
const MAX_RATE_ENTRIES_PER_SHARD: usize = 4096;
const RATE_IDLE_EVICT_NS: u64 = 120 * 1_000_000_000; // 2 minutes

#[repr(align(64))]
#[derive(Debug, Default)]
struct GuardShard {
    conns: Mutex<FxHashMap<IpUnit, u32>>,
    rates: Mutex<FxHashMap<IpUnit, RateSlot>>,
}

#[derive(Debug, Clone, Copy)]
struct RateSlot {
    tat_ns: u64,
    last_seen_ns: u64,
}

/// 64-way sharded global per-IP concurrent connection & connection-rate guard.
#[derive(Debug)]
pub struct GlobalIpGuard {
    shards: Box<[GuardShard]>,
}

impl Default for GlobalIpGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalIpGuard {
    pub fn new() -> Self {
        let shards = (0..GUARD_SHARDS)
            .map(|_| GuardShard::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { shards }
    }

    #[inline]
    fn shard_idx(unit: IpUnit) -> usize {
        (FxBuildHasher.hash_one(unit) as usize) & (GUARD_SHARDS - 1)
    }

    /// Check global per-IP new-connection rate (`max_per_sec` connections/s, burst 2×).
    /// Returns `true` if admitted, `false` if rate-limited.
    /// Loopback/private IPs or `max_per_sec == 0` always pass in O(1) with zero locks!
    #[inline]
    pub fn allow_new_connection(&self, ip: IpAddr, max_per_sec: u32, now_ns: u64) -> bool {
        if max_per_sec == 0 || !is_personal_ip(ip) {
            return true;
        }
        let unit = IpUnit::from_ip(ip);
        let shard = &self.shards[Self::shard_idx(unit)];
        let increment_ns = (1_000_000_000u64 / u64::from(max_per_sec)).max(1);
        let burst_ns = increment_ns.saturating_mul(u64::from(max_per_sec).saturating_mul(2).max(2));

        let mut map = shard.rates.lock();
        if !map.contains_key(&unit) && map.len() >= MAX_RATE_ENTRIES_PER_SHARD {
            // Reclaim idle entries first to stay strictly bounded in RAM under random-IP floods.
            map.retain(|_, slot| now_ns.saturating_sub(slot.last_seen_ns) < RATE_IDLE_EVICT_NS);
            if map.len() >= MAX_RATE_ENTRIES_PER_SHARD {
                // Evict one arbitrary slot so the table never grows unboundedly.
                if let Some(&victim) = map.keys().next() {
                    map.remove(&victim);
                }
            }
        }

        let slot = map.entry(unit).or_insert(RateSlot {
            tat_ns: now_ns,
            last_seen_ns: now_ns,
        });
        slot.last_seen_ns = now_ns;
        let base = slot.tat_ns.max(now_ns);
        let next_tat = base.saturating_add(increment_ns);
        if next_tat.saturating_sub(now_ns) > burst_ns {
            return false;
        }
        slot.tat_ns = next_tat;
        true
    }

    /// Acquire a global per-IP concurrent connection slot (returning an RAII permit that
    /// automatically releases the slot on drop!).
    /// Returns `Some(permit)` if admitted (`None` if `ip` is already at `max_conns`).
    /// When `max_conns == 0` or `ip` is loopback/private, returns a zero-cost no-op permit!
    #[inline]
    pub fn try_acquire_conn(
        self: &Arc<Self>,
        ip: IpAddr,
        max_conns: u32,
    ) -> Option<GlobalIpConnPermit> {
        if max_conns == 0 || !is_personal_ip(ip) {
            return Some(GlobalIpConnPermit {
                guard: None,
                unit: IpUnit::from_ip(ip),
                shard_idx: 0,
            });
        }
        let unit = IpUnit::from_ip(ip);
        let shard_idx = Self::shard_idx(unit);
        let mut map = self.shards[shard_idx].conns.lock();
        let count = map.entry(unit).or_insert(0);
        if *count >= max_conns {
            if *count == 0 {
                map.remove(&unit);
            }
            return None;
        }
        *count += 1;
        Some(GlobalIpConnPermit {
            guard: Some(Arc::clone(self)),
            unit,
            shard_idx,
        })
    }

    /// Reclaim idle per-IP connection-rate entries across all 64 shards (called every ~60s).
    pub fn sweep_stale_rates(&self, now_ns: u64) {
        for shard in &self.shards {
            let mut map = shard.rates.lock();
            if map.is_empty() {
                continue;
            }
            map.retain(|_, slot| now_ns.saturating_sub(slot.last_seen_ns) < RATE_IDLE_EVICT_NS);
            if map.is_empty() && map.capacity() > 256 {
                map.shrink_to(0);
            }
        }
    }

    /// Total distinct active public IPs currently holding a global connection permit.
    pub fn active_tracked_ips(&self) -> usize {
        self.shards.iter().map(|s| s.conns.lock().len()).sum()
    }
}

/// RAII permit holding one global per-IP concurrent connection slot.
#[derive(Debug)]
pub struct GlobalIpConnPermit {
    guard: Option<Arc<GlobalIpGuard>>,
    unit: IpUnit,
    shard_idx: usize,
}

impl Drop for GlobalIpConnPermit {
    fn drop(&mut self) {
        let Some(guard) = self.guard.take() else {
            return;
        };
        let mut map = guard.shards[self.shard_idx].conns.lock();
        if let Some(cnt) = map.get_mut(&self.unit) {
            *cnt = cnt.saturating_sub(1);
            if *cnt == 0 {
                map.remove(&self.unit);
            }
        }
        if map.is_empty() && map.capacity() > 256 {
            map.shrink_to(0);
        }
    }
}

/// CGNAT-safe per-TCP-connection speed limiters (`conn-speed`, `conn-speed-up`,
/// `conn-speed-down`), boxed behind `Option<Box<Self>>` on `DirectRelay` so
/// unlimited streams allocate **0 bytes**!
#[derive(Debug)]
pub struct ConnSpeedLimiters {
    pub combined: GcraLimiter,
    pub up: GcraLimiter,
    pub down: GcraLimiter,
}

impl ConnSpeedLimiters {
    /// Resolve effective per-connection limits (secret overrides global when > 0).
    /// Returns `None` when all three are unlimited (zero heap allocation!).
    pub fn effective(secret: &SecretLimits, global: &GlobalLimits) -> Option<Box<Self>> {
        let combined = if secret.conn_speed_bytes_per_second > 0 {
            secret.conn_speed_bytes_per_second
        } else {
            global.conn_speed_bytes_per_second
        };
        let up = if secret.conn_speed_up_bytes_per_second > 0 {
            secret.conn_speed_up_bytes_per_second
        } else {
            global.conn_speed_up_bytes_per_second
        };
        let down = if secret.conn_speed_down_bytes_per_second > 0 {
            secret.conn_speed_down_bytes_per_second
        } else {
            global.conn_speed_down_bytes_per_second
        };
        Self::from_rates(combined, up, down)
    }

    pub fn from_rates(combined: i64, up: i64, down: i64) -> Option<Box<Self>> {
        if combined <= 0 && up <= 0 && down <= 0 {
            return None;
        }
        Some(Box::new(Self {
            combined: if combined > 0 {
                GcraLimiter::new(combined, addr_burst(combined))
            } else {
                GcraLimiter::unlimited()
            },
            up: if up > 0 {
                GcraLimiter::new(up, addr_burst(up))
            } else {
                GcraLimiter::unlimited()
            },
            down: if down > 0 {
                GcraLimiter::new(down, addr_burst(down))
            } else {
                GcraLimiter::unlimited()
            },
        }))
    }

    #[inline]
    pub fn is_limited(&self, is_upload: bool) -> bool {
        self.combined.is_limited()
            || if is_upload {
                self.up.is_limited()
            } else {
                self.down.is_limited()
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_ip_guard_enforces_max_conns_per_ip_with_raii_release_and_rate_limit() {
        let guard = Arc::new(GlobalIpGuard::new());
        let ip_a: IpAddr = "5.160.1.10".parse().unwrap();
        let ip_b: IpAddr = "5.160.1.11".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();

        // Concurrent cap = 2 per IP
        let p1 = guard.try_acquire_conn(ip_a, 2).expect("1st slot");
        let p2 = guard.try_acquire_conn(ip_a, 2).expect("2nd slot");
        assert!(
            guard.try_acquire_conn(ip_a, 2).is_none(),
            "3rd slot must be refused"
        );
        // Another IP is unaffected
        let pb = guard
            .try_acquire_conn(ip_b, 2)
            .expect("other IP unaffected");
        // Loopback is never capped
        let _pl1 = guard.try_acquire_conn(loopback, 1).unwrap();
        let _pl2 = guard.try_acquire_conn(loopback, 1).unwrap();

        // Dropping p1 immediately frees a slot via RAII!
        drop(p1);
        let p3 = guard.try_acquire_conn(ip_a, 2).expect("freed slot");
        drop((p2, p3, pb));
        assert_eq!(guard.active_tracked_ips(), 0);

        // Rate limit: 5/sec -> burst = 10 -> 11th instantaneous connect rejected, recovers after 200ms!
        let t0 = 10_000_000_000u64;
        for i in 0..10 {
            assert!(
                guard.allow_new_connection(ip_a, 5, t0),
                "burst attempt {i} should pass"
            );
        }
        assert!(
            !guard.allow_new_connection(ip_a, 5, t0),
            "11th instant connection must be rate-limited"
        );
        // After 200ms (1/5 sec), exactly 1 token refills
        assert!(guard.allow_new_connection(ip_a, 5, t0 + 200_000_000));
        // Sweeping far in the future clears idle rate entries
        guard.sweep_stale_rates(t0 + RATE_IDLE_EVICT_NS + 1_000_000_000);
    }

    #[test]
    fn conn_speed_limiters_inherit_and_override_cleanly() {
        let g = GlobalLimits {
            conn_speed_down_bytes_per_second: 500_000,
            ..GlobalLimits::default()
        };
        let s = SecretLimits {
            conn_speed_up_bytes_per_second: 100_000,
            ..SecretLimits::default()
        };
        let eff = ConnSpeedLimiters::effective(&s, &g).unwrap();
        assert!(!eff.combined.is_limited());
        assert_eq!(eff.up.rate_bps(), 100_000);
        assert_eq!(eff.down.rate_bps(), 500_000);
        assert!(eff.is_limited(true));
        assert!(eff.is_limited(false));

        assert!(
            ConnSpeedLimiters::effective(&SecretLimits::default(), &GlobalLimits::default())
                .is_none()
        );
    }
}
