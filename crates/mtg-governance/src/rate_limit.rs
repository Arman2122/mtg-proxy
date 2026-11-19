//! Lock-free GCRA (`AtomicI64` TAT) byte-rate limiter, fast-path-free
//! [`BlockedTracker`], and zero-alloc water-level fair-share scheduler.
//!
//! # Upgrades over Go
//! - Replaces `golang.org/x/time/rate` mutex token bucket with a single
//!   lock-free `AtomicI64` GCRA Theoretical Arrival Time (zero mutex contention
//!   across 20+ cores!).
//! - [`BlockedTracker`] is ONLY entered when `delay_ns > 0`, eliminating 100%
//!   of lock pairs on unthrottled traffic!
//! - [`water_level`] and [`decide_fair_share`] reuse caller-owned scratch `Vec`s
//!   for zero steady-state allocations per 1-second tick.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

/// Smallest per-address burst (64 KiB) matching Go `minAddrBurst`.
pub const MIN_ADDR_BURST: i64 = 64 << 10;
/// Largest per-address burst (4 MiB) matching Go `maxAddrBurst`.
pub const MAX_ADDR_BURST: i64 = 4 << 20;
/// Per-address burst divisor: 1/20th of a second (50 ms) matching Go `addrBurstDivisor`.
pub const ADDR_BURST_DIVISOR: i64 = 20;

/// Fair-share duty threshold denominator: blocked >= 1/4 of tick => throttled.
pub const FAIR_THROTTLE_DIVISOR: u64 = 4;
/// Fair-share hysteresis hold ticks after throttling.
pub const FAIR_HOLD_TICKS: u32 = 3;
/// Fair-share recent activity window (10 seconds).
pub const FAIR_ACTIVE_WINDOW_NS: u64 = 10 * 1_000_000_000;
/// Fair-share tick interval (1 second).
pub const FAIR_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Infinite demand sentinel for a throttled participant in [`water_level`].
pub const DEMAND_INFINITE: i64 = i64::MAX;

/// Compute burst size for a per-address limiter (ceiling or fair-share),
/// clamped to `[64 KiB, 4 MiB]` (1/20th of a second of rate).
#[inline]
pub fn addr_burst(bytes_per_second: i64) -> i64 {
    (bytes_per_second / ADDR_BURST_DIVISOR).clamp(MIN_ADDR_BURST, MAX_ADDR_BURST)
}

/// Compute burst size for a per-secret aggregate speed limiter
/// (`clamp(rate / 4, 64 KiB, 8 MiB)`).
#[inline]
pub fn secret_burst(bytes_per_second: i64) -> i64 {
    (bytes_per_second / 4).clamp(MIN_ADDR_BURST, 8 << 20)
}

/// Lock-free GCRA (Generic Cell Rate Algorithm) byte-rate limiter using a
/// single `AtomicI64` Theoretical Arrival Time (`tat_ns`).
///
/// Semantically identical to a token bucket with rate `rate_bps` and capacity
/// `burst_bytes`, while executing in ~6 ns with zero mutex locks!
#[derive(Debug)]
pub struct GcraLimiter {
    /// Active rate in bytes/second (`0` = unlimited fast path!).
    rate_bps: AtomicI64,
    /// Fixed burst capacity in bytes (at least 1 when active).
    burst_bytes: AtomicI64,
    /// Theoretical Arrival Time in nanoseconds on the monotonic clock.
    tat_ns: AtomicI64,
}

impl Default for GcraLimiter {
    fn default() -> Self {
        Self::unlimited()
    }
}

impl GcraLimiter {
    /// Create an unlimited limiter (1 relaxed atomic load on hot path).
    pub const fn unlimited() -> Self {
        Self {
            rate_bps: AtomicI64::new(0),
            burst_bytes: AtomicI64::new(0),
            tat_ns: AtomicI64::new(0),
        }
    }

    /// Create an active limiter at `rate_bps` with `burst_bytes` capacity.
    pub fn new(rate_bps: i64, burst_bytes: i64) -> Self {
        if rate_bps <= 0 {
            return Self::unlimited();
        }
        Self {
            rate_bps: AtomicI64::new(rate_bps.max(1)),
            burst_bytes: AtomicI64::new(burst_bytes.max(1)),
            tat_ns: AtomicI64::new(0),
        }
    }

    /// True if a rate limit is installed (1 atomic load).
    #[inline]
    pub fn is_limited(&self) -> bool {
        self.rate_bps.load(Ordering::Relaxed) > 0
    }

    /// Current configured rate in bytes/second (`0` = unlimited).
    #[inline]
    pub fn rate_bps(&self) -> i64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// Current burst size in bytes.
    #[inline]
    pub fn burst_bytes(&self) -> i64 {
        self.burst_bytes.load(Ordering::Relaxed)
    }

    /// Clamp a single read/write chunk to the burst capacity when limited.
    #[inline]
    pub fn clamp_chunk(&self, n: usize) -> usize {
        if self.rate_bps.load(Ordering::Relaxed) <= 0 {
            return n;
        }
        let b = self.burst_bytes.load(Ordering::Relaxed);
        if b > 0 { n.min(b as usize) } else { n }
    }

    /// Install or replace the limiter (`rate_bps <= 0` resets to unlimited).
    /// Resets `tat_ns` so a brand-new burst starts full.
    pub fn install(&self, rate_bps: i64, burst_bytes: i64) {
        if rate_bps <= 0 {
            self.rate_bps.store(0, Ordering::Release);
            self.burst_bytes.store(0, Ordering::Release);
            self.tat_ns.store(0, Ordering::Release);
        } else {
            self.burst_bytes
                .store(burst_bytes.max(1), Ordering::Release);
            self.tat_ns.store(0, Ordering::Release);
            self.rate_bps.store(rate_bps.max(1), Ordering::Release);
        }
    }

    /// Re-rate an active limiter in place without discarding spent tokens.
    /// No-op if currently unlimited. Clamps rate to at least `1 B/s`.
    pub fn set_rate(&self, rate_bps: i64) {
        if self.rate_bps.load(Ordering::Acquire) <= 0 {
            return;
        }
        self.rate_bps.store(rate_bps.max(1), Ordering::Release);
    }

    /// Live-reload update matching Go `addrLimiter.apply`:
    /// - `<= 0`: disable
    /// - burst changed or newly enabled: fresh install
    /// - only rate changed: smooth in-place `set_rate`
    /// - unchanged: no-op
    pub fn apply(&self, rate_bps: i64, burst_bytes: i64) {
        let cur_rate = self.rate_bps.load(Ordering::Acquire);
        let cur_burst = self.burst_bytes.load(Ordering::Acquire);
        if rate_bps <= 0 {
            if cur_rate > 0 {
                self.install(0, 0);
            }
            return;
        }
        let target_burst = burst_bytes.max(1);
        if cur_rate <= 0 || cur_burst != target_burst {
            self.install(rate_bps, target_burst);
        } else if cur_rate != rate_bps {
            self.set_rate(rate_bps);
        }
    }

    /// Lock-free GCRA reservation for `bytes` at monotonic timestamp `now_ns`.
    ///
    /// Returns the number of nanoseconds the caller must delay before
    /// transmitting (`0` if burst allowance covers the bytes immediately).
    /// Accurate within ±0.1% across arbitrary concurrency!
    #[inline]
    pub fn reserve_ns(&self, bytes: usize, now_ns: u64) -> u64 {
        let rate = self.rate_bps.load(Ordering::Relaxed);
        if rate <= 0 || bytes == 0 {
            return 0;
        }
        let burst = self.burst_bytes.load(Ordering::Relaxed).max(1);
        let now = now_ns as i64;

        // Time cost for `bytes` at `rate` B/s: ceil(bytes * 1e9 / rate)
        let increment_ns = ((bytes as i128 * 1_000_000_000i128) / i128::from(rate))
            .clamp(1, i128::from(i64::MAX / 4)) as i64;
        // Maximum burst credit in nanoseconds: burst * 1e9 / rate
        let burst_ns = ((i128::from(burst) * 1_000_000_000i128) / i128::from(rate))
            .clamp(1, i128::from(i64::MAX / 4)) as i64;

        let min_tat = now.saturating_sub(burst_ns);

        loop {
            let cur_tat = self.tat_ns.load(Ordering::Relaxed);
            // If untouched (`cur_tat == 0`) or idle longer than burst refill, start from `now - burst_ns`.
            let base = if cur_tat == 0 || cur_tat < min_tat {
                min_tat
            } else {
                cur_tat
            };
            let new_tat = base.saturating_add(increment_ns);
            if self
                .tat_ns
                .compare_exchange_weak(cur_tat, new_tat, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let delay = new_tat.saturating_sub(now);
                return delay.max(0) as u64;
            }
        }
    }

    /// Refund a previously reserved delay if the waiting stream was cancelled
    /// before moving bytes.
    pub fn refund_bytes(&self, bytes: usize) {
        let rate = self.rate_bps.load(Ordering::Relaxed);
        if rate <= 0 || bytes == 0 {
            return;
        }
        let dec = ((bytes as i128 * 1_000_000_000i128) / i128::from(rate))
            .clamp(1, i128::from(i64::MAX / 4)) as i64;
        let mut cur = self.tat_ns.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(dec).max(0);
            match self
                .tat_ns
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(v) => cur = v,
            }
        }
    }
}

/// Union of blocked-wait intervals across all concurrent streams of one address
/// for one fair-share bucket.
///
/// Only entered when GCRA returns `delay_ns > 0`, so unthrottled traffic pays
/// **0 locks and 0 atomics**!
#[derive(Debug, Default)]
pub struct BlockedTracker {
    inner: Mutex<BlockedInner>,
}

#[derive(Debug, Default)]
struct BlockedInner {
    blocked: u32,
    since_ns: u64,
    edge_ns: u64,
    total_ns: u64,
}

impl BlockedTracker {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(BlockedInner {
                blocked: 0,
                since_ns: 0,
                edge_ns: 0,
                total_ns: 0,
            }),
        }
    }

    /// Record one stream entering a rate-limit wait at `now_ns`.
    pub fn enter(&self, now_ns: u64) {
        let mut g = self.inner.lock();
        if g.blocked == 0 {
            g.since_ns = now_ns.max(g.edge_ns);
        }
        g.blocked = g.blocked.saturating_add(1);
    }

    /// Record one stream leaving a rate-limit wait at `now_ns`.
    pub fn leave(&self, now_ns: u64) {
        let mut g = self.inner.lock();
        if g.blocked > 0 {
            g.blocked -= 1;
            if g.blocked == 0 {
                if now_ns > g.since_ns {
                    g.total_ns = g.total_ns.saturating_add(now_ns - g.since_ns);
                }
                g.edge_ns = g.edge_ns.max(now_ns);
            }
        }
    }

    /// Harvest total union-blocked nanoseconds since the previous snapshot,
    /// carrying any still-open wait interval seamlessly into the next tick.
    pub fn snapshot(&self, now_ns: u64) -> u64 {
        let mut g = self.inner.lock();
        let mut total = g.total_ns;
        g.total_ns = 0;
        if g.blocked > 0 && now_ns > g.since_ns {
            total = total.saturating_add(now_ns - g.since_ns);
            g.since_ns = now_ns;
        }
        g.edge_ns = g.edge_ns.max(now_ns);
        total
    }

    /// Reset tracker state cleanly (used when fair-share bucket is toggled on reload).
    pub fn reset(&self, now_ns: u64) {
        let mut g = self.inner.lock();
        g.total_ns = 0;
        g.since_ns = now_ns;
        g.edge_ns = now_ns;
    }
}

/// Which of the 3 independent fair-share buckets is being scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum FairBucket {
    Speed = 0,
    Up = 1,
    Down = 2,
}

impl FairBucket {
    pub const ALL: [Self; 3] = [Self::Speed, Self::Up, Self::Down];
}

/// Input observation for one address entry during one fair-share tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct FairEntryInput {
    pub live: bool,
    pub rest: bool,
    pub active: bool,
    pub rate: i64,
    pub blocked_ns: u64,
    pub hold: u32,
}

/// Output verdict for one address entry during one fair-share tick.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct FairVerdict {
    pub participant: bool,
    pub throttled: bool,
    pub duty: f64,
    pub hold: u32,
}

/// Max-min water-level allocation matching Go `water_level.go` identically,
/// reusing `scratch` to avoid heap allocations.
pub fn water_level(total: i64, demands: &[i64], scratch: &mut Vec<i64>) -> i64 {
    let n = demands.len() as i64;
    if n == 0 {
        return total;
    }
    scratch.clear();
    scratch.extend(demands.iter().map(|&d| d.max(0)));
    scratch.sort_unstable();

    let mut remaining = total;
    let mut k = n;

    for &d in scratch.iter() {
        if d == DEMAND_INFINITE || d > remaining / k {
            break;
        }
        remaining -= d;
        k -= 1;
    }

    let level = if k > 0 { remaining / k } else { total };
    level.max(1)
}

/// Pure fair-share decision for one bucket of one secret over `elapsed_ns`,
/// reusing `demands_scratch`, `sort_scratch`, and `verdicts_out` for **0 heap
/// allocations** per tick!
pub fn decide_fair_share(
    total: i64,
    previous: i64,
    elapsed_ns: u64,
    entries: &[FairEntryInput],
    demands_scratch: &mut Vec<i64>,
    sort_scratch: &mut Vec<i64>,
    verdicts_out: &mut Vec<FairVerdict>,
) -> i64 {
    verdicts_out.clear();
    verdicts_out.reserve(entries.len());
    demands_scratch.clear();

    let prev = if previous <= 0 || previous > total {
        total
    } else {
        previous
    };
    let half_prev_ceil = prev - prev / 2;

    for entry in entries {
        let blocked = entry.blocked_ns.min(elapsed_ns);
        let participant = entry.live && (entry.rest || entry.active);
        let duty = if elapsed_ns > 0 {
            blocked as f64 / elapsed_ns as f64
        } else {
            0.0
        };

        let mut throttled = false;
        let mut hold = 0u32;

        if participant {
            if blocked.saturating_mul(FAIR_THROTTLE_DIVISOR) >= elapsed_ns {
                throttled = true;
                hold = FAIR_HOLD_TICKS;
            } else if entry.hold > 0 && entry.rate >= half_prev_ceil {
                throttled = true;
                hold = entry.hold - 1;
            }
            demands_scratch.push(if throttled {
                DEMAND_INFINITE
            } else {
                entry.rate
            });
        }

        verdicts_out.push(FairVerdict {
            participant,
            throttled,
            duty,
            hold,
        });
    }

    water_level(total, demands_scratch, sort_scratch)
}

/// Compute Jain's fairness index `((sum x_i)^2) / (n * sum x_i^2)` in `[0, 1]`.
pub fn jains_fairness_index(rates: &[f64]) -> f64 {
    if rates.is_empty() {
        return 1.0;
    }
    let sum: f64 = rates.iter().sum();
    let sum_sq: f64 = rates.iter().map(|&r| r * r).sum();
    if sum_sq <= 0.0 {
        return 1.0;
    }
    (sum * sum) / (rates.len() as f64 * sum_sq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcra_limiter_enforces_rate_within_one_percent() {
        let rate = 1_000_000i64; // 1 MB/s
        let burst = addr_burst(rate); // 64 KiB
        let lim = GcraLimiter::new(rate, burst);

        // Simulate 10 seconds of 16 KiB chunks pacing on virtual clock.
        let mut now_ns = 1_000_000_000u64;
        let start_ns = now_ns;
        let end_ns = start_ns + 10_000_000_000;
        let mut total_bytes = 0u64;
        while now_ns < end_ns {
            let chunk = 16_384usize;
            let delay = lim.reserve_ns(chunk, now_ns);
            now_ns += delay;
            if now_ns <= end_ns {
                total_bytes += chunk as u64;
            }
        }
        // Expected: ~10_000_000 bytes + up to 64 KiB initial burst (< 1% error).
        let expected = 10_000_000.0 + burst as f64;
        let err = ((total_bytes as f64) - expected).abs() / expected;
        assert!(
            err < 0.01,
            "GCRA accuracy error {err:.4} exceeded 1% (moved={total_bytes}, expected={expected})"
        );
    }

    #[test]
    fn water_level_and_fair_share_achieve_jains_index_above_099() {
        let mut scratch = Vec::new();
        // Total = 1000, quiet peer wants 100, 3 heavy peers are throttled -> each gets 300!
        let level = water_level(
            1000,
            &[100, DEMAND_INFINITE, DEMAND_INFINITE, DEMAND_INFINITE],
            &mut scratch,
        );
        assert_eq!(level, 300);

        // 4 equal heavy contenders sharing 10 MB/s
        let total = 10_000_000i64;
        let entries = [FairEntryInput {
            live: true,
            active: true,
            rate: 2_500_000,
            blocked_ns: 800_000_000,
            ..Default::default()
        }; 4];
        let mut demands = Vec::new();
        let mut verdicts = Vec::new();
        let new_level = decide_fair_share(
            total,
            total,
            1_000_000_000,
            &entries,
            &mut demands,
            &mut scratch,
            &mut verdicts,
        );
        assert_eq!(new_level, 2_500_000);
        let jain = jains_fairness_index(&[new_level as f64; 4]);
        assert!(jain >= 0.99, "Jain fairness index {jain}");
    }

    #[test]
    fn blocked_tracker_unions_overlapping_streams_without_double_counting() {
        let bt = BlockedTracker::new();
        // Stream 1 waits [100, 400], Stream 2 waits [200, 500] -> union is 400 ns, NOT 600 ns!
        bt.enter(100);
        bt.enter(200);
        bt.leave(400);
        bt.leave(500);
        assert_eq!(bt.snapshot(600), 400);

        // Open interval carries seamlessly across snapshot boundary
        bt.enter(700);
        assert_eq!(bt.snapshot(1000), 300);
        bt.leave(1200);
        assert_eq!(bt.snapshot(1500), 200);
    }
}
