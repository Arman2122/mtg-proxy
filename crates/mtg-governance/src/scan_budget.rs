//! FakeTLS CPU scan budget (`enforce` / `observe` / `off`):
//! - Calibrates actual host SHA-256 block latency once at startup using
//!   `mtg-crypto`'s real hardware-accelerated HMAC-SHA256 (`10..=2000 ns/block`).
//! - Enforces both a per-IP scan CPU quota (default `50 ms/s`, 4s burst) and
//!   a process-wide CPU% quota (default `25%` of available cores, 1s burst).
//! - Caps scan size at `MAX_SCAN_BLOCKS = 128` (~8 KiB hello).
//! - Refunds reserved cost in full upon successful secret match via
//!   [`ScanReservation::settle`].

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mtg_config::HandshakeBudgetMode;
use mtg_core::IpUnit;
use mtg_crypto::faketls::FakeTlsCandidate;
use mtg_net::coarse_now_ns;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;

use crate::hints::{MAX_SCAN_BLOCKS, hint_key};

pub const DEFAULT_BUDGET_PER_IP_MS: u32 = 50;
pub const MAX_BUDGET_PER_IP_MS: u32 = 1000;
pub const DEFAULT_BUDGET_CPU_PERCENT: u32 = 25;
pub const MAX_BUDGET_CPU_PERCENT: u32 = 100;
pub const PER_IP_BURST_SECS: f64 = 4.0;
pub const GLOBAL_BURST_SECS: f64 = 1.0;
pub const DEFAULT_BUDGET_MAX_WAIT: Duration = Duration::from_millis(150);
pub const MIN_COST_BLOCKS: usize = 12;
pub const BURST_FLOOR_HELLOS: usize = 4;
pub const MAX_BUDGET_ADDRESSES: usize = 32_768;
pub const BUDGET_ROTATION: Duration = Duration::from_secs(30 * 60);

const MIN_BLOCK_NANOS: f64 = 10.0;
const MAX_BLOCK_NANOS: f64 = 2000.0;
const CALIBRATION_RUNS: usize = 3;
const CALIBRATION_RUN: Duration = Duration::from_millis(4);
const CALIBRATION_HELLO_SIZE: usize = 517;
const CALIBRATION_CALL_BLOCKS: usize = 3 + (CALIBRATION_HELLO_SIZE + 9).div_ceil(64);

static PROCESS_BLOCK_NANOS: OnceLock<f64> = OnceLock::new();

/// Measure and cache the host CPU's single SHA-256 block latency in nanoseconds
/// using `mtg-crypto`'s real hardware-accelerated FakeTLS candidate verifier.
pub fn calibrated_block_nanos() -> f64 {
    *PROCESS_BLOCK_NANOS.get_or_init(measure_block_nanos)
}

fn measure_block_nanos() -> f64 {
    let cand = FakeTlsCandidate::new(&[0x42u8; 16]);
    let mut hello = [0x11u8; CALIBRATION_HELLO_SIZE];
    let mut best = f64::INFINITY;

    for _ in 0..CALIBRATION_RUNS {
        let mut blocks = 0usize;
        let started = Instant::now();
        loop {
            let digest = cand.midstate().hmac_slices(&[&hello]);
            hello[..32].copy_from_slice(&digest);
            blocks += CALIBRATION_CALL_BLOCKS;
            let elapsed = started.elapsed();
            if elapsed >= CALIBRATION_RUN {
                let ns = elapsed.as_nanos() as f64 / blocks as f64;
                if ns < best {
                    best = ns;
                }
                break;
            }
        }
    }

    if best.is_nan() || best > MAX_BLOCK_NANOS {
        MAX_BLOCK_NANOS
    } else if best < MIN_BLOCK_NANOS {
        MIN_BLOCK_NANOS
    } else {
        best
    }
}

/// Configuration for [`ScanBudget`].
#[derive(Debug, Clone, Copy)]
pub struct ScanBudgetConfig {
    pub mode: HandshakeBudgetMode,
    /// Per-address CPU budget in ms/s (`Some(0)` disables per-IP buckets; `None` -> 50 ms).
    pub per_ip_ms: Option<u32>,
    /// Process-wide CPU% budget (`None` / `0` -> 25%).
    pub cpu_percent: Option<u32>,
    /// Override CPU core count (`0` -> auto `available_parallelism()`).
    pub procs: usize,
    /// Override calibrated ns/block (`0.0` -> `calibrated_block_nanos()`).
    pub ns_per_block: f64,
    /// Max pacing wait before denying (`Duration::ZERO` -> 150 ms).
    pub max_wait: Duration,
}

impl Default for ScanBudgetConfig {
    fn default() -> Self {
        Self {
            mode: HandshakeBudgetMode::Enforce,
            per_ip_ms: None,
            cpu_percent: None,
            procs: 0,
            ns_per_block: 0.0,
            max_wait: DEFAULT_BUDGET_MAX_WAIT,
        }
    }
}

/// Outcome of [`ScanBudget::reserve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    Granted,
    DeniedIp,
    DeniedGlobal,
    Oversized,
}

#[derive(Debug, Clone, Copy)]
struct BucketParams {
    rate: f64,
    burst: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct BucketState {
    tokens: f64,
    last_ns: u64,
}

impl BucketState {
    fn available(&self, rate: f64, burst: f64, now_ns: u64) -> f64 {
        if self.last_ns == 0 {
            return burst;
        }
        let elapsed_secs = now_ns.saturating_sub(self.last_ns) as f64 / 1e9;
        burst.min(self.tokens + elapsed_secs * rate)
    }
}

#[derive(Debug, Default)]
struct BudgetInner {
    global: BucketState,
    current: FxHashMap<IpUnit, BucketState>,
    previous: FxHashMap<IpUnit, BucketState>,
}

/// Refundable reservation handle returned by [`ScanBudget::reserve`].
#[derive(Debug)]
pub struct ScanReservation {
    unit: Option<IpUnit>,
    cost: f64,
    ip_burst: f64,
    global_burst: f64,
    settled: bool,
}

impl ScanReservation {
    /// Settle the reservation: `success = true` refunds the full scan cost to
    /// both buckets (legitimate clients never lose scan budget!); `false` keeps
    /// the charge against scanners/probers.
    pub fn settle(&mut self, budget: &ScanBudget, success: bool) {
        if self.settled {
            return;
        }
        self.settled = true;
        if !success {
            return;
        }
        let mut guard = budget.inner.lock();
        let g = &mut *guard;
        g.global.tokens = self.global_burst.min(g.global.tokens + self.cost);
        if let Some(unit) = self.unit
            && let Some(st) = g
                .current
                .get_mut(&unit)
                .or_else(|| g.previous.get_mut(&unit))
        {
            st.tokens = self.ip_burst.min(st.tokens + self.cost);
        }
    }
}

/// Two-bucket (per-IP + process-wide) FakeTLS CPU scan budget.
#[derive(Debug)]
pub struct ScanBudget {
    mode: HandshakeBudgetMode,
    max_wait: Duration,
    ns_per_block: f64,
    per_ip: BucketParams,
    global: BucketParams,
    inner: Mutex<BudgetInner>,
}

impl ScanBudget {
    pub fn new(cfg: ScanBudgetConfig) -> Self {
        let ns_per_block = if cfg.ns_per_block > 0.0 {
            cfg.ns_per_block
        } else {
            calibrated_block_nanos()
        };
        let procs = if cfg.procs > 0 {
            cfg.procs
        } else {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        };
        let per_ip_ms = match cfg.per_ip_ms {
            Some(0) => 0,
            Some(v) => v.min(MAX_BUDGET_PER_IP_MS),
            None => DEFAULT_BUDGET_PER_IP_MS,
        };
        let cpu_pct = cfg
            .cpu_percent
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_BUDGET_CPU_PERCENT)
            .min(MAX_BUDGET_CPU_PERCENT);
        let max_wait = if cfg.max_wait.is_zero() {
            DEFAULT_BUDGET_MAX_WAIT
        } else {
            cfg.max_wait
        };

        let per_ip_rate = if per_ip_ms > 0 {
            f64::from(per_ip_ms) * 1_000_000.0 / ns_per_block
        } else {
            0.0
        };
        let global_rate =
            (f64::from(cpu_pct) / 100.0) * (procs as f64) * 1_000_000_000.0 / ns_per_block;

        Self {
            mode: cfg.mode,
            max_wait,
            ns_per_block,
            per_ip: BucketParams {
                rate: per_ip_rate,
                burst: per_ip_rate * PER_IP_BURST_SECS,
            },
            global: BucketParams {
                rate: global_rate,
                burst: global_rate * GLOBAL_BURST_SECS,
            },
            inner: Mutex::new(BudgetInner::default()),
        }
    }

    #[inline]
    pub const fn mode(&self) -> HandshakeBudgetMode {
        self.mode
    }

    #[inline]
    pub const fn is_enforced(&self) -> bool {
        matches!(self.mode, HandshakeBudgetMode::Enforce)
    }

    #[inline]
    pub const fn block_nanos(&self) -> f64 {
        self.ns_per_block
    }

    #[inline]
    pub const fn is_oversized(&self, blocks: usize) -> bool {
        !matches!(self.mode, HandshakeBudgetMode::Off) && blocks > MAX_SCAN_BLOCKS
    }

    /// Reserve scan budget for scanning `candidates` FakeTLS secrets on a hello
    /// of `blocks` SHA-256 blocks from `ip`.
    pub fn reserve(
        &self,
        ip: IpAddr,
        blocks: usize,
        candidates: usize,
    ) -> (Option<ScanReservation>, Duration, BudgetVerdict) {
        self.reserve_at(ip, blocks, candidates, coarse_now_ns())
    }

    pub fn reserve_at(
        &self,
        ip: IpAddr,
        blocks: usize,
        candidates: usize,
        now_ns: u64,
    ) -> (Option<ScanReservation>, Duration, BudgetVerdict) {
        if matches!(self.mode, HandshakeBudgetMode::Off) {
            return (None, Duration::ZERO, BudgetVerdict::Granted);
        }
        if blocks > MAX_SCAN_BLOCKS {
            return (None, Duration::ZERO, BudgetVerdict::Oversized);
        }
        if candidates == 0 {
            return (None, Duration::ZERO, BudgetVerdict::Granted);
        }

        let cost = (candidates as f64) * (blocks.clamp(MIN_COST_BLOCKS, MAX_SCAN_BLOCKS) as f64);
        let floor = (BURST_FLOOR_HELLOS * candidates * MIN_COST_BLOCKS) as f64;
        let ip_burst = self.per_ip.burst.max(floor);
        let global_burst = self.global.burst.max(floor);

        let unit = if self.per_ip.rate > 0.0 {
            hint_key(ip)
        } else {
            None
        };

        let mut g = self.inner.lock();
        let max_wait_s = self.max_wait.as_secs_f64();

        // 1. Check per-IP bucket if keyed and capacity permits
        let mut ip_wait_s = 0.0f64;
        let mut ip_after = None;
        let mut charged_unit = None;

        if let Some(u) = unit {
            let st_opt = if let Some(&st) = g.current.get(&u) {
                Some(st)
            } else if let Some(st) = g.previous.remove(&u) {
                g.current.insert(u, st);
                Some(st)
            } else if g.current.len() + g.previous.len() < MAX_BUDGET_ADDRESSES {
                Some(BucketState::default())
            } else {
                None
            };

            if let Some(st) = st_opt {
                let after = st.available(self.per_ip.rate, ip_burst, now_ns) - cost;
                if after < 0.0 {
                    if -after > self.per_ip.rate * max_wait_s {
                        return (None, Duration::ZERO, BudgetVerdict::DeniedIp);
                    }
                    ip_wait_s = -after / self.per_ip.rate;
                }
                ip_after = Some(after);
                charged_unit = Some(u);
            }
        }

        // 2. Check process-wide bucket
        let global_after = g.global.available(self.global.rate, global_burst, now_ns) - cost;
        let mut wait_s = ip_wait_s;
        if global_after < 0.0 {
            if -global_after > self.global.rate * max_wait_s {
                return (None, Duration::ZERO, BudgetVerdict::DeniedGlobal);
            }
            wait_s = wait_s.max(-global_after / self.global.rate);
        }

        // 3. Both buckets can pay: commit atomically!
        if let (Some(u), Some(after)) = (charged_unit, ip_after) {
            let st = g.current.entry(u).or_default();
            st.tokens = after;
            st.last_ns = st.last_ns.max(now_ns);
        }
        g.global.tokens = global_after;
        g.global.last_ns = g.global.last_ns.max(now_ns);

        let res = ScanReservation {
            unit: charged_unit,
            cost,
            ip_burst,
            global_burst,
            settled: false,
        };
        let wait = if matches!(self.mode, HandshakeBudgetMode::Observe) || wait_s <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_nanos((wait_s * 1e9).ceil() as u64)
        };
        (Some(res), wait, BudgetVerdict::Granted)
    }

    /// Periodic 30-minute address bucket generation rotation.
    pub fn rotate(&self) {
        let mut g = self.inner.lock();
        g.previous = std::mem::take(&mut g.current);
    }
}
