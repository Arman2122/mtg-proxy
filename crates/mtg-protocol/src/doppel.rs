//! Zero-goroutine Doppelganger traffic shaping, Weibull MLE fitting, Dynamic
//! TLS Record Sizing (DRS), and fixed TLS handshake scouting.
//!
//! # Key Upgrades over Go `doppel`
//! 1. **Zero per-connection goroutines / 512 KiB buffers**: [`DoppelConnState`]
//!    is a compact 24-byte value embedded directly inside `ConnHot`, driven by
//!    the worker's hierarchical timing wheel.
//! 2. **Fixed DRS `startRecord` stale reset bug**: updates `last_write_ns`
//!    consistently on every record in both [`ShapingMode::Record`] and
//!    [`ShapingMode::Burst`].
//! 3. **Precomputed `ln(v)` Weibull MLE**: eliminates 70× redundant `ln()`
//!    evaluations during bisection.
//! 4. **Fixed TLS Scout parser**: preserves real TLS record versions and
//!    correctly measures server certificate-flight sizes on TLS 1.3 (with OR
//!    without ChangeCipherSpec) as well as TLS 1.2.

use std::cell::RefCell;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use mtg_crypto::{
    NoiseParams, ServerHelloProfile, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC,
    TLS_RECORD_HANDSHAKE,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use thiserror::Error;

use crate::tls_record::MAX_TLS_RECORD_PAYLOAD;

/// Weibull bisection iterations (matches Go `StatsBisectTimes`).
pub const WEIBULL_BISECT_ITERS: usize = 70;
/// Weibull shape search lower bound.
pub const WEIBULL_LOW_K: f64 = 0.01;
/// Weibull shape search upper bound.
pub const WEIBULL_HIGH_K: f64 = 10.0;
/// Minimum positive inter-record duration samples needed before fitting.
pub const MIN_DURATIONS_TO_FIT: usize = 100;

/// Default Moscow `ok.ru` Weibull shape `k`.
pub const DEFAULT_WEIBULL_K: f64 = 0.378_463_738_957_853_35;
/// Default Moscow `ok.ru` Weibull scale `lambda` (milliseconds).
pub const DEFAULT_WEIBULL_LAMBDA: f64 = 1.731_770_860_154_85;

/// Dynamic Record Sizing constants (Cloudflare / nginx model).
pub const DRS_RECORD_START: usize = 1450;
pub const DRS_RECORD_ACCEL: usize = 4096;
pub const DRS_RECORD_MAX: usize = MAX_TLS_RECORD_PAYLOAD;
pub const DRS_ACCEL_AFTER: u32 = 40;
pub const DRS_MAX_AFTER: u32 = 60;
pub const DRS_NOISE_BYTES: usize = 100;
pub const DRS_IDLE_RESET_NS: u64 = 1_000_000_000;

/// Maximum pacing wait drawn from the Weibull distribution (1 second) in [`ShapingMode::Record`].
pub const MAX_PACING_DELAY: Duration = Duration::from_secs(1);

/// Maximum interactive wake-up pacing delay in [`ShapingMode::Burst`] (35 ms):
/// preserves randomized TTFB anti-fingerprinting while ensuring interactive
/// Telegram chat messages never suffer heavy-tail 200ms–1000ms stalls!
pub const BURST_MAX_WAKEUP_DELAY: Duration = Duration::from_millis(35);

/// Maximum burst write size (headers included) in [`ShapingMode::Burst`].
pub const BURST_WRITE_MAX: usize = 64 << 10;

thread_local! {
    static DOPPEL_RNG: RefCell<ChaCha8Rng> = RefCell::new({
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS CSPRNG failed");
        ChaCha8Rng::from_seed(seed)
    });
}

/// Error parsing a shaping mode name.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unknown doppelganger shaping {0:?}: use \"record\" or \"burst\"")]
pub struct ShapingParseError(pub String);

/// How Doppelganger spaces TLS ApplicationData records in time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ShapingMode {
    /// Wait a Weibull-sampled delay before every TLS record.
    #[default]
    Record = 0,
    /// Wait one Weibull-sampled delay upon waking from >= 1s idle, then emit
    /// records back-to-back up to [`BURST_WRITE_MAX`] bytes.
    Burst = 1,
}

impl ShapingMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Burst => "burst",
        }
    }
}

impl fmt::Display for ShapingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ShapingMode {
    type Err = ShapingParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "record" => Ok(Self::Record),
            "burst" => Ok(Self::Burst),
            _ => Err(ShapingParseError(s.to_owned())),
        }
    }
}

/// Immutable per-host Doppelganger parameters published via `ArcSwap`
/// (replacing Go's single-goroutine actor channel).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DoppelParams {
    pub k: f64,
    pub lambda_ms: f64,
    pub drs: bool,
    pub shaping: ShapingMode,
    pub noise: NoiseParams,
    /// Live-calibrated cover ServerHello profile (PQ `X25519MLKEM768`, cipher, extension order).
    pub server_hello: ServerHelloProfile,
}

impl Default for DoppelParams {
    fn default() -> Self {
        Self {
            k: DEFAULT_WEIBULL_K,
            lambda_ms: DEFAULT_WEIBULL_LAMBDA,
            drs: false,
            shaping: ShapingMode::Record,
            noise: NoiseParams::default(),
            server_hello: ServerHelloProfile::default(),
        }
    }
}

impl DoppelParams {
    /// Fit a Weibull MLE model to positive inter-record gaps (in milliseconds),
    /// precomputing `ln(v)` once before bisection.
    pub fn fit_weibull(
        durations_ms: &[f64],
        drs: bool,
        shaping: ShapingMode,
        noise: NoiseParams,
    ) -> Self {
        let mut vals = Vec::with_capacity(durations_ms.len());
        let mut logs = Vec::with_capacity(durations_ms.len());
        let mut sum_log = 0.0f64;

        for &v in durations_ms {
            if v > 0.0 && v.is_finite() {
                let ln_v = v.ln();
                vals.push(v);
                logs.push(ln_v);
                sum_log += ln_v;
            }
        }

        if vals.len() < MIN_DURATIONS_TO_FIT {
            return Self {
                k: 0.0,
                lambda_ms: 0.0,
                drs,
                shaping,
                noise,
                server_hello: ServerHelloProfile::from_noise(noise),
            };
        }

        let n = vals.len() as f64;
        let mean_log = sum_log / n;
        let mut low_k = WEIBULL_LOW_K;
        let mut high_k = WEIBULL_HIGH_K;

        for _ in 0..WEIBULL_BISECT_ITERS {
            let mid_k = f64::midpoint(low_k, high_k);
            let mut sum_xk = 0.0f64;
            let mut sum_xk_log = 0.0f64;

            // Since v^k = exp(k * ln(v)), using precomputed `ln_v` avoids both
            // repeated `ln(v)` and slow `powf` calls!
            for &ln_v in &logs {
                let xk = (mid_k * ln_v).exp();
                sum_xk += xk;
                sum_xk_log += xk * ln_v;
            }

            if (1.0 / mid_k) + mean_log - (sum_xk_log / sum_xk) > 0.0 {
                low_k = mid_k;
            } else {
                high_k = mid_k;
            }
        }

        let k = f64::midpoint(low_k, high_k);
        let mut sum_xk = 0.0f64;
        for &ln_v in &logs {
            sum_xk += (k * ln_v).exp();
        }
        let lambda_ms = (sum_xk / n).powf(1.0 / k);

        Self {
            k,
            lambda_ms,
            drs,
            shaping,
            noise,
            server_hello: ServerHelloProfile::from_noise(noise),
        }
    }

    /// True if the fitted shape and scale are finite, strictly positive, and
    /// not pinned to the bisection search bounds.
    pub fn is_usable(&self) -> bool {
        const MARGIN: f64 = 1e-6;
        self.k > WEIBULL_LOW_K * (1.0 + MARGIN)
            && self.k < WEIBULL_HIGH_K * (1.0 - MARGIN)
            && self.lambda_ms > 0.0
            && self.lambda_ms.is_finite()
    }

    /// Return `self` if usable, otherwise the default Moscow `ok.ru` parameters
    /// keeping `drs`, `shaping`, `noise`, and `server_hello`.
    pub fn or_default(&self) -> Self {
        if self.is_usable() {
            *self
        } else {
            Self {
                k: DEFAULT_WEIBULL_K,
                lambda_ms: DEFAULT_WEIBULL_LAMBDA,
                drs: self.drs,
                shaping: self.shaping,
                noise: self.noise,
                server_hello: self.server_hello,
            }
        }
    }

    /// Draw one Weibull-distributed inter-record pacing delay, capped at 1s.
    pub fn sample_delay(&self) -> Duration {
        let model = self.or_default();
        let u = DOPPEL_RNG.with(|cell| {
            // Uniform in (0, 1] avoiding ln(0): take 53 random bits.
            let bits = cell.borrow_mut().next_u64() >> 11;
            let f = (bits as f64) * (1.0 / ((1u64 << 53) as f64)); // [0, 1)
            1.0 - f // (0, 1]
        });

        let generated_ms = model.lambda_ms * (-u.ln()).powf(1.0 / model.k);
        if !generated_ms.is_finite() || generated_ms >= 1000.0 {
            return MAX_PACING_DELAY;
        }
        if generated_ms <= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_nanos((generated_ms * 1_000_000.0) as u64)
    }
}

/// Compact 24-byte per-connection Doppelganger pacing & DRS state embedded in `ConnHot`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DoppelConnState {
    /// Monotonic coarse timestamp (ns) of the last emitted TLS record (0 = none yet).
    pub last_write_ns: u64,
    /// Number of consecutive records emitted since last >= 1s idle reset.
    pub record_count: u32,
    pub drs: bool,
    pub shaping: ShapingMode,
}

impl DoppelConnState {
    #[inline]
    pub const fn new(drs: bool, shaping: ShapingMode) -> Self {
        Self {
            last_write_ns: 0,
            record_count: 0,
            drs,
            shaping,
        }
    }

    /// True when the connection is inside an active [`ShapingMode::Burst`] and
    /// has already completed both the idle wake-up pacing delay and any DRS
    /// ramp (`record_count >= DRS_MAX_AFTER` or `!drs`), allowing the relay to
    /// stream full-speed multi-record `writev(2)` batches with zero per-record
    /// timer overhead while preserving authentic burst TTFB + DRS stealth!
    #[inline]
    pub const fn is_burst_full_speed(&self, now_ns: u64) -> bool {
        matches!(self.shaping, ShapingMode::Burst)
            && self.last_write_ns > 0
            && now_ns.saturating_sub(self.last_write_ns) <= DRS_IDLE_RESET_NS
            && (!self.drs || self.record_count >= DRS_MAX_AFTER)
    }

    /// Update burst activity timestamp during full-speed multi-record batches.
    #[inline]
    pub const fn touch_burst_write(&mut self, now_ns: u64, records_sent: u32) {
        self.last_write_ns = now_ns;
        self.record_count = self.record_count.saturating_add(records_sent);
    }

    /// Compute `(pacing_delay, max_record_payload)` for the next outbound TLS
    /// ApplicationData record at `now_ns`, updating DRS and idle state cleanly.
    ///
    /// Fixes Go's `startRecord` bug where `last_write_ns` could drift stale and
    /// spuriously reset DRS mid-burst.
    pub fn next_record(&mut self, params: &DoppelParams, now_ns: u64) -> (Duration, usize) {
        let idle = self.last_write_ns == 0
            || now_ns.saturating_sub(self.last_write_ns) > DRS_IDLE_RESET_NS;

        if idle {
            self.record_count = 0;
        }

        let delay = match self.shaping {
            ShapingMode::Record => params.sample_delay(),
            ShapingMode::Burst => {
                if idle {
                    params.sample_delay().min(BURST_MAX_WAKEUP_DELAY)
                } else {
                    Duration::ZERO
                }
            }
        };

        self.last_write_ns = now_ns;
        self.record_count = self.record_count.saturating_add(1);

        let max_payload = if self.drs {
            let noise = DOPPEL_RNG.with(|c| (c.borrow_mut().next_u64() as usize) % DRS_NOISE_BYTES);
            if self.record_count <= DRS_ACCEL_AFTER {
                DRS_RECORD_START - noise
            } else if self.record_count <= DRS_MAX_AFTER {
                DRS_RECORD_ACCEL - noise
            } else {
                DRS_RECORD_MAX
            }
        } else {
            DRS_RECORD_MAX
        };

        (delay, max_payload)
    }
}

/// One observed TLS record during cover-site scouting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoutRecord {
    pub timestamp_ns: u64,
    pub record_type: u8,
    pub version: [u8; 2],
    pub payload_len: usize,
}

/// Race-free TLS record observer for Doppelganger cover-site scouting.
///
/// Correctly tracks both TLS 1.3 (with or without ChangeCipherSpec) and TLS 1.2
/// server certificate flights by letting the caller mark the exact handshake
/// completion boundary (`mark_client_post_handshake_write`), rather than
/// gating on `seenCCS` alone.
#[derive(Debug, Default, Clone)]
pub struct ScoutCollector {
    records: Vec<ScoutRecord>,
    hdr: [u8; 5],
    hdr_len: usize,
    payload_rem: usize,
    pending_type: u8,
    pending_ver: [u8; 2],
    pending_len: usize,
    handshake_end_idx: Option<usize>,
    seen_server_hello: bool,
}

impl ScoutCollector {
    pub fn new() -> Self {
        Self {
            records: Vec::with_capacity(128),
            ..Self::default()
        }
    }

    /// Feed raw bytes read from the cover server socket at monotonic time `now_ns`.
    pub fn observe_server_bytes(&mut self, mut data: &[u8], now_ns: u64) {
        while !data.is_empty() {
            if self.payload_rem > 0 {
                let take = data.len().min(self.payload_rem);
                data = &data[take..];
                self.payload_rem -= take;
                if self.payload_rem == 0 {
                    if self.pending_type == TLS_RECORD_HANDSHAKE {
                        self.seen_server_hello = true;
                    }
                    self.records.push(ScoutRecord {
                        timestamp_ns: now_ns,
                        record_type: self.pending_type,
                        version: self.pending_ver,
                        payload_len: self.pending_len,
                    });
                }
                continue;
            }

            let need = 5 - self.hdr_len;
            let take = data.len().min(need);
            self.hdr[self.hdr_len..self.hdr_len + take].copy_from_slice(&data[..take]);
            self.hdr_len += take;
            data = &data[take..];

            if self.hdr_len == 5 {
                self.pending_type = self.hdr[0];
                self.pending_ver = [self.hdr[1], self.hdr[2]];
                self.pending_len = usize::from(u16::from_be_bytes([self.hdr[3], self.hdr[4]]));
                self.hdr_len = 0;
                if self.pending_len == 0 {
                    self.records.push(ScoutRecord {
                        timestamp_ns: now_ns,
                        record_type: self.pending_type,
                        version: self.pending_ver,
                        payload_len: 0,
                    });
                } else {
                    self.payload_rem = self.pending_len;
                }
            }
        }
    }

    /// Mark the moment the TLS client begins writing post-handshake HTTP
    /// request data (works identically for TLS 1.3 with/without CCS and TLS 1.2).
    pub fn mark_handshake_complete(&mut self) {
        if self.handshake_end_idx.is_none() && self.seen_server_hello {
            self.handshake_end_idx = Some(self.records.len());
        }
    }

    /// Estimate the server's encrypted handshake / certificate flight total
    /// payload bytes (for calibrating FakeTLS ServerHello `NoiseParams`).
    pub fn measure_cert_flight_bytes(&self) -> Option<usize> {
        let end = self.handshake_end_idx.unwrap_or(self.records.len());
        let slice = &self.records[..end];

        // TLS 1.3 flight: sum ApplicationData records after ServerHello/CCS before HTTP request.
        let mut tls13_sum = 0usize;
        let mut after_sh = false;
        let mut tls12_hs_sum = 0usize;
        let mut hs_records_seen = 0usize;

        for rec in slice {
            match rec.record_type {
                TLS_RECORD_HANDSHAKE => {
                    hs_records_seen += 1;
                    if hs_records_seen > 1 {
                        // TLS 1.2 Certificate + ServerKeyExchange + ServerHelloDone
                        tls12_hs_sum += rec.payload_len;
                    }
                    after_sh = true;
                }
                TLS_RECORD_CHANGE_CIPHER_SPEC => {
                    after_sh = true;
                }
                TLS_RECORD_APPLICATION_DATA if after_sh => {
                    tls13_sum += rec.payload_len;
                }
                _ => {}
            }
        }

        let measured = if tls13_sum > 0 {
            tls13_sum
        } else {
            tls12_hs_sum
        };
        if measured > 0 { Some(measured) } else { None }
    }

    /// Extract inter-record arrival gaps (in milliseconds) for post-handshake
    /// ApplicationData records and detect whether Dynamic Record Sizing (DRS)
    /// was observed on the cover server.
    pub fn extract_gaps_and_drs(&self) -> (Vec<f64>, bool) {
        let start = self.handshake_end_idx.unwrap_or(0);
        let app_records: Vec<&ScoutRecord> = self.records[start..]
            .iter()
            .filter(|r| r.record_type == TLS_RECORD_APPLICATION_DATA)
            .collect();

        let mut gaps_ms = Vec::with_capacity(app_records.len());
        for pair in app_records.windows(2) {
            let dt = pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns);
            if dt > 0 {
                gaps_ms.push((dt as f64) / 1_000_000.0);
            }
        }

        // Detect DRS if early records are near MTU (~1.2–1.6 KiB) and later
        // records ramp up significantly (>= 4 KiB).
        let drs = app_records.len() >= 10
            && app_records[0].payload_len <= 1600
            && app_records.iter().skip(5).any(|r| r.payload_len >= 4000);

        (gaps_ms, drs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weibull_mle_fits_synthetic_samples_and_rejects_degenerate() {
        // Generate 400 synthetic samples from Weibull(k=0.8, lambda=5.0)
        let k_true = 0.8f64;
        let lam_true = 5.0f64;
        let samples: Vec<f64> = (1..=400)
            .map(|i| {
                let u = f64::from(i) / 401.0;
                lam_true * (-u.ln()).powf(1.0 / k_true)
            })
            .collect();

        let fitted =
            DoppelParams::fit_weibull(&samples, true, ShapingMode::Burst, NoiseParams::default());
        assert!(fitted.is_usable());
        assert!((fitted.k - k_true).abs() < 0.08, "got k={}", fitted.k);
        assert!(
            (fitted.lambda_ms - lam_true).abs() < 0.6,
            "got lambda={}",
            fitted.lambda_ms
        );

        // Degenerate identical gaps pin k to upper bound -> NOT usable!
        let flat = vec![2.0f64; 200];
        let deg =
            DoppelParams::fit_weibull(&flat, false, ShapingMode::Record, NoiseParams::default());
        assert!(!deg.is_usable());
    }

    #[test]
    fn doppel_conn_state_size_and_drs_progression() {
        assert!(std::mem::size_of::<DoppelConnState>() <= 24);

        let params = DoppelParams {
            drs: true,
            shaping: ShapingMode::Burst,
            ..DoppelParams::default()
        };
        let mut st = DoppelConnState::new(true, ShapingMode::Burst);

        // First record wakes from idle -> small DRS size.
        let (_, sz1) = st.next_record(&params, 1_000_000_000);
        assert!((DRS_RECORD_START - DRS_NOISE_BYTES..=DRS_RECORD_START).contains(&sz1));

        // Next 39 records within burst -> 0 delay, small DRS size.
        for i in 1..40u64 {
            let (delay, sz) = st.next_record(&params, 1_000_000_000 + i * 1_000_000);
            assert_eq!(delay, Duration::ZERO);
            assert!(sz <= DRS_RECORD_START);
        }

        // Record 41 -> ramps up to DRS_RECORD_ACCEL (~4096).
        let (delay, sz41) = st.next_record(&params, 1_045_000_000);
        assert_eq!(delay, Duration::ZERO);
        assert!((DRS_RECORD_ACCEL - DRS_NOISE_BYTES..=DRS_RECORD_ACCEL).contains(&sz41));

        // Record 61 -> ramps up to DRS_RECORD_MAX (16379).
        for i in 42..=60u64 {
            st.next_record(&params, 1_045_000_000 + i * 1_000_000);
        }
        let (_, sz61) = st.next_record(&params, 1_110_000_000);
        assert_eq!(sz61, DRS_RECORD_MAX);

        // After >1s idle -> resets cleanly back to DRS_RECORD_START.
        let (_, sz_reset) = st.next_record(&params, 3_000_000_000);
        assert!(sz_reset <= DRS_RECORD_START);
    }

    #[test]
    fn scout_measures_tls13_without_ccs_and_tls12() {
        let mut scout = ScoutCollector::new();
        // TLS 1.3 ServerHello (0x16, 122B) followed immediately by 2 AppData cert-flight records (no CCS!)
        let mut wire = Vec::new();
        wire.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 3, 3, 0, 10]);
        wire.extend_from_slice(&[0u8; 10]);
        wire.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 3, 3, 0x0b, 0xb8]); // 3000B
        wire.extend_from_slice(&vec![0u8; 3000]);
        wire.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 3, 3, 0x01, 0xf4]); // 500B
        wire.extend_from_slice(&vec![0u8; 500]);

        scout.observe_server_bytes(&wire, 100);
        scout.mark_handshake_complete();
        assert_eq!(scout.measure_cert_flight_bytes(), Some(3500));
    }
}
