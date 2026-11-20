//! Monotonic wall-clock high-water mark (`RotationClock`) for retiring-key expiry.
//!
//! Ensures an NTP step backwards cannot resurrect an already-expired retiring
//! key within a running process, and fires an `on_behind` hook once per episode
//! whenever the underlying wall clock lags more than 1 second behind the mark.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};

const BEHIND_THRESHOLD_NS: i64 = 1_000_000_000;

type NowFn = Box<dyn Fn() -> DateTime<Utc> + Send + Sync>;
type BehindFn = Box<dyn Fn(Duration) + Send + Sync>;

/// High-water wall clock shared between config reloads and the proxy engine.
pub struct RotationClock {
    now_fn: Option<NowFn>,
    mark_ns: AtomicI64,
    behind: AtomicBool,
    on_behind: Option<BehindFn>,
}

impl fmt::Debug for RotationClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotationClock")
            .field("mark_ns", &self.mark_ns.load(Ordering::Relaxed))
            .field("behind", &self.behind.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for RotationClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RotationClock {
    /// Create a high-water clock backed by `Utc::now()` with no callback.
    pub fn new() -> Self {
        Self {
            now_fn: None,
            mark_ns: AtomicI64::new(i64::MIN),
            behind: AtomicBool::new(false),
            on_behind: None,
        }
    }

    /// Create a clock with an optional custom wall-clock source and optional
    /// callback invoked once per backwards-jump episode (> 1s behind mark).
    pub fn with_hooks(
        now_fn: Option<impl Fn() -> DateTime<Utc> + Send + Sync + 'static>,
        on_behind: Option<impl Fn(Duration) + Send + Sync + 'static>,
    ) -> Self {
        Self {
            now_fn: now_fn.map(|f| Box::new(f) as NowFn),
            mark_ns: AtomicI64::new(i64::MIN),
            behind: AtomicBool::new(false),
            on_behind: on_behind.map(|f| Box::new(f) as BehindFn),
        }
    }

    /// Return the current monotonic wall time (never earlier than any previous
    /// call on this instance).
    pub fn now(&self) -> DateTime<Utc> {
        let source_now = match &self.now_fn {
            Some(f) => f(),
            None => Utc::now(),
        };
        let ns = source_now.timestamp_nanos_opt().unwrap_or(i64::MAX);

        loop {
            let mark = self.mark_ns.load(Ordering::Acquire);
            if ns < mark {
                let gap_ns = mark.saturating_sub(ns);
                if gap_ns > BEHIND_THRESHOLD_NS
                    && self
                        .behind
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    && let Some(cb) = &self.on_behind
                {
                    cb(Duration::from_nanos(gap_ns as u64));
                }
                return DateTime::from_timestamp_nanos(mark);
            }

            if ns == mark
                || self
                    .mark_ns
                    .compare_exchange(mark, ns, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                if self.behind.load(Ordering::Acquire) {
                    self.behind.store(false, Ordering::Release);
                }
                return DateTime::from_timestamp_nanos(ns);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn holds_high_water_mark_and_reports_behind_episode_once() {
        let base_ns = 1_700_000_000_000_000_000i64;
        let current = Arc::new(AtomicI64::new(base_ns));
        let calls = Arc::new(AtomicUsize::new(0));

        let c_read = Arc::clone(&current);
        let calls_w = Arc::clone(&calls);

        let clock = RotationClock::with_hooks(
            Some(move || DateTime::from_timestamp_nanos(c_read.load(Ordering::SeqCst))),
            Some(move |_| {
                calls_w.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let t0 = clock.now();
        assert_eq!(t0.timestamp_nanos_opt().unwrap(), base_ns);

        // Step backwards by 500ms (<= 1s): held at base_ns, NOT reported.
        current.store(base_ns - 500_000_000, Ordering::SeqCst);
        assert_eq!(clock.now().timestamp_nanos_opt().unwrap(), base_ns);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Step backwards by 5s (> 1s): held at base_ns, reported ONCE across repeated reads.
        current.store(base_ns - 5_000_000_000, Ordering::SeqCst);
        assert_eq!(clock.now().timestamp_nanos_opt().unwrap(), base_ns);
        assert_eq!(clock.now().timestamp_nanos_opt().unwrap(), base_ns);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Catch up to mark: clears behind episode.
        current.store(base_ns + 1_000_000_000, Ordering::SeqCst);
        assert_eq!(
            clock.now().timestamp_nanos_opt().unwrap(),
            base_ns + 1_000_000_000
        );

        // Second episode reports again.
        current.store(base_ns - 1_000_000_000, Ordering::SeqCst);
        assert_eq!(
            clock.now().timestamp_nanos_opt().unwrap(),
            base_ns + 1_000_000_000
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
