//! Zero-syscall Linux vDSO `CLOCK_MONOTONIC_COARSE` clock + 4-level
//! hierarchical timing wheel (10 ms base tick, O(1) insert / cancel / fire).
//!
//! Replaces per-connection `timerfd` / `tokio::time::Sleep` allocations in the
//! pinned thread-per-core worker loop: 100,000 idle connections require 0
//! timer syscalls and ~24 bytes per active timer entry.

use slab::Slab;

/// Base tick granularity of [`TimerWheel`]: 10 milliseconds.
pub const TICK_MS: u64 = 10;
/// Base tick granularity in nanoseconds.
pub const TICK_NS: u64 = TICK_MS * 1_000_000;

const SLOTS: usize = 256;
const SLOT_MASK: u64 = (SLOTS as u64) - 1;
const LEVELS: usize = 4;

/// Read Linux `CLOCK_MONOTONIC_COARSE` via vDSO (~3 ns, zero syscalls).
///
/// Monotonically non-decreasing nanoseconds since an unspecified boot epoch.
#[inline]
pub fn coarse_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid mutable `libc::timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &raw mut ts) };
    if rc == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

/// Read Linux `CLOCK_REALTIME_COARSE` Unix timestamp seconds via vDSO (~2 ns, zero syscalls).
#[inline]
pub fn coarse_unix_secs() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid mutable `libc::timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &raw mut ts) };
    if rc == 0 { ts.tv_sec } else { 0 }
}

/// Read Linux `CLOCK_REALTIME_COARSE` Unix timestamp nanoseconds via vDSO (~2 ns, zero syscalls).
#[inline]
pub fn coarse_realtime_ns() -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid mutable `libc::timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &raw mut ts) };
    if rc == 0 {
        i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec)
    } else {
        0
    }
}

/// Read high-resolution Linux `CLOCK_MONOTONIC` via vDSO (for RTT/bench timing).
#[inline]
pub fn mono_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid mutable `libc::timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    if rc == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

/// Opaque cancelable timer handle returned by [`TimerWheel::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle {
    index: u32,
    gen_id: u32,
}

#[derive(Debug)]
struct TimerEntry<T> {
    deadline_tick: u64,
    gen_id: u32,
    level: u8,
    slot: u8,
    prev: Option<u32>,
    next: Option<u32>,
    payload: T,
}

/// Intrusive 4-level hierarchical timing wheel (256 slots/level, 10 ms ticks).
///
/// Covers `256^4 * 10 ms` ≈ 497 days without allocating per-bucket `Vec`s: every
/// bucket stores only an `Option<u32>` intrusive doubly-linked list head into
/// a dense `Slab<TimerEntry<T>>`.
#[derive(Debug)]
pub struct TimerWheel<T> {
    origin_ns: u64,
    current_tick: u64,
    next_gen: u32,
    entries: Slab<TimerEntry<T>>,
    heads: [[Option<u32>; SLOTS]; LEVELS],
}

impl<T> TimerWheel<T> {
    /// Create a new timing wheel anchored at `now_ns`.
    pub fn new(now_ns: u64) -> Self {
        Self {
            origin_ns: now_ns,
            current_tick: 0,
            next_gen: 1,
            entries: Slab::with_capacity(1024),
            heads: [[None; SLOTS]; LEVELS],
        }
    }

    /// Number of active pending timers.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no timers are armed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current logical tick index (each tick = [`TICK_MS`] ms).
    #[inline]
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Convert a coarse timestamp `now_ns` into a wheel tick.
    #[inline]
    pub fn tick_for(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.origin_ns) / TICK_NS
    }

    /// Schedule `payload` to fire after `delay_ms` milliseconds from the current
    /// wheel tick (rounded up to at least 1 tick when `delay_ms > 0`).
    pub fn insert(&mut self, delay_ms: u64, payload: T) -> TimerHandle {
        let delta_ticks = if delay_ms == 0 {
            1
        } else {
            delay_ms.div_ceil(TICK_MS)
        };
        let deadline_tick = self.current_tick.saturating_add(delta_ticks);
        let gen_id = self.alloc_gen();

        let (level, slot) = self.place_coords(deadline_tick);
        let idx = self.entries.insert(TimerEntry {
            deadline_tick,
            gen_id,
            level,
            slot,
            prev: None,
            next: None,
            payload,
        }) as u32;

        self.link(idx, level, slot);
        TimerHandle { index: idx, gen_id }
    }

    /// Cancel an armed timer in O(1). Returns the payload if it was still live.
    pub fn cancel(&mut self, handle: TimerHandle) -> Option<T> {
        let idx = handle.index as usize;
        let entry = self.entries.get(idx)?;
        if entry.gen_id != handle.gen_id {
            return None;
        }
        let level = entry.level;
        let slot = entry.slot;
        self.unlink(handle.index, level, slot);
        Some(self.entries.remove(idx).payload)
    }

    /// Advance the wheel to `now_ns` and invoke `on_fire` for every expired timer.
    ///
    /// Returns the number of expired timers fired.
    pub fn advance<F>(&mut self, now_ns: u64, mut on_fire: F) -> usize
    where
        F: FnMut(T),
    {
        let target = self.tick_for(now_ns);
        self.advance_to_tick(target, &mut on_fire)
    }

    /// Advance directly to `target_tick` (deterministic for unit tests).
    pub fn advance_to_tick<F>(&mut self, target_tick: u64, mut on_fire: F) -> usize
    where
        F: FnMut(T),
    {
        let mut fired = 0usize;
        while self.current_tick < target_tick {
            self.current_tick += 1;

            // Cascade higher wheels whenever a lower wheel wraps at 0.
            let t = self.current_tick;
            if (t & SLOT_MASK) == 0 {
                self.cascade(1, ((t >> 8) & SLOT_MASK) as usize);
                if ((t >> 8) & SLOT_MASK) == 0 {
                    self.cascade(2, ((t >> 16) & SLOT_MASK) as usize);
                    if ((t >> 16) & SLOT_MASK) == 0 {
                        self.cascade(3, ((t >> 24) & SLOT_MASK) as usize);
                    }
                }
            }

            let slot = (self.current_tick & SLOT_MASK) as usize;
            let mut cursor = self.heads[0][slot].take();
            while let Some(idx) = cursor {
                let entry = self.entries.remove(idx as usize);
                cursor = entry.next;
                on_fire(entry.payload);
                fired += 1;
            }
        }
        fired
    }

    /// Compute recommended `io_uring_enter`/`epoll_wait` timeout in milliseconds.
    ///
    /// Returns `max_ms` when idle, or `TICK_MS` when any timer is armed.
    #[inline]
    pub fn poll_timeout_ms(&self, max_ms: u32) -> u32 {
        if self.entries.is_empty() {
            max_ms
        } else {
            (TICK_MS as u32).min(max_ms)
        }
    }

    fn alloc_gen(&mut self) -> u32 {
        let g = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        if self.next_gen == 0 {
            self.next_gen = 1;
        }
        g
    }

    fn place_coords(&self, deadline_tick: u64) -> (u8, u8) {
        let delta = deadline_tick.saturating_sub(self.current_tick);
        if delta < 256 {
            (0, (deadline_tick & SLOT_MASK) as u8)
        } else if delta < (1 << 16) {
            (1, ((deadline_tick >> 8) & SLOT_MASK) as u8)
        } else if delta < (1 << 24) {
            (2, ((deadline_tick >> 16) & SLOT_MASK) as u8)
        } else {
            (3, ((deadline_tick >> 24) & SLOT_MASK) as u8)
        }
    }

    fn cascade(&mut self, level: usize, slot: usize) {
        let mut cursor = self.heads[level][slot].take();
        while let Some(idx) = cursor {
            let next = self.entries[idx as usize].next;
            let deadline = self.entries[idx as usize].deadline_tick;
            let (new_lvl, new_slot) = self.place_coords(deadline);
            let e = &mut self.entries[idx as usize];
            e.level = new_lvl;
            e.slot = new_slot;
            e.prev = None;
            e.next = None;
            self.link(idx, new_lvl, new_slot);
            cursor = next;
        }
    }

    fn link(&mut self, idx: u32, level: u8, slot: u8) {
        let head = &mut self.heads[level as usize][slot as usize];
        let old_head = *head;
        *head = Some(idx);

        self.entries[idx as usize].prev = None;
        self.entries[idx as usize].next = old_head;
        if let Some(oh) = old_head {
            self.entries[oh as usize].prev = Some(idx);
        }
    }

    fn unlink(&mut self, idx: u32, level: u8, slot: u8) {
        let (prev, next) = {
            let e = &self.entries[idx as usize];
            (e.prev, e.next)
        };
        if let Some(p) = prev {
            self.entries[p as usize].next = next;
        } else {
            self.heads[level as usize][slot as usize] = next;
        }
        if let Some(n) = next {
            self.entries[n as usize].prev = prev;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_clock_is_monotonic_and_nonzero() {
        let a = coarse_now_ns();
        let b = coarse_now_ns();
        assert!(a > 0);
        assert!(b >= a);
    }

    #[test]
    fn wheel_fires_across_all_levels_and_supports_o1_cancel() {
        let mut w = TimerWheel::new(0);
        let h_short = w.insert(50, "short"); // tick 5
        let h_cancel = w.insert(100, "cancel"); // tick 10
        let _h_lvl1 = w.insert(5_000, "lvl1"); // tick 500
        let _h_lvl2 = w.insert(700_000, "lvl2"); // tick 70_000

        assert_eq!(w.cancel(h_cancel), Some("cancel"));
        assert_eq!(w.cancel(h_cancel), None); // double cancel safe
        assert_eq!(w.len(), 3);

        let mut fired = Vec::new();
        w.advance_to_tick(4, |v| fired.push(v));
        assert!(fired.is_empty());

        w.advance_to_tick(5, |v| fired.push(v));
        assert_eq!(fired, vec!["short"]);
        assert_eq!(w.cancel(h_short), None);

        w.advance_to_tick(500, |v| fired.push(v));
        assert_eq!(fired, vec!["short", "lvl1"]);

        w.advance_to_tick(70_000, |v| fired.push(v));
        assert_eq!(fired, vec!["short", "lvl1", "lvl2"]);
        assert!(w.is_empty());
    }
}
