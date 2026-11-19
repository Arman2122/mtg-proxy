//! Compact 32-byte lock-free one-shot cancellation token (`CancelToken`).
//!
//! Replaces per-connection `tokio::sync::watch::channel(false)` (~320 B heap
//! with `RwLock` + `Notify` linked list) with a single `Arc<CancelState>`
//! carrying an `AtomicBool` fast-path (1 relaxed load) and a single `Waker`
//! slot — saving ~280 B per live connection and eliminating watch contention!

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;

#[derive(Debug, Default)]
struct CancelState {
    cancelled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

/// Compact cloneable cancellation token shared between `ProxyEngine` and one
/// live connection task.
#[derive(Debug, Clone)]
pub struct CancelToken {
    inner: Arc<CancelState>,
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelState {
                cancelled: AtomicBool::new(false),
                waker: Mutex::new(None),
            }),
        }
    }

    /// Trigger cancellation and immediately wake any task polling this token.
    #[inline]
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::Release)
            && let Some(w) = self.inner.waker.lock().take()
        {
            w.wake();
        }
    }

    /// Lock-free O(1) check whether cancellation has been signalled.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Poll for cancellation inside a manual `poll_fn` loop without allocating.
    ///
    /// Fast path when already cancelled is 1 atomic load; otherwise registers
    /// `cx.waker()` only when changed (`will_wake` avoids cloning `Waker`).
    #[inline]
    pub fn poll_cancelled(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.inner.cancelled.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let mut slot = self.inner.waker.lock();
        if self.inner.cancelled.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        match slot.as_mut() {
            Some(existing) if existing.will_wake(cx.waker()) => {}
            _ => *slot = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Async future completing as soon as [`Self::cancel`] is invoked.
    #[inline]
    pub fn cancelled(&self) -> CancelledFuture<'_> {
        CancelledFuture { token: self }
    }
}

/// Future returned by [`CancelToken::cancelled`].
#[derive(Debug)]
pub struct CancelledFuture<'a> {
    token: &'a CancelToken,
}

impl Future for CancelledFuture<'_> {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.token.poll_cancelled(cx)
    }
}
