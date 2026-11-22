//! Bounded O(1) FIFO WEB relay bootstrap & session store.
//!
//! Enforces:
//! - Single-use bootstraps (`BOOTSTRAP_TTL = 2m`) with idempotent retry on
//!   identical `SHA-256(HELLO)` body while the session is unattached.
//! - Capacity limit (`max_sessions`) that leaves the bootstrap UNSPENT when
//!   returning `CreateOutcome::AtCapacity` (`503 Retry-After: 1`).
//! - Single-carrier invariant per session (`attach` refuses a second concurrent
//!   WebSocket!) and `RECONNECT_GRACE = 2m` on detach.
//! - Instant `DELETE /api/v1/session` teardown via `watch::Sender<bool>`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use crate::hub::SessionHub;

/// Lifetime of an unspent bootstrap token embedded in one bridge HTML page.
pub const BOOTSTRAP_TTL: Duration = Duration::from_secs(120);
/// Grace window after a carrier detaches before the session is reaped.
pub const RECONNECT_GRACE: Duration = Duration::from_secs(120);
/// Default maximum concurrent sessions.
pub const DEFAULT_MAX_SESSIONS: usize = 2048;

/// Outcome of `POST /api/v1/session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome {
    /// Session admitted (or idempotent retry matched); carries the session token.
    Admitted(String),
    /// Process is at `max_sessions`; bootstrap remains UNSPENT for retry.
    AtCapacity,
    /// Bootstrap unknown, expired, spent with different body, or already attached.
    Refused,
}

#[derive(Debug)]
struct BootstrapEntry {
    profile: usize,
    expires_at: Instant,
    spent: Option<SpentBootstrap>,
}

#[derive(Debug)]
struct SpentBootstrap {
    body_hash: [u8; 32],
    session_token: String,
}

#[derive(Debug)]
struct SessionEntry {
    profile: usize,
    attached: bool,
    detached_at: Option<Instant>,
    cancel_tx: Option<watch::Sender<bool>>,
    hub: Option<Arc<SessionHub>>,
}

#[derive(Debug)]
struct StoreInner {
    max_sessions: usize,
    max_bootstraps: usize,
    bootstraps: FxHashMap<String, BootstrapEntry>,
    bootstrap_order: VecDeque<String>,
    sessions: FxHashMap<String, SessionEntry>,
}

/// Thread-safe bounded bootstrap + session registry.
#[derive(Debug)]
pub struct SessionStore {
    inner: Mutex<StoreInner>,
}

impl SessionStore {
    pub fn new(max_sessions: usize) -> Self {
        let max_s = if max_sessions == 0 {
            DEFAULT_MAX_SESSIONS
        } else {
            max_sessions
        };
        let max_b = max_s.saturating_mul(4).max(1024);
        Self {
            inner: Mutex::new(StoreInner {
                max_sessions: max_s,
                max_bootstraps: max_b,
                bootstraps: FxHashMap::default(),
                bootstrap_order: VecDeque::new(),
                sessions: FxHashMap::default(),
            }),
        }
    }

    /// Maximum configured sessions.
    pub fn max_sessions(&self) -> usize {
        self.inner.lock().max_sessions
    }

    /// Current live session count (after reaping expired detached sessions).
    pub fn active_sessions(&self) -> usize {
        self.active_sessions_at(Instant::now())
    }

    pub fn active_sessions_at(&self, now: Instant) -> usize {
        let mut guard = self.inner.lock();
        reap(&mut guard, now);
        guard.sessions.len()
    }

    /// Record a freshly minted bootstrap token issued to `profile`.
    pub fn issue_bootstrap(&self, token: String, profile: usize) {
        self.issue_bootstrap_at(token, profile, Instant::now());
    }

    pub fn issue_bootstrap_at(&self, token: String, profile: usize, now: Instant) {
        let mut guard = self.inner.lock();
        reap(&mut guard, now);
        while guard.bootstraps.len() >= guard.max_bootstraps {
            let Some(oldest) = guard.bootstrap_order.pop_front() else {
                break;
            };
            guard.bootstraps.remove(&oldest);
        }
        guard.bootstrap_order.push_back(token.clone());
        guard.bootstraps.insert(
            token,
            BootstrapEntry {
                profile,
                expires_at: now + BOOTSTRAP_TTL,
                spent: None,
            },
        );
    }

    /// Spend `bootstrap_token` to admit a new session (or return the same
    /// session token on an idempotent retry with identical `hello_body`).
    pub fn create_session<F, E>(
        &self,
        bootstrap_token: &str,
        hello_body: &[u8],
        mint: F,
    ) -> CreateOutcome
    where
        F: FnOnce() -> Result<String, E>,
    {
        self.create_session_at(bootstrap_token, hello_body, Instant::now(), mint)
    }

    pub fn create_session_at<F, E>(
        &self,
        bootstrap_token: &str,
        hello_body: &[u8],
        now: Instant,
        mint: F,
    ) -> CreateOutcome
    where
        F: FnOnce() -> Result<String, E>,
    {
        let mut guard = self.inner.lock();
        reap(&mut guard, now);

        let body_hash: [u8; 32] = Sha256::digest(hello_body).into();

        let Some(boot) = guard.bootstraps.get(bootstrap_token) else {
            return CreateOutcome::Refused;
        };
        if now >= boot.expires_at {
            guard.bootstraps.remove(bootstrap_token);
            return CreateOutcome::Refused;
        }

        // Idempotent retry check when already spent.
        if let Some(spent) = &boot.spent {
            if spent.body_hash == body_hash
                && guard
                    .sessions
                    .get(&spent.session_token)
                    .is_some_and(|s| !s.attached)
            {
                return CreateOutcome::Admitted(spent.session_token.clone());
            }
            return CreateOutcome::Refused;
        }

        // Capacity check BEFORE spending the bootstrap so client can retry safely!
        if guard.sessions.len() >= guard.max_sessions {
            return CreateOutcome::AtCapacity;
        }

        let profile = boot.profile;
        let Ok(session_token) = mint() else {
            return CreateOutcome::Refused;
        };

        if let Some(b) = guard.bootstraps.get_mut(bootstrap_token) {
            b.spent = Some(SpentBootstrap {
                body_hash,
                session_token: session_token.clone(),
            });
        }

        guard.sessions.insert(
            session_token.clone(),
            SessionEntry {
                profile,
                attached: false,
                detached_at: Some(now),
                cancel_tx: None,
                hub: None,
            },
        );

        CreateOutcome::Admitted(session_token)
    }

    /// Attach a single WebSocket carrier to `session_token`, returning the
    /// owning profile index and a cancellation watch receiver triggered by
    /// `DELETE /api/v1/session`.
    pub fn attach(&self, session_token: &str) -> Option<(usize, watch::Receiver<bool>)> {
        self.attach_at(session_token, Instant::now())
    }

    pub fn attach_at(
        &self,
        session_token: &str,
        now: Instant,
    ) -> Option<(usize, watch::Receiver<bool>)> {
        let mut guard = self.inner.lock();
        reap(&mut guard, now);

        let entry = guard.sessions.get_mut(session_token)?;
        if entry.attached {
            return None;
        }
        let (tx, rx) = watch::channel(false);
        entry.attached = true;
        entry.detached_at = None;
        entry.cancel_tx = Some(tx);
        Some((entry.profile, rx))
    }

    /// Detach the active carrier, starting `RECONNECT_GRACE` unless the session
    /// was already deleted.
    pub fn detach(&self, session_token: &str) {
        self.detach_at(session_token, Instant::now());
    }

    pub fn detach_at(&self, session_token: &str, now: Instant) {
        let mut guard = self.inner.lock();
        if let Some(entry) = guard.sessions.get_mut(session_token) {
            entry.attached = false;
            entry.detached_at = Some(now);
            entry.cancel_tx = None;
        }
    }

    /// Return the active [`SessionHub`] for `session_token`, lazily spawning one
    /// via `spawn_fn` on first `https` / `https-lanes` / `ws-lanes` / `h2-stream`
    /// carrier request (returns `None` if session is unknown or already bound to
    /// an exclusive single-carrier WebSocket).
    pub fn get_or_spawn_hub<F>(
        &self,
        session_token: &str,
        spawn_fn: F,
    ) -> Option<(usize, Arc<SessionHub>, bool)>
    where
        F: FnOnce(watch::Receiver<bool>) -> Arc<SessionHub>,
    {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        reap(&mut guard, now);

        let entry = guard.sessions.get_mut(session_token)?;
        if let Some(existing) = &entry.hub {
            if existing.is_closed() {
                return None;
            }
            return Some((entry.profile, Arc::clone(existing), false));
        }
        // Refuse if an exclusive classic single-carrier WebSocket already owns this session.
        if entry.attached {
            return None;
        }
        let (tx, rx) = watch::channel(false);
        let hub = spawn_fn(rx);
        entry.attached = true;
        entry.detached_at = None;
        entry.cancel_tx = Some(tx);
        entry.hub = Some(Arc::clone(&hub));
        Some((entry.profile, hub, true))
    }

    /// Permanently delete `session_token` and immediately cancel any live carrier.
    pub fn remove(&self, session_token: &str) -> bool {
        self.remove_at(session_token, Instant::now())
    }

    pub fn remove_at(&self, session_token: &str, now: Instant) -> bool {
        let mut guard = self.inner.lock();
        reap(&mut guard, now);
        if let Some(entry) = guard.sessions.remove(session_token) {
            if let Some(tx) = entry.cancel_tx {
                let _ = tx.send(true);
            }
            if let Some(hub) = entry.hub {
                hub.shutdown();
            }
            true
        } else {
            false
        }
    }
}

fn reap(inner: &mut StoreInner, now: Instant) {
    while let Some(front) = inner.bootstrap_order.front() {
        let expired = inner
            .bootstraps
            .get(front)
            .is_none_or(|b| now >= b.expires_at);
        if expired {
            if let Some(tok) = inner.bootstrap_order.pop_front() {
                inner.bootstraps.remove(&tok);
            }
        } else {
            break;
        }
    }

    inner.sessions.retain(|_, s| {
        if let Some(hub) = &s.hub {
            return !hub.is_closed();
        }
        s.attached
            || s.detached_at
                .is_none_or(|dt| now.saturating_duration_since(dt) < RECONNECT_GRACE)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_idempotency_capacity_single_carrier_and_delete_cancel() {
        let store = SessionStore::new(1);
        let t0 = Instant::now();

        store.issue_bootstrap_at("b1".into(), 0, t0);
        store.issue_bootstrap_at("b2".into(), 0, t0);

        let hello = b"\x10\x00\x00\x00\x00\x00\x00\x01\x01";
        let s1 = match store.create_session_at("b1", hello, t0, || Ok::<_, ()>("s1".into())) {
            CreateOutcome::Admitted(tok) => tok,
            other => panic!("expected Admitted, got {other:?}"),
        };
        assert_eq!(s1, "s1");

        // Idempotent retry returns same session token
        assert_eq!(
            store.create_session_at("b1", hello, t0, || Ok::<_, ()>("s_other".into())),
            CreateOutcome::Admitted("s1".into())
        );

        // Second bootstrap hits capacity and stays UNSPENT
        assert_eq!(
            store.create_session_at("b2", hello, t0, || Ok::<_, ()>("s2".into())),
            CreateOutcome::AtCapacity
        );

        // Attach once succeeds; second concurrent attach fails
        let (prof, cancel_rx) = store.attach_at("s1", t0).unwrap();
        assert_eq!(prof, 0);
        assert!(store.attach_at("s1", t0).is_none());

        // DELETE removes s1 and fires cancellation immediately!
        assert!(store.remove_at("s1", t0));
        assert!(*cancel_rx.borrow());
        assert!(!store.remove_at("s1", t0));

        // Now b2 succeeds because capacity freed and b2 was never spent!
        assert_eq!(
            store.create_session_at("b2", hello, t0, || Ok::<_, ()>("s2".into())),
            CreateOutcome::Admitted("s2".into())
        );
    }
}
