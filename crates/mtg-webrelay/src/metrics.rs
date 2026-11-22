//! Lock-free WEB relay operational counters, exact `RelayStats` JSON schema,
//! and separate loopback `/stats` HTTP handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use parking_lot::Mutex;
use serde::Serialize;

use crate::store::SessionStore;

/// Lock-free hot-path counters for a running WEB relay.
#[derive(Debug)]
pub struct RelayCounters {
    started_at: DateTime<Utc>,
    sessions_created: AtomicI64,
    sessions_attached: AtomicI64,
    streams_opened: AtomicI64,
    streams_active: AtomicI64,
    bytes_up: AtomicI64,
    bytes_down: AtomicI64,
    cover_served: AtomicI64,
    not_found: AtomicI64,
    bad_token: AtomicI64,
    session_limit: AtomicI64,
    reloads: AtomicI64,
    reload_failures: AtomicI64,
    carrier_ws: AtomicI64,
    carrier_ws_lanes: AtomicI64,
    carrier_https: AtomicI64,
    carrier_https_lanes: AtomicI64,
    carrier_h2_stream: AtomicI64,
    conveyor_up_batches: AtomicI64,
    downlink_polls: AtomicI64,
    meta: Mutex<RelayMeta>,
}

#[derive(Debug, Default)]
struct RelayMeta {
    profiles: Vec<String>,
    last_reload: Option<DateTime<Utc>>,
}

impl Default for RelayCounters {
    fn default() -> Self {
        Self::new(Utc::now())
    }
}

impl RelayCounters {
    pub fn new(started_at: DateTime<Utc>) -> Self {
        Self {
            started_at,
            sessions_created: AtomicI64::new(0),
            sessions_attached: AtomicI64::new(0),
            streams_opened: AtomicI64::new(0),
            streams_active: AtomicI64::new(0),
            bytes_up: AtomicI64::new(0),
            bytes_down: AtomicI64::new(0),
            cover_served: AtomicI64::new(0),
            not_found: AtomicI64::new(0),
            bad_token: AtomicI64::new(0),
            session_limit: AtomicI64::new(0),
            reloads: AtomicI64::new(0),
            reload_failures: AtomicI64::new(0),
            carrier_ws: AtomicI64::new(0),
            carrier_ws_lanes: AtomicI64::new(0),
            carrier_https: AtomicI64::new(0),
            carrier_https_lanes: AtomicI64::new(0),
            carrier_h2_stream: AtomicI64::new(0),
            conveyor_up_batches: AtomicI64::new(0),
            downlink_polls: AtomicI64::new(0),
            meta: Mutex::new(RelayMeta::default()),
        }
    }

    #[inline]
    pub fn on_carrier_selected(&self, mode: &str) {
        match mode {
            "ws-lanes" => {
                self.carrier_ws_lanes.fetch_add(1, Ordering::Relaxed);
            }
            "https" => {
                self.carrier_https.fetch_add(1, Ordering::Relaxed);
            }
            "https-lanes" => {
                self.carrier_https_lanes.fetch_add(1, Ordering::Relaxed);
            }
            "h2-stream" => {
                self.carrier_h2_stream.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.carrier_ws.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn on_conveyor_up(&self) {
        self.conveyor_up_batches.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_downlink_poll(&self) {
        self.downlink_polls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_profiles(&self, names: Vec<String>) {
        self.meta.lock().profiles = names;
    }

    pub fn on_reload(&self, ok: bool) {
        if ok {
            self.reloads.fetch_add(1, Ordering::Relaxed);
            self.meta.lock().last_reload = Some(Utc::now());
        } else {
            self.reload_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn on_session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_session_attached(&self) {
        self.sessions_attached.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        self.streams_active.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_stream_closed(&self) {
        self.streams_active.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_bytes_up(&self, n: usize) {
        if n > 0 {
            self.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_bytes_down(&self, n: usize) {
        if n > 0 {
            self.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn on_cover_served(&self) {
        self.cover_served.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_not_found(&self) {
        self.not_found.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_bad_token(&self) {
        self.bad_token.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_session_limit(&self) {
        self.session_limit.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot live stats into the exact JSON contract expected by operators.
    pub fn snapshot(&self, max_sessions: usize, active_sessions: usize) -> RelayStats {
        let now = Utc::now();
        let meta = self.meta.lock();
        let profiles = meta.profiles.clone();
        let last_reload = meta.last_reload;
        drop(meta);

        RelayStats {
            started_at: self.started_at,
            uptime_seconds: (now - self.started_at).num_seconds().max(0),
            profiles,
            reloads: self.reloads.load(Ordering::Relaxed),
            reload_failures: self.reload_failures.load(Ordering::Relaxed),
            last_reload,
            sessions: RelaySessionStats {
                active: active_sessions as i64,
                created: self.sessions_created.load(Ordering::Relaxed),
                attached: self.sessions_attached.load(Ordering::Relaxed),
                max: max_sessions as i64,
            },
            streams: RelayStreamStats {
                active: self.streams_active.load(Ordering::Relaxed),
                opened: self.streams_opened.load(Ordering::Relaxed),
            },
            bytes: RelayByteStats {
                up: self.bytes_up.load(Ordering::Relaxed),
                down: self.bytes_down.load(Ordering::Relaxed),
            },
            refused: RelayRefusedStats {
                cover_served: self.cover_served.load(Ordering::Relaxed),
                not_found: self.not_found.load(Ordering::Relaxed),
                bad_token: self.bad_token.load(Ordering::Relaxed),
                session_limit: self.session_limit.load(Ordering::Relaxed),
            },
            carriers: RelayCarrierStats {
                websocket: self.carrier_ws.load(Ordering::Relaxed),
                ws_lanes: self.carrier_ws_lanes.load(Ordering::Relaxed),
                https: self.carrier_https.load(Ordering::Relaxed),
                https_lanes: self.carrier_https_lanes.load(Ordering::Relaxed),
                h2_stream: self.carrier_h2_stream.load(Ordering::Relaxed),
                conveyor_up_batches: self.conveyor_up_batches.load(Ordering::Relaxed),
                downlink_polls: self.downlink_polls.load(Ordering::Relaxed),
            },
        }
    }
}

/// Exact JSON payload returned by `GET /stats` on `[web] stats-bind-to`.
#[derive(Debug, Clone, Serialize)]
pub struct RelayStats {
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub profiles: Vec<String>,
    pub reloads: i64,
    pub reload_failures: i64,
    pub last_reload: Option<DateTime<Utc>>,
    pub sessions: RelaySessionStats,
    pub streams: RelayStreamStats,
    pub bytes: RelayByteStats,
    pub refused: RelayRefusedStats,
    pub carriers: RelayCarrierStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayCarrierStats {
    pub websocket: i64,
    pub ws_lanes: i64,
    pub https: i64,
    pub https_lanes: i64,
    pub h2_stream: i64,
    pub conveyor_up_batches: i64,
    pub downlink_polls: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelaySessionStats {
    pub active: i64,
    pub created: i64,
    pub attached: i64,
    pub max: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayStreamStats {
    pub active: i64,
    pub opened: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayByteStats {
    pub up: i64,
    pub down: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayRefusedStats {
    pub cover_served: i64,
    pub not_found: i64,
    pub bad_token: i64,
    pub session_limit: i64,
}

/// Handle one HTTP request arriving on the separate loopback `/stats` socket.
pub fn handle_stats_request<B>(
    req: &Request<B>,
    counters: &Arc<RelayCounters>,
    store: &Arc<SessionStore>,
) -> Response<Full<Bytes>> {
    if req.uri().path() != "/stats" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("cache-control", "no-store")
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"404 page not found\n")))
            .expect("valid response");
    }

    if req.method() != Method::GET {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("allow", "GET")
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::new()))
            .expect("valid response");
    }

    let snap = counters.snapshot(store.max_sessions(), store.active_sessions());
    let body = serde_json::to_vec(&snap).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}
