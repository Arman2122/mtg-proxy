//! All 19 Management HTTP API route handlers, constant-time Bearer token auth
//! middleware, and strict JSON request decoder.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures_core::Stream;
use mtg_config::parse_duration;
use mtg_core::{
    GlobalLimits, IpUnit, Secret, SecretLimits, parse_expiry, parse_quota_bytes, parse_quota_reset,
    parse_speed,
};
use mtg_engine::{
    BatchUpsertSecret, EngineError, EngineEvent, GlobalLimitsPatch, ProxyEngine,
    RuntimeStateSnapshot, SUPPORTED_FEATURES, SecretPatch, is_secret_served,
};
use mtg_governance::{
    BanError, DEFAULT_EXTERNAL_ADDRESS_TTL, FairBucket, MAX_EXTERNAL_ADDRESS_TTL,
    MAX_EXTERNAL_ADDRESSES, SecretRecord, parse_ban_request, parse_ban_unit,
};
use mtg_net::SUPPORTED_OUTBOUND_PROTOCOLS;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq as _;
use tokio::sync::broadcast;
use tracing::warn;

use crate::dto::{
    AccountLedgerRowJson, AccountingCheckpointReq, AccountingResponse, AccountingTotalsJson,
    AdTagResponse, AddressReportJson, BanReq, BanResultJson, BansReportJson, BatchSecretsReq,
    BatchSecretsResultJson, CapabilitiesResponse, ClientRowJson, ClientUsageJson,
    ClientsReportJson, DisconnectResultJson, ErrorBody, ExternalIpsReq, FakeTlsJson,
    FlushResultJson, HealthzResponse, KickReq, KickResultJson, ObfuscatedJson,
    OutboundProbeResultJson, OutboundsReportJson, PatchGlobalLimitsReq, PatchSecretReq,
    PostSecretReq, PutAdTagReq, PutGlobalLimitsReq, PutOutboundsReq, PutSecretsReq, STATUS_OK,
    SecretInfoJson, SecretsListResponse, StatsResponse, ThrottleJson, UnbanResultJson,
    UserStatsJson, quota_reset_str,
};

const DEFAULT_CLIENTS_LIMIT: usize = 100;
const MAX_CLIENTS_LIMIT: usize = 1000;

/// Shared state passed to every Management API handler.
#[derive(Debug, Clone)]
pub struct ApiState {
    pub engine: Arc<ProxyEngine>,
    pub bearer_expected: Option<Arc<[u8]>>,
}

impl ApiState {
    pub fn new(engine: Arc<ProxyEngine>, token: &str) -> Self {
        let bearer_expected = if token.is_empty() {
            None
        } else {
            Some(format!("Bearer {token}").into_bytes().into())
        };
        Self {
            engine,
            bearer_expected,
        }
    }
}

/// Constant-time `Authorization: Bearer <token>` middleware (pass-through when token empty).
pub async fn bearer_auth_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(expected) = &state.bearer_expected else {
        return next.run(req).await;
    };

    let got = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map_or(&[][..], str::as_bytes);

    if got.ct_eq(expected.as_ref()).unwrap_u8() != 1 {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
            "unauthorized\n",
        )
            .into_response();
    }

    next.run(req).await
}

/// Optimistic-concurrency middleware enforcing optional HTTP `If-Match` on
/// mutating requests (`412 Precondition Failed` on stale revisions) and
/// stamping strong `ETag: "rev-N"` + `X-State-Revision: N` on every response.
pub async fn revision_concurrency_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let is_mutation = matches!(
        *req.method(),
        Method::PUT | Method::POST | Method::PATCH | Method::DELETE
    );
    let path = req.uri().path().to_owned();
    if is_mutation {
        let if_match = req
            .headers()
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok());
        if let Err(current_etag) = state.engine.check_if_match(if_match) {
            let mut resp = (
                StatusCode::PRECONDITION_FAILED,
                Json(serde_json::json!({
                    "error": "precondition failed: state revision mismatch",
                    "current_etag": current_etag,
                    "state_revision": state.engine.state_revision(),
                })),
            )
                .into_response();
            attach_revision_headers(&state.engine, resp.headers_mut());
            return resp;
        }
    }

    let mut resp = next.run(req).await;
    if path != "/events" {
        attach_revision_headers(&state.engine, resp.headers_mut());
    }
    resp
}

fn attach_revision_headers(engine: &ProxyEngine, headers: &mut axum::http::HeaderMap) {
    let rev = engine.state_revision();
    if let Ok(etag_val) = HeaderValue::from_str(&format!("\"rev-{rev}\"")) {
        headers.insert(header::ETAG, etag_val);
    }
    if let Ok(rev_val) = HeaderValue::from_str(&rev.to_string()) {
        headers.insert(HeaderName::from_static("x-state-revision"), rev_val);
    }
}

fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: msg.into() })).into_response()
}

fn map_engine_error(err: &EngineError) -> Response {
    let status = match err {
        EngineError::SecretNotFound(_) => StatusCode::NOT_FOUND,
        EngineError::LastSecret | EngineError::Ban(BanError::ListFull { .. }) => {
            StatusCode::CONFLICT
        }
        EngineError::Invalid(_) | EngineError::Ban(BanError::InvalidAddress(_)) => {
            StatusCode::BAD_REQUEST
        }
        EngineError::Reload(_) | EngineError::Persistence(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, err.to_string())
}

#[allow(clippy::result_large_err)]
fn decode_strict_json<T: DeserializeOwned>(body: &Bytes) -> Result<T, Response> {
    serde_json::from_slice::<T>(body).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("invalid request body: {e}"),
        )
    })
}

fn parse_ad_tag_hex(raw: &str) -> Result<Option<[u8; 16]>, String> {
    if raw.is_empty() {
        return Ok(None);
    }
    let decoded = hex::decode(raw).map_err(|e| format!("ad_tag must be a hex string: {e}"))?;
    if decoded.len() != 16 {
        return Err(format!(
            "ad_tag must be 16 bytes (32 hex chars), got {}",
            decoded.len()
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&decoded);
    Ok(Some(out))
}

// ============================================================================
// Route 1: GET /stats
// ============================================================================

pub async fn handle_stats(State(state): State<ApiState>) -> Response {
    let eng = &state.engine;
    let now = Utc::now();
    let track = eng.track_client_ips();

    let set = eng.secrets.load();
    let has_retiring = set.records.values().any(|r| !r.retiring.is_empty());
    let rot_now = has_retiring.then(|| eng.rotation_clock.now());

    let addr_reports = eng.addresses.report_all(track, now);
    let client_counts = eng.clients.counts();

    let mut total_conns = 0i64;
    let mut users = BTreeMap::new();

    for (name, rt) in eng.metrics.all_users() {
        let conns = rt.connections.load(Ordering::Relaxed);
        total_conns += conns;

        let last_seen_unix = rt.last_seen_unix.load(Ordering::Relaxed);
        let last_seen = (last_seen_unix > 0)
            .then(|| DateTime::from_timestamp(last_seen_unix, 0))
            .flatten();

        let last_ip = if track {
            rt.last_ip.read().clone()
        } else {
            String::new()
        };

        let quota_used = rt.quota_used.load(Ordering::Relaxed);

        let mut u = UserStatsJson {
            connections: conns,
            bytes_in: rt.bytes_in.load(Ordering::Relaxed),
            bytes_out: rt.bytes_out.load(Ordering::Relaxed),
            last_seen,
            quota_used,
            quota: 0,
            quota_remaining: None,
            quota_reset: String::new(),
            expires_at: None,
            disabled: false,
            quota_cutoffs: rt.quota_cutoffs.load(Ordering::Relaxed),
            ad_tag_skipped: rt.ad_tag_skipped.load(Ordering::Relaxed),
            ad_tag_failed: rt.ad_tag_failed.load(Ordering::Relaxed),
            speed_limit: 0,
            throttled_ms: rt.total_throttled_ms(),
            speed_limit_up: 0,
            speed_limit_down: 0,
            ip_limit: 0,
            active_ips: 0,
            ip_limit_refused: rt.ip_limit_refused.load(Ordering::Relaxed),
            client_conns: 0,
            max_connections: 0,
            client_conns_refused: rt.client_conns_refused.load(Ordering::Relaxed),
            client_speed_limit: 0,
            client_speed_limit_up: 0,
            client_speed_limit_down: 0,
            client_fair: false,
            conn_speed_limit: 0,
            conn_speed_limit_up: 0,
            conn_speed_limit_down: 0,
            clients: 0,
            clients_overflow: 0,
            connected_ips: Vec::new(),
            last_ip,
            external_ips: Vec::new(),
            external_expires_at: None,
            connected_ips_last_seen: BTreeMap::new(),
            retiring_keys: 0,
            retiring_until: None,
            retiring_connections: 0,
            retiring_last_seen: None,
        };

        if let Some(rep) = addr_reports.get(&name) {
            u.active_ips = rep.active_ips;
            u.connected_ips.clone_from(&rep.connected_ips);
            u.external_ips.clone_from(&rep.external_ips);
            u.external_expires_at = rep.external_expires_at;
            if !rep.connected_ips_last_seen.is_empty() {
                u.connected_ips_last_seen = rep.connected_ips_last_seen.iter().cloned().collect();
            }
        }

        if let Some(cc) = client_counts.get(&name) {
            u.clients = cc.clients;
            u.clients_overflow = cc.overflow;
        }

        if let Some(rec) = set.records.get(&name) {
            apply_limits_to_user_stats(&mut u, &rec.limits);
            if let Some(rnow) = rot_now {
                let (rk, ru, rc, rls) = retiring_view_for(rec, &rt, rnow);
                u.retiring_keys = rk;
                u.retiring_until = ru;
                u.retiring_connections = rc;
                u.retiring_last_seen = rls;
            }
        }

        users.insert(name, u);
    }

    let throttle = eng
        .metrics
        .throttle_snapshot()
        .map(|(active, limit, caps)| ThrottleJson {
            active,
            limit,
            caps,
        });

    let obfuscated = if eng.listener_modes.is_empty() {
        None
    } else {
        Some(ObfuscatedJson {
            trials: eng.metrics.obfs.trials.load(Ordering::Relaxed),
            misses: eng.metrics.obfs.misses.load(Ordering::Relaxed),
            denied: eng.metrics.obfs.denied.load(Ordering::Relaxed),
            draining: eng.metrics.obfs.draining.load(Ordering::Relaxed),
            rate_limited: eng.metrics.obfs.rate_limited.load(Ordering::Relaxed),
        })
    };

    let faketls_handshake = if eng.metrics.faketls.any_counted() {
        Some(FakeTlsJson {
            hinted: eng.metrics.faketls.hinted.load(Ordering::Relaxed),
            scanned: eng.metrics.faketls.scanned.load(Ordering::Relaxed),
            unmatched: eng.metrics.faketls.unmatched.load(Ordering::Relaxed),
            denied_ip: eng.metrics.faketls.denied_ip.load(Ordering::Relaxed),
            denied_global: eng.metrics.faketls.denied_global.load(Ordering::Relaxed),
            oversized: eng.metrics.faketls.oversized.load(Ordering::Relaxed),
            over_budget_matched: eng
                .metrics
                .faketls
                .over_budget_matched
                .load(Ordering::Relaxed),
            enforced: eng.scan_budget.is_enforced(),
            ns_per_block: eng.scan_budget.block_nanos(),
        })
    } else {
        None
    };

    let resp = StatsResponse {
        started_at: eng.metrics.started_at,
        uptime_seconds: eng.metrics.started_instant.elapsed().as_secs() as i64,
        total_connections: total_conns,
        features: SUPPORTED_FEATURES.to_vec(),
        throttle,
        listeners: eng.listener_reports.clone(),
        obfuscated,
        faketls_handshake,
        users,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

fn apply_limits_to_user_stats(u: &mut UserStatsJson, lim: &SecretLimits) {
    if lim.quota_bytes > 0 {
        u.quota = lim.quota_bytes;
        u.quota_remaining = Some((lim.quota_bytes - u.quota_used).max(0));
    }
    u.quota_reset = quota_reset_str(lim.quota_reset);
    u.expires_at = lim.expires_at;
    u.disabled = lim.disabled;
    u.speed_limit = lim.speed_bytes_per_second;
    u.speed_limit_up = lim.speed_up_bytes_per_second;
    u.speed_limit_down = lim.speed_down_bytes_per_second;
    u.ip_limit = lim.ip_limit;
    u.client_conns = lim.client_conns;
    u.max_connections = lim.max_connections;
    u.client_speed_limit = lim.client_speed_bytes_per_second;
    u.client_speed_limit_up = lim.client_speed_up_bytes_per_second;
    u.client_speed_limit_down = lim.client_speed_down_bytes_per_second;
    u.client_fair = lim.client_fair;
    u.conn_speed_limit = lim.conn_speed_bytes_per_second;
    u.conn_speed_limit_up = lim.conn_speed_up_bytes_per_second;
    u.conn_speed_limit_down = lim.conn_speed_down_bytes_per_second;
}

fn retiring_view_for(
    rec: &SecretRecord,
    rt: &mtg_engine::SecretRuntime,
    rot_now: DateTime<Utc>,
) -> (usize, Option<DateTime<Utc>>, i64, Option<DateTime<Utc>>) {
    let mut keys = 0usize;
    let mut max_until: Option<DateTime<Utc>> = None;
    for r in &rec.retiring {
        if rot_now < r.until {
            keys += 1;
            if max_until.is_none_or(|cur| r.until > cur) {
                max_until = Some(r.until);
            }
        }
    }
    if keys == 0 {
        return (0, None, 0, None);
    }
    let conns = rt.retiring_connections.load(Ordering::Relaxed);
    let rls_ns = rt.retiring_last_seen_ns.load(Ordering::Relaxed);
    let last_seen = (rls_ns > 0).then(|| DateTime::from_timestamp_nanos(rls_ns));
    (keys, max_until, conns, last_seen)
}

// ============================================================================
// Route 2: POST /reload (405 for non-POST, 503 if no config path)
// ============================================================================

pub async fn handle_reload(method: Method, State(state): State<ApiState>) -> Response {
    if method != Method::POST {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, HeaderValue::from_static("POST"))],
            "only POST is allowed\n",
        )
            .into_response();
    }

    if state.engine.settings.config_path.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, "reload is not supported\n").into_response();
    }

    match state.engine.reload_from_disk_async().await {
        Ok(_warnings) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => {
            warn!(error = %e, "config reload failed");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}\n")).into_response()
        }
    }
}

// ============================================================================
// Routes 3, 6: GET /secrets, GET /secrets/{name} (O(1)!)
// ============================================================================

fn build_secret_info(
    eng: &ProxyEngine,
    name: &str,
    rec: &SecretRecord,
    default_ad_tag: Option<[u8; 16]>,
    addr_report: &mtg_governance::AddressReport,
    rot_now: Option<DateTime<Utc>>,
) -> SecretInfoJson {
    let rt = eng.metrics.get_user(name);
    let track = eng.track_client_ips();

    let quota_used = rt
        .as_ref()
        .map_or(0, |r| r.quota_used.load(Ordering::Relaxed));
    let connections = rt
        .as_ref()
        .map_or(0, |r| r.connections.load(Ordering::Relaxed));
    let last_seen = rt
        .as_ref()
        .map(|r| r.last_seen_unix.load(Ordering::Relaxed))
        .filter(|&ts| ts > 0)
        .and_then(|ts| DateTime::from_timestamp(ts, 0));
    let last_ip = if track {
        rt.as_ref()
            .map_or_else(String::new, |r| r.last_ip.read().clone())
    } else {
        String::new()
    };

    let (quota, quota_used_out, quota_remaining) = if rec.limits.quota_bytes > 0 {
        let rem = (rec.limits.quota_bytes - quota_used).max(0);
        (rec.limits.quota_bytes, quota_used, Some(rem))
    } else {
        (0, 0, None)
    };

    let ad_tag = rec.ad_tag.map(hex::encode).unwrap_or_default();
    let effective_ad_tag = rec
        .ad_tag
        .or(default_ad_tag)
        .map(hex::encode)
        .unwrap_or_default();

    let (retiring_keys, retiring_until, retiring_connections, retiring_last_seen) =
        match (rot_now, rt.as_ref()) {
            (Some(rnow), Some(r)) => retiring_view_for(rec, r, rnow),
            (Some(rnow), None) => {
                let mut k = 0usize;
                let mut max_u: Option<DateTime<Utc>> = None;
                for item in &rec.retiring {
                    if rnow < item.until {
                        k += 1;
                        if max_u.is_none_or(|c| item.until > c) {
                            max_u = Some(item.until);
                        }
                    }
                }
                (k, max_u, 0, None)
            }
            _ => (0, None, 0, None),
        };

    SecretInfoJson {
        name: name.to_owned(),
        secret: rec.secret.encode_base64(),
        host: rec.secret.host().to_owned(),
        ad_tag,
        effective_ad_tag,
        quota,
        quota_used: quota_used_out,
        quota_remaining,
        quota_reset: quota_reset_str(rec.limits.quota_reset),
        expires_at: rec.limits.expires_at,
        disabled: rec.limits.disabled,
        speed_limit: rec.limits.speed_bytes_per_second,
        speed_limit_up: rec.limits.speed_up_bytes_per_second,
        speed_limit_down: rec.limits.speed_down_bytes_per_second,
        ip_limit: rec.limits.ip_limit,
        active_ips: addr_report.active_ips,
        client_conns: rec.limits.client_conns,
        max_connections: rec.limits.max_connections,
        client_speed_limit: rec.limits.client_speed_bytes_per_second,
        client_speed_limit_up: rec.limits.client_speed_up_bytes_per_second,
        client_speed_limit_down: rec.limits.client_speed_down_bytes_per_second,
        client_fair: rec.limits.client_fair,
        conn_speed_limit: rec.limits.conn_speed_bytes_per_second,
        conn_speed_limit_up: rec.limits.conn_speed_up_bytes_per_second,
        conn_speed_limit_down: rec.limits.conn_speed_down_bytes_per_second,
        outbound: rec.limits.outbound.clone(),
        mode: rec.secret.mode().as_str().to_owned(),
        unserved: !is_secret_served(&rec.secret, eng.listener_modes),
        connections,
        last_seen,
        connected_ips: addr_report.connected_ips.clone(),
        last_ip,
        connected_ips_last_seen: addr_report
            .connected_ips_last_seen
            .iter()
            .cloned()
            .collect(),
        external_ips: addr_report.external_ips.clone(),
        external_expires_at: addr_report.external_expires_at,
        retiring_keys,
        retiring_until,
        retiring_connections,
        retiring_last_seen,
    }
}

pub async fn handle_get_secrets(State(state): State<ApiState>) -> Response {
    let eng = &state.engine;
    let now = Utc::now();
    let set = eng.secrets.load();
    let has_retiring = set.records.values().any(|r| !r.retiring.is_empty());
    let rot_now = has_retiring.then(|| eng.rotation_clock.now());
    let addr_reports = eng.addresses.report_all(eng.track_client_ips(), now);
    let empty_report = mtg_governance::AddressReport::default();

    let mut secrets = Vec::with_capacity(set.records.len());
    for (name, rec) in &set.records {
        let rep = addr_reports.get(name).unwrap_or(&empty_report);
        secrets.push(build_secret_info(
            eng,
            name,
            rec,
            set.default_ad_tag,
            rep,
            rot_now,
        ));
    }

    (StatusCode::OK, Json(SecretsListResponse { secrets })).into_response()
}

/// O(1) single-secret lookup (unlike Go's O(N) scan of `SnapshotSecrets()`!).
pub async fn handle_get_secret(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    let eng = &state.engine;
    let set = eng.secrets.load();
    let Some(rec) = set.records.get(&name) else {
        return json_error(StatusCode::NOT_FOUND, format!("secret not found: {name:?}"));
    };
    let rot_now = (!rec.retiring.is_empty()).then(|| eng.rotation_clock.now());
    let rep = eng
        .addresses
        .report_one(&name, eng.track_client_ips(), Utc::now());
    let info = build_secret_info(eng, &name, rec, set.default_ad_tag, &rep, rot_now);
    (StatusCode::OK, Json(info)).into_response()
}

// ============================================================================
// Routes 4, 5, 7: PUT /secrets, POST /secrets, DELETE /secrets/{name}
// ============================================================================

pub async fn handle_put_secrets(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PutSecretsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut secrets = BTreeMap::new();
    let mut limits_map = BTreeMap::new();
    let mut ad_tags = BTreeMap::new();

    for (name, entry) in req.secrets {
        let secret = match Secret::parse(&entry.secret) {
            Ok(s) => s,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid secret {name:?}: {e}"),
                );
            }
        };
        let tag = match parse_ad_tag_hex(&entry.ad_tag) {
            Ok(t) => t,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid ad_tag for {name:?}: {e}"),
                );
            }
        };
        let lim = match entry.parse_limits() {
            Ok(l) => l,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid limits for {name:?}: {e}"),
                );
            }
        };

        secrets.insert(name.clone(), secret);
        if let Some(t) = tag {
            ad_tags.insert(name.clone(), t);
        }
        if !lim.is_zero() {
            limits_map.insert(name, lim);
        }
    }

    let global_tag = match parse_ad_tag_hex(&req.ad_tag) {
        Ok(t) => t,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid ad_tag: {e}")),
    };

    match state
        .engine
        .replace_secrets_keeping_retiring(&secrets, &limits_map, &ad_tags, global_tag)
    {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_post_secret(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PostSecretReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let secret = match Secret::parse(&req.secret) {
        Ok(s) => s,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid secret: {e}")),
    };
    let tag = match parse_ad_tag_hex(&req.ad_tag) {
        Ok(t) => t,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid ad_tag: {e}")),
    };
    let limits = match req.parse_limits() {
        Ok(l) => l,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid limits: {e}")),
    };

    match state.engine.put_secret(req.name, secret, tag, limits) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_delete_secret(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match state.engine.delete_secret(&name) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Route 8: POST /secrets/{name}/reset-quota
// ============================================================================

pub async fn handle_reset_quota(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match state.engine.reset_quota(&name) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Route 9: POST /secrets/{name}/kick
// ============================================================================

pub async fn handle_kick(
    Path(name): Path<String>,
    State(state): State<ApiState>,
    body: Bytes,
) -> Response {
    let req: KickReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if req.ips.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid kick addresses: no addresses",
        );
    }

    let mut units = Vec::with_capacity(req.ips.len());
    for raw in &req.ips {
        if raw.contains('%') {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid kick addresses: {raw:?} carries a zone"),
            );
        }
        let Ok(ip) = raw.parse::<IpAddr>() else {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid kick addresses: {raw:?} is not an IP address"),
            );
        };
        units.push(IpUnit::from_ip(ip));
    }

    match state.engine.kick_units(&name, &units) {
        Ok(closed) => (StatusCode::OK, Json(KickResultJson { closed })).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Route 10: GET /secrets/{name}/clients?limit=N
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ClientsQuery {
    #[serde(default)]
    pub limit: Option<String>,
}

fn parse_clients_limit(raw: Option<&str>) -> Result<usize, String> {
    let Some(text) = raw else {
        return Ok(DEFAULT_CLIENTS_LIMIT);
    };
    if text.is_empty() {
        return Ok(DEFAULT_CLIENTS_LIMIT);
    }
    if text.starts_with('-') {
        return Err(format!("limit must be a whole number above zero: {text:?}"));
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("limit must be a whole number above zero: {text:?}"));
    }
    match text.parse::<usize>() {
        Ok(0) => Err(format!("limit must be a whole number above zero: {text:?}")),
        Ok(n) => Ok(n.min(MAX_CLIENTS_LIMIT)),
        // Overflow of positive integer clamps to MAX_CLIENTS_LIMIT (matches Go Atoi ErrRange)!
        Err(_) => Ok(MAX_CLIENTS_LIMIT),
    }
}

#[inline]
fn tighter_rate(a: i64, b: i64) -> i64 {
    if a == 0 {
        b
    } else if b == 0 {
        a
    } else {
        a.min(b)
    }
}

fn client_usage_of(
    entry: &mtg_governance::ClientEntry,
    connections: u32,
    bytes_in: i64,
    bytes_out: i64,
    banned_until: Option<DateTime<Utc>>,
) -> ClientUsageJson {
    let first_seen = entry.first_seen;
    let last_seen = DateTime::from_timestamp(entry.last_seen_unix.load(Ordering::Relaxed), 0)
        .unwrap_or(DateTime::UNIX_EPOCH);
    ClientUsageJson {
        connections,
        bytes_in,
        bytes_out,
        throttled_ms: (entry.throttled_nanos.load(Ordering::Relaxed) / 1_000_000) as i64,
        first_seen,
        last_seen,
        speed_limit: tighter_rate(
            entry.ceiling.rate_bps(),
            entry.fair_limiter(FairBucket::Speed).rate_bps(),
        ),
        speed_limit_up: entry.fair_limiter(FairBucket::Up).rate_bps(),
        speed_limit_down: entry.fair_limiter(FairBucket::Down).rate_bps(),
        banned_until,
    }
}

pub async fn handle_get_clients(
    Path(name): Path<String>,
    Query(query): Query<ClientsQuery>,
    State(state): State<ApiState>,
) -> Response {
    let limit = match parse_clients_limit(query.limit.as_deref()) {
        Ok(n) => n,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };

    let (view, live_counts) = match state.engine.snapshot_clients_view(&name) {
        Ok(v) => v,
        Err(e) => return map_engine_error(&e),
    };

    if !state.engine.track_client_ips() {
        return (
            StatusCode::OK,
            Json(ClientsReportJson {
                total: view.total,
                overflow: view.overflow,
                tracking: false,
                rest: None,
                clients: None,
            }),
        )
            .into_response();
    }

    let mut rows: Vec<(Arc<mtg_governance::ClientEntry>, String, u32, i64, i64)> = view
        .entries
        .into_iter()
        .zip(live_counts)
        .map(|(entry, conns)| {
            let addr = entry.key.map_or_else(String::new, |u| u.to_string());
            let bi = entry.bytes_in.load(Ordering::Relaxed);
            let bo = entry.bytes_out.load(Ordering::Relaxed);
            (entry, addr, conns, bi, bo)
        })
        .collect();

    rows.sort_by(|a, b| {
        let tot_a = a.3.saturating_add(a.4);
        let tot_b = b.3.saturating_add(b.4);
        tot_b.cmp(&tot_a).then_with(|| a.1.cmp(&b.1))
    });
    rows.truncate(limit);

    let ban_map = state.engine.bans.until_map(&name, Utc::now());
    let clients: Vec<ClientRowJson> = rows
        .into_iter()
        .map(|(entry, address, conns, bi, bo)| {
            let banned_until = entry.key.and_then(|u| ban_map.get(&u).copied());
            ClientRowJson {
                address,
                usage: client_usage_of(&entry, conns, bi, bo, banned_until),
            }
        })
        .collect();

    let rest = view.rest.as_ref().map(|r| {
        let bi = r.bytes_in.load(Ordering::Relaxed);
        let bo = r.bytes_out.load(Ordering::Relaxed);
        client_usage_of(r, view.rest_refs, bi, bo, None)
    });

    (
        StatusCode::OK,
        Json(ClientsReportJson {
            total: view.total,
            overflow: view.overflow,
            tracking: true,
            rest,
            clients: Some(clients),
        }),
    )
        .into_response()
}

// ============================================================================
// Routes 11, 12, 13: POST /GET /DELETE /secrets/{name}/bans
// ============================================================================

pub async fn handle_post_bans(
    Path(name): Path<String>,
    State(state): State<ApiState>,
    body: Bytes,
) -> Response {
    let req: BanReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (units, ttl) = match parse_ban_request(&req.ips, &req.ttl, req.force) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    match state.engine.ban_units(&name, &units, ttl) {
        Ok((banned, closed, addresses)) => (
            StatusCode::OK,
            Json(BanResultJson {
                banned,
                closed,
                addresses,
            }),
        )
            .into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_get_bans(Path(name): Path<String>, State(state): State<ApiState>) -> Response {
    match state.engine.list_bans(&name) {
        Ok((total, tracking, list)) => (
            StatusCode::OK,
            Json(BansReportJson {
                total,
                tracking,
                bans: tracking.then_some(list),
            }),
        )
            .into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_delete_ban(
    Path((name, address)): Path<(String, String)>,
    State(state): State<ApiState>,
) -> Response {
    let clean = address.trim_start_matches('/');
    let unit = match parse_ban_unit(clean) {
        Ok(u) => u,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    match state.engine.unban_unit(&name, unit) {
        Ok(removed) => (
            StatusCode::OK,
            Json(UnbanResultJson {
                removed: u8::from(removed),
            }),
        )
            .into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Routes 14, 15, 16: GET /PUT /DELETE /secrets/{name}/external-ips
// ============================================================================

fn build_address_report_json(eng: &ProxyEngine, name: &str) -> Option<AddressReportJson> {
    let set = eng.secrets.load();
    let rec = set.records.get(name)?;
    let rep = eng
        .addresses
        .report_one(name, eng.track_client_ips(), Utc::now());
    Some(AddressReportJson {
        name: name.to_owned(),
        ip_limit: rec.limits.ip_limit,
        active_ips: rep.active_ips,
        connected_ips: rep.connected_ips,
        external_ips: rep.external_ips,
        external_expires_at: rep.external_expires_at,
        connected_ips_last_seen: rep.connected_ips_last_seen.into_iter().collect(),
    })
}

pub async fn handle_get_external_ips(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match build_address_report_json(&state.engine, &name) {
        Some(rep) => (StatusCode::OK, Json(rep)).into_response(),
        None => json_error(StatusCode::NOT_FOUND, format!("secret not found: {name:?}")),
    }
}

fn parse_external_ips_req(req: &ExternalIpsReq) -> Result<(Vec<IpAddr>, Duration), String> {
    if req.ips.len() > MAX_EXTERNAL_ADDRESSES {
        return Err(format!(
            "invalid external addresses: {} addresses, the most is {MAX_EXTERNAL_ADDRESSES}",
            req.ips.len()
        ));
    }
    let mut addrs = Vec::with_capacity(req.ips.len());
    for raw in &req.ips {
        if raw.contains('%') {
            return Err(format!(
                "invalid external addresses: {raw:?} carries a zone"
            ));
        }
        let ip = raw
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid external addresses: {raw:?} is not an IP address"))?;
        addrs.push(ip);
    }

    let ttl = if req.ttl.is_empty() {
        DEFAULT_EXTERNAL_ADDRESS_TTL
    } else {
        let d = parse_duration(&req.ttl)
            .map_err(|e| format!("invalid external addresses: ttl {:?}: {e}", req.ttl))?;
        if d.is_zero() || d > MAX_EXTERNAL_ADDRESS_TTL {
            return Err(format!(
                "invalid external addresses: ttl {:?} is outside (0, 1h]",
                req.ttl
            ));
        }
        d
    };
    Ok((addrs, ttl))
}

pub async fn handle_put_external_ips(
    Path(name): Path<String>,
    State(state): State<ApiState>,
    body: Bytes,
) -> Response {
    let req: ExternalIpsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (addrs, ttl) = match parse_external_ips_req(&req) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };

    if let Err(e) = state.engine.set_external_addresses(&name, &addrs, ttl) {
        return map_engine_error(&e);
    }

    match build_address_report_json(&state.engine, &name) {
        Some(rep) => (StatusCode::OK, Json(rep)).into_response(),
        None => json_error(StatusCode::NOT_FOUND, format!("secret not found: {name:?}")),
    }
}

pub async fn handle_delete_external_ips(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match state
        .engine
        .set_external_addresses(&name, &[], DEFAULT_EXTERNAL_ADDRESS_TTL)
    {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Routes 17, 18, 19: GET /PUT /DELETE /adtag
// ============================================================================

pub async fn handle_get_adtag(State(state): State<ApiState>) -> Response {
    let ad_tag = state.engine.secrets.load().default_ad_tag.map(hex::encode);
    (StatusCode::OK, Json(AdTagResponse { ad_tag })).into_response()
}

pub async fn handle_put_adtag(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PutAdTagReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let tag = match parse_ad_tag_hex(&req.ad_tag) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "ad_tag is required; use DELETE /adtag to clear it",
            );
        }
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };

    match state.engine.set_global_ad_tag(Some(tag)) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_delete_adtag(State(state): State<ApiState>) -> Response {
    match state.engine.set_global_ad_tag(None) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

// ============================================================================
// Enterprise Routes (v2.3.0+): /healthz, PATCH /secrets/{name},
// POST /secrets/{name}/disconnect, POST /secrets/batch,
// GET /accounting, POST /accounting/flush, GET /ip-filters, POST /ip-filters/refresh
// ============================================================================

pub async fn handle_healthz(State(state): State<ApiState>) -> Response {
    let eng = &state.engine;
    let ipf = eng.ip_filters_status();
    let resp = HealthzResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: eng.metrics.started_instant.elapsed().as_secs() as i64,
        total_connections: eng.metrics.total_active_connections(),
        secrets_count: eng.secrets.load().records.len(),
        allowlist_enabled: ipf.allowlist.enabled,
        allowlist_ready: ipf.allowlist.status.as_ref().is_none_or(|s| s.ready),
        allowlist_entries: ipf.allowlist.status.as_ref().map_or(0, |s| s.entries),
        blocklist_enabled: ipf.blocklist.enabled,
        blocklist_ready: ipf.blocklist.status.as_ref().is_none_or(|s| s.ready),
        blocklist_entries: ipf.blocklist.status.as_ref().map_or(0, |s| s.entries),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn handle_patch_secret(
    Path(name): Path<String>,
    State(state): State<ApiState>,
    body: Bytes,
) -> Response {
    let req: PatchSecretReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut patch = SecretPatch {
        reset_quota: req.reset_quota,
        disabled: req.disabled,
        client_fair: req.client_fair,
        ..SecretPatch::default()
    };

    if let Some(s) = req.secret {
        match Secret::parse(&s) {
            Ok(parsed) => patch.secret = Some(parsed),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid secret: {e}")),
        }
    }
    if let Some(tag_str) = req.ad_tag {
        match parse_ad_tag_hex(&tag_str) {
            Ok(tag) => patch.ad_tag = Some(tag),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid ad_tag: {e}")),
        }
    }
    if let Some(q) = req.quota {
        match parse_quota_bytes(&q) {
            Ok(bytes) => patch.quota_bytes = Some(bytes),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid quota: {e}")),
        }
    }
    if let Some(aq) = req.add_quota {
        match parse_quota_bytes(&aq) {
            Ok(bytes) => patch.add_quota_bytes = Some(bytes),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid add_quota: {e}"));
            }
        }
    }
    if let Some(qr) = req.quota_reset {
        match parse_quota_reset(&qr) {
            Ok(reset) => patch.quota_reset = Some(reset),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid quota_reset: {e}"));
            }
        }
    }
    if let Some(exp) = req.expires {
        match parse_expiry(&exp) {
            Ok(dt) => patch.expires_at = Some(dt),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid expires: {e}")),
        }
    }
    if let Some(sp) = req.speed {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_bytes_per_second = Some(v),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed: {e}")),
        }
    }
    if let Some(sp) = req.speed_up {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_up_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_up: {e}"));
            }
        }
    }
    if let Some(sp) = req.speed_down {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_down_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_down: {e}"));
            }
        }
    }
    if let Some(sp) = req.client_speed {
        match parse_speed(&sp) {
            Ok(v) => patch.client_speed_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid client_speed: {e}"),
                );
            }
        }
    }
    if let Some(sp) = req.client_speed_up {
        match parse_speed(&sp) {
            Ok(v) => patch.client_speed_up_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid client_speed_up: {e}"),
                );
            }
        }
    }
    if let Some(sp) = req.client_speed_down {
        match parse_speed(&sp) {
            Ok(v) => patch.client_speed_down_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid client_speed_down: {e}"),
                );
            }
        }
    }
    if let Some(sp) = req.conn_speed {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid conn_speed: {e}"));
            }
        }
    }
    if let Some(sp) = req.conn_speed_up {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_up_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid conn_speed_up: {e}"),
                );
            }
        }
    }
    if let Some(sp) = req.conn_speed_down {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_down_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid conn_speed_down: {e}"),
                );
            }
        }
    }
    if let Some(v) = req.ip_limit {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(StatusCode::BAD_REQUEST, "ip_limit out of range");
        }
        patch.ip_limit = Some(v as u32);
    }
    if let Some(v) = req.client_conns {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(StatusCode::BAD_REQUEST, "client_conns out of range");
        }
        patch.client_conns = Some(v as u32);
    }
    if let Some(v) = req.max_connections {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(StatusCode::BAD_REQUEST, "max_connections out of range");
        }
        patch.max_connections = Some(v as u32);
    }
    if let Some(ob) = req.outbound {
        let trimmed = ob.trim();
        patch.outbound = Some((!trimmed.is_empty()).then(|| trimmed.to_owned()));
    }

    match state.engine.patch_secret(&name, patch) {
        Ok(()) => (StatusCode::OK, Json(STATUS_OK)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_disconnect_secret(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match state.engine.disconnect_secret_all(&name) {
        Ok(closed) => (StatusCode::OK, Json(DisconnectResultJson { closed })).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_batch_secrets(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: BatchSecretsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut upserts = Vec::with_capacity(req.upsert.len());
    for (name, entry) in req.upsert {
        let secret = match Secret::parse(&entry.secret) {
            Ok(s) => s,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid secret {name:?}: {e}"),
                );
            }
        };
        let ad_tag = match parse_ad_tag_hex(&entry.ad_tag) {
            Ok(t) => t,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid ad_tag for {name:?}: {e}"),
                );
            }
        };
        let limits = match entry.parse_limits() {
            Ok(l) => l,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid limits for {name:?}: {e}"),
                );
            }
        };
        upserts.push(BatchUpsertSecret {
            name,
            secret,
            ad_tag,
            limits,
        });
    }

    match state.engine.batch_mutate_secrets(upserts, &req.delete) {
        Ok((upserted, deleted)) => (
            StatusCode::OK,
            Json(BatchSecretsResultJson {
                status: "ok",
                upserted,
                deleted,
            }),
        )
            .into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_get_accounting(State(state): State<ApiState>) -> Response {
    let eng = &state.engine;
    let now = Utc::now();
    let set = eng.secrets.load();
    let addr_reports = eng.addresses.report_all(false, now);

    let mut total_in = 0i64;
    let mut total_out = 0i64;
    let mut active_conns = 0i64;
    let mut lifetime_conns = 0u64;
    let mut accounts = Vec::with_capacity(set.records.len());

    for (name, rec) in &set.records {
        let rt = eng.metrics.get_user(name);
        let bi = rt
            .as_ref()
            .map_or(0, |r| r.bytes_in.load(Ordering::Relaxed));
        let bo = rt
            .as_ref()
            .map_or(0, |r| r.bytes_out.load(Ordering::Relaxed));
        let conns = rt
            .as_ref()
            .map_or(0, |r| r.connections.load(Ordering::Relaxed));
        let life = rt
            .as_ref()
            .map_or(0, |r| r.total_connections.load(Ordering::Relaxed));
        let quota_used = rt
            .as_ref()
            .map_or(0, |r| r.quota_used.load(Ordering::Relaxed));
        let cutoffs = rt
            .as_ref()
            .map_or(0, |r| r.quota_cutoffs.load(Ordering::Relaxed));
        let pstart_ns = rt
            .as_ref()
            .map_or(0, |r| r.period_start_ns.load(Ordering::Relaxed));
        let period_start = (pstart_ns > 0).then(|| DateTime::from_timestamp_nanos(pstart_ns));
        let last_seen_unix = rt
            .as_ref()
            .map_or(0, |r| r.last_seen_unix.load(Ordering::Relaxed));
        let last_seen = (last_seen_unix > 0)
            .then(|| DateTime::from_timestamp(last_seen_unix, 0))
            .flatten();

        let quota = rec.limits.quota_bytes;
        let quota_remaining = (quota > 0).then(|| (quota - quota_used).max(0));
        let active_ips = addr_reports.get(name).map_or(0, |r| r.active_ips);

        total_in = total_in.saturating_add(bi);
        total_out = total_out.saturating_add(bo);
        active_conns = active_conns.saturating_add(conns);
        lifetime_conns = lifetime_conns.saturating_add(life);

        accounts.push(AccountLedgerRowJson {
            name: name.clone(),
            mode: rec.secret.mode().as_str().to_owned(),
            active_connections: conns,
            total_connections: life,
            bytes_in: bi,
            bytes_out: bo,
            total_bytes: bi.saturating_add(bo),
            quota,
            quota_used,
            quota_remaining,
            quota_reset: quota_reset_str(rec.limits.quota_reset),
            period_start,
            quota_cutoffs: cutoffs,
            active_ips,
            ip_limit: rec.limits.ip_limit,
            max_connections: rec.limits.max_connections,
            speed_limit: rec.limits.speed_bytes_per_second,
            disabled: rec.limits.disabled,
            expires_at: rec.limits.expires_at,
            last_seen,
        });
    }

    let mut fronted_total = 0u64;
    let mut allowlist_rejected_total = 0u64;
    let mut blocklisted_total = 0u64;
    let mut replay_attacks = 0u64;
    for c in &eng.metrics.cores {
        fronted_total += c.fronted_total.load(Ordering::Relaxed);
        allowlist_rejected_total += c.allowlist_rejected_total.load(Ordering::Relaxed);
        blocklisted_total += c.blocklisted_total.load(Ordering::Relaxed);
        replay_attacks += c.replay_attacks.load(Ordering::Relaxed);
    }

    let resp = AccountingResponse {
        started_at: eng.metrics.started_at,
        uptime_seconds: eng.metrics.started_instant.elapsed().as_secs() as i64,
        usage_persisted: eng.settings.usage_state_file.is_some(),
        totals: AccountingTotalsJson {
            total_bytes_in: total_in,
            total_bytes_out: total_out,
            total_bytes: total_in.saturating_add(total_out),
            active_connections: active_conns,
            lifetime_connections: lifetime_conns,
            secrets_count: set.records.len(),
            fronted_total,
            allowlist_rejected_total,
            blocklisted_total,
            replay_attacks,
        },
        accounts,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn handle_flush_accounting(State(state): State<ApiState>) -> Response {
    match state.engine.flush_usage_now() {
        Ok(flushed) => (
            StatusCode::OK,
            Json(FlushResultJson {
                status: "ok",
                flushed,
            }),
        )
            .into_response(),
        Err(e) => map_engine_error(&e),
    }
}

pub async fn handle_get_ip_filters(State(state): State<ApiState>) -> Response {
    (StatusCode::OK, Json(state.engine.ip_filters_status())).into_response()
}

pub async fn handle_refresh_ip_filters(State(state): State<ApiState>) -> Response {
    let report = state.engine.refresh_ip_filters_now().await;
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn handle_get_limits(State(state): State<ApiState>) -> Response {
    (StatusCode::OK, Json(state.engine.global_limits_report())).into_response()
}

pub async fn handle_patch_limits(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PatchGlobalLimitsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut patch = GlobalLimitsPatch {
        reset_quota: req.reset_quota,
        ..GlobalLimitsPatch::default()
    };

    if let Some(v) = req.concurrency {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(StatusCode::BAD_REQUEST, "concurrency out of range");
        }
        patch.concurrency = Some(v as u32);
    }
    if let Some(v) = req.throttle_max_connections {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "throttle_max_connections out of range",
            );
        }
        patch.throttle_max_connections = Some(v as u32);
    }
    if let Some(sp) = req.speed {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_bytes_per_second = Some(v),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed: {e}")),
        }
    }
    if let Some(sp) = req.speed_up {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_up_bytes_per_second = Some(v),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_up: {e}")),
        }
    }
    if let Some(sp) = req.speed_down {
        match parse_speed(&sp) {
            Ok(v) => patch.speed_down_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_down: {e}"));
            }
        }
    }
    if let Some(q) = req.quota {
        match parse_quota_bytes(&q) {
            Ok(v) => patch.quota_bytes = Some(v),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid quota: {e}")),
        }
    }
    if let Some(add_q) = req.add_quota {
        match parse_quota_bytes(&add_q) {
            Ok(v) => patch.add_quota_bytes = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid add_quota: {e}"));
            }
        }
    }
    if let Some(qr) = req.quota_reset {
        match parse_quota_reset(&qr) {
            Ok(v) => patch.quota_reset = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid quota_reset: {e}"));
            }
        }
    }
    if let Some(v) = req.max_connections_per_ip {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "max_connections_per_ip out of range",
            );
        }
        patch.max_connections_per_ip = Some(v as u32);
    }
    if let Some(v) = req.max_new_connections_per_ip {
        if v < 0 || v > i64::from(u32::MAX) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "max_new_connections_per_ip out of range",
            );
        }
        patch.max_new_connections_per_ip = Some(v as u32);
    }
    if let Some(sp) = req.conn_speed {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(StatusCode::BAD_REQUEST, format!("invalid conn_speed: {e}"));
            }
        }
    }
    if let Some(sp) = req.conn_speed_up {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_up_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid conn_speed_up: {e}"),
                );
            }
        }
    }
    if let Some(sp) = req.conn_speed_down {
        match parse_speed(&sp) {
            Ok(v) => patch.conn_speed_down_bytes_per_second = Some(v),
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid conn_speed_down: {e}"),
                );
            }
        }
    }

    let report = state.engine.patch_global_limits(patch);
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn handle_put_limits(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PutGlobalLimitsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let concurrency = match req.concurrency {
        Some(v) => match u32::try_from(v) {
            Ok(c) => Some(c),
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "concurrency out of range"),
        },
        None => None,
    };
    let throttle = match req.throttle_max_connections {
        Some(v) => match u32::try_from(v) {
            Ok(t) => Some(t),
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "throttle_max_connections out of range",
                );
            }
        },
        None => None,
    };
    if req.max_connections_per_ip < 0 || req.max_connections_per_ip > i64::from(u32::MAX) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "max_connections_per_ip out of range",
        );
    }
    if req.max_new_connections_per_ip < 0 || req.max_new_connections_per_ip > i64::from(u32::MAX) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "max_new_connections_per_ip out of range",
        );
    }

    let speed = match parse_speed(&req.speed) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed: {e}")),
    };
    let speed_up = match parse_speed(&req.speed_up) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_up: {e}")),
    };
    let speed_down = match parse_speed(&req.speed_down) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid speed_down: {e}")),
    };
    let quota = match parse_quota_bytes(&req.quota) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid quota: {e}")),
    };
    let quota_reset = match parse_quota_reset(&req.quota_reset) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid quota_reset: {e}")),
    };
    let conn_speed = match parse_speed(&req.conn_speed) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid conn_speed: {e}")),
    };
    let conn_speed_up = match parse_speed(&req.conn_speed_up) {
        Ok(v) => v,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid conn_speed_up: {e}"),
            );
        }
    };
    let conn_speed_down = match parse_speed(&req.conn_speed_down) {
        Ok(v) => v,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid conn_speed_down: {e}"),
            );
        }
    };

    let lim = GlobalLimits {
        speed_bytes_per_second: speed,
        speed_up_bytes_per_second: speed_up,
        speed_down_bytes_per_second: speed_down,
        quota_bytes: quota,
        quota_reset,
        max_connections_per_ip: req.max_connections_per_ip as u32,
        max_new_connections_per_ip: req.max_new_connections_per_ip as u32,
        conn_speed_bytes_per_second: conn_speed,
        conn_speed_up_bytes_per_second: conn_speed_up,
        conn_speed_down_bytes_per_second: conn_speed_down,
    };
    let report = state
        .engine
        .replace_global_limits(concurrency, throttle, &lim);
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn handle_reset_global_quota(State(state): State<ApiState>) -> Response {
    (StatusCode::OK, Json(state.engine.reset_global_quota())).into_response()
}

// ============================================================================
// Enterprise Panel & Universal Outbound Routes (v2.6.0+):
//   GET  /capabilities
//   GET  /state, PUT /state
//   GET  /events (SSE text/event-stream)
//   POST /accounting/checkpoint
//   GET  /outbounds, PUT /outbounds, POST /outbounds/{name}/probe
// ============================================================================

const TRANSPORTS_SUPPORTED: &[&str] = &[
    "ee",
    "dd",
    "plain",
    "web-ws",
    "web-ws-lanes",
    "web-https",
    "web-https-lanes",
    "web-h2-stream",
];

const OUTBOUND_STRATEGIES_SUPPORTED: &[&str] =
    &["ewma-rtt", "failover", "weighted", "round-robin", "hash-dc"];

const API_CAPABILITIES_SUPPORTED: &[&str] = &[
    "accounting-checkpoints",
    "batch-mutations",
    "desired-state-convergence",
    "dynamic-outbounds",
    "etag-optimistic-locking",
    "geo-stealth-ip-filters",
    "global-limits",
    "hot-reload",
    "per-secret-outbound-routing",
    "sse-events",
];

/// `GET /capabilities` — multi-core VPN panel discovery endpoint.
pub async fn handle_get_capabilities(State(state): State<ApiState>) -> Response {
    let eng = &state.engine;
    let resp = CapabilitiesResponse {
        core: "mtg-proxy",
        protocol: "mtproto",
        version: env!("CARGO_PKG_VERSION"),
        boot_id: eng.boot_id(),
        state_revision: eng.state_revision(),
        etag: eng.state_etag(),
        persistence: eng.persistence_mode.as_str(),
        state_file_configured: eng.state_file.is_some(),
        transports: TRANSPORTS_SUPPORTED,
        outbound_protocols: SUPPORTED_OUTBOUND_PROTOCOLS,
        outbound_strategies: OUTBOUND_STRATEGIES_SUPPORTED,
        api_capabilities: API_CAPABILITIES_SUPPORTED,
        features: SUPPORTED_FEATURES,
        listeners: eng.listener_reports.clone(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

/// `GET /state` — complete declarative control-plane snapshot with strong `ETag`.
pub async fn handle_get_state(State(state): State<ApiState>) -> Response {
    let snap = state.engine.export_state_snapshot();
    (StatusCode::OK, Json(snap)).into_response()
}

/// `PUT /state` — single-call atomic desired-state convergence (supports `If-Match`).
pub async fn handle_put_state(State(state): State<ApiState>, body: Bytes) -> Response {
    let desired: RuntimeStateSnapshot = match decode_strict_json(&body) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match state.engine.apply_state_snapshot(&desired) {
        Ok(converged) => (StatusCode::OK, Json(converged)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

/// `POST /accounting/checkpoint` — exact-once per-consumer distributed billing deltas.
pub async fn handle_accounting_checkpoint(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: AccountingCheckpointReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state
        .engine
        .take_billing_checkpoint(&req.consumer_id, req.peek)
    {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(e) => map_engine_error(&e),
    }
}

/// `GET /outbounds` — live telemetry + declarative configuration for universal outbounds.
pub async fn handle_get_outbounds(State(state): State<ApiState>) -> Response {
    let (specs, groups, routing) = state.engine.outbound_config_export();
    let resp = OutboundsReportJson {
        supported_protocols: SUPPORTED_OUTBOUND_PROTOCOLS,
        outbounds: state.engine.outbound_snapshots(),
        specs,
        groups,
        routing,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

/// `PUT /outbounds` — hot-swap universal plug-in outbounds, groups & routing rules live!
pub async fn handle_put_outbounds(State(state): State<ApiState>, body: Bytes) -> Response {
    let req: PutOutboundsReq = match decode_strict_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state
        .engine
        .replace_outbounds(&req.outbounds, &req.outbound_groups, req.routing)
    {
        Ok(outbounds) => {
            let (specs, groups, routing) = state.engine.outbound_config_export();
            (
                StatusCode::OK,
                Json(OutboundsReportJson {
                    supported_protocols: SUPPORTED_OUTBOUND_PROTOCOLS,
                    outbounds,
                    specs,
                    groups,
                    routing,
                }),
            )
                .into_response()
        }
        Err(e) => map_engine_error(&e),
    }
}

/// `POST /outbounds/{name}/probe` — live active dial probe of a named outbound transport.
pub async fn handle_probe_outbound(
    Path(name): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    match state.engine.probe_outbound(&name).await {
        Ok(rtt) => (
            StatusCode::OK,
            Json(OutboundProbeResultJson {
                name,
                ok: true,
                rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                error: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::OK,
            Json(OutboundProbeResultJson {
                name,
                ok: false,
                rtt_ms: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

type SseRecvFut = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = (
                    Result<EngineEvent, broadcast::error::RecvError>,
                    broadcast::Receiver<EngineEvent>,
                ),
            > + Send,
    >,
>;

struct EngineSseStream {
    initial: Option<SseEvent>,
    rx: Option<broadcast::Receiver<EngineEvent>>,
    pending: Option<SseRecvFut>,
    engine: Arc<ProxyEngine>,
}

impl Stream for EngineSseStream {
    type Item = Result<SseEvent, std::convert::Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(ev) = this.initial.take() {
            return std::task::Poll::Ready(Some(Ok(ev)));
        }
        if this.pending.is_none() {
            let Some(mut rx) = this.rx.take() else {
                return std::task::Poll::Ready(None);
            };
            this.pending = Some(Box::pin(async move {
                let res = rx.recv().await;
                (res, rx)
            }));
        }
        let fut = this.pending.as_mut().expect("pending set");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready((res, rx)) => {
                this.pending = None;
                match res {
                    Ok(ev) => {
                        this.rx = Some(rx);
                        let data = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_owned());
                        let sse = SseEvent::default()
                            .id(ev.id.to_string())
                            .event(ev.event)
                            .data(data);
                        std::task::Poll::Ready(Some(Ok(sse)))
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        this.rx = Some(rx);
                        let data = serde_json::json!({
                            "skipped": skipped,
                            "revision": this.engine.state_revision(),
                            "etag": this.engine.state_etag(),
                        })
                        .to_string();
                        let sse = SseEvent::default().event("lagged").data(data);
                        std::task::Poll::Ready(Some(Ok(sse)))
                    }
                    Err(broadcast::error::RecvError::Closed) => std::task::Poll::Ready(None),
                }
            }
        }
    }
}

/// `GET /events` — zero-polling real-time Server-Sent Events (`text/event-stream`).
pub async fn handle_events_sse(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let rx = state.engine.subscribe_events();
    let ready_json = serde_json::json!({
        "boot_id": state.engine.boot_id(),
        "revision": state.engine.state_revision(),
        "etag": state.engine.state_etag(),
    })
    .to_string();
    let initial = Some(SseEvent::default().event("ready").data(ready_json));
    let stream = EngineSseStream {
        initial,
        rx: Some(rx),
        pending: None,
        engine: Arc::clone(&state.engine),
    };
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
