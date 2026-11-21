//! Management HTTP API (all 19 routes with 100% Go/Penhoon contract parity),
//! Prometheus OpenMetrics endpoint, and 1-second batched StatsD exporter.

pub mod dto;
pub mod handlers;
pub mod observability;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{any, delete, get, post};
use mtg_engine::ProxyEngine;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

pub use handlers::ApiState;
pub use observability::{build_prometheus_router, spawn_prometheus_server, spawn_statsd_exporter};

/// Maximum Management API JSON request body size (4 MiB).
pub const MAX_API_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Build the complete 19-route Management HTTP API `Router` wrapped with
/// constant-time Bearer token authentication (when `token` is non-empty) and a
/// 4 MiB body limit.
pub fn build_api_router(engine: Arc<ProxyEngine>, token: &str) -> Router {
    let state = ApiState::new(engine, token);
    Router::new()
        .route("/healthz", get(handlers::handle_healthz))
        .route("/stats", get(handlers::handle_stats))
        .route("/reload", any(handlers::handle_reload))
        .route("/accounting", get(handlers::handle_get_accounting))
        .route("/accounting/flush", post(handlers::handle_flush_accounting))
        .route("/ip-filters", get(handlers::handle_get_ip_filters))
        .route(
            "/ip-filters/refresh",
            post(handlers::handle_refresh_ip_filters),
        )
        .route(
            "/secrets",
            get(handlers::handle_get_secrets)
                .put(handlers::handle_put_secrets)
                .post(handlers::handle_post_secret),
        )
        .route("/secrets/batch", post(handlers::handle_batch_secrets))
        .route(
            "/secrets/{name}",
            get(handlers::handle_get_secret)
                .patch(handlers::handle_patch_secret)
                .delete(handlers::handle_delete_secret),
        )
        .route(
            "/secrets/{name}/disconnect",
            post(handlers::handle_disconnect_secret),
        )
        .route(
            "/secrets/{name}/reset-quota",
            post(handlers::handle_reset_quota),
        )
        .route("/secrets/{name}/kick", post(handlers::handle_kick))
        .route("/secrets/{name}/clients", get(handlers::handle_get_clients))
        .route(
            "/secrets/{name}/bans",
            post(handlers::handle_post_bans).get(handlers::handle_get_bans),
        )
        .route(
            "/secrets/{name}/bans/{*address}",
            delete(handlers::handle_delete_ban),
        )
        .route(
            "/secrets/{name}/external-ips",
            get(handlers::handle_get_external_ips)
                .put(handlers::handle_put_external_ips)
                .delete(handlers::handle_delete_external_ips),
        )
        .route(
            "/adtag",
            get(handlers::handle_get_adtag)
                .put(handlers::handle_put_adtag)
                .delete(handlers::handle_delete_adtag),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            handlers::bearer_auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .with_state(state)
}

/// Bind and serve the Management HTTP API until `shutdown` signals `true`.
pub async fn spawn_api_server(
    engine: Arc<ProxyEngine>,
    bind_to: &str,
    token: &str,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(bind_to).await?;
    let local_addr = listener.local_addr()?;
    let app = build_api_router(engine, token);
    let auth_state = if token.is_empty() {
        "unauthenticated"
    } else {
        "bearer-token"
    };
    info!(bind = %local_addr, auth = auth_state, "Management API server started");

    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            loop {
                if *shutdown.borrow() {
                    return;
                }
                if shutdown.changed().await.is_err() {
                    return;
                }
            }
        });
        if let Err(e) = server.await {
            warn!(error = %e, "Management API server exited with error");
        }
    });

    Ok((local_addr, handle))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use http_body_util::BodyExt as _;
    use mtg_config::Config;
    use mtg_engine::{ProxyEngine, SUPPORTED_FEATURES};
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;

    const ALICE_SECRET: &str =
        "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d";
    const BOB_SECRET: &str = "ee00112233445566778899aabbccddeeff6578616d706c652e636f6d";
    const RETIRING_SECRET: &str =
        "eeffeeddccbbaa9988776655443322110073746f726167652e676f6f676c65617069732e636f6d";

    fn build_test_engine(track_ips: bool, with_retiring: bool) -> Arc<ProxyEngine> {
        let retiring_block = if with_retiring {
            format!(
                "[[retiring-secret]]\nname = \"alice\"\nsecret = \"{RETIRING_SECRET}\"\nuntil = \"2099-01-01T00:00:00Z\"\n"
            )
        } else {
            String::new()
        };
        let toml = format!(
            r#"
bind-to = "127.0.0.1:3133"
track-client-ips = {track_ips}
{retiring_block}
[secrets]
alice = "{ALICE_SECRET}"
"#
        );
        let cfg = Config::parse(toml.as_bytes()).unwrap();
        ProxyEngine::from_config(&cfg, None, 1, false).unwrap()
    }

    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        auth: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(a) = auth {
            builder = builder.header(header::AUTHORIZATION, a);
        }
        let req = match body {
            Some(v) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "_raw": String::from_utf8_lossy(&bytes).into_owned() }));
        (status, json)
    }

    #[tokio::test]
    async fn penhoon_contract_all_19_routes_auth_and_edge_cases() {
        let engine = build_test_engine(true, true);
        let app = build_api_router(Arc::clone(&engine), "top-secret-token");
        let auth = Some("Bearer top-secret-token");

        // 1. Constant-time Bearer auth rejects missing/wrong token with 401
        let (st, _) = send(&app, Method::GET, "/stats", None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = send(&app, Method::GET, "/stats", Some("Bearer wrong"), None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // 2. GET /stats verifies exact 20 sorted Penhoon feature flags
        let (st, stats) = send(&app, Method::GET, "/stats", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        let feats: Vec<&str> = stats["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(feats.len(), 20);
        assert_eq!(feats, SUPPORTED_FEATURES);
        let mut sorted = feats.clone();
        sorted.sort_unstable();
        assert_eq!(feats, sorted);
        assert_eq!(stats["users"]["alice"]["retiring_keys"], 1);
        assert!(stats.get("faketls_handshake").is_none());
        assert!(stats.get("obfuscated").is_none());

        // 3. /reload returns 405 on GET, 503 when no config_path is attached
        let (st, _) = send(&app, Method::GET, "/reload", auth, None).await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
        let (st, _) = send(&app, Method::POST, "/reload", auth, None).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);

        // 4. GET /secrets & O(1) GET /secrets/{name}
        let (st, list) = send(&app, Method::GET, "/secrets", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(list["secrets"].as_array().unwrap().len(), 1);
        assert_eq!(list["secrets"][0]["name"], "alice");
        assert_eq!(list["secrets"][0]["retiring_keys"], 1);

        let (st, single) = send(&app, Method::GET, "/secrets/alice", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(single["name"], "alice");
        let (st, _) = send(&app, Method::GET, "/secrets/nobody", auth, None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // 5. Strict unknown-field rejection (Go DisallowUnknownFields parity)
        let (st, _) = send(
            &app,
            Method::POST,
            "/secrets",
            auth,
            Some(json!({ "name": "bob", "secret": BOB_SECRET, "rogue_field": 1 })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // 6. POST /secrets adds bob with quota & speed; client_fair without speed fails 400
        let (st, _) = send(
            &app,
            Method::POST,
            "/secrets",
            auth,
            Some(json!({ "name": "bob", "secret": BOB_SECRET, "client_fair": true })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let (st, _) = send(
            &app,
            Method::POST,
            "/secrets",
            auth,
            Some(json!({
                "name": "bob",
                "secret": BOB_SECRET,
                "quota": "1GB",
                "quota_reset": "monthly",
                "speed": "10mbit",
                "client_fair": true,
                "ip_limit": 3
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // 7. PUT /secrets preserves alice's retiring key while replacing the map!
        let (st, _) = send(
            &app,
            Method::PUT,
            "/secrets",
            auth,
            Some(json!({
                "secrets": {
                    "alice": { "secret": ALICE_SECRET, "ip_limit": 2 },
                    "bob": { "secret": BOB_SECRET }
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (st, alice) = send(&app, Method::GET, "/secrets/alice", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(alice["retiring_keys"], 1);
        assert_eq!(alice["ip_limit"], 2);

        // 8. DELETE /secrets/bob -> 200; DELETE /secrets/alice (last secret) -> 409!
        let (st, _) = send(&app, Method::DELETE, "/secrets/bob", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = send(&app, Method::DELETE, "/secrets/alice", auth, None).await;
        assert_eq!(st, StatusCode::CONFLICT);

        // 9. POST /secrets/alice/reset-quota
        let (st, _) = send(&app, Method::POST, "/secrets/alice/reset-quota", auth, None).await;
        assert_eq!(st, StatusCode::OK);

        // 10. POST /secrets/alice/kick
        let (st, kick) = send(
            &app,
            Method::POST,
            "/secrets/alice/kick",
            auth,
            Some(json!({ "ips": ["203.0.113.5"] })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(kick["closed"], 0);

        // 11. GET /secrets/alice/clients (default limit, invalid limit -> 400)
        let (st, clients) = send(&app, Method::GET, "/secrets/alice/clients", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(clients["tracking"], true);
        assert_eq!(clients["clients"].as_array().unwrap().len(), 0);
        let (st, _) = send(
            &app,
            Method::GET,
            "/secrets/alice/clients?limit=0",
            auth,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // 12. Bans: loopback blocked without force (400), IPv6 /64 accepted & unbanned unescaped!
        let (st, _) = send(
            &app,
            Method::POST,
            "/secrets/alice/bans",
            auth,
            Some(json!({ "ips": ["127.0.0.1"] })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let (st, banned) = send(
            &app,
            Method::POST,
            "/secrets/alice/bans",
            auth,
            Some(json!({ "ips": ["2001:db8:abcd::42", "198.51.100.7"], "ttl": "2h" })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(banned["banned"], 2);

        let (st, bans_list) = send(&app, Method::GET, "/secrets/alice/bans", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bans_list["total"], 2);
        assert_eq!(bans_list["bans"].as_array().unwrap().len(), 2);

        // Unescaped IPv6 /64 wildcard delete!
        let (st, unban) = send(
            &app,
            Method::DELETE,
            "/secrets/alice/bans/2001:db8:abcd::/64",
            auth,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(unban["removed"], 1);

        // 13. External IPs GET / PUT / DELETE
        let (st, ext) = send(
            &app,
            Method::PUT,
            "/secrets/alice/external-ips",
            auth,
            Some(json!({ "ips": ["198.51.100.9"], "ttl": "5m" })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(ext["active_ips"], 1);
        assert_eq!(ext["external_ips"], json!(["198.51.100.9"]));

        let (st, ext_get) =
            send(&app, Method::GET, "/secrets/alice/external-ips", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(ext_get["active_ips"], 1);

        let (st, _) = send(
            &app,
            Method::DELETE,
            "/secrets/alice/external-ips",
            auth,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // 14. Global adtag GET / PUT / DELETE
        let (st, at) = send(&app, Method::GET, "/adtag", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(at["ad_tag"].is_null());

        let (st, _) = send(
            &app,
            Method::PUT,
            "/adtag",
            auth,
            Some(json!({ "ad_tag": "" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let tag_hex = "00112233445566778899aabbccddeeff";
        let (st, _) = send(
            &app,
            Method::PUT,
            "/adtag",
            auth,
            Some(json!({ "ad_tag": tag_hex })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (st, at) = send(&app, Method::GET, "/adtag", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(at["ad_tag"], tag_hex);

        let (st, _) = send(&app, Method::DELETE, "/adtag", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        let (st, at) = send(&app, Method::GET, "/adtag", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(at["ad_tag"].is_null());

        // 15. Prometheus HTTP endpoint serves valid exposition text
        let prom = build_prometheus_router(Arc::clone(&engine), "/metrics", "mtg");
        let resp = prom
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("mtg_client_connections"));
    }

    #[tokio::test]
    async fn enterprise_accounting_patch_batch_disconnect_healthz_and_ip_filters() {
        let engine = build_test_engine(true, false);
        let app = build_api_router(Arc::clone(&engine), "ops-token");
        let auth = Some("Bearer ops-token");

        // 1. GET /healthz
        let (st, hz) = send(&app, Method::GET, "/healthz", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(hz["status"], "ok");
        assert_eq!(hz["secrets_count"], 1);

        // 2. POST /secrets/batch atomically adds bob & charlie!
        let (st, batch) = send(
            &app,
            Method::POST,
            "/secrets/batch",
            auth,
            Some(json!({
                "upsert": {
                    "bob": { "secret": BOB_SECRET, "quota": "1GB", "quota_reset": "daily", "max_connections": 25 },
                    "charlie": { "secret": RETIRING_SECRET, "quota": "5GB", "quota_reset": "weekly" }
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(batch["upserted"], 2);
        assert_eq!(batch["deleted"], 0);

        // 3. PATCH /secrets/bob tops up quota (+2GB -> 3GB), updates disabled, without resending secret!
        let (st, _) = send(
            &app,
            Method::PATCH,
            "/secrets/bob",
            auth,
            Some(json!({ "add_quota": "2GB", "disabled": true, "reset_quota": true })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let (st, bob) = send(&app, Method::GET, "/secrets/bob", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bob["quota"], 3i64 << 30);
        assert_eq!(bob["quota_reset"], "daily");
        assert_eq!(bob["max_connections"], 25);
        assert_eq!(bob["disabled"], true);

        // 4. POST /secrets/bob/disconnect
        let (st, disc) = send(&app, Method::POST, "/secrets/bob/disconnect", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(disc["closed"], 0);

        // 5. GET /accounting & POST /accounting/flush
        let (st, acc) = send(&app, Method::GET, "/accounting", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(acc["totals"]["secrets_count"], 3);
        assert_eq!(acc["accounts"].as_array().unwrap().len(), 3);

        let (st, fl) = send(&app, Method::POST, "/accounting/flush", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(fl["flushed"], false);

        // 6. GET /ip-filters & POST /ip-filters/refresh
        let (st, ipf) = send(&app, Method::GET, "/ip-filters", auth, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(ipf["allowlist"]["enabled"], false);
        assert_eq!(ipf["blocklist"]["enabled"], false);

        let (st, _) = send(&app, Method::POST, "/ip-filters/refresh", auth, None).await;
        assert_eq!(st, StatusCode::OK);
    }
}
