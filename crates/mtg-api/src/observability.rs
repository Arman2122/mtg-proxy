//! Prometheus OpenMetrics HTTP endpoint and 1-second batched StatsD UDP exporter.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use mtg_config::StatsdTagFormat;
use mtg_engine::ProxyEngine;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Clone)]
struct PromState {
    engine: Arc<ProxyEngine>,
    prefix: Arc<str>,
}

async fn handle_prometheus(State(state): State<PromState>) -> impl IntoResponse {
    let body = state.engine.metrics.render_prometheus(&state.prefix);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
}

/// Build the Prometheus HTTP `Router` serving `http_path` (default `/`).
pub fn build_prometheus_router(engine: Arc<ProxyEngine>, http_path: &str, prefix: &str) -> Router {
    let path = if http_path.is_empty() || !http_path.starts_with('/') {
        "/"
    } else {
        http_path
    };
    let state = PromState {
        engine,
        prefix: Arc::from(if prefix.is_empty() { "mtg" } else { prefix }),
    };
    Router::new()
        .route(path, get(handle_prometheus))
        .with_state(state)
}

/// Bind and serve the Prometheus exporter until `shutdown` signals `true`.
pub async fn spawn_prometheus_server(
    engine: Arc<ProxyEngine>,
    bind_to: &str,
    http_path: &str,
    prefix: &str,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(bind_to).await?;
    let local_addr = listener.local_addr()?;
    let app = build_prometheus_router(engine, http_path, prefix);
    info!(bind = %local_addr, path = http_path, "Prometheus metrics server started");

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
            warn!(error = %e, "Prometheus server exited with error");
        }
    });

    Ok((local_addr, handle))
}

/// Spawn a 1-second batched StatsD UDP exporter (Datadog / InfluxDB / Graphite).
pub fn spawn_statsd_exporter(
    engine: &ProxyEngine,
    address: String,
    prefix: String,
    tag_format: StatsdTagFormat,
    shutdown: watch::Receiver<bool>,
) {
    info!(address = %address, format = ?tag_format, "StatsD exporter started");
    engine
        .metrics
        .spawn_statsd_flusher(address, prefix, tag_format, shutdown);
}
