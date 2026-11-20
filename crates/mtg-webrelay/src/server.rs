//! Standalone WEB relay server runtime (`mtg-proxy web-relay`), PROXY protocol
//! listener wrapper (`client-ip = "proxy-protocol"`), loopback `/stats` server,
//! and SIGHUP + 2s config-file watcher (`FeatureWebRelayWatch`) enforcing
//! structural `[web]` immutability while atomically reloading `(secrets, retired)`.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use chrono::Utc;
use http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use mtg_config::{ClientIpSource, Config, ConfigWeb};
use mtg_core::Secret;
use mtg_protocol::proxyproto::{ProxyParseStatus, ProxyProtoMode, parse_proxy_header};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::WebRelayError;
use crate::cover::{CoverSite, StaticCover, UpstreamCover};
use crate::frame::FrameLimits;
use crate::metrics::{RelayCounters, handle_stats_request};
use crate::origin::{Origin, OriginOptions, UpgradedIoExtractor};
use crate::session::{DEFAULT_DIAL_TIMEOUT, TcpProxyBackend};
use crate::token::Signer;

const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Stream wrapper prepending any leftover bytes already read while parsing a
/// required PROXY protocol v1/v2 header.
#[derive(Debug)]
pub struct PrefixedStream {
    prefix: Bytes,
    inner: TcpStream,
}

impl PrefixedStream {
    pub fn new(inner: TcpStream, prefix: Bytes) -> Self {
        Self { prefix, inner }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Read a REQUIRED HAProxy PROXY protocol v1/v2 header asynchronously under
/// timeout, returning the resolved client [`SocketAddr`] and [`PrefixedStream`].
async fn accept_proxy_protocol(
    mut stream: TcpStream,
    raw_peer: SocketAddr,
) -> io::Result<(SocketAddr, PrefixedStream)> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 512];

    tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, async {
        loop {
            match parse_proxy_header(&buf, ProxyProtoMode::Required) {
                Ok(ProxyParseStatus::Complete { header, consumed }) => {
                    let client = header.source.unwrap_or(raw_peer);
                    let leftover = if consumed < buf.len() {
                        Bytes::copy_from_slice(&buf[consumed..])
                    } else {
                        Bytes::new()
                    };
                    return Ok((client, PrefixedStream::new(stream, leftover)));
                }
                Ok(ProxyParseStatus::Incomplete) => {
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF during PROXY protocol header",
                        ));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 8192 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PROXY protocol header too large",
                        ));
                    }
                }
                Ok(ProxyParseStatus::NotPresent) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing required PROXY protocol header",
                    ));
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
            }
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "PROXY protocol handshake timed out",
        )
    })?
}

/// Build an [`UpgradedIoExtractor`] for [`PrefixedStream`] that enforces ZERO
/// pipelined trailing bytes before `101 Switching Protocols`!
fn prefixed_upgrade_extractor() -> UpgradedIoExtractor {
    Box::new(|upgraded| {
        let parts = upgraded.downcast::<TokioIo<PrefixedStream>>().ok()?;
        if !parts.read_buf.is_empty() {
            return None;
        }
        let stream = parts.io.into_inner();
        let (r, w) = tokio::io::split(stream);
        Some((Box::new(r), Box::new(w)))
    })
}

/// Extract ordered `(profile_names, live_secrets, retired_secrets)` from `conf`.
pub fn extract_secrets_and_retired(conf: &Config) -> (Vec<String>, Vec<Secret>, Vec<Secret>) {
    let map: BTreeMap<String, Secret> = conf.get_secrets();
    let mut names = Vec::with_capacity(map.len());
    let mut secrets = Vec::with_capacity(map.len());
    for (k, v) in map {
        names.push(k);
        secrets.push(v);
    }
    let retired = conf.retiring_values();
    (names, secrets, retired)
}

/// Build a live [`Origin`] from validated `[web]` config.
pub async fn build_origin_from_config(
    conf: &Config,
    counters: Arc<RelayCounters>,
) -> Result<Arc<Origin>, WebRelayError> {
    conf.validate_web()
        .map_err(|e| WebRelayError::Config(e.to_string()))?;

    let host = conf
        .web
        .host
        .clone()
        .ok_or_else(|| WebRelayError::Config("missing [web] host".to_owned()))?;
    let backend_hp = conf
        .web
        .backend
        .as_ref()
        .ok_or_else(|| WebRelayError::Config("missing [web] backend".to_owned()))?;
    let backend_addr = resolve_socket_addr(backend_hp.as_str()).await?;

    let signer = Signer::load_file(Path::new(&conf.web.token_key))
        .map_err(|e| WebRelayError::Config(e.to_string()))?;

    let cover = if !conf.web.cover_dir.is_empty() {
        CoverSite::Static(Arc::new(
            StaticCover::new(&conf.web.cover_dir)
                .map_err(|e| WebRelayError::Config(e.to_string()))?,
        ))
    } else if !conf.web.cover_upstream.is_empty() {
        CoverSite::Upstream(Arc::new(
            UpstreamCover::new(&conf.web.cover_upstream)
                .map_err(|e| WebRelayError::Config(e.to_string()))?,
        ))
    } else {
        return Err(WebRelayError::Config(
            "must configure either [web] cover-dir or [web] cover-upstream".to_owned(),
        ));
    };

    let (names, secrets, retired) = extract_secrets_and_retired(conf);
    counters.set_profiles(names);

    let limits = FrameLimits {
        max_payload: conf.web.max_frame_payload.unwrap_or(0) as usize,
        batch_bytes: conf.web.carrier_batch_bytes.unwrap_or(0) as usize,
    };

    let origin = Origin::new(OriginOptions {
        host,
        secrets,
        retired,
        signer,
        cover,
        backend: Arc::new(TcpProxyBackend::new(backend_addr, DEFAULT_DIAL_TIMEOUT)),
        limits,
        max_sessions: conf.web.max_sessions.unwrap_or(0) as usize,
        max_streams: conf.web.max_streams.unwrap_or(0) as usize,
        client_ip_source: conf.web.client_ip.unwrap_or_default(),
        counters: Some(counters),
    })
    .map_err(|e| WebRelayError::Config(e.to_string()))?;

    Ok(Arc::new(origin))
}

/// Bind a tuned Linux `TcpListener` with zero-syscall child socket inheritance
/// (`TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`,
/// `TCP_FASTOPEN`, best-effort BBR).
async fn bind_tuned_listener(bind_addr: &str) -> Result<TcpListener, WebRelayError> {
    let sa = resolve_socket_addr(bind_addr).await?;
    let cfg = mtg_net::SocketConfig {
        reuse_port: false,
        ..mtg_net::SocketConfig::default()
    };
    let sock = mtg_net::create_listener_socket(sa, &cfg)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(TcpListener::from_std(std_listener)?)
}

/// Spawn the public HTTP/WebSocket origin listener on `bind_addr`.
pub async fn spawn_origin_server(
    origin: Arc<Origin>,
    bind_addr: &str,
    require_proxy_proto: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), WebRelayError> {
    let listener = bind_tuned_listener(bind_addr).await?;
    let local_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                res = listener.accept() => res,
            };

            let (stream, raw_peer) = match accept {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(%e, "web relay accept error");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            let origin = Arc::clone(&origin);

            tokio::spawn(async move {
                let (client_peer, io_stream) = if require_proxy_proto {
                    match accept_proxy_protocol(stream, raw_peer).await {
                        Ok(res) => res,
                        Err(_) => return,
                    }
                } else {
                    (raw_peer, PrefixedStream::new(stream, Bytes::new()))
                };

                let io = TokioIo::new(io_stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let origin = Arc::clone(&origin);
                    async move {
                        let resp = origin
                            .handle_incoming(req, client_peer, prefixed_upgrade_extractor())
                            .await;
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });

                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await;
            });
        }
    });

    Ok((local_addr, handle))
}

/// Spawn the separate loopback `/stats` HTTP server on `bind_addr`.
pub async fn spawn_stats_server(
    counters: Arc<RelayCounters>,
    store: Arc<crate::store::SessionStore>,
    bind_addr: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), WebRelayError> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                res = listener.accept() => res,
            };

            let Ok((stream, _)) = accept else {
                continue;
            };
            let counters = Arc::clone(&counters);
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let counters = Arc::clone(&counters);
                    let store = Arc::clone(&store);
                    async move {
                        let resp = handle_stats_request(&req, &counters, &store);
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    Ok((local_addr, handle))
}

/// Full standalone `mtg-proxy web-relay` entrypoint!
pub async fn run_web_relay(
    conf: &Config,
    config_path: &Path,
    version: &str,
    check_only: bool,
) -> Result<(), WebRelayError> {
    conf.validate_web()
        .map_err(|e| WebRelayError::Config(e.to_string()))?;

    let host = conf.web.host.as_deref().unwrap_or("");
    let listen = conf
        .web
        .bind_to
        .as_ref()
        .map_or("", mtg_config::HostPort::as_str);
    let backend = conf
        .web
        .backend
        .as_ref()
        .map_or("", mtg_config::HostPort::as_str);
    let stats_bind = conf
        .web
        .stats_bind_to
        .as_ref()
        .map(mtg_config::HostPort::as_str);

    if check_only {
        // Also verify token key file & cover path exist and are readable!
        let _ = Signer::load_file(Path::new(&conf.web.token_key))
            .map_err(|e| WebRelayError::Config(e.to_string()))?;
        if !conf.web.cover_dir.is_empty() {
            let _ = StaticCover::new(&conf.web.cover_dir)
                .map_err(|e| WebRelayError::Config(e.to_string()))?;
        } else if !conf.web.cover_upstream.is_empty() {
            let _ = UpstreamCover::new(&conf.web.cover_upstream)
                .map_err(|e| WebRelayError::Config(e.to_string()))?;
        }

        println!("mtg-proxy {version}: [web] configuration is usable");
        println!("  host      {host}");
        println!("  listen    {listen}");
        println!("  backend   {backend}");
        println!("  profiles  {}", conf.get_secrets().len());
        println!(
            "  client-ip {}",
            conf.web.client_ip.unwrap_or_default().as_str()
        );
        println!("  stats     {}", stats_bind.unwrap_or("(off)"));
        return Ok(());
    }

    if let Ok((cur, max)) = mtg_net::raise_nofile_limit(1_048_576) {
        info!(
            nofile_soft = cur,
            nofile_hard = max,
            version,
            "starting web-relay"
        );
    }

    let counters = Arc::new(RelayCounters::new(Utc::now()));
    let origin = build_origin_from_config(conf, Arc::clone(&counters)).await?;
    let initial_web = conf.web.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let require_pp = conf.web.client_ip.unwrap_or_default() == ClientIpSource::ProxyProtocol;

    let (origin_addr, origin_handle) =
        spawn_origin_server(Arc::clone(&origin), listen, require_pp, shutdown_rx.clone()).await?;
    info!(%origin_addr, host, backend, profiles = origin.profiles_len(), "web-relay listening");

    let stats_handle = if let Some(sb) = stats_bind {
        let (sa, sh) = spawn_stats_server(
            Arc::clone(&counters),
            Arc::clone(origin.store()),
            sb,
            shutdown_rx.clone(),
        )
        .await?;
        info!(stats_addr = %sa, "web-relay stats endpoint listening");
        Some(sh)
    } else {
        None
    };

    // Spawn 2-second file-watch reload task (FeatureWebRelayWatch) + SIGHUP!
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut poll_tick = tokio::time::interval(CONFIG_POLL_INTERVAL);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll_tick.tick().await; // consume immediate first tick

    let cfg_path = PathBuf::from(config_path);
    let mut last_mtime = file_mtime(&cfg_path);

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                info!("received SIGHUP; reloading WEB relay profiles");
                reload_web_profiles(&cfg_path, &initial_web, &origin, &counters);
                last_mtime = file_mtime(&cfg_path);
            }
            _ = poll_tick.tick() => {
                let cur_mtime = file_mtime(&cfg_path);
                if cur_mtime.is_some() && cur_mtime != last_mtime {
                    last_mtime = cur_mtime;
                    info!("detected config file change; reloading WEB relay profiles");
                    reload_web_profiles(&cfg_path, &initial_web, &origin, &counters);
                }
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM; shutting down web-relay");
                break;
            }
            _ = sigint.recv() => {
                info!("received SIGINT; shutting down web-relay");
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = origin_handle.await;
    if let Some(sh) = stats_handle {
        let _ = sh.await;
    }
    Ok(())
}

/// Reload `(secrets, retired)` from disk while STRICTLY refusing structural
/// `[web]` changes that require a process restart!
pub fn reload_web_profiles(
    config_path: &Path,
    initial_web: &ConfigWeb,
    origin: &Origin,
    counters: &RelayCounters,
) -> bool {
    let raw = match fs::read(config_path) {
        Ok(b) => b,
        Err(e) => {
            error!(%e, "web-relay reload: cannot read config");
            counters.on_reload(false);
            return false;
        }
    };
    let mut next = match Config::parse(&raw) {
        Ok(c) => c,
        Err(e) => {
            error!(%e, "web-relay reload: cannot parse config");
            counters.on_reload(false);
            return false;
        }
    };
    if let Err(e) = next.apply_environment() {
        error!(%e, "web-relay reload: cannot apply environment");
        counters.on_reload(false);
        return false;
    }
    if let Err(e) = next.validate().and_then(|()| next.validate_web()) {
        error!(%e, "web-relay reload: invalid configuration");
        counters.on_reload(false);
        return false;
    }

    // Refuse ANY structural `[web]` change (requires restart).
    if next.web != *initial_web {
        warn!("web-relay reload refused: structural [web] fields changed (restart required)");
        counters.on_reload(false);
        return false;
    }

    let (names, secrets, retired) = extract_secrets_and_retired(&next);
    match origin.set_secrets_with_retired(&secrets, &retired) {
        Ok(()) => {
            counters.set_profiles(names);
            counters.on_reload(true);
            info!(
                profiles = secrets.len(),
                retired = retired.len(),
                "web-relay profiles reloaded atomically"
            );
            true
        }
        Err(e) => {
            error!(%e, "web-relay reload: failed to build capability registry");
            counters.on_reload(false);
            false
        }
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

async fn resolve_socket_addr(addr: &str) -> Result<SocketAddr, WebRelayError> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut resolved = tokio::net::lookup_host(addr).await?;
    resolved
        .next()
        .ok_or_else(|| WebRelayError::Config(format!("cannot resolve socket address {addr:?}")))
}
