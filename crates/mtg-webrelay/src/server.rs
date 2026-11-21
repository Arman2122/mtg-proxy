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

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use mtg_config::{ClientIpSource, Config, ConfigWeb, IpFilterAction, PreferIp};
use mtg_core::Secret;
use mtg_governance::{DEFAULT_IPFILTER_UPDATE_EACH, LiveIpFilter, LiveIpFilterConfig};
use mtg_net::{DnsResolver, ProxyPool, SocketConfig};
use mtg_protocol::proxyproto::{ProxyParseStatus, ProxyProtoMode, parse_proxy_header};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::WebRelayError;
use crate::cover::{CoverSite, StaticCover, UpstreamCover};
use crate::frame::FrameLimits;
use crate::metrics::{RelayCounters, handle_stats_request};
use crate::origin::{Origin, OriginIpFilters, OriginOptions, UpgradedIoExtractor};
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

/// Lock-free read half preserving any leftover prefix bytes alongside
/// `TcpStream::into_split()`'s `OwnedReadHalf`.
#[derive(Debug)]
struct PrefixedReadHalf {
    prefix: Bytes,
    inner: tokio::net::tcp::OwnedReadHalf,
}

impl AsyncRead for PrefixedReadHalf {
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

impl PrefixedStream {
    pub fn new(inner: TcpStream, prefix: Bytes) -> Self {
        Self { prefix, inner }
    }

    /// Split into lock-free owned read/write halves via `TcpStream::into_split()`
    /// (completely eliminates `tokio::io::split`'s `Arc<BiLock>` mutex on every
    /// WebSocket read and write!).
    pub fn into_owned_split(
        self,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) {
        let (r, w) = self.inner.into_split();
        if self.prefix.is_empty() {
            (Box::new(r), Box::new(w))
        } else {
            (
                Box::new(PrefixedReadHalf {
                    prefix: self.prefix,
                    inner: r,
                }),
                Box::new(w),
            )
        }
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
/// pipelined trailing bytes before `101 Switching Protocols` and splits the
/// underlying `TcpStream` into lock-free owned halves!
fn prefixed_upgrade_extractor() -> UpgradedIoExtractor {
    Box::new(|upgraded| {
        let parts = upgraded.downcast::<TokioIo<PrefixedStream>>().ok()?;
        if !parts.read_buf.is_empty() {
            return None;
        }
        let stream = parts.io.into_inner();
        Some(stream.into_owned_split())
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

/// Pre-loaded allowlist/blocklist handles shared from `ProxyEngine` in
/// `[web] integrated = true` mode (avoids duplicate CIDR downloads/bitmaps).
#[derive(Debug, Clone)]
pub struct SharedGeoFilters {
    pub allowlist: Option<Arc<LiveIpFilter>>,
    pub allowlist_action: IpFilterAction,
    pub blocklist: Option<Arc<LiveIpFilter>>,
    pub blocklist_action: IpFilterAction,
}

/// Build a live [`Origin`] from validated `[web]` config (standalone `web-relay` mode).
pub async fn build_origin_from_config(
    conf: &Config,
    counters: Arc<RelayCounters>,
) -> Result<Arc<Origin>, WebRelayError> {
    build_origin_with_overrides(conf, counters, None, None, None).await
}

/// Build a live [`Origin`] for embedded `[web] integrated = true` mode inside `mtg-proxy run`,
/// sharing the proxy engine's already-loaded Geo-Stealth allowlist/blocklist and pointing
/// directly at an internal loopback `dd` listener!
pub async fn build_origin_with_overrides(
    conf: &Config,
    counters: Arc<RelayCounters>,
    backend_override: Option<SocketAddr>,
    client_ip_override: Option<ClientIpSource>,
    shared_ip_filters: Option<SharedGeoFilters>,
) -> Result<Arc<Origin>, WebRelayError> {
    conf.validate_web()
        .map_err(|e| WebRelayError::Config(e.to_string()))?;

    let host = conf
        .web
        .host
        .clone()
        .ok_or_else(|| WebRelayError::Config("missing [web] host".to_owned()))?;
    let backend_addr = if let Some(sa) = backend_override {
        sa
    } else {
        let backend_hp = conf
            .web
            .backend
            .as_ref()
            .ok_or_else(|| WebRelayError::Config("missing [web] backend".to_owned()))?;
        resolve_socket_addr(backend_hp.as_str()).await?
    };

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

    let ip_filters = build_ip_filters_from_config(conf, shared_ip_filters).await?;

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
        client_ip_source: client_ip_override
            .or(conf.web.client_ip)
            .unwrap_or_default(),
        counters: Some(counters),
        ip_filters,
    })
    .map_err(|e| WebRelayError::Config(e.to_string()))?;

    Ok(Arc::new(origin))
}

/// Build an [`OriginIpFilters`] from `[defense.allowlist]`, `[defense.blocklist]`,
/// and CDN trusted-proxy settings (`[web] cdn`, `trusted-proxies`, `trusted-proxy-urls`,
/// `client-ip-header`).
pub async fn build_ip_filters_from_config(
    conf: &Config,
    shared_ip_filters: Option<SharedGeoFilters>,
) -> Result<OriginIpFilters, WebRelayError> {
    let want_bl = shared_ip_filters.is_none() && conf.defense.blocklist.enabled.unwrap_or(false);
    let want_al = shared_ip_filters.is_none() && conf.defense.allowlist.enabled.unwrap_or(false);
    let want_cdn = conf.web.cdn.is_some()
        || conf
            .web
            .trusted_proxies
            .as_ref()
            .is_some_and(|v| !v.is_empty())
        || conf
            .web
            .trusted_proxy_urls
            .as_ref()
            .is_some_and(|v| !v.is_empty());

    let (dns, prefer_ip, proxy_pool, sock_cfg) = if want_bl || want_al || want_cdn {
        let prefer_ip = conf.prefer_ip.unwrap_or(PreferIp::PreferIpv6);
        let sock_cfg = SocketConfig::default();
        let dns = Arc::new(
            DnsResolver::build(conf.network.dns.as_deref(), conf.network.doh_ip, prefer_ip)
                .map_err(|e| WebRelayError::Config(format!("dns init failed: {e}")))?,
        );
        let tcp_timeout = conf.network.timeout.tcp.unwrap_or(Duration::from_secs(10));
        let proxy_pool = match &conf.network.proxies {
            Some(urls) if !urls.is_empty() => Some(
                ProxyPool::from_urls(urls, sock_cfg, tcp_timeout)
                    .map_err(|e| WebRelayError::Config(e.to_string()))?,
            ),
            _ => None,
        };
        (Some(dns), prefer_ip, proxy_pool, sock_cfg)
    } else {
        (None, PreferIp::PreferIpv6, None, SocketConfig::default())
    };

    let (allowlist, allowlist_action, blocklist, blocklist_action) =
        if let Some(shared) = shared_ip_filters {
            (
                shared.allowlist,
                shared.allowlist_action,
                shared.blocklist,
                shared.blocklist_action,
            )
        } else {
            let blocklist = if want_bl {
                let bl = Arc::new(LiveIpFilter::from_list_config(
                    &conf.defense.blocklist,
                    dns.clone(),
                    prefer_ip,
                    proxy_pool.clone(),
                    sock_cfg,
                ));
                if let Err(e) = bl.init_load().await {
                    warn!(error = %e, "web-relay initial blocklist load failed");
                }
                Some(bl)
            } else {
                None
            };

            let allowlist = if want_al {
                let al = Arc::new(LiveIpFilter::from_list_config(
                    &conf.defense.allowlist,
                    dns.clone(),
                    prefer_ip,
                    proxy_pool.clone(),
                    sock_cfg,
                ));
                if let Err(e) = al.init_load().await {
                    warn!(error = %e, "web-relay initial allowlist load failed");
                }
                Some(al)
            } else {
                None
            };

            (
                allowlist,
                conf.defense
                    .allowlist
                    .action
                    .unwrap_or(IpFilterAction::Front),
                blocklist,
                conf.defense
                    .blocklist
                    .action
                    .unwrap_or(IpFilterAction::Close),
            )
        };

    // Build wait-free O(1) trusted CDN / reverse-proxy IP range filter!
    let trusted_proxies = if want_cdn {
        let mut sources: Vec<String> = Vec::new();
        let mut inline_cidrs: Vec<String> = Vec::new();
        if let Some(preset) = conf.web.cdn {
            sources.extend(preset.ip_feed_urls().iter().map(|s| (*s).to_owned()));
            inline_cidrs.extend(preset.fallback_cidrs().iter().map(|s| (*s).to_owned()));
        }
        if let Some(extra_urls) = &conf.web.trusted_proxy_urls {
            sources.extend(extra_urls.iter().cloned());
        }
        if let Some(extra_cidrs) = &conf.web.trusted_proxies {
            inline_cidrs.extend(extra_cidrs.iter().cloned());
        }
        let tp = Arc::new(LiveIpFilter::from_config(LiveIpFilterConfig {
            sources,
            inline_cidrs,
            cache_file: None,
            update_each: DEFAULT_IPFILTER_UPDATE_EACH,
            download_concurrency: 4,
            dns,
            prefer_ip,
            proxy_pool,
            sock_cfg,
        }));
        if let Err(e) = tp.init_load().await {
            warn!(error = %e, "web-relay trusted-proxies CDN feed load failed; using built-in/inline CIDRs");
        }
        Some(tp)
    } else {
        None
    };

    let client_ip_header = conf
        .web
        .client_ip_header
        .as_deref()
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            conf.web
                .cdn
                .map(|c| c.default_client_ip_header().to_owned())
        });

    Ok(OriginIpFilters {
        allowlist,
        allowlist_action,
        blocklist,
        blocklist_action,
        trusted_proxies,
        client_ip_header,
    })
}

/// Load a PEM certificate chain & private key into a `tokio_rustls::TlsAcceptor`
/// (supports RSA, ECDSA, Ed25519 keys & Let's Encrypt `fullchain.pem` / `privkey.pem`,
/// hot-reloadable on `SIGHUP`!).
pub fn load_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, WebRelayError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            WebRelayError::Config(format!(
                "cannot read [web] tls-cert {}: {e}",
                cert_path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            WebRelayError::Config(format!(
                "invalid PEM in [web] tls-cert {}: {e}",
                cert_path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(WebRelayError::Config(format!(
            "[web] tls-cert {} contains no certificates",
            cert_path.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        WebRelayError::Config(format!(
            "cannot read [web] tls-key {}: {e}",
            key_path.display()
        ))
    })?;

    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| WebRelayError::Config(format!("TLS protocol config error: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| WebRelayError::Config(format!("invalid TLS cert/key pair: {e}")))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Hot-reloadable TLS acceptor backed by a wait-free `ArcSwap<TlsAcceptor>`
/// (supports zero-downtime Let's Encrypt certificate renewal on `SIGHUP`).
#[derive(Clone)]
pub struct ReloadableTlsAcceptor {
    inner: Arc<ArcSwap<TlsAcceptor>>,
}

impl std::fmt::Debug for ReloadableTlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableTlsAcceptor")
            .finish_non_exhaustive()
    }
}

impl ReloadableTlsAcceptor {
    /// Load a PEM certificate chain & private key from disk.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self, WebRelayError> {
        let acceptor = load_tls_acceptor(cert_path, key_path)?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(acceptor)),
        })
    }

    /// Atomically hot-reload certificates from disk without dropping live sessions.
    pub fn reload(&self, cert_path: &Path, key_path: &Path) -> Result<(), WebRelayError> {
        let next = load_tls_acceptor(cert_path, key_path)?;
        self.inner.store(Arc::new(next));
        Ok(())
    }

    #[inline]
    fn load_full(&self) -> Arc<TlsAcceptor> {
        self.inner.load_full()
    }
}

/// Build an [`UpgradedIoExtractor`] for a TLS-wrapped [`PrefixedStream`].
fn tls_upgrade_extractor() -> UpgradedIoExtractor {
    Box::new(|upgraded| {
        let parts = upgraded
            .downcast::<TokioIo<tokio_rustls::server::TlsStream<PrefixedStream>>>()
            .ok()?;
        if !parts.read_buf.is_empty() {
            return None;
        }
        let (r, w) = tokio::io::split(parts.io.into_inner());
        Some((Box::new(r), Box::new(w)))
    })
}

/// Spawn an in-process HTTPS/WSS [`Origin`] listener backed by a hot-reloadable
/// [`ReloadableTlsAcceptor`] (enabling zero-Nginx/Caddy single-port `:443`
/// all-in-one deployment when paired with `[web] integrated = true`!).
pub async fn spawn_tls_origin_server(
    origin: Arc<Origin>,
    bind_addr: &str,
    require_proxy_proto: bool,
    tls_acceptor: ReloadableTlsAcceptor,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), WebRelayError> {
    let listeners = bind_tuned_listeners(bind_addr).await?;
    let local_addr = listeners[0].local_addr()?;

    let handle = tokio::spawn(async move {
        let mut acceptors = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let origin = Arc::clone(&origin);
            let tls_acceptor = tls_acceptor.clone();
            let mut sd = shutdown_rx.clone();
            acceptors.push(tokio::spawn(async move {
                loop {
                    let accept = tokio::select! {
                        _ = sd.changed() => {
                            if *sd.borrow() {
                                break;
                            }
                            continue;
                        }
                        res = listener.accept() => res,
                    };

                    let (stream, raw_peer) = match accept {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!(%e, "web relay TLS accept error");
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            continue;
                        }
                    };
                    let origin = Arc::clone(&origin);
                    let acceptor = tls_acceptor.load_full();

                    tokio::spawn(async move {
                        let (client_peer, prefixed) = if require_proxy_proto {
                            match accept_proxy_protocol(stream, raw_peer).await {
                                Ok(res) => res,
                                Err(_) => return,
                            }
                        } else {
                            (raw_peer, PrefixedStream::new(stream, Bytes::new()))
                        };

                        let Ok(Ok(tls_stream)) = tokio::time::timeout(
                            Duration::from_secs(10),
                            acceptor.accept(prefixed),
                        )
                        .await
                        else {
                            return;
                        };

                        let io = TokioIo::new(tls_stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let origin = Arc::clone(&origin);
                            async move {
                                let resp = origin
                                    .handle_incoming(req, client_peer, tls_upgrade_extractor())
                                    .await;
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });

                        let _ = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .keep_alive(true)
                            .pipeline_flush(true)
                            .header_read_timeout(Duration::from_secs(10))
                            .max_buf_size(64 * 1024)
                            .serve_connection(io, svc)
                            .with_upgrades()
                            .await;
                    });
                }
            }));
        }
        for acc in acceptors {
            let _ = acc.await;
        }
    });

    Ok((local_addr, handle))
}

/// Bind tuned Linux `TcpListener`(s) with zero-syscall child socket inheritance
/// (`TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`,
/// `TCP_FASTOPEN`, best-effort BBR) and multi-acceptor `SO_REUSEPORT` scaling
/// on fixed production ports.
async fn bind_tuned_listeners(bind_addr: &str) -> Result<Vec<TcpListener>, WebRelayError> {
    let sa = resolve_socket_addr(bind_addr).await?;
    let want_reuse_port = sa.port() != 0;
    let count = if want_reuse_port {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .clamp(1, 4)
    } else {
        1
    };

    let cfg = mtg_net::SocketConfig {
        reuse_port: want_reuse_port,
        ..mtg_net::SocketConfig::default()
    };

    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        let sock = mtg_net::create_listener_socket(sa, &cfg)?;
        let std_listener: std::net::TcpListener = sock.into();
        listeners.push(TcpListener::from_std(std_listener)?);
    }
    Ok(listeners)
}

/// Spawn the public HTTP/WebSocket origin listener(s) on `bind_addr`.
pub async fn spawn_origin_server(
    origin: Arc<Origin>,
    bind_addr: &str,
    require_proxy_proto: bool,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), WebRelayError> {
    let listeners = bind_tuned_listeners(bind_addr).await?;
    let local_addr = listeners[0].local_addr()?;

    let handle = tokio::spawn(async move {
        let mut acceptors = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let origin = Arc::clone(&origin);
            let mut sd = shutdown_rx.clone();
            acceptors.push(tokio::spawn(async move {
                loop {
                    let accept = tokio::select! {
                        _ = sd.changed() => {
                            if *sd.borrow() {
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
                            .timer(TokioTimer::new())
                            .keep_alive(true)
                            .pipeline_flush(true)
                            .header_read_timeout(Duration::from_secs(10))
                            .max_buf_size(64 * 1024)
                            .serve_connection(io, svc)
                            .with_upgrades()
                            .await;
                    });
                }
            }));
        }
        for acc in acceptors {
            let _ = acc.await;
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
                let _ = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .keep_alive(true)
                    .header_read_timeout(Duration::from_secs(10))
                    .max_buf_size(32 * 1024)
                    .serve_connection(io, svc)
                    .await;
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
        // Also verify token key file, cover path, and optional TLS cert/key exist and are readable!
        let _ = Signer::load_file(Path::new(&conf.web.token_key))
            .map_err(|e| WebRelayError::Config(e.to_string()))?;
        if !conf.web.cover_dir.is_empty() {
            let _ = StaticCover::new(&conf.web.cover_dir)
                .map_err(|e| WebRelayError::Config(e.to_string()))?;
        } else if !conf.web.cover_upstream.is_empty() {
            let _ = UpstreamCover::new(&conf.web.cover_upstream)
                .map_err(|e| WebRelayError::Config(e.to_string()))?;
        }
        if let (Some(cert), Some(key)) = (&conf.web.tls_cert, &conf.web.tls_key) {
            let _ = ReloadableTlsAcceptor::load(Path::new(cert), Path::new(key))?;
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
        if let Some(cdn) = conf.web.cdn {
            println!(
                "  cdn       {} (header={})",
                cdn.as_str(),
                conf.web
                    .client_ip_header
                    .as_deref()
                    .unwrap_or(cdn.default_client_ip_header())
            );
        } else if conf
            .web
            .trusted_proxies
            .as_ref()
            .is_some_and(|v| !v.is_empty())
            || conf
                .web
                .trusted_proxy_urls
                .as_ref()
                .is_some_and(|v| !v.is_empty())
        {
            println!(
                "  trusted-proxies custom (header={})",
                conf.web
                    .client_ip_header
                    .as_deref()
                    .unwrap_or("x-forwarded-for")
            );
        }
        if let Some(cert) = &conf.web.tls_cert {
            println!("  tls       enabled ({cert})");
        }
        println!("  stats     {}", stats_bind.unwrap_or("(off)"));
        if conf.defense.allowlist.enabled.unwrap_or(false) {
            println!(
                "  allowlist enabled (action={})",
                conf.defense
                    .allowlist
                    .action
                    .unwrap_or(IpFilterAction::Front)
            );
        }
        if conf.defense.blocklist.enabled.unwrap_or(false) {
            println!(
                "  blocklist enabled (action={})",
                conf.defense
                    .blocklist
                    .action
                    .unwrap_or(IpFilterAction::Close)
            );
        }
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
    origin.spawn_ip_filter_refresh_loops(shutdown_rx.clone());
    let require_pp = conf.web.client_ip.unwrap_or_default() == ClientIpSource::ProxyProtocol;

    let tls_acceptor = if let (Some(cert), Some(key)) = (&conf.web.tls_cert, &conf.web.tls_key) {
        Some(ReloadableTlsAcceptor::load(
            Path::new(cert),
            Path::new(key),
        )?)
    } else {
        None
    };

    let (origin_addr, origin_handle) = if let Some(acc) = tls_acceptor.clone() {
        spawn_tls_origin_server(
            Arc::clone(&origin),
            listen,
            require_pp,
            acc,
            shutdown_rx.clone(),
        )
        .await?
    } else {
        spawn_origin_server(Arc::clone(&origin), listen, require_pp, shutdown_rx.clone()).await?
    };
    info!(
        %origin_addr,
        host,
        backend,
        tls = tls_acceptor.is_some(),
        profiles = origin.profiles_len(),
        "web-relay listening"
    );

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
                origin.trigger_ip_filter_refresh();
                if let (Some(acc), Some(cert), Some(key)) =
                    (&tls_acceptor, &initial_web.tls_cert, &initial_web.tls_key)
                {
                    match acc.reload(Path::new(cert), Path::new(key)) {
                        Ok(()) => info!(cert, "reloaded [web] TLS certificate via SIGHUP"),
                        Err(e) => warn!(error = %e, "SIGHUP [web] TLS reload failed; keeping active cert"),
                    }
                }
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
