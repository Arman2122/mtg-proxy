//! Cover-site responders (Tier-3 unauthenticated traffic):
//! - [`StaticCover`]: traversal-safe static directory server with NO directory
//!   listing, NO 301 redirect leak on directories lacking `index.html`, and a
//!   bounded 16 MiB in-memory cache with 5-second mtime revalidation (zero disk
//!   syscalls on hot hits!).
//! - [`UpstreamCover`]: HTTP/HTTPS reverse proxy using RFC 8305 Happy Eyeballs
//!   and a warm HTTP/1.1 keep-alive connection pool, forwarding method, path,
//!   raw query, headers, and body verbatim WITHOUT injecting `X-Forwarded-*`
//!   headers, returning `502 Bad Gateway` on upstream failure.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{self, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use mtg_net::{SocketConfig, coarse_now_ns, happy_eyeballs_connect};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use url::Url;

/// Maximum request/response body buffered when proxying to an upstream cover site.
const MAX_COVER_BODY_BYTES: usize = 32 << 20;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum total bytes cached in memory by [`StaticCover`] (`16 MiB`).
const STATIC_CACHE_MAX_BYTES: usize = 16 << 20;
/// Maximum size of any single file cached by [`StaticCover`] (`2 MiB`).
const STATIC_CACHE_MAX_FILE_BYTES: usize = 2 << 20;
/// Revalidation interval for cached static cover files (`5s`).
const STATIC_CACHE_REVALIDATE_NS: u64 = 5_000_000_000;
/// Maximum warm HTTP/1.1 keep-alive connections kept by [`UpstreamCover`].
const UPSTREAM_POOL_MAX_IDLE: usize = 8;
/// Maximum idle age for a pooled upstream HTTP/1.1 connection (`30s`).
const UPSTREAM_POOL_MAX_AGE_NS: u64 = 30_000_000_000;

#[derive(Debug, Error)]
pub enum CoverError {
    #[error("cannot serve cover site from {path:?}: {source}")]
    StaticIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cover site root {0:?} is not a directory")]
    NotADirectory(PathBuf),
    #[error("invalid cover upstream URL {0:?}: {1}")]
    InvalidUpstream(String, String),
}

/// Pluggable Tier-3 cover handler (used by production cover modes & unit tests).
pub trait CoverHandler: Send + Sync + std::fmt::Debug {
    fn serve(
        &self,
        req: Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send + '_>>;
}

/// Configured cover-site backend.
#[derive(Debug, Clone)]
pub enum CoverSite {
    Static(Arc<StaticCover>),
    Upstream(Arc<UpstreamCover>),
    Custom(Arc<dyn CoverHandler>),
}

impl CoverSite {
    pub async fn serve_incoming(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();
        let bytes = match http_body_util::Limited::new(body, MAX_COVER_BODY_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::new()))
                    .expect("valid response");
            }
        };
        let req = Request::from_parts(parts, bytes);
        self.serve_bytes(req).await
    }

    pub async fn serve_bytes(&self, req: Request<Bytes>) -> Response<Full<Bytes>> {
        match self {
            Self::Static(s) => s.serve(&req).await,
            Self::Upstream(u) => u.serve(req).await,
            Self::Custom(c) => c.serve(req).await,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedStaticFile {
    mime: &'static str,
    bytes: Bytes,
    mtime: Option<SystemTime>,
    checked_ns: u64,
}

#[derive(Debug, Default)]
struct StaticCache {
    entries: FxHashMap<PathBuf, CachedStaticFile>,
    order: VecDeque<PathBuf>,
    total_bytes: usize,
}

impl StaticCache {
    fn insert(&mut self, key: PathBuf, entry: CachedStaticFile) {
        let new_len = entry.bytes.len();
        if new_len > STATIC_CACHE_MAX_FILE_BYTES {
            return;
        }
        if let Some(old) = self.entries.insert(key.clone(), entry) {
            self.total_bytes = self.total_bytes.saturating_sub(old.bytes.len());
        } else {
            self.order.push_back(key);
        }
        self.total_bytes += new_len;

        while self.total_bytes > STATIC_CACHE_MAX_BYTES {
            let Some(evict_key) = self.order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&evict_key) {
                self.total_bytes = self.total_bytes.saturating_sub(evicted.bytes.len());
            }
        }
    }

    fn remove(&mut self, key: &Path) {
        if let Some(old) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(old.bytes.len());
        }
    }
}

enum StaticDiskOutcome {
    NotFound,
    Unchanged,
    Loaded {
        mime: &'static str,
        bytes: Bytes,
        mtime: Option<SystemTime>,
    },
}

/// Traversal-safe static file cover server with zero directory-listing leaks
/// and a bounded 16 MiB in-memory cache with 5-second mtime revalidation.
#[derive(Debug)]
pub struct StaticCover {
    root: PathBuf,
    cache: Mutex<StaticCache>,
}

impl StaticCover {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CoverError> {
        let path = root.as_ref();
        let meta = std::fs::metadata(path).map_err(|source| CoverError::StaticIo {
            path: path.to_path_buf(),
            source,
        })?;
        if !meta.is_dir() {
            return Err(CoverError::NotADirectory(path.to_path_buf()));
        }
        let canonical = std::fs::canonicalize(path).map_err(|source| CoverError::StaticIo {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root: canonical,
            cache: Mutex::new(StaticCache::default()),
        })
    }

    pub async fn serve(&self, req: &Request<Bytes>) -> Response<Full<Bytes>> {
        let method = req.method();
        if method != Method::GET && method != Method::HEAD {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, "GET, HEAD")
                .body(Full::new(Bytes::new()))
                .expect("valid response");
        }

        let Some(target) = self.resolve_path(req.uri().path()) else {
            return not_found_plain();
        };
        let is_head = method == Method::HEAD;
        let now_ns = coarse_now_ns();

        // Fast path: fresh in-memory cache hit -> 0 disk syscalls, 0 spawn_blocking!
        let cached_entry = {
            let cache = self.cache.lock();
            cache.entries.get(&target).cloned()
        };
        if let Some(ref entry) = cached_entry
            && now_ns.saturating_sub(entry.checked_ns) < STATIC_CACHE_REVALIDATE_NS
        {
            return build_static_response(entry.mime, &entry.bytes, is_head);
        }

        let root = self.root.clone();
        let target_clone = target.clone();
        let prev_meta = cached_entry.as_ref().map(|e| (e.mtime, e.bytes.len()));

        let loaded = tokio::task::spawn_blocking(move || -> StaticDiskOutcome {
            let Ok(meta) = std::fs::metadata(&target_clone) else {
                return StaticDiskOutcome::NotFound;
            };
            // Never issue a 301 redirect for directories lacking index.html!
            let (file_path, file_meta) = if meta.is_dir() {
                let idx = target_clone.join("index.html");
                let Ok(im) = std::fs::metadata(&idx) else {
                    return StaticDiskOutcome::NotFound;
                };
                if im.is_file() {
                    (idx, im)
                } else {
                    return StaticDiskOutcome::NotFound;
                }
            } else if meta.is_file() {
                (target_clone, meta)
            } else {
                return StaticDiskOutcome::NotFound;
            };

            let Ok(canon) = std::fs::canonicalize(&file_path) else {
                return StaticDiskOutcome::NotFound;
            };
            if !canon.starts_with(&root) {
                return StaticDiskOutcome::NotFound;
            }

            let mtime = file_meta.modified().ok();
            let file_len = file_meta.len() as usize;
            if let Some((prev_mtime, prev_len)) = prev_meta
                && mtime.is_some()
                && mtime == prev_mtime
                && file_len == prev_len
            {
                return StaticDiskOutcome::Unchanged;
            }

            let mime = guess_mime(&canon);
            let Ok(data) = std::fs::read(&canon) else {
                return StaticDiskOutcome::NotFound;
            };
            StaticDiskOutcome::Loaded {
                mime,
                bytes: Bytes::from(data),
                mtime,
            }
        })
        .await;

        match loaded {
            Ok(StaticDiskOutcome::Unchanged) => {
                if let Some(mut entry) = cached_entry {
                    entry.checked_ns = now_ns;
                    let resp = build_static_response(entry.mime, &entry.bytes, is_head);
                    self.cache.lock().insert(target, entry);
                    return resp;
                }
                not_found_plain()
            }
            Ok(StaticDiskOutcome::Loaded { mime, bytes, mtime }) => {
                let resp = build_static_response(mime, &bytes, is_head);
                if bytes.len() <= STATIC_CACHE_MAX_FILE_BYTES {
                    self.cache.lock().insert(
                        target,
                        CachedStaticFile {
                            mime,
                            bytes,
                            mtime,
                            checked_ns: now_ns,
                        },
                    );
                }
                resp
            }
            Ok(StaticDiskOutcome::NotFound) | Err(_) => {
                self.cache.lock().remove(&target);
                not_found_plain()
            }
        }
    }

    fn resolve_path(&self, raw_path: &str) -> Option<PathBuf> {
        let trimmed = raw_path.trim_start_matches('/');
        if trimmed.contains('\0') {
            return None;
        }
        let mut rel = PathBuf::new();
        for comp in Path::new(trimmed).components() {
            match comp {
                Component::Normal(seg) => rel.push(seg),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        Some(self.root.join(rel))
    }
}

fn build_static_response(
    mime: &'static str,
    bytes: &Bytes,
    is_head: bool,
) -> Response<Full<Bytes>> {
    let body = if is_head { Bytes::new() } else { bytes.clone() };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(Full::new(body))
        .expect("valid response")
}

struct PooledUpstream {
    sender: SendRequest<Full<Bytes>>,
    last_used_ns: u64,
}

/// Transparent HTTP/HTTPS reverse proxy cover site with Happy Eyeballs dialing
/// and a warm HTTP/1.1 keep-alive connection pool (no `X-Forwarded-*` headers!).
pub struct UpstreamCover {
    scheme_https: bool,
    host: String,
    port: u16,
    authority: String,
    is_loopback: bool,
    tls: TlsConnector,
    pool: Mutex<VecDeque<PooledUpstream>>,
}

impl std::fmt::Debug for UpstreamCover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamCover")
            .field("scheme_https", &self.scheme_https)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl UpstreamCover {
    pub fn new(target: &str) -> Result<Self, CoverError> {
        let parsed = Url::parse(target)
            .map_err(|e| CoverError::InvalidUpstream(target.to_owned(), e.to_string()))?;
        let scheme_https = match parsed.scheme() {
            "http" => false,
            "https" => true,
            other => {
                return Err(CoverError::InvalidUpstream(
                    target.to_owned(),
                    format!("must be http or https, got {other:?}"),
                ));
            }
        };
        let host = parsed
            .host_str()
            .ok_or_else(|| {
                CoverError::InvalidUpstream(target.to_owned(), "missing host".to_owned())
            })?
            .to_owned();
        let default_port = if scheme_https { 443 } else { 80 };
        let port = parsed.port_or_known_default().unwrap_or(default_port);
        let authority = if port == default_port {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let is_loopback = bare_host.eq_ignore_ascii_case("localhost")
            || bare_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("rustls default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        Ok(Self {
            scheme_https,
            host,
            port,
            authority,
            is_loopback,
            tls: TlsConnector::from(Arc::new(cfg)),
            pool: Mutex::new(VecDeque::new()),
        })
    }

    pub async fn serve(&self, req: Request<Bytes>) -> Response<Full<Bytes>> {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, self.proxy_once(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) | Err(_) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from_static(b"502 Bad Gateway\n")))
                .expect("valid response"),
        }
    }

    fn take_pooled(&self) -> Option<SendRequest<Full<Bytes>>> {
        let now_ns = coarse_now_ns();
        let mut pool = self.pool.lock();
        // LIFO: prefer freshest keep-alive connection.
        while let Some(entry) = pool.pop_back() {
            if now_ns.saturating_sub(entry.last_used_ns) > UPSTREAM_POOL_MAX_AGE_NS {
                continue;
            }
            if entry.sender.is_ready() {
                return Some(entry.sender);
            }
        }
        None
    }

    fn return_pooled(&self, sender: SendRequest<Full<Bytes>>) {
        if !sender.is_ready() {
            return;
        }
        let mut pool = self.pool.lock();
        while pool.len() >= UPSTREAM_POOL_MAX_IDLE {
            pool.pop_front();
        }
        pool.push_back(PooledUpstream {
            sender,
            last_used_ns: coarse_now_ns(),
        });
    }

    async fn dial_sender(&self) -> Result<SendRequest<Full<Bytes>>, String> {
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<SocketAddr> = if let Ok(ip) = bare.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, self.port)]
        } else {
            tokio::net::lookup_host((bare, self.port))
                .await
                .map_err(|e| e.to_string())?
                .collect()
        };
        let sock_cfg = SocketConfig::default();
        let (tcp, _) = happy_eyeballs_connect(&addrs, &sock_cfg, UPSTREAM_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;

        if self.scheme_https {
            let server_name = ServerName::try_from(bare.to_owned()).map_err(|e| e.to_string())?;
            let tls_stream = self
                .tls
                .connect(server_name, tcp)
                .await
                .map_err(|e| e.to_string())?;
            handshake_http1(TokioIo::new(tls_stream)).await
        } else {
            handshake_http1(TokioIo::new(tcp)).await
        }
    }

    fn build_outbound_request(
        &self,
        method: &Method,
        out_uri: &Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<Request<Full<Bytes>>, String> {
        let mut out_builder = Request::builder().method(method).uri(out_uri.clone());
        let mut saw_host = false;
        for (name, val) in headers {
            if is_hop_by_hop(name) {
                continue;
            }
            if name == header::HOST {
                saw_host = true;
                if !self.is_loopback {
                    // Rewrite Host to upstream cover authority so real CDNs
                    // (Cloudflare, Google, nginx) return 200 instead of 400/404!
                    out_builder = out_builder.header(header::HOST, &self.authority);
                    continue;
                }
            }
            out_builder = out_builder.header(name, val);
        }
        if !saw_host {
            out_builder = out_builder.header(header::HOST, &self.authority);
        }
        out_builder.body(Full::new(body)).map_err(|e| e.to_string())
    }

    async fn proxy_once(&self, req: Request<Bytes>) -> Result<Response<Full<Bytes>>, String> {
        let pq = req
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let out_uri: Uri = pq
            .parse()
            .map_err(|e: http::uri::InvalidUri| e.to_string())?;
        let (req_parts, req_body) = req.into_parts();

        // Try a warm keep-alive connection first; on stale-socket error transparently retry once!
        let (mut sender, upstream_resp) = if let Some(mut pooled) = self.take_pooled() {
            let first_req = self.build_outbound_request(
                &req_parts.method,
                &out_uri,
                &req_parts.headers,
                req_body.clone(),
            )?;
            if let Ok(resp) = pooled.send_request(first_req).await {
                (pooled, resp)
            } else {
                let mut fresh = self.dial_sender().await?;
                let retry_req = self.build_outbound_request(
                    &req_parts.method,
                    &out_uri,
                    &req_parts.headers,
                    req_body,
                )?;
                let resp = fresh
                    .send_request(retry_req)
                    .await
                    .map_err(|e| e.to_string())?;
                (fresh, resp)
            }
        } else {
            let mut fresh = self.dial_sender().await?;
            let out_req = self.build_outbound_request(
                &req_parts.method,
                &out_uri,
                &req_parts.headers,
                req_body,
            )?;
            let resp = fresh
                .send_request(out_req)
                .await
                .map_err(|e| e.to_string())?;
            (fresh, resp)
        };

        let (parts, body) = upstream_resp.into_parts();
        let peer_closes = parts
            .headers
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("close"));
        let bytes = http_body_util::Limited::new(body, MAX_COVER_BODY_BYTES)
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();

        if !peer_closes {
            // Poll once for readiness or return directly if ready for keep-alive reuse.
            let _ = sender.ready().await;
            self.return_pooled(sender);
        }

        let mut resp_builder = Response::builder().status(parts.status);
        for (name, val) in &parts.headers {
            if is_hop_by_hop(name) || name == header::CONTENT_LENGTH {
                continue;
            }
            resp_builder = resp_builder.header(name, val);
        }
        resp_builder = resp_builder.header(header::CONTENT_LENGTH, bytes.len());
        resp_builder
            .body(Full::new(bytes))
            .map_err(|e| e.to_string())
    }
}

async fn handshake_http1<IO>(io: IO) -> Result<SendRequest<Full<Bytes>>, String>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn not_found_plain() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"404 page not found\n")))
        .expect("valid response")
}

fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_cover_serves_index_and_blocks_dir_leak_and_traversal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<h1>hello</h1>").unwrap();
        std::fs::create_dir(dir.path().join("secret_dir")).unwrap();
        std::fs::write(dir.path().join("secret_dir/file.txt"), b"ok").unwrap();

        let cover = StaticCover::new(dir.path()).unwrap();

        let r_root = Request::builder().uri("/").body(Bytes::new()).unwrap();
        let resp = cover.serve(&r_root).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.into_body().collect().await.unwrap().to_bytes(),
            &b"<h1>hello</h1>"[..]
        );

        // Directory without index.html MUST return 404 directly (NO 301 redirect leak!)
        let r_dir = Request::builder()
            .uri("/secret_dir")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(cover.serve(&r_dir).await.status(), StatusCode::NOT_FOUND);
        let r_dir2 = Request::builder()
            .uri("/secret_dir/")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(cover.serve(&r_dir2).await.status(), StatusCode::NOT_FOUND);

        // Path traversal rejected
        let r_trav = Request::builder()
            .uri("/../etc/passwd")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(cover.serve(&r_trav).await.status(), StatusCode::NOT_FOUND);

        // Hot cache hit + HEAD response preserves exact Content-Length with empty body
        let r_head = Request::builder()
            .method(Method::HEAD)
            .uri("/")
            .body(Bytes::new())
            .unwrap();
        let head_resp = cover.serve(&r_head).await;
        assert_eq!(head_resp.status(), StatusCode::OK);
        assert_eq!(
            head_resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            "14"
        );
        assert!(
            head_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn upstream_cover_reuses_keepalive_pool_without_x_forwarded_headers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = Arc::clone(&accepts);

        let srv = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accepts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        assert!(!req.headers().contains_key("x-forwarded-for"));
                        assert!(!req.headers().contains_key("x-forwarded-host"));
                        let body = format!("ok:{}", req.uri());
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        let cover = UpstreamCover::new(&format!("http://{addr}")).unwrap();
        for i in 0..5 {
            let req = Request::builder()
                .uri(format!("/item?n={i}"))
                .body(Bytes::new())
                .unwrap();
            let resp = cover.serve(req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, format!("ok:/item?n={i}").as_bytes());
        }

        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "UpstreamCover keep-alive pool must reuse 1 TCP connection across sequential requests!"
        );
        srv.abort();
    }
}
