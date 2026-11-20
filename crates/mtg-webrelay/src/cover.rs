//! Cover-site responders (Tier-3 unauthenticated traffic):
//! - [`StaticCover`]: traversal-safe static directory server with NO directory
//!   listing and NO 301 redirect leak on directories lacking `index.html`.
//! - [`UpstreamCover`]: HTTP/HTTPS reverse proxy forwarding method, path, raw
//!   query, headers, and body verbatim WITHOUT injecting `X-Forwarded-*`
//!   headers, returning `502 Bad Gateway` on upstream failure.

use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Maximum request/response body buffered when proxying to an upstream cover site.
const MAX_COVER_BODY_BYTES: usize = 32 << 20;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Traversal-safe static file cover server with zero directory-listing leaks.
#[derive(Debug)]
pub struct StaticCover {
    root: PathBuf,
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
        Ok(Self { root: canonical })
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
        let root = self.root.clone();
        let is_head = method == Method::HEAD;

        let loaded =
            tokio::task::spawn_blocking(move || -> Option<(&'static str, usize, Vec<u8>)> {
                let meta = std::fs::metadata(&target).ok()?;
                // Never issue a 301 redirect for directories lacking index.html!
                let file_path = if meta.is_dir() {
                    let idx = target.join("index.html");
                    let im = std::fs::metadata(&idx).ok()?;
                    if im.is_file() { idx } else { return None }
                } else if meta.is_file() {
                    target
                } else {
                    return None;
                };

                let canon = std::fs::canonicalize(&file_path).ok()?;
                if !canon.starts_with(&root) {
                    return None;
                }
                let mime = guess_mime(&canon);
                let data = std::fs::read(&canon).ok()?;
                let len = data.len();
                Some((mime, len, if is_head { Vec::new() } else { data }))
            })
            .await;

        let Ok(Some((mime, len, data))) = loaded else {
            return not_found_plain();
        };

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, len)
            .body(Full::new(Bytes::from(data)))
            .expect("valid response")
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

/// Transparent HTTP/HTTPS reverse proxy cover site (no `X-Forwarded-*` headers!).
pub struct UpstreamCover {
    scheme_https: bool,
    host: String,
    port: u16,
    tls: TlsConnector,
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
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if scheme_https { 443 } else { 80 });

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
            tls: TlsConnector::from(Arc::new(cfg)),
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

    async fn proxy_once(&self, req: Request<Bytes>) -> Result<Response<Full<Bytes>>, String> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| e.to_string())?;
        let _ = tcp.set_nodelay(true);

        let pq = req
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let out_uri: Uri = pq
            .parse()
            .map_err(|e: http::uri::InvalidUri| e.to_string())?;

        let mut out_builder = Request::builder().method(req.method()).uri(out_uri);
        for (name, val) in req.headers() {
            if is_hop_by_hop(name) {
                continue;
            }
            out_builder = out_builder.header(name, val);
        }
        if !req.headers().contains_key(header::HOST) {
            out_builder = out_builder.header(header::HOST, &self.host);
        }
        let out_req = out_builder
            .body(Full::new(req.into_body()))
            .map_err(|e| e.to_string())?;

        let upstream_resp = if self.scheme_https {
            let server_name = ServerName::try_from(self.host.clone()).map_err(|e| e.to_string())?;
            let tls_stream = self
                .tls
                .connect(server_name, tcp)
                .await
                .map_err(|e| e.to_string())?;
            send_http1(TokioIo::new(tls_stream), out_req).await?
        } else {
            send_http1(TokioIo::new(tcp), out_req).await?
        };

        let (parts, body) = upstream_resp.into_parts();
        let bytes = http_body_util::Limited::new(body, MAX_COVER_BODY_BYTES)
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();

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

async fn send_http1<IO>(io: IO, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, String>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.map_err(|e| e.to_string())
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
    }
}
