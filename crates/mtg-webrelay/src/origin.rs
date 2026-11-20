//! Three-tier WEB relay HTTP origin (`Origin`) with leak-proof credential
//! recognition, atomic profile+retired hot-reload, strict RFC 6455 upgrade,
//! and trusted client-IP extraction (`proxy-protocol` or loopback `XFF`).
//!
//! Security improvements over Go `internal/webrelay/origin.go`:
//! 1. **Non-short-circuiting Tier-2 scan**: uses bitwise `|` (`registry.is_authentic(atom)
//!    | self.signer.is_authentic(atom)`), fixing Go's accidental `||` short-circuit.
//! 2. **Query-KEY + Query-VALUE scanning**: scans BOTH query keys and values so
//!    `/?<capability>=1` or `/?<capability>` never leaks credentials to the cover site!
//! 3. **Lenient token Tier-2 recognition**: via [`Signer::is_authentic`], padded
//!    or standard-alphabet spellings of bootstrap/session tokens NEVER leak to cover!

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use mtg_config::ClientIpSource;
use mtg_core::Secret;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use crate::capability::{CAPABILITY_LEN, CapabilityError, Registry, canonical_host};
use crate::cover::CoverSite;
use crate::frame::{FrameLimits, MAX_SESSION_CREATE_BODY, WELCOME_WIRE, decode_hello};
use crate::metrics::RelayCounters;
use crate::page::{BridgePage, CARRIER_MODE, PageError};
use crate::session::{
    BackendDialer, DEFAULT_MAX_STREAMS, GlobalBudget, SessionConfig, serve_session,
};
use crate::store::{CreateOutcome, DEFAULT_MAX_SESSIONS, SessionStore};
use crate::token::{Signer, TokenKind};
use crate::ws::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_WRITE_TIMEOUT, WsReader, WsWriter, is_upgrade, validate_upgrade,
};

pub const SESSION_PATH: &str = "/api/v1/session";
pub const CARRIER_PATH: &str = "/api/v1/ws";
pub const BRIDGE_QUERY: &str = "bridge";
pub const SUBPROTOCOL_PREFIX: &str = "tproxy-v1.";
const MAX_CREDENTIAL_ATOMS: usize = 64;

#[derive(Debug, Error)]
pub enum OriginError {
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    #[error(transparent)]
    Page(#[from] PageError),
    #[error("invalid frame limits: {0}")]
    Limits(String),
}

/// Configuration constructing one [`Origin`].
#[derive(Debug)]
pub struct OriginOptions {
    pub host: String,
    pub secrets: Vec<Secret>,
    pub retired: Vec<Secret>,
    pub signer: Signer,
    pub cover: CoverSite,
    pub backend: Arc<dyn BackendDialer>,
    pub limits: FrameLimits,
    pub max_sessions: usize,
    pub max_streams: usize,
    pub client_ip_source: ClientIpSource,
    pub counters: Option<Arc<RelayCounters>>,
}

/// Public HTTP/WebSocket origin serving Tier-1 (carrier), Tier-2 (local
/// uncacheable 404 on any authentic-but-unusable credential), and Tier-3
/// (cover site verbatim).
#[derive(Debug)]
pub struct Origin {
    host: String,
    registry: ArcSwap<Registry>,
    signer: Signer,
    bridge: BridgePage,
    cover: CoverSite,
    store: Arc<SessionStore>,
    backend: Arc<dyn BackendDialer>,
    limits: FrameLimits,
    max_streams: usize,
    client_ip_source: ClientIpSource,
    counters: Option<Arc<RelayCounters>>,
    global_budget: Arc<GlobalBudget>,
}

/// Type-erased upgraded WebSocket stream extractor (lets `Origin::handle` check
/// `read_buf.is_empty()` for zero pipelined bytes cleanly across TCP & test streams).
pub type UpgradedIoExtractor = Box<
    dyn FnOnce(
            hyper::upgrade::Upgraded,
        ) -> Option<(
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        )> + Send,
>;

impl Origin {
    pub fn new(opts: OriginOptions) -> Result<Self, OriginError> {
        let host = canonical_host(&opts.host)?;
        opts.limits
            .validate()
            .map_err(|e| OriginError::Limits(e.to_string()))?;
        let registry = Registry::new(&host, &opts.secrets, &opts.retired)?;
        let bridge = BridgePage::new(&host)?;
        let max_sessions = if opts.max_sessions == 0 {
            DEFAULT_MAX_SESSIONS
        } else {
            opts.max_sessions
        };
        let max_streams = if opts.max_streams == 0 {
            DEFAULT_MAX_STREAMS
        } else {
            opts.max_streams
        };

        Ok(Self {
            host,
            registry: ArcSwap::from_pointee(registry),
            signer: opts.signer,
            bridge,
            cover: opts.cover,
            store: Arc::new(SessionStore::new(max_sessions)),
            backend: opts.backend,
            limits: opts.limits,
            max_streams,
            client_ip_source: opts.client_ip_source,
            counters: opts.counters,
            global_budget: Arc::new(GlobalBudget::default()),
        })
    }

    /// Atomically swap `(secrets, retired)` on live reload (preserving previous
    /// live + retired sets untouched if the new set is invalid!).
    pub fn set_secrets_with_retired(
        &self,
        secrets: &[Secret],
        retired: &[Secret],
    ) -> Result<(), CapabilityError> {
        let next = Registry::new(&self.host, secrets, retired)?;
        self.registry.store(Arc::new(next));
        Ok(())
    }

    pub fn profiles_len(&self) -> usize {
        self.registry.load().len()
    }

    pub fn store(&self) -> &Arc<SessionStore> {
        &self.store
    }

    pub fn counters(&self) -> Option<&Arc<RelayCounters>> {
        self.counters.as_ref()
    }

    /// Handle one incoming HTTP/1.1 request over a live socket (`peer_addr` is
    /// already resolved from PROXY protocol when `client-ip = "proxy-protocol"`).
    pub async fn handle_incoming(
        self: &Arc<Self>,
        mut req: Request<Incoming>,
        peer_addr: SocketAddr,
        extractor: UpgradedIoExtractor,
    ) -> Response<Full<Bytes>> {
        // ONE atomic snapshot for the ENTIRE request (Tier-1 + Tier-2)!
        let registry = self.registry.load();

        let method = req.method().clone();
        let path = req.uri().path().to_owned();

        // Tier-1: Exact authentic & usable carrier routes.
        let tier1 = match (method.clone(), path.as_str()) {
            (Method::GET, "/") => self.try_serve_bridge(&req, &registry),
            (Method::POST, SESSION_PATH) => self.try_serve_session_create(&mut req).await,
            (Method::DELETE, SESSION_PATH) => self.try_serve_session_delete(&req),
            (_, CARRIER_PATH) => self.try_serve_websocket(&mut req, peer_addr, extractor),
            _ => None,
        };
        if let Some(resp) = tier1 {
            return resp;
        }

        // Tier-2: Any authentic credential anywhere in query keys/values, path,
        // or headers -> local uncacheable 404, NEVER forwarded to cover!
        if self.recognises(
            req.uri().path(),
            req.uri().query().unwrap_or(""),
            req.headers(),
            &registry,
        ) {
            return self.not_found();
        }

        // Tier-3: Unauthenticated traffic -> cover site verbatim.
        if let Some(c) = &self.counters {
            c.on_cover_served();
        }
        self.cover.serve_incoming(req).await
    }

    /// Direct non-Hyper request handler for unit tests & synthetic requests.
    pub async fn handle_bytes(&self, req: Request<Bytes>) -> Response<Full<Bytes>> {
        let registry = self.registry.load();

        let tier1 = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => self.try_serve_bridge(&req, &registry),
            (&Method::POST, SESSION_PATH) => self.try_serve_session_create_bytes(&req),
            (&Method::DELETE, SESSION_PATH) => self.try_serve_session_delete(&req),
            _ => None,
        };
        if let Some(resp) = tier1 {
            return resp;
        }

        if self.recognises(
            req.uri().path(),
            req.uri().query().unwrap_or(""),
            req.headers(),
            &registry,
        ) {
            return self.not_found();
        }

        if let Some(c) = &self.counters {
            c.on_cover_served();
        }
        self.cover.serve_bytes(req).await
    }

    fn try_serve_bridge<B>(
        &self,
        req: &Request<B>,
        registry: &Registry,
    ) -> Option<Response<Full<Bytes>>> {
        let raw_q = req.uri().query()?;
        // Exact match: ONE query field named `bridge`, canonical spelling.
        let mut pairs = url::form_urlencoded::parse(raw_q.as_bytes());
        let (k, v) = pairs.next()?;
        if k != BRIDGE_QUERY || pairs.next().is_some() {
            return None;
        }
        let profile = registry.lookup(&v)?;

        let Ok(token) = self.signer.mint(TokenKind::Bootstrap) else {
            return Some(self.not_found());
        };
        let Ok(doc) = self.bridge.render(&token) else {
            return Some(self.not_found());
        };
        self.store.issue_bootstrap(token, profile);

        let mut builder = Response::builder().status(StatusCode::OK);
        for (name, val) in doc.headers {
            builder = builder.header(name, val);
        }
        Some(
            builder
                .body(Full::new(Bytes::from(doc.html)))
                .expect("valid bridge response"),
        )
    }

    async fn try_serve_session_create(
        &self,
        req: &mut Request<Incoming>,
    ) -> Option<Response<Full<Bytes>>> {
        let token = extract_bearer(req.headers())?.to_owned();
        if !self.signer.verify(&token, TokenKind::Bootstrap) {
            return None;
        }
        // Credential is authentic -> every remaining outcome is ours, NEVER cover!
        if has_cookies(req.headers()) {
            return Some(self.not_found());
        }

        let limited = http_body_util::Limited::new(req.body_mut(), MAX_SESSION_CREATE_BODY);
        let Ok(collected) = limited.collect().await else {
            return Some(self.not_found());
        };
        let body = collected.to_bytes();
        Some(self.finish_session_create(&token, &body))
    }

    fn try_serve_session_create_bytes(
        &self,
        req: &Request<Bytes>,
    ) -> Option<Response<Full<Bytes>>> {
        let token = extract_bearer(req.headers())?;
        if !self.signer.verify(token, TokenKind::Bootstrap) {
            return None;
        }
        if has_cookies(req.headers()) {
            return Some(self.not_found());
        }
        if req.body().len() > MAX_SESSION_CREATE_BODY {
            return Some(self.not_found());
        }
        Some(self.finish_session_create(token, req.body()))
    }

    fn finish_session_create(&self, bootstrap_token: &str, body: &[u8]) -> Response<Full<Bytes>> {
        if decode_hello(body).is_err() {
            return self.not_found();
        }
        match self.store.create_session(bootstrap_token, body, || {
            self.signer.mint(TokenKind::Session)
        }) {
            CreateOutcome::Admitted(session_tok) => {
                if let Some(c) = &self.counters {
                    c.on_session_created();
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .header("x-session-token", session_tok)
                    .header("x-down-cursor", "0")
                    .header("x-carrier-mode", CARRIER_MODE)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CACHE_CONTROL, "no-store")
                    .header(header::CONTENT_LENGTH, WELCOME_WIRE.len())
                    .body(Full::new(Bytes::copy_from_slice(&WELCOME_WIRE)))
                    .expect("valid response")
            }
            CreateOutcome::AtCapacity => {
                if let Some(c) = &self.counters {
                    c.on_session_limit();
                }
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header(header::RETRY_AFTER, "1")
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(Full::new(Bytes::new()))
                    .expect("valid response")
            }
            CreateOutcome::Refused => self.not_found(),
        }
    }

    fn try_serve_session_delete<B>(&self, req: &Request<B>) -> Option<Response<Full<Bytes>>> {
        let token = extract_bearer(req.headers())?;
        if !self.signer.verify(token, TokenKind::Session) {
            return None;
        }
        if has_cookies(req.headers()) {
            return Some(self.not_found());
        }
        if !self.store.remove(token) {
            if let Some(c) = &self.counters {
                c.on_bad_token();
            }
            return Some(self.not_found());
        }
        Some(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Full::new(Bytes::new()))
                .expect("valid response"),
        )
    }

    fn try_serve_websocket(
        self: &Arc<Self>,
        req: &mut Request<Incoming>,
        peer_addr: SocketAddr,
        extractor: UpgradedIoExtractor,
    ) -> Option<Response<Full<Bytes>>> {
        // Must have exact single `Sec-WebSocket-Protocol: tproxy-v1.<session_token>`.
        let mut proto_vals = req.headers().get_all("sec-websocket-protocol").iter();
        let offered = proto_vals.next()?.to_str().ok()?.trim().to_owned();
        if proto_vals.next().is_some() {
            return None;
        }
        let token = offered.strip_prefix(SUBPROTOCOL_PREFIX)?.to_owned();
        if !self.signer.verify(&token, TokenKind::Session) {
            return None;
        }

        // Authentic session token -> every refusal from here is local 404!
        // Note: Cookies are deliberately NOT refused on WebSocket upgrades!
        if !is_upgrade(req.method(), req.headers()) {
            return Some(self.not_found());
        }
        let Ok(accept) =
            validate_upgrade(req.method(), req.version(), req.headers(), Some(&offered))
        else {
            return Some(self.not_found());
        };
        let Some(client_addr) = self.resolve_client_addr(req.headers(), peer_addr) else {
            return Some(self.not_found());
        };
        let Some((profile, cancel_rx)) = self.store.attach(&token) else {
            if let Some(c) = &self.counters {
                c.on_bad_token();
            }
            return Some(self.not_found());
        };

        let on_upgrade = hyper::upgrade::on(req);
        let origin = Arc::clone(self);
        let tok_clone = token.clone();

        tokio::spawn(async move {
            let detach_guard = DetachGuard {
                store: Arc::clone(&origin.store),
                token: tok_clone,
            };

            let Ok(upgraded) = on_upgrade.await else {
                drop(detach_guard);
                return;
            };
            let Some((read_io, write_io)) = extractor(upgraded) else {
                // Pipelined bytes before 101 was processed -> refuse & close!
                warn!(profile, %client_addr, "rejected WebSocket with pipelined data");
                drop(detach_guard);
                return;
            };

            if let Some(c) = &origin.counters {
                c.on_session_attached();
            }
            debug!(profile, %client_addr, "web relay carrier attached");

            let cfg = SessionConfig {
                backend: Arc::clone(&origin.backend),
                limits: origin.limits,
                global_budget: Arc::clone(&origin.global_budget),
                client_addr,
                max_streams: origin.max_streams,
                idle_timeout: DEFAULT_IDLE_TIMEOUT,
                counters: origin.counters.clone(),
            };

            let ws_reader = WsReader::new(read_io, origin.limits.effective_batch_bytes());
            let ws_writer = WsWriter::new(write_io, DEFAULT_WRITE_TIMEOUT);

            if let Err(err) = serve_session(ws_reader, ws_writer, cfg, cancel_rx).await {
                debug!(profile, %client_addr, %err, "web relay session ended");
            }
            drop(detach_guard);
        });

        Some(
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .version(Version::HTTP_11)
                .header(header::UPGRADE, "websocket")
                .header(header::CONNECTION, "Upgrade")
                .header("sec-websocket-accept", accept)
                .header("sec-websocket-protocol", offered)
                .body(Full::new(Bytes::new()))
                .expect("valid 101 response"),
        )
    }

    fn resolve_client_addr(
        &self,
        headers: &HeaderMap,
        peer_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        match self.client_ip_source {
            ClientIpSource::ProxyProtocol => Some(peer_addr),
            ClientIpSource::XForwardedFor => {
                // ONLY trust X-Forwarded-For from a loopback front proxy!
                if !peer_addr.ip().is_loopback() {
                    return None;
                }
                // Rightmost valid IP in X-Forwarded-For (set by the trusted front proxy).
                let mut rightmost: Option<IpAddr> = None;
                for val in headers.get_all("x-forwarded-for") {
                    let Ok(s) = val.to_str() else {
                        continue;
                    };
                    for part in s.split(',') {
                        let trimmed = part.trim();
                        if let Ok(ip) = trimmed.parse::<IpAddr>() {
                            rightmost = Some(ip);
                        } else if let Ok(sa) = trimmed.parse::<SocketAddr>() {
                            rightmost = Some(sa.ip());
                        }
                    }
                }
                rightmost.map(|ip| SocketAddr::new(ip, 0))
            }
        }
    }

    /// Tier-2 recognition scan: checks EVERY base64-shaped 43/44-char atom in
    /// query KEYS and VALUES, URL path, and ALL header values against BOTH
    /// `registry.is_authentic` AND `signer.is_authentic` WITHOUT short-circuiting!
    pub fn recognises(
        &self,
        path: &str,
        raw_query: &str,
        headers: &HeaderMap,
        registry: &Registry,
    ) -> bool {
        let mut found = false;
        let mut atoms_seen = 0usize;

        let mut visit = |s: &str| {
            for atom in credential_atoms(s) {
                atoms_seen += 1;
                if atoms_seen > MAX_CREDENTIAL_ATOMS {
                    return;
                }
                // Bitwise `|` — NEVER short-circuits!
                let authentic = registry.is_authentic(atom) | self.signer.is_authentic(atom);
                found |= authentic;
            }
        };

        // Scan BOTH query keys and values (raw + percent-decoded)!
        for pair in raw_query.split(['&', ';']) {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (pair, None),
            };
            visit(k);
            if let Some(dec_k) = percent_decode_utf8(k) {
                visit(&dec_k);
            }
            if let Some(val) = v {
                visit(val);
                if let Some(dec_v) = percent_decode_utf8(val) {
                    visit(&dec_v);
                }
            }
        }

        // Scan URL path (raw + percent-decoded).
        visit(path);
        if let Some(dec_p) = percent_decode_utf8(path) {
            visit(&dec_p);
        }

        // Scan ALL header values.
        for val in headers.values() {
            if let Ok(s) = val.to_str() {
                visit(s);
            }
        }

        found
    }

    fn not_found(&self) -> Response<Full<Bytes>> {
        if let Some(c) = &self.counters {
            c.on_not_found();
        }
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CONTENT_LENGTH, 19)
            .body(Full::new(Bytes::from_static(b"404 page not found\n")))
            .expect("valid 404")
    }
}

struct DetachGuard {
    store: Arc<SessionStore>,
    token: String,
}

impl Drop for DetachGuard {
    fn drop(&mut self) {
        self.store.detach(&self.token);
    }
}

/// Extract an exact single `Authorization: Bearer <token>` value.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let mut vals = headers.get_all(header::AUTHORIZATION).iter();
    let first = vals.next()?.to_str().ok()?;
    if vals.next().is_some() {
        return None;
    }
    first.strip_prefix("Bearer ").map(str::trim)
}

#[inline]
fn has_cookies(headers: &HeaderMap) -> bool {
    headers.contains_key(header::COOKIE)
}

/// Extract all 43- or 44-char base64-alphabet substrings from `value`.
fn credential_atoms(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=')))
        .filter(|atom| atom.len() == CAPABILITY_LEN || atom.len() == CAPABILITY_LEN + 1)
}

fn percent_decode_utf8(input: &str) -> Option<String> {
    if !input.as_bytes().contains(&b'%') {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

#[inline]
const fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Keep unused imports warning-free (`Duration`, `HeaderName`, `HeaderValue` re-exported/used in tests).
#[allow(dead_code)]
fn _keep_types(_: Duration, _: HeaderName, _: HeaderValue) {}
