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
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use mtg_config::{ClientIpSource, IpFilterAction};
use mtg_core::Secret;
use mtg_governance::LiveIpFilter;
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

/// Optional wait-free Geo-Stealth IP allowlist/blocklist and CDN trusted-proxy
/// configuration attached to [`Origin`].
#[derive(Debug, Clone)]
pub struct OriginIpFilters {
    pub allowlist: Option<Arc<LiveIpFilter>>,
    pub allowlist_action: IpFilterAction,
    pub blocklist: Option<Arc<LiveIpFilter>>,
    pub blocklist_action: IpFilterAction,
    /// Trusted CDN / reverse-proxy IP ranges (e.g. Cloudflare / ArvanCloud / Nginx).
    /// Peeled right-to-left from `X-Forwarded-For` and required before trusting
    /// `client_ip_header` (100% immune to direct client header spoofing!).
    pub trusted_proxies: Option<Arc<LiveIpFilter>>,
    /// Authoritative real-client-IP header stamped by a verified CDN hop
    /// (e.g. `"cf-connecting-ip"`, `"ar-real-ip"`).
    pub client_ip_header: Option<String>,
}

impl Default for OriginIpFilters {
    fn default() -> Self {
        Self {
            allowlist: None,
            allowlist_action: IpFilterAction::Front,
            blocklist: None,
            blocklist_action: IpFilterAction::Close,
            trusted_proxies: None,
            client_ip_header: None,
        }
    }
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
    pub ip_filters: OriginIpFilters,
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
    ip_filters: ArcSwap<OriginIpFilters>,
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
            ip_filters: ArcSwap::from_pointee(opts.ip_filters),
            global_budget: Arc::new(GlobalBudget::default()),
        })
    }

    /// Atomically replace active Geo-Stealth allowlist/blocklist & CDN trusted-proxy
    /// filters (used during `SIGHUP` / `POST /reload` hot-reloads!).
    pub fn set_ip_filters(&self, next: OriginIpFilters) {
        self.ip_filters.store(Arc::new(next));
    }

    /// Atomically update allowlist/blocklist while preserving configured CDN
    /// `trusted_proxies` and `client_ip_header` (used by integrated `[web]` sync!).
    pub fn update_geo_filters(
        &self,
        allowlist: Option<Arc<LiveIpFilter>>,
        allowlist_action: IpFilterAction,
        blocklist: Option<Arc<LiveIpFilter>>,
        blocklist_action: IpFilterAction,
    ) {
        let prev = self.ip_filters.load();
        self.ip_filters.store(Arc::new(OriginIpFilters {
            allowlist,
            allowlist_action,
            blocklist,
            blocklist_action,
            trusted_proxies: prev.trusted_proxies.clone(),
            client_ip_header: prev.client_ip_header.clone(),
        }));
    }

    /// Spawn periodic background refresh loops for any attached IP allowlist/blocklist
    /// and auto-updating CDN trusted-proxy ranges.
    pub fn spawn_ip_filter_refresh_loops(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let filters = self.ip_filters.load();
        if let Some(bl) = &filters.blocklist {
            bl.spawn_refresh_loop(shutdown.clone());
        }
        if let Some(al) = &filters.allowlist {
            al.spawn_refresh_loop(shutdown.clone());
        }
        if let Some(tp) = &filters.trusted_proxies {
            tp.spawn_refresh_loop(shutdown);
        }
    }

    /// Spawn periodic background refresh loop ONLY for CDN `trusted_proxies`
    /// (used by `[web] integrated = true` where `ProxyEngine` already manages
    /// `allowlist` and `blocklist` refresh loops).
    pub fn spawn_trusted_proxies_refresh_loop(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let filters = self.ip_filters.load();
        if let Some(tp) = &filters.trusted_proxies {
            tp.spawn_refresh_loop(shutdown);
        }
    }

    /// Trigger a non-blocking refresh ONLY for CDN `trusted_proxies`.
    pub fn trigger_trusted_proxies_refresh(&self) {
        let filters = self.ip_filters.load();
        if let Some(tp) = &filters.trusted_proxies {
            let tp = Arc::clone(tp);
            tokio::spawn(async move {
                let _ = tp.refresh_once().await;
            });
        }
    }

    /// Trigger a non-blocking refresh of attached IP filters & CDN ranges (e.g. on `SIGHUP`).
    pub fn trigger_ip_filter_refresh(&self) {
        let filters = self.ip_filters.load();
        if let Some(bl) = &filters.blocklist {
            let bl = Arc::clone(bl);
            tokio::spawn(async move {
                let _ = bl.refresh_once().await;
            });
        }
        if let Some(al) = &filters.allowlist {
            let al = Arc::clone(al);
            tokio::spawn(async move {
                let _ = al.refresh_once().await;
            });
        }
        if let Some(tp) = &filters.trusted_proxies {
            let tp = Arc::clone(tp);
            tokio::spawn(async move {
                let _ = tp.refresh_once().await;
            });
        }
    }

    pub fn ip_filters(&self) -> arc_swap::Guard<Arc<OriginIpFilters>> {
        self.ip_filters.load()
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
        // Geo-Stealth IP allowlist / blocklist check BEFORE Tier-1 & Tier-2:
        // - `Front` (default for allowlist): strip any bridge/token atoms so nothing
        //   leaks to cover-upstream logs, then serve Tier-3 cover site directly!
        // - `Close` (default for blocklist): return uncacheable 404.
        match self.check_ip_filters(req.headers(), Some(peer_addr)) {
            WebIpVerdict::Close => return self.not_found(),
            WebIpVerdict::Front => {
                sanitize_stealth_cover_request(&mut req);
                if let Some(c) = &self.counters {
                    c.on_cover_served();
                }
                return self.cover.serve_incoming(req).await;
            }
            WebIpVerdict::Allow => {}
        }

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
        self.handle_bytes_from(req, None).await
    }

    /// Direct non-Hyper request handler with an explicit `peer_addr` (for testing
    /// IP allowlist / blocklist enforcement).
    pub async fn handle_bytes_from(
        &self,
        mut req: Request<Bytes>,
        peer_addr: Option<SocketAddr>,
    ) -> Response<Full<Bytes>> {
        match self.check_ip_filters(req.headers(), peer_addr) {
            WebIpVerdict::Close => return self.not_found(),
            WebIpVerdict::Front => {
                sanitize_stealth_cover_request(&mut req);
                if let Some(c) = &self.counters {
                    c.on_cover_served();
                }
                return self.cover.serve_bytes(req).await;
            }
            WebIpVerdict::Allow => {}
        }

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

    fn check_ip_filters(&self, headers: &HeaderMap, peer_addr: Option<SocketAddr>) -> WebIpVerdict {
        let filters = self.ip_filters.load();
        if filters.blocklist.is_none() && filters.allowlist.is_none() {
            return WebIpVerdict::Allow;
        }
        let resolved_ip = peer_addr
            .and_then(|sa| self.resolve_client_addr(headers, sa))
            .map(|sa| mtg_core::ip::unmap_ip(sa.ip()));

        if let Some(block) = &filters.blocklist
            && let Some(ip) = resolved_ip
            && block.contains(ip)
        {
            return match filters.blocklist_action {
                IpFilterAction::Front => WebIpVerdict::Front,
                IpFilterAction::Close => WebIpVerdict::Close,
            };
        }
        if let Some(allow) = &filters.allowlist {
            let allowed = resolved_ip.is_some_and(|ip| allow.contains(ip));
            if !allowed {
                return match filters.allowlist_action {
                    IpFilterAction::Front => WebIpVerdict::Front,
                    IpFilterAction::Close => WebIpVerdict::Close,
                };
            }
        }
        WebIpVerdict::Allow
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

    /// Resolve the real browser client IP using spoof-proof trusted-proxy right-to-left
    /// hop peeling (supports direct PROXY protocol, local Nginx/Caddy XFF, AND multi-hop
    /// CDN chains like Cloudflare `CF-Connecting-IP` / ArvanCloud `Ar-Real-IP`!).
    pub fn resolve_client_addr(
        &self,
        headers: &HeaderMap,
        peer_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        let filters = self.ip_filters.load();
        if let Some(tp) = &filters.trusted_proxies {
            let raw_peer = mtg_core::ip::unmap_ip(peer_addr.ip());
            let peer_is_cdn = tp.contains(raw_peer);
            let peer_is_trusted = raw_peer.is_loopback() || peer_is_cdn;
            if !peer_is_trusted {
                // Direct connection from an untrusted public IP (bypassing CDN!):
                // NEVER trust any HTTP IP header — prevents Geo-Stealth IP spoofing!
                return Some(SocketAddr::new(raw_peer, peer_addr.port()));
            }

            // Collect X-Forwarded-For chain left-to-right, then peel trusted CDN/loopback
            // hops right-to-left to find the first untrusted client IP!
            let mut xff_ips: Vec<IpAddr> = Vec::new();
            for val in headers.get_all("x-forwarded-for") {
                let Ok(s) = val.to_str() else {
                    continue;
                };
                for part in s.split(',') {
                    if let Some(ip) = parse_ip_or_sock(part.trim()) {
                        xff_ips.push(mtg_core::ip::unmap_ip(ip));
                    }
                }
            }

            let mut saw_cdn_hop = peer_is_cdn;
            let mut peeled_client: Option<IpAddr> = None;
            for &hop in xff_ips.iter().rev() {
                if tp.contains(hop) {
                    saw_cdn_hop = true;
                    continue;
                }
                if hop.is_loopback() {
                    continue;
                }
                peeled_client = Some(hop);
                break;
            }

            // Only honor an authoritative CDN header (e.g. `CF-Connecting-IP`) when
            // network routing proved a trusted CDN hop in `trusted_proxies` delivered
            // this request (100% immune to direct-to-origin header forgery!).
            if saw_cdn_hop
                && let Some(hdr_name) = &filters.client_ip_header
                && let Some(ip) = extract_single_header_ip(headers, hdr_name)
            {
                return Some(SocketAddr::new(mtg_core::ip::unmap_ip(ip), 0));
            }

            if let Some(ip) = peeled_client {
                return Some(SocketAddr::new(ip, 0));
            }

            if self.client_ip_source == ClientIpSource::ProxyProtocol && !raw_peer.is_loopback() {
                return Some(SocketAddr::new(raw_peer, peer_addr.port()));
            }
            return None;
        }

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
                        if let Some(ip) = parse_ip_or_sock(part.trim()) {
                            rightmost = Some(mtg_core::ip::unmap_ip(ip));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebIpVerdict {
    Allow,
    Front,
    Close,
}

/// Strip potential proxy bridge query parameters and carrier auth/subprotocol
/// headers before passing a geo-fronted request to `cover`, so:
/// 1. A foreign prober presenting a leaked `/?bridge=<cap>` gets the exact `200 OK`
///    cover homepage (zero 404 oracle!).
/// 2. No leaked capability or bearer token is ever forwarded into `cover-upstream` logs!
fn sanitize_stealth_cover_request<B>(req: &mut Request<B>) {
    if let Some(query) = req.uri().query() {
        let has_bridge_or_token =
            query.contains(BRIDGE_QUERY) || credential_atoms(query).next().is_some();
        if has_bridge_or_token {
            let clean_path = req.uri().path().to_owned();
            if let Ok(clean_uri) = clean_path.parse::<Uri>() {
                *req.uri_mut() = clean_uri;
            }
        }
    }
    if req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("Bearer "))
    {
        req.headers_mut().remove(header::AUTHORIZATION);
    }
    if req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains(SUBPROTOCOL_PREFIX))
    {
        req.headers_mut().remove("sec-websocket-protocol");
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

fn parse_ip_or_sock(trimmed: &str) -> Option<IpAddr> {
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    None
}

fn extract_single_header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    let mut vals = headers.get_all(name).iter();
    let first = vals.next()?.to_str().ok()?.trim();
    if vals.next().is_some() {
        return None;
    }
    parse_ip_or_sock(first)
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
