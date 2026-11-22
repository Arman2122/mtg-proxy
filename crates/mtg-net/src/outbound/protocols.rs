//! Built-in network outbound transports:
//! - [`DirectTransport`]: Linux direct TCP with optional `SO_BINDTODEVICE`,
//!   `SO_MARK` (`fwmark`), and source-IP binding (`bind-ipv4`/`bind-ipv6`).
//! - [`Socks5Transport`]: RFC 1928/1929 `socks5://` & `socks5h://` (with `BND.ADDR` capture).
//! - [`Socks4Transport`]: SOCKS4 & SOCKS4a (`socks4://` / `socks4a://`).
//! - [`HttpConnectTransport`]: Plaintext HTTP/1.1 `CONNECT` (`http://`).
//! - [`HttpsConnectTransport`]: Native TLS 1.3 (`tokio-rustls` + `webpki-roots`)
//!   wrapped HTTP/1.1 `CONNECT` (`https://`) with custom SNI support.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use mtg_config::redact_proxy_url;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::stream::{DialResult, OutboundStream, TunnelStream};
use super::unix::{http_connect_handshake_generic, socks5_handshake_generic};
use super::{OutboundError, OutboundTarget, OutboundTransport};
use crate::dns::DnsResolver;
use crate::sockopts::{OutboundBindOptions, SocketConfig, connect_tcp_tuned_bound};
use crate::timer::coarse_now_ns;

/// Parse `host:port` strictly (supports IPv6 `[::1]:8080`, requires non-zero port).
pub(crate) fn split_host_port_strict(hp: &str) -> Option<(String, u16)> {
    if hp.is_empty() {
        return None;
    }
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let p: u16 = tail.strip_prefix(':')?.parse().ok()?;
        if h.is_empty() || p == 0 {
            return None;
        }
        return Some((h.to_owned(), p));
    }
    let (h, p_str) = hp.rsplit_once(':')?;
    if h.is_empty() || h.contains(':') {
        return None;
    }
    let p: u16 = p_str.parse().ok()?;
    if p == 0 {
        return None;
    }
    Some((h.to_owned(), p))
}

fn split_host_port_default(hp: &str, default_port: u16) -> Option<(String, u16)> {
    if hp.is_empty() {
        return None;
    }
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        if tail.is_empty() {
            return Some((h.to_owned(), default_port));
        }
        let p: u16 = tail.strip_prefix(':')?.parse().ok()?;
        if h.is_empty() || p == 0 {
            return None;
        }
        return Some((h.to_owned(), p));
    }
    if let Some((h, p_str)) = hp.rsplit_once(':')
        && !h.contains(':')
    {
        let p: u16 = p_str.parse().ok()?;
        if h.is_empty() || p == 0 {
            return None;
        }
        return Some((h.to_owned(), p));
    }
    Some((hp.to_owned(), default_port))
}

struct ParsedAuthority {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    query: String,
}

fn parse_authority_url(raw: &str, default_port: u16) -> Result<ParsedAuthority, OutboundError> {
    let redacted = redact_proxy_url(raw);
    let after_scheme = raw
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or_else(|| OutboundError::InvalidConfig(redacted.clone()))?;
    let (authority_and_path, query) = match after_scheme.split_once('?') {
        Some((a, q)) => (a, q.to_owned()),
        None => (after_scheme, String::new()),
    };
    let authority = authority_and_path.split('/').next().unwrap_or("");
    let (auth, hostport) = match authority.rsplit_once('@') {
        Some((a, hp)) => (Some(a), hp),
        None => (None, authority),
    };
    let (username, password) = match auth {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (Some(u.to_owned()), Some(p.to_owned())),
            None => (Some(a.to_owned()), Some(String::new())),
        },
        None => (None, None),
    };
    let (host, port) = split_host_port_default(hostport, default_port)
        .ok_or(OutboundError::InvalidConfig(redacted))?;
    Ok(ParsedAuthority {
        host,
        port,
        username,
        password,
        query,
    })
}

/// Direct Linux TCP transport (`direct://`) supporting `SO_BINDTODEVICE`,
/// `SO_MARK` (`fwmark`), and source IP binding (`bind-ipv4`/`bind-ipv6`).
pub struct DirectTransport {
    name: Arc<str>,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for DirectTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectTransport")
            .field("name", &self.name)
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl DirectTransport {
    pub fn new(
        name: Arc<str>,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Self {
        let mut parts = Vec::new();
        if let Some(iface) = &bind.interface {
            parts.push(format!("iface={iface}"));
        }
        if let Some(v4) = bind.bind_ipv4 {
            parts.push(format!("v4={v4}"));
        }
        if let Some(v6) = bind.bind_ipv6 {
            parts.push(format!("v6={v6}"));
        }
        if let Some(mark) = bind.fwmark {
            parts.push(format!("fwmark={mark:#x}"));
        }
        let redacted = if parts.is_empty() {
            "direct://".to_owned()
        } else {
            format!("direct://?{}", parts.join("&"))
        };
        Self {
            name,
            dns,
            sock_cfg,
            bind,
            redacted,
        }
    }
}

impl OutboundTransport for DirectTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addr = match target {
                OutboundTarget::Addr(sa) => *sa,
                OutboundTarget::HostPort(host, port) => {
                    let addrs = self
                        .dns
                        .resolve_host(host, *port)
                        .await
                        .map_err(|e| OutboundError::Dns(e.to_string()))?;
                    *addrs
                        .first()
                        .ok_or_else(|| OutboundError::Dns(format!("no addresses for {host}")))?
                }
            };
            let tcp = connect_tcp_tuned_bound(addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;
            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tcp(tcp),
                bound_addr: None,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

/// SOCKS5 / SOCKS5h (`socks5://`, `socks5h://`) transport yielding a concrete
/// [`OutboundStream::Tcp`] and capturing `BND.ADDR:BND.PORT`.
pub struct Socks5Transport {
    name: Arc<str>,
    proxy_host: String,
    proxy_port: u16,
    resolve_remote: bool,
    username: Option<String>,
    password: Option<String>,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for Socks5Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Transport")
            .field("name", &self.name)
            .field("endpoint", &self.redacted)
            .finish_non_exhaustive()
    }
}

impl Socks5Transport {
    pub fn parse(
        name: Arc<str>,
        raw_url: &str,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Result<Self, OutboundError> {
        let resolve_remote = raw_url.starts_with("socks5h://");
        if !resolve_remote && !raw_url.starts_with("socks5://") {
            return Err(OutboundError::InvalidConfig(redact_proxy_url(raw_url)));
        }
        let parsed = parse_authority_url(raw_url, 1080)?;
        let redacted = redact_proxy_url(raw_url);
        Ok(Self {
            name,
            proxy_host: parsed.host,
            proxy_port: parsed.port,
            resolve_remote,
            username: parsed.username,
            password: parsed.password,
            dns,
            sock_cfg,
            bind,
            redacted,
        })
    }
}

impl OutboundTransport for Socks5Transport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        if self.resolve_remote {
            "socks5h"
        } else {
            "socks5"
        }
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addrs = self
                .dns
                .resolve_host(&self.proxy_host, self.proxy_port)
                .await
                .map_err(|e| OutboundError::Dns(e.to_string()))?;
            let &proxy_addr = addrs.first().ok_or_else(|| {
                OutboundError::Dns(format!("no addresses for {}", self.proxy_host))
            })?;

            // If `socks5://` (not `socks5h://`) receives a hostname, resolve locally first.
            let effective_target = match target {
                OutboundTarget::HostPort(h, p) if !self.resolve_remote => {
                    let resolved = self
                        .dns
                        .resolve_host(h, *p)
                        .await
                        .map_err(|e| OutboundError::Dns(e.to_string()))?;
                    OutboundTarget::Addr(*resolved.first().ok_or_else(|| {
                        OutboundError::Dns(format!("no addresses for target {h}"))
                    })?)
                }
                other => other.clone(),
            };

            let mut tcp = connect_tcp_tuned_bound(proxy_addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;
            let bound_addr = tokio::time::timeout(
                timeout,
                socks5_handshake_generic(
                    &mut tcp,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    &effective_target,
                ),
            )
            .await
            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;

            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tcp(tcp),
                bound_addr,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

/// SOCKS4 / SOCKS4a (`socks4://`, `socks4a://`) transport yielding a concrete
/// [`OutboundStream::Tcp`].
pub struct Socks4Transport {
    name: Arc<str>,
    proxy_host: String,
    proxy_port: u16,
    socks4a: bool,
    user_id: String,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for Socks4Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks4Transport")
            .field("name", &self.name)
            .field("endpoint", &self.redacted)
            .finish_non_exhaustive()
    }
}

impl Socks4Transport {
    pub fn parse(
        name: Arc<str>,
        raw_url: &str,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Result<Self, OutboundError> {
        let socks4a = raw_url.starts_with("socks4a://");
        if !socks4a && !raw_url.starts_with("socks4://") {
            return Err(OutboundError::InvalidConfig(redact_proxy_url(raw_url)));
        }
        let parsed = parse_authority_url(raw_url, 1080)?;
        let redacted = redact_proxy_url(raw_url);
        Ok(Self {
            name,
            proxy_host: parsed.host,
            proxy_port: parsed.port,
            socks4a,
            user_id: parsed.username.unwrap_or_default(),
            dns,
            sock_cfg,
            bind,
            redacted,
        })
    }
}

impl OutboundTransport for Socks4Transport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        if self.socks4a { "socks4a" } else { "socks4" }
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addrs = self
                .dns
                .resolve_host(&self.proxy_host, self.proxy_port)
                .await
                .map_err(|e| OutboundError::Dns(e.to_string()))?;
            let &proxy_addr = addrs.first().ok_or_else(|| {
                OutboundError::Dns(format!("no addresses for {}", self.proxy_host))
            })?;

            let mut req = Vec::with_capacity(64);
            req.push(0x04); // VN = 4
            req.push(0x01); // CD = CONNECT

            match target {
                OutboundTarget::Addr(SocketAddr::V4(v4)) => {
                    req.extend_from_slice(&v4.port().to_be_bytes());
                    req.extend_from_slice(&v4.ip().octets());
                    req.extend_from_slice(self.user_id.as_bytes());
                    req.push(0x00);
                }
                OutboundTarget::Addr(SocketAddr::V6(_)) => {
                    return Err(OutboundError::Protocol(
                        "SOCKS4/4a does not support IPv6 targets".into(),
                    ));
                }
                OutboundTarget::HostPort(host, port) => {
                    if let Ok(IpAddr::V4(v4)) = host.parse::<IpAddr>() {
                        req.extend_from_slice(&port.to_be_bytes());
                        req.extend_from_slice(&v4.octets());
                        req.extend_from_slice(self.user_id.as_bytes());
                        req.push(0x00);
                    } else if self.socks4a {
                        req.extend_from_slice(&port.to_be_bytes());
                        req.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                        req.extend_from_slice(self.user_id.as_bytes());
                        req.push(0x00);
                        req.extend_from_slice(host.as_bytes());
                        req.push(0x00);
                    } else {
                        let resolved = self
                            .dns
                            .resolve_host(host, *port)
                            .await
                            .map_err(|e| OutboundError::Dns(e.to_string()))?;
                        let v4 = resolved.iter().find_map(|sa| match sa {
                            SocketAddr::V4(a) => Some(a),
                            SocketAddr::V6(_) => None,
                        });
                        let Some(v4) = v4 else {
                            return Err(OutboundError::Protocol(
                                "SOCKS4 requires an IPv4 target".into(),
                            ));
                        };
                        req.extend_from_slice(&v4.port().to_be_bytes());
                        req.extend_from_slice(&v4.ip().octets());
                        req.extend_from_slice(self.user_id.as_bytes());
                        req.push(0x00);
                    }
                }
            }

            let mut tcp = connect_tcp_tuned_bound(proxy_addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;
            tokio::time::timeout(timeout, async {
                tcp.write_all(&req).await?;
                let mut reply = [0u8; 8];
                tcp.read_exact(&mut reply).await?;
                if reply[1] != 0x5A {
                    return Err(OutboundError::Protocol(format!(
                        "SOCKS4 CONNECT rejected (cd={:#x})",
                        reply[1]
                    )));
                }
                Ok(())
            })
            .await
            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;

            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tcp(tcp),
                bound_addr: None,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

/// Plaintext HTTP/1.1 `CONNECT` (`http://`) transport yielding [`OutboundStream::Tcp`].
pub struct HttpConnectTransport {
    name: Arc<str>,
    proxy_host: String,
    proxy_port: u16,
    username: Option<String>,
    password: Option<String>,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for HttpConnectTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectTransport")
            .field("name", &self.name)
            .field("endpoint", &self.redacted)
            .finish_non_exhaustive()
    }
}

impl HttpConnectTransport {
    pub fn parse(
        name: Arc<str>,
        raw_url: &str,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Result<Self, OutboundError> {
        if !raw_url.starts_with("http://") {
            return Err(OutboundError::InvalidConfig(redact_proxy_url(raw_url)));
        }
        let parsed = parse_authority_url(raw_url, 8080)?;
        let redacted = redact_proxy_url(raw_url);
        Ok(Self {
            name,
            proxy_host: parsed.host,
            proxy_port: parsed.port,
            username: parsed.username,
            password: parsed.password,
            dns,
            sock_cfg,
            bind,
            redacted,
        })
    }
}

impl OutboundTransport for HttpConnectTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "http"
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addrs = self
                .dns
                .resolve_host(&self.proxy_host, self.proxy_port)
                .await
                .map_err(|e| OutboundError::Dns(e.to_string()))?;
            let &proxy_addr = addrs.first().ok_or_else(|| {
                OutboundError::Dns(format!("no addresses for {}", self.proxy_host))
            })?;

            let mut tcp = connect_tcp_tuned_bound(proxy_addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;
            tokio::time::timeout(
                timeout,
                http_connect_handshake_generic(
                    &mut tcp,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    target,
                ),
            )
            .await
            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;

            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tcp(tcp),
                bound_addr: None,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

/// TLS-wrapped tunnel stream for `https://` forward proxy CONNECT tunnels.
pub struct TlsTunnelStream(TlsStream<TcpStream>);

impl fmt::Debug for TlsTunnelStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTunnelStream").finish_non_exhaustive()
    }
}

impl TunnelStream for TlsTunnelStream {
    fn transport_label(&self) -> &'static str {
        "https"
    }
}

impl AsyncRead for TlsTunnelStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsTunnelStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Native TLS 1.3 wrapped HTTP/1.1 `CONNECT` (`https://`) forward proxy transport.
/// Supports `?sni=custom.host` override and verified WebPKI roots!
pub struct HttpsConnectTransport {
    name: Arc<str>,
    proxy_host: String,
    proxy_port: u16,
    sni_host: String,
    username: Option<String>,
    password: Option<String>,
    tls_connector: TlsConnector,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for HttpsConnectTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsConnectTransport")
            .field("name", &self.name)
            .field("endpoint", &self.redacted)
            .field("sni", &self.sni_host)
            .finish_non_exhaustive()
    }
}

impl HttpsConnectTransport {
    pub fn parse(
        name: Arc<str>,
        raw_url: &str,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Result<Self, OutboundError> {
        if !raw_url.starts_with("https://") {
            return Err(OutboundError::InvalidConfig(redact_proxy_url(raw_url)));
        }
        let parsed = parse_authority_url(raw_url, 443)?;
        let mut sni_host = parsed.host.clone();
        for pair in parsed.query.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k.eq_ignore_ascii_case("sni")
                && !v.is_empty()
            {
                v.clone_into(&mut sni_host);
            }
        }
        let _ = ServerName::try_from(sni_host.clone()).map_err(|_| {
            OutboundError::InvalidConfig(format!("invalid TLS SNI {sni_host:?} for {name:?}"))
        })?;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(tls_cfg));
        let redacted = redact_proxy_url(raw_url);

        Ok(Self {
            name,
            proxy_host: parsed.host,
            proxy_port: parsed.port,
            sni_host,
            username: parsed.username,
            password: parsed.password,
            tls_connector,
            dns,
            sock_cfg,
            bind,
            redacted,
        })
    }
}

impl OutboundTransport for HttpsConnectTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "https"
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addrs = self
                .dns
                .resolve_host(&self.proxy_host, self.proxy_port)
                .await
                .map_err(|e| OutboundError::Dns(e.to_string()))?;
            let &proxy_addr = addrs.first().ok_or_else(|| {
                OutboundError::Dns(format!("no addresses for {}", self.proxy_host))
            })?;

            let tcp = connect_tcp_tuned_bound(proxy_addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;
            let server_name = ServerName::try_from(self.sni_host.clone())
                .map_err(|_| OutboundError::Protocol("invalid TLS SNI".into()))?;
            let mut tls =
                tokio::time::timeout(timeout, self.tls_connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| OutboundError::Timeout(self.redacted.clone()))?
                    .map_err(OutboundError::Io)?;

            tokio::time::timeout(
                timeout,
                http_connect_handshake_generic(
                    &mut tls,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    target,
                ),
            )
            .await
            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;

            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tunnel(TlsTunnelStream(tls)),
                bound_addr: None,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}
