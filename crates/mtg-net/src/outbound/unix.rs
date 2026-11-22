//! Universal Linux Unix Domain Socket Sidecar Transport (`unix://`,
//! `unix+socks5://`, `unix+http://`).
//!
//! Enables **ANY** external protocol daemon — Xray-core (VLESS+Reality/XHTTP),
//! sing-box (Hysteria2/TUIC/Trojan/AnyTLS), Clash/mihomo, WireGuard userspace,
//! Tor, SSH dynamic forward, or any future custom transport — to carry outbound
//! MTProto traffic out of `mtg-proxy` over local Linux Unix sockets (filesystem
//! path `/run/xray.sock` OR abstract namespace `@sing-box-out`) with **zero
//! loopback TCP/IP stack overhead**!

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::linux::net::SocketAddrExt as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use mtg_protocol::proxyproto::encode_v2_tcp;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
    ReadBuf,
};
use tokio::net::UnixStream;

use super::stream::{DialResult, OutboundStream, TunnelStream};
use super::{OutboundError, OutboundTarget, OutboundTransport};
use crate::timer::coarse_now_ns;

/// Framing protocol spoken over the local Unix domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixFraming {
    /// Raw byte stream (`unix:///path` or `unix://@abstract`).
    Raw { proxy_v2: bool },
    /// RFC 1928 SOCKS5 over Unix socket (`unix+socks5:///path`).
    Socks5,
    /// HTTP/1.1 CONNECT over Unix socket (`unix+http:///path`).
    HttpConnect,
}

/// Wrapper implementing [`TunnelStream`] over a Linux [`UnixStream`].
#[derive(Debug)]
pub struct UnixTunnelStream {
    inner: UnixStream,
    label: &'static str,
}

impl TunnelStream for UnixTunnelStream {
    fn transport_label(&self) -> &'static str {
        self.label
    }
}

impl AsyncRead for UnixTunnelStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixTunnelStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Unix domain socket sidecar transport (`unix://`, `unix+socks5://`, `unix+http://`).
pub struct UnixSidecarTransport {
    name: Arc<str>,
    /// Filesystem path (`/run/xray.sock`) or abstract name (`@sing-box`).
    socket_path: String,
    framing: UnixFraming,
    username: Option<String>,
    password: Option<String>,
    redacted: String,
}

impl fmt::Debug for UnixSidecarTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixSidecarTransport")
            .field("name", &self.name)
            .field("endpoint", &self.redacted)
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl UnixSidecarTransport {
    /// Parse `unix:///path/to.sock`, `unix://@abstract`, `unix+socks5://[user:pass@]/path`,
    /// or `unix+http://[user:pass@]/path`.
    pub fn parse(name: Arc<str>, raw_url: &str) -> Result<Self, OutboundError> {
        let (scheme, rest, base_framing) = if let Some(r) = raw_url.strip_prefix("unix+socks5://") {
            ("unix+socks5", r, UnixFraming::Socks5)
        } else if let Some(r) = raw_url.strip_prefix("unix+http://") {
            ("unix+http", r, UnixFraming::HttpConnect)
        } else if let Some(r) = raw_url.strip_prefix("unix://") {
            ("unix", r, UnixFraming::Raw { proxy_v2: false })
        } else {
            return Err(OutboundError::InvalidConfig(format!(
                "unsupported unix scheme in {raw_url:?}"
            )));
        };

        let (path_and_auth, query) = match rest.split_once('?') {
            Some((p, q)) => (p, q),
            None => (rest, ""),
        };

        let (username, password, socket_path) =
            if let Some((auth, path)) = path_and_auth.split_once("@/") {
                let (u, p) = match auth.split_once(':') {
                    Some((u, p)) => (Some(u.to_owned()), Some(p.to_owned())),
                    None => (Some(auth.to_owned()), Some(String::new())),
                };
                (u, p, format!("/{path}"))
            } else {
                (None, None, path_and_auth.to_owned())
            };

        if socket_path.is_empty()
            || (!socket_path.starts_with('/') && !socket_path.starts_with('@'))
        {
            return Err(OutboundError::InvalidConfig(format!(
                "unix outbound {name:?} requires an absolute path (/...) or abstract name (@...)"
            )));
        }

        let mut framing = base_framing;
        if let UnixFraming::Raw { ref mut proxy_v2 } = framing {
            for pair in query.split('&') {
                if pair.eq_ignore_ascii_case("proxy_v2=1")
                    || pair.eq_ignore_ascii_case("proxy_v2=true")
                    || pair.eq_ignore_ascii_case("protocol=proxy-v2")
                {
                    *proxy_v2 = true;
                }
            }
        }

        let redacted = format!("{scheme}://{socket_path}");
        Ok(Self {
            name,
            socket_path,
            framing,
            username,
            password,
            redacted,
        })
    }

    async fn connect_unix(&self, timeout: Duration) -> Result<UnixStream, OutboundError> {
        let path = self.socket_path.clone();
        let fut = async move {
            if let Some(abstract_name) = path.strip_prefix('@') {
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name)?;
                let std_stream = tokio::task::spawn_blocking(move || {
                    let s = std::os::unix::net::UnixStream::connect_addr(&addr)?;
                    s.set_nonblocking(true)?;
                    Ok::<_, io::Error>(s)
                })
                .await
                .map_err(|e| io::Error::other(e.to_string()))??;
                UnixStream::from_std(std_stream)
            } else {
                UnixStream::connect(&path).await
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))?
            .map_err(OutboundError::Io)
    }
}

impl OutboundTransport for UnixSidecarTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        match self.framing {
            UnixFraming::Raw { .. } => "unix",
            UnixFraming::Socks5 => "unix+socks5",
            UnixFraming::HttpConnect => "unix+http",
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
            let mut stream = self.connect_unix(timeout).await?;
            let mut bound_addr = None;

            match self.framing {
                UnixFraming::Raw { proxy_v2 } => {
                    if proxy_v2 && let OutboundTarget::Addr(dst) = target {
                        let src = match dst {
                            SocketAddr::V4(_) => {
                                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
                            }
                            SocketAddr::V6(_) => {
                                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
                            }
                        };
                        let hdr = encode_v2_tcp(src, *dst);
                        tokio::time::timeout(timeout, stream.write_all(hdr.as_slice()))
                            .await
                            .map_err(|_| OutboundError::Timeout(self.redacted.clone()))?
                            .map_err(OutboundError::Io)?;
                    }
                }
                UnixFraming::Socks5 => {
                    bound_addr = tokio::time::timeout(
                        timeout,
                        socks5_handshake_generic(
                            &mut stream,
                            self.username.as_deref(),
                            self.password.as_deref(),
                            target,
                        ),
                    )
                    .await
                    .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;
                }
                UnixFraming::HttpConnect => {
                    tokio::time::timeout(
                        timeout,
                        http_connect_handshake_generic(
                            &mut stream,
                            self.username.as_deref(),
                            self.password.as_deref(),
                            target,
                        ),
                    )
                    .await
                    .map_err(|_| OutboundError::Timeout(self.redacted.clone()))??;
                }
            }

            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tunnel(UnixTunnelStream {
                    inner: stream,
                    label: self.protocol(),
                }),
                bound_addr,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

/// Generic RFC 1928 + RFC 1929 SOCKS5 handshake usable over ANY `AsyncRead + AsyncWrite`
/// stream (`TcpStream`, `UnixStream`, TLS stream, chained tunnel!).
pub(crate) async fn socks5_handshake_generic<S>(
    stream: &mut S,
    username: Option<&str>,
    password: Option<&str>,
    target: &OutboundTarget,
) -> Result<Option<SocketAddr>, OutboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let has_auth = username.is_some();
    if has_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(OutboundError::Protocol(format!(
            "SOCKS5 bad version: {}",
            greeting[0]
        )));
    }
    match greeting[1] {
        0x00 => {}
        0x02 => {
            let u = username.unwrap_or("").as_bytes();
            let p = password.unwrap_or("").as_bytes();
            if u.len() > 255 || p.len() > 255 {
                return Err(OutboundError::Protocol(
                    "SOCKS5 credentials exceed 255 bytes".into(),
                ));
            }
            let mut auth = Vec::with_capacity(3 + u.len() + p.len());
            auth.push(0x01);
            auth.push(u.len() as u8);
            auth.extend_from_slice(u);
            auth.push(p.len() as u8);
            auth.extend_from_slice(p);
            stream.write_all(&auth).await?;

            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await?;
            if reply[0] != 0x01 || reply[1] != 0x00 {
                return Err(OutboundError::Protocol(format!(
                    "SOCKS5 auth rejected (status={})",
                    reply[1]
                )));
            }
        }
        other => {
            return Err(OutboundError::Protocol(format!(
                "SOCKS5 unsupported auth method: {other:#x}"
            )));
        }
    }

    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    encode_socks5_addr(target, &mut req)?;
    stream.write_all(&req).await?;

    let mut resp_hdr = [0u8; 4];
    stream.read_exact(&mut resp_hdr).await?;
    if resp_hdr[0] != 0x05 || resp_hdr[1] != 0x00 {
        return Err(OutboundError::Protocol(format!(
            "SOCKS5 CONNECT failed (rep={:#x})",
            resp_hdr[1]
        )));
    }
    let bound_addr = match resp_hdr[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut skip).await?;
            None
        }
        other => {
            return Err(OutboundError::Protocol(format!(
                "SOCKS5 unknown reply ATYP: {other:#x}"
            )));
        }
    };
    Ok(bound_addr)
}

/// Encode a SOCKS5/Shadowsocks address block (`ATYP | ADDR | PORT_BE16`).
pub(crate) fn encode_socks5_addr(
    target: &OutboundTarget,
    out: &mut Vec<u8>,
) -> Result<(), OutboundError> {
    match target {
        OutboundTarget::Addr(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        OutboundTarget::Addr(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        OutboundTarget::HostPort(host, port) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return encode_socks5_addr(&OutboundTarget::Addr(SocketAddr::new(ip, *port)), out);
            }
            if host.is_empty() || host.len() > 255 {
                return Err(OutboundError::Protocol(format!(
                    "target host invalid length: {}",
                    host.len()
                )));
            }
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// Generic HTTP/1.1 `CONNECT` handshake usable over ANY `AsyncRead + AsyncWrite`
/// stream (`TcpStream`, `TlsStream<TcpStream>`, `UnixStream`).
pub(crate) async fn http_connect_handshake_generic<S>(
    stream: &mut S,
    username: Option<&str>,
    password: Option<&str>,
    target: &OutboundTarget,
) -> Result<(), OutboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hostport = target.host_port_string();
    let mut req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n");
    if let Some(u) = username {
        use std::fmt::Write as _;
        let creds = format!("{u}:{}", password.unwrap_or(""));
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        let _ = write!(req, "Proxy-Authorization: Basic {b64}\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read status line + headers byte-by-byte / line-by-line WITHOUT consuming
    // any post-header payload bytes (1-byte peek or BufReader check).
    let mut reader = BufReader::with_capacity(1, stream);
    let mut status_line = String::new();
    let n = reader.read_line(&mut status_line).await?;
    if n == 0 {
        return Err(OutboundError::Protocol(
            "HTTP CONNECT unexpected EOF".into(),
        ));
    }
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code == "200");
    if !ok {
        return Err(OutboundError::Protocol(format!(
            "HTTP CONNECT rejected: {}",
            status_line.trim()
        )));
    }
    loop {
        let mut line = String::new();
        let m = reader.read_line(&mut line).await?;
        if m == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}
