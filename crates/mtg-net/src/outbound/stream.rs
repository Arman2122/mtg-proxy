//! Zero-overhead concrete-fast-path [`OutboundStream`] abstraction.
//!
//! - [`OutboundStream::Tcp`] carries direct TCP, Linux `SO_BINDTODEVICE` / `SO_MARK`
//!   policy-routed TCP, SOCKS5/5h, SOCKS4/4a, and plaintext HTTP CONNECT tunnels with
//!   **zero heap allocation and zero vtable indirection** on the hot data plane.
//! - [`OutboundStream::Tunnel`] boxes encrypted or non-TCP transports (Shadowsocks
//!   AEAD-2022 / classic AEAD, TLS-wrapped HTTPS CONNECT, Linux Unix domain socket
//!   sidecars for Xray / sing-box / VLESS / Hysteria2, or any custom [`OutboundTransport`])
//!   so `DirectRelay`'s steady-state future size stays strictly within its 1.5 KiB budget!

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Trait implemented by non-raw-TCP outbound tunnels (Shadowsocks AEAD-2022,
/// TLS HTTPS CONNECT, Unix domain socket sidecars, custom pluggable protocols).
pub trait TunnelStream: AsyncRead + AsyncWrite + Unpin + Send + fmt::Debug {
    /// Human-readable diagnostic label for logs/metrics (never contains secrets).
    fn transport_label(&self) -> &'static str;
}

/// Outbound byte stream connecting `mtg-proxy` to a Telegram DC, MiddleProxy, or
/// upstream target through any configured protocol.
#[derive(Debug)]
pub enum OutboundStream {
    /// Zero-cost native Linux TCP socket (direct, `SO_BINDTODEVICE`, `SO_MARK`,
    /// SOCKS5, SOCKS4, HTTP CONNECT).
    Tcp(TcpStream),
    /// Encapsulated / encrypted / Unix-IPC tunnel (`ss://`, `https://`, `unix://`,
    /// or custom [`OutboundTransport`](super::OutboundTransport)).
    Tunnel(Box<dyn TunnelStream>),
}

impl OutboundStream {
    #[inline]
    pub fn from_tcp(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }

    #[inline]
    pub fn from_tunnel<T: TunnelStream + 'static>(tunnel: T) -> Self {
        Self::Tunnel(Box::new(tunnel))
    }

    #[inline]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    #[inline]
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(s) => Some(s),
            Self::Tunnel(_) => None,
        }
    }

    #[inline]
    pub fn into_tcp(self) -> Result<TcpStream, Self> {
        match self {
            Self::Tcp(s) => Ok(s),
            other @ Self::Tunnel(_) => Err(other),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(s) => s.peer_addr(),
            Self::Tunnel(_) => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "tunneled outbound has no raw TCP peer_addr",
            )),
        }
    }

    /// Zero-overhead readiness-based read for `DirectRelay`:
    /// - `Tcp`: calls `TcpStream::try_read` directly.
    /// - `Tunnel`: calls `AsyncRead::poll_read(cx)`, mapping `Poll::Pending` to
    ///   `WouldBlock` while leaving the waker registered on `cx`.
    #[inline]
    pub fn try_read_with_cx(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.try_read(buf),
            Self::Tunnel(t) => {
                let mut rbuf = ReadBuf::new(buf);
                match Pin::new(&mut **t).poll_read(cx, &mut rbuf) {
                    Poll::Ready(Ok(())) => Ok(rbuf.filled().len()),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                }
            }
        }
    }

    /// Zero-overhead readiness-based write for `DirectRelay`.
    #[inline]
    pub fn try_write_with_cx(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.try_write(buf),
            Self::Tunnel(t) => match Pin::new(&mut **t).poll_write(cx, buf) {
                Poll::Ready(res) => res,
                Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            },
        }
    }

    /// Zero-overhead vectored write for `DirectRelay`.
    #[inline]
    pub fn try_write_vectored_with_cx(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.try_write_vectored(bufs),
            Self::Tunnel(t) => match Pin::new(&mut **t).poll_write_vectored(cx, bufs) {
                Poll::Ready(res) => res,
                Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            },
        }
    }

    /// Poll read readiness for `Tcp`; for `Tunnel`, returns `Ready(Ok(()))` so the
    /// caller invokes `try_read_with_cx` (which arms the waker on `Pending`).
    #[inline]
    pub fn poll_read_ready_compat(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tcp(s) => s.poll_read_ready(cx),
            Self::Tunnel(_) => Poll::Ready(Ok(())),
        }
    }

    /// Poll write readiness for `Tcp`; for `Tunnel`, returns `Pending` because
    /// `try_write_with_cx` already armed the waker on `Pending`.
    #[inline]
    pub fn poll_write_ready_compat(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tcp(s) => s.poll_write_ready(cx),
            Self::Tunnel(_) => Poll::Pending,
        }
    }
}

impl AsyncRead for OutboundStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tunnel(t) => Pin::new(&mut **t).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tunnel(t) => Pin::new(&mut **t).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Tunnel(t) => Pin::new(&mut **t).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tunnel(t) => Pin::new(&mut **t).poll_shutdown(cx),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tunnel(t) => Pin::new(&mut **t).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Tunnel(t) => t.is_write_vectored(),
        }
    }
}

/// Successful outbound dial result returned by [`super::OutboundTransport::dial`].
#[derive(Debug)]
pub struct DialResult {
    /// Connected stream ready for MTProto / RPC / HTTP payload.
    pub stream: OutboundStream,
    /// Optional upstream-assigned source/bound address (e.g. SOCKS5 `BND.ADDR:BND.PORT`,
    /// used by MiddleProxy KDF when exiting through NATed proxies).
    pub bound_addr: Option<SocketAddr>,
    /// Name of the outbound that served this dial.
    pub outbound_name: Arc<str>,
    /// Measured dial latency in microseconds.
    pub rtt_us: u64,
}
