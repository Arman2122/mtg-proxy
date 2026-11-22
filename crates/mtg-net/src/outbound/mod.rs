//! Universal Pluggable Outbound Traffic Engine (`mtg-net::outbound`).
//!
//! Allows **any** outbound protocol to carry traffic out of `mtg-proxy` with
//! zero overhead on direct TCP paths:
//! - `direct://` (Linux `SO_BINDTODEVICE`, `SO_MARK` policy routing, source IP bind)
//! - `socks5://` / `socks5h://` (RFC 1928/1929 + `BND.ADDR` capture)
//! - `socks4://` / `socks4a://`
//! - `http://` (HTTP/1.1 CONNECT)
//! - `https://` (TLS 1.3 wrapped HTTP CONNECT via `tokio-rustls`)
//! - `ss://` (hardware-accelerated Shadowsocks AEAD-2022 SIP022 + Classic AEAD)
//! - `unix://` / `unix+socks5://` / `unix+http://` (zero-TCP-overhead Linux Unix
//!   domain sockets & abstract sockets for Xray, sing-box, VLESS-Reality,
//!   Hysteria2, Trojan, WireGuard, Tor, SSH, or any future sidecar daemon!)
//! - Custom Rust [`OutboundTransport`] plugin trait for first-class extensions.

pub mod protocols;
pub mod router;
pub mod shadowsocks;
pub mod stream;
pub mod unix;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use thiserror::Error;

pub use protocols::{
    DirectTransport, HttpConnectTransport, HttpsConnectTransport, Socks4Transport, Socks5Transport,
};
pub use router::{
    DEFAULT_DIRECT_OUTBOUND, OutboundGroupSpec, OutboundRouter, OutboundSnapshot, OutboundSpec,
    OutboundStrategy, RoutingSpec, build_transport_from_url,
};
pub use shadowsocks::{ShadowsocksStream, ShadowsocksTransport, SsCipher};
pub use stream::{DialResult, OutboundStream, TunnelStream};
pub use unix::{UnixFraming, UnixSidecarTransport, UnixTunnelStream};

/// Supported built-in outbound protocol labels advertised by `/capabilities`.
pub const SUPPORTED_OUTBOUND_PROTOCOLS: &[&str] = &[
    "direct",
    "socks5",
    "socks5h",
    "socks4",
    "socks4a",
    "http",
    "https",
    "ss-2022",
    "ss-aead",
    "unix",
    "unix+socks5",
    "unix+http",
];

/// Errors produced while configuring or dialing an outbound transport.
#[derive(Debug, Error)]
pub enum OutboundError {
    #[error("invalid outbound configuration: {0}")]
    InvalidConfig(String),
    #[error("unknown outbound: {0}")]
    UnknownOutbound(String),
    #[error("outbound circuit open: {0}")]
    CircuitOpen(String),
    #[error("outbound dial timed out: {0}")]
    Timeout(String),
    #[error("outbound DNS resolution failed: {0}")]
    Dns(String),
    #[error("outbound protocol error: {0}")]
    Protocol(String),
    #[error("all outbound candidates failed: {0}")]
    AllFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Destination endpoint passed to [`OutboundTransport::dial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundTarget {
    Addr(SocketAddr),
    HostPort(String, u16),
}

impl OutboundTarget {
    pub fn host_port_string(&self) -> String {
        match self {
            Self::Addr(sa) => sa.to_string(),
            Self::HostPort(h, p) => {
                if h.contains(':') && !h.starts_with('[') {
                    format!("[{h}]:{p}")
                } else {
                    format!("{h}:{p}")
                }
            }
        }
    }
}

/// Pluggable outbound transport trait.
///
/// Implement this trait to carry outbound MTProto traffic over any future
/// protocol (VLESS, Trojan, Hysteria2, MASQUE, QUIC, WireGuard userspace, etc.)
/// and register it into [`OutboundRouter`].
pub trait OutboundTransport: Send + Sync + fmt::Debug {
    /// Unique operator-defined outbound name (e.g. `"eu-xray"`, `"wg-de"`).
    fn name(&self) -> &str;
    /// Short protocol identifier (e.g. `"direct"`, `"ss-2022"`, `"unix+socks5"`).
    fn protocol(&self) -> &'static str;
    /// Secret-free diagnostic endpoint string safe for logs and API responses.
    fn redacted_endpoint(&self) -> &str;
    /// Establish an outbound connection to `target` within `timeout`.
    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, UnixListener};

    use super::*;
    use crate::dns::DnsResolver;
    use crate::sockopts::SocketConfig;

    #[tokio::test]
    async fn unix_sidecar_socks5_and_failover_policy_routing_work_end_to_end() {
        let tmp =
            std::env::temp_dir().join(format!("mtg-unix-sidecar-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let uln = UnixListener::bind(&tmp).unwrap();
        let sock_path = tmp.to_string_lossy().into_owned();

        // Mock Xray/sing-box SOCKS5 sidecar listening on a Linux Unix domain socket!
        let sidecar = tokio::spawn(async move {
            let (mut s, _) = uln.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x01]);
            // Reply with BND.ADDR 198.51.100.7:4433
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 198, 51, 100, 7, 0x11, 0x51])
                .await
                .unwrap();

            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        // Also spin up a direct echo TCP server for DC 4 direct route.
        let tln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = tln.local_addr().unwrap();
        let direct_srv = tokio::spawn(async move {
            let (mut s, _) = tln.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        let dns = Arc::new(DnsResolver::build(None, None, mtg_config::PreferIp::OnlyIpv4).unwrap());
        let specs = vec![
            OutboundSpec {
                name: "xray-unix".into(),
                url: format!("unix+socks5://{sock_path}"),
                weight: 100,
                interface: None,
                bind_ipv4: None,
                bind_ipv6: None,
                fwmark: None,
                max_fails: 3,
                cooldown_secs: 10,
            },
            OutboundSpec {
                name: "broken-primary".into(),
                url: "socks5://127.0.0.1:1".into(),
                weight: 100,
                interface: None,
                bind_ipv4: None,
                bind_ipv6: None,
                fwmark: None,
                max_fails: 1,
                cooldown_secs: 60,
            },
        ];
        let groups = vec![OutboundGroupSpec {
            name: "auto-exit".into(),
            strategy: OutboundStrategy::Failover,
            members: vec!["broken-primary".into(), "xray-unix".into()],
        }];
        let mut dc_routes = std::collections::BTreeMap::new();
        dc_routes.insert(2, "auto-exit".into());
        let routing = RoutingSpec {
            default_outbound: Some("direct".into()),
            dc_routes,
        };

        let router = OutboundRouter::build(
            &specs,
            &groups,
            routing,
            &[],
            &dns,
            SocketConfig::default(),
            Vec::new(),
        )
        .unwrap();

        // DC 2 routes to `auto-exit`: broken-primary fails -> seamlessly fails over to `xray-unix`!
        let mut res = router
            .dial_routed(
                &OutboundTarget::Addr("149.154.167.51:443".parse().unwrap()),
                None,
                Some(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(&*res.outbound_name, "xray-unix");
        assert_eq!(res.bound_addr, Some("198.51.100.7:4433".parse().unwrap()));
        res.stream.write_all(b"ping-xray").await.unwrap();
        let mut echo = [0u8; 9];
        res.stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping-xray");

        // Secret override `"direct"` bypasses DC 2 rule and uses zero-overhead concrete TCP!
        let mut direct_res = router
            .dial_routed(
                &OutboundTarget::Addr(direct_addr),
                Some("direct"),
                Some(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(direct_res.stream.is_tcp());
        direct_res.stream.write_all(b"fast-tcp").await.unwrap();
        let mut echo2 = [0u8; 8];
        direct_res.stream.read_exact(&mut echo2).await.unwrap();
        assert_eq!(&echo2, b"fast-tcp");

        sidecar.await.unwrap();
        direct_srv.await.unwrap();
        let _ = std::fs::remove_file(&tmp);
    }
}
