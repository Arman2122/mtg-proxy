//! Zero-copy Linux domain fronting (`splice(2)` kernel-to-kernel pipe relay)
//! with verbatim ClientHello replay and optional PROXY protocol v2 header.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mtg_net::{DnsResolver, ProxyPool, ProxyTarget, SocketConfig, SplicePipe, tune_tokio_stream};
use mtg_protocol::proxyproto::encode_v2_tcp;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tracing::debug;

use crate::metrics::CoreMetrics;

/// Parameters for forwarding an unmatched/replayed/denied FakeTLS client
/// transparently to a cover website.
#[derive(Debug, Clone)]
pub struct FrontingTarget {
    pub host: String,
    pub port: u16,
    pub send_proxy_v2: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

/// Replay `initial_bytes` (the raw TLS ClientHello bytes already read from the
/// client) to `target` and relay both directions with Linux `splice(2)` zero-copy
/// kernel pipes until either side closes or `idle_timeout` fires.
#[allow(clippy::too_many_arguments)]
pub async fn front_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    initial_bytes: &[u8],
    target: &FrontingTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
    core_metrics: &CoreMetrics,
) {
    if target.host.is_empty() {
        return;
    }

    let is_v4 = client_addr.is_ipv4();
    core_metrics.fronted_total.fetch_add(1, Ordering::Relaxed);
    if is_v4 {
        core_metrics
            .fronted_conns_v4
            .fetch_add(1, Ordering::Relaxed);
    } else {
        core_metrics
            .fronted_conns_v6
            .fetch_add(1, Ordering::Relaxed);
    }

    let _guard = FrontedConnGuard {
        core_metrics,
        is_v4,
    };

    let Ok(mut origin) = dial_fronting_origin(target, dns, proxy_pool, sock_cfg).await else {
        debug!(host = %target.host, port = target.port, "fronting origin dial failed");
        return;
    };

    // Optional PROXY v2 header toward fronting reverse proxy (e.g. nginx/caddy).
    if target.send_proxy_v2 {
        let hdr = encode_v2_tcp(client_addr, local_addr);
        if origin.write_all(hdr.as_slice()).await.is_err() {
            return;
        }
    }

    // Replay the exact ClientHello bytes already consumed during FakeTLS inspection.
    if !initial_bytes.is_empty() {
        if origin.write_all(initial_bytes).await.is_err() {
            return;
        }
        core_metrics
            .fronted_bytes_from_client
            .fetch_add(initial_bytes.len() as u64, Ordering::Relaxed);
    }

    // Bidirectional zero-copy kernel `splice(2)` relay using non-blocking Linux pipes!
    let idle = if target.idle_timeout.is_zero() {
        Duration::from_secs(60)
    } else {
        target.idle_timeout
    };

    let _ = splice_bidirectional(&mut client, &mut origin, idle, core_metrics).await;
}

struct FrontedConnGuard<'a> {
    core_metrics: &'a CoreMetrics,
    is_v4: bool,
}

impl Drop for FrontedConnGuard<'_> {
    fn drop(&mut self) {
        if self.is_v4 {
            self.core_metrics
                .fronted_conns_v4
                .fetch_sub(1, Ordering::Relaxed);
        } else {
            self.core_metrics
                .fronted_conns_v6
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

async fn dial_fronting_origin(
    target: &FrontingTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
) -> io::Result<TcpStream> {
    let timeout = if target.connect_timeout.is_zero() {
        Duration::from_secs(10)
    } else {
        target.connect_timeout
    };

    if let Some(pool) = proxy_pool
        && !pool.is_empty()
    {
        return tokio::time::timeout(
            timeout,
            pool.dial(&ProxyTarget::Domain(target.host.clone(), target.port)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting proxy dial timeout"))?
        .map_err(|e| io::Error::other(e.to_string()));
    }

    let addrs = tokio::time::timeout(timeout, dns.resolve_socket_addrs(&target.host, target.port))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting DNS timeout"))??;

    let mut last_err = io::Error::other("no fronting address");
    for sa in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(sa)).await {
            Ok(Ok(stream)) => {
                let _ = tune_tokio_stream(&stream, sock_cfg);
                return Ok(stream);
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => {
                last_err = io::Error::new(io::ErrorKind::TimedOut, "fronting connect timeout");
            }
        }
    }
    Err(last_err)
}

/// Zero-copy bidirectional Linux `splice(2)` copy between two `TcpStream`s
/// with automatic fallback to `tokio::io::copy_bidirectional` if pipe creation
/// or `splice(2)` is disallowed (`EINVAL` / `ENOSYS` / `EPERM` under strict
/// sandboxes or exotic kernels).
async fn splice_bidirectional(
    client: &mut TcpStream,
    origin: &mut TcpStream,
    idle_timeout: Duration,
    core_metrics: &CoreMetrics,
) -> io::Result<()> {
    let Ok(pipe_c2o) = SplicePipe::new() else {
        let _ =
            tokio::time::timeout(idle_timeout, tokio::io::copy_bidirectional(client, origin)).await;
        return Ok(());
    };
    let Ok(pipe_o2c) = SplicePipe::new() else {
        let _ =
            tokio::time::timeout(idle_timeout, tokio::io::copy_bidirectional(client, origin)).await;
        return Ok(());
    };

    let c2o = splice_one_way(client, origin, &pipe_c2o, idle_timeout, true, core_metrics);
    let o2c = splice_one_way(origin, client, &pipe_o2c, idle_timeout, false, core_metrics);
    let (r1, r2) = tokio::join!(c2o, o2c);
    if is_splice_unsupported(&r1) || is_splice_unsupported(&r2) {
        let _ =
            tokio::time::timeout(idle_timeout, tokio::io::copy_bidirectional(client, origin)).await;
    }
    Ok(())
}

#[inline]
fn is_splice_unsupported(res: &io::Result<()>) -> bool {
    let Err(e) = res else {
        return false;
    };
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EPERM)
    )
}

async fn splice_one_way(
    src: &TcpStream,
    dst: &TcpStream,
    pipe: &SplicePipe,
    idle_timeout: Duration,
    from_client: bool,
    core_metrics: &CoreMetrics,
) -> io::Result<()> {
    const CHUNK: usize = 65_536;
    let flags = libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE;
    let mut in_pipe: usize = 0;

    loop {
        if in_pipe == 0 {
            tokio::time::timeout(idle_timeout, src.readable())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting idle"))??;
            let res = src.try_io(tokio::io::Interest::READABLE, || {
                // SAFETY: `src` and `pipe` are valid non-blocking Linux fds.
                let n = unsafe {
                    libc::splice(
                        src.as_raw_fd(),
                        std::ptr::null_mut(),
                        pipe.write_fd(),
                        std::ptr::null_mut(),
                        CHUNK,
                        flags,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(0) => {
                    // Half-close write direction on `dst` cleanly.
                    // SAFETY: `dst` is a valid TCP socket fd.
                    unsafe {
                        let _ = libc::shutdown(dst.as_raw_fd(), libc::SHUT_WR);
                    }
                    return Ok(());
                }
                Ok(n) => in_pipe = n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }

        while in_pipe > 0 {
            tokio::time::timeout(idle_timeout, dst.writable())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting write idle"))??;
            let res = dst.try_io(tokio::io::Interest::WRITABLE, || {
                // SAFETY: `pipe` and `dst` are valid non-blocking Linux fds.
                let n = unsafe {
                    libc::splice(
                        pipe.read_fd(),
                        std::ptr::null_mut(),
                        dst.as_raw_fd(),
                        std::ptr::null_mut(),
                        in_pipe,
                        flags,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    in_pipe -= n;
                    if from_client {
                        core_metrics
                            .fronted_bytes_from_client
                            .fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        core_metrics
                            .fronted_bytes_to_client
                            .fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}
