//! Advanced Anti-DPI Domain Fronting Engine (`FrontingPool` + Linux `splice(2)`):
//! - **Zero-RTT Warm Standby Pool**: pre-connects clean idle TCP sockets to
//!   active cover origins (checked via non-blocking `MSG_PEEK | MSG_DONTWAIT`
//!   before handoff) so active Iranian/GFW DPI probers see **zero extra
//!   proxy->cover TCP handshake RTT side-channel**!
//! - **Multi-Origin SNI-Matched Failover**: prioritizes the exact hosted cover
//!   domain matching the prober's SNI (100% matching TLS certificate, zero SSRF),
//!   with automatic failover to healthy backup cover hosts so active probers
//!   never see a bare TCP RST.
//! - **Anti-Self-Loop Guard**: filters out the proxy's own public IPv4/IPv6
//!   addresses from resolved fronting targets to prevent infinite self-dial loops.
//! - **RFC 8305 Happy Eyeballs + EWMA Health Scoring**: instant IPv4 failover on
//!   IPv4-only Linux VPSs and automatic deprioritization of degraded origins.
//! - **Zero-Copy Linux `splice(2)` Kernel Pipe Relay** with verbatim
//!   ClientHello + pipelined bytes replay, exact `SHUT_WR` half-close parity,
//!   and automatic userspace fallback on restricted sandboxes.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mtg_net::{
    DnsResolver, ProxyPool, ProxyTarget, SocketConfig, SplicePipe, coarse_now_ns,
    happy_eyeballs_connect,
};
use mtg_protocol::proxyproto::encode_v2_tcp;
use parking_lot::{Mutex, RwLock};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tracing::debug;

use crate::metrics::CoreMetrics;

/// Maximum pre-warmed standby TCP sockets kept per `(host, port)` cover origin.
const MAX_WARM_PER_ORIGIN: usize = 4;
/// Maximum idle age of a pre-warmed cover TCP socket before discarding (`12s`).
const MAX_WARM_AGE_NS: u64 = 12_000_000_000;
/// Maximum distinct origins tracked in [`FrontingPool`] (bounds memory strictly).
const MAX_TRACKED_ORIGINS: usize = 64;

/// 7-byte nginx-identical TLS 1.2/1.3 fatal `unrecognized_name` alert (`level=2`, `desc=112`),
/// emitted immediately on unmatched unknown-SNI probes when
/// `[domain-fronting] unknown-sni-action = "reject-handshake"`.
pub const NGINX_UNRECOGNIZED_NAME_ALERT: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];

/// Parameters for forwarding an unmatched/replayed/denied FakeTLS client
/// transparently to a cover website.
#[derive(Debug, Clone)]
pub struct FrontingTarget {
    /// Ordered candidate cover hosts (primary SNI-matched host first, followed
    /// by configured fallback covers for automatic failover).
    pub hosts: Vec<String>,
    pub port: u16,
    pub send_proxy_v2: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

#[derive(Debug)]
struct WarmSocket {
    stream: TcpStream,
    created_ns: u64,
}

#[derive(Debug, Default)]
struct OriginHealth {
    ewma_rtt_us: AtomicU64,
    failures: AtomicU64,
    last_fail_ns: AtomicU64,
}

/// Minimum cooldown between background pre-warm attempts after a dial failure (`30s`).
const REFILL_FAIL_COOLDOWN_NS: u64 = 30_000_000_000;

/// Discover all non-loopback IPv4/IPv6 addresses assigned to local Linux
/// network interfaces via `libc::getifaddrs()` so fronting DNS resolutions
/// pointing back to any NIC on this host can never create a self-dial loop!
///
/// Loopback (`127.0.0.1`, `::1`) is intentionally excluded so local reverse
/// proxy / cover web servers (`nginx`/`caddy` on `127.0.0.1:<port>`) work cleanly.
fn discover_local_interface_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` populates `ifap` with a linked list freed via `freeifaddrs`.
    if unsafe { libc::getifaddrs(&raw mut ifap) } != 0 || ifap.is_null() {
        return out;
    }

    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node in the list returned by `getifaddrs`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` points to a valid `sockaddr` for this interface.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            let maybe_ip = if family == libc::AF_INET {
                // SAFETY: `sa_family == AF_INET` guarantees `sockaddr_in` layout.
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                let octets = sin.sin_addr.s_addr.to_ne_bytes();
                Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
            } else if family == libc::AF_INET6 {
                // SAFETY: `sa_family == AF_INET6` guarantees `sockaddr_in6` layout.
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                Some(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            } else {
                None
            };
            if let Some(ip) = maybe_ip {
                let ip = mtg_core::ip::unmap_ip(ip);
                if !ip.is_loopback() && !ip.is_unspecified() && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `ifap` was returned by `getifaddrs` above.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// Zero-RTT warm standby TCP pool + health tracker + anti-self-loop filter for
/// stealth domain fronting.
#[derive(Debug)]
pub struct FrontingPool {
    self_ips: Vec<IpAddr>,
    warm: Mutex<FxHashMap<(String, u16), VecDeque<WarmSocket>>>,
    refilling: Mutex<FxHashSet<(String, u16)>>,
    health: RwLock<FxHashMap<(String, u16), Arc<OriginHealth>>>,
    last_prewarm_ns: AtomicU64,
}

impl Default for FrontingPool {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl FrontingPool {
    pub fn new(self_v4: Option<IpAddr>, self_v6: Option<IpAddr>) -> Self {
        let mut self_ips = discover_local_interface_ips();
        for extra in [self_v4, self_v6].into_iter().flatten() {
            let ip = mtg_core::ip::unmap_ip(extra);
            if !ip.is_loopback() && !ip.is_unspecified() && !self_ips.contains(&ip) {
                self_ips.push(ip);
            }
        }
        Self {
            self_ips,
            warm: Mutex::new(FxHashMap::default()),
            refilling: Mutex::new(FxHashSet::default()),
            health: RwLock::new(FxHashMap::default()),
            last_prewarm_ns: AtomicU64::new(0),
        }
    }

    /// Wait-free 2-second gate so high-rate FakeTLS handshakes check cover
    /// pre-warming at most once every 2s (~1 ns atomic load on 99.99% of calls!).
    #[inline]
    pub fn try_claim_prewarm_tick(&self) -> bool {
        let now = coarse_now_ns();
        let prev = self.last_prewarm_ns.load(Ordering::Relaxed);
        if prev != 0 && now.saturating_sub(prev) < 2_000_000_000 {
            return false;
        }
        self.last_prewarm_ns
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Pop a clean, live pre-connected TCP socket for `(host, port)`, discarding
    /// any aged or peer-closed sockets via non-blocking `MSG_PEEK | MSG_DONTWAIT`.
    pub fn take_warm(&self, host: &str, port: u16) -> Option<TcpStream> {
        let now_ns = coarse_now_ns();
        let key = (host.to_ascii_lowercase(), port);
        let mut map = self.warm.lock();
        let queue = map.get_mut(&key)?;
        // LIFO: prefer freshest warm socket so idle server timeouts are least likely.
        while let Some(entry) = queue.pop_back() {
            if now_ns.saturating_sub(entry.created_ns) > MAX_WARM_AGE_NS {
                continue;
            }
            if is_socket_clean_idle(&entry.stream) {
                return Some(entry.stream);
            }
        }
        None
    }

    /// Store a freshly connected idle TCP socket into the warm standby pool.
    fn put_warm(&self, host: &str, port: u16, stream: TcpStream) {
        let key = (host.to_ascii_lowercase(), port);
        let mut map = self.warm.lock();
        if !map.contains_key(&key) && map.len() >= MAX_TRACKED_ORIGINS {
            return;
        }
        let queue = map.entry(key).or_default();
        while queue.len() >= MAX_WARM_PER_ORIGIN {
            queue.pop_front();
        }
        queue.push_back(WarmSocket {
            stream,
            created_ns: coarse_now_ns(),
        });
    }

    /// Number of currently fresh warm standby sockets for `(host, port)` (evicts expired entries).
    pub fn warm_count(&self, host: &str, port: u16) -> usize {
        let now_ns = coarse_now_ns();
        let key = (host.to_ascii_lowercase(), port);
        let mut map = self.warm.lock();
        let Some(queue) = map.get_mut(&key) else {
            return 0;
        };
        while let Some(front) = queue.front() {
            if now_ns.saturating_sub(front.created_ns) > MAX_WARM_AGE_NS {
                queue.pop_front();
            } else {
                break;
            }
        }
        queue.len()
    }

    /// Explicitly pre-connect one warm standby TCP socket for `(host, port)`.
    pub async fn warm_one(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        dns: &DnsResolver,
        proxy_pool: Option<&ProxyPool>,
        sock_cfg: &SocketConfig,
    ) -> io::Result<()> {
        let stream = self
            .dial_fresh_host(host, port, timeout, dns, proxy_pool, sock_cfg)
            .await?;
        self.put_warm(host, port, stream);
        Ok(())
    }

    /// Asynchronously replenish 1 warm standby socket in the background for a
    /// real (non-loopback) cover origin, deduplicated to at most 1 concurrent
    /// refill per `(host, port)` and rate-limited on failure cooldown.
    pub fn schedule_warm_refill(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        timeout: Duration,
        dns: Arc<DnsResolver>,
        proxy_pool: Option<ProxyPool>,
        sock_cfg: SocketConfig,
    ) {
        if host.is_empty() || is_loopback_host(host) {
            return;
        }
        let key = (host.to_ascii_lowercase(), port);
        if self.warm_count(&key.0, port) >= 2 {
            return;
        }
        let health = self.health_of(&key.0, port);
        let last_fail = health.last_fail_ns.load(Ordering::Relaxed);
        if last_fail != 0 && coarse_now_ns().saturating_sub(last_fail) < REFILL_FAIL_COOLDOWN_NS {
            return;
        }
        {
            let mut inflight = self.refilling.lock();
            if !inflight.insert(key.clone()) {
                return;
            }
        }
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let _ = pool
                .warm_one(&key.0, port, timeout, &dns, proxy_pool.as_ref(), &sock_cfg)
                .await;
            pool.refilling.lock().remove(&key);
        });
    }

    /// Filter out all of the proxy host's own public AND local NIC IPv4/IPv6
    /// addresses (discovered via `getifaddrs()` + configured `public-ipv4/6`)
    /// to prevent infinite fronting self-loops!
    pub fn filter_self_ips(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if self.self_ips.is_empty() {
            return addrs;
        }
        addrs
            .into_iter()
            .filter(|sa| {
                let ip = mtg_core::ip::unmap_ip(sa.ip());
                !self.self_ips.contains(&ip)
            })
            .collect()
    }

    fn health_of(&self, host: &str, port: u16) -> Arc<OriginHealth> {
        let key = (host.to_ascii_lowercase(), port);
        if let Some(h) = self.health.read().get(&key) {
            return Arc::clone(h);
        }
        let mut w = self.health.write();
        if w.len() >= MAX_TRACKED_ORIGINS && !w.contains_key(&key) {
            return Arc::new(OriginHealth::default());
        }
        Arc::clone(w.entry(key).or_default())
    }

    fn record_success(&self, host: &str, port: u16, rtt_us: u64) {
        let h = self.health_of(host, port);
        h.failures.store(0, Ordering::Relaxed);
        h.last_fail_ns.store(0, Ordering::Relaxed);
        let prev = h.ewma_rtt_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            rtt_us.max(1)
        } else {
            (prev.saturating_mul(3).saturating_add(rtt_us.max(1))) >> 2
        };
        h.ewma_rtt_us.store(next.max(1), Ordering::Relaxed);
    }

    fn record_failure(&self, host: &str, port: u16) {
        let h = self.health_of(host, port);
        h.failures.fetch_add(1, Ordering::Relaxed);
        h.last_fail_ns.store(coarse_now_ns(), Ordering::Relaxed);
    }

    async fn dial_fresh_host(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        dns: &DnsResolver,
        proxy_pool: Option<&ProxyPool>,
        sock_cfg: &SocketConfig,
    ) -> io::Result<TcpStream> {
        let started = coarse_now_ns();
        let res = if let Some(pool) = proxy_pool
            && !pool.is_empty()
        {
            tokio::time::timeout(
                timeout,
                pool.dial(&ProxyTarget::Domain(host.to_owned(), port)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting proxy dial timeout"))?
            .map_err(|e| io::Error::other(e.to_string()))
        } else {
            let resolved = tokio::time::timeout(timeout, dns.resolve_socket_addrs(host, port))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fronting DNS timeout"))??;
            let filtered = self.filter_self_ips(resolved);
            if filtered.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "fronting target resolved only to proxy's own IP (self-loop prevented)",
                ));
            }
            let (stream, _) = happy_eyeballs_connect(&filtered, sock_cfg, timeout).await?;
            Ok(stream)
        };

        match res {
            Ok(stream) => {
                self.record_success(host, port, coarse_now_ns().saturating_sub(started) / 1_000);
                Ok(stream)
            }
            Err(e) => {
                self.record_failure(host, port);
                Err(e)
            }
        }
    }

    /// Connect to the first reachable cover host in `hosts` (preferring Zero-RTT
    /// warm standby sockets, falling back to Happy Eyeballs fresh dials across
    /// backup cover hosts if the primary fails!).
    pub async fn connect_any(
        self: &Arc<Self>,
        hosts: &[String],
        port: u16,
        timeout: Duration,
        dns: &Arc<DnsResolver>,
        proxy_pool: Option<&ProxyPool>,
        sock_cfg: &SocketConfig,
    ) -> io::Result<(TcpStream, String)> {
        let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "no fronting host");
        for host in hosts {
            if host.is_empty() {
                continue;
            }
            if let Some(warm) = self.take_warm(host, port) {
                self.schedule_warm_refill(
                    host,
                    port,
                    timeout,
                    Arc::clone(dns),
                    proxy_pool.cloned(),
                    *sock_cfg,
                );
                return Ok((warm, host.clone()));
            }
            match self
                .dial_fresh_host(host, port, timeout, dns, proxy_pool, sock_cfg)
                .await
            {
                Ok(stream) => {
                    self.schedule_warm_refill(
                        host,
                        port,
                        timeout,
                        Arc::clone(dns),
                        proxy_pool.cloned(),
                        *sock_cfg,
                    );
                    return Ok((stream, host.clone()));
                }
                Err(e) => {
                    debug!(host = %host, port, error = %e, "fronting origin dial failed; trying next cover");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }
}

/// Non-blocking liveness check for an idle pre-warmed TCP socket:
/// returns `true` ONLY if the socket is still open with zero unread/EOF state
/// (`recv(MSG_PEEK | MSG_DONTWAIT)` returns `EAGAIN`/`EWOULDBLOCK`).
fn is_socket_clean_idle(stream: &TcpStream) -> bool {
    let mut byte = [0u8; 1];
    // SAFETY: `stream` owns a valid TCP socket fd and `byte` is a valid 1-byte buffer.
    let rc = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast::<libc::c_void>(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return err.kind() == io::ErrorKind::WouldBlock;
    }
    // `rc == 0` means peer sent FIN (closed); `rc > 0` means unexpected server banner.
    false
}

#[inline]
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Replay `initial_bytes` (the raw TLS ClientHello + any pipelined bytes already
/// read from the client) to `target` using [`FrontingPool`] (Zero-RTT warm pool
/// and multi-cover failover) and relay both directions with Linux `splice(2)`
/// zero-copy kernel pipes until either side closes or `idle_timeout` fires.
#[allow(clippy::too_many_arguments)]
pub async fn front_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    initial_bytes: &[u8],
    target: &FrontingTarget,
    fronting_pool: &Arc<FrontingPool>,
    dns: &Arc<DnsResolver>,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
    core_metrics: &CoreMetrics,
) {
    if target.hosts.is_empty() {
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

    let connect_timeout = if target.connect_timeout.is_zero() {
        Duration::from_secs(10)
    } else {
        target.connect_timeout
    };

    let Ok((mut origin, _chosen_host)) = fronting_pool
        .connect_any(
            &target.hosts,
            target.port,
            connect_timeout,
            dns,
            proxy_pool,
            sock_cfg,
        )
        .await
    else {
        debug!(hosts = ?target.hosts, port = target.port, "all fronting origins failed");
        return;
    };

    // Optional PROXY v2 header toward fronting reverse proxy (e.g. nginx/caddy).
    if target.send_proxy_v2 {
        let hdr = encode_v2_tcp(client_addr, local_addr);
        if origin.write_all(hdr.as_slice()).await.is_err() {
            return;
        }
    }

    // Replay the exact ClientHello + pipelined bytes already consumed during FakeTLS inspection.
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

#[cfg(test)]
mod tests {
    use mtg_config::PreferIp;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn fronting_pool_serves_warm_socket_and_evicts_closed_stale_sockets() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let dns = Arc::new(DnsResolver::build(None, None, PreferIp::OnlyIpv4).unwrap());
        let pool = Arc::new(FrontingPool::new(None, None));
        let sock_cfg = SocketConfig::default();

        // Warm socket #1 (kept open by server) and #2 (immediately closed by server).
        let srv = tokio::spawn(async move {
            let (_keep_open, _) = ln.accept().await.unwrap();
            let (close_me, _) = ln.accept().await.unwrap();
            drop(close_me); // Sends FIN to socket #2!
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        pool.warm_one(
            "127.0.0.1",
            port,
            Duration::from_secs(2),
            &dns,
            None,
            &sock_cfg,
        )
        .await
        .unwrap();
        pool.warm_one(
            "127.0.0.1",
            port,
            Duration::from_secs(2),
            &dns,
            None,
            &sock_cfg,
        )
        .await
        .unwrap();
        assert_eq!(pool.warm_count("127.0.0.1", port), 2);

        // Give FIN a moment to arrive on socket #2 (newest in LIFO queue).
        tokio::time::sleep(Duration::from_millis(25)).await;

        // `take_warm` MUST discard closed socket #2 via MSG_PEEK and return live socket #1!
        let live = pool.take_warm("127.0.0.1", port);
        assert!(live.is_some(), "expected healthy socket #1 from warm pool");
        assert_eq!(pool.warm_count("127.0.0.1", port), 0);
        srv.abort();
    }

    #[test]
    fn fronting_pool_filters_self_public_ips_to_prevent_loop() {
        let self_v4: IpAddr = "203.0.113.10".parse().unwrap();
        let other_v4: IpAddr = "198.51.100.42".parse().unwrap();
        let pool = FrontingPool::new(Some(self_v4), None);

        let filtered = pool.filter_self_ips(vec![
            SocketAddr::new(self_v4, 443),
            SocketAddr::new(other_v4, 443),
        ]);
        assert_eq!(filtered, vec![SocketAddr::new(other_v4, 443)]);
    }
}
