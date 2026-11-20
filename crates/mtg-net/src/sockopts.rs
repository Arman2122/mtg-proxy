//! Unified Linux TCP socket tuning for all three socket classes:
//! 1. Inbound listeners & accepted client sockets
//! 2. Direct outbound sockets (Telegram DCs & domain-fronting origins)
//! 3. Upstream SOCKS5 / HTTP CONNECT outbound sockets
//!
//! Fixes Go's broken `SO_REUSEPORT` post-bind placement, removes blocking
//! `SO_LINGER {1, 1}`, adds `IP_BIND_ADDRESS_NO_PORT` pre-connect, `TCP_SYNCNT`,
//! `TCP_USER_TIMEOUT`, configurable `TCP_NOTSENT_LOWAT` (`0` disables), and
//! best-effort `TCP_CONGESTION = "bbr"` with once-logged fallback on `ENOENT`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Once;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use tracing::{info, warn};

/// Default listen backlog (`somaxconn` permitting).
pub const DEFAULT_LISTEN_BACKLOG: i32 = 65_535;
/// Default `TCP_NOTSENT_LOWAT` (16 KiB) — matches bufferbloat-free pacing while
/// allowing `0` to disable cleanly.
pub const DEFAULT_TCP_NOTSENT_LOWAT: u32 = 16 * 1024;
/// Default `TCP_SYNCNT` (3 SYN retransmits ~7s instead of kernel default 6 ~127s).
pub const DEFAULT_TCP_SYNCNT: u32 = 3;
/// Default `RLIMIT_NOFILE` target raised at process startup.
pub const DEFAULT_NOFILE_TARGET: u64 = 1_048_576;
/// Default best-effort `TCP_FASTOPEN` listener queue length.
pub const DEFAULT_TCP_FASTOPEN_QLEN: i32 = 1024;

static BBR_WARN_ONCE: Once = Once::new();

/// Unified Linux socket tuning profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketConfig {
    pub keepalive_enabled: bool,
    pub keepalive_idle: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_count: u32,
    /// `TCP_NOTSENT_LOWAT` in bytes. `0` disables setting it.
    pub tcp_notsent_lowat: u32,
    /// `TCP_SYNCNT` SYN retransmit cap (0 leaves kernel default).
    pub tcp_syncnt: u32,
    /// Optional `TCP_FASTOPEN` queue length on listeners (0 disables).
    pub tcp_fastopen_qlen: i32,
    /// Optional `TCP_DEFER_ACCEPT` timeout in seconds on listeners (0 disables).
    pub tcp_defer_accept_secs: i32,
    /// Attempt best-effort `TCP_CONGESTION = "bbr"`.
    pub prefer_bbr: bool,
    /// Listen backlog passed to `listen(2)`.
    pub backlog: i32,
    /// Enable `SO_REUSEPORT` pre-bind on listeners (required for thread-per-core).
    pub reuse_port: bool,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            keepalive_enabled: true,
            keepalive_idle: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(15),
            keepalive_count: 4,
            tcp_notsent_lowat: DEFAULT_TCP_NOTSENT_LOWAT,
            tcp_syncnt: DEFAULT_TCP_SYNCNT,
            tcp_fastopen_qlen: DEFAULT_TCP_FASTOPEN_QLEN,
            tcp_defer_accept_secs: 0,
            prefer_bbr: true,
            backlog: DEFAULT_LISTEN_BACKLOG,
            reuse_port: true,
        }
    }
}

impl SocketConfig {
    /// Compute Linux `TCP_USER_TIMEOUT` in milliseconds matching keepalive probes
    /// (`idle + interval * count`), or `None` when keepalive is disabled.
    pub fn tcp_user_timeout_ms(&self) -> Option<u32> {
        if !self.keepalive_enabled {
            return None;
        }
        let total = self.keepalive_idle
            + self
                .keepalive_interval
                .saturating_mul(self.keepalive_count.max(1));
        let ms = total.as_millis().clamp(1_000, u128::from(u32::MAX)) as u32;
        Some(ms)
    }
}

/// Raise Linux `RLIMIT_NOFILE` soft limit up to `min(desired, hard_limit)`
/// (and try raising hard limit too if `CAP_SYS_RESOURCE` is available).
///
/// Returns `(soft, hard)` currently active after the attempt.
pub fn raise_nofile_limit(desired: u64) -> io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid mutable pointer to `libc::rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Best-effort raise of hard limit when privileged.
    if lim.rlim_max < desired {
        let raised = libc::rlimit {
            rlim_cur: desired,
            rlim_max: desired,
        };
        // SAFETY: `raised` is a valid initialized `libc::rlimit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) } == 0 {
            return Ok((desired, desired));
        }
    }

    let target_soft = desired.min(lim.rlim_max);
    if target_soft > lim.rlim_cur {
        let updated = libc::rlimit {
            rlim_cur: target_soft,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: `updated` is a valid initialized `libc::rlimit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const updated) } == 0 {
            lim.rlim_cur = target_soft;
        }
    }
    Ok((lim.rlim_cur, lim.rlim_max))
}

/// Create, tune, bind, and listen on a non-blocking Linux TCP listener socket.
///
/// Sets `SO_REUSEADDR` and `SO_REUSEPORT` **before** `bind(2)` so multiple
/// pinned worker threads can each own an independent kernel listen queue.
pub fn create_listener_socket(addr: SocketAddr, cfg: &SocketConfig) -> io::Result<Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    set_cloexec(sock.as_raw_fd())?;
    sock.set_reuse_address(true)?;
    if cfg.reuse_port {
        sock.set_reuse_port(true)?;
    }

    if let SocketAddr::V6(v6) = addr {
        // Explicit non-wildcard IPv6 binds V6ONLY; wildcard `[::]` permits dual-stack
        // unless operator explicitly binds v4 separately (matches Linux standard behavior).
        let v6_only = !v6.ip().is_unspecified();
        let _ = sock.set_only_v6(v6_only);
    }

    if cfg.tcp_fastopen_qlen > 0 {
        let _ = set_sockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            cfg.tcp_fastopen_qlen,
        );
    }
    if cfg.tcp_defer_accept_secs > 0 {
        let _ = set_sockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            cfg.tcp_defer_accept_secs,
        );
    }

    // Apply TCP_NODELAY, SO_KEEPALIVE, TCP_KEEP*, TCP_USER_TIMEOUT,
    // TCP_NOTSENT_LOWAT, and TCP_CONGESTION=bbr ONCE on the listener so the
    // Linux kernel automatically inherits ALL of them onto every accepted child
    // socket — eliminating 8 `setsockopt(2)` syscalls per accepted connection!
    tune_connected_fd(sock.as_raw_fd(), cfg)?;

    let sa = SockAddr::from(addr);
    sock.bind(&sa)?;
    sock.listen(cfg.backlog.max(128))?;
    Ok(sock)
}

/// Enable Linux `TCP_QUICKACK` (best-effort) to suppress 40 ms delayed ACK stalls.
#[inline]
pub fn set_tcp_quickack(fd: RawFd) {
    let _ = set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, 1);
}

/// Return the exact list of CPU core IDs permitted for this process by Linux
/// `sched_getaffinity(0)` (respecting Docker/Kubernetes/systemd cgroup cpusets!).
pub fn allowed_linux_cpus() -> Vec<usize> {
    let mut cpus = Vec::new();
    // SAFETY: zeroed `cpu_set_t` populated by `sched_getaffinity(0, ...)`.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut set) == 0 {
            for cpu in 0..(libc::CPU_SETSIZE as usize) {
                if libc::CPU_ISSET(cpu, &set) {
                    cpus.push(cpu);
                }
            }
        }
    }
    if cpus.is_empty() {
        let n = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        cpus.extend(0..n);
    }
    cpus
}

/// Create a pre-tuned non-blocking Linux outbound TCP socket ready for
/// `connect(2)` (used for Telegram DCs, fronting origins, and upstream proxies).
///
/// Sets `IP_BIND_ADDRESS_NO_PORT` before `connect(2)` to eliminate ephemeral
/// source-port exhaustion under high concurrency.
pub fn create_outbound_socket(domain: Domain, cfg: &SocketConfig) -> io::Result<Socket> {
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    set_cloexec(sock.as_raw_fd())?;

    // Pre-connect Linux optimization: share ephemeral ports across distinct destinations.
    let _ = set_sockopt_int(
        sock.as_raw_fd(),
        libc::SOL_IP,
        libc::IP_BIND_ADDRESS_NO_PORT,
        1,
    );

    if cfg.tcp_syncnt > 0 {
        let _ = set_sockopt_int(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_SYNCNT,
            cfg.tcp_syncnt as libc::c_int,
        );
    }

    tune_connected_fd(sock.as_raw_fd(), cfg)?;
    Ok(sock)
}

/// Apply post-accept / post-connect Linux TCP tuning to any live TCP fd.
///
/// Never sets `SO_LINGER {1, 1}` so `close(2)` never stalls an event-loop worker.
pub fn tune_connected_fd(fd: RawFd, cfg: &SocketConfig) -> io::Result<()> {
    set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;

    if cfg.keepalive_enabled {
        // Apply keepalive via borrowed socket2 view (without closing fd!).
        let borrowed = RawFdBorrow(fd);
        let sock_ref = socket2::SockRef::from(&borrowed);
        let ka = TcpKeepalive::new()
            .with_time(cfg.keepalive_idle)
            .with_interval(cfg.keepalive_interval)
            .with_retries(cfg.keepalive_count);
        sock_ref.set_tcp_keepalive(&ka)?;

        if let Some(user_timeout_ms) = cfg.tcp_user_timeout_ms() {
            let _ = set_sockopt_int(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                user_timeout_ms as libc::c_int,
            );
        }
    } else {
        let _ = set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 0);
    }

    if cfg.tcp_notsent_lowat > 0 {
        let _ = set_sockopt_int(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            cfg.tcp_notsent_lowat as libc::c_int,
        );
    }

    if cfg.prefer_bbr {
        try_enable_bbr(fd);
    }

    Ok(())
}

/// Apply `tune_connected_fd` to a Tokio `TcpStream` (for control-plane / proxy
/// / WebRelay async sockets so all 3 socket classes share identical tuning).
pub fn tune_tokio_stream(stream: &tokio::net::TcpStream, cfg: &SocketConfig) -> io::Result<()> {
    tune_connected_fd(stream.as_raw_fd(), cfg)
}

/// Query kernel's active congestion control name on `fd` (useful for tests/doctor).
pub fn get_tcp_congestion(fd: RawFd) -> io::Result<String> {
    let mut buf = [0u8; 32];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: `buf` is valid for `len` bytes and `len` is initialized.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            buf.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(len as usize);
    Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
}

/// Query `TCP_NOTSENT_LOWAT` on `fd`.
pub fn get_tcp_notsent_lowat(fd: RawFd) -> io::Result<u32> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `val` is a valid `c_int` pointer.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&raw mut val).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(val.max(0) as u32)
}

fn try_enable_bbr(fd: RawFd) {
    const BBR: &[u8] = b"bbr\0";
    // SAFETY: `BBR` is a valid NUL-terminated byte slice.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            BBR.as_ptr().cast(),
            3,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        BBR_WARN_ONCE.call_once(|| {
            if err.raw_os_error() == Some(libc::ENOENT) {
                info!("tcp_bbr kernel module unavailable; falling back to default TCP congestion control");
            } else {
                warn!(error = %err, "TCP_CONGESTION=bbr unavailable; falling back to kernel default");
            }
        });
    }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fcntl(F_SETFD, FD_CLOEXEC)` on a valid fd.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_sockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `val` is a valid initialized `c_int`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-owning `AsFd` wrapper for `socket2::SockRef::from`.
struct RawFdBorrow(RawFd);

impl std::os::fd::AsFd for RawFdBorrow {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: `RawFdBorrow` is strictly scoped to a live fd during `tune_connected_fd`.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_and_outbound_sockopts_apply_cleanly_on_linux() {
        let cfg = SocketConfig::default();
        let listener = create_listener_socket("127.0.0.1:0".parse().unwrap(), &cfg).unwrap();
        let local_addr = listener.local_addr().unwrap().as_socket().unwrap();

        let client = create_outbound_socket(Domain::IPV4, &cfg).unwrap();
        let _ = client.connect(&SockAddr::from(local_addr));

        // Verify Linux kernel inherited TCP_NOTSENT_LOWAT onto accepted socket
        // with ZERO post-accept setsockopt syscalls!
        let std_ln = std::net::TcpListener::from(listener);
        let _ = std_ln.set_nonblocking(false);
        let (accepted, _) = std_ln.accept().unwrap();
        assert_eq!(
            get_tcp_notsent_lowat(accepted.as_raw_fd()).unwrap(),
            DEFAULT_TCP_NOTSENT_LOWAT
        );
        assert!(!allowed_linux_cpus().is_empty());

        assert_eq!(
            get_tcp_notsent_lowat(client.as_raw_fd()).unwrap(),
            DEFAULT_TCP_NOTSENT_LOWAT
        );
        let cc = get_tcp_congestion(client.as_raw_fd()).unwrap();
        assert!(!cc.is_empty());

        // `tcp_notsent_lowat = 0` must NOT override kernel default to a tiny value.
        let cfg_zero = SocketConfig {
            tcp_notsent_lowat: 0,
            ..cfg
        };
        let c2 = create_outbound_socket(Domain::IPV4, &cfg_zero).unwrap();
        let lowat = get_tcp_notsent_lowat(c2.as_raw_fd()).unwrap();
        assert_ne!(lowat, DEFAULT_TCP_NOTSENT_LOWAT);

        let (soft, hard) = raise_nofile_limit(65_536).unwrap();
        assert!(soft > 0 && soft <= hard);
    }
}
