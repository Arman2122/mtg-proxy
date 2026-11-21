//! Linux-native networking layer for `mtg-proxy`:
//! - Primary `io_uring` driver (`UringDriver`) with automatic `epoll(7)` fallback (`EpollDriver`)
//! - Unified Linux socket tuning (`SO_REUSEPORT`, `IP_BIND_ADDRESS_NO_PORT`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`, `TCP_CONGESTION=bbr`)
//! - Zero-syscall vDSO `CLOCK_MONOTONIC_COARSE` + 4-level hierarchical [`TimerWheel`]
//! - `hickory-resolver` DNS (system, UDP/TCP, DoT, DoH)
//! - Lock-free atomic circuit-breaker + P2C EWMA upstream SOCKS5/HTTP proxy pool
//! - Unified hourly Telegram DC / MiddleProxy config fetcher + Happy Eyeballs dialer
//! - Persistent multiplexed MiddleProxy RPC carrier pool (`RPC_PING`/`RPC_PONG` + `conn_id` routing)

pub mod dc;
pub mod dns;
pub mod driver;
pub mod epoll;
pub mod middleproxy_pool;
pub mod proxy_pool;
pub mod sockopts;
pub mod timer;
pub mod uring;

pub use dc::{
    ConditionalFetch, DEFAULT_DC, DcDirectory, DcRouter, FETCH_TIMEOUT, FIRST_FETCH_GRACE,
    HAPPY_EYEBALLS_DELAY, REFRESH_PERIOD, RETRY_PERIOD, TELEGRAM_PROXY_CONFIG_V4_URL,
    TELEGRAM_PROXY_CONFIG_V6_URL, TELEGRAM_PROXY_SECRET_URL, build_tls_client_config,
    default_core_addresses, fetch_url_bytes, fetch_url_bytes_with_dns,
    fetch_url_conditional_with_dns, happy_eyeballs_connect, happy_eyeballs_connect_with,
    parse_proxy_config,
};
pub use dns::DnsResolver;
pub use driver::{
    BGID_LARGE, BGID_SMALL, BufHandle, DriverCapabilities, DriverConfig, DriverFd, DriverKind,
    IoDriver, IoEvent, LARGE_BUF_SIZE, SEND_ZC_THRESHOLD, SMALL_BUF_SIZE, SplicePipe,
    SplicePipePool, TLS_HEADROOM, signal_wake_fd,
};
pub use epoll::EpollDriver;
pub use middleproxy_pool::{
    DEFAULT_CARRIERS_PER_DC, MAX_CARRIERS_PER_DC, MiddleDownMsg, MiddleProxyPool, MiddleStream,
    MiddleStreamParams,
};
pub use proxy_pool::{
    CircuitBreaker, DEFAULT_CB_HALF_OPEN_TIMEOUT, DEFAULT_CB_OPEN_THRESHOLD,
    DEFAULT_CB_RESET_WINDOW, ProxyDialError, ProxyEndpoint, ProxyPool, ProxyScheme, ProxyTarget,
    dial_via_endpoint,
};
pub use sockopts::{
    DEFAULT_LISTEN_BACKLOG, DEFAULT_NOFILE_TARGET, DEFAULT_TCP_FASTOPEN_QLEN,
    DEFAULT_TCP_NOTSENT_LOWAT, DEFAULT_TCP_SYNCNT, SocketConfig, allowed_linux_cpus,
    create_listener_socket, create_outbound_socket, get_tcp_congestion, get_tcp_notsent_lowat,
    raise_nofile_limit, set_tcp_quickack, tune_connected_fd, tune_tokio_stream,
};
pub use timer::{
    TICK_MS, TICK_NS, TimerHandle, TimerWheel, coarse_now_ns, coarse_realtime_ns, coarse_unix_secs,
    mono_now_ns,
};
pub use uring::{UringDriver, probe_uring};

/// Runtime enum selecting the fastest available Linux [`IoDriver`].
#[derive(Debug)]
pub enum AutoDriver {
    Uring(Box<UringDriver>),
    Epoll(Box<EpollDriver>),
}

/// Open `UringDriver` if the Linux kernel supports all required features;
/// otherwise transparently fall back to `EpollDriver`.
pub fn open_best_driver(cfg: DriverConfig, force_epoll: bool) -> std::io::Result<AutoDriver> {
    if !force_epoll {
        match UringDriver::new(cfg) {
            Ok(u) => return Ok(AutoDriver::Uring(Box::new(u))),
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "io_uring unavailable or restricted on this kernel; falling back to epoll(7)"
                );
            }
        }
    }
    Ok(AutoDriver::Epoll(Box::new(EpollDriver::new(cfg)?)))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::fd::OwnedFd;

    use socket2::Domain;

    use super::*;

    /// Identical Linux integration test run against BOTH `UringDriver` and `EpollDriver`:
    /// verifies accept, connect, recv with 5-byte FakeTLS headroom stamp, send (including
    /// >= 8 KiB SEND_ZC path), eventfd wakeup, and zero-copy kernel `splice(2)` fronting!
    fn run_driver_contract_suite<D: IoDriver>(mut driver: D) {
        let cfg = SocketConfig::default();

        // 1. Test eventfd wakeup
        signal_wake_fd(driver.wake_fd()).unwrap();
        let mut events = Vec::new();
        driver.submit_and_wait(100, &mut events).unwrap();
        assert!(events.iter().any(|e| matches!(e, IoEvent::Wakeup)));

        // 2. Test listener accept + recv + 5-byte headroom + large >= 16 KiB send (exercises SEND_ZC!)
        let listener = create_listener_socket("127.0.0.1:0".parse().unwrap(), &cfg).unwrap();
        let listen_addr = listener.local_addr().unwrap().as_socket().unwrap();
        let lfd = driver.register_fd(OwnedFd::from(listener)).unwrap();
        driver.arm_accept(lfd, 100).unwrap();

        let client_handle = std::thread::spawn(move || {
            let mut s = TcpStream::connect(listen_addr).unwrap();
            s.write_all(b"hello-driver").unwrap();
            let mut reply = vec![0u8; 5 + 12];
            s.read_exact(&mut reply).unwrap();
            assert_eq!(&reply[0..5], &[0x17, 0x03, 0x03, 0x00, 12]);
            assert_eq!(&reply[5..], b"hello-driver");

            // Read 16 KiB large payload (exercises SEND_ZC on io_uring!)
            let mut big = vec![0u8; 16_384];
            s.read_exact(&mut big).unwrap();
            assert!(big.iter().all(|&b| b == 0xAB));
        });

        // Wait for Accept
        let accepted_fd = loop {
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            if let Some(fd) = events.drain(..).find_map(|e| match e {
                IoEvent::Accept { token: 100, fd, .. } => Some(fd),
                _ => None,
            }) {
                break fd;
            }
        };
        let cfd = driver.register_fd(accepted_fd).unwrap();
        driver.arm_recv(cfd, 200, BGID_SMALL).unwrap();

        // Wait for Recv
        let handle = loop {
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            if let Some(h) = events.drain(..).find_map(|e| match e {
                IoEvent::Recv {
                    token: 200,
                    buf: Some(h),
                    result: Ok(n),
                    ..
                } if n > 0 => Some(h),
                _ => None,
            }) {
                break h;
            }
        };
        assert_eq!(driver.buf_slice(handle), b"hello-driver");

        // Stamp 5-byte FakeTLS header into headroom in-place!
        let framed = {
            let full = driver.buf_with_headroom_mut(handle);
            full[0..5].copy_from_slice(&[0x17, 0x03, 0x03, 0x00, 12]);
            full.to_vec()
        };
        driver.recycle_buf(handle);

        driver.queue_send(cfd, 201, framed, 0, false).unwrap();
        let big_payload = vec![0xABu8; 16_384];
        driver.queue_send(cfd, 202, big_payload, 0, true).unwrap();

        let mut sends_done = 0usize;
        while sends_done < 2 {
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            for ev in &events {
                if let IoEvent::SendComplete {
                    token: 201 | 202,
                    result: Ok(_),
                } = ev
                {
                    sends_done += 1;
                }
            }
        }
        client_handle.join().unwrap();
        driver.unregister_fd(cfd).unwrap();
        driver.unregister_fd(lfd).unwrap();

        // 3. Test async outbound connect + zero-copy kernel `splice(2)` fronting!
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr: SocketAddr = origin.local_addr().unwrap();
        let origin_thread = std::thread::spawn(move || {
            let (mut conn, _) = origin.accept().unwrap();
            let mut got = vec![0u8; 4096];
            conn.read_exact(&mut got).unwrap();
            assert!(got.iter().all(|&b| b == 0x55));
        });

        let front_listener = create_listener_socket("127.0.0.1:0".parse().unwrap(), &cfg).unwrap();
        let front_addr = front_listener.local_addr().unwrap().as_socket().unwrap();
        let flfd = driver.register_fd(OwnedFd::from(front_listener)).unwrap();
        driver.arm_accept(flfd, 300).unwrap();

        let sender_thread = std::thread::spawn(move || {
            let mut s = TcpStream::connect(front_addr).unwrap();
            s.write_all(&vec![0x55u8; 4096]).unwrap();
        });

        let src_owned = loop {
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            if let Some(fd) = events.drain(..).find_map(|e| match e {
                IoEvent::Accept { token: 300, fd, .. } => Some(fd),
                _ => None,
            }) {
                break fd;
            }
        };
        let src_dfd = driver.register_fd(src_owned).unwrap();

        let out_sock = create_outbound_socket(Domain::IPV4, &cfg).unwrap();
        let dst_dfd = driver.register_fd(OwnedFd::from(out_sock)).unwrap();
        driver.queue_connect(dst_dfd, origin_addr, 301).unwrap();

        loop {
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            if events.iter().any(|e| {
                matches!(
                    e,
                    IoEvent::Connect {
                        token: 301,
                        result: Ok(())
                    }
                )
            }) {
                break;
            }
        }

        let mut pipe_pool = SplicePipePool::new(4);
        let pipe = pipe_pool.acquire().unwrap();
        let mut spliced_total = 0usize;
        while spliced_total < 4096 {
            driver
                .queue_splice(src_dfd, dst_dfd, &pipe, (4096 - spliced_total) as u32, 302)
                .unwrap();
            events.clear();
            driver.submit_and_wait(200, &mut events).unwrap();
            for ev in &events {
                if let IoEvent::SpliceComplete {
                    token: 302,
                    result: Ok(n),
                } = ev
                {
                    spliced_total += *n;
                }
            }
        }
        pipe_pool.release(pipe);
        sender_thread.join().unwrap();
        origin_thread.join().unwrap();
        driver.unregister_fd(src_dfd).unwrap();
        driver.unregister_fd(dst_dfd).unwrap();
        driver.unregister_fd(flfd).unwrap();
    }

    #[test]
    fn epoll_driver_passes_full_linux_io_and_splice_contract() {
        let cfg = DriverConfig {
            small_bufs: 32,
            large_bufs: 16,
            ..DriverConfig::default()
        };
        let driver = EpollDriver::new(cfg).unwrap();
        assert_eq!(driver.kind(), DriverKind::Epoll);
        run_driver_contract_suite(driver);
    }

    #[test]
    fn uring_driver_passes_full_linux_io_and_splice_contract() {
        let caps = probe_uring().unwrap();
        eprintln!("Probed WSL2 Linux io_uring capabilities: {caps:?}");
        let cfg = DriverConfig {
            ring_entries: 128,
            max_files: 256,
            small_bufs: 32,
            large_bufs: 16,
            enable_send_zc: true,
        };
        let driver = UringDriver::new(cfg).unwrap();
        assert_eq!(driver.kind(), DriverKind::IoUring);
        run_driver_contract_suite(driver);
    }
}
