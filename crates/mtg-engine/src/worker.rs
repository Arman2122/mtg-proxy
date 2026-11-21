//! Pinned thread-per-core Linux worker runtime (`EngineRuntime`):
//! - Raises `RLIMIT_NOFILE` at startup (`1_048_576` cap)
//! - Awaits initial `blocklist` / `allowlist` load before accepting traffic
//! - Pins each worker OS thread to its dedicated CPU core (`sched_setaffinity`)
//! - Opens independent `SO_REUSEPORT` listener sockets per worker core for
//!   zero accept-lock contention across 20+ cores!
//! - Runs a single-threaded `LocalSet` event loop per pinned core (zero
//!   work-stealing cross-core cache migrations!)
//! - Probes and reports Linux `io_uring` driver capabilities

use std::io;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use mtg_config::ListenerPolicy;
use mtg_net::{
    DEFAULT_NOFILE_TARGET, DriverCapabilities, DriverKind, SocketConfig, allowed_linux_cpus,
    create_listener_socket, probe_uring, raise_nofile_limit,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::handshake::{handle_faketls_connection, handle_obfs2_connection};
use crate::state::ProxyEngine;

/// Resolved listener specification bound on every pinned worker core via `SO_REUSEPORT`.
#[derive(Debug, Clone)]
pub enum BoundListenerSpec {
    FakeTls(SocketAddr),
    Obfs2(SocketAddr, ListenerPolicy),
}

/// Running thread-per-core engine handle (call [`Self::shutdown`] to drain and join).
#[derive(Debug)]
pub struct EngineRuntime {
    pub engine: Arc<ProxyEngine>,
    pub bound_faketls_addrs: Vec<SocketAddr>,
    pub bound_obfs2_addrs: Vec<SocketAddr>,
    pub driver_caps: DriverCapabilities,
    shutdown_tx: watch::Sender<bool>,
    workers: Vec<JoinHandle<()>>,
}

impl EngineRuntime {
    /// Start the pinned thread-per-core Linux proxy engine:
    /// 1. Raises `RLIMIT_NOFILE`.
    /// 2. Probes kernel `io_uring` capabilities.
    /// 3. Awaits initial IP blocklist / allowlist load (so connections never slip
    ///    through an empty list at boot!).
    /// 4. Binds primary FakeTLS `bind-to` and extra `[[listener]]` sockets with
    ///    `SO_REUSEPORT` pre-bind on every worker thread.
    /// 5. Spawns `worker_count` CPU-pinned OS worker threads and background
    ///    maintenance tasks.
    pub async fn start(engine: Arc<ProxyEngine>) -> io::Result<Self> {
        if let Ok((soft, hard)) = raise_nofile_limit(DEFAULT_NOFILE_TARGET) {
            info!(soft, hard, "RLIMIT_NOFILE configured");
        }

        let driver_caps = if engine.settings.force_epoll {
            DriverCapabilities {
                kind: Some(DriverKind::Epoll),
                splice: true,
                ..DriverCapabilities::default()
            }
        } else {
            probe_uring().unwrap_or(DriverCapabilities {
                kind: Some(DriverKind::Epoll),
                splice: true,
                ..DriverCapabilities::default()
            })
        };
        info!(
            io_engine = "pinned-epoll+splice",
            uring_probe = %driver_caps.kind.unwrap_or(DriverKind::Epoll),
            send_zc = driver_caps.send_zc,
            buf_ring = driver_caps.buf_ring,
            "Linux I/O engine initialized"
        );

        // Await initial IP filter load (warm cache + inline CIDRs + live fetch)
        // before accepting traffic so connections never slip through an empty list at boot!
        if let Some(bl) = &engine.blocklist {
            match bl.init_load().await {
                Ok(n) => {
                    engine
                        .metrics
                        .blocklist_size
                        .store(n as u64, std::sync::atomic::Ordering::Release);
                }
                Err(e) => warn!(error = %e, "initial blocklist load failed"),
            }
        }
        if let Some(al) = &engine.allowlist {
            match al.init_load().await {
                Ok(n) => {
                    engine
                        .metrics
                        .allowlist_size
                        .store(n as u64, std::sync::atomic::Ordering::Release);
                }
                Err(e) => warn!(error = %e, "initial allowlist load failed"),
            }
        }

        // Resolve and pre-bind worker 0's listeners first so port `:0` assignments
        // are known (and shared across all SO_REUSEPORT worker threads!) and bind
        // failures surface synchronously to the caller!
        let sock_cfg = engine.settings.sock_cfg;
        let mut specs: Vec<BoundListenerSpec> = Vec::new();
        let mut bound_faketls_addrs = Vec::new();
        let mut bound_obfs2_addrs = Vec::new();
        let mut worker0_sockets: Vec<(std::net::TcpListener, BoundListenerSpec)> = Vec::new();

        for raw in &engine.settings.bind_to {
            let sa = resolve_bind_addr(raw)?;
            let sock = create_listener_socket(sa, &sock_cfg)?;
            let actual = sock
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("non-IP listener socket"))?;
            let spec = BoundListenerSpec::FakeTls(actual);
            bound_faketls_addrs.push(actual);
            specs.push(spec.clone());
            worker0_sockets.push((std::net::TcpListener::from(sock), spec));
        }

        for (raw, policy) in &engine.settings.listeners {
            let sa = resolve_bind_addr(raw)?;
            let sock = create_listener_socket(sa, &sock_cfg)?;
            let actual = sock
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("non-IP listener socket"))?;
            let spec = BoundListenerSpec::Obfs2(actual, *policy);
            bound_obfs2_addrs.push(actual);
            specs.push(spec.clone());
            worker0_sockets.push((std::net::TcpListener::from(sock), spec));
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        engine.spawn_background_tasks(shutdown_rx.clone());

        let allowed_cpus = Arc::new(allowed_linux_cpus());
        let worker_count = engine.settings.worker_count.max(1);
        let mut workers = Vec::with_capacity(worker_count);

        for wid in 0..worker_count {
            let prebound = if wid == 0 {
                std::mem::take(&mut worker0_sockets)
            } else {
                bind_worker_sockets(&specs, &sock_cfg)?
            };

            let eng = Arc::clone(&engine);
            let sd = shutdown_rx.clone();
            let target_cpu = allowed_cpus[wid % allowed_cpus.len()];
            let handle = thread::Builder::new()
                .name(format!("mtg-worker-{wid}"))
                .spawn(move || {
                    pin_current_thread_to_cpu(target_cpu);
                    run_worker_thread(wid as u16, prebound, eng, sd);
                })?;
            workers.push(handle);
        }

        info!(
            workers = worker_count,
            faketls = ?bound_faketls_addrs,
            obfs2 = ?bound_obfs2_addrs,
            "mtg-proxy engine started"
        );

        Ok(Self {
            engine,
            bound_faketls_addrs,
            bound_obfs2_addrs,
            driver_caps,
            shutdown_tx,
            workers,
        })
    }

    /// Gracefully stop listeners, cancel active streams, flush `usage.json`, and
    /// join all worker threads.
    pub fn shutdown(self) {
        self.engine.begin_shutdown();
        let _ = self.shutdown_tx.send(true);
        for w in self.workers {
            let _ = w.join();
        }
        if let Some(path) = &self.engine.settings.usage_state_file {
            let _ = self.engine.metrics.flush_usage_atomic(path);
        }
    }
}

fn bind_worker_sockets(
    specs: &[BoundListenerSpec],
    sock_cfg: &SocketConfig,
) -> io::Result<Vec<(std::net::TcpListener, BoundListenerSpec)>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let sa = match spec {
            BoundListenerSpec::FakeTls(a) | BoundListenerSpec::Obfs2(a, _) => *a,
        };
        let sock = create_listener_socket(sa, sock_cfg)?;
        out.push((std::net::TcpListener::from(sock), spec.clone()));
    }
    Ok(out)
}

fn run_worker_thread(
    worker_id: u16,
    listeners: Vec<(std::net::TcpListener, BoundListenerSpec)>,
    engine: Arc<ProxyEngine>,
    mut shutdown: watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("single-threaded worker tokio runtime");

    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(async move {
        let mut accept_tasks = Vec::with_capacity(listeners.len());
        for (std_ln, spec) in listeners {
            let Ok(ln) = TcpListener::from_std(std_ln) else {
                continue;
            };
            let eng = Arc::clone(&engine);
            let mut sd = shutdown.clone();
            let task = tokio::task::spawn_local(async move {
                let local_addr = ln
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid"));
                loop {
                    tokio::select! {
                        _ = sd.changed() => {
                            if *sd.borrow() {
                                break;
                            }
                        }
                        res = ln.accept() => {
                            let Ok((stream, peer)) = res else {
                                if *sd.borrow() {
                                    break;
                                }
                                continue;
                            };
                            // All 8 TCP options (TCP_NODELAY, SO_KEEPALIVE, TCP_KEEP*,
                            // TCP_USER_TIMEOUT, TCP_NOTSENT_LOWAT, TCP_CONGESTION=bbr)
                            // were inherited directly from the pre-tuned SO_REUSEPORT
                            // listener socket by the Linux kernel — ZERO syscalls here!
                            let eng_conn = Arc::clone(&eng);
                            match &spec {
                                BoundListenerSpec::FakeTls(_) => {
                                    tokio::task::spawn_local(handle_faketls_connection(
                                        stream,
                                        peer,
                                        local_addr,
                                        worker_id,
                                        eng_conn,
                                    ));
                                }
                                BoundListenerSpec::Obfs2(_, pol) => {
                                    let policy = *pol;
                                    tokio::task::spawn_local(handle_obfs2_connection(
                                        stream,
                                        peer,
                                        policy,
                                        worker_id,
                                        eng_conn,
                                    ));
                                }
                            }
                        }
                    }
                }
            });
            accept_tasks.push(task);
        }

        // Wait until shutdown signal fires.
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        for t in accept_tasks {
            let _ = t.await;
        }
    }));
}

fn resolve_bind_addr(raw: &str) -> io::Result<SocketAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Some(port) = raw.strip_prefix(':') {
        let p: u16 = port.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad bind {raw:?}"))
        })?;
        return Ok(SocketAddr::from(([0, 0, 0, 0], p)));
    }
    raw.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cannot resolve {raw:?}"),
        )
    })
}

/// Pin current worker OS thread to exact allowed Linux CPU `target_cpu` via `sched_setaffinity`.
fn pin_current_thread_to_cpu(target_cpu: usize) {
    // SAFETY: zeroed `cpu_set_t` + `CPU_SET` + `sched_setaffinity(0, ...)` for current thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(target_cpu, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set);
    }
}
