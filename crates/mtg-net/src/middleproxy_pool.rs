//! Persistent multiplexed MiddleProxy RPC connection pool (`K` warm
//! authenticated RPC sockets per DC, scaling dynamically from `4` up to `32`).
//!
//! Architectural upgrades over Go's 1-TCP-socket-per-client-connection model:
//! - Runs `RPC_NONCE` + `RPC_HANDSHAKE` ONCE per warm carrier socket (saving
//!   2–3 RTTs + handshake CPU on every subsequent client stream).
//! - Multiplexes many concurrent client streams (`conn_id: [u8; 8]`) over each
//!   persistent AES-256-CBC RPC carrier, dynamically adding carriers when load
//!   grows and picking the least-loaded carrier via Power-of-Two-Choices (P2C).
//! - Per-DC async dial lock eliminates thundering-herd carrier storms during
//!   startup or sudden reconnect spikes.
//! - Zero head-of-line (HOL) blocking: the carrier reader delivers downlink
//!   messages via non-blocking `try_send`; a single stalled client is evicted
//!   cleanly (`RPC_CLOSE_CONN`) without ever blocking other clients or delaying
//!   `RPC_PONG` responses!
//! - Dedicated high-priority control channel (`RPC_PONG`, `RPC_PING`,
//!   `RPC_CLOSE_CONN`) polled with `biased` priority ahead of data frames, plus
//!   proactive 30-second `RPC_PING` keepalives and write-side frame coalescing.
//! - Exact Telegram wire parity: stamps per-packet `FLAG_QUICK_ACK` and
//!   `FLAG_ENCRYPTED` (for `auth_key_id == 0` unencrypted handshakes such as
//!   `req_pq_multi`) into every `RPC_PROXY_REQ`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use mtg_crypto::Aes256CbcEncryptor;
use mtg_protocol::middleproxy::{
    AD_TAG_LEN, ClientFraming, FLAG_ENCRYPTED, FLAG_QUICK_ACK, MAX_WIRE_CLIENT_PACKET,
    NonceRequest, RPC_FLAG_USE_CRC32C, RpcDownEvent, RpcFrameDecoder, SEQ_NO_HANDSHAKE,
    SEQ_NO_NONCE, append_rpc_frame, append_rpc_frame_with_crc, build_close_conn_body,
    build_proxy_req_header_with_framing, build_rpc_ping_body, build_rpc_pong_body,
    derive_middleproxy_ciphers, handshake_request_bytes_with_flags, parse_nonce_response,
    parse_rpc_down_event, validate_handshake_response_flags,
};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, warn};

use crate::dc::{DcRouter, happy_eyeballs_connect};
use crate::outbound::{OutboundStream, OutboundTarget};
use crate::proxy_pool::{ProxyPool, ProxyTarget};
use crate::sockopts::{SocketConfig, tune_tokio_stream};
use crate::timer::coarse_now_ns;

/// Default baseline number of warm persistent MiddleProxy RPC carriers per DC.
pub const DEFAULT_CARRIERS_PER_DC: usize = 4;
/// Upper bound on dynamically scaled persistent carriers per DC under heavy load.
pub const MAX_CARRIERS_PER_DC: usize = 32;
/// Scale up an extra carrier when every live carrier for a DC carries at least
/// this many active multiplexed client streams.
const STREAMS_PER_CARRIER_SCALE_THRESHOLD: usize = 128;
/// High-priority control queue capacity (`RPC_PONG`, `RPC_PING`, `RPC_CLOSE_CONN`).
const CARRIER_CTRL_CAP: usize = 512;
/// Data-plane RPC queue capacity per carrier (`RPC_PROXY_REQ`).
const CARRIER_TX_CAP: usize = 2048;
/// Per-client downlink queue capacity (non-blocking `try_send` prevents HOL).
const STREAM_RX_CAP: usize = 256;
/// Coalesce up to 64 KiB of queued RPC frames into one CBC encrypt + `write_all`.
const WRITE_COALESCE_BYTES: usize = 64 * 1024;
/// Proactive `RPC_PING` keepalive cadence for warm idle carriers.
const CARRIER_PING_INTERVAL: Duration = Duration::from_secs(30);
/// Maximum wait for an `RPC_PONG` reply before evicting a dead/blackholed carrier.
const CARRIER_PONG_TIMEOUT_NS: u64 = 15_000_000_000;

/// Parameters identifying a client stream carried over MiddleProxy.
#[derive(Debug, Clone, Copy)]
pub struct MiddleStreamParams {
    pub dc: i32,
    pub client_addr: SocketAddr,
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
    pub advertised_port: u16,
    pub framing: ClientFraming,
    pub ad_tag: [u8; AD_TAG_LEN],
}

/// Downlink event delivered to a multiplexed [`MiddleStream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiddleDownMsg {
    /// Intermediate-framed MTProto response bytes from `RPC_PROXY_ANS`.
    Data { flags: u32, payload: Vec<u8> },
    /// Quick-ACK token from `RPC_SIMPLE_ACK` (forwarded verbatim to client).
    SimpleAck(Vec<u8>),
}

/// A single multiplexed client stream over a warm MiddleProxy RPC carrier.
#[derive(Debug)]
pub struct MiddleStream {
    conn_id: [u8; 8],
    header: [u8; 84],
    base_flags: u32,
    carrier: Arc<RpcCarrier>,
    rx: mpsc::Receiver<MiddleDownMsg>,
    remote_ip: IpAddr,
}

impl MiddleStream {
    /// Remote MiddleProxy IP address (for `connected_to_dc` observability).
    #[inline]
    pub const fn remote_ip(&self) -> IpAddr {
        self.remote_ip
    }

    /// Unique 8-byte `conn_id` on the carrier.
    #[inline]
    pub const fn conn_id(&self) -> [u8; 8] {
        self.conn_id
    }

    /// Send an MTProto intermediate/padded-intermediate client packet to Telegram
    /// wrapped in `RPC_PROXY_REQ`, stamping exact per-packet `FLAG_QUICK_ACK`
    /// and `FLAG_ENCRYPTED` (for `auth_key_id == 0` unencrypted handshakes).
    pub async fn send_packet(&self, payload: &[u8], quick_ack: bool) -> io::Result<()> {
        if payload.len() > MAX_WIRE_CLIENT_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "middleproxy payload exceeds wire maximum",
            ));
        }

        let mut flags = self.base_flags;
        if quick_ack {
            flags |= FLAG_QUICK_ACK;
        }
        if payload.len() >= 8 && payload[0..8] == [0u8; 8] {
            flags |= FLAG_ENCRYPTED;
        }

        let mut body = Vec::with_capacity(self.header.len() + payload.len());
        body.extend_from_slice(&self.header[0..4]);
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&self.header[8..]);
        body.extend_from_slice(payload);
        self.carrier.send_rpc_body(body).await
    }

    /// Receive the next decoded downlink message (`Ok(None)` on EOF/close).
    pub async fn recv_msg(&mut self) -> io::Result<Option<MiddleDownMsg>> {
        Ok(self.rx.recv().await)
    }

    /// Gracefully notify MiddleProxy (`RPC_CLOSE_CONN`) and detach from carrier.
    pub async fn close_graceful(self) {
        self.carrier.detach_stream(self.conn_id, true).await;
    }
}

impl Drop for MiddleStream {
    fn drop(&mut self) {
        self.carrier.detach_stream_sync(self.conn_id);
    }
}

#[derive(Debug)]
struct RpcCarrier {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    generation: u64,
    use_crc32c: bool,
    alive: AtomicBool,
    draining: AtomicBool,
    /// Pending `RPC_PING` ID awaiting `RPC_PONG` (`0` = none in flight).
    pending_ping_id: AtomicU64,
    pending_ping_sent_ns: AtomicU64,
    /// Most recently measured `RPC_PING -> RPC_PONG` RTT in microseconds.
    ewma_pong_rtt_us: AtomicU64,
    ctrl_tx: mpsc::Sender<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    streams: Mutex<FxHashMap<[u8; 8], mpsc::Sender<MiddleDownMsg>>>,
    active_streams: AtomicUsize,
}

impl RpcCarrier {
    #[inline]
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    #[inline]
    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    #[inline]
    fn mark_draining(&self) {
        self.draining.store(true, Ordering::Release);
    }

    #[inline]
    fn is_accepting_new(&self, current_gen: u64) -> bool {
        self.is_alive() && !self.is_draining() && self.generation == current_gen
    }

    #[inline]
    fn load(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// Record a received `RPC_PONG` matching our outstanding keepalive ping and
    /// update the carrier's EWMA RTT.
    fn record_pong(&self, ping_id: u64) {
        let pending = self.pending_ping_id.load(Ordering::Acquire);
        if pending != 0 && pending == ping_id {
            let sent_ns = self.pending_ping_sent_ns.load(Ordering::Acquire);
            self.pending_ping_id.store(0, Ordering::Release);
            if sent_ns > 0 {
                let rtt_us = coarse_now_ns().saturating_sub(sent_ns) / 1_000;
                let prev = self.ewma_pong_rtt_us.load(Ordering::Relaxed);
                let next = if prev == 0 {
                    rtt_us.max(1)
                } else {
                    (prev.saturating_mul(3).saturating_add(rtt_us.max(1))) >> 2
                };
                self.ewma_pong_rtt_us.store(next.max(1), Ordering::Relaxed);
            }
        }
    }

    /// True if an outstanding `RPC_PING` has gone unanswered past [`CARRIER_PONG_TIMEOUT_NS`].
    fn is_pong_timed_out(&self, now_ns: u64) -> bool {
        let pending = self.pending_ping_id.load(Ordering::Acquire);
        if pending == 0 {
            return false;
        }
        let sent_ns = self.pending_ping_sent_ns.load(Ordering::Acquire);
        sent_ns > 0 && now_ns.saturating_sub(sent_ns) > CARRIER_PONG_TIMEOUT_NS
    }

    async fn send_rpc_body(&self, body: Vec<u8>) -> io::Result<()> {
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "middleproxy carrier closed",
            ));
        }
        self.tx
            .send(body)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "middleproxy carrier closed"))
    }

    fn send_ctrl_nonblocking(&self, body: Vec<u8>) {
        if self.is_alive() {
            let _ = self.ctrl_tx.try_send(body);
        }
    }

    /// Allocate a fresh, non-zero `conn_id` guaranteed unique on this carrier
    /// and register its downlink channel atomically.
    fn attach_unique_stream(&self) -> io::Result<([u8; 8], mpsc::Receiver<MiddleDownMsg>)> {
        let (tx, rx) = mpsc::channel(STREAM_RX_CAP);
        let mut guard = self.streams.lock();
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "middleproxy carrier closed",
            ));
        }
        let mut conn_id = [0u8; 8];
        for _ in 0..8 {
            getrandom::fill(&mut conn_id).map_err(|e| io::Error::other(e.to_string()))?;
            if conn_id != [0u8; 8] && !guard.contains_key(&conn_id) {
                guard.insert(conn_id, tx);
                self.active_streams.fetch_add(1, Ordering::Relaxed);
                return Ok((conn_id, rx));
            }
        }
        Err(io::Error::other("failed to allocate unique conn_id"))
    }

    fn detach_stream_sync(&self, conn_id: [u8; 8]) {
        let removed = self.streams.lock().remove(&conn_id).is_some();
        if removed {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            self.send_ctrl_nonblocking(build_close_conn_body(conn_id).to_vec());
        }
    }

    async fn detach_stream(&self, conn_id: [u8; 8], send_close: bool) {
        let removed = self.streams.lock().remove(&conn_id).is_some();
        if removed {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            if send_close && self.is_alive() {
                let _ = self
                    .ctrl_tx
                    .send(build_close_conn_body(conn_id).to_vec())
                    .await;
            }
        }
    }

    fn evict_stalled_stream(&self, conn_id: [u8; 8]) {
        let removed = self.streams.lock().remove(&conn_id).is_some();
        if removed {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            self.send_ctrl_nonblocking(build_close_conn_body(conn_id).to_vec());
        }
    }

    fn fail_all(&self) {
        self.alive.store(false, Ordering::Release);
        self.streams.lock().clear();
        self.active_streams.store(0, Ordering::Relaxed);
    }
}

/// Per-DC pool of warm multiplexed [`RpcCarrier`]s with thundering-herd
/// protection, P2C least-loaded balancing, and dynamic carrier scaling.
#[derive(Debug)]
pub struct MiddleProxyPool {
    dc_router: Arc<DcRouter>,
    proxy_pool: Option<ProxyPool>,
    sock_cfg: SocketConfig,
    dial_timeout: Duration,
    carriers_per_dc: usize,
    carriers: Mutex<FxHashMap<i32, Vec<Arc<RpcCarrier>>>>,
    dial_locks: Mutex<FxHashMap<i32, Arc<tokio::sync::Mutex<()>>>>,
    rr_counter: AtomicU64,
}

impl MiddleProxyPool {
    pub fn new(
        dc_router: Arc<DcRouter>,
        proxy_pool: Option<ProxyPool>,
        sock_cfg: SocketConfig,
        dial_timeout: Duration,
        carriers_per_dc: usize,
    ) -> Self {
        Self {
            dc_router,
            proxy_pool,
            sock_cfg,
            dial_timeout,
            carriers_per_dc: carriers_per_dc.clamp(1, MAX_CARRIERS_PER_DC),
            carriers: Mutex::new(FxHashMap::default()),
            dial_locks: Mutex::new(FxHashMap::default()),
            rr_counter: AtomicU64::new(0),
        }
    }

    /// Open a multiplexed [`MiddleStream`] on a warm carrier for `params.dc`.
    pub async fn open_stream(&self, params: MiddleStreamParams) -> io::Result<MiddleStream> {
        let dc = params.dc.abs();
        let carrier = self
            .acquire_carrier(dc, params.public_ipv4, params.public_ipv6)
            .await?;

        let (conn_id, rx) = carrier.attach_unique_stream()?;

        let local_ip = match carrier.local_addr {
            SocketAddr::V4(v4) => params.public_ipv4.unwrap_or(IpAddr::V4(*v4.ip())),
            SocketAddr::V6(v6) => params.public_ipv6.unwrap_or(IpAddr::V6(*v6.ip())),
        };
        let our_addr = SocketAddr::new(local_ip, params.advertised_port);
        let header = build_proxy_req_header_with_framing(
            conn_id,
            params.client_addr,
            our_addr,
            params.ad_tag,
            params.framing,
        );
        let base_flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        Ok(MiddleStream {
            conn_id,
            header,
            base_flags,
            remote_ip: carrier.remote_addr.ip(),
            carrier,
            rx,
        })
    }

    fn dc_dial_lock(&self, dc: i32) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.dial_locks.lock();
        Arc::clone(
            locks
                .entry(dc)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    fn pick_least_loaded(&self, list: &[Arc<RpcCarrier>]) -> Arc<RpcCarrier> {
        debug_assert!(!list.is_empty());
        if list.len() == 1 {
            return Arc::clone(&list[0]);
        }
        if list.len() <= 8 {
            // Exact minimum across <= 8 warm carriers (<= 8 relaxed atomic loads).
            let mut best = &list[0];
            let mut best_load = best.load();
            for c in &list[1..] {
                let l = c.load();
                if l < best_load {
                    best = c;
                    best_load = l;
                }
            }
            return Arc::clone(best);
        }
        // Power-of-Two-Choices (P2C) for larger scaled carrier pools.
        let n = list.len();
        let tick = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let a = tick % n;
        let b = (a + 1 + ((tick >> 3) % (n - 1))) % n;
        if list[a].load() <= list[b].load() {
            Arc::clone(&list[a])
        } else {
            Arc::clone(&list[b])
        }
    }

    fn try_select_existing(&self, dc: i32) -> (Option<Arc<RpcCarrier>>, bool) {
        let current_gen = self.dc_router.middle_generation();
        let mut map = self.carriers.lock();
        let Some(list) = map.get_mut(&dc) else {
            return (None, true);
        };
        // Gracefully retire carriers from an older Telegram proxy_secret/config
        // generation: existing streams continue draining cleanly until close,
        // while new streams dial fresh carriers with the rotated secret!
        for c in list.iter() {
            if c.generation != current_gen {
                c.mark_draining();
            }
        }
        list.retain(|c| c.is_accepting_new(current_gen));
        if list.is_empty() {
            return (None, true);
        }
        let chosen = self.pick_least_loaded(list);
        let need_more = list.len() < self.carriers_per_dc
            || (list.len() < MAX_CARRIERS_PER_DC
                && chosen.load() >= STREAMS_PER_CARRIER_SCALE_THRESHOLD);
        (Some(chosen), need_more)
    }

    async fn acquire_carrier(
        &self,
        dc: i32,
        public_ipv4: Option<IpAddr>,
        public_ipv6: Option<IpAddr>,
    ) -> io::Result<Arc<RpcCarrier>> {
        // Fast path: reuse an alive warm carrier with zero async lock wait!
        let (existing, need_more) = self.try_select_existing(dc);
        if let Some(carrier) = existing
            && !need_more
        {
            return Ok(carrier);
        }

        // Slow path (cold start, carrier replacement, or scale-up): serialize
        // per-DC dials so 1,000 simultaneous logins don't dial 1,000 sockets!
        let dial_mu = self.dc_dial_lock(dc);
        let _dial_guard = dial_mu.lock().await;

        // Re-check after acquiring per-DC dial lock: a peer task may have just dialed!
        let (existing_after, still_need_more) = self.try_select_existing(dc);
        if let Some(carrier) = existing_after.as_ref()
            && !still_need_more
        {
            return Ok(Arc::clone(carrier));
        }

        match self.dial_carrier(dc, public_ipv4, public_ipv6).await {
            Ok(carrier) => {
                let mut map = self.carriers.lock();
                let list = map.entry(dc).or_default();
                list.retain(|c| c.is_alive());
                if list.len() < MAX_CARRIERS_PER_DC {
                    list.push(Arc::clone(&carrier));
                }
                Ok(carrier)
            }
            Err(e) => {
                // If scaling up failed transiently, keep serving on an existing healthy carrier!
                if let Some(fallback) = existing_after
                    && fallback.is_alive()
                {
                    return Ok(fallback);
                }
                Err(e)
            }
        }
    }

    async fn dial_carrier(
        &self,
        dc: i32,
        public_ipv4: Option<IpAddr>,
        public_ipv6: Option<IpAddr>,
    ) -> io::Result<Arc<RpcCarrier>> {
        let generation = self.dc_router.middle_generation();
        let dir = self.dc_router.directory();
        let Some(secret) = dir.proxy_secret.as_ref().filter(|s| !s.is_empty()) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "middle-proxy secret not yet fetched",
            ));
        };
        let secret = Arc::clone(secret);
        drop(dir);

        let addrs = self.dc_router.ranked_middle_addresses(dc);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no middle-proxy addresses for DC {dc}"),
            ));
        }

        let custom_router = self
            .dc_router
            .outbound_router()
            .filter(|r| !r.is_plain_direct_only());

        // Fast Happy Eyeballs attempt first when connecting directly (handles
        // IPv4-only VPSs with default `prefer-ipv6` in < 1 ms instead of timing out).
        if custom_router.is_none()
            && self.proxy_pool.as_ref().is_none_or(ProxyPool::is_empty)
            && addrs.len() > 1
            && let Ok((mut stream, first_addr)) =
                happy_eyeballs_connect(&addrs, &self.sock_cfg, self.dial_timeout).await
        {
            let local_addr = stream.local_addr()?;
            let remote_addr = stream.peer_addr().unwrap_or(first_addr);
            let key_local = compute_key_local(local_addr, public_ipv4, public_ipv6);
            match tokio::time::timeout(
                self.dial_timeout,
                perform_rpc_handshake(&mut stream, &secret, key_local, remote_addr),
            )
            .await
            {
                Ok(Ok((enc, dec, use_crc32c))) => {
                    self.dc_router.record_success(first_addr, 1_000);
                    return Ok(spawn_carrier_tasks(
                        OutboundStream::Tcp(stream),
                        enc,
                        dec,
                        local_addr,
                        remote_addr,
                        generation,
                        use_crc32c,
                    ));
                }
                Ok(Err(e)) => {
                    self.dc_router.record_failure(first_addr);
                    debug!(addr = %first_addr, error = %e, "middleproxy handshake failed on Happy Eyeballs winner; trying remaining endpoints");
                }
                Err(_) => {
                    self.dc_router.record_failure(first_addr);
                }
            }
        }

        let mut last_err = io::Error::other("no middle-proxy reached");
        for addr in addrs {
            let connect_res: io::Result<(OutboundStream, Option<SocketAddr>)> =
                if let Some(router) = &custom_router {
                    router
                        .dial_routed(
                            &OutboundTarget::Addr(addr),
                            None,
                            Some(dc),
                            self.dial_timeout,
                        )
                        .await
                        .map(|res| (res.stream, res.bound_addr))
                        .map_err(|e| io::Error::other(e.to_string()))
                } else if let Some(pool) = &self.proxy_pool
                    && !pool.is_empty()
                {
                    pool.dial_with_bound_addr(&ProxyTarget::SocketAddr(addr))
                        .await
                        .map(|(s, b)| (OutboundStream::Tcp(s), b))
                        .map_err(|e| io::Error::other(e.to_string()))
                } else {
                    tokio::time::timeout(self.dial_timeout, async {
                        let s = TcpStream::connect(addr).await?;
                        let _ = tune_tokio_stream(&s, &self.sock_cfg);
                        Ok::<(OutboundStream, Option<SocketAddr>), io::Error>((
                            OutboundStream::Tcp(s),
                            None,
                        ))
                    })
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "middle dial timeout",
                        ))
                    })
                };

            let (mut stream, socks_bound) = match connect_res {
                Ok(pair) => pair,
                Err(e) => {
                    self.dc_router.record_failure(addr);
                    last_err = e;
                    continue;
                }
            };

            // Use SOCKS5 BND.ADDR:BND.PORT or bound socket address when available so KDF matches egress!
            let fallback_local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            let local_addr = socks_bound
                .or_else(|| stream.as_tcp().and_then(|s| s.local_addr().ok()))
                .unwrap_or(fallback_local);
            let remote_addr = if socks_bound.is_some() {
                addr
            } else {
                stream
                    .as_tcp()
                    .and_then(|s| s.peer_addr().ok())
                    .unwrap_or(addr)
            };
            let key_local = compute_key_local(local_addr, public_ipv4, public_ipv6);

            match tokio::time::timeout(
                self.dial_timeout,
                perform_rpc_handshake(&mut stream, &secret, key_local, remote_addr),
            )
            .await
            {
                Ok(Ok((enc, dec, use_crc32c))) => {
                    self.dc_router.record_success(addr, 1_000);
                    return Ok(spawn_carrier_tasks(
                        stream,
                        enc,
                        dec,
                        local_addr,
                        remote_addr,
                        generation,
                        use_crc32c,
                    ));
                }
                Ok(Err(e)) => {
                    self.dc_router.record_failure(addr);
                    last_err = e;
                }
                Err(_) => {
                    self.dc_router.record_failure(addr);
                    last_err = io::Error::new(io::ErrorKind::TimedOut, "middle handshake timeout");
                }
            }
        }
        Err(last_err)
    }
}

#[inline]
fn compute_key_local(
    local_addr: SocketAddr,
    public_ipv4: Option<IpAddr>,
    public_ipv6: Option<IpAddr>,
) -> SocketAddr {
    let key_local_ip = match local_addr {
        SocketAddr::V4(v4) => public_ipv4.unwrap_or(IpAddr::V4(*v4.ip())),
        SocketAddr::V6(v6) => public_ipv6.unwrap_or(IpAddr::V6(*v6.ip())),
    };
    SocketAddr::new(key_local_ip, local_addr.port())
}

/// Run the 2-RTT `RPC_NONCE` + `RPC_HANDSHAKE` exchange over `stream`,
/// negotiating hardware Castagnoli [`RPC_FLAG_USE_CRC32C`] with automatic
/// fallback to standard IEEE CRC32 if the server does not advertise support.
async fn perform_rpc_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy_secret: &[u8],
    key_local: SocketAddr,
    remote_addr: SocketAddr,
) -> io::Result<(Aes256CbcEncryptor, RpcFrameDecoder, bool)> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let req = NonceRequest::generate(proxy_secret, ts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    // 1. Send plaintext RPC_NONCE (seq_no = -2, IEEE CRC32)
    let mut seq_no = SEQ_NO_NONCE;
    let mut wire = Vec::with_capacity(64);
    let nonce_body = req.to_bytes();
    append_rpc_frame(&mut wire, &mut seq_no, &[&nonce_body]);
    stream.write_all(&wire).await?;

    // 2. Read plaintext RPC_NONCE response (seq_no = -2)
    let mut plain_dec = RpcFrameDecoder::new(None, SEQ_NO_NONCE);
    let nonce_resp = read_next_rpc_body(stream, &mut plain_dec).await?;
    let server_nonce = parse_nonce_response(&nonce_resp, &req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // 3. Derive AES-256-CBC encryptor/decryptor
    let (mut enc, dec_cipher) =
        derive_middleproxy_ciphers(&req, &server_nonce, key_local, remote_addr, proxy_secret);

    // 4. Send encrypted RPC_HANDSHAKE (seq_no = -1, requesting USE_CRC32C)
    wire.clear();
    let hs_body = handshake_request_bytes_with_flags(RPC_FLAG_USE_CRC32C);
    append_rpc_frame(&mut wire, &mut seq_no, &[&hs_body]);
    enc.encrypt_blocks_in_place(&mut wire)
        .map_err(|e| io::Error::other(e.to_string()))?;
    stream.write_all(&wire).await?;

    // 5. Read & validate encrypted RPC_HANDSHAKE response (seq_no = -1)
    let mut enc_dec = RpcFrameDecoder::new(Some(dec_cipher), SEQ_NO_HANDSHAKE);
    let hs_resp = read_next_rpc_body(stream, &mut enc_dec).await?;
    let server_flags = validate_handshake_response_flags(&hs_resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let use_crc32c = (server_flags & RPC_FLAG_USE_CRC32C) != 0;
    enc_dec.set_use_crc32c(use_crc32c);

    Ok((enc, enc_dec, use_crc32c))
}

async fn read_next_rpc_body<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut RpcFrameDecoder,
) -> io::Result<Vec<u8>> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(body) = dec
            .next_frame()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        {
            return Ok(body);
        }
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "middleproxy EOF",
            ));
        }
        dec.push_wire_bytes(&tmp[..n]);
    }
}

fn spawn_carrier_tasks(
    stream: OutboundStream,
    mut enc: Aes256CbcEncryptor,
    mut dec: RpcFrameDecoder,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    generation: u64,
    use_crc32c: bool,
) -> Arc<RpcCarrier> {
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(CARRIER_CTRL_CAP);
    let (tx, mut rx_out) = mpsc::channel::<Vec<u8>>(CARRIER_TX_CAP);
    let carrier = Arc::new(RpcCarrier {
        remote_addr,
        local_addr,
        generation,
        use_crc32c,
        alive: AtomicBool::new(true),
        draining: AtomicBool::new(false),
        pending_ping_id: AtomicU64::new(0),
        pending_ping_sent_ns: AtomicU64::new(0),
        ewma_pong_rtt_us: AtomicU64::new(0),
        ctrl_tx: ctrl_tx.clone(),
        tx,
        streams: Mutex::new(FxHashMap::default()),
        active_streams: AtomicUsize::new(0),
    });

    let (mut rd, mut wr): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) = match stream {
        OutboundStream::Tcp(tcp) => {
            let (r, w) = tcp.into_split();
            (Box::new(r), Box::new(w))
        }
        OutboundStream::Tunnel(tunnel) => {
            let (r, w) = tokio::io::split(tunnel);
            (Box::new(r), Box::new(w))
        }
    };

    // Writer task: strictly prioritizes control frames (`RPC_PONG`, `RPC_PING`,
    // `RPC_CLOSE_CONN`), coalesces bursty data frames into single CBC + write
    // sweeps, uses negotiated CRC32C/CRC32, enforces Pong dead-carrier eviction,
    // and exits cleanly once a rotated carrier finishes draining all streams!
    let wr_carrier = Arc::clone(&carrier);
    tokio::spawn(async move {
        let mut seq_no: i32 = 0;
        let mut ping_id: u64 = 1;
        let mut wire = Vec::with_capacity(8192);
        let mut ping_tick = tokio::time::interval(CARRIER_PING_INTERVAL);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping_tick.tick().await; // consume immediate t=0 tick
        let crc32c = wr_carrier.use_crc32c;

        loop {
            if wr_carrier.is_draining() && wr_carrier.load() == 0 {
                break;
            }
            let first = tokio::select! {
                biased;
                ctrl = ctrl_rx.recv() => match ctrl {
                    Some(b) => b,
                    None => break,
                },
                data = rx_out.recv() => match data {
                    Some(b) => b,
                    None => break,
                },
                _ = ping_tick.tick() => {
                    if !wr_carrier.is_alive() {
                        break;
                    }
                    if wr_carrier.is_draining() && wr_carrier.load() == 0 {
                        break;
                    }
                    let now_ns = coarse_now_ns();
                    if wr_carrier.is_pong_timed_out(now_ns) {
                        warn!(
                            remote = %wr_carrier.remote_addr,
                            "evicting unresponsive middleproxy carrier (RPC_PONG timeout > 15s)"
                        );
                        break;
                    }
                    let id = ping_id;
                    ping_id = ping_id.wrapping_add(1).max(1);
                    wr_carrier.pending_ping_sent_ns.store(now_ns, Ordering::Release);
                    wr_carrier.pending_ping_id.store(id, Ordering::Release);
                    build_rpc_ping_body(id).to_vec()
                }
            };

            wire.clear();
            append_rpc_frame_with_crc(&mut wire, &mut seq_no, &[&first], crc32c);

            // Drain any additional ready control frames first, then coalesce ready data frames.
            while wire.len() < WRITE_COALESCE_BYTES {
                if let Ok(c) = ctrl_rx.try_recv() {
                    append_rpc_frame_with_crc(&mut wire, &mut seq_no, &[&c], crc32c);
                } else if let Ok(d) = rx_out.try_recv() {
                    append_rpc_frame_with_crc(&mut wire, &mut seq_no, &[&d], crc32c);
                } else {
                    break;
                }
            }

            if let Err(e) = enc.encrypt_blocks_in_place(&mut wire) {
                warn!(error = %e, "middleproxy CBC encrypt alignment error");
                break;
            }
            if let Err(e) = wr.write_all(&wire).await {
                debug!(remote = %wr_carrier.remote_addr, error = %e, "middleproxy carrier write error");
                break;
            }
            if wire.capacity() > (256 << 10) {
                wire.clear();
                wire.shrink_to(16_384);
            }
        }
        wr_carrier.fail_all();
    });

    // Reader task: decodes incoming RPC frames and dispatches via NON-BLOCKING
    // `try_send` so a single stalled client can NEVER freeze the carrier or
    // delay `RPC_PONG` responses!
    let rd_carrier = Arc::clone(&carrier);
    tokio::spawn(async move {
        loop {
            let body = match read_next_rpc_body(&mut rd, &mut dec).await {
                Ok(b) => b,
                Err(e) => {
                    debug!(remote = %rd_carrier.remote_addr, error = %e, "middleproxy carrier read ended");
                    break;
                }
            };
            match parse_rpc_down_event(&body) {
                Ok(RpcDownEvent::ProxyAns {
                    flags,
                    conn_id,
                    payload,
                }) => {
                    let target = rd_carrier.streams.lock().get(&conn_id).cloned();
                    if let Some(st_tx) = target {
                        match st_tx.try_send(MiddleDownMsg::Data {
                            flags,
                            payload: payload.to_vec(),
                        }) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                debug!(remote = %rd_carrier.remote_addr, "evicting stalled middleproxy stream to protect carrier");
                                rd_carrier.evict_stalled_stream(conn_id);
                            }
                            Err(TrySendError::Closed(_)) => {
                                rd_carrier.evict_stalled_stream(conn_id);
                            }
                        }
                    } else {
                        // Unknown/already-closed stream: notify MiddleProxy cleanly.
                        rd_carrier.send_ctrl_nonblocking(build_close_conn_body(conn_id).to_vec());
                    }
                }
                Ok(RpcDownEvent::SimpleAck { conn_id, payload }) => {
                    let target = rd_carrier.streams.lock().get(&conn_id).cloned();
                    if let Some(st_tx) = target
                        && st_tx
                            .try_send(MiddleDownMsg::SimpleAck(payload.to_vec()))
                            .is_err()
                    {
                        rd_carrier.evict_stalled_stream(conn_id);
                    }
                }
                Ok(RpcDownEvent::CloseExt { conn_id }) => {
                    if let Some(cid) = conn_id {
                        if rd_carrier.streams.lock().remove(&cid).is_some() {
                            rd_carrier.active_streams.fetch_sub(1, Ordering::Relaxed);
                        }
                    } else {
                        rd_carrier.fail_all();
                        break;
                    }
                }
                Ok(RpcDownEvent::Ping { ping_id }) => {
                    let _ = ctrl_tx.try_send(build_rpc_pong_body(ping_id).to_vec());
                }
                Ok(RpcDownEvent::Pong { ping_id }) => {
                    rd_carrier.record_pong(ping_id);
                }
                Err(e) => {
                    warn!(error = %e, "malformed middleproxy RPC response");
                }
            }
        }
        rd_carrier.fail_all();
    });

    carrier
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU64;

    use mtg_config::PreferIp;
    use mtg_protocol::middleproxy::{
        FLAG_ENCRYPTED, FLAG_QUICK_ACK, NonceRequest, RpcFrameDecoder, SEQ_NO_HANDSHAKE,
        SEQ_NO_NONCE, TAG_RPC_CLOSE_CONN, TAG_RPC_HANDSHAKE, TAG_RPC_NONCE, TAG_RPC_PONG,
        TAG_RPC_PROXY_ANS, TAG_RPC_PROXY_REQ, append_rpc_frame, build_rpc_ping_body,
        derive_middleproxy_server_ciphers, handshake_request_bytes,
    };
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    use super::*;
    use crate::dc::DcDirectory;

    /// Regression test for Showstopper #4 (HOL deadlock protection):
    /// When one multiplexed stream stops reading and overflows its `STREAM_RX_CAP`
    /// downlink channel, the carrier MUST evict ONLY that stalled stream (sending
    /// `RPC_CLOSE_CONN`), NEVER block the carrier reader, keep delivering packets
    /// to healthy sibling streams, and still answer `RPC_PING` with `RPC_PONG`!
    #[tokio::test]
    async fn stalled_stream_is_evicted_without_blocking_carrier_or_siblings() {
        let proxy_secret: Vec<u8> = (0u8..64)
            .map(|i| i.wrapping_mul(13).wrapping_add(7))
            .collect();
        let expected_ping: u64 = 0xfeed_face_cafe_babe;
        let pong_seen = Arc::new(AtomicU64::new(0));
        let closed_ids: Arc<Mutex<Vec<[u8; 8]>>> = Arc::new(Mutex::new(Vec::new()));

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();

        let srv_secret = proxy_secret.clone();
        let srv_pong = Arc::clone(&pong_seen);
        let srv_closed = Arc::clone(&closed_ids);
        tokio::spawn(async move {
            let (mut s, peer) = ln.accept().await.unwrap();
            let local = s.local_addr().unwrap();

            let mut plain_dec = RpcFrameDecoder::new(None, SEQ_NO_NONCE);
            let nonce_body = read_next_rpc_body(&mut s, &mut plain_dec).await.unwrap();
            let req = NonceRequest {
                key_selector: nonce_body[4..8].try_into().unwrap(),
                crypto_ts: nonce_body[12..16].try_into().unwrap(),
                nonce: nonce_body[16..32].try_into().unwrap(),
            };
            let server_nonce = [0x33u8; 16];
            let mut nresp = [0u8; 32];
            nresp[0..4].copy_from_slice(&TAG_RPC_NONCE);
            nresp[4..8].copy_from_slice(&req.key_selector);
            nresp[8..12].copy_from_slice(&[1, 0, 0, 0]);
            nresp[12..16].copy_from_slice(&req.crypto_ts);
            nresp[16..32].copy_from_slice(&server_nonce);
            let mut wr_seq = SEQ_NO_NONCE;
            let mut wire = Vec::new();
            append_rpc_frame(&mut wire, &mut wr_seq, &[&nresp]);
            s.write_all(&wire).await.unwrap();

            let (mut enc, dec_c) =
                derive_middleproxy_server_ciphers(&req, &server_nonce, peer, local, &srv_secret);
            let mut enc_dec = RpcFrameDecoder::new(Some(dec_c), SEQ_NO_HANDSHAKE);
            let hs = read_next_rpc_body(&mut s, &mut enc_dec).await.unwrap();
            assert_eq!(&hs[0..4], &TAG_RPC_HANDSHAKE);
            wire.clear();
            let hs_resp = handshake_request_bytes();
            append_rpc_frame(&mut wire, &mut wr_seq, &[&hs_resp]);
            enc.encrypt_blocks_in_place(&mut wire).unwrap();
            s.write_all(&wire).await.unwrap();

            // Receive initial packets from BOTH stalled stream and healthy sibling!
            let b1 = read_next_rpc_body(&mut s, &mut enc_dec).await.unwrap();
            assert_eq!(&b1[0..4], &TAG_RPC_PROXY_REQ);
            let stalled_cid: [u8; 8] = b1[8..16].try_into().unwrap();
            let f1 = u32::from_le_bytes(b1[4..8].try_into().unwrap());
            assert_ne!(f1 & FLAG_ENCRYPTED, 0);
            assert_ne!(f1 & FLAG_QUICK_ACK, 0);

            let b2 = read_next_rpc_body(&mut s, &mut enc_dec).await.unwrap();
            assert_eq!(&b2[0..4], &TAG_RPC_PROXY_REQ);
            let healthy_cid: [u8; 8] = b2[8..16].try_into().unwrap();

            // Flood stalled_cid with STREAM_RX_CAP + 32 responses, then send 1
            // response to healthy_cid AND 1 RPC_PING!
            wire.clear();
            for i in 0..(STREAM_RX_CAP + 32) {
                let mut ans = Vec::with_capacity(20);
                ans.extend_from_slice(&TAG_RPC_PROXY_ANS);
                ans.extend_from_slice(&0u32.to_le_bytes());
                ans.extend_from_slice(&stalled_cid);
                ans.extend_from_slice(&(i as u32).to_le_bytes());
                append_rpc_frame(&mut wire, &mut wr_seq, &[&ans]);
            }
            let mut healthy_ans = Vec::with_capacity(24);
            healthy_ans.extend_from_slice(&TAG_RPC_PROXY_ANS);
            healthy_ans.extend_from_slice(&0u32.to_le_bytes());
            healthy_ans.extend_from_slice(&healthy_cid);
            healthy_ans.extend_from_slice(b"STILL_ALIVE!");
            append_rpc_frame(&mut wire, &mut wr_seq, &[&healthy_ans]);

            let ping = build_rpc_ping_body(expected_ping);
            append_rpc_frame(&mut wire, &mut wr_seq, &[&ping]);

            enc.encrypt_blocks_in_place(&mut wire).unwrap();
            s.write_all(&wire).await.unwrap();

            while let Ok(body) = read_next_rpc_body(&mut s, &mut enc_dec).await {
                if body.len() >= 12 && body[0..4] == TAG_RPC_PONG {
                    srv_pong.store(
                        u64::from_le_bytes(body[4..12].try_into().unwrap()),
                        Ordering::Release,
                    );
                } else if body.len() >= 12 && body[0..4] == TAG_RPC_CLOSE_CONN {
                    srv_closed.lock().push(body[4..12].try_into().unwrap());
                }
            }
        });

        let router = Arc::new(DcRouter::new(
            PreferIp::OnlyIpv4,
            false,
            SocketConfig::default(),
            Duration::from_secs(2),
            None,
        ));
        let mut middle_v4 = BTreeMap::new();
        middle_v4.insert(2, vec![addr]);
        router.set_directory(DcDirectory {
            middle_v4,
            proxy_secret: Some(Arc::new(Zeroizing::new(proxy_secret))),
            ..DcDirectory::default()
        });

        // 1 carrier so both streams MUST share the exact same carrier!
        let pool = MiddleProxyPool::new(
            router,
            None,
            SocketConfig::default(),
            Duration::from_secs(2),
            1,
        );
        let params = MiddleStreamParams {
            dc: 2,
            client_addr: "198.51.100.10:55555".parse().unwrap(),
            public_ipv4: None,
            public_ipv6: None,
            advertised_port: 443,
            framing: ClientFraming::PaddedIntermediate,
            ad_tag: [0x11u8; 16],
        };

        let stalled = pool.open_stream(params).await.unwrap();
        let stalled_cid = stalled.conn_id();
        let mut healthy = pool.open_stream(params).await.unwrap();

        // Trigger flood: stalled sends auth_key_id == 0 + quick_ack, healthy sends normal packet.
        stalled.send_packet(&[0u8; 16], true).await.unwrap();
        healthy.send_packet(b"PING_HEALTHY", false).await.unwrap();

        // Healthy sibling MUST receive its response immediately even though `stalled` never reads!
        let msg = tokio::time::timeout(Duration::from_secs(2), healthy.recv_msg())
            .await
            .expect("healthy sibling must not deadlock!")
            .unwrap()
            .unwrap();
        assert_eq!(
            msg,
            MiddleDownMsg::Data {
                flags: 0,
                payload: b"STILL_ALIVE!".to_vec()
            }
        );

        // And `RPC_PONG` + `RPC_CLOSE_CONN(stalled_cid)` MUST arrive promptly!
        for _ in 0..40 {
            if pong_seen.load(Ordering::Acquire) == expected_ping
                && closed_ids.lock().contains(&stalled_cid)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(pong_seen.load(Ordering::Acquire), expected_ping);
        assert!(closed_ids.lock().contains(&stalled_cid));
        drop(stalled);
        healthy.close_graceful().await;
    }
}
