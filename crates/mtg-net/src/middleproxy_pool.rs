//! Persistent multiplexed MiddleProxy RPC connection pool (`K` warm
//! authenticated RPC sockets per DC, default `K = 4`).
//!
//! Architectural upgrade over Go's 1-TCP-socket-per-client-connection model:
//! - Runs `RPC_NONCE` + `RPC_HANDSHAKE` ONCE per warm carrier socket.
//! - Multiplexes many concurrent client streams (`conn_id: [u8; 8]`) over each
//!   persistent AES-256-CBC RPC carrier, eliminating per-client RTT + handshake CPU.
//! - Handles `RPC_PROXY_REQ`, `RPC_PROXY_ANS`, `RPC_SIMPLE_ACK`, `RPC_CLOSE_EXT`,
//!   `RPC_CLOSE_CONN`, and **`RPC_PING` / `RPC_PONG`** keepalives (which Go dropped!).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use mtg_crypto::Aes256CbcEncryptor;
use mtg_protocol::middleproxy::{
    AD_TAG_LEN, MAX_WIRE_CLIENT_PACKET, NonceRequest, RpcDownEvent, RpcFrameDecoder,
    SEQ_NO_HANDSHAKE, SEQ_NO_NONCE, append_rpc_frame, build_close_conn_body,
    build_proxy_req_header, build_rpc_pong_body, derive_middleproxy_ciphers,
    handshake_request_bytes, parse_nonce_response, parse_rpc_down_event,
    validate_handshake_response,
};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::dc::DcRouter;
use crate::proxy_pool::{ProxyPool, ProxyTarget};
use crate::sockopts::{SocketConfig, tune_tokio_stream};

/// Default number of warm persistent MiddleProxy RPC carriers per DC.
pub const DEFAULT_CARRIERS_PER_DC: usize = 4;
const CARRIER_TX_CAP: usize = 1024;
const STREAM_RX_CAP: usize = 64;

/// Parameters identifying a client stream carried over MiddleProxy.
#[derive(Debug, Clone, Copy)]
pub struct MiddleStreamParams {
    pub dc: i32,
    pub client_addr: SocketAddr,
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
    pub advertised_port: u16,
    pub padded_intermediate: bool,
    pub ad_tag: [u8; AD_TAG_LEN],
}

/// Downlink event delivered to a multiplexed [`MiddleStream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiddleDownMsg {
    /// Intermediate-framed MTProto response bytes (with optional quick-ack bit).
    Data { flags: u32, payload: Vec<u8> },
    /// Quick-ACK token from `RPC_SIMPLE_ACK`.
    SimpleAck(Vec<u8>),
}

/// A single multiplexed client stream over a warm MiddleProxy RPC carrier.
#[derive(Debug)]
pub struct MiddleStream {
    conn_id: [u8; 8],
    header: [u8; 84],
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
    /// wrapped in `RPC_PROXY_REQ`.
    pub async fn send_packet(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_WIRE_CLIENT_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "middleproxy payload exceeds wire maximum",
            ));
        }
        let mut body = Vec::with_capacity(self.header.len() + payload.len());
        body.extend_from_slice(&self.header);
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
    alive: AtomicBool,
    tx: mpsc::Sender<Vec<u8>>,
    streams: Mutex<FxHashMap<[u8; 8], mpsc::Sender<MiddleDownMsg>>>,
    active_streams: AtomicUsize,
}

impl RpcCarrier {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
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

    fn attach_stream(&self, conn_id: [u8; 8]) -> mpsc::Receiver<MiddleDownMsg> {
        let (tx, rx) = mpsc::channel(STREAM_RX_CAP);
        self.streams.lock().insert(conn_id, tx);
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        rx
    }

    fn detach_stream_sync(&self, conn_id: [u8; 8]) {
        let removed = self.streams.lock().remove(&conn_id).is_some();
        if removed {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            if self.is_alive() {
                let _ = self.tx.try_send(build_close_conn_body(conn_id).to_vec());
            }
        }
    }

    async fn detach_stream(&self, conn_id: [u8; 8], send_close: bool) {
        let removed = self.streams.lock().remove(&conn_id).is_some();
        if removed {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            if send_close && self.is_alive() {
                let _ = self.tx.send(build_close_conn_body(conn_id).to_vec()).await;
            }
        }
    }

    fn fail_all(&self) {
        self.alive.store(false, Ordering::Release);
        self.streams.lock().clear();
        self.active_streams.store(0, Ordering::Relaxed);
    }
}

/// Per-DC pool of `K` warm multiplexed [`RpcCarrier`]s.
#[derive(Debug)]
pub struct MiddleProxyPool {
    dc_router: Arc<DcRouter>,
    proxy_pool: Option<ProxyPool>,
    sock_cfg: SocketConfig,
    dial_timeout: Duration,
    carriers_per_dc: usize,
    carriers: Mutex<FxHashMap<i32, Vec<Arc<RpcCarrier>>>>,
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
            carriers_per_dc: carriers_per_dc.max(1),
            carriers: Mutex::new(FxHashMap::default()),
            rr_counter: AtomicU64::new(0),
        }
    }

    /// Open a multiplexed [`MiddleStream`] on a warm carrier for `params.dc`.
    pub async fn open_stream(&self, params: MiddleStreamParams) -> io::Result<MiddleStream> {
        let dc = params.dc.abs();
        let carrier = self
            .acquire_carrier(dc, params.public_ipv4, params.public_ipv6)
            .await?;

        let mut conn_id = [0u8; 8];
        getrandom::fill(&mut conn_id).map_err(|e| io::Error::other(e.to_string()))?;

        let local_ip = match carrier.local_addr {
            SocketAddr::V4(v4) => params.public_ipv4.unwrap_or(IpAddr::V4(*v4.ip())),
            SocketAddr::V6(v6) => params.public_ipv6.unwrap_or(IpAddr::V6(*v6.ip())),
        };
        let our_addr = SocketAddr::new(local_ip, params.advertised_port);
        let header = build_proxy_req_header(
            conn_id,
            params.client_addr,
            our_addr,
            params.ad_tag,
            params.padded_intermediate,
        );
        let rx = carrier.attach_stream(conn_id);

        Ok(MiddleStream {
            conn_id,
            header,
            remote_ip: carrier.remote_addr.ip(),
            carrier,
            rx,
        })
    }

    async fn acquire_carrier(
        &self,
        dc: i32,
        public_ipv4: Option<IpAddr>,
        public_ipv6: Option<IpAddr>,
    ) -> io::Result<Arc<RpcCarrier>> {
        {
            let mut map = self.carriers.lock();
            if let Some(list) = map.get_mut(&dc) {
                list.retain(|c| c.is_alive());
                if list.len() >= self.carriers_per_dc {
                    let idx =
                        (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % list.len();
                    return Ok(Arc::clone(&list[idx]));
                }
            }
        }

        let carrier = self.dial_carrier(dc, public_ipv4, public_ipv6).await?;
        let mut map = self.carriers.lock();
        let list = map.entry(dc).or_default();
        list.retain(|c| c.is_alive());
        if list.len() < self.carriers_per_dc {
            list.push(Arc::clone(&carrier));
        }
        Ok(carrier)
    }

    async fn dial_carrier(
        &self,
        dc: i32,
        public_ipv4: Option<IpAddr>,
        public_ipv6: Option<IpAddr>,
    ) -> io::Result<Arc<RpcCarrier>> {
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

        let mut last_err = io::Error::other("no middle-proxy reached");
        for addr in addrs {
            let connect_res = if let Some(pool) = &self.proxy_pool
                && !pool.is_empty()
            {
                pool.dial(&ProxyTarget::SocketAddr(addr))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))
            } else {
                tokio::time::timeout(self.dial_timeout, async {
                    let s = TcpStream::connect(addr).await?;
                    let _ = tune_tokio_stream(&s, &self.sock_cfg);
                    Ok::<TcpStream, io::Error>(s)
                })
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "middle dial timeout",
                    ))
                })
            };

            let mut stream = match connect_res {
                Ok(s) => s,
                Err(e) => {
                    self.dc_router.record_failure(addr);
                    last_err = e;
                    continue;
                }
            };

            let local_addr = stream.local_addr()?;
            let remote_addr = stream.peer_addr().unwrap_or(addr);
            let key_local_ip = match local_addr {
                SocketAddr::V4(v4) => public_ipv4.unwrap_or(IpAddr::V4(*v4.ip())),
                SocketAddr::V6(v6) => public_ipv6.unwrap_or(IpAddr::V6(*v6.ip())),
            };
            let key_local = SocketAddr::new(key_local_ip, local_addr.port());

            match perform_rpc_handshake(&mut stream, &secret, key_local, remote_addr).await {
                Ok((enc, dec)) => {
                    self.dc_router.record_success(addr, 1_000);
                    return Ok(spawn_carrier_tasks(
                        stream,
                        enc,
                        dec,
                        local_addr,
                        remote_addr,
                    ));
                }
                Err(e) => {
                    self.dc_router.record_failure(addr);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }
}

/// Run the 2-RTT `RPC_NONCE` + `RPC_HANDSHAKE` exchange over `stream` and return
/// the initialized AES-256-CBC encryptor and incremental [`RpcFrameDecoder`].
async fn perform_rpc_handshake(
    stream: &mut TcpStream,
    proxy_secret: &[u8],
    key_local: SocketAddr,
    remote_addr: SocketAddr,
) -> io::Result<(Aes256CbcEncryptor, RpcFrameDecoder)> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let req = NonceRequest::generate(proxy_secret, ts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    // 1. Send plaintext RPC_NONCE (seq_no = -2)
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

    // 4. Send encrypted RPC_HANDSHAKE (seq_no = -1)
    wire.clear();
    let hs_body = handshake_request_bytes();
    append_rpc_frame(&mut wire, &mut seq_no, &[&hs_body]);
    enc.encrypt_blocks_in_place(&mut wire)
        .map_err(|e| io::Error::other(e.to_string()))?;
    stream.write_all(&wire).await?;

    // 5. Read & validate encrypted RPC_HANDSHAKE response (seq_no = -1)
    let mut enc_dec = RpcFrameDecoder::new(Some(dec_cipher), SEQ_NO_HANDSHAKE);
    let hs_resp = read_next_rpc_body(stream, &mut enc_dec).await?;
    validate_handshake_response(&hs_resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok((enc, enc_dec))
}

async fn read_next_rpc_body<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut RpcFrameDecoder,
) -> io::Result<Vec<u8>> {
    let mut tmp = [0u8; 4096];
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
    stream: TcpStream,
    mut enc: Aes256CbcEncryptor,
    mut dec: RpcFrameDecoder,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Arc<RpcCarrier> {
    let (tx, mut rx_out) = mpsc::channel::<Vec<u8>>(CARRIER_TX_CAP);
    let carrier = Arc::new(RpcCarrier {
        remote_addr,
        local_addr,
        alive: AtomicBool::new(true),
        tx: tx.clone(),
        streams: Mutex::new(FxHashMap::default()),
        active_streams: AtomicUsize::new(0),
    });

    let (mut rd, mut wr) = stream.into_split();

    // Writer task: frames, CRC32s, encrypts, and sends queued RPC bodies sequentially (starting at seq_no = 0).
    let wr_carrier = Arc::clone(&carrier);
    tokio::spawn(async move {
        let mut seq_no: i32 = 0;
        let mut wire = Vec::with_capacity(4096);
        while let Some(body) = rx_out.recv().await {
            wire.clear();
            append_rpc_frame(&mut wire, &mut seq_no, &[&body]);
            if let Err(e) = enc.encrypt_blocks_in_place(&mut wire) {
                warn!(error = %e, "middleproxy CBC encrypt alignment error");
                break;
            }
            if let Err(e) = wr.write_all(&wire).await {
                debug!(remote = %wr_carrier.remote_addr, error = %e, "middleproxy carrier write error");
                break;
            }
        }
        wr_carrier.fail_all();
    });

    // Reader task: decodes incoming RPC frames, routes by `conn_id`, and replies to `RPC_PING`!
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
                        let _ = st_tx
                            .send(MiddleDownMsg::Data {
                                flags,
                                payload: payload.to_vec(),
                            })
                            .await;
                    }
                }
                Ok(RpcDownEvent::SimpleAck { conn_id, payload }) => {
                    let target = rd_carrier.streams.lock().get(&conn_id).cloned();
                    if let Some(st_tx) = target {
                        let _ = st_tx.send(MiddleDownMsg::SimpleAck(payload.to_vec())).await;
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
                    let _ = tx.try_send(build_rpc_pong_body(ping_id).to_vec());
                }
                Ok(RpcDownEvent::Pong { .. }) => {}
                Err(e) => {
                    warn!(error = %e, "malformed middleproxy RPC response");
                }
            }
        }
        rd_carrier.fail_all();
    });

    carrier
}
