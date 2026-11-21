//! Single-task-per-session readiness-gated Shared-Frame v1 multiplexer.
//!
//! Architecture improvements over Go's 4-goroutines-per-stream relay:
//! - **1 Tokio task per session, 0 tasks per stream**: all dialing, uplink
//!   flushing, readiness-gated downlink reading, flow-control coalescing,
//!   outbox packing, and WebSocket framing run inside a single cooperative
//!   event loop.
//! - **0B idle buffer per stream**: a single shared 64 KiB read scratch buffer
//!   lives on the session struct; streams only read when `downlink_send_window
//!   > 0` AND outbox budget allows.
//! - **Instant dial cancellation**: receiving `CLOSE` while a stream is dialing
//!   simply drops the dial future immediately.
//! - **Strictly atomic two-phase `plan()` / `commit()`**: validates EVERY frame
//!   in an uplink batch (including BOTH `DATA` credit exhaustion AND 32-bit
//!   `WINDOW` overflow!) BEFORE mutating any stream state.
//! - **Lock-free `GlobalBudget`** (`512 MiB / 262,144 items`) + per-session
//!   budget (`32 MiB / 16,384 items` with `CONTROL_RESERVE = 1024`) so control
//!   frames (`CLOSE`, `WINDOW`, `BYE`) are never starved by bulk `DATA`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use mtg_net::coarse_now_ns;
use mtg_protocol::proxyproto::encode_v2_tcp;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;

thread_local! {
    /// Per-worker reusable 64 KiB read staging buffer shared across ALL WebRelay
    /// sessions on this thread -> **0 B** idle read scratch per session!
    static WEBRELAY_READ_SCRATCH: RefCell<Vec<u8>> =
        RefCell::new(vec![0u8; MAX_RELAY_DATA_CHUNK]);
}

/// Reusable per-session scratch vectors (0 B while idle; eliminates per-batch
/// and per-poll `Vec`/`BytesMut` heap allocations during active traffic!).
#[derive(Default)]
struct SessionScratch {
    batch_frames: Vec<Frame>,
    header_scratch: Vec<u8>,
    header_spans: Vec<(usize, usize)>,
    stream_ids: Vec<u32>,
    to_close: Vec<u32>,
    rr_cursor: usize,
}

use crate::frame::{
    Direction, Frame, FrameLimits, FrameType, HEADER_SIZE, INITIAL_WINDOW, MAX_RELAY_DATA_CHUNK,
    WINDOW_PAYLOAD_SIZE, decode_batch, encode_header,
};
use crate::metrics::RelayCounters;
use crate::ws::{
    CLOSE_INTERNAL_ERROR, CLOSE_NORMAL, CLOSE_PROTOCOL_ERROR, DEFAULT_IDLE_TIMEOUT, OP_PING,
    OP_PONG, WsError, WsEvent, WsReader, WsWriter,
};

/// Process-wide pending downlink byte budget (`512 MiB`).
pub const DEFAULT_GLOBAL_PENDING_BYTES: usize = 512 << 20;
/// Process-wide pending downlink frame count budget (`262,144`).
pub const DEFAULT_GLOBAL_PENDING_ITEMS: usize = 262_144;
/// Per-session pending downlink byte budget (`32 MiB`).
pub const DEFAULT_SESSION_PENDING_BYTES: usize = 32 << 20;
/// Per-session pending downlink frame count budget (`16,384`).
pub const DEFAULT_SESSION_PENDING_ITEMS: usize = 16_384;
/// Reserved control-frame slots inside the per-session budget (`CLOSE`/`WINDOW`).
pub const CONTROL_RESERVE_ITEMS: usize = 1024;
/// Default maximum concurrent logical streams per session.
pub const DEFAULT_MAX_STREAMS: usize = 64;
/// Maximum closed/refused stream IDs remembered to tolerate close races.
pub const MAX_TOMBSTONES: usize = 1024;
/// Coalesce uplink `WINDOW` returns until at least this many bytes drained (or queue emptied).
const WINDOW_COALESCE_BYTES: u32 = 64 << 10;
/// Minimum drained bytes to trigger an immediate `WINDOW` return when uplink queue empties.
const WINDOW_IDLE_FLUSH_BYTES: u32 = 16 << 10;
/// Default backend dial timeout.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Type-erased async stream returned by [`BackendDialer`].
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

/// Dialer abstraction opening one backend connection per logical `OPEN` stream.
pub trait BackendDialer: Send + Sync + std::fmt::Debug {
    fn dial(
        &self,
        client_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send + '_>>;
}

/// Production TCP backend dialer connecting to loopback `mtg-proxy` and
/// prepending a family-matched HAProxy PROXY protocol v2 header!
#[derive(Debug, Clone)]
pub struct TcpProxyBackend {
    pub backend_addr: SocketAddr,
    pub dial_timeout: Duration,
}

impl TcpProxyBackend {
    pub fn new(backend_addr: SocketAddr, dial_timeout: Duration) -> Self {
        Self {
            backend_addr,
            dial_timeout: if dial_timeout.is_zero() {
                DEFAULT_DIAL_TIMEOUT
            } else {
                dial_timeout
            },
        }
    }
}

impl BackendDialer for TcpProxyBackend {
    fn dial(
        &self,
        client_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send + '_>> {
        let addr = self.backend_addr;
        let timeout = self.dial_timeout;
        Box::pin(async move {
            let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend dial timed out"))??;
            let _ = stream.set_nodelay(true);
            let dst = stream.peer_addr().unwrap_or(addr);
            let proxy_hdr = encode_v2_tcp(client_addr, dst);
            tokio::time::timeout(timeout, stream.write_all(proxy_hdr.as_slice()))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "backend PROXY v2 write timed out")
                })??;
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}

/// Lock-free process-wide downlink buffer budget shared across all sessions.
#[derive(Debug)]
pub struct GlobalBudget {
    max_bytes: i64,
    max_items: i64,
    bytes: AtomicI64,
    items: AtomicI64,
}

impl Default for GlobalBudget {
    fn default() -> Self {
        Self::new(DEFAULT_GLOBAL_PENDING_BYTES, DEFAULT_GLOBAL_PENDING_ITEMS)
    }
}

impl GlobalBudget {
    pub fn new(max_bytes: usize, max_items: usize) -> Self {
        Self {
            max_bytes: max_bytes as i64,
            max_items: max_items as i64,
            bytes: AtomicI64::new(0),
            items: AtomicI64::new(0),
        }
    }

    #[inline]
    pub fn try_acquire(&self, bytes: usize, is_control: bool) -> bool {
        let b = bytes as i64;
        let prev_i = self.items.fetch_add(1, Ordering::Relaxed);
        let prev_b = self.bytes.fetch_add(b, Ordering::Relaxed);
        let item_cap = if is_control {
            self.max_items.saturating_add(CONTROL_RESERVE_ITEMS as i64)
        } else {
            self.max_items
        };
        if !is_control && (prev_i + 1 > item_cap || prev_b + b > self.max_bytes) {
            self.items.fetch_sub(1, Ordering::Relaxed);
            self.bytes.fetch_sub(b, Ordering::Relaxed);
            return false;
        }
        true
    }

    #[inline]
    pub fn release(&self, bytes: usize) {
        self.items.fetch_sub(1, Ordering::Relaxed);
        self.bytes.fetch_sub(bytes as i64, Ordering::Relaxed);
    }

    #[inline]
    pub fn pending_bytes(&self) -> i64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// Bounded FIFO tombstone set remembering closed/refused stream IDs to tolerate
/// in-flight close races without unbounded memory growth.
#[derive(Debug, Default)]
struct Tombstones {
    set: FxHashSet<u32>,
    order: VecDeque<u32>,
    cap: usize,
}

impl Tombstones {
    fn new(cap: usize) -> Self {
        Self {
            set: FxHashSet::default(),
            order: VecDeque::with_capacity(cap.min(256)),
            cap,
        }
    }

    #[inline]
    fn has(&self, id: u32) -> bool {
        self.set.contains(&id)
    }

    fn insert(&mut self, id: u32) {
        if !self.set.insert(id) {
            return;
        }
        if self.order.len() >= self.cap
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        self.order.push_back(id);
    }
}

/// Outbound downlink queue separating priority control frames (`CLOSE`/`WINDOW`)
/// from bulk `DATA`, enforcing both per-session and global pending budgets.
struct Outbox {
    control: VecDeque<Frame>,
    data: VecDeque<Frame>,
    pending_bytes: usize,
    pending_items: usize,
    max_bytes: usize,
    max_items: usize,
    global: Arc<GlobalBudget>,
}

impl Outbox {
    fn new(max_bytes: usize, max_items: usize, global: Arc<GlobalBudget>) -> Self {
        Self {
            control: VecDeque::new(),
            data: VecDeque::new(),
            pending_bytes: 0,
            pending_items: 0,
            max_bytes,
            max_items,
            global,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.control.is_empty() && self.data.is_empty()
    }

    #[inline]
    fn can_accept_data(&self) -> bool {
        let data_item_limit = self.max_items.saturating_sub(CONTROL_RESERVE_ITEMS);
        self.pending_items < data_item_limit && self.pending_bytes < self.max_bytes
    }

    #[inline]
    fn remaining_data_bytes(&self) -> usize {
        self.max_bytes.saturating_sub(self.pending_bytes)
    }

    fn push_control(&mut self, frame: Frame) {
        let bytes = frame.encoded_len();
        self.global.try_acquire(bytes, true);
        self.pending_bytes += bytes;
        self.pending_items += 1;
        self.control.push_back(frame);
    }

    fn push_data(&mut self, frame: Frame) -> bool {
        let bytes = frame.encoded_len();
        if !self.can_accept_data() || self.pending_bytes + bytes > self.max_bytes {
            return false;
        }
        if !self.global.try_acquire(bytes, false) {
            return false;
        }
        self.pending_bytes += bytes;
        self.pending_items += 1;
        self.data.push_back(frame);
        true
    }

    /// Pop a coalesced batch of frames fitting within `batch_budget` bytes into
    /// reusable `out` (zero per-batch heap allocation!), draining control frames
    /// first so `CLOSE`/`WINDOW` are never starved.
    fn take_batch_into(&mut self, batch_budget: usize, out: &mut Vec<Frame>) {
        out.clear();
        let mut used = 0usize;

        while let Some(front) = self.control.front() {
            let sz = front.encoded_len();
            if !out.is_empty() && used + sz > batch_budget {
                break;
            }
            if let Some(f) = self.control.pop_front() {
                self.release_one(sz);
                used += sz;
                out.push(f);
            }
        }

        while let Some(front) = self.data.front() {
            let sz = front.encoded_len();
            if !out.is_empty() && used + sz > batch_budget {
                break;
            }
            if let Some(f) = self.data.pop_front() {
                self.release_one(sz);
                used += sz;
                out.push(f);
            }
        }
    }

    #[inline]
    fn release_one(&mut self, bytes: usize) {
        self.pending_bytes = self.pending_bytes.saturating_sub(bytes);
        self.pending_items = self.pending_items.saturating_sub(1);
        self.global.release(bytes);
    }

    fn clear_all(&mut self) {
        while let Some(f) = self.control.pop_front() {
            self.release_one(f.encoded_len());
        }
        while let Some(f) = self.data.pop_front() {
            self.release_one(f.encoded_len());
        }
    }
}

impl Drop for Outbox {
    fn drop(&mut self) {
        self.clear_all();
    }
}

enum StreamState {
    Dialing(Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send>>),
    Open(BoxedStream),
}

struct StreamEntry {
    state: StreamState,
    uplink_queue: VecDeque<Bytes>,
    uplink_window_credit: u32,
    uplink_drained: u32,
    downlink_send_window: u32,
}

impl StreamEntry {
    fn new_dialing(
        dial_fut: Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send>>,
    ) -> Self {
        Self {
            state: StreamState::Dialing(dial_fut),
            uplink_queue: VecDeque::new(),
            uplink_window_credit: INITIAL_WINDOW,
            uplink_drained: 0,
            downlink_send_window: INITIAL_WINDOW,
        }
    }
}

/// Configuration for one WebSocket carrier session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub backend: Arc<dyn BackendDialer>,
    pub limits: FrameLimits,
    pub global_budget: Arc<GlobalBudget>,
    pub client_addr: SocketAddr,
    pub max_streams: usize,
    pub idle_timeout: Duration,
    pub counters: Option<Arc<RelayCounters>>,
}

impl SessionConfig {
    fn effective_max_streams(&self) -> usize {
        if self.max_streams == 0 {
            DEFAULT_MAX_STREAMS
        } else {
            self.max_streams
        }
    }

    fn effective_idle_timeout(&self) -> Duration {
        if self.idle_timeout.is_zero() {
            DEFAULT_IDLE_TIMEOUT
        } else {
            self.idle_timeout
        }
    }
}

/// Protocol violation detected during atomic batch planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    SecondHello,
    StreamReused(u32),
    UnknownStream(u32),
    UplinkWindowExceeded(u32),
    DownlinkWindowOverflow(u32),
}

#[derive(Debug)]
enum PlannedAction {
    Ignore,
    Open(u32),
    Refuse(u32),
    Data(u32, Bytes),
    Window(u32, u32),
    Close(u32),
}

/// Atomic two-phase batch planner state (extracted so it is directly unit-testable).
#[derive(Debug, Clone, Copy)]
struct SimStream {
    uplink_credit: u32,
    downlink_window: u32,
}

/// Run a single-task-per-session multiplexed Shared-Frame v1 carrier until
/// normal close, protocol violation, idle timeout, or external `DELETE` cancel.
pub async fn serve_session<R, W>(
    mut ws_reader: WsReader<R>,
    mut ws_writer: WsWriter<W>,
    cfg: SessionConfig,
    mut cancel_rx: watch::Receiver<bool>,
) -> Result<(), WsError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_streams = cfg.effective_max_streams();
    let idle_timeout = cfg.effective_idle_timeout();
    let batch_budget = cfg.limits.effective_batch_bytes();
    let max_payload = cfg.limits.effective_payload().min(MAX_RELAY_DATA_CHUNK);

    let mut streams: FxHashMap<u32, StreamEntry> = FxHashMap::default();
    let mut tombstones = Tombstones::new(MAX_TOMBSTONES);
    let mut outbox = Outbox::new(
        DEFAULT_SESSION_PENDING_BYTES,
        DEFAULT_SESSION_PENDING_ITEMS,
        Arc::clone(&cfg.global_budget),
    );
    let mut scratch = SessionScratch::default();
    let mut pending_pong: Option<Bytes> = None;

    // ONE pinned idle timer reused for the entire session lifetime (throttled
    // resets at 1s granularity via vDSO `coarse_now_ns()` -> zero timer churn!).
    let idle_timeout_ns = idle_timeout.as_nanos().min(u128::from(u64::MAX)) as u64;
    let mut last_activity_ns = coarse_now_ns();
    let mut last_reset_ns = last_activity_ns;
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut ping_sent = false;
    let close_code;
    let mut result = Ok(());

    // Helper counter to close & clean up all remaining streams on exit.
    let mut active_stream_count_tracked: usize = 0;

    loop {
        // 1. High-priority WebSocket Pong response if peer pinged us.
        if let Some(pong_payload) = pending_pong.take()
            && let Err(e) = ws_writer.write_control(OP_PONG, &pong_payload).await
        {
            close_code = e.close_code();
            result = Err(e);
            break;
        }

        // 2. Drain any ready downlink batch via zero-alloc stack-vectored writev(2)!
        if !outbox.is_empty() {
            outbox.take_batch_into(batch_budget, &mut scratch.batch_frames);
            if !scratch.batch_frames.is_empty()
                && let Err(e) = write_frame_batch(&mut ws_writer, &mut scratch).await
            {
                close_code = e.close_code();
                result = Err(e);
                break;
            }
        }

        // 3. Single-task cooperative multiplex:
        //    - External DELETE / shutdown cancellation
        //    - Incoming WebSocket events (cancel-safe!)
        //    - All active streams' dial/write/readiness-gated read in ONE poll_fn!
        //    - Reused pinned idle liveness timer (Ping after 1x idle, close after 2x idle)
        tokio::select! {
            biased;

            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    close_code = CLOSE_NORMAL;
                    break;
                }
            }

            ev = ws_reader.read_event() => {
                let now_ns = coarse_now_ns();
                last_activity_ns = now_ns;
                if ping_sent || now_ns.saturating_sub(last_reset_ns) >= 1_000_000_000 {
                    last_reset_ns = now_ns;
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                }
                ping_sent = false;

                match ev {
                    Ok(WsEvent::Binary(msg)) => {
                        if msg.is_empty() {
                            continue;
                        }
                        let frames = match decode_batch(&msg, cfg.limits, Direction::ClientToRelay) {
                            Ok(f) => f,
                            Err(err) => {
                                debug!(%err, "shared-frame decode violation");
                                close_code = CLOSE_PROTOCOL_ERROR;
                                result = Err(WsError::Protocol("shared-frame decode error"));
                                break;
                            }
                        };
                        match plan_batch(&streams, &tombstones, max_streams, &frames) {
                            Ok(actions) => {
                                apply_actions(
                                    actions,
                                    &mut streams,
                                    &mut tombstones,
                                    &mut outbox,
                                    &cfg,
                                    &mut active_stream_count_tracked,
                                );
                            }
                            Err(err) => {
                                debug!(?err, "shared-frame state violation");
                                close_code = CLOSE_PROTOCOL_ERROR;
                                result = Err(WsError::Protocol("shared-frame state violation"));
                                break;
                            }
                        }
                    }
                    Ok(WsEvent::Ping(payload)) => {
                        pending_pong = Some(payload);
                    }
                    Ok(WsEvent::Pong(_)) => {}
                    Ok(WsEvent::Close(_)) | Err(WsError::Closed) => {
                        close_code = CLOSE_NORMAL;
                        break;
                    }
                    Err(e) => {
                        close_code = e.close_code();
                        result = Err(e);
                        break;
                    }
                }
            }

            () = poll_fn(|cx| {
                poll_all_streams(
                    cx,
                    &mut streams,
                    &mut tombstones,
                    &mut outbox,
                    &mut scratch,
                    max_payload,
                    batch_budget,
                    &cfg,
                    &mut active_stream_count_tracked,
                )
            }), if !streams.is_empty() => {
                // One or more streams made progress (produced downlink frames,
                // emitted WINDOW/CLOSE, or transitioned Dialing -> Open).
            }

            () = &mut idle_sleep => {
                let now_ns = coarse_now_ns();
                let elapsed_ns = now_ns.saturating_sub(last_activity_ns);
                if !ping_sent && elapsed_ns < idle_timeout_ns {
                    let rem_ns = idle_timeout_ns - elapsed_ns;
                    last_reset_ns = now_ns;
                    idle_sleep
                        .as_mut()
                        .reset(Instant::now() + Duration::from_nanos(rem_ns));
                    continue;
                }
                if ping_sent {
                    // Two consecutive idle periods with no response -> dead peer!
                    close_code = CLOSE_NORMAL;
                    break;
                }
                ping_sent = true;
                last_activity_ns = now_ns;
                last_reset_ns = now_ns;
                idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                if let Err(e) = ws_writer.write_control(OP_PING, &[]).await {
                    close_code = e.close_code();
                    result = Err(e);
                    break;
                }
            }
        }
    }

    // Tear down all remaining streams cleanly (drops dial futures & closes sockets).
    if let Some(counters) = &cfg.counters {
        for _ in 0..active_stream_count_tracked {
            counters.on_stream_closed();
        }
    }
    streams.clear();
    outbox.clear_all();
    let _ = ws_writer.write_close(close_code).await;
    result
}

/// Two-phase atomic batch validator: checks EVERY frame in `frames` before any
/// mutation occurs, verifying:
/// - No `HELLO` inside WebSocket carrier
/// - No reuse of live, batch-opened, batch-refused, or tombstoned stream IDs
/// - `OPEN` past `max_streams` -> stream-level `Refuse` (emits `CLOSE`), NOT session fatal
/// - `DATA`/`WINDOW`/`CLOSE` on closed/refused/tombstoned stream -> ignored
/// - `DATA`/`WINDOW`/`CLOSE` on never-opened stream -> fatal `UnknownStream`
/// - `DATA` exceeding stream's remaining uplink receive credit -> fatal `UplinkWindowExceeded`
/// - `WINDOW` overflowing 32-bit `downlink_send_window` -> fatal `DownlinkWindowOverflow`
fn plan_batch(
    streams: &FxHashMap<u32, StreamEntry>,
    tombstones: &Tombstones,
    max_streams: usize,
    frames: &[Frame],
) -> Result<Vec<PlannedAction>, PlanError> {
    let mut actions = Vec::with_capacity(frames.len());
    let mut sim: FxHashMap<u32, SimStream> = FxHashMap::default();
    let mut refused: FxHashSet<u32> = FxHashSet::default();
    let mut closed_in_batch: FxHashSet<u32> = FxHashSet::default();
    let mut new_open_count: usize = 0;

    for f in frames {
        match f {
            Frame::Hello { .. } => return Err(PlanError::SecondHello),
            Frame::Pong { .. } => actions.push(PlannedAction::Ignore),
            Frame::Open { stream_id } => {
                let id = *stream_id;
                if streams.contains_key(&id)
                    || sim.contains_key(&id)
                    || refused.contains(&id)
                    || closed_in_batch.contains(&id)
                    || tombstones.has(id)
                {
                    return Err(PlanError::StreamReused(id));
                }
                if streams.len() + new_open_count >= max_streams {
                    refused.insert(id);
                    actions.push(PlannedAction::Refuse(id));
                    continue;
                }
                new_open_count += 1;
                sim.insert(
                    id,
                    SimStream {
                        uplink_credit: INITIAL_WINDOW,
                        downlink_window: INITIAL_WINDOW,
                    },
                );
                actions.push(PlannedAction::Open(id));
            }
            Frame::Data { stream_id, payload } => {
                let id = *stream_id;
                if closed_in_batch.contains(&id) || refused.contains(&id) || tombstones.has(id) {
                    actions.push(PlannedAction::Ignore);
                    continue;
                }
                let st = get_or_load_sim(&mut sim, streams, id)?;
                let len = u32::try_from(payload.len())
                    .map_err(|_| PlanError::UplinkWindowExceeded(id))?;
                let Some(next_credit) = st.uplink_credit.checked_sub(len) else {
                    return Err(PlanError::UplinkWindowExceeded(id));
                };
                st.uplink_credit = next_credit;
                actions.push(PlannedAction::Data(id, payload.clone()));
            }
            Frame::Window { stream_id, delta } => {
                let id = *stream_id;
                if closed_in_batch.contains(&id) || refused.contains(&id) || tombstones.has(id) {
                    actions.push(PlannedAction::Ignore);
                    continue;
                }
                let st = get_or_load_sim(&mut sim, streams, id)?;
                let Some(next_win) = st.downlink_window.checked_add(*delta) else {
                    return Err(PlanError::DownlinkWindowOverflow(id));
                };
                st.downlink_window = next_win;
                actions.push(PlannedAction::Window(id, *delta));
            }
            Frame::Close { stream_id } => {
                let id = *stream_id;
                if closed_in_batch.contains(&id) || refused.contains(&id) || tombstones.has(id) {
                    actions.push(PlannedAction::Ignore);
                    continue;
                }
                // Verify stream actually exists (live or opened earlier in batch).
                let _ = get_or_load_sim(&mut sim, streams, id)?;
                sim.remove(&id);
                closed_in_batch.insert(id);
                actions.push(PlannedAction::Close(id));
            }
            // Codec already blocks RelayToClient frames in ClientToRelay batches.
            Frame::Welcome | Frame::Ping { .. } | Frame::Bye { .. } => {
                return Err(PlanError::SecondHello);
            }
        }
    }

    Ok(actions)
}

#[inline]
fn get_or_load_sim<'a>(
    sim: &'a mut FxHashMap<u32, SimStream>,
    streams: &FxHashMap<u32, StreamEntry>,
    id: u32,
) -> Result<&'a mut SimStream, PlanError> {
    match sim.entry(id) {
        std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
        std::collections::hash_map::Entry::Vacant(e) => {
            let Some(live) = streams.get(&id) else {
                return Err(PlanError::UnknownStream(id));
            };
            Ok(e.insert(SimStream {
                uplink_credit: live.uplink_window_credit,
                downlink_window: live.downlink_send_window,
            }))
        }
    }
}

fn apply_actions(
    actions: Vec<PlannedAction>,
    streams: &mut FxHashMap<u32, StreamEntry>,
    tombstones: &mut Tombstones,
    outbox: &mut Outbox,
    cfg: &SessionConfig,
    active_count: &mut usize,
) {
    for act in actions {
        match act {
            PlannedAction::Ignore => {}
            PlannedAction::Refuse(id) => {
                tombstones.insert(id);
                outbox.push_control(Frame::Close { stream_id: id });
            }
            PlannedAction::Open(id) => {
                let backend = Arc::clone(&cfg.backend);
                let client_addr = cfg.client_addr;
                let dial_fut = Box::pin(async move { backend.dial(client_addr).await });
                streams.insert(id, StreamEntry::new_dialing(dial_fut));
                *active_count += 1;
                if let Some(c) = &cfg.counters {
                    c.on_stream_opened();
                }
            }
            PlannedAction::Data(id, payload) => {
                if let Some(st) = streams.get_mut(&id) {
                    let len = payload.len();
                    st.uplink_window_credit -= len as u32;
                    st.uplink_queue.push_back(payload);
                    if let Some(c) = &cfg.counters {
                        c.add_bytes_up(len);
                    }
                }
            }
            PlannedAction::Window(id, delta) => {
                if let Some(st) = streams.get_mut(&id) {
                    st.downlink_send_window += delta;
                }
            }
            PlannedAction::Close(id) => {
                // Dropping StreamEntry IMMEDIATELY cancels any in-flight dial future
                // and closes any open TCP socket!
                if streams.remove(&id).is_some() {
                    *active_count = active_count.saturating_sub(1);
                    if let Some(c) = &cfg.counters {
                        c.on_stream_closed();
                    }
                }
                tombstones.insert(id);
            }
        }
    }
}

/// Poll all active streams in a single fair round-robin cooperative pass:
/// 1. Advance any `Dialing` futures.
/// 2. Flush queued uplink bytes to `Open` sockets and coalesce `WINDOW` returns.
/// 3. Readiness-gated downlink read via thread-local `WEBRELAY_READ_SCRATCH`
///    (0 B per idle session!) with burst coalescing up to `batch_budget` ONLY
///    when `downlink_send_window > 0` and `outbox.can_accept_data()`!
#[allow(clippy::too_many_arguments)]
fn poll_all_streams(
    cx: &mut Context<'_>,
    streams: &mut FxHashMap<u32, StreamEntry>,
    tombstones: &mut Tombstones,
    outbox: &mut Outbox,
    scratch: &mut SessionScratch,
    max_payload: usize,
    batch_budget: usize,
    cfg: &SessionConfig,
    active_count: &mut usize,
) -> Poll<()> {
    let mut made_progress = false;
    scratch.to_close.clear();
    scratch.stream_ids.clear();
    scratch.stream_ids.extend(streams.keys().copied());

    let n_streams = scratch.stream_ids.len();
    if n_streams == 0 {
        return Poll::Pending;
    }
    let start = scratch.rr_cursor % n_streams;
    scratch.rr_cursor = scratch.rr_cursor.wrapping_add(1);

    let mut pass_read_bytes = 0usize;

    WEBRELAY_READ_SCRATCH.with(|cell| {
        let mut tls_scratch = cell.borrow_mut();
        let scratch_len = tls_scratch.len();

        for offset in 0..n_streams {
            let id = scratch.stream_ids[(start + offset) % n_streams];
            let Some(st) = streams.get_mut(&id) else {
                continue;
            };

            // Phase A: Poll dialing future if still connecting.
            if let StreamState::Dialing(fut) = &mut st.state {
                match fut.as_mut().poll(cx) {
                    Poll::Pending => continue,
                    Poll::Ready(Ok(io)) => {
                        st.state = StreamState::Open(io);
                        made_progress = true;
                    }
                    Poll::Ready(Err(_)) => {
                        scratch.to_close.push(id);
                        made_progress = true;
                        continue;
                    }
                }
            }

            let StreamState::Open(io) = &mut st.state else {
                continue;
            };

            // Phase B: Flush uplink queue to backend TCP socket.
            let mut write_failed = false;
            while let Some(front) = st.uplink_queue.front_mut() {
                match Pin::new(&mut **io).poll_write(cx, front) {
                    Poll::Pending => break,
                    Poll::Ready(Ok(0) | Err(_)) => {
                        write_failed = true;
                        break;
                    }
                    Poll::Ready(Ok(n)) => {
                        let _ = front.split_to(n);
                        if front.is_empty() {
                            st.uplink_queue.pop_front();
                        }
                        st.uplink_drained = st.uplink_drained.saturating_add(n as u32);
                        made_progress = true;
                    }
                }
            }
            if write_failed {
                scratch.to_close.push(id);
                made_progress = true;
                continue;
            }

            // Coalesced WINDOW return once threshold reached or queue emptied.
            let should_return_window = st.uplink_drained >= WINDOW_COALESCE_BYTES
                || (st.uplink_queue.is_empty() && st.uplink_drained >= WINDOW_IDLE_FLUSH_BYTES);
            if should_return_window {
                let delta = st.uplink_drained;
                st.uplink_drained = 0;
                st.uplink_window_credit = st.uplink_window_credit.saturating_add(delta);
                outbox.push_control(Frame::Window {
                    stream_id: id,
                    delta,
                });
                made_progress = true;
            }

            // Phase C: STRICTLY readiness-gated downlink read with burst coalescing!
            // Fills up to `batch_budget` across up to 4 non-blocking reads per stream
            // so bulk downloads pack full 256 KiB WebSocket writev(2) frames!
            for _ in 0..4 {
                if pass_read_bytes >= batch_budget
                    || st.downlink_send_window == 0
                    || !outbox.can_accept_data()
                {
                    break;
                }
                let max_room = outbox.remaining_data_bytes().saturating_sub(HEADER_SIZE);
                let budget_rem = batch_budget.saturating_sub(pass_read_bytes);
                let cap = max_payload
                    .min(st.downlink_send_window as usize)
                    .min(max_room)
                    .min(budget_rem)
                    .min(scratch_len);
                if cap == 0 {
                    break;
                }
                let mut rbuf = ReadBuf::new(&mut tls_scratch[..cap]);
                match Pin::new(&mut **io).poll_read(cx, &mut rbuf) {
                    Poll::Pending => break,
                    Poll::Ready(Ok(())) => {
                        let n = rbuf.filled().len();
                        if n == 0 {
                            scratch.to_close.push(id);
                            made_progress = true;
                            break;
                        }
                        let payload = Bytes::copy_from_slice(rbuf.filled());
                        if outbox.push_data(Frame::Data {
                            stream_id: id,
                            payload,
                        }) {
                            st.downlink_send_window -= n as u32;
                            pass_read_bytes += n;
                            if let Some(c) = &cfg.counters {
                                c.add_bytes_down(n);
                            }
                            made_progress = true;
                        } else {
                            break;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        scratch.to_close.push(id);
                        made_progress = true;
                        break;
                    }
                }
            }
        }
    });

    for id in scratch.to_close.drain(..) {
        if streams.remove(&id).is_some() {
            *active_count = active_count.saturating_sub(1);
            if let Some(c) = &cfg.counters {
                c.on_stream_closed();
            }
        }
        tombstones.insert(id);
        outbox.push_control(Frame::Close { stream_id: id });
    }

    if made_progress || !outbox.is_empty() {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

/// Encode and transmit a downlink batch as ONE zero-alloc stack-vectored
/// `writev(2)` WebSocket binary message with ZERO payload copying!
async fn write_frame_batch<W: AsyncWrite + Unpin>(
    ws_writer: &mut WsWriter<W>,
    scratch: &mut SessionScratch,
) -> Result<(), WsError> {
    scratch.header_scratch.clear();
    scratch.header_spans.clear();

    for f in &scratch.batch_frames {
        let start = scratch.header_scratch.len();
        let mut hdr = [0u8; HEADER_SIZE];
        match f {
            Frame::Data { stream_id, payload } => {
                encode_header(&mut hdr, FrameType::Data, *stream_id, payload.len() as u32);
                scratch.header_scratch.extend_from_slice(&hdr);
            }
            Frame::Close { stream_id } => {
                encode_header(&mut hdr, FrameType::Close, *stream_id, 0);
                scratch.header_scratch.extend_from_slice(&hdr);
            }
            Frame::Window { stream_id, delta } => {
                encode_header(
                    &mut hdr,
                    FrameType::Window,
                    *stream_id,
                    WINDOW_PAYLOAD_SIZE as u32,
                );
                scratch.header_scratch.extend_from_slice(&hdr);
                scratch
                    .header_scratch
                    .extend_from_slice(&delta.to_be_bytes());
            }
            Frame::Welcome => {
                encode_header(&mut hdr, FrameType::Welcome, 0, 0);
                scratch.header_scratch.extend_from_slice(&hdr);
            }
            Frame::Ping { payload } => {
                encode_header(&mut hdr, FrameType::Ping, 0, payload.len() as u32);
                scratch.header_scratch.extend_from_slice(&hdr);
            }
            Frame::Bye { payload } => {
                encode_header(&mut hdr, FrameType::Bye, 0, payload.len() as u32);
                scratch.header_scratch.extend_from_slice(&hdr);
            }
            Frame::Open { .. } | Frame::Pong { .. } | Frame::Hello { .. } => {
                scratch.batch_frames.clear();
                return Err(WsError::Io(io::Error::other("invalid downlink frame type")));
            }
        }
        scratch
            .header_spans
            .push((start, scratch.header_scratch.len()));
    }

    let hdr_buf = scratch.header_scratch.as_slice();
    let max_slices = scratch.batch_frames.len() * 2;
    let res = if max_slices <= 63 {
        let mut stack_slices: [&[u8]; 63] = [&[]; 63];
        let mut count = 0usize;
        for (f, (s, e)) in scratch.batch_frames.iter().zip(scratch.header_spans.iter()) {
            stack_slices[count] = &hdr_buf[*s..*e];
            count += 1;
            match f {
                Frame::Data { payload, .. } | Frame::Ping { payload } | Frame::Bye { payload }
                    if !payload.is_empty() =>
                {
                    stack_slices[count] = payload;
                    count += 1;
                }
                _ => {}
            }
        }
        ws_writer
            .write_binary_vectored(&stack_slices[..count])
            .await
    } else {
        let mut slices: Vec<&[u8]> = Vec::with_capacity(max_slices);
        for (f, (s, e)) in scratch.batch_frames.iter().zip(scratch.header_spans.iter()) {
            slices.push(&hdr_buf[*s..*e]);
            match f {
                Frame::Data { payload, .. } | Frame::Ping { payload } | Frame::Bye { payload }
                    if !payload.is_empty() =>
                {
                    slices.push(payload);
                }
                _ => {}
            }
        }
        ws_writer.write_binary_vectored(&slices).await
    };

    // Release frame payload Bytes references immediately after wire flush!
    scratch.batch_frames.clear();
    if res.is_err() {
        let _ = ws_writer.write_close(CLOSE_INTERNAL_ERROR).await;
    }
    res
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn atomic_plan_rejects_window_overflow_and_credit_exhaustion_before_mutation() {
        let streams: FxHashMap<u32, StreamEntry> = FxHashMap::default();
        let tombstones = Tombstones::new(MAX_TOMBSTONES);

        // Batch opens stream 1, then sends WINDOW that overflows u32 (INITIAL_WINDOW + u32::MAX)!
        let bad_win = vec![
            Frame::Open { stream_id: 1 },
            Frame::Window {
                stream_id: 1,
                delta: u32::MAX,
            },
        ];
        assert_eq!(
            plan_batch(&streams, &tombstones, 64, &bad_win).unwrap_err(),
            PlanError::DownlinkWindowOverflow(1)
        );
        // Zero side effects on live map!
        assert!(streams.is_empty());

        // Batch opens stream 1, sends 5 x 1 MiB (> 4 MiB INITIAL_WINDOW) -> UplinkWindowExceeded!
        let big = Bytes::from(vec![0xAA; 1 << 20]);
        let bad_data = vec![
            Frame::Open { stream_id: 1 },
            Frame::Data {
                stream_id: 1,
                payload: big.clone(),
            },
            Frame::Data {
                stream_id: 1,
                payload: big.clone(),
            },
            Frame::Data {
                stream_id: 1,
                payload: big.clone(),
            },
            Frame::Data {
                stream_id: 1,
                payload: big.clone(),
            },
            Frame::Data {
                stream_id: 1,
                payload: Bytes::from_static(b"1"),
            },
        ];
        assert_eq!(
            plan_batch(&streams, &tombstones, 64, &bad_data).unwrap_err(),
            PlanError::UplinkWindowExceeded(1)
        );

        // Capacity refusal on OPEN does NOT kill batch and ignores trailing DATA on refused id!
        let cap_batch = vec![
            Frame::Open { stream_id: 1 },
            Frame::Open { stream_id: 2 },
            Frame::Data {
                stream_id: 2,
                payload: Bytes::from_static(b"dropped"),
            },
        ];
        let plan = plan_batch(&streams, &tombstones, 1, &cap_batch).unwrap();
        assert!(matches!(plan[0], PlannedAction::Open(1)));
        assert!(matches!(plan[1], PlannedAction::Refuse(2)));
        assert!(matches!(plan[2], PlannedAction::Ignore));
    }

    #[derive(Debug)]
    struct SlowCancelDialer {
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl BackendDialer for SlowCancelDialer {
        fn dial(
            &self,
            _client_addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send + '_>> {
            let flag = Arc::clone(&self.cancelled);
            Box::pin(async move {
                struct DropGuard(Arc<std::sync::atomic::AtomicBool>);
                impl Drop for DropGuard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _guard = DropGuard(flag);
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "slow"))
            })
        }
    }

    #[tokio::test]
    async fn close_cancels_in_flight_dial_immediately() {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dialer = Arc::new(SlowCancelDialer {
            cancelled: Arc::clone(&cancelled),
        });
        let (mut client_io, server_io) = tokio::io::duplex(64 << 10);
        let (srv_r, srv_w) = tokio::io::split(server_io);
        let (_cancel_tx, cancel_rx) = watch::channel(false);

        let cfg = SessionConfig {
            backend: dialer,
            limits: FrameLimits::default(),
            global_budget: Arc::new(GlobalBudget::default()),
            client_addr: "198.51.100.9:44444".parse().unwrap(),
            max_streams: 8,
            idle_timeout: Duration::from_secs(30),
            counters: None,
        };

        let task = tokio::spawn(serve_session(
            WsReader::new(srv_r, 1 << 20),
            WsWriter::new(srv_w, Duration::from_secs(5)),
            cfg,
            cancel_rx,
        ));

        // Send masked binary WS message containing OPEN(1)
        let mut open_batch = BytesMut::new();
        Frame::Open { stream_id: 1 }
            .encode_into(
                &mut open_batch,
                FrameLimits::default(),
                Direction::ClientToRelay,
            )
            .unwrap();
        let mask = [0x11, 0x22, 0x33, 0x44];
        let mut ws1 = vec![0x82, 0x80 | (open_batch.len() as u8)];
        ws1.extend_from_slice(&mask);
        for (i, b) in open_batch.iter().enumerate() {
            ws1.push(b ^ mask[i & 3]);
        }
        client_io.write_all(&ws1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!cancelled.load(Ordering::SeqCst));

        // Now send CLOSE(1) -> dial future MUST be dropped immediately!
        let mut close_batch = BytesMut::new();
        Frame::Close { stream_id: 1 }
            .encode_into(
                &mut close_batch,
                FrameLimits::default(),
                Direction::ClientToRelay,
            )
            .unwrap();
        let mut ws2 = vec![0x82, 0x80 | (close_batch.len() as u8)];
        ws2.extend_from_slice(&mask);
        for (i, b) in close_batch.iter().enumerate() {
            ws2.push(b ^ mask[i & 3]);
        }
        client_io.write_all(&ws2).await.unwrap();

        tokio::time::timeout(Duration::from_millis(500), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("dial future must cancel immediately on CLOSE");

        drop(client_io);
        let _ = task.await;
    }
}
