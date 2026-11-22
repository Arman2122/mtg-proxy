//! Multi-Carrier Single-Task Session Hub (`SessionHub`) powering:
//! - **`https`** / **`https-lanes`** (HTTP/2 & HTTP/1.1 Fetch Conveyor: sequenced
//!   pipelined `POST /up` + event-driven cursor long-poll `GET /down?cursor=N`
//!   with a bounded replay ring so dropped mobile cellular requests recover with
//!   ZERO lost MTProto bytes — works natively on Telegram iOS `WKWebView` &
//!   networks blocking WebSocket upgrades!)
//! - **`ws-lanes`** (up to 8 parallel WebSocket lanes sharing one session)
//! - **Full-Duplex HTTP/2 Streaming** (`POST /stream` bidirectional length-prefixed stream)
//!
//! Uses **1 Tokio task per session and 0 tasks per logical stream**, reusing the
//! exact readiness-gated multiplexer, atomic two-phase `plan_batch`, `Outbox`,
//! `GlobalBudget`, and thread-local `WEBRELAY_READ_SCRATCH` from [`crate::session`].

use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use bytes::{BufMut as _, Bytes, BytesMut};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;
use tracing::debug;

use crate::frame::{
    Direction, Frame, FrameLimits, FrameType, HEADER_SIZE, MAX_RELAY_DATA_CHUNK, decode_batch,
    encode_header,
};
use crate::session::{
    DEFAULT_SESSION_PENDING_BYTES, DEFAULT_SESSION_PENDING_ITEMS, MAX_TOMBSTONES, Outbox,
    SessionConfig, SessionScratch, StreamEntry, Tombstones, apply_actions, plan_batch,
    poll_all_streams,
};
use crate::ws::{
    CLOSE_NORMAL, CLOSE_PROTOCOL_ERROR, OP_PONG, WsError, WsEvent, WsReader, WsWriter,
};
use mtg_net::coarse_now_ns;

/// Maximum out-of-order HTTP Conveyor uplink batches held while awaiting a gap.
const MAX_REORDER_SLOTS: usize = 32;
/// Maximum total bytes held in the uplink reorder buffer (`4 MiB`).
const MAX_REORDER_BYTES: usize = 4 << 20;
/// Maximum historical downlink batches kept in the cursor replay ring.
const MAX_REPLAY_BATCHES: usize = 64;
/// Maximum total bytes retained in the downlink cursor replay ring (`4 MiB`).
const MAX_REPLAY_BYTES: usize = 4 << 20;
/// Default long-poll hold duration when no downlink frames are waiting.
pub const DEFAULT_LONG_POLL_WAIT: Duration = Duration::from_secs(20);
/// Maximum permitted client-requested long-poll wait.
pub const MAX_LONG_POLL_WAIT: Duration = Duration::from_secs(25);
/// Hard cap on parallel `ws-lanes` / `https-lanes` per session.
pub const MAX_CARRIER_LANES: u8 = 8;

/// Errors returned by [`SessionHub`] carrier operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HubError {
    #[error("session hub is closed")]
    Closed,
    #[error("uplink batch exceeds configured carrier limit")]
    BatchTooLarge,
    #[error("uplink reorder buffer overflow")]
    ReorderOverflow,
    #[error("downlink cursor {requested} expired behind oldest retained cursor {oldest}")]
    CursorExpired { requested: u64, oldest: u64 },
    #[error("maximum parallel WebSocket lanes ({0}) reached")]
    LaneLimitReached(u8),
    #[error("shared-frame protocol violation")]
    ProtocolViolation,
}

/// Sequenced uplink conveyor reorder state (guarantees strict in-order delivery
/// across concurrent HTTP/2 `POST /up` uploads + idempotent cellular retries!).
#[derive(Debug, Default)]
struct UplinkConveyor {
    next_seq: u64,
    pending: BTreeMap<u64, Bytes>,
    pending_bytes: usize,
}

impl UplinkConveyor {
    /// Submit an optional sequence-numbered batch. Returns ready batches in strict order.
    fn submit(&mut self, seq: Option<u64>, batch: Bytes) -> Result<Vec<Bytes>, HubError> {
        let Some(s) = seq else {
            return Ok(vec![batch]);
        };
        // Duplicate / retried sequence already delivered -> idempotent success!
        if s < self.next_seq {
            return Ok(Vec::new());
        }
        if s == self.next_seq {
            let mut ready = vec![batch];
            self.next_seq += 1;
            while let Some(next_batch) = self.pending.remove(&self.next_seq) {
                self.pending_bytes = self.pending_bytes.saturating_sub(next_batch.len());
                ready.push(next_batch);
                self.next_seq += 1;
            }
            return Ok(ready);
        }
        // Out-of-order future sequence: deduplicate or store within strict bounds.
        if self.pending.contains_key(&s) {
            return Ok(Vec::new());
        }
        if self.pending.len() >= MAX_REORDER_SLOTS
            || self.pending_bytes.saturating_add(batch.len()) > MAX_REORDER_BYTES
        {
            return Err(HubError::ReorderOverflow);
        }
        self.pending_bytes += batch.len();
        self.pending.insert(s, batch);
        Ok(Vec::new())
    }
}

/// Bounded downlink cursor + replay ring shared across `https` / `https-lanes` /
/// `h2-stream` and `ws-lanes` consumers.
#[derive(Debug, Default)]
struct DownlinkRing {
    /// Monotonic cursor assigned to the newest emitted batch (`0` = nothing emitted yet).
    latest_cursor: u64,
    /// Ordered ring of `(cursor, encoded_batch_bytes)`.
    ring: VecDeque<(u64, Bytes)>,
    ring_bytes: usize,
    /// For `ws-lanes` consumer queue: cursor already claimed by a WebSocket lane.
    ws_claimed_cursor: u64,
}

impl DownlinkRing {
    fn push(&mut self, batch: Bytes) -> u64 {
        let next_cursor = self.latest_cursor + 1;
        self.latest_cursor = next_cursor;
        self.ring_bytes += batch.len();
        self.ring.push_back((next_cursor, batch));
        while self.ring.len() > MAX_REPLAY_BATCHES || self.ring_bytes > MAX_REPLAY_BYTES {
            if let Some((_, old)) = self.ring.pop_front() {
                self.ring_bytes = self.ring_bytes.saturating_sub(old.len());
            } else {
                break;
            }
        }
        next_cursor
    }

    /// Collect all batches strictly newer than `since_cursor` up to `max_bytes`,
    /// returning `(new_cursor, combined_bytes, frame_batch_count)`.
    fn read_since(
        &self,
        since_cursor: u64,
        max_bytes: usize,
    ) -> Result<Option<(u64, Bytes, usize)>, HubError> {
        if since_cursor >= self.latest_cursor {
            return Ok(None);
        }
        let Some(&(oldest_cursor, _)) = self.ring.front() else {
            return Ok(None);
        };
        // Client's cursor is valid if `since_cursor + 1 >= oldest_cursor` (or 0 when oldest is 1).
        if since_cursor + 1 < oldest_cursor {
            return Err(HubError::CursorExpired {
                requested: since_cursor,
                oldest: oldest_cursor,
            });
        }

        let mut new_cursor = since_cursor;
        let mut selected: Vec<&Bytes> = Vec::new();
        let mut total_bytes = 0usize;
        for (cur, data) in &self.ring {
            if *cur <= since_cursor {
                continue;
            }
            if !selected.is_empty() && total_bytes + data.len() > max_bytes {
                break;
            }
            selected.push(data);
            total_bytes += data.len();
            new_cursor = *cur;
        }
        if selected.is_empty() {
            return Ok(None);
        }
        let count = selected.len();
        let bytes = if count == 1 {
            selected[0].clone()
        } else {
            let mut merged = BytesMut::with_capacity(total_bytes);
            for s in selected {
                merged.put_slice(s);
            }
            merged.freeze()
        };
        Ok(Some((new_cursor, bytes, count)))
    }

    /// Claim the next unclaimed batch for a `ws-lanes` WebSocket writer.
    fn claim_next_for_ws(&mut self, max_bytes: usize) -> Option<Bytes> {
        let since = self.ws_claimed_cursor;
        match self.read_since(since, max_bytes) {
            Ok(Some((new_cur, data, _))) => {
                self.ws_claimed_cursor = new_cur;
                Some(data)
            }
            Err(HubError::CursorExpired { oldest, .. }) => {
                // Advance to oldest retained cursor cleanly.
                let adjusted = oldest.saturating_sub(1);
                if let Ok(Some((new_cur, data, _))) = self.read_since(adjusted, max_bytes) {
                    self.ws_claimed_cursor = new_cur;
                    Some(data)
                } else {
                    None
                }
            }
            Ok(None) | Err(_) => None,
        }
    }
}

/// Thread-safe handle to a running multi-carrier WEB proxy session hub.
#[derive(Debug)]
pub struct SessionHub {
    uplink_tx: mpsc::Sender<Bytes>,
    conveyor: Mutex<UplinkConveyor>,
    downlink: Mutex<DownlinkRing>,
    downlink_notify: Notify,
    closed: AtomicBool,
    cancel_tx: watch::Sender<bool>,
    active_ws_lanes: AtomicU8,
    max_lanes: u8,
    max_batch_bytes: usize,
    last_activity_ns: AtomicU64,
    replay_hits: AtomicU64,
}

impl SessionHub {
    /// Spawn a new single-task [`SessionHub`] background multiplexer for one session.
    pub fn spawn(
        cfg: SessionConfig,
        max_lanes: u8,
        mut external_cancel: watch::Receiver<bool>,
    ) -> Arc<Self> {
        let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(64);
        let (cancel_tx, mut hub_cancel_rx) = watch::channel(false);
        let max_batch_bytes = cfg.limits.effective_batch_bytes();

        let hub = Arc::new(Self {
            uplink_tx,
            conveyor: Mutex::new(UplinkConveyor::default()),
            downlink: Mutex::new(DownlinkRing::default()),
            downlink_notify: Notify::new(),
            closed: AtomicBool::new(false),
            cancel_tx,
            active_ws_lanes: AtomicU8::new(0),
            max_lanes: max_lanes.clamp(1, MAX_CARRIER_LANES),
            max_batch_bytes,
            last_activity_ns: AtomicU64::new(coarse_now_ns()),
            replay_hits: AtomicU64::new(0),
        });

        let hub_task = Arc::clone(&hub);
        tokio::spawn(async move {
            run_hub_loop(
                hub_task,
                cfg,
                uplink_rx,
                &mut external_cancel,
                &mut hub_cancel_rx,
            )
            .await;
        });

        hub
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    #[inline]
    pub fn touch(&self) {
        self.last_activity_ns
            .store(coarse_now_ns(), Ordering::Relaxed);
    }

    #[inline]
    pub fn latest_cursor(&self) -> u64 {
        self.downlink.lock().latest_cursor
    }

    #[inline]
    pub fn active_ws_lanes(&self) -> u8 {
        self.active_ws_lanes.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn replay_hits(&self) -> u64 {
        self.replay_hits.load(Ordering::Relaxed)
    }

    /// Immediately terminate this session hub and wake all waiting consumers.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.cancel_tx.send(true);
        self.downlink_notify.notify_waiters();
    }

    /// Submit an uplink Shared-Frame v1 batch (optionally sequenced via `X-Up-Seq`).
    pub async fn submit_uplink(&self, seq: Option<u64>, batch: Bytes) -> Result<(), HubError> {
        if self.is_closed() {
            return Err(HubError::Closed);
        }
        if batch.len() > self.max_batch_bytes {
            return Err(HubError::BatchTooLarge);
        }
        self.touch();
        if batch.is_empty() {
            return Ok(());
        }
        let ready = {
            let mut conv = self.conveyor.lock();
            conv.submit(seq, batch)?
        };
        for item in ready {
            self.uplink_tx
                .send(item)
                .await
                .map_err(|_| HubError::Closed)?;
        }
        Ok(())
    }

    /// Wait for the next coalesced downlink batch strictly after `since_cursor`
    /// (event-driven via `Notify`, zero polling!).
    ///
    /// Returns:
    /// - `Ok(Some((new_cursor, batch, batch_count)))` when data is ready (or replayed!)
    /// - `Ok(None)` on clean keepalive timeout (`204 No Content`)
    /// - `Err(HubError::Closed | HubError::CursorExpired)` on terminal failure
    pub async fn poll_downlink(
        &self,
        since_cursor: u64,
        wait: Duration,
    ) -> Result<Option<(u64, Bytes, usize)>, HubError> {
        let clamped_wait = wait.clamp(Duration::from_millis(50), MAX_LONG_POLL_WAIT);
        let deadline = Instant::now() + clamped_wait;

        loop {
            // Register notification BEFORE checking state to avoid missed wakeups!
            let notified = self.downlink_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let ring = self.downlink.lock();
                if let Some(res) = ring.read_since(since_cursor, self.max_batch_bytes)? {
                    if since_cursor > 0 && since_cursor + 1 < ring.latest_cursor {
                        self.replay_hits.fetch_add(1, Ordering::Relaxed);
                    }
                    self.touch();
                    return Ok(Some(res));
                }
            }

            if self.is_closed() {
                return Err(HubError::Closed);
            }

            let now = Instant::now();
            if now >= deadline {
                self.touch();
                return Ok(None);
            }

            if tokio::time::timeout(deadline - now, notified)
                .await
                .is_err()
            {
                self.touch();
                return Ok(None);
            }
        }
    }

    /// Acquire one parallel WebSocket lane slot (`ws-lanes`).
    pub fn try_acquire_ws_lane(self: &Arc<Self>) -> Result<WsLaneGuard, HubError> {
        if self.is_closed() {
            return Err(HubError::Closed);
        }
        loop {
            let cur = self.active_ws_lanes.load(Ordering::Acquire);
            if cur >= self.max_lanes {
                return Err(HubError::LaneLimitReached(self.max_lanes));
            }
            if self
                .active_ws_lanes
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(WsLaneGuard {
                    hub: Arc::clone(self),
                });
            }
        }
    }

    /// Drive one attached `ws-lanes` WebSocket connection connected to this hub.
    pub async fn serve_ws_lane<R, W>(
        self: &Arc<Self>,
        mut ws_reader: WsReader<R>,
        mut ws_writer: WsWriter<W>,
    ) -> Result<(), WsError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let _lane_guard = self
            .try_acquire_ws_lane()
            .map_err(|_| WsError::Protocol("ws lane limit reached"))?;
        let mut cancel_rx = self.cancel_tx.subscribe();

        loop {
            let notified = self.downlink_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let next_batch = self.downlink.lock().claim_next_for_ws(self.max_batch_bytes);
            if let Some(batch) = next_batch {
                ws_writer.write_binary(&batch).await?;
                continue;
            }
            if self.is_closed() {
                let _ = ws_writer.write_close(CLOSE_NORMAL).await;
                return Ok(());
            }

            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    let _ = ws_writer.write_close(CLOSE_NORMAL).await;
                    return Ok(());
                }
                () = notified => {
                    // Downlink batch arrived -> loop top drains it immediately!
                }
                ev = ws_reader.read_event() => {
                    match ev {
                        Ok(WsEvent::Binary(payload)) => {
                            if let Err(e) = self.submit_uplink(None, payload).await {
                                let code = match e {
                                    HubError::Closed => CLOSE_NORMAL,
                                    _ => CLOSE_PROTOCOL_ERROR,
                                };
                                let _ = ws_writer.write_close(code).await;
                                return Ok(());
                            }
                        }
                        Ok(WsEvent::Ping(p)) => {
                            ws_writer.write_control(OP_PONG, &p).await?;
                        }
                        Ok(WsEvent::Pong(_)) => {}
                        Ok(WsEvent::Close(_)) | Err(WsError::Closed) => {
                            let _ = ws_writer.write_close(CLOSE_NORMAL).await;
                            return Ok(());
                        }
                        Err(e) => {
                            let _ = ws_writer.write_close(e.close_code()).await;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

/// RAII decrement guard for an active `ws-lanes` WebSocket lane.
#[derive(Debug)]
pub struct WsLaneGuard {
    hub: Arc<SessionHub>,
}

impl Drop for WsLaneGuard {
    fn drop(&mut self) {
        self.hub.active_ws_lanes.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Encode a batch of [`Frame`]s into a single contiguous wire `Bytes` block.
fn encode_frames_to_bytes(frames: &[Frame]) -> Bytes {
    let total: usize = frames.iter().map(Frame::encoded_len).sum();
    let mut out = BytesMut::with_capacity(total);
    let mut hdr = [0u8; HEADER_SIZE];
    for f in frames {
        match f {
            Frame::Open { stream_id } => {
                encode_header(&mut hdr, FrameType::Open, *stream_id, 0);
                out.put_slice(&hdr);
            }
            Frame::Data { stream_id, payload } => {
                encode_header(&mut hdr, FrameType::Data, *stream_id, payload.len() as u32);
                out.put_slice(&hdr);
                out.put_slice(payload);
            }
            Frame::Window { stream_id, delta } => {
                encode_header(&mut hdr, FrameType::Window, *stream_id, 4);
                out.put_slice(&hdr);
                out.put_slice(&delta.to_be_bytes());
            }
            Frame::Close { stream_id } => {
                encode_header(&mut hdr, FrameType::Close, *stream_id, 0);
                out.put_slice(&hdr);
            }
            Frame::Ping { payload } => {
                encode_header(&mut hdr, FrameType::Ping, 0, payload.len() as u32);
                out.put_slice(&hdr);
                out.put_slice(payload);
            }
            Frame::Pong { payload } => {
                encode_header(&mut hdr, FrameType::Pong, 0, payload.len() as u32);
                out.put_slice(&hdr);
                out.put_slice(payload);
            }
            Frame::Bye { payload } => {
                encode_header(&mut hdr, FrameType::Bye, 0, payload.len() as u32);
                out.put_slice(&hdr);
                out.put_slice(payload);
            }
            Frame::Hello { .. } | Frame::Welcome => {}
        }
    }
    out.freeze()
}

/// Single-task cooperative event loop driving all backend streams for one [`SessionHub`].
async fn run_hub_loop(
    hub: Arc<SessionHub>,
    cfg: SessionConfig,
    mut uplink_rx: mpsc::Receiver<Bytes>,
    external_cancel: &mut watch::Receiver<bool>,
    hub_cancel: &mut watch::Receiver<bool>,
) {
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
    let mut active_stream_count_tracked: usize = 0;

    // 2× idle timeout covers mobile cellular handoffs cleanly.
    let idle_limit_ns = idle_timeout
        .saturating_mul(2)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let idle_check_interval = Duration::from_secs(15);
    let mut idle_tick = tokio::time::interval(idle_check_interval);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Flush any ready downlink frames straight into the cursor replay ring & notify waiters!
        while !outbox.is_empty() {
            outbox.take_batch_into(batch_budget, &mut scratch.batch_frames);
            if !scratch.batch_frames.is_empty() {
                let encoded = encode_frames_to_bytes(&scratch.batch_frames);
                hub.downlink.lock().push(encoded);
                hub.downlink_notify.notify_waiters();
            }
        }

        tokio::select! {
            biased;

            _ = external_cancel.changed() => {
                if *external_cancel.borrow() {
                    break;
                }
            }

            _ = hub_cancel.changed() => {
                if *hub_cancel.borrow() {
                    break;
                }
            }

            maybe_up = uplink_rx.recv() => {
                let Some(payload) = maybe_up else {
                    break;
                };
                hub.touch();
                let frames = match decode_batch(&payload, cfg.limits, Direction::ClientToRelay) {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(error = %e, "hub uplink batch decode failed");
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
                    Err(e) => {
                        debug!(?e, "hub shared-frame state violation");
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
                hub.touch();
            }

            _ = idle_tick.tick() => {
                let last = hub.last_activity_ns.load(Ordering::Relaxed);
                let elapsed = coarse_now_ns().saturating_sub(last);
                if elapsed >= idle_limit_ns {
                    break;
                }
            }
        }
    }

    // Clean teardown: drop all backend streams & wake any blocked HTTP long-polls!
    if let Some(counters) = &cfg.counters {
        for _ in 0..active_stream_count_tracked {
            counters.on_stream_closed();
        }
    }
    streams.clear();
    outbox.clear_all();
    hub.shutdown();
}

/// Helper framing one Shared-Frame v1 batch inside a 4-byte BE length prefix for
/// bidirectional HTTP/2 `POST /stream` transport.
pub fn encode_h2_stream_chunk(batch: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(4 + batch.len());
    buf.put_u32(batch.len() as u32);
    buf.put_slice(batch);
    buf.freeze()
}

/// Parse complete 4-byte BE length-prefixed chunks out of `buf` for HTTP/2 `POST /stream`.
pub fn take_h2_stream_chunks(
    buf: &mut BytesMut,
    limits: FrameLimits,
) -> Result<Vec<Bytes>, HubError> {
    let max_batch = limits.effective_batch_bytes();
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > max_batch {
            return Err(HubError::BatchTooLarge);
        }
        if buf.len() < 4 + len {
            break;
        }
        let _ = buf.split_to(4);
        let chunk = buf.split_to(len).freeze();
        out.push(chunk);
    }
    Ok(out)
}

type DownlinkPollFut = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<(u64, Bytes, usize)>, HubError>> + Send>,
>;

/// Async streaming HTTP response body for full-duplex HTTP/2 `POST /stream`.
pub struct H2DownlinkBody {
    hub: Arc<SessionHub>,
    cursor: u64,
    pending_fut: Option<DownlinkPollFut>,
}

impl std::fmt::Debug for H2DownlinkBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2DownlinkBody")
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl H2DownlinkBody {
    pub fn new(hub: Arc<SessionHub>, start_cursor: u64) -> Self {
        Self {
            hub,
            cursor: start_cursor,
            pending_fut: None,
        }
    }
}

impl hyper::body::Body for H2DownlinkBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        if this.pending_fut.is_none() {
            let hub = Arc::clone(&this.hub);
            let cur = this.cursor;
            this.pending_fut = Some(Box::pin(async move {
                hub.poll_downlink(cur, DEFAULT_LONG_POLL_WAIT).await
            }));
        }
        let fut = this.pending_fut.as_mut().expect("pending_fut set");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(res) => {
                this.pending_fut = None;
                match res {
                    Ok(Some((new_cur, batch, _))) => {
                        this.cursor = new_cur;
                        let framed = encode_h2_stream_chunk(&batch);
                        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(framed))))
                    }
                    Ok(None) => {
                        // Keepalive zero-length heartbeat frame so HTTP/2 proxies stay warm!
                        let hb = encode_h2_stream_chunk(&[]);
                        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(hb))))
                    }
                    Err(HubError::Closed) => std::task::Poll::Ready(None),
                    Err(e) => std::task::Poll::Ready(Some(Err(io::Error::other(e.to_string())))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_conveyor_reorders_out_of_order_and_deduplicates_retries() {
        let mut conv = UplinkConveyor::default();
        // Out-of-order seq 1 and 2 arrive before seq 0
        assert!(
            conv.submit(Some(1), Bytes::from_static(b"b"))
                .unwrap()
                .is_empty()
        );
        assert!(
            conv.submit(Some(2), Bytes::from_static(b"c"))
                .unwrap()
                .is_empty()
        );
        // Duplicate seq 1 is ignored
        assert!(
            conv.submit(Some(1), Bytes::from_static(b"b"))
                .unwrap()
                .is_empty()
        );
        // Seq 0 arrives -> flushes 0, 1, 2 in strict order!
        let ready = conv.submit(Some(0), Bytes::from_static(b"a")).unwrap();
        assert_eq!(
            ready,
            vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c")
            ]
        );
        // Late retry of seq 0 -> idempotent no-op!
        assert!(
            conv.submit(Some(0), Bytes::from_static(b"a"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn downlink_ring_replays_missed_cursors_and_coalesces_batches() {
        let mut ring = DownlinkRing::default();
        let c1 = ring.push(Bytes::from_static(b"one"));
        let c2 = ring.push(Bytes::from_static(b"two"));
        let c3 = ring.push(Bytes::from_static(b"three"));
        assert_eq!((c1, c2, c3), (1, 2, 3));

        // Client retrying from cursor 0 gets coalesced batches 1..=3!
        let (cur, bytes, cnt) = ring.read_since(0, 1024).unwrap().unwrap();
        assert_eq!(cur, 3);
        assert_eq!(cnt, 3);
        assert_eq!(&bytes[..], b"onetwothree");

        // Client retrying from cursor 1 replays 2..=3 without losing anything!
        let (cur2, bytes2, cnt2) = ring.read_since(1, 1024).unwrap().unwrap();
        assert_eq!(cur2, 3);
        assert_eq!(cnt2, 2);
        assert_eq!(&bytes2[..], b"twothree");
    }
}
