//! Zero-copy fused-CTR hot-path relay (`FusedCtrPair` VAES/AES-NI/ARMv8-AES
//! single-pass decrypt+re-encrypt in-place, 5-byte FakeTLS record headroom,
//! single-poll full-duplex `DirectRelay` with zero `into_split()` overhead,
//! zero idle I/O buffers, live quota cutoff, lock-free GCRA pacing, and
//! MiddleProxy multiplexed stream bridging!).

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use mtg_crypto::aes_ctr::{Aes256Ctr, FusedCtrPair};
use mtg_governance::{ClientEntry, ConnSpeedLimiters, FairBucket, GcraLimiter};
use mtg_net::{
    MiddleDownMsg, MiddleStream, OutboundStream, TLS_HEADROOM, coarse_now_ns, coarse_unix_secs,
};
use mtg_protocol::doppel::{DoppelConnState, DoppelParams};
use mtg_protocol::middleproxy::ClientFraming;
use mtg_protocol::tls_record::{
    MAX_TLS_RECORD_PAYLOAD, TlsRecordError, TlsUnframer, stamp_app_data_header,
};
use tokio::io::{AsyncWrite as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::cancel::CancelToken;
use crate::metrics::{DcEndpointStats, GlobalLimitsRuntime, ProxyMetrics, SecretRuntime};

/// Upload read batch capacity (128 KiB — up to 8 FakeTLS records per read(2) syscall).
const UPLOAD_SCRATCH_CAP: usize = 128 * 1024;
/// Maximum zero-memmove FakeTLS upload payload spans tracked on stack per read(2).
const UPLOAD_MAX_SPANS: usize = 16;
/// Download coalesced read capacity (8 x 16 KiB FakeTLS records = ~128 KiB per read(2)/writev(2)!).
const DOWNLOAD_BATCH_RECORDS: usize = 8;
const DOWNLOAD_SCRATCH_CAP: usize = DOWNLOAD_BATCH_RECORDS * MAX_TLS_RECORD_PAYLOAD;
/// Fairness burst cap per direction per poll turn (256 KiB keeps p99/p99.9 flat under 32+ streams).
const POLL_BURST_CAP: usize = 256 * 1024;
/// Minimum interval between resetting the single reusable idle `Sleep` timer (1s).
const IDLE_RESET_GRANULARITY_NS: u64 = 1_000_000_000;

thread_local! {
    /// Per-worker L1/L2-hot scratch buffer for readiness-gated zero-idle-RAM relay.
    /// Idle connections hold ZERO bytes of I/O buffer!
    static RELAY_SCRATCH: RefCell<Box<[u8; UPLOAD_SCRATCH_CAP]>> =
        RefCell::new(vec![0u8; UPLOAD_SCRATCH_CAP].into_boxed_slice().try_into().expect("128 KiB"));
}

/// Context passed into the bidirectional hot relay for one admitted stream.
#[derive(Debug)]
pub struct RelayContext {
    pub is_faketls: bool,
    pub tls_unframer: TlsUnframer,
    pub idle_timeout: Duration,
    pub user: Arc<SecretRuntime>,
    pub client_entry: Arc<ClientEntry>,
    pub global_limits: Arc<GlobalLimitsRuntime>,
    pub conn_limits: Option<Box<ConnSpeedLimiters>>,
    pub dc_stats: Arc<DcEndpointStats>,
    pub doppel: Option<Box<(DoppelConnState, DoppelParams)>>,
    pub cancel: CancelToken,
    pub metrics: Arc<ProxyMetrics>,
}

/// Optional boxed Doppelganger cadence state (costs only 8 bytes when disabled!).
struct DoppelRelayState {
    conn: DoppelConnState,
    params: DoppelParams,
    next_cap: Option<usize>,
    /// Reusable pinned Sleep timer (allocated at most once per shaped stream,
    /// reset in-place via `.as_mut().reset(...)` — zero per-record heap allocs!).
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    delay_active: bool,
}

enum DrainResult {
    Done,
    Pending,
    Closed,
}

enum StepOutcome {
    Done,
    NeedPace { is_upload: bool, bytes: usize },
}

/// Single-poll full-duplex relay owning `(client, dc)` directly by value —
/// eliminates `into_split()` (4 `Arc<TcpStream>`s), cuts `tokio::time::Sleep`
/// entries in half (1 instead of 2), and holds ZERO bytes of heap I/O buffer
/// whenever a stream is idle or uncongested!
///
/// Constructed synchronously via [`DirectRelay::new`] and driven via
/// [`DirectRelay::run`] (`&mut self`) so the 4 expanded AES-256-CTR schedules
/// appear **strictly once** in the async task frame (zero duplicate generator slots!).
pub struct DirectRelay {
    client: TcpStream,
    dc: OutboundStream,
    fused_up: FusedCtrPair,
    fused_down: FusedCtrPair,
    tls_unframer: TlsUnframer,
    is_faketls: bool,
    client_eof: bool,
    dc_eof: bool,
    dc_wr_closed: bool,
    client_wr_closed: bool,
    idle_timeout: Duration,
    last_reset_ns: u64,
    user: Arc<SecretRuntime>,
    client_entry: Arc<ClientEntry>,
    global_limits: Arc<GlobalLimitsRuntime>,
    conn_limits: Option<Box<ConnSpeedLimiters>>,
    dc_stats: Arc<DcEndpointStats>,
    metrics: Arc<ProxyMetrics>,
    cancel: CancelToken,
    doppel: Option<Box<DoppelRelayState>>,
    /// Leftover application bytes already read during handshake (drained & freed immediately).
    initial_app: Vec<u8>,
    /// Only allocated on write backpressure or pacing; reclaimed back to 0 B when idle!
    up_pending: Vec<u8>,
    up_off: usize,
    down_pending: Vec<u8>,
    down_off: usize,
}

impl DirectRelay {
    /// Construct a ready-to-run [`DirectRelay`] synchronously (fusing ciphers
    /// immediately so only ONE copy of the 4 AES-256-CTR schedules ever exists).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: TcpStream,
        dc: OutboundStream,
        client_recv_initial: Vec<u8>,
        client_ciphers: (Aes256Ctr, Aes256Ctr), // (recv_from_client, send_to_client)
        dc_ciphers: (Aes256Ctr, Aes256Ctr),     // (recv_from_dc, send_to_dc)
        ctx: RelayContext,
    ) -> Self {
        let fused_up = FusedCtrPair::new(client_ciphers.0, dc_ciphers.1);
        let fused_down = FusedCtrPair::new(dc_ciphers.0, client_ciphers.1);
        ctx.dc_stats.active_conns.fetch_add(1, Ordering::Relaxed);
        let doppel = ctx.doppel.map(|b| {
            let (conn, params) = *b;
            Box::new(DoppelRelayState {
                conn,
                params,
                next_cap: None,
                delay: None,
                delay_active: false,
            })
        });
        Self {
            client,
            dc,
            fused_up,
            fused_down,
            tls_unframer: ctx.tls_unframer,
            is_faketls: ctx.is_faketls,
            client_eof: false,
            dc_eof: false,
            dc_wr_closed: false,
            client_wr_closed: false,
            idle_timeout: ctx.idle_timeout,
            last_reset_ns: coarse_now_ns(),
            user: ctx.user,
            client_entry: ctx.client_entry,
            global_limits: ctx.global_limits,
            conn_limits: ctx.conn_limits,
            dc_stats: ctx.dc_stats,
            metrics: ctx.metrics,
            cancel: ctx.cancel,
            doppel,
            initial_app: client_recv_initial,
            up_pending: Vec::new(),
            up_off: 0,
            down_pending: Vec::new(),
            down_off: 0,
        }
    }

    #[inline]
    fn maybe_reclaim_buf(buf: &mut Vec<u8>, off: &mut usize) {
        if buf.is_empty() && buf.capacity() > 0 {
            *buf = Vec::new();
            *off = 0;
        }
    }

    #[inline]
    fn try_drain_buf_outbound(
        sock: &mut OutboundStream,
        buf: &mut Vec<u8>,
        off: &mut usize,
        cx: &mut Context<'_>,
    ) -> DrainResult {
        while *off < buf.len() {
            match sock.try_write_with_cx(cx, &buf[*off..]) {
                Ok(0) => return DrainResult::Closed,
                Ok(w) => *off += w,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if !sock.is_tcp() {
                        // Non-TCP tunnel already registered `cx.waker()` inside `poll_write`.
                        return DrainResult::Pending;
                    }
                    match sock.poll_write_ready_compat(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => return DrainResult::Closed,
                        Poll::Pending => return DrainResult::Pending,
                    }
                }
                Err(_) => return DrainResult::Closed,
            }
        }
        buf.clear();
        *off = 0;
        DrainResult::Done
    }

    #[inline]
    fn try_drain_buf(
        sock: &TcpStream,
        buf: &mut Vec<u8>,
        off: &mut usize,
        cx: &mut Context<'_>,
    ) -> DrainResult {
        while *off < buf.len() {
            match sock.try_write(&buf[*off..]) {
                Ok(0) => return DrainResult::Closed,
                Ok(w) => *off += w,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match sock.poll_write_ready(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => return DrainResult::Closed,
                        Poll::Pending => return DrainResult::Pending,
                    }
                }
                Err(_) => return DrainResult::Closed,
            }
        }
        buf.clear();
        *off = 0;
        DrainResult::Done
    }

    /// Account moved bytes, reset the shared idle timer at most once per second,
    /// and return `true` if quota ceiling was exceeded (stream must close!).
    #[inline]
    fn account_and_refresh_idle(
        &mut self,
        up_moved: usize,
        down_moved: usize,
        mut idle_sleep: Pin<&mut tokio::time::Sleep>,
        cx: &mut Context<'_>,
    ) -> bool {
        if up_moved == 0 && down_moved == 0 {
            return false;
        }
        let now_ns = coarse_now_ns();
        if now_ns.saturating_sub(self.last_reset_ns) >= IDLE_RESET_GRANULARITY_NS {
            self.last_reset_ns = now_ns;
            idle_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + self.idle_timeout);
            // Re-register timer wheel entry after reset!
            let _ = idle_sleep.as_mut().poll(cx);
        }

        let now_unix = coarse_unix_secs();
        self.client_entry.mark_seen(now_unix);

        if up_moved > 0 {
            self.client_entry
                .bytes_in
                .fetch_add(up_moved as i64, Ordering::Relaxed);
            self.dc_stats
                .bytes_from_client
                .fetch_add(up_moved as u64, Ordering::Relaxed);
            if self.user.record_traffic(up_moved as i64, true, now_unix) {
                self.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if self.global_limits.record_traffic(up_moved as i64) {
                return true;
            }
        }
        if down_moved > 0 {
            self.client_entry
                .bytes_out
                .fetch_add(down_moved as i64, Ordering::Relaxed);
            self.dc_stats
                .bytes_to_client
                .fetch_add(down_moved as u64, Ordering::Relaxed);
            if self.user.record_traffic(down_moved as i64, false, now_unix) {
                self.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if self.global_limits.record_traffic(down_moved as i64) {
                return true;
            }
        }
        false
    }

    /// Core full-duplex readiness poll servicing BOTH upload (`client -> dc`)
    /// and download (`dc -> client`) in ONE poll pass!
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        mut idle_sleep: Pin<&mut tokio::time::Sleep>,
    ) -> Poll<StepOutcome> {
        // 0. Lock-free cancellation check (1 atomic load) + idle timer check
        if self.cancel.poll_cancelled(cx).is_ready() {
            return Poll::Ready(StepOutcome::Done);
        }
        if idle_sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(StepOutcome::Done);
        }

        let mut up_moved = 0usize;
        let mut down_moved = 0usize;
        let mut yield_needed = false;

        // ---------------------------------------------------------------------
        // 1. UPLOAD: client -> DC (with true RFC 793 half-close!)
        // ---------------------------------------------------------------------
        let up_can_read = if self.up_off < self.up_pending.len() {
            match Self::try_drain_buf_outbound(
                &mut self.dc,
                &mut self.up_pending,
                &mut self.up_off,
                cx,
            ) {
                DrainResult::Done => {
                    if self.client_eof && !self.dc_wr_closed {
                        self.dc_wr_closed = true;
                        let _ = Pin::new(&mut self.dc).poll_shutdown(cx);
                    }
                    !self.client_eof
                }
                DrainResult::Pending => false,
                DrainResult::Closed => {
                    self.client_eof = true;
                    self.dc_wr_closed = true;
                    self.up_pending.clear();
                    self.up_off = 0;
                    false
                }
            }
        } else {
            !self.client_eof
        };

        if up_can_read {
            match self.client.poll_read_ready(cx) {
                Poll::Pending => {
                    Self::maybe_reclaim_buf(&mut self.up_pending, &mut self.up_off);
                }
                Poll::Ready(Err(_)) => return Poll::Ready(StepOutcome::Done),
                Poll::Ready(Ok(())) => {
                    let up_paced = has_pacing(
                        true,
                        &self.user,
                        &self.client_entry,
                        &self.global_limits,
                        self.conn_limits.as_deref(),
                    );
                    let mut spurious_wb = 0u8;

                    loop {
                        let step = RELAY_SCRATCH.with(|cell| {
                            let mut scratch = cell.borrow_mut();
                            match self.client.try_read(&mut scratch[..UPLOAD_SCRATCH_CAP]) {
                                Ok(0) => ReadStep::Eof,
                                Ok(n) => {
                                    if self.is_faketls {
                                        // Zero-memmove fast path: locate payload spans in-place,
                                        // run fused CTR directly on each span, and writev(2)!
                                        let mut spans = [(0usize, 0usize); UPLOAD_MAX_SPANS];
                                        match self
                                            .tls_unframer
                                            .unframe_spans(&scratch[..n], &mut spans)
                                        {
                                            Ok(Some(0)) => return ReadStep::ZeroApp,
                                            Ok(Some(span_count)) => {
                                                let mut moved = 0usize;
                                                for &(s, e) in &spans[..span_count] {
                                                    moved += e - s;
                                                }
                                                if up_paced {
                                                    self.up_pending.clear();
                                                    self.up_off = 0;
                                                    self.up_pending.reserve(moved);
                                                    for &(s, e) in &spans[..span_count] {
                                                        self.up_pending
                                                            .extend_from_slice(&scratch[s..e]);
                                                    }
                                                    return ReadStep::NeedPace(moved);
                                                }
                                                for &(s, e) in &spans[..span_count] {
                                                    self.fused_up
                                                        .apply_fused_in_place(&mut scratch[s..e]);
                                                }
                                                if span_count == 1 {
                                                    let (s, e) = spans[0];
                                                    return match self
                                                        .dc
                                                        .try_write_with_cx(cx, &scratch[s..e])
                                                    {
                                                        Ok(w) if w == moved => {
                                                            ReadStep::Sent(moved)
                                                        }
                                                        Ok(0) => ReadStep::Err,
                                                        Ok(w) => {
                                                            self.up_pending.clear();
                                                            self.up_off = 0;
                                                            self.up_pending.extend_from_slice(
                                                                &scratch[s + w..e],
                                                            );
                                                            ReadStep::Partial(moved)
                                                        }
                                                        Err(ref err)
                                                            if err.kind()
                                                                == io::ErrorKind::WouldBlock =>
                                                        {
                                                            self.up_pending.clear();
                                                            self.up_off = 0;
                                                            self.up_pending
                                                                .extend_from_slice(&scratch[s..e]);
                                                            ReadStep::Partial(moved)
                                                        }
                                                        Err(_) => ReadStep::Err,
                                                    };
                                                }
                                                let mut iov = [IoSlice::new(&[]); UPLOAD_MAX_SPANS];
                                                for (idx, &(s, e)) in
                                                    spans[..span_count].iter().enumerate()
                                                {
                                                    iov[idx] = IoSlice::new(&scratch[s..e]);
                                                }
                                                return match self.dc.try_write_vectored_with_cx(
                                                    cx,
                                                    &iov[..span_count],
                                                ) {
                                                    Ok(w) if w == moved => ReadStep::Sent(moved),
                                                    Ok(0) => ReadStep::Err,
                                                    Ok(w) => {
                                                        self.up_pending.clear();
                                                        self.up_off = 0;
                                                        copy_vectored_tail(
                                                            &iov[..span_count],
                                                            w,
                                                            &mut self.up_pending,
                                                        );
                                                        ReadStep::Partial(moved)
                                                    }
                                                    Err(ref err)
                                                        if err.kind()
                                                            == io::ErrorKind::WouldBlock =>
                                                    {
                                                        self.up_pending.clear();
                                                        self.up_off = 0;
                                                        copy_vectored_tail(
                                                            &iov[..span_count],
                                                            0,
                                                            &mut self.up_pending,
                                                        );
                                                        ReadStep::Partial(moved)
                                                    }
                                                    Err(_) => ReadStep::Err,
                                                };
                                            }
                                            Ok(None) => {
                                                // Rare: >16 tiny TLS records in one read -> compact fallback.
                                                let moved = match self
                                                    .tls_unframer
                                                    .unframe_in_place(&mut scratch[..n])
                                                {
                                                    Ok(m) => m,
                                                    Err(TlsRecordError::AlertClose) => {
                                                        return ReadStep::AlertEof;
                                                    }
                                                    Err(_) => return ReadStep::Err,
                                                };
                                                if moved == 0 {
                                                    return ReadStep::ZeroApp;
                                                }
                                                if up_paced {
                                                    self.up_pending.clear();
                                                    self.up_off = 0;
                                                    self.up_pending
                                                        .extend_from_slice(&scratch[..moved]);
                                                    return ReadStep::NeedPace(moved);
                                                }
                                                self.fused_up
                                                    .apply_fused_in_place(&mut scratch[..moved]);
                                                return match self
                                                    .dc
                                                    .try_write_with_cx(cx, &scratch[..moved])
                                                {
                                                    Ok(w) if w == moved => ReadStep::Sent(moved),
                                                    Ok(0) => ReadStep::Err,
                                                    Ok(w) => {
                                                        self.up_pending.clear();
                                                        self.up_off = 0;
                                                        self.up_pending
                                                            .extend_from_slice(&scratch[w..moved]);
                                                        ReadStep::Partial(moved)
                                                    }
                                                    Err(ref err)
                                                        if err.kind()
                                                            == io::ErrorKind::WouldBlock =>
                                                    {
                                                        self.up_pending.clear();
                                                        self.up_off = 0;
                                                        self.up_pending
                                                            .extend_from_slice(&scratch[..moved]);
                                                        ReadStep::Partial(moved)
                                                    }
                                                    Err(_) => ReadStep::Err,
                                                };
                                            }
                                            Err(TlsRecordError::AlertClose) => {
                                                return ReadStep::AlertEof;
                                            }
                                            Err(_) => return ReadStep::Err,
                                        }
                                    }

                                    let moved = n;
                                    if up_paced {
                                        self.up_pending.clear();
                                        self.up_off = 0;
                                        self.up_pending.extend_from_slice(&scratch[..moved]);
                                        return ReadStep::NeedPace(moved);
                                    }
                                    self.fused_up.apply_fused_in_place(&mut scratch[..moved]);
                                    match self.dc.try_write_with_cx(cx, &scratch[..moved]) {
                                        Ok(w) if w == moved => ReadStep::Sent(moved),
                                        Ok(0) => ReadStep::Err,
                                        Ok(w) => {
                                            self.up_pending.clear();
                                            self.up_off = 0;
                                            self.up_pending.extend_from_slice(&scratch[w..moved]);
                                            ReadStep::Partial(moved)
                                        }
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            self.up_pending.clear();
                                            self.up_off = 0;
                                            self.up_pending.extend_from_slice(&scratch[..moved]);
                                            ReadStep::Partial(moved)
                                        }
                                        Err(_) => ReadStep::Err,
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    ReadStep::WouldBlock
                                }
                                Err(_) => ReadStep::Err,
                            }
                        });

                        match step {
                            ReadStep::Sent(moved) => {
                                spurious_wb = 0;
                                up_moved += moved;
                                if self.is_faketls && self.tls_unframer.alert_seen() {
                                    self.metrics
                                        .faketls
                                        .alert_closes
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.client_eof = true;
                                    if !self.dc_wr_closed {
                                        self.dc_wr_closed = true;
                                        let _ = Pin::new(&mut self.dc).poll_shutdown(cx);
                                    }
                                    break;
                                }
                                if up_moved >= POLL_BURST_CAP {
                                    yield_needed = true;
                                    break;
                                }
                            }
                            ReadStep::ZeroApp => {
                                spurious_wb = 0;
                            }
                            ReadStep::Partial(moved) => {
                                up_moved += moved;
                                if self.is_faketls && self.tls_unframer.alert_seen() {
                                    self.metrics
                                        .faketls
                                        .alert_closes
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.client_eof = true;
                                }
                                match Self::try_drain_buf_outbound(
                                    &mut self.dc,
                                    &mut self.up_pending,
                                    &mut self.up_off,
                                    cx,
                                ) {
                                    DrainResult::Done => {
                                        if self.client_eof {
                                            if !self.dc_wr_closed {
                                                self.dc_wr_closed = true;
                                                let _ = Pin::new(&mut self.dc).poll_shutdown(cx);
                                            }
                                            break;
                                        }
                                        if up_moved >= POLL_BURST_CAP {
                                            yield_needed = true;
                                            break;
                                        }
                                    }
                                    DrainResult::Pending => break,
                                    DrainResult::Closed => {
                                        let _ = self.account_and_refresh_idle(
                                            up_moved,
                                            0,
                                            idle_sleep.as_mut(),
                                            cx,
                                        );
                                        return Poll::Ready(StepOutcome::Done);
                                    }
                                }
                            }
                            ReadStep::NeedPace(bytes) => {
                                if self.account_and_refresh_idle(
                                    up_moved,
                                    0,
                                    idle_sleep.as_mut(),
                                    cx,
                                ) {
                                    return Poll::Ready(StepOutcome::Done);
                                }
                                return Poll::Ready(StepOutcome::NeedPace {
                                    is_upload: true,
                                    bytes,
                                });
                            }
                            ReadStep::WouldBlock => match self.client.poll_read_ready(cx) {
                                Poll::Pending => {
                                    Self::maybe_reclaim_buf(&mut self.up_pending, &mut self.up_off);
                                    break;
                                }
                                Poll::Ready(Err(_)) => {
                                    let _ = self.account_and_refresh_idle(
                                        up_moved,
                                        0,
                                        idle_sleep.as_mut(),
                                        cx,
                                    );
                                    return Poll::Ready(StepOutcome::Done);
                                }
                                Poll::Ready(Ok(())) => {
                                    spurious_wb += 1;
                                    if spurious_wb >= 4 {
                                        yield_needed = true;
                                        break;
                                    }
                                }
                            },
                            ReadStep::AlertEof => {
                                self.metrics
                                    .faketls
                                    .alert_closes
                                    .fetch_add(1, Ordering::Relaxed);
                                self.client_eof = true;
                                if self.up_off >= self.up_pending.len() && !self.dc_wr_closed {
                                    self.dc_wr_closed = true;
                                    let _ = Pin::new(&mut self.dc).poll_shutdown(cx);
                                }
                                break;
                            }
                            ReadStep::Eof => {
                                self.client_eof = true;
                                if self.up_off >= self.up_pending.len() && !self.dc_wr_closed {
                                    self.dc_wr_closed = true;
                                    let _ = Pin::new(&mut self.dc).poll_shutdown(cx);
                                }
                                break;
                            }
                            ReadStep::Err => {
                                let _ = self.account_and_refresh_idle(
                                    up_moved,
                                    0,
                                    idle_sleep.as_mut(),
                                    cx,
                                );
                                return Poll::Ready(StepOutcome::Done);
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------------
        // 2. DOWNLOAD: DC -> client (with true RFC 793 half-close!)
        // ---------------------------------------------------------------------
        let down_can_read = if self.down_off < self.down_pending.len() {
            match Self::try_drain_buf(&self.client, &mut self.down_pending, &mut self.down_off, cx)
            {
                DrainResult::Done => {
                    if self.dc_eof && !self.client_wr_closed {
                        self.client_wr_closed = true;
                        let _ = Pin::new(&mut self.client).poll_shutdown(cx);
                    }
                    !self.dc_eof
                }
                DrainResult::Pending => false,
                DrainResult::Closed => {
                    let _ = self.account_and_refresh_idle(up_moved, 0, idle_sleep.as_mut(), cx);
                    return Poll::Ready(StepOutcome::Done);
                }
            }
        } else {
            !self.dc_eof
        };

        if down_can_read {
            // Optional Doppelganger cadence shaping (zero cost when `self.doppel` is `None`!)
            let mut doppel_waiting = false;
            let mut max_read = DOWNLOAD_SCRATCH_CAP;
            let mut single_record_mode = false;
            let mut burst_full_speed = false;

            if self.is_faketls
                && let Some(d) = self.doppel.as_mut()
            {
                if d.delay_active
                    && let Some(delay) = d.delay.as_mut()
                {
                    if delay.as_mut().poll(cx).is_pending() {
                        doppel_waiting = true;
                    } else {
                        d.delay_active = false;
                    }
                }
                if !doppel_waiting {
                    let now_ns = coarse_now_ns();
                    if d.next_cap.is_none() && d.conn.is_burst_full_speed(now_ns) {
                        // Burst mode after initial TTFB pacing & DRS ramp: unlock
                        // full 8-record 128 KiB writev(2) zero-copy batching!
                        burst_full_speed = true;
                    } else {
                        single_record_mode = true;
                        if d.next_cap.is_none() {
                            let (delay_dur, cap) = d.conn.next_record(&d.params, now_ns);
                            d.next_cap = Some(cap.clamp(1, MAX_TLS_RECORD_PAYLOAD));
                            if !delay_dur.is_zero() {
                                let target = tokio::time::Instant::now() + delay_dur;
                                let sleep = if let Some(existing) = d.delay.as_mut() {
                                    existing.as_mut().reset(target);
                                    existing
                                } else {
                                    d.delay = Some(Box::pin(tokio::time::sleep_until(target)));
                                    d.delay.as_mut().expect("just inserted")
                                };
                                if sleep.as_mut().poll(cx).is_pending() {
                                    d.delay_active = true;
                                    doppel_waiting = true;
                                }
                            }
                        }
                        if !doppel_waiting {
                            max_read = d.next_cap.unwrap_or(MAX_TLS_RECORD_PAYLOAD);
                        }
                    }
                }
            }

            if !doppel_waiting {
                match self.dc.poll_read_ready_compat(cx) {
                    Poll::Pending => {
                        Self::maybe_reclaim_buf(&mut self.down_pending, &mut self.down_off);
                    }
                    Poll::Ready(Err(_)) => {
                        let _ = self.account_and_refresh_idle(up_moved, 0, idle_sleep.as_mut(), cx);
                        return Poll::Ready(StepOutcome::Done);
                    }
                    Poll::Ready(Ok(())) => {
                        let down_paced = has_pacing(
                            false,
                            &self.user,
                            &self.client_entry,
                            &self.global_limits,
                            self.conn_limits.as_deref(),
                        );
                        let mut spurious_wb = 0u8;

                        loop {
                            let step = RELAY_SCRATCH.with(|cell| {
                                let mut scratch = cell.borrow_mut();
                                match self.dc.try_read_with_cx(cx, &mut scratch[..max_read]) {
                                    Ok(0) => ReadStep::Eof,
                                    Ok(n) => {
                                        if down_paced {
                                            self.down_pending.clear();
                                            self.down_off = 0;
                                            self.down_pending.extend_from_slice(&scratch[..n]);
                                            return ReadStep::NeedPace(n);
                                        }
                                        self.fused_down.apply_fused_in_place(&mut scratch[..n]);

                                        if !self.is_faketls {
                                            match self.client.try_write(&scratch[..n]) {
                                                Ok(w) if w == n => return ReadStep::Sent(n),
                                                Ok(0) => return ReadStep::Err,
                                                Ok(w) => {
                                                    self.down_pending.clear();
                                                    self.down_off = 0;
                                                    self.down_pending
                                                        .extend_from_slice(&scratch[w..n]);
                                                    return ReadStep::Partial(n);
                                                }
                                                Err(ref e)
                                                    if e.kind() == io::ErrorKind::WouldBlock =>
                                                {
                                                    self.down_pending.clear();
                                                    self.down_off = 0;
                                                    self.down_pending
                                                        .extend_from_slice(&scratch[..n]);
                                                    return ReadStep::Partial(n);
                                                }
                                                Err(_) => return ReadStep::Err,
                                            }
                                        }

                                        // FakeTLS multi-record vectored writev(2): up to 4 records
                                        // (each <= 16,384 bytes) stamped on stack in ONE syscall!
                                        let mut hdrs =
                                            [[0u8; TLS_HEADROOM]; DOWNLOAD_BATCH_RECORDS];
                                        let mut iov: [IoSlice<'_>; DOWNLOAD_BATCH_RECORDS * 2] =
                                            [IoSlice::new(&[]); DOWNLOAD_BATCH_RECORDS * 2];
                                        let mut rec_count = 0usize;
                                        let mut off = 0usize;
                                        let mut total_wire = 0usize;

                                        while off < n {
                                            let chunk_len = (n - off).min(MAX_TLS_RECORD_PAYLOAD);
                                            stamp_app_data_header(
                                                &mut hdrs[rec_count],
                                                chunk_len as u16,
                                            );
                                            total_wire += TLS_HEADROOM + chunk_len;
                                            off += chunk_len;
                                            rec_count += 1;
                                        }

                                        let mut off2 = 0usize;
                                        for (idx, hdr) in hdrs.iter().enumerate().take(rec_count) {
                                            let chunk_len = (n - off2).min(MAX_TLS_RECORD_PAYLOAD);
                                            iov[idx * 2] = IoSlice::new(hdr);
                                            iov[idx * 2 + 1] =
                                                IoSlice::new(&scratch[off2..off2 + chunk_len]);
                                            off2 += chunk_len;
                                        }

                                        match self.client.try_write_vectored(&iov[..rec_count * 2])
                                        {
                                            Ok(w) if w == total_wire => ReadStep::Sent(n),
                                            Ok(0) => ReadStep::Err,
                                            Ok(w) => {
                                                self.down_pending.clear();
                                                self.down_off = 0;
                                                copy_vectored_tail(
                                                    &iov[..rec_count * 2],
                                                    w,
                                                    &mut self.down_pending,
                                                );
                                                ReadStep::Partial(n)
                                            }
                                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                                self.down_pending.clear();
                                                self.down_off = 0;
                                                copy_vectored_tail(
                                                    &iov[..rec_count * 2],
                                                    0,
                                                    &mut self.down_pending,
                                                );
                                                ReadStep::Partial(n)
                                            }
                                            Err(_) => ReadStep::Err,
                                        }
                                    }
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        ReadStep::WouldBlock
                                    }
                                    Err(_) => ReadStep::Err,
                                }
                            });

                            match step {
                                ReadStep::Sent(n) => {
                                    spurious_wb = 0;
                                    down_moved += n;
                                    if burst_full_speed && let Some(d) = self.doppel.as_mut() {
                                        let recs = n.div_ceil(MAX_TLS_RECORD_PAYLOAD) as u32;
                                        d.conn.touch_burst_write(coarse_now_ns(), recs);
                                    }
                                    if single_record_mode {
                                        if let Some(d) = self.doppel.as_mut() {
                                            d.next_cap = None;
                                        }
                                        yield_needed = true;
                                        break;
                                    }
                                    if down_moved >= POLL_BURST_CAP {
                                        yield_needed = true;
                                        break;
                                    }
                                }
                                ReadStep::ZeroApp => {
                                    spurious_wb = 0;
                                }
                                ReadStep::Partial(n) => {
                                    down_moved += n;
                                    if burst_full_speed && let Some(d) = self.doppel.as_mut() {
                                        let recs = n.div_ceil(MAX_TLS_RECORD_PAYLOAD) as u32;
                                        d.conn.touch_burst_write(coarse_now_ns(), recs);
                                    }
                                    if single_record_mode && let Some(d) = self.doppel.as_mut() {
                                        d.next_cap = None;
                                    }
                                    match Self::try_drain_buf(
                                        &self.client,
                                        &mut self.down_pending,
                                        &mut self.down_off,
                                        cx,
                                    ) {
                                        DrainResult::Done => {
                                            if single_record_mode || down_moved >= POLL_BURST_CAP {
                                                yield_needed = true;
                                                break;
                                            }
                                        }
                                        DrainResult::Pending => break,
                                        DrainResult::Closed => {
                                            let _ = self.account_and_refresh_idle(
                                                up_moved,
                                                down_moved,
                                                idle_sleep.as_mut(),
                                                cx,
                                            );
                                            return Poll::Ready(StepOutcome::Done);
                                        }
                                    }
                                }
                                ReadStep::NeedPace(bytes) => {
                                    if single_record_mode && let Some(d) = self.doppel.as_mut() {
                                        d.next_cap = None;
                                    }
                                    if self.account_and_refresh_idle(
                                        up_moved,
                                        down_moved,
                                        idle_sleep.as_mut(),
                                        cx,
                                    ) {
                                        return Poll::Ready(StepOutcome::Done);
                                    }
                                    return Poll::Ready(StepOutcome::NeedPace {
                                        is_upload: false,
                                        bytes,
                                    });
                                }
                                ReadStep::WouldBlock => {
                                    if !self.dc.is_tcp() {
                                        // Non-TCP tunnel already registered `cx.waker()` inside `poll_read`.
                                        Self::maybe_reclaim_buf(
                                            &mut self.down_pending,
                                            &mut self.down_off,
                                        );
                                        break;
                                    }
                                    match self.dc.poll_read_ready_compat(cx) {
                                        Poll::Pending => {
                                            Self::maybe_reclaim_buf(
                                                &mut self.down_pending,
                                                &mut self.down_off,
                                            );
                                            break;
                                        }
                                        Poll::Ready(Err(_)) => {
                                            let _ = self.account_and_refresh_idle(
                                                up_moved,
                                                down_moved,
                                                idle_sleep.as_mut(),
                                                cx,
                                            );
                                            return Poll::Ready(StepOutcome::Done);
                                        }
                                        Poll::Ready(Ok(())) => {
                                            spurious_wb += 1;
                                            if spurious_wb >= 4 {
                                                yield_needed = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                ReadStep::AlertEof | ReadStep::Eof => {
                                    self.dc_eof = true;
                                    if self.down_off >= self.down_pending.len()
                                        && !self.client_wr_closed
                                    {
                                        self.client_wr_closed = true;
                                        let _ = Pin::new(&mut self.client).poll_shutdown(cx);
                                    }
                                    break;
                                }
                                ReadStep::Err => {
                                    let _ = self.account_and_refresh_idle(
                                        up_moved,
                                        down_moved,
                                        idle_sleep.as_mut(),
                                        cx,
                                    );
                                    return Poll::Ready(StepOutcome::Done);
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------------
        // 3. Account moved bytes, check quota, reset idle timer at 1s cadence,
        //    and close cleanly once BOTH directions have reached EOF & drained!
        // ---------------------------------------------------------------------
        if self.account_and_refresh_idle(up_moved, down_moved, idle_sleep.as_mut(), cx) {
            return Poll::Ready(StepOutcome::Done);
        }

        if self.client_eof
            && self.dc_eof
            && self.up_off >= self.up_pending.len()
            && self.down_off >= self.down_pending.len()
        {
            return Poll::Ready(StepOutcome::Done);
        }

        if yield_needed {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for DirectRelay {
    fn drop(&mut self) {
        self.dc_stats.active_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for DirectRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRelay")
            .field("is_faketls", &self.is_faketls)
            .field("idle_timeout", &self.idle_timeout)
            .field("up_pending_len", &self.up_pending.len())
            .field("down_pending_len", &self.down_pending.len())
            .finish_non_exhaustive()
    }
}

impl DirectRelay {
    /// Drive the single-poll full-duplex relay to completion by `&mut self`
    /// (zero extra copies of the 1.15 KiB cipher state in the async frame!).
    pub async fn run(&mut self) {
        // Cold/rare path: flush any leftover already-unframed app bytes read with handshake.
        // Boxed so its future never bloats steady-state idle connection memory!
        if !self.initial_app.is_empty() {
            let initial = std::mem::take(&mut self.initial_app);
            if !Box::pin(flush_initial_app(self, initial)).await {
                return;
            }
        }

        // If a TLS Alert (0x15) arrived pipelined in the same TCP read as the
        // initial obfs2 frame, propagate half-close (`SHUT_WR`) to the DC immediately!
        if self.is_faketls && self.tls_unframer.alert_seen() && !self.client_eof {
            self.metrics
                .faketls
                .alert_closes
                .fetch_add(1, Ordering::Relaxed);
            self.client_eof = true;
            if !self.dc_wr_closed {
                self.dc_wr_closed = true;
                let _ = self.dc.shutdown().await;
            }
        }

        let idle_sleep = tokio::time::sleep(self.idle_timeout);
        tokio::pin!(idle_sleep);

        loop {
            match poll_fn(|cx| self.poll_step(cx, idle_sleep.as_mut())).await {
                StepOutcome::Done => return,
                StepOutcome::NeedPace { is_upload, bytes } => {
                    // Boxed so GCRA Sleep futures NEVER inflate idle connection frame size!
                    let ok = Box::pin(pace_and_flush_direct(self, is_upload, bytes)).await;
                    if !ok {
                        return;
                    }
                    let now_ns = coarse_now_ns();
                    if now_ns.saturating_sub(self.last_reset_ns) >= IDLE_RESET_GRANULARITY_NS {
                        self.last_reset_ns = now_ns;
                        idle_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + self.idle_timeout);
                    }
                }
            }
        }
    }
}

/// Flush leftover application payload received in the same TCP segment as the
/// Obfuscated2 handshake (boxed cold path — zero steady-state frame bloat!).
async fn flush_initial_app(state: &mut DirectRelay, mut initial_app: Vec<u8>) -> bool {
    let n = initial_app.len();
    if pace_transfer(
        n,
        true,
        &state.user,
        &state.client_entry,
        &state.global_limits,
        state.conn_limits.as_deref(),
        &state.cancel,
    )
    .await
    .is_err()
    {
        return false;
    }
    state.fused_up.apply_fused_in_place(&mut initial_app);
    if state.dc.write_all(&initial_app).await.is_err() {
        return false;
    }
    let now_unix = coarse_unix_secs();
    state
        .client_entry
        .bytes_in
        .fetch_add(n as i64, Ordering::Relaxed);
    state.client_entry.mark_seen(now_unix);
    state
        .dc_stats
        .bytes_from_client
        .fetch_add(n as u64, Ordering::Relaxed);
    if state.user.record_traffic(n as i64, true, now_unix) {
        state.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    !state.global_limits.record_traffic(n as i64)
}

/// Paced transfer flush path (boxed cold path — only allocated when speed/fair
/// limits are active!).
async fn pace_and_flush_direct(state: &mut DirectRelay, is_upload: bool, bytes: usize) -> bool {
    if pace_transfer(
        bytes,
        is_upload,
        &state.user,
        &state.client_entry,
        &state.global_limits,
        state.conn_limits.as_deref(),
        &state.cancel,
    )
    .await
    .is_err()
    {
        return false;
    }

    if is_upload {
        state.fused_up.apply_fused_in_place(&mut state.up_pending);
        if state.dc.write_all(&state.up_pending).await.is_err() {
            return false;
        }
        state.up_pending.clear();
        state.up_off = 0;

        let now_unix = coarse_unix_secs();
        state
            .client_entry
            .bytes_in
            .fetch_add(bytes as i64, Ordering::Relaxed);
        state.client_entry.mark_seen(now_unix);
        state
            .dc_stats
            .bytes_from_client
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if state.user.record_traffic(bytes as i64, true, now_unix) {
            state.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if state.global_limits.record_traffic(bytes as i64) {
            return false;
        }
    } else {
        state
            .fused_down
            .apply_fused_in_place(&mut state.down_pending);
        if state.is_faketls {
            let mut framed = Vec::with_capacity(
                state.down_pending.len() + TLS_HEADROOM * DOWNLOAD_BATCH_RECORDS,
            );
            let mut off = 0usize;
            while off < state.down_pending.len() {
                let take = (state.down_pending.len() - off).min(MAX_TLS_RECORD_PAYLOAD);
                let mut hdr = [0u8; TLS_HEADROOM];
                stamp_app_data_header(&mut hdr, take as u16);
                framed.extend_from_slice(&hdr);
                framed.extend_from_slice(&state.down_pending[off..off + take]);
                off += take;
            }
            if state.client.write_all(&framed).await.is_err() {
                return false;
            }
        } else if state.client.write_all(&state.down_pending).await.is_err() {
            return false;
        }
        state.down_pending.clear();
        state.down_off = 0;

        let now_unix = coarse_unix_secs();
        state
            .client_entry
            .bytes_out
            .fetch_add(bytes as i64, Ordering::Relaxed);
        state.client_entry.mark_seen(now_unix);
        state
            .dc_stats
            .bytes_to_client
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if state.user.record_traffic(bytes as i64, false, now_unix) {
            state.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if state.global_limits.record_traffic(bytes as i64) {
            return false;
        }
    }
    true
}

/// Relay traffic between a client socket and a multiplexed [`MiddleStream`]
/// (carrying `ad_tag` over a persistent AES-256-CBC MiddleProxy carrier).
///
/// Zero-idle-RAM design: owns `client: TcpStream` directly (no `into_split`),
/// uses readiness-gated thread-local [`RELAY_SCRATCH`] for all socket reads &
/// writes (0 bytes of permanent I/O buffers while idle!), resets one shared
/// idle timer at 1s granularity, and implements byte-exact intermediate /
/// padded-intermediate framing (including `FLAG_QUICK_ACK`, `FLAG_ENCRYPTED`,
/// clean 4-byte `RPC_PROXY_ANS` lengths, and verbatim `RPC_SIMPLE_ACK` tokens).
#[allow(clippy::too_many_arguments)]
pub async fn relay_middleproxy(
    mut client: TcpStream,
    mut middle: MiddleStream,
    mut client_recv_initial: Vec<u8>,
    mut client_ciphers: (Aes256Ctr, Aes256Ctr), // (recv, send)
    framing: ClientFraming,
    ctx: RelayContext,
) {
    ctx.dc_stats.active_conns.fetch_add(1, Ordering::Relaxed);
    let _dc_guard = DcActiveGuard(&ctx.dc_stats);

    let mut tls_unframer = ctx.tls_unframer;
    // Reclaimed back to 0 capacity whenever empty so idle ad-tag streams use 0 B heap I/O!
    let mut plain_in: Vec<u8> = Vec::new();
    let cancel = ctx.cancel;
    let mut doppel = ctx.doppel;
    let idle_timeout = ctx.idle_timeout;
    let mut last_reset_ns = coarse_now_ns();
    let mut idle_sleep = std::pin::pin!(tokio::time::sleep(idle_timeout));

    // Seed any leftover unframed obfuscated2 ciphertext bytes already read during handshake.
    if !client_recv_initial.is_empty() {
        client_ciphers.0.apply_keystream(&mut client_recv_initial);
        plain_in.extend_from_slice(&client_recv_initial);
    }
    drop(client_recv_initial);

    loop {
        // Flush any complete MTProto packets (Intermediate / Padded-Intermediate / Abridged) -> MiddleProxy
        let mut up_sent = 0usize;
        while let Some(pkt_res) = take_client_packet(&mut plain_in, framing) {
            let Ok((pkt, quick_ack)) = pkt_res else {
                middle.close_graceful().await;
                return;
            };
            let n = pkt.len();
            if pace_transfer(
                n,
                true,
                &ctx.user,
                &ctx.client_entry,
                &ctx.global_limits,
                ctx.conn_limits.as_deref(),
                &cancel,
            )
            .await
            .is_err()
            {
                middle.close_graceful().await;
                return;
            }
            if middle.send_packet(&pkt, quick_ack).await.is_err() {
                middle.close_graceful().await;
                return;
            }
            up_sent += n;
            let now_unix = coarse_unix_secs();
            ctx.client_entry
                .bytes_in
                .fetch_add(n as i64, Ordering::Relaxed);
            ctx.client_entry.mark_seen(now_unix);
            ctx.dc_stats
                .bytes_from_client
                .fetch_add(n as u64, Ordering::Relaxed);
            if ctx.user.record_traffic(n as i64, true, now_unix) {
                ctx.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
                middle.close_graceful().await;
                return;
            }
            if ctx.global_limits.record_traffic(n as i64) {
                middle.close_graceful().await;
                return;
            }
        }
        if plain_in.is_empty() && plain_in.capacity() > 0 {
            plain_in = Vec::new();
        }
        if up_sent > 0 {
            let now_ns = coarse_now_ns();
            if now_ns.saturating_sub(last_reset_ns) >= IDLE_RESET_GRANULARITY_NS {
                last_reset_ns = now_ns;
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
            }
        }

        tokio::select! {
            () = cancel.cancelled() => {
                break;
            }
            () = idle_sleep.as_mut() => {
                break;
            }
            rd_ready = client.readable(), if !(ctx.is_faketls && tls_unframer.alert_seen()) => {
                if rd_ready.is_err() {
                    break;
                }
                let read_res = RELAY_SCRATCH.with(|cell| {
                    let mut scratch = cell.borrow_mut();
                    match client.try_read(&mut scratch[..UPLOAD_SCRATCH_CAP]) {
                        Ok(0) => Ok(None),
                        Ok(n) => {
                            let app_len = if ctx.is_faketls {
                                match tls_unframer.unframe_in_place(&mut scratch[..n]) {
                                    Ok(w) => w,
                                    Err(TlsRecordError::AlertClose) => {
                                        ctx.metrics
                                            .faketls
                                            .alert_closes
                                            .fetch_add(1, Ordering::Relaxed);
                                        return Ok(None);
                                    }
                                    Err(_) => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "bad FakeTLS frame",
                                        ));
                                    }
                                }
                            } else {
                                n
                            };
                            if app_len > 0 {
                                client_ciphers.0.apply_keystream(&mut scratch[..app_len]);
                                plain_in.extend_from_slice(&scratch[..app_len]);
                            }
                            Ok(Some(app_len))
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Some(0)),
                        Err(e) => Err(e),
                    }
                });
                match read_res {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            down = middle.recv_msg() => {
                let Ok(Some(msg)) = down else { break; };
                // Exact MTProto download framing matching client's negotiated transport tag:
                // - `RPC_PROXY_ANS` (Intermediate / Padded): 4-byte LE byte length + payload.
                // - `RPC_PROXY_ANS` (Abridged): 1-byte (<0x7f) or 4-byte (0x7f + 24b LE) word count + payload.
                // - `RPC_SIMPLE_ACK`: verbatim 4-byte quick-ack token (no length prefix).
                let wire_plain = match msg {
                    MiddleDownMsg::Data { payload, .. } => {
                        encode_client_download_packet(&payload, framing)
                    }
                    MiddleDownMsg::SimpleAck(ack) => ack,
                };
                if wire_plain.is_empty() {
                    continue;
                }
                if pace_transfer(
                    wire_plain.len(),
                    false,
                    &ctx.user,
                    &ctx.client_entry,
                    &ctx.global_limits,
                    ctx.conn_limits.as_deref(),
                    &cancel,
                )
                .await
                .is_err()
                {
                    break;
                }
                let mut offset = 0usize;
                while offset < wire_plain.len() {
                    let max_chunk = if ctx.is_faketls {
                        if let Some(d_box) = doppel.as_mut() {
                            let (d, params) = &mut **d_box;
                            let (delay, cap) = d.next_record(params, coarse_now_ns());
                            if !delay.is_zero() && sleep_cancelable(delay, &cancel).await.is_err() {
                                middle.close_graceful().await;
                                return;
                            }
                            cap.clamp(1, MAX_TLS_RECORD_PAYLOAD)
                        } else {
                            MAX_TLS_RECORD_PAYLOAD
                        }
                    } else {
                        MAX_TLS_RECORD_PAYLOAD
                    };
                    let take = (wire_plain.len() - offset).min(max_chunk);
                    let tail = RELAY_SCRATCH.with(|cell| {
                        let mut scratch = cell.borrow_mut();
                        let payload_dst = &mut scratch[TLS_HEADROOM..TLS_HEADROOM + take];
                        payload_dst.copy_from_slice(&wire_plain[offset..offset + take]);
                        client_ciphers.1.apply_keystream(payload_dst);

                        let write_slice = if ctx.is_faketls {
                            let hdr: &mut [u8; TLS_HEADROOM] = (&mut scratch[..TLS_HEADROOM])
                                .try_into()
                                .expect("5B headroom");
                            stamp_app_data_header(hdr, take as u16);
                            &scratch[..TLS_HEADROOM + take]
                        } else {
                            &scratch[TLS_HEADROOM..TLS_HEADROOM + take]
                        };
                        match client.try_write(write_slice) {
                            Ok(w) if w == write_slice.len() => Ok(None),
                            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "client closed")),
                            Ok(w) => Ok(Some(write_slice[w..].to_vec())),
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                Ok(Some(write_slice.to_vec()))
                            }
                            Err(e) => Err(e),
                        }
                    });
                    match tail {
                        Ok(None) => {}
                        Ok(Some(rem)) => {
                            if client.write_all(&rem).await.is_err() {
                                middle.close_graceful().await;
                                return;
                            }
                        }
                        Err(_) => {
                            middle.close_graceful().await;
                            return;
                        }
                    }
                    offset += take;
                }
                let n = wire_plain.len();
                let now_ns = coarse_now_ns();
                if now_ns.saturating_sub(last_reset_ns) >= IDLE_RESET_GRANULARITY_NS {
                    last_reset_ns = now_ns;
                    idle_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_timeout);
                }
                let now_unix = coarse_unix_secs();
                ctx.client_entry
                    .bytes_out
                    .fetch_add(n as i64, Ordering::Relaxed);
                ctx.client_entry.mark_seen(now_unix);
                ctx.dc_stats
                    .bytes_to_client
                    .fetch_add(n as u64, Ordering::Relaxed);
                if ctx.user.record_traffic(n as i64, false, now_unix) {
                    ctx.user.quota_cutoffs.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                if ctx.global_limits.record_traffic(n as i64) {
                    break;
                }
            }
        }
    }
    middle.close_graceful().await;
}

/// Extract one MTProto client packet (Intermediate, Padded-Intermediate, or
/// Abridged) from `buf`, returning `(payload, quick_ack)` while rejecting
/// oversized frames and unaligned non-padded lengths.
fn take_client_packet(
    buf: &mut Vec<u8>,
    framing: ClientFraming,
) -> Option<Result<(Vec<u8>, bool), ()>> {
    match framing {
        ClientFraming::Intermediate | ClientFraming::PaddedIntermediate => {
            let padded = framing == ClientFraming::PaddedIntermediate;
            if buf.len() < 4 {
                return None;
            }
            let mut declared = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let quick_ack = if declared >= mtg_protocol::middleproxy::QUICK_ACK_BIT {
                declared -= mtg_protocol::middleproxy::QUICK_ACK_BIT;
                true
            } else {
                false
            };
            let len = declared as usize;
            if len > mtg_protocol::middleproxy::DEFAULT_MAX_CLIENT_PACKET {
                return Some(Err(()));
            }
            if !padded && !len.is_multiple_of(4) {
                return Some(Err(()));
            }
            if buf.len() < 4 + len {
                return None;
            }
            let mut pkt = buf[4..4 + len].to_vec();
            buf.drain(..4 + len);
            if padded {
                // Trim 0..3 random trailing bytes to 4-byte alignment per MTProxy spec.
                let aligned = pkt.len() & !3;
                pkt.truncate(aligned);
            }
            Some(Ok((pkt, quick_ack)))
        }
        ClientFraming::Abridged => {
            if buf.is_empty() {
                return None;
            }
            let b0 = buf[0];
            let quick_ack = (b0 & 0x80) != 0;
            let tag = b0 & 0x7f;
            let (hdr_len, words) = if tag < 0x7f {
                (1usize, usize::from(tag))
            } else {
                if buf.len() < 4 {
                    return None;
                }
                let w = u32::from_le_bytes([buf[1], buf[2], buf[3], 0]) as usize;
                (4usize, w)
            };
            let len = words.saturating_mul(4);
            if len > mtg_protocol::middleproxy::DEFAULT_MAX_CLIENT_PACKET {
                return Some(Err(()));
            }
            if buf.len() < hdr_len + len {
                return None;
            }
            let pkt = buf[hdr_len..hdr_len + len].to_vec();
            buf.drain(..hdr_len + len);
            Some(Ok((pkt, quick_ack)))
        }
    }
}

/// Encode one `RPC_PROXY_ANS` download payload into the client's MTProto transport framing.
fn encode_client_download_packet(payload: &[u8], framing: ClientFraming) -> Vec<u8> {
    match framing {
        ClientFraming::Intermediate | ClientFraming::PaddedIntermediate => {
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            framed.extend_from_slice(payload);
            framed
        }
        ClientFraming::Abridged => {
            let words = payload.len() / 4;
            if words < 0x7f {
                let mut framed = Vec::with_capacity(1 + payload.len());
                framed.push(words as u8);
                framed.extend_from_slice(payload);
                framed
            } else {
                let mut framed = Vec::with_capacity(4 + payload.len());
                framed.push(0x7f);
                framed.push((words & 0xff) as u8);
                framed.push(((words >> 8) & 0xff) as u8);
                framed.push(((words >> 16) & 0xff) as u8);
                framed.extend_from_slice(payload);
                framed
            }
        }
    }
}

enum ReadStep {
    Sent(usize),
    Partial(usize),
    NeedPace(usize),
    ZeroApp,
    WouldBlock,
    AlertEof,
    Eof,
    Err,
}

#[inline]
fn copy_vectored_tail(slices: &[IoSlice<'_>], mut skip: usize, dst: &mut Vec<u8>) {
    for s in slices {
        let bytes: &[u8] = s;
        if skip >= bytes.len() {
            skip -= bytes.len();
        } else {
            dst.extend_from_slice(&bytes[skip..]);
            skip = 0;
        }
    }
}

async fn sleep_cancelable(delay: Duration, cancel: &CancelToken) -> Result<(), ()> {
    tokio::select! {
        () = cancel.cancelled() => Err(()),
        () = tokio::time::sleep(delay) => Ok(()),
    }
}

#[inline]
fn has_pacing(
    is_upload: bool,
    user: &SecretRuntime,
    entry: &ClientEntry,
    global: &GlobalLimitsRuntime,
    conn: Option<&ConnSpeedLimiters>,
) -> bool {
    let dir_bucket = if is_upload {
        FairBucket::Up
    } else {
        FairBucket::Down
    };
    let user_dir = if is_upload {
        &user.speed_up
    } else {
        &user.speed_down
    };
    let client_dir = if is_upload {
        &entry.ceiling_up
    } else {
        &entry.ceiling_down
    };
    global.is_speed_limited(is_upload)
        || user.speed.is_limited()
        || user_dir.is_limited()
        || entry.ceiling.is_limited()
        || client_dir.is_limited()
        || entry.fair_limiter(FairBucket::Speed).is_limited()
        || entry.fair_limiter(dir_bucket).is_limited()
        || conn.is_some_and(|c| c.is_limited(is_upload))
}

/// Lock-free GCRA pacing across all 4 governance tiers:
/// 1. Server-wide global bandwidth (`[limits] speed`, `speed-up`, `speed-down`)
/// 2. Secret aggregate bandwidth (`speed`, `speed-up`, `speed-down`)
/// 3. Per-address ceilings (`client-speed`, `client-speed-up`, `client-speed-down`)
///    and water-level fair-share (`client-fair`)
/// 4. CGNAT-safe per-connection bandwidth (`conn-speed`, `conn-speed-up`, `conn-speed-down`)
///
/// Fast-path optimized: when unlimited, pays only relaxed atomic loads — ZERO locks!
#[allow(clippy::too_many_arguments)]
async fn pace_transfer(
    bytes: usize,
    is_upload: bool,
    user: &SecretRuntime,
    entry: &ClientEntry,
    global: &GlobalLimitsRuntime,
    conn: Option<&ConnSpeedLimiters>,
    cancel: &CancelToken,
) -> io::Result<()> {
    let dir_bucket = if is_upload {
        FairBucket::Up
    } else {
        FairBucket::Down
    };
    let user_dir = if is_upload {
        &user.speed_up
    } else {
        &user.speed_down
    };
    let global_dir = if is_upload {
        &global.speed_up
    } else {
        &global.speed_down
    };
    let client_dir = if is_upload {
        &entry.ceiling_up
    } else {
        &entry.ceiling_down
    };

    // Fast exit when all tiers are unlimited (~8 relaxed atomic loads, ~4 ns!)
    if !global.is_speed_limited(is_upload)
        && !user.speed.is_limited()
        && !user_dir.is_limited()
        && !entry.ceiling.is_limited()
        && !client_dir.is_limited()
        && !entry.fair_limiter(FairBucket::Speed).is_limited()
        && !entry.fair_limiter(dir_bucket).is_limited()
        && conn.is_none_or(|c| !c.is_limited(is_upload))
    {
        return Ok(());
    }

    // 0. Server-wide global bandwidth shaper (`[limits] speed`, `speed-up`, `speed-down`)
    pace_one(
        bytes,
        &global.speed,
        None,
        &global.speed_throttled_ns,
        None,
        cancel,
    )
    .await?;

    pace_one(
        bytes,
        global_dir,
        None,
        &global.speed_throttled_ns,
        None,
        cancel,
    )
    .await?;

    // 1. User aggregate combined + directional buckets (count toward fair-share duty!)
    pace_one(
        bytes,
        &user.speed,
        Some(entry.fair_blocked(FairBucket::Speed)),
        &user.speed_throttled_ns,
        None,
        cancel,
    )
    .await?;

    pace_one(
        bytes,
        user_dir,
        Some(entry.fair_blocked(dir_bucket)),
        &user.speed_throttled_ns,
        None,
        cancel,
    )
    .await?;

    // 2. Per-address static ceilings (`client-speed`, `client-speed-up`, `client-speed-down`)
    //    — NEVER count toward fair-share duty!
    pace_one(
        bytes,
        &entry.ceiling,
        None,
        &user.client_throttled_ns,
        Some(&entry.throttled_nanos),
        cancel,
    )
    .await?;

    pace_one(
        bytes,
        client_dir,
        None,
        &user.client_throttled_ns,
        Some(&entry.throttled_nanos),
        cancel,
    )
    .await?;

    // 3. Per-address fair-share limiters (combined + directional)
    pace_one(
        bytes,
        entry.fair_limiter(FairBucket::Speed),
        Some(entry.fair_blocked(FairBucket::Speed)),
        &user.client_throttled_ns,
        Some(&entry.throttled_nanos),
        cancel,
    )
    .await?;

    pace_one(
        bytes,
        entry.fair_limiter(dir_bucket),
        Some(entry.fair_blocked(dir_bucket)),
        &user.client_throttled_ns,
        Some(&entry.throttled_nanos),
        cancel,
    )
    .await?;

    // 4. CGNAT-safe per-connection speed cap (`conn-speed`, `conn-speed-up`, `conn-speed-down`)
    if let Some(c) = conn {
        let conn_dir = if is_upload { &c.up } else { &c.down };
        pace_one(
            bytes,
            &c.combined,
            None,
            &user.client_throttled_ns,
            Some(&entry.throttled_nanos),
            cancel,
        )
        .await?;
        pace_one(
            bytes,
            conn_dir,
            None,
            &user.client_throttled_ns,
            Some(&entry.throttled_nanos),
            cancel,
        )
        .await?;
    }

    Ok(())
}

async fn pace_one(
    bytes: usize,
    limiter: &GcraLimiter,
    blocked: Option<&mtg_governance::BlockedTracker>,
    user_throttled_ns: &std::sync::atomic::AtomicU64,
    client_throttled_ns: Option<&std::sync::atomic::AtomicU64>,
    cancel: &CancelToken,
) -> io::Result<()> {
    if !limiter.is_limited() {
        return Ok(());
    }
    let now_ns = coarse_now_ns();
    let delay_ns = limiter.reserve_ns(bytes, now_ns);
    if delay_ns == 0 {
        return Ok(());
    }

    if let Some(bt) = blocked {
        bt.enter(now_ns);
    }
    let sleep_res = tokio::select! {
        () = tokio::time::sleep(Duration::from_nanos(delay_ns)) => Ok(()),
        () = cancel.cancelled() => {
            limiter.refund_bytes(bytes);
            Err(io::Error::new(io::ErrorKind::ConnectionAborted, "cancelled"))
        }
    };
    let after_ns = coarse_now_ns();
    if let Some(bt) = blocked {
        bt.leave(after_ns);
    }
    sleep_res?;
    user_throttled_ns.fetch_add(delay_ns, Ordering::Relaxed);
    if let Some(ct) = client_throttled_ns {
        ct.fetch_add(delay_ns, Ordering::Relaxed);
    }
    Ok(())
}

struct DcActiveGuard<'a>(&'a DcEndpointStats);

impl Drop for DcActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.active_conns.fetch_sub(1, Ordering::Relaxed);
    }
}
