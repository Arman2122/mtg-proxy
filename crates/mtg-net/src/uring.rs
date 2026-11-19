//! Primary Linux `io_uring` [`IoDriver`] implementation (Linux 6.1+ optimal,
//! 5.19+ compatible, auto-falls back to [`crate::epoll::EpollDriver`] on
//! `EPERM`/`ENOSYS` or unsupported opcodes).
//!
//! Features engineered for maximum throughput & minimum syscall overhead:
//! - `IORING_SETUP_SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN` (probed cleanly)
//! - Sparse direct fixed-file table (`register_files_sparse` + `types::Fixed`)
//! - Page-aligned `mmap` provided buffer rings (`IORING_REGISTER_PBUF_RING`)
//!   with 2 buffer classes (4 KiB + 16 KiB+64B) and 5-byte FakeTLS headroom
//! - `IORING_OP_ACCEPT` multishot (`SOCK_NONBLOCK | SOCK_CLOEXEC`)
//! - `IORING_OP_RECV` multishot using kernel-selected ring buffers
//! - `IORING_OP_SEND_ZC` zero-copy DMA for payloads `>= 8 KiB` (strictly
//!   retaining buffer ownership until `IORING_CQE_F_NOTIF` arrives!)
//! - Linked `IORING_OP_SPLICE` (`src -> pipe -> dst`) for zero-copy fronting
//! - `eventfd` read SQE for instant cross-thread control-plane wakeups

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU16, Ordering};

use io_uring::cqueue::{buffer_select, more as cqe_more, notif as cqe_notif};
use io_uring::types::{BufRingEntry, Fd, Fixed, Timespec};
use io_uring::{IoUring, Probe, opcode, squeue};
use rustc_hash::FxHashMap;
use slab::Slab;
use socket2::SockAddr;

use crate::driver::{
    BGID_LARGE, BGID_SMALL, BufHandle, DriverCapabilities, DriverConfig, DriverFd, DriverKind,
    IoDriver, IoEvent, LARGE_BUF_SIZE, SEND_ZC_THRESHOLD, SMALL_BUF_SIZE, SplicePipe, TLS_HEADROOM,
    create_eventfd,
};

/// Encoded SQE `user_data` tags (high 4 bits identify operation kind).
const OP_SHIFT: u32 = 60;
const OP_WAKE: u64 = 1;
const OP_ACCEPT: u64 = 2;
const OP_RECV: u64 = 3;
const OP_CONNECT: u64 = 4;
const OP_SEND: u64 = 5;
const OP_SEND_ZC: u64 = 6;
const OP_SPLICE_IN: u64 = 7;
const OP_SPLICE_OUT: u64 = 8;
const ID_MASK: u64 = (1u64 << OP_SHIFT) - 1;

#[inline]
const fn encode_ud(op: u64, id: u64) -> u64 {
    (op << OP_SHIFT) | (id & ID_MASK)
}

#[inline]
const fn decode_ud(ud: u64) -> (u64, u64) {
    (ud >> OP_SHIFT, ud & ID_MASK)
}

/// Probe the running Linux kernel for `io_uring` support and advanced opcodes.
///
/// Safe to call in `mtg-proxy doctor` and during engine startup; never panics.
pub fn probe_uring() -> io::Result<DriverCapabilities> {
    let mut caps = DriverCapabilities::default();

    // Try ideal 6.1+ flags first, then progressively downgrade flags if EINVAL.
    let (ring, single_issuer, defer_taskrun, coop_taskrun) = try_build_ring(32)?;
    caps.kind = Some(DriverKind::IoUring);
    caps.single_issuer = single_issuer;
    caps.defer_taskrun = defer_taskrun;
    caps.coop_taskrun = coop_taskrun;

    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe)?;

    caps.accept_multishot = probe.is_supported(opcode::AcceptMulti::CODE);
    caps.recv_multishot = probe.is_supported(opcode::RecvMulti::CODE);
    caps.send_zc = probe.is_supported(opcode::SendZc::CODE);
    caps.splice = probe.is_supported(opcode::Splice::CODE);

    // Probe sparse fixed-file registration.
    if ring.submitter().register_files_sparse(16).is_ok() {
        caps.registered_files = true;
        let _ = ring.submitter().unregister_files();
    }

    // Probe provided buffer ring registration with a tiny 1-page ring.
    if let Ok(br) = ProvidedBufRing::new(BGID_SMALL, 8, 64) {
        // SAFETY: `br` is page-aligned and stays valid until unregistered immediately below.
        let reg = unsafe {
            ring.submitter().register_buf_ring_with_flags(
                br.ring_ptr_u64(),
                br.ring_entries,
                br.bgid,
                0,
            )
        };
        if reg.is_ok() {
            caps.buf_ring = true;
            let _ = ring.submitter().unregister_buf_ring(br.bgid);
        }
    }

    Ok(caps)
}

fn try_build_ring(entries: u32) -> io::Result<(IoUring, bool, bool, bool)> {
    // 1. Best: Linux 6.1+ SINGLE_ISSUER + DEFER_TASKRUN + COOP_TASKRUN
    if let Ok(ring) = IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .setup_coop_taskrun()
        .build(entries)
    {
        return Ok((ring, true, true, true));
    }
    // 2. Linux 5.19+: COOP_TASKRUN only
    if let Ok(ring) = IoUring::builder().setup_coop_taskrun().build(entries) {
        return Ok((ring, false, false, true));
    }
    // 3. Baseline io_uring
    let ring = IoUring::builder().build(entries)?;
    Ok((ring, false, false, false))
}

/// Page-aligned kernel-shared `io_uring_buf_ring` + backing buffer storage
/// with [`TLS_HEADROOM`] writable bytes reserved immediately before each
/// kernel-exposed receive slice!
struct ProvidedBufRing {
    bgid: u16,
    ring_entries: u16,
    ring_mask: u16,
    ring_mmap: *mut BufRingEntry,
    ring_mmap_len: usize,
    local_tail: u16,
    stride: usize,
    payload_cap: usize,
    /// Heap-allocated backing storage pinned by `Box<[u8]>` (never reallocates!).
    storage: Box<[u8]>,
}

impl std::fmt::Debug for ProvidedBufRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvidedBufRing")
            .field("bgid", &self.bgid)
            .field("ring_entries", &self.ring_entries)
            .field("payload_cap", &self.payload_cap)
            .finish_non_exhaustive()
    }
}

impl ProvidedBufRing {
    fn new(bgid: u16, count: u16, payload_cap: usize) -> io::Result<Self> {
        let ring_entries = count.max(8).next_power_of_two();
        let ring_mask = ring_entries - 1;
        let entry_size = std::mem::size_of::<BufRingEntry>();
        let page_size = 4096usize;
        let ring_bytes = (usize::from(ring_entries) * entry_size).max(page_size);
        let ring_mmap_len = (ring_bytes + page_size - 1) & !(page_size - 1);

        // SAFETY: anonymous private read/write mmap aligned to OS page boundary.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let stride = (TLS_HEADROOM + payload_cap + 63) & !63;
        let storage = vec![0u8; stride * usize::from(ring_entries)].into_boxed_slice();

        let mut br = Self {
            bgid,
            ring_entries,
            ring_mask,
            ring_mmap: ptr.cast::<BufRingEntry>(),
            ring_mmap_len,
            local_tail: 0,
            stride,
            payload_cap,
            storage,
        };

        // Populate every buffer slot initially into the ring.
        for bid in 0..ring_entries {
            br.push_entry(bid);
        }
        br.publish_tail();

        Ok(br)
    }

    #[inline]
    fn ring_ptr_u64(&self) -> u64 {
        self.ring_mmap as u64
    }

    #[inline]
    fn entry_mut(&mut self, slot: u16) -> &mut BufRingEntry {
        // SAFETY: `slot < ring_entries`, mmap covers `ring_entries * sizeof(BufRingEntry)` and is page-aligned.
        unsafe { &mut *self.ring_mmap.add(usize::from(slot)) }
    }

    #[inline]
    fn payload_ptr(&self, bid: u16) -> u64 {
        let off = usize::from(bid) * self.stride + TLS_HEADROOM;
        // SAFETY: `storage` is a boxed slice whose address never moves while `self` lives.
        unsafe { self.storage.as_ptr().add(off) as u64 }
    }

    #[inline]
    fn push_entry(&mut self, bid: u16) {
        let slot = self.local_tail & self.ring_mask;
        let addr = self.payload_ptr(bid);
        let len = self.payload_cap as u32;
        let e = self.entry_mut(slot);
        e.set_addr(addr);
        e.set_len(len);
        e.set_bid(bid);
        self.local_tail = self.local_tail.wrapping_add(1);
    }

    #[inline]
    fn publish_tail(&self) {
        // SAFETY: `BufRingEntry::tail` returns the shared ring tail field pointer.
        let tail_ptr = unsafe { BufRingEntry::tail(self.ring_mmap).cast::<AtomicU16>() };
        // SAFETY: `tail_ptr` is aligned to u16 inside page-aligned `ring_mmap`.
        unsafe {
            (*tail_ptr).store(self.local_tail, Ordering::Release);
        }
    }

    #[inline]
    fn recycle(&mut self, bid: u16) {
        self.push_entry(bid);
        self.publish_tail();
    }

    #[inline]
    fn payload_slice(&self, bid: u16, len: usize) -> &[u8] {
        let base = usize::from(bid) * self.stride + TLS_HEADROOM;
        &self.storage[base..base + len]
    }

    #[inline]
    fn with_headroom_mut(&mut self, bid: u16, len: usize) -> &mut [u8] {
        let base = usize::from(bid) * self.stride;
        &mut self.storage[base..base + TLS_HEADROOM + len]
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        // SAFETY: `ring_mmap` was created via `libc::mmap` with length `ring_mmap_len`.
        unsafe {
            let _ = libc::munmap(self.ring_mmap.cast(), self.ring_mmap_len);
        }
    }
}

#[derive(Debug)]
struct InFlightConnect {
    token: u64,
    // Kept pinned in heap memory until kernel finishes `IORING_OP_CONNECT`.
    _addr: Box<SockAddr>,
}

#[derive(Debug)]
struct InFlightSend {
    token: u64,
    // Kept pinned in heap memory until kernel finishes `SEND` or `SEND_ZC` NOTIF!
    _data: Vec<u8>,
    /// For `SEND_ZC`: saved byte result from first CQE while waiting for `NOTIF`.
    zc_result: Option<io::Result<usize>>,
}

#[derive(Debug)]
struct InFlightSplice {
    token: u64,
}

/// Primary Linux `io_uring` [`IoDriver`] implementation.
pub struct UringDriver {
    ring: IoUring,
    caps: DriverCapabilities,
    enable_send_zc: bool,
    wake: OwnedFd,
    /// Pinned 8-byte buffer for async `eventfd` reads.
    wake_buf: Box<u64>,
    wake_armed: bool,
    /// Fixed file slots (`Some(OwnedFd)` = active registered slot).
    files: Vec<Option<OwnedFd>>,
    free_file_slots: Vec<u32>,
    small_ring: ProvidedBufRing,
    large_ring: ProvidedBufRing,
    /// Active accept tokens keyed by fixed slot index (for re-arming if needed).
    accept_tokens: FxHashMap<u32, u64>,
    /// Active recv metadata keyed by fixed slot index -> `(token, bgid)`.
    recv_meta: FxHashMap<u32, (u64, u16)>,
    connects: Slab<InFlightConnect>,
    sends: Slab<InFlightSend>,
    splices: Slab<InFlightSplice>,
}

impl std::fmt::Debug for UringDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringDriver")
            .field("caps", &self.caps)
            .field(
                "registered_files",
                &(self.files.len() - self.free_file_slots.len()),
            )
            .finish_non_exhaustive()
    }
}

impl UringDriver {
    /// Initialize a thread-local `io_uring` driver. Returns `Err` cleanly if
    /// the kernel lacks `io_uring` or required features (`buf_ring`, `registered_files`,
    /// `accept_multishot`, `recv_multishot`), allowing transparent fallback to `EpollDriver`.
    pub fn new(cfg: DriverConfig) -> io::Result<Self> {
        let caps = probe_uring()?;
        if !caps.buf_ring
            || !caps.registered_files
            || !caps.accept_multishot
            || !caps.recv_multishot
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel io_uring missing required 5.19+ features: {caps:?}"),
            ));
        }

        let entries = cfg.ring_entries.max(64).next_power_of_two();
        let (ring, _, _, _) = try_build_ring(entries)?;

        let max_files = cfg.max_files.max(256);
        ring.submitter().register_files_sparse(max_files)?;

        let small_ring = ProvidedBufRing::new(BGID_SMALL, cfg.small_bufs, SMALL_BUF_SIZE)?;
        let large_ring = ProvidedBufRing::new(BGID_LARGE, cfg.large_bufs, LARGE_BUF_SIZE)?;

        // SAFETY: Both `ProvidedBufRing`s are page-aligned and remain alive until
        // explicitly unregistered in `UringDriver::drop`.
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                small_ring.ring_ptr_u64(),
                small_ring.ring_entries,
                BGID_SMALL,
                0,
            )?;
            ring.submitter().register_buf_ring_with_flags(
                large_ring.ring_ptr_u64(),
                large_ring.ring_entries,
                BGID_LARGE,
                0,
            )?;
        }

        let wake = create_eventfd()?;
        let mut free_file_slots = Vec::with_capacity(max_files as usize);
        for s in (0..max_files).rev() {
            free_file_slots.push(s);
        }

        let mut driver = Self {
            ring,
            caps,
            enable_send_zc: cfg.enable_send_zc && caps.send_zc,
            wake,
            wake_buf: Box::new(0u64),
            wake_armed: false,
            files: (0..max_files).map(|_| None).collect(),
            free_file_slots,
            small_ring,
            large_ring,
            accept_tokens: FxHashMap::default(),
            recv_meta: FxHashMap::default(),
            connects: Slab::with_capacity(64),
            sends: Slab::with_capacity(256),
            splices: Slab::with_capacity(64),
        };
        driver.arm_wake_sqe()?;
        Ok(driver)
    }

    fn push_sqe(&mut self, entry: &squeue::Entry) -> io::Result<()> {
        // Flush SQ if full before pushing.
        if self.ring.submission().is_full() {
            self.ring.submit()?;
        }
        // SAFETY: Caller ensures all pointers/FDs referenced by `entry` remain
        // valid until the matching CQE (and `NOTIF` for `SEND_ZC`) completes.
        unsafe {
            self.ring
                .submission()
                .push(entry)
                .map_err(|_| io::Error::other("io_uring submission queue full"))?;
        }
        Ok(())
    }

    fn arm_wake_sqe(&mut self) -> io::Result<()> {
        if self.wake_armed {
            return Ok(());
        }
        let ptr = (&raw mut *self.wake_buf).cast::<u8>();
        let sqe = opcode::Read::new(Fd(self.wake.as_raw_fd()), ptr, 8)
            .build()
            .user_data(encode_ud(OP_WAKE, 0));
        self.push_sqe(&sqe)?;
        self.wake_armed = true;
        Ok(())
    }

    fn push_accept_multi(&mut self, slot: u32) -> io::Result<()> {
        let sqe = opcode::AcceptMulti::new(Fixed(slot))
            .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
            .build()
            .user_data(encode_ud(OP_ACCEPT, u64::from(slot)));
        self.push_sqe(&sqe)
    }

    fn push_recv_multi(&mut self, slot: u32, bgid: u16) -> io::Result<()> {
        let sqe = opcode::RecvMulti::new(Fixed(slot), bgid)
            .build()
            .user_data(encode_ud(OP_RECV, u64::from(slot)));
        self.push_sqe(&sqe)
    }
}

impl Drop for UringDriver {
    fn drop(&mut self) {
        let _ = self.ring.submitter().unregister_buf_ring(BGID_SMALL);
        let _ = self.ring.submitter().unregister_buf_ring(BGID_LARGE);
        let _ = self.ring.submitter().unregister_files();
    }
}

impl IoDriver for UringDriver {
    fn kind(&self) -> DriverKind {
        DriverKind::IoUring
    }

    fn capabilities(&self) -> DriverCapabilities {
        self.caps
    }

    fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    fn register_fd(&mut self, fd: OwnedFd) -> io::Result<DriverFd> {
        let slot = self
            .free_file_slots
            .pop()
            .ok_or_else(|| io::Error::other("io_uring direct file table exhausted"))?;
        let raw = fd.as_raw_fd();
        self.ring.submitter().register_files_update(slot, &[raw])?;
        self.files[slot as usize] = Some(fd);
        Ok(DriverFd(slot))
    }

    fn unregister_fd(&mut self, dfd: DriverFd) -> io::Result<()> {
        let slot = dfd.0;
        if let Some(entry) = self.files.get_mut(slot as usize)
            && let Some(owned) = entry.take()
        {
            self.accept_tokens.remove(&slot);
            self.recv_meta.remove(&slot);
            let _ = self.ring.submitter().register_files_update(slot, &[-1]);
            drop(owned);
            self.free_file_slots.push(slot);
        }
        Ok(())
    }

    fn raw_fd(&self, dfd: DriverFd) -> Option<RawFd> {
        self.files
            .get(dfd.0 as usize)
            .and_then(|opt| opt.as_ref().map(AsRawFd::as_raw_fd))
    }

    fn arm_accept(&mut self, listener: DriverFd, token: u64) -> io::Result<()> {
        self.accept_tokens.insert(listener.0, token);
        self.push_accept_multi(listener.0)
    }

    fn arm_recv(&mut self, fd: DriverFd, token: u64, bgid: u16) -> io::Result<()> {
        self.recv_meta.insert(fd.0, (token, bgid));
        self.push_recv_multi(fd.0, bgid)
    }

    fn queue_connect(&mut self, fd: DriverFd, addr: SocketAddr, token: u64) -> io::Result<()> {
        let boxed = Box::new(SockAddr::from(addr));
        let ptr = boxed.as_ptr().cast::<libc::sockaddr>();
        let len = boxed.len();
        let id = self.connects.insert(InFlightConnect {
            token,
            _addr: boxed,
        }) as u64;
        let sqe = opcode::Connect::new(Fixed(fd.0), ptr, len)
            .build()
            .user_data(encode_ud(OP_CONNECT, id));
        self.push_sqe(&sqe)
    }

    fn queue_send(
        &mut self,
        fd: DriverFd,
        token: u64,
        data: Vec<u8>,
        offset: usize,
        zero_copy_hint: bool,
    ) -> io::Result<()> {
        let rem = data.len().saturating_sub(offset);
        if rem == 0 {
            return Ok(());
        }
        let ptr = unsafe { data.as_ptr().add(offset) };
        let use_zc = self.enable_send_zc && zero_copy_hint && rem >= SEND_ZC_THRESHOLD;
        let id = self.sends.insert(InFlightSend {
            token,
            _data: data,
            zc_result: None,
        }) as u64;

        let sqe = if use_zc {
            opcode::SendZc::new(Fixed(fd.0), ptr, rem as u32)
                .flags(libc::MSG_NOSIGNAL)
                .build()
                .user_data(encode_ud(OP_SEND_ZC, id))
        } else {
            opcode::Send::new(Fixed(fd.0), ptr, rem as u32)
                .flags(libc::MSG_NOSIGNAL)
                .build()
                .user_data(encode_ud(OP_SEND, id))
        };
        self.push_sqe(&sqe)
    }

    fn queue_splice(
        &mut self,
        src: DriverFd,
        dst: DriverFd,
        pipe: &SplicePipe,
        len: u32,
        token: u64,
    ) -> io::Result<()> {
        // Ensure space for 2 linked SQEs so they are never split across submissions.
        let free_sqes = {
            let sq = self.ring.submission();
            sq.capacity() - sq.len()
        };
        if free_sqes < 2 {
            self.ring.submit()?;
        }
        let id = self.splices.insert(InFlightSplice { token }) as u64;
        let flags = libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE;

        // Linked step 1: src socket -> kernel pipe write end
        let sqe_in = opcode::Splice::new(Fixed(src.0), -1, Fd(pipe.write_fd()), -1, len)
            .flags(flags)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(encode_ud(OP_SPLICE_IN, id));

        // Linked step 2: kernel pipe read end -> dst socket
        let sqe_out = opcode::Splice::new(Fd(pipe.read_fd()), -1, Fixed(dst.0), -1, len)
            .flags(flags)
            .build()
            .user_data(encode_ud(OP_SPLICE_OUT, id));

        // SAFETY: `Fixed(src.0)`, `Fixed(dst.0)`, and `pipe` fds remain valid while queued.
        unsafe {
            let mut sq = self.ring.submission();
            sq.push(&sqe_in)
                .map_err(|_| io::Error::other("io_uring SQ full (splice_in)"))?;
            sq.push(&sqe_out)
                .map_err(|_| io::Error::other("io_uring SQ full (splice_out)"))?;
        }
        Ok(())
    }

    fn buf_slice(&self, handle: BufHandle) -> &[u8] {
        if handle.group == BGID_SMALL {
            self.small_ring
                .payload_slice(handle.id, handle.len as usize)
        } else {
            self.large_ring
                .payload_slice(handle.id, handle.len as usize)
        }
    }

    fn buf_with_headroom_mut(&mut self, handle: BufHandle) -> &mut [u8] {
        if handle.group == BGID_SMALL {
            self.small_ring
                .with_headroom_mut(handle.id, handle.len as usize)
        } else {
            self.large_ring
                .with_headroom_mut(handle.id, handle.len as usize)
        }
    }

    fn recycle_buf(&mut self, handle: BufHandle) {
        if handle.group == BGID_SMALL {
            self.small_ring.recycle(handle.id);
        } else {
            self.large_ring.recycle(handle.id);
        }
    }

    fn submit_and_wait(&mut self, timeout_ms: u32, events: &mut Vec<IoEvent>) -> io::Result<usize> {
        let before = events.len();
        let ts = Timespec::new()
            .sec(u64::from(timeout_ms / 1000))
            .nsec((timeout_ms % 1000) * 1_000_000);
        let args = io_uring::types::SubmitArgs::new().timespec(&ts);

        match self.ring.submitter().submit_with_args(1, &args) {
            Ok(_) => {}
            Err(e)
                if e.raw_os_error() == Some(libc::ETIME)
                    || e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => return Err(e),
        }

        // Drain CQEs into a local scratch batch so we can mutate `self` cleanly.
        let mut raw_cqes: Vec<(u64, i32, u32)> = Vec::with_capacity(64);
        {
            let cq = self.ring.completion();
            for cqe in cq {
                raw_cqes.push((cqe.user_data(), cqe.result(), cqe.flags()));
            }
        }

        let mut rearm_wake = false;
        let mut rearm_accepts: Vec<u32> = Vec::new();
        let mut rearm_recvs: Vec<(u32, u16)> = Vec::new();

        for (ud, res, flags) in raw_cqes {
            let (op, id) = decode_ud(ud);
            match op {
                OP_WAKE => {
                    self.wake_armed = false;
                    rearm_wake = true;
                    events.push(IoEvent::Wakeup);
                }
                OP_ACCEPT => {
                    let slot = id as u32;
                    let has_more = cqe_more(flags);
                    if let Some(&token) = self.accept_tokens.get(&slot) {
                        if res >= 0 {
                            // SAFETY: `AcceptMulti` returned a newly owned nonblocking CLOEXEC fd.
                            let fd = unsafe { OwnedFd::from_raw_fd(res) };
                            let peer = peer_addr_of(fd.as_raw_fd());
                            events.push(IoEvent::Accept {
                                token,
                                fd,
                                peer,
                                more: has_more,
                            });
                        } else if -res != libc::ECANCELED {
                            events.push(IoEvent::Error {
                                token,
                                err: io::Error::from_raw_os_error(-res),
                            });
                        }
                        if !has_more && -res != libc::ECANCELED {
                            rearm_accepts.push(slot);
                        }
                    }
                }
                OP_RECV => {
                    let slot = id as u32;
                    let has_more = cqe_more(flags);
                    if let Some(&(token, bgid)) = self.recv_meta.get(&slot) {
                        match res.cmp(&0) {
                            std::cmp::Ordering::Greater => {
                                let bid = buffer_select(flags);
                                let handle = bid.map(|bid| BufHandle {
                                    group: bgid,
                                    id: bid,
                                    len: res as u32,
                                });
                                events.push(IoEvent::Recv {
                                    token,
                                    buf: handle,
                                    result: Ok(res as usize),
                                    more: has_more,
                                });
                                if !has_more {
                                    rearm_recvs.push((slot, bgid));
                                }
                            }
                            std::cmp::Ordering::Equal => {
                                if let Some(bid) = buffer_select(flags) {
                                    self.recycle_buf(BufHandle {
                                        group: bgid,
                                        id: bid,
                                        len: 0,
                                    });
                                }
                                events.push(IoEvent::Recv {
                                    token,
                                    buf: None,
                                    result: Ok(0),
                                    more: false,
                                });
                            }
                            std::cmp::Ordering::Less => {
                                if let Some(bid) = buffer_select(flags) {
                                    self.recycle_buf(BufHandle {
                                        group: bgid,
                                        id: bid,
                                        len: 0,
                                    });
                                }
                                if -res == libc::ENOBUFS {
                                    // Buffer ring briefly exhausted; re-arm recv cleanly.
                                    rearm_recvs.push((slot, bgid));
                                } else if -res != libc::ECANCELED {
                                    events.push(IoEvent::Recv {
                                        token,
                                        buf: None,
                                        result: Err(io::Error::from_raw_os_error(-res)),
                                        more: false,
                                    });
                                }
                            }
                        }
                    }
                }
                OP_CONNECT => {
                    if let Some(c) = self.connects.try_remove(id as usize) {
                        let result = if res >= 0 {
                            Ok(())
                        } else {
                            Err(io::Error::from_raw_os_error(-res))
                        };
                        events.push(IoEvent::Connect {
                            token: c.token,
                            result,
                        });
                    }
                }
                OP_SEND => {
                    if let Some(s) = self.sends.try_remove(id as usize) {
                        let result = if res >= 0 {
                            Ok(res as usize)
                        } else {
                            Err(io::Error::from_raw_os_error(-res))
                        };
                        events.push(IoEvent::SendComplete {
                            token: s.token,
                            result,
                        });
                    }
                }
                OP_SEND_ZC => {
                    let is_notif = cqe_notif(flags);
                    let has_more = cqe_more(flags);
                    if is_notif {
                        // Kernel finished DMA; NOW it is safe to drop `InFlightSend::_data`!
                        if let Some(s) = self.sends.try_remove(id as usize) {
                            let result = s.zc_result.unwrap_or(Ok(0));
                            events.push(IoEvent::SendComplete {
                                token: s.token,
                                result,
                            });
                        }
                    } else {
                        let result = if res >= 0 {
                            Ok(res as usize)
                        } else {
                            Err(io::Error::from_raw_os_error(-res))
                        };
                        if has_more {
                            // Keep buffer alive until NOTIF CQE arrives!
                            if let Some(s) = self.sends.get_mut(id as usize) {
                                s.zc_result = Some(result);
                            }
                        } else if let Some(s) = self.sends.try_remove(id as usize) {
                            events.push(IoEvent::SendComplete {
                                token: s.token,
                                result,
                            });
                        }
                    }
                }
                OP_SPLICE_IN => {
                    // If step 1 failed or hit EOF (0), the linked step 2 will get ECANCELED
                    // (or 0); emit result early on error/EOF and remove slab entry.
                    if res <= 0
                        && let Some(sp) = self.splices.try_remove(id as usize)
                    {
                        let result = if res == 0 {
                            Ok(0)
                        } else {
                            Err(io::Error::from_raw_os_error(-res))
                        };
                        events.push(IoEvent::SpliceComplete {
                            token: sp.token,
                            result,
                        });
                    }
                }
                OP_SPLICE_OUT => {
                    if let Some(sp) = self.splices.try_remove(id as usize) {
                        let result = if res >= 0 {
                            Ok(res as usize)
                        } else {
                            Err(io::Error::from_raw_os_error(-res))
                        };
                        events.push(IoEvent::SpliceComplete {
                            token: sp.token,
                            result,
                        });
                    }
                }
                _ => {}
            }
        }

        if rearm_wake {
            let _ = self.arm_wake_sqe();
        }
        for slot in rearm_accepts {
            if self.accept_tokens.contains_key(&slot) {
                let _ = self.push_accept_multi(slot);
            }
        }
        for (slot, bgid) in rearm_recvs {
            if self.recv_meta.contains_key(&slot) {
                let _ = self.push_recv_multi(slot, bgid);
            }
        }

        Ok(events.len() - before)
    }
}

fn peer_addr_of(fd: RawFd) -> Option<SocketAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `fd` is a newly accepted socket and `storage` is writable.
    let rc = unsafe { libc::getpeername(fd, (&raw mut storage).cast(), &raw mut len) };
    if rc != 0 {
        return None;
    }
    crate::epoll::sockaddr_storage_to_std(&storage, len)
}
