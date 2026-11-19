//! Production Linux `epoll(7)` edge-triggered (`EPOLLET`) fallback driver.
//!
//! Automatically selected whenever `io_uring` is disabled (`EPERM` in restricted
//! Docker/seccomp sandboxes or kernel < 6.1). Delivers:
//! - Zero idle per-connection buffers (buffers leased only when `EPOLLIN` fires)
//! - 5-byte FakeTLS record headroom in every slab slot
//! - Zero-copy kernel `splice(2)` domain fronting using pooled non-blocking pipes
//! - `eventfd(2)` control-plane wakeup

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use rustc_hash::FxHashMap;
use socket2::SockAddr;

use crate::driver::{
    BGID_LARGE, BGID_SMALL, BufHandle, DriverCapabilities, DriverConfig, DriverFd, DriverKind,
    IoDriver, IoEvent, LARGE_BUF_SIZE, SMALL_BUF_SIZE, SplicePipe, TLS_HEADROOM, create_eventfd,
    drain_eventfd,
};

const WAKE_TOKEN: u64 = u64::MAX;

/// Flat aligned buffer slab with 5-byte FakeTLS headroom before every slot.
#[derive(Debug)]
struct SlabGroup {
    stride: usize,
    payload_cap: usize,
    storage: Vec<u8>,
    free: Vec<u16>,
}

impl SlabGroup {
    fn new(count: u16, payload_cap: usize) -> Self {
        let stride = (TLS_HEADROOM + payload_cap + 63) & !63;
        let storage = vec![0u8; stride * usize::from(count)];
        let mut free = Vec::with_capacity(usize::from(count));
        for id in (0..count).rev() {
            free.push(id);
        }
        Self {
            stride,
            payload_cap,
            storage,
            free,
        }
    }

    fn alloc(&mut self) -> Option<u16> {
        self.free.pop()
    }

    fn recycle(&mut self, id: u16) {
        self.free.push(id);
    }

    #[inline]
    fn payload_mut(&mut self, id: u16) -> &mut [u8] {
        let base = usize::from(id) * self.stride + TLS_HEADROOM;
        &mut self.storage[base..base + self.payload_cap]
    }

    #[inline]
    fn payload(&self, id: u16, len: usize) -> &[u8] {
        let base = usize::from(id) * self.stride + TLS_HEADROOM;
        &self.storage[base..base + len]
    }

    #[inline]
    fn with_headroom_mut(&mut self, id: u16, len: usize) -> &mut [u8] {
        let base = usize::from(id) * self.stride;
        &mut self.storage[base..base + TLS_HEADROOM + len]
    }
}

#[derive(Debug)]
enum FdRole {
    Idle,
    Listener {
        token: u64,
    },
    Connecting {
        token: u64,
    },
    Stream {
        recv_token: Option<u64>,
        recv_bgid: u16,
        pending_send: Option<PendingSend>,
    },
}

#[derive(Debug)]
struct PendingSend {
    token: u64,
    data: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
struct FdEntry {
    fd: OwnedFd,
    role: FdRole,
    epoll_events: u32,
}

/// Edge-triggered Linux `epoll(7)` [`IoDriver`] implementation.
#[derive(Debug)]
pub struct EpollDriver {
    epfd: OwnedFd,
    wake: OwnedFd,
    fds: FxHashMap<RawFd, FdEntry>,
    raw_events: Vec<libc::epoll_event>,
    small_slab: SlabGroup,
    large_slab: SlabGroup,
    immediate_events: Vec<IoEvent>,
}

impl EpollDriver {
    /// Create a new Linux `epoll` driver for one worker thread.
    pub fn new(cfg: DriverConfig) -> io::Result<Self> {
        // SAFETY: `epoll_create1(EPOLL_CLOEXEC)` is safe.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `epfd` is a newly created valid fd.
        let epfd = unsafe { OwnedFd::from_raw_fd(epfd) };
        let wake = create_eventfd()?;

        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLET) as u32,
            u64: WAKE_TOKEN,
        };
        // SAFETY: valid `epfd`, valid `wake` fd, valid pointer to `ev`.
        if unsafe {
            libc::epoll_ctl(
                epfd.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                wake.as_raw_fd(),
                &raw mut ev,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            epfd,
            wake,
            fds: FxHashMap::default(),
            raw_events: vec![libc::epoll_event { events: 0, u64: 0 }; 512],
            small_slab: SlabGroup::new(cfg.small_bufs.max(16), SMALL_BUF_SIZE),
            large_slab: SlabGroup::new(cfg.large_bufs.max(16), LARGE_BUF_SIZE),
            immediate_events: Vec::with_capacity(64),
        })
    }

    fn update_interest(&mut self, raw: RawFd, want_events: u32) -> io::Result<()> {
        let Some(entry) = self.fds.get_mut(&raw) else {
            return Ok(());
        };
        if entry.epoll_events == want_events {
            return Ok(());
        }
        let op = if entry.epoll_events == 0 {
            libc::EPOLL_CTL_ADD
        } else {
            libc::EPOLL_CTL_MOD
        };
        let mut ev = libc::epoll_event {
            events: want_events,
            u64: raw as u64,
        };
        // SAFETY: `epfd` and `raw` are valid registered fds.
        let rc = unsafe { libc::epoll_ctl(self.epfd.as_raw_fd(), op, raw, &raw mut ev) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        entry.epoll_events = want_events;
        Ok(())
    }

    fn drain_accept(raw: RawFd, token: u64, out: &mut Vec<IoEvent>) {
        loop {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: valid listener fd and writable `sockaddr_storage`.
            let cfd = unsafe {
                libc::accept4(
                    raw,
                    (&raw mut storage).cast::<libc::sockaddr>(),
                    &raw mut len,
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if cfd < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                out.push(IoEvent::Error { token, err });
                break;
            }
            // SAFETY: `cfd` is a newly accepted owned fd.
            let owned = unsafe { OwnedFd::from_raw_fd(cfd) };
            let peer = sockaddr_storage_to_std(&storage, len);
            out.push(IoEvent::Accept {
                token,
                fd: owned,
                peer,
                more: true,
            });
        }
    }

    fn drain_recv(&mut self, raw: RawFd, token: u64, bgid: u16, out: &mut Vec<IoEvent>) {
        let slab = if bgid == BGID_SMALL {
            &mut self.small_slab
        } else {
            &mut self.large_slab
        };

        // Read up to 4 chunks per readiness wake to prevent starving other peers.
        for _ in 0..4 {
            let Some(id) = slab.alloc() else {
                break;
            };
            let buf = slab.payload_mut(id);
            // SAFETY: valid nonblocking socket fd and writable slice `buf`.
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                slab.recycle(id);
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                out.push(IoEvent::Recv {
                    token,
                    buf: None,
                    result: Err(err),
                    more: false,
                });
                break;
            }
            let n = n as usize;
            if n == 0 {
                slab.recycle(id);
                out.push(IoEvent::Recv {
                    token,
                    buf: None,
                    result: Ok(0),
                    more: false,
                });
                break;
            }
            out.push(IoEvent::Recv {
                token,
                buf: Some(BufHandle {
                    group: bgid,
                    id,
                    len: n as u32,
                }),
                result: Ok(n),
                more: true,
            });
            if n < slab.payload_cap {
                break;
            }
        }
    }

    fn flush_pending_send(raw: RawFd, ps: &mut PendingSend) -> Option<io::Result<usize>> {
        while ps.offset < ps.data.len() {
            let slice = &ps.data[ps.offset..];
            // SAFETY: valid socket fd and readable slice `slice`.
            let n = unsafe {
                libc::send(
                    raw,
                    slice.as_ptr().cast(),
                    slice.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return None;
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Some(Err(err));
            }
            ps.offset += n as usize;
        }
        Some(Ok(ps.data.len()))
    }
}

impl IoDriver for EpollDriver {
    fn kind(&self) -> DriverKind {
        DriverKind::Epoll
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities {
            kind: Some(DriverKind::Epoll),
            splice: true,
            ..DriverCapabilities::default()
        }
    }

    fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    fn register_fd(&mut self, fd: OwnedFd) -> io::Result<DriverFd> {
        let raw = fd.as_raw_fd();
        self.fds.insert(
            raw,
            FdEntry {
                fd,
                role: FdRole::Idle,
                epoll_events: 0,
            },
        );
        Ok(DriverFd(raw as u32))
    }

    fn unregister_fd(&mut self, dfd: DriverFd) -> io::Result<()> {
        let raw = dfd.0 as RawFd;
        if let Some(entry) = self.fds.remove(&raw) {
            if entry.epoll_events != 0 {
                // SAFETY: removing valid fd from valid epfd before dropping `OwnedFd`.
                unsafe {
                    let _ = libc::epoll_ctl(
                        self.epfd.as_raw_fd(),
                        libc::EPOLL_CTL_DEL,
                        raw,
                        std::ptr::null_mut(),
                    );
                }
            }
            drop(entry.fd);
        }
        Ok(())
    }

    fn raw_fd(&self, dfd: DriverFd) -> Option<RawFd> {
        let raw = dfd.0 as RawFd;
        self.fds.contains_key(&raw).then_some(raw)
    }

    fn arm_accept(&mut self, listener: DriverFd, token: u64) -> io::Result<()> {
        let raw = listener.0 as RawFd;
        if let Some(entry) = self.fds.get_mut(&raw) {
            entry.role = FdRole::Listener { token };
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown listener fd",
            ));
        }
        self.update_interest(raw, (libc::EPOLLIN | libc::EPOLLET) as u32)
    }

    fn arm_recv(&mut self, fd: DriverFd, token: u64, bgid: u16) -> io::Result<()> {
        let raw = fd.0 as RawFd;
        let has_send = {
            let Some(entry) = self.fds.get_mut(&raw) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "unknown stream fd"));
            };
            let existing_send = match &mut entry.role {
                FdRole::Stream { pending_send, .. } => pending_send.take(),
                _ => None,
            };
            let has_send = existing_send.is_some();
            entry.role = FdRole::Stream {
                recv_token: Some(token),
                recv_bgid: bgid,
                pending_send: existing_send,
            };
            has_send
        };
        let mut mask = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
        if has_send {
            mask |= libc::EPOLLOUT as u32;
        }
        self.update_interest(raw, mask)
    }

    fn queue_connect(&mut self, fd: DriverFd, addr: SocketAddr, token: u64) -> io::Result<()> {
        let raw = fd.0 as RawFd;
        if !self.fds.contains_key(&raw) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown connect fd",
            ));
        }
        let sa = SockAddr::from(addr);
        // SAFETY: `raw` is a valid non-blocking socket fd and `sa` is valid.
        let rc = unsafe { libc::connect(raw, sa.as_ptr().cast(), sa.len()) };
        if rc == 0 {
            self.immediate_events.push(IoEvent::Connect {
                token,
                result: Ok(()),
            });
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINPROGRESS) {
            if let Some(entry) = self.fds.get_mut(&raw) {
                entry.role = FdRole::Connecting { token };
            }
            self.update_interest(raw, (libc::EPOLLOUT | libc::EPOLLET) as u32)?;
            return Ok(());
        }
        self.immediate_events.push(IoEvent::Connect {
            token,
            result: Err(err),
        });
        Ok(())
    }

    fn queue_send(
        &mut self,
        fd: DriverFd,
        token: u64,
        data: Vec<u8>,
        offset: usize,
        _zero_copy_hint: bool,
    ) -> io::Result<()> {
        let raw = fd.0 as RawFd;
        let mut ps = PendingSend {
            token,
            data,
            offset,
        };
        if let Some(res) = Self::flush_pending_send(raw, &mut ps) {
            self.immediate_events
                .push(IoEvent::SendComplete { token, result: res });
            return Ok(());
        }
        let want_in = {
            let Some(entry) = self.fds.get_mut(&raw) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "unknown send fd"));
            };
            if let FdRole::Stream {
                recv_token,
                pending_send,
                ..
            } = &mut entry.role
            {
                *pending_send = Some(ps);
                recv_token.is_some()
            } else {
                entry.role = FdRole::Stream {
                    recv_token: None,
                    recv_bgid: BGID_LARGE,
                    pending_send: Some(ps),
                };
                false
            }
        };
        let mut mask = (libc::EPOLLOUT | libc::EPOLLET) as u32;
        if want_in {
            mask |= (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
        }
        self.update_interest(raw, mask)
    }

    fn queue_splice(
        &mut self,
        src: DriverFd,
        dst: DriverFd,
        pipe: &SplicePipe,
        len: u32,
        token: u64,
    ) -> io::Result<()> {
        let src_fd = src.0 as RawFd;
        let dst_fd = dst.0 as RawFd;
        let flags = libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE;

        // SAFETY: `src_fd` and `pipe.write_fd()` are valid non-blocking Linux fds.
        let n_in = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe.write_fd(),
                std::ptr::null_mut(),
                len as usize,
                flags,
            )
        };
        if n_in < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            self.immediate_events.push(IoEvent::SpliceComplete {
                token,
                result: Err(err),
            });
            return Ok(());
        }
        if n_in == 0 {
            self.immediate_events.push(IoEvent::SpliceComplete {
                token,
                result: Ok(0),
            });
            return Ok(());
        }

        let mut remaining = n_in as usize;
        let mut total_out = 0usize;
        while remaining > 0 {
            // SAFETY: `pipe.read_fd()` and `dst_fd` are valid non-blocking Linux fds.
            let n_out = unsafe {
                libc::splice(
                    pipe.read_fd(),
                    std::ptr::null_mut(),
                    dst_fd,
                    std::ptr::null_mut(),
                    remaining,
                    flags,
                )
            };
            if n_out < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                self.immediate_events.push(IoEvent::SpliceComplete {
                    token,
                    result: Err(err),
                });
                return Ok(());
            }
            total_out += n_out as usize;
            remaining -= n_out as usize;
        }
        self.immediate_events.push(IoEvent::SpliceComplete {
            token,
            result: Ok(total_out),
        });
        Ok(())
    }

    fn buf_slice(&self, handle: BufHandle) -> &[u8] {
        let slab = if handle.group == BGID_SMALL {
            &self.small_slab
        } else {
            &self.large_slab
        };
        slab.payload(handle.id, handle.len as usize)
    }

    fn buf_with_headroom_mut(&mut self, handle: BufHandle) -> &mut [u8] {
        let slab = if handle.group == BGID_SMALL {
            &mut self.small_slab
        } else {
            &mut self.large_slab
        };
        slab.with_headroom_mut(handle.id, handle.len as usize)
    }

    fn recycle_buf(&mut self, handle: BufHandle) {
        let slab = if handle.group == BGID_SMALL {
            &mut self.small_slab
        } else {
            &mut self.large_slab
        };
        slab.recycle(handle.id);
    }

    fn submit_and_wait(&mut self, timeout_ms: u32, events: &mut Vec<IoEvent>) -> io::Result<usize> {
        let before = events.len();
        if !self.immediate_events.is_empty() {
            events.append(&mut self.immediate_events);
        }
        let wait_ms = if events.len() > before {
            0
        } else {
            timeout_ms.min(i32::MAX as u32) as libc::c_int
        };

        // SAFETY: valid `epfd` and writable `raw_events` slice.
        let n = unsafe {
            libc::epoll_wait(
                self.epfd.as_raw_fd(),
                self.raw_events.as_mut_ptr(),
                self.raw_events.len() as libc::c_int,
                wait_ms,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(events.len() - before);
            }
            return Err(err);
        }

        let ready_count = n as usize;
        // Copy out ready (fd, mask) tuples so we can mutably borrow `self` cleanly.
        let mut ready: [(u64, u32); 512] = [(0, 0); 512];
        for (dst, src) in ready[..ready_count]
            .iter_mut()
            .zip(&self.raw_events[..ready_count])
        {
            *dst = (src.u64, src.events);
        }

        for &(u64_id, mask) in &ready[..ready_count] {
            if u64_id == WAKE_TOKEN {
                drain_eventfd(self.wake.as_raw_fd());
                events.push(IoEvent::Wakeup);
                continue;
            }
            let raw = u64_id as RawFd;
            let action = match self.fds.get(&raw).map(|e| &e.role) {
                Some(FdRole::Listener { token }) => (1u8, *token, 0u16),
                Some(FdRole::Connecting { token }) => (2u8, *token, 0u16),
                Some(FdRole::Stream {
                    recv_token,
                    recv_bgid,
                    ..
                }) => (3u8, recv_token.unwrap_or(0), *recv_bgid),
                _ => continue,
            };

            match action.0 {
                1 => Self::drain_accept(raw, action.1, events),
                2 => {
                    let mut so_err: libc::c_int = 0;
                    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    // SAFETY: `raw` is a valid socket fd, `so_err` is writable.
                    let rc = unsafe {
                        libc::getsockopt(
                            raw,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            (&raw mut so_err).cast(),
                            &raw mut len,
                        )
                    };
                    let res = if rc != 0 {
                        Err(io::Error::last_os_error())
                    } else if so_err != 0 {
                        Err(io::Error::from_raw_os_error(so_err))
                    } else {
                        Ok(())
                    };
                    if let Some(entry) = self.fds.get_mut(&raw) {
                        entry.role = FdRole::Idle;
                    }
                    let _ = self.update_interest(raw, (libc::EPOLLRDHUP | libc::EPOLLET) as u32);
                    events.push(IoEvent::Connect {
                        token: action.1,
                        result: res,
                    });
                }
                3 => {
                    if (mask
                        & (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR)
                            as u32)
                        != 0
                        && self.fds.get(&raw).is_some_and(|e| {
                            matches!(
                                e.role,
                                FdRole::Stream {
                                    recv_token: Some(_),
                                    ..
                                }
                            )
                        })
                    {
                        self.drain_recv(raw, action.1, action.2, events);
                    }
                    if (mask & libc::EPOLLOUT as u32) != 0 {
                        let mut finished = None;
                        let mut keep_in = false;
                        if let Some(entry) = self.fds.get_mut(&raw)
                            && let FdRole::Stream {
                                recv_token,
                                pending_send,
                                ..
                            } = &mut entry.role
                        {
                            keep_in = recv_token.is_some();
                            if let Some(ps) = pending_send.as_mut()
                                && let Some(res) = Self::flush_pending_send(raw, ps)
                            {
                                let tok = ps.token;
                                *pending_send = None;
                                finished = Some((tok, res));
                            }
                        }
                        if let Some((tok, res)) = finished {
                            let mut new_mask = libc::EPOLLET as u32;
                            if keep_in {
                                new_mask |= (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
                            }
                            let _ = self.update_interest(raw, new_mask);
                            events.push(IoEvent::SendComplete {
                                token: tok,
                                result: res,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(events.len() - before)
    }
}

pub(crate) fn sockaddr_storage_to_std(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    // SAFETY: `storage` was populated by `accept4(2)` with `len` valid bytes.
    let sa = unsafe { SockAddr::new(*storage, len) };
    sa.as_socket()
}
