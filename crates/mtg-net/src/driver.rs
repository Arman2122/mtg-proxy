//! Monomorphized Linux I/O driver abstraction (`IoDriver`), buffer handles with
//! 5-byte FakeTLS record headroom, and pooled non-blocking `pipe2(2)` pairs for
//! zero-copy kernel `splice(2)` domain fronting.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// 5-byte headroom reserved before every receive buffer payload so FakeTLS
/// `0x17 0x03 0x03 <len_be16>` headers can be stamped directly in-place with
/// zero copy before `send` / `send_zc`.
pub const TLS_HEADROOM: usize = 5;

/// Small provided-buffer payload capacity (4 KiB — handshakes & interactive).
pub const SMALL_BUF_SIZE: usize = 4096;
/// Large provided-buffer payload capacity (16 KiB + 64B framing headroom).
pub const LARGE_BUF_SIZE: usize = 16 * 1024 + 64;
/// Buffer group ID for small buffers (`bgid = 0`).
pub const BGID_SMALL: u16 = 0;
/// Buffer group ID for large buffers (`bgid = 1`).
pub const BGID_LARGE: u16 = 1;
/// Minimum payload size to engage `IORING_OP_SEND_ZC` (zero-copy DMA).
pub const SEND_ZC_THRESHOLD: usize = 8192;

/// Active Linux I/O backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    IoUring,
    Epoll,
}

impl std::fmt::Display for DriverKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoUring => f.write_str("io_uring"),
            Self::Epoll => f.write_str("epoll"),
        }
    }
}

/// Probed kernel feature flags for observability (`doctor` & `/stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DriverCapabilities {
    pub kind: Option<DriverKind>,
    pub single_issuer: bool,
    pub defer_taskrun: bool,
    pub coop_taskrun: bool,
    pub accept_multishot: bool,
    pub recv_multishot: bool,
    pub buf_ring: bool,
    pub send_zc: bool,
    pub splice: bool,
    pub registered_files: bool,
}

/// Driver-scoped descriptor handle:
/// - In `UringDriver`: fixed direct file table slot index.
/// - In `EpollDriver`: raw file descriptor number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DriverFd(pub u32);

/// Borrowed buffer slab slot returned by [`IoEvent::Recv`].
///
/// The caller MUST return it via [`IoDriver::recycle_buf`] after processing.
/// The underlying backing memory always provides [`TLS_HEADROOM`] writable
/// bytes immediately before `payload_offset` so FakeTLS record headers can be
/// stamped in-place without moving bytes!
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufHandle {
    pub group: u16,
    pub id: u16,
    pub len: u32,
}

/// Completion event emitted by [`IoDriver::submit_and_wait`].
#[derive(Debug)]
pub enum IoEvent {
    /// New client socket accepted on listener `token`.
    Accept {
        token: u64,
        fd: OwnedFd,
        peer: Option<SocketAddr>,
        more: bool,
    },
    /// Non-blocking outbound `connect(2)` finished.
    Connect { token: u64, result: io::Result<()> },
    /// Data received into driver-managed buffer `buf` (`len == 0` means peer EOF).
    Recv {
        token: u64,
        buf: Option<BufHandle>,
        result: io::Result<usize>,
        more: bool,
    },
    /// Socket became writable (used by `epoll` or paced flush).
    Writable { token: u64 },
    /// Queued send finished (and for `SEND_ZC`, DMA buffer is safe to drop).
    SendComplete {
        token: u64,
        result: io::Result<usize>,
    },
    /// Zero-copy `splice(2)` transfer chunk finished (`Ok(0)` = EOF).
    SpliceComplete {
        token: u64,
        result: io::Result<usize>,
    },
    /// Control-plane `eventfd` wakeup fired.
    Wakeup,
    /// Socket closed / hangup / error.
    Error { token: u64, err: io::Error },
}

/// Non-blocking Linux kernel pipe pair (`pipe2(O_NONBLOCK | O_CLOEXEC)`) used
/// for zero-copy `splice(2)` fronting.
#[derive(Debug)]
pub struct SplicePipe {
    pub read_end: OwnedFd,
    pub write_end: OwnedFd,
}

impl SplicePipe {
    /// Create a fresh non-blocking `O_CLOEXEC` Linux pipe pair.
    pub fn new() -> io::Result<Self> {
        let mut fds = [-1 as libc::c_int; 2];
        // SAFETY: `fds` is a valid 2-element `c_int` array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Best-effort 64 KiB pipe sizing for steady-state TLS record splicing.
        // SAFETY: `fds[1]` is a newly opened valid pipe write fd.
        unsafe {
            let _ = libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 65_536 as libc::c_int);
        }
        // SAFETY: `pipe2` returned two newly owned valid file descriptors.
        unsafe {
            Ok(Self {
                read_end: OwnedFd::from_raw_fd(fds[0]),
                write_end: OwnedFd::from_raw_fd(fds[1]),
            })
        }
    }

    #[inline]
    pub fn read_fd(&self) -> RawFd {
        self.read_end.as_raw_fd()
    }

    #[inline]
    pub fn write_fd(&self) -> RawFd {
        self.write_end.as_raw_fd()
    }
}

/// Per-worker LIFO pool of [`SplicePipe`] pairs avoiding `pipe2`/`close` churn
/// during domain-fronting bursts.
#[derive(Debug)]
pub struct SplicePipePool {
    pipes: Vec<SplicePipe>,
    max_cached: usize,
}

impl SplicePipePool {
    pub fn new(max_cached: usize) -> Self {
        Self {
            pipes: Vec::with_capacity(max_cached.min(64)),
            max_cached,
        }
    }

    pub fn acquire(&mut self) -> io::Result<SplicePipe> {
        if let Some(p) = self.pipes.pop() {
            Ok(p)
        } else {
            SplicePipe::new()
        }
    }

    /// Return a drained pipe to the pool (caller must only recycle empty pipes).
    pub fn release(&mut self, pipe: SplicePipe) {
        if self.pipes.len() < self.max_cached {
            self.pipes.push(pipe);
        }
    }
}

/// Configuration for initializing an [`IoDriver`] on one worker core.
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    /// SQ/CQ ring entries for `io_uring` (rounded up to power of 2).
    pub ring_entries: u32,
    /// Maximum registered/tracked descriptors per worker.
    pub max_files: u32,
    /// Number of 4 KiB buffers in group 0 (must be power of 2).
    pub small_bufs: u16,
    /// Number of 16 KiB+64B buffers in group 1 (must be power of 2).
    pub large_bufs: u16,
    /// Prefer `SEND_ZC` for buffers >= [`SEND_ZC_THRESHOLD`].
    pub enable_send_zc: bool,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            ring_entries: 1024,
            max_files: 65_536,
            small_bufs: 512,
            large_bufs: 256,
            enable_send_zc: true,
        }
    }
}

/// Monomorphized Linux event-loop I/O driver (`UringDriver` or `EpollDriver`).
///
/// The hot worker loop is generic over `D: IoDriver` so every call is statically
/// dispatched with zero dynamic vtable overhead.
pub trait IoDriver: Sized {
    /// Driver backend kind.
    fn kind(&self) -> DriverKind;

    /// Probed capability summary.
    fn capabilities(&self) -> DriverCapabilities;

    /// `eventfd` raw descriptor that another thread can write `1u64` to in order
    /// to wake this worker immediately out of `submit_and_wait`.
    fn wake_fd(&self) -> RawFd;

    /// Register an owned socket with this worker and receive a [`DriverFd`].
    fn register_fd(&mut self, fd: OwnedFd) -> io::Result<DriverFd>;

    /// Unregister and close `dfd`.
    fn unregister_fd(&mut self, dfd: DriverFd) -> io::Result<()>;

    /// Obtain the underlying OS `RawFd` (for `getsockname`/`setsockopt` etc.).
    fn raw_fd(&self, dfd: DriverFd) -> Option<RawFd>;

    /// Arm accepting incoming TCP connections on `listener`.
    fn arm_accept(&mut self, listener: DriverFd, token: u64) -> io::Result<()>;

    /// Arm receiving data from `fd` into buffer group `bgid` (`BGID_SMALL` or `BGID_LARGE`).
    fn arm_recv(&mut self, fd: DriverFd, token: u64, bgid: u16) -> io::Result<()>;

    /// Queue an asynchronous non-blocking TCP `connect(2)`.
    fn queue_connect(&mut self, fd: DriverFd, addr: SocketAddr, token: u64) -> io::Result<()>;

    /// Queue a non-blocking send of `data` on `fd`.
    ///
    /// Takes ownership of `data` so `UringDriver` can keep the memory pinned
    /// across kernel DMA (`SEND_ZC` or async `SEND`) until `SendComplete` arrives.
    fn queue_send(
        &mut self,
        fd: DriverFd,
        token: u64,
        data: Vec<u8>,
        offset: usize,
        zero_copy_hint: bool,
    ) -> io::Result<()>;

    /// Perform or queue a zero-copy kernel `splice(2)` transfer of up to `len`
    /// bytes from `src` -> `pipe` -> `dst`.
    fn queue_splice(
        &mut self,
        src: DriverFd,
        dst: DriverFd,
        pipe: &SplicePipe,
        len: u32,
        token: u64,
    ) -> io::Result<()>;

    /// Access the received payload slice of `handle` (zero-copy view into slab/ring).
    fn buf_slice(&self, handle: BufHandle) -> &[u8];

    /// Access the mutable payload slice of `handle` PLUS the [`TLS_HEADROOM`]
    /// bytes immediately preceding it (`&mut [0..TLS_HEADROOM + handle.len]`)
    /// so in-place decryption + FakeTLS framing requires 0 copies!
    fn buf_with_headroom_mut(&mut self, handle: BufHandle) -> &mut [u8];

    /// Recycle `handle` back into the driver's buffer ring / free slab.
    fn recycle_buf(&mut self, handle: BufHandle);

    /// Submit queued SQEs / interest updates and wait up to `timeout_ms` for
    /// completions, pushing them into `events`.
    fn submit_and_wait(&mut self, timeout_ms: u32, events: &mut Vec<IoEvent>) -> io::Result<usize>;
}

/// Signal a worker's `wake_fd` (`eventfd`) from any thread.
pub fn signal_wake_fd(wake_fd: RawFd) -> io::Result<()> {
    let val: u64 = 1;
    // SAFETY: `val` is a valid 8-byte aligned `u64` for `eventfd(2)` write.
    let rc = unsafe { libc::write(wake_fd, (&raw const val).cast(), 8) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Create a non-blocking `EFD_CLOEXEC | EFD_NONBLOCK` Linux `eventfd`.
pub(crate) fn create_eventfd() -> io::Result<OwnedFd> {
    // SAFETY: `eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)` is always safe.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly created owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Drain pending counter value from an `eventfd`.
pub(crate) fn drain_eventfd(fd: RawFd) {
    let mut buf = 0u64;
    // SAFETY: `buf` is a valid 8-byte buffer for reading an `eventfd`.
    let _ = unsafe { libc::read(fd, (&raw mut buf).cast(), 8) };
}
