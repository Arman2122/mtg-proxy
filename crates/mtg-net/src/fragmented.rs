//! Two-speed Linux `MSG_EOR` ServerHello TCP fragmentation.
//!
//! Splits ONLY the FakeTLS `ServerHello` flight into small, sealed kernel
//! `sk_buff`s using `libc::send(..., MSG_EOR | MSG_DONTWAIT | MSG_NOSIGNAL)`
//! (respecting negotiated `TCP_INFO` `tcpi_snd_mss` and `TCPI_OPT_TIMESTAMPS`),
//! defeating stateful DPI/TSPU inspection on the handshake while leaving 100%
//! of post-handshake bulk data running at full MTU / TSO / GSO speed!

use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::net::TcpStream;

/// Linux `<linux/tcp.h>` `TCPI_OPT_TIMESTAMPS` bit in `tcp_info.tcpi_options`.
const TCPI_OPT_TIMESTAMPS: u8 = 1;
/// TCP timestamps option length in bytes (RFC 7323).
const TCP_TIMESTAMP_OPT_BYTES: usize = 12;
/// Minimum safe chunk size even after subtracting TCP timestamp option overhead.
const MIN_FRAGMENT_CHUNK: usize = 64;

/// Query Linux `TCP_INFO` to compute the effective per-segment chunk size for
/// `target_mss`:
/// - Reads `tcpi_options` (`TCPI_OPT_TIMESTAMPS` -> subtracts 12 B) and `tcpi_snd_mss`.
/// - Falls back cleanly to `target_mss` if `getsockopt` is unavailable.
pub fn effective_fragment_chunk(fd: libc::c_int, target_mss: u16) -> usize {
    let mut chunk = usize::from(target_mss);
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: `fd` is a valid TCP socket fd and `info` is a properly sized `libc::tcp_info`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc == 0 {
        let snd_mss = usize::try_from(info.tcpi_snd_mss).unwrap_or(0);
        if snd_mss >= MIN_FRAGMENT_CHUNK {
            chunk = chunk.min(snd_mss);
        }
        if (info.tcpi_options & TCPI_OPT_TIMESTAMPS) != 0 {
            chunk = chunk.saturating_sub(TCP_TIMESTAMP_OPT_BYTES);
        }
    }
    chunk.clamp(MIN_FRAGMENT_CHUNK, 1400)
}

/// Transmit `data` (the FakeTLS `ServerHello` + CCS + encrypted handshake flight)
/// in sealed `effective_chunk`-byte TCP segments using Linux `MSG_EOR`.
///
/// Each `send(MSG_EOR)` marks `TCP_SKB_CB(skb)->eor = 1` inside Linux TCP,
/// preventing kernel coalescing across adjacent chunks while requiring zero
/// `TCP_MAXSEG` mutations so post-handshake bulk relay traffic stays at 100% MTU!
pub async fn send_fragmented_server_hello(
    stream: &TcpStream,
    data: &[u8],
    target_mss: u16,
    timeout: Duration,
) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let fd = stream.as_raw_fd();
    let chunk_size = effective_fragment_chunk(fd, target_mss);
    let deadline = tokio::time::Instant::now() + timeout;

    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let mut piece = &data[offset..end];

        while !piece.is_empty() {
            let send_res = stream.try_io(tokio::io::Interest::WRITABLE, || {
                // SAFETY: `fd` is a valid non-blocking Linux TCP socket and `piece` is readable.
                let n = unsafe {
                    libc::send(
                        fd,
                        piece.as_ptr().cast::<libc::c_void>(),
                        piece.len(),
                        libc::MSG_EOR | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match send_res {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "fragmented ServerHello write zero",
                    ));
                }
                Ok(written) => {
                    piece = &piece[written..];
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if rem.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "fragmented ServerHello timeout",
                        ));
                    }
                    tokio::time::timeout(rem, stream.writable())
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "fragmented ServerHello timeout",
                            )
                        })??;
                }
                Err(e) => return Err(e),
            }
        }

        offset = end;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn msg_eor_fragmented_server_hello_delivers_exact_payload() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();

        let payload: Vec<u8> = (0..4_123usize)
            .map(|i| (i.wrapping_mul(73).wrapping_add(19)) as u8)
            .collect();
        let expected = payload.clone();

        let srv = tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut got = vec![0u8; expected.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let chunk = effective_fragment_chunk(client.as_raw_fd(), 92);
        assert!((MIN_FRAGMENT_CHUNK..=92).contains(&chunk));

        send_fragmented_server_hello(&client, &payload, 92, Duration::from_secs(2))
            .await
            .unwrap();
        srv.await.unwrap();
    }
}
