//! Strict server-only RFC 6455 WebSocket implementation tailored for the
//! Shared-Frame v1 WEB relay carrier.
//!
//! Security & performance properties:
//! - Exact RFC 6455 §1.3 `Sec-WebSocket-Accept` hash verified against the RFC's
//!   own published test vector.
//! - Rejects every ambiguity/probing distinguisher: unmasked client frames,
//!   non-minimal length encodings, non-zero RSV bits, reserved opcodes,
//!   fragmented or >125B control frames, text messages (`1003`), oversized
//!   messages BEFORE allocating (`1009`), >1024 continuation fragments (`1002`),
//!   and client ping floods (>16 pings per 10s window, `1002`).
//! - 64-bit SWAR (auto-vectorized) in-place unmasking + zero-copy vectored
//!   `writev(2)` server frame transmission.
//! - Split `(WsReader, WsWriter)` where `WsReader::read_event` is 100%
//!   cancel-safe for single-task `tokio::select!` multiplexing.

use std::io::{self, IoSlice};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf as _, Bytes, BytesMut};
use http::{HeaderMap, Method, Version};
use sha1::{Digest as _, Sha1};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// RFC 6455 §1.3 WebSocket GUID constant.
pub const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Opcodes handled by the strict carrier.
pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// RFC 6455 close status codes emitted by the relay.
pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
pub const CLOSE_TOO_BIG: u16 = 1009;
pub const CLOSE_INTERNAL_ERROR: u16 = 1011;

/// Maximum RFC 6455 control frame payload length (`125` bytes).
pub const MAX_CONTROL_PAYLOAD: usize = 125;
/// Maximum number of continuation frames permitted in one fragmented message.
pub const MAX_CONTINUATION_FRAMES: usize = 1024;
/// Ping flood rate-limit ceiling per window.
pub const MAX_PINGS_PER_WINDOW: u32 = 16;
/// Ping rate-limit window duration.
pub const PING_WINDOW: Duration = Duration::from_secs(10);
/// Default maximum reassembled binary message length (`2 MiB`).
pub const DEFAULT_MAX_MESSAGE: usize = 2 << 20;
/// Default silence period before sending a liveness Ping.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(25);
/// Default bound on one WebSocket write flush.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// WebSocket handshake and frame-layer errors.
#[derive(Debug, Error)]
pub enum WsError {
    #[error("not a WebSocket upgrade request")]
    NotWebSocket,
    #[error("WebSocket handshake refused: {0}")]
    Handshake(&'static str),
    #[error("WebSocket protocol error: {0}")]
    Protocol(&'static str),
    #[error("WebSocket unsupported data (text frame)")]
    UnsupportedData,
    #[error("WebSocket message exceeds maximum size ({len} > {max})")]
    MessageTooBig { len: usize, max: usize },
    #[error("WebSocket connection closed")]
    Closed,
    #[error("WebSocket I/O error: {0}")]
    Io(#[from] io::Error),
}

impl WsError {
    /// RFC 6455 close code to transmit when terminating on this error.
    #[inline]
    pub const fn close_code(&self) -> u16 {
        match self {
            Self::UnsupportedData => CLOSE_UNSUPPORTED_DATA,
            Self::MessageTooBig { .. } => CLOSE_TOO_BIG,
            Self::Protocol(_) => CLOSE_PROTOCOL_ERROR,
            Self::Closed => CLOSE_NORMAL,
            Self::Io(_) | Self::NotWebSocket | Self::Handshake(_) => CLOSE_INTERNAL_ERROR,
        }
    }
}

/// Incoming validated WebSocket event produced by [`WsReader::read_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(u16),
}

/// Compute the RFC 6455 §1.3 `Sec-WebSocket-Accept` header value.
pub fn accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(ACCEPT_GUID.as_bytes());
    let digest = hasher.finalize();
    STANDARD.encode(digest)
}

/// Reports whether an HTTP request is requesting a WebSocket upgrade.
pub fn is_upgrade(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET {
        return false;
    }
    let has_conn_upgrade = header_token_list_contains(headers, "connection", "upgrade");
    let has_ws_upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"));
    has_conn_upgrade && has_ws_upgrade
}

/// Strictly validate an HTTP/1.1 RFC 6455 WebSocket upgrade request and return
/// the computed `Sec-WebSocket-Accept` string.
pub fn validate_upgrade(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
    expected_subprotocol: Option<&str>,
) -> Result<String, WsError> {
    if !is_upgrade(method, headers) {
        return Err(WsError::NotWebSocket);
    }
    if version != Version::HTTP_11 {
        return Err(WsError::Handshake("requires HTTP/1.1"));
    }

    let ver = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ver != "13" {
        return Err(WsError::Handshake("unsupported Sec-WebSocket-Version"));
    }

    let key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(WsError::Handshake("missing Sec-WebSocket-Key"))?;
    let mut key_raw = [0u8; 24];
    let decoded_len = STANDARD
        .decode_slice(key.as_bytes(), &mut key_raw)
        .map_err(|_| WsError::Handshake("malformed Sec-WebSocket-Key"))?;
    if decoded_len != 16 {
        return Err(WsError::Handshake(
            "Sec-WebSocket-Key must decode to 16 bytes",
        ));
    }

    if let Some(want) = expected_subprotocol {
        let offered = split_header_token_list(headers, "sec-websocket-protocol");
        if offered.len() != 1 || offered[0] != want {
            return Err(WsError::Handshake("subprotocol mismatch"));
        }
    }

    Ok(accept_key(key))
}

fn header_token_list_contains(headers: &HeaderMap, name: &str, want: &str) -> bool {
    for val in headers.get_all(name) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        for tok in s.split(',') {
            if tok.trim().eq_ignore_ascii_case(want) {
                return true;
            }
        }
    }
    false
}

fn split_header_token_list<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for val in headers.get_all(name) {
        if let Ok(s) = val.to_str() {
            for tok in s.split(',') {
                let t = tok.trim();
                if !t.is_empty() {
                    out.push(t);
                }
            }
        }
    }
    out
}

/// Fast 64-bit SWAR (auto-vectorized to SSE2/AVX2) in-place RFC 6455 unmasking.
#[inline]
pub fn unmask_in_place(buf: &mut [u8], mask: [u8; 4]) {
    let mask64 = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let mut chunks = buf.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let mut word = u64::from_ne_bytes(chunk.try_into().expect("8 bytes"));
        word ^= mask64;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    let rem = chunks.into_remainder();
    for (i, b) in rem.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
}

/// Encode a minimal unmasked server RFC 6455 header (`FIN = 1`) into `dst`,
/// returning the header length (`2`, `4`, or `10`).
#[inline]
pub fn encode_server_header(dst: &mut [u8; 10], opcode: u8, payload_len: usize) -> usize {
    dst[0] = 0x80 | (opcode & 0x0f);
    if payload_len < 126 {
        dst[1] = payload_len as u8;
        2
    } else if u16::try_from(payload_len).is_ok() {
        dst[1] = 126;
        dst[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        4
    } else {
        dst[1] = 127;
        dst[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
        10
    }
}

/// Cancel-safe strict RFC 6455 server WebSocket reader.
#[derive(Debug)]
pub struct WsReader<R> {
    io: R,
    read_buf: BytesMut,
    frag_buf: BytesMut,
    in_frag: bool,
    frag_count: usize,
    max_message: usize,
    ping_window_start: Instant,
    ping_count: u32,
}

impl<R: AsyncRead + Unpin> WsReader<R> {
    pub fn new(io: R, max_message: usize) -> Self {
        let max_msg = if max_message == 0 {
            DEFAULT_MAX_MESSAGE
        } else {
            max_message
        };
        Self {
            io,
            // Lazy 0B allocation while WebSocket is idle; grows on demand!
            read_buf: BytesMut::new(),
            frag_buf: BytesMut::new(),
            in_frag: false,
            frag_count: 0,
            max_message: max_msg,
            ping_window_start: Instant::now(),
            ping_count: 0,
        }
    }

    /// Read the next validated WebSocket event (`Binary`, `Ping`, `Pong`, `Close`).
    ///
    /// **100% cancel-safe**: bytes already read remain safely buffered in
    /// `self.read_buf` and are never lost if dropped inside `tokio::select!`.
    pub async fn read_event(&mut self) -> Result<WsEvent, WsError> {
        loop {
            if let Some(ev) = self.try_parse_next()? {
                // Reclaim oversized read buffer capacity once drained to keep idle RSS minimal!
                if self.read_buf.is_empty() && self.read_buf.capacity() > 16 * 1024 {
                    self.read_buf = BytesMut::new();
                }
                return Ok(ev);
            }
            if self.read_buf.capacity() - self.read_buf.len() < 4096 {
                self.read_buf.reserve(4096);
            }
            let n = self.io.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                return Err(WsError::Closed);
            }
        }
    }

    fn try_parse_next(&mut self) -> Result<Option<WsEvent>, WsError> {
        loop {
            let buf = &self.read_buf[..];
            if buf.len() < 2 {
                return Ok(None);
            }

            let b0 = buf[0];
            let b1 = buf[1];
            let fin = (b0 & 0x80) != 0;
            let rsv = b0 & 0x70;
            let opcode = b0 & 0x0f;
            let masked = (b1 & 0x80) != 0;
            let len7 = b1 & 0x7f;

            // Strict RFC 6455 validations BEFORE reading payload!
            if rsv != 0 {
                return Err(WsError::Protocol("non-zero RSV bits"));
            }
            if !masked {
                return Err(WsError::Protocol("unmasked client frame"));
            }
            match opcode {
                OP_CONTINUATION | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG => {}
                OP_TEXT => return Err(WsError::UnsupportedData),
                _ => return Err(WsError::Protocol("reserved opcode")),
            }

            let is_control = (opcode & 0x08) != 0;
            if is_control && !fin {
                return Err(WsError::Protocol("fragmented control frame"));
            }

            let (hdr_len, payload_len): (usize, usize) = match len7 {
                0..=125 => (2 + 4, usize::from(len7)),
                126 => {
                    if buf.len() < 4 {
                        return Ok(None);
                    }
                    let ext = u16::from_be_bytes([buf[2], buf[3]]);
                    if ext < 126 {
                        return Err(WsError::Protocol("non-minimal 16-bit length"));
                    }
                    (4 + 4, usize::from(ext))
                }
                127 => {
                    if buf.len() < 10 {
                        return Ok(None);
                    }
                    let ext = u64::from_be_bytes(buf[2..10].try_into().expect("8 bytes"));
                    if (ext & (1u64 << 63)) != 0 || u16::try_from(ext).is_ok() {
                        return Err(WsError::Protocol("non-minimal or MSB-set 64-bit length"));
                    }
                    let ext_usize = usize::try_from(ext).map_err(|_| WsError::MessageTooBig {
                        len: usize::MAX,
                        max: self.max_message,
                    })?;
                    (10 + 4, ext_usize)
                }
                _ => unreachable!("len7 is masked with 0x7f"),
            };

            if is_control && payload_len > MAX_CONTROL_PAYLOAD {
                return Err(WsError::Protocol("control frame payload exceeds 125 bytes"));
            }

            // Validate fragmentation & message size bounds BEFORE waiting/allocating payload!
            if !is_control {
                match opcode {
                    OP_BINARY => {
                        if self.in_frag {
                            return Err(WsError::Protocol("new binary frame during fragmentation"));
                        }
                        if payload_len > self.max_message {
                            return Err(WsError::MessageTooBig {
                                len: payload_len,
                                max: self.max_message,
                            });
                        }
                    }
                    OP_CONTINUATION => {
                        if !self.in_frag {
                            return Err(WsError::Protocol("unexpected continuation frame"));
                        }
                        if self.frag_count >= MAX_CONTINUATION_FRAMES {
                            return Err(WsError::Protocol("too many continuation frames"));
                        }
                        let total = self.frag_buf.len().saturating_add(payload_len);
                        if total > self.max_message {
                            return Err(WsError::MessageTooBig {
                                len: total,
                                max: self.max_message,
                            });
                        }
                    }
                    _ => unreachable!(),
                }
            }

            let total_frame = hdr_len.saturating_add(payload_len);
            if buf.len() < total_frame {
                // Pre-reserve exact frame size once validated against max_message.
                let needed = total_frame - buf.len();
                if self.read_buf.capacity() - self.read_buf.len() < needed {
                    self.read_buf.reserve(needed);
                }
                return Ok(None);
            }

            // Extract mask and frame payload cleanly.
            let mask: [u8; 4] = buf[hdr_len - 4..hdr_len].try_into().expect("4 mask bytes");
            self.read_buf.advance(hdr_len);
            let mut payload = self.read_buf.split_to(payload_len);
            unmask_in_place(&mut payload, mask);

            if is_control {
                match opcode {
                    OP_PING => {
                        let now = Instant::now();
                        if now.duration_since(self.ping_window_start) >= PING_WINDOW {
                            self.ping_window_start = now;
                            self.ping_count = 0;
                        }
                        self.ping_count = self.ping_count.saturating_add(1);
                        if self.ping_count > MAX_PINGS_PER_WINDOW {
                            return Err(WsError::Protocol("ping flood rate limit exceeded"));
                        }
                        return Ok(Some(WsEvent::Ping(payload.freeze())));
                    }
                    OP_PONG => return Ok(Some(WsEvent::Pong(payload.freeze()))),
                    OP_CLOSE => {
                        let code = match payload.len() {
                            0 => CLOSE_NORMAL,
                            1 => return Err(WsError::Protocol("1-byte close payload")),
                            _ => {
                                let c = u16::from_be_bytes([payload[0], payload[1]]);
                                if !is_valid_peer_close_code(c) {
                                    return Err(WsError::Protocol("invalid close status code"));
                                }
                                if std::str::from_utf8(&payload[2..]).is_err() {
                                    return Err(WsError::Protocol("non-UTF-8 close reason"));
                                }
                                c
                            }
                        };
                        return Ok(Some(WsEvent::Close(code)));
                    }
                    _ => unreachable!(),
                }
            }

            // Data frame (binary or continuation)
            if opcode == OP_BINARY && fin {
                return Ok(Some(WsEvent::Binary(payload.freeze())));
            }

            if opcode == OP_BINARY {
                self.in_frag = true;
                self.frag_count = 1;
                self.frag_buf.clear();
                self.frag_buf.extend_from_slice(&payload);
                // Keep looping to see if next fragment is already buffered.
                continue;
            }

            // OP_CONTINUATION
            self.frag_count += 1;
            self.frag_buf.extend_from_slice(&payload);
            if fin {
                self.in_frag = false;
                self.frag_count = 0;
                let msg = self.frag_buf.split().freeze();
                return Ok(Some(WsEvent::Binary(msg)));
            }
        }
    }
}

#[inline]
const fn is_valid_peer_close_code(code: u16) -> bool {
    matches!(
        code,
        1000..=1003 | 1007..=1014 | 3000..=4999
    )
}

/// Unmasked server RFC 6455 WebSocket writer with vectored `writev(2)` support.
#[derive(Debug)]
pub struct WsWriter<W> {
    io: W,
    write_timeout: Duration,
    close_sent: bool,
}

impl<W: AsyncWrite + Unpin> WsWriter<W> {
    pub fn new(io: W, write_timeout: Duration) -> Self {
        Self {
            io,
            write_timeout: if write_timeout.is_zero() {
                DEFAULT_WRITE_TIMEOUT
            } else {
                write_timeout
            },
            close_sent: false,
        }
    }

    /// Write a single binary WebSocket message whose payload is scattered across
    /// `slices` using vectored `writev(2)` syscalls (zero intermediate copy!).
    pub async fn write_binary_vectored(&mut self, slices: &[&[u8]]) -> Result<(), WsError> {
        let total: usize = slices.iter().map(|s| s.len()).sum();
        let mut hdr = [0u8; 10];
        let hdr_len = encode_server_header(&mut hdr, OP_BINARY, total);

        let mut bufs: Vec<&[u8]> = Vec::with_capacity(slices.len() + 1);
        bufs.push(&hdr[..hdr_len]);
        for s in slices {
            if !s.is_empty() {
                bufs.push(s);
            }
        }
        self.write_all_vectored_timeout(&bufs).await
    }

    /// Write a single binary WebSocket message.
    pub async fn write_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.write_binary_vectored(&[data]).await
    }

    /// Write a server control frame (`OP_PING` or `OP_PONG`), truncated to `125` bytes.
    pub async fn write_control(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        let body = &payload[..payload.len().min(MAX_CONTROL_PAYLOAD)];
        let mut frame = [0u8; 2 + MAX_CONTROL_PAYLOAD];
        let mut hdr = [0u8; 10];
        let hlen = encode_server_header(&mut hdr, opcode, body.len());
        frame[..hlen].copy_from_slice(&hdr[..hlen]);
        frame[hlen..hlen + body.len()].copy_from_slice(body);
        self.write_all_timeout(&frame[..hlen + body.len()]).await
    }

    /// Write an RFC 6455 Close frame with `code` (idempotent — at most once).
    pub async fn write_close(&mut self, code: u16) -> Result<(), WsError> {
        if self.close_sent {
            return Ok(());
        }
        self.close_sent = true;
        let payload = code.to_be_bytes();
        let mut buf = [0u8; 4];
        buf[0] = 0x80 | OP_CLOSE;
        buf[1] = 2;
        buf[2..4].copy_from_slice(&payload);
        let _ = self.write_all_timeout(&buf).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.io.shutdown()).await;
        Ok(())
    }

    async fn write_all_timeout(&mut self, data: &[u8]) -> Result<(), WsError> {
        tokio::time::timeout(self.write_timeout, self.io.write_all(data))
            .await
            .map_err(|_| {
                WsError::Io(io::Error::new(io::ErrorKind::TimedOut, "ws write timeout"))
            })??;
        Ok(())
    }

    async fn write_all_vectored_timeout(&mut self, slices: &[&[u8]]) -> Result<(), WsError> {
        let fut = async {
            let mut idx = 0usize;
            let mut off = 0usize;
            let mut io_slices: Vec<IoSlice<'_>> = Vec::with_capacity(slices.len().min(64));

            while idx < slices.len() {
                io_slices.clear();
                let first = &slices[idx][off..];
                if !first.is_empty() {
                    io_slices.push(IoSlice::new(first));
                }
                for s in slices.iter().skip(idx + 1).take(63) {
                    if !s.is_empty() {
                        io_slices.push(IoSlice::new(s));
                    }
                }
                if io_slices.is_empty() {
                    break;
                }
                let mut written = self.io.write_vectored(&io_slices).await?;
                if written == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_vectored returned 0",
                    ));
                }
                while written > 0 && idx < slices.len() {
                    let avail = slices[idx].len() - off;
                    if written >= avail {
                        written -= avail;
                        idx += 1;
                        off = 0;
                    } else {
                        off += written;
                        written = 0;
                    }
                }
            }
            Ok(())
        };

        tokio::time::timeout(self.write_timeout, fut)
            .await
            .map_err(|_| {
                WsError::Io(io::Error::new(io::ErrorKind::TimedOut, "ws write timeout"))
            })??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_client_frame(fin: bool, opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 } else { 0x00 } | opcode);
        if payload.len() < 126 {
            out.push(0x80 | (payload.len() as u8));
        } else if u16::try_from(payload.len()).is_ok() {
            out.push(0x80 | 0x7e);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            out.push(0x80 | 0x7f);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        let mut body = payload.to_vec();
        unmask_in_place(&mut body, mask);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn accept_key_matches_rfc6455_section_1_3_vector() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn strict_parser_accepts_fragmented_binary_and_rejects_violations() {
        // Fragmented binary message + interleaved ping
        let (mut client, server) = tokio::io::duplex(4096);
        let mut reader = WsReader::new(server, 1024);

        let f1 = mask_client_frame(false, OP_BINARY, b"hello ", [1, 2, 3, 4]);
        let ping = mask_client_frame(true, OP_PING, b"hi", [5, 6, 7, 8]);
        let f2 = mask_client_frame(true, OP_CONTINUATION, b"world!", [9, 10, 11, 12]);
        client.write_all(&f1).await.unwrap();
        client.write_all(&ping).await.unwrap();
        client.write_all(&f2).await.unwrap();

        assert_eq!(
            reader.read_event().await.unwrap(),
            WsEvent::Ping(Bytes::from_static(b"hi"))
        );
        assert_eq!(
            reader.read_event().await.unwrap(),
            WsEvent::Binary(Bytes::from_static(b"hello world!"))
        );

        // Unmasked frame rejected with Protocol error
        client.write_all(&[0x82, 0x02, b'o', b'k']).await.unwrap();
        let err = reader.read_event().await.unwrap_err();
        assert_eq!(err.close_code(), CLOSE_PROTOCOL_ERROR);

        // Non-minimal 16-bit length for 4-byte payload rejected!
        let (mut client2, server2) = tokio::io::duplex(4096);
        let mut reader2 = WsReader::new(server2, 1024);
        client2
            .write_all(&[0x82, 0x80 | 0x7e, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0])
            .await
            .unwrap();
        let err = reader2.read_event().await.unwrap_err();
        assert_eq!(err.close_code(), CLOSE_PROTOCOL_ERROR);

        // Text frame rejected with 1003
        let (mut client3, server3) = tokio::io::duplex(4096);
        let mut reader3 = WsReader::new(server3, 1024);
        let txt = mask_client_frame(true, OP_TEXT, b"abc", [1, 1, 1, 1]);
        client3.write_all(&txt).await.unwrap();
        let err = reader3.read_event().await.unwrap_err();
        assert_eq!(err.close_code(), CLOSE_UNSUPPORTED_DATA);

        // Oversized message rejected with 1009 BEFORE full payload arrives
        let (mut client4, server4) = tokio::io::duplex(4096);
        let mut reader4 = WsReader::new(server4, 64);
        client4
            .write_all(&[0x82, 0x80 | 0x7e, 0x01, 0x00, 1, 2, 3, 4])
            .await
            .unwrap();
        let err = reader4.read_event().await.unwrap_err();
        assert_eq!(err.close_code(), CLOSE_TOO_BIG);
    }
}
