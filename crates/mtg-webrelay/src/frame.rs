//! Shared-Frame v1 wire codec for Telegram WEB proxy (`type:u8 | stream_id:u24
//! | payload_len:u32 | payload`), 100% byte-identical with Go `internal/webrelay/frame`.

use bytes::{BufMut as _, Bytes, BytesMut};
use thiserror::Error;

/// Fixed frame header length (`8` bytes).
pub const HEADER_SIZE: usize = 8;
/// Protocol maximum payload per single frame (`1 MiB`).
pub const MAX_PAYLOAD_SIZE: usize = 1 << 20;
/// Protocol maximum encoded batch size (`2 MiB`).
pub const MAX_BATCH_BYTES: usize = 2 << 20;
/// Maximum 24-bit stream ID.
pub const MAX_STREAM_ID: u32 = (1 << 24) - 1;
/// Maximum frames allowed in one carrier batch.
pub const MAX_FRAMES_PER_BATCH: usize = 4096;
/// Maximum `POST /api/v1/session` body size (one `HELLO` frame).
pub const MAX_SESSION_CREATE_BODY: usize = 64;
/// Maximum relay-generated `DATA` frame chunk size (`64 KiB`).
pub const MAX_RELAY_DATA_CHUNK: usize = 64 << 10;
/// Exact payload length of a `WINDOW` frame (`4` bytes).
pub const WINDOW_PAYLOAD_SIZE: usize = 4;
/// Shared-Frame v1 `HELLO` protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Implicit initial flow-control receive credit per stream direction (`4 MiB`).
pub const INITIAL_WINDOW: u32 = 4 << 20;

/// Wire frame type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Open = 0x01,
    Data = 0x02,
    Close = 0x03,
    Window = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    Hello = 0x10,
    Welcome = 0x11,
    Bye = 0x1f,
}

impl FrameType {
    #[inline]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Open),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Close),
            0x04 => Some(Self::Window),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::Pong),
            0x10 => Some(Self::Hello),
            0x11 => Some(Self::Welcome),
            0x1f => Some(Self::Bye),
            _ => None,
        }
    }

    #[inline]
    pub const fn is_session_frame(self) -> bool {
        matches!(
            self,
            Self::Ping | Self::Pong | Self::Hello | Self::Welcome | Self::Bye
        )
    }

    #[inline]
    pub const fn allowed_in(self, dir: Direction) -> bool {
        match dir {
            Direction::ClientToRelay => matches!(
                self,
                Self::Open | Self::Data | Self::Close | Self::Window | Self::Pong | Self::Hello
            ),
            Direction::RelayToClient => matches!(
                self,
                Self::Data | Self::Close | Self::Window | Self::Ping | Self::Welcome | Self::Bye
            ),
        }
    }

    #[inline]
    pub const fn payload_bounds(self) -> (usize, usize) {
        match self {
            Self::Open | Self::Close | Self::Welcome => (0, 0),
            Self::Data => (1, MAX_PAYLOAD_SIZE),
            Self::Window => (WINDOW_PAYLOAD_SIZE, WINDOW_PAYLOAD_SIZE),
            Self::Hello => (1, 1),
            Self::Ping | Self::Pong | Self::Bye => (0, MAX_PAYLOAD_SIZE),
        }
    }
}

/// Wire travel direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToRelay,
    RelayToClient,
}

/// Deployment-configurable frame bounds (always clamped at or below protocol ceilings).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameLimits {
    pub max_payload: usize,
    pub batch_bytes: usize,
}

impl FrameLimits {
    #[inline]
    pub const fn effective_payload(self) -> usize {
        if self.max_payload == 0 || self.max_payload > MAX_PAYLOAD_SIZE {
            MAX_PAYLOAD_SIZE
        } else {
            self.max_payload
        }
    }

    #[inline]
    pub const fn effective_batch_bytes(self) -> usize {
        if self.batch_bytes == 0 || self.batch_bytes > MAX_BATCH_BYTES {
            MAX_BATCH_BYTES
        } else {
            self.batch_bytes
        }
    }

    pub fn validate(self) -> Result<(), FrameError> {
        if self.max_payload > MAX_PAYLOAD_SIZE {
            return Err(FrameError::LimitOutOfRange(format!(
                "frame payload {} exceeds ceiling {MAX_PAYLOAD_SIZE}",
                self.max_payload
            )));
        }
        if self.batch_bytes > MAX_BATCH_BYTES {
            return Err(FrameError::LimitOutOfRange(format!(
                "batch bytes {} exceeds ceiling {MAX_BATCH_BYTES}",
                self.batch_bytes
            )));
        }
        Ok(())
    }
}

/// Errors produced by Shared-Frame v1 decoding or validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
    #[error("frame {0:?} not allowed in {1:?}")]
    WrongDirection(FrameType, Direction),
    #[error("session frame {0:?} carried nonzero stream_id {1}")]
    SessionFrameOnStream(FrameType, u32),
    #[error("stream frame {0:?} carried zero stream_id")]
    StreamFrameOnZero(FrameType),
    #[error("stream_id {0} exceeds 24-bit maximum")]
    StreamIdOutOfRange(u32),
    #[error("frame payload {len} exceeds cap {cap}")]
    PayloadTooLarge { len: usize, cap: usize },
    #[error("empty DATA frame")]
    EmptyData,
    #[error("invalid payload length {len} for {kind:?}")]
    PayloadLength { kind: FrameType, len: usize },
    #[error("zero WINDOW grant")]
    ZeroWindow,
    #[error("unsupported HELLO version {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("batch size {len} exceeds budget {budget}")]
    BatchTooLarge { len: usize, budget: usize },
    #[error("batch contains more than {MAX_FRAMES_PER_BATCH} frames")]
    TooManyFrames,
    #[error("truncated frame in batch")]
    PartialFrame,
    #[error("invalid HELLO session-create body")]
    InvalidHelloBody,
    #[error("limit out of range: {0}")]
    LimitOutOfRange(String),
}

/// One decoded/owned Shared-Frame v1 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Open { stream_id: u32 },
    Data { stream_id: u32, payload: Bytes },
    Close { stream_id: u32 },
    Window { stream_id: u32, delta: u32 },
    Ping { payload: Bytes },
    Pong { payload: Bytes },
    Hello { version: u8 },
    Welcome,
    Bye { payload: Bytes },
}

impl Frame {
    #[inline]
    pub const fn kind(&self) -> FrameType {
        match self {
            Self::Open { .. } => FrameType::Open,
            Self::Data { .. } => FrameType::Data,
            Self::Close { .. } => FrameType::Close,
            Self::Window { .. } => FrameType::Window,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Hello { .. } => FrameType::Hello,
            Self::Welcome => FrameType::Welcome,
            Self::Bye { .. } => FrameType::Bye,
        }
    }

    #[inline]
    pub const fn stream_id(&self) -> u32 {
        match *self {
            Self::Open { stream_id }
            | Self::Data { stream_id, .. }
            | Self::Close { stream_id }
            | Self::Window { stream_id, .. } => stream_id,
            Self::Ping { .. }
            | Self::Pong { .. }
            | Self::Hello { .. }
            | Self::Welcome
            | Self::Bye { .. } => 0,
        }
    }

    #[inline]
    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE
            + match self {
                Self::Open { .. } | Self::Close { .. } | Self::Welcome => 0,
                Self::Data { payload, .. }
                | Self::Ping { payload }
                | Self::Pong { payload }
                | Self::Bye { payload } => payload.len(),
                Self::Window { .. } => WINDOW_PAYLOAD_SIZE,
                Self::Hello { .. } => 1,
            }
    }

    /// Encode this frame into `out`, validating wire bounds first.
    pub fn encode_into(
        &self,
        out: &mut BytesMut,
        limits: FrameLimits,
        dir: Direction,
    ) -> Result<(), FrameError> {
        let kind = self.kind();
        let stream_id = self.stream_id();
        if stream_id > MAX_STREAM_ID {
            return Err(FrameError::StreamIdOutOfRange(stream_id));
        }
        let payload_len = self.encoded_len() - HEADER_SIZE;
        check_header(
            kind,
            stream_id,
            payload_len as u32,
            limits.effective_payload(),
            dir,
        )?;
        if let Self::Window { delta: 0, .. } = self {
            return Err(FrameError::ZeroWindow);
        }
        if let Self::Hello { version } = *self
            && version != PROTOCOL_VERSION
        {
            return Err(FrameError::UnsupportedVersion(version));
        }

        out.reserve(HEADER_SIZE + payload_len);
        out.put_u8(kind as u8);
        out.put_u8(((stream_id >> 16) & 0xff) as u8);
        out.put_u8(((stream_id >> 8) & 0xff) as u8);
        out.put_u8((stream_id & 0xff) as u8);
        out.put_u32(payload_len as u32);

        match self {
            Self::Open { .. } | Self::Close { .. } | Self::Welcome => {}
            Self::Data { payload, .. }
            | Self::Ping { payload }
            | Self::Pong { payload }
            | Self::Bye { payload } => out.extend_from_slice(payload),
            Self::Window { delta, .. } => out.put_u32(*delta),
            Self::Hello { version } => out.put_u8(*version),
        }
        Ok(())
    }
}

/// Pre-encoded 8-byte `WELCOME` frame constant.
pub const WELCOME_WIRE: [u8; HEADER_SIZE] = [FrameType::Welcome as u8, 0, 0, 0, 0, 0, 0, 0];

/// Encode a single 8-byte header into `dst`.
#[inline]
pub fn encode_header(
    dst: &mut [u8; HEADER_SIZE],
    kind: FrameType,
    stream_id: u32,
    payload_len: u32,
) {
    dst[0] = kind as u8;
    dst[1] = ((stream_id >> 16) & 0xff) as u8;
    dst[2] = ((stream_id >> 8) & 0xff) as u8;
    dst[3] = (stream_id & 0xff) as u8;
    dst[4..8].copy_from_slice(&payload_len.to_be_bytes());
}

fn check_header(
    kind: FrameType,
    stream_id: u32,
    payload_len: u32,
    max_payload: usize,
    dir: Direction,
) -> Result<(), FrameError> {
    if !kind.allowed_in(dir) {
        return Err(FrameError::WrongDirection(kind, dir));
    }
    if kind.is_session_frame() && stream_id != 0 {
        return Err(FrameError::SessionFrameOnStream(kind, stream_id));
    }
    if !kind.is_session_frame() && stream_id == 0 {
        return Err(FrameError::StreamFrameOnZero(kind));
    }
    let len = payload_len as usize;
    if len > max_payload {
        return Err(FrameError::PayloadTooLarge {
            len,
            cap: max_payload,
        });
    }
    let (min_len, max_len) = kind.payload_bounds();
    if len < min_len || len > max_len {
        if kind == FrameType::Data && len == 0 {
            return Err(FrameError::EmptyData);
        }
        return Err(FrameError::PayloadLength { kind, len });
    }
    Ok(())
}

/// Validate a `POST /api/v1/session` body: must be EXACTLY one valid `HELLO(v1)` frame!
pub fn decode_hello(body: &[u8]) -> Result<(), FrameError> {
    if body.len() != HEADER_SIZE + 1 {
        return Err(FrameError::InvalidHelloBody);
    }
    let kind = FrameType::from_u8(body[0]).ok_or(FrameError::UnknownType(body[0]))?;
    if kind != FrameType::Hello {
        return Err(FrameError::InvalidHelloBody);
    }
    let stream_id = (u32::from(body[1]) << 16) | (u32::from(body[2]) << 8) | u32::from(body[3]);
    let payload_len = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    check_header(
        kind,
        stream_id,
        payload_len,
        MAX_PAYLOAD_SIZE,
        Direction::ClientToRelay,
    )?;
    if body[HEADER_SIZE] != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(body[HEADER_SIZE]));
    }
    Ok(())
}

/// Atomically decode and validate a whole carrier batch (`Bytes`), returning
/// `Ok(frames)` ONLY if every single frame passes validation!
///
/// Unpins tiny `DATA` slices (`4 * len < batch.len()`) so a 10-byte queued
/// payload never keeps a 2 MiB WebSocket message alive, while bulk `DATA`
/// frames remain zero-copy slices of `batch`!
pub fn decode_batch(
    batch: &Bytes,
    limits: FrameLimits,
    dir: Direction,
) -> Result<Vec<Frame>, FrameError> {
    let budget = limits.effective_batch_bytes();
    if batch.len() > budget {
        return Err(FrameError::BatchTooLarge {
            len: batch.len(),
            budget,
        });
    }
    let max_payload = limits.effective_payload();
    let mut frames = Vec::new();
    let mut off = 0usize;

    while off < batch.len() {
        if frames.len() >= MAX_FRAMES_PER_BATCH {
            return Err(FrameError::TooManyFrames);
        }
        if batch.len() - off < HEADER_SIZE {
            return Err(FrameError::PartialFrame);
        }

        let b = &batch[off..off + HEADER_SIZE];
        let kind = FrameType::from_u8(b[0]).ok_or(FrameError::UnknownType(b[0]))?;
        let stream_id = (u32::from(b[1]) << 16) | (u32::from(b[2]) << 8) | u32::from(b[3]);
        let payload_len = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);

        check_header(kind, stream_id, payload_len, max_payload, dir)?;

        let len = payload_len as usize;
        off += HEADER_SIZE;
        if batch.len() - off < len {
            return Err(FrameError::PartialFrame);
        }

        let slice_range = off..off + len;
        off += len;

        let frame = match kind {
            FrameType::Open => Frame::Open { stream_id },
            FrameType::Close => Frame::Close { stream_id },
            FrameType::Welcome => Frame::Welcome,
            FrameType::Hello => {
                let version = batch[slice_range.start];
                if version != PROTOCOL_VERSION {
                    return Err(FrameError::UnsupportedVersion(version));
                }
                Frame::Hello { version }
            }
            FrameType::Window => {
                let s = &batch[slice_range];
                let delta = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
                if delta == 0 {
                    return Err(FrameError::ZeroWindow);
                }
                Frame::Window { stream_id, delta }
            }
            FrameType::Data => {
                let payload = if len.saturating_mul(4) < batch.len() {
                    Bytes::copy_from_slice(&batch[slice_range])
                } else {
                    batch.slice(slice_range)
                };
                Frame::Data { stream_id, payload }
            }
            FrameType::Ping => Frame::Ping {
                payload: Bytes::copy_from_slice(&batch[slice_range]),
            },
            FrameType::Pong => Frame::Pong {
                payload: Bytes::copy_from_slice(&batch[slice_range]),
            },
            FrameType::Bye => Frame::Bye {
                payload: Bytes::copy_from_slice(&batch[slice_range]),
            },
        };
        frames.push(frame);
    }

    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_frame_v1_roundtrip_and_strict_rejects() {
        let mut buf = BytesMut::new();
        Frame::Open { stream_id: 7 }
            .encode_into(&mut buf, FrameLimits::default(), Direction::ClientToRelay)
            .unwrap();
        Frame::Data {
            stream_id: 7,
            payload: Bytes::from_static(b"hello"),
        }
        .encode_into(&mut buf, FrameLimits::default(), Direction::ClientToRelay)
        .unwrap();
        Frame::Window {
            stream_id: 7,
            delta: 4096,
        }
        .encode_into(&mut buf, FrameLimits::default(), Direction::ClientToRelay)
        .unwrap();

        let decoded = decode_batch(
            &buf.freeze(),
            FrameLimits::default(),
            Direction::ClientToRelay,
        )
        .unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], Frame::Open { stream_id: 7 });
        assert_eq!(
            decoded[1],
            Frame::Data {
                stream_id: 7,
                payload: Bytes::from_static(b"hello")
            }
        );
        assert_eq!(
            decoded[2],
            Frame::Window {
                stream_id: 7,
                delta: 4096
            }
        );

        // Zero WINDOW rejected
        let zero_win = Bytes::from_static(&[0x04, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0]);
        assert_eq!(
            decode_batch(&zero_win, FrameLimits::default(), Direction::ClientToRelay).unwrap_err(),
            FrameError::ZeroWindow
        );

        // Valid HELLO
        let hello = [0x10, 0, 0, 0, 0, 0, 0, 1, 0x01];
        decode_hello(&hello).unwrap();
        let bad_hello = [0x10, 0, 0, 0, 0, 0, 0, 1, 0x02];
        assert_eq!(
            decode_hello(&bad_hello).unwrap_err(),
            FrameError::UnsupportedVersion(0x02)
        );
    }
}
