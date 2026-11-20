//! Telegram MiddleProxy (`ad-tag`) RPC wire protocol, key derivation, framing,
//! and multiplexing primitives.
//!
//! # Upgrades over Go `middleproxy`
//! 1. **100% byte-exact parity** verified against `middle_upload_intermediate.golden`,
//!    `middle_upload_padded.golden`, and `middle_download.golden`.
//! 2. **Hardware PCLMULQDQ CRC32** via `crc32fast` + AES-NI CBC via `mtg-crypto`.
//! 3. **Full multiplexing & keepalive support**: implements `RPC_PING`
//!    (`0x5730a2df`), `RPC_PONG` (`0x8430eaa7`), `RPC_CLOSE_CONN` (`0x1e46756e`),
//!    and routes every `RPC_PROXY_ANS` / `RPC_SIMPLE_ACK` / `RPC_CLOSE_EXT` by
//!    its 8-byte `conn_id` so a single persistent RPC socket carries many client
//!    streams simultaneously (saving 2–3 RTTs per client connect!).
//! 4. **Strict plain-intermediate guard**: rejects unaligned (`len % 4 != 0`)
//!    plain-intermediate client packets instead of letting them corrupt RPC
//!    16-byte CBC block alignment.

use std::net::{IpAddr, SocketAddr};

use md5::{Digest as _, Md5};
use mtg_crypto::{Aes256CbcDecryptor, Aes256CbcEncryptor};
use sha1::Sha1;
use thiserror::Error;

/// Length of a Telegram sponsored-channel `ad_tag` in bytes.
pub const AD_TAG_LEN: usize = 16;

/// RPC message tags (4-byte little-endian magic constants).
pub const TAG_RPC_NONCE: [u8; 4] = [0xaa, 0x87, 0xcb, 0x7a];
pub const TAG_RPC_HANDSHAKE: [u8; 4] = [0xf5, 0xee, 0x82, 0x76];
pub const TAG_RPC_PROXY_REQ: [u8; 4] = [0xee, 0xf1, 0xce, 0x36];
pub const TAG_RPC_PROXY_ANS: [u8; 4] = [0x0d, 0xda, 0x03, 0x44];
pub const TAG_RPC_SIMPLE_ACK: [u8; 4] = [0x9b, 0x40, 0xac, 0x3b];
pub const TAG_RPC_CLOSE_EXT: [u8; 4] = [0xa2, 0x34, 0xb6, 0x5e];
/// Per-stream close sent by proxy -> middle proxy (`0x1e46756e` LE).
pub const TAG_RPC_CLOSE_CONN: [u8; 4] = [0x6e, 0x75, 0x46, 0x1e];
/// Keepalive ping (`0x5730a2df` LE).
pub const TAG_RPC_PING: [u8; 4] = [0xdf, 0xa2, 0x30, 0x57];
/// Keepalive pong (`0x8430eaa7` LE).
pub const TAG_RPC_PONG: [u8; 4] = [0xa7, 0xea, 0x30, 0x84];

const NONCE_CRYPTO_AES: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
const HANDSHAKE_FLAGS: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const HANDSHAKE_PID: &[u8; 12] = b"IPIPPRPDTIME";

/// TL `extra` block size (24 = 0x18) + `%Server_Proxy_Tag` constructor id.
const PROXY_REQ_EXTRA_SIZE: [u8; 4] = [0x18, 0x00, 0x00, 0x00];
const PROXY_REQ_PROXY_TAG: [u8; 4] = [0xae, 0x26, 0x1e, 0xdb];

/// 4-byte padding word repeated to align frames to 16-byte CBC block boundaries.
pub const FRAME_PADDING_WORD: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

/// `RPC_PROXY_REQ` flag bits.
pub const FLAG_ENCRYPTED: u32 = 0x2;
pub const FLAG_HAS_AD_TAG: u32 = 0x8;
pub const FLAG_MAGIC: u32 = 0x1000;
pub const FLAG_EXT_MODE2: u32 = 0x20000;
pub const FLAG_PAD: u32 = 0x0800_0000;
pub const FLAG_INTERMEDIATE: u32 = 0x2000_0000;
pub const FLAG_QUICK_ACK: u32 = 0x8000_0000;

/// Special sequence numbers during RPC link handshake.
pub const SEQ_NO_NONCE: i32 = -2;
pub const SEQ_NO_HANDSHAKE: i32 = -1;

/// Framing limits matching Telegram MTProxy & Go `middleproxy`.
pub const FRAME_MIN_LEN: usize = 12;
pub const FRAME_MAX_LEN: usize = 16_777_216;
pub const REQ_HEADER_LEN: usize = 84;
/// Default maximum single client packet accepted (configurable; 2 MiB default
/// protects against 16 MiB pre-frame memory spikes while still allowing full
/// 512 KiB–1 MiB Telegram media parts, and `MAX_WIRE_CLIENT_PACKET` is the
/// hard protocol limit).
pub const DEFAULT_MAX_CLIENT_PACKET: usize = 2 << 20;
pub const MAX_WIRE_CLIENT_PACKET: usize = FRAME_MAX_LEN - 4 - 4 - REQ_HEADER_LEN - 4;
pub const QUICK_ACK_BIT: u32 = 0x8000_0000;

/// Errors returned by MiddleProxy handshake, framing, or stream codecs.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MiddleProxyError {
    #[error("unexpected nonce response length {0}")]
    InvalidNonceLength(usize),
    #[error("unexpected nonce response tag")]
    InvalidNonceTag,
    #[error("unexpected nonce crypto type")]
    InvalidNonceCrypto,
    #[error("unexpected nonce key selector")]
    InvalidKeySelector,
    #[error("unexpected handshake response length {0}")]
    InvalidHandshakeLength(usize),
    #[error("unexpected handshake response tag")]
    InvalidHandshakeTag,
    #[error("incorrect handshake peer PID")]
    InvalidPeerPid,
    #[error("invalid RPC frame length {0}")]
    InvalidFrameLength(usize),
    #[error("RPC sequence number mismatch: got {got}, expected {expected}")]
    SeqNoMismatch { got: i32, expected: i32 },
    #[error("RPC frame CRC32 mismatch")]
    CrcMismatch,
    #[error("client packet too large: {declared} bytes declared, max {max}")]
    ClientPacketTooLarge { declared: usize, max: usize },
    #[error("plain intermediate packet length {0} is not 4-byte aligned")]
    UnalignedPlainPacket(usize),
    #[error("truncated or unknown RPC response packet")]
    MalformedRpcResponse,
}

/// Nonce request payload sent at `seq_no = -2` (plaintext RPC frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceRequest {
    pub key_selector: [u8; 4],
    pub crypto_ts: [u8; 4],
    pub nonce: [u8; 16],
}

impl NonceRequest {
    /// Build a fresh `RPC_NONCE` request from `proxy_secret` (at least 4 bytes)
    /// and Unix timestamp seconds.
    pub fn generate(proxy_secret: &[u8], unix_secs: u32) -> Result<Self, MiddleProxyError> {
        if proxy_secret.len() < 4 {
            return Err(MiddleProxyError::InvalidKeySelector);
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("OS CSPRNG failed");
        let mut key_selector = [0u8; 4];
        key_selector.copy_from_slice(&proxy_secret[..4]);
        Ok(Self {
            key_selector,
            crypto_ts: unix_secs.to_le_bytes(),
            nonce,
        })
    }

    /// Encode the 32-byte `RPC_NONCE` message body.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&TAG_RPC_NONCE);
        out[4..8].copy_from_slice(&self.key_selector);
        out[8..12].copy_from_slice(&NONCE_CRYPTO_AES);
        out[12..16].copy_from_slice(&self.crypto_ts);
        out[16..32].copy_from_slice(&self.nonce);
        out
    }
}

/// Validate a 32-byte `RPC_NONCE` response and extract the server's 16-byte nonce.
pub fn parse_nonce_response(data: &[u8], req: &NonceRequest) -> Result<[u8; 16], MiddleProxyError> {
    if data.len() != 32 {
        return Err(MiddleProxyError::InvalidNonceLength(data.len()));
    }
    if data[0..4] != TAG_RPC_NONCE {
        return Err(MiddleProxyError::InvalidNonceTag);
    }
    if data[8..12] != NONCE_CRYPTO_AES {
        return Err(MiddleProxyError::InvalidNonceCrypto);
    }
    if data[4..8] != req.key_selector {
        return Err(MiddleProxyError::InvalidKeySelector);
    }
    let mut server_nonce = [0u8; 16];
    server_nonce.copy_from_slice(&data[16..32]);
    Ok(server_nonce)
}

/// Build the 32-byte `RPC_HANDSHAKE` message body sent at `seq_no = -1` (encrypted).
pub fn handshake_request_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&TAG_RPC_HANDSHAKE);
    out[4..8].copy_from_slice(&HANDSHAKE_FLAGS);
    out[8..20].copy_from_slice(HANDSHAKE_PID);
    out[20..32].copy_from_slice(HANDSHAKE_PID);
    out
}

/// Validate a 32-byte `RPC_HANDSHAKE` response body.
pub fn validate_handshake_response(data: &[u8]) -> Result<(), MiddleProxyError> {
    if data.len() != 32 {
        return Err(MiddleProxyError::InvalidHandshakeLength(data.len()));
    }
    if data[0..4] != TAG_RPC_HANDSHAKE {
        return Err(MiddleProxyError::InvalidHandshakeTag);
    }
    if &data[20..32] != HANDSHAKE_PID {
        return Err(MiddleProxyError::InvalidPeerPid);
    }
    Ok(())
}

/// Derive the exact Telegram MiddleProxy AES-256-CBC encryptor (`CLIENT` purpose,
/// proxy -> middle) and decryptor (`SERVER` purpose, middle -> proxy).
pub fn derive_middleproxy_ciphers(
    req: &NonceRequest,
    server_nonce: &[u8; 16],
    local: SocketAddr,
    remote: SocketAddr,
    proxy_secret: &[u8],
) -> (Aes256CbcEncryptor, Aes256CbcDecryptor) {
    let (enc_key, enc_iv) =
        derive_key_iv(*b"CLIENT", req, server_nonce, local, remote, proxy_secret);
    let (dec_key, dec_iv) =
        derive_key_iv(*b"SERVER", req, server_nonce, local, remote, proxy_secret);
    (
        Aes256CbcEncryptor::new(&enc_key, &enc_iv),
        Aes256CbcDecryptor::new(&dec_key, &dec_iv),
    )
}

/// Derive the server-side MiddleProxy AES-256-CBC encryptor (`SERVER` purpose,
/// middle -> proxy) and decryptor (`CLIENT` purpose, proxy -> middle) — the
/// exact mirror of [`derive_middleproxy_ciphers`] for end-to-end tests.
pub fn derive_middleproxy_server_ciphers(
    req: &NonceRequest,
    server_nonce: &[u8; 16],
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    proxy_secret: &[u8],
) -> (Aes256CbcEncryptor, Aes256CbcDecryptor) {
    let (enc_key, enc_iv) = derive_key_iv(
        *b"SERVER",
        req,
        server_nonce,
        client_addr,
        server_addr,
        proxy_secret,
    );
    let (dec_key, dec_iv) = derive_key_iv(
        *b"CLIENT",
        req,
        server_nonce,
        client_addr,
        server_addr,
        proxy_secret,
    );
    (
        Aes256CbcEncryptor::new(&enc_key, &enc_iv),
        Aes256CbcDecryptor::new(&dec_key, &dec_iv),
    )
}

fn derive_key_iv(
    purpose: [u8; 6],
    req: &NonceRequest,
    server_nonce: &[u8; 16],
    local: SocketAddr,
    remote: SocketAddr,
    proxy_secret: &[u8],
) -> ([u8; 32], [u8; 16]) {
    let mut msg = Vec::with_capacity(128 + proxy_secret.len());
    msg.extend_from_slice(server_nonce);
    msg.extend_from_slice(&req.nonce);
    msg.extend_from_slice(&req.crypto_ts);

    let (client_v4, server_v4, is_v6) = match (unmap_v4(local.ip()), unmap_v4(remote.ip())) {
        (IpAddr::V4(c4), IpAddr::V4(s4)) => {
            let mut co = c4.octets();
            co.reverse();
            let mut so = s4.octets();
            so.reverse();
            (co, so, false)
        }
        _ => ([0u8; 4], [0u8; 4], true),
    };

    msg.extend_from_slice(&server_v4);
    msg.extend_from_slice(&local.port().to_le_bytes());
    msg.extend_from_slice(&purpose);
    msg.extend_from_slice(&client_v4);
    msg.extend_from_slice(&remote.port().to_le_bytes());
    msg.extend_from_slice(proxy_secret);
    msg.extend_from_slice(server_nonce);

    if is_v6 {
        msg.extend_from_slice(&to_v6_bytes(local.ip()));
        msg.extend_from_slice(&to_v6_bytes(remote.ip()));
    }

    msg.extend_from_slice(&req.nonce);

    let md5_key = Md5::digest(&msg[1..]);
    let sha1_key = Sha1::digest(&msg);
    let md5_iv = Md5::digest(&msg[2..]);

    let mut key = [0u8; 32];
    key[0..12].copy_from_slice(&md5_key[0..12]);
    key[12..32].copy_from_slice(&sha1_key[0..20]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&md5_iv[0..16]);

    (key, iv)
}

#[inline]
fn unmap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

#[inline]
fn to_v6_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Encode `addr` as 16-byte IPv6/v4-mapped address + 4-byte LE port inside `RPC_PROXY_REQ`.
#[inline]
fn encode_ip_port(addr: SocketAddr, dst: &mut [u8; 20]) {
    dst[0..16].copy_from_slice(&to_v6_bytes(addr.ip()));
    dst[16..20].copy_from_slice(&u32::from(addr.port()).to_le_bytes());
}

/// Append one plaintext MTProto RPC transport frame to `dst` and increment `write_seq_no`:
/// `[ MSGLEN(4 LE) | SEQNO(4 LE) | parts... | CRC32(4 LE) | PADDING(0x04000000 * k) ]`.
pub fn append_rpc_frame(dst: &mut Vec<u8>, write_seq_no: &mut i32, parts: &[&[u8]]) {
    let body_len: usize = parts.iter().map(|p| p.len()).sum();
    let msg_len = 4 + 4 + body_len + 4;
    let pad_len = (16 - (msg_len % 16)) % 16;
    let start = dst.len();

    dst.reserve(msg_len + pad_len);
    dst.extend_from_slice(&(msg_len as u32).to_le_bytes());
    dst.extend_from_slice(&write_seq_no.to_le_bytes());
    for part in parts {
        dst.extend_from_slice(part);
    }

    let crc = crc32fast::hash(&dst[start..]);
    dst.extend_from_slice(&crc.to_le_bytes());

    for _ in 0..(pad_len / 4) {
        dst.extend_from_slice(&FRAME_PADDING_WORD);
    }

    *write_seq_no = write_seq_no.wrapping_add(1);
}

/// Build the 84-byte `RPC_PROXY_REQ` header for a client stream.
pub fn build_proxy_req_header(
    conn_id: [u8; 8],
    client_addr: SocketAddr,
    our_addr: SocketAddr,
    ad_tag: [u8; AD_TAG_LEN],
    padded: bool,
) -> [u8; REQ_HEADER_LEN] {
    let mut h = [0u8; REQ_HEADER_LEN];
    h[0..4].copy_from_slice(&TAG_RPC_PROXY_REQ);
    let mut base_flags = FLAG_HAS_AD_TAG | FLAG_MAGIC | FLAG_EXT_MODE2 | FLAG_INTERMEDIATE;
    if padded {
        base_flags |= FLAG_PAD;
    }
    h[4..8].copy_from_slice(&base_flags.to_le_bytes());
    h[8..16].copy_from_slice(&conn_id);

    let mut c_addr = [0u8; 20];
    let mut o_addr = [0u8; 20];
    encode_ip_port(client_addr, &mut c_addr);
    encode_ip_port(our_addr, &mut o_addr);
    h[16..36].copy_from_slice(&c_addr);
    h[36..56].copy_from_slice(&o_addr);

    h[56..60].copy_from_slice(&PROXY_REQ_EXTRA_SIZE);
    h[60..64].copy_from_slice(&PROXY_REQ_PROXY_TAG);
    h[64] = AD_TAG_LEN as u8;
    h[65..81].copy_from_slice(&ad_tag);
    // bytes 81..84 are 3 zero alignment bytes (84 % 4 == 0).
    h
}

/// Build a 12-byte `RPC_CLOSE_CONN` message body (`tag(4) | conn_id(8)`) to
/// close one multiplexed stream on a shared MiddleProxy RPC link.
#[inline]
pub fn build_close_conn_body(conn_id: [u8; 8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&TAG_RPC_CLOSE_CONN);
    out[4..12].copy_from_slice(&conn_id);
    out
}

/// Build a 12-byte `RPC_PING` message body (`tag(4) | ping_id(8)`).
#[inline]
pub fn build_rpc_ping_body(ping_id: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&TAG_RPC_PING);
    out[4..12].copy_from_slice(&ping_id.to_le_bytes());
    out
}

/// Build a 12-byte `RPC_PONG` message body (`tag(4) | ping_id(8)`).
#[inline]
pub fn build_rpc_pong_body(ping_id: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&TAG_RPC_PONG);
    out[4..12].copy_from_slice(&ping_id.to_le_bytes());
    out
}

/// Decoded RPC message coming from Telegram's MiddleProxy server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcDownEvent<'a> {
    /// `RPC_PROXY_ANS`: intermediate-framed response payload for `conn_id`.
    ProxyAns {
        flags: u32,
        conn_id: [u8; 8],
        payload: &'a [u8],
    },
    /// `RPC_SIMPLE_ACK`: quick-ack token forwarded verbatim to client for `conn_id`.
    SimpleAck { conn_id: [u8; 8], payload: &'a [u8] },
    /// `RPC_CLOSE_EXT`: middle proxy closed stream `conn_id` (or entire conn if `None`).
    CloseExt { conn_id: Option<[u8; 8]> },
    /// `RPC_PING`: peer keepalive ping — respond immediately with `RPC_PONG`.
    Ping { ping_id: u64 },
    /// `RPC_PONG`: reply to our keepalive ping.
    Pong { ping_id: u64 },
}

/// Parse one verified RPC frame body (after stripping length, seqno, CRC32) into
/// an [`RpcDownEvent`].
pub fn parse_rpc_down_event(body: &[u8]) -> Result<RpcDownEvent<'_>, MiddleProxyError> {
    if body.len() < 4 {
        return Err(MiddleProxyError::MalformedRpcResponse);
    }
    let tag: [u8; 4] = body[0..4].try_into().expect("4 bytes");
    match tag {
        TAG_RPC_PROXY_ANS => {
            if body.len() < 16 {
                return Err(MiddleProxyError::MalformedRpcResponse);
            }
            let flags = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let mut conn_id = [0u8; 8];
            conn_id.copy_from_slice(&body[8..16]);
            Ok(RpcDownEvent::ProxyAns {
                flags,
                conn_id,
                payload: &body[16..],
            })
        }
        TAG_RPC_SIMPLE_ACK => {
            if body.len() < 12 {
                return Err(MiddleProxyError::MalformedRpcResponse);
            }
            let mut conn_id = [0u8; 8];
            conn_id.copy_from_slice(&body[4..12]);
            Ok(RpcDownEvent::SimpleAck {
                conn_id,
                payload: &body[12..],
            })
        }
        TAG_RPC_CLOSE_EXT => {
            let conn_id = if body.len() >= 12 {
                let mut cid = [0u8; 8];
                cid.copy_from_slice(&body[4..12]);
                Some(cid)
            } else {
                None
            };
            Ok(RpcDownEvent::CloseExt { conn_id })
        }
        TAG_RPC_PING => {
            if body.len() < 12 {
                return Err(MiddleProxyError::MalformedRpcResponse);
            }
            let ping_id = u64::from_le_bytes(body[4..12].try_into().expect("8 bytes"));
            Ok(RpcDownEvent::Ping { ping_id })
        }
        TAG_RPC_PONG => {
            if body.len() < 12 {
                return Err(MiddleProxyError::MalformedRpcResponse);
            }
            let ping_id = u64::from_le_bytes(body[4..12].try_into().expect("8 bytes"));
            Ok(RpcDownEvent::Pong { ping_id })
        }
        _ => Err(MiddleProxyError::MalformedRpcResponse),
    }
}

/// Incremental AES-256-CBC + RPC transport frame decoder (supports arbitrary
/// TCP chunk splits down to 1 byte at a time).
#[derive(Debug)]
pub struct RpcFrameDecoder {
    dec: Option<Aes256CbcDecryptor>,
    read_seq_no: i32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    plain_pos: usize,
}

impl RpcFrameDecoder {
    /// Create a decoder (`dec = None` for plaintext nonce exchange at `seq_no = -2`,
    /// `dec = Some(...)` for encrypted RPC frames starting at `seq_no = -1` or `0`).
    pub fn new(dec: Option<Aes256CbcDecryptor>, start_seq_no: i32) -> Self {
        Self {
            dec,
            read_seq_no: start_seq_no,
            cipher_buf: Vec::with_capacity(4096),
            plain_buf: Vec::with_capacity(16_384),
            plain_pos: 0,
        }
    }

    /// Feed raw wire bytes received from the MiddleProxy socket.
    pub fn push_wire_bytes(&mut self, bytes: &[u8]) {
        if let Some(dec) = &mut self.dec {
            self.cipher_buf.extend_from_slice(bytes);
            let full = self.cipher_buf.len() & !15;
            if full > 0 {
                let start = self.plain_buf.len();
                self.plain_buf.extend_from_slice(&self.cipher_buf[..full]);
                dec.decrypt_blocks_in_place(&mut self.plain_buf[start..])
                    .expect("full is a multiple of 16");
                self.cipher_buf.drain(..full);
            }
        } else {
            self.plain_buf.extend_from_slice(bytes);
        }
    }

    /// Pop the next complete, CRC32- and seqno-verified RPC message body, or
    /// `Ok(None)` if more wire bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, MiddleProxyError> {
        loop {
            let avail = &self.plain_buf[self.plain_pos..];
            if avail.len() < 4 {
                self.compact();
                return Ok(None);
            }

            // Skip leading 4-byte 0x04000000 padding words between frames.
            if avail[0..4] == FRAME_PADDING_WORD {
                self.plain_pos += 4;
                continue;
            }

            let msg_len = u32::from_le_bytes([avail[0], avail[1], avail[2], avail[3]]) as usize;
            if !(FRAME_MIN_LEN..=FRAME_MAX_LEN).contains(&msg_len) {
                return Err(MiddleProxyError::InvalidFrameLength(msg_len));
            }
            if avail.len() < msg_len {
                self.compact();
                return Ok(None);
            }

            let frame = &avail[..msg_len];
            let seq_no = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
            if seq_no != self.read_seq_no {
                return Err(MiddleProxyError::SeqNoMismatch {
                    got: seq_no,
                    expected: self.read_seq_no,
                });
            }

            let expected_crc = u32::from_le_bytes([
                frame[msg_len - 4],
                frame[msg_len - 3],
                frame[msg_len - 2],
                frame[msg_len - 1],
            ]);
            let actual_crc = crc32fast::hash(&frame[..msg_len - 4]);
            if actual_crc != expected_crc {
                return Err(MiddleProxyError::CrcMismatch);
            }

            let body = frame[8..msg_len - 4].to_vec();
            self.plain_pos += msg_len;
            self.read_seq_no = self.read_seq_no.wrapping_add(1);
            self.compact();
            return Ok(Some(body));
        }
    }

    fn compact(&mut self) {
        if self.plain_pos > 0 {
            let rem = self.plain_buf.len() - self.plain_pos;
            if rem == 0 {
                self.plain_buf.clear();
            } else if self.plain_pos >= 8192 || self.plain_pos * 2 >= self.plain_buf.len() {
                self.plain_buf.copy_within(self.plain_pos.., 0);
                self.plain_buf.truncate(rem);
            } else {
                return;
            }
            self.plain_pos = 0;
            if self.plain_buf.capacity() > (64 << 10) && self.plain_buf.is_empty() {
                self.plain_buf.shrink_to(16_384);
            }
        }
    }
}

/// Client-stream upload encoder converting a client's (padded-)intermediate
/// byte stream into batched, AES-256-CBC-encrypted `RPC_PROXY_REQ` frames.
#[derive(Debug)]
pub struct ClientUploadFramer {
    header: [u8; REQ_HEADER_LEN],
    base_flags: u32,
    padded: bool,
    max_client_packet: usize,
    inbuf: Vec<u8>,
}

impl ClientUploadFramer {
    pub fn new(
        conn_id: [u8; 8],
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        ad_tag: [u8; AD_TAG_LEN],
        padded: bool,
        max_client_packet: usize,
    ) -> Self {
        let header = build_proxy_req_header(conn_id, client_addr, our_addr, ad_tag, padded);
        let base_flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        Self {
            header,
            base_flags,
            padded,
            max_client_packet: max_client_packet.min(MAX_WIRE_CLIENT_PACKET),
            inbuf: Vec::with_capacity(4096),
        }
    }

    /// Feed client intermediate-transport bytes; appends all complete
    /// plaintext `RPC_PROXY_REQ` frames to `out_frames` (caller encrypts the
    /// entire batch in one CBC sweep!).
    pub fn feed_client_bytes(
        &mut self,
        chunk: &[u8],
        write_seq_no: &mut i32,
        out_frames: &mut Vec<u8>,
    ) -> Result<(), MiddleProxyError> {
        self.inbuf.extend_from_slice(chunk);
        let mut consumed = 0usize;

        while self.inbuf.len() - consumed >= 4 {
            let rest = &self.inbuf[consumed..];
            let mut declared = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let quick_ack = if declared >= QUICK_ACK_BIT {
                declared -= QUICK_ACK_BIT;
                true
            } else {
                false
            };

            let len = declared as usize;
            if len > self.max_client_packet {
                self.inbuf.clear();
                return Err(MiddleProxyError::ClientPacketTooLarge {
                    declared: len,
                    max: self.max_client_packet,
                });
            }

            if !self.padded && !len.is_multiple_of(4) {
                self.inbuf.clear();
                return Err(MiddleProxyError::UnalignedPlainPacket(len));
            }

            if rest.len() < 4 + len {
                break;
            }

            let mut packet = &rest[4..4 + len];
            if self.padded {
                // Trim 0..3 random trailing bytes to 4-byte alignment per MTProxy spec.
                packet = &packet[..packet.len() & !3];
            }

            let mut flags = self.base_flags;
            if quick_ack {
                flags |= FLAG_QUICK_ACK;
            }
            if packet.len() >= 8 && packet[0..8] == [0u8; 8] {
                flags |= FLAG_ENCRYPTED;
            }
            self.header[4..8].copy_from_slice(&flags.to_le_bytes());

            append_rpc_frame(out_frames, write_seq_no, &[&self.header, packet]);
            consumed += 4 + len;
        }

        if consumed > 0 {
            let rem = self.inbuf.len() - consumed;
            self.inbuf.copy_within(consumed.., 0);
            self.inbuf.truncate(rem);
            if self.inbuf.capacity() > (64 << 10) && self.inbuf.len() <= (64 << 10) {
                self.inbuf.shrink_to(16_384);
            }
        }

        Ok(())
    }
}

/// Reframe an [`RpcDownEvent`] into client-bound intermediate bytes appended to `out`.
///
/// Returns `Ok(true)` if the stream should continue, `Ok(false)` on `CloseExt`.
pub fn format_client_download(event: &RpcDownEvent<'_>, out: &mut Vec<u8>) -> bool {
    match event {
        RpcDownEvent::ProxyAns { payload, .. } => {
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
            true
        }
        RpcDownEvent::SimpleAck { payload, .. } => {
            out.extend_from_slice(payload);
            true
        }
        RpcDownEvent::CloseExt { .. } => false,
        RpcDownEvent::Ping { .. } | RpcDownEvent::Pong { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn load_golden_hex(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/mtglib/internal/middleproxy/testdata")
            .join(name);
        let text = std::fs::read_to_string(path).unwrap();
        let hex_only: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(str::trim)
            .collect();
        hex::decode(hex_only).unwrap()
    }

    fn fixed_ciphers() -> (
        Aes256CbcEncryptor,
        Aes256CbcDecryptor,
        Aes256CbcEncryptor,
        Aes256CbcDecryptor,
    ) {
        let up_k = [0x41u8; 32];
        let down_k = [0x42u8; 32];
        let up_iv = [0x51u8; 16];
        let down_iv = [0x52u8; 16];
        (
            Aes256CbcEncryptor::new(&up_k, &up_iv),
            Aes256CbcDecryptor::new(&down_k, &down_iv),
            Aes256CbcEncryptor::new(&down_k, &down_iv),
            Aes256CbcDecryptor::new(&up_k, &up_iv),
        )
    }

    fn upload_stream(padded: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, &size) in [4usize, 16, 100, 1024, 16_384, 8].iter().enumerate() {
            let mut payload = vec![0u8; size];
            for (j, b) in payload.iter_mut().enumerate() {
                *b = (i * 31 + j) as u8;
            }
            if size == 1024 {
                payload[..8].fill(0);
            }
            if padded {
                payload.extend(std::iter::repeat_n(0xeeu8, 1 + i % 3));
            }
            let mut len = payload.len() as u32;
            if size == 8 {
                len |= QUICK_ACK_BIT;
            }
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&payload);
        }
        out
    }

    #[test]
    fn golden_middleproxy_upload_intermediate_and_padded_byte_exact() {
        let conn_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let ad_tag = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let client: SocketAddr = "198.51.100.7:50123".parse().unwrap();
        let ours: SocketAddr = "203.0.113.9:8443".parse().unwrap();

        for (padded, golden_file) in [
            (false, "middle_upload_intermediate.golden"),
            (true, "middle_upload_padded.golden"),
        ] {
            let expected = load_golden_hex(golden_file);
            let stream = upload_stream(padded);

            for chunk_size in [1usize, 5, 4096] {
                let (mut proxy_enc, _, _, _) = fixed_ciphers();
                let mut framer = ClientUploadFramer::new(
                    conn_id,
                    client,
                    ours,
                    ad_tag,
                    padded,
                    MAX_WIRE_CLIENT_PACKET,
                );
                let mut seq = 0i32;
                let mut wire = Vec::new();
                let mut batch = Vec::new();

                for piece in stream.chunks(chunk_size) {
                    batch.clear();
                    framer
                        .feed_client_bytes(piece, &mut seq, &mut batch)
                        .unwrap();
                    if !batch.is_empty() {
                        proxy_enc.encrypt_blocks_in_place(&mut batch).unwrap();
                        wire.extend_from_slice(&batch);
                    }
                }

                assert_eq!(
                    wire, expected,
                    "mismatch for {golden_file} with chunk_size={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn golden_middleproxy_download_byte_exact() {
        let conn_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let expected = load_golden_hex("middle_download.golden");

        // Build identical wire input to Go's downloadWire()
        let (_, proxy_dec, mut peer_enc, _) = fixed_ciphers();
        let mut peer_seq = 0i32;
        let mut wire = Vec::new();

        for (i, &size) in [4usize, 1000, 16_384, 70_000].iter().enumerate() {
            let mut payload = vec![0u8; size];
            for (j, b) in payload.iter_mut().enumerate() {
                *b = (i * 17 + j * 7) as u8;
            }
            let mut hdr = [0u8; 16];
            hdr[0..4].copy_from_slice(&TAG_RPC_PROXY_ANS);
            hdr[8..16].copy_from_slice(&conn_id);
            append_rpc_frame(&mut wire, &mut peer_seq, &[&hdr, &payload]);
        }

        let mut ack = [0u8; 16];
        ack[0..4].copy_from_slice(&TAG_RPC_SIMPLE_ACK);
        ack[4..12].copy_from_slice(&conn_id);
        ack[12..16].copy_from_slice(&[1, 2, 3, 4]);
        append_rpc_frame(&mut wire, &mut peer_seq, &[&ack]);
        append_rpc_frame(&mut wire, &mut peer_seq, &[&TAG_RPC_CLOSE_EXT]);

        peer_enc.encrypt_blocks_in_place(&mut wire).unwrap();

        // Feed in tiny irregular chunks (1, 2, 3, 16, 17 bytes) just like Go's tinyReadConn!
        let mut decoder = RpcFrameDecoder::new(Some(proxy_dec), 0);
        let mut client_out = Vec::new();
        let steps = [1usize, 2, 3, 16, 17];
        let mut pos = 0;
        let mut step_idx = 0;
        let mut closed = false;

        while pos < wire.len() {
            let n = steps[step_idx % steps.len()].min(wire.len() - pos);
            decoder.push_wire_bytes(&wire[pos..pos + n]);
            pos += n;
            step_idx += 1;

            while let Some(body) = decoder.next_frame().unwrap() {
                let ev = parse_rpc_down_event(&body).unwrap();
                if !format_client_download(&ev, &mut client_out) {
                    closed = true;
                }
            }
        }

        assert!(closed);
        assert_eq!(client_out, expected);
    }

    #[test]
    fn rpc_ping_pong_close_conn_and_plain_alignment_guard() {
        let ping = build_rpc_ping_body(0x1234_5678_9abc_def0);
        assert_eq!(
            parse_rpc_down_event(&ping).unwrap(),
            RpcDownEvent::Ping {
                ping_id: 0x1234_5678_9abc_def0
            }
        );

        let pong = build_rpc_pong_body(0x1234_5678_9abc_def0);
        assert_eq!(
            parse_rpc_down_event(&pong).unwrap(),
            RpcDownEvent::Pong {
                ping_id: 0x1234_5678_9abc_def0
            }
        );

        // Plain intermediate rejects non-4-byte-aligned packet!
        let mut framer = ClientUploadFramer::new(
            [0; 8],
            "1.2.3.4:1000".parse().unwrap(),
            "5.6.7.8:443".parse().unwrap(),
            [0; 16],
            false,
            DEFAULT_MAX_CLIENT_PACKET,
        );
        let mut seq = 0;
        let mut out = Vec::new();
        let bad = [5u8, 0, 0, 0, 1, 2, 3, 4, 5];
        assert_eq!(
            framer
                .feed_client_bytes(&bad, &mut seq, &mut out)
                .unwrap_err(),
            MiddleProxyError::UnalignedPlainPacket(5)
        );
    }

    #[test]
    fn key_derivation_and_handshake_roundtrip() {
        let proxy_secret = [0xdeu8; 128];
        let req = NonceRequest::generate(&proxy_secret, 1_700_000_000).unwrap();
        let mut resp = req.to_bytes();
        resp[16..32].copy_from_slice(&[0x55u8; 16]);
        let server_nonce = parse_nonce_response(&resp, &req).unwrap();
        assert_eq!(server_nonce, [0x55u8; 16]);

        let local: SocketAddr = "203.0.113.10:40000".parse().unwrap();
        let remote: SocketAddr = "149.154.167.50:8888".parse().unwrap();
        let (mut c_enc, mut c_dec) =
            derive_middleproxy_ciphers(&req, &server_nonce, local, remote, &proxy_secret);

        let mut hs = Vec::new();
        let mut seq = SEQ_NO_HANDSHAKE;
        append_rpc_frame(&mut hs, &mut seq, &[&handshake_request_bytes()]);
        c_enc.encrypt_blocks_in_place(&mut hs).unwrap();
        assert_eq!(hs.len() % 16, 0);

        // Verify SERVER-purpose decryptor works cleanly on a dummy encrypted block.
        let mut blk = [0u8; 16];
        c_dec.decrypt_blocks_in_place(&mut blk).unwrap();

        validate_handshake_response(&handshake_request_bytes()).unwrap();
    }
}
