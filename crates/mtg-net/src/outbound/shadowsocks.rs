//! Hardware-accelerated **Shadowsocks AEAD-2022 (SIP022)** & **Classic AEAD
//! (SIP004/SIP007)** outbound transport (`ss://`).
//!
//! Supported ciphers (all powered by `ring::aead` hardware AES-NI/CLMUL/ARMv8
//! Crypto & AVX2/NEON ChaCha20 + `blake3` KDF):
//! - **AEAD-2022 (SIP022):**
//!   - `2022-blake3-aes-128-gcm` (16 B PSK/salt + optional multi-user EIH)
//!   - `2022-blake3-aes-256-gcm` (32 B PSK/salt + optional multi-user EIH)
//!   - `2022-blake3-chacha20-poly1305` (32 B PSK/salt)
//! - **Classic AEAD:**
//!   - `aes-256-gcm` (32 B key/salt, `EVP_BytesToKey` + `HKDF-SHA1("ss-subkey")`)
//!   - `aes-128-gcm` (16 B key/salt)
//!   - `chacha20-poly1305` (32 B key/salt)
//!
//! URL formats supported:
//! - SIP002: `ss://<base64(method:password)>@host:port`
//! - Plain/AEAD-2022: `ss://<method>:<base64-psk[:base64-psk2]>@host:port`
//!   (percent-encoded `%3A`/`%2B`/`%2F`/`%3D` automatically decoded!)

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt as _, KeyInit as _};
use base64::Engine as _;
use md5::{Digest as _, Md5};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::stream::{DialResult, OutboundStream, TunnelStream};
use super::unix::encode_socks5_addr;
use super::{OutboundError, OutboundTarget, OutboundTransport};
use crate::dns::DnsResolver;
use crate::sockopts::{OutboundBindOptions, SocketConfig, connect_tcp_tuned_bound};
use crate::timer::coarse_now_ns;

const AEAD_TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CLASSIC_MAX_CHUNK: usize = 0x3FFF; // 16,383 bytes per SIP004
const SS2022_MAX_CHUNK: usize = 0xFFFF; // 65,535 bytes per SIP022
const SS2022_TYPE_CLIENT: u8 = 0x00;
const SS2022_TYPE_SERVER: u8 = 0x01;
const SS2022_MAX_TIME_DIFF_SECS: u64 = 30;
const SS2022_SESSION_SUBKEY_CTX: &str = "shadowsocks 2022 session subkey";
const SS2022_IDENTITY_SUBKEY_CTX: &str = "shadowsocks 2022 identity subkey";

/// Supported Shadowsocks cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    Aes128Gcm2022,
    Aes256Gcm2022,
    ChaCha20Poly1305_2022,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SsCipher {
    pub fn parse(method: &str) -> Result<Self, OutboundError> {
        match method.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm2022),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm2022),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly1305_2022),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            other => Err(OutboundError::InvalidConfig(format!(
                "unsupported Shadowsocks cipher: {other:?}"
            ))),
        }
    }

    #[inline]
    pub const fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::ChaCha20Poly1305_2022
        )
    }

    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm2022 | Self::Aes128Gcm => 16,
            Self::Aes256Gcm2022
            | Self::ChaCha20Poly1305_2022
            | Self::Aes256Gcm
            | Self::ChaCha20Poly1305 => 32,
        }
    }

    #[inline]
    pub const fn max_chunk(self) -> usize {
        if self.is_2022() {
            SS2022_MAX_CHUNK
        } else {
            CLASSIC_MAX_CHUNK
        }
    }

    #[inline]
    pub const fn protocol_name(self) -> &'static str {
        if self.is_2022() { "ss-2022" } else { "ss-aead" }
    }

    #[inline]
    fn ring_alg(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm2022 | Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm2022 | Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305_2022 | Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

#[derive(Clone)]
struct SsKeyMaterial {
    cipher: SsCipher,
    /// Primary session key (derived master key for classic, final PSK for 2022).
    primary_key: Zeroizing<Vec<u8>>,
    /// Optional SIP022 Extensible Identity Header PSK chain (parent PSKs before user PSK).
    eih_psks: Vec<Zeroizing<Vec<u8>>>,
}

impl SsKeyMaterial {
    fn from_password(cipher: SsCipher, password: &str) -> Result<Self, OutboundError> {
        let key_len = cipher.key_len();
        if cipher.is_2022() {
            let parts: Vec<&str> = password.split(':').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                return Err(OutboundError::InvalidConfig(
                    "Shadowsocks 2022 requires base64 PSK".into(),
                ));
            }
            let mut decoded = Vec::with_capacity(parts.len());
            for part in parts {
                let raw = decode_b64_flexible(part).map_err(|e| {
                    OutboundError::InvalidConfig(format!(
                        "invalid Shadowsocks 2022 base64 PSK: {e}"
                    ))
                })?;
                if raw.len() != key_len {
                    return Err(OutboundError::InvalidConfig(format!(
                        "Shadowsocks 2022 PSK length mismatch: got {} bytes, expected {key_len}",
                        raw.len()
                    )));
                }
                decoded.push(Zeroizing::new(raw));
            }
            if decoded.len() > 1 && cipher == SsCipher::ChaCha20Poly1305_2022 {
                return Err(OutboundError::InvalidConfig(
                    "multi-user EIH is only supported with 2022-blake3-aes-*-gcm".into(),
                ));
            }
            let primary_key = decoded.pop().expect("non-empty");
            Ok(Self {
                cipher,
                primary_key,
                eih_psks: decoded,
            })
        } else {
            let master = evp_bytes_to_key(password.as_bytes(), key_len);
            Ok(Self {
                cipher,
                primary_key: Zeroizing::new(master),
                eih_psks: Vec::new(),
            })
        }
    }

    fn derive_subkey(&self, salt: &[u8]) -> Result<LessSafeKey, OutboundError> {
        let key_len = self.cipher.key_len();
        let mut subkey = Zeroizing::new(vec![0u8; key_len]);
        if self.cipher.is_2022() {
            let mut ikm = Zeroizing::new(Vec::with_capacity(self.primary_key.len() + salt.len()));
            ikm.extend_from_slice(&self.primary_key);
            ikm.extend_from_slice(salt);
            let derived = blake3::derive_key(SS2022_SESSION_SUBKEY_CTX, &ikm);
            subkey.copy_from_slice(&derived[..key_len]);
        } else {
            let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
                .extract(&self.primary_key);
            let okm = prk
                .expand(&[b"ss-subkey"], RawKeyLen(key_len))
                .map_err(|_| OutboundError::Protocol("HKDF-SHA1 expand failed".into()))?;
            okm.fill(&mut subkey)
                .map_err(|_| OutboundError::Protocol("HKDF-SHA1 fill failed".into()))?;
        }
        let unbound = UnboundKey::new(self.cipher.ring_alg(), &subkey)
            .map_err(|_| OutboundError::Protocol("invalid AEAD subkey".into()))?;
        Ok(LessSafeKey::new(unbound))
    }

    /// Build SIP022 Extensible Identity Headers (16 B each) when multi-user PSKs are configured.
    fn build_eih(&self, salt: &[u8]) -> Vec<u8> {
        if self.eih_psks.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.eih_psks.len() * 16);
        let mut chain: Vec<&[u8]> = self.eih_psks.iter().map(|k| k.as_slice()).collect();
        chain.push(self.primary_key.as_slice());

        for win in chain.windows(2) {
            let ipsk = win[0];
            let next_psk = win[1];
            let next_hash = blake3::hash(next_psk);
            let mut block = [0u8; 16];
            block.copy_from_slice(&next_hash.as_bytes()[..16]);

            let mut mat = Zeroizing::new(Vec::with_capacity(ipsk.len() + salt.len()));
            mat.extend_from_slice(ipsk);
            mat.extend_from_slice(salt);
            let subkey = blake3::derive_key(SS2022_IDENTITY_SUBKEY_CTX, &mat);

            match self.cipher {
                SsCipher::Aes128Gcm2022 => {
                    let c = aes::Aes128::new_from_slice(&subkey[..16]).expect("16B AES-128 key");
                    c.encrypt_block((&mut block).into());
                }
                SsCipher::Aes256Gcm2022 => {
                    let c = aes::Aes256::new_from_slice(&subkey[..32]).expect("32B AES-256 key");
                    c.encrypt_block((&mut block).into());
                }
                _ => {}
            }
            out.extend_from_slice(&block);
        }
        out
    }
}

struct RawKeyLen(usize);

impl hkdf::KeyType for RawKeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// OpenSSL `EVP_BytesToKey` (MD5, no salt) used by classic Shadowsocks AEAD.
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Option<[u8; 16]> = None;
    while out.len() < key_len {
        let mut h = Md5::new();
        if let Some(p) = prev {
            h.update(p);
        }
        h.update(password);
        let digest: [u8; 16] = h.finalize().into();
        out.extend_from_slice(&digest);
        prev = Some(digest);
    }
    out.truncate(key_len);
    out
}

fn decode_b64_flexible(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let clean = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(clean))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
fn next_nonce(counter: &mut u64) -> Nonce {
    let mut raw = [0u8; NONCE_LEN];
    raw[..8].copy_from_slice(&counter.to_le_bytes());
    *counter = counter.wrapping_add(1);
    Nonce::assume_unique_for_key(raw)
}

#[inline]
fn seal_in_place(key: &LessSafeKey, counter: &mut u64, buf: &mut Vec<u8>) -> io::Result<()> {
    let nonce = next_nonce(counter);
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::empty(), buf)
        .map_err(|_| io::Error::other("Shadowsocks AEAD seal failed"))?;
    buf.extend_from_slice(tag.as_ref());
    Ok(())
}

#[inline]
fn open_in_place<'a>(
    key: &LessSafeKey,
    counter: &mut u64,
    buf: &'a mut [u8],
) -> io::Result<&'a [u8]> {
    let nonce = next_nonce(counter);
    let plain = key
        .open_in_place(nonce, Aad::empty(), buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Shadowsocks AEAD open failed"))?;
    Ok(plain)
}

/// Outbound Shadowsocks (`ss://`) transport supporting both AEAD-2022 and Classic AEAD.
pub struct ShadowsocksTransport {
    name: Arc<str>,
    server_host: String,
    server_port: u16,
    keys: Arc<SsKeyMaterial>,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
    redacted: String,
}

impl fmt::Debug for ShadowsocksTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksTransport")
            .field("name", &self.name)
            .field("cipher", &self.keys.cipher)
            .field("endpoint", &self.redacted)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksTransport {
    /// Parse a Shadowsocks `ss://` URL (both SIP002 base64 userinfo and plain
    /// `method:psk@host:port`).
    pub fn parse(
        name: Arc<str>,
        raw_url: &str,
        dns: Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        bind: OutboundBindOptions,
    ) -> Result<Self, OutboundError> {
        let rest = raw_url.strip_prefix("ss://").ok_or_else(|| {
            OutboundError::InvalidConfig(format!("expected ss:// scheme for {name:?}"))
        })?;
        // Strip optional `#fragment` and `?plugin=...` query.
        let without_frag = rest.split('#').next().unwrap_or("");
        let without_query = without_frag.split('?').next().unwrap_or("");

        // Handle legacy whole-URL base64 (`ss://<base64(method:pass@host:port)>`)
        // as well as SIP002 (`ss://<base64(method:pass)>@host:port`) and plain
        // (`ss://2022-blake3-aes-256-gcm:<psk>@host:port`).
        let (userinfo_raw, hostport) = if let Some((u, hp)) = without_query.rsplit_once('@') {
            (u.to_owned(), hp.to_owned())
        } else {
            let decoded = decode_b64_flexible(without_query).map_err(|e| {
                OutboundError::InvalidConfig(format!("invalid Shadowsocks URL encoding: {e}"))
            })?;
            let text = String::from_utf8(decoded).map_err(|_| {
                OutboundError::InvalidConfig("invalid UTF-8 in Shadowsocks URL".into())
            })?;
            let (u, hp) = text.rsplit_once('@').ok_or_else(|| {
                OutboundError::InvalidConfig("Shadowsocks URL missing @host:port".into())
            })?;
            (u.to_owned(), hp.to_owned())
        };

        let userinfo_decoded = if userinfo_raw.contains(':')
            || userinfo_raw.contains("%3A")
            || userinfo_raw.contains("%3a")
        {
            percent_decode(&userinfo_raw)
        } else {
            let bytes = decode_b64_flexible(&userinfo_raw).map_err(|e| {
                OutboundError::InvalidConfig(format!("invalid SIP002 userinfo base64: {e}"))
            })?;
            String::from_utf8(bytes).map_err(|_| {
                OutboundError::InvalidConfig("invalid UTF-8 in SIP002 userinfo".into())
            })?
        };

        let (method, password) = userinfo_decoded.split_once(':').ok_or_else(|| {
            OutboundError::InvalidConfig("Shadowsocks userinfo missing method:password".into())
        })?;
        let cipher = SsCipher::parse(method)?;
        let keys = Arc::new(SsKeyMaterial::from_password(cipher, password)?);

        let (server_host, server_port) = super::protocols::split_host_port_strict(&hostport)
            .ok_or_else(|| {
                OutboundError::InvalidConfig(format!(
                    "Shadowsocks outbound {name:?} missing valid host:port"
                ))
            })?;

        let redacted = format!("ss://***@{server_host}:{server_port}");
        Ok(Self {
            name,
            server_host,
            server_port,
            keys,
            dns,
            sock_cfg,
            bind,
            redacted,
        })
    }
}

impl OutboundTransport for ShadowsocksTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        self.keys.cipher.protocol_name()
    }

    fn redacted_endpoint(&self) -> &str {
        &self.redacted
    }

    fn dial<'a>(
        &'a self,
        target: &'a OutboundTarget,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DialResult, OutboundError>> + Send + 'a>> {
        Box::pin(async move {
            let t0 = coarse_now_ns();
            let addrs = self
                .dns
                .resolve_host(&self.server_host, self.server_port)
                .await
                .map_err(|e| OutboundError::Dns(e.to_string()))?;
            let Some(&server_addr) = addrs.first() else {
                return Err(OutboundError::Dns(format!(
                    "no addresses resolved for {}",
                    self.server_host
                )));
            };

            let tcp = connect_tcp_tuned_bound(server_addr, &self.sock_cfg, &self.bind, timeout)
                .await
                .map_err(OutboundError::Io)?;

            let ss_stream = ShadowsocksStream::new_client(tcp, Arc::clone(&self.keys), target)?;
            let rtt_us = coarse_now_ns().saturating_sub(t0) / 1_000;
            Ok(DialResult {
                stream: OutboundStream::from_tunnel(ss_stream),
                bound_addr: None,
                outbound_name: Arc::clone(&self.name),
                rtt_us,
            })
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    NeedSalt,
    Need2022FixedHeader,
    Need2022InitialPayload(usize),
    NeedChunkLen,
    NeedChunkPayload(usize),
}

/// Full-duplex async AEAD-2022 / Classic-AEAD Shadowsocks stream wrapping any
/// `AsyncRead + AsyncWrite` transport (zero-copy staging, 1-RTT piggybacked
/// request header on first write!).
pub struct ShadowsocksStream<S> {
    inner: S,
    keys: Arc<SsKeyMaterial>,
    client_salt: Vec<u8>,
    target_addr_wire: Vec<u8>,
    enc_key: LessSafeKey,
    enc_nonce: u64,
    header_sent: bool,
    write_buf: Vec<u8>,
    write_off: usize,
    pending_plain_len: usize,

    dec_key: Option<LessSafeKey>,
    dec_nonce: u64,
    read_phase: ReadPhase,
    wire_in: Vec<u8>,
    plain_out: Vec<u8>,
    plain_off: usize,
}

impl<S> fmt::Debug for ShadowsocksStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksStream")
            .field("cipher", &self.keys.cipher)
            .field("header_sent", &self.header_sent)
            .field("read_phase", &self.read_phase)
            .finish_non_exhaustive()
    }
}

impl<S> ShadowsocksStream<S> {
    fn new_client(
        inner: S,
        keys: Arc<SsKeyMaterial>,
        target: &OutboundTarget,
    ) -> Result<Self, OutboundError> {
        let salt_len = keys.cipher.key_len();
        let mut client_salt = vec![0u8; salt_len];
        getrandom::fill(&mut client_salt)
            .map_err(|e| OutboundError::Protocol(format!("CSPRNG error: {e}")))?;
        let enc_key = keys.derive_subkey(&client_salt)?;

        let mut target_addr_wire = Vec::with_capacity(32);
        encode_socks5_addr(target, &mut target_addr_wire)?;

        Ok(Self {
            inner,
            keys,
            client_salt,
            target_addr_wire,
            enc_key,
            enc_nonce: 0,
            header_sent: false,
            write_buf: Vec::new(),
            write_off: 0,
            pending_plain_len: 0,
            dec_key: None,
            dec_nonce: 0,
            read_phase: ReadPhase::NeedSalt,
            wire_in: Vec::new(),
            plain_out: Vec::new(),
            plain_off: 0,
        })
    }

    fn encode_write_chunk(&mut self, payload: &[u8]) -> io::Result<usize> {
        self.write_buf.clear();
        self.write_off = 0;

        if !self.header_sent {
            self.header_sent = true;
            if self.keys.cipher.is_2022() {
                // SIP022 1-RTT client request header piggybacking initial payload!
                // Wire: salt || EIH... || AEAD(fixed_hdr, nonce=0) || AEAD(var_hdr, nonce=1)
                let pad_len: u16 = if payload.is_empty() { 16 } else { 0 };
                let max_initial = SS2022_MAX_CHUNK
                    .saturating_sub(self.target_addr_wire.len() + 2 + usize::from(pad_len));
                let take = payload.len().min(max_initial);
                let var_len = self.target_addr_wire.len() + 2 + usize::from(pad_len) + take;

                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let mut fixed = Vec::with_capacity(11 + AEAD_TAG_LEN);
                fixed.push(SS2022_TYPE_CLIENT);
                fixed.extend_from_slice(&ts.to_be_bytes());
                fixed.extend_from_slice(&(var_len as u16).to_be_bytes());
                seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut fixed)?;

                let mut var = Vec::with_capacity(var_len + AEAD_TAG_LEN);
                var.extend_from_slice(&self.target_addr_wire);
                var.extend_from_slice(&pad_len.to_be_bytes());
                if pad_len > 0 {
                    let start = var.len();
                    var.resize(start + usize::from(pad_len), 0);
                    let _ = getrandom::fill(&mut var[start..]);
                }
                var.extend_from_slice(&payload[..take]);
                seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut var)?;

                self.write_buf.extend_from_slice(&self.client_salt);
                let eih = self.keys.build_eih(&self.client_salt);
                self.write_buf.extend_from_slice(&eih);
                self.write_buf.extend_from_slice(&fixed);
                self.write_buf.extend_from_slice(&var);
                return Ok(take);
            }

            // Classic AEAD: salt || AEAD(len(addr+payload)) || AEAD(addr+payload)
            let max_first = CLASSIC_MAX_CHUNK.saturating_sub(self.target_addr_wire.len());
            let take = payload.len().min(max_first);
            let combined_len = self.target_addr_wire.len() + take;

            self.write_buf.extend_from_slice(&self.client_salt);
            let mut len_block = Vec::with_capacity(2 + AEAD_TAG_LEN);
            len_block.extend_from_slice(&(combined_len as u16).to_be_bytes());
            seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut len_block)?;
            self.write_buf.extend_from_slice(&len_block);

            let mut data_block = Vec::with_capacity(combined_len + AEAD_TAG_LEN);
            data_block.extend_from_slice(&self.target_addr_wire);
            data_block.extend_from_slice(&payload[..take]);
            seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut data_block)?;
            self.write_buf.extend_from_slice(&data_block);
            return Ok(take);
        }

        // Subsequent data chunks (both SIP022 & Classic AEAD).
        let take = payload.len().min(self.keys.cipher.max_chunk());
        let mut len_block = Vec::with_capacity(2 + AEAD_TAG_LEN);
        len_block.extend_from_slice(&(take as u16).to_be_bytes());
        seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut len_block)?;
        self.write_buf.extend_from_slice(&len_block);

        let mut data_block = Vec::with_capacity(take + AEAD_TAG_LEN);
        data_block.extend_from_slice(&payload[..take]);
        seal_in_place(&self.enc_key, &mut self.enc_nonce, &mut data_block)?;
        self.write_buf.extend_from_slice(&data_block);
        Ok(take)
    }

    fn needed_wire_bytes(&self) -> usize {
        let salt_len = self.keys.cipher.key_len();
        match self.read_phase {
            ReadPhase::NeedSalt => salt_len,
            ReadPhase::Need2022FixedHeader => 1 + 8 + salt_len + 2 + AEAD_TAG_LEN,
            ReadPhase::Need2022InitialPayload(n) | ReadPhase::NeedChunkPayload(n) => {
                n + AEAD_TAG_LEN
            }
            ReadPhase::NeedChunkLen => 2 + AEAD_TAG_LEN,
        }
    }

    fn advance_read_state(&mut self) -> io::Result<()> {
        let salt_len = self.keys.cipher.key_len();
        match self.read_phase {
            ReadPhase::NeedSalt => {
                let key = self
                    .keys
                    .derive_subkey(&self.wire_in[..salt_len])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                self.dec_key = Some(key);
                self.dec_nonce = 0;
                self.wire_in.clear();
                self.read_phase = if self.keys.cipher.is_2022() {
                    ReadPhase::Need2022FixedHeader
                } else {
                    ReadPhase::NeedChunkLen
                };
            }
            ReadPhase::Need2022FixedHeader => {
                let dec_key = self.dec_key.as_ref().expect("dec_key initialized");
                let plain = open_in_place(dec_key, &mut self.dec_nonce, &mut self.wire_in)?;
                let expected_len = 1 + 8 + salt_len + 2;
                if plain.len() != expected_len || plain[0] != SS2022_TYPE_SERVER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Shadowsocks 2022 server header type",
                    ));
                }
                let server_ts = u64::from_be_bytes(plain[1..9].try_into().expect("8B ts"));
                let now_ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now_ts.abs_diff(server_ts) > SS2022_MAX_TIME_DIFF_SECS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks 2022 server timestamp out of range",
                    ));
                }
                let echoed_salt = &plain[9..9 + salt_len];
                if !bool::from(subtle::ConstantTimeEq::ct_eq(
                    echoed_salt,
                    self.client_salt.as_slice(),
                )) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks 2022 server echoed mismatched client salt",
                    ));
                }
                let init_len = usize::from(u16::from_be_bytes([
                    plain[9 + salt_len],
                    plain[10 + salt_len],
                ]));
                self.wire_in.clear();
                self.read_phase = if init_len > 0 {
                    ReadPhase::Need2022InitialPayload(init_len)
                } else {
                    ReadPhase::NeedChunkLen
                };
            }
            ReadPhase::Need2022InitialPayload(_) | ReadPhase::NeedChunkPayload(_) => {
                let dec_key = self.dec_key.as_ref().expect("dec_key initialized");
                let plain = open_in_place(dec_key, &mut self.dec_nonce, &mut self.wire_in)?;
                self.plain_out.clear();
                self.plain_off = 0;
                self.plain_out.extend_from_slice(plain);
                self.wire_in.clear();
                self.read_phase = ReadPhase::NeedChunkLen;
            }
            ReadPhase::NeedChunkLen => {
                let dec_key = self.dec_key.as_ref().expect("dec_key initialized");
                let plain = open_in_place(dec_key, &mut self.dec_nonce, &mut self.wire_in)?;
                let chunk_len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
                let max_len = self.keys.cipher.max_chunk();
                if chunk_len == 0 || chunk_len > max_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid Shadowsocks chunk length {chunk_len}"),
                    ));
                }
                self.wire_in.clear();
                self.read_phase = ReadPhase::NeedChunkPayload(chunk_len);
            }
        }
        Ok(())
    }
}

impl TunnelStream for ShadowsocksStream<TcpStream> {
    fn transport_label(&self) -> &'static str {
        self.keys.cipher.protocol_name()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.plain_off < this.plain_out.len() {
                let avail = this.plain_out.len() - this.plain_off;
                let take = avail.min(buf.remaining());
                buf.put_slice(&this.plain_out[this.plain_off..this.plain_off + take]);
                this.plain_off += take;
                if this.plain_off >= this.plain_out.len() {
                    this.plain_out.clear();
                    this.plain_off = 0;
                    if this.plain_out.capacity() > 65_536 {
                        this.plain_out = Vec::new();
                    }
                }
                return Poll::Ready(Ok(()));
            }

            let need = this.needed_wire_bytes();
            if this.wire_in.len() < need {
                let cur = this.wire_in.len();
                this.wire_in.resize(need, 0);
                let mut rbuf = ReadBuf::new(&mut this.wire_in[cur..need]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                    Poll::Pending => {
                        this.wire_in.truncate(cur);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        this.wire_in.truncate(cur);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => {
                        let got = rbuf.filled().len();
                        this.wire_in.truncate(cur + got);
                        if got == 0 {
                            if cur == 0
                                && matches!(
                                    this.read_phase,
                                    ReadPhase::NeedSalt | ReadPhase::NeedChunkLen
                                )
                            {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF in Shadowsocks stream",
                            )));
                        }
                        if this.wire_in.len() < need {
                            continue;
                        }
                    }
                }
            }

            if let Err(e) = this.advance_read_state() {
                return Poll::Ready(Err(e));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Drain any in-progress ciphertext frame first.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks underlying write zero",
                    )));
                }
                Poll::Ready(Ok(w)) => {
                    this.write_off += w;
                }
            }
        }
        if this.pending_plain_len > 0 {
            let done = this.pending_plain_len;
            this.pending_plain_len = 0;
            this.write_buf.clear();
            this.write_off = 0;
            return Poll::Ready(Ok(done));
        }

        let taken = match this.encode_write_chunk(buf) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        this.pending_plain_len = taken;

        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks underlying write zero",
                    )));
                }
                Poll::Ready(Ok(w)) => {
                    this.write_off += w;
                }
            }
        }
        let done = this.pending_plain_len;
        this.pending_plain_len = 0;
        this.write_buf.clear();
        this.write_off = 0;
        if this.write_buf.capacity() > 65_536 {
            this.write_buf = Vec::new();
        }
        Poll::Ready(Ok(done))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks flush write zero",
                    )));
                }
                Poll::Ready(Ok(w)) => this.write_off += w,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    /// Spec-exact mock Shadowsocks AEAD-2022 & Classic AEAD echo server for
    /// roundtrip wire verification of every cipher suite!
    async fn run_mock_ss_server(listener: TcpListener, cipher: SsCipher, password: String) {
        let keys = SsKeyMaterial::from_password(cipher, &password).unwrap();
        let (mut s, _) = listener.accept().await.unwrap();
        let salt_len = cipher.key_len();

        let mut client_salt = vec![0u8; salt_len];
        s.read_exact(&mut client_salt).await.unwrap();
        let dec_key = keys.derive_subkey(&client_salt).unwrap();
        let mut dec_nonce = 0u64;

        let mut server_salt = vec![0u8; salt_len];
        getrandom::fill(&mut server_salt).unwrap();
        let enc_key = keys.derive_subkey(&server_salt).unwrap();
        let mut enc_nonce = 0u64;

        let first_payload = if cipher.is_2022() {
            let mut fixed = vec![0u8; 11 + AEAD_TAG_LEN];
            s.read_exact(&mut fixed).await.unwrap();
            let fplain = open_in_place(&dec_key, &mut dec_nonce, &mut fixed).unwrap();
            assert_eq!(fplain[0], SS2022_TYPE_CLIENT);
            let var_len = usize::from(u16::from_be_bytes([fplain[9], fplain[10]]));
            let mut var = vec![0u8; var_len + AEAD_TAG_LEN];
            s.read_exact(&mut var).await.unwrap();
            let vplain = open_in_place(&dec_key, &mut dec_nonce, &mut var).unwrap();
            assert_eq!(vplain[0], 0x01); // IPv4 target
            let pad_len = usize::from(u16::from_be_bytes([vplain[7], vplain[8]]));
            vplain[9 + pad_len..].to_vec()
        } else {
            let mut lbuf = vec![0u8; 2 + AEAD_TAG_LEN];
            s.read_exact(&mut lbuf).await.unwrap();
            let lp = open_in_place(&dec_key, &mut dec_nonce, &mut lbuf).unwrap();
            let clen = usize::from(u16::from_be_bytes([lp[0], lp[1]]));
            let mut pbuf = vec![0u8; clen + AEAD_TAG_LEN];
            s.read_exact(&mut pbuf).await.unwrap();
            let pp = open_in_place(&dec_key, &mut dec_nonce, &mut pbuf).unwrap();
            assert_eq!(pp[0], 0x01);
            pp[7..].to_vec()
        };

        // Read one more chunk from client
        let mut lbuf = vec![0u8; 2 + AEAD_TAG_LEN];
        s.read_exact(&mut lbuf).await.unwrap();
        let lp = open_in_place(&dec_key, &mut dec_nonce, &mut lbuf).unwrap();
        let clen = usize::from(u16::from_be_bytes([lp[0], lp[1]]));
        let mut pbuf = vec![0u8; clen + AEAD_TAG_LEN];
        s.read_exact(&mut pbuf).await.unwrap();
        let second_payload = open_in_place(&dec_key, &mut dec_nonce, &mut pbuf)
            .unwrap()
            .to_vec();

        // Reply: server salt + SIP022 header (or classic chunk) echoing both payloads!
        s.write_all(&server_salt).await.unwrap();
        if cipher.is_2022() {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut shdr = Vec::with_capacity(1 + 8 + salt_len + 2 + AEAD_TAG_LEN);
            shdr.push(SS2022_TYPE_SERVER);
            shdr.extend_from_slice(&ts.to_be_bytes());
            shdr.extend_from_slice(&client_salt);
            shdr.extend_from_slice(&(first_payload.len() as u16).to_be_bytes());
            seal_in_place(&enc_key, &mut enc_nonce, &mut shdr).unwrap();
            s.write_all(&shdr).await.unwrap();

            let mut init_ct = first_payload;
            seal_in_place(&enc_key, &mut enc_nonce, &mut init_ct).unwrap();
            s.write_all(&init_ct).await.unwrap();
        } else {
            let mut lb = (first_payload.len() as u16).to_be_bytes().to_vec();
            seal_in_place(&enc_key, &mut enc_nonce, &mut lb).unwrap();
            let mut db = first_payload;
            seal_in_place(&enc_key, &mut enc_nonce, &mut db).unwrap();
            s.write_all(&lb).await.unwrap();
            s.write_all(&db).await.unwrap();
        }

        let mut lb2 = (second_payload.len() as u16).to_be_bytes().to_vec();
        seal_in_place(&enc_key, &mut enc_nonce, &mut lb2).unwrap();
        let mut db2 = second_payload;
        seal_in_place(&enc_key, &mut enc_nonce, &mut db2).unwrap();
        s.write_all(&lb2).await.unwrap();
        s.write_all(&db2).await.unwrap();
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_2022_and_classic_aead_roundtrip_all_ciphers() {
        let cases = [
            (
                SsCipher::Aes128Gcm2022,
                "2022-blake3-aes-128-gcm",
                base64::engine::general_purpose::STANDARD.encode([0x11u8; 16]),
            ),
            (
                SsCipher::Aes256Gcm2022,
                "2022-blake3-aes-256-gcm",
                base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]),
            ),
            (
                SsCipher::ChaCha20Poly1305_2022,
                "2022-blake3-chacha20-poly1305",
                base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]),
            ),
            (
                SsCipher::Aes256Gcm,
                "aes-256-gcm",
                "super-secret-pass".into(),
            ),
            (
                SsCipher::ChaCha20Poly1305,
                "chacha20-ietf-poly1305",
                "another-secret".into(),
            ),
        ];

        let dns = Arc::new(DnsResolver::build(None, None, mtg_config::PreferIp::OnlyIpv4).unwrap());

        for (cipher, method, pass) in cases {
            let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = ln.local_addr().unwrap();
            let srv = tokio::spawn(run_mock_ss_server(ln, cipher, pass.clone()));

            let url = format!("ss://{method}:{pass}@127.0.0.1:{}", addr.port());
            let tx = ShadowsocksTransport::parse(
                Arc::from("ss-test"),
                &url,
                Arc::clone(&dns),
                SocketConfig::default(),
                OutboundBindOptions::default(),
            )
            .unwrap();

            let target = OutboundTarget::Addr("149.154.167.51:443".parse().unwrap());
            let mut res = tx.dial(&target, Duration::from_secs(3)).await.unwrap();
            res.stream
                .write_all(b"hello-ss-first-flight")
                .await
                .unwrap();
            res.stream.write_all(b"-and-second-chunk!").await.unwrap();
            res.stream.flush().await.unwrap();

            let mut got = Vec::new();
            res.stream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hello-ss-first-flight-and-second-chunk!");
            srv.await.unwrap();
        }
    }
}
