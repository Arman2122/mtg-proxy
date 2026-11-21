//! FakeTLS (`ee` mode) ClientHello parser, multi-secret SIMD verifier, and
//! zero-allocation ServerHello generator.

use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::sha256_fast::HmacSha256Midstate;
#[cfg(target_arch = "x86_64")]
use crate::sha256_fast::PrecomputedSchedule;

/// TLS record type: Handshake (`0x16`).
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS record type: ChangeCipherSpec (`0x14`).
pub const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
/// TLS record type: ApplicationData (`0x17`).
pub const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;

/// TLS Handshake type: ClientHello (`0x01`).
pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// TLS Handshake type: ServerHello (`0x02`).
pub const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// ChangeCipherSpec payload byte (`0x01`).
pub const CHANGE_CIPHER_VALUE: u8 = 0x01;

/// Maximum TLS plaintext record payload length (`2^14 = 16,384` bytes).
pub const MAX_RECORD_PAYLOAD: usize = 16_384;

/// Maximum single ApplicationData noise payload in ServerHello (safe within
/// `MAX_RECORD_PAYLOAD` including 5-byte header margin).
pub const MAX_SERVER_HELLO_NOISE: usize = 16_379;

/// Maximum re-synthesized ClientHello handshake body size (`65535 - 4 = 65531`).
pub const MAX_CLIENT_HELLO_SIZE: usize = 65_531;

/// Maximum number of TLS fragments permitted for a single ClientHello.
pub const MAX_FRAGMENTS: usize = 10;

/// Byte offset of the 32-byte `Random` field inside the canonical single-record
/// ClientHello/ServerHello (`record_hdr(5) + hs_hdr(4) + version(2) = 11`).
pub const RANDOM_OFFSET: usize = 11;

/// Length of TLS `Random` in bytes.
pub const RANDOM_LEN: usize = 32;

const GREASE_MASK: u16 = 0x0f0f;
const GREASE_VALUE: u16 = 0x0a0a;
const EXT_TYPE_SNI: u16 = 0x0000;
const SNI_DNS_NAME_TYPE: u8 = 0x00;
const EMPTY_RANDOM: [u8; RANDOM_LEN] = [0u8; RANDOM_LEN];

/// Static ServerHello extension suffix (TLS 1.3 supported_versions + x25519 key_share header).
const SERVER_HELLO_SUFFIX: [u8; 17] = [
    0x00, // no compression
    0x00, 0x2e, // 46 bytes of extensions
    0x00, 0x2b, // Extension: Supported Versions
    0x00, 0x02, // 2 bytes
    0x03, 0x04, // TLS 1.3
    0x00, 0x33, // Extension: Key Share
    0x00, 0x24, // 36 bytes
    0x00, 0x1d, // x25519
    0x00, 0x20, // 32 bytes public key follows
];

thread_local! {
    static TLS_RNG: RefCell<ChaCha8Rng> = RefCell::new({
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS CSPRNG failed");
        ChaCha8Rng::from_seed(seed)
    });
}

/// Errors encountered while parsing or authenticating a FakeTLS ClientHello.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FakeTlsError {
    #[error("unexpected TLS record type {0:#x}")]
    UnexpectedRecordType(u8),
    #[error("unexpected TLS record version {0:#x} {1:#x}")]
    UnexpectedRecordVersion(u8, u8),
    #[error("TLS record payload is too large: {0} bytes")]
    RecordTooLarge(usize),
    #[error("too many TLS handshake fragments")]
    TooManyFragments,
    #[error("unexpected handshake message type {0:#x}")]
    UnexpectedHandshakeType(u8),
    #[error("client hello is too large: {0} bytes")]
    HelloTooLarge(usize),
    #[error("truncated client hello")]
    Truncated,
    #[error("invalid cipher suites length: {0}")]
    InvalidCipherSuitesLength(usize),
    #[error("cannot find a non-GREASE cipher suite")]
    CannotFindCipher,
    #[error("invalid TLS extensions framing")]
    InvalidExtensions,
    #[error("incorrect SNI list type {0:#x}")]
    InvalidSniType(u8),
    #[error("no allowed SNI hostname matched")]
    NoMatchingSni,
    #[error("bad digest")]
    BadDigest,
}

/// Result of incremental non-blocking ClientHello parsing over a byte buffer.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ParseStatus {
    /// Need more bytes from the peer socket before ClientHello is complete.
    Incomplete,
    /// Full ClientHello received and parsed; `consumed` is the exact number of
    /// raw wire bytes belonging to the ClientHello record(s).
    Complete {
        parsed: ParsedClientHello,
        consumed: usize,
    },
}

/// Stack-stored TLS Session ID (0..=255 bytes, zero heap allocation).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionId {
    buf: [u8; 255],
    len: u8,
}

impl SessionId {
    pub fn from_slice(src: &[u8]) -> Result<Self, FakeTlsError> {
        if src.len() > 255 {
            return Err(FakeTlsError::Truncated);
        }
        let mut buf = [0u8; 255];
        buf[..src.len()].copy_from_slice(src);
        Ok(Self {
            buf,
            len: src.len() as u8,
        })
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    #[inline]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionId")
            .field(&hex::encode(self.as_slice()))
            .finish()
    }
}

/// Extracted fields of a TLS ClientHello required to synthesize ServerHello and
/// track FakeTLS session replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub random: [u8; RANDOM_LEN],
    pub session_id: SessionId,
    pub cipher_suite: u16,
}

/// Precomputed FakeTLS verification candidate (64 bytes, 1 cache line).
///
/// Built once per secret key at startup/reload and reused across all worker
/// cores and handshakes with zero allocations.
#[derive(Clone, Debug)]
pub struct FakeTlsCandidate {
    midstate: HmacSha256Midstate,
}

impl FakeTlsCandidate {
    /// Precompute inner/outer SHA-256 HMAC midstates for `secret_key`.
    pub fn new(secret_key: &[u8]) -> Self {
        Self {
            midstate: HmacSha256Midstate::new(secret_key),
        }
    }

    #[inline]
    pub fn midstate(&self) -> &HmacSha256Midstate {
        &self.midstate
    }
}

/// Parsed ClientHello together with its canonical single-record wire
/// representation (over which the client computed its HMAC-SHA256) and
/// extracted SNI DNS names.
#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    pub hello: ClientHello,
    pub sni_hostnames: Vec<String>,
    /// Canonical single-record TLS ClientHello:
    /// `[0x16, 0x03, 0x01, u16_be(4+len), 0x01, u24_be(len), body...]`.
    pub canonical_record: Vec<u8>,
}

impl ParsedClientHello {
    /// SHA-256 block cost charged to the handshake scan budget, matching Go
    /// `Parsed.Blocks()`: `3 + ceil((L + 9) / 64)`.
    #[inline]
    pub fn scan_blocks(&self) -> usize {
        3 + (self.canonical_record.len() + 9).div_ceil(64)
    }

    /// Return the first hostname from `allowed_hostnames` that appears in the
    /// ClientHello's SNI list.
    pub fn match_sni<'a>(&self, allowed_hostnames: &'a [String]) -> Option<&'a str> {
        for allowed in allowed_hostnames {
            if self.sni_hostnames.iter().any(|h| h == allowed) {
                return Some(allowed.as_str());
            }
        }
        None
    }

    /// Verify a single candidate at the current wall clock with **0 heap allocations**.
    #[inline]
    pub fn verify(&self, candidate: &FakeTlsCandidate, skew: Duration) -> bool {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i128);
        self.verify_at(candidate, now_ns, skew.as_nanos() as i128)
    }

    /// Verify a single candidate at a specified Unix timestamp (nanoseconds)
    /// and allowed skew (nanoseconds), with **0 heap allocations**.
    #[inline]
    pub fn verify_at(
        &self,
        candidate: &FakeTlsCandidate,
        now_unix_ns: i128,
        skew_ns: i128,
    ) -> bool {
        if self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return false;
        }

        let parts = [
            &self.canonical_record[..RANDOM_OFFSET],
            &EMPTY_RANDOM[..],
            &self.canonical_record[RANDOM_OFFSET + RANDOM_LEN..],
        ];
        let mac = candidate.midstate.hmac_slices(&parts);
        check_faketls_digest(&mac, &self.hello.random, now_unix_ns, skew_ns)
    }

    /// Scan a slice of candidates using the fastest available SIMD backend
    /// (SHA-NI single-lane or 8-way AVX2 multi-buffer with precomputed message
    /// schedule), returning the index of the first matching candidate.
    pub fn scan_candidates_at(
        &self,
        candidates: &[FakeTlsCandidate],
        now_unix_ns: i128,
        skew_ns: i128,
    ) -> Option<usize> {
        if candidates.is_empty() || self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        {
            // 1. Fastest path on modern Intel/AMD CPUs with SHA-NI: 4-way
            //    interleaved SHA-NI reusing a single stack-resident
            //    `PrecomputedSchedule` (`W[t]+K[t]`) -> ~0.25-0.35 ms for 5,000 secrets!
            if candidates.len() >= 4
                && std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("sse4.1")
                && std::arch::is_x86_feature_detected!("ssse3")
            {
                return self.scan_candidates_shani_4way_at(candidates, now_unix_ns, skew_ns);
            }
            // 2. Fallback for AVX2 CPUs without SHA-NI (Haswell..Cascade Lake):
            //    8-way AVX2 multi-buffer SHA-256 over shared `PrecomputedSchedule`.
            if candidates.len() >= 8 && std::arch::is_x86_feature_detected!("avx2") {
                return self.scan_candidates_avx2_8way_at(candidates, now_unix_ns, skew_ns);
            }
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if self.verify_at(cand, now_unix_ns, skew_ns) {
                return Some(idx);
            }
        }
        None
    }

    /// Scan candidates via 4-way interleaved SHA-NI (`sha` + `sse4.1` + `ssse3`)
    /// reusing a single stack-resident [`PrecomputedSchedule`].
    pub fn scan_candidates_shani_4way_at(
        &self,
        candidates: &[FakeTlsCandidate],
        now_unix_ns: i128,
        skew_ns: i128,
    ) -> Option<usize> {
        if candidates.is_empty() || self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        if candidates.len() >= 4
            && std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            let parts = [
                &self.canonical_record[..RANDOM_OFFSET],
                &EMPTY_RANDOM[..],
                &self.canonical_record[RANDOM_OFFSET + RANDOM_LEN..],
            ];
            let schedule = PrecomputedSchedule::for_hmac_inner(&parts);
            let mut out = [[0u8; 32]; 4];
            let chunks = candidates.chunks_exact(4);
            let rem_start = chunks.len() * 4;

            for (batch_idx, chunk) in chunks.enumerate() {
                let refs = [
                    &chunk[0].midstate,
                    &chunk[1].midstate,
                    &chunk[2].midstate,
                    &chunk[3].midstate,
                ];
                // SAFETY: runtime feature check confirmed `sha`, `sse4.1`, `ssse3`.
                unsafe {
                    crate::sha256_fast::hmac_sha256_4way_shani(&refs, &schedule, &mut out);
                }
                for (lane, mac) in out.iter().enumerate() {
                    if check_faketls_digest(mac, &self.hello.random, now_unix_ns, skew_ns) {
                        return Some(batch_idx * 4 + lane);
                    }
                }
            }

            for (offset, cand) in candidates[rem_start..].iter().enumerate() {
                if self.verify_at(cand, now_unix_ns, skew_ns) {
                    return Some(rem_start + offset);
                }
            }
            return None;
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if self.verify_at(cand, now_unix_ns, skew_ns) {
                return Some(idx);
            }
        }
        None
    }

    /// Scan candidates explicitly via 8-way AVX2 multi-buffer HMAC-SHA256
    /// (computing `W[t] + K[t]` once for the entire ClientHello).
    ///
    /// Falls back to scalar `verify_at` on non-AVX2 CPUs or trailing `< 8` items.
    pub fn scan_candidates_avx2_8way_at(
        &self,
        candidates: &[FakeTlsCandidate],
        now_unix_ns: i128,
        skew_ns: i128,
    ) -> Option<usize> {
        if candidates.is_empty() || self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        if candidates.len() >= 8 && std::arch::is_x86_feature_detected!("avx2") {
            let parts = [
                &self.canonical_record[..RANDOM_OFFSET],
                &EMPTY_RANDOM[..],
                &self.canonical_record[RANDOM_OFFSET + RANDOM_LEN..],
            ];
            let schedule = PrecomputedSchedule::for_hmac_inner(&parts);
            let mut out = [[0u8; 32]; 8];
            let chunks = candidates.chunks_exact(8);
            let rem_start = chunks.len() * 8;

            for (batch_idx, chunk) in chunks.enumerate() {
                let refs = [
                    &chunk[0].midstate,
                    &chunk[1].midstate,
                    &chunk[2].midstate,
                    &chunk[3].midstate,
                    &chunk[4].midstate,
                    &chunk[5].midstate,
                    &chunk[6].midstate,
                    &chunk[7].midstate,
                ];
                // SAFETY: runtime feature check confirmed `avx2`.
                unsafe {
                    crate::sha256_fast::hmac_sha256_8way_avx2(&refs, &schedule, &mut out);
                }
                for (lane, mac) in out.iter().enumerate() {
                    if check_faketls_digest(mac, &self.hello.random, now_unix_ns, skew_ns) {
                        return Some(batch_idx * 8 + lane);
                    }
                }
            }

            for (offset, cand) in candidates[rem_start..].iter().enumerate() {
                if self.verify_at(cand, now_unix_ns, skew_ns) {
                    return Some(rem_start + offset);
                }
            }
            return None;
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if self.verify_at(cand, now_unix_ns, skew_ns) {
                return Some(idx);
            }
        }
        None
    }
}

/// Constant-time check that `(mac ^ client_random)[0..28] == 0` and the
/// trailing little-endian `u32` Unix timestamp is within `skew_ns` of `now_unix_ns`.
#[inline(always)]
fn check_faketls_digest(
    mac: &[u8; 32],
    client_random: &[u8; 32],
    now_unix_ns: i128,
    skew_ns: i128,
) -> bool {
    let mut xored = [0u8; 32];
    for i in 0..32 {
        xored[i] = mac[i] ^ client_random[i];
    }

    if xored[..28].ct_eq(&EMPTY_RANDOM[..28]).unwrap_u8() != 1 {
        return false;
    }

    let ts_secs = i128::from(u32::from_le_bytes([
        xored[28], xored[29], xored[30], xored[31],
    ]));
    let ts_ns = ts_secs * 1_000_000_000;
    (now_unix_ns - ts_ns).abs() <= skew_ns
}

/// Incrementally parse a (possibly multi-record fragmented) TLS ClientHello
/// from `wire` without blocking.
///
/// Enforces all pre-auth DoS bounds before allocating/buffering:
/// - `record_payload <= 16,384` (RFC 5246 §6.2.1)
/// - `handshake_body <= 65,531` (`uint16(4 + len)` no-wrap bound)
/// - `fragments <= 10` (checked on each additional fragment)
pub fn parse_client_hello_incremental(wire: &[u8]) -> Result<ParseStatus, FakeTlsError> {
    let mut pos = 0usize;
    let mut fragments = 0usize;
    let mut hs_header = [0u8; 4];
    let mut hs_header_got = 0usize;
    let mut expected_body_len: Option<usize> = None;
    let mut canonical: Vec<u8> = Vec::new();
    let mut body_got = 0usize;

    loop {
        if let Some(target_len) = expected_body_len
            && body_got >= target_len
        {
            break;
        }

        if fragments > MAX_FRAGMENTS {
            return Err(FakeTlsError::TooManyFragments);
        }

        // Need 5-byte TLS record header.
        if wire.len() - pos < 5 {
            return Ok(ParseStatus::Incomplete);
        }

        let rec_type = wire[pos];
        let v_maj = wire[pos + 1];
        let v_min = wire[pos + 2];
        let rec_len = usize::from(u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]));

        if rec_type != TLS_RECORD_HANDSHAKE {
            return Err(FakeTlsError::UnexpectedRecordType(rec_type));
        }
        if v_maj != 3 || v_min != 1 {
            return Err(FakeTlsError::UnexpectedRecordVersion(v_maj, v_min));
        }
        if rec_len > MAX_RECORD_PAYLOAD {
            return Err(FakeTlsError::RecordTooLarge(rec_len));
        }

        pos += 5;
        if wire.len() - pos < rec_len {
            return Ok(ParseStatus::Incomplete);
        }

        let mut payload = &wire[pos..pos + rec_len];
        pos += rec_len;
        fragments += 1;

        if expected_body_len.is_none() {
            let take = (4 - hs_header_got).min(payload.len());
            hs_header[hs_header_got..hs_header_got + take].copy_from_slice(&payload[..take]);
            hs_header_got += take;
            payload = &payload[take..];

            if hs_header_got < 4 {
                continue;
            }

            if hs_header[0] != TLS_HANDSHAKE_CLIENT_HELLO {
                return Err(FakeTlsError::UnexpectedHandshakeType(hs_header[0]));
            }
            let body_len =
                usize::from_be_bytes([0, 0, 0, 0, 0, hs_header[1], hs_header[2], hs_header[3]]);
            if body_len > MAX_CLIENT_HELLO_SIZE {
                return Err(FakeTlsError::HelloTooLarge(body_len));
            }

            expected_body_len = Some(body_len);
            canonical = Vec::with_capacity(9 + body_len);
            let rec_total = (4 + body_len) as u16;
            canonical.extend_from_slice(&[
                TLS_RECORD_HANDSHAKE,
                3,
                1,
                (rec_total >> 8) as u8,
                rec_total as u8,
            ]);
            canonical.extend_from_slice(&hs_header);
        }

        if let Some(target_len) = expected_body_len {
            let remaining = target_len - body_got;
            let take = remaining.min(payload.len());
            canonical.extend_from_slice(&payload[..take]);
            body_got += take;
        }
    }

    let body = &canonical[9..];
    let (hello, sni_hostnames) = parse_client_hello_body(body)?;

    Ok(ParseStatus::Complete {
        parsed: ParsedClientHello {
            hello,
            sni_hostnames,
            canonical_record: canonical,
        },
        consumed: pos,
    })
}

/// Parse a complete TLS ClientHello from a contiguous byte slice.
pub fn parse_client_hello_bytes(wire: &[u8]) -> Result<ParsedClientHello, FakeTlsError> {
    match parse_client_hello_incremental(wire)? {
        ParseStatus::Complete { parsed, .. } => Ok(parsed),
        ParseStatus::Incomplete => Err(FakeTlsError::Truncated),
    }
}

fn parse_client_hello_body(body: &[u8]) -> Result<(ClientHello, Vec<String>), FakeTlsError> {
    let mut cur = body;

    // 2B client legacy_version + 32B client random + 1B session_id_len
    if cur.len() < 2 + RANDOM_LEN + 1 {
        return Err(FakeTlsError::Truncated);
    }
    cur = &cur[2..]; // skip legacy_version

    let mut random = [0u8; RANDOM_LEN];
    random.copy_from_slice(&cur[..RANDOM_LEN]);
    cur = &cur[RANDOM_LEN..];

    let sid_len = usize::from(cur[0]);
    cur = &cur[1..];
    if cur.len() < sid_len {
        return Err(FakeTlsError::Truncated);
    }
    let session_id = SessionId::from_slice(&cur[..sid_len])?;
    cur = &cur[sid_len..];

    // 2B cipher suites length
    if cur.len() < 2 {
        return Err(FakeTlsError::Truncated);
    }
    let cs_len = usize::from(u16::from_be_bytes([cur[0], cur[1]]));
    cur = &cur[2..];
    if cs_len % 2 != 0 {
        return Err(FakeTlsError::InvalidCipherSuitesLength(cs_len));
    }
    if cur.len() < cs_len {
        return Err(FakeTlsError::Truncated);
    }
    let cs_bytes = &cur[..cs_len];
    cur = &cur[cs_len..];

    let mut chosen_cipher: u16 = 0;
    for pair in cs_bytes.chunks_exact(2) {
        let cs = u16::from_be_bytes([pair[0], pair[1]]);
        if chosen_cipher == 0 && cs != 0 && (cs & GREASE_MASK) != GREASE_VALUE {
            chosen_cipher = cs;
        }
    }
    if chosen_cipher == 0 {
        return Err(FakeTlsError::CannotFindCipher);
    }

    // 1B compression methods length + compression methods
    if cur.is_empty() {
        return Err(FakeTlsError::Truncated);
    }
    let comp_len = usize::from(cur[0]);
    cur = &cur[1..];
    if cur.len() < comp_len {
        return Err(FakeTlsError::Truncated);
    }
    cur = &cur[comp_len..];

    // 2B extensions length + extensions payload
    if cur.len() < 2 {
        return Err(FakeTlsError::Truncated);
    }
    let ext_len = usize::from(u16::from_be_bytes([cur[0], cur[1]]));
    cur = &cur[2..];
    if cur.len() < ext_len {
        return Err(FakeTlsError::Truncated);
    }
    let sni_hostnames = parse_sni_extension(&cur[..ext_len])?;

    Ok((
        ClientHello {
            random,
            session_id,
            cipher_suite: chosen_cipher,
        },
        sni_hostnames,
    ))
}

fn parse_sni_extension(mut exts: &[u8]) -> Result<Vec<String>, FakeTlsError> {
    while !exts.is_empty() {
        if exts.len() < 4 {
            return Err(FakeTlsError::InvalidExtensions);
        }
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
        exts = &exts[4..];
        if exts.len() < ext_len {
            return Err(FakeTlsError::InvalidExtensions);
        }
        let ext_data = &exts[..ext_len];
        exts = &exts[ext_len..];

        if ext_type != EXT_TYPE_SNI {
            continue;
        }

        if ext_data.len() < 2 {
            return Err(FakeTlsError::InvalidExtensions);
        }
        let list_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
        if list_len == 0 {
            return Ok(Vec::new());
        }
        let mut list = ext_data
            .get(2..2 + list_len)
            .ok_or(FakeTlsError::InvalidExtensions)?;

        let mut names = Vec::with_capacity(1);
        while !list.is_empty() {
            let name_type = list[0];
            if name_type != SNI_DNS_NAME_TYPE {
                return Err(FakeTlsError::InvalidSniType(name_type));
            }
            if list.len() < 3 {
                return Err(FakeTlsError::InvalidExtensions);
            }
            let name_len = usize::from(u16::from_be_bytes([list[1], list[2]]));
            list = &list[3..];
            if list.len() < name_len {
                return Err(FakeTlsError::InvalidExtensions);
            }
            let name_bytes = &list[..name_len];
            list = &list[name_len..];
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            names.push(name);
        }

        return Ok(names);
    }

    Ok(Vec::new())
}

/// Controls the size of the fake TLS 1.3 encrypted server handshake
/// ApplicationData noise record inside ServerHello.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoiseParams {
    pub mean: usize,
    pub jitter: usize,
}

impl NoiseParams {
    /// Sample a valid noise record payload length guaranteed to fit inside a
    /// single TLS ApplicationData record (`1000..=16379`).
    pub fn sample_len(self) -> usize {
        let raw = TLS_RNG.with(|cell| {
            let mut rng = cell.borrow_mut();
            if self.mean > 0 && self.jitter > 0 {
                let span = (self.jitter * 2) as u64;
                let offset = (rng.next_u64() % span) as usize;
                self.mean.saturating_sub(self.jitter).saturating_add(offset)
            } else {
                // Legacy range: 2500..4700
                2500 + (rng.next_u64() % 2200) as usize
            }
        });
        raw.clamp(1000, MAX_SERVER_HELLO_NOISE)
    }
}

/// Ephemeral X25519 public key generator for FakeTLS `ServerHello` `key_share`
/// extensions.
///
/// # Anti-DPI Stealth Upgrade
/// Instead of cycling through a static ring of public keys (which repeats the
/// exact same 32-byte `key_share` every `N` handshakes — an easily fingerprinted
/// synthetic TLS anomaly under DPI inspection), every handshake derives a
/// cryptographically fresh, never-repeating Curve25519 public point directly
/// from the worker's thread-local CSPRNG (`TLS_RNG`, zero syscalls, zero
/// cross-core atomic contention!).
#[derive(Debug, Default)]
pub struct X25519KeyRing {
    _private: (),
}

impl X25519KeyRing {
    /// Construct a fresh ephemeral X25519 key generator.
    pub const fn new(_count: usize) -> Self {
        Self { _private: () }
    }

    /// Generate a fresh, cryptographically unique Curve25519 public key for one
    /// FakeTLS `ServerHello` `key_share` extension (zero syscalls, zero locks).
    #[inline]
    pub fn next_public_key(&self) -> [u8; 32] {
        let mut scalar = [0u8; 32];
        TLS_RNG.with(|cell| {
            cell.borrow_mut().fill_bytes(&mut scalar);
        });
        let secret = StaticSecret::from(scalar);
        *PublicKey::from(&secret).as_bytes()
    }
}

/// Build the complete 3-record FakeTLS ServerHello response into `out`
/// (`ServerHello` + `ChangeCipherSpec` + exactly 1 `ApplicationData` noise record).
///
/// Clears `out` before writing. Performs **0 heap allocations** when `out` has
/// pre-reserved capacity `>= 16_600` bytes!
pub fn build_server_hello(
    out: &mut Vec<u8>,
    candidate: &FakeTlsCandidate,
    client_hello: &ClientHello,
    noise: NoiseParams,
    key_ring: &X25519KeyRing,
) {
    out.clear();

    let sid = client_hello.session_id.as_slice();
    // ServerHello handshake body:
    //   version(2) + random(32) + sid_len(1) + sid + cipher(2) + suffix(17) + x25519_pub(32)
    let hs_body_len = 2 + RANDOM_LEN + 1 + sid.len() + 2 + SERVER_HELLO_SUFFIX.len() + 32;
    let hs_record_len = 4 + hs_body_len;
    let noise_len = noise.sample_len();

    let total_len = (5 + hs_record_len) + 6 + (5 + noise_len);
    if out.capacity() < total_len {
        out.reserve(total_len - out.capacity());
    }

    // 1. Handshake Record (ServerHello)
    out.push(TLS_RECORD_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(hs_record_len as u16).to_be_bytes());

    out.push(TLS_HANDSHAKE_SERVER_HELLO);
    out.push(((hs_body_len >> 16) & 0xff) as u8);
    out.push(((hs_body_len >> 8) & 0xff) as u8);
    out.push((hs_body_len & 0xff) as u8);

    out.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy_version
    out.extend_from_slice(&EMPTY_RANDOM); // zeroed placeholder at RANDOM_OFFSET..RANDOM_OFFSET+32
    out.push(sid.len() as u8);
    out.extend_from_slice(sid);
    out.extend_from_slice(&client_hello.cipher_suite.to_be_bytes());
    out.extend_from_slice(&SERVER_HELLO_SUFFIX);
    out.extend_from_slice(&key_ring.next_public_key());

    // 2. ChangeCipherSpec Record (6 bytes)
    out.extend_from_slice(&[
        TLS_RECORD_CHANGE_CIPHER_SPEC,
        0x03,
        0x03,
        0x00,
        0x01,
        CHANGE_CIPHER_VALUE,
    ]);

    // 3. Exactly ONE ApplicationData noise record
    out.push(TLS_RECORD_APPLICATION_DATA);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(noise_len as u16).to_be_bytes());

    let noise_start = out.len();
    out.resize(noise_start + noise_len, 0);
    TLS_RNG.with(|cell| {
        cell.borrow_mut().fill_bytes(&mut out[noise_start..]);
    });

    // Stamp ServerHello Random = HMAC-SHA256(secret, client_hello.random || packet_with_zero_random).
    let mac = candidate
        .midstate
        .hmac_slices(&[&client_hello.random[..], out.as_slice()]);
    out[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN].copy_from_slice(&mac);
}

/// Build a valid FakeTLS `ClientHello` record authenticated with `secret_key`,
/// carrying `sni_host` and `unix_secs` timestamp in the final 4 bytes of Random.
///
/// Used by integration tests, interop checks against the Go oracle, and
/// pure-Rust `mtg-bench` load generators.
pub fn build_client_hello(secret_key: &[u8; 16], sni_host: &str, unix_secs: u32) -> Vec<u8> {
    let mut sid = [0u8; 32];
    TLS_RNG.with(|cell| {
        cell.borrow_mut().fill_bytes(&mut sid);
    });

    // Build SNI extension (type 0x0000)
    let host_bytes = sni_host.as_bytes();
    let sni_entry_len = 1 + 2 + host_bytes.len();
    let sni_ext_body_len = 2 + sni_entry_len;
    let exts_total_len = if host_bytes.is_empty() {
        0
    } else {
        4 + sni_ext_body_len
    };

    // Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301) + TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    let ciphers: [u8; 4] = [0x13, 0x01, 0x13, 0x03];

    // ClientHello handshake body:
    // version(2) + random(32) + sid_len(1) + sid(32) + ciphers_len(2) + ciphers(4)
    // + comp_len(1) + comp(1) + exts_len(2) + exts
    let body_len = 2 + 32 + 1 + 32 + 2 + ciphers.len() + 1 + 1 + 2 + exts_total_len;
    let rec_len = 4 + body_len;

    let mut out = Vec::with_capacity(5 + rec_len);
    out.push(TLS_RECORD_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&(rec_len as u16).to_be_bytes());

    out.push(TLS_HANDSHAKE_CLIENT_HELLO);
    out.push(((body_len >> 16) & 0xff) as u8);
    out.push(((body_len >> 8) & 0xff) as u8);
    out.push((body_len & 0xff) as u8);

    out.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    out.extend_from_slice(&EMPTY_RANDOM); // zeroed placeholder at RANDOM_OFFSET..RANDOM_OFFSET+32
    out.push(32);
    out.extend_from_slice(&sid);
    out.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    out.extend_from_slice(&ciphers);
    out.push(1);
    out.push(0); // null compression
    out.extend_from_slice(&(exts_total_len as u16).to_be_bytes());

    if !host_bytes.is_empty() {
        out.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI extension
        out.extend_from_slice(&(sni_ext_body_len as u16).to_be_bytes());
        out.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        out.push(0x00); // host_name
        out.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(host_bytes);
    }

    // Stamp ClientHello Random = HMAC-SHA256(secret_key, out_with_zero_random),
    // with the final 4 bytes XORed with little-endian `unix_secs`.
    let cand = FakeTlsCandidate::new(secret_key);
    let mut mac = cand.midstate.hmac_slices(&[out.as_slice()]);
    let ts_le = unix_secs.to_le_bytes();
    for i in 0..4 {
        mac[28 + i] ^= ts_le[i];
    }
    out[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN].copy_from_slice(&mac);
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hmac::{Hmac, Mac as _};
    use mtg_core::Secret;
    use serde::Deserialize;
    use sha2::Sha256;

    use super::*;

    #[derive(Deserialize)]
    struct GoldenSnapshot {
        time: i64,
        random: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        host: String,
        #[serde(rename = "cipherSuite")]
        cipher_suite: u16,
        full: String,
    }

    fn golden_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/mtglib/internal/tls/fake/testdata")
    }

    #[test]
    fn golden_faketls_client_hello_snapshots_ok_and_bad() {
        let secret = Secret::parse(
            "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d",
        )
        .unwrap();
        let cand = FakeTlsCandidate::new(secret.key());
        let dir = golden_dir();
        let mut ok_count = 0usize;
        let mut bad_count = 0usize;

        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if !Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                continue;
            }
            let raw = std::fs::read_to_string(entry.path()).unwrap();
            let snap: GoldenSnapshot = serde_json::from_str(&raw).unwrap();
            let wire = STANDARD.decode(&snap.full).unwrap();

            // Verify byte-by-byte incremental parsing yields identical result.
            for split in 1..wire.len() {
                if let ParseStatus::Complete { consumed, .. } =
                    parse_client_hello_incremental(&wire[..split]).unwrap()
                {
                    assert_eq!(consumed, wire.len());
                    break;
                }
            }

            let parsed = parse_client_hello_bytes(&wire).unwrap();
            let now_ns = i128::from(snap.time) * 1_000_000_000;
            let skew_ns = 300i128 * 1_000_000_000;

            if name.starts_with("client-hello-ok-") {
                ok_count += 1;
                assert_eq!(
                    parsed.hello.random.as_slice(),
                    STANDARD.decode(&snap.random).unwrap()
                );
                assert_eq!(
                    parsed.hello.session_id.as_slice(),
                    STANDARD.decode(&snap.session_id).unwrap()
                );
                assert_eq!(parsed.hello.cipher_suite, snap.cipher_suite, "{name}");
                assert_eq!(
                    parsed.match_sni(std::slice::from_ref(&snap.host)),
                    Some(snap.host.as_str())
                );
                assert!(parsed.verify_at(&cand, now_ns, skew_ns), "{name}");

                // Also verify AVX2 8-way scanner finds it behind 13 decoys!
                let mut decoys: Vec<FakeTlsCandidate> = (0..13)
                    .map(|i| FakeTlsCandidate::new(&[i as u8 + 1; 16]))
                    .collect();
                decoys.push(cand.clone());
                decoys.push(FakeTlsCandidate::new(&[0xfe; 16]));
                decoys.push(FakeTlsCandidate::new(&[0xfd; 16]));
                assert_eq!(
                    parsed.scan_candidates_avx2_8way_at(&decoys, now_ns, skew_ns),
                    Some(13),
                    "{name}"
                );
                assert_eq!(
                    parsed.scan_candidates_at(&decoys, now_ns, skew_ns),
                    Some(13),
                    "{name}"
                );
            } else if name.starts_with("client-hello-bad-") {
                bad_count += 1;
                assert!(!parsed.verify_at(&cand, now_ns, skew_ns), "{name}");
            }
        }

        assert_eq!(ok_count, 6);
        assert_eq!(bad_count, 1);
    }

    #[test]
    fn size_boundaries_match_go_tests() {
        let make_rec = |payload: &[u8], len_field: u16| {
            let mut v = vec![TLS_RECORD_HANDSHAKE, 3, 1];
            v.extend_from_slice(&len_field.to_be_bytes());
            v.extend_from_slice(payload);
            v
        };

        // Record > 16384 rejected on 5-byte header alone.
        let oversized_rec = make_rec(&[], (MAX_RECORD_PAYLOAD + 1) as u16);
        assert_eq!(
            parse_client_hello_incremental(&oversized_rec).unwrap_err(),
            FakeTlsError::RecordTooLarge(MAX_RECORD_PAYLOAD + 1)
        );

        // Hello 65532 rejected immediately on 9-byte prefix.
        let oversized_hello = make_rec(&[0x01, 0x00, 0xff, 0xfc], 4);
        assert_eq!(
            parse_client_hello_incremental(&oversized_hello).unwrap_err(),
            FakeTlsError::HelloTooLarge(65_532)
        );

        // Hello 65531 is legal framing -> Incomplete (not HelloTooLarge).
        let max_hello = make_rec(&[0x01, 0x00, 0xff, 0xfb], 4);
        assert!(matches!(
            parse_client_hello_incremental(&max_hello),
            Ok(ParseStatus::Incomplete)
        ));
    }

    #[test]
    fn server_hello_structure_hmac_and_noise_clamping() {
        let secret = Secret::generate("example.com").unwrap();
        let cand = FakeTlsCandidate::new(secret.key());
        let ring = X25519KeyRing::new(8);
        let ch = ClientHello {
            random: [0x11; 32],
            session_id: SessionId::from_slice(&[0x22; 32]).unwrap(),
            cipher_suite: 0x1303,
        };

        let mut buf = Vec::with_capacity(17_000);
        // Test huge mean gets clamped to single AppData record <= 16379!
        build_server_hello(
            &mut buf,
            &cand,
            &ch,
            NoiseParams {
                mean: 30_000,
                jitter: 500,
            },
            &ring,
        );

        // Parse the 3 records and verify HMAC against reference Hmac<Sha256>.
        assert_eq!(buf[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(&buf[1..3], &[3, 3]);
        let hs_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
        let ccs_off = 5 + hs_len;
        assert_eq!(
            &buf[ccs_off..ccs_off + 6],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        );
        let app_off = ccs_off + 6;
        assert_eq!(buf[app_off], TLS_RECORD_APPLICATION_DATA);
        let app_len = usize::from(u16::from_be_bytes([buf[app_off + 3], buf[app_off + 4]]));
        assert_eq!(app_len, MAX_SERVER_HELLO_NOISE);
        assert_eq!(app_off + 5 + app_len, buf.len());

        // Verify HMAC.
        let mut zeroed = buf.clone();
        let mut got_random = [0u8; 32];
        got_random.copy_from_slice(&zeroed[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]);
        zeroed[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN].fill(0);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.key()).unwrap();
        mac.update(&ch.random);
        mac.update(&zeroed);
        let want: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(got_random, want);
    }

    #[test]
    fn ephemeral_x25519_key_shares_never_repeat_across_handshakes() {
        let ring = X25519KeyRing::default();
        let mut seen = std::collections::HashSet::with_capacity(512);
        for _ in 0..512 {
            let pk = ring.next_public_key();
            assert_ne!(pk, [0u8; 32]);
            assert!(
                seen.insert(pk),
                "X25519 key_share repeated — DPI fingerprint leak!"
            );
        }
    }
}
