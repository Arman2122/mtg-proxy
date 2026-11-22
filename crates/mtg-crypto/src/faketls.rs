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
/// TLS record type: Alert (`0x15`).
pub const TLS_RECORD_ALERT: u8 = 0x15;
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

/// Maximum boot-time / uptime timestamp (seconds) accepted for Telegram clients
/// that stamp monotonic uptime instead of Unix epoch right after boot.
pub const BOOT_TIME_MAX_SECS: u32 = 120;

/// TLS 1.3 cipher suites (RFC 8446 §B.4).
pub const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const TLS13_AES_128_CCM_SHA256: u16 = 0x1304;
pub const TLS13_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// TLS Named Groups for `key_share` (`0x0033`).
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

/// `X25519MLKEM768` hybrid post-quantum key_share payload lengths (draft-ietf-tls-ecdhe-mlkem).
/// ClientHello sends `1,184 B` ML-KEM-768 encapsulation key + `32 B` X25519 public key = `1,216 B`.
pub const X25519_MLKEM768_CLIENT_SHARE_LEN: usize = 1_216;
/// ServerHello sends `1,088 B` ML-KEM-768 ciphertext + `32 B` X25519 public key = `1,120 B`.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
pub const X25519_MLKEM768_SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + 32;

const EXT_TYPE_SNI: u16 = 0x0000;
const EXT_TYPE_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_TYPE_KEY_SHARE: u16 = 0x0033;
const SNI_DNS_NAME_TYPE: u8 = 0x00;
const EMPTY_RANDOM: [u8; RANDOM_LEN] = [0u8; RANDOM_LEN];

/// Exact RFC 8701 GREASE codepoint check (`0x?a?a` with matching high & low bytes).
#[inline]
pub const fn is_grease_u16(val: u16) -> bool {
    let hi = (val >> 8) as u8;
    let lo = (val & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Bitmask bit for a valid TLS 1.3 cipher suite (`0x1301..=0x1305`), or `0` for non-TLS-1.3.
#[inline]
pub const fn tls13_cipher_bit(cs: u16) -> u8 {
    match cs {
        TLS13_AES_128_GCM_SHA256 => 1 << 0,
        TLS13_AES_256_GCM_SHA384 => 1 << 1,
        TLS13_CHACHA20_POLY1305_SHA256 => 1 << 2,
        TLS13_AES_128_CCM_SHA256 => 1 << 3,
        TLS13_AES_128_CCM_8_SHA256 => 1 << 4,
        _ => 0,
    }
}

/// Exact RFC 8446 `supported_versions` ServerHello extension (6 bytes: `0x002b, len=2, TLS 1.3`).
const EXT_SUPPORTED_VERSIONS_TLS13: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// Classic X25519 `key_share` ServerHello extension header (8 bytes; 32 B public key follows).
const EXT_KEY_SHARE_X25519_HDR: [u8; 8] = [0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
/// Post-quantum `X25519MLKEM768` (`0x11EC`) `key_share` ServerHello extension header
/// (8 bytes; `1,088 B` ML-KEM-768 ciphertext + `32 B` X25519 public key = `1,120 B` follows).
const EXT_KEY_SHARE_MLKEM768_HDR: [u8; 8] = [0x00, 0x33, 0x04, 0x64, 0x11, 0xec, 0x04, 0x60];

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
    #[error("invalid TLS session ID length: {0} (max 32)")]
    InvalidSessionIdLength(usize),
    #[error("invalid cipher suites length: {0}")]
    InvalidCipherSuitesLength(usize),
    #[error("cannot find a non-GREASE cipher suite")]
    CannotFindCipher,
    #[error("invalid TLS extensions framing")]
    InvalidExtensions,
    #[error("duplicate TLS SNI extension")]
    DuplicateSni,
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

/// Stack-stored TLS Session ID (0..=32 bytes per RFC 8446 §4.1.2, zero heap allocation).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionId {
    buf: [u8; 32],
    len: u8,
}

impl SessionId {
    pub fn from_slice(src: &[u8]) -> Result<Self, FakeTlsError> {
        if src.len() > 32 {
            return Err(FakeTlsError::InvalidSessionIdLength(src.len()));
        }
        let mut buf = [0u8; 32];
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

/// Compact zero-allocation passive TLS ClientHello fingerprint metadata
/// (JA4-style structural counters computed in a single parse pass).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ClientHelloFingerprint {
    pub record_version: [u8; 2],
    pub cipher_count: u8,
    pub ext_count: u8,
    pub has_sni: bool,
    pub offers_x25519: bool,
    pub offers_pq_mlkem768: bool,
}

/// Extracted fields of a TLS ClientHello required to synthesize ServerHello,
/// negotiate Post-Quantum `X25519MLKEM768` / TLS 1.3 cipher suites, and track
/// FakeTLS replay protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub random: [u8; RANDOM_LEN],
    pub session_id: SessionId,
    /// First non-GREASE cipher suite offered by the client.
    pub cipher_suite: u16,
    /// Bitmask of TLS 1.3 cipher suites offered by the client (`0x1301..=0x1305`).
    pub tls13_ciphers_mask: u8,
    /// First valid TLS 1.3 cipher suite offered by the client (0 if none offered).
    pub first_tls13_cipher: u16,
    /// Passive structural metadata (including PQ `X25519MLKEM768` offer status).
    pub fingerprint: ClientHelloFingerprint,
}

impl ClientHello {
    /// Select a strictly valid TLS 1.3 cipher suite for `ServerHello`, never
    /// echoing a TLS 1.2 cipher inside a TLS 1.3 response!
    ///
    /// Priority:
    /// 1. Cover server's preferred TLS 1.3 cipher (`preferred`), if offered by client.
    /// 2. Client's first offered TLS 1.3 cipher (`first_tls13_cipher`).
    /// 3. `cipher_suite` if it is itself a valid TLS 1.3 cipher (manually constructed structs).
    /// 4. Safe RFC 8446 default `TLS_AES_128_GCM_SHA256` (`0x1301`).
    #[inline]
    pub const fn select_tls13_cipher(&self, preferred: Option<u16>) -> u16 {
        if let Some(pref) = preferred {
            let bit = tls13_cipher_bit(pref);
            if bit != 0
                && ((self.tls13_ciphers_mask & bit) != 0
                    || (self.tls13_ciphers_mask == 0 && self.cipher_suite == pref))
            {
                return pref;
            }
        }
        if self.first_tls13_cipher != 0 {
            return self.first_tls13_cipher;
        }
        if tls13_cipher_bit(self.cipher_suite) != 0 {
            return self.cipher_suite;
        }
        TLS13_AES_128_GCM_SHA256
    }

    /// True if the client offered a `1,216 B` Post-Quantum `X25519MLKEM768` (`0x11EC`) key share.
    #[inline]
    pub const fn offers_pq_mlkem768(&self) -> bool {
        self.fingerprint.offers_pq_mlkem768
    }

    /// 16-byte FakeTLS replay protection key derived from `client_random[..16]`
    /// (authenticated by HMAC-SHA256, unique per handshake even when `session_id`
    /// is empty or reused by a TLS client!).
    #[inline]
    pub fn replay_key(&self) -> &[u8; 16] {
        self.random[..16].try_into().expect("16 bytes")
    }
}

/// Options controlling FakeTLS ClientHello timestamp verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyOptions {
    pub now_unix_ns: i128,
    pub skew_ns: i128,
    /// When `true`, skip timestamp freshness checks (HMAC still verified in constant time).
    pub ignore_time_skew: bool,
    /// Accept monotonic boot-time / uptime timestamps (`ts < 120s`, including `0`)
    /// stamped by certain Telegram mobile clients before NTP sync completes.
    pub allow_boot_time: bool,
}

impl VerifyOptions {
    #[inline]
    pub const fn new(now_unix_ns: i128, skew_ns: i128) -> Self {
        Self {
            now_unix_ns,
            skew_ns,
            ignore_time_skew: false,
            allow_boot_time: true,
        }
    }
}

/// How a FakeTLS ClientHello timestamp passed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMatch {
    /// Timestamp matched current Unix wall clock within `skew_ns`.
    WallClock,
    /// Timestamp matched monotonic boot-time / uptime compatibility window (`< 120s`).
    BootTime,
    /// Timestamp check was explicitly disabled via `ignore-time-skew = true`.
    SkewIgnored,
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
        self.verify_with_opts(candidate, VerifyOptions::new(now_unix_ns, skew_ns))
            .is_some()
    }

    /// Verify a single candidate with explicit [`VerifyOptions`] (supporting
    /// boot-time/uptime compatibility and `ignore_time_skew`) with **0 heap allocations**.
    #[inline]
    pub fn verify_with_opts(
        &self,
        candidate: &FakeTlsCandidate,
        opts: VerifyOptions,
    ) -> Option<VerifyMatch> {
        if self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return None;
        }

        let parts = [
            &self.canonical_record[..RANDOM_OFFSET],
            &EMPTY_RANDOM[..],
            &self.canonical_record[RANDOM_OFFSET + RANDOM_LEN..],
        ];
        let mac = candidate.midstate.hmac_slices(&parts);
        check_faketls_digest_opts(&mac, &self.hello.random, opts)
    }

    /// Scan a slice of candidates using the fastest available SIMD backend
    /// (4-way SHA-NI or 8-way AVX2 multi-buffer with precomputed message
    /// schedule), returning the index of the first matching candidate.
    pub fn scan_candidates_at(
        &self,
        candidates: &[FakeTlsCandidate],
        now_unix_ns: i128,
        skew_ns: i128,
    ) -> Option<usize> {
        self.scan_candidates_with_opts(candidates, VerifyOptions::new(now_unix_ns, skew_ns))
            .map(|(idx, _)| idx)
    }

    /// Scan a slice of candidates using the fastest available SIMD backend with
    /// explicit [`VerifyOptions`], returning `(index, VerifyMatch)`.
    pub fn scan_candidates_with_opts(
        &self,
        candidates: &[FakeTlsCandidate],
        opts: VerifyOptions,
    ) -> Option<(usize, VerifyMatch)> {
        if candidates.is_empty() || self.canonical_record.len() < RANDOM_OFFSET + RANDOM_LEN {
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if candidates.len() >= 4
                && std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("sse4.1")
                && std::arch::is_x86_feature_detected!("ssse3")
            {
                return self.scan_candidates_shani_4way_with_opts(candidates, opts);
            }
            if candidates.len() >= 8 && std::arch::is_x86_feature_detected!("avx2") {
                return self.scan_candidates_avx2_8way_with_opts(candidates, opts);
            }
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if let Some(m) = self.verify_with_opts(cand, opts) {
                return Some((idx, m));
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
        self.scan_candidates_shani_4way_with_opts(
            candidates,
            VerifyOptions::new(now_unix_ns, skew_ns),
        )
        .map(|(idx, _)| idx)
    }

    /// 4-way SHA-NI scan with explicit [`VerifyOptions`].
    pub fn scan_candidates_shani_4way_with_opts(
        &self,
        candidates: &[FakeTlsCandidate],
        opts: VerifyOptions,
    ) -> Option<(usize, VerifyMatch)> {
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
                    if let Some(m) = check_faketls_digest_opts(mac, &self.hello.random, opts) {
                        return Some((batch_idx * 4 + lane, m));
                    }
                }
            }

            for (offset, cand) in candidates[rem_start..].iter().enumerate() {
                if let Some(m) = self.verify_with_opts(cand, opts) {
                    return Some((rem_start + offset, m));
                }
            }
            return None;
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if let Some(m) = self.verify_with_opts(cand, opts) {
                return Some((idx, m));
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
        self.scan_candidates_avx2_8way_with_opts(
            candidates,
            VerifyOptions::new(now_unix_ns, skew_ns),
        )
        .map(|(idx, _)| idx)
    }

    /// 8-way AVX2 multi-buffer scan with explicit [`VerifyOptions`].
    pub fn scan_candidates_avx2_8way_with_opts(
        &self,
        candidates: &[FakeTlsCandidate],
        opts: VerifyOptions,
    ) -> Option<(usize, VerifyMatch)> {
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
                    if let Some(m) = check_faketls_digest_opts(mac, &self.hello.random, opts) {
                        return Some((batch_idx * 8 + lane, m));
                    }
                }
            }

            for (offset, cand) in candidates[rem_start..].iter().enumerate() {
                if let Some(m) = self.verify_with_opts(cand, opts) {
                    return Some((rem_start + offset, m));
                }
            }
            return None;
        }

        for (idx, cand) in candidates.iter().enumerate() {
            if let Some(m) = self.verify_with_opts(cand, opts) {
                return Some((idx, m));
            }
        }
        None
    }
}

/// Constant-time check that `(mac ^ client_random)[0..28] == 0` and the
/// trailing little-endian `u32` timestamp satisfies `opts` (wall clock within
/// `skew_ns`, monotonic boot-time `< 120s` when enabled, or `ignore_time_skew`).
#[inline(always)]
fn check_faketls_digest_opts(
    mac: &[u8; 32],
    client_random: &[u8; 32],
    opts: VerifyOptions,
) -> Option<VerifyMatch> {
    let mut xored = [0u8; 32];
    for i in 0..32 {
        xored[i] = mac[i] ^ client_random[i];
    }

    if xored[..28].ct_eq(&EMPTY_RANDOM[..28]).unwrap_u8() != 1 {
        return None;
    }

    if opts.ignore_time_skew {
        return Some(VerifyMatch::SkewIgnored);
    }

    let ts_u32 = u32::from_le_bytes([xored[28], xored[29], xored[30], xored[31]]);
    let ts_ns = i128::from(ts_u32) * 1_000_000_000;
    if (opts.now_unix_ns - ts_ns).abs() <= opts.skew_ns {
        return Some(VerifyMatch::WallClock);
    }

    if opts.allow_boot_time && ts_u32 < BOOT_TIME_MAX_SECS {
        return Some(VerifyMatch::BootTime);
    }

    None
}

/// Incrementally parse a (possibly multi-record fragmented) TLS ClientHello
/// from `wire` without blocking.
///
/// Accepts both RFC 8446 §5.1 ClientHello record versions (`0x03 0x01` and
/// `0x03 0x03`), preserving the wire version in `canonical_record` for exact
/// HMAC verification.
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
    let mut first_rec_ver: [u8; 2] = [0x03, 0x01];

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
        // RFC 8446 §5.1 permits legacy_record_version 0x0301 or 0x0303 on ClientHello.
        if v_maj != 3 || (v_min != 1 && v_min != 3) {
            return Err(FakeTlsError::UnexpectedRecordVersion(v_maj, v_min));
        }
        if rec_len > MAX_RECORD_PAYLOAD {
            return Err(FakeTlsError::RecordTooLarge(rec_len));
        }
        if fragments == 0 {
            first_rec_ver = [v_maj, v_min];
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
                first_rec_ver[0],
                first_rec_ver[1],
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
    let (hello, sni_hostnames) = parse_client_hello_body(body, first_rec_ver)?;

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

fn parse_client_hello_body(
    body: &[u8],
    record_version: [u8; 2],
) -> Result<(ClientHello, Vec<String>), FakeTlsError> {
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
    let mut tls13_ciphers_mask: u8 = 0;
    let mut first_tls13_cipher: u16 = 0;
    let mut non_grease_ciphers: u8 = 0;
    for pair in cs_bytes.chunks_exact(2) {
        let cs = u16::from_be_bytes([pair[0], pair[1]]);
        if cs == 0 || is_grease_u16(cs) {
            continue;
        }
        non_grease_ciphers = non_grease_ciphers.saturating_add(1);
        if chosen_cipher == 0 {
            chosen_cipher = cs;
        }
        let bit = tls13_cipher_bit(cs);
        if bit != 0 {
            tls13_ciphers_mask |= bit;
            if first_tls13_cipher == 0 {
                first_tls13_cipher = cs;
            }
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

    // RFC 5246 §7.4.1.2 allows 0-extension ClientHellos (no trailing extensions_length field).
    let (sni_hostnames, ext_count, offers_x25519, offers_pq_mlkem768) = if cur.is_empty() {
        (Vec::new(), 0, false, false)
    } else {
        if cur.len() < 2 {
            return Err(FakeTlsError::Truncated);
        }
        let ext_len = usize::from(u16::from_be_bytes([cur[0], cur[1]]));
        cur = &cur[2..];
        if cur.len() < ext_len {
            return Err(FakeTlsError::Truncated);
        }
        parse_client_extensions(&cur[..ext_len])?
    };

    let fingerprint = ClientHelloFingerprint {
        record_version,
        cipher_count: non_grease_ciphers,
        ext_count,
        has_sni: !sni_hostnames.is_empty(),
        offers_x25519,
        offers_pq_mlkem768,
    };

    Ok((
        ClientHello {
            random,
            session_id,
            cipher_suite: chosen_cipher,
            tls13_ciphers_mask,
            first_tls13_cipher,
            fingerprint,
        },
        sni_hostnames,
    ))
}

fn parse_client_extensions(mut exts: &[u8]) -> Result<(Vec<String>, u8, bool, bool), FakeTlsError> {
    let mut names: Option<Vec<String>> = None;
    let mut ext_count: u8 = 0;
    let mut offers_x25519 = false;
    let mut offers_pq_mlkem768 = false;

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

        if !is_grease_u16(ext_type) {
            ext_count = ext_count.saturating_add(1);
        }

        match ext_type {
            EXT_TYPE_SNI => {
                if names.is_some() {
                    return Err(FakeTlsError::DuplicateSni);
                }
                if ext_data.len() < 2 {
                    return Err(FakeTlsError::InvalidExtensions);
                }
                let list_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                if list_len == 0 {
                    names = Some(Vec::new());
                    continue;
                }
                let mut list = ext_data
                    .get(2..2 + list_len)
                    .ok_or(FakeTlsError::InvalidExtensions)?;

                let mut parsed_names = Vec::with_capacity(1);
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
                    parsed_names.push(String::from_utf8_lossy(name_bytes).into_owned());
                }
                names = Some(parsed_names);
            }
            EXT_TYPE_KEY_SHARE => {
                // RFC 8446 §4.2.8: `client_shares<0..2^16-1>`
                if ext_data.len() >= 2 {
                    let shares_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                    if let Some(mut shares) = ext_data.get(2..2 + shares_len) {
                        while shares.len() >= 4 {
                            let group = u16::from_be_bytes([shares[0], shares[1]]);
                            let klen = usize::from(u16::from_be_bytes([shares[2], shares[3]]));
                            shares = &shares[4..];
                            if shares.len() < klen {
                                break;
                            }
                            if group == GROUP_X25519 && klen == 32 {
                                offers_x25519 = true;
                            } else if group == GROUP_X25519_MLKEM768
                                && klen == X25519_MLKEM768_CLIENT_SHARE_LEN
                            {
                                offers_pq_mlkem768 = true;
                            }
                            shares = &shares[klen..];
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok((
        names.unwrap_or_default(),
        ext_count,
        offers_x25519,
        offers_pq_mlkem768,
    ))
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

/// Live-calibrated cover-server `ServerHello` wire profile (24 bytes, `Copy`, zero allocs).
///
/// Mirrors the real cover origin's exact TLS 1.3 ServerHello structure:
/// - Preferred TLS 1.3 cipher suite (chosen only if offered by the client!)
/// - Post-Quantum `X25519MLKEM768` (`0x11EC`, `1,210 B` ServerHello) vs classic `X25519` (`122 B`)
/// - Exact extension wire ordering (`key_share` before `supported_versions`, or vice versa)
/// - Calibrated encrypted certificate-flight `ApplicationData` noise length!
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloProfile {
    /// Preferred TLS 1.3 cipher suite observed from the real cover origin (e.g. `0x1301` or `0x1302`).
    pub cipher_suite: Option<u16>,
    /// Emit Post-Quantum `X25519MLKEM768` (`0x11EC`, `1,120 B` key_share -> `1,210 B` ServerHello)
    /// whenever the client offers `X25519MLKEM768` (matching real `www.google.com` / Cloudflare!).
    pub prefer_pq_mlkem768: bool,
    /// Put `key_share` (`0x0033`) before `supported_versions` (`0x002b`) when `true`
    /// (matches OpenSSL/nginx/BoringSSL ordering observed on the live cover!).
    pub key_share_first: bool,
    /// Calibrated noise payload size for the fake encrypted handshake flight record.
    pub noise: NoiseParams,
}

impl Default for ServerHelloProfile {
    fn default() -> Self {
        Self {
            cipher_suite: None,
            prefer_pq_mlkem768: true,
            key_share_first: false,
            noise: NoiseParams::default(),
        }
    }
}

impl ServerHelloProfile {
    #[inline]
    pub const fn from_noise(noise: NoiseParams) -> Self {
        Self {
            cipher_suite: None,
            prefer_pq_mlkem768: true,
            key_share_first: false,
            noise,
        }
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
/// pre-reserved capacity `>= 18_432` bytes!
pub fn build_server_hello(
    out: &mut Vec<u8>,
    candidate: &FakeTlsCandidate,
    client_hello: &ClientHello,
    noise: NoiseParams,
    key_ring: &X25519KeyRing,
) {
    let _ = build_server_hello_with_profile(
        out,
        candidate,
        client_hello,
        ServerHelloProfile::from_noise(noise),
        key_ring,
    );
}

/// Build the complete 3-record FakeTLS ServerHello response matching `profile`
/// (including Post-Quantum `X25519MLKEM768` `1,210 B` ServerHello when both
/// `profile.prefer_pq_mlkem768` and `client_hello.offers_pq_mlkem768()` hold,
/// strict TLS 1.3 cipher selection, and cover-matched extension order!).
///
/// Returns `true` if a Post-Quantum `X25519MLKEM768` ServerHello was emitted,
/// `false` if classic `X25519` was emitted.
///
/// Clears `out` before writing. Performs **0 heap allocations** when `out` has
/// pre-reserved capacity `>= 18_432` bytes!
pub fn build_server_hello_with_profile(
    out: &mut Vec<u8>,
    candidate: &FakeTlsCandidate,
    client_hello: &ClientHello,
    profile: ServerHelloProfile,
    key_ring: &X25519KeyRing,
) -> bool {
    out.clear();

    let sid = client_hello.session_id.as_slice();
    let use_pq = profile.prefer_pq_mlkem768 && client_hello.offers_pq_mlkem768();
    let cipher = client_hello.select_tls13_cipher(profile.cipher_suite);

    // Extensions: supported_versions (6 B) + key_share (8 + 1120 = 1128 B for PQ, or 8 + 32 = 40 B for X25519)
    let key_share_val_len = if use_pq {
        X25519_MLKEM768_SERVER_SHARE_LEN
    } else {
        32
    };
    let exts_len = EXT_SUPPORTED_VERSIONS_TLS13.len() + 8 + key_share_val_len;

    // ServerHello handshake body:
    //   version(2) + random(32) + sid_len(1) + sid + cipher(2) + comp(1) + exts_len(2) + exts
    let hs_body_len = 2 + RANDOM_LEN + 1 + sid.len() + 2 + 1 + 2 + exts_len;
    let hs_record_len = 4 + hs_body_len;
    let noise_len = profile.noise.sample_len();

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
    out.extend_from_slice(&cipher.to_be_bytes());
    out.push(0x00); // no compression
    out.extend_from_slice(&(exts_len as u16).to_be_bytes());

    let write_key_share = |dst: &mut Vec<u8>| {
        if use_pq {
            dst.extend_from_slice(&EXT_KEY_SHARE_MLKEM768_HDR);
            // FIPS 203 ML-KEM-768 ciphertext (1,088 B IND-CCA2 pseudorandom) + real ephemeral X25519 point (32 B)
            let ct_start = dst.len();
            dst.resize(ct_start + MLKEM768_CIPHERTEXT_LEN, 0);
            TLS_RNG.with(|cell| {
                cell.borrow_mut().fill_bytes(&mut dst[ct_start..]);
            });
            dst.extend_from_slice(&key_ring.next_public_key());
        } else {
            dst.extend_from_slice(&EXT_KEY_SHARE_X25519_HDR);
            dst.extend_from_slice(&key_ring.next_public_key());
        }
    };

    if profile.key_share_first {
        write_key_share(out);
        out.extend_from_slice(&EXT_SUPPORTED_VERSIONS_TLS13);
    } else {
        out.extend_from_slice(&EXT_SUPPORTED_VERSIONS_TLS13);
        write_key_share(out);
    }

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
    use_pq
}

/// Build a realistic Chrome/Telegram-iOS-like TLS 1.3 Post-Quantum `ClientHello`
/// offering `X25519MLKEM768` (`0x11EC`) + `X25519` (`0x001D`) and all standard
/// TLS 1.3 cipher suites, used by the live cover ServerHello profiler in
/// `doppel_scout` to observe the cover origin's exact `ServerHelloProfile`!
pub fn build_pq_scout_client_hello(sni_host: &str) -> Vec<u8> {
    let mut random = [0u8; 32];
    let mut sid = [0u8; 32];
    let mut pq_key = vec![0u8; X25519_MLKEM768_CLIENT_SHARE_LEN];
    let x25519_pub = X25519KeyRing::default().next_public_key();
    TLS_RNG.with(|cell| {
        let mut rng = cell.borrow_mut();
        rng.fill_bytes(&mut random);
        rng.fill_bytes(&mut sid);
        rng.fill_bytes(&mut pq_key[..1184]);
    });
    pq_key[1184..].copy_from_slice(&x25519_pub);

    let ciphers: [u8; 10] = [
        0x2a, 0x2a, // GREASE
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (fallback compat)
    ];

    let mut exts = Vec::with_capacity(1400);
    // 1. SNI (0x0000)
    let host_bytes = sni_host.as_bytes();
    if !host_bytes.is_empty() {
        let entry_len = 1 + 2 + host_bytes.len();
        let body_len = 2 + entry_len;
        exts.extend_from_slice(&EXT_TYPE_SNI.to_be_bytes());
        exts.extend_from_slice(&(body_len as u16).to_be_bytes());
        exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
        exts.push(SNI_DNS_NAME_TYPE);
        exts.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(host_bytes);
    }
    // 2. supported_groups (0x000a): GREASE, X25519MLKEM768, X25519, secp256r1
    exts.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x4a, 0x4a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17,
    ]);
    // 3. signature_algorithms (0x000d): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp384r1_sha384
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
    ]);
    // 4. supported_versions (0x002b): GREASE, TLS 1.3, TLS 1.2
    exts.extend_from_slice(&[
        0x00, 0x2b, 0x00, 0x07, 0x06, 0x6a, 0x6a, 0x03, 0x04, 0x03, 0x03,
    ]);
    // 5. psk_key_exchange_modes (0x002d): psk_dhe_ke
    exts.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
    // 6. ALPN (0x0010): h2, http/1.1
    exts.extend_from_slice(&[
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/',
        b'1', b'.', b'1',
    ]);
    // 7. key_share (0x0033): X25519MLKEM768 (1216 B) + X25519 (32 B)
    let shares_len = (4 + pq_key.len()) + (4 + x25519_pub.len());
    exts.extend_from_slice(&EXT_TYPE_KEY_SHARE.to_be_bytes());
    exts.extend_from_slice(&((2 + shares_len) as u16).to_be_bytes());
    exts.extend_from_slice(&(shares_len as u16).to_be_bytes());
    exts.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
    exts.extend_from_slice(&(pq_key.len() as u16).to_be_bytes());
    exts.extend_from_slice(&pq_key);
    exts.extend_from_slice(&GROUP_X25519.to_be_bytes());
    exts.extend_from_slice(&(x25519_pub.len() as u16).to_be_bytes());
    exts.extend_from_slice(&x25519_pub);

    let body_len = 2 + 32 + 1 + 32 + 2 + ciphers.len() + 1 + 1 + 2 + exts.len();
    let rec_len = 4 + body_len;

    let mut out = Vec::with_capacity(5 + rec_len);
    out.push(TLS_RECORD_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&(rec_len as u16).to_be_bytes());

    out.push(TLS_HANDSHAKE_CLIENT_HELLO);
    out.push(((body_len >> 16) & 0xff) as u8);
    out.push(((body_len >> 8) & 0xff) as u8);
    out.push((body_len & 0xff) as u8);

    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&random);
    out.push(32);
    out.extend_from_slice(&sid);
    out.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    out.extend_from_slice(&ciphers);
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    out.extend_from_slice(&exts);
    out
}

/// Parse a real cover server's raw TLS 1.3 handshake response flight
/// (`ServerHello` + optional `ChangeCipherSpec` + encrypted `ApplicationData`
/// cert flight) into an exact [`ServerHelloProfile`]!
///
/// Returns `None` if the cover did not return a valid TLS 1.3 `ServerHello`.
pub fn parse_raw_server_hello_profile(raw: &[u8]) -> Option<ServerHelloProfile> {
    let mut pos = 0usize;
    let mut cipher_suite: Option<u16> = None;
    let mut is_tls13 = false;
    let mut prefer_pq_mlkem768 = false;
    let mut key_share_first = false;
    let mut app_flight_bytes = 0usize;
    let mut saw_sh = false;

    while pos + 5 <= raw.len() {
        let rec_type = raw[pos];
        let rec_len = usize::from(u16::from_be_bytes([raw[pos + 3], raw[pos + 4]]));
        pos += 5;
        if raw.len() - pos < rec_len {
            break;
        }
        let payload = &raw[pos..pos + rec_len];
        pos += rec_len;

        match rec_type {
            TLS_RECORD_HANDSHAKE if !saw_sh => {
                if payload.len() < 4 || payload[0] != TLS_HANDSHAKE_SERVER_HELLO {
                    return None;
                }
                let body_len =
                    usize::from_be_bytes([0, 0, 0, 0, 0, payload[1], payload[2], payload[3]]);
                let body = payload.get(4..4 + body_len)?;
                // version(2) + random(32) + sid_len(1)
                if body.len() < 35 {
                    return None;
                }
                let sid_len = usize::from(body[34]);
                let after_sid = 35 + sid_len;
                // cipher(2) + comp(1) + exts_len(2)
                if body.len() < after_sid + 5 {
                    return None;
                }
                let cs = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]);
                if tls13_cipher_bit(cs) != 0 {
                    cipher_suite = Some(cs);
                }
                let exts_len = usize::from(u16::from_be_bytes([
                    body[after_sid + 3],
                    body[after_sid + 4],
                ]));
                let mut exts = body.get(after_sid + 5..after_sid + 5 + exts_len)?;
                let mut seen_sv = false;
                let mut seen_ks = false;

                while exts.len() >= 4 {
                    let etype = u16::from_be_bytes([exts[0], exts[1]]);
                    let elen = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
                    exts = &exts[4..];
                    if exts.len() < elen {
                        break;
                    }
                    let edata = &exts[..elen];
                    exts = &exts[elen..];

                    if etype == EXT_TYPE_SUPPORTED_VERSIONS && edata == [0x03, 0x04] {
                        is_tls13 = true;
                        seen_sv = true;
                    } else if etype == EXT_TYPE_KEY_SHARE && edata.len() >= 4 {
                        if !seen_sv {
                            key_share_first = true;
                        }
                        seen_ks = true;
                        let group = u16::from_be_bytes([edata[0], edata[1]]);
                        let klen = usize::from(u16::from_be_bytes([edata[2], edata[3]]));
                        if group == GROUP_X25519_MLKEM768
                            && klen == X25519_MLKEM768_SERVER_SHARE_LEN
                        {
                            prefer_pq_mlkem768 = true;
                        }
                    }
                }
                if !is_tls13 || !seen_ks {
                    return None;
                }
                saw_sh = true;
            }
            TLS_RECORD_APPLICATION_DATA if saw_sh => {
                app_flight_bytes = app_flight_bytes.saturating_add(rec_len);
            }
            _ => {}
        }
    }

    if !saw_sh {
        return None;
    }

    let noise = if app_flight_bytes >= 500 {
        let mean = app_flight_bytes.clamp(1000, 16_000);
        let jitter = (mean / 8).max(200).min(mean / 2);
        NoiseParams { mean, jitter }
    } else {
        NoiseParams::default()
    };

    Some(ServerHelloProfile {
        cipher_suite,
        prefer_pq_mlkem768,
        key_share_first,
        noise,
    })
}

/// Build a valid FakeTLS `ClientHello` record authenticated with `secret_key`,
/// carrying `sni_host` and `unix_secs` timestamp in the final 4 bytes of Random.
///
/// Used by integration tests, interop checks against the Go oracle, and
/// pure-Rust `mtg-bench` load generators.
pub fn build_client_hello(secret_key: &[u8; 16], sni_host: &str, unix_secs: u32) -> Vec<u8> {
    build_client_hello_opts(secret_key, sni_host, unix_secs, false, [0x03, 0x01])
}

/// Build an authenticated Post-Quantum `X25519MLKEM768` FakeTLS `ClientHello`
/// (mimicking Telegram iOS 2026 / Chrome 131+ on the wire!) for integration tests.
pub fn build_pq_client_hello(secret_key: &[u8; 16], sni_host: &str, unix_secs: u32) -> Vec<u8> {
    build_client_hello_opts(secret_key, sni_host, unix_secs, true, [0x03, 0x01])
}

/// Configurable FakeTLS `ClientHello` builder supporting PQ `X25519MLKEM768`
/// key_share and custom legacy record version (`[0x03, 0x01]` or `[0x03, 0x03]`).
pub fn build_client_hello_opts(
    secret_key: &[u8; 16],
    sni_host: &str,
    unix_secs: u32,
    include_pq_key_share: bool,
    record_version: [u8; 2],
) -> Vec<u8> {
    let mut sid = [0u8; 32];
    TLS_RNG.with(|cell| {
        cell.borrow_mut().fill_bytes(&mut sid);
    });

    let mut exts = Vec::with_capacity(if include_pq_key_share { 1320 } else { 64 });
    let host_bytes = sni_host.as_bytes();
    if !host_bytes.is_empty() {
        let sni_entry_len = 1 + 2 + host_bytes.len();
        let sni_ext_body_len = 2 + sni_entry_len;
        exts.extend_from_slice(&EXT_TYPE_SNI.to_be_bytes());
        exts.extend_from_slice(&(sni_ext_body_len as u16).to_be_bytes());
        exts.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        exts.push(SNI_DNS_NAME_TYPE);
        exts.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(host_bytes);
    }

    if include_pq_key_share {
        let mut pq_key = vec![0u8; X25519_MLKEM768_CLIENT_SHARE_LEN];
        let x25519_pub = X25519KeyRing::default().next_public_key();
        TLS_RNG.with(|cell| {
            cell.borrow_mut().fill_bytes(&mut pq_key[..1184]);
        });
        pq_key[1184..].copy_from_slice(&x25519_pub);

        let shares_len = (4 + pq_key.len()) + (4 + 32);
        exts.extend_from_slice(&EXT_TYPE_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&((2 + shares_len) as u16).to_be_bytes());
        exts.extend_from_slice(&(shares_len as u16).to_be_bytes());
        exts.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
        exts.extend_from_slice(&(pq_key.len() as u16).to_be_bytes());
        exts.extend_from_slice(&pq_key);
        exts.extend_from_slice(&GROUP_X25519.to_be_bytes());
        exts.extend_from_slice(&32u16.to_be_bytes());
        exts.extend_from_slice(&x25519_pub);
    }

    // Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301) + TLS_AES_256_GCM_SHA384 (0x1302) + TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    let ciphers: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];

    let body_len = 2 + 32 + 1 + 32 + 2 + ciphers.len() + 1 + 1 + 2 + exts.len();
    let rec_len = 4 + body_len;

    let mut out = Vec::with_capacity(5 + rec_len);
    out.push(TLS_RECORD_HANDSHAKE);
    out.extend_from_slice(&record_version);
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
    out.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    out.extend_from_slice(&exts);

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
            tls13_ciphers_mask: tls13_cipher_bit(0x1303),
            first_tls13_cipher: 0x1303,
            fingerprint: ClientHelloFingerprint::default(),
        };

        let mut buf = Vec::with_capacity(18_432);
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
        assert_eq!(hs_len, 122); // classic X25519 ServerHello with 32 B sid
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
    fn post_quantum_x25519_mlkem768_server_hello_exact_1210_bytes_hmac_and_profile_roundtrip() {
        let secret = Secret::generate("www.google.com").unwrap();
        let cand = FakeTlsCandidate::new(secret.key());
        let ring = X25519KeyRing::default();

        let pq_ch_wire = build_pq_client_hello(secret.key(), "www.google.com", 1_760_000_000);
        let parsed = parse_client_hello_bytes(&pq_ch_wire).unwrap();
        assert!(parsed.hello.offers_pq_mlkem768());
        assert!(parsed.hello.fingerprint.offers_x25519);
        assert_eq!(parsed.sni_hostnames, vec!["www.google.com".to_owned()]);

        let profile = ServerHelloProfile {
            cipher_suite: Some(TLS13_AES_256_GCM_SHA384),
            prefer_pq_mlkem768: true,
            key_share_first: true,
            noise: NoiseParams {
                mean: 3200,
                jitter: 300,
            },
        };
        let mut buf = Vec::with_capacity(18_432);
        let used_pq =
            build_server_hello_with_profile(&mut buf, &cand, &parsed.hello, profile, &ring);
        assert!(used_pq);

        // Exact 1,210 B ServerHello record payload matching real www.google.com / Cloudflare!
        assert_eq!(buf[0], TLS_RECORD_HANDSHAKE);
        let sh_rec_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
        assert_eq!(sh_rec_len, 1210);

        // Verify HMAC-SHA256 covers the entire 3-record PQ ServerHello flight!
        let mut zeroed = buf.clone();
        let mut got_random = [0u8; 32];
        got_random.copy_from_slice(&zeroed[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]);
        zeroed[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN].fill(0);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.key()).unwrap();
        mac.update(&parsed.hello.random);
        mac.update(&zeroed);
        let want: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(got_random, want);

        // Raw cover profiler parses our own PQ ServerHello right back to the exact profile!
        let observed = parse_raw_server_hello_profile(&buf).expect("parsed PQ ServerHello");
        assert_eq!(observed.cipher_suite, Some(TLS13_AES_256_GCM_SHA384));
        assert!(observed.prefer_pq_mlkem768);
        assert!(observed.key_share_first);
        assert!((2900..=3500).contains(&observed.noise.mean));
    }

    #[test]
    fn grease_exact_rfc8701_tls13_cipher_never_echoes_tls12_and_strict_client_hello_checks() {
        // RFC 8701 GREASE requires BOTH bytes equal AND low nibble 0x0a.
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0x2a2a));
        assert!(is_grease_u16(0xfafa));
        assert!(!is_grease_u16(0x1a2a)); // mismatched bytes -> NOT GREASE!
        assert!(!is_grease_u16(0x1301));

        // Client offering TLS 1.2 first (0xc02f) then TLS 1.3 (0x1302) MUST pick 0x1302 in ServerHello!
        let ch = ClientHello {
            random: [0x33; 32],
            session_id: SessionId::from_slice(&[]).unwrap(),
            cipher_suite: 0xc02f,
            tls13_ciphers_mask: tls13_cipher_bit(TLS13_AES_256_GCM_SHA384),
            first_tls13_cipher: TLS13_AES_256_GCM_SHA384,
            fingerprint: ClientHelloFingerprint::default(),
        };
        assert_eq!(ch.select_tls13_cipher(None), TLS13_AES_256_GCM_SHA384);
        assert_eq!(
            ch.select_tls13_cipher(Some(TLS13_AES_128_GCM_SHA256)),
            TLS13_AES_256_GCM_SHA384
        );

        // Client offering ONLY TLS 1.2 falls back safely to 0x1301 (never echoes 0xc02f in TLS 1.3!).
        let ch_legacy = ClientHello {
            random: [0x33; 32],
            session_id: SessionId::from_slice(&[]).unwrap(),
            cipher_suite: 0xc02f,
            tls13_ciphers_mask: 0,
            first_tls13_cipher: 0,
            fingerprint: ClientHelloFingerprint::default(),
        };
        assert_eq!(
            ch_legacy.select_tls13_cipher(None),
            TLS13_AES_128_GCM_SHA256
        );

        // RFC 8446 0x0303 ClientHello record header parses & authenticates cleanly!
        let secret = Secret::generate("www.google.com").unwrap();
        let cand = FakeTlsCandidate::new(secret.key());
        let ts = 1_760_000_000u32;
        let wire_33 =
            build_client_hello_opts(secret.key(), "www.google.com", ts, false, [0x03, 0x03]);
        let parsed_33 = parse_client_hello_bytes(&wire_33).unwrap();
        assert_eq!(parsed_33.hello.fingerprint.record_version, [0x03, 0x03]);
        assert!(parsed_33.verify_at(&cand, i128::from(ts) * 1_000_000_000, 5_000_000_000));

        // Boot-time timestamp (ts = 15s, or ts = 0s) & ignore_time_skew verification!
        let wire_boot = build_client_hello(secret.key(), "www.google.com", 15);
        let parsed_boot = parse_client_hello_bytes(&wire_boot).unwrap();
        let now_ns = i128::from(ts) * 1_000_000_000;
        assert_eq!(
            parsed_boot.verify_with_opts(&cand, VerifyOptions::new(now_ns, 5_000_000_000)),
            Some(VerifyMatch::BootTime)
        );
        let mut strict_opts = VerifyOptions::new(now_ns, 5_000_000_000);
        strict_opts.allow_boot_time = false;
        assert_eq!(parsed_boot.verify_with_opts(&cand, strict_opts), None);
        strict_opts.ignore_time_skew = true;
        assert_eq!(
            parsed_boot.verify_with_opts(&cand, strict_opts),
            Some(VerifyMatch::SkewIgnored)
        );

        // Session ID > 32 bytes MUST be rejected!
        assert_eq!(
            SessionId::from_slice(&[0u8; 33]).unwrap_err(),
            FakeTlsError::InvalidSessionIdLength(33)
        );

        // Duplicate SNI extensions MUST be rejected!
        let dup_sni: [u8; 12] = [
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, // SNI #1 (empty)
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, // SNI #2 (duplicate!)
        ];
        assert_eq!(
            parse_client_extensions(&dup_sni).unwrap_err(),
            FakeTlsError::DuplicateSni
        );

        // 0-extension ClientHello (no extensions_length field at all) MUST parse cleanly!
        let mut zero_ext_body = Vec::new();
        zero_ext_body.extend_from_slice(&[0x03, 0x03]); // version
        zero_ext_body.extend_from_slice(&[0x44; 32]); // random
        zero_ext_body.push(0); // sid_len = 0
        zero_ext_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher
        zero_ext_body.extend_from_slice(&[0x01, 0x00]); // null compression; EOF right here!
        let (zh, zsnis) = parse_client_hello_body(&zero_ext_body, [0x03, 0x01]).unwrap();
        assert_eq!(zh.cipher_suite, TLS13_AES_128_GCM_SHA256);
        assert!(zsnis.is_empty());
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
