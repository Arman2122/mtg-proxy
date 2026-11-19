//! Hardware-accelerated cryptography, FakeTLS, Obfuscated2, and MiddleProxy CBC.
//!
//! All `unsafe` SIMD intrinsics are isolated inside `aes_ctr` and `sha256_fast`,
//! guarded by runtime CPU feature detection, and cross-verified against safe
//! reference implementations.

pub mod aes_ctr;
pub mod cbc;
pub mod faketls;
pub mod obfs2;
pub mod sha256_fast;

pub use aes_ctr::{
    AES_BLOCK_SIZE, Aes256Ctr, Aes256EncKey, AesBackend, FusedCtrPair, detect_aes_backend,
    incr_be128,
};
pub use cbc::{Aes256CbcDecryptor, Aes256CbcEncryptor, UnalignedCbcLength};
pub use faketls::{
    CHANGE_CIPHER_VALUE, ClientHello, FakeTlsCandidate, FakeTlsError, MAX_CLIENT_HELLO_SIZE,
    MAX_FRAGMENTS, MAX_RECORD_PAYLOAD, MAX_SERVER_HELLO_NOISE, NoiseParams, ParseStatus,
    ParsedClientHello, RANDOM_LEN, RANDOM_OFFSET, SessionId, TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_SERVER_HELLO, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC,
    TLS_RECORD_HANDSHAKE, X25519KeyRing, build_server_hello, parse_client_hello_bytes,
    parse_client_hello_incremental,
};
pub use obfs2::{
    DEFAULT_DC, HANDSHAKE_FRAME_LEN, Obfs2Ciphers, Obfs2Error, Obfs2Match, REPLAY_KEY_DOMAIN_OBFS2,
    build_outbound_handshake, match_handshake, match_single_handshake, peek_tag,
};
pub use sha256_fast::{
    HmacSha256Midstate, PrecomputedSchedule, Sha256Hasher, sha256_48, sha256_oneshot,
};
