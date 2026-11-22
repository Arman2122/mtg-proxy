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
    BOOT_TIME_MAX_SECS, CHANGE_CIPHER_VALUE, ClientHello, ClientHelloFingerprint, FakeTlsCandidate,
    FakeTlsError, GROUP_X25519, GROUP_X25519_MLKEM768, MAX_CLIENT_HELLO_SIZE, MAX_FRAGMENTS,
    MAX_RECORD_PAYLOAD, MAX_SERVER_HELLO_NOISE, MLKEM768_CIPHERTEXT_LEN, NoiseParams, ParseStatus,
    ParsedClientHello, RANDOM_LEN, RANDOM_OFFSET, ServerHelloProfile, SessionId,
    TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_SERVER_HELLO, TLS_RECORD_ALERT,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    VerifyMatch, VerifyOptions, X25519_MLKEM768_CLIENT_SHARE_LEN, X25519_MLKEM768_SERVER_SHARE_LEN,
    X25519KeyRing, build_client_hello, build_client_hello_opts, build_pq_client_hello,
    build_pq_scout_client_hello, build_server_hello, build_server_hello_with_profile,
    is_grease_u16, parse_client_hello_bytes, parse_client_hello_incremental,
    parse_raw_server_hello_profile, tls13_cipher_bit,
};
pub use obfs2::{
    DEFAULT_DC, HANDSHAKE_FRAME_LEN, Obfs2Ciphers, Obfs2Error, Obfs2Match, REPLAY_KEY_DOMAIN_OBFS2,
    build_outbound_handshake, match_handshake, match_single_handshake, peek_tag,
};
pub use sha256_fast::{
    HmacSha256Midstate, PrecomputedSchedule, Sha256Hasher, sha256_48, sha256_oneshot,
};
