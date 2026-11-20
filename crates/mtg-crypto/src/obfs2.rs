//! Telegram Obfuscated2 handshake matcher and outbound frame generator.
//!
//! # Zero-Allocation Hot-Path Optimization
//! In Go `obfuscation/matcher.go`, `peekTag` heap-allocated `sha256.New()` +
//! `aes.NewCipher()` per candidate, then threw away BOTH the expanded AES-256
//! key AND keystream block 3 (`IV + 3`) on match, repeating SHA-256 + AES key
//! expansion + a dummy 64-byte CTR decrypt!
//!
//! Here:
//! - [`peek_tag`] runs completely on the stack with **0 heap allocations**
//!   using 1-block [`sha256_48`] + hardware AES-NI key expansion.
//! - On match, [`match_handshake`] **reuses** the already-expanded
//!   [`Aes256EncKey`] and block-3 keystream (`ks3`) to decode `dc` (`raw[60..62]
//!   ^ ks3[12..14]`) and initializes `recv_ctr` straight at `IV + 4` (offset 64)!

use std::cell::RefCell;

use mtg_core::{ConnectionTag, SECRET_KEY_LEN, TagSet};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use thiserror::Error;

use crate::aes_ctr::{AES_BLOCK_SIZE, Aes256Ctr, Aes256EncKey, incr_be128};
use crate::sha256_fast::sha256_48;

/// Length of an obfuscated2 handshake frame in bytes (always 64).
pub const HANDSHAKE_FRAME_LEN: usize = 64;

/// Default Telegram DC when the client's signed `int16` DC field is 0.
pub const DEFAULT_DC: i32 = 2;

/// Domain prefix byte for obfuscated2 anti-replay keys (keeps them disjoint
/// from 32-byte FakeTLS session IDs).
pub const REPLAY_KEY_DOMAIN_OBFS2: u8 = 0x01;

const OFFSET_KEY: usize = 8;
const OFFSET_IV: usize = 40;
const OFFSET_TAG: usize = 56;
const OFFSET_DC: usize = 60;

thread_local! {
    static OBFS2_RNG: RefCell<ChaCha8Rng> = RefCell::new({
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS CSPRNG failed");
        ChaCha8Rng::from_seed(seed)
    });
}

/// Errors from obfuscated2 handshake matching.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Obfs2Error {
    #[error("no configured secret decrypts this handshake")]
    NoMatchingSecret,
}

/// Bidirectional AES-256-CTR cipher pair for an obfuscated2 stream.
#[derive(Debug, Clone)]
pub struct Obfs2Ciphers {
    pub recv: Aes256Ctr,
    pub send: Aes256Ctr,
}

/// Result of matching a 64-byte client obfuscated2 handshake frame.
#[derive(Debug, Clone)]
pub struct Obfs2Match {
    /// Index of the matched secret in the candidate slice.
    pub index: usize,
    /// Requested Telegram DC (always positive; 0 maps to `DEFAULT_DC = 2`).
    pub dc: i32,
    /// Decrypted transport tag (`0xdddddddd`, `0xeeeeeeee`, or `0xefefefef`).
    pub tag: ConnectionTag,
    /// Ready-to-use ciphers (`recv` positioned at offset 64, `send` at offset 0).
    pub ciphers: Obfs2Ciphers,
    /// 49-byte anti-replay identity: `[0x01] || raw[8..56]`.
    pub replay_key: [u8; 49],
}

/// Peek the 4-byte transport tag of `raw` under `secret` with **0 heap allocations**.
///
/// Returns `(tag, expanded_recv_key, block3_keystream)` so a caller that accepts
/// the tag can finish constructing `recv_ctr` and extract `dc` with zero wasted
/// crypto work.
#[inline]
pub fn peek_tag(
    raw: &[u8; HANDSHAKE_FRAME_LEN],
    secret: Option<&[u8; SECRET_KEY_LEN]>,
) -> (ConnectionTag, Aes256EncKey, [u8; AES_BLOCK_SIZE]) {
    let key_seed: &[u8; 32] = raw[OFFSET_KEY..OFFSET_IV].try_into().expect("32 bytes");
    let aes_key = match secret {
        Some(s) => sha256_48(key_seed, s),
        None => *key_seed,
    };

    let enc_key = Aes256EncKey::new(&aes_key);
    let mut ctr: [u8; AES_BLOCK_SIZE] = raw[OFFSET_IV..OFFSET_TAG].try_into().expect("16 bytes");
    incr_be128(&mut ctr, 3);

    let mut ks3 = ctr;
    enc_key.encrypt_block(&mut ks3);

    // Bytes 56..60 lie at intra-block offsets 8..12 of counter block 3 (bytes 48..64).
    let tag = ConnectionTag([
        raw[OFFSET_TAG] ^ ks3[8],
        raw[OFFSET_TAG + 1] ^ ks3[9],
        raw[OFFSET_TAG + 2] ^ ks3[10],
        raw[OFFSET_TAG + 3] ^ ks3[11],
    ]);

    (tag, enc_key, ks3)
}

/// Decode the requested DC index from encrypted `raw[60..62]` and `ks3[12..14]`.
#[inline]
fn decode_dc(raw: &[u8; HANDSHAKE_FRAME_LEN], ks3: &[u8; AES_BLOCK_SIZE]) -> i32 {
    let raw_dc = i16::from_le_bytes([raw[OFFSET_DC] ^ ks3[12], raw[OFFSET_DC + 1] ^ ks3[13]]);
    let dc = i32::from(raw_dc).abs();
    if dc == 0 { DEFAULT_DC } else { dc }
}

/// Derive the server-to-client (`send`) AES-256-CTR cipher from reversed
/// `raw[8..56]` (starting at counter offset 0).
#[inline]
fn derive_reverted_ctr(
    raw: &[u8; HANDSHAKE_FRAME_LEN],
    secret: Option<&[u8; SECRET_KEY_LEN]>,
) -> Aes256Ctr {
    let mut rev = [0u8; 48];
    for i in 0..48 {
        rev[i] = raw[OFFSET_TAG - 1 - i];
    }
    let key_seed: &[u8; 32] = rev[..32].try_into().expect("32 bytes");
    let iv: [u8; 16] = rev[32..48].try_into().expect("16 bytes");
    let aes_key = match secret {
        Some(s) => sha256_48(key_seed, s),
        None => *key_seed,
    };
    Aes256Ctr::new(&aes_key, &iv)
}

/// Match a 64-byte client obfuscated2 handshake frame against a list of
/// optional secret keys (`Some(key)` for proxy secrets, `None` for direct/unmixed).
///
/// Performs **0 heap allocations**.
pub fn match_handshake<'a, I>(
    raw: &[u8; HANDSHAKE_FRAME_LEN],
    secrets: I,
    allowed: TagSet,
) -> Result<Obfs2Match, Obfs2Error>
where
    I: IntoIterator<Item = Option<&'a [u8; SECRET_KEY_LEN]>>,
{
    for (index, secret) in secrets.into_iter().enumerate() {
        let (tag, recv_key, ks3) = peek_tag(raw, secret);
        if allowed.match_bytes(tag.as_bytes()).is_none() {
            continue;
        }

        let dc = decode_dc(raw, &ks3);

        // Reuse the expanded `recv_key`, positioning `recv` directly at block IV + 4 (offset 64)!
        let mut recv_iv: [u8; AES_BLOCK_SIZE] =
            raw[OFFSET_IV..OFFSET_TAG].try_into().expect("16 bytes");
        incr_be128(&mut recv_iv, 4);
        let recv = Aes256Ctr::from_expanded(recv_key, recv_iv);

        // Derive reply (`send`) cipher from reversed `raw[8..56]` at offset 0.
        let send = derive_reverted_ctr(raw, secret);

        let mut replay_key = [0u8; 49];
        replay_key[0] = REPLAY_KEY_DOMAIN_OBFS2;
        replay_key[1..].copy_from_slice(&raw[OFFSET_KEY..OFFSET_TAG]);

        return Ok(Obfs2Match {
            index,
            dc,
            tag,
            ciphers: Obfs2Ciphers { recv, send },
            replay_key,
        });
    }

    Err(Obfs2Error::NoMatchingSecret)
}

/// Match a single secret key (convenience wrapper over [`match_handshake`]).
#[inline]
pub fn match_single_handshake(
    raw: &[u8; HANDSHAKE_FRAME_LEN],
    secret: Option<&[u8; SECRET_KEY_LEN]>,
    allowed: TagSet,
) -> Result<Obfs2Match, Obfs2Error> {
    match_handshake(raw, core::iter::once(secret), allowed)
}

/// Generate a fresh outbound 64-byte obfuscated2 handshake frame (e.g., proxy ->
/// Telegram DC with `secret = None`, or client -> proxy with `secret = Some(key)`)
/// and return `(wire_frame, ciphers)`.
///
/// Mirrors TDLib & Go's exact leading-byte rejection rules so bytes `0..8`
/// never mimic HTTP verbs, abridged/intermediate/padded headers, TLS records,
/// or zeroed words `[4..8]`.
pub fn build_outbound_handshake(
    dc: i16,
    tag: ConnectionTag,
    secret: Option<&[u8; SECRET_KEY_LEN]>,
) -> ([u8; HANDSHAKE_FRAME_LEN], Obfs2Ciphers) {
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];

    OBFS2_RNG.with(|cell| {
        let mut rng = cell.borrow_mut();
        loop {
            rng.fill_bytes(&mut frame);

            if frame[0] == 0xef {
                continue;
            }
            let first4 = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
            if matches!(
                first4,
                0x4441_4548 // HEAD
                    | 0x5453_4f50 // POST
                    | 0x2054_4547 // GET 
                    | 0x4954_504f // OPTI
                    | 0x0201_0316 // TLS-like
                    | 0xdddd_dddd // PaddedIntermediate
                    | 0xeeee_eeee // Intermediate
            ) {
                continue;
            }
            if (frame[4] | frame[5] | frame[6] | frame[7]) == 0 {
                continue;
            }
            break;
        }
    });

    frame[OFFSET_TAG..OFFSET_DC].copy_from_slice(&tag.as_bytes());
    frame[OFFSET_DC..OFFSET_DC + 2].copy_from_slice(&dc.to_le_bytes());

    // Forward key + IV -> `send` cipher (encrypt trailing 8 bytes with block IV + 3,
    // then position `send` at IV + 4 = offset 64).
    let key_seed: &[u8; 32] = frame[OFFSET_KEY..OFFSET_IV].try_into().expect("32 bytes");
    let send_aes_key = match secret {
        Some(s) => sha256_48(key_seed, s),
        None => *key_seed,
    };
    let send_enc = Aes256EncKey::new(&send_aes_key);
    let mut send_iv: [u8; AES_BLOCK_SIZE] =
        frame[OFFSET_IV..OFFSET_TAG].try_into().expect("16 bytes");

    let mut ks3 = send_iv;
    incr_be128(&mut ks3, 3);
    send_enc.encrypt_block(&mut ks3);

    // Only bytes 56..64 travel encrypted on the wire.
    for i in 0..8 {
        frame[OFFSET_TAG + i] ^= ks3[8 + i];
    }

    incr_be128(&mut send_iv, 4);
    let send = Aes256Ctr::from_expanded(send_enc, send_iv);

    // Reversed `frame[8..56]` -> `recv` cipher at offset 0.
    let recv = derive_reverted_ctr(&frame, secret);

    (frame, Obfs2Ciphers { recv, send })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct PairData {
        text: String,
        cipher: String,
    }

    #[derive(Deserialize)]
    struct ObfsSnapshot {
        secret: String,
        frame: String,
        dc: i32,
        decrypted: PairData,
        encrypted: PairData,
    }

    fn golden_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/mtglib/obfuscation/testdata")
    }

    #[test]
    fn golden_obfuscated2_snapshots_match_byte_exact() {
        let dir = golden_dir();
        let mut count = 0usize;

        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if !name.starts_with("client-handshake-snapshot-") {
                continue;
            }
            count += 1;
            let raw_json = std::fs::read_to_string(entry.path()).unwrap();
            let snap: ObfsSnapshot = serde_json::from_str(&raw_json).unwrap();

            let secret: [u8; 16] = STANDARD_NO_PAD
                .decode(&snap.secret)
                .unwrap()
                .try_into()
                .unwrap();
            let frame: [u8; 64] = STANDARD_NO_PAD
                .decode(&snap.frame)
                .unwrap()
                .try_into()
                .unwrap();
            let dec_cipher = STANDARD_NO_PAD.decode(&snap.decrypted.cipher).unwrap();
            let dec_text = STANDARD_NO_PAD.decode(&snap.decrypted.text).unwrap();
            let enc_text = STANDARD_NO_PAD.decode(&snap.encrypted.text).unwrap();
            let enc_cipher = STANDARD_NO_PAD.decode(&snap.encrypted.cipher).unwrap();

            let decoy1 = [0x11u8; 16];
            let decoy2 = [0x22u8; 16];
            let decoy3 = [0x33u8; 16];
            let candidates = [Some(&decoy1), Some(&decoy2), Some(&secret), Some(&decoy3)];

            let mut matched = match_handshake(&frame, candidates, TagSet::all()).unwrap();
            assert_eq!(matched.index, 2, "{name}");
            assert_eq!(matched.dc, snap.dc, "{name}");
            assert_eq!(matched.tag, ConnectionTag::PADDED_INTERMEDIATE, "{name}");
            assert_eq!(matched.replay_key[0], REPLAY_KEY_DOMAIN_OBFS2);
            assert_eq!(&matched.replay_key[1..], &frame[8..56]);

            // Verify client -> server decrypt starts at exact keystream offset 64!
            let mut got_dec = dec_cipher;
            matched.ciphers.recv.apply_keystream(&mut got_dec);
            assert_eq!(got_dec, dec_text, "{name} recv stream");

            // Verify server -> client encrypt starts at exact keystream offset 0!
            let mut got_enc = enc_text;
            matched.ciphers.send.apply_keystream(&mut got_enc);
            assert_eq!(got_enc, enc_cipher, "{name} send stream");
        }

        assert_eq!(count, 2);
    }

    #[test]
    fn outbound_and_inbound_roundtrip_all_tags_and_negative_dc() {
        let secret = [0x99u8; 16];
        for (dc, expect_dc, tag) in [
            (2i16, 2i32, ConnectionTag::PADDED_INTERMEDIATE),
            (-4i16, 4i32, ConnectionTag::INTERMEDIATE),
            (0i16, DEFAULT_DC, ConnectionTag::ABRIDGED),
        ] {
            let (frame, mut client) = build_outbound_handshake(dc, tag, Some(&secret));
            let mut server = match_single_handshake(&frame, Some(&secret), TagSet::all()).unwrap();
            assert_eq!(server.dc, expect_dc);
            assert_eq!(server.tag, tag);

            let mut msg = b"hello telegram mtproto rust!".to_vec();
            let orig = msg.clone();
            client.send.apply_keystream(&mut msg);
            assert_ne!(msg, orig);
            server.ciphers.recv.apply_keystream(&mut msg);
            assert_eq!(msg, orig);

            let mut reply = b"reply from dc!".to_vec();
            let orig_r = reply.clone();
            server.ciphers.send.apply_keystream(&mut reply);
            client.recv.apply_keystream(&mut reply);
            assert_eq!(reply, orig_r);
        }
    }
}
