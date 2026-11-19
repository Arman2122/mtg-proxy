//! MTProto active DC health probe (`req_pq_multi` -> `resPQ`).
//!
//! Performs the unauthenticated first step of MTProto auth-key negotiation over
//! an obfuscated2 + padded-intermediate stream to prove an endpoint is a real,
//! responsive Telegram DC (immune to spoofed TCP acceptors).

use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq as _;
use thiserror::Error;

/// TL constructor ID: `req_pq_multi#be7e8ef1 nonce:int128 = ResPQ`.
pub const CTOR_REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;

/// TL constructor ID: `resPQ#05162463 nonce:int128 ... = ResPQ`.
pub const CTOR_RES_PQ: u32 = 0x0516_2463;

/// Minimum legal `resPQ` frame payload length: 20B unencrypted MTProto
/// envelope + 4B constructor + 16B echoed nonce.
pub const MIN_RES_PQ_FRAME: usize = 40;

/// Maximum legal `resPQ` frame payload length (real replies are ~84 bytes).
pub const MAX_RES_PQ_FRAME: usize = 256;

/// Errors returned while validating a `resPQ` reply.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DcProbeError {
    #[error("peer did not respond with a matching resPQ: frame too short ({0} bytes)")]
    FrameTooShort(usize),
    #[error("peer did not respond with a matching resPQ: frame too large ({0} bytes)")]
    FrameTooLarge(usize),
    #[error(
        "peer did not respond with a matching resPQ: got constructor {0:#010x}, want {CTOR_RES_PQ:#010x}"
    )]
    UnexpectedConstructor(u32),
    #[error("peer did not respond with a matching resPQ: nonce echo mismatch")]
    NonceMismatch,
}

/// Generate an MTProto client-to-server `message_id` from Unix nanoseconds
/// (lower 2 bits cleared per MTProto specification).
#[inline]
pub fn generate_message_id(unix_nanos: u64) -> u64 {
    let sec = unix_nanos / 1_000_000_000;
    let ns_in_sec = unix_nanos % 1_000_000_000;
    let subsec = (ns_in_sec << 32) / 1_000_000_000;
    ((sec << 32) | subsec) & !3
}

/// Build the 44-byte padded-intermediate `req_pq_multi` probe frame on the stack:
/// `[len=40 (4B LE) | auth_key_id=0 (8B) | msg_id (8B LE) | msg_len=20 (4B LE) | ctor (4B LE) | nonce (16B)]`.
pub fn build_req_pq_multi_frame(nonce: &[u8; 16], now_unix_nanos: u64) -> [u8; 44] {
    let mut frame = [0u8; 44];
    // 4-byte padded-intermediate frame length = 40 bytes.
    frame[0..4].copy_from_slice(&40u32.to_le_bytes());
    // bytes 4..12: auth_key_id = 0 (already zeroed).
    // bytes 12..20: message_id.
    frame[12..20].copy_from_slice(&generate_message_id(now_unix_nanos).to_le_bytes());
    // bytes 20..24: message_data_length = 20.
    frame[20..24].copy_from_slice(&20u32.to_le_bytes());
    // bytes 24..28: req_pq_multi constructor.
    frame[24..28].copy_from_slice(&CTOR_REQ_PQ_MULTI.to_le_bytes());
    // bytes 28..44: 16-byte client nonce.
    frame[28..44].copy_from_slice(nonce);
    frame
}

/// Convenience helper using `SystemTime::now()`.
pub fn build_req_pq_multi_frame_now(nonce: &[u8; 16]) -> [u8; 44] {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    build_req_pq_multi_frame(nonce, now_ns)
}

/// Validate the declared padded-intermediate reply length before buffering.
#[inline]
pub fn validate_res_pq_len(resp_len: usize) -> Result<(), DcProbeError> {
    if resp_len < MIN_RES_PQ_FRAME {
        return Err(DcProbeError::FrameTooShort(resp_len));
    }
    if resp_len > MAX_RES_PQ_FRAME {
        return Err(DcProbeError::FrameTooLarge(resp_len));
    }
    Ok(())
}

/// Verify a received `resPQ` frame payload (after stripping the 4-byte
/// padded-intermediate length prefix) matches `expected_nonce`.
pub fn verify_res_pq_payload(
    payload: &[u8],
    expected_nonce: &[u8; 16],
) -> Result<(), DcProbeError> {
    validate_res_pq_len(payload.len())?;

    // Unwrap 20-byte MTProto unencrypted envelope: auth_key_id(8) + msg_id(8) + len(4).
    let tl = &payload[20..];
    let ctor = u32::from_le_bytes([tl[0], tl[1], tl[2], tl[3]]);
    if ctor != CTOR_RES_PQ {
        return Err(DcProbeError::UnexpectedConstructor(ctor));
    }

    if tl[4..20].ct_eq(expected_nonce).unwrap_u8() != 1 {
        return Err(DcProbeError::NonceMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_pq_multi_and_res_pq_validation() {
        let nonce = [0x42u8; 16];
        let req = build_req_pq_multi_frame(&nonce, 1_700_000_000_500_000_000);
        assert_eq!(u32::from_le_bytes(req[0..4].try_into().unwrap()), 40);
        assert_eq!(&req[4..12], &[0u8; 8]);
        assert_eq!(u64::from_le_bytes(req[12..20].try_into().unwrap()) & 3, 0);
        assert_eq!(u32::from_le_bytes(req[20..24].try_into().unwrap()), 20);
        assert_eq!(
            u32::from_le_bytes(req[24..28].try_into().unwrap()),
            CTOR_REQ_PQ_MULTI
        );
        assert_eq!(&req[28..44], &nonce);

        // Valid resPQ reply
        let mut reply = vec![0u8; 84];
        reply[20..24].copy_from_slice(&CTOR_RES_PQ.to_le_bytes());
        reply[24..40].copy_from_slice(&nonce);
        verify_res_pq_payload(&reply, &nonce).unwrap();

        // Wrong nonce
        reply[24] ^= 1;
        assert_eq!(
            verify_res_pq_payload(&reply, &nonce),
            Err(DcProbeError::NonceMismatch)
        );

        // Wrong constructor
        reply[20..24].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert_eq!(
            verify_res_pq_payload(&reply, &nonce),
            Err(DcProbeError::UnexpectedConstructor(0xdead_beef))
        );
    }
}
