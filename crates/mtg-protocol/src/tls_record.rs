//! 12-byte zero-copy TLS 1.3 record unframer and 5-byte headroom writer.
//!
//! Replaces Go's 16 KiB per-connection `bufio.Reader` inside `tls.Conn` with a
//! tiny inline state machine (`<= 12 bytes`) that unframes incoming FakeTLS
//! ApplicationData records directly in place inside the worker's temporary I/O
//! buffer, and guards against infinite-spin DoS on empty / non-ApplicationData
//! record floods.

use mtg_crypto::{TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC};
use thiserror::Error;

/// TLS record header size (`type(1) + version(2) + length(2) = 5`).
pub const TLS_HEADER_LEN: usize = 5;

/// TLS 1.2 legacy record version used on the wire by both TLS 1.2 and TLS 1.3.
pub const TLS_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// Maximum TLS record payload size (`16,384 - 5 = 16,379` when capped with
/// header, matching Go `tls.MaxRecordPayloadSize`).
pub const MAX_TLS_RECORD_PAYLOAD: usize = 16_384 - TLS_HEADER_LEN;

/// Maximum consecutive non-ApplicationData or zero-length records accepted
/// before closing the connection to prevent spin/CPU-exhaustion DoS.
const MAX_EMPTY_OR_NON_APP_STREAK: u8 = 64;

/// Errors emitted while unframing incoming FakeTLS records.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordError {
    #[error("invalid TLS record version {0:#x} {1:#x}")]
    InvalidVersion(u8, u8),
    #[error("too many consecutive empty or non-ApplicationData TLS records")]
    ExcessiveControlRecords,
}

/// Compact 12-byte inline state machine for zero-copy FakeTLS record unframing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TlsUnframer {
    hdr: [u8; TLS_HEADER_LEN],
    hdr_len: u8,
    /// Remaining payload bytes of the current ApplicationData record.
    app_rem: u16,
    /// Remaining payload bytes of a non-ApplicationData record to discard.
    skip_rem: u16,
    /// Consecutive non-ApplicationData or 0-byte ApplicationData records seen.
    control_streak: u8,
}

impl TlsUnframer {
    #[inline]
    pub const fn new() -> Self {
        Self {
            hdr: [0u8; TLS_HEADER_LEN],
            hdr_len: 0,
            app_rem: 0,
            skip_rem: 0,
            control_streak: 0,
        }
    }

    /// True if currently in the middle of a record header or payload (used to
    /// distinguish clean EOF at record boundary from `UnexpectedEof`).
    #[inline]
    pub const fn is_mid_record(&self) -> bool {
        self.hdr_len > 0 || self.app_rem > 0 || self.skip_rem > 0
    }

    /// Zero-memmove span-based TLS record unframer.
    ///
    /// Scans `buf` and writes `(start, end)` byte spans of ApplicationData
    /// payload slices into `out_spans` **without moving any payload bytes**.
    /// Returns `Ok(Some(span_count))` if all payload slices in `buf` fit in
    /// `out_spans` (the 99.99% fast path for reads up to 128 KiB!), or
    /// `Ok(None)` if `buf` contained more records than `out_spans.len()` (in
    /// which case `self` is left **unmodified** so the caller can seamlessly
    /// fall back to [`Self::unframe_in_place`]).
    pub fn unframe_spans(
        &mut self,
        buf: &[u8],
        out_spans: &mut [(usize, usize)],
    ) -> Result<Option<usize>, TlsRecordError> {
        let saved = *self;
        let len = buf.len();
        let mut r = 0usize;
        let mut count = 0usize;

        while r < len {
            if self.app_rem > 0 {
                let take = (len - r).min(usize::from(self.app_rem));
                if count >= out_spans.len() {
                    *self = saved;
                    return Ok(None);
                }
                // Coalesce immediately adjacent spans if any.
                if count > 0 && out_spans[count - 1].1 == r {
                    out_spans[count - 1].1 = r + take;
                } else {
                    out_spans[count] = (r, r + take);
                    count += 1;
                }
                r += take;
                self.app_rem -= take as u16;
                continue;
            }

            if self.skip_rem > 0 {
                let drop_n = (len - r).min(usize::from(self.skip_rem));
                r += drop_n;
                self.skip_rem -= drop_n as u16;
                continue;
            }

            let need = TLS_HEADER_LEN - usize::from(self.hdr_len);
            let avail = len - r;
            if avail < need {
                let start = usize::from(self.hdr_len);
                self.hdr[start..start + avail].copy_from_slice(&buf[r..len]);
                self.hdr_len += avail as u8;
                break;
            }

            let hdr = if self.hdr_len == 0 {
                let h = [buf[r], buf[r + 1], buf[r + 2], buf[r + 3], buf[r + 4]];
                r += TLS_HEADER_LEN;
                h
            } else {
                let start = usize::from(self.hdr_len);
                self.hdr[start..TLS_HEADER_LEN].copy_from_slice(&buf[r..r + need]);
                r += need;
                self.hdr_len = 0;
                self.hdr
            };

            if hdr[1] != TLS_RECORD_VERSION[0] || hdr[2] != TLS_RECORD_VERSION[1] {
                return Err(TlsRecordError::InvalidVersion(hdr[1], hdr[2]));
            }

            let rec_type = hdr[0];
            let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]);

            if rec_type == TLS_RECORD_APPLICATION_DATA {
                if rec_len == 0 {
                    self.control_streak = self.control_streak.saturating_add(1);
                    if self.control_streak > MAX_EMPTY_OR_NON_APP_STREAK {
                        return Err(TlsRecordError::ExcessiveControlRecords);
                    }
                } else {
                    self.control_streak = 0;
                    self.app_rem = rec_len;
                }
            } else {
                self.control_streak = self.control_streak.saturating_add(1);
                if self.control_streak > MAX_EMPTY_OR_NON_APP_STREAK {
                    return Err(TlsRecordError::ExcessiveControlRecords);
                }
                self.skip_rem = rec_len;
            }
        }

        Ok(Some(count))
    }

    /// Unframe TLS records in `buf` **in place** with zero allocations,
    /// compacting extracted ApplicationData payload into `buf[..written]` and
    /// returning `written`.
    ///
    /// Non-ApplicationData records (e.g., ChangeCipherSpec `0x14`) are silently
    /// discarded, matching Go `tls.Conn.openRecord`.
    pub fn unframe_in_place(&mut self, buf: &mut [u8]) -> Result<usize, TlsRecordError> {
        let len = buf.len();
        let mut r = 0usize;
        let mut w = 0usize;

        while r < len {
            if self.app_rem > 0 {
                let take = (len - r).min(usize::from(self.app_rem));
                if r != w {
                    buf.copy_within(r..r + take, w);
                }
                r += take;
                w += take;
                self.app_rem -= take as u16;
                continue;
            }

            if self.skip_rem > 0 {
                let drop_n = (len - r).min(usize::from(self.skip_rem));
                r += drop_n;
                self.skip_rem -= drop_n as u16;
                continue;
            }

            // Accumulate 5-byte TLS record header.
            let need = TLS_HEADER_LEN - usize::from(self.hdr_len);
            let avail = len - r;
            if avail < need {
                let start = usize::from(self.hdr_len);
                self.hdr[start..start + avail].copy_from_slice(&buf[r..len]);
                self.hdr_len += avail as u8;
                break;
            }

            let hdr = if self.hdr_len == 0 {
                let h = [buf[r], buf[r + 1], buf[r + 2], buf[r + 3], buf[r + 4]];
                r += TLS_HEADER_LEN;
                h
            } else {
                let start = usize::from(self.hdr_len);
                self.hdr[start..TLS_HEADER_LEN].copy_from_slice(&buf[r..r + need]);
                r += need;
                self.hdr_len = 0;
                self.hdr
            };

            if hdr[1] != TLS_RECORD_VERSION[0] || hdr[2] != TLS_RECORD_VERSION[1] {
                return Err(TlsRecordError::InvalidVersion(hdr[1], hdr[2]));
            }

            let rec_type = hdr[0];
            let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]);

            if rec_type == TLS_RECORD_APPLICATION_DATA {
                if rec_len == 0 {
                    self.control_streak = self.control_streak.saturating_add(1);
                    if self.control_streak > MAX_EMPTY_OR_NON_APP_STREAK {
                        return Err(TlsRecordError::ExcessiveControlRecords);
                    }
                } else {
                    self.control_streak = 0;
                    self.app_rem = rec_len;
                }
            } else {
                // Skip non-ApplicationData (CCS, Alert, Handshake, etc.), guarded against flood.
                self.control_streak = self.control_streak.saturating_add(1);
                if self.control_streak > MAX_EMPTY_OR_NON_APP_STREAK {
                    return Err(TlsRecordError::ExcessiveControlRecords);
                }
                self.skip_rem = rec_len;
            }
        }

        Ok(w)
    }
}

/// Stamp a 5-byte TLS 1.3 ApplicationData header into `headroom[0..5]` for a
/// payload of `payload_len` bytes sitting immediately after at `buf[5..5+payload_len]`.
///
/// Enables true 0-copy outbound FakeTLS writes directly from the worker's
/// provided buffer ring!
#[inline]
pub fn stamp_app_data_header(headroom: &mut [u8; TLS_HEADER_LEN], payload_len: u16) {
    headroom[0] = TLS_RECORD_APPLICATION_DATA;
    headroom[1] = TLS_RECORD_VERSION[0];
    headroom[2] = TLS_RECORD_VERSION[1];
    let len_be = payload_len.to_be_bytes();
    headroom[3] = len_be[0];
    headroom[4] = len_be[1];
}

/// Encode `payload` into one or more TLS ApplicationData records appended to `out`
/// (splitting at `MAX_TLS_RECORD_PAYLOAD` if larger than a single TLS record).
pub fn append_app_data_records(out: &mut Vec<u8>, mut payload: &[u8]) {
    while !payload.is_empty() {
        let chunk_len = payload.len().min(MAX_TLS_RECORD_PAYLOAD);
        let mut hdr = [0u8; TLS_HEADER_LEN];
        stamp_app_data_header(&mut hdr, chunk_len as u16);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&payload[..chunk_len]);
        payload = &payload[chunk_len..];
    }
}

/// Build a 6-byte TLS ChangeCipherSpec record (used by clients/tests).
#[inline]
pub const fn change_cipher_spec_record() -> [u8; 6] {
    [
        TLS_RECORD_CHANGE_CIPHER_SPEC,
        TLS_RECORD_VERSION[0],
        TLS_RECORD_VERSION[1],
        0x00,
        0x01,
        0x01,
    ]
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn unframer_is_12_bytes_or_less() {
        assert!(std::mem::size_of::<TlsUnframer>() <= 12);
    }

    #[test]
    fn skips_ccs_and_guards_empty_record_spin_dos() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&change_cipher_spec_record());
        append_app_data_records(&mut wire, b"hello");
        wire.extend_from_slice(&change_cipher_spec_record());
        append_app_data_records(&mut wire, b" world");

        let mut u = TlsUnframer::new();
        let n = u.unframe_in_place(&mut wire).unwrap();
        assert_eq!(&wire[..n], b"hello world");
        assert!(!u.is_mid_record());

        // 70 consecutive 0-byte AppData records MUST be rejected!
        let mut flood = Vec::new();
        for _ in 0..70 {
            flood.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 3, 3, 0, 0]);
        }
        let mut u2 = TlsUnframer::new();
        assert_eq!(
            u2.unframe_in_place(&mut flood),
            Err(TlsRecordError::ExcessiveControlRecords)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_chunk_splits_reconstruct_exact_payload(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..400), 1..16),
            read_sizes in proptest::collection::vec(1usize..120, 1..20),
        ) {
            let mut expected = Vec::new();
            let mut wire = Vec::new();
            for (idx, c) in chunks.iter().enumerate() {
                if idx % 3 == 0 {
                    wire.extend_from_slice(&change_cipher_spec_record());
                }
                expected.extend_from_slice(c);
                append_app_data_records(&mut wire, c);
            }

            let mut u = TlsUnframer::new();
            let mut u_spans = TlsUnframer::new();
            let mut got = Vec::new();
            let mut got_spans = Vec::new();
            let mut pos = 0;
            let mut step_idx = 0;
            while pos < wire.len() {
                let step = read_sizes[step_idx % read_sizes.len()].min(wire.len() - pos);
                let orig = wire[pos..pos + step].to_vec();
                let mut slice = orig.clone();
                let n = u.unframe_in_place(&mut slice).unwrap();
                got.extend_from_slice(&slice[..n]);

                let mut spans = [(0usize, 0usize); 4];
                if let Some(sc) = u_spans.unframe_spans(&orig, &mut spans).unwrap() {
                    for &(s, e) in &spans[..sc] {
                        got_spans.extend_from_slice(&orig[s..e]);
                    }
                } else {
                    let mut fallback = orig;
                    let m = u_spans.unframe_in_place(&mut fallback).unwrap();
                    got_spans.extend_from_slice(&fallback[..m]);
                }

                pos += step;
                step_idx += 1;
            }
            prop_assert!(!u.is_mid_record());
            prop_assert!(!u_spans.is_mid_record());
            prop_assert_eq!(got, expected.clone());
            prop_assert_eq!(got_spans, expected);
        }
    }
}
