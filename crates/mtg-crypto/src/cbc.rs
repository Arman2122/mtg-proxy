//! Continuous AES-256-CBC stream state for Telegram MiddleProxy RPC links.
//!
//! MiddleProxy maintains a single running CBC IV across all encrypted RPC
//! frames on a connection (each frame is a multiple of 16 bytes, or padded to
//! 16 bytes with `0x04` before CBC encryption).

use std::fmt;

use aes::Aes256;
use aes::cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _};
use thiserror::Error;

type CbcEnc = cbc::Encryptor<Aes256>;
type CbcDec = cbc::Decryptor<Aes256>;

/// Error when CBC input is not a multiple of the 16-byte AES block size.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("AES-256-CBC buffer length {0} is not a multiple of 16 bytes")]
pub struct UnalignedCbcLength(pub usize);

/// Stateful AES-256-CBC encryptor (maintains chained IV across calls).
pub struct Aes256CbcEncryptor {
    inner: CbcEnc,
}

impl fmt::Debug for Aes256CbcEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes256CbcEncryptor(<redacted>)")
    }
}

impl Aes256CbcEncryptor {
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            inner: CbcEnc::new(key.into(), iv.into()),
        }
    }

    /// Encrypt `buf` in place. Length must be a multiple of 16 bytes.
    #[inline]
    pub fn encrypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), UnalignedCbcLength> {
        if !buf.len().is_multiple_of(16) {
            return Err(UnalignedCbcLength(buf.len()));
        }
        for chunk in buf.chunks_exact_mut(16) {
            let block = aes::Block::from_mut_slice(chunk);
            self.inner.encrypt_block_mut(block);
        }
        Ok(())
    }
}

/// Stateful AES-256-CBC decryptor (maintains chained IV across calls).
pub struct Aes256CbcDecryptor {
    inner: CbcDec,
}

impl fmt::Debug for Aes256CbcDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes256CbcDecryptor(<redacted>)")
    }
}

impl Aes256CbcDecryptor {
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            inner: CbcDec::new(key.into(), iv.into()),
        }
    }

    /// Decrypt `buf` in place. Length must be a multiple of 16 bytes.
    #[inline]
    pub fn decrypt_blocks_in_place(&mut self, buf: &mut [u8]) -> Result<(), UnalignedCbcLength> {
        if !buf.len().is_multiple_of(16) {
            return Err(UnalignedCbcLength(buf.len()));
        }
        for chunk in buf.chunks_exact_mut(16) {
            let block = aes::Block::from_mut_slice(chunk);
            self.inner.decrypt_block_mut(block);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_continuous_chaining_roundtrip() {
        let key = [0xabu8; 32];
        let iv = [0xcdu8; 16];
        let mut enc = Aes256CbcEncryptor::new(&key, &iv);
        let mut dec = Aes256CbcDecryptor::new(&key, &iv);

        let mut frame1 = [0x11u8; 32];
        let mut frame2 = [0x22u8; 48];
        let orig1 = frame1;
        let orig2 = frame2;

        enc.encrypt_blocks_in_place(&mut frame1).unwrap();
        enc.encrypt_blocks_in_place(&mut frame2).unwrap();
        assert_ne!(frame1, orig1);
        assert_ne!(frame2, orig2);

        dec.decrypt_blocks_in_place(&mut frame1).unwrap();
        dec.decrypt_blocks_in_place(&mut frame2).unwrap();
        assert_eq!(frame1, orig1);
        assert_eq!(frame2, orig2);

        assert!(enc.encrypt_blocks_in_place(&mut [0u8; 15]).is_err());
    }
}
