//! WEB relay token signer with precomputed HMAC-SHA256 midstates (zero heap
//! allocations on verify/recognise!) and fixed lenient Tier-2 decoding so
//! padded/standard-alphabet token spellings NEVER leak to the cover site.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtg_crypto::sha256_fast::HmacSha256Midstate;
use subtle::{Choice, ConstantTimeEq as _};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::capability::{parse_capability_lenient, parse_capability_strict};

const TOKEN_NONCE_LEN: usize = 16;
const TOKEN_MAC_LEN: usize = 16;
const TOKEN_TOTAL_LEN: usize = TOKEN_NONCE_LEN + TOKEN_MAC_LEN;
const TOKEN_LABEL: &[u8] = b"tproxy-server-token-v1\0";

/// Length of an encoded unpadded base64url token (`43` chars).
pub const TOKEN_LEN: usize = 43;

/// Length of the persistent signing key on disk (`32` bytes).
pub const TOKEN_KEY_LEN: usize = 32;

/// Credential domain distinguishing bootstrap vs session tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenKind {
    /// Embedded in one bridge HTML response; spent once on `POST /api/v1/session`.
    Bootstrap = 0x01,
    /// Authenticates `GET /api/v1/ws` and `DELETE /api/v1/session`.
    Session = 0x02,
}

/// Errors loading or generating the persistent token signing key.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("WEB relay token key file is missing: {0}")]
    Missing(String),
    #[error("WEB relay token key file already exists: {0}; remove it first to regenerate")]
    AlreadyExists(String),
    #[error("WEB relay token key file is the wrong size: {got} bytes, want {TOKEN_KEY_LEN}")]
    WrongSize { got: usize },
    #[error(
        "WEB relay token key file {path} is readable by group or other (mode {mode:#o}, want 0600)"
    )]
    BadPermissions { path: String, mode: u32 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OS CSPRNG error: {0}")]
    Rng(String),
}

/// Zero-allocation HMAC-SHA256 token minter & verifier.
#[derive(Clone)]
pub struct Signer {
    midstate: HmacSha256Midstate,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer([redacted])")
    }
}

impl Signer {
    /// Build a signer from raw 32-byte key material, precomputing inner/outer
    /// SHA-256 HMAC midstates once at startup.
    pub fn new(key: &[u8]) -> Result<Self, TokenError> {
        if key.len() != TOKEN_KEY_LEN {
            return Err(TokenError::WrongSize { got: key.len() });
        }
        Ok(Self {
            midstate: HmacSha256Midstate::new(key),
        })
    }

    /// Load persistent 32-byte signing key from disk, enforcing `0600` permissions.
    pub fn load_file(path: &Path) -> Result<Self, TokenError> {
        let meta = fs::metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TokenError::Missing(path.display().to_string())
            } else {
                TokenError::Io(e)
            }
        })?;

        let perm = meta.mode() & 0o777;
        if perm & 0o077 != 0 {
            return Err(TokenError::BadPermissions {
                path: path.display().to_string(),
                mode: perm,
            });
        }

        let key = Zeroizing::new(fs::read(path)?);
        Self::new(&key)
    }

    /// Mint a fresh 43-char base64url token of `kind`.
    pub fn mint(&self, kind: TokenKind) -> Result<String, TokenError> {
        let mut raw = [0u8; TOKEN_TOTAL_LEN];
        getrandom::fill(&mut raw[..TOKEN_NONCE_LEN]).map_err(|e| TokenError::Rng(e.to_string()))?;
        let mac = self.compute_mac(kind, &raw[..TOKEN_NONCE_LEN]);
        raw[TOKEN_NONCE_LEN..].copy_from_slice(&mac);
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Strict Tier-1 verification: requires exact canonical 43-char unpadded
    /// base64url encoding AND matching MAC for `kind`. Zero heap allocations!
    #[inline]
    pub fn verify(&self, token: &str, kind: TokenKind) -> bool {
        let Some(cap) = parse_capability_strict(token) else {
            return false;
        };
        let raw = cap.0;
        let expected = self.compute_mac(kind, &raw[..TOKEN_NONCE_LEN]);
        bool::from(raw[TOKEN_NONCE_LEN..].ct_eq(&expected))
    }

    /// Lenient Tier-2 recognition: recognizes ANY base64 spelling (padded,
    /// standard alphabet, trailing bits, space-for-`+`) of a Bootstrap OR
    /// Session token minted by this key! Always checks BOTH kinds without
    /// short-circuiting. Fixes Go's Tier-2 padded-token leak bug!
    #[inline]
    pub fn is_authentic(&self, token: &str) -> bool {
        let Some(raw) = parse_capability_lenient(token) else {
            return false;
        };
        let mac_boot = self.compute_mac(TokenKind::Bootstrap, &raw[..TOKEN_NONCE_LEN]);
        let mac_sess = self.compute_mac(TokenKind::Session, &raw[..TOKEN_NONCE_LEN]);

        let eq_boot = raw[TOKEN_NONCE_LEN..].ct_eq(&mac_boot);
        let eq_sess = raw[TOKEN_NONCE_LEN..].ct_eq(&mac_sess);
        let found: Choice = eq_boot | eq_sess;
        bool::from(found)
    }

    #[inline]
    fn compute_mac(&self, kind: TokenKind, nonce: &[u8]) -> [u8; TOKEN_MAC_LEN] {
        let kind_byte = [kind as u8];
        let full = self.midstate.hmac_slices(&[TOKEN_LABEL, &kind_byte, nonce]);
        let mut out = [0u8; TOKEN_MAC_LEN];
        out.copy_from_slice(&full[..TOKEN_MAC_LEN]);
        out
    }
}

/// Atomically write a fresh 32-byte CSPRNG signing key (`0600`) to `path`,
/// refusing to overwrite an existing key file!
pub fn generate_token_key(path: &Path) -> Result<(), TokenError> {
    if path.exists() {
        return Err(TokenError::AlreadyExists(path.display().to_string()));
    }

    let mut key = Zeroizing::new([0u8; TOKEN_KEY_LEN]);
    getrandom::fill(&mut key[..]).map_err(|e| TokenError::Rng(e.to_string()))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                TokenError::AlreadyExists(path.display().to_string())
            } else {
                TokenError::Io(e)
            }
        })?;
    f.write_all(&key[..])?;
    f.sync_all()?;
    drop(f);

    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn signer_mint_verify_and_lenient_tier2_blocks_padded_leak() {
        let signer = Signer::new(&[0x42; TOKEN_KEY_LEN]).unwrap();
        let boot = signer.mint(TokenKind::Bootstrap).unwrap();
        let sess = signer.mint(TokenKind::Session).unwrap();
        assert_eq!(boot.len(), TOKEN_LEN);
        assert_eq!(sess.len(), TOKEN_LEN);

        assert!(signer.verify(&boot, TokenKind::Bootstrap));
        assert!(!signer.verify(&boot, TokenKind::Session));
        assert!(signer.verify(&sess, TokenKind::Session));
        assert!(!signer.verify(&sess, TokenKind::Bootstrap));

        // Tier-2 MUST recognize padded standard base64 spelling of a real token!
        let raw = URL_SAFE_NO_PAD.decode(&sess).unwrap();
        let padded_std = STANDARD.encode(&raw);
        assert!(!signer.verify(&padded_std, TokenKind::Session));
        assert!(signer.is_authentic(&padded_std));
    }
}
