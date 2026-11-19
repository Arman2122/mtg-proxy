//! WEB proxy v1 bridge capability derivation, UTS #46 canonical hostname
//! validation, lenient/strict base64url parsing, and constant-time profile
//! registry (live + retired keys).

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use mtg_core::{Secret, SecretMode};
use mtg_crypto::sha256_fast::HmacSha256Midstate;
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _};
use thiserror::Error;

/// Pinned v1 capability derivation label (matches Telegram clients & Go).
pub const BRIDGE_CONTEXT_LABEL: &[u8] = b"tdesktop-web-proxy-bridge-v1\n";

/// Canonical unpadded base64url length of a 32-byte capability / token.
pub const CAPABILITY_LEN: usize = 43;

/// Maximum configured live (and separately retired) profiles scanned per request.
pub const MAX_PROFILES: usize = 4096;

/// Errors returned by [`canonical_host`], [`derive_capability`], or [`Registry::new`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("hostname is not a canonical WEB proxy host: {0}")]
    InvalidHost(String),
    #[error("secret mode {0} is not usable for a WEB proxy (WEB accepts dd or plain)")]
    UnsupportedSecretMode(SecretMode),
    #[error("secret is not valid: {0}")]
    InvalidSecret(String),
    #[error("two profiles derive the same bridge capability (profiles {0} and {1})")]
    Collision(usize, usize),
    #[error("no WEB proxy profiles configured")]
    NoProfiles,
    #[error("more WEB proxy profiles than the maximum ({0} > {MAX_PROFILES})")]
    TooManyProfiles(usize),
}

/// 32-byte HMAC-SHA256 bridge capability.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capability(pub [u8; 32]);

impl Capability {
    /// Render in canonical unpadded base64url (always 43 chars).
    pub fn encode_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Capability([redacted])")
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode_base64url())
    }
}

/// Re-express any [`Secret`] (`ee`, `dd`, or `plain`) in the `dd` form a WEB
/// client holds (preserving the exact 16 key bytes).
pub fn web_secret(secret: &Secret) -> Secret {
    Secret::from_parts(*secret.key(), String::new(), SecretMode::Dd)
}

/// Normalize and validate a configured `[web] host` using UTS #46 (`idna`),
/// enforcing lowercase LDH output, DNS label/length limits, fixed-point
/// idempotence, and rejecting URL delimiters, IP literals, single-label names,
/// empty labels, and trailing dots.
pub fn canonical_host(host: &str) -> Result<String, CapabilityError> {
    if host.is_empty() {
        return Err(CapabilityError::InvalidHost("empty".to_owned()));
    }
    if let Some(ch) = host
        .chars()
        .find(|&c| matches!(c, ':' | '/' | '?' | '#' | '@'))
    {
        return Err(CapabilityError::InvalidHost(format!(
            "must not contain {ch:?}"
        )));
    }
    if host.ends_with('.') {
        return Err(CapabilityError::InvalidHost(
            "has a trailing dot".to_owned(),
        ));
    }

    let ascii = idna::domain_to_ascii_strict(host)
        .map_err(|_| CapabilityError::InvalidHost("IDNA conversion failed".to_owned()))?;

    if !ascii
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(CapabilityError::InvalidHost(
            "mapped host is not lowercase LDH".to_owned(),
        ));
    }

    // Fixed-point idempotence check
    let remapped = idna::domain_to_ascii_strict(&ascii)
        .map_err(|_| CapabilityError::InvalidHost("mapped host is not idempotent".to_owned()))?;
    if remapped != ascii {
        return Err(CapabilityError::InvalidHost(
            "mapped host is not a fixed point".to_owned(),
        ));
    }

    if ascii.ends_with('.') {
        return Err(CapabilityError::InvalidHost(
            "has a trailing dot".to_owned(),
        ));
    }
    if ascii.starts_with('.') || ascii.contains("..") {
        return Err(CapabilityError::InvalidHost(
            "has an empty label".to_owned(),
        ));
    }
    if ascii.parse::<IpAddr>().is_ok() {
        return Err(CapabilityError::InvalidHost("is an IP address".to_owned()));
    }
    if !ascii.contains('.') {
        return Err(CapabilityError::InvalidHost(
            "is a single-label name".to_owned(),
        ));
    }

    Ok(ascii)
}

/// Derive the 32-byte bridge capability for a `dd` or `plain` [`Secret`] on `host`.
pub fn derive_capability(secret: &Secret, host: &str) -> Result<Capability, CapabilityError> {
    let canonical = canonical_host(host)?;
    if !secret.is_valid() {
        return Err(CapabilityError::InvalidSecret(format!(
            "{} secret with empty key",
            secret.mode()
        )));
    }

    let mut dd_key = [0u8; 17];
    let key_slice: &[u8] = match secret.mode() {
        SecretMode::Dd => {
            dd_key[0] = 0xdd;
            dd_key[1..].copy_from_slice(secret.key());
            &dd_key
        }
        SecretMode::Plain => secret.key(),
        SecretMode::FakeTls => {
            return Err(CapabilityError::UnsupportedSecretMode(SecretMode::FakeTls));
        }
    };

    let mid = HmacSha256Midstate::new(key_slice);
    let mac = mid.hmac_slices(&[BRIDGE_CONTEXT_LABEL, canonical.as_bytes()]);
    Ok(Capability(mac))
}

/// Strict canonical decoder: accepts ONLY 43-char unpadded base64url whose
/// trailing unused bits are zero (exact round-trip match).
#[inline]
pub fn parse_capability_strict(param: &str) -> Option<Capability> {
    if param.len() != CAPABILITY_LEN {
        return None;
    }
    let mut out = [0u8; 32];
    let n = URL_SAFE_NO_PAD
        .decode_slice(param.as_bytes(), &mut out)
        .ok()?;
    if n != 32 {
        return None;
    }
    // Verify canonical encoding (zero unused low bits in 43rd char) with 0 heap allocs.
    let mut reencoded = [0u8; 44];
    let rlen = URL_SAFE_NO_PAD.encode_slice(out, &mut reencoded).ok()?;
    if rlen != CAPABILITY_LEN || &reencoded[..CAPABILITY_LEN] != param.as_bytes() {
        return None;
    }
    Some(Capability(out))
}

/// Lenient Tier-2 decoder: recognizes ANY base64 spelling of a 32-byte value
/// (URL or Standard alphabet, padded or unpadded, ignoring trailing bits, and
/// restoring spaces turned from `+` by form-query decoders). Zero allocations
/// when no spaces are present!
pub fn parse_capability_lenient(param: &str) -> Option<[u8; 32]> {
    if let Some(raw) = decode_any_base64_32(param.as_bytes()) {
        return Some(raw);
    }
    if param.as_bytes().contains(&b' ') && param.len() <= 44 {
        let mut buf = [0u8; 44];
        for (dst, &src) in buf[..param.len()].iter_mut().zip(param.as_bytes()) {
            *dst = if src == b' ' { b'+' } else { src };
        }
        return decode_any_base64_32(&buf[..param.len()]);
    }
    None
}

fn decode_any_base64_32(input: &[u8]) -> Option<[u8; 32]> {
    use base64::engine::DecodePaddingMode;
    use base64::engine::general_purpose::GeneralPurposeConfig;

    const LENIENT_CFG: GeneralPurposeConfig = GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);

    if input.len() != 43 && input.len() != 44 {
        return None;
    }
    let url_eng = base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, LENIENT_CFG);
    let std_eng = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, LENIENT_CFG);

    let mut out = [0u8; 32];
    if url_eng.decode_slice(input, &mut out).is_ok_and(|n| n == 32) {
        return Some(out);
    }
    if std_eng.decode_slice(input, &mut out).is_ok_and(|n| n == 32) {
        return Some(out);
    }
    let _ = (STANDARD, STANDARD_NO_PAD, URL_SAFE);
    None
}

/// Constant-time capability registry (live profiles + retired rotation keys).
#[derive(Debug, Clone)]
pub struct Registry {
    capabilities: Vec<Capability>,
    retired: Vec<Capability>,
}

impl Registry {
    /// Build a registry for `host` from active `secrets` (re-spelled via [`web_secret`])
    /// and optional `retired` rotation secrets (silently deduped and capped at
    /// `MAX_PROFILES`).
    pub fn new(
        host: &str,
        secrets: &[Secret],
        retired: &[Secret],
    ) -> Result<Self, CapabilityError> {
        if secrets.is_empty() {
            return Err(CapabilityError::NoProfiles);
        }
        if secrets.len() > MAX_PROFILES {
            return Err(CapabilityError::TooManyProfiles(secrets.len()));
        }

        let canonical = canonical_host(host)?;
        let mut capabilities = Vec::with_capacity(secrets.len());
        for (i, s) in secrets.iter().enumerate() {
            let cap = derive_capability(&web_secret(s), &canonical)?;
            for (j, other) in capabilities.iter().enumerate() {
                if other == &cap {
                    return Err(CapabilityError::Collision(j, i));
                }
            }
            capabilities.push(cap);
        }

        let mut seen: HashSet<Capability> = capabilities.iter().copied().collect();
        let mut retired_caps = Vec::with_capacity(retired.len().min(MAX_PROFILES));
        for s in retired {
            if retired_caps.len() >= MAX_PROFILES {
                break;
            }
            if let Ok(cap) = derive_capability(&web_secret(s), &canonical)
                && seen.insert(cap)
            {
                retired_caps.push(cap);
            }
        }

        Ok(Self {
            capabilities,
            retired: retired_caps,
        })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    #[inline]
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// Strict Tier-1 lookup: scans EVERY live capability without breaking early
    /// so execution time never leaks which profile matched (or whether one did).
    pub fn lookup(&self, param: &str) -> Option<usize> {
        let presented = parse_capability_strict(param)?;
        let mut selected: u32 = 0;
        let mut found = Choice::from(0u8);

        for (i, cap) in self.capabilities.iter().enumerate() {
            let eq = cap.0.ct_eq(&presented.0);
            selected.conditional_assign(&(i as u32), eq);
            found |= eq;
        }

        if bool::from(found) {
            Some(selected as usize)
        } else {
            None
        }
    }

    /// Lenient Tier-2 authenticity scan: compares against EVERY live capability
    /// AND EVERY retired capability without early return.
    ///
    /// Returns `true` if `param` is any base64 spelling of a live or retired
    /// capability — caller MUST answer locally with an uncacheable 404 and NEVER
    /// forward to the cover site!
    pub fn is_authentic(&self, param: &str) -> bool {
        let Some(presented) = parse_capability_lenient(param) else {
            return false;
        };
        let mut found = Choice::from(0u8);
        for cap in &self.capabilities {
            found |= cap.0.ct_eq(&presented);
        }
        for cap in &self.retired {
            found |= cap.0.ct_eq(&presented);
        }
        bool::from(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_host_rules_and_idna() {
        assert_eq!(
            canonical_host("Proxy.Example.COM").unwrap(),
            "proxy.example.com"
        );
        assert!(canonical_host("").is_err());
        assert!(canonical_host("localhost").is_err());
        assert!(canonical_host("127.0.0.1").is_err());
        assert!(canonical_host("proxy.example.com.").is_err());
        assert!(canonical_host("https://proxy.example.com").is_err());
        assert!(canonical_host("proxy.example.com:443").is_err());
        assert!(canonical_host("a..b.com").is_err());
    }

    #[test]
    fn strict_vs_lenient_and_retired_recognition() {
        let s1 = Secret::generate_mode(SecretMode::FakeTls, "cover.example.com").unwrap();
        let s2 = Secret::generate_mode(SecretMode::Dd, "").unwrap();
        let reg = Registry::new(
            "proxy.example.test",
            std::slice::from_ref(&s1),
            std::slice::from_ref(&s2),
        )
        .unwrap();

        let live_cap = derive_capability(&web_secret(&s1), "proxy.example.test").unwrap();
        let ret_cap = derive_capability(&web_secret(&s2), "proxy.example.test").unwrap();

        assert_eq!(reg.lookup(&live_cap.encode_base64url()), Some(0));
        assert!(reg.is_authentic(&live_cap.encode_base64url()));

        // Padded standard base64 fails strict lookup, MUST pass Tier-2 is_authentic!
        let padded_std = STANDARD.encode(live_cap.0);
        assert_eq!(reg.lookup(&padded_std), None);
        assert!(reg.is_authentic(&padded_std));

        // Retired key fails strict lookup, MUST pass Tier-2 is_authentic!
        assert_eq!(reg.lookup(&ret_cap.encode_base64url()), None);
        assert!(reg.is_authentic(&ret_cap.encode_base64url()));
    }
}
