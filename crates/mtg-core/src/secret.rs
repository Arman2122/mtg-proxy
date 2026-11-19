//! Telegram MTProto proxy secret, wire modes, obfuscated2 transport tags, and
//! retiring-secret metadata.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Length in bytes of an MTProto proxy secret key.
pub const SECRET_KEY_LEN: usize = 16;

const SECRET_FAKETLS_FIRST_BYTE: u8 = 0xee;
const SECRET_DD_FIRST_BYTE: u8 = 0xdd;
const EMPTY_KEY: [u8; SECRET_KEY_LEN] = [0u8; SECRET_KEY_LEN];

/// Maximum recommended overlap for a retiring key (30 days = 720 hours).
pub const MAX_RETIRING_OVERLAP: Duration = Duration::from_secs(720 * 3600);

/// Maximum retiring keys retained per secret name.
pub const MAX_RETIRING_PER_SECRET: usize = 4;

/// Maximum total retiring keys retained across the entire proxy.
pub const MAX_RETIRING_SECRETS: usize = 4096;

/// Errors returned when parsing or generating a [`Secret`] or [`SecretMode`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret is empty")]
    Empty,
    #[error("secret key is invalid (all zeros or missing hostname for ee mode)")]
    Invalid,
    #[error("incorrect secret format: must be valid hex or raw URL-safe base64")]
    IncorrectFormat,
    #[error("a 17-byte secret is the dd form and must start with 0xdd, got {0:#x}")]
    InvalidDdPrefix(u8),
    #[error("incorrect first byte of secret: {0:#x}")]
    InvalidFakeTlsPrefix(u8),
    #[error("hostname cannot be empty for ee secret")]
    EmptyHostname,
    #[error("hostname contains invalid non-ASCII bytes")]
    InvalidHostname,
    #[error(
        "unrecognised secret: {0} bytes (expected 16 for plain, 17 starting with 0xdd for dd, or 0xee followed by 16 key bytes and a hostname for ee)"
    )]
    UnrecognisedLength(usize),
    #[error("unknown secret mode {0:?} (expected one of \"dd\", \"ee\", \"plain\")")]
    UnknownMode(String),
    #[error("mode {0} requires a domain fronting hostname")]
    ModeRequiresHostname(SecretMode),
    #[error("mode {0} does not carry a hostname on the wire")]
    ModeForbidsHostname(SecretMode),
    #[error("OS random generator failed")]
    RandomFailure,
}

/// Wire presentation form of a secret.
///
/// The cryptographic key is identical in all three forms; `Mode` records how
/// the secret is encoded for client links and whether it carries a FakeTLS SNI
/// fronting hostname.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SecretMode {
    /// `0xee` + 16-byte key + ASCII hostname (FakeTLS). Default / zero value.
    #[default]
    FakeTls = 0,
    /// `0xdd` + 16-byte key (obfuscated2 padded-intermediate, no TLS).
    Dd = 1,
    /// Bare 16-byte key (obfuscated2, any transport tag, no TLS).
    Plain = 2,
}

impl SecretMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FakeTls => "ee",
            Self::Dd => "dd",
            Self::Plain => "plain",
        }
    }

    pub const fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
}

impl fmt::Display for SecretMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretMode {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ee" | "faketls" => Ok(Self::FakeTls),
            "dd" => Ok(Self::Dd),
            "plain" => Ok(Self::Plain),
            _ => Err(SecretError::UnknownMode(s.to_owned())),
        }
    }
}

impl Serialize for SecretMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Obfuscated2 4-byte transport tag located at byte offset 56 of the 64-byte
/// handshake frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionTag(pub [u8; 4]);

impl ConnectionTag {
    /// Abridged MTProto transport (`0xefefefef`).
    pub const ABRIDGED: Self = Self([0xef, 0xef, 0xef, 0xef]);
    /// Intermediate MTProto transport (`0xeeeeeeee`).
    pub const INTERMEDIATE: Self = Self([0xee, 0xee, 0xee, 0xee]);
    /// Padded-intermediate MTProto transport (`0xdddddddd`).
    pub const PADDED_INTERMEDIATE: Self = Self([0xdd, 0xdd, 0xdd, 0xdd]);

    pub const fn as_bytes(self) -> [u8; 4] {
        self.0
    }

    pub const fn as_u32_le(self) -> u32 {
        u32::from_le_bytes(self.0)
    }

    /// Map a raw 4-byte wire tag into its corresponding [`TagSet`] flag, if known.
    pub const fn to_flag(bytes: [u8; 4]) -> Option<(Self, TagSet)> {
        match bytes {
            [0xdd, 0xdd, 0xdd, 0xdd] => {
                Some((Self::PADDED_INTERMEDIATE, TagSet::PADDED_INTERMEDIATE))
            }
            [0xee, 0xee, 0xee, 0xee] => Some((Self::INTERMEDIATE, TagSet::INTERMEDIATE)),
            [0xef, 0xef, 0xef, 0xef] => Some((Self::ABRIDGED, TagSet::ABRIDGED)),
            _ => None,
        }
    }
}

bitflags! {
    /// Bitset of allowed obfuscated2 transport tags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TagSet: u8 {
        const PADDED_INTERMEDIATE = 1 << 0;
        const INTERMEDIATE        = 1 << 1;
        const ABRIDGED            = 1 << 2;
    }
}

impl TagSet {
    /// Check whether raw 4-byte wire tag belongs to this set and return the
    /// matched [`ConnectionTag`].
    #[inline]
    pub const fn match_bytes(self, bytes: [u8; 4]) -> Option<ConnectionTag> {
        match ConnectionTag::to_flag(bytes) {
            Some((tag, flag)) if self.contains(flag) => Some(tag),
            _ => None,
        }
    }
}

bitflags! {
    /// Bitset of [`SecretMode`] values enabled on a listener or proxy.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ModeSet: u8 {
        const FAKE_TLS = 1 << 0;
        const DD       = 1 << 1;
        const PLAIN    = 1 << 2;
    }
}

impl ModeSet {
    pub fn of(modes: &[SecretMode]) -> Self {
        let mut set = Self::empty();
        for &m in modes {
            set |= Self::from_mode(m);
        }
        set
    }

    pub const fn from_mode(mode: SecretMode) -> Self {
        match mode {
            SecretMode::FakeTls => Self::FAKE_TLS,
            SecretMode::Dd => Self::DD,
            SecretMode::Plain => Self::PLAIN,
        }
    }

    pub const fn has(self, mode: SecretMode) -> bool {
        self.contains(Self::from_mode(mode))
    }

    pub fn parse_names<S: AsRef<str>>(names: &[S]) -> Result<Self, SecretError> {
        let mut set = Self::empty();
        for name in names {
            let mode = SecretMode::from_str(name.as_ref())?;
            set |= Self::from_mode(mode);
        }
        Ok(set)
    }

    /// Sorted canonical mode names (`"dd"`, `"ee"`, `"plain"`).
    pub fn sorted_names(self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(3);
        if self.contains(Self::DD) {
            out.push("dd");
        }
        if self.contains(Self::FAKE_TLS) {
            out.push("ee");
        }
        if self.contains(Self::PLAIN) {
            out.push("plain");
        }
        out
    }

    /// Obfuscated2 transport tags honoured at frame offset 56 for this mode set.
    ///
    /// - `dd` honours padded-intermediate (`0xdddddddd`) only.
    /// - `plain` honours all three transports (`0xdddddddd`, `0xeeeeeeee`, `0xefefefef`).
    pub const fn tags(self) -> TagSet {
        let mut tags = TagSet::empty();
        if self.contains(Self::DD) {
            tags = tags.union(TagSet::PADDED_INTERMEDIATE);
        }
        if self.contains(Self::PLAIN) {
            tags = tags
                .union(TagSet::PADDED_INTERMEDIATE)
                .union(TagSet::INTERMEDIATE)
                .union(TagSet::ABRIDGED);
        }
        tags
    }
}

impl fmt::Display for ModeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.sorted_names();
        for (idx, name) in names.iter().enumerate() {
            if idx > 0 {
                f.write_str(",")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

/// A parsed Telegram MTProto proxy secret.
///
/// Key material is stored in [`Zeroizing`] and wiped on drop. `Debug`
/// intentionally redacts key bytes so credentials cannot leak into logs or
/// panic traces.
#[derive(Clone)]
pub struct Secret {
    key: Zeroizing<[u8; SECRET_KEY_LEN]>,
    host: String,
    mode: SecretMode,
}

impl Secret {
    /// Construct a secret directly from validated parts.
    pub fn from_parts(
        key: [u8; SECRET_KEY_LEN],
        host: impl Into<String>,
        mode: SecretMode,
    ) -> Self {
        Self {
            key: Zeroizing::new(key),
            host: host.into(),
            mode,
        }
    }

    /// Construct a new random FakeTLS (`ee`) secret for `hostname`.
    pub fn generate(hostname: impl Into<String>) -> Result<Self, SecretError> {
        Self::generate_mode(SecretMode::FakeTls, hostname.into())
    }

    /// Construct a new random secret in the requested mode.
    pub fn generate_mode(
        mode: SecretMode,
        hostname: impl Into<String>,
    ) -> Result<Self, SecretError> {
        let host = hostname.into();
        match mode {
            SecretMode::FakeTls => {
                if host.is_empty() {
                    return Err(SecretError::ModeRequiresHostname(mode));
                }
                if !host.is_ascii() {
                    return Err(SecretError::InvalidHostname);
                }
            }
            SecretMode::Dd | SecretMode::Plain => {
                if !host.is_empty() {
                    return Err(SecretError::ModeForbidsHostname(mode));
                }
            }
        }

        let mut key = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        loop {
            getrandom::fill(&mut *key).map_err(|_| SecretError::RandomFailure)?;
            if key.as_slice().ct_eq(&EMPTY_KEY).unwrap_u8() == 0 {
                break;
            }
        }

        Ok(Self { key, host, mode })
    }

    /// Parse a secret from hex or raw URL-safe base64.
    pub fn parse(text: &str) -> Result<Self, SecretError> {
        if text.is_empty() {
            return Err(SecretError::Empty);
        }

        let mut decoded = hex::decode(text)
            .or_else(|_| URL_SAFE_NO_PAD.decode(text))
            .map_err(|_| SecretError::IncorrectFormat)?;

        let result = Self::from_wire_bytes(&decoded);
        decoded.zeroize();
        result
    }

    /// Parse a secret from raw decoded wire bytes.
    ///
    /// Length discriminates before the first byte does, matching tdlib's
    /// `ProxySecret::from_binary`:
    /// - 16 bytes -> `plain`
    /// - 17 bytes starting with `0xdd` -> `dd`
    /// - >17 bytes starting with `0xee` -> `ee` + 16-byte key + non-empty ASCII host
    pub fn from_wire_bytes(decoded: &[u8]) -> Result<Self, SecretError> {
        let (mode, key_slice, host) = match decoded.len() {
            SECRET_KEY_LEN => (SecretMode::Plain, decoded, String::new()),
            n if n == SECRET_KEY_LEN + 1 => {
                if decoded[0] != SECRET_DD_FIRST_BYTE {
                    return Err(SecretError::InvalidDdPrefix(decoded[0]));
                }
                (SecretMode::Dd, &decoded[1..], String::new())
            }
            n if n > SECRET_KEY_LEN + 1 => {
                if decoded[0] != SECRET_FAKETLS_FIRST_BYTE {
                    return Err(SecretError::InvalidFakeTlsPrefix(decoded[0]));
                }
                let host_bytes = &decoded[1 + SECRET_KEY_LEN..];
                if host_bytes.is_empty() {
                    return Err(SecretError::EmptyHostname);
                }
                let host = std::str::from_utf8(host_bytes)
                    .map_err(|_| SecretError::InvalidHostname)?
                    .to_owned();
                (SecretMode::FakeTls, &decoded[1..=SECRET_KEY_LEN], host)
            }
            n => return Err(SecretError::UnrecognisedLength(n)),
        };

        let mut key = [0u8; SECRET_KEY_LEN];
        key.copy_from_slice(key_slice);

        if key.ct_eq(&EMPTY_KEY).unwrap_u8() == 1 {
            key.zeroize();
            return Err(SecretError::Invalid);
        }

        Ok(Self {
            key: Zeroizing::new(key),
            host,
            mode,
        })
    }

    #[inline]
    pub fn key(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.key
    }

    #[inline]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[inline]
    pub const fn mode(&self) -> SecretMode {
        self.mode
    }

    /// True if key is non-zero and `ee` mode carries a non-empty host.
    #[inline]
    pub fn is_valid(&self) -> bool {
        if self.key.as_slice().ct_eq(&EMPTY_KEY).unwrap_u8() == 1 {
            return false;
        }
        self.mode != SecretMode::FakeTls || !self.host.is_empty()
    }

    /// True if this secret can serve the FakeTLS (`ee`) entry.
    #[inline]
    pub const fn is_hosted(&self) -> bool {
        matches!(self.mode, SecretMode::FakeTls)
    }

    /// Wire bytes in this secret's own mode form.
    pub fn to_wire_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = match self.mode {
            SecretMode::Plain => Vec::with_capacity(SECRET_KEY_LEN),
            SecretMode::Dd => Vec::with_capacity(1 + SECRET_KEY_LEN),
            SecretMode::FakeTls => Vec::with_capacity(1 + SECRET_KEY_LEN + self.host.len()),
        };

        match self.mode {
            SecretMode::Plain => buf.extend_from_slice(&*self.key),
            SecretMode::Dd => {
                buf.push(SECRET_DD_FIRST_BYTE);
                buf.extend_from_slice(&*self.key);
            }
            SecretMode::FakeTls => {
                buf.push(SECRET_FAKETLS_FIRST_BYTE);
                buf.extend_from_slice(&*self.key);
                buf.extend_from_slice(self.host.as_bytes());
            }
        }

        Zeroizing::new(buf)
    }

    /// Canonical raw URL-safe base64 encoding (matches Go `Secret.String()` / `Base64()`).
    pub fn encode_base64(&self) -> String {
        let raw = self.to_wire_bytes();
        URL_SAFE_NO_PAD.encode(raw.as_slice())
    }

    /// Hex encoding in this secret's own mode form.
    pub fn encode_hex(&self) -> String {
        let raw = self.to_wire_bytes();
        hex::encode(raw.as_slice())
    }

    /// Hex encoding of this key in `dd` link form (`dd` + 16 key bytes).
    pub fn encode_dd_hex(&self) -> String {
        let mut raw = Zeroizing::new([0u8; 1 + SECRET_KEY_LEN]);
        raw[0] = SECRET_DD_FIRST_BYTE;
        raw[1..].copy_from_slice(&*self.key);
        hex::encode(raw.as_slice())
    }

    /// Hex encoding of this key in `plain` link form (bare 16 key bytes).
    pub fn encode_plain_hex(&self) -> String {
        hex::encode(self.key.as_slice())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        let keys_eq = self.key.as_slice().ct_eq(other.key.as_slice()).unwrap_u8() == 1;
        keys_eq && self.mode == other.mode && self.host == other.host
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("mode", &self.mode)
            .field("host", &self.host)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl FromStr for Secret {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.is_valid() {
            serializer.serialize_str(&self.encode_base64())
        } else {
            serializer.serialize_str("")
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Secret::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A previous secret key still accepted for a named secret during a rotation
/// overlap window until `until`.
#[derive(Clone, PartialEq, Eq)]
pub struct RetiringSecret {
    pub name: String,
    pub secret: Secret,
    pub until: DateTime<Utc>,
}

impl fmt::Debug for RetiringSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetiringSecret")
            .field("name", &self.name)
            .field("until", &self.until)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Machine-friendly reason why a retiring secret entry was dropped while
/// building a secret set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetiringDropReason {
    Invalid,
    Expired,
    Dangling,
    KeyOfOtherSecret,
    SameAsPrimary,
    Duplicate,
    OverCap,
}

impl RetiringDropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::Dangling => "dangling",
            Self::KeyOfOtherSecret => "key_of_other_secret",
            Self::SameAsPrimary => "same_as_primary",
            Self::Duplicate => "duplicate",
            Self::OverCap => "over_cap",
        }
    }
}

impl fmt::Display for RetiringDropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_dd_and_ee_discriminates_by_length_first() {
        // 16 bytes starting with 0xee MUST parse as plain (not ee!).
        let plain_starting_ee = "ee0102030405060708090a0b0c0d0e0f";
        let s = Secret::parse(plain_starting_ee).unwrap();
        assert_eq!(s.mode(), SecretMode::Plain);
        assert_eq!(s.host(), "");
        assert_eq!(s.encode_hex(), plain_starting_ee);
        assert!(s.is_valid());
        assert!(!s.is_hosted());

        // 16 bytes starting with 0xdd MUST parse as plain.
        let plain_starting_dd = "dd0102030405060708090a0b0c0d0e0f";
        let s = Secret::parse(plain_starting_dd).unwrap();
        assert_eq!(s.mode(), SecretMode::Plain);

        // 17 bytes starting with 0xdd -> dd.
        let dd_hex = "dd0102030405060708090a0b0c0d0e0f10";
        let s = Secret::parse(dd_hex).unwrap();
        assert_eq!(s.mode(), SecretMode::Dd);
        assert_eq!(s.host(), "");
        assert_eq!(s.encode_dd_hex(), dd_hex);
        assert_eq!(s.encode_plain_hex(), "0102030405060708090a0b0c0d0e0f10");

        // 17 bytes NOT starting with 0xdd -> error.
        assert!(matches!(
            Secret::parse("ee0102030405060708090a0b0c0d0e0f10"),
            Err(SecretError::InvalidDdPrefix(0xee))
        ));

        // ee + 16 bytes + host (hex & base64 roundtrip).
        let ee_hex =
            "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d";
        let s = Secret::parse(ee_hex).unwrap();
        assert_eq!(s.mode(), SecretMode::FakeTls);
        assert_eq!(s.host(), "storage.googleapis.com");
        assert!(s.is_hosted());
        assert_eq!(s.encode_hex(), ee_hex);
        let b64 = s.encode_base64();
        let s2 = Secret::parse(&b64).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn rejects_all_zero_key_in_all_modes() {
        assert_eq!(
            Secret::parse("00000000000000000000000000000000"),
            Err(SecretError::Invalid)
        );
        assert_eq!(
            Secret::parse("dd00000000000000000000000000000000"),
            Err(SecretError::Invalid)
        );
        assert_eq!(
            Secret::parse("ee00000000000000000000000000000000676f6f676c652e636f6d"),
            Err(SecretError::Invalid)
        );
    }

    #[test]
    fn debug_redacts_secret_key() {
        let s = Secret::generate("example.com").unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&s.encode_plain_hex()));
        assert!(!dbg.contains(&s.encode_base64()));
    }

    #[test]
    fn mode_set_tags_match_protocol() {
        assert_eq!(ModeSet::FAKE_TLS.tags(), TagSet::empty());
        assert_eq!(ModeSet::DD.tags(), TagSet::PADDED_INTERMEDIATE);
        assert_eq!(
            ModeSet::PLAIN.tags(),
            TagSet::PADDED_INTERMEDIATE | TagSet::INTERMEDIATE | TagSet::ABRIDGED
        );
        assert_eq!(
            ModeSet::of(&[SecretMode::Plain, SecretMode::FakeTls, SecretMode::Dd]).to_string(),
            "dd,ee,plain"
        );
    }
}
