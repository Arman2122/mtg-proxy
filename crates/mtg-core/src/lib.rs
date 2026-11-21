//! Core domain types for `mtg-rs`.
//!
//! Contains secrets, transport modes & tags, normalized IP accounting units,
//! per-secret governance limits & parsers, and the monotonic wall-clock
//! high-water mark (`RotationClock`).

pub mod clock;
pub mod ip;
pub mod limits;
pub mod secret;

pub use clock::RotationClock;
pub use ip::{IpUnit, is_personal_ip};
pub use limits::{
    DenyReason, FairTotals, GlobalLimits, LimitParseError, MIN_SPEED_BYTES_PER_SECOND, QuotaReset,
    SecretLimits, parse_expiry, parse_quota_bytes, parse_quota_reset, parse_speed,
};
pub use secret::{
    ConnectionTag, MAX_RETIRING_OVERLAP, MAX_RETIRING_PER_SECRET, MAX_RETIRING_SECRETS, ModeSet,
    RetiringDropReason, RetiringSecret, SECRET_KEY_LEN, Secret, SecretError, SecretMode, TagSet,
};
