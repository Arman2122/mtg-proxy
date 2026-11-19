//! Per-secret operator IP ban list (`IpUnit`-keyed, atomic zero-lock fast path,
//! 4,096 global cap, `force` guard against non-personal/loopback/private IPs).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use mtg_core::{IpUnit, is_personal_ip};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use serde::Serialize;
use thiserror::Error;

/// Default ban duration when request omits `ttl` (`1h`).
pub const DEFAULT_BAN_TTL: Duration = Duration::from_secs(3600);
/// Maximum allowed ban TTL (`30d`).
pub const MAX_BAN_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Global maximum simultaneous bans across all secrets (`4096`).
pub const MAX_BANS: usize = 4096;

/// Errors returned by ban request parsing or ban insertion.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BanError {
    #[error("invalid ban addresses: {0}")]
    InvalidAddress(String),
    #[error("ban list full: {held} bans held, {fresh} more asked for, the most is {MAX_BANS}")]
    ListFull { held: usize, fresh: usize },
}

/// One active ban entry for `GET /secrets/{name}/bans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BanEntryJson {
    pub address: String,
    pub expires_at: DateTime<Utc>,
}

/// Parse one ban/unban target: literal IPv4, literal IPv6, or IPv6 `/64` prefix.
pub fn parse_ban_unit(text: &str) -> Result<IpUnit, BanError> {
    if text.contains('%') {
        return Err(BanError::InvalidAddress(format!("{text:?} carries a zone")));
    }
    text.parse::<IpUnit>()
        .map_err(|e| BanError::InvalidAddress(format!("{text:?}: {e}")))
}

/// Validate a `POST /secrets/{name}/bans` request payload (exact parity with
/// Go `ParseBanAddresses`, refusing loopback/private/link-local unless `force = true`).
pub fn parse_ban_request(
    ips: &[String],
    ttl_str: &str,
    force: bool,
) -> Result<(Vec<IpUnit>, Duration), BanError> {
    if ips.is_empty() {
        return Err(BanError::InvalidAddress("no addresses".to_owned()));
    }
    if ips.len() > MAX_BANS {
        return Err(BanError::InvalidAddress(format!(
            "{} addresses, the most one request may name is {MAX_BANS}",
            ips.len()
        )));
    }
    let mut units = Vec::with_capacity(ips.len());
    for text in ips {
        let unit = parse_ban_unit(text)?;
        if !force && !is_personal_ip(unit.base_ip()) {
            return Err(BanError::InvalidAddress(format!(
                "{text:?}, banned as {unit}, is or takes in an address that does not stand for one place, \
                 and behind a front or a PROXY-protocol listener such an address can be every client; \
                 send \"force\": true to ban it anyway"
            )));
        }
        units.push(unit);
    }

    let ttl = if ttl_str.is_empty() {
        DEFAULT_BAN_TTL
    } else {
        let d = mtg_config::parse_duration(ttl_str)
            .map_err(|e| BanError::InvalidAddress(format!("ttl {ttl_str:?}: {e}")))?;
        if d.is_zero() || d > MAX_BAN_TTL {
            return Err(BanError::InvalidAddress(format!(
                "ttl {ttl_str:?} is outside (0, 720h]"
            )));
        }
        d
    };
    Ok((units, ttl))
}

/// Per-secret IP ban store with 1-atomic-load zero-lock fast path when empty.
#[derive(Debug, Default)]
pub struct BanList {
    held: AtomicI64,
    bans: Mutex<FxHashMap<String, FxHashMap<IpUnit, DateTime<Utc>>>>,
}

impl BanList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fast-path check (1 atomic load when no bans exist!).
    #[inline]
    pub fn is_empty_fast(&self) -> bool {
        self.held.load(Ordering::Acquire) == 0
    }

    /// Return `true` if `unit` is currently banned for `secret_name` at `now`.
    /// Lazily prunes an expired ban if encountered.
    pub fn is_banned(&self, secret_name: &str, unit: IpUnit, now: DateTime<Utc>) -> bool {
        if self.is_empty_fast() {
            return false;
        }
        let mut map = self.bans.lock();
        let Some(sec) = map.get_mut(secret_name) else {
            return false;
        };
        let Some(&until) = sec.get(&unit) else {
            return false;
        };
        if now < until {
            return true;
        }
        sec.remove(&unit);
        if sec.is_empty() {
            map.remove(secret_name);
        }
        self.held.fetch_sub(1, Ordering::AcqRel);
        false
    }

    /// Atomically add bans for all deduplicated `units` on `secret_name` for `ttl`.
    /// All-or-nothing against `MAX_BANS` after pruning expired entries.
    pub fn add(
        &self,
        secret_name: &str,
        units: &[IpUnit],
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<IpUnit>, BanError> {
        let until = now + chrono::Duration::from_std(ttl).unwrap_or_default();
        let mut map = self.bans.lock();
        self.prune_locked(&mut map, now);

        let mut dedup: Vec<IpUnit> = Vec::with_capacity(units.len());
        let mut fresh = 0usize;
        let existing = map.get(secret_name);
        for &u in units {
            if dedup.contains(&u) {
                continue;
            }
            dedup.push(u);
            if existing.is_none_or(|m| !m.contains_key(&u)) {
                fresh += 1;
            }
        }

        let cur_held = self.held.load(Ordering::Acquire).max(0) as usize;
        if cur_held + fresh > MAX_BANS {
            return Err(BanError::ListFull {
                held: cur_held,
                fresh,
            });
        }

        let sec = map.entry(secret_name.to_owned()).or_default();
        for &u in &dedup {
            sec.insert(u, until);
        }
        self.held.fetch_add(fresh as i64, Ordering::AcqRel);
        Ok(dedup)
    }

    /// Lift one ban; returns `true` if a live ban was removed.
    pub fn remove(&self, secret_name: &str, unit: IpUnit, now: DateTime<Utc>) -> bool {
        if self.is_empty_fast() {
            return false;
        }
        let mut map = self.bans.lock();
        self.prune_locked(&mut map, now);
        let Some(sec) = map.get_mut(secret_name) else {
            return false;
        };
        let removed = sec.remove(&unit).is_some();
        if removed {
            if sec.is_empty() {
                map.remove(secret_name);
            }
            self.held.fetch_sub(1, Ordering::AcqRel);
        }
        removed
    }

    /// Count active bans on `secret_name`.
    pub fn count(&self, secret_name: &str, now: DateTime<Utc>) -> usize {
        if self.is_empty_fast() {
            return 0;
        }
        let mut map = self.bans.lock();
        self.prune_locked(&mut map, now);
        map.get(secret_name).map_or(0, FxHashMap::len)
    }

    /// Sorted active bans for `GET /secrets/{name}/bans`.
    pub fn list(&self, secret_name: &str, now: DateTime<Utc>) -> Vec<BanEntryJson> {
        if self.is_empty_fast() {
            return Vec::new();
        }
        let mut map = self.bans.lock();
        self.prune_locked(&mut map, now);
        let Some(sec) = map.get(secret_name) else {
            return Vec::new();
        };
        let mut out: Vec<BanEntryJson> = sec
            .iter()
            .map(|(u, &exp)| BanEntryJson {
                address: u.to_string(),
                expires_at: exp,
            })
            .collect();
        out.sort_by(|a, b| a.address.cmp(&b.address));
        out
    }

    /// Snapshot map of `IpUnit -> expires_at` for `secret_name` (used by `/clients`).
    pub fn until_map(
        &self,
        secret_name: &str,
        now: DateTime<Utc>,
    ) -> FxHashMap<IpUnit, DateTime<Utc>> {
        if self.is_empty_fast() {
            return FxHashMap::default();
        }
        let mut map = self.bans.lock();
        self.prune_locked(&mut map, now);
        map.get(secret_name).cloned().unwrap_or_default()
    }

    /// Remove all bans for a deleted secret.
    pub fn drop_secret(&self, secret_name: &str) {
        if self.is_empty_fast() {
            return;
        }
        let mut map = self.bans.lock();
        if let Some(sec) = map.remove(secret_name) {
            self.held.fetch_sub(sec.len() as i64, Ordering::AcqRel);
        }
    }

    fn prune_locked(
        &self,
        map: &mut FxHashMap<String, FxHashMap<IpUnit, DateTime<Utc>>>,
        now: DateTime<Utc>,
    ) {
        let mut removed = 0i64;
        map.retain(|_, sec| {
            let before = sec.len();
            sec.retain(|_, &mut until| now < until);
            removed += (before - sec.len()) as i64;
            !sec.is_empty()
        });
        if removed > 0 {
            self.held.fetch_sub(removed, Ordering::AcqRel);
        }
    }
}
