//! Lock-free `ArcSwap<SecretSet>` secret catalog with:
//! - Cross-reload `FakeTlsCandidate` HMAC midstate caching (adding 1 secret out
//!   of 5,000 recomputes ONLY 1 midstate instead of 5,000!)
//! - **SNI-first candidate partitioning**: buckets candidates by lowercase SNI
//!   hostname so FakeTLS handshakes try ONLY the matching SNI bucket before
//!   falling back to the full list!
//! - Primary + retiring keys (8-rule validated via `mtg-config` + live
//!   [`RotationClock`] expiry enforcement!)
//! - Pre-built Obfuscated2 (`dd`/`plain`) key slice for zero-alloc matching
//! - Pre-filtered `fair_secrets` list so the 1s fair-share ticker ONLY visits
//!   secrets with `client-fair = true`!

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mtg_config::Config;
use mtg_core::{
    FairTotals, ModeSet, RetiringSecret, RotationClock, SECRET_KEY_LEN, Secret, SecretLimits,
    SecretMode,
};
use mtg_crypto::faketls::FakeTlsCandidate;
use rustc_hash::FxHashMap;
use zeroize::Zeroizing;

/// One FakeTLS candidate entry referencing either a primary or retiring key.
#[derive(Debug, Clone)]
pub struct HostedCandidate {
    /// Owning secret name (e.g., `"alice"` or `"default"`).
    pub name: Arc<str>,
    /// Precomputed 64-byte HMAC-SHA256 midstate candidate.
    pub candidate: FakeTlsCandidate,
    /// Lowercase fronting hostname (SNI).
    pub host_lower: String,
    /// `None` for primary key; `Some(until)` for retiring key.
    pub retiring_until: Option<DateTime<Utc>>,
}

impl HostedCandidate {
    /// True if this candidate is currently valid at `now`.
    #[inline]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.retiring_until.is_none_or(|until| now < until)
    }
}

/// One Obfuscated2 (`dd` or `plain`) candidate key entry.
#[derive(Debug, Clone)]
pub struct Obfs2Candidate {
    pub name: Arc<str>,
    pub key: Zeroizing<[u8; SECRET_KEY_LEN]>,
    pub mode: SecretMode,
    pub retiring_until: Option<DateTime<Utc>>,
}

impl Obfs2Candidate {
    #[inline]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.retiring_until.is_none_or(|until| now < until)
    }
}

/// Per-secret metadata & policy snapshot stored inside [`SecretSet`].
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub name: Arc<str>,
    pub secret: Secret,
    pub limits: SecretLimits,
    pub ad_tag: Option<[u8; 16]>,
    pub retiring: Vec<RetiringSecret>,
    /// Indices into `SecretSet::faketls_entries` belonging to this secret
    /// (primary first, then retiring keys) for O(1) hint resolution!
    pub faketls_positions: Vec<usize>,
}

/// Snapshot of a fair-share-enabled secret for the 1-second ticker.
#[derive(Debug, Clone)]
pub struct FairSecretSpec {
    pub name: Arc<str>,
    pub totals: FairTotals,
}

/// Contiguous SNI-partitioned FakeTLS candidate slice for 8-way AVX2 SIMD scans.
#[derive(Debug, Clone, Default)]
pub struct SniBucket {
    pub positions: Vec<usize>,
    pub candidates: Vec<FakeTlsCandidate>,
}

/// Immutable, wait-free (`ArcSwap`-published) snapshot of all active secrets,
/// retiring keys, limits, ad-tags, and precomputed cryptographic candidates.
#[derive(Debug)]
pub struct SecretSet {
    pub records: BTreeMap<String, SecretRecord>,
    /// Parallel dense arrays for SIMD 8-way AVX2 FakeTLS scanning.
    pub faketls_candidates: Vec<FakeTlsCandidate>,
    pub faketls_meta: Vec<HostedCandidate>,
    /// SNI-partitioned dense candidate buckets (`lowercase_sni -> SniBucket`)
    /// so shared-SNI scans also execute full 8-way AVX2 multi-buffer HMAC-SHA256!
    pub sni_buckets: FxHashMap<String, SniBucket>,
    /// Dense array of Obfuscated2 keys across ALL secrets (`ee` + `dd` + `plain`,
    /// primary + retiring), matching Go `doObfuscatedEntry` so `[[listener]]
    /// accept = ["dd"]` seamlessly serves WEB relay / `dd` re-spellings of `ee` secrets!
    pub obfs2_entries: Vec<Obfs2Candidate>,
    /// Precomputed list of secrets with `client_fair = true` and at least one
    /// non-zero speed limit.
    pub fair_secrets: Vec<FairSecretSpec>,
    /// Global default `ad_tag` (overridden per-secret by `SecretRecord::ad_tag`).
    pub default_ad_tag: Option<[u8; 16]>,
    /// Cached key -> `FakeTlsCandidate` table reused on next reload!
    candidate_cache: FxHashMap<[u8; SECRET_KEY_LEN], FakeTlsCandidate>,
}

impl SecretSet {
    /// Build a [`SecretSet`] from a validated [`Config`], reusing precomputed
    /// HMAC midstates from `prev` whenever keys are unchanged!
    pub fn from_config(
        cfg: &Config,
        now: DateTime<Utc>,
        prev: Option<&Self>,
    ) -> (Self, Vec<String>) {
        let secrets = cfg.get_secrets();
        let limits = cfg.get_secret_limits();
        let ad_tags = cfg.get_secret_ad_tags();
        let retiring_report = cfg.get_retiring_secrets(now);
        let default_ad_tag = cfg.ad_tag.as_deref().copied();

        let set = Self::build(
            &secrets,
            &limits,
            &ad_tags,
            default_ad_tag,
            &retiring_report.usable,
            prev,
        );
        (set, retiring_report.lines)
    }

    /// Build a [`SecretSet`] directly from explicit secret/limit/retiring maps
    /// (used by both startup config loading and live Management API mutations).
    pub fn build(
        secrets: &BTreeMap<String, Secret>,
        limits: &BTreeMap<String, SecretLimits>,
        ad_tags: &BTreeMap<String, [u8; 16]>,
        default_ad_tag: Option<[u8; 16]>,
        retiring: &[RetiringSecret],
        prev: Option<&Self>,
    ) -> Self {
        let mut retiring_by_name: FxHashMap<&str, Vec<RetiringSecret>> = FxHashMap::default();
        for r in retiring {
            retiring_by_name
                .entry(r.name.as_str())
                .or_default()
                .push(r.clone());
        }

        let mut records = BTreeMap::new();
        let mut faketls_candidates = Vec::new();
        let mut faketls_meta = Vec::new();
        let mut sni_buckets: FxHashMap<String, SniBucket> = FxHashMap::default();
        let mut obfs2_entries = Vec::new();
        let mut fair_secrets = Vec::new();
        let mut candidate_cache: FxHashMap<[u8; SECRET_KEY_LEN], FakeTlsCandidate> =
            FxHashMap::default();

        let get_or_build = |key: &[u8; SECRET_KEY_LEN],
                            cache: &mut FxHashMap<[u8; SECRET_KEY_LEN], FakeTlsCandidate>|
         -> FakeTlsCandidate {
            if let Some(c) = cache.get(key) {
                return c.clone();
            }
            let c = prev
                .and_then(|p| p.candidate_cache.get(key).cloned())
                .unwrap_or_else(|| FakeTlsCandidate::new(key));
            cache.insert(*key, c.clone());
            c
        };

        for (name, secret) in secrets {
            let arc_name: Arc<str> = Arc::from(name.as_str());
            let lim = limits.get(name).cloned().unwrap_or_default();
            let ad_tag = ad_tags.get(name).copied();
            let ret_list = retiring_by_name.remove(name.as_str()).unwrap_or_default();

            let mut faketls_positions = Vec::new();

            // 1. Register primary secret
            if secret.mode() == SecretMode::FakeTls {
                let cand = get_or_build(secret.key(), &mut candidate_cache);
                let pos = faketls_candidates.len();
                let host_lower = secret.host().to_ascii_lowercase();
                faketls_candidates.push(cand.clone());
                faketls_meta.push(HostedCandidate {
                    name: Arc::clone(&arc_name),
                    candidate: cand.clone(),
                    host_lower: host_lower.clone(),
                    retiring_until: None,
                });
                if !host_lower.is_empty() {
                    let bucket = sni_buckets.entry(host_lower).or_default();
                    bucket.positions.push(pos);
                    bucket.candidates.push(cand);
                }
                faketls_positions.push(pos);
            }
            // Every secret's 16-byte key is eligible on obfuscated2 listeners (filtered
            // by the listener's ModeSet::tags(), matching Go `mtglib/proxy_entry.go`).
            obfs2_entries.push(Obfs2Candidate {
                name: Arc::clone(&arc_name),
                key: Zeroizing::new(*secret.key()),
                mode: secret.mode(),
                retiring_until: None,
            });

            // 2. Register retiring keys for this secret
            for r in &ret_list {
                if r.secret.mode() == SecretMode::FakeTls {
                    let cand = get_or_build(r.secret.key(), &mut candidate_cache);
                    let pos = faketls_candidates.len();
                    let host_lower = r.secret.host().to_ascii_lowercase();
                    faketls_candidates.push(cand.clone());
                    faketls_meta.push(HostedCandidate {
                        name: Arc::clone(&arc_name),
                        candidate: cand.clone(),
                        host_lower: host_lower.clone(),
                        retiring_until: Some(r.until),
                    });
                    if !host_lower.is_empty() {
                        let bucket = sni_buckets.entry(host_lower).or_default();
                        bucket.positions.push(pos);
                        bucket.candidates.push(cand);
                    }
                    faketls_positions.push(pos);
                }
                obfs2_entries.push(Obfs2Candidate {
                    name: Arc::clone(&arc_name),
                    key: Zeroizing::new(*r.secret.key()),
                    mode: r.secret.mode(),
                    retiring_until: Some(r.until),
                });
            }

            // 3. Index fair-share secrets once at reload time
            let ft = lim.fair_totals();
            if ft.speed > 0 || ft.up > 0 || ft.down > 0 {
                fair_secrets.push(FairSecretSpec {
                    name: Arc::clone(&arc_name),
                    totals: ft,
                });
            }

            records.insert(
                name.clone(),
                SecretRecord {
                    name: arc_name,
                    secret: secret.clone(),
                    limits: lim,
                    ad_tag,
                    retiring: ret_list,
                    faketls_positions,
                },
            );
        }

        Self {
            records,
            faketls_candidates,
            faketls_meta,
            sni_buckets,
            obfs2_entries,
            fair_secrets,
            default_ad_tag,
            candidate_cache,
        }
    }

    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        self.records.contains_key(name)
    }

    #[inline]
    pub fn get(&self, name: &str) -> Option<&SecretRecord> {
        self.records.get(name)
    }

    #[inline]
    pub fn limits_of(&self, name: &str) -> Option<&SecretLimits> {
        self.records.get(name).map(|r| &r.limits)
    }

    /// Resolve effective 16-byte `ad_tag` for `name` (per-secret override -> global default).
    #[inline]
    pub fn effective_ad_tag(&self, name: &str) -> Option<[u8; 16]> {
        self.records
            .get(name)
            .and_then(|r| r.ad_tag)
            .or(self.default_ad_tag)
    }

    /// Return the pre-grouped SIMD SNI bucket matching `sni` (case-insensitive),
    /// if any hosted FakeTLS secrets share that cover hostname.
    #[inline]
    pub fn sni_bucket(&self, sni: &str) -> Option<&SniBucket> {
        if sni.is_empty() {
            return None;
        }
        if let Some(b) = self.sni_buckets.get(sni) {
            return Some(b);
        }
        let lower = sni.to_ascii_lowercase();
        self.sni_buckets.get(&lower)
    }

    /// Resolve hinted secret names into up to `max_positions` candidate indices.
    pub fn resolve_hint_positions(&self, names: &[Arc<str>], max_positions: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(names.len().min(max_positions));
        for name in names {
            if let Some(rec) = self.records.get(name.as_ref()) {
                for &pos in &rec.faketls_positions {
                    if out.len() >= max_positions {
                        return out;
                    }
                    out.push(pos);
                }
            }
        }
        out
    }

    /// Count unexpired retiring keys across all secrets at `clock.now()`.
    pub fn active_retiring_count(&self, clock: &RotationClock) -> usize {
        let now = clock.now();
        self.obfs2_entries
            .iter()
            .filter(|m| m.retiring_until.is_some_and(|u| now < u))
            .count()
    }

    /// Collect all active Obfuscated2 keys valid at `now`.
    ///
    /// Note: matching Go `doObfuscatedEntry`, ALL configured secrets (`ee`, `dd`,
    /// `plain`) participate by 16-byte key; the listener's `allowed_modes.tags()`
    /// restricts which MTProto connection tags (`0xdddddddd`, `0xeeeeeeee`,
    /// `0xefefefef`) are accepted on the wire.
    pub fn active_obfs2_for_modes(
        &self,
        allowed_modes: ModeSet,
        now: DateTime<Utc>,
    ) -> Vec<&Obfs2Candidate> {
        if allowed_modes.is_empty() {
            return Vec::new();
        }
        self.obfs2_entries
            .iter()
            .filter(|e| e.is_valid_at(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_partitioning_and_midstate_caching_across_reloads() {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "alice".to_owned(),
            Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com").unwrap(),
        );
        secrets.insert(
            "bob".to_owned(),
            Secret::generate_mode(SecretMode::FakeTls, "cdn.cloudflare.net").unwrap(),
        );
        secrets.insert(
            "carol".to_owned(),
            Secret::generate_mode(SecretMode::Dd, "").unwrap(),
        );

        let set1 = SecretSet::build(
            &secrets,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &[],
            None,
        );
        assert_eq!(set1.faketls_candidates.len(), 2);
        assert_eq!(set1.obfs2_entries.len(), 3);
        assert_eq!(
            set1.sni_bucket("storage.googleapis.com")
                .unwrap()
                .positions
                .len(),
            1
        );
        assert_eq!(
            set1.sni_bucket("CDN.CLOUDFLARE.NET")
                .unwrap()
                .positions
                .len(),
            1
        );
        assert!(set1.sni_bucket("other.example").is_none());

        // Add dave sharing alice's SNI and reuse `set1` midstates!
        secrets.insert(
            "dave".to_owned(),
            Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com").unwrap(),
        );
        let set2 = SecretSet::build(
            &secrets,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &[],
            Some(&set1),
        );
        assert_eq!(
            set2.sni_bucket("storage.googleapis.com")
                .unwrap()
                .positions
                .len(),
            2
        );
        assert_eq!(set2.candidate_cache.len(), 3);
    }
}
