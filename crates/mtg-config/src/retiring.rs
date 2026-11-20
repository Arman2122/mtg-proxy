//! All 8 rules of `[[retiring-secret]]` evaluation (`get_retiring_secrets`) and
//! WEB relay retired-value extraction (`retiring_values`).
//!
//! Pure over `(Config, now)` with zero secret value leakage in any diagnostic
//! line, matching Go's `internal/config/retiring.go` rules 1–8 verbatim.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mtg_core::{
    MAX_RETIRING_OVERLAP, MAX_RETIRING_PER_SECRET, MAX_RETIRING_SECRETS, RetiringSecret,
    SECRET_KEY_LEN, Secret, SecretError,
};

use crate::schema::{
    Config, ConfigRetiringSecret, MISPLACED_RETIRING_USER, RETIRING_NAME_WRONG_TYPE,
    RETIRING_SECRET_WRONG_TYPE, RETIRING_UNTIL_WRONG_TYPE,
};
use crate::scrub::reads_as_a_value;

const REASON_NAME_MISSING: &str = "name is missing or empty";
const REASON_NAME_NOT_STRING: &str = "name is not a string";

const REASON_SECRET_MISSING: &str = "secret is missing or empty";
const REASON_SECRET_NOT_STRING: &str = "secret is not a string";
const REASON_SECRET_INVALID: &str =
    "secret is not a valid secret value (hex or base64url, in the ee, dd or plain form)";
const REASON_SECRET_ZERO_KEY: &str = "secret has an all-zero key";

const REASON_UNTIL_MISSING: &str = "until is missing or empty";
const REASON_UNTIL_INVALID: &str =
    "until is not an RFC 3339 date-time with an offset, such as 2026-10-09T09:30:00Z";

const REASON_DANGLING: &str = "name is not a configured secret";
const REASON_DANGLING_DEFAULT: &str =
    r#"name "default" is the top-level secret, which is not served while [secrets] is present"#;

const REASON_PRIMARY_OF_OTHER: &str = "the key is another secret's primary key";
const REASON_KEY_OF_OTHER: &str =
    "the key is also the key of a retiring-secret entry of another name";

const PROBLEM_TAIL: &str = "; the entry is ignored and its key is not accepted";
const OVER_LONG_TAIL: &str = ": until is more than 720h away; it is honoured, but an overlap is a \
    migration window, not a second key: shorten it (run --check refuses this file)";
const OWN_PRIMARY_NOTE: &str = ": the key is the secret's own primary; the entry changes nothing";
const DUPLICATE_NOTE: &str =
    ": the same key as another entry of this name; the later until is kept";

/// Line reported when `[secrets]` contains the reserved name `"retiring-secret"`.
pub const RETIRING_MISPLACED_USER_LINE: &str = r#"a [secrets] user named "retiring-secret" is ignored: [[retiring-secret]] blocks go in their own table, above or between the other tables, one per old key"#;

/// Report produced by [`Config::get_retiring_secrets`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetiringReport {
    /// Usable retiring entries handed to the proxy engine, in file order.
    pub usable: Vec<RetiringSecret>,
    /// Problem and warning lines, in file order (fails `run --check` and `doctor`).
    pub lines: Vec<String>,
    /// Count of expired (inert) entries whose `until <= now`.
    pub expired: usize,
    /// Informational notes (own primary or duplicate key).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Kept,
    Problem,
    Inert,
    OwnPrimary,
    Duplicate,
}

#[derive(Debug, Clone)]
struct JudgedEntry {
    label: String,
    name: String,
    secret: Option<Secret>,
    until: Option<DateTime<Utc>>,
    verdict: Verdict,
    reason: String,
}

impl JudgedEntry {
    fn drop_with(&mut self, reason: impl Into<String>) {
        self.verdict = Verdict::Problem;
        self.reason = reason.into();
    }
}

#[derive(Debug, Clone)]
struct OwnerClaim {
    name: String,
    many: bool,
}

fn claim_key(
    map: &mut BTreeMap<[u8; SECRET_KEY_LEN], OwnerClaim>,
    name: &str,
    key: [u8; SECRET_KEY_LEN],
) {
    match map.get_mut(&key) {
        None => {
            map.insert(
                key,
                OwnerClaim {
                    name: name.to_owned(),
                    many: false,
                },
            );
        }
        Some(owner) => {
            if owner.name != name {
                owner.many = true;
            }
        }
    }
}

fn judge_shape(position_1based: usize, raw: &ConfigRetiringSecret) -> JudgedEntry {
    let mut entry = JudgedEntry {
        label: format!("retiring-secret #{position_1based}"),
        name: raw.name.clone(),
        secret: None,
        until: None,
        verdict: Verdict::Kept,
        reason: String::new(),
    };

    if raw.wrong_type & RETIRING_NAME_WRONG_TYPE != 0 {
        entry.drop_with(REASON_NAME_NOT_STRING);
        return entry;
    }
    if raw.name.is_empty() {
        entry.drop_with(REASON_NAME_MISSING);
        return entry;
    }

    if !reads_as_a_value(&raw.name) {
        entry.label = format!("retiring-secret #{position_1based} (name {:?})", raw.name);
    }

    if raw.wrong_type & RETIRING_SECRET_WRONG_TYPE != 0 {
        entry.drop_with(REASON_SECRET_NOT_STRING);
        return entry;
    }
    if raw.secret.is_empty() {
        entry.drop_with(REASON_SECRET_MISSING);
        return entry;
    }

    let secret = match Secret::parse(&raw.secret) {
        Ok(s) if s.is_valid() => s,
        Err(SecretError::Invalid) => {
            entry.drop_with(REASON_SECRET_ZERO_KEY);
            return entry;
        }
        _ => {
            entry.drop_with(REASON_SECRET_INVALID);
            return entry;
        }
    };

    if raw.wrong_type & RETIRING_UNTIL_WRONG_TYPE != 0 {
        entry.drop_with(REASON_UNTIL_INVALID);
        return entry;
    }
    if raw.until.is_empty() {
        entry.drop_with(REASON_UNTIL_MISSING);
        return entry;
    }

    let Ok(until) = DateTime::parse_from_rfc3339(&raw.until).map(|dt| dt.with_timezone(&Utc))
    else {
        entry.drop_with(REASON_UNTIL_INVALID);
        return entry;
    };

    entry.secret = Some(secret);
    entry.until = Some(until);
    entry
}

fn outranks(a: &JudgedEntry, b: &JudgedEntry) -> bool {
    let a_until = a.until.expect("valid");
    let b_until = b.until.expect("valid");
    if a_until != b_until {
        return a_until > b_until;
    }
    let a_sec = a.secret.as_ref().expect("valid");
    let b_sec = b.secret.as_ref().expect("valid");
    if a_sec.mode() != b_sec.mode() {
        return (a_sec.mode() as u8) < (b_sec.mode() as u8);
    }
    a_sec.host() < b_sec.host()
}

impl Config {
    /// Judge all `[[retiring-secret]]` blocks at instant `now` according to all
    /// 8 rules of the rotation specification.
    pub fn get_retiring_secrets(&self, now: DateTime<Utc>) -> RetiringReport {
        let mut report = RetiringReport::default();

        if self.secrets.contains_key(MISPLACED_RETIRING_USER) {
            report.lines.push(RETIRING_MISPLACED_USER_LINE.to_owned());
        }

        if self.retiring_secrets.is_empty() {
            return report;
        }

        let primaries = self.get_secrets();
        let mut entries: Vec<JudgedEntry> = self
            .retiring_secrets
            .iter()
            .enumerate()
            .map(|(i, raw)| judge_shape(i + 1, raw))
            .collect();

        // Rule 5 population: every primary + every rule-1-passing retiring entry (expired/dangling included).
        let mut primary_owners = BTreeMap::new();
        let mut all_owners = BTreeMap::new();
        for (name, sec) in &primaries {
            claim_key(&mut primary_owners, name, *sec.key());
            claim_key(&mut all_owners, name, *sec.key());
        }
        for e in &entries {
            if e.verdict != Verdict::Problem
                && let Some(sec) = &e.secret
            {
                claim_key(&mut all_owners, &e.name, *sec.key());
            }
        }

        let mut survivors = Vec::new();
        for (i, entry) in entries.iter_mut().enumerate() {
            if entry.verdict == Verdict::Problem {
                continue;
            }
            let until = entry.until.expect("rule 1 passed");
            let key = *entry.secret.as_ref().expect("rule 1 passed").key();

            if now >= until {
                entry.verdict = Verdict::Inert;
                report.expired += 1;
                continue;
            }

            let Some(primary) = primaries.get(&entry.name) else {
                let reason = if entry.name == "default" && !self.secrets.is_empty() {
                    REASON_DANGLING_DEFAULT
                } else {
                    REASON_DANGLING
                };
                entry.drop_with(reason);
                continue;
            };

            if all_owners.get(&key).is_some_and(|o| o.many) {
                let is_other_primary = primary_owners
                    .get(&key)
                    .is_some_and(|o| o.many || o.name != entry.name);
                entry.drop_with(if is_other_primary {
                    REASON_PRIMARY_OF_OTHER
                } else {
                    REASON_KEY_OF_OTHER
                });
                continue;
            }

            if key == *primary.key() {
                entry.verdict = Verdict::OwnPrimary;
                continue;
            }

            survivors.push(i);
        }

        // Rule 7: collapse duplicate keys within the same secret name.
        let mut best: BTreeMap<(String, [u8; SECRET_KEY_LEN]), usize> = BTreeMap::new();
        for &i in &survivors {
            let key = (
                entries[i].name.clone(),
                *entries[i].secret.as_ref().expect("valid").key(),
            );
            if let Some(&other) = best.get(&key) {
                if outranks(&entries[i], &entries[other]) {
                    entries[other].verdict = Verdict::Duplicate;
                    best.insert(key, i);
                } else {
                    entries[i].verdict = Verdict::Duplicate;
                }
            } else {
                best.insert(key, i);
            }
        }
        survivors.retain(|&i| entries[i].verdict == Verdict::Kept);

        // Rule 8: per-name cap (MAX_RETIRING_PER_SECRET) then global cap (MAX_RETIRING_SECRETS).
        let over_cap_name = format!(
            "more than {MAX_RETIRING_PER_SECRET} unexpired entries for this name; only the {MAX_RETIRING_PER_SECRET} with the latest until are kept"
        );
        let over_cap_all = format!(
            "more than {MAX_RETIRING_SECRETS} unexpired entries in all; only the {MAX_RETIRING_SECRETS} with the latest until are kept"
        );

        let mut ranked = survivors.clone();
        ranked.sort_by(|&a, &b| {
            entries[a]
                .name
                .cmp(&entries[b].name)
                .then_with(|| entries[b].until.cmp(&entries[a].until))
                .then_with(|| {
                    entries[a]
                        .secret
                        .as_ref()
                        .expect("valid")
                        .key()
                        .cmp(entries[b].secret.as_ref().expect("valid").key())
                })
        });

        let mut of_name = 0usize;
        for idx in 0..ranked.len() {
            let cur = ranked[idx];
            if idx == 0 || entries[cur].name != entries[ranked[idx - 1]].name {
                of_name = 0;
            }
            of_name += 1;
            if of_name > MAX_RETIRING_PER_SECRET {
                entries[cur].drop_with(over_cap_name.clone());
            }
        }

        ranked.retain(|&i| entries[i].verdict == Verdict::Kept);
        if ranked.len() > MAX_RETIRING_SECRETS {
            ranked.sort_by(|&a, &b| {
                entries[b]
                    .until
                    .cmp(&entries[a].until)
                    .then_with(|| entries[a].name.cmp(&entries[b].name))
                    .then_with(|| {
                        entries[a]
                            .secret
                            .as_ref()
                            .expect("valid")
                            .key()
                            .cmp(entries[b].secret.as_ref().expect("valid").key())
                    })
            });
            for &i in &ranked[MAX_RETIRING_SECRETS..] {
                entries[i].drop_with(over_cap_all.clone());
            }
        }

        let over_long_after =
            now + chrono::Duration::from_std(MAX_RETIRING_OVERLAP).expect("720h fits chrono");

        for entry in entries {
            match entry.verdict {
                Verdict::Kept => {
                    let until = entry.until.expect("valid");
                    let secret = entry.secret.expect("valid");
                    report.usable.push(RetiringSecret {
                        name: entry.name,
                        secret,
                        until,
                    });
                    if until > over_long_after {
                        report
                            .lines
                            .push(format!("{}{OVER_LONG_TAIL}", entry.label));
                    }
                }
                Verdict::Problem => {
                    report
                        .lines
                        .push(format!("{}: {}{PROBLEM_TAIL}", entry.label, entry.reason));
                }
                Verdict::OwnPrimary => {
                    report
                        .notes
                        .push(format!("{}{OWN_PRIMARY_NOTE}", entry.label));
                }
                Verdict::Duplicate => {
                    report
                        .notes
                        .push(format!("{}{DUPLICATE_NOTE}", entry.label));
                }
                Verdict::Inert => {}
            }
        }

        report
    }

    /// Return all rule-1-valid retiring secret values ordered by `until`
    /// descending (ties in file order), used by the WEB relay so retired
    /// capabilities are answered with local 404 rather than forwarded to cover.
    pub fn retiring_values(&self) -> Vec<Secret> {
        let mut valid: Vec<(DateTime<Utc>, Secret)> = self
            .retiring_secrets
            .iter()
            .enumerate()
            .filter_map(|(i, raw)| {
                let judged = judge_shape(i + 1, raw);
                if judged.verdict == Verdict::Problem {
                    None
                } else {
                    Some((judged.until?, judged.secret?))
                }
            })
            .collect();

        // Stable sort descending by instant preserves file order on ties.
        valid.sort_by_key(|a| std::cmp::Reverse(a.0));
        valid.into_iter().map(|(_, s)| s).collect()
    }
}
