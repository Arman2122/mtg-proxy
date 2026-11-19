//! Surgical byte-span TOML secret rotation engine + atomic Linux file lock & commit.
//!
//! Mirrors Go's `internal/rotation/` spec §7.3 with **byte-for-byte parity**:
//! - Preserves comments, blank lines, key ordering, quoting style (`"`/`'`),
//!   hex vs base64url encoding, CRLF vs LF line endings, and missing final newlines.
//! - Enforces **Invariant R0** ([`RotationError::KeyRevived`]): an edit can
//!   never resurrect an expired, colliding, or over-cap key.
//! - Re-parses the spliced output and checks full deep equality against the
//!   expected `Config` ([`RotationError::EditVerification`]) before returning bytes.
//! - Provides Linux-native atomic file locking (`O_CREAT | O_EXCL` `.rotate.lock`),
//!   Penhoon panel path guard, `chown`/`chmod` metadata preservation, SHA-256
//!   concurrent-edit race detection, `fsync` + atomic `rename` + parent dir `fsync`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::ops::Range;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SubsecRound as _, Utc};
use mtg_core::{MAX_RETIRING_OVERLAP, MAX_RETIRING_PER_SECRET, SECRET_KEY_LEN, Secret};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use toml_edit::{ImDocument, Item, Table, Value as TomlValue};

use crate::retiring::RetiringReport;
use crate::schema::{Config, ConfigRetiringSecret};
use crate::scrub::{reads_as_a_value, unknown_key_path};

const RETIRING_TABLE: &str = "retiring-secret";

/// Errors returned by [`PreparedRotation::prepare`], [`PreparedRotation::apply`],
/// or [`rotate_file_atomic`].
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("internal error: the edit changed more than it meant to; nothing was written")]
    EditVerification,
    #[error(
        "removing these blocks would make a key usable again that is not accepted now ({0} would come back); remove or change that block first"
    )]
    KeyRevived(String),
    #[error(
        "the new key is already held by this file, as a primary or a previous key; generate another"
    )]
    KeyHeld,
    #[error("the config cannot be mapped for editing; edit it by hand")]
    Unlocatable,
    #[error("refusing to edit panel-managed config path {0:?} without --force")]
    PanelManagedPath(PathBuf),
    #[error(
        "config lock already held at {path:?} (if no rotation is running, remove the stale lock file)"
    )]
    LockHeld { path: PathBuf },
    #[error("config file was modified concurrently during rotation; retry")]
    ConcurrentModification,
    #[error("{0}")]
    InvalidRequest(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parameters for one `rotate-secret` operation.
#[derive(Debug, Clone)]
pub struct RotationRequest {
    /// Secret name in `[secrets]`, or `"default"` for top-level `secret`, or `""` for `--prune` alone.
    pub name: String,
    /// Generate/splice a new primary key for `name`.
    pub rotate: bool,
    /// Optional overlap end instant (`None` means `--overlap 0`: replace primary with no retiring block).
    pub until: Option<DateTime<Utc>>,
    /// Remove all `[[retiring-secret]]` blocks belonging to `name`.
    pub end_overlap: bool,
    /// Remove all expired `[[retiring-secret]]` blocks (`until <= now`).
    pub prune: bool,
    /// Single consistent instant for this run.
    pub now: DateTime<Utc>,
}

/// One removed `[[retiring-secret]]` block in [`RotationSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedBlock {
    pub name: String,
    pub until: String,
}

/// Human-safe, value-free summary of a rotation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationSummary {
    pub name: String,
    pub until: Option<DateTime<Utc>>,
    pub removed: Vec<RemovedBlock>,
    pub no_op: bool,
}

#[derive(Debug, Clone)]
struct HeaderPos {
    line: usize,
    path: Vec<String>,
    array: bool,
}

#[derive(Debug, Clone)]
struct BlockPos {
    start: usize,
    end: usize,
    single: bool,
    name_is_string: bool,
}

#[derive(Debug, Default, Clone)]
struct StringLoc {
    found: bool,
    not_string: bool,
    start: usize,
    end: usize,
    text: String,
}

#[derive(Debug, Clone)]
struct SpanEdit {
    start: usize,
    end: usize,
    text: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Layout {
    eol: &'static str,
    final_newline: bool,
    comments: BTreeSet<usize>,
    headers: Vec<HeaderPos>,
    blocks: Vec<BlockPos>,
    secrets_header_idx: Option<usize>,
    target: StringLoc,
    retiring_key: bool,
}

/// A planned and pre-validated surgical rotation ready to apply.
#[derive(Debug, Clone)]
pub struct PreparedRotation {
    doc: Vec<u8>,
    req: RotationRequest,
    conf: Config,
    report: RetiringReport,
    loc: Layout,

    primary: Option<Secret>,
    in_table: bool,
    hex_value: bool,

    add_block: bool,
    until: Option<DateTime<Utc>>,
    insert_at: Option<usize>,

    cuts: Vec<SpanEdit>,
    cut_to_end: bool,

    expected: Vec<ConfigRetiringSecret>,
    expected_from: Vec<Option<usize>>,
    unknown_keys: Vec<String>,
    summary: RotationSummary,
}

impl PreparedRotation {
    /// Step 1: parse, validate, locate byte spans, choose cuts, and simulate
    /// the edit to catch R0 revivals or new problems before touching disk.
    pub fn prepare(doc: &[u8], req: RotationRequest) -> Result<Self, RotationError> {
        check_request(&req)?;

        let conf = Config::parse(doc)
            .map_err(|e| RotationError::InvalidRequest(format!("the config does not load: {e}")))?;
        conf.validate()
            .map_err(|e| RotationError::InvalidRequest(format!("the config is not valid: {e}")))?;

        let report = conf.get_retiring_secrets(req.now);

        let (primary, in_table, target_path) = if req.name.is_empty() {
            (None, false, None)
        } else {
            let secrets = conf.get_secrets();
            let Some(p) = secrets.get(&req.name) else {
                if req.name == "default" && !conf.secrets.is_empty() {
                    return Err(RotationError::InvalidRequest(
                        r#""default" is not served while [secrets] is present; rotate a name from [secrets]"#.to_owned(),
                    ));
                }
                if reads_as_a_value(&req.name) {
                    return Err(RotationError::InvalidRequest(
                        "there is no secret by that name (it is not shown: it reads as a secret value)".to_owned(),
                    ));
                }
                return Err(RotationError::InvalidRequest(format!(
                    "there is no secret named {:?}",
                    req.name
                )));
            };
            let in_tbl = conf.secrets.contains_key(&req.name);
            let path = if in_tbl {
                vec!["secrets".to_owned(), req.name.clone()]
            } else {
                vec!["secret".to_owned()]
            };
            (Some(p.clone()), in_tbl, Some(path))
        };

        let loc = locate(doc, target_path.as_deref())?;

        if loc.retiring_key || loc.blocks.len() != conf.retiring_secrets.len() {
            return Err(RotationError::InvalidRequest(
                "the file's retiring-secret entries are not all [[retiring-secret]] blocks \
                 (an inline array of tables, or a retiring-secret key?); rotate-secret edits only blocks: \
                 rewrite them as blocks and retry"
                    .to_owned(),
            ));
        }

        let hex_value =
            loc.target.found && !loc.target.not_string && hex::decode(&loc.target.text).is_ok();
        if req.rotate {
            if !loc.target.found || loc.target.not_string {
                return Err(RotationError::InvalidRequest(format!(
                    "the value of {} cannot be found in the file for editing; edit it by hand",
                    shown_rot_name(&req.name)
                )));
            }
            let raw_val = &doc[loc.target.start..loc.target.end];
            if raw_val.starts_with(b"\"\"\"") || raw_val.starts_with(b"'''") {
                return Err(RotationError::InvalidRequest(format!(
                    "the value of {} is a multi-line string, which rotate-secret does not edit: \
                     write it on one line, between \"\" or '', and retry",
                    shown_rot_name(&req.name)
                )));
            }
        }

        let mut removed = Vec::new();
        let mut removed_blocks = Vec::new();
        for (i, blk) in loc.blocks.iter().enumerate() {
            let entry = &conf.retiring_secrets[i];
            let mut should_rm = req.end_overlap && entry.name == req.name;
            if req.prune
                && let Ok(u) = DateTime::parse_from_rfc3339(&entry.until)
                && req.now >= u.with_timezone(&Utc)
            {
                should_rm = true;
            }
            if should_rm {
                removed.push(i);
                removed_blocks.push(blk.clone());
            }
        }

        let cuts = compute_cuts(doc, &loc, &removed_blocks);
        let cut_to_end = cuts.last().is_some_and(|c| c.end == doc.len());

        let unknown_keys = if cuts.is_empty() {
            conf.unknown_keys.clone()
        } else {
            let cut_doc = assemble(doc, cuts.clone()).ok_or(RotationError::EditVerification)?;
            let cut_conf = Config::parse(&cut_doc).map_err(|_| RotationError::EditVerification)?;
            cut_conf.unknown_keys
        };

        let insert_at = insertion_point(doc, &loc);
        let add_block = req.rotate && req.until.is_some();
        let mut until = None;

        if add_block {
            let u = req.until.expect("checked").trunc_subsecs(0);
            let max_until =
                req.now + chrono::Duration::from_std(MAX_RETIRING_OVERLAP).expect("720h");
            if u <= req.now {
                return Err(RotationError::InvalidRequest(format!(
                    "until {} is not after now ({})",
                    u.format("%Y-%m-%dT%H:%M:%SZ"),
                    req.now.format("%Y-%m-%dT%H:%M:%SZ")
                )));
            }
            if u > max_until {
                return Err(RotationError::InvalidRequest(format!(
                    "until {} is more than 720h after now ({})",
                    u.format("%Y-%m-%dT%H:%M:%SZ"),
                    req.now.format("%Y-%m-%dT%H:%M:%SZ")
                )));
            }
            for (i, blk) in loc.blocks.iter().enumerate() {
                if blk.single && !removed.contains(&i) {
                    return Err(RotationError::InvalidRequest(
                        "the file has a [retiring-secret] table with one pair of brackets, and a \
                         [[retiring-secret]] block cannot be added beside it: write its header as [[retiring-secret]] and retry"
                            .to_owned(),
                    ));
                }
            }
            let held = report.usable.iter().filter(|e| e.name == req.name).count();
            if held >= MAX_RETIRING_PER_SECRET {
                return Err(RotationError::InvalidRequest(format!(
                    "{} already has {held} unexpired previous keys, the most one secret can have: \
                     end them with --end-overlap, or wait for one to expire, and retry",
                    shown_rot_name(&req.name)
                )));
            }
            until = Some(u);
        }

        // Compute expected retiring entries in resulting file order.
        let mut placed: Vec<(usize, Option<usize>, ConfigRetiringSecret)> = Vec::new();
        for (i, blk) in loc.blocks.iter().enumerate() {
            if !removed.contains(&i) {
                placed.push((blk.start, Some(i), conf.retiring_secrets[i].clone()));
            }
        }
        if add_block {
            let at = insert_at.unwrap_or(doc.len() + 1);
            placed.push((
                at,
                None,
                ConfigRetiringSecret {
                    name: req.name.clone(),
                    secret: loc.target.text.clone(),
                    until: until.expect("set").format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    wrong_type: 0,
                },
            ));
        }
        placed.sort_by_key(|(at, _, _)| *at);

        let expected: Vec<ConfigRetiringSecret> =
            placed.iter().map(|(_, _, e)| e.clone()).collect();
        let expected_from: Vec<Option<usize>> = placed.iter().map(|(_, f, _)| *f).collect();

        let summary = build_summary(&req, &conf, &loc, &removed, until);

        let prepared = Self {
            doc: doc.to_vec(),
            req,
            conf,
            report,
            loc,
            primary,
            in_table,
            hex_value,
            add_block,
            until,
            insert_at,
            cuts,
            cut_to_end,
            expected,
            expected_from,
            unknown_keys,
            summary,
        };

        prepared.simulate()?;
        Ok(prepared)
    }

    pub fn warnings(&self) -> &[String] {
        &self.report.lines
    }

    pub fn primary(&self) -> Option<&Secret> {
        self.primary.as_ref()
    }

    pub fn summary(&self) -> &RotationSummary {
        &self.summary
    }

    /// Format `secret` in the same encoding (hex vs base64url) as the current value in the file.
    pub fn value_text(&self, secret: &Secret) -> String {
        if self.hex_value {
            secret.encode_hex()
        } else {
            secret.encode_base64()
        }
    }

    /// Steps 2–5: splice the new primary (if rotating) and retiring-block edits,
    /// then re-parse and deep-verify before returning the new file bytes.
    pub fn apply(&self, new_primary: Option<&Secret>) -> Result<Vec<u8>, RotationError> {
        if self.req.rotate {
            let Some(new_p) = new_primary else {
                return Err(RotationError::InvalidRequest(
                    "a new primary key is required for rotation".to_owned(),
                ));
            };
            if !new_p.is_valid() {
                return Err(RotationError::InvalidRequest(
                    "the new key is not a valid secret".to_owned(),
                ));
            }
            if let Some(old_p) = &self.primary
                && new_p.key() == old_p.key()
            {
                return Err(RotationError::InvalidRequest(
                    "the new key is the current key".to_owned(),
                ));
            }
            if self.held_keys().contains(new_p.key()) {
                return Err(RotationError::KeyHeld);
            }
        }

        let out = self
            .splice(new_primary)
            .ok_or(RotationError::EditVerification)?;
        self.verify(&out, new_primary)?;
        Ok(out)
    }

    fn held_keys(&self) -> BTreeSet<[u8; SECRET_KEY_LEN]> {
        let mut held = BTreeSet::new();
        for s in self.conf.get_secrets().values() {
            held.insert(*s.key());
        }
        for e in &self.conf.retiring_secrets {
            if let Ok(s) = Secret::parse(&e.secret) {
                held.insert(*s.key());
            }
        }
        held
    }

    fn placeholder(&self) -> Secret {
        let held = self.held_keys();
        let mut key = [
            0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5,
            0x5a, 0xa5,
        ];
        while held.contains(&key) {
            key[15] = key[15].wrapping_add(1);
        }
        let old = self.primary.as_ref().expect("rotate has primary");
        Secret::from_parts(key, old.host(), old.mode())
    }

    fn set_primary(&self, cfg: &mut Config, new_p: &Secret) {
        if self.in_table {
            cfg.secrets.insert(self.req.name.clone(), new_p.clone());
        } else {
            cfg.secret = Some(new_p.clone());
        }
    }

    fn simulate(&self) -> Result<(), RotationError> {
        let mut sim = self.conf.clone();
        sim.retiring_secrets.clone_from(&self.expected);

        let placeholder = if self.req.rotate {
            let ph = self.placeholder();
            self.set_primary(&mut sim, &ph);
            Some(ph)
        } else {
            None
        };

        let report = sim.get_retiring_secrets(self.req.now);
        let added = new_lines(&self.report.lines, &report.lines);
        if !added.is_empty() {
            if self.add_block
                && self.new_block_has_line(&added)
                && let Some(err) = self.explain_collision(&sim.get_secrets())
            {
                return Err(err);
            }
            let named: Vec<String> = added.iter().map(|l| self.as_written(l)).collect();
            return Err(RotationError::InvalidRequest(format!(
                "the edit would add a problem the file does not have: {}",
                named.join("; and ")
            )));
        }

        if let Some(label) = self.revived(&report, &sim.get_secrets(), placeholder.as_ref()) {
            return Err(RotationError::KeyRevived(label));
        }

        if self.req.rotate
            && let Some((holder, until)) = self.key_still_held(&report)
        {
            let old_key = *self.primary.as_ref().expect("primary").key();
            return Err(RotationError::InvalidRequest(format!(
                "the current key of {} would still be accepted until {} by {}; {}",
                shown_rot_name(&self.req.name),
                until.format("%Y-%m-%dT%H:%M:%SZ"),
                self.label_for(&holder, old_key, until),
                end_overlap_advice(&holder)
            )));
        }

        Ok(())
    }

    fn splice(&self, new_primary: Option<&Secret>) -> Option<Vec<u8>> {
        let mut edits = self.cuts.clone();

        if self.req.rotate {
            let new_p = new_primary?;
            let quote = self.doc[self.loc.target.start] as char;
            let mut text = Vec::new();
            text.push(quote as u8);
            text.extend_from_slice(self.value_text(new_p).as_bytes());
            text.push(quote as u8);
            edits.push(SpanEdit {
                start: self.loc.target.start,
                end: self.loc.target.end,
                text,
            });
        }

        let block_text = if self.add_block {
            Some(self.block_lines().join(self.loc.eol))
        } else {
            None
        };

        if let (Some(blk), Some(ins)) = (&block_text, self.insert_at) {
            let mut text = Vec::with_capacity(blk.len() + self.loc.eol.len() * 2);
            text.extend_from_slice(blk.as_bytes());
            text.extend_from_slice(self.loc.eol.as_bytes());
            text.extend_from_slice(self.loc.eol.as_bytes());
            edits.push(SpanEdit {
                start: ins,
                end: ins,
                text,
            });
        }

        let mut out = assemble(&self.doc, edits)?;

        if self.cut_to_end && !self.loc.final_newline {
            trim_line_ending(&mut out);
        }

        if let (Some(blk), None) = (&block_text, self.insert_at) {
            if !out.is_empty() && *out.last().unwrap() != b'\n' {
                out.extend_from_slice(self.loc.eol.as_bytes());
            }
            if !out.is_empty() && !last_line_blank(&out) {
                out.extend_from_slice(self.loc.eol.as_bytes());
            }
            out.extend_from_slice(blk.as_bytes());
            if self.loc.final_newline {
                out.extend_from_slice(self.loc.eol.as_bytes());
            }
        }

        Some(out)
    }

    fn block_lines(&self) -> [String; 5] {
        let old_raw = std::str::from_utf8(&self.doc[self.loc.target.start..self.loc.target.end])
            .expect("valid utf8");
        [
            format!("[[{RETIRING_TABLE}]]"),
            format!(
                "# added by mtg-proxy rotate-secret at {}",
                self.req.now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            format!("name   = {}", basic_toml_string(&self.req.name)),
            format!("secret = {old_raw}"),
            format!(
                "until  = {}",
                basic_toml_string(
                    &self
                        .until
                        .expect("add_block has until")
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string()
                )
            ),
        ]
    }

    fn verify(&self, out: &[u8], new_primary: Option<&Secret>) -> Result<(), RotationError> {
        let edited = Config::parse(out).map_err(|_| RotationError::EditVerification)?;
        if edited.validate().is_err() {
            return Err(RotationError::EditVerification);
        }

        let mut want = self.conf.clone();
        want.retiring_secrets.clone_from(&self.expected);
        want.unknown_keys = normalize_unknown_key_paths(&self.unknown_keys);
        if self.req.rotate {
            self.set_primary(&mut want, new_primary.expect("rotate has new_primary"));
        }

        let mut got = edited.clone();
        got.unknown_keys = normalize_unknown_key_paths(&edited.unknown_keys);

        if want != got {
            return Err(RotationError::EditVerification);
        }

        let report = edited.get_retiring_secrets(self.req.now);
        if !new_lines(&self.report.lines, &report.lines).is_empty() {
            return Err(RotationError::EditVerification);
        }

        if let Some(label) = self.revived(&report, &edited.get_secrets(), new_primary) {
            return Err(RotationError::KeyRevived(label));
        }

        if self.req.rotate
            && (self.key_still_held(&report).is_some()
                || (self.add_block && !self.grant_made(&report)))
        {
            return Err(RotationError::EditVerification);
        }

        Ok(())
    }

    fn revived(
        &self,
        after: &RetiringReport,
        primaries: &BTreeMap<String, Secret>,
        new_primary: Option<&Secret>,
    ) -> Option<String> {
        let mut before = BTreeSet::new();
        for s in self.conf.get_secrets().values() {
            before.insert(*s.key());
        }
        for e in &self.report.usable {
            before.insert(*e.secret.key());
        }

        let allowed = |k: &[u8; SECRET_KEY_LEN]| -> bool {
            before.contains(k) || (self.req.rotate && new_primary.is_some_and(|np| np.key() == k))
        };

        for e in &after.usable {
            if !allowed(e.secret.key()) {
                return Some(self.label_for(&e.name, *e.secret.key(), e.until));
            }
        }
        for (name, s) in primaries {
            if !allowed(s.key()) {
                return Some(format!("the primary key of {}", shown_rot_name(name)));
            }
        }
        None
    }

    fn key_still_held(&self, report: &RetiringReport) -> Option<(String, DateTime<Utc>)> {
        let old_key = self.primary.as_ref()?.key();
        for e in &report.usable {
            if e.secret.key() != old_key {
                continue;
            }
            if self.add_block && e.name == self.req.name && self.until.is_some_and(|u| e.until == u)
            {
                continue;
            }
            return Some((e.name.clone(), e.until));
        }
        None
    }

    fn grant_made(&self, report: &RetiringReport) -> bool {
        let (Some(old_p), Some(until)) = (&self.primary, self.until) else {
            return false;
        };
        report
            .usable
            .iter()
            .any(|e| e.secret.key() == old_p.key() && e.name == self.req.name && e.until == until)
    }

    fn new_block_has_line(&self, added: &[String]) -> bool {
        let Some(pos_idx) = self.expected_from.iter().position(Option::is_none) else {
            return false;
        };
        added
            .iter()
            .any(|l| parse_position(l).is_some_and(|(n, _)| n == pos_idx + 1))
    }

    fn explain_collision(&self, primaries: &BTreeMap<String, Secret>) -> Option<RotationError> {
        let old_key = *self.primary.as_ref()?.key();
        for (i, entry) in self.expected.iter().enumerate() {
            let Some(from) = self.expected_from[i] else {
                continue;
            };
            if entry.name == self.req.name || !self.claims_a_key(from) {
                continue;
            }
            if let Ok(sec) = Secret::parse(&entry.secret)
                && *sec.key() == old_key
            {
                return Some(RotationError::InvalidRequest(format!(
                    "{} already holds the key being retired, so the new block would be ignored; \
                     remove that block (--prune removes it if it has expired) and rotate again",
                    entry_label(from + 1, &entry.name)
                )));
            }
        }
        for (name, sec) in primaries {
            if name != &self.req.name && *sec.key() == old_key {
                return Some(RotationError::InvalidRequest(format!(
                    "the key being retired is also the primary key of {}, so the new block would be ignored; \
                     two secrets share one key: give each its own, then rotate",
                    shown_rot_name(name)
                )));
            }
        }
        None
    }

    fn claims_a_key(&self, idx: usize) -> bool {
        let e = &self.conf.retiring_secrets[idx];
        self.loc.blocks[idx].name_is_string
            && !e.name.is_empty()
            && Secret::parse(&e.secret).is_ok_and(|s| s.is_valid())
            && DateTime::parse_from_rfc3339(&e.until).is_ok()
    }

    fn as_written(&self, line: &str) -> String {
        let Some((n, rest)) = parse_position(line) else {
            return line.to_owned();
        };
        if n < 1 || n > self.expected_from.len() {
            return line.to_owned();
        }
        match self.expected_from[n - 1] {
            Some(from) => format!("{RETIRING_TABLE} #{}{rest}", from + 1),
            None => format!("the new block{rest}"),
        }
    }

    fn label_for(&self, name: &str, key: [u8; SECRET_KEY_LEN], until: DateTime<Utc>) -> String {
        for (i, entry) in self.expected.iter().enumerate() {
            let Some(from) = self.expected_from[i] else {
                continue;
            };
            if entry.name != name {
                continue;
            }
            if let (Ok(sec), Ok(at)) = (
                Secret::parse(&entry.secret),
                DateTime::parse_from_rfc3339(&entry.until),
            ) && *sec.key() == key
                && at.with_timezone(&Utc) == until
            {
                return entry_label(from + 1, name);
            }
        }
        entry_label(0, name)
    }
}

fn check_request(req: &RotationRequest) -> Result<(), RotationError> {
    if req.rotate && req.end_overlap {
        return Err(RotationError::InvalidRequest(
            "a rotation and --end-overlap cannot be asked at once".to_owned(),
        ));
    }
    if !req.rotate && !req.end_overlap && !req.prune {
        return Err(RotationError::InvalidRequest(
            "nothing to do: ask for a rotation, --end-overlap or --prune".to_owned(),
        ));
    }
    if (req.rotate || req.end_overlap) && req.name.is_empty() {
        return Err(RotationError::InvalidRequest(
            "a rotation or --end-overlap needs a name".to_owned(),
        ));
    }
    if !req.rotate && !req.end_overlap && !req.name.is_empty() {
        return Err(RotationError::InvalidRequest(
            "--prune alone takes no name".to_owned(),
        ));
    }
    if !req.rotate && req.until.is_some() {
        return Err(RotationError::InvalidRequest(
            "an until is given without a rotation".to_owned(),
        ));
    }
    Ok(())
}

fn shown_rot_name(name: &str) -> String {
    if reads_as_a_value(name) {
        "the secret asked for (its name reads as a secret value and is not shown)".to_owned()
    } else {
        format!("{name:?}")
    }
}

fn entry_label(pos_1based: usize, name: &str) -> String {
    let mut label = if pos_1based > 0 {
        format!("{RETIRING_TABLE} #{pos_1based}")
    } else {
        "a retiring-secret block".to_owned()
    };
    if !reads_as_a_value(name) {
        let _ = write!(label, " (name {name:?})");
    }
    label
}

fn end_overlap_advice(holder: &str) -> String {
    if reads_as_a_value(holder) {
        "rotate-secret <config> <that name> --end-overlap ends every previous key of that name; \
         or edit the block by hand"
            .to_owned()
    } else {
        format!(
            "rotate-secret <config> {holder:?} --end-overlap ends every previous key of {holder:?}; \
             or edit the block by hand"
        )
    }
}

fn build_summary(
    req: &RotationRequest,
    conf: &Config,
    loc: &Layout,
    removed: &[usize],
    until: Option<DateTime<Utc>>,
) -> RotationSummary {
    let mut summary = RotationSummary {
        name: if reads_as_a_value(&req.name) {
            String::new()
        } else {
            req.name.clone()
        },
        until,
        removed: Vec::with_capacity(removed.len()),
        no_op: !req.rotate && removed.is_empty(),
    };

    for &i in removed {
        let e = &conf.retiring_secrets[i];
        let name = if loc.blocks[i].name_is_string && !reads_as_a_value(&e.name) {
            e.name.clone()
        } else {
            String::new()
        };
        let u = if DateTime::parse_from_rfc3339(&e.until).is_ok() {
            e.until.clone()
        } else {
            String::new()
        };
        summary.removed.push(RemovedBlock { name, until: u });
    }
    summary
}

// ---------------------------------------------------------------------------
// Lossless TOML Byte-Span Locator (via toml_edit::ImDocument)
// ---------------------------------------------------------------------------

fn locate(doc: &[u8], target: Option<&[String]>) -> Result<Layout, RotationError> {
    let text = std::str::from_utf8(doc).map_err(|_| RotationError::Unlocatable)?;
    let parsed = ImDocument::parse(text.to_owned()).map_err(|_| RotationError::Unlocatable)?;

    let mut headers: Vec<HeaderPos> = Vec::new();
    let mut blocks: Vec<BlockPos> = Vec::new();
    let mut target_loc = StringLoc::default();
    let mut retiring_key = false;
    let mut multiline_spans: Vec<Range<usize>> = Vec::new();

    // Check top-level `retiring-secret` form.
    if let Some(item) = parsed.as_table().get(RETIRING_TABLE) {
        match item {
            Item::ArrayOfTables(_) => {}
            Item::Table(t) if !t.is_dotted() && !t.is_implicit() => {}
            _ => retiring_key = true,
        }
    }

    // Collect every explicit table / array-of-tables header, multi-line string spans,
    // retiring-secret block info, and target value span.
    let mut path = Vec::new();
    collect_table_spans(
        doc,
        parsed.as_table(),
        &mut path,
        target,
        &mut headers,
        &mut blocks,
        &mut target_loc,
        &mut multiline_spans,
    )?;

    headers.sort_by_key(|h| h.line);
    blocks.sort_by_key(|b| b.start);

    // Compute end offset of every retiring-secret block (next header line or EOF).
    for blk in &mut blocks {
        blk.end = doc.len();
        for h in &headers {
            if h.line > blk.start {
                blk.end = h.line;
                break;
            }
        }
    }

    let secrets_header_idx = headers
        .iter()
        .position(|h| !h.array && h.path.len() == 1 && h.path[0] == "secrets");

    let comments = scan_comment_lines(doc, &multiline_spans);

    Ok(Layout {
        eol: detect_eol(doc),
        final_newline: doc.last() == Some(&b'\n'),
        comments,
        headers,
        blocks,
        secrets_header_idx,
        target: target_loc,
        retiring_key,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_table_spans(
    doc: &[u8],
    table: &Table,
    path: &mut Vec<String>,
    target: Option<&[String]>,
    headers: &mut Vec<HeaderPos>,
    blocks: &mut Vec<BlockPos>,
    target_loc: &mut StringLoc,
    multiline_spans: &mut Vec<Range<usize>>,
) -> Result<(), RotationError> {
    for (key, item) in table {
        path.push(key.to_owned());
        match item {
            Item::Table(sub) => {
                if !sub.is_implicit() && !sub.is_dotted() {
                    let span = sub.span().ok_or(RotationError::Unlocatable)?;
                    let line = find_header_line_start(doc, span.start, false)?;
                    headers.push(HeaderPos {
                        line,
                        path: path.clone(),
                        array: false,
                    });
                    if path.len() == 1 && path[0] == RETIRING_TABLE {
                        let name_is_str = sub
                            .get("name")
                            .and_then(Item::as_value)
                            .is_some_and(TomlValue::is_str);
                        blocks.push(BlockPos {
                            start: line,
                            end: doc.len(),
                            single: true,
                            name_is_string: name_is_str,
                        });
                    }
                }
                collect_table_spans(
                    doc,
                    sub,
                    path,
                    target,
                    headers,
                    blocks,
                    target_loc,
                    multiline_spans,
                )?;
            }
            Item::ArrayOfTables(arr) => {
                for elem in arr {
                    let span = elem.span().ok_or(RotationError::Unlocatable)?;
                    let line = find_header_line_start(doc, span.start, true)?;
                    headers.push(HeaderPos {
                        line,
                        path: path.clone(),
                        array: true,
                    });
                    if path.len() == 1 && path[0] == RETIRING_TABLE {
                        let name_is_str = elem
                            .get("name")
                            .and_then(Item::as_value)
                            .is_some_and(TomlValue::is_str);
                        blocks.push(BlockPos {
                            start: line,
                            end: doc.len(),
                            single: false,
                            name_is_string: name_is_str,
                        });
                    }
                    collect_table_spans(
                        doc,
                        elem,
                        path,
                        target,
                        headers,
                        blocks,
                        target_loc,
                        multiline_spans,
                    )?;
                }
            }
            Item::Value(val) => {
                visit_value(doc, val, path, target, target_loc, multiline_spans);
            }
            Item::None => {}
        }
        path.pop();
    }
    Ok(())
}

fn visit_value(
    doc: &[u8],
    val: &TomlValue,
    path: &mut Vec<String>,
    target: Option<&[String]>,
    target_loc: &mut StringLoc,
    multiline_spans: &mut Vec<Range<usize>>,
) {
    match val {
        TomlValue::InlineTable(it) => {
            for (k, v) in it {
                path.push(k.to_owned());
                visit_value(doc, v, path, target, target_loc, multiline_spans);
                path.pop();
            }
        }
        TomlValue::Array(arr) => {
            for elem in arr {
                visit_value(doc, elem, path, target, target_loc, multiline_spans);
            }
        }
        TomlValue::String(s) => {
            if let Some(span) = s.span() {
                let raw = &doc[span.start..span.end];
                if raw.starts_with(b"\"\"\"") || raw.starts_with(b"'''") {
                    multiline_spans.push(span.clone());
                }
                if target.is_some_and(|t| t == path.as_slice()) {
                    *target_loc = StringLoc {
                        found: true,
                        not_string: false,
                        start: span.start,
                        end: span.end,
                        text: s.value().clone(),
                    };
                }
            }
        }
        _ => {
            if target.is_some_and(|t| t == path.as_slice()) {
                *target_loc = StringLoc {
                    found: true,
                    not_string: true,
                    ..StringLoc::default()
                };
            }
        }
    }
}

/// Locate the start of the line carrying the `[` or `[[` header for a table
/// whose `toml_edit` span starts at `span_start`.
fn find_header_line_start(
    doc: &[u8],
    span_start: usize,
    is_array: bool,
) -> Result<usize, RotationError> {
    // In `toml_edit`, `Table::span()` starts at the opening `[` (or leading
    // trivia/prefix on that line); scan forward from `span_start` to the first
    // `[` on that block if trivia was included.
    let mut pos = span_start;
    while pos < doc.len() && doc[pos] != b'[' {
        pos += 1;
    }
    if pos >= doc.len() {
        return Err(RotationError::Unlocatable);
    }
    if is_array && (pos + 1 >= doc.len() || doc[pos + 1] != b'[') {
        return Err(RotationError::Unlocatable);
    }
    let ls = line_start(doc, pos);
    if !doc[ls..pos].iter().all(|&b| b == b' ' || b == b'\t') {
        return Err(RotationError::Unlocatable);
    }
    Ok(ls)
}

fn scan_comment_lines(doc: &[u8], multiline_spans: &[Range<usize>]) -> BTreeSet<usize> {
    let mut set = BTreeSet::new();
    let mut pos = 0usize;
    while pos < doc.len() {
        let ls = pos;
        let next = next_line(doc, ls);
        let in_ml = multiline_spans.iter().any(|r| ls > r.start && ls < r.end);
        if !in_ml {
            let trimmed = doc[ls..next].iter().position(|&b| b != b' ' && b != b'\t');
            if let Some(off) = trimmed
                && doc[ls + off] == b'#'
            {
                set.insert(ls);
            }
        }
        pos = next;
    }
    set
}

fn insertion_point(doc: &[u8], loc: &Layout) -> Option<usize> {
    let idx = loc.secrets_header_idx?;
    let mut at = loc.headers[idx].line;
    while at > 0 {
        let prev = previous_line(doc, at);
        if loc.comments.contains(&prev) {
            at = prev;
        } else {
            break;
        }
    }
    Some(at)
}

fn compute_cuts(doc: &[u8], loc: &Layout, blocks: &[BlockPos]) -> Vec<SpanEdit> {
    let mut cuts: Vec<SpanEdit> = Vec::with_capacity(blocks.len());

    for b in blocks {
        let mut end = b.end;
        if end < doc.len() {
            loop {
                let prev = previous_line(doc, end);
                if prev <= b.start || (!loc.comments.contains(&prev) && !is_blank_line(doc, prev)) {
                    break;
                }
                end = prev;
            }
            while end < b.end && is_blank_line(doc, end) {
                end = next_line(doc, end);
            }
        }
        cuts.push(SpanEdit {
            start: b.start,
            end,
            text: Vec::new(),
        });
    }

    cuts.sort_by_key(|c| c.start);
    let mut merged: Vec<SpanEdit> = Vec::with_capacity(cuts.len());
    for cut in cuts {
        if let Some(last) = merged.last_mut()
            && cut.start <= last.end
        {
            last.end = last.end.max(cut.end);
            continue;
        }
        merged.push(cut);
    }

    if let Some(last) = merged.last_mut()
        && last.end == doc.len()
    {
        while last.start > 0 && is_blank_line(doc, previous_line(doc, last.start)) {
            last.start = previous_line(doc, last.start);
        }
    }

    merged
}

fn assemble(doc: &[u8], mut edits: Vec<SpanEdit>) -> Option<Vec<u8>> {
    edits.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
    let mut out = Vec::with_capacity(doc.len() + 256);
    let mut at = 0usize;
    for e in edits {
        if e.start < at || e.end < e.start || e.end > doc.len() {
            return None;
        }
        out.extend_from_slice(&doc[at..e.start]);
        out.extend_from_slice(&e.text);
        at = e.end;
    }
    out.extend_from_slice(&doc[at..]);
    Some(out)
}

fn is_blank_line(doc: &[u8], start: usize) -> bool {
    for &b in &doc[start..] {
        match b {
            b'\n' => return true,
            b' ' | b'\t' | b'\r' => {}
            _ => return false,
        }
    }
    true
}

fn line_start(doc: &[u8], at: usize) -> usize {
    doc[..at]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1)
}

fn previous_line(doc: &[u8], line: usize) -> usize {
    line_start(doc, line - 1)
}

fn next_line(doc: &[u8], line: usize) -> usize {
    doc[line..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(doc.len(), |i| line + i + 1)
}

fn detect_eol(doc: &[u8]) -> &'static str {
    if let Some(i) = doc.iter().position(|&b| b == b'\n')
        && i > 0
        && doc[i - 1] == b'\r'
    {
        return "\r\n";
    }
    "\n"
}

fn trim_line_ending(buf: &mut Vec<u8>) {
    if buf.ends_with(b"\r\n") {
        buf.truncate(buf.len() - 2);
    } else if buf.ends_with(b"\n") {
        buf.truncate(buf.len() - 1);
    }
}

fn last_line_blank(buf: &[u8]) -> bool {
    let ls = line_start(buf, buf.len() - 1);
    buf[ls..buf.len() - 1]
        .iter()
        .all(|&b| b == b' ' || b == b'\t' || b == b'\r')
}

fn basic_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\u{08}' => out.push_str(r"\b"),
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\u{0C}' => out.push_str(r"\f"),
            '\r' => out.push_str(r"\r"),
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                let _ = write!(out, r"\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_position(line: &str) -> Option<(usize, &str)> {
    let prefix = format!("{RETIRING_TABLE} #");
    let rest = line.strip_prefix(&prefix)?;
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let n: usize = rest[..digits_end].parse().ok()?;
    Some((n, &rest[digits_end..]))
}

fn without_position(line: &str) -> String {
    match parse_position(line) {
        Some((_, rest)) => format!("{RETIRING_TABLE} #{rest}"),
        None => line.to_owned(),
    }
}

fn new_lines(old: &[String], edited: &[String]) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for l in old {
        *counts.entry(without_position(l)).or_default() += 1;
    }
    let mut added = Vec::new();
    for l in edited {
        let k = without_position(l);
        if let Some(c) = counts.get_mut(&k)
            && *c > 0
        {
            *c -= 1;
            continue;
        }
        added.push(l.clone());
    }
    added
}

fn normalize_unknown_key_paths(keys: &[String]) -> Vec<String> {
    let mut out: Vec<String> = keys
        .iter()
        .map(|k| unknown_key_path(k).to_owned())
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Atomic Linux File Transaction & Penhoon Panel Guard
// ---------------------------------------------------------------------------

/// Guard against overwriting a Penhoon / p-ui managed config file unless forced.
pub fn is_panel_managed_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/etc/p-ui/") || s.starts_with("/var/lib/penhoon/")
}

/// Exclusive `.rotate.lock` guard acquired via `O_CREAT | O_EXCL` on Linux.
struct RotateLock {
    path: PathBuf,
}

impl RotateLock {
    fn acquire(config_path: &Path) -> Result<Self, RotationError> {
        let mut lock_name = config_path
            .file_name()
            .ok_or_else(|| RotationError::InvalidRequest("config path has no filename".to_owned()))?
            .to_os_string();
        lock_name.push(".rotate.lock");
        let lock_path = config_path.with_file_name(lock_name);

        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    RotationError::LockHeld {
                        path: lock_path.clone(),
                    }
                } else {
                    RotationError::Io(e)
                }
            })?;
        let _ = writeln!(f, "pid={}", std::process::id());
        let _ = f.sync_all();

        Ok(Self { path: lock_path })
    }
}

impl Drop for RotateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Outcome of an atomic file rotation commit.
#[derive(Debug, Clone)]
pub struct FileRotationResult {
    pub summary: RotationSummary,
    pub warnings: Vec<String>,
    pub new_primary: Option<Secret>,
    pub new_value_text: Option<String>,
}

/// Execute a full crash-safe atomic `rotate-secret` transaction on `config_path`:
/// 1. Refuses Penhoon panel-managed paths unless `force = true`.
/// 2. Acquires exclusive `O_CREAT | O_EXCL` `<config>.rotate.lock`.
/// 3. Reads original bytes + SHA-256 + `uid`/`gid`/`mode`.
/// 4. Runs `PreparedRotation::prepare` + `apply` (generating a fresh non-colliding
///    secret if `req.rotate && explicit_new_primary.is_none()`).
/// 5. Writes to temporary file in same directory (`0600`), restores original
///    `chmod` + best-effort `chown`, `fsync`s temp file, re-verifies source
///    SHA-256 against concurrent external edits, atomically `rename`s, and
///    `fsync`s the parent directory.
pub fn rotate_file_atomic(
    config_path: &Path,
    req: &RotationRequest,
    explicit_new_primary: Option<Secret>,
    force: bool,
    dry_run: bool,
) -> Result<FileRotationResult, RotationError> {
    if !force && is_panel_managed_path(config_path) {
        return Err(RotationError::PanelManagedPath(config_path.to_path_buf()));
    }

    let _lock = if dry_run {
        None
    } else {
        Some(RotateLock::acquire(config_path)?)
    };

    let meta = fs::metadata(config_path)?;
    let orig_bytes = fs::read(config_path)?;
    let orig_hash: [u8; 32] = Sha256::digest(&orig_bytes).into();

    let prepared = PreparedRotation::prepare(&orig_bytes, req.clone())?;
    let new_primary = if req.rotate {
        if let Some(p) = explicit_new_primary {
            Some(p)
        } else {
            let old = prepared.primary().expect("rotate has primary");
            let held = prepared.held_keys();
            let generated = loop {
                let candidate = Secret::generate_mode(old.mode(), old.host())
                    .map_err(|e| RotationError::InvalidRequest(e.to_string()))?;
                if !held.contains(candidate.key()) {
                    break candidate;
                }
            };
            Some(generated)
        }
    } else {
        None
    };

    let new_bytes = prepared.apply(new_primary.as_ref())?;
    let new_value_text = new_primary.as_ref().map(|s| prepared.value_text(s));

    if !dry_run && !prepared.summary().no_op {
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let tmp_name = format!(
            ".{}.rotate.tmp.{}",
            config_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("config"),
            std::process::id()
        );
        let tmp_path = parent.join(tmp_name);

        let write_result = (|| -> Result<(), RotationError> {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            tmp.write_all(&new_bytes)?;

            // Restore original permissions & best-effort uid/gid ownership.
            let perms = fs::Permissions::from_mode(meta.mode() & 0o7777);
            tmp.set_permissions(perms)?;
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd as _;
                // Best-effort fchown: succeeds when running as root; non-fatal for unprivileged users.
                unsafe {
                    let _ = libc::fchown(tmp.as_raw_fd(), meta.uid(), meta.gid());
                }
            }
            tmp.sync_all()?;
            drop(tmp);

            // Second SHA-256 check to guarantee no concurrent external writer edited config_path.
            let current_bytes = fs::read(config_path)?;
            let current_hash: [u8; 32] = Sha256::digest(&current_bytes).into();
            if current_hash != orig_hash {
                return Err(RotationError::ConcurrentModification);
            }

            fs::rename(&tmp_path, config_path)?;

            // Fsync parent directory to make rename durable across power loss.
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
            write_result?;
        }
    }

    Ok(FileRotationResult {
        summary: prepared.summary().clone(),
        warnings: prepared.warnings().to_vec(),
        new_primary,
        new_value_text,
    })
}
