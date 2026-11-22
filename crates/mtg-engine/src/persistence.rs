//! Enterprise persistence, lossless TOML writeback, optimistic-concurrency
//! revision state, real-time SSE event stream types, and distributed multi-node
//! billing delta checkpoints.
//!
//! # Three Persistence Modes (`[api] persistence = ...`)
//! 1. **`"memory"`** (default): Zero disk writes; ideal when an external VPN
//!    control plane (e.g. Penhoon or a multi-core web panel backed by
//!    PostgreSQL/SQLite) owns the source of truth and pushes desired state via
//!    `PUT /state` or `/secrets`.
//! 2. **`"overlay"`**: Crash-safe atomic `0600` JSON overlay file with SHA-256
//!    integrity checksum, `flock(2)` lockfile serialization, `fsync(2)`,
//!    atomic `rename(2)`, and parent directory `fsync(2)`. Operator's
//!    `config.toml` remains 100% clean/immutable (GitOps/Ansible-friendly),
//!    while live API changes survive process restarts and reboots!
//! 3. **`"toml"`**: Lossless `toml_edit` writeback directly into `config.toml`
//!    under `flock(2)` + atomic rename, preserving comments and unrelated
//!    `[network]`/`[defense]`/`[web]` sections verbatim.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use mtg_core::{GlobalLimits, QuotaReset, SecretLimits};
use mtg_net::{OutboundGroupSpec, OutboundSpec, RoutingSpec};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current JSON overlay schema version.
pub const RUNTIME_STATE_SCHEMA_VERSION: u32 = 1;

/// Maximum retained billing checkpoint consumers (bounds memory under hostile callers).
const MAX_BILLING_CONSUMERS: usize = 256;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Complete declarative snapshot of mutable proxy control-plane state (for
/// `GET /state`, `PUT /state`, `"overlay"` persistence, and `"toml"` writeback).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStateSnapshot {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub revision: u64,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
    /// Named proxy secrets (`name -> canonical secret string`).
    pub secrets: BTreeMap<String, String>,
    /// Per-secret ad-tags (`name -> 32-char lowercase hex`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_ad_tags: BTreeMap<String, String>,
    /// Per-secret limits & outbound overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_limits: BTreeMap<String, SecretLimitsSnapshot>,
    /// Global default ad-tag (`32-char lowercase hex`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_ad_tag: Option<String>,
    /// Global hard concurrency ceiling (`0` = unlimited).
    #[serde(default)]
    pub concurrency: u32,
    /// Global fair-throttle connection threshold (`0` = disabled).
    #[serde(default)]
    pub throttle_max_connections: u32,
    /// Server-wide bandwidth, quota, and per-IP rate/connection caps.
    #[serde(default)]
    pub global_limits: GlobalLimitsSnapshot,
    /// Declarative universal plug-in outbounds (`[[outbound]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<OutboundSpec>,
    /// Declarative outbound groups (`[[outbound-group]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_groups: Vec<OutboundGroupSpec>,
    /// Declarative outbound routing policy (`[routing]`).
    #[serde(default)]
    pub routing: RoutingSpec,
}

const fn default_schema_version() -> u32 {
    RUNTIME_STATE_SCHEMA_VERSION
}

/// Serializable mirror of [`SecretLimits`] using canonical numeric units.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretLimitsSnapshot {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub quota_bytes: i64,
    #[serde(default, skip_serializing_if = "is_quota_reset_none")]
    pub quota_reset: QuotaReset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_up_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_down_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ip_limit: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub client_conns: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_connections: u32,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub client_speed_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub client_speed_up_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub client_speed_down_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_fair: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_up_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_down_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

impl From<&SecretLimits> for SecretLimitsSnapshot {
    fn from(l: &SecretLimits) -> Self {
        Self {
            quota_bytes: l.quota_bytes,
            quota_reset: l.quota_reset,
            expires_at: l.expires_at,
            disabled: l.disabled,
            speed_bytes_per_second: l.speed_bytes_per_second,
            speed_up_bytes_per_second: l.speed_up_bytes_per_second,
            speed_down_bytes_per_second: l.speed_down_bytes_per_second,
            ip_limit: l.ip_limit,
            client_conns: l.client_conns,
            max_connections: l.max_connections,
            client_speed_bytes_per_second: l.client_speed_bytes_per_second,
            client_speed_up_bytes_per_second: l.client_speed_up_bytes_per_second,
            client_speed_down_bytes_per_second: l.client_speed_down_bytes_per_second,
            client_fair: l.client_fair,
            conn_speed_bytes_per_second: l.conn_speed_bytes_per_second,
            conn_speed_up_bytes_per_second: l.conn_speed_up_bytes_per_second,
            conn_speed_down_bytes_per_second: l.conn_speed_down_bytes_per_second,
            outbound: l.outbound.clone(),
        }
    }
}

impl From<SecretLimitsSnapshot> for SecretLimits {
    fn from(s: SecretLimitsSnapshot) -> Self {
        Self {
            quota_bytes: s.quota_bytes.max(0),
            quota_reset: s.quota_reset,
            expires_at: s.expires_at,
            disabled: s.disabled,
            speed_bytes_per_second: s.speed_bytes_per_second.max(0),
            speed_up_bytes_per_second: s.speed_up_bytes_per_second.max(0),
            speed_down_bytes_per_second: s.speed_down_bytes_per_second.max(0),
            ip_limit: s.ip_limit,
            client_conns: s.client_conns,
            max_connections: s.max_connections,
            client_speed_bytes_per_second: s.client_speed_bytes_per_second.max(0),
            client_speed_up_bytes_per_second: s.client_speed_up_bytes_per_second.max(0),
            client_speed_down_bytes_per_second: s.client_speed_down_bytes_per_second.max(0),
            client_fair: s.client_fair,
            conn_speed_bytes_per_second: s.conn_speed_bytes_per_second.max(0),
            conn_speed_up_bytes_per_second: s.conn_speed_up_bytes_per_second.max(0),
            conn_speed_down_bytes_per_second: s.conn_speed_down_bytes_per_second.max(0),
            outbound: s.outbound.filter(|v| !v.trim().is_empty()),
        }
    }
}

/// Serializable mirror of [`GlobalLimits`].
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalLimitsSnapshot {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_up_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed_down_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub quota_bytes: i64,
    #[serde(default, skip_serializing_if = "is_quota_reset_none")]
    pub quota_reset: QuotaReset,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_connections_per_ip: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_new_connections_per_ip: u32,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_up_bytes_per_second: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub conn_speed_down_bytes_per_second: i64,
}

impl From<&GlobalLimits> for GlobalLimitsSnapshot {
    fn from(g: &GlobalLimits) -> Self {
        Self {
            speed_bytes_per_second: g.speed_bytes_per_second,
            speed_up_bytes_per_second: g.speed_up_bytes_per_second,
            speed_down_bytes_per_second: g.speed_down_bytes_per_second,
            quota_bytes: g.quota_bytes,
            quota_reset: g.quota_reset,
            max_connections_per_ip: g.max_connections_per_ip,
            max_new_connections_per_ip: g.max_new_connections_per_ip,
            conn_speed_bytes_per_second: g.conn_speed_bytes_per_second,
            conn_speed_up_bytes_per_second: g.conn_speed_up_bytes_per_second,
            conn_speed_down_bytes_per_second: g.conn_speed_down_bytes_per_second,
        }
    }
}

impl From<&GlobalLimitsSnapshot> for GlobalLimits {
    fn from(s: &GlobalLimitsSnapshot) -> Self {
        Self {
            speed_bytes_per_second: s.speed_bytes_per_second.max(0),
            speed_up_bytes_per_second: s.speed_up_bytes_per_second.max(0),
            speed_down_bytes_per_second: s.speed_down_bytes_per_second.max(0),
            quota_bytes: s.quota_bytes.max(0),
            quota_reset: s.quota_reset,
            max_connections_per_ip: s.max_connections_per_ip,
            max_new_connections_per_ip: s.max_new_connections_per_ip,
            conn_speed_bytes_per_second: s.conn_speed_bytes_per_second.max(0),
            conn_speed_up_bytes_per_second: s.conn_speed_up_bytes_per_second.max(0),
            conn_speed_down_bytes_per_second: s.conn_speed_down_bytes_per_second.max(0),
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
const fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
const fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
const fn is_quota_reset_none(q: &QuotaReset) -> bool {
    matches!(q, QuotaReset::None)
}

/// Real-time control-plane event emitted on the SSE `GET /events` broadcast bus.
#[derive(Debug, Clone, Serialize)]
pub struct EngineEvent {
    pub id: u64,
    pub event: &'static str,
    pub revision: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

/// One secret's exact monotonic billing delta returned by `POST /accounting/checkpoint`.
#[derive(Debug, Clone, Serialize)]
pub struct SecretBillingDelta {
    pub delta_bytes_in: u64,
    pub delta_bytes_out: u64,
    pub delta_total_bytes: u64,
    pub delta_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_connections: u64,
    pub quota_used: u64,
    pub quota_cutoffs: u64,
    pub active_connections: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub counter_reset: bool,
}

/// Distributed multi-node billing checkpoint response (`POST /accounting/checkpoint`).
#[derive(Debug, Clone, Serialize)]
pub struct BillingCheckpointReport {
    pub consumer_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub peek: bool,
    pub checkpoint_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_at: Option<DateTime<Utc>>,
    pub total_delta_bytes_in: u64,
    pub total_delta_bytes_out: u64,
    pub total_delta_bytes: u64,
    pub secrets: BTreeMap<String, SecretBillingDelta>,
}

#[derive(Debug, Clone, Copy, Default)]
struct SecretCursor {
    bytes_in: u64,
    bytes_out: u64,
    total_connections: u64,
}

#[derive(Debug, Clone)]
struct ConsumerCheckpointState {
    sequence: u64,
    last_at: DateTime<Utc>,
    secrets: FxHashMap<String, SecretCursor>,
}

/// Per-consumer exact-once delta billing ledger (`POST /accounting/checkpoint`).
#[derive(Debug)]
pub struct BillingTracker {
    boot_id: String,
    consumers: FxHashMap<String, ConsumerCheckpointState>,
}

impl Default for BillingTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BillingTracker {
    pub fn new() -> Self {
        let mut raw = [0u8; 16];
        let _ = getrandom::fill(&mut raw);
        Self {
            boot_id: hex::encode(raw),
            consumers: FxHashMap::default(),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Compute exact deltas since `consumer_id`'s last checkpoint and (unless
    /// `peek == true`) advance the consumer's cursor atomically.
    pub fn checkpoint(
        &mut self,
        consumer_id: &str,
        peek: bool,
        current: &[(String, u64, u64, u64, u64, u64, i64)], // (name, in, out, total_conns, quota_used, cutoffs, active)
    ) -> Result<BillingCheckpointReport, String> {
        let cid = consumer_id.trim();
        if cid.is_empty() || cid.len() > 128 {
            return Err("consumer_id must be 1..=128 characters".to_owned());
        }
        if !self.consumers.contains_key(cid) && self.consumers.len() >= MAX_BILLING_CONSUMERS {
            // Evict oldest inactive consumer to guarantee bounded memory.
            if let Some(oldest_key) = self
                .consumers
                .iter()
                .min_by_key(|(_, st)| st.last_at)
                .map(|(k, _)| k.clone())
            {
                self.consumers.remove(&oldest_key);
            }
        }

        let now = Utc::now();
        let prev_state = self.consumers.get(cid);
        let prev_at = prev_state.map(|s| s.last_at);
        let prev_seq = prev_state.map_or(0, |s| s.sequence);
        let next_seq = prev_seq.saturating_add(1);

        let mut secrets_out = BTreeMap::new();
        let mut next_cursors = FxHashMap::default();
        let mut sum_in = 0u64;
        let mut sum_out = 0u64;

        for &(ref name, b_in, b_out, t_conns, q_used, q_cut, active) in current {
            let prev = prev_state
                .and_then(|s| s.secrets.get(name))
                .copied()
                .unwrap_or_default();
            let counter_reset =
                b_in < prev.bytes_in || b_out < prev.bytes_out || t_conns < prev.total_connections;
            let d_in = if b_in >= prev.bytes_in {
                b_in - prev.bytes_in
            } else {
                b_in
            };
            let d_out = if b_out >= prev.bytes_out {
                b_out - prev.bytes_out
            } else {
                b_out
            };
            let d_conns = if t_conns >= prev.total_connections {
                t_conns - prev.total_connections
            } else {
                t_conns
            };
            sum_in = sum_in.saturating_add(d_in);
            sum_out = sum_out.saturating_add(d_out);

            secrets_out.insert(
                name.clone(),
                SecretBillingDelta {
                    delta_bytes_in: d_in,
                    delta_bytes_out: d_out,
                    delta_total_bytes: d_in.saturating_add(d_out),
                    delta_connections: d_conns,
                    total_bytes_in: b_in,
                    total_bytes_out: b_out,
                    total_connections: t_conns,
                    quota_used: q_used,
                    quota_cutoffs: q_cut,
                    active_connections: active,
                    counter_reset,
                },
            );
            next_cursors.insert(
                name.clone(),
                SecretCursor {
                    bytes_in: b_in,
                    bytes_out: b_out,
                    total_connections: t_conns,
                },
            );
        }

        if !peek {
            self.consumers.insert(
                cid.to_owned(),
                ConsumerCheckpointState {
                    sequence: next_seq,
                    last_at: now,
                    secrets: next_cursors,
                },
            );
        }

        Ok(BillingCheckpointReport {
            consumer_id: cid.to_owned(),
            boot_id: self.boot_id.clone(),
            sequence: if peek { prev_seq } else { next_seq },
            peek,
            checkpoint_at: now,
            previous_checkpoint_at: prev_at,
            total_delta_bytes_in: sum_in,
            total_delta_bytes_out: sum_out,
            total_delta_bytes: sum_in.saturating_add(sum_out),
            secrets: secrets_out,
        })
    }
}

/// On-disk checksummed wrapper for `[api] persistence = "overlay"`.
#[derive(Debug, Serialize, Deserialize)]
struct OverlayEnvelope {
    version: u32,
    sha256: String,
    state: RuntimeStateSnapshot,
}

/// Acquire an exclusive advisory `flock(2)` on `<path>.lock` (released on drop).
struct FileLockGuard {
    file: File,
}

impl FileLockGuard {
    fn lock_for(target: &Path) -> io::Result<Self> {
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut lock_os = target.as_os_str().to_os_string();
        lock_os.push(".lock");
        let lock_path = PathBuf::from(lock_os);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        // SAFETY: valid open file descriptor locked with standard POSIX/Linux flock(2).
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file })
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // SAFETY: unlock before fd closes.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Write `bytes` crash-safely to `target` (`0600` temp file -> `write_all` ->
/// `sync_all` -> atomic `rename(2)` -> parent dir `fsync(2)`).
fn write_file_atomic_0600(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut tmp_os = target.as_os_str().to_os_string();
    tmp_os.push(format!(".tmp.{pid}.{seq}"));
    let tmp_path = PathBuf::from(tmp_os);

    let write_res = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Best-effort parent directory fsync so the directory entry survives power loss.
    if let Ok(dir) = File::open(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Resolve the default overlay state file path when `[api] persistence = "overlay"`
/// and `[api] state-file` is omitted.
pub fn default_overlay_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        let stem = cfg
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("mtg-proxy");
        let dir = cfg.parent().unwrap_or_else(|| Path::new("."));
        dir.join(format!("{stem}.runtime-state.json"))
    } else {
        PathBuf::from("/var/lib/mtg-proxy/runtime-state.json")
    }
}

/// Atomically persist `snapshot` into an integrity-checked `0600` JSON overlay file.
pub fn save_overlay_atomic(path: &Path, snapshot: &RuntimeStateSnapshot) -> io::Result<()> {
    let _lock = FileLockGuard::lock_for(path)?;
    let canonical_state =
        serde_json::to_vec(snapshot).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let digest = hex::encode(Sha256::digest(&canonical_state));
    let env = OverlayEnvelope {
        version: RUNTIME_STATE_SCHEMA_VERSION,
        sha256: digest,
        state: snapshot.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&env)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    write_file_atomic_0600(path, &bytes)
}

/// Load & SHA-256 verify a persisted overlay state file (`Ok(None)` if not present yet).
pub fn load_overlay_verified(path: &Path) -> io::Result<Option<RuntimeStateSnapshot>> {
    let raw = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let env: OverlayEnvelope = serde_json::from_slice(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt overlay: {e}")))?;
    if env.version != RUNTIME_STATE_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported overlay schema version {}", env.version),
        ));
    }
    let canonical = serde_json::to_vec(&env.state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let expected = hex::encode(Sha256::digest(&canonical));
    if !env.sha256.eq_ignore_ascii_case(&expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "overlay state SHA-256 checksum mismatch (corrupted or tampered file)",
        ));
    }
    Ok(Some(env.state))
}

/// Lossless `toml_edit` writeback directly into `config_path` under `flock(2)`.
/// Preserves existing operator comments and unrelated sections (`[network]`,
/// `[defense]`, `[web]`, `bind-to`, `[[listener]]`) while atomically updating
/// `[secrets]`, `[secret-limits]`, `[secret-ad-tags]`, `[limits]`, `ad-tag`,
/// `concurrency`, `[throttle].max-connections`, `[[outbound]]`,
/// `[[outbound-group]]`, and `[routing]`.
pub fn save_toml_atomic(config_path: &Path, snapshot: &RuntimeStateSnapshot) -> io::Result<()> {
    let _lock = FileLockGuard::lock_for(config_path)?;
    let existing = fs::read_to_string(config_path)?;
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot parse {} for writeback: {e}", config_path.display()),
        )
    })?;

    // Clear single-secret legacy key if present; write canonical `[secrets]` table.
    doc.remove("secret");
    let mut secrets_tbl = toml_edit::Table::new();
    for (name, val) in &snapshot.secrets {
        secrets_tbl.insert(name, toml_edit::value(val.as_str()));
    }
    doc["secrets"] = toml_edit::Item::Table(secrets_tbl);

    // Global `ad-tag`
    if let Some(tag) = &snapshot.global_ad_tag {
        doc["ad-tag"] = toml_edit::value(tag.as_str());
    } else {
        doc.remove("ad-tag");
    }

    // Per-secret `[secret-ad-tags]`
    if snapshot.secret_ad_tags.is_empty() {
        doc.remove("secret-ad-tags");
    } else {
        let mut tags_tbl = toml_edit::Table::new();
        for (name, tag) in &snapshot.secret_ad_tags {
            tags_tbl.insert(name, toml_edit::value(tag.as_str()));
        }
        doc["secret-ad-tags"] = toml_edit::Item::Table(tags_tbl);
    }

    // Per-secret `[secret-limits.<name>]`
    if snapshot.secret_limits.is_empty() {
        doc.remove("secret-limits");
    } else {
        let mut sl_root = toml_edit::Table::new();
        sl_root.set_implicit(true);
        for (name, lim) in &snapshot.secret_limits {
            let mut sub = toml_edit::Table::new();
            if lim.quota_bytes > 0 {
                sub.insert("quota", toml_edit::value(format!("{}B", lim.quota_bytes)));
            }
            if !matches!(lim.quota_reset, QuotaReset::None) {
                sub.insert("quota-reset", toml_edit::value(lim.quota_reset.as_str()));
            }
            if let Some(exp) = lim.expires_at {
                sub.insert("expires", toml_edit::value(exp.to_rfc3339()));
            }
            if lim.disabled {
                sub.insert("disabled", toml_edit::value(true));
            }
            if lim.speed_bytes_per_second > 0 {
                sub.insert(
                    "speed",
                    toml_edit::value(format!("{}B/s", lim.speed_bytes_per_second)),
                );
            }
            if lim.speed_up_bytes_per_second > 0 {
                sub.insert(
                    "speed-up",
                    toml_edit::value(format!("{}B/s", lim.speed_up_bytes_per_second)),
                );
            }
            if lim.speed_down_bytes_per_second > 0 {
                sub.insert(
                    "speed-down",
                    toml_edit::value(format!("{}B/s", lim.speed_down_bytes_per_second)),
                );
            }
            if lim.ip_limit > 0 {
                sub.insert("ip-limit", toml_edit::value(i64::from(lim.ip_limit)));
            }
            if lim.client_conns > 0 {
                sub.insert(
                    "client-conns",
                    toml_edit::value(i64::from(lim.client_conns)),
                );
            }
            if lim.max_connections > 0 {
                sub.insert(
                    "max-connections",
                    toml_edit::value(i64::from(lim.max_connections)),
                );
            }
            if lim.client_speed_bytes_per_second > 0 {
                sub.insert(
                    "client-speed",
                    toml_edit::value(format!("{}B/s", lim.client_speed_bytes_per_second)),
                );
            }
            if lim.client_speed_up_bytes_per_second > 0 {
                sub.insert(
                    "client-speed-up",
                    toml_edit::value(format!("{}B/s", lim.client_speed_up_bytes_per_second)),
                );
            }
            if lim.client_speed_down_bytes_per_second > 0 {
                sub.insert(
                    "client-speed-down",
                    toml_edit::value(format!("{}B/s", lim.client_speed_down_bytes_per_second)),
                );
            }
            if lim.client_fair {
                sub.insert("client-fair", toml_edit::value(true));
            }
            if lim.conn_speed_bytes_per_second > 0 {
                sub.insert(
                    "conn-speed",
                    toml_edit::value(format!("{}B/s", lim.conn_speed_bytes_per_second)),
                );
            }
            if lim.conn_speed_up_bytes_per_second > 0 {
                sub.insert(
                    "conn-speed-up",
                    toml_edit::value(format!("{}B/s", lim.conn_speed_up_bytes_per_second)),
                );
            }
            if lim.conn_speed_down_bytes_per_second > 0 {
                sub.insert(
                    "conn-speed-down",
                    toml_edit::value(format!("{}B/s", lim.conn_speed_down_bytes_per_second)),
                );
            }
            if let Some(ob) = &lim.outbound {
                sub.insert("outbound", toml_edit::value(ob.as_str()));
            }
            if !sub.is_empty() {
                sl_root.insert(name, toml_edit::Item::Table(sub));
            }
        }
        if sl_root.is_empty() {
            doc.remove("secret-limits");
        } else {
            doc["secret-limits"] = toml_edit::Item::Table(sl_root);
        }
    }

    // Global `concurrency` & `[throttle] max-connections`
    if snapshot.concurrency > 0 {
        doc["concurrency"] = toml_edit::value(i64::from(snapshot.concurrency));
    }
    if snapshot.throttle_max_connections > 0 {
        if !doc.contains_key("throttle") {
            doc["throttle"] = toml_edit::table();
        }
        doc["throttle"]["max-connections"] =
            toml_edit::value(i64::from(snapshot.throttle_max_connections));
    }

    // Global `[limits]` (preserves `[limits.default-secret]` if already present!)
    let gl = &snapshot.global_limits;
    let gl_any = gl.speed_bytes_per_second > 0
        || gl.speed_up_bytes_per_second > 0
        || gl.speed_down_bytes_per_second > 0
        || gl.quota_bytes > 0
        || !matches!(gl.quota_reset, QuotaReset::None)
        || gl.max_connections_per_ip > 0
        || gl.max_new_connections_per_ip > 0
        || gl.conn_speed_bytes_per_second > 0
        || gl.conn_speed_up_bytes_per_second > 0
        || gl.conn_speed_down_bytes_per_second > 0;
    if gl_any || doc.contains_key("limits") {
        if !doc.contains_key("limits") {
            doc["limits"] = toml_edit::table();
        }
        if let Some(tbl) = doc["limits"].as_table_mut() {
            set_or_remove_speed(tbl, "speed", gl.speed_bytes_per_second);
            set_or_remove_speed(tbl, "speed-up", gl.speed_up_bytes_per_second);
            set_or_remove_speed(tbl, "speed-down", gl.speed_down_bytes_per_second);
            if gl.quota_bytes > 0 {
                tbl.insert("quota", toml_edit::value(format!("{}B", gl.quota_bytes)));
            } else {
                tbl.remove("quota");
            }
            if matches!(gl.quota_reset, QuotaReset::None) {
                tbl.remove("quota-reset");
            } else {
                tbl.insert("quota-reset", toml_edit::value(gl.quota_reset.as_str()));
            }
            set_or_remove_u32(tbl, "max-connections-per-ip", gl.max_connections_per_ip);
            set_or_remove_u32(
                tbl,
                "max-new-connections-per-ip",
                gl.max_new_connections_per_ip,
            );
            set_or_remove_speed(tbl, "conn-speed", gl.conn_speed_bytes_per_second);
            set_or_remove_speed(tbl, "conn-speed-up", gl.conn_speed_up_bytes_per_second);
            set_or_remove_speed(tbl, "conn-speed-down", gl.conn_speed_down_bytes_per_second);
        }
    }

    // `[[outbound]]`
    if snapshot.outbounds.is_empty() {
        doc.remove("outbound");
    } else {
        let mut arr = toml_edit::ArrayOfTables::new();
        for ob in &snapshot.outbounds {
            let mut t = toml_edit::Table::new();
            t.insert("name", toml_edit::value(ob.name.as_str()));
            t.insert("url", toml_edit::value(ob.url.as_str()));
            if let Some(iface) = &ob.interface {
                t.insert("interface", toml_edit::value(iface.as_str()));
            }
            if let Some(v4) = ob.bind_ipv4 {
                t.insert("bind-ipv4", toml_edit::value(v4.to_string()));
            }
            if let Some(v6) = ob.bind_ipv6 {
                t.insert("bind-ipv6", toml_edit::value(v6.to_string()));
            }
            if let Some(mark) = ob.fwmark {
                t.insert("fwmark", toml_edit::value(i64::from(mark)));
            }
            if ob.weight != 100 {
                t.insert("weight", toml_edit::value(i64::from(ob.weight)));
            }
            if ob.max_fails != 5 {
                t.insert("max-fails", toml_edit::value(i64::from(ob.max_fails)));
            }
            if ob.cooldown_secs != 30 {
                t.insert(
                    "cooldown-secs",
                    toml_edit::value(ob.cooldown_secs.min(i64::MAX as u64) as i64),
                );
            }
            arr.push(t);
        }
        doc["outbound"] = toml_edit::Item::ArrayOfTables(arr);
    }

    // `[[outbound-group]]`
    if snapshot.outbound_groups.is_empty() {
        doc.remove("outbound-group");
    } else {
        let mut arr = toml_edit::ArrayOfTables::new();
        for grp in &snapshot.outbound_groups {
            let mut t = toml_edit::Table::new();
            t.insert("name", toml_edit::value(grp.name.as_str()));
            t.insert("strategy", toml_edit::value(grp.strategy.as_str()));
            let mut members = toml_edit::Array::new();
            for m in &grp.members {
                members.push(m.as_str());
            }
            t.insert("members", toml_edit::value(members));
            arr.push(t);
        }
        doc["outbound-group"] = toml_edit::Item::ArrayOfTables(arr);
    }

    // `[routing]`
    if snapshot.routing.default_outbound.is_none() && snapshot.routing.dc_routes.is_empty() {
        doc.remove("routing");
    } else {
        let mut rt = toml_edit::Table::new();
        if let Some(def) = &snapshot.routing.default_outbound {
            rt.insert("default-outbound", toml_edit::value(def.as_str()));
        }
        if !snapshot.routing.dc_routes.is_empty() {
            let mut dc_tbl = toml_edit::Table::new();
            for (dc, target) in &snapshot.routing.dc_routes {
                dc_tbl.insert(&dc.to_string(), toml_edit::value(target.as_str()));
            }
            rt.insert("dc", toml_edit::Item::Table(dc_tbl));
        }
        doc["routing"] = toml_edit::Item::Table(rt);
    }

    let rendered = doc.to_string();
    write_file_atomic_0600(config_path, rendered.as_bytes())
}

fn set_or_remove_speed(tbl: &mut toml_edit::Table, key: &str, bytes_per_sec: i64) {
    if bytes_per_sec > 0 {
        tbl.insert(key, toml_edit::value(format!("{bytes_per_sec}B/s")));
    } else {
        tbl.remove(key);
    }
}

fn set_or_remove_u32(tbl: &mut toml_edit::Table, key: &str, val: u32) {
    if val > 0 {
        tbl.insert(key, toml_edit::value(i64::from(val)));
    } else {
        tbl.remove(key);
    }
}

/// Parse an HTTP `If-Match` header against the current strong `ETag` (`"rev-N"`).
/// Returns `true` if `header` is omitted, `"*"`, or contains a matching revision tag.
pub fn if_match_satisfied(header: Option<&str>, current_revision: u64) -> bool {
    let Some(raw) = header.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    if raw == "*" {
        return true;
    }
    let want_bare = format!("rev-{current_revision}");
    let want_num = current_revision.to_string();
    for part in raw.split(',') {
        let mut token = part.trim();
        if let Some(stripped) = token
            .strip_prefix("W/")
            .or_else(|| token.strip_prefix("w/"))
        {
            token = stripped.trim();
        }
        let unquoted = token.trim_matches('"');
        if unquoted == want_bare || unquoted == want_num {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtg_config::Config;
    use mtg_net::OutboundStrategy;

    fn sample_snapshot() -> RuntimeStateSnapshot {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "alice".to_owned(),
            "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
                .to_owned(),
        );
        let mut secret_limits = BTreeMap::new();
        secret_limits.insert(
            "alice".to_owned(),
            SecretLimitsSnapshot {
                quota_bytes: 10_737_418_240,
                quota_reset: QuotaReset::Monthly,
                speed_bytes_per_second: 1_250_000,
                outbound: Some("xray-eu".to_owned()),
                ..SecretLimitsSnapshot::default()
            },
        );
        let mut dc_routes = BTreeMap::new();
        dc_routes.insert(2, "xray-eu".to_owned());

        RuntimeStateSnapshot {
            schema_version: RUNTIME_STATE_SCHEMA_VERSION,
            revision: 7,
            updated_at: Utc::now(),
            secrets,
            secret_ad_tags: BTreeMap::new(),
            secret_limits,
            global_ad_tag: None,
            concurrency: 4096,
            throttle_max_connections: 0,
            global_limits: GlobalLimitsSnapshot {
                max_connections_per_ip: 64,
                ..GlobalLimitsSnapshot::default()
            },
            outbounds: vec![OutboundSpec {
                name: "xray-eu".to_owned(),
                url: "unix+socks5:///run/xray/socks.sock".to_owned(),
                interface: None,
                bind_ipv4: None,
                bind_ipv6: None,
                fwmark: None,
                weight: 100,
                max_fails: 5,
                cooldown_secs: 30,
            }],
            outbound_groups: vec![OutboundGroupSpec {
                name: "egress".to_owned(),
                strategy: OutboundStrategy::Failover,
                members: vec!["xray-eu".to_owned(), "direct".to_owned()],
            }],
            routing: RoutingSpec {
                default_outbound: Some("egress".to_owned()),
                dc_routes,
            },
        }
    }

    #[test]
    fn overlay_atomic_save_verify_and_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime-state.json");
        let snap = sample_snapshot();
        save_overlay_atomic(&path, &snap).unwrap();

        let loaded = load_overlay_verified(&path).unwrap().unwrap();
        assert_eq!(loaded.revision, 7);
        assert_eq!(loaded.secrets, snap.secrets);
        assert_eq!(loaded.secret_limits, snap.secret_limits);
        assert_eq!(loaded.outbounds.len(), 1);
        assert_eq!(loaded.routing.default_outbound.as_deref(), Some("egress"));

        // Tamper with one byte of the JSON state -> SHA-256 verification MUST reject!
        let mut tampered = fs::read_to_string(&path).unwrap();
        tampered = tampered.replace("4096", "9999");
        fs::write(&path, tampered).unwrap();
        let err = load_overlay_verified(&path).unwrap_err();
        assert!(err.to_string().contains("SHA-256"), "err={err}");
    }

    #[test]
    fn toml_lossless_writeback_preserves_comments_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let original = r#"# Operator comment MUST survive lossless writeback!
bind-to = "0.0.0.0:443"
prefer-ip = "only-ipv4"

[secrets]
old = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
"#;
        fs::write(&cfg_path, original).unwrap();

        let snap = sample_snapshot();
        save_toml_atomic(&cfg_path, &snap).unwrap();

        let written = fs::read_to_string(&cfg_path).unwrap();
        assert!(
            written.contains("# Operator comment MUST survive lossless writeback!"),
            "comment lost:\n{written}"
        );
        let reparsed = Config::parse(written.as_bytes()).unwrap();
        reparsed.validate().unwrap();
        assert!(reparsed.get_secrets().contains_key("alice"));
        assert!(!reparsed.get_secrets().contains_key("old"));
        assert_eq!(reparsed.outbounds.len(), 1);
        assert_eq!(reparsed.routing.default_outbound.as_deref(), Some("egress"));
    }

    #[test]
    fn if_match_and_billing_checkpoint_deltas_work() {
        assert!(if_match_satisfied(None, 5));
        assert!(if_match_satisfied(Some("*"), 5));
        assert!(if_match_satisfied(Some("\"rev-5\""), 5));
        assert!(if_match_satisfied(Some("W/\"rev-5\""), 5));
        assert!(!if_match_satisfied(Some("\"rev-4\""), 5));

        let mut tracker = BillingTracker::new();
        let cp1 = tracker
            .checkpoint(
                "panel-a",
                false,
                &[("alice".into(), 1000, 2000, 3, 3000, 0, 1)],
            )
            .unwrap();
        assert_eq!(cp1.sequence, 1);
        assert_eq!(cp1.total_delta_bytes, 3000);

        // Peek does not advance cursor.
        let peek = tracker
            .checkpoint(
                "panel-a",
                true,
                &[("alice".into(), 1500, 2500, 4, 4000, 0, 1)],
            )
            .unwrap();
        assert_eq!(peek.total_delta_bytes, 1000);
        assert_eq!(peek.sequence, 1);

        // Next real checkpoint gets exact 1000 delta and advances sequence to 2.
        let cp2 = tracker
            .checkpoint(
                "panel-a",
                false,
                &[("alice".into(), 1500, 2500, 4, 4000, 0, 1)],
            )
            .unwrap();
        assert_eq!(cp2.total_delta_bytes, 1000);
        assert_eq!(cp2.sequence, 2);

        // Independent second consumer still gets full cumulative delta!
        let cp_b = tracker
            .checkpoint(
                "panel-b",
                false,
                &[("alice".into(), 1500, 2500, 4, 4000, 0, 1)],
            )
            .unwrap();
        assert_eq!(cp_b.total_delta_bytes, 4000);
    }
}
