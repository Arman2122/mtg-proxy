//! Exact JSON request & response DTOs matching Go `mtglib` and the Penhoon
//! panel API contract byte-for-field, including `#[serde(deny_unknown_fields)]`
//! strict decoding (Go `DisallowUnknownFields()`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mtg_core::{
    QuotaReset, SecretLimits, parse_expiry, parse_quota_bytes, parse_quota_reset, parse_speed,
};
use mtg_engine::ListenerReport;
use mtg_governance::BanEntryJson;
use mtg_net::{OutboundGroupSpec, OutboundSnapshot, OutboundSpec, RoutingSpec};
use serde::{Deserialize, Serialize};

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn is_false(v: &bool) -> bool {
    !*v
}

/// Top-level `GET /stats` JSON response.
#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub total_connections: i64,
    pub features: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttle: Option<ThrottleJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscated: Option<ObfuscatedJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faketls_handshake: Option<FakeTlsJson>,
    pub users: BTreeMap<String, UserStatsJson>,
}

/// `throttle` block on `GET /stats`.
#[derive(Debug, Clone, Serialize)]
pub struct ThrottleJson {
    pub active: bool,
    pub limit: i64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, i64>,
}

/// `obfuscated` block on `GET /stats` (present only when `[[listener]]` is configured).
#[derive(Debug, Clone, Serialize)]
pub struct ObfuscatedJson {
    pub trials: i64,
    pub misses: i64,
    pub denied: i64,
    pub draining: i64,
    pub rate_limited: i64,
}

/// `faketls_handshake` block on `GET /stats` (omitted until the door counts something).
#[derive(Debug, Clone, Serialize)]
pub struct FakeTlsJson {
    pub hinted: i64,
    pub scanned: i64,
    pub unmatched: i64,
    pub denied_ip: i64,
    pub denied_global: i64,
    pub oversized: i64,
    pub over_budget_matched: i64,
    pub enforced: bool,
    pub ns_per_block: f64,
}

/// Per-user stats entry under `GET /stats` (`users.<name>`).
#[derive(Debug, Clone, Serialize)]
pub struct UserStatsJson {
    pub connections: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub last_seen: Option<DateTime<Utc>>,

    pub quota_used: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub quota: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_remaining: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quota_reset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "is_false")]
    pub disabled: bool,

    #[serde(skip_serializing_if = "is_zero_i64")]
    pub quota_cutoffs: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub ad_tag_skipped: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub ad_tag_failed: i64,

    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub throttled_ms: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_down: i64,

    #[serde(skip_serializing_if = "is_zero_u32")]
    pub ip_limit: u32,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub active_ips: usize,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub ip_limit_refused: i64,

    #[serde(skip_serializing_if = "is_zero_u32")]
    pub client_conns: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub max_connections: u32,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_conns_refused: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit_down: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub client_fair: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit_down: i64,

    #[serde(skip_serializing_if = "is_zero_usize")]
    pub clients: usize,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub clients_overflow: u64,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connected_ips: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_ip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connected_ips_last_seen: BTreeMap<String, DateTime<Utc>>,

    #[serde(skip_serializing_if = "is_zero_usize")]
    pub retiring_keys: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retiring_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub retiring_connections: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retiring_last_seen: Option<DateTime<Utc>>,
}

/// One secret object returned by `GET /secrets` and `GET /secrets/{name}`.
#[derive(Debug, Clone, Serialize)]
pub struct SecretInfoJson {
    pub name: String,
    pub secret: String,
    pub host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ad_tag: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub effective_ad_tag: String,

    #[serde(skip_serializing_if = "is_zero_i64")]
    pub quota: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub quota_used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_remaining: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quota_reset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "is_false")]
    pub disabled: bool,

    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_down: i64,

    #[serde(skip_serializing_if = "is_zero_u32")]
    pub ip_limit: u32,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub active_ips: usize,

    #[serde(skip_serializing_if = "is_zero_u32")]
    pub client_conns: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub max_connections: u32,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub client_speed_limit_down: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub client_fair: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub conn_speed_limit_down: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,

    pub mode: String,
    #[serde(skip_serializing_if = "is_false")]
    pub unserved: bool,

    pub connections: i64,
    pub last_seen: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connected_ips: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_ip: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connected_ips_last_seen: BTreeMap<String, DateTime<Utc>>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_expires_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "is_zero_usize")]
    pub retiring_keys: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retiring_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub retiring_connections: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retiring_last_seen: Option<DateTime<Utc>>,
}

/// `GET /secrets` envelope.
#[derive(Debug, Clone, Serialize)]
pub struct SecretsListResponse {
    pub secrets: Vec<SecretInfoJson>,
}

/// `GET /secrets/{name}/external-ips` and `PUT /secrets/{name}/external-ips` response.
#[derive(Debug, Clone, Serialize)]
pub struct AddressReportJson {
    pub name: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub ip_limit: u32,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub active_ips: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connected_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connected_ips_last_seen: BTreeMap<String, DateTime<Utc>>,
}

/// Per-address usage block on `GET /secrets/{name}/clients`.
#[derive(Debug, Clone, Serialize)]
pub struct ClientUsageJson {
    pub connections: u32,
    pub bytes_in: i64,
    pub bytes_out: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub throttled_ms: i64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_up: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub speed_limit_down: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banned_until: Option<DateTime<Utc>>,
}

/// One row of `GET /secrets/{name}/clients`.
#[derive(Debug, Clone, Serialize)]
pub struct ClientRowJson {
    pub address: String,
    #[serde(flatten)]
    pub usage: ClientUsageJson,
}

/// `GET /secrets/{name}/clients` response.
#[derive(Debug, Clone, Serialize)]
pub struct ClientsReportJson {
    pub total: usize,
    pub overflow: u64,
    pub tracking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rest: Option<ClientUsageJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ClientRowJson>>,
}

/// `POST /secrets/{name}/kick` response.
#[derive(Debug, Clone, Serialize)]
pub struct KickResultJson {
    pub closed: usize,
}

/// `POST /secrets/{name}/bans` response.
#[derive(Debug, Clone, Serialize)]
pub struct BanResultJson {
    pub banned: usize,
    pub closed: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

/// `GET /secrets/{name}/bans` response.
#[derive(Debug, Clone, Serialize)]
pub struct BansReportJson {
    pub total: usize,
    pub tracking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bans: Option<Vec<BanEntryJson>>,
}

/// `DELETE /secrets/{name}/bans/{*address}` response.
#[derive(Debug, Clone, Serialize)]
pub struct UnbanResultJson {
    pub removed: u8,
}

/// `GET /adtag` response.
#[derive(Debug, Clone, Serialize)]
pub struct AdTagResponse {
    pub ad_tag: Option<String>,
}

/// Standard `{"status":"ok"}` response.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StatusOk {
    pub status: &'static str,
}

pub const STATUS_OK: StatusOk = StatusOk { status: "ok" };

/// Standard `{"error":"..."}` response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

// ============================================================================
// Strict Request Payloads (`#[serde(deny_unknown_fields)]`)
// ============================================================================

/// Shared per-secret limit fields in `PUT /secrets` and `POST /secrets`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitFieldsReq {
    #[serde(default)]
    pub quota: String,
    #[serde(default)]
    pub quota_reset: String,
    #[serde(default)]
    pub expires: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub speed: String,
    #[serde(default)]
    pub speed_up: String,
    #[serde(default)]
    pub speed_down: String,
    #[serde(default)]
    pub ip_limit: i64,
    #[serde(default)]
    pub client_conns: i64,
    #[serde(default)]
    pub max_connections: i64,
    #[serde(default)]
    pub client_speed: String,
    #[serde(default)]
    pub client_speed_up: String,
    #[serde(default)]
    pub client_speed_down: String,
    #[serde(default)]
    pub client_fair: bool,
    #[serde(default)]
    pub conn_speed: String,
    #[serde(default)]
    pub conn_speed_up: String,
    #[serde(default)]
    pub conn_speed_down: String,
    #[serde(default)]
    pub outbound: String,
}

impl LimitFieldsReq {
    pub fn parse_limits(&self) -> Result<SecretLimits, String> {
        if self.ip_limit < 0 || self.ip_limit > i64::from(u32::MAX) {
            return Err(format!("ip_limit must not be negative ({})", self.ip_limit));
        }
        if self.client_conns < 0 || self.client_conns > i64::from(u32::MAX) {
            return Err(format!(
                "client_conns must not be negative ({})",
                self.client_conns
            ));
        }
        if self.max_connections < 0 || self.max_connections > i64::from(u32::MAX) {
            return Err(format!(
                "max_connections must not be negative ({})",
                self.max_connections
            ));
        }
        let quota_bytes = parse_quota_bytes(&self.quota).map_err(|e| e.to_string())?;
        let quota_reset = parse_quota_reset(&self.quota_reset).map_err(|e| e.to_string())?;
        let expires_at = parse_expiry(&self.expires).map_err(|e| e.to_string())?;
        let speed = parse_speed(&self.speed).map_err(|e| e.to_string())?;
        let speed_up = parse_speed(&self.speed_up).map_err(|e| format!("speed_up: {e}"))?;
        let speed_down = parse_speed(&self.speed_down).map_err(|e| format!("speed_down: {e}"))?;
        let client_speed =
            parse_speed(&self.client_speed).map_err(|e| format!("client_speed: {e}"))?;
        let client_speed_up =
            parse_speed(&self.client_speed_up).map_err(|e| format!("client_speed_up: {e}"))?;
        let client_speed_down =
            parse_speed(&self.client_speed_down).map_err(|e| format!("client_speed_down: {e}"))?;
        let conn_speed = parse_speed(&self.conn_speed).map_err(|e| format!("conn_speed: {e}"))?;
        let conn_speed_up =
            parse_speed(&self.conn_speed_up).map_err(|e| format!("conn_speed_up: {e}"))?;
        let conn_speed_down =
            parse_speed(&self.conn_speed_down).map_err(|e| format!("conn_speed_down: {e}"))?;
        let outbound = (!self.outbound.trim().is_empty()).then(|| self.outbound.trim().to_owned());

        let lim = SecretLimits {
            quota_bytes,
            quota_reset,
            expires_at,
            disabled: self.disabled,
            speed_bytes_per_second: speed,
            speed_up_bytes_per_second: speed_up,
            speed_down_bytes_per_second: speed_down,
            ip_limit: self.ip_limit as u32,
            client_conns: self.client_conns as u32,
            max_connections: self.max_connections as u32,
            client_speed_bytes_per_second: client_speed,
            client_speed_up_bytes_per_second: client_speed_up,
            client_speed_down_bytes_per_second: client_speed_down,
            client_fair: self.client_fair,
            conn_speed_bytes_per_second: conn_speed,
            conn_speed_up_bytes_per_second: conn_speed_up,
            conn_speed_down_bytes_per_second: conn_speed_down,
            outbound,
        };

        if lim.client_fair && !lim.fair_totals().is_active() {
            return Err(
                "client_fair divides the secret's speed and needs speed, speed_up or speed_down"
                    .to_owned(),
            );
        }

        Ok(lim)
    }
}

/// Entry inside `PUT /secrets` (`secrets.<name>`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEntryReq {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub ad_tag: String,
    #[serde(default)]
    pub quota: String,
    #[serde(default)]
    pub quota_reset: String,
    #[serde(default)]
    pub expires: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub speed: String,
    #[serde(default)]
    pub speed_up: String,
    #[serde(default)]
    pub speed_down: String,
    #[serde(default)]
    pub ip_limit: i64,
    #[serde(default)]
    pub client_conns: i64,
    #[serde(default)]
    pub max_connections: i64,
    #[serde(default)]
    pub client_speed: String,
    #[serde(default)]
    pub client_speed_up: String,
    #[serde(default)]
    pub client_speed_down: String,
    #[serde(default)]
    pub client_fair: bool,
    #[serde(default)]
    pub conn_speed: String,
    #[serde(default)]
    pub conn_speed_up: String,
    #[serde(default)]
    pub conn_speed_down: String,
    #[serde(default)]
    pub outbound: String,
}

impl SecretEntryReq {
    pub fn parse_limits(&self) -> Result<SecretLimits, String> {
        LimitFieldsReq {
            quota: self.quota.clone(),
            quota_reset: self.quota_reset.clone(),
            expires: self.expires.clone(),
            disabled: self.disabled,
            speed: self.speed.clone(),
            speed_up: self.speed_up.clone(),
            speed_down: self.speed_down.clone(),
            ip_limit: self.ip_limit,
            client_conns: self.client_conns,
            max_connections: self.max_connections,
            client_speed: self.client_speed.clone(),
            client_speed_up: self.client_speed_up.clone(),
            client_speed_down: self.client_speed_down.clone(),
            client_fair: self.client_fair,
            conn_speed: self.conn_speed.clone(),
            conn_speed_up: self.conn_speed_up.clone(),
            conn_speed_down: self.conn_speed_down.clone(),
            outbound: self.outbound.clone(),
        }
        .parse_limits()
    }
}

/// `PUT /secrets` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutSecretsReq {
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretEntryReq>,
    #[serde(default)]
    pub ad_tag: String,
}

/// `POST /secrets` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostSecretReq {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub ad_tag: String,
    #[serde(default)]
    pub quota: String,
    #[serde(default)]
    pub quota_reset: String,
    #[serde(default)]
    pub expires: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub speed: String,
    #[serde(default)]
    pub speed_up: String,
    #[serde(default)]
    pub speed_down: String,
    #[serde(default)]
    pub ip_limit: i64,
    #[serde(default)]
    pub client_conns: i64,
    #[serde(default)]
    pub max_connections: i64,
    #[serde(default)]
    pub client_speed: String,
    #[serde(default)]
    pub client_speed_up: String,
    #[serde(default)]
    pub client_speed_down: String,
    #[serde(default)]
    pub client_fair: bool,
    #[serde(default)]
    pub conn_speed: String,
    #[serde(default)]
    pub conn_speed_up: String,
    #[serde(default)]
    pub conn_speed_down: String,
    #[serde(default)]
    pub outbound: String,
}

impl PostSecretReq {
    pub fn parse_limits(&self) -> Result<SecretLimits, String> {
        LimitFieldsReq {
            quota: self.quota.clone(),
            quota_reset: self.quota_reset.clone(),
            expires: self.expires.clone(),
            disabled: self.disabled,
            speed: self.speed.clone(),
            speed_up: self.speed_up.clone(),
            speed_down: self.speed_down.clone(),
            ip_limit: self.ip_limit,
            client_conns: self.client_conns,
            max_connections: self.max_connections,
            client_speed: self.client_speed.clone(),
            client_speed_up: self.client_speed_up.clone(),
            client_speed_down: self.client_speed_down.clone(),
            client_fair: self.client_fair,
            conn_speed: self.conn_speed.clone(),
            conn_speed_up: self.conn_speed_up.clone(),
            conn_speed_down: self.conn_speed_down.clone(),
            outbound: self.outbound.clone(),
        }
        .parse_limits()
    }
}

/// `POST /secrets/{name}/kick` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KickReq {
    #[serde(default)]
    pub ips: Vec<String>,
}

/// `POST /secrets/{name}/bans` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanReq {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ttl: String,
    #[serde(default)]
    pub force: bool,
}

/// `PUT /secrets/{name}/external-ips` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIpsReq {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ttl: String,
}

/// `PUT /adtag` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutAdTagReq {
    #[serde(default)]
    pub ad_tag: String,
}

/// Format quota reset string (`""` when `QuotaReset::None`, `"daily"` / `"weekly"` / `"monthly"` otherwise).
#[inline]
pub fn quota_reset_str(r: QuotaReset) -> String {
    match r {
        QuotaReset::None => String::new(),
        QuotaReset::Daily | QuotaReset::Weekly | QuotaReset::Monthly => r.as_str().to_owned(),
    }
}

// ============================================================================
// Enterprise Accounting, Health, Batch & IP Filter DTOs (v2.3.0+)
// ============================================================================

/// `GET /healthz` response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthzResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: i64,
    pub total_connections: i64,
    pub secrets_count: usize,
    pub allowlist_enabled: bool,
    pub allowlist_ready: bool,
    pub allowlist_entries: usize,
    pub blocklist_enabled: bool,
    pub blocklist_ready: bool,
    pub blocklist_entries: usize,
}

/// `PATCH /secrets/{name}` partial account mutation payload.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSecretReq {
    pub secret: Option<String>,
    pub ad_tag: Option<String>,
    pub quota: Option<String>,
    /// Add extra bytes to the user's current quota ceiling (billing top-up!).
    pub add_quota: Option<String>,
    /// Reset `quota_used` to `0` and restart the quota period atomically.
    #[serde(default)]
    pub reset_quota: bool,
    pub quota_reset: Option<String>,
    pub expires: Option<String>,
    pub disabled: Option<bool>,
    pub speed: Option<String>,
    pub speed_up: Option<String>,
    pub speed_down: Option<String>,
    pub ip_limit: Option<i64>,
    pub client_conns: Option<i64>,
    pub max_connections: Option<i64>,
    pub client_speed: Option<String>,
    pub client_speed_up: Option<String>,
    pub client_speed_down: Option<String>,
    pub client_fair: Option<bool>,
    pub conn_speed: Option<String>,
    pub conn_speed_up: Option<String>,
    pub conn_speed_down: Option<String>,
    /// Named outbound transport or group override (`""` clears override back to policy routing).
    pub outbound: Option<String>,
}

/// `POST /secrets/{name}/disconnect` response.
#[derive(Debug, Clone, Serialize)]
pub struct DisconnectResultJson {
    pub closed: usize,
}

/// `POST /secrets/batch` atomic bulk mutation request.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSecretsReq {
    #[serde(default)]
    pub upsert: BTreeMap<String, SecretEntryReq>,
    #[serde(default)]
    pub delete: Vec<String>,
}

/// `POST /secrets/batch` response.
#[derive(Debug, Clone, Serialize)]
pub struct BatchSecretsResultJson {
    pub status: &'static str,
    pub upserted: usize,
    pub deleted: usize,
}

/// Global aggregate totals inside `GET /accounting`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountingTotalsJson {
    pub total_bytes_in: i64,
    pub total_bytes_out: i64,
    pub total_bytes: i64,
    pub active_connections: i64,
    pub lifetime_connections: u64,
    pub secrets_count: usize,
    pub fronted_total: u64,
    pub allowlist_rejected_total: u64,
    pub blocklisted_total: u64,
    pub replay_attacks: u64,
}

/// Per-account billing & governance record inside `GET /accounting`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountLedgerRowJson {
    pub name: String,
    pub mode: String,
    pub active_connections: i64,
    pub total_connections: u64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub total_bytes: i64,
    pub quota: i64,
    pub quota_used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_remaining: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub quota_reset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_start: Option<DateTime<Utc>>,
    pub quota_cutoffs: i64,
    pub active_ips: usize,
    pub ip_limit: u32,
    pub max_connections: u32,
    pub speed_limit: i64,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// `GET /accounting` response.
#[derive(Debug, Clone, Serialize)]
pub struct AccountingResponse {
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub usage_persisted: bool,
    pub totals: AccountingTotalsJson,
    pub accounts: Vec<AccountLedgerRowJson>,
}

/// `POST /accounting/flush` response.
#[derive(Debug, Clone, Serialize)]
pub struct FlushResultJson {
    pub status: &'static str,
    pub flushed: bool,
}

/// `PATCH /limits` partial live update payload.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchGlobalLimitsReq {
    pub concurrency: Option<i64>,
    pub throttle_max_connections: Option<i64>,
    pub speed: Option<String>,
    pub speed_up: Option<String>,
    pub speed_down: Option<String>,
    pub quota: Option<String>,
    pub add_quota: Option<String>,
    #[serde(default)]
    pub reset_quota: bool,
    pub quota_reset: Option<String>,
    pub max_connections_per_ip: Option<i64>,
    pub max_new_connections_per_ip: Option<i64>,
    pub conn_speed: Option<String>,
    pub conn_speed_up: Option<String>,
    pub conn_speed_down: Option<String>,
}

/// `PUT /limits` full replacement payload (omitted fields reset to unlimited).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutGlobalLimitsReq {
    pub concurrency: Option<i64>,
    pub throttle_max_connections: Option<i64>,
    #[serde(default)]
    pub speed: String,
    #[serde(default)]
    pub speed_up: String,
    #[serde(default)]
    pub speed_down: String,
    #[serde(default)]
    pub quota: String,
    #[serde(default)]
    pub quota_reset: String,
    #[serde(default)]
    pub max_connections_per_ip: i64,
    #[serde(default)]
    pub max_new_connections_per_ip: i64,
    #[serde(default)]
    pub conn_speed: String,
    #[serde(default)]
    pub conn_speed_up: String,
    #[serde(default)]
    pub conn_speed_down: String,
}

// ============================================================================
// Enterprise Panel & Universal Outbound DTOs (v2.6.0+)
// ============================================================================

/// `GET /capabilities` — multi-core VPN panel discovery response.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesResponse {
    pub core: &'static str,
    pub protocol: &'static str,
    pub version: &'static str,
    pub boot_id: String,
    pub state_revision: u64,
    pub etag: String,
    pub persistence: &'static str,
    pub state_file_configured: bool,
    pub transports: &'static [&'static str],
    pub outbound_protocols: &'static [&'static str],
    pub outbound_strategies: &'static [&'static str],
    pub api_capabilities: &'static [&'static str],
    pub features: &'static [&'static str],
    pub listeners: Vec<ListenerReport>,
}

/// `POST /accounting/checkpoint` request payload.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingCheckpointReq {
    pub consumer_id: String,
    #[serde(default)]
    pub peek: bool,
}

/// `GET /outbounds` response payload.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundsReportJson {
    pub supported_protocols: &'static [&'static str],
    pub outbounds: Vec<OutboundSnapshot>,
    pub specs: Vec<OutboundSpec>,
    pub groups: Vec<OutboundGroupSpec>,
    pub routing: RoutingSpec,
}

/// `PUT /outbounds` request payload.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutOutboundsReq {
    #[serde(default)]
    pub outbounds: Vec<OutboundSpec>,
    #[serde(default)]
    pub outbound_groups: Vec<OutboundGroupSpec>,
    #[serde(default)]
    pub routing: RoutingSpec,
}

/// `POST /outbounds/{name}/probe` response payload.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundProbeResultJson {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
