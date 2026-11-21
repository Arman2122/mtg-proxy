//! Complete TOML configuration schema, lossless parser with unknown-key
//! reporting, validation, environment overlays, and credential-redacted JSON
//! rendering (`panel-config-string.golden` compatible).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mtg_core::{
    ModeSet, QuotaReset, Secret, SecretLimits, SecretMode, parse_expiry, parse_quota_reset,
    parse_speed,
};
use mtg_protocol::doppel::ShapingMode;
use serde_json::{Map, Value, json};
use thiserror::Error;
use toml_edit::{ImDocument, Item, TableLike, Value as TomlValue};
use zeroize::Zeroizing;

use crate::scrub::{
    UNKNOWN_KEY_LINE, reads_as_a_value, scrub_error_against_doc, shown_name, value_free_name,
};
use crate::types::{
    AD_TAG_LEN, ClientIpSource, HandshakeBudgetMode, HostPort, IpFilterAction, PreferIp,
    StatsdTagFormat, UnknownSecretAction, canonical_web_host, format_bytes_go, format_duration_go,
    parse_ad_tag, parse_bytes_str, parse_duration, redact_proxy_url, validate_ip_or_cidr,
};

/// Reserved `[secrets]` username that is never served (prevents hand-edit
/// `retiring-secret = "<old key>"` below `[secrets]` from acting as a permanent primary).
pub const MISPLACED_RETIRING_USER: &str = "retiring-secret";

/// Default per-IP obfuscated2 handshake failure budget on a public `[[listener]]`.
pub const DEFAULT_HANDSHAKES_PER_IP: u32 = 30;

/// Bitmask flags on [`ConfigRetiringSecret::wrong_type`].
pub const RETIRING_NAME_WRONG_TYPE: u8 = 1 << 0;
pub const RETIRING_SECRET_WRONG_TYPE: u8 = 1 << 1;
pub const RETIRING_UNTIL_WRONG_TYPE: u8 = 1 << 2;

const REDACTED: &str = "[redacted]";

/// Environment variable names (prefixed `MTG_` wins over bare official-image name).
pub const ENV_SECRET: &str = "SECRET";
pub const ENV_SECRET_HOST: &str = "SECRET_HOST";
pub const ENV_AD_TAG: &str = "TAG";
pub const ENV_BIND_TO: &str = "MTG_BIND_TO";

/// Errors returned while parsing, overlaying env vars, or validating [`Config`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("cannot parse toml config: {0}")]
    TomlSyntax(String),
    #[error("cannot parse a config: {0}")]
    FieldParse(String),
    #[error("bind-to is required")]
    MissingBindTo,
    #[error("bind-to array elements must be strings")]
    NonStringBindTo,
    #[error(
        r#"[secrets] holds only the reserved name "retiring-secret", which is never served, and the top-level secret is not served while [secrets] is present, so the file serves no secret: name the users to serve in [secrets], and write an old key as a [[retiring-secret]] block above [secrets]"#
    )]
    OnlyMisplacedRetiringUser,
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Environment(String),
}

/// Runtime policy derived from a `[[listener]]` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerPolicy {
    pub modes: ModeSet,
    pub public: bool,
    pub proxy_protocol: bool,
    pub on_unknown_secret: UnknownSecretAction,
    pub handshakes_per_ip: u32,
}

/// One `[[listener]]` stanza serving `dd` and/or `plain` secrets.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigListener {
    pub bind_to: Option<HostPort>,
    pub accept: Vec<SecretMode>,
    pub public: Option<bool>,
    pub proxy_protocol: Option<bool>,
    pub on_unknown_secret: Option<UnknownSecretAction>,
    pub handshakes_per_ip: Option<u32>,
}

impl ConfigListener {
    /// Convert this configured listener into its runtime [`ListenerPolicy`].
    pub fn policy(&self) -> Result<ListenerPolicy, ConfigError> {
        let modes = ModeSet::of(&self.accept);
        let addr = self.bind_to.as_ref().map_or("", HostPort::as_str);

        if modes.is_empty() || modes.has(SecretMode::FakeTls) {
            return Err(ConfigError::Validation(format!(
                "listener {addr}: accept must be a non-empty subset of [\"dd\",\"plain\"]; \
                 the top-level bind-to serves FakeTLS and a [[listener]] never does. \
                 Run two listeners if you need both"
            )));
        }

        Ok(ListenerPolicy {
            modes,
            public: self.public.unwrap_or(false),
            proxy_protocol: self.proxy_protocol.unwrap_or(false),
            on_unknown_secret: self.on_unknown_secret.unwrap_or(UnknownSecretAction::Close),
            handshakes_per_ip: self.handshakes_per_ip.unwrap_or(DEFAULT_HANDSHAKES_PER_IP),
        })
    }
}

/// One `[secret-limits.<name>]` table.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigSecretLimit {
    pub quota: Option<u64>,
    pub quota_reset: Option<QuotaReset>,
    pub expires: Option<DateTime<Utc>>,
    pub disabled: Option<bool>,
    pub speed: Option<i64>,
    pub speed_up: Option<i64>,
    pub speed_down: Option<i64>,
    pub ip_limit: Option<u32>,
    pub client_conns: Option<u32>,
    pub client_speed: Option<i64>,
    pub client_fair: Option<bool>,
}

/// One raw `[[retiring-secret]]` block prior to [`Config::get_retiring_secrets`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigRetiringSecret {
    pub name: String,
    pub secret: String,
    pub until: String,
    pub wrong_type: u8,
}

/// `[web]` configuration table for the WEB relay.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigWeb {
    pub enabled: Option<bool>,
    pub host: Option<String>,
    pub bind_to: Option<HostPort>,
    pub backend: Option<HostPort>,
    pub token_key: String,
    pub cover_dir: String,
    pub cover_upstream: String,
    pub client_ip: Option<ClientIpSource>,
    pub max_sessions: Option<u32>,
    pub max_streams: Option<u32>,
    pub max_frame_payload: Option<u64>,
    pub carrier_batch_bytes: Option<u64>,
    pub stats_bind_to: Option<HostPort>,
    /// Optional Rust-native zero-hop embedded mode (`[web] integrated = true`).
    pub integrated: Option<bool>,
}

/// `[defense.blocklist]` / `[defense.allowlist]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ListConfig {
    pub enabled: Option<bool>,
    pub download_concurrency: Option<u32>,
    pub urls: Option<Vec<String>>,
    pub update_each: Option<Duration>,
    /// Action on denied IP: `"front"` (default for allowlist: stealth cover-only) or `"close"` (default for blocklist).
    pub action: Option<IpFilterAction>,
    /// Optional inline IP/CIDR entries always merged with `urls`.
    pub cidrs: Option<Vec<String>>,
    /// Optional atomic on-disk cache path (instant warm boot & survives upstream outages).
    pub cache_file: Option<String>,
}

/// `[defense.anti-replay]`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AntiReplayConfig {
    pub enabled: Option<bool>,
    pub max_size: Option<u64>,
    pub error_rate: Option<f64>,
}

/// `[defense.doppelganger]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DoppelgangerConfig {
    pub urls: Option<Vec<String>>,
    pub repeats_per_raid: Option<u32>,
    pub raid_each: Option<Duration>,
    pub drs: Option<bool>,
    pub shaping: Option<ShapingMode>,
    pub scout_covers: Option<bool>,
}

/// `[defense.handshake-budget]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HandshakeBudgetConfig {
    pub mode: Option<HandshakeBudgetMode>,
    pub per_ip_ms: Option<u32>,
    pub cpu_percent: Option<u32>,
    pub hints: Option<bool>,
}

impl HandshakeBudgetConfig {
    pub const fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.per_ip_ms.is_none()
            && self.cpu_percent.is_none()
            && self.hints.is_none()
    }
}

/// `[defense]`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DefenseConfig {
    pub anti_replay: AntiReplayConfig,
    pub blocklist: ListConfig,
    pub allowlist: ListConfig,
    pub doppelganger: DoppelgangerConfig,
    pub handshake_budget: HandshakeBudgetConfig,
}

/// `[domain-fronting]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainFrontingConfig {
    pub host: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub proxy_protocol: Option<bool>,
}

/// `[network.timeout]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TimeoutConfig {
    pub tcp: Option<Duration>,
    pub http: Option<Duration>,
    pub idle: Option<Duration>,
    pub handshake: Option<Duration>,
}

/// `[network.keep-alive]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeepAliveConfig {
    pub disabled: Option<bool>,
    pub idle: Option<Duration>,
    pub interval: Option<Duration>,
    pub count: Option<u32>,
}

/// `[network]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub timeout: TimeoutConfig,
    pub keep_alive: KeepAliveConfig,
    pub doh_ip: Option<IpAddr>,
    pub dns: Option<String>,
    pub proxies: Option<Vec<String>>,
    pub tcp_not_sent_lowat: Option<u64>,
}

/// `[throttle]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ThrottleConfig {
    pub max_connections: Option<u32>,
    pub check_interval: Option<Duration>,
}

/// `[stats.statsd]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatsdConfig {
    pub enabled: Option<bool>,
    pub address: Option<HostPort>,
    pub metric_prefix: Option<String>,
    pub tag_format: Option<StatsdTagFormat>,
}

/// `[stats.prometheus]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrometheusConfig {
    pub enabled: Option<bool>,
    pub bind_to: Option<HostPort>,
    pub http_path: Option<String>,
    pub metric_prefix: Option<String>,
}

/// `[stats]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatsConfig {
    pub statsd: StatsdConfig,
    pub prometheus: PrometheusConfig,
}

/// Full parsed `mtg-proxy` configuration.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Config {
    pub debug: Option<bool>,
    pub allow_fallback_on_unknown_dc: Option<bool>,
    pub secret: Option<Secret>,
    pub secrets: BTreeMap<String, Secret>,
    pub ad_tag: Option<Zeroizing<[u8; AD_TAG_LEN]>>,
    pub secret_ad_tags: BTreeMap<String, Zeroizing<[u8; AD_TAG_LEN]>>,
    pub secret_limits: BTreeMap<String, ConfigSecretLimit>,
    pub retiring_secrets: Vec<ConfigRetiringSecret>,
    pub unknown_keys: Vec<String>,
    pub usage_state_file: String,
    pub api_token: Zeroizing<String>,
    pub bind_to: Vec<HostPort>,
    pub listeners: Vec<ConfigListener>,
    pub web: ConfigWeb,
    pub proxy_protocol_listener: Option<bool>,
    pub prefer_ip: Option<PreferIp>,
    pub auto_update: Option<bool>,
    pub track_client_ips: Option<bool>,
    pub domain_fronting_port: Option<u16>,
    pub domain_fronting_ip: Option<IpAddr>,
    pub domain_fronting_proxy_protocol: Option<bool>,
    pub tolerate_time_skewness: Option<Duration>,
    pub concurrency: Option<u32>,
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
    pub domain_fronting: DomainFrontingConfig,
    pub defense: DefenseConfig,
    pub network: NetworkConfig,
    pub api_bind_to: Option<HostPort>,
    pub throttle: ThrottleConfig,
    pub stats: StatsConfig,
}

impl Config {
    /// Parse a TOML configuration document directly from raw UTF-8 bytes.
    ///
    /// - Rejects UTF-8 BOM and syntax errors with value-free scrubbed diagnostics.
    /// - Collects all unknown TOML keys sorted with scrubbed secret-like segments.
    /// - Supports both `bind-to = "..."` and `bind-to = ["...", "..."]`.
    /// - Supports both bare-integer and string-unit `quota` / byte fields.
    /// - Preserves explicit `0` and `false` values everywhere.
    pub fn parse(raw_data: &[u8]) -> Result<Self, ConfigError> {
        // Reject UTF-8 BOM identically to Go's go-toml strict behavior.
        if raw_data.starts_with(&[0xef, 0xbb, 0xbf]) {
            return Err(ConfigError::TomlSyntax(
                "unexpected UTF-8 byte-order mark at start of config".to_owned(),
            ));
        }

        let text = std::str::from_utf8(raw_data)
            .map_err(|_| ConfigError::TomlSyntax("config file is not valid UTF-8".to_owned()))?;

        let doc = ImDocument::parse(text.to_owned()).map_err(|err| {
            let msg = err.message().to_owned();
            let (scrubbed, replaced) = scrub_error_against_doc(raw_data, &msg);
            if replaced && let Some(span) = err.span() {
                let (line, col) = line_col(raw_data, span.start);
                return ConfigError::TomlSyntax(format!("{scrubbed} (line {line}, column {col})"));
            }
            ConfigError::TomlSyntax(scrubbed)
        })?;

        let mut cfg = Self::default();
        let mut unknown = BTreeSet::new();
        let root = doc.as_table();

        parse_root_table(raw_data, root, &mut cfg, &mut unknown).map_err(|err| {
            // Scrub any value-like run that appeared in doc from FieldParse errors.
            match err {
                ConfigError::FieldParse(msg) => {
                    let (scrubbed, _) = scrub_error_against_doc(raw_data, &msg);
                    ConfigError::FieldParse(scrubbed)
                }
                other => other,
            }
        })?;

        if cfg.bind_to.is_empty() {
            return Err(ConfigError::MissingBindTo);
        }

        cfg.unknown_keys = unknown.into_iter().collect();
        Ok(cfg)
    }

    /// Overlay `MTG_SECRET`/`SECRET`, `MTG_SECRET_HOST`/`SECRET_HOST`,
    /// `MTG_TAG`/`TAG`, and `MTG_BIND_TO` environment variables onto `self`.
    pub fn apply_environment(&mut self) -> Result<(), ConfigError> {
        self.apply_environment_with(|k| std::env::var(k).ok())
    }

    /// Deterministic testable variant of [`Self::apply_environment`].
    pub fn apply_environment_with<F>(&mut self, mut getenv: F) -> Result<(), ConfigError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut lookup = |name: &str| -> Option<String> {
            getenv(&format!("MTG_{name}")).or_else(|| getenv(name))
        };

        if let Some(val) = lookup(ENV_SECRET) {
            let mut secret = Secret::parse(val.trim()).map_err(|e| {
                ConfigError::Environment(format!(
                    "incorrect {ENV_SECRET} environment variable: {e}"
                ))
            })?;
            if secret.mode() != SecretMode::FakeTls {
                let host = lookup(ENV_SECRET_HOST)
                    .map(|h| h.trim().to_owned())
                    .unwrap_or_default();
                if host.is_empty() {
                    return Err(ConfigError::Environment(format!(
                        "{ENV_SECRET} is a {}-mode secret with no fronting hostname; the bind-to listener serves FakeTLS \
                         only and the environment cannot declare a [[listener]], so either set {ENV_SECRET_HOST} to a fronting \
                         domain, provide a full ee-prefixed secret, or move the secret into the config file's \
                         [secrets] table alongside a matching [[listener]]",
                        secret.mode()
                    )));
                }
                secret = Secret::from_parts(*secret.key(), host, SecretMode::FakeTls);
            }
            self.secret = Some(secret);
            self.secrets.clear();
            self.secret_ad_tags.clear();
            self.secret_limits.clear();
            self.retiring_secrets.clear();
        }

        if let Some(val) = lookup(ENV_AD_TAG) {
            let parsed = parse_ad_tag(val.trim()).map_err(|e| {
                ConfigError::Environment(format!(
                    "incorrect {ENV_AD_TAG} environment variable: {e}"
                ))
            })?;
            self.ad_tag = parsed.map(Zeroizing::new);
        }

        if let Some(val) = getenv(ENV_BIND_TO) {
            let mut binds = Vec::new();
            for part in val.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                let hp = HostPort::parse(p).map_err(|e| {
                    ConfigError::Environment(format!(
                        "incorrect {ENV_BIND_TO} environment variable: {e}"
                    ))
                })?;
                binds.push(hp);
            }
            if binds.is_empty() {
                return Err(ConfigError::Environment(format!(
                    "{ENV_BIND_TO} must contain at least one host:port"
                )));
            }
            self.bind_to = binds;
        }

        Ok(())
    }

    /// Return the served secret map (`[secrets]` excluding reserved `"retiring-secret"`,
    /// or `{"default": secret}` when `[secrets]` is empty).
    pub fn get_secrets(&self) -> BTreeMap<String, Secret> {
        if !self.secrets.is_empty() {
            return self.served_secrets();
        }
        let mut map = BTreeMap::new();
        if let Some(s) = &self.secret {
            map.insert("default".to_owned(), s.clone());
        }
        map
    }

    fn served_secrets(&self) -> BTreeMap<String, Secret> {
        self.secrets
            .iter()
            .filter(|(k, _)| k.as_str() != MISPLACED_RETIRING_USER)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Return per-secret engine-level [`SecretLimits`] (omitting all-zero entries).
    pub fn get_secret_limits(&self) -> BTreeMap<String, SecretLimits> {
        let mut out = BTreeMap::new();
        for (name, cfg) in &self.secret_limits {
            let lim = SecretLimits {
                quota_bytes: cfg.quota.unwrap_or(0) as i64,
                quota_reset: cfg.quota_reset.unwrap_or(QuotaReset::None),
                expires_at: cfg.expires,
                disabled: cfg.disabled.unwrap_or(false),
                speed_bytes_per_second: cfg.speed.unwrap_or(0),
                speed_up_bytes_per_second: cfg.speed_up.unwrap_or(0),
                speed_down_bytes_per_second: cfg.speed_down.unwrap_or(0),
                ip_limit: cfg.ip_limit.unwrap_or(0),
                client_conns: cfg.client_conns.unwrap_or(0),
                client_speed_bytes_per_second: cfg.client_speed.unwrap_or(0),
                client_fair: cfg.client_fair.unwrap_or(false),
            };
            if !lim.is_zero() {
                out.insert(name.clone(), lim);
            }
        }
        out
    }

    /// Return per-secret 16-byte `ad_tag` overrides.
    pub fn get_secret_ad_tags(&self) -> BTreeMap<String, [u8; AD_TAG_LEN]> {
        self.secret_ad_tags
            .iter()
            .map(|(k, v)| (k.clone(), **v))
            .collect()
    }

    pub fn get_domain_fronting_host(&self) -> &str {
        self.domain_fronting.host.as_deref().unwrap_or("")
    }

    pub fn get_domain_fronting_port(&self, default_port: u16) -> u16 {
        self.domain_fronting
            .port
            .or(self.domain_fronting_port)
            .unwrap_or(default_port)
    }

    pub fn get_domain_fronting_ip(&self) -> Option<IpAddr> {
        self.domain_fronting.ip.or(self.domain_fronting_ip)
    }

    pub fn get_domain_fronting_proxy_protocol(&self, default_val: bool) -> bool {
        self.domain_fronting
            .proxy_protocol
            .or(self.domain_fronting_proxy_protocol)
            .unwrap_or(default_val)
    }

    pub fn get_listener_modes(&self) -> ModeSet {
        let mut set = ModeSet::empty();
        for l in &self.listeners {
            set |= ModeSet::of(&l.accept);
        }
        set
    }

    /// Find the `[[listener]]` referenced by `[web] backend`.
    pub fn web_backend_listener(&self) -> Option<&ConfigListener> {
        let backend = self.web.backend.as_ref()?;
        self.listeners
            .iter()
            .find(|l| l.bind_to.as_ref().is_some_and(|b| b.same_address(backend)))
    }

    /// Format human-friendly warning lines for all unknown TOML keys.
    pub fn unknown_key_warnings(&self) -> Vec<String> {
        self.unknown_keys
            .iter()
            .map(|k| {
                format!(
                    "unknown config key {k:?} is ignored: a typo, or a key written under the wrong table?"
                )
            })
            .collect()
    }

    /// Validate proxy configuration semantics (secrets, bind addresses, listeners,
    /// fronting cover availability, ad-tags, and secret-limits cross-checks).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let served = self.served_secrets();
        if self.secrets.is_empty() {
            match &self.secret {
                Some(s) if s.is_valid() => {}
                _ => {
                    return Err(ConfigError::Validation(
                        "invalid or missing secret".to_owned(),
                    ));
                }
            }
        } else if served.is_empty() {
            return Err(ConfigError::OnlyMisplacedRetiringUser);
        } else {
            for (name, s) in &served {
                if !s.is_valid() {
                    return Err(ConfigError::Validation(format!(
                        "invalid secret {}",
                        shown_name(name)
                    )));
                }
            }
        }

        if self.bind_to.is_empty() {
            return Err(ConfigError::Validation(
                "incorrect bind-to parameter: no addresses specified".to_owned(),
            ));
        }

        let mut seen = BTreeSet::new();
        for addr in &self.bind_to {
            if !seen.insert(addr.as_str().to_owned()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate bind-to address: {addr}"
                )));
            }
        }

        for l in &self.listeners {
            let Some(bind) = &l.bind_to else {
                return Err(ConfigError::Validation(
                    "incorrect listener bind-to parameter: empty address".to_owned(),
                ));
            };
            if !seen.insert(bind.as_str().to_owned()) {
                return Err(ConfigError::Validation(format!(
                    "two listeners bind {bind}; one address serves one accept policy"
                )));
            }
            let policy = l.policy()?;
            if !bind.is_loopback() && !policy.public {
                return Err(ConfigError::Validation(format!(
                    "listener {bind} accepts {:?} on a public address. \
                     A non-FakeTLS listener answers obfuscated2 and is fingerprintable as an MTProto proxy. \
                     Set public = true on this [[listener]] to confirm, or bind it to 127.0.0.1",
                    policy.modes.sorted_names()
                )));
            }
        }

        // V4: bind-to is permanently FakeTLS-only; need at least one ee secret or domain-fronting.host.
        let has_fronting = !self.get_domain_fronting_host().is_empty()
            || self.get_secrets().values().any(Secret::is_hosted);
        if !has_fronting {
            return Err(ConfigError::Validation(
                "no secret carries a fronting hostname and domain-fronting.host is unset; \
                 the FakeTLS listener would have no cover site. \
                 Set domain-fronting.host, or keep at least one ee secret"
                    .to_owned(),
            ));
        }

        let known: BTreeSet<&str> = if self.secrets.is_empty() {
            BTreeSet::from(["default"])
        } else {
            self.secrets.keys().map(String::as_str).collect()
        };

        for name in self.secret_ad_tags.keys() {
            if !known.contains(name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "secret-ad-tags refers to unknown secret {}",
                    shown_name(name)
                )));
            }
        }

        for (name, lim) in &self.secret_limits {
            if !known.contains(name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "secret-limits refers to unknown secret {}",
                    shown_name(name)
                )));
            }
            if lim.client_fair.unwrap_or(false)
                && lim.speed.unwrap_or(0) == 0
                && lim.speed_up.unwrap_or(0) == 0
                && lim.speed_down.unwrap_or(0) == 0
            {
                return Err(ConfigError::Validation(format!(
                    "secret-limits.{}: client-fair divides the secret's speed among its addresses \
                     and needs speed, speed-up or speed-down beside it",
                    value_free_name(name)
                )));
            }
        }

        for (section, list) in [
            ("defense.allowlist", &self.defense.allowlist),
            ("defense.blocklist", &self.defense.blocklist),
        ] {
            if let Some(cidrs) = &list.cidrs {
                for entry in cidrs {
                    validate_ip_or_cidr(entry)
                        .map_err(|e| ConfigError::Validation(format!("{section}.cidrs: {e}")))?;
                }
            }
        }

        Ok(())
    }

    /// Validate `[web]` table separately from core proxy validation.
    pub fn validate_web(&self) -> Result<(), ConfigError> {
        if !self.web.enabled.unwrap_or(false) {
            return Err(ConfigError::Validation(
                "[web] is not enabled in this configuration".to_owned(),
            ));
        }

        let host = self.web.host.as_deref().unwrap_or("");
        canonical_web_host(host)
            .map_err(|e| ConfigError::Validation(format!("[web] host: {e}")))?;

        if self.web.bind_to.is_none() {
            return Err(ConfigError::Validation(
                "[web] bind-to is required".to_owned(),
            ));
        }

        let integrated = self.web.integrated.unwrap_or(false);
        if !integrated && self.web.backend.is_none() {
            return Err(ConfigError::Validation(
                "[web] backend is required".to_owned(),
            ));
        }

        if self.web.token_key.is_empty() {
            return Err(ConfigError::Validation(
                "[web] token-key is required; create one with 'mtg-proxy generate-web-key <path>'"
                    .to_owned(),
            ));
        }

        if self.web.cover_dir.is_empty() == self.web.cover_upstream.is_empty() {
            return Err(ConfigError::Validation(
                "[web] needs exactly one of cover-dir or cover-upstream: \
                 the hostname must serve a plausible website to everyone who is not a Telegram client"
                    .to_owned(),
            ));
        }

        if let Some(stats_bind) = &self.web.stats_bind_to
            && !stats_bind.is_loopback()
        {
            return Err(ConfigError::Validation(format!(
                "[web] stats-bind-to must be a loopback address: {:?} is reachable from outside this host",
                stats_bind.as_str()
            )));
        }

        if !integrated {
            let backend = self.web.backend.as_ref().expect("checked above");
            let Some(listener) = self.web_backend_listener() else {
                return Err(ConfigError::Validation(format!(
                    "[web] backend {backend} names no [[listener]]; \
                     the relay dials one of this proxy's own loopback sockets"
                )));
            };
            let policy = listener.policy()?;
            if !policy.modes.has(SecretMode::Dd) {
                return Err(ConfigError::Validation(format!(
                    "[web] backend {backend} does not accept dd secrets, which is the only form a WEB client can hold"
                )));
            }
        }

        Ok(())
    }

    /// Render the configuration as a single-line compact JSON string with every
    /// credential redacted (`[redacted]`), matching Go `Config.String()` and
    /// `panel-config-string.golden` byte-for-byte!
    pub fn redacted_json(&self) -> String {
        let mut root = Map::new();

        root.insert("adTag".into(), Value::String(REDACTED.into()));
        root.insert(
            "allowFallbackOnUnknownDc".into(),
            Value::Bool(self.allow_fallback_on_unknown_dc.unwrap_or(false)),
        );
        root.insert(
            "apiBindTo".into(),
            Value::String(
                self.api_bind_to
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        root.insert("apiToken".into(), Value::String(REDACTED.into()));
        root.insert(
            "autoUpdate".into(),
            Value::Bool(self.auto_update.unwrap_or(false)),
        );
        root.insert(
            "bindTo".into(),
            Value::Array(
                self.bind_to
                    .iter()
                    .map(|b| Value::String(b.as_str().to_owned()))
                    .collect(),
            ),
        );
        root.insert("concurrency".into(), json!(self.concurrency.unwrap_or(0)));
        root.insert("debug".into(), Value::Bool(self.debug.unwrap_or(false)));

        // defense
        let mut defense = Map::new();
        defense.insert("allowlist".into(), list_to_json(&self.defense.allowlist));
        let mut ar = Map::new();
        ar.insert(
            "enabled".into(),
            self.defense
                .anti_replay
                .enabled
                .map_or(Value::Null, Value::Bool),
        );
        let er = self.defense.anti_replay.error_rate.unwrap_or(0.0);
        ar.insert(
            "errorRate".into(),
            if er == 0.0 { json!(0) } else { json!(er) },
        );
        ar.insert(
            "maxSize".into(),
            Value::String(
                self.defense
                    .anti_replay
                    .max_size
                    .map_or_else(String::new, format_bytes_go),
            ),
        );
        defense.insert("antiReplay".into(), Value::Object(ar));
        defense.insert("blocklist".into(), list_to_json(&self.defense.blocklist));

        let mut dop = Map::new();
        dop.insert(
            "drs".into(),
            Value::Bool(self.defense.doppelganger.drs.unwrap_or(false)),
        );
        dop.insert(
            "raid_each".into(),
            Value::String(
                self.defense
                    .doppelganger
                    .raid_each
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        dop.insert(
            "repeats_per_raid".into(),
            json!(self.defense.doppelganger.repeats_per_raid.unwrap_or(0)),
        );
        dop.insert(
            "scout_covers".into(),
            self.defense
                .doppelganger
                .scout_covers
                .map_or(Value::Null, Value::Bool),
        );
        dop.insert(
            "shaping".into(),
            Value::String(
                self.defense
                    .doppelganger
                    .shaping
                    .map_or_else(String::new, |s| s.as_str().to_owned()),
            ),
        );
        dop.insert(
            "urls".into(),
            opt_vec_str_to_json(self.defense.doppelganger.urls.as_deref()),
        );
        defense.insert("doppelganger".into(), Value::Object(dop));

        if !self.defense.handshake_budget.is_empty() {
            let mut hb = Map::new();
            hb.insert(
                "cpuPercent".into(),
                json!(self.defense.handshake_budget.cpu_percent.unwrap_or(0)),
            );
            if let Some(h) = self.defense.handshake_budget.hints {
                hb.insert("hints".into(), Value::Bool(h));
            }
            hb.insert(
                "mode".into(),
                Value::String(
                    self.defense
                        .handshake_budget
                        .mode
                        .map_or_else(String::new, |m| m.as_str().to_owned()),
                ),
            );
            if let Some(ms) = self.defense.handshake_budget.per_ip_ms {
                hb.insert("perIpMs".into(), json!(ms));
            }
            defense.insert("handshakeBudget".into(), Value::Object(hb));
        }
        root.insert("defense".into(), Value::Object(defense));

        // domainFronting
        let mut df = Map::new();
        df.insert(
            "host".into(),
            Value::String(self.domain_fronting.host.clone().unwrap_or_default()),
        );
        df.insert(
            "ip".into(),
            Value::String(
                self.domain_fronting
                    .ip
                    .map_or_else(String::new, |ip| ip.to_string()),
            ),
        );
        df.insert("port".into(), json!(self.domain_fronting.port.unwrap_or(0)));
        df.insert(
            "proxyProtocol".into(),
            Value::Bool(self.domain_fronting.proxy_protocol.unwrap_or(false)),
        );
        root.insert("domainFronting".into(), Value::Object(df));
        root.insert(
            "domainFrontingIp".into(),
            Value::String(
                self.domain_fronting_ip
                    .map_or_else(String::new, |ip| ip.to_string()),
            ),
        );
        root.insert(
            "domainFrontingPort".into(),
            json!(self.domain_fronting_port.unwrap_or(0)),
        );
        root.insert(
            "domainFrontingProxyProtocol".into(),
            Value::Bool(self.domain_fronting_proxy_protocol.unwrap_or(false)),
        );

        // listeners
        root.insert(
            "listeners".into(),
            if self.listeners.is_empty() {
                Value::Null
            } else {
                Value::Array(
                    self.listeners
                        .iter()
                        .map(|l| {
                            let mut lm = Map::new();
                            lm.insert(
                                "accept".into(),
                                Value::Array(
                                    l.accept
                                        .iter()
                                        .map(|m| Value::String(m.as_str().to_owned()))
                                        .collect(),
                                ),
                            );
                            lm.insert(
                                "bindTo".into(),
                                Value::String(
                                    l.bind_to
                                        .as_ref()
                                        .map_or_else(String::new, |b| b.as_str().to_owned()),
                                ),
                            );
                            lm.insert(
                                "handshakesPerIp".into(),
                                json!(l.handshakes_per_ip.unwrap_or(0)),
                            );
                            lm.insert(
                                "onUnknownSecret".into(),
                                Value::String(
                                    l.on_unknown_secret
                                        .map_or_else(String::new, |a| a.as_str().to_owned()),
                                ),
                            );
                            lm.insert(
                                "proxyProtocol".into(),
                                Value::Bool(l.proxy_protocol.unwrap_or(false)),
                            );
                            lm.insert("public".into(), Value::Bool(l.public.unwrap_or(false)));
                            Value::Object(lm)
                        })
                        .collect(),
                )
            },
        );

        // network
        let mut net = Map::new();
        net.insert(
            "dns".into(),
            Value::String(self.network.dns.clone().unwrap_or_default()),
        );
        net.insert(
            "dohIp".into(),
            Value::String(
                self.network
                    .doh_ip
                    .map_or_else(String::new, |ip| ip.to_string()),
            ),
        );
        let mut ka = Map::new();
        ka.insert(
            "count".into(),
            json!(self.network.keep_alive.count.unwrap_or(0)),
        );
        ka.insert(
            "disabled".into(),
            Value::Bool(self.network.keep_alive.disabled.unwrap_or(false)),
        );
        ka.insert(
            "idle".into(),
            Value::String(
                self.network
                    .keep_alive
                    .idle
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        ka.insert(
            "interval".into(),
            Value::String(
                self.network
                    .keep_alive
                    .interval
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        net.insert("keepAlive".into(), Value::Object(ka));
        net.insert(
            "proxies".into(),
            match &self.network.proxies {
                None => Value::Null,
                Some(list) => Value::Array(
                    list.iter()
                        .map(|u| Value::String(redact_proxy_url(u)))
                        .collect(),
                ),
            },
        );
        net.insert(
            "tcpNotSentLowat".into(),
            Value::String(
                self.network
                    .tcp_not_sent_lowat
                    .map_or_else(String::new, format_bytes_go),
            ),
        );
        let mut to = Map::new();
        to.insert(
            "handshake".into(),
            Value::String(
                self.network
                    .timeout
                    .handshake
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        to.insert(
            "http".into(),
            Value::String(
                self.network
                    .timeout
                    .http
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        to.insert(
            "idle".into(),
            Value::String(
                self.network
                    .timeout
                    .idle
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        to.insert(
            "tcp".into(),
            Value::String(
                self.network
                    .timeout
                    .tcp
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        net.insert("timeout".into(), Value::Object(to));
        root.insert("network".into(), Value::Object(net));

        root.insert(
            "preferIp".into(),
            Value::String(
                self.prefer_ip
                    .map_or_else(String::new, |p| p.as_str().to_owned()),
            ),
        );
        root.insert(
            "proxyProtocolListener".into(),
            Value::Bool(self.proxy_protocol_listener.unwrap_or(false)),
        );
        root.insert(
            "publicIpv4".into(),
            Value::String(
                self.public_ipv4
                    .map_or_else(String::new, |ip| ip.to_string()),
            ),
        );
        root.insert(
            "publicIpv6".into(),
            Value::String(
                self.public_ipv6
                    .map_or_else(String::new, |ip| ip.to_string()),
            ),
        );

        if !self.retiring_secrets.is_empty() {
            let arr = self
                .retiring_secrets
                .iter()
                .map(|r| {
                    let mut m = Map::new();
                    let name = if (r.wrong_type & RETIRING_NAME_WRONG_TYPE) != 0
                        || reads_as_a_value(&r.name)
                    {
                        REDACTED.to_owned()
                    } else {
                        r.name.clone()
                    };
                    let until = if (r.wrong_type & RETIRING_UNTIL_WRONG_TYPE) != 0
                        || reads_as_a_value(&r.until)
                    {
                        REDACTED.to_owned()
                    } else {
                        r.until.clone()
                    };
                    m.insert("name".into(), Value::String(name));
                    m.insert("secret".into(), Value::String(REDACTED.into()));
                    m.insert("until".into(), Value::String(until));
                    Value::Object(m)
                })
                .collect();
            root.insert("retiringSecrets".into(), Value::Array(arr));
        }

        root.insert("secret".into(), Value::String(REDACTED.into()));

        root.insert(
            "secretAdTags".into(),
            if self.secret_ad_tags.is_empty() {
                Value::Null
            } else {
                let mut m = Map::new();
                for name in self.secret_ad_tags.keys() {
                    m.insert(name.clone(), Value::String(REDACTED.into()));
                }
                Value::Object(m)
            },
        );

        root.insert(
            "secretLimits".into(),
            if self.secret_limits.is_empty() {
                Value::Null
            } else {
                let mut m = Map::new();
                for (name, lim) in &self.secret_limits {
                    let mut lm = Map::new();
                    if let Some(cc) = lim.client_conns
                        && cc > 0
                    {
                        lm.insert("clientConns".into(), json!(cc));
                    }
                    if let Some(cf) = lim.client_fair
                        && cf
                    {
                        lm.insert("clientFair".into(), Value::Bool(true));
                    }
                    if let Some(cs) = lim.client_speed
                        && cs > 0
                    {
                        lm.insert("clientSpeed".into(), Value::String(format!("{cs}B/s")));
                    }
                    lm.insert(
                        "disabled".into(),
                        Value::Bool(lim.disabled.unwrap_or(false)),
                    );
                    lm.insert(
                        "expires".into(),
                        Value::String(lim.expires.map_or_else(String::new, |t| {
                            t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                        })),
                    );
                    lm.insert("ipLimit".into(), json!(lim.ip_limit.unwrap_or(0)));
                    lm.insert(
                        "quota".into(),
                        Value::String(lim.quota.map_or_else(String::new, format_bytes_go)),
                    );
                    lm.insert(
                        "quotaReset".into(),
                        Value::String(
                            lim.quota_reset
                                .map_or_else(String::new, |q| q.as_str().to_owned()),
                        ),
                    );
                    lm.insert(
                        "speed".into(),
                        Value::String(lim.speed.map_or_else(String::new, |s| format!("{s}B/s"))),
                    );
                    lm.insert(
                        "speedDown".into(),
                        Value::String(
                            lim.speed_down
                                .map_or_else(String::new, |s| format!("{s}B/s")),
                        ),
                    );
                    lm.insert(
                        "speedUp".into(),
                        Value::String(lim.speed_up.map_or_else(String::new, |s| format!("{s}B/s"))),
                    );
                    m.insert(name.clone(), Value::Object(lm));
                }
                Value::Object(m)
            },
        );

        root.insert(
            "secrets".into(),
            if self.secrets.is_empty() {
                Value::Null
            } else {
                let mut m = Map::new();
                for name in self.secrets.keys() {
                    m.insert(name.clone(), Value::String(REDACTED.into()));
                }
                Value::Object(m)
            },
        );

        // stats
        let mut stats = Map::new();
        let mut prom = Map::new();
        prom.insert(
            "bindTo".into(),
            Value::String(
                self.stats
                    .prometheus
                    .bind_to
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        prom.insert(
            "enabled".into(),
            Value::Bool(self.stats.prometheus.enabled.unwrap_or(false)),
        );
        prom.insert(
            "httpPath".into(),
            Value::String(self.stats.prometheus.http_path.clone().unwrap_or_default()),
        );
        prom.insert(
            "metricPrefix".into(),
            Value::String(
                self.stats
                    .prometheus
                    .metric_prefix
                    .clone()
                    .unwrap_or_default(),
            ),
        );
        stats.insert("prometheus".into(), Value::Object(prom));

        let mut sd = Map::new();
        sd.insert(
            "address".into(),
            Value::String(
                self.stats
                    .statsd
                    .address
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        sd.insert(
            "enabled".into(),
            Value::Bool(self.stats.statsd.enabled.unwrap_or(false)),
        );
        sd.insert(
            "metricPrefix".into(),
            Value::String(self.stats.statsd.metric_prefix.clone().unwrap_or_default()),
        );
        sd.insert(
            "tagFormat".into(),
            Value::String(
                self.stats
                    .statsd
                    .tag_format
                    .map_or_else(String::new, |t| t.as_str().to_owned()),
            ),
        );
        stats.insert("statsd".into(), Value::Object(sd));
        root.insert("stats".into(), Value::Object(stats));

        // throttle
        let mut thr = Map::new();
        thr.insert(
            "checkInterval".into(),
            Value::String(
                self.throttle
                    .check_interval
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        thr.insert(
            "maxConnections".into(),
            json!(self.throttle.max_connections.unwrap_or(0)),
        );
        root.insert("throttle".into(), Value::Object(thr));

        root.insert(
            "tolerateTimeSkewness".into(),
            Value::String(
                self.tolerate_time_skewness
                    .map_or_else(String::new, format_duration_go),
            ),
        );
        root.insert(
            "trackClientIps".into(),
            Value::Bool(self.track_client_ips.unwrap_or(false)),
        );
        root.insert(
            "usageStateFile".into(),
            Value::String(self.usage_state_file.clone()),
        );

        // web
        let mut web = Map::new();
        web.insert(
            "backend".into(),
            Value::String(
                self.web
                    .backend
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        web.insert(
            "bindTo".into(),
            Value::String(
                self.web
                    .bind_to
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        web.insert(
            "carrierBatchBytes".into(),
            Value::String(
                self.web
                    .carrier_batch_bytes
                    .map_or_else(String::new, format_bytes_go),
            ),
        );
        web.insert(
            "clientIp".into(),
            Value::String(
                self.web
                    .client_ip
                    .unwrap_or(ClientIpSource::ProxyProtocol)
                    .as_str()
                    .to_owned(),
            ),
        );
        web.insert("coverDir".into(), Value::String(self.web.cover_dir.clone()));
        web.insert(
            "coverUpstream".into(),
            Value::String(self.web.cover_upstream.clone()),
        );
        web.insert(
            "enabled".into(),
            Value::Bool(self.web.enabled.unwrap_or(false)),
        );
        web.insert(
            "host".into(),
            Value::String(self.web.host.clone().unwrap_or_default()),
        );
        web.insert(
            "maxFramePayload".into(),
            Value::String(
                self.web
                    .max_frame_payload
                    .map_or_else(String::new, format_bytes_go),
            ),
        );
        web.insert(
            "maxSessions".into(),
            json!(self.web.max_sessions.unwrap_or(0)),
        );
        web.insert(
            "maxStreams".into(),
            json!(self.web.max_streams.unwrap_or(0)),
        );
        web.insert(
            "statsBindTo".into(),
            Value::String(
                self.web
                    .stats_bind_to
                    .as_ref()
                    .map_or_else(String::new, |h| h.as_str().to_owned()),
            ),
        );
        web.insert("tokenKey".into(), Value::String(self.web.token_key.clone()));
        if let Some(integrated) = self.web.integrated {
            web.insert("integrated".into(), Value::Bool(integrated));
        }
        root.insert("web".into(), Value::Object(web));

        serde_json::to_string(&Value::Object(root)).expect("JSON serialization cannot fail")
    }
}

fn list_to_json(l: &ListConfig) -> Value {
    let mut m = Map::new();
    if let Some(action) = l.action {
        m.insert("action".into(), Value::String(action.as_str().to_owned()));
    }
    if let Some(cache_file) = &l.cache_file {
        m.insert("cacheFile".into(), Value::String(cache_file.clone()));
    }
    if let Some(cidrs) = &l.cidrs {
        m.insert("cidrs".into(), opt_vec_str_to_json(Some(cidrs.as_slice())));
    }
    m.insert(
        "downloadConcurrency".into(),
        json!(l.download_concurrency.unwrap_or(0)),
    );
    m.insert("enabled".into(), Value::Bool(l.enabled.unwrap_or(false)));
    m.insert(
        "updateEach".into(),
        Value::String(l.update_each.map_or_else(String::new, format_duration_go)),
    );
    m.insert("urls".into(), opt_vec_str_to_json(l.urls.as_deref()));
    Value::Object(m)
}

fn opt_vec_str_to_json(v: Option<&[String]>) -> Value {
    match v {
        None => Value::Null,
        Some(slice) => Value::Array(slice.iter().map(|s| Value::String(s.clone())).collect()),
    }
}

// ---------------------------------------------------------------------------
// Lossless TOML DOM Walker
// ---------------------------------------------------------------------------

fn line_col(doc: &[u8], offset: usize) -> (usize, usize) {
    let clamped = offset.min(doc.len());
    let before = &doc[..clamped];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let last_nl = before
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let col = clamped - last_nl + 1;
    (line, col)
}

fn record_unknown(
    doc: &[u8],
    unknown: &mut BTreeSet<String>,
    prefix: &[&str],
    key: &str,
    item: &Item,
) {
    let mut raw_parts: Vec<&str> = prefix.to_vec();
    raw_parts.push(key);
    let written = raw_parts.join(".");

    let scrubbed_parts: Vec<String> = raw_parts.iter().map(|p| value_free_name(p)).collect();
    let mut scrubbed = scrubbed_parts.join(".");
    if scrubbed != written
        && let Some(span) = item.span()
    {
        let (line, _) = line_col(doc, span.start);
        let _ = write!(scrubbed, "{UNKNOWN_KEY_LINE}{line})");
    }
    unknown.insert(scrubbed);
}

fn expect_str<'a>(item: &'a Item, field: &str) -> Result<&'a str, ConfigError> {
    item.as_str()
        .ok_or_else(|| ConfigError::FieldParse(format!("{field} must be a string")))
}

fn expect_bool(item: &Item, field: &str) -> Result<bool, ConfigError> {
    item.as_bool()
        .ok_or_else(|| ConfigError::FieldParse(format!("{field} must be a boolean")))
}

fn expect_u32(item: &Item, field: &str) -> Result<u32, ConfigError> {
    let v = item
        .as_integer()
        .ok_or_else(|| ConfigError::FieldParse(format!("{field} must be an integer")))?;
    u32::try_from(v)
        .map_err(|_| ConfigError::FieldParse(format!("{field} must be a non-negative integer")))
}

fn expect_u16_port(item: &Item, field: &str) -> Result<u16, ConfigError> {
    let v = item
        .as_integer()
        .ok_or_else(|| ConfigError::FieldParse(format!("{field} must be an integer port")))?;
    if !(1..=65535).contains(&v) {
        return Err(ConfigError::FieldParse(format!(
            "{field} must be a port in 1..=65535"
        )));
    }
    Ok(v as u16)
}

fn expect_bytes(item: &Item, field: &str) -> Result<u64, ConfigError> {
    if let Some(n) = item.as_integer() {
        return u64::try_from(n)
            .map_err(|_| ConfigError::FieldParse(format!("{field} must be non-negative")));
    }
    let s = expect_str(item, field)?;
    parse_bytes_str(s).map_err(|e| ConfigError::FieldParse(format!("{field}: {e}")))
}

fn expect_string_array(item: &Item, field: &str) -> Result<Vec<String>, ConfigError> {
    let arr = item
        .as_array()
        .ok_or_else(|| ConfigError::FieldParse(format!("{field} must be an array of strings")))?;
    let mut out = Vec::with_capacity(arr.len());
    for elem in arr {
        let s = elem
            .as_str()
            .ok_or_else(|| ConfigError::FieldParse(format!("{field} elements must be strings")))?;
        out.push(s.to_owned());
    }
    Ok(out)
}

fn parse_root_table(
    doc: &[u8],
    table: &dyn TableLike,
    cfg: &mut Config,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (key, item) in table.iter() {
        match key {
            "debug" => cfg.debug = Some(expect_bool(item, "debug")?),
            "allow-fallback-on-unknown-dc" => {
                cfg.allow_fallback_on_unknown_dc =
                    Some(expect_bool(item, "allow-fallback-on-unknown-dc")?);
            }
            "secret" => {
                let s = expect_str(item, "secret")?;
                if !s.is_empty() {
                    cfg.secret = Some(
                        Secret::parse(s)
                            .map_err(|e| ConfigError::FieldParse(format!("secret: {e}")))?,
                    );
                }
            }
            "secrets" => {
                let tbl = item
                    .as_table_like()
                    .ok_or_else(|| ConfigError::FieldParse("secrets must be a table".to_owned()))?;
                for (name, val) in tbl.iter() {
                    let s = expect_str(val, "secrets entry")?;
                    if name == MISPLACED_RETIRING_USER {
                        // Still parse if valid or placeholder dummy so GetRetiringSecrets sees the misplaced name!
                        let parsed = Secret::parse(s).unwrap_or_else(|_| {
                            Secret::from_parts([1u8; 16], "", SecretMode::Plain)
                        });
                        cfg.secrets.insert(name.to_owned(), parsed);
                        continue;
                    }
                    let parsed = Secret::parse(s).map_err(|e| {
                        ConfigError::FieldParse(format!("secrets.{}: {e}", value_free_name(name)))
                    })?;
                    cfg.secrets.insert(name.to_owned(), parsed);
                }
            }
            "ad-tag" => {
                let s = expect_str(item, "ad-tag")?;
                cfg.ad_tag = parse_ad_tag(s)
                    .map_err(|e| ConfigError::FieldParse(format!("ad-tag: {e}")))?
                    .map(Zeroizing::new);
            }
            "secret-ad-tags" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("secret-ad-tags must be a table".to_owned())
                })?;
                for (name, val) in tbl.iter() {
                    let s = expect_str(val, "secret-ad-tags entry")?;
                    if let Some(tag) = parse_ad_tag(s).map_err(|e| {
                        ConfigError::FieldParse(format!(
                            "secret-ad-tags.{}: {e}",
                            value_free_name(name)
                        ))
                    })? {
                        cfg.secret_ad_tags
                            .insert(name.to_owned(), Zeroizing::new(tag));
                    }
                }
            }
            "secret-limits" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("secret-limits must be a table".to_owned())
                })?;
                for (name, sub) in tbl.iter() {
                    let sub_tbl = sub.as_table_like().ok_or_else(|| {
                        ConfigError::FieldParse(format!(
                            "secret-limits.{} must be a table",
                            value_free_name(name)
                        ))
                    })?;
                    let lim = parse_secret_limit(doc, name, sub_tbl, unknown)?;
                    cfg.secret_limits.insert(name.to_owned(), lim);
                }
            }
            "retiring-secret" => {
                parse_retiring_secret_item(doc, item, &mut cfg.retiring_secrets, unknown)?;
            }
            "usage-state-file" => {
                expect_str(item, "usage-state-file")?.clone_into(&mut cfg.usage_state_file);
            }
            "api-token" => {
                cfg.api_token = Zeroizing::new(expect_str(item, "api-token")?.to_owned());
            }
            "bind-to" => {
                cfg.bind_to = parse_bind_to(item)?;
            }
            "listener" => {
                parse_listeners_item(doc, item, &mut cfg.listeners, unknown)?;
            }
            "web" => {
                let tbl = item
                    .as_table_like()
                    .ok_or_else(|| ConfigError::FieldParse("[web] must be a table".to_owned()))?;
                parse_web_table(doc, tbl, &mut cfg.web, unknown)?;
            }
            "proxy-protocol-listener" => {
                cfg.proxy_protocol_listener = Some(expect_bool(item, "proxy-protocol-listener")?);
            }
            "prefer-ip" => {
                let s = expect_str(item, "prefer-ip")?;
                if !s.is_empty() {
                    cfg.prefer_ip = Some(
                        s.parse()
                            .map_err(|e| ConfigError::FieldParse(format!("prefer-ip: {e}")))?,
                    );
                }
            }
            "auto-update" => cfg.auto_update = Some(expect_bool(item, "auto-update")?),
            "track-client-ips" => {
                cfg.track_client_ips = Some(expect_bool(item, "track-client-ips")?);
            }
            "domain-fronting-port" => {
                cfg.domain_fronting_port = Some(expect_u16_port(item, "domain-fronting-port")?);
            }
            "domain-fronting-ip" => {
                let s = expect_str(item, "domain-fronting-ip")?;
                if !s.is_empty() {
                    cfg.domain_fronting_ip = Some(s.parse().map_err(|_| {
                        ConfigError::FieldParse(format!("invalid domain-fronting-ip {s:?}"))
                    })?);
                }
            }
            "domain-fronting-proxy-protocol" => {
                cfg.domain_fronting_proxy_protocol =
                    Some(expect_bool(item, "domain-fronting-proxy-protocol")?);
            }
            "tolerate-time-skewness" => {
                let s = expect_str(item, "tolerate-time-skewness")?;
                if !s.is_empty() {
                    cfg.tolerate_time_skewness = Some(parse_duration(s).map_err(|e| {
                        ConfigError::FieldParse(format!("tolerate-time-skewness: {e}"))
                    })?);
                }
            }
            "concurrency" => cfg.concurrency = Some(expect_u32(item, "concurrency")?),
            "public-ipv4" => {
                let s = expect_str(item, "public-ipv4")?;
                if !s.is_empty() {
                    let ip: IpAddr = s.parse().map_err(|_| {
                        ConfigError::FieldParse(format!("invalid public-ipv4 {s:?}"))
                    })?;
                    if !ip.is_ipv4() {
                        return Err(ConfigError::FieldParse(format!(
                            "public-ipv4 must be an IPv4 address: {s:?}"
                        )));
                    }
                    cfg.public_ipv4 = Some(ip);
                }
            }
            "public-ipv6" => {
                let s = expect_str(item, "public-ipv6")?;
                if !s.is_empty() {
                    let ip: IpAddr = s.parse().map_err(|_| {
                        ConfigError::FieldParse(format!("invalid public-ipv6 {s:?}"))
                    })?;
                    if !ip.is_ipv6() {
                        return Err(ConfigError::FieldParse(format!(
                            "public-ipv6 must be an IPv6 address: {s:?}"
                        )));
                    }
                    cfg.public_ipv6 = Some(ip);
                }
            }
            "domain-fronting" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[domain-fronting] must be a table".to_owned())
                })?;
                parse_domain_fronting(doc, tbl, &mut cfg.domain_fronting, unknown)?;
            }
            "defense" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense] must be a table".to_owned())
                })?;
                parse_defense(doc, tbl, &mut cfg.defense, unknown)?;
            }
            "network" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[network] must be a table".to_owned())
                })?;
                parse_network(doc, tbl, &mut cfg.network, unknown)?;
            }
            "api-bind-to" => {
                let s = expect_str(item, "api-bind-to")?;
                if !s.is_empty() {
                    cfg.api_bind_to = Some(
                        HostPort::parse(s)
                            .map_err(|e| ConfigError::FieldParse(format!("api-bind-to: {e}")))?,
                    );
                }
            }
            "throttle" => {
                let tbl = item.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[throttle] must be a table".to_owned())
                })?;
                parse_throttle(doc, tbl, &mut cfg.throttle, unknown)?;
            }
            "stats" => {
                let tbl = item
                    .as_table_like()
                    .ok_or_else(|| ConfigError::FieldParse("[stats] must be a table".to_owned()))?;
                parse_stats(doc, tbl, &mut cfg.stats, unknown)?;
            }
            _ => record_unknown(doc, unknown, &[], key, item),
        }
    }
    Ok(())
}

fn parse_bind_to(item: &Item) -> Result<Vec<HostPort>, ConfigError> {
    if let Some(s) = item.as_str() {
        if s.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(vec![
            HostPort::parse(s).map_err(|e| ConfigError::FieldParse(format!("bind-to: {e}")))?,
        ]);
    }
    if let Some(arr) = item.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for elem in arr {
            let s = elem.as_str().ok_or(ConfigError::NonStringBindTo)?;
            let hp =
                HostPort::parse(s).map_err(|e| ConfigError::FieldParse(format!("bind-to: {e}")))?;
            out.push(hp);
        }
        return Ok(out);
    }
    Err(ConfigError::FieldParse(
        "bind-to must be a string or array of strings".to_owned(),
    ))
}

fn parse_secret_limit(
    doc: &[u8],
    name: &str,
    tbl: &dyn TableLike,
    unknown: &mut BTreeSet<String>,
) -> Result<ConfigSecretLimit, ConfigError> {
    let mut lim = ConfigSecretLimit::default();
    for (k, v) in tbl.iter() {
        match k {
            "quota" => {
                if v.as_str().is_some_and(str::is_empty) {
                    continue;
                }
                lim.quota = Some(expect_bytes(v, "quota")?);
            }
            "quota-reset" => {
                let s = expect_str(v, "quota-reset")?;
                if !s.is_empty() {
                    lim.quota_reset = Some(
                        parse_quota_reset(s)
                            .map_err(|e| ConfigError::FieldParse(format!("quota-reset: {e}")))?,
                    );
                }
            }
            "expires" => {
                let s = expect_str(v, "expires")?;
                if !s.is_empty() {
                    lim.expires = parse_expiry(s)
                        .map_err(|e| ConfigError::FieldParse(format!("expires: {e}")))?;
                }
            }
            "disabled" => lim.disabled = Some(expect_bool(v, "disabled")?),
            "speed" => {
                let s = expect_str(v, "speed")?;
                if !s.is_empty() {
                    lim.speed = Some(
                        parse_speed(s)
                            .map_err(|e| ConfigError::FieldParse(format!("speed: {e}")))?,
                    );
                }
            }
            "speed-up" => {
                let s = expect_str(v, "speed-up")?;
                if !s.is_empty() {
                    lim.speed_up = Some(
                        parse_speed(s)
                            .map_err(|e| ConfigError::FieldParse(format!("speed-up: {e}")))?,
                    );
                }
            }
            "speed-down" => {
                let s = expect_str(v, "speed-down")?;
                if !s.is_empty() {
                    lim.speed_down = Some(
                        parse_speed(s)
                            .map_err(|e| ConfigError::FieldParse(format!("speed-down: {e}")))?,
                    );
                }
            }
            "ip-limit" => lim.ip_limit = Some(expect_u32(v, "ip-limit")?),
            "client-conns" => lim.client_conns = Some(expect_u32(v, "client-conns")?),
            "client-speed" => {
                let s = expect_str(v, "client-speed")?;
                if !s.is_empty() {
                    lim.client_speed = Some(
                        parse_speed(s)
                            .map_err(|e| ConfigError::FieldParse(format!("client-speed: {e}")))?,
                    );
                }
            }
            "client-fair" => lim.client_fair = Some(expect_bool(v, "client-fair")?),
            _ => record_unknown(doc, unknown, &["secret-limits", name], k, v),
        }
    }
    Ok(lim)
}

fn parse_retiring_secret_item(
    doc: &[u8],
    item: &Item,
    out: &mut Vec<ConfigRetiringSecret>,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    if let Some(arr) = item.as_array_of_tables() {
        for tbl in arr {
            out.push(parse_one_retiring_table(doc, tbl, unknown));
        }
        return Ok(());
    }
    if let Some(tbl) = item.as_table_like() {
        // Single-table typo `[retiring-secret]` accepted as 1-element slice (matches Go).
        out.push(parse_one_retiring_table(doc, tbl, unknown));
        return Ok(());
    }
    if let Some(arr) = item.as_array() {
        // Inline array of tables `retiring-secret = [{...}]`
        for elem in arr {
            let Some(tbl) = elem.as_inline_table() else {
                return Err(ConfigError::TomlSyntax(
                    "retiring-secret array elements must be tables".to_owned(),
                ));
            };
            out.push(parse_one_retiring_table(doc, tbl, unknown));
        }
        return Ok(());
    }
    Err(ConfigError::TomlSyntax(
        "retiring-secret must be a [[retiring-secret]] array of tables".to_owned(),
    ))
}

fn parse_one_retiring_table(
    doc: &[u8],
    tbl: &dyn TableLike,
    unknown: &mut BTreeSet<String>,
) -> ConfigRetiringSecret {
    let mut entry = ConfigRetiringSecret::default();
    for (k, v) in tbl.iter() {
        match k {
            "name" => {
                let (txt, wrong) = normalise_retiring_field(v, false);
                entry.name = txt;
                if wrong {
                    entry.wrong_type |= RETIRING_NAME_WRONG_TYPE;
                }
            }
            "secret" => {
                let (txt, wrong) = normalise_retiring_field(v, false);
                entry.secret = txt;
                if wrong {
                    entry.wrong_type |= RETIRING_SECRET_WRONG_TYPE;
                }
            }
            "until" => {
                let (txt, wrong) = normalise_retiring_field(v, true);
                entry.until = txt;
                if wrong {
                    entry.wrong_type |= RETIRING_UNTIL_WRONG_TYPE;
                }
            }
            _ => record_unknown(doc, unknown, &["retiring-secret"], k, v),
        }
    }
    entry
}

fn normalise_retiring_field(item: &Item, allow_offset_datetime: bool) -> (String, bool) {
    let Some(val) = item.as_value() else {
        return (item.to_string().trim().to_owned(), true);
    };
    match val {
        TomlValue::String(s) => (s.value().clone(), false),
        TomlValue::Datetime(dt) => {
            let d = dt.value();
            // Only an offset date-time (date + time + offset) is valid for `until`.
            if allow_offset_datetime && d.date.is_some() && d.time.is_some() && d.offset.is_some() {
                let formatted = d.to_string();
                if let Ok(parsed) = DateTime::parse_from_rfc3339(&formatted) {
                    return (
                        parsed.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
                        false,
                    );
                }
            }
            (d.to_string(), true)
        }
        other => (other.to_string().trim().to_owned(), true),
    }
}

fn parse_listeners_item(
    doc: &[u8],
    item: &Item,
    out: &mut Vec<ConfigListener>,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    let tables: Vec<&dyn TableLike> = if let Some(arr) = item.as_array_of_tables() {
        arr.iter().map(|t| t as &dyn TableLike).collect()
    } else if let Some(tbl) = item.as_table_like() {
        vec![tbl]
    } else {
        return Err(ConfigError::FieldParse(
            "listener must be a [[listener]] array of tables".to_owned(),
        ));
    };

    for tbl in tables {
        let mut l = ConfigListener::default();
        for (k, v) in tbl.iter() {
            match k {
                "bind-to" => {
                    let s = expect_str(v, "listener.bind-to")?;
                    if !s.is_empty() {
                        l.bind_to = Some(HostPort::parse(s).map_err(|e| {
                            ConfigError::FieldParse(format!("listener.bind-to: {e}"))
                        })?);
                    }
                }
                "accept" => {
                    let names = expect_string_array(v, "listener.accept")?;
                    for name in names {
                        l.accept.push(name.parse().map_err(|e| {
                            ConfigError::FieldParse(format!("listener.accept: {e}"))
                        })?);
                    }
                }
                "public" => l.public = Some(expect_bool(v, "listener.public")?),
                "proxy-protocol" => {
                    l.proxy_protocol = Some(expect_bool(v, "listener.proxy-protocol")?);
                }
                "on-unknown-secret" => {
                    let s = expect_str(v, "listener.on-unknown-secret")?;
                    if !s.is_empty() {
                        l.on_unknown_secret = Some(s.parse().map_err(|e| {
                            ConfigError::FieldParse(format!("listener.on-unknown-secret: {e}"))
                        })?);
                    }
                }
                "handshakes-per-ip" => {
                    l.handshakes_per_ip = Some(expect_u32(v, "listener.handshakes-per-ip")?);
                }
                _ => record_unknown(doc, unknown, &["listener"], k, v),
            }
        }
        out.push(l);
    }
    Ok(())
}

fn parse_web_table(
    doc: &[u8],
    tbl: &dyn TableLike,
    web: &mut ConfigWeb,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "enabled" => web.enabled = Some(expect_bool(v, "web.enabled")?),
            "host" => {
                let s = expect_str(v, "web.host")?;
                if !s.is_empty() {
                    web.host = Some(s.to_owned());
                }
            }
            "bind-to" => {
                let s = expect_str(v, "web.bind-to")?;
                if !s.is_empty() {
                    web.bind_to = Some(
                        HostPort::parse(s)
                            .map_err(|e| ConfigError::FieldParse(format!("web.bind-to: {e}")))?,
                    );
                }
            }
            "backend" => {
                let s = expect_str(v, "web.backend")?;
                if !s.is_empty() {
                    web.backend = Some(
                        HostPort::parse(s)
                            .map_err(|e| ConfigError::FieldParse(format!("web.backend: {e}")))?,
                    );
                }
            }
            "token-key" => expect_str(v, "web.token-key")?.clone_into(&mut web.token_key),
            "cover-dir" => expect_str(v, "web.cover-dir")?.clone_into(&mut web.cover_dir),
            "cover-upstream" => {
                expect_str(v, "web.cover-upstream")?.clone_into(&mut web.cover_upstream);
            }
            "client-ip" => {
                let s = expect_str(v, "web.client-ip")?;
                if !s.is_empty() {
                    web.client_ip = Some(
                        s.parse()
                            .map_err(|e| ConfigError::FieldParse(format!("web.client-ip: {e}")))?,
                    );
                }
            }
            "max-sessions" => web.max_sessions = Some(expect_u32(v, "web.max-sessions")?),
            "max-streams" => web.max_streams = Some(expect_u32(v, "web.max-streams")?),
            "max-frame-payload" => {
                if !v.as_str().is_some_and(str::is_empty) {
                    web.max_frame_payload = Some(expect_bytes(v, "web.max-frame-payload")?);
                }
            }
            "carrier-batch-bytes" => {
                if !v.as_str().is_some_and(str::is_empty) {
                    web.carrier_batch_bytes = Some(expect_bytes(v, "web.carrier-batch-bytes")?);
                }
            }
            "stats-bind-to" => {
                let s = expect_str(v, "web.stats-bind-to")?;
                if !s.is_empty() {
                    web.stats_bind_to =
                        Some(HostPort::parse(s).map_err(|e| {
                            ConfigError::FieldParse(format!("web.stats-bind-to: {e}"))
                        })?);
                }
            }
            "integrated" => web.integrated = Some(expect_bool(v, "web.integrated")?),
            _ => record_unknown(doc, unknown, &["web"], k, v),
        }
    }
    Ok(())
}

fn parse_domain_fronting(
    doc: &[u8],
    tbl: &dyn TableLike,
    df: &mut DomainFrontingConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "host" => {
                let s = expect_str(v, "domain-fronting.host")?;
                if !s.is_empty() {
                    df.host = Some(s.to_owned());
                }
            }
            "ip" => {
                let s = expect_str(v, "domain-fronting.ip")?;
                if !s.is_empty() {
                    df.ip = Some(s.parse().map_err(|_| {
                        ConfigError::FieldParse(format!("invalid domain-fronting.ip {s:?}"))
                    })?);
                }
            }
            "port" => df.port = Some(expect_u16_port(v, "domain-fronting.port")?),
            "proxy-protocol" => {
                df.proxy_protocol = Some(expect_bool(v, "domain-fronting.proxy-protocol")?);
            }
            _ => record_unknown(doc, unknown, &["domain-fronting"], k, v),
        }
    }
    Ok(())
}

fn parse_list_config(
    doc: &[u8],
    prefix: &[&str],
    tbl: &dyn TableLike,
    list: &mut ListConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "enabled" => list.enabled = Some(expect_bool(v, "enabled")?),
            "download-concurrency" => {
                list.download_concurrency = Some(expect_u32(v, "download-concurrency")?);
            }
            "urls" => list.urls = Some(expect_string_array(v, "urls")?),
            "cidrs" => list.cidrs = Some(expect_string_array(v, "cidrs")?),
            "cache-file" => {
                let s = expect_str(v, "cache-file")?;
                if !s.is_empty() {
                    list.cache_file = Some(s.to_owned());
                }
            }
            "action" => {
                let s = expect_str(v, "action")?;
                if !s.is_empty() {
                    list.action = Some(
                        s.parse()
                            .map_err(|e| ConfigError::FieldParse(format!("action: {e}")))?,
                    );
                }
            }
            "update-each" => {
                let s = expect_str(v, "update-each")?;
                if !s.is_empty() {
                    list.update_each = Some(
                        parse_duration(s)
                            .map_err(|e| ConfigError::FieldParse(format!("update-each: {e}")))?,
                    );
                }
            }
            _ => record_unknown(doc, unknown, prefix, k, v),
        }
    }
    Ok(())
}

fn parse_defense(
    doc: &[u8],
    tbl: &dyn TableLike,
    def: &mut DefenseConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "anti-replay" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense.anti-replay] must be a table".to_owned())
                })?;
                for (ak, av) in sub.iter() {
                    match ak {
                        "enabled" => {
                            def.anti_replay.enabled = Some(expect_bool(av, "anti-replay.enabled")?);
                        }
                        "max-size" => {
                            if !av.as_str().is_some_and(str::is_empty) {
                                def.anti_replay.max_size =
                                    Some(expect_bytes(av, "anti-replay.max-size")?);
                            }
                        }
                        "error-rate" => {
                            let val = av
                                .as_float()
                                .or_else(|| av.as_integer().map(|i| i as f64))
                                .ok_or_else(|| {
                                    ConfigError::FieldParse(
                                        "anti-replay.error-rate must be a float".to_owned(),
                                    )
                                })?;
                            if !(val > 0.0 && val < 1.0) {
                                return Err(ConfigError::FieldParse(format!(
                                    "anti-replay.error-rate must be in (0, 1), got {val}"
                                )));
                            }
                            def.anti_replay.error_rate = Some(val);
                        }
                        _ => record_unknown(doc, unknown, &["defense", "anti-replay"], ak, av),
                    }
                }
            }
            "blocklist" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense.blocklist] must be a table".to_owned())
                })?;
                parse_list_config(
                    doc,
                    &["defense", "blocklist"],
                    sub,
                    &mut def.blocklist,
                    unknown,
                )?;
            }
            "allowlist" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense.allowlist] must be a table".to_owned())
                })?;
                parse_list_config(
                    doc,
                    &["defense", "allowlist"],
                    sub,
                    &mut def.allowlist,
                    unknown,
                )?;
            }
            "doppelganger" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense.doppelganger] must be a table".to_owned())
                })?;
                for (dk, dv) in sub.iter() {
                    match dk {
                        "urls" => {
                            def.doppelganger.urls =
                                Some(expect_string_array(dv, "doppelganger.urls")?);
                        }
                        "repeats-per-raid" => {
                            def.doppelganger.repeats_per_raid =
                                Some(expect_u32(dv, "doppelganger.repeats-per-raid")?);
                        }
                        "raid-each" => {
                            let s = expect_str(dv, "doppelganger.raid-each")?;
                            if !s.is_empty() {
                                def.doppelganger.raid_each =
                                    Some(parse_duration(s).map_err(|e| {
                                        ConfigError::FieldParse(format!(
                                            "doppelganger.raid-each: {e}"
                                        ))
                                    })?);
                            }
                        }
                        "drs" => def.doppelganger.drs = Some(expect_bool(dv, "doppelganger.drs")?),
                        "shaping" => {
                            let s = expect_str(dv, "doppelganger.shaping")?;
                            if !s.is_empty() {
                                def.doppelganger.shaping = Some(s.parse().map_err(|e| {
                                    ConfigError::FieldParse(format!("doppelganger.shaping: {e}"))
                                })?);
                            }
                        }
                        "scout-covers" => {
                            def.doppelganger.scout_covers =
                                Some(expect_bool(dv, "doppelganger.scout-covers")?);
                        }
                        _ => record_unknown(doc, unknown, &["defense", "doppelganger"], dk, dv),
                    }
                }
            }
            "handshake-budget" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[defense.handshake-budget] must be a table".to_owned())
                })?;
                for (hk, hv) in sub.iter() {
                    match hk {
                        "mode" => {
                            let s = expect_str(hv, "handshake-budget.mode")?;
                            if !s.is_empty() {
                                def.handshake_budget.mode = Some(s.parse().map_err(|e| {
                                    ConfigError::FieldParse(format!("handshake-budget.mode: {e}"))
                                })?);
                            }
                        }
                        "per-ip-ms" => {
                            let n = hv.as_integer().ok_or_else(|| {
                                ConfigError::FieldParse(
                                    "handshake-budget.per-ip-ms must be an integer".to_owned(),
                                )
                            })?;
                            if n < 0 {
                                return Err(ConfigError::FieldParse(format!(
                                    "handshake-budget.per-ip-ms must be >= 0, got {n}"
                                )));
                            }
                            def.handshake_budget.per_ip_ms = Some(n as u32);
                        }
                        "cpu-percent" => {
                            let n = hv.as_integer().ok_or_else(|| {
                                ConfigError::FieldParse(
                                    "handshake-budget.cpu-percent must be an integer".to_owned(),
                                )
                            })?;
                            if !(1..=100).contains(&n) {
                                return Err(ConfigError::FieldParse(format!(
                                    "handshake-budget.cpu-percent must be in 1..=100, got {n}"
                                )));
                            }
                            def.handshake_budget.cpu_percent = Some(n as u32);
                        }
                        "hints" => {
                            def.handshake_budget.hints =
                                Some(expect_bool(hv, "handshake-budget.hints")?);
                        }
                        _ => record_unknown(doc, unknown, &["defense", "handshake-budget"], hk, hv),
                    }
                }
            }
            _ => record_unknown(doc, unknown, &["defense"], k, v),
        }
    }
    Ok(())
}

fn parse_network(
    doc: &[u8],
    tbl: &dyn TableLike,
    net: &mut NetworkConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "timeout" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[network.timeout] must be a table".to_owned())
                })?;
                for (tk, tv) in sub.iter() {
                    match tk {
                        "tcp" => {
                            let s = expect_str(tv, "network.timeout.tcp")?;
                            if !s.is_empty() {
                                net.timeout.tcp = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("network.timeout.tcp: {e}"))
                                })?);
                            }
                        }
                        "http" => {
                            let s = expect_str(tv, "network.timeout.http")?;
                            if !s.is_empty() {
                                net.timeout.http = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("network.timeout.http: {e}"))
                                })?);
                            }
                        }
                        "idle" => {
                            let s = expect_str(tv, "network.timeout.idle")?;
                            if !s.is_empty() {
                                net.timeout.idle = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("network.timeout.idle: {e}"))
                                })?);
                            }
                        }
                        "handshake" => {
                            let s = expect_str(tv, "network.timeout.handshake")?;
                            if !s.is_empty() {
                                net.timeout.handshake = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!(
                                        "network.timeout.handshake: {e}"
                                    ))
                                })?);
                            }
                        }
                        _ => record_unknown(doc, unknown, &["network", "timeout"], tk, tv),
                    }
                }
            }
            "keep-alive" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[network.keep-alive] must be a table".to_owned())
                })?;
                for (kk, kv) in sub.iter() {
                    match kk {
                        "disabled" => {
                            net.keep_alive.disabled = Some(expect_bool(kv, "keep-alive.disabled")?);
                        }
                        "idle" => {
                            let s = expect_str(kv, "keep-alive.idle")?;
                            if !s.is_empty() {
                                net.keep_alive.idle = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("keep-alive.idle: {e}"))
                                })?);
                            }
                        }
                        "interval" => {
                            let s = expect_str(kv, "keep-alive.interval")?;
                            if !s.is_empty() {
                                net.keep_alive.interval = Some(parse_duration(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("keep-alive.interval: {e}"))
                                })?);
                            }
                        }
                        "count" => net.keep_alive.count = Some(expect_u32(kv, "keep-alive.count")?),
                        _ => record_unknown(doc, unknown, &["network", "keep-alive"], kk, kv),
                    }
                }
            }
            "doh-ip" => {
                let s = expect_str(v, "network.doh-ip")?;
                if !s.is_empty() {
                    net.doh_ip = Some(s.parse().map_err(|_| {
                        ConfigError::FieldParse(format!("invalid network.doh-ip {s:?}"))
                    })?);
                }
            }
            "dns" => {
                let s = expect_str(v, "network.dns")?;
                if !s.is_empty() {
                    net.dns = Some(s.to_owned());
                }
            }
            "proxies" => {
                let list = expect_string_array(v, "network.proxies")?;
                net.proxies = Some(list);
            }
            "tcp-not-sent-lowat" => {
                if !v.as_str().is_some_and(str::is_empty) {
                    net.tcp_not_sent_lowat = Some(expect_bytes(v, "network.tcp-not-sent-lowat")?);
                }
            }
            _ => record_unknown(doc, unknown, &["network"], k, v),
        }
    }
    Ok(())
}

fn parse_throttle(
    doc: &[u8],
    tbl: &dyn TableLike,
    thr: &mut ThrottleConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "max-connections" => {
                thr.max_connections = Some(expect_u32(v, "throttle.max-connections")?);
            }
            "check-interval" => {
                let s = expect_str(v, "throttle.check-interval")?;
                if !s.is_empty() {
                    thr.check_interval = Some(parse_duration(s).map_err(|e| {
                        ConfigError::FieldParse(format!("throttle.check-interval: {e}"))
                    })?);
                }
            }
            _ => record_unknown(doc, unknown, &["throttle"], k, v),
        }
    }
    Ok(())
}

fn parse_stats(
    doc: &[u8],
    tbl: &dyn TableLike,
    stats: &mut StatsConfig,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    for (k, v) in tbl.iter() {
        match k {
            "statsd" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[stats.statsd] must be a table".to_owned())
                })?;
                for (sk, sv) in sub.iter() {
                    match sk {
                        "enabled" => {
                            stats.statsd.enabled = Some(expect_bool(sv, "statsd.enabled")?);
                        }
                        "address" => {
                            let s = expect_str(sv, "statsd.address")?;
                            if !s.is_empty() {
                                stats.statsd.address = Some(HostPort::parse(s).map_err(|e| {
                                    ConfigError::FieldParse(format!("statsd.address: {e}"))
                                })?);
                            }
                        }
                        "metric-prefix" => {
                            let s = expect_str(sv, "statsd.metric-prefix")?;
                            if !s.is_empty() {
                                stats.statsd.metric_prefix = Some(s.to_owned());
                            }
                        }
                        "tag-format" => {
                            let s = expect_str(sv, "statsd.tag-format")?;
                            if !s.is_empty() {
                                stats.statsd.tag_format = Some(s.parse().map_err(|e| {
                                    ConfigError::FieldParse(format!("statsd.tag-format: {e}"))
                                })?);
                            }
                        }
                        _ => record_unknown(doc, unknown, &["stats", "statsd"], sk, sv),
                    }
                }
            }
            "prometheus" => {
                let sub = v.as_table_like().ok_or_else(|| {
                    ConfigError::FieldParse("[stats.prometheus] must be a table".to_owned())
                })?;
                for (pk, pv) in sub.iter() {
                    match pk {
                        "enabled" => {
                            stats.prometheus.enabled = Some(expect_bool(pv, "prometheus.enabled")?);
                        }
                        "bind-to" => {
                            let s = expect_str(pv, "prometheus.bind-to")?;
                            if !s.is_empty() {
                                stats.prometheus.bind_to =
                                    Some(HostPort::parse(s).map_err(|e| {
                                        ConfigError::FieldParse(format!("prometheus.bind-to: {e}"))
                                    })?);
                            }
                        }
                        "http-path" => {
                            let s = expect_str(pv, "prometheus.http-path")?;
                            if !s.is_empty() {
                                stats.prometheus.http_path = Some(s.to_owned());
                            }
                        }
                        "metric-prefix" => {
                            let s = expect_str(pv, "prometheus.metric-prefix")?;
                            if !s.is_empty() {
                                stats.prometheus.metric_prefix = Some(s.to_owned());
                            }
                        }
                        _ => record_unknown(doc, unknown, &["stats", "prometheus"], pk, pv),
                    }
                }
            }
            _ => record_unknown(doc, unknown, &["stats"], k, v),
        }
    }
    Ok(())
}
