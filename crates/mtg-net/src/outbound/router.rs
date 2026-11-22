//! Enterprise Multi-Outbound Policy Router (`OutboundRouter`):
//! - Named pluggable transports (`[[outbound]]`) & load-balanced groups (`[[outbound-group]]`)
//! - 5 selection strategies: `ewma-rtt` (P2C + circuit breaker), `failover`, `weighted`,
//!   `round-robin`, and `hash-dc` (sticky DC pinning)
//! - Per-secret & per-DC policy routing with lock-free circuit breakers & EWMA RTT telemetry
//! - Custom Rust [`OutboundTransport`] plugin registration for zero-coupling future protocols!

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::Rng as _;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::protocols::{
    DirectTransport, HttpConnectTransport, HttpsConnectTransport, Socks4Transport, Socks5Transport,
};
use super::shadowsocks::ShadowsocksTransport;
use super::stream::DialResult;
use super::unix::UnixSidecarTransport;
use super::{OutboundError, OutboundTarget, OutboundTransport};
use crate::dns::DnsResolver;
use crate::proxy_pool::{
    CircuitBreaker, DEFAULT_CB_HALF_OPEN_TIMEOUT, DEFAULT_CB_OPEN_THRESHOLD,
    DEFAULT_CB_RESET_WINDOW,
};
use crate::sockopts::{OutboundBindOptions, SocketConfig};

/// Built-in default outbound name.
pub const DEFAULT_DIRECT_OUTBOUND: &str = "direct";

/// Load-balancing strategy for an [`OutboundGroupSpec`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundStrategy {
    /// Power-of-Two-Choices by EWMA RTT across healthy members (default).
    #[default]
    EwmaRtt,
    /// Strict priority order (first healthy member wins).
    Failover,
    /// Weighted random selection across healthy members.
    Weighted,
    /// Lock-free atomic round-robin across healthy members.
    RoundRobin,
    /// Consistent hash pinned by Telegram DC ID (keeps each DC on one exit IP).
    HashDc,
}

impl OutboundStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EwmaRtt => "ewma-rtt",
            Self::Failover => "failover",
            Self::Weighted => "weighted",
            Self::RoundRobin => "round-robin",
            Self::HashDc => "hash-dc",
        }
    }
}

impl std::str::FromStr for OutboundStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "ewma-rtt" | "ewma_rtt" | "p2c" => Ok(Self::EwmaRtt),
            "failover" | "priority" => Ok(Self::Failover),
            "weighted" => Ok(Self::Weighted),
            "round-robin" | "round_robin" | "rr" => Ok(Self::RoundRobin),
            "hash-dc" | "hash_dc" => Ok(Self::HashDc),
            other => Err(format!(
                "unknown outbound strategy {other:?} (want ewma-rtt, failover, weighted, round-robin, or hash-dc)"
            )),
        }
    }
}

/// Declarative outbound transport specification (TOML `[[outbound]]` & REST `PUT /outbounds`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundSpec {
    pub name: String,
    /// Transport URL:
    /// - `"direct://"` (default when omitted)
    /// - `"socks5://[user:pass@]host:port"` / `"socks5h://..."`
    /// - `"socks4://[user@]host:port"` / `"socks4a://..."`
    /// - `"http://[user:pass@]host:port"`
    /// - `"https://[user:pass@]host:port[?sni=...]"`
    /// - `"ss://<method>:<psk>@host:port"` (AEAD-2022 + classic AEAD)
    /// - `"unix:///run/sidecar.sock"` / `"unix://@abstract"` / `"unix+socks5:///..."` / `"unix+http:///..."`
    #[serde(default = "default_direct_url")]
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub bind_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub bind_ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default = "default_max_fails")]
    pub max_fails: u32,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
}

fn default_direct_url() -> String {
    "direct://".to_owned()
}
const fn default_weight() -> u32 {
    100
}
const fn default_max_fails() -> u32 {
    DEFAULT_CB_OPEN_THRESHOLD
}
const fn default_cooldown_secs() -> u64 {
    30
}

/// Declarative outbound pool/group (`[[outbound-group]]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundGroupSpec {
    pub name: String,
    #[serde(default)]
    pub strategy: OutboundStrategy,
    pub members: Vec<String>,
}

/// Policy routing rules (`[routing]`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingSpec {
    /// Default outbound or group name used when no secret/DC rule matches.
    #[serde(default)]
    pub default_outbound: Option<String>,
    /// Per-DC outbound or group overrides (keyed by positive DC ID, e.g. `2 -> "eu-direct"`).
    #[serde(default)]
    pub dc_routes: BTreeMap<i32, String>,
}

/// Live observability snapshot for one configured outbound transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSnapshot {
    pub name: String,
    pub protocol: String,
    pub endpoint: String,
    pub weight: u32,
    pub circuit_open: bool,
    pub ewma_rtt_ms: f64,
    pub total_dials: u64,
    pub failed_dials: u64,
}

#[derive(Debug)]
struct OutboundNode {
    transport: Arc<dyn OutboundTransport>,
    weight: u32,
    breaker: CircuitBreaker,
    ewma_rtt_us: AtomicU64,
    total_dials: AtomicU64,
    failed_dials: AtomicU64,
}

impl OutboundNode {
    fn new(
        transport: Arc<dyn OutboundTransport>,
        weight: u32,
        max_fails: u32,
        cooldown: Duration,
    ) -> Self {
        Self {
            transport,
            weight: weight.max(1),
            breaker: CircuitBreaker::new(
                max_fails.max(1),
                if cooldown.is_zero() {
                    DEFAULT_CB_HALF_OPEN_TIMEOUT
                } else {
                    cooldown
                },
                DEFAULT_CB_RESET_WINDOW,
            ),
            ewma_rtt_us: AtomicU64::new(50_000),
            total_dials: AtomicU64::new(0),
            failed_dials: AtomicU64::new(0),
        }
    }

    fn record_rtt(&self, rtt_us: u64) {
        let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            rtt_us.max(1)
        } else {
            ((prev * 7) + rtt_us.max(1)) / 8
        };
        self.ewma_rtt_us.store(next, Ordering::Relaxed);
    }

    fn snapshot(&self) -> OutboundSnapshot {
        OutboundSnapshot {
            name: self.transport.name().to_owned(),
            protocol: self.transport.protocol().to_owned(),
            endpoint: self.transport.redacted_endpoint().to_owned(),
            weight: self.weight,
            circuit_open: self.breaker.is_open(),
            ewma_rtt_ms: self.ewma_rtt_us.load(Ordering::Relaxed) as f64 / 1000.0,
            total_dials: self.total_dials.load(Ordering::Relaxed),
            failed_dials: self.failed_dials.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct OutboundGroup {
    strategy: OutboundStrategy,
    members: Vec<Arc<OutboundNode>>,
    rr_cursor: AtomicU64,
}

/// Lock-free multi-protocol outbound router supporting custom transport plugins,
/// per-secret & per-DC routing, health-checked groups, and zero-overhead direct TCP.
#[derive(Debug)]
pub struct OutboundRouter {
    nodes: FxHashMap<String, Arc<OutboundNode>>,
    node_order: Vec<String>,
    groups: FxHashMap<String, OutboundGroup>,
    routing: RoutingSpec,
    default_direct: Arc<OutboundNode>,
    raw_specs: Vec<OutboundSpec>,
    raw_groups: Vec<OutboundGroupSpec>,
}

impl OutboundRouter {
    /// Build a zero-overhead default router containing only `"direct"`.
    pub fn direct_only(dns: &Arc<DnsResolver>, sock_cfg: SocketConfig) -> Self {
        Self::build(
            &[],
            &[],
            RoutingSpec::default(),
            &[],
            dns,
            sock_cfg,
            Vec::new(),
        )
        .expect("default direct router is always valid")
    }

    /// Construct an [`OutboundRouter`] from declarative specs, legacy `[network] proxies`,
    /// and any custom Rust [`OutboundTransport`] plugins.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        specs: &[OutboundSpec],
        group_specs: &[OutboundGroupSpec],
        mut routing: RoutingSpec,
        legacy_proxies: &[String],
        dns: &Arc<DnsResolver>,
        sock_cfg: SocketConfig,
        custom_transports: Vec<Arc<dyn OutboundTransport>>,
    ) -> Result<Self, OutboundError> {
        let mut nodes: FxHashMap<String, Arc<OutboundNode>> = FxHashMap::default();
        let mut node_order = Vec::new();

        let default_direct_tx: Arc<dyn OutboundTransport> = Arc::new(DirectTransport::new(
            Arc::from(DEFAULT_DIRECT_OUTBOUND),
            Arc::clone(dns),
            sock_cfg,
            OutboundBindOptions::default(),
        ));
        let default_direct = Arc::new(OutboundNode::new(
            default_direct_tx,
            100,
            DEFAULT_CB_OPEN_THRESHOLD,
            DEFAULT_CB_HALF_OPEN_TIMEOUT,
        ));

        // Register custom Rust plugins first (allows overriding or extending protocols!).
        for tx in custom_transports {
            let key = tx.name().to_owned();
            node_order.push(key.clone());
            nodes.insert(
                key,
                Arc::new(OutboundNode::new(
                    tx,
                    100,
                    DEFAULT_CB_OPEN_THRESHOLD,
                    DEFAULT_CB_HALF_OPEN_TIMEOUT,
                )),
            );
        }

        // Parse and register declarative `[[outbound]]` entries.
        for spec in specs {
            let name = spec.name.trim();
            if name.is_empty() {
                return Err(OutboundError::InvalidConfig(
                    "outbound name must not be empty".into(),
                ));
            }
            let bind = OutboundBindOptions {
                interface: spec.interface.clone(),
                bind_ipv4: spec.bind_ipv4,
                bind_ipv6: spec.bind_ipv6,
                fwmark: spec.fwmark,
            };
            let tx = build_transport_from_url(
                Arc::from(name),
                spec.url.trim(),
                Arc::clone(dns),
                sock_cfg,
                bind,
            )?;
            let node = Arc::new(OutboundNode::new(
                tx,
                spec.weight,
                spec.max_fails,
                Duration::from_secs(spec.cooldown_secs),
            ));
            if !nodes.contains_key(name) {
                node_order.push(name.to_owned());
            }
            nodes.insert(name.to_owned(), node);
        }

        // Always guarantee a `"direct"` outbound exists unless explicitly overridden.
        if !nodes.contains_key(DEFAULT_DIRECT_OUTBOUND) {
            node_order.insert(0, DEFAULT_DIRECT_OUTBOUND.to_owned());
            nodes.insert(
                DEFAULT_DIRECT_OUTBOUND.to_owned(),
                Arc::clone(&default_direct),
            );
        }

        // Backwards compatibility: map legacy `[network] proxies = [...]` into a
        // synthetic `"legacy-proxies"` EWMA-RTT group when no explicit default_outbound is set.
        let mut groups: FxHashMap<String, OutboundGroup> = FxHashMap::default();
        let mut legacy_members = Vec::new();
        for (idx, raw) in legacy_proxies.iter().enumerate() {
            let trimmed = raw.trim();
            let node = if trimmed.is_empty() {
                Arc::clone(&default_direct)
            } else {
                let lname = format!("proxy-{idx}");
                let tx = build_transport_from_url(
                    Arc::from(lname.as_str()),
                    trimmed,
                    Arc::clone(dns),
                    sock_cfg,
                    OutboundBindOptions::default(),
                )?;
                let n = Arc::new(OutboundNode::new(
                    tx,
                    100,
                    DEFAULT_CB_OPEN_THRESHOLD,
                    DEFAULT_CB_HALF_OPEN_TIMEOUT,
                ));
                node_order.push(lname.clone());
                nodes.insert(lname, Arc::clone(&n));
                n
            };
            legacy_members.push(node);
        }
        if !legacy_members.is_empty() {
            groups.insert(
                "legacy-proxies".to_owned(),
                OutboundGroup {
                    strategy: OutboundStrategy::EwmaRtt,
                    members: legacy_members,
                    rr_cursor: AtomicU64::new(0),
                },
            );
            if routing.default_outbound.is_none() {
                routing.default_outbound = Some("legacy-proxies".to_owned());
            }
        }

        // Register declarative `[[outbound-group]]` pools.
        for g in group_specs {
            let gname = g.name.trim();
            if gname.is_empty() || g.members.is_empty() {
                return Err(OutboundError::InvalidConfig(format!(
                    "outbound-group {gname:?} must have a name and at least one member"
                )));
            }
            let mut members = Vec::with_capacity(g.members.len());
            for m in &g.members {
                let Some(node) = nodes.get(m) else {
                    return Err(OutboundError::InvalidConfig(format!(
                        "outbound-group {gname:?} references unknown outbound {m:?}"
                    )));
                };
                members.push(Arc::clone(node));
            }
            groups.insert(
                gname.to_owned(),
                OutboundGroup {
                    strategy: g.strategy,
                    members,
                    rr_cursor: AtomicU64::new(0),
                },
            );
        }

        // Validate routing targets exist.
        if let Some(def) = &routing.default_outbound
            && !nodes.contains_key(def)
            && !groups.contains_key(def)
        {
            return Err(OutboundError::InvalidConfig(format!(
                "routing default-outbound {def:?} does not exist"
            )));
        }
        for (&dc, target) in &routing.dc_routes {
            if !nodes.contains_key(target) && !groups.contains_key(target) {
                return Err(OutboundError::InvalidConfig(format!(
                    "routing dc {dc} references unknown outbound {target:?}"
                )));
            }
        }

        Ok(Self {
            nodes,
            node_order,
            groups,
            routing,
            default_direct,
            raw_specs: specs.to_vec(),
            raw_groups: group_specs.to_vec(),
        })
    }

    /// True if every dial resolves to the built-in zero-overhead `"direct"` TCP path
    /// (zero custom outbounds, zero routing overrides).
    #[inline]
    pub fn is_plain_direct_only(&self) -> bool {
        self.raw_specs.is_empty()
            && self.groups.is_empty()
            && self.routing.default_outbound.is_none()
            && self.routing.dc_routes.is_empty()
            && self.nodes.len() == 1
    }

    /// True if `name` is a valid configured outbound node or outbound group.
    pub fn has_target(&self, name: &str) -> bool {
        self.nodes.contains_key(name) || self.groups.contains_key(name)
    }

    /// Return current declarative specs & routing rules (for persistence / API).
    pub fn config_export(&self) -> (Vec<OutboundSpec>, Vec<OutboundGroupSpec>, RoutingSpec) {
        (
            self.raw_specs.clone(),
            self.raw_groups.clone(),
            self.routing.clone(),
        )
    }

    /// Snapshot live telemetry for every registered outbound node.
    pub fn snapshots(&self) -> Vec<OutboundSnapshot> {
        self.node_order
            .iter()
            .filter_map(|k| self.nodes.get(k))
            .map(|n| n.snapshot())
            .collect()
    }

    /// Snapshot configured group definitions.
    pub fn group_specs(&self) -> &[OutboundGroupSpec] {
        &self.raw_groups
    }

    /// Current policy routing rules.
    pub fn routing(&self) -> &RoutingSpec {
        &self.routing
    }

    /// Resolve the effective outbound/group name for `(secret_outbound, dc_id)`.
    #[inline]
    pub fn resolve_route<'a>(
        &'a self,
        secret_outbound: Option<&'a str>,
        dc_id: Option<i32>,
    ) -> &'a str {
        if let Some(s) = secret_outbound
            && !s.is_empty()
            && self.has_target(s)
        {
            return s;
        }
        if let Some(dc) = dc_id
            && let Some(target) = self.routing.dc_routes.get(&dc.abs())
        {
            return target.as_str();
        }
        self.routing
            .default_outbound
            .as_deref()
            .unwrap_or(DEFAULT_DIRECT_OUTBOUND)
    }

    /// Dial `target` through the policy-resolved outbound or group for `(secret_outbound, dc_id)`.
    pub async fn dial_routed(
        &self,
        target: &OutboundTarget,
        secret_outbound: Option<&str>,
        dc_id: Option<i32>,
        timeout: Duration,
    ) -> Result<DialResult, OutboundError> {
        let route = self.resolve_route(secret_outbound, dc_id);
        self.dial_named(route, target, dc_id, timeout).await
    }

    /// Dial `target` directly through a named outbound node or outbound group.
    pub async fn dial_named(
        &self,
        name: &str,
        target: &OutboundTarget,
        dc_id: Option<i32>,
        timeout: Duration,
    ) -> Result<DialResult, OutboundError> {
        if let Some(group) = self.groups.get(name) {
            return self.dial_group(group, target, dc_id, timeout).await;
        }
        let node = self.nodes.get(name).unwrap_or(&self.default_direct);
        self.dial_node(node, target, timeout, false).await
    }

    /// Actively probe one named outbound node against `target` (ignoring open circuit
    /// so operators can test recovery via `POST /outbounds/{name}/probe`).
    pub async fn probe_named(
        &self,
        name: &str,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> Result<DialResult, OutboundError> {
        let Some(node) = self.nodes.get(name) else {
            return Err(OutboundError::UnknownOutbound(name.to_owned()));
        };
        self.dial_node(node, target, timeout, true).await
    }

    async fn dial_node(
        &self,
        node: &OutboundNode,
        target: &OutboundTarget,
        timeout: Duration,
        bypass_circuit: bool,
    ) -> Result<DialResult, OutboundError> {
        if !bypass_circuit && node.breaker.allow().is_none() {
            return Err(OutboundError::CircuitOpen(node.transport.name().to_owned()));
        }
        node.total_dials.fetch_add(1, Ordering::Relaxed);
        match node.transport.dial(target, timeout).await {
            Ok(res) => {
                node.breaker.on_success();
                node.record_rtt(res.rtt_us);
                Ok(res)
            }
            Err(err) => {
                node.failed_dials.fetch_add(1, Ordering::Relaxed);
                node.breaker.on_failure();
                Err(err)
            }
        }
    }

    async fn dial_group(
        &self,
        group: &OutboundGroup,
        target: &OutboundTarget,
        dc_id: Option<i32>,
        timeout: Duration,
    ) -> Result<DialResult, OutboundError> {
        let ordered = select_group_order(group, dc_id);
        let mut last_err = None;
        for (node, bypass) in ordered {
            match self.dial_node(&node, target, timeout, bypass).await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    debug!(
                        outbound = node.transport.name(),
                        error = %e,
                        "group outbound dial failed, failing over"
                    );
                    last_err = Some(e);
                }
            }
        }
        warn!("all members of outbound group failed");
        Err(last_err.unwrap_or_else(|| OutboundError::AllFailed("empty outbound group".into())))
    }
}

/// Order group members according to `group.strategy`, prioritizing healthy
/// circuits first and appending open-circuit fallbacks at the end so all-open
/// transient blips still attempt recovery cleanly.
fn select_group_order(group: &OutboundGroup, dc_id: Option<i32>) -> Vec<(Arc<OutboundNode>, bool)> {
    let n = group.members.len();
    if n == 0 {
        return Vec::new();
    }
    let mut healthy: Vec<Arc<OutboundNode>> = Vec::with_capacity(n);
    let mut fallback: Vec<Arc<OutboundNode>> = Vec::new();
    for m in &group.members {
        if m.breaker.is_open() {
            fallback.push(Arc::clone(m));
        } else {
            healthy.push(Arc::clone(m));
        }
    }

    if healthy.len() > 1 {
        match group.strategy {
            OutboundStrategy::Failover => {
                // Preserve exact declaration order!
            }
            OutboundStrategy::RoundRobin => {
                let start =
                    (group.rr_cursor.fetch_add(1, Ordering::Relaxed) as usize) % healthy.len();
                healthy.rotate_left(start);
            }
            OutboundStrategy::HashDc => {
                let idx = (dc_id.unwrap_or(2).unsigned_abs() as usize) % healthy.len();
                healthy.rotate_left(idx);
            }
            OutboundStrategy::Weighted => {
                let total: u64 = healthy.iter().map(|m| u64::from(m.weight)).sum();
                if total > 0 {
                    let mut pick = rand::rng().random_range(0..total);
                    let mut chosen = 0;
                    for (i, m) in healthy.iter().enumerate() {
                        let w = u64::from(m.weight);
                        if pick < w {
                            chosen = i;
                            break;
                        }
                        pick -= w;
                    }
                    healthy.swap(0, chosen);
                }
            }
            OutboundStrategy::EwmaRtt => {
                let mut rng = rand::rng();
                let a = rng.random_range(0..healthy.len());
                let mut b = rng.random_range(0..healthy.len());
                if b == a {
                    b = (a + 1) % healthy.len();
                }
                let best = if healthy[a].ewma_rtt_us.load(Ordering::Relaxed)
                    <= healthy[b].ewma_rtt_us.load(Ordering::Relaxed)
                {
                    a
                } else {
                    b
                };
                healthy.swap(0, best);
            }
        }
    }

    let mut out = Vec::with_capacity(n);
    for h in healthy {
        out.push((h, false));
    }
    for f in fallback {
        out.push((f, false));
    }
    out
}

/// Construct the appropriate pluggable [`OutboundTransport`] from a URL scheme.
pub fn build_transport_from_url(
    name: Arc<str>,
    url: &str,
    dns: Arc<DnsResolver>,
    sock_cfg: SocketConfig,
    bind: OutboundBindOptions,
) -> Result<Arc<dyn OutboundTransport>, OutboundError> {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("direct://")
        || trimmed.eq_ignore_ascii_case("direct")
    {
        return Ok(Arc::new(DirectTransport::new(name, dns, sock_cfg, bind)));
    }
    if trimmed.starts_with("socks5://") || trimmed.starts_with("socks5h://") {
        return Ok(Arc::new(Socks5Transport::parse(
            name, trimmed, dns, sock_cfg, bind,
        )?));
    }
    if trimmed.starts_with("socks4://") || trimmed.starts_with("socks4a://") {
        return Ok(Arc::new(Socks4Transport::parse(
            name, trimmed, dns, sock_cfg, bind,
        )?));
    }
    if trimmed.starts_with("http://") {
        return Ok(Arc::new(HttpConnectTransport::parse(
            name, trimmed, dns, sock_cfg, bind,
        )?));
    }
    if trimmed.starts_with("https://") {
        return Ok(Arc::new(HttpsConnectTransport::parse(
            name, trimmed, dns, sock_cfg, bind,
        )?));
    }
    if trimmed.starts_with("ss://") {
        return Ok(Arc::new(ShadowsocksTransport::parse(
            name, trimmed, dns, sock_cfg, bind,
        )?));
    }
    if trimmed.starts_with("unix://")
        || trimmed.starts_with("unix+socks5://")
        || trimmed.starts_with("unix+http://")
    {
        return Ok(Arc::new(UnixSidecarTransport::parse(name, trimmed)?));
    }
    Err(OutboundError::InvalidConfig(format!(
        "unsupported outbound scheme in {:?}",
        mtg_config::redact_proxy_url(trimmed)
    )))
}
