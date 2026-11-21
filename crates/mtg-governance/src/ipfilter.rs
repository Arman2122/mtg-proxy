//! Wait-free IP blocklist / allowlist engine (`Option<ArcSwap<IpFilter>>`):
//! - `None` when disabled -> **0 ns** lookup cost!
//! - IPv4: **DIR-24-8 O(1) direct lookup table** (2 MiB compact bitmap for all
//!   `/24` prefixes + sorted overflow intervals for `/25..=/32`!) -> **~3–6 ns**!
//! - IPv6: **Sorted coalesced non-overlapping `u128` intervals** with binary
//!   search -> **~8–15 ns**!
//! - Universal parser supporting:
//!   - Plain CIDR / single-IP lists (e.g. `Arman2122/IR-Geo-DB` `ir-ipv4.txt`, `ir-ipv6.txt`)
//!   - FireHOL `.ipset` files (verified against `tests/golden/ipblocklist/testdata/*.ipset`)
//!   - Linux `ipset restore` files (`create`, `flush`, `add <set> <cidr> [-exist]`, e.g. `ir.ipset`)
//! - Enterprise resilience:
//!   - Instant cold-boot warm coverage from optional atomic on-disk `cache-file` + inline `cidrs`
//!   - Multi-hop HTTP redirect support (GitHub `/releases/latest/download/...`) + 1 automatic retry
//!   - Per-source Last-Known-Good (LKG) retention (if 1 of 2 URLs fails, never drops the healthy source!)
//!   - Bounded concurrent downloads (`download-concurrency`) + 60s backoff retry on partial/full outage
//!   - Crash-safe atomic `cache-file` persistence (`0600`, `tmp + sync_data + rename`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use mtg_config::{ListConfig, PreferIp};
use mtg_core::ip::unmap_ip;
use mtg_net::{DnsResolver, ProxyPool, SocketConfig, fetch_url_bytes_with_dns};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

/// Default remote IP list refresh interval (24 hours).
pub const DEFAULT_IPFILTER_UPDATE_EACH: Duration = Duration::from_secs(24 * 3600);
/// Retry interval when any source fails during refresh.
pub const DEFAULT_IPFILTER_RETRY_EACH: Duration = Duration::from_secs(60);
/// Default bounded concurrent URL downloads.
pub const DEFAULT_IPFILTER_CONCURRENCY: usize = 4;
/// Per-URL HTTP download timeout.
const IPFILTER_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Brief pause before one automatic retry on transient HTTP download error.
const IPFILTER_TRANSIENT_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Errors parsing a FireHOL `.ipset` / CIDR / Linux `ipset restore` file.
#[derive(Debug, Error)]
pub enum IpFilterError {
    #[error("cannot parse line {line}: invalid IP or CIDR {text:?}")]
    InvalidLine { line: usize, text: String },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Immutable compiled IPv4 + IPv6 lookup structure.
///
/// IPv4 lookup path:
/// 1. Check 1-bit `/24` bitmap (`v4_dir24`: 2 MiB = `2^24` bits covering every
///    `a.b.c.0/24`). If set, immediate `true` in ~3–5 ns!
/// 2. Otherwise check sorted coalesced `/25..=/32` exact ranges (`v4_fine`)
///    via binary search (empty for most pure-CIDR lists -> instant `false`!).
#[derive(Debug, Clone)]
pub struct IpFilter {
    /// `2^24` bits = `262_144` `u64` words (2 MiB): bit `ip >> 8` is 1 iff the
    /// entire `/24` containing `ip` is covered by a `<= /24` prefix.
    v4_dir24: Box<[u64]>,
    /// Coalesced non-overlapping inclusive `[start, end]` intervals for `/25..=/32`.
    v4_fine: Vec<(u32, u32)>,
    /// Coalesced non-overlapping inclusive `[start, end]` IPv6 intervals.
    v6_ranges: Vec<(u128, u128)>,
    /// Number of raw entries inserted before coalescing (for observability).
    entry_count: usize,
    v4_entry_count: usize,
    v6_entry_count: usize,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::empty()
    }
}

impl IpFilter {
    /// Empty filter matching no IP addresses.
    pub fn empty() -> Self {
        Self {
            v4_dir24: Box::new([]),
            v4_fine: Vec::new(),
            v6_ranges: Vec::new(),
            entry_count: 0,
            v4_entry_count: 0,
            v6_entry_count: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entry_count
    }

    #[inline]
    pub fn v4_len(&self) -> usize {
        self.v4_entry_count
    }

    #[inline]
    pub fn v6_len(&self) -> usize {
        self.v6_entry_count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Wait-free O(1) IPv4 / O(log N) IPv6 membership test (~4–15 ns).
    ///
    /// Automatically unmaps IPv4-mapped IPv6 (`::ffff:a.b.c.d`) identically to Go.
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.entry_count == 0 {
            return false;
        }
        match unmap_ip(ip) {
            IpAddr::V4(v4) => self.contains_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.contains_v6(u128::from(v6)),
        }
    }

    #[inline]
    pub fn contains_v4(&self, ip: u32) -> bool {
        if !self.v4_dir24.is_empty() {
            let idx = (ip >> 8) as usize;
            let word = self.v4_dir24[idx >> 6];
            if ((word >> (idx & 63)) & 1) != 0 {
                return true;
            }
        }
        if self.v4_fine.is_empty() {
            return false;
        }
        range_contains_u32(&self.v4_fine, ip)
    }

    #[inline]
    pub fn contains_v6(&self, ip: u128) -> bool {
        if self.v6_ranges.is_empty() {
            return false;
        }
        range_contains_u128(&self.v6_ranges, ip)
    }
}

#[inline]
fn range_contains_u32(ranges: &[(u32, u32)], val: u32) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= val);
    idx > 0 && val <= ranges[idx - 1].1
}

#[inline]
fn range_contains_u128(ranges: &[(u128, u128)], val: u128) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= val);
    idx > 0 && val <= ranges[idx - 1].1
}

/// Incremental builder compiling CIDR / FireHOL `.ipset` / Linux `ipset restore`
/// feeds into a wait-free [`IpFilter`].
#[derive(Debug, Default)]
pub struct IpFilterBuilder {
    v4_coarse: Vec<(u32, u32)>,
    v4_fine: Vec<(u32, u32)>,
    v6_ranges: Vec<(u128, u128)>,
    entry_count: usize,
    v4_entry_count: usize,
    v6_entry_count: usize,
}

impl IpFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a CIDR / FireHOL `.ipset` / Linux `ipset restore` text stream.
    ///
    /// Supports:
    /// - `#` and `;` line/inline comments, CRLF, and blank lines
    /// - Bare IPv4 / IPv6 addresses and CIDR prefixes (`5.160.0.0/16`, `2a01:5ec0::/32`)
    /// - Linux `ipset restore` directives (`create <set> ...`, `flush <set>`,
    ///   `destroy <set>`, `swap <a> <b>`, and `add <set> <cidr> [-exist ...]`)
    pub fn push_ipset_str(&mut self, text: &str) -> Result<(), IpFilterError> {
        self.push_ipset_str_inner(text, None)
    }

    /// Parse identically to [`Self::push_ipset_str`] while also appending canonical
    /// normalized CIDR lines into `canonical_out` (for atomic cache persistence).
    pub fn push_ipset_str_collecting(
        &mut self,
        text: &str,
        canonical_out: &mut Vec<String>,
    ) -> Result<(), IpFilterError> {
        self.push_ipset_str_inner(text, Some(canonical_out))
    }

    fn push_ipset_str_inner(
        &mut self,
        text: &str,
        mut canonical_out: Option<&mut Vec<String>>,
    ) -> Result<(), IpFilterError> {
        for (idx, raw_line) in text.lines().enumerate() {
            let without_comment = match raw_line.find(['#', ';']) {
                Some(pos) => &raw_line[..pos],
                None => raw_line,
            };
            let trimmed = without_comment.trim();
            if trimmed.is_empty() {
                continue;
            }

            let target_token = match parse_ipset_restore_directive(trimmed) {
                DirectiveAction::Skip => continue,
                DirectiveAction::Entry(tok) => tok,
                DirectiveAction::Invalid => {
                    return Err(IpFilterError::InvalidLine {
                        line: idx + 1,
                        text: trimmed.to_owned(),
                    });
                }
            };

            self.push_line_inner(target_token, canonical_out.as_deref_mut())
                .map_err(|_| IpFilterError::InvalidLine {
                    line: idx + 1,
                    text: trimmed.to_owned(),
                })?;
        }
        Ok(())
    }

    /// Parse a single non-empty trimmed IP or CIDR token.
    pub fn push_line(&mut self, token: &str) -> Result<(), IpFilterError> {
        self.push_line_inner(token, None)
    }

    fn push_line_inner(
        &mut self,
        token: &str,
        canonical_out: Option<&mut Vec<String>>,
    ) -> Result<(), IpFilterError> {
        let invalid = || IpFilterError::InvalidLine {
            line: 0,
            text: token.to_owned(),
        };
        if let Some((ip_str, bits_str)) = token.split_once('/') {
            let ip: IpAddr = ip_str.parse().map_err(|_| invalid())?;
            let bits: u8 = bits_str.parse().map_err(|_| invalid())?;
            match unmap_ip(ip) {
                IpAddr::V4(v4) => {
                    if bits > 32 {
                        return Err(invalid());
                    }
                    let start = self.push_v4_prefix(v4, bits);
                    if let Some(out) = canonical_out {
                        out.push(format!("{}/{bits}", Ipv4Addr::from(start)));
                    }
                }
                IpAddr::V6(v6) => {
                    if bits > 128 {
                        return Err(invalid());
                    }
                    let start = self.push_v6_prefix(v6, bits);
                    if let Some(out) = canonical_out {
                        out.push(format!("{}/{bits}", Ipv6Addr::from(start)));
                    }
                }
            }
        } else {
            let ip: IpAddr = token.parse().map_err(|_| invalid())?;
            match unmap_ip(ip) {
                IpAddr::V4(v4) => {
                    let start = self.push_v4_prefix(v4, 32);
                    if let Some(out) = canonical_out {
                        out.push(format!("{}/32", Ipv4Addr::from(start)));
                    }
                }
                IpAddr::V6(v6) => {
                    let start = self.push_v6_prefix(v6, 128);
                    if let Some(out) = canonical_out {
                        out.push(format!("{}/128", Ipv6Addr::from(start)));
                    }
                }
            }
        }
        self.entry_count += 1;
        Ok(())
    }

    fn push_v4_prefix(&mut self, ip: Ipv4Addr, bits: u8) -> u32 {
        let raw = u32::from(ip);
        let (start, end) = if bits == 0 {
            (0u32, u32::MAX)
        } else {
            let mask = !0u32 << (32 - bits);
            let s = raw & mask;
            (s, s | !mask)
        };
        if bits <= 24 {
            self.v4_coarse.push((start >> 8, end >> 8));
        } else {
            self.v4_fine.push((start, end));
        }
        self.v4_entry_count += 1;
        start
    }

    fn push_v6_prefix(&mut self, ip: Ipv6Addr, bits: u8) -> u128 {
        let raw = u128::from(ip);
        let (start, end) = if bits == 0 {
            (0u128, u128::MAX)
        } else {
            let mask = !0u128 << (128 - bits);
            let s = raw & mask;
            (s, s | !mask)
        };
        self.v6_ranges.push((start, end));
        self.v6_entry_count += 1;
        start
    }

    /// Finalize into a compiled wait-free [`IpFilter`].
    pub fn build(self) -> IpFilter {
        let v4_dir24 = if self.v4_coarse.is_empty() {
            Box::new([])
        } else {
            let mut bitmap = vec![0u64; 1 << 18].into_boxed_slice(); // 2^24 bits = 2 MiB
            for (s24, e24) in coalesce_u32(self.v4_coarse) {
                let mut cur = s24 as usize;
                let end = e24 as usize;
                // Set whole 64-bit words in bulk when aligned!
                while cur <= end && (cur & 63) != 0 {
                    bitmap[cur >> 6] |= 1u64 << (cur & 63);
                    cur += 1;
                }
                while cur + 63 <= end {
                    bitmap[cur >> 6] = u64::MAX;
                    cur += 64;
                }
                while cur <= end {
                    bitmap[cur >> 6] |= 1u64 << (cur & 63);
                    cur += 1;
                }
            }
            bitmap
        };

        let v4_fine = coalesce_u32(self.v4_fine);
        let v6_ranges = coalesce_u128(self.v6_ranges);

        IpFilter {
            v4_dir24,
            v4_fine,
            v6_ranges,
            entry_count: self.entry_count,
            v4_entry_count: self.v4_entry_count,
            v6_entry_count: self.v6_entry_count,
        }
    }
}

enum DirectiveAction<'a> {
    Skip,
    Entry(&'a str),
    Invalid,
}

/// Inspect a trimmed non-empty line for Linux `ipset restore` commands (`create`,
/// `flush`, `destroy`, `swap`, `add <set> <cidr> [-exist]`) vs plain CIDR tokens.
fn parse_ipset_restore_directive(line: &str) -> DirectiveAction<'_> {
    let mut parts = line.split_ascii_whitespace();
    let Some(first) = parts.next() else {
        return DirectiveAction::Skip;
    };
    let Some(second) = parts.next() else {
        // Single-token line: standard CIDR or bare IP entry.
        return DirectiveAction::Entry(first);
    };

    if first.eq_ignore_ascii_case("create")
        || first.eq_ignore_ascii_case("flush")
        || first.eq_ignore_ascii_case("destroy")
        || first.eq_ignore_ascii_case("swap")
    {
        // Valid ipset control directive (`second` is the set name).
        let _ = second;
        return DirectiveAction::Skip;
    }

    if first.eq_ignore_ascii_case("add") {
        // `add <setname> <ip_or_cidr> [-exist] [timeout ...]`
        return match parts.next() {
            Some(cidr) => DirectiveAction::Entry(cidr),
            None => DirectiveAction::Invalid,
        };
    }

    // Unexpected multi-token garbage (strictly reject!).
    DirectiveAction::Invalid
}

fn coalesce_u32(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_unstable_by_key(|&(s, _)| s);
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = out.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        out.push((s, e));
    }
    out
}

fn coalesce_u128(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_unstable_by_key(|&(s, _)| s);
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = out.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        out.push((s, e));
    }
    out
}

/// Configuration for [`LiveIpFilter`].
#[derive(Debug, Clone)]
pub struct LiveIpFilterConfig {
    pub sources: Vec<String>,
    pub inline_cidrs: Vec<String>,
    pub cache_file: Option<PathBuf>,
    pub update_each: Duration,
    pub download_concurrency: usize,
    pub dns: Option<Arc<DnsResolver>>,
    pub prefer_ip: PreferIp,
    pub proxy_pool: Option<ProxyPool>,
    pub sock_cfg: SocketConfig,
}

impl Default for LiveIpFilterConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            inline_cidrs: Vec::new(),
            cache_file: None,
            update_each: DEFAULT_IPFILTER_UPDATE_EACH,
            download_concurrency: DEFAULT_IPFILTER_CONCURRENCY,
            dns: None,
            prefer_ip: PreferIp::PreferIpv6,
            proxy_pool: None,
            sock_cfg: SocketConfig::default(),
        }
    }
}

/// Live-updating wait-free wrapper around [`IpFilter`] (`None` = disabled, 0 ns).
///
/// Guarantees:
/// - Warm-loads optional atomic on-disk `cache-file` + inline `cidrs` immediately
///   at startup before waiting on remote fetches.
/// - Follows multi-hop HTTP redirects (e.g. GitHub `/releases/latest/download/...`)
///   and retries once on transient download errors.
/// - Per-source Last-Known-Good (LKG) retention: if 1 of 2 URLs fails transiently,
///   rebuilds with fresh data + retained LKG for the failed source (zero partial lockout!).
/// - Retries automatically every 60 seconds after any failed/partial refresh, then
///   returns to `update_each` cadence once all sources are healthy.
#[derive(Debug)]
pub struct LiveIpFilter {
    current: Arc<ArcSwap<IpFilter>>,
    cfg: LiveIpFilterConfig,
    /// Per-source validated Last-Known-Good raw feed text.
    last_source_bodies: Mutex<FxHashMap<String, String>>,
    /// Warm on-disk cache body kept until every remote source has succeeded once.
    warm_cache_body: Mutex<Option<String>>,
    loaded_once: AtomicBool,
    last_partial_failure: AtomicBool,
    last_updated_unix: AtomicI64,
}

impl LiveIpFilter {
    /// Construct a [`LiveIpFilter`] with default concurrency and no cache/inline CIDRs.
    pub fn new(
        sources: Vec<String>,
        update_each: Duration,
        proxy_pool: Option<ProxyPool>,
        sock_cfg: SocketConfig,
    ) -> Self {
        Self::from_config(LiveIpFilterConfig {
            sources,
            update_each,
            proxy_pool,
            sock_cfg,
            ..LiveIpFilterConfig::default()
        })
    }

    /// Construct a [`LiveIpFilter`] directly from a parsed [`ListConfig`].
    pub fn from_list_config(
        list: &ListConfig,
        dns: Option<Arc<DnsResolver>>,
        prefer_ip: PreferIp,
        proxy_pool: Option<ProxyPool>,
        sock_cfg: SocketConfig,
    ) -> Self {
        Self::from_config(LiveIpFilterConfig {
            sources: list.urls.clone().unwrap_or_default(),
            inline_cidrs: list.cidrs.clone().unwrap_or_default(),
            cache_file: list.cache_file.as_deref().map(PathBuf::from),
            update_each: list.update_each.unwrap_or(DEFAULT_IPFILTER_UPDATE_EACH),
            download_concurrency: list
                .download_concurrency
                .map_or(DEFAULT_IPFILTER_CONCURRENCY, |c| c as usize),
            dns,
            prefer_ip,
            proxy_pool,
            sock_cfg,
        })
    }

    /// Construct a [`LiveIpFilter`] from a complete [`LiveIpFilterConfig`].
    pub fn from_config(mut cfg: LiveIpFilterConfig) -> Self {
        if cfg.update_each.is_zero() {
            cfg.update_each = DEFAULT_IPFILTER_UPDATE_EACH;
        }
        cfg.download_concurrency = if cfg.download_concurrency == 0 {
            DEFAULT_IPFILTER_CONCURRENCY
        } else {
            cfg.download_concurrency.clamp(1, 16)
        };
        Self {
            current: Arc::new(ArcSwap::from_pointee(IpFilter::empty())),
            cfg,
            last_source_bodies: Mutex::new(FxHashMap::default()),
            warm_cache_body: Mutex::new(None),
            loaded_once: AtomicBool::new(false),
            last_partial_failure: AtomicBool::new(false),
            last_updated_unix: AtomicI64::new(0),
        }
    }

    /// Wait-free hot-path membership check (~4 ns IPv4, ~10 ns IPv6).
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.current.load().contains(ip)
    }

    /// Current total CIDR/IP entry count (for metrics & diagnostics).
    #[inline]
    pub fn len(&self) -> usize {
        self.current.load().len()
    }

    /// Current IPv4 entry count.
    #[inline]
    pub fn v4_len(&self) -> usize {
        self.current.load().v4_len()
    }

    /// Current IPv6 entry count.
    #[inline]
    pub fn v6_len(&self) -> usize {
        self.current.load().v6_len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.current.load().is_empty()
    }

    /// True once at least one valid snapshot (cache, inline CIDRs, or remote) is active.
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.loaded_once.load(Ordering::Acquire)
    }

    /// Unix timestamp (seconds) of the last successful compilation (`0` if never loaded).
    #[inline]
    pub fn last_updated_unix(&self) -> i64 {
        self.last_updated_unix.load(Ordering::Acquire)
    }

    /// Cold-boot initialization:
    /// 1. Immediately warms the filter from `cache_file` + `inline_cidrs` if present.
    /// 2. Fetches all configured `sources` concurrently (with redirect following & retry).
    /// 3. Falls back cleanly to the warm cache / inline CIDRs if remote sources are
    ///    temporarily unreachable at boot (while scheduling 60s retry backoff!).
    pub async fn init_load(&self) -> Result<usize, IpFilterError> {
        let mut warm_loaded = false;
        let mut warm_builder = IpFilterBuilder::new();

        for cidr in &self.cfg.inline_cidrs {
            warm_builder.push_line(cidr.trim())?;
            warm_loaded = true;
        }

        if let Some(cache_path) = &self.cfg.cache_file {
            let path = cache_path.clone();
            match tokio::task::spawn_blocking(move || fs::read_to_string(&path)).await {
                Ok(Ok(body)) => {
                    let mut probe = IpFilterBuilder::new();
                    match probe.push_ipset_str(&body) {
                        Ok(()) => {
                            let _ = warm_builder.push_ipset_str(&body);
                            *self.warm_cache_body.lock() = Some(body);
                            warm_loaded = true;
                        }
                        Err(e) => {
                            warn!(
                                cache = %cache_path.display(),
                                error = %e,
                                "ignoring corrupt IP filter cache file"
                            );
                        }
                    }
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Ok(Err(e)) => {
                    warn!(
                        cache = %cache_path.display(),
                        error = %e,
                        "cannot read IP filter cache file"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "IP filter cache read task panicked");
                }
            }
        }

        if warm_loaded {
            let compiled = warm_builder.build();
            let count = compiled.len();
            let v4 = compiled.v4_len();
            let v6 = compiled.v6_len();
            self.current.store(Arc::new(compiled));
            self.loaded_once.store(true, Ordering::Release);
            info!(
                entries = count,
                v4, v6, "IP filter pre-warmed from cache/inline CIDRs"
            );
        }

        if self.cfg.sources.is_empty() {
            self.last_partial_failure.store(false, Ordering::Release);
            self.last_updated_unix
                .store(Utc::now().timestamp(), Ordering::Release);
            return Ok(self.len());
        }

        match self.refresh_once().await {
            Ok(n) => Ok(n),
            Err(e) if self.is_ready() => {
                warn!(
                    error = %e,
                    cached_entries = self.len(),
                    "initial remote IP filter fetch failed; serving warm cache/inline CIDRs and retrying in 60s"
                );
                Ok(self.len())
            }
            Err(e) => Err(e),
        }
    }

    /// Perform one concurrent refresh across all local files & HTTP(S) URLs.
    ///
    /// - Validates every source independently BEFORE updating per-source LKG so
    ///   corrupt responses can never poison an active filter.
    /// - If some sources fail transiently, retains their per-source LKG (or warm
    ///   cache body until every source has succeeded once) -> ZERO partial lockout!
    /// - Atomically persists `cache_file` (`0600`) whenever all sources succeed.
    pub async fn refresh_once(&self) -> Result<usize, IpFilterError> {
        if self.cfg.sources.is_empty() {
            let mut builder = IpFilterBuilder::new();
            for cidr in &self.cfg.inline_cidrs {
                builder.push_line(cidr.trim())?;
            }
            let compiled = builder.build();
            let count = compiled.len();
            self.current.store(Arc::new(compiled));
            self.loaded_once.store(true, Ordering::Release);
            self.last_partial_failure.store(false, Ordering::Release);
            self.last_updated_unix
                .store(Utc::now().timestamp(), Ordering::Release);
            return Ok(count);
        }

        let sem = Arc::new(Semaphore::new(self.cfg.download_concurrency));
        let mut set = JoinSet::new();

        for src in self.cfg.sources.clone() {
            let permit_sem = Arc::clone(&sem);
            let dns = self.cfg.dns.clone();
            let prefer_ip = self.cfg.prefer_ip;
            let proxy_pool = self.cfg.proxy_pool.clone();
            let sock_cfg = self.cfg.sock_cfg;

            set.spawn(async move {
                let _permit = permit_sem.acquire_owned().await;
                let fetched = fetch_single_source(
                    &src,
                    dns.as_deref(),
                    prefer_ip,
                    proxy_pool.as_ref(),
                    sock_cfg,
                )
                .await;
                (src, fetched)
            });
        }

        let mut fresh_bodies: Vec<(String, String)> = Vec::with_capacity(self.cfg.sources.len());
        let mut failed_sources = 0usize;

        while let Some(joined) = set.join_next().await {
            let Ok((src, res)) = joined else {
                failed_sources += 1;
                continue;
            };
            match res {
                Ok(text) => {
                    // Validate parse BEFORE admitting into per-source LKG!
                    let mut validator = IpFilterBuilder::new();
                    match validator.push_ipset_str(&text) {
                        Ok(()) => fresh_bodies.push((src, text)),
                        Err(e) => {
                            warn!(source = %src, error = %e, "IP filter parse failed; keeping last-known-good");
                            failed_sources += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(source = %src, error = %e, "IP filter source download failed; keeping last-known-good");
                    failed_sources += 1;
                }
            }
        }

        let fresh_ok = fresh_bodies.len();
        if fresh_ok == 0 {
            self.last_partial_failure.store(true, Ordering::Release);
            return Err(IpFilterError::Io(io::Error::other(
                "all IP filter sources failed; retaining previous filter",
            )));
        }

        // Update per-source LKG map and snapshot all available source bodies.
        let (lkg_snapshot, missing_lkg_sources) = {
            let mut lkg = self.last_source_bodies.lock();
            for (src, body) in fresh_bodies {
                lkg.insert(src, body);
            }
            let mut ordered = Vec::with_capacity(self.cfg.sources.len());
            let mut missing = 0usize;
            for src in &self.cfg.sources {
                if let Some(body) = lkg.get(src) {
                    ordered.push(body.clone());
                } else {
                    missing += 1;
                }
            }
            (ordered, missing)
        };

        // Once every configured source has its own verified LKG, drop the boot warm-cache fallback.
        let fallback_cache = if missing_lkg_sources == 0 {
            self.warm_cache_body.lock().take();
            None
        } else {
            self.warm_cache_body.lock().clone()
        };

        let mut builder = IpFilterBuilder::new();
        let want_cache_write = self.cfg.cache_file.is_some() && failed_sources == 0;
        let mut canonical_lines: Vec<String> = if want_cache_write {
            Vec::with_capacity(4096)
        } else {
            Vec::new()
        };

        for cidr in &self.cfg.inline_cidrs {
            let trimmed = cidr.trim();
            if trimmed.is_empty() {
                continue;
            }
            builder.push_line_inner(trimmed, None)?;
        }

        if let Some(ref warm) = fallback_cache {
            let _ = builder.push_ipset_str(warm);
        }

        for body in &lkg_snapshot {
            if want_cache_write {
                builder.push_ipset_str_collecting(body, &mut canonical_lines)?;
            } else {
                builder.push_ipset_str(body)?;
            }
        }

        let compiled = builder.build();
        let count = compiled.len();
        let v4 = compiled.v4_len();
        let v6 = compiled.v6_len();

        self.current.store(Arc::new(compiled));
        self.loaded_once.store(true, Ordering::Release);
        self.last_partial_failure
            .store(failed_sources > 0, Ordering::Release);
        self.last_updated_unix
            .store(Utc::now().timestamp(), Ordering::Release);

        if want_cache_write && let Some(cache_path) = self.cfg.cache_file.clone() {
            let lines = canonical_lines;
            let write_res =
                tokio::task::spawn_blocking(move || write_cache_atomic(&cache_path, &lines)).await;
            if let Ok(Err(e)) = write_res {
                warn!(error = %e, "IP filter atomic cache write failed");
            }
        }

        info!(
            entries = count,
            v4,
            v6,
            fresh_sources = fresh_ok,
            failed_sources,
            "IP filter updated"
        );
        Ok(count)
    }

    /// Spawn periodic background refresh loop (stops cleanly on `shutdown`).
    pub fn spawn_refresh_loop(self: &Arc<Self>, shutdown: tokio::sync::watch::Receiver<bool>) {
        self.spawn_refresh_loop_with_hook(shutdown, |_| {});
    }

    /// Spawn periodic background refresh loop with a live entry-count hook
    /// (for updating Prometheus / StatsD gauges on every daily auto-refresh).
    ///
    /// Automatically uses 60s retry backoff whenever a previous round had partial
    /// or full failures, returning to `update_each` once healthy.
    pub fn spawn_refresh_loop_with_hook<F>(
        self: &Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        on_update: F,
    ) where
        F: Fn(usize) + Send + Sync + 'static,
    {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let wait = if me.last_partial_failure.load(Ordering::Acquire) || !me.is_ready() {
                    DEFAULT_IPFILTER_RETRY_EACH.min(me.cfg.update_each)
                } else {
                    me.cfg.update_each
                };

                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                }
                if let Ok(n) = me.refresh_once().await {
                    on_update(n);
                }
            }
        });
    }
}

async fn fetch_single_source(
    src: &str,
    dns: Option<&DnsResolver>,
    prefer_ip: PreferIp,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: SocketConfig,
) -> io::Result<String> {
    if src.starts_with("http://") || src.starts_with("https://") {
        let mut last_err = None;
        for attempt in 0..2 {
            match fetch_url_bytes_with_dns(
                src,
                dns,
                prefer_ip,
                proxy_pool,
                sock_cfg,
                IPFILTER_FETCH_TIMEOUT,
            )
            .await
            {
                Ok(bytes) => return Ok(String::from_utf8_lossy(&bytes).into_owned()),
                Err(e) => {
                    last_err = Some(e);
                    if attempt == 0 {
                        tokio::time::sleep(IPFILTER_TRANSIENT_RETRY_DELAY).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("download failed")))
    } else {
        let path = Path::new(src).to_path_buf();
        tokio::task::spawn_blocking(move || fs::read_to_string(&path))
            .await
            .map_err(|e| io::Error::other(format!("local file read join error: {e}")))?
    }
}

/// Crash-safe atomic cache file writer (`0600`, `tmp + sync_data + rename + dir fsync`).
fn write_cache_atomic(path: &Path, lines: &[String]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ipfilter.cache");
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));

    let res = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        let mut buf = String::with_capacity(lines.len().saturating_mul(20) + 64);
        buf.push_str("# mtg-proxy ipfilter cache\n");
        for line in lines {
            buf.push_str(line);
            buf.push('\n');
        }
        f.write_all(buf.as_bytes())?;
        f.sync_data()?;
        drop(f);

        fs::rename(&tmp_path, path)?;
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    res
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn ipset_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/ipblocklist/testdata")
    }

    #[test]
    fn parses_golden_firehol_ipset_fixtures() {
        let good = std::fs::read_to_string(ipset_dir().join("good_ipset.ipset")).unwrap();
        let remote = std::fs::read_to_string(ipset_dir().join("remote_ipset.ipset")).unwrap();
        let broken = std::fs::read_to_string(ipset_dir().join("broken_ipset.ipset")).unwrap();

        let mut b = IpFilterBuilder::new();
        b.push_ipset_str(&good).unwrap();
        b.push_ipset_str(&remote).unwrap();
        let filter = b.build();

        assert!(filter.contains("10.0.0.10".parse().unwrap()));
        assert!(!filter.contains("10.0.0.11".parse().unwrap()));
        assert!(filter.contains("10.1.0.0".parse().unwrap()));
        assert!(filter.contains("10.1.0.255".parse().unwrap()));
        assert!(!filter.contains("10.1.1.0".parse().unwrap()));
        assert!(filter.contains("10.2.2.2".parse().unwrap()));
        // IPv4-mapped IPv6 unmaps automatically!
        assert!(filter.contains("::ffff:10.0.0.10".parse().unwrap()));
        // IPv6 host
        assert!(filter.contains("2001:db8:85a3::8a2e:370:7334".parse().unwrap()));
        assert!(!filter.contains("2001:db8:85a3::1".parse().unwrap()));

        let mut bad = IpFilterBuilder::new();
        assert!(bad.push_ipset_str(&broken).is_err());
    }

    #[test]
    fn parses_ir_geo_db_cidr_and_linux_ipset_restore_formats() {
        // Exact format produced by https://github.com/Arman2122/IR-Geo-DB `ir.ipset`
        let ir_ipset = "\
# IR-Geo-DB ipset restore file\r\n\
; semicolon comment\r\n\
create ir-v4 hash:net family inet hashsize 4096 maxelem 65536 -exist\r\n\
flush ir-v4\r\n\
add ir-v4 5.160.0.0/16 -exist\r\n\
add ir-v4 198.51.100.42/32 -exist\r\n\
create ir-v6 hash:net family inet6 hashsize 1024 maxelem 65536 -exist\r\n\
flush ir-v6\r\n\
add ir-v6 2a01:5ec0::/32 -exist\r\n";

        let mut b = IpFilterBuilder::new();
        let mut canonical = Vec::new();
        b.push_ipset_str_collecting(ir_ipset, &mut canonical)
            .unwrap();
        let filter = b.build();

        assert_eq!(filter.len(), 3);
        assert_eq!(filter.v4_len(), 2);
        assert_eq!(filter.v6_len(), 1);
        assert_eq!(
            canonical,
            vec!["5.160.0.0/16", "198.51.100.42/32", "2a01:5ec0::/32"]
        );

        assert!(filter.contains("5.160.123.45".parse().unwrap()));
        assert!(filter.contains("::ffff:5.160.123.45".parse().unwrap()));
        assert!(filter.contains("198.51.100.42".parse().unwrap()));
        assert!(!filter.contains("198.51.100.43".parse().unwrap()));
        assert!(filter.contains("2a01:5ec0:beef::1".parse().unwrap()));
        assert!(!filter.contains("2001:db8::1".parse().unwrap()));

        // Strict rejection of malformed `add` or multi-token garbage!
        assert!(IpFilterBuilder::new().push_ipset_str("add ir-v4").is_err());
        assert!(
            IpFilterBuilder::new()
                .push_ipset_str("garbage two tokens")
                .is_err()
        );
    }

    #[tokio::test]
    async fn per_source_lkg_prevents_partial_outage_lockout_and_cache_survives_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let v4_path = dir.path().join("ir-ipv4.txt");
        let v6_path = dir.path().join("ir-ipv6.txt");
        let cache_path = dir.path().join("allowlist.cache");

        std::fs::write(&v4_path, "# v4\n5.160.0.0/16\n").unwrap();
        std::fs::write(&v6_path, "# v6\n2a01:5ec0::/32\n").unwrap();

        let cfg = LiveIpFilterConfig {
            sources: vec![
                v4_path.to_string_lossy().into_owned(),
                v6_path.to_string_lossy().into_owned(),
            ],
            inline_cidrs: vec!["127.0.0.1/32".to_owned()],
            cache_file: Some(cache_path.clone()),
            update_each: Duration::from_secs(3600),
            download_concurrency: 2,
            ..LiveIpFilterConfig::default()
        };

        let live = LiveIpFilter::from_config(cfg.clone());
        let n = live.init_load().await.unwrap();
        assert_eq!(n, 3);
        assert!(live.contains("5.160.1.1".parse().unwrap()));
        assert!(live.contains("2a01:5ec0::42".parse().unwrap()));
        assert!(live.contains("127.0.0.1".parse().unwrap()));
        assert!(!live.contains("203.0.113.9".parse().unwrap()));
        assert!(cache_path.exists());

        // Simulate partial upstream outage: v4 file gets corrupted/deleted while v6 updates!
        std::fs::write(&v4_path, "<html>502 Bad Gateway</html>").unwrap();
        std::fs::write(&v6_path, "# v6 updated\n2a01:5ec0::/32\n2a02:2330::/32\n").unwrap();

        let n2 = live.refresh_once().await.unwrap();
        assert_eq!(n2, 4);
        // Fresh v6 entry applied AND v4 LKG retained (ZERO lockout for IPv4 users!)
        assert!(live.contains("5.160.1.1".parse().unwrap()));
        assert!(live.contains("2a02:2330::7".parse().unwrap()));

        // Simulate cold reboot while BOTH upstream sources are completely unavailable!
        std::fs::remove_file(&v4_path).unwrap();
        std::fs::remove_file(&v6_path).unwrap();

        let cold = LiveIpFilter::from_config(cfg);
        let n_warm = cold.init_load().await.unwrap();
        assert_eq!(n_warm, 3);
        assert!(cold.contains("5.160.1.1".parse().unwrap()));
        assert!(cold.contains("2a01:5ec0::42".parse().unwrap()));
        assert!(cold.contains("127.0.0.1".parse().unwrap()));
        assert!(!cold.contains("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn dir24_lookup_is_fast_under_large_cidr_set() {
        let mut b = IpFilterBuilder::new();
        for a in 1..=200u8 {
            for c in (0..=250u8).step_by(5) {
                b.push_line(&format!("{a}.{c}.0.0/16")).unwrap();
            }
        }
        b.push_line("192.168.1.42").unwrap();
        let filter = b.build();

        let start = std::time::Instant::now();
        let mut hits = 0u64;
        for i in 0..100_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(2_654_435_761)));
            if filter.contains(ip) {
                hits += 1;
            }
        }
        let ns_per_op = start.elapsed().as_nanos() as f64 / 100_000.0;
        assert!(hits > 0);
        // Debug build is ~10x slower than release; verify it's already sub-microsecond even unoptimized.
        eprintln!("IpFilter lookup (debug): {ns_per_op:.1} ns/op (hits={hits})");
    }
}
