//! Live background Doppelganger cover-site scouting (`[defense.doppelganger]`).
//!
//! Probes configured `urls` and/or FakeTLS secret fronting hosts over real TLS
//! (using `tokio-rustls` + `webpki-roots` wrapped in a zero-copy wire observer),
//! measures actual server encrypted handshake certificate-flight sizes and
//! post-handshake inter-record arrival gaps, fits Weibull MLE + DRS detection,
//! and publishes updated [`DoppelParams`] atomically via `ArcSwap` with zero
//! disruption to live connections!

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use mtg_crypto::{
    NoiseParams, ServerHelloProfile, build_pq_scout_client_hello, parse_raw_server_hello_profile,
};
use mtg_net::{
    DnsResolver, ProxyPool, ProxyTarget, SocketConfig, coarse_now_ns, happy_eyeballs_connect,
};
use mtg_protocol::doppel::{DoppelParams, ScoutCollector, ShapingMode};
use rustc_hash::FxHashMap;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// Maximum cover hosts probed concurrently per scouting cycle (prevents
/// DNS/network bursts when thousands of secrets are configured).
pub const MAX_SCOUT_TARGETS: usize = 16;
/// Per-target network timeout during cover scouting.
pub const SCOUT_TARGET_TIMEOUT: Duration = Duration::from_secs(6);
/// Maximum post-handshake response bytes read per cover URL for gap sampling.
pub const SCOUT_MAX_BODY_BYTES: usize = 256 * 1024;
/// Periodic background re-scouting cadence (6 hours).
pub const SCOUT_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Parsed cover scouting target `(host, port, path)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScoutTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ScoutTarget {
    /// Parse an HTTPS URL (`https://example.com:8443/path`) or bare hostname
    /// (`storage.googleapis.com`) into a [`ScoutTarget`].
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let rest = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);

        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }

        // Handle bracketed IPv6 `[::1]:443` or `host:port` or bare `host`.
        let (host, port) = if let Some(after_open) = authority.strip_prefix('[') {
            let close = after_open.find(']')?;
            let host = &after_open[..close];
            let port_part = &after_open[close + 1..];
            let port = if let Some(p) = port_part.strip_prefix(':') {
                p.parse::<u16>().ok()?
            } else {
                443
            };
            (host, port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                (h, port)
            } else {
                (authority, 443)
            }
        } else {
            (authority, 443)
        };

        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
        })
    }
}

/// Transparent wrapper around `TcpStream` that records raw server TLS wire
/// records into a shared [`ScoutCollector`] without interfering with TLS I/O.
struct ObservingStream {
    inner: TcpStream,
    collector: Arc<Mutex<ScoutCollector>>,
}

impl AsyncRead for ObservingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before
                    && let Ok(mut c) = self.collector.lock()
                {
                    c.observe_server_bytes(&buf.filled()[before..after], coarse_now_ns());
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for ObservingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Measurement gathered from probing a single cover server.
#[derive(Debug, Clone)]
pub struct ScoutSample {
    pub cert_flight_bytes: Option<usize>,
    pub gaps_ms: Vec<f64>,
    pub observed_drs: bool,
    /// Exact live TLS 1.3 `ServerHelloProfile` captured via a raw Post-Quantum
    /// `X25519MLKEM768` + `X25519` ClientHello probe (cipher, PQ support, extension order).
    pub server_hello: Option<ServerHelloProfile>,
}

/// Aggregate raw [`ScoutSample`]s from one or more cover hosts into a validated
/// [`DoppelParams`] model (preserving configured `shaping`, fallback `drs`, and
/// live cover `ServerHelloProfile`).
pub fn aggregate_samples(
    samples: &[ScoutSample],
    configured_drs: bool,
    shaping: ShapingMode,
) -> Option<DoppelParams> {
    if samples.is_empty() {
        return None;
    }

    let mut cert_sizes: Vec<usize> = samples
        .iter()
        .filter_map(|s| s.cert_flight_bytes)
        .filter(|&sz| sz > 0)
        .collect();
    let noise = if cert_sizes.is_empty() {
        NoiseParams::default()
    } else {
        cert_sizes.sort_unstable();
        let sum: usize = cert_sizes.iter().sum();
        let mean = (sum / cert_sizes.len()).clamp(1000, 16_000);
        let spread = cert_sizes
            .last()
            .copied()
            .unwrap_or(mean)
            .saturating_sub(cert_sizes.first().copied().unwrap_or(mean))
            / 2;
        // Keep realistic jitter (>= 250 B or 12% of mean) so ServerHello sizes vary naturally.
        let jitter = spread.max(mean / 8).max(250).min(mean / 2);
        NoiseParams { mean, jitter }
    };

    let mut all_gaps = Vec::new();
    let mut any_drs = configured_drs;
    let mut observed_sh: Option<ServerHelloProfile> = None;
    for s in samples {
        all_gaps.extend_from_slice(&s.gaps_ms);
        if s.observed_drs {
            any_drs = true;
        }
        if observed_sh.is_none() && s.server_hello.is_some() {
            observed_sh = s.server_hello;
        }
    }

    let mut fitted = DoppelParams::fit_weibull(&all_gaps, any_drs, shaping, noise).or_default();
    if let Some(mut sh) = observed_sh {
        if noise.mean > 0 {
            sh.noise = noise;
        }
        fitted.server_hello = sh;
    } else {
        fitted.server_hello.noise = noise;
    }
    Some(fitted)
}

/// Send a raw Chrome-like Post-Quantum `X25519MLKEM768` + `X25519` TLS 1.3
/// `ClientHello` to `target` and parse the cover server's exact raw wire
/// `ServerHello` (`cipher_suite`, `prefer_pq_mlkem768`, `key_share_first`, and
/// encrypted handshake flight size).
pub async fn probe_cover_server_hello_profile(
    target: &ScoutTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
) -> io::Result<ServerHelloProfile> {
    let mut tcp = dial_target(target, dns, proxy_pool, sock_cfg).await?;
    let ch = build_pq_scout_client_hello(&target.host);
    tokio::time::timeout(SCOUT_TARGET_TIMEOUT, tcp.write_all(&ch))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pq scout write timeout"))??;

    let mut raw = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    while raw.len() < 16_384 {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            break;
        }
        let read_wait = if raw.is_empty() {
            rem
        } else {
            rem.min(Duration::from_millis(120))
        };
        match tokio::time::timeout(read_wait, tcp.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                raw.extend_from_slice(&tmp[..n]);
                if parse_raw_server_hello_profile(&raw).is_some_and(|p| p.noise.mean >= 1000) {
                    break;
                }
            }
            Ok(Err(e)) => {
                if raw.is_empty() {
                    return Err(e);
                }
                break;
            }
        }
    }

    parse_raw_server_hello_profile(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cover did not return a TLS 1.3 ServerHello",
        )
    })
}

/// Probe one HTTPS cover target via raw PQ TLS 1.3 ServerHello profiling +
/// real TLS 1.3/1.2 handshake + HTTP GET, returning observed cert-flight bytes,
/// inter-record arrival gaps, DRS flag, and live `ServerHelloProfile`.
pub async fn probe_cover_target(
    target: &ScoutTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
    connector: &TlsConnector,
) -> io::Result<ScoutSample> {
    // 1. Capture exact raw wire ServerHello profile (PQ X25519MLKEM768, cipher, extension order)!
    let server_hello = probe_cover_server_hello_profile(target, dns, proxy_pool, sock_cfg)
        .await
        .ok();

    let tcp = dial_target(target, dns, proxy_pool, sock_cfg).await?;
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS SNI"))?;

    let collector = Arc::new(Mutex::new(ScoutCollector::new()));
    let obs = ObservingStream {
        inner: tcp,
        collector: Arc::clone(&collector),
    };

    let mut tls = tokio::time::timeout(SCOUT_TARGET_TIMEOUT, connector.connect(server_name, obs))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "doppel scout TLS timeout"))??;

    if let Ok(mut c) = collector.lock() {
        c.mark_handshake_complete();
    }

    // Issue a lightweight HTTP/1.1 GET to sample real server record pacing & DRS.
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    let _ = tokio::time::timeout(SCOUT_TARGET_TIMEOUT, async {
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;
        let mut sink = [0u8; 8192];
        let mut total = 0usize;
        while total < SCOUT_MAX_BODY_BYTES {
            match tls.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        Ok::<(), io::Error>(())
    })
    .await;

    let guard = collector
        .lock()
        .map_err(|_| io::Error::other("scout collector poisoned"))?;
    let cert_flight_bytes = guard
        .measure_cert_flight_bytes()
        .or_else(|| server_hello.map(|p| p.noise.mean).filter(|&m| m > 0));
    let (gaps_ms, observed_drs) = guard.extract_gaps_and_drs();
    Ok(ScoutSample {
        cert_flight_bytes,
        gaps_ms,
        observed_drs,
        server_hello,
    })
}

/// Build a shared `TlsConnector` configured with Mozilla's `webpki-roots`.
pub fn build_scout_tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// Per-SNI calibrated Doppelganger profile catalog published atomically via `ArcSwap`.
///
/// When a proxy serves multiple FakeTLS cover domains (e.g. `storage.googleapis.com`
/// and `www.cloudflare.com`), each domain receives its own exact live-measured
/// TLS certificate-flight size, jitter, Weibull inter-arrival model, and DRS flag
/// instead of averaging unrelated websites together!
#[derive(Debug, Clone, Default)]
pub struct DoppelCatalog {
    pub default: DoppelParams,
    pub per_host: FxHashMap<String, DoppelParams>,
}

impl DoppelCatalog {
    #[inline]
    pub fn from_default(default: DoppelParams) -> Self {
        Self {
            default,
            per_host: FxHashMap::default(),
        }
    }

    /// Look up the calibrated [`DoppelParams`] for the first matching client SNI,
    /// falling back to `self.default`.
    #[inline]
    pub fn params_for_sni(&self, sni_list: &[String]) -> DoppelParams {
        if !self.per_host.is_empty() {
            for sni in sni_list {
                if let Some(&p) = self.per_host.get(sni) {
                    return p;
                }
                let lower = sni.to_ascii_lowercase();
                if let Some(&p) = self.per_host.get(&lower) {
                    return p;
                }
            }
        }
        self.default
    }
}

/// Execute one complete **concurrent** scouting round over `targets`, returning
/// a [`DoppelCatalog`] with both per-SNI host profiles and an aggregated fallback!
pub async fn run_scout_round(
    targets: &[ScoutTarget],
    configured_drs: bool,
    shaping: ShapingMode,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
) -> Option<DoppelCatalog> {
    if targets.is_empty() {
        return None;
    }
    let connector = build_scout_tls_connector();
    let dns_owned = dns.clone();
    let pool_owned = proxy_pool.cloned();
    let sc = *sock_cfg;

    let mut join_set = tokio::task::JoinSet::new();
    for target in targets.iter().take(MAX_SCOUT_TARGETS).cloned() {
        let conn = connector.clone();
        let d = dns_owned.clone();
        let p = pool_owned.clone();
        join_set.spawn(async move {
            let res = probe_cover_target(&target, &d, p.as_ref(), &sc, &conn).await;
            (target, res)
        });
    }

    let mut samples = Vec::new();
    let mut per_host_samples: FxHashMap<String, Vec<ScoutSample>> = FxHashMap::default();

    while let Some(joined) = join_set.join_next().await {
        let Ok((target, res)) = joined else {
            continue;
        };
        match res {
            Ok(sample) => {
                debug!(
                    host = %target.host,
                    port = target.port,
                    cert_bytes = ?sample.cert_flight_bytes,
                    gaps = sample.gaps_ms.len(),
                    drs = sample.observed_drs,
                    "doppelganger cover scouted"
                );
                per_host_samples
                    .entry(target.host.clone())
                    .or_default()
                    .push(sample.clone());
                samples.push(sample);
            }
            Err(e) => {
                debug!(
                    host = %target.host,
                    port = target.port,
                    error = %e,
                    "doppelganger cover scout skipped unreachable target"
                );
            }
        }
    }

    let default = aggregate_samples(&samples, configured_drs, shaping)?;
    let mut per_host = FxHashMap::default();
    for (host, host_samples) in per_host_samples {
        if let Some(p) = aggregate_samples(&host_samples, configured_drs, shaping) {
            per_host.insert(host, p);
        }
    }

    info!(
        k = default.k,
        lambda_ms = default.lambda_ms,
        drs = default.drs,
        noise_mean = default.noise.mean,
        noise_jitter = default.noise.jitter,
        pq_mlkem768 = default.server_hello.prefer_pq_mlkem768,
        cipher_suite = ?default.server_hello.cipher_suite.map(|c| format!("0x{c:04x}")),
        key_share_first = default.server_hello.key_share_first,
        probed = samples.len(),
        per_host_profiles = per_host.len(),
        "doppelganger traffic & ServerHello profile calibrated from live covers"
    );

    Some(DoppelCatalog { default, per_host })
}

async fn dial_target(
    target: &ScoutTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
) -> io::Result<TcpStream> {
    if let Some(pool) = proxy_pool
        && !pool.is_empty()
    {
        return tokio::time::timeout(
            SCOUT_TARGET_TIMEOUT,
            pool.dial(&ProxyTarget::Domain(target.host.clone(), target.port)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "scout proxy dial timeout"))?
        .map_err(|e| io::Error::other(e.to_string()));
    }

    let addrs = tokio::time::timeout(
        SCOUT_TARGET_TIMEOUT,
        dns.resolve_socket_addrs(&target.host, target.port),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "scout DNS timeout"))??;

    let (stream, _) = happy_eyeballs_connect(&addrs, sock_cfg, SCOUT_TARGET_TIMEOUT).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scout_target_parses_urls_and_bare_hosts() {
        assert_eq!(
            ScoutTarget::parse("https://storage.googleapis.com/assets/app.js"),
            Some(ScoutTarget {
                host: "storage.googleapis.com".to_owned(),
                port: 443,
                path: "/assets/app.js".to_owned(),
            })
        );
        assert_eq!(
            ScoutTarget::parse("https://cdn.example.com:8443"),
            Some(ScoutTarget {
                host: "cdn.example.com".to_owned(),
                port: 8443,
                path: "/".to_owned(),
            })
        );
        assert_eq!(
            ScoutTarget::parse("Google.COM"),
            Some(ScoutTarget {
                host: "google.com".to_owned(),
                port: 443,
                path: "/".to_owned(),
            })
        );
        assert_eq!(ScoutTarget::parse(""), None);
    }

    #[test]
    fn aggregate_samples_calibrates_noise_weibull_and_drs() {
        // Synthetic Weibull(k=0.75, lambda=4.0) arrival gaps + realistic cert-flight sizes.
        let gaps: Vec<f64> = (1..=300)
            .map(|i| {
                let u = f64::from(i) / 301.0;
                4.0 * (-u.ln()).powf(1.0 / 0.75)
            })
            .collect();
        let samples = vec![
            ScoutSample {
                cert_flight_bytes: Some(3200),
                gaps_ms: gaps[..150].to_vec(),
                observed_drs: false,
                server_hello: Some(ServerHelloProfile {
                    cipher_suite: Some(mtg_crypto::TLS13_AES_256_GCM_SHA384),
                    prefer_pq_mlkem768: true,
                    key_share_first: true,
                    noise: NoiseParams::default(),
                }),
            },
            ScoutSample {
                cert_flight_bytes: Some(4400),
                gaps_ms: gaps[150..].to_vec(),
                observed_drs: true,
                server_hello: None,
            },
        ];

        let params = aggregate_samples(&samples, false, ShapingMode::Burst).expect("params");
        assert!(params.drs);
        assert_eq!(params.shaping, ShapingMode::Burst);
        assert_eq!(params.noise.mean, 3800);
        assert_eq!(params.noise.jitter, 600);
        assert!(params.server_hello.prefer_pq_mlkem768);
        assert!(params.server_hello.key_share_first);
        assert_eq!(
            params.server_hello.cipher_suite,
            Some(mtg_crypto::TLS13_AES_256_GCM_SHA384)
        );
        assert_eq!(params.server_hello.noise.mean, 3800);
        assert!((params.k - 0.75).abs() < 0.1, "k={}", params.k);
        assert!(
            (params.lambda_ms - 4.0).abs() < 0.8,
            "lambda={}",
            params.lambda_ms
        );
    }
}
