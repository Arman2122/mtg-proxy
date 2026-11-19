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

use mtg_crypto::NoiseParams;
use mtg_net::{
    DnsResolver, ProxyPool, ProxyTarget, SocketConfig, coarse_now_ns, tune_tokio_stream,
};
use mtg_protocol::doppel::{DoppelParams, ScoutCollector, ShapingMode};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// Maximum cover hosts probed per scouting cycle (prevents DNS/network bursts
/// when thousands of secrets are configured).
pub const MAX_SCOUT_TARGETS: usize = 8;
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
}

/// Aggregate raw [`ScoutSample`]s from one or more cover hosts into a validated
/// [`DoppelParams`] model (preserving configured `shaping` and fallback `drs`).
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
    for s in samples {
        all_gaps.extend_from_slice(&s.gaps_ms);
        if s.observed_drs {
            any_drs = true;
        }
    }

    let fitted = DoppelParams::fit_weibull(&all_gaps, any_drs, shaping, noise).or_default();
    Some(fitted)
}

/// Probe one HTTPS cover target via real TLS 1.3/1.2 handshake + HTTP GET,
/// returning observed cert-flight bytes, inter-record arrival gaps, and DRS flag.
pub async fn probe_cover_target(
    target: &ScoutTarget,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
    connector: &TlsConnector,
) -> io::Result<ScoutSample> {
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
    let cert_flight_bytes = guard.measure_cert_flight_bytes();
    let (gaps_ms, observed_drs) = guard.extract_gaps_and_drs();
    Ok(ScoutSample {
        cert_flight_bytes,
        gaps_ms,
        observed_drs,
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

/// Execute one complete scouting round over `targets`, returning aggregated
/// [`DoppelParams`] if at least one cover server responded cleanly.
pub async fn run_scout_round(
    targets: &[ScoutTarget],
    configured_drs: bool,
    shaping: ShapingMode,
    dns: &DnsResolver,
    proxy_pool: Option<&ProxyPool>,
    sock_cfg: &SocketConfig,
) -> Option<DoppelParams> {
    if targets.is_empty() {
        return None;
    }
    let connector = build_scout_tls_connector();
    let mut samples = Vec::new();
    for target in targets.iter().take(MAX_SCOUT_TARGETS) {
        match probe_cover_target(target, dns, proxy_pool, sock_cfg, &connector).await {
            Ok(sample) => {
                debug!(
                    host = %target.host,
                    port = target.port,
                    cert_bytes = ?sample.cert_flight_bytes,
                    gaps = sample.gaps_ms.len(),
                    drs = sample.observed_drs,
                    "doppelganger cover scouted"
                );
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

    let updated = aggregate_samples(&samples, configured_drs, shaping);
    if let Some(p) = updated {
        info!(
            k = p.k,
            lambda_ms = p.lambda_ms,
            drs = p.drs,
            noise_mean = p.noise.mean,
            noise_jitter = p.noise.jitter,
            probed = samples.len(),
            "doppelganger traffic profile calibrated from live covers"
        );
    }
    updated
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

    let mut last_err = io::Error::other("no cover addresses resolved");
    for sa in addrs {
        match tokio::time::timeout(SCOUT_TARGET_TIMEOUT, TcpStream::connect(sa)).await {
            Ok(Ok(stream)) => {
                let _ = tune_tokio_stream(&stream, sock_cfg);
                return Ok(stream);
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = io::Error::new(io::ErrorKind::TimedOut, "scout connect timeout"),
        }
    }
    Err(last_err)
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
            },
            ScoutSample {
                cert_flight_bytes: Some(4400),
                gaps_ms: gaps[150..].to_vec(),
                observed_drs: true,
            },
        ];

        let params = aggregate_samples(&samples, false, ShapingMode::Burst).expect("params");
        assert!(params.drs);
        assert_eq!(params.shaping, ShapingMode::Burst);
        assert_eq!(params.noise.mean, 3800);
        assert_eq!(params.noise.jitter, 600);
        assert!((params.k - 0.75).abs() < 0.1, "k={}", params.k);
        assert!(
            (params.lambda_ms - 4.0).abs() < 0.8,
            "lambda={}",
            params.lambda_ms
        );
    }
}
