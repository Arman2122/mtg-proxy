//! `run`, `run --check`, and `simple-run` subcommands with Linux SIGHUP live
//! atomic reload, SIGTERM/SIGINT graceful drain, Management HTTP API,
//! Prometheus, StatsD, and `RLIMIT_NOFILE` auto-tuning.

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use chrono::Utc;
use clap::Args;
use mtg_api::{spawn_api_server, spawn_prometheus_server, spawn_statsd_exporter};
use mtg_config::{Config, HostPort, PreferIp, parse_bytes_str, parse_duration};
use mtg_core::Secret;
use mtg_engine::{EngineRuntime, ProxyEngine};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{VERSION, init_logging};

/// Arguments for `mtg-proxy simple-run <bind-to> <secret> ...`.
#[derive(Debug, Args)]
pub struct SimpleRunArgs {
    /// A host:port to bind proxy to.
    pub bind_to: String,
    /// Proxy secret.
    pub secret: String,

    /// Run in debug mode.
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,
    /// Max number of concurrent connections to proxy.
    #[arg(short = 'c', long = "concurrency", default_value_t = 8192)]
    pub concurrency: u32,
    /// Deprecated and ignored.
    #[arg(short = 'b', long = "tcp-buffer", default_value = "4KB")]
    pub tcp_buffer: String,
    /// IP preference (`prefer-ipv6`, `prefer-ipv4`, `only-ipv4`, `only-ipv6`).
    #[arg(short = 'i', long = "prefer-ip", default_value = "prefer-ipv6")]
    pub prefer_ip: String,
    /// A port to access for domain fronting.
    #[arg(short = 'p', long = "domain-fronting-port", default_value_t = 443)]
    pub domain_fronting_port: u16,
    /// Hostname or IP to dial for domain fronting instead of resolving the secret hostname.
    #[arg(long = "domain-fronting-host")]
    pub domain_fronting_host: Option<String>,
    /// Deprecated: use --domain-fronting-host.
    #[arg(long = "domain-fronting-ip")]
    pub domain_fronting_ip: Option<String>,
    /// IP address of DNS-over-HTTPS to use.
    #[arg(short = 'n', long = "doh-ip", default_value = "1.1.1.1")]
    pub doh_ip: IpAddr,
    /// Network timeout to use (e.g. 10s).
    #[arg(short = 't', long = "timeout", default_value = "10s")]
    pub timeout: String,
    /// SOCKS5 proxies to use for network access.
    #[arg(short = 's', long = "socks5-proxy")]
    pub socks5_proxies: Vec<String>,
    /// Size of anti-replay cache to use.
    #[arg(short = 'a', long = "antireplay-cache-size", default_value = "1MB")]
    pub antireplay_cache_size: String,
    /// Expect PROXY protocol (v1 or v2) headers on the listener.
    #[arg(long = "proxy-protocol-listener")]
    pub proxy_protocol_listener: bool,
    /// Override pinned worker thread count (defaults to available CPU cores).
    #[arg(long = "workers", default_value_t = 0)]
    pub workers: usize,
    /// Skip Linux io_uring capability probe at startup (recommended under strict container seccomp profiles).
    #[arg(long = "epoll")]
    pub epoll: bool,
}

/// Read, parse, apply env overlays, and validate a TOML config file.
pub fn read_and_validate_config(path: &Path) -> Result<Config> {
    let raw = fs::read(path).with_context(|| format!("cannot read config {}", path.display()))?;
    let mut conf = Config::parse(&raw).context("cannot parse config")?;
    conf.apply_environment()
        .context("cannot apply environment variables")?;
    conf.validate().context("invalid configuration")?;
    Ok(conf)
}

/// `run <config-path> [--check]`.
pub async fn execute_run(
    config_path: &Path,
    check_only: bool,
    workers: usize,
    force_epoll: bool,
) -> Result<()> {
    let conf = read_and_validate_config(config_path)?;

    if check_only {
        return check_config(&conf);
    }

    run_proxy(&conf, Some(config_path), workers, force_epoll).await
}

/// `run --check`: refuses unknown config keys or any retiring-secret warning lines.
fn check_config(conf: &Config) -> Result<()> {
    let mut errors = Vec::new();
    if !conf.unknown_keys.is_empty() {
        errors.push(format!(
            "unknown config keys: {}",
            conf.unknown_keys.join(", ")
        ));
    }
    let report = conf.get_retiring_secrets(Utc::now());
    if !report.lines.is_empty() {
        errors.push(format!(
            "retiring-secret settings that run ignores or warns about:\n  {}",
            report.lines.join("\n  ")
        ));
    }
    if !errors.is_empty() {
        bail!("{}", errors.join("\n"));
    }
    Ok(())
}

/// `simple-run <bind-to> <secret> ...`.
pub async fn execute_simple_run(args: SimpleRunArgs) -> Result<()> {
    let mut conf = Config::default();

    let hp = HostPort::parse(&args.bind_to)
        .map_err(|e| anyhow::anyhow!("incorrect bind-to parameter: {e}"))?;
    conf.bind_to = vec![hp];

    let secret =
        Secret::parse(&args.secret).map_err(|e| anyhow::anyhow!("incorrect secret: {e}"))?;
    conf.secret = Some(secret);

    conf.concurrency = Some(args.concurrency);
    conf.prefer_ip = Some(
        args.prefer_ip
            .parse::<PreferIp>()
            .map_err(|e| anyhow::anyhow!("incorrect prefer-ip: {e}"))?,
    );
    conf.domain_fronting.port = Some(args.domain_fronting_port);
    conf.domain_fronting.host = args.domain_fronting_host;
    if let Some(df_ip) = args.domain_fronting_ip {
        conf.domain_fronting_ip = Some(
            df_ip
                .parse()
                .map_err(|e| anyhow::anyhow!("incorrect domain-fronting-ip: {e}"))?,
        );
    }
    conf.network.doh_ip = Some(args.doh_ip);

    let timeout =
        parse_duration(&args.timeout).map_err(|e| anyhow::anyhow!("incorrect timeout: {e}"))?;
    conf.network.timeout.tcp = Some(timeout);
    conf.network.timeout.http = Some(timeout);
    conf.network.timeout.idle = Some(timeout);

    let cache_bytes = parse_bytes_str(&args.antireplay_cache_size)
        .map_err(|e| anyhow::anyhow!("incorrect antireplay-cache-size: {e}"))?;
    conf.defense.anti_replay.enabled = Some(true);
    conf.defense.anti_replay.max_size = Some(cache_bytes);

    if !args.socks5_proxies.is_empty() {
        conf.network.proxies = Some(args.socks5_proxies);
    }

    conf.debug = Some(args.debug);
    conf.allow_fallback_on_unknown_dc = Some(true);
    conf.proxy_protocol_listener = Some(args.proxy_protocol_listener);

    conf.validate().context("invalid result configuration")?;

    run_proxy(&conf, None, args.workers, args.epoll).await
}

/// Core proxy runner shared by `run` and `simple-run`.
async fn run_proxy(
    conf: &Config,
    config_path: Option<&Path>,
    workers: usize,
    force_epoll: bool,
) -> Result<()> {
    init_logging(conf.debug.unwrap_or(false));

    // Raise Linux RLIMIT_NOFILE automatically before binding sockets!
    if let Ok((cur, max)) = mtg_net::raise_nofile_limit(1_048_576) {
        info!(
            nofile_soft = cur,
            nofile_hard = max,
            version = VERSION,
            "starting mtg-proxy"
        );
    }

    if !conf.unknown_keys.is_empty() {
        for w in conf.unknown_key_warnings() {
            warn!("{w}");
        }
    }
    if conf.domain_fronting_ip.is_some() {
        warn!("domain-fronting-ip is deprecated and ignored; use [domain-fronting] host instead");
    }

    let engine = ProxyEngine::from_config(
        conf,
        config_path.map(Path::to_path_buf),
        workers,
        force_epoll,
    )
    .context("cannot initialize proxy engine")?;

    // Warn about retiring-secret issues at startup (matching Go behavior).
    let ret_report = conf.get_retiring_secrets(Utc::now());
    for line in &ret_report.lines {
        warn!("retiring-secret: {line}");
    }

    // Warn about unserved dd/plain secrets when no matching [[listener]] exists.
    {
        let set = engine.secrets.load();
        for (name, rec) in &set.records {
            if !mtg_engine::is_secret_served(&rec.secret, engine.listener_modes) {
                warn!(
                    secret = %name,
                    mode = %rec.secret.mode(),
                    "secret has no matching [[listener]] and cannot be reached directly"
                );
            }
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Start pinned thread-per-core data-plane runtime (also spawns background maintenance loops once)
    let runtime = EngineRuntime::start(Arc::clone(&engine))
        .await
        .context("cannot start proxy listeners")?;

    // 2. Optional Management HTTP API
    let mut aux_tasks = Vec::new();
    if let Some(bind) = &engine.settings.api_bind_to {
        let (_, handle) = spawn_api_server(
            Arc::clone(&engine),
            bind,
            &engine.settings.api_token,
            shutdown_rx.clone(),
        )
        .await
        .with_context(|| format!("cannot start management API on {bind}"))?;
        aux_tasks.push(handle);
    }

    // 4. Optional Prometheus HTTP exporter
    if conf.stats.prometheus.enabled.unwrap_or(false) {
        let bind = conf
            .stats
            .prometheus
            .bind_to
            .as_ref()
            .map_or("127.0.0.1:3129", HostPort::as_str);
        let path = conf.stats.prometheus.http_path.as_deref().unwrap_or("/");
        let prefix = conf
            .stats
            .prometheus
            .metric_prefix
            .as_deref()
            .unwrap_or("mtg");
        let (_, handle) =
            spawn_prometheus_server(Arc::clone(&engine), bind, path, prefix, shutdown_rx.clone())
                .await
                .with_context(|| format!("cannot start Prometheus server on {bind}"))?;
        aux_tasks.push(handle);
    }

    // 5. Optional StatsD UDP exporter
    if conf.stats.statsd.enabled.unwrap_or(false)
        && let Some(addr) = &conf.stats.statsd.address
    {
        let prefix = conf
            .stats
            .statsd
            .metric_prefix
            .as_deref()
            .unwrap_or("mtg")
            .to_owned();
        let format = conf.stats.statsd.tag_format.unwrap_or_default();
        spawn_statsd_exporter(
            &engine,
            addr.as_str().to_owned(),
            prefix,
            format,
            shutdown_rx.clone(),
        );
    }

    // 6. Signal loop: SIGHUP -> live atomic reload; SIGINT / SIGTERM -> graceful shutdown!
    let mut sighup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                if engine.settings.config_path.is_some() {
                    match engine.reload_from_disk() {
                        Ok(warnings) => {
                            info!("reloaded secrets via SIGHUP");
                            for w in warnings {
                                warn!("retiring-secret: {w}");
                            }
                            engine.trigger_ip_filter_refresh();
                        }
                        Err(e) => {
                            warn!(error = %e, "SIGHUP reload failed; keeping active secret set");
                        }
                    }
                } else {
                    warn!("SIGHUP ignored: proxy started without a config file");
                }
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM; shutting down gracefully");
                break;
            }
            _ = sigint.recv() => {
                info!("received SIGINT; shutting down gracefully");
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);
    engine.begin_shutdown();
    runtime.shutdown();

    for task in aux_tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    if let Some(usage_path) = &engine.settings.usage_state_file
        && let Err(e) = engine.metrics.flush_usage_atomic(usage_path)
    {
        warn!(path = %usage_path.display(), error = %e, "final usage.json flush failed");
    }

    Ok(())
}
