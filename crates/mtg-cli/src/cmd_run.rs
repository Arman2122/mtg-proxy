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
use mtg_config::{
    ClientIpSource, Config, HostPort, ListenerPolicy, PreferIp, UnknownSecretAction,
    parse_bytes_str, parse_duration,
};
use mtg_core::{ModeSet, Secret, SecretMode};
use mtg_engine::{EngineRuntime, FrontingRuntimeConfig, ProxyEngine};
use mtg_webrelay::{
    Origin, RelayCounters, ReloadableTlsAcceptor, SharedGeoFilters, build_origin_with_overrides,
    spawn_origin_server, spawn_stats_server, spawn_tls_origin_server,
};
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
    if conf.web.enabled.unwrap_or(false) && conf.web.integrated.unwrap_or(false) {
        if let Err(e) = conf.validate_web() {
            errors.push(format!("integrated [web] configuration error: {e}"));
        } else if let (Some(cert), Some(key)) = (&conf.web.tls_cert, &conf.web.tls_key)
            && let Err(e) = ReloadableTlsAcceptor::load(Path::new(cert), Path::new(key))
        {
            errors.push(format!("integrated [web] TLS error: {e}"));
        }
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

    let integrated_web = conf.web.enabled.unwrap_or(false) && conf.web.integrated.unwrap_or(false);
    if integrated_web {
        conf.validate_web()
            .context("invalid integrated [web] configuration")?;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Start pinned thread-per-core data-plane runtime (auto-binding an internal
    //    loopback `dd` backend when `[web] integrated = true` omits `[web] backend`!)
    let mut extra_obfs = Vec::new();
    let auto_internal_dd = integrated_web && conf.web.backend.is_none();
    if auto_internal_dd {
        extra_obfs.push((
            "127.0.0.1:0".to_owned(),
            ListenerPolicy {
                modes: ModeSet::of(&[SecretMode::Dd]),
                public: false,
                proxy_protocol: true,
                on_unknown_secret: UnknownSecretAction::Close,
                handshakes_per_ip: 0,
            },
        ));
    }

    let runtime = EngineRuntime::start_with_extra_obfs_listeners(Arc::clone(&engine), &extra_obfs)
        .await
        .context("cannot start proxy listeners")?;

    let mut aux_tasks = Vec::new();

    // 2. Optional embedded `[web] integrated = true` WEB proxy + cover site
    //    (shares ProxyEngine's secrets, accounting, Geo-Stealth allowlist/blocklist,
    //    and optionally terminates TLS in-process for all-in-one single-port `:443`!)
    let mut web_origin: Option<Arc<Origin>> = None;
    let mut web_tls_acceptor: Option<ReloadableTlsAcceptor> = None;
    if integrated_web {
        let backend_override = if auto_internal_dd {
            Some(
                *runtime
                    .bound_obfs2_addrs
                    .last()
                    .expect("auto-bound internal dd backend"),
            )
        } else {
            None
        };
        let has_tls = conf.web.tls_cert.is_some() && conf.web.tls_key.is_some();
        let auto_front_tls = has_tls && conf.web.bind_to.is_none();
        let client_ip_override = if auto_front_tls
            || (has_tls
                && conf.web.client_ip.is_none()
                && conf.web.bind_to.as_ref().is_some_and(|b| !b.is_loopback()))
        {
            Some(ClientIpSource::ProxyProtocol)
        } else {
            None
        };

        let ipf = engine.ip_filters.load_full();
        let web_counters = Arc::new(RelayCounters::new(Utc::now()));
        let origin = build_origin_with_overrides(
            conf,
            Arc::clone(&web_counters),
            backend_override,
            client_ip_override,
            Some(SharedGeoFilters {
                allowlist: ipf.allowlist.clone(),
                allowlist_action: ipf.allowlist_action,
                blocklist: ipf.blocklist.clone(),
                blocklist_action: ipf.blocklist_action,
            }),
        )
        .await
        .context("cannot initialize integrated [web] relay")?;

        origin.spawn_trusted_proxies_refresh_loop(shutdown_rx.clone());

        // Real-time zero-delay sync of secrets, retired keys, AND hot-reloaded
        // Geo-Stealth IP filters from ProxyEngine into the integrated WEB Origin!
        {
            let eng_sync = Arc::clone(&engine);
            let origin_sync = Arc::clone(&origin);
            let counters_sync = Arc::clone(&web_counters);
            let mut secret_rx = engine.subscribe_secret_changes();
            let mut sd = shutdown_rx.clone();
            aux_tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sd.changed() => {
                            if *sd.borrow() {
                                break;
                            }
                        }
                        res = secret_rx.changed() => {
                            if res.is_err() {
                                break;
                            }
                            sync_engine_to_web_origin(&eng_sync, &origin_sync, &counters_sync);
                        }
                    }
                }
            }));
        }

        if let (Some(cert), Some(key)) = (&conf.web.tls_cert, &conf.web.tls_key) {
            let acc = ReloadableTlsAcceptor::load(Path::new(cert), Path::new(key))
                .context("cannot load integrated [web] TLS certificate/key")?;
            let (bind_str, require_pp, should_auto_front) = match &conf.web.bind_to {
                None => (
                    "127.0.0.1:0",
                    true,
                    conf.get_domain_fronting_host().is_empty(),
                ),
                Some(hp) => {
                    let pp = conf.web.client_ip == Some(ClientIpSource::ProxyProtocol);
                    (
                        hp.as_str(),
                        pp,
                        conf.get_domain_fronting_host().is_empty() && hp.is_loopback(),
                    )
                }
            };
            let (tls_addr, handle) = spawn_tls_origin_server(
                Arc::clone(&origin),
                bind_str,
                require_pp,
                acc.clone(),
                shutdown_rx.clone(),
            )
            .await
            .with_context(|| format!("cannot start integrated [web] TLS listener on {bind_str}"))?;
            if should_auto_front {
                engine.set_fronting_config(FrontingRuntimeConfig {
                    host: tls_addr.ip().to_string(),
                    port: tls_addr.port(),
                    proxy_protocol: require_pp,
                });
                info!(
                    %tls_addr,
                    host = conf.web.host.as_deref().unwrap_or(""),
                    "integrated single-port HTTPS WEB relay & cover site auto-wired to primary bind-to"
                );
            } else {
                info!(
                    %tls_addr,
                    host = conf.web.host.as_deref().unwrap_or(""),
                    "integrated [web] HTTPS relay listening"
                );
            }
            aux_tasks.push(handle);
            web_tls_acceptor = Some(acc);
        } else if let Some(bind) = &conf.web.bind_to {
            let require_pp = conf.web.client_ip == Some(ClientIpSource::ProxyProtocol);
            let (web_addr, handle) = spawn_origin_server(
                Arc::clone(&origin),
                bind.as_str(),
                require_pp,
                shutdown_rx.clone(),
            )
            .await
            .with_context(|| format!("cannot start integrated [web] listener on {bind}"))?;
            info!(
                %web_addr,
                host = conf.web.host.as_deref().unwrap_or(""),
                "integrated [web] HTTP relay listening"
            );
            aux_tasks.push(handle);
        }

        if let Some(sb) = &conf.web.stats_bind_to {
            let (sa, sh) = spawn_stats_server(
                Arc::clone(&web_counters),
                Arc::clone(origin.store()),
                sb.as_str(),
                shutdown_rx.clone(),
            )
            .await
            .with_context(|| format!("cannot start integrated [web] stats server on {sb}"))?;
            info!(stats_addr = %sa, "integrated [web] stats endpoint listening");
            aux_tasks.push(sh);
        }

        web_origin = Some(origin);
    }

    // 3. Optional Management HTTP API
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

    // 6. Signal loop: SIGHUP -> full async live atomic reload; SIGINT / SIGTERM -> graceful shutdown!
    let mut sighup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                if engine.settings.config_path.is_some() {
                    match engine.reload_from_disk_async().await {
                        Ok(warnings) => {
                            info!("reloaded configuration via SIGHUP (secrets, limits, fronting & IP filters)");
                            for w in warnings {
                                warn!("retiring-secret: {w}");
                            }
                            if let Some(origin) = &web_origin {
                                origin.trigger_trusted_proxies_refresh();
                            }
                            if let (Some(acc), Some(cert), Some(key)) =
                                (&web_tls_acceptor, &conf.web.tls_cert, &conf.web.tls_key)
                            {
                                match acc.reload(Path::new(cert), Path::new(key)) {
                                    Ok(()) => info!(cert, "reloaded integrated [web] TLS certificate via SIGHUP"),
                                    Err(e) => warn!(error = %e, "SIGHUP integrated [web] TLS reload failed; keeping active cert"),
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "SIGHUP reload failed; keeping active configuration");
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

fn sync_engine_to_web_origin(engine: &ProxyEngine, origin: &Origin, counters: &RelayCounters) {
    let set = engine.secrets.load();
    let mut names = Vec::with_capacity(set.records.len());
    let mut secrets = Vec::with_capacity(set.records.len());
    let mut retired = Vec::new();
    for (k, rec) in &set.records {
        names.push(k.clone());
        secrets.push(rec.secret.clone());
        for r in &rec.retiring {
            retired.push(r.secret.clone());
        }
    }
    match origin.set_secrets_with_retired(&secrets, &retired) {
        Ok(()) => {
            counters.set_profiles(names);
            counters.on_reload(true);
        }
        Err(e) => {
            warn!(error = %e, "integrated [web] secret sync failed");
            counters.on_reload(false);
        }
    }
    let ipf = engine.ip_filters.load();
    origin.update_geo_filters(
        ipf.allowlist.clone(),
        ipf.allowlist_action,
        ipf.blocklist.clone(),
        ipf.blocklist_action,
    );
}
