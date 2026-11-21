//! `mtg-proxy doctor` — full Linux-native + Telegram DC RPC diagnostic suite!

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use chrono::Utc;
use mtg_config::{Config, IpFilterAction, PreferIp};
use mtg_crypto::aes_ctr::detect_aes_backend;
use mtg_crypto::obfs2::build_outbound_handshake;
use mtg_governance::LiveIpFilter;
use mtg_net::{
    DcRouter, DnsResolver, DriverKind, ProxyPool, SocketConfig, allowed_linux_cpus, probe_uring,
};
use mtg_protocol::dcprobe;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;

use crate::cmd_run::read_and_validate_config;

/// Execute `mtg-proxy doctor <config-path>`. Returns `Ok(true)` if all critical
/// checks passed, `Ok(false)` if any check failed (exit code 1).
pub async fn execute_doctor(config_path: &Path, skip_native_check: bool) -> Result<bool> {
    let conf = read_and_validate_config(config_path)?;
    let mut all_ok = true;

    // 1. Config unknown keys & retiring-secret warnings
    println!("Checking configuration...");
    if conf.unknown_keys.is_empty() {
        println!("  ✅ Every key in the file is known to this binary");
    } else {
        for w in conf.unknown_key_warnings() {
            println!("  ⚠️  {w}");
        }
    }
    let ret = conf.get_retiring_secrets(Utc::now());
    if ret.lines.is_empty() {
        println!("  ✅ No retiring-secret issues");
    } else {
        for line in &ret.lines {
            println!("  ⚠️  retiring-secret: {line}");
        }
    }
    if conf.domain_fronting_ip.is_some() {
        println!(
            "  ⚠️  Option \"domain-fronting-ip\" is deprecated. Please use \"host\" in [domain-fronting] section instead."
        );
    }
    let obfs_mux = conf.get_bind_to_obfs_modes();
    if !obfs_mux.is_empty() {
        println!(
            "  ✅ Single-port multi-transport enabled on bind-to: ee + {:?}",
            obfs_mux.sorted_names()
        );
    }

    // 2. Linux kernel, CPU affinity & hardware crypto capability probe
    println!("Checking Linux kernel & CPU capabilities...");
    let allowed_cpus = allowed_linux_cpus();
    println!(
        "  ✅ CPU affinity: {} permitted core(s) (arch={}, aes={:?}, sha={})",
        allowed_cpus.len(),
        std::env::consts::ARCH,
        detect_aes_backend(),
        detect_sha_label()
    );
    if let Ok(caps) = probe_uring()
        && caps.kind == Some(DriverKind::IoUring)
    {
        println!(
            "  ✅ io_uring kernel probe passed (single_issuer={}, defer_taskrun={}, multishot_accept={}, buf_ring={}, send_zc={}, splice={})",
            caps.single_issuer,
            caps.defer_taskrun,
            caps.accept_multishot,
            caps.buf_ring,
            caps.send_zc,
            caps.splice
        );
    } else {
        println!(
            "  ✅ Data plane uses pinned per-core epoll(7) + splice(2) (io_uring probe unavailable in this kernel/sandbox)"
        );
    }
    check_linux_sysctls();

    // 3. NTP clock skew check vs `tolerate-time-skewness`
    println!("Checking clock drift (SNTP)...");
    let skew_limit = conf
        .tolerate_time_skewness
        .unwrap_or(Duration::from_secs(5));
    match query_sntp_offset("0.pool.ntp.org:123").await {
        Ok(drift) => {
            let abs_ms = drift.unsigned_abs().as_millis();
            let limit_ms = skew_limit.as_millis();
            if abs_ms <= limit_ms / 2 {
                println!("  ✅ Time drift is {abs_ms}ms, tolerate-time-skewness is {limit_ms}ms");
            } else if abs_ms <= limit_ms {
                println!(
                    "  ⚠️  Time drift is {abs_ms}ms, tolerate-time-skewness is {limit_ms}ms. Please check NTP."
                );
            } else {
                println!(
                    "  ❌ Time drift is {abs_ms}ms, exceeds tolerate-time-skewness {limit_ms}ms!"
                );
                all_ok = false;
            }
        }
        Err(e) => {
            println!("  ⚠️  Cannot query NTP offset: {e}");
        }
    }

    let prefer_ip = conf.prefer_ip.unwrap_or(PreferIp::PreferIpv6);
    let dns = std::sync::Arc::new(DnsResolver::build(
        conf.network.dns.as_deref(),
        conf.network.doh_ip,
        prefer_ip,
    )?);
    let sock_cfg = SocketConfig::default();
    let proxy_pool = conf
        .network
        .proxies
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|urls| ProxyPool::from_urls(urls, sock_cfg, Duration::from_secs(10)))
        .transpose()?;

    // 4. Domain fronting origin reachability + SNI self-pointing loop guard
    println!("Checking domain fronting...");
    let integrated_tls_cover = conf.web.enabled.unwrap_or(false)
        && conf.web.integrated.unwrap_or(false)
        && conf.web.tls_cert.is_some()
        && conf.web.tls_key.is_some()
        && conf.get_domain_fronting_host().is_empty();
    let fronting_host = resolve_fronting_host(&conf);
    let fronting_port = conf.get_domain_fronting_port(443);
    if integrated_tls_cover {
        println!(
            "  ✅ Domain fronting auto-wired to in-process integrated [web] TLS cover origin (PROXY v2)"
        );
    } else if !fronting_host.is_empty() {
        let addr_label = format!("{fronting_host}:{fronting_port}");
        match check_tcp_reachable(&dns, &fronting_host, fronting_port, Duration::from_secs(5)).await
        {
            Ok((rtt, resolved_ips)) => {
                println!("  ✅ {addr_label} is reachable ({}ms)", rtt.as_millis());
                let self_v4 = conf.public_ipv4;
                let self_v6 = conf.public_ipv6;
                let points_to_self = resolved_ips.iter().any(|ip| {
                    self_v4.is_some_and(|v4| *ip == v4) || self_v6.is_some_and(|v6| *ip == v6)
                });
                if points_to_self {
                    println!(
                        "  ⚠️  Fronting host {fronting_host:?} resolves to this server's own public IP — active probes may loop back to mtg-proxy!"
                    );
                }
            }
            Err(e) => {
                println!("  ❌ {addr_label}: {e}");
                all_ok = false;
            }
        }
    }

    // 4c. Optional [web] relay, in-process TLS & CDN trusted-proxy diagnostics
    if conf.web.enabled.unwrap_or(false) {
        println!("Checking [web] relay configuration...");
        match conf.validate_web() {
            Ok(()) => {
                let mode = if conf.web.integrated.unwrap_or(false) {
                    "integrated"
                } else {
                    "standalone"
                };
                println!(
                    "  ✅ [web] schema valid (mode={mode}, host={})",
                    conf.web.host.as_deref().unwrap_or("")
                );
                if let Err(e) = mtg_webrelay::Signer::load_file(Path::new(&conf.web.token_key)) {
                    println!("  ❌ [web] token-key {}: {e}", conf.web.token_key);
                    all_ok = false;
                } else {
                    println!("  ✅ [web] token-key readable");
                }
                if !conf.web.cover_dir.is_empty() {
                    if let Err(e) = mtg_webrelay::StaticCover::new(&conf.web.cover_dir) {
                        println!("  ❌ [web] cover-dir {}: {e}", conf.web.cover_dir);
                        all_ok = false;
                    } else {
                        println!("  ✅ [web] cover-dir usable ({})", conf.web.cover_dir);
                    }
                }
                if let (Some(cert), Some(key)) = (&conf.web.tls_cert, &conf.web.tls_key) {
                    if let Err(e) =
                        mtg_webrelay::ReloadableTlsAcceptor::load(Path::new(cert), Path::new(key))
                    {
                        println!("  ❌ [web] TLS cert/key load failed: {e}");
                        all_ok = false;
                    } else {
                        println!("  ✅ [web] in-process TLS cert/key valid ({cert})");
                    }
                }
                if conf.web.cdn.is_some()
                    || conf
                        .web
                        .trusted_proxies
                        .as_ref()
                        .is_some_and(|v| !v.is_empty())
                    || conf
                        .web
                        .trusted_proxy_urls
                        .as_ref()
                        .is_some_and(|v| !v.is_empty())
                {
                    let start = Instant::now();
                    match mtg_webrelay::build_ip_filters_from_config(
                        &conf,
                        Some(mtg_webrelay::SharedGeoFilters {
                            allowlist: None,
                            allowlist_action: IpFilterAction::Front,
                            blocklist: None,
                            blocklist_action: IpFilterAction::Close,
                        }),
                    )
                    .await
                    {
                        Ok(filters) => {
                            if let Some(tp) = filters.trusted_proxies {
                                println!(
                                    "  ✅ [web] CDN trusted-proxies loaded {} CIDRs ({} IPv4, {} IPv6) in {}ms (header={})",
                                    tp.len(),
                                    tp.v4_len(),
                                    tp.v6_len(),
                                    start.elapsed().as_millis(),
                                    filters
                                        .client_ip_header
                                        .as_deref()
                                        .unwrap_or("x-forwarded-for")
                                );
                            }
                        }
                        Err(e) => {
                            println!("  ❌ [web] CDN trusted-proxies load failed: {e}");
                            all_ok = false;
                        }
                    }
                }
            }
            Err(e) => {
                println!("  ❌ [web] validation failed: {e}");
                all_ok = false;
            }
        }
    }

    // 4b. IP allowlist / blocklist (Geo-Stealth) live feed check
    if conf.defense.allowlist.enabled.unwrap_or(false)
        || conf.defense.blocklist.enabled.unwrap_or(false)
    {
        println!("Checking IP filters (allowlist / blocklist)...");
        for (label, list, default_action) in [
            ("allowlist", &conf.defense.allowlist, IpFilterAction::Front),
            ("blocklist", &conf.defense.blocklist, IpFilterAction::Close),
        ] {
            if !list.enabled.unwrap_or(false) {
                continue;
            }
            let action = list.action.unwrap_or(default_action);
            let live = LiveIpFilter::from_list_config(
                list,
                Some(std::sync::Arc::clone(&dns)),
                prefer_ip,
                proxy_pool.clone(),
                sock_cfg,
            );
            let start = Instant::now();
            match live.init_load().await {
                Ok(n) if n > 0 => {
                    println!(
                        "  ✅ {label}: loaded {n} entries ({} IPv4, {} IPv6) in {}ms (action={action})",
                        live.v4_len(),
                        live.v6_len(),
                        start.elapsed().as_millis()
                    );
                }
                Ok(_) => {
                    println!(
                        "  ⚠️  {label}: enabled (action={action}) but loaded 0 entries — check urls/cidrs!"
                    );
                }
                Err(e) => {
                    println!("  ❌ {label}: load failed ({e})");
                    all_ok = false;
                }
            }
        }
    }

    // 5. Real Telegram DC RPC connectivity (`dcprobe` over obfuscated2!)
    if !skip_native_check {
        println!("Checking Telegram DC connectivity (RPC req_pq_multi)...");
        let router = DcRouter::new(
            prefer_ip,
            conf.allow_fallback_on_unknown_dc.unwrap_or(true),
            sock_cfg,
            Duration::from_secs(10),
            proxy_pool,
        )
        .with_dns(dns);
        let _ = router.refresh_once().await;

        let mut any_dc_ok = false;
        for dc in 1..=5 {
            match probe_dc(&router, dc, Duration::from_secs(5)).await {
                Ok(rtt) => {
                    println!("  ✅ DC {dc} (rpc {}ms)", rtt.as_millis());
                    any_dc_ok = true;
                }
                Err(e) => {
                    println!("  ❌ DC {dc}: {e}");
                }
            }
        }
        if !any_dc_ok {
            all_ok = false;
        }
    }

    Ok(all_ok)
}

fn detect_sha_label() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            return "SHA-NI (4-way interleaved)";
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return "AVX2 (8-way multi-buffer)";
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            return "ARMv8 SHA-256";
        }
    }
    "Portable"
}

fn check_linux_sysctls() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid `rlimit` struct pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) };
    if rc == 0 {
        if lim.rlim_cur >= 65_536 {
            println!(
                "  ✅ RLIMIT_NOFILE soft={} hard={}",
                lim.rlim_cur, lim.rlim_max
            );
        } else {
            println!(
                "  ⚠️  RLIMIT_NOFILE soft={} hard={} (recommend >= 65536 for high concurrency)",
                lim.rlim_cur, lim.rlim_max
            );
        }
    }
    if let Ok(cc) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control") {
        println!("  ✅ TCP congestion control: {}", cc.trim());
    }
}

fn resolve_fronting_host(conf: &Config) -> String {
    let explicit = conf.get_domain_fronting_host();
    if !explicit.is_empty() {
        return explicit.to_owned();
    }
    for s in conf.get_secrets().values() {
        if s.is_hosted() {
            return s.host().to_owned();
        }
    }
    String::new()
}

async fn check_tcp_reachable(
    dns: &DnsResolver,
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::io::Result<(Duration, Vec<IpAddr>)> {
    let start = Instant::now();
    let ips: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        dns.resolve_ips(host).await?
    };
    let mut last_err = std::io::Error::other("no addresses resolved");
    for &ip in &ips {
        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return Ok((start.elapsed(), ips)),
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"),
        }
    }
    Err(last_err)
}

async fn probe_dc(router: &DcRouter, dc: i32, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let (mut stream, _, effective_dc) = tokio::time::timeout(timeout, router.dial_direct(dc))
        .await
        .map_err(|_| anyhow::anyhow!("dial timeout"))??;

    let (frame, mut ciphers) = build_outbound_handshake(
        effective_dc as i16,
        mtg_core::ConnectionTag::PADDED_INTERMEDIATE,
        None,
    );
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let mut req = dcprobe::build_req_pq_multi_frame_now(&nonce);
    ciphers.send.apply_keystream(&mut req);

    tokio::time::timeout(timeout, async {
        stream.write_all(&frame).await?;
        stream.write_all(&req).await?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        ciphers.recv.apply_keystream(&mut len_buf);
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        dcprobe::validate_res_pq_len(resp_len)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        ciphers.recv.apply_keystream(&mut resp);
        dcprobe::verify_res_pq_payload(&resp, &nonce)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    })
    .await
    .map_err(|_| anyhow::anyhow!("RPC probe timeout"))??;

    Ok(start.elapsed())
}

/// Minimal RFC 4330 SNTPv4 client (48-byte UDP packet) returning signed clock offset.
async fn query_sntp_offset(server: &str) -> std::io::Result<SignedDuration> {
    const NTP_UNIX_DELTA: u64 = 2_208_988_800;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(server).await?;

    let mut req = [0u8; 48];
    req[0] = 0x23; // LI=0, VN=4, Mode=3 (Client)
    let t1 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    sock.send(&req).await?;

    let mut resp = [0u8; 48];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut resp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "NTP timeout"))??;
    let t4 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if n < 48 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "short NTP packet",
        ));
    }

    let tx_secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]);
    let tx_frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]);
    let server_unix_secs = u64::from(tx_secs).saturating_sub(NTP_UNIX_DELTA);
    let server_nanos = (u64::from(tx_frac) * 1_000_000_000) >> 32;
    let server_ns = i128::from(server_unix_secs) * 1_000_000_000 + i128::from(server_nanos);

    let local_mid_ns = i128::midpoint(t1.as_nanos() as i128, t4.as_nanos() as i128);
    let offset_ns = server_ns - local_mid_ns;
    Ok(SignedDuration(offset_ns))
}

struct SignedDuration(i128);

impl SignedDuration {
    fn unsigned_abs(&self) -> Duration {
        let abs = self.0.unsigned_abs();
        Duration::from_nanos(u64::try_from(abs).unwrap_or(u64::MAX))
    }
}
