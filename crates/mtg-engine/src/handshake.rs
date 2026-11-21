//! FakeTLS (`ee`) and Obfuscated2 (`dd`/`plain`) connection entry doors.
//!
//! Implements the exact security & stealth pipeline:
//! - Optional PROXY protocol v1/v2 parsing (preserving real client IP)
//! - Wait-free blocklist / allowlist filtering
//! - FakeTLS door: incremental `ClientHello` parse -> `MatchHints` -> SNI-first
//!   bucket -> budgeted hardware-accelerated candidate scan (4-way SHA-NI /
//!   8-way AVX2 / ARMv8 SHA-256, `enforce`/`observe`/`off`) -> timestamp
//!   skewness + `RotationClock` check -> lock-free anti-replay -> atomic
//!   governance admission -> zero-alloc thread-local `ServerHello` + CCS +
//!   AppData -> TLS unframe -> Obfuscated2 DC decode -> MiddleProxy or direct
//!   DC dial -> single-poll full-duplex fused-CTR relay!
//! - Any FakeTLS failure (unmatched, over-budget, replay, disabled, expired,
//!   quota exceeded, banned, ip-limit, client-conns) transparently domain-fronts
//!   the verbatim raw ClientHello bytes to the cover website via Linux `splice(2)`!
//! - Obfuscated2 `[[listener]]` door: public per-IP failure limiter (still reads
//!   full 64B frame so rate-limiting is indistinguishable!) -> zero-alloc
//!   `obfs2::match_handshake` -> lock-free SBF anti-replay -> governance gate ->
//!   indistinguishable `close` or bounded `drain` on denial!
//!
//! # Memory Architecture
//! The entire short-lived handshake, fronting, and MiddleProxy branch runs
//! inside a single short-lived `Box::pin(...)` future that is dropped and
//! returned to jemalloc's thread-local cache the instant a direct connection
//! enters steady-state [`relay_direct`]. Long-lived idle connections therefore
//! carry ZERO handshake buffers, ZERO `ParsedClientHello` state, ZERO fronting
//! state, and ZERO `MiddleStream` state in their Tokio task frame!

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mtg_config::{ListenerPolicy, UnknownSecretAction};
use mtg_core::{ConnectionTag, TagSet};
use mtg_crypto::faketls::{
    FakeTlsCandidate, ParseStatus, ParsedClientHello, build_server_hello,
    parse_client_hello_incremental,
};
use mtg_crypto::obfs2::{HANDSHAKE_FRAME_LEN, build_outbound_handshake, match_handshake};
use mtg_governance::{BudgetVerdict, MAX_HINT_POSITIONS};
use mtg_net::{MiddleStreamParams, coarse_realtime_ns};
use mtg_protocol::doppel::{DoppelConnState, DoppelParams};
use mtg_protocol::proxyproto::{ProxyParseStatus, ProxyProtoMode, parse_proxy_header};
use mtg_protocol::tls_record::TlsUnframer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::debug;

use crate::cancel::CancelToken;
use crate::fronting::{FrontingTarget, front_connection};
use crate::relay::{DirectRelay, RelayContext, relay_middleproxy};
use crate::state::{IpFilterVerdict, ProxyEngine, peer_ip_of};

thread_local! {
    /// Per-worker reusable FakeTLS ServerHello + CCS + AppData staging buffer.
    /// Eliminates the ~16.6 KiB heap allocation on every FakeTLS handshake!
    static HS_SH_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(16_640));
}

/// Handshake result handed from the short-lived boxed handshake phase to the
/// compact steady-state [`DirectRelay::run`] loop.
struct EstablishedDirectRelay {
    relay: DirectRelay,
    _active_guard: ActiveConnGuard,
    _release_guard: ReleaseConnGuard,
}

/// Handle one accepted connection on the primary FakeTLS (`ee`) `bind-to` door.
pub async fn handle_faketls_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    worker_id: u16,
    engine: Arc<ProxyEngine>,
) {
    let core_metrics = engine.metrics.core(usize::from(worker_id));
    core_metrics.accepted_total.fetch_add(1, Ordering::Relaxed);

    // Concurrency cap
    if engine.settings.concurrency > 0
        && engine.metrics.total_active_connections() >= i64::from(engine.settings.concurrency)
    {
        core_metrics
            .concurrency_limited
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Box the short-lived handshake / fronting / MiddleProxy phase so its state
    // machine is completely freed before entering steady-state direct relay!
    if let Some(mut conn) = Box::pin(faketls_handshake_and_dial(
        stream, peer_addr, local_addr, worker_id, engine,
    ))
    .await
    {
        conn.relay.run().await;
    }
}

/// Handle one accepted connection on a non-FakeTLS (`dd` / `plain`) `[[listener]]`.
pub async fn handle_obfs2_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    policy: ListenerPolicy,
    worker_id: u16,
    engine: Arc<ProxyEngine>,
) {
    let core_metrics = engine.metrics.core(usize::from(worker_id));
    core_metrics.accepted_total.fetch_add(1, Ordering::Relaxed);

    if engine.settings.concurrency > 0
        && engine.metrics.total_active_connections() >= i64::from(engine.settings.concurrency)
    {
        core_metrics
            .concurrency_limited
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    if let Some(mut conn) = Box::pin(obfs2_handshake_and_dial(
        stream, peer_addr, policy, worker_id, engine,
    ))
    .await
    {
        conn.relay.run().await;
    }
}

async fn faketls_handshake_and_dial(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    worker_id: u16,
    engine: Arc<ProxyEngine>,
) -> Option<EstablishedDirectRelay> {
    let mut client_addr = peer_addr;
    let mut dst_addr = local_addr;
    let mut raw_buf = Vec::with_capacity(1024);

    // 1. Optional PROXY protocol v1/v2 header
    if engine.settings.proxy_protocol_listener {
        match read_proxy_header(&mut stream, &mut raw_buf, engine.settings.handshake_timeout).await
        {
            Ok(Some((src, dst))) => {
                client_addr = src;
                dst_addr = dst;
            }
            Ok(None) => {}
            Err(()) => return None,
        }
    }

    let client_ip = peer_ip_of(client_addr);
    let is_v4 = client_ip.is_ipv4();
    let core_metrics = engine.metrics.core(usize::from(worker_id));
    if is_v4 {
        core_metrics.active_conns_v4.fetch_add(1, Ordering::Relaxed);
    } else {
        core_metrics.active_conns_v6.fetch_add(1, Ordering::Relaxed);
    }
    let active_guard = ActiveConnGuard {
        engine: Arc::clone(&engine),
        worker_id,
        is_v4,
    };

    // 2. Wait-free IP blocklist / allowlist check (0 ns when disabled!)
    //    - `Close`: drop immediately (default for explicit blocklists)
    //    - `Front`: Geo-Stealth cover-only mode (default for allowlists):
    //      * Single/fixed cover -> ZERO ClientHello parse, ZERO HMAC CPU, instant
    //        zero-copy kernel `splice(2)` from byte 0 straight to the cover website!
    //      * Multi-domain public covers -> SNI-only ClientHello peek (ZERO HMAC CPU,
    //        ZERO secret authentication!) so the prober gets the exact matching cert!
    let filter_verdict = engine.check_ip_filters(client_ip, usize::from(worker_id));
    match filter_verdict {
        IpFilterVerdict::Close => return None,
        IpFilterVerdict::Front if engine.has_fixed_fronting_host() => {
            let hosts = engine.fronting_hosts_for(&[]);
            do_front(
                stream,
                client_addr,
                dst_addr,
                &raw_buf,
                hosts,
                worker_id,
                &engine,
            )
            .await;
            return None;
        }
        IpFilterVerdict::Front | IpFilterVerdict::Allow => {}
    }

    // 3. Single-port multi-transport demux (`ee` + `dd`/`plain` + Cover/WEB on ONE port!).
    //    When `bind-to-accept` includes `dd`/`plain` AND this IP is allowed, peek the first
    //    bytes to distinguish TLS (`0x16 0x03 0x00..=0x04`) from plaintext HTTP and raw
    //    64-byte Obfuscated2 handshakes — preserving verbatim bytes for fronting on any miss!
    let obfs_modes = engine.settings.bind_to_obfs_modes;
    if filter_verdict == IpFilterVerdict::Allow && !obfs_modes.is_empty() {
        let peek_ok = read_at_least(
            &mut stream,
            &mut raw_buf,
            5,
            engine.settings.handshake_timeout,
        )
        .await;
        if !peek_ok {
            let hosts = engine.fronting_hosts_for(&[]);
            do_front(
                stream,
                client_addr,
                dst_addr,
                &raw_buf,
                hosts,
                worker_id,
                &engine,
            )
            .await;
            return None;
        }
        let looks_like_tls =
            raw_buf.len() >= 3 && raw_buf[0] == 0x16 && raw_buf[1] == 0x03 && raw_buf[2] <= 0x04;
        if !looks_like_tls {
            if !looks_like_plain_http(&raw_buf)
                && read_at_least(
                    &mut stream,
                    &mut raw_buf,
                    HANDSHAKE_FRAME_LEN,
                    engine.settings.handshake_timeout,
                )
                .await
            {
                return try_single_port_obfs2_or_front(
                    stream,
                    client_addr,
                    dst_addr,
                    client_ip,
                    raw_buf,
                    obfs_modes,
                    worker_id,
                    active_guard,
                    engine,
                )
                .await;
            }
            // Plain HTTP or short non-TLS probe -> transparently front verbatim to cover!
            let hosts = engine.fronting_hosts_for(&[]);
            do_front(
                stream,
                client_addr,
                dst_addr,
                &raw_buf,
                hosts,
                worker_id,
                &engine,
            )
            .await;
            return None;
        }
    }

    // 4. Incrementally read & parse FakeTLS ClientHello within handshake timeout
    let (parsed, mut hello_wire, mut post_hello_buf) = if let Ok((parsed, consumed)) =
        read_faketls_client_hello(&mut stream, &mut raw_buf, engine.settings.handshake_timeout)
            .await
    {
        // Keep raw ClientHello bytes verbatim for fronting if anything fails!
        let leftover = raw_buf.split_off(consumed);
        (parsed, raw_buf, leftover)
    } else {
        // Rare 1-in-16M edge case: an Obfuscated2 random 64-byte frame started with
        // `0x16 0x03 0x00..=0x04` (not `16 03 01 02`), failing TLS ClientHello parsing!
        if filter_verdict == IpFilterVerdict::Allow
            && !obfs_modes.is_empty()
            && read_at_least(
                &mut stream,
                &mut raw_buf,
                HANDSHAKE_FRAME_LEN,
                engine.settings.handshake_timeout,
            )
            .await
        {
            return try_single_port_obfs2_or_front(
                stream,
                client_addr,
                dst_addr,
                client_ip,
                raw_buf,
                obfs_modes,
                worker_id,
                active_guard,
                engine,
            )
            .await;
        }
        // Non-TLS / truncated / malformed probe -> front verbatim bytes!
        let hosts = engine.fronting_hosts_for(&[]);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &raw_buf,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    };

    // Multi-domain Geo-Stealth cover-only path: front using SNI without touching any secrets!
    if filter_verdict == IpFilterVerdict::Front {
        let hosts = engine.fronting_hosts_for(&parsed.sni_hostnames);
        hello_wire.extend_from_slice(&post_hello_buf);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &hello_wire,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    }

    // 4. Match secret: Hints -> SNI bucket -> Budgeted hardware SIMD/SHA-NI scan
    let matched = match_faketls_secret(&parsed, client_ip, &engine).await;
    let Some(m) = matched else {
        let hosts = engine.fronting_hosts_for(&parsed.sni_hostnames);
        hello_wire.extend_from_slice(&post_hello_buf);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &hello_wire,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    };

    // 5. Lock-free FakeTLS anti-replay check (replays front cleanly!)
    if engine
        .faketls_replay
        .seen_before(parsed.hello.session_id.as_slice())
    {
        core_metrics.replay_attacks.fetch_add(1, Ordering::Relaxed);
        let hosts = engine.fronting_hosts_for(&parsed.sni_hostnames);
        hello_wire.extend_from_slice(&post_hello_buf);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &hello_wire,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    }

    // 6. Atomic governance admission (disabled, expired, quota, throttle, ban, ip-limit, client-conns)
    let Ok((conn_handle, client_entry, cancel)) = engine.admit_connection(
        worker_id,
        &m.secret_name,
        m.key_bytes,
        m.retiring,
        Some(client_ip),
        &m.limits,
    ) else {
        let hosts = engine.fronting_hosts_for(&parsed.sni_hostnames);
        hello_wire.extend_from_slice(&post_hello_buf);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &hello_wire,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    };

    // Earned hint: record ONLY after full admission succeeded!
    engine.hints.remember(client_ip, Arc::clone(&m.secret_name));
    // Trigger throttled (<=1 per 2s) Zero-RTT cover pre-warm so reactive DPI
    // active probes arriving right after a user handshake see 0 ms connect RTT!
    engine.prewarm_fronting_cover(&parsed.sni_hostnames);

    let release_guard = ReleaseConnGuard {
        engine: Arc::clone(&engine),
        secret_name: Arc::clone(&m.secret_name),
        handle: conn_handle,
        entry: Arc::clone(&client_entry),
        retiring: m.retiring,
    };

    // 7. Build & send FakeTLS ServerHello + ChangeCipherSpec + AppData noise!
    // Uses per-SNI calibrated cover cert-flight size + thread-local `HS_SH_BUF`
    // + non-blocking `try_write` fast path -> ZERO heap allocations per handshake!
    let doppel_params = engine.doppel.params_for_sni(&parsed.sni_hostnames);
    let write_ok = send_server_hello_zero_alloc(
        &mut stream,
        &m.candidate,
        &parsed.hello,
        doppel_params.noise,
        &engine.x25519_keys,
        engine.settings.handshake_timeout,
    )
    .await;
    drop(hello_wire);
    drop(parsed);
    if !write_ok {
        return None;
    }

    // 8. Unframe TLS ApplicationData records until we have the 64-byte Obfuscated2 frame
    let Ok((obfs_frame, leftover_app, tls_unframer)) = read_faketls_obfs2_frame(
        &mut stream,
        &mut post_hello_buf,
        engine.settings.handshake_timeout,
    )
    .await
    else {
        return None;
    };
    drop(post_hello_buf);

    let Ok(obfs_match) = match_handshake(&obfs_frame, [Some(&m.key_bytes)], TagSet::all()) else {
        debug!(secret = %m.secret_name, "inner FakeTLS obfuscated2 handshake failed");
        return None;
    };

    // 9. Dial Telegram DC (multiplexed MiddleProxy when ad_tag present & reframable, else direct DC)
    dial_and_prepare_relay(
        stream,
        client_addr,
        true,
        tls_unframer,
        doppel_params,
        m.secret_name,
        m.ad_tag,
        obfs_match,
        leftover_app,
        client_entry,
        cancel,
        active_guard,
        release_guard,
        &engine,
    )
    .await
}

async fn obfs2_handshake_and_dial(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    policy: ListenerPolicy,
    worker_id: u16,
    engine: Arc<ProxyEngine>,
) -> Option<EstablishedDirectRelay> {
    let mut client_addr = peer_addr;
    let mut raw_buf = Vec::with_capacity(128);

    if policy.proxy_protocol {
        match read_proxy_header(&mut stream, &mut raw_buf, engine.settings.handshake_timeout).await
        {
            Ok(Some((src, _))) => client_addr = src,
            Ok(None) => {}
            Err(()) => return None,
        }
    }

    let client_ip = peer_ip_of(client_addr);
    let is_v4 = client_ip.is_ipv4();
    let core_metrics = engine.metrics.core(usize::from(worker_id));
    if is_v4 {
        core_metrics.active_conns_v4.fetch_add(1, Ordering::Relaxed);
    } else {
        core_metrics.active_conns_v6.fetch_add(1, Ordering::Relaxed);
    }
    let active_guard = ActiveConnGuard {
        engine: Arc::clone(&engine),
        worker_id,
        is_v4,
    };

    let filter_verdict = engine.check_ip_filters(client_ip, usize::from(worker_id));
    if filter_verdict == IpFilterVerdict::Close {
        return None;
    }

    // Always read the 64-byte obfuscated2 frame BEFORE checking rate limit or
    // stealth IP denial so a denied peer cannot be distinguished from a normal no-match!
    while raw_buf.len() < HANDSHAKE_FRAME_LEN {
        let mut tmp = [0u8; 64];
        let need = HANDSHAKE_FRAME_LEN - raw_buf.len();
        match tokio::time::timeout(
            engine.settings.handshake_timeout,
            stream.read(&mut tmp[..need]),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => raw_buf.extend_from_slice(&tmp[..n]),
        }
    }
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    frame.copy_from_slice(&raw_buf[..HANDSHAKE_FRAME_LEN]);
    let leftover = raw_buf.split_off(HANDSHAKE_FRAME_LEN);
    drop(raw_buf);

    if filter_verdict == IpFilterVerdict::Front {
        dispose_obfs_denied(stream, policy, &engine).await;
        return None;
    }

    if !engine.obfs_limiter.allow(&policy, client_ip) {
        engine
            .metrics
            .obfs
            .rate_limited
            .fetch_add(1, Ordering::Relaxed);
        dispose_obfs_denied(stream, policy, &engine).await;
        return None;
    }

    engine.metrics.obfs.trials.fetch_add(1, Ordering::Relaxed);

    let set = engine.secrets.load();
    let rot_now = engine.rotation_clock.now();
    let candidates = set.active_obfs2_for_modes(policy.modes, rot_now);

    let Ok(obfs_match) = match_handshake(
        &frame,
        candidates.iter().map(|c| Some(&*c.key)),
        policy.modes.tags(),
    ) else {
        engine.metrics.obfs.misses.fetch_add(1, Ordering::Relaxed);
        engine.obfs_limiter.fail(&policy, client_ip);
        dispose_obfs_denied(stream, policy, &engine).await;
        return None;
    };

    let matched_cand = candidates[obfs_match.index];
    let secret_name = Arc::clone(&matched_cand.name);
    let key_bytes = *matched_cand.key;
    let retiring = matched_cand.retiring_until.is_some();
    let limits = set.limits_of(&secret_name).cloned().unwrap_or_default();
    let ad_tag = set.effective_ad_tag(&secret_name);
    drop(set);

    if engine.obfs2_replay.seen_before(&obfs_match.replay_key) {
        core_metrics.replay_attacks.fetch_add(1, Ordering::Relaxed);
        dispose_obfs_denied(stream, policy, &engine).await;
        return None;
    }

    let Ok((conn_handle, client_entry, cancel)) = engine.admit_connection(
        worker_id,
        &secret_name,
        key_bytes,
        retiring,
        Some(client_ip),
        &limits,
    ) else {
        dispose_obfs_denied(stream, policy, &engine).await;
        return None;
    };

    let release_guard = ReleaseConnGuard {
        engine: Arc::clone(&engine),
        secret_name: Arc::clone(&secret_name),
        handle: conn_handle,
        entry: Arc::clone(&client_entry),
        retiring,
    };

    dial_and_prepare_relay(
        stream,
        client_addr,
        false,
        TlsUnframer::new(),
        engine.doppel.params_for_sni(&[]),
        secret_name,
        ad_tag,
        obfs_match,
        leftover,
        client_entry,
        cancel,
        active_guard,
        release_guard,
        &engine,
    )
    .await
}

/// Build FakeTLS ServerHello + CCS + AppData inside thread-local `HS_SH_BUF`
/// and attempt an immediate non-blocking `try_write` (zero heap allocations on
/// 99.99% of fresh TCP connections!). Only spills the unwritten tail into a
/// temporary `Vec` if the kernel send buffer is momentarily full.
async fn send_server_hello_zero_alloc(
    stream: &mut TcpStream,
    candidate: &FakeTlsCandidate,
    hello: &mtg_crypto::faketls::ClientHello,
    noise: mtg_crypto::faketls::NoiseParams,
    x25519_keys: &mtg_crypto::faketls::X25519KeyRing,
    timeout: Duration,
) -> bool {
    enum ShWrite {
        Complete,
        Tail(Vec<u8>),
        Err,
    }

    let outcome = HS_SH_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        build_server_hello(&mut buf, candidate, hello, noise, x25519_keys);
        match stream.try_write(&buf) {
            Ok(w) if w == buf.len() => ShWrite::Complete,
            Ok(0) => ShWrite::Err,
            Ok(w) => ShWrite::Tail(buf[w..].to_vec()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => ShWrite::Tail(buf.clone()),
            Err(_) => ShWrite::Err,
        }
    });

    match outcome {
        ShWrite::Complete => true,
        ShWrite::Err => false,
        ShWrite::Tail(tail) => tokio::time::timeout(timeout, stream.write_all(&tail))
            .await
            .is_ok_and(|r| r.is_ok()),
    }
}

struct MatchedFakeTls {
    secret_name: Arc<str>,
    key_bytes: [u8; 16],
    candidate: FakeTlsCandidate,
    retiring: bool,
    limits: mtg_core::SecretLimits,
    ad_tag: Option<[u8; 16]>,
}

async fn match_faketls_secret(
    parsed: &ParsedClientHello,
    client_ip: IpAddr,
    engine: &ProxyEngine,
) -> Option<MatchedFakeTls> {
    let set = engine.secrets.load();
    if set.faketls_candidates.is_empty() {
        return None;
    }

    let now_unix_ns = coarse_realtime_ns();
    let rot_now = engine.rotation_clock.now();
    let skew_ns = engine.tolerate_time_skewness().as_nanos() as i128;
    let blocks = parsed.scan_blocks();

    let accept_pos = |pos: usize| -> Option<MatchedFakeTls> {
        let meta = &set.faketls_meta[pos];
        if !meta.is_valid_at(rot_now) {
            return None;
        }
        let rec = set.records.get(meta.name.as_ref())?;
        let key_bytes = if let Some(until) = meta.retiring_until {
            rec.retiring
                .iter()
                .find(|r| r.until == until)
                .map_or(*rec.secret.key(), |r| *r.secret.key())
        } else {
            *rec.secret.key()
        };
        Some(MatchedFakeTls {
            secret_name: Arc::clone(&meta.name),
            key_bytes,
            candidate: set.faketls_candidates[pos].clone(),
            retiring: meta.retiring_until.is_some(),
            limits: rec.limits.clone(),
            ad_tag: set.effective_ad_tag(&meta.name),
        })
    };

    // 1. Check MatchHints first (only if hello is within scan block cap!)
    if engine.hints.is_enabled() && blocks <= mtg_governance::MAX_SCAN_BLOCKS {
        let hinted_names = engine.hints.recall(client_ip);
        if !hinted_names.is_empty() {
            let positions = set.resolve_hint_positions(&hinted_names, MAX_HINT_POSITIONS);
            for pos in positions {
                if parsed.verify_at(&set.faketls_candidates[pos], now_unix_ns, skew_ns)
                    && let Some(m) = accept_pos(pos)
                {
                    engine
                        .metrics
                        .faketls
                        .hinted
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(m);
                }
            }
        }
    }

    // 2. SNI-first candidate partitioning: if ClientHello's SNI matches a hosted
    //    bucket, scan ONLY that bucket first using hardware 4-way SHA-NI / 8-way AVX2!
    let mut sni_bucket = None;
    for sni in &parsed.sni_hostnames {
        if let Some(bucket) = set.sni_bucket(sni) {
            sni_bucket = Some(bucket);
            break;
        }
    }

    let candidate_count = sni_bucket.map_or(set.faketls_candidates.len(), |b| b.candidates.len());

    // 3. Enforce FakeTLS scan CPU budget
    let (mut reservation, wait, verdict) =
        engine
            .scan_budget
            .reserve(client_ip, blocks, candidate_count);
    let over_budget = match verdict {
        BudgetVerdict::Granted => false,
        BudgetVerdict::DeniedIp => {
            engine
                .metrics
                .faketls
                .denied_ip
                .fetch_add(1, Ordering::Relaxed);
            if engine.scan_budget.is_enforced() {
                return None;
            }
            true
        }
        BudgetVerdict::DeniedGlobal => {
            engine
                .metrics
                .faketls
                .denied_global
                .fetch_add(1, Ordering::Relaxed);
            if engine.scan_budget.is_enforced() {
                return None;
            }
            true
        }
        BudgetVerdict::Oversized => {
            engine
                .metrics
                .faketls
                .oversized
                .fetch_add(1, Ordering::Relaxed);
            if engine.scan_budget.is_enforced() {
                return None;
            }
            true
        }
    };

    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }

    // 4. Execute scan using 4-way SHA-NI / 8-way AVX2 / ARMv8 SHA-256!
    let found_pos = if let Some(bucket) = sni_bucket {
        parsed
            .scan_candidates_at(&bucket.candidates, now_unix_ns, skew_ns)
            .map(|local_idx| bucket.positions[local_idx])
    } else {
        parsed.scan_candidates_at(&set.faketls_candidates, now_unix_ns, skew_ns)
    };

    if let Some(pos) = found_pos
        && let Some(m) = accept_pos(pos)
    {
        if let Some(res) = reservation.as_mut() {
            res.settle(&engine.scan_budget, true);
        }
        if over_budget {
            engine
                .metrics
                .faketls
                .over_budget_matched
                .fetch_add(1, Ordering::Relaxed);
        } else {
            engine
                .metrics
                .faketls
                .scanned
                .fetch_add(1, Ordering::Relaxed);
        }
        return Some(m);
    }

    if let Some(res) = reservation.as_mut() {
        res.settle(&engine.scan_budget, false);
    }
    engine
        .metrics
        .faketls
        .unmatched
        .fetch_add(1, Ordering::Relaxed);
    None
}

#[allow(clippy::too_many_arguments)]
async fn dial_and_prepare_relay(
    client: TcpStream,
    client_addr: SocketAddr,
    is_faketls: bool,
    tls_unframer: TlsUnframer,
    doppel_params: DoppelParams,
    secret_name: Arc<str>,
    ad_tag: Option<[u8; 16]>,
    obfs_match: mtg_crypto::obfs2::Obfs2Match,
    leftover_app: Vec<u8>,
    client_entry: Arc<mtg_governance::ClientEntry>,
    cancel: CancelToken,
    active_guard: ActiveConnGuard,
    release_guard: ReleaseConnGuard,
    engine: &ProxyEngine,
) -> Option<EstablishedDirectRelay> {
    let user = engine.metrics.user(&secret_name);
    let dc = obfs_match.dc;
    let doppel = build_doppel_state(engine, is_faketls, doppel_params);

    // 1. Try multiplexed MiddleProxy when `ad_tag` is set!
    if let Some(tag_bytes) = ad_tag {
        let reframable = matches!(
            obfs_match.tag,
            ConnectionTag::INTERMEDIATE | ConnectionTag::PADDED_INTERMEDIATE
        );
        if reframable {
            let padded = obfs_match.tag == ConnectionTag::PADDED_INTERMEDIATE;
            // Allow short grace wait on startup if first Telegram config fetch is still in flight
            let _ = engine
                .dc_router
                .wait_initial_ready(mtg_net::FIRST_FETCH_GRACE)
                .await;
            let params = MiddleStreamParams {
                dc,
                client_addr,
                public_ipv4: engine.settings.public_ipv4,
                public_ipv6: engine.settings.public_ipv6,
                advertised_port: engine.settings.advertised_port,
                padded_intermediate: padded,
                ad_tag: tag_bytes,
            };
            match engine.middleproxy.open_stream(params).await {
                Ok(middle) => {
                    let remote_ip = middle.remote_ip();
                    let dc_stats = engine.metrics.dc_endpoint(remote_ip, dc);
                    let ctx = RelayContext {
                        is_faketls,
                        tls_unframer,
                        idle_timeout: engine.settings.idle_timeout,
                        user,
                        client_entry,
                        dc_stats,
                        doppel,
                        cancel,
                    };
                    let _active = active_guard;
                    let _release = release_guard;
                    relay_middleproxy(
                        client,
                        middle,
                        leftover_app,
                        (obfs_match.ciphers.recv, obfs_match.ciphers.send),
                        padded,
                        ctx,
                    )
                    .await;
                    return None;
                }
                Err(e) => {
                    debug!(secret = %secret_name, dc, error = %e, "middleproxy dial failed; falling back to direct DC");
                    user.ad_tag_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            user.ad_tag_skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    // 2. Direct Telegram DC dial via Happy Eyeballs + outbound obfuscated2 handshake
    let Ok((mut dc_stream, dc_addr, effective_dc)) = engine.dc_router.dial_direct(dc).await else {
        debug!(secret = %secret_name, dc, "direct Telegram DC dial failed");
        return None;
    };

    let (out_frame, out_ciphers) =
        build_outbound_handshake(effective_dc as i16, obfs_match.tag, None);
    // Fast non-blocking write path for 64B outbound obfuscated2 frame!
    let sent_direct = match dc_stream.try_write(&out_frame) {
        Ok(w) if w == out_frame.len() => true,
        Ok(0) => return None,
        Ok(w) => tokio::time::timeout(
            engine.settings.tcp_timeout,
            dc_stream.write_all(&out_frame[w..]),
        )
        .await
        .is_ok_and(|r| r.is_ok()),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            tokio::time::timeout(engine.settings.tcp_timeout, dc_stream.write_all(&out_frame))
                .await
                .is_ok_and(|r| r.is_ok())
        }
        Err(_) => return None,
    };
    if !sent_direct {
        return None;
    }

    let dc_stats = engine.metrics.dc_endpoint(dc_addr.ip(), effective_dc);
    let ctx = RelayContext {
        is_faketls,
        tls_unframer,
        idle_timeout: engine.settings.idle_timeout,
        user,
        client_entry,
        dc_stats,
        doppel,
        cancel,
    };
    Some(EstablishedDirectRelay {
        relay: DirectRelay::new(
            client,
            dc_stream,
            leftover_app,
            (obfs_match.ciphers.recv, obfs_match.ciphers.send),
            (out_ciphers.recv, out_ciphers.send),
            ctx,
        ),
        _active_guard: active_guard,
        _release_guard: release_guard,
    })
}

fn build_doppel_state(
    engine: &ProxyEngine,
    is_faketls: bool,
    params: DoppelParams,
) -> Option<Box<(DoppelConnState, DoppelParams)>> {
    if !engine.doppel.enabled || !is_faketls {
        return None;
    }
    Some(Box::new((
        DoppelConnState::new(params.drs || engine.doppel.drs, engine.doppel.shaping),
        params,
    )))
}

async fn do_front(
    stream: TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    initial_bytes: &[u8],
    hosts: Vec<String>,
    worker_id: u16,
    engine: &ProxyEngine,
) {
    let fcfg = engine.fronting_config();
    let target = FrontingTarget {
        hosts,
        port: fcfg.port,
        send_proxy_v2: fcfg.proxy_protocol,
        connect_timeout: engine.settings.tcp_timeout,
        idle_timeout: engine.settings.idle_timeout,
    };
    front_connection(
        stream,
        client_addr,
        local_addr,
        initial_bytes,
        &target,
        &engine.fronting_pool,
        &engine.dns,
        engine.proxy_pool.as_ref(),
        &engine.settings.sock_cfg,
        engine.metrics.core(usize::from(worker_id)),
    )
    .await;
}

async fn dispose_obfs_denied(mut stream: TcpStream, policy: ListenerPolicy, engine: &ProxyEngine) {
    engine.metrics.obfs.denied.fetch_add(1, Ordering::Relaxed);
    if policy.on_unknown_secret == UnknownSecretAction::Drain {
        engine.metrics.obfs.draining.fetch_add(1, Ordering::Relaxed);
        let mut sink = [0u8; 512];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut drained = 0usize;
        while drained < 4096 {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                break;
            }
            match tokio::time::timeout(rem, stream.read(&mut sink)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => drained += n,
            }
        }
        engine.metrics.obfs.draining.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Fast check for plaintext HTTP methods (so HTTP probes on `:443` skip Obfuscated2
/// trials completely and front immediately to the cover server!).
#[inline]
fn looks_like_plain_http(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    matches!(
        &buf[..4],
        b"GET " | b"POST" | b"HEAD" | b"PUT " | b"OPTI" | b"DELE" | b"PATC"
    )
}

async fn read_at_least(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    need: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while buf.len() < need {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return false;
        }
        let mut tmp = [0u8; 128];
        let to_read = (need - buf.len()).min(tmp.len());
        match tokio::time::timeout(rem, stream.read(&mut tmp[..to_read])).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return false,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    true
}

/// Unified single-port Obfuscated2 (`dd` / `plain`) authentication branch on `bind-to`.
/// On ANY miss, rate-limit, replay, or governance denial, transparently fronts the
/// verbatim raw bytes to the cover website via `splice(2)` (zero fingerprint!).
#[allow(clippy::too_many_arguments)]
async fn try_single_port_obfs2_or_front(
    stream: TcpStream,
    client_addr: SocketAddr,
    dst_addr: SocketAddr,
    client_ip: IpAddr,
    mut raw_buf: Vec<u8>,
    modes: mtg_core::ModeSet,
    worker_id: u16,
    active_guard: ActiveConnGuard,
    engine: Arc<ProxyEngine>,
) -> Option<EstablishedDirectRelay> {
    let public_policy = ListenerPolicy {
        modes,
        public: true,
        proxy_protocol: engine.settings.proxy_protocol_listener,
        on_unknown_secret: UnknownSecretAction::Close,
        handshakes_per_ip: mtg_config::DEFAULT_HANDSHAKES_PER_IP,
    };

    if !engine.obfs_limiter.allow(&public_policy, client_ip) {
        engine
            .metrics
            .obfs
            .rate_limited
            .fetch_add(1, Ordering::Relaxed);
        let hosts = engine.fronting_hosts_for(&[]);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &raw_buf,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    }

    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    frame.copy_from_slice(&raw_buf[..HANDSHAKE_FRAME_LEN]);

    engine.metrics.obfs.trials.fetch_add(1, Ordering::Relaxed);

    let set = engine.secrets.load();
    let rot_now = engine.rotation_clock.now();
    let candidates = set.active_obfs2_for_modes(modes, rot_now);

    let Ok(obfs_match) = match_handshake(
        &frame,
        candidates.iter().map(|c| Some(&*c.key)),
        modes.tags(),
    ) else {
        drop(set);
        engine.metrics.obfs.misses.fetch_add(1, Ordering::Relaxed);
        engine.obfs_limiter.fail(&public_policy, client_ip);
        let hosts = engine.fronting_hosts_for(&[]);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &raw_buf,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    };

    let matched_cand = candidates[obfs_match.index];
    let secret_name = Arc::clone(&matched_cand.name);
    let key_bytes = *matched_cand.key;
    let retiring = matched_cand.retiring_until.is_some();
    let limits = set.limits_of(&secret_name).cloned().unwrap_or_default();
    let ad_tag = set.effective_ad_tag(&secret_name);
    drop(set);

    if engine.obfs2_replay.seen_before(&obfs_match.replay_key) {
        engine
            .metrics
            .core(usize::from(worker_id))
            .replay_attacks
            .fetch_add(1, Ordering::Relaxed);
        let hosts = engine.fronting_hosts_for(&[]);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &raw_buf,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    }

    let Ok((conn_handle, client_entry, cancel)) = engine.admit_connection(
        worker_id,
        &secret_name,
        key_bytes,
        retiring,
        Some(client_ip),
        &limits,
    ) else {
        let hosts = engine.fronting_hosts_for(&[]);
        do_front(
            stream,
            client_addr,
            dst_addr,
            &raw_buf,
            hosts,
            worker_id,
            &engine,
        )
        .await;
        return None;
    };

    let leftover = raw_buf.split_off(HANDSHAKE_FRAME_LEN);
    drop(raw_buf);

    let release_guard = ReleaseConnGuard {
        engine: Arc::clone(&engine),
        secret_name: Arc::clone(&secret_name),
        handle: conn_handle,
        entry: Arc::clone(&client_entry),
        retiring,
    };

    dial_and_prepare_relay(
        stream,
        client_addr,
        false,
        TlsUnframer::new(),
        DoppelParams::default(),
        secret_name,
        ad_tag,
        obfs_match,
        leftover,
        client_entry,
        cancel,
        active_guard,
        release_guard,
        &engine,
    )
    .await
}

async fn read_proxy_header(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Result<Option<(SocketAddr, SocketAddr)>, ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match parse_proxy_header(buf, ProxyProtoMode::Optional) {
            Ok(ProxyParseStatus::Complete { header, consumed }) => {
                buf.drain(..consumed);
                if let (Some(src), Some(dst)) = (header.source, header.destination) {
                    return Ok(Some((src, dst)));
                }
                return Ok(None);
            }
            Ok(ProxyParseStatus::NotPresent) => return Ok(None),
            Ok(ProxyParseStatus::Incomplete) => {}
            Err(_) => return Err(()),
        }
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() || buf.len() >= 4096 {
            return Err(());
        }
        buf.reserve(512);
        match tokio::time::timeout(rem, stream.read_buf(buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return Err(()),
            Ok(Ok(_)) => {}
        }
    }
}

async fn read_faketls_client_hello(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Result<(ParsedClientHello, usize), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match parse_client_hello_incremental(buf) {
            Ok(ParseStatus::Complete { parsed, consumed }) => return Ok((parsed, consumed)),
            Ok(ParseStatus::Incomplete) => {}
            Err(_) => return Err(()),
        }
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() || buf.len() >= 65_536 {
            return Err(());
        }
        buf.reserve(1024);
        match tokio::time::timeout(rem, stream.read_buf(buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return Err(()),
            Ok(Ok(_)) => {}
        }
    }
}

async fn read_faketls_obfs2_frame(
    stream: &mut TcpStream,
    raw_in: &mut Vec<u8>,
    timeout: Duration,
) -> Result<([u8; HANDSHAKE_FRAME_LEN], Vec<u8>, TlsUnframer), ()> {
    let mut unframer = TlsUnframer::new();
    let mut app = Vec::with_capacity(128);
    let mut tmp = [0u8; 512];
    let deadline = tokio::time::Instant::now() + timeout;

    if !raw_in.is_empty() {
        let Ok(written) = unframer.unframe_in_place(raw_in) else {
            return Err(());
        };
        app.extend_from_slice(&raw_in[..written]);
        raw_in.clear();
    }

    loop {
        if app.len() >= HANDSHAKE_FRAME_LEN {
            let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
            frame.copy_from_slice(&app[..HANDSHAKE_FRAME_LEN]);
            let leftover = app.split_off(HANDSHAKE_FRAME_LEN);
            return Ok((frame, leftover, unframer));
        }
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err(());
        }
        match tokio::time::timeout(rem, stream.read(&mut tmp)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return Err(()),
            Ok(Ok(n)) => {
                let Ok(written) = unframer.unframe_in_place(&mut tmp[..n]) else {
                    return Err(());
                };
                app.extend_from_slice(&tmp[..written]);
            }
        }
    }
}

struct ActiveConnGuard {
    engine: Arc<ProxyEngine>,
    worker_id: u16,
    is_v4: bool,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        let c = self.engine.metrics.core(usize::from(self.worker_id));
        if self.is_v4 {
            c.active_conns_v4.fetch_sub(1, Ordering::Relaxed);
        } else {
            c.active_conns_v6.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct ReleaseConnGuard {
    engine: Arc<ProxyEngine>,
    secret_name: Arc<str>,
    handle: mtg_governance::ConnHandle,
    entry: Arc<mtg_governance::ClientEntry>,
    retiring: bool,
}

impl Drop for ReleaseConnGuard {
    fn drop(&mut self) {
        self.engine
            .release_connection(&self.secret_name, self.handle, &self.entry, self.retiring);
    }
}
