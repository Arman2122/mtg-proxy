//! Pure-Rust Linux A/B benchmark & wire-interop harness for `mtg-proxy`.
//!
//! Executes interleaved rounds (`A, B, A, B, ...`) against two real Linux proxy
//! binaries (e.g., frozen Go oracle vs pure-Rust `mtg-proxy`) using an
//! in-process SOCKS5 mock Telegram DC so BOTH binaries run 100% unmodified
//! production code paths (FakeTLS `ee`, Obfuscated2 `dd`, PROXY v2, `/stats`).
//!
//! Captures:
//! - Throughput (`GiB/s`), `CPU-s/GB`, `syscalls/MB`, `VmRSS` / `VmHWM` (`MiB`),
//!   context switches, and `KiB/idle-conn` directly from Linux `/proc/<pid>/`.
//! - `HdrHistogram` p50 / p99 / p99.9 latencies (µs / ms).
//! - Mann-Whitney U significance statistic across interleaved rounds.

use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use mtg_core::{ConnectionTag, Secret, SecretMode, TagSet};
use mtg_crypto::aes_ctr::{Aes256Ctr, FusedCtrPair};
use mtg_crypto::faketls::build_client_hello;
use mtg_crypto::obfs2::{HANDSHAKE_FRAME_LEN, build_outbound_handshake, match_handshake};
use mtg_protocol::proxyproto::encode_v2_tcp;
use mtg_protocol::tls_record::{MAX_TLS_RECORD_PAYLOAD, TlsUnframer, stamp_app_data_header};
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

#[derive(Debug, Parser)]
#[command(
    name = "mtg-bench",
    about = "Interleaved Linux A/B benchmark suite for mtg-proxy"
)]
struct Cli {
    #[command(subcommand)]
    cmd: BenchCmd,
}

#[derive(Debug, Subcommand)]
enum BenchCmd {
    /// Run interleaved Go-vs-Rust A/B benchmarks & wire interop verification.
    Ab {
        /// Path to baseline binary A (e.g. frozen Go oracle).
        #[arg(long = "bin-a")]
        bin_a: PathBuf,
        /// Path to candidate binary B (e.g. pure-Rust mtg-proxy).
        #[arg(long = "bin-b")]
        bin_b: PathBuf,
        /// Display label for binary A.
        #[arg(long = "label-a", default_value = "Go-Oracle")]
        label_a: String,
        /// Display label for binary B.
        #[arg(long = "label-b", default_value = "Rust-2.0")]
        label_b: String,
        /// Number of interleaved A/B rounds per benchmark.
        #[arg(long = "rounds", default_value_t = 3)]
        rounds: usize,
        /// Total MiB transferred in single-stream bulk FakeTLS benchmark.
        #[arg(long = "single-mb", default_value_t = 256)]
        single_mb: usize,
        /// Total MiB transferred in 32-stream concurrent FakeTLS benchmark.
        #[arg(long = "multi-mb", default_value_t = 512)]
        multi_mb: usize,
        /// Number of configured FakeTLS secrets in the 5k handshake flood test.
        #[arg(long = "secrets", default_value_t = 5000)]
        secrets: usize,
        /// Number of handshakes per round in the 5k secret flood test.
        #[arg(long = "handshakes", default_value_t = 1000)]
        handshakes: usize,
        /// Number of simultaneous idle FakeTLS connections for RSS measurement.
        #[arg(long = "idle-conns", default_value_t = 2000)]
        idle_conns: usize,
        /// Optional path to write full JSON results.
        #[arg(long = "json-out")]
        json_out: Option<PathBuf>,
    },
}

/// Snapshot of Linux `/proc/<pid>/{status,io,stat}` counters.
#[derive(Debug, Clone, Copy, Default, Serialize)]
struct ProcSample {
    rss_kib: u64,
    hwm_kib: u64,
    cpu_secs: f64,
    syscr: u64,
    syscw: u64,
    voluntary_cs: u64,
    nonvoluntary_cs: u64,
}

fn sample_proc(pid: u32) -> ProcSample {
    let mut s = ProcSample::default();
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("VmRSS:") {
                s.rss_kib = parse_first_u64(v);
            } else if let Some(v) = line.strip_prefix("VmHWM:") {
                s.hwm_kib = parse_first_u64(v);
            } else if let Some(v) = line.strip_prefix("voluntary_ctxt_switches:") {
                s.voluntary_cs = parse_first_u64(v);
            } else if let Some(v) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
                s.nonvoluntary_cs = parse_first_u64(v);
            }
        }
    }
    if let Ok(io_txt) = fs::read_to_string(format!("/proc/{pid}/io")) {
        for line in io_txt.lines() {
            if let Some(v) = line.strip_prefix("syscr:") {
                s.syscr = parse_first_u64(v);
            } else if let Some(v) = line.strip_prefix("syscw:") {
                s.syscw = parse_first_u64(v);
            }
        }
    }
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat"))
        && let Some(rparen) = stat.rfind(')')
    {
        let fields: Vec<&str> = stat[rparen + 2..].split_whitespace().collect();
        // After ')': index 11 is utime (field 14), index 12 is stime (field 15).
        if fields.len() > 13 {
            let utime: u64 = fields[11].parse().unwrap_or(0);
            let stime: u64 = fields[12].parse().unwrap_or(0);
            // SAFETY: standard POSIX sysconf query for clock ticks per second.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
            s.cpu_secs = (utime + stime) as f64 / hz;
        }
    }
    s
}

fn parse_first_u64(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy)]
enum MockDcMode {
    Echo,
    HoldIdle,
}

/// In-process SOCKS5 + unkeyed Obfuscated2 mock Telegram DC.
///
/// Accepts SOCKS5 `CONNECT` from EITHER Go `mtg-proxy-go` OR Rust `mtg-proxy`,
/// decrypts the proxy's 64-byte unkeyed Obfuscated2 DC handshake, and then
/// either echoes encrypted traffic at VAES speed (`Echo`) or holds the socket
/// open cleanly (`HoldIdle`) for memory/handshake benchmarks.
async fn spawn_mock_socks_dc(
    mode: MockDcMode,
) -> Result<(SocketAddr, watch::Sender<bool>, Arc<AtomicU64>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let accepted = Arc::new(AtomicU64::new(0));
    let acc_clone = Arc::clone(&accepted);

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() { break; }
                    continue;
                }
                res = listener.accept() => res,
            };
            let Ok((mut sock, _)) = accept else { continue };
            let _ = sock.set_nodelay(true);
            acc_clone.fetch_add(1, Ordering::Relaxed);
            let mut conn_stop = stop_rx.clone();

            tokio::spawn(async move {
                if socks5_server_handshake(&mut sock).await.is_err() {
                    return;
                }

                // Read 64-byte unkeyed Obfuscated2 handshake frame from proxy -> DC!
                let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
                if sock.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let Ok(m) = match_handshake(&frame, [None::<&[u8; 16]>], TagSet::all()) else {
                    return;
                };

                match mode {
                    MockDcMode::HoldIdle => {
                        let mut tiny = [0u8; 64];
                        loop {
                            tokio::select! {
                                _ = conn_stop.changed() => {
                                    if *conn_stop.borrow() { break; }
                                }
                                r = sock.read(&mut tiny) => {
                                    match r {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            let mut fused = FusedCtrPair::new(
                                                m.ciphers.recv.clone(),
                                                m.ciphers.send.clone(),
                                            );
                                            fused.apply_fused_in_place(&mut tiny[..n]);
                                            let _ = sock.write_all(&tiny[..n]).await;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    MockDcMode::Echo => {
                        let mut fused = FusedCtrPair::new(m.ciphers.recv, m.ciphers.send);
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            let n = match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            fused.apply_fused_in_place(&mut buf[..n]);
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    Ok((addr, stop_tx, accepted))
}

async fn socks5_server_handshake(sock: &mut TcpStream) -> Result<()> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; usize::from(hdr[1])];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        bail!("unsupported SOCKS5 cmd");
    }
    match req[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            sock.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            sock.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            sock.read_exact(&mut rest).await?;
        }
        _ => bail!("invalid SOCKS5 atyp"),
    }
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB])
        .await?;
    Ok(())
}

struct ManagedProxy {
    child: Child,
    pid: u32,
    bind_addr: SocketAddr,
    dd_addr: Option<SocketAddr>,
    api_addr: Option<SocketAddr>,
    _cfg_path: PathBuf,
}

impl ManagedProxy {
    async fn start(
        bin: &Path,
        cfg_toml: &str,
        bind_addr: SocketAddr,
        dd_addr: Option<SocketAddr>,
        api_addr: Option<SocketAddr>,
        tmp_dir: &Path,
        tag: &str,
    ) -> Result<Self> {
        let cfg_path = tmp_dir.join(format!("bench_{tag}_{}.toml", bind_addr.port()));
        fs::write(&cfg_path, cfg_toml)?;

        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn {}", bin.display()))?;
        let pid = child.id();

        // Wait until listener accepts TCP connections (up to 15s for 5k-secret init).
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("proxy {} exited early with {status}", bin.display());
            }
            if TcpStream::connect(bind_addr).await.is_ok() {
                // Give a brief moment so listener & stats settle.
                tokio::time::sleep(Duration::from_millis(60)).await;
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("timed out waiting for {} on {bind_addr}", bin.display());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        Ok(Self {
            child,
            pid,
            bind_addr,
            dd_addr,
            api_addr,
            _cfg_path: cfg_path,
        })
    }

    fn stop(mut self) {
        // SAFETY: SIGTERM our own spawned child process cleanly.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_loopback_addr() -> Result<SocketAddr> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?)
}

/// Complete a real FakeTLS `ee` + Obfuscated2 client handshake over `stream`,
/// returning `(encrypt_to_proxy, decrypt_from_proxy, tls_unframer)`.
async fn client_faketls_handshake(
    stream: &mut TcpStream,
    secret: &Secret,
    spoof_proxy_v2_src: Option<SocketAddr>,
    dc_id: i16,
) -> Result<(Aes256Ctr, Aes256Ctr, TlsUnframer)> {
    if let Some(src) = spoof_proxy_v2_src {
        let dst = stream.peer_addr()?;
        let pp = encode_v2_tcp(src, dst);
        stream.write_all(pp.as_slice()).await?;
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let hello = build_client_hello(secret.key(), secret.host(), now_unix);
    stream.write_all(&hello).await?;

    // Read FakeTLS ServerHello (3 TLS records: Handshake 0x16, ChangeCipherSpec 0x14, AppData 0x17)
    let mut rec_hdr = [0u8; 5];
    for expected_type in [0x16u8, 0x14u8, 0x17u8] {
        stream.read_exact(&mut rec_hdr).await?;
        if rec_hdr[0] != expected_type {
            bail!(
                "unexpected FakeTLS server record {:#x} (want {:#x})",
                rec_hdr[0],
                expected_type
            );
        }
        let len = usize::from(u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]));
        let mut discard = vec![0u8; len];
        stream.read_exact(&mut discard).await?;
    }

    // Build 64-byte Obfuscated2 client frame inside a FakeTLS AppData record!
    let (frame, ciphers) = build_outbound_handshake(
        dc_id,
        ConnectionTag::PADDED_INTERMEDIATE,
        Some(secret.key()),
    );
    let mut wrapped = [0u8; 5 + HANDSHAKE_FRAME_LEN];
    stamp_app_data_header(
        (&mut wrapped[..5]).try_into().expect("5B"),
        HANDSHAKE_FRAME_LEN as u16,
    );
    wrapped[5..].copy_from_slice(&frame);
    stream.write_all(&wrapped).await?;

    Ok((ciphers.send, ciphers.recv, TlsUnframer::new()))
}

/// Complete a direct Obfuscated2 `dd` handshake (no FakeTLS).
async fn client_dd_handshake(
    stream: &mut TcpStream,
    secret: &Secret,
    dc_id: i16,
) -> Result<(Aes256Ctr, Aes256Ctr)> {
    let (frame, ciphers) = build_outbound_handshake(
        dc_id,
        ConnectionTag::PADDED_INTERMEDIATE,
        Some(secret.key()),
    );
    stream.write_all(&frame).await?;
    Ok((ciphers.send, ciphers.recv))
}

/// Read exact `need` unframed plaintext bytes from a FakeTLS stream.
async fn read_exact_faketls(
    stream: &mut TcpStream,
    unframer: &mut TlsUnframer,
    dec: &mut Aes256Ctr,
    pending: &mut Vec<u8>,
    raw_tmp: &mut [u8],
    dst: &mut [u8],
) -> Result<()> {
    let mut filled = 0usize;
    if !pending.is_empty() {
        let take = pending.len().min(dst.len());
        dst[..take].copy_from_slice(&pending[..take]);
        pending.drain(..take);
        filled += take;
    }
    while filled < dst.len() {
        let n = stream.read(raw_tmp).await?;
        if n == 0 {
            bail!("unexpected EOF reading FakeTLS downlink");
        }
        let app_len = unframer
            .unframe_in_place(&mut raw_tmp[..n])
            .map_err(|e| anyhow::anyhow!("unframe error: {e}"))?;
        if app_len == 0 {
            continue;
        }
        dec.apply_keystream(&mut raw_tmp[..app_len]);
        let need = dst.len() - filled;
        let take = app_len.min(need);
        dst[filled..filled + take].copy_from_slice(&raw_tmp[..take]);
        filled += take;
        if app_len > take {
            pending.extend_from_slice(&raw_tmp[take..app_len]);
        }
    }
    Ok(())
}

/// Write `plain` framed as FakeTLS AppData records (`<= 16 KiB` each).
async fn write_all_faketls(
    stream: &mut TcpStream,
    enc: &mut Aes256Ctr,
    plain: &[u8],
    wire_buf: &mut Vec<u8>,
) -> Result<()> {
    wire_buf.clear();
    let mut off = 0usize;
    while off < plain.len() {
        let take = (plain.len() - off).min(MAX_TLS_RECORD_PAYLOAD);
        let start = wire_buf.len();
        let mut hdr = [0u8; 5];
        stamp_app_data_header(&mut hdr, take as u16);
        wire_buf.extend_from_slice(&hdr);
        wire_buf.extend_from_slice(&plain[off..off + take]);
        enc.apply_keystream(&mut wire_buf[start + 5..start + 5 + take]);
        off += take;
    }
    stream.write_all(wire_buf).await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct BulkResult {
    gib_per_sec: f64,
    cpu_secs_per_gb: f64,
    syscalls_per_mb: f64,
    rtt_p50_us: u64,
    rtt_p99_us: u64,
    rtt_p999_us: u64,
    rss_mib: f64,
}

#[derive(Debug, Clone, Serialize)]
struct HandshakeResult {
    handshakes_per_sec: f64,
    p50_ms: f64,
    p99_ms: f64,
    rss_mib: f64,
}

#[derive(Debug, Clone, Serialize)]
struct IdleMemResult {
    conns: usize,
    rss_mib: f64,
    hwm_mib: f64,
    kib_per_conn: f64,
}

#[derive(Debug, Clone, Serialize)]
struct RoundBundle {
    single_dd: BulkResult,
    multi_dd: BulkResult,
    single: BulkResult,
    multi: BulkResult,
    handshake_5k: HandshakeResult,
    idle_mem: IdleMemResult,
}

/// Verify wire interoperability: FakeTLS `ee`, Obfuscated2 `dd`, bit-exact echo, and `/stats` JSON!
async fn run_interop_gate(bin: &Path, label: &str, tmp_dir: &Path) -> Result<()> {
    let (socks_addr, stop_dc, _) = spawn_mock_socks_dc(MockDcMode::Echo).await?;
    let ee_addr = free_loopback_addr()?;
    let dd_addr = free_loopback_addr()?;
    let api_addr = free_loopback_addr()?;

    let secret = Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com")?;
    let dd_secret = Secret::from_parts(*secret.key(), "", SecretMode::Dd);

    let cfg = format!(
        r#"
bind-to = "{ee_addr}"
concurrency = 256
prefer-ip = "only-ipv4"
api-bind-to = "{api_addr}"
api-token = "bench-interop-token"

[secrets]
alice = "{}"

[[listener]]
bind-to = "{dd_addr}"
accept = ["dd"]
public = true

[defense.anti-replay]
enabled = true
max-size = "1MB"

[network]
proxies = ["socks5://{socks_addr}"]
"#,
        secret.encode_hex()
    );

    let proxy = ManagedProxy::start(
        bin,
        &cfg,
        ee_addr,
        Some(dd_addr),
        Some(api_addr),
        tmp_dir,
        &format!("interop_{label}"),
    )
    .await?;

    // 1. FakeTLS `ee` 256 KiB bit-exact echo test
    let mut s_ee = TcpStream::connect(proxy.bind_addr).await?;
    let _ = s_ee.set_nodelay(true);
    let (mut enc, mut dec, mut unframer) =
        client_faketls_handshake(&mut s_ee, &secret, None, 2).await?;
    let payload: Vec<u8> = (0..(256 * 1024))
        .map(|i| ((i * 131 + 17) & 0xff) as u8)
        .collect();
    let mut wire_buf = Vec::new();
    let mut recv_buf = vec![0u8; payload.len()];
    let mut pending = Vec::new();
    let mut raw_tmp = vec![0u8; 65_536];

    // Concurrent send + receive to avoid loopback TCP deadlock on 256 KiB.
    let (mut r_half, mut w_half) = s_ee.into_split();
    let payload_send = payload.clone();
    let send_task = tokio::spawn(async move {
        let mut off = 0;
        while off < payload_send.len() {
            let take = (payload_send.len() - off).min(MAX_TLS_RECORD_PAYLOAD);
            wire_buf.clear();
            let mut hdr = [0u8; 5];
            stamp_app_data_header(&mut hdr, take as u16);
            wire_buf.extend_from_slice(&hdr);
            wire_buf.extend_from_slice(&payload_send[off..off + take]);
            enc.apply_keystream(&mut wire_buf[5..5 + take]);
            w_half.write_all(&wire_buf).await?;
            off += take;
        }
        Ok::<_, anyhow::Error>(w_half)
    });

    let mut filled = 0;
    while filled < recv_buf.len() {
        let n = r_half.read(&mut raw_tmp).await?;
        if n == 0 {
            bail!("{label}: unexpected EOF during FakeTLS interop echo");
        }
        let app = unframer
            .unframe_in_place(&mut raw_tmp[..n])
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if app > 0 {
            dec.apply_keystream(&mut raw_tmp[..app]);
            let take = app.min(recv_buf.len() - filled);
            recv_buf[filled..filled + take].copy_from_slice(&raw_tmp[..take]);
            filled += take;
            if app > take {
                pending.extend_from_slice(&raw_tmp[take..app]);
            }
        }
    }
    let _w_half = send_task.await??;
    if recv_buf != payload {
        bail!("{label}: FakeTLS echoed payload mismatch!");
    }

    // 2. Obfuscated2 `dd` 64 KiB bit-exact echo test
    let mut s_dd = TcpStream::connect(proxy.dd_addr.unwrap()).await?;
    let _ = s_dd.set_nodelay(true);
    let (mut dd_enc, mut dd_dec) = client_dd_handshake(&mut s_dd, &dd_secret, 2).await?;
    let dd_plain: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 73 + 5) & 0xff) as u8)
        .collect();
    let mut dd_cipher = dd_plain.clone();
    dd_enc.apply_keystream(&mut dd_cipher);
    s_dd.write_all(&dd_cipher).await?;
    let mut dd_recv = vec![0u8; dd_plain.len()];
    s_dd.read_exact(&mut dd_recv).await?;
    dd_dec.apply_keystream(&mut dd_recv);
    if dd_recv != dd_plain {
        bail!("{label}: dd echoed payload mismatch!");
    }

    // 3. `/stats` HTTP API JSON sanity check
    let mut api_sock = TcpStream::connect(proxy.api_addr.unwrap()).await?;
    api_sock
        .write_all(
            b"GET /stats HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer bench-interop-token\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut api_raw = Vec::new();
    api_sock.read_to_end(&mut api_raw).await?;
    let api_str = String::from_utf8_lossy(&api_raw);
    let body = api_str.split("\r\n\r\n").nth(1).unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(body).with_context(|| format!("{label}: bad /stats JSON: {body}"))?;
    if !parsed["features"].is_array() {
        bail!("{label}: /stats missing features array");
    }

    proxy.stop();
    let _ = stop_dc.send(true);
    println!(
        "  [INTEROP PASS] {label}: FakeTLS ee (256 KiB bit-exact) + dd (64 KiB bit-exact) + /stats JSON"
    );
    Ok(())
}

/// Unshaped raw Obfuscated2 `dd` bulk echo benchmark (100% apples-to-apples
/// pure data-plane comparison — zero Doppelganger delay on either Go or Rust!).
async fn bench_bulk_dd(
    bin: &Path,
    label: &str,
    streams: usize,
    total_mb: usize,
    tmp_dir: &Path,
) -> Result<BulkResult> {
    let (socks_addr, stop_dc, _) = spawn_mock_socks_dc(MockDcMode::Echo).await?;
    let ee_addr = free_loopback_addr()?;
    let dd_addr = free_loopback_addr()?;
    let secret = Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com")?;
    let dd_secret = Secret::from_parts(*secret.key(), "", SecretMode::Dd);

    let cfg = format!(
        r#"
bind-to = "{ee_addr}"
concurrency = 4096
prefer-ip = "only-ipv4"

[secrets]
alice = "{}"

[[listener]]
bind-to = "{dd_addr}"
accept = ["dd"]
public = true

[defense.anti-replay]
enabled = false

[defense.doppelganger]
drs = false
scout-covers = false

[network]
proxies = ["socks5://{socks_addr}"]
"#,
        secret.encode_hex()
    );

    let proxy = ManagedProxy::start(
        bin,
        &cfg,
        ee_addr,
        Some(dd_addr),
        None,
        tmp_dir,
        &format!("dd{streams}_{label}"),
    )
    .await?;

    let per_stream_bytes = (total_mb * 1024 * 1024) / streams;
    let chunk_size = 64 * 1024;
    let chunks_per_stream = (per_stream_bytes / chunk_size).max(1);
    let actual_total_bytes = streams * chunks_per_stream * chunk_size;

    let mut conns = Vec::with_capacity(streams);
    for _ in 0..streams {
        let mut s = TcpStream::connect(proxy.dd_addr.unwrap()).await?;
        let _ = s.set_nodelay(true);
        let hs = client_dd_handshake(&mut s, &dd_secret, 2).await?;
        conns.push((s, hs));
    }

    let before = sample_proc(proxy.pid);
    let t0 = Instant::now();

    let mut handles = Vec::with_capacity(streams);
    for (mut s, (mut enc, mut dec)) in conns {
        handles.push(tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new(3).unwrap();
            let mut tx = vec![0x5Au8; chunk_size];
            let mut rx = vec![0u8; chunk_size];

            for _ in 0..chunks_per_stream {
                let c0 = Instant::now();
                enc.apply_keystream(&mut tx);
                s.write_all(&tx).await?;
                s.read_exact(&mut rx).await?;
                dec.apply_keystream(&mut rx);
                let us = c0.elapsed().as_micros() as u64;
                let _ = hist.record(us.max(1));
            }
            Ok::<_, anyhow::Error>(hist)
        }));
    }

    let mut merged = Histogram::<u64>::new(3).unwrap();
    for h in handles {
        let sub = h.await??;
        merged.add(&sub)?;
    }

    let elapsed = t0.elapsed().as_secs_f64().max(1e-6);
    let after = sample_proc(proxy.pid);
    proxy.stop();
    let _ = stop_dc.send(true);

    let duplex_bytes = (actual_total_bytes * 2) as f64;
    let gib = duplex_bytes / (1024.0 * 1024.0 * 1024.0);
    let gb = duplex_bytes / 1e9;
    let mb = duplex_bytes / (1024.0 * 1024.0);
    let cpu_delta = (after.cpu_secs - before.cpu_secs).max(0.0);
    let syscalls_delta =
        after.syscr.saturating_sub(before.syscr) + after.syscw.saturating_sub(before.syscw);

    Ok(BulkResult {
        gib_per_sec: gib / elapsed,
        cpu_secs_per_gb: cpu_delta / gb.max(1e-6),
        syscalls_per_mb: syscalls_delta as f64 / mb.max(1e-6),
        rtt_p50_us: merged.value_at_quantile(0.50),
        rtt_p99_us: merged.value_at_quantile(0.99),
        rtt_p999_us: merged.value_at_quantile(0.999),
        rss_mib: after.rss_kib as f64 / 1024.0,
    })
}

/// Bulk FakeTLS echo benchmark (1 or N concurrent streams).
async fn bench_bulk(
    bin: &Path,
    label: &str,
    streams: usize,
    total_mb: usize,
    tmp_dir: &Path,
) -> Result<BulkResult> {
    let (socks_addr, stop_dc, _) = spawn_mock_socks_dc(MockDcMode::Echo).await?;
    let bind_addr = free_loopback_addr()?;
    let secret = Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com")?;

    let cfg = format!(
        r#"
bind-to = "{bind_addr}"
concurrency = 4096
prefer-ip = "only-ipv4"

[secrets]
alice = "{}"

[defense.anti-replay]
enabled = false

[defense.doppelganger]
drs = false
scout-covers = false

[network]
proxies = ["socks5://{socks_addr}"]
"#,
        secret.encode_hex()
    );

    let proxy = ManagedProxy::start(
        bin,
        &cfg,
        bind_addr,
        None,
        None,
        tmp_dir,
        &format!("bulk{streams}_{label}"),
    )
    .await?;

    let per_stream_bytes = (total_mb * 1024 * 1024) / streams;
    let chunk_size = 64 * 1024;
    let chunks_per_stream = (per_stream_bytes / chunk_size).max(1);
    let actual_total_bytes = streams * chunks_per_stream * chunk_size;

    // Establish all streams BEFORE starting measurement timer so we measure steady-state data plane!
    let mut conns = Vec::with_capacity(streams);
    for _ in 0..streams {
        let mut s = TcpStream::connect(proxy.bind_addr).await?;
        let _ = s.set_nodelay(true);
        let hs = client_faketls_handshake(&mut s, &secret, None, 2).await?;
        conns.push((s, hs));
    }

    let before = sample_proc(proxy.pid);
    let t0 = Instant::now();

    let mut handles = Vec::with_capacity(streams);
    for (mut s, (mut enc, mut dec, mut unframer)) in conns {
        handles.push(tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new(3).unwrap();
            let plain = vec![0x5Au8; chunk_size];
            let mut recv = vec![0u8; chunk_size];
            let mut wire = Vec::with_capacity(chunk_size + 64);
            let mut pending = Vec::new();
            let mut raw_tmp = vec![0u8; 65_536];

            for _ in 0..chunks_per_stream {
                let c0 = Instant::now();
                write_all_faketls(&mut s, &mut enc, &plain, &mut wire).await?;
                read_exact_faketls(
                    &mut s,
                    &mut unframer,
                    &mut dec,
                    &mut pending,
                    &mut raw_tmp,
                    &mut recv,
                )
                .await?;
                let us = c0.elapsed().as_micros() as u64;
                let _ = hist.record(us.max(1));
            }
            Ok::<_, anyhow::Error>(hist)
        }));
    }

    let mut merged = Histogram::<u64>::new(3).unwrap();
    for h in handles {
        let sub = h.await??;
        merged.add(&sub)?;
    }

    let elapsed = t0.elapsed().as_secs_f64().max(1e-6);
    let after = sample_proc(proxy.pid);
    proxy.stop();
    let _ = stop_dc.send(true);

    // Full-duplex echo moves `actual_total_bytes` UP + `actual_total_bytes` DOWN = 2x through the proxy!
    let duplex_bytes = (actual_total_bytes * 2) as f64;
    let gib = duplex_bytes / (1024.0 * 1024.0 * 1024.0);
    let gb = duplex_bytes / 1e9;
    let mb = duplex_bytes / (1024.0 * 1024.0);
    let cpu_delta = (after.cpu_secs - before.cpu_secs).max(0.0);
    let syscalls_delta =
        after.syscr.saturating_sub(before.syscr) + after.syscw.saturating_sub(before.syscw);

    Ok(BulkResult {
        gib_per_sec: gib / elapsed,
        cpu_secs_per_gb: cpu_delta / gb.max(1e-6),
        syscalls_per_mb: syscalls_delta as f64 / mb.max(1e-6),
        rtt_p50_us: merged.value_at_quantile(0.50),
        rtt_p99_us: merged.value_at_quantile(0.99),
        rtt_p999_us: merged.value_at_quantile(0.999),
        rss_mib: after.rss_kib as f64 / 1024.0,
    })
}

/// N=5,000-secret FakeTLS handshake flood benchmark (with PROXY v2 unique source IPs).
async fn bench_handshake_5k(
    bin: &Path,
    label: &str,
    num_secrets: usize,
    total_handshakes: usize,
    tmp_dir: &Path,
) -> Result<HandshakeResult> {
    let (socks_addr, stop_dc, _) = spawn_mock_socks_dc(MockDcMode::HoldIdle).await?;
    let bind_addr = free_loopback_addr()?;

    // Generate N secrets ALL sharing the same SNI host (`storage.googleapis.com`)
    // so worst-case candidate scan across all N secrets is exercised!
    let mut cfg = format!(
        r#"
bind-to = "{bind_addr}"
concurrency = 8192
prefer-ip = "only-ipv4"
proxy-protocol-listener = true

[defense.anti-replay]
enabled = false

[defense.doppelganger]
drs = false
scout-covers = false

[defense.handshake-budget]
mode = "off"

[network]
proxies = ["socks5://{socks_addr}"]

[secrets]
"#
    );

    let mut targets = Vec::with_capacity(16);
    for i in 0..num_secrets {
        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&(i as u32 + 1).to_be_bytes());
        key[4..8].copy_from_slice(&0xA55A_1337u32.to_be_bytes());
        key[8..16].copy_from_slice(&(i as u64 ^ 0xDEAD_BEEF_CAFE_BABEu64).to_be_bytes());
        let s = Secret::from_parts(key, "storage.googleapis.com", SecretMode::FakeTls);
        let _ = writeln!(cfg, "u{i:05} = \"{}\"", s.encode_hex());
        // Probe secrets from the END of the 5,000-secret table (worst-case linear scan)!
        if i + 16 >= num_secrets {
            targets.push(s);
        }
    }
    let targets = Arc::new(targets);

    let proxy = ManagedProxy::start(
        bin,
        &cfg,
        bind_addr,
        None,
        None,
        tmp_dir,
        &format!("hs5k_{label}"),
    )
    .await?;

    let sem = Arc::new(Semaphore::new(64));
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(total_handshakes);

    for i in 0..total_handshakes {
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let target = targets[i % targets.len()].clone();
        let addr = proxy.bind_addr;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            // Unique client IP via PROXY v2 so IP hint table does not shortcut scan!
            let b1 = 10u8;
            let b2 = ((i >> 16) & 0xff) as u8;
            let b3 = ((i >> 8) & 0xff) as u8;
            let b4 = (i & 0xff).max(1) as u8;
            let spoof = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b1, b2, b3, b4)), 40000);

            let h0 = Instant::now();
            let mut s = TcpStream::connect(addr).await?;
            let _ = s.set_nodelay(true);
            let _ = client_faketls_handshake(&mut s, &target, Some(spoof), 2).await?;
            let us = h0.elapsed().as_micros() as u64;
            drop(s);
            Ok::<_, anyhow::Error>(us)
        }));
    }

    let mut hist = Histogram::<u64>::new(3).unwrap();
    let mut ok_count = 0usize;
    for h in handles {
        if let Ok(Ok(us)) = h.await {
            let _ = hist.record(us.max(1));
            ok_count += 1;
        }
    }
    if ok_count < total_handshakes * 9 / 10 {
        bail!("{label}: too many handshake failures ({ok_count}/{total_handshakes})");
    }

    let elapsed = t0.elapsed().as_secs_f64().max(1e-6);
    let sample = sample_proc(proxy.pid);
    proxy.stop();
    let _ = stop_dc.send(true);

    Ok(HandshakeResult {
        handshakes_per_sec: ok_count as f64 / elapsed,
        p50_ms: hist.value_at_quantile(0.50) as f64 / 1000.0,
        p99_ms: hist.value_at_quantile(0.99) as f64 / 1000.0,
        rss_mib: sample.rss_kib as f64 / 1024.0,
    })
}

/// Simultaneous idle FakeTLS connection memory (`VmRSS`, `VmHWM`, `KiB/conn`).
async fn bench_idle_memory(
    bin: &Path,
    label: &str,
    conns: usize,
    tmp_dir: &Path,
) -> Result<IdleMemResult> {
    let (socks_addr, stop_dc, _) = spawn_mock_socks_dc(MockDcMode::HoldIdle).await?;
    let bind_addr = free_loopback_addr()?;
    let secret = Secret::generate_mode(SecretMode::FakeTls, "storage.googleapis.com")?;

    let cfg = format!(
        r#"
bind-to = "{bind_addr}"
concurrency = {}
prefer-ip = "only-ipv4"

[secrets]
alice = "{}"

[defense.anti-replay]
enabled = false

[defense.doppelganger]
drs = false
scout-covers = false

[network]
proxies = ["socks5://{socks_addr}"]
"#,
        conns.saturating_mul(2).max(8192),
        secret.encode_hex()
    );

    let proxy = ManagedProxy::start(
        bin,
        &cfg,
        bind_addr,
        None,
        None,
        tmp_dir,
        &format!("idle_{label}"),
    )
    .await?;

    let base_sample = sample_proc(proxy.pid);
    let sem = Arc::new(Semaphore::new(128));
    let mut open_tasks = Vec::with_capacity(conns);
    let failed = Arc::new(AtomicBool::new(false));

    for _ in 0..conns {
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let sec = secret.clone();
        let addr = proxy.bind_addr;
        let fail_flag = Arc::clone(&failed);
        open_tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let Ok(mut s) = TcpStream::connect(addr).await else {
                fail_flag.store(true, Ordering::Relaxed);
                return None;
            };
            if client_faketls_handshake(&mut s, &sec, None, 2)
                .await
                .is_ok()
            {
                Some(s)
            } else {
                fail_flag.store(true, Ordering::Relaxed);
                None
            }
        }));
    }

    let mut held = Vec::with_capacity(conns);
    for t in open_tasks {
        if let Ok(Some(sock)) = t.await {
            held.push(sock);
        }
    }
    if held.len() < conns * 9 / 10 {
        proxy.stop();
        let _ = stop_dc.send(true);
        bail!(
            "{label}: only established {}/{conns} idle connections",
            held.len()
        );
    }

    // Let GC (Go) / jemalloc dirty decay settle briefly before sampling RSS.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let peak = sample_proc(proxy.pid);

    let established = held.len();
    drop(held);
    proxy.stop();
    let _ = stop_dc.send(true);

    let delta_kib = peak.rss_kib.saturating_sub(base_sample.rss_kib);
    Ok(IdleMemResult {
        conns: established,
        rss_mib: peak.rss_kib as f64 / 1024.0,
        hwm_mib: peak.hwm_kib as f64 / 1024.0,
        kib_per_conn: delta_kib as f64 / established.max(1) as f64,
    })
}

fn median(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut s = vals.to_vec();
    s.sort_by(f64::total_cmp);
    let mid = s.len() / 2;
    if s.len().is_multiple_of(2) {
        f64::midpoint(s[mid - 1], s[mid])
    } else {
        s[mid]
    }
}

/// Compute Mann-Whitney U statistic for sample A vs sample B (smaller U means
/// clearer separation; `U == 0` on 3v3 rounds means 100% non-overlapping!).
fn mann_whitney_u(a: &[f64], b: &[f64]) -> f64 {
    let mut u1 = 0.0;
    for &va in a {
        for &vb in b {
            if va > vb {
                u1 += 1.0;
            } else if (va - vb).abs() < 1e-12 {
                u1 += 0.5;
            }
        }
    }
    let u2 = (a.len() * b.len()) as f64 - u1;
    u1.min(u2)
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = mtg_net::raise_nofile_limit(1_048_576);
    let cli = Cli::parse();

    match cli.cmd {
        BenchCmd::Ab {
            bin_a,
            bin_b,
            label_a,
            label_b,
            rounds,
            single_mb,
            multi_mb,
            secrets,
            handshakes,
            idle_conns,
            json_out,
        } => {
            let tmp_dir = std::env::temp_dir().join(format!("mtg_bench_{}", std::process::id()));
            fs::create_dir_all(&tmp_dir)?;

            println!("====================================================================");
            println!(" mtg-proxy Linux Interleaved A/B Benchmark Suite");
            println!("   A ({label_a}): {}", bin_a.display());
            println!("   B ({label_b}): {}", bin_b.display());
            println!(
                "   Rounds: {rounds} | Bulk1: {single_mb} MiB | Bulk32: {multi_mb} MiB | HS5k: {secrets} secrets x {handshakes} | Idle: {idle_conns}"
            );
            println!("====================================================================");

            println!("\n[Phase 0] Wire Interoperability Gate (FakeTLS ee + dd + /stats):");
            run_interop_gate(&bin_a, &label_a, &tmp_dir).await?;
            run_interop_gate(&bin_b, &label_b, &tmp_dir).await?;

            let mut results_a = Vec::with_capacity(rounds);
            let mut results_b = Vec::with_capacity(rounds);

            for r in 0..rounds {
                println!("\n--- Interleaved Round {}/{rounds} ---", r + 1);
                // Alternate order on odd rounds (A,B then B,A) to eliminate order bias!
                let order: [(bool, &Path, &str); 2] = if r.is_multiple_of(2) {
                    [(true, &bin_a, &label_a), (false, &bin_b, &label_b)]
                } else {
                    [(false, &bin_b, &label_b), (true, &bin_a, &label_a)]
                };

                for (is_a, bin, lbl) in order {
                    let single_dd = bench_bulk_dd(bin, lbl, 1, single_mb, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [dd 1-str ] {:.2} GiB/s | {:.2} CPU-s/GB | {:.1} sys/MB | p50={}us p99={}us",
                        single_dd.gib_per_sec,
                        single_dd.cpu_secs_per_gb,
                        single_dd.syscalls_per_mb,
                        single_dd.rtt_p50_us,
                        single_dd.rtt_p99_us
                    );

                    let multi_dd = bench_bulk_dd(bin, lbl, 32, multi_mb, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [dd 32-str] {:.2} GiB/s | {:.2} CPU-s/GB | {:.1} sys/MB | p50={}us p99={}us p99.9={}us",
                        multi_dd.gib_per_sec,
                        multi_dd.cpu_secs_per_gb,
                        multi_dd.syscalls_per_mb,
                        multi_dd.rtt_p50_us,
                        multi_dd.rtt_p99_us,
                        multi_dd.rtt_p999_us
                    );

                    let single = bench_bulk(bin, lbl, 1, single_mb, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [ee 1-str ] {:.2} GiB/s | {:.2} CPU-s/GB | {:.1} sys/MB | p50={}us p99={}us",
                        single.gib_per_sec,
                        single.cpu_secs_per_gb,
                        single.syscalls_per_mb,
                        single.rtt_p50_us,
                        single.rtt_p99_us
                    );

                    let multi = bench_bulk(bin, lbl, 32, multi_mb, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [ee 32-str] {:.2} GiB/s | {:.2} CPU-s/GB | {:.1} sys/MB | p50={}us p99={}us p99.9={}us",
                        multi.gib_per_sec,
                        multi.cpu_secs_per_gb,
                        multi.syscalls_per_mb,
                        multi.rtt_p50_us,
                        multi.rtt_p99_us,
                        multi.rtt_p999_us
                    );

                    let hs = bench_handshake_5k(bin, lbl, secrets, handshakes, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [HS 5k    ] {:.0} hs/s | p50={:.2}ms p99={:.2}ms | RSS={:.1} MiB",
                        hs.handshakes_per_sec, hs.p50_ms, hs.p99_ms, hs.rss_mib
                    );

                    let idle = bench_idle_memory(bin, lbl, idle_conns, &tmp_dir).await?;
                    println!(
                        "  {lbl:<10} [Idle {0}] RSS={1:.1} MiB (HWM={2:.1} MiB) | {3:.2} KiB/conn",
                        idle.conns, idle.rss_mib, idle.hwm_mib, idle.kib_per_conn
                    );

                    let bundle = RoundBundle {
                        single_dd,
                        multi_dd,
                        single,
                        multi,
                        handshake_5k: hs,
                        idle_mem: idle,
                    };
                    if is_a {
                        results_a.push(bundle);
                    } else {
                        results_b.push(bundle);
                    }
                }
            }

            // Aggregate medians & Mann-Whitney U summary table
            let dd1_a: Vec<f64> = results_a.iter().map(|r| r.single_dd.gib_per_sec).collect();
            let dd1_b: Vec<f64> = results_b.iter().map(|r| r.single_dd.gib_per_sec).collect();
            let ddm_a: Vec<f64> = results_a.iter().map(|r| r.multi_dd.gib_per_sec).collect();
            let ddm_b: Vec<f64> = results_b.iter().map(|r| r.multi_dd.gib_per_sec).collect();
            let ddcpu_a: Vec<f64> = results_a
                .iter()
                .map(|r| r.multi_dd.cpu_secs_per_gb)
                .collect();
            let ddcpu_b: Vec<f64> = results_b
                .iter()
                .map(|r| r.multi_dd.cpu_secs_per_gb)
                .collect();
            let ddsys_a: Vec<f64> = results_a
                .iter()
                .map(|r| r.multi_dd.syscalls_per_mb)
                .collect();
            let ddsys_b: Vec<f64> = results_b
                .iter()
                .map(|r| r.multi_dd.syscalls_per_mb)
                .collect();
            let ddp99_a: Vec<f64> = results_a
                .iter()
                .map(|r| r.multi_dd.rtt_p99_us as f64)
                .collect();
            let ddp99_b: Vec<f64> = results_b
                .iter()
                .map(|r| r.multi_dd.rtt_p99_us as f64)
                .collect();

            let s1_a: Vec<f64> = results_a.iter().map(|r| r.single.gib_per_sec).collect();
            let s1_b: Vec<f64> = results_b.iter().map(|r| r.single.gib_per_sec).collect();
            let sm_a: Vec<f64> = results_a.iter().map(|r| r.multi.gib_per_sec).collect();
            let sm_b: Vec<f64> = results_b.iter().map(|r| r.multi.gib_per_sec).collect();
            let cpu_a: Vec<f64> = results_a.iter().map(|r| r.multi.cpu_secs_per_gb).collect();
            let cpu_b: Vec<f64> = results_b.iter().map(|r| r.multi.cpu_secs_per_gb).collect();
            let sys_a: Vec<f64> = results_a.iter().map(|r| r.multi.syscalls_per_mb).collect();
            let sys_b: Vec<f64> = results_b.iter().map(|r| r.multi.syscalls_per_mb).collect();
            let p99_a: Vec<f64> = results_a
                .iter()
                .map(|r| r.multi.rtt_p99_us as f64)
                .collect();
            let p99_b: Vec<f64> = results_b
                .iter()
                .map(|r| r.multi.rtt_p99_us as f64)
                .collect();
            let hs_a: Vec<f64> = results_a
                .iter()
                .map(|r| r.handshake_5k.handshakes_per_sec)
                .collect();
            let hs_b: Vec<f64> = results_b
                .iter()
                .map(|r| r.handshake_5k.handshakes_per_sec)
                .collect();
            let hsp99_a: Vec<f64> = results_a.iter().map(|r| r.handshake_5k.p99_ms).collect();
            let hsp99_b: Vec<f64> = results_b.iter().map(|r| r.handshake_5k.p99_ms).collect();
            let mem_a: Vec<f64> = results_a.iter().map(|r| r.idle_mem.kib_per_conn).collect();
            let mem_b: Vec<f64> = results_b.iter().map(|r| r.idle_mem.kib_per_conn).collect();
            let rss_a: Vec<f64> = results_a.iter().map(|r| r.idle_mem.rss_mib).collect();
            let rss_b: Vec<f64> = results_b.iter().map(|r| r.idle_mem.rss_mib).collect();

            println!("\n===================== MEDIAN A/B SUMMARY =====================");
            println!(
                "{:<28} {:>14} {:>14} {:>12} {:>8}",
                "Metric", label_a, label_b, "Delta/Speedup", "MW-U"
            );
            println!("{}", "-".repeat(80));
            print_row("dd 1-stream raw (GiB/s)", &dd1_a, &dd1_b, true);
            print_row("dd 32-stream raw (GiB/s)", &ddm_a, &ddm_b, true);
            print_row("dd 32-stream CPU (s/GB)", &ddcpu_a, &ddcpu_b, false);
            print_row("dd 32-stream Syscalls (/MB)", &ddsys_a, &ddsys_b, false);
            print_row("dd 32-stream RTT p99 (us)", &ddp99_a, &ddp99_b, false);
            print_row("ee 1-stream FakeTLS (GiB/s)", &s1_a, &s1_b, true);
            print_row("ee 32-stream FakeTLS (GiB/s)", &sm_a, &sm_b, true);
            print_row("ee 32-stream CPU (s/GB)", &cpu_a, &cpu_b, false);
            print_row("ee 32-stream Syscalls (/MB)", &sys_a, &sys_b, false);
            print_row("ee 32-stream RTT p99 (us)", &p99_a, &p99_b, false);
            print_row("5k-secret HS rate (hs/s)", &hs_a, &hs_b, true);
            print_row("5k-secret HS p99 (ms)", &hsp99_a, &hsp99_b, false);
            print_row("Idle memory (KiB/conn)", &mem_a, &mem_b, false);
            print_row("Idle total RSS (MiB)", &rss_a, &rss_b, false);
            println!("==============================================================");

            if let Some(out) = json_out {
                let doc = serde_json::json!({
                    "label_a": label_a,
                    "label_b": label_b,
                    "rounds_a": results_a,
                    "rounds_b": results_b,
                });
                fs::write(&out, serde_json::to_vec_pretty(&doc)?)?;
                println!("Wrote JSON report to {}", out.display());
            }

            let _ = fs::remove_dir_all(&tmp_dir);
        }
    }

    Ok(())
}

fn print_row(name: &str, a: &[f64], b: &[f64], higher_is_better: bool) {
    let ma = median(a);
    let mb = median(b);
    let ratio = if higher_is_better {
        mb / ma.max(1e-9)
    } else {
        ma / mb.max(1e-9)
    };
    let u = mann_whitney_u(a, b);
    println!("{name:<28} {ma:>14.2} {mb:>14.2} {ratio:>11.2}x {u:>8.1}");
}
