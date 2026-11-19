//! Thread-per-core Linux proxy engine (`mtg-engine`):
//! FakeTLS (`ee`) + Obfuscated2 (`dd`/`plain`) doors, single-pass VAES fused-CTR
//! zero-copy relay, kernel `splice(2)` domain fronting, persistent multiplexed
//! MiddleProxy, governance enforcement, metrics, and graceful shutdown.

pub mod cancel;
pub mod doppel_scout;
pub mod fronting;
pub mod handshake;
pub mod metrics;
pub mod relay;
pub mod state;
pub mod worker;

pub use cancel::CancelToken;
pub use fronting::{FrontingTarget, front_connection};
pub use metrics::{
    CoreMetrics, DcEndpointStats, FakeTlsCounters, ObfsCounters, ProxyMetrics, SecretRuntime,
    UsageRecord, compute_fair_caps,
};
pub use state::{
    DoppelState, EngineError, EngineSettings, ListenerReport, ProxyEngine, SUPPORTED_FEATURES,
    is_secret_served, peer_ip_of,
};
pub use worker::{BoundListenerSpec, EngineRuntime};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use chrono::Utc;
    use mtg_config::Config;
    use mtg_core::{ConnectionTag, Secret};
    use mtg_crypto::aes_ctr::Aes256Ctr;
    use mtg_crypto::faketls::build_client_hello;
    use mtg_crypto::obfs2::build_outbound_handshake;
    use mtg_net::DcDirectory;
    use mtg_protocol::tls_record::{TlsUnframer, stamp_app_data_header};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// End-to-end Linux integration test exercising:
    /// 1. Real FakeTLS `ee` ClientHello -> ServerHello -> TLS ApplicationData ->
    ///    Obfuscated2 handshake -> Fused-CTR relay -> Mock Telegram DC echo ->
    ///    TLS-framed response back to client!
    /// 2. Live quota & byte counting in `ProxyMetrics`.
    /// 3. Domain fronting via Linux `splice(2)` when a wrong-secret TLS probe arrives!
    #[tokio::test]
    async fn end_to_end_faketls_relay_and_splice_domain_fronting() {
        // 1. Start mock Telegram DC echo server (accepts outbound obfuscated2 and echoes plaintext back!)
        let mock_dc = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc_addr = mock_dc.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = mock_dc.accept().await.unwrap();
            let mut hs = [0u8; 64];
            s.read_exact(&mut hs).await.unwrap();
            // Outbound proxy->DC obfuscated2 uses NO secret (empty key)!
            // Derive recv/send directly using zero-secret matching? Wait: outbound frame uses None secret ->
            // key = raw[8..40], iv = raw[40..56], reversed = raw[8..56].rev().
            let mut recv_key = [0u8; 32];
            let mut recv_iv = [0u8; 16];
            recv_key.copy_from_slice(&hs[8..40]);
            recv_iv.copy_from_slice(&hs[40..56]);
            let mut rev = [0u8; 48];
            rev.copy_from_slice(&hs[8..56]);
            rev.reverse();
            let mut send_key = [0u8; 32];
            let mut send_iv = [0u8; 16];
            send_key.copy_from_slice(&rev[..32]);
            send_iv.copy_from_slice(&rev[32..48]);

            let mut dec = Aes256Ctr::new(&recv_key, &recv_iv);
            let mut enc = Aes256Ctr::new(&send_key, &send_iv);
            // Advance dec past 64-byte handshake
            let mut dummy = [0u8; 64];
            dec.apply_keystream(&mut dummy);

            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            dec.apply_keystream(&mut buf[..n]);
            enc.apply_keystream(&mut buf[..n]);
            s.write_all(&buf[..n]).await.unwrap();
        });

        // 2. Start mock fronting cover origin (echoes exact raw ClientHello bytes back with prefix!)
        let mock_cover = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = mock_cover.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = mock_cover.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"COVER:").await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        // 3. Configure & launch pure-Rust `ProxyEngine` + `EngineRuntime` on a free local port!
        let proxy_port = {
            let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tmp.local_addr().unwrap().port()
        };
        let secret_hex =
            "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d";
        let secret = Secret::parse(secret_hex).unwrap();
        let cfg_toml = format!(
            r#"
bind-to = "127.0.0.1:{proxy_port}"
prefer-ip = "only-ipv4"
track-client-ips = true
[domain-fronting]
host = "127.0.0.1"
port = {}
[secrets]
alice = "{secret_hex}"
"#,
            cover_addr.port()
        );
        let cfg = Config::parse(cfg_toml.as_bytes()).unwrap();
        let engine = ProxyEngine::from_config(&cfg, None, 2, false).unwrap();

        // Point DC 2 to our local mock DC!
        let mut dir = DcDirectory::default();
        let mut v4 = BTreeMap::new();
        v4.insert(2, vec![dc_addr]);
        dir.direct_v4 = v4;
        engine.dc_router.set_directory(dir);

        let runtime = EngineRuntime::start(Arc::clone(&engine)).await.unwrap();
        let proxy_addr = runtime.bound_faketls_addrs[0];

        // 4. Test A: Valid FakeTLS client handshake + bidirectional echo through fused-CTR relay!
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let now_secs = Utc::now().timestamp() as u32;
        let ch = build_client_hello(secret.key(), "storage.googleapis.com", now_secs);
        client.write_all(&ch).await.unwrap();

        // Read ServerHello + CCS + AppData (3 TLS records)
        let mut sh_read = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut records_seen = 0usize;
        let mut pos = 0usize;
        while records_seen < 3 {
            let n = client.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            sh_read.extend_from_slice(&tmp[..n]);
            while sh_read.len() >= pos + 5 {
                let rlen = u16::from_be_bytes([sh_read[pos + 3], sh_read[pos + 4]]) as usize;
                if sh_read.len() < pos + 5 + rlen {
                    break;
                }
                pos += 5 + rlen;
                records_seen += 1;
            }
        }
        assert_eq!(sh_read[0], 0x16); // ServerHello

        // Send TLS-framed 64-byte obfuscated2 handshake + encrypted payload "HELLO-MTG-RUST!!"
        let (obfs_frame, mut client_ciphers) =
            build_outbound_handshake(2, ConnectionTag::PADDED_INTERMEDIATE, Some(secret.key()));
        let mut payload = *b"HELLO-MTG-RUST!!";
        client_ciphers.send.apply_keystream(&mut payload);

        let mut tls_pkt = vec![0u8; 5 + 64 + payload.len()];
        let hdr: &mut [u8; 5] = (&mut tls_pkt[..5]).try_into().unwrap();
        stamp_app_data_header(hdr, (64 + payload.len()) as u16);
        tls_pkt[5..69].copy_from_slice(&obfs_frame);
        tls_pkt[69..].copy_from_slice(&payload);
        client.write_all(&tls_pkt).await.unwrap();

        // Read TLS-framed echo back from proxy!
        let mut unframer = TlsUnframer::new();
        let mut app_back = Vec::new();
        while app_back.len() < 16 {
            let n = client.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            let w = unframer.unframe_in_place(&mut tmp[..n]).unwrap();
            app_back.extend_from_slice(&tmp[..w]);
        }
        client_ciphers.recv.apply_keystream(&mut app_back[..16]);
        assert_eq!(&app_back[..16], b"HELLO-MTG-RUST!!");
        drop(client);

        // Verify stats recorded alice's traffic!
        let alice_rt = engine.metrics.user("alice");
        assert!(alice_rt.bytes_in.load(Ordering::Relaxed) >= 16);
        assert!(alice_rt.bytes_out.load(Ordering::Relaxed) >= 16);

        // 5. Test B: Wrong-secret probe transparently domain-fronted via Linux `splice(2)`!
        let mut probe = TcpStream::connect(proxy_addr).await.unwrap();
        let probe_bytes = b"GET / HTTP/1.1\r\nHost: cover.example\r\n\r\n";
        probe.write_all(probe_bytes).await.unwrap();
        let mut fronted_reply = vec![0u8; 6 + probe_bytes.len()];
        probe.read_exact(&mut fronted_reply).await.unwrap();
        assert_eq!(&fronted_reply[..6], b"COVER:");
        assert_eq!(&fronted_reply[6..], probe_bytes);
        drop(probe);

        runtime.shutdown();
    }

    /// Regression firewall locking steady-state async task frame size for live
    /// connections so accidental unboxed buffers or large handshake structs
    /// can NEVER re-bloat idle per-connection RAM!
    #[test]
    fn steady_state_connection_future_size_guard() {
        let direct_relay_size = std::mem::size_of::<relay::DirectRelay>();

        let run_fut_size = {
            fn size_of_method<'a, F, Fut>(_: F) -> usize
            where
                F: Fn(&'a mut relay::DirectRelay) -> Fut,
            {
                std::mem::size_of::<Fut>()
            }
            size_of_method(relay::DirectRelay::run)
        };

        let faketls_fut_size = {
            fn size_of_return5<F, A1, A2, A3, A4, A5, Fut>(_: F) -> usize
            where
                F: Fn(A1, A2, A3, A4, A5) -> Fut,
            {
                std::mem::size_of::<Fut>()
            }
            size_of_return5(handshake::handle_faketls_connection)
        };

        let obfs2_fut_size = {
            fn size_of_return5<F, A1, A2, A3, A4, A5, Fut>(_: F) -> usize
            where
                F: Fn(A1, A2, A3, A4, A5) -> Fut,
            {
                std::mem::size_of::<Fut>()
            }
            size_of_return5(handshake::handle_obfs2_connection)
        };

        eprintln!(
            "Steady-state sizes: DirectRelay={direct_relay_size}B, run()={run_fut_size}B, handle_faketls={faketls_fut_size}B, handle_obfs2={obfs2_fut_size}B"
        );
        // 4 x Aes256Ctr (1,152 B) + 2 x TcpStream + compact metadata (~1,408 B)
        assert!(
            direct_relay_size <= 1_536,
            "DirectRelay struct bloated to {direct_relay_size} bytes!"
        );
        // run(&mut self) only holds `&mut DirectRelay` + 1 x Sleep (~160 B!)
        assert!(
            run_fut_size <= 256,
            "DirectRelay::run future bloated to {run_fut_size} bytes!"
        );
        // Total live Tokio task future stays strictly <= 1,920 B even in debug builds!
        assert!(
            faketls_fut_size <= 1_920,
            "handle_faketls_connection future bloated to {faketls_fut_size} bytes!"
        );
        assert!(
            obfs2_fut_size <= 1_920,
            "handle_obfs2_connection future bloated to {obfs2_fut_size} bytes!"
        );
    }
}
