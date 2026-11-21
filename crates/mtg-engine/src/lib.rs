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
pub use doppel_scout::DoppelCatalog;
pub use fronting::{FrontingPool, FrontingTarget, front_connection};
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

    /// Full-stack end-to-end MiddleProxy (`ad-tag`) test exercising:
    /// 1. Real FakeTLS `ee` clients -> `ProxyEngine` -> `MiddleProxyPool` -> mock
    ///    Telegram MiddleProxy RPC server (`RPC_NONCE` + AES-256-CBC + `RPC_HANDSHAKE`).
    /// 2. Exact `ad_tag` propagation in `RPC_PROXY_REQ`.
    /// 3. Per-packet `FLAG_ENCRYPTED` (set on `auth_key_id == 0` handshakes like
    ///    `req_pq_multi`, cleared on normal encrypted packets) and `FLAG_QUICK_ACK`.
    /// 4. Clean 4-byte `RPC_PROXY_ANS` framing even when the server sets
    ///    `FLAG_QUICK_ACK` in response flags (regression guard for Showstopper #2).
    /// 5. Verbatim `RPC_SIMPLE_ACK` quick-ack forwarding.
    /// 6. `RPC_PING` -> `RPC_PONG` keepalive over active carrier.
    /// 7. Graceful `RPC_CLOSE_CONN` when Client 1 disconnects while Client 2
    ///    continues operating cleanly!
    #[tokio::test]
    async fn end_to_end_faketls_middleproxy_ad_tag_roundtrip_and_multiplexing() {
        use std::sync::atomic::AtomicU64;

        use mtg_protocol::middleproxy::{
            FLAG_ENCRYPTED, FLAG_HAS_AD_TAG, FLAG_PAD, FLAG_QUICK_ACK, NonceRequest, QUICK_ACK_BIT,
            RpcFrameDecoder, SEQ_NO_HANDSHAKE, SEQ_NO_NONCE, TAG_RPC_CLOSE_CONN, TAG_RPC_HANDSHAKE,
            TAG_RPC_NONCE, TAG_RPC_PONG, TAG_RPC_PROXY_ANS, TAG_RPC_PROXY_REQ, TAG_RPC_SIMPLE_ACK,
            append_rpc_frame, build_rpc_ping_body, derive_middleproxy_server_ciphers,
            handshake_request_bytes,
        };
        use parking_lot::Mutex;
        use zeroize::Zeroizing;

        #[derive(Debug, Clone)]
        struct ObservedReq {
            flags: u32,
            conn_id: [u8; 8],
            ad_tag: [u8; 16],
            payload: Vec<u8>,
        }

        async fn connect_faketls_client(
            proxy_addr: std::net::SocketAddr,
            secret: &Secret,
        ) -> (TcpStream, mtg_crypto::obfs2::Obfs2Ciphers) {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let now_secs = Utc::now().timestamp() as u32;
            let ch = build_client_hello(secret.key(), "storage.googleapis.com", now_secs);
            client.write_all(&ch).await.unwrap();

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
            let (obfs_frame, ciphers) =
                build_outbound_handshake(2, ConnectionTag::PADDED_INTERMEDIATE, Some(secret.key()));
            let mut tls_hs = vec![0u8; 5 + 64];
            let hdr: &mut [u8; 5] = (&mut tls_hs[..5]).try_into().unwrap();
            stamp_app_data_header(hdr, 64);
            tls_hs[5..69].copy_from_slice(&obfs_frame);
            client.write_all(&tls_hs).await.unwrap();
            (client, ciphers)
        }

        async fn send_tls_app(client: &mut TcpStream, send_ctr: &mut Aes256Ctr, plain: &[u8]) {
            let mut buf = vec![0u8; 5 + plain.len()];
            let hdr: &mut [u8; 5] = (&mut buf[..5]).try_into().unwrap();
            stamp_app_data_header(hdr, plain.len() as u16);
            buf[5..].copy_from_slice(plain);
            send_ctr.apply_keystream(&mut buf[5..]);
            client.write_all(&buf).await.unwrap();
        }

        async fn recv_tls_app_exact(
            client: &mut TcpStream,
            recv_ctr: &mut Aes256Ctr,
            unframer: &mut TlsUnframer,
            buf: &mut Vec<u8>,
            need: usize,
        ) -> Vec<u8> {
            let mut tmp = [0u8; 4096];
            while buf.len() < need {
                let n = client.read(&mut tmp).await.unwrap();
                assert!(
                    n > 0,
                    "unexpected EOF waiting for {need} bytes, got {}",
                    buf.len()
                );
                let w = unframer.unframe_in_place(&mut tmp[..n]).unwrap();
                if w > 0 {
                    recv_ctr.apply_keystream(&mut tmp[..w]);
                    buf.extend_from_slice(&tmp[..w]);
                }
            }
            buf.drain(..need).collect()
        }

        let proxy_secret: Vec<u8> = (0u8..128)
            .map(|i| i.wrapping_mul(17).wrapping_add(3))
            .collect();
        let expected_ad_tag_hex = "0123456789abcdef0123456789abcdef";
        let expected_ad_tag: [u8; 16] = hex::decode(expected_ad_tag_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let expected_ping_id: u64 = 0x1122_3344_5566_7788;
        let expected_quick_ack_token = [0xefu8, 0xbe, 0xad, 0xde];

        let observed_reqs: Arc<Mutex<Vec<ObservedReq>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_closes: Arc<Mutex<Vec<[u8; 8]>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_pong: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

        // 1. Start mock Telegram MiddleProxy RPC server
        let mock_mp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mp_addr = mock_mp.local_addr().unwrap();
        let mp_secret = proxy_secret.clone();
        let mp_reqs = Arc::clone(&observed_reqs);
        let mp_closes = Arc::clone(&observed_closes);
        let mp_pong = Arc::clone(&observed_pong);
        tokio::spawn(async move {
            async fn read_rpc(
                s: &mut TcpStream,
                dec: &mut RpcFrameDecoder,
            ) -> std::io::Result<Vec<u8>> {
                let mut tmp = [0u8; 4096];
                loop {
                    if let Some(body) = dec.next_frame().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })? {
                        return Ok(body);
                    }
                    let n = s.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "eof",
                        ));
                    }
                    dec.push_wire_bytes(&tmp[..n]);
                }
            }

            while let Ok((mut s, peer)) = mock_mp.accept().await {
                let secret = mp_secret.clone();
                let reqs = Arc::clone(&mp_reqs);
                let closes = Arc::clone(&mp_closes);
                let pong = Arc::clone(&mp_pong);
                let local = s.local_addr().unwrap();
                tokio::spawn(async move {
                    // Plaintext RPC_NONCE (seq_no = -2)
                    let mut plain_dec = RpcFrameDecoder::new(None, SEQ_NO_NONCE);
                    let Ok(nonce_req_body) = read_rpc(&mut s, &mut plain_dec).await else {
                        return;
                    };
                    assert_eq!(nonce_req_body.len(), 32);
                    assert_eq!(&nonce_req_body[0..4], &TAG_RPC_NONCE);
                    assert_eq!(&nonce_req_body[4..8], &secret[0..4]);

                    let req = NonceRequest {
                        key_selector: nonce_req_body[4..8].try_into().unwrap(),
                        crypto_ts: nonce_req_body[12..16].try_into().unwrap(),
                        nonce: nonce_req_body[16..32].try_into().unwrap(),
                    };
                    let server_nonce = [0x5Au8; 16];
                    let mut nonce_resp = [0u8; 32];
                    nonce_resp[0..4].copy_from_slice(&TAG_RPC_NONCE);
                    nonce_resp[4..8].copy_from_slice(&req.key_selector);
                    nonce_resp[8..12].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // AES
                    nonce_resp[12..16].copy_from_slice(&req.crypto_ts);
                    nonce_resp[16..32].copy_from_slice(&server_nonce);

                    let mut wr_seq = SEQ_NO_NONCE;
                    let mut wire = Vec::new();
                    append_rpc_frame(&mut wire, &mut wr_seq, &[&nonce_resp]);
                    s.write_all(&wire).await.unwrap();

                    // Switch to AES-256-CBC (server side!)
                    let (mut enc, dec_cipher) = derive_middleproxy_server_ciphers(
                        &req,
                        &server_nonce,
                        peer,
                        local,
                        &secret,
                    );
                    let mut enc_dec = RpcFrameDecoder::new(Some(dec_cipher), SEQ_NO_HANDSHAKE);

                    // Encrypted RPC_HANDSHAKE (seq_no = -1)
                    let hs_body = read_rpc(&mut s, &mut enc_dec).await.unwrap();
                    assert_eq!(hs_body.len(), 32);
                    assert_eq!(&hs_body[0..4], &TAG_RPC_HANDSHAKE);

                    let hs_resp = handshake_request_bytes();
                    wire.clear();
                    append_rpc_frame(&mut wire, &mut wr_seq, &[&hs_resp]);
                    enc.encrypt_blocks_in_place(&mut wire).unwrap();
                    s.write_all(&wire).await.unwrap();

                    let mut sent_ping = false;
                    // Main RPC carrier loop (seq_no >= 0)
                    while let Ok(body) = read_rpc(&mut s, &mut enc_dec).await {
                        let tag: [u8; 4] = body[0..4].try_into().unwrap();
                        if tag == TAG_RPC_PROXY_REQ {
                            assert!(body.len() >= 84);
                            let flags = u32::from_le_bytes(body[4..8].try_into().unwrap());
                            let conn_id: [u8; 8] = body[8..16].try_into().unwrap();
                            let ad_tag: [u8; 16] = body[65..81].try_into().unwrap();
                            let payload = body[84..].to_vec();
                            reqs.lock().push(ObservedReq {
                                flags,
                                conn_id,
                                ad_tag,
                                payload: payload.clone(),
                            });

                            wire.clear();
                            if !sent_ping {
                                sent_ping = true;
                                let ping = build_rpc_ping_body(expected_ping_id);
                                append_rpc_frame(&mut wire, &mut wr_seq, &[&ping]);
                            }

                            // Intentionally set FLAG_QUICK_ACK on RPC_PROXY_ANS to prove the proxy
                            // does NOT corrupt the 4-byte client length prefix!
                            let ans_flags = flags | FLAG_QUICK_ACK;
                            let mut ans = Vec::with_capacity(16 + payload.len());
                            ans.extend_from_slice(&TAG_RPC_PROXY_ANS);
                            ans.extend_from_slice(&ans_flags.to_le_bytes());
                            ans.extend_from_slice(&conn_id);
                            ans.extend_from_slice(&payload);
                            append_rpc_frame(&mut wire, &mut wr_seq, &[&ans]);

                            if (flags & FLAG_QUICK_ACK) != 0 {
                                let mut ack = Vec::with_capacity(16);
                                ack.extend_from_slice(&TAG_RPC_SIMPLE_ACK);
                                ack.extend_from_slice(&conn_id);
                                ack.extend_from_slice(&expected_quick_ack_token);
                                append_rpc_frame(&mut wire, &mut wr_seq, &[&ack]);
                            }

                            enc.encrypt_blocks_in_place(&mut wire).unwrap();
                            if s.write_all(&wire).await.is_err() {
                                break;
                            }
                        } else if tag == TAG_RPC_CLOSE_CONN && body.len() >= 12 {
                            let conn_id: [u8; 8] = body[4..12].try_into().unwrap();
                            closes.lock().push(conn_id);
                        } else if tag == TAG_RPC_PONG && body.len() >= 12 {
                            let pid = u64::from_le_bytes(body[4..12].try_into().unwrap());
                            pong.store(pid, Ordering::Release);
                        }
                    }
                });
            }
        });

        // 2. Configure ProxyEngine with `ad-tag` and point ONLY `middle_v4` DC 2 to mock server
        //    (removing direct DC 2 so any accidental direct fallback would fail immediately!).
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
ad-tag = "{expected_ad_tag_hex}"
[secrets]
alice = "{secret_hex}"
"#
        );
        let cfg = Config::parse(cfg_toml.as_bytes()).unwrap();
        let engine = ProxyEngine::from_config(&cfg, None, 1, false).unwrap();

        let mut dir = DcDirectory::default();
        dir.direct_v4.clear();
        dir.direct_v6.clear();
        dir.middle_v4.insert(2, vec![mp_addr]);
        dir.proxy_secret = Some(Arc::new(Zeroizing::new(proxy_secret)));
        engine.dc_router.set_directory(dir);

        let runtime = EngineRuntime::start(Arc::clone(&engine)).await.unwrap();
        let proxy_addr = runtime.bound_faketls_addrs[0];

        // 3. Client 1: unencrypted req_pq_multi-like handshake (`auth_key_id == 0`)
        //    with `QUICK_ACK_BIT` + 2 bytes of random padded-intermediate padding!
        let (mut c1, mut c1_ciphers) = connect_faketls_client(proxy_addr, &secret).await;
        let mut c1_unframer = TlsUnframer::new();
        let mut c1_plain_rx = Vec::new();

        let mut req_pq_payload = vec![0u8; 24]; // 8 zero bytes (auth_key_id == 0) + 16 payload
        req_pq_payload[8..24].copy_from_slice(b"REQ_PQ_MULTI_001");
        let mut c1_frame = Vec::new();
        let declared_len: u32 = (24 + 2) | QUICK_ACK_BIT; // +2 padding bytes + quick-ack!
        c1_frame.extend_from_slice(&declared_len.to_le_bytes());
        c1_frame.extend_from_slice(&req_pq_payload);
        c1_frame.extend_from_slice(&[0xaa, 0xbb]); // 2 trailing pad bytes trimmed to 24B
        send_tls_app(&mut c1, &mut c1_ciphers.send, &c1_frame).await;

        // Expect clean 4-byte length `24` (NO QUICK_ACK_BIT corruption!) + 24B payload + 4B SimpleAck!
        let got_hdr = recv_tls_app_exact(
            &mut c1,
            &mut c1_ciphers.recv,
            &mut c1_unframer,
            &mut c1_plain_rx,
            4,
        )
        .await;
        assert_eq!(
            u32::from_le_bytes(got_hdr.try_into().unwrap()),
            24,
            "RPC_PROXY_ANS length MUST NOT have QUICK_ACK_BIT OR'd into it!"
        );
        let got_body = recv_tls_app_exact(
            &mut c1,
            &mut c1_ciphers.recv,
            &mut c1_unframer,
            &mut c1_plain_rx,
            24,
        )
        .await;
        assert_eq!(got_body, req_pq_payload);
        let got_ack = recv_tls_app_exact(
            &mut c1,
            &mut c1_ciphers.recv,
            &mut c1_unframer,
            &mut c1_plain_rx,
            4,
        )
        .await;
        assert_eq!(got_ack, expected_quick_ack_token);

        // 4. Client 2 concurrently: normal encrypted MTProto packet (`auth_key_id != 0`, no quick-ack)
        let (mut c2, mut c2_ciphers) = connect_faketls_client(proxy_addr, &secret).await;
        let mut c2_unframer = TlsUnframer::new();
        let mut c2_plain_rx = Vec::new();

        // Close Client 1 first while Client 2 stays open!
        drop(c1);

        let c2_payload = b"ENCRYPTED_MTPROTO_20";
        assert_eq!(c2_payload.len(), 20);
        let mut c2_frame = Vec::with_capacity(24);
        c2_frame.extend_from_slice(&(20u32).to_le_bytes());
        c2_frame.extend_from_slice(c2_payload);
        send_tls_app(&mut c2, &mut c2_ciphers.send, &c2_frame).await;

        let got_c2_hdr = recv_tls_app_exact(
            &mut c2,
            &mut c2_ciphers.recv,
            &mut c2_unframer,
            &mut c2_plain_rx,
            4,
        )
        .await;
        assert_eq!(u32::from_le_bytes(got_c2_hdr.try_into().unwrap()), 20);
        let got_c2_body = recv_tls_app_exact(
            &mut c2,
            &mut c2_ciphers.recv,
            &mut c2_unframer,
            &mut c2_plain_rx,
            20,
        )
        .await;
        assert_eq!(got_c2_body, c2_payload);
        drop(c2);

        // Wait briefly for RPC_PONG & RPC_CLOSE_CONN frames to arrive at mock MiddleProxy.
        for _ in 0..40 {
            if observed_pong.load(Ordering::Acquire) == expected_ping_id
                && observed_closes.lock().len() >= 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        // 5. Assert every wire-level MiddleProxy invariant!
        let reqs = observed_reqs.lock().clone();
        assert_eq!(reqs.len(), 2);

        let r1 = &reqs[0];
        assert_eq!(r1.ad_tag, expected_ad_tag);
        assert_eq!(r1.payload, req_pq_payload);
        assert_ne!(r1.flags & FLAG_HAS_AD_TAG, 0);
        assert_ne!(r1.flags & FLAG_PAD, 0);
        assert_ne!(
            r1.flags & FLAG_ENCRYPTED,
            0,
            "auth_key_id == 0 packet MUST set FLAG_ENCRYPTED!"
        );
        assert_ne!(
            r1.flags & FLAG_QUICK_ACK,
            0,
            "client quick-ack bit MUST set FLAG_QUICK_ACK!"
        );

        let r2 = &reqs[1];
        assert_eq!(r2.ad_tag, expected_ad_tag);
        assert_eq!(r2.payload, c2_payload);
        assert_eq!(
            r2.flags & FLAG_ENCRYPTED,
            0,
            "non-zero auth_key_id packet MUST NOT set FLAG_ENCRYPTED!"
        );
        assert_eq!(
            r2.flags & FLAG_QUICK_ACK,
            0,
            "non-quick-ack packet MUST NOT set FLAG_QUICK_ACK!"
        );
        assert_ne!(r1.conn_id, r2.conn_id);

        assert_eq!(
            observed_pong.load(Ordering::Acquire),
            expected_ping_id,
            "proxy MUST respond to RPC_PING with matching RPC_PONG!"
        );
        let closes = observed_closes.lock().clone();
        assert!(
            closes.contains(&r1.conn_id),
            "expected RPC_CLOSE_CONN for client 1!"
        );

        let alice = engine.metrics.user("alice");
        assert_eq!(alice.ad_tag_failed.load(Ordering::Relaxed), 0);
        assert_eq!(alice.ad_tag_skipped.load(Ordering::Relaxed), 0);
        assert!(alice.bytes_in.load(Ordering::Relaxed) >= 44);
        assert!(alice.bytes_out.load(Ordering::Relaxed) >= 48);

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
