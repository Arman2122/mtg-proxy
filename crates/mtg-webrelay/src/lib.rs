//! Pure-Rust WEB proxy v1 relay:
//! - Constant-time capability derivation & live+retired profile [`capability::Registry`]
//! - Precomputed-midstate zero-alloc HMAC-SHA256 [`token::Signer`] with fixed Tier-2 lenient recognition
//! - Shared-Frame v1 wire codec ([`frame`])
//! - Cleaned ES5 `bridge.js` & dynamic CSP-nonce [`page::BridgePage`]
//! - Strict server-only RFC 6455 WebSocket ([`ws`]) with 64-bit SWAR unmasking & `writev`
//! - Single-task-per-session readiness-gated multiplexer ([`session`])
//! - Leak-proof 3-tier [`origin::Origin`] + cover sites ([`cover`]) + loopback `/stats` ([`metrics`])
//! - Standalone `mtg-proxy web-relay` server with `SIGHUP` + 2s file watcher ([`server`]).

pub mod capability;
pub mod cover;
pub mod frame;
pub mod metrics;
pub mod origin;
pub mod page;
pub mod server;
pub mod session;
pub mod store;
pub mod token;
pub mod ws;

use std::path::Path;

use thiserror::Error;

pub use capability::{
    BRIDGE_CONTEXT_LABEL, CAPABILITY_LEN, Capability, CapabilityError, MAX_PROFILES, Registry,
    canonical_host, derive_capability, parse_capability_lenient, parse_capability_strict,
    web_secret,
};
pub use cover::{CoverError, CoverHandler, CoverSite, StaticCover, UpstreamCover};
pub use frame::{
    Direction, Frame, FrameError, FrameLimits, FrameType, HEADER_SIZE, INITIAL_WINDOW,
    MAX_BATCH_BYTES, MAX_FRAMES_PER_BATCH, MAX_PAYLOAD_SIZE, MAX_RELAY_DATA_CHUNK,
    MAX_SESSION_CREATE_BODY, MAX_STREAM_ID, PROTOCOL_VERSION, WELCOME_WIRE, WINDOW_PAYLOAD_SIZE,
    decode_batch, decode_hello,
};
pub use metrics::{
    RelayByteStats, RelayCounters, RelayRefusedStats, RelaySessionStats, RelayStats,
    RelayStreamStats, handle_stats_request,
};
pub use origin::{
    BRIDGE_QUERY, CARRIER_PATH, Origin, OriginError, OriginOptions, SESSION_PATH,
    SUBPROTOCOL_PREFIX,
};
pub use page::{BRIDGE_JS, BridgeDocument, BridgePage, CARRIER_MODE, PageError};
pub use server::{
    PrefixedStream, build_origin_from_config, reload_web_profiles, run_web_relay,
    spawn_origin_server, spawn_stats_server,
};
pub use session::{
    AsyncStream, BackendDialer, BoxedStream, CONTROL_RESERVE_ITEMS, DEFAULT_DIAL_TIMEOUT,
    DEFAULT_GLOBAL_PENDING_BYTES, DEFAULT_GLOBAL_PENDING_ITEMS, DEFAULT_MAX_STREAMS,
    DEFAULT_SESSION_PENDING_BYTES, DEFAULT_SESSION_PENDING_ITEMS, GlobalBudget, MAX_TOMBSTONES,
    PlanError, SessionConfig, TcpProxyBackend, serve_session,
};
pub use store::{
    BOOTSTRAP_TTL, CreateOutcome, DEFAULT_MAX_SESSIONS, RECONNECT_GRACE, SessionStore,
};
pub use token::{Signer, TOKEN_KEY_LEN, TOKEN_LEN, TokenError, TokenKind};

/// Top-level WEB relay errors returned to CLI callers.
#[derive(Debug, Error)]
pub enum WebRelayError {
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("invalid [web] configuration: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Runtime(String),
}

/// Atomically write a fresh 32-byte CSPRNG signing key (`0600`) to `path`,
/// refusing to overwrite an existing key file.
pub fn generate_token_key(path: &Path) -> Result<(), WebRelayError> {
    token::generate_token_key(path)?;
    Ok(())
}

#[cfg(test)]
mod integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use bytes::{Bytes, BytesMut};
    use http::{Method, Request, StatusCode};
    use http_body_util::BodyExt as _;
    use mtg_config::ClientIpSource;
    use mtg_core::{Secret, SecretMode};
    use mtg_protocol::proxyproto::{ProxyParseStatus, ProxyProtoMode, parse_proxy_header};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    use super::*;
    use crate::ws::unmask_in_place;

    #[derive(Debug)]
    struct MarkerCover;

    impl CoverHandler for MarkerCover {
        fn serve(
            &self,
            _req: Request<Bytes>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = http::Response<http_body_util::Full<Bytes>>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                http::Response::builder()
                    .status(StatusCode::OK)
                    .header("x-cover", "yes")
                    .body(http_body_util::Full::new(Bytes::from_static(b"COVER_SITE")))
                    .unwrap()
            })
        }
    }

    #[tokio::test]
    async fn three_tier_origin_never_leaks_live_retired_padded_or_query_key_credentials() {
        let s_live = Secret::generate_mode(SecretMode::FakeTls, "cover.example.com").unwrap();
        let s_ret = Secret::generate_mode(SecretMode::Dd, "").unwrap();
        let signer = Signer::new(&[0x5A; TOKEN_KEY_LEN]).unwrap();
        let counters = Arc::new(RelayCounters::default());

        let origin = Origin::new(OriginOptions {
            host: "relay.example.test".to_owned(),
            secrets: vec![s_live.clone()],
            retired: vec![s_ret.clone()],
            signer: signer.clone(),
            cover: CoverSite::Custom(Arc::new(MarkerCover)),
            backend: Arc::new(TcpProxyBackend::new(
                "127.0.0.1:1".parse().unwrap(),
                Duration::from_secs(1),
            )),
            limits: FrameLimits::default(),
            max_sessions: 1,
            max_streams: 8,
            client_ip_source: ClientIpSource::XForwardedFor,
            counters: Some(Arc::clone(&counters)),
        })
        .unwrap();

        let live_cap = derive_capability(&web_secret(&s_live), "relay.example.test").unwrap();
        let ret_cap = derive_capability(&web_secret(&s_ret), "relay.example.test").unwrap();

        // 1. Tier-3 ordinary visit -> COVER_SITE
        let r_cover = Request::builder().uri("/").body(Bytes::new()).unwrap();
        let resp = origin.handle_bytes(r_cover).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-cover").unwrap(), "yes");

        // 2. Tier-1 valid bridge request -> 200 HTML with CSP nonce & TPROXY_BOOT
        let r_bridge = Request::builder()
            .uri(format!("/?bridge={}", live_cap.encode_base64url()))
            .body(Bytes::new())
            .unwrap();
        let resp = origin.handle_bytes(r_bridge).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("content-security-policy"));
        assert!(!resp.headers().contains_key("x-frame-options"));
        let html = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("var TPROXY_BOOT="));
        // Extract minted bootstrap token from TPROXY_BOOT JSON!
        let tok_marker = "\"token\":\"";
        let start = html.find(tok_marker).unwrap() + tok_marker.len();
        let end = html[start..].find('"').unwrap() + start;
        let boot_token = html[start..end].to_owned();
        assert_eq!(boot_token.len(), TOKEN_LEN);

        // 3. Tier-2 security checks — EVERY ONE MUST get local 404 (NEVER cover)!
        let padded_live = STANDARD.encode(live_cap.0);
        let padded_tok = STANDARD.encode(URL_SAFE_NO_PAD.decode(&boot_token).unwrap());
        let leak_cases = [
            // Padded standard base64 capability in bridge query
            Request::builder()
                .uri(format!("/?bridge={padded_live}"))
                .body(Bytes::new())
                .unwrap(),
            // Retired capability in bridge query
            Request::builder()
                .uri(format!("/?bridge={}", ret_cap.encode_base64url()))
                .body(Bytes::new())
                .unwrap(),
            // Query KEY carrying capability (regression fix for Go bug!)
            Request::builder()
                .uri(format!("/?{}=1", live_cap.encode_base64url()))
                .body(Bytes::new())
                .unwrap(),
            // Padded standard base64 bootstrap token in arbitrary header (regression fix!)
            Request::builder()
                .uri("/random/path")
                .header("x-debug", &padded_tok)
                .body(Bytes::new())
                .unwrap(),
            // Cookie attached to POST /api/v1/session -> refused with 404!
            Request::builder()
                .method(Method::POST)
                .uri(SESSION_PATH)
                .header("authorization", format!("Bearer {boot_token}"))
                .header("cookie", "sid=evil")
                .body(Bytes::from_static(b"\x10\x00\x00\x00\x00\x00\x00\x01\x01"))
                .unwrap(),
        ];
        for req in leak_cases {
            let r = origin.handle_bytes(req).await;
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
            assert!(r.headers().get("x-cover").is_none());
            assert_eq!(r.headers().get("cache-control").unwrap(), "no-store");
        }

        // 4. Valid POST /api/v1/session -> 200 OK with X-Session-Token & WELCOME_WIRE
        let hello = Bytes::from_static(b"\x10\x00\x00\x00\x00\x00\x00\x01\x01");
        let r_sess = Request::builder()
            .method(Method::POST)
            .uri(SESSION_PATH)
            .header("authorization", format!("Bearer {boot_token}"))
            .body(hello.clone())
            .unwrap();
        let resp = origin.handle_bytes(r_sess).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sess_token = resp
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(resp.headers().get("x-down-cursor").unwrap(), "0");
        assert_eq!(resp.headers().get("x-carrier-mode").unwrap(), "websocket");
        assert_eq!(
            resp.into_body().collect().await.unwrap().to_bytes(),
            &WELCOME_WIRE[..]
        );

        // 5. Second bridge hits max_sessions=1 -> 503 Retry-After: 1 (bootstrap UNSPENT!)
        let r_bridge2 = Request::builder()
            .uri(format!("/?bridge={}", live_cap.encode_base64url()))
            .body(Bytes::new())
            .unwrap();
        let html2 = String::from_utf8(
            origin
                .handle_bytes(r_bridge2)
                .await
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let s2 = html2.find(tok_marker).unwrap() + tok_marker.len();
        let e2 = html2[s2..].find('"').unwrap() + s2;
        let boot2 = html2[s2..e2].to_owned();

        let r_cap = Request::builder()
            .method(Method::POST)
            .uri(SESSION_PATH)
            .header("authorization", format!("Bearer {boot2}"))
            .body(hello.clone())
            .unwrap();
        let resp_503 = origin.handle_bytes(r_cap).await;
        assert_eq!(resp_503.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp_503.headers().get("retry-after").unwrap(), "1");

        // 6. DELETE first session -> 204 No Content; retry boot2 -> 200 OK!
        let r_del = Request::builder()
            .method(Method::DELETE)
            .uri(SESSION_PATH)
            .header("authorization", format!("Bearer {sess_token}"))
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            origin.handle_bytes(r_del).await.status(),
            StatusCode::NO_CONTENT
        );

        let r_retry = Request::builder()
            .method(Method::POST)
            .uri(SESSION_PATH)
            .header("authorization", format!("Bearer {boot2}"))
            .body(hello)
            .unwrap();
        assert_eq!(origin.handle_bytes(r_retry).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn end_to_end_live_websocket_multiplex_proxy_v2_and_stats() {
        // 1. Start mock loopback MTProto backend verifying HAProxy PROXY v2 header + echoing payload!
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        let expected_client_ip: SocketAddr = "203.0.113.77:0".parse().unwrap();

        let backend_task = tokio::spawn(async move {
            let (mut sock, _) = backend_listener.accept().await.unwrap();
            let mut hdr_buf = vec![0u8; 28];
            sock.read_exact(&mut hdr_buf).await.unwrap();
            let ProxyParseStatus::Complete { header, consumed } =
                parse_proxy_header(&hdr_buf, ProxyProtoMode::Required).unwrap()
            else {
                panic!("expected complete PROXY v2 header");
            };
            assert_eq!(consumed, 28);
            assert_eq!(header.source.unwrap().ip(), expected_client_ip.ip());

            // Echo payload back
            let mut echo = [0u8; 64];
            let n = sock.read(&mut echo).await.unwrap();
            sock.write_all(&echo[..n]).await.unwrap();
        });

        // 2. Start live Origin server + separate loopback /stats server!
        let secret = Secret::generate_mode(SecretMode::Dd, "").unwrap();
        let signer = Signer::new(&[0x77; TOKEN_KEY_LEN]).unwrap();
        let counters = Arc::new(RelayCounters::default());
        counters.set_profiles(vec!["alice".to_owned()]);

        let origin = Arc::new(
            Origin::new(OriginOptions {
                host: "e2e.example.test".to_owned(),
                secrets: vec![secret.clone()],
                retired: vec![],
                signer,
                cover: CoverSite::Custom(Arc::new(MarkerCover)),
                backend: Arc::new(TcpProxyBackend::new(backend_addr, Duration::from_secs(5))),
                limits: FrameLimits::default(),
                max_sessions: 16,
                max_streams: 16,
                client_ip_source: ClientIpSource::XForwardedFor,
                counters: Some(Arc::clone(&counters)),
            })
            .unwrap(),
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (origin_addr, origin_srv) = spawn_origin_server(
            Arc::clone(&origin),
            "127.0.0.1:0",
            false,
            shutdown_rx.clone(),
        )
        .await
        .unwrap();
        let (stats_addr, stats_srv) = spawn_stats_server(
            Arc::clone(&counters),
            Arc::clone(origin.store()),
            "127.0.0.1:0",
            shutdown_rx,
        )
        .await
        .unwrap();

        // 3. Mint bootstrap & session via Origin API directly, then connect over real TCP WS!
        let cap = derive_capability(&web_secret(&secret), "e2e.example.test").unwrap();
        let boot_resp = origin
            .handle_bytes(
                Request::builder()
                    .uri(format!("/?bridge={}", cap.encode_base64url()))
                    .body(Bytes::new())
                    .unwrap(),
            )
            .await;
        let html = String::from_utf8(
            boot_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let s = html.find("\"token\":\"").unwrap() + 9;
        let e = html[s..].find('"').unwrap() + s;
        let boot_tok = &html[s..e];

        let sess_resp = origin
            .handle_bytes(
                Request::builder()
                    .method(Method::POST)
                    .uri(SESSION_PATH)
                    .header("authorization", format!("Bearer {boot_tok}"))
                    .body(Bytes::from_static(b"\x10\x00\x00\x00\x00\x00\x00\x01\x01"))
                    .unwrap(),
            )
            .await;
        let sess_tok = sess_resp
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        // 4. Perform real HTTP/1.1 WebSocket upgrade over loopback TCP!
        let mut ws_tcp = TcpStream::connect(origin_addr).await.unwrap();
        let upgrade_req = format!(
            "GET {CARRIER_PATH} HTTP/1.1\r\n\
             Host: e2e.example.test\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: {SUBPROTOCOL_PREFIX}{sess_tok}\r\n\
             X-Forwarded-For: 203.0.113.77\r\n\r\n"
        );
        ws_tcp.write_all(upgrade_req.as_bytes()).await.unwrap();

        let mut resp_buf = Vec::new();
        let mut byte = [0u8; 1];
        while !resp_buf.ends_with(b"\r\n\r\n") {
            ws_tcp.read_exact(&mut byte).await.unwrap();
            resp_buf.push(byte[0]);
        }
        let resp_str = String::from_utf8(resp_buf).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(resp_str.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

        // 5. Send Shared-Frame v1 OPEN(1) + DATA(1, "ping-rust-webrelay") in ONE masked binary WS frame!
        let mut batch = BytesMut::new();
        Frame::Open { stream_id: 1 }
            .encode_into(&mut batch, FrameLimits::default(), Direction::ClientToRelay)
            .unwrap();
        Frame::Data {
            stream_id: 1,
            payload: Bytes::from_static(b"ping-rust-webrelay"),
        }
        .encode_into(&mut batch, FrameLimits::default(), Direction::ClientToRelay)
        .unwrap();

        let mask = [0x31, 0x41, 0x59, 0x26];
        let mut masked_payload = batch.to_vec();
        unmask_in_place(&mut masked_payload, mask);
        let mut ws_frame = vec![0x82, 0x80 | (masked_payload.len() as u8)];
        ws_frame.extend_from_slice(&mask);
        ws_frame.extend_from_slice(&masked_payload);
        ws_tcp.write_all(&ws_frame).await.unwrap();

        // 6. Read unmasked server WS binary frame carrying echoed DATA(1, "ping-rust-webrelay")!
        let mut srv_hdr = [0u8; 2];
        ws_tcp.read_exact(&mut srv_hdr).await.unwrap();
        assert_eq!(srv_hdr[0], 0x82);
        let srv_len = usize::from(srv_hdr[1] & 0x7f);
        let mut srv_body = vec![0u8; srv_len];
        ws_tcp.read_exact(&mut srv_body).await.unwrap();

        let down_frames = decode_batch(
            &Bytes::from(srv_body),
            FrameLimits::default(),
            Direction::RelayToClient,
        )
        .unwrap();
        assert!(down_frames.contains(&Frame::Data {
            stream_id: 1,
            payload: Bytes::from_static(b"ping-rust-webrelay"),
        }));

        backend_task.await.unwrap();

        // 7. Query separate loopback /stats HTTP endpoint!
        let mut stats_tcp = TcpStream::connect(stats_addr).await.unwrap();
        stats_tcp
            .write_all(b"GET /stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut stats_raw = Vec::new();
        stats_tcp.read_to_end(&mut stats_raw).await.unwrap();
        let stats_str = String::from_utf8(stats_raw).unwrap();
        let json_body = stats_str.split("\r\n\r\n").nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json_body).unwrap();
        assert_eq!(parsed["profiles"][0], "alice");
        assert_eq!(parsed["sessions"]["created"], 1);
        assert_eq!(parsed["sessions"]["attached"], 1);
        assert_eq!(parsed["streams"]["opened"], 1);
        assert_eq!(parsed["bytes"]["up"], 18);
        assert_eq!(parsed["bytes"]["down"], 18);

        drop(ws_tcp);
        let _ = shutdown_tx.send(true);
        let _ = origin_srv.await;
        let _ = stats_srv.await;
    }
}
