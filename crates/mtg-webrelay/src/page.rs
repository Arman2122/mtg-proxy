//! Dynamic CSP-nonce-bearing WEB proxy v1 bridge HTML document generator.
//!
//! Embeds the cleaned ES5 `bridge.js` directly in the binary and sets exact
//! security headers (`Content-Security-Policy`, `Permissions-Policy`,
//! `Cross-Origin-Resource-Policy: same-origin`, `Content-Length`, and NO
//! `X-Frame-Options`/`COOP`/`COEP` so Telegram's loopback iframe fallback works!).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;

use crate::capability::parse_capability_strict;

/// Embedded cleaned ES5 bridge script.
pub const BRIDGE_JS: &str = include_str!("bridge.js");

/// Carrier mode announced in `TPROXY_BOOT` and `X-Carrier-Mode`.
pub const CARRIER_MODE: &str = "websocket";

const NONCE_BYTES: usize = 16;

const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
camera=(), display-capture=(), document-domain=(), encrypted-media=(), \
fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), \
midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), \
screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=()";

const PAGE_HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><script nonce=""#;
const PAGE_BOOT: &str = r#"">var TPROXY_BOOT="#;
const PAGE_TAIL: &str = "</script></body></html>";

#[derive(Debug, Error)]
pub enum PageError {
    #[error("bridge host is not a canonical hostname: {0:?}")]
    InvalidHost(String),
    #[error("bootstrap token is not canonical base64url")]
    InvalidToken,
    #[error("CSPRNG error: {0}")]
    Rng(String),
}

/// Rendered single-use bridge HTML document + exact HTTP response headers.
#[derive(Debug, Clone)]
pub struct BridgeDocument {
    pub html: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

/// Bridge HTML generator bound to one canonical public hostname.
#[derive(Debug, Clone)]
pub struct BridgePage {
    host: String,
    csp_prefix: String,
    csp_suffix: String,
}

impl BridgePage {
    pub fn new(host: &str) -> Result<Self, PageError> {
        if host.is_empty()
            || host.len() > 253
            || !host.contains('.')
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            return Err(PageError::InvalidHost(host.to_owned()));
        }

        let csp_prefix = format!(
            "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://{host}; \
             font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; \
             frame-src 'none'; img-src 'none'; manifest-src 'none'; media-src 'none'; \
             object-src 'none'; script-src 'nonce-"
        );
        let csp_suffix =
            "'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts"
                .to_owned();

        Ok(Self {
            host: host.to_owned(),
            csp_prefix,
            csp_suffix,
        })
    }

    /// Render a single-use bridge HTML document with a fresh 128-bit CSP nonce
    /// and exact `Content-Length` header.
    pub fn render(&self, bootstrap_token: &str) -> Result<BridgeDocument, PageError> {
        if parse_capability_strict(bootstrap_token).is_none() {
            return Err(PageError::InvalidToken);
        }

        let mut nonce_raw = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce_raw).map_err(|e| PageError::Rng(e.to_string()))?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce_raw);

        // Both host (lowercase LDH) and token (base64url) contain zero JSON-escapable chars,
        // and we format as valid JSON object identical to Go `json.Marshal`.
        let boot_json = format!(
            r#"{{"host":"{}","mode":"{}","token":"{}"}}"#,
            self.host, CARRIER_MODE, bootstrap_token
        );

        let mut html = Vec::with_capacity(
            PAGE_HEAD.len()
                + nonce.len()
                + PAGE_BOOT.len()
                + boot_json.len()
                + 2
                + BRIDGE_JS.len()
                + PAGE_TAIL.len(),
        );
        html.extend_from_slice(PAGE_HEAD.as_bytes());
        html.extend_from_slice(nonce.as_bytes());
        html.extend_from_slice(PAGE_BOOT.as_bytes());
        html.extend_from_slice(boot_json.as_bytes());
        html.extend_from_slice(b";\n");
        html.extend_from_slice(BRIDGE_JS.as_bytes());
        html.extend_from_slice(PAGE_TAIL.as_bytes());

        let csp = format!("{}{nonce}{}", self.csp_prefix, self.csp_suffix);
        let headers = vec![
            ("Content-Type", "text/html; charset=utf-8".to_owned()),
            ("Content-Length", html.len().to_string()),
            ("Cache-Control", "no-store".to_owned()),
            ("Pragma", "no-cache".to_owned()),
            ("Referrer-Policy", "no-referrer".to_owned()),
            ("X-Content-Type-Options", "nosniff".to_owned()),
            ("X-Dns-Prefetch-Control", "off".to_owned()),
            ("Permissions-Policy", PERMISSIONS_POLICY.to_owned()),
            ("Cross-Origin-Resource-Policy", "same-origin".to_owned()),
            ("Content-Security-Policy", csp),
        ];

        Ok(BridgeDocument { html, headers })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn bridge_page_headers_and_optional_playwright_harness() {
        let page = BridgePage::new("proxy.example.test").unwrap();
        let boot_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let capability = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let doc = page.render(boot_token).unwrap();

        let header_map: BTreeMap<String, String> = doc
            .headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();

        assert_eq!(header_map["Content-Type"], "text/html; charset=utf-8");
        assert_eq!(header_map["Content-Length"], doc.html.len().to_string());
        assert_eq!(header_map["Cross-Origin-Resource-Policy"], "same-origin");
        assert!(
            header_map["Content-Security-Policy"].contains("frame-ancestors http://127.0.0.1:*")
        );
        assert!(!header_map.contains_key("X-Frame-Options"));
        assert!(!header_map.contains_key("Cross-Origin-Opener-Policy"));
        assert!(!header_map.contains_key("Cross-Origin-Embedder-Policy"));

        let fixture = serde_json::json!({
            "capability": capability,
            "html": String::from_utf8(doc.html).unwrap(),
            "headers": header_map,
        });

        if let Ok(out_path) = std::env::var("MTG_WRITE_BRIDGE_FIXTURE") {
            std::fs::write(&out_path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
        }

        if std::env::var("MTG_REQUIRE_BROWSER_HARNESS").as_deref() == Ok("1") {
            let dir = tempfile::tempdir().unwrap();
            let fix_path = dir.path().join("fixture.json");
            std::fs::write(&fix_path, serde_json::to_vec(&fixture).unwrap()).unwrap();
            let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../test/webbridge/harness.mjs");
            let status = std::process::Command::new("node")
                .arg(&harness)
                .arg(&fix_path)
                .status()
                .expect("failed to invoke node Playwright harness");
            assert!(status.success(), "Playwright harness exited with {status}");
        }
    }
}
