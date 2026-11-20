//! TOML configuration schema, env overlays, 8-rule retiring-secret evaluation,
//! credential-redacted logging, and byte-exact surgical secret rotation.

pub mod retiring;
pub mod rotation;
pub mod schema;
pub mod scrub;
pub mod types;

pub use retiring::{RETIRING_MISPLACED_USER_LINE, RetiringReport};
pub use rotation::{
    FileRotationResult, PreparedRotation, RemovedBlock, RotationError, RotationRequest,
    RotationSummary, is_panel_managed_path, rotate_file_atomic,
};
pub use schema::{
    AntiReplayConfig, Config, ConfigError, ConfigListener, ConfigRetiringSecret, ConfigSecretLimit,
    ConfigWeb, DEFAULT_HANDSHAKES_PER_IP, DefenseConfig, DomainFrontingConfig, DoppelgangerConfig,
    ENV_AD_TAG, ENV_BIND_TO, ENV_SECRET, ENV_SECRET_HOST, HandshakeBudgetConfig, KeepAliveConfig,
    ListConfig, ListenerPolicy, MISPLACED_RETIRING_USER, NetworkConfig, PrometheusConfig,
    StatsConfig, StatsdConfig, ThrottleConfig, TimeoutConfig,
};
pub use scrub::{
    UNKNOWN_KEY_LINE, VALUE_NOT_SHOWN, holds_a_value, reads_as_a_value, scrub_error_against_doc,
    shown_name, unknown_key_path, value_free_name, value_free_text,
};
pub use types::{
    AD_TAG_LEN, ClientIpSource, HandshakeBudgetMode, HostPort, PreferIp, StatsdTagFormat,
    TypeParseError, UnknownSecretAction, canonical_web_host, format_bytes_go, format_duration_go,
    parse_ad_tag, parse_bytes_str, parse_duration, redact_proxy_url,
};

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use chrono::{TimeZone as _, Utc};
    use mtg_core::Secret;

    use super::*;

    fn golden_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
    }

    #[test]
    fn panel_rendered_toml_matches_panel_config_string_golden_byte_exact() {
        let cfg_dir = golden_root().join("internal/config/testdata");
        let raw_toml = std::fs::read(cfg_dir.join("panel-rendered.toml")).unwrap();
        let expected_json =
            std::fs::read_to_string(cfg_dir.join("panel-config-string.golden")).unwrap();

        let cfg = Config::parse(&raw_toml).unwrap();
        cfg.validate().unwrap();
        cfg.validate_web().unwrap();
        assert!(
            cfg.unknown_keys.is_empty(),
            "unknown: {:?}",
            cfg.unknown_keys
        );

        let got = cfg.redacted_json();
        assert_eq!(got, expected_json.trim_end());
    }

    #[test]
    fn all_config_testdata_fixtures_validate_as_expected() {
        let cfg_dir = golden_root().join("internal/config/testdata");

        // Valid fixtures
        for ok_file in [
            "minimal.toml",
            "adtag.toml",
            "multi_bind.toml",
            "domain_fronting_host.toml",
            "domain_fronting_ip.toml",
            "domain_fronting_host_ip.toml",
            "public_ip.toml",
            "public_ip_v4_only.toml",
        ] {
            let raw = std::fs::read(cfg_dir.join(ok_file)).unwrap();
            let cfg = Config::parse(&raw).unwrap_or_else(|e| panic!("{ok_file}: {e}"));
            cfg.validate().unwrap_or_else(|e| panic!("{ok_file}: {e}"));
        }

        // Invalid fixtures (either Parse or Validate must fail)
        for bad_file in [
            "broken.toml",
            "empty_bind.toml",
            "duplicate_bind.toml",
            "invalid_bind_addr.toml",
            "non_string_bind.toml",
            "only_secret.toml",
            "adtag_unknown_secret.toml",
            "public_ip_invalid.toml",
        ] {
            let raw = std::fs::read(cfg_dir.join(bad_file)).unwrap();
            let res = Config::parse(&raw).and_then(|c| c.validate());
            assert!(res.is_err(), "{bad_file} unexpectedly succeeded");
        }
    }

    #[test]
    fn bare_integer_quota_and_explicit_zero_settings_preserved() {
        let toml = br#"
bind-to = "0.0.0.0:443"
[network]
tcp-not-sent-lowat = "0B"
[defense.anti-replay]
enabled = false
[defense.doppelganger]
scout-covers = false
[defense.handshake-budget]
per-ip-ms = 0
hints = false
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
[secret-limits.alice]
quota = 1048576
"#;
        let cfg = Config::parse(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.network.tcp_not_sent_lowat, Some(0));
        assert_eq!(cfg.defense.anti_replay.enabled, Some(false));
        assert_eq!(cfg.defense.doppelganger.scout_covers, Some(false));
        assert_eq!(cfg.defense.handshake_budget.per_ip_ms, Some(0));
        assert_eq!(cfg.defense.handshake_budget.hints, Some(false));
        assert_eq!(cfg.secret_limits["alice"].quota, Some(1_048_576));
    }

    #[test]
    fn all_10_rotation_corpus_golden_files_match_byte_for_byte() {
        let rot_dir = golden_root().join("internal/rotation/testdata");
        let test_now = Utc.with_ymd_and_hms(2026, 10, 8, 9, 30, 0).unwrap();
        let test_until = test_now + chrono::Duration::hours(24);
        let key_new: [u8; 16] = hex::decode("c0ffee00c0ffee00c0ffee00c0ffee00")
            .unwrap()
            .try_into()
            .unwrap();

        let make_req = |name: &str, prune: bool| RotationRequest {
            name: name.to_owned(),
            rotate: true,
            until: Some(test_until),
            end_overlap: false,
            prune,
            now: test_now,
        };

        let cases: &[(&str, RotationRequest, Option<&str>)] = &[
            ("example", make_req("alice", false), None),
            ("panel-quoted-keys", make_req("alice", false), None),
            ("dotted-secrets", make_req("bob", false), None),
            ("inline-secrets", make_req("bob smith", false), None),
            ("single-secret", make_req("default", false), None),
            ("crlf", make_req("alice", true), Some("existing-blocks")),
            ("no-final-newline", make_req("default", true), None),
            ("comments-above-secrets", make_req("alice", false), None),
            ("existing-blocks", make_req("alice", true), None),
            ("single-table-typo-block", make_req("alice", true), None),
        ];

        for (case_name, req, crlf_src) in cases {
            let (doc, expected) = if let Some(src) = crlf_src {
                let d = std::fs::read(rot_dir.join(format!("{src}.toml"))).unwrap();
                let g = std::fs::read(rot_dir.join(format!("{src}.golden"))).unwrap();
                let to_crlf = |b: Vec<u8>| {
                    String::from_utf8(b)
                        .unwrap()
                        .replace('\n', "\r\n")
                        .into_bytes()
                };
                (to_crlf(d), to_crlf(g))
            } else {
                (
                    std::fs::read(rot_dir.join(format!("{case_name}.toml"))).unwrap(),
                    std::fs::read(rot_dir.join(format!("{case_name}.golden"))).unwrap(),
                )
            };

            let prepared = PreparedRotation::prepare(&doc, req.clone())
                .unwrap_or_else(|e| panic!("prepare failed for {case_name}: {e}"));
            let old = prepared.primary().unwrap();
            let new_primary = Secret::from_parts(key_new, old.host(), old.mode());
            let out = prepared
                .apply(Some(&new_primary))
                .unwrap_or_else(|e| panic!("apply failed for {case_name}: {e}"));

            assert_eq!(
                out,
                expected,
                "byte mismatch in golden case {case_name}:\n--- GOT ---\n{}\n--- WANT ---\n{}",
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(&expected)
            );

            // Re-parse and verify resulting config!
            let parsed = Config::parse(&out).unwrap();
            parsed.validate().unwrap();
            assert_eq!(parsed.get_secrets().get(&req.name), Some(&new_primary));
            let rep = parsed.get_retiring_secrets(test_now);
            assert!(rep.lines.is_empty(), "{case_name}: {:?}", rep.lines);
        }
    }

    #[test]
    fn rotation_refuses_r0_key_revival_on_collision_removal() {
        let test_now = Utc.with_ymd_and_hms(2026, 10, 8, 9, 30, 0).unwrap();
        // Alice and Bob both have a retiring block for the SAME key -> rule 5 drops BOTH!
        // Running --end-overlap for bob would remove bob's block and REVIVE alice's!
        let doc = br#"
bind-to = "0.0.0.0:3128"

[[retiring-secret]]
name = "alice"
secret = "ee1111111111111111aaaaaaaaaaaaaaaa73746f726167652e676f6f676c65617069732e636f6d"
until = "2026-10-09T09:30:00Z"

[[retiring-secret]]
name = "bob"
secret = "ee1111111111111111aaaaaaaaaaaaaaaa73746f726167652e676f6f676c65617069732e636f6d"
until = "2026-10-09T09:30:00Z"

[secrets]
alice = "eea1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d473746f726167652e676f6f676c65617069732e636f6d"
bob = "eeb5b5b5b5c6c6c6c6d7d7d7d7e8e8e8e873746f726167652e676f6f676c65617069732e636f6d"
"#;
        let req = RotationRequest {
            name: "bob".to_owned(),
            rotate: false,
            until: None,
            end_overlap: true,
            prune: false,
            now: test_now,
        };
        let err = PreparedRotation::prepare(doc, req).unwrap_err();
        assert!(
            matches!(err, RotationError::KeyRevived(_)),
            "expected KeyRevived, got: {err}"
        );
    }

    #[test]
    fn atomic_file_rotation_and_panel_guard() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("mtg.toml");
        let src =
            std::fs::read(golden_root().join("internal/rotation/testdata/example.toml")).unwrap();
        std::fs::write(&cfg_path, &src).unwrap();

        let now = Utc.with_ymd_and_hms(2026, 10, 8, 9, 30, 0).unwrap();
        let req = RotationRequest {
            name: "alice".to_owned(),
            rotate: true,
            until: Some(now + chrono::Duration::hours(24)),
            end_overlap: false,
            prune: false,
            now,
        };

        // Panel path guard
        let panel_err = rotate_file_atomic(
            Path::new("/etc/p-ui/mtproto/7.toml"),
            &req,
            None,
            false,
            true,
        )
        .unwrap_err();
        assert!(matches!(panel_err, RotationError::PanelManagedPath(_)));

        // Real atomic write on Linux ext4/tmpfs
        let res = rotate_file_atomic(&cfg_path, &req, None, false, false).unwrap();
        assert!(!res.summary.no_op);
        assert!(res.new_primary.is_some());
        let after = Config::parse(&std::fs::read(&cfg_path).unwrap()).unwrap();
        after.validate().unwrap();
        assert_eq!(after.get_secrets().get("alice"), res.new_primary.as_ref());
        // Lock file must have been cleaned up.
        assert!(!dir.path().join("mtg.toml.rotate.lock").exists());
    }

    #[test]
    fn env_overlay_prefers_mtg_prefix_and_clears_named_secrets() {
        let raw = br#"
bind-to = "0.0.0.0:3128"
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
"#;
        let mut cfg = Config::parse(raw).unwrap();
        cfg.apply_environment_with(|k| match k {
            "MTG_SECRET" => Some("0102030405060708090a0b0c0d0e0f10".to_owned()),
            "MTG_SECRET_HOST" => Some("example.com".to_owned()),
            "MTG_BIND_TO" => Some("127.0.0.1:443, [::1]:443".to_owned()),
            _ => None,
        })
        .unwrap();
        cfg.validate().unwrap();
        assert!(cfg.secrets.is_empty());
        assert_eq!(cfg.bind_to.len(), 2);
        assert_eq!(cfg.get_secrets()["default"].host(), "example.com");
    }
}
