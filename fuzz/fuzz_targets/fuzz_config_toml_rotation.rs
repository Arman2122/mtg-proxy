#![no_main]

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use mtg_config::{Config, PreparedRotation, RotationRequest};

fuzz_target!(|data: &[u8]| {
    if let Ok(cfg) = Config::parse(data) {
        let _ = cfg.validate();
        let _ = cfg.validate_web();
        let _ = cfg.redacted_json();
    }
    let req = RotationRequest {
        name: "alice".to_owned(),
        rotate: true,
        until: None,
        end_overlap: false,
        prune: true,
        now: Utc::now(),
    };
    let _ = PreparedRotation::prepare(data, req);
});
