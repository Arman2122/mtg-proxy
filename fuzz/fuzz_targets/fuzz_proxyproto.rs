#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_protocol::proxyproto::{ProxyProtoMode, parse_proxy_header};

fuzz_target!(|data: &[u8]| {
    let _ = parse_proxy_header(data, ProxyProtoMode::Required);
    let _ = parse_proxy_header(data, ProxyProtoMode::Optional);
    // Incremental prefix safety
    for end in 0..=data.len().min(128) {
        let _ = parse_proxy_header(&data[..end], ProxyProtoMode::Optional);
    }
});
