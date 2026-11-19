#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_crypto::faketls::{FakeTlsCandidate, ParseStatus, parse_client_hello_incremental};

fuzz_target!(|data: &[u8]| {
    if let Ok(ParseStatus::Complete { parsed, .. }) = parse_client_hello_incremental(data) {
        let key = [0x42u8; 16];
        let cand = FakeTlsCandidate::new(&key);
        let _ = parsed.verify_at(&cand, 1_700_000_000_000_000_000, 3_000_000_000);
    }
});
