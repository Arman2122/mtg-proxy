#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_protocol::tls_record::TlsUnframer;

fuzz_target!(|data: &[u8]| {
    let mut unframer = TlsUnframer::new();
    let mut full = data.to_vec();
    let _ = unframer.unframe_in_place(&mut full);

    // Also exercise arbitrary chunk splits using first byte as stride.
    if let Some((&stride_raw, rest)) = data.split_first() {
        let stride = (usize::from(stride_raw) % 64) + 1;
        let mut inc = TlsUnframer::new();
        for chunk in rest.chunks(stride) {
            let mut copy = chunk.to_vec();
            if inc.unframe_in_place(&mut copy).is_err() {
                break;
            }
        }
    }
});
