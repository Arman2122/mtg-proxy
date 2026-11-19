#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_protocol::middleproxy::{
    RpcFrameDecoder, parse_rpc_down_event, validate_handshake_response,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_rpc_down_event(data);
    let _ = validate_handshake_response(data);

    let mut dec = RpcFrameDecoder::new(None, 0);
    dec.push_wire_bytes(data);
    for _ in 0..16 {
        match dec.next_frame() {
            Ok(Some(body)) => {
                let _ = parse_rpc_down_event(&body);
            }
            Ok(None) | Err(_) => break,
        }
    }
});
