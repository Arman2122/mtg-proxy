#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mtg_webrelay::frame::{Direction, FrameLimits, decode_batch, decode_hello};

fuzz_target!(|data: &[u8]| {
    let _ = decode_hello(data);
    let b = Bytes::copy_from_slice(data);
    let _ = decode_batch(&b, FrameLimits::default(), Direction::ClientToRelay);
    let _ = decode_batch(&b, FrameLimits::default(), Direction::RelayToClient);
});
