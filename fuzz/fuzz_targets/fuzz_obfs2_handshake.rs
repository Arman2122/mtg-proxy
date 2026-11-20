#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_core::TagSet;
use mtg_crypto::obfs2::{HANDSHAKE_FRAME_LEN, match_handshake};

fuzz_target!(|data: &[u8]| {
    if data.len() < HANDSHAKE_FRAME_LEN {
        return;
    }
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    frame.copy_from_slice(&data[..HANDSHAKE_FRAME_LEN]);
    let key = [0x11u8; 16];
    let _ = match_handshake(&frame, [Some(&key), None], TagSet::all());
});
