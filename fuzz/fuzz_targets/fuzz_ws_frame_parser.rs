#![no_main]

use libfuzzer_sys::fuzz_target;
use mtg_webrelay::ws::WsReader;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    rt.block_on(async {
        let mut reader = WsReader::new(data, 64 * 1024);
        for _ in 0..16 {
            if reader.read_event().await.is_err() {
                break;
            }
        }
    });
});
