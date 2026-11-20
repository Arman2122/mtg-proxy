//! Zero-allocation regression guard for `mtg-crypto` hot paths.
//!
//! Fails CI immediately if steady-state fused AES-256-CTR relay, FakeTLS
//! `verify_at`, pre-buffered `build_server_hello`, or Obfuscated2 `peek_tag` /
//! `match_handshake` allocates even a single byte on the heap.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use mtg_core::{ConnectionTag, TagSet};
use mtg_crypto::{
    Aes256Ctr, ClientHello, FakeTlsCandidate, FusedCtrPair, NoiseParams, SessionId, X25519KeyRing,
    build_outbound_handshake, build_server_hello, match_handshake, parse_client_hello_bytes,
    peek_tag,
};

struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: delegates directly to `std::alloc::System` while incrementing an atomic counter.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn assert_zero_allocs<F: FnOnce()>(label: &str, f: F) {
    let before = ALLOC_COUNT.load(Ordering::SeqCst);
    f();
    let after = ALLOC_COUNT.load(Ordering::SeqCst);
    assert_eq!(
        after - before,
        0,
        "hot path `{label}` performed {} heap allocations (must be 0)",
        after - before
    );
}

#[test]
fn hot_paths_perform_zero_heap_allocations() {
    // 1. Fused double-CTR and single CTR over 16 KiB chunk
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let iv1 = [0x33u8; 16];
    let iv2 = [0x44u8; 16];
    let mut fused = FusedCtrPair::new(Aes256Ctr::new(&k1, &iv1), Aes256Ctr::new(&k2, &iv2));
    let mut single = Aes256Ctr::new(&k1, &iv1);
    let mut buf = vec![0xa5u8; 16_384];

    assert_zero_allocs("FusedCtrPair::apply_fused_in_place(16KiB)", || {
        fused.apply_fused_in_place(&mut buf);
    });
    assert_zero_allocs("Aes256Ctr::apply_keystream(16KiB)", || {
        single.apply_keystream(&mut buf);
    });

    // 2. FakeTLS verify_at & pre-buffered build_server_hello
    let snap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/mtglib/internal/tls/fake/testdata/client-hello-ok-19dfe38384b9884b.json");
    let snap_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(snap_path).unwrap()).unwrap();
    let full_b64 = snap_val["full"].as_str().unwrap();
    let snap_time = snap_val["time"].as_i64().unwrap();
    let wire =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, full_b64).unwrap();
    let parsed = parse_client_hello_bytes(&wire).unwrap();
    let secret = mtg_core::Secret::parse(
        "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d",
    )
    .unwrap();
    let cand = FakeTlsCandidate::new(secret.key());
    let now_ns = i128::from(snap_time) * 1_000_000_000;
    let skew_ns = 300i128 * 1_000_000_000;

    // Warm up thread-local RNG before measuring ServerHello.
    let ring = X25519KeyRing::new(16);
    let ch = ClientHello {
        random: parsed.hello.random,
        session_id: SessionId::from_slice(&[0x55; 32]).unwrap(),
        cipher_suite: 0x1303,
    };
    let mut sh_buf = Vec::with_capacity(17_000);
    build_server_hello(&mut sh_buf, &cand, &ch, NoiseParams::default(), &ring);

    assert_zero_allocs("ParsedClientHello::verify_at", || {
        assert!(parsed.verify_at(&cand, now_ns, skew_ns));
    });
    assert_zero_allocs("build_server_hello(preallocated)", || {
        build_server_hello(&mut sh_buf, &cand, &ch, NoiseParams::default(), &ring);
    });

    // 3. Obfuscated2 peek_tag & match_handshake
    let obfs_secret = [0x77u8; 16];
    let decoy = [0x88u8; 16];
    let (frame, _) =
        build_outbound_handshake(2, ConnectionTag::PADDED_INTERMEDIATE, Some(&obfs_secret));
    let keys = [Some(&decoy), Some(&obfs_secret)];

    assert_zero_allocs("obfs2::peek_tag", || {
        let (tag, _, _) = peek_tag(&frame, Some(&obfs_secret));
        assert_eq!(tag, ConnectionTag::PADDED_INTERMEDIATE);
    });
    assert_zero_allocs("obfs2::match_handshake", || {
        let m = match_handshake(&frame, keys, TagSet::all()).unwrap();
        assert_eq!(m.index, 1);
    });
}
