use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mtg_core::{ConnectionTag, Secret, TagSet};
use mtg_crypto::{
    Aes256Ctr, FakeTlsCandidate, FusedCtrPair, build_outbound_handshake, match_handshake,
    parse_client_hello_bytes,
};

fn bench_aes_ctr(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256_ctr_16kib");
    group.throughput(Throughput::Bytes(16_384));

    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let iv1 = [0x33u8; 16];
    let iv2 = [0x44u8; 16];
    let mut buf = vec![0xa5u8; 16_384];

    group.bench_function("single_ctr", |b| {
        let mut ctr = Aes256Ctr::new(&k1, &iv1);
        b.iter(|| {
            ctr.apply_keystream(black_box(&mut buf));
        });
    });

    group.bench_function("fused_double_ctr", |b| {
        let mut pair = FusedCtrPair::new(Aes256Ctr::new(&k1, &iv1), Aes256Ctr::new(&k2, &iv2));
        b.iter(|| {
            pair.apply_fused_in_place(black_box(&mut buf));
        });
    });

    group.finish();
}

fn bench_faketls_scan(c: &mut Criterion) {
    let snap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/mtglib/internal/tls/fake/testdata/client-hello-ok-19dfe38384b9884b.json");
    let snap_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(snap_path).unwrap()).unwrap();
    let wire = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        snap_val["full"].as_str().unwrap(),
    )
    .unwrap();
    let parsed = parse_client_hello_bytes(&wire).unwrap();
    let snap_time = snap_val["time"].as_i64().unwrap();
    let now_ns = i128::from(snap_time) * 1_000_000_000;
    let skew_ns = 300i128 * 1_000_000_000;

    let secret = Secret::parse(
        "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d",
    )
    .unwrap();

    // 5,000 candidates (worst-case match at index 4999).
    let mut cands: Vec<FakeTlsCandidate> = (0..4999u32)
        .map(|i| {
            let mut k = [0u8; 16];
            k[..4].copy_from_slice(&i.to_le_bytes());
            FakeTlsCandidate::new(&k)
        })
        .collect();
    cands.push(FakeTlsCandidate::new(secret.key()));

    let mut group = c.benchmark_group("faketls_5000_scan");
    group.sample_size(20);

    group.bench_function("auto_shani_5000", |b| {
        b.iter(|| {
            assert_eq!(
                parsed.scan_candidates_at(black_box(&cands), now_ns, skew_ns),
                Some(4999)
            );
        });
    });

    group.bench_function("avx2_8way_5000", |b| {
        b.iter(|| {
            assert_eq!(
                parsed.scan_candidates_avx2_8way_at(black_box(&cands), now_ns, skew_ns),
                Some(4999)
            );
        });
    });

    group.finish();
}

fn bench_obfs2_scan(c: &mut Criterion) {
    let target = [0x99u8; 16];
    let (frame, _) = build_outbound_handshake(2, ConnectionTag::PADDED_INTERMEDIATE, Some(&target));
    let mut keys: Vec<[u8; 16]> = (0..999u32)
        .map(|i| {
            let mut k = [0u8; 16];
            k[..4].copy_from_slice(&i.to_le_bytes());
            k
        })
        .collect();
    keys.push(target);

    c.bench_function("obfs2_match_1000_keys", |b| {
        b.iter(|| {
            let iter = keys.iter().map(Some);
            let m = match_handshake(black_box(&frame), iter, TagSet::all()).unwrap();
            assert_eq!(m.index, 999);
        });
    });
}

criterion_group!(benches, bench_aes_ctr, bench_faketls_scan, bench_obfs2_scan);
criterion_main!(benches);
