# Contributing

Pull requests are welcome. So are bug reports, benchmarks on new Linux kernels/architectures, questions, and "I tried to set this up and got stuck at step four" — the last one is genuinely useful, because it is the only way documentation gets tested.

## Where things go

| You want to | Go here |
|---|---|
| Ask how to do something | [Discussions → Q&A](https://github.com/Arman2122/mtg-proxy/discussions/categories/q-a) |
| Report something broken | [Open an issue](https://github.com/Arman2122/mtg-proxy/issues/new/choose) |
| Suggest something, unsure yet | [Discussions](https://github.com/Arman2122/mtg-proxy/discussions) |
| Report a vulnerability | [Privately](SECURITY.md) — never a public issue |
| Read the documentation | [The wiki](https://github.com/Arman2122/mtg-proxy/wiki) |

## Getting set up

`mtg-proxy` v2.0+ is a pure-Rust Linux workspace (`edition = "2024"`, Rust 1.89+ stable). You need a Linux host (or WSL2 on Windows) with `rustup` and a C toolchain (`gcc`, `make`, `pkg-config` for `tikv-jemalloc-sys` and `ring`).

```bash
git clone https://github.com/Arman2122/mtg-proxy.git
cd mtg-proxy
cargo build --release --bin mtg-proxy
```

If you use [mise](https://mise.jdx.dev/), `mise install && mise run build` sets up the toolchain and builds the optimized binary.

## Running the checks

Run what [CI](.github/workflows/ci.yml) runs before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

To cross-check ARM64 (`aarch64` ARMv8 AES/SHA-2 intrinsics) from an `x86_64` host:

```bash
rustup target add aarch64-unknown-linux-gnu
cargo clippy -p mtg-core -p mtg-crypto -p mtg-protocol -p mtg-config \
    --target aarch64-unknown-linux-gnu -- -D warnings
```

To run the interleaved Linux benchmark harness against another binary:

```bash
cargo build --release --bin mtg-proxy --bin mtg-bench
./target/release/mtg-bench ab \
    --bin-a /path/to/baseline-mtg-proxy \
    --bin-b ./target/release/mtg-proxy \
    --rounds 3
```

### The WEB bridge browser harness

The WEB proxy's bridge page has an end-to-end test that runs inside real Chromium via Playwright. It catches browser/WebView/CSP regressions that static unit tests cannot see.

One-time setup:

```bash
cd test/webbridge && npm ci && npx playwright install chromium
```

Run with strict failure on missing browser (the exact CI gate):

```bash
MTG_REQUIRE_BROWSER_HARNESS=1 cargo test -p mtg-webrelay \
    bridge_page_headers_and_optional_playwright_harness -- --nocapture
```

## Engineering standards

- **Keep idle connection memory tiny:** `mtg-engine::tests::steady_state_connection_future_size_guard` enforces hard upper bounds on `DirectRelay` (`<= 1,536 B`), `DirectRelay::run()` (`<= 256 B`), and `handle_faketls_connection` / `handle_obfs2_connection` (`<= 1,920 B`). Box cold or short-lived async phases (`handshake`, `fronting`, `pacing`, `MiddleProxy`) so they never bloat long-lived idle Tokio tasks.
- **Zero heap allocations on hot crypto paths:** `crates/mtg-crypto/tests/zero_alloc.rs` guards `parse_client_hello_incremental`, `scan_candidates_at`, `build_server_hello`, `match_handshake`, and `FusedCtrPair::apply_fused_in_place`.
- **Every `unsafe` block must carry a `// SAFETY:` justification** and compile cleanly with `unsafe_op_in_unsafe_fn = "warn"` and `-D warnings` on both `x86_64` and `aarch64`.
- **Preserve additive contracts:** Release asset names, TOML keys, Management API JSON schemas, and wire formats are external contracts panels and clients depend on. Add rather than rename.
- **Secrets never reach logs:** Always redact credentials via `Config::redacted_json()` and custom `fmt::Debug` implementations (`Secret`, `Aes256EncKey`, `ProxyEndpoint`).
- **Wire constants come from specs and golden vectors:** Pin test vectors in `tests/golden/` rather than self-generated expectations.

## Workspace layout

| Crate | Responsibility |
|---|---|
| `crates/mtg-core` | Secrets, `IpUnit`, limits, monotonic `RotationClock` |
| `crates/mtg-crypto` | Hardware VAES/AES-NI/ARMv8-AES fused-CTR, 4-way SHA-NI / 8-way AVX2 / ARMv8-SHA2 FakeTLS, Obfuscated2, AES-CBC |
| `crates/mtg-protocol` | TLS record unframer, PROXY protocol v1/v2, MiddleProxy RPC, Doppelganger MLE/DRS, Telegram DC `req_pq_multi` probe |
| `crates/mtg-net` | Linux sockopts & listener inheritance, cgroup CPU affinity, `epoll`/`io_uring` drivers, `splice(2)`, DNS/DoH/DoT, Happy Eyeballs DC router, proxy pool, MiddleProxy multiplexer |
| `crates/mtg-governance` | Sharded `AddressRegistry`, `ClientTable`, lock-free GCRA + fair-share water-level pacing, bans, anti-replay, `MatchHints`, `ScanBudget`, FireHOL IP filters |
| `crates/mtg-webrelay` | Telegram Desktop 7.1+ WEB proxy origin, strict RFC 6455 WebSocket, shared binary framing, bridge HTML/CSP nonce, 2s live config watcher |
| `crates/mtg-config` | Strict TOML parser, env overlays, secret redaction, lossless `toml_edit` rotation |
| `crates/mtg-engine` | Pinned thread-per-core workers, boxed handshake doors, single-poll `DirectRelay`, `splice(2)` fronting, live Doppelganger cover scouting, metrics |
| `crates/mtg-api` | 19-route Penhoon Management HTTP API, constant-time Bearer auth, Prometheus & StatsD exporters |
| `crates/mtg-cli` | `mtg-proxy` binary (all 9 subcommands, `tikv-jemallocator`, `SIGHUP` reload, `doctor`) |
| `crates/mtg-bench` | Interleaved Linux A/B benchmark & wire-interop harness |
| `fuzz/` | 8 `libFuzzer` harnesses for hostile network/config inputs |

## Licence

By contributing you agree your work is licensed under the [MIT licence](LICENSE), the same as the rest of the project.
