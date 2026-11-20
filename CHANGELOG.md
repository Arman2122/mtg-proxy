# Changelog

All notable changes to `mtg-proxy` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.1] — 2026-11-20

Critical production-correctness, `ad-tag` MiddleProxy wire-protocol, IPv4-only VPS Happy Eyeballs, and high-concurrency scalability hardening release.

### Fixed
- **IPv4-Only Linux VPS Direct-DC Failover (`mtg-net`):** Fixed a critical RFC 8305 Happy Eyeballs bug in `DcRouter::happy_eyeballs_dial` where an immediate primary error (`ENETUNREACH` on IPv4-only hosts using the default `prefer-ip = "prefer-ipv6"`) skipped the `secondary` IPv4 endpoint instead of failing over immediately. Extracted reusable `happy_eyeballs_connect` / `happy_eyeballs_connect_with` across direct DCs, MiddleProxy dialing, `getProxyConfig` / `getProxySecret` fetches, and domain fronting origins.
- **`ad-tag` MiddleProxy `RPC_PROXY_ANS` Download Framing (`mtg-engine`):** Fixed a wire-level corruption bug in `relay_middleproxy` where `FLAG_QUICK_ACK` in server response flags was erroneously OR'd (`0x80000000`) into the client's 4-byte intermediate frame length prefix. `RPC_PROXY_ANS` now always emits a clean 4-byte LE payload length, while `RPC_SIMPLE_ACK` carries raw 4-byte quick-ack tokens verbatim (matching Telegram MTProxy & Go golden parity).
- **`ad-tag` MiddleProxy Per-Packet `FLAG_ENCRYPTED` & `FLAG_QUICK_ACK` (`mtg-net`, `mtg-engine`):** Fixed `MiddleStream::send_packet` and `take_intermediate_packet` to stamp `FLAG_ENCRYPTED` (`0x2`) on unencrypted MTProto handshakes (`auth_key_id == 0`, e.g. `req_pq_multi`) and preserve client `FLAG_QUICK_ACK` (`0x80000000`) per packet instead of reusing static header flags.
- **`ad-tag` MiddleProxy Head-of-Line Deadlock & Carrier Scaling (`mtg-net`):** Eliminated carrier reader head-of-line blocking by switching per-stream delivery to non-blocking `try_send` (`STREAM_RX_CAP = 256`) that cleanly evicts only a stalled client (`RPC_CLOSE_CONN`) without freezing sibling clients or delaying `RPC_PONG`. Added a dedicated `biased`-priority control channel (`RPC_PONG`, `RPC_PING`, `RPC_CLOSE_CONN`), proactive 30s `RPC_PING` keepalives, 64 KiB write coalescing, per-DC async dial locking (preventing thundering-herd carrier storms), P2C least-loaded selection, and dynamic scaling up to 32 carriers/DC.
- **DoH/DoT & `prefer-ip` for Telegram Config Fetches (`mtg-net`, `mtg-engine`, `mtg-cli`):** Wired configured `DnsResolver` and `PreferIp` into `DcRouter` -> `fetch_url_bytes_with_dns` so `core.telegram.org/getProxySecret` and `getProxyConfig` honor custom DNS/DoH/DoT resolvers on censored or IPv4-only networks.
- **Unknown-DC Fallback Effective DC ID (`mtg-net`, `mtg-engine`):** Propagated `effective_dc` (`DEFAULT_DC = 2`) from `DcRouter::dial_direct` into outbound obfuscated2 handshakes and DC metrics when `allow-fallback-on-unknown-dc = true` triggers.
- **Lossless Domain Fronting (`mtg-engine`):** Concatenated any pipelined post-`ClientHello` bytes before replaying to the fronting origin so TLS 1.3 0-RTT or pipelined probes forward without byte loss.
- **Release CI SBOM & Multi-Arch Docker Build Speed (`.github/workflows/release.yml`, `Dockerfile`):** Fixed `anchore/sbom-action` path (`Cargo.lock` -> `.`) for GitHub Release SBOM generation, and upgraded `Dockerfile` to native `$BUILDPLATFORM` cross-compilation (`linux/amd64` + `linux/arm64`) removing slow QEMU Rust LTO builds.

### Performance & Scalability
- **Zero-Idle-RAM `relay_middleproxy` (`mtg-engine`):** Eliminated permanent 48 KiB/conn heap buffers and `into_split()` overhead from `ad-tag` streams by switching to readiness-gated thread-local `RELAY_SCRATCH`, reclaimed `plain_in`, and a single amortized idle timer (saving ~480 MiB at 10,000 idle `ad-tag` connections).
- **Per-Secret Sharded `ClientTable` (`mtg-governance`):** Replaced the single global `ClientTable` mutex with per-secret `Arc<Mutex<SecretClients>>` shards + lock-free atomic `MAX_CLIENTS` tracking and tombstone eviction safety, eliminating cross-core admission lock contention across 10,000+ users.

### Tests
- Added full-stack end-to-end FakeTLS -> `ProxyEngine` -> `MiddleProxyPool` -> mock Telegram MiddleProxy RPC server integration test verifying `ad_tag`, `FLAG_ENCRYPTED`, `FLAG_QUICK_ACK`, clean `RPC_PROXY_ANS` framing, `RPC_SIMPLE_ACK`, `RPC_PING`/`RPC_PONG`, and graceful `RPC_CLOSE_CONN` multiplexing.
- Added regression tests for IPv4-only Happy Eyeballs instant failover, carrier HOL-stalled-stream eviction isolation, unknown-DC fallback effective DC propagation, and 8-thread concurrent sharded `ClientTable` admissions & chunked sweeps.

---

## [2.0.0] — 2026-11-20

Complete pure-Rust, Linux-native (`x86_64` and `aarch64`) architectural rewrite of `mtg-proxy`, delivering full drop-in parity for TOML configurations, FakeTLS (`ee`), obfuscated2 (`dd`/`plain`), MiddleProxy (`ad-tag`), the 19-route Penhoon Management HTTP API, per-address governance, secret rotation, and the WEB proxy relay — while dramatically increasing throughput and cutting memory usage by an order of magnitude.

### Breaking Changes
- **Linux-only server runtime (`x86_64` and `aarch64`):** Legacy Go sources and non-Linux server targets have been retired in favor of a specialized pure-Rust Linux engine (`SO_REUSEPORT`, `sched_getaffinity`/`sched_setaffinity`, `splice(2)`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`, `TCP_FASTOPEN`, `TCP_CONGESTION=bbr`, vDSO coarse clocks, and `tikv-jemallocator`).
- **Config, Wire Protocol & Management API:** 100% drop-in compatible with `v1.10.0` configs, environment variables, secrets, `usage-state-file`, `/stats`, Management API routes, and `mtg-proxy web-relay`.

### Added
- **11-Crate Modular Rust Workspace (`edition = "2024"`, Rust 1.89+):**
  - `mtg-core`, `mtg-crypto`, `mtg-protocol`, `mtg-net`, `mtg-governance`, `mtg-webrelay`, `mtg-config`, `mtg-api`, `mtg-engine`, `mtg-cli`, `mtg-bench`, plus 8 `libFuzzer` targets in `fuzz/`.
- **Multi-Architecture Hardware Cryptography (`mtg-crypto`):**
  - Single-pass in-place fused double-CTR (`FusedCtrPair`) with runtime CPU dispatch: `x86_64` VAES+AVX2 (8-block), `x86_64` AES-NI (4-block), `aarch64` ARMv8 AES (4-block), and portable fallback.
  - Multi-secret FakeTLS `ClientHello` HMAC-SHA256 verification: `x86_64` 4-way interleaved SHA-NI (`357.8 µs` per 5,000 secrets), `x86_64` 8-way multi-buffer AVX2, `aarch64` ARMv8 SHA-256, and stack-resident `PrecomputedSchedule` (`0` heap allocations on hot paths).
- **Single-Poll Full-Duplex `DirectRelay` (`mtg-engine`):**
  - Owns `(client, dc)` directly without `into_split()` `Arc`s, uses a single amortized idle timer, L1-hot thread-local 64 KiB scratch buffers (`0 B` idle I/O RAM per connection), 4-record stack-stamped `writev(2)` FakeTLS batching, compact 32-byte `CancelToken`, short-lived boxed handshake phase, zero-alloc thread-local `ServerHello` staging, and a unit-test future-size firewall (`DirectRelay = 1,408 B`, live task frame `= 1,776 B`).
- **Universal Linux Networking & Cgroup Awareness (`mtg-net`):**
  - Pinned thread-per-core `LocalSet` workers respecting Linux `sched_getaffinity(0)` (Docker, Kubernetes, systemd `AllowedCPUs=`), per-core `SO_REUSEPORT` listeners with zero-syscall child socket option inheritance, best-effort `TCP_FASTOPEN` & `BBR`, vDSO `CLOCK_REALTIME_COARSE`/`CLOCK_MONOTONIC_COARSE`, zero-copy kernel `splice(2)` domain fronting with automatic userspace fallback, and `--epoll` strict-seccomp probe bypass.
- **Zero-Contention Governance & Live Doppelganger Scouting:**
  - Cache-line-aligned per-worker striped admission gate & live-connection shards, per-secret sharded `AddressRegistry`, zero-alloc `ClientTable` admissions, and live background TLS cover-site scouting (`tokio-rustls` + Weibull MLE + DRS) updating `DoppelParams` atomically via `ArcSwap`.
- **Operations, Observability & Release Engineering:**
  - Upgraded `mtg-proxy doctor` with CPU hardware-crypto detection, cgroup CPU affinity check, kernel capability probe, SNI self-loop guard, SNTP clock skew check, and live Telegram DC RPC `req_pq_multi` probing.
  - Added hardened `deploy/systemd/mtg-proxy.service`, `deploy/systemd/mtg-web-relay.service`, `deploy/sysctl.d/99-mtg-proxy.conf`, multi-arch `Dockerfile` (`distroless/cc-debian12`), `mtg-bench` interleaved Linux A/B harness, and automated `x86_64` + `aarch64` GitHub Actions CI & Sigstore-attested release workflows.

### Performance Highlights (Interleaved Linux A/B vs Go `v1.10.0`)
- **Idle Memory (5,000 live FakeTLS connections):** `39.8 MiB` vs `307.6 MiB` (**7.7× less total RAM**; `4.58 KiB/conn` vs `60.1 KiB/conn` marginal slope — **13.1× reduction**).
- **32-Stream Raw `dd` Throughput:** `10.80–12.34 GiB/s` vs `4.92–5.67 GiB/s` (**2.2× faster**), `0.50–0.54 CPU-s/GB` (**1.9× less CPU**), `p99.9` `1.31–1.58 ms` vs `39.7 ms` (**up to 30× tighter tail**).
- **32-Stream FakeTLS `ee` Throughput:** `9.68–10.70 GiB/s` (`16 sys/MB`, `0.56 CPU-s/GB`).
- **5,000-Secret FakeTLS Scan:** `357.8 µs` single-core 4-way SHA-NI microbenchmark; `1.24–1.51 ms` live `p50` handshake latency (peak `9,710 hs/s`).

---

## [1.x] — Legacy Go Series (v1.0.0 – v1.10.0)

Prior releases (`v1.0.0` through `v1.10.0`) were implemented in Go and remain preserved in git history and release tags. Highlights included multi-secret support, the Penhoon Management API, per-user quotas/speed limits, per-address fair-share & bans, secret rotation with overlap, extra `[[listener]]` obfuscated2 doors, and the Telegram Desktop 7.1+ WEB proxy relay.
