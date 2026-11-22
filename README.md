<div align="center">

# mtg-proxy

**Ultra-high-performance, pure-Rust, Linux-native Telegram MTProto Proxy**

[![CI](https://github.com/Arman2122/mtg-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Arman2122/mtg-proxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Arman2122/mtg-proxy?sort=semver)](https://github.com/Arman2122/mtg-proxy/releases/latest)
[![Rust](https://img.shields.io/badge/rust-1.89%2B%20%7C%20Linux%20x86__64%20%26%20aarch64-orange)](Cargo.toml)
[![Docker](https://img.shields.io/badge/ghcr.io-linux%2Famd64%20%7C%20linux%2Farm64-2496ED?logo=docker&logoColor=white)](https://github.com/Arman2122/mtg-proxy/pkgs/container/mtg-proxy)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

*One `9.6 MiB` binary. Multi-tenant governance. Hardware VAES / SHA-NI / ARMv8 crypto. `10+ GiB/s` throughput. `4.58 KiB/conn` marginal RAM.*

</div>

---

`mtg-proxy` is a censorship-resistant [Telegram MTProto proxy](https://core.telegram.org/mtproto) engineered to serve thousands of users and 100k+ concurrent connections from a single Linux process.

Unlike single-secret proxies, `mtg-proxy` gives every user their own named secret, fronting hostname, traffic counters, quota/speed/address governance, and live rotation — all mutable at runtime via a REST Management API or `SIGHUP` without dropping existing connections.

**Version 2.0** is a complete ground-up rewrite in pure Rust targeting Linux (`x86_64` and `aarch64`) on bare metal, VMs, and containers, maintaining **100% drop-in compatibility** with `v1.x` TOML configs, Penhoon panel APIs, FakeTLS (`ee`), obfuscated2 (`dd`/`plain`), MiddleProxy (`ad-tag`), and the Telegram Desktop 7.1+ WEB proxy transport.

---

## Table of Contents

- [Architecture & Performance Benchmarks](#architecture--performance-benchmarks)
- [How Clients Reach It](#how-clients-reach-it)
- [Quick Start](#quick-start)
- [Verifying Releases](#verifying-releases)
- [Running with Docker](#running-with-docker)
- [Production Linux Tuning (`systemd` & `sysctl`)](#production-linux-tuning-systemd--sysctl)
- [Features](#features)
  - [Multiple Secrets & Hot Reload](#multiple-secrets--hot-reload)
  - [Management HTTP API & Stats](#management-http-api--stats)
  - [4-Tier Connection & Speed Governance](#4-tier-connection--speed-governance-global-per-secret-per-ip--cgnat-safe-per-connection)
  - [Per-Address Controls, Fair-Share & Bans](#per-address-controls-fair-share--bans)
  - [Secret Rotation with Overlap](#secret-rotation-with-overlap)
  - [Sponsored Channel (`ad-tag`)](#sponsored-channel-ad-tag)
  - [Connection Throttling](#connection-throttling)
  - [Unified Single-Port Multi-Transport & WEB Proxy (`web-relay`)](#unified-single-port-multi-transport--web-proxy-web-relay)
  - [Doppelganger Cover Scouting, Post-Quantum `X25519MLKEM768` & Two-Speed Anti-DPI](#doppelganger-cover-scouting-post-quantum-x25519mlkem768--two-speed-anti-dpi)
  - [Geo-Stealth Country Allowlist (`IR-Geo-DB`) & Cover-Only Fronting](#geo-stealth-country-allowlist-ir-geo-db--cover-only-fronting)
  - [Public IP Override & Environment Variables](#public-ip-override--environment-variables)
- [CLI Command Reference](#cli-command-reference)
- [Upgrading from v1.x (Go) to v2.0 (Rust)](#upgrading-from-v1x-go-to-v20-rust)
- [Workspace Architecture](#workspace-architecture)
- [Documentation, Security & Contributing](#documentation-security--contributing)
- [Credits & License](#credits--license)

---

## Architecture & Performance Benchmarks

### Key Systems Engineering

| Layer | Pure-Rust v2.0 Implementation |
|---|---|
| **Thread-per-Core Runtime** | Pinned single-threaded `LocalSet` workers respecting Linux `sched_getaffinity(0)` (Docker/Kubernetes/systemd `AllowedCPUs=` cpusets) with independent per-core `SO_REUSEPORT` listen queues. |
| **Zero-Syscall Socket Inheritance** | Tunes `TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_KEEP*`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`, `TCP_FASTOPEN`, and best-effort `TCP_CONGESTION=bbr` once on each listener before `listen(2)` — **0 `setsockopt` syscalls per accepted connection**. |
| **Single-Poll Full-Duplex `DirectRelay`** | Owns `(client, dc)` directly (no `into_split()` `Arc`s), shares 1 amortized idle timer, uses zero-memmove `TlsUnframer::unframe_spans` + L1/L2-hot 128 KiB thread-local scratch (`0 B` idle I/O buffers), batches up to 8 × 16 KiB FakeTLS records per `writev(2)` (`8 sys/MB`), and locks live task frame size to **`1,776 B`** via CI unit-test guard. |
| **Multi-Arch Hardware Crypto** | Single-pass in-place fused double-CTR (`x86_64` **VAES+AVX2** 8-block, **AES-NI** 4-block; `aarch64` **ARMv8 AES** 4-block), **Post-Quantum `X25519MLKEM768` (`0x11EC`)** & ephemeral X25519 FakeTLS handshakes (`0` heap allocs), hardware **SSE4.2 / ARMv8 CRC32C** for MiddleProxy, and multi-secret FakeTLS HMAC-SHA256 (**4-way interleaved SHA-NI**, **8-way AVX2**, **ARMv8 SHA-256**). |
| **Zero-RTT Domain Fronting (`FrontingPool`)** | Pre-warmed standby TCP pool (liveness-checked via `MSG_PEEK \| MSG_DONTWAIT`) with reactive cover pre-warming for 0 ms proxy→cover connect RTT against active DPI probes, SNI-matched multi-cover failover, Linux `getifaddrs(3)` local-NIC anti-self-loop filtering, authentic nginx `unrecognized_name(112)` rejection option, and zero-copy Linux `splice(2)` kernel pipe relay. |
| **Geo-Stealth IP Filter (`DIR-24-8`)** | Wait-free O(1) IPv4 DIR-24-8 bitmap (`~4 ns`) + coalesced IPv6 ranges (`~10 ns`), multi-hop GitHub redirect auto-updater (`IR-Geo-DB` / FireHOL / Linux `ipset restore`), per-source LKG retention, atomic `cache-file`, and zero-HMAC byte-0 `splice(2)` cover-only fronting for foreign IPs across both FakeTLS `ee` and `web-relay`. |
| **High-Throughput WEB Transport (`mtg-webrelay`)** | Lock-free `TcpStream::into_split()`, `0 B` idle per-session scratch, stack-vectored `writev(2)` Shared-Frame v1 batching, fair round-robin stream coalescing, multi-acceptor `SO_REUSEPORT`, Slowloris-hardened HTTP/1.1, 16 MiB cached `StaticCover`, and Happy-Eyeballs keep-alive pooled `UpstreamCover`. |
| **Lock-Free & Sharded State** | Cache-line-aligned per-worker admission gate & live-connection shards, per-secret sharded `AddressRegistry`, compact 32-byte `CancelToken`, vDSO `CLOCK_REALTIME_COARSE`/`CLOCK_MONOTONIC_COARSE`, and `tikv-jemallocator` (`percpu_arena:percpu`, 1s dirty/muzzy decay). |

### Interleaved Linux A/B Benchmarks (`Go v1.10.0` vs `Rust v2.0.0`)

Measured with `mtg-bench ab` (interleaved rounds, wire-interop verified on both binaries, identical configs):

| Workload | Legacy Go (`v1.10.0`, 15 MiB) | **Rust (`v2.0.0`, 9.6 MiB)** | Improvement |
|---|---:|---:|---:|
| **5,000 Idle FakeTLS Conns — Total RSS** | `307.6 MiB` | **`39.8 MiB`** | **7.7× less total RAM** |
| **5,000 Idle FakeTLS Conns — Per Conn** | `58.92 KiB/conn` | **`5.38 KiB/conn`** | **10.95× less RAM/conn** |
| **Marginal RAM Slope (`2k → 5k` conns)** | `60.05 KiB/conn` | **`4.58 KiB/conn`** | **13.1× less marginal RAM** |
| **32-Stream Raw `dd` Throughput** | `4.92–5.67 GiB/s` | **`10.80–12.34 GiB/s`** | **2.0–2.2× faster** |
| **32-Stream Raw `dd` CPU / `p99.9` Tail** | `1.01 CPU-s/GB` / `39.7 ms` | **`0.50–0.54 CPU-s/GB` / `1.31–1.58 ms`** | **1.9× less CPU, up to 30× tighter tail** |
| **32-Stream FakeTLS `ee` Throughput** | `0.08–0.09 GiB/s` | **`9.68–10.70 GiB/s`** (`16 sys/MB`) | **~115× faster, 11.7× fewer syscalls** |
| **5,000-Secret FakeTLS Scan (1-core bench)** | `~6.5 ms` | **`357.8 µs`** (4-way SHA-NI) | **~18× faster** |
| **5,000-Secret Live Handshake Flood (`p50`)** | `3.9–6.0 ms` (`3.9k–5.5k hs/s`) | **`1.24–1.51 ms`** (peak **`9,710 hs/s`**) | **3–4× lower median latency** |

---

## How Clients Reach It

Three entry paths share one set of users. A secret is 16 key bytes; the prefix tells the *client* which door to use, so one user keeps a single name, quota bucket, and counter set across every transport:

| Transport | Listener | Secret Form | Network Appearance |
|---|---|---|---|
| **FakeTLS** | `bind-to` (default `:443`) | `ee…` | Realistic TLS 1.3 handshake to your fronting domain; unmatched or denied traffic is transparently `splice(2)`-fronted. |
| **Obfuscated2** | `[[listener]]` | `dd…` or bare 32-hex | Raw obfuscated2 TCP stream (keep on loopback behind a carrier unless `public = true`). |
| **WEB Proxy** | HTTPS origin via `web-relay` | `dd…` | Genuine TLS + browser WebView loading an HTTPS page and opening a WebSocket (Telegram Desktop 7.1.2+). |

---

## Quick Start

### Option 1 — Download a Prebuilt Linux Binary

Grab the latest `linux-amd64` or `linux-arm64` archive from [Releases](https://github.com/Arman2122/mtg-proxy/releases) and verify it (see [Verifying Releases](#verifying-releases)).

### Option 2 — Build from Source (Linux `x86_64` or `aarch64`, Rust 1.89+)

```bash
git clone https://github.com/Arman2122/mtg-proxy.git
cd mtg-proxy
cargo build --release --bin mtg-proxy
# Produces target/release/mtg-proxy (~9.6 MiB, fat-LTO stripped)
```

### Generate Secrets, Write a Config & Run

```bash
# Generate FakeTLS secrets (choose a real, reachable HTTPS CDN/domain)
mtg-proxy generate-secret --hex storage.googleapis.com
```

```toml
# /etc/mtg-proxy/config.toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"
api-token = "replace-with-strong-random-token"
usage-state-file = "/var/lib/mtg-proxy/usage.json"

[throttle]
max-connections = 5000

# [secrets] must appear after all top-level keys (TOML table scoping rule).
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

Validate, diagnose, run, and print client links:

```bash
mtg-proxy run --check /etc/mtg-proxy/config.toml
mtg-proxy doctor /etc/mtg-proxy/config.toml
mtg-proxy run /etc/mtg-proxy/config.toml
mtg-proxy access /etc/mtg-proxy/config.toml
```

---

## Verifying Releases

Every tagged release publishes:

- `mtg-proxy-<version>-linux-amd64.tar.gz` and `mtg-proxy-<version>-linux-arm64.tar.gz`
- `mtg-proxy-<version>-checksums.txt` (SHA-256)
- `mtg-proxy-<version>-sbom.spdx.json` (SPDX 2.3 Rust Cargo SBOM)
- Signed Sigstore / in-toto [build provenance attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)

```bash
VERSION=2.0.0
PKG=mtg-proxy-${VERSION}-linux-amd64
BASE="https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}"

# 1. Verify SHA-256 checksum
curl -sfLO "${BASE}/${PKG}.tar.gz"
curl -sfLO "${BASE}/mtg-proxy-${VERSION}-checksums.txt"
sha256sum -c --ignore-missing "mtg-proxy-${VERSION}-checksums.txt"

# 2. Verify signed Sigstore provenance attestation
gh attestation verify "${PKG}.tar.gz" \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/release.yml

# 3. Verify container image provenance
gh attestation verify "oci://ghcr.io/arman2122/mtg-proxy:${VERSION}" \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/docker-publish.yml
```

See [SECURITY.md](SECURITY.md) for the full verification & threat model specification.

---

## Running with Docker

Multi-arch images (`linux/amd64`, `linux/arm64`, `gcr.io/distroless/cc-debian12`) are published to GHCR and ship with a working default config at `/config/config.toml`, supporting zero-config env-var launches:

```bash
docker run -d --name mtg -p 443:443 \
    -e SECRET=00112233445566778899aabbccddeeff \
    -e SECRET_HOST=storage.googleapis.com \
    -e TAG=3f40462915a3e6026a4d790127b95ded \
    -e MTG_BIND_TO=0.0.0.0:443 \
    ghcr.io/arman2122/mtg-proxy:latest
```

Or mount your own config file (recommended with `--user 65534:65534` for non-root hardening):

```bash
docker run -d --name mtg -p 443:443 --user 65534:65534 \
    -v /etc/mtg-proxy/config.toml:/config/config.toml:ro \
    ghcr.io/arman2122/mtg-proxy:latest
```

> **Note for non-root containers & strict seccomp:** Make sure the mounted config is readable by uid `65534` (`0640`/`0644`), and if running under a strict seccomp profile that audits `io_uring_setup`, pass `run --epoll /config/config.toml`. `:latest` only moves on tagged releases; `main` builds publish under `sha-<commit>`.

---

## Production Linux Tuning (`systemd` & `sysctl`)

Ready-to-deploy production templates are shipped in `deploy/`:

- [deploy/sysctl.d/99-mtg-proxy.conf](deploy/sysctl.d/99-mtg-proxy.conf) — enables `fq` + `bbr`, 65,535 listen/SYN backlogs, 16 MiB TCP buffer auto-tuning, `tcp_fastopen = 3`, `tcp_notsent_lowat = 16384`, and `fs.file-max = 2097152`.
- [deploy/systemd/mtg-proxy.service](deploy/systemd/mtg-proxy.service) — least-privilege systemd unit (`CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, `LimitNOFILE=1048576`, `ExecReload=/bin/kill -HUP $MAINPID`).
- [deploy/systemd/mtg-web-relay.service](deploy/systemd/mtg-web-relay.service) — dedicated hardened systemd unit for `mtg-proxy web-relay`.

```bash
sudo install -m 0755 target/release/mtg-proxy /usr/local/bin/mtg-proxy
sudo install -m 0644 deploy/sysctl.d/99-mtg-proxy.conf /etc/sysctl.d/99-mtg-proxy.conf
sudo sysctl --system
sudo install -m 0644 deploy/systemd/mtg-proxy.service /etc/systemd/system/mtg-proxy.service
sudo systemctl daemon-reload && sudo systemctl enable --now mtg-proxy
```

---

## Features

### Multiple Secrets & Hot Reload

Define one named secret per user under `[secrets]` (single-secret `secret = "..."` still works and maps to `default`). Reload changes without restarting or dropping active users via `SIGHUP` (`systemctl reload mtg-proxy`) or `POST /reload`:

```bash
curl -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:9090/reload
```

Hot reload atomically swaps `[secrets]`, `ad-tag`, `[secret-ad-tags]`, `[secret-limits]`, and `[[retiring-secret]]`. Removed or re-keyed secrets close immediately (unless covered by a `[[retiring-secret]]` overlap); untouched users remain connected with all counters preserved.

### Management HTTP API & Stats

Configure `api-bind-to` (bind to loopback unless `api-token` is set — verified in constant time via `Authorization: Bearer <token>`):

| Method & Path | Description |
|---|---|
| `GET /healthz` | Lightweight liveness/readiness probe (uptime, connections, active secrets, IP filter state). |
| `GET /stats` | Live global & per-user counters, `features` capability list, `listeners`, `obfuscated`, `faketls_handshake`, and `throttle` state. |
| `GET /accounting` | Enterprise multi-tenant billing ledger (`bytes_in`, `bytes_out`, `total_connections`, `quota_used`/`remaining`, `quota_cutoffs`, `last_seen`, all limits). |
| `POST /accounting/flush` | Force an immediate crash-safe atomic flush of `usage-state-file` to disk. |
| `GET /limits` | Inspect live server-wide `[limits]` (concurrency, global speed/quota, per-IP conn/rate caps, CGNAT-safe `conn-speed`, rejection counts). |
| `PUT /limits` / `PATCH /limits` | Live atomic update of global `concurrency`, `throttle_max_connections`, `speed*`, `quota`, `max_connections_per_ip`, `max_new_connections_per_ip`, and `conn_speed*`. |
| `POST /limits/reset-quota` | Reset the server-wide `[limits]` quota counter to zero immediately. |
| `POST /reload` | Full async hot-reload: `[secrets]`, limits, ad-tags, retiring-secrets, `[throttle]`, `track-client-ips`, `tolerate-time-skewness`, `[domain-fronting]`, and `[defense.allowlist]`/`[defense.blocklist]`. |
| `GET /secrets` | List all secrets with mode, host, effective ad-tag, limits, retiring info, and live usage. |
| `POST /secrets` | Add or update one secret (key, optional `ad_tag`, and any governance limits). |
| `PATCH /secrets/{name}` | Partial atomic account mutation (top-up `add_quota`, `reset_quota`, `disabled`, `expires`, `max_connections`, speed/IP limits) without resending the secret key. |
| `PUT /secrets` | Atomically replace the entire secret set while keeping active retiring keys of retained names. |
| `POST /secrets/batch` | Atomic bulk `upsert` + `delete` in a single lock-free `ArcSwap` swap (ideal for billing panels). |
| `GET /secrets/{name}` | Inspect one named secret and its live counters (`404` if missing). |
| `DELETE /secrets/{name}` | Delete one secret (`409` if it is the last remaining secret). |
| `POST /secrets/{name}/reset-quota` | Reset a secret's `quota_used` counter to zero and restart its quota period. |
| `POST /secrets/{name}/disconnect` | Immediately disconnect ALL live streams for this secret without banning. |
| `POST /secrets/{name}/kick` | Immediately close live streams matching specified `ips` (O(K) indexed lookup). |
| `GET /secrets/{name}/external-ips` | View local & externally reported active addresses and `ip_limit`. |
| `PUT /secrets/{name}/external-ips` | Report external addresses (`{"ips":[...],"ttl":"90s"}`) counted toward `ip-limit`. |
| `DELETE /secrets/{name}/external-ips` | Clear external address report. |
| `GET /secrets/{name}/clients` | Per-address usage sorted by bytes moved (`?limit=N`, default 100, max 1,000). |
| `POST /secrets/{name}/bans` | Temporarily ban addresses from a secret (`{"ips":[...],"ttl":"1h","force"?}`) and kick live streams. |
| `GET /secrets/{name}/bans` | List active bans for a secret (addresses shown only when `track-client-ips = true`). |
| `DELETE /secrets/{name}/bans/{address}` | Unban one IPv4 address or IPv6 `/64` prefix. |
| `GET /ip-filters` | Inspect live `[defense.allowlist]` / `[defense.blocklist]` status (CIDR counts, ETag/304 hits, SHA-256 content hash, last refresh). |
| `POST /ip-filters/refresh` | Trigger synchronous conditional HTTP (`If-None-Match` / `304`) refresh of allowlist/blocklist feeds. |
| `GET /adtag` / `PUT /adtag` / `DELETE /adtag` | Read, set (`32` hex chars), or clear the global sponsored-channel `ad_tag`. |

> **Privacy default (`track-client-ips = false`):** Client IP addresses (`connected_ips`, `last_ip`, per-address IP listings) are omitted by default and never written to disk; `usage-state-file` persists byte quotas only.

Prometheus (`/metrics`) and StatsD UDP exporters are also built in under `[stats.prometheus]` and `[stats.statsd]`.

### 4-Tier Connection & Speed Governance (Global, Per-Secret, Per-IP & CGNAT-Safe Per-Connection)

Enforce lock-free GCRA bandwidth shaping, connection limits, and data quotas across **all four tiers** — hot-reloadable via `SIGHUP`, `POST /reload`, or live `PUT/PATCH /limits` with zero dropped connections:

```toml
usage-state-file = "/var/lib/mtg-proxy/usage.json"
concurrency = 32768               # Hot-reloadable global hard TCP cap

[limits]
speed = "800mbit"                 # Server-wide combined bandwidth cap (up + down)
speed-up = "400mbit"              # Server-wide upload cap
speed-down = "800mbit"            # Server-wide download cap
quota = "950GB"                   # Server-wide monthly data ceiling (prevents VPS overage!)
quota-reset = "monthly"           # "none" | "daily" | "weekly" | "monthly"
max-connections-per-ip = 64       # Global concurrent connections per IPv4 / IPv6 /64
max-new-connections-per-ip = 25   # Global connect-rate flood shield (conns/sec, burst 2x)
conn-speed-up = "2mbit"           # CGNAT-safe per-connection upload cap
conn-speed-down = "8mbit"         # CGNAT-safe per-connection download cap

# Optional defaults inherited by EVERY secret unless overridden in [secret-limits.<name>]:
[limits.default-secret]
client-conns = 16
client-speed-up = "2mbit"
client-speed-down = "10mbit"

[secret-limits.alice]
quota = "10GB"            # human size or bare bytes
quota-reset = "monthly"   # "none" (default), "daily", "weekly", or "monthly"
max-connections = 32      # hard concurrent connection cap for this account across all IPs
speed = "5mbit"           # combined up+down sustained cap (lock-free GCRA)
speed-up = "2mbit"        # optional directional caps (speed-up / speed-down)
speed-down = "5mbit"
ip-limit = 2              # max simultaneous places (IPv4 or IPv6 /64)
conn-speed-down = "4mbit" # per-connection override for this secret
expires = "2026-12-31"    # RFC3339 or YYYY-MM-DD
disabled = false
```

- Exceeded quotas cut off live streams at the ceiling (`quota_cutoffs`) and transparently front new attempts to the cover site so probers cannot distinguish limited users from invalid secrets.
- Speed limits pace without buffering (backpressure stays in the kernel TCP window) and update live on reload without dropping connections.

### Per-Address Controls, Fair-Share & Bans

Inside a shared secret, prevent a single heavy address from starving others:

```toml
[secret-limits.shared]
speed = "50mbit"
ip-limit = 30
client-conns = 16         # max simultaneous connections per IPv4 / IPv6 /64
client-speed = "10mbit"   # per-address static speed ceiling
client-fair = true        # 1-second water-level fair-share across active addresses
```

### Secret Rotation with Overlap

Rotate a leaked link without disconnecting legitimate users simultaneously:

```bash
mtg-proxy rotate-secret /etc/mtg-proxy/config.toml alice --overlap 24h --reload
```

Writes the new primary key into `[secrets]` (preserving comments and formatting via lossless TOML editing) and records the previous key in `[[retiring-secret]]` with an absolute `until` timestamp guarded by a monotonic `RotationClock`. Supports `--end-overlap`, `--prune`, `--host`, `--dry-run`, `--reload`, and `--force`.

### Sponsored Channel (`ad-tag`)

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"

[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

Register the **bare 32-hex key** (without `ee` or hostname) with [@MTProxybot](https://t.me/MTProxybot). `mtg-proxy` multiplexes eligible streams over persistent AES-256-CBC MiddleProxy carriers and falls back transparently to direct Telegram DCs if a carrier is unreachable.

### Connection Throttling

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Recomputes per-user fair-share connection caps automatically: light users keep all their slots while heavy consumers share the remaining budget equally (existing streams are never killed).

### Unified Single-Port Multi-Transport & WEB Proxy (`web-relay`)

`mtg-proxy` supports **both** dedicated listeners (`[[listener]]` + standalone `mtg-proxy web-relay`) **and** all-in-one single-port `:443` multiplexing (`ee` + `dd`/`plain` + HTTPS `web-relay` + cover website from ONE process on ONE port, with zero Nginx/Caddy required!):

```toml
# All-in-One Single-Port :443 (FakeTLS ee + Obfuscated2 dd + HTTPS WEB Relay + Cover Site)
bind-to = "0.0.0.0:443"
bind-to-accept = ["ee", "dd"]       # Optional: also accept dd (or plain) on :443 alongside ee!

[web]
enabled = true
integrated = true                   # Runs inside `mtg-proxy run`, auto-binds internal loopback dd backend!
host = "example.com"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"             # or cover-upstream = "http://127.0.0.1:8080"
tls-cert = "/etc/letsencrypt/live/example.com/fullchain.pem"  # Hot-reloaded on SIGHUP!
tls-key  = "/etc/letsencrypt/live/example.com/privkey.pem"
stats-bind-to = "127.0.0.1:8100"
```

- **CDN-Aware Spoof-Proof Geo-Stealth (`cdn = "cloudflare" | "arvancloud"`):** When running `[web]` behind Cloudflare, ArvanCloud, or a custom CDN alongside `[defense.allowlist]` (such as `IR-Geo-DB`), CDN edge IPs are foreign and would otherwise conflict with a country allowlist. Setting `cdn = "cloudflare"` (or `cdn = "arvancloud"`, or custom `trusted-proxies` / `trusted-proxy-urls` + `client-ip-header`) automatically fetches and refreshes official CDN edge CIDRs, peels trusted CDN hops right-to-left, and **only** trusts `CF-Connecting-IP` / `Ar-Real-IP` when network routing proves the request arrived from a real CDN CIDR — **100% immune to direct-to-origin header spoofing**!
- **Standalone Mode:** You can still run `mtg-proxy web-relay /etc/mtg-proxy/config.toml` as a separate process behind Caddy/Nginx (`[[listener]]` + `[web] bind-to` + `[web] backend`). Features a 3-tier anti-oracle origin, per-page 128-bit CSP nonces, strict RFC 6455 WebSocket framing, and automatic 2-second config-file watch + `SIGHUP` secret/TLS reloads. See [contrib/web-relay/README.md](contrib/web-relay/README.md) for Caddy examples.

### Doppelganger Cover Scouting, Post-Quantum `X25519MLKEM768` & Two-Speed Anti-DPI

`mtg-proxy` mirrors real 2026 TLS 1.3 web handshakes down to the exact cipher suite, extension order, Post-Quantum `X25519MLKEM768` (`0x11EC`, `1,210 B`) `ServerHello`, and certificate-flight size — while keeping the bulk data plane at full MTU wire speed (`128 KiB` 8-record `writev(2)`):

```toml
tolerate-time-skewness = "120s" # Mobile-friendly default (boot-time <120s also auto-accepted)
# ignore-time-skew = false      # Optional: accept arbitrary client clock drift (HMAC + anti-replay still enforced)

[domain-fronting]
unknown-sni-action = "front"    # "front" (default) | "reject-handshake" (nginx alert 112) | "drop"

[defense.doppelganger]
scout-covers = true                  # Live per-SNI raw PQ ServerHello + cert-flight profiling (0 data-plane latency!)
pq-key-share = true                  # Mirror 1,210 B Post-Quantum X25519MLKEM768 when offered by iOS/Chrome clients
server-hello-fragment-mss = "balanced" # Two-speed Linux MSG_EOR splitting on ServerHello ONLY ("off"|"extreme"|"tspu"|"balanced"|88..=1400)
# shaping = "burst"                  # Optional: TTFB pacing (<=35ms cap) + DRS ramp after >1s idle, then 128 KiB wire speed
# drs = true                         # Optional: Dynamic Record Sizing (1450 -> 4096 -> 16384 B)
```

Live background TLS scouting probes each hosted cover domain with a real PQ `X25519MLKEM768` `ClientHello` to capture its exact `ServerHelloProfile` (TLS 1.3 cipher suite, PQ vs X25519 selection, extension ordering, and certificate-flight noise size) and publishes calibrated per-SNI profiles atomically via `ArcSwap` — even when `shaping` and `drs` are disabled for zero data-plane latency.

- **Two-Speed `MSG_EOR` ServerHello Fragmentation:** Splits only the `ServerHello` flight across kernel-MSS-aware TCP segments (`TCP_INFO tcpi_snd_mss` minus TCP timestamps) via Linux `send(MSG_EOR | MSG_DONTWAIT | MSG_NOSIGNAL)` to defeat stateless DPI inspection while leaving all bulk chat/media transfers at full MTU.
- **RFC 793 True Half-Close & TLS Alert Hygiene:** Properly handles client `TLS Alert (0x15)` `close_notify` and TCP `FIN` half-closes (`SHUT_WR`) so in-flight Telegram messages and media chunks finish cleanly without truncation or mobile reconnect loops.
- **Hardware CRC32C & Abridged MiddleProxy (`ad-tag`):** Automatically negotiates `RPC_FLAG_USE_CRC32C` (`x86_64` SSE4.2 / `aarch64` ARMv8 CRC instructions), supports `Abridged` / `Intermediate` / `PaddedIntermediate` framing, binds SOCKS5 `BND.ADDR` into the KDF, monitors carrier EWMA RTT via `RPC_PING`/`RPC_PONG`, and drains carriers cleanly on Telegram proxy-secret rotations.

### Geo-Stealth Country Allowlist (`IR-Geo-DB`) & Cover-Only Fronting

Restrict proxy authentication to a specific country's IP ranges (for example, Iran via daily-updated [IR-Geo-DB](https://github.com/Arman2122/IR-Geo-DB)) while presenting a genuine cover website to every foreign scanner, probe, or censor — **even if a foreign prober holds a valid leaked `ee` secret or WEB bridge link**:

```toml
[defense.allowlist]
enabled = true
action = "front"             # Default for allowlist: stealth cover-only (never TCP-RST/drop!)
urls = [
    "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/ir-ipv4.txt",
    "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/ir-ipv6.txt",
    # Or single combined Linux ipset restore file (IPv4 + IPv6):
    # "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/ir.ipset",
]
# Optional inline CIDRs always permitted (e.g., loopback / operator IP)
cidrs = ["127.0.0.1/32", "::1/128"]
# Atomic on-disk cache (0600) for instant cold boot & GitHub outage resilience
cache-file = "/var/lib/mtg-proxy/ir-allowlist.cache"
update-each = "12h"
download-concurrency = 4
```

- **Zero-Fingerprint Cover-Only Fronting (`action = "front"`):**
  - **FakeTLS (`ee`):** Rejected foreign IPs skip secret scanning completely (**0 HMAC CPU**) and enter zero-copy Linux `splice(2)` directly to the cover website from byte 0 (for single/fixed covers) or SNI-matched cover (for multi-domain covers). Allowed country IPs both browse the cover website normally AND authenticate to Telegram via `ee` secrets at ~4 ns DIR-24-8 lookup cost.
  - **WEB Relay (`web-relay`):** Rejected foreign IPs hitting any path — even a leaked `/?bridge=<cap>` or `/api/v1/ws` — silently receive the Tier-3 cover website with bridge/bearer atoms stripped so nothing leaks to upstream logs and zero 404 oracle exists.
- **Enterprise Auto-Update & Resilience:** Uses conditional HTTP (`ETag`/`If-None-Match` and `Last-Modified`/`If-Modified-Since` → `304 Not Modified`), SHA-256 content deduplication (skips 2 MiB DIR-24-8 rebuilds and SSD cache rewrites when unchanged), ±5% fleet schedule jitter, multi-hop HTTP `301/302/307/308` GitHub release redirects, parse-before-swap validation, per-source Last-Known-Good (LKG) retention, `60s` retry backoff on partial outages, atomic `0600` on-disk `cache-file`, live `SIGHUP`/`POST /reload` config hot-reload, and Management API observability (`GET /ip-filters`, `POST /ip-filters/refresh`).

### Public IP Override & Environment Variables

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

Environment variables always override the config file (re-applied on every reload):

| Variable | Precedence Alias | Purpose |
|---|---|---|
| `SECRET` | `MTG_SECRET` | Full secret (`ee…`/base64) or bare 16-byte hex key (paired with `SECRET_HOST`). |
| `SECRET_HOST` | `MTG_SECRET_HOST` | Fronting hostname when `SECRET` is a bare 16-byte hex key. |
| `TAG` | `MTG_TAG` | Global sponsored-channel `ad-tag` (empty clears it). |
| `MTG_BIND_TO` | — | Comma-separated `host:port` list overriding `bind-to`. |

---

## CLI Command Reference

| Command | Description |
|---|---|
| `mtg-proxy run [--check] [--workers N] [--epoll] <config>` | Run the full proxy with `SIGHUP` reload and API. `--check` strictly validates config & exits. `--workers N` overrides pinned core count. `--epoll` skips startup `io_uring` probing for strict seccomp sandboxes. |
| `mtg-proxy simple-run <bind-to> <secret> [flags]` | Run a single-secret proxy directly from CLI flags without a config file. |
| `mtg-proxy generate-secret [--hex] [--mode ee\|dd\|plain] [hostname]` | Generate a cryptographically random secret (`--hex`/`-x` for hex, default base64). |
| `mtg-proxy access [--ipv4 IP] [--ipv6 IP] [--port N] [--hex] <config>` | Print `tg://` / `t.me` / `tg://webproxy` links and QR URLs as JSON. |
| `mtg-proxy doctor [--skip-native-check] <config>` | Diagnose config, CPU hardware crypto (`VAES`/`AES-NI`/`SHA-NI`/`ARMv8`), cgroup CPU affinity, kernel capabilities, SNTP clock skew, fronting reachability, SNI self-loop check, and live Telegram DC RPC probes. |
| `mtg-proxy rotate-secret <config> <name> [flags]` | Losslessly rotate a secret with optional `--overlap`, `--end-overlap`, `--prune`, `--dry-run`, `--reload`. |
| `mtg-proxy web-relay [--check] <config>` | Run the standalone WEB proxy relay with `SIGHUP` + 2-second config watcher. |
| `mtg-proxy generate-web-key <path>` | Generate a 32-byte WEB relay token signing key (`0600`). |
| `mtg-proxy version` / `--version` / `-v` | Print version, target triple, and git revision. |

See [example.config.toml](example.config.toml) for every supported option and default value.

---

## Upgrading from v1.x (Go) to v2.0 (Rust)

- **Config files & env vars:** Drop-in compatible. Run `mtg-proxy run --check /etc/mtg-proxy/config.toml` before swapping binaries.
- **`usage-state-file`:** Identical JSON schema; existing quota counters carry over seamlessly.
- **Management API & Penhoon panels:** All 19 endpoints, Bearer auth, status codes, and JSON payloads are unchanged.
- **Platform note:** `v2.0.0` targets Linux (`x86_64` and `aarch64`) exclusively; macOS/Windows/BSD server builds are not provided.

---

## Workspace Architecture

```text
mtg-proxy/
├── Cargo.toml                  # 11-crate Rust 2024 workspace (fat LTO, abort, strip)
├── crates/
│   ├── mtg-core/               # Secrets, IpUnit, limits, monotonic RotationClock
│   ├── mtg-crypto/             # VAES/AES-NI/ARMv8-AES fused-CTR, 4-way SHA-NI / 8-way AVX2 / ARMv8-SHA2
│   ├── mtg-protocol/           # TLS unframer, PROXY v1/v2, MiddleProxy RPC, Doppelganger MLE/DRS, dcprobe
│   ├── mtg-net/                # Linux sockopts, cgroup affinity, epoll/io_uring, splice(2), DoH/DoT, DC router
│   ├── mtg-governance/         # Sharded AddressRegistry, ClientTable, GCRA + fair-share, bans, anti-replay, FireHOL
│   ├── mtg-webrelay/           # WEB proxy origin, strict RFC 6455 WS, bridge page/CSP, 2s live watcher
│   ├── mtg-config/             # Strict TOML parser, env overlays, redaction, lossless toml_edit rotation
│   ├── mtg-engine/             # Pinned workers, DirectRelay, splice fronting, live Doppelganger scout, metrics
│   ├── mtg-api/                # 19-route Penhoon Management API, Prometheus & StatsD exporters
│   ├── mtg-cli/                # mtg-proxy binary, tikv-jemallocator, SIGHUP reload, doctor
│   └── mtg-bench/              # Interleaved Linux A/B benchmark & wire-interop verifier
├── deploy/                     # Production systemd units & sysctl.d Linux kernel tuning
├── fuzz/                       # 8 libFuzzer harnesses covering every untrusted parser
├── test/webbridge/             # Live Chromium Playwright harness (36 checks)
└── tests/golden/               # Byte-exact FakeTLS, obfs2, MiddleProxy, config & rotation golden fixtures
```

---

## Documentation, Security & Contributing

- **[Changelog](CHANGELOG.md)** — full release history and `v2.0.0` migration notes.
- **[Wiki Documentation](https://github.com/Arman2122/mtg-proxy/wiki)** — deep guides on installation, configuration, WEB relay setup, monitoring, and security.
- **[Security Policy](SECURITY.md)** — private vulnerability reporting, release attestation verification, and known side-channel notes.
- **[Contributing Guide](CONTRIBUTING.md)** — Rust build/lint/test commands, ARM64 cross-checks, Playwright bridge harness, and performance guardrails.

---

## Credits & License

`mtg-proxy` originated as a fork of [9seconds/mtg](https://github.com/9seconds/mtg) by Sergey Arkhipov and contributors, expanded with multi-user governance, the Penhoon Management API, MiddleProxy ad-tags, secret rotation, the WEB proxy transport, and completely re-architected in pure Rust for v2.0.

Licensed under the [MIT License](LICENSE).
