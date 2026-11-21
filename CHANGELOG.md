# Changelog

All notable changes to `mtg-proxy` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.4.0] — 2026-11-22

Carrier-grade 4-tier connection & speed governance engine: server-wide bandwidth shaping & VPS-safe global data quotas (`[limits]`), 64-way sharded global per-IP connection & connect-rate flood shields, Iranian CGNAT-safe per-connection speed caps (`conn-speed*`), directional per-IP ceilings (`client-speed-up`/`down`), `[limits.default-secret]` policy inheritance, hot-reloadable `concurrency`, and live `/limits` Management API.

### Added
- **Server-Wide Global Traffic & Connection Shaping (`[limits]` across `mtg-core`, `mtg-governance`, `mtg-config`, `mtg-engine`, `mtg-api`, `mtg-cli`):**
  - **Global Bandwidth Shaper (`speed`, `speed-up`, `speed-down`):** Lock-free `AtomicI64` GCRA rate limiters shared across all secrets, workers, and transports (`DirectRelay` & `MiddleProxy`), adding ~4 ns fast-path bypass when unlimited.
  - **Server-Wide Data Quota (`quota`, `quota-reset = "none" | "daily" | "weekly" | "monthly"`):** Prevents unexpected VPS bandwidth overages (e.g., `950GB` monthly cap on a 1 TB droplet); cuts off live streams cleanly at the ceiling, transparently fronts new attempts to the cover site, and persists backward-compatibly inside `usage.json`.
  - **64-Way Sharded Global Per-IP Guard (`GlobalIpGuard`):** Enforces `max-connections-per-ip` via leak-proof RAII `GlobalIpConnPermit` handles and `max-new-connections-per-ip` via bounded-RAM GCRA connect-rate limiting (`burst = 2×`, max `4096` entries/shard with 60s idle sweeping), protecting single-core droplets from accept/connection-churn floods before spending any FakeTLS HMAC CPU.
  - **CGNAT-Safe Per-Connection Speed Caps (`conn-speed`, `conn-speed-up`, `conn-speed-down`):** Boxed per-TCP-connection GCRA limiters (`0 B` heap allocated when unset; `DirectRelay` stays well below future-size firewall!) configurable globally in `[limits]` or overridden per secret — smoothly paces heavy media downloads without punishing innocent users sharing a carrier-grade NAT IPv4 address.
  - **Directional Per-IP Ceilings (`client-speed-up`, `client-speed-down`) & `[limits.default-secret]` Inheritance:** Asymmetric per-address download/upload caps inside `[secret-limits.<name>]` plus global default secret policy inheritance (`SecretLimits::merge_defaults`) so multi-tenant & public proxies configure baseline policies once.
- **Hot-Reloadable `concurrency` & Live `/limits` Management API (`mtg-engine`, `mtg-api`):**
  - Upgraded `concurrency` to an `AtomicU32` hot-reloadable via `SIGHUP`, `POST /reload`, or `PUT`/`PATCH /limits`.
  - Added `GET /limits`, `PUT /limits`, `PATCH /limits`, and `POST /limits/reset-quota` alongside 5 new Prometheus metrics (`mtg_global_quota_used_bytes`, `mtg_global_quota_limit_bytes`, `mtg_global_speed_throttled_seconds_total`, `mtg_global_ip_conn_limited_total`, `mtg_global_ip_rate_limited_total`) and `mtg-proxy doctor` `[limits]` reporting.

### Performance & Quality Gates
- Boxed the single-port `try_single_port_obfs2_or_front` branch inside `faketls_handshake_and_dial`, cutting handshake future stack usage by 16 KiB.
- `110/110` Rust workspace tests passing, `0` clippy warnings (`-D warnings`), `panel-config-string.golden` byte-exact, `steady_state_connection_future_size_guard` passing.

---

## [2.3.0] — 2026-11-22

Unified single-port multi-transport multiplexing (`ee` + `dd`/`plain` + integrated in-process TLS `web-relay` + cover site on ONE port `:443`), CDN-aware spoof-proof Geo-Stealth (`cdn = "cloudflare" | "arvancloud"`), enterprise multi-tenant accounting & full async hot-reload, conditional HTTP `ETag`/`304` + SHA-256 IP filter auto-updates, and Node.js 24 GitHub Actions workflow upgrades.

### Added
- **Unified Single-Port Multi-Transport Multiplexing (`mtg-config`, `mtg-engine`, `mtg-webrelay`, `mtg-cli`):**
  - Added optional `bind-to-accept = ["ee", "dd"]` / `["ee", "dd", "plain"]` (default `["ee"]` only — zero overhead when unset) allowing one port (e.g. `:443`) to serve FakeTLS (`ee`), Obfuscated2 (`dd`/`plain`), and the cover website / WEB proxy simultaneously while enforcing Geo-Stealth byte-0 fronting for foreign IPs, public per-IP failed-handshake rate limiting, Obfuscated2 anti-replay, and verbatim fronting on unmatched probes.
  - Added embedded **`[web] integrated = true`** inside `mtg-proxy run`: automatically binds an internal loopback `dd` listener (when `[web] backend` is omitted), shares `ProxyEngine`'s live secrets, governance, accounting, and Geo-Stealth allowlist/blocklist with zero-delay real-time synchronization (`subscribe_secret_changes`), and eliminates running a separate `web-relay` daemon.
  - Added **in-process hot-reloadable TLS** (`[web] tls-cert` + `tls-key`, `ReloadableTlsAcceptor`, zero new crate dependencies via `rustls-pki-types`) supporting Let's Encrypt `fullchain.pem`/`privkey.pem` (RSA, ECDSA, Ed25519) with zero-downtime `SIGHUP` cert reload. When paired with `integrated = true` and no `[web] bind-to`, `mtg-proxy` auto-wires `:443` domain fronting via PROXY protocol v2 straight into the in-process HTTPS/WSS WEB origin — enabling **true zero-Nginx/Caddy single-port `:443` all-in-one deployments**.
- **CDN-Aware Spoof-Proof Geo-Stealth for `web-relay` (`mtg-config`, `mtg-webrelay`):**
  - Added `[web] cdn = "cloudflare" | "arvancloud"`, `trusted-proxies`, `trusted-proxy-urls`, and `client-ip-header` so deployments behind Cloudflare or ArvanCloud (whose edge IPs are non-Iranian) work seamlessly with `[defense.allowlist]` (`IR-Geo-DB`).
  - Automatically fetches and refreshes official CDN edge CIDRs (with built-in offline Cloudflare IPv4 + IPv6 fallback CIDRs) and performs right-to-left trusted-hop peeling in `Origin::resolve_client_addr`: `CF-Connecting-IP` / `Ar-Real-IP` is **only** trusted when network routing proves the hop arrived from a verified CIDR in `trusted_proxies`, remaining **100% immune to direct-to-origin or direct-to-Nginx header spoofing**.
- **Enterprise Multi-Tenant Accounting, Quotas & Full Async Hot-Reload (`mtg-core`, `mtg-engine`, `mtg-api`, `mtg-cli`):**
  - Added `quota-reset = "daily" | "weekly" | "monthly" | "none"` and per-secret `max-connections` hard concurrent cap (`DenyReason::MaxConnections`).
  - Upgraded `usage-state-file` (`usage.json` v2) with backward-compatible persistence of `bytes_in`, `bytes_out`, `total_connections`, `quota_cutoffs`, and `last_seen_unix`, plus zero-overhead idle dirty-digest skipping to avoid unnecessary SSD writes.
  - Upgraded `SIGHUP` and `POST /reload` to full async atomic hot-reload covering `[secrets]`, limits, ad-tags, retiring-secrets, `[throttle] max-connections`, `track-client-ips`, `tolerate-time-skewness`, `[domain-fronting]`, AND `[defense.allowlist]`/`[defense.blocklist]` (warm-loaded before atomic swap so zero traffic slips through an empty list!) plus integrated `[web]` TLS certs & filters.
  - Added 8 strictly additive Management API endpoints (preserving all 19 Penhoon routes and 20 `SUPPORTED_FEATURES` 100% intact):
    - `GET /healthz` (unblocks `deploy/scripts/deploy-release.sh` automated health verification!)
    - `GET /accounting` (full multi-tenant billing ledger & directional counters) & `POST /accounting/flush`
    - `PATCH /secrets/{name}` (partial atomic updates including billing top-up `add_quota`, `reset_quota`, `max_connections`)
    - `POST /secrets/{name}/disconnect` (instant disconnect without banning)
    - `POST /secrets/batch` (atomic bulk `upsert` + `delete` in a single `ArcSwap` swap)
    - `GET /ip-filters` & `POST /ip-filters/refresh` (live IP filter telemetry & on-demand conditional refresh)
- **Conditional HTTP (`ETag`/`304`) & SHA-256 IP Filter Auto-Updates (`mtg-net`, `mtg-governance`):**
  - Added `fetch_url_conditional_with_dns` supporting `If-None-Match` / `If-Modified-Since` → `304 Not Modified`, per-source ETag/Last-Modified tracking, SHA-256 content-hash deduplication (skips 2 MiB DIR-24-8 rebuilds and SSD cache rewrites when unchanged), and ±5% deterministic fleet schedule jitter.
- **Diagnostics (`mtg-cli`):**
  - Extended `mtg-proxy doctor` and `mtg-proxy web-relay --check` with single-port multi-transport reporting, integrated `[web]` TLS validation, and live CDN `trusted-proxies` CIDR verification.

### Fixed
- **GitHub Actions Node.js 20 Deprecation Warnings (`.github/workflows/ci.yml`, `.github/workflows/release.yml`):**
  - Upgraded remaining GitHub Actions to Node.js 24-native major tags: `actions/checkout@v7`, `actions/setup-node@v7` (`node-version: "24"`), `actions/upload-artifact@v7`, `actions/download-artifact@v8`, and `actions/attest-build-provenance@v4`.

### Verified Live (`mtg-dev` DigitalOcean `s-2vcpu-2gb-intel`)
- **All-in-One Single-Port `:18443` 7-Probe Live Matrix (`bind-to-accept = ["ee", "dd"]`, `[web] integrated = true`, `tls-cert`/`tls-key`, `cdn = "cloudflare"`, live `IR-Geo-DB`):**
  - Iranian `ee` FakeTLS → real Telegram DC 2 `resPQ` (`100 B`) in `17.4 ms`.
  - Iranian `dd` Obfuscated2 **on the exact same port** → real Telegram DC 2 `resPQ` (`100 B`) in `17.5 ms`.
  - Iranian HTTPS browser **on the exact same port** → in-process TLS 1.3 dummy website `200 OK`.
  - Iranian integrated WSS WEB proxy **on the exact same port** → auto-bound internal `dd` → real Telegram DC 2 `resPQ` (`103 B`) in `25.4 ms`.
  - Cloudflare CDN live feed (`44` CIDRs in `35 ms`): Cloudflare edge IP `172.70.114.25` + `CF-Connecting-IP: <Iran IP>` → `200 OK` WEB bridge.
  - Foreign attacker (`1.1.1.1`) with forged `CF-Connecting-IP: <Iran IP>` + valid `/?bridge=<cap>` AND valid leaked `ee` secret → neutralized (`200 OK` dummy website only, `delta faketls.scanned = 0`).
  - Live `POST /ip-filters/refresh` → `HTTP 304 Not Modified` (`2,552` CIDRs retained with zero rebuild); `GET /healthz`, `GET /accounting`, `PATCH /secrets/{name}` top-up, `POST /secrets/batch` + zero-delay integrated WEB sync, `POST /accounting/flush`, and `POST /reload` all `200 OK`.
- **Quality Gates:** `106/106` Rust workspace tests passing, `0` clippy warnings (`-D warnings`), `panel-config-string.golden` byte-exact, `steady_state_connection_future_size_guard` passing, Playwright WebBridge `36/36` passing.

---

## [2.2.0] — 2026-11-22

Geo-Stealth cover-only fronting and enterprise auto-updating country IP allowlist/blocklist engine — designed for daily-updated geo-IP feeds such as [IR-Geo-DB](https://github.com/Arman2122/IR-Geo-DB) so foreign active probers and DPI scanners only ever see a genuine cover website (even with a leaked valid `ee` secret or WEB bridge capability) with zero HMAC CPU and zero TCP-drop fingerprinting.

### Added
- **Geo-Stealth Cover-Only Fronting (`action = "front" | "close"` across `mtg-config`, `mtg-engine`, `mtg-webrelay`):**
  - Added configurable `action` (`"front"` default for `[defense.allowlist]`, `"close"` default for `[defense.blocklist]`), inline `cidrs = [...]` (strictly validated by `run --check` and `doctor`), and atomic on-disk `cache-file` to `[defense.allowlist]` and `[defense.blocklist]` while preserving 100% byte-exact `panel-config-string.golden` backwards compatibility.
  - **FakeTLS (`ee`) Zero-HMAC Byte-0 `splice(2)` Fast Path:** Non-allowed (foreign) IPs with `action = "front"` never suffer a fingerprintable TCP drop/RST and never authenticate — even when presenting a valid leaked `ee` secret (`faketls.scanned = 0`, zero HMAC CPU!). Single/fixed covers skip ClientHello parsing altogether and enter zero-copy Linux `splice(2)` from byte 0; multi-domain covers peek SNI only (zero HMAC) to serve the exact matching TLS certificate. Allowed country IPs seamlessly browse the cover website normally AND authenticate to Telegram at ~4–25 ns DIR-24-8 O(1) lookup cost.
  - **WEB Relay (`mtg-webrelay`) Geo-Stealth & Zero-Leak Cover Sanitization:** Wired `[defense.allowlist]` and `[defense.blocklist]` into `Origin` and `mtg-proxy web-relay` (with startup `init_load`, periodic background refresh, and `SIGHUP` refresh). Foreign IPs hitting any URL — including a leaked `/?bridge=<cap>`, `POST /api/v1/session`, or `GET /api/v1/ws` — silently receive the Tier-3 cover website with bridge/bearer/subprotocol atoms stripped so nothing leaks to `cover-upstream` logs and zero 404 oracle exists.
  - **Obfuscated2 (`[[listener]]`) Indistinguishable Denial:** Non-allowed IPs with `action = "front"` read the 64-byte frame and exit via `dispose_obfs_denied` (`close` or bounded `drain`), indistinguishable from an unknown secret.
- **Universal Auto-Updating IP Filter Engine (`mtg-net`, `mtg-governance`):**
  - Upgraded `fetch_url_bytes_with_dns` to follow up to 5 HTTP `301/302/303/307/308` redirects (required for GitHub `/releases/latest/download/...` URLs), honoring custom DoH/DoT `DnsResolver`, `prefer-ip`, upstream proxies, and a strict 16 MiB body cap.
  - Extended `IpFilterBuilder` to parse plain CIDR/IP files (`ir-ipv4.txt`, `ir-ipv6.txt`), FireHOL `.ipset`/`.netset`, AND Linux `ipset restore` files (`ir.ipset` — `create`, `flush`, `destroy`, `swap`, `add <set> <cidr> [-exist]`, both IPv4 + IPv6 in one file) while keeping strict rejection of corrupt feeds.
  - Upgraded `LiveIpFilter` with bounded concurrent downloads (`download-concurrency`), 1 automatic transient retry, parse-before-swap validation, **per-source Last-Known-Good (LKG) retention** (if 1 of 2 URLs fails transiently, never drops the healthy source's IPv4/IPv6 coverage!), **crash-safe atomic `0600` `cache-file` snapshots** (warm-loaded in ~1.4 ms at boot; survives upstream GitHub outages), 60-second automatic retry backoff on partial/failed rounds, `SIGHUP` on-demand refresh, and live Prometheus/StatsD `mtg_iplist_size` gauge updates.
- **`mtg-proxy doctor` Live IP Filter Verification (`mtg-cli`):**
  - Added live `[defense.allowlist]` / `[defense.blocklist]` diagnostics reporting loaded IPv4 + IPv6 entry counts, fetch latency, and configured action.

### Verified Live (`Arman2122/IR-Geo-DB` on DigitalOcean `s-2vcpu-2gb-intel`)
- **`ir-ipv4.txt` + `ir-ipv6.txt` (GitHub multi-hop 302):** `2,552` CIDRs (`1,911` IPv4, `641` IPv6) fetched in `177–390 ms`, persisted to atomic `0600` cache (`39.8 KiB`), cold-boot warm-loaded in **`1.37 ms`**.
- **`ir.ipset` (single combined Linux `ipset restore` file):** identical `2,552` CIDRs (`1,911` IPv4, `641` IPv6) parsed in `333 ms`.
- **DIR-24-8 O(1) Lookup Throughput (Xeon Cascade Lake, 10k `/16`s random sweep):** `25.3 ns/op` (`~40 million lookups/s` per core).
- **Live 4-Probe Geo-Stealth Matrix:**
  - Foreign IP (`1.1.1.1`) with **100% valid `ee` secret** -> fronted byte-0 to real `storage.googleapis.com:443`, `faketls.scanned = 0`, `mtg_ip_blocklisted{ip_list="allowlist"} = 1`.
  - Foreign IP (`1.1.1.1`) real HTTPS browser -> verified Google TLSv1.3 cert + real cover HTTP response.
  - Iranian IP (`5.160.1.10`) with valid `ee` secret -> real Telegram DC 2 `resPQ` (`0x05162463`, `100 B`) in `95.6 ms`.
  - Iranian IP (`5.160.1.10`) normal HTTPS browser -> verified Google TLSv1.3 cert + real cover HTTP response.
- **Quality Gates:** `102/102` Rust workspace tests passing, `0` clippy warnings (`-D warnings`), `panel-config-string.golden` byte-exact, Playwright WebBridge `36/36` passing.

---

## [2.1.0] — 2026-11-21

Major FakeTLS (`ee`) hot-path acceleration, Iranian/GFW DPI anti-fingerprinting & stealth-at-wire-speed upgrade, Zero-RTT multi-cover domain fronting engine, and high-throughput `mtg-webrelay` Web Transport overhaul — all verified head-to-head on real Linux Intel Xeon hardware.

### Added
- **Zero-RTT Warm Domain Fronting Pool (`mtg-engine` — `FrontingPool`):**
  - Pre-warms clean idle standby TCP sockets to hosted cover origins (verified live & unread via non-blocking `recv(MSG_PEEK | MSG_DONTWAIT)` before handoff) and triggers wait-free, 2-second-throttled reactive pre-warming after legitimate FakeTLS handshakes so reactive DPI replay/active probes experience **0 ms proxy→cover TCP connect RTT** without spamming CDNs when idle.
  - Added **multi-cover SNI-matched failover** (`fronting_hosts_for`): strictly prioritizes the exact hosted secret cover matching the client's SNI (100% matching TLS certificate, zero SSRF), falling back across configured explicit & alternate hosted covers so active probers never see a bare TCP RST.
  - Added **anti-self-loop IP filtering** (`filter_self_ips`) stripping `public-ipv4`/`public-ipv6` from resolved fronting addresses, plus per-origin EWMA RTT & failure-cooldown health tracking.
- **Per-SNI Calibrated Doppelganger Scouting (`mtg-engine` — `DoppelCatalog`):**
  - Multi-domain proxies now concurrently probe up to `16` distinct cover hosts via `JoinSet` + RFC 8305 Happy Eyeballs and publish per-SNI calibrated TLS certificate-flight noise, Weibull arrival parameters, and DRS flags atomically via `ArcSwap`.
- **Fresh Ephemeral X25519 Key Exchange per FakeTLS Handshake (`mtg-crypto`):**
  - Replaced the static 256-entry `X25519KeyRing` (which repeated identical 32-byte `key_share` public keys every 257 connections, creating a DPI fingerprinting distinguisher) with zero-syscall thread-local CSPRNG ephemeral Curve25519 generation on every handshake.
- **High-Performance Web Transport Covers (`mtg-webrelay`):**
  - Added a bounded **16 MiB in-memory cache with 5-second mtime revalidation** to `StaticCover` (zero disk syscalls & zero `spawn_blocking` hops on hot hits).
  - Upgraded `UpstreamCover` with **RFC 8305 Happy Eyeballs dialing**, a **warm HTTP/1.1 keep-alive connection pool** (max 8 idle, 30s TTL, automatic stale-socket retry), and accurate `Host` header rewriting for external HTTPS CDNs.

### Performance & Scalability
- **Zero-Memmove FakeTLS `ee` Upload & 128 KiB 8-Record Download Coalescing (`mtg-protocol`, `mtg-engine`):**
  - Added `TlsUnframer::unframe_spans` to locate decrypted TLS record payload slices in-place without `copy_within` memmoves, pairing directly with in-place VAES/AES-NI fused-CTR encryption and vectored writes.
  - Expanded thread-local `RELAY_SCRATCH` to **128 KiB** (`8 × 16 KiB` FakeTLS records per `writev(2)` batch), halving streaming FakeTLS `ee` download syscalls (`16.02 → 8.03 sys/MB`) while preserving **`0 B` idle I/O RAM** per connection.
- **Doppelganger Stealth-at-Wire-Speed (`mtg-protocol`, `mtg-engine`):**
  - Upgraded `DoppelConnState` & `DoppelRelayState` so `shaping = "burst"` + `drs = true` delivers authentic TTFB pacing and Cloudflare/nginx Dynamic Record Sizing (`1450 → 4096 → 16384 B`) after every `> 1s` idle gap, then unlocks full 8-record 128 KiB `writev(2)` wire speed using a single reused pinned `Sleep` (zero per-record heap `Box::pin(sleep)` allocations, cutting syscalls **7.2×** from `64.86 → 8.98 sys/MB`!).
- **Zero-Alloc, Lock-Free `mtg-webrelay` WebSocket Multiplexer (`mtg-webrelay`):**
  - Replaced per-session permanent 64 KiB `read_scratch` with thread-local `WEBRELAY_READ_SCRATCH` (**`0 B` idle read buffer per session**, saving ~320 MiB at 5,000 idle sessions).
  - Replaced `tokio::io::split` (`Arc<BiLock>` mutex on every read/write) with lock-free `PrefixedStream::into_owned_split()` via `TcpStream::into_split()`.
  - Eliminated per-batch heap allocations in `Outbox`, `write_frame_batch`, and `WsWriter::write_binary_vectored` via reusable `SessionScratch` + stack `[IoSlice; 64]`, hoisted a single throttled pinned idle timer, added fair round-robin stream polling with `batch_budget` burst coalescing, hardened `http1::Builder` with `header_read_timeout(10s)` + `pipeline_flush(true)`, and enabled multi-acceptor `SO_REUSEPORT` scaling.

### Measured Benchmarks (`v2.0.1` vs `v2.1.0` on DigitalOcean `s-2vcpu-2gb-intel`, Xeon Cascade Lake)
- **FakeTLS `ee` 32-Stream CPU Efficiency:** `2.03 → 1.62 CPU-s/GB` (**`1.26×` less CPU** — matching raw `dd` `1.63 CPU-s/GB`!)
- **FakeTLS `ee` 1-Stream / 32-Stream Throughput & Tail (`p99`):** `0.22 → 0.25 GiB/s` (`+12%`) / `0.43 → 0.48 GiB/s` (`+12%`), `p99` `14.13 → 11.97 ms` (**`1.18×` tighter**)
- **Streaming FakeTLS `ee` Download Syscalls:** `16.02 → 8.03 sys/MB` (**`2.00×` fewer syscalls**)
- **Doppelganger `shaping = "burst" + drs = true` Syscalls:** `64.86 → 8.98 sys/MB` (**`7.22×` fewer syscalls** with authentic DRS ramp `[1371..1439 B]` → `16 KiB`)
- **5,000-Secret Handshake Rate (with fresh ephemeral X25519):** `970 → 992 hs/s` (`+2%`, zero performance penalty for fresh keys)
- **WebRelay 4-Stream Shared-Frame v1 Syscalls:** `7.29 → 4.49 sys/MB` (**`1.62×` fewer syscalls**)
- **WebRelay `StaticCover` (16 MiB cache):** `3,859 → 6,122 req/s` (**`1.59×` faster**), `p50` `246.6 → 150.1 µs`, `p99` `456.7 → 314.3 µs`
- **WebRelay `UpstreamCover` (keep-alive pool):** `1,397 → 2,808 req/s` (**`2.01×` faster**), `200 → 1` TCP dials per 200 requests (**`200×` fewer upstream handshakes**)
- **Playwright Real-Chromium WebBridge Harness:** `36/36` checks passing, `0` CSP violations.

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
